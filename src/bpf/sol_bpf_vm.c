/*
 * sol_bpf_vm.c - BPF Virtual Machine Implementation
 *
 * Implements the Solana BPF interpreter and VM management.
 */

#include "sol_bpf.h"
#include "../util/sol_alloc.h"
#include "../util/sol_hash_fn.h"
#include "../util/sol_log.h"
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <stdio.h>
#if defined(__linux__)
#include <sys/mman.h>
#include <unistd.h>
#endif

#if defined(__linux__)
static size_t
page_align_up(size_t n) {
    long ps = sysconf(_SC_PAGESIZE);
    size_t page_sz = (ps > 0) ? (size_t)ps : 4096u;
    size_t add = page_sz - 1u;
    if (n > SIZE_MAX - add) return 0;
    return (n + add) & ~add;
}

static int
sol_bpf_vm_mmap_alloc_enabled(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v >= 0, 1)) return v;
    const char* env = getenv("SOL_BPF_MMAP_STACK_HEAP");
    /* Default off: mmap+madvise based reset can regress on workloads that touch
     * many stack pages (page faults can cost more than a memset). Enable for
     * experimentation via SOL_BPF_MMAP_STACK_HEAP=1. */
    int enabled = 0;
    if (env && env[0] != '\0') {
        enabled = (strcmp(env, "0") != 0);
    }
    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled;
}

static int
sol_bpf_vm_fast_reset_enabled(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v >= 0, 1)) return v;
    const char* env = getenv("SOL_BPF_FAST_RESET");
    /* Default off: only relevant when SOL_BPF_MMAP_STACK_HEAP is enabled. */
    int enabled = 0;
    if (env && env[0] != '\0') {
        enabled = (strcmp(env, "0") != 0);
    }
    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled;
}
#endif

/* Optional syscall profiling (opt-in via SOL_SBF_SYSCALL_PROFILE=1).
 *
 * This is intended for production performance work where perf is unavailable.
 * When enabled, we measure wall-clock time around each syscall handler call and
 * aggregate totals per syscall index. */
typedef struct {
    const char* name;
    uint32_t    hash;
    _Atomic uint64_t count;
    _Atomic uint64_t ns;
} sol_syscall_prof_entry_t;

typedef struct {
    const char* name;
    uint32_t    hash;
    uint64_t    count;
    uint64_t    ns;
} sol_syscall_prof_snapshot_t;

static sol_syscall_prof_entry_t* g_syscall_prof = NULL;
static size_t                    g_syscall_prof_len = 0;
static pthread_mutex_t           g_syscall_prof_mu = PTHREAD_MUTEX_INITIALIZER;

static inline uint64_t
syscall_prof_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int
syscall_prof_cmp_desc_ns(const void* a, const void* b) {
    const sol_syscall_prof_snapshot_t* x = (const sol_syscall_prof_snapshot_t*)a;
    const sol_syscall_prof_snapshot_t* y = (const sol_syscall_prof_snapshot_t*)b;
    if (x->ns < y->ns) return 1;
    if (x->ns > y->ns) return -1;
    return 0;
}

static void
syscall_prof_report_atexit(void) {
    sol_syscall_prof_entry_t* tab = g_syscall_prof;
    size_t len = g_syscall_prof_len;
    if (!tab || !len) return;

    /* Make a local copy so we can sort without locking. */
    sol_syscall_prof_snapshot_t* tmp = (sol_syscall_prof_snapshot_t*)malloc(len * sizeof(*tmp));
    if (!tmp) return;
    for (size_t i = 0; i < len; i++) {
        tmp[i].name = tab[i].name;
        tmp[i].hash = tab[i].hash;
        tmp[i].count = __atomic_load_n(&tab[i].count, __ATOMIC_RELAXED);
        tmp[i].ns = __atomic_load_n(&tab[i].ns, __ATOMIC_RELAXED);
    }

    /* Sort descending by total time. */
    qsort(tmp, len, sizeof(*tmp), syscall_prof_cmp_desc_ns);

    fprintf(stderr, "sbf_syscall_profile: top syscalls by wall time:\n");
    size_t shown = 0;
    for (size_t i = 0; i < len && shown < 32; i++) {
        if (!tmp[i].count) continue;
        double ms = (double)tmp[i].ns / 1e6;
        fprintf(stderr,
                "  %-32s calls=%-10lu time_ms=%.3f hash=0x%08x\n",
                tmp[i].name ? tmp[i].name : "?",
                (unsigned long)tmp[i].count,
                ms,
                (unsigned)tmp[i].hash);
        shown++;
    }

    free(tmp);
}

static bool
syscall_prof_enabled(void) {
    static int cached = -1;
    static int registered = 0;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v >= 0, 1)) return v != 0;
    const char* env = getenv("SOL_SBF_SYSCALL_PROFILE");
    int enabled = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    if (enabled && __sync_bool_compare_and_swap(&registered, 0, 1)) {
        atexit(syscall_prof_report_atexit);
    }
    return enabled != 0;
}

static void
syscall_prof_init_table(sol_bpf_vm_t* vm) {
    if (!vm) return;
    if (g_syscall_prof) return;
    pthread_mutex_lock(&g_syscall_prof_mu);
    if (!g_syscall_prof && vm->syscall_count) {
        g_syscall_prof_len = vm->syscall_count;
        g_syscall_prof = sol_calloc(g_syscall_prof_len, sizeof(*g_syscall_prof));
        if (g_syscall_prof) {
            for (size_t i = 0; i < g_syscall_prof_len; i++) {
                g_syscall_prof[i].name = vm->syscalls[i].name;
                g_syscall_prof[i].hash = vm->syscalls[i].hash;
            }
        } else {
            g_syscall_prof_len = 0;
        }
    }
    pthread_mutex_unlock(&g_syscall_prof_mu);
}

/*
 * Murmur3 hash for syscall names
 */
static uint32_t
murmur3_32(const uint8_t* data, size_t len, uint32_t seed) {
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;
    const uint32_t r1 = 15;
    const uint32_t r2 = 13;
    const uint32_t m = 5;
    const uint32_t n = 0xe6546b64;

    uint32_t hash = seed;
    const int nblocks = (int)(len / 4);
    const uint32_t* blocks = (const uint32_t*)data;

    for (int i = 0; i < nblocks; i++) {
        uint32_t k = blocks[i];
        k *= c1;
        k = (k << r1) | (k >> (32 - r1));
        k *= c2;

        hash ^= k;
        hash = ((hash << r2) | (hash >> (32 - r2))) * m + n;
    }

    const uint8_t* tail = data + nblocks * 4;
    uint32_t k1 = 0;

    switch (len & 3) {
    case 3: k1 ^= (uint32_t)tail[2] << 16; /* fallthrough */
    case 2: k1 ^= (uint32_t)tail[1] << 8;  /* fallthrough */
    case 1: k1 ^= tail[0];
            k1 *= c1;
            k1 = (k1 << r1) | (k1 >> (32 - r1));
            k1 *= c2;
            hash ^= k1;
    }

    hash ^= (uint32_t)len;
    hash ^= hash >> 16;
    hash *= 0x85ebca6b;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35;
    hash ^= hash >> 16;

    return hash;
}

uint32_t
sol_bpf_syscall_hash(const char* name) {
    if (name == NULL) {
        return 0;
    }
    return murmur3_32((const uint8_t*)name, strlen(name), 0);
}

/*
 * Error messages
 */
const char*
sol_bpf_error_str(sol_bpf_error_t err) {
    switch (err) {
    case SOL_BPF_OK:                    return "success";
    case SOL_BPF_ERR_DIVIDE_BY_ZERO:    return "divide by zero";
    case SOL_BPF_ERR_DIVIDE_OVERFLOW:   return "divide overflow";
    case SOL_BPF_ERR_INVALID_INSN:      return "invalid instruction";
    case SOL_BPF_ERR_INVALID_MEMORY:    return "invalid memory access";
    case SOL_BPF_ERR_STACK_OVERFLOW:    return "stack overflow";
    case SOL_BPF_ERR_CALL_DEPTH:        return "call depth exceeded";
    case SOL_BPF_ERR_CALL_OUTSIDE_TEXT: return "call outside text segment";
    case SOL_BPF_ERR_UNKNOWN_SYSCALL:   return "unknown syscall";
    case SOL_BPF_ERR_SYSCALL_ERROR:     return "syscall error";
    case SOL_BPF_ERR_COMPUTE_EXCEEDED:  return "compute units exceeded";
    case SOL_BPF_ERR_ACCESS_VIOLATION:  return "memory access violation";
    case SOL_BPF_ERR_JIT_NOT_COMPILED:  return "JIT code not compiled";
    case SOL_BPF_ERR_ABORT:             return "program aborted";
    default:                            return "unknown error";
    }
}

/*
 * Memory region management
 */
sol_err_t
sol_bpf_memory_add_region(
    sol_bpf_memory_t* mem,
    uint64_t vaddr,
    uint8_t* host_addr,
    size_t len,
    bool writable
) {
    if (mem == NULL || host_addr == NULL || len == 0) {
        return SOL_ERR_INVAL;
    }

    /* Grow region array if needed */
    if (mem->region_count >= mem->region_cap) {
        size_t new_cap = mem->region_cap == 0 ? 8 : mem->region_cap * 2;
        sol_bpf_region_t* new_regions = sol_realloc(
            mem->regions, new_cap * sizeof(sol_bpf_region_t)
        );
        if (new_regions == NULL) {
            return SOL_ERR_NOMEM;
        }
        mem->regions = new_regions;
        mem->region_cap = new_cap;
    }

    /* Add region */
    sol_bpf_region_t* region = &mem->regions[mem->region_count++];
    region->vaddr = vaddr;
    region->len = len;
    region->host_addr = host_addr;
    region->writable = writable;
    region->kind = SOL_BPF_REGION_LINEAR;
    region->host_len = len;
    region->elem_len = 0;
    region->gap_len = 0;

    /* Cache canonical SBPF regions for fast translation (see fixed_region_idx). */
    if (__builtin_expect(mem->region_count <= (size_t)UINT16_MAX, 1)) {
        uint16_t idx1 = (uint16_t)mem->region_count; /* region_index + 1 */
        if (vaddr == SOL_BPF_MM_PROGRAM_START) mem->fixed_region_idx[1] = idx1;
        else if (vaddr == SOL_BPF_MM_STACK_START) mem->fixed_region_idx[2] = idx1;
        else if (vaddr == SOL_BPF_MM_HEAP_START) mem->fixed_region_idx[3] = idx1;
        else if (vaddr == SOL_BPF_MM_INPUT_START) mem->fixed_region_idx[4] = idx1;
    }

    return SOL_OK;
}

static sol_err_t
sol_bpf_memory_add_gapped_region(sol_bpf_memory_t* mem,
                                 uint64_t vaddr,
                                 uint8_t* host_addr,
                                 uint64_t host_len,
                                 uint64_t elem_len,
                                 uint64_t gap_len,
                                 bool writable,
                                 uint64_t* out_virt_len) {
    if (out_virt_len) *out_virt_len = 0;
    if (mem == NULL || host_addr == NULL || host_len == 0 || elem_len == 0) {
        return SOL_ERR_INVAL;
    }
    if ((host_len % elem_len) != 0) {
        return SOL_ERR_INVAL;
    }

    uint64_t elems = host_len / elem_len;
    if (elems == 0) {
        return SOL_ERR_INVAL;
    }

    if (elems == 1 || gap_len == 0) {
        sol_err_t err = sol_bpf_memory_add_region(mem, vaddr, host_addr, (size_t)host_len, writable);
        if (err == SOL_OK && out_virt_len) *out_virt_len = host_len;
        return err;
    }

    uint64_t virt_len = host_len + gap_len * (elems - 1);
    if (virt_len < host_len) {
        return SOL_ERR_OVERFLOW;
    }
    if (virt_len > (uint64_t)SIZE_MAX) {
        return SOL_ERR_OVERFLOW;
    }

    sol_err_t err = sol_bpf_memory_add_region(mem, vaddr, host_addr, (size_t)virt_len, writable);
    if (err != SOL_OK) {
        return err;
    }

    sol_bpf_region_t* region = &mem->regions[mem->region_count - 1];
    region->kind = SOL_BPF_REGION_GAPPED;
    region->host_len = host_len;
    region->elem_len = elem_len;
    region->gap_len = gap_len;

    if (out_virt_len) *out_virt_len = virt_len;
    return SOL_OK;
}

/*
 * Translate virtual address to host address
 */
SOL_INLINE uint8_t*
sol_bpf_translate_region(const sol_bpf_region_t* region,
                         uint64_t vaddr,
                         size_t len,
                         bool write) {
    if (!region || len == 0) return NULL;
    if (vaddr < region->vaddr) return NULL;

    uint64_t offset = vaddr - region->vaddr;
    uint64_t end = offset + (uint64_t)len;
    if (end < offset || end > region->len) {
        return NULL;
    }

    if (write && !region->writable) {
        return NULL;
    }

    if (__builtin_expect(region->kind == SOL_BPF_REGION_GAPPED, 0)) {
        uint64_t elem_len = region->elem_len;
        uint64_t gap_len = region->gap_len;
        uint64_t stride = elem_len + gap_len;
        if (elem_len == 0 || stride < elem_len) {
            return NULL;
        }

        uint64_t elem = 0;
        uint64_t within = 0;
        /* Division/modulo is very slow; use shifts for power-of-two strides.
         * For Solana stack frame gaps this is the common case (stride=8192). */
        if (__builtin_expect((stride & (stride - 1u)) == 0u, 1)) {
            uint64_t mask = stride - 1u;
            unsigned shift = (unsigned)__builtin_ctzll((unsigned long long)stride);
            elem = offset >> shift;
            within = offset & mask;
        } else {
            elem = offset / stride;
            within = offset % stride;
        }

        if (within + (uint64_t)len > elem_len) {
            return NULL; /* Spans into gap / next element */
        }

        uint64_t phys = elem * elem_len + within;
        if (phys + (uint64_t)len > region->host_len) {
            return NULL;
        }

        return region->host_addr + phys;
    }

    return region->host_addr + offset;
}

uint8_t*
sol_bpf_memory_translate(
    sol_bpf_memory_t* mem,
    uint64_t vaddr,
    size_t len,
    bool write
) {
    if (mem == NULL || len == 0) {
        return NULL;
    }

    /* Fast path: canonical SBPF regions are keyed by high 32-bits of vaddr
     * (1=program, 2=stack, 3=heap, 4=input). */
    {
        uint64_t tag = vaddr >> 32;
        if (__builtin_expect(tag > 0u && tag < 5u, 1)) {
            uint16_t idx1 = mem->fixed_region_idx[(size_t)tag];
            if (__builtin_expect(idx1 != 0u, 1) &&
                __builtin_expect((size_t)idx1 <= mem->region_count, 1)) {
                size_t idx = (size_t)idx1 - 1u;
                const sol_bpf_region_t* region = &mem->regions[idx];
                uint8_t* p = sol_bpf_translate_region(region, vaddr, len, write);
                if (p) {
                    mem->last_region_idx = idx;
                    return p;
                }
            }
        }
    }

    /* Hot path: most accesses stay within the same region (stack/heap/input).
       Cache the last successful lookup to avoid scanning regions for every
       load/store. */
    if (mem->region_count > 0 && mem->last_region_idx < mem->region_count) {
        const sol_bpf_region_t* region = &mem->regions[mem->last_region_idx];
        uint8_t* p = sol_bpf_translate_region(region, vaddr, len, write);
        if (p) {
            return p;
        }
    }

    for (size_t i = 0; i < mem->region_count; i++) {
        const sol_bpf_region_t* region = &mem->regions[i];
        uint8_t* p = sol_bpf_translate_region(region, vaddr, len, write);
        if (p) {
            mem->last_region_idx = i;
            return p;
        }
    }

    return NULL;  /* Address not found */
}

/* Specialized translator for the hot interpreter load/store path.
 *
 * sol_bpf_memory_translate() already has a fast path based on the high 32-bits
 * tag, but that still needs to load the fixed-region index and bounds-check it
 * on every translation.  For interpreter memory ops, the canonical regions
 * don't change across the VM invocation, so we can precompute their pointers
 * once and skip the repeated lookups. */
SOL_INLINE uint8_t*
sol_bpf_memory_translate_fixed_fast(
    sol_bpf_memory_t* mem,
    const sol_bpf_region_t* const fixed_regions[static 5],
    const size_t fixed_region_idx[static 5],
    uint64_t vaddr,
    size_t len,
    bool write
) {
    uint64_t tag = vaddr >> 32;
    if (__builtin_expect(tag > 0u && tag < 5u, 1)) {
        const sol_bpf_region_t* region = fixed_regions[tag];
        if (__builtin_expect(region != NULL, 1)) {
            uint8_t* p = sol_bpf_translate_region(region, vaddr, len, write);
            if (p) {
                mem->last_region_idx = fixed_region_idx[tag];
                return p;
            }
        }
    }

    return sol_bpf_memory_translate(mem, vaddr, len, write);
}

static bool
sol_bpf_stack_frame_gaps_enabled(void) {
    /* Default: enabled.  On current mainnet, Agave's
       create_program_runtime_environment_v1() sets
       enable_stack_frame_gaps = true in rbpf Config.  The v2 runtime
       (unused on mainnet) sets it to false.  Stack frame gaps only
       affect SBPFv0 programs (static frames); SBPFv1+ use dynamic
       stack frames and skip the VM's r10 advancement entirely.
       Set SOL_BPF_STACK_FRAME_GAPS=0 to disable for testing. */
    const char* env = getenv("SOL_BPF_STACK_FRAME_GAPS");
    if (!env || env[0] == '\0') {
        return true;
    }

    while (*env && isspace((unsigned char)*env)) env++;
    if (*env == '\0') return true;
    if (*env == '0') return false;
    if (*env == 'n' || *env == 'N') return false;
    if (*env == 'f' || *env == 'F') return false;
    return true;
}

SOL_INLINE void
sol_bpf_vm_record_fault(sol_bpf_vm_t* vm, uint64_t vaddr, uint64_t len, bool write) {
    if (!vm) return;
    vm->fault_vaddr = vaddr;
    vm->fault_len = len;
    vm->fault_write = write;
    vm->fault_pc = vm->pc ? (vm->pc - 1u) : 0u;
}

/*
 * Heap allocation
 */
uint64_t
sol_bpf_heap_alloc(sol_bpf_vm_t* vm, size_t size, size_t align) {
    if (vm == NULL || size == 0) {
        return 0;
    }

    /* Align position */
    size_t aligned_pos = (vm->heap_pos + align - 1) & ~(align - 1);

    if (aligned_pos + size > vm->heap_size) {
        return 0;  /* Out of heap space */
    }

    uint64_t addr = SOL_BPF_MM_HEAP_START + aligned_pos;
    vm->heap_pos = aligned_pos + size;

    return addr;
}

/*
 * Program management
 */
sol_bpf_program_t*
sol_bpf_program_new(void) {
    return sol_calloc(1, sizeof(sol_bpf_program_t));
}

void
sol_bpf_program_destroy(sol_bpf_program_t* prog) {
    if (prog == NULL) {
        return;
    }

#if SOL_BPF_JIT_SUPPORTED
    sol_bpf_jit_free(prog);
#endif

    sol_free(prog->function_registry);
    sol_free(prog->ro_section);  /* text_segment points into this, don't free separately */
    sol_free(prog);
}

/*
 * Create VM
 */
sol_bpf_vm_t*
sol_bpf_vm_new(const sol_bpf_config_t* config) {
    sol_bpf_config_t cfg;
    if (config != NULL) {
        cfg = *config;
    } else {
        cfg = (sol_bpf_config_t)SOL_BPF_CONFIG_DEFAULT;
    }

    sol_bpf_vm_t* vm = sol_calloc(1, sizeof(sol_bpf_vm_t));
    if (vm == NULL) {
        return NULL;
    }

    /* Allocate stack */
    vm->stack_size = cfg.stack_size;
    vm->stack_alloc_size = vm->stack_size;
    vm->stack_is_mmap = false;
    if (vm->stack_size == 0) {
        sol_free(vm);
        return NULL;
    }
#if defined(__linux__)
    if (sol_bpf_vm_mmap_alloc_enabled()) {
        size_t alloc_len = page_align_up(vm->stack_size);
        if (alloc_len != 0) {
            void* p = mmap(NULL, alloc_len, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (p != MAP_FAILED) {
                vm->stack = (uint8_t*)p;
                vm->stack_alloc_size = alloc_len;
                vm->stack_is_mmap = true;
            }
        }
    }
#endif
    if (vm->stack == NULL) {
        vm->stack = sol_calloc(1, vm->stack_size);
        vm->stack_alloc_size = vm->stack_size;
        vm->stack_is_mmap = false;
    }
    if (vm->stack == NULL) {
        sol_free(vm);
        return NULL;
    }

    /* Allocate heap */
    vm->heap_size = cfg.heap_size;
    vm->heap_alloc_size = vm->heap_size;
    vm->heap_is_mmap = false;
    if (vm->heap_size == 0) {
#if defined(__linux__)
        if (vm->stack_is_mmap) {
            munmap(vm->stack, vm->stack_alloc_size);
        } else
#endif
        {
            sol_free(vm->stack);
        }
        sol_free(vm);
        return NULL;
    }
#if defined(__linux__)
    if (sol_bpf_vm_mmap_alloc_enabled()) {
        size_t alloc_len = page_align_up(vm->heap_size);
        if (alloc_len != 0) {
            void* p = mmap(NULL, alloc_len, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (p != MAP_FAILED) {
                vm->heap = (uint8_t*)p;
                vm->heap_alloc_size = alloc_len;
                vm->heap_is_mmap = true;
            }
        }
    }
#endif
    if (vm->heap == NULL) {
        vm->heap = sol_calloc(1, vm->heap_size);
        vm->heap_alloc_size = vm->heap_size;
        vm->heap_is_mmap = false;
    }
    if (vm->heap == NULL) {
#if defined(__linux__)
        if (vm->stack_is_mmap) {
            munmap(vm->stack, vm->stack_alloc_size);
        } else
#endif
        {
            sol_free(vm->stack);
        }
        sol_free(vm);
        return NULL;
    }

    /* Initialize state */
    vm->state = SOL_BPF_STATE_READY;
    vm->compute_units = cfg.compute_units;

    /* Setup memory regions */
    vm->stack_frame_size = SOL_BPF_STACK_FRAME_SIZE;

    uint64_t stack_virt_len = 0;
    sol_err_t map_err = SOL_OK;
    uint64_t frames = 0;
    if (vm->stack_frame_size > 0 && (vm->stack_size % (size_t)vm->stack_frame_size) == 0) {
        frames = (uint64_t)vm->stack_size / vm->stack_frame_size;
    }
    if (frames > 1 && sol_bpf_stack_frame_gaps_enabled()) {
        vm->stack_gap_size = vm->stack_frame_size;
        map_err = sol_bpf_memory_add_gapped_region(
            &vm->memory,
            SOL_BPF_MM_STACK_START,
            vm->stack,
            (uint64_t)vm->stack_size,
            vm->stack_frame_size,
            vm->stack_gap_size,
            true,
            &stack_virt_len
        );
        if (map_err == SOL_OK) {
            vm->stack_virt_size = stack_virt_len;
        }
    } else {
        vm->stack_gap_size = 0u;
        map_err = sol_bpf_memory_add_region(&vm->memory,
                                            SOL_BPF_MM_STACK_START,
                                            vm->stack,
                                            vm->stack_size,
                                            true);
        if (map_err == SOL_OK) {
            vm->stack_virt_size = (uint64_t)vm->stack_size;
        }
    }
    if (map_err != SOL_OK) {
        sol_bpf_vm_destroy(vm);
        return NULL;
    }

    map_err = sol_bpf_memory_add_region(&vm->memory,
                                        SOL_BPF_MM_HEAP_START,
                                        vm->heap,
                                        vm->heap_size,
                                        true);
    if (map_err != SOL_OK) {
        sol_bpf_vm_destroy(vm);
        return NULL;
    }

    /* Initialize frame pointer: default to top of first frame (SBPFv0).
     * For SBPFv1+ (dynamic frames), sol_bpf_vm_load() will re-set r10 to
     * MM_STACK_START + stack_size after the ELF is loaded and the SBPF
     * version is known. */
    vm->reg[10] = SOL_BPF_MM_STACK_START + (uint64_t)vm->stack_frame_size;

    /* Register default syscalls */
    sol_err_t err = sol_bpf_register_syscalls(vm);
    if (err != SOL_OK) {
        sol_bpf_vm_destroy(vm);
        return NULL;
    }

    err = sol_bpf_register_cpi_syscalls(vm);
    if (err != SOL_OK) {
        sol_bpf_vm_destroy(vm);
        return NULL;
    }

    /* Build fast syscall lookup table (optional). */
    (void)sol_bpf_vm_reset(vm, vm->compute_units); /* also builds stack+heap mappings */

    return vm;
}

/*
 * Build the syscall LUT from the registered syscall array.
 * Callers must ensure vm->syscall_lut is NULL.
 */
static void
build_syscall_lut(sol_bpf_vm_t* vm) {
    if (!vm || !vm->syscalls || vm->syscall_count == 0) return;

    /* Keep load factor <= 0.5 to minimize probe chains. */
    size_t want = vm->syscall_count * 2u;
    size_t cap = 32u;
    while (cap < want && cap < (SIZE_MAX / 2u)) {
        cap *= 2u;
    }

    sol_bpf_syscall_lut_entry_t* lut = sol_calloc(cap, sizeof(*lut));
    if (!lut) return;

    size_t mask = cap - 1u;
    for (size_t i = 0; i < vm->syscall_count; i++) {
        sol_bpf_syscall_t* s = &vm->syscalls[i];
        /* Multiplicative hash; cap is power-of-two. */
        size_t idx = (size_t)(((uint64_t)s->hash * 11400714819323198485ull) & (uint64_t)mask);
        for (;;) {
            sol_bpf_syscall_lut_entry_t* e = &lut[idx];
            if (e->syscall == NULL) {
                e->hash = s->hash;
                e->syscall = s;
                break;
            }
            idx = (idx + 1u) & mask;
        }
    }

    vm->syscall_lut = lut;
    vm->syscall_lut_cap = cap;
}

sol_err_t
sol_bpf_vm_reset(sol_bpf_vm_t* vm, uint64_t compute_units) {
    if (!vm) return SOL_ERR_INVAL;

    /* Bump the per-invocation ID first so any syscall-local caches keyed by
     * (vm*, invocation_id) won't accidentally carry across resets. */
    vm->invocation_id++;

    /* Clear execution state. Preserve syscall registry and allocated buffers. */
    memset(vm->reg, 0, sizeof(vm->reg));
    vm->pc = 0;
    vm->state = SOL_BPF_STATE_READY;
    vm->error = SOL_BPF_OK;
    vm->call_depth = 0;
    vm->heap_pos = 0;
    vm->program = NULL;

    vm->compute_units = compute_units;
    vm->compute_units_used = 0;
    vm->insn_count = 0;
    vm->return_value = 0;

    vm->fault_vaddr = 0;
    vm->fault_len = 0;
    vm->fault_write = false;
    vm->fault_pc = 0;

    vm->context = NULL;
    vm->cpi_handler = NULL;
    vm->caller_input_buf = NULL;
    vm->caller_input_len = 0;
    vm->caller_metas = NULL;
    vm->caller_meta_count = 0;

    vm->trace = false;
    vm->loader_deprecated = false;
    vm->syscall_exec_count = 0;

    /* Reset memory mappings to stack + heap only. */
    vm->memory.region_count = 0;
    vm->memory.last_region_idx = 0;
    memset(vm->memory.fixed_region_idx, 0, sizeof(vm->memory.fixed_region_idx));
    vm->stack_gap_size = 0u;
    vm->stack_virt_size = 0u;

    uint64_t stack_virt_len = 0;
    sol_err_t map_err = SOL_OK;
    uint64_t frames = 0;
    if (vm->stack_frame_size > 0 &&
        (vm->stack_size % (size_t)vm->stack_frame_size) == 0) {
        frames = (uint64_t)vm->stack_size / vm->stack_frame_size;
    }
    if (frames > 1 && sol_bpf_stack_frame_gaps_enabled()) {
        vm->stack_gap_size = vm->stack_frame_size;
        map_err = sol_bpf_memory_add_gapped_region(
            &vm->memory,
            SOL_BPF_MM_STACK_START,
            vm->stack,
            (uint64_t)vm->stack_size,
            vm->stack_frame_size,
            vm->stack_gap_size,
            true,
            &stack_virt_len
        );
        if (map_err == SOL_OK) {
            vm->stack_virt_size = stack_virt_len;
        }
    } else {
        vm->stack_gap_size = 0u;
        map_err = sol_bpf_memory_add_region(
            &vm->memory,
            SOL_BPF_MM_STACK_START,
            vm->stack,
            vm->stack_size,
            true
        );
        if (map_err == SOL_OK) {
            vm->stack_virt_size = (uint64_t)vm->stack_size;
        }
    }
    if (map_err != SOL_OK) {
        return map_err;
    }

    map_err = sol_bpf_memory_add_region(
        &vm->memory,
        SOL_BPF_MM_HEAP_START,
        vm->heap,
        vm->heap_size,
        true
    );
    if (map_err != SOL_OK) {
        return map_err;
    }

    /* Default frame pointer: SBPFv0 (static frames). SBPFv1+ will adjust when
     * a program is attached. */
    vm->reg[10] = SOL_BPF_MM_STACK_START + (uint64_t)vm->stack_frame_size;

    /* Preserve deterministic execution semantics: stack+heap must start as
     * zero for each invocation. For the stack (256 KiB), a full memset per
     * program invocation is expensive; on Linux, when stack/heap are mmap'd,
     * we can discard pages and let them fault back as zero on demand. */
#if defined(__linux__)
    if (sol_bpf_vm_fast_reset_enabled() && vm->stack_is_mmap && vm->stack_alloc_size > 0) {
        if (madvise(vm->stack, vm->stack_alloc_size, MADV_DONTNEED) != 0) {
            memset(vm->stack, 0, vm->stack_size);
        }
    } else {
        memset(vm->stack, 0, vm->stack_size);
    }

    /* Heap is smaller by default (32 KiB). Keep it hot with memset unless the
     * caller explicitly grows it large enough that discarding pages wins. */
    if (sol_bpf_vm_fast_reset_enabled() && vm->heap_is_mmap && vm->heap_alloc_size >= (64u * 1024u)) {
        if (madvise(vm->heap, vm->heap_alloc_size, MADV_DONTNEED) != 0) {
            memset(vm->heap, 0, vm->heap_size);
        }
    } else {
        memset(vm->heap, 0, vm->heap_size);
    }
#else
    memset(vm->stack, 0, vm->stack_size);
    memset(vm->heap, 0, vm->heap_size);
#endif

    /* Rebuild syscall LUT if needed. */
    if (!vm->syscall_lut && vm->syscall_count > 0) {
        build_syscall_lut(vm);
    }

    return SOL_OK;
}

/*
 * Destroy VM
 */
void
sol_bpf_vm_destroy(sol_bpf_vm_t* vm) {
    if (vm == NULL) {
        return;
    }

    sol_free(vm->memory.regions);
#if defined(__linux__)
    if (vm->stack_is_mmap) {
        if (vm->stack && vm->stack_alloc_size) {
            munmap(vm->stack, vm->stack_alloc_size);
        }
    } else {
        sol_free(vm->stack);
    }

    if (vm->heap_is_mmap) {
        if (vm->heap && vm->heap_alloc_size) {
            munmap(vm->heap, vm->heap_alloc_size);
        }
    } else {
        sol_free(vm->heap);
    }
#else
    sol_free(vm->stack);
    sol_free(vm->heap);
#endif
    sol_free(vm->syscalls);
    sol_free(vm->syscall_lut);

    if (vm->program != NULL) {
        sol_bpf_program_destroy(vm->program);
    }

    sol_free(vm);
}

/*
 * Load raw instructions
 */
sol_err_t
sol_bpf_vm_load_raw(
    sol_bpf_vm_t* vm,
    const sol_bpf_insn_t* insns,
    size_t insn_count
) {
    if (vm == NULL || insns == NULL || insn_count == 0) {
        return SOL_ERR_INVAL;
    }

    sol_bpf_program_t* prog = sol_bpf_program_new();
    if (prog == NULL) {
        return SOL_ERR_NOMEM;
    }

    /* Copy instructions into ro_section (text_segment points into it) */
    size_t text_len = insn_count * sizeof(sol_bpf_insn_t);
    prog->ro_section = sol_alloc(text_len);
    if (prog->ro_section == NULL) {
        sol_bpf_program_destroy(prog);
        return SOL_ERR_NOMEM;
    }

    memcpy(prog->ro_section, insns, text_len);
    prog->ro_section_len = text_len;
    prog->text_segment = prog->ro_section;
    prog->instructions = (const sol_bpf_insn_t*)prog->text_segment;
    prog->insn_count = insn_count;
    prog->text_len = text_len;
    prog->entry_pc = 0;

    /* Add ro_section to memory */
    sol_bpf_memory_add_region(&vm->memory, SOL_BPF_MM_PROGRAM_START,
                              prog->ro_section, text_len, false);

    vm->program = prog;
    vm->pc = prog->entry_pc;

    return SOL_OK;
}

/*
 * Set input data
 */
sol_err_t
sol_bpf_vm_set_input(
    sol_bpf_vm_t* vm,
    const uint8_t* data,
    size_t len
) {
    if (vm == NULL) {
        return SOL_ERR_INVAL;
    }

    if (data == NULL || len == 0) {
        vm->reg[1] = 0;
        return SOL_OK;
    }

    /* Add input region (read-only) */
    sol_err_t err = sol_bpf_memory_add_region(
        &vm->memory, SOL_BPF_MM_INPUT_START,
        (uint8_t*)data, len, false
    );

    if (err != SOL_OK) {
        return err;
    }

    /* Set r1 to point to input */
    vm->reg[1] = SOL_BPF_MM_INPUT_START;

    return SOL_OK;
}

/*
 * Register syscall
 */
sol_err_t
sol_bpf_vm_register_syscall(
    sol_bpf_vm_t* vm,
    const char* name,
    sol_bpf_syscall_fn handler
) {
    if (vm == NULL || name == NULL || handler == NULL) {
        return SOL_ERR_INVAL;
    }

    /* Grow syscall array if needed */
    if (vm->syscall_count >= vm->syscall_cap) {
        size_t new_cap = vm->syscall_cap == 0 ? 32 : vm->syscall_cap * 2;
        sol_bpf_syscall_t* new_syscalls = sol_realloc(
            vm->syscalls, new_cap * sizeof(sol_bpf_syscall_t)
        );
        if (new_syscalls == NULL) {
            return SOL_ERR_NOMEM;
        }
        vm->syscalls = new_syscalls;
        vm->syscall_cap = new_cap;
    }

    /* Add syscall */
    sol_bpf_syscall_t* syscall = &vm->syscalls[vm->syscall_count++];
    syscall->name = name;
    syscall->hash = sol_bpf_syscall_hash(name);
    syscall->handler = handler;

    /* Registry mutated: drop LUT so it is rebuilt on next reset/new. */
    if (vm->syscall_lut) {
        sol_free(vm->syscall_lut);
        vm->syscall_lut = NULL;
        vm->syscall_lut_cap = 0;
    }

    return SOL_OK;
}

/*
 * Set context
 */
void
sol_bpf_vm_set_context(sol_bpf_vm_t* vm, void* ctx) {
    if (vm != NULL) {
        vm->context = ctx;
    }
}

void
sol_bpf_vm_set_cpi_handler(sol_bpf_vm_t* vm, sol_bpf_cpi_handler_t handler) {
    if (vm != NULL) {
        vm->cpi_handler = handler;
    }
}

/*
 * Find syscall by hash
 */
static sol_bpf_syscall_t*
find_syscall(sol_bpf_vm_t* vm, uint32_t hash) {
    if (vm->syscall_lut && vm->syscall_lut_cap) {
        size_t mask = vm->syscall_lut_cap - 1u;
        size_t idx = (size_t)(((uint64_t)hash * 11400714819323198485ull) & (uint64_t)mask);
        for (;;) {
            sol_bpf_syscall_lut_entry_t* e = &vm->syscall_lut[idx];
            if (e->syscall == NULL) {
                break;
            }
            if (e->hash == hash) {
                return e->syscall;
            }
            idx = (idx + 1u) & mask;
        }
        return NULL;
    }

    for (size_t i = 0; i < vm->syscall_count; i++) {
        if (vm->syscalls[i].hash == hash) {
            return &vm->syscalls[i];
        }
    }
    return NULL;
}

/*
 * Execute interpreter
 */
sol_err_t
sol_bpf_vm_execute(sol_bpf_vm_t* vm) {
    if (vm == NULL || vm->program == NULL) {
        return SOL_ERR_INVAL;
    }

    vm->error = SOL_BPF_OK;

    /* Keep hot execution state in locals so the compiler can keep them in
     * registers across the massive interpreter loop.  Sync back to `vm` at
     * the end and at syscall boundaries. */
    sol_bpf_state_t state = SOL_BPF_STATE_RUNNING;
    uint64_t pc = vm->pc;
    uint64_t compute_limit = vm->compute_units;
    uint64_t compute_used = vm->compute_units_used;
    uint64_t compute_left = compute_used >= compute_limit ? 0u : (compute_limit - compute_used);
    uint64_t* reg = vm->reg;

    /* Precompute canonical region pointers for fast fixed-tag translations. */
    sol_bpf_memory_t* mem = &vm->memory;
    const sol_bpf_region_t* fixed_regions[5] = {0};
    size_t fixed_region_idx[5] = {0};
    for (size_t tag = 1u; tag < 5u; tag++) {
        uint16_t idx1 = mem->fixed_region_idx[tag];
        if (idx1 != 0u && (size_t)idx1 <= mem->region_count) {
            size_t idx = (size_t)idx1 - 1u;
            fixed_regions[tag] = &mem->regions[idx];
            fixed_region_idx[tag] = idx;
        }
    }

    const sol_bpf_insn_t* insns = vm->program->instructions;
    size_t insn_count = vm->program->insn_count;
    sol_sbpf_version_t sbpf_ver = vm->program->sbpf_version;
    bool v2_mem_classes = sol_sbpf_move_mem_classes(sbpf_ver);
    bool dynamic_frames = sol_sbpf_dynamic_stack_frames(sbpf_ver);
    bool callx_uses_src = sol_sbpf_callx_uses_src(sbpf_ver);
    bool swap_sub_operands = sol_sbpf_swap_sub_operands(sbpf_ver);
    bool explicit_sign_ext = sol_sbpf_explicit_sign_ext(sbpf_ver); /* sign/zero extension is unconditional per Agave rbpf 0.8.3 */

    /* Capturing per-instruction trace state is extremely expensive. Gate behind
     * an env var so mainnet replay isn't dominated by debug bookkeeping. */
    static int trace_ring_enabled_cached = -1;
    if (trace_ring_enabled_cached < 0) {
        const char* env = getenv("SOL_BPF_TRACE_RING");
        trace_ring_enabled_cached = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    }
    bool capture_trace_ring = trace_ring_enabled_cached != 0;

    /* Post-mortem ring buffer: capture last N instructions for error diagnosis.
     * Use 8192 to capture full execution of programs like MNFSTq (7205 insns).
     * Static buffer to avoid stack overflow. */
#define TRACE_RING_SIZE 8192
#define TRACE_RING_MASK (TRACE_RING_SIZE - 1)
    typedef struct { uint64_t pc; uint8_t opcode; uint8_t dst; uint8_t src; int16_t off; int32_t imm; uint64_t reg_dst; uint64_t reg_src; } trace_entry_t;
    static __thread trace_entry_t trace_ring[TRACE_RING_SIZE];
    uint32_t trace_ring_pos = 0;

    /* Cache seldom-enabled flags outside the hot loop. */
    const bool vm_trace = vm->trace;
    const bool do_syscall_prof = syscall_prof_enabled();

    while (state == SOL_BPF_STATE_RUNNING) {
        /* Check compute budget */
        if (__builtin_expect(compute_left == 0u, 0)) {
            vm->error = SOL_BPF_ERR_COMPUTE_EXCEEDED;
            state = SOL_BPF_STATE_ERROR;
            goto done;
        }

        /* Bounds check PC */
        if (__builtin_expect(pc >= insn_count, 0)) {
            vm->error = SOL_BPF_ERR_CALL_OUTSIDE_TEXT;
            state = SOL_BPF_STATE_ERROR;
            goto done;
        }

        const sol_bpf_insn_t* insn = &insns[pc];
        uint8_t dst = SOL_BPF_INSN_DST(insn);
        uint8_t src = SOL_BPF_INSN_SRC(insn);
        int16_t off = insn->offset;
        int32_t imm = insn->imm;

        pc++;
        compute_left--;

        uint8_t op_class = SOL_BPF_OP_CLASS(insn->opcode);
        uint8_t op_code = SOL_BPF_OP_CODE(insn->opcode);

        bool use_imm = (SOL_BPF_OP_SRC(insn->opcode) == SOL_BPF_SRC_K);

        /* Record to post-mortem ring buffer */
        if (__builtin_expect(capture_trace_ring, 0)) {
            uint32_t ti = trace_ring_pos & TRACE_RING_MASK;
            trace_ring[ti].pc = pc - 1u;
            trace_ring[ti].opcode = insn->opcode;
            trace_ring[ti].dst = dst;
            trace_ring[ti].src = src;
            trace_ring[ti].off = off;
            trace_ring[ti].imm = imm;
            trace_ring[ti].reg_dst = reg[dst];
            trace_ring[ti].reg_src = reg[src];
            trace_ring_pos++;
        }

        if (__builtin_expect(vm_trace, 0)) {
            sol_log_info("BPF_TRACE: pc=%lu op=0x%02x dst=r%u src=r%u off=%d imm=%d "
                         "r0=0x%lx r1=0x%lx r2=0x%lx r3=0x%lx r4=0x%lx r5=0x%lx "
                         "r6=0x%lx r7=0x%lx r8=0x%lx r9=0x%lx r10=0x%lx",
                         (unsigned long)(pc - 1u), insn->opcode, dst, src, (int)off, (int)imm,
                         (unsigned long)reg[0], (unsigned long)reg[1],
                         (unsigned long)reg[2], (unsigned long)reg[3],
                         (unsigned long)reg[4], (unsigned long)reg[5],
                         (unsigned long)reg[6], (unsigned long)reg[7],
                         (unsigned long)reg[8], (unsigned long)reg[9],
                         (unsigned long)reg[10]);
        }

        switch (op_class) {
        case SOL_BPF_CLASS_ALU64: {
            /* SBPFv2: MUL/DIV/NEG/MOD opcodes in ALU64 class become memory stores */
            if (__builtin_expect(v2_mem_classes, 0) &&
                (op_code == SOL_BPF_ALU_MUL || op_code == SOL_BPF_ALU_DIV ||
                 op_code == SOL_BPF_ALU_NEG || op_code == SOL_BPF_ALU_MOD)) {
                size_t st_len;
                switch (op_code) {
                case SOL_BPF_ALU_MUL: st_len = 1; break;
                case SOL_BPF_ALU_DIV: st_len = 2; break;
                case SOL_BPF_ALU_NEG: st_len = 4; break;
                default:              st_len = 8; break; /* MOD */
                }
				                uint64_t addr = reg[dst] + off;
				                uint8_t* host_addr = sol_bpf_memory_translate_fixed_fast(mem, fixed_regions, fixed_region_idx, addr, st_len, true);
				                if (host_addr == NULL) {
				                    vm->pc = pc;
				                    sol_bpf_vm_record_fault(vm, addr, (uint64_t)st_len, true);
				                    vm->error = SOL_BPF_ERR_ACCESS_VIOLATION;
				                    state = SOL_BPF_STATE_ERROR;
			                    goto done;
			                }
                uint64_t val = use_imm ? (uint64_t)(int64_t)imm : reg[src];
                switch (st_len) {
                case 1: *(uint8_t*)host_addr  = (uint8_t)val;  break;
                case 2: *(uint16_t*)host_addr = (uint16_t)val; break;
                case 4: *(uint32_t*)host_addr = (uint32_t)val; break;
                case 8: *(uint64_t*)host_addr = val;           break;
                }
                break;
            }

            uint64_t src_val = use_imm ? (uint64_t)(int64_t)imm : reg[src];

            switch (op_code) {
            case SOL_BPF_ALU_ADD:
                reg[dst] += src_val;
                break;
            case SOL_BPF_ALU_SUB:
                if (__builtin_expect(swap_sub_operands, 0) && use_imm)
                    reg[dst] = src_val - reg[dst];
                else
                    reg[dst] -= src_val;
                break;
            case SOL_BPF_ALU_MUL:
                reg[dst] *= src_val;
                break;
            case SOL_BPF_ALU_DIV:
                if (src_val == 0) {
                    vm->error = SOL_BPF_ERR_DIVIDE_BY_ZERO;
                    state = SOL_BPF_STATE_ERROR;
                    goto done;
                }
                reg[dst] /= src_val;
                break;
            case SOL_BPF_ALU_OR:
                reg[dst] |= src_val;
                break;
            case SOL_BPF_ALU_AND:
                reg[dst] &= src_val;
                break;
            case SOL_BPF_ALU_LSH:
                reg[dst] <<= (src_val & 63);
                break;
            case SOL_BPF_ALU_RSH:
                reg[dst] >>= (src_val & 63);
                break;
            case SOL_BPF_ALU_NEG:
                /* V2: NEG disabled (op_code=0x80 is handled as store above) */
                reg[dst] = (uint64_t)(-(int64_t)reg[dst]);
                break;
		            case SOL_BPF_ALU_MOD:
		                if (src_val == 0) {
		                    sol_log_info("BPF_DIAG: ALU64 MOD div0 pc=%lu opcode=0x%02x v2_mem=%d sbpf_ver=%d",
		                                 (unsigned long)(pc - 1u), insn->opcode, (int)v2_mem_classes, (int)sbpf_ver);
		                    vm->error = SOL_BPF_ERR_DIVIDE_BY_ZERO;
		                    state = SOL_BPF_STATE_ERROR;
		                    goto done;
		                }
                reg[dst] %= src_val;
                break;
            case SOL_BPF_ALU_XOR:
                reg[dst] ^= src_val;
                break;
            case SOL_BPF_ALU_MOV:
                reg[dst] = src_val;
                break;
            case SOL_BPF_ALU_ARSH:
                reg[dst] = (uint64_t)((int64_t)reg[dst] >> (src_val & 63));
                break;
            case SOL_BPF_ALU_HOR:
                /* SBPFv2+: High OR — r_dst |= ((u64)imm << 32)
                 * Used in place of LDDW to construct 64-bit constants.
                 * Always uses the immediate field, regardless of BPF_K/BPF_X flag. */
                reg[dst] |= ((uint64_t)(uint32_t)imm << 32);
                break;
            default:
                vm->error = SOL_BPF_ERR_INVALID_INSN;
                state = SOL_BPF_STATE_ERROR;
                goto done;
            }
            break;
        }

        case SOL_BPF_CLASS_ALU: {
            /* SBPFv2: MUL/DIV/NEG/MOD opcodes in ALU32 class become memory loads
             * (only with BPF_X / register source) */
            if (__builtin_expect(v2_mem_classes, 0) && !use_imm &&
                (op_code == SOL_BPF_ALU_MUL || op_code == SOL_BPF_ALU_DIV ||
                 op_code == SOL_BPF_ALU_NEG || op_code == SOL_BPF_ALU_MOD)) {
                size_t ld_len;
                switch (op_code) {
                case SOL_BPF_ALU_MUL: ld_len = 1; break;
                case SOL_BPF_ALU_DIV: ld_len = 2; break;
                case SOL_BPF_ALU_NEG: ld_len = 4; break;
                default:              ld_len = 8; break; /* MOD */
                }
				                uint64_t addr = reg[src] + off;
				                uint8_t* host_addr = sol_bpf_memory_translate_fixed_fast(mem, fixed_regions, fixed_region_idx, addr, ld_len, false);
				                if (host_addr == NULL) {
				                    vm->pc = pc;
				                    sol_bpf_vm_record_fault(vm, addr, (uint64_t)ld_len, false);
				                    vm->error = SOL_BPF_ERR_ACCESS_VIOLATION;
				                    state = SOL_BPF_STATE_ERROR;
			                    goto done;
			                }
			                switch (ld_len) {
			                case 1: reg[dst] = *(uint8_t*)host_addr;  break;
			                case 2: reg[dst] = *(uint16_t*)host_addr; break;
			                case 4: reg[dst] = *(uint32_t*)host_addr; break;
			                case 8: reg[dst] = *(uint64_t*)host_addr; break;
			                }
			                break;
			            }

	            uint32_t dst_val = (uint32_t)reg[dst];
	            uint32_t src_val = use_imm ? (uint32_t)imm : (uint32_t)reg[src];

            /* ALU32 result extension rules (matching Agave rbpf):
             *   V0/V1: ADD/SUB/MUL sign-extend (sign_extension() with !explicit_sign_ext)
             *   V2+:   ADD/SUB/MUL zero-extend (sign_extension() with explicit_sign_ext)
             *   MOV32_REG: V2+ sign-extends, V0/V1 zero-extends
             *   All other ops: always zero-extend. */
            bool sign_ext_arith = !explicit_sign_ext;
            switch (op_code) {
            case SOL_BPF_ALU_ADD:
                if (sign_ext_arith) {
                    reg[dst] = (uint64_t)(int64_t)(int32_t)(dst_val + src_val);
                } else {
                    reg[dst] = (uint64_t)(uint32_t)(dst_val + src_val);
                }
                break;
            case SOL_BPF_ALU_SUB:
                if (__builtin_expect(swap_sub_operands, 0) && use_imm) {
                    if (sign_ext_arith) {
                        reg[dst] = (uint64_t)(int64_t)(int32_t)(src_val - dst_val);
                    } else {
                        reg[dst] = (uint64_t)(uint32_t)(src_val - dst_val);
                    }
                } else {
                    if (sign_ext_arith) {
                        reg[dst] = (uint64_t)(int64_t)(int32_t)(dst_val - src_val);
                    } else {
                        reg[dst] = (uint64_t)(uint32_t)(dst_val - src_val);
                    }
                }
                break;
            case SOL_BPF_ALU_MUL:
                if (sign_ext_arith) {
                    reg[dst] = (uint64_t)(int64_t)(int32_t)(dst_val * src_val);
                } else {
                    reg[dst] = (uint64_t)(uint32_t)(dst_val * src_val);
                }
                break;
	            case SOL_BPF_ALU_DIV:
	                if (src_val == 0) {
	                    vm->error = SOL_BPF_ERR_DIVIDE_BY_ZERO;
	                    state = SOL_BPF_STATE_ERROR;
	                    goto done;
	                }
                        reg[dst] = (uint64_t)(dst_val / src_val);
                        break;
            case SOL_BPF_ALU_OR:
                reg[dst] = (uint64_t)(dst_val | src_val);
                break;
            case SOL_BPF_ALU_AND:
                reg[dst] = (uint64_t)(dst_val & src_val);
                break;
            case SOL_BPF_ALU_LSH:
                reg[dst] = (uint64_t)(dst_val << (src_val & 31));
                break;
            case SOL_BPF_ALU_RSH:
                reg[dst] = (uint64_t)(dst_val >> (src_val & 31));
                break;
            case SOL_BPF_ALU_NEG:
                /* V2: NEG disabled - would have been caught as LD above for reg source.
                 * IMM source NEG reaching here is invalid in V2. */
                reg[dst] = (uint64_t)(uint32_t)(-(int32_t)dst_val);
                break;
		            case SOL_BPF_ALU_MOD:
		                if (src_val == 0) {
		                    sol_log_info("BPF_DIAG: ALU32 MOD div0 pc=%lu opcode=0x%02x v2_mem=%d use_imm=%d sbpf_ver=%d "
		                                 "dst=r%u(0x%lx) src=r%u(0x%lx)",
		                                 (unsigned long)(pc - 1u), insn->opcode, (int)v2_mem_classes,
		                                 (int)use_imm, (int)sbpf_ver,
		                                 dst, (unsigned long)reg[dst], src, (unsigned long)reg[src]);
		                    vm->error = SOL_BPF_ERR_DIVIDE_BY_ZERO;
		                    state = SOL_BPF_STATE_ERROR;
		                    goto done;
		                }
                reg[dst] = (uint64_t)(dst_val % src_val);
                break;
            case SOL_BPF_ALU_XOR:
                reg[dst] = (uint64_t)(dst_val ^ src_val);
                break;
            case SOL_BPF_ALU_MOV:
                if (!use_imm && explicit_sign_ext) {
                    /* V2+ MOV32_REG: sign-extend (Agave: self.reg[src] as i32 as i64 as u64) */
                    reg[dst] = (uint64_t)(int64_t)(int32_t)src_val;
                } else {
                    /* V0/V1 MOV32_REG or any MOV32_IMM: zero-extend */
                    reg[dst] = (uint64_t)src_val;
                }
                break;
            case SOL_BPF_ALU_ARSH:
                reg[dst] = (uint64_t)(uint32_t)((int32_t)dst_val >> (src_val & 31));
                break;
            case SOL_BPF_ALU_END:
                if (use_imm) {
                    /* LE (BPF_TO_LE, opcode 0xd4): on a little-endian host
                       this is a no-op except for truncation + zero-extension. */
                    if (imm == 16) {
                        reg[dst] = (uint16_t)reg[dst];
                    } else if (imm == 32) {
                        reg[dst] = (uint32_t)reg[dst];
                    } else if (imm == 64) {
                        /* le64 is a true no-op */
                    }
                } else {
                    /* BE (BPF_TO_BE, opcode 0xdc): byte swap + zero-extension. */
                    if (imm == 16) {
                        reg[dst] = __builtin_bswap16((uint16_t)reg[dst]);
                    } else if (imm == 32) {
                        reg[dst] = __builtin_bswap32((uint32_t)reg[dst]);
                    } else if (imm == 64) {
                        reg[dst] = __builtin_bswap64(reg[dst]);
                    }
                }
                break;
            default:
                vm->error = SOL_BPF_ERR_INVALID_INSN;
                state = SOL_BPF_STATE_ERROR;
                goto done;
            }
            break;
        }

        case SOL_BPF_CLASS_JMP:
        case SOL_BPF_CLASS_JMP32: /* == SOL_BPF_CLASS_PQR (0x06) */ {
            /* Solana SBPF uses op class 0x06 for PQR (product/quotient/remainder).
             * JMP32 is not used by Solana programs in practice, so treat 0x06
             * as PQR unconditionally to match the runtime environment used for
             * on-chain programs and unit tests. */
            if (op_class == SOL_BPF_CLASS_JMP32) {
                goto handle_pqr;
            }
            uint64_t dst_val = reg[dst];
            uint64_t src_val = use_imm ? (uint64_t)(int64_t)imm : reg[src];

            if (op_class == SOL_BPF_CLASS_JMP32) {
                dst_val = (uint32_t)dst_val;
                src_val = (uint32_t)src_val;
            }

            bool jump = false;

            switch (op_code) {
            case SOL_BPF_JMP_JA:
                jump = true;
                break;
            case SOL_BPF_JMP_JEQ:
                jump = (dst_val == src_val);
                break;
            case SOL_BPF_JMP_JGT:
                jump = (dst_val > src_val);
                break;
            case SOL_BPF_JMP_JGE:
                jump = (dst_val >= src_val);
                break;
            case SOL_BPF_JMP_JSET:
                jump = (dst_val & src_val) != 0;
                break;
            case SOL_BPF_JMP_JNE:
                jump = (dst_val != src_val);
                break;
            case SOL_BPF_JMP_JSGT:
                jump = ((int64_t)dst_val > (int64_t)src_val);
                break;
            case SOL_BPF_JMP_JSGE:
                jump = ((int64_t)dst_val >= (int64_t)src_val);
                break;
            case SOL_BPF_JMP_JLT:
                jump = (dst_val < src_val);
                break;
            case SOL_BPF_JMP_JLE:
                jump = (dst_val <= src_val);
                break;
            case SOL_BPF_JMP_JSLT:
                jump = ((int64_t)dst_val < (int64_t)src_val);
                break;
            case SOL_BPF_JMP_JSLE:
                jump = ((int64_t)dst_val <= (int64_t)src_val);
                break;
	            case SOL_BPF_JMP_CALL:
	                if (!use_imm) {
                    /* callx: indirect internal call.
                       V0: register number is in imm field.
                       V2+: register number is in src field. */
	                    uint32_t callx_reg = callx_uses_src ? (uint32_t)src : (uint32_t)imm;
	                    if (callx_reg >= SOL_BPF_NUM_REGISTERS) {
	                        vm->error = SOL_BPF_ERR_INVALID_INSN;
	                        state = SOL_BPF_STATE_ERROR;
	                        goto done;
	                    }

	                    uint64_t target_addr = reg[callx_reg];
	                    uint64_t text_start = SOL_BPF_MM_PROGRAM_START + vm->program->text_vaddr;
	                    uint64_t text_end = text_start + vm->program->text_len;
		                    if (target_addr < text_start ||
		                        target_addr >= text_end ||
		                        ((target_addr - text_start) & 7u) != 0) {
		                        sol_log_debug("SBF callx target outside text: pc=%lu reg=%u target=0x%lx text=[0x%lx..0x%lx)",
		                                      (unsigned long)(pc ? (pc - 1u) : 0u),
		                                      (unsigned)callx_reg,
		                                      (unsigned long)target_addr,
		                                      (unsigned long)text_start,
		                                      (unsigned long)text_end);
	                        vm->error = SOL_BPF_ERR_CALL_OUTSIDE_TEXT;
	                        state = SOL_BPF_STATE_ERROR;
	                        goto done;
	                    }

                    uint64_t target_pc = (target_addr - text_start) / 8u;

	                    if (vm->call_depth >= SOL_BPF_MAX_CALL_DEPTH) {
	                        vm->error = SOL_BPF_ERR_CALL_DEPTH;
	                        state = SOL_BPF_STATE_ERROR;
	                        goto done;
	                    }

	                    sol_bpf_frame_t* frame = &vm->call_stack[vm->call_depth++];
		                    frame->saved_regs[0] = reg[6];
		                    frame->saved_regs[1] = reg[7];
		                    frame->saved_regs[2] = reg[8];
		                    frame->saved_regs[3] = reg[9];
		                    frame->return_pc = pc;
		                    frame->frame_ptr = reg[10];

                    /* V0 (static frames): advance r10 to next frame.
                     * V1+ (dynamic frames): r10 is NOT advanced by the VM;
                     *   the callee manages its own stack pointer. */
	                    if (!dynamic_frames) {
	                        uint64_t stride = (uint64_t)vm->stack_frame_size + (uint64_t)vm->stack_gap_size;
	                        reg[10] += stride;
	                    }

		                    pc = target_pc;
		                    break;
		                }

		                /* call: src=0 syscall (imm=hash), src=1 internal (imm=PC rel). */
		                if (src == 0) {
			                    sol_bpf_syscall_t* syscall = find_syscall(vm, (uint32_t)imm);
			                    if (syscall == NULL) {
                                    uint64_t used = compute_limit - compute_left;
			                        sol_log_error("BPF: unknown syscall hash=0x%08x cu_used=%lu",
			                                      (unsigned)imm, (unsigned long)used);
			                        vm->error = SOL_BPF_ERR_UNKNOWN_SYSCALL;
			                        state = SOL_BPF_STATE_ERROR;
			                        goto done;
			                    }

			                    /* Syscalls charge compute units and may set vm->state=ERROR. */
			                    vm->compute_units_used = compute_limit - compute_left;
			                    vm->state = state;
			                    vm->pc = pc;

			                    {
			                        uint64_t ret = 0;
			                        if (__builtin_expect(do_syscall_prof, 0)) {
			                            syscall_prof_init_table(vm);
			                            uint64_t t0 = syscall_prof_now_ns();
			                            ret = syscall->handler(
			                                vm,
			                                reg[1], reg[2], reg[3],
		                                reg[4], reg[5]
		                            );
		                            uint64_t t1 = syscall_prof_now_ns();
		                            size_t sidx = (size_t)(syscall - vm->syscalls);
		                            if (g_syscall_prof &&
		                                __builtin_expect(sidx < g_syscall_prof_len, 1)) {
		                                __atomic_fetch_add(&g_syscall_prof[sidx].count, 1u, __ATOMIC_RELAXED);
		                                __atomic_fetch_add(&g_syscall_prof[sidx].ns, t1 - t0, __ATOMIC_RELAXED);
		                            }
		                        } else {
		                            ret = syscall->handler(
		                                vm,
		                                reg[1], reg[2], reg[3],
		                                reg[4], reg[5]
		                            );
			                        }
			                        reg[0] = ret;
			                    }

			                    compute_left = compute_limit - vm->compute_units_used;
			                    state = vm->state;
			                    if (__builtin_expect(state != SOL_BPF_STATE_RUNNING, 0)) {
			                        goto done;
			                    }
			                    break;
		                }

	                if (src != 1) {
	                    vm->error = SOL_BPF_ERR_INVALID_INSN;
	                    state = SOL_BPF_STATE_ERROR;
	                    goto done;
	                }

		                int64_t target_pc = (int64_t)pc + (int64_t)imm;
		                if (target_pc < 0 || (size_t)target_pc >= insn_count) {
		                    vm->error = SOL_BPF_ERR_CALL_OUTSIDE_TEXT;
		                    state = SOL_BPF_STATE_ERROR;
		                    goto done;
		                }

                /* Internal function call */
	                if (vm->call_depth >= SOL_BPF_MAX_CALL_DEPTH) {
	                    vm->error = SOL_BPF_ERR_CALL_DEPTH;
	                    state = SOL_BPF_STATE_ERROR;
	                    goto done;
	                }

                /* Save frame */
	                sol_bpf_frame_t* frame = &vm->call_stack[vm->call_depth++];
		                frame->saved_regs[0] = reg[6];
		                frame->saved_regs[1] = reg[7];
		                frame->saved_regs[2] = reg[8];
		                frame->saved_regs[3] = reg[9];
		                frame->return_pc = pc;
		                frame->frame_ptr = reg[10];

                /* V0 (static frames): advance r10 to next frame.
                 * V1+ (dynamic frames): r10 is NOT advanced by the VM. */
	                if (!dynamic_frames) {
	                    uint64_t stride = (uint64_t)vm->stack_frame_size + (uint64_t)vm->stack_gap_size;
	                    reg[10] += stride;
		                }

		                /* Jump to function */
		                pc = (uint64_t)target_pc;
		                break;
		            case SOL_BPF_JMP_EXIT:
		                if (vm->call_depth == 0) {
	                    /* Exit program */
	                    if (reg[0] >= 0x100000000ULL) {
	                        static int exit_diag_cached = -1;
	                        if (exit_diag_cached < 0) {
	                            const char* env = getenv("SOL_BPF_EXIT_DIAG");
	                            exit_diag_cached = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
	                        }
				                        if (exit_diag_cached) {
                                            uint64_t used = compute_limit - compute_left;
				                            sol_log_info("BPF EXIT_DIAG: r0=0x%lx r1=0x%lx r2=0x%lx pc=%lu cu=%lu",
				                                         (unsigned long)reg[0], (unsigned long)reg[1],
				                                         (unsigned long)reg[2], (unsigned long)pc,
				                                         (unsigned long)used);
				                        }
				                    }
			                    vm->return_value = reg[0];
			                    state = SOL_BPF_STATE_STOPPED;
		                    goto done;
	                } else {
	                    /* Return from function call */
		                    sol_bpf_frame_t* ret_frame = &vm->call_stack[--vm->call_depth];
			                    reg[6] = ret_frame->saved_regs[0];
			                    reg[7] = ret_frame->saved_regs[1];
			                    reg[8] = ret_frame->saved_regs[2];
			                    reg[9] = ret_frame->saved_regs[3];
			                    pc = ret_frame->return_pc;
			                    reg[10] = ret_frame->frame_ptr;
			                }
		                break;
	            default:
	                vm->error = SOL_BPF_ERR_INVALID_INSN;
	                state = SOL_BPF_STATE_ERROR;
	                goto done;
		            }

		            if (jump && op_code != SOL_BPF_JMP_CALL && op_code != SOL_BPF_JMP_EXIT) {
		                pc += off;
		            }
		            break;
		        }

        case SOL_BPF_CLASS_LD: {
            uint8_t mode = SOL_BPF_OP_MODE(insn->opcode);
            uint8_t size = SOL_BPF_OP_SIZE(insn->opcode);

	            if (mode == SOL_BPF_MODE_IMM && size == SOL_BPF_SIZE_DW) {
	                /* LDDW - 64-bit immediate load (2 instructions).
	                 * Disabled in SBPFv2+. */
	                if (__builtin_expect(sol_sbpf_disable_lddw(sbpf_ver), 0)) {
	                    vm->error = SOL_BPF_ERR_INVALID_INSN;
	                    state = SOL_BPF_STATE_ERROR;
	                    goto done;
	                }
	                if (pc >= insn_count) {
	                    vm->error = SOL_BPF_ERR_INVALID_INSN;
	                    state = SOL_BPF_STATE_ERROR;
	                    goto done;
		                }

		                const sol_bpf_insn_t* insn2 = &insns[pc++];
		                /* Do NOT charge extra CU here. rbpf counts LDDW as 1
		                   instruction for metering despite occupying 2 slots. */

		                uint64_t val = (uint64_t)(uint32_t)imm |
	                               ((uint64_t)(uint32_t)insn2->imm << 32);
	                reg[dst] = val;
	            } else {
	                vm->error = SOL_BPF_ERR_INVALID_INSN;
	                state = SOL_BPF_STATE_ERROR;
	                goto done;
	            }
            break;
        }

        case SOL_BPF_CLASS_LDX: {
            uint8_t size = SOL_BPF_OP_SIZE(insn->opcode);
            uint64_t addr = reg[src] + off;
            size_t len;

            switch (size) {
            case SOL_BPF_SIZE_B:  len = 1; break;
            case SOL_BPF_SIZE_H:  len = 2; break;
            case SOL_BPF_SIZE_W:  len = 4; break;
            case SOL_BPF_SIZE_DW: len = 8; break;
            default:
                vm->error = SOL_BPF_ERR_INVALID_INSN;
                state = SOL_BPF_STATE_ERROR;
                goto done;
            }

            uint8_t* host_addr = sol_bpf_memory_translate_fixed_fast(mem, fixed_regions, fixed_region_idx, addr, len, false);
            if (host_addr == NULL) {
                vm->pc = pc;
                sol_bpf_vm_record_fault(vm, addr, (uint64_t)len, false);
                vm->error = SOL_BPF_ERR_ACCESS_VIOLATION;
                state = SOL_BPF_STATE_ERROR;
                goto done;
            }

            switch (size) {
            case SOL_BPF_SIZE_B:
                reg[dst] = *(uint8_t*)host_addr;
                break;
            case SOL_BPF_SIZE_H:
                reg[dst] = *(uint16_t*)host_addr;
                break;
            case SOL_BPF_SIZE_W:
                reg[dst] = *(uint32_t*)host_addr;
                break;
            case SOL_BPF_SIZE_DW:
                reg[dst] = *(uint64_t*)host_addr;
                break;
            }

            if (__builtin_expect(vm->trace, 0)) {
                sol_log_info("BPF_TRACE_LDX: vaddr=0x%lx len=%zu val=0x%lx -> r%u",
                             (unsigned long)addr, len, (unsigned long)reg[dst], dst);
            }
            break;
        }

        case SOL_BPF_CLASS_ST: {
            uint8_t size = SOL_BPF_OP_SIZE(insn->opcode);
            uint64_t addr = reg[dst] + off;
            size_t len;

            switch (size) {
            case SOL_BPF_SIZE_B:  len = 1; break;
            case SOL_BPF_SIZE_H:  len = 2; break;
            case SOL_BPF_SIZE_W:  len = 4; break;
            case SOL_BPF_SIZE_DW: len = 8; break;
            default:
                vm->error = SOL_BPF_ERR_INVALID_INSN;
                state = SOL_BPF_STATE_ERROR;
                goto done;
            }

            uint8_t* host_addr = sol_bpf_memory_translate_fixed_fast(mem, fixed_regions, fixed_region_idx, addr, len, true);
            if (host_addr == NULL) {
                vm->pc = pc;
                sol_bpf_vm_record_fault(vm, addr, (uint64_t)len, true);
                vm->error = SOL_BPF_ERR_ACCESS_VIOLATION;
                state = SOL_BPF_STATE_ERROR;
                goto done;
            }

            switch (size) {
            case SOL_BPF_SIZE_B:
                *(uint8_t*)host_addr = (uint8_t)imm;
                break;
            case SOL_BPF_SIZE_H:
                *(uint16_t*)host_addr = (uint16_t)imm;
                break;
            case SOL_BPF_SIZE_W:
                *(uint32_t*)host_addr = (uint32_t)imm;
                break;
            case SOL_BPF_SIZE_DW:
                *(uint64_t*)host_addr = (uint64_t)(int64_t)imm;
                break;
            }
            break;
        }

        case SOL_BPF_CLASS_STX: {
            uint8_t size = SOL_BPF_OP_SIZE(insn->opcode);
            uint64_t addr = reg[dst] + off;
            size_t len;

            switch (size) {
            case SOL_BPF_SIZE_B:  len = 1; break;
            case SOL_BPF_SIZE_H:  len = 2; break;
            case SOL_BPF_SIZE_W:  len = 4; break;
            case SOL_BPF_SIZE_DW: len = 8; break;
            default:
                vm->error = SOL_BPF_ERR_INVALID_INSN;
                state = SOL_BPF_STATE_ERROR;
                goto done;
            }

            uint8_t* host_addr = sol_bpf_memory_translate_fixed_fast(mem, fixed_regions, fixed_region_idx, addr, len, true);
            if (host_addr == NULL) {
                vm->pc = pc;
                sol_bpf_vm_record_fault(vm, addr, (uint64_t)len, true);
                vm->error = SOL_BPF_ERR_ACCESS_VIOLATION;
                state = SOL_BPF_STATE_ERROR;
                goto done;
            }

            switch (size) {
            case SOL_BPF_SIZE_B:
                *(uint8_t*)host_addr = (uint8_t)reg[src];
                break;
            case SOL_BPF_SIZE_H:
                *(uint16_t*)host_addr = (uint16_t)reg[src];
                break;
            case SOL_BPF_SIZE_W:
                *(uint32_t*)host_addr = (uint32_t)reg[src];
                break;
            case SOL_BPF_SIZE_DW:
                *(uint64_t*)host_addr = reg[src];
                break;
            }
            break;
        }

	        handle_pqr: {
            /* SBPFv2+ PQR class: Product/Quotient/Remainder instructions.
             * Format: bits 5-7 = operation, bit 4 (BPF_B=0x10) = 64-bit,
             * bit 3 (BPF_X=0x08) = register source, bits 0-2 = class.
             *
             * IMM operand extension (matching Agave rbpf):
             *   Signed ops (LMUL, SHMUL, SDIV, SREM): sign-extend  (imm as i64 as u64)
             *   Unsigned ops (UHMUL, UDIV, UREM):     zero-extend  (imm as u32 as u64)
             *
             * 32-bit result extension (matching Agave rbpf):
             *   LMUL32, UDIV32, UREM32: zero-extend  (result as u32 as u64)
             *   SDIV32, SREM32:         zero-extend  (result as u32 as u64)
             *   SHMUL32:                sign-extend  (result as i32 as i64 as u64) */

            bool pqr_64 = (insn->opcode & SOL_BPF_PQR_64) != 0;
            uint8_t pqr_op = insn->opcode & 0xe0; /* operation in bits 5-7 */

	            switch (pqr_op) {
	            case SOL_BPF_PQR_LMUL: {
	                uint64_t pqr_src = use_imm ? (uint64_t)(int64_t)imm : reg[src];
	                if (pqr_64)
	                    reg[dst] *= pqr_src;
	                else {
	                    uint32_t r = (uint32_t)reg[dst] * (uint32_t)pqr_src;
	                    reg[dst] = (uint64_t)r; /* zero-extend (rbpf: wrapping_mul as u64) */
	                }
	                break;
	            }
	            case SOL_BPF_PQR_UHMUL: {
	                /* Unsigned: zero-extend immediate */
	                uint64_t pqr_src = use_imm ? (uint64_t)(uint32_t)imm : reg[src];
	                if (pqr_64)
	                    reg[dst] = (uint64_t)((__uint128_t)reg[dst] * (__uint128_t)pqr_src >> 64);
	                else {
	                    uint32_t r = (uint32_t)(((uint64_t)(uint32_t)reg[dst] * (uint64_t)(uint32_t)pqr_src) >> 32);
	                    reg[dst] = (uint64_t)r; /* zero-extend */
	                }
	                break;
	            }
	            case SOL_BPF_PQR_UDIV: {
	                /* Unsigned: zero-extend immediate */
	                uint64_t pqr_src = use_imm ? (uint64_t)(uint32_t)imm : reg[src];
	                if (pqr_64) {
	                    if (pqr_src == 0) { vm->error = SOL_BPF_ERR_DIVIDE_BY_ZERO; state = SOL_BPF_STATE_ERROR; goto done; }
	                    reg[dst] /= pqr_src;
	                } else {
	                    uint32_t d = (uint32_t)pqr_src;
	                    if (d == 0) { vm->error = SOL_BPF_ERR_DIVIDE_BY_ZERO; state = SOL_BPF_STATE_ERROR; goto done; }
	                    reg[dst] = (uint64_t)((uint32_t)reg[dst] / d); /* zero-extend */
	                }
	                break;
	            }
	            case SOL_BPF_PQR_UREM: {
	                /* Unsigned: zero-extend immediate */
	                uint64_t pqr_src = use_imm ? (uint64_t)(uint32_t)imm : reg[src];
	                if (pqr_64) {
	                    if (pqr_src == 0) { vm->error = SOL_BPF_ERR_DIVIDE_BY_ZERO; state = SOL_BPF_STATE_ERROR; goto done; }
	                    reg[dst] %= pqr_src;
	                } else {
	                    uint32_t d = (uint32_t)pqr_src;
	                    if (d == 0) { vm->error = SOL_BPF_ERR_DIVIDE_BY_ZERO; state = SOL_BPF_STATE_ERROR; goto done; }
	                    reg[dst] = (uint64_t)((uint32_t)reg[dst] % d); /* zero-extend */
	                }
	                break;
	            }
	            case SOL_BPF_PQR_SHMUL: {
	                uint64_t pqr_src = use_imm ? (uint64_t)(int64_t)imm : reg[src];
	                if (pqr_64)
	                    reg[dst] = (uint64_t)(((__int128)(int64_t)reg[dst] * (__int128)(int64_t)pqr_src) >> 64);
	                else {
	                    uint32_t r = (uint32_t)((int64_t)(int32_t)(uint32_t)reg[dst] * (int64_t)(int32_t)(uint32_t)pqr_src >> 32);
	                    reg[dst] = (uint64_t)(int64_t)(int32_t)r; /* sign-extend for SHMUL */
	                }
	                break;
	            }
	            case SOL_BPF_PQR_SDIV: {
	                uint64_t pqr_src = use_imm ? (uint64_t)(int64_t)imm : reg[src];
	                if (pqr_64) {
	                    int64_t a = (int64_t)reg[dst], b = (int64_t)pqr_src;
	                    if (b == 0) { vm->error = SOL_BPF_ERR_DIVIDE_BY_ZERO; state = SOL_BPF_STATE_ERROR; goto done; }
	                    if (a == INT64_MIN && b == -1) { vm->error = SOL_BPF_ERR_DIVIDE_OVERFLOW; state = SOL_BPF_STATE_ERROR; goto done; }
	                    reg[dst] = (uint64_t)(a / b);
	                } else {
	                    int32_t a = (int32_t)(uint32_t)reg[dst], b = (int32_t)(uint32_t)pqr_src;
	                    if (b == 0) { vm->error = SOL_BPF_ERR_DIVIDE_BY_ZERO; state = SOL_BPF_STATE_ERROR; goto done; }
	                    if (a == INT32_MIN && b == -1) { vm->error = SOL_BPF_ERR_DIVIDE_OVERFLOW; state = SOL_BPF_STATE_ERROR; goto done; }
	                    reg[dst] = (uint64_t)(uint32_t)(a / b); /* zero-extend (rbpf: as u32 as u64) */
	                }
	                break;
	            }
	            case SOL_BPF_PQR_SREM: {
	                uint64_t pqr_src = use_imm ? (uint64_t)(int64_t)imm : reg[src];
	                if (pqr_64) {
	                    int64_t a = (int64_t)reg[dst], b = (int64_t)pqr_src;
	                    if (b == 0) { vm->error = SOL_BPF_ERR_DIVIDE_BY_ZERO; state = SOL_BPF_STATE_ERROR; goto done; }
	                    if (a == INT64_MIN && b == -1) { vm->error = SOL_BPF_ERR_DIVIDE_OVERFLOW; state = SOL_BPF_STATE_ERROR; goto done; }
	                    reg[dst] = (uint64_t)(a % b);
	                } else {
	                    int32_t a = (int32_t)(uint32_t)reg[dst], b = (int32_t)(uint32_t)pqr_src;
	                    if (b == 0) { vm->error = SOL_BPF_ERR_DIVIDE_BY_ZERO; state = SOL_BPF_STATE_ERROR; goto done; }
	                    if (a == INT32_MIN && b == -1) { vm->error = SOL_BPF_ERR_DIVIDE_OVERFLOW; state = SOL_BPF_STATE_ERROR; goto done; }
	                    reg[dst] = (uint64_t)(uint32_t)(a % b); /* zero-extend (rbpf: as u32 as u64) */
	                }
	                break;
	            }
	            default:
	                vm->error = SOL_BPF_ERR_INVALID_INSN;
	                state = SOL_BPF_STATE_ERROR;
	                goto done;
	            }
            break;
        }

        default:
            vm->error = SOL_BPF_ERR_INVALID_INSN;
            state = SOL_BPF_STATE_ERROR;
            goto done;
        }
    }

	done:

		    /* Commit hot locals back to the VM struct. */
		    vm->pc = pc;
		    vm->compute_units_used = compute_limit - compute_left;
		    vm->state = state;

	    /* POSTMORTEM logging disabled for performance — re-enable for BPF debugging */
#if 0
	    if (vm->error == SOL_BPF_ERR_ABORT || vm->error == SOL_BPF_ERR_SYSCALL_ERROR) {
        sol_log_info("POSTMORTEM: error=%d pc=%lu sbpf_ver=%d insn_count=%lu",
                     vm->error, (unsigned long)vm->pc, (int)sbpf_ver,
                     (unsigned long)vm->insn_count);
        sol_log_info("POSTMORTEM_REGS: r0=0x%lx r1=0x%lx r2=0x%lx r3=0x%lx r4=0x%lx r5=0x%lx "
                     "r6=0x%lx r7=0x%lx r8=0x%lx r9=0x%lx r10=0x%lx",
                     (unsigned long)vm->reg[0], (unsigned long)vm->reg[1],
                     (unsigned long)vm->reg[2], (unsigned long)vm->reg[3],
                     (unsigned long)vm->reg[4], (unsigned long)vm->reg[5],
                     (unsigned long)vm->reg[6], (unsigned long)vm->reg[7],
                     (unsigned long)vm->reg[8], (unsigned long)vm->reg[9],
                     (unsigned long)vm->reg[10]);
        uint32_t count = trace_ring_pos < TRACE_RING_SIZE ? trace_ring_pos : TRACE_RING_SIZE;
        uint32_t start = trace_ring_pos >= TRACE_RING_SIZE ? (trace_ring_pos & TRACE_RING_MASK) : 0;
        for (uint32_t ri = 0; ri < count; ri++) {
            uint32_t idx = (start + ri) & TRACE_RING_MASK;
            int is_tail = (ri + 200 >= count);
            uint64_t rd = trace_ring[idx].reg_dst;
            uint64_t rs = trace_ring[idx].reg_src;
            int is_suspicious = (rd == 0x10000004F || rs == 0x10000004F ||
                                 (rd > 0xFFFFFFFF && rd < 0x100001000) ||
                                 (rs > 0xFFFFFFFF && rs < 0x100001000));
            if (is_tail || is_suspicious) {
                sol_log_info("POSTMORTEM[%04u]: pc=%lu op=0x%02x dst=r%u(0x%lx) src=r%u(0x%lx) off=%d imm=%d",
                             ri, (unsigned long)trace_ring[idx].pc,
                             trace_ring[idx].opcode,
                             trace_ring[idx].dst, (unsigned long)trace_ring[idx].reg_dst,
                             trace_ring[idx].src, (unsigned long)trace_ring[idx].reg_src,
                             (int)trace_ring[idx].off, (int)trace_ring[idx].imm);
            }
        }
    }
#endif
    if (vm->error != SOL_BPF_OK) {
        return SOL_ERR_BPF_EXECUTE;
    }

    return SOL_OK;
}

/*
 * Get return value
 */
uint64_t
sol_bpf_vm_return_value(const sol_bpf_vm_t* vm) {
    return vm ? vm->return_value : 0;
}

/*
 * Get compute units used
 */
uint64_t
sol_bpf_vm_compute_used(const sol_bpf_vm_t* vm) {
    return vm ? vm->compute_units_used : 0;
}

/*
 * JIT stubs for non-x86_64 platforms
 */
#if !SOL_BPF_JIT_SUPPORTED
sol_err_t
sol_bpf_jit_compile(sol_bpf_vm_t* vm, void** code_out, size_t* code_len_out) {
    (void)vm;
    (void)code_out;
    (void)code_len_out;
    return SOL_ERR_UNSUPPORTED;
}

void
sol_bpf_jit_free(sol_bpf_program_t* prog) {
    (void)prog;
}

sol_err_t
sol_bpf_vm_execute_jit(sol_bpf_vm_t* vm) {
    (void)vm;
    return SOL_ERR_NOT_IMPLEMENTED;
}
#endif
