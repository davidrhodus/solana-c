/*
 * sol_bpf_loader_program.c - BPF Loader native programs
 *
 * Implements the BPF Loader programs that handle deploying and
 * executing on-chain programs:
 * - BPF Loader v2 (BPFLoader2111111111111111111111111111111111)
 * - BPF Upgradeable Loader (BPFLoaderUpgradeab1e11111111111111111111111)
 */

#include "sol_bpf_loader_program.h"
#include "sol_system_program.h"  /* For sol_invoke_context_t */
#include "../runtime/sol_account.h"
#include "../runtime/sol_bank.h"
#include "../runtime/sol_program.h"
#include "../bpf/sol_bpf.h"
#include "../crypto/sol_sha256.h"
#include "../txn/sol_pubkey.h"
#include "../util/sol_hash_fn.h"
#include "../util/sol_log.h"
#include "../util/sol_alloc.h"
#include "../util/sol_map.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

/* Profiling helpers (opt-in via SOL_SBF_PROFILE=1). */
static inline uint64_t
monotonic_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void sbf_profile_report_atexit(void);

static int
sbf_profile_enabled(void) {
    static int cached = -1;
    static int registered = 0;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v >= 0, 1)) return v != 0;
    const char* env = getenv("SOL_SBF_PROFILE");
    int enabled = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    if (enabled && __sync_bool_compare_and_swap(&registered, 0, 1)) {
        atexit(sbf_profile_report_atexit);
    }
    return enabled != 0;
}

/* Diagnostics that stringify pubkeys and dump account headers can be very
 * expensive on mainnet. Opt-in via SOL_SBF_VM_DIAG=1. */
static int
sbf_vm_diag_enabled(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v >= 0, 1)) return v != 0;
    const char* env = getenv("SOL_SBF_VM_DIAG");
    int enabled = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled != 0;
}

static uint64_t
sbf_slow_threshold_ns(void) {
    /* Returns 0 when disabled. Cached after first call. */
    static _Atomic uint64_t cached = UINT64_MAX;
    uint64_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != UINT64_MAX, 1)) {
        return v;
    }

    uint64_t ns = 0;
    const char* env = getenv("SOL_SBF_SLOW_MS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long ms = strtoul(env, &end, 10);
        if (end != env && ms > 0ul) {
            ns = (uint64_t)ms * 1000000ull;
        }
    }

    __atomic_store_n(&cached, ns, __ATOMIC_RELEASE);
    return ns;
}

/* Program load diagnostics for cache-miss/load-wait attribution.
 * Disabled by default; enable with SOL_BPF_LOAD_SLOW_MS=<ms>. */
static uint64_t
bpf_load_slow_threshold_ns(void) {
    static _Atomic uint64_t cached = UINT64_MAX;
    uint64_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != UINT64_MAX, 1)) {
        return v;
    }

    uint64_t ns = 0;
    const char* env = getenv("SOL_BPF_LOAD_SLOW_MS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long ms = strtoul(env, &end, 10);
        if (end != env && ms > 0ul) {
            ns = (uint64_t)ms * 1000000ull;
        }
    }

    __atomic_store_n(&cached, ns, __ATOMIC_RELEASE);
    return ns;
}

/* Bound how long execute-path callers wait on an in-flight program load before
 * falling back to an uncached local load to avoid replay convoy tails.
 * Set SOL_BPF_LOAD_WAIT_BUDGET_MS=0 for immediate fallback behavior. */
static uint64_t
bpf_load_wait_budget_ns(void) {
    static _Atomic uint64_t cached = UINT64_MAX;
    uint64_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != UINT64_MAX, 1)) {
        return v;
    }

    uint64_t budget_ms = 128u;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu >= 96) {
        budget_ms = 64u;
    } else if (ncpu >= 48) {
        budget_ms = 96u;
    }

    const char* env = getenv("SOL_BPF_LOAD_WAIT_BUDGET_MS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long parsed = strtoul(env, &end, 10);
        if (end != env) {
            budget_ms = (uint64_t)parsed;
        }
    }

    if (budget_ms > 5000u) {
        budget_ms = 5000u;
    }
    uint64_t ns = budget_ms * 1000000ull;

    __atomic_store_n(&cached, ns, __ATOMIC_RELEASE);
    return ns;
}

static inline void
bpf_log_slow_stage(const char* stage,
                   const sol_pubkey_t* program_id,
                   uint64_t slot,
                   uint64_t elapsed_ns,
                   sol_err_t err,
                   size_t ro_section_len) {
    if (!stage || !program_id) return;
    uint64_t thresh_ns = bpf_load_slow_threshold_ns();
    if (thresh_ns == 0u || elapsed_ns < thresh_ns) return;

    char p58[SOL_PUBKEY_BASE58_LEN] = {0};
    sol_pubkey_to_base58(program_id, p58, sizeof(p58));
    sol_log_info("BPF_LOAD_SLOW: slot=%lu stage=%s ms=%.3f err=%d ro_kb=%.1f program=%s",
                 (unsigned long)slot,
                 stage,
                 (double)elapsed_ns / 1e6,
                 err,
                 (double)ro_section_len / 1024.0,
                 p58);
}

static _Atomic uint64_t g_sbf_prof_calls = 0;
static _Atomic uint64_t g_sbf_prof_build_ns = 0;
static _Atomic uint64_t g_sbf_prof_map_ns = 0;
static _Atomic uint64_t g_sbf_prof_exec_ns = 0;
static _Atomic uint64_t g_sbf_prof_wb_ns = 0;
static _Atomic uint64_t g_sbf_prof_input_bytes = 0;
static _Atomic uint64_t g_sbf_prof_meta_total = 0;
static _Atomic uint64_t g_sbf_prof_last_log_ns = 0;

static uint64_t
sbf_profile_log_interval_ns(void) {
    static _Atomic uint64_t cached = UINT64_MAX;
    uint64_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != UINT64_MAX, 1)) {
        return v;
    }

    /* Default to periodic logs every 5s while profiling. */
    uint64_t interval_ms = 5000u;
    const char* env = getenv("SOL_SBF_PROFILE_LOG_INTERVAL_MS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long parsed = strtoul(env, &end, 10);
        if (end != env) {
            interval_ms = (uint64_t)parsed;
        }
    }

    uint64_t interval_ns = interval_ms ? (interval_ms * 1000000ull) : 0ull;
    __atomic_store_n(&cached, interval_ns, __ATOMIC_RELEASE);
    return interval_ns;
}

static inline void
sbf_profile_maybe_log(void) {
    uint64_t interval_ns = sbf_profile_log_interval_ns();
    if (interval_ns == 0u) return;

    uint64_t now = monotonic_ns();
    uint64_t last = __atomic_load_n(&g_sbf_prof_last_log_ns, __ATOMIC_RELAXED);
    if (last != 0u && (now - last) < interval_ns) return;
    if (!__atomic_compare_exchange_n(&g_sbf_prof_last_log_ns,
                                     &last,
                                     now,
                                     false,
                                     __ATOMIC_RELAXED,
                                     __ATOMIC_RELAXED)) {
        return;
    }

    uint64_t calls = __atomic_load_n(&g_sbf_prof_calls, __ATOMIC_RELAXED);
    if (!calls) return;

    uint64_t build_ns = __atomic_load_n(&g_sbf_prof_build_ns, __ATOMIC_RELAXED);
    uint64_t map_ns = __atomic_load_n(&g_sbf_prof_map_ns, __ATOMIC_RELAXED);
    uint64_t exec_ns = __atomic_load_n(&g_sbf_prof_exec_ns, __ATOMIC_RELAXED);
    uint64_t wb_ns = __atomic_load_n(&g_sbf_prof_wb_ns, __ATOMIC_RELAXED);
    uint64_t bytes = __atomic_load_n(&g_sbf_prof_input_bytes, __ATOMIC_RELAXED);
    uint64_t metas = __atomic_load_n(&g_sbf_prof_meta_total, __ATOMIC_RELAXED);
    uint64_t total_ns = build_ns + map_ns + exec_ns + wb_ns;

    sol_log_info("sbf_profile_live: calls=%lu avg_ms(total/build/map/exec/wb)=%.3f/%.3f/%.3f/%.3f/%.3f avg_input_kb=%.2f avg_meta=%.2f",
                 (unsigned long)calls,
                 (double)total_ns / 1e6 / (double)calls,
                 (double)build_ns / 1e6 / (double)calls,
                 (double)map_ns / 1e6 / (double)calls,
                 (double)exec_ns / 1e6 / (double)calls,
                 (double)wb_ns / 1e6 / (double)calls,
                 (double)bytes / 1024.0 / (double)calls,
                 (double)metas / (double)calls);
}

static inline void
sbf_profile_commit(uint64_t build_ns,
                   uint64_t map_ns,
                   uint64_t exec_ns,
                   uint64_t wb_ns,
                   size_t input_len,
                   size_t meta_count) {
    __atomic_fetch_add(&g_sbf_prof_calls, 1u, __ATOMIC_RELAXED);
    __atomic_fetch_add(&g_sbf_prof_build_ns, build_ns, __ATOMIC_RELAXED);
    __atomic_fetch_add(&g_sbf_prof_map_ns, map_ns, __ATOMIC_RELAXED);
    __atomic_fetch_add(&g_sbf_prof_exec_ns, exec_ns, __ATOMIC_RELAXED);
    __atomic_fetch_add(&g_sbf_prof_wb_ns, wb_ns, __ATOMIC_RELAXED);
    __atomic_fetch_add(&g_sbf_prof_input_bytes, (uint64_t)input_len, __ATOMIC_RELAXED);
    __atomic_fetch_add(&g_sbf_prof_meta_total, (uint64_t)meta_count, __ATOMIC_RELAXED);
    sbf_profile_maybe_log();
}

static void
sbf_profile_report_atexit(void) {
    if (!sbf_profile_enabled()) return;
    uint64_t calls = __atomic_load_n(&g_sbf_prof_calls, __ATOMIC_RELAXED);
    if (!calls) return;
    uint64_t build_ns = __atomic_load_n(&g_sbf_prof_build_ns, __ATOMIC_RELAXED);
    uint64_t map_ns = __atomic_load_n(&g_sbf_prof_map_ns, __ATOMIC_RELAXED);
    uint64_t exec_ns = __atomic_load_n(&g_sbf_prof_exec_ns, __ATOMIC_RELAXED);
    uint64_t wb_ns = __atomic_load_n(&g_sbf_prof_wb_ns, __ATOMIC_RELAXED);
    uint64_t bytes = __atomic_load_n(&g_sbf_prof_input_bytes, __ATOMIC_RELAXED);
    uint64_t metas = __atomic_load_n(&g_sbf_prof_meta_total, __ATOMIC_RELAXED);

    double ms_build = (double)build_ns / 1e6;
    double ms_map = (double)map_ns / 1e6;
    double ms_exec = (double)exec_ns / 1e6;
    double ms_wb = (double)wb_ns / 1e6;

    fprintf(stderr,
            "sbf_profile: calls=%lu build_ms=%.3f map_ms=%.3f exec_ms=%.3f wb_ms=%.3f "
            "avg_input_kb=%.2f avg_meta=%.2f\n",
            (unsigned long)calls,
            ms_build, ms_map, ms_exec, ms_wb,
            calls ? ((double)bytes / 1024.0 / (double)calls) : 0.0,
            calls ? ((double)metas / (double)calls) : 0.0);
}

/*
 * SBF entrypoint input serialization (Agave v3.1.8 compatible)
 *
 * Format matches platform-tools-sdk `sol/deserialize.h` for
 * SBFLoader2111111111111111111111111111111111 and
 * SBFLoaderUpgradeab1e11111111111111111111111.
 */
#define SOL_SBF_NON_DUP_MARKER             ((uint8_t)0xFFu)
#define SOL_SBF_DUP_PADDING                (7u)
#define SOL_SBF_MAX_PERMITTED_DATA_INCREASE (1024u * 10u)

typedef struct {
    uint8_t     key_index;       /* Index into ctx->account_keys */
    bool        is_writable;
    bool        is_signer;
    uint64_t    pre_lamports;
    uint64_t    pre_data_len;
    /* Optional pre-exec snapshot retained from sbf_build_input().
     *
     * Writeback needs to observe CPI mutations, so it generally reloads the
     * current account value from the bank. However, for overlay banks most
     * accounts are unchanged locally; reloading from the parent can hit disk
     * (AppendVec page faults / pread), causing multi-second stalls. Retaining
     * the pre-exec snapshot allows writeback to:
     * - validate read-only accounts without reloading
     * - use the snapshot as the "current" value when the overlay has no local
     *   entry (i.e. the account was not modified by CPI/previous instructions)
     *
     * This pointer is owned by the meta and released via
     * sbf_metas_release_retained(). */
    sol_account_t* ro_account;
    size_t      owner_off;
    size_t      lamports_off;
    size_t      data_len_off;
    size_t      data_off;
} sol_sbf_account_meta_t;

static void
sbf_metas_release_retained(sol_sbf_account_meta_t* metas, size_t meta_count) {
    if (!metas) return;
    for (size_t i = 0; i < meta_count; i++) {
        if (metas[i].ro_account) {
            sol_account_destroy(metas[i].ro_account);
            metas[i].ro_account = NULL;
        }
    }
}

static inline void
sbf_destroy_if_not_retained(sol_account_t* account, bool account_owned_by_meta) {
    if (account && !account_owned_by_meta) {
        sol_account_destroy(account);
    }
}

typedef struct {
    uint8_t* data;
    size_t   len;
    size_t   cap;
    bool     pooled;
    bool     zeroed; /* true when [len..cap) is known to be zero-filled */
} sol_sbf_buf_t;

static void
sbf_buf_free(sol_sbf_buf_t* b) {
    if (!b) return;
    if (!b->pooled) {
        sol_free(b->data);
    }
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
    b->pooled = false;
    b->zeroed = false;
}

static bool
sbf_buf_reserve(sol_sbf_buf_t* b, size_t extra) {
    if (!b) return false;
    if (extra > SIZE_MAX - b->len) return false;
    size_t need = b->len + extra;
    if (need <= b->cap) return true;

    /* Pooled buffers are fixed-size and must not be reallocated. */
    if (b->pooled) return false;

    size_t new_cap = b->cap ? b->cap : 4096u;
    while (new_cap < need) {
        if (new_cap > SIZE_MAX / 2) {
            new_cap = need;
            break;
        }
        new_cap *= 2;
    }

    /* Critical perf path: The aligned SBF input format includes large zero
     * padding regions (10 KiB realloc pad per account). Explicitly writing
     * those zeros with memset is extremely expensive. Use zeroed allocations
     * so sbf_buf_write_zeros() can simply advance the cursor without touching
     * memory; large calloc() allocations typically come from mmap'd zero pages
     * and don't require per-byte stores. */
    uint8_t* next = (uint8_t*)sol_calloc(1u, new_cap);
    if (!next) return false;
    if (b->data && b->len) {
        memcpy(next, b->data, b->len);
    }
    sol_free(b->data);
    b->data = next;
    b->cap = new_cap;
    b->zeroed = true;
    return true;
}

static bool
sbf_buf_write(sol_sbf_buf_t* b, const void* src, size_t n) {
    if (!b || (!src && n)) return false;
    if (!sbf_buf_reserve(b, n)) return false;
    memcpy(b->data + b->len, src, n);
    b->len += n;
    return true;
}

static bool
sbf_buf_write_zeros(sol_sbf_buf_t* b, size_t n) {
    if (!b) return false;
    if (!sbf_buf_reserve(b, n)) return false;
    if (!b->zeroed && n) {
        memset(b->data + b->len, 0, n);
    }
    b->len += n;
    return true;
}

static bool
sbf_buf_write_u8(sol_sbf_buf_t* b, uint8_t v) {
    return sbf_buf_write(b, &v, 1);
}

static bool
sbf_buf_write_u64_le(sol_sbf_buf_t* b, uint64_t v) {
    /* Host is little-endian (Linux x86_64); serialize as little-endian. */
    return sbf_buf_write(b, &v, sizeof(uint64_t));
}

typedef struct {
    uint8_t* buf;
    size_t   cap;
} sol_sbf_input_pool_t;

static inline bool
sbf_size_add(size_t* acc, size_t v) {
    if (!acc) return false;
    if (v > SIZE_MAX - *acc) return false;
    *acc += v;
    return true;
}

static inline bool
sbf_u64_to_size(uint64_t v, size_t* out) {
    if (!out) return false;
    if (v > (uint64_t)SIZE_MAX) return false;
    *out = (size_t)v;
    return true;
}

static void
sbf_loaded_accounts_destroy(sol_account_t* loaded_accounts[256]) {
    if (!loaded_accounts) return;
    for (size_t i = 0; i < 256u; i++) {
        if (loaded_accounts[i]) {
            sol_account_destroy(loaded_accounts[i]);
            loaded_accounts[i] = NULL;
        }
    }
}

/*
 * BPF program cache
 *
 * Mainnet execution invokes a small set of hot programs (Token, Memo, etc)
 * many times per slot. Loading/parsing ELF from AppendVec on every invocation
 * is catastrophic for replay throughput. Cache loaded `sol_bpf_program_t` per
 * program-id and invalidate when the loader modifies program/programdata.
 */
typedef struct sol_bpf_prog_handle {
    sol_bpf_program_t* prog;            /* Loaded ELF (ro_section + instruction view) */
    sol_pubkey_t       programdata;     /* Upgradeable: ProgramData pubkey */
    bool               has_programdata;
    bool               loader_deprecated;
    uint64_t           last_used;       /* LRU clock (updated under cache lock) */
    size_t             ro_section_len;  /* For cache sizing */
    uint32_t           refcnt;          /* Includes cache's ref while resident */

    /* Cache-miss coordination: on mainnet it's common for many txs in a slot to
     * invoke the same (previously unseen) program. Without coordination, every
     * worker thread races to load+parse the same ELF, causing huge tail latency
     * spikes. */
    pthread_mutex_t    load_mu;
    pthread_cond_t     load_cv;
    int               load_state;       /* 0=ready 1=loading 2=failed */
    sol_err_t          load_err;
    bool              load_sync_inited;
} sol_bpf_prog_handle_t;

enum {
    BPF_PROG_STATE_READY = 0,
    BPF_PROG_STATE_LOADING = 1,
    BPF_PROG_STATE_FAILED = 2,
};

static pthread_once_t    g_bpf_prog_cache_once = PTHREAD_ONCE_INIT;
static pthread_rwlock_t  g_bpf_prog_cache_lock;
static sol_pubkey_map_t* g_bpf_prog_cache = NULL;
static _Atomic uint64_t  g_bpf_prog_cache_clock = 0;
static size_t            g_bpf_prog_cache_total_bytes = 0;
static size_t            g_bpf_prog_cache_max_bytes = 0;
static size_t            g_bpf_prog_cache_max_entries = 0;
static size_t            g_bpf_prog_cache_evict_cursor = 0;

static inline void
bpf_prog_handle_acquire(sol_bpf_prog_handle_t* h) {
    if (!h) return;
    __atomic_fetch_add(&h->refcnt, 1u, __ATOMIC_ACQUIRE);
}

static inline void
bpf_prog_handle_release(sol_bpf_prog_handle_t* h) {
    if (!h) return;
    uint32_t prev = __atomic_fetch_sub(&h->refcnt, 1u, __ATOMIC_RELEASE);
    if (prev == 1u) {
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if (h->prog) {
            sol_bpf_program_destroy(h->prog);
        }
        if (h->load_sync_inited) {
            (void)pthread_cond_destroy(&h->load_cv);
            (void)pthread_mutex_destroy(&h->load_mu);
        }
        sol_free(h);
    }
}

static sol_bpf_prog_handle_t*
bpf_prog_handle_new(int state) {
    sol_bpf_prog_handle_t* h = sol_alloc_t(sol_bpf_prog_handle_t);
    if (!h) return NULL;
    memset(h, 0, sizeof(*h));
    h->refcnt = 1u;
    h->load_state = state;
    h->load_err = SOL_OK;

    if (pthread_mutex_init(&h->load_mu, NULL) != 0) {
        sol_free(h);
        return NULL;
    }
    if (pthread_cond_init(&h->load_cv, NULL) != 0) {
        (void)pthread_mutex_destroy(&h->load_mu);
        sol_free(h);
        return NULL;
    }
    h->load_sync_inited = true;
    return h;
}

static inline sol_err_t
bpf_prog_handle_wait_ready(sol_bpf_prog_handle_t* h) {
    if (!h) return SOL_ERR_INVAL;
    int st = __atomic_load_n(&h->load_state, __ATOMIC_ACQUIRE);
    if (st == BPF_PROG_STATE_READY) {
        return (h->prog != NULL) ? SOL_OK : SOL_ERR_INVAL;
    }
    if (!h->load_sync_inited) {
        return h->load_err ? h->load_err : SOL_ERR_INVAL;
    }

    pthread_mutex_lock(&h->load_mu);
    while (h->load_state == BPF_PROG_STATE_LOADING) {
        pthread_cond_wait(&h->load_cv, &h->load_mu);
    }
    sol_err_t err = SOL_OK;
    if (h->load_state != BPF_PROG_STATE_READY || !h->prog) {
        err = h->load_err ? h->load_err : SOL_ERR_INVAL;
    }
    pthread_mutex_unlock(&h->load_mu);
    return err;
}

static inline sol_err_t
bpf_prog_handle_wait_ready_budget(sol_bpf_prog_handle_t* h,
                                  uint64_t budget_ns,
                                  bool* timed_out) {
    if (timed_out) {
        *timed_out = false;
    }
    if (!h) {
        return SOL_ERR_INVAL;
    }

    int st = __atomic_load_n(&h->load_state, __ATOMIC_ACQUIRE);
    if (st == BPF_PROG_STATE_READY) {
        return (h->prog != NULL) ? SOL_OK : SOL_ERR_INVAL;
    }
    if (!h->load_sync_inited) {
        return h->load_err ? h->load_err : SOL_ERR_INVAL;
    }

    pthread_mutex_lock(&h->load_mu);

    if (budget_ns == 0u && h->load_state == BPF_PROG_STATE_LOADING) {
        pthread_mutex_unlock(&h->load_mu);
        if (timed_out) {
            *timed_out = true;
        }
        return SOL_ERR_TIMEOUT;
    }

    uint64_t start_ns = budget_ns ? monotonic_ns() : 0u;
    while (h->load_state == BPF_PROG_STATE_LOADING) {
        if (budget_ns == 0u) {
            pthread_mutex_unlock(&h->load_mu);
            if (timed_out) {
                *timed_out = true;
            }
            return SOL_ERR_TIMEOUT;
        }

        uint64_t elapsed_ns = monotonic_ns() - start_ns;
        if (elapsed_ns >= budget_ns) {
            pthread_mutex_unlock(&h->load_mu);
            if (timed_out) {
                *timed_out = true;
            }
            return SOL_ERR_TIMEOUT;
        }

        uint64_t remain_ns = budget_ns - elapsed_ns;
        struct timespec deadline;
        if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
            pthread_cond_wait(&h->load_cv, &h->load_mu);
            continue;
        }

        deadline.tv_sec += (time_t)(remain_ns / 1000000000ull);
        deadline.tv_nsec += (long)(remain_ns % 1000000000ull);
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec += 1;
            deadline.tv_nsec -= 1000000000L;
        }

        int rc = pthread_cond_timedwait(&h->load_cv, &h->load_mu, &deadline);
        if (rc == ETIMEDOUT && h->load_state == BPF_PROG_STATE_LOADING) {
            pthread_mutex_unlock(&h->load_mu);
            if (timed_out) {
                *timed_out = true;
            }
            return SOL_ERR_TIMEOUT;
        }
    }

    sol_err_t err = SOL_OK;
    if (h->load_state != BPF_PROG_STATE_READY || !h->prog) {
        err = h->load_err ? h->load_err : SOL_ERR_INVAL;
    }
    pthread_mutex_unlock(&h->load_mu);
    return err;
}

static size_t
parse_size_env(const char* env, size_t def) {
    if (!env || env[0] == '\0') return def;
    char* end = NULL;
    unsigned long long v = strtoull(env, &end, 10);
    if (end == env) return def;
    if (v > (unsigned long long)SIZE_MAX) return def;
    return (size_t)v;
}

static void
bpf_prog_cache_do_init(void) {
    (void)pthread_rwlock_init(&g_bpf_prog_cache_lock, NULL);

    /* Defaults tuned by host size; still overrideable via env.
     * Set either to 0 to disable caching. */
    size_t default_mb = 1024u;
    size_t default_entries = 8192u;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu >= 128) {
        default_mb = 8192u;
        default_entries = 65536u;
    } else if (ncpu >= 64) {
        default_mb = 4096u;
        default_entries = 32768u;
    }

    size_t mb = parse_size_env(getenv("SOL_BPF_PROG_CACHE_MB"), default_mb);
    g_bpf_prog_cache_max_entries =
        parse_size_env(getenv("SOL_BPF_PROG_CACHE_ENTRIES"), default_entries);
    if (mb == 0 || g_bpf_prog_cache_max_entries == 0) {
        g_bpf_prog_cache_max_bytes = 0;
        g_bpf_prog_cache_max_entries = 0;
        g_bpf_prog_cache = NULL;
        return;
    }

    if (mb > (SIZE_MAX / (1024u * 1024u))) {
        mb = SIZE_MAX / (1024u * 1024u);
    }
    g_bpf_prog_cache_max_bytes = mb * 1024u * 1024u;

    /* program_id -> sol_bpf_prog_handle_t* */
    g_bpf_prog_cache = sol_pubkey_map_new(sizeof(sol_bpf_prog_handle_t*), 1024u);
    if (!g_bpf_prog_cache) {
        g_bpf_prog_cache_max_bytes = 0;
        g_bpf_prog_cache_max_entries = 0;
    }
}

static inline void
bpf_prog_cache_init(void) {
    (void)pthread_once(&g_bpf_prog_cache_once, bpf_prog_cache_do_init);
}

static void
bpf_prog_cache_remove_locked(const sol_pubkey_t* program_id) {
    if (!g_bpf_prog_cache || !program_id) return;

    sol_bpf_prog_handle_t** slot = (sol_bpf_prog_handle_t**)sol_pubkey_map_get(g_bpf_prog_cache, program_id);
    if (!slot || !*slot) return;

    sol_bpf_prog_handle_t* victim = *slot;
    (void)sol_pubkey_map_remove(g_bpf_prog_cache, program_id);

    if (victim) {
        if (g_bpf_prog_cache_total_bytes >= victim->ro_section_len) {
            g_bpf_prog_cache_total_bytes -= victim->ro_section_len;
        } else {
            g_bpf_prog_cache_total_bytes = 0;
        }
        /* Drop the cache's reference; handle may stay alive while executing. */
        bpf_prog_handle_release(victim);
    }
}

static void
bpf_prog_cache_evict_one_locked(void) {
    if (!g_bpf_prog_cache) return;
    if (!g_bpf_prog_cache->inner || sol_map_size(g_bpf_prog_cache->inner) == 0) return;

    sol_map_t* m = g_bpf_prog_cache->inner;
    size_t cap = m->capacity;
    if (cap == 0) return;

    /* Sample a bounded window first to keep eviction lock hold times low. */
    size_t idx = g_bpf_prog_cache_evict_cursor % cap;
    const size_t sample_window = cap < 256u ? cap : 256u;
    bool found = false;
    size_t victim_idx = 0;
    uint64_t best = UINT64_MAX;

    for (size_t scanned = 0; scanned < sample_window; scanned++) {
        if (m->ctrl[idx] & SOL_MAP_OCCUPIED) {
            void* valp = (char*)m->vals + idx * m->val_size;
            sol_bpf_prog_handle_t* h = valp ? *(sol_bpf_prog_handle_t**)valp : NULL;
            if (h && h->prog) {
                uint64_t last = __atomic_load_n(&h->last_used, __ATOMIC_RELAXED);
                if (last < best) {
                    best = last;
                    victim_idx = idx;
                    found = true;
                }
            }
        }
        idx = (idx + 1u) % cap;
    }

    /* Fallback: if no victim in sampled window, scan full map once. */
    if (!found) {
        idx = g_bpf_prog_cache_evict_cursor % cap;
        for (size_t scanned = 0; scanned < cap; scanned++) {
            if (m->ctrl[idx] & SOL_MAP_OCCUPIED) {
                void* valp = (char*)m->vals + idx * m->val_size;
                sol_bpf_prog_handle_t* h = valp ? *(sol_bpf_prog_handle_t**)valp : NULL;
                if (h && h->prog) {
                    uint64_t last = __atomic_load_n(&h->last_used, __ATOMIC_RELAXED);
                    if (last < best) {
                        best = last;
                        victim_idx = idx;
                        found = true;
                    }
                }
            }
            idx = (idx + 1u) % cap;
        }
    }

    if (!found) return;

    sol_pubkey_t victim_key = {0};
    void* victim_keyp = (char*)m->keys + victim_idx * m->key_size;
    memcpy(victim_key.bytes, victim_keyp, SOL_PUBKEY_SIZE);
    g_bpf_prog_cache_evict_cursor = (victim_idx + 1u) % cap;
    bpf_prog_cache_remove_locked(&victim_key);
}

static void
bpf_prog_cache_evict_if_needed_locked(size_t incoming_bytes) {
    if (!g_bpf_prog_cache) return;

    /* Ensure we can at least hold one program. */
    if (incoming_bytes > g_bpf_prog_cache_max_bytes) {
        while (sol_map_size(g_bpf_prog_cache->inner) > 0) {
            bpf_prog_cache_evict_one_locked();
        }
        return;
    }

    while (sol_map_size(g_bpf_prog_cache->inner) >= g_bpf_prog_cache_max_entries ||
           g_bpf_prog_cache_total_bytes + incoming_bytes > g_bpf_prog_cache_max_bytes) {
        size_t before = sol_map_size(g_bpf_prog_cache->inner);
        bpf_prog_cache_evict_one_locked();
        if (sol_map_size(g_bpf_prog_cache->inner) == before) {
            break;
        }
    }
}

static sol_bpf_prog_handle_t*
bpf_prog_cache_get_locked(const sol_pubkey_t* program_id) {
    if (!g_bpf_prog_cache || !program_id) return NULL;
    sol_bpf_prog_handle_t** slot = (sol_bpf_prog_handle_t**)sol_pubkey_map_get(g_bpf_prog_cache, program_id);
    sol_bpf_prog_handle_t* h = slot ? *slot : NULL;
    if (h) {
        uint64_t tick = __atomic_add_fetch(&g_bpf_prog_cache_clock, 1u, __ATOMIC_RELAXED);
        __atomic_store_n(&h->last_used, tick, __ATOMIC_RELAXED);
        bpf_prog_handle_acquire(h);
    }
    return h;
}

static sol_bpf_prog_handle_t*
bpf_prog_cache_insert_locked(const sol_pubkey_t* program_id, sol_bpf_prog_handle_t* h) {
    if (!g_bpf_prog_cache || !program_id || !h) return NULL;

    /* Another thread may have inserted while we were loading. Use the existing handle. */
    sol_bpf_prog_handle_t* existing = bpf_prog_cache_get_locked(program_id);
    if (existing) {
        return existing;
    }

    if (h->ro_section_len > g_bpf_prog_cache_max_bytes) {
        return NULL;
    }

    bpf_prog_cache_evict_if_needed_locked(h->ro_section_len);

    uint64_t tick = __atomic_add_fetch(&g_bpf_prog_cache_clock, 1u, __ATOMIC_RELAXED);
    __atomic_store_n(&h->last_used, tick, __ATOMIC_RELAXED);
    h->refcnt = 1u; /* cache owns one ref while resident */

    sol_bpf_prog_handle_t* val = h;
    void* slot = sol_pubkey_map_insert(g_bpf_prog_cache, program_id, &val);
    if (!slot) {
        return NULL;
    }

    g_bpf_prog_cache_total_bytes += h->ro_section_len;

    /* Return an acquired ref for execution. */
    bpf_prog_handle_acquire(h);
    return h;
}

static void
bpf_prog_cache_invalidate_program(const sol_pubkey_t* program_id) {
    bpf_prog_cache_init();
    if (!g_bpf_prog_cache) return;
    pthread_rwlock_wrlock(&g_bpf_prog_cache_lock);
    bpf_prog_cache_remove_locked(program_id);
    pthread_rwlock_unlock(&g_bpf_prog_cache_lock);

    /* Parallel scheduler also caches Program->ProgramData mapping. */
    sol_bank_programdata_cache_invalidate_program(program_id);
}

static void
bpf_prog_cache_invalidate_programdata(const sol_pubkey_t* programdata_id) {
    bpf_prog_cache_init();
    if (!g_bpf_prog_cache || !programdata_id) return;

    pthread_rwlock_wrlock(&g_bpf_prog_cache_lock);

    sol_pubkey_t to_remove[128];
    size_t n = 0;

    sol_map_iter_t it = sol_map_iter(g_bpf_prog_cache->inner);
    void* keyp = NULL;
    void* valp = NULL;
    while (sol_map_iter_next(&it, &keyp, &valp)) {
        sol_bpf_prog_handle_t* h = valp ? *(sol_bpf_prog_handle_t**)valp : NULL;
        if (!h || !h->prog) continue;
        if (!h->has_programdata) continue;
        if (!sol_pubkey_eq(&h->programdata, programdata_id)) continue;
        if (n < (sizeof(to_remove) / sizeof(to_remove[0]))) {
            memcpy(to_remove[n].bytes, keyp, SOL_PUBKEY_SIZE);
            n++;
        }
    }

    for (size_t i = 0; i < n; i++) {
        bpf_prog_cache_remove_locked(&to_remove[i]);
    }

    pthread_rwlock_unlock(&g_bpf_prog_cache_lock);

    sol_bank_programdata_cache_invalidate_programdata(programdata_id);
}

static sol_err_t
sbf_build_input(
    const sol_invoke_context_t* ctx,
    uint8_t** out_buf,
    size_t* out_len,
    sol_sbf_account_meta_t* out_metas,
    size_t* out_meta_count,
    uint64_t* out_instruction_data_vaddr,
    bool is_loader_deprecated
) {
    if (!ctx || !out_buf || !out_len || !out_metas || !out_meta_count) {
        return SOL_ERR_INVAL;
    }

    *out_buf = NULL;
    *out_len = 0;
    *out_meta_count = 0;
    if (out_instruction_data_vaddr) {
        *out_instruction_data_vaddr = 0;
    }

    if ((ctx->account_indices_len > 0 && !ctx->account_indices) ||
        (ctx->account_keys_len > 0 && !ctx->account_keys)) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    sol_err_t err = SOL_OK;

    int16_t first_pos[256];
    for (size_t i = 0; i < 256; i++) {
        first_pos[i] = -1;
    }

    /* Load unique accounts once, then allocate the full SBF input buffer once.
     *
     * Performance note: aligned SBF input includes large zero padding regions
     * (10 KiB realloc pad per account). The existing sbf_buf_reserve() uses
     * calloc() so sbf_buf_write_zeros() can advance without touching memory,
     * but repeated growth/copy dominates build time. */
    sol_account_t* loaded_accounts[256] = {0};
    const sol_slot_t zombie_slot = sol_bank_zombie_filter_slot(ctx->bank);
    sol_sbf_buf_t b = {0};
    size_t meta_count = 0;

    size_t total_len = 0;
    if (!sbf_size_add(&total_len, sizeof(uint64_t))) { /* ka_num */
        err = SOL_ERR_NOMEM;
        goto fail;
    }

    size_t meta_count_pre = 0;
    for (uint8_t ix_pos = 0; ix_pos < ctx->account_indices_len; ix_pos++) {
        uint8_t key_idx = ctx->account_indices[ix_pos];
        if (key_idx >= ctx->account_keys_len) {
            err = SOL_ERR_PROGRAM_INVALID_INSTR;
            goto fail;
        }

        int16_t prev = first_pos[key_idx];
        if (prev >= 0) {
            /* Duplicate account reference */
            if (!sbf_size_add(&total_len, 1u)) { /* dup marker */
                err = SOL_ERR_NOMEM;
                goto fail;
            }
            if (!is_loader_deprecated) {
                if (!sbf_size_add(&total_len, (size_t)SOL_SBF_DUP_PADDING)) {
                    err = SOL_ERR_NOMEM;
                    goto fail;
                }
            }
            continue;
        }

        first_pos[key_idx] = (int16_t)ix_pos;

        const sol_pubkey_t* key = &ctx->account_keys[key_idx];
        sol_slot_t stored_slot = 0;
        sol_account_t* account = sol_bank_load_account_view_ex(ctx->bank, key, &stored_slot);

        /* Zombie filtering (see main serialization loop for rationale). */
        if (account && account->meta.lamports == 0 &&
            stored_slot <= zombie_slot) {
            sol_account_destroy(account);
            account = NULL;
        }

        loaded_accounts[key_idx] = account;

        uint64_t data_len_u64 = account ? account->meta.data_len : 0;
        size_t data_len = 0;
        if (!sbf_u64_to_size(data_len_u64, &data_len)) {
            err = SOL_ERR_NOMEM;
            goto fail;
        }

        if (is_loader_deprecated) {
            /* 92 bytes of fixed fields + data_len bytes */
            if (!sbf_size_add(&total_len, 92u) ||
                !sbf_size_add(&total_len, data_len)) {
                err = SOL_ERR_NOMEM;
                goto fail;
            }
        } else {
            /* 10336 bytes of fixed fields (incl realloc pad + rent_epoch) + data + align pad */
            size_t pad = (8u - (data_len & 7u)) & 7u;
            if (!sbf_size_add(&total_len, 10336u) ||
                !sbf_size_add(&total_len, data_len) ||
                !sbf_size_add(&total_len, pad)) {
                err = SOL_ERR_NOMEM;
                goto fail;
            }
        }

        meta_count_pre++;
        if (meta_count_pre > SOL_MAX_ACCOUNTS_PER_TX) {
            err = SOL_ERR_PROGRAM_MAX_ACCOUNTS;
            goto fail;
        }
    }

    /* instruction data (u64 len + bytes) */
    size_t ix_data_len = 0;
    if (!sbf_u64_to_size((uint64_t)ctx->instruction_data_len, &ix_data_len)) {
        err = SOL_ERR_NOMEM;
        goto fail;
    }
    if (!sbf_size_add(&total_len, sizeof(uint64_t)) ||
        !sbf_size_add(&total_len, ix_data_len) ||
        !sbf_size_add(&total_len, 32u)) { /* program id */
        err = SOL_ERR_NOMEM;
        goto fail;
    }

    /* Pool serialized SBF input buffers per OS thread and CPI stack height to
     * avoid repeated large calloc/free churn and page faults on mainnet.
     *
     * IMPORTANT: use a distinct pool slot per stack height so nested CPI
     * invocations don't clobber the caller's serialized buffer. */
    enum { SOL_SBF_INPUT_POOL_MAX = 8 };
    static __thread sol_sbf_input_pool_t tls_input_pool[SOL_SBF_INPUT_POOL_MAX];

    size_t pool_idx = 0;
    if (ctx && ctx->stack_height > 0) {
        pool_idx = (size_t)(ctx->stack_height - 1u);
        if (pool_idx >= SOL_SBF_INPUT_POOL_MAX) {
            pool_idx = SOL_SBF_INPUT_POOL_MAX - 1u;
        }
    }

    sol_sbf_input_pool_t* pool = &tls_input_pool[pool_idx];
    if (!pool->buf || pool->cap < total_len) {
        size_t new_cap = pool->cap ? pool->cap : 4096u;
        while (new_cap < total_len) {
            if (new_cap > SIZE_MAX / 2) {
                new_cap = total_len;
                break;
            }
            new_cap *= 2u;
        }

        uint8_t* next = (uint8_t*)sol_alloc(new_cap);
        if (!next) {
            err = SOL_ERR_NOMEM;
            goto fail;
        }
        sol_free(pool->buf);
        pool->buf = next;
        pool->cap = new_cap;
    }

    b.data = pool->buf;
    b.cap = total_len;
    b.pooled = true;
    b.zeroed = false;

    /* ka_num (u64) */
    if (!sbf_buf_write_u64_le(&b, (uint64_t)ctx->account_indices_len)) {
        err = SOL_ERR_NOMEM;
        goto fail;
    }

    for (uint8_t ix_pos = 0; ix_pos < ctx->account_indices_len; ix_pos++) {
        uint8_t key_idx = ctx->account_indices[ix_pos];
        if (key_idx >= ctx->account_keys_len) {
            err = SOL_ERR_PROGRAM_INVALID_INSTR;
            goto fail;
        }

        int16_t prev = first_pos[key_idx];
        if (prev >= 0 && prev != (int16_t)ix_pos) {
            /* Duplicate account reference */
            if (!sbf_buf_write_u8(&b, (uint8_t)prev)) {
                err = SOL_ERR_NOMEM;
                goto fail;
            }
            /* Aligned (v2/upgradeable): 7 bytes padding.
               Unaligned (deprecated v1): no padding. */
            if (!is_loader_deprecated) {
                if (!sbf_buf_write_zeros(&b, SOL_SBF_DUP_PADDING)) {
                    err = SOL_ERR_NOMEM;
                    goto fail;
                }
            }
            continue;
        }

        const bool is_signer = ctx->is_signer
            ? ctx->is_signer[key_idx]
            : (key_idx < ctx->num_signers);
        const bool is_writable = ctx->is_writable
            ? ctx->is_writable[key_idx]
            : false;

        const sol_pubkey_t* key = &ctx->account_keys[key_idx];
        sol_account_t* account = loaded_accounts[key_idx];

        sol_pubkey_t owner = SOL_SYSTEM_PROGRAM_ID;
        uint64_t lamports = 0;
        uint64_t data_len = 0;
        bool executable = false;
        uint64_t rent_epoch = UINT64_MAX;  /* mask_out_rent_epoch_in_vm_serialization */
        const uint8_t* data = NULL;

        if (account) {
            owner = account->meta.owner;
            lamports = account->meta.lamports;
            data_len = account->meta.data_len;
            executable = account->meta.executable;
            /* rent_epoch is masked to UINT64_MAX for all accounts
             * (Agave feature: mask_out_rent_epoch_in_vm_serialization) */
            data = account->data;
        }

        size_t owner_off, lamports_off, data_len_off, data_off;

        if (is_loader_deprecated) {
            /* ========== Unaligned serialization (BPF Loader v1 / deprecated) ==========
             * Layout per Agave serialize_parameters_unaligned():
             *   u8 NON_DUP_MARKER, u8 is_signer, u8 is_writable,
             *   [32 key], u64 lamports, u64 data_len, [data],
             *   [32 owner], u8 executable, u64 rent_epoch
             * No 4-byte padding, no realloc padding, no alignment padding. */

            if (!sbf_buf_write_u8(&b, SOL_SBF_NON_DUP_MARKER) ||
                !sbf_buf_write_u8(&b, is_signer ? 1u : 0u) ||
                !sbf_buf_write_u8(&b, is_writable ? 1u : 0u)) {
                err = SOL_ERR_NOMEM;
                goto fail;
            }

            /* key */
            if (!sbf_buf_write(&b, key->bytes, 32u)) {
                err = SOL_ERR_NOMEM;
                goto fail;
            }

            /* lamports */
            lamports_off = b.len;
            if (!sbf_buf_write_u64_le(&b, lamports)) {
                err = SOL_ERR_NOMEM;
                goto fail;
            }

            /* data len */
            data_len_off = b.len;
            if (!sbf_buf_write_u64_le(&b, data_len)) {
                err = SOL_ERR_NOMEM;
                goto fail;
            }

            /* data (no realloc padding, no alignment padding) */
            data_off = b.len;
            if (data_len > 0) {
                if (!data || !sbf_buf_write(&b, data, (size_t)data_len)) {
                    err = SOL_ERR_NOMEM;
                    goto fail;
                }
            }

            /* owner (after data for unaligned format) */
            owner_off = b.len;
            if (!sbf_buf_write(&b, owner.bytes, 32u)) {
                err = SOL_ERR_NOMEM;
                goto fail;
            }

            /* executable */
            if (!sbf_buf_write_u8(&b, executable ? 1u : 0u)) {
                err = SOL_ERR_NOMEM;
                goto fail;
            }

            /* rent epoch */
            if (!sbf_buf_write_u64_le(&b, rent_epoch)) {
                err = SOL_ERR_NOMEM;
                goto fail;
            }
        } else {
            /* ========== Aligned serialization (BPF Loader v2 / Upgradeable) ==========
             * Layout per Agave serialize_parameters_aligned():
             *   u8 NON_DUP_MARKER, u8 is_signer, u8 is_writable, u8 executable,
             *   [4 pad], [32 key], [32 owner], u64 lamports, u64 data_len,
             *   [data], [10K realloc pad], [align pad], u64 rent_epoch */

            /* dup_info + flags */
            if (!sbf_buf_write_u8(&b, SOL_SBF_NON_DUP_MARKER) ||
                !sbf_buf_write_u8(&b, is_signer ? 1u : 0u) ||
                !sbf_buf_write_u8(&b, is_writable ? 1u : 0u) ||
                !sbf_buf_write_u8(&b, executable ? 1u : 0u) ||
                !sbf_buf_write_zeros(&b, 4u)) {
                err = SOL_ERR_NOMEM;
                goto fail;
            }

            /* key */
            if (!sbf_buf_write(&b, key->bytes, 32u)) {
                err = SOL_ERR_NOMEM;
                goto fail;
            }

            /* owner */
            owner_off = b.len;
            if (!sbf_buf_write(&b, owner.bytes, 32u)) {
                err = SOL_ERR_NOMEM;
                goto fail;
            }

            /* lamports */
            lamports_off = b.len;
            if (!sbf_buf_write_u64_le(&b, lamports)) {
                err = SOL_ERR_NOMEM;
                goto fail;
            }

            /* data len */
            data_len_off = b.len;
            if (!sbf_buf_write_u64_le(&b, data_len)) {
                err = SOL_ERR_NOMEM;
                goto fail;
            }

            /* data */
            data_off = b.len;
            if (data_len > 0) {
                if (!data || !sbf_buf_write(&b, data, (size_t)data_len)) {
                    err = SOL_ERR_NOMEM;
                    goto fail;
                }
            }

            /* realloc padding */
            if (!sbf_buf_write_zeros(&b, SOL_SBF_MAX_PERMITTED_DATA_INCREASE)) {
                err = SOL_ERR_NOMEM;
                goto fail;
            }

            /* align to BPF_ALIGN_OF_U128 (8-byte) boundary after realloc region */
            size_t pad = (8u - ((size_t)data_len & 7u)) & 7u;
            if (pad && !sbf_buf_write_zeros(&b, pad)) {
                err = SOL_ERR_NOMEM;
                goto fail;
            }

            /* rent epoch */
            if (!sbf_buf_write_u64_le(&b, rent_epoch)) {
                err = SOL_ERR_NOMEM;
                goto fail;
            }
        }

        if (meta_count >= SOL_MAX_ACCOUNTS_PER_TX) {
            err = SOL_ERR_PROGRAM_MAX_ACCOUNTS;
            goto fail;
        }

        /* Retain the pre-exec account snapshot for writeback. This avoids
         * re-loading from the parent (disk) when the overlay has no local delta. */
        sol_account_t* ro_keep = account;

        out_metas[meta_count++] = (sol_sbf_account_meta_t){
            .key_index = key_idx,
            .is_writable = is_writable,
            .is_signer = is_signer,
            .pre_lamports = lamports,
            .pre_data_len = data_len,
            .ro_account = ro_keep,
            .owner_off = owner_off,
            .lamports_off = lamports_off,
            .data_len_off = data_len_off,
            .data_off = data_off,
        };

        /* Transfer ownership of the loaded account snapshot to meta. */
        if (account) {
            loaded_accounts[key_idx] = NULL;
        }
    }

    /* instruction data */
    if (!sbf_buf_write_u64_le(&b, (uint64_t)ctx->instruction_data_len)) {
        err = SOL_ERR_NOMEM;
        goto fail;
    }

    if (out_instruction_data_vaddr) {
        *out_instruction_data_vaddr = SOL_BPF_MM_INPUT_START + (uint64_t)b.len;
    }

    if (ctx->instruction_data_len > 0) {
        if (!ctx->instruction_data ||
            !sbf_buf_write(&b, ctx->instruction_data, (size_t)ctx->instruction_data_len)) {
            err = SOL_ERR_NOMEM;
            goto fail;
        }
    }

    /* program id */
    if (!sbf_buf_write(&b, ctx->program_id.bytes, 32u)) {
        err = SOL_ERR_NOMEM;
        goto fail;
    }

    *out_buf = b.data;
    *out_len = b.len;
    *out_meta_count = meta_count;

    sbf_loaded_accounts_destroy(loaded_accounts);
    return SOL_OK;

fail:
    sbf_metas_release_retained(out_metas, meta_count);
    sbf_loaded_accounts_destroy(loaded_accounts);
    sbf_buf_free(&b);
    return err;
}

static sol_err_t
sbf_apply_output(
    const sol_invoke_context_t* ctx,
    const uint8_t* buf,
    size_t buf_len,
    const sol_sbf_account_meta_t* metas,
    size_t meta_count
) {
    if (!ctx || !ctx->bank || !buf || (!metas && meta_count > 0)) {
        return SOL_ERR_INVAL;
    }

    if (meta_count > 0 && !ctx->account_keys) {
        return SOL_ERR_INVAL;
    }

    /* Verify instruction lamports balance (best-effort). */
    static int sbf_wb_diag_cached = -1;
    if (sbf_wb_diag_cached < 0) {
        const char* env = getenv("SOL_SBF_WB_DIAG");
        sbf_wb_diag_cached = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    }
    bool wb_diag = sbf_wb_diag_cached != 0;

    int128 delta = 0;
    int128 bank_delta = 0;  /* cross-check against current bank values (diagnostic) */
    for (size_t i = 0; i < meta_count; i++) {
        const sol_sbf_account_meta_t* m = &metas[i];
        if (m->lamports_off + sizeof(uint64_t) > buf_len) {
            sol_log_error("bpf_wb: lamports_off OOB i=%zu off=%zu buf_len=%zu",
                          i, m->lamports_off, buf_len);
            return SOL_ERR_BPF_EXECUTE;
        }
        uint64_t post_lamports = 0;
        memcpy(&post_lamports, buf + m->lamports_off, sizeof(uint64_t));
        delta += (int128)post_lamports - (int128)m->pre_lamports;

        /* Cross-check: compare post_lamports vs current bank value */
        if (wb_diag && m->key_index < ctx->account_keys_len) {
            sol_account_t* _chk = sol_bank_load_account_view(ctx->bank, &ctx->account_keys[m->key_index]);
            uint64_t bank_lam = _chk ? _chk->meta.lamports : 0;
            if (_chk) sol_account_destroy(_chk);
            bank_delta += (int128)post_lamports - (int128)bank_lam;
            /* Log when bank value differs from BOTH pre and post (CPI residual) */
            if (bank_lam != m->pre_lamports && bank_lam != post_lamports) {
                char _k58[SOL_PUBKEY_BASE58_LEN] = {0};
                sol_pubkey_to_base58(&ctx->account_keys[m->key_index], _k58, sizeof(_k58));
                sol_log_info("SBF_WB_3WAY: key=%s pre=%lu bank=%lu post=%lu",
                             _k58, (unsigned long)m->pre_lamports,
                             (unsigned long)bank_lam, (unsigned long)post_lamports);
            }
        }
    }
    /* Optional writeback diagnostics: these require loading bank state and can
     * severely throttle replay. */
    if (wb_diag && (delta != 0 || bank_delta != 0)) {
        char _prog58[SOL_PUBKEY_BASE58_LEN] = {0};
        sol_pubkey_to_base58(&ctx->program_id, _prog58, sizeof(_prog58));
        sol_log_info("SBF_BALANCE: delta=%lld bank_delta=%lld meta_count=%zu program=%s depth=%u",
                     (long long)(int64_t)delta, (long long)(int64_t)bank_delta,
                     meta_count, _prog58, (unsigned)ctx->stack_height);
    }
    if (delta != 0) {
        char _prog58[SOL_PUBKEY_BASE58_LEN] = {0};
        sol_pubkey_to_base58(&ctx->program_id, _prog58, sizeof(_prog58));
        sol_log_error("SBF: unbalanced instruction lamports delta=%lld program=%s meta_count=%zu",
                      (long long)(int64_t)delta, _prog58, meta_count);
        for (size_t i = 0; i < meta_count && i < 64; i++) {
            const sol_sbf_account_meta_t* m = &metas[i];
            uint64_t post = 0;
            memcpy(&post, buf + m->lamports_off, sizeof(uint64_t));
            char _k58[SOL_PUBKEY_BASE58_LEN] = {0};
            if (m->key_index < ctx->account_keys_len) {
                sol_pubkey_to_base58(&ctx->account_keys[m->key_index], _k58, sizeof(_k58));
            }
            sol_log_error("  account[%zu] key=%s pre=%lu post=%lu diff=%lld writable=%d",
                          i, _k58, (unsigned long)m->pre_lamports, (unsigned long)post,
                          (long long)((int64_t)post - (int64_t)m->pre_lamports),
                          (int)m->is_writable);
        }
        return SOL_ERR_ACCOUNT_LAMPORTS;
    }

    sol_accounts_db_t* accounts_db = sol_bank_get_accounts_db(ctx->bank);
    bool overlay_bank = accounts_db && sol_accounts_db_is_overlay(accounts_db);

    for (size_t i = 0; i < meta_count; i++) {
        const sol_sbf_account_meta_t* m = &metas[i];
        uint8_t key_idx = m->key_index;
        if (key_idx >= ctx->account_keys_len) {
            return SOL_ERR_PROGRAM_INVALID_INSTR;
        }

        const sol_pubkey_t* pubkey = &ctx->account_keys[key_idx];

        uint64_t post_lamports = 0;
        uint64_t post_data_len = 0;
        sol_pubkey_t post_owner = {0};

        if (m->lamports_off + sizeof(uint64_t) > buf_len ||
            m->data_len_off + sizeof(uint64_t) > buf_len ||
            m->owner_off + 32u > buf_len) {
            sol_log_error("bpf_wb: field OOB i=%zu lam=%zu dl=%zu own=%zu buf=%zu",
                          i, m->lamports_off, m->data_len_off, m->owner_off, buf_len);
            return SOL_ERR_BPF_EXECUTE;
        }

        memcpy(&post_lamports, buf + m->lamports_off, sizeof(uint64_t));
        memcpy(&post_data_len, buf + m->data_len_off, sizeof(uint64_t));
        memcpy(post_owner.bytes, buf + m->owner_off, 32u);

        if (post_data_len > SOL_ACCOUNT_MAX_DATA_SIZE) {
            return SOL_ERR_ACCOUNT_DATA_TOO_LARGE;
        }

        /* Basic realloc bound (no realloc syscall support yet, but be defensive). */
        if (post_data_len > m->pre_data_len &&
            (post_data_len - m->pre_data_len) > SOL_SBF_MAX_PERMITTED_DATA_INCREASE) {
            return SOL_ERR_ACCOUNT_DATA_TOO_LARGE;
        }

        if (m->data_off + (size_t)post_data_len > buf_len) {
            char k58[SOL_PUBKEY_BASE58_LEN] = {0};
            sol_pubkey_to_base58(pubkey, k58, sizeof(k58));
            sol_log_error("bpf_wb: data OOB i=%zu acct=%s data_off=%zu post_data_len=%lu "
                          "pre_data_len=%lu buf_len=%zu",
                          i, k58, m->data_off, (unsigned long)post_data_len,
                          (unsigned long)m->pre_data_len, buf_len);
            return SOL_ERR_BPF_EXECUTE;
        }

        const uint8_t* post_data = buf + m->data_off;
        uint64_t pre_lamports = m->pre_lamports;
        uint64_t pre_data_len = m->pre_data_len;
        sol_pubkey_t pre_owner = SOL_SYSTEM_PROGRAM_ID;
        const uint8_t* pre_data = NULL;
        if (m->ro_account) {
            pre_owner = m->ro_account->meta.owner;
            pre_data = m->ro_account->data;
        }

        bool owner_ok = sol_pubkey_eq(&post_owner, &pre_owner);
        bool lamports_ok = post_lamports == pre_lamports;
        bool len_ok = post_data_len == pre_data_len;
        bool data_ok = true;
        if (post_data_len > 0) {
            if (!pre_data) {
                data_ok = false;
            } else if (memcmp(pre_data, post_data, (size_t)post_data_len) != 0) {
                data_ok = false;
            }
        }

        /* Fast path: read-only accounts cannot legally change during a program
         * invocation (including during CPI), so validate against the retained
         * pre-exec snapshot and skip the post-exec reload. */
        if (!m->is_writable) {
            if (!owner_ok || !lamports_ok || !len_ok || !data_ok) {
                char k58[SOL_PUBKEY_BASE58_LEN] = {0};
                sol_pubkey_to_base58(pubkey, k58, sizeof(k58));
                sol_log_error("bpf_wb_diag: ro_mutation acct=%s lam_pre=%lu lam_post=%lu len_pre=%lu len_post=%lu",
                              k58, (unsigned long)pre_lamports, (unsigned long)post_lamports,
                              (unsigned long)pre_data_len, (unsigned long)post_data_len);
                return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
            }

            continue;
        }

        /* Writable fast path: unchanged output means no bank reload/store needed.
         * This avoids expensive local-kind lookups and data compares on hot
         * account sets where many writable accounts are untouched. */
        if (owner_ok && lamports_ok && len_ok && data_ok) {
            continue;
        }

        sol_account_t* account = NULL;
        bool account_owned_by_meta = false;

        /* Avoid expensive parent reloads for overlay banks.
         *
         * For overlay banks, CPI/previous-instruction mutations are stored in
         * the local layer. If there's no local entry, the current value is the
         * same as the pre-exec snapshot we already loaded in sbf_build_input(). */
        if (overlay_bank) {
            sol_account_t* local = NULL;
            sol_accounts_db_local_kind_t kind =
                sol_accounts_db_get_local_kind(accounts_db, pubkey, &local);
            if (kind == SOL_ACCOUNTS_DB_LOCAL_ACCOUNT) {
                account = local; /* owned by caller */
            } else if (kind == SOL_ACCOUNTS_DB_LOCAL_TOMBSTONE) {
                account = NULL;
            } else { /* SOL_ACCOUNTS_DB_LOCAL_MISSING */
                if (m->ro_account) {
                    account = m->ro_account; /* owned by meta */
                    account_owned_by_meta = true;
                }
            }
        } else {
            sol_slot_t sto_slot = 0;
            account = sol_bank_load_account_view_ex(ctx->bank, pubkey, &sto_slot);
            /* Filter zombie accounts (0 lamports, stored before current slot) */
            if (account && account->meta.lamports == 0 && m->pre_lamports == 0 &&
                sto_slot <= sol_bank_zombie_filter_slot(ctx->bank)) {
                sol_account_destroy(account);
                account = NULL;
            }
        }

        if (!account) {
            account = sol_account_new(0, 0, &SOL_SYSTEM_PROGRAM_ID);
            if (!account) {
                return SOL_ERR_NOMEM;
            }
            account_owned_by_meta = false;
        }

        bool touched = false;

        /* Lamports writeback + checks */
        if (post_lamports != account->meta.lamports) {
            if (!m->is_writable) {
                if (wb_diag) {
                    char k58[SOL_PUBKEY_BASE58_LEN] = {0};
                    sol_pubkey_to_base58(pubkey, k58, sizeof(k58));
                    sol_log_error("bpf_wb_diag: lamports_ro acct=%s pre=%lu post=%lu",
                                  k58, (unsigned long)account->meta.lamports,
                                  (unsigned long)post_lamports);
                }
                sbf_destroy_if_not_retained(account, account_owned_by_meta);
                return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
            }
            if (!sol_pubkey_eq(&account->meta.owner, &ctx->program_id) &&
                post_lamports < account->meta.lamports) {
                if (wb_diag) {
                    char k58[SOL_PUBKEY_BASE58_LEN] = {0};
                    sol_pubkey_to_base58(pubkey, k58, sizeof(k58));
                    sol_log_error("bpf_wb_diag: lamports_nonowner acct=%s pre=%lu post=%lu",
                                  k58, (unsigned long)account->meta.lamports,
                                  (unsigned long)post_lamports);
                }
                sbf_destroy_if_not_retained(account, account_owned_by_meta);
                return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
            }
            account->meta.lamports = post_lamports;
            touched = true;
        }

        /* Data writeback + checks */
        bool data_changed = false;
        if (account->meta.data_len != (size_t)post_data_len) {
            data_changed = true;
        } else if (post_data_len > 0) {
            if (!account->data) {
                data_changed = true;
            } else if (memcmp(account->data, post_data, (size_t)post_data_len) != 0) {
                data_changed = true;
            }
        }

        if (data_changed) {
            if (!m->is_writable) {
                if (wb_diag) {
                    char k58[SOL_PUBKEY_BASE58_LEN] = {0};
                    sol_pubkey_to_base58(pubkey, k58, sizeof(k58));
                    sol_log_error("bpf_wb_diag: data_ro acct=%s data_len=%zu post_len=%lu",
                                  k58, account->meta.data_len, (unsigned long)post_data_len);
                }
                sbf_destroy_if_not_retained(account, account_owned_by_meta);
                return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
            }
            if (!sol_pubkey_eq(&account->meta.owner, &ctx->program_id)) {
                if (wb_diag) {
                    char k58[SOL_PUBKEY_BASE58_LEN] = {0};
                    char own58[SOL_PUBKEY_BASE58_LEN] = {0};
                    char prog58[SOL_PUBKEY_BASE58_LEN] = {0};
                    sol_pubkey_to_base58(pubkey, k58, sizeof(k58));
                    sol_pubkey_to_base58(&account->meta.owner, own58, sizeof(own58));
                    sol_pubkey_to_base58(&ctx->program_id, prog58, sizeof(prog58));
                    sol_log_error("bpf_wb_diag: data_nonowner acct=%s owner=%s prog=%s",
                                  k58, own58, prog58);
                }
                sbf_destroy_if_not_retained(account, account_owned_by_meta);
                return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
            }
            sol_err_t set_err = sol_account_set_data(account, post_data, (size_t)post_data_len);
            if (set_err != SOL_OK) {
                sbf_destroy_if_not_retained(account, account_owned_by_meta);
                return set_err;
            }
            touched = true;
        }

        /* Owner writeback (rare; typically updated via CPI before end). */
        if (!sol_pubkey_eq(&post_owner, &account->meta.owner)) {
            if (!m->is_writable) {
                if (wb_diag) {
                    char k58[SOL_PUBKEY_BASE58_LEN] = {0};
                    sol_pubkey_to_base58(pubkey, k58, sizeof(k58));
                    sol_log_error("bpf_wb_diag: owner_ro acct=%s", k58);
                }
                sbf_destroy_if_not_retained(account, account_owned_by_meta);
                return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
            }
            if (!sol_pubkey_eq(&account->meta.owner, &ctx->program_id)) {
                if (wb_diag) {
                    char k58[SOL_PUBKEY_BASE58_LEN] = {0};
                    char own58[SOL_PUBKEY_BASE58_LEN] = {0};
                    char prog58[SOL_PUBKEY_BASE58_LEN] = {0};
                    sol_pubkey_to_base58(pubkey, k58, sizeof(k58));
                    sol_pubkey_to_base58(&account->meta.owner, own58, sizeof(own58));
                    sol_pubkey_to_base58(&ctx->program_id, prog58, sizeof(prog58));
                    sol_log_error("bpf_wb_diag: owner_nonowner acct=%s owner=%s prog=%s",
                                  k58, own58, prog58);
                }
                sbf_destroy_if_not_retained(account, account_owned_by_meta);
                return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
            }

            /* Require data be zeroed/empty when changing owner. */
            bool zeroed = true;
            for (size_t j = 0; j < account->meta.data_len; j++) {
                if (account->data && account->data[j] != 0) {
                    zeroed = false;
                    break;
                }
            }
            if (!zeroed) {
                if (wb_diag) {
                    char k58[SOL_PUBKEY_BASE58_LEN] = {0};
                    sol_pubkey_to_base58(pubkey, k58, sizeof(k58));
                    sol_log_error("bpf_wb_diag: owner_data_nonzero acct=%s data_len=%zu",
                                  k58, account->meta.data_len);
                }
                sbf_destroy_if_not_retained(account, account_owned_by_meta);
                return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
            }

            account->meta.owner = post_owner;
            touched = true;
        }

        if (touched) {
            sol_err_t store_err = sol_bank_store_account(ctx->bank, pubkey, account);
            if (store_err != SOL_OK) {
                sbf_destroy_if_not_retained(account, account_owned_by_meta);
                return store_err;
            }
        }

        if (!account_owned_by_meta) {
            sol_account_destroy(account);
        }
    }

    return SOL_OK;
}

static sol_bpf_vm_t*
new_vm_for_context(const sol_invoke_context_t* ctx) {
    sol_bpf_config_t cfg = (sol_bpf_config_t)SOL_BPF_CONFIG_DEFAULT;

    if (ctx != NULL) {
        if (ctx->compute_budget != NULL) {
            cfg.heap_size = (size_t)ctx->compute_budget->heap_size;
        }

        if (ctx->compute_meter != NULL) {
            cfg.compute_units = ctx->compute_meter->remaining;
        } else if (ctx->compute_budget != NULL) {
            cfg.compute_units = (uint64_t)ctx->compute_budget->compute_unit_limit;
        }
    }

    /* Creating and destroying a full VM for every program invocation is
     * extremely expensive (stack+heap allocation + syscall registration).
     * Reuse VMs per OS thread *and per CPI stack height* so nested invocations
     * do not clobber the caller VM. */
    enum { SOL_BPF_VM_POOL_MAX = 8 };
    static __thread sol_bpf_vm_t* tls_vm_pool[SOL_BPF_VM_POOL_MAX];

    size_t pool_idx = 0;
    if (ctx && ctx->stack_height > 0) {
        pool_idx = (size_t)(ctx->stack_height - 1u);
        if (pool_idx >= SOL_BPF_VM_POOL_MAX) {
            pool_idx = SOL_BPF_VM_POOL_MAX - 1u;
        }
    }

    sol_bpf_vm_t** slot = &tls_vm_pool[pool_idx];

    if (*slot == NULL || (*slot)->heap_size != cfg.heap_size) {
        if (*slot) {
            sol_bpf_vm_destroy(*slot);
            *slot = NULL;
        }
        *slot = sol_bpf_vm_new(&cfg);
        if (*slot == NULL) {
            return NULL;
        }
    }

    if (sol_bpf_vm_reset(*slot, cfg.compute_units) != SOL_OK) {
        /* Defensive: if reset fails (OOM), fall back to a fresh VM. */
        sol_bpf_vm_destroy(*slot);
        *slot = sol_bpf_vm_new(&cfg);
        if (*slot == NULL) {
            return NULL;
        }
        if (sol_bpf_vm_reset(*slot, cfg.compute_units) != SOL_OK) {
            return NULL;
        }
    }

    return *slot;
}

static void
destroy_vm_detach_program(sol_bpf_vm_t* vm) {
    if (!vm) return;
    vm->program = NULL; /* program may be cached/shared */
    /* VM is thread-local pooled; do not destroy. */
}

static sol_err_t
vm_attach_program(sol_bpf_vm_t* vm, sol_bpf_program_t* prog) {
    if (!vm || !prog || !prog->ro_section || prog->ro_section_len == 0) {
        return SOL_ERR_INVAL;
    }

    sol_err_t err = sol_bpf_memory_add_region(&vm->memory, SOL_BPF_MM_PROGRAM_START,
                                              prog->ro_section, prog->ro_section_len, false);
    if (err != SOL_OK) {
        return err;
    }

    vm->program = prog;
    vm->pc = prog->entry_pc;

    /* Adjust frame pointer (r10) based on SBPF version (matches sol_bpf_vm_load). */
    if (sol_sbpf_dynamic_stack_frames(prog->sbpf_version)) {
        vm->reg[10] = SOL_BPF_MM_STACK_START + (uint64_t)vm->stack_size;

        /* Convert gapped stack mapping to linear for SBPFv1+. */
        for (size_t i = 0; i < vm->memory.region_count; i++) {
            sol_bpf_region_t* r = &vm->memory.regions[i];
            if (r->vaddr == SOL_BPF_MM_STACK_START &&
                r->kind == SOL_BPF_REGION_GAPPED) {
                r->kind = SOL_BPF_REGION_LINEAR;
                r->len = r->host_len;
                r->elem_len = 0;
                r->gap_len = 0;
                vm->stack_virt_size = r->host_len;
                vm->stack_gap_size = 0;
                break;
            }
        }
    }

    return SOL_OK;
}

static sol_err_t
execute_sbf_program(
    sol_invoke_context_t* ctx,
    sol_bpf_program_t* prog,
    bool is_loader_deprecated
) {
    if (!ctx || !ctx->bank || !prog) {
        return SOL_ERR_INVAL;
    }

    const bool prof = sbf_profile_enabled();
    const uint64_t slow_thresh_ns = sbf_slow_threshold_ns();
    const bool slow_enabled = slow_thresh_ns != 0u;
    uint64_t prof_build_ns = 0;
    uint64_t prof_map_ns = 0;
    uint64_t prof_exec_ns = 0;
    uint64_t prof_wb_ns = 0;
    size_t prof_input_len = 0;
    size_t prof_meta_count = 0;
    uint64_t t0 = 0;
    uint64_t t1 = 0;

    uint64_t slow_total_t0 = slow_enabled ? monotonic_ns() : 0;
    uint64_t slow_build_ns = 0;
    uint64_t slow_map_ns = 0;
    uint64_t slow_exec_ns = 0;
    uint64_t slow_wb_ns = 0;
    size_t slow_input_len = 0;
    size_t slow_meta_count = 0;

    /* BPF runtime error diagnostics are extremely expensive on mainnet because
     * many transactions fail legitimately (compute exceeded, syscall failures,
     * etc). Opt-in via SOL_SBF_VM_DIAG=1. */
    static int sbf_vm_diag_cached = -1;
    if (sbf_vm_diag_cached < 0) {
        const char* env = getenv("SOL_SBF_VM_DIAG");
        sbf_vm_diag_cached = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    }
    bool vm_diag = sbf_vm_diag_cached != 0;
    /* Avoid expensive debug formatting (base58, etc) when debug logging is off. */
    const bool log_debug = sol_log_get_level() <= SOL_LOG_DEBUG;

    sol_bpf_vm_t* vm = new_vm_for_context(ctx);
    if (vm == NULL) {
        return SOL_ERR_NOMEM;
    }

    vm->loader_deprecated = is_loader_deprecated;

    sol_bpf_vm_set_cpi_handler(vm, sol_bpf_loader_cpi_dispatch);
    sol_bpf_vm_set_context(vm, ctx);

    sol_err_t err = vm_attach_program(vm, prog);
    if (err != SOL_OK) {
        destroy_vm_detach_program(vm);
        return err;
    }

    uint8_t* input_buf = NULL;
    size_t input_len = 0;
    sol_sbf_account_meta_t metas[SOL_MAX_ACCOUNTS_PER_TX];
    size_t meta_count = 0;
    uint64_t instruction_data_vaddr = 0;

    if (prof || slow_enabled) t0 = monotonic_ns();
    err = sbf_build_input(ctx, &input_buf, &input_len,
                          metas, &meta_count,
                          &instruction_data_vaddr,
                          is_loader_deprecated);
    if (prof || slow_enabled) {
        t1 = monotonic_ns();
        if (prof) {
            prof_build_ns = t1 - t0;
            prof_input_len = input_len;
            prof_meta_count = meta_count;
        }
        if (slow_enabled) {
            slow_build_ns = t1 - t0;
            slow_input_len = input_len;
            slow_meta_count = meta_count;
        }
    }
    if (err != SOL_OK) {
        destroy_vm_detach_program(vm);
        sbf_metas_release_retained(metas, meta_count);
        if (prof) {
            sbf_profile_commit(prof_build_ns, prof_map_ns, prof_exec_ns, prof_wb_ns,
                               prof_input_len, prof_meta_count);
        }
        return err;
    }

    /* Map the entire serialized input buffer as a single writable region.
     *
     * Agave (rbpf) maps the input as one contiguous writable region and
     * enforces account writeability during post-exec deserialization/writeback
     * (sbf_apply_output).  Per-account overlays were previously used here to
     * fault early on writes to read-only accounts, but this differs from
     * Agave's behaviour: programs that temporarily write to read-only account
     * fields and later restore them succeed in Agave but would crash in our
     * VM due to the read-only overlay. */
    if (prof || slow_enabled) t0 = monotonic_ns();
    err = sol_bpf_memory_add_region(&vm->memory,
                                    SOL_BPF_MM_INPUT_START,
                                    input_buf,
                                    input_len,
                                    true);
    if (prof || slow_enabled) {
        t1 = monotonic_ns();
        if (prof) {
            prof_map_ns = t1 - t0;
        }
        if (slow_enabled) {
            slow_map_ns = t1 - t0;
        }
    }
    if (err != SOL_OK) {
        destroy_vm_detach_program(vm);
        sbf_metas_release_retained(metas, meta_count);
        if (prof) {
            sbf_profile_commit(prof_build_ns, prof_map_ns, prof_exec_ns, prof_wb_ns,
                               prof_input_len, prof_meta_count);
        }
        return err;
    }

    vm->reg[1] = SOL_BPF_MM_INPUT_START;
    /* r2-r5 stay 0, matching Agave's rbpf register initialization. */

    /* Store caller's serialized buffer info for CPI writeback.
     * When CPI returns, we must update the serialized buffer directly
     * (not through account_info pointers which may not point to the buffer). */
    vm->caller_input_buf = input_buf;
    vm->caller_input_len = input_len;
    vm->caller_metas = metas;
    vm->caller_meta_count = meta_count;

    /* BPF instruction tracing is opt-in. Enabling it can generate extremely
     * large logs and should never be on by default on mainnet. */
    {
        static int bpf_trace_cached = -1;
        static sol_pubkey_t trace_program_id;
        static int trace_program_id_valid = 0;
        static int trace_once = 1;
        static int trace_used = 0;

        if (bpf_trace_cached < 0) {
            const char* env = getenv("SOL_BPF_TRACE_PROGRAM_ID");
            if (env && env[0] != '\0' && strcmp(env, "0") != 0 &&
                sol_pubkey_from_base58(env, &trace_program_id) == SOL_OK) {
                trace_program_id_valid = 1;
            }
            const char* once_env = getenv("SOL_BPF_TRACE_ONCE");
            if (once_env && once_env[0] != '\0') {
                trace_once = strcmp(once_env, "0") != 0;
            }
            bpf_trace_cached = 0;
        }

        if (trace_program_id_valid && sol_pubkey_eq(&ctx->program_id, &trace_program_id)) {
            bool do_trace = true;
            if (trace_once) {
                do_trace = __sync_bool_compare_and_swap(&trace_used, 0, 1);
            }

            if (do_trace) {
                vm->trace = true;
                char p58[SOL_PUBKEY_BASE58_LEN] = {0};
                sol_pubkey_to_base58(&ctx->program_id, p58, sizeof(p58));
                sol_log_info("BPF_TRACE_START: program=%s input_len=%zu meta_count=%zu cu_limit=%lu",
                             p58, input_len, meta_count, (unsigned long)vm->compute_units);

                const char* dump_env = getenv("SOL_BPF_TRACE_DUMP_INPUT");
                if (dump_env && dump_env[0] != '\0' && strcmp(dump_env, "0") != 0) {
                    char fname[128];
                    snprintf(fname, sizeof(fname), "/tmp/bpf_trace_%s.bin", p58);
                    FILE* f = fopen(fname, "wb");
                    if (f) {
                        fwrite(input_buf, 1, input_len, f);
                        fclose(f);
                        sol_log_info("BPF_TRACE: dumped %zu bytes to %s", input_len, fname);
                    }
                }
            }
        }
    }

    if (__builtin_expect(log_debug, 0)) {
        char _cu_p58[SOL_PUBKEY_BASE58_LEN] = {0};
        sol_pubkey_to_base58(&ctx->program_id, _cu_p58, sizeof(_cu_p58));
        sol_log_debug("CU_TRACE vm_enter: program=%s vm_budget=%lu meter_remaining=%lu meter_consumed=%lu stack=%u",
                     _cu_p58,
                     (unsigned long)vm->compute_units,
                     ctx->compute_meter ? (unsigned long)ctx->compute_meter->remaining : 0UL,
                     ctx->compute_meter ? (unsigned long)ctx->compute_meter->consumed : 0UL,
                     (unsigned)ctx->stack_height);
    }

    if (prof || slow_enabled) t0 = monotonic_ns();
    err = sol_bpf_vm_execute(vm);
    if (prof || slow_enabled) {
        t1 = monotonic_ns();
        if (prof) {
            prof_exec_ns = t1 - t0;
        }
        if (slow_enabled) {
            slow_exec_ns = t1 - t0;
        }
    }
    sol_bpf_error_t vm_error = vm->error;
    uint64_t vm_pc = vm->pc;
    uint64_t fault_vaddr = vm->fault_vaddr;
    uint64_t fault_len = vm->fault_len;
    bool fault_write = vm->fault_write;
    uint64_t fault_pc = vm->fault_pc;
    uint64_t return_value = sol_bpf_vm_return_value(vm);
    uint64_t compute_used = sol_bpf_vm_compute_used(vm);

    if (__builtin_expect(log_debug, 0)) {
        char _cu_p58[SOL_PUBKEY_BASE58_LEN] = {0};
        sol_pubkey_to_base58(&ctx->program_id, _cu_p58, sizeof(_cu_p58));
        sol_log_debug("CU_TRACE vm_exit: program=%s vm_used=%lu vm_budget=%lu accounted=%lu meter_remaining=%lu meter_consumed=%lu err=%d vm_err=%d r0=%lu stack=%u",
                     _cu_p58,
                     (unsigned long)compute_used,
                     (unsigned long)vm->compute_units,
                     (unsigned long)ctx->compute_units_accounted,
                     ctx->compute_meter ? (unsigned long)ctx->compute_meter->remaining : 0UL,
                     ctx->compute_meter ? (unsigned long)ctx->compute_meter->consumed : 0UL,
                     (int)err, (int)vm_error,
                     (unsigned long)return_value,
                     (unsigned)ctx->stack_height);
    }

    if (ctx->compute_meter != NULL && compute_used >= ctx->compute_units_accounted) {
        uint64_t delta = compute_used - ctx->compute_units_accounted;
        sol_err_t meter_err = sol_compute_meter_consume(ctx->compute_meter, delta);
        ctx->compute_units_accounted = compute_used;
        if (err == SOL_OK && meter_err != SOL_OK) {
            err = meter_err;
        }
    }

    /*
     * deplete_cu_meter_on_vm_failure (SIMD-0182): In Agave, when the VM halts
     * due to a non-syscall error (divide by zero, access violation, etc.), all
     * remaining compute units are depleted. SyscallErrors (including CPI
     * failures) are excluded because the CU consumed up to the syscall call
     * is already tracked.
     */
    if (err != SOL_OK && ctx->compute_meter != NULL &&
        vm_error != SOL_BPF_ERR_SYSCALL_ERROR &&
        vm_error != SOL_BPF_OK) {
        ctx->compute_meter->remaining = 0;
    }

    if (err != SOL_OK) {
        if (vm_diag) {
        {
            char _p58[SOL_PUBKEY_BASE58_LEN] = {0};
            sol_pubkey_to_base58(&ctx->program_id, _p58, sizeof(_p58));
            if (vm_error == SOL_BPF_ERR_ACCESS_VIOLATION) {
                sol_log_info("SBF VM error: %s (pc=%lu) program=%s fault_vaddr=0x%lx fault_len=%lu fault_write=%d fault_pc=%lu",
                             sol_bpf_error_str(vm_error),
                             (unsigned long)vm_pc, _p58,
                             (unsigned long)fault_vaddr,
                             (unsigned long)fault_len,
                             (int)fault_write,
                             (unsigned long)fault_pc);
            } else {
                sol_log_info("SBF VM error: %s (pc=%lu) program=%s",
                             sol_bpf_error_str(vm_error),
                             (unsigned long)vm_pc, _p58);
            }
        }

        if (vm_error == SOL_BPF_ERR_INVALID_INSN &&
            vm->program != NULL &&
            vm->program->instructions != NULL) {
            uint64_t insn_pc = vm_pc ? (vm_pc - 1u) : 0u;
            if (insn_pc < vm->program->insn_count) {
                const sol_bpf_insn_t* bad = &vm->program->instructions[insn_pc];
                sol_log_info("SBF invalid insn: pc=%lu opcode=0x%02x dst=%u src=%u off=%d imm=%d",
                              (unsigned long)insn_pc,
                              (unsigned)bad->opcode,
                              (unsigned)SOL_BPF_INSN_DST(bad),
                              (unsigned)SOL_BPF_INSN_SRC(bad),
                              (int)bad->offset,
                              (int)bad->imm);
                sol_log_info("SBF invalid insn decoded: class=%u code=%u mode=%u size=%u src=%u",
                              (unsigned)SOL_BPF_OP_CLASS(bad->opcode),
                              (unsigned)SOL_BPF_OP_CODE(bad->opcode),
                              (unsigned)SOL_BPF_OP_MODE(bad->opcode),
                              (unsigned)SOL_BPF_OP_SIZE(bad->opcode),
                              (unsigned)SOL_BPF_OP_SRC(bad->opcode));
            }
        }

        if ((vm_error == SOL_BPF_ERR_DIVIDE_BY_ZERO || vm_error == SOL_BPF_ERR_DIVIDE_OVERFLOW) &&
            vm->program != NULL && vm->program->instructions != NULL) {
            uint64_t insn_pc = vm_pc ? (vm_pc - 1u) : 0u;
            if (insn_pc < vm->program->insn_count) {
                const sol_bpf_insn_t* bad = &vm->program->instructions[insn_pc];
                sol_log_info("SBF div error insn: pc=%lu opcode=0x%02x class=%u code=0x%02x "
                              "src_bit=%u dst=%u src=%u off=%d imm=%d "
                              "rdst=0x%lx rsrc=0x%lx r0=0x%lx r1=0x%lx",
                              (unsigned long)insn_pc,
                              (unsigned)bad->opcode,
                              (unsigned)SOL_BPF_OP_CLASS(bad->opcode),
                              (unsigned)SOL_BPF_OP_CODE(bad->opcode),
                              (unsigned)SOL_BPF_OP_SRC(bad->opcode),
                              (unsigned)SOL_BPF_INSN_DST(bad),
                              (unsigned)SOL_BPF_INSN_SRC(bad),
                              (int)bad->offset,
                              (int)bad->imm,
                              (unsigned long)(SOL_BPF_INSN_DST(bad) < SOL_BPF_NUM_REGISTERS ? vm->reg[SOL_BPF_INSN_DST(bad)] : 0ul),
                              (unsigned long)(SOL_BPF_INSN_SRC(bad) < SOL_BPF_NUM_REGISTERS ? vm->reg[SOL_BPF_INSN_SRC(bad)] : 0ul),
                              (unsigned long)vm->reg[0],
                              (unsigned long)vm->reg[1]);
            }
            /* Dump all registers at point of error */
            sol_log_info("SBF div regs: r0=0x%lx r1=0x%lx r2=0x%lx r3=0x%lx r4=0x%lx r5=0x%lx "
                          "r6=0x%lx r7=0x%lx r8=0x%lx r9=0x%lx r10=0x%lx",
                          (unsigned long)vm->reg[0], (unsigned long)vm->reg[1],
                          (unsigned long)vm->reg[2], (unsigned long)vm->reg[3],
                          (unsigned long)vm->reg[4], (unsigned long)vm->reg[5],
                          (unsigned long)vm->reg[6], (unsigned long)vm->reg[7],
                          (unsigned long)vm->reg[8], (unsigned long)vm->reg[9],
                          (unsigned long)vm->reg[10]);
            /* Dump 10 instructions before error PC */
            uint64_t err_pc = vm_pc ? (vm_pc - 1u) : 0u;
            uint64_t start_pc = (err_pc >= 10) ? (err_pc - 10) : 0;
            for (uint64_t di = start_pc; di <= err_pc && di < vm->program->insn_count; di++) {
                const sol_bpf_insn_t* d = &vm->program->instructions[di];
                sol_log_info("SBF div trace pc=%lu: op=0x%02x dst=%u src=%u off=%d imm=%d",
                              (unsigned long)di,
                              (unsigned)d->opcode,
                              (unsigned)SOL_BPF_INSN_DST(d),
                              (unsigned)SOL_BPF_INSN_SRC(d),
                              (int)d->offset,
                              (int)d->imm);
            }
            /* Dump entry_pc and first 10 insns around entrypoint for diagnosis */
            uint32_t epc = vm->program->entry_pc;
            sol_log_info("SBF div diag: entry_pc=%u insn_count=%zu text_vaddr=0x%lx text_len=%zu",
                          epc, vm->program->insn_count,
                          (unsigned long)vm->program->text_vaddr,
                          vm->program->text_len);
            for (uint32_t di = 0; di < 10 && (epc + di) < vm->program->insn_count; di++) {
                const sol_bpf_insn_t* d = &vm->program->instructions[epc + di];
                sol_log_info("SBF div diag insn[entry+%u] pc=%u: op=0x%02x dst=%u src=%u off=%d imm=%d",
                              di, epc + di,
                              (unsigned)d->opcode,
                              (unsigned)SOL_BPF_INSN_DST(d),
                              (unsigned)SOL_BPF_INSN_SRC(d),
                              (int)d->offset,
                              (int)d->imm);
            }
        }

        if (vm_error == SOL_BPF_ERR_CALL_OUTSIDE_TEXT) {
            static unsigned call_outside_budget = 32;
            if (call_outside_budget > 0 && vm->program != NULL && vm->program->instructions != NULL) {
                call_outside_budget--;

                uint64_t call_site_pc = vm_pc ? (vm_pc - 1u) : 0u;
                if (call_site_pc < vm->program->insn_count) {
                    const sol_bpf_insn_t* call_insn = &vm->program->instructions[call_site_pc];
                    uint8_t op_class = SOL_BPF_OP_CLASS(call_insn->opcode);
                    uint8_t op_code = SOL_BPF_OP_CODE(call_insn->opcode);
                    bool is_call = (op_class == SOL_BPF_CLASS_JMP && op_code == SOL_BPF_JMP_CALL);
                    bool use_imm = (SOL_BPF_OP_SRC(call_insn->opcode) == SOL_BPF_SRC_K);
                    uint8_t call_dst = SOL_BPF_INSN_DST(call_insn);
                    uint8_t call_src = SOL_BPF_INSN_SRC(call_insn);
                    int16_t call_off = call_insn->offset;
                    int32_t call_imm = call_insn->imm;

                    if (!is_call) {
                        sol_log_info("SBF call outside: pc=%lu opcode=0x%02x regs=0x%02x off=%d imm=%d (not a CALL)",
                                      (unsigned long)call_site_pc,
                                      call_insn->opcode,
                                      call_insn->regs,
                                      (int)call_off,
                                      (int)call_imm);
                    } else if (!use_imm) {
                        /* SBFv1: callx register is in imm, not src */
                        int reg = (int)call_imm;
                        uint64_t target_addr = 0;
                        if (reg >= 0 && reg < (int)SOL_BPF_NUM_REGISTERS) {
                            target_addr = vm->reg[(uint32_t)reg];
                        }
                        uint64_t text_start = SOL_BPF_MM_PROGRAM_START + vm->program->text_vaddr;
                        uint64_t text_end = text_start + vm->program->text_len;
                        sol_log_info("SBF call outside: callx pc=%lu opcode=0x%02x regs=0x%02x reg=%d target=0x%lx text=[0x%lx..0x%lx)",
                                      (unsigned long)call_site_pc,
                                      call_insn->opcode,
                                      call_insn->regs,
                                      reg,
                                      (unsigned long)target_addr,
                                      (unsigned long)text_start,
                                      (unsigned long)text_end);
                    } else {
                        int64_t target_pc = (int64_t)vm_pc + (int64_t)call_imm;
                        sol_log_info("SBF call outside: call pc=%lu opcode=0x%02x regs=0x%02x dst=%u src=%u off=%d imm=%d target_pc=%ld insn_count=%zu",
                                      (unsigned long)call_site_pc,
                                      call_insn->opcode,
                                      call_insn->regs,
                                      (unsigned)call_dst,
                                      (unsigned)call_src,
                                      (int)call_off,
                                      (int)call_imm,
                                      (long)target_pc,
                                      vm->program->insn_count);
                    }
                }
            }
        }

        if (vm_error == SOL_BPF_ERR_UNKNOWN_SYSCALL && vm->program && vm->program->instructions) {
            uint64_t call_site_pc = vm_pc ? (vm_pc - 1u) : 0u;
            if (call_site_pc < vm->program->insn_count) {
                const sol_bpf_insn_t* insn = &vm->program->instructions[call_site_pc];
                uint32_t hash = (uint32_t)insn->imm;

                const sol_invoke_context_t* ictx = (const sol_invoke_context_t*)vm->context;
                char prog_b58[64] = {0};
                if (ictx) {
                    (void)sol_pubkey_to_base58(&ictx->program_id, prog_b58, sizeof(prog_b58));
                }

                sol_log_info("SBF unknown syscall: program=%s hash=0x%08x pc=%lu opcode=0x%02x regs=0x%02x",
                              prog_b58[0] ? prog_b58 : "?",
                              hash,
                              (unsigned long)call_site_pc,
                              insn->opcode,
                              insn->regs);
            }
        }

        if (vm_error == SOL_BPF_ERR_ACCESS_VIOLATION || vm_error == SOL_BPF_ERR_INVALID_MEMORY) {
            const char* region = "unknown";
            if (fault_vaddr >= SOL_BPF_MM_INPUT_START) {
                region = "input";
            } else if (fault_vaddr >= SOL_BPF_MM_HEAP_START) {
                region = "heap";
            } else if (fault_vaddr >= SOL_BPF_MM_STACK_START) {
                region = "stack";
            } else if (fault_vaddr >= SOL_BPF_MM_PROGRAM_START) {
                region = "program";
            }
            sol_log_info("SBF fault: pc=%lu vaddr=0x%lx (%s) len=%lu write=%s",
                          (unsigned long)fault_pc,
                          (unsigned long)fault_vaddr,
                          region,
                          (unsigned long)fault_len,
                          fault_write ? "yes" : "no");

            static unsigned fault_budget = 32;
            if (fault_budget > 0 && vm->program && vm->program->instructions && fault_pc < vm->program->insn_count) {
                fault_budget--;
                const sol_bpf_insn_t* insn = &vm->program->instructions[fault_pc];
                uint8_t op_class = SOL_BPF_OP_CLASS(insn->opcode);
                uint8_t op_code = SOL_BPF_OP_CODE(insn->opcode);
                uint8_t dst = SOL_BPF_INSN_DST(insn);
                uint8_t src = SOL_BPF_INSN_SRC(insn);
                int16_t off = insn->offset;
                int32_t imm = insn->imm;

                const char* cls = "?";
                if (op_class == SOL_BPF_CLASS_LDX) cls = "LDX";
                else if (op_class == SOL_BPF_CLASS_STX) cls = "STX";
                else if (op_class == SOL_BPF_CLASS_ST) cls = "ST";

                sol_log_info("SBF fault insn: %s opcode=0x%02x code=0x%02x regs=0x%02x dst=%u src=%u off=%d imm=%d rdst=0x%lx rsrc=0x%lx",
                              cls,
                              insn->opcode,
                              op_code,
                              insn->regs,
                              (unsigned)dst,
                              (unsigned)src,
                              (int)off,
                              (int)imm,
                              (unsigned long)(dst < SOL_BPF_NUM_REGISTERS ? vm->reg[dst] : 0ul),
                              (unsigned long)(src < SOL_BPF_NUM_REGISTERS ? vm->reg[src] : 0ul));
            }
        }

        /* Log the specific BPF error type for diagnostics. */
        {
            const char* err_name = "?";
            switch (vm_error) {
                case SOL_BPF_OK:                err_name = "OK"; break;
                case SOL_BPF_ERR_UNKNOWN_SYSCALL: err_name = "UNKNOWN_SYSCALL"; break;
                case SOL_BPF_ERR_SYSCALL_ERROR: err_name = "SYSCALL_ERROR"; break;
                case SOL_BPF_ERR_COMPUTE_EXCEEDED: err_name = "COMPUTE_EXCEEDED"; break;
                case SOL_BPF_ERR_ACCESS_VIOLATION: err_name = "ACCESS_VIOLATION"; break;
                case SOL_BPF_ERR_INVALID_MEMORY: err_name = "INVALID_MEMORY"; break;
                case SOL_BPF_ERR_ABORT:         err_name = "ABORT"; break;
                case SOL_BPF_ERR_DIVIDE_BY_ZERO: err_name = "DIVIDE_BY_ZERO"; break;
                case SOL_BPF_ERR_DIVIDE_OVERFLOW: err_name = "DIVIDE_OVERFLOW"; break;
                case SOL_BPF_ERR_INVALID_INSN:  err_name = "INVALID_INSN"; break;
                case SOL_BPF_ERR_STACK_OVERFLOW: err_name = "STACK_OVERFLOW"; break;
                case SOL_BPF_ERR_CALL_DEPTH:    err_name = "CALL_DEPTH"; break;
                case SOL_BPF_ERR_CALL_OUTSIDE_TEXT: err_name = "CALL_OUTSIDE_TEXT"; break;
                case SOL_BPF_ERR_JIT_NOT_COMPILED: err_name = "JIT_NOT_COMPILED"; break;
                default:                        err_name = "OTHER"; break;
            }
            const sol_invoke_context_t* diag_ctx = (const sol_invoke_context_t*)vm->context;
            char diag_b58[64] = {0};
            if (diag_ctx) {
                (void)sol_pubkey_to_base58(&diag_ctx->program_id, diag_b58, sizeof(diag_b58));
            }
            sol_log_info("SBF vm_error: %s (%d) pc=%lu r0=%lu program=%s",
                          err_name, vm_error,
                          (unsigned long)vm_pc,
                          (unsigned long)return_value,
                          diag_b58[0] ? diag_b58 : "?");
        }
        }

        /* Provide a more specific failure bucket when possible. */
        switch (vm_error) {
            case SOL_BPF_OK:
            case SOL_BPF_ERR_UNKNOWN_SYSCALL:
            case SOL_BPF_ERR_SYSCALL_ERROR:
                err = SOL_ERR_BPF_SYSCALL;
                break;
            case SOL_BPF_ERR_COMPUTE_EXCEEDED:
                err = SOL_ERR_PROGRAM_COMPUTE;
                break;
            case SOL_BPF_ERR_ACCESS_VIOLATION:
            case SOL_BPF_ERR_INVALID_MEMORY:
                err = SOL_ERR_PROGRAM_MEMORY;
                break;
            case SOL_BPF_ERR_ABORT:
                err = SOL_ERR_PROGRAM_FAILED;
                break;
            case SOL_BPF_ERR_DIVIDE_BY_ZERO:
            case SOL_BPF_ERR_DIVIDE_OVERFLOW:
            case SOL_BPF_ERR_INVALID_INSN:
            case SOL_BPF_ERR_STACK_OVERFLOW:
            case SOL_BPF_ERR_CALL_DEPTH:
            case SOL_BPF_ERR_CALL_OUTSIDE_TEXT:
            case SOL_BPF_ERR_JIT_NOT_COMPILED:
            default:
                /* Keep SOL_ERR_BPF_EXECUTE */
                break;
        }
    }

    destroy_vm_detach_program(vm);

    /* Expensive per-transaction failure diagnostics are opt-in. Mainnet has a
     * large volume of failing transactions (which are still valid), and
     * dumping all account headers on failure can severely throttle replay. */
    static int bpf_fail_diag_cached = -1;
    if (bpf_fail_diag_cached < 0) {
        const char* env = getenv("SOL_BPF_FAIL_DIAG");
        bpf_fail_diag_cached = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    }

    /* Diagnostic: dump ALL account headers on BPF program failure */
    if (bpf_fail_diag_cached &&
        err == SOL_OK && return_value != 0 && input_buf && input_len >= 16) {
        /* MMM program: mmm3XBJg5gk8XJxEKBvdgptZz6SgK4tXvn36sodowMc */
        static const uint8_t mmm_id[32] = {
            0x0b, 0x78, 0x2a, 0x49, 0x3f, 0x91, 0xad, 0xf5,
            0x70, 0xe0, 0x69, 0x80, 0x15, 0x49, 0x12, 0xeb,
            0xff, 0x4a, 0x21, 0xe9, 0xfd, 0x74, 0x44, 0x43,
            0x25, 0xad, 0x6e, 0x17, 0xbb, 0x22, 0xeb, 0x73
        };
        bool is_mmm = memcmp(ctx->program_id.bytes, mmm_id, 32) == 0;
        static int _fail_diag_count = 0;
        if (_fail_diag_count < 50 || is_mmm) {
            _fail_diag_count++;
            char _p58[SOL_PUBKEY_BASE58_LEN] = {0};
            sol_pubkey_to_base58(&ctx->program_id, _p58, sizeof(_p58));
            uint64_t num_accts = 0;
            memcpy(&num_accts, input_buf, 8);
            sol_log_warn("BPF_FAIL_DIAG: program=%s r0=%lu num_accounts=%lu input_len=%zu stack=%u",
                         _p58, (unsigned long)return_value, (unsigned long)num_accts,
                         input_len, (unsigned)ctx->stack_height);

            /* Walk the aligned serialization format to dump each account */
            size_t off = 8; /* skip num_accounts */
            for (uint64_t ai = 0; ai < num_accts && off + 1 < input_len; ai++) {
                uint8_t marker = input_buf[off];
                if (marker == SOL_SBF_NON_DUP_MARKER) {
                    /* Non-duplicate: flags(4) + pad(4) + key(32) + owner(32) + lamports(8) + data_len(8) */
                    if (off + 4 + 4 + 32 + 32 + 8 + 8 > input_len) break;
                    uint8_t is_signer = input_buf[off + 1];
                    uint8_t is_writable = input_buf[off + 2];
                    uint8_t executable = input_buf[off + 3];
                    char key58[SOL_PUBKEY_BASE58_LEN] = {0};
                    char own58[SOL_PUBKEY_BASE58_LEN] = {0};
                    sol_pubkey_to_base58((const sol_pubkey_t*)(input_buf + off + 8), key58, sizeof(key58));
                    sol_pubkey_to_base58((const sol_pubkey_t*)(input_buf + off + 40), own58, sizeof(own58));
                    uint64_t lamports = 0, data_len = 0;
                    memcpy(&lamports, input_buf + off + 72, 8);
                    memcpy(&data_len, input_buf + off + 80, 8);
                    uint64_t rent_epoch = 0;
                    /* rent_epoch is after data + realloc_pad + align_pad */
                    size_t data_start = off + 88;
                    size_t realloc_end = data_start + (size_t)data_len + SOL_SBF_MAX_PERMITTED_DATA_INCREASE;
                    size_t align_pad = (8u - ((size_t)data_len & 7u)) & 7u;
                    size_t rent_off = realloc_end + align_pad;
                    if (rent_off + 8 <= input_len) {
                        memcpy(&rent_epoch, input_buf + rent_off, 8);
                    }
                    sol_log_warn("BPF_ACCT[%lu]: key=%s owner=%s lamports=%lu data_len=%lu signer=%d writable=%d exec=%d rent_epoch=%lu",
                                 (unsigned long)ai, key58, own58,
                                 (unsigned long)lamports, (unsigned long)data_len,
                                 is_signer, is_writable, executable,
                                 (unsigned long)rent_epoch);
                    /* Advance past: flags(4) + pad(4) + key(32) + owner(32) + lamports(8)
                       + data_len(8) + data + realloc_pad + align_pad + rent_epoch(8) */
                    off = rent_off + 8;
                } else {
                    /* Duplicate marker: 1 byte index + 7 bytes padding */
                    sol_log_warn("BPF_ACCT[%lu]: DUP of %u", (unsigned long)ai, (unsigned)marker);
                    off += 8;
                }
            }
        }
    }

    if (err == SOL_OK && return_value == 0) {
        if (prof || slow_enabled) t0 = monotonic_ns();
        sol_err_t wb_err = sbf_apply_output(ctx, input_buf, input_len, metas, meta_count);
        if (prof || slow_enabled) {
            t1 = monotonic_ns();
            if (prof) {
                prof_wb_ns = t1 - t0;
            }
            if (slow_enabled) {
                slow_wb_ns = t1 - t0;
            }
        }
        sbf_metas_release_retained(metas, meta_count);
        if (slow_enabled) {
            uint64_t slow_total_ns = monotonic_ns() - slow_total_t0;
            if (slow_total_ns >= slow_thresh_ns) {
                char prog_b58[SOL_PUBKEY_BASE58_LEN] = {0};
                sol_pubkey_to_base58(&ctx->program_id, prog_b58, sizeof(prog_b58));

                char sig_b58[SOL_SIGNATURE_BASE58_LEN] = {0};
                if (ctx->tx_signature) {
                    sol_signature_to_base58(ctx->tx_signature, sig_b58, sizeof(sig_b58));
                }

                uint64_t cu_limit = vm ? vm->compute_units : 0u;
                uint64_t meter_remaining = ctx->compute_meter ? ctx->compute_meter->remaining : 0u;

                sol_log_info("SBF_SLOW: slot=%lu total_ms=%.3f build_ms=%.3f map_ms=%.3f exec_ms=%.3f wb_ms=%.3f input_len=%zu meta=%zu cu_limit=%lu meter_remaining=%lu stack=%lu program=%s sig=%s wb_err=%d",
                             (unsigned long)sol_bank_slot(ctx->bank),
                             (double)slow_total_ns / 1e6,
                             (double)slow_build_ns / 1e6,
                             (double)slow_map_ns / 1e6,
                             (double)slow_exec_ns / 1e6,
                             (double)slow_wb_ns / 1e6,
                             slow_input_len,
                             slow_meta_count,
                             (unsigned long)cu_limit,
                             (unsigned long)meter_remaining,
                             (unsigned long)ctx->stack_height,
                             prog_b58[0] ? prog_b58 : "?",
                             sig_b58[0] ? sig_b58 : "none",
                             (int)wb_err);
            }
        }
        if (prof) {
            sbf_profile_commit(prof_build_ns, prof_map_ns, prof_exec_ns, prof_wb_ns,
                               prof_input_len, prof_meta_count);
        }
        return wb_err;
    }

    sbf_metas_release_retained(metas, meta_count);

    if (slow_enabled) {
        uint64_t slow_total_ns = monotonic_ns() - slow_total_t0;
        if (slow_total_ns >= slow_thresh_ns) {
            char prog_b58[SOL_PUBKEY_BASE58_LEN] = {0};
            sol_pubkey_to_base58(&ctx->program_id, prog_b58, sizeof(prog_b58));

            char sig_b58[SOL_SIGNATURE_BASE58_LEN] = {0};
            if (ctx->tx_signature) {
                sol_signature_to_base58(ctx->tx_signature, sig_b58, sizeof(sig_b58));
            }

            uint64_t cu_limit = vm ? vm->compute_units : 0u;
            uint64_t meter_remaining = ctx->compute_meter ? ctx->compute_meter->remaining : 0u;

            sol_log_info("SBF_SLOW: slot=%lu total_ms=%.3f build_ms=%.3f map_ms=%.3f exec_ms=%.3f wb_ms=%.3f input_len=%zu meta=%zu cu_limit=%lu meter_remaining=%lu stack=%lu program=%s sig=%s err=%d r0=%lu",
                         (unsigned long)sol_bank_slot(ctx->bank),
                         (double)slow_total_ns / 1e6,
                         (double)slow_build_ns / 1e6,
                         (double)slow_map_ns / 1e6,
                         (double)slow_exec_ns / 1e6,
                         (double)slow_wb_ns / 1e6,
                         slow_input_len,
                         slow_meta_count,
                         (unsigned long)cu_limit,
                         (unsigned long)meter_remaining,
                         (unsigned long)ctx->stack_height,
                         prog_b58[0] ? prog_b58 : "?",
                         sig_b58[0] ? sig_b58 : "none",
                         (int)err,
                         (unsigned long)return_value);
        }
    }

    if (err != SOL_OK) {
        if (prof) {
            sbf_profile_commit(prof_build_ns, prof_map_ns, prof_exec_ns, prof_wb_ns,
                               prof_input_len, prof_meta_count);
        }
        return err;
    }

    if (return_value != 0) {
        char _p58[SOL_PUBKEY_BASE58_LEN] = {0};
        sol_pubkey_to_base58(&ctx->program_id, _p58, sizeof(_p58));
        sol_log_debug("BPF program returned error: %lu (0x%lx) program=%s",
                     (unsigned long)return_value,
                     (unsigned long)return_value, _p58);
        if (prof) {
            sbf_profile_commit(prof_build_ns, prof_map_ns, prof_exec_ns, prof_wb_ns,
                               prof_input_len, prof_meta_count);
        }
        return SOL_ERR_PROGRAM_FAILED;
    }

    if (prof) {
        sbf_profile_commit(prof_build_ns, prof_map_ns, prof_exec_ns, prof_wb_ns,
                           prof_input_len, prof_meta_count);
    }
    return SOL_OK;
}

/*
 * Account state types for upgradeable loader
 */
typedef enum {
    UPGRADEABLE_LOADER_STATE_UNINITIALIZED = 0,
    UPGRADEABLE_LOADER_STATE_BUFFER = 1,
    UPGRADEABLE_LOADER_STATE_PROGRAM = 2,
    UPGRADEABLE_LOADER_STATE_PROGRAM_DATA = 3,
} upgradeable_loader_state_type_t;

/*
 * Instruction discriminators for upgradeable loader
 */
typedef enum {
    UPGRADEABLE_LOADER_INSTR_INITIALIZE_BUFFER = 0,
    UPGRADEABLE_LOADER_INSTR_WRITE = 1,
    UPGRADEABLE_LOADER_INSTR_DEPLOY_WITH_MAX_DATA_LEN = 2,
    UPGRADEABLE_LOADER_INSTR_UPGRADE = 3,
    UPGRADEABLE_LOADER_INSTR_SET_AUTHORITY = 4,
    UPGRADEABLE_LOADER_INSTR_CLOSE = 5,
    UPGRADEABLE_LOADER_INSTR_EXTEND_PROGRAM = 6,
    UPGRADEABLE_LOADER_INSTR_SET_AUTHORITY_CHECKED = 7,
} upgradeable_loader_instruction_t;

/*
 * Size constants
 */
#define UPGRADEABLE_LOADER_STATE_SIZE 4
#define UPGRADEABLE_LOADER_BUFFER_METADATA_SIZE (4 + 1 + 32)  /* type + option_tag + authority_pubkey */
#define UPGRADEABLE_LOADER_PROGRAM_SIZE (4 + 32)  /* type + programdata_address */
#define UPGRADEABLE_LOADER_PROGRAMDATA_METADATA_SIZE (4 + 8 + 1 + 32)  /* type + slot + option_tag + authority_pubkey */

/* Bincode layout offsets for UpgradeableLoaderState variants.
 * Option<Pubkey> serialized as: u8(tag) + Pubkey(32 bytes if Some). */
#define BUF_AUTH_TAG_OFF      4u   /* Buffer: option tag offset */
#define BUF_AUTH_PUBKEY_OFF   5u   /* Buffer: authority pubkey offset */
#define PD_AUTH_TAG_OFF      12u   /* ProgramData: option tag offset (after u32 type + u64 slot) */
#define PD_AUTH_PUBKEY_OFF   13u   /* ProgramData: authority pubkey offset */

/*
 * Get account from context by index
 */
static sol_err_t
get_account(sol_invoke_context_t* ctx, uint8_t index,
            const sol_pubkey_t** pubkey, sol_account_t** account) {
    if (index >= ctx->account_indices_len) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    uint8_t key_index = ctx->account_indices[index];
    if (key_index >= ctx->account_keys_len) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    *pubkey = &ctx->account_keys[key_index];
    sol_slot_t ss = 0;
    *account = sol_bank_load_account_ex(ctx->bank, *pubkey, &ss);

    /* Filter zombie accounts (0 lamports, stored before current slot) */
    if (*account && (*account)->meta.lamports == 0 &&
        ss <= sol_bank_zombie_filter_slot(ctx->bank)) {
        sol_account_destroy(*account);
        *account = NULL;
    }

    /* Agave creates a default account for any key not in the DB */
    if (!*account) {
        *account = sol_account_alloc();
        if (*account) {
            (*account)->meta.owner = SOL_SYSTEM_PROGRAM_ID;
            (*account)->meta.rent_epoch = UINT64_MAX;
        }
    }

    return SOL_OK;
}

/*
 * Check if account is a signer
 */
static bool
is_signer(sol_invoke_context_t* ctx, uint8_t index) {
    if (index >= ctx->account_indices_len) {
        return false;
    }
    uint8_t key_index = ctx->account_indices[index];
    if (ctx->is_signer != NULL && key_index < ctx->account_keys_len) {
        return ctx->is_signer[key_index];
    }
    /* Fallback: first num_signers accounts are signers */
    return key_index < ctx->num_signers;
}

/*
 * Helper to check if pubkey matches program ID
 */
static bool is_bpf_loader(const sol_pubkey_t* program_id) {
    return sol_pubkey_eq(program_id, &SOL_BPF_LOADER_V2_ID);
}

static bool is_bpf_loader_2(const sol_pubkey_t* program_id) {
    return sol_pubkey_eq(program_id, &SOL_BPF_LOADER_V3_ID);
}

static bool is_bpf_upgradeable_loader(const sol_pubkey_t* program_id) {
    return sol_pubkey_eq(program_id, &SOL_BPF_LOADER_UPGRADEABLE_ID);
}

/*
 * Process InitializeBuffer instruction
 */
static sol_err_t
process_initialize_buffer(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 1) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    const sol_pubkey_t* buffer_pubkey;
    sol_account_t* buffer;
    SOL_TRY(get_account(ctx, 0, &buffer_pubkey, &buffer));

    if (buffer == NULL) {
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Buffer must have sufficient space */
    if (buffer->meta.data_len < UPGRADEABLE_LOADER_BUFFER_METADATA_SIZE) {
        sol_account_destroy(buffer);
        return SOL_ERR_ACCOUNT_DATA_TOO_SMALL;
    }

    /* Check if already initialized */
    uint32_t account_type;
    memcpy(&account_type, buffer->data, 4);
    if (account_type != UPGRADEABLE_LOADER_STATE_UNINITIALIZED) {
        sol_account_destroy(buffer);
        return SOL_ERR_ALREADY_INITIALIZED;
    }

    /* Initialize as buffer */
    account_type = UPGRADEABLE_LOADER_STATE_BUFFER;
    memcpy(buffer->data, &account_type, 4);

    /* Set authority if provided (accounts[1]) */
    if (ctx->account_indices_len >= 2) {
        const sol_pubkey_t* authority_pubkey;
        sol_account_t* authority_account;
        sol_err_t err = get_account(ctx, 1, &authority_pubkey, &authority_account);
        if (err == SOL_OK) {
            buffer->data[BUF_AUTH_TAG_OFF] = 1;  /* Some */
            memcpy(buffer->data + BUF_AUTH_PUBKEY_OFF, authority_pubkey->bytes, 32);
            if (authority_account) sol_account_destroy(authority_account);
        } else {
            buffer->data[BUF_AUTH_TAG_OFF] = 0;  /* None */
            memset(buffer->data + BUF_AUTH_PUBKEY_OFF, 0, 32);
        }
    } else {
        buffer->data[BUF_AUTH_TAG_OFF] = 0;  /* None */
        memset(buffer->data + BUF_AUTH_PUBKEY_OFF, 0, 32);
    }

    sol_bank_store_account(ctx->bank, buffer_pubkey, buffer);
    sol_account_destroy(buffer);

    sol_log_info("BPF Loader: Initialized buffer");
    return SOL_OK;
}

/*
 * Process Write instruction
 */
static sol_err_t
process_write(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 2 || ctx->instruction_data_len < 8) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    const sol_pubkey_t* buffer_pubkey;
    sol_account_t* buffer;
    SOL_TRY(get_account(ctx, 0, &buffer_pubkey, &buffer));

    if (buffer == NULL) {
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Parse instruction: variant(4) + offset(4) + vec_len(8) + data */
    if (ctx->instruction_data_len < 16) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
    uint32_t offset;
    memcpy(&offset, ctx->instruction_data + 4, 4);  /* Skip instruction discriminator */

    uint64_t vec_len;
    memcpy(&vec_len, ctx->instruction_data + 8, 8);  /* Bincode Vec<u8> length prefix */

    const uint8_t* write_data = ctx->instruction_data + 16;
    size_t write_len = (size_t)vec_len;

    /* Verify buffer state */
    if (buffer->meta.data_len < UPGRADEABLE_LOADER_BUFFER_METADATA_SIZE) {
        sol_account_destroy(buffer);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    uint32_t account_type;
    memcpy(&account_type, buffer->data, 4);
    if (account_type != UPGRADEABLE_LOADER_STATE_BUFFER) {
        sol_account_destroy(buffer);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    /* Verify authority is signer */
    if (!is_signer(ctx, 1)) {
        sol_account_destroy(buffer);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    /* Check authority matches */
    if (buffer->data[BUF_AUTH_TAG_OFF] == 1) {  /* Some(authority) */
        const sol_pubkey_t* authority_pubkey;
        sol_account_t* authority_account;
        sol_err_t err = get_account(ctx, 1, &authority_pubkey, &authority_account);
        if (err != SOL_OK) {
            sol_account_destroy(buffer);
            return err;
        }
        if (memcmp(buffer->data + BUF_AUTH_PUBKEY_OFF, authority_pubkey->bytes, 32) != 0) {
            if (authority_account) sol_account_destroy(authority_account);
            sol_account_destroy(buffer);
            return SOL_ERR_PROGRAM_INVALID_OWNER;
        }
        if (authority_account) sol_account_destroy(authority_account);
    }

    /* Calculate write position */
    size_t write_offset = UPGRADEABLE_LOADER_BUFFER_METADATA_SIZE + offset;

    /* Check bounds */
    if (write_offset + write_len > buffer->meta.data_len) {
        sol_account_destroy(buffer);
        return SOL_ERR_ACCOUNT_DATA_TOO_SMALL;
    }

    /* Write data */
    memcpy(buffer->data + write_offset, write_data, write_len);

    sol_bank_store_account(ctx->bank, buffer_pubkey, buffer);
    sol_account_destroy(buffer);

    /* This instruction can occur many times in a single deploy/upgrade.
     * Keep it at debug to avoid log spam during replay. */
    sol_log_debug("BPF Loader: Wrote %zu bytes at offset %u", write_len, offset);
    return SOL_OK;
}

/*
 * Process DeployWithMaxDataLen instruction
 */
static sol_err_t
process_deploy(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 4 || ctx->instruction_data_len < 12) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /*
     * Expected accounts:
     * 0. Payer (signer, writable)
     * 1. Program data account (writable)
     * 2. Program account (writable)
     * 3. Buffer account
     * 4. Rent sysvar
     * 5. Clock sysvar
     * 6. System program
     * 7. Upgrade authority (signer)
     */
    const sol_pubkey_t* program_data_pubkey;
    sol_account_t* program_data;
    SOL_TRY(get_account(ctx, 1, &program_data_pubkey, &program_data));

    const sol_pubkey_t* program_pubkey;
    sol_account_t* program;
    sol_err_t err = get_account(ctx, 2, &program_pubkey, &program);
    if (err != SOL_OK) {
        if (program_data) sol_account_destroy(program_data);
        return err;
    }

    const sol_pubkey_t* buffer_pubkey;
    sol_account_t* buffer;
    err = get_account(ctx, 3, &buffer_pubkey, &buffer);
    if (err != SOL_OK) {
        if (program_data) sol_account_destroy(program_data);
        if (program) sol_account_destroy(program);
        return err;
    }

    if (program_data == NULL || program == NULL || buffer == NULL) {
        if (program_data) sol_account_destroy(program_data);
        if (program) sol_account_destroy(program);
        if (buffer) sol_account_destroy(buffer);
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Parse max_data_len from instruction */
    uint64_t max_data_len;
    memcpy(&max_data_len, ctx->instruction_data + 4, 8);  /* Skip discriminator */

    /* Verify buffer contains valid ELF */
    if (buffer->meta.data_len < UPGRADEABLE_LOADER_BUFFER_METADATA_SIZE) {
        sol_account_destroy(program_data);
        sol_account_destroy(program);
        sol_account_destroy(buffer);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    uint32_t buffer_type;
    memcpy(&buffer_type, buffer->data, 4);
    if (buffer_type != UPGRADEABLE_LOADER_STATE_BUFFER) {
        sol_account_destroy(program_data);
        sol_account_destroy(program);
        sol_account_destroy(buffer);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    /* Get ELF data from buffer */
    const uint8_t* elf_data = buffer->data + UPGRADEABLE_LOADER_BUFFER_METADATA_SIZE;
    size_t elf_len = buffer->meta.data_len - UPGRADEABLE_LOADER_BUFFER_METADATA_SIZE;

    /* Validate ELF (basic check) */
    if (elf_len < 4 || memcmp(elf_data, "\x7f""ELF", 4) != 0) {
        sol_log_error("BPF Loader: Invalid ELF magic");
        sol_account_destroy(program_data);
        sol_account_destroy(program);
        sol_account_destroy(buffer);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    /* Initialize program account */
    if (program->meta.data_len < UPGRADEABLE_LOADER_PROGRAM_SIZE) {
        sol_account_destroy(program_data);
        sol_account_destroy(program);
        sol_account_destroy(buffer);
        return SOL_ERR_ACCOUNT_DATA_TOO_SMALL;
    }

    uint32_t program_type = UPGRADEABLE_LOADER_STATE_PROGRAM;
    memcpy(program->data, &program_type, 4);

    /* Set program data address */
    memcpy(program->data + 4, program_data_pubkey->bytes, 32);

    /* Mark program as executable */
    program->meta.executable = true;

    /* Initialize program data account */
    if (program_data->meta.data_len < UPGRADEABLE_LOADER_PROGRAMDATA_METADATA_SIZE + elf_len) {
        sol_account_destroy(program_data);
        sol_account_destroy(program);
        sol_account_destroy(buffer);
        return SOL_ERR_ACCOUNT_DATA_TOO_SMALL;
    }

    uint32_t program_data_type = UPGRADEABLE_LOADER_STATE_PROGRAM_DATA;
    memcpy(program_data->data, &program_data_type, 4);

    /* Set deployment slot */
    uint64_t slot = sol_bank_slot(ctx->bank);
    memcpy(program_data->data + 4, &slot, 8);

    /* Set upgrade authority from buffer or accounts[7] if present */
    if (buffer->data[BUF_AUTH_TAG_OFF] == 1) {  /* buffer has authority */
        program_data->data[PD_AUTH_TAG_OFF] = 1;  /* Some */
        memcpy(program_data->data + PD_AUTH_PUBKEY_OFF, buffer->data + BUF_AUTH_PUBKEY_OFF, 32);
    } else if (ctx->account_indices_len >= 8) {
        const sol_pubkey_t* auth_pubkey;
        sol_account_t* auth_account;
        if (get_account(ctx, 7, &auth_pubkey, &auth_account) == SOL_OK) {
            program_data->data[PD_AUTH_TAG_OFF] = 1;  /* Some */
            memcpy(program_data->data + PD_AUTH_PUBKEY_OFF, auth_pubkey->bytes, 32);
            if (auth_account) sol_account_destroy(auth_account);
        } else {
            program_data->data[PD_AUTH_TAG_OFF] = 0;  /* None */
            memset(program_data->data + PD_AUTH_PUBKEY_OFF, 0, 32);
        }
    } else {
        program_data->data[PD_AUTH_TAG_OFF] = 0;  /* None */
        memset(program_data->data + PD_AUTH_PUBKEY_OFF, 0, 32);
    }

    /* Copy ELF data */
    memcpy(program_data->data + UPGRADEABLE_LOADER_PROGRAMDATA_METADATA_SIZE, elf_data, elf_len);

    /* Store accounts */
    sol_bank_store_account(ctx->bank, program_pubkey, program);
    sol_bank_store_account(ctx->bank, program_data_pubkey, program_data);
    bpf_prog_cache_invalidate_program(program_pubkey);
    bpf_prog_cache_invalidate_programdata(program_data_pubkey);

    sol_account_destroy(program_data);
    sol_account_destroy(program);
    sol_account_destroy(buffer);

    sol_log_info("BPF Loader: Deployed program, ELF size=%zu, max_data_len=%lu",
                 elf_len, (unsigned long)max_data_len);
    return SOL_OK;
}

/*
 * Process Upgrade instruction
 */
static sol_err_t
process_upgrade(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 7) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /*
     * Expected accounts:
     * 0. Program data account (writable)
     * 1. Program account
     * 2. Buffer account
     * 3. Spill account (writable)
     * 4. Rent sysvar
     * 5. Clock sysvar
     * 6. Upgrade authority (signer)
     */
    const sol_pubkey_t* program_data_pubkey;
    sol_account_t* program_data;
    SOL_TRY(get_account(ctx, 0, &program_data_pubkey, &program_data));

    const sol_pubkey_t* buffer_pubkey;
    sol_account_t* buffer;
    sol_err_t err = get_account(ctx, 2, &buffer_pubkey, &buffer);
    if (err != SOL_OK) {
        if (program_data) sol_account_destroy(program_data);
        return err;
    }

    if (program_data == NULL || buffer == NULL) {
        if (program_data) sol_account_destroy(program_data);
        if (buffer) sol_account_destroy(buffer);
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Verify program data state */
    if (program_data->meta.data_len < UPGRADEABLE_LOADER_PROGRAMDATA_METADATA_SIZE) {
        sol_account_destroy(program_data);
        sol_account_destroy(buffer);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    uint32_t program_data_type;
    memcpy(&program_data_type, program_data->data, 4);
    if (program_data_type != UPGRADEABLE_LOADER_STATE_PROGRAM_DATA) {
        sol_account_destroy(program_data);
        sol_account_destroy(buffer);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    /* Verify upgrade authority */
    if (program_data->data[PD_AUTH_TAG_OFF] != 1) {  /* has_upgrade_authority */
        sol_log_error("BPF Loader: Program is immutable (no upgrade authority)");
        sol_account_destroy(program_data);
        sol_account_destroy(buffer);
        return SOL_ERR_PROGRAM_INVALID_STATE;
    }

    const sol_pubkey_t* upgrade_authority_pubkey;
    sol_account_t* upgrade_authority_account;
    err = get_account(ctx, 6, &upgrade_authority_pubkey, &upgrade_authority_account);
    if (err != SOL_OK) {
        sol_account_destroy(program_data);
        sol_account_destroy(buffer);
        return err;
    }

    if (memcmp(program_data->data + PD_AUTH_PUBKEY_OFF, upgrade_authority_pubkey->bytes, 32) != 0) {
        if (upgrade_authority_account) sol_account_destroy(upgrade_authority_account);
        sol_account_destroy(program_data);
        sol_account_destroy(buffer);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    if (!is_signer(ctx, 6)) {
        if (upgrade_authority_account) sol_account_destroy(upgrade_authority_account);
        sol_account_destroy(program_data);
        sol_account_destroy(buffer);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    if (upgrade_authority_account) sol_account_destroy(upgrade_authority_account);

    /* Verify buffer */
    if (buffer->meta.data_len < UPGRADEABLE_LOADER_BUFFER_METADATA_SIZE) {
        sol_account_destroy(program_data);
        sol_account_destroy(buffer);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    uint32_t buffer_type;
    memcpy(&buffer_type, buffer->data, 4);
    if (buffer_type != UPGRADEABLE_LOADER_STATE_BUFFER) {
        sol_account_destroy(program_data);
        sol_account_destroy(buffer);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    /* Get new ELF data */
    const uint8_t* new_elf = buffer->data + UPGRADEABLE_LOADER_BUFFER_METADATA_SIZE;
    size_t new_elf_len = buffer->meta.data_len - UPGRADEABLE_LOADER_BUFFER_METADATA_SIZE;

    /* Check space */
    size_t available = program_data->meta.data_len - UPGRADEABLE_LOADER_PROGRAMDATA_METADATA_SIZE;
    if (new_elf_len > available) {
        sol_log_error("BPF Loader: New program too large (%zu > %zu)", new_elf_len, available);
        sol_account_destroy(program_data);
        sol_account_destroy(buffer);
        return SOL_ERR_ACCOUNT_DATA_TOO_SMALL;
    }

    /* Save buffer lamports before mutations */
    uint64_t buffer_lamports = buffer->meta.lamports;

    /* Update slot */
    uint64_t slot = sol_bank_slot(ctx->bank);
    memcpy(program_data->data + 4, &slot, 8);

    /* Copy new ELF */
    memcpy(program_data->data + UPGRADEABLE_LOADER_PROGRAMDATA_METADATA_SIZE, new_elf, new_elf_len);

    /* Zero remaining space */
    if (new_elf_len < available) {
        memset(program_data->data + UPGRADEABLE_LOADER_PROGRAMDATA_METADATA_SIZE + new_elf_len,
               0, available - new_elf_len);
    }

    /* Compute rent-exempt minimum for programdata */
    uint64_t programdata_balance_required = sol_bank_rent_exempt_minimum(
        ctx->bank, program_data->meta.data_len);
    if (programdata_balance_required == 0) programdata_balance_required = 1;

    /* Transfer excess lamports to spill account (index 3) */
    const sol_pubkey_t* spill_pubkey;
    sol_account_t* spill;
    err = get_account(ctx, 3, &spill_pubkey, &spill);
    if (err != SOL_OK) {
        sol_account_destroy(program_data);
        sol_account_destroy(buffer);
        return err;
    }
    if (spill == NULL) {
        sol_account_destroy(program_data);
        sol_account_destroy(buffer);
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    spill->meta.lamports += program_data->meta.lamports + buffer_lamports - programdata_balance_required;
    sol_bank_store_account(ctx->bank, spill_pubkey, spill);
    sol_account_destroy(spill);

    /* Close buffer: zero lamports, truncate data to metadata-only (37 bytes) */
    buffer->meta.lamports = 0;
    if (buffer->meta.data_len > UPGRADEABLE_LOADER_BUFFER_METADATA_SIZE) {
        sol_account_resize(buffer, UPGRADEABLE_LOADER_BUFFER_METADATA_SIZE);
    }
    sol_bank_store_account(ctx->bank, buffer_pubkey, buffer);
    sol_account_destroy(buffer);

    /* Set programdata lamports to rent-exempt minimum */
    program_data->meta.lamports = programdata_balance_required;
    sol_bank_store_account(ctx->bank, program_data_pubkey, program_data);
    {
        const sol_pubkey_t* program_pubkey = NULL;
        if (ctx->account_indices_len >= 2) {
            uint8_t key_index = ctx->account_indices[1];
            if (key_index < ctx->account_keys_len) {
                program_pubkey = &ctx->account_keys[key_index];
            }
        }
        if (program_pubkey) {
            bpf_prog_cache_invalidate_program(program_pubkey);
        }
        bpf_prog_cache_invalidate_programdata(program_data_pubkey);
    }
    sol_account_destroy(program_data);

    sol_log_info("BPF Loader: Upgraded program, new ELF size=%zu", new_elf_len);
    return SOL_OK;
}

/*
 * Process SetAuthority instruction
 */
static sol_err_t
process_set_authority(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 2) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    const sol_pubkey_t* account_pubkey;
    sol_account_t* account;
    SOL_TRY(get_account(ctx, 0, &account_pubkey, &account));

    if (account == NULL) {
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    if (account->meta.data_len < 4) {
        sol_account_destroy(account);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    uint32_t account_type;
    memcpy(&account_type, account->data, 4);

    size_t auth_tag_off;
    size_t auth_pubkey_off;
    if (account_type == UPGRADEABLE_LOADER_STATE_BUFFER) {
        auth_tag_off = BUF_AUTH_TAG_OFF;
        auth_pubkey_off = BUF_AUTH_PUBKEY_OFF;
    } else if (account_type == UPGRADEABLE_LOADER_STATE_PROGRAM_DATA) {
        auth_tag_off = PD_AUTH_TAG_OFF;
        auth_pubkey_off = PD_AUTH_PUBKEY_OFF;
    } else {
        sol_account_destroy(account);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    /* Verify current authority matches and is signer */
    if (account->data[auth_tag_off] != 1) {
        sol_log_error("BPF Loader: Account has no authority");
        sol_account_destroy(account);
        return SOL_ERR_PROGRAM_INVALID_STATE;
    }

    const sol_pubkey_t* current_authority_pubkey;
    sol_account_t* current_authority_account;
    sol_err_t err = get_account(ctx, 1, &current_authority_pubkey, &current_authority_account);
    if (err != SOL_OK) {
        sol_account_destroy(account);
        return err;
    }

    if (memcmp(account->data + auth_pubkey_off, current_authority_pubkey->bytes, 32) != 0) {
        if (current_authority_account) sol_account_destroy(current_authority_account);
        sol_account_destroy(account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    if (!is_signer(ctx, 1)) {
        if (current_authority_account) sol_account_destroy(current_authority_account);
        sol_account_destroy(account);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    if (current_authority_account) sol_account_destroy(current_authority_account);

    /* Set new authority */
    if (ctx->account_indices_len >= 3) {
        const sol_pubkey_t* new_authority_pubkey;
        sol_account_t* new_authority_account;
        err = get_account(ctx, 2, &new_authority_pubkey, &new_authority_account);
        if (err == SOL_OK) {
            account->data[auth_tag_off] = 1;  /* Some */
            memcpy(account->data + auth_pubkey_off, new_authority_pubkey->bytes, 32);
            if (new_authority_account) sol_account_destroy(new_authority_account);
            sol_log_info("BPF Loader: Authority changed");
        } else {
            sol_account_destroy(account);
            return err;
        }
    } else {
        account->data[auth_tag_off] = 0;  /* None */
        memset(account->data + auth_pubkey_off, 0, 32);
        sol_log_info("BPF Loader: Authority cleared (now immutable)");
    }

    sol_bank_store_account(ctx->bank, account_pubkey, account);
    sol_account_destroy(account);

    return SOL_OK;
}

/*
 * Process Close instruction
 */
static sol_err_t
process_close(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 2) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    const sol_pubkey_t* close_account_pubkey;
    sol_account_t* close_account;
    SOL_TRY(get_account(ctx, 0, &close_account_pubkey, &close_account));

    const sol_pubkey_t* recipient_pubkey;
    sol_account_t* recipient;
    sol_err_t err = get_account(ctx, 1, &recipient_pubkey, &recipient);
    if (err != SOL_OK) {
        if (close_account) sol_account_destroy(close_account);
        return err;
    }

    if (close_account == NULL || recipient == NULL) {
        if (close_account) sol_account_destroy(close_account);
        if (recipient) sol_account_destroy(recipient);
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    if (close_account->meta.data_len < 4) {
        sol_account_destroy(close_account);
        sol_account_destroy(recipient);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    uint32_t account_type;
    memcpy(&account_type, close_account->data, 4);

    /* Only buffers and program data can be closed */
    if (account_type != UPGRADEABLE_LOADER_STATE_BUFFER &&
        account_type != UPGRADEABLE_LOADER_STATE_PROGRAM_DATA) {
        sol_log_error("BPF Loader: Cannot close this account type");
        sol_account_destroy(close_account);
        sol_account_destroy(recipient);
        return SOL_ERR_PROGRAM_INVALID_STATE;
    }

    /* Verify authority if present */
    size_t close_tag_off = (account_type == UPGRADEABLE_LOADER_STATE_BUFFER)
        ? BUF_AUTH_TAG_OFF : PD_AUTH_TAG_OFF;
    size_t close_pubkey_off = (account_type == UPGRADEABLE_LOADER_STATE_BUFFER)
        ? BUF_AUTH_PUBKEY_OFF : PD_AUTH_PUBKEY_OFF;

    if (close_account->data[close_tag_off] == 1) {
        if (ctx->account_indices_len < 3 || !is_signer(ctx, 2)) {
            sol_account_destroy(close_account);
            sol_account_destroy(recipient);
            return SOL_ERR_MISSING_SIGNATURE;
        }

        const sol_pubkey_t* authority_pubkey;
        sol_account_t* authority_account;
        err = get_account(ctx, 2, &authority_pubkey, &authority_account);
        if (err != SOL_OK) {
            sol_account_destroy(close_account);
            sol_account_destroy(recipient);
            return err;
        }

        if (memcmp(close_account->data + close_pubkey_off, authority_pubkey->bytes, 32) != 0) {
            if (authority_account) sol_account_destroy(authority_account);
            sol_account_destroy(close_account);
            sol_account_destroy(recipient);
            return SOL_ERR_PROGRAM_INVALID_OWNER;
        }

        if (authority_account) sol_account_destroy(authority_account);
    }

    /* Self-close: In Agave, simultaneous mutable borrows of the same account
       would fail (BorrowError). Reject the operation. */
    if (sol_pubkey_eq(close_account_pubkey, recipient_pubkey)) {
        sol_account_destroy(close_account);
        sol_account_destroy(recipient);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Transfer lamports to recipient */
    recipient->meta.lamports += close_account->meta.lamports;
    close_account->meta.lamports = 0;

    /* Clear account data */
    memset(close_account->data, 0, close_account->meta.data_len);

    sol_bank_store_account(ctx->bank, close_account_pubkey, close_account);
    sol_bank_store_account(ctx->bank, recipient_pubkey, recipient);
    if (account_type == UPGRADEABLE_LOADER_STATE_PROGRAM_DATA) {
        bpf_prog_cache_invalidate_programdata(close_account_pubkey);
    }

    sol_account_destroy(close_account);
    sol_account_destroy(recipient);

    sol_log_info("BPF Loader: Closed account");
    return SOL_OK;
}

/*
 * Process ExtendProgram instruction
 */
static sol_err_t
process_extend_program(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 2 || ctx->instruction_data_len < 8) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    const sol_pubkey_t* program_data_pubkey;
    sol_account_t* program_data;
    SOL_TRY(get_account(ctx, 0, &program_data_pubkey, &program_data));

    if (program_data == NULL) {
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Parse additional bytes from instruction */
    uint32_t additional_bytes;
    memcpy(&additional_bytes, ctx->instruction_data + 4, 4);

    if (additional_bytes == 0) {
        sol_account_destroy(program_data);
        return SOL_OK;
    }

    /* Verify program data state */
    if (program_data->meta.data_len < UPGRADEABLE_LOADER_PROGRAMDATA_METADATA_SIZE) {
        sol_account_destroy(program_data);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    uint32_t program_data_type;
    memcpy(&program_data_type, program_data->data, 4);
    if (program_data_type != UPGRADEABLE_LOADER_STATE_PROGRAM_DATA) {
        sol_account_destroy(program_data);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    /* Verify upgrade authority exists. */
    if (program_data->data[PD_AUTH_TAG_OFF] != 1) {  /* has_upgrade_authority */
        sol_account_destroy(program_data);
        return SOL_ERR_PROGRAM_INVALID_STATE;
    }

    sol_pubkey_t upgrade_authority = {0};
    memcpy(upgrade_authority.bytes, program_data->data + PD_AUTH_PUBKEY_OFF, 32);

    /* Require a signer matching the program's upgrade authority. */
    bool have_authority_sig = false;
    for (uint8_t i = 0; i < ctx->account_indices_len; i++) {
        if (!is_signer(ctx, i)) continue;
        uint8_t key_index = ctx->account_indices[i];
        if (key_index >= ctx->account_keys_len) continue;
        const sol_pubkey_t* signer_pubkey = &ctx->account_keys[key_index];
        if (memcmp(signer_pubkey->bytes, upgrade_authority.bytes, 32) == 0) {
            have_authority_sig = true;
            break;
        }
    }
    if (!have_authority_sig) {
        sol_account_destroy(program_data);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    /* Grow the account data. Solana's upgradeable loader enforces rent-exempt
     * funding for the new size. Best-effort: use the first non-program-data
     * signer account as payer (often the authority itself). */
    size_t old_len = program_data->meta.data_len;
    size_t new_len = old_len + (size_t)additional_bytes;
    if (new_len < old_len || new_len > SOL_ACCOUNT_MAX_DATA_SIZE) {
        sol_account_destroy(program_data);
        return SOL_ERR_ACCOUNT_DATA_TOO_LARGE;
    }

    sol_err_t resize_err = sol_account_resize(program_data, new_len);
    if (resize_err != SOL_OK) {
        sol_account_destroy(program_data);
        return resize_err;
    }

    uint64_t required_min_balance =
        sol_bank_rent_exempt_minimum(ctx->bank, program_data->meta.data_len);
    if (required_min_balance > program_data->meta.lamports) {
        uint64_t needed = required_min_balance - program_data->meta.lamports;

        const sol_pubkey_t* payer_pubkey = NULL;
        sol_account_t* payer = NULL;
        for (uint8_t i = 1; i < ctx->account_indices_len; i++) {
            if (!is_signer(ctx, i)) continue;
            sol_err_t err = get_account(ctx, i, &payer_pubkey, &payer);
            if (err != SOL_OK) {
                sol_account_destroy(program_data);
                return err;
            }
            if (payer) break;
        }

        if (!payer) {
            sol_account_destroy(program_data);
            return SOL_ERR_ACCOUNT_NOT_FOUND;
        }

        if (payer->meta.lamports < needed) {
            sol_account_destroy(payer);
            sol_account_destroy(program_data);
            return SOL_ERR_PROGRAM_INSUFFICIENT_FUNDS;
        }

        /* Self-funding: no-op if payer == program_data */
        if (sol_pubkey_eq(payer_pubkey, program_data_pubkey)) {
            sol_account_destroy(payer);
        } else {
            payer->meta.lamports -= needed;
            program_data->meta.lamports += needed;

            sol_bank_store_account(ctx->bank, payer_pubkey, payer);
            sol_account_destroy(payer);
        }
    }

    /* Update slot in ProgramData header to current slot (matches Agave) */
    uint64_t slot = sol_bank_slot(ctx->bank);
    memcpy(program_data->data + 4, &slot, 8);

    sol_log_info("BPF Loader: ExtendProgram requested %u additional bytes", additional_bytes);

    sol_bank_store_account(ctx->bank, program_data_pubkey, program_data);
    bpf_prog_cache_invalidate_programdata(program_data_pubkey);
    sol_account_destroy(program_data);
    return SOL_OK;
}

static sol_err_t
bpf_loader_load_program_into_handle(sol_bank_t* bank,
                                    const sol_pubkey_t* program_id,
                                    sol_bpf_prog_handle_t* out_handle) {
    if (!bank || !program_id || !out_handle) {
        return SOL_ERR_INVAL;
    }

    sol_err_t ret = SOL_OK;
    sol_account_t* program_account = NULL;
    sol_account_t* program_data = NULL;
    sol_bpf_program_t* loaded = NULL;

    const uint8_t* elf_data = NULL;
    size_t elf_len = 0;
    bool has_programdata = false;
    sol_pubkey_t program_data_address = {0};

    program_account = sol_bank_load_account_view(bank, program_id);
    if (!program_account || !program_account->meta.executable) {
        ret = SOL_ERR_PROGRAM_INVALID_ACCOUNT;
        goto done;
    }

    bool loader_deprecated = is_bpf_loader_2(&program_account->meta.owner);

    if (is_bpf_loader(&program_account->meta.owner) || loader_deprecated) {
        elf_data = program_account->data;
        elf_len = program_account->meta.data_len;
    } else if (is_bpf_upgradeable_loader(&program_account->meta.owner)) {
        if (program_account->meta.data_len < UPGRADEABLE_LOADER_PROGRAM_SIZE) {
            ret = SOL_ERR_PROGRAM_INVALID_ACCOUNT;
            goto done;
        }

        uint32_t program_type = 0;
        memcpy(&program_type, program_account->data, 4);
        if (program_type != UPGRADEABLE_LOADER_STATE_PROGRAM) {
            ret = SOL_ERR_PROGRAM_INVALID_ACCOUNT;
            goto done;
        }

        has_programdata = true;
        memcpy(program_data_address.bytes, program_account->data + 4, 32);
        program_data = sol_bank_load_account_view(bank, &program_data_address);
        if (!program_data) {
            ret = SOL_ERR_ACCOUNT_NOT_FOUND;
            goto done;
        }

        if (program_data->meta.data_len < UPGRADEABLE_LOADER_PROGRAMDATA_METADATA_SIZE) {
            ret = SOL_ERR_PROGRAM_INVALID_ACCOUNT;
            goto done;
        }

        uint32_t program_data_type = 0;
        memcpy(&program_data_type, program_data->data, 4);
        if (program_data_type != UPGRADEABLE_LOADER_STATE_PROGRAM_DATA) {
            ret = SOL_ERR_PROGRAM_INVALID_ACCOUNT;
            goto done;
        }

        elf_data = program_data->data + UPGRADEABLE_LOADER_PROGRAMDATA_METADATA_SIZE;
        elf_len = program_data->meta.data_len - UPGRADEABLE_LOADER_PROGRAMDATA_METADATA_SIZE;
        loader_deprecated = false;
    } else {
        ret = SOL_ERR_PROGRAM_INVALID_OWNER;
        goto done;
    }

    loaded = sol_bpf_program_new();
    if (!loaded) {
        ret = SOL_ERR_NOMEM;
        goto done;
    }

    sol_err_t load_err = sol_bpf_elf_load(loaded, elf_data, elf_len);
    if (load_err != SOL_OK) {
        ret = load_err;
        goto done;
    }

    out_handle->prog = loaded;
    loaded = NULL;
    out_handle->has_programdata = has_programdata;
    out_handle->programdata = program_data_address;
    out_handle->loader_deprecated = loader_deprecated;
    out_handle->ro_section_len = out_handle->prog ? out_handle->prog->ro_section_len : 0;

done:
    if (loaded) {
        sol_bpf_program_destroy(loaded);
    }
    if (program_data) {
        sol_account_destroy(program_data);
    }
    if (program_account) {
        sol_account_destroy(program_account);
    }
    return ret;
}

sol_err_t
sol_bpf_loader_prewarm_program_budget(sol_bank_t* bank,
                                      const sol_pubkey_t* program_id,
                                      uint64_t wait_budget_ns) {
    if (!bank || !program_id) {
        return SOL_ERR_INVAL;
    }

    bpf_prog_cache_init();
    if (!g_bpf_prog_cache) {
        return SOL_OK;
    }
    const bool bounded_wait = (wait_budget_ns != UINT64_MAX);

    pthread_rwlock_rdlock(&g_bpf_prog_cache_lock);
    sol_bpf_prog_handle_t* cached = bpf_prog_cache_get_locked(program_id);
    pthread_rwlock_unlock(&g_bpf_prog_cache_lock);
    if (cached) {
        uint64_t wait_t0 = monotonic_ns();
        bool wait_timed_out = false;
        sol_err_t werr = bounded_wait
            ? bpf_prog_handle_wait_ready_budget(cached, wait_budget_ns, &wait_timed_out)
            : bpf_prog_handle_wait_ready(cached);
        bpf_log_slow_stage("prewarm_wait_cached",
                           program_id,
                           sol_bank_slot(bank),
                           monotonic_ns() - wait_t0,
                           werr,
                           cached->prog ? cached->ro_section_len : 0u);
        bpf_prog_handle_release(cached);
        return werr;
    }

    sol_bpf_prog_handle_t* inflight = NULL;
    bool inflight_loader = false;

    sol_bpf_prog_handle_t* placeholder = bpf_prog_handle_new(BPF_PROG_STATE_LOADING);
    if (!placeholder) {
        return SOL_ERR_NOMEM;
    }

    pthread_rwlock_wrlock(&g_bpf_prog_cache_lock);
    inflight = bpf_prog_cache_get_locked(program_id);
    if (!inflight) {
        inflight = bpf_prog_cache_insert_locked(program_id, placeholder);
        if (!inflight) {
            pthread_rwlock_unlock(&g_bpf_prog_cache_lock);
            bpf_prog_handle_release(placeholder);
            return SOL_ERR_NOMEM;
        } else if (inflight == placeholder) {
            inflight_loader = true;
        } else {
            bpf_prog_handle_release(placeholder);
            placeholder = NULL;
        }
    } else {
        bpf_prog_handle_release(placeholder);
        placeholder = NULL;
    }
    pthread_rwlock_unlock(&g_bpf_prog_cache_lock);

    if (!inflight) {
        return SOL_ERR_NOMEM;
    }

    if (!inflight_loader) {
        uint64_t wait_t0 = monotonic_ns();
        bool wait_timed_out = false;
        sol_err_t werr = bounded_wait
            ? bpf_prog_handle_wait_ready_budget(inflight, wait_budget_ns, &wait_timed_out)
            : bpf_prog_handle_wait_ready(inflight);
        bpf_log_slow_stage("prewarm_wait_inflight",
                           program_id,
                           sol_bank_slot(bank),
                           monotonic_ns() - wait_t0,
                           werr,
                           inflight->prog ? inflight->ro_section_len : 0u);
        bpf_prog_handle_release(inflight);
        return werr;
    }

    uint64_t load_t0 = monotonic_ns();
    sol_err_t ret = bpf_loader_load_program_into_handle(bank, program_id, inflight);
    bpf_log_slow_stage("prewarm_load_parse",
                       program_id,
                       sol_bank_slot(bank),
                       monotonic_ns() - load_t0,
                       ret,
                       inflight->prog ? inflight->ro_section_len : 0u);
    if (ret == SOL_OK) {
        pthread_rwlock_wrlock(&g_bpf_prog_cache_lock);
        if (g_bpf_prog_cache) {
            sol_bpf_prog_handle_t** slot =
                (sol_bpf_prog_handle_t**)sol_pubkey_map_get(g_bpf_prog_cache, program_id);
            if (slot && *slot == inflight) {
                if (inflight->ro_section_len > g_bpf_prog_cache_max_bytes) {
                    size_t saved = inflight->ro_section_len;
                    inflight->ro_section_len = 0;
                    bpf_prog_cache_remove_locked(program_id);
                    inflight->ro_section_len = saved;
                } else {
                    bpf_prog_cache_evict_if_needed_locked(inflight->ro_section_len);
                    g_bpf_prog_cache_total_bytes += inflight->ro_section_len;
                }
            }
        }
        pthread_rwlock_unlock(&g_bpf_prog_cache_lock);

        pthread_mutex_lock(&inflight->load_mu);
        inflight->load_err = SOL_OK;
        __atomic_store_n(&inflight->load_state, BPF_PROG_STATE_READY, __ATOMIC_RELEASE);
        pthread_cond_broadcast(&inflight->load_cv);
        pthread_mutex_unlock(&inflight->load_mu);

        bpf_prog_handle_release(inflight);
        return SOL_OK;
    }

    pthread_mutex_lock(&inflight->load_mu);
    inflight->load_err = ret;
    __atomic_store_n(&inflight->load_state, BPF_PROG_STATE_FAILED, __ATOMIC_RELEASE);
    pthread_cond_broadcast(&inflight->load_cv);
    pthread_mutex_unlock(&inflight->load_mu);

    pthread_rwlock_wrlock(&g_bpf_prog_cache_lock);
    if (g_bpf_prog_cache) {
        sol_bpf_prog_handle_t** slot =
            (sol_bpf_prog_handle_t**)sol_pubkey_map_get(g_bpf_prog_cache, program_id);
        if (slot && *slot == inflight) {
            bpf_prog_cache_remove_locked(program_id);
        }
    }
    pthread_rwlock_unlock(&g_bpf_prog_cache_lock);

    bpf_prog_handle_release(inflight);
    return ret;
}

sol_err_t
sol_bpf_loader_prewarm_program(sol_bank_t* bank, const sol_pubkey_t* program_id) {
    return sol_bpf_loader_prewarm_program_budget(bank, program_id, UINT64_MAX);
}

/*
 * Execute a deployed BPF program
 */
sol_err_t sol_bpf_loader_execute_program(
    sol_invoke_context_t* ctx,
    const sol_pubkey_t* program_id
) {
    static unsigned _bpf_exec_trace = 64;
    if (_bpf_exec_trace > 0) {
        _bpf_exec_trace--;
        char p58[SOL_PUBKEY_BASE58_LEN] = {0};
        sol_pubkey_to_base58(program_id, p58, sizeof(p58));
        sol_log_debug("bpf_exec_entry: program=%s", p58);
    }
    if (ctx != NULL) {
        ctx->compute_units_accounted = 0;
    }

    bpf_prog_cache_init();
    sol_bpf_prog_handle_t* inflight = NULL;
    bool inflight_loader = false;
    const uint64_t load_diag_thresh_ns = bpf_load_slow_threshold_ns();
    const uint64_t wait_budget_ns = bpf_load_wait_budget_ns();
    bool force_uncached_load = false;

    /* Fast path: execute from cache (or wait for an in-flight load). */
    if (g_bpf_prog_cache) {
        pthread_rwlock_rdlock(&g_bpf_prog_cache_lock);
        sol_bpf_prog_handle_t* cached = bpf_prog_cache_get_locked(program_id);
        pthread_rwlock_unlock(&g_bpf_prog_cache_lock);
        if (cached) {
            uint64_t wait_t0 = monotonic_ns();
            bool wait_timed_out = false;
            sol_err_t werr =
                bpf_prog_handle_wait_ready_budget(cached, wait_budget_ns, &wait_timed_out);
            bpf_log_slow_stage("exec_wait_cached",
                               program_id,
                               sol_bank_slot(ctx->bank),
                               monotonic_ns() - wait_t0,
                               werr,
                               cached->prog ? cached->ro_section_len : 0u);
            if (werr == SOL_OK) {
                sol_err_t err = execute_sbf_program(ctx, cached->prog, cached->loader_deprecated);
                bpf_prog_handle_release(cached);
                return err;
            }
            bpf_prog_handle_release(cached);
            if (wait_timed_out) {
                force_uncached_load = true;
            } else {
                return werr;
            }
        }
    }

    /* Cache miss: install an in-flight placeholder so only one thread performs
     * AccountsDB loads + ELF parsing for this program. */
    if (g_bpf_prog_cache && !force_uncached_load) {
        sol_bpf_prog_handle_t* placeholder = bpf_prog_handle_new(BPF_PROG_STATE_LOADING);
        if (placeholder) {
            pthread_rwlock_wrlock(&g_bpf_prog_cache_lock);
            inflight = bpf_prog_cache_get_locked(program_id);
            if (!inflight) {
                inflight = bpf_prog_cache_insert_locked(program_id, placeholder);
                if (!inflight) {
                    bpf_prog_handle_release(placeholder);
                    placeholder = NULL;
                } else if (inflight == placeholder) {
                    inflight_loader = true;
                } else {
                    bpf_prog_handle_release(placeholder);
                    placeholder = NULL;
                }
            } else {
                bpf_prog_handle_release(placeholder);
                placeholder = NULL;
            }
            pthread_rwlock_unlock(&g_bpf_prog_cache_lock);
        }

        if (inflight && !inflight_loader) {
            uint64_t wait_t0 = monotonic_ns();
            bool wait_timed_out = false;
            sol_err_t werr =
                bpf_prog_handle_wait_ready_budget(inflight, wait_budget_ns, &wait_timed_out);
            bpf_log_slow_stage("exec_wait_inflight",
                               program_id,
                               sol_bank_slot(ctx->bank),
                               monotonic_ns() - wait_t0,
                               werr,
                               inflight->prog ? inflight->ro_section_len : 0u);
            if (werr == SOL_OK) {
                sol_err_t err = execute_sbf_program(ctx, inflight->prog, inflight->loader_deprecated);
                bpf_prog_handle_release(inflight);
                return err;
            }
            bpf_prog_handle_release(inflight);
            if (wait_timed_out) {
                force_uncached_load = true;
                inflight = NULL;
            } else {
                return werr;
            }
        }
    }

    sol_err_t ret = SOL_OK;

    sol_account_t* program_account = NULL;
    sol_account_t* program_data = NULL;
    sol_bpf_program_t* loaded = NULL;

    const uint8_t* elf_data = NULL;
    size_t elf_len = 0;
    bool has_programdata = false;
    sol_pubkey_t program_data_address = {0};
    uint64_t load_t0 = load_diag_thresh_ns ? monotonic_ns() : 0u;

    /* Cache miss (or inflight loader): load program account, fetch ELF, parse once. */
    program_account = sol_bank_load_account_view(ctx->bank, program_id);

    if (program_account == NULL || !program_account->meta.executable) {
        if (sbf_vm_diag_enabled() || sol_log_get_level() <= SOL_LOG_DEBUG) {
            char p58[SOL_PUBKEY_BASE58_LEN] = {0};
            sol_pubkey_to_base58(program_id, p58, sizeof(p58));
            if (sbf_vm_diag_enabled()) {
                sol_log_error("bpf_exec_diag: check1 program=%s acct=%s exec=%d",
                              p58,
                              program_account ? "found" : "NULL",
                              program_account ? (int)program_account->meta.executable : -1);
            } else {
                sol_log_debug("bpf_exec_diag: check1 program=%s acct=%s exec=%d",
                              p58,
                              program_account ? "found" : "NULL",
                              program_account ? (int)program_account->meta.executable : -1);
            }
        }
        ret = SOL_ERR_PROGRAM_INVALID_ACCOUNT;
        goto fail;
    }

    /* Detect BPF Loader v1 (deprecated) for different serialization/VM config.
     * is_bpf_loader_2() checks SOL_BPF_LOADER_V3_ID which is BPFLoader1111... */
    bool loader_deprecated = is_bpf_loader_2(&program_account->meta.owner);

    /* Check program owner to determine loader type */
    if (is_bpf_loader(&program_account->meta.owner) || loader_deprecated) {
        /* For v1/v2, ELF is stored directly in program account */
        elf_data = program_account->data;
        elf_len = program_account->meta.data_len;
    } else if (is_bpf_upgradeable_loader(&program_account->meta.owner)) {
        /* For upgradeable, get program data account */
        if (program_account->meta.data_len < UPGRADEABLE_LOADER_PROGRAM_SIZE) {
            if (sbf_vm_diag_enabled() || sol_log_get_level() <= SOL_LOG_DEBUG) {
                char p58[SOL_PUBKEY_BASE58_LEN] = {0};
                sol_pubkey_to_base58(program_id, p58, sizeof(p58));
                if (sbf_vm_diag_enabled()) {
                    sol_log_error("bpf_exec_diag: check2 program=%s data_len=%zu need=%d",
                                  p58, program_account->meta.data_len, UPGRADEABLE_LOADER_PROGRAM_SIZE);
                } else {
                    sol_log_debug("bpf_exec_diag: check2 program=%s data_len=%zu need=%d",
                                  p58, program_account->meta.data_len, UPGRADEABLE_LOADER_PROGRAM_SIZE);
                }
            }
            ret = SOL_ERR_PROGRAM_INVALID_ACCOUNT;
            goto fail;
        }

        uint32_t program_type;
        memcpy(&program_type, program_account->data, 4);
        if (program_type != UPGRADEABLE_LOADER_STATE_PROGRAM) {
            if (sbf_vm_diag_enabled() || sol_log_get_level() <= SOL_LOG_DEBUG) {
                char p58[SOL_PUBKEY_BASE58_LEN] = {0};
                sol_pubkey_to_base58(program_id, p58, sizeof(p58));
                if (sbf_vm_diag_enabled()) {
                    sol_log_error("bpf_exec_diag: check3 program=%s type=%u expected=%u",
                                  p58, program_type, UPGRADEABLE_LOADER_STATE_PROGRAM);
                } else {
                    sol_log_debug("bpf_exec_diag: check3 program=%s type=%u expected=%u",
                                  p58, program_type, UPGRADEABLE_LOADER_STATE_PROGRAM);
                }
            }
            ret = SOL_ERR_PROGRAM_INVALID_ACCOUNT;
            goto fail;
        }

        /* Get program data address */
        has_programdata = true;
        memcpy(program_data_address.bytes, program_account->data + 4, 32);

        /* Load program data account */
        program_data = sol_bank_load_account_view(ctx->bank, &program_data_address);
        if (program_data == NULL) {
            if (sbf_vm_diag_enabled() || sol_log_get_level() <= SOL_LOG_DEBUG) {
                char p58[SOL_PUBKEY_BASE58_LEN] = {0};
                char pd58[SOL_PUBKEY_BASE58_LEN] = {0};
                sol_pubkey_to_base58(program_id, p58, sizeof(p58));
                sol_pubkey_to_base58(&program_data_address, pd58, sizeof(pd58));
                if (sbf_vm_diag_enabled()) {
                    sol_log_error("bpf_exec_diag: check4 program=%s program_data=%s NOT_FOUND",
                                  p58, pd58);
                } else {
                    sol_log_debug("bpf_exec_diag: check4 program=%s program_data=%s NOT_FOUND",
                                  p58, pd58);
                }
            }
            ret = SOL_ERR_ACCOUNT_NOT_FOUND;
            goto fail;
        }

        /* Verify program data state */
        if (program_data->meta.data_len < UPGRADEABLE_LOADER_PROGRAMDATA_METADATA_SIZE) {
            if (sbf_vm_diag_enabled() || sol_log_get_level() <= SOL_LOG_DEBUG) {
                char p58[SOL_PUBKEY_BASE58_LEN] = {0};
                sol_pubkey_to_base58(program_id, p58, sizeof(p58));
                if (sbf_vm_diag_enabled()) {
                    sol_log_error("bpf_exec_diag: check5 program=%s pd_data_len=%zu need=%d",
                                  p58, program_data->meta.data_len,
                                  UPGRADEABLE_LOADER_PROGRAMDATA_METADATA_SIZE);
                } else {
                    sol_log_debug("bpf_exec_diag: check5 program=%s pd_data_len=%zu need=%d",
                                  p58, program_data->meta.data_len,
                                  UPGRADEABLE_LOADER_PROGRAMDATA_METADATA_SIZE);
                }
            }
            ret = SOL_ERR_PROGRAM_INVALID_ACCOUNT;
            goto fail;
        }

        uint32_t program_data_type;
        memcpy(&program_data_type, program_data->data, 4);
        if (program_data_type != UPGRADEABLE_LOADER_STATE_PROGRAM_DATA) {
            if (sbf_vm_diag_enabled() || sol_log_get_level() <= SOL_LOG_DEBUG) {
                char p58[SOL_PUBKEY_BASE58_LEN] = {0};
                sol_pubkey_to_base58(program_id, p58, sizeof(p58));
                if (sbf_vm_diag_enabled()) {
                    sol_log_error("bpf_exec_diag: check6 program=%s pd_type=%u expected=%u",
                                  p58, program_data_type, UPGRADEABLE_LOADER_STATE_PROGRAM_DATA);
                } else {
                    sol_log_debug("bpf_exec_diag: check6 program=%s pd_type=%u expected=%u",
                                  p58, program_data_type, UPGRADEABLE_LOADER_STATE_PROGRAM_DATA);
                }
            }
            ret = SOL_ERR_PROGRAM_INVALID_ACCOUNT;
            goto fail;
        }

        elf_data = program_data->data + UPGRADEABLE_LOADER_PROGRAMDATA_METADATA_SIZE;
        elf_len = program_data->meta.data_len - UPGRADEABLE_LOADER_PROGRAMDATA_METADATA_SIZE;
        loader_deprecated = false;
    } else {
        sol_log_error("BPF Loader: Unknown program owner");
        ret = SOL_ERR_PROGRAM_INVALID_OWNER;
        goto fail;
    }

    loaded = sol_bpf_program_new();
    if (!loaded) {
        ret = SOL_ERR_NOMEM;
        goto fail;
    }

    sol_err_t load_err = sol_bpf_elf_load(loaded, elf_data, elf_len);
    if (load_err != SOL_OK) {
        bpf_log_slow_stage(inflight_loader ? "exec_load_parse_owner" : "exec_load_parse_fallback",
                           program_id,
                           sol_bank_slot(ctx->bank),
                           load_t0 ? (monotonic_ns() - load_t0) : 0u,
                           load_err,
                           0u);
        if (sbf_vm_diag_enabled() || sol_log_get_level() <= SOL_LOG_DEBUG) {
            char p58[SOL_PUBKEY_BASE58_LEN] = {0};
            sol_pubkey_to_base58(program_id, p58, sizeof(p58));
            if (sbf_vm_diag_enabled()) {
                sol_log_error("bpf_exec_diag: elf_load_fail program=%s elf_len=%zu err=%d",
                              p58, elf_len, load_err);
            } else {
                sol_log_debug("bpf_exec_diag: elf_load_fail program=%s elf_len=%zu err=%d",
                              p58, elf_len, load_err);
            }
        }
        ret = load_err;
        goto fail;
    }
    bpf_log_slow_stage(inflight_loader ? "exec_load_parse_owner" : "exec_load_parse_fallback",
                       program_id,
                       sol_bank_slot(ctx->bank),
                       load_t0 ? (monotonic_ns() - load_t0) : 0u,
                       SOL_OK,
                       loaded ? loaded->ro_section_len : 0u);

    if (program_data) {
        sol_account_destroy(program_data);
        program_data = NULL;
    }
    if (program_account) {
        sol_account_destroy(program_account);
        program_account = NULL;
    }

    if (inflight_loader && inflight) {
        inflight->prog = loaded;
        loaded = NULL;
        inflight->has_programdata = has_programdata;
        inflight->programdata = program_data_address;
        inflight->loader_deprecated = loader_deprecated;
        inflight->ro_section_len = inflight->prog ? inflight->prog->ro_section_len : 0;

        if (g_bpf_prog_cache) {
            pthread_rwlock_wrlock(&g_bpf_prog_cache_lock);
            if (g_bpf_prog_cache) {
                sol_bpf_prog_handle_t** slot =
                    (sol_bpf_prog_handle_t**)sol_pubkey_map_get(g_bpf_prog_cache, program_id);
                if (slot && *slot == inflight) {
                    if (inflight->ro_section_len > g_bpf_prog_cache_max_bytes) {
                        /* Do not flush the entire cache for an oversized program. */
                        size_t saved = inflight->ro_section_len;
                        inflight->ro_section_len = 0;
                        bpf_prog_cache_remove_locked(program_id);
                        inflight->ro_section_len = saved;
                    } else {
                        bpf_prog_cache_evict_if_needed_locked(inflight->ro_section_len);
                        g_bpf_prog_cache_total_bytes += inflight->ro_section_len;
                    }
                }
            }
            pthread_rwlock_unlock(&g_bpf_prog_cache_lock);
        }

        pthread_mutex_lock(&inflight->load_mu);
        inflight->load_err = SOL_OK;
        __atomic_store_n(&inflight->load_state, BPF_PROG_STATE_READY, __ATOMIC_RELEASE);
        pthread_cond_broadcast(&inflight->load_cv);
        pthread_mutex_unlock(&inflight->load_mu);

        sol_err_t err = execute_sbf_program(ctx, inflight->prog, inflight->loader_deprecated);
        bpf_prog_handle_release(inflight);
        return err;
    }

    if (force_uncached_load) {
        sol_err_t err = execute_sbf_program(ctx, loaded, loader_deprecated);
        sol_bpf_program_destroy(loaded);
        loaded = NULL;
        return err;
    }

    sol_bpf_prog_handle_t* h = bpf_prog_handle_new(BPF_PROG_STATE_READY);
    if (!h) {
        sol_err_t err = execute_sbf_program(ctx, loaded, loader_deprecated);
        sol_bpf_program_destroy(loaded);
        loaded = NULL;
        return err;
    }

    h->prog = loaded;
    loaded = NULL;
    h->has_programdata = has_programdata;
    h->programdata = program_data_address;
    h->loader_deprecated = loader_deprecated;
    h->ro_section_len = h->prog ? h->prog->ro_section_len : 0;

    sol_bpf_prog_handle_t* exec_h = NULL;
    if (g_bpf_prog_cache) {
        pthread_rwlock_wrlock(&g_bpf_prog_cache_lock);
        exec_h = bpf_prog_cache_insert_locked(program_id, h);
        pthread_rwlock_unlock(&g_bpf_prog_cache_lock);
    }
    if (!exec_h) {
        exec_h = h;
    } else if (exec_h != h) {
        /* Another thread won the race; discard our freshly-loaded handle. */
        bpf_prog_handle_release(h);
    }

    sol_err_t err = execute_sbf_program(ctx, exec_h->prog, exec_h->loader_deprecated);
    bpf_prog_handle_release(exec_h);
    return err;

fail:
    if (loaded) {
        sol_bpf_program_destroy(loaded);
        loaded = NULL;
    }
    if (program_data) {
        sol_account_destroy(program_data);
        program_data = NULL;
    }
    if (program_account) {
        sol_account_destroy(program_account);
        program_account = NULL;
    }

    if (inflight_loader && inflight) {
        pthread_mutex_lock(&inflight->load_mu);
        inflight->load_err = ret;
        __atomic_store_n(&inflight->load_state, BPF_PROG_STATE_FAILED, __ATOMIC_RELEASE);
        pthread_cond_broadcast(&inflight->load_cv);
        pthread_mutex_unlock(&inflight->load_mu);

        if (g_bpf_prog_cache) {
            pthread_rwlock_wrlock(&g_bpf_prog_cache_lock);
            if (g_bpf_prog_cache) {
                sol_bpf_prog_handle_t** slot =
                    (sol_bpf_prog_handle_t**)sol_pubkey_map_get(g_bpf_prog_cache, program_id);
                if (slot && *slot == inflight) {
                    bpf_prog_cache_remove_locked(program_id);
                }
            }
            pthread_rwlock_unlock(&g_bpf_prog_cache_lock);
        }

        bpf_prog_handle_release(inflight);
    }

    return ret;
}

/*
 * Process BPF Upgradeable Loader instruction
 */
sol_err_t sol_bpf_upgradeable_loader_process(sol_invoke_context_t* ctx) {
    if (ctx->instruction_data_len < 4) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    uint32_t instruction;
    memcpy(&instruction, ctx->instruction_data, 4);

    switch (instruction) {
        case UPGRADEABLE_LOADER_INSTR_INITIALIZE_BUFFER:
            return process_initialize_buffer(ctx);

        case UPGRADEABLE_LOADER_INSTR_WRITE:
            return process_write(ctx);

        case UPGRADEABLE_LOADER_INSTR_DEPLOY_WITH_MAX_DATA_LEN:
            return process_deploy(ctx);

        case UPGRADEABLE_LOADER_INSTR_UPGRADE:
            return process_upgrade(ctx);

        case UPGRADEABLE_LOADER_INSTR_SET_AUTHORITY:
        case UPGRADEABLE_LOADER_INSTR_SET_AUTHORITY_CHECKED:
            return process_set_authority(ctx);

        case UPGRADEABLE_LOADER_INSTR_CLOSE:
            return process_close(ctx);

        case UPGRADEABLE_LOADER_INSTR_EXTEND_PROGRAM:
            return process_extend_program(ctx);

        default:
            sol_log_error("BPF Loader: Unknown instruction %u", instruction);
            return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
}

/*
 * Process BPF Loader v2 instruction (non-upgradeable)
 */
sol_err_t sol_bpf_loader_2_process(sol_invoke_context_t* ctx) {
    /* BPF Loader v2 only supports Write and Finalize during deployment */
    if (ctx->instruction_data_len < 4) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    uint32_t instruction;
    memcpy(&instruction, ctx->instruction_data, 4);

    if (instruction == 0) {
        /* Write instruction: variant(4) + offset(4) + vec_len(8) + data */
        if (ctx->account_indices_len < 1 || ctx->instruction_data_len < 16) {
            return SOL_ERR_PROGRAM_INVALID_INSTR;
        }

        const sol_pubkey_t* program_pubkey;
        sol_account_t* program;
        SOL_TRY(get_account(ctx, 0, &program_pubkey, &program));

        if (program == NULL) {
            return SOL_ERR_ACCOUNT_NOT_FOUND;
        }

        uint32_t offset;
        memcpy(&offset, ctx->instruction_data + 4, 4);

        uint64_t vec_len;
        memcpy(&vec_len, ctx->instruction_data + 8, 8);  /* Bincode Vec<u8> length prefix */

        const uint8_t* write_data = ctx->instruction_data + 16;
        size_t write_len = (size_t)vec_len;

        if (offset + write_len > program->meta.data_len) {
            sol_account_destroy(program);
            return SOL_ERR_ACCOUNT_DATA_TOO_SMALL;
        }

        memcpy(program->data + offset, write_data, write_len);
        sol_bank_store_account(ctx->bank, program_pubkey, program);
        bpf_prog_cache_invalidate_program(program_pubkey);
        sol_account_destroy(program);

        sol_log_info("BPF Loader v2: Wrote %zu bytes at offset %u", write_len, offset);
        return SOL_OK;
    } else if (instruction == 1) {
        /* Finalize instruction - mark as executable */
        if (ctx->account_indices_len < 1) {
            return SOL_ERR_PROGRAM_INVALID_INSTR;
        }

        const sol_pubkey_t* program_pubkey;
        sol_account_t* program;
        SOL_TRY(get_account(ctx, 0, &program_pubkey, &program));

        if (program == NULL) {
            return SOL_ERR_ACCOUNT_NOT_FOUND;
        }

        /* Validate ELF */
        if (program->meta.data_len < 4 || memcmp(program->data, "\x7f""ELF", 4) != 0) {
            sol_log_error("BPF Loader v2: Invalid ELF");
            sol_account_destroy(program);
            return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
        }

        program->meta.executable = true;
        sol_bank_store_account(ctx->bank, program_pubkey, program);
        bpf_prog_cache_invalidate_program(program_pubkey);
        sol_account_destroy(program);

        sol_log_info("BPF Loader v2: Finalized program");
        return SOL_OK;
    }

    return SOL_ERR_PROGRAM_INVALID_INSTR;
}

/*
 * Main entry point for BPF Loader programs
 */
sol_err_t sol_bpf_loader_program_execute(sol_invoke_context_t* ctx) {
    /* Get program ID from first account in instruction */
    if (ctx->account_indices_len < 1) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    uint8_t program_key_index = ctx->account_indices[0];
    if (program_key_index >= ctx->account_keys_len) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* The program ID is actually determined by the instruction's program_id
     * which in Solana's execution model is passed separately.
     * For now, we'll check against the known loader IDs */

    /* Check which loader is being invoked based on the instruction's accounts */
    /* In the actual runtime, the program_id would be passed separately */

    /* For BPF loader instructions, they're invoking the loader itself */
    if (is_bpf_upgradeable_loader(&SOL_BPF_LOADER_UPGRADEABLE_ID)) {
        return sol_bpf_upgradeable_loader_process(ctx);
    } else if (is_bpf_loader_2(&SOL_BPF_LOADER_V3_ID)) {
        return sol_bpf_loader_2_process(ctx);
    }

    return SOL_ERR_PROGRAM_INVALID_INSTR;
}
#define SOL_BPF_CPI_MAX_ACCOUNTS  SOL_BPF_MAX_CPI_ACCOUNTS

typedef struct {
    uint64_t    pubkey_ptr;
    uint64_t    lamports_ptr;
    uint64_t    data_len;
    uint64_t    data_ptr;
    uint64_t    owner_ptr;
    uint64_t    rent_epoch;
    uint8_t     is_signer;
    uint8_t     is_writable;
    uint8_t     executable;
    uint8_t     _padding[5];
} sol_bpf_account_info_t;

typedef struct {
    uint64_t    key_ptr;
    uint64_t    lamports_rc_ptr;
    uint64_t    data_rc_ptr;
    uint64_t    owner_ptr;
    uint64_t    rent_epoch;
    uint8_t     is_signer;
    uint8_t     is_writable;
    uint8_t     executable;
    uint8_t     _padding[5];
} sol_bpf_rust_account_info_t;

#define SOL_BPF_RUST_ACCOUNT_INFO_SIZE 48u
#define SOL_BPF_RUST_RC_REF_CELL_VALUE_OFF 24u

static SOL_UNUSED bool
read_account_info_mem(
    sol_bpf_vm_t* vm,
    uint64_t info_ptr,
    sol_bpf_account_info_t* out
) {
    uint8_t* data = sol_bpf_memory_translate(
        &vm->memory, info_ptr, sizeof(sol_bpf_account_info_t), false
    );
    if (data == NULL) {
        return false;
    }

    memcpy(out, data, sizeof(sol_bpf_account_info_t));
    return true;
}

static SOL_UNUSED bool
read_rust_account_info_mem(
    sol_bpf_vm_t* vm,
    uint64_t info_ptr,
    sol_bpf_rust_account_info_t* out
) {
    uint8_t* data = sol_bpf_memory_translate(
        &vm->memory, info_ptr, SOL_BPF_RUST_ACCOUNT_INFO_SIZE, false
    );
    if (data == NULL) {
        return false;
    }

    memcpy(&out->key_ptr, data + 0, 8);
    memcpy(&out->lamports_rc_ptr, data + 8, 8);
    memcpy(&out->data_rc_ptr, data + 16, 8);
    memcpy(&out->owner_ptr, data + 24, 8);
    memcpy(&out->rent_epoch, data + 32, 8);
    out->is_signer = data[40];
    out->is_writable = data[41];
    out->executable = data[42];
    /* padding bytes may be uninitialized; ignore */
    return true;
}

static bool
rust_refcell_read_u64_ptr(
    sol_bpf_vm_t* vm,
    uint64_t rc_ptr,
    uint64_t* out_ptr
) {
    if (!vm || !out_ptr || rc_ptr == 0) {
        return false;
    }

    uint64_t ptr_vaddr = rc_ptr + (uint64_t)SOL_BPF_RUST_RC_REF_CELL_VALUE_OFF;
    uint8_t* p = sol_bpf_memory_translate(&vm->memory, ptr_vaddr, sizeof(uint64_t), false);
    if (p == NULL) {
        return false;
    }

    memcpy(out_ptr, p, sizeof(uint64_t));
    return true;
}

static bool
rust_refcell_read_slice(
    sol_bpf_vm_t* vm,
    uint64_t rc_ptr,
    uint64_t* out_data_ptr,
    uint64_t* out_data_len
) {
    if (!vm || !out_data_ptr || !out_data_len || rc_ptr == 0) {
        return false;
    }

    uint64_t base_vaddr = rc_ptr + (uint64_t)SOL_BPF_RUST_RC_REF_CELL_VALUE_OFF;
    uint8_t* p = sol_bpf_memory_translate(&vm->memory, base_vaddr, 16u, false);
    if (p == NULL) {
        return false;
    }

    memcpy(out_data_ptr, p + 0, 8);
    memcpy(out_data_len, p + 8, 8);
    return true;
}

static bool
rust_refcell_write_slice_len(
    sol_bpf_vm_t* vm,
    uint64_t rc_ptr,
    uint64_t new_len
) {
    if (!vm || rc_ptr == 0) {
        return false;
    }

    uint64_t len_vaddr = rc_ptr + (uint64_t)SOL_BPF_RUST_RC_REF_CELL_VALUE_OFF + 8u;
    uint8_t* p = sol_bpf_memory_translate(&vm->memory, len_vaddr, sizeof(uint64_t), true);
    if (p == NULL) {
        return false;
    }

    memcpy(p, &new_len, sizeof(uint64_t));
    return true;
}

static bool
read_pubkey_ptr(
    sol_bpf_vm_t* vm,
    uint64_t pubkey_ptr,
    sol_pubkey_t* out
) {
    uint8_t* data = sol_bpf_memory_translate(&vm->memory, pubkey_ptr, 32, false);
    if (data == NULL) {
        return false;
    }

    memcpy(out->bytes, data, 32);
    return true;
}

#define CPI_PUBKEY_MAP_SZ   (256u)
#define CPI_PUBKEY_MAP_MASK (CPI_PUBKEY_MAP_SZ - 1u)

static inline void
cpi_pubkey_map_init(int16_t map[static CPI_PUBKEY_MAP_SZ]) {
    memset(map, 0xff, CPI_PUBKEY_MAP_SZ * sizeof(map[0])); /* -1 */
}

static inline void
cpi_pubkey_map_insert(int16_t map[static CPI_PUBKEY_MAP_SZ],
                      const sol_pubkey_t* keys,
                      size_t idx) {
    uint64_t h = sol_xxhash64(keys[idx].bytes, 32, 0);
    size_t pos = (size_t)h & (size_t)CPI_PUBKEY_MAP_MASK;
    for (size_t probe = 0; probe < CPI_PUBKEY_MAP_SZ; probe++) {
        int16_t cur = map[pos];
        if (cur < 0) {
            map[pos] = (int16_t)idx;
            return;
        }
        /* Keep the first occurrence to match the legacy linear scan. */
        if (sol_pubkey_eq(&keys[(size_t)cur], &keys[idx])) {
            return;
        }
        pos = (pos + 1u) & (size_t)CPI_PUBKEY_MAP_MASK;
    }
}

static inline int
cpi_pubkey_map_lookup(const int16_t map[static CPI_PUBKEY_MAP_SZ],
                      const sol_pubkey_t* keys,
                      size_t keys_len,
                      const sol_pubkey_t* key) {
    if (!key) return -1;
    uint64_t h = sol_xxhash64(key->bytes, 32, 0);
    size_t pos = (size_t)h & (size_t)CPI_PUBKEY_MAP_MASK;
    for (size_t probe = 0; probe < CPI_PUBKEY_MAP_SZ; probe++) {
        int16_t cur = map[pos];
        if (cur < 0) return -1;
        size_t idx = (size_t)cur;
        if (__builtin_expect(idx < keys_len, 1) &&
            sol_pubkey_eq(&keys[idx], key)) {
            return (int)idx;
        }
        pos = (pos + 1u) & (size_t)CPI_PUBKEY_MAP_MASK;
    }
    return -1;
}

static SOL_UNUSED int
find_info_index(
    const sol_pubkey_t* pubkeys,
    size_t count,
    const sol_pubkey_t* key
) {
    for (size_t i = 0; i < count; i++) {
        if (sol_pubkey_eq(&pubkeys[i], key)) {
            return (int)i;
        }
    }

    return -1;
}

sol_err_t
sol_bpf_loader_cpi_dispatch(
    sol_bpf_vm_t* vm,
    const sol_bpf_cpi_instruction_t* instr
) {
    if (vm == NULL || instr == NULL) {
        return SOL_ERR_INVAL;
    }

    sol_invoke_context_t* caller = (sol_invoke_context_t*)vm->context;
    if (caller == NULL) {
        return SOL_ERR_INVAL;
    }
    /* Avoid expensive debug formatting (base58, etc) when debug logging is off. */
    const bool log_debug = sol_log_get_level() <= SOL_LOG_DEBUG;

    if (caller->compute_meter != NULL) {
        uint64_t used = sol_bpf_vm_compute_used(vm);
        if (used >= caller->compute_units_accounted) {
            uint64_t delta = used - caller->compute_units_accounted;
            if (__builtin_expect(log_debug, 0)) {
                char _cpi_p58[SOL_PUBKEY_BASE58_LEN] = {0};
                sol_pubkey_to_base58(&caller->program_id, _cpi_p58, sizeof(_cpi_p58));
                sol_log_debug("CU_TRACE cpi_sync: caller=%s vm_used=%lu accounted=%lu delta=%lu meter_remaining=%lu meter_consumed=%lu",
                             _cpi_p58,
                             (unsigned long)used,
                             (unsigned long)caller->compute_units_accounted,
                             (unsigned long)delta,
                             (unsigned long)caller->compute_meter->remaining,
                             (unsigned long)caller->compute_meter->consumed);
            }
            sol_err_t meter_err = sol_compute_meter_consume(caller->compute_meter, delta);
            caller->compute_units_accounted = used;
            if (meter_err != SOL_OK) {
                sol_log_debug("CPI_DIAG: CU sync exhaustion delta=%lu", (unsigned long)delta);
                return meter_err;
            }
        }
    }

    /* Log CPI dispatch entry */
    if (__builtin_expect(log_debug, 0)) {
        char _caller_p[SOL_PUBKEY_BASE58_LEN] = {0};
        char _callee_p[SOL_PUBKEY_BASE58_LEN] = {0};
        sol_pubkey_to_base58(&caller->program_id, _caller_p, sizeof(_caller_p));
        sol_pubkey_to_base58(&instr->program_id, _callee_p, sizeof(_callee_p));
        sol_log_debug("CPI_ENTER: caller=%s callee=%s depth=%u cu_remaining=%lu accts=%zu",
                     _caller_p, _callee_p,
                     (unsigned)(caller->stack_height + 1),
                     caller->compute_meter ? (unsigned long)caller->compute_meter->remaining : 0UL,
                     instr->account_count);
    }

    size_t count = instr->account_count;
    if (count > SOL_BPF_CPI_ACCOUNT_INFO_LIMIT) {
        return SOL_ERR_INVAL;
    }

    /*
     * Build a CPI-local "message" account_keys list:
     * - Unique pubkeys only (so duplicates can use dup_info markers).
     * - Signers first, so native programs that rely on num_signers work.
     */
    sol_pubkey_t unique_keys[SOL_BPF_CPI_MAX_ACCOUNTS];
    uint8_t account_indices[SOL_BPF_CPI_MAX_ACCOUNTS];
    bool unique_is_signer[SOL_BPF_CPI_MAX_ACCOUNTS];
    bool unique_is_writable[SOL_BPF_CPI_MAX_ACCOUNTS];

    size_t unique_count = 0;
    int16_t unique_map[CPI_PUBKEY_MAP_SZ];
    cpi_pubkey_map_init(unique_map);

    /* Pass 1: unique signer keys (preserve relative order among signers). */
    for (size_t i = 0; i < count; i++) {
        if (!instr->accounts[i].is_signer) {
            continue;
        }

        const sol_pubkey_t* key = &instr->accounts[i].pubkey;
        int idx = cpi_pubkey_map_lookup(unique_map, unique_keys, unique_count, key);
        if (idx < 0) {
            unique_keys[unique_count] = *key;
            unique_is_signer[unique_count] = true;
            unique_is_writable[unique_count] = instr->accounts[i].is_writable;
            cpi_pubkey_map_insert(unique_map, unique_keys, unique_count);
            unique_count++;
        } else if (instr->accounts[i].is_writable) {
            unique_is_writable[(size_t)idx] = true;
        }
    }

    size_t signer_count = unique_count;

    /* Pass 2: unique non-signer keys. */
    for (size_t i = 0; i < count; i++) {
        if (instr->accounts[i].is_signer) {
            continue;
        }

        const sol_pubkey_t* key = &instr->accounts[i].pubkey;
        int idx = cpi_pubkey_map_lookup(unique_map, unique_keys, unique_count, key);
        if (idx < 0) {
            unique_keys[unique_count] = *key;
            unique_is_signer[unique_count] = false;
            unique_is_writable[unique_count] = instr->accounts[i].is_writable;
            cpi_pubkey_map_insert(unique_map, unique_keys, unique_count);
            unique_count++;
        } else if (instr->accounts[i].is_writable) {
            unique_is_writable[(size_t)idx] = true;
        }
    }

    /* Map instruction account metas -> unique key indices (duplicates allowed). */
    for (size_t i = 0; i < count; i++) {
        int idx = cpi_pubkey_map_lookup(unique_map,
                                        unique_keys,
                                        unique_count,
                                        &instr->accounts[i].pubkey);
        if (idx < 0) {
            return SOL_ERR_INVAL;
        }
        account_indices[i] = (uint8_t)idx;
    }

    sol_bpf_account_info_t infos[SOL_BPF_CPI_MAX_ACCOUNTS];
    sol_bpf_rust_account_info_t rust_infos[SOL_BPF_CPI_MAX_ACCOUNTS];
    sol_pubkey_t info_pubkeys_local[SOL_BPF_CPI_MAX_ACCOUNTS];
    const sol_pubkey_t* info_pubkeys = NULL;
    uint64_t info_ptrs[SOL_BPF_CPI_MAX_ACCOUNTS];
    size_t info_count = (size_t)instr->account_infos_len;

    if (info_count > SOL_BPF_CPI_ACCOUNT_INFO_LIMIT) {
        return SOL_ERR_INVAL;
    }

    if (info_count > 0 && instr->account_infos_pubkeys != NULL) {
        info_pubkeys = instr->account_infos_pubkeys;
    } else {
        info_pubkeys = info_pubkeys_local;
    }
    const bool need_pubkeys = (info_pubkeys == info_pubkeys_local);

    int16_t info_map[CPI_PUBKEY_MAP_SZ];
    cpi_pubkey_map_init(info_map);

    if (info_count == 0) {
        /* No account_infos were provided. This is valid for CPI instructions that
         * require no accounts (e.g. some sysvar/stake queries). */
    } else if (!instr->account_infos_are_rust) {
        size_t stride = sizeof(sol_bpf_account_info_t);
        if (info_count > (SIZE_MAX / stride)) {
            return SOL_ERR_OVERFLOW;
        }
        size_t total = info_count * stride;
        uint8_t* infos_raw = sol_bpf_memory_translate(&vm->memory,
                                                      instr->account_infos_ptr,
                                                      total,
                                                      false);
        if (infos_raw == NULL) {
            sol_log_debug("CPI_DIAG: translate account_infos C fail ptr=0x%lx len=%zu total=%zu",
                          (unsigned long)instr->account_infos_ptr,
                          info_count,
                          total);
            return SOL_ERR_BPF_EXECUTE;
        }

        for (size_t i = 0; i < info_count; i++) {
            const uint8_t* raw = infos_raw + i * stride;
            memcpy(&infos[i], raw, sizeof(sol_bpf_account_info_t));

            if (need_pubkeys) {
                if (!read_pubkey_ptr(vm, infos[i].pubkey_ptr, &info_pubkeys_local[i])) {
                    sol_log_debug("CPI_DIAG: read_pubkey_ptr C fail i=%zu ptr=0x%lx",
                                  i,
                                  (unsigned long)infos[i].pubkey_ptr);
                    return SOL_ERR_BPF_EXECUTE;
                }
            }

            info_ptrs[i] = instr->account_infos_ptr + (uint64_t)(i * stride);
            cpi_pubkey_map_insert(info_map, info_pubkeys, i);
        }
    } else {
        size_t stride = (size_t)SOL_BPF_RUST_ACCOUNT_INFO_SIZE;
        if (info_count > (SIZE_MAX / stride)) {
            return SOL_ERR_OVERFLOW;
        }
        size_t total = info_count * stride;
        uint8_t* infos_raw = sol_bpf_memory_translate(&vm->memory,
                                                      instr->account_infos_ptr,
                                                      total,
                                                      false);
        if (infos_raw == NULL) {
            sol_log_debug("CPI_DIAG: translate account_infos Rust fail ptr=0x%lx len=%zu total=%zu",
                          (unsigned long)instr->account_infos_ptr,
                          info_count,
                          total);
            return SOL_ERR_BPF_EXECUTE;
        }

        for (size_t i = 0; i < info_count; i++) {
            const uint8_t* data = infos_raw + i * stride;
            memcpy(&rust_infos[i].key_ptr, data + 0, 8);
            memcpy(&rust_infos[i].lamports_rc_ptr, data + 8, 8);
            memcpy(&rust_infos[i].data_rc_ptr, data + 16, 8);
            memcpy(&rust_infos[i].owner_ptr, data + 24, 8);
            memcpy(&rust_infos[i].rent_epoch, data + 32, 8);
            rust_infos[i].is_signer = data[40];
            rust_infos[i].is_writable = data[41];
            rust_infos[i].executable = data[42];

            if (need_pubkeys) {
                if (!read_pubkey_ptr(vm, rust_infos[i].key_ptr, &info_pubkeys_local[i])) {
                    sol_log_debug("CPI_DIAG: read_pubkey_ptr Rust fail i=%zu ptr=0x%lx",
                                  i,
                                  (unsigned long)rust_infos[i].key_ptr);
                    return SOL_ERR_BPF_EXECUTE;
                }
            }

            info_ptrs[i] = instr->account_infos_ptr + (uint64_t)(i * stride);
            cpi_pubkey_map_insert(info_map, info_pubkeys, i);
        }
    }

    /* Per-account data translation cost (pre-SIMD-0339).
       Agave's translate_accounts_common charges for each unique instruction
       account (skipping duplicates):
       - Executable accounts: stored_data_len / cpi_bytes_per_unit
         (uses the bank's stored account data length)
       - Non-executable accounts: account_info data_len / cpi_bytes_per_unit
         (uses the caller's account_info data length, charged inside
          CallerAccount::from_account_info / from_sol_account_info) */
    if (caller->compute_meter != NULL) {
        bool charged_unique[SOL_BPF_CPI_MAX_ACCOUNTS];
        memset(charged_unique, 0, sizeof(charged_unique));

        for (size_t i = 0; i < count; i++) {
            uint8_t uid = account_indices[i];
            if (charged_unique[uid]) continue;
            charged_unique[uid] = true;

            uint64_t charge_data_len = 0;

            /* Prefer account_infos data length when available.
             *
             * For non-executable accounts, Agave charges based on account_info data_len.
             * For executable accounts, Agave charges based on the bank's stored data_len,
             * but when an executable account is present in account_infos, its data_len
             * matches the stored length, so we can avoid an expensive bank load.
             *
             * If an account is executable and absent from account_infos (Agave permits
             * this), fall back to a bank load to get the stored data_len. */
            int info_idx = cpi_pubkey_map_lookup(info_map,
                                                 info_pubkeys,
                                                 info_count,
                                                 &unique_keys[uid]);
            if (info_idx >= 0) {
                if (!instr->account_infos_are_rust) {
                    charge_data_len = infos[info_idx].data_len;
                } else {
                    uint64_t d_ptr = 0, d_len = 0;
                    if (rust_refcell_read_slice(vm,
                                                rust_infos[info_idx].data_rc_ptr,
                                                &d_ptr, &d_len)) {
                        charge_data_len = d_len;
                    }
                }
            } else if (caller->bank != NULL) {
                sol_account_t* acct = sol_bank_load_account_view(caller->bank,
                                                                 &unique_keys[uid]);
                if (acct != NULL && acct->meta.executable) {
                    charge_data_len = (uint64_t)acct->meta.data_len;
                }
                if (acct != NULL) sol_account_destroy(acct);
            }

            uint64_t cost = charge_data_len / SOL_CU_CPI_BYTES_PER_UNIT;
            if (cost > 0) {
                sol_err_t meter_err = sol_compute_meter_consume(
                    caller->compute_meter, cost);
                if (meter_err != SOL_OK) {
                    sol_log_debug("CPI_DIAG: translation CU exhaustion at acct %zu cost=%lu", i, (unsigned long)cost);
                    return meter_err;
                }
            }
        }
    }

    /*
     * CPI caller-state overrides:
     *
     * The caller may have mutated account state in its in-VM AccountInfo buffers
     * without writing back to the bank yet. Agave exposes these mutations to the
     * callee via a shared transaction context. We replicate that behavior (and
     * avoid a very expensive bank sync) by pushing a short-lived TLS override
     * table, keyed by the caller-provided account_infos.
     *
     * While overrides are active, bank account loads return the caller AccountInfo
     * view unless the callee has written the pubkey (then bank state is
     * authoritative for that pubkey within the CPI).
     */
    sol_account_t override_accounts[SOL_BPF_CPI_MAX_ACCOUNTS];
    uint8_t override_written[SOL_BPF_CPI_MAX_ACCOUNTS];
    sol_bank_account_overrides_t overrides = {0};
    sol_bank_account_overrides_t* overrides_prev = NULL;
    bool overrides_active = false;

    if (caller->bank != NULL && info_count > 0) {
        memset(override_accounts, 0, sizeof(override_accounts));
        memset(override_written, 0, sizeof(override_written));

        for (size_t i = 0; i < info_count; i++) {
            sol_account_t* oa = &override_accounts[i];
            oa->data_borrowed = true;
            oa->meta.owner = SOL_SYSTEM_PROGRAM_ID;

            uint64_t lamports_val = 0;
            sol_pubkey_t owner = {0};
            uint64_t data_ptr = 0;
            uint64_t data_len = 0;
            const uint8_t* data = NULL;
            uint64_t rent_epoch = UINT64_MAX;
            bool executable = false;

            if (!instr->account_infos_are_rust) {
                sol_bpf_account_info_t* info = &infos[i];

                rent_epoch = info->rent_epoch;
                executable = info->executable != 0;

                uint64_t* lamports = (uint64_t*)sol_bpf_memory_translate(
                    &vm->memory, info->lamports_ptr, sizeof(uint64_t), false
                );
                if (lamports == NULL) {
                    sol_log_debug("CPI_DIAG: overrides C lamports translate fail i=%zu ptr=0x%lx",
                                  i, (unsigned long)info->lamports_ptr);
                    return SOL_ERR_BPF_EXECUTE;
                }
                lamports_val = *lamports;

                if (!read_pubkey_ptr(vm, info->owner_ptr, &owner)) {
                    sol_log_debug("CPI_DIAG: overrides C owner translate fail i=%zu ptr=0x%lx",
                                  i, (unsigned long)info->owner_ptr);
                    return SOL_ERR_BPF_EXECUTE;
                }

                data_ptr = info->data_ptr;
                data_len = info->data_len;
                if (data_len > 0) {
                    if (data_len > (uint64_t)SIZE_MAX) return SOL_ERR_OVERFLOW;
                    data = sol_bpf_memory_translate(&vm->memory, data_ptr, (size_t)data_len, false);
                    if (data == NULL) {
                        sol_log_debug("CPI_DIAG: overrides C data translate fail i=%zu ptr=0x%lx len=%lu",
                                      i, (unsigned long)data_ptr, (unsigned long)data_len);
                        return SOL_ERR_BPF_EXECUTE;
                    }
                }
            } else {
                sol_bpf_rust_account_info_t* info = &rust_infos[i];

                rent_epoch = info->rent_epoch;
                executable = info->executable != 0;

                uint64_t lamports_ptr = 0;
                if (!rust_refcell_read_u64_ptr(vm, info->lamports_rc_ptr, &lamports_ptr)) {
                    sol_log_debug("CPI_DIAG: overrides Rust lamports_rc fail i=%zu rc_ptr=0x%lx",
                                  i, (unsigned long)info->lamports_rc_ptr);
                    return SOL_ERR_BPF_EXECUTE;
                }

                uint64_t* lamports = (uint64_t*)sol_bpf_memory_translate(
                    &vm->memory, lamports_ptr, sizeof(uint64_t), false
                );
                if (lamports == NULL) {
                    sol_log_debug("CPI_DIAG: overrides Rust lamports translate fail i=%zu ptr=0x%lx",
                                  i, (unsigned long)lamports_ptr);
                    return SOL_ERR_BPF_EXECUTE;
                }
                lamports_val = *lamports;

                if (!read_pubkey_ptr(vm, info->owner_ptr, &owner)) {
                    sol_log_debug("CPI_DIAG: overrides Rust owner translate fail i=%zu ptr=0x%lx",
                                  i, (unsigned long)info->owner_ptr);
                    return SOL_ERR_BPF_EXECUTE;
                }

                if (!rust_refcell_read_slice(vm, info->data_rc_ptr, &data_ptr, &data_len)) {
                    sol_log_debug("CPI_DIAG: overrides Rust data_rc fail i=%zu rc_ptr=0x%lx",
                                  i, (unsigned long)info->data_rc_ptr);
                    return SOL_ERR_BPF_EXECUTE;
                }
                if (data_len > 0) {
                    if (data_len > (uint64_t)SIZE_MAX) return SOL_ERR_OVERFLOW;
                    data = sol_bpf_memory_translate(&vm->memory, data_ptr, (size_t)data_len, false);
                    if (data == NULL) {
                        sol_log_debug("CPI_DIAG: overrides Rust data translate fail i=%zu ptr=0x%lx len=%lu",
                                      i, (unsigned long)data_ptr, (unsigned long)data_len);
                        return SOL_ERR_BPF_EXECUTE;
                    }
                }
            }

            oa->meta.lamports = lamports_val;
            oa->meta.owner = owner;
            oa->meta.data_len = (ulong)data_len;
            oa->meta.rent_epoch = (sol_epoch_t)rent_epoch;
            oa->meta.executable = executable;
            oa->data = (uint8_t*)data;
        }

        overrides.keys = info_pubkeys;
        overrides.accounts = override_accounts;
        overrides.written = override_written;
        overrides.len = info_count;
        overrides_active = true;
    }

    if (__builtin_expect(log_debug, 0)) {
        char _p58[SOL_PUBKEY_BASE58_LEN] = {0};
        sol_pubkey_to_base58(&instr->program_id, _p58, sizeof(_p58));
        sol_log_debug("CPI_DIAG: dispatch_ok callee=%s count=%zu info_count=%zu unique=%zu depth=%lu",
                     _p58, count, info_count, unique_count,
                     (unsigned long)(caller->stack_height ? caller->stack_height : 1));
    }

    sol_invoke_context_t cpi_ctx = {0};
    cpi_ctx.bank = caller->bank;
    cpi_ctx.account_keys = unique_keys;
    cpi_ctx.account_keys_len = (uint8_t)unique_count;
    cpi_ctx.is_writable = unique_is_writable;
    cpi_ctx.is_signer = unique_is_signer;
    cpi_ctx.account_indices = account_indices;
    cpi_ctx.account_indices_len = (uint8_t)count;
    cpi_ctx.instruction_data = instr->data;
    cpi_ctx.instruction_data_len = (uint16_t)instr->data_len;
    cpi_ctx.program_id = instr->program_id;
    cpi_ctx.num_signers = (uint8_t)signer_count;
    uint64_t caller_height = caller->stack_height ? caller->stack_height : 1;
    cpi_ctx.stack_height = caller_height + 1;
    cpi_ctx.clock = caller->clock;
    cpi_ctx.rent = caller->rent;
    cpi_ctx.epoch_schedule = caller->epoch_schedule;
    cpi_ctx.lamports_per_signature = caller->lamports_per_signature;
    cpi_ctx.compute_budget = caller->compute_budget;
    cpi_ctx.compute_meter = caller->compute_meter;
    cpi_ctx.compute_units_accounted = 0;
    cpi_ctx.transaction = caller->transaction;
    cpi_ctx.current_instruction_index = caller->current_instruction_index;
    cpi_ctx.instruction_trace = caller->instruction_trace;

    if (overrides_active) {
        overrides_prev = sol_bank_overrides_push(&overrides);
    }
    sol_err_t err = sol_program_execute(&cpi_ctx);
    if (overrides_active) {
        sol_bank_overrides_pop(overrides_prev);
    }

    if (caller->compute_meter != NULL) {
        if (__builtin_expect(log_debug, 0)) {
            char _cpi_p58[SOL_PUBKEY_BASE58_LEN] = {0};
            char _callee_p58[SOL_PUBKEY_BASE58_LEN] = {0};
            sol_pubkey_to_base58(&caller->program_id, _cpi_p58, sizeof(_cpi_p58));
            sol_pubkey_to_base58(&cpi_ctx.program_id, _callee_p58, sizeof(_callee_p58));
            sol_log_debug("CU_TRACE cpi_return: caller=%s callee=%s err=%d vm_used=%lu meter_remaining=%lu meter_consumed=%lu new_budget=%lu",
                         _cpi_p58, _callee_p58,
                         (int)err,
                         (unsigned long)vm->compute_units_used,
                         (unsigned long)caller->compute_meter->remaining,
                         (unsigned long)caller->compute_meter->consumed,
                         (unsigned long)(vm->compute_units_used + caller->compute_meter->remaining));
        }
        vm->compute_units = vm->compute_units_used + caller->compute_meter->remaining;
    }

    /*
     * Propagate return data from callee to caller.
     *
     * In Agave, the transaction context is shared between all CPI levels,
     * so return data set by the callee is automatically visible to the
     * caller when it calls sol_get_return_data.  In our code, each CPI
     * level has its own invoke_context, so we must copy the return data
     * back to the caller's context explicitly.
     *
     * This must happen even on CPI failure — Agave's transaction context
     * retains the callee's return data regardless of success/failure.
     */
    /* CPI return_data propagation logging disabled for performance */
    memcpy(caller->return_data, cpi_ctx.return_data, cpi_ctx.return_data_len);
    caller->return_data_len = cpi_ctx.return_data_len;
    caller->return_data_program = cpi_ctx.return_data_program;

    /*
     * CPI failure: skip post-update and return error.
     *
     * In Agave, when process_instruction returns Err, cpi_common returns
     * immediately via the ? operator. The post-update (update_caller_account)
     * is NOT executed on failure. The transaction context rolls back the
     * callee's changes, and the caller VM halts (handled in sol_bpf_cpi.c).
     *
     * We must NOT update the caller's serialized buffer or account_infos
     * on CPI failure, as this would corrupt the lamport conservation check.
     */
    if (err != SOL_OK) {
        char cpi_prog[SOL_PUBKEY_BASE58_LEN] = {0};
        sol_pubkey_to_base58(&instr->program_id, cpi_prog, sizeof(cpi_prog));
        sol_log_debug("CPI_FAIL: callee=%s err=%d(%s) depth=%u",
                     cpi_prog, err, sol_err_str(err),
                     (unsigned)cpi_ctx.stack_height);
        return err;
    }

    if (caller->bank != NULL) {
        bool synced_info[SOL_BPF_CPI_MAX_ACCOUNTS];
        memset(synced_info, 0, sizeof(synced_info));

        int16_t caller_key_map[CPI_PUBKEY_MAP_SZ];
        cpi_pubkey_map_init(caller_key_map);
        for (size_t ki = 0; ki < caller->account_keys_len; ki++) {
            cpi_pubkey_map_insert(caller_key_map, caller->account_keys, ki);
        }

        int16_t caller_meta_by_key_idx[256];
        for (size_t k = 0; k < 256u; k++) {
            caller_meta_by_key_idx[k] = -1;
        }
        const sol_sbf_account_meta_t* caller_metas =
            (const sol_sbf_account_meta_t*)vm->caller_metas;
        if (caller_metas != NULL) {
            for (size_t mi = 0; mi < vm->caller_meta_count; mi++) {
                uint8_t ckey = caller_metas[mi].key_index;
                if (ckey < caller->account_keys_len && caller_meta_by_key_idx[ckey] < 0) {
                    caller_meta_by_key_idx[ckey] = (int16_t)mi;
                }
            }
        }

        for (size_t i = 0; i < count; i++) {
            if (!instr->accounts[i].is_writable) {
                continue;
            }

            int info_idx = cpi_pubkey_map_lookup(info_map,
                                                 info_pubkeys,
                                                 info_count,
                                                 &instr->accounts[i].pubkey);
            if (info_idx < 0) {
                /* Executable accounts may be absent from account_infos.
                 * They should never be writable, but handle gracefully. */
                sol_account_t* chk = sol_bank_load_account_view(caller->bank,
                                                            &instr->accounts[i].pubkey);
                if (chk != NULL && chk->meta.executable) {
                    sol_account_destroy(chk);
                    continue;
                }
                if (chk != NULL) sol_account_destroy(chk);
                return SOL_ERR_ACCOUNT_NOT_FOUND;
            }

            /* If the callee did not touch this account, the caller's AccountInfo
             * buffers already contain the correct state (including any mutations
             * the caller made before the CPI).  Loading from the bank here would
             * revert those caller-local changes because we avoided the expensive
             * pre-sync (CPI pre-update) and the bank may still hold stale state. */
            if (overrides_active && override_written[info_idx] == 0) {
                continue;
            }

            if ((size_t)info_idx < info_count && synced_info[info_idx]) {
                continue;
            }
            if ((size_t)info_idx < info_count) {
                synced_info[info_idx] = true;
            }

            const sol_sbf_account_meta_t* caller_meta = NULL;
            size_t caller_meta_idx = 0;
            int caller_key_idx = cpi_pubkey_map_lookup(caller_key_map,
                                                       caller->account_keys,
                                                       caller->account_keys_len,
                                                       &instr->accounts[i].pubkey);
            if (caller_key_idx >= 0) {
                int16_t mi = caller_meta_by_key_idx[(uint8_t)caller_key_idx];
                if (mi >= 0 && (size_t)mi < vm->caller_meta_count) {
                    caller_meta_idx = (size_t)mi;
                    caller_meta = &caller_metas[caller_meta_idx];
                }
            }

            sol_account_t* account = sol_bank_load_account_view(caller->bank, &instr->accounts[i].pubkey);
            if (account == NULL) {
                continue;
            }

            uint64_t data_ptr = 0;
            uint64_t pre_len = 0;

            /* Look up original_data_len from caller serialization metadata.
               Agave checks realloc bounds against the data length at the start
               of the caller instruction, not the current (possibly grown) length. */
            uint64_t original_data_len = caller_meta ? caller_meta->pre_data_len : 0;

            if (!instr->account_infos_are_rust) {
                sol_bpf_account_info_t* info = &infos[info_idx];

                uint64_t* lamports = (uint64_t*)sol_bpf_memory_translate(
                    &vm->memory, info->lamports_ptr, sizeof(uint64_t), false
                );
                if (lamports != NULL) {
                    *lamports = account->meta.lamports;
                }

                uint8_t* owner_ptr = sol_bpf_memory_translate(
                    &vm->memory, info->owner_ptr, 32, false
                );
                if (owner_ptr != NULL) {
                    memcpy(owner_ptr, account->meta.owner.bytes, 32);
                }

                uint8_t* info_mem = sol_bpf_memory_translate(
                    &vm->memory, info_ptrs[info_idx], sizeof(sol_bpf_account_info_t), false
                );
                if (info_mem != NULL) {
                    /* Update account data length in the caller frame. */
                    pre_len = info->data_len;
                    uint64_t post_len = (uint64_t)account->meta.data_len;
                    /* Agave checks against original_data_len (length at start of
                       caller instruction), not current pre_len which may already
                       be grown from a previous CPI. */
                    uint64_t realloc_limit = original_data_len +
                                             SOL_SBF_MAX_PERMITTED_DATA_INCREASE;
                    if (post_len > realloc_limit) {
                        sol_account_destroy(account);
                        return SOL_ERR_ACCOUNT_DATA_TOO_LARGE;
                    }

                    memcpy(info_mem + 16, &post_len, sizeof(uint64_t)); /* data_len */
                    /* Note: Agave's update_caller_account does NOT sync
                     * executable or rent_epoch back to the caller. */
                }

                data_ptr = info->data_ptr;

                /*
                 * Keep the serialized input buffer consistent so that the caller's
                 * eventual writeback doesn't revert CPI changes.
                 */
                if (data_ptr >= sizeof(uint64_t)) {
                    uint64_t data_len_ptr_vaddr = data_ptr - sizeof(uint64_t);
                    uint8_t* data_len_ptr = sol_bpf_memory_translate(
                        &vm->memory, data_len_ptr_vaddr, sizeof(uint64_t), false
                    );
                    if (data_len_ptr != NULL) {
                        uint64_t post_len = (uint64_t)account->meta.data_len;
                        memcpy(data_len_ptr, &post_len, sizeof(uint64_t));
                    }
                }
            } else {
                sol_bpf_rust_account_info_t* info = &rust_infos[info_idx];

                uint64_t lamports_ptr = 0;
                if (!rust_refcell_read_u64_ptr(vm, info->lamports_rc_ptr, &lamports_ptr)) {
                    sol_account_destroy(account);
                    return SOL_ERR_BPF_EXECUTE;
                }

                uint64_t* lamports = (uint64_t*)sol_bpf_memory_translate(
                    &vm->memory, lamports_ptr, sizeof(uint64_t), true
                );
                if (lamports != NULL) {
                    *lamports = account->meta.lamports;
                }

                uint8_t* owner_ptr = sol_bpf_memory_translate(
                    &vm->memory, info->owner_ptr, 32, true
                );
                if (owner_ptr != NULL) {
                    memcpy(owner_ptr, account->meta.owner.bytes, 32);
                }

                uint64_t data_len = 0;
                if (!rust_refcell_read_slice(vm, info->data_rc_ptr, &data_ptr, &data_len)) {
                    sol_account_destroy(account);
                    return SOL_ERR_BPF_EXECUTE;
                }

                pre_len = data_len;
                uint64_t post_len = (uint64_t)account->meta.data_len;
                uint64_t realloc_limit = original_data_len +
                                         SOL_SBF_MAX_PERMITTED_DATA_INCREASE;
                if (post_len > realloc_limit) {
                    sol_account_destroy(account);
                    return SOL_ERR_ACCOUNT_DATA_TOO_LARGE;
                }

                (void)rust_refcell_write_slice_len(vm, info->data_rc_ptr, post_len);
                /* Note: Agave's update_caller_account does NOT sync
                 * executable or rent_epoch back to the caller. */

                if (data_ptr >= sizeof(uint64_t)) {
                    uint64_t data_len_ptr_vaddr = data_ptr - sizeof(uint64_t);
                    uint8_t* data_len_ptr = sol_bpf_memory_translate(
                        &vm->memory, data_len_ptr_vaddr, sizeof(uint64_t), true
                    );
                    if (data_len_ptr != NULL) {
                        memcpy(data_len_ptr, &post_len, sizeof(uint64_t));
                    }
                }
            }

            if (account->meta.data_len > 0 && account->data != NULL && data_ptr != 0) {
                uint8_t* data_mem = sol_bpf_memory_translate(
                    &vm->memory, data_ptr, account->meta.data_len, true
                );
                if (data_mem != NULL) {
                    memcpy(data_mem, account->data, account->meta.data_len);
                }
            }

            /* Zero-fill freed data region when account data shrinks.
               Agave does this in update_caller_account (cpi.rs:1308-1313). */
            if ((uint64_t)account->meta.data_len < pre_len && data_ptr != 0) {
                uint64_t zero_off = (uint64_t)account->meta.data_len;
                uint64_t zero_len = pre_len - zero_off;
                uint8_t* zero_mem = sol_bpf_memory_translate(
                    &vm->memory, data_ptr + zero_off, zero_len, true
                );
                if (zero_mem != NULL) {
                    memset(zero_mem, 0, (size_t)zero_len);
                }
            }

            /*
             * Also update the serialized input buffer directly.
             *
             * In Agave, update_caller_account writes to CallerAccount which
             * points into the serialized buffer. We do the same here to ensure
             * sbf_apply_output sees the correct post-CPI lamport values,
             * matching the account_info pointer writes above.
             */
            if (caller_meta != NULL && vm->caller_input_buf != NULL) {
                /* Update lamports in serialized buffer */
                if (caller_meta->lamports_off + sizeof(uint64_t) <= vm->caller_input_len) {
                    uint64_t buf_old = 0;
                    memcpy(&buf_old, vm->caller_input_buf + caller_meta->lamports_off, sizeof(uint64_t));
                    memcpy(vm->caller_input_buf + caller_meta->lamports_off,
                           &account->meta.lamports, sizeof(uint64_t));
                    if (buf_old != account->meta.lamports) {
                        if (__builtin_expect(log_debug, 0)) {
                            char _k58[SOL_PUBKEY_BASE58_LEN] = {0};
                            sol_pubkey_to_base58(&instr->accounts[i].pubkey, _k58, sizeof(_k58));
                            sol_log_debug("CPI_BUF_WRITE: key=%s buf_old=%lu new=%lu off=%zu mi=%zu",
                                         _k58, (unsigned long)buf_old, (unsigned long)account->meta.lamports,
                                         caller_meta->lamports_off, caller_meta_idx);
                        }
                    }
                }
                /* Update data_len in serialized buffer */
                if (caller_meta->data_len_off + sizeof(uint64_t) <= vm->caller_input_len) {
                    uint64_t post_data_len = (uint64_t)account->meta.data_len;
                    memcpy(vm->caller_input_buf + caller_meta->data_len_off,
                           &post_data_len, sizeof(uint64_t));
                }
                /* Update owner in serialized buffer */
                if (caller_meta->owner_off + 32 <= vm->caller_input_len) {
                    memcpy(vm->caller_input_buf + caller_meta->owner_off,
                           account->meta.owner.bytes, 32);
                }
                /* Update data in serialized buffer */
                if (account->meta.data_len > 0 && account->data != NULL &&
                    caller_meta->data_off + account->meta.data_len <= vm->caller_input_len) {
                    memcpy(vm->caller_input_buf + caller_meta->data_off,
                           account->data, account->meta.data_len);
                }
                /* Zero-fill freed data in serialized buffer on shrink */
                if ((uint64_t)account->meta.data_len < pre_len &&
                    caller_meta->data_off + pre_len <= vm->caller_input_len) {
                    memset(vm->caller_input_buf + caller_meta->data_off + account->meta.data_len,
                           0, (size_t)(pre_len - account->meta.data_len));
                }
            } else if (vm->caller_metas != NULL && vm->caller_input_buf != NULL) {
                char _k58[SOL_PUBKEY_BASE58_LEN] = {0};
                sol_pubkey_to_base58(&instr->accounts[i].pubkey, _k58, sizeof(_k58));
                sol_log_warn("CPI_BUF_NOMATCH: key=%s meta_count=%zu", _k58, vm->caller_meta_count);
            }

            sol_account_destroy(account);
        }
    }

    caller->return_data_len = cpi_ctx.return_data_len;
    if (cpi_ctx.return_data_len > 0) {
        memcpy(caller->return_data, cpi_ctx.return_data, cpi_ctx.return_data_len);
    }
    caller->return_data_program = cpi_ctx.return_data_program;

    /* CPI success trace */
    if (__builtin_expect(log_debug, 0)) {
        char _callee[SOL_PUBKEY_BASE58_LEN] = {0};
        sol_pubkey_to_base58(&instr->program_id, _callee, sizeof(_callee));
        sol_log_debug("CPI_OK: callee=%s depth=%u cu_used=%lu ret_data_len=%u",
                     _callee, (unsigned)cpi_ctx.stack_height,
                     (unsigned long)vm->compute_units_used,
                     (unsigned)caller->return_data_len);
    }

    return err;
}
