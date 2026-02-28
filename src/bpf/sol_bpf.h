/*
 * sol_bpf.h - Solana BPF/SBF Virtual Machine
 *
 * Implements the Solana Berkeley Packet Filter (sBPF) virtual machine
 * for executing on-chain programs. Supports both interpreter and JIT modes.
 */

#ifndef SOL_BPF_H
#define SOL_BPF_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/*
 * SBPF Version (detected from ELF e_flags)
 */
typedef enum {
    SOL_SBPF_V0 = 0,    /* Legacy format */
    SOL_SBPF_V1 = 1,    /* SIMD-0166: dynamic stack frames */
    SOL_SBPF_V2 = 2,    /* SIMD-0174/0173: PQR, moved mem classes, etc. */
    SOL_SBPF_V3 = 3,    /* SIMD-0178/0179/0189: static syscalls */
} sol_sbpf_version_t;

/* Version feature helpers (matching Agave rbpf program.rs) */
static inline bool sol_sbpf_dynamic_stack_frames(sol_sbpf_version_t v) { return v >= SOL_SBPF_V1; }
static inline bool sol_sbpf_enable_pqr(sol_sbpf_version_t v) { return v >= SOL_SBPF_V2; }
static inline bool sol_sbpf_explicit_sign_ext(sol_sbpf_version_t v) { return v >= SOL_SBPF_V2; }
static inline bool sol_sbpf_swap_sub_operands(sol_sbpf_version_t v) { return v >= SOL_SBPF_V2; }
static inline bool sol_sbpf_disable_neg(sol_sbpf_version_t v) { return v >= SOL_SBPF_V2; }
static inline bool sol_sbpf_callx_uses_src(sol_sbpf_version_t v) { return v >= SOL_SBPF_V2; }
static inline bool sol_sbpf_disable_lddw(sol_sbpf_version_t v) { return v >= SOL_SBPF_V2; }
static inline bool sol_sbpf_disable_le(sol_sbpf_version_t v) { return v >= SOL_SBPF_V2; }
static inline bool sol_sbpf_move_mem_classes(sol_sbpf_version_t v) { return v >= SOL_SBPF_V2; }
static inline bool sol_sbpf_static_syscalls(sol_sbpf_version_t v) { return v >= SOL_SBPF_V3; }

/*
 * BPF Constants
 */
#define SOL_BPF_NUM_REGISTERS     11      /* r0-r10 */
#define SOL_BPF_STACK_FRAME_SIZE  4096    /* Per-call stack frame size */
#define SOL_BPF_STACK_SIZE        (SOL_BPF_STACK_FRAME_SIZE * SOL_BPF_MAX_CALL_DEPTH) /* Total stack bytes: matches rbpf stack_size() = frame_size * max_call_depth */
#define SOL_BPF_MAX_CALL_DEPTH    64      /* Maximum call depth */
#define SOL_BPF_MAX_INSTRUCTIONS  2000000 /* Max instructions per program */
#define SOL_BPF_HEAP_SIZE         (32 * 1024)  /* 32KB default heap */
/* CPI account limit.  Pre-SIMD-0339 (with increase_tx_account_lock_limit
 * active): MAX_CPI_ACCOUNT_INFOS = 128.  SIMD-0339 raises this to 255 but
 * is NOT yet active on mainnet.  Keep stack arrays sized at 256 for safety
 * but enforce the 128 limit in validation. */
#define SOL_BPF_MAX_CPI_ACCOUNTS  256
#define SOL_BPF_CPI_ACCOUNT_INFO_LIMIT 128

/*
 * Memory regions
 */
#define SOL_BPF_MM_PROGRAM_START    0x100000000ULL   /* Program text */
#define SOL_BPF_MM_STACK_START      0x200000000ULL   /* Stack */
#define SOL_BPF_MM_HEAP_START       0x300000000ULL   /* Heap */
#define SOL_BPF_MM_INPUT_START      0x400000000ULL   /* Input data */

/*
 * BPF Instruction Classes
 */
#define SOL_BPF_CLASS_LD      0x00    /* Load immediate */
#define SOL_BPF_CLASS_LDX     0x01    /* Load from memory */
#define SOL_BPF_CLASS_ST      0x02    /* Store immediate */
#define SOL_BPF_CLASS_STX     0x03    /* Store from register */
#define SOL_BPF_CLASS_ALU     0x04    /* 32-bit ALU */
#define SOL_BPF_CLASS_JMP     0x05    /* Jump */
#define SOL_BPF_CLASS_JMP32   0x06    /* 32-bit jump */
#define SOL_BPF_CLASS_ALU64   0x07    /* 64-bit ALU */

/*
 * ALU/ALU64 Operations
 */
#define SOL_BPF_ALU_ADD   0x00
#define SOL_BPF_ALU_SUB   0x10
#define SOL_BPF_ALU_MUL   0x20
#define SOL_BPF_ALU_DIV   0x30
#define SOL_BPF_ALU_OR    0x40
#define SOL_BPF_ALU_AND   0x50
#define SOL_BPF_ALU_LSH   0x60
#define SOL_BPF_ALU_RSH   0x70
#define SOL_BPF_ALU_NEG   0x80
#define SOL_BPF_ALU_MOD   0x90
#define SOL_BPF_ALU_XOR   0xa0
#define SOL_BPF_ALU_MOV   0xb0
#define SOL_BPF_ALU_ARSH  0xc0
#define SOL_BPF_ALU_END   0xd0   /* Endianness conversion */
#define SOL_BPF_ALU_HOR   0xf0   /* SBPFv2+: High OR (r_dst |= (u64)imm << 32) */

/*
 * SBPFv2 PQR class (0x06) operation codes
 * NOTE: PQR class reuses class value 0x06 (same as JMP32 in V0/V1).
 * In V2+, class 0x06 is PQR; JMP32 is no longer used.
 */
#define SOL_BPF_CLASS_PQR     0x06
#define SOL_BPF_PQR_LMUL     0x80
#define SOL_BPF_PQR_UHMUL    0x20
#define SOL_BPF_PQR_UDIV     0x40
#define SOL_BPF_PQR_UREM     0x60
#define SOL_BPF_PQR_SHMUL    0xa0
#define SOL_BPF_PQR_SDIV     0xc0
#define SOL_BPF_PQR_SREM     0xe0
/* BPF_B (0x10) flag converts 32-bit PQR to 64-bit */
#define SOL_BPF_PQR_64       0x10

/*
 * SBPFv2 moved memory instruction classes (move_memory_instruction_classes)
 * Loads move from class LDX(0x01) to ALU32(0x04)
 * Stores move from class ST/STX(0x02/0x03) to ALU64(0x07)
 */
#define SOL_BPF_V2_MEM_1B    0x20
#define SOL_BPF_V2_MEM_2B    0x30
#define SOL_BPF_V2_MEM_4B    0x80
#define SOL_BPF_V2_MEM_8B    0x90

/*
 * Jump Operations
 */
#define SOL_BPF_JMP_JA    0x00   /* Unconditional jump */
#define SOL_BPF_JMP_JEQ   0x10   /* Jump if equal */
#define SOL_BPF_JMP_JGT   0x20   /* Jump if greater than (unsigned) */
#define SOL_BPF_JMP_JGE   0x30   /* Jump if greater or equal (unsigned) */
#define SOL_BPF_JMP_JSET  0x40   /* Jump if bits set */
#define SOL_BPF_JMP_JNE   0x50   /* Jump if not equal */
#define SOL_BPF_JMP_JSGT  0x60   /* Jump if greater than (signed) */
#define SOL_BPF_JMP_JSGE  0x70   /* Jump if greater or equal (signed) */
#define SOL_BPF_JMP_CALL  0x80   /* Function call */
#define SOL_BPF_JMP_EXIT  0x90   /* Exit program */
#define SOL_BPF_JMP_JLT   0xa0   /* Jump if less than (unsigned) */
#define SOL_BPF_JMP_JLE   0xb0   /* Jump if less or equal (unsigned) */
#define SOL_BPF_JMP_JSLT  0xc0   /* Jump if less than (signed) */
#define SOL_BPF_JMP_JSLE  0xd0   /* Jump if less or equal (signed) */

/*
 * Load/Store Sizes
 */
#define SOL_BPF_SIZE_W    0x00   /* Word (4 bytes) */
#define SOL_BPF_SIZE_H    0x08   /* Half word (2 bytes) */
#define SOL_BPF_SIZE_B    0x10   /* Byte */
#define SOL_BPF_SIZE_DW   0x18   /* Double word (8 bytes) */

/*
 * Source operand
 */
#define SOL_BPF_SRC_K     0x00   /* Immediate */
#define SOL_BPF_SRC_X     0x08   /* Register */

/*
 * Load modes
 */
#define SOL_BPF_MODE_IMM  0x00   /* Immediate */
#define SOL_BPF_MODE_ABS  0x20   /* Absolute */
#define SOL_BPF_MODE_IND  0x40   /* Indirect */
#define SOL_BPF_MODE_MEM  0x60   /* Memory */

/*
 * Opcode macros
 */
#define SOL_BPF_OP_CLASS(op)   ((op) & 0x07)
#define SOL_BPF_OP_SIZE(op)    ((op) & 0x18)
#define SOL_BPF_OP_MODE(op)    ((op) & 0xe0)
#define SOL_BPF_OP_CODE(op)    ((op) & 0xf0)
#define SOL_BPF_OP_SRC(op)     ((op) & 0x08)

/*
 * Opcode construction
 */
#define SOL_BPF_OP(cls, src, code)  ((cls) | (src) | (code))

/*
 * Common opcodes
 */
#define SOL_BPF_OP_ADD64_IMM   (SOL_BPF_CLASS_ALU64 | SOL_BPF_SRC_K | SOL_BPF_ALU_ADD)
#define SOL_BPF_OP_ADD64_REG   (SOL_BPF_CLASS_ALU64 | SOL_BPF_SRC_X | SOL_BPF_ALU_ADD)
#define SOL_BPF_OP_MOV64_IMM   (SOL_BPF_CLASS_ALU64 | SOL_BPF_SRC_K | SOL_BPF_ALU_MOV)
#define SOL_BPF_OP_MOV64_REG   (SOL_BPF_CLASS_ALU64 | SOL_BPF_SRC_X | SOL_BPF_ALU_MOV)
#define SOL_BPF_OP_EXIT        (SOL_BPF_CLASS_JMP | SOL_BPF_JMP_EXIT)
#define SOL_BPF_OP_CALL        (SOL_BPF_CLASS_JMP | SOL_BPF_JMP_CALL)
#define SOL_BPF_OP_LDDW        (SOL_BPF_CLASS_LD | SOL_BPF_SIZE_DW | SOL_BPF_MODE_IMM)

/*
 * BPF Instruction (8 bytes)
 */
typedef struct {
    uint8_t  opcode;    /* Operation code */
    uint8_t  regs;      /* dst:4 | src:4 */
    int16_t  offset;    /* Offset for jumps/memory access */
    int32_t  imm;       /* Immediate value */
} sol_bpf_insn_t;

#define SOL_BPF_INSN_DST(insn)  ((insn)->regs & 0x0f)
#define SOL_BPF_INSN_SRC(insn)  (((insn)->regs >> 4) & 0x0f)

/*
 * Forward declarations
 */
typedef struct sol_bpf_vm sol_bpf_vm_t;
typedef struct sol_bpf_program sol_bpf_program_t;

/*
 * Syscall name hashing (Murmur3 32-bit, seed 0)
 */
uint32_t sol_bpf_syscall_hash(const char* name);

/*
 * Syscall function signature
 *
 * Arguments passed in r1-r5, return value in r0
 */
typedef uint64_t (*sol_bpf_syscall_fn)(
    sol_bpf_vm_t* vm,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5
);

/*
 * Syscall definition
 */
typedef struct {
    const char*         name;
    uint32_t            hash;       /* murmur3 hash of name */
    sol_bpf_syscall_fn  handler;
} sol_bpf_syscall_t;

/*
 * Fast syscall lookup table entry (open addressing).
 *
 * Stores a pointer to the syscall definition so callers can access both
 * handler and name when needed.
 */
typedef struct {
    uint32_t         hash;
    sol_bpf_syscall_t* syscall; /* NULL => empty slot */
} sol_bpf_syscall_lut_entry_t;

/*
 * CPI account meta
 */
typedef struct {
    sol_pubkey_t    pubkey;
    bool            is_signer;
    bool            is_writable;
} sol_bpf_cpi_account_meta_t;

/*
 * CPI instruction
 */
typedef struct {
    sol_pubkey_t                        program_id;
    const sol_bpf_cpi_account_meta_t*   accounts;
    size_t                              account_count;
    const uint8_t*                      data;
    size_t                              data_len;
    uint64_t                            account_infos_ptr;
    uint64_t                            account_infos_len;
    bool                                account_infos_are_rust;
    /* Optional: pre-parsed account_infos pubkeys from the invoke syscall path.
     * When non-NULL, this avoids re-translating pubkey pointers in the CPI
     * dispatch path. Lifetime is the duration of the syscall handler call. */
    const sol_pubkey_t*                 account_infos_pubkeys;
} sol_bpf_cpi_instruction_t;

/*
 * CPI handler
 */
typedef sol_err_t (*sol_bpf_cpi_handler_t)(
    sol_bpf_vm_t* vm,
    const sol_bpf_cpi_instruction_t* instr
);

/*
 * Memory region kind
 */
typedef enum {
    SOL_BPF_REGION_LINEAR = 0,
    SOL_BPF_REGION_GAPPED = 1,
} sol_bpf_region_kind_t;

/*
 * Memory region
 */
typedef struct {
    uint64_t    vaddr;      /* Virtual address start */
    uint64_t    len;        /* Virtual length in bytes */
    uint8_t*    host_addr;  /* Host memory pointer (base) */
    bool        writable;   /* Write permission */

    /* For gapped regions: host_len describes the physical backing length,
     * elem_len is the mapped chunk length, and gap_len is the unmapped gap
     * inserted between chunks in the virtual address space. */
    sol_bpf_region_kind_t kind;
    uint64_t    host_len;
    uint64_t    elem_len;
    uint64_t    gap_len;
} sol_bpf_region_t;

/*
 * Memory mapping
 */
typedef struct {
    sol_bpf_region_t*   regions;
    size_t              region_count;
    size_t              region_cap;
    size_t              last_region_idx; /* Small cache for translate() hot path */
    /* Fast lookup for the canonical Solana SBPF regions keyed by (vaddr >> 32):
     *   1=program, 2=stack, 3=heap, 4=input.
     * Stored as region_index+1 so 0 means "unset". */
    uint16_t            fixed_region_idx[5];
} sol_bpf_memory_t;

/*
 * Call frame
 */
typedef struct {
    uint64_t    saved_regs[4];   /* r6-r9 */
    uint64_t    return_pc;        /* Return address */
    uint64_t    frame_ptr;        /* Saved r10 (frame pointer) */
} sol_bpf_frame_t;

/*
 * BPF Program
 */
struct sol_bpf_program {
    const sol_bpf_insn_t*   instructions;
    size_t                  insn_count;

    /* SBPF version (from ELF e_flags) */
    sol_sbpf_version_t      sbpf_version;

    /* Program section virtual addresses (ELF sh_addr) */
    uint64_t                text_vaddr;
    uint64_t                rodata_vaddr;
    uint64_t                data_rel_ro_vaddr;

    /* Function registry (for internal calls) */
    uint32_t*               function_registry;
    size_t                  function_count;

    /* Entry point */
    uint32_t                entry_pc;

    /* JIT compiled code (NULL if interpreted) */
    void*                   jit_code;
    size_t                  jit_code_len;

    /* Unified read-only section (matches Agave rbpf ro_section).
     * Zero-filled buffer from vaddr 0 to highest_addr, with .text,
     * .rodata, .data.rel.ro, and .eh_frame copied at their sh_addr
     * offsets.  Mapped as one contiguous region at MM_PROGRAM_START. */
    uint8_t*                ro_section;
    size_t                  ro_section_len;

    /* text_segment points into ro_section at text_vaddr offset (not separately allocated) */
    uint8_t*                text_segment;
    size_t                  text_len;
};

/*
 * VM execution state
 */
typedef enum {
    SOL_BPF_STATE_READY,
    SOL_BPF_STATE_RUNNING,
    SOL_BPF_STATE_STOPPED,
    SOL_BPF_STATE_ERROR
} sol_bpf_state_t;

/*
 * VM error codes
 */
typedef enum {
    SOL_BPF_OK = 0,
    SOL_BPF_ERR_DIVIDE_BY_ZERO,
    SOL_BPF_ERR_DIVIDE_OVERFLOW,
    SOL_BPF_ERR_INVALID_INSN,
    SOL_BPF_ERR_INVALID_MEMORY,
    SOL_BPF_ERR_STACK_OVERFLOW,
    SOL_BPF_ERR_CALL_DEPTH,
    SOL_BPF_ERR_CALL_OUTSIDE_TEXT,
    SOL_BPF_ERR_UNKNOWN_SYSCALL,
    SOL_BPF_ERR_SYSCALL_ERROR,
    SOL_BPF_ERR_COMPUTE_EXCEEDED,
    SOL_BPF_ERR_ACCESS_VIOLATION,
    SOL_BPF_ERR_JIT_NOT_COMPILED,
    SOL_BPF_ERR_ABORT,
} sol_bpf_error_t;

/*
 * BPF Virtual Machine
 */
struct sol_bpf_vm {
    /* Registers r0-r10 */
    uint64_t    reg[SOL_BPF_NUM_REGISTERS];

    /* Program counter */
    uint64_t    pc;

    /* Execution state */
    sol_bpf_state_t     state;
    sol_bpf_error_t     error;

    /* Call stack */
    sol_bpf_frame_t     call_stack[SOL_BPF_MAX_CALL_DEPTH];
    uint32_t            call_depth;

    /* Memory */
    sol_bpf_memory_t    memory;

    /* Stack memory */
    uint8_t*            stack;
    size_t              stack_size;
    size_t              stack_alloc_size; /* underlying allocation length (may be page-aligned) */
    uint64_t            stack_frame_size;
    uint64_t            stack_gap_size;
    uint64_t            stack_virt_size;
    bool                stack_is_mmap;    /* stack was allocated via mmap() */

    /* Heap memory */
    uint8_t*            heap;
    size_t              heap_size;
    size_t              heap_alloc_size;  /* underlying allocation length (may be page-aligned) */
    size_t              heap_pos;   /* Bump allocator position */
    bool                heap_is_mmap;     /* heap was allocated via mmap() */

    /* Program */
    sol_bpf_program_t*  program;

    /* Syscalls */
    sol_bpf_syscall_t*  syscalls;
    size_t              syscall_count;
    size_t              syscall_cap;
    sol_bpf_cpi_handler_t cpi_handler;

    /* Open-addressing lookup table for syscall hash -> syscall def. */
    sol_bpf_syscall_lut_entry_t* syscall_lut;
    size_t                       syscall_lut_cap;

    /* Compute budget */
    uint64_t            compute_units;
    uint64_t            compute_units_used;

    /* Instruction counter */
    uint64_t            insn_count;

    /* Fault metadata (best-effort). Populated on memory access violations. */
    uint64_t            fault_vaddr;
    uint64_t            fault_len;
    bool                fault_write;
    uint64_t            fault_pc;

    /* Context for syscalls */
    void*               context;

    /* Caller's serialized input buffer (for CPI writeback).
     * When a BPF program does CPI, the post-CPI update must write directly
     * to the serialized buffer (not through account_info pointers which may
     * point elsewhere). */
    uint8_t*            caller_input_buf;
    size_t              caller_input_len;
    const void*         caller_metas;       /* sol_sbf_account_meta_t* */
    size_t              caller_meta_count;

    /* Return value (after exit) */
    uint64_t            return_value;

    /* Instruction-level trace (debug only) */
    bool                trace;

    /* BPF Loader v1 (deprecated) flag.
     * When true, heap allocation uses alignment=1 (no alignment)
     * instead of BPF_ALIGN_OF_U128=8 for v2/upgradeable loaders. */
    bool                loader_deprecated;

    /* Optional counters (debug/perf). */
    uint64_t            syscall_exec_count;

    /* Monotonically increasing ID bumped on vm_reset(). Used to safely key
     * per-invocation syscall caches (e.g., CPI account_info decoding). */
    uint64_t            invocation_id;
};

/*
 * VM Configuration
 */
typedef struct {
    size_t      stack_size;
    size_t      heap_size;
    uint64_t    compute_units;
    bool        enable_jit;
} sol_bpf_config_t;

#define SOL_BPF_CONFIG_DEFAULT {            \
    .stack_size = SOL_BPF_STACK_SIZE,       \
    .heap_size = SOL_BPF_HEAP_SIZE,         \
    .compute_units = 200000,                \
    .enable_jit = true                      \
}

/*
 * Create a new VM
 */
sol_bpf_vm_t* sol_bpf_vm_new(const sol_bpf_config_t* config);

/*
 * Reset a VM for reuse without re-registering syscalls or reallocating
 * stack/heap.
 *
 * This is intended for high-throughput execution paths where creating a new
 * VM per invocation is too expensive. It preserves the syscall registry but
 * clears all execution state and resets memory mappings to stack+heap only.
 */
sol_err_t sol_bpf_vm_reset(sol_bpf_vm_t* vm, uint64_t compute_units);

/*
 * Destroy VM
 */
void sol_bpf_vm_destroy(sol_bpf_vm_t* vm);

/*
 * Load program into VM
 */
sol_err_t sol_bpf_vm_load(
    sol_bpf_vm_t* vm,
    const uint8_t* elf_data,
    size_t elf_len
);

/*
 * Load program from raw instructions (for testing)
 */
sol_err_t sol_bpf_vm_load_raw(
    sol_bpf_vm_t* vm,
    const sol_bpf_insn_t* insns,
    size_t insn_count
);

/*
 * Set input data
 */
sol_err_t sol_bpf_vm_set_input(
    sol_bpf_vm_t* vm,
    const uint8_t* data,
    size_t len
);

/*
 * Register a syscall
 */
sol_err_t sol_bpf_vm_register_syscall(
    sol_bpf_vm_t* vm,
    const char* name,
    sol_bpf_syscall_fn handler
);

/*
 * Set CPI handler
 */
void sol_bpf_vm_set_cpi_handler(sol_bpf_vm_t* vm, sol_bpf_cpi_handler_t handler);

/*
 * Set context for syscalls
 */
void sol_bpf_vm_set_context(sol_bpf_vm_t* vm, void* ctx);

/*
 * Execute program (interpreter)
 */
sol_err_t sol_bpf_vm_execute(sol_bpf_vm_t* vm);

/*
 * Execute program (JIT)
 */
sol_err_t sol_bpf_vm_execute_jit(sol_bpf_vm_t* vm);

/*
 * Get return value
 */
uint64_t sol_bpf_vm_return_value(const sol_bpf_vm_t* vm);

/*
 * Get compute units used
 */
uint64_t sol_bpf_vm_compute_used(const sol_bpf_vm_t* vm);

/*
 * Get error message
 */
const char* sol_bpf_error_str(sol_bpf_error_t err);

/*
 * Memory operations
 */
sol_err_t sol_bpf_memory_add_region(
    sol_bpf_memory_t* mem,
    uint64_t vaddr,
    uint8_t* host_addr,
    size_t len,
    bool writable
);

uint8_t* sol_bpf_memory_translate(
    sol_bpf_memory_t* mem,
    uint64_t vaddr,
    size_t len,
    bool write
);

/*
 * Heap allocation (bump allocator)
 */
uint64_t sol_bpf_heap_alloc(sol_bpf_vm_t* vm, size_t size, size_t align);

/*
 * Program functions
 */
sol_bpf_program_t* sol_bpf_program_new(void);
void sol_bpf_program_destroy(sol_bpf_program_t* prog);

/*
 * ELF loader
 */
sol_err_t sol_bpf_elf_load(
    sol_bpf_program_t* prog,
    const uint8_t* elf_data,
    size_t elf_len
);

/*
 * Verifier
 */
sol_err_t sol_bpf_verify(const sol_bpf_program_t* prog);

/*
 * JIT Compiler
 */
#if defined(__x86_64__) || defined(_M_X64)
#define SOL_BPF_JIT_SUPPORTED 1

sol_err_t sol_bpf_jit_compile(sol_bpf_vm_t* vm, void** code_out, size_t* code_len_out);
void sol_bpf_jit_free(sol_bpf_program_t* prog);
#else
#define SOL_BPF_JIT_SUPPORTED 0
#endif

/*
 * Instruction helpers
 */
static inline sol_bpf_insn_t
sol_bpf_insn(uint8_t op, uint8_t dst, uint8_t src, int16_t off, int32_t imm) {
    return (sol_bpf_insn_t){
        .opcode = op,
        .regs = (src << 4) | dst,
        .offset = off,
        .imm = imm
    };
}

#define SOL_BPF_MOV64_IMM(dst, imm) \
    sol_bpf_insn(SOL_BPF_OP_MOV64_IMM, dst, 0, 0, imm)

#define SOL_BPF_MOV64_REG(dst, src) \
    sol_bpf_insn(SOL_BPF_OP_MOV64_REG, dst, src, 0, 0)

#define SOL_BPF_ADD64_IMM(dst, imm) \
    sol_bpf_insn(SOL_BPF_OP_ADD64_IMM, dst, 0, 0, imm)

#define SOL_BPF_EXIT() \
    sol_bpf_insn(SOL_BPF_OP_EXIT, 0, 0, 0, 0)

#define SOL_BPF_CALL_IMM(imm) \
    sol_bpf_insn(SOL_BPF_OP_CALL, 0, 0, 0, imm)

/*
 * Register all Solana syscalls with the VM
 */
sol_err_t sol_bpf_register_syscalls(sol_bpf_vm_t* vm);

/*
 * Register CPI-related syscalls
 */
sol_err_t sol_bpf_register_cpi_syscalls(sol_bpf_vm_t* vm);

/*
 * CPI syscall handlers (for direct use)
 */
uint64_t sol_bpf_syscall_invoke_signed(
    sol_bpf_vm_t* vm,
    uint64_t instruction_ptr,
    uint64_t account_infos_ptr,
    uint64_t account_infos_len,
    uint64_t signers_seeds_ptr,
    uint64_t signers_seeds_len
);

#endif /* SOL_BPF_H */
