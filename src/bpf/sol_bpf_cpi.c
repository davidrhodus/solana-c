/*
 * sol_bpf_cpi.c - Cross-Program Invocation Implementation
 *
 * Implements the sol_invoke syscall for cross-program invocation,
 * allowing BPF programs to call other programs.
 */

#include "sol_bpf.h"
#include "../programs/sol_system_program.h"
#include "../crypto/sol_sha256.h"
#include "../crypto/sol_ed25519.h"
#include "../runtime/sol_compute_budget.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include "../txn/sol_pubkey.h"
#include <string.h>

static inline bool
consume_compute(sol_bpf_vm_t* vm, uint64_t units) {
    if (vm == NULL || units == 0) {
        return true;
    }

    if (vm->compute_units_used + units > vm->compute_units) {
        vm->compute_units_used = vm->compute_units;
        vm->error = SOL_BPF_ERR_COMPUTE_EXCEEDED;
        vm->state = SOL_BPF_STATE_ERROR;
        return false;
    }

    vm->compute_units_used += units;
    return true;
}

/*
 * Maximum CPI depth
 */
#define SOL_BPF_MAX_CPI_DEPTH   4

/*
 * Maximum instruction data size
 */
#define SOL_BPF_MAX_CPI_DATA    10240

/*
 * Max signer seeds for invoke_signed
 */
#define SOL_BPF_MAX_SIGNER_SEEDS    16

/*
 * Max seed length
 */
#define SOL_BPF_MAX_SEED_LEN        32

/*
 * Rust CPI AccountInfo layout (observed on mainnet, Agave v3.1.x):
 *   key: *const Pubkey (u64)
 *   lamports: Rc<RefCell<&mut u64>> (u64)
 *   data: Rc<RefCell<&mut [u8]>> (u64)
 *   owner: *const Pubkey (u64)
 *   rent_epoch: u64
 *   is_signer: bool (u8)
 *   is_writable: bool (u8)
 *   executable: bool (u8)
 *   padding[5]
 */
#define SOL_BPF_RUST_ACCOUNT_INFO_SIZE 48u

/*
 * Account info structure (as seen by BPF programs)
 *
 * This matches the Solana AccountInfo layout in memory:
 *   - pubkey: *const Pubkey (8 bytes)
 *   - lamports: *mut u64 (8 bytes)
 *   - data_len: u64 (8 bytes)
 *   - data: *mut u8 (8 bytes)
 *   - owner: *const Pubkey (8 bytes)
 *   - rent_epoch: u64 (8 bytes)
 *   - is_signer: bool (1 byte)
 *   - is_writable: bool (1 byte)
 *   - executable: bool (1 byte)
 */
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

/*
 * Read account info from VM memory
 */
static sol_err_t
read_account_info(
    sol_bpf_vm_t* vm,
    uint64_t account_info_ptr,
    sol_bpf_account_info_t* out
) {
    uint8_t* data = sol_bpf_memory_translate(
        &vm->memory, account_info_ptr, sizeof(sol_bpf_account_info_t), false
    );
    if (data == NULL) {
        return SOL_ERR_BPF_EXECUTE;
    }

    /* Read fields - handle alignment carefully */
    memcpy(&out->pubkey_ptr, data, 8);
    memcpy(&out->lamports_ptr, data + 8, 8);
    memcpy(&out->data_len, data + 16, 8);
    memcpy(&out->data_ptr, data + 24, 8);
    memcpy(&out->owner_ptr, data + 32, 8);
    memcpy(&out->rent_epoch, data + 40, 8);
    out->is_signer = data[48];
    out->is_writable = data[49];
    out->executable = data[50];

    return SOL_OK;
}

/*
 * Read instruction from VM memory (Rust syscall layout).
 *
 * BPF programs pass a StableInstruction struct (80 bytes, #[repr(C)]):
 *
 *   accounts: StableVec<AccountMeta>  (ptr u64 + cap u64 + len u64) offset 0
 *   data:     StableVec<u8>           (ptr u64 + cap u64 + len u64) offset 24
 *   program_id: Pubkey                (32 bytes)                    offset 48
 *
 * Older programs (pre-StableInstruction) may use the legacy Instruction layout
 * with Vec fields (ptr, cap, len order per Rust ABI):
 *
 *   program_id: Pubkey (32 bytes)                                   offset 0
 *   accounts: Vec<AccountMeta> (ptr u64 + cap u64 + len u64)       offset 32
 *   data:     Vec<u8>          (ptr u64 + cap u64 + len u64)       offset 56
 */
static sol_err_t
read_instruction_rust(
    sol_bpf_vm_t* vm,
    uint64_t instruction_ptr,
    sol_pubkey_t* program_id,
    uint64_t* accounts_ptr,
    uint64_t* accounts_len,
    uint64_t* data_ptr,
    uint64_t* data_len
) {
    if (!vm || !program_id || !accounts_ptr || !accounts_len || !data_ptr || !data_len) {
        return SOL_ERR_INVAL;
    }

    uint8_t* data80 = sol_bpf_memory_translate(&vm->memory, instruction_ptr, 80, false);
    if (data80 == NULL) {
        sol_log_debug("CPI: rust instruction translate failed instr_ptr=0x%lx",
                      (unsigned long)instruction_ptr);
        return SOL_ERR_BPF_EXECUTE;
    }

    /*
     * StableInstruction layout (primary, used by all current BPF programs):
     *   offset  0: accounts.ptr  (u64)
     *   offset  8: accounts.cap  (u64)
     *   offset 16: accounts.len  (u64)
     *   offset 24: data.ptr      (u64)
     *   offset 32: data.cap      (u64)
     *   offset 40: data.len      (u64)
     *   offset 48: program_id    (32 bytes)
     */
    sol_pubkey_t pid_stable = {0};
    uint64_t acc_ptr_stable = 0, acc_len_stable = 0;
    uint64_t dat_ptr_stable = 0, dat_len_stable = 0;

    memcpy(&acc_ptr_stable, data80 + 0,  8);
    memcpy(&acc_len_stable, data80 + 16, 8);  /* len at +16, NOT cap at +8 */
    memcpy(&dat_ptr_stable, data80 + 24, 8);
    memcpy(&dat_len_stable, data80 + 40, 8);  /* len at +40, NOT cap at +32 */
    memcpy(&pid_stable,     data80 + 48, 32);

    bool stable_ok = true;
    if (acc_len_stable > SOL_BPF_MAX_CPI_ACCOUNTS) stable_ok = false;
    if (dat_len_stable > SOL_BPF_MAX_CPI_DATA)     stable_ok = false;
    if (stable_ok && dat_len_stable > 0) {
        if (sol_bpf_memory_translate(&vm->memory, dat_ptr_stable, dat_len_stable, false) == NULL) {
            stable_ok = false;
        }
    }
    if (stable_ok && acc_len_stable > 0) {
        /* Verify accounts array is translatable (34 bytes per AccountMeta) */
        if (sol_bpf_memory_translate(&vm->memory, acc_ptr_stable, acc_len_stable * 34, false) == NULL) {
            stable_ok = false;
        }
    }

    /*
     * Legacy Instruction layout (older programs with Vec fields):
     *   offset  0: program_id    (32 bytes)
     *   offset 32: accounts.ptr  (u64)
     *   offset 40: accounts.cap  (u64)
     *   offset 48: accounts.len  (u64)
     *   offset 56: data.ptr      (u64)
     *   offset 64: data.cap      (u64)
     *   offset 72: data.len      (u64)
     */
    sol_pubkey_t pid_legacy = {0};
    uint64_t acc_ptr_legacy = 0, acc_len_legacy = 0;
    uint64_t dat_ptr_legacy = 0, dat_len_legacy = 0;

    memcpy(&pid_legacy,     data80 + 0,  32);
    memcpy(&acc_ptr_legacy, data80 + 32, 8);
    memcpy(&acc_len_legacy, data80 + 48, 8);  /* len at +48, NOT cap at +40 */
    memcpy(&dat_ptr_legacy, data80 + 56, 8);
    memcpy(&dat_len_legacy, data80 + 72, 8);  /* len at +72, NOT cap at +64 */

    bool legacy_ok = true;
    if (acc_len_legacy > SOL_BPF_MAX_CPI_ACCOUNTS) legacy_ok = false;
    if (dat_len_legacy > SOL_BPF_MAX_CPI_DATA)     legacy_ok = false;
    if (legacy_ok && dat_len_legacy > 0) {
        if (sol_bpf_memory_translate(&vm->memory, dat_ptr_legacy, dat_len_legacy, false) == NULL) {
            legacy_ok = false;
        }
    }
    if (legacy_ok && acc_len_legacy > 0) {
        if (sol_bpf_memory_translate(&vm->memory, acc_ptr_legacy, acc_len_legacy * 34, false) == NULL) {
            legacy_ok = false;
        }
    }

    /* Prefer StableInstruction (all current BPF programs use this) */
    if (stable_ok && !legacy_ok) {
        *program_id   = pid_stable;
        *accounts_ptr = acc_ptr_stable;
        *accounts_len = acc_len_stable;
        *data_ptr     = dat_ptr_stable;
        *data_len     = dat_len_stable;
        return SOL_OK;
    }

    if (legacy_ok && !stable_ok) {
        sol_log_debug("CPI: rust instruction ABI=legacy (program_id,accounts,data) instr_ptr=0x%lx",
                      (unsigned long)instruction_ptr);
        *program_id   = pid_legacy;
        *accounts_ptr = acc_ptr_legacy;
        *accounts_len = acc_len_legacy;
        *data_ptr     = dat_ptr_legacy;
        *data_len     = dat_len_legacy;
        return SOL_OK;
    }

    if (stable_ok && legacy_ok) {
        /* Both match — prefer stable (current ABI) */
        sol_log_debug("CPI: rust instruction ABI ambiguous (stable+legacy ok); using stable instr_ptr=0x%lx",
                      (unsigned long)instruction_ptr);
        *program_id   = pid_stable;
        *accounts_ptr = acc_ptr_stable;
        *accounts_len = acc_len_stable;
        *data_ptr     = dat_ptr_stable;
        *data_len     = dat_len_stable;
        return SOL_OK;
    }

    sol_log_debug("CPI: rust instruction parse failed (no ABI matched) instr_ptr=0x%lx "
                  "stable(acc_ptr=0x%lx acc_len=%lu data_ptr=0x%lx data_len=%lu) "
                  "legacy(acc_ptr=0x%lx acc_len=%lu data_ptr=0x%lx data_len=%lu)",
                  (unsigned long)instruction_ptr,
                  (unsigned long)acc_ptr_stable,
                  (unsigned long)acc_len_stable,
                  (unsigned long)dat_ptr_stable,
                  (unsigned long)dat_len_stable,
                  (unsigned long)acc_ptr_legacy,
                  (unsigned long)acc_len_legacy,
                  (unsigned long)dat_ptr_legacy,
                  (unsigned long)dat_len_legacy);
    return SOL_ERR_BPF_EXECUTE;
}

/*
 * Read instruction from VM memory (C syscall layout).
 *
 * SolInstruction layout in memory:
 *   - program_id_addr: u64
 *   - accounts_addr: u64
 *   - accounts_len: u64
 *   - data_addr: u64
 *   - data_len: u64
 */
static sol_err_t
read_instruction_c(
    sol_bpf_vm_t* vm,
    uint64_t instruction_ptr,
    sol_pubkey_t* program_id,
    uint64_t* accounts_ptr,
    uint64_t* accounts_len,
    uint64_t* data_ptr,
    uint64_t* data_len
) {
    if (!vm || !program_id || !accounts_ptr || !accounts_len || !data_ptr || !data_len) {
        return SOL_ERR_INVAL;
    }

    uint8_t* data = sol_bpf_memory_translate(&vm->memory, instruction_ptr, 40, false);
    if (data == NULL) {
        return SOL_ERR_BPF_EXECUTE;
    }

    uint64_t program_id_addr = 0;
    memcpy(&program_id_addr, data, 8);
    memcpy(accounts_ptr, data + 8, 8);
    memcpy(accounts_len, data + 16, 8);
    memcpy(data_ptr, data + 24, 8);
    memcpy(data_len, data + 32, 8);

    uint8_t* pid = sol_bpf_memory_translate(&vm->memory, program_id_addr, 32, false);
    if (pid == NULL) {
        return SOL_ERR_BPF_EXECUTE;
    }
    memcpy(program_id, pid, 32);
    return SOL_OK;
}

/*
 * Read account meta from VM memory (Rust syscall layout).
 *
 * AccountMeta layout:
 *   - pubkey: Pubkey (32 bytes)
 *   - is_signer: bool (1 byte)
 *   - is_writable: bool (1 byte)
 */
static sol_err_t
read_account_meta_rust(
    sol_bpf_vm_t* vm,
    uint64_t meta_ptr,
    sol_pubkey_t* pubkey,
    bool* is_signer,
    bool* is_writable
) {
    uint8_t* data = sol_bpf_memory_translate(
        &vm->memory, meta_ptr, 34, false
    );
    if (data == NULL) {
        return SOL_ERR_BPF_EXECUTE;
    }

    memcpy(pubkey, data, 32);
    *is_signer = data[32] != 0;
    *is_writable = data[33] != 0;

    return SOL_OK;
}

/*
 * Read account meta from VM memory (C syscall layout).
 *
 * SolAccountMeta layout:
 *   - pubkey_addr: u64
 *   - is_writable: bool (1 byte)
 *   - is_signer: bool (1 byte)
 *   - padding
 */
static sol_err_t
read_account_meta_c(
    sol_bpf_vm_t* vm,
    uint64_t meta_ptr,
    sol_pubkey_t* pubkey,
    bool* is_signer,
    bool* is_writable
) {
    if (!vm || !pubkey || !is_signer || !is_writable) {
        return SOL_ERR_INVAL;
    }

    uint8_t* data = sol_bpf_memory_translate(&vm->memory, meta_ptr, 16, false);
    if (data == NULL) {
        return SOL_ERR_BPF_EXECUTE;
    }

    uint64_t pubkey_addr = 0;
    memcpy(&pubkey_addr, data, 8);

    /* SolAccountMeta is_writable then is_signer. */
    *is_writable = data[8] != 0;
    *is_signer = data[9] != 0;

    uint8_t* pk = sol_bpf_memory_translate(&vm->memory, pubkey_addr, 32, false);
    if (pk == NULL) {
        return SOL_ERR_BPF_EXECUTE;
    }
    memcpy(pubkey, pk, 32);
    return SOL_OK;
}

static int
find_account_info_index(const sol_pubkey_t* infos, size_t count, const sol_pubkey_t* pubkey) {
    if (infos == NULL || pubkey == NULL) {
        return -1;
    }

    for (size_t i = 0; i < count; i++) {
        if (sol_pubkey_eq(&infos[i], pubkey)) {
            return (int)i;
        }
    }

    return -1;
}

static sol_err_t
derive_program_address(
    const sol_pubkey_t* program_id,
    const uint8_t* const* seeds,
    const size_t* seed_lens,
    size_t seed_count,
    sol_pubkey_t* out
) {
    if (!program_id || !out) {
        return SOL_ERR_INVAL;
    }

    sol_sha256_ctx_t ctx;
    sol_sha256_t hash;

    sol_sha256_init(&ctx);
    for (size_t i = 0; i < seed_count; i++) {
        if (seed_lens[i] > 0 && seeds[i] != NULL) {
            sol_sha256_update(&ctx, seeds[i], seed_lens[i]);
        }
    }
    sol_sha256_update(&ctx, program_id->bytes, 32);
    static const char PDA_MARKER[] = "ProgramDerivedAddress";
    sol_sha256_update(&ctx, PDA_MARKER, sizeof(PDA_MARKER) - 1);
    sol_sha256_final(&ctx, &hash);

    memcpy(out->bytes, hash.bytes, 32);

    if (sol_ed25519_pubkey_is_on_curve(out)) {
        return SOL_ERR_CRYPTO;
    }

    return SOL_OK;
}

static bool
is_pda_signer(
    sol_bpf_vm_t* vm,
    const sol_pubkey_t* program_id,
    uint64_t signers_seeds_ptr,
    uint64_t signers_seeds_len,
    const sol_pubkey_t* pubkey
) {
    if (vm == NULL || program_id == NULL || pubkey == NULL) {
        return false;
    }

    if (signers_seeds_len == 0) {
        return false;
    }

    if (signers_seeds_len > SOL_BPF_MAX_SIGNER_SEEDS) {
        sol_log_error("CPI: Too many signer seed sets");
        return false;
    }

    for (uint64_t i = 0; i < signers_seeds_len; i++) {
        uint8_t* seed_set = sol_bpf_memory_translate(
            &vm->memory, signers_seeds_ptr + i * 16, 16, false
        );
        if (seed_set == NULL) {
            return false;
        }

        uint64_t seeds_ptr = *(uint64_t*)seed_set;
        uint64_t seeds_len = *(uint64_t*)(seed_set + 8);

        if (seeds_len > SOL_BPF_MAX_SIGNER_SEEDS) {
            sol_log_error("CPI: Too many seeds in signer set");
            return false;
        }

        const uint8_t* seed_ptrs[SOL_BPF_MAX_SIGNER_SEEDS];
        size_t seed_lens[SOL_BPF_MAX_SIGNER_SEEDS];

        for (uint64_t j = 0; j < seeds_len; j++) {
            uint8_t* seed = sol_bpf_memory_translate(
                &vm->memory, seeds_ptr + j * 16, 16, false
            );
            if (seed == NULL) {
                return false;
            }

            uint64_t data_ptr = *(uint64_t*)seed;
            uint64_t data_len = *(uint64_t*)(seed + 8);

            if (data_len > SOL_BPF_MAX_SEED_LEN) {
                sol_log_error("CPI: Seed length too long");
                return false;
            }

            seed_lens[j] = (size_t)data_len;
            if (data_len > 0) {
                seed_ptrs[j] = sol_bpf_memory_translate(
                    &vm->memory, data_ptr, data_len, false
                );
                if (seed_ptrs[j] == NULL) {
                    return false;
                }
            } else {
                seed_ptrs[j] = NULL;
            }
        }

        sol_pubkey_t derived;
        if (derive_program_address(program_id, seed_ptrs, seed_lens, seeds_len, &derived) == SOL_OK) {
            if (sol_pubkey_eq(&derived, pubkey)) {
                return true;
            }
        }
    }

    return false;
}

/*
 * Syscall: sol_invoke_signed_c
 *
 * Cross-program invocation syscall.
 *
 * r1 = instruction pointer
 * r2 = account_infos pointer
 * r3 = account_infos length
 * r4 = signers_seeds pointer (for PDA signing)
 * r5 = signers_seeds length
 */
static uint64_t
sol_bpf_syscall_invoke_signed_impl(
    sol_bpf_vm_t* vm,
    uint64_t instruction_ptr,
    bool instruction_is_c,
    uint64_t account_infos_ptr,
    uint64_t account_infos_len,
    uint64_t signers_seeds_ptr,
    uint64_t signers_seeds_len
) {
    sol_invoke_context_t* ctx = (sol_invoke_context_t*)vm->context;
    if (ctx == NULL) {
        sol_log_error("CPI: No context");
        return 1;
    }

    /* Base invoke cost.
     * Pre-SIMD-0339: invoke_units = 1000 (DEFAULT_INVOCATION_COST).
     * SIMD-0339 (increase_cpi_account_info_limit) changes this to 946
     * but is NOT yet active on mainnet as of epoch 925. */
    if (!consume_compute(vm, 1000)) {
        return 1;
    }

    sol_err_t (*read_instruction_fn)(
        sol_bpf_vm_t*,
        uint64_t,
        sol_pubkey_t*,
        uint64_t*,
        uint64_t*,
        uint64_t*,
        uint64_t*) = instruction_is_c ? read_instruction_c : read_instruction_rust;

    sol_err_t (*read_meta_fn)(
        sol_bpf_vm_t*,
        uint64_t,
        sol_pubkey_t*,
        bool*,
        bool*) = instruction_is_c ? read_account_meta_c : read_account_meta_rust;

    const uint64_t meta_stride = instruction_is_c ? 16u : 34u;

    /* Check CPI depth.  Stack height starts at 1 for top-level.
     * Max invoke stack depth is SOL_BPF_MAX_CPI_DEPTH + 1 = 5
     * (Agave: MAX_INSTRUCTION_STACK_DEPTH = 5).
     * If we're already at stack_height > SOL_BPF_MAX_CPI_DEPTH, the
     * callee would exceed the limit. */
    if (ctx->stack_height > SOL_BPF_MAX_CPI_DEPTH) {
        sol_log_error("CPI: Maximum depth exceeded");
        return 1;
    }

    /* Validate account count.
     * Pre-SIMD-0339: MAX_CPI_ACCOUNT_INFOS = 128.
     * SIMD-0339 raises to 255, but is NOT active on mainnet. */
    if (account_infos_len > SOL_BPF_CPI_ACCOUNT_INFO_LIMIT) {
        sol_log_error("CPI: Too many accounts");
        return 1;
    }


    /* Read instruction */
    sol_pubkey_t program_id;
    uint64_t accounts_ptr, accounts_len, data_ptr, data_len;

    sol_err_t err = read_instruction_fn(vm, instruction_ptr,
                                        &program_id, &accounts_ptr, &accounts_len,
                                        &data_ptr, &data_len);
    if (err != SOL_OK) {
        sol_log_error("CPI: Failed to read instruction");
        sol_log_debug("CPI: read_instruction failed (abi=%s instr_ptr=0x%lx err=%d)",
                      instruction_is_c ? "c" : "rust",
                      (unsigned long)instruction_ptr,
                      (int)err);

        /* Best-effort dump of the instruction struct prefix to aid ABI debugging. */
        size_t dump_len = instruction_is_c ? 40u : 80u;
        uint8_t* raw = sol_bpf_memory_translate(&vm->memory, instruction_ptr, dump_len, false);
        if (raw == NULL && !instruction_is_c) {
            dump_len = 64u;
            raw = sol_bpf_memory_translate(&vm->memory, instruction_ptr, dump_len, false);
        }
        if (raw != NULL) {
            sol_log_hexdump(SOL_LOG_DEBUG, "CPI instr bytes", raw, dump_len);
        }
        return 1;
    }

    /* Validate data length */
    if (data_len > SOL_BPF_MAX_CPI_DATA) {
        sol_log_error("CPI: Instruction data too large");
        return 1;
    }

    /* Validate account meta count.
     * Pre-SIMD-0339: MAX_CPI_ACCOUNT_INFOS = 128.
     * SIMD-0339 raises to 255, but is NOT active on mainnet. */
    if (accounts_len > SOL_BPF_CPI_ACCOUNT_INFO_LIMIT) {
        sol_log_error("CPI: Too many account metas");
        return 1;
    }

    /* Note: account_infos_len can be less than accounts_len because
       the same account_info can satisfy multiple account_metas.
       The per-key lookup below handles this correctly. */

    /* Instruction data translation cost.
     * Pre-SIMD-0339 (loosen_cpi_size_restriction active): only data_len / 250.
     * SIMD-0339 adds account meta cost: (accounts_len * 34) / 250,
     * but is NOT active on mainnet as of epoch 925. */
    {
        uint64_t translate_cost = data_len / SOL_CU_CPI_BYTES_PER_UNIT;
        if (translate_cost > 0 && !consume_compute(vm, translate_cost)) {
            return 1;
        }
    }

    /* Read instruction data */
    uint8_t* instr_data = NULL;
    if (data_len > 0) {
        instr_data = sol_bpf_memory_translate(&vm->memory, data_ptr, data_len, false);
        if (instr_data == NULL) {
            sol_log_error("CPI: Failed to read instruction data");
            return 1;
        }
    }

    /* Read account infos for privilege validation */
    sol_pubkey_t info_pubkeys[SOL_BPF_MAX_CPI_ACCOUNTS];
    bool info_is_signer[SOL_BPF_MAX_CPI_ACCOUNTS];
    bool info_is_writable[SOL_BPF_MAX_CPI_ACCOUNTS];

    if (instruction_is_c) {
        for (uint64_t i = 0; i < account_infos_len; i++) {
            sol_bpf_account_info_t info;
            uint64_t info_addr = account_infos_ptr + i * (uint64_t)sizeof(sol_bpf_account_info_t);
            err = read_account_info(vm, info_addr, &info);
            if (err != SOL_OK) {
                sol_log_error("CPI: Failed to read account info %lu", (unsigned long)i);
                sol_log_debug("CPI: account_infos_ptr=0x%lx len=%lu stride=%zu failed_addr=0x%lx",
                              (unsigned long)account_infos_ptr,
                              (unsigned long)account_infos_len,
                              sizeof(sol_bpf_account_info_t),
                              (unsigned long)info_addr);

                size_t dump_len = 192u;
                uint8_t* base = sol_bpf_memory_translate(&vm->memory, account_infos_ptr, dump_len, false);
                if (base == NULL) {
                    dump_len = 64u;
                    base = sol_bpf_memory_translate(&vm->memory, account_infos_ptr, dump_len, false);
                }
                if (base != NULL) {
                    sol_log_hexdump(SOL_LOG_DEBUG, "CPI account_infos bytes", base, dump_len);
                }

                uint8_t* near = sol_bpf_memory_translate(&vm->memory, info_addr, 16, false);
                if (near != NULL) {
                    sol_log_hexdump(SOL_LOG_DEBUG, "CPI account_info bytes", near, 16);
                }
                return 1;
            }

            uint8_t* pubkey = sol_bpf_memory_translate(&vm->memory, info.pubkey_ptr, 32, false);
            if (pubkey == NULL) {
                sol_log_error("CPI: Failed to read account pubkey");
                return 1;
            }

            memcpy(&info_pubkeys[i], pubkey, 32);
            info_is_signer[i] = info.is_signer != 0;
            info_is_writable[i] = info.is_writable != 0;
        }
    } else {
        for (uint64_t i = 0; i < account_infos_len; i++) {
            uint64_t info_addr = account_infos_ptr + i * (uint64_t)SOL_BPF_RUST_ACCOUNT_INFO_SIZE;
            uint8_t* raw = sol_bpf_memory_translate(&vm->memory, info_addr, SOL_BPF_RUST_ACCOUNT_INFO_SIZE, false);
            if (raw == NULL) {
                sol_log_error("CPI: Failed to read rust account info %lu", (unsigned long)i);
                sol_log_debug("CPI: rust account_infos_ptr=0x%lx len=%lu stride=%u failed_addr=0x%lx",
                              (unsigned long)account_infos_ptr,
                              (unsigned long)account_infos_len,
                              (unsigned)SOL_BPF_RUST_ACCOUNT_INFO_SIZE,
                              (unsigned long)info_addr);
                return 1;
            }

            uint64_t key_ptr = 0;
            memcpy(&key_ptr, raw, 8);

            const uint8_t is_signer = raw[40];
            const uint8_t is_writable = raw[41];

            uint8_t* pubkey = sol_bpf_memory_translate(&vm->memory, key_ptr, 32, false);
            if (pubkey == NULL) {
                sol_log_error("CPI: Failed to read rust account pubkey");
                return 1;
            }

            memcpy(&info_pubkeys[i], pubkey, 32);
            info_is_signer[i] = is_signer != 0;
            info_is_writable[i] = is_writable != 0;
        }
    }

    /* Account info batch translation cost.
     * SIMD-0339 adds: (account_infos_len * 80) / 250, but is NOT active
     * on mainnet as of epoch 925. Pre-SIMD-0339: no batch charge here. */

    sol_bpf_cpi_account_meta_t metas[SOL_BPF_MAX_CPI_ACCOUNTS];

    /* Read account metas and verify privileges */
    for (uint64_t i = 0; i < accounts_len; i++) {
        sol_pubkey_t meta_pubkey;
        bool meta_is_signer, meta_is_writable;

        err = read_meta_fn(vm, accounts_ptr + i * meta_stride,
                           &meta_pubkey, &meta_is_signer, &meta_is_writable);
        if (err != SOL_OK) {
            sol_log_error("CPI: Failed to read account meta %lu accounts_ptr=0x%lx stride=%lu target=0x%lx abi=%s accounts_len=%lu data_ptr=0x%lx data_len=%lu",
                          (unsigned long)i,
                          (unsigned long)accounts_ptr,
                          (unsigned long)meta_stride,
                          (unsigned long)(accounts_ptr + i * meta_stride),
                          instruction_is_c ? "c" : "rust",
                          (unsigned long)accounts_len,
                          (unsigned long)data_ptr,
                          (unsigned long)data_len);
            /* Dump the raw instruction struct for ABI debugging */
            {
                uint8_t* raw80 = sol_bpf_memory_translate(&vm->memory, instruction_ptr, 80, false);
                if (raw80 != NULL) {
                    sol_log_hexdump(SOL_LOG_ERROR, "CPI instr raw 80B", raw80, 80);
                }
                /* Also try to dump what's at accounts_ptr */
                uint8_t* acc_raw = sol_bpf_memory_translate(&vm->memory, accounts_ptr, 64, false);
                if (acc_raw != NULL) {
                    sol_log_hexdump(SOL_LOG_ERROR, "CPI accounts_ptr 64B", acc_raw, 64);
                } else {
                    sol_log_error("CPI: accounts_ptr 0x%lx NOT translatable", (unsigned long)accounts_ptr);
                }
            }
            return 1;
        }

        metas[i].pubkey = meta_pubkey;
        metas[i].is_signer = meta_is_signer;
        metas[i].is_writable = meta_is_writable;

        int info_idx = find_account_info_index(info_pubkeys, account_infos_len, &meta_pubkey);
        if (info_idx < 0) {
            /* Agave allows executable accounts (programs) to be absent from
             * account_infos.  In translate_accounts_common, if an account is
             * executable it just charges CU for the program data size and
             * skips the account_info lookup entirely. */
            sol_account_t* acct = sol_bank_load_account(ctx->bank, &meta_pubkey);
            if (acct != NULL && acct->meta.executable) {
                /* CU charge for executable accounts is handled in
                 * sol_bpf_loader_cpi_dispatch (translate_accounts loop).
                 * Don't charge here to avoid double-charging. */
                sol_account_destroy(acct);
                continue; /* Skip privilege checks for executable accounts */
            }
            if (acct != NULL) {
                sol_account_destroy(acct);
            }
            sol_log_error("CPI: Missing account info for meta %lu", (unsigned long)i);
            return 1;
        }

        if (meta_is_writable && !info_is_writable[info_idx]) {
            sol_log_error("CPI: Writable privilege escalated");
            return 1;
        }

        /* If instruction requires signer, verify caller has authority */
        if (meta_is_signer) {
            bool authorized = info_is_signer[info_idx];

            /* Check if it's the calling program's PDA (signed via signers_seeds) */
            if (!authorized && signers_seeds_len > 0) {
                authorized = is_pda_signer(vm, &ctx->program_id,
                                           signers_seeds_ptr, signers_seeds_len,
                                           &meta_pubkey);
            }

            if (!authorized) {
                char b58[45];
                sol_pubkey_to_base58(&meta_pubkey, b58, sizeof(b58));
                sol_log_error("CPI: Missing signer privilege for %s", b58);
                return 1;
            }
        }
    }

    /* Log the CPI */
    {
        char prog_b58[45];
        sol_pubkey_to_base58(&program_id, prog_b58, sizeof(prog_b58));
        sol_log_debug("CPI: Invoking %s at stack_height %lu", prog_b58, (unsigned long)ctx->stack_height);
    }

    if (vm->cpi_handler != NULL) {
        sol_bpf_cpi_instruction_t call = {
            .program_id = program_id,
            .accounts = metas,
            .account_count = accounts_len,
            .data = instr_data,
            .data_len = data_len,
            .account_infos_ptr = account_infos_ptr,
            .account_infos_len = account_infos_len,
            .account_infos_are_rust = !instruction_is_c,
        };

        sol_err_t cpi_err = vm->cpi_handler(vm, &call);
        if (cpi_err != SOL_OK) {
            /*
             * Match Agave behavior: CPI failure halts the caller VM.
             * In Agave's rbpf, when cpi_common returns Err(InstructionError),
             * the error is stored in vm.program_result as EbpfError::SyscallError
             * and the interpreter immediately stops (returns false from step()).
             * The caller program does NOT get a chance to handle the error.
             */
            vm->error = SOL_BPF_ERR_SYSCALL_ERROR;
            vm->state = SOL_BPF_STATE_ERROR;
            return 1;
        }

        return 0;
    }

    /* No CPI handler installed. In production this should always be set by the
     * BPF loader to bridge into native/BPF program dispatch.
     *
     * Returning success here would let contracts "succeed" without actually
     * invoking the callee, which breaks consensus determinism. */
    char prog_b58[45];
    sol_pubkey_to_base58(&program_id, prog_b58, sizeof(prog_b58));
    sol_log_error("CPI: Missing CPI handler (cannot invoke %s)", prog_b58);
    (void)signers_seeds_ptr;
    (void)instr_data;
    return 1;
}

uint64_t
sol_bpf_syscall_invoke_signed(
    sol_bpf_vm_t* vm,
    uint64_t instruction_ptr,
    uint64_t account_infos_ptr,
    uint64_t account_infos_len,
    uint64_t signers_seeds_ptr,
    uint64_t signers_seeds_len
) {
    /* C syscall layout (SolInstruction + SolAccountMeta). */
    return sol_bpf_syscall_invoke_signed_impl(vm,
                                              instruction_ptr,
                                              true,
                                              account_infos_ptr,
                                              account_infos_len,
                                              signers_seeds_ptr,
                                              signers_seeds_len);
}

/*
 * Syscall: sol_invoke_signed_rust
 *
 * Same as sol_invoke_signed_c but with Rust-style arguments.
 * This is kept for compatibility.
 */
uint64_t
sol_bpf_syscall_invoke_signed_rust(
	sol_bpf_vm_t* vm,
	uint64_t instruction_ptr,
	uint64_t account_infos_ptr,
	uint64_t account_infos_len,
	uint64_t signers_seeds_ptr,
	uint64_t signers_seeds_len
) {
    /* Rust syscall layout (StableInstruction + AccountMeta). */
    return sol_bpf_syscall_invoke_signed_impl(vm,
                                              instruction_ptr,
                                              false,
                                              account_infos_ptr,
                                              account_infos_len,
                                              signers_seeds_ptr,
                                              signers_seeds_len);
}

/*
 * Syscall: sol_set_return_data
 *
 * Sets return data that can be read by the caller.
 *
 * r1 = data pointer
 * r2 = data length
 */
uint64_t
sol_bpf_syscall_set_return_data(
    sol_bpf_vm_t* vm,
    uint64_t data_ptr,
    uint64_t data_len,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5
) {
    (void)arg3; (void)arg4; (void)arg5;

    sol_invoke_context_t* ctx = (sol_invoke_context_t*)vm->context;
    if (ctx == NULL) {
        sol_log_error("Return data: No context");
        return 1;
    }

    /* Agave: set_return_data charges len/cpi_bytes_per_unit + syscall_base_cost */
    {
        uint64_t cost = data_len / SOL_CU_CPI_BYTES_PER_UNIT + SOL_CU_SYSCALL_BASE;
        if (!consume_compute(vm, cost)) {
            return 1;
        }
    }

    if (data_len > SOL_MAX_RETURN_DATA) {
        sol_log_error("Return data too large");
        return 1;
    }

    if (data_len == 0) {
        ctx->return_data_len = 0;
        memset(&ctx->return_data_program, 0, sizeof(sol_pubkey_t));
        return 0;
    }

    uint8_t* data = sol_bpf_memory_translate(&vm->memory, data_ptr, data_len, false);
    if (data == NULL) {
        return 1;
    }

    memcpy(ctx->return_data, data, data_len);
    ctx->return_data_len = (uint16_t)data_len;
    ctx->return_data_program = ctx->program_id;
    sol_log_debug("Program set %lu bytes of return data", (unsigned long)data_len);

    return 0;
}

/*
 * Syscall: sol_get_return_data
 *
 * Gets return data from the last CPI.
 *
 * r1 = data buffer pointer
 * r2 = data buffer length
 * r3 = program_id output pointer
 */
uint64_t
sol_bpf_syscall_get_return_data(
    sol_bpf_vm_t* vm,
    uint64_t data_ptr,
    uint64_t data_len,
    uint64_t program_id_ptr,
    uint64_t arg4,
    uint64_t arg5
) {
    (void)arg4; (void)arg5;

    sol_invoke_context_t* ctx = (sol_invoke_context_t*)vm->context;
    if (ctx == NULL) {
        return 0;
    }

    /* Agave: get_return_data first charges syscall_base_cost */
    if (!consume_compute(vm, SOL_CU_SYSCALL_BASE)) {
        return 0;
    }

    size_t available = ctx->return_data_len;
    size_t copy_len = data_len < available ? data_len : available;

    /* Agave: if length != 0, charges (length + sizeof(Pubkey)) / cpi_bytes_per_unit */
    if (copy_len > 0) {
        uint64_t cost = ((uint64_t)copy_len + 32) / SOL_CU_CPI_BYTES_PER_UNIT;
        if (!consume_compute(vm, cost)) {
            return 0;
        }
    }

    if (data_ptr != 0 && copy_len > 0) {
        uint8_t* out = sol_bpf_memory_translate(&vm->memory, data_ptr, copy_len, true);
        if (out == NULL) {
            return 0;
        }
        memcpy(out, ctx->return_data, copy_len);
    }

    if (program_id_ptr != 0) {
        uint8_t* prog_id = sol_bpf_memory_translate(&vm->memory, program_id_ptr, 32, true);
        if (prog_id != NULL) {
            memcpy(prog_id, ctx->return_data_program.bytes, 32);
        }
    }

    return available;  /* Return data length */
}

/*
 * Syscall: sol_get_stack_height
 *
 * Returns the current CPI stack height.
 */
uint64_t
sol_bpf_syscall_get_stack_height(
    sol_bpf_vm_t* vm,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5
) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;

    if (!consume_compute(vm, SOL_CU_SYSCALL_BASE)) {
        return 0;
    }

    sol_invoke_context_t* ctx = (sol_invoke_context_t*)vm->context;
    if (ctx == NULL) {
        return 0;
    }

    return ctx->stack_height ? ctx->stack_height : 1;
}

/*
 * Register CPI-related syscalls
 */
sol_err_t
sol_bpf_register_cpi_syscalls(sol_bpf_vm_t* vm) {
    if (vm == NULL) {
        return SOL_ERR_INVAL;
    }

    sol_err_t err;

    err = sol_bpf_vm_register_syscall(vm, "sol_invoke_signed_c",
                                      sol_bpf_syscall_invoke_signed);
    if (err != SOL_OK) return err;

    err = sol_bpf_vm_register_syscall(vm, "sol_invoke_signed_rust",
                                      sol_bpf_syscall_invoke_signed_rust);
    if (err != SOL_OK) return err;

    err = sol_bpf_vm_register_syscall(vm, "sol_set_return_data",
                                      sol_bpf_syscall_set_return_data);
    if (err != SOL_OK) return err;

    err = sol_bpf_vm_register_syscall(vm, "sol_get_return_data",
                                      sol_bpf_syscall_get_return_data);
    if (err != SOL_OK) return err;

    err = sol_bpf_vm_register_syscall(vm, "sol_get_stack_height",
                                      sol_bpf_syscall_get_stack_height);
    if (err != SOL_OK) return err;

    return SOL_OK;
}
