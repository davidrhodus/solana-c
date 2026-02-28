/*
 * sol_bpf_syscall.c - BPF Syscall Implementations
 *
 * Implements the Solana BPF syscall interface for on-chain programs.
 * These syscalls allow programs to interact with the Solana runtime.
 */

#include "sol_bpf.h"
#include "../programs/sol_system_program.h"
#include "../runtime/sol_sysvar.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include "../crypto/sol_sha256.h"
#include "../crypto/sol_blake3.h"
#include "../crypto/sol_keccak256.h"
#include "../crypto/sol_ed25519.h"
#include "../crypto/sol_secp256k1.h"
#include "../runtime/sol_compute_budget.h"
#include "../txn/sol_pubkey.h"
#include <string.h>
#include <stdio.h>
#if SOL_USE_LIBSODIUM
#include <sodium.h>
#endif
#if SOL_USE_OPENSSL
#include <openssl/bn.h>
#endif

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
 * Syscall: sol_log_
 *
 * Logs a message from the program.
 * r1 = pointer to message
 * r2 = message length
 */
static uint64_t
syscall_sol_log(
    sol_bpf_vm_t* vm,
    uint64_t msg_ptr,
    uint64_t msg_len,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5
) {
    (void)arg3; (void)arg4; (void)arg5;

    if (msg_len > 32 * 1024) {
        msg_len = 32 * 1024;  /* Cap at 32KB */
    }

    /* Agave formula: max(syscall_base_cost, msg_len) */
    {
        uint64_t log_cost = msg_len > SOL_CU_SYSCALL_BASE ? msg_len : SOL_CU_SYSCALL_BASE;
        if (!consume_compute(vm, log_cost)) {
            return 1;
        }
    }

    if (msg_len == 0) {
        return 0;
    }

    uint8_t* msg = sol_bpf_memory_translate(&vm->memory, msg_ptr, msg_len, false);
    if (msg == NULL) {
        return 1;  /* Access violation */
    }

    /* Log the message (debug to avoid overwhelming replay logs) */
    sol_log_debug("Program log: %.*s", (int)msg_len, msg);

    return 0;
}

/*
 * Syscall: sol_log_64_
 *
 * Logs 5 u64 values (for debugging).
 */
static uint64_t
syscall_sol_log_64(
    sol_bpf_vm_t* vm,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5
) {
    if (!consume_compute(vm, SOL_CU_LOG_BASE)) {
        return 1;
    }

    sol_log_debug("Program log: %lu %lu %lu %lu %lu",
                 (unsigned long)arg1, (unsigned long)arg2,
                 (unsigned long)arg3, (unsigned long)arg4,
                 (unsigned long)arg5);

    return 0;
}

/*
 * Syscall: sol_log_pubkey
 *
 * Logs a pubkey in base58.
 */
static uint64_t
syscall_sol_log_pubkey(
    sol_bpf_vm_t* vm,
    uint64_t pubkey_ptr,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5
) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;

    if (!consume_compute(vm, SOL_CU_LOG_BASE)) {
        return 1;
    }

    uint8_t* pubkey = sol_bpf_memory_translate(&vm->memory, pubkey_ptr, 32, false);
    if (pubkey == NULL) {
        return 1;
    }

    char b58[45];
    sol_pubkey_t pk;
    memcpy(&pk, pubkey, 32);
    sol_pubkey_to_base58(&pk, b58, sizeof(b58));

    sol_log_debug("Program log: %s", b58);

    return 0;
}

/*
 * Syscall: sol_log_compute_units_
 *
 * Logs remaining compute units.
 */
static uint64_t
syscall_sol_log_compute_units(
    sol_bpf_vm_t* vm,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5
) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;

    if (!consume_compute(vm, SOL_CU_LOG_BASE)) {
        return 1;
    }

    uint64_t remaining = vm->compute_units - vm->compute_units_used;
    sol_log_debug("Program log: %lu compute units remaining",
                 (unsigned long)remaining);

    return 0;
}

/*
 * Syscall: sol_log_data
 *
 * Logs data slices in a debug-friendly hex format.
 * r1 = pointer to array of byte slices
 * r2 = number of slices
 */
static uint64_t
syscall_sol_log_data(
    sol_bpf_vm_t* vm,
    uint64_t vals_ptr,
    uint64_t vals_len,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5
) {
    (void)arg3; (void)arg4; (void)arg5;

    if (vals_len > 20) {
        return 1;
    }

    /* Estimate total bytes for compute charging */
    uint64_t total_len = 0;
    for (uint64_t i = 0; i < vals_len; i++) {
        uint8_t* slice = sol_bpf_memory_translate(
            &vm->memory, vals_ptr + i * 16, 16, false);
        if (slice == NULL) {
            return 1;
        }
        uint64_t data_len = *(uint64_t*)(slice + 8);
        total_len += data_len;
    }

    /* Agave formula: syscall_base_cost + syscall_base_cost * num_fields + total_bytes */
    if (!consume_compute(vm, SOL_CU_SYSCALL_BASE + SOL_CU_SYSCALL_BASE * vals_len + total_len)) {
        return 1;
    }

    char buf[2048];

    for (uint64_t i = 0; i < vals_len; i++) {
        uint8_t* slice = sol_bpf_memory_translate(
            &vm->memory, vals_ptr + i * 16, 16, false);
        if (slice == NULL) {
            return 1;
        }

        uint64_t data_ptr = *(uint64_t*)slice;
        uint64_t data_len = *(uint64_t*)(slice + 8);

        if (data_len == 0) {
            sol_log_debug("Program data: <empty>");
            continue;
        }

        uint8_t* data = sol_bpf_memory_translate(
            &vm->memory, data_ptr, data_len, false);
        if (data == NULL) {
            return 1;
        }

        size_t out = 0;
        out += (size_t)snprintf(buf + out, sizeof(buf) - out, "Program data: ");
        for (uint64_t j = 0; j < data_len && out + 2 < sizeof(buf); j++) {
            out += (size_t)snprintf(buf + out, sizeof(buf) - out, "%02x", data[j]);
        }
        sol_log_debug("%s", buf);
    }

    return 0;
}

/*
 * Syscall: sol_sha256
 *
 * Computes SHA256 hash.
 * r1 = pointer to array of byte slices
 * r2 = number of slices
 * r3 = output hash pointer (32 bytes)
 */
static uint64_t
syscall_sol_sha256(
    sol_bpf_vm_t* vm,
    uint64_t vals_ptr,
    uint64_t vals_len,
    uint64_t result_ptr,
    uint64_t arg4,
    uint64_t arg5
) {
    (void)arg4; (void)arg5;

    if (vals_len > SOL_CU_HASH_MAX_SLICES) {
        return 1;  /* Too many slices */
    }

    /* Charge base cost upfront (Agave: sha256_base_cost = 85) */
    if (!consume_compute(vm, SOL_CU_HASH_BASE)) {
        return 1;
    }

    /* Translate result pointer */
    uint8_t* result = sol_bpf_memory_translate(&vm->memory, result_ptr, 32, true);
    if (result == NULL) {
        return 1;
    }

    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);

    /* Process each slice, charging per-slice CU (Agave formula) */
    for (uint64_t i = 0; i < vals_len; i++) {
        /* Each slice is (ptr, len) = 16 bytes */
        uint8_t* slice = sol_bpf_memory_translate(
            &vm->memory, vals_ptr + i * 16, 16, false);
        if (slice == NULL) {
            return 1;
        }

        uint64_t data_ptr = *(uint64_t*)slice;
        uint64_t data_len = *(uint64_t*)(slice + 8);

        /* Per-slice cost: max(mem_op_base, byte_cost * slice_len / 2) */
        uint64_t slice_cost = SOL_CU_HASH_BYTE_COST * (data_len / 2);
        if (slice_cost < SOL_CU_MEM_OP_BASE) slice_cost = SOL_CU_MEM_OP_BASE;
        if (!consume_compute(vm, slice_cost)) {
            return 1;
        }

        if (data_len > 0) {
            uint8_t* data = sol_bpf_memory_translate(
                &vm->memory, data_ptr, data_len, false);
            if (data == NULL) {
                return 1;
            }
            sol_sha256_update(&ctx, data, data_len);
        }
    }

    sol_sha256_t hash;
    sol_sha256_final(&ctx, &hash);
    memcpy(result, hash.bytes, 32);

    return 0;
}

/*
 * Syscall: sol_keccak256
 *
 * Computes Keccak256 hash.
 */
static uint64_t
syscall_sol_keccak256(
    sol_bpf_vm_t* vm,
    uint64_t vals_ptr,
    uint64_t vals_len,
    uint64_t result_ptr,
    uint64_t arg4,
    uint64_t arg5
) {
    (void)arg4; (void)arg5;

    if (vals_len > SOL_CU_HASH_MAX_SLICES) {
        return 1;
    }

    /* Agave: Keccak256 uses the SAME cost constants as SHA256 */
    if (!consume_compute(vm, SOL_CU_HASH_BASE)) {
        return 1;
    }

    uint8_t* result = sol_bpf_memory_translate(&vm->memory, result_ptr, 32, true);
    if (result == NULL) {
        return 1;
    }

    sol_keccak256_ctx_t ctx;
    sol_keccak256_init(&ctx);

    for (uint64_t i = 0; i < vals_len; i++) {
        uint8_t* slice = sol_bpf_memory_translate(
            &vm->memory, vals_ptr + i * 16, 16, false);
        if (slice == NULL) {
            return 1;
        }

        uint64_t data_ptr = *(uint64_t*)slice;
        uint64_t data_len = *(uint64_t*)(slice + 8);

        /* Per-slice cost: max(mem_op_base, byte_cost * slice_len / 2) */
        uint64_t slice_cost = SOL_CU_HASH_BYTE_COST * (data_len / 2);
        if (slice_cost < SOL_CU_MEM_OP_BASE) slice_cost = SOL_CU_MEM_OP_BASE;
        if (!consume_compute(vm, slice_cost)) {
            return 1;
        }

        if (data_len > 0) {
            uint8_t* data = sol_bpf_memory_translate(
                &vm->memory, data_ptr, data_len, false);
            if (data == NULL) {
                return 1;
            }
            sol_keccak256_update(&ctx, data, data_len);
        }
    }

    sol_keccak256_t hash;
    sol_keccak256_final(&ctx, &hash);
    memcpy(result, hash.bytes, 32);

    return 0;
}

/*
 * Syscall: sol_blake3
 *
 * Computes BLAKE3 hash.
 */
static uint64_t
syscall_sol_blake3(
    sol_bpf_vm_t* vm,
    uint64_t vals_ptr,
    uint64_t vals_len,
    uint64_t result_ptr,
    uint64_t arg4,
    uint64_t arg5
) {
    (void)arg4; (void)arg5;

    if (vals_len > SOL_CU_HASH_MAX_SLICES) {
        return 1;
    }

    /* Agave: BLAKE3 uses the SAME cost constants as SHA256 */
    if (!consume_compute(vm, SOL_CU_HASH_BASE)) {
        return 1;
    }

    uint8_t* result = sol_bpf_memory_translate(&vm->memory, result_ptr, 32, true);
    if (result == NULL) {
        return 1;
    }

    sol_blake3_ctx_t ctx;
    sol_blake3_init(&ctx);

    for (uint64_t i = 0; i < vals_len; i++) {
        uint8_t* slice = sol_bpf_memory_translate(
            &vm->memory, vals_ptr + i * 16, 16, false);
        if (slice == NULL) {
            return 1;
        }

        uint64_t data_ptr = *(uint64_t*)slice;
        uint64_t data_len = *(uint64_t*)(slice + 8);

        /* Per-slice cost: max(mem_op_base, byte_cost * slice_len / 2) */
        uint64_t slice_cost = SOL_CU_HASH_BYTE_COST * (data_len / 2);
        if (slice_cost < SOL_CU_MEM_OP_BASE) slice_cost = SOL_CU_MEM_OP_BASE;
        if (!consume_compute(vm, slice_cost)) {
            return 1;
        }

        if (data_len > 0) {
            uint8_t* data = sol_bpf_memory_translate(
                &vm->memory, data_ptr, data_len, false);
            if (data == NULL) {
                return 1;
            }
            sol_blake3_update(&ctx, data, data_len);
        }
    }

    sol_blake3_t hash;
    sol_blake3_final(&ctx, &hash);
    memcpy(result, hash.bytes, 32);

    return 0;
}

/*
 * Syscall: sol_create_program_address
 *
 * Creates a program derived address (PDA).
 * r1 = seeds array pointer
 * r2 = seeds count
 * r3 = program_id pointer
 * r4 = result address pointer
 */
static sol_err_t
derive_program_address(
    const sol_pubkey_t* program_id,
    const uint8_t* const* seeds,
    const size_t* seed_lens,
    size_t seed_count,
    sol_pubkey_t* out
) {
    if (program_id == NULL || out == NULL) {
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

static uint64_t
syscall_sol_create_program_address(
    sol_bpf_vm_t* vm,
    uint64_t seeds_ptr,
    uint64_t seeds_len,
    uint64_t program_id_ptr,
    uint64_t result_ptr,
    uint64_t arg5
) {
    (void)arg5;

    if (seeds_len > 16) {
        return 1;  /* Too many seeds */
    }

    if (!consume_compute(vm, SOL_CU_CREATE_PROGRAM_ADDRESS)) {
        return 1;
    }

    /* Translate pointers */
    uint8_t* program_id = sol_bpf_memory_translate(
        &vm->memory, program_id_ptr, 32, false);
    if (program_id == NULL) {
        return 1;
    }

    uint8_t* result = sol_bpf_memory_translate(
        &vm->memory, result_ptr, 32, true);
    if (result == NULL) {
        return 1;
    }

    /* Collect seeds */
    const uint8_t* seed_ptrs[16];
    size_t seed_lens[16];

    for (uint64_t i = 0; i < seeds_len; i++) {
        uint8_t* slice = sol_bpf_memory_translate(
            &vm->memory, seeds_ptr + i * 16, 16, false);
        if (slice == NULL) {
            return 1;
        }

        uint64_t data_ptr = *(uint64_t*)slice;
        uint64_t data_len = *(uint64_t*)(slice + 8);

        if (data_len > 32) {
            return 2;  /* Seed too long */
        }

        seed_lens[i] = (size_t)data_len;
        if (data_len > 0) {
            seed_ptrs[i] = sol_bpf_memory_translate(
                &vm->memory, data_ptr, data_len, false);
            if (seed_ptrs[i] == NULL) {
                return 1;
            }
        } else {
            seed_ptrs[i] = NULL;
        }
    }

    /* Create PDA */
    sol_pubkey_t prog_id;
    memcpy(&prog_id, program_id, 32);

    sol_pubkey_t pda;
    if (derive_program_address(&prog_id, seed_ptrs, seed_lens, seeds_len, &pda) != SOL_OK) {
        return 1; /* Failed to create PDA */
    }

    memcpy(result, pda.bytes, 32);
    return 0;
}

/*
 * Syscall: sol_try_find_program_address
 *
 * Finds a valid program address with bump seed.
 * r1 = seeds array pointer
 * r2 = seeds count
 * r3 = program_id pointer
 * r4 = result address pointer
 * r5 = result bump pointer
 */
static uint64_t
syscall_sol_try_find_program_address(
    sol_bpf_vm_t* vm,
    uint64_t seeds_ptr,
    uint64_t seeds_len,
    uint64_t program_id_ptr,
    uint64_t result_ptr,
    uint64_t bump_ptr
) {
    if (seeds_len > 16) {
        return 1;
    }

    /* Translate pointers */
    uint8_t* program_id = sol_bpf_memory_translate(
        &vm->memory, program_id_ptr, 32, false);
    if (program_id == NULL) {
        return 1;
    }

    uint8_t* result = sol_bpf_memory_translate(
        &vm->memory, result_ptr, 32, true);
    if (result == NULL) {
        return 1;
    }

    uint8_t* bump = sol_bpf_memory_translate(
        &vm->memory, bump_ptr, 1, true);
    if (bump == NULL) {
        return 1;
    }

    /* Collect seeds */
    const uint8_t* seed_ptrs[16];
    size_t seed_lens[16];

    for (uint64_t i = 0; i < seeds_len; i++) {
        uint8_t* slice = sol_bpf_memory_translate(
            &vm->memory, seeds_ptr + i * 16, 16, false);
        if (slice == NULL) {
            return 1;
        }

        uint64_t data_ptr = *(uint64_t*)slice;
        uint64_t data_len = *(uint64_t*)(slice + 8);

        if (data_len > 32) {
            return 2;
        }

        seed_lens[i] = (size_t)data_len;
        if (data_len > 0) {
            seed_ptrs[i] = sol_bpf_memory_translate(
                &vm->memory, data_ptr, data_len, false);
            if (seed_ptrs[i] == NULL) {
                return 1;
            }
        } else {
            seed_ptrs[i] = NULL;
        }
    }

    /* Find PDA - charge CU per bump iteration (matching Agave) */
    sol_pubkey_t prog_id;
    memcpy(&prog_id, program_id, 32);

    sol_pubkey_t pda;
    bool found = false;
    uint8_t bump_seed = 0;

    /* Fast path: hash seeds once, then clone the SHA256 state per bump attempt. */
    sol_sha256_ctx_t base_ctx;
    sol_sha256_init(&base_ctx);
    for (size_t i = 0; i < (size_t)seeds_len; i++) {
        sol_sha256_update(&base_ctx, seed_ptrs[i], seed_lens[i]);
    }
    static const char PDA_MARKER[] = "ProgramDerivedAddress";

    for (int b = 255; b >= 0; b--) {
        if (!consume_compute(vm, SOL_CU_CREATE_PROGRAM_ADDRESS)) {
            return 1;
        }

        sol_sha256_ctx_t ctx = base_ctx;
        sol_sha256_t hash;
        uint8_t bump_byte = (uint8_t)b;

        /* Hash: seeds || bump || program_id || "ProgramDerivedAddress" */
        sol_sha256_update(&ctx, &bump_byte, 1);
        sol_sha256_update(&ctx, prog_id.bytes, 32);
        sol_sha256_update(&ctx, PDA_MARKER, sizeof(PDA_MARKER) - 1);
        sol_sha256_final(&ctx, &hash);

        memcpy(pda.bytes, hash.bytes, 32);
        if (!sol_ed25519_pubkey_is_on_curve(&pda)) {
            bump_seed = (uint8_t)b;
            found = true;
            break;
        }
    }

    if (!found) {
        return 1;
    }

    memcpy(result, pda.bytes, 32);
    *bump = bump_seed;

    return 0;
}

/*
 * Syscall: sol_memcpy_
 *
 * Memory copy (non-overlapping).
 */
static uint64_t
syscall_sol_memcpy(
    sol_bpf_vm_t* vm,
    uint64_t dst_ptr,
    uint64_t src_ptr,
    uint64_t len,
    uint64_t arg4,
    uint64_t arg5
) {
    (void)arg4; (void)arg5;

    /* Agave formula: max(mem_op_base, len / cpi_bytes_per_unit) */
    {
        uint64_t cost = len / SOL_CU_CPI_BYTES_PER_UNIT;
        if (cost < SOL_CU_MEM_OP_BASE) cost = SOL_CU_MEM_OP_BASE;
        if (!consume_compute(vm, cost)) {
            return 1;
        }
    }

    if (len == 0) {
        return 0;
    }

    uint8_t* dst = sol_bpf_memory_translate(&vm->memory, dst_ptr, len, true);
    if (dst == NULL) {
        return 1;
    }

    uint8_t* src = sol_bpf_memory_translate(&vm->memory, src_ptr, len, false);
    if (src == NULL) {
        return 1;
    }

    /* Check for overlap (undefined behavior in memcpy) */
    if ((dst < src + len && dst + len > src)) {
        return 1;  /* Overlapping - use memmove */
    }

    memcpy(dst, src, len);
    return 0;
}

/*
 * Syscall: sol_memmove_
 *
 * Memory move (handles overlapping).
 */
static uint64_t
syscall_sol_memmove(
    sol_bpf_vm_t* vm,
    uint64_t dst_ptr,
    uint64_t src_ptr,
    uint64_t len,
    uint64_t arg4,
    uint64_t arg5
) {
    (void)arg4; (void)arg5;

    /* Agave formula: max(mem_op_base, len / cpi_bytes_per_unit) */
    {
        uint64_t cost = len / SOL_CU_CPI_BYTES_PER_UNIT;
        if (cost < SOL_CU_MEM_OP_BASE) cost = SOL_CU_MEM_OP_BASE;
        if (!consume_compute(vm, cost)) {
            return 1;
        }
    }

    if (len == 0) {
        return 0;
    }

    uint8_t* dst = sol_bpf_memory_translate(&vm->memory, dst_ptr, len, true);
    if (dst == NULL) {
        return 1;
    }

    uint8_t* src = sol_bpf_memory_translate(&vm->memory, src_ptr, len, false);
    if (src == NULL) {
        return 1;
    }

    memmove(dst, src, len);
    return 0;
}

/*
 * Syscall: sol_memcmp_
 *
 * Memory comparison.
 */
static uint64_t
syscall_sol_memcmp(
    sol_bpf_vm_t* vm,
    uint64_t s1_ptr,
    uint64_t s2_ptr,
    uint64_t len,
    uint64_t result_ptr,
    uint64_t arg5
) {
    (void)arg5;

    /* Agave formula: max(mem_op_base, len / cpi_bytes_per_unit) */
    {
        uint64_t cost = len / SOL_CU_CPI_BYTES_PER_UNIT;
        if (cost < SOL_CU_MEM_OP_BASE) cost = SOL_CU_MEM_OP_BASE;
        if (!consume_compute(vm, cost)) {
            return 1;
        }
    }

    int32_t* result = (int32_t*)sol_bpf_memory_translate(
        &vm->memory, result_ptr, 4, true);
    if (result == NULL) {
        return 1;
    }

    if (len == 0) {
        *result = 0;
        return 0;
    }

    uint8_t* s1 = sol_bpf_memory_translate(&vm->memory, s1_ptr, len, false);
    if (s1 == NULL) {
        return 1;
    }

    uint8_t* s2 = sol_bpf_memory_translate(&vm->memory, s2_ptr, len, false);
    if (s2 == NULL) {
        return 1;
    }

    *result = memcmp(s1, s2, len);
    return 0;
}

/*
 * Syscall: sol_memset_
 *
 * Memory set.
 */
static uint64_t
syscall_sol_memset(
    sol_bpf_vm_t* vm,
    uint64_t dst_ptr,
    uint64_t val,
    uint64_t len,
    uint64_t arg4,
    uint64_t arg5
) {
    (void)arg4; (void)arg5;

    /* Agave formula: max(mem_op_base, len / cpi_bytes_per_unit) */
    {
        uint64_t cost = len / SOL_CU_CPI_BYTES_PER_UNIT;
        if (cost < SOL_CU_MEM_OP_BASE) cost = SOL_CU_MEM_OP_BASE;
        if (!consume_compute(vm, cost)) {
            return 1;
        }
    }

    if (len == 0) {
        return 0;
    }

    uint8_t* dst = sol_bpf_memory_translate(&vm->memory, dst_ptr, len, true);
    if (dst == NULL) {
        return 1;
    }

    memset(dst, (int)val, len);
    return 0;
}

/*
 * Syscall: sol_alloc_free_
 *
 * Heap allocation (bump allocator).
 * r1 = size to allocate (0 means free, which is a no-op)
 * r2 = pointer to free (ignored)
 */
static uint64_t
syscall_sol_alloc_free(
    sol_bpf_vm_t* vm,
    uint64_t size,
    uint64_t free_ptr,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5
) {
    (void)free_ptr; (void)arg3; (void)arg4; (void)arg5;

    if (size == 0) {
        return 0;  /* Free is a no-op in bump allocator */
    }

    /* Agave's SyscallAllocFree does NOT charge compute units.
       Unlike other syscalls, there is no consume_checked() call in the
       function body, and the declare_builtin_function! macro only syncs
       the instruction meter (not additional CU).  Do NOT charge here. */

    /* Agave uses BPF_ALIGN_OF_U128 = 8 when check_aligned is true (v2/upgradeable).
       For deprecated loader (v1), check_aligned is false → alignment=1. */
    size_t align = vm->loader_deprecated ? 1u : 8u;
    return sol_bpf_heap_alloc(vm, size, align);
}

/*
 * Syscall: abort
 *
 * Aborts program execution.
 */
static uint64_t
syscall_abort(
    sol_bpf_vm_t* vm,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5
) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;

    /* Agave's SyscallAbort charges 0 CU - it just returns Err(Abort) */

    vm->error = SOL_BPF_ERR_ABORT;
    vm->state = SOL_BPF_STATE_ERROR;

    return 0;
}

/*
 * Syscall: sol_panic_
 *
 * Panics with file/line info.
 */
static uint64_t
syscall_sol_panic(
    sol_bpf_vm_t* vm,
    uint64_t file_ptr,
    uint64_t file_len,
    uint64_t line,
    uint64_t column,
    uint64_t arg5
) {
    (void)arg5;

    /* Agave's SyscallPanic charges `len` (the filename length), not syscall_base_cost */
    (void)consume_compute(vm, file_len);

    /* Panics are common on mainnet (tx failures) and logging them at ERROR can
     * dominate replay. Default to DEBUG and allow forcing ERROR for debugging
     * via SOL_LOG_PROGRAM_PANIC=1. */
    static int force_error_cached = -1;
    int force_error = __atomic_load_n(&force_error_cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(force_error < 0, 0)) {
        const char* env = getenv("SOL_LOG_PROGRAM_PANIC");
        force_error = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
        __atomic_store_n(&force_error_cached, force_error, __ATOMIC_RELEASE);
    }

    bool should_log = force_error || (sol_log_get_level() <= SOL_LOG_DEBUG);
    if (__builtin_expect(should_log, 0)) {
        const char* file = "unknown";
        if (file_len > 0 && file_len < 1024) {
            uint8_t* f = sol_bpf_memory_translate(&vm->memory, file_ptr, file_len, false);
            if (f != NULL) {
                file = (const char*)f;
            }
        }

        if (force_error) {
            sol_log_error("Program panic at %.*s:%lu:%lu",
                          (int)file_len, file,
                          (unsigned long)line, (unsigned long)column);
        } else {
            sol_log_debug("Program panic at %.*s:%lu:%lu",
                          (int)file_len, file,
                          (unsigned long)line, (unsigned long)column);
        }
    }

    vm->error = SOL_BPF_ERR_ABORT;
    vm->state = SOL_BPF_STATE_ERROR;

    return 0;
}

/*
 * Syscall: sol_get_sysvar
 *
 * Copies sysvar account data into a buffer.
 * r1 = sysvar pubkey (32 bytes)
 * r2 = destination buffer
 * r3 = offset into sysvar data
 * r4 = length to copy
 */
static uint64_t
syscall_sol_get_sysvar(
    sol_bpf_vm_t* vm,
    uint64_t sysvar_id_ptr,
    uint64_t dst_ptr,
    uint64_t offset,
    uint64_t len,
    uint64_t arg5
) {
    (void)arg5;

    /* Agave: sysvar_base_cost + (32/cpi_bytes_per_unit) + max(len/cpi_bytes_per_unit, mem_op_base) */
    {
        uint64_t sysvar_id_cost = 32 / SOL_CU_CPI_BYTES_PER_UNIT;
        uint64_t sysvar_buf_cost = len / SOL_CU_CPI_BYTES_PER_UNIT;
        if (sysvar_buf_cost < SOL_CU_MEM_OP_BASE) sysvar_buf_cost = SOL_CU_MEM_OP_BASE;
        uint64_t total_cost = SOL_CU_SYSVAR_BASE + sysvar_id_cost + sysvar_buf_cost;
        if (!consume_compute(vm, total_cost)) {
            return 1;
        }
    }

    uint8_t* sysvar_id_bytes =
        sol_bpf_memory_translate(&vm->memory, sysvar_id_ptr, SOL_PUBKEY_SIZE, false);
    if (sysvar_id_bytes == NULL) {
        return 1;
    }

    sol_pubkey_t sysvar_id;
    memcpy(sysvar_id.bytes, sysvar_id_bytes, SOL_PUBKEY_SIZE);

    /* Agave return codes: 0=SUCCESS, 1=OFFSET_LENGTH_EXCEEDS, 2=SYSVAR_NOT_FOUND */
#define SYSVAR_NOT_FOUND           2
#define OFFSET_LENGTH_EXCEEDS      1

    /* Prevent programs from reading arbitrary accounts via this syscall. */
    if (!sol_is_sysvar(&sysvar_id)) {
        return SYSVAR_NOT_FOUND;
    }

    if (len == 0) {
        return 0;
    }

    if (len > SIZE_MAX || offset > SIZE_MAX) {
        return OFFSET_LENGTH_EXCEEDS;
    }

    size_t copy_len = (size_t)len;
    size_t off = (size_t)offset;
    if (off > SIZE_MAX - copy_len) {
        return OFFSET_LENGTH_EXCEEDS;
    }

    uint8_t* dst = sol_bpf_memory_translate(&vm->memory, dst_ptr, copy_len, true);
    if (dst == NULL) {
        return 1;  /* VM abort */
    }

    sol_invoke_context_t* ctx = (sol_invoke_context_t*)vm->context;
    if (ctx == NULL || ctx->bank == NULL) {
        return SYSVAR_NOT_FOUND;
    }

    sol_account_t* sysvar_account = sol_bank_load_account(ctx->bank, &sysvar_id);
    if (sysvar_account == NULL) {
        return SYSVAR_NOT_FOUND;
    }

    if (off > sysvar_account->meta.data_len ||
        copy_len > (size_t)sysvar_account->meta.data_len - off ||
        (copy_len > 0 && sysvar_account->data == NULL)) {
        sol_account_destroy(sysvar_account);
        return OFFSET_LENGTH_EXCEEDS;
    }

#undef SYSVAR_NOT_FOUND
#undef OFFSET_LENGTH_EXCEEDS

    memcpy(dst, sysvar_account->data + off, copy_len);
    sol_account_destroy(sysvar_account);
    return 0;
}

/*
 * Syscall: sol_get_clock_sysvar
 *
 * Gets the Clock sysvar.
 */
static uint64_t
syscall_sol_get_clock_sysvar(
    sol_bpf_vm_t* vm,
    uint64_t result_ptr,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5
) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;

    /* Agave charges sysvar_base_cost + sizeof(sysvar) */
    if (!consume_compute(vm, SOL_CU_SYSVAR_BASE + SOL_CLOCK_SIZE)) {
        return 1;
    }

    /* Clock struct: slot(8) + epoch_start_timestamp(8) + epoch(8) +
     *               leader_schedule_epoch(8) + unix_timestamp(8) = 40 bytes */
    uint8_t* result = sol_bpf_memory_translate(&vm->memory, result_ptr, SOL_CLOCK_SIZE, true);
    if (result == NULL) {
        return 1;
    }

    /* Get clock from invoke context */
    sol_invoke_context_t* ctx = (sol_invoke_context_t*)vm->context;
    if (ctx == NULL) {
        /* Return default clock */
        memset(result, 0, SOL_CLOCK_SIZE);
        return 0;
    }

    size_t offset = 0;
    uint64_t slot = ctx->clock.slot;
    int64_t epoch_start_ts = (int64_t)ctx->clock.epoch_start_timestamp;
    uint64_t epoch = ctx->clock.epoch;
    uint64_t leader_epoch = ctx->clock.leader_schedule_epoch;
    int64_t unix_ts = (int64_t)ctx->clock.unix_timestamp;

    memcpy(result + offset, &slot, 8);
    offset += 8;

    memcpy(result + offset, &epoch_start_ts, 8);
    offset += 8;

    memcpy(result + offset, &epoch, 8);
    offset += 8;

    memcpy(result + offset, &leader_epoch, 8);
    offset += 8;

    memcpy(result + offset, &unix_ts, 8);

    return 0;
}

/*
 * Syscall: sol_get_rent_sysvar
 *
 * Gets the Rent sysvar.
 */
static uint64_t
syscall_sol_get_rent_sysvar(
    sol_bpf_vm_t* vm,
    uint64_t result_ptr,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5
) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;

    /* Agave charges sysvar_base_cost + sizeof(sysvar) */
    if (!consume_compute(vm, SOL_CU_SYSVAR_BASE + SOL_RENT_SIZE)) {
        return 1;
    }

    /* Rent: #[repr(C)] = u64(8) + f64(8) + u8(1) + 7pad = 24 bytes */
    uint8_t* result = sol_bpf_memory_translate(&vm->memory, result_ptr, SOL_RENT_SIZE, true);
    if (result == NULL) {
        return 1;
    }

    /* Default rent values */
    uint64_t lamports_per_byte_year = 3480;
    double exemption_threshold = 2.0;
    uint8_t burn_percent = 50;

    sol_invoke_context_t* ctx = (sol_invoke_context_t*)vm->context;
    if (ctx != NULL && ctx->rent.lamports_per_byte_year != 0) {
        lamports_per_byte_year = ctx->rent.lamports_per_byte_year;
        exemption_threshold = ctx->rent.exemption_threshold;
        burn_percent = ctx->rent.burn_percent;
    }

    /* Write in #[repr(C)] layout with padding */
    memset(result, 0, SOL_RENT_SIZE);
    memcpy(result, &lamports_per_byte_year, 8);
    memcpy(result + 8, &exemption_threshold, 8);
    result[16] = burn_percent;
    /* 7 bytes padding at offset 17-23 (zeroed by memset) */

    return 0;
}

/*
 * Syscall: sol_get_epoch_schedule_sysvar
 *
 * Gets the EpochSchedule sysvar.
 */
static uint64_t
syscall_sol_get_epoch_schedule_sysvar(
    sol_bpf_vm_t* vm,
    uint64_t result_ptr,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5
) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;

    /* Agave charges sysvar_base_cost + sizeof(sysvar) */
    if (!consume_compute(vm, SOL_CU_SYSVAR_BASE + SOL_EPOCH_SCHEDULE_SIZE)) {
        return 1;
    }

    /* EpochSchedule syscall returns the bincode-serialized layout (no struct
     * padding), matching Solana's stable ABI:
     *   slots_per_epoch(8) + leader_schedule_slot_offset(8) +
     *   warmup(1) + first_normal_epoch(8) + first_normal_slot(8) = 33 bytes.
     *
     * The output buffer is still expected to be SOL_EPOCH_SCHEDULE_SIZE bytes
     * to match existing callers and CU charging conventions. */
    uint8_t* result = sol_bpf_memory_translate(&vm->memory, result_ptr, SOL_EPOCH_SCHEDULE_SIZE, true);
    if (result == NULL) {
        return 1;
    }

    /* Default epoch schedule values */
    uint64_t slots_per_epoch = 432000;
    uint64_t leader_schedule_slot_offset = 4;
    uint8_t warmup = 0;
    uint64_t first_normal_epoch = 0;
    uint64_t first_normal_slot = 0;

    sol_invoke_context_t* ctx = (sol_invoke_context_t*)vm->context;
    if (ctx != NULL && ctx->epoch_schedule.slots_per_epoch != 0) {
        slots_per_epoch = ctx->epoch_schedule.slots_per_epoch;
        leader_schedule_slot_offset = ctx->epoch_schedule.leader_schedule_slot_offset;
        warmup = ctx->epoch_schedule.warmup ? 1 : 0;
        first_normal_epoch = ctx->epoch_schedule.first_normal_epoch;
        first_normal_slot = ctx->epoch_schedule.first_normal_slot;
    }

    /* Write bincode layout (no padding between fields) */
    memset(result, 0, SOL_EPOCH_SCHEDULE_SIZE);
    memcpy(result + 0, &slots_per_epoch, 8);
    memcpy(result + 8, &leader_schedule_slot_offset, 8);
    result[16] = warmup;
    memcpy(result + 17, &first_normal_epoch, 8);
    memcpy(result + 25, &first_normal_slot, 8);

    return 0;
}

/*
 * Syscall: sol_get_fees_sysvar
 *
 * Gets the Fees sysvar (deprecated).
 */
static uint64_t
syscall_sol_get_fees_sysvar(
    sol_bpf_vm_t* vm,
    uint64_t result_ptr,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5
) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;

    /* Agave charges sysvar_base_cost + sizeof(sysvar) */
    if (!consume_compute(vm, SOL_CU_SYSVAR_BASE + SOL_FEES_SIZE)) {
        return 1;
    }

    /* Fees struct: lamports_per_signature(8) */
    uint8_t* result = sol_bpf_memory_translate(&vm->memory, result_ptr, SOL_FEES_SIZE, true);
    if (result == NULL) {
        return 1;
    }

    uint64_t lamports_per_signature = 5000;
    sol_invoke_context_t* ctx = (sol_invoke_context_t*)vm->context;
    if (ctx != NULL && ctx->lamports_per_signature != 0) {
        lamports_per_signature = ctx->lamports_per_signature;
    }

    memcpy(result, &lamports_per_signature, 8);
    return 0;
}

/*
 * Syscall: sol_secp256k1_recover
 *
 * Recovers an uncompressed secp256k1 public key (64 bytes: x||y) from a
 * compact signature and recovery id.
 * r1 = message hash (32 bytes)
 * r2 = recovery id (0..3)
 * r3 = signature (64 bytes, compact)
 * r4 = result pubkey (64 bytes)
 */
static uint64_t
syscall_sol_secp256k1_recover(
    sol_bpf_vm_t* vm,
    uint64_t hash_ptr,
    uint64_t recovery_id,
    uint64_t sig_ptr,
    uint64_t result_ptr,
    uint64_t arg5
) {
    (void)arg5;

    if (!consume_compute(vm, SOL_CU_SECP256K1_RECOVER)) {
        return 1;
    }

    uint8_t* hash = sol_bpf_memory_translate(&vm->memory, hash_ptr, 32, false);
    if (hash == NULL) {
        return 1;
    }

    uint8_t* sig = sol_bpf_memory_translate(&vm->memory, sig_ptr, 64, false);
    if (sig == NULL) {
        return 1;
    }

    uint8_t* out = sol_bpf_memory_translate(&vm->memory, result_ptr, 64, true);
    if (out == NULL) {
        return 1;
    }

    sol_err_t err = sol_secp256k1_recover_pubkey(sig, (uint8_t)recovery_id, hash, out);
    return (err == SOL_OK) ? 0 : 1;
}

/*
 * Syscall: sol_remaining_compute_units
 *
 * Returns the number of remaining compute units.
 */
static uint64_t
syscall_sol_remaining_compute_units(
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

    return vm->compute_units > vm->compute_units_used
        ? vm->compute_units - vm->compute_units_used
        : 0;
}

/*
 * Syscall: sol_get_last_restart_slot
 *
 * Gets the LastRestartSlot sysvar (a single u64).
 * Agave: sysvar_base_cost + sizeof(LastRestartSlot) = 100 + 8 = 108 CU
 */
#define SOL_LAST_RESTART_SLOT_SIZE  8
static uint64_t
syscall_sol_get_last_restart_slot(
    sol_bpf_vm_t* vm,
    uint64_t result_ptr,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5
) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;

    if (!consume_compute(vm, SOL_CU_SYSVAR_BASE + SOL_LAST_RESTART_SLOT_SIZE)) {
        return 1;
    }

    uint8_t* result = sol_bpf_memory_translate(
        &vm->memory, result_ptr, SOL_LAST_RESTART_SLOT_SIZE, true);
    if (result == NULL) {
        return 1;
    }

    /* Read the LastRestartSlot sysvar from the bank's AccountsDB.
       The sysvar data is a single u64 (last_restart_slot).
       In Agave this is populated from hard forks / cluster restarts. */
    uint64_t last_restart_slot = 0;
    sol_invoke_context_t* ctx = (sol_invoke_context_t*)vm->context;
    if (ctx != NULL && ctx->bank != NULL) {
        sol_account_t* sysvar_account = sol_bank_load_account(
            ctx->bank, &SOL_SYSVAR_LAST_RESTART_SLOT_ID);
        if (sysvar_account != NULL && sysvar_account->data != NULL &&
            sysvar_account->meta.data_len >= 8) {
            memcpy(&last_restart_slot, sysvar_account->data, 8);
        }
        if (sysvar_account) sol_account_destroy(sysvar_account);
    }

    memcpy(result, &last_restart_slot, 8);
    return 0;
}

/*
 * Syscall: sol_get_epoch_rewards_sysvar
 *
 * Gets the EpochRewards sysvar.
 * Layout (bincode, 81 bytes):
 *   distribution_starting_block_height(8) + num_partitions(8) +
 *   parent_blockhash(32) + total_points(16) + total_rewards(8) +
 *   distributed_rewards(8) + active(1)
 *
 * CU cost: sysvar_base_cost + sizeof(EpochRewards)
 */
static uint64_t
syscall_sol_get_epoch_rewards_sysvar(
    sol_bpf_vm_t* vm,
    uint64_t result_ptr,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5
) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;

    if (!consume_compute(vm, SOL_CU_SYSVAR_BASE + SOL_EPOCH_REWARDS_SIZE)) {
        return 1;
    }

    uint8_t* result = sol_bpf_memory_translate(
        &vm->memory, result_ptr, SOL_EPOCH_REWARDS_SIZE, true);
    if (result == NULL) {
        return 1;
    }

    sol_invoke_context_t* ctx = (sol_invoke_context_t*)vm->context;
    if (ctx == NULL || ctx->bank == NULL) {
        /* Return default (inactive) EpochRewards */
        memset(result, 0, SOL_EPOCH_REWARDS_SIZE);
        return 0;
    }

    /* Load the EpochRewards sysvar account from the bank.
     * The account stores bincode data (81 bytes), but the typed getter
     * writes the #[repr(C, align(16))] struct layout (96 bytes).
     * The first 81 bytes of the Rust struct layout match the bincode layout
     * (no internal padding needed); only trailing padding differs. */
#define EPOCH_REWARDS_BINCODE_SIZE 81
    sol_account_t* sysvar_account = sol_bank_load_account(
        ctx->bank, &SOL_SYSVAR_EPOCH_REWARDS_ID);
    if (sysvar_account == NULL || sysvar_account->data == NULL ||
        sysvar_account->meta.data_len < EPOCH_REWARDS_BINCODE_SIZE) {
        /* Sysvar doesn't exist or is too small - return default (inactive) */
        memset(result, 0, SOL_EPOCH_REWARDS_SIZE);
        if (sysvar_account) sol_account_destroy(sysvar_account);
        return 0;
    }

    memset(result, 0, SOL_EPOCH_REWARDS_SIZE);
    memcpy(result, sysvar_account->data, EPOCH_REWARDS_BINCODE_SIZE);
    sol_account_destroy(sysvar_account);
    return 0;
#undef EPOCH_REWARDS_BINCODE_SIZE
}

/*
 * Syscall: sol_get_epoch_stake
 *
 * Gets the delegated stake for a vote account in the current epoch.
 * r1 = pointer to vote account pubkey (32 bytes)
 * Returns: delegated stake as u64 (in r0)
 *
 * CU cost: syscall_base_cost
 */
static uint64_t
syscall_sol_get_epoch_stake(
    sol_bpf_vm_t* vm,
    uint64_t vote_addr_ptr,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5
) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;

    if (!consume_compute(vm, SOL_CU_SYSCALL_BASE)) {
        return 0;
    }

    const uint8_t* vote_addr = sol_bpf_memory_translate(
        &vm->memory, vote_addr_ptr, 32, false);
    if (vote_addr == NULL) {
        return 0;
    }

    /* TODO: Look up actual delegated stake from vote accounts.
       For now return 0 (unknown). This syscall is feature-gated and
       may not be active on mainnet yet. */
    (void)vote_addr;
    return 0;
}

/*
 * Syscall: sol_get_processed_sibling_instruction
 *
 * Returns info about a processed sibling instruction at the same stack height.
 * r1 = index (0-based, reverse iteration — 0 = most recent sibling)
 * r2 = pointer to ProcessedSiblingInstruction meta struct (data_len: u64, accounts_len: u64)
 * r3 = pointer to program_id output (32 bytes)
 * r4 = pointer to instruction data output buffer
 * r5 = pointer to account metas output buffer
 *
 * Returns 1 if instruction found, 0 if not found.
 * Agave charges syscall_base_cost (100 CU).
 *
 * Agave matching logic: walks the instruction trace backwards.  The first
 * entry at the same stack_height is the CURRENT instruction (skipped via
 * the `index + 1 == reverse_count` check).  index=0 returns the most
 * recently completed sibling at the same depth.
 */
static uint64_t
syscall_sol_get_processed_sibling_instruction(
    sol_bpf_vm_t* vm,
    uint64_t index,
    uint64_t meta_ptr,
    uint64_t program_id_ptr,
    uint64_t data_ptr,
    uint64_t accounts_ptr
) {
    if (!consume_compute(vm, SOL_CU_SYSCALL_BASE)) {
        return 1;
    }

    /* Translate the meta struct (data_len: u64, accounts_len: u64) */
    uint8_t* meta = sol_bpf_memory_translate(&vm->memory, meta_ptr, 16, true);
    if (meta == NULL) {
        return 0;
    }

    sol_invoke_context_t* ctx = (sol_invoke_context_t*)vm->context;
    if (!ctx) {
        return 0;
    }

    uint64_t stack_height = ctx->stack_height ? ctx->stack_height : 1;

    /* Use instruction trace if available (works at all stack heights) */
    if (ctx->instruction_trace != NULL && ctx->instruction_trace->count > 0) {
        sol_instruction_trace_t* trace = ctx->instruction_trace;
        size_t trace_len = trace->count;

        /* Walk backwards through the trace matching Agave's loop:
         *   - Entries at stack_height > current: skip (deeper children of siblings)
         *   - Entries at stack_height == current: count as potential sibling
         *   - Entries at stack_height < current: break (parent instruction)
         * The first match at same stack_height is the current instruction
         * itself (skipped by the index+1 check). */
        uint64_t reverse_index_at_stack_height = 0;
        const sol_instruction_trace_entry_t* found = NULL;

        for (size_t i = trace_len; i > 0; i--) {
            const sol_instruction_trace_entry_t* e = &trace->entries[i - 1];
            if (e->stack_height < (uint8_t)stack_height) {
                break;
            }
            if (e->stack_height == (uint8_t)stack_height) {
                if (index + 1 == reverse_index_at_stack_height) {
                    found = e;
                    break;
                }
                reverse_index_at_stack_height++;
            }
        }

        if (found == NULL) {
            return 0;
        }

        /* Read caller's buffer sizes from meta */
        uint64_t caller_data_len = 0;
        uint64_t caller_accounts_len = 0;
        memcpy(&caller_data_len, meta, 8);
        memcpy(&caller_accounts_len, meta + 8, 8);

        /* Write actual sizes to meta */
        uint64_t actual_data_len = (uint64_t)found->data_len;
        uint64_t actual_accounts_len = (uint64_t)found->accounts_len;
        memcpy(meta, &actual_data_len, 8);
        memcpy(meta + 8, &actual_accounts_len, 8);

        /* If caller's buffers are too small, return 1 (found, re-allocate) */
        if (caller_data_len < actual_data_len || caller_accounts_len < actual_accounts_len) {
            return 1;
        }

        /* Write program_id */
        if (program_id_ptr != 0) {
            uint8_t* pid_out = sol_bpf_memory_translate(&vm->memory, program_id_ptr, 32, true);
            if (pid_out == NULL) return 0;
            memcpy(pid_out, found->program_id.bytes, 32);
        }

        /* Write instruction data */
        if (data_ptr != 0 && actual_data_len > 0 && found->data) {
            uint8_t* data_out = sol_bpf_memory_translate(
                &vm->memory, data_ptr, (size_t)actual_data_len, true);
            if (data_out == NULL) return 0;
            memcpy(data_out, found->data, (size_t)actual_data_len);
        }

        /* Write account metas: { pubkey: [u8;32], is_signer: bool, is_writable: bool }
           = 34 bytes per account */
        if (accounts_ptr != 0 && actual_accounts_len > 0 && found->account_keys) {
            size_t meta_size = (size_t)actual_accounts_len * 34;
            uint8_t* accts_out = sol_bpf_memory_translate(
                &vm->memory, accounts_ptr, meta_size, true);
            if (accts_out == NULL) return 0;

            for (uint16_t j = 0; j < found->accounts_len; j++) {
                uint8_t* entry = accts_out + (size_t)j * 34;
                memcpy(entry, found->account_keys[j].bytes, 32);
                entry[32] = (found->account_is_signer && found->account_is_signer[j]) ? 1 : 0;
                entry[33] = (found->account_is_writable && found->account_is_writable[j]) ? 1 : 0;
            }
        }

        return 1;
    }

    /* Fallback: no instruction trace, only handle stack_height==1 using
     * the transaction message instructions (legacy behavior). */
    if (!ctx->transaction) {
        return 0;
    }

    if (stack_height != 1) {
        return 0;
    }

    uint8_t num_processed = ctx->current_instruction_index;
    if (index >= num_processed) {
        return 0;
    }

    uint8_t sibling_idx = (uint8_t)(num_processed - 1 - (uint8_t)index);

    const sol_transaction_t* tx = ctx->transaction;
    const sol_message_t* msg = &tx->message;
    if (sibling_idx >= msg->instructions_len) {
        return 0;
    }

    const sol_compiled_instruction_t* ix = &msg->instructions[sibling_idx];

    const sol_pubkey_t* acct_keys = msg->resolved_accounts_len
        ? msg->resolved_accounts : msg->account_keys;
    uint16_t acct_keys_len = msg->resolved_accounts_len
        ? msg->resolved_accounts_len : (uint16_t)msg->account_keys_len;

    uint64_t caller_data_len = 0;
    uint64_t caller_accounts_len = 0;
    memcpy(&caller_data_len, meta, 8);
    memcpy(&caller_accounts_len, meta + 8, 8);

    uint64_t actual_data_len = (uint64_t)ix->data_len;
    uint64_t actual_accounts_len = (uint64_t)ix->account_indices_len;
    memcpy(meta, &actual_data_len, 8);
    memcpy(meta + 8, &actual_accounts_len, 8);

    if (caller_data_len < actual_data_len || caller_accounts_len < actual_accounts_len) {
        return 1;
    }

    if (program_id_ptr != 0) {
        uint8_t* pid_out = sol_bpf_memory_translate(&vm->memory, program_id_ptr, 32, true);
        if (pid_out == NULL) return 0;
        if (acct_keys && ix->program_id_index < acct_keys_len) {
            memcpy(pid_out, acct_keys[ix->program_id_index].bytes, 32);
        } else {
            memset(pid_out, 0, 32);
        }
    }

    if (data_ptr != 0 && actual_data_len > 0 && ix->data) {
        uint8_t* data_out = sol_bpf_memory_translate(
            &vm->memory, data_ptr, (size_t)actual_data_len, true);
        if (data_out == NULL) return 0;
        memcpy(data_out, ix->data, (size_t)actual_data_len);
    }

    if (accounts_ptr != 0 && actual_accounts_len > 0 && ix->account_indices) {
        size_t meta_size = (size_t)actual_accounts_len * 34;
        uint8_t* accts_out = sol_bpf_memory_translate(
            &vm->memory, accounts_ptr, meta_size, true);
        if (accts_out == NULL) return 0;

        for (uint8_t j = 0; j < ix->account_indices_len; j++) {
            uint8_t key_idx = ix->account_indices[j];
            uint8_t* entry = accts_out + (size_t)j * 34;
            if (acct_keys && key_idx < acct_keys_len) {
                memcpy(entry, acct_keys[key_idx].bytes, 32);
            } else {
                memset(entry, 0, 32);
            }
            bool is_signer = (msg->is_signer && key_idx < acct_keys_len)
                ? msg->is_signer[key_idx]
                : (key_idx < msg->header.num_required_signatures);
            entry[32] = is_signer ? 1 : 0;
            bool is_writable = false;
            if (ctx->is_writable && key_idx < ctx->account_keys_len) {
                is_writable = ctx->is_writable[key_idx];
            } else if (msg->is_writable && key_idx < acct_keys_len) {
                is_writable = msg->is_writable[key_idx];
            } else {
                is_writable = sol_message_is_writable_index(msg, key_idx);
            }
            entry[33] = is_writable ? 1 : 0;
        }
    }

    return 1;
}

/*
 * Curve25519 constants matching Agave's curve_syscall_traits.rs
 */
#define CURVE25519_EDWARDS    0
#define CURVE25519_RISTRETTO  1

#define CURVE25519_ADD  0
#define CURVE25519_SUB  1
#define CURVE25519_MUL  2

/* CU costs per operation (from Agave compute_budget.rs) */
#define CU_CURVE25519_EDWARDS_ADD   473
#define CU_CURVE25519_EDWARDS_SUB   475
#define CU_CURVE25519_EDWARDS_MUL  2177
#define CU_CURVE25519_RISTRETTO_ADD  521
#define CU_CURVE25519_RISTRETTO_SUB  519
#define CU_CURVE25519_RISTRETTO_MUL 2208

#define CU_CURVE25519_EDWARDS_VALIDATE   159
#define CU_CURVE25519_RISTRETTO_VALIDATE 169

#define CURVE_POINT_BYTES  32
#define CURVE_SCALAR_BYTES 32

/*
 * Syscall: sol_curve_group_op
 *
 * Performs elliptic curve group operations (add, sub, mul) on
 * curve25519 Edwards and Ristretto255 points.
 *
 * r1 = curve_id (0=Edwards, 1=Ristretto)
 * r2 = group_op (0=ADD, 1=SUB, 2=MUL)
 * r3 = left_input pointer (point for ADD/SUB, scalar for MUL)
 * r4 = right_input pointer (point)
 * r5 = result_point pointer
 */
static uint64_t
syscall_sol_curve_group_op(
    sol_bpf_vm_t* vm,
    uint64_t curve_id,
    uint64_t group_op,
    uint64_t left_ptr,
    uint64_t right_ptr,
    uint64_t result_ptr
) {
    /* Determine CU cost */
    uint64_t cost;
    if (curve_id == CURVE25519_EDWARDS) {
        switch (group_op) {
        case CURVE25519_ADD: cost = CU_CURVE25519_EDWARDS_ADD; break;
        case CURVE25519_SUB: cost = CU_CURVE25519_EDWARDS_SUB; break;
        case CURVE25519_MUL: cost = CU_CURVE25519_EDWARDS_MUL; break;
        default: return 1;
        }
    } else if (curve_id == CURVE25519_RISTRETTO) {
        switch (group_op) {
        case CURVE25519_ADD: cost = CU_CURVE25519_RISTRETTO_ADD; break;
        case CURVE25519_SUB: cost = CU_CURVE25519_RISTRETTO_SUB; break;
        case CURVE25519_MUL: cost = CU_CURVE25519_RISTRETTO_MUL; break;
        default: return 1;
        }
    } else {
        return 1;  /* Unknown curve */
    }

    if (!consume_compute(vm, cost)) return 1;

#if SOL_USE_LIBSODIUM
    /* Translate VM memory */
    size_t left_len  = (group_op == CURVE25519_MUL) ? CURVE_SCALAR_BYTES : CURVE_POINT_BYTES;
    size_t right_len = CURVE_POINT_BYTES;

    const uint8_t* left = sol_bpf_memory_translate(
        &vm->memory, left_ptr, left_len, false);
    if (left == NULL) return 1;

    const uint8_t* right = sol_bpf_memory_translate(
        &vm->memory, right_ptr, right_len, false);
    if (right == NULL) return 1;

    uint8_t* result = sol_bpf_memory_translate(
        &vm->memory, result_ptr, CURVE_POINT_BYTES, true);
    if (result == NULL) return 1;

    int rc;
    if (curve_id == CURVE25519_EDWARDS) {
        switch (group_op) {
        case CURVE25519_ADD:
            rc = crypto_core_ed25519_add(result, left, right);
            break;
        case CURVE25519_SUB:
            rc = crypto_core_ed25519_sub(result, left, right);
            break;
        case CURVE25519_MUL:
            rc = crypto_scalarmult_ed25519_noclamp(result, left, right);
            break;
        default:
            return 1;
        }
    } else {
        switch (group_op) {
        case CURVE25519_ADD:
            rc = crypto_core_ristretto255_add(result, left, right);
            break;
        case CURVE25519_SUB:
            rc = crypto_core_ristretto255_sub(result, left, right);
            break;
        case CURVE25519_MUL:
            rc = crypto_scalarmult_ristretto255(result, left, right);
            break;
        default:
            return 1;
        }
    }

    return (rc == 0) ? 0 : 1;
#else
    (void)left_ptr; (void)right_ptr; (void)result_ptr;
    return 1;  /* No crypto backend */
#endif
}

/*
 * Syscall: sol_curve_point_validation
 *
 * Validates whether bytes represent a valid curve point.
 *
 * r1 = curve_id (0=Edwards, 1=Ristretto)
 * r2 = point pointer (32 bytes)
 *
 * Returns 0 if valid, 1 if invalid.
 */
static uint64_t
syscall_sol_curve_point_validation(
    sol_bpf_vm_t* vm,
    uint64_t curve_id,
    uint64_t point_ptr,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5
) {
    (void)arg3; (void)arg4; (void)arg5;

    uint64_t cost;
    if (curve_id == CURVE25519_EDWARDS) {
        cost = CU_CURVE25519_EDWARDS_VALIDATE;
    } else if (curve_id == CURVE25519_RISTRETTO) {
        cost = CU_CURVE25519_RISTRETTO_VALIDATE;
    } else {
        return 1;
    }

    if (!consume_compute(vm, cost)) return 1;

#if SOL_USE_LIBSODIUM
    const uint8_t* point = sol_bpf_memory_translate(
        &vm->memory, point_ptr, CURVE_POINT_BYTES, false);
    if (point == NULL) return 1;

    int valid;
    if (curve_id == CURVE25519_EDWARDS) {
        valid = crypto_core_ed25519_is_valid_point(point);
    } else {
        valid = crypto_core_ristretto255_is_valid_point(point);
    }

    return valid ? 0 : 1;
#else
    (void)point_ptr;
    return 1;
#endif
}

/*
 * Syscall: sol_curve_multiscalar_multiplication
 *
 * Performs multiscalar multiplication on curve25519.
 * Stub - not yet fully implemented (requires multi-point MSM).
 */
static uint64_t
syscall_sol_curve_multiscalar_multiplication(
    sol_bpf_vm_t* vm,
    uint64_t arg1, uint64_t arg2, uint64_t arg3,
    uint64_t arg4, uint64_t arg5
) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    if (!consume_compute(vm, SOL_CU_SYSCALL_BASE)) return 1;
    return 1;  /* Not implemented - return error */
}

/*
 * BN254/alt_bn128 and Poseidon syscalls.
 * Uses Firedancer's pure-C implementation for BN254 curve operations
 * and Poseidon hashing over the BN254 scalar field.
 */

/* Firedancer BN254 headers */
#include "../../external/fd-src/src/ballet/bn254/fd_bn254.h"
#include "../../external/fd-src/src/ballet/bn254/fd_poseidon.h"

/* alt_bn128 group operation IDs */
#define ALT_BN128_ADD     0
#define ALT_BN128_MUL     2
#define ALT_BN128_PAIRING 3

/* CU costs for alt_bn128 group operations */
#define ALT_BN128_ADD_CU      334
#define ALT_BN128_MUL_CU      3840
#define ALT_BN128_PAIRING_ONE  36364
#define ALT_BN128_PAIRING_EACH 12121

/* CU costs for alt_bn128 compression */
#define ALT_BN128_G1_COMPRESS_CU    30
#define ALT_BN128_G1_DECOMPRESS_CU  398
#define ALT_BN128_G2_COMPRESS_CU    86
#define ALT_BN128_G2_DECOMPRESS_CU  13610

/* Compression operation IDs */
#define ALT_BN128_G1_COMPRESS    0
#define ALT_BN128_G1_DECOMPRESS  1
#define ALT_BN128_G2_COMPRESS    2
#define ALT_BN128_G2_DECOMPRESS  3

/* Poseidon parameters */
#define POSEIDON_PARAMETERS_BN254_X5  0
#define POSEIDON_ENDIANNESS_BIG       0
#define POSEIDON_ENDIANNESS_LITTLE    1
#define POSEIDON_MAX_INPUTS           12

static uint64_t
syscall_sol_poseidon(
    sol_bpf_vm_t* vm,
    uint64_t parameters,
    uint64_t endianness,
    uint64_t vals_addr,
    uint64_t vals_len,
    uint64_t result_addr
) {
    /* Validate parameters */
    if (parameters != POSEIDON_PARAMETERS_BN254_X5) return 1;
    if (endianness != POSEIDON_ENDIANNESS_BIG && endianness != POSEIDON_ENDIANNESS_LITTLE) return 1;
    if (vals_len == 0 || vals_len > POSEIDON_MAX_INPUTS) return 1;

    /* CU cost: 61 * vals_len^2 + 542 */
    uint64_t cu_cost = 61 * vals_len * vals_len + 542;
    if (!consume_compute(vm, cu_cost)) return 1;

    /* Translate result buffer */
    uint8_t* result = sol_bpf_memory_translate(&vm->memory, result_addr, 32, true);
    if (result == NULL) return 1;

    /* Initialize Poseidon state */
    fd_poseidon_t pos[1];
    int big_endian = (endianness == POSEIDON_ENDIANNESS_BIG) ? 1 : 0;
    fd_poseidon_init(pos, big_endian);

    /* Process each input element */
    for (uint64_t i = 0; i < vals_len; i++) {
        /* Each slice descriptor is { ptr: u64, len: u64 } = 16 bytes */
        uint8_t* slice = sol_bpf_memory_translate(
            &vm->memory, vals_addr + i * 16, 16, false);
        if (slice == NULL) return 1;

        uint64_t data_ptr = *(uint64_t*)slice;
        uint64_t data_len = *(uint64_t*)(slice + 8);

        uint8_t* data = sol_bpf_memory_translate(
            &vm->memory, data_ptr, data_len, false);
        if (data == NULL) return 1;

        /* poseidon_enforce_padding is NOT active on mainnet (epoch 937+).
           Legacy mode: accept 1-32 byte inputs, fd_poseidon_append pads internally. */
        if (fd_poseidon_append(pos, data, (unsigned long)data_len, 0) == NULL) {
            return 1;  /* Input >= field modulus, empty, or >32 bytes */
        }
    }

    /* Finalize hash */
    if (fd_poseidon_fini(pos, result) == NULL) {
        return 1;
    }

    return 0;
}

static uint64_t
syscall_sol_alt_bn128_group_op(
    sol_bpf_vm_t* vm,
    uint64_t group_op,
    uint64_t input_addr,
    uint64_t input_sz,
    uint64_t result_addr,
    uint64_t arg5
) {
    (void)arg5;

    /* Determine CU cost and output size based on operation */
    uint64_t cu_cost;
    uint64_t output_sz;

    switch (group_op) {
    case ALT_BN128_ADD:
        cu_cost = ALT_BN128_ADD_CU;
        output_sz = 64;
        break;
    case ALT_BN128_MUL:
        cu_cost = ALT_BN128_MUL_CU;
        output_sz = 64;
        break;
    case ALT_BN128_PAIRING: {
        if (input_sz % 192 != 0) return 1;
        uint64_t num_pairs = input_sz / 192;
        /* CU: 36364 + 12121 * max(0, num_pairs - 1) + 85 + input_sz + 32 */
        cu_cost = ALT_BN128_PAIRING_ONE;
        if (num_pairs > 1) cu_cost += ALT_BN128_PAIRING_EACH * (num_pairs - 1);
        cu_cost += 85 + input_sz + 32;
        output_sz = 32;
        break;
    }
    default:
        return 1;
    }

    if (!consume_compute(vm, cu_cost)) return 1;

    /* Translate output buffer */
    uint8_t* result = sol_bpf_memory_translate(&vm->memory, result_addr, output_sz, true);
    if (result == NULL) return 1;

    /* Translate input buffer (may be empty for pairing with 0 pairs) */
    uint8_t* input = NULL;
    if (input_sz > 0) {
        input = sol_bpf_memory_translate(&vm->memory, input_addr, input_sz, false);
        if (input == NULL) return 1;
    }

    int ret;
    int big_endian = 1;  /* Solana uses big-endian encoding */

    switch (group_op) {
    case ALT_BN128_ADD:
        ret = fd_bn254_g1_add_syscall(result, input, (unsigned long)input_sz, big_endian);
        break;
    case ALT_BN128_MUL:
        ret = fd_bn254_g1_scalar_mul_syscall(result, input, (unsigned long)input_sz, big_endian);
        break;
    case ALT_BN128_PAIRING:
        ret = fd_bn254_pairing_is_one_syscall(result, input, (unsigned long)input_sz, big_endian, 1);
        break;
    default:
        ret = -1;
    }

    /* simplify_alt_bn128_syscall_error_codes: all errors return 1 */
    return (ret == 0) ? 0 : 1;
}

static uint64_t
syscall_sol_alt_bn128_compression(
    sol_bpf_vm_t* vm,
    uint64_t op,
    uint64_t input_addr,
    uint64_t input_sz,
    uint64_t result_addr,
    uint64_t arg5
) {
    (void)arg5;

    uint64_t cu_cost;
    uint64_t expected_input_sz;
    uint64_t output_sz;

    switch (op) {
    case ALT_BN128_G1_COMPRESS:
        cu_cost = ALT_BN128_G1_COMPRESS_CU;
        expected_input_sz = 64;
        output_sz = 32;
        break;
    case ALT_BN128_G1_DECOMPRESS:
        cu_cost = ALT_BN128_G1_DECOMPRESS_CU;
        expected_input_sz = 32;
        output_sz = 64;
        break;
    case ALT_BN128_G2_COMPRESS:
        cu_cost = ALT_BN128_G2_COMPRESS_CU;
        expected_input_sz = 128;
        output_sz = 64;
        break;
    case ALT_BN128_G2_DECOMPRESS:
        cu_cost = ALT_BN128_G2_DECOMPRESS_CU;
        expected_input_sz = 64;
        output_sz = 128;
        break;
    default:
        return 1;
    }

    if (!consume_compute(vm, cu_cost)) return 1;

    /* Input size must exactly match */
    if (input_sz != expected_input_sz) return 1;

    /* Translate buffers */
    uint8_t* input = sol_bpf_memory_translate(&vm->memory, input_addr, input_sz, false);
    if (input == NULL) return 1;

    uint8_t* result = sol_bpf_memory_translate(&vm->memory, result_addr, output_sz, true);
    if (result == NULL) return 1;

    int big_endian = 1;
    void* ret = NULL;

    switch (op) {
    case ALT_BN128_G1_COMPRESS:
        ret = fd_bn254_g1_compress(result, input, big_endian);
        break;
    case ALT_BN128_G1_DECOMPRESS:
        ret = fd_bn254_g1_decompress(result, input, big_endian);
        break;
    case ALT_BN128_G2_COMPRESS:
        ret = fd_bn254_g2_compress(result, input, big_endian);
        break;
    case ALT_BN128_G2_DECOMPRESS:
        ret = fd_bn254_g2_decompress(result, input, big_endian);
        break;
    }

    return (ret != NULL) ? 0 : 1;
}

static uint64_t
syscall_sol_big_mod_exp(
    sol_bpf_vm_t* vm,
    uint64_t params_addr, uint64_t result_addr, uint64_t arg3,
    uint64_t arg4, uint64_t arg5
) {
    (void)arg3; (void)arg4; (void)arg5;

#if SOL_USE_OPENSSL
    /* BigModExpParams: { base: *u8, base_len: u64, exponent: *u8, exponent_len: u64, modulus: *u8, modulus_len: u64 } = 48 bytes */
    uint8_t* params = sol_bpf_memory_translate(&vm->memory, params_addr, 48, false);
    if (params == NULL) return 1;

    uint64_t base_ptr     = *(uint64_t*)(params + 0);
    uint64_t base_len     = *(uint64_t*)(params + 8);
    uint64_t exp_ptr      = *(uint64_t*)(params + 16);
    uint64_t exp_len      = *(uint64_t*)(params + 24);
    uint64_t mod_ptr      = *(uint64_t*)(params + 32);
    uint64_t mod_len      = *(uint64_t*)(params + 40);

    /* Each length must be <= 512 */
    if (base_len > 512 || exp_len > 512 || mod_len > 512) return 1;

    /* CU cost: syscall_base(100) + input_len^2/2 + big_mod_exp_base(190) */
    uint64_t input_len = base_len;
    if (exp_len > input_len) input_len = exp_len;
    if (mod_len > input_len) input_len = mod_len;
    uint64_t cu_cost = SOL_CU_SYSCALL_BASE + (input_len * input_len) / 2 + 190;
    if (!consume_compute(vm, cu_cost)) return 1;

    /* Translate output buffer (modulus_len bytes) */
    uint8_t* result = sol_bpf_memory_translate(&vm->memory, result_addr, mod_len, true);
    if (result == NULL) return 1;

    /* If modulus_len is 0, nothing to do */
    if (mod_len == 0) return 0;

    /* Translate input buffers */
    uint8_t* base_buf = (base_len > 0) ? sol_bpf_memory_translate(&vm->memory, base_ptr, base_len, false) : NULL;
    uint8_t* exp_buf  = (exp_len > 0)  ? sol_bpf_memory_translate(&vm->memory, exp_ptr, exp_len, false) : NULL;
    uint8_t* mod_buf  = sol_bpf_memory_translate(&vm->memory, mod_ptr, mod_len, false);

    if ((base_len > 0 && base_buf == NULL) || (exp_len > 0 && exp_buf == NULL) || mod_buf == NULL) return 1;

    /* Convert from big-endian bytes to BIGNUMs */
    BIGNUM *bn_base = BN_new();
    BIGNUM *bn_exp  = BN_new();
    BIGNUM *bn_mod  = BN_new();
    BIGNUM *bn_result = BN_new();

    if (!bn_base || !bn_exp || !bn_mod || !bn_result) goto bn_fail;

    if (base_len > 0)
        BN_bin2bn(base_buf, (int)base_len, bn_base);
    else
        BN_zero(bn_base);

    if (exp_len > 0)
        BN_bin2bn(exp_buf, (int)exp_len, bn_exp);
    else
        BN_zero(bn_exp);

    BN_bin2bn(mod_buf, (int)mod_len, bn_mod);

    /* If modulus is 0 or 1, result is all zeros */
    if (BN_is_zero(bn_mod) || BN_is_one(bn_mod)) {
        memset(result, 0, mod_len);
        BN_free(bn_base); BN_free(bn_exp); BN_free(bn_mod); BN_free(bn_result);
        return 0;
    }

    /* Compute base^exp mod modulus */
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) goto bn_fail;

    if (!BN_mod_exp(bn_result, bn_base, bn_exp, bn_mod, ctx)) {
        BN_CTX_free(ctx);
        goto bn_fail;
    }
    BN_CTX_free(ctx);

    /* Convert result to big-endian bytes, zero-padded to mod_len */
    int result_bytes = BN_num_bytes(bn_result);
    memset(result, 0, mod_len);
    if (result_bytes > 0) {
        BN_bn2bin(bn_result, result + (mod_len - (uint64_t)result_bytes));
    }

    BN_free(bn_base); BN_free(bn_exp); BN_free(bn_mod); BN_free(bn_result);
    return 0;

bn_fail:
    if (bn_base) BN_free(bn_base);
    if (bn_exp) BN_free(bn_exp);
    if (bn_mod) BN_free(bn_mod);
    if (bn_result) BN_free(bn_result);
    return 1;
#else
    (void)params_addr; (void)result_addr;
    if (!consume_compute(vm, SOL_CU_SYSCALL_BASE)) return 1;
    return 1;  /* OpenSSL not available */
#endif
}

/*
 * Register all Solana syscalls
 */
sol_err_t
sol_bpf_register_syscalls(sol_bpf_vm_t* vm) {
    if (vm == NULL) {
        return SOL_ERR_INVAL;
    }

#define REGISTER(name, fn) \
    do { \
        sol_err_t err = sol_bpf_vm_register_syscall(vm, name, fn); \
        if (err != SOL_OK) return err; \
    } while(0)

    /* Logging */
    REGISTER("sol_log_", syscall_sol_log);
    REGISTER("sol_log_64_", syscall_sol_log_64);
    REGISTER("sol_log_pubkey", syscall_sol_log_pubkey);
    REGISTER("sol_log_compute_units_", syscall_sol_log_compute_units);
    REGISTER("sol_log_data", syscall_sol_log_data);

    /* Cryptography */
    REGISTER("sol_sha256", syscall_sol_sha256);
    REGISTER("sol_keccak256", syscall_sol_keccak256);
    REGISTER("sol_secp256k1_recover", syscall_sol_secp256k1_recover);
    REGISTER("sol_blake3", syscall_sol_blake3);

    /* PDA */
    REGISTER("sol_create_program_address", syscall_sol_create_program_address);
    REGISTER("sol_try_find_program_address", syscall_sol_try_find_program_address);

    /* Memory */
    REGISTER("sol_memcpy_", syscall_sol_memcpy);
    REGISTER("sol_memmove_", syscall_sol_memmove);
    REGISTER("sol_memcmp_", syscall_sol_memcmp);
    REGISTER("sol_memset_", syscall_sol_memset);
    REGISTER("sol_alloc_free_", syscall_sol_alloc_free);

    /* Program control */
    REGISTER("abort", syscall_abort);
    REGISTER("sol_panic_", syscall_sol_panic);

    /* Compute */
    REGISTER("sol_remaining_compute_units", syscall_sol_remaining_compute_units);

    /* Sysvars */
    REGISTER("sol_get_sysvar", syscall_sol_get_sysvar);
    REGISTER("sol_get_clock_sysvar", syscall_sol_get_clock_sysvar);
    REGISTER("sol_get_rent_sysvar", syscall_sol_get_rent_sysvar);
    REGISTER("sol_get_epoch_schedule_sysvar", syscall_sol_get_epoch_schedule_sysvar);
    REGISTER("sol_get_fees_sysvar", syscall_sol_get_fees_sysvar);
    REGISTER("sol_get_last_restart_slot", syscall_sol_get_last_restart_slot);
    REGISTER("sol_get_epoch_rewards_sysvar", syscall_sol_get_epoch_rewards_sysvar);
    REGISTER("sol_get_epoch_stake", syscall_sol_get_epoch_stake);

    /* Instruction introspection */
    REGISTER("sol_get_processed_sibling_instruction",
             syscall_sol_get_processed_sibling_instruction);

    /* Curve25519 operations */
    REGISTER("sol_curve_group_op", syscall_sol_curve_group_op);
    REGISTER("sol_curve_validate_point", syscall_sol_curve_point_validation);
    REGISTER("sol_curve_multiscalar_mul", syscall_sol_curve_multiscalar_multiplication);

    /* Crypto stubs (return error but don't crash VM) */
    REGISTER("sol_poseidon", syscall_sol_poseidon);
    REGISTER("sol_alt_bn128_group_op", syscall_sol_alt_bn128_group_op);
    REGISTER("sol_alt_bn128_compression", syscall_sol_alt_bn128_compression);
    REGISTER("sol_big_mod_exp", syscall_sol_big_mod_exp);

#undef REGISTER

    return SOL_OK;
}
