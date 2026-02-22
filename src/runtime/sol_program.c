/*
 * sol_program.c - Program Dispatch
 */

#include "sol_program.h"
#include "sol_bank.h"
#include "../util/sol_log.h"
#include "../programs/sol_vote_program.h"
#include "../programs/sol_stake_program.h"
#include "../programs/sol_config_program.h"
#include "../programs/sol_address_lookup_table_program.h"
#include "../programs/sol_token_program.h"
#include "../programs/sol_bpf_loader_program.h"
#include "../programs/sol_ed25519_program.h"
#include "../programs/sol_secp256k1_program.h"
#include "../programs/sol_secp256r1_program.h"

static uint64_t
program_base_compute_units(const sol_pubkey_t* program_id) {
    /* Base compute-unit cost charged from the compute meter before a
       builtin program's process_instruction runs.  These values match
       Agave's BUILTIN_INSTRUCTION_COSTS (solana-cost-model).

       BPF programs (everything that is NOT a builtin) must return 0
       here because all CU tracking for BPF execution happens inside
       the BPF VM; Agave never charges a flat base cost for them. */

    if (sol_pubkey_eq(program_id, &SOL_SYSTEM_PROGRAM_ID))    return 150;
    if (sol_pubkey_eq(program_id, &SOL_COMPUTE_BUDGET_ID))    return 150;
    if (sol_pubkey_eq(program_id, &SOL_VOTE_PROGRAM_ID))      return 2100;
    /* Stake, Config, and ALT are migrated builtins (BPF programs on mainnet).
       They no longer have builtin CU costs -- all CU tracking happens in the VM. */

    /* BPF loaders: charged only when invoked directly (deploy/upgrade/etc.),
       NOT when executing a BPF program on behalf of the user. */
    if (sol_pubkey_eq(program_id, &SOL_BPF_LOADER_UPGRADEABLE_ID)) return 2370;
    if (sol_pubkey_eq(program_id, &SOL_BPF_LOADER_V2_ID))          return 570;

    /* Precompiles (ed25519, secp256k1, secp256r1): verification happens
       during transaction loading in Agave; the execution-phase dispatch
       is a no-op that charges 0 CU from the compute meter. */

    /* Everything else (BPF programs) — no base cost. */
    return 0;
}

sol_err_t
sol_program_execute(sol_invoke_context_t* ctx) {
    if (ctx == NULL) {
        return SOL_ERR_INVAL;
    }

    const sol_pubkey_t* program_id = &ctx->program_id;

    if (ctx->compute_meter != NULL) {
        sol_err_t err = sol_compute_meter_consume(
            ctx->compute_meter, program_base_compute_units(program_id)
        );
        if (err != SOL_OK) {
            return err;
        }
    }

    /* Push instruction to trace (before execution, matching Agave push() semantics).
     * Resolve instruction account pubkeys from account_indices → account_keys. */
    if (ctx->instruction_trace != NULL && ctx->account_keys != NULL) {
        uint8_t sh = ctx->stack_height ? (uint8_t)ctx->stack_height : 1;
        uint8_t n = ctx->account_indices_len;
        sol_pubkey_t resolved_keys[64];
        bool resolved_signer[64];
        bool resolved_writable[64];
        if (n > 64) n = 64;
        for (uint8_t i = 0; i < n; i++) {
            uint8_t idx = ctx->account_indices ? ctx->account_indices[i] : i;
            if (idx < ctx->account_keys_len) {
                resolved_keys[i] = ctx->account_keys[idx];
                resolved_signer[i] = ctx->is_signer ? ctx->is_signer[idx] : false;
                resolved_writable[i] = ctx->is_writable ? ctx->is_writable[idx] : false;
            } else {
                memset(&resolved_keys[i], 0, sizeof(sol_pubkey_t));
                resolved_signer[i] = false;
                resolved_writable[i] = false;
            }
        }
        sol_instruction_trace_push(ctx->instruction_trace, sh, program_id,
                                    ctx->instruction_data, ctx->instruction_data_len,
                                    resolved_keys, resolved_signer, resolved_writable, n);
    }

    if (sol_pubkey_eq(program_id, &SOL_SYSTEM_PROGRAM_ID)) {
        return sol_system_program_execute(ctx);
    }

    if (sol_pubkey_eq(program_id, &SOL_VOTE_PROGRAM_ID)) {
        return sol_vote_program_execute(ctx);
    }

    if (sol_pubkey_eq(program_id, &SOL_COMPUTE_BUDGET_ID)) {
        return SOL_OK;
    }

    /* Stake, Config, AddressLookupTable, Token, and Associated Token Account
       programs are deployed BPF programs on mainnet (migrated builtins).
       They must be executed via the BPF VM (fall through to the generic
       executable-account path below) to ensure behavioral parity with Agave.
       Native implementations are kept for testing only. */

    if (sol_pubkey_eq(program_id, &SOL_ED25519_PROGRAM_ID)) {
        return sol_ed25519_program_execute(ctx);
    }

    if (sol_pubkey_eq(program_id, &SOL_SECP256K1_PROGRAM_ID)) {
        return sol_secp256k1_program_execute(ctx);
    }

    if (sol_pubkey_eq(program_id, &SOL_SECP256R1_PROGRAM_ID)) {
        return sol_secp256r1_program_execute(ctx);
    }

    if (sol_pubkey_eq(program_id, &SOL_BPF_LOADER_UPGRADEABLE_ID)) {
        return sol_bpf_upgradeable_loader_process(ctx);
    }

    if (sol_pubkey_eq(program_id, &SOL_BPF_LOADER_V2_ID)) {
        return sol_bpf_loader_2_process(ctx);
    }

    sol_accounts_db_t* accounts_db = ctx->bank ? sol_bank_get_accounts_db(ctx->bank) : NULL;
    if (accounts_db) {
        sol_account_t* program_account = sol_accounts_db_load(accounts_db, program_id);
        if (program_account && program_account->meta.executable) {
            sol_err_t err = sol_bpf_loader_execute_program(ctx, program_id);
            if (err == SOL_ERR_PROGRAM_INVALID_ACCOUNT) {
                char p58[SOL_PUBKEY_BASE58_LEN] = {0};
                sol_pubkey_to_base58(program_id, p58, sizeof(p58));
                sol_log_error("dispatch_diag: bpf_fallback returned -518 program=%s", p58);
            }
            sol_account_destroy(program_account);
            return err;
        }
        if (program_account) {
            char p58[SOL_PUBKEY_BASE58_LEN] = {0};
            sol_pubkey_to_base58(program_id, p58, sizeof(p58));
            sol_log_error("dispatch_diag: not_executable program=%s data_len=%zu",
                          p58, program_account->meta.data_len);
            sol_account_destroy(program_account);
        } else {
            char p58[SOL_PUBKEY_BASE58_LEN] = {0};
            sol_pubkey_to_base58(program_id, p58, sizeof(p58));
            sol_log_error("dispatch_diag: not_found program=%s", p58);
        }
    }

    sol_log_debug("Unknown program ID");
    return SOL_ERR_PROGRAM_NOT_FOUND;
}
