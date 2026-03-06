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

static void
log_program_fallback_once(volatile uint32_t* once_flag, const char* msg) {
    if (!once_flag || !msg) {
        return;
    }
    if (__atomic_exchange_n(once_flag, 1u, __ATOMIC_RELAXED) == 0u) {
        sol_log_warn("%s", msg);
    }
}

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
     * For stack_height==1, syscall_sol_get_processed_sibling_instruction falls back
     * to ctx->transaction, so avoid heap allocations in the common case. */
    uint8_t sh = ctx->stack_height ? (uint8_t)ctx->stack_height : 1;
    if (sh > 1 && ctx->instruction_trace != NULL && ctx->account_keys != NULL) {
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

    /* Everything else should be treated as a deployed executable account and
     * executed through the BPF loader. The loader itself is responsible for
     * validating executable/owner/type. Avoid a redundant AccountsDB load here:
     * the BPF execution path is hot and caching happens inside the loader. */
    if (ctx->bank) {
        sol_err_t err = sol_bpf_loader_execute_program(ctx, program_id);
        if (err == SOL_ERR_PROGRAM_INVALID_ACCOUNT ||
            err == SOL_ERR_ACCOUNT_NOT_FOUND) {
            static volatile uint32_t stake_fallback_warned = 0u;
            static volatile uint32_t token_fallback_warned = 0u;
            static volatile uint32_t ata_fallback_warned = 0u;

            /* Migrated builtins (Stake, Config, ALT, Token) are BPF programs on
               mainnet and must execute via the VM.  However, unit tests commonly
               construct a minimal in-memory bank without these program accounts
               present.  Fall back to the native stake implementation in that
               specific case so CPI return-data tests can remain self-contained. */
            if (sol_pubkey_eq(program_id, &SOL_STAKE_PROGRAM_ID)) {
                log_program_fallback_once(&stake_fallback_warned,
                                          "Stake program account not found; falling back to native stake program");
                return sol_stake_program_execute(ctx);
            }
            if (sol_pubkey_eq(program_id, &SOL_TOKEN_PROGRAM_ID)) {
                log_program_fallback_once(&token_fallback_warned,
                                          "Token program account not found; falling back to native token program");
                return sol_token_program_execute(ctx);
            }
            if (sol_pubkey_eq(program_id, &SOL_ASSOCIATED_TOKEN_PROGRAM_ID)) {
                log_program_fallback_once(&ata_fallback_warned,
                                          "Associated Token program account not found; falling back to native associated token program");
                return sol_associated_token_program_execute(ctx);
            }
            return SOL_ERR_PROGRAM_NOT_FOUND;
        }
        return err;
    }

    return SOL_ERR_PROGRAM_NOT_FOUND;
}
