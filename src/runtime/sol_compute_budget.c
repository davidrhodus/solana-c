/*
 * sol_compute_budget.c - Compute Budget and Cost Model Implementation
 */

#include "sol_compute_budget.h"
#include "../util/sol_alloc.h"
#include <string.h>

/*
 * ComputeBudget program ID
 */
static const sol_pubkey_t COMPUTE_BUDGET_PROGRAM_ID = {{
    0x03, 0x06, 0x46, 0x6f, 0xe5, 0x21, 0x17, 0x32,
    0xff, 0xec, 0xad, 0xba, 0x72, 0xc3, 0x9b, 0xe7,
    0xbc, 0x8c, 0xe5, 0xbb, 0xc5, 0xf7, 0x12, 0x6b,
    0x2c, 0x43, 0x9b, 0x3a, 0x40, 0x00, 0x00, 0x00
}};

/*
 * Initialize compute budget with defaults
 */
void
sol_compute_budget_init(sol_compute_budget_t* budget) {
    if (!budget) return;
    *budget = (sol_compute_budget_t)SOL_COMPUTE_BUDGET_DEFAULT;
}

/*
 * Parse a single compute budget instruction
 */
static sol_err_t
parse_compute_budget_instruction(sol_compute_budget_t* budget,
                                  const uint8_t* data,
                                  size_t len) {
    if (len < 1) return SOL_ERR_INVAL;

    uint8_t instruction_type = data[0];

    switch (instruction_type) {
        case 0: /* RequestUnitsDeprecated */
            if (len < 9) return SOL_ERR_INVAL;
            {
                uint32_t units;
                uint32_t additional_fee_lamports;
                memcpy(&units, data + 1, 4);
                memcpy(&additional_fee_lamports, data + 5, 4);

                if (units == 0) {
                    return SOL_ERR_INVAL;
                }

                if (units > SOL_MAX_COMPUTE_UNITS) {
                    units = SOL_MAX_COMPUTE_UNITS;
                }

                budget->compute_unit_limit = units;

                /* additional_fee is in lamports; compute_unit_price uses micro-lamports */
                uint128 micro_fee = (uint128)additional_fee_lamports * (uint128)1000000;
                budget->compute_unit_price = (uint64_t)(micro_fee / (uint128)units);
            }
            break;

        case 1: /* RequestHeapFrame (deprecated) */
            if (len < 5) return SOL_ERR_INVAL;
            {
                uint32_t bytes;
                memcpy(&bytes, data + 1, 4);
                if (bytes > SOL_MAX_HEAP_BYTES || bytes < SOL_DEFAULT_HEAP_BYTES) {
                    return SOL_ERR_INVAL;
                }
                if ((bytes % 1024) != 0) {
                    return SOL_ERR_INVAL;
                }
                budget->heap_size = bytes;
                budget->uses_request_heap_frame = true;
            }
            break;

        case 2: /* SetComputeUnitLimit */
            if (len < 5) return SOL_ERR_INVAL;
            {
                uint32_t units;
                memcpy(&units, data + 1, 4);
                if (units > SOL_MAX_COMPUTE_UNITS) {
                    units = SOL_MAX_COMPUTE_UNITS;
                }
                /* No minimum clamping — Agave accepts any value from 0 to 1.4M */
                budget->compute_unit_limit = units;
            }
            break;

        case 3: /* SetComputeUnitPrice */
            if (len < 9) return SOL_ERR_INVAL;
            {
                uint64_t price;
                memcpy(&price, data + 1, 8);
                budget->compute_unit_price = price;
            }
            break;

        case 4: /* SetLoadedAccountsDataSizeLimit */
            if (len < 5) return SOL_ERR_INVAL;
            {
                uint32_t bytes;
                memcpy(&bytes, data + 1, 4);
                budget->loaded_accounts_data_size = bytes;
            }
            break;

        default:
            return SOL_ERR_INVAL;
    }

    return SOL_OK;
}

/*
 * BPF Loader Deprecated (BPFLoader1111111111111111111111111111111111)
 */
static const sol_pubkey_t SOL_BPF_LOADER_DEPRECATED_ID = {{
    0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x88, 0xa1, 0x6b,
    0xbd, 0x23, 0x95, 0x85, 0x5f, 0x64, 0x04, 0xd9,
    0xb4, 0xf4, 0x56, 0xb7, 0x82, 0x1b, 0xb0, 0x14,
    0x57, 0x49, 0x42, 0x8c, 0x00, 0x00, 0x00, 0x00
}};

/*
 * Loader v4 (LoaderV411111111111111111111111111111111111)
 */
static const sol_pubkey_t SOL_LOADER_V4_ID = {{
    0x05, 0x12, 0xb4, 0x11, 0x51, 0x51, 0xe3, 0x7a,
    0xad, 0x0a, 0x8b, 0xc5, 0xd3, 0x88, 0x2e, 0x7b,
    0x7f, 0xda, 0x4c, 0xf3, 0xd2, 0xc0, 0x28, 0xc8,
    0xcf, 0x83, 0x36, 0x18, 0x00, 0x00, 0x00, 0x00
}};

/*
 * Check if a program ID is a non-migratable builtin for default CU allocation.
 *
 * Matches Agave 3.1.8's BuiltinProgramsFilter. Non-migratable builtins get
 * 3,000 CU default allocation per instruction. All other programs (BPF +
 * migrated builtins like Stake, Config, ALT) get 200,000 CU each.
 *
 * This list does NOT include migrated builtins (Stake, Config, ALT, Secp256r1)
 * which are now BPF programs and get 200,000 CU.
 */
static bool
is_non_migratable_builtin(const sol_pubkey_t* program_id) {
    return sol_pubkey_eq(program_id, &SOL_SYSTEM_PROGRAM_ID) ||
           sol_pubkey_eq(program_id, &SOL_VOTE_PROGRAM_ID) ||
           sol_pubkey_eq(program_id, &COMPUTE_BUDGET_PROGRAM_ID) ||
           sol_pubkey_eq(program_id, &SOL_BPF_LOADER_UPGRADEABLE_ID) ||
           sol_pubkey_eq(program_id, &SOL_BPF_LOADER_V2_ID) ||
           sol_pubkey_eq(program_id, &SOL_BPF_LOADER_DEPRECATED_ID) ||
           sol_pubkey_eq(program_id, &SOL_LOADER_V4_ID) ||
           sol_pubkey_eq(program_id, &SOL_ED25519_PROGRAM_ID) ||
           sol_pubkey_eq(program_id, &SOL_SECP256K1_PROGRAM_ID);
}

/*
 * Parse compute budget instructions from transaction
 *
 * Matches Agave's process_compute_budget_instructions():
 * - RequestUnitsDeprecated (type 0) is rejected (feature active on mainnet)
 * - Duplicate instructions of the same type are rejected
 * - Unknown instruction types are rejected
 */
sol_err_t
sol_compute_budget_parse(sol_compute_budget_t* budget,
                         const sol_transaction_t* tx) {
    if (!budget || !tx) {
        return SOL_ERR_INVAL;
    }

    /* Start with defaults */
    sol_compute_budget_init(budget);

    const sol_pubkey_t* account_keys = tx->message.resolved_accounts_len
        ? tx->message.resolved_accounts
        : tx->message.account_keys;
    size_t account_keys_len = tx->message.resolved_accounts_len
        ? (size_t)tx->message.resolved_accounts_len
        : (size_t)tx->message.account_keys_len;

    bool has_explicit_limit = false;
    bool seen_heap_frame = false;
    bool seen_compute_unit_limit = false;
    bool seen_compute_unit_price = false;
    bool seen_loaded_accounts_data_size = false;

    /* Look for ComputeBudget program instructions */
    for (size_t i = 0; i < tx->message.instructions_len; i++) {
        const sol_compiled_instruction_t* ix = &tx->message.instructions[i];

        /* Check if this is a ComputeBudget instruction */
        if (ix->program_id_index >= account_keys_len) {
            continue;
        }

        const sol_pubkey_t* program_id = &account_keys[ix->program_id_index];
        if (!sol_pubkey_eq(program_id, &COMPUTE_BUDGET_PROGRAM_ID)) {
            continue;
        }

        if (ix->data_len < 1) {
            return SOL_ERR_PROGRAM_INVALID_INSTR;
        }

        uint8_t instruction_type = ix->data[0];

        switch (instruction_type) {
            case 0: /* RequestUnitsDeprecated */
                /* Deprecated but still accepted for backwards-compatibility.
                   This instruction sets BOTH the CU limit and CU price. */
                if (seen_compute_unit_limit || seen_compute_unit_price) {
                    return SOL_ERR_TX_DUPLICATE_INSTR;
                }
                seen_compute_unit_limit = true;
                seen_compute_unit_price = true;
                has_explicit_limit = true;
                break;

            case 1: /* RequestHeapFrame */
                if (seen_heap_frame) {
                    return SOL_ERR_TX_DUPLICATE_INSTR;
                }
                seen_heap_frame = true;
                break;

            case 2: /* SetComputeUnitLimit */
                if (seen_compute_unit_limit) {
                    return SOL_ERR_TX_DUPLICATE_INSTR;
                }
                seen_compute_unit_limit = true;
                has_explicit_limit = true;
                break;

            case 3: /* SetComputeUnitPrice */
                if (seen_compute_unit_price) {
                    return SOL_ERR_TX_DUPLICATE_INSTR;
                }
                seen_compute_unit_price = true;
                break;

            case 4: /* SetLoadedAccountsDataSizeLimit */
                if (seen_loaded_accounts_data_size) {
                    return SOL_ERR_TX_DUPLICATE_INSTR;
                }
                seen_loaded_accounts_data_size = true;
                break;

            default: /* Unknown instruction type */
                return SOL_ERR_PROGRAM_INVALID_INSTR;
        }

        /* Parse the instruction (applies the values) */
        sol_err_t err = parse_compute_budget_instruction(budget, ix->data, ix->data_len);
        if (err != SOL_OK) {
            return err;
        }
    }

    /* If no explicit compute unit limit was set, calculate per-instruction
       default matching Agave 3.1.8's BuiltinProgramsFilter behavior:
       - Count ALL instructions (including ComputeBudget)
       - Non-migratable builtins: 3,000 CU each
       - All other programs (BPF + migrated builtins): 200,000 CU each
       - Sum the per-instruction allocations */
    if (!has_explicit_limit) {
        uint32_t total = 0;
        for (size_t i = 0; i < tx->message.instructions_len; i++) {
            const sol_compiled_instruction_t* ix = &tx->message.instructions[i];
            if (ix->program_id_index >= account_keys_len) {
                total += SOL_DEFAULT_INSTRUCTION_COMPUTE_UNITS; /* 200,000 */
                continue;
            }
            const sol_pubkey_t* program_id = &account_keys[ix->program_id_index];
            if (is_non_migratable_builtin(program_id)) {
                total += SOL_MAX_BUILTIN_COMPUTE_UNITS; /* 3,000 */
            } else {
                total += SOL_DEFAULT_INSTRUCTION_COMPUTE_UNITS; /* 200,000 */
            }
        }
        if (total > SOL_MAX_COMPUTE_UNITS) {
            total = SOL_MAX_COMPUTE_UNITS;
        }
        budget->compute_unit_limit = total;
    }

    return SOL_OK;
}

/*
 * Calculate prioritization fee
 * Fee = ceil(compute_unit_limit * compute_unit_price / 1_000_000)
 *
 * Agave uses ceiling division (rounds up) when converting micro-lamports
 * to lamports. See compute-budget/src/compute_budget_limits.rs:
 *   micro_lamport_fee
 *       .saturating_add(MICRO_LAMPORTS_PER_LAMPORT.saturating_sub(1))
 *       .checked_div(MICRO_LAMPORTS_PER_LAMPORT)
 */
uint64_t
sol_compute_budget_priority_fee(const sol_compute_budget_t* budget) {
    if (!budget) return 0;

    /* Micro-lamports to lamports: ceiling division by 1M */
    uint128 fee = (uint128)budget->compute_unit_limit *
                  (uint128)budget->compute_unit_price;
    fee = (fee + 999999) / 1000000;

    /* Saturate to u64::MAX on overflow (matches Agave) */
    if (fee > (uint128)UINT64_MAX) return UINT64_MAX;
    return (uint64_t)fee;
}

/*
 * Initialize compute meter
 */
void
sol_compute_meter_init(sol_compute_meter_t* meter, uint64_t limit) {
    if (!meter) return;
    meter->remaining = limit;
    meter->consumed = 0;
    meter->limit = limit;
}

/*
 * Consume compute units
 */
sol_err_t
sol_compute_meter_consume(sol_compute_meter_t* meter, uint64_t units) {
    if (!meter) return SOL_ERR_INVAL;

    if (units > meter->remaining) {
        meter->remaining = 0;
        return SOL_ERR_PROGRAM_COMPUTE;
    }

    meter->remaining -= units;
    meter->consumed += units;
    return SOL_OK;
}

/*
 * Check if enough CUs remain
 */
bool
sol_compute_meter_check(const sol_compute_meter_t* meter, uint64_t units) {
    if (!meter) return false;
    return meter->remaining >= units;
}

/*
 * Get remaining CUs
 */
uint64_t
sol_compute_meter_remaining(const sol_compute_meter_t* meter) {
    if (!meter) return 0;
    return meter->remaining;
}

/*
 * Initialize cost model
 */
void
sol_cost_model_init(sol_cost_model_t* model, const sol_cost_model_config_t* config) {
    if (!model) return;

    if (config) {
        model->config = *config;
    } else {
        model->config = (sol_cost_model_config_t)SOL_COST_MODEL_CONFIG_DEFAULT;
    }

    model->block_cost = 0;
    model->vote_cost = 0;
    model->writable_accounts = 0;
    model->account_data_bytes = 0;
}

/*
 * Check if transaction is a simple vote
 */
static bool
is_simple_vote(const sol_transaction_t* tx) {
    /* A simple vote has exactly one instruction to the vote program */
    if (tx->message.instructions_len != 1) {
        return false;
    }

    const sol_compiled_instruction_t* ix = &tx->message.instructions[0];
    const sol_pubkey_t* account_keys = tx->message.resolved_accounts_len
        ? tx->message.resolved_accounts
        : tx->message.account_keys;
    size_t account_keys_len = tx->message.resolved_accounts_len
        ? (size_t)tx->message.resolved_accounts_len
        : (size_t)tx->message.account_keys_len;

    if (!account_keys || ix->program_id_index >= account_keys_len) {
        return false;
    }

    const sol_pubkey_t* program_id = &account_keys[ix->program_id_index];
    return sol_pubkey_eq(program_id, &SOL_VOTE_PROGRAM_ID);
}

/*
 * Calculate transaction cost
 */
sol_err_t
sol_cost_model_calculate(const sol_cost_model_t* model,
                         const sol_transaction_t* tx,
                         const sol_compute_budget_t* budget,
                         sol_tx_cost_t* out_cost) {
    if (!model || !tx || !out_cost) {
        return SOL_ERR_INVAL;
    }

    memset(out_cost, 0, sizeof(sol_tx_cost_t));

    /* Signature cost */
    out_cost->signature_cost = tx->signatures_len * model->config.signature_cost;

    /* Write lock cost - count writable accounts */
    size_t account_keys_len = tx->message.resolved_accounts_len
        ? (size_t)tx->message.resolved_accounts_len
        : (size_t)tx->message.account_keys_len;
    size_t writable_count = 0;
    for (size_t i = 0; i < account_keys_len; i++) {
        bool writable = false;

        if (tx->message.is_writable && tx->message.resolved_accounts_len != 0 &&
            i < tx->message.resolved_accounts_len) {
            writable = tx->message.is_writable[i];
        } else if (i < tx->message.account_keys_len) {
            writable = sol_message_is_writable_index(&tx->message, (uint8_t)i);
        } else {
            /* If we can't determine writability, be conservative. */
            writable = true;
        }

        if (writable) {
            writable_count++;
        }
    }
    out_cost->write_lock_cost = writable_count * model->config.write_lock_cost;

    /* Data bytes cost - sum instruction data */
    size_t data_bytes = 0;
    for (size_t i = 0; i < tx->message.instructions_len; i++) {
        data_bytes += tx->message.instructions[i].data_len;
    }
    out_cost->data_bytes_cost = data_bytes * model->config.data_byte_cost;

    /* Compute unit limit from budget */
    if (budget) {
        out_cost->compute_unit_limit = budget->compute_unit_limit;
    } else {
        out_cost->compute_unit_limit = SOL_DEFAULT_COMPUTE_UNITS;
    }

    /* Check if simple vote */
    out_cost->is_simple_vote = is_simple_vote(tx);

    /* Calculate total */
    out_cost->total_cost = out_cost->signature_cost +
                           out_cost->write_lock_cost +
                           out_cost->data_bytes_cost +
                           out_cost->compute_unit_limit;

    return SOL_OK;
}

/*
 * Check if transaction fits in block
 */
bool
sol_cost_model_would_fit(const sol_cost_model_t* model,
                         const sol_tx_cost_t* cost) {
    if (!model || !cost) return false;

    /* Check block limit */
    if (model->block_cost + cost->total_cost > model->config.max_block_units) {
        return false;
    }

    /* Check vote limit (if this is a vote) */
    if (cost->is_simple_vote) {
        if (model->vote_cost + cost->total_cost > model->config.max_vote_units) {
            return false;
        }
    }

    return true;
}

/*
 * Add transaction cost to block
 */
sol_err_t
sol_cost_model_add(sol_cost_model_t* model, const sol_tx_cost_t* cost) {
    if (!model || !cost) {
        return SOL_ERR_INVAL;
    }

    if (!sol_cost_model_would_fit(model, cost)) {
        return SOL_ERR_FULL;
    }

    model->block_cost += cost->total_cost;
    if (cost->is_simple_vote) {
        model->vote_cost += cost->total_cost;
    }

    return SOL_OK;
}

/*
 * Remove transaction cost (rollback)
 */
void
sol_cost_model_remove(sol_cost_model_t* model, const sol_tx_cost_t* cost) {
    if (!model || !cost) return;

    if (model->block_cost >= cost->total_cost) {
        model->block_cost -= cost->total_cost;
    } else {
        model->block_cost = 0;
    }

    if (cost->is_simple_vote) {
        if (model->vote_cost >= cost->total_cost) {
            model->vote_cost -= cost->total_cost;
        } else {
            model->vote_cost = 0;
        }
    }
}

/*
 * Reset cost model for new block
 */
void
sol_cost_model_reset(sol_cost_model_t* model) {
    if (!model) return;
    model->block_cost = 0;
    model->vote_cost = 0;
    model->writable_accounts = 0;
    model->account_data_bytes = 0;
}

/*
 * Get cost model stats
 */
void
sol_cost_model_stats(const sol_cost_model_t* model,
                     sol_cost_model_stats_t* out_stats) {
    if (!model || !out_stats) return;

    out_stats->block_utilization = model->config.max_block_units > 0 ?
        (double)model->block_cost / (double)model->config.max_block_units : 0.0;

    out_stats->vote_utilization = model->config.max_vote_units > 0 ?
        (double)model->vote_cost / (double)model->config.max_vote_units : 0.0;

    out_stats->accounts_utilization = model->config.max_writable_accounts > 0 ?
        (double)model->writable_accounts / (double)model->config.max_writable_accounts : 0.0;

    out_stats->data_utilization = model->config.max_account_data_bytes > 0 ?
        (double)model->account_data_bytes / (double)model->config.max_account_data_bytes : 0.0;
}
