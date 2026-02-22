/*
 * sol_config_program.c - Config Program Implementation
 */

#include "sol_config_program.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include "../runtime/sol_bank.h"
#include <string.h>

/* SOL_CONFIG_PROGRAM_ID is defined in sol_types.c */

/*
 * Size of a serialized config key
 */
#define CONFIG_KEY_SIZE 33

/*
 * Get account from context
 */
static sol_err_t
get_account(sol_invoke_context_t* ctx, uint8_t index,
            const sol_pubkey_t** pubkey, sol_account_t** account) {
    if (index >= ctx->account_indices_len) {
        return SOL_ERR_PROGRAM_MISSING_ACCOUNT;
    }

    uint8_t key_index = ctx->account_indices[index];
    if (key_index >= ctx->account_keys_len) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    *pubkey = &ctx->account_keys[key_index];
    sol_slot_t ss = 0;
    *account = sol_bank_load_account_ex(ctx->bank, *pubkey, &ss);

    /* Simulate Agave's clean_accounts: only filter snapshot-era zombies */
    sol_slot_t zfs = sol_bank_zombie_filter_slot(ctx->bank);
    if (*account && (*account)->meta.lamports == 0 && zfs > 0 && ss <= zfs) {
        sol_account_destroy(*account);
        *account = NULL;
    }

    /* Agave creates a default account for any key not in the DB */
    if (!*account) {
        *account = sol_calloc(1, sizeof(sol_account_t));
        if (*account) {
            (*account)->meta.owner = SOL_SYSTEM_PROGRAM_ID;
            (*account)->meta.rent_epoch = UINT64_MAX;
        }
    }

    return SOL_OK;
}

void
sol_config_state_init(sol_config_state_t* state) {
    if (!state) return;
    memset(state, 0, sizeof(sol_config_state_t));
}

void
sol_config_state_free(sol_config_state_t* state) {
    if (!state) return;
    sol_free(state->keys);
    sol_free(state->data);
    state->keys = NULL;
    state->keys_len = 0;
    state->data = NULL;
    state->data_len = 0;
}

sol_err_t
sol_config_deserialize(sol_config_state_t* state, const uint8_t* data, size_t len) {
    if (!state || !data) return SOL_ERR_INVAL;
    if (len < 2) return SOL_ERR_TRUNCATED;

    sol_config_state_init(state);

    size_t offset = 0;

    /* Number of keys (u16 le) */
    uint16_t num_keys;
    memcpy(&num_keys, data + offset, 2);
    offset += 2;

    if (num_keys > SOL_CONFIG_MAX_KEYS) {
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    /* Check we have enough data for keys */
    size_t keys_size = num_keys * CONFIG_KEY_SIZE;
    if (offset + keys_size > len) {
        return SOL_ERR_TRUNCATED;
    }

    /* Allocate and read keys */
    if (num_keys > 0) {
        state->keys = sol_alloc(num_keys * sizeof(sol_config_key_t));
        if (!state->keys) return SOL_ERR_NOMEM;

        for (uint16_t i = 0; i < num_keys; i++) {
            memcpy(state->keys[i].pubkey.bytes, data + offset, 32);
            offset += 32;
            state->keys[i].is_signer = data[offset] != 0;
            offset += 1;
        }
        state->keys_len = num_keys;
    }

    /* Remaining data is config data */
    size_t data_len = len - offset;
    if (data_len > 0) {
        state->data = sol_alloc(data_len);
        if (!state->data) {
            sol_free(state->keys);
            state->keys = NULL;
            state->keys_len = 0;
            return SOL_ERR_NOMEM;
        }
        memcpy(state->data, data + offset, data_len);
        state->data_len = data_len;
    }

    return SOL_OK;
}

sol_err_t
sol_config_serialize(const sol_config_state_t* state, uint8_t* data, size_t len,
                     size_t* written) {
    if (!state || !data || !written) return SOL_ERR_INVAL;

    size_t needed = sol_config_account_size(state->keys_len, state->data_len);
    if (len < needed) return SOL_ERR_OVERFLOW;

    size_t offset = 0;

    /* Number of keys (u16 le) */
    memcpy(data + offset, &state->keys_len, 2);
    offset += 2;

    /* Keys */
    for (uint16_t i = 0; i < state->keys_len; i++) {
        memcpy(data + offset, state->keys[i].pubkey.bytes, 32);
        offset += 32;
        data[offset] = state->keys[i].is_signer ? 1 : 0;
        offset += 1;
    }

    /* Config data */
    if (state->data_len > 0 && state->data) {
        memcpy(data + offset, state->data, state->data_len);
        offset += state->data_len;
    }

    *written = offset;
    return SOL_OK;
}

size_t
sol_config_account_size(uint16_t num_keys, size_t data_len) {
    return 2 + (num_keys * CONFIG_KEY_SIZE) + data_len;
}

/*
 * Verify signers match required config keys
 */
static bool
verify_config_signers(const sol_config_state_t* state,
                      sol_invoke_context_t* ctx) {
    if (!state) return false;

    /* Check each key that requires signature */
    for (uint16_t i = 0; i < state->keys_len; i++) {
        if (!state->keys[i].is_signer) continue;

        /* Look for this key in the transaction accounts and verify it's a signer */
        bool found_signer = false;
        for (uint8_t j = 0; j < ctx->account_keys_len; j++) {
            if (sol_pubkey_eq(&ctx->account_keys[j], &state->keys[i].pubkey)) {
                /* Verify this account index is actually a signer.
                 * Signers are the first num_signers accounts in the message. */
                if (j < ctx->num_signers) {
                    found_signer = true;
                }
                break;
            }
        }

        if (!found_signer) {
            sol_log_debug("Missing required signer for config key %u", i);
            return false;
        }
    }

    return true;
}

/*
 * Execute Store instruction
 */
static sol_err_t
execute_store(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 1) {
        return SOL_ERR_PROGRAM_MISSING_ACCOUNT;
    }
    if (ctx->instruction_data_len < 2) {
        return SOL_ERR_INVAL;
    }

    const sol_pubkey_t* config_pubkey;
    sol_account_t* config_account;
    SOL_TRY(get_account(ctx, 0, &config_pubkey, &config_account));

    /* Parse instruction data */
    const uint8_t* data = ctx->instruction_data;
    size_t offset = 0;

    /* Number of keys in instruction */
    uint16_t num_keys;
    memcpy(&num_keys, data + offset, 2);
    offset += 2;

    if (num_keys > SOL_CONFIG_MAX_KEYS) {
        sol_account_destroy(config_account);
        return SOL_ERR_INVAL;
    }

    /* Check we have enough data */
    size_t keys_size = num_keys * CONFIG_KEY_SIZE;
    if (offset + keys_size > ctx->instruction_data_len) {
        sol_account_destroy(config_account);
        return SOL_ERR_TRUNCATED;
    }

    /* Parse keys from instruction */
    sol_config_key_t* new_keys = NULL;
    if (num_keys > 0) {
        new_keys = sol_alloc(num_keys * sizeof(sol_config_key_t));
        if (!new_keys) {
            sol_account_destroy(config_account);
            return SOL_ERR_NOMEM;
        }

        for (uint16_t i = 0; i < num_keys; i++) {
            memcpy(new_keys[i].pubkey.bytes, data + offset, 32);
            offset += 32;
            new_keys[i].is_signer = data[offset] != 0;
            offset += 1;
        }
    }

    /* Remaining data is the new config data */
    size_t new_data_len = ctx->instruction_data_len - offset;
    const uint8_t* new_data = data + offset;

    /* If account has existing data, verify signers */
    if (config_account && config_account->meta.data_len > 0 && config_account->data != NULL) {
        sol_config_state_t current_state;
        sol_err_t err = sol_config_deserialize(&current_state, config_account->data,
                                                config_account->meta.data_len);
        if (err == SOL_OK) {
            /* Verify signers from current state */
            if (!verify_config_signers(&current_state, ctx)) {
                sol_config_state_free(&current_state);
                sol_free(new_keys);
                sol_account_destroy(config_account);
                return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
            }
            sol_config_state_free(&current_state);
        }
    }

    /* Build new state */
    sol_config_state_t new_state;
    sol_config_state_init(&new_state);
    new_state.keys = new_keys;
    new_state.keys_len = num_keys;

    if (new_data_len > 0) {
        new_state.data = sol_alloc(new_data_len);
        if (!new_state.data) {
            sol_free(new_keys);
            sol_account_destroy(config_account);
            return SOL_ERR_NOMEM;
        }
        memcpy(new_state.data, new_data, new_data_len);
        new_state.data_len = new_data_len;
    }

    /* Calculate new account size */
    size_t new_account_size = sol_config_account_size(num_keys, new_data_len);

    /* Create or resize account */
    if (!config_account) {
        config_account = sol_account_new(0, new_account_size, &SOL_CONFIG_PROGRAM_ID);
        if (!config_account) {
            sol_config_state_free(&new_state);
            return SOL_ERR_NOMEM;
        }
    } else if (new_account_size > config_account->meta.data_len) {
        sol_err_t err = sol_account_resize(config_account, new_account_size);
        if (err != SOL_OK) {
            sol_config_state_free(&new_state);
            sol_account_destroy(config_account);
            return err;
        }
    }

    /* Serialize new state to account */
    size_t written;
    sol_err_t err = sol_config_serialize(&new_state, config_account->data,
                                          config_account->meta.data_len, &written);

    /* Set owner if not already set */
    if (err == SOL_OK) {
        config_account->meta.owner = SOL_CONFIG_PROGRAM_ID;
        sol_bank_store_account(ctx->bank, config_pubkey, config_account);
    }

    sol_config_state_free(&new_state);
    sol_account_destroy(config_account);

    sol_log_debug("Config store: %u keys, %zu bytes data",
                  (unsigned)num_keys, new_data_len);

    return err;
}

sol_err_t
sol_config_process(sol_invoke_context_t* ctx) {
    if (!ctx || !ctx->instruction_data) {
        return SOL_ERR_INVAL;
    }

    /* Config program only has Store instruction, no type byte needed */
    return execute_store(ctx);
}
