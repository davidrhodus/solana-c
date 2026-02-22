/*
 * sol_address_lookup_table_program.c - Address Lookup Table Program Implementation
 */

#include "sol_address_lookup_table_program.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include "../crypto/sol_sha256.h"
#include "../runtime/sol_bank.h"
#include <string.h>

/* SOL_ADDRESS_LOOKUP_TABLE_ID is defined in sol_types.c */

/*
 * Type discriminator for lookup table account
 */
#define ALT_TYPE_DISCRIMINATOR 1

/*
 * Slot indicating table is active (not deactivated)
 */
#define ALT_ACTIVE_SLOT UINT64_MAX

/*
 * Minimum rent-exempt balance calculation constant
 */
#define LAMPORTS_PER_BYTE_YEAR 3480

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

/*
 * Check if account at instruction index is a signer.
 * Uses ctx->is_signer[] array when available (required for V0 messages
 * with resolved accounts), falling back to num_signers check.
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

void
sol_alt_state_init(sol_alt_state_t* state) {
    if (!state) return;
    memset(state, 0, sizeof(sol_alt_state_t));
    state->meta.deactivation_slot = ALT_ACTIVE_SLOT;
}

void
sol_alt_state_free(sol_alt_state_t* state) {
    if (!state) return;
    sol_free(state->addresses);
    state->addresses = NULL;
    state->addresses_len = 0;
}

sol_err_t
sol_alt_deserialize(sol_alt_state_t* state, const uint8_t* data, size_t len) {
    if (!state || !data) return SOL_ERR_INVAL;
    if (len < SOL_ALT_METADATA_SIZE) return SOL_ERR_TRUNCATED;

    sol_alt_state_init(state);

    size_t offset = 0;

    /* Type discriminator (u32) */
    memcpy(&state->meta.type_discriminator, data + offset, 4);
    offset += 4;

    if (state->meta.type_discriminator != ALT_TYPE_DISCRIMINATOR) {
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    /* Deactivation slot (u64) */
    memcpy(&state->meta.deactivation_slot, data + offset, 8);
    offset += 8;

    /* Last extended slot (u64) */
    memcpy(&state->meta.last_extended_slot, data + offset, 8);
    offset += 8;

    /* Last extended slot start index (u8) */
    state->meta.last_extended_slot_start_index = data[offset];
    offset += 1;

    /* Authority (Option<Pubkey>): has_authority flag at byte 21, pubkey at 22..54 */
    state->meta.has_authority = data[offset];
    offset += 1;

    if (state->meta.has_authority) {
        memcpy(state->meta.authority.bytes, data + offset, 32);
    }
    offset += 32;

    /* Padding to 56 bytes */
    offset = SOL_ALT_METADATA_SIZE;

    /* Calculate number of addresses */
    size_t addresses_data_len = len - SOL_ALT_METADATA_SIZE;
    size_t num_addresses = addresses_data_len / 32;

    if (num_addresses > SOL_ALT_MAX_ADDRESSES) {
        num_addresses = SOL_ALT_MAX_ADDRESSES;
    }

    state->addresses_len = (uint16_t)num_addresses;

    if (num_addresses > 0) {
        state->addresses = sol_alloc(num_addresses * sizeof(sol_pubkey_t));
        if (!state->addresses) return SOL_ERR_NOMEM;

        for (size_t i = 0; i < num_addresses; i++) {
            memcpy(state->addresses[i].bytes, data + offset, 32);
            offset += 32;
        }
    }

    return SOL_OK;
}

sol_err_t
sol_alt_serialize(const sol_alt_state_t* state, uint8_t* data, size_t len,
                  size_t* written) {
    if (!state || !data || !written) return SOL_ERR_INVAL;

    size_t needed = SOL_ALT_METADATA_SIZE + ((size_t)state->addresses_len * 32);
    if (len < needed) return SOL_ERR_OVERFLOW;

    size_t offset = 0;

    /* Type discriminator (u32) */
    uint32_t discriminator = ALT_TYPE_DISCRIMINATOR;
    memcpy(data + offset, &discriminator, 4);
    offset += 4;

    /* Deactivation slot (u64) */
    memcpy(data + offset, &state->meta.deactivation_slot, 8);
    offset += 8;

    /* Last extended slot (u64) */
    memcpy(data + offset, &state->meta.last_extended_slot, 8);
    offset += 8;

    /* Last extended slot start index (u8) */
    data[offset] = state->meta.last_extended_slot_start_index;
    offset += 1;

    /* Authority (Option<Pubkey>): has_authority at byte 21, pubkey at 22..54 */
    data[offset] = state->meta.has_authority;
    offset += 1;

    if (state->meta.has_authority) {
        memcpy(data + offset, state->meta.authority.bytes, 32);
    } else {
        memset(data + offset, 0, 32);
    }
    offset += 32;

    /* Padding to 56 bytes */
    while (offset < SOL_ALT_METADATA_SIZE) {
        data[offset++] = 0;
    }

    /* Addresses */
    for (uint16_t i = 0; i < state->addresses_len; i++) {
        memcpy(data + offset, state->addresses[i].bytes, 32);
        offset += 32;
    }

    *written = offset;
    return SOL_OK;
}

const sol_pubkey_t*
sol_alt_get_address(const sol_alt_state_t* state, uint8_t index) {
    if (!state || index >= state->addresses_len) {
        return NULL;
    }
    return &state->addresses[index];
}

bool
sol_alt_is_active(const sol_alt_state_t* state, sol_slot_t current_slot) {
    if (!state) return false;

    if (state->meta.deactivation_slot == ALT_ACTIVE_SLOT) {
        return true;
    }

    /* Table is deactivated - check if cooldown period has passed */
    /* Cooldown is 512 slots */
    /* Check for overflow before adding */
    if (state->meta.deactivation_slot > UINT64_MAX - 512) {
        return false;  /* Overflow would occur, consider inactive */
    }
    return current_slot < state->meta.deactivation_slot + 512;
}

sol_err_t
sol_alt_derive_address(const sol_pubkey_t* authority, uint64_t recent_slot,
                       sol_pubkey_t* out_address, uint8_t* out_bump) {
    if (!authority || !out_address) return SOL_ERR_INVAL;

    /* Seeds: [authority, recent_slot as le bytes] */
    uint8_t slot_bytes[8];
    memcpy(slot_bytes, &recent_slot, 8);

    /* Try bump seeds from 255 down to 0 */
    for (int bump = 255; bump >= 0; bump--) {
        sol_sha256_ctx_t ctx;
        sol_sha256_init(&ctx);

        /* Hash: authority || slot || bump || program_id || "ProgramDerivedAddress" */
        sol_sha256_update(&ctx, authority->bytes, 32);
        sol_sha256_update(&ctx, slot_bytes, 8);

        uint8_t bump_byte = (uint8_t)bump;
        sol_sha256_update(&ctx, &bump_byte, 1);

        sol_sha256_update(&ctx, SOL_ADDRESS_LOOKUP_TABLE_ID.bytes, 32);

        const char* pda_marker = "ProgramDerivedAddress";
        sol_sha256_update(&ctx, (const uint8_t*)pda_marker, 21);

        sol_sha256_t hash;
        sol_sha256_final(&ctx, &hash);

        memcpy(out_address->bytes, hash.bytes, 32);

        if (out_bump) *out_bump = bump_byte;
        return SOL_OK;
    }

    return SOL_ERR_NOTFOUND;
}

/*
 * Execute CreateLookupTable instruction
 */
static sol_err_t
execute_create(sol_invoke_context_t* ctx, sol_slot_t current_slot) {
    if (ctx->account_indices_len < 4) {
        return SOL_ERR_PROGRAM_MISSING_ACCOUNT;
    }
    if (ctx->instruction_data_len < 13) {
        return SOL_ERR_INVAL;
    }

    const sol_pubkey_t* table_pubkey;
    sol_account_t* table_account;
    SOL_TRY(get_account(ctx, 0, &table_pubkey, &table_account));

    const sol_pubkey_t* authority_pubkey;
    sol_account_t* authority_account;
    SOL_TRY(get_account(ctx, 1, &authority_pubkey, &authority_account));

    const sol_pubkey_t* payer_pubkey;
    sol_account_t* payer_account;
    SOL_TRY(get_account(ctx, 2, &payer_pubkey, &payer_account));

    /* Verify payer (account 2) is a signer */
    if (!is_signer(ctx, 2)) {
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        sol_account_destroy(payer_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Parse instruction data */
    const uint8_t* data = ctx->instruction_data;
    uint64_t recent_slot;
    memcpy(&recent_slot, data + 4, 8);  /* Skip 4-byte instruction type */
    uint8_t bump_seed = data[12];
    (void)bump_seed;  /* Used for derivation verification */

    /* Check table account is not already initialized */
    if (table_account && table_account->meta.data_len > 0 && table_account->data != NULL) {
        uint32_t discriminator = 0;
        memcpy(&discriminator, table_account->data, 4);
        if (discriminator == ALT_TYPE_DISCRIMINATOR) {
            sol_account_destroy(table_account);
            sol_account_destroy(authority_account);
            sol_account_destroy(payer_account);
            return SOL_ERR_PROGRAM_ACCOUNT_ALREADY_INIT;
        }
    }

    /* Calculate required space and rent */
    size_t space = SOL_ALT_METADATA_SIZE;
    uint64_t rent = sol_account_rent_exempt_minimum(space, LAMPORTS_PER_BYTE_YEAR, 2);

    /* Check payer has enough lamports */
    if (!payer_account || payer_account->meta.lamports < rent) {
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        sol_account_destroy(payer_account);
        return SOL_ERR_PROGRAM_INSUFFICIENT_FUNDS;
    }

    /* Create new table account if doesn't exist */
    if (!table_account) {
        table_account = sol_account_new(0, space, &SOL_ADDRESS_LOOKUP_TABLE_ID);
        if (!table_account) {
            sol_account_destroy(authority_account);
            sol_account_destroy(payer_account);
            return SOL_ERR_NOMEM;
        }
    } else {
        /* Resize existing account */
        sol_account_resize(table_account, space);
    }

    /* Initialize table state */
    sol_alt_state_t state;
    sol_alt_state_init(&state);
    state.meta.has_authority = 1;
    state.meta.authority = *authority_pubkey;
    state.meta.last_extended_slot = current_slot;
    state.meta.last_extended_slot_start_index = 0;

    /* Serialize to account */
    size_t written;
    sol_err_t err = sol_alt_serialize(&state, table_account->data, space, &written);
    if (err != SOL_OK) {
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        sol_account_destroy(payer_account);
        return err;
    }

    /* Transfer rent from payer (skip lamport transfer if self-referencing) */
    if (!sol_pubkey_eq(payer_pubkey, table_pubkey)) {
        payer_account->meta.lamports -= rent;
        table_account->meta.lamports += rent;
    }
    table_account->meta.owner = SOL_ADDRESS_LOOKUP_TABLE_ID;

    /* Store accounts back */
    sol_bank_store_account(ctx->bank, table_pubkey, table_account);
    if (!sol_pubkey_eq(payer_pubkey, table_pubkey)) {
        sol_bank_store_account(ctx->bank, payer_pubkey, payer_account);
    }

    sol_account_destroy(table_account);
    sol_account_destroy(authority_account);
    sol_account_destroy(payer_account);

    sol_log_debug("Created lookup table at slot %llu", (unsigned long long)recent_slot);

    return SOL_OK;
}

/*
 * Execute FreezeLookupTable instruction
 */
static sol_err_t
execute_freeze(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 2) {
        return SOL_ERR_PROGRAM_MISSING_ACCOUNT;
    }

    const sol_pubkey_t* table_pubkey;
    sol_account_t* table_account;
    SOL_TRY(get_account(ctx, 0, &table_pubkey, &table_account));

    const sol_pubkey_t* authority_pubkey;
    sol_account_t* authority_account;
    SOL_TRY(get_account(ctx, 1, &authority_pubkey, &authority_account));

    if (!table_account) {
        sol_account_destroy(authority_account);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    /* Verify account is owned by ALT program */
    if (!sol_pubkey_eq(&table_account->meta.owner, &SOL_ADDRESS_LOOKUP_TABLE_ID)) {
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Deserialize current state */
    sol_alt_state_t state;
    sol_err_t err = sol_alt_deserialize(&state, table_account->data,
                                         table_account->meta.data_len);
    if (err != SOL_OK) {
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        return err;
    }

    /* Check authority matches and is a signer */
    if (!state.meta.has_authority ||
        !sol_pubkey_eq(&state.meta.authority, authority_pubkey)) {
        sol_alt_state_free(&state);
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Verify authority signed the transaction */
    if (!is_signer(ctx, 1)) {
        sol_alt_state_free(&state);
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Remove authority (freeze) */
    state.meta.has_authority = 0;
    memset(&state.meta.authority, 0, sizeof(sol_pubkey_t));

    /* Serialize back */
    size_t written;
    err = sol_alt_serialize(&state, table_account->data,
                            table_account->meta.data_len, &written);

    sol_alt_state_free(&state);

    if (err == SOL_OK) {
        sol_bank_store_account(ctx->bank, table_pubkey, table_account);
    }

    sol_account_destroy(table_account);
    sol_account_destroy(authority_account);

    sol_log_debug("Froze lookup table");

    return err;
}

/*
 * Execute ExtendLookupTable instruction
 */
static sol_err_t
execute_extend(sol_invoke_context_t* ctx, sol_slot_t current_slot) {
    if (ctx->account_indices_len < 2) {
        return SOL_ERR_PROGRAM_MISSING_ACCOUNT;
    }
    if (ctx->instruction_data_len < 12) {
        return SOL_ERR_INVAL;
    }

    const sol_pubkey_t* table_pubkey;
    sol_account_t* table_account;
    SOL_TRY(get_account(ctx, 0, &table_pubkey, &table_account));

    const sol_pubkey_t* authority_pubkey;
    sol_account_t* authority_account;
    SOL_TRY(get_account(ctx, 1, &authority_pubkey, &authority_account));

    if (!table_account) {
        sol_account_destroy(authority_account);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    /* Verify account is owned by ALT program */
    if (!sol_pubkey_eq(&table_account->meta.owner, &SOL_ADDRESS_LOOKUP_TABLE_ID)) {
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Parse instruction: [0..4] = type, [4..12] = num_addresses (u64), [12..] = addresses */
    const uint8_t* data = ctx->instruction_data;
    uint64_t num_new_addresses;
    memcpy(&num_new_addresses, data + 4, 8);

    if (num_new_addresses == 0) {
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        return SOL_ERR_INVAL;
    }

    if (ctx->instruction_data_len < 12 + (num_new_addresses * 32)) {
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        return SOL_ERR_TRUNCATED;
    }

    /* Deserialize current state */
    sol_alt_state_t state;
    sol_err_t err = sol_alt_deserialize(&state, table_account->data,
                                         table_account->meta.data_len);
    if (err != SOL_OK) {
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        return err;
    }

    /* Check authority matches and is a signer */
    if (!state.meta.has_authority ||
        !sol_pubkey_eq(&state.meta.authority, authority_pubkey)) {
        sol_alt_state_free(&state);
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Verify authority signed the transaction */
    if (!is_signer(ctx, 1)) {
        sol_alt_state_free(&state);
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Check if table is active */
    if (state.meta.deactivation_slot != ALT_ACTIVE_SLOT) {
        sol_alt_state_free(&state);
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    /* Check total addresses won't exceed max */
    size_t new_total = state.addresses_len + num_new_addresses;
    if (new_total > SOL_ALT_MAX_ADDRESSES) {
        sol_alt_state_free(&state);
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        return SOL_ERR_PROGRAM_MAX_ACCOUNTS;
    }

    /* Calculate new account size */
    size_t new_data_len = SOL_ALT_METADATA_SIZE + (new_total * 32);

    /* Update metadata: only update last_extended_slot_start_index if
     * extending in a new slot (Agave preserves start_index within same slot) */
    uint16_t old_len = state.addresses_len;
    if (current_slot != state.meta.last_extended_slot) {
        state.meta.last_extended_slot = current_slot;
        state.meta.last_extended_slot_start_index = (uint8_t)old_len;
    }

    /* Reallocate addresses array */
    sol_pubkey_t* new_addresses = sol_realloc(state.addresses,
                                               new_total * sizeof(sol_pubkey_t));
    if (!new_addresses && new_total > 0) {
        sol_alt_state_free(&state);
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        return SOL_ERR_NOMEM;
    }
    state.addresses = new_addresses;

    /* Add new addresses */
    for (uint64_t i = 0; i < num_new_addresses; i++) {
        memcpy(state.addresses[old_len + i].bytes, data + 12 + (i * 32), 32);
    }
    state.addresses_len = (uint16_t)new_total;

    /* Reallocate account data */
    err = sol_account_resize(table_account, new_data_len);
    if (err != SOL_OK) {
        sol_alt_state_free(&state);
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        return err;
    }

    /* Serialize back */
    size_t written;
    err = sol_alt_serialize(&state, table_account->data,
                            table_account->meta.data_len, &written);
    sol_alt_state_free(&state);
    if (err != SOL_OK) {
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        return err;
    }

    /* Calculate rent-exempt minimum for new size and transfer from payer
     * if the table needs more lamports.  Agave uses native_invoke to CPI
     * into the system program; we do it directly as a builtin. */
    uint64_t rent_min = sol_account_rent_exempt_minimum(new_data_len, LAMPORTS_PER_BYTE_YEAR, 2);
    if (rent_min < 1) rent_min = 1;
    uint64_t lookup_table_lamports = table_account->meta.lamports;
    uint64_t required_lamports = (rent_min > lookup_table_lamports)
                                  ? (rent_min - lookup_table_lamports) : 0;

    sol_account_t* payer_account = NULL;
    const sol_pubkey_t* payer_pubkey = NULL;
    if (required_lamports > 0) {
        if (ctx->account_indices_len < 3) {
            sol_account_destroy(table_account);
            sol_account_destroy(authority_account);
            return SOL_ERR_PROGRAM_MISSING_ACCOUNT;
        }
        SOL_TRY_CLEANUP(get_account(ctx, 2, &payer_pubkey, &payer_account), {
            sol_account_destroy(table_account);
            sol_account_destroy(authority_account);
        });
        if (!is_signer(ctx, 2)) {
            sol_account_destroy(table_account);
            sol_account_destroy(authority_account);
            sol_account_destroy(payer_account);
            return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
        }
        if (!payer_account || payer_account->meta.lamports < required_lamports) {
            sol_account_destroy(table_account);
            sol_account_destroy(authority_account);
            sol_account_destroy(payer_account);
            return SOL_ERR_PROGRAM_INSUFFICIENT_FUNDS;
        }
        payer_account->meta.lamports -= required_lamports;
        table_account->meta.lamports += required_lamports;
    }

    /* Store accounts back */
    sol_bank_store_account(ctx->bank, table_pubkey, table_account);
    if (payer_account && payer_pubkey && !sol_pubkey_eq(payer_pubkey, table_pubkey)) {
        sol_bank_store_account(ctx->bank, payer_pubkey, payer_account);
    }

    sol_account_destroy(table_account);
    sol_account_destroy(authority_account);
    sol_account_destroy(payer_account);

    sol_log_debug("Extended lookup table with %llu addresses (transferred %llu lamports)",
                  (unsigned long long)num_new_addresses,
                  (unsigned long long)required_lamports);

    return SOL_OK;
}

/*
 * Execute DeactivateLookupTable instruction
 */
static sol_err_t
execute_deactivate(sol_invoke_context_t* ctx, sol_slot_t current_slot) {
    if (ctx->account_indices_len < 2) {
        return SOL_ERR_PROGRAM_MISSING_ACCOUNT;
    }

    const sol_pubkey_t* table_pubkey;
    sol_account_t* table_account;
    SOL_TRY(get_account(ctx, 0, &table_pubkey, &table_account));

    const sol_pubkey_t* authority_pubkey;
    sol_account_t* authority_account;
    SOL_TRY(get_account(ctx, 1, &authority_pubkey, &authority_account));

    if (!table_account) {
        sol_account_destroy(authority_account);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    /* Verify account is owned by ALT program */
    if (!sol_pubkey_eq(&table_account->meta.owner, &SOL_ADDRESS_LOOKUP_TABLE_ID)) {
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Deserialize current state */
    sol_alt_state_t state;
    sol_err_t err = sol_alt_deserialize(&state, table_account->data,
                                         table_account->meta.data_len);
    if (err != SOL_OK) {
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        return err;
    }

    /* Check authority matches and is a signer */
    if (!state.meta.has_authority ||
        !sol_pubkey_eq(&state.meta.authority, authority_pubkey)) {
        sol_alt_state_free(&state);
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Verify authority signed the transaction */
    if (!is_signer(ctx, 1)) {
        sol_alt_state_free(&state);
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Check not already deactivated */
    if (state.meta.deactivation_slot != ALT_ACTIVE_SLOT) {
        sol_alt_state_free(&state);
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    /* Set deactivation slot */
    state.meta.deactivation_slot = current_slot;

    /* Serialize back */
    size_t written;
    err = sol_alt_serialize(&state, table_account->data,
                            table_account->meta.data_len, &written);

    sol_alt_state_free(&state);

    if (err == SOL_OK) {
        sol_bank_store_account(ctx->bank, table_pubkey, table_account);
    }

    sol_account_destroy(table_account);
    sol_account_destroy(authority_account);

    sol_log_debug("Deactivated lookup table at slot %llu",
                  (unsigned long long)current_slot);

    return err;
}

/*
 * Execute CloseLookupTable instruction
 */
static sol_err_t
execute_close(sol_invoke_context_t* ctx, sol_slot_t current_slot) {
    if (ctx->account_indices_len < 3) {
        return SOL_ERR_PROGRAM_MISSING_ACCOUNT;
    }

    const sol_pubkey_t* table_pubkey;
    sol_account_t* table_account;
    SOL_TRY(get_account(ctx, 0, &table_pubkey, &table_account));

    const sol_pubkey_t* authority_pubkey;
    sol_account_t* authority_account;
    SOL_TRY(get_account(ctx, 1, &authority_pubkey, &authority_account));

    const sol_pubkey_t* recipient_pubkey;
    sol_account_t* recipient_account;
    SOL_TRY(get_account(ctx, 2, &recipient_pubkey, &recipient_account));

    if (!table_account) {
        sol_account_destroy(authority_account);
        sol_account_destroy(recipient_account);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    /* Verify account is owned by ALT program */
    if (!sol_pubkey_eq(&table_account->meta.owner, &SOL_ADDRESS_LOOKUP_TABLE_ID)) {
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        sol_account_destroy(recipient_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Deserialize current state */
    sol_alt_state_t state;
    sol_err_t err = sol_alt_deserialize(&state, table_account->data,
                                         table_account->meta.data_len);
    if (err != SOL_OK) {
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        sol_account_destroy(recipient_account);
        return err;
    }

    /* Check authority matches and is a signer */
    if (!state.meta.has_authority ||
        !sol_pubkey_eq(&state.meta.authority, authority_pubkey)) {
        sol_alt_state_free(&state);
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        sol_account_destroy(recipient_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Verify authority signed the transaction */
    if (!is_signer(ctx, 1)) {
        sol_alt_state_free(&state);
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        sol_account_destroy(recipient_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Check table is deactivated and cooldown has passed */
    if (state.meta.deactivation_slot == ALT_ACTIVE_SLOT) {
        sol_alt_state_free(&state);
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        sol_account_destroy(recipient_account);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    /* Cooldown period is 512 slots */
    if (current_slot < state.meta.deactivation_slot + 512) {
        sol_alt_state_free(&state);
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        sol_account_destroy(recipient_account);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    sol_alt_state_free(&state);

    /* Self-close: reject if table == recipient (Agave rejects double mut borrow) */
    if (sol_pubkey_eq(table_pubkey, recipient_pubkey)) {
        sol_account_destroy(table_account);
        sol_account_destroy(authority_account);
        if (recipient_account) sol_account_destroy(recipient_account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Transfer lamports to recipient */
    if (!recipient_account) {
        recipient_account = sol_account_new(0, 0, &SOL_SYSTEM_PROGRAM_ID);
    }
    if (recipient_account) {
        recipient_account->meta.lamports += table_account->meta.lamports;
        sol_bank_store_account(ctx->bank, recipient_pubkey, recipient_account);
    }

    /* Close table account */
    table_account->meta.lamports = 0;
    table_account->meta.data_len = 0;
    sol_free(table_account->data);
    table_account->data = NULL;
    sol_bank_store_account(ctx->bank, table_pubkey, table_account);

    sol_account_destroy(table_account);
    sol_account_destroy(authority_account);
    sol_account_destroy(recipient_account);

    sol_log_debug("Closed lookup table");

    return SOL_OK;
}

sol_err_t
sol_address_lookup_table_process(sol_invoke_context_t* ctx, sol_slot_t current_slot) {
    if (!ctx || !ctx->instruction_data) {
        return SOL_ERR_INVAL;
    }

    if (ctx->instruction_data_len < 4) {
        return SOL_ERR_INVAL;
    }

    uint32_t instruction_type;
    memcpy(&instruction_type, ctx->instruction_data, 4);

    switch (instruction_type) {
        case SOL_ALT_INSTR_CREATE:
            return execute_create(ctx, current_slot);

        case SOL_ALT_INSTR_FREEZE:
            return execute_freeze(ctx);

        case SOL_ALT_INSTR_EXTEND:
            return execute_extend(ctx, current_slot);

        case SOL_ALT_INSTR_DEACTIVATE:
            return execute_deactivate(ctx, current_slot);

        case SOL_ALT_INSTR_CLOSE:
            return execute_close(ctx, current_slot);

        default:
            return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
}
