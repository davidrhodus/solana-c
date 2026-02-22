/*
 * sol_token_program.c - SPL Token Program Implementation
 */

#include "sol_token_program.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include "../crypto/sol_ed25519.h"
#include "../crypto/sol_sha256.h"
#include "../runtime/sol_sysvar.h"
#include "../txn/sol_signature.h"
#include <string.h>
#include <stdio.h>

/*
 * Token Program ID: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
 */
const sol_pubkey_t SOL_TOKEN_PROGRAM_ID = {{
    0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93,
    0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
    0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91,
    0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9
}};

/*
 * Associated Token Program ID: ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL
 */
const sol_pubkey_t SOL_ASSOCIATED_TOKEN_PROGRAM_ID = {{
    0x8c, 0x97, 0x25, 0x8f, 0x4e, 0x24, 0x89, 0xf1,
    0xbb, 0x3d, 0x10, 0x29, 0x14, 0x8e, 0x0d, 0x83,
    0x0b, 0x5a, 0x13, 0x99, 0xda, 0xff, 0x10, 0x84,
    0x04, 0x8e, 0x7b, 0xd8, 0xdb, 0xe9, 0xf8, 0x59
}};

/*
 * Native SOL mint: So11111111111111111111111111111111111111112
 */
const sol_pubkey_t SOL_NATIVE_MINT = {{
    0x06, 0x9b, 0x88, 0x57, 0xfe, 0xab, 0x81, 0x84,
    0xfb, 0x68, 0x7f, 0x63, 0x46, 0x18, 0xc0, 0x35,
    0xda, 0xc4, 0x39, 0xdc, 0x1a, 0xeb, 0x3b, 0x55,
    0x98, 0xa0, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x01
}};

/*
 * Helper: Load account from context
 */
static sol_account_t*
load_account(sol_invoke_context_t* ctx, uint8_t account_idx) {
    if (account_idx >= ctx->account_indices_len) return NULL;

    uint8_t key_idx = ctx->account_indices[account_idx];
    if (key_idx >= ctx->account_keys_len) return NULL;

    const sol_pubkey_t* pubkey = &ctx->account_keys[key_idx];
    sol_slot_t ss = 0;
    sol_account_t* account = sol_bank_load_account_ex(ctx->bank, pubkey, &ss);
    /* Simulate Agave's clean_accounts: only filter snapshot-era zombies */
    sol_slot_t zfs = sol_bank_zombie_filter_slot(ctx->bank);
    if (account && account->meta.lamports == 0 && zfs > 0 && ss <= zfs) {
        sol_account_destroy(account);
        return NULL;
    }
    return account;
}

/*
 * Helper: Get account pubkey from context
 */
static const sol_pubkey_t*
get_account_pubkey(sol_invoke_context_t* ctx, uint8_t account_idx) {
    if (account_idx >= ctx->account_indices_len) return NULL;

    uint8_t key_idx = ctx->account_indices[account_idx];
    if (key_idx >= ctx->account_keys_len) return NULL;

    return &ctx->account_keys[key_idx];
}

static bool
get_mint_owner(sol_invoke_context_t* ctx, const sol_pubkey_t* mint, sol_pubkey_t* out_owner) {
    if (!ctx || !ctx->bank || !mint || !out_owner) {
        return false;
    }

    sol_account_t* mint_account = sol_bank_load_account(ctx->bank, mint);
    if (!mint_account) {
        return false;
    }

    *out_owner = mint_account->meta.owner;
    sol_account_destroy(mint_account);
    return true;
}

/*
 * Helper: Store account back to bank
 */
static sol_err_t
store_account(sol_invoke_context_t* ctx, uint8_t account_idx,
              const sol_account_t* account) {
    if (account_idx >= ctx->account_indices_len) return SOL_ERR_INVAL;

    uint8_t key_idx = ctx->account_indices[account_idx];
    if (key_idx >= ctx->account_keys_len) return SOL_ERR_INVAL;

    const sol_pubkey_t* pubkey = &ctx->account_keys[key_idx];
    return sol_bank_store_account(ctx->bank, pubkey, account);
}

/*
 * Helper: Check if account at index is a signer
 *
 * The transaction message header specifies how many signatures are required.
 * Account keys at indices 0..num_signers-1 are signers.
 */
static bool
is_signer(sol_invoke_context_t* ctx, uint8_t account_idx) {
    if (account_idx >= ctx->account_indices_len) {
        return false;
    }
    uint8_t key_idx = ctx->account_indices[account_idx];
    if (key_idx >= ctx->account_keys_len) {
        return false;
    }
    return key_idx < ctx->num_signers;
}

/*
 * Unpack mint from account data
 */
sol_err_t
sol_token_unpack_mint(const uint8_t* data, size_t len,
                      sol_token_mint_t* out_mint) {
    if (!data || !out_mint || len < SOL_TOKEN_MINT_SIZE) {
        return SOL_ERR_INVAL;
    }

    memcpy(out_mint, data, sizeof(sol_token_mint_t));

    if (!out_mint->is_initialized) {
        return SOL_ERR_UNINITIALIZED;
    }

    return SOL_OK;
}

/*
 * Pack mint to account data
 */
size_t
sol_token_pack_mint(const sol_token_mint_t* mint,
                    uint8_t* out_data, size_t max_len) {
    if (!mint || !out_data || max_len < SOL_TOKEN_MINT_SIZE) {
        return 0;
    }

    memcpy(out_data, mint, sizeof(sol_token_mint_t));
    return SOL_TOKEN_MINT_SIZE;
}

/*
 * Unpack token account from account data
 */
sol_err_t
sol_token_unpack_account(const uint8_t* data, size_t len,
                         sol_token_account_t* out_account) {
    if (!data || !out_account || len < SOL_TOKEN_ACCOUNT_SIZE) {
        return SOL_ERR_INVAL;
    }

    memcpy(out_account, data, sizeof(sol_token_account_t));

    if (out_account->state == SOL_TOKEN_ACCOUNT_STATE_UNINITIALIZED) {
        return SOL_ERR_UNINITIALIZED;
    }

    return SOL_OK;
}

/*
 * Pack token account to account data
 */
size_t
sol_token_pack_account(const sol_token_account_t* account,
                       uint8_t* out_data, size_t max_len) {
    if (!account || !out_data || max_len < SOL_TOKEN_ACCOUNT_SIZE) {
        return 0;
    }

    memcpy(out_data, account, sizeof(sol_token_account_t));
    return SOL_TOKEN_ACCOUNT_SIZE;
}

/*
 * Process InitializeMint instruction
 * Accounts: [mint, rent_sysvar]
 * Data: decimals (u8), mint_authority (pubkey), freeze_authority (option<pubkey>)
 */
static sol_err_t
process_initialize_mint(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 1) {
        return SOL_ERR_NOT_ENOUGH_KEYS;
    }

    if (ctx->instruction_data_len < 1 + 32) {
        return SOL_ERR_INVAL;
    }

    /* Load mint account */
    sol_account_t* mint_account = load_account(ctx, 0);
    if (!mint_account) {
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Check not already initialized */
    if (mint_account->meta.data_len >= SOL_TOKEN_MINT_SIZE) {
        sol_token_mint_t existing;
        if (sol_token_unpack_mint(mint_account->data, mint_account->meta.data_len,
                                   &existing) == SOL_OK) {
            sol_account_destroy(mint_account);
            return SOL_ERR_ALREADY_INITIALIZED;
        }
    }

    /* Parse instruction data */
    const uint8_t* data = ctx->instruction_data;
    uint8_t decimals = data[1];
    sol_pubkey_t mint_authority;
    memcpy(&mint_authority, &data[2], 32);

    /* Optional freeze authority */
    sol_pubkey_t freeze_authority = {0};
    bool has_freeze_authority = false;
    if (ctx->instruction_data_len >= 1 + 32 + 1 + 32) {
        has_freeze_authority = (data[34] == 1);
        if (has_freeze_authority) {
            memcpy(&freeze_authority, &data[35], 32);
        }
    }

    /* Initialize mint state */
    sol_token_mint_t mint = {0};
    mint.mint_authority_option = 1;
    mint.mint_authority = mint_authority;
    mint.supply = 0;
    mint.decimals = decimals;
    mint.is_initialized = true;
    mint.freeze_authority_option = has_freeze_authority ? 1 : 0;
    mint.freeze_authority = freeze_authority;

    /* Resize account data if needed */
    if (mint_account->meta.data_len < SOL_TOKEN_MINT_SIZE) {
        uint8_t* new_data = sol_alloc(SOL_TOKEN_MINT_SIZE);
        if (!new_data) {
            sol_account_destroy(mint_account);
            return SOL_ERR_NOMEM;
        }
        memset(new_data, 0, SOL_TOKEN_MINT_SIZE);
        sol_free(mint_account->data);
        mint_account->data = new_data;
        mint_account->meta.data_len = SOL_TOKEN_MINT_SIZE;
    }

    /* Pack mint state */
    sol_token_pack_mint(&mint, mint_account->data, mint_account->meta.data_len);

    /* Store account */
    sol_err_t err = store_account(ctx, 0, mint_account);
    sol_account_destroy(mint_account);

    return err;
}

/*
 * Process InitializeAccount instruction
 * Accounts: [account, mint, owner, rent_sysvar]
 */
static sol_err_t
process_initialize_account(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 3) {
        return SOL_ERR_NOT_ENOUGH_KEYS;
    }

    /* Load accounts */
    sol_account_t* token_account = load_account(ctx, 0);
    sol_account_t* mint_account = load_account(ctx, 1);
    const sol_pubkey_t* owner_pubkey = get_account_pubkey(ctx, 2);

    if (!token_account || !mint_account || !owner_pubkey) {
        if (token_account) sol_account_destroy(token_account);
        if (mint_account) sol_account_destroy(mint_account);
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Verify mint is initialized */
    sol_token_mint_t mint;
    sol_err_t err = sol_token_unpack_mint(mint_account->data,
                                          mint_account->meta.data_len, &mint);
    sol_account_destroy(mint_account);
    if (err != SOL_OK) {
        sol_account_destroy(token_account);
        return err;
    }

    /* Check account not already initialized */
    if (token_account->meta.data_len >= SOL_TOKEN_ACCOUNT_SIZE) {
        sol_token_account_t existing;
        if (sol_token_unpack_account(token_account->data,
                                      token_account->meta.data_len,
                                      &existing) == SOL_OK) {
            sol_account_destroy(token_account);
            return SOL_ERR_ALREADY_INITIALIZED;
        }
    }

    const sol_pubkey_t* mint_pubkey = get_account_pubkey(ctx, 1);

    /* Initialize account state */
    sol_token_account_t account = {0};
    account.mint = *mint_pubkey;
    account.owner = *owner_pubkey;
    account.amount = 0;
    account.delegate_option = 0;
    account.state = SOL_TOKEN_ACCOUNT_STATE_INITIALIZED;
    account.is_native_option = 0;
    account.delegated_amount = 0;
    account.close_authority_option = 0;

    /* Check if this is wrapped SOL */
    if (sol_pubkey_eq(mint_pubkey, &SOL_NATIVE_MINT)) {
        /* For native SOL, the token amount equals lamports minus rent */
        sol_rent_t rent = SOL_RENT_DEFAULT;
        uint64_t rent_exempt = sol_rent_minimum_balance(&rent, SOL_TOKEN_ACCOUNT_SIZE);
        if (token_account->meta.lamports > rent_exempt) {
            account.is_native_option = 1;
            account.is_native = rent_exempt;
            account.amount = token_account->meta.lamports - rent_exempt;
        }
    }

    /* Resize account data if needed */
    if (token_account->meta.data_len < SOL_TOKEN_ACCOUNT_SIZE) {
        uint8_t* new_data = sol_alloc(SOL_TOKEN_ACCOUNT_SIZE);
        if (!new_data) {
            sol_account_destroy(token_account);
            return SOL_ERR_NOMEM;
        }
        memset(new_data, 0, SOL_TOKEN_ACCOUNT_SIZE);
        sol_free(token_account->data);
        token_account->data = new_data;
        token_account->meta.data_len = SOL_TOKEN_ACCOUNT_SIZE;
    }

    /* Pack account state */
    sol_token_pack_account(&account, token_account->data,
                           token_account->meta.data_len);

    /* Store account */
    err = store_account(ctx, 0, token_account);
    sol_account_destroy(token_account);

    return err;
}

/*
 * Process Transfer instruction
 * Accounts: [source, destination, authority, ...signers]
 * Data: amount (u64)
 */
static sol_err_t
process_transfer(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 3) {
        return SOL_ERR_NOT_ENOUGH_KEYS;
    }

    if (ctx->instruction_data_len < 1 + 8) {
        return SOL_ERR_INVAL;
    }

    /* Parse amount */
    uint64_t amount;
    memcpy(&amount, &ctx->instruction_data[1], 8);

    /* Load accounts */
    sol_account_t* source_account = load_account(ctx, 0);
    sol_account_t* dest_account = load_account(ctx, 1);
    const sol_pubkey_t* authority = get_account_pubkey(ctx, 2);

    if (!source_account || !dest_account || !authority) {
        if (source_account) sol_account_destroy(source_account);
        if (dest_account) sol_account_destroy(dest_account);
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Verify accounts are owned by token program */
    if (!sol_pubkey_eq(&source_account->meta.owner, &SOL_TOKEN_PROGRAM_ID) ||
        !sol_pubkey_eq(&dest_account->meta.owner, &SOL_TOKEN_PROGRAM_ID)) {
        sol_account_destroy(source_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Unpack source token account */
    sol_token_account_t source;
    sol_err_t err = sol_token_unpack_account(source_account->data,
                                              source_account->meta.data_len,
                                              &source);
    if (err != SOL_OK) {
        sol_account_destroy(source_account);
        sol_account_destroy(dest_account);
        return err;
    }

    /* Unpack destination token account */
    sol_token_account_t dest;
    err = sol_token_unpack_account(dest_account->data,
                                   dest_account->meta.data_len, &dest);
    if (err != SOL_OK) {
        sol_account_destroy(source_account);
        sol_account_destroy(dest_account);
        return err;
    }

    /* Verify accounts are for same mint */
    if (!sol_pubkey_eq(&source.mint, &dest.mint)) {
        sol_account_destroy(source_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_INVAL;
    }

    /* Verify authority is owner or delegate */
    bool is_owner = sol_pubkey_eq(authority, &source.owner);
    bool is_delegate = (source.delegate_option == 1) &&
                       sol_pubkey_eq(authority, &source.delegate);

    if (!is_owner && !is_delegate) {
        sol_account_destroy(source_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    /* Verify authority signed the transaction */
    if (!is_signer(ctx, 2)) {
        sol_account_destroy(source_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    /* Check sufficient balance */
    if (is_delegate) {
        if (source.delegated_amount < amount) {
            sol_account_destroy(source_account);
            sol_account_destroy(dest_account);
            return SOL_ERR_INSUFFICIENT_FUNDS;
        }
    }

    if (source.amount < amount) {
        sol_account_destroy(source_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_INSUFFICIENT_FUNDS;
    }

    /* Check accounts not frozen */
    if (source.state == SOL_TOKEN_ACCOUNT_STATE_FROZEN ||
        dest.state == SOL_TOKEN_ACCOUNT_STATE_FROZEN) {
        sol_account_destroy(source_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_FROZEN;
    }

    /* Perform transfer */
    source.amount -= amount;
    dest.amount += amount;

    if (is_delegate) {
        source.delegated_amount -= amount;
    }

    /* Pack updated states */
    sol_token_pack_account(&source, source_account->data,
                           source_account->meta.data_len);
    sol_token_pack_account(&dest, dest_account->data,
                           dest_account->meta.data_len);

    /* Store accounts */
    err = store_account(ctx, 0, source_account);
    if (err == SOL_OK) {
        err = store_account(ctx, 1, dest_account);
    }

    sol_account_destroy(source_account);
    sol_account_destroy(dest_account);

    return err;
}

/*
 * Process TransferChecked instruction
 * Accounts: [source, mint, destination, authority, ...signers]
 * Data: amount (u64), decimals (u8)
 *
 * Like Transfer but requires mint account and verifies decimals.
 */
static sol_err_t
process_transfer_checked(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 4) {
        return SOL_ERR_NOT_ENOUGH_KEYS;
    }

    if (ctx->instruction_data_len < 1 + 8 + 1) {
        return SOL_ERR_INVAL;
    }

    /* Parse amount and decimals */
    uint64_t amount;
    memcpy(&amount, &ctx->instruction_data[1], 8);
    uint8_t expected_decimals = ctx->instruction_data[9];

    /* Load accounts */
    sol_account_t* source_account = load_account(ctx, 0);
    sol_account_t* mint_account = load_account(ctx, 1);
    sol_account_t* dest_account = load_account(ctx, 2);
    const sol_pubkey_t* authority = get_account_pubkey(ctx, 3);

    if (!source_account || !mint_account || !dest_account || !authority) {
        if (source_account) sol_account_destroy(source_account);
        if (mint_account) sol_account_destroy(mint_account);
        if (dest_account) sol_account_destroy(dest_account);
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Verify accounts are owned by token program */
    if (!sol_pubkey_eq(&source_account->meta.owner, &SOL_TOKEN_PROGRAM_ID) ||
        !sol_pubkey_eq(&mint_account->meta.owner, &SOL_TOKEN_PROGRAM_ID) ||
        !sol_pubkey_eq(&dest_account->meta.owner, &SOL_TOKEN_PROGRAM_ID)) {
        sol_account_destroy(source_account);
        sol_account_destroy(mint_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Unpack mint to verify decimals */
    sol_token_mint_t mint;
    sol_err_t err = sol_token_unpack_mint(mint_account->data,
                                          mint_account->meta.data_len, &mint);
    if (err != SOL_OK) {
        sol_account_destroy(source_account);
        sol_account_destroy(mint_account);
        sol_account_destroy(dest_account);
        return err;
    }

    /* Verify decimals match */
    if (mint.decimals != expected_decimals) {
        sol_account_destroy(source_account);
        sol_account_destroy(mint_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_INVAL;
    }

    const sol_pubkey_t* mint_pubkey = get_account_pubkey(ctx, 1);

    /* Unpack source token account */
    sol_token_account_t source;
    err = sol_token_unpack_account(source_account->data,
                                   source_account->meta.data_len, &source);
    if (err != SOL_OK) {
        sol_account_destroy(source_account);
        sol_account_destroy(mint_account);
        sol_account_destroy(dest_account);
        return err;
    }

    /* Verify source is for this mint */
    if (!sol_pubkey_eq(&source.mint, mint_pubkey)) {
        sol_account_destroy(source_account);
        sol_account_destroy(mint_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_INVAL;
    }

    /* Unpack destination token account */
    sol_token_account_t dest;
    err = sol_token_unpack_account(dest_account->data,
                                   dest_account->meta.data_len, &dest);
    if (err != SOL_OK) {
        sol_account_destroy(source_account);
        sol_account_destroy(mint_account);
        sol_account_destroy(dest_account);
        return err;
    }

    /* Verify destination is for this mint */
    if (!sol_pubkey_eq(&dest.mint, mint_pubkey)) {
        sol_account_destroy(source_account);
        sol_account_destroy(mint_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_INVAL;
    }

    sol_account_destroy(mint_account);

    /* Verify authority is owner or delegate */
    bool is_owner = sol_pubkey_eq(authority, &source.owner);
    bool is_delegate = (source.delegate_option == 1) &&
                       sol_pubkey_eq(authority, &source.delegate);

    if (!is_owner && !is_delegate) {
        sol_account_destroy(source_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    /* Verify authority signed the transaction */
    if (!is_signer(ctx, 3)) {
        sol_account_destroy(source_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    /* Check sufficient balance */
    if (is_delegate) {
        if (source.delegated_amount < amount) {
            sol_account_destroy(source_account);
            sol_account_destroy(dest_account);
            return SOL_ERR_INSUFFICIENT_FUNDS;
        }
    }

    if (source.amount < amount) {
        sol_account_destroy(source_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_INSUFFICIENT_FUNDS;
    }

    /* Check accounts not frozen */
    if (source.state == SOL_TOKEN_ACCOUNT_STATE_FROZEN ||
        dest.state == SOL_TOKEN_ACCOUNT_STATE_FROZEN) {
        sol_account_destroy(source_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_FROZEN;
    }

    /* Perform transfer */
    source.amount -= amount;
    dest.amount += amount;

    if (is_delegate) {
        source.delegated_amount -= amount;
    }

    /* Pack updated states */
    sol_token_pack_account(&source, source_account->data,
                           source_account->meta.data_len);
    sol_token_pack_account(&dest, dest_account->data,
                           dest_account->meta.data_len);

    /* Store accounts */
    err = store_account(ctx, 0, source_account);
    if (err == SOL_OK) {
        err = store_account(ctx, 2, dest_account);
    }

    sol_account_destroy(source_account);
    sol_account_destroy(dest_account);

    return err;
}

/*
 * Process MintTo instruction
 * Accounts: [mint, destination, mint_authority, ...signers]
 * Data: amount (u64)
 */
static sol_err_t
process_mint_to(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 3) {
        return SOL_ERR_NOT_ENOUGH_KEYS;
    }

    if (ctx->instruction_data_len < 1 + 8) {
        return SOL_ERR_INVAL;
    }

    /* Parse amount */
    uint64_t amount;
    memcpy(&amount, &ctx->instruction_data[1], 8);

    /* Load accounts */
    sol_account_t* mint_account = load_account(ctx, 0);
    sol_account_t* dest_account = load_account(ctx, 1);
    const sol_pubkey_t* authority = get_account_pubkey(ctx, 2);

    if (!mint_account || !dest_account || !authority) {
        if (mint_account) sol_account_destroy(mint_account);
        if (dest_account) sol_account_destroy(dest_account);
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Verify mint account is owned by token program */
    if (!sol_pubkey_eq(&mint_account->meta.owner, &SOL_TOKEN_PROGRAM_ID)) {
        sol_account_destroy(mint_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Unpack mint */
    sol_token_mint_t mint;
    sol_err_t err = sol_token_unpack_mint(mint_account->data,
                                          mint_account->meta.data_len, &mint);
    if (err != SOL_OK) {
        sol_account_destroy(mint_account);
        sol_account_destroy(dest_account);
        return err;
    }

    /* Verify mint authority */
    if (mint.mint_authority_option == 0 ||
        !sol_pubkey_eq(authority, &mint.mint_authority)) {
        sol_account_destroy(mint_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    /* Verify authority is a signer */
    if (!is_signer(ctx, 2)) {
        sol_account_destroy(mint_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    /* Unpack destination account */
    sol_token_account_t dest;
    err = sol_token_unpack_account(dest_account->data,
                                   dest_account->meta.data_len, &dest);
    if (err != SOL_OK) {
        sol_account_destroy(mint_account);
        sol_account_destroy(dest_account);
        return err;
    }

    /* Verify destination is for this mint */
    const sol_pubkey_t* mint_pubkey = get_account_pubkey(ctx, 0);
    if (!sol_pubkey_eq(&dest.mint, mint_pubkey)) {
        sol_account_destroy(mint_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_INVAL;
    }

    /* Check account not frozen */
    if (dest.state == SOL_TOKEN_ACCOUNT_STATE_FROZEN) {
        sol_account_destroy(mint_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_FROZEN;
    }

    /* Check for overflow */
    if (mint.supply > UINT64_MAX - amount ||
        dest.amount > UINT64_MAX - amount) {
        sol_account_destroy(mint_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_OVERFLOW;
    }

    /* Mint tokens */
    mint.supply += amount;
    dest.amount += amount;

    /* Pack updated states */
    sol_token_pack_mint(&mint, mint_account->data, mint_account->meta.data_len);
    sol_token_pack_account(&dest, dest_account->data, dest_account->meta.data_len);

    /* Store accounts */
    err = store_account(ctx, 0, mint_account);
    if (err == SOL_OK) {
        err = store_account(ctx, 1, dest_account);
    }

    sol_account_destroy(mint_account);
    sol_account_destroy(dest_account);

    return err;
}

/*
 * Process MintToChecked instruction
 * Accounts: [mint, destination, mint_authority, ...signers]
 * Data: amount (u64), decimals (u8)
 *
 * Like MintTo but verifies the decimals parameter matches the mint.
 */
static sol_err_t
process_mint_to_checked(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 3) {
        return SOL_ERR_NOT_ENOUGH_KEYS;
    }

    if (ctx->instruction_data_len < 1 + 8 + 1) {
        return SOL_ERR_INVAL;
    }

    /* Parse amount and decimals */
    uint64_t amount;
    memcpy(&amount, &ctx->instruction_data[1], 8);
    uint8_t expected_decimals = ctx->instruction_data[9];

    /* Load accounts */
    sol_account_t* mint_account = load_account(ctx, 0);
    sol_account_t* dest_account = load_account(ctx, 1);
    const sol_pubkey_t* authority = get_account_pubkey(ctx, 2);

    if (!mint_account || !dest_account || !authority) {
        if (mint_account) sol_account_destroy(mint_account);
        if (dest_account) sol_account_destroy(dest_account);
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Verify mint account is owned by token program */
    if (!sol_pubkey_eq(&mint_account->meta.owner, &SOL_TOKEN_PROGRAM_ID)) {
        sol_account_destroy(mint_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Unpack mint */
    sol_token_mint_t mint;
    sol_err_t err = sol_token_unpack_mint(mint_account->data,
                                          mint_account->meta.data_len, &mint);
    if (err != SOL_OK) {
        sol_account_destroy(mint_account);
        sol_account_destroy(dest_account);
        return err;
    }

    /* Verify decimals match */
    if (mint.decimals != expected_decimals) {
        sol_account_destroy(mint_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_INVAL;
    }

    /* Verify mint authority */
    if (mint.mint_authority_option == 0 ||
        !sol_pubkey_eq(authority, &mint.mint_authority)) {
        sol_account_destroy(mint_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    /* Verify authority is a signer */
    if (!is_signer(ctx, 2)) {
        sol_account_destroy(mint_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    /* Unpack destination account */
    sol_token_account_t dest;
    err = sol_token_unpack_account(dest_account->data,
                                   dest_account->meta.data_len, &dest);
    if (err != SOL_OK) {
        sol_account_destroy(mint_account);
        sol_account_destroy(dest_account);
        return err;
    }

    /* Verify destination is for this mint */
    const sol_pubkey_t* mint_pubkey = get_account_pubkey(ctx, 0);
    if (!sol_pubkey_eq(&dest.mint, mint_pubkey)) {
        sol_account_destroy(mint_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_INVAL;
    }

    /* Check account not frozen */
    if (dest.state == SOL_TOKEN_ACCOUNT_STATE_FROZEN) {
        sol_account_destroy(mint_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_FROZEN;
    }

    /* Check for overflow */
    if (mint.supply > UINT64_MAX - amount ||
        dest.amount > UINT64_MAX - amount) {
        sol_account_destroy(mint_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_OVERFLOW;
    }

    /* Mint tokens */
    mint.supply += amount;
    dest.amount += amount;

    /* Pack updated states */
    sol_token_pack_mint(&mint, mint_account->data, mint_account->meta.data_len);
    sol_token_pack_account(&dest, dest_account->data, dest_account->meta.data_len);

    /* Store accounts */
    err = store_account(ctx, 0, mint_account);
    if (err == SOL_OK) {
        err = store_account(ctx, 1, dest_account);
    }

    sol_account_destroy(mint_account);
    sol_account_destroy(dest_account);

    return err;
}

/*
 * Process Burn instruction
 * Accounts: [account, mint, authority, ...signers]
 * Data: amount (u64)
 */
static sol_err_t
process_burn(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 3) {
        return SOL_ERR_NOT_ENOUGH_KEYS;
    }

    if (ctx->instruction_data_len < 1 + 8) {
        return SOL_ERR_INVAL;
    }

    /* Parse amount */
    uint64_t amount;
    memcpy(&amount, &ctx->instruction_data[1], 8);

    /* Load accounts */
    sol_account_t* token_account = load_account(ctx, 0);
    sol_account_t* mint_account = load_account(ctx, 1);
    const sol_pubkey_t* authority = get_account_pubkey(ctx, 2);

    if (!token_account || !mint_account || !authority) {
        if (token_account) sol_account_destroy(token_account);
        if (mint_account) sol_account_destroy(mint_account);
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Verify accounts are owned by token program */
    if (!sol_pubkey_eq(&token_account->meta.owner, &SOL_TOKEN_PROGRAM_ID) ||
        !sol_pubkey_eq(&mint_account->meta.owner, &SOL_TOKEN_PROGRAM_ID)) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Unpack token account */
    sol_token_account_t account;
    sol_err_t err = sol_token_unpack_account(token_account->data,
                                              token_account->meta.data_len,
                                              &account);
    if (err != SOL_OK) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return err;
    }

    /* Unpack mint */
    sol_token_mint_t mint;
    err = sol_token_unpack_mint(mint_account->data,
                                mint_account->meta.data_len, &mint);
    if (err != SOL_OK) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return err;
    }

    /* Verify authority is owner or delegate */
    bool is_owner = sol_pubkey_eq(authority, &account.owner);
    bool is_delegate = (account.delegate_option == 1) &&
                       sol_pubkey_eq(authority, &account.delegate);

    if (!is_owner && !is_delegate) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    /* Verify authority is a signer */
    if (!is_signer(ctx, 2)) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    /* Check sufficient balance */
    if (account.amount < amount) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_INSUFFICIENT_FUNDS;
    }

    /* Check account not frozen */
    if (account.state == SOL_TOKEN_ACCOUNT_STATE_FROZEN) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_FROZEN;
    }

    /* Burn tokens */
    account.amount -= amount;
    mint.supply -= amount;

    if (is_delegate) {
        account.delegated_amount -= amount;
    }

    /* Pack updated states */
    sol_token_pack_account(&account, token_account->data,
                           token_account->meta.data_len);
    sol_token_pack_mint(&mint, mint_account->data, mint_account->meta.data_len);

    /* Store accounts */
    err = store_account(ctx, 0, token_account);
    if (err == SOL_OK) {
        err = store_account(ctx, 1, mint_account);
    }

    sol_account_destroy(token_account);
    sol_account_destroy(mint_account);

    return err;
}

/*
 * Process BurnChecked instruction
 * Accounts: [account, mint, authority, ...signers]
 * Data: amount (u64), decimals (u8)
 *
 * Like Burn but verifies the decimals parameter matches the mint.
 */
static sol_err_t
process_burn_checked(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 3) {
        return SOL_ERR_NOT_ENOUGH_KEYS;
    }

    if (ctx->instruction_data_len < 1 + 8 + 1) {
        return SOL_ERR_INVAL;
    }

    /* Parse amount and decimals */
    uint64_t amount;
    memcpy(&amount, &ctx->instruction_data[1], 8);
    uint8_t expected_decimals = ctx->instruction_data[9];

    /* Load accounts */
    sol_account_t* token_account = load_account(ctx, 0);
    sol_account_t* mint_account = load_account(ctx, 1);
    const sol_pubkey_t* authority = get_account_pubkey(ctx, 2);

    if (!token_account || !mint_account || !authority) {
        if (token_account) sol_account_destroy(token_account);
        if (mint_account) sol_account_destroy(mint_account);
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Verify accounts are owned by token program */
    if (!sol_pubkey_eq(&token_account->meta.owner, &SOL_TOKEN_PROGRAM_ID) ||
        !sol_pubkey_eq(&mint_account->meta.owner, &SOL_TOKEN_PROGRAM_ID)) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Unpack token account */
    sol_token_account_t account;
    sol_err_t err = sol_token_unpack_account(token_account->data,
                                              token_account->meta.data_len,
                                              &account);
    if (err != SOL_OK) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return err;
    }

    /* Unpack mint */
    sol_token_mint_t mint;
    err = sol_token_unpack_mint(mint_account->data,
                                mint_account->meta.data_len, &mint);
    if (err != SOL_OK) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return err;
    }

    /* Verify decimals match */
    if (mint.decimals != expected_decimals) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_INVAL;
    }

    /* Verify token account is for this mint */
    const sol_pubkey_t* mint_pubkey = get_account_pubkey(ctx, 1);
    if (!sol_pubkey_eq(&account.mint, mint_pubkey)) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_INVAL;
    }

    /* Verify authority is owner or delegate */
    bool is_owner = sol_pubkey_eq(authority, &account.owner);
    bool is_delegate = (account.delegate_option == 1) &&
                       sol_pubkey_eq(authority, &account.delegate);

    if (!is_owner && !is_delegate) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    /* Verify authority is a signer */
    if (!is_signer(ctx, 2)) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    /* Check sufficient balance */
    if (account.amount < amount) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_INSUFFICIENT_FUNDS;
    }

    /* Check account not frozen */
    if (account.state == SOL_TOKEN_ACCOUNT_STATE_FROZEN) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_FROZEN;
    }

    /* Burn tokens */
    account.amount -= amount;
    mint.supply -= amount;

    if (is_delegate) {
        account.delegated_amount -= amount;
    }

    /* Pack updated states */
    sol_token_pack_account(&account, token_account->data,
                           token_account->meta.data_len);
    sol_token_pack_mint(&mint, mint_account->data, mint_account->meta.data_len);

    /* Store accounts */
    err = store_account(ctx, 0, token_account);
    if (err == SOL_OK) {
        err = store_account(ctx, 1, mint_account);
    }

    sol_account_destroy(token_account);
    sol_account_destroy(mint_account);

    return err;
}

/*
 * Process Approve instruction
 * Accounts: [source, delegate, owner, ...signers]
 * Data: amount (u64)
 */
static sol_err_t
process_approve(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 3) {
        return SOL_ERR_NOT_ENOUGH_KEYS;
    }

    if (ctx->instruction_data_len < 1 + 8) {
        return SOL_ERR_INVAL;
    }

    /* Parse amount */
    uint64_t amount;
    memcpy(&amount, &ctx->instruction_data[1], 8);

    /* Load accounts */
    sol_account_t* source_account = load_account(ctx, 0);
    const sol_pubkey_t* delegate = get_account_pubkey(ctx, 1);
    const sol_pubkey_t* owner = get_account_pubkey(ctx, 2);

    if (!source_account || !delegate || !owner) {
        if (source_account) sol_account_destroy(source_account);
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Verify source account is owned by token program */
    if (!sol_pubkey_eq(&source_account->meta.owner, &SOL_TOKEN_PROGRAM_ID)) {
        sol_account_destroy(source_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Unpack source account */
    sol_token_account_t source;
    sol_err_t err = sol_token_unpack_account(source_account->data,
                                              source_account->meta.data_len,
                                              &source);
    if (err != SOL_OK) {
        sol_account_destroy(source_account);
        return err;
    }

    /* Verify owner matches and signed the transaction */
    if (!sol_pubkey_eq(owner, &source.owner)) {
        sol_account_destroy(source_account);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    if (!is_signer(ctx, 2)) {
        sol_account_destroy(source_account);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    /* Set delegate */
    source.delegate_option = 1;
    source.delegate = *delegate;
    source.delegated_amount = amount;

    /* Pack updated state */
    sol_token_pack_account(&source, source_account->data,
                           source_account->meta.data_len);

    /* Store account */
    err = store_account(ctx, 0, source_account);
    sol_account_destroy(source_account);

    return err;
}

/*
 * Process ApproveChecked instruction
 * Accounts: [source, mint, delegate, owner, ...signers]
 * Data: amount (u64), decimals (u8)
 *
 * Like Approve but requires mint account and verifies decimals.
 */
static sol_err_t
process_approve_checked(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 4) {
        return SOL_ERR_NOT_ENOUGH_KEYS;
    }

    if (ctx->instruction_data_len < 1 + 8 + 1) {
        return SOL_ERR_INVAL;
    }

    /* Parse amount and decimals */
    uint64_t amount;
    memcpy(&amount, &ctx->instruction_data[1], 8);
    uint8_t expected_decimals = ctx->instruction_data[9];

    /* Load accounts */
    sol_account_t* source_account = load_account(ctx, 0);
    sol_account_t* mint_account = load_account(ctx, 1);
    const sol_pubkey_t* delegate = get_account_pubkey(ctx, 2);
    const sol_pubkey_t* owner = get_account_pubkey(ctx, 3);

    if (!source_account || !mint_account || !delegate || !owner) {
        if (source_account) sol_account_destroy(source_account);
        if (mint_account) sol_account_destroy(mint_account);
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Unpack mint to verify decimals */
    sol_token_mint_t mint;
    sol_err_t err = sol_token_unpack_mint(mint_account->data,
                                          mint_account->meta.data_len, &mint);
    if (err != SOL_OK) {
        sol_account_destroy(source_account);
        sol_account_destroy(mint_account);
        return err;
    }

    /* Verify decimals match */
    if (mint.decimals != expected_decimals) {
        sol_account_destroy(source_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_INVAL;
    }

    const sol_pubkey_t* mint_pubkey = get_account_pubkey(ctx, 1);

    /* Unpack source account */
    sol_token_account_t source;
    err = sol_token_unpack_account(source_account->data,
                                   source_account->meta.data_len, &source);
    if (err != SOL_OK) {
        sol_account_destroy(source_account);
        sol_account_destroy(mint_account);
        return err;
    }

    /* Verify source is for this mint */
    if (!sol_pubkey_eq(&source.mint, mint_pubkey)) {
        sol_account_destroy(source_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_INVAL;
    }

    sol_account_destroy(mint_account);

    /* Verify owner matches and signed the transaction */
    if (!sol_pubkey_eq(owner, &source.owner)) {
        sol_account_destroy(source_account);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    if (!is_signer(ctx, 3)) {
        sol_account_destroy(source_account);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    /* Set delegate */
    source.delegate_option = 1;
    source.delegate = *delegate;
    source.delegated_amount = amount;

    /* Pack updated state */
    sol_token_pack_account(&source, source_account->data,
                           source_account->meta.data_len);

    /* Store account */
    err = store_account(ctx, 0, source_account);
    sol_account_destroy(source_account);

    return err;
}

/*
 * Process Revoke instruction
 * Accounts: [source, owner, ...signers]
 */
static sol_err_t
process_revoke(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 2) {
        return SOL_ERR_NOT_ENOUGH_KEYS;
    }

    /* Load accounts */
    sol_account_t* source_account = load_account(ctx, 0);
    const sol_pubkey_t* owner = get_account_pubkey(ctx, 1);

    if (!source_account || !owner) {
        if (source_account) sol_account_destroy(source_account);
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Verify source account is owned by token program */
    if (!sol_pubkey_eq(&source_account->meta.owner, &SOL_TOKEN_PROGRAM_ID)) {
        sol_account_destroy(source_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Unpack source account */
    sol_token_account_t source;
    sol_err_t err = sol_token_unpack_account(source_account->data,
                                              source_account->meta.data_len,
                                              &source);
    if (err != SOL_OK) {
        sol_account_destroy(source_account);
        return err;
    }

    /* Verify owner */
    if (!sol_pubkey_eq(owner, &source.owner)) {
        sol_account_destroy(source_account);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    /* Verify owner is a signer */
    if (!is_signer(ctx, 1)) {
        sol_account_destroy(source_account);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    /* Clear delegate */
    source.delegate_option = 0;
    memset(&source.delegate, 0, sizeof(sol_pubkey_t));
    source.delegated_amount = 0;

    /* Pack updated state */
    sol_token_pack_account(&source, source_account->data,
                           source_account->meta.data_len);

    /* Store account */
    err = store_account(ctx, 0, source_account);
    sol_account_destroy(source_account);

    return err;
}

/*
 * Process CloseAccount instruction
 * Accounts: [account, destination, owner, ...signers]
 */
static sol_err_t
process_close_account(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 3) {
        return SOL_ERR_NOT_ENOUGH_KEYS;
    }

    /* Load accounts */
    sol_account_t* token_account = load_account(ctx, 0);
    sol_account_t* dest_account = load_account(ctx, 1);
    const sol_pubkey_t* owner = get_account_pubkey(ctx, 2);

    if (!token_account || !dest_account || !owner) {
        if (token_account) sol_account_destroy(token_account);
        if (dest_account) sol_account_destroy(dest_account);
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Verify token account is owned by token program */
    if (!sol_pubkey_eq(&token_account->meta.owner, &SOL_TOKEN_PROGRAM_ID)) {
        sol_account_destroy(token_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Unpack token account */
    sol_token_account_t account;
    sol_err_t err = sol_token_unpack_account(token_account->data,
                                              token_account->meta.data_len,
                                              &account);
    if (err != SOL_OK) {
        sol_account_destroy(token_account);
        sol_account_destroy(dest_account);
        return err;
    }

    /* Verify owner or close authority */
    bool is_owner = sol_pubkey_eq(owner, &account.owner);
    bool is_close_auth = (account.close_authority_option == 1) &&
                         sol_pubkey_eq(owner, &account.close_authority);

    if (!is_owner && !is_close_auth) {
        sol_account_destroy(token_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    /* Verify authority is a signer */
    if (!is_signer(ctx, 2)) {
        sol_account_destroy(token_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    /* Check balance is zero (or is native SOL) */
    if (account.amount != 0 && account.is_native_option == 0) {
        sol_account_destroy(token_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_INVAL;
    }

    /* Transfer lamports to destination */
    dest_account->meta.lamports += token_account->meta.lamports;
    token_account->meta.lamports = 0;

    /* Clear account data */
    memset(token_account->data, 0, token_account->meta.data_len);

    /* Store accounts */
    err = store_account(ctx, 0, token_account);
    if (err == SOL_OK) {
        err = store_account(ctx, 1, dest_account);
    }

    sol_account_destroy(token_account);
    sol_account_destroy(dest_account);

    return err;
}

/*
 * Process FreezeAccount instruction
 *
 * Accounts:
 * 0. [writable] The token account to freeze
 * 1. [] The mint account
 * 2. [signer] The freeze authority
 */
static sol_err_t
process_freeze_account(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 3) {
        return SOL_ERR_NOT_ENOUGH_KEYS;
    }

    sol_account_t* token_account = load_account(ctx, 0);
    sol_account_t* mint_account = load_account(ctx, 1);

    if (!token_account || !mint_account) {
        if (token_account) sol_account_destroy(token_account);
        if (mint_account) sol_account_destroy(mint_account);
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Verify accounts are owned by token program */
    if (!sol_pubkey_eq(&token_account->meta.owner, &SOL_TOKEN_PROGRAM_ID) ||
        !sol_pubkey_eq(&mint_account->meta.owner, &SOL_TOKEN_PROGRAM_ID)) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Validate token account */
    if (token_account->meta.data_len != SOL_TOKEN_ACCOUNT_SIZE) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    sol_token_account_t* token_data = (sol_token_account_t*)token_account->data;

    /* Validate mint account */
    if (mint_account->meta.data_len != SOL_TOKEN_MINT_SIZE) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    sol_token_mint_t* mint_data = (sol_token_mint_t*)mint_account->data;

    /* Check token account belongs to this mint */
    if (!sol_pubkey_eq(&token_data->mint, &ctx->account_keys[ctx->account_indices[1]])) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    /* Check mint has freeze authority */
    if (mint_data->freeze_authority_option == 0) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_PROGRAM_INVALID_STATE;
    }

    /* Verify freeze authority is signer (account 2) */
    uint8_t auth_idx = ctx->account_indices[2];
    if (auth_idx >= ctx->account_keys_len) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_INVAL;
    }

    if (!sol_pubkey_eq(&mint_data->freeze_authority, &ctx->account_keys[auth_idx])) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    /* Verify freeze authority is a signer */
    if (!is_signer(ctx, 2)) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    /* Check account is initialized and not already frozen */
    if (token_data->state != SOL_TOKEN_ACCOUNT_STATE_INITIALIZED) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_PROGRAM_INVALID_STATE;
    }

    /* Freeze the account */
    token_data->state = SOL_TOKEN_ACCOUNT_STATE_FROZEN;

    /* Store updated token account */
    sol_err_t err = store_account(ctx, 0, token_account);

    sol_account_destroy(token_account);
    sol_account_destroy(mint_account);

    return err;
}

/*
 * Process ThawAccount instruction
 *
 * Accounts:
 * 0. [writable] The token account to thaw
 * 1. [] The mint account
 * 2. [signer] The freeze authority
 */
static sol_err_t
process_thaw_account(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 3) {
        return SOL_ERR_NOT_ENOUGH_KEYS;
    }

    sol_account_t* token_account = load_account(ctx, 0);
    sol_account_t* mint_account = load_account(ctx, 1);

    if (!token_account || !mint_account) {
        if (token_account) sol_account_destroy(token_account);
        if (mint_account) sol_account_destroy(mint_account);
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Verify accounts are owned by token program */
    if (!sol_pubkey_eq(&token_account->meta.owner, &SOL_TOKEN_PROGRAM_ID) ||
        !sol_pubkey_eq(&mint_account->meta.owner, &SOL_TOKEN_PROGRAM_ID)) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Validate token account */
    if (token_account->meta.data_len != SOL_TOKEN_ACCOUNT_SIZE) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    sol_token_account_t* token_data = (sol_token_account_t*)token_account->data;

    /* Validate mint account */
    if (mint_account->meta.data_len != SOL_TOKEN_MINT_SIZE) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    sol_token_mint_t* mint_data = (sol_token_mint_t*)mint_account->data;

    /* Check token account belongs to this mint */
    if (!sol_pubkey_eq(&token_data->mint, &ctx->account_keys[ctx->account_indices[1]])) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    /* Check mint has freeze authority */
    if (mint_data->freeze_authority_option == 0) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_PROGRAM_INVALID_STATE;
    }

    /* Verify freeze authority is signer (account 2) */
    uint8_t auth_idx = ctx->account_indices[2];
    if (auth_idx >= ctx->account_keys_len) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_INVAL;
    }

    if (!sol_pubkey_eq(&mint_data->freeze_authority, &ctx->account_keys[auth_idx])) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    /* Verify freeze authority is a signer */
    if (!is_signer(ctx, 2)) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    /* Check account is frozen */
    if (token_data->state != SOL_TOKEN_ACCOUNT_STATE_FROZEN) {
        sol_account_destroy(token_account);
        sol_account_destroy(mint_account);
        return SOL_ERR_PROGRAM_INVALID_STATE;
    }

    /* Thaw the account */
    token_data->state = SOL_TOKEN_ACCOUNT_STATE_INITIALIZED;

    /* Store updated token account */
    sol_err_t err = store_account(ctx, 0, token_account);

    sol_account_destroy(token_account);
    sol_account_destroy(mint_account);

    return err;
}

/*
 * Process SetAuthority instruction
 *
 * Accounts:
 * 0. [writable] The account to change authority of
 * 1. [signer] Current authority
 *
 * Instruction data:
 * 0: instruction type (6)
 * 1: authority type (0=MintTokens, 1=FreezeAccount, 2=AccountOwner, 3=CloseAccount)
 * 2: new authority option (0=None, 1=Some)
 * 3-34: new authority pubkey (if option=1)
 */
static sol_err_t
process_set_authority(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 2) {
        return SOL_ERR_NOT_ENOUGH_KEYS;
    }

    if (ctx->instruction_data_len < 3) {
        return SOL_ERR_INVAL;
    }

    uint8_t authority_type = ctx->instruction_data[1];
    uint8_t new_auth_option = ctx->instruction_data[2];

    sol_pubkey_t new_authority = {0};
    if (new_auth_option == 1) {
        if (ctx->instruction_data_len < 35) {
            return SOL_ERR_INVAL;
        }
        memcpy(new_authority.bytes, &ctx->instruction_data[3], 32);
    }

    sol_account_t* account = load_account(ctx, 0);
    if (!account) {
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Verify authority is a signer */
    if (!is_signer(ctx, 1)) {
        sol_account_destroy(account);
        return SOL_ERR_MISSING_SIGNATURE;
    }

    sol_err_t err = SOL_OK;

    /* Verify account is owned by token program */
    if (!sol_pubkey_eq(&account->meta.owner, &SOL_TOKEN_PROGRAM_ID)) {
        sol_account_destroy(account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Determine if this is a mint or token account based on authority type */
    if (authority_type == SOL_TOKEN_AUTH_MINT_TOKENS ||
        authority_type == SOL_TOKEN_AUTH_FREEZE_ACCOUNT) {
        /* Mint account */
        if (account->meta.data_len != SOL_TOKEN_MINT_SIZE) {
            sol_account_destroy(account);
            return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
        }

        sol_token_mint_t* mint = (sol_token_mint_t*)account->data;

        if (authority_type == SOL_TOKEN_AUTH_MINT_TOKENS) {
            /* Verify current mint authority */
            if (mint->mint_authority_option == 0) {
                sol_account_destroy(account);
                return SOL_ERR_PROGRAM_INVALID_STATE;
            }

            uint8_t auth_idx = ctx->account_indices[1];
            if (auth_idx >= ctx->account_keys_len ||
                !sol_pubkey_eq(&mint->mint_authority, &ctx->account_keys[auth_idx])) {
                sol_account_destroy(account);
                return SOL_ERR_MISSING_SIGNATURE;
            }

            /* Set new authority */
            mint->mint_authority_option = new_auth_option;
            if (new_auth_option == 1) {
                mint->mint_authority = new_authority;
            }
        } else {
            /* Freeze authority */
            if (mint->freeze_authority_option == 0) {
                sol_account_destroy(account);
                return SOL_ERR_PROGRAM_INVALID_STATE;
            }

            uint8_t auth_idx = ctx->account_indices[1];
            if (auth_idx >= ctx->account_keys_len ||
                !sol_pubkey_eq(&mint->freeze_authority, &ctx->account_keys[auth_idx])) {
                sol_account_destroy(account);
                return SOL_ERR_MISSING_SIGNATURE;
            }

            /* Set new authority */
            mint->freeze_authority_option = new_auth_option;
            if (new_auth_option == 1) {
                mint->freeze_authority = new_authority;
            }
        }
    } else {
        /* Token account */
        if (account->meta.data_len != SOL_TOKEN_ACCOUNT_SIZE) {
            sol_account_destroy(account);
            return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
        }

        sol_token_account_t* token = (sol_token_account_t*)account->data;

        if (authority_type == SOL_TOKEN_AUTH_ACCOUNT_OWNER) {
            /* Verify current owner */
            uint8_t auth_idx = ctx->account_indices[1];
            if (auth_idx >= ctx->account_keys_len ||
                !sol_pubkey_eq(&token->owner, &ctx->account_keys[auth_idx])) {
                sol_account_destroy(account);
                return SOL_ERR_MISSING_SIGNATURE;
            }

            /* Must have a new owner (can't clear) */
            if (new_auth_option == 0) {
                sol_account_destroy(account);
                return SOL_ERR_INVAL;
            }

            token->owner = new_authority;
        } else if (authority_type == SOL_TOKEN_AUTH_CLOSE_ACCOUNT) {
            /* Verify current close authority (or owner if not set) */
            uint8_t auth_idx = ctx->account_indices[1];
            const sol_pubkey_t* current_auth = token->close_authority_option ?
                &token->close_authority : &token->owner;

            if (auth_idx >= ctx->account_keys_len ||
                !sol_pubkey_eq(current_auth, &ctx->account_keys[auth_idx])) {
                sol_account_destroy(account);
                return SOL_ERR_MISSING_SIGNATURE;
            }

            /* Set new close authority */
            token->close_authority_option = new_auth_option;
            if (new_auth_option == 1) {
                token->close_authority = new_authority;
            }
        } else {
            sol_account_destroy(account);
            return SOL_ERR_INVAL;
        }
    }

    /* Store updated account */
    err = store_account(ctx, 0, account);
    sol_account_destroy(account);

    return err;
}

/*
 * Process SyncNative instruction
 *
 * Updates a native token account's token balance to reflect
 * its actual lamport balance (minus rent-exempt reserve).
 *
 * Accounts:
 * 0. [writable] The native token account to sync
 */
static sol_err_t
process_sync_native(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 1) {
        return SOL_ERR_NOT_ENOUGH_KEYS;
    }

    sol_account_t* token_account = load_account(ctx, 0);
    if (!token_account) {
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Verify token account is owned by token program */
    if (!sol_pubkey_eq(&token_account->meta.owner, &SOL_TOKEN_PROGRAM_ID)) {
        sol_account_destroy(token_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Validate token account size */
    if (token_account->meta.data_len != SOL_TOKEN_ACCOUNT_SIZE) {
        sol_account_destroy(token_account);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    sol_token_account_t* token_data = (sol_token_account_t*)token_account->data;

    /* Check this is a native (wrapped SOL) account */
    if (token_data->is_native_option == 0) {
        sol_account_destroy(token_account);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    /* Check account is initialized */
    if (token_data->state != SOL_TOKEN_ACCOUNT_STATE_INITIALIZED) {
        sol_account_destroy(token_account);
        return SOL_ERR_PROGRAM_INVALID_STATE;
    }

    /* Calculate rent-exempt reserve */
    uint64_t rent_exempt_reserve = sol_account_rent_exempt_minimum(
        SOL_TOKEN_ACCOUNT_SIZE, 3480, 2);

    /* Calculate available lamports (total - rent reserve) */
    uint64_t available = 0;
    if (token_account->meta.lamports > rent_exempt_reserve) {
        available = token_account->meta.lamports - rent_exempt_reserve;
    }

    /* Update token amount to match lamports */
    token_data->amount = available;
    token_data->is_native = rent_exempt_reserve;

    /* Store updated account */
    sol_err_t err = store_account(ctx, 0, token_account);
    sol_account_destroy(token_account);

    return err;
}

/*
 * Process AmountToUiAmount instruction
 *
 * Converts a raw token amount to UI amount string
 * Accounts: [mint]
 * Data: [u8 instruction_type, u64 amount]
 */
static sol_err_t
process_amount_to_ui_amount(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 1) {
        return SOL_ERR_NOT_ENOUGH_KEYS;
    }

    /* Parse amount from instruction data */
    if (ctx->instruction_data_len < 1 + 8) {
        return SOL_ERR_INVAL;
    }

    uint64_t amount;
    memcpy(&amount, &ctx->instruction_data[1], sizeof(uint64_t));

    /* Load mint account */
    sol_account_t* mint_account = load_account(ctx, 0);
    if (!mint_account) {
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Unpack mint to get decimals */
    sol_token_mint_t mint;
    sol_err_t err = sol_token_unpack_mint(mint_account->data,
                                          mint_account->meta.data_len, &mint);
    sol_account_destroy(mint_account);
    if (err != SOL_OK) {
        return err;
    }

    /* Convert amount to UI amount string */
    /* e.g., 1500000 with decimals=6 -> "1.5" */
    char ui_amount[64];
    if (mint.decimals == 0) {
        snprintf(ui_amount, sizeof(ui_amount), "%lu", (unsigned long)amount);
    } else {
        uint64_t divisor = 1;
        for (int i = 0; i < mint.decimals; i++) {
            divisor *= 10;
        }
        uint64_t whole = amount / divisor;
        uint64_t frac = amount % divisor;

        /* Format with correct decimal places, trimming trailing zeros */
        char frac_str[32];
        snprintf(frac_str, sizeof(frac_str), "%0*lu",
                 (int)mint.decimals, (unsigned long)frac);

        /* Trim trailing zeros */
        size_t frac_len = strlen(frac_str);
        while (frac_len > 0 && frac_str[frac_len - 1] == '0') {
            frac_str[--frac_len] = '\0';
        }

        if (frac_len > 0) {
            snprintf(ui_amount, sizeof(ui_amount), "%lu.%s",
                     (unsigned long)whole, frac_str);
        } else {
            snprintf(ui_amount, sizeof(ui_amount), "%lu",
                     (unsigned long)whole);
        }
    }

    /* Set return data (in simulation, this would be returned) */
    size_t len = strlen(ui_amount);
    if (len < SOL_MAX_RETURN_DATA) {
        memcpy(ctx->return_data, ui_amount, len);
        ctx->return_data_len = (uint16_t)len;
        memcpy(&ctx->return_data_program, &SOL_TOKEN_PROGRAM_ID,
               sizeof(sol_pubkey_t));
    }

    return SOL_OK;
}

/*
 * Process UiAmountToAmount instruction
 *
 * Converts a UI amount string to raw token amount
 * Accounts: [mint]
 * Data: [u8 instruction_type, string ui_amount (null-terminated)]
 */
static sol_err_t
process_ui_amount_to_amount(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 1) {
        return SOL_ERR_NOT_ENOUGH_KEYS;
    }

    /* Parse UI amount string from instruction data */
    if (ctx->instruction_data_len < 2) {
        return SOL_ERR_INVAL;
    }

    const char* ui_amount = (const char*)&ctx->instruction_data[1];
    size_t max_len = ctx->instruction_data_len - 1;

    /* Find string length (may not be null-terminated) */
    size_t str_len = 0;
    while (str_len < max_len && ui_amount[str_len] != '\0') {
        str_len++;
    }

    /* Load mint account */
    sol_account_t* mint_account = load_account(ctx, 0);
    if (!mint_account) {
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Unpack mint to get decimals */
    sol_token_mint_t mint;
    sol_err_t err = sol_token_unpack_mint(mint_account->data,
                                          mint_account->meta.data_len, &mint);
    sol_account_destroy(mint_account);
    if (err != SOL_OK) {
        return err;
    }

    /* Parse UI amount string -> raw amount */
    /* e.g., "1.5" with decimals=6 -> 1500000 */
    uint64_t whole = 0;
    uint64_t frac = 0;
    int frac_digits = 0;
    bool in_frac = false;

    for (size_t i = 0; i < str_len; i++) {
        char c = ui_amount[i];
        if (c == '.') {
            if (in_frac) return SOL_ERR_INVAL;  /* Multiple decimal points */
            in_frac = true;
        } else if (c >= '0' && c <= '9') {
            if (in_frac) {
                if (frac_digits < mint.decimals) {
                    frac = frac * 10 + (c - '0');
                    frac_digits++;
                }
                /* Ignore extra decimal places */
            } else {
                whole = whole * 10 + (c - '0');
            }
        } else {
            return SOL_ERR_INVAL;  /* Invalid character */
        }
    }

    /* Pad fraction to full decimals */
    while (frac_digits < mint.decimals) {
        frac *= 10;
        frac_digits++;
    }

    /* Calculate final amount */
    uint64_t multiplier = 1;
    for (int i = 0; i < mint.decimals; i++) {
        multiplier *= 10;
    }
    uint64_t amount = whole * multiplier + frac;

    /* Set return data */
    memcpy(ctx->return_data, &amount, sizeof(uint64_t));
    ctx->return_data_len = sizeof(uint64_t);
    memcpy(&ctx->return_data_program, &SOL_TOKEN_PROGRAM_ID, sizeof(sol_pubkey_t));

    return SOL_OK;
}

/*
 * Process InitializeMultisig instruction
 *
 * Creates a multisig account with M of N signers
 * Accounts: [multisig, rent_sysvar, signer1, signer2, ...]
 * Data: [u8 instruction_type, u8 m (required signers)]
 */
static sol_err_t
process_initialize_multisig(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 3) {  /* multisig + rent + at least 1 signer */
        return SOL_ERR_NOT_ENOUGH_KEYS;
    }

    /* Parse M from instruction data */
    if (ctx->instruction_data_len < 2) {
        return SOL_ERR_INVAL;
    }

    uint8_t m = ctx->instruction_data[1];

    /* Calculate number of signers (accounts after multisig and rent sysvar) */
    uint8_t n = ctx->account_indices_len - 2;

    /* Validate M and N */
    if (n < 1 || n > 11) {
        return SOL_ERR_INVAL;  /* 1-11 signers allowed */
    }
    if (m < 1 || m > n) {
        return SOL_ERR_INVAL;  /* M must be 1..N */
    }

    /* Load multisig account */
    sol_account_t* multisig_account = load_account(ctx, 0);
    if (!multisig_account) {
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Verify multisig account is owned by token program */
    if (!sol_pubkey_eq(&multisig_account->meta.owner, &SOL_TOKEN_PROGRAM_ID)) {
        sol_account_destroy(multisig_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Validate multisig account size */
    if (multisig_account->meta.data_len != SOL_TOKEN_MULTISIG_SIZE) {
        sol_account_destroy(multisig_account);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    sol_token_multisig_t* ms = (sol_token_multisig_t*)multisig_account->data;

    /* Check not already initialized */
    if (ms->is_initialized) {
        sol_account_destroy(multisig_account);
        return SOL_ERR_ALREADY_INITIALIZED;
    }

    /* Initialize multisig state */
    ms->m = m;
    ms->n = n;
    ms->is_initialized = true;

    /* Copy signer pubkeys */
    for (uint8_t i = 0; i < n && i < 11; i++) {
        const sol_pubkey_t* signer = get_account_pubkey(ctx, i + 2);
        if (signer) {
            memcpy(&ms->signers[i], signer, sizeof(sol_pubkey_t));
        }
    }

    /* Store updated account */
    sol_err_t err = store_account(ctx, 0, multisig_account);
    sol_account_destroy(multisig_account);

    return err;
}

/*
 * Process GetAccountDataSize instruction
 *
 * Returns the size needed for a token account via return_data.
 * This is a simulation-only instruction.
 * Accounts: [mint]
 * Data: [u8 instruction_type, ...extension_types]
 */
static sol_err_t
process_get_account_data_size(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 1) {
        return SOL_ERR_NOT_ENOUGH_KEYS;
    }

    /* Load mint account to verify it exists and is initialized */
    sol_account_t* mint_account = load_account(ctx, 0);
    if (!mint_account) {
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Verify mint is initialized */
    sol_token_mint_t mint;
    sol_err_t err = sol_token_unpack_mint(mint_account->data,
                                          mint_account->meta.data_len, &mint);
    sol_account_destroy(mint_account);
    if (err != SOL_OK) {
        return err;
    }

    /* Base token account size is 165 bytes */
    /* Token-2022 extensions would add more, but we only support base Token */
    uint64_t size = SOL_TOKEN_ACCOUNT_SIZE;

    /* Return size via return_data */
    memcpy(ctx->return_data, &size, sizeof(uint64_t));
    ctx->return_data_len = sizeof(uint64_t);
    memcpy(&ctx->return_data_program, &SOL_TOKEN_PROGRAM_ID, sizeof(sol_pubkey_t));

    return SOL_OK;
}

/*
 * Process InitializeImmutableOwner instruction
 *
 * Marks a token account as having an immutable owner.
 * This is effectively a no-op for the base Token program since
 * account ownership is already controlled by the owner field.
 * For Token-2022, this adds an extension. We just validate the account.
 * Accounts: [token_account]
 * Data: [u8 instruction_type]
 */
static sol_err_t
process_initialize_immutable_owner(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 1) {
        return SOL_ERR_NOT_ENOUGH_KEYS;
    }

    /* Load token account */
    sol_account_t* token_account = load_account(ctx, 0);
    if (!token_account) {
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Validate account size */
    if (token_account->meta.data_len != SOL_TOKEN_ACCOUNT_SIZE) {
        sol_account_destroy(token_account);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    /* Verify account is owned by token program */
    if (!sol_pubkey_eq(&token_account->meta.owner, &SOL_TOKEN_PROGRAM_ID)) {
        sol_account_destroy(token_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    sol_token_account_t* token_data = (sol_token_account_t*)token_account->data;

    /* Account must be uninitialized - this instruction is called
     * before InitializeAccount to set up the immutable owner extension.
     * For base Token program, we just verify the account exists and
     * is in the right state. */
    if (token_data->state != SOL_TOKEN_ACCOUNT_STATE_UNINITIALIZED) {
        sol_account_destroy(token_account);
        return SOL_ERR_ALREADY_INITIALIZED;
    }

    /* For base Token program, this is essentially a no-op since
     * ownership is already controlled. Just return success. */
    sol_account_destroy(token_account);

    return SOL_OK;
}

/*
 * Main token program entry point
 */
sol_err_t
sol_token_program_execute(sol_invoke_context_t* ctx) {
    if (!ctx || ctx->instruction_data_len < 1) {
        return SOL_ERR_INVAL;
    }

    uint8_t instr_type = ctx->instruction_data[0];
    sol_err_t result;

    switch (instr_type) {
        case SOL_TOKEN_INSTR_INITIALIZE_MINT:
        case SOL_TOKEN_INSTR_INITIALIZE_MINT2:
            result = process_initialize_mint(ctx); break;

        case SOL_TOKEN_INSTR_INITIALIZE_ACCOUNT:
        case SOL_TOKEN_INSTR_INITIALIZE_ACCOUNT2:
        case SOL_TOKEN_INSTR_INITIALIZE_ACCOUNT3:
            result = process_initialize_account(ctx); break;

        case SOL_TOKEN_INSTR_TRANSFER:
            result = process_transfer(ctx); break;

        case SOL_TOKEN_INSTR_TRANSFER_CHECKED:
            result = process_transfer_checked(ctx); break;

        case SOL_TOKEN_INSTR_APPROVE:
            result = process_approve(ctx); break;

        case SOL_TOKEN_INSTR_APPROVE_CHECKED:
            result = process_approve_checked(ctx); break;

        case SOL_TOKEN_INSTR_REVOKE:
            result = process_revoke(ctx); break;

        case SOL_TOKEN_INSTR_MINT_TO:
            result = process_mint_to(ctx); break;

        case SOL_TOKEN_INSTR_MINT_TO_CHECKED:
            result = process_mint_to_checked(ctx); break;

        case SOL_TOKEN_INSTR_BURN:
            result = process_burn(ctx); break;

        case SOL_TOKEN_INSTR_BURN_CHECKED:
            result = process_burn_checked(ctx); break;

        case SOL_TOKEN_INSTR_CLOSE_ACCOUNT:
            result = process_close_account(ctx); break;

        case SOL_TOKEN_INSTR_FREEZE_ACCOUNT:
            result = process_freeze_account(ctx); break;

        case SOL_TOKEN_INSTR_THAW_ACCOUNT:
            result = process_thaw_account(ctx); break;

        case SOL_TOKEN_INSTR_SET_AUTHORITY:
            result = process_set_authority(ctx); break;

        case SOL_TOKEN_INSTR_SYNC_NATIVE:
            result = process_sync_native(ctx); break;

        case SOL_TOKEN_INSTR_INITIALIZE_MULTISIG:
        case SOL_TOKEN_INSTR_INITIALIZE_MULTISIG2:
            result = process_initialize_multisig(ctx); break;

        case SOL_TOKEN_INSTR_AMOUNT_TO_UI_AMOUNT:
            result = process_amount_to_ui_amount(ctx); break;

        case SOL_TOKEN_INSTR_UI_AMOUNT_TO_AMOUNT:
            result = process_ui_amount_to_amount(ctx); break;

        case SOL_TOKEN_INSTR_GET_ACCOUNT_DATA_SIZE:
            result = process_get_account_data_size(ctx); break;

        case SOL_TOKEN_INSTR_INITIALIZE_IMMUTABLE_OWNER:
            result = process_initialize_immutable_owner(ctx); break;

        default:
            result = SOL_ERR_INVAL; break;
    }

    /* Diagnostic: log account data_len values for -518 failures */
    if (result == SOL_ERR_PROGRAM_INVALID_ACCOUNT) {
        sol_log_info("token_diag: instr_type=%u err=-518 n_accounts=%u",
                     (unsigned)instr_type,
                     (unsigned)ctx->account_indices_len);
        for (uint8_t i = 0; i < ctx->account_indices_len && i < 6; i++) {
            uint8_t key_idx = ctx->account_indices[i];
            if (key_idx < ctx->account_keys_len) {
                char pub_b58[SOL_PUBKEY_BASE58_LEN] = {0};
                sol_pubkey_to_base58(&ctx->account_keys[key_idx], pub_b58, sizeof(pub_b58));
                sol_account_t* acct = sol_bank_load_account(ctx->bank, &ctx->account_keys[key_idx]);
                if (acct) {
                    char owner_b58[SOL_PUBKEY_BASE58_LEN] = {0};
                    sol_pubkey_to_base58(&acct->meta.owner, owner_b58, sizeof(owner_b58));
                    sol_log_info("token_diag:  [%u] %s data_len=%lu lamports=%lu owner=%s",
                                (unsigned)i, pub_b58,
                                (unsigned long)acct->meta.data_len,
                                (unsigned long)acct->meta.lamports,
                                owner_b58);
                    sol_account_destroy(acct);
                } else {
                    sol_log_info("token_diag:  [%u] %s NOT_FOUND", (unsigned)i, pub_b58);
                }
            }
        }
    }

    return result;
}

/*
 * Get associated token address for a wallet and mint
 * Uses PDA derivation: [wallet, token_program_id, mint]
 */
sol_err_t
sol_get_associated_token_address(const sol_pubkey_t* wallet,
                                  const sol_pubkey_t* mint,
                                  const sol_pubkey_t* token_program_id,
                                  sol_pubkey_t* out_address) {
    if (!wallet || !mint || !token_program_id || !out_address) {
        return SOL_ERR_INVAL;
    }

    /* PDA seeds: [wallet, token_program, mint] */
    uint8_t seeds[3 * 32];
    memcpy(&seeds[0], wallet->bytes, 32);
    memcpy(&seeds[32], token_program_id->bytes, 32);
    memcpy(&seeds[64], mint->bytes, 32);

    /* Find program address by trying bump seeds 255 down to 0 */
    for (int bump = 255; bump >= 0; bump--) {
        uint8_t bump_seed = (uint8_t)bump;
        sol_sha256_ctx_t sha_ctx;
        sol_sha256_init(&sha_ctx);
        sol_sha256_update(&sha_ctx, seeds, sizeof(seeds));
        sol_sha256_update(&sha_ctx, &bump_seed, 1);
        sol_sha256_update(&sha_ctx, SOL_ASSOCIATED_TOKEN_PROGRAM_ID.bytes, 32);
        sol_sha256_update(&sha_ctx, (const uint8_t*)"ProgramDerivedAddress", 21);

        sol_sha256_t hash;
        sol_sha256_final(&sha_ctx, &hash);

        sol_pubkey_t candidate;
        memcpy(candidate.bytes, hash.bytes, 32);

        /* PDA must not be a valid ed25519 curve point. */
        if (!sol_ed25519_pubkey_is_on_curve(&candidate)) {
            *out_address = candidate;
            return SOL_OK;
        }
    }

    return SOL_ERR_INVAL;
}

/*
 * Associated Token Account program instruction types
 */
typedef enum {
    ATA_INSTR_CREATE = 0,
    ATA_INSTR_CREATE_IDEMPOTENT = 1,
    ATA_INSTR_RECOVER_NESTED = 2,
} ata_instr_type_t;

/*
 * Process ATA Create instruction
 *
 * Accounts:
 * 0. [writeable,signer] Funding account (payer)
 * 1. [writeable] Associated token account address to be created
 * 2. [] Wallet address for the new associated token account
 * 3. [] Token mint for the new associated token account
 * 4. [] System Program
 * 5. [] SPL Token Program
 */
static sol_err_t
process_ata_create(sol_invoke_context_t* ctx, bool idempotent) {
    if (ctx->account_indices_len < 6) {
        return SOL_ERR_NOT_ENOUGH_KEYS;
    }

    /* Get account indices */
    uint8_t payer_idx = ctx->account_indices[0];
    uint8_t ata_idx = ctx->account_indices[1];
    uint8_t wallet_idx = ctx->account_indices[2];
    uint8_t mint_idx = ctx->account_indices[3];

    if (payer_idx >= ctx->account_keys_len ||
        ata_idx >= ctx->account_keys_len ||
        wallet_idx >= ctx->account_keys_len ||
        mint_idx >= ctx->account_keys_len) {
        return SOL_ERR_INVAL;
    }

    const sol_pubkey_t* payer = &ctx->account_keys[payer_idx];
    const sol_pubkey_t* ata_address = &ctx->account_keys[ata_idx];
    const sol_pubkey_t* wallet = &ctx->account_keys[wallet_idx];
    const sol_pubkey_t* mint = &ctx->account_keys[mint_idx];

    sol_pubkey_t mint_owner = {0};
    bool have_mint_owner = get_mint_owner(ctx, mint, &mint_owner);
    if (!have_mint_owner) {
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Verify expected ATA address */
    sol_pubkey_t expected_ata;
    const sol_pubkey_t* token_program = NULL;

    /* Try to find the token program account by matching the provided ATA address.
     * Some call paths may include extra accounts; do not assume the token program
     * is always at index 5. */
    for (uint8_t i = 5; i < ctx->account_indices_len; i++) {
        const sol_pubkey_t* candidate = get_account_pubkey(ctx, i);
        if (!candidate) continue;

        sol_pubkey_t derived;
        sol_err_t derr = sol_get_associated_token_address(wallet, mint, candidate, &derived);
        if (derr != SOL_OK) {
            continue;
        }

        if (sol_pubkey_eq(ata_address, &derived)) {
            token_program = candidate;
            expected_ata = derived;
            break;
        }
    }

    if (!token_program) {
        /* Fall back to the legacy account order so errors surface as address mismatches. */
        token_program = get_account_pubkey(ctx, 5);
        if (!token_program) {
            return SOL_ERR_INVAL;
        }

        sol_err_t err = sol_get_associated_token_address(wallet, mint, token_program, &expected_ata);
        if (err != SOL_OK) {
            return err;
        }
    }

    if (!sol_pubkey_eq(token_program, &mint_owner)) {
        static uint32_t s_token_prog_mismatch_logged = 0;
        if (s_token_prog_mismatch_logged < 5) {
            char sig_b58[SOL_SIGNATURE_BASE58_LEN] = "unknown";
            if (ctx->tx_signature) {
                if (sol_signature_to_base58(ctx->tx_signature, sig_b58, sizeof(sig_b58)) != SOL_OK) {
                    snprintf(sig_b58, sizeof(sig_b58), "unknown");
                }
            }
            char wallet_b58[SOL_PUBKEY_BASE58_LEN] = {0};
            char mint_b58[SOL_PUBKEY_BASE58_LEN] = {0};
            char token_prog_b58[SOL_PUBKEY_BASE58_LEN] = {0};
            char mint_owner_b58[SOL_PUBKEY_BASE58_LEN] = {0};
            (void)sol_pubkey_to_base58(wallet, wallet_b58, sizeof(wallet_b58));
            (void)sol_pubkey_to_base58(mint, mint_b58, sizeof(mint_b58));
            (void)sol_pubkey_to_base58(token_program, token_prog_b58, sizeof(token_prog_b58));
            (void)sol_pubkey_to_base58(&mint_owner, mint_owner_b58, sizeof(mint_owner_b58));
            sol_log_warn("ATA create: token program mismatch (slot=%lu tx=%s wallet=%s mint=%s mint_owner=%s token_program=%s)",
                         (unsigned long)(ctx->bank ? sol_bank_slot(ctx->bank) : 0),
                         sig_b58,
                         wallet_b58,
                         mint_b58,
                         mint_owner_b58,
                         token_prog_b58);
            s_token_prog_mismatch_logged++;
            if (s_token_prog_mismatch_logged == 5) {
                sol_log_warn("ATA create: token program mismatch (suppressing further logs)");
            }
        }
        return SOL_ERR_INVAL;
    }

    if (!sol_pubkey_eq(ata_address, &expected_ata)) {
        static uint32_t s_ata_mismatch_logged = 0;
        if (s_ata_mismatch_logged < 5) {
            char sig_b58[SOL_SIGNATURE_BASE58_LEN] = "unknown";
            if (ctx->tx_signature) {
                if (sol_signature_to_base58(ctx->tx_signature, sig_b58, sizeof(sig_b58)) != SOL_OK) {
                    snprintf(sig_b58, sizeof(sig_b58), "unknown");
                }
            }
            char wallet_b58[SOL_PUBKEY_BASE58_LEN] = {0};
            char mint_b58[SOL_PUBKEY_BASE58_LEN] = {0};
            char token_prog_b58[SOL_PUBKEY_BASE58_LEN] = {0};
            char expected_b58[SOL_PUBKEY_BASE58_LEN] = {0};
            char got_b58[SOL_PUBKEY_BASE58_LEN] = {0};

            (void)sol_pubkey_to_base58(wallet, wallet_b58, sizeof(wallet_b58));
            (void)sol_pubkey_to_base58(mint, mint_b58, sizeof(mint_b58));
            (void)sol_pubkey_to_base58(token_program, token_prog_b58, sizeof(token_prog_b58));
            (void)sol_pubkey_to_base58(&expected_ata, expected_b58, sizeof(expected_b58));
            (void)sol_pubkey_to_base58(ata_address, got_b58, sizeof(got_b58));

            sol_log_warn("ATA address mismatch (slot=%lu tx=%s wallet=%s mint=%s token_program=%s expected=%s got=%s)",
                         (unsigned long)(ctx->bank ? sol_bank_slot(ctx->bank) : 0),
                         sig_b58,
                         wallet_b58,
                         mint_b58,
                         token_prog_b58,
                         expected_b58,
                         got_b58);
            s_ata_mismatch_logged++;
            if (s_ata_mismatch_logged == 5) {
                sol_log_warn("ATA address mismatch (suppressing further logs)");
            }
        }
        return SOL_ERR_INVAL;
    }

    sol_err_t err = SOL_OK;

    /* Check if account already exists */
    sol_slot_t ata_ss = 0;
    sol_account_t* existing = sol_bank_load_account_ex(ctx->bank, ata_address, &ata_ss);
    /* Simulate Agave's clean_accounts: only filter snapshot-era zombies */
    sol_slot_t ata_zfs = sol_bank_zombie_filter_slot(ctx->bank);
    if (existing && existing->meta.lamports == 0 && ata_zfs > 0 && ata_ss <= ata_zfs) {
        sol_account_destroy(existing);
        existing = NULL;
    }
    if (existing) {
        if (existing->meta.data_len > 0) {
            sol_account_destroy(existing);
            if (idempotent) {
                return SOL_OK;  /* Account exists, success for idempotent */
            }
            return SOL_ERR_ALREADY_INITIALIZED;
        }
        sol_account_destroy(existing);
    }

    /* Calculate rent-exempt balance */
    uint64_t rent_minimum = sol_account_rent_exempt_minimum(
        SOL_TOKEN_ACCOUNT_SIZE,
        3480,   /* rent_per_byte_year */
        2       /* exemption_threshold */
    );

    /* Create the account via system program (allocate space) */
    sol_account_t* new_account = sol_account_new(
        rent_minimum,
        SOL_TOKEN_ACCOUNT_SIZE,
        token_program
    );

    if (!new_account) {
        return SOL_ERR_NOMEM;
    }

    /* Initialize token account data */
    sol_token_account_t token_acc = {0};
    token_acc.mint = *mint;
    token_acc.owner = *wallet;
    token_acc.amount = 0;
    token_acc.delegate_option = 0;
    token_acc.state = SOL_TOKEN_ACCOUNT_STATE_INITIALIZED;
    token_acc.is_native_option = 0;
    token_acc.is_native = 0;
    token_acc.delegated_amount = 0;
    token_acc.close_authority_option = 0;

    memcpy(new_account->data, &token_acc, sizeof(sol_token_account_t));

    /* Store the new account */
    err = sol_bank_store_account(ctx->bank, ata_address, new_account);

    /* Deduct rent from payer */
    if (err == SOL_OK) {
        sol_account_t* payer_account = sol_bank_load_account(ctx->bank, payer);
        if (payer_account && payer_account->meta.lamports >= rent_minimum) {
            payer_account->meta.lamports -= rent_minimum;
            sol_bank_store_account(ctx->bank, payer, payer_account);
            sol_account_destroy(payer_account);
        } else {
            if (payer_account) sol_account_destroy(payer_account);
            err = SOL_ERR_INSUFFICIENT_FUNDS;
        }
    }

    sol_account_destroy(new_account);
    return err;
}

/*
 * Process RecoverNested instruction
 *
 * Recovers tokens from a nested associated token account.
 * This handles the case where an ATA was accidentally created
 * for another ATA (the "owner" is itself an ATA).
 *
 * Accounts:
 * 0. [w] Nested ATA (the source - owned by owner ATA)
 * 1. [] Nested mint
 * 2. [w] Destination ATA for recovered tokens
 * 3. [] Owner ATA's owner (the wallet that owns the owner ATA)
 * 4. [] Owner ATA (the ATA that accidentally owns the nested ATA)
 * 5. [] Owner ATA's mint
 * 6. [] Token Program
 */
static sol_err_t
process_ata_recover_nested(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 7) {
        return SOL_ERR_NOT_ENOUGH_KEYS;
    }

    /* Get account pubkeys */
    const sol_pubkey_t* nested_ata = get_account_pubkey(ctx, 0);
    const sol_pubkey_t* nested_mint = get_account_pubkey(ctx, 1);
    const sol_pubkey_t* dest_ata = get_account_pubkey(ctx, 2);
    const sol_pubkey_t* wallet = get_account_pubkey(ctx, 3);
    const sol_pubkey_t* owner_ata = get_account_pubkey(ctx, 4);
    const sol_pubkey_t* owner_mint = get_account_pubkey(ctx, 5);
    const sol_pubkey_t* token_program = NULL;

    if (!nested_ata || !nested_mint || !dest_ata || !wallet ||
        !owner_ata || !owner_mint) {
        return SOL_ERR_INVAL;
    }

    sol_pubkey_t mint_owner = {0};
    bool have_mint_owner = get_mint_owner(ctx, nested_mint, &mint_owner);

    if (!have_mint_owner) {
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Select token program by matching the owner_ata derivation; tolerate extra accounts. */
    for (uint8_t i = 6; i < ctx->account_indices_len; i++) {
        const sol_pubkey_t* candidate = get_account_pubkey(ctx, i);
        if (!candidate) continue;

        sol_pubkey_t derived_owner_ata;
        sol_err_t derr = sol_get_associated_token_address(wallet, owner_mint, candidate, &derived_owner_ata);
        if (derr != SOL_OK) {
            continue;
        }

        if (sol_pubkey_eq(owner_ata, &derived_owner_ata)) {
            token_program = candidate;
            break;
        }
    }

    if (!token_program) {
        token_program = get_account_pubkey(ctx, 6);
    }
    if (!token_program) {
        return SOL_ERR_INVAL;
    }

    if (!sol_pubkey_eq(token_program, &mint_owner)) {
        sol_log_warn("ATA recover_nested: token program does not match mint owner");
        return SOL_ERR_INVAL;
    }

    /* Verify owner_ata is actually the ATA for wallet/owner_mint */
    sol_pubkey_t expected_owner_ata;
    sol_err_t err = sol_get_associated_token_address(wallet, owner_mint,
                                                      token_program,
                                                      &expected_owner_ata);
    if (err != SOL_OK || !sol_pubkey_eq(owner_ata, &expected_owner_ata)) {
        sol_log_warn("Owner ATA address mismatch");
        return SOL_ERR_INVAL;
    }

    /* Verify nested_ata is the ATA for owner_ata/nested_mint */
    sol_pubkey_t expected_nested_ata;
    err = sol_get_associated_token_address(owner_ata, nested_mint,
                                           token_program,
                                           &expected_nested_ata);
    if (err != SOL_OK || !sol_pubkey_eq(nested_ata, &expected_nested_ata)) {
        sol_log_warn("Nested ATA address mismatch");
        return SOL_ERR_INVAL;
    }

    /* Verify dest_ata is the ATA for wallet/nested_mint */
    sol_pubkey_t expected_dest_ata;
    err = sol_get_associated_token_address(wallet, nested_mint, token_program, &expected_dest_ata);
    if (err != SOL_OK || !sol_pubkey_eq(dest_ata, &expected_dest_ata)) {
        sol_log_warn("Destination ATA address mismatch");
        return SOL_ERR_INVAL;
    }

    /* Load nested ATA to get balance */
    sol_account_t* nested_account = sol_bank_load_account(ctx->bank, nested_ata);
    if (!nested_account) {
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    if (nested_account->meta.data_len != SOL_TOKEN_ACCOUNT_SIZE) {
        sol_account_destroy(nested_account);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    sol_token_account_t* nested_data = (sol_token_account_t*)nested_account->data;

    /* Verify nested account is owned by owner_ata */
    sol_pubkey_t nested_owner;
    memcpy(&nested_owner, &nested_data->owner, sizeof(sol_pubkey_t));
    if (!sol_pubkey_eq(&nested_owner, owner_ata)) {
        sol_account_destroy(nested_account);
        sol_log_warn("Nested ATA not owned by owner ATA");
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    uint64_t amount = nested_data->amount;

    /* Load destination ATA */
    sol_account_t* dest_account = sol_bank_load_account(ctx->bank, dest_ata);
    if (!dest_account) {
        sol_account_destroy(nested_account);
        return SOL_ERR_ACCOUNT_NOT_FOUND;
    }

    if (dest_account->meta.data_len != SOL_TOKEN_ACCOUNT_SIZE) {
        sol_account_destroy(nested_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_PROGRAM_INVALID_ACCOUNT;
    }

    sol_token_account_t* dest_data = (sol_token_account_t*)dest_account->data;

    /* Transfer tokens from nested to destination */
    nested_data->amount = 0;
    dest_data->amount += amount;

    /* Store updated accounts */
    err = sol_bank_store_account(ctx->bank, nested_ata, nested_account);
    if (err == SOL_OK) {
        err = sol_bank_store_account(ctx->bank, dest_ata, dest_account);
    }

    sol_account_destroy(nested_account);
    sol_account_destroy(dest_account);

    return err;
}

/*
 * Associated Token Account program entry point
 */
sol_err_t
sol_associated_token_program_execute(sol_invoke_context_t* ctx) {
    if (!ctx) {
        return SOL_ERR_INVAL;
    }

    /* ATA program instructions can be empty (defaults to Create) or have type byte */
    uint8_t instr_type = ATA_INSTR_CREATE;
    if (ctx->instruction_data_len >= 1) {
        instr_type = ctx->instruction_data[0];
    }

    switch (instr_type) {
        case ATA_INSTR_CREATE:
            return process_ata_create(ctx, false);

        case ATA_INSTR_CREATE_IDEMPOTENT:
            return process_ata_create(ctx, true);

        case ATA_INSTR_RECOVER_NESTED:
            return process_ata_recover_nested(ctx);

        default:
            sol_log_warn("Unknown ATA instruction type: %d", instr_type);
            return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
}
