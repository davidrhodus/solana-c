/*
 * sol_system_program.c - System Program Implementation
 */

#include "sol_system_program.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include "../crypto/sol_sha256.h"
#include "../runtime/sol_account.h"
#include "../runtime/sol_bank.h"
#include <string.h>

/*
 * System Program ID (all zeros) - defined in sol_account.c
 */

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

    /* Simulate Agave's clean_accounts: only filter snapshot-era zombies */
    sol_slot_t zfs = sol_bank_zombie_filter_slot(ctx->bank);
    if (*account && (*account)->meta.lamports == 0 && zfs > 0 && ss <= zfs) {
        sol_account_destroy(*account);
        *account = NULL;
    }

    /* In Agave, load_transaction_accounts() creates a default AccountSharedData
     * for any account key not in the accounts DB.  Native programs therefore
     * always see a valid (zero-lamport, system-owned) account rather than NULL.
     * Match that behavior here. */
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
 * Check if account is a signer
 *
 * In Solana, the first N accounts in the account_keys array are signers,
 * where N is specified by the message header's num_required_signatures.
 * This value is passed through ctx->num_signers.
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
 * Execute CreateAccount instruction
 */
static sol_err_t
execute_create_account(sol_invoke_context_t* ctx) {
    if (ctx->instruction_data_len < 4 + 8 + 8 + 32) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
    if (ctx->account_indices_len < 2) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Parse instruction data */
    const uint8_t* data = ctx->instruction_data + 4;  /* Skip instruction type */

    uint64_t lamports;
    memcpy(&lamports, data, 8);
    data += 8;

    uint64_t space;
    memcpy(&space, data, 8);
    data += 8;

    sol_pubkey_t owner;
    memcpy(owner.bytes, data, 32);

    /* Get accounts */
    const sol_pubkey_t* from_pubkey;
    sol_account_t* from_account;
    SOL_TRY(get_account(ctx, 0, &from_pubkey, &from_account));

    const sol_pubkey_t* to_pubkey;
    sol_account_t* to_account;
    SOL_TRY(get_account(ctx, 1, &to_pubkey, &to_account));

    /* Validate */
    if (!is_signer(ctx, 0)) {
        sol_account_destroy(from_account);
        if (to_account) sol_account_destroy(to_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    if (!from_account) {
        if (to_account) sol_account_destroy(to_account);
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    if (from_account->meta.lamports < lamports) {
        sol_account_destroy(from_account);
        if (to_account) sol_account_destroy(to_account);
        return SOL_ERR_TX_INSUFFICIENT_FUNDS;
    }

    /* Check if target account already exists with data or lamports */
    if (to_account && (to_account->meta.lamports > 0 || to_account->meta.data_len > 0)) {
        sol_account_destroy(from_account);
        sol_account_destroy(to_account);
        return SOL_ERR_PROGRAM_ACCOUNT_ALREADY_INIT;
    }

    /* Check space limit */
    if (space > SOL_ACCOUNT_MAX_DATA_SIZE) {
        sol_account_destroy(from_account);
        if (to_account) sol_account_destroy(to_account);
        return SOL_ERR_TOO_LARGE;
    }

    /* NOTE: Agave does NOT check rent exemption in System::CreateAccount.
       Rent state is validated post-execution at the transaction level
       (Uninitialized→Uninitialized and Uninitialized→RentExempt are valid). */

    /* Debit from account */
    from_account->meta.lamports -= lamports;
    sol_bank_store_account(ctx->bank, from_pubkey, from_account);

    /* Create or update target account */
    if (!to_account) {
        to_account = sol_account_new(lamports, (size_t)space, &owner);
    } else {
        to_account->meta.lamports = lamports;
        to_account->meta.owner = owner;
        sol_account_resize(to_account, (size_t)space);
    }

    sol_bank_store_account(ctx->bank, to_pubkey, to_account);

    sol_account_destroy(from_account);
    sol_account_destroy(to_account);

    return SOL_OK;
}

/*
 * Execute Assign instruction
 */
static sol_err_t
execute_assign(sol_invoke_context_t* ctx) {
    if (ctx->instruction_data_len < 4 + 32) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
    if (ctx->account_indices_len < 1) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Parse instruction data */
    const uint8_t* data = ctx->instruction_data + 4;
    sol_pubkey_t new_owner;
    memcpy(new_owner.bytes, data, 32);

    /* Get account */
    const sol_pubkey_t* account_pubkey;
    sol_account_t* account;
    SOL_TRY(get_account(ctx, 0, &account_pubkey, &account));

    if (!account) {
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Must be signer */
    if (!is_signer(ctx, 0)) {
        sol_account_destroy(account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Must be owned by system program */
    if (!sol_pubkey_eq(&account->meta.owner, &SOL_SYSTEM_PROGRAM_ID)) {
        sol_account_destroy(account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Assign new owner */
    account->meta.owner = new_owner;
    sol_bank_store_account(ctx->bank, account_pubkey, account);

    sol_account_destroy(account);
    return SOL_OK;
}

/*
 * Execute Transfer instruction
 */
static sol_err_t
execute_transfer(sol_invoke_context_t* ctx) {
    if (ctx->instruction_data_len < 4 + 8) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
    if (ctx->account_indices_len < 2) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Parse instruction data */
    const uint8_t* data = ctx->instruction_data + 4;
    uint64_t lamports;
    memcpy(&lamports, data, 8);

    /* Get accounts */
    const sol_pubkey_t* from_pubkey;
    sol_account_t* from_account;
    SOL_TRY(get_account(ctx, 0, &from_pubkey, &from_account));

    const sol_pubkey_t* to_pubkey;
    sol_account_t* to_account;
    sol_err_t err = get_account(ctx, 1, &to_pubkey, &to_account);
    if (err != SOL_OK) {
        if (from_account) sol_account_destroy(from_account);
        return err;
    }

    /* Validate source */
    if (!from_account) {
        if (to_account) sol_account_destroy(to_account);
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    if (!is_signer(ctx, 0)) {
        sol_account_destroy(from_account);
        if (to_account) sol_account_destroy(to_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Agave: Transfer: `from` must not carry data */
    if (from_account->meta.data_len > 0) {
        sol_account_destroy(from_account);
        if (to_account) sol_account_destroy(to_account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    if (from_account->meta.lamports < lamports) {
        sol_account_destroy(from_account);
        if (to_account) sol_account_destroy(to_account);
        return SOL_ERR_TX_INSUFFICIENT_FUNDS;
    }

    /* Self-transfer: In Agave, both borrows reference the same underlying
       account, so sub then add = no net change.  We must still store the
       account to mark it as "touched" in the overlay. */
    if (sol_pubkey_eq(from_pubkey, to_pubkey)) {
        sol_bank_store_account(ctx->bank, from_pubkey, from_account);
        sol_account_destroy(from_account);
        if (to_account) sol_account_destroy(to_account);
        return SOL_OK;
    }

    /* Create target account if doesn't exist */
    if (!to_account) {
        to_account = sol_account_new(0, 0, &SOL_SYSTEM_PROGRAM_ID);
        if (!to_account) {
            sol_account_destroy(from_account);
            return SOL_ERR_NOMEM;
        }
    }

    /* Transfer */
    from_account->meta.lamports -= lamports;
    to_account->meta.lamports += lamports;

    sol_bank_store_account(ctx->bank, from_pubkey, from_account);
    sol_bank_store_account(ctx->bank, to_pubkey, to_account);

    sol_account_destroy(from_account);
    sol_account_destroy(to_account);

    return SOL_OK;
}

/*
 * Execute Allocate instruction
 */
static sol_err_t
execute_allocate(sol_invoke_context_t* ctx) {
    if (ctx->instruction_data_len < 4 + 8) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
    if (ctx->account_indices_len < 1) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Parse instruction data */
    const uint8_t* data = ctx->instruction_data + 4;
    uint64_t space;
    memcpy(&space, data, 8);

    /* Get account */
    const sol_pubkey_t* account_pubkey;
    sol_account_t* account;
    SOL_TRY(get_account(ctx, 0, &account_pubkey, &account));

    if (!account) {
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Must be signer */
    if (!is_signer(ctx, 0)) {
        sol_account_destroy(account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Must be owned by system program */
    if (!sol_pubkey_eq(&account->meta.owner, &SOL_SYSTEM_PROGRAM_ID)) {
        sol_account_destroy(account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Cannot shrink */
    if (space < account->meta.data_len) {
        sol_account_destroy(account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Check space limit */
    if (space > SOL_ACCOUNT_MAX_DATA_SIZE) {
        sol_account_destroy(account);
        return SOL_ERR_TOO_LARGE;
    }

    /* Allocate */
    sol_err_t err = sol_account_resize(account, (size_t)space);
    if (err != SOL_OK) {
        sol_account_destroy(account);
        return err;
    }

    sol_bank_store_account(ctx->bank, account_pubkey, account);
    sol_account_destroy(account);

    return SOL_OK;
}

/*
 * Execute InitializeNonce instruction
 *
 * Accounts: [0] = nonce account, [1] = recent blockhashes sysvar, [2] = rent sysvar
 */
static sol_err_t
execute_initialize_nonce(sol_invoke_context_t* ctx) {
    if (ctx->instruction_data_len < 4 + 32) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
    if (ctx->account_indices_len < 1) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Note: Agave does NOT require the nonce account to be a signer for
     * InitializeNonceAccount. Only writability is checked. */

    /* Parse instruction data */
    const uint8_t* data = ctx->instruction_data + 4;
    sol_pubkey_t authority;
    memcpy(authority.bytes, data, 32);

    /* Get nonce account */
    const sol_pubkey_t* nonce_pubkey;
    sol_account_t* nonce_account;
    SOL_TRY(get_account(ctx, 0, &nonce_pubkey, &nonce_account));

    if (!nonce_account) {
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Verify account is owned by system program */
    if (!sol_pubkey_eq(&nonce_account->meta.owner, &SOL_SYSTEM_PROGRAM_ID)) {
        sol_account_destroy(nonce_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Check account size */
    if (nonce_account->meta.data_len < SOL_NONCE_DATA_SIZE) {
        sol_account_destroy(nonce_account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Initialize nonce data */
    sol_nonce_data_t nonce_data = {
        .version = 1,
        .state = SOL_NONCE_STATE_INITIALIZED,
        .authority = authority,
        .lamports_per_signature = sol_bank_lamports_per_signature(ctx->bank),
    };

    /* Get recent blockhash and derive DurableNonce.
     * In Agave: DurableNonce::from_blockhash(blockhash) = SHA256("DURABLE_NONCE" || blockhash) */
    const sol_hash_t* blockhash = sol_bank_blockhash(ctx->bank);
    if (blockhash) {
        sol_sha256_ctx_t sha_ctx;
        sol_sha256_init(&sha_ctx);
        sol_sha256_update(&sha_ctx, "DURABLE_NONCE", 13);
        sol_sha256_update(&sha_ctx, blockhash->bytes, 32);
        sol_sha256_final_bytes(&sha_ctx, nonce_data.blockhash.bytes);
    }

    /* Write nonce data to account */
    memcpy(nonce_account->data, &nonce_data, sizeof(sol_nonce_data_t));
    sol_bank_store_account(ctx->bank, nonce_pubkey, nonce_account);

    sol_account_destroy(nonce_account);
    return SOL_OK;
}

/*
 * Execute WithdrawNonce instruction
 *
 * Withdraws lamports from nonce account to recipient.
 * Accounts: [0] = nonce account, [1] = recipient,
 *           [2] = RecentBlockhashes sysvar, [3] = Rent sysvar,
 *           [4] = authority (signer)
 */
static sol_err_t
execute_withdraw_nonce(sol_invoke_context_t* ctx) {
    if (ctx->instruction_data_len < 4 + 8) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
    if (ctx->account_indices_len < 5) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Parse instruction data */
    const uint8_t* data = ctx->instruction_data + 4;
    uint64_t lamports;
    memcpy(&lamports, data, 8);

    /* Get accounts */
    const sol_pubkey_t* nonce_pubkey;
    sol_account_t* nonce_account;
    SOL_TRY(get_account(ctx, 0, &nonce_pubkey, &nonce_account));

    const sol_pubkey_t* recipient_pubkey;
    sol_account_t* recipient_account;
    sol_err_t err = get_account(ctx, 1, &recipient_pubkey, &recipient_account);
    if (err != SOL_OK) {
        if (nonce_account) sol_account_destroy(nonce_account);
        return err;
    }

    if (!nonce_account) {
        if (recipient_account) sol_account_destroy(recipient_account);
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Verify nonce account is owned by system program */
    if (!sol_pubkey_eq(&nonce_account->meta.owner, &SOL_SYSTEM_PROGRAM_ID)) {
        sol_account_destroy(nonce_account);
        if (recipient_account) sol_account_destroy(recipient_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Verify nonce account data */
    if (nonce_account->meta.data_len < SOL_NONCE_DATA_SIZE) {
        sol_account_destroy(nonce_account);
        if (recipient_account) sol_account_destroy(recipient_account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Read nonce data */
    sol_nonce_data_t nonce_data;
    memcpy(&nonce_data, nonce_account->data, sizeof(sol_nonce_data_t));

    if (nonce_data.state != SOL_NONCE_STATE_INITIALIZED) {
        sol_account_destroy(nonce_account);
        if (recipient_account) sol_account_destroy(recipient_account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Verify authority matches and is a signer (index 4, after sysvars) */
    const sol_pubkey_t* authority_pubkey;
    sol_account_t* authority_account;
    sol_err_t auth_err = get_account(ctx, 4, &authority_pubkey, &authority_account);
    if (auth_err != SOL_OK) {
        sol_account_destroy(nonce_account);
        if (recipient_account) sol_account_destroy(recipient_account);
        return auth_err;
    }

    if (!sol_pubkey_eq(authority_pubkey, &nonce_data.authority)) {
        sol_account_destroy(nonce_account);
        if (recipient_account) sol_account_destroy(recipient_account);
        if (authority_account) sol_account_destroy(authority_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    if (!is_signer(ctx, 4)) {
        sol_account_destroy(nonce_account);
        if (recipient_account) sol_account_destroy(recipient_account);
        if (authority_account) sol_account_destroy(authority_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    if (authority_account) sol_account_destroy(authority_account);

    /* Check sufficient lamports */
    if (nonce_account->meta.lamports < lamports) {
        sol_account_destroy(nonce_account);
        if (recipient_account) sol_account_destroy(recipient_account);
        return SOL_ERR_TX_INSUFFICIENT_FUNDS;
    }

    /* Self-withdrawal: no-op for lamports (sub+add on same account = no change) */
    if (sol_pubkey_eq(nonce_pubkey, recipient_pubkey)) {
        sol_bank_store_account(ctx->bank, nonce_pubkey, nonce_account);
        sol_account_destroy(nonce_account);
        if (recipient_account) sol_account_destroy(recipient_account);
        return SOL_OK;
    }

    /* Create recipient if needed */
    if (!recipient_account) {
        recipient_account = sol_account_new(0, 0, &SOL_SYSTEM_PROGRAM_ID);
        if (!recipient_account) {
            sol_account_destroy(nonce_account);
            return SOL_ERR_NOMEM;
        }
    }

    /* Transfer lamports */
    nonce_account->meta.lamports -= lamports;
    recipient_account->meta.lamports += lamports;

    sol_bank_store_account(ctx->bank, nonce_pubkey, nonce_account);
    sol_bank_store_account(ctx->bank, recipient_pubkey, recipient_account);

    sol_account_destroy(nonce_account);
    sol_account_destroy(recipient_account);

    return SOL_OK;
}

/*
 * Execute AuthorizeNonce instruction
 *
 * Changes the authority of a nonce account.
 * Accounts: [0] = nonce account, [1] = current authority (signer)
 */
static sol_err_t
execute_authorize_nonce(sol_invoke_context_t* ctx) {
    if (ctx->instruction_data_len < 4 + 32) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
    if (ctx->account_indices_len < 2) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Parse instruction data - new authority */
    const uint8_t* data = ctx->instruction_data + 4;
    sol_pubkey_t new_authority;
    memcpy(new_authority.bytes, data, 32);

    /* Get nonce account */
    const sol_pubkey_t* nonce_pubkey;
    sol_account_t* nonce_account;
    SOL_TRY(get_account(ctx, 0, &nonce_pubkey, &nonce_account));

    if (!nonce_account) {
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Verify nonce account is owned by system program */
    if (!sol_pubkey_eq(&nonce_account->meta.owner, &SOL_SYSTEM_PROGRAM_ID)) {
        sol_account_destroy(nonce_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Verify nonce account data */
    if (nonce_account->meta.data_len < SOL_NONCE_DATA_SIZE) {
        sol_account_destroy(nonce_account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Read nonce data */
    sol_nonce_data_t nonce_data;
    memcpy(&nonce_data, nonce_account->data, sizeof(sol_nonce_data_t));

    if (nonce_data.state != SOL_NONCE_STATE_INITIALIZED) {
        sol_account_destroy(nonce_account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Verify current authority matches and is a signer */
    const sol_pubkey_t* authority_pubkey;
    sol_account_t* authority_account;
    sol_err_t auth_err = get_account(ctx, 1, &authority_pubkey, &authority_account);
    if (auth_err != SOL_OK) {
        sol_account_destroy(nonce_account);
        return auth_err;
    }

    if (!sol_pubkey_eq(authority_pubkey, &nonce_data.authority)) {
        sol_account_destroy(nonce_account);
        if (authority_account) sol_account_destroy(authority_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    if (!is_signer(ctx, 1)) {
        sol_account_destroy(nonce_account);
        if (authority_account) sol_account_destroy(authority_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    if (authority_account) sol_account_destroy(authority_account);

    /* Update authority */
    nonce_data.authority = new_authority;

    /* Write updated nonce data */
    memcpy(nonce_account->data, &nonce_data, sizeof(sol_nonce_data_t));
    sol_bank_store_account(ctx->bank, nonce_pubkey, nonce_account);

    sol_account_destroy(nonce_account);
    return SOL_OK;
}

/*
 * Execute UpgradeNonce instruction
 *
 * Upgrades nonce account version (v0 -> v1).
 * Accounts: [0] = nonce account
 */
static sol_err_t
execute_upgrade_nonce(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 1) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Get nonce account */
    const sol_pubkey_t* nonce_pubkey;
    sol_account_t* nonce_account;
    SOL_TRY(get_account(ctx, 0, &nonce_pubkey, &nonce_account));

    if (!nonce_account) {
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Verify nonce account data */
    if (nonce_account->meta.data_len < SOL_NONCE_DATA_SIZE) {
        sol_account_destroy(nonce_account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Read nonce data */
    sol_nonce_data_t nonce_data;
    memcpy(&nonce_data, nonce_account->data, sizeof(sol_nonce_data_t));

    /* Can only upgrade initialized nonces */
    if (nonce_data.state != SOL_NONCE_STATE_INITIALIZED) {
        sol_account_destroy(nonce_account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Upgrade version to 1 if it's older */
    if (nonce_data.version < 1) {
        nonce_data.version = 1;
        memcpy(nonce_account->data, &nonce_data, sizeof(sol_nonce_data_t));
        sol_bank_store_account(ctx->bank, nonce_pubkey, nonce_account);
    }

    sol_account_destroy(nonce_account);
    return SOL_OK;
}

/*
 * Execute CreateAccountWithSeed instruction
 *
 * Creates account at address derived from base + seed + owner.
 * Accounts: [0] = funding account, [1] = created account, [2] = base account
 */
static sol_err_t
execute_create_account_with_seed(sol_invoke_context_t* ctx) {
    /* Minimum: type(4) + base(32) + seed_len(8) + seed(min 0) + lamports(8) + space(8) + owner(32) */
    if (ctx->instruction_data_len < 4 + 32 + 8 + 8 + 8 + 32) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
    if (ctx->account_indices_len < 2) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Parse instruction data */
    const uint8_t* data = ctx->instruction_data + 4;

    sol_pubkey_t base;
    memcpy(base.bytes, data, 32);
    data += 32;

    uint64_t seed_len;
    memcpy(&seed_len, data, 8);
    data += 8;

    if (seed_len > 32 || ctx->instruction_data_len < 4 + 32 + 8 + seed_len + 8 + 8 + 32) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    const char* seed = (const char*)data;
    data += seed_len;

    uint64_t lamports;
    memcpy(&lamports, data, 8);
    data += 8;

    uint64_t space;
    memcpy(&space, data, 8);
    data += 8;

    sol_pubkey_t owner;
    memcpy(owner.bytes, data, 32);

    /* Derive expected address */
    sol_pubkey_t expected_address;
    sol_create_with_seed(&base, seed, (size_t)seed_len, &owner, &expected_address);

    /* Get accounts */
    const sol_pubkey_t* from_pubkey;
    sol_account_t* from_account;
    SOL_TRY(get_account(ctx, 0, &from_pubkey, &from_account));

    const sol_pubkey_t* to_pubkey;
    sol_account_t* to_account;
    sol_err_t err = get_account(ctx, 1, &to_pubkey, &to_account);
    if (err != SOL_OK) {
        if (from_account) sol_account_destroy(from_account);
        return err;
    }

    if (!from_account) {
        if (to_account) sol_account_destroy(to_account);
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Verify derived address matches */
    if (!sol_pubkey_eq(to_pubkey, &expected_address)) {
        sol_account_destroy(from_account);
        if (to_account) sol_account_destroy(to_account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Check sufficient funds */
    if (from_account->meta.lamports < lamports) {
        sol_account_destroy(from_account);
        if (to_account) sol_account_destroy(to_account);
        return SOL_ERR_TX_INSUFFICIENT_FUNDS;
    }

    /* Check space limit */
    if (space > SOL_ACCOUNT_MAX_DATA_SIZE) {
        sol_account_destroy(from_account);
        if (to_account) sol_account_destroy(to_account);
        return SOL_ERR_TOO_LARGE;
    }

    /* NOTE: Agave does NOT check rent exemption in System::CreateAccountWithSeed.
       Rent state is validated post-execution at the transaction level. */

    /* Check target doesn't already exist with data */
    if (to_account && (to_account->meta.lamports > 0 || to_account->meta.data_len > 0)) {
        sol_account_destroy(from_account);
        sol_account_destroy(to_account);
        return SOL_ERR_PROGRAM_ACCOUNT_ALREADY_INIT;
    }

    /* Debit from account */
    from_account->meta.lamports -= lamports;
    sol_bank_store_account(ctx->bank, from_pubkey, from_account);

    /* Create target account */
    if (!to_account) {
        to_account = sol_account_new(lamports, (size_t)space, &owner);
    } else {
        to_account->meta.lamports = lamports;
        to_account->meta.owner = owner;
        sol_account_resize(to_account, (size_t)space);
    }

    sol_bank_store_account(ctx->bank, to_pubkey, to_account);

    sol_account_destroy(from_account);
    sol_account_destroy(to_account);

    return SOL_OK;
}

/*
 * Execute AllocateWithSeed instruction
 *
 * Allocates space for account at seeded address.
 * Accounts: [0] = account, [1] = base account (signer)
 */
static sol_err_t
execute_allocate_with_seed(sol_invoke_context_t* ctx) {
    /* Minimum: type(4) + base(32) + seed_len(8) + space(8) + owner(32) */
    if (ctx->instruction_data_len < 4 + 32 + 8 + 8 + 32) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
    if (ctx->account_indices_len < 2) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Parse instruction data */
    const uint8_t* data = ctx->instruction_data + 4;

    sol_pubkey_t base;
    memcpy(base.bytes, data, 32);
    data += 32;

    uint64_t seed_len;
    memcpy(&seed_len, data, 8);
    data += 8;

    if (seed_len > 32 || ctx->instruction_data_len < 4 + 32 + 8 + seed_len + 8 + 32) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    const char* seed = (const char*)data;
    data += seed_len;

    uint64_t space;
    memcpy(&space, data, 8);
    data += 8;

    sol_pubkey_t owner;
    memcpy(owner.bytes, data, 32);

    /* Derive expected address */
    sol_pubkey_t expected_address;
    sol_create_with_seed(&base, seed, (size_t)seed_len, &owner, &expected_address);

    /* Get account */
    const sol_pubkey_t* account_pubkey;
    sol_account_t* account;
    SOL_TRY(get_account(ctx, 0, &account_pubkey, &account));

    if (!account) {
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Verify derived address matches */
    if (!sol_pubkey_eq(account_pubkey, &expected_address)) {
        sol_account_destroy(account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /*
     * Verify base account (account 1) is a signer.
     * For seeded operations, the base account must authorize the operation.
     */
    if (!is_signer(ctx, 1)) {
        sol_log_debug("AllocateWithSeed: base account must be a signer");
        sol_account_destroy(account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Check space limit */
    if (space > SOL_ACCOUNT_MAX_DATA_SIZE) {
        sol_account_destroy(account);
        return SOL_ERR_TOO_LARGE;
    }

    /* Cannot shrink */
    if (space < account->meta.data_len) {
        sol_account_destroy(account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Allocate and set owner */
    sol_err_t err = sol_account_resize(account, (size_t)space);
    if (err != SOL_OK) {
        sol_account_destroy(account);
        return err;
    }
    account->meta.owner = owner;

    sol_bank_store_account(ctx->bank, account_pubkey, account);
    sol_account_destroy(account);

    return SOL_OK;
}

/*
 * Execute AssignWithSeed instruction
 *
 * Assigns program owner to account at seeded address.
 * Accounts: [0] = account, [1] = base account (signer)
 */
static sol_err_t
execute_assign_with_seed(sol_invoke_context_t* ctx) {
    /* Minimum: type(4) + base(32) + seed_len(8) + owner(32) */
    if (ctx->instruction_data_len < 4 + 32 + 8 + 32) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
    if (ctx->account_indices_len < 2) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Parse instruction data */
    const uint8_t* data = ctx->instruction_data + 4;

    sol_pubkey_t base;
    memcpy(base.bytes, data, 32);
    data += 32;

    uint64_t seed_len;
    memcpy(&seed_len, data, 8);
    data += 8;

    if (seed_len > 32 || ctx->instruction_data_len < 4 + 32 + 8 + seed_len + 32) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    const char* seed = (const char*)data;
    data += seed_len;

    sol_pubkey_t owner;
    memcpy(owner.bytes, data, 32);

    /* Derive expected address */
    sol_pubkey_t expected_address;
    sol_create_with_seed(&base, seed, (size_t)seed_len, &owner, &expected_address);

    /* Get account */
    const sol_pubkey_t* account_pubkey;
    sol_account_t* account;
    SOL_TRY(get_account(ctx, 0, &account_pubkey, &account));

    if (!account) {
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Verify derived address matches */
    if (!sol_pubkey_eq(account_pubkey, &expected_address)) {
        sol_account_destroy(account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /*
     * Verify base account (account 1) is a signer.
     * For seeded operations, the base account must authorize the operation.
     */
    if (!is_signer(ctx, 1)) {
        sol_log_debug("AssignWithSeed: base account must be a signer");
        sol_account_destroy(account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Assign new owner */
    account->meta.owner = owner;
    sol_bank_store_account(ctx->bank, account_pubkey, account);

    sol_account_destroy(account);
    return SOL_OK;
}

/*
 * Execute TransferWithSeed instruction
 *
 * Transfers lamports from seeded address.
 * Accounts: [0] = from account, [1] = base account (signer), [2] = to account
 */
static sol_err_t
execute_transfer_with_seed(sol_invoke_context_t* ctx) {
    /* Minimum: type(4) + lamports(8) + seed_len(8) + from_owner(32) */
    if (ctx->instruction_data_len < 4 + 8 + 8 + 32) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
    if (ctx->account_indices_len < 3) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Parse instruction data */
    const uint8_t* data = ctx->instruction_data + 4;

    uint64_t lamports;
    memcpy(&lamports, data, 8);
    data += 8;

    uint64_t seed_len;
    memcpy(&seed_len, data, 8);
    data += 8;

    if (seed_len > 32 || ctx->instruction_data_len < 4 + 8 + 8 + seed_len + 32) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    const char* seed = (const char*)data;
    data += seed_len;

    sol_pubkey_t from_owner;
    memcpy(from_owner.bytes, data, 32);

    /* Get accounts */
    const sol_pubkey_t* from_pubkey;
    sol_account_t* from_account;
    SOL_TRY(get_account(ctx, 0, &from_pubkey, &from_account));

    const sol_pubkey_t* base_pubkey;
    sol_account_t* base_account;
    sol_err_t err = get_account(ctx, 1, &base_pubkey, &base_account);
    if (err != SOL_OK) {
        if (from_account) sol_account_destroy(from_account);
        return err;
    }

    const sol_pubkey_t* to_pubkey;
    sol_account_t* to_account;
    err = get_account(ctx, 2, &to_pubkey, &to_account);
    if (err != SOL_OK) {
        if (from_account) sol_account_destroy(from_account);
        if (base_account) sol_account_destroy(base_account);
        return err;
    }

    if (!from_account) {
        if (base_account) sol_account_destroy(base_account);
        if (to_account) sol_account_destroy(to_account);
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Derive expected from address */
    sol_pubkey_t expected_from;
    sol_create_with_seed(base_pubkey, seed, (size_t)seed_len, &from_owner, &expected_from);

    /* Verify derived address matches */
    if (!sol_pubkey_eq(from_pubkey, &expected_from)) {
        sol_account_destroy(from_account);
        if (base_account) sol_account_destroy(base_account);
        if (to_account) sol_account_destroy(to_account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /*
     * Verify base account (account 1) is a signer.
     * For seeded operations, the base account must authorize the operation.
     */
    if (!is_signer(ctx, 1)) {
        sol_log_debug("TransferWithSeed: base account must be a signer");
        sol_account_destroy(from_account);
        if (base_account) sol_account_destroy(base_account);
        if (to_account) sol_account_destroy(to_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Agave: Transfer: `from` must not carry data */
    if (from_account->meta.data_len > 0) {
        sol_account_destroy(from_account);
        if (base_account) sol_account_destroy(base_account);
        if (to_account) sol_account_destroy(to_account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Check sufficient funds */
    if (from_account->meta.lamports < lamports) {
        sol_account_destroy(from_account);
        if (base_account) sol_account_destroy(base_account);
        if (to_account) sol_account_destroy(to_account);
        return SOL_ERR_TX_INSUFFICIENT_FUNDS;
    }

    /* Self-transfer: no-op for lamports (sub+add on same account = no change) */
    if (sol_pubkey_eq(from_pubkey, to_pubkey)) {
        sol_bank_store_account(ctx->bank, from_pubkey, from_account);
        sol_account_destroy(from_account);
        if (base_account) sol_account_destroy(base_account);
        if (to_account) sol_account_destroy(to_account);
        return SOL_OK;
    }

    /* Create target if needed */
    if (!to_account) {
        to_account = sol_account_new(0, 0, &SOL_SYSTEM_PROGRAM_ID);
        if (!to_account) {
            sol_account_destroy(from_account);
            if (base_account) sol_account_destroy(base_account);
            return SOL_ERR_NOMEM;
        }
    }

    /* Transfer lamports */
    from_account->meta.lamports -= lamports;
    to_account->meta.lamports += lamports;

    sol_bank_store_account(ctx->bank, from_pubkey, from_account);
    sol_bank_store_account(ctx->bank, to_pubkey, to_account);

    sol_account_destroy(from_account);
    if (base_account) sol_account_destroy(base_account);
    sol_account_destroy(to_account);

    return SOL_OK;
}

/*
 * Execute AdvanceNonce instruction
 *
 * Accounts:
 * [0] = nonce account (writable)
 * [1] = recent blockhash sysvar
 * [2] = nonce authority (signer)
 */
static sol_err_t
execute_advance_nonce(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 3) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Get nonce account */
    const sol_pubkey_t* nonce_pubkey;
    sol_account_t* nonce_account;
    SOL_TRY(get_account(ctx, 0, &nonce_pubkey, &nonce_account));

    if (!nonce_account) {
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Verify nonce account is owned by system program */
    if (!sol_pubkey_eq(&nonce_account->meta.owner, &SOL_SYSTEM_PROGRAM_ID)) {
        sol_account_destroy(nonce_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    if (nonce_account->meta.data_len < SOL_NONCE_DATA_SIZE) {
        sol_account_destroy(nonce_account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Read nonce data */
    sol_nonce_data_t nonce_data;
    memcpy(&nonce_data, nonce_account->data, sizeof(sol_nonce_data_t));

    if (nonce_data.state != SOL_NONCE_STATE_INITIALIZED) {
        sol_account_destroy(nonce_account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Get authority account and verify it matches nonce authority */
    const sol_pubkey_t* authority_pubkey;
    sol_account_t* authority_account;
    SOL_TRY(get_account(ctx, 2, &authority_pubkey, &authority_account));

    if (!sol_pubkey_eq(authority_pubkey, &nonce_data.authority)) {
        sol_account_destroy(nonce_account);
        if (authority_account) sol_account_destroy(authority_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Verify authority is a signer */
    if (!is_signer(ctx, 2)) {
        sol_account_destroy(nonce_account);
        if (authority_account) sol_account_destroy(authority_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    if (authority_account) sol_account_destroy(authority_account);

    /* Advance nonce to current blockhash.
     * In Agave the stored nonce is DurableNonce::from_blockhash(blockhash)
     * which is SHA256("DURABLE_NONCE" || blockhash), NOT the raw blockhash. */
    const sol_hash_t* blockhash = sol_bank_blockhash(ctx->bank);
    if (blockhash) {
        sol_hash_t durable_nonce;
        sol_sha256_ctx_t sha_ctx;
        sol_sha256_init(&sha_ctx);
        sol_sha256_update(&sha_ctx, "DURABLE_NONCE", 13);
        sol_sha256_update(&sha_ctx, blockhash->bytes, 32);
        sol_sha256_final_bytes(&sha_ctx, durable_nonce.bytes);

        /* Check that we're not using the same durable nonce */
        if (memcmp(nonce_data.blockhash.bytes, durable_nonce.bytes, 32) == 0) {
            sol_account_destroy(nonce_account);
            return SOL_ERR_PROGRAM_INVALID_INSTR;
        }

        nonce_data.blockhash = durable_nonce;
        nonce_data.lamports_per_signature = sol_bank_lamports_per_signature(ctx->bank);
    }

    /* Write updated nonce data */
    memcpy(nonce_account->data, &nonce_data, sizeof(sol_nonce_data_t));
    sol_bank_store_account(ctx->bank, nonce_pubkey, nonce_account);

    sol_account_destroy(nonce_account);
    return SOL_OK;
}

sol_err_t
sol_system_program_execute(sol_invoke_context_t* ctx) {
    if (!ctx || !ctx->bank || !ctx->instruction_data || ctx->instruction_data_len < 4) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Read instruction type */
    uint32_t instr_type;
    memcpy(&instr_type, ctx->instruction_data, 4);

    switch (instr_type) {
    case SOL_SYSTEM_INSTR_CREATE_ACCOUNT:
        return execute_create_account(ctx);

    case SOL_SYSTEM_INSTR_ASSIGN:
        return execute_assign(ctx);

    case SOL_SYSTEM_INSTR_TRANSFER:
        return execute_transfer(ctx);

    case SOL_SYSTEM_INSTR_ALLOCATE:
        return execute_allocate(ctx);

    case SOL_SYSTEM_INSTR_INITIALIZE_NONCE:
        return execute_initialize_nonce(ctx);

    case SOL_SYSTEM_INSTR_ADVANCE_NONCE:
        return execute_advance_nonce(ctx);

    case SOL_SYSTEM_INSTR_CREATE_ACCOUNT_WITH_SEED:
        return execute_create_account_with_seed(ctx);

    case SOL_SYSTEM_INSTR_WITHDRAW_NONCE:
        return execute_withdraw_nonce(ctx);

    case SOL_SYSTEM_INSTR_AUTHORIZE_NONCE:
        return execute_authorize_nonce(ctx);

    case SOL_SYSTEM_INSTR_ALLOCATE_WITH_SEED:
        return execute_allocate_with_seed(ctx);

    case SOL_SYSTEM_INSTR_ASSIGN_WITH_SEED:
        return execute_assign_with_seed(ctx);

    case SOL_SYSTEM_INSTR_TRANSFER_WITH_SEED:
        return execute_transfer_with_seed(ctx);

    case SOL_SYSTEM_INSTR_UPGRADE_NONCE:
        return execute_upgrade_nonce(ctx);

    default:
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
}

/*
 * Create instruction data helpers
 */

sol_err_t
sol_system_create_account_instruction(const sol_pubkey_t* from,
                                       const sol_pubkey_t* to,
                                       uint64_t lamports,
                                       uint64_t space,
                                       const sol_pubkey_t* owner,
                                       uint8_t* out_data,
                                       size_t* out_len) {
    (void)from;
    (void)to;

    if (!out_data || !out_len || *out_len < 52) {
        return SOL_ERR_INVAL;
    }

    uint32_t instr_type = SOL_SYSTEM_INSTR_CREATE_ACCOUNT;
    memcpy(out_data, &instr_type, 4);
    memcpy(out_data + 4, &lamports, 8);
    memcpy(out_data + 12, &space, 8);
    memcpy(out_data + 20, owner->bytes, 32);

    *out_len = 52;
    return SOL_OK;
}

sol_err_t
sol_system_transfer_instruction(const sol_pubkey_t* from,
                                 const sol_pubkey_t* to,
                                 uint64_t lamports,
                                 uint8_t* out_data,
                                 size_t* out_len) {
    (void)from;
    (void)to;

    if (!out_data || !out_len || *out_len < 12) {
        return SOL_ERR_INVAL;
    }

    uint32_t instr_type = SOL_SYSTEM_INSTR_TRANSFER;
    memcpy(out_data, &instr_type, 4);
    memcpy(out_data + 4, &lamports, 8);

    *out_len = 12;
    return SOL_OK;
}

sol_err_t
sol_system_assign_instruction(const sol_pubkey_t* account,
                               const sol_pubkey_t* owner,
                               uint8_t* out_data,
                               size_t* out_len) {
    (void)account;

    if (!out_data || !out_len || *out_len < 36) {
        return SOL_ERR_INVAL;
    }

    uint32_t instr_type = SOL_SYSTEM_INSTR_ASSIGN;
    memcpy(out_data, &instr_type, 4);
    memcpy(out_data + 4, owner->bytes, 32);

    *out_len = 36;
    return SOL_OK;
}

sol_err_t
sol_system_allocate_instruction(const sol_pubkey_t* account,
                                 uint64_t space,
                                 uint8_t* out_data,
                                 size_t* out_len) {
    (void)account;

    if (!out_data || !out_len || *out_len < 12) {
        return SOL_ERR_INVAL;
    }

    uint32_t instr_type = SOL_SYSTEM_INSTR_ALLOCATE;
    memcpy(out_data, &instr_type, 4);
    memcpy(out_data + 4, &space, 8);

    *out_len = 12;
    return SOL_OK;
}

sol_err_t
sol_create_with_seed(const sol_pubkey_t* base,
                      const char* seed,
                      size_t seed_len,
                      const sol_pubkey_t* program_id,
                      sol_pubkey_t* out_address) {
    if (!base || !seed || !program_id || !out_address) {
        return SOL_ERR_INVAL;
    }

    /* Address = SHA256(base || seed || program_id) */
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    sol_sha256_update(&ctx, base->bytes, 32);
    sol_sha256_update(&ctx, (const uint8_t*)seed, seed_len);
    sol_sha256_update(&ctx, program_id->bytes, 32);

    sol_sha256_t hash;
    sol_sha256_final(&ctx, &hash);
    memcpy(out_address->bytes, hash.bytes, 32);

    return SOL_OK;
}
