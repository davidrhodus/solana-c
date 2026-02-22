/*
 * sol_accounts_hash.c - Extended Accounts Hash Computation Implementation
 */

#include "sol_accounts_hash.h"
#include "../crypto/sol_sha256.h"
#include <string.h>

/*
 * Accumulator functions
 */

void
sol_accounts_hash_acc_init(sol_accounts_hash_acc_t* acc) {
    if (!acc) return;
    memset(acc, 0, sizeof(sol_accounts_hash_acc_t));
}

void
sol_accounts_hash_acc_add(sol_accounts_hash_acc_t* acc,
                          const sol_hash_t* account_hash,
                          uint64_t lamports) {
    if (!acc || !account_hash) return;

    /* Skip zero hashes (from zero-lamport accounts) */
    if (sol_hash_is_zero(account_hash)) {
        return;
    }

    /* Update running hash: new_hash = SHA256(current || account_hash) */
    if (acc->count == 0) {
        acc->current = *account_hash;
    } else {
        sol_sha256_ctx_t ctx;
        sol_sha256_init(&ctx);
        sol_sha256_update(&ctx, acc->current.bytes, SOL_HASH_SIZE);
        sol_sha256_update(&ctx, account_hash->bytes, SOL_HASH_SIZE);
        sol_sha256_t result;
        sol_sha256_final(&ctx, &result);
        memcpy(acc->current.bytes, result.bytes, SOL_HASH_SIZE);
    }

    acc->count++;
    acc->lamports += lamports;
}

void
sol_accounts_hash_acc_finalize(const sol_accounts_hash_acc_t* acc,
                                sol_hash_t* out_hash) {
    if (!acc || !out_hash) return;

    if (acc->count == 0) {
        memset(out_hash->bytes, 0, SOL_HASH_SIZE);
    } else {
        *out_hash = acc->current;
    }
}

/*
 * Combine two hashes (for parallel merging)
 */
void
sol_accounts_hash_combine(const sol_hash_t* hash1,
                          const sol_hash_t* hash2,
                          sol_hash_t* out_hash) {
    if (!hash1 || !hash2 || !out_hash) return;

    /* If either hash is zero, return the other */
    if (sol_hash_is_zero(hash1)) {
        *out_hash = *hash2;
        return;
    }
    if (sol_hash_is_zero(hash2)) {
        *out_hash = *hash1;
        return;
    }

    /* Combined hash = SHA256(hash1 || hash2) */
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    sol_sha256_update(&ctx, hash1->bytes, SOL_HASH_SIZE);
    sol_sha256_update(&ctx, hash2->bytes, SOL_HASH_SIZE);
    sol_sha256_t result;
    sol_sha256_final(&ctx, &result);
    memcpy(out_hash->bytes, result.bytes, SOL_HASH_SIZE);
}

/*
 * Compute bank hash
 *
 * The bank hash combines:
 * - Accounts hash (state of all accounts)
 * - Number of signatures processed
 * - Last blockhash
 * - Epoch accounts hash (at epoch boundaries)
 */
void
sol_bank_hash_compute(const sol_hash_t* accounts_hash,
                      uint64_t num_signatures,
                      const sol_hash_t* last_blockhash,
                      const sol_hash_t* epoch_accounts_hash,
                      sol_hash_t* out_hash) {
    if (!accounts_hash || !last_blockhash || !out_hash) return;

    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);

    /* Accounts hash */
    sol_sha256_update(&ctx, accounts_hash->bytes, SOL_HASH_SIZE);

    /* Number of signatures (8 bytes) */
    sol_sha256_update(&ctx, (uint8_t*)&num_signatures, 8);

    /* Last blockhash */
    sol_sha256_update(&ctx, last_blockhash->bytes, SOL_HASH_SIZE);

    /* Epoch accounts hash (if provided) */
    if (epoch_accounts_hash != NULL) {
        sol_sha256_update(&ctx, epoch_accounts_hash->bytes, SOL_HASH_SIZE);
    }

    sol_sha256_t result;
    sol_sha256_final(&ctx, &result);
    memcpy(out_hash->bytes, result.bytes, SOL_HASH_SIZE);
}
