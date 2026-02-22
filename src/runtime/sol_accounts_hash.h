/*
 * sol_accounts_hash.h - Extended Accounts Hash Computation
 *
 * This extends the basic accounts hash in sol_accounts_db with:
 *   - Incremental hash computation
 *   - Delta hashes for incremental snapshots
 *   - Bank hash computation
 *
 * Note: Basic account hash and db hash are in sol_account.h and sol_accounts_db.h
 */

#ifndef SOL_ACCOUNTS_HASH_H
#define SOL_ACCOUNTS_HASH_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "sol_accounts_db.h"

/*
 * Accumulator for incremental accounts hash computation
 */
typedef struct {
    sol_hash_t          current;        /* Current accumulated hash */
    size_t              count;          /* Number of accounts accumulated */
    uint64_t            lamports;       /* Total lamports */
} sol_accounts_hash_acc_t;

/*
 * Initialize accumulator
 */
void sol_accounts_hash_acc_init(sol_accounts_hash_acc_t* acc);

/*
 * Add an account hash to the accumulator
 */
void sol_accounts_hash_acc_add(
    sol_accounts_hash_acc_t* acc,
    const sol_hash_t* account_hash,
    uint64_t lamports
);

/*
 * Finalize and get the accounts hash
 */
void sol_accounts_hash_acc_finalize(
    const sol_accounts_hash_acc_t* acc,
    sol_hash_t* out_hash
);

/*
 * Combine two accounts hashes (for parallel computation)
 */
void sol_accounts_hash_combine(
    const sol_hash_t* hash1,
    const sol_hash_t* hash2,
    sol_hash_t* out_hash
);

/*
 * Compute bank hash from accounts hash and other inputs
 * Bank hash = SHA256(accounts_hash || num_sigs || last_blockhash || epoch_accounts_hash)
 */
void sol_bank_hash_compute(
    const sol_hash_t* accounts_hash,
    uint64_t num_signatures,
    const sol_hash_t* last_blockhash,
    const sol_hash_t* epoch_accounts_hash,  /* May be NULL for non-epoch slots */
    sol_hash_t* out_hash
);

#endif /* SOL_ACCOUNTS_HASH_H */
