/*
 * sol_sigverify.h - Parallel Signature Verification
 *
 * Sigverify performs parallel Ed25519 signature verification on batches
 * of transactions. This is one of the most compute-intensive parts of
 * transaction processing and benefits greatly from parallelization.
 */

#ifndef SOL_SIGVERIFY_H
#define SOL_SIGVERIFY_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../txn/sol_transaction.h"
#include <stdbool.h>
#include <pthread.h>

/*
 * Configuration
 */
typedef struct {
    size_t      num_threads;            /* Number of worker threads */
    size_t      batch_size;             /* Transactions per batch */
    bool        reject_invalid;         /* Reject invalid immediately */
} sol_sigverify_config_t;

#define SOL_SIGVERIFY_CONFIG_DEFAULT {  \
    .num_threads = 4,                   \
    .batch_size = 128,                  \
    .reject_invalid = true,             \
}

/*
 * Verification result for a single transaction
 */
typedef enum {
    SOL_SIGVERIFY_OK,               /* All signatures valid */
    SOL_SIGVERIFY_INVALID,          /* One or more signatures invalid */
    SOL_SIGVERIFY_MALFORMED,        /* Transaction is malformed */
    SOL_SIGVERIFY_PENDING,          /* Verification in progress */
} sol_sigverify_status_t;

/*
 * Transaction verification entry
 */
typedef struct {
    sol_transaction_t*      tx;             /* Transaction to verify */
    sol_sigverify_status_t  status;         /* Verification status */
    uint64_t                verify_time_ns; /* Time to verify (ns) */
} sol_sigverify_entry_t;

/*
 * Batch of transactions for verification
 */
typedef struct {
    sol_sigverify_entry_t*  entries;
    size_t                  count;
    size_t                  capacity;
    size_t                  verified;       /* Number verified so far */
    size_t                  valid;          /* Number valid */
    size_t                  invalid;        /* Number invalid */
} sol_sigverify_batch_t;

/*
 * Statistics
 */
typedef struct {
    uint64_t    transactions_verified;  /* Total txs verified */
    uint64_t    signatures_verified;    /* Total sigs verified */
    uint64_t    valid_count;            /* Valid transactions */
    uint64_t    invalid_count;          /* Invalid transactions */
    uint64_t    total_time_ns;          /* Total verification time */
    double      avg_time_per_sig_ns;    /* Average time per signature */
} sol_sigverify_stats_t;

/*
 * Sigverify service
 */
typedef struct sol_sigverify sol_sigverify_t;

/*
 * Create sigverify service
 */
sol_sigverify_t* sol_sigverify_new(const sol_sigverify_config_t* config);

/*
 * Destroy sigverify service
 */
void sol_sigverify_destroy(sol_sigverify_t* sv);

/*
 * Verify a single transaction (blocking)
 */
sol_sigverify_status_t sol_sigverify_verify_one(
    sol_sigverify_t* sv,
    sol_transaction_t* tx
);

/*
 * Verify transaction signatures directly (no service needed)
 */
sol_sigverify_status_t sol_sigverify_verify_tx(const sol_transaction_t* tx);

/*
 * Create a batch for verification
 */
sol_sigverify_batch_t* sol_sigverify_batch_new(size_t capacity);

/*
 * Destroy a batch
 */
void sol_sigverify_batch_destroy(sol_sigverify_batch_t* batch);

/*
 * Add transaction to batch
 */
sol_err_t sol_sigverify_batch_add(
    sol_sigverify_batch_t* batch,
    sol_transaction_t* tx
);

/*
 * Clear batch for reuse
 */
void sol_sigverify_batch_clear(sol_sigverify_batch_t* batch);

/*
 * Verify all transactions in batch (blocking)
 * Uses worker threads for parallel verification.
 */
sol_err_t sol_sigverify_verify_batch(
    sol_sigverify_t* sv,
    sol_sigverify_batch_t* batch
);

/*
 * Submit batch for async verification (non-blocking)
 */
sol_err_t sol_sigverify_submit_batch(
    sol_sigverify_t* sv,
    sol_sigverify_batch_t* batch
);

/*
 * Wait for batch verification to complete
 */
sol_err_t sol_sigverify_wait_batch(
    sol_sigverify_t* sv,
    sol_sigverify_batch_t* batch,
    uint64_t timeout_ms
);

/*
 * Get verification statistics
 */
void sol_sigverify_stats(
    const sol_sigverify_t* sv,
    sol_sigverify_stats_t* out_stats
);

/*
 * Reset statistics
 */
void sol_sigverify_stats_reset(sol_sigverify_t* sv);

/*
 * Filter batch to only valid transactions
 * Moves valid transactions to front, returns count of valid.
 */
size_t sol_sigverify_batch_filter_valid(sol_sigverify_batch_t* batch);

/*
 * Get valid transactions from batch
 * Returns array of pointers to valid transactions.
 * Caller must free the returned array (but not the transactions).
 */
sol_transaction_t** sol_sigverify_batch_get_valid(
    const sol_sigverify_batch_t* batch,
    size_t* out_count
);

#endif /* SOL_SIGVERIFY_H */
