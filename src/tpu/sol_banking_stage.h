/*
 * sol_banking_stage.h - Banking Stage (Transaction Processing)
 *
 * The banking stage receives verified transactions from sigverify and
 * processes them in batches. It handles:
 *   - Transaction deduplication
 *   - Account lock acquisition
 *   - Parallel transaction execution
 *   - Entry creation for PoH
 */

#ifndef SOL_BANKING_STAGE_H
#define SOL_BANKING_STAGE_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../txn/sol_transaction.h"
#include "../runtime/sol_bank.h"
#include "../runtime/sol_compute_budget.h"
#include "sol_sigverify.h"
#include <stdbool.h>
#include <pthread.h>

/*
 * Configuration
 */
typedef struct {
    size_t      num_threads;            /* Number of processing threads */
    size_t      batch_size;             /* Transactions per batch */
    size_t      max_pending_txs;        /* Max pending transactions */
    uint64_t    max_batch_time_ns;      /* Max time per batch */
    bool        enable_forwarding;      /* Forward to next leader */
} sol_banking_stage_config_t;

#define SOL_BANKING_STAGE_CONFIG_DEFAULT {  \
    .num_threads = 4,                       \
    .batch_size = 64,                       \
    .max_pending_txs = 10000,               \
    .max_batch_time_ns = 100000000,         \
    .enable_forwarding = false,             \
}

/*
 * Transaction processing result
 */
typedef enum {
    SOL_BANKING_SUCCESS,            /* Transaction executed successfully */
    SOL_BANKING_FAILED,             /* Transaction execution failed */
    SOL_BANKING_DUPLICATE,          /* Duplicate transaction */
    SOL_BANKING_EXPIRED,            /* Transaction expired (blockhash) */
    SOL_BANKING_ACCOUNT_LOCKED,     /* Account locked by another tx */
    SOL_BANKING_INSUFFICIENT_FUNDS, /* Insufficient lamports for fees */
    SOL_BANKING_COST_LIMIT,         /* Block cost limit exceeded */
    SOL_BANKING_DROPPED,            /* Transaction dropped */
} sol_banking_result_t;

/*
 * Processing result for a single transaction
 */
typedef struct {
    sol_transaction_t*      tx;
    sol_banking_result_t    result;
    sol_err_t               error;          /* Execution error if failed */
    uint64_t                compute_used;   /* Compute units consumed */
    uint64_t                fee_paid;       /* Fee paid */
} sol_banking_tx_result_t;

/*
 * Batch processing results
 */
typedef struct {
    sol_banking_tx_result_t*    results;
    size_t                      count;
    size_t                      successful;
    size_t                      failed;
    size_t                      dropped;
    uint64_t                    total_cu_used;
    uint64_t                    total_fees;
    uint64_t                    process_time_ns;
} sol_banking_batch_result_t;

/*
 * Statistics
 */
typedef struct {
    uint64_t    transactions_received;
    uint64_t    transactions_processed;
    uint64_t    transactions_successful;
    uint64_t    transactions_failed;
    uint64_t    transactions_dropped;
    uint64_t    duplicates_filtered;
    uint64_t    expired_filtered;
    uint64_t    batches_processed;
    uint64_t    total_cu_consumed;
    uint64_t    total_fees_collected;
    uint64_t    total_process_time_ns;
    double      avg_batch_time_ns;
    double      tps;                    /* Transactions per second */
} sol_banking_stage_stats_t;

/*
 * Account lock manager
 */
typedef struct sol_account_locks sol_account_locks_t;

sol_account_locks_t* sol_account_locks_new(void);
void sol_account_locks_destroy(sol_account_locks_t* locks);

/*
 * Try to acquire locks for a transaction
 * Returns true if all locks acquired, false otherwise.
 */
bool sol_account_locks_try_lock(
    sol_account_locks_t* locks,
    const sol_transaction_t* tx
);

/*
 * Release locks for a transaction
 */
void sol_account_locks_unlock(
    sol_account_locks_t* locks,
    const sol_transaction_t* tx
);

/*
 * Banking stage service
 */
typedef struct sol_banking_stage sol_banking_stage_t;

/*
 * Create banking stage
 */
sol_banking_stage_t* sol_banking_stage_new(
    sol_bank_t* bank,
    sol_sigverify_t* sigverify,
    const sol_banking_stage_config_t* config
);

/*
 * Destroy banking stage
 */
void sol_banking_stage_destroy(sol_banking_stage_t* stage);

/*
 * Start banking stage processing
 */
sol_err_t sol_banking_stage_start(sol_banking_stage_t* stage);

/*
 * Stop banking stage processing
 */
void sol_banking_stage_stop(sol_banking_stage_t* stage);

/*
 * Submit transaction for processing
 */
sol_err_t sol_banking_stage_submit(
    sol_banking_stage_t* stage,
    sol_transaction_t* tx
);

/*
 * Submit batch of transactions
 */
sol_err_t sol_banking_stage_submit_batch(
    sol_banking_stage_t* stage,
    sol_transaction_t** txs,
    size_t count
);

/*
 * Process a single batch (blocking)
 * Processes up to batch_size transactions from the queue.
 */
sol_err_t sol_banking_stage_process_batch(
    sol_banking_stage_t* stage,
    sol_banking_batch_result_t* out_result
);

/*
 * Get pending transaction count
 */
size_t sol_banking_stage_pending_count(const sol_banking_stage_t* stage);

/*
 * Set the bank for processing
 */
void sol_banking_stage_set_bank(sol_banking_stage_t* stage, sol_bank_t* bank);

/*
 * Get statistics
 */
void sol_banking_stage_stats(
    const sol_banking_stage_t* stage,
    sol_banking_stage_stats_t* out_stats
);

/*
 * Reset statistics
 */
void sol_banking_stage_stats_reset(sol_banking_stage_t* stage);

/*
 * Check if transaction has been seen (deduplication)
 */
bool sol_banking_stage_is_duplicate(
    sol_banking_stage_t* stage,
    const sol_transaction_t* tx
);

/*
 * Mark transaction as seen
 */
void sol_banking_stage_mark_seen(
    sol_banking_stage_t* stage,
    const sol_transaction_t* tx
);

/*
 * Transaction queue for pending transactions
 */
typedef struct sol_tx_queue sol_tx_queue_t;

sol_tx_queue_t* sol_tx_queue_new(size_t capacity);
void sol_tx_queue_destroy(sol_tx_queue_t* queue);
sol_err_t sol_tx_queue_push(sol_tx_queue_t* queue, sol_transaction_t* tx);
sol_transaction_t* sol_tx_queue_pop(sol_tx_queue_t* queue);
size_t sol_tx_queue_len(const sol_tx_queue_t* queue);
bool sol_tx_queue_is_empty(const sol_tx_queue_t* queue);
bool sol_tx_queue_is_full(const sol_tx_queue_t* queue);
void sol_tx_queue_clear(sol_tx_queue_t* queue);

/*
 * Prioritized transaction queue (by fee)
 */
typedef struct sol_priority_queue sol_priority_queue_t;

sol_priority_queue_t* sol_priority_queue_new(size_t capacity);
void sol_priority_queue_destroy(sol_priority_queue_t* pq);
sol_err_t sol_priority_queue_push(sol_priority_queue_t* pq, sol_transaction_t* tx, uint64_t priority);
sol_transaction_t* sol_priority_queue_pop(sol_priority_queue_t* pq);
size_t sol_priority_queue_len(const sol_priority_queue_t* pq);

#endif /* SOL_BANKING_STAGE_H */
