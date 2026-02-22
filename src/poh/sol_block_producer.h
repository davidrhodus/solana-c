/*
 * sol_block_producer.h - Block Production
 *
 * The block producer is responsible for:
 * - Receiving transactions from TPU
 * - Processing transactions through the bank
 * - Recording processed transactions in PoH
 * - Creating entries and shreds for propagation
 */

#ifndef SOL_BLOCK_PRODUCER_H
#define SOL_BLOCK_PRODUCER_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../runtime/sol_bank.h"
#include "../entry/sol_entry.h"
#include "../shred/sol_shred.h"
#include "sol_poh.h"
#include <pthread.h>

/*
 * Maximum transactions per entry
 */
#define SOL_MAX_TXS_PER_ENTRY 64

/*
 * Maximum entries per slot
 */
#define SOL_MAX_ENTRIES_PER_SLOT 4096

/*
 * Block producer configuration
 */
typedef struct {
    uint64_t    max_txs_per_entry;      /* Max transactions per entry */
    uint64_t    max_entries_per_slot;   /* Max entries per slot */
    uint64_t    target_ns_per_entry;    /* Target time per entry */
    bool        skip_verification;      /* Skip signature verification (testing) */
} sol_block_producer_config_t;

#define SOL_BLOCK_PRODUCER_CONFIG_DEFAULT {         \
    .max_txs_per_entry = SOL_MAX_TXS_PER_ENTRY,     \
    .max_entries_per_slot = SOL_MAX_ENTRIES_PER_SLOT, \
    .target_ns_per_entry = 6000000,  /* 6ms */      \
    .skip_verification = false,                      \
}

/*
 * Block producer handle
 */
typedef struct sol_block_producer sol_block_producer_t;

/*
 * Entry produced callback
 */
typedef void (*sol_entry_callback_t)(
    void*                   ctx,
    const sol_entry_t*      entry,
    sol_slot_t              slot,
    uint64_t                entry_index
);

/*
 * Slot completed callback
 */
typedef void (*sol_slot_complete_callback_t)(
    void*               ctx,
    sol_slot_t          slot,
    const sol_hash_t*   blockhash,
    uint64_t            num_entries,
    uint64_t            num_transactions
);

/*
 * Block data callback
 *
 * Called when a slot is completed and the block data (serialized entry batch)
 * is available.
 *
 * The block_data pointer is only valid for the duration of the callback.
 */
typedef void (*sol_block_data_callback_t)(
    void*               ctx,
    sol_slot_t          slot,
    const sol_hash_t*   blockhash,
    const uint8_t*      block_data,
    size_t              block_data_len,
    uint64_t            num_entries,
    uint64_t            num_transactions
);

/*
 * Create a new block producer
 *
 * @param poh_recorder      PoH recorder to use
 * @param config            Configuration (NULL for defaults)
 * @return                  Block producer or NULL on error
 */
sol_block_producer_t* sol_block_producer_new(
    sol_poh_recorder_t*                 poh_recorder,
    const sol_block_producer_config_t*  config
);

/*
 * Destroy block producer
 */
void sol_block_producer_destroy(sol_block_producer_t* producer);

/*
 * Set the working bank for the current slot
 *
 * Must be called before starting production for a slot.
 */
sol_err_t sol_block_producer_set_bank(
    sol_block_producer_t*   producer,
    sol_bank_t*             bank
);

/*
 * Clear the working bank
 */
sol_err_t sol_block_producer_clear_bank(sol_block_producer_t* producer);

/*
 * Start block production
 */
sol_err_t sol_block_producer_start(sol_block_producer_t* producer);

/*
 * Stop block production
 */
sol_err_t sol_block_producer_stop(sol_block_producer_t* producer);

/*
 * Check if currently producing
 */
bool sol_block_producer_is_producing(const sol_block_producer_t* producer);

/*
 * Submit a transaction for processing
 *
 * The transaction will be queued and processed by the producer.
 *
 * @param producer      Block producer
 * @param tx            Transaction to process
 * @return              SOL_OK if queued, error otherwise
 */
sol_err_t sol_block_producer_submit(
    sol_block_producer_t*       producer,
    const sol_transaction_t*    tx
);

/*
 * Submit a batch of transactions
 */
sol_err_t sol_block_producer_submit_batch(
    sol_block_producer_t*       producer,
    const sol_transaction_t**   txs,
    size_t                      count
);

/*
 * Force an entry to be created with current transactions
 */
sol_err_t sol_block_producer_flush_entry(sol_block_producer_t* producer);

/*
 * Get produced entries for the current slot
 *
 * @param producer      Block producer
 * @param out_entries   Output array for entries
 * @param max_entries   Maximum entries to return
 * @return              Number of entries written
 */
size_t sol_block_producer_get_entries(
    sol_block_producer_t*   producer,
    sol_entry_t*            out_entries,
    size_t                  max_entries
);

/*
 * Get current slot being produced
 */
sol_slot_t sol_block_producer_slot(const sol_block_producer_t* producer);

/*
 * Get number of entries produced in current slot
 */
uint64_t sol_block_producer_entry_count(const sol_block_producer_t* producer);

/*
 * Get number of transactions processed in current slot
 */
uint64_t sol_block_producer_tx_count(const sol_block_producer_t* producer);

/*
 * Set entry produced callback
 */
void sol_block_producer_set_entry_callback(
    sol_block_producer_t*   producer,
    sol_entry_callback_t    callback,
    void*                   ctx
);

/*
 * Set slot completed callback
 */
void sol_block_producer_set_slot_callback(
    sol_block_producer_t*           producer,
    sol_slot_complete_callback_t    callback,
    void*                           ctx
);

/*
 * Set block data callback
 */
void sol_block_producer_set_block_data_callback(
    sol_block_producer_t*           producer,
    sol_block_data_callback_t       callback,
    void*                           ctx
);

/*
 * Statistics
 */
typedef struct {
    uint64_t    entries_produced;       /* Total entries produced */
    uint64_t    transactions_processed; /* Total transactions processed */
    uint64_t    transactions_failed;    /* Transactions that failed */
    uint64_t    slots_completed;        /* Slots completed */
    uint64_t    ticks_produced;         /* Ticks produced */
} sol_block_producer_stats_t;

/*
 * Get statistics
 */
sol_block_producer_stats_t sol_block_producer_stats(
    const sol_block_producer_t* producer
);

#endif /* SOL_BLOCK_PRODUCER_H */
