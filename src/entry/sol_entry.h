/*
 * sol_entry.h - Block Entry Structure
 *
 * Entries are the atomic units within a block. Each entry contains:
 * - A hash (the PoH hash at this point)
 * - Number of hashes since the previous entry
 * - A list of transactions
 *
 * The entry hash chain forms the Proof of History (PoH) sequence.
 */

#ifndef SOL_ENTRY_H
#define SOL_ENTRY_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../crypto/sol_sha256.h"
#include "../txn/sol_transaction.h"

/*
 * Entry constants
 */
#define SOL_ENTRY_MAX_TRANSACTIONS  2048    /* Max transactions per entry */
#define SOL_ENTRY_HASH_SIZE         32      /* SHA256 hash size */

/*
 * Entry structure
 *
 * Wire format:
 *   num_hashes: u64
 *   hash: [u8; 32]
 *   num_transactions: u64
 *   transactions: [Transaction; num_transactions]
 */
typedef struct {
    uint64_t            num_hashes;             /* Hashes since previous entry */
    sol_hash_t          hash;                   /* PoH hash at this entry */
    uint32_t            num_transactions;       /* Number of transactions */
    sol_transaction_t*  transactions;           /* Parsed transactions */
    size_t              transactions_capacity;  /* Allocated capacity */

    /* Raw transaction data (needed because transactions use zero-copy) */
    uint8_t*            raw_data;               /* Owned copy of transaction data */
    size_t              raw_data_len;
} sol_entry_t;

/*
 * Entry batch (multiple entries from a block)
 */
typedef struct {
    sol_entry_t*    entries;                /* Array of entries */
    size_t          num_entries;            /* Number of entries */
    size_t          capacity;               /* Allocated capacity */
    sol_slot_t      slot;                   /* Slot these entries belong to */
} sol_entry_batch_t;

/*
 * Entry verification result
 */
typedef struct {
    bool            valid;                  /* Overall validity */
    uint32_t        num_verified;           /* Number of entries verified */
    uint32_t        failed_entry;           /* Index of failed entry (if any) */
    sol_err_t       error;                  /* Error code if invalid */
} sol_entry_verify_result_t;

/*
 * Initialize entry structure
 */
void sol_entry_init(sol_entry_t* entry);

/*
 * Cleanup entry (free internal allocations)
 */
void sol_entry_cleanup(sol_entry_t* entry);

/*
 * Parse entry from binary data
 *
 * Returns:
 *   SOL_OK on success
 *   SOL_ERR_PARSE on parse error
 *   SOL_ERR_TRUNCATED if data is incomplete
 */
sol_err_t sol_entry_parse(
    sol_entry_t*    entry,
    const uint8_t*  data,
    size_t          len,
    size_t*         bytes_consumed
);

/*
 * Serialize entry to binary
 */
sol_err_t sol_entry_serialize(
    const sol_entry_t*  entry,
    uint8_t*            buf,
    size_t              buf_len,
    size_t*             bytes_written
);

/*
 * Verify entry hash chain
 *
 * Verifies that entry.hash = SHA256(prev_hash, entry.num_hashes, transactions)
 */
bool sol_entry_verify_hash(
    const sol_entry_t*  entry,
    const sol_hash_t*   prev_hash
);

/*
 * Verify all transaction signatures in entry
 */
bool sol_entry_verify_signatures(const sol_entry_t* entry);

/*
 * Check if entry is a tick (no transactions, just PoH advancement)
 */
static inline bool
sol_entry_is_tick(const sol_entry_t* entry) {
    return entry && entry->num_transactions == 0;
}

/*
 * Get total transaction count in entry
 */
static inline uint32_t
sol_entry_transaction_count(const sol_entry_t* entry) {
    return entry ? entry->num_transactions : 0;
}

/*
 * Create entry batch
 */
sol_entry_batch_t* sol_entry_batch_new(size_t initial_capacity);

/*
 * Destroy entry batch
 */
void sol_entry_batch_destroy(sol_entry_batch_t* batch);

/*
 * Parse entries from block data
 *
 * Block data is a sequence of entries.
 */
sol_err_t sol_entry_batch_parse(
    sol_entry_batch_t*  batch,
    const uint8_t*      data,
    size_t              len
);

/*
 * Verify entry batch hash chain
 *
 * Verifies that all entries form a valid PoH chain starting from start_hash.
 */
sol_entry_verify_result_t sol_entry_batch_verify(
    const sol_entry_batch_t*    batch,
    const sol_hash_t*           start_hash
);

/*
 * Get total transaction count in batch
 */
uint32_t sol_entry_batch_transaction_count(const sol_entry_batch_t* batch);

/*
 * Get tick count in batch
 */
uint32_t sol_entry_batch_tick_count(const sol_entry_batch_t* batch);

/*
 * Compute entry hash
 *
 * hash = SHA256(prev_hash || num_hashes || merkle_root(transactions))
 */
void sol_entry_compute_hash(
    const sol_entry_t*  entry,
    const sol_hash_t*   prev_hash,
    sol_hash_t*         out_hash
);

/*
 * Compute transaction merkle root
 */
void sol_entry_transaction_merkle_root(
    const sol_entry_t*  entry,
    sol_hash_t*         out_root
);

#endif /* SOL_ENTRY_H */
