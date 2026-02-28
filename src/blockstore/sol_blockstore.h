/*
 * sol_blockstore.h - Shred and Block Storage
 *
 * The blockstore stores shreds received from turbine/repair and
 * assembles them into complete blocks for replay.
 *
 * Supports both in-memory storage (for testing) and persistent
 * RocksDB storage (for production).
 */

#ifndef SOL_BLOCKSTORE_H
#define SOL_BLOCKSTORE_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../shred/sol_shred.h"
#include "../txn/sol_pubkey.h"
#include "../storage/sol_storage_backend.h"
#include <pthread.h>

/*
 * Blockstore constants
 */
#define SOL_BLOCKSTORE_MAX_SLOTS        1024    /* Max slots in memory */
#define SOL_BLOCKSTORE_MAX_SHREDS_SLOT  2048    /* Max shreds per slot */

/*
 * Slot metadata
 */
typedef struct {
    sol_slot_t      slot;
    sol_slot_t      parent_slot;
    sol_pubkey_t    leader;

    /* Shred tracking */
    uint32_t        num_data_shreds;        /* Total data shreds expected */
    uint32_t        num_code_shreds;        /* Total code shreds expected */
    uint32_t        received_data;          /* Data shreds received */
    uint32_t        received_code;          /* Code shreds received */
    uint32_t        first_shred_index;      /* First shred index in slot */
    uint32_t        last_shred_index;       /* Last shred index (if known) */

    /* Flags */
    bool            is_complete;            /* All data shreds received */
    bool            is_full;                /* Last shred received */
    bool            is_rooted;              /* Slot is rooted/finalized */
    bool            is_dead;                /* Slot marked dead (invalid) */

    /* Timing */
    uint64_t        received_time;          /* First shred received time */
    uint64_t        completed_time;         /* Slot completion time */
} sol_slot_meta_t;

/*
 * Shred storage entry
 */
typedef struct {
    uint32_t        index;                  /* Shred index */
    bool            is_data;                /* Data or code shred */
    uint8_t*        data;                   /* Raw shred data */
    size_t          data_len;               /* Shred data length */
} sol_blockstore_shred_t;

/*
 * Slot storage
 */
typedef struct {
    sol_slot_meta_t         meta;
    sol_blockstore_shred_t* data_shreds;    /* Data shreds array */
    sol_blockstore_shred_t* code_shreds;    /* Code shreds array */
    size_t                  data_capacity;
    size_t                  code_capacity;
    uint8_t*                received_bitmap; /* Bitmap of received shreds */
    size_t                  bitmap_size;
} sol_slot_store_t;

/*
 * Block data (assembled from shreds)
 */
typedef struct {
    sol_slot_t      slot;
    sol_slot_t      parent_slot;
    sol_pubkey_t    leader;
    uint8_t*        data;                   /* Block entry data */
    size_t          data_len;
    uint32_t        num_entries;            /* Number of entries */
    uint32_t        num_transactions;       /* Total transactions */
} sol_block_t;

/*
 * Blockstore statistics
 */
typedef struct {
    uint64_t        shreds_received;
    uint64_t        shreds_inserted;
    uint64_t        shreds_duplicate;
    uint64_t        slots_created;
    uint64_t        slots_completed;
    uint64_t        slots_rooted;
    uint64_t        blocks_assembled;
} sol_blockstore_stats_t;

/*
 * Blockstore storage type
 */
typedef enum {
    SOL_BLOCKSTORE_STORAGE_MEMORY  = 0,  /* In-memory only (default) */
    SOL_BLOCKSTORE_STORAGE_ROCKSDB = 1,  /* RocksDB persistent storage */
} sol_blockstore_storage_type_t;

/*
 * Blockstore configuration
 */
typedef struct {
    size_t                          max_slots;          /* Max slots to keep in memory */
    size_t                          max_shreds_per_slot;/* Max shreds per slot */
    bool                            enable_fec_recovery;/* Enable FEC shred recovery */
    sol_blockstore_storage_type_t   storage_type;       /* Storage backend type */
    const char*                     rocksdb_path;       /* Path for RocksDB (if used) */
    size_t                          rocksdb_cache_mb;   /* RocksDB block cache size MB */
} sol_blockstore_config_t;

#define SOL_BLOCKSTORE_CONFIG_DEFAULT {         \
    .max_slots = 1024,                          \
    .max_shreds_per_slot = 32768,               \
    .enable_fec_recovery = true,                \
    .storage_type = SOL_BLOCKSTORE_STORAGE_MEMORY, \
    .rocksdb_path = NULL,                       \
    .rocksdb_cache_mb = 512,                    \
}

/*
 * Blockstore handle
 */
typedef struct sol_blockstore sol_blockstore_t;

/*
 * Slot completion callback
 */
typedef void (*sol_blockstore_slot_cb)(
    sol_slot_t      slot,
    void*           ctx
);

/*
 * Create blockstore
 */
sol_blockstore_t* sol_blockstore_new(const sol_blockstore_config_t* config);

/*
 * Destroy blockstore
 */
void sol_blockstore_destroy(sol_blockstore_t* bs);

/*
 * Insert a shred
 *
 * Returns:
 *   SOL_OK - Shred inserted successfully
 *   SOL_ERR_DUPLICATE - Shred already exists
 *   SOL_ERR_INVAL - Invalid shred
 */
sol_err_t sol_blockstore_insert_shred(
    sol_blockstore_t*   bs,
    const sol_shred_t*  shred,
    const uint8_t*      raw_data,
    size_t              raw_len
);

/*
 * Insert multiple shreds
 */
sol_err_t sol_blockstore_insert_shreds(
    sol_blockstore_t*       bs,
    const sol_shred_t*      shreds,
    const uint8_t* const*   raw_data,
    const size_t*           raw_lens,
    size_t                  count
);

/*
 * Get shred by slot and index
 */
sol_err_t sol_blockstore_get_shred(
    sol_blockstore_t*   bs,
    sol_slot_t          slot,
    uint32_t            index,
    bool                is_data,
    uint8_t*            buf,
    size_t*             buf_len
);

/*
 * Check if shred exists
 */
bool sol_blockstore_has_shred(
    sol_blockstore_t*   bs,
    sol_slot_t          slot,
    uint32_t            index,
    bool                is_data
);

/*
 * Get slot metadata
 */
sol_err_t sol_blockstore_get_slot_meta(
    sol_blockstore_t*   bs,
    sol_slot_t          slot,
    sol_slot_meta_t*    meta
);

/*
 * Get slot metadata for a specific variant.
 *
 * For variant_id == 0, this is equivalent to sol_blockstore_get_slot_meta().
 */
sol_err_t sol_blockstore_get_slot_meta_variant(
    sol_blockstore_t*   bs,
    sol_slot_t          slot,
    uint32_t            variant_id,
    sol_slot_meta_t*    meta
);

/*
 * Check if slot is complete
 */
bool sol_blockstore_is_slot_complete(
    sol_blockstore_t*   bs,
    sol_slot_t          slot
);

/*
 * Get missing shred indices for a slot
 */
size_t sol_blockstore_get_missing_shreds(
    sol_blockstore_t*   bs,
    sol_slot_t          slot,
    uint32_t*           indices,
    size_t              max_indices
);

/*
 * Assemble block from complete slot
 *
 * Caller must free returned block with sol_block_destroy
 */
sol_block_t* sol_blockstore_get_block(
    sol_blockstore_t*   bs,
    sol_slot_t          slot
);

/*
 * Get number of stored block variants for a slot.
 *
 * Variant 0 is the primary shard set. Additional variants are created when
 * conflicting data shreds are observed for the same (slot, index).
 */
size_t sol_blockstore_num_variants(
    sol_blockstore_t*   bs,
    sol_slot_t          slot
);

/*
 * Assemble block for a specific variant.
 *
 * @param variant_id    0 for the primary variant, otherwise a slot-local id
 */
sol_block_t* sol_blockstore_get_block_variant(
    sol_blockstore_t*   bs,
    sol_slot_t          slot,
    uint32_t            variant_id
);

/*
 * Assemble block for a specific variant from persistent storage only (RocksDB).
 *
 * This bypasses the in-memory slot cache and is useful as a fallback path when
 * in-memory assembly fails or is suspected to be corrupt.
 *
 * Returns NULL when RocksDB support is not enabled or persistence isn't
 * configured.
 */
sol_block_t* sol_blockstore_get_block_variant_rocksdb(
    sol_blockstore_t*   bs,
    sol_slot_t          slot,
    uint32_t            variant_id
);

/*
 * Free block
 */
void sol_block_destroy(sol_block_t* block);

/*
 * Set slot as rooted
 */
sol_err_t sol_blockstore_set_rooted(
    sol_blockstore_t*   bs,
    sol_slot_t          slot
);

/*
 * Set slot as dead
 */
sol_err_t sol_blockstore_set_dead(
    sol_blockstore_t*   bs,
    sol_slot_t          slot
);

/*
 * Get block hash for a slot
 *
 * The block hash is the hash of the last entry in the slot.
 */
sol_err_t sol_blockstore_get_block_hash(
    sol_blockstore_t*   bs,
    sol_slot_t          slot,
    sol_hash_t*         hash
);

/*
 * Get block hash for a specific variant.
 *
 * For variant_id == 0, this is equivalent to sol_blockstore_get_block_hash().
 */
sol_err_t sol_blockstore_get_block_hash_variant(
    sol_blockstore_t*   bs,
    sol_slot_t          slot,
    uint32_t            variant_id,
    sol_hash_t*         hash
);

/*
 * Get highest slot with data
 */
sol_slot_t sol_blockstore_highest_slot(sol_blockstore_t* bs);

/*
 * Get highest complete slot
 */
sol_slot_t sol_blockstore_highest_complete_slot(sol_blockstore_t* bs);

/*
 * Get highest rooted slot
 */
sol_slot_t sol_blockstore_highest_rooted_slot(sol_blockstore_t* bs);

/*
 * Get lowest available slot
 */
sol_slot_t sol_blockstore_lowest_slot(sol_blockstore_t* bs);

/*
 * Set slot completion callback
 */
void sol_blockstore_set_slot_callback(
    sol_blockstore_t*       bs,
    sol_blockstore_slot_cb  callback,
    void*                   ctx
);

/*
 * Purge old slots below a given slot
 */
size_t sol_blockstore_purge_slots_below(
    sol_blockstore_t*   bs,
    sol_slot_t          min_slot
);

/*
 * Get statistics
 */
void sol_blockstore_stats(
    const sol_blockstore_t* bs,
    sol_blockstore_stats_t* stats
);

/*
 * Reset statistics
 */
void sol_blockstore_stats_reset(sol_blockstore_t* bs);

/*
 * Get slot count
 */
size_t sol_blockstore_slot_count(const sol_blockstore_t* bs);

/*
 * Transaction signature index (for RPC)
 */
typedef struct {
    sol_signature_t signature;
    sol_slot_t      slot;
    sol_err_t       err;   /* SOL_OK on success */
} sol_blockstore_address_signature_t;

/*
 * Index a transaction signature for all involved addresses.
 *
 * This is used to back getSignaturesForAddress-style queries.
 */
sol_err_t sol_blockstore_index_transaction(
    sol_blockstore_t*        bs,
    sol_slot_t               slot,
    const sol_signature_t*   signature,
    const sol_pubkey_t*      account_keys,
    size_t                   account_keys_len,
    sol_err_t                err
);

/*
 * Batch-write address signature index entries.
 *
 * This is a lower-level helper to avoid per-transaction RocksDB write overhead
 * in replay/catchup. Each op in `batch` must be a `SOL_BATCH_OP_PUT` where:
 * - key: [32 bytes address][8 bytes inv_slot_be][64 bytes signature]
 * - value: 4 bytes int32 error code (host endian)
 *
 * Returns SOL_ERR_NOT_IMPLEMENTED if the address signature index is disabled or
 * the backend does not support batch writes.
 */
sol_err_t sol_blockstore_address_sig_batch_write(
    sol_blockstore_t*     bs,
    sol_storage_batch_t*  batch
);

/*
 * Returns true if the address signature index is available and supports
 * `batch_write`.
 */
bool sol_blockstore_address_sig_batch_supported(const sol_blockstore_t* bs);

/*
 * Query recent signatures for an address.
 *
 * Results are returned in descending slot order (best-effort).
 */
size_t sol_blockstore_get_signatures_for_address(
    sol_blockstore_t*                    bs,
    const sol_pubkey_t*                  address,
    size_t                               limit,
    sol_blockstore_address_signature_t*  out,
    size_t                               out_cap
);

#endif /* SOL_BLOCKSTORE_H */
