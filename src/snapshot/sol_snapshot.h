/*
 * sol_snapshot.h - Snapshot Support
 *
 * Snapshots provide a way to capture the complete validator state at a point
 * in time, enabling fast sync without replaying all transactions from genesis.
 *
 * Snapshot types:
 * - Full snapshot: Complete account state at a slot
 * - Incremental snapshot: Changes since a base full snapshot
 *
 * Archive format: tar.zst containing:
 * - snapshots/<slot>/snapshots/<slot>/<slot>  (bank serialization)
 * - accounts/<slot>.0/...                      (account storage files)
 * - version                                    (format version)
 * - status_cache                               (recent tx results)
 */

#ifndef SOL_SNAPSHOT_H
#define SOL_SNAPSHOT_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../runtime/sol_bank.h"
#include "../runtime/sol_accounts_db.h"

/*
 * Snapshot archive version
 */
#define SOL_SNAPSHOT_VERSION        1
#define SOL_SNAPSHOT_ARCHIVE_VERSION "1.2.0"

/*
 * Snapshot type
 */
typedef enum {
    SOL_SNAPSHOT_FULL,          /* Full snapshot */
    SOL_SNAPSHOT_INCREMENTAL,   /* Incremental from base */
} sol_snapshot_type_t;

/*
 * Snapshot archive compression
 */
typedef enum {
    SOL_SNAPSHOT_COMPRESSION_NONE,
    SOL_SNAPSHOT_COMPRESSION_GZIP,
    SOL_SNAPSHOT_COMPRESSION_BZIP2,
    SOL_SNAPSHOT_COMPRESSION_ZSTD,
    SOL_SNAPSHOT_COMPRESSION_LZ4,
} sol_snapshot_compression_t;

/*
 * Snapshot info (manifest)
 */
typedef struct {
    sol_slot_t              slot;               /* Snapshot slot */
    sol_hash_t              hash;               /* Hash token from archive name (Solana snapshot hash) */
    sol_hash_t              bank_hash;          /* Bank hash at this slot (for voting/replay verification) */
    sol_hash_t              accounts_hash;      /* Accounts hash (if present in manifest) */
    sol_hash_t              epoch_accounts_hash; /* Epoch accounts hash (if present in manifest) */
    bool                    manifest_is_solana_c; /* manifest format=solana-c (hash token may not match Solana snapshot hash) */
    sol_slot_t              base_slot;          /* Base snapshot slot (for incremental) */
    sol_hash_t              base_hash;          /* Base snapshot hash */
    sol_snapshot_type_t     type;               /* Full or incremental */
    uint64_t                lamports_per_signature; /* Fee rate */
    uint64_t                epoch;              /* Current epoch */
    uint64_t                block_height;       /* Block height */
    uint64_t                capitalization;     /* Total lamports */
    uint64_t                num_accounts;       /* Number of accounts */
    uint64_t                archive_size;       /* Compressed size */
    uint64_t                uncompressed_size;  /* Uncompressed size */
    sol_snapshot_compression_t compression;     /* Compression type */
} sol_snapshot_info_t;

/*
 * Snapshot configuration
 */
typedef struct {
    char*                       snapshot_dir;       /* Directory for snapshots */
    char*                       archive_dir;        /* Directory for archives */
    uint64_t                    full_interval;      /* Slots between full snapshots */
    uint64_t                    incremental_interval; /* Slots between incrementals */
    sol_snapshot_compression_t  compression;        /* Compression to use */
    uint32_t                    compression_level;  /* Compression level (1-22 for zstd) */
    uint64_t                    max_archive_count;  /* Max archives to keep */
    bool                        enable_incremental; /* Enable incremental snapshots */
    bool                        verify_accounts_hash; /* Verify snapshot accounts hash at load time (very expensive) */
} sol_snapshot_config_t;

#define SOL_SNAPSHOT_CONFIG_DEFAULT {                   \
    .snapshot_dir = NULL,                               \
    .archive_dir = NULL,                                \
    .full_interval = 25000,                             \
    .incremental_interval = 5000,                       \
    .compression = SOL_SNAPSHOT_COMPRESSION_ZSTD,       \
    .compression_level = 3,                             \
    .max_archive_count = 10,                            \
    .enable_incremental = true,                         \
    .verify_accounts_hash = false,                      \
}

/*
 * Snapshot manager handle
 */
typedef struct sol_snapshot_mgr sol_snapshot_mgr_t;

/*
 * Create snapshot manager
 *
 * @param config        Configuration (NULL for defaults)
 * @return              Manager or NULL on error
 */
sol_snapshot_mgr_t* sol_snapshot_mgr_new(const sol_snapshot_config_t* config);

/*
 * Destroy snapshot manager
 */
void sol_snapshot_mgr_destroy(sol_snapshot_mgr_t* mgr);

/*
 * Set directories
 *
 * @param mgr           Snapshot manager
 * @param snapshot_dir  Directory for snapshot working files
 * @param archive_dir   Directory for compressed archives
 * @return              SOL_OK or error
 */
sol_err_t sol_snapshot_mgr_set_dirs(
    sol_snapshot_mgr_t*     mgr,
    const char*             snapshot_dir,
    const char*             archive_dir
);

/*
 * Create a full snapshot
 *
 * @param mgr           Snapshot manager
 * @param bank          Bank to snapshot
 * @param accounts_db   Accounts database
 * @param out_info      Output snapshot info
 * @return              SOL_OK or error
 */
sol_err_t sol_snapshot_create_full(
    sol_snapshot_mgr_t*     mgr,
    const sol_bank_t*       bank,
    sol_accounts_db_t*      accounts_db,
    sol_snapshot_info_t*    out_info
);

/*
 * Create an incremental snapshot
 *
 * @param mgr           Snapshot manager
 * @param bank          Bank to snapshot
 * @param accounts_db   Accounts database
 * @param base_slot     Base full snapshot slot
 * @param out_info      Output snapshot info
 * @return              SOL_OK or error
 */
sol_err_t sol_snapshot_create_incremental(
    sol_snapshot_mgr_t*     mgr,
    const sol_bank_t*       bank,
    sol_accounts_db_t*      accounts_db,
    sol_slot_t              base_slot,
    sol_snapshot_info_t*    out_info
);

/*
 * Load a bank from snapshot
 *
 * @param mgr               Snapshot manager
 * @param archive_path      Path to snapshot archive
 * @param out_bank          Output bank
 * @param out_accounts_db   Output accounts database
 * @return                  SOL_OK or error
 */
sol_err_t sol_snapshot_load(
    sol_snapshot_mgr_t*     mgr,
    const char*             archive_path,
    sol_bank_t**            out_bank,
    sol_accounts_db_t**     out_accounts_db
);

/*
 * Load a bank from snapshot, using a caller-provided AccountsDB configuration.
 *
 * This is useful for loading snapshots directly into a persistent backend
 * (e.g., RocksDB) when available.
 */
sol_err_t sol_snapshot_load_with_accounts_db_config(
    sol_snapshot_mgr_t*                 mgr,
    const char*                         archive_path,
    const sol_accounts_db_config_t*     accounts_db_config,
    sol_bank_t**                        out_bank,
    sol_accounts_db_t**                 out_accounts_db
);

/*
 * Load a base full snapshot and optionally apply an incremental snapshot on top.
 *
 * If `incremental_archive_path` is NULL, this behaves like loading a full snapshot.
 * When provided, the incremental snapshot's accounts are loaded into the same
 * AccountsDB (overwriting existing entries) and the returned bank reflects the
 * incremental slot/hash.
 */
sol_err_t sol_snapshot_load_full_and_incremental(
    sol_snapshot_mgr_t*                 mgr,
    const char*                         full_archive_path,
    const char*                         incremental_archive_path,
    const sol_accounts_db_config_t*     accounts_db_config,
    sol_bank_t**                        out_bank,
    sol_accounts_db_t**                 out_accounts_db
);

/*
 * Apply an incremental snapshot onto an existing AccountsDB.
 *
 * The AccountsDB must already contain the base full snapshot state at
 * `expected_base_slot`. On success, returns a frozen bank at the incremental
 * slot.
 */
sol_err_t sol_snapshot_apply_incremental_to_accounts_db(
    sol_snapshot_mgr_t*     mgr,
    const char*             incremental_archive_path,
    sol_slot_t              expected_base_slot,
    sol_accounts_db_t*      accounts_db,
    sol_bank_t**            out_bank
);

/*
 * Get snapshot info from archive
 *
 * @param archive_path  Path to snapshot archive
 * @param out_info      Output info
 * @return              SOL_OK or error
 */
sol_err_t sol_snapshot_get_info(
    const char*             archive_path,
    sol_snapshot_info_t*    out_info
);

/*
 * List available snapshots
 *
 * @param archive_dir   Directory containing archives
 * @param out_infos     Output array of infos
 * @param max_count     Maximum infos to return
 * @return              Number of snapshots found
 */
size_t sol_snapshot_list(
    const char*             archive_dir,
    sol_snapshot_info_t*    out_infos,
    size_t                  max_count
);

/*
 * Find the best snapshot for a target slot
 *
 * Returns the most recent full snapshot <= target_slot,
 * and optionally the best incremental snapshot.
 *
 * @param archive_dir       Directory containing archives
 * @param target_slot       Target slot
 * @param out_full          Output full snapshot info
 * @param out_incremental   Output incremental info (optional)
 * @return                  SOL_OK if found, error otherwise
 */
sol_err_t sol_snapshot_find_best(
    const char*             archive_dir,
    sol_slot_t              target_slot,
    sol_snapshot_info_t*    out_full,
    sol_snapshot_info_t*    out_incremental
);

/*
 * Delete old snapshots beyond max count
 *
 * @param mgr           Snapshot manager
 * @return              Number of snapshots deleted
 */
size_t sol_snapshot_cleanup(sol_snapshot_mgr_t* mgr);

/*
 * Get archive filename for a snapshot
 *
 * Full: snapshot-<slot>-<hash>.tar.zst
 * Incremental: incremental-snapshot-<base>-<slot>-<hash>.tar.zst
 *
 * @param info          Snapshot info
 * @param out_name      Output buffer
 * @param max_len       Buffer size
 * @return              Length of name or 0 on error
 */
size_t sol_snapshot_archive_name(
    const sol_snapshot_info_t*  info,
    char*                       out_name,
    size_t                      max_len
);

/*
 * Verify a snapshot archive
 *
 * @param archive_path  Path to archive
 * @return              SOL_OK if valid
 */
sol_err_t sol_snapshot_verify(const char* archive_path);

/*
 * Account storage file format
 */

/*
 * Account storage header
 */
typedef struct {
    uint64_t    slot;               /* Storage slot */
    uint64_t    id;                 /* Storage ID */
    uint64_t    count;              /* Number of accounts */
    uint64_t    data_len;           /* Total data length */
} sol_account_storage_header_t;

/*
 * Stored account header (before account data)
 */
typedef struct {
    uint64_t    write_version;      /* Write version */
    uint64_t    data_len;           /* Account data length */
    sol_pubkey_t pubkey;            /* Account pubkey */
    sol_pubkey_t owner;             /* Owner program */
    uint64_t    lamports;           /* Balance */
    uint64_t    rent_epoch;         /* Rent epoch */
    bool        executable;         /* Is executable */
    uint8_t     padding[7];         /* Alignment padding */
} sol_stored_account_t;

/*
 * Serialize accounts to storage file
 *
 * @param accounts      Array of accounts
 * @param count         Number of accounts
 * @param slot          Slot for storage
 * @param storage_id    Storage file ID
 * @param out_data      Output buffer
 * @param max_len       Buffer size
 * @return              Bytes written or 0 on error
 */
size_t sol_account_storage_serialize(
    const sol_account_t*    accounts,
    size_t                  count,
    sol_slot_t              slot,
    uint64_t                storage_id,
    uint8_t*                out_data,
    size_t                  max_len
);

/*
 * Deserialize accounts from storage file
 *
 * @param data          Storage data
 * @param len           Data length
 * @param out_accounts  Output accounts array
 * @param max_count     Maximum accounts to return
 * @return              Number of accounts or 0 on error
 */
size_t sol_account_storage_deserialize(
    const uint8_t*          data,
    size_t                  len,
    sol_account_t*          out_accounts,
    size_t                  max_count
);

/*
 * Bank serialization for snapshots
 */

/*
 * Bank fields that are serialized in snapshot
 */
typedef struct {
    sol_slot_t      slot;
    sol_slot_t      parent_slot;
    sol_hash_t      hash;
    sol_hash_t      parent_hash;
    uint64_t        block_height;
    uint64_t        epoch;
    uint64_t        transaction_count;
    uint64_t        capitalization;
    uint64_t        max_tick_height;
    uint64_t        hashes_per_tick;
    uint64_t        ticks_per_slot;
    uint64_t        lamports_per_signature;
    uint64_t        slots_per_epoch;
    /* Fee rate governor */
    uint64_t        target_lamports_per_signature;
    uint64_t        target_signatures_per_slot;
    uint64_t        min_lamports_per_signature;
    uint64_t        max_lamports_per_signature;
    /* Rent */
    uint64_t        rent_lamports_per_byte_year;
    float           rent_exemption_threshold;
    uint8_t         rent_burn_percent;
    /* Inflation */
    float           inflation_initial;
    float           inflation_terminal;
    float           inflation_taper;
    float           inflation_foundation;
    float           inflation_foundation_term;
    uint64_t        inflation_epoch;
} sol_bank_fields_t;

/*
 * Serialize bank fields
 */
size_t sol_bank_fields_serialize(
    const sol_bank_t*   bank,
    uint8_t*            out_data,
    size_t              max_len
);

/*
 * Deserialize bank fields
 */
sol_err_t sol_bank_fields_deserialize(
    const uint8_t*      data,
    size_t              len,
    sol_bank_fields_t*  out_fields
);

/*
 * Read bank fields directly from a snapshot archive (tar.*) without extracting
 * the full accounts payload to disk.
 *
 * This streams the bank snapshot file from the archive and parses enough of
 * the header to recover cluster parameters like hashes_per_tick/ticks_per_slot.
 *
 * @param archive_path      Path to snapshot archive (.tar.zst, etc)
 * @param expected_slot     Snapshot slot (from archive name/manifest)
 * @param out_fields        Parsed bank fields
 * @return                 SOL_OK on success, error otherwise
 */
sol_err_t sol_snapshot_read_bank_fields_from_archive(
    const char*         archive_path,
    sol_slot_t          expected_slot,
    sol_bank_fields_t*  out_fields
);

/*
 * Read recent blockhash queue directly from a snapshot archive (tar.*) without
 * extracting the full accounts payload to disk.
 *
 * The on-chain RecentBlockhashes sysvar can contain fewer entries than the
 * bank's internal BlockhashQueue. Accurate replay requires restoring the full
 * queue (up to max_age) from the bank snapshot.
 *
 * @param archive_path               Path to snapshot archive (.tar.zst, etc)
 * @param expected_slot              Snapshot slot (from archive name/manifest)
 * @param out_hashes                 Output blockhashes (most recent first)
 * @param out_lamports_per_signature Output lamports_per_signature for each hash
 * @param out_cap                    Capacity of out_* arrays
 * @param out_len                    Number of entries written
 * @return                           SOL_OK on success, error otherwise
 */
sol_err_t sol_snapshot_read_blockhash_queue_from_archive(
    const char*         archive_path,
    sol_slot_t          expected_slot,
    sol_hash_t*         out_hashes,
    uint64_t*           out_lamports_per_signature,
    size_t              out_cap,
    size_t*             out_len
);

/*
 * Status cache entry
 */
typedef struct {
    sol_signature_t     signature;
    sol_slot_t          slot;
    sol_err_t           status;
} sol_status_cache_entry_t;

/*
 * Status cache (recent transaction results)
 */
typedef struct {
    sol_status_cache_entry_t*   entries;
    size_t                      count;
    size_t                      capacity;
    sol_slot_t                  oldest_slot;
} sol_status_cache_t;

/*
 * Create status cache
 */
sol_status_cache_t* sol_status_cache_new(size_t capacity);

/*
 * Destroy status cache
 */
void sol_status_cache_destroy(sol_status_cache_t* cache);

/*
 * Add entry to status cache
 */
sol_err_t sol_status_cache_add(
    sol_status_cache_t*         cache,
    const sol_signature_t*      sig,
    sol_slot_t                  slot,
    sol_err_t                   status
);

/*
 * Lookup in status cache
 */
bool sol_status_cache_lookup(
    const sol_status_cache_t*   cache,
    const sol_signature_t*      sig,
    sol_slot_t*                 out_slot,
    sol_err_t*                  out_status
);

/*
 * Purge old entries from status cache
 */
size_t sol_status_cache_purge(
    sol_status_cache_t*     cache,
    sol_slot_t              min_slot
);

/*
 * Serialize status cache
 */
size_t sol_status_cache_serialize(
    const sol_status_cache_t*   cache,
    uint8_t*                    out_data,
    size_t                      max_len
);

/*
 * Deserialize status cache
 */
sol_err_t sol_status_cache_deserialize(
    const uint8_t*          data,
    size_t                  len,
    sol_status_cache_t*     cache
);

#endif /* SOL_SNAPSHOT_H */
