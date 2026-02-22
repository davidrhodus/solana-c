/*
 * sol_rocksdb.h - RocksDB storage backend
 *
 * Provides persistent key-value storage using RocksDB.
 */

#ifndef SOL_ROCKSDB_H
#define SOL_ROCKSDB_H

#include "sol_storage_backend.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * RocksDB-specific types
 */
typedef struct sol_rocksdb sol_rocksdb_t;

/*
 * Column family names for different data types
 */
#define SOL_ROCKSDB_CF_DEFAULT      "default"
#define SOL_ROCKSDB_CF_ACCOUNTS     "accounts"
#define SOL_ROCKSDB_CF_ACCOUNTS_INDEX "accounts_index"
#define SOL_ROCKSDB_CF_ACCOUNTS_OWNER_INDEX "accounts_owner_index"
#define SOL_ROCKSDB_CF_ACCOUNTS_OWNER_REVERSE "accounts_owner_reverse"
#define SOL_ROCKSDB_CF_BLOCKSTORE   "blockstore"
#define SOL_ROCKSDB_CF_STATUS_CACHE "status_cache"
#define SOL_ROCKSDB_CF_SLOT_META    "slot_meta"
#define SOL_ROCKSDB_CF_ADDRESS_SIGNATURES "address_signatures"

/*
 * Create a new RocksDB instance
 */
sol_rocksdb_t* sol_rocksdb_new(const sol_rocksdb_config_t* config);

/*
 * Open or create column family
 */
sol_err_t sol_rocksdb_open_cf(sol_rocksdb_t* db, const char* cf_name);

/*
 * Get storage backend for a specific column family
 */
sol_storage_backend_t* sol_rocksdb_get_backend(
    sol_rocksdb_t* db,
    const char* cf_name
);

/*
 * Flush all column families
 */
sol_err_t sol_rocksdb_flush_all(sol_rocksdb_t* db);

/*
 * Compact all column families
 */
sol_err_t sol_rocksdb_compact_all(sol_rocksdb_t* db);

/*
 * Get database statistics
 */
typedef struct {
    size_t      total_keys;
    size_t      total_size_bytes;
    size_t      block_cache_usage;
    size_t      block_cache_pinned;
    uint64_t    reads;
    uint64_t    writes;
    uint64_t    compactions;
} sol_rocksdb_stats_t;

sol_rocksdb_stats_t sol_rocksdb_stats(sol_rocksdb_t* db);

/*
 * Configure write options
 *
 * These toggles should be applied during initialization or other quiescent
 * periods (i.e. when no other threads are performing RocksDB writes).
 */
void sol_rocksdb_set_disable_wal(sol_rocksdb_t* db, bool disable_wal);

/*
 * Configure bulk-load tuning options.
 *
 * These toggles are intended to speed up initial snapshot ingestion by
 * increasing write buffering and (optionally) disabling expensive background
 * work. They should be applied only during initialization/quiescent periods.
 *
 * Best-effort: on older RocksDB builds some options may be rejected.
 */
sol_err_t sol_rocksdb_set_bulk_load_mode(sol_rocksdb_t* db, bool enable);

/*
 * Destroy RocksDB instance and all column families
 */
void sol_rocksdb_destroy(sol_rocksdb_t* db);

#ifdef __cplusplus
}
#endif

#endif /* SOL_ROCKSDB_H */
