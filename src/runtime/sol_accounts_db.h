/*
 * sol_accounts_db.h - Accounts Database
 *
 * Account storage with pluggable backends (in-memory or RocksDB).
 * Supports both volatile in-memory storage for testing and persistent
 * RocksDB storage for production.
 */

#ifndef SOL_ACCOUNTS_DB_H
#define SOL_ACCOUNTS_DB_H

#include "sol_account.h"
#include "../crypto/sol_lt_hash.h"
#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../storage/sol_storage_backend.h"
#include <pthread.h>

/*
 * Storage backend type
 */
typedef enum {
    SOL_ACCOUNTS_STORAGE_MEMORY  = 0,  /* In-memory hash table (default) */
    SOL_ACCOUNTS_STORAGE_ROCKSDB = 1,  /* RocksDB persistent storage */
    SOL_ACCOUNTS_STORAGE_APPENDVEC = 2, /* AppendVec files + RocksDB index */
} sol_accounts_storage_type_t;

/*
 * AccountsDB configuration
 */
typedef struct {
    size_t                      initial_capacity;   /* Initial hash table capacity */
    bool                        enable_snapshots;   /* Enable snapshot support */
    sol_accounts_storage_type_t storage_type;       /* Storage backend type */
    const char*                 rocksdb_path;       /* Path for RocksDB (if used) */
    size_t                      rocksdb_cache_mb;   /* RocksDB block cache size MB */
    const char*                 appendvec_path;     /* Path to AppendVec accounts dir (appendvec mode) */
    bool                        quiet;             /* Suppress initialization logs */
} sol_accounts_db_config_t;

#define SOL_ACCOUNTS_DB_CONFIG_DEFAULT {    \
    .initial_capacity = 65536,              \
    .enable_snapshots = false,              \
    .storage_type = SOL_ACCOUNTS_STORAGE_MEMORY, \
    .rocksdb_path = NULL,                   \
    .rocksdb_cache_mb = 512,                \
    .appendvec_path = NULL,                 \
    .quiet = false,                         \
}

/*
 * AccountsDB statistics
 */
typedef struct {
    uint64_t    accounts_count;     /* Number of accounts */
    uint64_t    total_lamports;     /* Total lamports in all accounts */
    uint64_t    total_data_bytes;   /* Total account data bytes */
    uint64_t    loads;              /* Number of account loads */
    uint64_t    stores;             /* Number of account stores */
    uint64_t    load_misses;        /* Number of load misses */
} sol_accounts_db_stats_t;

/*
 * AccountsDB handle
 */
typedef struct sol_accounts_db sol_accounts_db_t;

typedef struct sol_io_ctx sol_io_ctx_t;
typedef struct sol_appendvec_index sol_appendvec_index_t;

/*
 * Local entry kind (for overlay/fork views)
 *
 * Overlay databases created via `sol_accounts_db_fork` store per-bank deltas in
 * a local in-memory layer, including tombstones that hide parent values. These
 * helpers make it possible to reason about what is present in the local layer
 * without consulting the parent.
 */
typedef enum {
    SOL_ACCOUNTS_DB_LOCAL_MISSING = 0,
    SOL_ACCOUNTS_DB_LOCAL_TOMBSTONE = 1,
    SOL_ACCOUNTS_DB_LOCAL_ACCOUNT = 2,
} sol_accounts_db_local_kind_t;

/*
 * Create accounts database
 */
sol_accounts_db_t* sol_accounts_db_new(const sol_accounts_db_config_t* config);

/*
 * Destroy accounts database
 */
void sol_accounts_db_destroy(sol_accounts_db_t* db);

/* Optional: attach a shared IO context (used by AppendVec IO paths). */
void sol_accounts_db_set_io_ctx(sol_accounts_db_t* db, sol_io_ctx_t* io_ctx);

/* Adopt ownership of an in-memory AppendVec index (root AccountsDB only).
 *
 * Used during snapshot ingestion to retain the deferred AppendVec index for
 * runtime reads, avoiding RocksDB lookups in the hot account-load path. */
void sol_accounts_db_adopt_appendvec_index(sol_accounts_db_t* db, sol_appendvec_index_t* idx);

/* Build an in-memory AppendVec index by iterating the persistent backend.
 *
 * This is intended for fast restarts where the node reuses an existing AppendVec
 * + RocksDB index instead of re-extracting a snapshot. No-op if not applicable
 * (non-AppendVec backend, overlays, or already built). */
sol_err_t sol_accounts_db_maybe_build_appendvec_index(sol_accounts_db_t* db);

/*
 * Configure backend durability options (RocksDB only)
 *
 * Primarily used to speed up initial snapshot ingestion. These toggles should
 * only be changed during initialization/quiescent periods.
 */
sol_err_t sol_accounts_db_set_disable_wal(sol_accounts_db_t* db, bool disable_wal);

/*
 * Configure bulk-load tuning options (RocksDB only).
 *
 * Used to speed up initial snapshot ingestion; should only be toggled during
 * initialization/quiescent periods.
 */
sol_err_t sol_accounts_db_set_bulk_load_mode(sol_accounts_db_t* db, bool enable);

/*
 * Load account by pubkey
 *
 * Returns a clone of the account. Caller must destroy with sol_account_destroy.
 * Returns NULL if account not found.
 */
sol_account_t* sol_accounts_db_load(
    sol_accounts_db_t*      db,
    const sol_pubkey_t*     pubkey
);

/*
 * Load account by pubkey, optionally returning the stored slot.
 * out_stored_slot may be NULL if not needed.
 */
sol_account_t* sol_accounts_db_load_ex(
    sol_accounts_db_t*      db,
    const sol_pubkey_t*     pubkey,
    sol_slot_t*             out_stored_slot
);

/*
 * Load account by pubkey (read-only view when possible)
 *
 * In AppendVec mode, this may return an account whose `data` points into a
 * memory-mapped AppendVec file (account->data_borrowed=true). The returned
 * account must be treated as read-only (callers must not mutate account->data
 * in-place).
 *
 * For non-AppendVec backends, this falls back to sol_accounts_db_load.
 */
sol_account_t* sol_accounts_db_load_view(
    sol_accounts_db_t*      db,
    const sol_pubkey_t*     pubkey
);

/*
 * Load account by pubkey (read-only view when possible), optionally returning
 * the stored slot.
 *
 * out_stored_slot may be NULL if not needed.
 */
sol_account_t* sol_accounts_db_load_view_ex(
    sol_accounts_db_t*      db,
    const sol_pubkey_t*     pubkey,
    sol_slot_t*             out_stored_slot
);

/* Debug: trace account lookup through parent chain */
void sol_accounts_db_trace_load(
    sol_accounts_db_t*      db,
    const sol_pubkey_t*     pubkey
);

/*
 * Check if account exists
 */
bool sol_accounts_db_exists(
    sol_accounts_db_t*      db,
    const sol_pubkey_t*     pubkey
);

/*
 * Store account
 *
 * If account already exists, it is replaced.
 * The account is cloned internally.
 */
sol_err_t sol_accounts_db_store(
    sol_accounts_db_t*      db,
    const sol_pubkey_t*     pubkey,
    const sol_account_t*    account
);

/*
 * Store account with slot/write_version (Solana-like indexing)
 *
 * If write_version is non-zero, the store will only be applied if it is newer
 * than the currently stored version for this pubkey. This is required for
 * correctly ingesting Solana snapshot storages that may contain multiple
 * versions of the same account.
 *
 * If write_version is zero, the store is always applied (legacy behavior).
 */
sol_err_t sol_accounts_db_store_versioned(
    sol_accounts_db_t*      db,
    const sol_pubkey_t*     pubkey,
    const sol_account_t*    account,
    sol_slot_t              slot,
    uint64_t                write_version
);

/*
 * Store account with a hint for the previously-visible parent meta.
 *
 * When storing into an overlay/fork view, AccountsDB may consult the parent to
 * adjust stats (lamports/data bytes) on the first write to a pubkey.  If the
 * caller already loaded the prior version (common during transaction
 * execution), it can provide the previous meta to avoid an extra parent lookup
 * (RocksDB+AppendVec IO).
 *
 * For non-overlay databases, this behaves like sol_accounts_db_store_versioned
 * (the hint is ignored).
 */
sol_err_t sol_accounts_db_store_versioned_with_prev_meta(
    sol_accounts_db_t*      db,
    const sol_pubkey_t*     pubkey,
    const sol_account_t*    account,
    sol_slot_t              slot,
    uint64_t                write_version,
    bool                    prev_exists,
    uint64_t                prev_lamports,
    uint64_t                prev_data_len
);

/*
 * Fix up known builtin/native program accounts.
 *
 * This enforces canonical metadata+data for certain builtin programs (notably
 * the System Program) to match Agave/Solana mainnet state. It is safe to call
 * multiple times and will only write when a mismatch is detected.
 *
 * NOTE: This mutates the AccountsDB (persists corrected accounts in persistent
 * backends).
 */
sol_err_t sol_accounts_db_fixup_builtin_program_accounts(sol_accounts_db_t* db);

/*
 * Bulk snapshot ingestion (optimized for snapshot loading)
 *
 * This API batches backend writes (e.g. RocksDB WriteBatch) and avoids per-key
 * read-modify-write overhead. It is intended for single-threaded bootstrap
 * paths (before the validator starts servicing requests).
 */
typedef struct sol_accounts_db_bulk_writer sol_accounts_db_bulk_writer_t;

sol_accounts_db_bulk_writer_t* sol_accounts_db_bulk_writer_new(
    sol_accounts_db_t*  db,
    size_t              batch_capacity
);

void sol_accounts_db_bulk_writer_destroy(sol_accounts_db_bulk_writer_t* writer);

/* Tuning knobs (primarily for snapshot ingestion). */
void sol_accounts_db_bulk_writer_set_max_bytes(
    sol_accounts_db_bulk_writer_t* writer,
    size_t                         max_bytes_queued
);

/* When enabled, write operations are queued as backend "merge" ops instead of
 * unconditional puts/deletes. This makes ingestion order-independent when used
 * with a version-aware merge operator (RocksDB). */
void sol_accounts_db_bulk_writer_set_use_merge(
    sol_accounts_db_bulk_writer_t* writer,
    bool                           use_merge
);

/* Enable writing owner-index keys (owner||pubkey) alongside account values.
 *
 * This is useful for bulk applying rooted deltas into a persistent AccountsDB
 * without paying per-key read-modify-write overhead. Deletions do not remove
 * prior owner-index keys; iterator helpers filter stale entries by re-loading
 * the account and checking its current owner. */
sol_err_t sol_accounts_db_bulk_writer_set_write_owner_index(
    sol_accounts_db_bulk_writer_t* writer,
    bool                           enable
);

/* Restrict owner-index writes to core programs (stake+vote). Must be used in
 * conjunction with `sol_accounts_db_bulk_writer_set_write_owner_index(true)`.
 * Intended for snapshot bootstrap where only stake/vote account iteration is
 * needed for consensus, avoiding the cost of a full owner index. */
void sol_accounts_db_bulk_writer_set_write_owner_index_core_only(
    sol_accounts_db_bulk_writer_t* writer,
    bool                           core_only
);

/* Returns true if the bulk writer is configured to emit owner-index entries. */
bool sol_accounts_db_bulk_writer_is_writing_owner_index(
    const sol_accounts_db_bulk_writer_t* writer
);

/* Enable/disable writing the owner-reverse mapping (pubkey -> owner/lamports).
 * Disabling can speed up snapshot ingestion, but some features (e.g. building
 * full owner index) may be slower until reverse is rebuilt. */
sol_err_t sol_accounts_db_bulk_writer_set_write_owner_reverse(
    sol_accounts_db_bulk_writer_t* writer,
    bool                           enable
);

sol_err_t sol_accounts_db_bulk_writer_put_versioned(
    sol_accounts_db_bulk_writer_t* writer,
    const sol_pubkey_t*            pubkey,
    const sol_account_t*           account,
    sol_slot_t                     slot,
    uint64_t                       write_version
);

/* Fast-path for snapshot ingestion: avoids intermediate sol_account_t and
 * serialization overhead by writing the on-disk account format directly. */
sol_err_t sol_accounts_db_bulk_writer_put_raw_versioned(
    sol_accounts_db_bulk_writer_t* writer,
    const sol_pubkey_t*            pubkey,
    const sol_pubkey_t*            owner,
    uint64_t                       lamports,
    const uint8_t*                 data,
    uint64_t                       data_len,
    bool                           executable,
    uint64_t                       rent_epoch,
    sol_slot_t                     slot,
    uint64_t                       write_version
);

/* Snapshot ingestion helper that supports both storage backends:
 * - RocksDB mode stores full account bytes.
 * - AppendVec mode stores an AppendVec location + account hash leaf. */
sol_err_t sol_accounts_db_bulk_writer_put_snapshot_account(
    sol_accounts_db_bulk_writer_t* writer,
    const sol_pubkey_t*            pubkey,
    const sol_pubkey_t*            owner,
    uint64_t                       lamports,
    const uint8_t*                 data,
    uint64_t                       data_len,
    bool                           executable,
    uint64_t                       rent_epoch,
    sol_slot_t                     slot,
    uint64_t                       write_version,
    const sol_hash_t*              leaf_hash,
    uint64_t                       file_key,
    uint64_t                       record_offset
);

sol_err_t sol_accounts_db_bulk_writer_delete_versioned(
    sol_accounts_db_bulk_writer_t* writer,
    const sol_pubkey_t*            pubkey,
    sol_slot_t                     slot,
    uint64_t                       write_version
);

sol_err_t sol_accounts_db_bulk_writer_flush(sol_accounts_db_bulk_writer_t* writer);

/*
 * Delete account
 */
sol_err_t sol_accounts_db_delete(
    sol_accounts_db_t*      db,
    const sol_pubkey_t*     pubkey
);

/*
 * Delete account with slot/write_version (Solana-like indexing)
 *
 * If write_version is non-zero, the delete will only be applied if it is newer
 * than the currently stored version for this pubkey.
 *
 * If write_version is zero, the delete is always applied (legacy behavior).
 */
sol_err_t sol_accounts_db_delete_versioned(
    sol_accounts_db_t*      db,
    const sol_pubkey_t*     pubkey,
    sol_slot_t              slot,
    uint64_t                write_version
);

/*
 * Check if AccountsDB is an overlay (forked) view
 */
bool sol_accounts_db_is_overlay(const sol_accounts_db_t* db);

/* Returns true if the root AccountsDB is configured for AppendVec-backed
 * storage (accounts in files + RocksDB index). */
bool sol_accounts_db_is_appendvec(const sol_accounts_db_t* db);

/* Returns the configured AppendVec directory path, or NULL if not in
 * AppendVec mode. */
const char* sol_accounts_db_appendvec_path(const sol_accounts_db_t* db);

/*
 * Get the root/base AccountsDB for a view.
 *
 * For overlay databases created via `sol_accounts_db_fork`, this walks the
 * parent chain and returns the underlying non-overlay database. For non-overlay
 * databases, returns `db`.
 */
sol_accounts_db_t* sol_accounts_db_root(sol_accounts_db_t* db);

/*
 * Stable identifier for an AccountsDB instance.
 *
 * Used for caching keyed to a long-lived AccountsDB. IDs are monotonically
 * increasing for the lifetime of the process.
 */
uint64_t sol_accounts_db_id(const sol_accounts_db_t* db);

/*
 * Convenience: get the instance id of the root/base AccountsDB.
 */
uint64_t sol_accounts_db_root_id(const sol_accounts_db_t* db);

/*
 * Query the local layer for a pubkey
 *
 * - Returns SOL_ACCOUNTS_DB_LOCAL_ACCOUNT and outputs a clone in out_account
 *   when a local value exists.
 * - Returns SOL_ACCOUNTS_DB_LOCAL_TOMBSTONE when a local tombstone exists.
 * - Returns SOL_ACCOUNTS_DB_LOCAL_MISSING when the local layer has no entry.
 */
sol_accounts_db_local_kind_t sol_accounts_db_get_local_kind(
    sol_accounts_db_t*      db,
    const sol_pubkey_t*     pubkey,
    sol_account_t**         out_account
);

/*
 * Clear a local override for a pubkey in an overlay database
 *
 * Removes a local entry (account or tombstone) so reads fall back to the
 * parent. No-op if the pubkey has no local entry.
 */
sol_err_t sol_accounts_db_clear_override(
    sol_accounts_db_t*      db,
    const sol_pubkey_t*     pubkey
);

/*
 * Get account count
 */
size_t sol_accounts_db_count(const sol_accounts_db_t* db);

/*
 * Get total lamports
 */
uint64_t sol_accounts_db_total_lamports(const sol_accounts_db_t* db);

/*
 * Iterate over all accounts
 *
 * Callback receives (pubkey, account, context).
 * Return false from callback to stop iteration.
 */
typedef bool (*sol_accounts_db_iter_cb)(
    const sol_pubkey_t*     pubkey,
    const sol_account_t*    account,
    void*                   ctx
);

void sol_accounts_db_iterate(
    sol_accounts_db_t*      db,
    sol_accounts_db_iter_cb callback,
    void*                   ctx
);

/*
 * Iterate accounts by owner/program-id
 *
 * Uses a secondary owner index when available (RocksDB backend) and falls back
 * to full iteration + filtering otherwise.
 */
void sol_accounts_db_iterate_owner(
    sol_accounts_db_t*      db,
    const sol_pubkey_t*     owner,
    sol_accounts_db_iter_cb callback,
    void*                   ctx
);

/*
 * Iterate accounts whose pubkey falls within [start, end].
 * Both start and end are inclusive (closed interval).
 * Uses the storage backend's iterate_range when available.
 * For in-memory backends, falls back to full iteration with filtering.
 */
void sol_accounts_db_iterate_pubkey_range(
    sol_accounts_db_t*      db,
    const sol_pubkey_t*     start,
    const sol_pubkey_t*     end,
    sol_accounts_db_iter_cb callback,
    void*                   ctx
);

/* Returns true if the root storage backend supports efficient pubkey-range
 * iteration (iterate_range). This is required for some parallel bootstrap
 * computations (e.g. full Accounts LtHash recompute). */
bool sol_accounts_db_iterate_pubkey_range_supported(const sol_accounts_db_t* db);

/*
 * Iterate over the local layer of an overlay AccountsDB
 *
 * Only iterates entries stored in the overlay's local in-memory table:
 * - account is non-NULL for local account values (lamports > 0)
 * - account is NULL for local tombstones (deletes and zero-lamport writes)
 *
 * The parent pointer is provided so callers can load the previous visible value
 * without needing access to internal struct fields.
 */
typedef bool (*sol_accounts_db_iter_local_cb)(
    sol_accounts_db_t*      parent,
    const sol_pubkey_t*     pubkey,
    const sol_account_t*    account,
    void*                   ctx
);

sol_err_t sol_accounts_db_iterate_local(
    sol_accounts_db_t*            db,
    sol_accounts_db_iter_local_cb callback,
    void*                         ctx
);

/* Snapshot the local layer of an overlay AccountsDB.
 *
 * Unlike sol_accounts_db_iterate_local(), this returns ownership of cloned
 * account values to the caller. This is useful for parallel iteration in
 * freeze-time paths where cloning under the AccountsDB lock must be decoupled
 * from heavy compute (hashing, parent lookups, etc).
 *
 * The snapshot is valid even if the underlying overlay continues to mutate,
 * because all returned accounts are clones. */
typedef struct {
    sol_pubkey_t   pubkey;
    sol_account_t* account; /* NULL for tombstone */
} sol_accounts_db_local_entry_t;

typedef struct {
    sol_accounts_db_t*             parent;
    sol_accounts_db_local_entry_t* entries;
    size_t                         len;
} sol_accounts_db_local_snapshot_t;

sol_err_t
sol_accounts_db_snapshot_local(sol_accounts_db_t* db,
                               sol_accounts_db_local_snapshot_t* out);

void
sol_accounts_db_local_snapshot_free(sol_accounts_db_local_snapshot_t* snap);

/* Snapshot the local layer of an overlay AccountsDB without cloning account
 * values.
 *
 * Returned `entries[i].account` pointers are BORROWED from the overlay and
 * remain valid only as long as the overlay does not mutate. This is intended
 * for freeze-time read-only paths (e.g. bank hashing) where the overlay is
 * immutable. Unlike sol_accounts_db_snapshot_local(), this avoids copying
 * account data and drastically reduces per-slot overhead. */
typedef struct {
    sol_accounts_db_t*             parent;
    sol_accounts_db_local_entry_t* entries; /* borrowed account pointers */
    size_t                         len;
} sol_accounts_db_local_snapshot_view_t;

sol_err_t
sol_accounts_db_snapshot_local_view(sol_accounts_db_t* db,
                                    sol_accounts_db_local_snapshot_view_t* out);

void
sol_accounts_db_local_snapshot_view_free(sol_accounts_db_local_snapshot_view_t* snap);

/*
 * Ensure the owner index is populated (RocksDB only)
 *
 * Snapshot ingestion may skip incremental index maintenance; this builds the
 * index from the current account state if it appears uninitialized.
 */
sol_err_t sol_accounts_db_ensure_owner_index(sol_accounts_db_t* db);

/*
 * Ensure a minimal owner index exists for core validator features.
 *
 * Snapshot ingestion uses a version-aware bulk writer (RocksDB Merge) that
 * populates the owner-reverse mapping but defers building the owner-index CF.
 * Many validator paths (stake weighting, leader schedule) rely on owner-based
 * iteration even when the RPC server is disabled. This helper builds a small
 * subset of the owner index (stake + vote program owners) from the reverse
 * mapping so replay and consensus can proceed without requiring the full RPC
 * owner index.
 */
sol_err_t sol_accounts_db_ensure_core_owner_index(sol_accounts_db_t* db);

/*
 * Mark the owner reverse mapping as populated (RocksDB only)
 *
 * Snapshot loaders that populate the owner reverse mapping during bulk
 * ingestion can call this once the load is complete so subsequent startups can
 * build the owner index without rescanning full account values.
 */
sol_err_t sol_accounts_db_mark_owner_reverse_built(sol_accounts_db_t* db);

/* Mark the core owner index (stake+vote only) as complete. This enables
 * `sol_accounts_db_iterate_owner` to use the owner-index CF for stake/vote
 * queries without requiring a full index build. */
sol_err_t sol_accounts_db_mark_owner_index_core_built(sol_accounts_db_t* db);

/*
 * Persisted bootstrap bank state (RocksDB only)
 *
 * Stores the minimal bank inputs needed to resume from an on-disk AccountsDB
 * without re-loading snapshot archives (fast restart).
 */
enum {
    SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_BLOCKHASH        = 1u << 0,
    SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_BANK_HASH       = 1u << 1,
    SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_ACCOUNTS_LT_HASH = 1u << 2,
    SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_GENESIS_HASH    = 1u << 3,
    SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_SHRED_VERSION   = 1u << 4,
};

typedef struct {
    sol_slot_t          slot;
    sol_slot_t          parent_slot;
    uint64_t            signature_count;
    uint32_t            flags;
    uint64_t            ticks_per_slot;
    uint64_t            hashes_per_tick;
    uint64_t            slots_per_epoch;
    uint64_t            lamports_per_signature;
    uint64_t            rent_per_byte_year;
    uint64_t            rent_exemption_threshold;
    sol_hash_t          blockhash;
    sol_hash_t          genesis_hash;
    uint32_t            shred_version;
    sol_hash_t          parent_bank_hash;
    sol_hash_t          bank_hash;
    sol_lt_hash_t       accounts_lt_hash;
} sol_accounts_db_bootstrap_state_t;

bool sol_accounts_db_get_bootstrap_state(const sol_accounts_db_t* db,
                                        sol_accounts_db_bootstrap_state_t* out_state);

sol_err_t sol_accounts_db_set_bootstrap_state(sol_accounts_db_t* db,
                                              const sol_accounts_db_bootstrap_state_t* state);

/*
 * Persisted bootstrap recent blockhash queue (RocksDB only)
 *
 * Solana stores the full BlockhashQueue in the bank snapshot. The on-chain
 * RecentBlockhashes sysvar may contain fewer entries, so bootstrapping from a
 * snapshot requires seeding the bank's recent blockhash queue from the bank
 * snapshot state for correct blockhash validation and fee calculation.
 */
bool sol_accounts_db_get_bootstrap_blockhash_queue(const sol_accounts_db_t* db,
                                                   sol_hash_t* out_hashes,
                                                   uint64_t* out_lamports_per_signature,
                                                   size_t out_cap,
                                                   size_t* out_len);

sol_err_t sol_accounts_db_set_bootstrap_blockhash_queue(sol_accounts_db_t* db,
                                                        const sol_hash_t* hashes,
                                                        const uint64_t* lamports_per_signature,
                                                        size_t len);

/*
 * Compute accounts hash (merkle root of all accounts)
 */
void sol_accounts_db_hash(
    sol_accounts_db_t*  db,
    sol_hash_t*         out_hash
);

/*
 * Compute accounts delta hash (hash of accounts modified in this DB's local layer)
 *
 * For overlay databases created via `sol_accounts_db_fork`, this hashes only the
 * locally written accounts (excluding tombstones).
 *
 * For non-overlay databases, this falls back to `sol_accounts_db_hash`.
 */
void sol_accounts_db_hash_delta(
    sol_accounts_db_t*  db,
    sol_hash_t*         out_hash
);

/*
 * Get statistics
 */
void sol_accounts_db_stats(
    const sol_accounts_db_t*    db,
    sol_accounts_db_stats_t*    stats
);

/*
 * Reset statistics
 */
void sol_accounts_db_stats_reset(sol_accounts_db_t* db);

/*
 * Create a snapshot (clone) of the database
 */
sol_accounts_db_t* sol_accounts_db_snapshot(sol_accounts_db_t* db);

/*
 * Create a forked (overlay) AccountsDB view
 *
 * The returned database stores writes/deletes locally and falls back to the
 * parent for reads and iteration. This is intended for bank forks, so
 * different banks can diverge without copying the full AccountsDB.
 *
 * The parent database is not owned and must outlive the fork.
 */
sol_accounts_db_t* sol_accounts_db_fork(sol_accounts_db_t* parent);

/*
 * Apply the local delta from src into dst
 *
 * Only the entries written/deleted in src are applied to dst. Parent state is
 * not iterated. This is used when advancing root (committing a bank's state).
 */
sol_err_t sol_accounts_db_apply_delta(sol_accounts_db_t* dst, sol_accounts_db_t* src);

/*
 * Apply the local delta from src into dst, substituting `default_slot` for any
 * overlay entries with slot==0.
 *
 * Overlay entries should always carry the bank slot they were written in. If
 * some legacy path stores into an overlay with slot==0, root advancement would
 * attempt to write into slot 0's (typically sealed) AppendVec and fail with
 * SOL_ERR_UNSUPPORTED. Bank forks know the bank slot being committed, so they
 * can use this helper to keep root advancement progressing.
 */
sol_err_t sol_accounts_db_apply_delta_default_slot(sol_accounts_db_t* dst,
                                                  sol_accounts_db_t* src,
                                                  sol_slot_t default_slot);

/*
 * Seal an AppendVec slot file after rooting.
 *
 * In AppendVec mode, rooted deltas are materialized into per-slot AppendVec
 * files keyed by (slot<<32)|file_id. Once a slot is rooted and its delta has
 * been fully applied, the corresponding AppendVec becomes immutable and safe
 * to memory-map for fast account loads.
 *
 * No-op for non-AppendVec backends.
 */
sol_err_t sol_accounts_db_appendvec_seal_slot(sol_accounts_db_t* db, sol_slot_t slot);

/*
 * Clear the local delta in an overlay database
 *
 * Frees all locally stored entries/tombstones while keeping the overlay alive.
 */
void sol_accounts_db_clear_local(sol_accounts_db_t* db);

/*
 * Update the parent pointer for an overlay database
 */
void sol_accounts_db_set_parent(sol_accounts_db_t* db, sol_accounts_db_t* parent);

/*
 * Get the parent database for an overlay, or NULL if not an overlay.
 */
sol_accounts_db_t* sol_accounts_db_get_parent(sol_accounts_db_t* db);

/*
 * Epoch Accounts Hash (EAH)
 *
 * Solana optionally hashes an Epoch Accounts Hash into the bank hash once per
 * epoch (see Agave docs: implemented-proposals/epoch_accounts_hash.md).
 *
 * This metadata is stored on the rooted/base AccountsDB so forked overlay views
 * can read it via their parent chain.
 */
bool sol_accounts_db_get_epoch_accounts_hash(
    const sol_accounts_db_t*    db,
    uint64_t                    epoch,
    sol_hash_t*                 out_hash
);

sol_err_t sol_accounts_db_set_epoch_accounts_hash(
    sol_accounts_db_t*          db,
    uint64_t                    epoch,
    const sol_hash_t*           hash
);

#endif /* SOL_ACCOUNTS_DB_H */
