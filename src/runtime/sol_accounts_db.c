/*
 * sol_accounts_db.c - Accounts Database Implementation
 *
 * Supports both in-memory hash table (legacy) and pluggable storage backends.
 */

#include "sol_accounts_db.h"
#include "sol_appendvec_index.h"
#include "../util/sol_alloc.h"
#include "../util/sol_arena.h"
#include "../util/sol_bits.h"
#include "../util/sol_io.h"
#include "../util/sol_map.h"
#include "../util/sol_log.h"
#include "../crypto/sol_sha256.h"
#include "../storage/sol_rocksdb.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static uint64_t g_accounts_db_id_gen = 1;

static inline uint64_t
accounts_db_monotonic_ns(void) {
    struct timespec ts = {0};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ull) + (uint64_t)ts.tv_nsec;
}

static uint64_t
appendvec_map_slow_threshold_ns(void) {
    static int cached = 0;
    static uint64_t threshold_ns = 0;
    if (__builtin_expect(!cached, 0)) {
        const char* env = getenv("SOL_APPENDVEC_MAP_SLOW_MS");
        if (env && env[0] != '\0') {
            char* end = NULL;
            unsigned long long ms = strtoull(env, &end, 10);
            if (end != env && ms > 0ull) {
                threshold_ns = ms * 1000000ull;
            }
        }
        cached = 1;
    }
    return threshold_ns;
}

static uint64_t
appendvec_map_wait_slow_threshold_ns(void) {
    static int cached = 0;
    static uint64_t threshold_ns = 0;
    if (__builtin_expect(!cached, 0)) {
        const char* env = getenv("SOL_APPENDVEC_MAP_WAIT_SLOW_MS");
        if (env && env[0] != '\0') {
            char* end = NULL;
            unsigned long long ms = strtoull(env, &end, 10);
            if (end != env && ms > 0ull) {
                threshold_ns = ms * 1000000ull;
            }
        }
        cached = 1;
    }
    return threshold_ns;
}

/*
 * Hash table entry for account storage (legacy in-memory mode)
 */
typedef struct sol_account_entry {
    sol_pubkey_t                pubkey;
    sol_account_t*              account;
    sol_slot_t                  slot;
    uint64_t                    write_version;
    struct sol_account_entry*   next;
} sol_account_entry_t;

/*
 * Versioned value header for backend storage.
 *
 * This enables Solana-like "accounts index" semantics (slot/write_version aware
 * upserts) while remaining backward-compatible with older stored values that
 * contain only the serialized account.
 */
#define SOL_ACCOUNTSDB_VALUE_MAGIC 0x31434153u /* "SAC1" */
typedef struct {
    uint32_t    magic;
    uint32_t    reserved;
    uint64_t    slot;
    uint64_t    write_version;
} sol_accountsdb_value_header_t;

/* AppendVec index payload stored in RocksDB when using
 * SOL_ACCOUNTS_STORAGE_APPENDVEC. */
typedef struct {
    uint64_t  file_key;      /* (slot << 32) | file_id */
    uint64_t  record_offset; /* Byte offset of record header within file */
    sol_hash_t account_hash; /* SHA256(pubkey||account_state). Zero => deleted. */
} sol_accountsdb_appendvec_ref_v1_t;

#define SOL_APPENDVEC_RECORD_HEADER_SIZE 104u
#define SOL_APPENDVEC_RECORD_META_SIZE   32u
#define SOL_APPENDVEC_RECORD_PREFIX_SIZE (SOL_APPENDVEC_RECORD_HEADER_SIZE + SOL_APPENDVEC_RECORD_META_SIZE)

typedef struct {
    int      fd;
    uint8_t  writable;
    uint8_t  sealed;
    uint8_t  map_inflight; /* another thread is currently mmap-ing this file */
    /* Current file end (bytes). Written with atomic ops by concurrent writers. */
    uint64_t size;
    uint8_t* map;      /* read-only mmap base (NULL if not mapped) */
    uint64_t map_size; /* bytes mapped */
} appendvec_file_t;

/*
 * Bulk writer for snapshot ingestion
 */
struct sol_accounts_db_bulk_writer {
    sol_accounts_db_t*      db;
    sol_storage_batch_t*    batch;
    sol_storage_batch_t*    rev_batch;
    sol_storage_batch_t*    idx_batch;
    sol_arena_t*            arena;
    size_t                  batch_capacity;
    size_t                  bytes_queued;
    size_t                  max_bytes_queued;
    bool                    use_merge;
    bool                    write_owner_index;
    bool                    write_owner_index_core_only;
    bool                    write_owner_reverse;
};

/*
 * AccountsDB structure
 */
struct sol_accounts_db {
    sol_accounts_db_config_t    config;
    uint64_t                    instance_id;

    /* Optional parent for forked/overlay views */
    struct sol_accounts_db*     parent;

    sol_io_ctx_t*               io_ctx;

    /* Epoch accounts hash metadata (root DB only; overlays read via parent chain) */
    sol_hash_t                  epoch_accounts_hash;
    uint64_t                    epoch_accounts_hash_epoch;
    bool                        epoch_accounts_hash_valid;

    /* Storage backend (when using pluggable storage) */
    sol_storage_backend_t*      backend;
    sol_storage_backend_t*      owner_index_backend;
    sol_storage_backend_t*      owner_reverse_backend;
    sol_rocksdb_t*              rocksdb;  /* RocksDB instance (if using RocksDB) */

    /* AppendVec-backed account storage (SOL_ACCOUNTS_STORAGE_APPENDVEC) */
    char*                       appendvec_dir;
    sol_map_t*                  appendvec_files; /* file_key(u64) -> appendvec_file_t* */
    pthread_rwlock_t            appendvec_lock;
    bool                        appendvec_lock_init;
    size_t                      appendvec_open_fds;
    size_t                      appendvec_open_fds_limit;
    int                         appendvec_fd_cache_warned;
    size_t                      appendvec_fd_evict_cursor;

    /* Optional in-memory index for AppendVec storage (pubkey -> ref). */
    sol_appendvec_index_t*       appendvec_index;

    /* Hash table (legacy in-memory mode, used when backend is NULL) */
    sol_account_entry_t**       buckets;
    size_t                      bucket_count;
    size_t                      account_count;
    pthread_rwlock_t*           stripe_locks;
    size_t                      stripe_count;
    size_t                      stripe_mask;

    /* Statistics */
    sol_accounts_db_stats_t     stats;
    uint8_t                     owner_index_state;
    uint8_t                     owner_reverse_state;

    /* Thread safety */
    pthread_rwlock_t            lock;
};

#define SOL_ACCOUNTS_DB_MAX_STRIPES 8192u

static inline size_t
floor_pow2_size(size_t x) {
    if (x == 0) return 0;
    size_t p = 1;
    while (p <= x / 2) p <<= 1;
    return p;
}

static inline size_t
stripe_for_bucket(const sol_accounts_db_t* db, size_t bucket_idx) {
    if (!db || !db->stripe_locks || db->stripe_count == 0) return 0;
    return bucket_idx & db->stripe_mask;
}

static inline size_t
stripe_for_pubkey(const sol_accounts_db_t* db, const sol_pubkey_t* pubkey) {
    if (!db || !pubkey || !db->stripe_locks || db->stripe_count == 0) return 0;
    uint64_t h = 0;
    memcpy(&h, pubkey->bytes, 8);
    return (size_t)h & db->stripe_mask;
}

static inline uint64_t
atomic_load_u64(const uint64_t* p) {
    return __atomic_load_n(p, __ATOMIC_RELAXED);
}

static inline void
atomic_inc_u64(uint64_t* p) {
    (void)__atomic_fetch_add(p, 1u, __ATOMIC_RELAXED);
}

static inline void
atomic_add_u64(uint64_t* p, uint64_t v) {
    (void)__atomic_fetch_add(p, v, __ATOMIC_RELAXED);
}

static inline void
atomic_sub_u64(uint64_t* p, uint64_t v) {
    (void)__atomic_fetch_sub(p, v, __ATOMIC_RELAXED);
}

static inline void
atomic_dec_u64_sat(uint64_t* p) {
    uint64_t cur = __atomic_load_n(p, __ATOMIC_RELAXED);
    while (cur != 0) {
        uint64_t next = cur - 1u;
        if (__atomic_compare_exchange_n(p, &cur, next, false,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
            break;
        }
    }
}

static inline void
atomic_add_size(size_t* p, size_t v) {
    (void)__atomic_fetch_add(p, v, __ATOMIC_RELAXED);
}

static inline void
atomic_sub_size(size_t* p, size_t v) {
    (void)__atomic_fetch_sub(p, v, __ATOMIC_RELAXED);
}

#define OWNER_INDEX_META_KEY_STR "__meta_owner_index_built"
#define OWNER_INDEX_CORE_META_KEY_STR "__meta_owner_index_core_v1"
#define OWNER_REVERSE_META_KEY_STR "__meta_owner_reverse_built"

/* Owner index metadata is persisted in the owner-index column family. The DB
 * may contain partial/incremental entries (from live updates) before the index
 * is fully (re)built. Gate owner-based iteration on these meta keys so callers
 * get correct results even when the index is not complete. */
#define OWNER_INDEX_STATE_LOADED (1u<<0)
#define OWNER_INDEX_STATE_FULL   (1u<<1)
#define OWNER_INDEX_STATE_CORE   (1u<<2)

#define OWNER_REVERSE_STATE_LOADED (1u<<0)
#define OWNER_REVERSE_STATE_BUILT  (1u<<1)

static bool
owner_index_is_core_owner(const sol_pubkey_t* owner) {
    if (!owner) return false;
    return sol_pubkey_eq(owner, &SOL_STAKE_PROGRAM_ID) ||
           sol_pubkey_eq(owner, &SOL_VOTE_PROGRAM_ID);
}

static uint8_t
accounts_db_owner_reverse_state(sol_accounts_db_t* root) {
    if (!root) return 0;

    uint8_t state = __atomic_load_n(&root->owner_reverse_state, __ATOMIC_ACQUIRE);
    if (state & OWNER_REVERSE_STATE_LOADED) {
        return state;
    }

    uint8_t next = OWNER_REVERSE_STATE_LOADED;

    if (root->owner_reverse_backend) {
        uint8_t* meta = NULL;
        size_t meta_len = 0;
        sol_err_t gerr = root->owner_reverse_backend->get(root->owner_reverse_backend->ctx,
                                                          (const uint8_t*)OWNER_REVERSE_META_KEY_STR,
                                                          sizeof(OWNER_REVERSE_META_KEY_STR) - 1,
                                                          &meta,
                                                          &meta_len);
        if (gerr == SOL_OK) {
            uint8_t version = (meta_len > 0) ? meta[0] : 0;
            if (version >= 2) {
                next |= OWNER_REVERSE_STATE_BUILT;
            }
            sol_free(meta);
        } else if (meta) {
            sol_free(meta);
        }
    }

    __atomic_store_n(&root->owner_reverse_state, next, __ATOMIC_RELEASE);
    return next;
}

static bool
accounts_db_can_use_owner_reverse(sol_accounts_db_t* root) {
    if (!root || !root->owner_reverse_backend) return false;
    uint8_t state = accounts_db_owner_reverse_state(root);
    return (state & OWNER_REVERSE_STATE_BUILT) != 0;
}

static uint8_t
accounts_db_owner_index_state(sol_accounts_db_t* root) {
    if (!root) return 0;

    uint8_t state = __atomic_load_n(&root->owner_index_state, __ATOMIC_ACQUIRE);
    if (state & OWNER_INDEX_STATE_LOADED) {
        return state;
    }

    uint8_t next = OWNER_INDEX_STATE_LOADED;

    if (root->owner_index_backend) {
        uint8_t* meta = NULL;
        size_t meta_len = 0;
        sol_err_t gerr = root->owner_index_backend->get(root->owner_index_backend->ctx,
                                                        (const uint8_t*)OWNER_INDEX_META_KEY_STR,
                                                        sizeof(OWNER_INDEX_META_KEY_STR) - 1,
                                                        &meta,
                                                        &meta_len);
        if (gerr == SOL_OK) {
            next |= OWNER_INDEX_STATE_FULL | OWNER_INDEX_STATE_CORE;
            sol_free(meta);
        } else if (gerr == SOL_ERR_NOTFOUND) {
            meta = NULL;
            meta_len = 0;
            gerr = root->owner_index_backend->get(root->owner_index_backend->ctx,
                                                  (const uint8_t*)OWNER_INDEX_CORE_META_KEY_STR,
                                                  sizeof(OWNER_INDEX_CORE_META_KEY_STR) - 1,
                                                  &meta,
                                                  &meta_len);
            if (gerr == SOL_OK) {
                next |= OWNER_INDEX_STATE_CORE;
                sol_free(meta);
            } else if (meta) {
                sol_free(meta);
            }
        } else if (meta) {
            sol_free(meta);
        }
    }

    __atomic_store_n(&root->owner_index_state, next, __ATOMIC_RELEASE);
    return next;
}

static bool
accounts_db_can_use_owner_index(sol_accounts_db_t* root, const sol_pubkey_t* owner) {
    if (!root || !root->owner_index_backend || !owner) return false;

    uint8_t state = accounts_db_owner_index_state(root);
    if (state & OWNER_INDEX_STATE_FULL) {
        return true;
    }
    if ((state & OWNER_INDEX_STATE_CORE) && owner_index_is_core_owner(owner)) {
        return true;
    }
    return false;
}

typedef enum {
    OWNER_TRACK_MODE_NONE = 0,
    OWNER_TRACK_MODE_CORE = 1,
    OWNER_TRACK_MODE_FULL = 2,
} owner_track_mode_t;

static owner_track_mode_t
accounts_db_owner_track_mode(sol_accounts_db_t* root) {
    if (!root || !root->owner_index_backend) return OWNER_TRACK_MODE_NONE;

    uint8_t state = accounts_db_owner_index_state(root);
    if (state & OWNER_INDEX_STATE_FULL) {
        return OWNER_TRACK_MODE_FULL;
    }
    if (state & OWNER_INDEX_STATE_CORE) {
        return OWNER_TRACK_MODE_CORE;
    }
    return OWNER_TRACK_MODE_NONE;
}

static inline bool
accounts_db_should_track_owner_live(sol_accounts_db_t* db, const sol_pubkey_t* owner) {
    if (!db || !owner) return false;
    owner_track_mode_t mode = accounts_db_owner_track_mode(db);
    if (mode == OWNER_TRACK_MODE_FULL) return true;
    if (mode == OWNER_TRACK_MODE_CORE) return owner_index_is_core_owner(owner);
    return false;
}

static sol_accounts_db_t*
accounts_db_root(sol_accounts_db_t* db);

static uint64_t
monotonic_ms(void);

sol_accounts_db_t*
sol_accounts_db_root(sol_accounts_db_t* db) {
    return accounts_db_root(db);
}

void
sol_accounts_db_set_io_ctx(sol_accounts_db_t* db, sol_io_ctx_t* io_ctx) {
    if (!db) return;
    sol_accounts_db_t* root = accounts_db_root(db);
    if (!root) return;
    root->io_ctx = io_ctx;
}

void
sol_accounts_db_adopt_appendvec_index(sol_accounts_db_t* db, sol_appendvec_index_t* idx) {
    if (!db) {
        sol_appendvec_index_destroy(idx);
        return;
    }

    sol_accounts_db_t* root = accounts_db_root(db);
    if (!root) {
        sol_appendvec_index_destroy(idx);
        return;
    }

    /* Only meaningful for AppendVec-rooted AccountsDBs. */
    if (root->config.storage_type != SOL_ACCOUNTS_STORAGE_APPENDVEC) {
        sol_appendvec_index_destroy(idx);
        return;
    }

    pthread_rwlock_wrlock(&root->lock);
    if (root->appendvec_index) {
        pthread_rwlock_unlock(&root->lock);
        sol_appendvec_index_destroy(idx);
        return;
    }
    root->appendvec_index = idx;
    pthread_rwlock_unlock(&root->lock);
}

uint64_t
sol_accounts_db_id(const sol_accounts_db_t* db) {
    return db ? db->instance_id : 0;
}

uint64_t
sol_accounts_db_root_id(const sol_accounts_db_t* db) {
    const sol_accounts_db_t* root = db;
    while (root && root->parent) {
        root = root->parent;
    }
    return root ? root->instance_id : 0;
}

sol_accounts_db_bulk_writer_t*
sol_accounts_db_bulk_writer_new(sol_accounts_db_t* db, size_t batch_capacity) {
    if (!db) return NULL;
    if (db->parent) return NULL;
    if (!db->backend || !db->backend->batch_write) return NULL;

    sol_accounts_db_bulk_writer_t* w = sol_calloc(1, sizeof(*w));
    if (!w) return NULL;

    if (batch_capacity == 0) batch_capacity = 4096;

    w->batch = sol_storage_batch_new(batch_capacity);
    if (!w->batch) {
        sol_free(w);
        return NULL;
    }

    /* Optional owner reverse mapping batch (RocksDB CF). */
    w->rev_batch = NULL;
    if (db->owner_reverse_backend && db->owner_reverse_backend->batch_write) {
        w->rev_batch = sol_storage_batch_new(batch_capacity);
        if (!w->rev_batch) {
            sol_storage_batch_destroy(w->batch);
            sol_free(w);
            return NULL;
        }
    }

    /* Owner index batch is opt-in (to keep snapshot ingestion memory usage low). */
    w->idx_batch = NULL;
    w->write_owner_index = false;
    w->write_owner_index_core_only = false;
    w->write_owner_reverse = true;

    /* Use a larger chunk size to reduce allocations for large snapshots. */
    w->arena = sol_arena_new(64 * 1024 * 1024);
    if (!w->arena) {
        if (w->rev_batch) {
            sol_storage_batch_destroy(w->rev_batch);
        }
        sol_storage_batch_destroy(w->batch);
        sol_free(w);
        return NULL;
    }

    w->db = db;
    w->batch_capacity = batch_capacity;
    w->bytes_queued = 0;
    w->max_bytes_queued = 512 * 1024 * 1024; /* 512MB */
    w->use_merge = false;
    return w;
}

void
sol_accounts_db_bulk_writer_destroy(sol_accounts_db_bulk_writer_t* writer) {
    if (!writer) return;
    (void)sol_accounts_db_bulk_writer_flush(writer);
    if (writer->arena) {
        sol_arena_destroy(writer->arena);
    }
    if (writer->batch) {
        sol_storage_batch_destroy(writer->batch);
    }
    if (writer->rev_batch) {
        sol_storage_batch_destroy(writer->rev_batch);
    }
    if (writer->idx_batch) {
        sol_storage_batch_destroy(writer->idx_batch);
    }
    sol_free(writer);
}

void
sol_accounts_db_bulk_writer_set_max_bytes(sol_accounts_db_bulk_writer_t* writer,
                                          size_t max_bytes_queued) {
    if (!writer) return;
    if (max_bytes_queued == 0) return;
    writer->max_bytes_queued = max_bytes_queued;
}

void
sol_accounts_db_bulk_writer_set_use_merge(sol_accounts_db_bulk_writer_t* writer,
                                          bool use_merge) {
    if (!writer) return;
    writer->use_merge = use_merge;
}

sol_err_t
sol_accounts_db_bulk_writer_set_write_owner_index(sol_accounts_db_bulk_writer_t* writer,
                                                  bool enable) {
    if (!writer) return SOL_ERR_INVAL;

    if (!enable) {
        writer->write_owner_index = false;
        writer->write_owner_index_core_only = false;
        if (writer->idx_batch) {
            sol_storage_batch_destroy(writer->idx_batch);
            writer->idx_batch = NULL;
        }
        return SOL_OK;
    }

    if (!writer->db || !writer->db->owner_index_backend ||
        !writer->db->owner_index_backend->batch_write) {
        /* Owner index not available on this DB/backend. Treat as no-op. */
        writer->write_owner_index = false;
        return SOL_OK;
    }

    if (!writer->idx_batch) {
        writer->idx_batch = sol_storage_batch_new(writer->batch_capacity);
        if (!writer->idx_batch) {
            writer->write_owner_index = false;
            return SOL_ERR_NOMEM;
        }
    }

    writer->write_owner_index = true;
    return SOL_OK;
}

void
sol_accounts_db_bulk_writer_set_write_owner_index_core_only(sol_accounts_db_bulk_writer_t* writer,
                                                            bool core_only) {
    if (!writer) return;
    writer->write_owner_index_core_only = core_only;
}

bool
sol_accounts_db_bulk_writer_is_writing_owner_index(const sol_accounts_db_bulk_writer_t* writer) {
    if (!writer) return false;
    if (!writer->write_owner_index) return false;
    if (!writer->idx_batch) return false;
    if (!writer->db || !writer->db->owner_index_backend) return false;
    if (!writer->db->owner_index_backend->batch_write) return false;
    return true;
}

sol_err_t
sol_accounts_db_bulk_writer_set_write_owner_reverse(sol_accounts_db_bulk_writer_t* writer,
                                                    bool enable) {
    if (!writer) return SOL_ERR_INVAL;

    if (!enable) {
        writer->write_owner_reverse = false;
        if (writer->rev_batch) {
            sol_storage_batch_destroy(writer->rev_batch);
            writer->rev_batch = NULL;
        }
        return SOL_OK;
    }

    if (!writer->db || !writer->db->owner_reverse_backend ||
        !writer->db->owner_reverse_backend->batch_write) {
        writer->write_owner_reverse = false;
        return SOL_OK;
    }

    if (!writer->rev_batch) {
        writer->rev_batch = sol_storage_batch_new(writer->batch_capacity);
        if (!writer->rev_batch) {
            writer->write_owner_reverse = false;
            return SOL_ERR_NOMEM;
        }
    }

    writer->write_owner_reverse = true;
    return SOL_OK;
}

sol_err_t
sol_accounts_db_bulk_writer_flush(sol_accounts_db_bulk_writer_t* writer) {
    if (!writer) return SOL_ERR_INVAL;
    if (!writer->db || !writer->db->backend || !writer->db->backend->batch_write) return SOL_ERR_UNINITIALIZED;

    if ((!writer->batch || writer->batch->count == 0) &&
        (!writer->rev_batch || writer->rev_batch->count == 0) &&
        (!writer->idx_batch || writer->idx_batch->count == 0)) {
        return SOL_OK;
    }

    if (writer->batch && writer->batch->count > 0) {
        sol_err_t err = writer->db->backend->batch_write(writer->db->backend->ctx, writer->batch);
        if (err != SOL_OK) return err;
        sol_storage_batch_clear(writer->batch);
    }

    if (writer->idx_batch && writer->idx_batch->count > 0 &&
        writer->write_owner_index &&
        writer->db->owner_index_backend && writer->db->owner_index_backend->batch_write) {
        sol_err_t err = writer->db->owner_index_backend->batch_write(writer->db->owner_index_backend->ctx,
                                                                     writer->idx_batch);
        if (err != SOL_OK) return err;
        sol_storage_batch_clear(writer->idx_batch);
    }

    if (writer->rev_batch && writer->rev_batch->count > 0 &&
        writer->write_owner_reverse &&
        writer->db->owner_reverse_backend && writer->db->owner_reverse_backend->batch_write) {
        sol_err_t err = writer->db->owner_reverse_backend->batch_write(writer->db->owner_reverse_backend->ctx,
                                                                       writer->rev_batch);
        if (err != SOL_OK) return err;
        sol_storage_batch_clear(writer->rev_batch);
    }

    if (writer->arena) {
        sol_arena_reset(writer->arena);
    }
    writer->bytes_queued = 0;
    return SOL_OK;
}

static sol_err_t
sol_accounts_db_bulk_writer_queue_owner_reverse(sol_accounts_db_bulk_writer_t* writer,
                                                const sol_pubkey_t* pubkey,
                                                sol_slot_t slot,
                                                uint64_t write_version,
                                                uint64_t lamports,
                                                uint64_t data_len,
                                                const sol_pubkey_t* owner) {
    if (!writer || !pubkey) return SOL_ERR_INVAL;
    if (!writer->write_owner_reverse || !writer->rev_batch) return SOL_OK;
    if (!writer->db || !writer->db->owner_reverse_backend) return SOL_OK;

    uint8_t* key = sol_arena_memdup(writer->arena, pubkey->bytes, sizeof(pubkey->bytes));
    if (!key) return SOL_ERR_NOMEM;

    size_t payload_len = 48;
    size_t value_len = sizeof(sol_accountsdb_value_header_t) + payload_len;
    uint8_t* value = sol_arena_alloc(writer->arena, value_len);
    if (!value) return SOL_ERR_NOMEM;

    sol_accountsdb_value_header_t hdr = {
        .magic = SOL_ACCOUNTSDB_VALUE_MAGIC,
        .reserved = 0,
        .slot = (uint64_t)slot,
        .write_version = write_version,
    };
    memcpy(value, &hdr, sizeof(hdr));

    size_t off = sizeof(hdr);
    memcpy(value + off + 0, &lamports, 8);
    memcpy(value + off + 8, &data_len, 8);
    if (owner) {
        memcpy(value + off + 16, owner->bytes, 32);
    } else {
        memset(value + off + 16, 0, 32);
    }

    sol_err_t err = writer->use_merge
        ? sol_storage_batch_merge(writer->rev_batch,
                                  key,
                                  sizeof(pubkey->bytes),
                                  value,
                                  value_len)
        : sol_storage_batch_put(writer->rev_batch,
                                key,
                                sizeof(pubkey->bytes),
                                value,
                                value_len);
    if (err != SOL_OK) return err;

    writer->bytes_queued += sizeof(pubkey->bytes) + value_len;
    return SOL_OK;
}

static sol_err_t
sol_accounts_db_bulk_writer_queue_owner_index(sol_accounts_db_bulk_writer_t* writer,
                                              const sol_pubkey_t* pubkey,
                                              const sol_pubkey_t* owner) {
    if (!writer || !pubkey || !owner) return SOL_ERR_INVAL;
    if (!writer->write_owner_index || !writer->idx_batch) return SOL_OK;
    if (writer->write_owner_index_core_only && !owner_index_is_core_owner(owner)) {
        return SOL_OK;
    }

    uint8_t* key = sol_arena_alloc(writer->arena, 64);
    if (!key) return SOL_ERR_NOMEM;
    memcpy(key + 0, owner->bytes, 32);
    memcpy(key + 32, pubkey->bytes, 32);

    uint8_t* value = sol_arena_alloc(writer->arena, 1);
    if (!value) return SOL_ERR_NOMEM;
    value[0] = 0;

    sol_err_t err = sol_storage_batch_put(writer->idx_batch, key, 64, value, 1);
    if (err != SOL_OK) return err;

    writer->bytes_queued += 64 + 1;
    return SOL_OK;
}

sol_err_t
sol_accounts_db_bulk_writer_delete_versioned(sol_accounts_db_bulk_writer_t* writer,
                                             const sol_pubkey_t* pubkey,
                                             sol_slot_t slot,
                                             uint64_t write_version) {
    if (!writer || !pubkey) return SOL_ERR_INVAL;
    if (!writer->db || !writer->db->backend) return SOL_ERR_UNINITIALIZED;

    /* In merge mode, represent deletes as a versioned tombstone value so the
     * result is independent of write ordering. */
    bool want_merge = writer->use_merge;
    if (want_merge) {
        uint8_t* key = sol_arena_memdup(writer->arena, pubkey->bytes, sizeof(pubkey->bytes));
        if (!key) return SOL_ERR_NOMEM;

        size_t account_buf_size = 8 + 8 + 0 + 32 + 1 + 8;
        size_t value_buf_size = sizeof(sol_accountsdb_value_header_t) + account_buf_size;
        uint8_t* value = sol_arena_alloc(writer->arena, value_buf_size);
        if (!value) return SOL_ERR_NOMEM;

        sol_accountsdb_value_header_t hdr = {
            .magic = SOL_ACCOUNTSDB_VALUE_MAGIC,
            .reserved = 0,
            .slot = (uint64_t)slot,
            .write_version = write_version,
        };
        memcpy(value, &hdr, sizeof(hdr));

        size_t off = sizeof(hdr);
        uint64_t lamports = 0;
        uint64_t data_len = 0;
        memset(value + off, 0, account_buf_size);
        memcpy(value + off + 0, &lamports, 8);
        memcpy(value + off + 8, &data_len, 8);
        /* owner/executable/rent_epoch already zeroed */

        sol_err_t err = sol_storage_batch_merge(writer->batch,
                                                key,
                                                sizeof(pubkey->bytes),
                                                value,
                                                value_buf_size);
        if (err != SOL_OK) return err;

        writer->bytes_queued += sizeof(pubkey->bytes) + value_buf_size;

        sol_err_t rerr = sol_accounts_db_bulk_writer_queue_owner_reverse(writer,
                                                                         pubkey,
                                                                         slot,
                                                                         write_version,
                                                                         0,
                                                                         0,
                                                                         NULL);
        if (rerr != SOL_OK) return rerr;

        size_t rev_ops = (writer->write_owner_reverse && writer->rev_batch) ? writer->rev_batch->count : 0;
        size_t idx_ops = writer->idx_batch ? writer->idx_batch->count : 0;
        if (writer->batch->count >= writer->batch_capacity ||
            rev_ops >= writer->batch_capacity ||
            idx_ops >= writer->batch_capacity ||
            writer->bytes_queued >= writer->max_bytes_queued) {
            return sol_accounts_db_bulk_writer_flush(writer);
        }
        return SOL_OK;
    }

    uint8_t* key = sol_arena_memdup(writer->arena, pubkey->bytes, sizeof(pubkey->bytes));
    if (!key) return SOL_ERR_NOMEM;

    sol_err_t err = sol_storage_batch_delete(writer->batch, key, sizeof(pubkey->bytes));
    if (err != SOL_OK) return err;

    writer->bytes_queued += sizeof(pubkey->bytes);

    if (writer->write_owner_reverse && writer->rev_batch) {
        uint8_t* rkey = sol_arena_memdup(writer->arena, pubkey->bytes, sizeof(pubkey->bytes));
        if (!rkey) return SOL_ERR_NOMEM;

        sol_err_t rerr = sol_storage_batch_delete(writer->rev_batch, rkey, sizeof(pubkey->bytes));
        if (rerr != SOL_OK) return rerr;

        writer->bytes_queued += sizeof(pubkey->bytes);
    }

    size_t rev_ops = (writer->write_owner_reverse && writer->rev_batch) ? writer->rev_batch->count : 0;
    size_t idx_ops = writer->idx_batch ? writer->idx_batch->count : 0;
    if (writer->batch->count >= writer->batch_capacity ||
        rev_ops >= writer->batch_capacity ||
        idx_ops >= writer->batch_capacity ||
        writer->bytes_queued >= writer->max_bytes_queued) {
        return sol_accounts_db_bulk_writer_flush(writer);
    }
    return SOL_OK;
}

sol_err_t
sol_accounts_db_bulk_writer_put_versioned(sol_accounts_db_bulk_writer_t* writer,
                                          const sol_pubkey_t* pubkey,
                                          const sol_account_t* account,
                                          sol_slot_t slot,
                                          uint64_t write_version) {
    if (!writer || !pubkey || !account) return SOL_ERR_INVAL;
    if (!writer->db || !writer->db->backend) return SOL_ERR_UNINITIALIZED;

    if (account->meta.lamports == 0) {
        return sol_accounts_db_bulk_writer_delete_versioned(writer, pubkey, slot, write_version);
    }

    bool want_merge = writer->use_merge;

    uint8_t* key = sol_arena_memdup(writer->arena, pubkey->bytes, sizeof(pubkey->bytes));
    if (!key) return SOL_ERR_NOMEM;

    size_t account_buf_size = 8 + 8 + account->meta.data_len + 32 + 1 + 8;
    size_t value_buf_size = sizeof(sol_accountsdb_value_header_t) + account_buf_size;
    uint8_t* value = sol_arena_alloc(writer->arena, value_buf_size);
    if (!value) return SOL_ERR_NOMEM;

    sol_accountsdb_value_header_t hdr = {
        .magic = SOL_ACCOUNTSDB_VALUE_MAGIC,
        .reserved = 0,
        .slot = (uint64_t)slot,
        .write_version = write_version,
    };
    memcpy(value, &hdr, sizeof(hdr));

    size_t bytes_written = 0;
    sol_err_t serr = sol_account_serialize(account,
                                           value + sizeof(hdr),
                                           value_buf_size - sizeof(hdr),
                                           &bytes_written);
    if (serr != SOL_OK) return serr;

    size_t total_written = sizeof(hdr) + bytes_written;
    sol_err_t err = want_merge
        ? sol_storage_batch_merge(writer->batch,
                                  key,
                                  sizeof(pubkey->bytes),
                                  value,
                                  total_written)
        : sol_storage_batch_put(writer->batch,
                                key,
                                sizeof(pubkey->bytes),
                                value,
                                total_written);
    if (err != SOL_OK) return err;

    writer->bytes_queued += sizeof(pubkey->bytes) + total_written;

    sol_err_t rerr = sol_accounts_db_bulk_writer_queue_owner_reverse(writer,
                                                                     pubkey,
                                                                     slot,
                                                                     write_version,
                                                                     account->meta.lamports,
                                                                     (uint64_t)account->meta.data_len,
                                                                     &account->meta.owner);
    if (rerr != SOL_OK) return rerr;

    sol_err_t ierr = sol_accounts_db_bulk_writer_queue_owner_index(writer, pubkey, &account->meta.owner);
    if (ierr != SOL_OK) return ierr;

    size_t rev_ops = (writer->write_owner_reverse && writer->rev_batch) ? writer->rev_batch->count : 0;
    size_t idx_ops = writer->idx_batch ? writer->idx_batch->count : 0;
    if (writer->batch->count >= writer->batch_capacity ||
        rev_ops >= writer->batch_capacity ||
        idx_ops >= writer->batch_capacity ||
        writer->bytes_queued >= writer->max_bytes_queued) {
        return sol_accounts_db_bulk_writer_flush(writer);
    }

    return SOL_OK;
}

sol_err_t
sol_accounts_db_bulk_writer_put_raw_versioned(sol_accounts_db_bulk_writer_t* writer,
                                              const sol_pubkey_t* pubkey,
                                              const sol_pubkey_t* owner,
                                              uint64_t lamports,
                                              const uint8_t* data,
                                              uint64_t data_len,
                                              bool executable,
                                              uint64_t rent_epoch,
                                              sol_slot_t slot,
                                              uint64_t write_version) {
    if (!writer || !pubkey || !owner) return SOL_ERR_INVAL;
    if (!writer->db || !writer->db->backend) return SOL_ERR_UNINITIALIZED;

    if (lamports == 0) {
        return sol_accounts_db_bulk_writer_delete_versioned(writer, pubkey, slot, write_version);
    }

    if (data_len > (uint64_t)SOL_ACCOUNT_MAX_DATA_SIZE) return SOL_ERR_TOO_LARGE;
    if (data_len > (uint64_t)SIZE_MAX) return SOL_ERR_TOO_LARGE;
    size_t data_len_sz = (size_t)data_len;
    if (data_len_sz > 0 && !data) return SOL_ERR_INVAL;

    bool want_merge = writer->use_merge;

    uint8_t* key = sol_arena_memdup(writer->arena, pubkey->bytes, sizeof(pubkey->bytes));
    if (!key) return SOL_ERR_NOMEM;

    size_t account_buf_size = 8 + 8 + data_len_sz + 32 + 1 + 8;
    size_t value_buf_size = sizeof(sol_accountsdb_value_header_t) + account_buf_size;
    if (value_buf_size < account_buf_size) return SOL_ERR_OVERFLOW;

    uint8_t* value = sol_arena_alloc(writer->arena, value_buf_size);
    if (!value) return SOL_ERR_NOMEM;

    sol_accountsdb_value_header_t hdr = {
        .magic = SOL_ACCOUNTSDB_VALUE_MAGIC,
        .reserved = 0,
        .slot = (uint64_t)slot,
        .write_version = write_version,
    };
    memcpy(value, &hdr, sizeof(hdr));

    uint8_t* p = value + sizeof(hdr);
    size_t off = 0;

    memcpy(p + off, &lamports, 8);
    off += 8;

    memcpy(p + off, &data_len, 8);
    off += 8;

    if (data_len_sz > 0) {
        memcpy(p + off, data, data_len_sz);
        off += data_len_sz;
    }

    memcpy(p + off, owner->bytes, 32);
    off += 32;

    p[off++] = executable ? 1 : 0;

    memcpy(p + off, &rent_epoch, 8);
    off += 8;

    size_t total_written = sizeof(hdr) + off;
    sol_err_t err = want_merge
        ? sol_storage_batch_merge(writer->batch,
                                  key,
                                  sizeof(pubkey->bytes),
                                  value,
                                  total_written)
        : sol_storage_batch_put(writer->batch,
                                key,
                                sizeof(pubkey->bytes),
                                value,
                                total_written);
    if (err != SOL_OK) return err;

    writer->bytes_queued += sizeof(pubkey->bytes) + total_written;

    sol_err_t rerr = sol_accounts_db_bulk_writer_queue_owner_reverse(writer,
                                                                     pubkey,
                                                                     slot,
                                                                     write_version,
                                                                     lamports,
                                                                     (uint64_t)data_len_sz,
                                                                     owner);
    if (rerr != SOL_OK) return rerr;

    sol_err_t ierr = sol_accounts_db_bulk_writer_queue_owner_index(writer, pubkey, owner);
    if (ierr != SOL_OK) return ierr;

    size_t rev_ops = (writer->write_owner_reverse && writer->rev_batch) ? writer->rev_batch->count : 0;
    size_t idx_ops = writer->idx_batch ? writer->idx_batch->count : 0;
    if (writer->batch->count >= writer->batch_capacity ||
        rev_ops >= writer->batch_capacity ||
        idx_ops >= writer->batch_capacity ||
        writer->bytes_queued >= writer->max_bytes_queued) {
        return sol_accounts_db_bulk_writer_flush(writer);
    }

    return SOL_OK;
}

sol_err_t
sol_accounts_db_bulk_writer_put_snapshot_account(sol_accounts_db_bulk_writer_t* writer,
                                                 const sol_pubkey_t* pubkey,
                                                 const sol_pubkey_t* owner,
                                                 uint64_t lamports,
                                                 const uint8_t* data,
                                                 uint64_t data_len,
                                                 bool executable,
                                                 uint64_t rent_epoch,
                                                 sol_slot_t slot,
                                                 uint64_t write_version,
                                                 const sol_hash_t* leaf_hash,
                                                 uint64_t file_key,
                                                 uint64_t record_offset) {
    if (!writer || !pubkey || !owner) return SOL_ERR_INVAL;
    if (!writer->db || !writer->db->backend) return SOL_ERR_UNINITIALIZED;

    /* Default behavior: store full account bytes. */
    if (writer->db->config.storage_type != SOL_ACCOUNTS_STORAGE_APPENDVEC) {
        return sol_accounts_db_bulk_writer_put_raw_versioned(writer,
                                                             pubkey,
                                                             owner,
                                                             lamports,
                                                             data,
                                                             data_len,
                                                             executable,
                                                             rent_epoch,
                                                             slot,
                                                             write_version);
    }

    /* AppendVec mode: store a reference into an on-disk AppendVec file plus the
     * account hash leaf needed for fast accounts-hash verification. */
    if (lamports == 0) {
        file_key = 0;
        record_offset = 0;
        data_len = 0;
        data = NULL;
    }

    if (data_len > (uint64_t)SOL_ACCOUNT_MAX_DATA_SIZE) return SOL_ERR_TOO_LARGE;
    if (data_len > (uint64_t)SIZE_MAX) return SOL_ERR_TOO_LARGE;
    size_t data_len_sz = (size_t)data_len;
    if (data_len_sz > 0 && !data) {
        /* For AppendVec storage we can skip providing account bytes when the
         * caller already supplied the precomputed account hash leaf. This
         * avoids per-account buffering during snapshot ingestion. */
        if (!(lamports != 0 && leaf_hash && !sol_hash_is_zero(leaf_hash))) {
            return SOL_ERR_INVAL;
        }
    }

    sol_hash_t leaf = {0};
    if (lamports != 0) {
        if (leaf_hash && !sol_hash_is_zero(leaf_hash)) {
            leaf = *leaf_hash;
        } else {
            sol_account_t account = {0};
            account.meta.owner = *owner;
            account.meta.lamports = lamports;
            account.meta.data_len = (ulong)data_len_sz;
            account.meta.executable = executable;
            account.meta.rent_epoch = (sol_epoch_t)rent_epoch;
            account.data = (uint8_t*)data;
            sol_account_hash(pubkey, &account, &leaf);
        }
    }

    sol_accountsdb_appendvec_ref_v1_t ref = {0};
    ref.file_key = file_key;
    ref.record_offset = record_offset;
    ref.account_hash = leaf;

    uint8_t* key = sol_arena_memdup(writer->arena, pubkey->bytes, sizeof(pubkey->bytes));
    if (!key) return SOL_ERR_NOMEM;

    size_t value_len = sizeof(sol_accountsdb_value_header_t) + sizeof(ref);
    uint8_t* value = sol_arena_alloc(writer->arena, value_len);
    if (!value) return SOL_ERR_NOMEM;

    sol_accountsdb_value_header_t hdr = {
        .magic = SOL_ACCOUNTSDB_VALUE_MAGIC,
        .reserved = 0,
        .slot = (uint64_t)slot,
        .write_version = write_version,
    };
    memcpy(value, &hdr, sizeof(hdr));
    memcpy(value + sizeof(hdr), &ref, sizeof(ref));

    bool want_merge = writer->use_merge;
    sol_err_t err = want_merge
        ? sol_storage_batch_merge(writer->batch,
                                  key,
                                  sizeof(pubkey->bytes),
                                  value,
                                  value_len)
        : sol_storage_batch_put(writer->batch,
                                key,
                                sizeof(pubkey->bytes),
                                value,
                                value_len);
    if (err != SOL_OK) return err;

    writer->bytes_queued += sizeof(pubkey->bytes) + value_len;

    /* Keep reverse mapping and (optional) owner index in sync for bootstrap. */
    sol_err_t rerr = sol_accounts_db_bulk_writer_queue_owner_reverse(writer,
                                                                     pubkey,
                                                                     slot,
                                                                     write_version,
                                                                     lamports,
                                                                     (uint64_t)data_len_sz,
                                                                     lamports ? owner : NULL);
    if (rerr != SOL_OK) return rerr;

    if (lamports != 0) {
        sol_err_t ierr = sol_accounts_db_bulk_writer_queue_owner_index(writer, pubkey, owner);
        if (ierr != SOL_OK) return ierr;
    }

    size_t rev_ops = (writer->write_owner_reverse && writer->rev_batch) ? writer->rev_batch->count : 0;
    size_t idx_ops = writer->idx_batch ? writer->idx_batch->count : 0;
    if (writer->batch->count >= writer->batch_capacity ||
        rev_ops >= writer->batch_capacity ||
        idx_ops >= writer->batch_capacity ||
        writer->bytes_queued >= writer->max_bytes_queued) {
        return sol_accounts_db_bulk_writer_flush(writer);
    }

    return SOL_OK;
}

/*
 * Hash function for pubkey
 */
static size_t
pubkey_hash(const sol_pubkey_t* pubkey, size_t bucket_count) {
    /* Use first 8 bytes as hash */
    uint64_t h;
    memcpy(&h, pubkey->bytes, 8);
    return (size_t)(h % bucket_count);
}

/*
 * Find entry in bucket
 */
static sol_account_entry_t*
find_entry(sol_account_entry_t* bucket, const sol_pubkey_t* pubkey) {
    while (bucket) {
        if (sol_pubkey_eq(&bucket->pubkey, pubkey)) {
            return bucket;
        }
        bucket = bucket->next;
    }
    return NULL;
}

static bool
decode_backend_value(const uint8_t* value,
                     size_t value_len,
                     sol_slot_t* out_slot,
                     uint64_t* out_write_version,
                     const uint8_t** out_account_bytes,
                     size_t* out_account_len) {
    if (!value || value_len == 0 || !out_account_bytes || !out_account_len) return false;

    if (out_slot) *out_slot = 0;
    if (out_write_version) *out_write_version = 0;

    if (value_len >= sizeof(sol_accountsdb_value_header_t)) {
        sol_accountsdb_value_header_t hdr;
        memcpy(&hdr, value, sizeof(hdr));

        if (hdr.magic == SOL_ACCOUNTSDB_VALUE_MAGIC) {
            if (out_slot) *out_slot = (sol_slot_t)hdr.slot;
            if (out_write_version) *out_write_version = hdr.write_version;
            *out_account_bytes = value + sizeof(hdr);
            *out_account_len = value_len - sizeof(hdr);
            return true;
        }
    }

    *out_account_bytes = value;
    *out_account_len = value_len;
    return false;
}

static bool
appendvec_ref_decode(const uint8_t* payload,
                     size_t payload_len,
                     sol_accountsdb_appendvec_ref_v1_t* out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!payload) return false;
    if (payload_len != sizeof(*out)) return false;
    memcpy(out, payload, sizeof(*out));
    return true;
}

static size_t
accounts_db_env_size_t(const char* key, size_t min, size_t max) {
    if (!key || key[0] == '\0') return 0;
    const char* env = getenv(key);
    if (!env || env[0] == '\0') return 0;

    while (*env && isspace((unsigned char)*env)) env++;
    if (*env == '\0') return 0;

    errno = 0;
    char* end = NULL;
    unsigned long long v = strtoull(env, &end, 10);
    if (errno != 0 || end == env) return 0;
    if (v < (unsigned long long)min) v = (unsigned long long)min;
    if (v > (unsigned long long)max) v = (unsigned long long)max;
    return (size_t)v;
}

static uint32_t
accounts_db_appendvec_index_default_shards(void) {
    long cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
    uint32_t threads = 1u;
    if (cpu_count > 0) threads = (uint32_t)cpu_count;

    size_t want = (size_t)threads * 8u;
    if (want < 64u) want = 64u;
    if (want > 4096u) want = 4096u;

    size_t env = accounts_db_env_size_t("SOL_SNAPSHOT_DEFER_APPENDVEC_INDEX_SHARDS", 1u, 16384u);
    if (env > 0) want = env;

    uint32_t shards = (uint32_t)want;
    shards = sol_next_pow2_32(shards);
    if (shards < 1u) shards = 1u;
    return shards;
}

static size_t
accounts_db_appendvec_index_default_capacity_per_shard(uint32_t shard_count) {
    if (shard_count == 0) return 0;

    size_t env = accounts_db_env_size_t("SOL_SNAPSHOT_DEFER_APPENDVEC_INDEX_CAPACITY_PER_SHARD",
                                        1024u,
                                        (size_t)1u << 24 /* 16,777,216 */);
    if (env > 0) return env;

    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGESIZE);
    if (pages <= 0 || page_size <= 0) return 0;

    uint64_t total = (uint64_t)pages * (uint64_t)page_size;
    uint64_t target_total_capacity = 0;

    if (total >= (1024ull * 1024ull * 1024ull * 1024ull)) {          /* >= 1 TiB */
        target_total_capacity = 1ull << 31;                           /* 2,147,483,648 */
    } else if (total >= (512ull * 1024ull * 1024ull * 1024ull)) {     /* >= 512 GiB */
        target_total_capacity = 1ull << 29;                           /* 536,870,912 */
    } else if (total >= (256ull * 1024ull * 1024ull * 1024ull)) {     /* >= 256 GiB */
        target_total_capacity = 1ull << 28;                           /* 268,435,456 */
    } else if (total >= (128ull * 1024ull * 1024ull * 1024ull)) {     /* >= 128 GiB */
        target_total_capacity = 1ull << 28;                           /* 268,435,456 */
    } else if (total >= (96ull * 1024ull * 1024ull * 1024ull)) {      /* >= 96 GiB */
        target_total_capacity = 1ull << 27;                           /* 134,217,728 */
    } else if (total >= (64ull * 1024ull * 1024ull * 1024ull)) {      /* >= 64 GiB */
        target_total_capacity = 1ull << 26;                           /* 67,108,864 */
    } else {
        return 0;
    }

    uint64_t per = target_total_capacity / (uint64_t)shard_count;
    if (per < 1024u) per = 1024u;
    if (per > (uint64_t)((size_t)1u << 24)) per = (uint64_t)((size_t)1u << 24);
    return (size_t)per;
}

static uint32_t
accounts_db_appendvec_index_build_threads_default(void) {
    size_t env = accounts_db_env_size_t("SOL_APPENDVEC_INDEX_BUILD_THREADS", 1u, 256u);
    if (env > 0) {
        return (uint32_t)env;
    }

    long cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
    uint32_t threads = 1u;
    if (cpu_count > 0) {
        threads = (uint32_t)cpu_count;
    }

    /* Parallelizing the initial RocksDB scan is beneficial, but too many
     * concurrent iterators can thrash the block cache. */
    if (threads > 64u) threads = 64u;
    if (threads < 1u) threads = 1u;
    return threads;
}

typedef struct {
    sol_appendvec_index_t* idx;
    sol_err_t              err;         /* atomic */
    uint64_t               keys_seen;   /* atomic */
    uint64_t               tombstones;  /* atomic */
    uint64_t               start_ms;
    uint64_t               last_log_ms; /* atomic */
} appendvec_index_build_ctx_t;

static bool
appendvec_index_build_iter_cb(const uint8_t* key,
                              size_t key_len,
                              const uint8_t* value,
                              size_t value_len,
                              void* ctx) {
    appendvec_index_build_ctx_t* c = (appendvec_index_build_ctx_t*)ctx;
    if (!c || !c->idx) return false;
    if (__atomic_load_n(&c->err, __ATOMIC_RELAXED) != SOL_OK) return false;

    if (!key || key_len < SOL_PUBKEY_SIZE) {
        return true; /* skip metadata keys */
    }
    if (!value || value_len == 0) {
        return true;
    }

    sol_pubkey_t pubkey;
    memcpy(pubkey.bytes, key, SOL_PUBKEY_SIZE);

    sol_slot_t stored_slot = 0;
    uint64_t stored_write_version = 0;
    const uint8_t* payload = NULL;
    size_t payload_len = 0;
    decode_backend_value(value, value_len, &stored_slot, &stored_write_version, &payload, &payload_len);

    sol_accountsdb_appendvec_ref_v1_t ref = {0};
    if (!appendvec_ref_decode(payload, payload_len, &ref)) {
        return true;
    }

    sol_appendvec_index_val_t v = {0};
    v.slot = (uint64_t)stored_slot;
    v.write_version = stored_write_version;
    v.file_key = ref.file_key;
    v.record_offset = ref.record_offset;
    v.leaf_hash = ref.account_hash;
    if (!sol_hash_is_zero(&ref.account_hash)) {
        /* We don't have the real lamports without reading AppendVec. Any non-zero
         * value marks the entry as live for the fast-path existence checks. */
        v.lamports = 1;
    } else {
        v.lamports = 0;
        atomic_inc_u64(&c->tombstones);
    }

    size_t shard = (size_t)(sol_load_u64_le(pubkey.bytes) & (c->idx->shard_count - 1u));
    sol_appendvec_index_shard_t* s = &c->idx->shards[shard];

    pthread_rwlock_wrlock(&s->lock);
    void* inserted = sol_pubkey_map_insert(s->map, &pubkey, &v);
    pthread_rwlock_unlock(&s->lock);
    if (!inserted) {
        sol_err_t expect = SOL_OK;
        (void)__atomic_compare_exchange_n(&c->err, &expect, SOL_ERR_NOMEM, false,
                                          __ATOMIC_RELAXED, __ATOMIC_RELAXED);
        return false;
    }

    atomic_inc_u64(&c->keys_seen);

    uint64_t now = monotonic_ms();
    uint64_t last = atomic_load_u64(&c->last_log_ms);
    if (now - last >= 5000u) {
        uint64_t expect = last;
        if (__atomic_compare_exchange_n(&c->last_log_ms, &expect, now, false,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
            uint64_t keys_seen = atomic_load_u64(&c->keys_seen);
            uint64_t tombstones = atomic_load_u64(&c->tombstones);
            double secs = (double)(now - c->start_ms) / 1000.0;
            double rate = secs > 0.0 ? ((double)keys_seen / secs) : 0.0;
            sol_log_info("AppendVec index build progress: %lu keys (tombstones=%lu) rate=%.0f keys/s",
                         (unsigned long)keys_seen,
                         (unsigned long)tombstones,
                         rate);
        }
    }

    return true;
}

typedef struct {
    sol_accounts_db_t*          root;
    appendvec_index_build_ctx_t* ctx;
    uint8_t                    start_key[SOL_PUBKEY_SIZE];
    uint8_t                    end_key[SOL_PUBKEY_SIZE];
    bool                       has_end;
} appendvec_index_build_worker_arg_t;

static void*
appendvec_index_build_worker(void* arg) {
    appendvec_index_build_worker_arg_t* a = (appendvec_index_build_worker_arg_t*)arg;
    if (!a || !a->root || !a->ctx) return NULL;
    if (!a->root->backend || !a->root->backend->iterate_range) return NULL;

    const uint8_t* end_key = a->has_end ? a->end_key : NULL;
    size_t end_len = a->has_end ? SOL_PUBKEY_SIZE : 0;

    a->root->backend->iterate_range(a->root->backend->ctx,
                                   a->start_key,
                                   SOL_PUBKEY_SIZE,
                                   end_key,
                                   end_len,
                                   appendvec_index_build_iter_cb,
                                   a->ctx);
    return NULL;
}

sol_err_t
sol_accounts_db_maybe_build_appendvec_index(sol_accounts_db_t* db) {
    if (!db) return SOL_ERR_INVAL;

    sol_accounts_db_t* root = accounts_db_root(db);
    if (!root) return SOL_ERR_INVAL;

    if (root->config.storage_type != SOL_ACCOUNTS_STORAGE_APPENDVEC) {
        return SOL_OK;
    }
    if (root->parent) {
        return SOL_OK;
    }
    if (!root->backend || !root->backend->iterate) {
        return SOL_OK;
    }

    pthread_rwlock_rdlock(&root->lock);
    bool already_built = (root->appendvec_index != NULL);
    pthread_rwlock_unlock(&root->lock);
    if (already_built) {
        return SOL_OK;
    }

    uint32_t shards = accounts_db_appendvec_index_default_shards();
    size_t cap_per_shard = accounts_db_appendvec_index_default_capacity_per_shard(shards);
    if (cap_per_shard == 0) {
        sol_log_warn("AccountsDB: skipping in-memory AppendVec index build (no safe default capacity; "
                     "set SOL_SNAPSHOT_DEFER_APPENDVEC_INDEX_CAPACITY_PER_SHARD to enable)");
        return SOL_OK;
    }

    sol_appendvec_index_t* idx = sol_appendvec_index_new(shards, cap_per_shard);
    if (!idx) {
        sol_log_warn("AccountsDB: failed to allocate in-memory AppendVec index (shards=%u cap/shard=%zu)",
                     (unsigned)shards,
                     cap_per_shard);
        return SOL_ERR_NOMEM;
    }

    uint32_t build_threads = accounts_db_appendvec_index_build_threads_default();
    if (!root->backend->iterate_range) {
        build_threads = 1u;
    }
    if (build_threads > 256u) build_threads = 256u;
    if (build_threads < 1u) build_threads = 1u;

    sol_log_info("AccountsDB: building in-memory AppendVec index from RocksDB (shards=%u cap/shard=%zu threads=%u)...",
                 (unsigned)shards,
                 cap_per_shard,
                 (unsigned)build_threads);

    appendvec_index_build_ctx_t bctx = {0};
    bctx.idx = idx;
    bctx.err = SOL_OK;
    bctx.keys_seen = 0;
    bctx.tombstones = 0;
    bctx.start_ms = monotonic_ms();
    bctx.last_log_ms = bctx.start_ms;

    bool ran_parallel = false;
    if (build_threads > 1u && root->backend->iterate_range) {
        pthread_t* threads = sol_calloc(build_threads, sizeof(*threads));
        appendvec_index_build_worker_arg_t* args = sol_calloc(build_threads, sizeof(*args));
        if (threads && args) {
            ran_parallel = true;
            uint32_t created = 0;
            for (uint32_t i = 0; i < build_threads; i++) {
                appendvec_index_build_worker_arg_t* a = &args[i];
                a->root = root;
                a->ctx = &bctx;
                memset(a->start_key, 0, sizeof(a->start_key));
                memset(a->end_key, 0, sizeof(a->end_key));

                uint32_t start = (uint32_t)((256ull * (uint64_t)i) / (uint64_t)build_threads);
                uint32_t end = (uint32_t)((256ull * (uint64_t)(i + 1u)) / (uint64_t)build_threads);
                if (start > 255u) start = 255u;
                if (end > 256u) end = 256u;

                a->start_key[0] = (uint8_t)start;
                a->has_end = (end < 256u);
                if (a->has_end) {
                    a->end_key[0] = (uint8_t)end;
                }

                if (pthread_create(&threads[i], NULL, appendvec_index_build_worker, a) != 0) {
                    sol_err_t expect = SOL_OK;
                    (void)__atomic_compare_exchange_n(&bctx.err, &expect, SOL_ERR_IO, false,
                                                      __ATOMIC_RELAXED, __ATOMIC_RELAXED);
                    break;
                }
                created++;
            }

            for (uint32_t i = 0; i < created; i++) {
                (void)pthread_join(threads[i], NULL);
            }
        } else {
            sol_log_warn("AccountsDB: failed to allocate AppendVec index build thread state; falling back to single-threaded build");
        }
        sol_free(args);
        sol_free(threads);
    }

    if (!ran_parallel) {
        root->backend->iterate(root->backend->ctx, appendvec_index_build_iter_cb, &bctx);
    }

    uint64_t elapsed_ms = monotonic_ms() - bctx.start_ms;
    sol_err_t build_err = __atomic_load_n(&bctx.err, __ATOMIC_RELAXED);
    uint64_t keys_seen = atomic_load_u64(&bctx.keys_seen);
    uint64_t tombstones = atomic_load_u64(&bctx.tombstones);
    if (build_err != SOL_OK) {
        sol_log_warn("AccountsDB: in-memory AppendVec index build failed after %lu keys: %s",
                     (unsigned long)keys_seen,
                     sol_err_str(build_err));
        sol_appendvec_index_destroy(idx);
        return build_err;
    }

    sol_log_info("AccountsDB: built in-memory AppendVec index (%lu keys, tombstones=%lu) in %lums",
                 (unsigned long)keys_seen,
                 (unsigned long)tombstones,
                 (unsigned long)elapsed_ms);

    sol_accounts_db_adopt_appendvec_index(root, idx);
    idx = NULL;
    return SOL_OK;
}

static sol_err_t
appendvec_build_path(const sol_accounts_db_t* db,
                     uint64_t file_key,
                     char out_path[512]) {
    if (!db || !out_path) return SOL_ERR_INVAL;
    if (!db->appendvec_dir || db->appendvec_dir[0] == '\0') return SOL_ERR_UNINITIALIZED;

    if (file_key == 0) {
        int n = snprintf(out_path, 512, "%s/storage.bin", db->appendvec_dir);
        if (n < 0 || n >= 512) return SOL_ERR_OVERFLOW;
        return SOL_OK;
    }

    uint64_t slot = file_key >> 32;
    uint64_t id = file_key & 0xFFFFFFFFu;
    int n = snprintf(out_path, 512, "%s/%lu.%lu",
                     db->appendvec_dir,
                     (unsigned long)slot,
                     (unsigned long)id);
    if (n < 0 || n >= 512) return SOL_ERR_OVERFLOW;
    return SOL_OK;
}

static size_t
appendvec_open_fd_limit(void) {
    /* Keep some headroom for network sockets, RocksDB, etc. */
    /* Mainnet snapshots can contain >65k appendvec files. If we cap too low,
     * we fall back to per-load open/pread/close (and often can't mmap), which
     * is catastrophic for replay throughput. Prefer a higher default while
     * still respecting RLIMIT_NOFILE and keeping headroom. */
    const size_t default_limit = 262144u;
    const size_t min_limit = 256u;
    const size_t max_limit = 1048576u;
    const size_t min_headroom = 128u;
    const size_t max_headroom = 8192u;

    size_t limit = default_limit;

    const char* env = getenv("SOL_APPENDVEC_MAX_OPEN_FDS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long v = strtoul(env, &end, 10);
        if (end != env) {
            limit = (size_t)v;
        }
    }

    if (limit < min_limit) limit = min_limit;
    if (limit > max_limit) limit = max_limit;

    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY) {
        size_t cur = (size_t)rl.rlim_cur;
        /* On low ulimit hosts, reserve a much larger fraction so RPC/gossip
         * sockets don't hit EMFILE during replay bootstrap. */
        size_t headroom = (cur < 16384u) ? (cur / 2u) : (cur / 8u);
        if (headroom < min_headroom) headroom = min_headroom;
        if (headroom > max_headroom) headroom = max_headroom;

        if (cur > min_limit && headroom + min_limit >= cur) {
            headroom = cur - min_limit;
        }

        if (cur > headroom) {
            size_t max_safe = cur - headroom;
            if (limit > max_safe) limit = max_safe;
        } else {
            limit = min_limit;
        }
    }

    if (limit < min_limit) limit = min_limit;
    return limit;
}

static int
appendvec_evict_one_fd_locked(sol_accounts_db_t* db,
                              uint64_t avoid_file_key) {
    if (!db || !db->appendvec_files || db->appendvec_open_fds == 0) return -1;

    sol_map_t* files = db->appendvec_files;
    size_t cap = files->capacity;
    if (cap == 0) return -1;

    size_t idx = db->appendvec_fd_evict_cursor % cap;
    for (size_t scanned = 0; scanned < cap; scanned++) {
        if (files->ctrl[idx] & SOL_MAP_OCCUPIED) {
            uint64_t* keyp = (uint64_t*)((char*)files->keys + idx * files->key_size);
            appendvec_file_t** valp =
                (appendvec_file_t**)((char*)files->vals + idx * files->val_size);
            appendvec_file_t* f = valp ? *valp : NULL;
            if (f && f->fd >= 0 && !f->writable && *keyp != avoid_file_key) {
                int fd = f->fd;
                f->fd = -1;
                if (db->appendvec_open_fds > 0) db->appendvec_open_fds--;
                db->appendvec_fd_evict_cursor = (idx + 1u) % cap;
                return fd;
            }
        }
        idx = (idx + 1u) % cap;
    }

    return -1;
}

static sol_err_t
appendvec_get_fd(sol_accounts_db_t* db,
                 uint64_t file_key,
                 bool want_write,
                 int* out_fd,
                 bool* out_ephemeral,
                 appendvec_file_t** out_file) {
    if (!db || !out_fd) return SOL_ERR_INVAL;
    *out_fd = -1;
    if (out_ephemeral) *out_ephemeral = false;
    if (out_file) *out_file = NULL;
    if (!db->appendvec_lock_init || !db->appendvec_files) return SOL_ERR_UNINITIALIZED;

    char path[512] = {0};
    sol_err_t perr = appendvec_build_path(db, file_key, path);
    if (perr != SOL_OK) return perr;

    /* Fast path: concurrent readers when file is already opened. */
    pthread_rwlock_rdlock(&db->appendvec_lock);
    appendvec_file_t** curp = (appendvec_file_t**)sol_map_get(db->appendvec_files, &file_key);
    appendvec_file_t* cur = curp ? *curp : NULL;
    if (cur && want_write && cur->sealed) {
        pthread_rwlock_unlock(&db->appendvec_lock);
        return SOL_ERR_UNSUPPORTED;
    }
    if (cur && cur->fd >= 0 && (!want_write || cur->writable)) {
        *out_fd = cur->fd;
        if (out_file) *out_file = cur;
        pthread_rwlock_unlock(&db->appendvec_lock);
        return SOL_OK;
    }
    pthread_rwlock_unlock(&db->appendvec_lock);

    /* Open outside the lock to avoid serializing other readers. */
    int flags = want_write ? (O_RDWR | O_CREAT) : O_RDONLY;
    int fd = open(path, flags | O_CLOEXEC, 0644);
    if (fd < 0) {
        return (errno == ENOENT) ? SOL_ERR_NOTFOUND : SOL_ERR_IO;
    }

    off_t end = lseek(fd, 0, SEEK_END);
    if (end < 0) {
        close(fd);
        return SOL_ERR_IO;
    }
    uint64_t end_u64 = (uint64_t)end;
    if (want_write) {
        end_u64 = (end_u64 + 7u) & ~7ull;
    }

    int old_fd_to_close = -1;
    int evicted_fd_to_close = -1;

    pthread_rwlock_wrlock(&db->appendvec_lock);

    /* Re-check under write lock in case another thread inserted. */
    curp = (appendvec_file_t**)sol_map_get(db->appendvec_files, &file_key);
    cur = curp ? *curp : NULL;
    if (cur && want_write && cur->sealed) {
        pthread_rwlock_unlock(&db->appendvec_lock);
        close(fd);
        return SOL_ERR_UNSUPPORTED;
    }
    if (cur && cur->fd >= 0 && (!want_write || cur->writable)) {
        *out_fd = cur->fd;
        if (out_file) *out_file = cur;
        pthread_rwlock_unlock(&db->appendvec_lock);
        close(fd);
        return SOL_OK;
    }

    /* If this would add a new cached FD and we're at the cap, return an
     * ephemeral FD instead (caller must close). This avoids unbounded FD growth
     * under random-access RPC workloads. */
    bool had_open_fd = (cur && cur->fd >= 0);
    if (!had_open_fd &&
        db->appendvec_open_fds_limit > 0 &&
        db->appendvec_open_fds >= db->appendvec_open_fds_limit) {
        evicted_fd_to_close = appendvec_evict_one_fd_locked(db, file_key);
    }

    if (!had_open_fd &&
        db->appendvec_open_fds_limit > 0 &&
        db->appendvec_open_fds >= db->appendvec_open_fds_limit) {
        if (!db->appendvec_fd_cache_warned) {
            db->appendvec_fd_cache_warned = 1;
            sol_log_warn("AppendVec FD cache limit reached (%zu); using ephemeral opens",
                         db->appendvec_open_fds_limit);
        }
        if (!cur) {
            appendvec_file_t* f = sol_calloc(1, sizeof(*f));
            if (!f) {
                pthread_rwlock_unlock(&db->appendvec_lock);
                if (evicted_fd_to_close >= 0) close(evicted_fd_to_close);
                close(fd);
                return SOL_ERR_NOMEM;
            }
            f->fd = -1;
            f->writable = want_write ? 1u : 0u;
            f->sealed = 0u;
            __atomic_store_n(&f->size, end_u64, __ATOMIC_RELAXED);
            f->map = NULL;
            f->map_size = 0;
            appendvec_file_t* tmp = f;
            appendvec_file_t** slot =
                (appendvec_file_t**)sol_map_insert(db->appendvec_files, &file_key, &tmp);
            if (!slot) {
                sol_free(f);
                pthread_rwlock_unlock(&db->appendvec_lock);
                if (evicted_fd_to_close >= 0) close(evicted_fd_to_close);
                close(fd);
                return SOL_ERR_NOMEM;
            }
            cur = f;
        } else if (__atomic_load_n(&cur->size, __ATOMIC_RELAXED) == 0u) {
            __atomic_store_n(&cur->size, end_u64, __ATOMIC_RELAXED);
        }
        *out_fd = fd;
        if (out_ephemeral) *out_ephemeral = true;
        if (out_file) *out_file = cur;
        pthread_rwlock_unlock(&db->appendvec_lock);
        if (evicted_fd_to_close >= 0) close(evicted_fd_to_close);
        return SOL_OK;
    }

    if (!cur) {
        appendvec_file_t* f = sol_calloc(1, sizeof(*f));
        if (!f) {
            pthread_rwlock_unlock(&db->appendvec_lock);
            if (evicted_fd_to_close >= 0) close(evicted_fd_to_close);
            close(fd);
            return SOL_ERR_NOMEM;
        }
        f->fd = fd;
        f->writable = want_write ? 1u : 0u;
        f->sealed = 0u;
        __atomic_store_n(&f->size, end_u64, __ATOMIC_RELAXED);
        f->map = NULL;
        f->map_size = 0;

        appendvec_file_t* tmp = f;
        appendvec_file_t** slot =
            (appendvec_file_t**)sol_map_insert(db->appendvec_files, &file_key, &tmp);
        if (!slot) {
            sol_free(f);
            pthread_rwlock_unlock(&db->appendvec_lock);
            if (evicted_fd_to_close >= 0) close(evicted_fd_to_close);
            close(fd);
            return SOL_ERR_NOMEM;
        }
        cur = f;
        if (!had_open_fd) {
            db->appendvec_open_fds++;
        }
    } else {
        int old_fd = (cur->fd >= 0) ? cur->fd : -1;
        if (old_fd >= 0 && old_fd != fd) {
            old_fd_to_close = old_fd;
        }
        cur->fd = fd;
        cur->writable = want_write ? 1u : cur->writable;
        if (__atomic_load_n(&cur->size, __ATOMIC_RELAXED) == 0u) {
            __atomic_store_n(&cur->size, end_u64, __ATOMIC_RELAXED);
        }
        if (!had_open_fd) {
            db->appendvec_open_fds++;
        }
    }

    *out_fd = cur->fd;
    if (out_file) *out_file = cur;
    pthread_rwlock_unlock(&db->appendvec_lock);

    if (old_fd_to_close >= 0) {
        close(old_fd_to_close);
    }
    if (evicted_fd_to_close >= 0) {
        close(evicted_fd_to_close);
    }

    return SOL_OK;
}

static sol_err_t
appendvec_wait_for_inflight_map(sol_accounts_db_t* db,
                                uint64_t file_key,
                                const uint8_t** out_base,
                                uint64_t* out_size) {
    if (!db || !out_base || !out_size) return SOL_ERR_INVAL;

    const uint64_t slow_wait_ns = appendvec_map_wait_slow_threshold_ns();
    const uint64_t wait_t0 = slow_wait_ns ? accounts_db_monotonic_ns() : 0u;
    uint32_t spins = 0;
    for (;;) {
        pthread_rwlock_rdlock(&db->appendvec_lock);
        appendvec_file_t** curp =
            (appendvec_file_t**)sol_map_get(db->appendvec_files, &file_key);
        appendvec_file_t* cur = curp ? *curp : NULL;
        if (cur && cur->map && cur->map_size != 0) {
            *out_base = cur->map;
            *out_size = cur->map_size;
            pthread_rwlock_unlock(&db->appendvec_lock);
            if (wait_t0) {
                uint64_t waited_ns = accounts_db_monotonic_ns() - wait_t0;
                if (waited_ns >= slow_wait_ns) {
                    sol_log_info("appendvec_map_wait: file=%lu wait_ms=%.3f spins=%u result=ready",
                                 (unsigned long)file_key,
                                 (double)waited_ns / 1000000.0,
                                 (unsigned)spins);
                }
            }
            return SOL_OK;
        }
        bool inflight = (cur && cur->map_inflight != 0);
        pthread_rwlock_unlock(&db->appendvec_lock);

        if (!inflight) {
            if (wait_t0) {
                uint64_t waited_ns = accounts_db_monotonic_ns() - wait_t0;
                if (waited_ns >= slow_wait_ns) {
                    sol_log_info("appendvec_map_wait: file=%lu wait_ms=%.3f spins=%u result=gone",
                                 (unsigned long)file_key,
                                 (double)waited_ns / 1000000.0,
                                 (unsigned)spins);
                }
            }
            return SOL_ERR_NOTFOUND;
        }

        if (++spins < 256u) {
            sched_yield();
        } else {
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 50000 };
            nanosleep(&ts, NULL);
        }
        if (spins > 200000u) {
            if (wait_t0) {
                uint64_t waited_ns = accounts_db_monotonic_ns() - wait_t0;
                if (waited_ns >= slow_wait_ns) {
                    sol_log_warn("appendvec_map_wait: file=%lu wait_ms=%.3f spins=%u result=timeout",
                                 (unsigned long)file_key,
                                 (double)waited_ns / 1000000.0,
                                 (unsigned)spins);
                }
            }
            return SOL_ERR_TIMEOUT;
        }
    }
}

static sol_err_t
appendvec_get_map_ro(sol_accounts_db_t* db,
                     uint64_t file_key,
                     const uint8_t** out_base,
                     uint64_t* out_size) {
    if (!out_base || !out_size) return SOL_ERR_INVAL;
    *out_base = NULL;
    *out_size = 0;

    if (!db || !db->appendvec_lock_init || !db->appendvec_files) {
        return SOL_ERR_UNINITIALIZED;
    }

    int fd = -1;
    bool ephemeral = false;
    sol_err_t ferr = appendvec_get_fd(db, file_key, false, &fd, &ephemeral, NULL);
    if (ferr != SOL_OK) return ferr;
    if (fd < 0) return SOL_ERR_IO;

    if (ephemeral) {
        /* We're at the FD cache cap. Still try to mmap for fast account loads,
         * but don't keep the FD open. Store the mmap in the tracked entry so
         * subsequent loads avoid open/pread/close. */
        off_t end = lseek(fd, 0, SEEK_END);
        if (end < 0) {
            close(fd);
            return SOL_ERR_IO;
        }
        if (end == 0) {
            close(fd);
            return SOL_ERR_UNSUPPORTED;
        }
        if ((uint64_t)end > (uint64_t)SIZE_MAX) {
            close(fd);
            return SOL_ERR_TOO_LARGE;
        }
        uint64_t cur_size = (uint64_t)end;

        for (;;) {
            pthread_rwlock_wrlock(&db->appendvec_lock);
            appendvec_file_t** curp =
                (appendvec_file_t**)sol_map_get(db->appendvec_files, &file_key);
            appendvec_file_t* cur = curp ? *curp : NULL;
            if (cur && cur->map && cur->map_size != 0) {
                *out_base = cur->map;
                *out_size = cur->map_size;
                pthread_rwlock_unlock(&db->appendvec_lock);
                close(fd);
                return SOL_OK;
            }

            if (!cur) {
                appendvec_file_t* f = sol_calloc(1, sizeof(*f));
                if (!f) {
                    pthread_rwlock_unlock(&db->appendvec_lock);
                    close(fd);
                    return SOL_ERR_NOMEM;
                }
                f->fd = -1;
                f->writable = 0u;
                f->sealed = 1u;
                f->map_inflight = 0u;
                __atomic_store_n(&f->size, cur_size, __ATOMIC_RELAXED);
                f->map = NULL;
                f->map_size = 0;

                appendvec_file_t* tmp = f;
                appendvec_file_t** slot =
                    (appendvec_file_t**)sol_map_insert(db->appendvec_files, &file_key, &tmp);
                if (!slot) {
                    sol_free(f);
                    pthread_rwlock_unlock(&db->appendvec_lock);
                    close(fd);
                    return SOL_ERR_NOMEM;
                }
                cur = f;
            } else if (cur->writable) {
                pthread_rwlock_unlock(&db->appendvec_lock);
                close(fd);
                return SOL_ERR_UNSUPPORTED;
            } else if (__atomic_load_n(&cur->size, __ATOMIC_RELAXED) == 0u) {
                __atomic_store_n(&cur->size, cur_size, __ATOMIC_RELAXED);
            }
            cur_size = __atomic_load_n(&cur->size, __ATOMIC_RELAXED);

            if (cur->map_inflight) {
                pthread_rwlock_unlock(&db->appendvec_lock);
                sol_err_t werr =
                    appendvec_wait_for_inflight_map(db, file_key, out_base, out_size);
                if (werr == SOL_OK) {
                    close(fd);
                    return SOL_OK;
                }
                continue;
            }

            cur->map_inflight = 1u;
            pthread_rwlock_unlock(&db->appendvec_lock);

            size_t map_len = (size_t)cur_size;
            const uint64_t slow_map_ns = appendvec_map_slow_threshold_ns();
            uint64_t map_t0 = slow_map_ns ? accounts_db_monotonic_ns() : 0u;
            void* map = mmap(NULL, map_len, PROT_READ, MAP_SHARED, fd, 0);
            if (map_t0) {
                uint64_t map_ns = accounts_db_monotonic_ns() - map_t0;
                if (map_ns >= slow_map_ns) {
                    sol_log_info("appendvec_map_slow: file=%lu ephemeral=1 size_mb=%.2f map_ms=%.3f ok=%d",
                                 (unsigned long)file_key,
                                 (double)map_len / (1024.0 * 1024.0),
                                 (double)map_ns / 1000000.0,
                                 map != MAP_FAILED);
                }
            }

            pthread_rwlock_wrlock(&db->appendvec_lock);
            curp = (appendvec_file_t**)sol_map_get(db->appendvec_files, &file_key);
            cur = curp ? *curp : NULL;

            if (cur && cur->map && cur->map_size != 0) {
                *out_base = cur->map;
                *out_size = cur->map_size;
                if (cur->map_inflight) cur->map_inflight = 0u;
                pthread_rwlock_unlock(&db->appendvec_lock);
                if (map != MAP_FAILED) munmap(map, map_len);
                close(fd);
                return SOL_OK;
            }

            if (map != MAP_FAILED && cur && !cur->writable) {
                cur->map = (uint8_t*)map;
                cur->map_size = cur_size;
                cur->sealed = 1u;
                cur->writable = 0u;
                cur->map_inflight = 0u;
                *out_base = cur->map;
                *out_size = cur->map_size;
                pthread_rwlock_unlock(&db->appendvec_lock);
                close(fd);
                return SOL_OK;
            }

            if (cur) cur->map_inflight = 0u;
            pthread_rwlock_unlock(&db->appendvec_lock);

            if (map != MAP_FAILED) munmap(map, map_len);
            close(fd);
            return (map == MAP_FAILED) ? SOL_ERR_IO : SOL_ERR_UNSUPPORTED;
        }
    }

    close(fd);

    for (;;) {
        pthread_rwlock_rdlock(&db->appendvec_lock);
        appendvec_file_t** curp =
            (appendvec_file_t**)sol_map_get(db->appendvec_files, &file_key);
        appendvec_file_t* cur = curp ? *curp : NULL;
        if (cur && cur->map && cur->map_size != 0) {
            *out_base = cur->map;
            *out_size = cur->map_size;
            pthread_rwlock_unlock(&db->appendvec_lock);
            return SOL_OK;
        }
        pthread_rwlock_unlock(&db->appendvec_lock);

        pthread_rwlock_wrlock(&db->appendvec_lock);
        curp = (appendvec_file_t**)sol_map_get(db->appendvec_files, &file_key);
        cur = curp ? *curp : NULL;
        if (cur && cur->map && cur->map_size != 0) {
            *out_base = cur->map;
            *out_size = cur->map_size;
            pthread_rwlock_unlock(&db->appendvec_lock);
            return SOL_OK;
        }

        uint64_t cur_size = cur ? __atomic_load_n(&cur->size, __ATOMIC_RELAXED) : 0u;
        if (!cur || cur->fd < 0 || cur_size == 0 || cur->writable) {
            pthread_rwlock_unlock(&db->appendvec_lock);
            return SOL_ERR_UNSUPPORTED;
        }

        if (cur->map_inflight) {
            pthread_rwlock_unlock(&db->appendvec_lock);
            sol_err_t werr =
                appendvec_wait_for_inflight_map(db, file_key, out_base, out_size);
            if (werr == SOL_OK) return SOL_OK;
            continue;
        }

        if (cur_size > (uint64_t)SIZE_MAX) {
            pthread_rwlock_unlock(&db->appendvec_lock);
            return SOL_ERR_TOO_LARGE;
        }

        int map_fd = dup(cur->fd);
        if (map_fd < 0) {
            pthread_rwlock_unlock(&db->appendvec_lock);
            return SOL_ERR_IO;
        }
        size_t map_len = (size_t)cur_size;
        cur->map_inflight = 1u;
        pthread_rwlock_unlock(&db->appendvec_lock);

        const uint64_t slow_map_ns = appendvec_map_slow_threshold_ns();
        uint64_t map_t0 = slow_map_ns ? accounts_db_monotonic_ns() : 0u;
        void* map = mmap(NULL, map_len, PROT_READ, MAP_SHARED, map_fd, 0);
        close(map_fd);
        if (map_t0) {
            uint64_t map_ns = accounts_db_monotonic_ns() - map_t0;
            if (map_ns >= slow_map_ns) {
                sol_log_info("appendvec_map_slow: file=%lu ephemeral=0 size_mb=%.2f map_ms=%.3f ok=%d",
                             (unsigned long)file_key,
                             (double)map_len / (1024.0 * 1024.0),
                             (double)map_ns / 1000000.0,
                             map != MAP_FAILED);
            }
        }

        pthread_rwlock_wrlock(&db->appendvec_lock);
        curp = (appendvec_file_t**)sol_map_get(db->appendvec_files, &file_key);
        cur = curp ? *curp : NULL;
        if (cur && cur->map && cur->map_size != 0) {
            *out_base = cur->map;
            *out_size = cur->map_size;
            if (cur->map_inflight) cur->map_inflight = 0u;
            pthread_rwlock_unlock(&db->appendvec_lock);
            if (map != MAP_FAILED) munmap(map, map_len);
            return SOL_OK;
        }
        if (map != MAP_FAILED && cur && !cur->writable) {
            cur->map = (uint8_t*)map;
            cur->map_size = cur_size;
            cur->sealed = 1u;
            cur->writable = 0u;
            cur->map_inflight = 0u;
            *out_base = cur->map;
            *out_size = cur->map_size;
            pthread_rwlock_unlock(&db->appendvec_lock);
            return SOL_OK;
        }
        if (cur) cur->map_inflight = 0u;
        pthread_rwlock_unlock(&db->appendvec_lock);

        if (map != MAP_FAILED) munmap(map, map_len);
        return (map == MAP_FAILED) ? SOL_ERR_IO : SOL_ERR_UNSUPPORTED;
    }
}

sol_err_t
sol_accounts_db_appendvec_seal_slot(sol_accounts_db_t* db, sol_slot_t slot) {
    if (!db) return SOL_ERR_INVAL;
    if (db->config.storage_type != SOL_ACCOUNTS_STORAGE_APPENDVEC) return SOL_OK;
    if (!db->appendvec_lock_init || !db->appendvec_files) return SOL_ERR_UNINITIALIZED;

    pthread_rwlock_wrlock(&db->appendvec_lock);
    const uint64_t slot_prefix = ((uint64_t)slot) << 32;

    /* Slots may have multiple AppendVec files. Seal all contiguous ids so future
     * readers can mmap them. */
    uint32_t consecutive_misses = 0;
    for (uint32_t id = 0; id < 4096u; id++) {
        uint64_t file_key = slot_prefix | (uint64_t)id;
        appendvec_file_t** curp =
            (appendvec_file_t**)sol_map_get(db->appendvec_files, &file_key);
        appendvec_file_t* cur = curp ? *curp : NULL;
        if (!cur) {
            if (id == 0) break; /* no AppendVec for this slot */
            if (++consecutive_misses >= 4u) break;
            continue;
        }
        consecutive_misses = 0;
        cur->writable = 0u;
        cur->sealed = 1u;
    }
    pthread_rwlock_unlock(&db->appendvec_lock);

    /* Not all slots necessarily create an AppendVec file (no account deltas). */
    return SOL_OK;
}

static uint64_t
appendvec_align_up_8(uint64_t v) {
    return (v + 7u) & ~7ull;
}

static sol_err_t
appendvec_append_record_solana3(sol_accounts_db_t* db,
                                uint64_t* inout_file_key,
                                const sol_pubkey_t* pubkey,
                                const sol_account_t* account,
                                uint64_t write_version,
                                uint64_t* out_record_offset) {
    if (!db || !inout_file_key || !pubkey || !account || !out_record_offset) return SOL_ERR_INVAL;
    if (!db->appendvec_lock_init || !db->appendvec_files) return SOL_ERR_UNINITIALIZED;
    *out_record_offset = 0;

    if (account->meta.data_len > SOL_ACCOUNT_MAX_DATA_SIZE) return SOL_ERR_TOO_LARGE;
    if (account->meta.data_len > (ulong)SIZE_MAX) return SOL_ERR_TOO_LARGE;

    const uint64_t data_len = (uint64_t)account->meta.data_len;
    const uint64_t record_size = SOL_APPENDVEC_RECORD_PREFIX_SIZE + data_len;
    if (record_size < data_len) return SOL_ERR_OVERFLOW;

    uint64_t alloc_len = appendvec_align_up_8(record_size);
    if (alloc_len < record_size) return SOL_ERR_OVERFLOW;

    uint64_t file_key = *inout_file_key;
    const uint64_t slot_prefix = file_key & 0xffffffff00000000ull;

    appendvec_file_t* file = NULL;
    int fd = -1;
    bool ephemeral_fd = false;

    /* Slots can have multiple AppendVec files. If the default file is sealed
     * (common after restarts/crash recovery), fall back to the next id. */
    for (uint32_t attempt = 0; attempt < 64u; attempt++) {
        file = NULL;
        fd = -1;
        ephemeral_fd = false;

        sol_err_t ferr = appendvec_get_fd(db, file_key, true, &fd, &ephemeral_fd, &file);
        if (ferr == SOL_ERR_UNSUPPORTED) {
            uint32_t id = (uint32_t)file_key;
            if (id == UINT32_MAX) return SOL_ERR_UNSUPPORTED;
            file_key = slot_prefix | (uint64_t)(id + 1u);
            continue;
        }
        if (ferr != SOL_OK) return ferr;

        if (!file || fd < 0 || !file->writable || file->sealed) {
            if (ephemeral_fd && fd >= 0) close(fd);

            uint32_t id = (uint32_t)file_key;
            if (id == UINT32_MAX) return SOL_ERR_UNSUPPORTED;
            file_key = slot_prefix | (uint64_t)(id + 1u);
            continue;
        }

        break;
    }

    if (!file || fd < 0 || !file->writable || file->sealed) {
        if (ephemeral_fd && fd >= 0) close(fd);
        return SOL_ERR_UNSUPPORTED;
    }

    uint64_t base_off = __atomic_fetch_add(&file->size, alloc_len, __ATOMIC_RELAXED);

    uint8_t prefix[SOL_APPENDVEC_RECORD_PREFIX_SIZE];
    memset(prefix, 0, sizeof(prefix));

    memcpy(prefix + 0, &write_version, 8);
    memcpy(prefix + 8, &data_len, 8);
    memcpy(prefix + 16, pubkey->bytes, 32);

    uint64_t lamports = (uint64_t)account->meta.lamports;
    memcpy(prefix + 48, &lamports, 8);

    uint64_t rent_epoch = (uint64_t)account->meta.rent_epoch;
    memcpy(prefix + 56, &rent_epoch, 8);

    memcpy(prefix + 64, account->meta.owner.bytes, 32);

    prefix[96] = account->meta.executable ? 1u : 0u;

    uint64_t tail = base_off + record_size;
    uint64_t aligned = base_off + alloc_len;
    uint8_t zeros[8] = {0};
    size_t pad = (aligned > tail) ? (size_t)(aligned - tail) : 0;

    struct iovec iov[3];
    int iovcnt = 0;
    iov[iovcnt++] = (struct iovec){ .iov_base = prefix, .iov_len = sizeof(prefix) };
    if (data_len > 0) {
        if (!account->data) return SOL_ERR_INVAL;
        iov[iovcnt++] = (struct iovec){ .iov_base = (void*)account->data, .iov_len = (size_t)data_len };
    }
    if (pad > 0) {
        iov[iovcnt++] = (struct iovec){ .iov_base = zeros, .iov_len = pad };
    }

    sol_err_t werr = sol_io_pwritev_all(db->io_ctx, fd, iov, iovcnt, base_off);
    if (werr != SOL_OK) {
        if (ephemeral_fd && fd >= 0) close(fd);
        return werr;
    }

    *out_record_offset = base_off;
    *inout_file_key = file_key;
    if (ephemeral_fd && fd >= 0) {
        close(fd);
    }
    return SOL_OK;
}

static bool
appendvec_parse_record_header_solana3(const uint8_t* hdr,
                                      size_t hdr_len,
                                      sol_pubkey_t* out_pubkey,
                                      sol_pubkey_t* out_owner,
                                      uint64_t* out_lamports,
                                      uint64_t* out_rent_epoch,
                                      bool* out_executable,
                                      uint64_t* out_data_len,
                                      uint64_t* out_write_version) {
    if (!hdr || hdr_len < SOL_APPENDVEC_RECORD_HEADER_SIZE) return false;

    uint64_t write_version = 0;
    uint64_t data_len = 0;
    uint64_t lamports = 0;
    uint64_t rent_epoch = 0;

    memcpy(&write_version, hdr + 0, 8);
    memcpy(&data_len, hdr + 8, 8);
    if (data_len > SOL_ACCOUNT_MAX_DATA_SIZE) return false;

    if (out_pubkey) memcpy(out_pubkey->bytes, hdr + 16, 32);

    memcpy(&lamports, hdr + 48, 8);
    memcpy(&rent_epoch, hdr + 56, 8);
    if (out_owner) memcpy(out_owner->bytes, hdr + 64, 32);

    uint8_t exec = hdr[96];
    if (exec > 1) return false;

    if (out_lamports) *out_lamports = lamports;
    if (out_rent_epoch) *out_rent_epoch = rent_epoch;
    if (out_executable) *out_executable = (exec != 0);
    if (out_data_len) *out_data_len = data_len;
    if (out_write_version) *out_write_version = write_version;
    return true;
}

static bool
appendvec_parse_record_header_legacy(const uint8_t* hdr,
                                     size_t hdr_len,
                                     sol_pubkey_t* out_pubkey,
                                     sol_pubkey_t* out_owner,
                                     uint64_t* out_lamports,
                                     uint64_t* out_rent_epoch,
                                     bool* out_executable,
                                     uint64_t* out_data_len,
                                     uint64_t* out_write_version) {
    if (!hdr || hdr_len < SOL_APPENDVEC_RECORD_HEADER_SIZE) return false;

    uint64_t write_version = 0;
    uint64_t data_len = 0;
    uint64_t lamports = 0;
    uint64_t rent_epoch = 0;

    memcpy(&write_version, hdr + 0, 8);
    memcpy(&data_len, hdr + 8, 8);
    if (data_len > SOL_ACCOUNT_MAX_DATA_SIZE) return false;

    if (out_pubkey) memcpy(out_pubkey->bytes, hdr + 16, 32);
    if (out_owner) memcpy(out_owner->bytes, hdr + 48, 32);

    memcpy(&lamports, hdr + 80, 8);
    memcpy(&rent_epoch, hdr + 88, 8);

    uint8_t exec = hdr[96];
    if (exec > 1) return false;

    if (out_lamports) *out_lamports = lamports;
    if (out_rent_epoch) *out_rent_epoch = rent_epoch;
    if (out_executable) *out_executable = (exec != 0);
    if (out_data_len) *out_data_len = data_len;
    if (out_write_version) *out_write_version = write_version;
    return true;
}

static bool
appendvec_parse_record_header_solana(const uint8_t* hdr,
                                     size_t hdr_len,
                                     sol_pubkey_t* out_pubkey,
                                     sol_pubkey_t* out_owner,
                                     uint64_t* out_lamports,
                                     uint64_t* out_rent_epoch,
                                     bool* out_executable,
                                     uint64_t* out_data_len,
                                     uint64_t* out_write_version) {
    if (!hdr || hdr_len < SOL_APPENDVEC_RECORD_HEADER_SIZE) return false;

    uint64_t write_version = 0;
    uint64_t data_len = 0;
    uint64_t lamports = 0;
    uint64_t rent_epoch = 0;

    memcpy(&write_version, hdr + 0, 8);
    if (out_pubkey) memcpy(out_pubkey->bytes, hdr + 8, 32);
    memcpy(&data_len, hdr + 40, 8);
    if (data_len > SOL_ACCOUNT_MAX_DATA_SIZE) return false;

    memcpy(&lamports, hdr + 48, 8);
    if (out_owner) memcpy(out_owner->bytes, hdr + 56, 32);

    uint8_t exec = hdr[88];
    if (exec > 1) return false;

    memcpy(&rent_epoch, hdr + 96, 8);

    if (out_lamports) *out_lamports = lamports;
    if (out_rent_epoch) *out_rent_epoch = rent_epoch;
    if (out_executable) *out_executable = (exec != 0);
    if (out_data_len) *out_data_len = data_len;
    if (out_write_version) *out_write_version = write_version;
    return true;
}

static bool
appendvec_parse_record_header_solana2(const uint8_t* hdr,
                                      size_t hdr_len,
                                      sol_pubkey_t* out_pubkey,
                                      sol_pubkey_t* out_owner,
                                      uint64_t* out_lamports,
                                      uint64_t* out_rent_epoch,
                                      bool* out_executable,
                                      uint64_t* out_data_len,
                                      uint64_t* out_write_version) {
    if (!hdr || hdr_len < SOL_APPENDVEC_RECORD_HEADER_SIZE) return false;

    uint64_t write_version = 0;
    uint64_t data_len = 0;
    uint64_t lamports = 0;
    uint64_t rent_epoch = 0;

    memcpy(&write_version, hdr + 0, 8);
    memcpy(&data_len, hdr + 8, 8);
    if (data_len > SOL_ACCOUNT_MAX_DATA_SIZE) return false;

    if (out_pubkey) memcpy(out_pubkey->bytes, hdr + 16, 32);

    memcpy(&lamports, hdr + 48, 8);
    if (out_owner) memcpy(out_owner->bytes, hdr + 56, 32);

    uint8_t exec = hdr[88];
    if (exec > 1) return false;

    memcpy(&rent_epoch, hdr + 96, 8);

    if (out_lamports) *out_lamports = lamports;
    if (out_rent_epoch) *out_rent_epoch = rent_epoch;
    if (out_executable) *out_executable = (exec != 0);
    if (out_data_len) *out_data_len = data_len;
    if (out_write_version) *out_write_version = write_version;
    return true;
}

typedef enum {
    APPENDVEC_LAYOUT_SOLANA3 = 0,
    APPENDVEC_LAYOUT_SOLANA2 = 1,
    APPENDVEC_LAYOUT_SOLANA  = 2,
    APPENDVEC_LAYOUT_LEGACY  = 3,
} appendvec_record_layout_t;

static bool
appendvec_parse_record_header_any(const uint8_t* hdr,
                                  size_t hdr_len,
                                  const sol_pubkey_t* expected_pubkey,
                                  sol_pubkey_t* out_owner,
                                  uint64_t* out_lamports,
                                  uint64_t* out_rent_epoch,
                                  bool* out_executable,
                                  uint64_t* out_data_len,
                                  uint64_t* out_write_version,
                                  appendvec_record_layout_t* out_layout) {
    if (!hdr || hdr_len < SOL_APPENDVEC_RECORD_HEADER_SIZE || !expected_pubkey) {
        return false;
    }

    sol_pubkey_t pubkey = {0};
    sol_pubkey_t owner = {0};
    uint64_t lamports = 0;
    uint64_t rent_epoch = 0;
    bool executable = false;
    uint64_t data_len = 0;
    uint64_t write_version = 0;

    struct {
        appendvec_record_layout_t layout;
        bool (*parse)(const uint8_t*,
                      size_t,
                      sol_pubkey_t*,
                      sol_pubkey_t*,
                      uint64_t*,
                      uint64_t*,
                      bool*,
                      uint64_t*,
                      uint64_t*);
    } candidates[] = {
        {APPENDVEC_LAYOUT_SOLANA3, appendvec_parse_record_header_solana3},
        {APPENDVEC_LAYOUT_SOLANA2, appendvec_parse_record_header_solana2},
        {APPENDVEC_LAYOUT_SOLANA, appendvec_parse_record_header_solana},
        {APPENDVEC_LAYOUT_LEGACY, appendvec_parse_record_header_legacy},
    };

    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        pubkey = (sol_pubkey_t){0};
        owner = (sol_pubkey_t){0};
        lamports = 0;
        rent_epoch = 0;
        executable = false;
        data_len = 0;
        write_version = 0;

        if (!candidates[i].parse(hdr,
                                 hdr_len,
                                 &pubkey,
                                 &owner,
                                 &lamports,
                                 &rent_epoch,
                                 &executable,
                                 &data_len,
                                 &write_version)) {
            continue;
        }

        if (!sol_pubkey_eq(&pubkey, expected_pubkey)) {
            continue;
        }

        if (out_owner) *out_owner = owner;
        if (out_lamports) *out_lamports = lamports;
        if (out_rent_epoch) *out_rent_epoch = rent_epoch;
        if (out_executable) *out_executable = executable;
        if (out_data_len) *out_data_len = data_len;
        if (out_write_version) *out_write_version = write_version;
        if (out_layout) *out_layout = candidates[i].layout;
        return true;
    }

    return false;
}

static sol_err_t
appendvec_load_account_by_ref(sol_accounts_db_t* db,
                              const sol_pubkey_t* expected_pubkey,
                              const sol_accountsdb_appendvec_ref_v1_t* ref,
                              sol_account_t** out_account) {
    if (!db || !expected_pubkey || !ref || !out_account) return SOL_ERR_INVAL;
    *out_account = NULL;

    if (sol_hash_is_zero(&ref->account_hash)) {
        return SOL_ERR_NOTFOUND;
    }

    int fd = -1;
    bool ephemeral = false;
    sol_err_t ferr = appendvec_get_fd(db, ref->file_key, false, &fd, &ephemeral, NULL);
    if (ferr != SOL_OK) return ferr;
    if (fd < 0) return SOL_ERR_IO;

    sol_err_t ret = SOL_OK;

    uint8_t hdr[SOL_APPENDVEC_RECORD_HEADER_SIZE];
    sol_err_t herr = sol_io_pread_all(db->io_ctx, fd, hdr, sizeof(hdr), ref->record_offset);
    if (herr != SOL_OK) {
        ret = herr;
        goto cleanup;
    }

    sol_pubkey_t owner = {0};
    uint64_t lamports = 0;
    uint64_t rent_epoch = 0;
    bool executable = false;
    uint64_t data_len_u64 = 0;
    appendvec_record_layout_t layout = APPENDVEC_LAYOUT_SOLANA3;
    if (!appendvec_parse_record_header_any(hdr, sizeof(hdr),
                                           expected_pubkey,
                                           &owner,
                                           &lamports,
                                           &rent_epoch,
                                           &executable,
                                           &data_len_u64,
                                           NULL,
                                           &layout)) {
        ret = SOL_ERR_SNAPSHOT_CORRUPT;
        goto cleanup;
    }

    if (data_len_u64 > (uint64_t)SIZE_MAX) {
        ret = SOL_ERR_TOO_LARGE;
        goto cleanup;
    }
    size_t data_len = (size_t)data_len_u64;

    uint64_t data_offset = 0;
    if (__builtin_add_overflow(ref->record_offset, (uint64_t)SOL_APPENDVEC_RECORD_PREFIX_SIZE, &data_offset)) {
        ret = SOL_ERR_OVERFLOW;
        goto cleanup;
    }

    sol_account_t* account = sol_account_alloc();
    if (!account) {
        ret = SOL_ERR_NOMEM;
        goto cleanup;
    }

    account->meta.lamports = lamports;
    account->meta.data_len = (ulong)data_len;
    account->meta.owner = owner;
    account->meta.executable = executable;
    account->meta.rent_epoch = (sol_epoch_t)rent_epoch;

    if (data_len > 0) {
        account->data = sol_alloc(data_len);
        if (!account->data) {
            sol_account_destroy(account);
            ret = SOL_ERR_NOMEM;
            goto cleanup;
        }

        sol_err_t derr = sol_io_pread_all(db->io_ctx, fd, account->data, data_len, data_offset);
        if (derr == SOL_ERR_TRUNCATED) {
            /* Some storages omit the 32-byte metadata suffix. Retry assuming a
             * tight header layout before failing the load. */
            uint64_t alt_offset = 0;
            if (!__builtin_add_overflow(ref->record_offset,
                                        (uint64_t)SOL_APPENDVEC_RECORD_HEADER_SIZE,
                                        &alt_offset)) {
                sol_err_t derr2 = sol_io_pread_all(db->io_ctx, fd, account->data, data_len, alt_offset);
                if (derr2 == SOL_OK) {
                    data_offset = alt_offset;
                } else {
                    sol_account_destroy(account);
                    ret = SOL_ERR_TRUNCATED;
                    goto cleanup;
                }
            } else {
                sol_account_destroy(account);
                ret = SOL_ERR_OVERFLOW;
                goto cleanup;
            }
        } else if (derr != SOL_OK) {
            sol_account_destroy(account);
            ret = derr;
            goto cleanup;
        }
    }

    if (account->meta.lamports == 0) {
        sol_account_destroy(account);
        ret = SOL_ERR_NOTFOUND;
        goto cleanup;
    }

    *out_account = account;
    ret = SOL_OK;

cleanup:
    if (ephemeral && fd >= 0) {
        close(fd);
    }
    return ret;
}

static sol_err_t
appendvec_load_account_view_by_ref(sol_accounts_db_t* db,
                                   const sol_pubkey_t* expected_pubkey,
                                   const sol_accountsdb_appendvec_ref_v1_t* ref,
                                   sol_account_t** out_account) {
    if (!db || !expected_pubkey || !ref || !out_account) return SOL_ERR_INVAL;
    *out_account = NULL;

    if (sol_hash_is_zero(&ref->account_hash)) {
        return SOL_ERR_NOTFOUND;
    }

    const uint8_t* base = NULL;
    uint64_t map_size = 0;
    sol_err_t merr = appendvec_get_map_ro(db, ref->file_key, &base, &map_size);
    if (merr != SOL_OK || !base || map_size == 0) {
        /* Fallback to the owned/copying load path. */
        return appendvec_load_account_by_ref(db, expected_pubkey, ref, out_account);
    }

    if (ref->record_offset > map_size ||
        map_size - ref->record_offset < (uint64_t)SOL_APPENDVEC_RECORD_HEADER_SIZE) {
        return SOL_ERR_TRUNCATED;
    }

    const uint8_t* hdr = base + ref->record_offset;

    sol_pubkey_t owner = {0};
    uint64_t lamports = 0;
    uint64_t rent_epoch = 0;
    bool executable = false;
    uint64_t data_len_u64 = 0;
    appendvec_record_layout_t layout = APPENDVEC_LAYOUT_SOLANA3;
    if (!appendvec_parse_record_header_any(hdr,
                                           SOL_APPENDVEC_RECORD_HEADER_SIZE,
                                           expected_pubkey,
                                           &owner,
                                           &lamports,
                                           &rent_epoch,
                                           &executable,
                                           &data_len_u64,
                                           NULL,
                                           &layout)) {
        return SOL_ERR_SNAPSHOT_CORRUPT;
    }

    if (lamports == 0) {
        return SOL_ERR_NOTFOUND;
    }

    if (data_len_u64 > (uint64_t)SIZE_MAX) return SOL_ERR_TOO_LARGE;
    size_t data_len = (size_t)data_len_u64;

    uint64_t data_offset = 0;
    if (__builtin_add_overflow(ref->record_offset,
                               (uint64_t)SOL_APPENDVEC_RECORD_PREFIX_SIZE,
                               &data_offset)) {
        return SOL_ERR_OVERFLOW;
    }

    if (data_offset > map_size ||
        (uint64_t)data_len > map_size - data_offset) {
        return SOL_ERR_TRUNCATED;
    }

    sol_account_t* account = sol_account_alloc();
    if (!account) return SOL_ERR_NOMEM;

    account->meta.lamports = lamports;
    account->meta.data_len = (ulong)data_len;
    account->meta.owner = owner;
    account->meta.executable = executable;
    account->meta.rent_epoch = (sol_epoch_t)rent_epoch;
    account->data = (data_len > 0) ? (uchar*)(base + data_offset) : NULL;
    account->data_borrowed = true;

    *out_account = account;
    return SOL_OK;
}

static sol_err_t
appendvec_load_account_meta_by_ref(sol_accounts_db_t* db,
                                   const sol_pubkey_t* expected_pubkey,
                                   const sol_accountsdb_appendvec_ref_v1_t* ref,
                                   uint64_t* out_lamports,
                                   uint64_t* out_data_len,
                                   uint64_t* out_rent_epoch) {
    if (out_lamports) *out_lamports = 0;
    if (out_data_len) *out_data_len = 0;
    if (out_rent_epoch) *out_rent_epoch = 0;
    if (!db || !expected_pubkey || !ref) return SOL_ERR_INVAL;

    if (sol_hash_is_zero(&ref->account_hash)) {
        return SOL_ERR_NOTFOUND;
    }

    int fd = -1;
    bool ephemeral = false;
    sol_err_t ferr = appendvec_get_fd(db, ref->file_key, false, &fd, &ephemeral, NULL);
    if (ferr != SOL_OK) return ferr;
    if (fd < 0) return SOL_ERR_IO;

    sol_err_t ret = SOL_OK;

    uint8_t hdr[SOL_APPENDVEC_RECORD_HEADER_SIZE];
    sol_err_t herr = sol_io_pread_all(db->io_ctx, fd, hdr, sizeof(hdr), ref->record_offset);
    if (herr != SOL_OK) {
        ret = herr;
        goto cleanup;
    }

    uint64_t lamports = 0;
    uint64_t data_len_u64 = 0;
    uint64_t rent_epoch = 0;
    if (!appendvec_parse_record_header_any(hdr, sizeof(hdr),
                                           expected_pubkey,
                                           NULL,
                                           &lamports,
                                           &rent_epoch,
                                           NULL,
                                           &data_len_u64,
                                           NULL,
                                           NULL)) {
        ret = SOL_ERR_SNAPSHOT_CORRUPT;
        goto cleanup;
    }

    if (lamports == 0) {
        ret = SOL_ERR_NOTFOUND;
        goto cleanup;
    }

    if (out_lamports) *out_lamports = lamports;
    if (out_data_len) *out_data_len = data_len_u64;
    if (out_rent_epoch) *out_rent_epoch = rent_epoch;
    ret = SOL_OK;

cleanup:
    if (ephemeral && fd >= 0) {
        close(fd);
    }
    return ret;
}

static bool
parse_serialized_account_meta(const uint8_t* data,
                              size_t len,
                              uint64_t* out_lamports,
                              uint64_t* out_data_len) {
    if (!data || len < 16) return false;
    uint64_t lamports = 0;
    uint64_t data_len = 0;
    memcpy(&lamports, data + 0, 8);
    memcpy(&data_len, data + 8, 8);
    if (out_lamports) *out_lamports = lamports;
    if (out_data_len) *out_data_len = data_len;
    return true;
}

static bool
parse_serialized_account_owner(const uint8_t* data,
                               size_t len,
                               sol_pubkey_t* out_owner) {
    if (!data || !out_owner || len < 16) return false;

    uint64_t data_len_u64 = 0;
    memcpy(&data_len_u64, data + 8, 8);
    if (data_len_u64 > SOL_ACCOUNT_MAX_DATA_SIZE) return false;

    size_t data_len = (size_t)data_len_u64;
    size_t off = 16 + data_len;
    if (off + 32 > len) return false;

    memcpy(out_owner->bytes, data + off, 32);
    return true;
}

static void
owner_index_key(const sol_pubkey_t* owner,
                const sol_pubkey_t* pubkey,
                uint8_t out_key[64]) {
    memcpy(out_key, owner->bytes, 32);
    memcpy(out_key + 32, pubkey->bytes, 32);
}

static sol_err_t
owner_index_put(sol_storage_backend_t* backend,
                const sol_pubkey_t* owner,
                const sol_pubkey_t* pubkey) {
    if (!backend || !owner || !pubkey) return SOL_ERR_INVAL;
    uint8_t key[64];
    owner_index_key(owner, pubkey, key);
    static const uint8_t v = 0;
    return backend->put(backend->ctx, key, sizeof(key), &v, sizeof(v));
}

static sol_err_t
owner_index_del(sol_storage_backend_t* backend,
                const sol_pubkey_t* owner,
                const sol_pubkey_t* pubkey) {
    if (!backend || !owner || !pubkey) return SOL_ERR_INVAL;
    uint8_t key[64];
    owner_index_key(owner, pubkey, key);
    return backend->del(backend->ctx, key, sizeof(key));
}

static const uint8_t OWNER_INDEX_META_KEY[] = OWNER_INDEX_META_KEY_STR;
static const uint8_t OWNER_REVERSE_META_KEY[] = OWNER_REVERSE_META_KEY_STR;
static const uint8_t ACCOUNTS_STATS_META_KEY[] = "__meta_accounts_stats_v1";
static const uint8_t BOOTSTRAP_STATE_META_KEY[] = "__meta_bootstrap_state_v1";
static const uint8_t BOOTSTRAP_BLOCKHASH_QUEUE_META_KEY[] = "__meta_bootstrap_blockhash_queue_v1";
static const uint8_t OWNER_INDEX_CORE_META_KEY[] = OWNER_INDEX_CORE_META_KEY_STR;

#define BOOTSTRAP_STATE_MAGIC   0x534f4c42u /* 'SOLB' */
#define BOOTSTRAP_STATE_VERSION_V1 1u
#define BOOTSTRAP_STATE_VERSION_V2 2u
#define BOOTSTRAP_STATE_VERSION_V3 3u
#define BOOTSTRAP_STATE_LEN_V1     2216u
#define BOOTSTRAP_STATE_LEN_V2     (BOOTSTRAP_STATE_LEN_V1 + 8u)
#define BOOTSTRAP_STATE_LEN_V3     (BOOTSTRAP_STATE_LEN_V2 + 40u)

#define BOOTSTRAP_BLOCKHASH_QUEUE_MAGIC 0x51484c42u /* 'BLHQ' */
#define BOOTSTRAP_BLOCKHASH_QUEUE_VERSION_V1 1u

typedef struct {
    uint64_t    lamports;
    uint64_t    data_len;
    sol_pubkey_t owner;
} owner_reverse_value_t;

static bool
owner_reverse_decode(const uint8_t* value,
                     size_t value_len,
                     owner_reverse_value_t* out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!value) return false;

    /* Bulk snapshot ingestion may store reverse values with the same versioned
     * header used by the main accounts values so writes remain order-independent
     * when using RocksDB Merge. Strip the header when present. */
    if (value_len >= sizeof(sol_accountsdb_value_header_t)) {
        sol_accountsdb_value_header_t hdr;
        memcpy(&hdr, value, sizeof(hdr));
        if (hdr.magic == SOL_ACCOUNTSDB_VALUE_MAGIC) {
            value += sizeof(hdr);
            value_len -= sizeof(hdr);
        }
    }

    if (value_len == 32) {
        /* Backward-compatible format: just owner bytes. */
        out->lamports = ~(uint64_t)0;
        out->data_len = ~(uint64_t)0;
        memcpy(out->owner.bytes, value, 32);
        return true;
    }

    if (value_len != 48) {
        return false;
    }

    memcpy(&out->lamports, value + 0, 8);
    memcpy(&out->data_len, value + 8, 8);
    memcpy(out->owner.bytes, value + 16, 32);
    return true;
}

static sol_err_t
owner_reverse_get(sol_storage_backend_t* backend,
                  const sol_pubkey_t* pubkey,
                  owner_reverse_value_t* out,
                  bool* out_found) {
    if (out_found) *out_found = false;
    if (!backend || !pubkey || !out) return SOL_ERR_INVAL;

    uint8_t* value = NULL;
    size_t value_len = 0;
    sol_err_t err = backend->get(backend->ctx,
                                 pubkey->bytes, sizeof(pubkey->bytes),
                                 &value, &value_len);
    if (err == SOL_ERR_NOTFOUND) {
        return SOL_OK;
    }
    if (err != SOL_OK) {
        return err;
    }

    bool ok = owner_reverse_decode(value, value_len, out);
    sol_free(value);
    if (!ok) {
        return SOL_ERR_TRUNCATED;
    }
    if (out_found) *out_found = true;
    return SOL_OK;
}

static sol_err_t
owner_reverse_put(sol_storage_backend_t* backend,
                  const sol_pubkey_t* pubkey,
                  const owner_reverse_value_t* val) {
    if (!backend || !pubkey || !val) return SOL_ERR_INVAL;

    uint8_t out[48];
    memcpy(out + 0, &val->lamports, 8);
    memcpy(out + 8, &val->data_len, 8);
    memcpy(out + 16, val->owner.bytes, 32);

    return backend->put(backend->ctx,
                        pubkey->bytes, sizeof(pubkey->bytes),
                        out, sizeof(out));
}

static sol_err_t
owner_reverse_del(sol_storage_backend_t* backend,
                  const sol_pubkey_t* pubkey) {
    if (!backend || !pubkey) return SOL_ERR_INVAL;
    return backend->del(backend->ctx, pubkey->bytes, sizeof(pubkey->bytes));
}

typedef struct {
    bool     found;      /* local layer has a non-tombstone account */
    bool     local_miss; /* local layer missing and should consult parent */
    uint64_t lamports;
    uint64_t data_len;
} accounts_db_meta_lookup_t;

static void
accounts_db_lookup_meta_local(sol_accounts_db_t* db,
                              const sol_pubkey_t* pubkey,
                              accounts_db_meta_lookup_t* out) {
    if (!out) return;
    out->found = false;
    out->local_miss = true;
    out->lamports = 0;
    out->data_len = 0;
    if (!db || !pubkey) return;

    /* Backend lookup */
    if (db->backend) {
        uint8_t* value = NULL;
        size_t value_len = 0;
        sol_err_t err = db->backend->get(db->backend->ctx,
                                         pubkey->bytes, sizeof(pubkey->bytes),
                                         &value, &value_len);
        if (err != SOL_OK || !value) {
            if (value) sol_free(value);
            out->local_miss = true;
            return;
        }

        out->local_miss = false;

        const uint8_t* payload = NULL;
        size_t payload_len = 0;
        decode_backend_value(value, value_len, NULL, NULL, &payload, &payload_len);

        if (db->config.storage_type == SOL_ACCOUNTS_STORAGE_APPENDVEC) {
            sol_accountsdb_appendvec_ref_v1_t ref = {0};
            if (!appendvec_ref_decode(payload, payload_len, &ref)) {
                /* Corrupt entry; treat as a miss so parents can satisfy the lookup. */
                out->local_miss = true;
                sol_free(value);
                return;
            }

            if (sol_hash_is_zero(&ref.account_hash)) {
                /* Tombstone/delete hides any parent. */
                out->found = false;
                out->local_miss = false;
                sol_free(value);
                return;
            }

            /* Prefer owner_reverse metadata when available (no AppendVec IO). */
            if (db->owner_reverse_backend) {
                owner_reverse_value_t rev = {0};
                bool rev_found = false;
                sol_err_t rerr = owner_reverse_get(db->owner_reverse_backend, pubkey, &rev, &rev_found);
                if (rerr == SOL_OK && rev_found &&
                    rev.lamports != ~(uint64_t)0 &&
                    rev.data_len != ~(uint64_t)0) {
                    if (rev.lamports == 0) {
                        /* Tombstone/delete hides any parent. */
                        out->found = false;
                        out->local_miss = false;
                        sol_free(value);
                        return;
                    }
                    out->found = true;
                    out->lamports = rev.lamports;
                    out->data_len = rev.data_len;
                    sol_free(value);
                    return;
                }
                /* If reverse is missing/old-format, fall back to reading record header. */
            }

            uint64_t lamports = 0;
            uint64_t data_len = 0;
            sol_err_t merr = appendvec_load_account_meta_by_ref(db, pubkey, &ref, &lamports, &data_len, NULL);
            if (merr == SOL_OK) {
                out->found = true;
                out->lamports = lamports;
                out->data_len = data_len;
            } else if (merr == SOL_ERR_NOTFOUND) {
                /* Treat as a tombstone/delete. */
                out->found = false;
                out->local_miss = false;
            } else {
                /* IO/corruption: allow parent fallback. */
                out->found = false;
                out->local_miss = true;
            }

            sol_free(value);
            return;
        }

        uint64_t lamports = 0;
        uint64_t data_len = 0;
        bool ok = parse_serialized_account_meta(payload, payload_len, &lamports, &data_len);
        sol_free(value);
        if (!ok) {
            out->local_miss = true;
            return;
        }
        if (lamports == 0) {
            /* Tombstone/delete hides any parent. */
            out->found = false;
            out->local_miss = false;
            return;
        }
        out->found = true;
        out->lamports = lamports;
        out->data_len = data_len;
        return;
    }

    /* In-memory lookup */
    pthread_rwlock_rdlock(&db->lock);
    size_t idx = pubkey_hash(pubkey, db->bucket_count);
    size_t stripe = stripe_for_bucket(db, idx);
    if (db->stripe_locks) {
        pthread_rwlock_rdlock(&db->stripe_locks[stripe]);
    }

    sol_account_entry_t* entry = find_entry(db->buckets[idx], pubkey);
    if (!entry) {
        out->local_miss = true;
        out->found = false;
    } else {
        out->local_miss = false;
        if (entry->account) {
            out->found = true;
            out->lamports = entry->account->meta.lamports;
            out->data_len = entry->account->meta.data_len;
        } else {
            out->found = false; /* tombstone */
        }
    }

    if (db->stripe_locks) {
        pthread_rwlock_unlock(&db->stripe_locks[stripe]);
    }
    pthread_rwlock_unlock(&db->lock);
}

static bool
accounts_db_lookup_meta_visible(sol_accounts_db_t* db,
                                const sol_pubkey_t* pubkey,
                                uint64_t* out_lamports,
                                uint64_t* out_data_len) {
    if (out_lamports) *out_lamports = 0;
    if (out_data_len) *out_data_len = 0;
    if (!db || !pubkey) return false;

    accounts_db_meta_lookup_t m = {0};
    accounts_db_lookup_meta_local(db, pubkey, &m);

    if (m.found) {
        if (out_lamports) *out_lamports = m.lamports;
        if (out_data_len) *out_data_len = m.data_len;
        return true;
    }

    if (m.local_miss && db->parent) {
        return accounts_db_lookup_meta_visible(db->parent, pubkey, out_lamports, out_data_len);
    }

    return false;
}

typedef struct {
    bool     found;      /* local layer has a non-tombstone account */
    bool     local_miss; /* local layer missing and should consult parent */
    uint64_t lamports;
    uint64_t data_len;
    uint64_t rent_epoch;
} accounts_db_rent_meta_lookup_t;

static sol_err_t
accounts_db_lookup_rent_meta_local(sol_accounts_db_t* db,
                                   const sol_pubkey_t* pubkey,
                                   accounts_db_rent_meta_lookup_t* out) {
    if (!out) return SOL_ERR_INVAL;
    out->found = false;
    out->local_miss = true;
    out->lamports = 0;
    out->data_len = 0;
    out->rent_epoch = 0;
    if (!db || !pubkey) return SOL_OK;

    if (db->backend) {
        if (db->config.storage_type == SOL_ACCOUNTS_STORAGE_APPENDVEC &&
            db->appendvec_index) {
            sol_appendvec_index_val_t v = {0};
            if (sol_appendvec_index_get(db->appendvec_index, pubkey, &v)) {
                out->local_miss = false;
                if (v.lamports == 0 || sol_hash_is_zero(&v.leaf_hash)) {
                    out->found = false;
                    return SOL_OK;
                }
                sol_accountsdb_appendvec_ref_v1_t ref = {
                    .file_key = v.file_key,
                    .record_offset = v.record_offset,
                    .account_hash = v.leaf_hash,
                };
                uint64_t lamports = 0;
                uint64_t data_len = 0;
                uint64_t rent_epoch = 0;
                sol_err_t merr = appendvec_load_account_meta_by_ref(db,
                                                                    pubkey,
                                                                    &ref,
                                                                    &lamports,
                                                                    &data_len,
                                                                    &rent_epoch);
                if (merr == SOL_OK) {
                    out->found = true;
                    out->lamports = lamports;
                    out->data_len = data_len;
                    out->rent_epoch = rent_epoch;
                    return SOL_OK;
                }
                if (merr == SOL_ERR_NOTFOUND) {
                    out->found = false;
                    return SOL_OK;
                }
                return merr;
            }
        }

        uint8_t* value = NULL;
        size_t value_len = 0;
        sol_err_t err = db->backend->get(db->backend->ctx,
                                         pubkey->bytes,
                                         sizeof(pubkey->bytes),
                                         &value,
                                         &value_len);
        if (err != SOL_OK || !value) {
            if (value) sol_free(value);
            out->local_miss = true;
            return SOL_OK;
        }

        out->local_miss = false;
        const uint8_t* payload = NULL;
        size_t payload_len = 0;
        decode_backend_value(value,
                             value_len,
                             NULL,
                             NULL,
                             &payload,
                             &payload_len);

        if (db->config.storage_type == SOL_ACCOUNTS_STORAGE_APPENDVEC) {
            sol_accountsdb_appendvec_ref_v1_t ref = {0};
            if (!appendvec_ref_decode(payload, payload_len, &ref)) {
                sol_free(value);
                return SOL_ERR_TRUNCATED;
            }
            if (sol_hash_is_zero(&ref.account_hash)) {
                out->found = false;
                sol_free(value);
                return SOL_OK;
            }

            uint64_t lamports = 0;
            uint64_t data_len = 0;
            uint64_t rent_epoch = 0;
            sol_err_t merr = appendvec_load_account_meta_by_ref(db,
                                                                pubkey,
                                                                &ref,
                                                                &lamports,
                                                                &data_len,
                                                                &rent_epoch);
            sol_free(value);
            if (merr == SOL_OK) {
                out->found = true;
                out->lamports = lamports;
                out->data_len = data_len;
                out->rent_epoch = rent_epoch;
                return SOL_OK;
            }
            if (merr == SOL_ERR_NOTFOUND) {
                out->found = false;
                return SOL_OK;
            }
            return merr;
        }

        sol_account_t* account = sol_account_alloc();
        if (!account) {
            sol_free(value);
            return SOL_ERR_NOMEM;
        }
        size_t consumed = 0;
        sol_err_t derr = sol_account_deserialize(account, payload, payload_len, &consumed);
        sol_free(value);
        if (derr != SOL_OK) {
            sol_account_destroy(account);
            return derr;
        }
        if (account->meta.lamports == 0) {
            sol_account_destroy(account);
            out->found = false;
            return SOL_OK;
        }
        out->found = true;
        out->lamports = account->meta.lamports;
        out->data_len = account->meta.data_len;
        out->rent_epoch = (uint64_t)account->meta.rent_epoch;
        sol_account_destroy(account);
        return SOL_OK;
    }

    pthread_rwlock_rdlock(&db->lock);
    size_t idx = pubkey_hash(pubkey, db->bucket_count);
    size_t stripe = stripe_for_bucket(db, idx);
    if (db->stripe_locks) {
        pthread_rwlock_rdlock(&db->stripe_locks[stripe]);
    }

    sol_account_entry_t* entry = find_entry(db->buckets[idx], pubkey);
    if (!entry) {
        out->local_miss = true;
        out->found = false;
    } else {
        out->local_miss = false;
        if (entry->account) {
            out->found = true;
            out->lamports = entry->account->meta.lamports;
            out->data_len = entry->account->meta.data_len;
            out->rent_epoch = (uint64_t)entry->account->meta.rent_epoch;
        } else {
            out->found = false;
        }
    }

    if (db->stripe_locks) {
        pthread_rwlock_unlock(&db->stripe_locks[stripe]);
    }
    pthread_rwlock_unlock(&db->lock);
    return SOL_OK;
}

sol_err_t
sol_accounts_db_lookup_visible_rent_meta(sol_accounts_db_t* db,
                                         const sol_pubkey_t* pubkey,
                                         bool* out_found,
                                         uint64_t* out_lamports,
                                         uint64_t* out_data_len,
                                         uint64_t* out_rent_epoch) {
    if (out_found) *out_found = false;
    if (out_lamports) *out_lamports = 0;
    if (out_data_len) *out_data_len = 0;
    if (out_rent_epoch) *out_rent_epoch = 0;
    if (!db || !pubkey) return SOL_ERR_INVAL;

    accounts_db_rent_meta_lookup_t m = {0};
    sol_err_t err = accounts_db_lookup_rent_meta_local(db, pubkey, &m);
    if (err != SOL_OK) return err;

    if (m.found) {
        if (out_found) *out_found = true;
        if (out_lamports) *out_lamports = m.lamports;
        if (out_data_len) *out_data_len = m.data_len;
        if (out_rent_epoch) *out_rent_epoch = m.rent_epoch;
        return SOL_OK;
    }

    if (m.local_miss && db->parent) {
        return sol_accounts_db_lookup_visible_rent_meta(db->parent,
                                                        pubkey,
                                                        out_found,
                                                        out_lamports,
                                                        out_data_len,
                                                        out_rent_epoch);
    }

    if (out_found) *out_found = false;
    return SOL_OK;
}

sol_accounts_db_t*
sol_accounts_db_new(const sol_accounts_db_config_t* config) {
    sol_accounts_db_t* db = sol_calloc(1, sizeof(sol_accounts_db_t));
    if (!db) return NULL;

    db->instance_id = __atomic_fetch_add(&g_accounts_db_id_gen, 1, __ATOMIC_RELAXED);

    if (config) {
        db->config = *config;
    } else {
        db->config = (sol_accounts_db_config_t)SOL_ACCOUNTS_DB_CONFIG_DEFAULT;
    }

    /* Root advancement needs to take writer locks on overlay AccountsDB views.
     * Under sustained read load, the default rwlock kind can starve writers and
     * stall the validator main loop. Prefer writers on glibc/Linux to ensure
     * root advancement makes forward progress. */
    pthread_rwlockattr_t lock_attr;
    pthread_rwlockattr_t* lock_attr_p = NULL;
    if (pthread_rwlockattr_init(&lock_attr) == 0) {
#if defined(SOL_OS_LINUX) && defined(__GLIBC__) && defined(PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP)
        (void)pthread_rwlockattr_setkind_np(&lock_attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
#endif
        lock_attr_p = &lock_attr;
    }

    if (pthread_rwlock_init(&db->lock, lock_attr_p) != 0) {
        if (lock_attr_p) {
            (void)pthread_rwlockattr_destroy(&lock_attr);
        }
        sol_free(db);
        return NULL;
    }
    if (lock_attr_p) {
        (void)pthread_rwlockattr_destroy(&lock_attr);
    }

    db->parent = NULL;

    /* Initialize storage backend based on configuration */
    if (db->config.storage_type == SOL_ACCOUNTS_STORAGE_ROCKSDB ||
        db->config.storage_type == SOL_ACCOUNTS_STORAGE_APPENDVEC) {
#ifdef SOL_HAS_ROCKSDB
        if (db->config.storage_type == SOL_ACCOUNTS_STORAGE_APPENDVEC) {
            if (!db->config.appendvec_path || db->config.appendvec_path[0] == '\0') {
                sol_log_error("AppendVec AccountsDB requires appendvec_path; falling back to RocksDB account storage");
                db->config.storage_type = SOL_ACCOUNTS_STORAGE_ROCKSDB;
            }
        }

        /* Create RocksDB backend */
        sol_rocksdb_config_t rocksdb_config = SOL_ROCKSDB_CONFIG_DEFAULT;
        if (db->config.rocksdb_path) {
            rocksdb_config.path = db->config.rocksdb_path;
        }
        if (db->config.rocksdb_cache_mb > 0) {
            rocksdb_config.block_cache_mb = db->config.rocksdb_cache_mb;
        }

        db->rocksdb = sol_rocksdb_new(&rocksdb_config);
        if (!db->rocksdb) {
            sol_log_error("Failed to create RocksDB instance");
            pthread_rwlock_destroy(&db->lock);
            sol_free(db);
            return NULL;
        }

        const char* accounts_cf =
            (db->config.storage_type == SOL_ACCOUNTS_STORAGE_APPENDVEC)
                ? SOL_ROCKSDB_CF_ACCOUNTS_INDEX
                : SOL_ROCKSDB_CF_ACCOUNTS;

        /* Open accounts column family */
        sol_err_t err = sol_rocksdb_open_cf(db->rocksdb, accounts_cf);
        if (err != SOL_OK) {
            sol_log_error("Failed to open accounts column family");
            sol_rocksdb_destroy(db->rocksdb);
            pthread_rwlock_destroy(&db->lock);
            sol_free(db);
            return NULL;
        }

        db->backend = sol_rocksdb_get_backend(db->rocksdb, accounts_cf);
        if (!db->backend) {
            sol_log_error("Failed to get accounts storage backend");
            sol_rocksdb_destroy(db->rocksdb);
            pthread_rwlock_destroy(&db->lock);
            sol_free(db);
            return NULL;
        }

        /* Open owner index column family for efficient program account queries. */
        err = sol_rocksdb_open_cf(db->rocksdb, SOL_ROCKSDB_CF_ACCOUNTS_OWNER_INDEX);
        if (err != SOL_OK) {
            sol_log_error("Failed to open accounts owner index column family");
            sol_rocksdb_destroy(db->rocksdb);
            pthread_rwlock_destroy(&db->lock);
            sol_free(db);
            return NULL;
        }

        db->owner_index_backend =
            sol_rocksdb_get_backend(db->rocksdb, SOL_ROCKSDB_CF_ACCOUNTS_OWNER_INDEX);
        if (!db->owner_index_backend) {
            sol_log_error("Failed to get accounts owner index storage backend");
            sol_rocksdb_destroy(db->rocksdb);
            pthread_rwlock_destroy(&db->lock);
            sol_free(db);
            return NULL;
        }

        err = sol_rocksdb_open_cf(db->rocksdb, SOL_ROCKSDB_CF_ACCOUNTS_OWNER_REVERSE);
        if (err != SOL_OK) {
            sol_log_error("Failed to open accounts owner reverse column family");
            sol_rocksdb_destroy(db->rocksdb);
            pthread_rwlock_destroy(&db->lock);
            sol_free(db);
            return NULL;
        }

        db->owner_reverse_backend =
            sol_rocksdb_get_backend(db->rocksdb, SOL_ROCKSDB_CF_ACCOUNTS_OWNER_REVERSE);
        if (!db->owner_reverse_backend) {
            sol_log_error("Failed to get accounts owner reverse storage backend");
            sol_rocksdb_destroy(db->rocksdb);
            pthread_rwlock_destroy(&db->lock);
            sol_free(db);
            return NULL;
        }

        /* Best-effort restore of persisted totals/counts. */
        uint8_t* stats_meta = NULL;
        size_t stats_meta_len = 0;
        sol_err_t stats_err = db->owner_reverse_backend->get(db->owner_reverse_backend->ctx,
                                                            ACCOUNTS_STATS_META_KEY,
                                                            sizeof(ACCOUNTS_STATS_META_KEY) - 1,
                                                            &stats_meta,
                                                            &stats_meta_len);
        if (stats_err == SOL_OK) {
            if (stats_meta && stats_meta_len == 24) {
                uint64_t count = 0;
                uint64_t lamports = 0;
                uint64_t data_bytes = 0;
                memcpy(&count, stats_meta + 0, 8);
                memcpy(&lamports, stats_meta + 8, 8);
                memcpy(&data_bytes, stats_meta + 16, 8);
                db->stats.accounts_count = count;
                db->stats.total_lamports = lamports;
                db->stats.total_data_bytes = data_bytes;
                db->account_count = (size_t)count;
            }
            sol_free(stats_meta);
        } else if (stats_err != SOL_ERR_NOTFOUND) {
            sol_log_warn("Failed to load accounts stats metadata: %s", sol_err_str(stats_err));
        }

        if (db->config.storage_type == SOL_ACCOUNTS_STORAGE_APPENDVEC) {
            size_t dir_len = strlen(db->config.appendvec_path);
            db->appendvec_dir = sol_alloc(dir_len + 1);
            if (!db->appendvec_dir) {
                sol_log_error("Failed to allocate appendvec dir path");
                sol_rocksdb_destroy(db->rocksdb);
                pthread_rwlock_destroy(&db->lock);
                sol_free(db);
                return NULL;
            }
            memcpy(db->appendvec_dir, db->config.appendvec_path, dir_len + 1);

            if (pthread_rwlock_init(&db->appendvec_lock, NULL) != 0) {
                sol_log_error("Failed to init appendvec lock");
                sol_free(db->appendvec_dir);
                db->appendvec_dir = NULL;
                sol_rocksdb_destroy(db->rocksdb);
                pthread_rwlock_destroy(&db->lock);
                sol_free(db);
                return NULL;
            }
            db->appendvec_lock_init = true;

            db->appendvec_files = sol_map_new(sizeof(uint64_t),
                                              sizeof(appendvec_file_t*),
                                              sol_map_hash_u64,
                                              sol_map_eq_u64,
                                              0);
            if (!db->appendvec_files) {
                sol_log_error("Failed to init appendvec file map");
                pthread_rwlock_destroy(&db->appendvec_lock);
                db->appendvec_lock_init = false;
                sol_free(db->appendvec_dir);
                db->appendvec_dir = NULL;
                sol_rocksdb_destroy(db->rocksdb);
                pthread_rwlock_destroy(&db->lock);
                sol_free(db);
                return NULL;
            }

            db->appendvec_open_fds = 0;
            db->appendvec_open_fds_limit = appendvec_open_fd_limit();
            db->appendvec_fd_cache_warned = 0;
            db->appendvec_fd_evict_cursor = 0;

            if (!db->config.quiet) {
                sol_log_info("AccountsDB using AppendVec backend (dir=%s, index=%s)",
                             db->appendvec_dir,
                             db->config.rocksdb_path ? db->config.rocksdb_path : "./rocksdb");
                sol_log_info("AppendVec FD cache limit: %zu", db->appendvec_open_fds_limit);
            }
        } else {
            if (!db->config.quiet) {
                sol_log_info("AccountsDB using RocksDB backend at %s",
                             db->config.rocksdb_path ? db->config.rocksdb_path : "./rocksdb");
            }
        }
#else
        sol_log_warn("RocksDB not available, falling back to memory backend");
        db->config.storage_type = SOL_ACCOUNTS_STORAGE_MEMORY;
#endif
    }

    /* Initialize in-memory hash table if not using backend */
    if (db->config.storage_type == SOL_ACCOUNTS_STORAGE_MEMORY) {
        db->bucket_count = db->config.initial_capacity;
        db->buckets = sol_calloc(db->bucket_count, sizeof(sol_account_entry_t*));
        if (!db->buckets) {
            pthread_rwlock_destroy(&db->lock);
            sol_free(db);
            return NULL;
        }

        size_t stripes = db->bucket_count;
        if (stripes > SOL_ACCOUNTS_DB_MAX_STRIPES) stripes = SOL_ACCOUNTS_DB_MAX_STRIPES;
        stripes = floor_pow2_size(stripes);
        if (stripes == 0) stripes = 1;
        db->stripe_count = stripes;
        db->stripe_mask = stripes - 1u;
        db->stripe_locks = sol_calloc(stripes, sizeof(pthread_rwlock_t));
        if (!db->stripe_locks) {
            sol_free(db->buckets);
            db->buckets = NULL;
            pthread_rwlock_destroy(&db->lock);
            sol_free(db);
            return NULL;
        }

        pthread_rwlockattr_t stripe_lock_attr;
        pthread_rwlockattr_t* stripe_lock_attr_p = NULL;
        if (pthread_rwlockattr_init(&stripe_lock_attr) == 0) {
#if defined(SOL_OS_LINUX) && defined(__GLIBC__) && defined(PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP)
            (void)pthread_rwlockattr_setkind_np(&stripe_lock_attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
#endif
            stripe_lock_attr_p = &stripe_lock_attr;
        }
        for (size_t i = 0; i < stripes; i++) {
            if (pthread_rwlock_init(&db->stripe_locks[i], stripe_lock_attr_p) != 0) {
                for (size_t j = 0; j < i; j++) {
                    pthread_rwlock_destroy(&db->stripe_locks[j]);
                }
                if (stripe_lock_attr_p) {
                    (void)pthread_rwlockattr_destroy(&stripe_lock_attr);
                }
                sol_free(db->stripe_locks);
                db->stripe_locks = NULL;
                db->stripe_count = 0;
                db->stripe_mask = 0;
                sol_free(db->buckets);
                db->buckets = NULL;
                pthread_rwlock_destroy(&db->lock);
                sol_free(db);
                return NULL;
            }
        }
        if (stripe_lock_attr_p) {
            (void)pthread_rwlockattr_destroy(&stripe_lock_attr);
        }

        if (!db->config.quiet) {
            sol_log_info("AccountsDB using in-memory backend with %zu buckets (%zu stripes)",
                         db->bucket_count, db->stripe_count);
        }
    }

    /* Persistent backends also need per-stripe locks so root advancement / live
     * writes don't stall all concurrent account loads behind a global RWLock. */
    if (db->backend && !db->stripe_locks) {
        long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
        if (ncpu < 1) ncpu = 1;

        /* Heavy replay runs many concurrent account reads/writes. A larger
         * stripe count materially lowers hot-bucket lock contention on
         * high-core hosts. */
        size_t stripes = (size_t)ncpu * 16u;
        if (stripes > SOL_ACCOUNTS_DB_MAX_STRIPES) stripes = SOL_ACCOUNTS_DB_MAX_STRIPES;
        stripes = floor_pow2_size(stripes);
        if (stripes == 0) stripes = 1;

        db->stripe_count = stripes;
        db->stripe_mask = stripes - 1u;
        db->stripe_locks = sol_calloc(stripes, sizeof(pthread_rwlock_t));
        if (!db->stripe_locks) {
            sol_log_error("Failed to allocate AccountsDB stripe locks");
            sol_accounts_db_destroy(db);
            return NULL;
        }

        pthread_rwlockattr_t stripe_lock_attr;
        pthread_rwlockattr_t* stripe_lock_attr_p = NULL;
        if (pthread_rwlockattr_init(&stripe_lock_attr) == 0) {
#if defined(SOL_OS_LINUX) && defined(__GLIBC__) && defined(PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP)
            (void)pthread_rwlockattr_setkind_np(&stripe_lock_attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
#endif
            stripe_lock_attr_p = &stripe_lock_attr;
        }
        for (size_t i = 0; i < stripes; i++) {
            if (pthread_rwlock_init(&db->stripe_locks[i], stripe_lock_attr_p) != 0) {
                if (stripe_lock_attr_p) {
                    (void)pthread_rwlockattr_destroy(&stripe_lock_attr);
                }
                sol_log_error("Failed to init AccountsDB stripe lock");
                sol_accounts_db_destroy(db);
                return NULL;
            }
        }
        if (stripe_lock_attr_p) {
            (void)pthread_rwlockattr_destroy(&stripe_lock_attr);
        }

        if (!db->config.quiet) {
            sol_log_info("AccountsDB backend stripe locks: %zu", db->stripe_count);
        }
    }

    if (db->config.enable_snapshots &&
        db->parent == NULL &&
        (db->config.storage_type == SOL_ACCOUNTS_STORAGE_ROCKSDB ||
         db->config.storage_type == SOL_ACCOUNTS_STORAGE_APPENDVEC)) {
        sol_err_t ferr = sol_accounts_db_fixup_builtin_program_accounts(db);
        if (ferr != SOL_OK) {
            sol_log_error("AccountsDB builtin fixup failed: %s", sol_err_str(ferr));
            sol_accounts_db_destroy(db);
            return NULL;
        }
    }

    return db;
}

void
sol_accounts_db_destroy(sol_accounts_db_t* db) {
    if (!db) return;

    if (db->appendvec_index) {
        sol_appendvec_index_destroy(db->appendvec_index);
        db->appendvec_index = NULL;
    }

    if (db->appendvec_lock_init) {
        pthread_rwlock_wrlock(&db->appendvec_lock);
        if (db->appendvec_files) {
            sol_map_iter_t it = sol_map_iter(db->appendvec_files);
            void* key = NULL;
            void* val = NULL;
            while (sol_map_iter_next(&it, &key, &val)) {
                appendvec_file_t* f = val ? *(appendvec_file_t**)val : NULL;
                if (f && f->fd >= 0) {
                    if (f->map && f->map_size != 0) {
                        (void)munmap(f->map, (size_t)f->map_size);
                        f->map = NULL;
                        f->map_size = 0;
                    }
                    close(f->fd);
                    f->fd = -1;
                }
                if (f) {
                    sol_free(f);
                }
            }
            sol_map_destroy(db->appendvec_files);
            db->appendvec_files = NULL;
        }
        pthread_rwlock_unlock(&db->appendvec_lock);
        pthread_rwlock_destroy(&db->appendvec_lock);
        db->appendvec_lock_init = false;
    }

    if (db->appendvec_dir) {
        sol_free(db->appendvec_dir);
        db->appendvec_dir = NULL;
    }

    /* Destroy storage backend if using one */
    if (db->rocksdb) {
#ifdef SOL_HAS_ROCKSDB
        sol_rocksdb_destroy(db->rocksdb);
#endif
        db->rocksdb = NULL;
        db->backend = NULL;
    }

    /* Free in-memory hash table entries if using memory backend */
    if (db->buckets) {
        for (size_t i = 0; i < db->bucket_count; i++) {
            sol_account_entry_t* entry = db->buckets[i];
            while (entry) {
                sol_account_entry_t* next = entry->next;
                if (entry->account) {
                    sol_account_destroy(entry->account);
                }
                sol_free(entry);
                entry = next;
            }
        }
        sol_free(db->buckets);
        db->buckets = NULL;
    }

    if (db->stripe_locks) {
        for (size_t i = 0; i < db->stripe_count; i++) {
            pthread_rwlock_destroy(&db->stripe_locks[i]);
        }
        sol_free(db->stripe_locks);
        db->stripe_locks = NULL;
        db->stripe_count = 0;
        db->stripe_mask = 0;
    }

    pthread_rwlock_destroy(&db->lock);
    sol_free(db);
}

sol_err_t
sol_accounts_db_set_disable_wal(sol_accounts_db_t* db, bool disable_wal) {
    if (!db) return SOL_ERR_INVAL;

#ifdef SOL_HAS_ROCKSDB
    if (!db->rocksdb) {
        (void)disable_wal;
        return SOL_ERR_NOT_IMPLEMENTED;
    }

    sol_rocksdb_set_disable_wal(db->rocksdb, disable_wal);
    return SOL_OK;
#else
    (void)disable_wal;
    return SOL_ERR_NOT_IMPLEMENTED;
#endif
}

sol_err_t
sol_accounts_db_set_bulk_load_mode(sol_accounts_db_t* db, bool enable) {
    if (!db) return SOL_ERR_INVAL;

#ifdef SOL_HAS_ROCKSDB
    if (!db->rocksdb) {
        (void)enable;
        return SOL_ERR_NOT_IMPLEMENTED;
    }

    return sol_rocksdb_set_bulk_load_mode(db->rocksdb, enable);
#else
    (void)enable;
    return SOL_ERR_NOT_IMPLEMENTED;
#endif
}

sol_account_t*
sol_accounts_db_load_ex(sol_accounts_db_t* db, const sol_pubkey_t* pubkey,
                        sol_slot_t* out_stored_slot) {
    if (!db || !pubkey) return NULL;

    if (out_stored_slot) *out_stored_slot = 0;

    bool locked = false;
    if (!db->backend) {
        pthread_rwlock_rdlock(&db->lock);
        locked = true;
    }

    atomic_inc_u64(&db->stats.loads);

    sol_account_t* result = NULL;
    bool local_miss = true;

    if (db->backend) {
        /* Use storage backend */
        const uint8_t* value = NULL;
        size_t value_len = 0;
        sol_rocksdb_pinned_slice_t* pinned = NULL;
        uint8_t* owned_value = NULL;

        sol_err_t err = SOL_ERR_UNSUPPORTED;

        /* Hot-path: use the in-memory AppendVec index to avoid a RocksDB read. */
        if (db->config.storage_type == SOL_ACCOUNTS_STORAGE_APPENDVEC && db->appendvec_index) {
            sol_appendvec_index_val_t v = {0};
            if (sol_appendvec_index_get(db->appendvec_index, pubkey, &v)) {
                if (v.lamports == 0 || sol_hash_is_zero(&v.leaf_hash)) {
                    local_miss = false;
                    if (out_stored_slot) *out_stored_slot = (sol_slot_t)v.slot;
                    result = NULL;
                    goto out_backend;
                }

                sol_accountsdb_appendvec_ref_v1_t ref = {0};
                ref.file_key = v.file_key;
                ref.record_offset = v.record_offset;
                ref.account_hash = v.leaf_hash;

                sol_account_t* loaded = NULL;
                sol_err_t lerr = appendvec_load_account_by_ref(db, pubkey, &ref, &loaded);
                if (lerr == SOL_OK) {
                    local_miss = false;
                    if (out_stored_slot) *out_stored_slot = (sol_slot_t)v.slot;
                    result = loaded;
                    goto out_backend;
                }
                if (lerr == SOL_ERR_NOTFOUND) {
                    local_miss = false;
                    if (out_stored_slot) *out_stored_slot = (sol_slot_t)v.slot;
                    result = NULL;
                    goto out_backend;
                }

                atomic_inc_u64(&db->stats.load_misses);
            }
        }

        if (db->config.storage_type == SOL_ACCOUNTS_STORAGE_APPENDVEC) {
            err = sol_rocksdb_backend_get_pinned(db->backend,
                                                 pubkey->bytes, sizeof(pubkey->bytes),
                                                 &value, &value_len,
                                                 &pinned);
            if (err == SOL_ERR_UNSUPPORTED) {
                err = db->backend->get(db->backend->ctx,
                                       pubkey->bytes, sizeof(pubkey->bytes),
                                       &owned_value, &value_len);
                value = owned_value;
            }
        } else {
            err = db->backend->get(db->backend->ctx,
                                   pubkey->bytes, sizeof(pubkey->bytes),
                                   &owned_value, &value_len);
            value = owned_value;
        }
        if (err == SOL_OK && value) {
            local_miss = false;
            const uint8_t* payload = NULL;
            size_t payload_len = 0;
            sol_slot_t stored_slot = 0;
            decode_backend_value(value, value_len, &stored_slot, NULL, &payload, &payload_len);
            if (out_stored_slot) *out_stored_slot = stored_slot;

            if (db->config.storage_type == SOL_ACCOUNTS_STORAGE_APPENDVEC) {
                sol_accountsdb_appendvec_ref_v1_t ref = {0};
                if (appendvec_ref_decode(payload, payload_len, &ref)) {
                    sol_account_t* loaded = NULL;
                    sol_err_t lerr = appendvec_load_account_by_ref(db, pubkey, &ref, &loaded);
                    if (lerr == SOL_OK) {
                        result = loaded;
                    } else if (lerr != SOL_ERR_NOTFOUND) {
                        atomic_inc_u64(&db->stats.load_misses);
                        local_miss = true;
                    }
                } else {
                    atomic_inc_u64(&db->stats.load_misses);
                    local_miss = true;
                }
            } else {
                /* Deserialize account from stored data */
                result = sol_account_alloc();
                if (result) {
                    size_t consumed = 0;
                    err = sol_account_deserialize(result, payload, payload_len, &consumed);
                    if (err != SOL_OK) {
                        sol_account_destroy(result);
                        result = NULL;
                    }
                }

                /* Storage backends may represent deletes as a tombstone value
                 * (lamports==0). Treat these as non-existent. */
                if (result && result->meta.lamports == 0) {
                    sol_account_destroy(result);
                    result = NULL;
                }
            }
        } else {
            atomic_inc_u64(&db->stats.load_misses);
        }

    out_backend:
        if (pinned) {
            sol_rocksdb_backend_pinned_destroy(pinned);
            pinned = NULL;
        }
        if (owned_value) {
            sol_free(owned_value);
            owned_value = NULL;
        }
    } else {
        /* Use in-memory hash table */
        size_t idx = pubkey_hash(pubkey, db->bucket_count);
        size_t stripe = stripe_for_bucket(db, idx);
        if (db->stripe_locks) {
            pthread_rwlock_rdlock(&db->stripe_locks[stripe]);
        }
        sol_account_entry_t* entry = find_entry(db->buckets[idx], pubkey);

        if (entry) {
            local_miss = false;
            if (entry->account) {
                result = sol_account_clone(entry->account);
                if (out_stored_slot) *out_stored_slot = entry->slot;
            } else {
                /* Tombstone in an overlay */
                result = NULL;
            }
        } else {
            atomic_inc_u64(&db->stats.load_misses);
        }
        if (db->stripe_locks) {
            pthread_rwlock_unlock(&db->stripe_locks[stripe]);
        }
    }

    if (locked) {
        pthread_rwlock_unlock(&db->lock);
    }

    /* Note: execution-time in-memory views may keep zero-lamport accounts
     * visible (matching Agave). Storage backends may represent deletes as a
     * lamports==0 tombstone value and are filtered above. Tombstones (entry
     * with NULL account) in an overlay still stop the parent lookup below. */

    /* Overlay miss falls through to parent. Tombstones stop the search. */
    if (!result && local_miss && db->parent) {
        return sol_accounts_db_load_ex(db->parent, pubkey, out_stored_slot);
    }
    return result;
}

sol_account_t*
sol_accounts_db_load(sol_accounts_db_t* db, const sol_pubkey_t* pubkey) {
    return sol_accounts_db_load_ex(db, pubkey, NULL);
}

sol_account_t*
sol_accounts_db_load_view_ex(sol_accounts_db_t* db,
                             const sol_pubkey_t* pubkey,
                             sol_slot_t* out_stored_slot) {
    if (!db || !pubkey) return NULL;
    if (out_stored_slot) *out_stored_slot = 0;

    bool locked = false;
    if (!db->backend) {
        pthread_rwlock_rdlock(&db->lock);
        locked = true;
    }

    atomic_inc_u64(&db->stats.loads);

    sol_account_t* result = NULL;
    bool local_miss = true;

    if (db->backend) {
        const uint8_t* value = NULL;
        size_t value_len = 0;
        sol_rocksdb_pinned_slice_t* pinned = NULL;
        uint8_t* owned_value = NULL;

        sol_err_t err = SOL_ERR_UNSUPPORTED;

        /* Hot-path: when available, use the in-memory AppendVec index to avoid
         * a RocksDB read for every account load. */
        if (db->config.storage_type == SOL_ACCOUNTS_STORAGE_APPENDVEC && db->appendvec_index) {
            sol_appendvec_index_val_t v = {0};
            if (sol_appendvec_index_get(db->appendvec_index, pubkey, &v)) {
                if (v.lamports == 0 || sol_hash_is_zero(&v.leaf_hash)) {
                    local_miss = false;
                    if (out_stored_slot) *out_stored_slot = (sol_slot_t)v.slot;
                    result = NULL;
                    goto out_backend;
                }

                sol_accountsdb_appendvec_ref_v1_t ref = {0};
                ref.file_key = v.file_key;
                ref.record_offset = v.record_offset;
                ref.account_hash = v.leaf_hash;

                sol_account_t* loaded = NULL;
                sol_err_t lerr = appendvec_load_account_view_by_ref(db, pubkey, &ref, &loaded);
                if (lerr == SOL_OK) {
                    local_miss = false;
                    if (out_stored_slot) *out_stored_slot = (sol_slot_t)v.slot;
                    result = loaded;
                    goto out_backend;
                }
                if (lerr == SOL_ERR_NOTFOUND) {
                    local_miss = false;
                    if (out_stored_slot) *out_stored_slot = (sol_slot_t)v.slot;
                    result = NULL;
                    goto out_backend;
                }

                /* Unexpected error - fall back to RocksDB for robustness. */
                atomic_inc_u64(&db->stats.load_misses);
            }
        }

        if (db->config.storage_type == SOL_ACCOUNTS_STORAGE_APPENDVEC) {
            err = sol_rocksdb_backend_get_pinned(db->backend,
                                                 pubkey->bytes, sizeof(pubkey->bytes),
                                                 &value, &value_len,
                                                 &pinned);
            if (err == SOL_ERR_UNSUPPORTED) {
                err = db->backend->get(db->backend->ctx,
                                       pubkey->bytes, sizeof(pubkey->bytes),
                                       &owned_value, &value_len);
                value = owned_value;
            }
        } else {
            err = db->backend->get(db->backend->ctx,
                                   pubkey->bytes, sizeof(pubkey->bytes),
                                   &owned_value, &value_len);
            value = owned_value;
        }
        if (err == SOL_OK && value) {
            local_miss = false;
            const uint8_t* payload = NULL;
            size_t payload_len = 0;
            sol_slot_t stored_slot = 0;
            decode_backend_value(value, value_len, &stored_slot, NULL, &payload, &payload_len);
            if (out_stored_slot) *out_stored_slot = stored_slot;

            if (db->config.storage_type == SOL_ACCOUNTS_STORAGE_APPENDVEC) {
                sol_accountsdb_appendvec_ref_v1_t ref = {0};
                if (appendvec_ref_decode(payload, payload_len, &ref)) {
                    sol_account_t* loaded = NULL;
                    sol_err_t lerr = appendvec_load_account_view_by_ref(db, pubkey, &ref, &loaded);
                    if (lerr == SOL_OK) {
                        result = loaded;
                    } else if (lerr != SOL_ERR_NOTFOUND) {
                        atomic_inc_u64(&db->stats.load_misses);
                        local_miss = true;
                    }
                } else {
                    atomic_inc_u64(&db->stats.load_misses);
                    local_miss = true;
                }
            } else {
                result = sol_account_alloc();
                if (result) {
                    size_t consumed = 0;
                    err = sol_account_deserialize(result, payload, payload_len, &consumed);
                    if (err != SOL_OK) {
                        sol_account_destroy(result);
                        result = NULL;
                    }
                }
                if (result && result->meta.lamports == 0) {
                    sol_account_destroy(result);
                    result = NULL;
                }
            }
        } else {
            atomic_inc_u64(&db->stats.load_misses);
        }

    out_backend:
        if (pinned) {
            sol_rocksdb_backend_pinned_destroy(pinned);
            pinned = NULL;
        }
        if (owned_value) {
            sol_free(owned_value);
            owned_value = NULL;
        }
    } else {
        size_t idx = pubkey_hash(pubkey, db->bucket_count);
        size_t stripe = stripe_for_bucket(db, idx);
        if (db->stripe_locks) {
            pthread_rwlock_rdlock(&db->stripe_locks[stripe]);
        }
        sol_account_entry_t* entry = find_entry(db->buckets[idx], pubkey);

        if (entry) {
            local_miss = false;
            if (entry->account) {
                result = sol_account_clone(entry->account);
                if (out_stored_slot) *out_stored_slot = entry->slot;
            } else {
                result = NULL;
            }
        } else {
            atomic_inc_u64(&db->stats.load_misses);
        }
        if (db->stripe_locks) {
            pthread_rwlock_unlock(&db->stripe_locks[stripe]);
        }
    }

    if (locked) {
        pthread_rwlock_unlock(&db->lock);
    }

    if (!result && local_miss && db->parent) {
        return sol_accounts_db_load_view_ex(db->parent, pubkey, out_stored_slot);
    }
    return result;
}

sol_account_t*
sol_accounts_db_load_view(sol_accounts_db_t* db, const sol_pubkey_t* pubkey) {
    return sol_accounts_db_load_view_ex(db, pubkey, NULL);
}

/* Debug: trace account lookup through parent chain */
void
sol_accounts_db_trace_load(sol_accounts_db_t* db, const sol_pubkey_t* pubkey) {
    if (!db || !pubkey) return;
    int depth = 0;
    sol_accounts_db_t* cur = db;
    while (cur) {
        bool found_local = false;
        bool is_tombstone = false;

        pthread_rwlock_rdlock(&cur->lock);
        if (cur->backend) {
            uint8_t* value = NULL;
            size_t value_len = 0;
            sol_err_t err = cur->backend->get(cur->backend->ctx,
                                              pubkey->bytes, sizeof(pubkey->bytes),
                                              &value, &value_len);
            if (err == SOL_OK && value) {
                found_local = true;
                sol_free(value);
            }
        } else {
            size_t idx = pubkey_hash(pubkey, cur->bucket_count);
            sol_account_entry_t* entry = find_entry(cur->buckets[idx], pubkey);
            if (entry) {
                found_local = true;
                is_tombstone = (entry->account == NULL);
            }
        }
        pthread_rwlock_unlock(&cur->lock);

        sol_log_warn("  TRACE depth=%d is_overlay=%d backend=%d bucket_count=%zu acct_count=%zu found=%d tombstone=%d",
                     depth, cur->parent != NULL, cur->backend != NULL,
                     cur->bucket_count, cur->account_count,
                     found_local, is_tombstone);

        if (found_local) break; /* found or tombstone stops traversal */
        cur = cur->parent;
        depth++;
    }
    if (!cur) {
        sol_log_warn("  TRACE: reached end of chain (depth=%d), not found", depth);
    }
}

bool
sol_accounts_db_exists(sol_accounts_db_t* db, const sol_pubkey_t* pubkey) {
    if (!db || !pubkey) return false;

    bool locked = false;
    if (!db->backend) {
        pthread_rwlock_rdlock(&db->lock);
        locked = true;
    }

    bool exists = false;
    bool local_miss = true;

    if (db->backend) {
        /* Use storage backend.
         *
         * We treat zero-lamport accounts as deleted, so a raw key existence
         * check is insufficient. */
        uint8_t* value = NULL;
        size_t value_len = 0;

        if (db->config.storage_type == SOL_ACCOUNTS_STORAGE_APPENDVEC && db->appendvec_index) {
            sol_appendvec_index_val_t v = {0};
            if (sol_appendvec_index_get(db->appendvec_index, pubkey, &v)) {
                local_miss = false;
                exists = (v.lamports != 0) && !sol_hash_is_zero(&v.leaf_hash);
                goto out_backend;
            }
        }

        sol_err_t err = db->backend->get(db->backend->ctx,
                                         pubkey->bytes, sizeof(pubkey->bytes),
                                         &value, &value_len);
        if (err == SOL_OK && value) {
            local_miss = false;
            const uint8_t* payload = NULL;
            size_t payload_len = 0;
            decode_backend_value(value, value_len, NULL, NULL, &payload, &payload_len);

            if (db->config.storage_type == SOL_ACCOUNTS_STORAGE_APPENDVEC) {
                sol_accountsdb_appendvec_ref_v1_t ref = {0};
                if (appendvec_ref_decode(payload, payload_len, &ref)) {
                    exists = !sol_hash_is_zero(&ref.account_hash);
                } else {
                    exists = false;
                    local_miss = true;
                }
            } else {
                uint64_t lamports = 0;
                (void)parse_serialized_account_meta(payload, payload_len, &lamports, NULL);
                exists = (lamports != 0);
            }

            sol_free(value);
        } else {
            exists = false;
            local_miss = true;
        }

    out_backend:
        ;
    } else {
        /* Use in-memory hash table */
        size_t idx = pubkey_hash(pubkey, db->bucket_count);
        size_t stripe = stripe_for_bucket(db, idx);
        if (db->stripe_locks) {
            pthread_rwlock_rdlock(&db->stripe_locks[stripe]);
        }
        sol_account_entry_t* entry = find_entry(db->buckets[idx], pubkey);
        if (entry) {
            /* Tombstones in an overlay hide parent entries. */
            local_miss = false;
            exists = entry->account != NULL && entry->account->meta.lamports != 0;
        } else {
            exists = false;
        }
        if (db->stripe_locks) {
            pthread_rwlock_unlock(&db->stripe_locks[stripe]);
        }
    }

    if (locked) {
        pthread_rwlock_unlock(&db->lock);
    }

    if (!exists && local_miss && db->parent) {
        return sol_accounts_db_exists(db->parent, pubkey);
    }
    return exists;
}

sol_err_t
sol_accounts_db_store(sol_accounts_db_t* db, const sol_pubkey_t* pubkey,
                      const sol_account_t* account) {
    return sol_accounts_db_store_versioned(db, pubkey, account, 0, 0);
}

sol_err_t
sol_accounts_db_fixup_builtin_program_accounts(sol_accounts_db_t* db) {
    if (!db) return SOL_ERR_INVAL;
    uint64_t fixup_t0_ms = monotonic_ms();

    /* System Program: canonical metadata+data per Agave mainnet. */
    static const uint8_t system_program_data[] = "solana_system_program";
    const size_t system_program_data_len = sizeof(system_program_data) - 1;

    bool need_fix = false;
    sol_account_t* existing = sol_accounts_db_load(db, &SOL_SYSTEM_PROGRAM_ID);
    if (!existing) {
        need_fix = true;
        sol_log_warn("fixup_builtin: System Program NOT FOUND in accounts DB (parent=%s, backend=%s)",
                     db->parent ? "yes" : "no",
                     db->backend ? "yes" : "no");
    } else {
        if (existing->meta.lamports != 1) need_fix = true;
        if (existing->meta.data_len != system_program_data_len) need_fix = true;
        if (!existing->meta.executable) need_fix = true;
        if (!sol_pubkey_eq(&existing->meta.owner, &SOL_NATIVE_LOADER_ID)) need_fix = true;
        if (existing->meta.rent_epoch != UINT64_MAX) need_fix = true;
        if (existing->meta.data_len == system_program_data_len) {
            if (!existing->data ||
                memcmp(existing->data, system_program_data, system_program_data_len) != 0) {
                need_fix = true;
            }
        }
        sol_log_info("fixup_builtin: System Program found: lamports=%lu exec=%d data_len=%lu rent_epoch=%lu need_fix=%d",
                     (unsigned long)existing->meta.lamports,
                     (int)existing->meta.executable,
                     (unsigned long)existing->meta.data_len,
                     (unsigned long)existing->meta.rent_epoch,
                     (int)need_fix);
    }
    if (existing) sol_account_destroy(existing);

    if (!need_fix) {
        return SOL_OK;
    }
    sol_log_warn("fixup_builtin: Applying System Program fix");

    if (db->config.storage_type == SOL_ACCOUNTS_STORAGE_APPENDVEC && db->appendvec_index) {
        sol_appendvec_index_val_t v = {0};
        if (sol_appendvec_index_get(db->appendvec_index, &SOL_SYSTEM_PROGRAM_ID, &v)) {
            sol_log_info("fixup_builtin: pre-store appendvec ref slot=%lu file=%lu off=%lu lamports=%lu",
                         (unsigned long)v.slot,
                         (unsigned long)v.file_key,
                         (unsigned long)v.record_offset,
                         (unsigned long)v.lamports);
        } else {
            sol_log_info("fixup_builtin: pre-store appendvec ref missing");
        }
    }

    sol_account_t* fixed = sol_account_new(1, system_program_data_len, &SOL_NATIVE_LOADER_ID);
    if (!fixed) {
        return SOL_ERR_NOMEM;
    }
    memcpy(fixed->data, system_program_data, system_program_data_len);
    fixed->meta.executable = true;
    fixed->meta.rent_epoch = UINT64_MAX;

    uint64_t store_t0_ms = monotonic_ms();
    sol_err_t err = sol_accounts_db_store(db, &SOL_SYSTEM_PROGRAM_ID, fixed);
    uint64_t store_dt_ms = monotonic_ms() - store_t0_ms;
    sol_account_destroy(fixed);

    if (err != SOL_OK) {
        sol_log_error("fixup_builtin: store failed after %lums: %s",
                      (unsigned long)store_dt_ms,
                      sol_err_str(err));
        return err;
    }
    sol_log_info("fixup_builtin: store completed in %lums (total=%lums)",
                 (unsigned long)store_dt_ms,
                 (unsigned long)(monotonic_ms() - fixup_t0_ms));

    /* Verify the fix took effect */
    uint64_t verify_t0_ms = monotonic_ms();
    sol_account_t* verify = sol_accounts_db_load(db, &SOL_SYSTEM_PROGRAM_ID);
    uint64_t verify_dt_ms = monotonic_ms() - verify_t0_ms;
    if (!verify) {
        sol_log_error("fixup_builtin: System Program STILL NOT FOUND after store! (verify=%lums total=%lums)",
                      (unsigned long)verify_dt_ms,
                      (unsigned long)(monotonic_ms() - fixup_t0_ms));
    } else {
        sol_log_info("fixup_builtin: Verified System Program after fix: lamports=%lu exec=%d data_len=%lu (verify=%lums total=%lums)",
                     (unsigned long)verify->meta.lamports,
                     (int)verify->meta.executable,
                     (unsigned long)verify->meta.data_len,
                     (unsigned long)verify_dt_ms,
                     (unsigned long)(monotonic_ms() - fixup_t0_ms));
        sol_account_destroy(verify);
    }

    return err;
}

static sol_err_t
accounts_db_store_fork_internal(sol_accounts_db_t* db,
                                const sol_pubkey_t* pubkey,
                                const sol_account_t* account,
                                sol_slot_t slot,
                                uint64_t write_version,
                                bool hint_prev_exists,
                                uint64_t hint_prev_lamports,
                                uint64_t hint_prev_data_len,
                                bool have_hint) {
    if (!db || !db->parent || !pubkey || !account) return SOL_ERR_INVAL;

    atomic_inc_u64(&db->stats.stores);

    /* Clone outside locks to keep bucket critical section short. */
    sol_account_t* clone = sol_account_clone(account);
    if (!clone) {
        return SOL_ERR_NOMEM;
    }

    size_t idx = pubkey_hash(pubkey, db->bucket_count);
    size_t stripe = stripe_for_bucket(db, idx);

    /* Fast path: update an existing local entry (no parent lookup). */
    pthread_rwlock_rdlock(&db->lock);
    if (db->stripe_locks) {
        pthread_rwlock_wrlock(&db->stripe_locks[stripe]);
    }

    sol_account_entry_t* entry = find_entry(db->buckets[idx], pubkey);
    if (entry) {
        if (write_version != 0 && entry->write_version != 0 &&
            (entry->write_version > write_version ||
             (entry->write_version == write_version && entry->slot >= slot))) {
            if (db->stripe_locks) {
                pthread_rwlock_unlock(&db->stripe_locks[stripe]);
            }
            pthread_rwlock_unlock(&db->lock);
            sol_account_destroy(clone);
            return SOL_OK;
        }

        bool prev_exists = entry->account != NULL;
        uint64_t prev_lamports = prev_exists ? entry->account->meta.lamports : 0;
        uint64_t prev_data_len = prev_exists ? entry->account->meta.data_len : 0;

        sol_account_t* old = entry->account;
        bool had_account = (old != NULL);

        entry->account = clone;
        entry->slot = slot;
        entry->write_version = write_version;

        if (!had_account) {
            atomic_add_size(&db->account_count, 1u);
        }

        if (db->stripe_locks) {
            pthread_rwlock_unlock(&db->stripe_locks[stripe]);
        }
        pthread_rwlock_unlock(&db->lock);

        if (old) {
            sol_account_destroy(old);
        }

        if (prev_exists) {
            atomic_sub_u64(&db->stats.total_lamports, prev_lamports);
            atomic_sub_u64(&db->stats.total_data_bytes, prev_data_len);
        } else {
            atomic_inc_u64(&db->stats.accounts_count);
        }
        atomic_add_u64(&db->stats.total_lamports, account->meta.lamports);
        atomic_add_u64(&db->stats.total_data_bytes, (uint64_t)account->meta.data_len);
        return SOL_OK;
    }

    if (db->stripe_locks) {
        pthread_rwlock_unlock(&db->stripe_locks[stripe]);
    }
    pthread_rwlock_unlock(&db->lock);

    /* Local miss: consult the parent view for previous visible meta. */
    bool prev_exists = false;
    uint64_t prev_lamports = 0;
    uint64_t prev_data_len = 0;
    if (have_hint) {
        prev_exists = hint_prev_exists;
        prev_lamports = hint_prev_lamports;
        prev_data_len = hint_prev_data_len;
    } else {
        prev_exists = accounts_db_lookup_meta_visible(db->parent, pubkey, &prev_lamports, &prev_data_len);
    }

    /* Prepare entry struct outside locks. */
    sol_account_entry_t* new_entry = sol_calloc(1, sizeof(sol_account_entry_t));
    if (!new_entry) {
        sol_account_destroy(clone);
        return SOL_ERR_NOMEM;
    }
    new_entry->pubkey = *pubkey;
    new_entry->account = clone;
    new_entry->slot = slot;
    new_entry->write_version = write_version;

    /* Insert or update under stripe lock. */
    pthread_rwlock_rdlock(&db->lock);
    if (db->stripe_locks) {
        pthread_rwlock_wrlock(&db->stripe_locks[stripe]);
    }

    entry = find_entry(db->buckets[idx], pubkey);
    if (entry) {
        /* Another writer won the race; treat as an update. */
        if (write_version != 0 && entry->write_version != 0 &&
            (entry->write_version > write_version ||
             (entry->write_version == write_version && entry->slot >= slot))) {
            if (db->stripe_locks) {
                pthread_rwlock_unlock(&db->stripe_locks[stripe]);
            }
            pthread_rwlock_unlock(&db->lock);
            sol_free(new_entry);
            sol_account_destroy(clone);
            return SOL_OK;
        }

        bool prev2_exists = entry->account != NULL;
        uint64_t prev2_lamports = prev2_exists ? entry->account->meta.lamports : 0;
        uint64_t prev2_data_len = prev2_exists ? entry->account->meta.data_len : 0;

        sol_account_t* old = entry->account;
        bool had_account = (old != NULL);

        entry->account = clone;
        entry->slot = slot;
        entry->write_version = write_version;

        if (!had_account) {
            atomic_add_size(&db->account_count, 1u);
        }

        if (db->stripe_locks) {
            pthread_rwlock_unlock(&db->stripe_locks[stripe]);
        }
        pthread_rwlock_unlock(&db->lock);

        sol_free(new_entry);

        if (old) {
            sol_account_destroy(old);
        }

        if (prev2_exists) {
            atomic_sub_u64(&db->stats.total_lamports, prev2_lamports);
            atomic_sub_u64(&db->stats.total_data_bytes, prev2_data_len);
        } else {
            atomic_inc_u64(&db->stats.accounts_count);
        }
        atomic_add_u64(&db->stats.total_lamports, account->meta.lamports);
        atomic_add_u64(&db->stats.total_data_bytes, (uint64_t)account->meta.data_len);
        return SOL_OK;
    }

    new_entry->next = db->buckets[idx];
    db->buckets[idx] = new_entry;
    atomic_add_size(&db->account_count, 1u);

    if (db->stripe_locks) {
        pthread_rwlock_unlock(&db->stripe_locks[stripe]);
    }
    pthread_rwlock_unlock(&db->lock);

    if (prev_exists) {
        atomic_sub_u64(&db->stats.total_lamports, prev_lamports);
        atomic_sub_u64(&db->stats.total_data_bytes, prev_data_len);
    } else {
        atomic_inc_u64(&db->stats.accounts_count);
    }
    atomic_add_u64(&db->stats.total_lamports, account->meta.lamports);
    atomic_add_u64(&db->stats.total_data_bytes, (uint64_t)account->meta.data_len);
    return SOL_OK;
}

static sol_err_t
accounts_db_store_fork(sol_accounts_db_t* db,
                       const sol_pubkey_t* pubkey,
                       const sol_account_t* account,
                       sol_slot_t slot,
                       uint64_t write_version) {
    return accounts_db_store_fork_internal(db,
                                           pubkey,
                                           account,
                                           slot,
                                           write_version,
                                           false,
                                           0,
                                           0,
                                           false);
}

sol_err_t
sol_accounts_db_store_versioned(sol_accounts_db_t* db,
                                const sol_pubkey_t* pubkey,
                                const sol_account_t* account,
                                sol_slot_t slot,
                                uint64_t write_version) {
    if (!db || !pubkey || !account) return SOL_ERR_INVAL;

    /* Note: zero-lamport accounts are stored normally. During execution,
     * CPI post-update needs to read debited-to-zero accounts. The lt_hash
     * computation handles 0-lamport accounts correctly (treats as deleted).
     * Cleanup happens during the clean/shrink phase, not at store time. */

    if (db->parent) {
        return accounts_db_store_fork(db, pubkey, account, slot, write_version);
    }

    /* Persistent store: backend + per-stripe lock (no global db->lock). */
    if (db->backend) {
        atomic_inc_u64(&db->stats.stores);

        size_t stripe = stripe_for_pubkey(db, pubkey);
        if (db->stripe_locks) {
            pthread_rwlock_wrlock(&db->stripe_locks[stripe]);
        }

        sol_err_t ret = SOL_OK;

        if (db->config.storage_type == SOL_ACCOUNTS_STORAGE_APPENDVEC) {
            owner_reverse_value_t existing_rev = {0};
            bool existing_rev_found = false;
            bool existing_owner_ok = false;
            uint64_t existing_lamports = 0;
            uint64_t existing_data_len = 0;
            bool existed_visible = false;
            bool existing_idx_hit = false;
            sol_appendvec_index_val_t existing_idx = {0};

            /* Hot path: avoid extra RocksDB reads on every store by sourcing
             * previous account metadata directly from the in-memory AppendVec index. */
            if (db->appendvec_index &&
                sol_appendvec_index_get(db->appendvec_index, pubkey, &existing_idx)) {
                existing_idx_hit = true;

                if (write_version != 0 &&
                    (existing_idx.write_version > write_version ||
                     (existing_idx.write_version == write_version && existing_idx.slot >= slot))) {
                    ret = SOL_OK;
                    goto out_backend;
                }

                existing_rev_found = true;
                existing_rev.owner = existing_idx.owner;
                existing_rev.lamports = existing_idx.lamports;
                existing_rev.data_len = existing_idx.data_len;

                if (existing_idx.lamports != 0 && !sol_hash_is_zero(&existing_idx.leaf_hash)) {
                    existed_visible = true;
                    existing_owner_ok = true;
                    existing_lamports = existing_idx.lamports;
                    existing_data_len = existing_idx.data_len;
                }
            }

            if (!existing_idx_hit && db->owner_reverse_backend) {
                sol_err_t rerr = owner_reverse_get(db->owner_reverse_backend,
                                                   pubkey,
                                                   &existing_rev,
                                                   &existing_rev_found);
                if (rerr != SOL_OK) {
                    ret = rerr;
                    goto out_backend;
                }
                if (existing_rev_found &&
                    existing_rev.lamports != ~(uint64_t)0 &&
                    existing_rev.data_len != ~(uint64_t)0 &&
                    existing_rev.lamports != 0) {
                    existed_visible = true;
                    existing_owner_ok = true;
                    existing_lamports = existing_rev.lamports;
                    existing_data_len = existing_rev.data_len;
                }
            }

            if (write_version != 0 && !existing_idx_hit) {
                uint8_t* existing_value = NULL;
                size_t existing_value_len = 0;
                sol_err_t gerr = db->backend->get(db->backend->ctx,
                                                  pubkey->bytes, sizeof(pubkey->bytes),
                                                  &existing_value, &existing_value_len);
                if (gerr == SOL_OK && existing_value) {
                    sol_slot_t existing_slot = 0;
                    uint64_t existing_write_version = 0;
                    const uint8_t* payload = NULL;
                    size_t payload_len = 0;
                    decode_backend_value(existing_value, existing_value_len,
                                         &existing_slot, &existing_write_version,
                                         &payload, &payload_len);
                    sol_free(existing_value);

                    if (existing_write_version > write_version ||
                        (existing_write_version == write_version && existing_slot >= slot)) {
                        ret = SOL_OK;
                        goto out_backend;
                    }
                } else if (existing_value) {
                    sol_free(existing_value);
                }
            }

            uint64_t file_key = ((uint64_t)slot << 32) | 0u;
            uint64_t record_offset = 0;
            sol_err_t aerr = appendvec_append_record_solana3(db,
                                                             &file_key,
                                                             pubkey,
                                                             account,
                                                             write_version,
                                                             &record_offset);
            if (aerr != SOL_OK) {
                ret = aerr;
                goto out_backend;
            }

            sol_hash_t leaf = {0};
            sol_account_hash(pubkey, account, &leaf);

            sol_accountsdb_appendvec_ref_v1_t ref = {0};
            ref.file_key = file_key;
            ref.record_offset = record_offset;
            ref.account_hash = leaf;

            uint8_t value_buf[sizeof(sol_accountsdb_value_header_t) + sizeof(ref)];
            sol_accountsdb_value_header_t hdr = {
                .magic = SOL_ACCOUNTSDB_VALUE_MAGIC,
                .reserved = 0,
                .slot = (uint64_t)slot,
                .write_version = write_version,
            };
            memcpy(value_buf, &hdr, sizeof(hdr));
            memcpy(value_buf + sizeof(hdr), &ref, sizeof(ref));

            sol_err_t perr = db->backend->put(db->backend->ctx,
                                              pubkey->bytes, sizeof(pubkey->bytes),
                                              value_buf, sizeof(value_buf));
            if (perr != SOL_OK) {
                ret = perr;
                goto out_backend;
            }

            if (!existed_visible) {
                atomic_inc_u64(&db->stats.accounts_count);
                atomic_add_size(&db->account_count, 1u);
            } else {
                atomic_sub_u64(&db->stats.total_lamports, existing_lamports);
                atomic_sub_u64(&db->stats.total_data_bytes, existing_data_len);
            }
            atomic_add_u64(&db->stats.total_lamports, account->meta.lamports);
            atomic_add_u64(&db->stats.total_data_bytes, (uint64_t)account->meta.data_len);

            if (db->owner_index_backend) {
                const sol_pubkey_t* new_owner = &account->meta.owner;
                const bool track_new_owner = accounts_db_should_track_owner_live(db, new_owner);
                const bool track_old_owner =
                    existed_visible && existing_owner_ok &&
                    accounts_db_should_track_owner_live(db, &existing_rev.owner);

                if (track_old_owner &&
                    (!track_new_owner || !sol_pubkey_eq(&existing_rev.owner, new_owner))) {
                    sol_err_t derr = owner_index_del(db->owner_index_backend, &existing_rev.owner, pubkey);
                    if (derr != SOL_OK) {
                        ret = derr;
                        goto out_backend;
                    }
                }
                if (track_new_owner) {
                    sol_err_t ierr = owner_index_put(db->owner_index_backend, new_owner, pubkey);
                    if (ierr != SOL_OK) {
                        ret = ierr;
                        goto out_backend;
                    }
                }
            }

            if (db->owner_reverse_backend) {
                owner_reverse_value_t val = {
                    .lamports = account->meta.lamports,
                    .data_len = account->meta.data_len,
                    .owner = account->meta.owner,
                };
                sol_err_t rerr = owner_reverse_put(db->owner_reverse_backend, pubkey, &val);
                if (rerr != SOL_OK) {
                    ret = rerr;
                    goto out_backend;
                }
            }

            if (db->appendvec_index) {
                (void)sol_appendvec_index_update(db->appendvec_index,
                                                 pubkey,
                                                 slot,
                                                 write_version,
                                                 &account->meta.owner,
                                                 (uint64_t)account->meta.lamports,
                                                 (uint64_t)account->meta.data_len,
                                                 file_key,
                                                 record_offset,
                                                 &leaf);
            }

            ret = SOL_OK;
            goto out_backend;
        }

        bool existed_visible = false;
        sol_slot_t existing_slot = 0;
        uint64_t existing_write_version = 0;
        owner_reverse_value_t existing_rev = {0};
        bool existing_rev_found = false;
        bool existing_owner_ok = false;
        uint64_t existing_lamports = 0;
        uint64_t existing_data_len = 0;

        uint8_t* existing_value = NULL;
        size_t existing_value_len = 0;

        if (write_version == 0 && db->owner_reverse_backend) {
            sol_err_t rerr = owner_reverse_get(db->owner_reverse_backend,
                                               pubkey,
                                               &existing_rev,
                                               &existing_rev_found);
            if (rerr != SOL_OK) {
                ret = rerr;
                goto out_backend;
            }
            if (existing_rev_found) {
                if (existing_rev.lamports == ~(uint64_t)0 ||
                    existing_rev.data_len == ~(uint64_t)0) {
                    existing_rev_found = false;
                } else {
                    existed_visible = true;
                    existing_owner_ok = true;
                    existing_lamports = existing_rev.lamports;
                    existing_data_len = existing_rev.data_len;
                }
            }
        }

        if (write_version != 0 || !existing_rev_found) {
            sol_err_t gerr = db->backend->get(db->backend->ctx,
                                              pubkey->bytes, sizeof(pubkey->bytes),
                                              &existing_value, &existing_value_len);
            if (gerr == SOL_OK && existing_value) {
                const uint8_t* existing_account_bytes = NULL;
                size_t existing_account_len = 0;
                decode_backend_value(existing_value, existing_value_len,
                                     &existing_slot, &existing_write_version,
                                     &existing_account_bytes, &existing_account_len);
                (void)parse_serialized_account_meta(existing_account_bytes,
                                                    existing_account_len,
                                                    &existing_lamports,
                                                    &existing_data_len);
                existing_owner_ok = parse_serialized_account_owner(
                    existing_account_bytes, existing_account_len, &existing_rev.owner);
                existed_visible = (existing_lamports != 0);

                if (write_version != 0 &&
                    (existing_write_version > write_version ||
                     (existing_write_version == write_version && existing_slot >= slot))) {
                    sol_free(existing_value);
                    ret = SOL_OK;
                    goto out_backend;
                }
            }
        }

        size_t account_buf_size = 8 + 8 + account->meta.data_len + 32 + 1 + 8;
        size_t value_buf_size = sizeof(sol_accountsdb_value_header_t) + account_buf_size;
        uint8_t* value = sol_alloc(value_buf_size);
        if (!value) {
            sol_free(existing_value);
            ret = SOL_ERR_NOMEM;
            goto out_backend;
        }

        sol_accountsdb_value_header_t hdr = {
            .magic = SOL_ACCOUNTSDB_VALUE_MAGIC,
            .reserved = 0,
            .slot = (uint64_t)slot,
            .write_version = write_version,
        };
        memcpy(value, &hdr, sizeof(hdr));

        size_t bytes_written = 0;
        sol_err_t serr = sol_account_serialize(account,
                                               value + sizeof(sol_accountsdb_value_header_t),
                                               value_buf_size - sizeof(sol_accountsdb_value_header_t),
                                               &bytes_written);
        if (serr != SOL_OK) {
            sol_free(value);
            sol_free(existing_value);
            ret = serr;
            goto out_backend;
        }

        size_t total_written = sizeof(sol_accountsdb_value_header_t) + bytes_written;
        ret = db->backend->put(db->backend->ctx,
                               pubkey->bytes, sizeof(pubkey->bytes),
                               value, total_written);
        sol_free(value);
        sol_free(existing_value);
        existing_value = NULL;

        if (ret == SOL_OK) {
            if (!existed_visible) {
                atomic_inc_u64(&db->stats.accounts_count);
                atomic_add_size(&db->account_count, 1u);
            } else {
                atomic_sub_u64(&db->stats.total_lamports, existing_lamports);
                atomic_sub_u64(&db->stats.total_data_bytes, existing_data_len);
            }
            atomic_add_u64(&db->stats.total_lamports, account->meta.lamports);
            atomic_add_u64(&db->stats.total_data_bytes, (uint64_t)account->meta.data_len);

            if (db->owner_index_backend) {
                const sol_pubkey_t* new_owner = &account->meta.owner;
                const bool track_new_owner = accounts_db_should_track_owner_live(db, new_owner);
                const bool track_old_owner =
                    existed_visible && existing_owner_ok &&
                    accounts_db_should_track_owner_live(db, &existing_rev.owner);

                if (track_old_owner &&
                    (!track_new_owner || !sol_pubkey_eq(&existing_rev.owner, new_owner))) {
                    sol_err_t derr = owner_index_del(db->owner_index_backend, &existing_rev.owner, pubkey);
                    if (derr != SOL_OK) {
                        ret = derr;
                        goto out_backend;
                    }
                }
                if (track_new_owner) {
                    sol_err_t perr = owner_index_put(db->owner_index_backend, new_owner, pubkey);
                    if (perr != SOL_OK) {
                        ret = perr;
                        goto out_backend;
                    }
                }
            }

            if (db->owner_reverse_backend) {
                owner_reverse_value_t val = {
                    .lamports = account->meta.lamports,
                    .data_len = account->meta.data_len,
                    .owner = account->meta.owner,
                };
                sol_err_t rerr = owner_reverse_put(db->owner_reverse_backend, pubkey, &val);
                if (rerr != SOL_OK) {
                    ret = rerr;
                    goto out_backend;
                }
            }
        }

    out_backend:
        if (db->stripe_locks) {
            pthread_rwlock_unlock(&db->stripe_locks[stripe]);
        }
        return ret;
    }

    /* Root in-memory backend (legacy). */
    pthread_rwlock_wrlock(&db->lock);

    db->stats.stores++;

    sol_err_t result = SOL_OK;

    /* Use in-memory hash table */
    size_t idx = pubkey_hash(pubkey, db->bucket_count);
    sol_account_entry_t* entry = find_entry(db->buckets[idx], pubkey);

        if (entry) {
            if (write_version != 0 && entry->write_version != 0 &&
                (entry->write_version > write_version ||
                 (entry->write_version == write_version && entry->slot >= slot))) {
                pthread_rwlock_unlock(&db->lock);
                return SOL_OK;
            }

            /* Update existing entry */
            sol_account_t* old = entry->account;

            /* Update stats */
            db->stats.total_lamports -= old->meta.lamports;
            db->stats.total_lamports += account->meta.lamports;
            db->stats.total_data_bytes -= old->meta.data_len;
            db->stats.total_data_bytes += account->meta.data_len;

            entry->account = sol_account_clone(account);
            if (!entry->account) {
                entry->account = old;  /* Restore on failure */
                pthread_rwlock_unlock(&db->lock);
                return SOL_ERR_NOMEM;
            }

            entry->slot = slot;
            entry->write_version = write_version;
            sol_account_destroy(old);
        } else {
            /* Create new entry */
            entry = sol_calloc(1, sizeof(sol_account_entry_t));
            if (!entry) {
                pthread_rwlock_unlock(&db->lock);
                return SOL_ERR_NOMEM;
            }

            entry->pubkey = *pubkey;
            entry->account = sol_account_clone(account);
            if (!entry->account) {
                sol_free(entry);
                pthread_rwlock_unlock(&db->lock);
                return SOL_ERR_NOMEM;
            }

            entry->slot = slot;
            entry->write_version = write_version;

            /* Insert at head of bucket */
            entry->next = db->buckets[idx];
            db->buckets[idx] = entry;
            db->account_count++;

            /* Update stats */
            db->stats.accounts_count++;
            db->stats.total_lamports += account->meta.lamports;
            db->stats.total_data_bytes += account->meta.data_len;
        }

    pthread_rwlock_unlock(&db->lock);
    return result;
}

sol_err_t
sol_accounts_db_store_versioned_with_prev_meta(sol_accounts_db_t* db,
                                               const sol_pubkey_t* pubkey,
                                               const sol_account_t* account,
                                               sol_slot_t slot,
                                               uint64_t write_version,
                                               bool prev_exists,
                                               uint64_t prev_lamports,
                                               uint64_t prev_data_len) {
    if (!db || !pubkey || !account) return SOL_ERR_INVAL;

    if (db->parent) {
        return accounts_db_store_fork_internal(db,
                                               pubkey,
                                               account,
                                               slot,
                                               write_version,
                                               prev_exists,
                                               prev_lamports,
                                               prev_data_len,
                                               true);
    }

    /* Persistent/non-overlay store path computes previous meta itself. */
    return sol_accounts_db_store_versioned(db, pubkey, account, slot, write_version);
}

sol_err_t
sol_accounts_db_delete(sol_accounts_db_t* db, const sol_pubkey_t* pubkey) {
    return sol_accounts_db_delete_versioned(db, pubkey, 0, 0);
}

static sol_err_t
accounts_db_delete_fork(sol_accounts_db_t* db,
                        const sol_pubkey_t* pubkey,
                        sol_slot_t slot,
                        uint64_t write_version) {
    if (!db || !db->parent || !pubkey) return SOL_ERR_INVAL;

    size_t idx = pubkey_hash(pubkey, db->bucket_count);
    size_t stripe = stripe_for_bucket(db, idx);

    /* Fast path: local entry exists (no parent lookup). */
    pthread_rwlock_rdlock(&db->lock);
    if (db->stripe_locks) {
        pthread_rwlock_wrlock(&db->stripe_locks[stripe]);
    }

    sol_account_entry_t* entry = find_entry(db->buckets[idx], pubkey);
    if (entry) {
        if (write_version != 0 && entry->write_version != 0 &&
            (entry->write_version > write_version ||
             (entry->write_version == write_version && entry->slot >= slot))) {
            if (db->stripe_locks) {
                pthread_rwlock_unlock(&db->stripe_locks[stripe]);
            }
            pthread_rwlock_unlock(&db->lock);
            return SOL_OK;
        }

        bool prev_exists = entry->account != NULL;
        uint64_t prev_lamports = prev_exists ? entry->account->meta.lamports : 0;
        uint64_t prev_data_len = prev_exists ? entry->account->meta.data_len : 0;

        sol_account_t* old = entry->account;
        if (old) {
            entry->account = NULL;
            atomic_sub_size(&db->account_count, 1u);
        }
        entry->slot = slot;
        entry->write_version = write_version;

        if (db->stripe_locks) {
            pthread_rwlock_unlock(&db->stripe_locks[stripe]);
        }
        pthread_rwlock_unlock(&db->lock);

        if (old) {
            sol_account_destroy(old);
        }

        if (prev_exists) {
            atomic_dec_u64_sat(&db->stats.accounts_count);
            atomic_sub_u64(&db->stats.total_lamports, prev_lamports);
            atomic_sub_u64(&db->stats.total_data_bytes, prev_data_len);
        }

        return SOL_OK;
    }

    if (db->stripe_locks) {
        pthread_rwlock_unlock(&db->stripe_locks[stripe]);
    }
    pthread_rwlock_unlock(&db->lock);

    /* Miss: consult the parent view. */
    bool prev_exists = false;
    uint64_t prev_lamports = 0;
    uint64_t prev_data_len = 0;
    prev_exists = accounts_db_lookup_meta_visible(db->parent, pubkey, &prev_lamports, &prev_data_len);

    /* Deleting a missing account in an overlay is a no-op. Avoid creating a
     * tombstone entry that would otherwise perturb the accounts-delta hash. */
    if (!prev_exists) {
        return SOL_OK;
    }

    sol_account_entry_t* new_entry = sol_calloc(1, sizeof(sol_account_entry_t));
    if (!new_entry) {
        return SOL_ERR_NOMEM;
    }
    new_entry->pubkey = *pubkey;
    new_entry->account = NULL; /* tombstone */
    new_entry->slot = slot;
    new_entry->write_version = write_version;

    pthread_rwlock_rdlock(&db->lock);
    if (db->stripe_locks) {
        pthread_rwlock_wrlock(&db->stripe_locks[stripe]);
    }

    entry = find_entry(db->buckets[idx], pubkey);
    if (entry) {
        /* Another writer won the race; handle as an update. */
        if (write_version != 0 && entry->write_version != 0 &&
            (entry->write_version > write_version ||
             (entry->write_version == write_version && entry->slot >= slot))) {
            if (db->stripe_locks) {
                pthread_rwlock_unlock(&db->stripe_locks[stripe]);
            }
            pthread_rwlock_unlock(&db->lock);
            sol_free(new_entry);
            return SOL_OK;
        }

        bool prev2_exists = entry->account != NULL;
        uint64_t prev2_lamports = prev2_exists ? entry->account->meta.lamports : 0;
        uint64_t prev2_data_len = prev2_exists ? entry->account->meta.data_len : 0;

        sol_account_t* old = entry->account;
        if (old) {
            entry->account = NULL;
            atomic_sub_size(&db->account_count, 1u);
        }
        entry->slot = slot;
        entry->write_version = write_version;

        if (db->stripe_locks) {
            pthread_rwlock_unlock(&db->stripe_locks[stripe]);
        }
        pthread_rwlock_unlock(&db->lock);

        sol_free(new_entry);

        if (old) {
            sol_account_destroy(old);
        }

        if (prev2_exists) {
            atomic_dec_u64_sat(&db->stats.accounts_count);
            atomic_sub_u64(&db->stats.total_lamports, prev2_lamports);
            atomic_sub_u64(&db->stats.total_data_bytes, prev2_data_len);
        }

        return SOL_OK;
    }

    new_entry->next = db->buckets[idx];
    db->buckets[idx] = new_entry;

    if (db->stripe_locks) {
        pthread_rwlock_unlock(&db->stripe_locks[stripe]);
    }
    pthread_rwlock_unlock(&db->lock);

    atomic_dec_u64_sat(&db->stats.accounts_count);
    atomic_sub_u64(&db->stats.total_lamports, prev_lamports);
    atomic_sub_u64(&db->stats.total_data_bytes, prev_data_len);
    return SOL_OK;
}

sol_err_t
sol_accounts_db_delete_versioned(sol_accounts_db_t* db,
                                 const sol_pubkey_t* pubkey,
                                 sol_slot_t slot,
                                 uint64_t write_version) {
    if (!db || !pubkey) return SOL_ERR_INVAL;

    if (db->parent) {
        return accounts_db_delete_fork(db, pubkey, slot, write_version);
    }

    /* Persistent delete: backend + per-stripe lock (no global db->lock). */
    if (db->backend) {
        size_t stripe = stripe_for_pubkey(db, pubkey);
        if (db->stripe_locks) {
            pthread_rwlock_wrlock(&db->stripe_locks[stripe]);
        }

        sol_err_t ret = SOL_OK;

        if (db->config.storage_type == SOL_ACCOUNTS_STORAGE_APPENDVEC) {
            owner_reverse_value_t existing_rev = {0};
            bool existing_rev_found = false;
            bool existing_owner_ok = false;
            uint64_t existing_lamports = 0;
            uint64_t existing_data_len = 0;
            bool existing_idx_hit = false;
            sol_appendvec_index_val_t existing_idx = {0};

            if (db->appendvec_index &&
                sol_appendvec_index_get(db->appendvec_index, pubkey, &existing_idx)) {
                existing_idx_hit = true;

                if (write_version != 0 &&
                    (existing_idx.write_version > write_version ||
                     (existing_idx.write_version == write_version && existing_idx.slot >= slot))) {
                    ret = SOL_OK;
                    goto out_backend;
                }

                existing_rev_found = true;
                existing_rev.owner = existing_idx.owner;
                existing_rev.lamports = existing_idx.lamports;
                existing_rev.data_len = existing_idx.data_len;

                if (existing_idx.lamports != 0 && !sol_hash_is_zero(&existing_idx.leaf_hash)) {
                    existing_owner_ok = true;
                    existing_lamports = existing_idx.lamports;
                    existing_data_len = existing_idx.data_len;
                }
            }

            if (!existing_idx_hit && db->owner_reverse_backend) {
                sol_err_t rerr = owner_reverse_get(db->owner_reverse_backend,
                                                   pubkey,
                                                   &existing_rev,
                                                   &existing_rev_found);
                if (rerr != SOL_OK) {
                    ret = rerr;
                    goto out_backend;
                }
                if (existing_rev_found &&
                    existing_rev.lamports != ~(uint64_t)0 &&
                    existing_rev.data_len != ~(uint64_t)0 &&
                    existing_rev.lamports != 0) {
                    existing_owner_ok = true;
                    existing_lamports = existing_rev.lamports;
                    existing_data_len = existing_rev.data_len;
                }
            }

            if (write_version != 0 && !existing_idx_hit) {
                uint8_t* existing_value = NULL;
                size_t existing_value_len = 0;
                sol_err_t gerr = db->backend->get(db->backend->ctx,
                                                  pubkey->bytes, sizeof(pubkey->bytes),
                                                  &existing_value, &existing_value_len);
                if (gerr == SOL_OK && existing_value) {
                    sol_slot_t existing_slot = 0;
                    uint64_t existing_write_version = 0;
                    const uint8_t* payload = NULL;
                    size_t payload_len = 0;
                    decode_backend_value(existing_value, existing_value_len,
                                         &existing_slot, &existing_write_version,
                                         &payload, &payload_len);
                    sol_free(existing_value);

                    if (existing_write_version > write_version ||
                        (existing_write_version == write_version && existing_slot >= slot)) {
                        ret = SOL_OK;
                        goto out_backend;
                    }
                } else if (existing_value) {
                    sol_free(existing_value);
                }
            }

            bool existed_visible = existing_rev_found &&
                                   existing_rev.lamports != ~(uint64_t)0 &&
                                   existing_rev.data_len != ~(uint64_t)0 &&
                                   existing_rev.lamports != 0;

            sol_accountsdb_appendvec_ref_v1_t ref = {0};
            uint8_t value_buf[sizeof(sol_accountsdb_value_header_t) + sizeof(ref)];
            sol_accountsdb_value_header_t hdr = {
                .magic = SOL_ACCOUNTSDB_VALUE_MAGIC,
                .reserved = 0,
                .slot = (uint64_t)slot,
                .write_version = write_version,
            };
            memcpy(value_buf, &hdr, sizeof(hdr));
            memcpy(value_buf + sizeof(hdr), &ref, sizeof(ref));

            sol_err_t perr = db->backend->put(db->backend->ctx,
                                              pubkey->bytes, sizeof(pubkey->bytes),
                                              value_buf, sizeof(value_buf));
            if (perr != SOL_OK) {
                ret = perr;
                goto out_backend;
            }

            if (existed_visible) {
                atomic_dec_u64_sat(&db->stats.accounts_count);
                atomic_sub_size(&db->account_count, 1u);
                atomic_sub_u64(&db->stats.total_lamports, existing_lamports);
                atomic_sub_u64(&db->stats.total_data_bytes, existing_data_len);
            }

            if (db->owner_index_backend && existed_visible && existing_owner_ok &&
                accounts_db_should_track_owner_live(db, &existing_rev.owner)) {
                sol_err_t derr = owner_index_del(db->owner_index_backend, &existing_rev.owner, pubkey);
                if (derr != SOL_OK) {
                    ret = derr;
                    goto out_backend;
                }
            }

            if (db->owner_reverse_backend && existed_visible) {
                sol_err_t rerr = owner_reverse_del(db->owner_reverse_backend, pubkey);
                if (rerr != SOL_OK) {
                    ret = rerr;
                    goto out_backend;
                }
            }

            if (db->appendvec_index) {
                (void)sol_appendvec_index_update(db->appendvec_index,
                                                 pubkey,
                                                 slot,
                                                 write_version,
                                                 NULL,
                                                 0,
                                                 0,
                                                 0,
                                                 0,
                                                 NULL);
            }

            ret = SOL_OK;
            goto out_backend;
        }

        owner_reverse_value_t existing_rev = {0};
        bool existing_rev_found = false;
        bool existing_owner_ok = false;
        uint64_t existing_lamports = 0;
        uint64_t existing_data_len = 0;
        sol_slot_t existing_slot = 0;
        uint64_t existing_write_version = 0;

        if (db->owner_reverse_backend) {
            sol_err_t rerr = owner_reverse_get(db->owner_reverse_backend,
                                               pubkey,
                                               &existing_rev,
                                               &existing_rev_found);
            if (rerr != SOL_OK) {
                ret = rerr;
                goto out_backend;
            }
            if (existing_rev_found) {
                if (existing_rev.lamports == ~(uint64_t)0 ||
                    existing_rev.data_len == ~(uint64_t)0) {
                    existing_rev_found = false;
                } else {
                    existing_owner_ok = true;
                    existing_lamports = existing_rev.lamports;
                    existing_data_len = existing_rev.data_len;
                }
            }
        }

        if (write_version != 0 || !existing_rev_found) {
            uint8_t* existing_value = NULL;
            size_t existing_value_len = 0;
            sol_err_t gerr = db->backend->get(db->backend->ctx,
                                              pubkey->bytes, sizeof(pubkey->bytes),
                                              &existing_value, &existing_value_len);
            if (gerr != SOL_OK || !existing_value) {
                ret = SOL_OK;
                goto out_backend;
            }

            const uint8_t* account_bytes = NULL;
            size_t account_len = 0;
            decode_backend_value(existing_value, existing_value_len,
                                 &existing_slot, &existing_write_version,
                                 &account_bytes, &account_len);

            if (write_version != 0 &&
                (existing_write_version > write_version ||
                 (existing_write_version == write_version && existing_slot >= slot))) {
                sol_free(existing_value);
                ret = SOL_OK;
                goto out_backend;
            }

            if (!existing_rev_found) {
                existing_owner_ok = parse_serialized_account_owner(
                    account_bytes, account_len, &existing_rev.owner);
                (void)parse_serialized_account_meta(account_bytes, account_len,
                                                    &existing_lamports, &existing_data_len);
            }

            sol_free(existing_value);
        }

        bool existed_visible = existing_rev_found || (existing_lamports != 0);

        ret = db->backend->del(db->backend->ctx,
                               pubkey->bytes, sizeof(pubkey->bytes));
        if (ret == SOL_ERR_NOTFOUND) {
            ret = SOL_OK;
        }

        if (ret == SOL_OK) {
            if (existed_visible) {
                atomic_dec_u64_sat(&db->stats.accounts_count);
                atomic_sub_size(&db->account_count, 1u);
                atomic_sub_u64(&db->stats.total_lamports, existing_lamports);
                atomic_sub_u64(&db->stats.total_data_bytes, existing_data_len);
            }

            if (db->owner_index_backend && existed_visible && existing_owner_ok &&
                accounts_db_should_track_owner_live(db, &existing_rev.owner)) {
                sol_err_t derr = owner_index_del(db->owner_index_backend, &existing_rev.owner, pubkey);
                if (derr != SOL_OK) {
                    ret = derr;
                    goto out_backend;
                }
            }

            if (db->owner_reverse_backend && existed_visible) {
                sol_err_t rerr = owner_reverse_del(db->owner_reverse_backend, pubkey);
                if (rerr != SOL_OK) {
                    ret = rerr;
                    goto out_backend;
                }
            }
        }

    out_backend:
        if (db->stripe_locks) {
            pthread_rwlock_unlock(&db->stripe_locks[stripe]);
        }
        return ret;
    }

    /* Root in-memory backend (legacy). */
    pthread_rwlock_wrlock(&db->lock);

    sol_err_t result = SOL_OK;

    /* Use in-memory hash table */
    size_t idx = pubkey_hash(pubkey, db->bucket_count);

    sol_account_entry_t** prev_ptr = &db->buckets[idx];
    sol_account_entry_t* entry = db->buckets[idx];

    while (entry) {
        if (sol_pubkey_eq(&entry->pubkey, pubkey)) {
            if (write_version != 0 && entry->write_version != 0 &&
                (entry->write_version > write_version ||
                 (entry->write_version == write_version && entry->slot >= slot))) {
                pthread_rwlock_unlock(&db->lock);
                return SOL_OK;
            }

            *prev_ptr = entry->next;

            /* Update stats */
            db->stats.accounts_count--;
            db->stats.total_lamports -= entry->account->meta.lamports;
            db->stats.total_data_bytes -= entry->account->meta.data_len;

            sol_account_destroy(entry->account);
            sol_free(entry);
            db->account_count--;

            pthread_rwlock_unlock(&db->lock);
            return SOL_OK;
        }

        prev_ptr = &entry->next;
        entry = entry->next;
    }

    result = SOL_OK;

    pthread_rwlock_unlock(&db->lock);
    return result;
}

bool
sol_accounts_db_is_overlay(const sol_accounts_db_t* db) {
    if (!db) return false;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&db->lock);
    bool is_overlay = db->parent != NULL;
    pthread_rwlock_unlock((pthread_rwlock_t*)&db->lock);
    return is_overlay;
}

bool
sol_accounts_db_is_appendvec(const sol_accounts_db_t* db) {
    if (!db) return false;
    const sol_accounts_db_t* root = db;
    while (root && root->parent) root = root->parent;
    return root &&
           root->config.storage_type == SOL_ACCOUNTS_STORAGE_APPENDVEC &&
           root->appendvec_dir != NULL &&
           root->appendvec_dir[0] != '\0';
}

const char*
sol_accounts_db_appendvec_path(const sol_accounts_db_t* db) {
    if (!db) return NULL;
    const sol_accounts_db_t* root = db;
    while (root && root->parent) root = root->parent;
    if (!root || root->config.storage_type != SOL_ACCOUNTS_STORAGE_APPENDVEC) {
        return NULL;
    }
    return root->appendvec_dir;
}

sol_accounts_db_local_kind_t
sol_accounts_db_get_local_kind(sol_accounts_db_t* db,
                               const sol_pubkey_t* pubkey,
                               sol_account_t** out_account) {
    if (out_account) {
        *out_account = NULL;
    }
    if (!db || !pubkey) return SOL_ACCOUNTS_DB_LOCAL_MISSING;

    pthread_rwlock_rdlock(&db->lock);

    if (db->backend) {
        pthread_rwlock_unlock(&db->lock);
        return SOL_ACCOUNTS_DB_LOCAL_MISSING;
    }

    size_t idx = pubkey_hash(pubkey, db->bucket_count);
    size_t stripe = stripe_for_bucket(db, idx);
    if (db->stripe_locks) {
        pthread_rwlock_rdlock(&db->stripe_locks[stripe]);
    }

    sol_account_entry_t* entry = find_entry(db->buckets[idx], pubkey);
    if (!entry) {
        if (db->stripe_locks) {
            pthread_rwlock_unlock(&db->stripe_locks[stripe]);
        }
        pthread_rwlock_unlock(&db->lock);
        return SOL_ACCOUNTS_DB_LOCAL_MISSING;
    }

    if (!entry->account || entry->account->meta.lamports == 0) {
        if (db->stripe_locks) {
            pthread_rwlock_unlock(&db->stripe_locks[stripe]);
        }
        pthread_rwlock_unlock(&db->lock);
        return SOL_ACCOUNTS_DB_LOCAL_TOMBSTONE;
    }

    /* Fast path: caller only needs to know whether a local override exists. */
    if (!out_account) {
        if (db->stripe_locks) {
            pthread_rwlock_unlock(&db->stripe_locks[stripe]);
        }
        pthread_rwlock_unlock(&db->lock);
        return SOL_ACCOUNTS_DB_LOCAL_ACCOUNT;
    }

    sol_account_t* clone = sol_account_clone(entry->account);

    if (db->stripe_locks) {
        pthread_rwlock_unlock(&db->stripe_locks[stripe]);
    }
    pthread_rwlock_unlock(&db->lock);

    if (!clone) {
        return SOL_ACCOUNTS_DB_LOCAL_MISSING;
    }

    *out_account = clone;
    return SOL_ACCOUNTS_DB_LOCAL_ACCOUNT;
}

sol_err_t
sol_accounts_db_clear_override(sol_accounts_db_t* db, const sol_pubkey_t* pubkey) {
    if (!db || !pubkey) return SOL_ERR_INVAL;

    pthread_rwlock_rdlock(&db->lock);

    if (!db->parent || db->backend) {
        pthread_rwlock_unlock(&db->lock);
        return SOL_ERR_INVAL;
    }

    size_t idx = pubkey_hash(pubkey, db->bucket_count);
    size_t stripe = stripe_for_bucket(db, idx);
    if (db->stripe_locks) {
        pthread_rwlock_wrlock(&db->stripe_locks[stripe]);
    }

    sol_account_entry_t** prev_ptr = &db->buckets[idx];
    sol_account_entry_t* entry = db->buckets[idx];

    while (entry) {
        if (sol_pubkey_eq(&entry->pubkey, pubkey)) {
            bool prev_exists = entry->account != NULL;
            uint64_t prev_lamports = prev_exists ? entry->account->meta.lamports : 0;
            uint64_t prev_data_len = prev_exists ? entry->account->meta.data_len : 0;

            /* Unlink entry from the local layer. */
            *prev_ptr = entry->next;

            sol_account_t* old = entry->account;
            entry->account = NULL;

            if (prev_exists) {
                atomic_sub_size(&db->account_count, 1u);
            }

            if (db->stripe_locks) {
                pthread_rwlock_unlock(&db->stripe_locks[stripe]);
            }
            pthread_rwlock_unlock(&db->lock);

            /* Fetch next visible meta from parent outside bucket locks. */
            bool next_exists = false;
            uint64_t next_lamports = 0;
            uint64_t next_data_len = 0;
            next_exists = accounts_db_lookup_meta_visible(db->parent, pubkey, &next_lamports, &next_data_len);

            if (prev_exists) {
                atomic_sub_u64(&db->stats.total_lamports, prev_lamports);
                atomic_sub_u64(&db->stats.total_data_bytes, prev_data_len);
            }

            if (prev_exists && !next_exists) {
                atomic_dec_u64_sat(&db->stats.accounts_count);
            } else if (!prev_exists && next_exists) {
                atomic_inc_u64(&db->stats.accounts_count);
            }

            if (next_exists) {
                atomic_add_u64(&db->stats.total_lamports, next_lamports);
                atomic_add_u64(&db->stats.total_data_bytes, next_data_len);
            }

            if (old) {
                sol_account_destroy(old);
            }
            sol_free(entry);
            return SOL_OK;
        }

        prev_ptr = &entry->next;
        entry = entry->next;
    }

    if (db->stripe_locks) {
        pthread_rwlock_unlock(&db->stripe_locks[stripe]);
    }
    pthread_rwlock_unlock(&db->lock);
    return SOL_OK;
}

size_t
sol_accounts_db_count(const sol_accounts_db_t* db) {
    if (!db) return 0;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&db->lock);

    size_t count;
    if (db->parent) {
        /* Overlay views track effective counts in stats */
        count = (size_t)atomic_load_u64(&db->stats.accounts_count);
    } else if (db->backend) {
        count = db->backend->count(db->backend->ctx);
    } else {
        count = db->account_count;
    }

    pthread_rwlock_unlock((pthread_rwlock_t*)&db->lock);

    return count;
}

uint64_t
sol_accounts_db_total_lamports(const sol_accounts_db_t* db) {
    if (!db) return 0;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&db->lock);
    uint64_t total = atomic_load_u64(&db->stats.total_lamports);
    pthread_rwlock_unlock((pthread_rwlock_t*)&db->lock);

    return total;
}

/*
 * Helper for backend iteration - wraps account callback
 */
typedef struct {
    sol_accounts_db_t*        db;
    sol_accounts_db_iter_cb callback;
    void*                   user_ctx;
} backend_iter_ctx_t;

typedef struct {
    sol_pubkey_map_t*        overrides;
    sol_accounts_db_iter_cb  callback;
    void*                    user_ctx;
    bool                     stop;
} overlay_iter_ctx_t;

typedef struct {
    sol_accounts_db_t* snapshot;
    bool               failed;
} accounts_snapshot_ctx_t;

static bool
accounts_snapshot_cb(const sol_pubkey_t* pubkey, const sol_account_t* account, void* ctx) {
    accounts_snapshot_ctx_t* s = (accounts_snapshot_ctx_t*)ctx;
    if (!s || s->failed) return false;
    if (!pubkey || !account) return true;
    if (sol_accounts_db_store(s->snapshot, pubkey, account) != SOL_OK) {
        s->failed = true;
        return false;
    }
    return true;
}

static bool
overlay_parent_iter_cb(const sol_pubkey_t* pubkey, const sol_account_t* account, void* vctx) {
    overlay_iter_ctx_t* o = (overlay_iter_ctx_t*)vctx;
    if (!o || o->stop) return false;

    if (sol_pubkey_map_get(o->overrides, pubkey) != NULL) {
        return true;
    }

    bool cont = o->callback(pubkey, account, o->user_ctx);
    if (!cont) o->stop = true;
    return cont;
}

static bool
backend_iter_wrapper(const uint8_t* key, size_t key_len,
                     const uint8_t* value, size_t value_len, void* ctx) {
    (void)key_len;  /* Should be 32 (pubkey size) */

    backend_iter_ctx_t* bctx = ctx;
    if (!bctx || !bctx->db) return true;
    sol_pubkey_t pubkey;
    memcpy(pubkey.bytes, key, sizeof(pubkey.bytes));

    const uint8_t* payload = NULL;
    size_t payload_len = 0;
    decode_backend_value(value, value_len, NULL, NULL, &payload, &payload_len);

    if (bctx->db->config.storage_type == SOL_ACCOUNTS_STORAGE_APPENDVEC) {
        sol_accountsdb_appendvec_ref_v1_t ref = {0};
        if (!appendvec_ref_decode(payload, payload_len, &ref)) {
            return true; /* skip invalid entry */
        }
        if (sol_hash_is_zero(&ref.account_hash)) {
            return true; /* tombstone/deleted */
        }

        sol_account_t* loaded = NULL;
        sol_err_t lerr = appendvec_load_account_by_ref(bctx->db, &pubkey, &ref, &loaded);
        if (lerr != SOL_OK || !loaded) {
            return true;
        }

        bool cont = bctx->callback(&pubkey, loaded, bctx->user_ctx);
        sol_account_destroy(loaded);
        return cont;
    }

    /* RocksDB value backend: payload is serialized account bytes. */
    sol_account_t account = {0};
    size_t consumed = 0;
    sol_err_t err = sol_account_deserialize(&account, payload, payload_len, &consumed);
    if (err != SOL_OK) return true;  /* Skip invalid entries */

    if (account.meta.lamports == 0) {
        sol_account_cleanup(&account);
        return true;
    }

    bool cont = bctx->callback(&pubkey, &account, bctx->user_ctx);
    sol_account_cleanup(&account);
    return cont;
}

void
sol_accounts_db_iterate(sol_accounts_db_t* db, sol_accounts_db_iter_cb callback,
                        void* ctx) {
    if (!db || !callback) return;

    /* Overlay view: parent iteration filtered by local overrides, then local
     * entries (non-tombstone). */
    if (db->parent) {
        typedef struct {
            sol_pubkey_t   pubkey;
            sol_account_t* account; /* NULL for tombstone */
        } overlay_entry_t;

        typedef struct {
            overlay_entry_t* entries;
            size_t           len;
            size_t           cap;
            sol_err_t        err;
        } overlay_snapshot_t;

        overlay_snapshot_t snap = {0};
        snap.err = SOL_OK;

        /* Take an exclusive lock while snapshotting the local overlay.
         * Overlay writers only take a shared lock plus stripe locks, so
         * rdlock here is insufficient. */
        pthread_rwlock_wrlock(&db->lock);
        for (size_t i = 0; i < db->bucket_count && snap.err == SOL_OK; i++) {
            sol_account_entry_t* entry = db->buckets[i];
            while (entry && snap.err == SOL_OK) {
                if (snap.len == snap.cap) {
                    size_t new_cap = snap.cap ? (snap.cap * 2) : 128;
                    if (new_cap < snap.cap) {
                        snap.err = SOL_ERR_OVERFLOW;
                        break;
                    }
                    overlay_entry_t* new_entries = sol_realloc(snap.entries, new_cap * sizeof(*new_entries));
                    if (!new_entries) {
                        snap.err = SOL_ERR_NOMEM;
                        break;
                    }
                    snap.entries = new_entries;
                    snap.cap = new_cap;
                }

                overlay_entry_t* dst = &snap.entries[snap.len++];
                dst->pubkey = entry->pubkey;
                dst->account = entry->account ? sol_account_clone(entry->account) : NULL;
                if (entry->account && !dst->account) {
                    snap.err = SOL_ERR_NOMEM;
                    break;
                }
                if (dst->account && dst->account->meta.lamports == 0) {
                    sol_account_destroy(dst->account);
                    dst->account = NULL; /* treat as tombstone */
                }

                entry = entry->next;
            }
        }
        pthread_rwlock_unlock(&db->lock);

        if (snap.err != SOL_OK) {
            for (size_t i = 0; i < snap.len; i++) {
                if (snap.entries[i].account) sol_account_destroy(snap.entries[i].account);
            }
            sol_free(snap.entries);
            return;
        }

        sol_pubkey_map_t* overrides = sol_pubkey_map_new(sizeof(uint8_t), snap.len * 2);
        if (!overrides) {
            for (size_t i = 0; i < snap.len; i++) {
                if (snap.entries[i].account) sol_account_destroy(snap.entries[i].account);
            }
            sol_free(snap.entries);
            return;
        }

        for (size_t i = 0; i < snap.len; i++) {
            uint8_t one = 1;
            (void)sol_pubkey_map_insert(overrides, &snap.entries[i].pubkey, &one);
        }

        overlay_iter_ctx_t octx = {
            .overrides = overrides,
            .callback = callback,
            .user_ctx = ctx,
            .stop = false,
        };

        sol_accounts_db_iterate(db->parent, overlay_parent_iter_cb, &octx);

        if (!octx.stop) {
            for (size_t i = 0; i < snap.len; i++) {
                if (snap.entries[i].account == NULL) {
                    continue; /* tombstone */
                }
                if (!callback(&snap.entries[i].pubkey, snap.entries[i].account, ctx)) {
                    break;
                }
            }
        }

        sol_pubkey_map_destroy(overrides);
        for (size_t i = 0; i < snap.len; i++) {
            if (snap.entries[i].account) sol_account_destroy(snap.entries[i].account);
        }
        sol_free(snap.entries);
        return;
    }

    pthread_rwlock_rdlock(&db->lock);

    if (db->backend) {
        /* Use storage backend iteration */
        backend_iter_ctx_t bctx = {
            .db = db,
            .callback = callback,
            .user_ctx = ctx
        };
        db->backend->iterate(db->backend->ctx, backend_iter_wrapper, &bctx);
    } else {
        /* Use in-memory hash table */
        for (size_t i = 0; i < db->bucket_count; i++) {
            sol_account_entry_t* entry = db->buckets[i];
            while (entry) {
                if (!entry->account) {
                    entry = entry->next;
                    continue;
                }
                if (entry->account->meta.lamports == 0) {
                    entry = entry->next;
                    continue;
                }
                if (!callback(&entry->pubkey, entry->account, ctx)) {
                    pthread_rwlock_unlock(&db->lock);
                    return;
                }
                entry = entry->next;
            }
        }
    }

    pthread_rwlock_unlock(&db->lock);
}

/*
 * Iterate accounts in pubkey range [start, end] (inclusive).
 */
typedef struct {
    sol_accounts_db_t*      db;
    const sol_pubkey_t*     end_inclusive;
    sol_accounts_db_iter_cb callback;
    void*                   user_ctx;
} pubkey_range_iter_ctx_t;

static bool
pubkey_range_backend_cb(const uint8_t* key, size_t key_len,
                        const uint8_t* value, size_t value_len, void* ctx) {
    pubkey_range_iter_ctx_t* rctx = ctx;
    if (!rctx || !rctx->db || !key || key_len < 32) return false;

    sol_pubkey_t pubkey;
    memcpy(pubkey.bytes, key, 32);

    /* Check if past the inclusive end */
    if (rctx->end_inclusive && memcmp(pubkey.bytes, rctx->end_inclusive->bytes, 32) > 0) {
        return false;  /* stop iteration */
    }

    const uint8_t* payload = NULL;
    size_t payload_len = 0;
    decode_backend_value(value, value_len, NULL, NULL, &payload, &payload_len);

    if (rctx->db->config.storage_type == SOL_ACCOUNTS_STORAGE_APPENDVEC) {
        sol_accountsdb_appendvec_ref_v1_t ref = {0};
        if (!appendvec_ref_decode(payload, payload_len, &ref)) return true;
        if (sol_hash_is_zero(&ref.account_hash)) return true;

        sol_account_t* loaded = NULL;
        sol_err_t lerr = appendvec_load_account_by_ref(rctx->db, &pubkey, &ref, &loaded);
        if (lerr != SOL_OK || !loaded) return true;

        bool cont = rctx->callback(&pubkey, loaded, rctx->user_ctx);
        sol_account_destroy(loaded);
        return cont;
    } else {
        sol_account_t acct;
        memset(&acct, 0, sizeof(acct));
        size_t consumed = 0;
        sol_err_t err = sol_account_deserialize(&acct, payload, payload_len, &consumed);
        if (err != SOL_OK) return true;
        bool cont = rctx->callback(&pubkey, &acct, rctx->user_ctx);
        sol_free(acct.data);
        return cont;
    }
}

void
sol_accounts_db_iterate_pubkey_range(sol_accounts_db_t* db,
                                     const sol_pubkey_t* start,
                                     const sol_pubkey_t* end,
                                     sol_accounts_db_iter_cb callback,
                                     void* ctx) {
    if (!db || !callback) return;

    /* Walk up to root for backend access */
    sol_accounts_db_t* root = db;
    while (root->parent) root = root->parent;

    if (!root->backend || !root->backend->iterate_range) {
        /* Not implemented for in-memory backend.
         * The parity test always uses AppendVec/RocksDB. */
        (void)start; (void)end; (void)callback; (void)ctx;
        return;
    }

    /* Compute exclusive end key: end + 1 byte (or NULL for unbounded) */
    uint8_t end_exclusive[32];
    bool has_end_exclusive = false;
    if (end) {
        memcpy(end_exclusive, end->bytes, 32);
        /* Increment by 1 */
        for (int i = 31; i >= 0; i--) {
            if (end_exclusive[i] != 0xFF) {
                end_exclusive[i]++;
                memset(end_exclusive + i + 1, 0, (size_t)(31 - i));
                has_end_exclusive = true;
                break;
            }
        }
        /* If all 0xFF, no exclusive end (iterate to end) */
    }

    pthread_rwlock_rdlock(&root->lock);

    pubkey_range_iter_ctx_t rctx = {
        .db = root,
        .end_inclusive = end,
        .callback = callback,
        .user_ctx = ctx,
    };

    root->backend->iterate_range(
        root->backend->ctx,
        start ? start->bytes : NULL,
        start ? 32 : 0,
        has_end_exclusive ? end_exclusive : NULL,
        has_end_exclusive ? 32 : 0,
        pubkey_range_backend_cb,
        &rctx
    );

    pthread_rwlock_unlock(&root->lock);
}

bool
sol_accounts_db_iterate_pubkey_range_supported(const sol_accounts_db_t* db) {
    if (!db) return false;

    const sol_accounts_db_t* root = db;
    while (root->parent) root = root->parent;
    return root->backend && root->backend->iterate_range;
}

typedef struct {
    const sol_pubkey_t*     owner;
    sol_accounts_db_iter_cb callback;
    void*                   user_ctx;
} owner_filter_ctx_t;

static bool
owner_filter_iter_cb(const sol_pubkey_t* pubkey,
                     const sol_account_t* account,
                     void* ctx) {
    owner_filter_ctx_t* f = (owner_filter_ctx_t*)ctx;
    if (!f || !pubkey || !account) return false;
    if (!sol_pubkey_eq(&account->meta.owner, f->owner)) return true;
    return f->callback(pubkey, account, f->user_ctx);
}

typedef struct {
    sol_accounts_db_t*      view;
    const sol_pubkey_t*     owner;
    sol_pubkey_map_t*       overrides;
    sol_accounts_db_iter_cb callback;
    void*                   user_ctx;
    bool                    stop;
} owner_index_iter_ctx_t;

static bool
owner_index_iter_cb(const uint8_t* key,
                    size_t key_len,
                    const uint8_t* value,
                    size_t value_len,
                    void* ctx) {
    (void)value;
    (void)value_len;

    owner_index_iter_ctx_t* o = (owner_index_iter_ctx_t*)ctx;
    if (!o || o->stop) return false;

    if (!key || key_len != 64) {
        return true;
    }

    sol_pubkey_t pubkey;
    memcpy(pubkey.bytes, key + 32, 32);

    if (o->overrides && sol_pubkey_map_get(o->overrides, &pubkey) != NULL) {
        return true;
    }

    sol_account_t* account = sol_accounts_db_load(o->view, &pubkey);
    if (!account) {
        return true;
    }

    bool cont = true;
    if (sol_pubkey_eq(&account->meta.owner, o->owner)) {
        cont = o->callback(&pubkey, account, o->user_ctx);
    }

    sol_account_destroy(account);

    if (!cont) {
        o->stop = true;
    }

    return cont;
}

typedef struct {
    sol_accounts_db_t*      view;
    const sol_pubkey_t*     owner;
    sol_pubkey_map_t*       overrides;
    sol_accounts_db_iter_cb callback;
    void*                   user_ctx;
    bool                    stop;
} owner_reverse_iter_ctx_t;

static bool
owner_reverse_iter_cb(const uint8_t* key,
                      size_t key_len,
                      const uint8_t* value,
                      size_t value_len,
                      void* ctx) {
    owner_reverse_iter_ctx_t* r = (owner_reverse_iter_ctx_t*)ctx;
    if (!r || r->stop) return false;

    if (!key || key_len != 32) {
        return true;
    }

    owner_reverse_value_t rev = {0};
    if (!owner_reverse_decode(value, value_len, &rev)) {
        return true;
    }
    if (rev.lamports == 0) {
        return true;
    }
    if (!sol_pubkey_eq(&rev.owner, r->owner)) {
        return true;
    }

    sol_pubkey_t pubkey;
    memcpy(pubkey.bytes, key, 32);

    if (r->overrides && sol_pubkey_map_get(r->overrides, &pubkey) != NULL) {
        return true;
    }

    sol_account_t* account = sol_accounts_db_load(r->view, &pubkey);
    if (!account) {
        return true;
    }

    bool cont = true;
    if (sol_pubkey_eq(&account->meta.owner, r->owner)) {
        cont = r->callback(&pubkey, account, r->user_ctx);
    }

    sol_account_destroy(account);

    if (!cont) {
        r->stop = true;
    }

    return cont;
}

typedef struct {
    const sol_pubkey_t*     owner;
    sol_accounts_db_iter_cb callback;
    void*                   user_ctx;
    bool                    stop;
} owner_local_iter_ctx_t;

static bool
owner_local_iter_cb(sol_accounts_db_t* parent,
                    const sol_pubkey_t* pubkey,
                    const sol_account_t* account,
                    void* ctx) {
    (void)parent;

    owner_local_iter_ctx_t* l = (owner_local_iter_ctx_t*)ctx;
    if (!l || l->stop) return false;
    if (!pubkey) return false;
    if (!account) return true; /* tombstone */
    if (!sol_pubkey_eq(&account->meta.owner, l->owner)) return true;

    bool cont = l->callback(pubkey, account, l->user_ctx);
    if (!cont) {
        l->stop = true;
    }
    return cont;
}

static bool
prefix_next(uint8_t* buf, size_t len) {
    if (!buf || len == 0) return false;
    for (size_t i = len; i-- > 0;) {
        if (buf[i] != 0xFF) {
            buf[i]++;
            memset(buf + i + 1, 0, len - i - 1);
            return true;
        }
    }
    return false;
}

void
sol_accounts_db_iterate_owner(sol_accounts_db_t* db,
                              const sol_pubkey_t* owner,
                              sol_accounts_db_iter_cb callback,
                              void* ctx) {
    if (!db || !owner || !callback) return;

    sol_accounts_db_t* root = accounts_db_root(db);
    bool can_use_index = accounts_db_can_use_owner_index(root, owner);
    bool can_use_reverse = root &&
                           root->owner_reverse_backend &&
                           root->owner_reverse_backend->iterate &&
                           accounts_db_can_use_owner_reverse(root);

    if (!can_use_index && !can_use_reverse) {
        owner_filter_ctx_t fctx = {
            .owner = owner,
            .callback = callback,
            .user_ctx = ctx,
        };
        sol_accounts_db_iterate(db, owner_filter_iter_cb, &fctx);
        return;
    }

    sol_pubkey_map_t* overrides = NULL;

    if (db->parent && !db->backend) {
        size_t cap = 128;
        size_t len = 0;
        sol_pubkey_t* keys = sol_alloc(cap * sizeof(*keys));
        if (!keys) {
            owner_filter_ctx_t fctx = {
                .owner = owner,
                .callback = callback,
                .user_ctx = ctx,
            };
            sol_accounts_db_iterate(db, owner_filter_iter_cb, &fctx);
            return;
        }

        bool ok = true;
        pthread_rwlock_rdlock(&db->lock);
        for (size_t i = 0; i < db->bucket_count && ok; i++) {
            sol_account_entry_t* entry = db->buckets[i];
            while (entry) {
                if (len == cap) {
                    size_t new_cap = cap * 2;
                    sol_pubkey_t* next = sol_realloc(keys, new_cap * sizeof(*keys));
                    if (!next) {
                        ok = false;
                        break;
                    }
                    keys = next;
                    cap = new_cap;
                }
                keys[len++] = entry->pubkey;
                entry = entry->next;
            }
        }
        pthread_rwlock_unlock(&db->lock);

        if (!ok) {
            sol_free(keys);
            owner_filter_ctx_t fctx = {
                .owner = owner,
                .callback = callback,
                .user_ctx = ctx,
            };
            sol_accounts_db_iterate(db, owner_filter_iter_cb, &fctx);
            return;
        }

        overrides = sol_pubkey_map_new(sizeof(uint8_t), len * 2);
        if (!overrides) {
            sol_free(keys);
            owner_filter_ctx_t fctx = {
                .owner = owner,
                .callback = callback,
                .user_ctx = ctx,
            };
            sol_accounts_db_iterate(db, owner_filter_iter_cb, &fctx);
            return;
        }

        for (size_t i = 0; i < len; i++) {
            uint8_t one = 1;
            (void)sol_pubkey_map_insert(overrides, &keys[i], &one);
        }

        sol_free(keys);
    }

    bool stop = false;

    if (can_use_index) {
        uint8_t start[32];
        memcpy(start, owner->bytes, 32);

        uint8_t end[32];
        memcpy(end, owner->bytes, 32);
        bool has_end = prefix_next(end, sizeof(end));

        owner_index_iter_ctx_t octx = {
            .view = db,
            .owner = owner,
            .overrides = overrides,
            .callback = callback,
            .user_ctx = ctx,
            .stop = false,
        };

        root->owner_index_backend->iterate_range(root->owner_index_backend->ctx,
                                                 start, sizeof(start),
                                                 has_end ? end : NULL,
                                                 has_end ? sizeof(end) : 0,
                                                 owner_index_iter_cb,
                                                 &octx);

        stop = octx.stop;
    } else if (can_use_reverse) {
        owner_reverse_iter_ctx_t rctx = {
            .view = db,
            .owner = owner,
            .overrides = overrides,
            .callback = callback,
            .user_ctx = ctx,
            .stop = false,
        };
        root->owner_reverse_backend->iterate(root->owner_reverse_backend->ctx,
                                             owner_reverse_iter_cb,
                                             &rctx);
        stop = rctx.stop;
    } else {
        owner_filter_ctx_t fctx = {
            .owner = owner,
            .callback = callback,
            .user_ctx = ctx,
        };
        sol_accounts_db_iterate(db, owner_filter_iter_cb, &fctx);
        stop = false;
    }

    if (db->parent && !db->backend && !stop) {
        owner_local_iter_ctx_t lctx = {
            .owner = owner,
            .callback = callback,
            .user_ctx = ctx,
            .stop = false,
        };
        (void)sol_accounts_db_iterate_local(db, owner_local_iter_cb, &lctx);
    }

    if (overrides) {
        sol_pubkey_map_destroy(overrides);
    }
}

typedef struct {
    sol_storage_backend_t* idx;
    sol_storage_backend_t* rev;
    sol_storage_backend_t* accounts;
    sol_storage_batch_t*   batch;
    sol_storage_batch_t*   rev_batch;
    sol_arena_t*           arena;
    size_t                 bytes_queued;
    sol_err_t              err;
    uint64_t               keys_seen;
    uint64_t               accounts_seen;
    uint64_t               total_lamports;
    uint64_t               total_data_bytes;
    uint64_t               entries_added;
    uint64_t               rev_entries_added;
    uint64_t               start_ms;
    uint64_t               last_log_ms;
    uint64_t               fallback_lookups;
} owner_index_build_ctx_t;

static sol_err_t
owner_index_build_flush(owner_index_build_ctx_t* c) {
    if (!c) return SOL_ERR_INVAL;
    if (c->err != SOL_OK) return c->err;
    if ((!c->batch || c->batch->count == 0) &&
        (!c->rev_batch || c->rev_batch->count == 0)) {
        return SOL_OK;
    }

    if (c->batch && c->batch->count > 0) {
        sol_err_t err = c->idx->batch_write(c->idx->ctx, c->batch);
        if (err != SOL_OK) return err;
        sol_storage_batch_clear(c->batch);
    }

    if (c->rev_batch && c->rev_batch->count > 0) {
        sol_err_t err = c->rev->batch_write(c->rev->ctx, c->rev_batch);
        if (err != SOL_OK) return err;
        sol_storage_batch_clear(c->rev_batch);
    }

    sol_arena_reset(c->arena);
    c->bytes_queued = 0;
    return SOL_OK;
}

static bool
owner_index_build_iter_cb(const uint8_t* key,
                          size_t key_len,
                          const uint8_t* value,
                          size_t value_len,
                          void* ctx) {
    owner_index_build_ctx_t* c = (owner_index_build_ctx_t*)ctx;
    if (!c || c->err != SOL_OK) return false;

    if (!key || key_len != 32 || !value) {
        c->err = SOL_ERR_INVAL;
        return false;
    }

    c->keys_seen++;

    const uint8_t* account_bytes = NULL;
    size_t account_len = 0;
    decode_backend_value(value, value_len, NULL, NULL, &account_bytes, &account_len);

    uint64_t lamports = 0;
    uint64_t data_len_u64 = 0;
    if (!parse_serialized_account_meta(account_bytes, account_len, &lamports, &data_len_u64)) {
        c->err = SOL_ERR_TRUNCATED;
        return false;
    }

    if (lamports == 0) {
        return true;
    }

    c->accounts_seen++;
    c->total_lamports += lamports;
    c->total_data_bytes += data_len_u64;

    bool want_owner = (c->idx && c->batch) || (c->rev && c->rev_batch);
    if (want_owner) {
        sol_pubkey_t owner = {0};
        if (parse_serialized_account_owner(account_bytes, account_len, &owner)) {
            sol_pubkey_t pubkey = {0};
            memcpy(pubkey.bytes, key, 32);

            if (c->idx && c->batch) {
                uint8_t* idx_key = sol_arena_alloc(c->arena, 64);
                if (!idx_key) {
                    c->err = SOL_ERR_NOMEM;
                    return false;
                }
                owner_index_key(&owner, &pubkey, idx_key);

                uint8_t* idx_val = sol_arena_alloc(c->arena, 1);
                if (!idx_val) {
                    c->err = SOL_ERR_NOMEM;
                    return false;
                }
                idx_val[0] = 0;

                sol_err_t err = sol_storage_batch_put(c->batch, idx_key, 64, idx_val, 1);
                if (err != SOL_OK) {
                    c->err = err;
                    return false;
                }

                c->entries_added++;
                c->bytes_queued += 64 + 1;
            }

            if (c->rev && c->rev_batch) {
                uint8_t* rev_key = sol_arena_alloc(c->arena, 32);
                if (!rev_key) {
                    c->err = SOL_ERR_NOMEM;
                    return false;
                }
                memcpy(rev_key, pubkey.bytes, 32);

                uint8_t* rev_val = sol_arena_alloc(c->arena, 48);
                if (!rev_val) {
                    c->err = SOL_ERR_NOMEM;
                    return false;
                }
                memcpy(rev_val + 0, &lamports, 8);
                memcpy(rev_val + 8, &data_len_u64, 8);
                memcpy(rev_val + 16, owner.bytes, 32);

                sol_err_t err = sol_storage_batch_put(c->rev_batch, rev_key, 32, rev_val, 48);
                if (err != SOL_OK) {
                    c->err = err;
                    return false;
                }

                c->rev_entries_added++;
                c->bytes_queued += 32 + 48;
            }
        }
    }

    if ((c->keys_seen & 0x3FFFu) == 0u) {
        uint64_t now = monotonic_ms();
        if (now - c->last_log_ms >= 5000u) {
            double secs = (double)(now - c->start_ms) / 1000.0;
            double rate = secs > 0.0 ? ((double)c->keys_seen / secs) : 0.0;
            if (!want_owner) {
                sol_log_info("Accounts stats build: keys=%lu accounts=%lu (%.0f keys/s)",
                             (unsigned long)c->keys_seen,
                             (unsigned long)c->accounts_seen,
                             rate);
            } else if (c->idx && c->rev) {
                sol_log_info("Owner index build: keys=%lu idx=%lu rev=%lu (%.0f keys/s)",
                             (unsigned long)c->keys_seen,
                             (unsigned long)c->entries_added,
                             (unsigned long)c->rev_entries_added,
                             rate);
            } else if (c->idx) {
                sol_log_info("Owner index build: keys=%lu idx=%lu (%.0f keys/s)",
                             (unsigned long)c->keys_seen,
                             (unsigned long)c->entries_added,
                             rate);
            } else {
                sol_log_info("Owner reverse build: keys=%lu rev=%lu (%.0f keys/s)",
                             (unsigned long)c->keys_seen,
                             (unsigned long)c->rev_entries_added,
                             rate);
            }
            c->last_log_ms = now;
        }
    }

    size_t idx_ops = c->batch ? c->batch->count : 0;
    size_t rev_ops = c->rev_batch ? c->rev_batch->count : 0;
    if (idx_ops >= 8192 || rev_ops >= 8192 || c->bytes_queued >= (256u * 1024u * 1024u)) {
        sol_err_t ferr = owner_index_build_flush(c);
        if (ferr != SOL_OK) {
            c->err = ferr;
            return false;
        }
    }

    return true;
}

static bool
owner_index_build_iter_rev_cb(const uint8_t* key,
                              size_t key_len,
                              const uint8_t* value,
                              size_t value_len,
                              void* ctx) {
    owner_index_build_ctx_t* c = (owner_index_build_ctx_t*)ctx;
    if (!c || c->err != SOL_OK) return false;

    if (!key || !value) return true;

    /* Owner reverse CF also stores metadata keys. Ignore those. */
    if (key_len != 32) {
        return true;
    }

    c->keys_seen++;

    owner_reverse_value_t rev = {0};
    if (!owner_reverse_decode(value, value_len, &rev)) {
        c->err = SOL_ERR_TRUNCATED;
        return false;
    }

    uint64_t lamports = rev.lamports;
    uint64_t data_len = rev.data_len;
    if (lamports == ~(uint64_t)0 || data_len == ~(uint64_t)0) {
        /* Backward-compatible reverse mapping (owner-only). Fetch the main
         * account value to compute stats and detect deletes. */
        if (!c->accounts) {
            c->err = SOL_ERR_UNSUPPORTED;
            return false;
        }

        uint8_t* account_value = NULL;
        size_t account_value_len = 0;
        sol_err_t gerr = c->accounts->get(c->accounts->ctx,
                                          key,
                                          key_len,
                                          &account_value,
                                          &account_value_len);
        if (gerr == SOL_ERR_NOTFOUND) {
            lamports = 0;
            data_len = 0;
        } else if (gerr != SOL_OK) {
            c->err = gerr;
            return false;
        } else {
            const uint8_t* account_bytes = NULL;
            size_t account_len = 0;
            decode_backend_value(account_value,
                                 account_value_len,
                                 NULL,
                                 NULL,
                                 &account_bytes,
                                 &account_len);

            if (!parse_serialized_account_meta(account_bytes, account_len, &lamports, &data_len)) {
                sol_free(account_value);
                c->err = SOL_ERR_TRUNCATED;
                return false;
            }
        }

        sol_free(account_value);
        c->fallback_lookups++;
    }

    if (lamports == 0) {
        return true;
    }

    c->accounts_seen++;
    c->total_lamports += lamports;
    c->total_data_bytes += data_len;

    bool want_owner = (c->idx && c->batch);
    if (want_owner) {
        sol_pubkey_t pubkey = {0};
        memcpy(pubkey.bytes, key, 32);

        uint8_t* idx_key = sol_arena_alloc(c->arena, 64);
        if (!idx_key) {
            c->err = SOL_ERR_NOMEM;
            return false;
        }
        owner_index_key(&rev.owner, &pubkey, idx_key);

        uint8_t* idx_val = sol_arena_alloc(c->arena, 1);
        if (!idx_val) {
            c->err = SOL_ERR_NOMEM;
            return false;
        }
        idx_val[0] = 0;

        sol_err_t err = sol_storage_batch_put(c->batch, idx_key, 64, idx_val, 1);
        if (err != SOL_OK) {
            c->err = err;
            return false;
        }

        c->entries_added++;
        c->bytes_queued += 64 + 1;
    }

    if ((c->keys_seen & 0x3FFFu) == 0u) {
        uint64_t now = monotonic_ms();
        if (now - c->last_log_ms >= 5000u) {
            double secs = (double)(now - c->start_ms) / 1000.0;
            double rate = secs > 0.0 ? ((double)c->keys_seen / secs) : 0.0;
            if (!want_owner) {
                sol_log_info("Accounts stats build: keys=%lu accounts=%lu (%.0f keys/s)",
                             (unsigned long)c->keys_seen,
                             (unsigned long)c->accounts_seen,
                             rate);
            } else {
                sol_log_info("Owner index build: keys=%lu idx=%lu (%.0f keys/s)",
                             (unsigned long)c->keys_seen,
                             (unsigned long)c->entries_added,
                             rate);
            }
            c->last_log_ms = now;
        }
    }

    size_t idx_ops = c->batch ? c->batch->count : 0;
    if (idx_ops >= 8192 || c->bytes_queued >= (256u * 1024u * 1024u)) {
        sol_err_t ferr = owner_index_build_flush(c);
        if (ferr != SOL_OK) {
            c->err = ferr;
            return false;
        }
    }

    return true;
}

sol_err_t
sol_accounts_db_ensure_owner_index(sol_accounts_db_t* db) {
    if (!db) return SOL_ERR_INVAL;

    sol_accounts_db_t* root = accounts_db_root(db);
    if (!root || !root->backend || !root->owner_index_backend) {
        return SOL_OK;
    }

    bool index_built = false;
    bool reverse_built = false;
    bool stats_built = false;

    if (root->owner_index_backend) {
        uint8_t* meta = NULL;
        size_t meta_len = 0;
        sol_err_t gerr = root->owner_index_backend->get(root->owner_index_backend->ctx,
                                                        OWNER_INDEX_META_KEY,
                                                        sizeof(OWNER_INDEX_META_KEY) - 1,
                                                        &meta,
                                                        &meta_len);
        if (gerr == SOL_OK) {
            index_built = true;
            (void)__atomic_fetch_or(&root->owner_index_state,
                                    (uint8_t)(OWNER_INDEX_STATE_LOADED | OWNER_INDEX_STATE_FULL | OWNER_INDEX_STATE_CORE),
                                    __ATOMIC_RELEASE);
            sol_free(meta);
        }
    }

    if (root->owner_reverse_backend) {
        uint8_t* meta = NULL;
        size_t meta_len = 0;
        sol_err_t gerr = root->owner_reverse_backend->get(root->owner_reverse_backend->ctx,
                                                          OWNER_REVERSE_META_KEY,
                                                          sizeof(OWNER_REVERSE_META_KEY) - 1,
                                                          &meta,
                                                          &meta_len);
        if (gerr == SOL_OK) {
            uint8_t version = (meta_len > 0) ? meta[0] : 0;
            reverse_built = version >= 2;
            (void)__atomic_fetch_or(&root->owner_reverse_state,
                                    (uint8_t)(OWNER_REVERSE_STATE_LOADED |
                                              (reverse_built ? OWNER_REVERSE_STATE_BUILT : 0u)),
                                    __ATOMIC_RELEASE);
            sol_free(meta);
        }
    }

    if (root->owner_reverse_backend) {
        uint8_t* meta = NULL;
        size_t meta_len = 0;
        sol_err_t gerr = root->owner_reverse_backend->get(root->owner_reverse_backend->ctx,
                                                          ACCOUNTS_STATS_META_KEY,
                                                          sizeof(ACCOUNTS_STATS_META_KEY) - 1,
                                                          &meta,
                                                          &meta_len);
        if (gerr == SOL_OK) {
            stats_built = (meta_len == 24);
            sol_free(meta);
        }
    }

    bool need_index = !index_built;
    bool need_reverse = (root->owner_reverse_backend != NULL) && !reverse_built;
    bool need_stats = (root->owner_reverse_backend != NULL) && !stats_built;
    bool can_build_from_reverse =
        (root->owner_reverse_backend != NULL) && reverse_built && !need_reverse;

    if (!need_index && !need_reverse && !need_stats) {
        return SOL_OK;
    }

    if (need_index && need_reverse && need_stats) {
        sol_log_info("Building accounts owner index + reverse + stats (one-time initialization)");
    } else if (need_index && need_reverse) {
        sol_log_info("Building accounts owner index + reverse mapping (one-time initialization)");
    } else if (need_index && need_stats) {
        sol_log_info("Building accounts owner index + stats (one-time initialization)");
    } else if (need_reverse && need_stats) {
        sol_log_info("Building accounts owner reverse + stats (one-time initialization)");
    } else if (need_index) {
        sol_log_info("Building accounts owner index (one-time initialization)");
    } else if (need_reverse) {
        sol_log_info("Building accounts owner reverse mapping (one-time initialization)");
    } else {
        sol_log_info("Building accounts stats (one-time initialization)");
    }

    if (!need_reverse && can_build_from_reverse && (need_index || need_stats)) {
        if (need_index && need_stats) {
            sol_log_info("Building accounts owner index + stats from owner reverse mapping");
        } else if (need_index) {
            sol_log_info("Building accounts owner index from owner reverse mapping");
        } else {
            sol_log_info("Building accounts stats from owner reverse mapping");
        }
    }

    sol_storage_batch_t* batch = need_index ? sol_storage_batch_new(8192) : NULL;
    sol_storage_batch_t* rev_batch = need_reverse ? sol_storage_batch_new(8192) : NULL;
    if ((need_index && !batch) || (need_reverse && !rev_batch)) {
        if (batch) sol_storage_batch_destroy(batch);
        if (rev_batch) sol_storage_batch_destroy(rev_batch);
        return SOL_ERR_NOMEM;
    }

    sol_arena_t* arena = sol_arena_new(64 * 1024 * 1024);
    if (!arena) {
        if (batch) sol_storage_batch_destroy(batch);
        if (rev_batch) sol_storage_batch_destroy(rev_batch);
        return SOL_ERR_NOMEM;
    }

    owner_index_build_ctx_t bctx = {0};
    bctx.idx = need_index ? root->owner_index_backend : NULL;
    bctx.rev = need_reverse ? root->owner_reverse_backend : NULL;
    bctx.accounts = root->backend;
    bctx.batch = batch;
    bctx.rev_batch = rev_batch;
    bctx.arena = arena;
    bctx.bytes_queued = 0;
    bctx.err = SOL_OK;
    bctx.start_ms = monotonic_ms();
    bctx.last_log_ms = bctx.start_ms;

    if (!need_reverse && can_build_from_reverse && (need_index || need_stats)) {
        root->owner_reverse_backend->iterate(root->owner_reverse_backend->ctx,
                                             owner_index_build_iter_rev_cb,
                                             &bctx);
    } else {
        root->backend->iterate(root->backend->ctx, owner_index_build_iter_cb, &bctx);
    }

    if (bctx.err == SOL_OK) {
        sol_err_t ferr = owner_index_build_flush(&bctx);
        if (ferr != SOL_OK) {
            bctx.err = ferr;
        }
    }

    sol_arena_destroy(arena);
    if (batch) sol_storage_batch_destroy(batch);
    if (rev_batch) sol_storage_batch_destroy(rev_batch);

    if (bctx.err != SOL_OK) {
        sol_log_error("Accounts metadata build failed: %s", sol_err_str(bctx.err));
        return bctx.err;
    }

    if (need_index) {
        static const uint8_t one = 1;
        sol_err_t perr = root->owner_index_backend->put(root->owner_index_backend->ctx,
                                                        OWNER_INDEX_META_KEY,
                                                        sizeof(OWNER_INDEX_META_KEY) - 1,
                                                        &one,
                                                        sizeof(one));
        if (perr != SOL_OK) {
            return perr;
        }
        (void)__atomic_fetch_or(&root->owner_index_state,
                                (uint8_t)(OWNER_INDEX_STATE_LOADED | OWNER_INDEX_STATE_FULL | OWNER_INDEX_STATE_CORE),
                                __ATOMIC_RELEASE);
    }

    if (need_reverse) {
        static const uint8_t v2 = 2;
        sol_err_t perr = root->owner_reverse_backend->put(root->owner_reverse_backend->ctx,
                                                          OWNER_REVERSE_META_KEY,
                                                          sizeof(OWNER_REVERSE_META_KEY) - 1,
                                                          &v2,
                                                          sizeof(v2));
        if (perr != SOL_OK) {
            return perr;
        }
    }

    if (root->owner_reverse_backend) {
        uint8_t buf[24];
        memcpy(buf + 0, &bctx.accounts_seen, 8);
        memcpy(buf + 8, &bctx.total_lamports, 8);
        memcpy(buf + 16, &bctx.total_data_bytes, 8);
        sol_err_t perr = root->owner_reverse_backend->put(root->owner_reverse_backend->ctx,
                                                          ACCOUNTS_STATS_META_KEY,
                                                          sizeof(ACCOUNTS_STATS_META_KEY) - 1,
                                                          buf,
                                                          sizeof(buf));
        if (perr != SOL_OK) {
            return perr;
        }
    }

    pthread_rwlock_wrlock(&root->lock);
    root->stats.accounts_count = bctx.accounts_seen;
    root->stats.total_lamports = bctx.total_lamports;
    root->stats.total_data_bytes = bctx.total_data_bytes;
    root->account_count = (size_t)bctx.accounts_seen;
    pthread_rwlock_unlock(&root->lock);

    if (need_stats) {
        sol_log_info("Accounts stats initialized (accounts=%lu lamports=%lu data_bytes=%lu)",
                     (unsigned long)bctx.accounts_seen,
                     (unsigned long)bctx.total_lamports,
                     (unsigned long)bctx.total_data_bytes);
    }

    if (need_index && need_reverse) {
        sol_log_info("Accounts owner index built (%lu entries), reverse built (%lu entries)",
                     (unsigned long)bctx.entries_added,
                     (unsigned long)bctx.rev_entries_added);
    } else if (need_index) {
        sol_log_info("Accounts owner index built (%lu entries)", (unsigned long)bctx.entries_added);
    } else if (need_reverse) {
        sol_log_info("Accounts owner reverse mapping built (%lu entries)", (unsigned long)bctx.rev_entries_added);
    }
    return SOL_OK;
}

typedef struct {
    sol_storage_backend_t* idx;
    sol_storage_backend_t* rev;
    sol_storage_batch_t*   batch;
    sol_arena_t*           arena;
    size_t                 bytes_queued;
    sol_err_t              err;
    uint64_t               keys_seen;
    uint64_t               entries_added;
    uint64_t               start_ms;
    uint64_t               last_log_ms;
} owner_index_core_build_ctx_t;

static sol_err_t
owner_index_core_build_flush(owner_index_core_build_ctx_t* c) {
    if (!c) return SOL_ERR_INVAL;
    if (c->err != SOL_OK) return c->err;
    if (!c->batch || c->batch->count == 0) return SOL_OK;
    if (!c->idx || !c->idx->batch_write) return SOL_ERR_UNINITIALIZED;

    sol_err_t err = c->idx->batch_write(c->idx->ctx, c->batch);
    if (err != SOL_OK) return err;
    sol_storage_batch_clear(c->batch);

    sol_arena_reset(c->arena);
    c->bytes_queued = 0;
    return SOL_OK;
}

static bool
owner_index_core_build_iter_rev_cb(const uint8_t* key,
                                  size_t key_len,
                                  const uint8_t* value,
                                  size_t value_len,
                                  void* ctx) {
    owner_index_core_build_ctx_t* c = (owner_index_core_build_ctx_t*)ctx;
    if (!c) return false;
    if (c->err != SOL_OK) return false;

    /* Skip metadata entries and malformed keys. */
    if (!key || key_len != 32) {
        return true;
    }

    owner_reverse_value_t rev = {0};
    if (!owner_reverse_decode(value, value_len, &rev)) {
        return true;
    }

    c->keys_seen++;

    if (rev.lamports == 0) {
        return true;
    }

    bool want_owner =
        sol_pubkey_eq(&rev.owner, &SOL_STAKE_PROGRAM_ID) ||
        sol_pubkey_eq(&rev.owner, &SOL_VOTE_PROGRAM_ID);
    if (!want_owner) {
        return true;
    }

    sol_pubkey_t pubkey = {0};
    memcpy(pubkey.bytes, key, 32);

    uint8_t* idx_key = sol_arena_alloc(c->arena, 64);
    if (!idx_key) {
        c->err = SOL_ERR_NOMEM;
        return false;
    }
    owner_index_key(&rev.owner, &pubkey, idx_key);

    uint8_t* idx_val = sol_arena_alloc(c->arena, 1);
    if (!idx_val) {
        c->err = SOL_ERR_NOMEM;
        return false;
    }
    idx_val[0] = 0;

    sol_err_t err = sol_storage_batch_put(c->batch, idx_key, 64, idx_val, 1);
    if (err != SOL_OK) {
        c->err = err;
        return false;
    }

    c->entries_added++;
    c->bytes_queued += 64 + 1;

    if ((c->keys_seen & 0x3FFFu) == 0u) {
        uint64_t now = monotonic_ms();
        if (now - c->last_log_ms >= 5000u) {
            double secs = (double)(now - c->start_ms) / 1000.0;
            double rate = secs > 0.0 ? ((double)c->keys_seen / secs) : 0.0;
            sol_log_info("Core owner index build: keys=%lu idx=%lu (%.0f keys/s)",
                         (unsigned long)c->keys_seen,
                         (unsigned long)c->entries_added,
                         rate);
            c->last_log_ms = now;
        }
    }

    if (c->batch->count >= 8192 || c->bytes_queued >= (256u * 1024u * 1024u)) {
        sol_err_t ferr = owner_index_core_build_flush(c);
        if (ferr != SOL_OK) {
            c->err = ferr;
            return false;
        }
    }

    return true;
}

static bool
owner_index_core_build_iter_accounts_cb(const uint8_t* key,
                                        size_t key_len,
                                        const uint8_t* value,
                                        size_t value_len,
                                        void* ctx) {
    owner_index_core_build_ctx_t* c = (owner_index_core_build_ctx_t*)ctx;
    if (!c) return false;
    if (c->err != SOL_OK) return false;

    /* Accounts DB keys are pubkeys; skip malformed entries. */
    if (!key || key_len != 32) {
        return true;
    }

    c->keys_seen++;

    const uint8_t* account_bytes = NULL;
    size_t account_len = 0;
    decode_backend_value(value, value_len, NULL, NULL, &account_bytes, &account_len);
    if (!account_bytes || account_len < 16) {
        return true;
    }

    uint64_t lamports = 0;
    memcpy(&lamports, account_bytes, 8);
    if (lamports == 0) {
        return true;
    }

    sol_pubkey_t owner = {0};
    if (!parse_serialized_account_owner(account_bytes, account_len, &owner)) {
        return true;
    }
    if (!owner_index_is_core_owner(&owner)) {
        return true;
    }

    sol_pubkey_t pubkey = {0};
    memcpy(pubkey.bytes, key, 32);

    uint8_t* idx_key = sol_arena_alloc(c->arena, 64);
    if (!idx_key) {
        c->err = SOL_ERR_NOMEM;
        return false;
    }
    owner_index_key(&owner, &pubkey, idx_key);

    uint8_t* idx_val = sol_arena_alloc(c->arena, 1);
    if (!idx_val) {
        c->err = SOL_ERR_NOMEM;
        return false;
    }
    idx_val[0] = 0;

    sol_err_t err = sol_storage_batch_put(c->batch, idx_key, 64, idx_val, 1);
    if (err != SOL_OK) {
        c->err = err;
        return false;
    }

    c->entries_added++;
    c->bytes_queued += 64 + 1;

    if ((c->keys_seen & 0x3FFFu) == 0u) {
        uint64_t now = monotonic_ms();
        if (now - c->last_log_ms >= 5000u) {
            double secs = (double)(now - c->start_ms) / 1000.0;
            double rate = secs > 0.0 ? ((double)c->keys_seen / secs) : 0.0;
            sol_log_info("Core owner index build (accounts scan): keys=%lu idx=%lu (%.0f keys/s)",
                         (unsigned long)c->keys_seen,
                         (unsigned long)c->entries_added,
                         rate);
            c->last_log_ms = now;
        }
    }

    if (c->batch->count >= 8192 || c->bytes_queued >= (256u * 1024u * 1024u)) {
        sol_err_t ferr = owner_index_core_build_flush(c);
        if (ferr != SOL_OK) {
            c->err = ferr;
            return false;
        }
    }

    return true;
}

sol_err_t
sol_accounts_db_ensure_core_owner_index(sol_accounts_db_t* db) {
    if (!db) return SOL_ERR_INVAL;

    sol_accounts_db_t* root = accounts_db_root(db);
    if (!root || !root->backend || !root->owner_index_backend) {
        return SOL_OK;
    }

    /* If the full owner index is built, or we already built the core subset,
     * there is nothing to do. */
    if (root->owner_index_backend) {
        uint8_t* meta = NULL;
        size_t meta_len = 0;
        sol_err_t gerr = root->owner_index_backend->get(root->owner_index_backend->ctx,
                                                        OWNER_INDEX_META_KEY,
                                                        sizeof(OWNER_INDEX_META_KEY) - 1,
                                                        &meta,
                                                        &meta_len);
        if (gerr == SOL_OK) {
            (void)__atomic_fetch_or(&root->owner_index_state,
                                    (uint8_t)(OWNER_INDEX_STATE_LOADED | OWNER_INDEX_STATE_FULL | OWNER_INDEX_STATE_CORE),
                                    __ATOMIC_RELEASE);
            sol_free(meta);
            return SOL_OK;
        }
    }

    if (root->owner_index_backend) {
        uint8_t* meta = NULL;
        size_t meta_len = 0;
        sol_err_t gerr = root->owner_index_backend->get(root->owner_index_backend->ctx,
                                                        OWNER_INDEX_CORE_META_KEY,
                                                        sizeof(OWNER_INDEX_CORE_META_KEY) - 1,
                                                        &meta,
                                                        &meta_len);
        if (gerr == SOL_OK) {
            (void)__atomic_fetch_or(&root->owner_index_state,
                                    (uint8_t)(OWNER_INDEX_STATE_LOADED | OWNER_INDEX_STATE_CORE),
                                    __ATOMIC_RELEASE);
            sol_free(meta);
            return SOL_OK;
        }
    }

    if (!root->owner_index_backend->batch_write) {
        return SOL_OK;
    }

    bool can_build_from_reverse =
        root->owner_reverse_backend &&
        root->owner_reverse_backend->iterate &&
        accounts_db_can_use_owner_reverse(root);

    if (!can_build_from_reverse && !root->backend->iterate) {
        return SOL_OK;
    }

    if (can_build_from_reverse) {
        sol_log_info("Building core owner index (stake+vote) from owner reverse mapping...");
    } else {
        sol_log_info("Building core owner index (stake+vote) by scanning accounts...");
    }

    sol_storage_batch_t* batch = sol_storage_batch_new(8192);
    if (!batch) {
        return SOL_ERR_NOMEM;
    }

    sol_arena_t* arena = sol_arena_new(64 * 1024 * 1024);
    if (!arena) {
        sol_storage_batch_destroy(batch);
        return SOL_ERR_NOMEM;
    }

    owner_index_core_build_ctx_t cctx = {0};
    cctx.idx = root->owner_index_backend;
    cctx.rev = can_build_from_reverse ? root->owner_reverse_backend : NULL;
    cctx.batch = batch;
    cctx.arena = arena;
    cctx.bytes_queued = 0;
    cctx.err = SOL_OK;
    cctx.start_ms = monotonic_ms();
    cctx.last_log_ms = cctx.start_ms;

    if (can_build_from_reverse) {
        cctx.rev->iterate(cctx.rev->ctx, owner_index_core_build_iter_rev_cb, &cctx);
    } else {
        root->backend->iterate(root->backend->ctx, owner_index_core_build_iter_accounts_cb, &cctx);
    }

    if (cctx.err == SOL_OK) {
        sol_err_t ferr = owner_index_core_build_flush(&cctx);
        if (ferr != SOL_OK) {
            cctx.err = ferr;
        }
    }

    sol_arena_destroy(arena);
    sol_storage_batch_destroy(batch);

    if (cctx.err != SOL_OK) {
        sol_log_error("Core owner index build failed: %s", sol_err_str(cctx.err));
        return cctx.err;
    }

    static const uint8_t one = 1;
    sol_err_t perr = root->owner_index_backend->put(root->owner_index_backend->ctx,
                                                    OWNER_INDEX_CORE_META_KEY,
                                                    sizeof(OWNER_INDEX_CORE_META_KEY) - 1,
                                                    &one,
                                                    sizeof(one));
    if (perr != SOL_OK) {
        return perr;
    }

    (void)__atomic_fetch_or(&root->owner_index_state,
                            (uint8_t)(OWNER_INDEX_STATE_LOADED | OWNER_INDEX_STATE_CORE),
                            __ATOMIC_RELEASE);
    sol_log_info("Core owner index built (%lu entries)", (unsigned long)cctx.entries_added);
    return SOL_OK;
}

sol_err_t
sol_accounts_db_mark_owner_reverse_built(sol_accounts_db_t* db) {
    if (!db) return SOL_ERR_INVAL;

    sol_accounts_db_t* root = accounts_db_root(db);
    if (!root || !root->owner_reverse_backend) {
        return SOL_OK;
    }

    static const uint8_t v2 = 2;
    sol_err_t err = root->owner_reverse_backend->put(root->owner_reverse_backend->ctx,
                                                     OWNER_REVERSE_META_KEY,
                                                     sizeof(OWNER_REVERSE_META_KEY) - 1,
                                                     &v2,
                                                     sizeof(v2));
    if (err == SOL_OK) {
        (void)__atomic_fetch_or(&root->owner_reverse_state,
                                (uint8_t)(OWNER_REVERSE_STATE_LOADED | OWNER_REVERSE_STATE_BUILT),
                                __ATOMIC_RELEASE);
    }
    return err;
}

sol_err_t
sol_accounts_db_mark_owner_index_core_built(sol_accounts_db_t* db) {
    if (!db) return SOL_ERR_INVAL;

    sol_accounts_db_t* root = accounts_db_root(db);
    if (!root || !root->owner_index_backend) {
        return SOL_OK;
    }

    static const uint8_t one = 1;
    sol_err_t err = root->owner_index_backend->put(root->owner_index_backend->ctx,
                                                   OWNER_INDEX_CORE_META_KEY,
                                                   sizeof(OWNER_INDEX_CORE_META_KEY) - 1,
                                                   &one,
                                                   sizeof(one));
    if (err != SOL_OK) {
        return err;
    }

    (void)__atomic_fetch_or(&root->owner_index_state,
                            (uint8_t)(OWNER_INDEX_STATE_LOADED | OWNER_INDEX_STATE_CORE),
                            __ATOMIC_RELEASE);
    return SOL_OK;
}

sol_err_t
sol_accounts_db_snapshot_local(sol_accounts_db_t* db,
                               sol_accounts_db_local_snapshot_t* out) {
    if (!db || !out) return SOL_ERR_INVAL;

    out->parent = NULL;
    out->entries = NULL;
    out->len = 0;

    if (!db->parent || db->backend) {
        return SOL_ERR_INVAL;
    }

    size_t cap = 0;
    sol_err_t err = SOL_OK;

    /* Overlay writers only take a shared lock plus stripe locks; take an
     * exclusive lock while snapshotting bucket chains without stripe locks. */
    pthread_rwlock_wrlock(&db->lock);
    out->parent = db->parent;
    if (db->account_count > 0) {
        if (db->account_count > (SIZE_MAX / sizeof(*out->entries))) {
            err = SOL_ERR_OVERFLOW;
        } else {
            cap = db->account_count;
            out->entries = sol_alloc(cap * sizeof(*out->entries));
            if (!out->entries) {
                err = SOL_ERR_NOMEM;
                cap = 0;
            }
        }
    }

    for (size_t i = 0; i < db->bucket_count && err == SOL_OK; i++) {
        sol_account_entry_t* entry = db->buckets[i];
        while (entry && err == SOL_OK) {
            if (out->len == cap) {
                size_t new_cap = cap ? (cap * 2) : 128;
                if (new_cap < cap) {
                    err = SOL_ERR_OVERFLOW;
                    break;
                }

                sol_accounts_db_local_entry_t* new_entries =
                    sol_realloc(out->entries, new_cap * sizeof(*new_entries));
                if (!new_entries) {
                    err = SOL_ERR_NOMEM;
                    break;
                }
                out->entries = new_entries;
                cap = new_cap;
            }

            sol_accounts_db_local_entry_t* dst = &out->entries[out->len++];
            dst->pubkey = entry->pubkey;
            dst->account = entry->account ? sol_account_clone(entry->account) : NULL;
            dst->slot = entry->slot;
            dst->write_version = entry->write_version;
            if (entry->account && !dst->account) {
                err = SOL_ERR_NOMEM;
                break;
            }
            /* Zero-lamport accounts are kept (not converted to tombstones)
             * because they may have had non-zero lamports previously, and
             * the lt_hash computation needs to mix out the old state.
             * Their current lt_hash contribution is identity (all zeros). */

            entry = entry->next;
        }
    }

    pthread_rwlock_unlock(&db->lock);

    if (err != SOL_OK) {
        sol_accounts_db_local_snapshot_free(out);
        return err;
    }

    return SOL_OK;
}

void
sol_accounts_db_local_snapshot_free(sol_accounts_db_local_snapshot_t* snap) {
    if (!snap) return;

    for (size_t i = 0; i < snap->len; i++) {
        if (snap->entries[i].account) {
            sol_account_destroy(snap->entries[i].account);
            snap->entries[i].account = NULL;
        }
    }
    sol_free(snap->entries);
    snap->entries = NULL;
    snap->len = 0;
    snap->parent = NULL;
}

static sol_err_t
sol_accounts_db_snapshot_local_view_impl(sol_accounts_db_t* db,
                                         sol_accounts_db_local_snapshot_view_t* out,
                                         bool immutable_overlay) {
    if (!db || !out) return SOL_ERR_INVAL;

    out->parent = NULL;
    out->entries = NULL;
    out->len = 0;

    if (!db->parent || db->backend) {
        return SOL_ERR_INVAL;
    }

    size_t cap = 0;
    sol_err_t err = SOL_OK;

    /* Mutable overlays need an exclusive lock while walking bucket chains
     * without stripe locks. Immutable overlays can safely use a shared lock to
     * avoid blocking concurrent readers during large snapshots. */
    if (immutable_overlay) {
        pthread_rwlock_rdlock(&db->lock);
    } else {
        pthread_rwlock_wrlock(&db->lock);
    }
    out->parent = db->parent;
    if (db->account_count > 0) {
        if (db->account_count > (SIZE_MAX / sizeof(*out->entries))) {
            err = SOL_ERR_OVERFLOW;
        } else {
            cap = db->account_count;
            out->entries = sol_alloc(cap * sizeof(*out->entries));
            if (!out->entries) {
                err = SOL_ERR_NOMEM;
                cap = 0;
            }
        }
    }

    for (size_t i = 0; i < db->bucket_count && err == SOL_OK; i++) {
        sol_account_entry_t* entry = db->buckets[i];
        while (entry && err == SOL_OK) {
            if (out->len == cap) {
                size_t new_cap = cap ? (cap * 2) : 128;
                if (new_cap < cap) {
                    err = SOL_ERR_OVERFLOW;
                    break;
                }

                sol_accounts_db_local_entry_t* new_entries =
                    sol_realloc(out->entries, new_cap * sizeof(*new_entries));
                if (!new_entries) {
                    err = SOL_ERR_NOMEM;
                    break;
                }
                out->entries = new_entries;
                cap = new_cap;
            }

            sol_accounts_db_local_entry_t* dst = &out->entries[out->len++];
            dst->pubkey = entry->pubkey;
            dst->account = entry->account; /* borrowed */
            dst->slot = entry->slot;
            dst->write_version = entry->write_version;

            entry = entry->next;
        }
    }

    pthread_rwlock_unlock(&db->lock);

    if (err != SOL_OK) {
        sol_accounts_db_local_snapshot_view_free(out);
        return err;
    }

    return SOL_OK;
}

sol_err_t
sol_accounts_db_snapshot_local_view(sol_accounts_db_t* db,
                                    sol_accounts_db_local_snapshot_view_t* out) {
    return sol_accounts_db_snapshot_local_view_impl(db, out, false);
}

sol_err_t
sol_accounts_db_snapshot_local_view_immutable(sol_accounts_db_t* db,
                                              sol_accounts_db_local_snapshot_view_t* out) {
    return sol_accounts_db_snapshot_local_view_impl(db, out, true);
}

void
sol_accounts_db_local_snapshot_view_free(sol_accounts_db_local_snapshot_view_t* snap) {
    if (!snap) return;

    sol_free(snap->entries);
    snap->entries = NULL;
    snap->len = 0;
    snap->parent = NULL;
}

sol_err_t
sol_accounts_db_iterate_local(sol_accounts_db_t* db,
                              sol_accounts_db_iter_local_cb callback,
                              void* ctx) {
    if (!db || !callback) return SOL_ERR_INVAL;

    sol_accounts_db_local_snapshot_t snap = {0};
    sol_err_t err = sol_accounts_db_snapshot_local(db, &snap);
    if (err != SOL_OK) {
        return err;
    }

    for (size_t i = 0; i < snap.len; i++) {
        if (!callback(snap.parent, &snap.entries[i].pubkey, snap.entries[i].account, ctx)) {
            break;
        }
    }

    sol_accounts_db_local_snapshot_free(&snap);
    return SOL_OK;
}

typedef struct {
    sol_pubkey_t pubkey;
    sol_hash_t   hash;
} accounts_hash_entry_t;

typedef struct {
    accounts_hash_entry_t* entries;
    size_t                 count;
    size_t                 cap;
    sol_err_t              err;
} accounts_hash_collect_ctx_t;

static int
accounts_hash_entry_cmp(const void* a, const void* b) {
    const accounts_hash_entry_t* ea = (const accounts_hash_entry_t*)a;
    const accounts_hash_entry_t* eb = (const accounts_hash_entry_t*)b;
    return memcmp(ea->pubkey.bytes, eb->pubkey.bytes, sizeof(ea->pubkey.bytes));
}

static bool
accounts_hash_collect_cb(const sol_pubkey_t* pubkey, const sol_account_t* account,
                         void* ctx) {
    accounts_hash_collect_ctx_t* c = (accounts_hash_collect_ctx_t*)ctx;
    if (!c || !pubkey || !account) return false;
    if (c->err != SOL_OK) return false;

    /* Zero-lamport accounts are treated as deleted in Solana's AccountsDB. */
    if (account->meta.lamports == 0) {
        return true;
    }

    if (c->count == c->cap) {
        size_t new_cap = c->cap ? (c->cap * 2) : 1024;
        if (new_cap < c->cap) {
            c->err = SOL_ERR_OVERFLOW;
            return false;
        }

        accounts_hash_entry_t* new_entries = sol_realloc(c->entries, new_cap * sizeof(*new_entries));
        if (!new_entries) {
            c->err = SOL_ERR_NOMEM;
            return false;
        }

        c->entries = new_entries;
        c->cap = new_cap;
    }

    accounts_hash_entry_t* e = &c->entries[c->count++];
    e->pubkey = *pubkey;
    sol_account_hash(pubkey, account, &e->hash);
    return true;
}

static void
hash_group_sha256(const sol_hash_t* hashes, size_t count, sol_hash_t* out_hash) {
    if (!hashes || !out_hash || count == 0) return;

    if (count == 1) {
        *out_hash = hashes[0];
        return;
    }

    sol_sha256_ctx_t sha;
    sol_sha256_init(&sha);
    for (size_t i = 0; i < count; i++) {
        sol_sha256_update(&sha, hashes[i].bytes, SOL_HASH_SIZE);
    }
    sol_sha256_t digest;
    sol_sha256_final(&sha, &digest);
    memcpy(out_hash->bytes, digest.bytes, SOL_HASH_SIZE);
}

/*
 * Streaming accounts-hash builder (fanout-16 merkle reduction).
 *
 * This avoids materializing/sorting all leaf hashes for the common case of
 * a root RocksDB AccountsDB where iteration order is already lexicographic by
 * pubkey bytes (matching Solana's sort order).
 */
#define SOL_ACCOUNTS_HASH_FANOUT 16u
#define SOL_ACCOUNTS_HASH_MAX_LEVELS 32u

typedef struct {
    sol_hash_t hashes[SOL_ACCOUNTS_HASH_FANOUT];
    size_t     count;
} sol_accounts_hash_level_t;

typedef struct {
    sol_accounts_hash_level_t levels[SOL_ACCOUNTS_HASH_MAX_LEVELS];
    sol_err_t                 err;
} sol_accounts_hash_builder_t;

static void
accounts_hash_builder_add(sol_accounts_hash_builder_t* b,
                          const sol_hash_t* hash);

static uint64_t
monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

typedef struct {
    sol_accounts_db_t*          db;
    sol_accounts_hash_builder_t builder;
    uint64_t                    keys_seen;
    uint64_t                    accounts_included;
    uint64_t                    accounts_skipped;
    uint64_t                    start_ms;
    uint64_t                    last_log_ms;
} accounts_hash_backend_ctx_t;

static bool
accounts_hash_backend_iter_cb(const uint8_t* key,
                              size_t key_len,
                              const uint8_t* value,
                              size_t value_len,
                              void* ctx) {
    accounts_hash_backend_ctx_t* c = (accounts_hash_backend_ctx_t*)ctx;
    if (!c) return false;

    sol_accounts_hash_builder_t* b = &c->builder;
    if (b->err != SOL_OK) return false;

    if (!key || key_len != 32 || !value) {
        b->err = SOL_ERR_INVAL;
        return false;
    }

    c->keys_seen++;

    const uint8_t* payload = NULL;
    size_t payload_len = 0;
    decode_backend_value(value, value_len, NULL, NULL, &payload, &payload_len);

    if (c->db && c->db->config.storage_type == SOL_ACCOUNTS_STORAGE_APPENDVEC) {
        sol_accountsdb_appendvec_ref_v1_t ref = {0};
        if (!appendvec_ref_decode(payload, payload_len, &ref)) {
            b->err = SOL_ERR_TRUNCATED;
            return false;
        }

        if (sol_hash_is_zero(&ref.account_hash)) {
            c->accounts_skipped++;
            if ((c->keys_seen & 0x3FFFu) == 0u) {
                uint64_t now = monotonic_ms();
                if (now - c->last_log_ms >= 5000u) {
                    double secs = (double)(now - c->start_ms) / 1000.0;
                    double rate = secs > 0.0 ? ((double)c->keys_seen / secs) : 0.0;
                    sol_log_info("Accounts hash progress: keys=%lu included=%lu skipped=%lu (%.0f keys/s)",
                                 (unsigned long)c->keys_seen,
                                 (unsigned long)c->accounts_included,
                                 (unsigned long)c->accounts_skipped,
                                 rate);
                    c->last_log_ms = now;
                }
            }
            return true;
        }

        accounts_hash_builder_add(b, &ref.account_hash);
        c->accounts_included++;
        return b->err == SOL_OK;
    }

    if (!payload || payload_len < 16) {
        b->err = SOL_ERR_TRUNCATED;
        return false;
    }

    uint64_t lamports = 0;
    uint64_t data_len_u64 = 0;
    if (!parse_serialized_account_meta(payload, payload_len, &lamports, &data_len_u64)) {
        b->err = SOL_ERR_TRUNCATED;
        return false;
    }

    if (lamports == 0) {
        c->accounts_skipped++;
        if ((c->keys_seen & 0x3FFFu) == 0u) {
            uint64_t now = monotonic_ms();
            if (now - c->last_log_ms >= 5000u) {
                double secs = (double)(now - c->start_ms) / 1000.0;
                double rate = secs > 0.0 ? ((double)c->keys_seen / secs) : 0.0;
                sol_log_info("Accounts hash progress: keys=%lu included=%lu skipped=%lu (%.0f keys/s)",
                             (unsigned long)c->keys_seen,
                             (unsigned long)c->accounts_included,
                             (unsigned long)c->accounts_skipped,
                             rate);
                c->last_log_ms = now;
            }
        }
        return true; /* deleted/tombstone */
    }

    if (data_len_u64 > SOL_ACCOUNT_MAX_DATA_SIZE) {
        b->err = SOL_ERR_TOO_LARGE;
        return false;
    }

    size_t data_len = (size_t)data_len_u64;
    size_t need = 8 + 8 + data_len + 32 + 1 + 8;
    if (need > payload_len) {
        b->err = SOL_ERR_TRUNCATED;
        return false;
    }

    sol_sha256_ctx_t sha;
    sol_sha256_init(&sha);
    sol_sha256_update(&sha, key, 32);

    /* Hash serialized lamports/data_len/data directly (little-endian). */
    sol_sha256_update(&sha, payload + 0, 8);
    sol_sha256_update(&sha, payload + 8, 8);
    sol_sha256_update(&sha, payload + 16, data_len);

    size_t off = 16 + data_len;
    sol_sha256_update(&sha, payload + off, 32); /* owner */
    off += 32;
    sol_sha256_update(&sha, payload + off, 1);  /* executable */
    off += 1;
    sol_sha256_update(&sha, payload + off, 8);  /* rent_epoch */

    sol_hash_t leaf = {0};
    sol_sha256_final_bytes(&sha, leaf.bytes);

    accounts_hash_builder_add(b, &leaf);

    c->accounts_included++;
    if ((c->keys_seen & 0x3FFFu) == 0u) {
        uint64_t now = monotonic_ms();
        if (now - c->last_log_ms >= 5000u) {
            double secs = (double)(now - c->start_ms) / 1000.0;
            double rate = secs > 0.0 ? ((double)c->keys_seen / secs) : 0.0;
            sol_log_info("Accounts hash progress: keys=%lu included=%lu skipped=%lu (%.0f keys/s)",
                         (unsigned long)c->keys_seen,
                         (unsigned long)c->accounts_included,
                         (unsigned long)c->accounts_skipped,
                         rate);
            c->last_log_ms = now;
        }
    }
    return b->err == SOL_OK;
}

static void
accounts_hash_builder_add_at_level(sol_accounts_hash_builder_t* b,
                                   size_t level,
                                   const sol_hash_t* hash) {
    if (!b || !hash) return;
    if (b->err != SOL_OK) return;

    sol_hash_t carry = *hash;
    size_t lvl = level;

    while (1) {
        if (lvl >= SOL_ACCOUNTS_HASH_MAX_LEVELS) {
            b->err = SOL_ERR_OVERFLOW;
            return;
        }

        sol_accounts_hash_level_t* L = &b->levels[lvl];
        L->hashes[L->count++] = carry;
        if (L->count < SOL_ACCOUNTS_HASH_FANOUT) {
            return;
        }

        hash_group_sha256(L->hashes, SOL_ACCOUNTS_HASH_FANOUT, &carry);
        L->count = 0;
        lvl++;
    }
}

static void
accounts_hash_builder_add(sol_accounts_hash_builder_t* b,
                          const sol_hash_t* hash) {
    accounts_hash_builder_add_at_level(b, 0, hash);
}

static void
accounts_hash_builder_finalize(sol_accounts_hash_builder_t* b,
                               sol_hash_t* out_hash) {
    if (!b || !out_hash) return;

    if (b->err != SOL_OK) {
        memset(out_hash->bytes, 0, sizeof(out_hash->bytes));
        return;
    }

    for (size_t level = 0; level + 1 < SOL_ACCOUNTS_HASH_MAX_LEVELS && b->err == SOL_OK; level++) {
        sol_accounts_hash_level_t* L = &b->levels[level];
        if (L->count == 0) continue;

        sol_hash_t group = {0};
        hash_group_sha256(L->hashes, L->count, &group);
        L->count = 0;

        accounts_hash_builder_add_at_level(b, level + 1, &group);
    }

    if (b->err != SOL_OK) {
        memset(out_hash->bytes, 0, sizeof(out_hash->bytes));
        return;
    }

    /* Find highest non-empty level. */
    size_t top = SOL_ACCOUNTS_HASH_MAX_LEVELS;
    while (top > 0 && b->levels[top - 1].count == 0) {
        top--;
    }

    if (top == 0) {
        memset(out_hash->bytes, 0, sizeof(out_hash->bytes));
        return;
    }

    sol_accounts_hash_level_t* L = &b->levels[top - 1];
    hash_group_sha256(L->hashes, L->count, out_hash);
}

static void
hash_deleted_account(const sol_pubkey_t* pubkey, sol_hash_t* out_hash) {
    if (!pubkey || !out_hash) return;

    /* Mirror sol_account_hash() for a deleted (zero-lamport) account without
     * needing a full sol_account_t allocation. Pubkey must remain in the hash
     * so deletions are unique per address. */
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    sol_sha256_update(&ctx, pubkey->bytes, 32);

    uint64_t zero64 = 0;
    sol_sha256_update(&ctx, &zero64, 8); /* lamports */
    sol_sha256_update(&ctx, &zero64, 8); /* data_len */
    /* no data */

    uint8_t zero_owner[32] = {0};
    sol_sha256_update(&ctx, zero_owner, 32);

    uint8_t exec = 0;
    sol_sha256_update(&ctx, &exec, 1);

    sol_sha256_update(&ctx, &zero64, 8); /* rent_epoch */
    sol_sha256_final_bytes(&ctx, out_hash->bytes);
}

void
sol_accounts_db_hash_delta(sol_accounts_db_t* db, sol_hash_t* out_hash) {
    if (!db || !out_hash) return;

    /* No local delta layer - fall back to full accounts hash. */
    if (!db->parent) {
        sol_accounts_db_hash(db, out_hash);
        return;
    }

    accounts_hash_collect_ctx_t c = {0};
    c.err = SOL_OK;

    pthread_rwlock_rdlock(&db->lock);

    for (size_t i = 0; i < db->bucket_count; i++) {
        sol_account_entry_t* entry = db->buckets[i];
        while (entry) {
            if (c.count == c.cap) {
                size_t new_cap = c.cap ? (c.cap * 2) : 1024;
                if (new_cap < c.cap) {
                    c.err = SOL_ERR_OVERFLOW;
                    pthread_rwlock_unlock(&db->lock);
                    goto finalize;
                }

                accounts_hash_entry_t* new_entries = sol_realloc(c.entries, new_cap * sizeof(*new_entries));
                if (!new_entries) {
                    c.err = SOL_ERR_NOMEM;
                    pthread_rwlock_unlock(&db->lock);
                    goto finalize;
                }

                c.entries = new_entries;
                c.cap = new_cap;
            }

            accounts_hash_entry_t* e = &c.entries[c.count++];
            e->pubkey = entry->pubkey;
            if (entry->account && entry->account->meta.lamports != 0) {
                sol_account_hash(&entry->pubkey, entry->account, &e->hash);
            } else {
                hash_deleted_account(&entry->pubkey, &e->hash);
            }

            entry = entry->next;
        }
    }

    pthread_rwlock_unlock(&db->lock);

finalize:
    if (c.err != SOL_OK) {
        memset(out_hash->bytes, 0, sizeof(out_hash->bytes));
        sol_free(c.entries);
        return;
    }

    if (c.count == 0) {
        memset(out_hash->bytes, 0, sizeof(out_hash->bytes));
        sol_free(c.entries);
        return;
    }

    qsort(c.entries, c.count, sizeof(c.entries[0]), accounts_hash_entry_cmp);

    /* Solana accounts-delta hash: hash of the concatenation of the state hashes
     * of each account modified during the current slot (sorted by pubkey). */
    sol_sha256_ctx_t sha;
    sol_sha256_init(&sha);
    for (size_t i = 0; i < c.count; i++) {
        sol_sha256_update(&sha, c.entries[i].hash.bytes, SOL_HASH_SIZE);
    }

    sol_sha256_final_bytes(&sha, out_hash->bytes);
    sol_free(c.entries);
}

void
sol_accounts_db_hash(sol_accounts_db_t* db, sol_hash_t* out_hash) {
    if (!db || !out_hash) return;

    /* Fast path: root RocksDB backend already iterates pubkeys in sorted order,
     * so we can stream a fanout-16 merkle reduction without allocating. */
    if (!db->parent && db->backend) {
        accounts_hash_backend_ctx_t c = {0};
        c.db = db;
        c.builder.err = SOL_OK;
        c.start_ms = monotonic_ms();
        c.last_log_ms = c.start_ms;

        pthread_rwlock_rdlock(&db->lock);
        db->backend->iterate(db->backend->ctx, accounts_hash_backend_iter_cb, &c);
        pthread_rwlock_unlock(&db->lock);

        if (c.builder.err != SOL_OK) {
            memset(out_hash->bytes, 0, sizeof(out_hash->bytes));
            return;
        }

        accounts_hash_builder_finalize(&c.builder, out_hash);
        return;
    }

    accounts_hash_collect_ctx_t c = {0};
    c.err = SOL_OK;

    sol_accounts_db_iterate(db, accounts_hash_collect_cb, &c);
    if (c.err != SOL_OK) {
        memset(out_hash->bytes, 0, sizeof(out_hash->bytes));
        sol_free(c.entries);
        return;
    }

    if (c.count == 0) {
        memset(out_hash->bytes, 0, sizeof(out_hash->bytes));
        sol_free(c.entries);
        return;
    }

    qsort(c.entries, c.count, sizeof(c.entries[0]), accounts_hash_entry_cmp);

    /* Solana-style accounts hash: merkle root over sorted account hashes using
     * a higher fanout for parallel reduction.
     *
     * Note: Solana uses a fixed merkle fanout (currently 16) for accounts hash
     * computation. */
    const size_t fanout = 16;
    sol_hash_t* level = sol_alloc(c.count * sizeof(sol_hash_t));
    if (!level) {
        memset(out_hash->bytes, 0, sizeof(out_hash->bytes));
        sol_free(c.entries);
        return;
    }
    for (size_t i = 0; i < c.count; i++) {
        level[i] = c.entries[i].hash;
    }
    sol_free(c.entries);
    c.entries = NULL;

    size_t level_len = c.count;
    while (level_len > 1) {
        size_t next_len = (level_len + fanout - 1) / fanout;
        sol_hash_t* next = sol_alloc(next_len * sizeof(sol_hash_t));
        if (!next) {
            memset(out_hash->bytes, 0, sizeof(out_hash->bytes));
            sol_free(level);
            return;
        }

        for (size_t i = 0; i < next_len; i++) {
            size_t start = i * fanout;
            size_t end = start + fanout;
            if (end > level_len) {
                end = level_len;
            }
            hash_group_sha256(&level[start], end - start, &next[i]);
        }

        sol_free(level);
        level = next;
        level_len = next_len;
    }

    *out_hash = level[0];
    sol_free(level);
}

void
sol_accounts_db_stats(const sol_accounts_db_t* db, sol_accounts_db_stats_t* stats) {
    if (!db || !stats) return;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&db->lock);
    stats->accounts_count = atomic_load_u64(&db->stats.accounts_count);
    stats->total_lamports = atomic_load_u64(&db->stats.total_lamports);
    stats->total_data_bytes = atomic_load_u64(&db->stats.total_data_bytes);
    stats->loads = atomic_load_u64(&db->stats.loads);
    stats->stores = atomic_load_u64(&db->stats.stores);
    stats->load_misses = atomic_load_u64(&db->stats.load_misses);
    pthread_rwlock_unlock((pthread_rwlock_t*)&db->lock);
}

void
sol_accounts_db_stats_reset(sol_accounts_db_t* db) {
    if (!db) return;

    pthread_rwlock_wrlock(&db->lock);

    /* Preserve counts, reset operation counts */
    uint64_t accounts = db->stats.accounts_count;
    uint64_t lamports = db->stats.total_lamports;
    uint64_t data_bytes = db->stats.total_data_bytes;

    memset(&db->stats, 0, sizeof(db->stats));

    db->stats.accounts_count = accounts;
    db->stats.total_lamports = lamports;
    db->stats.total_data_bytes = data_bytes;

    pthread_rwlock_unlock(&db->lock);
}

sol_accounts_db_t*
sol_accounts_db_snapshot(sol_accounts_db_t* db) {
    if (!db) return NULL;

    /* Always materialize snapshots into an in-memory DB to avoid accidentally
     * reopening the same RocksDB path. */
    sol_accounts_db_config_t cfg = db->config;
    cfg.storage_type = SOL_ACCOUNTS_STORAGE_MEMORY;
    cfg.rocksdb_path = NULL;
    cfg.quiet = true;

    sol_accounts_db_t* snapshot = sol_accounts_db_new(&cfg);
    if (!snapshot) return NULL;

    accounts_snapshot_ctx_t sctx = {
        .snapshot = snapshot,
        .failed = false,
    };

    sol_accounts_db_iterate(db, accounts_snapshot_cb, &sctx);
    if (sctx.failed) {
        sol_accounts_db_destroy(snapshot);
        return NULL;
    }

    return snapshot;
}

sol_accounts_db_t*
sol_accounts_db_fork(sol_accounts_db_t* parent) {
    if (!parent) return NULL;

    sol_accounts_db_config_t cfg = parent->config;
    cfg.storage_type = SOL_ACCOUNTS_STORAGE_MEMORY;
    cfg.rocksdb_path = NULL;
    cfg.quiet = true;
    /* Fork views only store per-bank deltas, so keep the table reasonably
     * small to avoid per-bank memory blowups. */
    size_t fork_cap = cfg.initial_capacity;
    if (fork_cap > 8192) fork_cap = 8192;
    if (fork_cap < 1024) fork_cap = 1024;
    cfg.initial_capacity = fork_cap;

    sol_accounts_db_t* fork = sol_accounts_db_new(&cfg);
    if (!fork) return NULL;

    fork->parent = parent;

    /* Initialize effective stats from parent so totals/counts remain correct. */
    sol_accounts_db_stats_t parent_stats;
    sol_accounts_db_stats(parent, &parent_stats);
    fork->stats.accounts_count = parent_stats.accounts_count;
    fork->stats.total_lamports = parent_stats.total_lamports;
    fork->stats.total_data_bytes = parent_stats.total_data_bytes;

    return fork;
}

static sol_err_t
appendvec_index_updates_push(sol_appendvec_index_update_t** updates,
                             size_t* len,
                             size_t* cap,
                             const sol_pubkey_t* pubkey,
                             sol_slot_t slot,
                             uint64_t write_version,
                             const sol_pubkey_t* owner,
                             uint64_t lamports,
                             uint64_t data_len,
                             uint64_t file_key,
                             uint64_t record_offset,
                             const sol_hash_t* leaf_hash) {
    if (!updates || !len || !cap || !pubkey) return SOL_ERR_INVAL;

    if (*len == *cap) {
        size_t new_cap = (*cap != 0) ? (*cap * 2u) : 4096u;
        if (new_cap < *cap) return SOL_ERR_OVERFLOW;
        sol_appendvec_index_update_t* next =
            sol_realloc(*updates, new_cap * sizeof(*next));
        if (!next) return SOL_ERR_NOMEM;
        *updates = next;
        *cap = new_cap;
    }

    sol_appendvec_index_update_t* upd = &(*updates)[*len];
    upd->pubkey = *pubkey;
    upd->value.slot = (uint64_t)slot;
    upd->value.write_version = write_version;
    upd->value.file_key = file_key;
    upd->value.record_offset = record_offset;
    upd->value.lamports = lamports;
    upd->value.data_len = data_len;
    if (owner) {
        upd->value.owner = *owner;
    } else {
        memset(upd->value.owner.bytes, 0, sizeof(upd->value.owner.bytes));
    }
    if (lamports != 0 && leaf_hash) {
        upd->value.leaf_hash = *leaf_hash;
    } else {
        memset(upd->value.leaf_hash.bytes, 0, sizeof(upd->value.leaf_hash.bytes));
    }

    (*len)++;
    return SOL_OK;
}

sol_err_t
sol_accounts_db_apply_delta_default_slot_ex(sol_accounts_db_t* dst,
                                            sol_accounts_db_t* src,
                                            sol_slot_t default_slot,
                                            bool src_immutable) {
    if (!dst || !src) return SOL_ERR_INVAL;
    if (!src->parent) return SOL_ERR_INVAL;

    static uint32_t warned_bad_slot = 0;
    static uint32_t warned_appendvec_index_batch = 0;

    /* Overlays should never store slot==0 entries in production. If they do,
     * root advancement must not try to write into slot 0's AppendVec (often
     * sealed from snapshot/genesis). Use the bank slot passed by the caller. */
    const bool use_default_slot = (default_slot != 0);
    const owner_track_mode_t owner_track_mode = accounts_db_owner_track_mode(dst);

    sol_accounts_db_local_snapshot_view_t src_view = {0};
    bool have_src_view = false;
    sol_accounts_db_stats_t src_stats = {0};

    if (src_immutable) {
        if (sol_accounts_db_snapshot_local_view_immutable(src, &src_view) == SOL_OK) {
            have_src_view = true;
            sol_accounts_db_stats(src, &src_stats);
        }
    }

    /* Fast path: bulk-apply overlay deltas into a persistent root (RocksDB).
     * This is a hot path during root advancement/catchup, so avoid per-account
     * read-modify-write overhead. */
    bool can_bulk_apply =
        (dst->parent == NULL) &&
        (dst->backend && dst->backend->batch_write) &&
        (dst->config.storage_type == SOL_ACCOUNTS_STORAGE_ROCKSDB) &&
        (src->backend == NULL); /* overlays are in-memory */

    if (can_bulk_apply) {
        const size_t batch_cap = 262144;
        sol_accounts_db_bulk_writer_t* bulk = sol_accounts_db_bulk_writer_new(dst, batch_cap);
        if (bulk) {
            if (owner_track_mode != OWNER_TRACK_MODE_NONE) {
                sol_err_t idx_err = sol_accounts_db_bulk_writer_set_write_owner_index(bulk, true);
                if (idx_err != SOL_OK) {
                    sol_accounts_db_bulk_writer_destroy(bulk);
                    bulk = NULL;
                } else if (owner_track_mode == OWNER_TRACK_MODE_CORE) {
                    sol_accounts_db_bulk_writer_set_write_owner_index_core_only(bulk, true);
                }
            }
        }

        if (bulk) {
            sol_err_t first_err = SOL_OK;

            if (have_src_view) {
                for (size_t i = 0; i < src_view.len && first_err == SOL_OK; i++) {
                    const sol_accounts_db_local_entry_t* entry = &src_view.entries[i];
                    sol_slot_t eff_slot = entry->slot;
                    if (__builtin_expect(use_default_slot && eff_slot == 0, 0)) {
                        uint32_t n = __atomic_fetch_add(&warned_bad_slot, 1u, __ATOMIC_RELAXED);
                        if (n < 8u) {
                            sol_log_warn("apply_delta: overlay entry slot=0; substituting default_slot=%lu",
                                         (unsigned long)default_slot);
                        }
                        eff_slot = default_slot;
                    }
                    if (entry->account) {
                        first_err = sol_accounts_db_bulk_writer_put_versioned(bulk,
                                                                              &entry->pubkey,
                                                                              entry->account,
                                                                              eff_slot,
                                                                              entry->write_version);
                    } else {
                        first_err = sol_accounts_db_bulk_writer_delete_versioned(bulk,
                                                                                 &entry->pubkey,
                                                                                 eff_slot,
                                                                                 entry->write_version);
                        if (first_err == SOL_ERR_NOTFOUND) {
                            first_err = SOL_OK;
                        }
                    }
                }
            } else {
                /* Overlay writers only take a shared lock plus stripe locks; take
                 * an exclusive lock while walking bucket chains. */
                pthread_rwlock_wrlock(&src->lock);
                src_stats = src->stats;
                for (size_t i = 0; i < src->bucket_count && first_err == SOL_OK; i++) {
                    sol_account_entry_t* entry = src->buckets[i];
                    while (entry && first_err == SOL_OK) {
                        sol_slot_t eff_slot = entry->slot;
                        if (__builtin_expect(use_default_slot && eff_slot == 0, 0)) {
                            uint32_t n = __atomic_fetch_add(&warned_bad_slot, 1u, __ATOMIC_RELAXED);
                            if (n < 8u) {
                                sol_log_warn("apply_delta: overlay entry slot=0; substituting default_slot=%lu",
                                             (unsigned long)default_slot);
                            }
                            eff_slot = default_slot;
                        }
                        if (entry->account) {
                            first_err = sol_accounts_db_bulk_writer_put_versioned(bulk,
                                                                                  &entry->pubkey,
                                                                                  entry->account,
                                                                                  eff_slot,
                                                                                  entry->write_version);
                        } else {
                            first_err = sol_accounts_db_bulk_writer_delete_versioned(bulk,
                                                                                     &entry->pubkey,
                                                                                     eff_slot,
                                                                                     entry->write_version);
                            if (first_err == SOL_ERR_NOTFOUND) {
                                first_err = SOL_OK;
                            }
                        }
                        entry = entry->next;
                    }
                }
                pthread_rwlock_unlock(&src->lock);
            }

            if (first_err == SOL_OK) {
                first_err = sol_accounts_db_bulk_writer_flush(bulk);
            }

            sol_accounts_db_bulk_writer_destroy(bulk);

            if (first_err != SOL_OK) {
                if (have_src_view) {
                    sol_accounts_db_local_snapshot_view_free(&src_view);
                }
                return first_err;
            }

            /* Overlay stats represent the merged view after applying the delta.
             * If the destination DB matched the overlay parent state, we can
             * fast-forward totals/counts without re-scanning. */
            pthread_rwlock_wrlock(&dst->lock);
            dst->stats.accounts_count = src_stats.accounts_count;
            dst->stats.total_lamports = src_stats.total_lamports;
            dst->stats.total_data_bytes = src_stats.total_data_bytes;
            dst->account_count = (size_t)src_stats.accounts_count;
            pthread_rwlock_unlock(&dst->lock);

            if (have_src_view) {
                sol_accounts_db_local_snapshot_view_free(&src_view);
            }
            return SOL_OK;
        }
    }

    /* Fast path: bulk-apply overlay deltas into an AppendVec-rooted DB.
     *
     * Root advancement can apply tens or hundreds of thousands of updates in a
     * burst; doing per-key RocksDB puts and owner-index maintenance here
     * creates multi-second stalls.  Instead, write new AppendVec records and
     * batch the index updates with RocksDB write batches. */
    bool can_bulk_apply_appendvec =
        (dst->parent == NULL) &&
        (dst->backend && dst->backend->batch_write) &&
        (dst->config.storage_type == SOL_ACCOUNTS_STORAGE_APPENDVEC) &&
        (src->backend == NULL); /* overlays are in-memory */

    if (can_bulk_apply_appendvec) {
        const size_t batch_cap = 262144;
        sol_accounts_db_bulk_writer_t* bulk = sol_accounts_db_bulk_writer_new(dst, batch_cap);
        if (bulk) {
            if (owner_track_mode != OWNER_TRACK_MODE_NONE) {
                sol_err_t idx_err = sol_accounts_db_bulk_writer_set_write_owner_index(bulk, true);
                if (idx_err != SOL_OK) {
                    sol_accounts_db_bulk_writer_destroy(bulk);
                    bulk = NULL;
                } else if (owner_track_mode == OWNER_TRACK_MODE_CORE) {
                    sol_accounts_db_bulk_writer_set_write_owner_index_core_only(bulk, true);
                }
            }
        }

        if (bulk) {
            sol_err_t first_err = SOL_OK;
            const sol_pubkey_t zero_owner = {0};
            sol_appendvec_index_update_t* index_updates = NULL;
            size_t index_updates_len = 0;
            size_t index_updates_cap = 0;
            const bool track_index = (dst->appendvec_index != NULL);

            if (have_src_view) {
                for (size_t i = 0; i < src_view.len && first_err == SOL_OK; i++) {
                    const sol_accounts_db_local_entry_t* entry = &src_view.entries[i];
                    sol_slot_t eff_slot = entry->slot;
                    if (__builtin_expect(use_default_slot && eff_slot == 0, 0)) {
                        uint32_t n = __atomic_fetch_add(&warned_bad_slot, 1u, __ATOMIC_RELAXED);
                        if (n < 8u) {
                            sol_log_warn("apply_delta: overlay entry slot=0; substituting default_slot=%lu",
                                         (unsigned long)default_slot);
                        }
                        eff_slot = default_slot;
                    }
                    const sol_pubkey_t* pubkey = &entry->pubkey;
                    const sol_account_t* account = entry->account;

                    /* Commit semantics: treat 0-lamport accounts as deleted in
                     * the rooted DB (tombstone in the index). */
                    bool deleted = (!account) || (account->meta.lamports == 0);
                    if (deleted) {
                        first_err = sol_accounts_db_bulk_writer_put_snapshot_account(
                            bulk,
                            pubkey,
                            &zero_owner,
                            0,      /* lamports */
                            NULL,   /* data */
                            0,      /* data_len */
                            false,  /* executable */
                            0,      /* rent_epoch */
                            eff_slot,
                            entry->write_version,
                            NULL,   /* leaf_hash */
                            0,      /* file_key */
                            0       /* record_offset */
                        );
                        if (first_err == SOL_OK && track_index) {
                            first_err = appendvec_index_updates_push(&index_updates,
                                                                     &index_updates_len,
                                                                     &index_updates_cap,
                                                                     pubkey,
                                                                     eff_slot,
                                                                     entry->write_version,
                                                                     NULL,
                                                                     0,
                                                                     0,
                                                                     0,
                                                                     0,
                                                                     NULL);
                        }
                        continue;
                    }

                    uint64_t file_key = ((uint64_t)eff_slot << 32) | 0u;
                    uint64_t record_offset = 0;
                    sol_err_t aerr = appendvec_append_record_solana3(dst,
                                                                     &file_key,
                                                                     pubkey,
                                                                     account,
                                                                     entry->write_version,
                                                                     &record_offset);
                    if (aerr != SOL_OK) {
                        first_err = aerr;
                        break;
                    }

                    sol_hash_t leaf = {0};
                    sol_account_hash(pubkey, account, &leaf);

                    first_err = sol_accounts_db_bulk_writer_put_snapshot_account(
                        bulk,
                        pubkey,
                        &account->meta.owner,
                        (uint64_t)account->meta.lamports,
                        account->data,
                        (uint64_t)account->meta.data_len,
                        account->meta.executable,
                        (uint64_t)account->meta.rent_epoch,
                        eff_slot,
                        entry->write_version,
                        &leaf,
                        file_key,
                        record_offset
                    );
                    if (first_err == SOL_OK && track_index) {
                        first_err = appendvec_index_updates_push(&index_updates,
                                                                 &index_updates_len,
                                                                 &index_updates_cap,
                                                                 pubkey,
                                                                 eff_slot,
                                                                 entry->write_version,
                                                                 &account->meta.owner,
                                                                 (uint64_t)account->meta.lamports,
                                                                 (uint64_t)account->meta.data_len,
                                                                 file_key,
                                                                 record_offset,
                                                                 &leaf);
                    }
                }
            } else {
                /* Overlay writers only take a shared lock plus stripe locks; take
                 * an exclusive lock while walking bucket chains. */
                pthread_rwlock_wrlock(&src->lock);
                src_stats = src->stats;
                for (size_t i = 0; i < src->bucket_count && first_err == SOL_OK; i++) {
                    sol_account_entry_t* entry = src->buckets[i];
                    while (entry && first_err == SOL_OK) {
                        sol_slot_t eff_slot = entry->slot;
                        if (__builtin_expect(use_default_slot && eff_slot == 0, 0)) {
                            uint32_t n = __atomic_fetch_add(&warned_bad_slot, 1u, __ATOMIC_RELAXED);
                            if (n < 8u) {
                                sol_log_warn("apply_delta: overlay entry slot=0; substituting default_slot=%lu",
                                             (unsigned long)default_slot);
                            }
                            eff_slot = default_slot;
                        }
                        const sol_pubkey_t* pubkey = &entry->pubkey;
                        const sol_account_t* account = entry->account;

                        bool deleted = (!account) || (account->meta.lamports == 0);
                        if (deleted) {
                            first_err = sol_accounts_db_bulk_writer_put_snapshot_account(
                                bulk,
                                pubkey,
                                &zero_owner,
                                0,
                                NULL,
                                0,
                                false,
                                0,
                                eff_slot,
                                entry->write_version,
                                NULL,
                                0,
                                0
                            );
                            if (first_err == SOL_OK && track_index) {
                                first_err = appendvec_index_updates_push(&index_updates,
                                                                         &index_updates_len,
                                                                         &index_updates_cap,
                                                                         pubkey,
                                                                         eff_slot,
                                                                         entry->write_version,
                                                                         NULL,
                                                                         0,
                                                                         0,
                                                                         0,
                                                                         0,
                                                                         NULL);
                            }
                            entry = entry->next;
                            continue;
                        }

                        uint64_t file_key = ((uint64_t)eff_slot << 32) | 0u;
                        uint64_t record_offset = 0;
                        sol_err_t aerr = appendvec_append_record_solana3(dst,
                                                                         &file_key,
                                                                         pubkey,
                                                                         account,
                                                                         entry->write_version,
                                                                         &record_offset);
                        if (aerr != SOL_OK) {
                            first_err = aerr;
                            break;
                        }

                        sol_hash_t leaf = {0};
                        sol_account_hash(pubkey, account, &leaf);
                        first_err = sol_accounts_db_bulk_writer_put_snapshot_account(
                            bulk,
                            pubkey,
                            &account->meta.owner,
                            (uint64_t)account->meta.lamports,
                            account->data,
                            (uint64_t)account->meta.data_len,
                            account->meta.executable,
                            (uint64_t)account->meta.rent_epoch,
                            eff_slot,
                            entry->write_version,
                            &leaf,
                            file_key,
                            record_offset
                        );
                        if (first_err == SOL_OK && track_index) {
                            first_err = appendvec_index_updates_push(&index_updates,
                                                                     &index_updates_len,
                                                                     &index_updates_cap,
                                                                     pubkey,
                                                                     eff_slot,
                                                                     entry->write_version,
                                                                     &account->meta.owner,
                                                                     (uint64_t)account->meta.lamports,
                                                                     (uint64_t)account->meta.data_len,
                                                                     file_key,
                                                                     record_offset,
                                                                     &leaf);
                        }
                        entry = entry->next;
                    }
                }
                pthread_rwlock_unlock(&src->lock);
            }

            if (first_err == SOL_OK) {
                first_err = sol_accounts_db_bulk_writer_flush(bulk);
            }

            if (first_err == SOL_OK && track_index && index_updates_len > 0) {
                sol_err_t ierr = sol_appendvec_index_update_batch(dst->appendvec_index,
                                                                  index_updates,
                                                                  index_updates_len);
                if (ierr != SOL_OK) {
                    uint32_t n = __atomic_fetch_add(&warned_appendvec_index_batch, 1u, __ATOMIC_RELAXED);
                    if (n < 8u) {
                        sol_log_warn("apply_delta: appendvec index batch update failed: %s",
                                     sol_err_str(ierr));
                    }
                }
            }
            sol_accounts_db_bulk_writer_destroy(bulk);
            sol_free(index_updates);

            if (first_err != SOL_OK) {
                if (have_src_view) {
                    sol_accounts_db_local_snapshot_view_free(&src_view);
                }
                return first_err;
            }

            /* Overlay stats represent the merged view after applying the delta.
             * If the destination DB matched the overlay parent state, we can
             * fast-forward totals/counts without re-scanning. */
            pthread_rwlock_wrlock(&dst->lock);
            dst->stats.accounts_count = src_stats.accounts_count;
            dst->stats.total_lamports = src_stats.total_lamports;
            dst->stats.total_data_bytes = src_stats.total_data_bytes;
            dst->account_count = (size_t)src_stats.accounts_count;
            pthread_rwlock_unlock(&dst->lock);

            if (have_src_view) {
                sol_accounts_db_local_snapshot_view_free(&src_view);
            }
            return SOL_OK;
        }
    }

    /* Fallback: apply entries via per-key stores/deletes (portable, slower). */
    if (have_src_view) {
        for (size_t i = 0; i < src_view.len; i++) {
            const sol_accounts_db_local_entry_t* entry = &src_view.entries[i];
            sol_slot_t eff_slot = entry->slot;
            if (__builtin_expect(use_default_slot && eff_slot == 0, 0)) {
                uint32_t n = __atomic_fetch_add(&warned_bad_slot, 1u, __ATOMIC_RELAXED);
                if (n < 8u) {
                    sol_log_warn("apply_delta: overlay entry slot=0; substituting default_slot=%lu",
                                 (unsigned long)default_slot);
                }
                eff_slot = default_slot;
            }

            sol_err_t err;
            if (entry->account) {
                err = sol_accounts_db_store_versioned(dst,
                                                     &entry->pubkey,
                                                     entry->account,
                                                     eff_slot,
                                                     entry->write_version);
            } else {
                err = sol_accounts_db_delete_versioned(dst,
                                                      &entry->pubkey,
                                                      eff_slot,
                                                      entry->write_version);
                if (err == SOL_ERR_NOTFOUND) {
                    err = SOL_OK;
                }
            }
            if (err != SOL_OK) {
                sol_accounts_db_local_snapshot_view_free(&src_view);
                return err;
            }
        }
        sol_accounts_db_local_snapshot_view_free(&src_view);
        return SOL_OK;
    }

    /* Overlay writers only take a shared lock plus stripe locks; take an
     * exclusive lock while walking bucket chains. */
    pthread_rwlock_wrlock(&src->lock);
    for (size_t i = 0; i < src->bucket_count; i++) {
        sol_account_entry_t* entry = src->buckets[i];
        while (entry) {
            sol_slot_t eff_slot = entry->slot;
            if (__builtin_expect(use_default_slot && eff_slot == 0, 0)) {
                uint32_t n = __atomic_fetch_add(&warned_bad_slot, 1u, __ATOMIC_RELAXED);
                if (n < 8u) {
                    sol_log_warn("apply_delta: overlay entry slot=0; substituting default_slot=%lu",
                                 (unsigned long)default_slot);
                }
                eff_slot = default_slot;
            }
            sol_err_t err;
            if (entry->account) {
                err = sol_accounts_db_store_versioned(dst,
                                                     &entry->pubkey,
                                                     entry->account,
                                                     eff_slot,
                                                     entry->write_version);
            } else {
                err = sol_accounts_db_delete_versioned(dst,
                                                      &entry->pubkey,
                                                      eff_slot,
                                                      entry->write_version);
                if (err == SOL_ERR_NOTFOUND) {
                    err = SOL_OK;
                }
            }
            if (err != SOL_OK) {
                pthread_rwlock_unlock(&src->lock);
                return err;
            }
            entry = entry->next;
        }
    }
    pthread_rwlock_unlock(&src->lock);
    return SOL_OK;
}

sol_err_t
sol_accounts_db_apply_delta_default_slot(sol_accounts_db_t* dst,
                                         sol_accounts_db_t* src,
                                         sol_slot_t default_slot) {
    return sol_accounts_db_apply_delta_default_slot_ex(dst, src, default_slot, false);
}

sol_err_t
sol_accounts_db_apply_delta(sol_accounts_db_t* dst, sol_accounts_db_t* src) {
    return sol_accounts_db_apply_delta_default_slot_ex(dst, src, 0, false);
}

void
sol_accounts_db_clear_local(sol_accounts_db_t* db) {
    if (!db || !db->parent) return;

    pthread_rwlock_wrlock(&db->lock);

    for (size_t i = 0; i < db->bucket_count; i++) {
        sol_account_entry_t* entry = db->buckets[i];
        while (entry) {
            sol_account_entry_t* next = entry->next;
            if (entry->account) {
                sol_account_destroy(entry->account);
            }
            sol_free(entry);
            entry = next;
        }
        db->buckets[i] = NULL;
    }

    db->account_count = 0;

    sol_accounts_db_stats_t parent_stats;
    sol_accounts_db_stats(db->parent, &parent_stats);
    db->stats.accounts_count = parent_stats.accounts_count;
    db->stats.total_lamports = parent_stats.total_lamports;
    db->stats.total_data_bytes = parent_stats.total_data_bytes;

    pthread_rwlock_unlock(&db->lock);
}

void
sol_accounts_db_set_parent(sol_accounts_db_t* db, sol_accounts_db_t* parent) {
    if (!db) return;

    pthread_rwlock_wrlock(&db->lock);
    db->parent = parent;
    pthread_rwlock_unlock(&db->lock);
}

sol_accounts_db_t*
sol_accounts_db_get_parent(sol_accounts_db_t* db) {
    if (!db) return NULL;
    pthread_rwlock_rdlock(&db->lock);
    sol_accounts_db_t* p = db->parent;
    pthread_rwlock_unlock(&db->lock);
    return p;
}

static sol_accounts_db_t*
accounts_db_root(sol_accounts_db_t* db) {
    if (!db) return NULL;
    sol_accounts_db_t* cur = db;
    while (cur->parent) cur = cur->parent;
    return cur;
}

static const sol_accounts_db_t*
accounts_db_root_const(const sol_accounts_db_t* db) {
    if (!db) return NULL;
    const sol_accounts_db_t* cur = db;
    while (cur->parent) cur = cur->parent;
    return cur;
}

bool
sol_accounts_db_get_epoch_accounts_hash(const sol_accounts_db_t* db,
                                        uint64_t epoch,
                                        sol_hash_t* out_hash) {
    if (!db || !out_hash) return false;

    const sol_accounts_db_t* root = accounts_db_root_const(db);
    if (!root) return false;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&root->lock);
    bool ok = root->epoch_accounts_hash_valid && (root->epoch_accounts_hash_epoch == epoch);
    if (ok) {
        *out_hash = root->epoch_accounts_hash;
    }
    pthread_rwlock_unlock((pthread_rwlock_t*)&root->lock);

    return ok;
}

sol_err_t
sol_accounts_db_set_epoch_accounts_hash(sol_accounts_db_t* db,
                                        uint64_t epoch,
                                        const sol_hash_t* hash) {
    if (!db || !hash) return SOL_ERR_INVAL;

    sol_accounts_db_t* root = accounts_db_root(db);
    if (!root) return SOL_ERR_INVAL;

    pthread_rwlock_wrlock(&root->lock);
    root->epoch_accounts_hash = *hash;
    root->epoch_accounts_hash_epoch = epoch;
    root->epoch_accounts_hash_valid = true;
    pthread_rwlock_unlock(&root->lock);

    return SOL_OK;
}

bool
sol_accounts_db_get_bootstrap_state(const sol_accounts_db_t* db,
                                    sol_accounts_db_bootstrap_state_t* out_state) {
    if (!db || !out_state) return false;

    const sol_accounts_db_t* root = accounts_db_root_const(db);
    if (!root || !root->owner_reverse_backend) return false;

    uint8_t* buf = NULL;
    size_t buf_len = 0;
    sol_err_t err = root->owner_reverse_backend->get(root->owner_reverse_backend->ctx,
                                                     BOOTSTRAP_STATE_META_KEY,
                                                     sizeof(BOOTSTRAP_STATE_META_KEY) - 1,
                                                     &buf,
                                                     &buf_len);
    if (err != SOL_OK || !buf) {
        sol_free(buf);
        return false;
    }

    if (buf_len != BOOTSTRAP_STATE_LEN_V1 &&
        buf_len != BOOTSTRAP_STATE_LEN_V2 &&
        buf_len != BOOTSTRAP_STATE_LEN_V3) {
        sol_free(buf);
        return false;
    }

    uint32_t magic = 0;
    uint16_t version = 0;
    uint16_t flags16 = 0;
    memcpy(&magic, buf + 0, 4);
    memcpy(&version, buf + 4, 2);
    memcpy(&flags16, buf + 6, 2);
    if (magic != BOOTSTRAP_STATE_MAGIC ||
        (version != BOOTSTRAP_STATE_VERSION_V1 &&
         version != BOOTSTRAP_STATE_VERSION_V2 &&
         version != BOOTSTRAP_STATE_VERSION_V3)) {
        sol_free(buf);
        return false;
    }

    if ((version == BOOTSTRAP_STATE_VERSION_V1 && buf_len != BOOTSTRAP_STATE_LEN_V1) ||
        (version == BOOTSTRAP_STATE_VERSION_V2 && buf_len != BOOTSTRAP_STATE_LEN_V2) ||
        (version == BOOTSTRAP_STATE_VERSION_V3 && buf_len != BOOTSTRAP_STATE_LEN_V3)) {
        sol_free(buf);
        return false;
    }

    memset(out_state, 0, sizeof(*out_state));

    uint64_t slot = 0;
    uint64_t signature_count = 0;
    uint64_t parent_slot = 0;
    memcpy(&slot, buf + 8, 8);
    memcpy(&signature_count, buf + 16, 8);
    memcpy(&parent_slot, buf + 24, 8);

    out_state->slot = (sol_slot_t)slot;
    out_state->parent_slot = (sol_slot_t)parent_slot;
    out_state->signature_count = signature_count;
    out_state->flags = (uint32_t)flags16;

    memcpy(&out_state->ticks_per_slot, buf + 32, 8);
    memcpy(&out_state->slots_per_epoch, buf + 40, 8);
    memcpy(&out_state->lamports_per_signature, buf + 48, 8);
    memcpy(&out_state->rent_per_byte_year, buf + 56, 8);
    memcpy(&out_state->rent_exemption_threshold, buf + 64, 8);

    memcpy(out_state->blockhash.bytes, buf + 72, SOL_HASH_SIZE);
    memcpy(out_state->parent_bank_hash.bytes, buf + 104, SOL_HASH_SIZE);
    memcpy(out_state->bank_hash.bytes, buf + 136, SOL_HASH_SIZE);
    memcpy(out_state->accounts_lt_hash.v, buf + 168, sizeof(out_state->accounts_lt_hash.v));

    if (version == BOOTSTRAP_STATE_VERSION_V2 || version == BOOTSTRAP_STATE_VERSION_V3) {
        memcpy(&out_state->hashes_per_tick, buf + BOOTSTRAP_STATE_LEN_V1, 8);
    } else {
        out_state->hashes_per_tick = 0;
    }

    if (version == BOOTSTRAP_STATE_VERSION_V3) {
        memcpy(out_state->genesis_hash.bytes, buf + BOOTSTRAP_STATE_LEN_V2, SOL_HASH_SIZE);
        memcpy(&out_state->shred_version, buf + BOOTSTRAP_STATE_LEN_V2 + SOL_HASH_SIZE, 4);
    } else {
        memset(out_state->genesis_hash.bytes, 0, SOL_HASH_SIZE);
        out_state->shred_version = 0;
        out_state->flags &= ~(SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_GENESIS_HASH |
                              SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_SHRED_VERSION);
    }

    sol_free(buf);
    return true;
}

sol_err_t
sol_accounts_db_set_bootstrap_state(sol_accounts_db_t* db,
                                    const sol_accounts_db_bootstrap_state_t* state) {
    if (!db || !state) return SOL_ERR_INVAL;

    sol_accounts_db_t* root = accounts_db_root(db);
    if (!root || !root->owner_reverse_backend) {
        return SOL_OK;
    }

    uint8_t buf[BOOTSTRAP_STATE_LEN_V3];
    memset(buf, 0, sizeof(buf));

    uint32_t magic = BOOTSTRAP_STATE_MAGIC;
    uint16_t version = BOOTSTRAP_STATE_VERSION_V3;
    uint16_t flags16 = (uint16_t)(state->flags & 0xFFFFu);
    memcpy(buf + 0, &magic, 4);
    memcpy(buf + 4, &version, 2);
    memcpy(buf + 6, &flags16, 2);

    uint64_t slot = (uint64_t)state->slot;
    uint64_t parent_slot = (uint64_t)state->parent_slot;
    memcpy(buf + 8, &slot, 8);
    memcpy(buf + 16, &state->signature_count, 8);
    memcpy(buf + 24, &parent_slot, 8);

    memcpy(buf + 32, &state->ticks_per_slot, 8);
    memcpy(buf + 40, &state->slots_per_epoch, 8);
    memcpy(buf + 48, &state->lamports_per_signature, 8);
    memcpy(buf + 56, &state->rent_per_byte_year, 8);
    memcpy(buf + 64, &state->rent_exemption_threshold, 8);

    memcpy(buf + 72, state->blockhash.bytes, SOL_HASH_SIZE);
    memcpy(buf + 104, state->parent_bank_hash.bytes, SOL_HASH_SIZE);
    memcpy(buf + 136, state->bank_hash.bytes, SOL_HASH_SIZE);
    memcpy(buf + 168, state->accounts_lt_hash.v, sizeof(state->accounts_lt_hash.v));

    memcpy(buf + BOOTSTRAP_STATE_LEN_V1, &state->hashes_per_tick, 8);

    if (state->flags & SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_GENESIS_HASH) {
        memcpy(buf + BOOTSTRAP_STATE_LEN_V2, state->genesis_hash.bytes, SOL_HASH_SIZE);
    }

    uint32_t shred_version = 0;
    if (state->flags & SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_SHRED_VERSION) {
        shred_version = state->shred_version;
    }
    memcpy(buf + BOOTSTRAP_STATE_LEN_V2 + SOL_HASH_SIZE, &shred_version, 4);

    return root->owner_reverse_backend->put(root->owner_reverse_backend->ctx,
                                           BOOTSTRAP_STATE_META_KEY,
                                           sizeof(BOOTSTRAP_STATE_META_KEY) - 1,
                                           buf,
                                           sizeof(buf));
}

bool
sol_accounts_db_get_bootstrap_blockhash_queue(const sol_accounts_db_t* db,
                                              sol_hash_t* out_hashes,
                                              uint64_t* out_lamports_per_signature,
                                              size_t out_cap,
                                              size_t* out_len) {
    if (out_len) {
        *out_len = 0;
    }
    if (!db || !out_hashes || !out_lamports_per_signature || out_cap == 0 || !out_len) {
        return false;
    }

    const sol_accounts_db_t* root = accounts_db_root_const(db);
    if (!root || !root->owner_reverse_backend) return false;

    uint8_t* buf = NULL;
    size_t buf_len = 0;
    sol_err_t err = root->owner_reverse_backend->get(root->owner_reverse_backend->ctx,
                                                     BOOTSTRAP_BLOCKHASH_QUEUE_META_KEY,
                                                     sizeof(BOOTSTRAP_BLOCKHASH_QUEUE_META_KEY) - 1,
                                                     &buf,
                                                     &buf_len);
    if (err != SOL_OK || !buf) {
        sol_free(buf);
        return false;
    }

    if (buf_len < 12) {
        sol_free(buf);
        return false;
    }

    uint32_t magic = 0;
    uint16_t version = 0;
    uint16_t reserved = 0;
    uint32_t len32 = 0;
    memcpy(&magic, buf + 0, 4);
    memcpy(&version, buf + 4, 2);
    memcpy(&reserved, buf + 6, 2);
    memcpy(&len32, buf + 8, 4);
    (void)reserved;

    if (magic != BOOTSTRAP_BLOCKHASH_QUEUE_MAGIC ||
        version != BOOTSTRAP_BLOCKHASH_QUEUE_VERSION_V1) {
        sol_free(buf);
        return false;
    }

    size_t len = (size_t)len32;
    if (len == 0 || len > SOL_MAX_RECENT_BLOCKHASHES) {
        sol_free(buf);
        return false;
    }
    if (len > out_cap) {
        sol_free(buf);
        return false;
    }

    size_t expect = 12 + len * 40u;
    if (buf_len != expect) {
        sol_free(buf);
        return false;
    }

    size_t off = 12;
    for (size_t i = 0; i < len; i++) {
        memcpy(out_hashes[i].bytes, buf + off, SOL_HASH_SIZE);
        off += SOL_HASH_SIZE;
        memcpy(&out_lamports_per_signature[i], buf + off, 8);
        off += 8;
    }

    sol_free(buf);
    *out_len = len;
    return true;
}

sol_err_t
sol_accounts_db_set_bootstrap_blockhash_queue(sol_accounts_db_t* db,
                                              const sol_hash_t* hashes,
                                              const uint64_t* lamports_per_signature,
                                              size_t len) {
    if (!db || !hashes || !lamports_per_signature || len == 0) return SOL_ERR_INVAL;
    if (len > SOL_MAX_RECENT_BLOCKHASHES) return SOL_ERR_RANGE;

    sol_accounts_db_t* root = accounts_db_root(db);
    if (!root || !root->owner_reverse_backend) {
        return SOL_OK;
    }

    size_t buf_len = 12 + len * 40u;
    if (buf_len < 12) return SOL_ERR_OVERFLOW;

    uint8_t* buf = sol_alloc(buf_len);
    if (!buf) return SOL_ERR_NOMEM;
    memset(buf, 0, buf_len);

    uint32_t magic = BOOTSTRAP_BLOCKHASH_QUEUE_MAGIC;
    uint16_t version = BOOTSTRAP_BLOCKHASH_QUEUE_VERSION_V1;
    uint16_t reserved = 0;
    uint32_t len32 = (uint32_t)len;
    memcpy(buf + 0, &magic, 4);
    memcpy(buf + 4, &version, 2);
    memcpy(buf + 6, &reserved, 2);
    memcpy(buf + 8, &len32, 4);

    size_t off = 12;
    for (size_t i = 0; i < len; i++) {
        memcpy(buf + off, hashes[i].bytes, SOL_HASH_SIZE);
        off += SOL_HASH_SIZE;
        memcpy(buf + off, &lamports_per_signature[i], 8);
        off += 8;
    }

    sol_err_t err = root->owner_reverse_backend->put(root->owner_reverse_backend->ctx,
                                                     BOOTSTRAP_BLOCKHASH_QUEUE_META_KEY,
                                                     sizeof(BOOTSTRAP_BLOCKHASH_QUEUE_META_KEY) - 1,
                                                     buf,
                                                     buf_len);
    sol_free(buf);
    return err;
}
