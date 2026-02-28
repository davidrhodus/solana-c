/*
 * sol_rocksdb.c - RocksDB storage backend implementation
 */

#include "sol_rocksdb.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#ifdef SOL_HAS_ROCKSDB
#include <rocksdb/c.h>
#endif

/*
 * Maximum number of column families
 */
#define MAX_COLUMN_FAMILIES 16

/*
 * Column family context
 */
typedef struct {
    char*                       name;
#ifdef SOL_HAS_ROCKSDB
    rocksdb_column_family_handle_t* handle;
#else
    void*                       handle;
#endif
    sol_storage_backend_t*      backend;
} cf_context_t;

/*
 * RocksDB instance
 */
struct sol_rocksdb {
    sol_rocksdb_config_t        config;
#ifdef SOL_HAS_ROCKSDB
    rocksdb_t*                  db;
    rocksdb_options_t*          options;
    rocksdb_mergeoperator_t*    merge_operator;
    rocksdb_writeoptions_t*     write_options;
    rocksdb_readoptions_t*      read_options;
    rocksdb_block_based_table_options_t* table_options;
    rocksdb_cache_t*            block_cache;
#else
    void*                       db;
    void*                       options;
    void*                       write_options;
    void*                       read_options;
    void*                       table_options;
    void*                       block_cache;
#endif
    cf_context_t                column_families[MAX_COLUMN_FAMILIES];
    size_t                      cf_count;
    pthread_mutex_t             lock;
    sol_rocksdb_stats_t         stats;
};

#ifdef SOL_HAS_ROCKSDB

static bool
sol_rocksdb_open_err_is_lock_conflict(const char* err) {
    if (!err) return false;
    /* RocksDB typically reports lock contention like:
     *   "IO error: While lock file: <path>/LOCK: Resource temporarily unavailable" */
    return strstr(err, "While lock file:") != NULL ||
           strstr(err, "lock file") != NULL ||
           strstr(err, "LOCK:") != NULL;
}

static void
sol_rocksdb_set_errno_from_open_err(const char* err) {
    if (!err) return;
    if (sol_rocksdb_open_err_is_lock_conflict(err)) {
        errno = EBUSY;
    }
}

/*
 * Merge operator for "versioned values" with a fixed header prefix.
 *
 * AccountsDB stores values as:
 *   [magic u32][reserved u32][slot u64][write_version u64][account_bytes...]
 *
 * During parallel snapshot ingestion we may write multiple versions of the
 * same account out-of-order. Using RocksDB Merge with this operator makes the
 * result independent of write ordering by always selecting the greatest
 * (write_version, slot) tuple. Ties are broken deterministically by length and
 * then lexicographic value bytes.
 */
#define SOL_VERSIONED_VALUE_MAGIC 0x31434153u /* "SAC1" */
typedef struct {
    uint32_t magic;
    uint32_t reserved;
    uint64_t slot;
    uint64_t write_version;
} sol_versioned_value_header_t;

static bool
sol_versioned_value_get_version(const char* value,
                                size_t value_len,
                                uint64_t* out_slot,
                                uint64_t* out_write_version) {
    if (!value || value_len < sizeof(sol_versioned_value_header_t)) return false;

    sol_versioned_value_header_t hdr;
    memcpy(&hdr, value, sizeof(hdr));
    if (hdr.magic != SOL_VERSIONED_VALUE_MAGIC) return false;

    if (out_slot) *out_slot = hdr.slot;
    if (out_write_version) *out_write_version = hdr.write_version;
    return true;
}

typedef struct {
    const char* data;
    size_t      len;
    uint64_t    slot;
    uint64_t    write_version;
    bool        has_version;
} sol_merge_candidate_t;

static sol_merge_candidate_t
sol_merge_candidate(const char* value, size_t value_len) {
    sol_merge_candidate_t c = {
        .data = value,
        .len = value_len,
        .slot = 0,
        .write_version = 0,
        .has_version = false,
    };

    uint64_t slot = 0;
    uint64_t write_version = 0;
    if (sol_versioned_value_get_version(value, value_len, &slot, &write_version)) {
        c.slot = slot;
        c.write_version = write_version;
        c.has_version = true;
    }
    return c;
}

static int
sol_merge_candidate_cmp(const sol_merge_candidate_t* a, const sol_merge_candidate_t* b) {
    if (a->write_version < b->write_version) return -1;
    if (a->write_version > b->write_version) return 1;
    if (a->slot < b->slot) return -1;
    if (a->slot > b->slot) return 1;

    if (a->len < b->len) return -1;
    if (a->len > b->len) return 1;

    if (a->len == 0) return 0;
    int cmp = memcmp(a->data, b->data, a->len);
    if (cmp < 0) return -1;
    if (cmp > 0) return 1;
    return 0;
}

static char*
sol_rocksdb_versioned_merge_full(void* state,
                                 const char* key,
                                 size_t key_length,
                                 const char* existing_value,
                                 size_t existing_value_length,
                                 const char* const* operands_list,
                                 const size_t* operands_list_length,
                                 int num_operands,
                                 unsigned char* success,
                                 size_t* new_value_length) {
    (void)state;
    (void)key;
    (void)key_length;

    if (success) *success = 0;
    if (new_value_length) *new_value_length = 0;

    sol_merge_candidate_t best = {0};
    bool have_best = false;

    if (existing_value && existing_value_length > 0) {
        best = sol_merge_candidate(existing_value, existing_value_length);
        have_best = true;
    }

    for (int i = 0; i < num_operands; i++) {
        const char* op = operands_list[i];
        size_t op_len = operands_list_length[i];
        if (!op || op_len == 0) continue;

        sol_merge_candidate_t c = sol_merge_candidate(op, op_len);
        if (!have_best || sol_merge_candidate_cmp(&best, &c) < 0) {
            best = c;
            have_best = true;
        }
    }

    if (!have_best || !best.data || best.len == 0) {
        if (success) *success = 0;
        if (new_value_length) *new_value_length = 0;
        return NULL;
    }

    char* out = malloc(best.len ? best.len : 1u);
    if (!out) return NULL;
    if (best.len) {
        memcpy(out, best.data, best.len);
    }
    if (success) *success = 1;
    if (new_value_length) *new_value_length = best.len;
    return out;
}

static char*
sol_rocksdb_versioned_merge_partial(void* state,
                                    const char* key,
                                    size_t key_length,
                                    const char* const* operands_list,
                                    const size_t* operands_list_length,
                                    int num_operands,
                                    unsigned char* success,
                                    size_t* new_value_length) {
    (void)state;
    (void)key;
    (void)key_length;

    if (success) *success = 0;
    if (new_value_length) *new_value_length = 0;

    sol_merge_candidate_t best = {0};
    bool have_best = false;

    for (int i = 0; i < num_operands; i++) {
        const char* op = operands_list[i];
        size_t op_len = operands_list_length[i];
        if (!op || op_len == 0) continue;

        sol_merge_candidate_t c = sol_merge_candidate(op, op_len);
        if (!have_best || sol_merge_candidate_cmp(&best, &c) < 0) {
            best = c;
            have_best = true;
        }
    }

    if (!have_best || !best.data || best.len == 0) {
        if (success) *success = 0;
        if (new_value_length) *new_value_length = 0;
        return NULL;
    }

    char* out = malloc(best.len ? best.len : 1u);
    if (!out) return NULL;
    if (best.len) {
        memcpy(out, best.data, best.len);
    }
    if (success) *success = 1;
    if (new_value_length) *new_value_length = best.len;
    return out;
}

static void
sol_rocksdb_versioned_merge_delete(void* state, const char* value, size_t value_length) {
    (void)state;
    (void)value_length;
    free((void*)value);
}

static const char*
sol_rocksdb_versioned_merge_name(void* state) {
    (void)state;
    return "solana_c_versioned_max_merge";
}

static void
sol_rocksdb_versioned_merge_destroy(void* state) {
    (void)state;
}

/*
 * RocksDB backend operations
 */

typedef struct {
    sol_rocksdb_t*                      db;
    rocksdb_column_family_handle_t*     cf;
} rocksdb_backend_ctx_t;

sol_err_t
sol_rocksdb_backend_get_pinned(sol_storage_backend_t* backend,
                               const uint8_t* key,
                               size_t key_len,
                               const uint8_t** value,
                               size_t* value_len,
                               sol_rocksdb_pinned_slice_t** out_slice) {
    if (value) *value = NULL;
    if (value_len) *value_len = 0;
    if (out_slice) *out_slice = NULL;

    if (!backend || !backend->ctx || !key || !value || !value_len || !out_slice) {
        return SOL_ERR_INVAL;
    }

    rocksdb_backend_ctx_t* rctx = backend->ctx;
    if (!rctx || !rctx->db || !rctx->db->db || !rctx->db->read_options || !rctx->cf) {
        return SOL_ERR_UNSUPPORTED;
    }

    char* err = NULL;
    rocksdb_pinnableslice_t* slice = rocksdb_get_pinned_cf(
        rctx->db->db,
        rctx->db->read_options,
        rctx->cf,
        (const char*)key,
        key_len,
        &err
    );

    if (err) {
        sol_log_error("RocksDB get_pinned error: %s", err);
        rocksdb_free(err);
        if (slice) {
            rocksdb_pinnableslice_destroy(slice);
        }
        return SOL_ERR_IO;
    }

    if (!slice) {
        return SOL_ERR_NOTFOUND;
    }

    size_t len = 0;
    const char* val = rocksdb_pinnableslice_value(slice, &len);
    if (!val) {
        rocksdb_pinnableslice_destroy(slice);
        return SOL_ERR_NOTFOUND;
    }

    /* Preserve storage-backend convention: empty value may be represented as
     * value==NULL, value_len==0. */
    if (len == 0) {
        rocksdb_pinnableslice_destroy(slice);
        *value = NULL;
        *value_len = 0;
        __atomic_fetch_add(&rctx->db->stats.reads, 1, __ATOMIC_RELAXED);
        return SOL_OK;
    }

    *value = (const uint8_t*)val;
    *value_len = len;
    *out_slice = (sol_rocksdb_pinned_slice_t*)slice;
    __atomic_fetch_add(&rctx->db->stats.reads, 1, __ATOMIC_RELAXED);
    return SOL_OK;
}

void
sol_rocksdb_backend_pinned_destroy(sol_rocksdb_pinned_slice_t* slice) {
    if (!slice) return;
    rocksdb_pinnableslice_destroy((rocksdb_pinnableslice_t*)slice);
}

static sol_err_t
sol_rocksdb_backend_get(void* ctx, const uint8_t* key, size_t key_len,
                        uint8_t** value, size_t* value_len) {
    rocksdb_backend_ctx_t* rctx = ctx;
    if (!rctx || !key || !value || !value_len) return SOL_ERR_INVAL;

    char* err = NULL;
    size_t len;

    char* val = rocksdb_get_cf(
        rctx->db->db,
        rctx->db->read_options,
        rctx->cf,
        (const char*)key,
        key_len,
        &len,
        &err
    );

    if (err) {
        sol_log_error("RocksDB get error: %s", err);
        rocksdb_free(err);
        return SOL_ERR_IO;
    }

    if (!val) {
        return SOL_ERR_NOTFOUND;
    }

    /* Preserve the storage backend contract: NULL is a valid representation of
     * an empty value. */
    if (len == 0) {
        rocksdb_free(val);
        *value = NULL;
        *value_len = 0;
        __atomic_fetch_add(&rctx->db->stats.reads, 1, __ATOMIC_RELAXED);
        return SOL_OK;
    }

#ifdef SOL_USE_JEMALLOC
    /* RocksDB allocates return values with libc malloc/free. When we build
     * solana-c with jemalloc, those pointers are not safe to pass to sol_free()
     * (je_free). Copy into our allocator in that configuration. */
    uint8_t* copy = sol_alloc(len);
    if (!copy) {
        rocksdb_free(val);
        return SOL_ERR_NOMEM;
    }
    memcpy(copy, val, len);
    rocksdb_free(val);
    *value = copy; /* Caller frees with sol_free() */
#else
    /* Fast-path: avoid an extra alloc+copy in the hot get() path. The RocksDB C
     * API uses rocksdb_free() which ultimately delegates to libc free(); in the
     * non-jemalloc build sol_free() is also libc free(), so the pointer is safe
     * to hand off to the caller. */
    *value = (uint8_t*)val; /* Caller frees with sol_free() */
#endif
    *value_len = len;

    __atomic_fetch_add(&rctx->db->stats.reads, 1, __ATOMIC_RELAXED);

    return SOL_OK;
}

static sol_err_t
sol_rocksdb_backend_put(void* ctx, const uint8_t* key, size_t key_len,
                        const uint8_t* value, size_t value_len) {
    rocksdb_backend_ctx_t* rctx = ctx;
    if (!rctx || !key || !value) return SOL_ERR_INVAL;

    char* err = NULL;

    rocksdb_put_cf(
        rctx->db->db,
        rctx->db->write_options,
        rctx->cf,
        (const char*)key,
        key_len,
        (const char*)value,
        value_len,
        &err
    );

    if (err) {
        sol_log_error("RocksDB put error: %s", err);
        rocksdb_free(err);
        return SOL_ERR_IO;
    }

    __atomic_fetch_add(&rctx->db->stats.writes, 1, __ATOMIC_RELAXED);

    return SOL_OK;
}

static sol_err_t
sol_rocksdb_backend_del(void* ctx, const uint8_t* key, size_t key_len) {
    rocksdb_backend_ctx_t* rctx = ctx;
    if (!rctx || !key) return SOL_ERR_INVAL;

    char* err = NULL;

    rocksdb_delete_cf(
        rctx->db->db,
        rctx->db->write_options,
        rctx->cf,
        (const char*)key,
        key_len,
        &err
    );

    if (err) {
        sol_log_error("RocksDB delete error: %s", err);
        rocksdb_free(err);
        return SOL_ERR_IO;
    }

    __atomic_fetch_add(&rctx->db->stats.writes, 1, __ATOMIC_RELAXED);

    return SOL_OK;
}

static bool
sol_rocksdb_backend_exists(void* ctx, const uint8_t* key, size_t key_len) {
    uint8_t* value = NULL;
    size_t value_len = 0;

    sol_err_t err = sol_rocksdb_backend_get(ctx, key, key_len, &value, &value_len);
    if (err == SOL_OK) {
        sol_free(value);
        return true;
    }
    return false;
}

static sol_err_t
sol_rocksdb_backend_batch_write(void* ctx, sol_storage_batch_t* batch) {
    rocksdb_backend_ctx_t* rctx = ctx;
    if (!rctx || !batch) return SOL_ERR_INVAL;

    rocksdb_writebatch_t* wb = rocksdb_writebatch_create();
    if (!wb) return SOL_ERR_NOMEM;

    size_t i = 0;
    while (i < batch->count) {
        sol_batch_op_type_t op_type = batch->ops[i].op;
        size_t j = i + 1;
        while (j < batch->count && batch->ops[j].op == op_type) {
            j++;
        }

        if (op_type == SOL_BATCH_OP_PUT) {
            for (size_t k = i; k < j; k++) {
                const sol_batch_op_t* op = &batch->ops[k];
                rocksdb_writebatch_put_cf(wb,
                                          rctx->cf,
                                          (const char*)op->key,
                                          op->key_len,
                                          (const char*)op->value,
                                          op->value_len);
            }
        } else if (op_type == SOL_BATCH_OP_MERGE) {
            for (size_t k = i; k < j; k++) {
                const sol_batch_op_t* op = &batch->ops[k];
                rocksdb_writebatch_merge_cf(wb,
                                            rctx->cf,
                                            (const char*)op->key,
                                            op->key_len,
                                            (const char*)op->value,
                                            op->value_len);
            }
        } else { /* SOL_BATCH_OP_DELETE */
            for (size_t k = i; k < j; k++) {
                const sol_batch_op_t* op = &batch->ops[k];
                rocksdb_writebatch_delete_cf(wb,
                                             rctx->cf,
                                             (const char*)op->key,
                                             op->key_len);
            }
        }

        i = j;
    }

    char* err = NULL;
    rocksdb_write(rctx->db->db, rctx->db->write_options, wb, &err);
    rocksdb_writebatch_destroy(wb);

    if (err) {
        sol_log_error("RocksDB batch write error: %s", err);
        rocksdb_free(err);
        return SOL_ERR_IO;
    }

    __atomic_fetch_add(&rctx->db->stats.writes, batch->count, __ATOMIC_RELAXED);

    return SOL_OK;
}

static void
rocksdb_iterate(void* ctx, sol_storage_iter_cb cb, void* cb_ctx) {
    rocksdb_backend_ctx_t* rctx = ctx;
    if (!rctx || !cb) return;

    rocksdb_iterator_t* iter = rocksdb_create_iterator_cf(
        rctx->db->db,
        rctx->db->read_options,
        rctx->cf
    );

    rocksdb_iter_seek_to_first(iter);

    while (rocksdb_iter_valid(iter)) {
        size_t key_len, value_len;
        const char* key = rocksdb_iter_key(iter, &key_len);
        const char* value = rocksdb_iter_value(iter, &value_len);

        if (!cb((const uint8_t*)key, key_len,
                (const uint8_t*)value, value_len, cb_ctx)) {
            break;
        }

        rocksdb_iter_next(iter);
    }

    rocksdb_iter_destroy(iter);
}

static void
rocksdb_iterate_range(void* ctx, const uint8_t* start_key, size_t start_len,
                      const uint8_t* end_key, size_t end_len,
                      sol_storage_iter_cb cb, void* cb_ctx) {
    rocksdb_backend_ctx_t* rctx = ctx;
    if (!rctx || !cb) return;

    rocksdb_iterator_t* iter = rocksdb_create_iterator_cf(
        rctx->db->db,
        rctx->db->read_options,
        rctx->cf
    );

    if (start_key) {
        rocksdb_iter_seek(iter, (const char*)start_key, start_len);
    } else {
        rocksdb_iter_seek_to_first(iter);
    }

    while (rocksdb_iter_valid(iter)) {
        size_t key_len, value_len;
        const char* key = rocksdb_iter_key(iter, &key_len);
        const char* value = rocksdb_iter_value(iter, &value_len);

        /* Check if we've passed the end key */
        if (end_key) {
            int cmp = memcmp(key, end_key, key_len < end_len ? key_len : end_len);
            if (cmp > 0 || (cmp == 0 && key_len >= end_len)) {
                break;
            }
        }

        if (!cb((const uint8_t*)key, key_len,
                (const uint8_t*)value, value_len, cb_ctx)) {
            break;
        }

        rocksdb_iter_next(iter);
    }

    rocksdb_iter_destroy(iter);
}

typedef struct {
    size_t count;
} count_ctx_t;

static bool count_cb(const uint8_t* key, size_t key_len,
                     const uint8_t* value, size_t value_len, void* ctx) {
    (void)key; (void)key_len; (void)value; (void)value_len;
    count_ctx_t* cctx = ctx;
    cctx->count++;
    return true;
}

static size_t
rocksdb_count(void* ctx) {
    count_ctx_t cctx = {0};
    rocksdb_iterate(ctx, count_cb, &cctx);
    return cctx.count;
}

static sol_err_t
sol_rocksdb_backend_flush(void* ctx) {
    rocksdb_backend_ctx_t* rctx = ctx;
    if (!rctx) return SOL_ERR_INVAL;

    rocksdb_flushoptions_t* flush_opts = rocksdb_flushoptions_create();
    rocksdb_flushoptions_set_wait(flush_opts, 1);

    char* err = NULL;
    rocksdb_flush_cf(rctx->db->db, flush_opts, rctx->cf, &err);
    rocksdb_flushoptions_destroy(flush_opts);

    if (err) {
        sol_log_error("RocksDB flush error: %s", err);
        rocksdb_free(err);
        return SOL_ERR_IO;
    }

    return SOL_OK;
}

static void*
sol_rocksdb_backend_snapshot(void* ctx) {
    rocksdb_backend_ctx_t* rctx = ctx;
    if (!rctx) return NULL;

    return (void*)rocksdb_create_snapshot(rctx->db->db);
}

static void
sol_rocksdb_backend_snapshot_release(void* ctx, void* snapshot) {
    rocksdb_backend_ctx_t* rctx = ctx;
    if (!rctx || !snapshot) return;

    rocksdb_release_snapshot(rctx->db->db, (const rocksdb_snapshot_t*)snapshot);
}

static void
rocksdb_backend_destroy(void* ctx) {
    rocksdb_backend_ctx_t* rctx = ctx;
    if (rctx) {
        free(rctx);
    }
}

/*
 * Create storage backend for column family
 */
static sol_storage_backend_t*
create_cf_backend(sol_rocksdb_t* db, rocksdb_column_family_handle_t* cf) {
    rocksdb_backend_ctx_t* ctx = calloc(1, sizeof(rocksdb_backend_ctx_t));
    if (!ctx) return NULL;

    ctx->db = db;
    ctx->cf = cf;

    sol_storage_backend_t* backend = calloc(1, sizeof(sol_storage_backend_t));
    if (!backend) {
        free(ctx);
        return NULL;
    }

    backend->ctx = ctx;
    backend->get = sol_rocksdb_backend_get;
    backend->put = sol_rocksdb_backend_put;
    backend->del = sol_rocksdb_backend_del;
    backend->exists = sol_rocksdb_backend_exists;
    backend->batch_write = sol_rocksdb_backend_batch_write;
    backend->iterate = rocksdb_iterate;
    backend->iterate_range = rocksdb_iterate_range;
    backend->count = rocksdb_count;
    backend->flush = sol_rocksdb_backend_flush;
    backend->snapshot = sol_rocksdb_backend_snapshot;
    backend->snapshot_release = sol_rocksdb_backend_snapshot_release;
    backend->destroy = rocksdb_backend_destroy;

    return backend;
}

/*
 * Public API implementation
 */

sol_rocksdb_t*
sol_rocksdb_new(const sol_rocksdb_config_t* config) {
    if (!config || !config->path) {
        sol_log_error("RocksDB: invalid config");
        return NULL;
    }

    sol_rocksdb_t* db = calloc(1, sizeof(sol_rocksdb_t));
    if (!db) return NULL;

    db->config = *config;
    db->config.path = strdup(config->path);
    pthread_mutex_init(&db->lock, NULL);

    /* Create options */
    db->options = rocksdb_options_create();
    rocksdb_options_set_create_if_missing(db->options, config->create_if_missing);
    rocksdb_options_set_create_missing_column_families(db->options, 1);

    /* Set write buffer size */
    rocksdb_options_set_write_buffer_size(db->options,
        config->write_buffer_mb * 1024 * 1024);

    /* Set max open files */
    rocksdb_options_set_max_open_files(db->options, config->max_open_files);

    /* Improve ingestion throughput under multi-threaded write loads. */
    rocksdb_options_set_allow_concurrent_memtable_write(db->options, 1);
    rocksdb_options_set_enable_pipelined_write(db->options, 1);

    /* Enable parallel background work (flush/compaction) based on available CPUs.
     * RocksDB's C API does not expose a dynamic DBOptions setter, so we tune this
     * at open time. */
    long cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpu_count > 0) {
        int bg_threads = (int)cpu_count;
        if (bg_threads > 32) bg_threads = 32;
        if (bg_threads < 2) bg_threads = 2;
        rocksdb_options_increase_parallelism(db->options, bg_threads);
    }

    /* Merge operator used by versioned-value snapshot ingestion. This is safe
     * to set unconditionally; it only affects explicit merge operations. */
    db->merge_operator = rocksdb_mergeoperator_create(
        NULL,
        sol_rocksdb_versioned_merge_destroy,
        sol_rocksdb_versioned_merge_full,
        sol_rocksdb_versioned_merge_partial,
        sol_rocksdb_versioned_merge_delete,
        sol_rocksdb_versioned_merge_name);
    if (db->merge_operator) {
        rocksdb_options_set_merge_operator(db->options, db->merge_operator);
    }

    /* Create block cache */
    db->block_cache = rocksdb_cache_create_lru(
        config->block_cache_mb * 1024 * 1024);

    /* Create table options with block cache */
    db->table_options = rocksdb_block_based_options_create();
    rocksdb_block_based_options_set_block_cache(db->table_options, db->block_cache);
    rocksdb_block_based_options_set_filter_policy(
        db->table_options, rocksdb_filterpolicy_create_bloom(10));

    rocksdb_options_set_block_based_table_factory(db->options, db->table_options);

    /* Set compression */
    if (config->compression) {
        rocksdb_options_set_compression(db->options, rocksdb_lz4_compression);
    }

    /* Create read/write options */
    db->write_options = rocksdb_writeoptions_create();
    db->read_options = rocksdb_readoptions_create();

    /* Open database (with column families if DB already has them) */
    char* err = NULL;
    size_t cf_count = 0;
    char** cf_names = rocksdb_list_column_families(db->options, config->path, &cf_count, &err);
    if (err) {
        /* Common case: DB doesn't exist yet. We'll create it with default CF. */
        rocksdb_free(err);
        err = NULL;
        cf_names = NULL;
        cf_count = 0;
    }

    if (cf_names && cf_count > 0) {
        rocksdb_options_t** cf_options = calloc(cf_count, sizeof(rocksdb_options_t*));
        rocksdb_column_family_handle_t** cf_handles =
            calloc(cf_count, sizeof(rocksdb_column_family_handle_t*));

        if (!cf_options || !cf_handles) {
            free(cf_options);
            free(cf_handles);
            rocksdb_list_column_families_destroy(cf_names, cf_count);
            sol_rocksdb_destroy(db);
            return NULL;
        }

        for (size_t i = 0; i < cf_count; i++) {
            cf_options[i] = db->options;
        }

        db->db = rocksdb_open_column_families(db->options, config->path,
                                              (int)cf_count,
                                              (const char* const*)cf_names,
                                              (const rocksdb_options_t* const*)cf_options,
                                              cf_handles,
                                              &err);

        free(cf_options);

        if (err) {
            sol_rocksdb_set_errno_from_open_err(err);
            sol_log_error("RocksDB open error: %s", err);
            rocksdb_free(err);
            free(cf_handles);
            rocksdb_list_column_families_destroy(cf_names, cf_count);
            sol_rocksdb_destroy(db);
            return NULL;
        }

        /* Register opened column families */
        for (size_t i = 0; i < cf_count; i++) {
            if (db->cf_count >= MAX_COLUMN_FAMILIES) {
                rocksdb_column_family_handle_destroy(cf_handles[i]);
                continue;
            }

            cf_context_t* cf_ctx = &db->column_families[db->cf_count++];
            cf_ctx->name = strdup(cf_names[i]);
            cf_ctx->handle = cf_handles[i];
            cf_ctx->backend = create_cf_backend(db, cf_handles[i]);
        }

        free(cf_handles);
        rocksdb_list_column_families_destroy(cf_names, cf_count);
    } else {
        db->db = rocksdb_open(db->options, config->path, &err);
    }

    if (err) {
        sol_rocksdb_set_errno_from_open_err(err);
        sol_log_error("RocksDB open error: %s", err);
        rocksdb_free(err);
        sol_rocksdb_destroy(db);
        return NULL;
    }

    sol_log_info("RocksDB opened at %s (cache=%zuMB, write_buf=%zuMB)",
                 config->path, config->block_cache_mb, config->write_buffer_mb);

    return db;
}

sol_err_t
sol_rocksdb_open_cf(sol_rocksdb_t* db, const char* cf_name) {
    if (!db || !cf_name) return SOL_ERR_INVAL;

    pthread_mutex_lock(&db->lock);

    /* Check if already open */
    for (size_t i = 0; i < db->cf_count; i++) {
        if (strcmp(db->column_families[i].name, cf_name) == 0) {
            pthread_mutex_unlock(&db->lock);
            return SOL_OK;  /* Already open */
        }
    }

    if (db->cf_count >= MAX_COLUMN_FAMILIES) {
        pthread_mutex_unlock(&db->lock);
        return SOL_ERR_NOMEM;
    }

    char* err = NULL;
    rocksdb_column_family_handle_t* cf_handle =
        rocksdb_create_column_family(db->db, db->options, cf_name, &err);
    if (err) {
        sol_log_error("RocksDB create column family error (%s): %s", cf_name, err);
        rocksdb_free(err);
        err = NULL;
    }

    if (!cf_handle) {
        pthread_mutex_unlock(&db->lock);
        return SOL_ERR_IO;
    }

    /* Store column family */
    cf_context_t* cf_ctx = &db->column_families[db->cf_count];
    cf_ctx->name = strdup(cf_name);
    cf_ctx->handle = cf_handle;
    cf_ctx->backend = create_cf_backend(db, cf_handle);

    db->cf_count++;

    pthread_mutex_unlock(&db->lock);

    sol_log_info("RocksDB: opened column family '%s'", cf_name);

    return SOL_OK;
}

sol_storage_backend_t*
sol_rocksdb_get_backend(sol_rocksdb_t* db, const char* cf_name) {
    if (!db || !cf_name) return NULL;

    pthread_mutex_lock(&db->lock);

    for (size_t i = 0; i < db->cf_count; i++) {
        if (strcmp(db->column_families[i].name, cf_name) == 0) {
            sol_storage_backend_t* backend = db->column_families[i].backend;
            pthread_mutex_unlock(&db->lock);
            return backend;
        }
    }

    pthread_mutex_unlock(&db->lock);
    return NULL;
}

sol_err_t
sol_rocksdb_flush_all(sol_rocksdb_t* db) {
    if (!db) return SOL_ERR_INVAL;

    pthread_mutex_lock(&db->lock);

    rocksdb_flushoptions_t* flush_opts = rocksdb_flushoptions_create();
    rocksdb_flushoptions_set_wait(flush_opts, 1);

    for (size_t i = 0; i < db->cf_count; i++) {
        char* err = NULL;
        rocksdb_flush_cf(db->db, flush_opts, db->column_families[i].handle, &err);
        if (err) {
            sol_log_warn("RocksDB flush error for %s: %s",
                         db->column_families[i].name, err);
            rocksdb_free(err);
        }
    }

    rocksdb_flushoptions_destroy(flush_opts);
    pthread_mutex_unlock(&db->lock);

    return SOL_OK;
}

sol_err_t
sol_rocksdb_compact_all(sol_rocksdb_t* db) {
    if (!db) return SOL_ERR_INVAL;

    pthread_mutex_lock(&db->lock);

    for (size_t i = 0; i < db->cf_count; i++) {
        rocksdb_compact_range_cf(
            db->db,
            db->column_families[i].handle,
            NULL, 0,  /* Start key */
            NULL, 0   /* End key - NULL means compact entire range */
        );
        __atomic_fetch_add(&db->stats.compactions, 1, __ATOMIC_RELAXED);
    }

    pthread_mutex_unlock(&db->lock);

    sol_log_info("RocksDB: compacted all column families");

    return SOL_OK;
}

sol_rocksdb_stats_t
sol_rocksdb_stats(sol_rocksdb_t* db) {
    sol_rocksdb_stats_t stats = {0};
    if (!db) return stats;

    stats = db->stats;

    /* Get cache usage */
    stats.block_cache_usage = rocksdb_cache_get_usage(db->block_cache);
    stats.block_cache_pinned = rocksdb_cache_get_pinned_usage(db->block_cache);

    return stats;
}

void
sol_rocksdb_set_disable_wal(sol_rocksdb_t* db, bool disable_wal) {
    if (!db || !db->write_options) return;

    /* Configuration toggle: only change during quiescent periods. */
    rocksdb_writeoptions_disable_WAL(db->write_options, disable_wal ? 1 : 0);
}

static void
rocksdb_set_option_cf(rocksdb_t* rdb,
                      rocksdb_column_family_handle_t* cf,
                      const char* key,
                      const char* value) {
    if (!rdb || !cf || !key || !value) return;

    const char* keys[1] = { key };
    const char* values[1] = { value };
    char* err = NULL;
    rocksdb_set_options_cf(rdb, cf, 1, keys, values, &err);
    if (err) {
        sol_log_warn("RocksDB: failed to set CF option %s=%s: %s", key, value, err);
        rocksdb_free(err);
    }
}

static bool
rocksdb_bulk_no_compression_enabled(void) {
    const char* env = getenv("SOL_ROCKSDB_BULK_NO_COMPRESSION");
    if (!env || env[0] == '\0') return false;
    switch (env[0]) {
    case '1':
    case 't':
    case 'T':
    case 'y':
    case 'Y':
        return true;
    default:
        return false;
    }
}

static bool
rocksdb_bulk_keep_compression_enabled(void) {
    const char* env = getenv("SOL_ROCKSDB_BULK_KEEP_COMPRESSION");
    if (!env || env[0] == '\0') return false;
    switch (env[0]) {
    case '1':
    case 't':
    case 'T':
    case 'y':
    case 'Y':
        return true;
    default:
        return false;
    }
}

sol_err_t
sol_rocksdb_set_bulk_load_mode(sol_rocksdb_t* db, bool enable) {
    if (!db) return SOL_ERR_INVAL;

    pthread_mutex_lock(&db->lock);

    if (!db->db) {
        pthread_mutex_unlock(&db->lock);
        return SOL_ERR_UNINITIALIZED;
    }

    /* Increase buffering. */
    char write_buf_bytes[32];
    size_t base_mb = db->config.write_buffer_mb ? db->config.write_buffer_mb : 64u;
    size_t bulk_mb = enable ? 512u : base_mb;
    snprintf(write_buf_bytes, sizeof(write_buf_bytes), "%llu",
             (unsigned long long)bulk_mb * 1024ull * 1024ull);

    const char* max_write_bufs = enable ? "16" : "2";

    for (size_t i = 0; i < db->cf_count; i++) {
        rocksdb_column_family_handle_t* cf = db->column_families[i].handle;
        if (!cf) continue;

        rocksdb_set_option_cf(db->db, cf, "write_buffer_size", write_buf_bytes);
        rocksdb_set_option_cf(db->db, cf, "max_write_buffer_number", max_write_bufs);

        if (enable) {
            /* Default: disable compression during bulk ingest to maximize
             * throughput; compactions after bootstrap can re-compress SSTs once
             * the node is live.
             *
             * Opt into keeping compression via:
             *   SOL_ROCKSDB_BULK_KEEP_COMPRESSION=1
             *
             * (Legacy) force-disable via:
             *   SOL_ROCKSDB_BULK_NO_COMPRESSION=1 */
            const bool keep_compression = rocksdb_bulk_keep_compression_enabled();
            const bool no_compression = rocksdb_bulk_no_compression_enabled();
            const char* compression =
                (no_compression || !db->config.compression)
                    ? "kNoCompression"
                    : (keep_compression ? "kLZ4Compression" : "kNoCompression");
            rocksdb_set_option_cf(db->db,
                                  cf,
                                  "compression",
                                  compression);
            rocksdb_set_option_cf(db->db, cf, "disable_auto_compactions", "true");
            rocksdb_set_option_cf(db->db, cf, "level0_slowdown_writes_trigger", "2000");
            rocksdb_set_option_cf(db->db, cf, "level0_stop_writes_trigger", "2000");
        } else {
            rocksdb_set_option_cf(db->db,
                                  cf,
                                  "compression",
                                  db->config.compression ? "kLZ4Compression" : "kNoCompression");
            rocksdb_set_option_cf(db->db, cf, "disable_auto_compactions", "false");
        }
    }

    pthread_mutex_unlock(&db->lock);
    return SOL_OK;
}

void
sol_rocksdb_destroy(sol_rocksdb_t* db) {
    if (!db) return;

    pthread_mutex_lock(&db->lock);

    /* Destroy column family backends and handles */
    for (size_t i = 0; i < db->cf_count; i++) {
        if (db->column_families[i].backend) {
            db->column_families[i].backend->destroy(
                db->column_families[i].backend->ctx);
            free(db->column_families[i].backend);
        }
        if (db->column_families[i].handle) {
            rocksdb_column_family_handle_destroy(db->column_families[i].handle);
        }
        free(db->column_families[i].name);
    }

    /* Close database */
    if (db->db) {
        rocksdb_close(db->db);
    }

    /* Destroy options */
    if (db->read_options) rocksdb_readoptions_destroy(db->read_options);
    if (db->write_options) rocksdb_writeoptions_destroy(db->write_options);
    if (db->table_options) rocksdb_block_based_options_destroy(db->table_options);
    if (db->block_cache) rocksdb_cache_destroy(db->block_cache);
    if (db->options) rocksdb_options_destroy(db->options);
    /* Note: merge operator lifetime is managed by RocksDB via options. */

    pthread_mutex_unlock(&db->lock);
    pthread_mutex_destroy(&db->lock);

    free((void*)db->config.path);
    free(db);

    sol_log_info("RocksDB: closed");
}

#else /* !SOL_HAS_ROCKSDB */

/*
 * Stub implementations when RocksDB is not available
 */

sol_rocksdb_t*
sol_rocksdb_new(const sol_rocksdb_config_t* config) {
    (void)config;
    sol_log_error("RocksDB: not compiled with RocksDB support");
    return NULL;
}

sol_err_t
sol_rocksdb_open_cf(sol_rocksdb_t* db, const char* cf_name) {
    (void)db; (void)cf_name;
    return SOL_ERR_NOT_IMPLEMENTED;
}

sol_storage_backend_t*
sol_rocksdb_get_backend(sol_rocksdb_t* db, const char* cf_name) {
    (void)db; (void)cf_name;
    return NULL;
}

sol_err_t
sol_rocksdb_flush_all(sol_rocksdb_t* db) {
    (void)db;
    return SOL_ERR_NOT_IMPLEMENTED;
}

sol_err_t
sol_rocksdb_compact_all(sol_rocksdb_t* db) {
    (void)db;
    return SOL_ERR_NOT_IMPLEMENTED;
}

sol_rocksdb_stats_t
sol_rocksdb_stats(sol_rocksdb_t* db) {
    (void)db;
    sol_rocksdb_stats_t stats = {0};
    return stats;
}

sol_err_t
sol_rocksdb_backend_get_pinned(sol_storage_backend_t* backend,
                               const uint8_t* key,
                               size_t key_len,
                               const uint8_t** value,
                               size_t* value_len,
                               sol_rocksdb_pinned_slice_t** out_slice) {
    (void)backend;
    (void)key;
    (void)key_len;
    if (value) *value = NULL;
    if (value_len) *value_len = 0;
    if (out_slice) *out_slice = NULL;
    return SOL_ERR_UNSUPPORTED;
}

void
sol_rocksdb_backend_pinned_destroy(sol_rocksdb_pinned_slice_t* slice) {
    (void)slice;
}

void
sol_rocksdb_set_disable_wal(sol_rocksdb_t* db, bool disable_wal) {
    (void)db;
    (void)disable_wal;
}

sol_err_t
sol_rocksdb_set_bulk_load_mode(sol_rocksdb_t* db, bool enable) {
    (void)db;
    (void)enable;
    return SOL_ERR_NOT_IMPLEMENTED;
}

void
sol_rocksdb_destroy(sol_rocksdb_t* db) {
    (void)db;
}

/*
 * Factory function stub
 */
sol_storage_backend_t*
sol_storage_backend_rocksdb_new(const sol_rocksdb_config_t* config) {
    (void)config;
    sol_log_error("RocksDB: not compiled with RocksDB support. Use memory backend.");
    return NULL;
}

#endif /* SOL_HAS_ROCKSDB */
