/*
 * sol_storage_backend.h - Abstract storage backend interface
 *
 * Provides a common interface for different storage implementations
 * (in-memory, RocksDB, etc.) to enable pluggable persistence.
 */

#ifndef SOL_STORAGE_BACKEND_H
#define SOL_STORAGE_BACKEND_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "../util/sol_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Storage backend types
 */
typedef enum {
    SOL_STORAGE_MEMORY   = 0,  /* In-memory hash table (default) */
    SOL_STORAGE_ROCKSDB  = 1,  /* RocksDB persistent storage */
} sol_storage_type_t;

/*
 * Batch operation for atomic writes
 */
typedef enum {
    SOL_BATCH_OP_PUT,
    /* Merge a value into an existing key using the backend's merge operator.
     * For backends without native merge semantics, this may behave like PUT. */
    SOL_BATCH_OP_MERGE,
    SOL_BATCH_OP_DELETE,
} sol_batch_op_type_t;

typedef struct {
    sol_batch_op_type_t op;
    const uint8_t*      key;
    size_t              key_len;
    const uint8_t*      value;      /* NULL for DELETE */
    size_t              value_len;  /* 0 for DELETE */
} sol_batch_op_t;

typedef struct {
    sol_batch_op_t* ops;
    size_t          count;
    size_t          capacity;
} sol_storage_batch_t;

/*
 * Iterator callback for scanning all entries
 */
typedef bool (*sol_storage_iter_cb)(
    const uint8_t* key,
    size_t         key_len,
    const uint8_t* value,
    size_t         value_len,
    void*          ctx
);

/*
 * Storage backend interface
 *
 * All storage implementations must provide these operations.
 */
typedef struct sol_storage_backend {
    void* ctx;  /* Implementation-specific context */

    /*
     * Get a value by key
     * Returns SOL_OK on success, SOL_ERR_NOT_FOUND if key doesn't exist
     * Caller must free *value (use sol_free; NULL is allowed for empty values)
     */
    sol_err_t (*get)(
        void*           ctx,
        const uint8_t*  key,
        size_t          key_len,
        uint8_t**       value,
        size_t*         value_len
    );

    /*
     * Store a key-value pair
     * Overwrites existing value if key exists
     */
    sol_err_t (*put)(
        void*           ctx,
        const uint8_t*  key,
        size_t          key_len,
        const uint8_t*  value,
        size_t          value_len
    );

    /*
     * Delete a key
     * Returns SOL_OK even if key doesn't exist
     */
    sol_err_t (*del)(
        void*           ctx,
        const uint8_t*  key,
        size_t          key_len
    );

    /*
     * Check if key exists
     */
    bool (*exists)(
        void*           ctx,
        const uint8_t*  key,
        size_t          key_len
    );

    /*
     * Atomic batch write
     * All operations succeed or none do
     */
    sol_err_t (*batch_write)(
        void*                   ctx,
        sol_storage_batch_t*    batch
    );

    /*
     * Iterate over all entries
     * Callback returns false to stop iteration
     */
    void (*iterate)(
        void*                ctx,
        sol_storage_iter_cb  cb,
        void*                cb_ctx
    );

    /*
     * Iterate over a key range [start, end)
     * Pass NULL for start to begin from first key
     * Pass NULL for end to iterate to last key
     */
    void (*iterate_range)(
        void*                ctx,
        const uint8_t*       start_key,
        size_t               start_len,
        const uint8_t*       end_key,
        size_t               end_len,
        sol_storage_iter_cb  cb,
        void*                cb_ctx
    );

    /*
     * Get number of entries
     */
    size_t (*count)(void* ctx);

    /*
     * Flush any buffered writes to persistent storage
     * No-op for in-memory backend
     */
    sol_err_t (*flush)(void* ctx);

    /*
     * Create a point-in-time snapshot
     * Returns opaque snapshot handle
     */
    void* (*snapshot)(void* ctx);

    /*
     * Release a snapshot
     */
    void (*snapshot_release)(void* ctx, void* snapshot);

    /*
     * Destroy backend and free resources
     */
    void (*destroy)(void* ctx);

} sol_storage_backend_t;

/*
 * Batch operations helper functions
 */
sol_storage_batch_t* sol_storage_batch_new(size_t initial_capacity);
void sol_storage_batch_destroy(sol_storage_batch_t* batch);
sol_err_t sol_storage_batch_put(
    sol_storage_batch_t* batch,
    const uint8_t*       key,
    size_t               key_len,
    const uint8_t*       value,
    size_t               value_len
);
sol_err_t sol_storage_batch_merge(
    sol_storage_batch_t* batch,
    const uint8_t*       key,
    size_t               key_len,
    const uint8_t*       value,
    size_t               value_len
);
sol_err_t sol_storage_batch_delete(
    sol_storage_batch_t* batch,
    const uint8_t*       key,
    size_t               key_len
);
void sol_storage_batch_clear(sol_storage_batch_t* batch);

/*
 * Backend factory functions
 */

/* Create in-memory backend */
sol_storage_backend_t* sol_storage_backend_memory_new(size_t initial_capacity);

/* Create RocksDB backend */
typedef struct {
    const char*     path;               /* Database directory path */
    size_t          block_cache_mb;     /* Block cache size in MB (default: 512) */
    size_t          write_buffer_mb;    /* Write buffer size in MB (default: 64) */
    int             max_open_files;     /* Max open file handles (default: -1 unlimited) */
    bool            compression;        /* Enable compression (default: true) */
    bool            create_if_missing;  /* Create DB if doesn't exist (default: true) */
    const char*     column_family;      /* Column family name (default: "default") */
} sol_rocksdb_config_t;

#define SOL_ROCKSDB_CONFIG_DEFAULT { \
    .path              = "./rocksdb", \
    .block_cache_mb    = 512, \
    .write_buffer_mb   = 64, \
    .max_open_files    = -1, \
    .compression       = true, \
    .create_if_missing = true, \
    .column_family     = "default", \
}

sol_storage_backend_t* sol_storage_backend_rocksdb_new(
    const sol_rocksdb_config_t* config
);

#ifdef __cplusplus
}
#endif

#endif /* SOL_STORAGE_BACKEND_H */
