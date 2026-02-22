/*
 * sol_storage_backend.c - Storage backend implementations
 */

#include "sol_storage_backend.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/*
 * Batch operations implementation
 */

sol_storage_batch_t*
sol_storage_batch_new(size_t initial_capacity) {
    sol_storage_batch_t* batch = calloc(1, sizeof(sol_storage_batch_t));
    if (!batch) return NULL;

    if (initial_capacity > 0) {
        batch->ops = calloc(initial_capacity, sizeof(sol_batch_op_t));
        if (!batch->ops) {
            free(batch);
            return NULL;
        }
        batch->capacity = initial_capacity;
    }

    return batch;
}

void
sol_storage_batch_destroy(sol_storage_batch_t* batch) {
    if (!batch) return;
    free(batch->ops);
    free(batch);
}

sol_err_t
sol_storage_batch_put(
    sol_storage_batch_t* batch,
    const uint8_t*       key,
    size_t               key_len,
    const uint8_t*       value,
    size_t               value_len
) {
    if (!batch || !key || !value) return SOL_ERR_INVAL;

    /* Grow if needed */
    if (batch->count >= batch->capacity) {
        size_t new_cap = batch->capacity ? batch->capacity * 2 : 16;
        sol_batch_op_t* new_ops = realloc(batch->ops, new_cap * sizeof(sol_batch_op_t));
        if (!new_ops) return SOL_ERR_NOMEM;
        batch->ops = new_ops;
        batch->capacity = new_cap;
    }

    sol_batch_op_t* op = &batch->ops[batch->count++];
    op->op = SOL_BATCH_OP_PUT;
    op->key = key;
    op->key_len = key_len;
    op->value = value;
    op->value_len = value_len;

    return SOL_OK;
}

sol_err_t
sol_storage_batch_merge(
    sol_storage_batch_t* batch,
    const uint8_t*       key,
    size_t               key_len,
    const uint8_t*       value,
    size_t               value_len
) {
    if (!batch || !key || !value) return SOL_ERR_INVAL;

    /* Grow if needed */
    if (batch->count >= batch->capacity) {
        size_t new_cap = batch->capacity ? batch->capacity * 2 : 16;
        sol_batch_op_t* new_ops = realloc(batch->ops, new_cap * sizeof(sol_batch_op_t));
        if (!new_ops) return SOL_ERR_NOMEM;
        batch->ops = new_ops;
        batch->capacity = new_cap;
    }

    sol_batch_op_t* op = &batch->ops[batch->count++];
    op->op = SOL_BATCH_OP_MERGE;
    op->key = key;
    op->key_len = key_len;
    op->value = value;
    op->value_len = value_len;

    return SOL_OK;
}

sol_err_t
sol_storage_batch_delete(
    sol_storage_batch_t* batch,
    const uint8_t*       key,
    size_t               key_len
) {
    if (!batch || !key) return SOL_ERR_INVAL;

    /* Grow if needed */
    if (batch->count >= batch->capacity) {
        size_t new_cap = batch->capacity ? batch->capacity * 2 : 16;
        sol_batch_op_t* new_ops = realloc(batch->ops, new_cap * sizeof(sol_batch_op_t));
        if (!new_ops) return SOL_ERR_NOMEM;
        batch->ops = new_ops;
        batch->capacity = new_cap;
    }

    sol_batch_op_t* op = &batch->ops[batch->count++];
    op->op = SOL_BATCH_OP_DELETE;
    op->key = key;
    op->key_len = key_len;
    op->value = NULL;
    op->value_len = 0;

    return SOL_OK;
}

void
sol_storage_batch_clear(sol_storage_batch_t* batch) {
    if (batch) {
        batch->count = 0;
    }
}

/*
 * In-memory backend implementation using hash table
 */

typedef struct mem_entry {
    uint8_t*            key;
    size_t              key_len;
    uint8_t*            value;
    size_t              value_len;
    struct mem_entry*   next;
} mem_entry_t;

typedef struct {
    mem_entry_t**       buckets;
    size_t              bucket_count;
    size_t              entry_count;
    pthread_rwlock_t    lock;
} mem_backend_t;

static int
mem_entry_ptr_key_cmp(const void* a, const void* b) {
    const mem_entry_t* ea = *(const mem_entry_t* const*)a;
    const mem_entry_t* eb = *(const mem_entry_t* const*)b;

    size_t min_len = ea->key_len < eb->key_len ? ea->key_len : eb->key_len;
    int cmp = memcmp(ea->key, eb->key, min_len);
    if (cmp != 0) return cmp;
    if (ea->key_len < eb->key_len) return -1;
    if (ea->key_len > eb->key_len) return 1;
    return 0;
}

static uint64_t
mem_hash(const uint8_t* key, size_t key_len) {
    /* FNV-1a hash */
    uint64_t hash = 14695981039346656037ULL;
    for (size_t i = 0; i < key_len; i++) {
        hash ^= key[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static sol_err_t
mem_get(void* ctx, const uint8_t* key, size_t key_len, uint8_t** value, size_t* value_len) {
    mem_backend_t* mem = ctx;
    if (!mem || !key || !value || !value_len) return SOL_ERR_INVAL;

    pthread_rwlock_rdlock(&mem->lock);

    uint64_t hash = mem_hash(key, key_len);
    size_t idx = hash % mem->bucket_count;

	for (mem_entry_t* e = mem->buckets[idx]; e; e = e->next) {
	    if (e->key_len == key_len && memcmp(e->key, key, key_len) == 0) {
	            *value = NULL;
	            if (e->value_len > 0) {
	                *value = sol_alloc(e->value_len);
	                if (!*value) {
	                    pthread_rwlock_unlock(&mem->lock);
	                    return SOL_ERR_NOMEM;
	                }
	                memcpy(*value, e->value, e->value_len);
	            }
	            *value_len = e->value_len;
	            pthread_rwlock_unlock(&mem->lock);
	            return SOL_OK;
	        }
	    }

    pthread_rwlock_unlock(&mem->lock);
    return SOL_ERR_NOTFOUND;
}

static sol_err_t
mem_put(void* ctx, const uint8_t* key, size_t key_len, const uint8_t* value, size_t value_len) {
    mem_backend_t* mem = ctx;
    if (!mem || !key || !value) return SOL_ERR_INVAL;

    pthread_rwlock_wrlock(&mem->lock);

    uint64_t hash = mem_hash(key, key_len);
    size_t idx = hash % mem->bucket_count;

    /* Check for existing entry */
    for (mem_entry_t* e = mem->buckets[idx]; e; e = e->next) {
        if (e->key_len == key_len && memcmp(e->key, key, key_len) == 0) {
            /* Update existing */
            uint8_t* new_value = malloc(value_len);
            if (!new_value) {
                pthread_rwlock_unlock(&mem->lock);
                return SOL_ERR_NOMEM;
            }
            memcpy(new_value, value, value_len);
            free(e->value);
            e->value = new_value;
            e->value_len = value_len;
            pthread_rwlock_unlock(&mem->lock);
            return SOL_OK;
        }
    }

    /* Create new entry */
    mem_entry_t* entry = calloc(1, sizeof(mem_entry_t));
    if (!entry) {
        pthread_rwlock_unlock(&mem->lock);
        return SOL_ERR_NOMEM;
    }

    entry->key = malloc(key_len);
    entry->value = malloc(value_len);
    if (!entry->key || !entry->value) {
        free(entry->key);
        free(entry->value);
        free(entry);
        pthread_rwlock_unlock(&mem->lock);
        return SOL_ERR_NOMEM;
    }

    memcpy(entry->key, key, key_len);
    memcpy(entry->value, value, value_len);
    entry->key_len = key_len;
    entry->value_len = value_len;

    entry->next = mem->buckets[idx];
    mem->buckets[idx] = entry;
    mem->entry_count++;

    pthread_rwlock_unlock(&mem->lock);
    return SOL_OK;
}

static sol_err_t
mem_del(void* ctx, const uint8_t* key, size_t key_len) {
    mem_backend_t* mem = ctx;
    if (!mem || !key) return SOL_ERR_INVAL;

    pthread_rwlock_wrlock(&mem->lock);

    uint64_t hash = mem_hash(key, key_len);
    size_t idx = hash % mem->bucket_count;

    mem_entry_t* prev = NULL;
    for (mem_entry_t* e = mem->buckets[idx]; e; prev = e, e = e->next) {
        if (e->key_len == key_len && memcmp(e->key, key, key_len) == 0) {
            if (prev) {
                prev->next = e->next;
            } else {
                mem->buckets[idx] = e->next;
            }
            free(e->key);
            free(e->value);
            free(e);
            mem->entry_count--;
            pthread_rwlock_unlock(&mem->lock);
            return SOL_OK;
        }
    }

    pthread_rwlock_unlock(&mem->lock);
    return SOL_OK;  /* Not an error if key doesn't exist */
}

static bool
mem_exists(void* ctx, const uint8_t* key, size_t key_len) {
    mem_backend_t* mem = ctx;
    if (!mem || !key) return false;

    pthread_rwlock_rdlock(&mem->lock);

    uint64_t hash = mem_hash(key, key_len);
    size_t idx = hash % mem->bucket_count;

    for (mem_entry_t* e = mem->buckets[idx]; e; e = e->next) {
        if (e->key_len == key_len && memcmp(e->key, key, key_len) == 0) {
            pthread_rwlock_unlock(&mem->lock);
            return true;
        }
    }

    pthread_rwlock_unlock(&mem->lock);
    return false;
}

static sol_err_t
mem_batch_write(void* ctx, sol_storage_batch_t* batch) {
    if (!ctx || !batch) return SOL_ERR_INVAL;

    /* Execute all operations - memory backend is always atomic */
    for (size_t i = 0; i < batch->count; i++) {
        sol_batch_op_t* op = &batch->ops[i];
        sol_err_t err;

        if (op->op == SOL_BATCH_OP_PUT || op->op == SOL_BATCH_OP_MERGE) {
            err = mem_put(ctx, op->key, op->key_len, op->value, op->value_len);
        } else {
            err = mem_del(ctx, op->key, op->key_len);
        }

        if (err != SOL_OK) return err;
    }

    return SOL_OK;
}

static void
mem_iterate(void* ctx, sol_storage_iter_cb cb, void* cb_ctx) {
    mem_backend_t* mem = ctx;
    if (!mem || !cb) return;

    pthread_rwlock_rdlock(&mem->lock);

    for (size_t i = 0; i < mem->bucket_count; i++) {
        for (mem_entry_t* e = mem->buckets[i]; e; e = e->next) {
            if (!cb(e->key, e->key_len, e->value, e->value_len, cb_ctx)) {
                pthread_rwlock_unlock(&mem->lock);
                return;
            }
        }
    }

    pthread_rwlock_unlock(&mem->lock);
}

static void
mem_iterate_range(void* ctx, const uint8_t* start_key, size_t start_len,
                  const uint8_t* end_key, size_t end_len,
                  sol_storage_iter_cb cb, void* cb_ctx) {
    mem_backend_t* mem = ctx;
    if (!mem || !cb) return;

    /* Memory backend doesn't support efficient range queries, but it should
     * still respect the API contract. */
    pthread_rwlock_rdlock(&mem->lock);

    /* Collect matching entries (best-effort) and return them in lexicographic order. */
    mem_entry_t** matches = NULL;
    size_t match_count = 0;
    size_t match_cap = 0;

    for (size_t i = 0; i < mem->bucket_count; i++) {
        for (mem_entry_t* e = mem->buckets[i]; e; e = e->next) {
            if (start_key) {
                size_t min_len = e->key_len < start_len ? e->key_len : start_len;
                int cmp = memcmp(e->key, start_key, min_len);
                if (cmp < 0 || (cmp == 0 && e->key_len < start_len)) {
                    continue;
                }
            }

            if (end_key) {
                size_t min_len = e->key_len < end_len ? e->key_len : end_len;
                int cmp = memcmp(e->key, end_key, min_len);
                if (cmp > 0 || (cmp == 0 && e->key_len >= end_len)) {
                    continue;
                }
            }

            if (match_count == match_cap) {
                size_t new_cap = match_cap ? (match_cap * 2) : 128;
                mem_entry_t** new_matches = realloc(matches, new_cap * sizeof(*new_matches));
                if (!new_matches) {
                    /* OOM: fall back to unsorted streaming. */
                    free(matches);
                    matches = NULL;
                    match_count = 0;
                    match_cap = 0;

                    if (!cb(e->key, e->key_len, e->value, e->value_len, cb_ctx)) {
                        pthread_rwlock_unlock(&mem->lock);
                        return;
                    }
                    continue;
                }
                matches = new_matches;
                match_cap = new_cap;
            }

            matches[match_count++] = e;
        }
    }

    if (matches) {
        qsort(matches, match_count, sizeof(*matches), mem_entry_ptr_key_cmp);

        for (size_t i = 0; i < match_count; i++) {
            mem_entry_t* e = matches[i];
            if (!cb(e->key, e->key_len, e->value, e->value_len, cb_ctx)) {
                break;
            }
        }

        free(matches);
    }

    pthread_rwlock_unlock(&mem->lock);
}

static size_t
mem_count(void* ctx) {
    mem_backend_t* mem = ctx;
    if (!mem) return 0;

    pthread_rwlock_rdlock(&mem->lock);
    size_t count = mem->entry_count;
    pthread_rwlock_unlock(&mem->lock);

    return count;
}

static sol_err_t
mem_flush(void* ctx) {
    (void)ctx;
    return SOL_OK;  /* No-op for memory backend */
}

static void*
mem_snapshot(void* ctx) {
    (void)ctx;
    return NULL;  /* Not implemented for memory backend */
}

static void
mem_snapshot_release(void* ctx, void* snapshot) {
    (void)ctx;
    (void)snapshot;
}

static void
mem_destroy(void* ctx) {
    mem_backend_t* mem = ctx;
    if (!mem) return;

    pthread_rwlock_wrlock(&mem->lock);

    for (size_t i = 0; i < mem->bucket_count; i++) {
        mem_entry_t* e = mem->buckets[i];
        while (e) {
            mem_entry_t* next = e->next;
            free(e->key);
            free(e->value);
            free(e);
            e = next;
        }
    }

    pthread_rwlock_unlock(&mem->lock);
    pthread_rwlock_destroy(&mem->lock);

    free(mem->buckets);
    free(mem);
}

sol_storage_backend_t*
sol_storage_backend_memory_new(size_t initial_capacity) {
    if (initial_capacity == 0) {
        initial_capacity = 65536;  /* Default */
    }

    mem_backend_t* mem = calloc(1, sizeof(mem_backend_t));
    if (!mem) return NULL;

    mem->buckets = calloc(initial_capacity, sizeof(mem_entry_t*));
    if (!mem->buckets) {
        free(mem);
        return NULL;
    }

    mem->bucket_count = initial_capacity;
    pthread_rwlock_init(&mem->lock, NULL);

    sol_storage_backend_t* backend = calloc(1, sizeof(sol_storage_backend_t));
    if (!backend) {
        free(mem->buckets);
        free(mem);
        return NULL;
    }

    backend->ctx = mem;
    backend->get = mem_get;
    backend->put = mem_put;
    backend->del = mem_del;
    backend->exists = mem_exists;
    backend->batch_write = mem_batch_write;
    backend->iterate = mem_iterate;
    backend->iterate_range = mem_iterate_range;
    backend->count = mem_count;
    backend->flush = mem_flush;
    backend->snapshot = mem_snapshot;
    backend->snapshot_release = mem_snapshot_release;
    backend->destroy = mem_destroy;

    sol_log_debug("Created memory storage backend with %zu buckets", initial_capacity);

    return backend;
}
