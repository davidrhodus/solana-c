/*
 * sol_appendvec_index.c - In-memory AppendVec accounts index implementation
 */

#include "sol_appendvec_index.h"
#include "../util/sol_alloc.h"
#include "../util/sol_bits.h"
#include <string.h>

SOL_INLINE size_t
sol_appendvec_index_shard_for(const sol_appendvec_index_t* idx,
                              const sol_pubkey_t* pubkey) {
    if (!idx || idx->shard_count == 0 || !pubkey) return 0;
    uint64_t h = sol_load_u64_le(pubkey->bytes);
    return (size_t)(h & (idx->shard_count - 1u));
}

sol_appendvec_index_t*
sol_appendvec_index_new(uint32_t shard_count, size_t capacity_per_shard) {
    if (shard_count == 0) shard_count = 1;
    shard_count = sol_next_pow2_32(shard_count);
    if (shard_count == 0) shard_count = 1;

    sol_appendvec_index_t* idx = sol_calloc(1, sizeof(*idx));
    if (!idx) return NULL;

    idx->shard_count = (size_t)shard_count;
    idx->shards = sol_calloc(idx->shard_count, sizeof(*idx->shards));
    if (!idx->shards) {
        sol_free(idx);
        return NULL;
    }

    /* Prefer writers on glibc/Linux to avoid starving updates under heavy read load. */
    pthread_rwlockattr_t lock_attr;
    pthread_rwlockattr_t* lock_attr_p = NULL;
    if (pthread_rwlockattr_init(&lock_attr) == 0) {
#if defined(SOL_OS_LINUX) && defined(__GLIBC__) && defined(PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP)
        (void)pthread_rwlockattr_setkind_np(&lock_attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
#endif
        lock_attr_p = &lock_attr;
    }

    for (size_t i = 0; i < idx->shard_count; i++) {
        if (pthread_rwlock_init(&idx->shards[i].lock, lock_attr_p) != 0) {
            for (size_t j = 0; j < i; j++) {
                pthread_rwlock_destroy(&idx->shards[j].lock);
                sol_pubkey_map_destroy(idx->shards[j].map);
            }
            if (lock_attr_p) {
                (void)pthread_rwlockattr_destroy(&lock_attr);
            }
            sol_free(idx->shards);
            sol_free(idx);
            return NULL;
        }

        idx->shards[i].map = sol_pubkey_map_new(sizeof(sol_appendvec_index_val_t), capacity_per_shard);
        if (!idx->shards[i].map) {
            pthread_rwlock_destroy(&idx->shards[i].lock);
            for (size_t j = 0; j < i; j++) {
                pthread_rwlock_destroy(&idx->shards[j].lock);
                sol_pubkey_map_destroy(idx->shards[j].map);
            }
            if (lock_attr_p) {
                (void)pthread_rwlockattr_destroy(&lock_attr);
            }
            sol_free(idx->shards);
            sol_free(idx);
            return NULL;
        }
    }

    if (lock_attr_p) {
        (void)pthread_rwlockattr_destroy(&lock_attr);
    }

    return idx;
}

void
sol_appendvec_index_destroy(sol_appendvec_index_t* idx) {
    if (!idx) return;
    if (idx->shards) {
        for (size_t i = 0; i < idx->shard_count; i++) {
            pthread_rwlock_destroy(&idx->shards[i].lock);
            sol_pubkey_map_destroy(idx->shards[i].map);
        }
        sol_free(idx->shards);
    }
    sol_free(idx);
}

sol_err_t
sol_appendvec_index_update(sol_appendvec_index_t* idx,
                           const sol_pubkey_t* pubkey,
                           sol_slot_t slot,
                           uint64_t write_version,
                           const sol_pubkey_t* owner,
                           uint64_t lamports,
                           uint64_t data_len,
                           uint64_t file_key,
                           uint64_t record_offset,
                           const sol_hash_t* leaf_hash) {
    if (!idx || !idx->shards || idx->shard_count == 0) return SOL_ERR_INVAL;
    if (!pubkey) return SOL_ERR_INVAL;

    sol_appendvec_index_val_t v = {0};
    v.slot = (uint64_t)slot;
    v.write_version = write_version;
    v.file_key = file_key;
    v.record_offset = record_offset;
    v.lamports = lamports;
    v.data_len = data_len;
    if (owner) {
        v.owner = *owner;
    } else {
        memset(v.owner.bytes, 0, sizeof(v.owner.bytes));
    }
    if (lamports != 0 && leaf_hash) {
        v.leaf_hash = *leaf_hash;
    } else {
        memset(v.leaf_hash.bytes, 0, sizeof(v.leaf_hash.bytes));
    }

    size_t shard = sol_appendvec_index_shard_for(idx, pubkey);
    sol_appendvec_index_shard_t* s = &idx->shards[shard];

    pthread_rwlock_wrlock(&s->lock);

    sol_appendvec_index_val_t* cur =
        (sol_appendvec_index_val_t*)sol_pubkey_map_get(s->map, pubkey);
    if (cur) {
        if (write_version != 0 &&
            (cur->write_version > write_version ||
             (cur->write_version == write_version && cur->slot >= (uint64_t)slot))) {
            pthread_rwlock_unlock(&s->lock);
            return SOL_OK;
        }
        *cur = v;
        pthread_rwlock_unlock(&s->lock);
        return SOL_OK;
    }

    void* inserted = sol_pubkey_map_insert(s->map, pubkey, &v);
    pthread_rwlock_unlock(&s->lock);
    return inserted ? SOL_OK : SOL_ERR_NOMEM;
}

bool
sol_appendvec_index_get(const sol_appendvec_index_t* idx,
                        const sol_pubkey_t* pubkey,
                        sol_appendvec_index_val_t* out) {
    if (!idx || !idx->shards || idx->shard_count == 0) return false;
    if (!pubkey || !out) return false;

    size_t shard = sol_appendvec_index_shard_for(idx, pubkey);
    const sol_appendvec_index_shard_t* s = &idx->shards[shard];

    pthread_rwlock_rdlock((pthread_rwlock_t*)&s->lock);
    const sol_appendvec_index_val_t* cur =
        (const sol_appendvec_index_val_t*)sol_pubkey_map_get(s->map, pubkey);
    if (cur) {
        *out = *cur;
        pthread_rwlock_unlock((pthread_rwlock_t*)&s->lock);
        return true;
    }
    pthread_rwlock_unlock((pthread_rwlock_t*)&s->lock);
    return false;
}

