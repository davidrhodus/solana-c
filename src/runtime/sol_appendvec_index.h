/*
 * sol_appendvec_index.h - In-memory AppendVec accounts index
 *
 * Maps pubkey -> (slot, write_version, file_key, record_offset, leaf_hash, owner, lamports, data_len).
 *
 * This is used to avoid RocksDB reads on the hot account-load path when
 * AccountsDB is configured for AppendVec storage.
 */

#ifndef SOL_APPENDVEC_INDEX_H
#define SOL_APPENDVEC_INDEX_H

#include "../util/sol_err.h"
#include "../util/sol_types.h"
#include "../util/sol_map.h"
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t     slot;
    uint64_t     write_version;
    uint64_t     file_key;
    uint64_t     record_offset;
    sol_hash_t   leaf_hash; /* Zero => deleted */
    sol_pubkey_t owner;
    uint64_t     lamports;
    uint64_t     data_len;
} sol_appendvec_index_val_t;

typedef struct {
    pthread_rwlock_t   lock;
    sol_pubkey_map_t*  map;
} sol_appendvec_index_shard_t;

typedef struct sol_appendvec_index {
    size_t                     shard_count;
    sol_appendvec_index_shard_t* shards;
} sol_appendvec_index_t;

/* Allocate an index with a fixed number of shards and per-shard map capacity.
 *
 * `shard_count` is rounded up to the next power-of-two.
 *
 * Returns NULL on allocation failure. */
sol_appendvec_index_t*
sol_appendvec_index_new(uint32_t shard_count, size_t capacity_per_shard);

void
sol_appendvec_index_destroy(sol_appendvec_index_t* idx);

/* Insert/update an entry.
 *
 * When `write_version != 0`, updates follow Solana AccountsDB ordering rules:
 * only apply the update if it is newer than the currently stored (slot,
 * write_version).
 *
 * When `write_version == 0`, the update is applied unconditionally (legacy).
 *
 * `leaf_hash` may be NULL. When `lamports == 0`, the entry is treated as a
 * tombstone and `leaf_hash` is stored as zero regardless of input. */
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
                           const sol_hash_t* leaf_hash);

/* Lookup an entry and copy it into `out`.
 *
 * Returns true on hit, false on miss or invalid input. */
bool
sol_appendvec_index_get(const sol_appendvec_index_t* idx,
                        const sol_pubkey_t* pubkey,
                        sol_appendvec_index_val_t* out);

#endif /* SOL_APPENDVEC_INDEX_H */
