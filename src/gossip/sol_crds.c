/*
 * sol_crds.c - CRDS implementation
 */

#include "sol_crds.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include <string.h>
#include <pthread.h>

/*
 * Hash table bucket
 */
typedef struct sol_crds_bucket {
    sol_crds_entry_t entry;
    bool             occupied;
    bool             deleted;
} sol_crds_bucket_t;

/*
 * CRDS store structure
 */
struct sol_crds {
    sol_crds_bucket_t* buckets;
    size_t             capacity;
    size_t             count;
    uint64_t           local_timestamp;  /* Monotonic counter for ordering */
    sol_crds_stats_t   stats;
    pthread_rwlock_t   lock;
};

/*
 * FNV-1a hash for CRDS key
 */
static uint64_t
crds_key_hash(const sol_crds_key_t* key) {
    uint64_t hash = 14695981039346656037ULL;
    const uint8_t* data = (const uint8_t*)key;
    size_t len = sizeof(*key);

    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 1099511628211ULL;
    }

    return hash;
}

/*
 * Find bucket for key
 */
static sol_crds_bucket_t*
find_bucket(sol_crds_t* crds, const sol_crds_key_t* key, bool for_insert) {
    uint64_t hash = crds_key_hash(key);
    size_t idx = hash % crds->capacity;
    size_t start = idx;
    sol_crds_bucket_t* first_deleted = NULL;

    do {
        sol_crds_bucket_t* b = &crds->buckets[idx];

        if (!b->occupied && !b->deleted) {
            /* Empty slot */
            if (for_insert) {
                return first_deleted ? first_deleted : b;
            }
            return NULL;
        }

        if (b->deleted) {
            /* Deleted slot - remember for insert */
            if (for_insert && !first_deleted) {
                first_deleted = b;
            }
        } else if (sol_crds_key_cmp(&b->entry.key, key) == 0) {
            /* Found matching entry */
            return b;
        }

        idx = (idx + 1) % crds->capacity;
    } while (idx != start);

    /* Table is full (shouldn't happen with proper load factor) */
    return first_deleted;
}

sol_crds_t*
sol_crds_new(size_t max_entries) {
    if (max_entries == 0) {
        max_entries = SOL_CRDS_MAX_ENTRIES;
    }

    /* Use 1.5x capacity for good hash table performance */
    size_t capacity = max_entries + max_entries / 2;

    sol_crds_t* crds = sol_calloc(1, sizeof(sol_crds_t));
    if (!crds) return NULL;

    crds->buckets = sol_calloc(capacity, sizeof(sol_crds_bucket_t));
    if (!crds->buckets) {
        sol_free(crds);
        return NULL;
    }

    crds->capacity = capacity;
    crds->count = 0;
    crds->local_timestamp = 0;
    memset(&crds->stats, 0, sizeof(crds->stats));

    if (pthread_rwlock_init(&crds->lock, NULL) != 0) {
        sol_free(crds->buckets);
        sol_free(crds);
        return NULL;
    }

    return crds;
}

void
sol_crds_destroy(sol_crds_t* crds) {
    if (!crds) return;

    pthread_rwlock_destroy(&crds->lock);
    sol_free(crds->buckets);
    sol_free(crds);
}

sol_err_t
sol_crds_insert(
    sol_crds_t*            crds,
    const sol_crds_value_t* value,
    const sol_pubkey_t*    origin,
    uint64_t               now_ms
) {
    if (!crds || !value) {
        return SOL_ERR_INVAL;
    }

    /* Validate wallclock drift */
    uint64_t wallclock = sol_crds_value_wallclock(value);
    if (wallclock > now_ms + SOL_CRDS_MAX_WALLCLOCK_DRIFT_MS) {
        /* Wallclock too far in the future - reject */
        crds->stats.stale++;
        return SOL_ERR_STALE;
    }
    if (wallclock + SOL_CRDS_MAX_WALLCLOCK_DRIFT_MS < now_ms) {
        /* Wallclock too far in the past - reject */
        crds->stats.stale++;
        return SOL_ERR_STALE;
    }

    sol_crds_key_t key;
    sol_crds_key_from_value(&key, value);

    pthread_rwlock_wrlock(&crds->lock);

    sol_crds_bucket_t* bucket = find_bucket(crds, &key, true);
    if (!bucket) {
        pthread_rwlock_unlock(&crds->lock);
        crds->stats.evictions++;
        return SOL_ERR_FULL;
    }

    if (bucket->occupied && !bucket->deleted) {
        /* Entry exists - check if update is needed */
        uint64_t existing_wc = sol_crds_value_wallclock(&bucket->entry.value);
        uint64_t new_wc = sol_crds_value_wallclock(value);

        if (new_wc < existing_wc) {
            /* Incoming value is older */
            pthread_rwlock_unlock(&crds->lock);
            crds->stats.stale++;
            return SOL_ERR_STALE;
        }

        if (new_wc == existing_wc) {
            /* Same timestamp - duplicate */
            pthread_rwlock_unlock(&crds->lock);
            crds->stats.duplicates++;
            return SOL_ERR_EXISTS;
        }

        /* Update existing entry */
        bucket->entry.value = *value;
        bucket->entry.insert_timestamp = now_ms;
        bucket->entry.local_timestamp = ++crds->local_timestamp;
        if (origin) {
            sol_pubkey_copy(&bucket->entry.origin, origin);
        }

        pthread_rwlock_unlock(&crds->lock);
        crds->stats.updates++;
        return SOL_OK;
    }

    /* Check if we're at capacity */
    if (crds->count >= crds->capacity * 2 / 3) {
        pthread_rwlock_unlock(&crds->lock);
        crds->stats.evictions++;
        return SOL_ERR_FULL;
    }

    /* Insert new entry */
    bucket->entry.value = *value;
    bucket->entry.key = key;
    bucket->entry.insert_timestamp = now_ms;
    bucket->entry.local_timestamp = ++crds->local_timestamp;
    if (origin) {
        sol_pubkey_copy(&bucket->entry.origin, origin);
    } else {
        sol_pubkey_init(&bucket->entry.origin);
    }
    bucket->entry.is_push = false;
    bucket->occupied = true;
    bucket->deleted = false;

    crds->count++;

    pthread_rwlock_unlock(&crds->lock);
    crds->stats.inserts++;
    return SOL_OK;
}

const sol_crds_entry_t*
sol_crds_get(sol_crds_t* crds, const sol_crds_key_t* key) {
    if (!crds || !key) return NULL;

    pthread_rwlock_rdlock(&crds->lock);

    sol_crds_bucket_t* bucket = find_bucket(crds, key, false);

    pthread_rwlock_unlock(&crds->lock);

    if (bucket && bucket->occupied && !bucket->deleted) {
        return &bucket->entry;
    }
    return NULL;
}

const sol_contact_info_t*
sol_crds_get_contact_info(sol_crds_t* crds, const sol_pubkey_t* pubkey) {
    if (!crds || !pubkey) return NULL;

    sol_crds_key_t key = {
        .type = SOL_CRDS_CONTACT_INFO,
        .index = 0
    };
    sol_pubkey_copy(&key.pubkey, pubkey);

    const sol_crds_entry_t* entry = sol_crds_get(crds, &key);
    if (entry && entry->value.type == SOL_CRDS_CONTACT_INFO) {
        return &entry->value.data.contact_info;
    }
    return NULL;
}

const sol_crds_version_t*
sol_crds_get_version(sol_crds_t* crds, const sol_pubkey_t* pubkey) {
    if (!crds || !pubkey) return NULL;

    sol_crds_key_t key = {
        .type = SOL_CRDS_VERSION,
        .index = 0
    };
    sol_pubkey_copy(&key.pubkey, pubkey);

    const sol_crds_entry_t* entry = sol_crds_get(crds, &key);
    if (entry && entry->value.type == SOL_CRDS_VERSION) {
        return &entry->value.data.version;
    }
    return NULL;
}

bool
sol_crds_contains(sol_crds_t* crds, const sol_crds_key_t* key) {
    return sol_crds_get(crds, key) != NULL;
}

size_t
sol_crds_len(const sol_crds_t* crds) {
    return crds ? crds->count : 0;
}

size_t
sol_crds_prune(sol_crds_t* crds, uint64_t now_ms, uint64_t timeout_ms) {
    if (!crds) return 0;

    uint64_t cutoff = now_ms - timeout_ms;
    size_t pruned = 0;

    pthread_rwlock_wrlock(&crds->lock);

    for (size_t i = 0; i < crds->capacity; i++) {
        sol_crds_bucket_t* b = &crds->buckets[i];
        if (b->occupied && !b->deleted) {
            if (b->entry.insert_timestamp < cutoff) {
                b->deleted = true;
                b->occupied = false;
                crds->count--;
                pruned++;
            }
        }
    }

    pthread_rwlock_unlock(&crds->lock);

    crds->stats.prunes += pruned;
    return pruned;
}

void
sol_crds_stats(const sol_crds_t* crds, sol_crds_stats_t* stats) {
    if (crds && stats) {
        *stats = crds->stats;
    }
}

void
sol_crds_stats_reset(sol_crds_t* crds) {
    if (crds) {
        memset(&crds->stats, 0, sizeof(crds->stats));
    }
}

void
sol_crds_foreach(sol_crds_t* crds, sol_crds_iter_fn fn, void* ctx) {
    if (!crds || !fn) return;

    pthread_rwlock_rdlock(&crds->lock);

    for (size_t i = 0; i < crds->capacity; i++) {
        sol_crds_bucket_t* b = &crds->buckets[i];
        if (b->occupied && !b->deleted) {
            if (!fn(&b->entry, ctx)) {
                break;
            }
        }
    }

    pthread_rwlock_unlock(&crds->lock);
}

void
sol_crds_foreach_type(
    sol_crds_t*      crds,
    sol_crds_type_t  type,
    sol_crds_iter_fn fn,
    void*            ctx
) {
    if (!crds || !fn) return;

    pthread_rwlock_rdlock(&crds->lock);

    for (size_t i = 0; i < crds->capacity; i++) {
        sol_crds_bucket_t* b = &crds->buckets[i];
        if (b->occupied && !b->deleted && b->entry.value.type == type) {
            if (!fn(&b->entry, ctx)) {
                break;
            }
        }
    }

    pthread_rwlock_unlock(&crds->lock);
}

size_t
sol_crds_get_all_contact_info(
    sol_crds_t*               crds,
    const sol_contact_info_t** out,
    size_t                    max_count
) {
    if (!crds || !out || max_count == 0) return 0;

    size_t count = 0;

    pthread_rwlock_rdlock(&crds->lock);

    for (size_t i = 0; i < crds->capacity && count < max_count; i++) {
        sol_crds_bucket_t* b = &crds->buckets[i];
        if (b->occupied && !b->deleted &&
            b->entry.value.type == SOL_CRDS_CONTACT_INFO) {
            out[count++] = &b->entry.value.data.contact_info;
        }
    }

    pthread_rwlock_unlock(&crds->lock);

    return count;
}

size_t
sol_crds_get_votes_for_slot(
    sol_crds_t*            crds,
    sol_slot_t             slot,
    const sol_crds_vote_t** out,
    size_t                 max_count
) {
    if (!crds || !out || max_count == 0) return 0;

    size_t count = 0;

    pthread_rwlock_rdlock(&crds->lock);

    for (size_t i = 0; i < crds->capacity && count < max_count; i++) {
        sol_crds_bucket_t* b = &crds->buckets[i];
        if (b->occupied && !b->deleted &&
            b->entry.value.type == SOL_CRDS_VOTE &&
            b->entry.value.data.vote.slot == slot) {
            out[count++] = &b->entry.value.data.vote;
        }
    }

    pthread_rwlock_unlock(&crds->lock);

    return count;
}

size_t
sol_crds_get_entries_since(
    sol_crds_t*              crds,
    uint64_t                 since,
    const sol_crds_entry_t** out,
    size_t                   max_count
) {
    if (!crds || !out || max_count == 0) return 0;

    size_t count = 0;

    pthread_rwlock_rdlock(&crds->lock);

    for (size_t i = 0; i < crds->capacity && count < max_count; i++) {
        sol_crds_bucket_t* b = &crds->buckets[i];
        if (b->occupied && !b->deleted &&
            b->entry.local_timestamp > since) {
            out[count++] = &b->entry;
        }
    }

    pthread_rwlock_unlock(&crds->lock);

    return count;
}
