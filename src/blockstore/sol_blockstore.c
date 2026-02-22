/*
 * sol_blockstore.c - Shred and Block Storage Implementation
 *
 * Supports both in-memory storage and RocksDB persistence.
 */

#include "sol_blockstore.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include "../entry/sol_entry.h"
#include "../storage/sol_rocksdb.h"
#include "../storage/sol_storage_backend.h"
#include "../txn/sol_message.h"
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#define SOL_BLOCKSTORE_MAX_SLOT_VARIANTS 4u

/*
 * Slot storage hash table entry
 */
typedef struct sol_slot_entry {
    sol_slot_t              slot;
    sol_slot_store_t        store;
    struct sol_slot_variant_entry* variants; /* Additional data shred variants */
    size_t                  variant_count;   /* Includes primary store */
    uint32_t                next_variant_id; /* Next variant id to assign */
    bool                    any_complete;    /* Any variant is complete */
    struct sol_fec_set_entry* fec_sets; /* FEC recovery state (optional) */
    struct sol_slot_entry*  next;
} sol_slot_entry_t;

/*
 * Per-slot block variant store.
 *
 * Variants are created when conflicting data shreds are observed for the same
 * (slot, index). Each variant owns its own shred byte storage.
 */
typedef struct sol_slot_variant_entry {
    uint32_t                        variant_id;
    sol_slot_store_t                store;
    struct sol_slot_variant_entry*  next;
} sol_slot_variant_entry_t;

/*
 * FEC set tracking entry (per slot)
 */
typedef struct sol_fec_set_entry {
    uint32_t                    fec_set_index;
    sol_fec_set_t*              fec;
    struct sol_fec_set_entry*   next;
} sol_fec_set_entry_t;

/*
 * Blockstore structure
 */
struct sol_blockstore {
    sol_blockstore_config_t config;

    /* Storage backends (when using RocksDB) */
    sol_rocksdb_t*          rocksdb;           /* RocksDB instance */
    sol_storage_backend_t*  shred_backend;     /* Shred storage */
    sol_storage_backend_t*  slot_meta_backend; /* Slot metadata storage */
    sol_storage_backend_t*  address_sig_backend; /* address -> signatures index */
    bool                    address_sig_backend_owned;

    /* Slot storage (simple hash table - also serves as cache when using RocksDB) */
    sol_slot_entry_t**      slots;
    size_t                  slot_table_size;
    size_t                  slot_count;

    /* Tracking */
    sol_slot_t              lowest_slot;
    sol_slot_t              highest_slot;
    sol_slot_t              highest_complete;
    sol_slot_t              highest_rooted;

    /* Callback */
    sol_blockstore_slot_cb  slot_callback;
    void*                   slot_callback_ctx;

    /* Statistics */
    sol_blockstore_stats_t  stats;

    /* Thread safety */
    pthread_rwlock_t        lock;
};

/*
 * Get current time in ms
 */
extern uint64_t sol_gossip_now_ms(void);

/*
 * Hash function for slot
 */
static inline size_t
slot_hash(sol_slot_t slot, size_t table_size) {
    return (size_t)(slot % table_size);
}

/*
 * Find slot entry
 */
static sol_slot_entry_t*
find_slot_entry(sol_blockstore_t* bs, sol_slot_t slot) {
    size_t idx = slot_hash(slot, bs->slot_table_size);
    sol_slot_entry_t* entry = bs->slots[idx];

    while (entry) {
        if (entry->slot == slot) {
            return entry;
        }
        entry = entry->next;
    }

    return NULL;
}

/*
 * Create slot entry
 */
static sol_slot_entry_t*
create_slot_entry(sol_blockstore_t* bs, sol_slot_t slot) {
    sol_slot_entry_t* entry = sol_calloc(1, sizeof(sol_slot_entry_t));
    if (!entry) return NULL;

    entry->slot = slot;
    entry->variants = NULL;
    entry->variant_count = 1;
    entry->next_variant_id = 1;
    entry->any_complete = false;
    entry->store.meta.slot = slot;
    entry->store.meta.received_time = sol_gossip_now_ms();

    /* Allocate shred arrays */
    size_t max_shreds = bs->config.max_shreds_per_slot;

    entry->store.data_shreds = sol_calloc(max_shreds, sizeof(sol_blockstore_shred_t));
    entry->store.code_shreds = sol_calloc(max_shreds, sizeof(sol_blockstore_shred_t));

    if (!entry->store.data_shreds || !entry->store.code_shreds) {
        sol_free(entry->store.data_shreds);
        sol_free(entry->store.code_shreds);
        sol_free(entry);
        return NULL;
    }

    entry->store.data_capacity = max_shreds;
    entry->store.code_capacity = max_shreds;

    /* Allocate received bitmap */
    entry->store.bitmap_size = (max_shreds + 7) / 8;
    entry->store.received_bitmap = sol_calloc(1, entry->store.bitmap_size);
    if (!entry->store.received_bitmap) {
        sol_free(entry->store.data_shreds);
        sol_free(entry->store.code_shreds);
        sol_free(entry);
        return NULL;
    }

    /* Insert into hash table */
    size_t idx = slot_hash(slot, bs->slot_table_size);
    entry->next = bs->slots[idx];
    bs->slots[idx] = entry;
    bs->slot_count++;
    bs->stats.slots_created++;

    /* Update highest slot */
    if (slot > bs->highest_slot) {
        bs->highest_slot = slot;
    }

    /* Update lowest slot */
    if (slot < bs->lowest_slot) {
        bs->lowest_slot = slot;
    }

    return entry;
}

/*
 * Free the contents of a slot store (arrays + owned shred bytes).
 */
static void
free_slot_store_contents(sol_slot_store_t* store) {
    if (!store) return;

    /* Free shred data */
    for (size_t i = 0; i < store->data_capacity; i++) {
        sol_free(store->data_shreds ? store->data_shreds[i].data : NULL);
    }
    for (size_t i = 0; i < store->code_capacity; i++) {
        sol_free(store->code_shreds ? store->code_shreds[i].data : NULL);
    }

    sol_free(store->data_shreds);
    sol_free(store->code_shreds);
    sol_free(store->received_bitmap);

    memset(store, 0, sizeof(*store));
}

/*
 * Free slot entry
 */
static void
free_slot_entry(sol_slot_entry_t* entry) {
    if (!entry) return;

    /* Free any FEC tracking structures */
    sol_fec_set_entry_t* fec_entry = entry->fec_sets;
    while (fec_entry) {
        sol_fec_set_entry_t* next = fec_entry->next;

        if (fec_entry->fec) {
            /* Free parsed shred structs (raw bytes are owned by blockstore arrays) */
            for (uint16_t i = 0; i < fec_entry->fec->num_data; i++) {
                sol_free(fec_entry->fec->data_shreds ? fec_entry->fec->data_shreds[i] : NULL);
            }
            for (uint16_t i = 0; i < fec_entry->fec->num_code; i++) {
                sol_free(fec_entry->fec->code_shreds ? fec_entry->fec->code_shreds[i] : NULL);
            }

            sol_fec_set_destroy(fec_entry->fec);
        }

        sol_free(fec_entry);
        fec_entry = next;
    }

    /* Free any variant stores */
    sol_slot_variant_entry_t* variant = entry->variants;
    while (variant) {
        sol_slot_variant_entry_t* next = variant->next;
        free_slot_store_contents(&variant->store);
        sol_free(variant);
        variant = next;
    }

    /* Free primary store */
    free_slot_store_contents(&entry->store);
    sol_free(entry);
}

static inline bool
shred_bytes_equal(const sol_blockstore_shred_t* stored,
                  const uint8_t* raw,
                  size_t raw_len) {
    if (!stored || !stored->data || !raw) return false;
    if (stored->data_len != raw_len) return false;
    return memcmp(stored->data, raw, raw_len) == 0;
}

static sol_slot_variant_entry_t*
find_variant_by_id(sol_slot_entry_t* entry, uint32_t variant_id) {
    for (sol_slot_variant_entry_t* v = entry ? entry->variants : NULL; v; v = v->next) {
        if (v->variant_id == variant_id) {
            return v;
        }
    }
    return NULL;
}

static sol_slot_store_t*
store_for_variant(sol_slot_entry_t* entry, uint32_t variant_id) {
    if (!entry) return NULL;
    if (variant_id == 0) return &entry->store;
    sol_slot_variant_entry_t* v = find_variant_by_id(entry, variant_id);
    return v ? &v->store : NULL;
}

static bool
variant_has_shred_bytes(const sol_slot_store_t* store,
                        uint32_t index,
                        bool is_data,
                        const uint8_t* raw,
                        size_t raw_len) {
    if (!store || !raw) return false;
    if (is_data) {
        if (index >= store->data_capacity) return false;
        return shred_bytes_equal(&store->data_shreds[index], raw, raw_len);
    }
    if (index >= store->code_capacity) return false;
    return shred_bytes_equal(&store->code_shreds[index], raw, raw_len);
}

static sol_err_t
clone_slot_store(const sol_slot_store_t* src, sol_slot_store_t* dst) {
    if (!src || !dst) return SOL_ERR_INVAL;

    *dst = (sol_slot_store_t){0};
    dst->meta = src->meta;
    dst->data_capacity = src->data_capacity;
    dst->code_capacity = src->code_capacity;
    dst->bitmap_size = src->bitmap_size;

    if (dst->data_capacity) {
        dst->data_shreds = sol_calloc(dst->data_capacity, sizeof(sol_blockstore_shred_t));
        if (!dst->data_shreds) return SOL_ERR_NOMEM;
    }

    if (dst->code_capacity) {
        dst->code_shreds = sol_calloc(dst->code_capacity, sizeof(sol_blockstore_shred_t));
        if (!dst->code_shreds) {
            free_slot_store_contents(dst);
            return SOL_ERR_NOMEM;
        }
    }

    if (dst->bitmap_size) {
        dst->received_bitmap = sol_calloc(1, dst->bitmap_size);
        if (!dst->received_bitmap) {
            free_slot_store_contents(dst);
            return SOL_ERR_NOMEM;
        }
        if (src->received_bitmap) {
            memcpy(dst->received_bitmap, src->received_bitmap, dst->bitmap_size);
        }
    }

    /* Deep copy shred bytes */
    for (size_t i = 0; i < dst->data_capacity; i++) {
        const sol_blockstore_shred_t* s = &src->data_shreds[i];
        sol_blockstore_shred_t* d = &dst->data_shreds[i];
        d->index = s->index;
        d->is_data = s->is_data;
        d->data_len = s->data_len;
        if (s->data && s->data_len) {
            d->data = sol_alloc(s->data_len);
            if (!d->data) {
                free_slot_store_contents(dst);
                return SOL_ERR_NOMEM;
            }
            memcpy(d->data, s->data, s->data_len);
        }
    }

    for (size_t i = 0; i < dst->code_capacity; i++) {
        const sol_blockstore_shred_t* s = &src->code_shreds[i];
        sol_blockstore_shred_t* d = &dst->code_shreds[i];
        d->index = s->index;
        d->is_data = s->is_data;
        d->data_len = s->data_len;
        if (s->data && s->data_len) {
            d->data = sol_alloc(s->data_len);
            if (!d->data) {
                free_slot_store_contents(dst);
                return SOL_ERR_NOMEM;
            }
            memcpy(d->data, s->data, s->data_len);
        }
    }

    return SOL_OK;
}

/*
 * Check if shred index is in bitmap
 */
static inline bool
bitmap_get(const uint8_t* bitmap, uint32_t index) {
    return (bitmap[index / 8] & (1 << (index % 8))) != 0;
}

/*
 * Set shred index in bitmap
 */
static inline void
bitmap_set(uint8_t* bitmap, uint32_t index) {
    bitmap[index / 8] |= (1 << (index % 8));
}

/*
 * Check if slot is complete (all data shreds received)
 */
static bool
check_slot_complete(sol_slot_store_t* store) {
    if (!store->meta.is_full) {
        /* Don't know total count yet */
        return false;
    }

    /* Check if we have all data shreds from 0 to last_shred_index */
    for (uint32_t i = 0; i <= store->meta.last_shred_index; i++) {
        if (!bitmap_get(store->received_bitmap, i)) {
            return false;
        }
    }

    return true;
}

#ifdef SOL_HAS_ROCKSDB
/* Forward declarations (defined below) */
static sol_err_t persist_shred(sol_blockstore_t* bs,
                               sol_slot_t slot,
                               uint32_t variant_id,
                               bool is_data,
                               uint32_t index,
                               const uint8_t* data,
                               size_t data_len);
static sol_err_t persist_slot_meta_variant(sol_blockstore_t* bs,
                                           sol_slot_t slot,
                                           uint32_t variant_id,
                                           const sol_slot_meta_t* meta);
static sol_err_t persist_slot_variants(sol_blockstore_t* bs,
                                       sol_slot_t slot,
                                       uint32_t variant_count,
                                       uint32_t next_variant_id);
#endif

/*
 * Mark slot complete + persist metadata + notify callback (caller holds bs lock)
 */
static void
maybe_mark_slot_complete_locked(sol_blockstore_t* bs,
                                sol_slot_entry_t* entry,
                                sol_slot_store_t* store,
                                uint32_t variant_id) {
    if (!bs || !entry || !store) return;
    sol_slot_t slot = store->meta.slot;

    if (store->meta.is_complete) return;
    if (!check_slot_complete(store)) return;

    bool first_complete = !entry->any_complete;

    store->meta.is_complete = true;
    store->meta.completed_time = sol_gossip_now_ms();
    if (first_complete) {
        entry->any_complete = true;
        bs->stats.slots_completed++;

        if (slot > bs->highest_complete) {
            bs->highest_complete = slot;
        }
    }

    sol_log_debug("Slot %llu complete with %u data shreds",
                  (unsigned long long)slot, store->meta.received_data);

#ifdef SOL_HAS_ROCKSDB
    if (bs->slot_meta_backend) {
        sol_err_t persist_err = persist_slot_meta_variant(bs, slot, variant_id, &store->meta);
        if (persist_err != SOL_OK) {
            sol_log_warn("Failed to persist slot meta for slot %llu (variant %u): %d",
                         (unsigned long long)slot, (unsigned)variant_id, persist_err);
        }

        /* Persist variant count mapping (best-effort) */
        sol_err_t v_err = persist_slot_variants(bs, slot,
                                               (uint32_t)entry->variant_count,
                                               entry->next_variant_id);
        if (v_err != SOL_OK) {
            sol_log_warn("Failed to persist slot variants for slot %llu: %d",
                         (unsigned long long)slot, v_err);
        }
    }
#endif

    /* Notify callback only once per slot (first complete variant). */
    if (first_complete && bs->slot_callback) {
        bs->slot_callback(slot, bs->slot_callback_ctx);
    }
}

/*
 * Find an existing FEC set entry for a slot
 */
static sol_fec_set_entry_t*
find_fec_set_entry(sol_slot_entry_t* entry, uint32_t fec_set_index) {
    for (sol_fec_set_entry_t* e = entry ? entry->fec_sets : NULL; e; e = e->next) {
        if (e->fec_set_index == fec_set_index) {
            return e;
        }
    }
    return NULL;
}

/*
 * Create (or return existing) FEC set entry (caller holds bs lock)
 */
static sol_fec_set_t*
get_or_create_fec_set_locked(sol_slot_entry_t* entry, sol_slot_t slot,
                             uint32_t fec_set_index, uint16_t num_data, uint16_t num_code) {
    sol_fec_set_entry_t* existing = find_fec_set_entry(entry, fec_set_index);
    if (existing) return existing->fec;

    sol_fec_set_t* fec = sol_fec_set_new(slot, fec_set_index, num_data, num_code);
    if (!fec) return NULL;

    sol_fec_set_entry_t* node = sol_calloc(1, sizeof(sol_fec_set_entry_t));
    if (!node) {
        sol_fec_set_destroy(fec);
        return NULL;
    }

    node->fec_set_index = fec_set_index;
    node->fec = fec;
    node->next = entry->fec_sets;
    entry->fec_sets = node;

    return fec;
}

/*
 * Parse a stored shred into a heap object (raw bytes must outlive returned struct)
 */
static sol_shred_t*
parse_stored_shred_new(const uint8_t* raw, size_t raw_len) {
    sol_shred_t* parsed = sol_calloc(1, sizeof(sol_shred_t));
    if (!parsed) return NULL;

    if (sol_shred_parse(parsed, raw, raw_len) != SOL_OK) {
        sol_free(parsed);
        return NULL;
    }

    return parsed;
}

/*
 * Store a recovered data shred into the slot.
 *
 * Takes ownership of raw bytes on success (caller retains ownership on error).
 * Caller holds bs lock.
 */
static sol_err_t
store_recovered_data_shred_locked(sol_blockstore_t* bs, sol_slot_store_t* store,
                                  sol_slot_t slot, uint32_t index,
                                  uint8_t* raw_owned, size_t raw_len,
                                  const sol_shred_t* parsed) {
    if (!bs || !store || !raw_owned || raw_len == 0 || !parsed) return SOL_ERR_INVAL;
    if (index >= bs->config.max_shreds_per_slot) return SOL_ERR_INVAL;

    sol_blockstore_shred_t* shred_store = &store->data_shreds[index];
    if (shred_store->data) {
        return SOL_ERR_EXISTS;
    }

    shred_store->data = raw_owned;
    shred_store->data_len = raw_len;
    shred_store->index = index;
    shred_store->is_data = true;

    store->meta.received_data++;
    bitmap_set(store->received_bitmap, index);
    bs->stats.shreds_inserted++;

#ifdef SOL_HAS_ROCKSDB
    if (bs->shred_backend) {
        sol_err_t persist_err = persist_shred(bs, slot, 0, true, index, raw_owned, raw_len);
        if (persist_err != SOL_OK) {
            sol_log_warn("Failed to persist recovered shred slot=%llu index=%u: %d",
                         (unsigned long long)slot, index, persist_err);
        }
    }
#endif

    /* Update metadata (best-effort) */
    if (store->meta.received_data == 1) {
        store->meta.parent_slot = parsed->header.data.parent_slot;
    }
    if (index < store->meta.first_shred_index || store->meta.received_data == 1) {
        store->meta.first_shred_index = index;
    }

    return SOL_OK;
}

#ifdef SOL_HAS_ROCKSDB
#define SOL_BLOCKSTORE_SLOT_META_VARIANTS_TAG 0xFFu

typedef struct {
    uint32_t variant_count;
    uint32_t next_variant_id;
} sol_slot_variants_record_t;

/*
 * Generate shred key for RocksDB storage
 * Format: slot(8 bytes) + type(1 byte) + index(4 bytes) = 13 bytes
 */
static void
make_shred_key(sol_slot_t slot, bool is_data, uint32_t index,
               uint8_t* key, size_t* key_len) {
    memcpy(key, &slot, 8);
    key[8] = is_data ? 1 : 0;
    memcpy(key + 9, &index, 4);
    *key_len = 13;
}

/*
 * Generate variant shred key for RocksDB storage.
 *
 * Primary variant (0) keeps the legacy key format.
 * Variant format: slot(8) + variant_id(4) + type(1) + index(4) = 17 bytes
 */
static void
make_shred_key_variant(sol_slot_t slot, uint32_t variant_id, bool is_data, uint32_t index,
                       uint8_t* key, size_t* key_len) {
    if (variant_id == 0) {
        make_shred_key(slot, is_data, index, key, key_len);
        return;
    }

    memcpy(key, &slot, 8);
    memcpy(key + 8, &variant_id, 4);
    key[12] = is_data ? 1 : 0;
    memcpy(key + 13, &index, 4);
    *key_len = 17;
}

/*
 * Persist shred to RocksDB
 */
static sol_err_t
persist_shred(sol_blockstore_t* bs,
              sol_slot_t slot,
              uint32_t variant_id,
              bool is_data,
              uint32_t index,
              const uint8_t* data,
              size_t data_len) {
    if (!bs->shred_backend) return SOL_OK;  /* No persistence configured */

    uint8_t key[17];
    size_t key_len;
    make_shred_key_variant(slot, variant_id, is_data, index, key, &key_len);

    return bs->shred_backend->put(bs->shred_backend->ctx,
                                   key, key_len, data, data_len);
}

static void
make_slot_meta_key(sol_slot_t slot, uint32_t variant_id, uint8_t* key, size_t* key_len) {
    memcpy(key, &slot, 8);
    if (variant_id == 0) {
        *key_len = 8;
        return;
    }

    memcpy(key + 8, &variant_id, 4);
    *key_len = 12;
}

/*
 * Persist slot metadata to RocksDB
 */
static sol_err_t
persist_slot_meta_variant(sol_blockstore_t* bs,
                          sol_slot_t slot,
                          uint32_t variant_id,
                          const sol_slot_meta_t* meta) {
    if (!bs->slot_meta_backend) return SOL_OK;  /* No persistence configured */

    uint8_t key[12];
    size_t key_len;
    make_slot_meta_key(slot, variant_id, key, &key_len);

    return bs->slot_meta_backend->put(bs->slot_meta_backend->ctx,
                                       key, key_len,
                                       (const uint8_t*)meta, sizeof(*meta));
}

static void
make_slot_variants_key(sol_slot_t slot, uint8_t* key, size_t* key_len) {
    memcpy(key, &slot, 8);
    key[8] = (uint8_t)SOL_BLOCKSTORE_SLOT_META_VARIANTS_TAG;
    *key_len = 9;
}

static sol_err_t
persist_slot_variants(sol_blockstore_t* bs,
                      sol_slot_t slot,
                      uint32_t variant_count,
                      uint32_t next_variant_id) {
    if (!bs->slot_meta_backend) return SOL_OK;

    sol_slot_variants_record_t rec = {
        .variant_count = variant_count,
        .next_variant_id = next_variant_id,
    };

    uint8_t key[9];
    size_t key_len;
    make_slot_variants_key(slot, key, &key_len);

    return bs->slot_meta_backend->put(bs->slot_meta_backend->ctx,
                                      key, key_len,
                                      (const uint8_t*)&rec, sizeof(rec));
}

static sol_err_t
load_slot_variants(sol_blockstore_t* bs,
                   sol_slot_t slot,
                   sol_slot_variants_record_t* out) {
    if (!bs || !out) return SOL_ERR_INVAL;
    if (!bs->slot_meta_backend) return SOL_ERR_NOTFOUND;

    uint8_t key[9];
    size_t key_len;
    make_slot_variants_key(slot, key, &key_len);

    uint8_t* value = NULL;
    size_t value_len = 0;

    sol_err_t err = bs->slot_meta_backend->get(bs->slot_meta_backend->ctx,
                                               key, key_len,
                                               &value, &value_len);
    if (err != SOL_OK) return err;

    if (value_len != sizeof(*out)) {
        sol_free(value);
        return SOL_ERR_MALFORMED;
    }

    memcpy(out, value, sizeof(*out));
    sol_free(value);
    return SOL_OK;
}

/*
 * Load shred from RocksDB
 */
static sol_err_t
load_shred(sol_blockstore_t* bs, sol_slot_t slot, bool is_data, uint32_t index,
           uint8_t** data, size_t* data_len) {
    if (!bs || !data || !data_len) return SOL_ERR_INVAL;
    if (!bs->shred_backend) return SOL_ERR_NOTFOUND;

    uint8_t key[13];
    size_t key_len;
    make_shred_key(slot, is_data, index, key, &key_len);

    return bs->shred_backend->get(bs->shred_backend->ctx,
                                  key, key_len,
                                  data, data_len);
}

static sol_err_t
load_shred_variant(sol_blockstore_t* bs,
                   sol_slot_t slot,
                   uint32_t variant_id,
                   bool is_data,
                   uint32_t index,
                   uint8_t** data,
                   size_t* data_len) {
    if (!bs || !data || !data_len) return SOL_ERR_INVAL;
    if (!bs->shred_backend) return SOL_ERR_NOTFOUND;

    if (variant_id == 0) {
        return load_shred(bs, slot, is_data, index, data, data_len);
    }

    uint8_t key[17];
    size_t key_len;
    make_shred_key_variant(slot, variant_id, is_data, index, key, &key_len);

    sol_err_t err = bs->shred_backend->get(bs->shred_backend->ctx,
                                          key, key_len,
                                          data, data_len);
    if (err == SOL_OK) return SOL_OK;

    /* Fallback to primary */
    return load_shred(bs, slot, is_data, index, data, data_len);
}

/*
 * Load slot metadata from RocksDB
 */
static sol_err_t
load_slot_meta(sol_blockstore_t* bs, sol_slot_t slot, sol_slot_meta_t* meta) {
    if (!bs || !meta) return SOL_ERR_INVAL;
    if (!bs->slot_meta_backend) return SOL_ERR_NOTFOUND;

    uint8_t* value = NULL;
    size_t value_len = 0;

    sol_err_t err = bs->slot_meta_backend->get(bs->slot_meta_backend->ctx,
                                               (const uint8_t*)&slot, sizeof(slot),
                                               &value, &value_len);
    if (err != SOL_OK) return err;

    if (value_len != sizeof(*meta)) {
        sol_free(value);
        return SOL_ERR_MALFORMED;
    }

    memcpy(meta, value, sizeof(*meta));
    sol_free(value);
    return SOL_OK;
}

static sol_err_t
load_slot_meta_variant(sol_blockstore_t* bs,
                       sol_slot_t slot,
                       uint32_t variant_id,
                       sol_slot_meta_t* meta) {
    if (!bs || !meta) return SOL_ERR_INVAL;
    if (!bs->slot_meta_backend) return SOL_ERR_NOTFOUND;

    if (variant_id == 0) {
        return load_slot_meta(bs, slot, meta);
    }

    uint8_t key[12];
    size_t key_len;
    make_slot_meta_key(slot, variant_id, key, &key_len);

    uint8_t* value = NULL;
    size_t value_len = 0;

    sol_err_t err = bs->slot_meta_backend->get(bs->slot_meta_backend->ctx,
                                               key, key_len,
                                               &value, &value_len);
    if (err != SOL_OK) return err;

    if (value_len != sizeof(*meta)) {
        sol_free(value);
        return SOL_ERR_MALFORMED;
    }

    memcpy(meta, value, sizeof(*meta));
    sol_free(value);
    return SOL_OK;
}
#endif /* SOL_HAS_ROCKSDB */

sol_blockstore_t*
sol_blockstore_new(const sol_blockstore_config_t* config) {
    sol_blockstore_t* bs = sol_calloc(1, sizeof(sol_blockstore_t));
    if (!bs) return NULL;

    if (config) {
        bs->config = *config;
    } else {
        bs->config = (sol_blockstore_config_t)SOL_BLOCKSTORE_CONFIG_DEFAULT;
    }

    if (pthread_rwlock_init(&bs->lock, NULL) != 0) {
        sol_free(bs);
        return NULL;
    }

    /* Initialize RocksDB storage if configured */
    if (bs->config.storage_type == SOL_BLOCKSTORE_STORAGE_ROCKSDB) {
#ifdef SOL_HAS_ROCKSDB
        sol_rocksdb_config_t rocksdb_config = SOL_ROCKSDB_CONFIG_DEFAULT;
        if (bs->config.rocksdb_path) {
            rocksdb_config.path = bs->config.rocksdb_path;
        } else {
            rocksdb_config.path = "./blockstore_rocksdb";
        }
        if (bs->config.rocksdb_cache_mb > 0) {
            rocksdb_config.block_cache_mb = bs->config.rocksdb_cache_mb;
        }

        bs->rocksdb = sol_rocksdb_new(&rocksdb_config);
        if (!bs->rocksdb) {
            sol_log_error("Failed to create blockstore RocksDB instance");
            pthread_rwlock_destroy(&bs->lock);
            sol_free(bs);
            return NULL;
        }

        /* Open blockstore and slot_meta column families */
        sol_err_t err = sol_rocksdb_open_cf(bs->rocksdb, SOL_ROCKSDB_CF_BLOCKSTORE);
        if (err != SOL_OK) {
            sol_log_error("Failed to open blockstore column family");
            sol_rocksdb_destroy(bs->rocksdb);
            pthread_rwlock_destroy(&bs->lock);
            sol_free(bs);
            return NULL;
        }

        err = sol_rocksdb_open_cf(bs->rocksdb, SOL_ROCKSDB_CF_SLOT_META);
        if (err != SOL_OK) {
            sol_log_error("Failed to open slot_meta column family");
            sol_rocksdb_destroy(bs->rocksdb);
            pthread_rwlock_destroy(&bs->lock);
            sol_free(bs);
            return NULL;
        }

        err = sol_rocksdb_open_cf(bs->rocksdb, SOL_ROCKSDB_CF_ADDRESS_SIGNATURES);
        if (err != SOL_OK) {
            sol_log_error("Failed to open address_signatures column family");
            sol_rocksdb_destroy(bs->rocksdb);
            pthread_rwlock_destroy(&bs->lock);
            sol_free(bs);
            return NULL;
        }

        bs->shred_backend = sol_rocksdb_get_backend(bs->rocksdb, SOL_ROCKSDB_CF_BLOCKSTORE);
        bs->slot_meta_backend = sol_rocksdb_get_backend(bs->rocksdb, SOL_ROCKSDB_CF_SLOT_META);
        bs->address_sig_backend = sol_rocksdb_get_backend(bs->rocksdb, SOL_ROCKSDB_CF_ADDRESS_SIGNATURES);
        bs->address_sig_backend_owned = false;

        if (!bs->shred_backend || !bs->slot_meta_backend || !bs->address_sig_backend) {
            sol_log_error("Failed to get blockstore storage backends");
            sol_rocksdb_destroy(bs->rocksdb);
            pthread_rwlock_destroy(&bs->lock);
            sol_free(bs);
            return NULL;
        }

        sol_log_info("Blockstore using RocksDB backend at %s",
                     bs->config.rocksdb_path ? bs->config.rocksdb_path : "./blockstore_rocksdb");
#else
        sol_log_warn("RocksDB not available, falling back to memory-only blockstore");
        bs->config.storage_type = SOL_BLOCKSTORE_STORAGE_MEMORY;
#endif
    }

    /* Allocate slot hash table (used as cache when using RocksDB) */
    bs->slot_table_size = bs->config.max_slots * 2; /* 50% load factor */
    bs->slots = sol_calloc(bs->slot_table_size, sizeof(sol_slot_entry_t*));
    if (!bs->slots) {
        if (bs->rocksdb) {
#ifdef SOL_HAS_ROCKSDB
            sol_rocksdb_destroy(bs->rocksdb);
#endif
        }
        pthread_rwlock_destroy(&bs->lock);
        sol_free(bs);
        return NULL;
    }

    /* Initialize lowest_slot to max (unset) */
    bs->lowest_slot = UINT64_MAX;

    if (bs->config.storage_type == SOL_BLOCKSTORE_STORAGE_MEMORY) {
        sol_log_info("Blockstore using in-memory storage with %zu max slots",
                     bs->config.max_slots);
    }

    /* Create an in-memory address->signature index when not using RocksDB. */
    if (!bs->address_sig_backend) {
        bs->address_sig_backend = sol_storage_backend_memory_new(65536);
        bs->address_sig_backend_owned = (bs->address_sig_backend != NULL);
    }

    return bs;
}

void
sol_blockstore_destroy(sol_blockstore_t* bs) {
    if (!bs) return;

    if (bs->address_sig_backend_owned && bs->address_sig_backend) {
        bs->address_sig_backend->destroy(bs->address_sig_backend->ctx);
        free(bs->address_sig_backend);
        bs->address_sig_backend = NULL;
        bs->address_sig_backend_owned = false;
    }

    /* Destroy RocksDB backend if used */
    if (bs->rocksdb) {
#ifdef SOL_HAS_ROCKSDB
        sol_rocksdb_destroy(bs->rocksdb);
#endif
        bs->rocksdb = NULL;
        bs->shred_backend = NULL;
        bs->slot_meta_backend = NULL;
        bs->address_sig_backend = NULL;
    }

    /* Free all slot entries from in-memory cache */
    if (bs->slots) {
        for (size_t i = 0; i < bs->slot_table_size; i++) {
            sol_slot_entry_t* entry = bs->slots[i];
            while (entry) {
                sol_slot_entry_t* next = entry->next;
                free_slot_entry(entry);
                entry = next;
            }
        }
        sol_free(bs->slots);
    }

    pthread_rwlock_destroy(&bs->lock);
    sol_free(bs);
}

typedef struct {
    uint32_t         variant_id;
    sol_slot_store_t* store;
} sol_store_ref_t;

static void
update_slot_meta_from_data_shred_locked(sol_slot_store_t* store,
                                        const sol_shred_t* shred,
                                        uint32_t index,
                                        bool data_complete,
                                        bool last_in_slot,
                                        uint32_t variant_id) {
    if (!store || !shred) return;

    /* Update parent slot from first data shred */
    if (store->meta.received_data == 1) {
        store->meta.parent_slot = shred->header.data.parent_slot;
    }

    /* Track first/last shred indices */
    if (index < store->meta.first_shred_index || store->meta.received_data == 1) {
        store->meta.first_shred_index = index;
    }

    if (index > store->meta.last_shred_index) {
        if (store->meta.is_full && !last_in_slot) {
            /* Higher index arrived after a previous LAST_IN_SLOT; treat as incomplete. */
            store->meta.is_full = false;
        }
        store->meta.last_shred_index = index;
    }

    /* Track DATA_COMPLETE for debugging/metrics, but only treat LAST_IN_SLOT as
     * the definitive "slot is full" marker (required for tick verification). */
    if (data_complete && !store->meta.is_full) {
        if (variant_id == 0) {
            sol_log_info("Slot %llu observed DATA_COMPLETE shred index=%u (flags=0x%02X)",
                         (unsigned long long)shred->slot,
                         (unsigned)index,
                         (unsigned)shred->header.data.flags);
        } else {
            sol_log_info("Slot %llu variant %u observed DATA_COMPLETE shred index=%u (flags=0x%02X)",
                         (unsigned long long)shred->slot,
                         (unsigned)variant_id,
                         (unsigned)index,
                         (unsigned)shred->header.data.flags);
        }
    }

    if (last_in_slot) {
        store->meta.is_full = true;
        store->meta.last_shred_index = index;
        store->meta.num_data_shreds = index + 1;
    }
}

static bool
slot_entry_any_complete(const sol_slot_entry_t* entry) {
    if (!entry) return false;
    if (entry->store.meta.is_complete) return true;
    for (const sol_slot_variant_entry_t* v = entry->variants; v; v = v->next) {
        if (v->store.meta.is_complete) return true;
    }
    return false;
}

static sol_err_t
insert_data_shred_multi_locked(sol_blockstore_t* bs,
                               sol_slot_entry_t* entry,
                               const sol_shred_t* shred,
                               uint32_t index,
                               const uint8_t* raw_data,
                               size_t raw_len,
                               bool* out_stored_in_primary) {
    if (out_stored_in_primary) *out_stored_in_primary = false;
    if (!bs || !entry || !shred || !raw_data || raw_len == 0) return SOL_ERR_INVAL;

    const bool data_complete = (shred->header.data.flags & SOL_SHRED_FLAG_DATA_COMPLETE) != 0;
    const bool last_in_slot = sol_shred_is_last_in_slot(shred);

    sol_store_ref_t stores[SOL_BLOCKSTORE_MAX_SLOT_VARIANTS];
    size_t store_count = 0;
    stores[store_count++] = (sol_store_ref_t){
        .variant_id = 0,
        .store = &entry->store,
    };

    for (sol_slot_variant_entry_t* v = entry->variants;
         v && store_count < SOL_BLOCKSTORE_MAX_SLOT_VARIANTS;
         v = v->next) {
        stores[store_count++] = (sol_store_ref_t){
            .variant_id = v->variant_id,
            .store = &v->store,
        };
    }

    bool any_duplicate = false;
    bool any_stored = false;
    bool any_alloc_failed = false;

    sol_store_ref_t conflicts[SOL_BLOCKSTORE_MAX_SLOT_VARIANTS];
    size_t conflict_count = 0;

    for (size_t si = 0; si < store_count; si++) {
        sol_store_ref_t ref = stores[si];
        sol_slot_store_t* store = ref.store;
        if (!store) continue;
        if (index >= store->data_capacity) continue;

        sol_blockstore_shred_t* shred_store = &store->data_shreds[index];
        if (shred_store->data) {
            if (shred_bytes_equal(shred_store, raw_data, raw_len)) {
                any_duplicate = true;
            } else {
                conflicts[conflict_count++] = ref;
            }
            continue;
        }

        shred_store->data = sol_alloc(raw_len);
        if (!shred_store->data) {
            any_alloc_failed = true;
            continue;
        }

        memcpy(shred_store->data, raw_data, raw_len);
        shred_store->data_len = raw_len;
        shred_store->index = index;
        shred_store->is_data = true;

        bool was_complete = store->meta.is_complete;
        uint32_t old_last = store->meta.last_shred_index;

        store->meta.received_data++;
        bitmap_set(store->received_bitmap, index);

#ifdef SOL_HAS_ROCKSDB
        if (bs->shred_backend) {
            sol_err_t persist_err = persist_shred(bs, shred->slot, ref.variant_id, true,
                                                 index, shred_store->data, raw_len);
            if (persist_err != SOL_OK) {
                sol_log_warn("Failed to persist shred slot=%llu variant=%u index=%u: %d",
                             (unsigned long long)shred->slot,
                             (unsigned)ref.variant_id,
                             (unsigned)index,
                             persist_err);
            }
        }
#endif

        update_slot_meta_from_data_shred_locked(store, shred, index, data_complete, last_in_slot, ref.variant_id);
        if (was_complete && index > old_last) {
            store->meta.is_complete = false;
            entry->any_complete = slot_entry_any_complete(entry);
        }
        maybe_mark_slot_complete_locked(bs, entry, store, ref.variant_id);

#ifdef SOL_HAS_ROCKSDB
        /* Persist slot metadata incrementally so catchup/repair can reason about
         * partially-received slots after restarts or cache eviction. */
        if (bs->slot_meta_backend) {
            sol_err_t persist_err = persist_slot_meta_variant(bs, shred->slot, ref.variant_id, &store->meta);
            if (persist_err != SOL_OK) {
                sol_log_warn("Failed to persist slot meta for slot %llu (variant %u): %d",
                             (unsigned long long)shred->slot,
                             (unsigned)ref.variant_id,
                             persist_err);
            }
        }
#endif

        if (ref.variant_id == 0 && out_stored_in_primary) {
            *out_stored_in_primary = true;
        }

        any_stored = true;
    }

    if (any_stored) {
        bs->stats.shreds_inserted++;
        return SOL_OK;
    }

    if (any_duplicate) {
        bs->stats.shreds_duplicate++;
        return SOL_ERR_EXISTS;
    }

    if (any_alloc_failed) {
        return SOL_ERR_NOMEM;
    }

    /* Conflicting shred across all known variants -> fork new variants */
    if (entry->variant_count >= SOL_BLOCKSTORE_MAX_SLOT_VARIANTS) {
        return SOL_ERR_FULL;
    }

    size_t max_new = SOL_BLOCKSTORE_MAX_SLOT_VARIANTS - entry->variant_count;
    size_t created = 0;

    for (size_t ci = 0; ci < conflict_count && created < max_new; ci++) {
        sol_store_ref_t src_ref = conflicts[ci];
        sol_slot_store_t* src = src_ref.store;
        if (!src) continue;

        sol_slot_variant_entry_t* variant = sol_calloc(1, sizeof(*variant));
        if (!variant) {
            any_alloc_failed = true;
            continue;
        }

        variant->variant_id = entry->next_variant_id++;

        sol_err_t cerr = clone_slot_store(src, &variant->store);
        if (cerr != SOL_OK) {
            sol_free(variant);
            if (cerr == SOL_ERR_NOMEM) any_alloc_failed = true;
            continue;
        }

        /* Force completeness to be recalculated/persisted for this variant. */
        variant->store.meta.is_complete = false;
        variant->store.meta.completed_time = 0;

        if (index >= variant->store.data_capacity) {
            free_slot_store_contents(&variant->store);
            sol_free(variant);
            continue;
        }

        sol_blockstore_shred_t* v_shred = &variant->store.data_shreds[index];
        sol_free(v_shred->data);
        v_shred->data = sol_alloc(raw_len);
        if (!v_shred->data) {
            free_slot_store_contents(&variant->store);
            sol_free(variant);
            any_alloc_failed = true;
            continue;
        }

        memcpy(v_shred->data, raw_data, raw_len);
        v_shred->data_len = raw_len;
        v_shred->index = index;
        v_shred->is_data = true;

        /* Update variant metadata from shred (without incrementing counts) */
        variant->store.meta.parent_slot = shred->header.data.parent_slot;
        if (index < variant->store.meta.first_shred_index) {
            variant->store.meta.first_shred_index = index;
        }
        if (last_in_slot) {
            variant->store.meta.is_full = true;
            variant->store.meta.last_shred_index = index;
            variant->store.meta.num_data_shreds = index + 1;
        } else if (variant->store.meta.is_full &&
                   variant->store.meta.last_shred_index == index) {
            /* Avoid falsely treating the slot as full after replacing the last shred. */
            variant->store.meta.is_full = false;
        }

        variant->next = entry->variants;
        entry->variants = variant;
        entry->variant_count++;
        created++;

#ifdef SOL_HAS_ROCKSDB
        if (bs->shred_backend) {
            sol_err_t persist_err = persist_shred(bs, shred->slot, variant->variant_id, true,
                                                 index, v_shred->data, raw_len);
            if (persist_err != SOL_OK) {
                sol_log_warn("Failed to persist variant shred slot=%llu variant=%u index=%u: %d",
                             (unsigned long long)shred->slot,
                             (unsigned)variant->variant_id,
                             (unsigned)index,
                             persist_err);
            }
        }

        if (bs->slot_meta_backend) {
            sol_err_t v_err = persist_slot_variants(bs, shred->slot,
                                                   (uint32_t)entry->variant_count,
                                                   entry->next_variant_id);
            if (v_err != SOL_OK) {
                sol_log_warn("Failed to persist slot variants for slot=%llu: %d",
                             (unsigned long long)shred->slot, v_err);
            }
        }
#endif

        maybe_mark_slot_complete_locked(bs, entry, &variant->store, variant->variant_id);
    }

    if (created > 0) {
        bs->stats.shreds_inserted++;
        return SOL_OK;
    }

    if (any_alloc_failed) {
        return SOL_ERR_NOMEM;
    }

    return SOL_ERR_FULL;
}

sol_err_t
sol_blockstore_insert_shred(sol_blockstore_t* bs, const sol_shred_t* shred,
                            const uint8_t* raw_data, size_t raw_len) {
    if (!bs || !shred || !raw_data || raw_len == 0) {
        return SOL_ERR_INVAL;
    }

    pthread_rwlock_wrlock(&bs->lock);

    bs->stats.shreds_received++;

    /* Find or create slot entry */
    sol_slot_entry_t* entry = find_slot_entry(bs, shred->slot);
    if (!entry) {
        entry = create_slot_entry(bs, shred->slot);
        if (!entry) {
            pthread_rwlock_unlock(&bs->lock);
            return SOL_ERR_NOMEM;
        }
    }

    sol_slot_store_t* store = &entry->store;
    bool is_data = (shred->type == SOL_SHRED_TYPE_DATA);
    uint32_t index = shred->index;

    /* Check bounds */
    if (index >= bs->config.max_shreds_per_slot) {
        pthread_rwlock_unlock(&bs->lock);
        return SOL_ERR_INVAL;
    }

    /* Store shred */
    sol_blockstore_shred_t* shred_store;
    if (is_data) {
        shred_store = &store->data_shreds[index];
    } else {
        /* For code shreds, use a separate index space */
        if (index >= store->code_capacity) {
            pthread_rwlock_unlock(&bs->lock);
            return SOL_ERR_INVAL;
        }
        shred_store = &store->code_shreds[index];
    }

    if (is_data) {
        bool stored_in_primary = false;
        sol_err_t derr = insert_data_shred_multi_locked(bs, entry, shred, index,
                                                       raw_data, raw_len,
                                                       &stored_in_primary);
        if (derr != SOL_OK) {
            pthread_rwlock_unlock(&bs->lock);
            return derr;
        }

        shred_store = stored_in_primary ? &store->data_shreds[index] : NULL;
        goto fec;
    }

    /* Check for duplicate */
    if (shred_store->data) {
        if (shred_bytes_equal(shred_store, raw_data, raw_len)) {
            /* Already have this shred */
            bs->stats.shreds_duplicate++;
            pthread_rwlock_unlock(&bs->lock);
            return SOL_ERR_EXISTS;
        }

        /* For now, only track duplicate variants for data shreds. */
        if (!is_data) {
            bs->stats.shreds_duplicate++;
            pthread_rwlock_unlock(&bs->lock);
            return SOL_ERR_EXISTS;
        }

        /* If an existing variant already matches these bytes, treat as duplicate. */
        for (sol_slot_variant_entry_t* v = entry->variants; v; v = v->next) {
            if (variant_has_shred_bytes(&v->store, index, true, raw_data, raw_len)) {
                bs->stats.shreds_duplicate++;
                pthread_rwlock_unlock(&bs->lock);
                return SOL_ERR_EXISTS;
            }
        }

        /* Conflicting data shred -> create a new variant store (best-effort). */
        if (entry->variant_count >= SOL_BLOCKSTORE_MAX_SLOT_VARIANTS) {
            pthread_rwlock_unlock(&bs->lock);
            return SOL_ERR_FULL;
        }

        sol_slot_variant_entry_t* variant = sol_calloc(1, sizeof(*variant));
        if (!variant) {
            pthread_rwlock_unlock(&bs->lock);
            return SOL_ERR_NOMEM;
        }

        variant->variant_id = entry->next_variant_id++;

        sol_err_t cerr = clone_slot_store(&entry->store, &variant->store);
        if (cerr != SOL_OK) {
            sol_free(variant);
            pthread_rwlock_unlock(&bs->lock);
            return cerr;
        }

        if (index >= variant->store.data_capacity) {
            free_slot_store_contents(&variant->store);
            sol_free(variant);
            pthread_rwlock_unlock(&bs->lock);
            return SOL_ERR_INVAL;
        }

        sol_blockstore_shred_t* v_shred = &variant->store.data_shreds[index];
        sol_free(v_shred->data);
        v_shred->data = sol_alloc(raw_len);
        if (!v_shred->data) {
            free_slot_store_contents(&variant->store);
            sol_free(variant);
            pthread_rwlock_unlock(&bs->lock);
            return SOL_ERR_NOMEM;
        }
        memcpy(v_shred->data, raw_data, raw_len);
        v_shred->data_len = raw_len;
        v_shred->index = index;
        v_shred->is_data = true;

        /* Update variant metadata from shred (without incrementing counts) */
        variant->store.meta.parent_slot = shred->header.data.parent_slot;
        if (index < variant->store.meta.first_shred_index) {
            variant->store.meta.first_shred_index = index;
        }
        if (sol_shred_is_last_in_slot(shred)) {
            variant->store.meta.is_full = true;
            variant->store.meta.last_shred_index = index;
            variant->store.meta.num_data_shreds = index + 1;
        } else if (variant->store.meta.is_full &&
                   variant->store.meta.last_shred_index == index) {
            /* Avoid falsely treating the slot as full after replacing the last shred. */
            variant->store.meta.is_full = false;
        }

        variant->next = entry->variants;
        entry->variants = variant;
        entry->variant_count++;

        bs->stats.shreds_inserted++;

#ifdef SOL_HAS_ROCKSDB
        if (bs->shred_backend) {
            sol_err_t persist_err = persist_shred(bs, shred->slot, variant->variant_id, true,
                                                  index, v_shred->data, raw_len);
            if (persist_err != SOL_OK) {
                sol_log_warn("Failed to persist variant shred slot=%llu variant=%u index=%u: %d",
                             (unsigned long long)shred->slot,
                             (unsigned)variant->variant_id,
                             (unsigned)index,
                             persist_err);
            }
        }

        if (bs->slot_meta_backend) {
            sol_err_t v_err = persist_slot_variants(bs, shred->slot,
                                                   (uint32_t)entry->variant_count,
                                                   entry->next_variant_id);
            if (v_err != SOL_OK) {
                sol_log_warn("Failed to persist slot variants for slot=%llu: %d",
                             (unsigned long long)shred->slot, v_err);
            }
        }
#endif

        maybe_mark_slot_complete_locked(bs, entry, &variant->store, variant->variant_id);

        pthread_rwlock_unlock(&bs->lock);
        return SOL_OK;
    }

    /* Allocate and copy shred data */
    shred_store->data = sol_alloc(raw_len);
    if (!shred_store->data) {
        pthread_rwlock_unlock(&bs->lock);
        return SOL_ERR_NOMEM;
    }

    memcpy(shred_store->data, raw_data, raw_len);
    shred_store->data_len = raw_len;
    shred_store->index = index;
    shred_store->is_data = is_data;

    bs->stats.shreds_inserted++;

    if (is_data) {
        store->meta.received_data++;
        bitmap_set(store->received_bitmap, index);
    } else {
        store->meta.received_code++;
    }

    /* Persist to RocksDB if configured */
#ifdef SOL_HAS_ROCKSDB
    if (bs->shred_backend) {
        sol_err_t persist_err = persist_shred(bs, shred->slot, 0, is_data,
                                               index, shred_store->data, raw_len);
        if (persist_err != SOL_OK) {
            sol_log_warn("Failed to persist shred slot=%llu index=%u: %d",
                        (unsigned long long)shred->slot, index, persist_err);
        }
    }
#endif

    /* Update slot metadata from shred */
    if (is_data) {
        bool data_complete = (shred->header.data.flags & SOL_SHRED_FLAG_DATA_COMPLETE) != 0;
        bool last_in_slot = sol_shred_is_last_in_slot(shred);

        /* Update parent slot from first data shred */
        if (store->meta.received_data == 1) {
            store->meta.parent_slot = shred->header.data.parent_slot;
        }

        /* Track first/last shred indices */
        if (index < store->meta.first_shred_index || store->meta.received_data == 1) {
            store->meta.first_shred_index = index;
        }

        if (!store->meta.is_full && index > store->meta.last_shred_index) {
            store->meta.last_shred_index = index;
        }

        /* Track DATA_COMPLETE for debugging/metrics, but only treat LAST_IN_SLOT as
         * the definitive "slot is full" marker (required for tick verification). */
        if (data_complete && !store->meta.is_full) {
            sol_log_info("Slot %llu observed DATA_COMPLETE shred index=%u (flags=0x%02X)",
                         (unsigned long long)shred->slot,
                         (unsigned)index,
                         (unsigned)shred->header.data.flags);
        }

        if (last_in_slot) {
            store->meta.is_full = true;
            store->meta.last_shred_index = index;
            store->meta.num_data_shreds = index + 1;
        }

        maybe_mark_slot_complete_locked(bs, entry, store, 0);

        /* Propagate shared shreds to any existing variants (best-effort). */
        for (sol_slot_variant_entry_t* v = entry->variants; v; v = v->next) {
            if (index >= v->store.data_capacity) continue;
            sol_blockstore_shred_t* vs = &v->store.data_shreds[index];
            if (vs->data) continue;

            vs->data = sol_alloc(raw_len);
            if (!vs->data) continue;

            memcpy(vs->data, raw_data, raw_len);
            vs->data_len = raw_len;
            vs->index = index;
            vs->is_data = true;

            v->store.meta.received_data++;
            bitmap_set(v->store.received_bitmap, index);

            if (v->store.meta.received_data == 1) {
                v->store.meta.parent_slot = shred->header.data.parent_slot;
            }
            if (index < v->store.meta.first_shred_index || v->store.meta.received_data == 1) {
                v->store.meta.first_shred_index = index;
            }
            if (!v->store.meta.is_full && index > v->store.meta.last_shred_index) {
                v->store.meta.last_shred_index = index;
            }
            if (data_complete && !v->store.meta.is_full) {
                sol_log_info("Slot %llu variant %u observed DATA_COMPLETE shred index=%u (flags=0x%02X)",
                             (unsigned long long)shred->slot,
                             (unsigned)v->variant_id,
                             (unsigned)index,
                             (unsigned)shred->header.data.flags);
            }

            if (last_in_slot) {
                v->store.meta.is_full = true;
                v->store.meta.last_shred_index = index;
                v->store.meta.num_data_shreds = index + 1;
            }

            maybe_mark_slot_complete_locked(bs, entry, &v->store, v->variant_id);
        }
    }

fec:
    /* Optional: attempt FEC recovery for this FEC set (best-effort) */
    if (bs->config.enable_fec_recovery) {
        sol_fec_set_t* fec = NULL;
        sol_fec_set_entry_t* fec_node = find_fec_set_entry(entry, shred->fec_set_index);
        if (fec_node) {
            fec = fec_node->fec;
        }

        /* Create FEC set when we see a code shred (provides num_data/num_code) */
        if (!fec && !is_data) {
            uint16_t num_data = shred->header.code.num_data_shreds;
            uint16_t num_code = shred->header.code.num_code_shreds;
            if (num_data > 0) {
                fec = get_or_create_fec_set_locked(entry, shred->slot, shred->fec_set_index,
                                                   num_data, num_code);
                if (fec) {
                    /* Add any already-received data shreds for this FEC set */
                    for (uint16_t i = 0; i < num_data; i++) {
                        uint32_t data_index = shred->fec_set_index + i;
                        if (data_index >= store->data_capacity) break;
                        if (fec->data_shreds && fec->data_shreds[i]) continue;

                        sol_blockstore_shred_t* ds = &store->data_shreds[data_index];
                        if (!ds->data) continue;

                        sol_shred_t* parsed = parse_stored_shred_new(ds->data, ds->data_len);
                        if (!parsed) continue;
                        sol_err_t aerr = sol_fec_set_add_shred(fec, parsed);
                        if (aerr != SOL_OK) {
                            sol_free(parsed);
                        }
                    }
                }
            }
        }

        /* If we have a set, add the current shred */
        if (fec && shred_store && shred_store->data && shred_store->data_len) {
            sol_shred_t* parsed = parse_stored_shred_new(shred_store->data, shred_store->data_len);
            if (parsed) {
                sol_err_t aerr = sol_fec_set_add_shred(fec, parsed);
                if (aerr != SOL_OK) {
                    sol_free(parsed);
                }
            }

            /* Try to recover missing data shreds once we have enough total shreds */
            if (sol_fec_set_can_recover(fec) && fec->data_received < fec->num_data) {
                sol_err_t rerr = sol_fec_set_recover(fec);
                if (rerr == SOL_OK && fec->data_shreds) {
                    for (uint16_t i = 0; i < fec->num_data; i++) {
                        uint32_t data_index = fec->fec_set_index + i;
                        if (data_index >= store->data_capacity) break;
                        if (store->data_shreds[data_index].data) continue;

                        sol_shred_t* recovered = fec->data_shreds[i];
                        if (!recovered || !recovered->raw_data || recovered->raw_len == 0) continue;

                        uint8_t* raw_owned = (uint8_t*)(uintptr_t)recovered->raw_data;
                        sol_err_t serr = store_recovered_data_shred_locked(bs, store, shred->slot,
                                                                           data_index,
                                                                           raw_owned,
                                                                           recovered->raw_len,
                                                                           recovered);
                        if (serr != SOL_OK) continue;
                    }

                    maybe_mark_slot_complete_locked(bs, entry, store, 0);
                }
            }
        }
    }

    pthread_rwlock_unlock(&bs->lock);
    return SOL_OK;
}

sol_err_t
sol_blockstore_insert_shreds(sol_blockstore_t* bs,
                             const sol_shred_t* shreds,
                             const uint8_t* const* raw_data,
                             const size_t* raw_lens,
                             size_t count) {
    if (!bs || !shreds || !raw_data || !raw_lens) {
        return SOL_ERR_INVAL;
    }

    sol_err_t first_error = SOL_OK;

    for (size_t i = 0; i < count; i++) {
        sol_err_t err = sol_blockstore_insert_shred(bs, &shreds[i],
                                                    raw_data[i], raw_lens[i]);
        if (err != SOL_OK && err != SOL_ERR_EXISTS && first_error == SOL_OK) {
            first_error = err;
        }
    }

    return first_error;
}

sol_err_t
sol_blockstore_get_shred(sol_blockstore_t* bs, sol_slot_t slot,
                         uint32_t index, bool is_data,
                         uint8_t* buf, size_t* buf_len) {
    if (!bs || !buf || !buf_len) {
        return SOL_ERR_INVAL;
    }

    /* Check bounds */
    if (index >= bs->config.max_shreds_per_slot) {
        return SOL_ERR_INVAL;
    }

    pthread_rwlock_rdlock(&bs->lock);

    sol_slot_entry_t* entry = find_slot_entry(bs, slot);
    if (entry) {
        sol_blockstore_shred_t* shred;
        if (is_data) {
            if (index >= entry->store.data_capacity) {
                pthread_rwlock_unlock(&bs->lock);
                return SOL_ERR_INVAL;
            }
            shred = &entry->store.data_shreds[index];
        } else {
            if (index >= entry->store.code_capacity) {
                pthread_rwlock_unlock(&bs->lock);
                return SOL_ERR_INVAL;
            }
            shred = &entry->store.code_shreds[index];
        }

        if (shred->data) {
            if (*buf_len < shred->data_len) {
                *buf_len = shred->data_len;
                pthread_rwlock_unlock(&bs->lock);
                return SOL_ERR_OVERFLOW;
            }

            memcpy(buf, shred->data, shred->data_len);
            *buf_len = shred->data_len;

            pthread_rwlock_unlock(&bs->lock);
            return SOL_OK;
        }
    }

    pthread_rwlock_unlock(&bs->lock);

#ifdef SOL_HAS_ROCKSDB
    if (bs->shred_backend) {
        uint8_t* value = NULL;
        size_t value_len = 0;

        sol_err_t err = load_shred(bs, slot, is_data, index, &value, &value_len);
        if (err != SOL_OK) return err;

        if (*buf_len < value_len) {
            *buf_len = value_len;
            sol_free(value);
            return SOL_ERR_OVERFLOW;
        }

        memcpy(buf, value, value_len);
        *buf_len = value_len;
        sol_free(value);
        return SOL_OK;
    }
#endif

    return SOL_ERR_NOTFOUND;
}

bool
sol_blockstore_has_shred(sol_blockstore_t* bs, sol_slot_t slot,
                         uint32_t index, bool is_data) {
    if (!bs) return false;

    if (index >= bs->config.max_shreds_per_slot) {
        return false;
    }

    pthread_rwlock_rdlock(&bs->lock);

    sol_slot_entry_t* entry = find_slot_entry(bs, slot);
    bool has = false;
    if (entry) {
        if (is_data) {
            has = index < entry->store.data_capacity &&
                  entry->store.data_shreds[index].data != NULL;
        } else {
            has = index < entry->store.code_capacity &&
                  entry->store.code_shreds[index].data != NULL;
        }
    }

    pthread_rwlock_unlock(&bs->lock);

    if (has) return true;

#ifdef SOL_HAS_ROCKSDB
    if (bs->shred_backend) {
        uint8_t key[13];
        size_t key_len;
        make_shred_key(slot, is_data, index, key, &key_len);
        return bs->shred_backend->exists(bs->shred_backend->ctx, key, key_len);
    }
#endif

    return false;
}

sol_err_t
sol_blockstore_get_slot_meta(sol_blockstore_t* bs, sol_slot_t slot,
                             sol_slot_meta_t* meta) {
    if (!bs || !meta) return SOL_ERR_INVAL;

    pthread_rwlock_rdlock(&bs->lock);

    sol_slot_entry_t* entry = find_slot_entry(bs, slot);
    if (entry) {
        *meta = entry->store.meta;
        pthread_rwlock_unlock(&bs->lock);
        return SOL_OK;
    }

    pthread_rwlock_unlock(&bs->lock);

#ifdef SOL_HAS_ROCKSDB
    if (bs->slot_meta_backend) {
        return load_slot_meta(bs, slot, meta);
    }
#endif

    return SOL_ERR_NOTFOUND;
}

sol_err_t
sol_blockstore_get_slot_meta_variant(sol_blockstore_t* bs,
                                     sol_slot_t slot,
                                     uint32_t variant_id,
                                     sol_slot_meta_t* meta) {
    if (!bs || !meta) return SOL_ERR_INVAL;

    if (variant_id == 0) {
        return sol_blockstore_get_slot_meta(bs, slot, meta);
    }

    pthread_rwlock_rdlock(&bs->lock);

    sol_slot_entry_t* entry = find_slot_entry(bs, slot);
    if (entry) {
        sol_slot_variant_entry_t* v = find_variant_by_id(entry, variant_id);
        if (v) {
            *meta = v->store.meta;
            pthread_rwlock_unlock(&bs->lock);
            return SOL_OK;
        }
    }

    pthread_rwlock_unlock(&bs->lock);

#ifdef SOL_HAS_ROCKSDB
    if (bs->slot_meta_backend) {
        return load_slot_meta_variant(bs, slot, variant_id, meta);
    }
#endif

    return SOL_ERR_NOTFOUND;
}

bool
sol_blockstore_is_slot_complete(sol_blockstore_t* bs, sol_slot_t slot) {
    if (!bs) return false;

    pthread_rwlock_rdlock(&bs->lock);

    sol_slot_entry_t* entry = find_slot_entry(bs, slot);
    bool complete = false;
    if (entry) {
        complete = entry->any_complete || entry->store.meta.is_complete;
        if (!complete) {
            for (sol_slot_variant_entry_t* v = entry->variants; v; v = v->next) {
                if (v->store.meta.is_complete) {
                    complete = true;
                    break;
                }
            }
        }
    }

    pthread_rwlock_unlock(&bs->lock);
    if (complete) return true;

#ifdef SOL_HAS_ROCKSDB
    if (bs->slot_meta_backend) {
        uint32_t variant_count = 1;
        sol_slot_variants_record_t variants;
        if (load_slot_variants(bs, slot, &variants) == SOL_OK &&
            variants.variant_count > 0) {
            variant_count = variants.variant_count;
        }

        for (uint32_t variant_id = 0; variant_id < variant_count; variant_id++) {
            sol_slot_meta_t meta;
            sol_err_t err = load_slot_meta_variant(bs, slot, variant_id, &meta);
            if (err != SOL_OK) continue;
            if (meta.is_complete) {
                return true;
            }
        }
    }
#endif

    return false;
}

size_t
sol_blockstore_get_missing_shreds(sol_blockstore_t* bs, sol_slot_t slot,
                                  uint32_t* indices, size_t max_indices) {
    if (!bs || !indices || max_indices == 0) return 0;

    pthread_rwlock_rdlock(&bs->lock);

    sol_slot_entry_t* entry = find_slot_entry(bs, slot);
    if (!entry) {
        pthread_rwlock_unlock(&bs->lock);
#ifdef SOL_HAS_ROCKSDB
        if (bs->slot_meta_backend && bs->shred_backend) {
            sol_slot_meta_t meta;
            if (load_slot_meta(bs, slot, &meta) != SOL_OK) {
                return 0;
            }

            uint32_t last = meta.last_shred_index;
            if (!meta.is_full && last == 0 && meta.received_data > 0) {
                last = meta.received_data;
            }
            if (bs->config.max_shreds_per_slot > 0 &&
                last >= bs->config.max_shreds_per_slot) {
                last = (uint32_t)bs->config.max_shreds_per_slot - 1;
            }
            if (meta.is_full && meta.num_data_shreds > 0 && last >= meta.num_data_shreds) {
                last = meta.num_data_shreds - 1;
            }

            size_t count = 0;
            for (uint32_t i = 0; i <= last && count < max_indices; i++) {
                uint8_t key[13];
                size_t key_len;
                make_shred_key(slot, true, i, key, &key_len);
                if (!bs->shred_backend->exists(bs->shred_backend->ctx, key, key_len)) {
                    indices[count++] = i;
                }
            }
            return count;
        }
#endif
        return 0;
    }

    sol_slot_store_t* store = &entry->store;
    size_t count = 0;

    /* When the true last index is unknown, use the highest index observed so
     * far as an approximation. This helps drive repair to fill gaps instead of
     * being capped by the received count (which can be sparse). */
    uint32_t last = store->meta.last_shred_index;
    if (!store->meta.is_full && last == 0 && store->meta.received_data > 0) {
        last = store->meta.received_data;
    }
    for (sol_slot_variant_entry_t* v = entry->variants; v; v = v->next) {
        uint32_t v_last = v->store.meta.last_shred_index;
        if (!v->store.meta.is_full && v_last == 0 && v->store.meta.received_data > 0) {
            v_last = v->store.meta.received_data;
        }
        if (v_last > last) last = v_last;
    }

    for (uint32_t i = 0; i <= last && count < max_indices; i++) {
        bool present = store->received_bitmap && bitmap_get(store->received_bitmap, i);
        if (!present) {
            for (sol_slot_variant_entry_t* v = entry->variants; v; v = v->next) {
                if (v->store.received_bitmap && bitmap_get(v->store.received_bitmap, i)) {
                    present = true;
                    break;
                }
            }
        }

        if (!present) {
            indices[count++] = i;
        }
    }

    /* When all known shreds are present but the slot isn't complete (no
     * LAST_IN_SLOT flag seen yet), probe beyond the highest known index to
     * discover additional shreds.  Use exponentially growing offsets to
     * quickly find the true slot extent when there are gaps between FEC sets. */
    if (count == 0 && !store->meta.is_full && last > 0) {
        uint32_t offset = 1;
        while (offset <= 16384 && count < max_indices) {
            uint32_t probe = last + offset;
            if (probe < last) break;  /* overflow */
            indices[count++] = probe;
            offset *= 2;
        }
    }

    pthread_rwlock_unlock(&bs->lock);
    return count;
}

size_t
sol_blockstore_num_variants(sol_blockstore_t* bs, sol_slot_t slot) {
    if (!bs) return 0;

    pthread_rwlock_rdlock(&bs->lock);
    sol_slot_entry_t* entry = find_slot_entry(bs, slot);
    size_t count = entry ? entry->variant_count : 0;
    pthread_rwlock_unlock(&bs->lock);

#ifdef SOL_HAS_ROCKSDB
    if (count == 0 && bs->slot_meta_backend) {
        sol_slot_variants_record_t variants;
        if (load_slot_variants(bs, slot, &variants) == SOL_OK &&
            variants.variant_count > 0) {
            return (size_t)variants.variant_count;
        }

        sol_slot_meta_t meta;
        if (load_slot_meta(bs, slot, &meta) == SOL_OK) {
            return 1;
        }
    }
#endif

    return count;
}

sol_block_t*
sol_blockstore_get_block_variant(sol_blockstore_t* bs, sol_slot_t slot, uint32_t variant_id) {
    if (!bs) return NULL;

    pthread_rwlock_rdlock(&bs->lock);

    sol_slot_entry_t* entry = find_slot_entry(bs, slot);
    sol_slot_store_t* store = entry ? store_for_variant(entry, variant_id) : NULL;
    if (store && store->meta.is_complete) {
        /* Calculate total data size */
        size_t total_size = 0;
        for (uint32_t i = 0; i <= store->meta.last_shred_index; i++) {
            sol_blockstore_shred_t* shred = &store->data_shreds[i];
            if (shred->data) {
                sol_shred_t parsed;
                if (sol_shred_parse(&parsed, shred->data, shred->data_len) == SOL_OK &&
                    parsed.type == SOL_SHRED_TYPE_DATA) {
                    total_size += parsed.payload_len;
                } else {
                    pthread_rwlock_unlock(&bs->lock);
                    return NULL;
                }
            }
        }

        /* Allocate block */
        sol_block_t* block = sol_calloc(1, sizeof(sol_block_t));
        if (!block) {
            pthread_rwlock_unlock(&bs->lock);
            return NULL;
        }

        block->slot = slot;
        block->parent_slot = store->meta.parent_slot;
        block->leader = store->meta.leader;

        if (total_size > 0) {
            block->data = sol_alloc(total_size);
            if (!block->data) {
                sol_free(block);
                pthread_rwlock_unlock(&bs->lock);
                return NULL;
            }

            /* Assemble block data from shreds */
            size_t offset = 0;
            for (uint32_t i = 0; i <= store->meta.last_shred_index; i++) {
                sol_blockstore_shred_t* shred = &store->data_shreds[i];
                if (shred->data) {
                    sol_shred_t parsed;
                    if (sol_shred_parse(&parsed, shred->data, shred->data_len) != SOL_OK ||
                        parsed.type != SOL_SHRED_TYPE_DATA) {
                        sol_block_destroy(block);
                        pthread_rwlock_unlock(&bs->lock);
                        return NULL;
                    }

                    if (parsed.payload && parsed.payload_len > 0) {
                        memcpy(block->data + offset, parsed.payload, parsed.payload_len);
                        offset += parsed.payload_len;
                    }
                }
            }
            block->data_len = offset;
        }

        bs->stats.blocks_assembled++;

        pthread_rwlock_unlock(&bs->lock);
        return block;
    }

    pthread_rwlock_unlock(&bs->lock);
    return sol_blockstore_get_block_variant_rocksdb(bs, slot, variant_id);
}

sol_block_t*
sol_blockstore_get_block_variant_rocksdb(sol_blockstore_t* bs, sol_slot_t slot, uint32_t variant_id) {
    if (!bs) return NULL;

#ifdef SOL_HAS_ROCKSDB
    if (!bs->shred_backend || !bs->slot_meta_backend) {
        return NULL;
    }

    sol_slot_meta_t meta;
    if (load_slot_meta_variant(bs, slot, variant_id, &meta) != SOL_OK) {
        return NULL;
    }
    if (!meta.is_complete) {
        return NULL;
    }
    if (meta.last_shred_index >= bs->config.max_shreds_per_slot) {
        return NULL;
    }

    sol_block_t* block = sol_calloc(1, sizeof(sol_block_t));
    if (!block) return NULL;

    block->slot = slot;
    block->parent_slot = meta.parent_slot;
    block->leader = meta.leader;

    uint32_t last = meta.last_shred_index;
    size_t max_payload_per_shred = SOL_SHRED_MAX_DATA_SIZE;
    size_t data_cap = ((size_t)last + 1u) * max_payload_per_shred;
    if (last > 0 && data_cap / ((size_t)last + 1u) != max_payload_per_shred) {
        sol_free(block);
        return NULL;
    }

    if (data_cap > 0) {
        block->data = sol_alloc(data_cap);
        if (!block->data) {
            sol_free(block);
            return NULL;
        }
    }

    size_t offset = 0;
    for (uint32_t i = 0; i <= last; i++) {
        uint8_t* shred_data = NULL;
        size_t shred_len = 0;

        sol_err_t err = load_shred_variant(bs, slot, variant_id, true, i, &shred_data, &shred_len);
        if (err != SOL_OK) {
            sol_block_destroy(block);
            return NULL;
        }

        sol_shred_t parsed;
        if (sol_shred_parse(&parsed, shred_data, shred_len) != SOL_OK ||
            parsed.type != SOL_SHRED_TYPE_DATA) {
            sol_free(shred_data);
            sol_block_destroy(block);
            return NULL;
        }

        if (parsed.payload && parsed.payload_len > 0) {
            if (offset + parsed.payload_len > data_cap) {
                sol_free(shred_data);
                sol_block_destroy(block);
                return NULL;
            }
            memcpy(block->data + offset, parsed.payload, parsed.payload_len);
            offset += parsed.payload_len;
        }

        sol_free(shred_data);
    }

    block->data_len = offset;

    if (block->data && block->data_len < data_cap) {
        uint8_t* resized = sol_realloc(block->data, block->data_len);
        if (resized || block->data_len == 0) {
            block->data = resized;
        }
    }

    pthread_rwlock_wrlock(&bs->lock);
    bs->stats.blocks_assembled++;
    pthread_rwlock_unlock(&bs->lock);

    return block;
#else
    (void)slot;
    (void)variant_id;
    return NULL;
#endif
}

sol_block_t*
sol_blockstore_get_block(sol_blockstore_t* bs, sol_slot_t slot) {
    return sol_blockstore_get_block_variant(bs, slot, 0);
}

void
sol_block_destroy(sol_block_t* block) {
    if (block) {
        sol_free(block->data);
        sol_free(block);
    }
}

sol_err_t
sol_blockstore_set_rooted(sol_blockstore_t* bs, sol_slot_t slot) {
    if (!bs) return SOL_ERR_INVAL;

    pthread_rwlock_wrlock(&bs->lock);

    sol_slot_entry_t* entry = find_slot_entry(bs, slot);
    if (!entry) {
        pthread_rwlock_unlock(&bs->lock);
        return SOL_ERR_NOTFOUND;
    }

    if (!entry->store.meta.is_rooted) {
        entry->store.meta.is_rooted = true;
        bs->stats.slots_rooted++;

        if (slot > bs->highest_rooted) {
            bs->highest_rooted = slot;
        }
    }

    for (sol_slot_variant_entry_t* v = entry->variants; v; v = v->next) {
        v->store.meta.is_rooted = true;
    }

    pthread_rwlock_unlock(&bs->lock);
    return SOL_OK;
}

sol_err_t
sol_blockstore_set_dead(sol_blockstore_t* bs, sol_slot_t slot) {
    if (!bs) return SOL_ERR_INVAL;

    pthread_rwlock_wrlock(&bs->lock);

    sol_slot_entry_t* entry = find_slot_entry(bs, slot);
    if (!entry) {
        pthread_rwlock_unlock(&bs->lock);
        return SOL_ERR_NOTFOUND;
    }

    entry->store.meta.is_dead = true;
    for (sol_slot_variant_entry_t* v = entry->variants; v; v = v->next) {
        v->store.meta.is_dead = true;
    }

    pthread_rwlock_unlock(&bs->lock);
    return SOL_OK;
}

sol_err_t
sol_blockstore_get_block_hash_variant(sol_blockstore_t* bs,
                                      sol_slot_t slot,
                                      uint32_t variant_id,
                                      sol_hash_t* hash) {
    if (!bs || !hash) return SOL_ERR_INVAL;

    /* Get the assembled block (this acquires its own lock) */
    sol_block_t* block = sol_blockstore_get_block_variant(bs, slot, variant_id);
    if (!block) {
        return SOL_ERR_NOTFOUND;
    }

    /* If block has no data, can't compute hash */
    if (!block->data || block->data_len == 0) {
        sol_block_destroy(block);
        return SOL_ERR_NOTFOUND;
    }

    /* Parse entries from block data */
    sol_entry_batch_t* batch = sol_entry_batch_new(16);
    if (!batch) {
        sol_block_destroy(block);
        return SOL_ERR_NOMEM;
    }

    sol_err_t err = sol_entry_batch_parse(batch, block->data, block->data_len);
    if (err != SOL_OK) {
        sol_entry_batch_destroy(batch);
        sol_block_destroy(block);
        return err;
    }

    if (batch->num_entries == 0) {
        sol_entry_batch_destroy(batch);
        sol_block_destroy(block);
        return SOL_ERR_NOTFOUND;
    }

    /* Block hash is the hash of the last entry (PoH endpoint) */
    sol_entry_t* last_entry = &batch->entries[batch->num_entries - 1];
    memcpy(hash, &last_entry->hash, sizeof(sol_hash_t));

    sol_entry_batch_destroy(batch);
    sol_block_destroy(block);
    return SOL_OK;
}

sol_err_t
sol_blockstore_get_block_hash(sol_blockstore_t* bs, sol_slot_t slot,
                               sol_hash_t* hash) {
    return sol_blockstore_get_block_hash_variant(bs, slot, 0, hash);
}

sol_slot_t
sol_blockstore_highest_slot(sol_blockstore_t* bs) {
    if (!bs) return 0;

    pthread_rwlock_rdlock(&bs->lock);
    sol_slot_t slot = bs->highest_slot;
    pthread_rwlock_unlock(&bs->lock);

    return slot;
}

sol_slot_t
sol_blockstore_highest_complete_slot(sol_blockstore_t* bs) {
    if (!bs) return 0;

    pthread_rwlock_rdlock(&bs->lock);
    sol_slot_t slot = bs->highest_complete;
    pthread_rwlock_unlock(&bs->lock);

    return slot;
}

sol_slot_t
sol_blockstore_highest_rooted_slot(sol_blockstore_t* bs) {
    if (!bs) return 0;

    pthread_rwlock_rdlock(&bs->lock);
    sol_slot_t slot = bs->highest_rooted;
    pthread_rwlock_unlock(&bs->lock);

    return slot;
}

sol_slot_t
sol_blockstore_lowest_slot(sol_blockstore_t* bs) {
    if (!bs) return 0;

    pthread_rwlock_rdlock(&bs->lock);
    sol_slot_t slot = bs->lowest_slot;
    pthread_rwlock_unlock(&bs->lock);

    /* If no slots stored yet, return 0 */
    if (slot == UINT64_MAX) {
        return 0;
    }

    return slot;
}

void
sol_blockstore_set_slot_callback(sol_blockstore_t* bs,
                                 sol_blockstore_slot_cb callback,
                                 void* ctx) {
    if (!bs) return;

    pthread_rwlock_wrlock(&bs->lock);
    bs->slot_callback = callback;
    bs->slot_callback_ctx = ctx;
    pthread_rwlock_unlock(&bs->lock);
}

size_t
sol_blockstore_purge_slots_below(sol_blockstore_t* bs, sol_slot_t min_slot) {
    if (!bs) return 0;

    pthread_rwlock_wrlock(&bs->lock);

    size_t purged = 0;

    for (size_t i = 0; i < bs->slot_table_size; i++) {
        sol_slot_entry_t** prev_ptr = &bs->slots[i];
        sol_slot_entry_t* entry = bs->slots[i];

        while (entry) {
            sol_slot_entry_t* next = entry->next;

            if (entry->slot < min_slot) {
                *prev_ptr = next;
                free_slot_entry(entry);
                bs->slot_count--;
                purged++;
            } else {
                prev_ptr = &entry->next;
            }

            entry = next;
        }
    }

    /* Update lowest_slot after purge */
    if (purged > 0 && bs->lowest_slot < min_slot) {
        bs->lowest_slot = min_slot;
    }

    pthread_rwlock_unlock(&bs->lock);
    return purged;
}

void
sol_blockstore_stats(const sol_blockstore_t* bs, sol_blockstore_stats_t* stats) {
    if (!bs || !stats) return;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&bs->lock);
    *stats = bs->stats;
    pthread_rwlock_unlock((pthread_rwlock_t*)&bs->lock);
}

void
sol_blockstore_stats_reset(sol_blockstore_t* bs) {
    if (!bs) return;

    pthread_rwlock_wrlock(&bs->lock);
    memset(&bs->stats, 0, sizeof(bs->stats));
    pthread_rwlock_unlock(&bs->lock);
}

size_t
sol_blockstore_slot_count(const sol_blockstore_t* bs) {
    if (!bs) return 0;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&bs->lock);
    size_t count = bs->slot_count;
    pthread_rwlock_unlock((pthread_rwlock_t*)&bs->lock);

    return count;
}

static void
store_u64_be(uint8_t* dst, uint64_t v) {
    dst[0] = (uint8_t)((v >> 56) & 0xFFu);
    dst[1] = (uint8_t)((v >> 48) & 0xFFu);
    dst[2] = (uint8_t)((v >> 40) & 0xFFu);
    dst[3] = (uint8_t)((v >> 32) & 0xFFu);
    dst[4] = (uint8_t)((v >> 24) & 0xFFu);
    dst[5] = (uint8_t)((v >> 16) & 0xFFu);
    dst[6] = (uint8_t)((v >> 8) & 0xFFu);
    dst[7] = (uint8_t)(v & 0xFFu);
}

static uint64_t
load_u64_be(const uint8_t* src) {
    return ((uint64_t)src[0] << 56) |
           ((uint64_t)src[1] << 48) |
           ((uint64_t)src[2] << 40) |
           ((uint64_t)src[3] << 32) |
           ((uint64_t)src[4] << 24) |
           ((uint64_t)src[5] << 16) |
           ((uint64_t)src[6] << 8) |
           ((uint64_t)src[7]);
}

static bool
prefix_next(const uint8_t* prefix, size_t len, uint8_t* out) {
    if (!prefix || !out || len == 0) return false;
    memcpy(out, prefix, len);

    for (size_t i = len; i > 0; i--) {
        size_t idx = i - 1;
        if (out[idx] != 0xFFu) {
            out[idx]++;
            for (size_t j = idx + 1; j < len; j++) {
                out[j] = 0;
            }
            return true;
        }
    }

    return false;
}

sol_err_t
sol_blockstore_index_transaction(sol_blockstore_t* bs,
                                 sol_slot_t slot,
                                 const sol_signature_t* signature,
                                 const sol_pubkey_t* account_keys,
                                 size_t account_keys_len,
                                 sol_err_t err) {
    if (!bs || !signature || !account_keys) return SOL_ERR_INVAL;
    if (account_keys_len == 0) return SOL_OK;
    if (!bs->address_sig_backend) return SOL_ERR_NOT_IMPLEMENTED;

    uint8_t key[32 + 8 + 64];
    uint8_t value[4];

    uint64_t inv_slot = UINT64_MAX - (uint64_t)slot;
    int32_t err32 = (int32_t)err;
    memcpy(value, &err32, sizeof(err32));

    store_u64_be(key + 32, inv_slot);
    memcpy(key + 32 + 8, signature->bytes, 64);

    /* Hot path: use RocksDB batch writes when available to avoid a write syscall
     * per account key (can be tens of thousands per slot). */
    if (bs->address_sig_backend->batch_write &&
        account_keys_len <= SOL_MAX_MESSAGE_ACCOUNTS) {
        sol_batch_op_t ops[SOL_MAX_MESSAGE_ACCOUNTS];
        uint8_t keys[SOL_MAX_MESSAGE_ACCOUNTS][sizeof(key)];

        for (size_t i = 0; i < account_keys_len; i++) {
            memcpy(keys[i], account_keys[i].bytes, 32);
            store_u64_be(keys[i] + 32, inv_slot);
            memcpy(keys[i] + 32 + 8, signature->bytes, 64);

            ops[i].op = SOL_BATCH_OP_PUT;
            ops[i].key = keys[i];
            ops[i].key_len = sizeof(keys[i]);
            ops[i].value = value;
            ops[i].value_len = sizeof(value);
        }

        sol_storage_batch_t batch = {
            .ops = ops,
            .count = account_keys_len,
            .capacity = account_keys_len,
        };

        return bs->address_sig_backend->batch_write(bs->address_sig_backend->ctx, &batch);
    }

    sol_err_t first_err = SOL_OK;
    for (size_t i = 0; i < account_keys_len; i++) {
        memcpy(key, account_keys[i].bytes, 32);
        sol_err_t per = bs->address_sig_backend->put(bs->address_sig_backend->ctx,
                                                     key, sizeof(key),
                                                     value, sizeof(value));
        if (per != SOL_OK && first_err == SOL_OK) {
            first_err = per;
        }
    }

    return first_err;
}

typedef struct {
    const sol_pubkey_t*                  address;
    sol_blockstore_address_signature_t*  out;
    size_t                               out_cap;
    size_t                               count;
} address_sig_iter_ctx_t;

static bool
address_sig_iter_cb(const uint8_t* key, size_t key_len,
                    const uint8_t* value, size_t value_len,
                    void* ctx) {
    address_sig_iter_ctx_t* c = (address_sig_iter_ctx_t*)ctx;
    if (!c || !key) return false;

    if (key_len != (32 + 8 + 64)) {
        return true;
    }

    if (memcmp(key, c->address->bytes, 32) != 0) {
        return true;
    }

    if (c->count >= c->out_cap) {
        return false;
    }

    sol_blockstore_address_signature_t* out = &c->out[c->count++];

    uint64_t inv_slot = load_u64_be(key + 32);
    out->slot = (sol_slot_t)(UINT64_MAX - inv_slot);
    memcpy(out->signature.bytes, key + 32 + 8, 64);

    out->err = SOL_OK;
    if (value && value_len >= 4) {
        int32_t err32 = 0;
        memcpy(&err32, value, 4);
        out->err = (sol_err_t)err32;
    }

    return true;
}

size_t
sol_blockstore_get_signatures_for_address(sol_blockstore_t* bs,
                                          const sol_pubkey_t* address,
                                          size_t limit,
                                          sol_blockstore_address_signature_t* out,
                                          size_t out_cap) {
    if (!bs || !address || !out || out_cap == 0) return 0;
    if (!bs->address_sig_backend) return 0;

    size_t want = limit;
    if (want == 0 || want > out_cap) {
        want = out_cap;
    }

    uint8_t end_prefix[32];
    const uint8_t* end_key = NULL;
    size_t end_len = 0;
    if (prefix_next(address->bytes, sizeof(end_prefix), end_prefix)) {
        end_key = end_prefix;
        end_len = sizeof(end_prefix);
    }

    address_sig_iter_ctx_t ctx = {
        .address = address,
        .out = out,
        .out_cap = want,
        .count = 0,
    };

    bs->address_sig_backend->iterate_range(
        bs->address_sig_backend->ctx,
        address->bytes, 32,
        end_key, end_len,
        address_sig_iter_cb, &ctx
    );

    return ctx.count;
}
