/*
 * sol_map.c - Hash map implementation
 */

#include "sol_types.h"  /* Must be before sol_map.h for pubkey_map */
#include "sol_map.h"
#include <string.h>

/*
 * Get control byte for hash
 */
static inline uint8_t
ctrl_byte(uint64_t hash) {
    /* Use high 7 bits as hash fragment, set high bit to mark occupied */
    return SOL_MAP_OCCUPIED | (uint8_t)(hash >> 57);
}

/*
 * Get slot index for hash
 */
static inline size_t
slot_index(uint64_t hash, size_t mask) {
    return (size_t)(hash & mask);
}

/*
 * Get key pointer at index
 */
static inline void*
key_at(const sol_map_t* map, size_t i) {
    return (char*)map->keys + i * map->key_size;
}

/*
 * Get value pointer at index
 */
static inline void*
val_at(const sol_map_t* map, size_t i) {
    return (char*)map->vals + i * map->val_size;
}

/*
 * Probe distance (Robin Hood)
 */
static inline size_t
probe_distance(uint64_t hash, size_t slot, size_t capacity) {
    size_t ideal = slot_index(hash, capacity - 1);
    return (slot - ideal) & (capacity - 1);
}

/*
 * Create new map
 */
sol_map_t*
sol_map_new(size_t key_size, size_t val_size,
            uint64_t (*hash)(const void*),
            bool (*eq)(const void*, const void*),
            size_t capacity) {
    if (hash == NULL || eq == NULL) {
        return NULL;
    }

    /* Round up to power of 2 */
    if (capacity < SOL_MAP_MIN_CAPACITY) {
        capacity = SOL_MAP_MIN_CAPACITY;
    }
    capacity = sol_next_pow2_64(capacity);
    if (capacity == 0) {
        return NULL; /* overflow */
    }

    if (key_size != 0 && capacity > SIZE_MAX / key_size) {
        return NULL;
    }
    if (val_size != 0 && capacity > SIZE_MAX / val_size) {
        return NULL;
    }

    sol_map_t* map = sol_alloc_t(sol_map_t);
    if (map == NULL) {
        return NULL;
    }

    map->size = 0;
    map->capacity = capacity;
    map->key_size = key_size;
    map->val_size = val_size;
    map->hash = hash;
    map->eq = eq;

    /* Allocate control bytes */
    map->ctrl = sol_calloc(capacity, sizeof(uint8_t));
    if (map->ctrl == NULL) {
        sol_free(map);
        return NULL;
    }

    /* Allocate keys */
    map->keys = sol_alloc(key_size * capacity);
    if (map->keys == NULL) {
        sol_free(map->ctrl);
        sol_free(map);
        return NULL;
    }

    /* Allocate values */
    map->vals = sol_alloc(val_size * capacity);
    if (map->vals == NULL) {
        sol_free(map->keys);
        sol_free(map->ctrl);
        sol_free(map);
        return NULL;
    }

    return map;
}

/*
 * Destroy map
 */
void
sol_map_destroy(sol_map_t* map) {
    if (map == NULL) {
        return;
    }

    sol_free(map->vals);
    sol_free(map->keys);
    sol_free(map->ctrl);
    sol_free(map);
}

/*
 * Clear all entries
 */
void
sol_map_clear(sol_map_t* map) {
    if (map == NULL) {
        return;
    }

    memset(map->ctrl, 0, map->capacity);
    map->size = 0;
}

/*
 * Grow map
 */
static sol_err_t
sol_map_grow(sol_map_t* map) {
    size_t old_cap = map->capacity;
    if (old_cap > SIZE_MAX / 2) {
        return SOL_ERR_NOMEM;
    }
    size_t new_cap = old_cap * 2;
    if (new_cap == 0) {
        return SOL_ERR_NOMEM;
    }

    if (map->key_size != 0 && new_cap > SIZE_MAX / map->key_size) {
        return SOL_ERR_NOMEM;
    }
    if (map->val_size != 0 && new_cap > SIZE_MAX / map->val_size) {
        return SOL_ERR_NOMEM;
    }

    uint8_t* old_ctrl = map->ctrl;
    void* old_keys = map->keys;
    void* old_vals = map->vals;

    /* Allocate new arrays */
    map->ctrl = sol_calloc(new_cap, sizeof(uint8_t));
    if (map->ctrl == NULL) {
        map->ctrl = old_ctrl;
        return SOL_ERR_NOMEM;
    }

    map->keys = sol_alloc(map->key_size * new_cap);
    if (map->keys == NULL) {
        sol_free(map->ctrl);
        map->ctrl = old_ctrl;
        map->keys = old_keys;
        return SOL_ERR_NOMEM;
    }

    map->vals = sol_alloc(map->val_size * new_cap);
    if (map->vals == NULL) {
        sol_free(map->keys);
        sol_free(map->ctrl);
        map->ctrl = old_ctrl;
        map->keys = old_keys;
        map->vals = old_vals;
        return SOL_ERR_NOMEM;
    }

    map->capacity = new_cap;
    map->size = 0;

    /* Rehash all entries */
    for (size_t i = 0; i < old_cap; i++) {
        if (old_ctrl[i] & SOL_MAP_OCCUPIED) {
            void* key = (char*)old_keys + i * map->key_size;
            void* val = (char*)old_vals + i * map->val_size;
            sol_map_insert(map, key, val);
        }
    }

    sol_free(old_vals);
    sol_free(old_keys);
    sol_free(old_ctrl);

    return SOL_OK;
}

/*
 * Find slot for key
 * Returns slot index, or capacity if not found
 * Sets *insert_slot to best slot for insertion
 */
static size_t
find_slot(const sol_map_t* map, const void* key, uint64_t hash, size_t* insert_slot) {
    size_t mask = map->capacity - 1;
    size_t slot = slot_index(hash, mask);
    uint8_t ctrl = ctrl_byte(hash);
    size_t dist = 0;
    size_t best_insert = map->capacity;

    while (true) {
        uint8_t c = map->ctrl[slot];

        if (c == SOL_MAP_EMPTY) {
            /* Empty slot - key not found */
            if (insert_slot != NULL) {
                *insert_slot = (best_insert < map->capacity) ? best_insert : slot;
            }
            return map->capacity;
        }

        if ((c & 0x7f) == (ctrl & 0x7f)) {
            /* Hash fragment matches - check full key */
            if (map->eq(key_at(map, slot), key)) {
                /* Found */
                if (insert_slot != NULL) {
                    *insert_slot = slot;
                }
                return slot;
            }
        }

        /* Robin Hood: check if current entry is "richer" */
        if (c & SOL_MAP_OCCUPIED) {
            uint64_t slot_hash = map->hash(key_at(map, slot));
            size_t slot_dist = probe_distance(slot_hash, slot, map->capacity);
            if (slot_dist < dist && best_insert == map->capacity) {
                best_insert = slot;
            }
        }

        slot = (slot + 1) & mask;
        dist++;

        /* Safety check - should never happen with proper load factor */
        if (dist > map->capacity) {
            if (insert_slot != NULL) {
                *insert_slot = map->capacity;
            }
            return map->capacity;
        }
    }
}

/*
 * Insert or update entry
 */
void*
sol_map_insert(sol_map_t* map, const void* key, const void* val) {
    if (map == NULL || key == NULL) {
        return NULL;
    }

    /* Check if we need to grow */
    size_t threshold = (map->capacity * SOL_MAP_MAX_LOAD_NUM) / SOL_MAP_MAX_LOAD_DENOM;
    if (map->size >= threshold) {
        if (sol_map_grow(map) != SOL_OK) {
            return NULL;
        }
    }

    uint64_t hash = map->hash(key);
    size_t insert_slot;
    size_t found = find_slot(map, key, hash, &insert_slot);

    if (found < map->capacity) {
        /* Update existing */
        if (val != NULL) {
            memcpy(val_at(map, found), val, map->val_size);
        }
        return val_at(map, found);
    }

    if (insert_slot >= map->capacity) {
        return NULL;  /* Should not happen */
    }

    /* Insert new with Robin Hood displacement */
    size_t slot = insert_slot;
    uint8_t ctrl = ctrl_byte(hash);

    /* Make copies of what we're inserting */
    char key_buf[256];
    char val_buf[256];
    sol_assert(map->key_size <= sizeof(key_buf));
    sol_assert(map->val_size <= sizeof(val_buf));
    memcpy(key_buf, key, map->key_size);
    if (val != NULL) {
        memcpy(val_buf, val, map->val_size);
    } else {
        memset(val_buf, 0, map->val_size);
    }

    void* result = NULL;
    size_t mask = map->capacity - 1;
    size_t dist = probe_distance(hash, slot, map->capacity);

    while (true) {
        if (map->ctrl[slot] == SOL_MAP_EMPTY) {
            /* Found empty slot */
            map->ctrl[slot] = ctrl;
            memcpy(key_at(map, slot), key_buf, map->key_size);
            memcpy(val_at(map, slot), val_buf, map->val_size);
            if (result == NULL) {
                result = val_at(map, slot);
            }
            map->size++;
            break;
        }

        /* Robin Hood: swap if current has shorter probe distance */
        uint64_t slot_hash = map->hash(key_at(map, slot));
        size_t slot_dist = probe_distance(slot_hash, slot, map->capacity);

        if (slot_dist < dist) {
            /* Swap */
            uint8_t tmp_ctrl = map->ctrl[slot];
            char tmp_key[256], tmp_val[256];
            memcpy(tmp_key, key_at(map, slot), map->key_size);
            memcpy(tmp_val, val_at(map, slot), map->val_size);

            map->ctrl[slot] = ctrl;
            memcpy(key_at(map, slot), key_buf, map->key_size);
            memcpy(val_at(map, slot), val_buf, map->val_size);

            if (result == NULL) {
                result = val_at(map, slot);
            }

            ctrl = tmp_ctrl;
            memcpy(key_buf, tmp_key, map->key_size);
            memcpy(val_buf, tmp_val, map->val_size);
            dist = slot_dist;
        }

        slot = (slot + 1) & mask;
        dist++;
    }

    return result;
}

/*
 * Look up entry
 */
void*
sol_map_get(const sol_map_t* map, const void* key) {
    if (map == NULL || key == NULL || map->size == 0) {
        return NULL;
    }

    uint64_t hash = map->hash(key);
    size_t found = find_slot(map, key, hash, NULL);

    if (found < map->capacity) {
        return val_at(map, found);
    }

    return NULL;
}

/*
 * Check if key exists
 */
bool
sol_map_contains(const sol_map_t* map, const void* key) {
    return sol_map_get(map, key) != NULL;
}

/*
 * Remove entry with backward shift deletion
 */
bool
sol_map_remove(sol_map_t* map, const void* key) {
    if (map == NULL || key == NULL || map->size == 0) {
        return false;
    }

    uint64_t hash = map->hash(key);
    size_t found = find_slot(map, key, hash, NULL);

    if (found >= map->capacity) {
        return false;
    }

    size_t mask = map->capacity - 1;
    size_t slot = found;

    /* Backward shift deletion */
    while (true) {
        size_t next = (slot + 1) & mask;

        if (map->ctrl[next] == SOL_MAP_EMPTY) {
            /* Next is empty, just clear this slot */
            map->ctrl[slot] = SOL_MAP_EMPTY;
            break;
        }

        /* Check if next entry is in its ideal position */
        uint64_t next_hash = map->hash(key_at(map, next));
        size_t ideal = slot_index(next_hash, mask);

        if (ideal == next) {
            /* Next entry is at ideal position, stop shifting */
            map->ctrl[slot] = SOL_MAP_EMPTY;
            break;
        }

        /* Shift next entry back */
        map->ctrl[slot] = map->ctrl[next];
        memcpy(key_at(map, slot), key_at(map, next), map->key_size);
        memcpy(val_at(map, slot), val_at(map, next), map->val_size);

        slot = next;
    }

    map->size--;
    return true;
}

/*
 * Reserve capacity
 */
sol_err_t
sol_map_reserve(sol_map_t* map, size_t capacity) {
    if (map == NULL) {
        return SOL_ERR_INVAL;
    }

    /* Adjust for load factor */
    if (capacity > SIZE_MAX / SOL_MAP_MAX_LOAD_DENOM) {
        return SOL_ERR_OVERFLOW;
    }
    capacity = (capacity * SOL_MAP_MAX_LOAD_DENOM) / SOL_MAP_MAX_LOAD_NUM + 1;
    capacity = sol_next_pow2_64(capacity);
    if (capacity == 0) {
        return SOL_ERR_OVERFLOW;
    }

    while (map->capacity < capacity) {
        SOL_TRY(sol_map_grow(map));
    }

    return SOL_OK;
}

/*
 * Iterator
 */
sol_map_iter_t
sol_map_iter(const sol_map_t* map) {
    return (sol_map_iter_t){ .map = map, .index = 0 };
}

bool
sol_map_iter_next(sol_map_iter_t* iter, void** key, void** val) {
    if (iter == NULL || iter->map == NULL) {
        return false;
    }

    while (iter->index < iter->map->capacity) {
        size_t i = iter->index++;

        if (iter->map->ctrl[i] & SOL_MAP_OCCUPIED) {
            if (key != NULL) {
                *key = key_at(iter->map, i);
            }
            if (val != NULL) {
                *val = val_at(iter->map, i);
            }
            return true;
        }
    }

    return false;
}

/*
 * Pubkey map specialization
 */

static uint64_t
pubkey_hash(const void* p) {
    /* First 8 bytes of pubkey as hash (already random enough) */
    return sol_load_u64_le(p);
}

static bool
pubkey_eq(const void* a, const void* b) {
    return memcmp(a, b, SOL_PUBKEY_SIZE) == 0;
}

sol_pubkey_map_t*
sol_pubkey_map_new(size_t val_size, size_t capacity) {
    sol_pubkey_map_t* map = sol_alloc_t(sol_pubkey_map_t);
    if (map == NULL) {
        return NULL;
    }

    map->inner = sol_map_new(SOL_PUBKEY_SIZE, val_size, pubkey_hash, pubkey_eq, capacity);
    if (map->inner == NULL) {
        sol_free(map);
        return NULL;
    }

    return map;
}

void
sol_pubkey_map_destroy(sol_pubkey_map_t* map) {
    if (map != NULL) {
        sol_map_destroy(map->inner);
        sol_free(map);
    }
}

void*
sol_pubkey_map_insert(sol_pubkey_map_t* map, const sol_pubkey_t* key, const void* val) {
    if (map == NULL || key == NULL) {
        return NULL;
    }
    return sol_map_insert(map->inner, key->bytes, val);
}

void*
sol_pubkey_map_get(const sol_pubkey_map_t* map, const sol_pubkey_t* key) {
    if (map == NULL || key == NULL) {
        return NULL;
    }
    return sol_map_get(map->inner, key->bytes);
}

bool
sol_pubkey_map_remove(sol_pubkey_map_t* map, const sol_pubkey_t* key) {
    if (map == NULL || key == NULL) {
        return false;
    }
    return sol_map_remove(map->inner, key->bytes);
}
