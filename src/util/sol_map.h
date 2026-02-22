/*
 * sol_map.h - Hash map implementation
 *
 * Robin Hood hashing with backward shift deletion.
 * Supports arbitrary key/value types via macros.
 */

#ifndef SOL_MAP_H
#define SOL_MAP_H

#include "sol_base.h"
#include "sol_alloc.h"
#include "sol_hash_fn.h"
#include "sol_err.h"

/*
 * Map entry states (stored in control byte)
 */
#define SOL_MAP_EMPTY    0x00
#define SOL_MAP_DELETED  0x01  /* Tombstone (not used with backward shift) */
#define SOL_MAP_OCCUPIED 0x80  /* High bit set = occupied, low 7 bits = hash fragment */

/*
 * Default load factor (87.5%)
 */
#define SOL_MAP_MAX_LOAD_NUM   7
#define SOL_MAP_MAX_LOAD_DENOM 8

/*
 * Minimum capacity
 */
#define SOL_MAP_MIN_CAPACITY 8

/*
 * Generic map header
 */
typedef struct {
    size_t   size;        /* Number of entries */
    size_t   capacity;    /* Total slots (power of 2) */
    size_t   key_size;    /* Size of key type */
    size_t   val_size;    /* Size of value type */
    uint64_t (*hash)(const void* key);
    bool     (*eq)(const void* a, const void* b);
    uint8_t* ctrl;        /* Control bytes */
    void*    keys;        /* Key array */
    void*    vals;        /* Value array */
} sol_map_t;

/*
 * Create new map
 *
 * @param key_size  Size of key type
 * @param val_size  Size of value type
 * @param hash      Hash function for keys
 * @param eq        Equality function for keys
 * @param capacity  Initial capacity (0 for default)
 */
sol_map_t* sol_map_new(size_t key_size, size_t val_size,
                       uint64_t (*hash)(const void*),
                       bool (*eq)(const void*, const void*),
                       size_t capacity);

/*
 * Destroy map
 */
void sol_map_destroy(sol_map_t* map);

/*
 * Clear all entries
 */
void sol_map_clear(sol_map_t* map);

/*
 * Get number of entries
 */
SOL_INLINE size_t
sol_map_size(const sol_map_t* map) {
    return map != NULL ? map->size : 0;
}

/*
 * Check if empty
 */
SOL_INLINE bool
sol_map_is_empty(const sol_map_t* map) {
    return sol_map_size(map) == 0;
}

/*
 * Get capacity
 */
SOL_INLINE size_t
sol_map_capacity(const sol_map_t* map) {
    return map != NULL ? map->capacity : 0;
}

/*
 * Insert or update entry
 * Returns pointer to value slot
 */
void* sol_map_insert(sol_map_t* map, const void* key, const void* val);

/*
 * Look up entry
 * Returns pointer to value or NULL if not found
 */
void* sol_map_get(const sol_map_t* map, const void* key);

/*
 * Check if key exists
 */
bool sol_map_contains(const sol_map_t* map, const void* key);

/*
 * Remove entry
 * Returns true if key was found and removed
 */
bool sol_map_remove(sol_map_t* map, const void* key);

/*
 * Reserve capacity
 */
sol_err_t sol_map_reserve(sol_map_t* map, size_t capacity);

/*
 * Iterator
 */
typedef struct {
    const sol_map_t* map;
    size_t           index;
} sol_map_iter_t;

/* Initialize iterator */
sol_map_iter_t sol_map_iter(const sol_map_t* map);

/* Get next entry, returns false when done */
bool sol_map_iter_next(sol_map_iter_t* iter, void** key, void** val);

/*
 * Type-safe map macros
 */

/* Hash function for common types */
SOL_INLINE uint64_t sol_map_hash_u64(const void* p) { return sol_hash_u64(*(const uint64_t*)p); }
SOL_INLINE uint64_t sol_map_hash_ptr(const void* p) { return sol_hash_ptr(*(void* const*)p); }
SOL_INLINE uint64_t sol_map_hash_str(const void* p) { return sol_hash_bytes(*(const char* const*)p, strlen(*(const char* const*)p)); }

/* Equality functions for common types */
SOL_INLINE bool sol_map_eq_u64(const void* a, const void* b) { return *(const uint64_t*)a == *(const uint64_t*)b; }
SOL_INLINE bool sol_map_eq_ptr(const void* a, const void* b) { return *(void* const*)a == *(void* const*)b; }
SOL_INLINE bool sol_map_eq_str(const void* a, const void* b) { return strcmp(*(const char* const*)a, *(const char* const*)b) == 0; }

/* Create typed map */
#define SOL_MAP_NEW(K, V, hash_fn, eq_fn, cap) \
    sol_map_new(sizeof(K), sizeof(V), (hash_fn), (eq_fn), (cap))

/* Insert typed */
#define SOL_MAP_INSERT(map, K, V, key, val) do { \
    K _k = (key); \
    V _v = (val); \
    sol_map_insert((map), &_k, &_v); \
} while(0)

/* Get typed (returns pointer to V or NULL) */
#define SOL_MAP_GET(map, K, V, key) \
    ((V*)({ K _k = (key); sol_map_get((map), &_k); }))

/* Remove typed */
#define SOL_MAP_REMOVE(map, K, key) \
    ({ K _k = (key); sol_map_remove((map), &_k); })

/*
 * Specialized map for pubkey -> value
 * See sol_map.c for implementation - requires sol_types.h
 */
#ifdef SOL_TYPES_H  /* Only declare if sol_types.h was included first */

typedef struct {
    sol_map_t* inner;
} sol_pubkey_map_t;

sol_pubkey_map_t* sol_pubkey_map_new(size_t val_size, size_t capacity);
void              sol_pubkey_map_destroy(sol_pubkey_map_t* map);
void*             sol_pubkey_map_insert(sol_pubkey_map_t* map, const sol_pubkey_t* key, const void* val);
void*             sol_pubkey_map_get(const sol_pubkey_map_t* map, const sol_pubkey_t* key);
bool              sol_pubkey_map_remove(sol_pubkey_map_t* map, const sol_pubkey_t* key);

#endif /* SOL_TYPES_H */

#endif /* SOL_MAP_H */
