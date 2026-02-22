/*
 * sol_vec.h - Dynamic array (vector)
 *
 * Type-safe dynamic array using macros.
 */

#ifndef SOL_VEC_H
#define SOL_VEC_H

#include "sol_base.h"
#include "sol_alloc.h"
#include "sol_err.h"

/*
 * Vector header stored before data
 */
typedef struct {
    size_t len;        /* Number of elements */
    size_t cap;        /* Capacity (allocated elements) */
    size_t elem_size;  /* Size of each element */
} sol_vec_hdr_t;

/*
 * Get header from data pointer
 */
#define sol_vec_hdr(v) \
    ((sol_vec_hdr_t*)((char*)(v) - sizeof(sol_vec_hdr_t)))

/*
 * Create new vector
 */
#define sol_vec_new(T) \
    ((T*)sol_vec_new_impl(sizeof(T), 0))

#define sol_vec_new_cap(T, cap) \
    ((T*)sol_vec_new_impl(sizeof(T), (cap)))

/*
 * Free vector
 */
#define sol_vec_free(v) do { \
    if ((v) != NULL) { \
        sol_free(sol_vec_hdr(v)); \
        (v) = NULL; \
    } \
} while(0)

/*
 * Length and capacity
 */
#define sol_vec_len(v) \
    ((v) == NULL ? 0 : sol_vec_hdr(v)->len)

#define sol_vec_cap(v) \
    ((v) == NULL ? 0 : sol_vec_hdr(v)->cap)

#define sol_vec_is_empty(v) \
    (sol_vec_len(v) == 0)

/*
 * Reserve capacity
 */
#define sol_vec_reserve(v, n) do { \
    size_t _n = (n); \
    if ((v) == NULL) { \
        (v) = sol_vec_new_impl(sizeof(*(v)), _n); \
    } else if (_n > sol_vec_cap(v)) { \
        (v) = sol_vec_grow_impl((v), _n); \
    } \
} while(0)

/*
 * Resize to exact length
 */
#define sol_vec_resize(v, n) do { \
    sol_vec_reserve((v), (n)); \
    if ((v) != NULL) sol_vec_hdr(v)->len = (n); \
} while(0)

/*
 * Clear (set length to 0, keep capacity)
 */
#define sol_vec_clear(v) do { \
    if ((v) != NULL) sol_vec_hdr(v)->len = 0; \
} while(0)

/*
 * Push element to back
 */
#define sol_vec_push(v, elem) do { \
    sol_vec_maybe_grow((v), 1); \
    (v)[sol_vec_hdr(v)->len++] = (elem); \
} while(0)

/*
 * Pop element from back
 */
#define sol_vec_pop(v) \
    ((v)[--sol_vec_hdr(v)->len])

/*
 * Get last element
 */
#define sol_vec_last(v) \
    ((v)[sol_vec_hdr(v)->len - 1])

/*
 * Get first element
 */
#define sol_vec_first(v) \
    ((v)[0])

/*
 * Insert at index
 */
#define sol_vec_insert(v, idx, elem) do { \
    size_t _idx = (idx); \
    sol_vec_maybe_grow((v), 1); \
    sol_vec_hdr_t* _h = sol_vec_hdr(v); \
    if (_idx < _h->len) { \
        memmove(&(v)[_idx + 1], &(v)[_idx], (_h->len - _idx) * sizeof(*(v))); \
    } \
    (v)[_idx] = (elem); \
    _h->len++; \
} while(0)

/*
 * Remove at index
 */
#define sol_vec_remove(v, idx) do { \
    size_t _idx = (idx); \
    sol_vec_hdr_t* _h = sol_vec_hdr(v); \
    if (_idx < _h->len - 1) { \
        memmove(&(v)[_idx], &(v)[_idx + 1], (_h->len - _idx - 1) * sizeof(*(v))); \
    } \
    _h->len--; \
} while(0)

/*
 * Remove by swapping with last (O(1) but doesn't preserve order)
 */
#define sol_vec_swap_remove(v, idx) do { \
    size_t _idx = (idx); \
    sol_vec_hdr_t* _h = sol_vec_hdr(v); \
    _h->len--; \
    if (_idx < _h->len) { \
        (v)[_idx] = (v)[_h->len]; \
    } \
} while(0)

/*
 * Append another vector
 */
#define sol_vec_append(v, other, count) do { \
    size_t _count = (count); \
    sol_vec_maybe_grow((v), _count); \
    memcpy(&(v)[sol_vec_hdr(v)->len], (other), _count * sizeof(*(v))); \
    sol_vec_hdr(v)->len += _count; \
} while(0)

/*
 * Iterate over vector
 */
#define sol_vec_foreach(v, iter) \
    for (size_t iter = 0; iter < sol_vec_len(v); iter++)

#define sol_vec_foreach_ptr(v, ptr) \
    for (__typeof__(v) ptr = (v); ptr < (v) + sol_vec_len(v); ptr++)

/*
 * Shrink capacity to fit length
 */
#define sol_vec_shrink(v) do { \
    if ((v) != NULL && sol_vec_cap(v) > sol_vec_len(v)) { \
        (v) = sol_vec_shrink_impl(v); \
    } \
} while(0)

/*
 * Internal: maybe grow to accommodate n more elements
 */
#define sol_vec_maybe_grow(v, n) do { \
    size_t _n = (n); \
    if ((v) == NULL) { \
        (v) = sol_vec_new_impl(sizeof(*(v)), _n); \
    } else if (sol_vec_hdr(v)->len + _n > sol_vec_cap(v)) { \
        (v) = sol_vec_grow_impl((v), sol_vec_hdr(v)->len + _n); \
    } \
} while(0)

/*
 * Implementation functions
 */

SOL_INLINE void*
sol_vec_new_impl(size_t elem_size, size_t cap) {
    if (cap == 0) cap = 8;  /* Default initial capacity */

    size_t size = sizeof(sol_vec_hdr_t) + elem_size * cap;
    sol_vec_hdr_t* hdr = (sol_vec_hdr_t*)sol_alloc(size);

    if (hdr == NULL) return NULL;

    hdr->len = 0;
    hdr->cap = cap;
    hdr->elem_size = elem_size;

    return (char*)hdr + sizeof(sol_vec_hdr_t);
}

SOL_INLINE void*
sol_vec_grow_impl(void* v, size_t min_cap) {
    sol_vec_hdr_t* hdr = sol_vec_hdr(v);

    /* Grow by 1.5x or to min_cap, whichever is larger */
    size_t new_cap = hdr->cap + (hdr->cap >> 1);
    if (new_cap < min_cap) new_cap = min_cap;

    size_t size = sizeof(sol_vec_hdr_t) + hdr->elem_size * new_cap;
    sol_vec_hdr_t* new_hdr = (sol_vec_hdr_t*)sol_realloc(hdr, size);

    if (new_hdr == NULL) return v;  /* Keep old on failure */

    new_hdr->cap = new_cap;
    return (char*)new_hdr + sizeof(sol_vec_hdr_t);
}

SOL_INLINE void*
sol_vec_shrink_impl(void* v) {
    sol_vec_hdr_t* hdr = sol_vec_hdr(v);

    size_t new_cap = hdr->len;
    if (new_cap == 0) new_cap = 1;

    size_t size = sizeof(sol_vec_hdr_t) + hdr->elem_size * new_cap;
    sol_vec_hdr_t* new_hdr = (sol_vec_hdr_t*)sol_realloc(hdr, size);

    if (new_hdr == NULL) return v;

    new_hdr->cap = new_cap;
    return (char*)new_hdr + sizeof(sol_vec_hdr_t);
}

#endif /* SOL_VEC_H */
