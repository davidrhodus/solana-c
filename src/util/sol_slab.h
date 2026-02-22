/*
 * sol_slab.h - Slab allocator for fixed-size objects
 *
 * Fast O(1) allocation/deallocation for objects of the same size.
 * Uses a freelist for recycling.
 */

#ifndef SOL_SLAB_H
#define SOL_SLAB_H

#include "sol_base.h"
#include "sol_err.h"

/*
 * Default slab size (64KB)
 */
#define SOL_SLAB_DEFAULT_CHUNK_SIZE (64 * 1024)

/*
 * Slab chunk (linked list of memory blocks)
 */
typedef struct sol_slab_chunk {
    struct sol_slab_chunk* next;
    size_t                 capacity;    /* Number of objects */
    size_t                 allocated;   /* Number allocated (for stats) */
    char                   data[];
} sol_slab_chunk_t;

/*
 * Free list node (overlaid on free objects)
 */
typedef struct sol_slab_free {
    struct sol_slab_free* next;
} sol_slab_free_t;

/*
 * Slab allocator
 */
typedef struct {
    sol_slab_chunk_t* chunks;        /* All chunks */
    sol_slab_free_t*  freelist;      /* Free objects */
    size_t            obj_size;      /* Size of each object */
    size_t            obj_align;     /* Alignment of objects */
    size_t            chunk_size;    /* Size for new chunks */
    size_t            total_objects; /* Total objects allocated */
    size_t            free_objects;  /* Objects in freelist */
} sol_slab_t;

/*
 * Create new slab allocator
 *
 * @param obj_size    Size of objects to allocate
 * @param obj_align   Alignment of objects (0 for default)
 * @param chunk_size  Size of memory chunks (0 for default)
 */
sol_slab_t* sol_slab_new(size_t obj_size, size_t obj_align, size_t chunk_size);

/* Create with defaults */
SOL_INLINE sol_slab_t*
sol_slab_new_default(size_t obj_size) {
    return sol_slab_new(obj_size, 0, 0);
}

/*
 * Destroy slab allocator
 */
void sol_slab_destroy(sol_slab_t* slab);

/*
 * Allocate object
 * Returns NULL on failure
 */
void* sol_slab_alloc(sol_slab_t* slab);

/*
 * Allocate and zero object
 */
void* sol_slab_calloc(sol_slab_t* slab);

/*
 * Free object back to slab
 */
void sol_slab_free(sol_slab_t* slab, void* ptr);

/*
 * Get statistics
 */
size_t sol_slab_total_objects(const sol_slab_t* slab);
size_t sol_slab_free_objects(const sol_slab_t* slab);
size_t sol_slab_used_objects(const sol_slab_t* slab);

/*
 * Typed allocation macro
 */
#define sol_slab_alloc_t(slab, T) ((T*)sol_slab_alloc(slab))

/*
 * Pre-allocate objects
 */
sol_err_t sol_slab_reserve(sol_slab_t* slab, size_t count);

/*
 * Shrink by releasing empty chunks
 */
void sol_slab_shrink(sol_slab_t* slab);

#endif /* SOL_SLAB_H */
