/*
 * sol_slab.c - Slab allocator implementation
 */

#include "sol_slab.h"
#include "sol_alloc.h"
#include <string.h>

/*
 * Create new slab allocator
 */
sol_slab_t*
sol_slab_new(size_t obj_size, size_t obj_align, size_t chunk_size) {
    /* Minimum object size to hold freelist pointer */
    if (obj_size < sizeof(sol_slab_free_t)) {
        obj_size = sizeof(sol_slab_free_t);
    }

    /* Default alignment */
    if (obj_align == 0) {
        obj_align = sizeof(void*);
    }

    /* Round object size up to alignment */
    obj_size = sol_align_up(obj_size, obj_align);

    /* Default chunk size */
    if (chunk_size == 0) {
        chunk_size = SOL_SLAB_DEFAULT_CHUNK_SIZE;
    }

    sol_slab_t* slab = sol_alloc_t(sol_slab_t);
    if (slab == NULL) {
        return NULL;
    }

    slab->chunks = NULL;
    slab->freelist = NULL;
    slab->obj_size = obj_size;
    slab->obj_align = obj_align;
    slab->chunk_size = chunk_size;
    slab->total_objects = 0;
    slab->free_objects = 0;

    return slab;
}

/*
 * Destroy slab allocator
 */
void
sol_slab_destroy(sol_slab_t* slab) {
    if (slab == NULL) {
        return;
    }

    /* Free all chunks */
    sol_slab_chunk_t* chunk = slab->chunks;
    while (chunk != NULL) {
        sol_slab_chunk_t* next = chunk->next;
        sol_free(chunk);
        chunk = next;
    }

    sol_free(slab);
}

/*
 * Add new chunk
 */
static sol_err_t
sol_slab_add_chunk(sol_slab_t* slab) {
    /* Calculate chunk capacity */
    size_t header_size = sol_align_up(sizeof(sol_slab_chunk_t), slab->obj_align);
    size_t data_size = slab->chunk_size - header_size;
    size_t capacity = data_size / slab->obj_size;

    if (capacity == 0) {
        /* Object too large for chunk, allocate exactly one */
        capacity = 1;
        data_size = slab->obj_size;
    }

    /* Allocate chunk */
    size_t alloc_size = header_size + capacity * slab->obj_size;
    sol_slab_chunk_t* chunk = (sol_slab_chunk_t*)sol_alloc_aligned(alloc_size, slab->obj_align);
    if (chunk == NULL) {
        return SOL_ERR_NOMEM;
    }

    chunk->next = slab->chunks;
    chunk->capacity = capacity;
    chunk->allocated = 0;
    slab->chunks = chunk;

    /* Add all objects to freelist */
    char* data = (char*)chunk + header_size;
    for (size_t i = 0; i < capacity; i++) {
        sol_slab_free_t* node = (sol_slab_free_t*)(data + i * slab->obj_size);
        node->next = slab->freelist;
        slab->freelist = node;
    }

    slab->total_objects += capacity;
    slab->free_objects += capacity;

    return SOL_OK;
}

/*
 * Allocate object
 */
void*
sol_slab_alloc(sol_slab_t* slab) {
    if (slab == NULL) {
        return NULL;
    }

    /* Check freelist */
    if (slab->freelist == NULL) {
        if (sol_slab_add_chunk(slab) != SOL_OK) {
            return NULL;
        }
    }

    /* Pop from freelist */
    sol_slab_free_t* node = slab->freelist;
    slab->freelist = node->next;
    slab->free_objects--;

    return node;
}

/*
 * Allocate and zero
 */
void*
sol_slab_calloc(sol_slab_t* slab) {
    void* ptr = sol_slab_alloc(slab);
    if (ptr != NULL) {
        memset(ptr, 0, slab->obj_size);
    }
    return ptr;
}

/*
 * Free object
 */
void
sol_slab_free(sol_slab_t* slab, void* ptr) {
    if (slab == NULL || ptr == NULL) {
        return;
    }

    /* Push to freelist */
    sol_slab_free_t* node = (sol_slab_free_t*)ptr;
    node->next = slab->freelist;
    slab->freelist = node;
    slab->free_objects++;
}

/*
 * Statistics
 */
size_t
sol_slab_total_objects(const sol_slab_t* slab) {
    return slab != NULL ? slab->total_objects : 0;
}

size_t
sol_slab_free_objects(const sol_slab_t* slab) {
    return slab != NULL ? slab->free_objects : 0;
}

size_t
sol_slab_used_objects(const sol_slab_t* slab) {
    if (slab == NULL) return 0;
    return slab->total_objects - slab->free_objects;
}

/*
 * Pre-allocate objects
 */
sol_err_t
sol_slab_reserve(sol_slab_t* slab, size_t count) {
    if (slab == NULL) {
        return SOL_ERR_INVAL;
    }

    while (slab->total_objects < count) {
        SOL_TRY(sol_slab_add_chunk(slab));
    }

    return SOL_OK;
}

/*
 * Shrink by releasing empty chunks
 *
 * Note: This is tricky because we can't easily tell which chunks
 * are completely free. For now, just skip if there are used objects.
 */
void
sol_slab_shrink(sol_slab_t* slab) {
    if (slab == NULL) {
        return;
    }

    /* Only shrink if all objects are free */
    if (slab->free_objects != slab->total_objects) {
        return;
    }

    /* Keep first chunk, free rest */
    if (slab->chunks != NULL) {
        sol_slab_chunk_t* keep = slab->chunks;
        sol_slab_chunk_t* chunk = keep->next;

        while (chunk != NULL) {
            sol_slab_chunk_t* next = chunk->next;
            slab->total_objects -= chunk->capacity;
            slab->free_objects -= chunk->capacity;
            sol_free(chunk);
            chunk = next;
        }

        keep->next = NULL;

        /* Rebuild freelist from remaining chunk */
        slab->freelist = NULL;
        size_t header_size = sol_align_up(sizeof(sol_slab_chunk_t), slab->obj_align);
        char* data = (char*)keep + header_size;
        for (size_t i = 0; i < keep->capacity; i++) {
            sol_slab_free_t* node = (sol_slab_free_t*)(data + i * slab->obj_size);
            node->next = slab->freelist;
            slab->freelist = node;
        }
    }
}
