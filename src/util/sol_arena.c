/*
 * sol_arena.c - Arena allocator implementation
 */

#include "sol_arena.h"
#include "sol_alloc.h"
#include <string.h>

/*
 * Create new arena
 */
sol_arena_t*
sol_arena_new(size_t chunk_size) {
    if (chunk_size == 0) {
        chunk_size = SOL_ARENA_DEFAULT_SIZE;
    }

    sol_arena_t* arena = sol_alloc_t(sol_arena_t);
    if (arena == NULL) {
        return NULL;
    }

    /* Allocate first chunk */
    sol_arena_chunk_t* chunk = (sol_arena_chunk_t*)sol_alloc(
        sizeof(sol_arena_chunk_t) + chunk_size
    );
    if (chunk == NULL) {
        sol_free(arena);
        return NULL;
    }

    chunk->next = NULL;
    chunk->size = chunk_size;
    chunk->used = 0;

    arena->head = chunk;
    arena->chunks = chunk;
    arena->chunk_size = chunk_size;
    arena->total_alloc = 0;
    arena->peak_alloc = 0;

    return arena;
}

/*
 * Destroy arena
 */
void
sol_arena_destroy(sol_arena_t* arena) {
    if (arena == NULL) {
        return;
    }

    /* Free all chunks */
    sol_arena_chunk_t* chunk = arena->chunks;
    while (chunk != NULL) {
        sol_arena_chunk_t* next = chunk->next;
        sol_free(chunk);
        chunk = next;
    }

    sol_free(arena);
}

/*
 * Reset arena
 */
void
sol_arena_reset(sol_arena_t* arena) {
    if (arena == NULL) {
        return;
    }

    /* Reset all chunks */
    for (sol_arena_chunk_t* chunk = arena->chunks; chunk != NULL; chunk = chunk->next) {
        chunk->used = 0;
    }

    /* Set head back to first chunk */
    arena->head = arena->chunks;
    arena->total_alloc = 0;
}

/*
 * Allocate aligned memory
 */
void*
sol_arena_alloc_aligned(sol_arena_t* arena, size_t size, size_t align) {
    if (arena == NULL || size == 0) {
        return NULL;
    }

    /* Ensure alignment is at least sizeof(void*) */
    if (align < sizeof(void*)) {
        align = sizeof(void*);
    }

    sol_arena_chunk_t* chunk = arena->head;

    /* Calculate aligned offset */
    size_t offset = sol_align_up(chunk->used, align);
    size_t end = offset + size;

    /* Check if we need a new chunk */
    if (end > chunk->size) {
        /* Try next chunk in list */
        if (chunk->next != NULL && chunk->next->size >= size) {
            arena->head = chunk->next;
            chunk = arena->head;
            chunk->used = 0;
            offset = 0;
            end = size;
        } else {
            /* Need new chunk */
            size_t new_size = arena->chunk_size;
            if (size > new_size) {
                new_size = sol_align_up(size, 4096);  /* At least page-aligned */
            }

            sol_arena_chunk_t* new_chunk = (sol_arena_chunk_t*)sol_alloc(
                sizeof(sol_arena_chunk_t) + new_size
            );
            if (new_chunk == NULL) {
                return NULL;
            }

            new_chunk->next = chunk->next;
            new_chunk->size = new_size;
            new_chunk->used = 0;

            chunk->next = new_chunk;
            arena->head = new_chunk;
            chunk = new_chunk;
            offset = 0;
            end = size;
        }
    }

    void* ptr = chunk->data + offset;
    chunk->used = end;

    arena->total_alloc += size;
    if (arena->total_alloc > arena->peak_alloc) {
        arena->peak_alloc = arena->total_alloc;
    }

    return ptr;
}

/*
 * Allocate memory (default alignment)
 */
void*
sol_arena_alloc(sol_arena_t* arena, size_t size) {
    return sol_arena_alloc_aligned(arena, size, sizeof(void*));
}

/*
 * Allocate and zero memory
 */
void*
sol_arena_calloc(sol_arena_t* arena, size_t nmemb, size_t size) {
    /* Check for overflow */
    if (nmemb != 0 && size > SIZE_MAX / nmemb) {
        return NULL;
    }

    size_t total = nmemb * size;
    void* ptr = sol_arena_alloc(arena, total);
    if (ptr != NULL) {
        memset(ptr, 0, total);
    }
    return ptr;
}

/*
 * Duplicate string
 */
char*
sol_arena_strdup(sol_arena_t* arena, const char* s) {
    if (s == NULL) {
        return NULL;
    }

    size_t len = strlen(s) + 1;
    char* dup = (char*)sol_arena_alloc(arena, len);
    if (dup != NULL) {
        memcpy(dup, s, len);
    }
    return dup;
}

/*
 * Duplicate bytes
 */
void*
sol_arena_memdup(sol_arena_t* arena, const void* p, size_t len) {
    if (p == NULL || len == 0) {
        return NULL;
    }

    void* dup = sol_arena_alloc(arena, len);
    if (dup != NULL) {
        memcpy(dup, p, len);
    }
    return dup;
}

/*
 * Statistics
 */
size_t
sol_arena_total_allocated(const sol_arena_t* arena) {
    return arena != NULL ? arena->total_alloc : 0;
}

size_t
sol_arena_peak_allocated(const sol_arena_t* arena) {
    return arena != NULL ? arena->peak_alloc : 0;
}

/*
 * Checkpoint
 */
sol_arena_checkpoint_t
sol_arena_checkpoint(const sol_arena_t* arena) {
    sol_arena_checkpoint_t cp = { NULL, 0 };
    if (arena != NULL && arena->head != NULL) {
        cp.chunk = arena->head;
        cp.used = arena->head->used;
    }
    return cp;
}

void
sol_arena_restore(sol_arena_t* arena, sol_arena_checkpoint_t cp) {
    if (arena == NULL || cp.chunk == NULL) {
        return;
    }

    /* Reset chunks after checkpoint */
    for (sol_arena_chunk_t* chunk = cp.chunk->next; chunk != NULL; chunk = chunk->next) {
        chunk->used = 0;
    }

    /* Restore checkpoint chunk */
    cp.chunk->used = cp.used;
    arena->head = cp.chunk;

    /* Recalculate total_alloc */
    arena->total_alloc = 0;
    for (sol_arena_chunk_t* chunk = arena->chunks; chunk != cp.chunk; chunk = chunk->next) {
        arena->total_alloc += chunk->used;
    }
    arena->total_alloc += cp.used;
}
