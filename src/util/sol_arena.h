/*
 * sol_arena.h - Arena (bump) allocator
 *
 * Fast allocation for temporary/scoped data. All allocations are freed
 * at once when the arena is reset or destroyed.
 */

#ifndef SOL_ARENA_H
#define SOL_ARENA_H

#include "sol_base.h"
#include "sol_err.h"

/*
 * Default arena size (1MB)
 */
#define SOL_ARENA_DEFAULT_SIZE (1024 * 1024)

/*
 * Arena chunk (linked list of memory blocks)
 */
typedef struct sol_arena_chunk {
    struct sol_arena_chunk* next;
    size_t                  size;      /* Total size of chunk */
    size_t                  used;      /* Bytes used */
    char                    data[];    /* Flexible array member */
} sol_arena_chunk_t;

/*
 * Arena allocator
 */
typedef struct {
    sol_arena_chunk_t*  head;          /* Current chunk */
    sol_arena_chunk_t*  chunks;        /* All chunks (for reset) */
    size_t              chunk_size;    /* Size for new chunks */
    size_t              total_alloc;   /* Total allocated bytes */
    size_t              peak_alloc;    /* Peak allocation */
} sol_arena_t;

/*
 * Create new arena
 */
sol_arena_t* sol_arena_new(size_t chunk_size);

/* Create with default size */
SOL_INLINE sol_arena_t*
sol_arena_new_default(void) {
    return sol_arena_new(SOL_ARENA_DEFAULT_SIZE);
}

/*
 * Destroy arena and free all memory
 */
void sol_arena_destroy(sol_arena_t* arena);

/*
 * Reset arena (free all allocations but keep chunks)
 */
void sol_arena_reset(sol_arena_t* arena);

/*
 * Allocate memory from arena (returns NULL on failure)
 */
void* sol_arena_alloc(sol_arena_t* arena, size_t size);

/*
 * Allocate aligned memory
 */
void* sol_arena_alloc_aligned(sol_arena_t* arena, size_t size, size_t align);

/*
 * Allocate and zero memory
 */
void* sol_arena_calloc(sol_arena_t* arena, size_t nmemb, size_t size);

/*
 * Duplicate string into arena
 */
char* sol_arena_strdup(sol_arena_t* arena, const char* s);

/*
 * Duplicate bytes into arena
 */
void* sol_arena_memdup(sol_arena_t* arena, const void* p, size_t len);

/*
 * Get allocation statistics
 */
size_t sol_arena_total_allocated(const sol_arena_t* arena);
size_t sol_arena_peak_allocated(const sol_arena_t* arena);

/*
 * Typed allocation macros
 */
#define sol_arena_alloc_t(arena, T) \
    ((T*)sol_arena_alloc_aligned((arena), sizeof(T), _Alignof(T)))

#define sol_arena_alloc_array(arena, T, n) \
    ((T*)sol_arena_alloc_aligned((arena), sizeof(T) * (n), _Alignof(T)))

/*
 * Checkpoint for partial reset
 */
typedef struct {
    sol_arena_chunk_t* chunk;
    size_t             used;
} sol_arena_checkpoint_t;

/* Save current position */
sol_arena_checkpoint_t sol_arena_checkpoint(const sol_arena_t* arena);

/* Restore to checkpoint (free everything allocated after) */
void sol_arena_restore(sol_arena_t* arena, sol_arena_checkpoint_t cp);

#endif /* SOL_ARENA_H */
