/*
 * sol_alloc.h - Memory allocation wrapper
 *
 * Provides a unified allocation interface that uses jemalloc when available,
 * falling back to system malloc otherwise. Includes allocation tracking
 * and debugging facilities.
 */

#ifndef SOL_ALLOC_H
#define SOL_ALLOC_H

#include "sol_base.h"
#include "sol_err.h"

/*
 * Configuration
 */
#ifndef SOL_ALLOC_DEBUG
#  ifdef SOL_DEBUG
#    define SOL_ALLOC_DEBUG 1
#  else
#    define SOL_ALLOC_DEBUG 0
#  endif
#endif

/*
 * Basic allocation functions
 */

/* Allocate memory (returns NULL on failure) */
SOL_MALLOC SOL_ALLOC_SIZE(1) SOL_NODISCARD
void* sol_alloc(size_t size);

/* Allocate zeroed memory */
SOL_MALLOC SOL_ALLOC_SIZE(1, 2) SOL_NODISCARD
void* sol_calloc(size_t nmemb, size_t size);

/* Reallocate memory */
SOL_ALLOC_SIZE(2) SOL_NODISCARD
void* sol_realloc(void* ptr, size_t size);

/* Free memory */
void sol_free(void* ptr);

/* Allocate aligned memory */
SOL_MALLOC SOL_ALLOC_SIZE(1) SOL_NODISCARD
void* sol_alloc_aligned(size_t size, size_t alignment);

/* Free aligned memory (same as sol_free with jemalloc) */
void sol_free_aligned(void* ptr);

/*
 * Typed allocation macros
 */

/* Allocate single instance of type */
#define sol_alloc_t(T) ((T*)sol_alloc(sizeof(T)))

/* Allocate array of type */
#define sol_alloc_array(T, n) ((T*)sol_calloc((n), sizeof(T)))

/* Reallocate array of type */
#define sol_realloc_array(T, ptr, n) ((T*)sol_realloc((ptr), (n) * sizeof(T)))

/* Allocate cache-aligned */
#define sol_alloc_cache_aligned(size) sol_alloc_aligned((size), SOL_CACHE_LINE_SIZE)

/*
 * Allocation with error checking (returns error code)
 */

SOL_NODISCARD
sol_err_t sol_alloc_checked(size_t size, void** out);

SOL_NODISCARD
sol_err_t sol_calloc_checked(size_t nmemb, size_t size, void** out);

SOL_NODISCARD
sol_err_t sol_realloc_checked(void* ptr, size_t size, void** out);

/*
 * Size queries
 */

/* Get usable size of allocation (may be larger than requested) */
size_t sol_alloc_usable_size(void* ptr);

/*
 * Memory statistics
 */
typedef struct {
    size_t allocated;      /* Currently allocated bytes */
    size_t active;         /* Active bytes (including metadata) */
    size_t resident;       /* Resident memory */
    size_t mapped;         /* Mapped memory */
    size_t retained;       /* Retained for reuse */
    size_t alloc_count;    /* Number of allocations */
    size_t free_count;     /* Number of frees */
} sol_alloc_stats_t;

/* Get current allocation statistics */
void sol_alloc_stats(sol_alloc_stats_t* stats);

/* Print allocation stats to stderr */
void sol_alloc_stats_print(void);

/*
 * Memory management hints
 */

/* Release unused memory back to OS */
void sol_alloc_trim(void);

/* Flush thread cache (call before thread exit) */
void sol_alloc_thread_flush(void);

/*
 * Arena allocator for thread-local allocations
 */

/* Large page support (2MB huge pages) */
SOL_MALLOC SOL_ALLOC_SIZE(1) SOL_NODISCARD
void* sol_alloc_huge(size_t size);

void sol_free_huge(void* ptr, size_t size);

/*
 * Debug allocation (tracks allocation site)
 */
#if SOL_ALLOC_DEBUG

void* sol_alloc_debug(size_t size, const char* file, int line);
void* sol_calloc_debug(size_t nmemb, size_t size, const char* file, int line);
void* sol_realloc_debug(void* ptr, size_t size, const char* file, int line);
void  sol_free_debug(void* ptr, const char* file, int line);
void* sol_alloc_aligned_debug(size_t size, size_t alignment, const char* file, int line);
void  sol_free_aligned_debug(void* ptr, const char* file, int line);

#define sol_alloc(size)          sol_alloc_debug((size), __FILE__, __LINE__)
#define sol_calloc(nmemb, size)  sol_calloc_debug((nmemb), (size), __FILE__, __LINE__)
#define sol_realloc(ptr, size)   sol_realloc_debug((ptr), (size), __FILE__, __LINE__)
#define sol_free(ptr)            sol_free_debug((ptr), __FILE__, __LINE__)
#define sol_alloc_aligned(size, align) sol_alloc_aligned_debug((size), (align), __FILE__, __LINE__)
#define sol_free_aligned(ptr)    sol_free_aligned_debug((ptr), __FILE__, __LINE__)

/* Dump all outstanding allocations */
void sol_alloc_dump_leaks(void);

/* Check for memory corruption */
void sol_alloc_check_integrity(void);

#else

#define sol_alloc_dump_leaks()     ((void)0)
#define sol_alloc_check_integrity() ((void)0)

#endif /* SOL_ALLOC_DEBUG */

/*
 * Initialization (called automatically via constructor)
 */
void sol_alloc_init(void);
void sol_alloc_fini(void);

#endif /* SOL_ALLOC_H */
