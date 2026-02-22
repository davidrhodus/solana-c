/*
 * sol_alloc.c - Memory allocation implementation
 */

#include "sol_alloc.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef SOL_USE_JEMALLOC
#  include <jemalloc/jemalloc.h>
#  define REAL_MALLOC(size)          je_malloc(size)
#  define REAL_CALLOC(nmemb, size)   je_calloc(nmemb, size)
#  define REAL_REALLOC(ptr, size)    je_realloc(ptr, size)
#  define REAL_FREE(ptr)             je_free(ptr)
#  define REAL_ALIGNED_ALLOC(a, s)   je_aligned_alloc(a, s)
#  define REAL_USABLE_SIZE(ptr)      je_malloc_usable_size(ptr)
#else
#  define REAL_MALLOC(size)          malloc(size)
#  define REAL_CALLOC(nmemb, size)   calloc(nmemb, size)
#  define REAL_REALLOC(ptr, size)    realloc(ptr, size)
#  define REAL_FREE(ptr)             free(ptr)
#  define REAL_ALIGNED_ALLOC(a, s)   aligned_alloc(a, s)
#  ifdef __linux__
#    include <malloc.h>
#    define REAL_USABLE_SIZE(ptr)    malloc_usable_size(ptr)
#  elif defined(__APPLE__)
#    include <malloc/malloc.h>
#    define REAL_USABLE_SIZE(ptr)    malloc_size(ptr)
#  else
#    define REAL_USABLE_SIZE(ptr)    0
#  endif
#endif

#ifdef SOL_OS_LINUX
#  include <sys/mman.h>
#endif

/*
 * Global statistics (atomic for thread safety)
 */
static volatile size_t g_alloc_count = 0;
static volatile size_t g_free_count = 0;
static volatile size_t g_allocated_bytes = 0;

/*
 * Basic allocation functions (non-debug version)
 */

#if !SOL_ALLOC_DEBUG

void*
sol_alloc(size_t size) {
    if (sol_unlikely(size == 0)) {
        return NULL;
    }

    void* ptr = REAL_MALLOC(size);
    if (sol_likely(ptr != NULL)) {
        sol_atomic_add_relaxed(&g_alloc_count, 1);
        sol_atomic_add_relaxed(&g_allocated_bytes, REAL_USABLE_SIZE(ptr));
    }
    return ptr;
}

void*
sol_calloc(size_t nmemb, size_t size) {
    if (sol_unlikely(nmemb == 0 || size == 0)) {
        return NULL;
    }

    /* Check for overflow */
    if (sol_unlikely(nmemb > SIZE_MAX / size)) {
        return NULL;
    }

    void* ptr = REAL_CALLOC(nmemb, size);
    if (sol_likely(ptr != NULL)) {
        sol_atomic_add_relaxed(&g_alloc_count, 1);
        sol_atomic_add_relaxed(&g_allocated_bytes, REAL_USABLE_SIZE(ptr));
    }
    return ptr;
}

void*
sol_realloc(void* ptr, size_t size) {
    if (ptr == NULL) {
        return sol_alloc(size);
    }

    if (size == 0) {
        sol_free(ptr);
        return NULL;
    }

    size_t old_size = REAL_USABLE_SIZE(ptr);
    void* new_ptr = REAL_REALLOC(ptr, size);

    if (sol_likely(new_ptr != NULL)) {
        size_t new_size = REAL_USABLE_SIZE(new_ptr);
        /* Update allocated bytes delta */
        if (new_size > old_size) {
            sol_atomic_add_relaxed(&g_allocated_bytes, new_size - old_size);
        } else if (new_size < old_size) {
            sol_atomic_sub(&g_allocated_bytes, old_size - new_size);
        }
    }
    return new_ptr;
}

void
sol_free(void* ptr) {
    if (sol_unlikely(ptr == NULL)) {
        return;
    }

    size_t size = REAL_USABLE_SIZE(ptr);
    sol_atomic_add_relaxed(&g_free_count, 1);
    sol_atomic_sub(&g_allocated_bytes, size);

    REAL_FREE(ptr);
}

#endif /* !SOL_ALLOC_DEBUG */

void*
sol_alloc_aligned_impl(size_t size, size_t alignment) {
    if (sol_unlikely(size == 0)) {
        return NULL;
    }

    /* Alignment must be power of 2 and at least sizeof(void*) */
    if (!sol_is_power_of_2(alignment) || alignment < sizeof(void*)) {
        return NULL;
    }

    /* Size must be multiple of alignment */
    size = sol_align_up(size, alignment);

    void* ptr = REAL_ALIGNED_ALLOC(alignment, size);
    if (sol_likely(ptr != NULL)) {
        sol_atomic_add_relaxed(&g_alloc_count, 1);
        sol_atomic_add_relaxed(&g_allocated_bytes, REAL_USABLE_SIZE(ptr));
    }
    return ptr;
}

void
sol_free_aligned_impl(void* ptr) {
    if (sol_unlikely(ptr == NULL)) {
        return;
    }

    sol_atomic_add_relaxed(&g_free_count, 1);
    sol_atomic_sub(&g_allocated_bytes, REAL_USABLE_SIZE(ptr));

    REAL_FREE(ptr);
}

#if !SOL_ALLOC_DEBUG
void*
sol_alloc_aligned(size_t size, size_t alignment) {
    return sol_alloc_aligned_impl(size, alignment);
}

void
sol_free_aligned(void* ptr) {
    sol_free_aligned_impl(ptr);
}
#endif

/*
 * Checked allocation (returns error code)
 */

sol_err_t
sol_alloc_checked(size_t size, void** out) {
    SOL_CHECK_NONNULL(out);

    *out = sol_alloc(size);
    if (sol_unlikely(*out == NULL && size > 0)) {
        return SOL_ERR_NOMEM;
    }
    return SOL_OK;
}

sol_err_t
sol_calloc_checked(size_t nmemb, size_t size, void** out) {
    SOL_CHECK_NONNULL(out);

    *out = sol_calloc(nmemb, size);
    if (sol_unlikely(*out == NULL && nmemb > 0 && size > 0)) {
        return SOL_ERR_NOMEM;
    }
    return SOL_OK;
}

sol_err_t
sol_realloc_checked(void* ptr, size_t size, void** out) {
    SOL_CHECK_NONNULL(out);

    *out = sol_realloc(ptr, size);
    if (sol_unlikely(*out == NULL && size > 0)) {
        return SOL_ERR_NOMEM;
    }
    return SOL_OK;
}

/*
 * Size query
 */

size_t
sol_alloc_usable_size(void* ptr) {
    if (ptr == NULL) {
        return 0;
    }
    return REAL_USABLE_SIZE(ptr);
}

/*
 * Statistics
 */

void
sol_alloc_stats(sol_alloc_stats_t* stats) {
    if (stats == NULL) {
        return;
    }

    memset(stats, 0, sizeof(*stats));
    stats->alloc_count = sol_atomic_load_relaxed(&g_alloc_count);
    stats->free_count = sol_atomic_load_relaxed(&g_free_count);
    stats->allocated = sol_atomic_load_relaxed(&g_allocated_bytes);

#ifdef SOL_USE_JEMALLOC
    size_t sz = sizeof(size_t);

    size_t active = 0;
    je_mallctl("stats.active", &active, &sz, NULL, 0);
    stats->active = active;

    size_t resident = 0;
    je_mallctl("stats.resident", &resident, &sz, NULL, 0);
    stats->resident = resident;

    size_t mapped = 0;
    je_mallctl("stats.mapped", &mapped, &sz, NULL, 0);
    stats->mapped = mapped;

    size_t retained = 0;
    je_mallctl("stats.retained", &retained, &sz, NULL, 0);
    stats->retained = retained;
#endif
}

void
sol_alloc_stats_print(void) {
    sol_alloc_stats_t stats;
    sol_alloc_stats(&stats);

    fprintf(stderr, "=== Memory Statistics ===\n");
    fprintf(stderr, "  Allocations:  %zu\n", stats.alloc_count);
    fprintf(stderr, "  Frees:        %zu\n", stats.free_count);
    fprintf(stderr, "  Outstanding:  %zu\n", stats.alloc_count - stats.free_count);
    fprintf(stderr, "  Allocated:    %zu bytes\n", stats.allocated);
#ifdef SOL_USE_JEMALLOC
    fprintf(stderr, "  Active:       %zu bytes\n", stats.active);
    fprintf(stderr, "  Resident:     %zu bytes\n", stats.resident);
    fprintf(stderr, "  Mapped:       %zu bytes\n", stats.mapped);
    fprintf(stderr, "  Retained:     %zu bytes\n", stats.retained);
#endif
    fprintf(stderr, "========================\n");
}

/*
 * Memory management
 */

void
sol_alloc_trim(void) {
#ifdef SOL_USE_JEMALLOC
    /* Purge unused dirty pages */
    unsigned arena = MALLCTL_ARENAS_ALL;
    je_mallctl("arena.0.purge", NULL, NULL, &arena, sizeof(arena));
#elif defined(__GLIBC__)
    malloc_trim(0);
#endif
}

void
sol_alloc_thread_flush(void) {
#ifdef SOL_USE_JEMALLOC
    je_mallctl("thread.tcache.flush", NULL, NULL, NULL, 0);
#endif
}

/*
 * Huge page allocation
 */

void*
sol_alloc_huge(size_t size) {
#ifdef SOL_OS_LINUX
    /* Align to 2MB huge page boundary */
    size = sol_align_up(size, 2 * 1024 * 1024);

    void* ptr = mmap(NULL, size,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
                     -1, 0);

    if (ptr == MAP_FAILED) {
        /* Fallback to regular pages */
        ptr = mmap(NULL, size,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS,
                   -1, 0);

        if (ptr == MAP_FAILED) {
            return NULL;
        }

        /* Try to use transparent huge pages */
#ifdef MADV_HUGEPAGE
        madvise(ptr, size, MADV_HUGEPAGE);
#endif
    }

    return ptr;
#else
    /* macOS: just use regular allocation */
    return sol_alloc_aligned(size, 2 * 1024 * 1024);
#endif
}

void
sol_free_huge(void* ptr, size_t size) {
    if (ptr == NULL) {
        return;
    }

#ifdef SOL_OS_LINUX
    size = sol_align_up(size, 2 * 1024 * 1024);
    munmap(ptr, size);
#else
    sol_free_aligned(ptr);
    (void)size;
#endif
}

/*
 * Debug allocation tracking
 */

#if SOL_ALLOC_DEBUG

#include <pthread.h>

typedef struct alloc_record {
    void*                  ptr;
    size_t                 size;
    const char*            file;
    int                    line;
    struct alloc_record*   next;
} alloc_record_t;

static pthread_mutex_t g_alloc_lock = PTHREAD_MUTEX_INITIALIZER;
static alloc_record_t* g_alloc_list = NULL;

static void
record_alloc(void* ptr, size_t size, const char* file, int line) {
    if (ptr == NULL) return;

    alloc_record_t* rec = REAL_MALLOC(sizeof(alloc_record_t));
    if (rec == NULL) return;

    rec->ptr = ptr;
    rec->size = size;
    rec->file = file;
    rec->line = line;

    pthread_mutex_lock(&g_alloc_lock);
    rec->next = g_alloc_list;
    g_alloc_list = rec;
    pthread_mutex_unlock(&g_alloc_lock);
}

static void
remove_alloc(void* ptr, const char* file, int line) {
    if (ptr == NULL) return;

    pthread_mutex_lock(&g_alloc_lock);

    alloc_record_t** pp = &g_alloc_list;
    while (*pp != NULL) {
        if ((*pp)->ptr == ptr) {
            alloc_record_t* rec = *pp;
            *pp = rec->next;
            pthread_mutex_unlock(&g_alloc_lock);
            REAL_FREE(rec);
            return;
        }
        pp = &(*pp)->next;
    }

    pthread_mutex_unlock(&g_alloc_lock);

    /* Double free or invalid pointer */
    fprintf(stderr, "WARNING: Invalid free at %s:%d (ptr=%p)\n",
            file, line, ptr);
}

void*
sol_alloc_debug(size_t size, const char* file, int line) {
    void* ptr = REAL_MALLOC(size);
    record_alloc(ptr, size, file, line);

    if (ptr != NULL) {
        sol_atomic_add_relaxed(&g_alloc_count, 1);
        sol_atomic_add_relaxed(&g_allocated_bytes, REAL_USABLE_SIZE(ptr));
    }

    return ptr;
}

void*
sol_calloc_debug(size_t nmemb, size_t size, const char* file, int line) {
    void* ptr = REAL_CALLOC(nmemb, size);
    record_alloc(ptr, nmemb * size, file, line);

    if (ptr != NULL) {
        sol_atomic_add_relaxed(&g_alloc_count, 1);
        sol_atomic_add_relaxed(&g_allocated_bytes, REAL_USABLE_SIZE(ptr));
    }

    return ptr;
}

void*
sol_realloc_debug(void* ptr, size_t size, const char* file, int line) {
    if (ptr != NULL) {
        remove_alloc(ptr, file, line);
        sol_atomic_sub(&g_allocated_bytes, REAL_USABLE_SIZE(ptr));
    }

    void* new_ptr = REAL_REALLOC(ptr, size);
    record_alloc(new_ptr, size, file, line);

    if (new_ptr != NULL) {
        sol_atomic_add_relaxed(&g_allocated_bytes, REAL_USABLE_SIZE(new_ptr));
    }

    return new_ptr;
}

void
sol_free_debug(void* ptr, const char* file, int line) {
    if (ptr == NULL) return;

    remove_alloc(ptr, file, line);

    sol_atomic_add_relaxed(&g_free_count, 1);
    sol_atomic_sub(&g_allocated_bytes, REAL_USABLE_SIZE(ptr));

    REAL_FREE(ptr);
}

void*
sol_alloc_aligned_debug(size_t size, size_t alignment, const char* file, int line) {
    void* ptr = sol_alloc_aligned_impl(size, alignment);
    record_alloc(ptr, size, file, line);
    return ptr;
}

void
sol_free_aligned_debug(void* ptr, const char* file, int line) {
    if (ptr == NULL) return;

    remove_alloc(ptr, file, line);
    sol_free_aligned_impl(ptr);
}

void
sol_alloc_dump_leaks(void) {
    pthread_mutex_lock(&g_alloc_lock);

    size_t count = 0;
    size_t total_bytes = 0;

    fprintf(stderr, "\n=== Memory Leak Report ===\n");

    for (alloc_record_t* rec = g_alloc_list; rec != NULL; rec = rec->next) {
        fprintf(stderr, "  LEAK: %zu bytes at %p (%s:%d)\n",
                rec->size, rec->ptr, rec->file, rec->line);
        count++;
        total_bytes += rec->size;
    }

    if (count == 0) {
        fprintf(stderr, "  No leaks detected.\n");
    } else {
        fprintf(stderr, "  Total: %zu allocations, %zu bytes\n",
                count, total_bytes);
    }

    fprintf(stderr, "==========================\n\n");

    pthread_mutex_unlock(&g_alloc_lock);
}

void
sol_alloc_check_integrity(void) {
#ifdef SOL_USE_JEMALLOC
    /* jemalloc can detect heap corruption */
    je_malloc_stats_print(NULL, NULL, NULL);
#endif
}

#endif /* SOL_ALLOC_DEBUG */

/*
 * Initialization
 */

SOL_CONSTRUCTOR
void
sol_alloc_init(void) {
#ifdef SOL_USE_JEMALLOC
    /* Configure jemalloc for our use case */
    /* This is done via MALLOC_CONF environment variable typically */
#endif
}

SOL_DESTRUCTOR
void
sol_alloc_fini(void) {
#if SOL_ALLOC_DEBUG
    sol_alloc_dump_leaks();
#endif

    sol_alloc_trim();
}
