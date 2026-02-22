/*
 * sol_base.h - Compiler macros, attributes, and fundamental definitions
 *
 * This header provides portable compiler intrinsics, attributes, and
 * basic macros used throughout the codebase.
 */

#ifndef SOL_BASE_H
#define SOL_BASE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdnoreturn.h>
#include <assert.h>

/*
 * Compiler detection
 */
#if defined(__GNUC__) && !defined(__clang__)
#  define SOL_COMPILER_GCC 1
#elif defined(__clang__)
#  define SOL_COMPILER_CLANG 1
#else
#  error "Unsupported compiler - requires GCC or Clang"
#endif

#define SOL_GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)

/*
 * Architecture detection
 * Production target is x86_64, but allow ARM64 for development
 */
#if defined(__x86_64__) || defined(_M_X64)
#  define SOL_ARCH_X86_64 1
#elif defined(__aarch64__) || defined(_M_ARM64)
#  define SOL_ARCH_ARM64 1
#else
#  error "Unsupported architecture - requires x86_64 or arm64"
#endif

/*
 * OS detection
 */
#if defined(__linux__)
#  define SOL_OS_LINUX 1
#elif defined(__APPLE__)
#  define SOL_OS_MACOS 1
#else
#  error "Unsupported OS - requires Linux or macOS"
#endif

/*
 * Function attributes
 */

/* Function never returns */
#define SOL_NORETURN noreturn

/* Function has no side effects, result depends only on arguments */
#define SOL_PURE __attribute__((pure))

/* Function has no side effects, result depends only on arguments, no pointer derefs */
#define SOL_CONST __attribute__((const))

/* Function should always be inlined */
#define SOL_INLINE static inline __attribute__((always_inline))

/* Function should never be inlined */
#define SOL_NOINLINE __attribute__((noinline))

/* Function is performance critical - optimize aggressively */
#define SOL_HOT __attribute__((hot))

/* Function is rarely called */
#define SOL_COLD __attribute__((cold))

/* Warn if return value is unused */
#define SOL_NODISCARD __attribute__((warn_unused_result))

/* Function does not return null */
#define SOL_NONNULL_RETURN __attribute__((returns_nonnull))

/* Specific arguments must not be null */
#define SOL_NONNULL(...) __attribute__((nonnull(__VA_ARGS__)))

/* Function uses printf-style format string */
#define SOL_PRINTF_FMT(fmt_idx, first_arg) __attribute__((format(printf, fmt_idx, first_arg)))

/* Function is deprecated */
#define SOL_DEPRECATED(msg) __attribute__((deprecated(msg)))

/* Function is a constructor (runs before main) */
#define SOL_CONSTRUCTOR __attribute__((constructor))

/* Function is a destructor (runs after main) */
#define SOL_DESTRUCTOR __attribute__((destructor))

/* Malloc-like function (returns new unaliased pointer) */
#define SOL_MALLOC __attribute__((malloc))

/* Specify allocation size for malloc-like functions */
#define SOL_ALLOC_SIZE(...) __attribute__((alloc_size(__VA_ARGS__)))

/*
 * Variable/type attributes
 */

/* Variable is unused (suppress warnings) */
#define SOL_UNUSED __attribute__((unused))

/* Specify alignment */
#define SOL_ALIGNED(n) __attribute__((aligned(n)))

/* Cache line alignment (64 bytes on x86_64) */
#define SOL_CACHE_ALIGNED SOL_ALIGNED(64)
#define SOL_CACHE_LINE_SIZE 64

/* Pack structure with no padding */
#define SOL_PACKED __attribute__((packed))

/* Variable should be in thread-local storage */
#define SOL_THREAD_LOCAL _Thread_local

/*
 * Branch prediction hints
 */
#define sol_likely(x)   __builtin_expect(!!(x), 1)
#define sol_unlikely(x) __builtin_expect(!!(x), 0)

/*
 * Prefetch hints
 */
#define sol_prefetch_read(addr)       __builtin_prefetch((addr), 0, 3)
#define sol_prefetch_write(addr)      __builtin_prefetch((addr), 1, 3)
#define sol_prefetch_read_nta(addr)   __builtin_prefetch((addr), 0, 0)
#define sol_prefetch_write_nta(addr)  __builtin_prefetch((addr), 1, 0)

/*
 * Unreachable code hint
 */
#define sol_unreachable() __builtin_unreachable()

/*
 * Trap / abort
 */
#define sol_trap() __builtin_trap()

/*
 * Static assertions
 */
#define SOL_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)

/*
 * Compile-time size checks
 */
#define SOL_ASSERT_SIZE(type, size) \
    SOL_STATIC_ASSERT(sizeof(type) == (size), "Size mismatch for " #type)

#define SOL_ASSERT_ALIGNMENT(type, align) \
    SOL_STATIC_ASSERT(_Alignof(type) == (align), "Alignment mismatch for " #type)

/*
 * Array length macro
 */
#define SOL_ARRAY_LEN(arr) (sizeof(arr) / sizeof((arr)[0]))

/*
 * Min/Max macros (type-safe with GNU extension)
 */
#define sol_min(a, b) \
    ({ __typeof__(a) _a = (a); __typeof__(b) _b = (b); _a < _b ? _a : _b; })

#define sol_max(a, b) \
    ({ __typeof__(a) _a = (a); __typeof__(b) _b = (b); _a > _b ? _a : _b; })

#define sol_clamp(x, lo, hi) sol_min(sol_max(x, lo), hi)

/*
 * Swap macro
 */
#define sol_swap(a, b) \
    do { __typeof__(a) _tmp = (a); (a) = (b); (b) = _tmp; } while(0)

/*
 * Stringify macros
 */
#define SOL_STRINGIFY(x) #x
#define SOL_STRINGIFY_EXPAND(x) SOL_STRINGIFY(x)

/*
 * Concatenation macros
 */
#define SOL_CONCAT(a, b) a##b
#define SOL_CONCAT_EXPAND(a, b) SOL_CONCAT(a, b)

/*
 * Unique identifier generation
 */
#define SOL_UNIQUE_ID(prefix) SOL_CONCAT_EXPAND(prefix, __COUNTER__)

/*
 * Offset of field in struct
 */
#define sol_offsetof(type, member) __builtin_offsetof(type, member)

/*
 * Container of - get struct pointer from member pointer
 */
#define sol_container_of(ptr, type, member) \
    ((type*)((char*)(ptr) - sol_offsetof(type, member)))

/*
 * Memory barriers
 */
#define sol_compiler_barrier() __asm__ __volatile__("" ::: "memory")
#define sol_memory_barrier()   __sync_synchronize()
#define sol_load_acquire(ptr)  __atomic_load_n((ptr), __ATOMIC_ACQUIRE)
#define sol_store_release(ptr, val) __atomic_store_n((ptr), (val), __ATOMIC_RELEASE)

/*
 * Atomics (C11 style wrappers)
 */
#define sol_atomic_load(ptr)           __atomic_load_n((ptr), __ATOMIC_SEQ_CST)
#define sol_atomic_store(ptr, val)     __atomic_store_n((ptr), (val), __ATOMIC_SEQ_CST)
#define sol_atomic_add(ptr, val)       __atomic_fetch_add((ptr), (val), __ATOMIC_SEQ_CST)
#define sol_atomic_sub(ptr, val)       __atomic_fetch_sub((ptr), (val), __ATOMIC_SEQ_CST)
#define sol_atomic_and(ptr, val)       __atomic_fetch_and((ptr), (val), __ATOMIC_SEQ_CST)
#define sol_atomic_or(ptr, val)        __atomic_fetch_or((ptr), (val), __ATOMIC_SEQ_CST)
#define sol_atomic_xor(ptr, val)       __atomic_fetch_xor((ptr), (val), __ATOMIC_SEQ_CST)
#define sol_atomic_cas(ptr, expected, desired) \
    __atomic_compare_exchange_n((ptr), (expected), (desired), false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#define sol_atomic_exchange(ptr, val)  __atomic_exchange_n((ptr), (val), __ATOMIC_SEQ_CST)

/*
 * Relaxed atomics (for counters, etc.)
 */
#define sol_atomic_load_relaxed(ptr)       __atomic_load_n((ptr), __ATOMIC_RELAXED)
#define sol_atomic_store_relaxed(ptr, val) __atomic_store_n((ptr), (val), __ATOMIC_RELAXED)
#define sol_atomic_add_relaxed(ptr, val)   __atomic_fetch_add((ptr), (val), __ATOMIC_RELAXED)

/*
 * Alignment helpers
 */
#define sol_is_aligned(ptr, align) (((uintptr_t)(ptr) & ((align) - 1)) == 0)
#define sol_align_up(x, align)     (((x) + ((align) - 1)) & ~((align) - 1))
#define sol_align_down(x, align)   ((x) & ~((align) - 1))

/*
 * Power of 2 check
 */
#define sol_is_power_of_2(x) (((x) != 0) && (((x) & ((x) - 1)) == 0))

/*
 * Debug assertions
 */
#ifdef SOL_DEBUG
#  define sol_assert(cond) assert(cond)
#  define sol_debug_assert(cond) assert(cond)
#else
#  define sol_assert(cond) \
      do { if (sol_unlikely(!(cond))) sol_unreachable(); } while(0)
#  define sol_debug_assert(cond) ((void)0)
#endif

/*
 * Sanity check that will always run (even in release)
 */
#define sol_check(cond) \
    do { if (sol_unlikely(!(cond))) sol_trap(); } while(0)

/*
 * Version encoding
 */
#define SOL_VERSION_ENCODE(major, minor, patch) \
    (((major) << 16) | ((minor) << 8) | (patch))

#define SOL_VERSION SOL_VERSION_ENCODE(0, 1, 0)

#endif /* SOL_BASE_H */
