/*
 * fd_bn254_compat.h - Compatibility shim for Firedancer BN254/Poseidon code
 *
 * Provides the minimal types and macros needed by Firedancer's bn254
 * and poseidon implementations without pulling in the full Firedancer
 * dependency tree.
 */

#ifndef FD_BN254_COMPAT_H
#define FD_BN254_COMPAT_H

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

/* Basic types used by Firedancer code */
typedef unsigned char  uchar;
typedef unsigned long  ulong;

/* 128-bit integer support */
#if defined(__SIZEOF_INT128__)
#define FD_HAS_INT128 1
typedef unsigned __int128 uint128;
#else
#define FD_HAS_INT128 0
#endif

/* x86 intrinsics */
#if defined(__x86_64__) || defined(_M_X64)
#define FD_HAS_X86 1
#else
#define FD_HAS_X86 0
#endif

/* GCC detection for optimization attributes */
#if defined(__GNUC__) && !defined(__clang__)
#define FD_USING_GCC 1
#else
#define FD_USING_GCC 0
#endif

/* AVX detection */
#ifdef __AVX2__
#define FD_HAS_AVX 1
#else
#define FD_HAS_AVX 0
#endif

#ifdef __AVX512F__
#define FD_HAS_AVX512 1
#else
#define FD_HAS_AVX512 0
#endif

/* Alignment */
#if FD_HAS_AVX512
#define FD_ALIGN (64UL)
#elif FD_HAS_AVX
#define FD_ALIGN (32UL)
#elif FD_HAS_INT128
#define FD_ALIGN (16UL)
#else
#define FD_ALIGN (8UL)
#endif
#define FD_ALIGNED __attribute__((aligned(FD_ALIGN)))

/* Branch prediction hints */
#define FD_LIKELY(x)   __builtin_expect(!!(x), 1)
#define FD_UNLIKELY(x) __builtin_expect(!!(x), 0)

/* extern "C" wrappers */
#ifdef __cplusplus
#define FD_PROTOTYPES_BEGIN extern "C" {
#define FD_PROTOTYPES_END   }
#else
#define FD_PROTOTYPES_BEGIN
#define FD_PROTOTYPES_END
#endif

/* Type punning helpers */
static inline void * fd_type_pun( void const * p ) {
  return (void *)p;
}
static inline void const * fd_type_pun_const( void const * p ) {
  return p;
}

/* Byte swap */
static inline ulong fd_ulong_bswap( ulong x ) {
  return __builtin_bswap64( x );
}

#endif /* FD_BN254_COMPAT_H */
