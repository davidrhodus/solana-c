/*
 * sol_bits.h - Bit manipulation utilities
 *
 * Fast bit operations using compiler intrinsics.
 */

#ifndef SOL_BITS_H
#define SOL_BITS_H

#include "sol_base.h"
#include <string.h>

/*
 * Count leading zeros
 */
SOL_INLINE unsigned int
sol_clz32(uint32_t x) {
    return x == 0 ? 32 : (unsigned int)__builtin_clz(x);
}

SOL_INLINE unsigned int
sol_clz64(uint64_t x) {
    return x == 0 ? 64 : (unsigned int)__builtin_clzll(x);
}

/*
 * Count trailing zeros
 */
SOL_INLINE unsigned int
sol_ctz32(uint32_t x) {
    return x == 0 ? 32 : (unsigned int)__builtin_ctz(x);
}

SOL_INLINE unsigned int
sol_ctz64(uint64_t x) {
    return x == 0 ? 64 : (unsigned int)__builtin_ctzll(x);
}

/*
 * Population count (number of set bits)
 */
SOL_INLINE unsigned int
sol_popcount32(uint32_t x) {
    return (unsigned int)__builtin_popcount(x);
}

SOL_INLINE unsigned int
sol_popcount64(uint64_t x) {
    return (unsigned int)__builtin_popcountll(x);
}

/*
 * Find first set bit (1-indexed, 0 if none)
 */
SOL_INLINE unsigned int
sol_ffs32(uint32_t x) {
    return (unsigned int)__builtin_ffs((int)x);
}

SOL_INLINE unsigned int
sol_ffs64(uint64_t x) {
    return (unsigned int)__builtin_ffsll((long long)x);
}

/*
 * Find last set bit (1-indexed, 0 if none)
 */
SOL_INLINE unsigned int
sol_fls32(uint32_t x) {
    return x == 0 ? 0 : 32 - sol_clz32(x);
}

SOL_INLINE unsigned int
sol_fls64(uint64_t x) {
    return x == 0 ? 0 : 64 - sol_clz64(x);
}

/*
 * Log base 2 (floor)
 */
SOL_INLINE unsigned int
sol_log2_32(uint32_t x) {
    return x == 0 ? 0 : 31 - sol_clz32(x);
}

SOL_INLINE unsigned int
sol_log2_64(uint64_t x) {
    return x == 0 ? 0 : 63 - sol_clz64(x);
}

/*
 * Round up to next power of 2
 */
SOL_INLINE uint32_t
sol_next_pow2_32(uint32_t x) {
    if (x == 0) return 1;
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    return x + 1;
}

SOL_INLINE uint64_t
sol_next_pow2_64(uint64_t x) {
    if (x == 0) return 1;
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    x |= x >> 32;
    return x + 1;
}

/*
 * Byte swap (endian conversion)
 */
SOL_INLINE uint16_t
sol_bswap16(uint16_t x) {
    return __builtin_bswap16(x);
}

SOL_INLINE uint32_t
sol_bswap32(uint32_t x) {
    return __builtin_bswap32(x);
}

SOL_INLINE uint64_t
sol_bswap64(uint64_t x) {
    return __builtin_bswap64(x);
}

/*
 * Host to little-endian (Solana uses little-endian)
 */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  define sol_htole16(x) (x)
#  define sol_htole32(x) (x)
#  define sol_htole64(x) (x)
#  define sol_le16toh(x) (x)
#  define sol_le32toh(x) (x)
#  define sol_le64toh(x) (x)
#  define sol_htobe16(x) sol_bswap16(x)
#  define sol_htobe32(x) sol_bswap32(x)
#  define sol_htobe64(x) sol_bswap64(x)
#  define sol_be16toh(x) sol_bswap16(x)
#  define sol_be32toh(x) sol_bswap32(x)
#  define sol_be64toh(x) sol_bswap64(x)
#else
#  define sol_htole16(x) sol_bswap16(x)
#  define sol_htole32(x) sol_bswap32(x)
#  define sol_htole64(x) sol_bswap64(x)
#  define sol_le16toh(x) sol_bswap16(x)
#  define sol_le32toh(x) sol_bswap32(x)
#  define sol_le64toh(x) sol_bswap64(x)
#  define sol_htobe16(x) (x)
#  define sol_htobe32(x) (x)
#  define sol_htobe64(x) (x)
#  define sol_be16toh(x) (x)
#  define sol_be32toh(x) (x)
#  define sol_be64toh(x) (x)
#endif

/*
 * Rotate left/right
 */
SOL_INLINE uint32_t
sol_rotl32(uint32_t x, unsigned int n) {
    return (x << n) | (x >> (32 - n));
}

SOL_INLINE uint32_t
sol_rotr32(uint32_t x, unsigned int n) {
    return (x >> n) | (x << (32 - n));
}

SOL_INLINE uint64_t
sol_rotl64(uint64_t x, unsigned int n) {
    return (x << n) | (x >> (64 - n));
}

SOL_INLINE uint64_t
sol_rotr64(uint64_t x, unsigned int n) {
    return (x >> n) | (x << (64 - n));
}

/*
 * Bit field extraction
 */
SOL_INLINE uint64_t
sol_bits_extract(uint64_t x, unsigned int start, unsigned int len) {
    return (x >> start) & ((1ULL << len) - 1);
}

SOL_INLINE uint64_t
sol_bits_insert(uint64_t x, uint64_t val, unsigned int start, unsigned int len) {
    uint64_t mask = ((1ULL << len) - 1) << start;
    return (x & ~mask) | ((val << start) & mask);
}

/*
 * Parity (1 if odd number of bits set)
 */
SOL_INLINE unsigned int
sol_parity32(uint32_t x) {
    return __builtin_parity(x);
}

SOL_INLINE unsigned int
sol_parity64(uint64_t x) {
    return __builtin_parityll(x);
}

/*
 * Bit scan for first/last set bit
 */
SOL_INLINE int
sol_bsf64(uint64_t x) {
    return x == 0 ? -1 : (int)sol_ctz64(x);
}

SOL_INLINE int
sol_bsr64(uint64_t x) {
    return x == 0 ? -1 : (int)(63 - sol_clz64(x));
}

/*
 * Unaligned memory access (for parsing)
 */
SOL_INLINE uint16_t
sol_load_u16_le(const void* p) {
    uint16_t v;
    memcpy(&v, p, sizeof(v));
    return sol_le16toh(v);
}

SOL_INLINE uint32_t
sol_load_u32_le(const void* p) {
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return sol_le32toh(v);
}

SOL_INLINE uint64_t
sol_load_u64_le(const void* p) {
    uint64_t v;
    memcpy(&v, p, sizeof(v));
    return sol_le64toh(v);
}

SOL_INLINE void
sol_store_u16_le(void* p, uint16_t v) {
    v = sol_htole16(v);
    memcpy(p, &v, sizeof(v));
}

SOL_INLINE void
sol_store_u32_le(void* p, uint32_t v) {
    v = sol_htole32(v);
    memcpy(p, &v, sizeof(v));
}

SOL_INLINE void
sol_store_u64_le(void* p, uint64_t v) {
    v = sol_htole64(v);
    memcpy(p, &v, sizeof(v));
}

#endif /* SOL_BITS_H */
