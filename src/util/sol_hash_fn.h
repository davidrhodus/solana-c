/*
 * sol_hash_fn.h - Non-cryptographic hash functions
 *
 * Fast hash functions for hash tables and bloom filters.
 * These are NOT cryptographically secure.
 */

#ifndef SOL_HASH_FN_H
#define SOL_HASH_FN_H

#include "sol_base.h"
#include "sol_bits.h"

/* 128-bit type for wide multiply */
typedef __uint128_t sol_uint128;

/*
 * wyhash - fast, high quality hash
 * https://github.com/wangyi-fudan/wyhash
 */

static const uint64_t WY_P0 = 0xa0761d6478bd642fULL;
static const uint64_t WY_P1 = 0xe7037ed1a0b428dbULL;
static const uint64_t WY_P2 = 0x8ebc6af09c88c6e3ULL;
static const uint64_t WY_P3 = 0x589965cc75374cc3ULL;

SOL_INLINE uint64_t
wymix(uint64_t a, uint64_t b) {
    sol_uint128 r = (sol_uint128)a * b;
    return (uint64_t)r ^ (uint64_t)(r >> 64);
}

SOL_INLINE uint64_t
wyread8(const uint8_t* p) {
    uint64_t v;
    memcpy(&v, p, 8);
    return v;
}

SOL_INLINE uint64_t
wyread4(const uint8_t* p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

SOL_INLINE uint64_t
wyread3(const uint8_t* p, size_t k) {
    return ((uint64_t)p[0] << 16) | ((uint64_t)p[k >> 1] << 8) | p[k - 1];
}

SOL_INLINE uint64_t
sol_wyhash(const void* key, size_t len, uint64_t seed) {
    const uint8_t* p = (const uint8_t*)key;
    uint64_t a, b;

    if (sol_likely(len <= 16)) {
        if (sol_likely(len >= 4)) {
            a = (wyread4(p) << 32) | wyread4(p + ((len >> 3) << 2));
            b = (wyread4(p + len - 4) << 32) | wyread4(p + len - 4 - ((len >> 3) << 2));
        } else if (sol_likely(len > 0)) {
            a = wyread3(p, len);
            b = 0;
        } else {
            a = b = 0;
        }
    } else {
        size_t i = len;
        if (sol_unlikely(i > 48)) {
            uint64_t see1 = seed, see2 = seed;
            do {
                seed = wymix(wyread8(p) ^ WY_P1, wyread8(p + 8) ^ seed);
                see1 = wymix(wyread8(p + 16) ^ WY_P2, wyread8(p + 24) ^ see1);
                see2 = wymix(wyread8(p + 32) ^ WY_P3, wyread8(p + 40) ^ see2);
                p += 48;
                i -= 48;
            } while (sol_likely(i > 48));
            seed ^= see1 ^ see2;
        }
        while (sol_unlikely(i > 16)) {
            seed = wymix(wyread8(p) ^ WY_P1, wyread8(p + 8) ^ seed);
            i -= 16;
            p += 16;
        }
        a = wyread8(p + i - 16);
        b = wyread8(p + i - 8);
    }

    return wymix(WY_P1 ^ len, wymix(a ^ WY_P1, b ^ seed));
}

/*
 * xxHash64 - another high quality hash
 */

#define XXH_PRIME64_1  0x9E3779B185EBCA87ULL
#define XXH_PRIME64_2  0xC2B2AE3D27D4EB4FULL
#define XXH_PRIME64_3  0x165667B19E3779F9ULL
#define XXH_PRIME64_4  0x85EBCA77C2B2AE63ULL
#define XXH_PRIME64_5  0x27D4EB2F165667C5ULL

SOL_INLINE uint64_t
xxh64_round(uint64_t acc, uint64_t input) {
    acc += input * XXH_PRIME64_2;
    acc = sol_rotl64(acc, 31);
    acc *= XXH_PRIME64_1;
    return acc;
}

SOL_INLINE uint64_t
xxh64_merge_round(uint64_t acc, uint64_t val) {
    val = xxh64_round(0, val);
    acc ^= val;
    acc = acc * XXH_PRIME64_1 + XXH_PRIME64_4;
    return acc;
}

SOL_INLINE uint64_t
xxh64_avalanche(uint64_t h64) {
    h64 ^= h64 >> 33;
    h64 *= XXH_PRIME64_2;
    h64 ^= h64 >> 29;
    h64 *= XXH_PRIME64_3;
    h64 ^= h64 >> 32;
    return h64;
}

SOL_INLINE uint64_t
sol_xxhash64(const void* input, size_t len, uint64_t seed) {
    const uint8_t* p = (const uint8_t*)input;
    const uint8_t* const end = p + len;
    uint64_t h64;

    if (len >= 32) {
        const uint8_t* const limit = end - 32;
        uint64_t v1 = seed + XXH_PRIME64_1 + XXH_PRIME64_2;
        uint64_t v2 = seed + XXH_PRIME64_2;
        uint64_t v3 = seed + 0;
        uint64_t v4 = seed - XXH_PRIME64_1;

        do {
            uint64_t k1, k2, k3, k4;
            memcpy(&k1, p, 8); p += 8;
            memcpy(&k2, p, 8); p += 8;
            memcpy(&k3, p, 8); p += 8;
            memcpy(&k4, p, 8); p += 8;

            v1 = xxh64_round(v1, k1);
            v2 = xxh64_round(v2, k2);
            v3 = xxh64_round(v3, k3);
            v4 = xxh64_round(v4, k4);
        } while (p <= limit);

        h64 = sol_rotl64(v1, 1) + sol_rotl64(v2, 7) +
              sol_rotl64(v3, 12) + sol_rotl64(v4, 18);
        h64 = xxh64_merge_round(h64, v1);
        h64 = xxh64_merge_round(h64, v2);
        h64 = xxh64_merge_round(h64, v3);
        h64 = xxh64_merge_round(h64, v4);
    } else {
        h64 = seed + XXH_PRIME64_5;
    }

    h64 += (uint64_t)len;

    while (p + 8 <= end) {
        uint64_t k1;
        memcpy(&k1, p, 8);
        k1 *= XXH_PRIME64_2;
        k1 = sol_rotl64(k1, 31);
        k1 *= XXH_PRIME64_1;
        h64 ^= k1;
        h64 = sol_rotl64(h64, 27) * XXH_PRIME64_1 + XXH_PRIME64_4;
        p += 8;
    }

    if (p + 4 <= end) {
        uint32_t k1;
        memcpy(&k1, p, 4);
        h64 ^= (uint64_t)k1 * XXH_PRIME64_1;
        h64 = sol_rotl64(h64, 23) * XXH_PRIME64_2 + XXH_PRIME64_3;
        p += 4;
    }

    while (p < end) {
        h64 ^= (*p++) * XXH_PRIME64_5;
        h64 = sol_rotl64(h64, 11) * XXH_PRIME64_1;
    }

    return xxh64_avalanche(h64);
}

/*
 * Convenience functions
 */

/* Hash a 64-bit integer */
SOL_INLINE uint64_t
sol_hash_u64(uint64_t x) {
    /* Splitmix64 */
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

/* Hash a pointer */
SOL_INLINE uint64_t
sol_hash_ptr(const void* p) {
    return sol_hash_u64((uintptr_t)p);
}

/* Hash bytes (default to wyhash) */
SOL_INLINE uint64_t
sol_hash_bytes(const void* data, size_t len) {
    return sol_wyhash(data, len, 0);
}

/* Hash bytes with seed */
SOL_INLINE uint64_t
sol_hash_bytes_seed(const void* data, size_t len, uint64_t seed) {
    return sol_wyhash(data, len, seed);
}

/* Combine two hashes */
SOL_INLINE uint64_t
sol_hash_combine(uint64_t h1, uint64_t h2) {
    return wymix(h1, h2);
}

#endif /* SOL_HASH_FN_H */
