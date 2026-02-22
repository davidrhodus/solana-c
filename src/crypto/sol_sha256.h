/*
 * sol_sha256.h - SHA-256 hash function
 *
 * Production-quality SHA-256 implementation.
 * Uses OpenSSL when available, otherwise pure C implementation.
 */

#ifndef SOL_SHA256_H
#define SOL_SHA256_H

#include "../util/sol_base.h"
#include "../util/sol_err.h"
#include <string.h>

/*
 * SHA-256 constants
 */
#define SOL_SHA256_HASH_SIZE   32
#define SOL_SHA256_BLOCK_SIZE  64

/*
 * SHA-256 hash output
 */
typedef struct SOL_ALIGNED(32) {
    uint8_t bytes[SOL_SHA256_HASH_SIZE];
} sol_sha256_t;

/*
 * SHA-256 context for incremental hashing
 */
typedef struct {
    uint32_t state[8];      /* Hash state */
    uint64_t count;         /* Number of bits processed */
    uint8_t  buffer[64];    /* Pending data buffer */
} sol_sha256_ctx_t;

/*
 * One-shot hash functions
 */

/* Hash data and return result */
void sol_sha256(const void* data, size_t len, sol_sha256_t* out);

/*
 * Specialized SHA-256 for a 32-byte message.
 *
 * This is a hot-path primitive for PoH-style hashing (`hash = sha256(hash)`),
 * where the input is always 32 bytes and the output is a 32-byte digest.
 *
 * Supports `in == out`.
 */
void sol_sha256_32bytes(const uint8_t in[static 32], uint8_t out[static 32]);

/* Hash data and return result (convenience returning pointer) */
sol_sha256_t* sol_sha256_hash(const void* data, size_t len, sol_sha256_t* out);

/* Hash multiple buffers (scatter-gather) */
void sol_sha256_multi(
    const void* const* data,
    const size_t*      lens,
    size_t             count,
    sol_sha256_t*      out
);

/*
 * Incremental hashing API
 */

/* Initialize context */
void sol_sha256_init(sol_sha256_ctx_t* ctx);

/* Update with more data */
void sol_sha256_update(sol_sha256_ctx_t* ctx, const void* data, size_t len);

/* Finalize and get hash */
void sol_sha256_final(sol_sha256_ctx_t* ctx, sol_sha256_t* out);

/*
 * Convenience wrappers for writing SHA-256 output into unaligned buffers.
 *
 * Note: `sol_sha256_t` is 32-byte aligned to enable optimized implementations.
 * Do not cast arbitrary pointers (e.g. `sol_hash_t*`) to `sol_sha256_t*` unless
 * you can guarantee the pointer alignment. Use these helpers instead.
 */
SOL_INLINE void
sol_sha256_bytes(const void* data, size_t len, uint8_t out[static SOL_SHA256_HASH_SIZE]) {
    sol_sha256_t tmp;
    sol_sha256(data, len, &tmp);
    memcpy(out, tmp.bytes, SOL_SHA256_HASH_SIZE);
}

SOL_INLINE void
sol_sha256_final_bytes(sol_sha256_ctx_t* ctx, uint8_t out[static SOL_SHA256_HASH_SIZE]) {
    sol_sha256_t tmp;
    sol_sha256_final(ctx, &tmp);
    memcpy(out, tmp.bytes, SOL_SHA256_HASH_SIZE);
}

/*
 * Utility functions
 */

/* Compare two hashes (constant time) */
bool sol_sha256_eq(const sol_sha256_t* a, const sol_sha256_t* b);

/* Check if hash is all zeros */
bool sol_sha256_is_zero(const sol_sha256_t* h);

/* Copy hash */
void sol_sha256_copy(sol_sha256_t* dst, const sol_sha256_t* src);

/* Convert to hex string (requires 65-byte buffer) */
void sol_sha256_to_hex(const sol_sha256_t* h, char* out);

/* Parse from hex string */
sol_err_t sol_sha256_from_hex(const char* hex, sol_sha256_t* out);

/*
 * HMAC-SHA256
 */

#define SOL_HMAC_SHA256_SIZE SOL_SHA256_HASH_SIZE

typedef struct {
    sol_sha256_ctx_t inner;
    sol_sha256_ctx_t outer;
} sol_hmac_sha256_ctx_t;

/* One-shot HMAC */
void sol_hmac_sha256(
    const void*   key,
    size_t        key_len,
    const void*   data,
    size_t        data_len,
    sol_sha256_t* out
);

/* Incremental HMAC */
void sol_hmac_sha256_init(sol_hmac_sha256_ctx_t* ctx, const void* key, size_t key_len);
void sol_hmac_sha256_update(sol_hmac_sha256_ctx_t* ctx, const void* data, size_t len);
void sol_hmac_sha256_final(sol_hmac_sha256_ctx_t* ctx, sol_sha256_t* out);

/*
 * HKDF-SHA256 (RFC 5869)
 */

/* Extract step */
void sol_hkdf_sha256_extract(
    const void*   salt,
    size_t        salt_len,
    const void*   ikm,
    size_t        ikm_len,
    sol_sha256_t* prk
);

/* Expand step */
sol_err_t sol_hkdf_sha256_expand(
    const sol_sha256_t* prk,
    const void*         info,
    size_t              info_len,
    void*               okm,
    size_t              okm_len
);

/* One-shot HKDF */
sol_err_t sol_hkdf_sha256(
    const void* salt,
    size_t      salt_len,
    const void* ikm,
    size_t      ikm_len,
    const void* info,
    size_t      info_len,
    void*       okm,
    size_t      okm_len
);

#endif /* SOL_SHA256_H */
