/*
 * sol_sha512.h - SHA-512 hash function
 *
 * Used internally by Ed25519 implementation.
 */

#ifndef SOL_SHA512_H
#define SOL_SHA512_H

#include "../util/sol_base.h"
#include "../util/sol_err.h"

/*
 * SHA-512 constants
 */
#define SOL_SHA512_HASH_SIZE   64
#define SOL_SHA512_BLOCK_SIZE  128

/*
 * SHA-512 hash output
 */
typedef struct SOL_ALIGNED(64) {
    uint8_t bytes[SOL_SHA512_HASH_SIZE];
} sol_sha512_t;

/*
 * SHA-512 context for incremental hashing
 */
typedef struct {
    uint64_t state[8];      /* Hash state */
    uint64_t count[2];      /* Number of bits processed (128-bit) */
    uint8_t  buffer[128];   /* Pending data buffer */
} sol_sha512_ctx_t;

/*
 * One-shot hash
 */
void sol_sha512(const void* data, size_t len, sol_sha512_t* out);

/*
 * Incremental hashing API
 */
void sol_sha512_init(sol_sha512_ctx_t* ctx);
void sol_sha512_update(sol_sha512_ctx_t* ctx, const void* data, size_t len);
void sol_sha512_final(sol_sha512_ctx_t* ctx, sol_sha512_t* out);

/*
 * Utility functions
 */
bool sol_sha512_eq(const sol_sha512_t* a, const sol_sha512_t* b);
void sol_sha512_copy(sol_sha512_t* dst, const sol_sha512_t* src);

#endif /* SOL_SHA512_H */
