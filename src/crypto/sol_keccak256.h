/*
 * sol_keccak256.h - Keccak-256 hash implementation
 *
 * Keccak-256 is used for Ethereum compatibility in Solana,
 * particularly for the secp256k1 signature recovery precompile.
 * Note: This is Keccak-256 (pre-SHA-3 standard), not SHA3-256.
 */

#ifndef SOL_KECCAK256_H
#define SOL_KECCAK256_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"

#define SOL_KECCAK256_OUT_LEN    32
#define SOL_KECCAK256_RATE       136  /* (1600 - 256*2) / 8 */

/*
 * Keccak-256 hash output
 */
typedef struct {
    uint8_t bytes[SOL_KECCAK256_OUT_LEN];
} sol_keccak256_t;

/*
 * Keccak-256 hasher state
 */
typedef struct {
    uint64_t state[25];     /* 1600-bit state */
    uint8_t  buf[SOL_KECCAK256_RATE];
    size_t   buf_len;
} sol_keccak256_ctx_t;

/*
 * Initialize a Keccak-256 hasher
 */
void sol_keccak256_init(sol_keccak256_ctx_t* ctx);

/*
 * Add data to the hasher
 */
void sol_keccak256_update(
    sol_keccak256_ctx_t*  ctx,
    const uint8_t*        data,
    size_t                len
);

/*
 * Finalize and get the hash output
 */
void sol_keccak256_final(
    sol_keccak256_ctx_t*  ctx,
    sol_keccak256_t*      out
);

/*
 * One-shot hash function
 */
void sol_keccak256_hash(
    const uint8_t*    data,
    size_t            len,
    sol_keccak256_t*  out
);

/*
 * Hash multiple inputs
 */
void sol_keccak256_hash_many(
    const uint8_t* const*  inputs,
    const size_t*          input_lens,
    size_t                 input_count,
    sol_keccak256_t*       out
);

/*
 * Compare two Keccak-256 hashes (constant time)
 */
bool sol_keccak256_equal(
    const sol_keccak256_t* a,
    const sol_keccak256_t* b
);

#endif /* SOL_KECCAK256_H */
