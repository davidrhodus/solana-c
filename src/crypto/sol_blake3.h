/*
 * sol_blake3.h - BLAKE3 hash implementation
 *
 * BLAKE3 is used in Solana for various purposes including
 * program derived addresses and merkle trees.
 */

#ifndef SOL_BLAKE3_H
#define SOL_BLAKE3_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"

#define SOL_BLAKE3_OUT_LEN     32
#define SOL_BLAKE3_KEY_LEN     32
#define SOL_BLAKE3_BLOCK_LEN   64
#define SOL_BLAKE3_CHUNK_LEN   1024
#define SOL_BLAKE3_MAX_DEPTH   54  /* 2^54 * 1024 = 2^64 bytes */

/*
 * BLAKE3 hash output
 */
typedef struct {
    uint8_t bytes[SOL_BLAKE3_OUT_LEN];
} sol_blake3_t;

/*
 * BLAKE3 hasher state
 *
 * This is an opaque structure - use the provided functions.
 */
typedef struct {
    /* Key words (IV for unkeyed mode). */
    uint32_t key_words[8];

    /* Current chunk state. */
    uint32_t cv[8];
    uint8_t  buf[SOL_BLAKE3_BLOCK_LEN];
    uint8_t  buf_len;
    uint8_t  blocks_compressed;
    uint64_t chunk_counter;

    /* Domain separation flags (KEYED_HASH / DERIVE_KEY_* etc). */
    uint8_t  flags;

    /* Stack of subtree chaining values for incremental tree hashing. */
    uint8_t  cv_stack_len;
    uint32_t cv_stack[SOL_BLAKE3_MAX_DEPTH][8];
} sol_blake3_ctx_t;

/*
 * Initialize a BLAKE3 hasher
 */
void sol_blake3_init(sol_blake3_ctx_t* ctx);

/*
 * Initialize a BLAKE3 hasher with a key (for keyed hashing)
 */
void sol_blake3_init_keyed(
    sol_blake3_ctx_t*  ctx,
    const uint8_t      key[SOL_BLAKE3_KEY_LEN]
);

/*
 * Initialize a BLAKE3 hasher for key derivation
 */
void sol_blake3_init_derive_key(
    sol_blake3_ctx_t*  ctx,
    const char*        context
);

/*
 * Add data to the hasher
 */
void sol_blake3_update(
    sol_blake3_ctx_t*  ctx,
    const uint8_t*     data,
    size_t             len
);

/*
 * Finalize and get the hash output
 *
 * The hasher can continue to be used after finalize.
 */
void sol_blake3_final(
    sol_blake3_ctx_t*  ctx,
    sol_blake3_t*      out
);

/*
 * Finalize with extended output
 *
 * BLAKE3 supports XOF (extendable output) mode.
 */
void sol_blake3_final_xof(
    sol_blake3_ctx_t*  ctx,
    uint8_t*           out,
    size_t             out_len
);

/*
 * One-shot hash function
 */
void sol_blake3_hash(
    const uint8_t*  data,
    size_t          len,
    sol_blake3_t*   out
);

/*
 * One-shot keyed hash
 */
void sol_blake3_keyed_hash(
    const uint8_t   key[SOL_BLAKE3_KEY_LEN],
    const uint8_t*  data,
    size_t          len,
    sol_blake3_t*   out
);

/*
 * Hash multiple inputs (useful for PDA derivation)
 */
void sol_blake3_hash_many(
    const uint8_t* const*  inputs,
    const size_t*          input_lens,
    size_t                 input_count,
    sol_blake3_t*          out
);

/*
 * Compare two BLAKE3 hashes (constant time)
 */
bool sol_blake3_equal(
    const sol_blake3_t* a,
    const sol_blake3_t* b
);

#endif /* SOL_BLAKE3_H */
