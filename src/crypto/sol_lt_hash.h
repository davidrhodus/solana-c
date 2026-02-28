/*
 * sol_lt_hash.h - Solana Lattice Hash (LtHash)
 *
 * Agave/Solana uses a lattice-based incremental hash ("LtHash") to represent
 * the accounts state for bank hashing. This is a commutative multiset hash
 * backed by BLAKE3 XOF output.
 */

#ifndef SOL_LT_HASH_H
#define SOL_LT_HASH_H

#include "../util/sol_types.h"
#include "sol_blake3.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SOL_LT_HASH_NUM_ELEMENTS 1024
#define SOL_LT_HASH_SIZE_BYTES   (SOL_LT_HASH_NUM_ELEMENTS * sizeof(uint16_t))

typedef struct {
    uint16_t v[SOL_LT_HASH_NUM_ELEMENTS];
} sol_lt_hash_t;

SOL_STATIC_ASSERT(sizeof(sol_lt_hash_t) == SOL_LT_HASH_SIZE_BYTES,
                  "sol_lt_hash_t must be 2048 bytes");

/* Initialize to identity (all zeros). */
void sol_lt_hash_identity(sol_lt_hash_t* out);

/* Mix in another lt hash (wrapping add). */
void sol_lt_hash_mix_in(sol_lt_hash_t* self, const sol_lt_hash_t* other);

/* Mix out another lt hash (wrapping sub). */
void sol_lt_hash_mix_out(sol_lt_hash_t* self, const sol_lt_hash_t* other);

/* Create an lt hash from a finalized BLAKE3 hasher using XOF output. */
void sol_lt_hash_from_blake3_hasher(sol_blake3_ctx_t* ctx, sol_lt_hash_t* out);

/* Compute checksum = BLAKE3(bytes(lt_hash)) (32 bytes). */
void sol_lt_hash_checksum(const sol_lt_hash_t* lt_hash, sol_blake3_t* out_checksum);

/* Compute per-account lt hash (identity for zero-lamport accounts). */
void sol_account_lt_hash(const sol_pubkey_t* pubkey,
                         const sol_account_t* account,
                         sol_lt_hash_t* out);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SOL_LT_HASH_H */
