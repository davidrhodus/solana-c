/*
 * sol_lt_hash.c - Solana Lattice Hash (LtHash)
 */

#include "sol_lt_hash.h"
#include "../util/sol_bits.h"
#include "blake3/fd_blake3.h"
#include <string.h>

#if defined(__AVX2__)
#include <immintrin.h>
#endif

void
sol_lt_hash_identity(sol_lt_hash_t* out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
}

void
sol_lt_hash_mix_in(sol_lt_hash_t* self, const sol_lt_hash_t* other) {
    if (!self || !other) return;
#if defined(__AVX2__)
    size_t i = 0;
    for (; i + 16u <= SOL_LT_HASH_NUM_ELEMENTS; i += 16u) {
        __m256i a = _mm256_loadu_si256((const __m256i*)&self->v[i]);
        __m256i b = _mm256_loadu_si256((const __m256i*)&other->v[i]);
        __m256i r = _mm256_add_epi16(a, b); /* wrapping add */
        _mm256_storeu_si256((__m256i*)&self->v[i], r);
    }
    for (; i < SOL_LT_HASH_NUM_ELEMENTS; i++) {
        self->v[i] = (uint16_t)(self->v[i] + other->v[i]);
    }
#else
    for (size_t i = 0; i < SOL_LT_HASH_NUM_ELEMENTS; i++) {
        self->v[i] = (uint16_t)(self->v[i] + other->v[i]);
    }
#endif
}

void
sol_lt_hash_mix_out(sol_lt_hash_t* self, const sol_lt_hash_t* other) {
    if (!self || !other) return;
#if defined(__AVX2__)
    size_t i = 0;
    for (; i + 16u <= SOL_LT_HASH_NUM_ELEMENTS; i += 16u) {
        __m256i a = _mm256_loadu_si256((const __m256i*)&self->v[i]);
        __m256i b = _mm256_loadu_si256((const __m256i*)&other->v[i]);
        __m256i r = _mm256_sub_epi16(a, b); /* wrapping sub */
        _mm256_storeu_si256((__m256i*)&self->v[i], r);
    }
    for (; i < SOL_LT_HASH_NUM_ELEMENTS; i++) {
        self->v[i] = (uint16_t)(self->v[i] - other->v[i]);
    }
#else
    for (size_t i = 0; i < SOL_LT_HASH_NUM_ELEMENTS; i++) {
        self->v[i] = (uint16_t)(self->v[i] - other->v[i]);
    }
#endif
}

void
sol_lt_hash_from_blake3_hasher(sol_blake3_ctx_t* ctx, sol_lt_hash_t* out) {
    if (!ctx || !out) return;
    sol_blake3_final_xof(ctx, (uint8_t*)out->v, SOL_LT_HASH_SIZE_BYTES);
}

void
sol_lt_hash_checksum(const sol_lt_hash_t* lt_hash, sol_blake3_t* out_checksum) {
    if (!lt_hash || !out_checksum) return;
    sol_blake3_hash((const uint8_t*)lt_hash->v, SOL_LT_HASH_SIZE_BYTES, out_checksum);
}

void
sol_account_lt_hash(const sol_pubkey_t* pubkey,
                    const sol_account_t* account,
                    sol_lt_hash_t* out) {
    if (!out) return;

    if (!pubkey || !account || account->meta.lamports == 0) {
        sol_lt_hash_identity(out);
        return;
    }
    /* In Agave, zero-lamport accounts have identity lt_hash (confirmed
     * via delta dump comparison: Agave curr_lthash=00000... for all
     * zero-lamport accounts). */

    /* Accounts LtHash dominates replay on busy slots. Use the vendored
     * Firedancer BLAKE3 implementation for the 2048-byte XOF. */
    fd_blake3_t hasher[1];
    fd_blake3_init(hasher);

    /* Field order must match Agave's hash_account_helper():
       lamports || data || executable || owner || pubkey
       Note: rent_epoch is NOT included in the lt_hash. */

    uint8_t lamports_le[8];
    sol_store_u64_le(lamports_le, (uint64_t)account->meta.lamports);
    fd_blake3_append(hasher, lamports_le, (ulong)sizeof(lamports_le));

    if (account->meta.data_len > 0 && account->data) {
        fd_blake3_append(hasher, account->data, (ulong)account->meta.data_len);
    }

    uint8_t executable = account->meta.executable ? 1U : 0U;
    fd_blake3_append(hasher, &executable, 1UL);
    fd_blake3_append(hasher, account->meta.owner.bytes, (ulong)SOL_PUBKEY_SIZE);
    fd_blake3_append(hasher, pubkey->bytes, (ulong)SOL_PUBKEY_SIZE);

    /* NOTE: fd_blake3_fini_2048 uses aligned AVX stores. Do not write directly
     * into `out` as it is not guaranteed to be 32-byte aligned (it may be part
     * of a heap-allocated struct). */
    uint8_t tmp[SOL_LT_HASH_SIZE_BYTES] __attribute__((aligned(32)));
    fd_blake3_fini_2048(hasher, tmp);
    memcpy(out->v, tmp, SOL_LT_HASH_SIZE_BYTES);
}
