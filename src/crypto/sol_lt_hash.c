/*
 * sol_lt_hash.c - Solana Lattice Hash (LtHash)
 */

#include "sol_lt_hash.h"
#include "../util/sol_bits.h"
#include <string.h>

void
sol_lt_hash_identity(sol_lt_hash_t* out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
}

void
sol_lt_hash_mix_in(sol_lt_hash_t* self, const sol_lt_hash_t* other) {
    if (!self || !other) return;
    for (size_t i = 0; i < SOL_LT_HASH_NUM_ELEMENTS; i++) {
        self->v[i] = (uint16_t)(self->v[i] + other->v[i]);
    }
}

void
sol_lt_hash_mix_out(sol_lt_hash_t* self, const sol_lt_hash_t* other) {
    if (!self || !other) return;
    for (size_t i = 0; i < SOL_LT_HASH_NUM_ELEMENTS; i++) {
        self->v[i] = (uint16_t)(self->v[i] - other->v[i]);
    }
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

    sol_blake3_ctx_t hasher;
    sol_blake3_init(&hasher);

    /* Field order must match Agave's hash_account_helper():
       lamports || data || executable || owner || pubkey
       Note: rent_epoch is NOT included in the lt_hash. */

    uint8_t lamports_le[8];
    sol_store_u64_le(lamports_le, (uint64_t)account->meta.lamports);
    sol_blake3_update(&hasher, lamports_le, sizeof(lamports_le));

    if (account->meta.data_len > 0 && account->data) {
        sol_blake3_update(&hasher, account->data, (size_t)account->meta.data_len);
    }

    uint8_t executable = account->meta.executable ? 1U : 0U;
    sol_blake3_update(&hasher, &executable, 1);
    sol_blake3_update(&hasher, account->meta.owner.bytes, SOL_PUBKEY_SIZE);
    sol_blake3_update(&hasher, pubkey->bytes, SOL_PUBKEY_SIZE);

    sol_lt_hash_from_blake3_hasher(&hasher, out);
}

