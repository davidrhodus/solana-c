/*
 * sol_pubkey.h - Solana public key type and extended operations
 *
 * This header extends sol_types.h with additional pubkey operations
 * like base58 encoding/decoding and bincode serialization.
 */

#ifndef SOL_PUBKEY_H
#define SOL_PUBKEY_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "sol_bincode.h"

/*
 * Base58 encoded pubkey is at most 44 characters + null
 */
#define SOL_PUBKEY_BASE58_LEN 45

/*
 * Initialize a pubkey to all zeros
 */
static inline void
sol_pubkey_init(sol_pubkey_t* pk) {
    memset(pk->bytes, 0, SOL_PUBKEY_SIZE);
}

/*
 * Decode pubkey from bincode
 */
static inline sol_err_t
sol_pubkey_decode(sol_decoder_t* dec, sol_pubkey_t* pk) {
    const uint8_t* data;
    SOL_DECODE_TRY(sol_decode_bytes(dec, SOL_PUBKEY_SIZE, &data));
    memcpy(pk->bytes, data, SOL_PUBKEY_SIZE);
    return SOL_OK;
}

/*
 * Encode pubkey to bincode
 */
static inline sol_err_t
sol_pubkey_encode(sol_encoder_t* enc, const sol_pubkey_t* pk) {
    return sol_encode_bytes(enc, pk->bytes, SOL_PUBKEY_SIZE);
}

/*
 * Convert pubkey to base58 string
 */
sol_err_t sol_pubkey_to_base58(
    const sol_pubkey_t* pk,
    char*               out,
    size_t              out_len
);

/*
 * Parse pubkey from base58 string
 */
sol_err_t sol_pubkey_from_base58(
    const char*   str,
    sol_pubkey_t* pk
);

/*
 * Hash pubkey (for use in hash maps)
 */
uint64_t sol_pubkey_hash(const sol_pubkey_t* pk);

/*
 * Load pubkey from a file containing base58-encoded address
 * The file should contain only the base58 string, optionally with whitespace.
 */
sol_err_t sol_pubkey_load(const char* path, sol_pubkey_t* pk);

/*
 * Save pubkey to file in base58 format
 */
sol_err_t sol_pubkey_save(const char* path, const sol_pubkey_t* pk);

#endif /* SOL_PUBKEY_H */
