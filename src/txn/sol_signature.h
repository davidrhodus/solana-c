/*
 * sol_signature.h - Solana signature type and extended operations
 *
 * This header extends sol_types.h with additional signature operations
 * like base58 encoding/decoding and bincode serialization.
 */

#ifndef SOL_SIGNATURE_H
#define SOL_SIGNATURE_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "sol_bincode.h"

/*
 * Base58 encoded signature is at most 88 characters + null
 */
#define SOL_SIGNATURE_BASE58_LEN 89

/*
 * Initialize a signature to all zeros
 */
static inline void
sol_signature_init(sol_signature_t* sig) {
    memset(sig->bytes, 0, SOL_SIGNATURE_SIZE);
}

/*
 * Copy a signature
 */
static inline void
sol_signature_copy(sol_signature_t* dst, const sol_signature_t* src) {
    memcpy(dst->bytes, src->bytes, SOL_SIGNATURE_SIZE);
}

/*
 * Decode signature from bincode
 */
static inline sol_err_t
sol_signature_decode(sol_decoder_t* dec, sol_signature_t* sig) {
    const uint8_t* data;
    SOL_DECODE_TRY(sol_decode_bytes(dec, SOL_SIGNATURE_SIZE, &data));
    memcpy(sig->bytes, data, SOL_SIGNATURE_SIZE);
    return SOL_OK;
}

/*
 * Encode signature to bincode
 */
static inline sol_err_t
sol_signature_encode(sol_encoder_t* enc, const sol_signature_t* sig) {
    return sol_encode_bytes(enc, sig->bytes, SOL_SIGNATURE_SIZE);
}

/*
 * Convert signature to base58 string
 */
sol_err_t sol_signature_to_base58(
    const sol_signature_t* sig,
    char*                  out,
    size_t                 out_len
);

/*
 * Parse signature from base58 string
 */
sol_err_t sol_signature_from_base58(
    const char*      str,
    sol_signature_t* sig
);

#endif /* SOL_SIGNATURE_H */
