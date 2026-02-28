/*
 * sol_transaction.c - Solana transaction parsing and verification
 */

#include "sol_transaction.h"
#include "../crypto/sol_ed25519.h"
#include "../crypto/sol_sha256.h"
#include <string.h>

/*
 * Parse a transaction from raw bytes
 */
sol_err_t
sol_transaction_decode(
    const uint8_t*      data,
    size_t              data_len,
    sol_transaction_t*  tx
) {
    if (data == NULL || tx == NULL) {
        return SOL_ERR_INVAL;
    }

    if (data_len < 4) {  /* Minimum: 1 sig count + 1 sig (64) would be 65, but header alone is 4 */
        return SOL_ERR_TRUNCATED;
    }

    sol_transaction_init(tx);

    sol_decoder_t dec;
    sol_decoder_init(&dec, data, data_len);

    /* Signature count (compact-u16) */
    uint16_t sig_count;
    SOL_DECODE_TRY(sol_decode_compact_u16(&dec, &sig_count));

    if (sig_count == 0 || sig_count > SOL_MAX_TX_SIGNATURES) {
        return SOL_ERR_TX_MALFORMED;
    }

    tx->signatures_len = (uint8_t)sig_count;

    /* Signatures (zero-copy) */
    const uint8_t* sig_data;
    SOL_DECODE_TRY(sol_decode_bytes(&dec, sig_count * SOL_SIGNATURE_SIZE, &sig_data));
    tx->signatures = (const sol_signature_t*)sig_data;

    /* Parse message (handles version detection) */
    size_t message_start = dec.pos;
    SOL_DECODE_TRY(sol_message_decode_versioned(&dec, &tx->message));
    size_t message_end = dec.pos;

    /* Record message bytes for signature verification */
    tx->message_data = data + message_start;
    tx->message_data_len = message_end - message_start;

    tx->encoded_len = dec.pos;
    if (tx->encoded_len > SOL_MAX_TX_SIZE) {
        return SOL_ERR_TX_TOO_LARGE;
    }

    /* Verify signature count matches header */
    if (tx->signatures_len != tx->message.header.num_required_signatures) {
        return SOL_ERR_TX_MALFORMED;
    }

    return SOL_OK;
}

/*
 * Encode a transaction to bytes
 */
sol_err_t
sol_transaction_encode(
    const sol_transaction_t*  tx,
    uint8_t*                  out,
    size_t                    out_len,
    size_t*                   written
) {
    if (tx == NULL || out == NULL || written == NULL) {
        return SOL_ERR_INVAL;
    }
    if (tx->signatures_len > 0 && tx->signatures == NULL) {
        return SOL_ERR_INVAL;
    }
    if (tx->message.version != SOL_MESSAGE_VERSION_LEGACY &&
        tx->message.version != SOL_MESSAGE_VERSION_V0) {
        return SOL_ERR_INVAL;
    }

    sol_encoder_t enc;
    sol_encoder_init(&enc, out, out_len);

    /* Signature count */
    SOL_ENCODE_TRY(sol_encode_compact_u16(&enc, tx->signatures_len));

    /* Signatures */
    for (uint8_t i = 0; i < tx->signatures_len; i++) {
        SOL_ENCODE_TRY(sol_signature_encode(&enc, &tx->signatures[i]));
    }

    /* Message */
    if (tx->message.version == SOL_MESSAGE_VERSION_LEGACY) {
        SOL_ENCODE_TRY(sol_message_encode_legacy(&enc, &tx->message));
    } else {
        /* V0 message - add version prefix */
        SOL_ENCODE_TRY(sol_encode_u8(&enc, 0x80));  /* Version 0 */
        SOL_ENCODE_TRY(sol_message_encode_v0(&enc, &tx->message));
    }

    *written = sol_encoder_len(&enc);
    return SOL_OK;
}

/*
 * Sanitize a transaction
 */
sol_err_t
sol_transaction_sanitize(const sol_transaction_t* tx) {
    if (tx == NULL) {
        return SOL_ERR_INVAL;
    }

    /* Must have at least one signature */
    if (tx->signatures_len == 0) {
        return SOL_ERR_TX_SANITIZE;
    }

    /* Signature count must match header */
    if (tx->signatures_len != tx->message.header.num_required_signatures) {
        return SOL_ERR_TX_SANITIZE;
    }

    /* Sanitize the message */
    SOL_TRY(sol_message_sanitize(&tx->message));

    /* Note: For legacy messages, instruction index validation happens
     * during decode (zero-copy parsing). */

    return SOL_OK;
}

/*
 * Verify transaction signatures
 */
bool
sol_transaction_verify_signatures(
    const sol_transaction_t*  tx,
    bool*                     results
) {
    if (tx == NULL || tx->signatures_len == 0) {
        return false;
    }

    if (tx->message_data == NULL || tx->message_data_len == 0) {
        return false;
    }

    /* Verify each signature */
    bool all_valid = true;

    for (uint8_t i = 0; i < tx->signatures_len; i++) {
        /* Get the corresponding signer pubkey */
        if (i >= tx->message.account_keys_len) {
            if (results) results[i] = false;
            all_valid = false;
            continue;
        }

        const sol_pubkey_t* signer = &tx->message.account_keys[i];
        const sol_signature_t* sig = &tx->signatures[i];

        /* Verify signature */
        bool valid = sol_ed25519_verify(
            signer,
            tx->message_data,
            tx->message_data_len,
            sig
        );

        if (results) results[i] = valid;
        if (!valid) all_valid = false;
    }

    return all_valid;
}

/*
 * Transaction hash
 */
sol_err_t
sol_transaction_hash(
    const sol_transaction_t*  tx,
    sol_hash_t*               hash
) {
    if (tx == NULL || hash == NULL) {
        return SOL_ERR_INVAL;
    }

    /* Need to serialize the transaction first */
    uint8_t buf[SOL_MAX_TX_SIZE];
    size_t written;

    sol_err_t err = sol_transaction_encode(tx, buf, sizeof(buf), &written);
    if (err != SOL_OK) {
        /* If we can't encode, try hashing just the message */
        if (tx->message_data != NULL && tx->message_data_len > 0) {
            sol_sha256_t sha_hash;
            sol_sha256(tx->message_data, tx->message_data_len, &sha_hash);
            memcpy(hash->bytes, sha_hash.bytes, SOL_HASH_SIZE);
            return SOL_OK;
        }
        return err;
    }

    sol_sha256_t sha_hash;
    sol_sha256(buf, written, &sha_hash);
    memcpy(hash->bytes, sha_hash.bytes, SOL_HASH_SIZE);

    return SOL_OK;
}
