/*
 * sol_secp256k1.c - Secp256k1/ECDSA helpers
 */

#include "sol_secp256k1.h"
#include "sol_keccak256.h"
#include "../util/sol_log.h"
#include <string.h>

#ifdef SOL_HAS_SECP256K1
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#endif

#ifdef SOL_HAS_SECP256K1
static secp256k1_context* g_secp256k1_ctx = NULL;

static secp256k1_context*
get_secp256k1_context(void) {
    if (g_secp256k1_ctx == NULL) {
        g_secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    }
    return g_secp256k1_ctx;
}
#endif

sol_err_t
sol_secp256k1_recover_pubkey(
    const uint8_t* signature_compact,
    uint8_t        recovery_id,
    const uint8_t* message_hash,
    uint8_t*       out_pubkey64
) {
    if (signature_compact == NULL || message_hash == NULL || out_pubkey64 == NULL) {
        return SOL_ERR_INVAL;
    }

    if (recovery_id > 3) {
        return SOL_ERR_INVAL;
    }

#ifndef SOL_HAS_SECP256K1
    (void)signature_compact;
    (void)message_hash;
    (void)out_pubkey64;
    sol_log_warn("Secp256k1: recovery not available (libsecp256k1 not linked)");
    return SOL_ERR_UNSUPPORTED;
#else
    secp256k1_context* ctx = get_secp256k1_context();
    if (ctx == NULL) {
        return SOL_ERR_CRYPTO;
    }

    secp256k1_ecdsa_recoverable_signature sig;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(
            ctx, &sig, signature_compact, (int)recovery_id)) {
        return SOL_ERR_INVALID_SIGNATURE;
    }

    secp256k1_pubkey pubkey;
    if (!secp256k1_ecdsa_recover(ctx, &pubkey, &sig, message_hash)) {
        return SOL_ERR_INVALID_SIGNATURE;
    }

    uint8_t pubkey_bytes[65];
    size_t pubkey_len = sizeof(pubkey_bytes);
    if (!secp256k1_ec_pubkey_serialize(
            ctx, pubkey_bytes, &pubkey_len, &pubkey, SECP256K1_EC_UNCOMPRESSED) ||
        pubkey_len != sizeof(pubkey_bytes)) {
        return SOL_ERR_CRYPTO;
    }

    /* Skip 0x04 prefix */
    memcpy(out_pubkey64, pubkey_bytes + 1, 64);
    return SOL_OK;
#endif
}

sol_err_t
sol_secp256k1_ecrecover_address(
    const uint8_t* signature_compact,
    uint8_t        recovery_id,
    const uint8_t* message_hash,
    uint8_t*       out_address20
) {
    if (signature_compact == NULL || message_hash == NULL || out_address20 == NULL) {
        return SOL_ERR_INVAL;
    }

    uint8_t pubkey64[64];
    sol_err_t err = sol_secp256k1_recover_pubkey(
        signature_compact, recovery_id, message_hash, pubkey64
    );
    if (err != SOL_OK) {
        return err;
    }

    sol_keccak256_t hash;
    sol_keccak256_hash(pubkey64, sizeof(pubkey64), &hash);

    /* Ethereum address is last 20 bytes of keccak256(pubkey64) */
    memcpy(out_address20, hash.bytes + 12, 20);
    return SOL_OK;
}

