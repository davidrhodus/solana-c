/*
 * sol_secp256k1.h - Secp256k1/ECDSA helpers
 *
 * Optional wrapper around libsecp256k1 for public key recovery and
 * Ethereum-compatible address derivation.
 */

#ifndef SOL_SECP256K1_H
#define SOL_SECP256K1_H

#include "../util/sol_err.h"
#include <stddef.h>
#include <stdint.h>

/*
 * Recover an uncompressed public key (x||y, 64 bytes) from a compact signature.
 *
 * @param signature_compact   64-byte compact signature (r||s)
 * @param recovery_id         Recovery id (0..3)
 * @param message_hash        32-byte message hash
 * @param out_pubkey64        Output buffer (64 bytes: x||y)
 */
sol_err_t sol_secp256k1_recover_pubkey(
    const uint8_t* signature_compact,
    uint8_t        recovery_id,
    const uint8_t* message_hash,
    uint8_t*       out_pubkey64
);

/*
 * Recover an Ethereum address from a compact signature.
 *
 * @param signature_compact   64-byte compact signature (r||s)
 * @param recovery_id         Recovery id (0..3)
 * @param message_hash        32-byte message hash
 * @param out_address20       Output buffer (20 bytes)
 */
sol_err_t sol_secp256k1_ecrecover_address(
    const uint8_t* signature_compact,
    uint8_t        recovery_id,
    const uint8_t* message_hash,
    uint8_t*       out_address20
);

#endif /* SOL_SECP256K1_H */

