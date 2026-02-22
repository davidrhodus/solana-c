/*
 * sol_secp256k1_program.h - Secp256k1 Signature Verification Precompile
 *
 * This native program verifies Secp256k1/ECDSA signatures and performs
 * public key recovery. It provides Ethereum compatibility for Solana programs.
 *
 * Program ID: KeccakSecp256k11111111111111111111111111111
 */

#ifndef SOL_SECP256K1_PROGRAM_H
#define SOL_SECP256K1_PROGRAM_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "sol_system_program.h"

/*
 * Secp256k1 Program ID
 * Base58: KeccakSecp256k11111111111111111111111111111
 */
extern const sol_pubkey_t SOL_SECP256K1_PROGRAM_ID;

/*
 * Secp256k1 constants
 */
#define SOL_SECP256K1_SIGNATURE_SIZE    64  /* r (32) + s (32) */
#define SOL_SECP256K1_PUBKEY_SIZE       64  /* x (32) + y (32) uncompressed */
#define SOL_SECP256K1_PUBKEY_COMPRESSED_SIZE 33
#define SOL_SECP256K1_RECOVERY_ID_SIZE  1
#define SOL_SECP256K1_ETH_ADDRESS_SIZE  20

/*
 * Secp256k1 instruction data format:
 *
 * | Offset | Size | Description                         |
 * |--------|------|-------------------------------------|
 * | 0      | 1    | Number of signatures to verify      |
 *
 * For each signature (11 bytes per entry):
 * | Offset | Size | Description                         |
 * |--------|------|-------------------------------------|
 * | +0     | 2    | Signature offset                    |
 * | +2     | 1    | Signature instruction index         |
 * | +3     | 2    | Eth address offset                  |
 * | +5     | 1    | Eth address instruction index       |
 * | +6     | 2    | Message data offset                 |
 * | +8     | 2    | Message data size                   |
 * | +10    | 1    | Message instruction index           |
 *
 * Signature data format (at signature offset):
 * | Offset | Size | Description                         |
 * |--------|------|-------------------------------------|
 * | 0      | 64   | Signature (r, s)                    |
 * | 64     | 1    | Recovery ID (v - 27)                |
 */

#define SOL_SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE 11
#define SOL_SECP256K1_SIGNATURE_OFFSETS_START 1
#define SOL_SECP256K1_DATA_START (SOL_SECP256K1_SIGNATURE_OFFSETS_START + 11)

/*
 * Secp256k1 signature offset structure
 */
typedef struct {
    uint16_t    signature_offset;           /* Offset to signature in data */
    uint8_t     signature_instruction_index; /* Which instruction contains sig */
    uint16_t    eth_address_offset;         /* Offset to eth address */
    uint8_t     eth_address_instruction_index;
    uint16_t    message_data_offset;        /* Offset to message in data */
    uint16_t    message_data_size;          /* Size of message */
    uint8_t     message_instruction_index;  /* Which instruction contains message */
} sol_secp256k1_signature_offsets_t;

/*
 * Process a Secp256k1 signature verification instruction
 *
 * This function verifies Secp256k1/ECDSA signatures using ecrecover.
 * It recovers the public key from the signature and verifies it matches
 * the expected Ethereum address.
 *
 * @param ctx       Execution context
 * @return          SOL_OK if all signatures verify, error otherwise
 */
sol_err_t sol_secp256k1_program_execute(sol_invoke_context_t* ctx);

/*
 * Recover Ethereum address from Secp256k1 signature
 *
 * @param signature     64-byte signature (r, s)
 * @param recovery_id   Recovery ID (0-3)
 * @param message_hash  32-byte Keccak256 hash of message
 * @param out_address   20-byte Ethereum address output
 * @return              SOL_OK on success, error otherwise
 */
sol_err_t sol_secp256k1_ecrecover(
    const uint8_t*  signature,
    uint8_t         recovery_id,
    const uint8_t*  message_hash,
    uint8_t*        out_address
);


/*
 * Create Secp256k1 verification instruction data
 *
 * Helper function to create properly formatted instruction data.
 *
 * @param signatures        Array of signatures (65 bytes each: sig + recovery_id)
 * @param eth_addresses     Array of expected Ethereum addresses (20 bytes each)
 * @param messages          Array of message pointers
 * @param message_lens      Array of message lengths
 * @param count             Number of signatures to verify
 * @param out_data          Output buffer for instruction data
 * @param out_len           Input: buffer size, Output: data size
 * @return                  SOL_OK on success, error otherwise
 */
sol_err_t sol_secp256k1_create_instruction(
    const uint8_t* const*   signatures,     /* 65 bytes each */
    const uint8_t* const*   eth_addresses,  /* 20 bytes each */
    const uint8_t* const*   messages,
    const size_t*           message_lens,
    size_t                  count,
    uint8_t*                out_data,
    size_t*                 out_len
);

#endif /* SOL_SECP256K1_PROGRAM_H */
