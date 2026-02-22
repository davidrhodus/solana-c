/*
 * sol_ed25519_program.h - Ed25519 Signature Verification Precompile
 *
 * This native program verifies Ed25519 signatures. It allows Solana
 * programs to verify arbitrary Ed25519 signatures without consuming
 * excessive compute units.
 *
 * Program ID: Ed25519SigVerify111111111111111111111111111
 */

#ifndef SOL_ED25519_PROGRAM_H
#define SOL_ED25519_PROGRAM_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../txn/sol_pubkey.h"
#include "sol_system_program.h"

/*
 * Ed25519 Program ID
 * Base58: Ed25519SigVerify111111111111111111111111111
 */
extern const sol_pubkey_t SOL_ED25519_PROGRAM_ID;

/*
 * Ed25519 instruction data format:
 *
 * | Offset | Size | Description                         |
 * |--------|------|-------------------------------------|
 * | 0      | 1    | Number of signatures to verify      |
 * | 1      | 1    | Padding (0)                         |
 *
 * For each signature (12 bytes per entry):
 * | Offset | Size | Description                         |
 * |--------|------|-------------------------------------|
 * | +0     | 2    | Signature offset in instruction data|
 * | +2     | 2    | Signature instruction index         |
 * | +4     | 2    | Public key offset in instruction    |
 * | +6     | 2    | Public key instruction index        |
 * | +8     | 2    | Message data offset in instruction  |
 * | +10    | 2    | Message data size                   |
 * | +12    | 2    | Message instruction index           |
 * | +14    | 2    | Padding                             |
 *
 * After the signature entries, the actual data (signatures, pubkeys,
 * messages) follows, referenced by the offsets above.
 */

#define SOL_ED25519_SIGNATURE_SIZE      64
#define SOL_ED25519_PUBKEY_SIZE         32
#define SOL_ED25519_SIGNATURE_OFFSETS_SERIALIZED_SIZE 14
#define SOL_ED25519_SIGNATURE_OFFSETS_START 2
#define SOL_ED25519_DATA_START          (SOL_ED25519_SIGNATURE_OFFSETS_START + 14)

/*
 * Ed25519 signature offset structure
 */
typedef struct {
    uint16_t    signature_offset;           /* Offset to signature in data */
    uint16_t    signature_instruction_index; /* Which instruction contains sig */
    uint16_t    public_key_offset;          /* Offset to pubkey in data */
    uint16_t    public_key_instruction_index; /* Which instruction contains pubkey */
    uint16_t    message_data_offset;        /* Offset to message in data */
    uint16_t    message_data_size;          /* Size of message */
    uint16_t    message_instruction_index;  /* Which instruction contains message */
} sol_ed25519_signature_offsets_t;

/*
 * Process an Ed25519 signature verification instruction
 *
 * This function verifies one or more Ed25519 signatures. The instruction
 * data contains signature entries that reference offsets within the
 * instruction data where signatures, public keys, and messages can be found.
 *
 * @param ctx       Execution context
 * @return          SOL_OK if all signatures verify, error otherwise
 */
sol_err_t sol_ed25519_program_execute(sol_invoke_context_t* ctx);

/*
 * Create Ed25519 verification instruction data
 *
 * Helper function to create properly formatted instruction data for
 * Ed25519 signature verification.
 *
 * @param signatures        Array of signatures to verify
 * @param pubkeys           Array of public keys
 * @param messages          Array of message pointers
 * @param message_lens      Array of message lengths
 * @param count             Number of signatures to verify
 * @param out_data          Output buffer for instruction data
 * @param out_len           Input: buffer size, Output: data size
 * @return                  SOL_OK on success, error otherwise
 */
sol_err_t sol_ed25519_create_instruction(
    const sol_signature_t*  signatures,
    const sol_pubkey_t*     pubkeys,
    const uint8_t* const*   messages,
    const size_t*           message_lens,
    size_t                  count,
    uint8_t*                out_data,
    size_t*                 out_len
);

/*
 * Verify a single Ed25519 signature (precompile helper)
 *
 * Helper function for direct signature verification without instruction
 * processing overhead.
 *
 * @param signature     64-byte Ed25519 signature
 * @param pubkey        32-byte Ed25519 public key
 * @param message       Message that was signed
 * @param message_len   Length of message
 * @return              SOL_OK if signature is valid, error otherwise
 */
sol_err_t sol_ed25519_program_verify_sig(
    const uint8_t*  signature,
    const uint8_t*  pubkey,
    const uint8_t*  message,
    size_t          message_len
);

#endif /* SOL_ED25519_PROGRAM_H */
