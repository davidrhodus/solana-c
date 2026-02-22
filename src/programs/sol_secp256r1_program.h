/*
 * sol_secp256r1_program.h - Secp256r1 Signature Verification Precompile
 *
 * This native program verifies secp256r1 (P-256) ECDSA signatures over
 * SHA-256(message). It is used as a precompile for efficient signature
 * verification within transactions.
 *
 * Program ID: Secp256r1SigVerify1111111111111111111111111
 */

#ifndef SOL_SECP256R1_PROGRAM_H
#define SOL_SECP256R1_PROGRAM_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "sol_system_program.h"

/* Instruction format constants (matches Agave v3.1.x) */
#define SOL_SECP256R1_MAX_SIGNATURES                 8
#define SOL_SECP256R1_SIGNATURE_SIZE                 64  /* r (32) || s (32) */
#define SOL_SECP256R1_PUBKEY_COMPRESSED_SIZE         33
#define SOL_SECP256R1_SIGNATURE_OFFSETS_SERIALIZED_SIZE 14
#define SOL_SECP256R1_SIGNATURE_OFFSETS_START        2

typedef struct {
    uint16_t signature_offset;
    uint16_t signature_instruction_index;
    uint16_t public_key_offset;
    uint16_t public_key_instruction_index;
    uint16_t message_data_offset;
    uint16_t message_data_size;
    uint16_t message_instruction_index;
} sol_secp256r1_signature_offsets_t;

sol_err_t sol_secp256r1_program_execute(sol_invoke_context_t* ctx);

#endif /* SOL_SECP256R1_PROGRAM_H */

