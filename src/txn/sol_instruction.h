/*
 * sol_instruction.h - Solana instruction structure
 *
 * An instruction is the basic unit of execution in Solana.
 * Each instruction specifies a program to invoke and the accounts
 * and data to pass to that program.
 */

#ifndef SOL_INSTRUCTION_H
#define SOL_INSTRUCTION_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "sol_bincode.h"
#include "sol_pubkey.h"

/*
 * Maximum instruction data size
 */
#define SOL_MAX_INSTRUCTION_DATA 1232

/*
 * Maximum accounts per instruction
 */
#define SOL_MAX_INSTRUCTION_ACCOUNTS 256

/*
 * Compiled instruction (references accounts by index)
 *
 * This is the format used in serialized transactions.
 * For zero-copy parsing, pointers reference the original data.
 */
typedef struct {
    uint8_t         program_id_index;     /* Index into message account keys */
    const uint8_t*  account_indices;      /* Indices into message account keys */
    uint8_t         account_indices_len;
    const uint8_t*  data;                 /* Instruction data */
    uint16_t        data_len;
} sol_compiled_instruction_t;

/*
 * Expanded instruction (with actual pubkeys)
 *
 * This is the format used when executing instructions.
 */
typedef struct {
    sol_pubkey_t   program_id;
    sol_pubkey_t*  accounts;
    uint8_t        accounts_len;
    uint8_t*       data;
    uint16_t       data_len;
} sol_instruction_t;

/*
 * Account meta for instructions - describes an account's role
 * Note: sol_account_meta_t is already defined in sol_types.h
 * for account storage. This is for instruction context.
 */
typedef struct {
    sol_pubkey_t  pubkey;
    bool          is_signer;
    bool          is_writable;
} sol_instr_account_meta_t;

/*
 * Decode a compiled instruction from bincode
 *
 * Note: The returned instruction contains pointers into the decoder's
 * data buffer. The instruction is only valid while the decoder's data is valid.
 */
static inline sol_err_t
sol_compiled_instruction_decode(
    sol_decoder_t*             dec,
    sol_compiled_instruction_t* instr
) {
    /* Program ID index */
    SOL_DECODE_TRY(sol_decode_u8(dec, &instr->program_id_index));

    /* Account indices (compact-u16 length prefix) */
    uint16_t account_len;
    SOL_DECODE_TRY(sol_decode_compact_u16(dec, &account_len));
    if (account_len > SOL_MAX_INSTRUCTION_ACCOUNTS) {
        return SOL_ERR_TX_MALFORMED;
    }
    instr->account_indices_len = (uint8_t)account_len;

    SOL_DECODE_TRY(sol_decode_bytes(dec, account_len, &instr->account_indices));

    /* Instruction data (compact-u16 length prefix) */
    uint16_t data_len;
    SOL_DECODE_TRY(sol_decode_compact_u16(dec, &data_len));
    if (data_len > SOL_MAX_INSTRUCTION_DATA) {
        return SOL_ERR_TX_MALFORMED;
    }
    instr->data_len = data_len;

    SOL_DECODE_TRY(sol_decode_bytes(dec, data_len, &instr->data));

    return SOL_OK;
}

/*
 * Encode a compiled instruction to bincode
 */
static inline sol_err_t
sol_compiled_instruction_encode(
    sol_encoder_t*                   enc,
    const sol_compiled_instruction_t* instr
) {
    SOL_ENCODE_TRY(sol_encode_u8(enc, instr->program_id_index));
    SOL_ENCODE_TRY(sol_encode_compact_u16(enc, instr->account_indices_len));
    SOL_ENCODE_TRY(sol_encode_bytes(enc, instr->account_indices, instr->account_indices_len));
    SOL_ENCODE_TRY(sol_encode_compact_u16(enc, instr->data_len));
    SOL_ENCODE_TRY(sol_encode_bytes(enc, instr->data, instr->data_len));
    return SOL_OK;
}

/*
 * Get the size of a compiled instruction when encoded
 */
static inline size_t
sol_compiled_instruction_encoded_size(const sol_compiled_instruction_t* instr) {
    size_t size = 1;  /* program_id_index */

    /* Account indices length (compact-u16) - uint8_t max 255, so max 2 bytes */
    size += (instr->account_indices_len < 0x80) ? 1 : 2;
    size += instr->account_indices_len;

    /* Data length (compact-u16) - uint16_t can need up to 3 bytes */
    if (instr->data_len < 0x80) size += 1;
    else if (instr->data_len < 0x4000) size += 2;
    else size += 3;

    size += instr->data_len;

    return size;
}

#endif /* SOL_INSTRUCTION_H */
