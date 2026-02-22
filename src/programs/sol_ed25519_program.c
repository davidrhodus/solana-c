/*
 * sol_ed25519_program.c - Ed25519 Signature Verification Precompile
 *
 * Implementation of the Ed25519 signature verification native program.
 */

#include "sol_ed25519_program.h"
#include "../crypto/sol_ed25519.h"
#include "../runtime/sol_sysvar.h"
#include "../util/sol_log.h"
#include <string.h>

/*
 * Ed25519 Program ID: Ed25519SigVerify111111111111111111111111111
 * (Defined in sol_types.c)
 */

/*
 * Parse u16 from little-endian bytes
 */
static inline uint16_t
read_u16_le(const uint8_t* data) {
    return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

/*
 * Write u16 to little-endian bytes
 */
static inline void
write_u16_le(uint8_t* data, uint16_t value) {
    data[0] = (uint8_t)(value & 0xFF);
    data[1] = (uint8_t)((value >> 8) & 0xFF);
}

/*
 * Verify a single Ed25519 signature for the precompile
 */
sol_err_t
sol_ed25519_program_verify_sig(
    const uint8_t*  signature,
    const uint8_t*  pubkey,
    const uint8_t*  message,
    size_t          message_len
) {
    if (signature == NULL || pubkey == NULL) {
        return SOL_ERR_INVAL;
    }

    if (message == NULL && message_len > 0) {
        return SOL_ERR_INVAL;
    }

    /* Use crypto library for verification */
    sol_pubkey_t pk;
    memcpy(pk.bytes, pubkey, SOL_ED25519_PUBKEY_SIZE);

    sol_signature_t sig;
    memcpy(sig.bytes, signature, SOL_ED25519_SIGNATURE_SIZE);

    bool valid = sol_ed25519_verify(&pk, message, message_len, &sig);
    return valid ? SOL_OK : SOL_ERR_INVALID_SIGNATURE;
}

/*
 * Process Ed25519 signature verification instruction
 */
sol_err_t
sol_ed25519_program_execute(sol_invoke_context_t* ctx) {
    if (ctx == NULL) {
        return SOL_ERR_INVAL;
    }

    const uint8_t* data = ctx->instruction_data;
    uint16_t data_len = ctx->instruction_data_len;

    /* Need at least 2 bytes for header */
    if (data_len < 2) {
        sol_log_warn("Ed25519: instruction too short");
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* First byte is number of signatures */
    uint8_t num_signatures = data[0];

    /* Second byte is padding, should be 0 */
    if (data[1] != 0) {
        sol_log_warn("Ed25519: invalid padding byte");
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* No signatures - nothing to do (success) */
    if (num_signatures == 0) {
        return SOL_OK;
    }

    /* Calculate minimum required size */
    size_t offsets_size = (size_t)num_signatures * SOL_ED25519_SIGNATURE_OFFSETS_SERIALIZED_SIZE;
    size_t min_size = SOL_ED25519_SIGNATURE_OFFSETS_START + offsets_size;

    if (data_len < min_size) {
        sol_log_warn("Ed25519: instruction data too short for %u signatures", num_signatures);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Process each signature */
    const uint8_t* offsets_data = data + SOL_ED25519_SIGNATURE_OFFSETS_START;
    sol_account_t* instr_sysvar_account = NULL;
    const uint8_t* instr_sysvar_data = NULL;
    size_t instr_sysvar_len = 0;

    for (uint8_t i = 0; i < num_signatures; i++) {
        const uint8_t* entry = offsets_data + (i * SOL_ED25519_SIGNATURE_OFFSETS_SERIALIZED_SIZE);

        /* Parse signature offsets */
        uint16_t sig_offset = read_u16_le(entry + 0);
        uint16_t sig_instr_index = read_u16_le(entry + 2);
        uint16_t pk_offset = read_u16_le(entry + 4);
        uint16_t pk_instr_index = read_u16_le(entry + 6);
        uint16_t msg_offset = read_u16_le(entry + 8);
        uint16_t msg_size = read_u16_le(entry + 10);
        uint16_t msg_instr_index = read_u16_le(entry + 12);

        if ((sig_instr_index != 0xFFFF || pk_instr_index != 0xFFFF || msg_instr_index != 0xFFFF) &&
            instr_sysvar_data == NULL) {
            instr_sysvar_account = sol_bank_load_account(ctx->bank, &SOL_SYSVAR_INSTRUCTIONS_ID);
            if (instr_sysvar_account == NULL) {
                sol_log_warn("Ed25519: instructions sysvar missing");
                return SOL_ERR_PROGRAM_INVALID_INSTR;
            }
            instr_sysvar_data = instr_sysvar_account->data;
            instr_sysvar_len = instr_sysvar_account->meta.data_len;
        }

        const uint8_t* sig_src = data;
        size_t sig_src_len = data_len;
        if (sig_instr_index != 0xFFFF) {
            sol_pubkey_t unused_prog = {0};
            sol_err_t load_err = sol_instructions_sysvar_load_instruction(
                instr_sysvar_data, instr_sysvar_len, sig_instr_index,
                &unused_prog, &sig_src, &sig_src_len);
            if (load_err != SOL_OK) {
                sol_log_warn("Ed25519: signature %u instruction index out of bounds", i);
                if (instr_sysvar_account) sol_account_destroy(instr_sysvar_account);
                return SOL_ERR_PROGRAM_INVALID_INSTR;
            }
        }

        const uint8_t* pk_src = data;
        size_t pk_src_len = data_len;
        if (pk_instr_index != 0xFFFF) {
            sol_pubkey_t unused_prog = {0};
            sol_err_t load_err = sol_instructions_sysvar_load_instruction(
                instr_sysvar_data, instr_sysvar_len, pk_instr_index,
                &unused_prog, &pk_src, &pk_src_len);
            if (load_err != SOL_OK) {
                sol_log_warn("Ed25519: public key %u instruction index out of bounds", i);
                if (instr_sysvar_account) sol_account_destroy(instr_sysvar_account);
                return SOL_ERR_PROGRAM_INVALID_INSTR;
            }
        }

        const uint8_t* msg_src = data;
        size_t msg_src_len = data_len;
        if (msg_instr_index != 0xFFFF) {
            sol_pubkey_t unused_prog = {0};
            sol_err_t load_err = sol_instructions_sysvar_load_instruction(
                instr_sysvar_data, instr_sysvar_len, msg_instr_index,
                &unused_prog, &msg_src, &msg_src_len);
            if (load_err != SOL_OK) {
                sol_log_warn("Ed25519: message %u instruction index out of bounds", i);
                if (instr_sysvar_account) sol_account_destroy(instr_sysvar_account);
                return SOL_ERR_PROGRAM_INVALID_INSTR;
            }
        }

        /* Validate signature offset and size */
        if ((size_t)sig_offset + SOL_ED25519_SIGNATURE_SIZE > sig_src_len) {
            sol_log_warn("Ed25519: signature %u offset out of bounds", i);
            if (instr_sysvar_account) sol_account_destroy(instr_sysvar_account);
            return SOL_ERR_PROGRAM_INVALID_INSTR;
        }

        /* Validate public key offset and size */
        if ((size_t)pk_offset + SOL_ED25519_PUBKEY_SIZE > pk_src_len) {
            sol_log_warn("Ed25519: public key %u offset out of bounds", i);
            if (instr_sysvar_account) sol_account_destroy(instr_sysvar_account);
            return SOL_ERR_PROGRAM_INVALID_INSTR;
        }

        /* Validate message offset and size */
        if ((size_t)msg_offset + msg_size > msg_src_len) {
            sol_log_warn("Ed25519: message %u offset/size out of bounds", i);
            if (instr_sysvar_account) sol_account_destroy(instr_sysvar_account);
            return SOL_ERR_PROGRAM_INVALID_INSTR;
        }

        /* Get pointers to signature, pubkey, and message */
        const uint8_t* signature = sig_src + sig_offset;
        const uint8_t* pubkey = pk_src + pk_offset;
        const uint8_t* message = (msg_size > 0) ? (msg_src + msg_offset) : NULL;

        /* Verify the signature */
        sol_err_t err = sol_ed25519_program_verify_sig(signature, pubkey, message, msg_size);
        if (err != SOL_OK) {
            sol_log_warn("Ed25519: signature %u verification failed", i);
            if (instr_sysvar_account) sol_account_destroy(instr_sysvar_account);
            return SOL_ERR_INVALID_SIGNATURE;
        }

        sol_log_debug("Ed25519: signature %u verified successfully", i);
    }

    if (instr_sysvar_account) {
        sol_account_destroy(instr_sysvar_account);
    }

    sol_log_debug("Ed25519: all %u signatures verified", num_signatures);
    return SOL_OK;
}

/*
 * Create Ed25519 verification instruction data
 */
sol_err_t
sol_ed25519_create_instruction(
    const sol_signature_t*  signatures,
    const sol_pubkey_t*     pubkeys,
    const uint8_t* const*   messages,
    const size_t*           message_lens,
    size_t                  count,
    uint8_t*                out_data,
    size_t*                 out_len
) {
    if (count == 0) {
        /* Empty instruction */
        if (*out_len < 2) {
            return SOL_ERR_TOO_LARGE;
        }
        out_data[0] = 0;
        out_data[1] = 0;
        *out_len = 2;
        return SOL_OK;
    }

    if (signatures == NULL || pubkeys == NULL || messages == NULL || message_lens == NULL) {
        return SOL_ERR_INVAL;
    }

    if (count > 255) {
        return SOL_ERR_INVAL;
    }

    /* Calculate total message size */
    size_t total_msg_size = 0;
    for (size_t i = 0; i < count; i++) {
        total_msg_size += message_lens[i];
    }

    /* Calculate total size needed */
    size_t header_size = 2;
    size_t offsets_size = count * SOL_ED25519_SIGNATURE_OFFSETS_SERIALIZED_SIZE;
    size_t signatures_size = count * SOL_ED25519_SIGNATURE_SIZE;
    size_t pubkeys_size = count * SOL_ED25519_PUBKEY_SIZE;
    size_t total_size = header_size + offsets_size + signatures_size + pubkeys_size + total_msg_size;

    if (*out_len < total_size) {
        *out_len = total_size;
        return SOL_ERR_TOO_LARGE;
    }

    /* Write header */
    out_data[0] = (uint8_t)count;
    out_data[1] = 0;  /* Padding */

    /* Calculate data section offsets */
    size_t data_start = header_size + offsets_size;
    size_t sig_section = data_start;
    size_t pk_section = sig_section + signatures_size;
    size_t msg_section = pk_section + pubkeys_size;

    /* Write offsets and copy data */
    uint8_t* offsets_ptr = out_data + header_size;
    size_t msg_offset = msg_section;

    for (size_t i = 0; i < count; i++) {
        uint8_t* entry = offsets_ptr + (i * SOL_ED25519_SIGNATURE_OFFSETS_SERIALIZED_SIZE);

        /* Write signature offset */
        uint16_t sig_off = (uint16_t)(sig_section + (i * SOL_ED25519_SIGNATURE_SIZE));
        write_u16_le(entry + 0, sig_off);
        write_u16_le(entry + 2, 0xFFFF);  /* Current instruction */

        /* Write public key offset */
        uint16_t pk_off = (uint16_t)(pk_section + (i * SOL_ED25519_PUBKEY_SIZE));
        write_u16_le(entry + 4, pk_off);
        write_u16_le(entry + 6, 0xFFFF);  /* Current instruction */

        /* Write message offset and size */
        write_u16_le(entry + 8, (uint16_t)msg_offset);
        write_u16_le(entry + 10, (uint16_t)message_lens[i]);
        write_u16_le(entry + 12, 0xFFFF);  /* Current instruction */

        /* Copy signature */
        memcpy(out_data + sig_off, signatures[i].bytes, SOL_ED25519_SIGNATURE_SIZE);

        /* Copy public key */
        memcpy(out_data + pk_off, pubkeys[i].bytes, SOL_ED25519_PUBKEY_SIZE);

        /* Copy message */
        if (message_lens[i] > 0) {
            memcpy(out_data + msg_offset, messages[i], message_lens[i]);
        }

        msg_offset += message_lens[i];
    }

    *out_len = total_size;
    return SOL_OK;
}
