/*
 * sol_secp256k1_program.c - Secp256k1 Signature Verification Precompile
 *
 * Implementation of the Secp256k1/ECDSA signature verification native program.
 * This provides Ethereum compatibility by supporting ecrecover operations.
 */

#include "sol_secp256k1_program.h"
#include "../crypto/sol_keccak256.h"
#include "../crypto/sol_secp256k1.h"
#include "../runtime/sol_sysvar.h"
#include "../util/sol_log.h"
#include <string.h>

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

sol_err_t
sol_secp256k1_ecrecover(
    const uint8_t*  signature,
    uint8_t         recovery_id,
    const uint8_t*  message_hash,
    uint8_t*        out_address
) {
    return sol_secp256k1_ecrecover_address(signature, recovery_id, message_hash, out_address);
}

/*
 * Process Secp256k1 signature verification instruction
 */
sol_err_t
sol_secp256k1_program_execute(sol_invoke_context_t* ctx) {
    if (ctx == NULL) {
        return SOL_ERR_INVAL;
    }

    const uint8_t* data = ctx->instruction_data;
    uint16_t data_len = ctx->instruction_data_len;

    /* Need at least 1 byte for count */
    if (data_len < 1) {
        sol_log_warn("Secp256k1: instruction too short");
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* First byte is number of signatures */
    uint8_t num_signatures = data[0];

    /* No signatures - nothing to do (success) */
    if (num_signatures == 0) {
        return SOL_OK;
    }

    /* Calculate minimum required size */
    size_t offsets_size = (size_t)num_signatures * SOL_SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE;
    size_t min_size = SOL_SECP256K1_SIGNATURE_OFFSETS_START + offsets_size;

    if (data_len < min_size) {
        sol_log_warn("Secp256k1: instruction data too short for %u signatures", num_signatures);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Process each signature */
    const uint8_t* offsets_data = data + SOL_SECP256K1_SIGNATURE_OFFSETS_START;
    sol_account_t* instr_sysvar_account = NULL;
    const uint8_t* instr_sysvar_data = NULL;
    size_t instr_sysvar_len = 0;

    for (uint8_t i = 0; i < num_signatures; i++) {
        const uint8_t* entry = offsets_data + (i * SOL_SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE);

        /* Parse signature offsets */
        uint16_t sig_offset = read_u16_le(entry + 0);
        uint8_t sig_instr_index = entry[2];
        uint16_t eth_addr_offset = read_u16_le(entry + 3);
        uint8_t eth_addr_instr_index = entry[5];
        uint16_t msg_offset = read_u16_le(entry + 6);
        uint16_t msg_size = read_u16_le(entry + 8);
        uint8_t msg_instr_index = entry[10];

        if ((sig_instr_index != 0xFF || eth_addr_instr_index != 0xFF || msg_instr_index != 0xFF) &&
            instr_sysvar_data == NULL) {
            instr_sysvar_account = sol_bank_load_account(ctx->bank, &SOL_SYSVAR_INSTRUCTIONS_ID);
            if (instr_sysvar_account == NULL) {
                sol_log_warn("Secp256k1: instructions sysvar missing");
                return SOL_ERR_PROGRAM_INVALID_INSTR;
            }
            instr_sysvar_data = instr_sysvar_account->data;
            instr_sysvar_len = instr_sysvar_account->meta.data_len;
        }

        const uint8_t* sig_src = data;
        size_t sig_src_len = data_len;
        if (sig_instr_index != 0xFF) {
            sol_pubkey_t unused_prog = {0};
            const uint8_t* loaded = NULL;
            size_t loaded_len = 0;
            sol_err_t load_err = sol_instructions_sysvar_load_instruction(
                instr_sysvar_data, instr_sysvar_len, (uint16_t)sig_instr_index,
                &unused_prog, &loaded, &loaded_len);
            if (load_err != SOL_OK) {
                sol_log_warn("Secp256k1: signature %u instruction index out of bounds", i);
                if (instr_sysvar_account) sol_account_destroy(instr_sysvar_account);
                return SOL_ERR_PROGRAM_INVALID_INSTR;
            }
            sig_src = loaded;
            sig_src_len = loaded_len;
        }

        const uint8_t* addr_src = data;
        size_t addr_src_len = data_len;
        if (eth_addr_instr_index != 0xFF) {
            sol_pubkey_t unused_prog = {0};
            const uint8_t* loaded = NULL;
            size_t loaded_len = 0;
            sol_err_t load_err = sol_instructions_sysvar_load_instruction(
                instr_sysvar_data, instr_sysvar_len, (uint16_t)eth_addr_instr_index,
                &unused_prog, &loaded, &loaded_len);
            if (load_err != SOL_OK) {
                sol_log_warn("Secp256k1: eth address %u instruction index out of bounds", i);
                if (instr_sysvar_account) sol_account_destroy(instr_sysvar_account);
                return SOL_ERR_PROGRAM_INVALID_INSTR;
            }
            addr_src = loaded;
            addr_src_len = loaded_len;
        }

        const uint8_t* msg_src = data;
        size_t msg_src_len = data_len;
        if (msg_instr_index != 0xFF) {
            sol_pubkey_t unused_prog = {0};
            const uint8_t* loaded = NULL;
            size_t loaded_len = 0;
            sol_err_t load_err = sol_instructions_sysvar_load_instruction(
                instr_sysvar_data, instr_sysvar_len, (uint16_t)msg_instr_index,
                &unused_prog, &loaded, &loaded_len);
            if (load_err != SOL_OK) {
                sol_log_warn("Secp256k1: message %u instruction index out of bounds", i);
                if (instr_sysvar_account) sol_account_destroy(instr_sysvar_account);
                return SOL_ERR_PROGRAM_INVALID_INSTR;
            }
            msg_src = loaded;
            msg_src_len = loaded_len;
        }

        /* Validate signature offset (64 bytes sig + 1 byte recovery_id) */
        if ((size_t)sig_offset + SOL_SECP256K1_SIGNATURE_SIZE + 1 > sig_src_len) {
            sol_log_warn("Secp256k1: signature %u offset out of bounds", i);
            if (instr_sysvar_account) sol_account_destroy(instr_sysvar_account);
            return SOL_ERR_PROGRAM_INVALID_INSTR;
        }

        /* Validate Ethereum address offset */
        if ((size_t)eth_addr_offset + SOL_SECP256K1_ETH_ADDRESS_SIZE > addr_src_len) {
            sol_log_warn("Secp256k1: eth address %u offset out of bounds", i);
            if (instr_sysvar_account) sol_account_destroy(instr_sysvar_account);
            return SOL_ERR_PROGRAM_INVALID_INSTR;
        }

        /* Validate message offset and size */
        if ((size_t)msg_offset + msg_size > msg_src_len) {
            sol_log_warn("Secp256k1: message %u offset/size out of bounds", i);
            if (instr_sysvar_account) sol_account_destroy(instr_sysvar_account);
            return SOL_ERR_PROGRAM_INVALID_INSTR;
        }

        /* Get pointers to data */
        const uint8_t* signature = sig_src + sig_offset;
        uint8_t recovery_id = signature[SOL_SECP256K1_SIGNATURE_SIZE];
        const uint8_t* expected_eth_addr = addr_src + eth_addr_offset;
        const uint8_t* message = msg_src + msg_offset;

        /* Hash the message with Keccak256 */
        uint8_t message_hash[32];
        sol_keccak256_t msg_hash;
        sol_keccak256_hash(message, msg_size, &msg_hash);
        memcpy(message_hash, msg_hash.bytes, 32);

        /* Recover the Ethereum address from signature */
        uint8_t recovered_addr[SOL_SECP256K1_ETH_ADDRESS_SIZE];
        sol_err_t err = sol_secp256k1_ecrecover(
            signature, recovery_id, message_hash, recovered_addr);

        if (err != SOL_OK) {
            sol_log_warn("Secp256k1: signature %u recovery failed", i);
            if (instr_sysvar_account) sol_account_destroy(instr_sysvar_account);
            return SOL_ERR_INVALID_SIGNATURE;
        }

        /* Verify recovered address matches expected */
        if (memcmp(recovered_addr, expected_eth_addr, SOL_SECP256K1_ETH_ADDRESS_SIZE) != 0) {
            sol_log_warn("Secp256k1: signature %u address mismatch", i);
            if (instr_sysvar_account) sol_account_destroy(instr_sysvar_account);
            return SOL_ERR_INVALID_SIGNATURE;
        }

        sol_log_debug("Secp256k1: signature %u verified successfully", i);
    }

    if (instr_sysvar_account) {
        sol_account_destroy(instr_sysvar_account);
    }

    sol_log_debug("Secp256k1: all %u signatures verified", num_signatures);
    return SOL_OK;
}

/*
 * Create Secp256k1 verification instruction data
 */
sol_err_t
sol_secp256k1_create_instruction(
    const uint8_t* const*   signatures,
    const uint8_t* const*   eth_addresses,
    const uint8_t* const*   messages,
    const size_t*           message_lens,
    size_t                  count,
    uint8_t*                out_data,
    size_t*                 out_len
) {
    if (count == 0) {
        /* Empty instruction */
        if (*out_len < 1) {
            return SOL_ERR_TOO_LARGE;
        }
        out_data[0] = 0;
        *out_len = 1;
        return SOL_OK;
    }

    if (signatures == NULL || eth_addresses == NULL || messages == NULL || message_lens == NULL) {
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
    size_t header_size = 1;
    size_t offsets_size = count * SOL_SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE;
    size_t signatures_size = count * (SOL_SECP256K1_SIGNATURE_SIZE + 1);  /* +1 for recovery_id */
    size_t addresses_size = count * SOL_SECP256K1_ETH_ADDRESS_SIZE;
    size_t total_size = header_size + offsets_size + signatures_size + addresses_size + total_msg_size;

    if (*out_len < total_size) {
        *out_len = total_size;
        return SOL_ERR_TOO_LARGE;
    }

    /* Write header */
    out_data[0] = (uint8_t)count;

    /* Calculate data section offsets */
    size_t data_start = header_size + offsets_size;
    size_t sig_section = data_start;
    size_t addr_section = sig_section + signatures_size;
    size_t msg_section = addr_section + addresses_size;

    /* Write offsets and copy data */
    uint8_t* offsets_ptr = out_data + header_size;
    size_t msg_offset = msg_section;

    for (size_t i = 0; i < count; i++) {
        uint8_t* entry = offsets_ptr + (i * SOL_SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE);

        /* Calculate offsets for this entry */
        uint16_t sig_off = (uint16_t)(sig_section + (i * (SOL_SECP256K1_SIGNATURE_SIZE + 1)));
        uint16_t addr_off = (uint16_t)(addr_section + (i * SOL_SECP256K1_ETH_ADDRESS_SIZE));

        /* Write signature offset */
        write_u16_le(entry + 0, sig_off);
        entry[2] = 0xFF;  /* Current instruction */

        /* Write eth address offset */
        write_u16_le(entry + 3, addr_off);
        entry[5] = 0xFF;  /* Current instruction */

        /* Write message offset and size */
        write_u16_le(entry + 6, (uint16_t)msg_offset);
        write_u16_le(entry + 8, (uint16_t)message_lens[i]);
        entry[10] = 0xFF;  /* Current instruction */

        /* Copy signature (65 bytes: 64 sig + 1 recovery_id) */
        memcpy(out_data + sig_off, signatures[i], SOL_SECP256K1_SIGNATURE_SIZE + 1);

        /* Copy Ethereum address */
        memcpy(out_data + addr_off, eth_addresses[i], SOL_SECP256K1_ETH_ADDRESS_SIZE);

        /* Copy message */
        if (message_lens[i] > 0) {
            memcpy(out_data + msg_offset, messages[i], message_lens[i]);
        }

        msg_offset += message_lens[i];
    }

    *out_len = total_size;
    return SOL_OK;
}
