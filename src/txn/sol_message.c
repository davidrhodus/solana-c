/*
 * sol_message.c - Solana transaction message parsing
 */

#include "sol_message.h"
#include <string.h>

/*
 * Parse a legacy message from bincode
 */
sol_err_t
sol_message_decode_legacy(
    sol_decoder_t*  dec,
    sol_message_t*  msg
) {
    sol_message_init(msg);
    msg->version = SOL_MESSAGE_VERSION_LEGACY;

    /* Header */
    SOL_DECODE_TRY(sol_message_header_decode(dec, &msg->header));

    /* Validate header */
    if (msg->header.num_required_signatures == 0) {
        return SOL_ERR_TX_MALFORMED;
    }

    /* Account keys (compact-u16 length) */
    uint16_t num_accounts;
    SOL_DECODE_TRY(sol_decode_compact_u16(dec, &num_accounts));

    if (num_accounts == 0 || num_accounts > SOL_MAX_MESSAGE_ACCOUNTS) {
        return SOL_ERR_TX_MALFORMED;
    }
    if (num_accounts < msg->header.num_required_signatures) {
        return SOL_ERR_TX_MALFORMED;
    }

    msg->account_keys_len = (uint8_t)num_accounts;

    /* Decode account keys (zero-copy - point into decoder data) */
    const uint8_t* keys_data;
    SOL_DECODE_TRY(sol_decode_bytes(dec, num_accounts * SOL_PUBKEY_SIZE, &keys_data));
    msg->account_keys = (const sol_pubkey_t*)keys_data;

    /* Recent blockhash */
    const uint8_t* blockhash_data;
    SOL_DECODE_TRY(sol_decode_bytes(dec, SOL_HASH_SIZE, &blockhash_data));
    memcpy(msg->recent_blockhash.bytes, blockhash_data, SOL_HASH_SIZE);

    /* Instructions (compact-u16 length) */
    uint16_t num_instructions;
    SOL_DECODE_TRY(sol_decode_compact_u16(dec, &num_instructions));

    /* Legacy messages can legally contain 0 instructions (they still pay fees). */
    if (num_instructions > SOL_MAX_MESSAGE_INSTRUCTIONS) {
        return SOL_ERR_TX_MALFORMED;
    }

    msg->instructions_len = (uint8_t)num_instructions;
    msg->instructions = msg->instructions_storage;

    /* Decode and validate instructions (zero-copy pointers into decoder data). */
    for (uint8_t i = 0; i < num_instructions; i++) {
        sol_compiled_instruction_t* ix = &msg->instructions_storage[i];
        SOL_DECODE_TRY(sol_compiled_instruction_decode(dec, ix));

        /* Validate indices */
        if (ix->program_id_index >= num_accounts) {
            return SOL_ERR_TX_MALFORMED;
        }
        for (uint8_t j = 0; j < ix->account_indices_len; j++) {
            if (ix->account_indices[j] >= num_accounts) {
                return SOL_ERR_TX_MALFORMED;
            }
        }
    }

    /* For legacy messages, resolved accounts are the same as static keys */
    msg->resolved_accounts = msg->account_keys;
    msg->resolved_accounts_len = msg->account_keys_len;

    return SOL_OK;
}

/*
 * Parse a v0 message from bincode
 */
sol_err_t
sol_message_decode_v0(
    sol_decoder_t*  dec,
    sol_message_t*  msg
) {
    sol_message_init(msg);
    msg->version = SOL_MESSAGE_VERSION_V0;

    /* Header */
    SOL_DECODE_TRY(sol_message_header_decode(dec, &msg->header));

    if (msg->header.num_required_signatures == 0) {
        return SOL_ERR_TX_MALFORMED;
    }

    /* Static account keys */
    uint16_t num_accounts;
    SOL_DECODE_TRY(sol_decode_compact_u16(dec, &num_accounts));

    if (num_accounts > SOL_MAX_MESSAGE_ACCOUNTS) {
        return SOL_ERR_TX_MALFORMED;
    }

    msg->account_keys_len = (uint8_t)num_accounts;

    const uint8_t* keys_data;
    SOL_DECODE_TRY(sol_decode_bytes(dec, num_accounts * SOL_PUBKEY_SIZE, &keys_data));
    msg->account_keys = (const sol_pubkey_t*)keys_data;

    /* Recent blockhash */
    const uint8_t* blockhash_data;
    SOL_DECODE_TRY(sol_decode_bytes(dec, SOL_HASH_SIZE, &blockhash_data));
    memcpy(msg->recent_blockhash.bytes, blockhash_data, SOL_HASH_SIZE);

    /* Instructions */
    uint16_t num_instructions;
    SOL_DECODE_TRY(sol_decode_compact_u16(dec, &num_instructions));

    if (num_instructions > SOL_MAX_MESSAGE_INSTRUCTIONS) {
        return SOL_ERR_TX_MALFORMED;
    }

    msg->instructions_len = (uint8_t)num_instructions;
    msg->instructions = msg->instructions_storage;

    /* Parse instructions (zero-copy). Index validation requires lookup resolution. */
    for (uint8_t i = 0; i < num_instructions; i++) {
        SOL_DECODE_TRY(sol_compiled_instruction_decode(dec, &msg->instructions_storage[i]));
    }

    /* Address lookup tables */
    uint16_t num_lookups;
    SOL_DECODE_TRY(sol_decode_compact_u16(dec, &num_lookups));

    if (num_lookups > SOL_MAX_ADDRESS_LOOKUP_TABLES) {
        return SOL_ERR_TX_MALFORMED;
    }

    msg->address_lookups_len = (uint8_t)num_lookups;

    /* Parse lookup tables (zero-copy) */
    if (num_lookups > 0) {
        msg->address_lookups = msg->address_lookups_storage;
        for (uint8_t i = 0; i < num_lookups; i++) {
            SOL_DECODE_TRY(sol_address_lookup_decode(dec, &msg->address_lookups_storage[i]));
        }
    } else {
        msg->address_lookups = NULL;
    }

    /* Note: Address lookup table resolution requires external account data
     * and must be done separately by the caller. */

    return SOL_OK;
}

/*
 * Parse a message (auto-detect version)
 */
sol_err_t
sol_message_decode(
    sol_decoder_t*  dec,
    sol_message_t*  msg
) {
    return sol_message_decode_versioned(dec, msg);
}

/* Correct message decode with proper version detection. */
sol_err_t
sol_message_decode_versioned(
    sol_decoder_t*  dec,
    sol_message_t*  msg
) {
    if (!sol_decoder_has(dec, 1)) {
        return SOL_ERR_TRUNCATED;
    }

    uint8_t first_byte = dec->data[dec->pos];

    if (first_byte & 0x80) {
        /* Versioned message */
        uint8_t version_byte;
        SOL_DECODE_TRY(sol_decode_u8(dec, &version_byte));

        uint8_t version = version_byte & 0x7F;
        if (version == 0) {
            return sol_message_decode_v0(dec, msg);
        } else {
            return SOL_ERR_UNSUPPORTED;
        }
    } else {
        /* Legacy message */
        return sol_message_decode_legacy(dec, msg);
    }
}

/*
 * Sanitize a message
 */
sol_err_t
sol_message_sanitize(const sol_message_t* msg) {
    /* Check header consistency */
    if (msg->header.num_required_signatures == 0) {
        return SOL_ERR_TX_SANITIZE;
    }

    uint8_t total_signed = msg->header.num_required_signatures;
    uint8_t readonly_signed = msg->header.num_readonly_signed;
    uint8_t readonly_unsigned = msg->header.num_readonly_unsigned;

    if (readonly_signed > total_signed) {
        return SOL_ERR_TX_SANITIZE;
    }

    /* Account count must be sufficient */
    if (msg->account_keys_len < total_signed) {
        return SOL_ERR_TX_SANITIZE;
    }

    uint8_t total_accounts = msg->account_keys_len;
    uint8_t unsigned_accounts = total_accounts - total_signed;

    if (readonly_unsigned > unsigned_accounts) {
        return SOL_ERR_TX_SANITIZE;
    }

    /* Fee payer must be writable signer */
    if (total_signed == 0) {
        return SOL_ERR_TX_SANITIZE;
    }

    /* Fee payer (index 0) must not be readonly */
    if (readonly_signed >= total_signed) {
        return SOL_ERR_TX_SANITIZE;
    }

    return SOL_OK;
}

/*
 * Encode an address lookup table reference
 */
static sol_err_t
sol_address_lookup_encode(sol_encoder_t* enc, const sol_address_lookup_t* lookup) {
    /* Account key */
    SOL_ENCODE_TRY(sol_pubkey_encode(enc, &lookup->account_key));

    /* Writable indices */
    SOL_ENCODE_TRY(sol_encode_compact_u16(enc, lookup->writable_indices_len));
    if (lookup->writable_indices_len > 0 && lookup->writable_indices) {
        SOL_ENCODE_TRY(sol_encode_bytes(enc, lookup->writable_indices, lookup->writable_indices_len));
    }

    /* Readonly indices */
    SOL_ENCODE_TRY(sol_encode_compact_u16(enc, lookup->readonly_indices_len));
    if (lookup->readonly_indices_len > 0 && lookup->readonly_indices) {
        SOL_ENCODE_TRY(sol_encode_bytes(enc, lookup->readonly_indices, lookup->readonly_indices_len));
    }

    return SOL_OK;
}

/*
 * Encode a V0 message
 */
sol_err_t
sol_message_encode_v0(
    sol_encoder_t*        enc,
    const sol_message_t*  msg
) {
    if (!enc || !msg) return SOL_ERR_INVAL;
    if (msg->account_keys_len > 0 && msg->account_keys == NULL) return SOL_ERR_INVAL;
    if (msg->instructions_len > 0 && msg->instructions == NULL) return SOL_ERR_INVAL;
    if (msg->address_lookups_len > 0 && msg->address_lookups == NULL) return SOL_ERR_INVAL;

    /* Header */
    SOL_ENCODE_TRY(sol_message_header_encode(enc, &msg->header));

    /* Account keys */
    SOL_ENCODE_TRY(sol_encode_compact_u16(enc, msg->account_keys_len));
    for (uint8_t i = 0; i < msg->account_keys_len; i++) {
        SOL_ENCODE_TRY(sol_pubkey_encode(enc, &msg->account_keys[i]));
    }

    /* Recent blockhash */
    SOL_ENCODE_TRY(sol_encode_bytes(enc, msg->recent_blockhash.bytes, SOL_HASH_SIZE));

    /* Instructions */
    SOL_ENCODE_TRY(sol_encode_compact_u16(enc, msg->instructions_len));
    for (uint8_t i = 0; i < msg->instructions_len; i++) {
        SOL_ENCODE_TRY(sol_compiled_instruction_encode(enc, &msg->instructions[i]));
    }

    /* Address lookup tables */
    SOL_ENCODE_TRY(sol_encode_compact_u16(enc, msg->address_lookups_len));
    for (uint8_t i = 0; i < msg->address_lookups_len; i++) {
        SOL_ENCODE_TRY(sol_address_lookup_encode(enc, &msg->address_lookups[i]));
    }

    return SOL_OK;
}

/*
 * Encode a legacy message
 */
sol_err_t
sol_message_encode_legacy(
    sol_encoder_t*        enc,
    const sol_message_t*  msg
) {
    if (!enc || !msg) return SOL_ERR_INVAL;
    if (msg->account_keys_len > 0 && msg->account_keys == NULL) return SOL_ERR_INVAL;
    if (msg->instructions_len > 0 && msg->instructions == NULL) return SOL_ERR_INVAL;

    /* Header */
    SOL_ENCODE_TRY(sol_message_header_encode(enc, &msg->header));

    /* Account keys */
    SOL_ENCODE_TRY(sol_encode_compact_u16(enc, msg->account_keys_len));
    for (uint8_t i = 0; i < msg->account_keys_len; i++) {
        SOL_ENCODE_TRY(sol_pubkey_encode(enc, &msg->account_keys[i]));
    }

    /* Recent blockhash */
    SOL_ENCODE_TRY(sol_encode_bytes(enc, msg->recent_blockhash.bytes, SOL_HASH_SIZE));

    /* Instructions */
    SOL_ENCODE_TRY(sol_encode_compact_u16(enc, msg->instructions_len));
    for (uint8_t i = 0; i < msg->instructions_len; i++) {
        SOL_ENCODE_TRY(sol_compiled_instruction_encode(enc, &msg->instructions[i]));
    }

    return SOL_OK;
}

/*
 * Get signing data
 */
sol_err_t
sol_message_get_signing_data(
    const sol_message_t*  msg,
    const uint8_t*        full_data,
    size_t                full_data_len,
    const uint8_t**       signing_data,
    size_t*               signing_data_len
) {
    (void)msg;  /* May be used in future for version-specific handling */

    /* For both legacy and versioned messages, the signing data is
     * the serialized message (including version prefix for v0). */
    *signing_data = full_data;
    *signing_data_len = full_data_len;

    return SOL_OK;
}
