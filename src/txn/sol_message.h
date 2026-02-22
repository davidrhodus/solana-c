/*
 * sol_message.h - Solana transaction message structure
 *
 * A message is the payload of a transaction that gets signed.
 * It contains the accounts, instructions, and recent blockhash.
 *
 * Solana supports two message formats:
 * - Legacy: The original format
 * - V0: Versioned format with address lookup table support
 */

#ifndef SOL_MESSAGE_H
#define SOL_MESSAGE_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../util/sol_arena.h"
#include "sol_bincode.h"
#include "sol_pubkey.h"
#include "sol_instruction.h"

/*
 * Maximum accounts in a message
 */
#define SOL_MAX_MESSAGE_ACCOUNTS 256

/*
 * Maximum instructions in a message
 */
#define SOL_MAX_MESSAGE_INSTRUCTIONS 64

/*
 * Maximum address lookup tables in a v0 message
 */
#define SOL_MAX_ADDRESS_LOOKUP_TABLES 256

/*
 * Message version
 */
typedef enum {
    SOL_MESSAGE_VERSION_LEGACY = 0xFF,  /* No version prefix */
    SOL_MESSAGE_VERSION_V0 = 0,
} sol_message_version_t;

/*
 * Message header
 *
 * Describes the account organization in the message.
 */
typedef struct {
    uint8_t num_required_signatures;
    uint8_t num_readonly_signed;
    uint8_t num_readonly_unsigned;
} sol_message_header_t;

/*
 * Address lookup table reference (v0 messages only)
 */
typedef struct {
    sol_pubkey_t    account_key;           /* Lookup table address */
    const uint8_t*  writable_indices;      /* Indices of writable accounts */
    uint8_t         writable_indices_len;
    const uint8_t*  readonly_indices;      /* Indices of readonly accounts */
    uint8_t         readonly_indices_len;
} sol_address_lookup_t;

/*
 * Parsed message structure
 *
 * Contains the decoded message data. Pointers reference either the
 * original transaction bytes (zero-copy) or arena-allocated memory.
 */
typedef struct {
    sol_message_version_t       version;
    sol_message_header_t        header;

    /* Static account keys (directly in message) - zero-copy pointer */
    const sol_pubkey_t*         account_keys;
    uint8_t                     account_keys_len;

    /* Recent blockhash */
    sol_hash_t                  recent_blockhash;

    /* Instructions - parsed separately, may be NULL for zero-copy */
    sol_compiled_instruction_t* instructions;
    uint8_t                     instructions_len;
    sol_compiled_instruction_t  instructions_storage[SOL_MAX_MESSAGE_INSTRUCTIONS];

    /* Address lookup tables (v0 only) */
    sol_address_lookup_t*       address_lookups;
    uint8_t                     address_lookups_len;

    /*
     * Resolved accounts (after lookup table expansion)
     * For legacy messages, this points to account_keys.
     * For v0 messages, this includes accounts from lookup tables.
     */
    const sol_pubkey_t*         resolved_accounts;
    uint16_t                    resolved_accounts_len;

    /* Flags for resolved accounts */
    bool*                       is_writable;
    bool*                       is_signer;
} sol_message_t;

/*
 * Initialize a message structure
 */
static inline void
sol_message_init(sol_message_t* msg) {
    msg->version = SOL_MESSAGE_VERSION_LEGACY;
    msg->header.num_required_signatures = 0;
    msg->header.num_readonly_signed = 0;
    msg->header.num_readonly_unsigned = 0;
    msg->account_keys = NULL;
    msg->account_keys_len = 0;
    memset(&msg->recent_blockhash, 0, sizeof(sol_hash_t));
    msg->instructions = NULL;
    msg->instructions_len = 0;
    msg->address_lookups = NULL;
    msg->address_lookups_len = 0;
    msg->resolved_accounts = NULL;
    msg->resolved_accounts_len = 0;
    msg->is_writable = NULL;
    msg->is_signer = NULL;
}

/*
 * Decode message header from bincode
 */
static inline sol_err_t
sol_message_header_decode(sol_decoder_t* dec, sol_message_header_t* hdr) {
    SOL_DECODE_TRY(sol_decode_u8(dec, &hdr->num_required_signatures));
    SOL_DECODE_TRY(sol_decode_u8(dec, &hdr->num_readonly_signed));
    SOL_DECODE_TRY(sol_decode_u8(dec, &hdr->num_readonly_unsigned));
    return SOL_OK;
}

/*
 * Encode message header to bincode
 */
static inline sol_err_t
sol_message_header_encode(sol_encoder_t* enc, const sol_message_header_t* hdr) {
    SOL_ENCODE_TRY(sol_encode_u8(enc, hdr->num_required_signatures));
    SOL_ENCODE_TRY(sol_encode_u8(enc, hdr->num_readonly_signed));
    SOL_ENCODE_TRY(sol_encode_u8(enc, hdr->num_readonly_unsigned));
    return SOL_OK;
}

/*
 * Decode address lookup table reference from bincode
 */
static inline sol_err_t
sol_address_lookup_decode(sol_decoder_t* dec, sol_address_lookup_t* lookup) {
    SOL_DECODE_TRY(sol_pubkey_decode(dec, &lookup->account_key));

    /* Writable indices */
    uint16_t writable_len;
    SOL_DECODE_TRY(sol_decode_compact_u16(dec, &writable_len));
    lookup->writable_indices_len = (uint8_t)writable_len;

    const uint8_t* writable_data;
    SOL_DECODE_TRY(sol_decode_bytes(dec, writable_len, &writable_data));
    lookup->writable_indices = writable_data;

    /* Readonly indices */
    uint16_t readonly_len;
    SOL_DECODE_TRY(sol_decode_compact_u16(dec, &readonly_len));
    lookup->readonly_indices_len = (uint8_t)readonly_len;

    const uint8_t* readonly_data;
    SOL_DECODE_TRY(sol_decode_bytes(dec, readonly_len, &readonly_data));
    lookup->readonly_indices = readonly_data;

    return SOL_OK;
}

/*
 * Parse a legacy message from bincode
 *
 * The message structure will contain pointers into the decoder's data.
 */
sol_err_t sol_message_decode_legacy(
    sol_decoder_t*  dec,
    sol_message_t*  msg
);

/*
 * Parse a v0 message from bincode
 */
sol_err_t sol_message_decode_v0(
    sol_decoder_t*  dec,
    sol_message_t*  msg
);

/*
 * Parse a message (auto-detect version)
 *
 * The first byte indicates version:
 * - 0x00..0x7F: Legacy message (first byte is header.num_required_signatures)
 * - 0x80..0xFF: Versioned message (first byte is version prefix: 0x80 | version)
 */
sol_err_t sol_message_decode(
    sol_decoder_t*  dec,
    sol_message_t*  msg
);

/*
 * Parse a message with correct version detection
 *
 * Version detection:
 * - If first byte has bit 7 set (0x80-0xFF): versioned message
 * - Otherwise: legacy message
 */
sol_err_t sol_message_decode_versioned(
    sol_decoder_t*  dec,
    sol_message_t*  msg
);

/*
 * Encode a legacy message to bincode
 */
sol_err_t sol_message_encode_legacy(
    sol_encoder_t*        enc,
    const sol_message_t*  msg
);

/*
 * Encode a V0 message to bincode
 */
sol_err_t sol_message_encode_v0(
    sol_encoder_t*        enc,
    const sol_message_t*  msg
);

/*
 * Get the byte range that should be signed
 *
 * For legacy messages, this is the entire serialized message.
 * For v0 messages, this is the message with version prefix.
 */
sol_err_t sol_message_get_signing_data(
    const sol_message_t*  msg,
    const uint8_t*        full_data,
    size_t                full_data_len,
    const uint8_t**       signing_data,
    size_t*               signing_data_len
);

/*
 * Check if an account index is a signer
 */
static inline bool
sol_message_is_signer(const sol_message_t* msg, uint8_t index) {
    return index < msg->header.num_required_signatures;
}

/*
 * Check if an account index is writable
 */
static inline bool
sol_message_is_writable_index(const sol_message_t* msg, uint8_t index) {
    /* Signers are writable if not in readonly_signed section */
    if (index < msg->header.num_required_signatures) {
        return index < (msg->header.num_required_signatures - msg->header.num_readonly_signed);
    }
    /* Non-signers are writable if not in readonly_unsigned section */
    uint8_t num_writable_unsigned = msg->account_keys_len -
                                    msg->header.num_required_signatures -
                                    msg->header.num_readonly_unsigned;
    return index < (msg->header.num_required_signatures + num_writable_unsigned);
}

/*
 * Get the fee payer (first signer)
 */
static inline const sol_pubkey_t*
sol_message_fee_payer(const sol_message_t* msg) {
    if (msg->account_keys_len == 0) return NULL;
    return &msg->account_keys[0];
}

/*
 * Sanitize a message structure
 *
 * Validates that the message is well-formed:
 * - Account indices in instructions are valid
 * - Header values are consistent
 * - No duplicate accounts (optional)
 */
sol_err_t sol_message_sanitize(const sol_message_t* msg);

#endif /* SOL_MESSAGE_H */
