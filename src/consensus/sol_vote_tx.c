/*
 * sol_vote_tx.c - Vote Transaction Builder Implementation
 */

#include "sol_vote_tx.h"
#include "sol_tower.h"
#include "../runtime/sol_bank.h"
#include "../runtime/sol_sysvar.h"
#include "../util/sol_log.h"
#include "../util/sol_alloc.h"
#include "../crypto/sol_sha256.h"

#include <string.h>

/*
 * Note: SOL_VOTE_PROGRAM_ID is defined in sol_types.c
 */

/*
 * Initialize vote transaction builder
 */
void
sol_vote_tx_builder_init(
    sol_vote_tx_builder_t*  builder,
    const sol_pubkey_t*     vote_account,
    const sol_keypair_t*    voter_keypair)
{
    memset(builder, 0, sizeof(*builder));

    if (vote_account) {
        memcpy(&builder->vote_account, vote_account, sizeof(sol_pubkey_t));
    }

    if (voter_keypair) {
        memcpy(&builder->voter_keypair, voter_keypair, sizeof(sol_keypair_t));
        /* Extract public key from keypair (last 32 bytes of 64-byte keypair) */
        memcpy(&builder->authorized_voter, &voter_keypair->bytes[32], 32);
    }
}

/*
 * Set the recent blockhash
 */
void
sol_vote_tx_builder_set_blockhash(
    sol_vote_tx_builder_t*  builder,
    const sol_hash_t*       blockhash)
{
    if (builder && blockhash) {
        memcpy(&builder->recent_blockhash, blockhash, sizeof(sol_hash_t));
    }
}

/*
 * Write compact-u16 encoding
 */
static size_t
write_compact_u16(uint8_t* out, uint16_t value)
{
    if (value < 0x80) {
        out[0] = (uint8_t)value;
        return 1;
    } else if (value < 0x4000) {
        out[0] = (uint8_t)((value & 0x7f) | 0x80);
        out[1] = (uint8_t)(value >> 7);
        return 2;
    } else {
        out[0] = (uint8_t)((value & 0x7f) | 0x80);
        out[1] = (uint8_t)(((value >> 7) & 0x7f) | 0x80);
        out[2] = (uint8_t)(value >> 14);
        return 3;
    }
}

/*
 * Serialize vote instruction data (legacy format)
 *
 * Format:
 *   4 bytes: instruction type (u32 LE)
 *   1 byte:  slots count
 *   N*8 bytes: slots (u64 LE each)
 *   32 bytes: bank hash
 *   9 bytes: optional timestamp (1 byte flag + 8 bytes if present)
 */
sol_err_t
sol_vote_instr_serialize(
    const sol_slot_t*   slots,
    uint8_t             slots_len,
    const sol_hash_t*   bank_hash,
    uint64_t            timestamp,
    uint8_t*            out,
    size_t              out_len,
    size_t*             written)
{
    size_t required = 4 + 1 + (slots_len * 8) + 32 + 1 + (timestamp ? 8 : 0);

    if (out_len < required) {
        return SOL_ERR_OVERFLOW;
    }

    size_t pos = 0;

    /* Instruction type: Vote (2) */
    uint32_t instr_type = SOL_VOTE_INSTR_VOTE;
    memcpy(out + pos, &instr_type, 4);
    pos += 4;

    /* Slots count */
    out[pos++] = slots_len;

    /* Slots (u64 LE) */
    for (uint8_t i = 0; i < slots_len; i++) {
        uint64_t slot = slots[i];
        memcpy(out + pos, &slot, 8);
        pos += 8;
    }

    /* Bank hash */
    memcpy(out + pos, bank_hash->bytes, 32);
    pos += 32;

    /* Optional timestamp */
    if (timestamp) {
        out[pos++] = 1;  /* Some */
        memcpy(out + pos, &timestamp, 8);
        pos += 8;
    } else {
        out[pos++] = 0;  /* None */
    }

    *written = pos;
    return SOL_OK;
}

/*
 * Serialize compact vote state update instruction data
 *
 * Format:
 *   4 bytes: instruction type (u32 LE)
 *   compact-u16: lockouts count
 *   N*(8+4) bytes: lockouts (slot u64 LE + confirmation u32 LE)
 *   1 byte: has root flag
 *   8 bytes: root slot (if has_root)
 *   32 bytes: bank hash
 *   1 byte: has timestamp flag
 *   8 bytes: timestamp (if has_timestamp)
 */
sol_err_t
sol_vote_instr_serialize_compact(
    const sol_lockout_t*    lockouts,
    uint8_t                 lockouts_len,
    sol_slot_t              root,
    const sol_hash_t*       bank_hash,
    uint64_t                timestamp,
    uint8_t*                out,
    size_t                  out_len,
    size_t*                 written)
{
    /* Estimate required size */
    size_t required = 4 + 3 + (lockouts_len * 12) + 1 + 8 + 32 + 1 + 8;

    if (out_len < required) {
        return SOL_ERR_OVERFLOW;
    }

    size_t pos = 0;

    /* Instruction type: CompactUpdateVoteState (11) */
    uint32_t instr_type = SOL_VOTE_INSTR_COMPACT_UPDATE_VOTE_STATE;
    memcpy(out + pos, &instr_type, 4);
    pos += 4;

    /* Lockouts count (compact-u16) */
    pos += write_compact_u16(out + pos, lockouts_len);

    /* Lockouts */
    for (uint8_t i = 0; i < lockouts_len; i++) {
        uint64_t slot = lockouts[i].slot;
        uint32_t conf = lockouts[i].confirmation_count;
        memcpy(out + pos, &slot, 8);
        pos += 8;
        memcpy(out + pos, &conf, 4);
        pos += 4;
    }

    /* Root slot (optional) */
    if (root > 0) {
        out[pos++] = 1;  /* Some */
        memcpy(out + pos, &root, 8);
        pos += 8;
    } else {
        out[pos++] = 0;  /* None */
    }

    /* Bank hash */
    memcpy(out + pos, bank_hash->bytes, 32);
    pos += 32;

    /* Timestamp (optional) */
    if (timestamp > 0) {
        out[pos++] = 1;  /* Some */
        memcpy(out + pos, &timestamp, 8);
        pos += 8;
    } else {
        out[pos++] = 0;  /* None */
    }

    *written = pos;
    return SOL_OK;
}

/*
 * Build a complete vote transaction
 */
static sol_err_t
build_vote_transaction(
    sol_vote_tx_builder_t*  builder,
    const uint8_t*          instr_data,
    size_t                  instr_data_len,
    uint8_t*                out_data,
    size_t                  out_len,
    size_t*                 written)
{
    /*
     * Transaction format:
     *   compact-u16: signature count (always 1)
     *   64 bytes: signature (authorized voter)
     *   Message:
     *     1 byte: num_required_signatures
     *     1 byte: num_readonly_signed
     *     1 byte: num_readonly_unsigned
     *     compact-u16: account keys count (5)
     *     5*32 bytes: account keys
     *     32 bytes: recent blockhash
     *     compact-u16: instruction count (1)
     *     Instruction:
     *       1 byte: program_id index
     *       compact-u16: accounts count
     *       N bytes: account indices
     *       compact-u16: data length
     *       N bytes: data
     */

    /* Account keys:
     *   0: authorized_voter (signer, readonly)
     *   1: vote_account (writable)
     *   2: sysvar_slot_hashes (readonly)
     *   3: sysvar_clock (readonly)
     *   4: vote_program (readonly)
     *
     * Instruction accounts (order expected by Solana vote program):
     *   [0] vote_account
     *   [1] sysvar_slot_hashes
     *   [2] sysvar_clock
     *   [3] authorized_voter (signer)
     */
    const uint8_t account_keys_len = 5;
    const uint8_t instr_accounts_len = 4;

    /* Calculate message size first (all counts fit in 1-byte compact-u16). */
    size_t instr_data_len_prefix = (instr_data_len < 0x80) ? 1 : (instr_data_len < 0x4000) ? 2 : 3;
    size_t msg_size =
        3 +                                 /* header */
        1 +                                 /* account_keys_len (compact-u16) */
        (size_t)account_keys_len * 32 +      /* account keys */
        32 +                                /* recent blockhash */
        1 +                                 /* instruction count (compact-u16) */
        1 +                                 /* program_id index */
        1 +                                 /* instruction accounts len (compact-u16) */
        (size_t)instr_accounts_len +         /* instruction account indices */
        instr_data_len_prefix +              /* instruction data len (compact-u16) */
        instr_data_len;                      /* instruction data */

    size_t tx_size =
        1 +     /* signature count (compact-u16) */
        64 +    /* signature */
        msg_size;

    if (out_len < tx_size) {
        return SOL_ERR_OVERFLOW;
    }

    size_t tx_pos = 0;

    /* Signature count (1) */
    out_data[tx_pos++] = 1;

    uint8_t* signature_start = out_data + tx_pos;
    tx_pos += 64;

    uint8_t* msg_start = out_data + tx_pos;
    size_t pos = 0;

    /* === Build Message === */

    /* Header */
    msg_start[pos++] = 1;  /* num_required_signatures */
    msg_start[pos++] = 1;  /* num_readonly_signed (authorized voter) */
    msg_start[pos++] = 3;  /* num_readonly_unsigned (slot hashes, clock, vote program) */

    /* Account keys count (compact-u16) */
    msg_start[pos++] = account_keys_len;

    /* Account keys */
    memcpy(msg_start + pos, &builder->authorized_voter, 32);
    pos += 32;
    memcpy(msg_start + pos, &builder->vote_account, 32);
    pos += 32;
    memcpy(msg_start + pos, &SOL_SYSVAR_SLOT_HASHES_ID, 32);
    pos += 32;
    memcpy(msg_start + pos, &SOL_SYSVAR_CLOCK_ID, 32);
    pos += 32;
    memcpy(msg_start + pos, &SOL_VOTE_PROGRAM_ID, 32);
    pos += 32;

    /* Recent blockhash */
    memcpy(msg_start + pos, &builder->recent_blockhash, 32);
    pos += 32;

    /* Instructions count (compact-u16) */
    msg_start[pos++] = 1;

    /* Instruction */
    msg_start[pos++] = 4;  /* program_id index (vote program) */

    /* accounts count (compact-u16) */
    msg_start[pos++] = instr_accounts_len;
    msg_start[pos++] = 1;  /* vote_account index */
    msg_start[pos++] = 2;  /* slot_hashes index */
    msg_start[pos++] = 3;  /* clock index */
    msg_start[pos++] = 0;  /* authorized_voter index (signer) */

    /* Instruction data length (compact-u16) */
    pos += write_compact_u16(msg_start + pos, (uint16_t)instr_data_len);

    /* Instruction data */
    memcpy(msg_start + pos, instr_data, instr_data_len);
    pos += instr_data_len;

    size_t actual_msg_size = pos;

    /* === Sign Message === */

    sol_signature_t signature;
    sol_ed25519_sign(
        &builder->voter_keypair,
        msg_start, actual_msg_size,
        &signature
    );

    /* Signature */
    memcpy(signature_start, signature.bytes, 64);

    *written = tx_pos + actual_msg_size;

    sol_log_debug("Built vote transaction: %zu bytes", *written);

    return SOL_OK;
}

/*
 * Create a vote transaction (legacy format)
 */
sol_err_t
sol_vote_tx_create(
    sol_vote_tx_builder_t*  builder,
    const sol_slot_t*       slots,
    uint8_t                 slots_len,
    const sol_hash_t*       bank_hash,
    uint8_t*                out_data,
    size_t                  out_len,
    size_t*                 written)
{
    if (!builder || !slots || !bank_hash || !out_data || !written) {
        return SOL_ERR_INVAL;
    }

    if (slots_len == 0 || slots_len > SOL_MAX_LOCKOUT_HISTORY) {
        return SOL_ERR_INVAL;
    }

    /* Serialize instruction data */
    uint8_t instr_data[512];
    size_t instr_len;

    sol_err_t err = sol_vote_instr_serialize(
        slots, slots_len, bank_hash, 0,
        instr_data, sizeof(instr_data), &instr_len
    );

    if (err != SOL_OK) {
        return err;
    }

    return build_vote_transaction(builder, instr_data, instr_len,
                                  out_data, out_len, written);
}

/*
 * Create a compact vote state update transaction
 */
sol_err_t
sol_vote_tx_create_compact(
    sol_vote_tx_builder_t*  builder,
    const sol_lockout_t*    lockouts,
    uint8_t                 lockouts_len,
    sol_slot_t              root,
    const sol_hash_t*       bank_hash,
    uint64_t                timestamp,
    uint8_t*                out_data,
    size_t                  out_len,
    size_t*                 written)
{
    if (!builder || !lockouts || !bank_hash || !out_data || !written) {
        return SOL_ERR_INVAL;
    }

    /* Serialize instruction data */
    uint8_t instr_data[512];
    size_t instr_len;

    sol_err_t err = sol_vote_instr_serialize_compact(
        lockouts, lockouts_len, root, bank_hash, timestamp,
        instr_data, sizeof(instr_data), &instr_len
    );

    if (err != SOL_OK) {
        return err;
    }

    return build_vote_transaction(builder, instr_data, instr_len,
                                  out_data, out_len, written);
}

/*
 * Create a vote transaction from tower state
 */
sol_err_t
sol_vote_tx_from_tower(
    sol_vote_tx_builder_t*  builder,
    const struct sol_tower* tower,
    struct sol_bank*        bank,
    uint8_t*                out_data,
    size_t                  out_len,
    size_t*                 written)
{
    if (!builder || !tower || !bank || !out_data || !written) {
        return SOL_ERR_INVAL;
    }

    /* Get vote state from tower */
    sol_vote_state_t vote_state;
    sol_err_t err = sol_tower_get_vote_state(tower, &vote_state);
    if (err != SOL_OK) {
        return err;
    }

    sol_hash_t bank_hash = {0};
    sol_bank_compute_hash(bank, &bank_hash);

    /* Use compact format */
    return sol_vote_tx_create_compact(
        builder,
        vote_state.votes,
        vote_state.votes_len,
        vote_state.root_slot,
        &bank_hash,
        0,  /* No timestamp */
        out_data, out_len, written
    );
}
