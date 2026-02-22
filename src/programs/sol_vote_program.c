/*
 * sol_vote_program.c - Vote Program Implementation
 */

#include "sol_vote_program.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include "../runtime/sol_account.h"
#include "../runtime/sol_sysvar.h"
#include <string.h>

/* Note: SOL_VOTE_PROGRAM_ID is defined in sol_types.c */

static sol_err_t
verify_hash_against_slot_hashes(sol_bank_t* bank, sol_slot_t slot, const sol_hash_t* hash) {
    if (!bank || !hash) {
        return SOL_ERR_INVAL;
    }

    sol_account_t* slot_hashes_account =
        sol_bank_load_account(bank, &SOL_SYSVAR_SLOT_HASHES_ID);
    if (!slot_hashes_account) {
        return SOL_ERR_SLOT_HASH_MISMATCH;
    }

    sol_slot_hashes_t slot_hashes;
    sol_slot_hashes_init(&slot_hashes);
    sol_err_t err = sol_slot_hashes_deserialize(
        &slot_hashes, slot_hashes_account->data, slot_hashes_account->meta.data_len);
    sol_account_destroy(slot_hashes_account);
    if (err != SOL_OK) {
        return err;
    }

    const sol_hash_t* expected = sol_slot_hashes_get(&slot_hashes, slot);
    if (!expected || !sol_hash_eq(expected, hash)) {
        return SOL_ERR_SLOT_HASH_MISMATCH;
    }

    return SOL_OK;
}

/*
 * Get account from context
 */
static sol_err_t
get_account(sol_invoke_context_t* ctx, uint8_t index,
            const sol_pubkey_t** pubkey, sol_account_t** account) {
    if (index >= ctx->account_indices_len) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    uint8_t key_index = ctx->account_indices[index];
    if (key_index >= ctx->account_keys_len) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    *pubkey = &ctx->account_keys[key_index];
    sol_slot_t ss = 0;
    *account = sol_bank_load_account_ex(ctx->bank, *pubkey, &ss);

    /* Simulate Agave's clean_accounts: only filter snapshot-era zombies */
    sol_slot_t zfs = sol_bank_zombie_filter_slot(ctx->bank);
    if (*account && (*account)->meta.lamports == 0 && zfs > 0 && ss <= zfs) {
        sol_account_destroy(*account);
        *account = NULL;
    }

    /* Agave creates a default account for any key not in the DB */
    if (!*account) {
        *account = sol_calloc(1, sizeof(sol_account_t));
        if (*account) {
            (*account)->meta.owner = SOL_SYSTEM_PROGRAM_ID;
            (*account)->meta.rent_epoch = UINT64_MAX;
        }
    }

    return SOL_OK;
}

/*
 * Check if account at instruction index is a signer
 */
static bool
is_signer(sol_invoke_context_t* ctx, uint8_t index) {
    if (index >= ctx->account_indices_len) {
        return false;
    }
    uint8_t key_index = ctx->account_indices[index];
    if (ctx->is_signer != NULL && key_index < ctx->account_keys_len) {
        return ctx->is_signer[key_index];
    }
    /* Fallback: first num_signers accounts are signers */
    return key_index < ctx->num_signers;
}

void
sol_vote_state_init(sol_vote_state_t* state, const sol_vote_init_t* init) {
    memset(state, 0, sizeof(sol_vote_state_t));

    if (init) {
        state->onchain_version = 2; /* Current mainnet bincode vote state */
        state->node_pubkey = init->node_pubkey;
        state->authorized_voter = init->authorized_voter;
        state->authorized_withdrawer = init->authorized_withdrawer;
        state->commission = init->commission;

        state->authorized_voters_len = 1;
        state->authorized_voters[0].epoch = 0;
        state->authorized_voters[0].pubkey = init->authorized_voter;
    }

    state->has_root = false;
    state->prior_voters_idx = 31;
    state->prior_voters_is_empty = true;
}

static void
vote_prior_voters_push(sol_vote_state_t* state,
                       const sol_pubkey_t* pubkey,
                       uint64_t start_epoch,
                       uint64_t end_epoch) {
    if (!state || !pubkey) return;

    uint64_t next = (state->prior_voters_idx + 1u) % 32u;
    state->prior_voters[next].pubkey = *pubkey;
    state->prior_voters[next].start_epoch = start_epoch;
    state->prior_voters[next].end_epoch = end_epoch;
    state->prior_voters_idx = next;
    state->prior_voters_is_empty = false;
}

/*
 * Look up the authorized voter for a given epoch.
 * Returns the voter for the largest epoch <= target_epoch.
 * Matches Agave's AuthorizedVoters::get_authorized_voter().
 */
static bool
vote_get_authorized_voter_for_epoch(const sol_vote_state_t* state,
                                     uint64_t target_epoch,
                                     sol_pubkey_t* out) {
    if (!state || !out || state->authorized_voters_len == 0) {
        return false;
    }

    /* authorized_voters is sorted by epoch ascending.
       Find the entry with the largest epoch <= target_epoch. */
    bool found = false;
    for (uint8_t i = 0; i < state->authorized_voters_len; i++) {
        if (state->authorized_voters[i].epoch <= target_epoch) {
            *out = state->authorized_voters[i].pubkey;
            found = true;
        } else {
            break; /* past target epoch */
        }
    }
    return found;
}

static void
vote_authorized_voters_set(sol_vote_state_t* state,
                           uint64_t epoch,
                           const sol_pubkey_t* authorized_voter) {
    if (!state || !authorized_voter) return;

    uint8_t len = state->authorized_voters_len;

    for (uint8_t i = 0; i < len; i++) {
        if (state->authorized_voters[i].epoch == epoch) {
            state->authorized_voters[i].pubkey = *authorized_voter;
            state->authorized_voter = *authorized_voter;
            return;
        }
    }

    /* Insert in ascending epoch order. */
    uint8_t insert_at = len;
    for (uint8_t i = 0; i < len; i++) {
        if (state->authorized_voters[i].epoch > epoch) {
            insert_at = i;
            break;
        }
    }

    if (len >= SOL_MAX_AUTHORIZED_VOTERS) {
        /* Drop the oldest entry to make room. */
        memmove(&state->authorized_voters[0],
                &state->authorized_voters[1],
                (SOL_MAX_AUTHORIZED_VOTERS - 1u) * sizeof(state->authorized_voters[0]));
        len = SOL_MAX_AUTHORIZED_VOTERS - 1u;
        if (insert_at > 0) insert_at--;
    }

    if (insert_at < len) {
        memmove(&state->authorized_voters[insert_at + 1],
                &state->authorized_voters[insert_at],
                (len - insert_at) * sizeof(state->authorized_voters[0]));
    }

    state->authorized_voters[insert_at].epoch = epoch;
    state->authorized_voters[insert_at].pubkey = *authorized_voter;
    state->authorized_voters_len = (uint8_t)(len + 1u);
    state->authorized_voter = *authorized_voter;
}

static sol_err_t
vote_decode_option_u64(sol_decoder_t* dec, bool* out_has, uint64_t* out_val) {
    if (!dec) return SOL_ERR_INVAL;
    uint8_t tag = 0;
    SOL_DECODE_TRY(sol_decode_u8(dec, &tag));
    if (tag == 0) {
        if (out_has) *out_has = false;
        if (out_val) *out_val = 0;
        return SOL_OK;
    }
    if (tag != 1) {
        return SOL_ERR_DECODE;
    }
    uint64_t v = 0;
    SOL_DECODE_TRY(sol_decode_u64(dec, &v));
    if (out_has) *out_has = true;
    if (out_val) *out_val = v;
    return SOL_OK;
}

static sol_err_t
vote_encode_option_u64(sol_encoder_t* enc, bool has, uint64_t val) {
    if (!enc) return SOL_ERR_INVAL;
    SOL_ENCODE_TRY(sol_encode_u8(enc, has ? 1u : 0u));
    if (has) {
        SOL_ENCODE_TRY(sol_encode_u64(enc, val));
    }
    return SOL_OK;
}

static sol_err_t
vote_decode_prior_voters_circbuf(sol_decoder_t* dec, sol_vote_state_t* state) {
    if (!dec || !state) return SOL_ERR_INVAL;

    /* CircBuf<(Pubkey, Epoch, Epoch)>:
     * buf: [ (Pubkey, u64, u64); 32 ]
     * idx: usize (u64 on x86_64)
     * is_empty: bool (u8) */
    for (size_t i = 0; i < 32; i++) {
        SOL_DECODE_TRY(sol_pubkey_decode(dec, &state->prior_voters[i].pubkey));
        SOL_DECODE_TRY(sol_decode_u64(dec, &state->prior_voters[i].start_epoch));
        SOL_DECODE_TRY(sol_decode_u64(dec, &state->prior_voters[i].end_epoch));
    }

    SOL_DECODE_TRY(sol_decode_u64(dec, &state->prior_voters_idx));

    uint8_t is_empty = 0;
    SOL_DECODE_TRY(sol_decode_u8(dec, &is_empty));
    state->prior_voters_is_empty = (is_empty != 0);
    return SOL_OK;
}

static sol_err_t
vote_decode_authorized_voters(sol_decoder_t* dec, sol_vote_state_t* state) {
    if (!dec || !state) return SOL_ERR_INVAL;

    uint64_t len = 0;
    SOL_DECODE_TRY(sol_decode_u64(dec, &len));
    if (len > SOL_MAX_AUTHORIZED_VOTERS) {
        return SOL_ERR_DECODE;
    }

    state->authorized_voters_len = (uint8_t)len;
    for (uint64_t i = 0; i < len; i++) {
        uint64_t epoch = 0;
        SOL_DECODE_TRY(sol_decode_u64(dec, &epoch));
        sol_pubkey_t pk;
        SOL_DECODE_TRY(sol_pubkey_decode(dec, &pk));
        state->authorized_voters[i].epoch = epoch;
        state->authorized_voters[i].pubkey = pk;
    }

    if (len > 0) {
        state->authorized_voter = state->authorized_voters[len - 1].pubkey;
    } else {
        sol_pubkey_init(&state->authorized_voter);
    }
    return SOL_OK;
}

static sol_err_t
vote_decode_epoch_credits(sol_decoder_t* dec, sol_vote_state_t* state) {
    if (!dec || !state) return SOL_ERR_INVAL;

    uint64_t len = 0;
    SOL_DECODE_TRY(sol_decode_u64(dec, &len));

    if (len > SOL_MAX_EPOCH_CREDITS_HISTORY) {
        return SOL_ERR_DECODE;
    }

    state->epoch_credits_len = (uint8_t)len;

    for (uint64_t i = 0; i < len; i++) {
        uint64_t epoch = 0, credits = 0, prev = 0;
        SOL_DECODE_TRY(sol_decode_u64(dec, &epoch));
        SOL_DECODE_TRY(sol_decode_u64(dec, &credits));
        SOL_DECODE_TRY(sol_decode_u64(dec, &prev));
        state->epoch_credits[i].epoch = epoch;
        state->epoch_credits[i].credits = credits;
        state->epoch_credits[i].prev_credits = prev;
    }

    return SOL_OK;
}

static sol_err_t
vote_decode_block_timestamp(sol_decoder_t* dec, sol_vote_state_t* state) {
    if (!dec || !state) return SOL_ERR_INVAL;

    uint64_t slot = 0;
    int64_t ts = 0;
    SOL_DECODE_TRY(sol_decode_u64(dec, &slot));
    SOL_DECODE_TRY(sol_decode_i64(dec, &ts));
    state->last_timestamp_slot = slot;
    state->last_timestamp = ts;
    return SOL_OK;
}

static sol_err_t
vote_decode_votes_lockouts(sol_decoder_t* dec, sol_vote_state_t* state, bool has_latency) {
    if (!dec || !state) return SOL_ERR_INVAL;

    uint64_t len = 0;
    SOL_DECODE_TRY(sol_decode_u64(dec, &len));

    if (len > SOL_MAX_LOCKOUT_HISTORY) {
        return SOL_ERR_DECODE;
    }

    state->votes_len = (uint8_t)len;
    for (uint64_t i = 0; i < len; i++) {
        uint8_t latency = 0;
        if (has_latency) {
            SOL_DECODE_TRY(sol_decode_u8(dec, &latency));
        }
        uint64_t slot = 0;
        uint32_t conf = 0;
        SOL_DECODE_TRY(sol_decode_u64(dec, &slot));
        SOL_DECODE_TRY(sol_decode_u32(dec, &conf));
        state->votes[i].slot = (sol_slot_t)slot;
        state->votes[i].confirmation_count = conf;
        state->vote_latencies[i] = latency;
    }

    return SOL_OK;
}

sol_err_t
sol_vote_state_serialize(const sol_vote_state_t* state,
                          uint8_t* data,
                          size_t data_len,
                          size_t* written) {
    if (!state || !data || data_len < 128) {
        return SOL_ERR_INVAL;
    }

    /* Prefer bincode VoteStateVersions when requested (or when overwriting an
     * existing bincode vote account).
     *
     * Note: vote accounts are fixed-size. Bytes beyond the serialized payload
     * may contain historical leftovers and are included in the account hash, so
     * we must overwrite in-place without clearing trailing bytes. */
    uint32_t target_version = state->onchain_version;
    if (target_version == 0 && data_len >= 4) {
        uint32_t existing = 0;
        memcpy(&existing, data, 4);
        if (existing == 1 || existing == 2) {
            target_version = existing;
        }
    }

    if (target_version == 1 || target_version == 2) {
        if (state->votes_len > SOL_MAX_LOCKOUT_HISTORY ||
            state->authorized_voters_len > SOL_MAX_AUTHORIZED_VOTERS ||
            state->epoch_credits_len > SOL_MAX_EPOCH_CREDITS_HISTORY) {
            return SOL_ERR_INVAL;
        }

        if (target_version == 1 && data_len != 3731) {
            /* VoteState1_14_11 is expected to use the legacy 3731-byte account size. */
            return SOL_ERR_INVAL;
        }

        sol_encoder_t enc;
        sol_encoder_init(&enc, data, data_len);

        SOL_ENCODE_TRY(sol_encode_u32(&enc, target_version));
        SOL_ENCODE_TRY(sol_pubkey_encode(&enc, &state->node_pubkey));
        SOL_ENCODE_TRY(sol_pubkey_encode(&enc, &state->authorized_withdrawer));
        SOL_ENCODE_TRY(sol_encode_u8(&enc, state->commission));

        SOL_ENCODE_TRY(sol_encode_u64(&enc, (uint64_t)state->votes_len));
        for (uint8_t i = 0; i < state->votes_len; i++) {
            if (target_version == 2) {
                SOL_ENCODE_TRY(sol_encode_u8(&enc, state->vote_latencies[i]));
            }
            SOL_ENCODE_TRY(sol_encode_u64(&enc, (uint64_t)state->votes[i].slot));
            SOL_ENCODE_TRY(sol_encode_u32(&enc, state->votes[i].confirmation_count));
        }

        SOL_ENCODE_TRY(vote_encode_option_u64(&enc, state->has_root, (uint64_t)state->root_slot));

        SOL_ENCODE_TRY(sol_encode_u64(&enc, (uint64_t)state->authorized_voters_len));
        for (uint8_t i = 0; i < state->authorized_voters_len; i++) {
            SOL_ENCODE_TRY(sol_encode_u64(&enc, state->authorized_voters[i].epoch));
            SOL_ENCODE_TRY(sol_pubkey_encode(&enc, &state->authorized_voters[i].pubkey));
        }

        for (size_t i = 0; i < 32; i++) {
            SOL_ENCODE_TRY(sol_pubkey_encode(&enc, &state->prior_voters[i].pubkey));
            SOL_ENCODE_TRY(sol_encode_u64(&enc, state->prior_voters[i].start_epoch));
            SOL_ENCODE_TRY(sol_encode_u64(&enc, state->prior_voters[i].end_epoch));
        }
        SOL_ENCODE_TRY(sol_encode_u64(&enc, state->prior_voters_idx));
        SOL_ENCODE_TRY(sol_encode_u8(&enc, state->prior_voters_is_empty ? 1u : 0u));

        SOL_ENCODE_TRY(sol_encode_u64(&enc, (uint64_t)state->epoch_credits_len));
        for (uint8_t i = 0; i < state->epoch_credits_len; i++) {
            SOL_ENCODE_TRY(sol_encode_u64(&enc, state->epoch_credits[i].epoch));
            SOL_ENCODE_TRY(sol_encode_u64(&enc, state->epoch_credits[i].credits));
            SOL_ENCODE_TRY(sol_encode_u64(&enc, state->epoch_credits[i].prev_credits));
        }

        SOL_ENCODE_TRY(sol_encode_u64(&enc, state->last_timestamp_slot));
        SOL_ENCODE_TRY(sol_encode_i64(&enc, state->last_timestamp));

        if (written) {
            *written = sol_encoder_len(&enc);
        }
        return SOL_OK;
    }

    size_t offset = 0;

    /* Version (4 bytes) */
    uint32_t version = SOL_VOTE_STATE_V1;
    memcpy(data + offset, &version, 4);
    offset += 4;

    /* Node pubkey (32 bytes) */
    memcpy(data + offset, state->node_pubkey.bytes, 32);
    offset += 32;

    /* Authorized voter (32 bytes) */
    memcpy(data + offset, state->authorized_voter.bytes, 32);
    offset += 32;

    /* Authorized withdrawer (32 bytes) */
    memcpy(data + offset, state->authorized_withdrawer.bytes, 32);
    offset += 32;

    /* Commission (1 byte) */
    data[offset++] = state->commission;

    /* Votes length (1 byte) */
    data[offset++] = state->votes_len;

    /* Votes */
    for (uint8_t i = 0; i < state->votes_len && offset + 12 <= data_len; i++) {
        memcpy(data + offset, &state->votes[i].slot, 8);
        offset += 8;
        memcpy(data + offset, &state->votes[i].confirmation_count, 4);
        offset += 4;
    }

    /* Root slot */
    data[offset++] = state->has_root ? 1 : 0;
    if (state->has_root && offset + 8 <= data_len) {
        memcpy(data + offset, &state->root_slot, 8);
        offset += 8;
    }

    /* Epoch credits length */
    if (offset < data_len) {
        data[offset++] = state->epoch_credits_len;
    }

    /* Epoch credits */
    for (uint8_t i = 0; i < state->epoch_credits_len && offset + 24 <= data_len; i++) {
        memcpy(data + offset, &state->epoch_credits[i].epoch, 8);
        offset += 8;
        memcpy(data + offset, &state->epoch_credits[i].credits, 8);
        offset += 8;
        memcpy(data + offset, &state->epoch_credits[i].prev_credits, 8);
        offset += 8;
    }

    /* Last timestamp */
    if (offset + 16 <= data_len) {
        memcpy(data + offset, &state->last_timestamp_slot, 8);
        offset += 8;
        memcpy(data + offset, &state->last_timestamp, 8);
        offset += 8;
    }

    if (written) {
        *written = offset;
    }

    return SOL_OK;
}

sol_err_t
sol_vote_state_deserialize(sol_vote_state_t* state,
                            const uint8_t* data,
                            size_t data_len) {
    if (!state || !data || data_len < 4) {
        return SOL_ERR_INVAL;
    }

    memset(state, 0, sizeof(sol_vote_state_t));

    uint32_t version_prefix = 0;
    memcpy(&version_prefix, data, 4);

    /* Detect Solana bincode VoteStateVersions. */
    bool maybe_bincode = (version_prefix == 2) || (version_prefix == 1 && data_len == 3731);
    if (maybe_bincode) {
        sol_decoder_t dec;
        sol_decoder_init(&dec, data, data_len);

        uint32_t variant = 0;
        if (sol_decode_u32(&dec, &variant) == SOL_OK) {
            state->onchain_version = variant;

            /* VoteStateVersions discriminants:
             * 0 => uninitialized
             * 1 => V1_14_11 (no vote latency)
             * 2 => current (with vote latency) */
            if (variant == 0) {
                return SOL_ERR_UNINITIALIZED;
            }

            if (variant == 2) {
                /* Current vote state */
                SOL_DECODE_TRY(sol_pubkey_decode(&dec, &state->node_pubkey));
                SOL_DECODE_TRY(sol_pubkey_decode(&dec, &state->authorized_withdrawer));
                SOL_DECODE_TRY(sol_decode_u8(&dec, &state->commission));

                SOL_DECODE_TRY(vote_decode_votes_lockouts(&dec, state, true));

                bool has_root = false;
                uint64_t root = 0;
                SOL_DECODE_TRY(vote_decode_option_u64(&dec, &has_root, &root));
                state->has_root = has_root;
                state->root_slot = (sol_slot_t)root;

                SOL_DECODE_TRY(vote_decode_authorized_voters(&dec, state));

                SOL_DECODE_TRY(vote_decode_prior_voters_circbuf(&dec, state));

                SOL_DECODE_TRY(vote_decode_epoch_credits(&dec, state));
                SOL_DECODE_TRY(vote_decode_block_timestamp(&dec, state));
                return SOL_OK;
            }

            if (variant == 1 && data_len == 3731) {
                /* VoteState1_14_11 (no vote latency) */
                SOL_DECODE_TRY(sol_pubkey_decode(&dec, &state->node_pubkey));
                SOL_DECODE_TRY(sol_pubkey_decode(&dec, &state->authorized_withdrawer));
                SOL_DECODE_TRY(sol_decode_u8(&dec, &state->commission));

                SOL_DECODE_TRY(vote_decode_votes_lockouts(&dec, state, false));

                bool has_root = false;
                uint64_t root = 0;
                SOL_DECODE_TRY(vote_decode_option_u64(&dec, &has_root, &root));
                state->has_root = has_root;
                state->root_slot = (sol_slot_t)root;

                SOL_DECODE_TRY(vote_decode_authorized_voters(&dec, state));

                SOL_DECODE_TRY(vote_decode_prior_voters_circbuf(&dec, state));

                SOL_DECODE_TRY(vote_decode_epoch_credits(&dec, state));
                SOL_DECODE_TRY(vote_decode_block_timestamp(&dec, state));
                return SOL_OK;
            }
        }
    }

    if (data_len < 128) {
        return SOL_ERR_INVAL;
    }

    size_t offset = 0;

    /* Version */
    uint32_t version;
    memcpy(&version, data + offset, 4);
    offset += 4;

    if (version > SOL_VOTE_STATE_V1) {
        return SOL_ERR_INVAL;
    }

    /* Node pubkey */
    memcpy(state->node_pubkey.bytes, data + offset, 32);
    offset += 32;

    /* Authorized voter */
    memcpy(state->authorized_voter.bytes, data + offset, 32);
    offset += 32;

    /* Authorized withdrawer */
    memcpy(state->authorized_withdrawer.bytes, data + offset, 32);
    offset += 32;

    /* Commission */
    state->commission = data[offset++];

    /* Votes */
    if (offset < data_len) {
        state->votes_len = data[offset++];
        if (state->votes_len > SOL_MAX_LOCKOUT_HISTORY) {
            state->votes_len = SOL_MAX_LOCKOUT_HISTORY;
        }

        for (uint8_t i = 0; i < state->votes_len && offset + 12 <= data_len; i++) {
            memcpy(&state->votes[i].slot, data + offset, 8);
            offset += 8;
            memcpy(&state->votes[i].confirmation_count, data + offset, 4);
            offset += 4;
        }
    }

    /* Root slot */
    if (offset < data_len) {
        state->has_root = data[offset++] != 0;
        if (state->has_root && offset + 8 <= data_len) {
            memcpy(&state->root_slot, data + offset, 8);
            offset += 8;
        }
    }

    /* Epoch credits */
    if (offset < data_len) {
        state->epoch_credits_len = data[offset++];
        if (state->epoch_credits_len > SOL_MAX_EPOCH_CREDITS_HISTORY) {
            state->epoch_credits_len = SOL_MAX_EPOCH_CREDITS_HISTORY;
        }

        for (uint8_t i = 0; i < state->epoch_credits_len && offset + 24 <= data_len; i++) {
            memcpy(&state->epoch_credits[i].epoch, data + offset, 8);
            offset += 8;
            memcpy(&state->epoch_credits[i].credits, data + offset, 8);
            offset += 8;
            memcpy(&state->epoch_credits[i].prev_credits, data + offset, 8);
            offset += 8;
        }
    }

    /* Last timestamp */
    if (offset + 16 <= data_len) {
        memcpy(&state->last_timestamp_slot, data + offset, 8);
        offset += 8;
        memcpy(&state->last_timestamp, data + offset, 8);
        offset += 8;
    }

    return SOL_OK;
}

/*
 * Check if a slot is in the votes
 */
static int
find_vote_index(const sol_vote_state_t* state, sol_slot_t slot) {
    for (uint8_t i = 0; i < state->votes_len; i++) {
        if (state->votes[i].slot == slot) {
            return (int)i;
        }
    }
    return -1;
}

/*
 * Calculate lockout for a vote at a given depth
 * Lockout = 2^(confirmation_count + 1)
 */
static uint64_t
calc_lockout(uint32_t confirmation_count) {
    if (confirmation_count >= 63u) {
        return UINT64_MAX;
    }
    return 1ULL << confirmation_count;
}

/*
 * last_locked_out_slot: slot + 2^confirmation_count
 * This is the first slot at which a vote with this confirmation_count
 * is no longer locked out.
 */
static sol_slot_t
last_locked_out_slot(const sol_lockout_t* lockout) {
    uint64_t lo = calc_lockout(lockout->confirmation_count);
    if (lo == UINT64_MAX) return UINT64_MAX;
    return lockout->slot + lo;
}

/*
 * Timely vote credits constants (SIMD-0033)
 */
#define VOTE_CREDITS_GRACE_SLOTS    2u
#define VOTE_CREDITS_MAXIMUM_PER_SLOT 16u

/*
 * Compute credits for a single vote at the given index in the vote state,
 * based on vote latency (timely vote credits).
 */
static uint64_t
credits_for_vote_at_index(const sol_vote_state_t* state, uint8_t index) {
    if (index >= state->votes_len) return 1;

    uint8_t latency = state->vote_latencies[index];

    /* Latency 0 means the vote was created before timely vote credits;
       award 1 credit for backwards compatibility. */
    if (latency == 0) return 1;

    if (latency <= VOTE_CREDITS_GRACE_SLOTS) {
        return (uint64_t)VOTE_CREDITS_MAXIMUM_PER_SLOT;
    }

    uint8_t diff = latency - VOTE_CREDITS_GRACE_SLOTS;
    if (diff >= VOTE_CREDITS_MAXIMUM_PER_SLOT) {
        return 1;
    }
    return (uint64_t)(VOTE_CREDITS_MAXIMUM_PER_SLOT - diff);
}

/*
 * Increment vote credits for the given epoch.
 * Matches Agave's VoteStateHandle::increment_credits exactly.
 */
static void
vote_state_add_credits(sol_vote_state_t* state, uint64_t current_epoch, uint64_t delta) {
    if (!state || delta == 0) return;

    if (state->epoch_credits_len == 0) {
        /* Never seen a credit — create initial entry */
        state->epoch_credits[0].epoch = current_epoch;
        state->epoch_credits[0].credits = 0;
        state->epoch_credits[0].prev_credits = 0;
        state->epoch_credits_len = 1;
    } else if (state->epoch_credits[state->epoch_credits_len - 1].epoch != current_epoch) {
        uint64_t prev_cred = state->epoch_credits[state->epoch_credits_len - 1].credits;
        uint64_t prev_prev = state->epoch_credits[state->epoch_credits_len - 1].prev_credits;
        if (prev_cred != prev_prev) {
            /* Credits were earned in the previous epoch — append new entry */
            if (state->epoch_credits_len < SOL_MAX_EPOCH_CREDITS_HISTORY) {
                state->epoch_credits[state->epoch_credits_len].epoch = current_epoch;
                state->epoch_credits[state->epoch_credits_len].credits = prev_cred;
                state->epoch_credits[state->epoch_credits_len].prev_credits = prev_cred;
                state->epoch_credits_len++;
            } else {
                /* Trim oldest to stay at MAX_EPOCH_CREDITS_HISTORY */
                memmove(&state->epoch_credits[0], &state->epoch_credits[1],
                        (SOL_MAX_EPOCH_CREDITS_HISTORY - 1) * sizeof(sol_epoch_credits_t));
                sol_epoch_credits_t* new_last = &state->epoch_credits[SOL_MAX_EPOCH_CREDITS_HISTORY - 1];
                new_last->epoch = current_epoch;
                new_last->credits = prev_cred;
                new_last->prev_credits = prev_cred;
            }
        } else {
            /* No credits earned in previous epoch — just reuse the entry */
            state->epoch_credits[state->epoch_credits_len - 1].epoch = current_epoch;
        }
    }

    /* Unconditionally add credits to the last entry */
    state->epoch_credits[state->epoch_credits_len - 1].credits += delta;
}

/*
 * Process a Vote instruction (old-style, non-compact).
 * Matches Agave's process_vote_unfiltered → process_next_vote_slot flow.
 *
 * Credits are awarded per rooted vote using latency-based calculation,
 * NOT per vote slot in the instruction.
 */
sol_err_t
sol_vote_state_process_vote(sol_vote_state_t* state,
                             const sol_vote_t* vote,
                             sol_slot_t current_slot,
                             uint64_t current_epoch) {
    if (!state || !vote || vote->slots_len == 0) {
        return SOL_ERR_INVAL;
    }

    /* Process each slot — matches Agave process_next_vote_slot per slot */
    for (size_t i = 0; i < vote->slots_len; i++) {
        sol_slot_t slot = vote->slots[i];

        /* Ignore votes for slots <= last voted slot */
        if (state->votes_len > 0 &&
            slot <= state->votes[state->votes_len - 1].slot) {
            continue;
        }

        /* Pop expired votes relative to this new vote */
        sol_vote_state_pop_expired_votes(state, slot);

        /* If tower is full, pop oldest to root and award credits */
        if (state->votes_len == SOL_MAX_LOCKOUT_HISTORY) {
            uint64_t credits = credits_for_vote_at_index(state, 0);
            state->root_slot = state->votes[0].slot;
            state->has_root = true;
            memmove(&state->votes[0], &state->votes[1],
                    (state->votes_len - 1) * sizeof(sol_lockout_t));
            memmove(&state->vote_latencies[0], &state->vote_latencies[1],
                    (state->votes_len - 1) * sizeof(state->vote_latencies[0]));
            state->votes_len--;
            vote_state_add_credits(state, current_epoch, credits);
        }

        /* Append new vote with confirmation_count = 1 */
        state->votes[state->votes_len].slot = slot;
        state->votes[state->votes_len].confirmation_count = 1;

        uint64_t lat = 0;
        if (current_slot >= slot) {
            lat = (uint64_t)(current_slot - slot);
        }
        if (lat > 0xffu) lat = 0xffu;
        state->vote_latencies[state->votes_len] = (uint8_t)lat;

        state->votes_len++;

        /* Double lockouts: new vote confirms all prior votes */
        for (uint8_t j = 0; j < state->votes_len; j++) {
            if (state->votes[j].confirmation_count < UINT32_MAX) {
                state->votes[j].confirmation_count++;
            }
        }
    }

    /* Update timestamp if provided */
    if (vote->has_timestamp && vote->slots_len > 0) {
        state->last_timestamp_slot = vote->slots[vote->slots_len - 1];
        state->last_timestamp = (int64_t)vote->timestamp;
    }

    return SOL_OK;
}

sol_slot_t
sol_vote_state_last_voted_slot(const sol_vote_state_t* state) {
    if (!state || state->votes_len == 0) {
        return 0;
    }
    return state->votes[state->votes_len - 1].slot;
}

bool
sol_vote_state_contains_slot(const sol_vote_state_t* state, sol_slot_t slot) {
    if (!state) return false;
    return find_vote_index(state, slot) >= 0;
}

uint64_t
sol_vote_state_lockout(const sol_vote_state_t* state, sol_slot_t slot) {
    if (!state) return 0;

    int idx = find_vote_index(state, slot);
    if (idx < 0) return 0;

    return calc_lockout(state->votes[idx].confirmation_count);
}

uint64_t
sol_vote_state_credits(const sol_vote_state_t* state) {
    if (!state || state->epoch_credits_len == 0) {
        return 0;
    }
    return state->epoch_credits[state->epoch_credits_len - 1].credits;
}

void
sol_vote_state_pop_expired_votes(sol_vote_state_t* state, sol_slot_t current_slot) {
    if (!state) return;

    while (state->votes_len > 0) {
        sol_lockout_t* oldest = &state->votes[0];
        uint64_t lockout = calc_lockout(oldest->confirmation_count);

        /* If oldest vote's lockout hasn't expired, stop */
        if (oldest->slot + lockout > current_slot) {
            break;
        }

        /* Lockout expired - this becomes the root */
        state->root_slot = oldest->slot;
        state->has_root = true;

        /* Remove from tower */
        memmove(&state->votes[0], &state->votes[1],
                (state->votes_len - 1) * sizeof(sol_lockout_t));
        memmove(&state->vote_latencies[0], &state->vote_latencies[1],
                (state->votes_len - 1) * sizeof(state->vote_latencies[0]));
        state->votes_len--;
    }
}

/*
 * Execute Initialize instruction
 */
static sol_err_t
execute_initialize(sol_invoke_context_t* ctx) {
    if (ctx->instruction_data_len < 4 + 32 + 32 + 32 + 1) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
    if (ctx->account_indices_len < 1) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Parse instruction data */
    const uint8_t* data = ctx->instruction_data + 4;

    sol_vote_init_t init;
    memcpy(init.node_pubkey.bytes, data, 32);
    data += 32;
    memcpy(init.authorized_voter.bytes, data, 32);
    data += 32;
    memcpy(init.authorized_withdrawer.bytes, data, 32);
    data += 32;
    init.commission = *data;

    /* Get vote account */
    const sol_pubkey_t* vote_pubkey;
    sol_account_t* vote_account;
    SOL_TRY(get_account(ctx, 0, &vote_pubkey, &vote_account));

    if (!vote_account) {
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Must be owned by vote program */
    if (!sol_pubkey_eq(&vote_account->meta.owner, &SOL_VOTE_PROGRAM_ID)) {
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Must have enough space */
    if (vote_account->meta.data_len < SOL_VOTE_STATE_SIZE) {
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Check if already initialized (non-zero data) */
    bool already_init = false;
    for (size_t i = 0; i < 4 && i < vote_account->meta.data_len; i++) {
        if (vote_account->data[i] != 0) {
            already_init = true;
            break;
        }
    }
    if (already_init) {
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_ACCOUNT_ALREADY_INIT;
    }

    /* Initialize vote state */
    sol_vote_state_t state;
    sol_vote_state_init(&state, &init);

    /* Serialize to account */
    size_t written;
    sol_err_t err = sol_vote_state_serialize(&state, vote_account->data,
                                              vote_account->meta.data_len, &written);
    if (err != SOL_OK) {
        sol_account_destroy(vote_account);
        return err;
    }

    sol_bank_store_account(ctx->bank, vote_pubkey, vote_account);
    sol_account_destroy(vote_account);

    return SOL_OK;
}

/*
 * Execute Vote instruction (legacy format)
 */
static sol_err_t
execute_vote_legacy(sol_invoke_context_t* ctx, sol_vote_state_t* state) {
    if (!ctx || !state || !ctx->instruction_data || ctx->instruction_data_len < 4) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    sol_decoder_t dec;
    sol_decoder_init(&dec, ctx->instruction_data, ctx->instruction_data_len);

    uint32_t instr_type = 0;
    SOL_DECODE_TRY(sol_decode_u32(&dec, &instr_type));

    bool is_switch = (instr_type == SOL_VOTE_INSTR_VOTE_SWITCH);
    if (instr_type != SOL_VOTE_INSTR_VOTE && !is_switch) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Vote: Vec<u64> slots (u64 len) */
    uint64_t slots_len_u64 = 0;
    SOL_DECODE_TRY(sol_decode_u64(&dec, &slots_len_u64));
    if (slots_len_u64 == 0 || slots_len_u64 > SOL_MAX_LOCKOUT_HISTORY) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    sol_slot_t slots[SOL_MAX_LOCKOUT_HISTORY];
    for (uint64_t i = 0; i < slots_len_u64; i++) {
        uint64_t slot = 0;
        SOL_DECODE_TRY(sol_decode_u64(&dec, &slot));
        slots[i] = (sol_slot_t)slot;
    }

    /* hash: [u8; 32] */
    sol_hash_t hash;
    const uint8_t* hash_bytes = NULL;
    SOL_DECODE_TRY(sol_decode_bytes(&dec, 32, &hash_bytes));
    memcpy(hash.bytes, hash_bytes, 32);

    /* timestamp: Option<i64> (u8 tag + i64) */
    uint8_t ts_tag = 0;
    SOL_DECODE_TRY(sol_decode_u8(&dec, &ts_tag));
    bool has_timestamp = false;
    int64_t timestamp = 0;
    if (ts_tag == 1) {
        SOL_DECODE_TRY(sol_decode_i64(&dec, &timestamp));
        has_timestamp = true;
    } else if (ts_tag != 0) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* VoteSwitch appends a 32-byte switch proof hash. */
    if (is_switch) {
        const uint8_t* switch_proof = NULL;
        SOL_DECODE_TRY(sol_decode_bytes(&dec, 32, &switch_proof));
        (void)switch_proof;
    }

    sol_vote_t vote = {
        .slots = slots,
        .slots_len = (size_t)slots_len_u64,
        .hash = hash,
        .timestamp = (uint64_t)timestamp,
        .has_timestamp = has_timestamp,
    };

    /*
     * Blockhash verification:
     * Reject votes with all-zero hash as this indicates an invalid/missing hash.
     * A full implementation would verify against the SlotHashes sysvar to ensure
     * the hash corresponds to a valid block at one of the voted slots.
     */
    bool hash_is_zero = true;
    for (int i = 0; i < 32; i++) {
        if (hash.bytes[i] != 0) {
            hash_is_zero = false;
            break;
        }
    }
    if (hash_is_zero) {
        sol_log_debug("Vote rejected: bank hash cannot be zero");
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    sol_slot_t vote_slot = vote.slots_len > 0 ? slots[vote.slots_len - 1] : 0;
    sol_err_t verify_err = verify_hash_against_slot_hashes(ctx->bank, vote_slot, &hash);
    if (verify_err != SOL_OK) {
        sol_log_debug("Vote rejected: slot %llu bank hash not in SlotHashes",
                      (unsigned long long)vote_slot);
        return verify_err;
    }

    /* Process vote */
    sol_slot_t current_slot = sol_bank_slot(ctx->bank);
    uint64_t current_epoch = sol_bank_epoch(ctx->bank);

    return sol_vote_state_process_vote(state, &vote, current_slot, current_epoch);
}

/*
 * Execute CompactUpdateVoteState instruction (compact tower encoding)
 *
 * Format:
 *   - type(4): instruction type (13/14)
 *   - root_slot(u64): new root slot (0 => none)
 *   - lockouts_len(compact-u16)
 *   - lockouts[]: (slot_offset: u8, confirmation_count: u8) repeated lockouts_len times
 *   - hash(32): bank hash for the last voted slot
 *   - timestamp(Option<i64>): 1 byte tag + optional 8 bytes
 *   - switch_hash(32): only for CompactUpdateVoteStateSwitch
 *
 * Matches Agave's process_new_vote_state() in vote_state/mod.rs.
 */
static sol_err_t
execute_vote_compact(sol_invoke_context_t* ctx, sol_vote_state_t* state) {
    if (!ctx || !state || !ctx->instruction_data || ctx->instruction_data_len < 4) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    sol_decoder_t dec;
    sol_decoder_init(&dec, ctx->instruction_data, ctx->instruction_data_len);

    uint32_t instr_type = 0;
    SOL_DECODE_TRY(sol_decode_u32(&dec, &instr_type));

    bool is_switch = (instr_type == SOL_VOTE_INSTR_COMPACT_UPDATE_VOTE_STATE_SWITCH);
    if (instr_type != SOL_VOTE_INSTR_COMPACT_UPDATE_VOTE_STATE && !is_switch) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* --- Parse new root --- */

    uint64_t root_u64 = 0;
    SOL_DECODE_TRY(sol_decode_u64(&dec, &root_u64));
    sol_slot_t new_root = (sol_slot_t)root_u64;
    bool has_new_root = (root_u64 != 0);

    /* Root rollback check (Agave lines 470-480) */
    if (state->has_root) {
        if (!has_new_root) {
            return SOL_ERR_PROGRAM_FAILED; /* RootRollBack */
        }
        if (new_root < state->root_slot) {
            return SOL_ERR_PROGRAM_FAILED; /* RootRollBack */
        }
    }

    /* --- Parse new lockouts --- */

    uint16_t lockouts_len = 0;
    SOL_DECODE_TRY(sol_decode_compact_u16(&dec, &lockouts_len));
    if (lockouts_len == 0 || lockouts_len > SOL_MAX_LOCKOUT_HISTORY) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    sol_lockout_t new_lockouts[SOL_MAX_LOCKOUT_HISTORY];
    uint8_t new_latencies[SOL_MAX_LOCKOUT_HISTORY];
    memset(new_latencies, 0, sizeof(new_latencies));
    sol_slot_t cursor = new_root;
    sol_slot_t current_slot = sol_bank_slot(ctx->bank);

    for (uint16_t i = 0; i < lockouts_len; i++) {
        uint8_t slot_offset = 0;
        uint8_t conf_u8 = 0;
        SOL_DECODE_TRY(sol_decode_u8(&dec, &slot_offset));
        SOL_DECODE_TRY(sol_decode_u8(&dec, &conf_u8));

        cursor = (sol_slot_t)(cursor + (sol_slot_t)slot_offset);
        new_lockouts[i].slot = cursor;
        new_lockouts[i].confirmation_count = (uint32_t)conf_u8;
        /* latencies will be filled in below */
    }

    const uint8_t* hash_bytes = NULL;
    SOL_DECODE_TRY(sol_decode_bytes(&dec, 32, &hash_bytes));
    sol_hash_t hash;
    memcpy(hash.bytes, hash_bytes, 32);

    /* timestamp: Option<i64> */
    uint8_t ts_tag = 0;
    SOL_DECODE_TRY(sol_decode_u8(&dec, &ts_tag));
    bool has_timestamp = false;
    int64_t timestamp = 0;
    if (ts_tag == 1) {
        SOL_DECODE_TRY(sol_decode_i64(&dec, &timestamp));
        has_timestamp = true;
    } else if (ts_tag != 0) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    if (is_switch) {
        const uint8_t* switch_hash = NULL;
        SOL_DECODE_TRY(sol_decode_bytes(&dec, 32, &switch_hash));
        (void)switch_hash;
    }

    if (sol_decoder_remaining(&dec) != 0) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* --- Validate new state (Agave lines 482-516) --- */

    /* Reject all-zero hashes */
    bool hash_is_zero = true;
    for (int k = 0; k < 32; k++) {
        if (hash.bytes[k] != 0) { hash_is_zero = false; break; }
    }
    if (hash_is_zero) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    for (uint16_t i = 0; i < lockouts_len; i++) {
        if (new_lockouts[i].confirmation_count == 0) {
            return SOL_ERR_PROGRAM_FAILED; /* ZeroConfirmations */
        }
        if (new_lockouts[i].confirmation_count > SOL_MAX_LOCKOUT_HISTORY) {
            return SOL_ERR_PROGRAM_FAILED; /* ConfirmationTooLarge */
        }
        /* Vote slot must be > root (unless root is 0/default) */
        if (has_new_root && new_root != 0 && new_lockouts[i].slot <= new_root) {
            return SOL_ERR_PROGRAM_FAILED; /* SlotSmallerThanRoot */
        }
        if (i > 0) {
            if (new_lockouts[i - 1].slot >= new_lockouts[i].slot) {
                return SOL_ERR_PROGRAM_FAILED; /* SlotsNotOrdered */
            }
            if (new_lockouts[i - 1].confirmation_count <= new_lockouts[i].confirmation_count) {
                return SOL_ERR_PROGRAM_FAILED; /* ConfirmationsNotOrdered */
            }
            /* Each vote must be within the lockout range of the previous vote */
            if (new_lockouts[i].slot > last_locked_out_slot(&new_lockouts[i - 1])) {
                return SOL_ERR_PROGRAM_FAILED; /* NewVoteStateLockoutMismatch */
            }
        }
    }

    /* Verify the last vote's hash against SlotHashes */
    sol_slot_t vote_slot = new_lockouts[lockouts_len - 1].slot;
    sol_err_t verify_err = verify_hash_against_slot_hashes(ctx->bank, vote_slot, &hash);
    if (verify_err != SOL_OK) {
        return verify_err;
    }

    /* --- Compute earned credits from old lockouts being rooted (Agave lines 520-543) --- */

    uint8_t  old_idx = 0;
    uint16_t new_idx = 0;
    uint64_t earned_credits = 0;

    if (has_new_root) {
        for (uint8_t i = 0; i < state->votes_len; i++) {
            if (state->votes[i].slot <= new_root) {
                earned_credits += credits_for_vote_at_index(state, i);
                old_idx = i + 1;
            } else {
                break;
            }
        }
    }

    /* --- Validate lockout conflicts and copy latencies (Agave lines 564-609) --- */

    while (old_idx < state->votes_len && new_idx < lockouts_len) {
        sol_slot_t old_slot = state->votes[old_idx].slot;
        sol_slot_t nw_slot  = new_lockouts[new_idx].slot;

        if (old_slot < nw_slot) {
            /* Old vote was popped by new state — check lockout conflict */
            if (last_locked_out_slot(&state->votes[old_idx]) >= nw_slot) {
                return SOL_ERR_PROGRAM_FAILED; /* LockoutConflict */
            }
            old_idx++;
        } else if (old_slot == nw_slot) {
            /* Same slot — confirmation count must not decrease */
            if (new_lockouts[new_idx].confirmation_count <
                state->votes[old_idx].confirmation_count) {
                return SOL_ERR_PROGRAM_FAILED; /* ConfirmationRollBack */
            }
            /* Copy latency from old state */
            new_latencies[new_idx] = state->vote_latencies[old_idx];
            old_idx++;
            new_idx++;
        } else {
            /* New vote not in old state — advance new index */
            new_idx++;
        }
    }

    /* Set latencies for new slots not found in old state (Agave lines 616-619) */
    for (uint16_t i = 0; i < lockouts_len; i++) {
        if (new_latencies[i] == 0) {
            uint64_t lat = 0;
            if (current_slot >= new_lockouts[i].slot) {
                lat = current_slot - new_lockouts[i].slot;
            }
            if (lat > 0xffu) lat = 0xffu;
            new_latencies[i] = (uint8_t)lat;
        }
    }

    /* --- Apply new state (Agave lines 622-633) --- */

    uint64_t current_epoch = sol_bank_epoch(ctx->bank);

    /* Only increment credits if root actually changed (Agave line 622) */
    bool root_changed;
    if (has_new_root) {
        if (state->has_root) {
            root_changed = (state->root_slot != new_root);
        } else {
            root_changed = true;
        }
    } else {
        root_changed = state->has_root; /* None != Some — but this would have been rejected above */
    }

    if (root_changed && earned_credits > 0) {
        vote_state_add_credits(state, current_epoch, earned_credits);
    }

    /* Process timestamp — matches Agave VoteStateHandle::process_timestamp */
    if (has_timestamp) {
        sol_slot_t last_slot = new_lockouts[lockouts_len - 1].slot;
        bool reject = (last_slot < state->last_timestamp_slot ||
                       timestamp < state->last_timestamp);
        if (!reject && last_slot == state->last_timestamp_slot &&
            timestamp != state->last_timestamp &&
            state->last_timestamp_slot != 0) {
            reject = true;
        }
        if (reject) {
            return SOL_ERR_PROGRAM_FAILED; /* TimestampTooOld */
        }
        state->last_timestamp_slot = last_slot;
        state->last_timestamp = timestamp;
    }

    /* Set new root (Agave line 632) */
    state->has_root = has_new_root;
    state->root_slot = new_root;

    /* Set new votes (Agave line 633) */
    state->votes_len = (uint8_t)lockouts_len;
    for (uint16_t i = 0; i < lockouts_len; i++) {
        state->votes[i] = new_lockouts[i];
        state->vote_latencies[i] = new_latencies[i];
    }

    return SOL_OK;
}

/*
 * Execute Vote instruction
 */
static sol_err_t
execute_vote(sol_invoke_context_t* ctx) {
    /* Mainnet vote traffic typically uses compact vote instructions that only
     * pass:
     *   [0] vote account (writable)
     *   [1] vote authority (signer)
     *
     * Older/alternate encodings may also include SlotHashes/Clock sysvars, but
     * the native vote program can load those directly from the bank. */
    if (ctx->account_indices_len < 2) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Get vote account */
    const sol_pubkey_t* vote_pubkey;
    sol_account_t* vote_account;
    SOL_TRY(get_account(ctx, 0, &vote_pubkey, &vote_account));

    if (!vote_account) {
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Verify vote account is owned by vote program */
    if (!sol_pubkey_eq(&vote_account->meta.owner, &SOL_VOTE_PROGRAM_ID)) {
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Deserialize current state */
    sol_vote_state_t state;
    sol_err_t err = sol_vote_state_deserialize(&state, vote_account->data,
                                                vote_account->meta.data_len);
    if (err != SOL_OK) {
        sol_account_destroy(vote_account);
        return err;
    }

    /* Verify vote authority signed. */
    uint8_t auth_index = 1;
    if (ctx->account_indices_len >= 4) {
        const sol_pubkey_t* pk1 = NULL;
        const sol_pubkey_t* pk2 = NULL;
        sol_account_t* acc1 = NULL;
        sol_account_t* acc2 = NULL;
        if (get_account(ctx, 1, &pk1, &acc1) == SOL_OK &&
            get_account(ctx, 2, &pk2, &acc2) == SOL_OK) {
            if (pk1 && pk2 &&
                sol_pubkey_eq(pk1, &SOL_SYSVAR_SLOT_HASHES_ID) &&
                sol_pubkey_eq(pk2, &SOL_SYSVAR_CLOCK_ID)) {
                auth_index = 3;
            }
        }
        if (acc1) sol_account_destroy(acc1);
        if (acc2) sol_account_destroy(acc2);
    }

    const sol_pubkey_t* vote_auth;
    sol_account_t* vote_auth_account;
    SOL_TRY(get_account(ctx, auth_index, &vote_auth, &vote_auth_account));
    sol_account_destroy(vote_auth_account);

    /* Look up the authorized voter for the current epoch (matches Agave's
       get_and_update_authorized_voter(clock.epoch)). */
    uint64_t current_epoch = ctx->bank ? sol_bank_epoch(ctx->bank) : ctx->clock.epoch;
    sol_pubkey_t expected_voter;
    if (!vote_get_authorized_voter_for_epoch(&state, current_epoch, &expected_voter)) {
        /* Fallback to the cached authorized_voter if lookup fails */
        expected_voter = state.authorized_voter;
    }

    if (!sol_pubkey_eq(vote_auth, &expected_voter)) {
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    if (!is_signer(ctx, auth_index)) {
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Check instruction type to determine format */
    if (ctx->instruction_data_len < 4) {
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    uint32_t instr_type;
    memcpy(&instr_type, ctx->instruction_data, 4);

    /* Dispatch based on instruction type */
    if (instr_type == SOL_VOTE_INSTR_COMPACT_UPDATE_VOTE_STATE ||
        instr_type == SOL_VOTE_INSTR_COMPACT_UPDATE_VOTE_STATE_SWITCH) {
        err = execute_vote_compact(ctx, &state);
    } else if (instr_type == SOL_VOTE_INSTR_UPDATE_VOTE_STATE ||
               instr_type == SOL_VOTE_INSTR_UPDATE_VOTE_STATE_SWITCH) {
        /* TODO: implement non-compact vote-state update variants. */
        err = SOL_ERR_NOT_IMPLEMENTED;
    } else {
        err = execute_vote_legacy(ctx, &state);
    }

    if (err != SOL_OK) {
        sol_account_destroy(vote_account);
        return err;
    }

    /* Serialize updated state */
    size_t written;
    err = sol_vote_state_serialize(&state, vote_account->data,
                                    vote_account->meta.data_len, &written);
    if (err != SOL_OK) {
        sol_account_destroy(vote_account);
        return err;
    }

    sol_bank_store_account(ctx->bank, vote_pubkey, vote_account);
    sol_account_destroy(vote_account);

    return SOL_OK;
}

/*
 * Execute Authorize instruction
 *
 * Changes the voter or withdrawer authority.
 * Instruction data: type (u32) | authorize_type (u32) | new_authority (32 bytes)
 * Accounts: [0] vote account, [1] clock sysvar, [2] current authority (signer)
 */
static sol_err_t
execute_authorize(sol_invoke_context_t* ctx, bool checked) {
    if (ctx->instruction_data_len < 4 + 4 + 32) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
    if (ctx->account_indices_len < 3) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Parse authorize type and new authority */
    uint32_t auth_type;
    memcpy(&auth_type, ctx->instruction_data + 4, 4);

    sol_pubkey_t new_authority;
    memcpy(new_authority.bytes, ctx->instruction_data + 8, 32);

    /* Get vote account */
    const sol_pubkey_t* vote_pubkey;
    sol_account_t* vote_account;
    SOL_TRY(get_account(ctx, 0, &vote_pubkey, &vote_account));

    if (!vote_account) {
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Verify vote account is owned by vote program */
    if (!sol_pubkey_eq(&vote_account->meta.owner, &SOL_VOTE_PROGRAM_ID)) {
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Deserialize vote state */
    sol_vote_state_t state;
    sol_err_t err = sol_vote_state_deserialize(&state, vote_account->data,
                                                vote_account->meta.data_len);
    if (err != SOL_OK) {
        sol_account_destroy(vote_account);
        return err;
    }

    /* Verify current authority is a signer (account 2) */
    if (!is_signer(ctx, 2)) {
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Verify current authority matches */
    const sol_pubkey_t* current_auth;
    sol_account_t* auth_account;
    SOL_TRY(get_account(ctx, 2, &current_auth, &auth_account));
    sol_account_destroy(auth_account);

    if (auth_type == SOL_VOTE_AUTHORIZE_VOTER) {
        if (!sol_pubkey_eq(current_auth, &state.authorized_voter)) {
            sol_account_destroy(vote_account);
            return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
        }
    } else if (auth_type == SOL_VOTE_AUTHORIZE_WITHDRAWER) {
        if (!sol_pubkey_eq(current_auth, &state.authorized_withdrawer)) {
            sol_account_destroy(vote_account);
            return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
        }
    }

    /* For checked variant, verify new authority is a signer */
    if (checked) {
        if (ctx->account_indices_len < 4) {
            sol_account_destroy(vote_account);
            return SOL_ERR_PROGRAM_INVALID_INSTR;
        }
        if (!is_signer(ctx, 3)) {
            sol_account_destroy(vote_account);
            return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
        }
    }

    /* Update the appropriate authority */
    if (auth_type == SOL_VOTE_AUTHORIZE_VOTER) {
        uint64_t current_epoch = sol_bank_epoch(ctx->bank);
        uint64_t old_start_epoch = 0;
        if (state.authorized_voters_len > 0) {
            old_start_epoch = state.authorized_voters[state.authorized_voters_len - 1].epoch;
        }
        vote_prior_voters_push(&state, &state.authorized_voter, old_start_epoch, current_epoch);
        vote_authorized_voters_set(&state, current_epoch, &new_authority);
    } else if (auth_type == SOL_VOTE_AUTHORIZE_WITHDRAWER) {
        sol_pubkey_copy(&state.authorized_withdrawer, &new_authority);
    } else {
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Serialize updated state */
    size_t written;
    err = sol_vote_state_serialize(&state, vote_account->data,
                                    vote_account->meta.data_len, &written);
    if (err != SOL_OK) {
        sol_account_destroy(vote_account);
        return err;
    }

    sol_bank_store_account(ctx->bank, vote_pubkey, vote_account);
    sol_account_destroy(vote_account);

    return SOL_OK;
}

/*
 * Execute AuthorizeWithSeed instruction
 *
 * Changes the voter or withdrawer authority using seed-based authorization.
 * The current authority is derived from: base_pubkey + seed + owner_program
 *
 * Instruction data:
 *   type (u32) | auth_type (u32) | owner (32 bytes) |
 *   seed_len (8 bytes) | seed (variable) | new_authority (32 bytes)
 *
 * Accounts:
 *   [0] = vote account
 *   [1] = clock sysvar
 *   [2] = base account (signer)
 *   [3] = (checked only) new authority (signer)
 */
static sol_err_t
execute_authorize_with_seed(sol_invoke_context_t* ctx, bool checked) {
    /* Minimum: type(4) + auth_type(4) + owner(32) + seed_len(8) + new_authority(32) */
    if (ctx->instruction_data_len < 4 + 4 + 32 + 8 + 32) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
    if (ctx->account_indices_len < 3) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Parse instruction data */
    const uint8_t* data = ctx->instruction_data + 4;  /* Skip type */

    uint32_t auth_type;
    memcpy(&auth_type, data, 4);
    data += 4;

    sol_pubkey_t current_authority_owner;
    memcpy(current_authority_owner.bytes, data, 32);
    data += 32;

    uint64_t seed_len;
    memcpy(&seed_len, data, 8);
    data += 8;

    /* Validate seed length */
    if (seed_len > 32) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Check we have enough data for seed + new_authority */
    if (ctx->instruction_data_len < 4 + 4 + 32 + 8 + seed_len + 32) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    const char* seed = (const char*)data;
    data += seed_len;

    sol_pubkey_t new_authority;
    memcpy(new_authority.bytes, data, 32);

    /* Get vote account */
    const sol_pubkey_t* vote_pubkey;
    sol_account_t* vote_account;
    SOL_TRY(get_account(ctx, 0, &vote_pubkey, &vote_account));

    if (!vote_account) {
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Verify vote account is owned by vote program */
    if (!sol_pubkey_eq(&vote_account->meta.owner, &SOL_VOTE_PROGRAM_ID)) {
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Get base account (signer whose key is used for derivation) */
    const sol_pubkey_t* base_pubkey;
    sol_account_t* base_account;
    sol_err_t err = get_account(ctx, 2, &base_pubkey, &base_account);
    if (err != SOL_OK) {
        sol_account_destroy(vote_account);
        return err;
    }

    /* Deserialize vote state */
    sol_vote_state_t state;
    err = sol_vote_state_deserialize(&state, vote_account->data,
                                      vote_account->meta.data_len);
    if (err != SOL_OK) {
        sol_account_destroy(vote_account);
        if (base_account) sol_account_destroy(base_account);
        return err;
    }

    /* Derive the expected authority from base + seed + owner */
    sol_pubkey_t derived_authority;
    err = sol_create_with_seed(base_pubkey, seed, (size_t)seed_len,
                               &current_authority_owner, &derived_authority);
    if (err != SOL_OK) {
        sol_account_destroy(vote_account);
        if (base_account) sol_account_destroy(base_account);
        return err;
    }

    /* Verify derived authority matches current authority */
    const sol_pubkey_t* current_authority = NULL;
    if (auth_type == SOL_VOTE_AUTHORIZE_VOTER) {
        current_authority = &state.authorized_voter;
    } else if (auth_type == SOL_VOTE_AUTHORIZE_WITHDRAWER) {
        current_authority = &state.authorized_withdrawer;
    } else {
        sol_account_destroy(vote_account);
        if (base_account) sol_account_destroy(base_account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    if (!sol_pubkey_eq(&derived_authority, current_authority)) {
        sol_log_debug("Seed-derived authority mismatch");
        sol_account_destroy(vote_account);
        if (base_account) sol_account_destroy(base_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* For checked variant, verify new authority is a signer (account 3) */
    if (checked) {
        if (ctx->account_indices_len < 4) {
            sol_account_destroy(vote_account);
            if (base_account) sol_account_destroy(base_account);
            return SOL_ERR_PROGRAM_INVALID_INSTR;
        }

        /* Verify account 3 matches new_authority */
        const sol_pubkey_t* new_auth_pubkey;
        sol_account_t* new_auth_account;
        err = get_account(ctx, 3, &new_auth_pubkey, &new_auth_account);
        if (err != SOL_OK) {
            sol_account_destroy(vote_account);
            if (base_account) sol_account_destroy(base_account);
            return err;
        }

        if (!sol_pubkey_eq(new_auth_pubkey, &new_authority)) {
            sol_account_destroy(vote_account);
            if (base_account) sol_account_destroy(base_account);
            if (new_auth_account) sol_account_destroy(new_auth_account);
            return SOL_ERR_PROGRAM_INVALID_INSTR;
        }

        if (new_auth_account) sol_account_destroy(new_auth_account);
    }

    /* Update the authority */
    if (auth_type == SOL_VOTE_AUTHORIZE_VOTER) {
        uint64_t current_epoch = sol_bank_epoch(ctx->bank);
        uint64_t old_start_epoch = 0;
        if (state.authorized_voters_len > 0) {
            old_start_epoch = state.authorized_voters[state.authorized_voters_len - 1].epoch;
        }
        vote_prior_voters_push(&state, &state.authorized_voter, old_start_epoch, current_epoch);
        vote_authorized_voters_set(&state, current_epoch, &new_authority);
    } else {
        sol_pubkey_copy(&state.authorized_withdrawer, &new_authority);
    }

    /* Serialize updated state */
    size_t written;
    err = sol_vote_state_serialize(&state, vote_account->data,
                                    vote_account->meta.data_len, &written);
    if (err != SOL_OK) {
        sol_account_destroy(vote_account);
        if (base_account) sol_account_destroy(base_account);
        return err;
    }

    sol_bank_store_account(ctx->bank, vote_pubkey, vote_account);
    sol_account_destroy(vote_account);
    if (base_account) sol_account_destroy(base_account);

    sol_log_debug("Vote authorize with seed: auth_type=%u, seed_len=%zu",
                  (unsigned)auth_type, (size_t)seed_len);

    return SOL_OK;
}

/*
 * Execute UpdateValidator instruction
 *
 * Changes the node identity pubkey.
 * Instruction data: type (u32) | new_identity (32 bytes)
 * Accounts: [0] vote account, [1] new identity (signer), [2] withdrawer (signer)
 */
static sol_err_t
execute_update_validator(sol_invoke_context_t* ctx, bool checked) {
    if (ctx->instruction_data_len < 4 + 32) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
    if (ctx->account_indices_len < 3) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Parse new identity */
    sol_pubkey_t new_identity;
    memcpy(new_identity.bytes, ctx->instruction_data + 4, 32);

    /* Get vote account */
    const sol_pubkey_t* vote_pubkey;
    sol_account_t* vote_account;
    SOL_TRY(get_account(ctx, 0, &vote_pubkey, &vote_account));

    if (!vote_account) {
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Verify vote account is owned by vote program */
    if (!sol_pubkey_eq(&vote_account->meta.owner, &SOL_VOTE_PROGRAM_ID)) {
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Deserialize vote state */
    sol_vote_state_t state;
    sol_err_t err = sol_vote_state_deserialize(&state, vote_account->data,
                                                vote_account->meta.data_len);
    if (err != SOL_OK) {
        sol_account_destroy(vote_account);
        return err;
    }

    /* Verify new identity (account 1) is a signer */
    if (!is_signer(ctx, 1)) {
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Get new identity pubkey and verify it matches instruction data */
    const sol_pubkey_t* new_identity_account;
    sol_account_t* identity_acc;
    SOL_TRY(get_account(ctx, 1, &new_identity_account, &identity_acc));
    if (identity_acc) sol_account_destroy(identity_acc);

    if (!sol_pubkey_eq(new_identity_account, &new_identity)) {
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Verify withdrawer (account 2) is a signer */
    if (!is_signer(ctx, 2)) {
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Verify withdrawer matches authorized withdrawer */
    const sol_pubkey_t* withdrawer_pubkey;
    sol_account_t* withdrawer_acc;
    SOL_TRY(get_account(ctx, 2, &withdrawer_pubkey, &withdrawer_acc));
    if (withdrawer_acc) sol_account_destroy(withdrawer_acc);

    if (!sol_pubkey_eq(withdrawer_pubkey, &state.authorized_withdrawer)) {
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    (void)checked;  /* Both variants require same validation */

    /* Update node identity */
    sol_pubkey_copy(&state.node_pubkey, &new_identity);

    /* Serialize updated state */
    size_t written;
    err = sol_vote_state_serialize(&state, vote_account->data,
                                    vote_account->meta.data_len, &written);
    if (err != SOL_OK) {
        sol_account_destroy(vote_account);
        return err;
    }

    sol_bank_store_account(ctx->bank, vote_pubkey, vote_account);
    sol_account_destroy(vote_account);

    return SOL_OK;
}

/*
 * Execute UpdateCommission instruction
 *
 * Changes the commission percentage.
 * Instruction data: type (u32) | commission (u8)
 * Accounts: [0] vote account, [1] withdrawer (signer)
 */
static sol_err_t
execute_update_commission(sol_invoke_context_t* ctx) {
    if (ctx->instruction_data_len < 4 + 1) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
    if (ctx->account_indices_len < 2) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Parse new commission */
    uint8_t new_commission = ctx->instruction_data[4];

    /* Validate commission (0-100) */
    if (new_commission > 100) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Get vote account */
    const sol_pubkey_t* vote_pubkey;
    sol_account_t* vote_account;
    SOL_TRY(get_account(ctx, 0, &vote_pubkey, &vote_account));

    if (!vote_account) {
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Verify vote account is owned by vote program */
    if (!sol_pubkey_eq(&vote_account->meta.owner, &SOL_VOTE_PROGRAM_ID)) {
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Deserialize vote state */
    sol_vote_state_t state;
    sol_err_t err = sol_vote_state_deserialize(&state, vote_account->data,
                                                vote_account->meta.data_len);
    if (err != SOL_OK) {
        sol_account_destroy(vote_account);
        return err;
    }

    /* Verify withdrawer (account 1) is a signer */
    if (!is_signer(ctx, 1)) {
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Verify withdrawer matches authorized withdrawer */
    const sol_pubkey_t* withdrawer_pubkey;
    sol_account_t* withdrawer_acc;
    SOL_TRY(get_account(ctx, 1, &withdrawer_pubkey, &withdrawer_acc));
    if (withdrawer_acc) sol_account_destroy(withdrawer_acc);

    if (!sol_pubkey_eq(withdrawer_pubkey, &state.authorized_withdrawer)) {
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Update commission */
    state.commission = new_commission;

    /* Serialize updated state */
    size_t written;
    err = sol_vote_state_serialize(&state, vote_account->data,
                                    vote_account->meta.data_len, &written);
    if (err != SOL_OK) {
        sol_account_destroy(vote_account);
        return err;
    }

    sol_bank_store_account(ctx->bank, vote_pubkey, vote_account);
    sol_account_destroy(vote_account);

    return SOL_OK;
}

/*
 * Execute Withdraw instruction
 */
static sol_err_t
execute_withdraw(sol_invoke_context_t* ctx) {
    if (ctx->instruction_data_len < 4 + 8) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
    if (ctx->account_indices_len < 3) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Parse amount */
    uint64_t lamports;
    memcpy(&lamports, ctx->instruction_data + 4, 8);

    /* Get vote account */
    const sol_pubkey_t* vote_pubkey;
    sol_account_t* vote_account;
    SOL_TRY(get_account(ctx, 0, &vote_pubkey, &vote_account));

    if (!vote_account) {
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Verify vote account is owned by vote program */
    if (!sol_pubkey_eq(&vote_account->meta.owner, &SOL_VOTE_PROGRAM_ID)) {
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Deserialize vote state to get authorized_withdrawer */
    sol_vote_state_t state;
    sol_err_t err = sol_vote_state_deserialize(&state, vote_account->data,
                                                vote_account->meta.data_len);
    if (err != SOL_OK) {
        sol_account_destroy(vote_account);
        return err;
    }

    /* Verify withdrawer (account 2) is a signer */
    if (!is_signer(ctx, 2)) {
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Get withdrawer pubkey and verify it matches authorized_withdrawer */
    const sol_pubkey_t* withdrawer_pubkey;
    sol_account_t* withdrawer_acc;
    err = get_account(ctx, 2, &withdrawer_pubkey, &withdrawer_acc);
    if (err != SOL_OK) {
        sol_account_destroy(vote_account);
        return err;
    }
    if (withdrawer_acc) sol_account_destroy(withdrawer_acc);

    if (!sol_pubkey_eq(withdrawer_pubkey, &state.authorized_withdrawer)) {
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Get destination account */
    const sol_pubkey_t* dest_pubkey;
    sol_account_t* dest_account;
    err = get_account(ctx, 1, &dest_pubkey, &dest_account);
    if (err != SOL_OK) {
        sol_account_destroy(vote_account);
        return err;
    }

    /* Check balance */
    if (vote_account->meta.lamports < lamports) {
        sol_account_destroy(vote_account);
        if (dest_account) sol_account_destroy(dest_account);
        return SOL_ERR_TX_INSUFFICIENT_FUNDS;
    }

    /* Self-withdrawal: no-op for lamports (sub+add on same account = no change) */
    if (sol_pubkey_eq(vote_pubkey, dest_pubkey)) {
        sol_bank_store_account(ctx->bank, vote_pubkey, vote_account);
        sol_account_destroy(vote_account);
        if (dest_account) sol_account_destroy(dest_account);
        return SOL_OK;
    }

    /* Create destination if doesn't exist */
    if (!dest_account) {
        dest_account = sol_account_new(0, 0, &SOL_SYSTEM_PROGRAM_ID);
        if (!dest_account) {
            sol_account_destroy(vote_account);
            return SOL_ERR_NOMEM;
        }
    }

    /* Transfer */
    vote_account->meta.lamports -= lamports;
    dest_account->meta.lamports += lamports;

    sol_bank_store_account(ctx->bank, vote_pubkey, vote_account);
    sol_bank_store_account(ctx->bank, dest_pubkey, dest_account);

    sol_account_destroy(vote_account);
    sol_account_destroy(dest_account);

    return SOL_OK;
}

sol_err_t
sol_vote_program_execute(sol_invoke_context_t* ctx) {
    if (!ctx || !ctx->bank || !ctx->instruction_data || ctx->instruction_data_len < 4) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Read instruction type */
    uint32_t instr_type;
    memcpy(&instr_type, ctx->instruction_data, 4);

    switch (instr_type) {
    case SOL_VOTE_INSTR_INITIALIZE:
        return execute_initialize(ctx);

    case SOL_VOTE_INSTR_VOTE:
    case SOL_VOTE_INSTR_VOTE_SWITCH:
    case SOL_VOTE_INSTR_UPDATE_VOTE_STATE:
    case SOL_VOTE_INSTR_UPDATE_VOTE_STATE_SWITCH:
    case SOL_VOTE_INSTR_COMPACT_UPDATE_VOTE_STATE:
    case SOL_VOTE_INSTR_COMPACT_UPDATE_VOTE_STATE_SWITCH:
        return execute_vote(ctx);

    case SOL_VOTE_INSTR_WITHDRAW:
        return execute_withdraw(ctx);

    case SOL_VOTE_INSTR_AUTHORIZE:
        return execute_authorize(ctx, false);

    case SOL_VOTE_INSTR_AUTHORIZE_CHECKED:
        return execute_authorize(ctx, true);

    case SOL_VOTE_INSTR_UPDATE_VALIDATOR:
        return execute_update_validator(ctx, false);

    case SOL_VOTE_INSTR_UPDATE_VALIDATOR_CHECKED:
        return execute_update_validator(ctx, true);

    case SOL_VOTE_INSTR_UPDATE_COMMISSION:
        return execute_update_commission(ctx);

    case SOL_VOTE_INSTR_AUTHORIZE_WITH_SEED:
        return execute_authorize_with_seed(ctx, false);

    case SOL_VOTE_INSTR_AUTHORIZE_CHECKED_WITH_SEED:
        return execute_authorize_with_seed(ctx, true);

    default:
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
}

sol_err_t
sol_vote_create_account(sol_bank_t* bank,
                         const sol_pubkey_t* vote_pubkey,
                         const sol_vote_init_t* init,
                         uint64_t lamports) {
    if (!bank || !vote_pubkey || !init) {
        return SOL_ERR_INVAL;
    }

    /* Create account with vote program as owner */
    sol_account_t* account = sol_account_new(lamports, SOL_VOTE_STATE_SIZE,
                                              &SOL_VOTE_PROGRAM_ID);
    if (!account) {
        return SOL_ERR_NOMEM;
    }

    /* Initialize vote state */
    sol_vote_state_t state;
    sol_vote_state_init(&state, init);

    /* Serialize to account */
    size_t written;
    sol_err_t err = sol_vote_state_serialize(&state, account->data,
                                              account->meta.data_len, &written);
    if (err != SOL_OK) {
        sol_account_destroy(account);
        return err;
    }

    err = sol_bank_store_account(bank, vote_pubkey, account);
    sol_account_destroy(account);

    return err;
}

sol_err_t
sol_vote_get_state(sol_bank_t* bank,
                    const sol_pubkey_t* vote_pubkey,
                    sol_vote_state_t* state) {
    if (!bank || !vote_pubkey || !state) {
        return SOL_ERR_INVAL;
    }

    sol_account_t* account = sol_bank_load_account(bank, vote_pubkey);
    if (!account) {
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    sol_err_t err = sol_vote_state_deserialize(state, account->data,
                                                account->meta.data_len);
    sol_account_destroy(account);

    return err;
}

bool
sol_vote_check_equivocation(const sol_vote_evidence_t* evidence1,
                             const sol_vote_evidence_t* evidence2) {
    if (!evidence1 || !evidence2) {
        return false;
    }

    /* Must be same voter */
    if (!sol_pubkey_eq(&evidence1->voter, &evidence2->voter)) {
        return false;
    }

    /* Must be same slot */
    if (evidence1->slot != evidence2->slot) {
        return false;
    }

    /* Must have different hashes (the actual equivocation) */
    if (memcmp(evidence1->hash.bytes, evidence2->hash.bytes, 32) == 0) {
        return false;
    }

    /*
     * In a full implementation, we would also verify the signatures
     * on each piece of evidence to ensure they're authentic.
     * For now, we trust that the evidence was validated before being
     * passed to this function.
     */

    sol_log_warn("Vote equivocation detected for slot %lu",
                 (unsigned long)evidence1->slot);

    return true;
}

sol_err_t
sol_vote_report_equivocation(sol_bank_t* bank,
                              const sol_pubkey_t* vote_account,
                              const sol_vote_evidence_t* evidence1,
                              const sol_vote_evidence_t* evidence2) {
    if (!bank || !vote_account || !evidence1 || !evidence2) {
        return SOL_ERR_INVAL;
    }

    /* Verify this is actually equivocation */
    if (!sol_vote_check_equivocation(evidence1, evidence2)) {
        return SOL_ERR_INVAL;
    }

    /* Load vote state */
    sol_vote_state_t state;
    sol_err_t err = sol_vote_get_state(bank, vote_account, &state);
    if (err != SOL_OK) {
        return err;
    }

    /* Verify the voter in the evidence matches the authorized voter */
    if (!sol_pubkey_eq(&evidence1->voter, &state.authorized_voter)) {
        /* Check prior voters - the equivocation might be from a previous authority */
        bool found = false;
        if (!state.prior_voters_is_empty) {
            for (size_t i = 0; i < 32; i++) {
                if (sol_pubkey_eq(&evidence1->voter, &state.prior_voters[i].pubkey)) {
                    found = true;
                    break;
                }
            }
        }
        if (!found) {
            sol_log_warn("Equivocation voter doesn't match vote account authority");
            return SOL_ERR_PROGRAM_INVALID_INSTR;
        }
    }

    /*
     * Slashing action: In Solana, slashing doesn't burn stake but rather
     * forces deactivation. The actual slashing logic would:
     *
     * 1. Mark the vote account as slashed (could add a flag to vote state)
     * 2. Force-deactivate all delegated stake
     * 3. Emit a slashing event for monitoring
     *
     * For now, we log the slashing event. Full implementation would
     * interact with the stake program to deactivate stake.
     */
    sol_log_error("SLASHING: Vote account slashed for equivocation at slot %lu",
                  (unsigned long)evidence1->slot);

    char vote_str[45];
    sol_pubkey_to_base58(vote_account, vote_str, sizeof(vote_str));
    sol_log_error("SLASHING: Vote account: %s", vote_str);

    return SOL_OK;
}
