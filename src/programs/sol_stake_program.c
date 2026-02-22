/*
 * sol_stake_program.c - Stake Program Implementation
 */

#include "sol_stake_program.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include "../util/sol_map.h"
#include "../runtime/sol_account.h"
#include "../runtime/sol_sysvar.h"
#include "sol_vote_program.h"
#include <string.h>

/* Note: SOL_STAKE_PROGRAM_ID is defined in sol_types.c */

/*
 * Stake Config Program ID
 */
const sol_pubkey_t SOL_STAKE_CONFIG_ID = {
    .bytes = {
        0x06, 0xa1, 0xd8, 0x17, 0x91, 0x37, 0x54, 0x3e,
        0x73, 0x63, 0x6d, 0xb6, 0x54, 0x24, 0xf2, 0xe0,
        0x63, 0x72, 0xf8, 0x8f, 0x53, 0x67, 0x62, 0x0b,
        0x1c, 0xca, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    }
};

/*
 * Default warmup/cooldown rate (25% per epoch)
 */
#define DEFAULT_WARMUP_COOLDOWN_RATE 0.25

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
 * Check if an account at the given instruction index is a signer.
 * Uses ctx->is_signer[] array when available (for V0 messages).
 */
static bool
is_signer(sol_invoke_context_t* ctx, uint8_t account_idx) {
    if (account_idx >= ctx->account_indices_len) {
        return false;
    }
    uint8_t key_idx = ctx->account_indices[account_idx];
    if (ctx->is_signer != NULL && key_idx < ctx->account_keys_len) {
        return ctx->is_signer[key_idx];
    }
    /* Fallback: first num_signers accounts are signers */
    return key_idx < ctx->num_signers;
}

/*
 * Get the pubkey at a given instruction account index
 */
static const sol_pubkey_t*
get_pubkey(sol_invoke_context_t* ctx, uint8_t account_idx) {
    if (account_idx >= ctx->account_indices_len) {
        return NULL;
    }
    uint8_t key_idx = ctx->account_indices[account_idx];
    if (key_idx >= ctx->account_keys_len) {
        return NULL;
    }
    return &ctx->account_keys[key_idx];
}

void
sol_stake_state_init(sol_stake_state_t* state,
                      const sol_stake_authorized_t* authorized,
                      const sol_lockup_t* lockup,
                      uint64_t rent_exempt_reserve) {
    memset(state, 0, sizeof(sol_stake_state_t));

    state->state = SOL_STAKE_STATE_INITIALIZED;
    state->meta.rent_exempt_reserve = rent_exempt_reserve;

    if (authorized) {
        state->meta.authorized = *authorized;
    }

    if (lockup) {
        state->meta.lockup = *lockup;
    }

    state->delegation.warmup_cooldown_rate = DEFAULT_WARMUP_COOLDOWN_RATE;
    state->delegation.deactivation_epoch = UINT64_MAX;
}

sol_err_t
sol_stake_state_serialize(const sol_stake_state_t* state,
                           uint8_t* data,
                           size_t data_len,
                           size_t* written) {
    if (!state || !data || data_len < SOL_STAKE_STATE_SIZE) {
        return SOL_ERR_INVAL;
    }

    size_t offset = 0;

    /* State type (4 bytes) */
    uint32_t state_type = (uint32_t)state->state;
    memcpy(data + offset, &state_type, 4);
    offset += 4;

    /* Meta: rent exempt reserve */
    memcpy(data + offset, &state->meta.rent_exempt_reserve, 8);
    offset += 8;

    /* Meta: authorized staker */
    memcpy(data + offset, state->meta.authorized.staker.bytes, 32);
    offset += 32;

    /* Meta: authorized withdrawer */
    memcpy(data + offset, state->meta.authorized.withdrawer.bytes, 32);
    offset += 32;

    /* Meta: lockup unix_timestamp */
    memcpy(data + offset, &state->meta.lockup.unix_timestamp, 8);
    offset += 8;

    /* Meta: lockup epoch */
    memcpy(data + offset, &state->meta.lockup.epoch, 8);
    offset += 8;

    /* Meta: lockup custodian */
    memcpy(data + offset, state->meta.lockup.custodian.bytes, 32);
    offset += 32;

    if (state->state == SOL_STAKE_STATE_STAKE) {
        /* Delegation: voter pubkey */
        memcpy(data + offset, state->delegation.voter_pubkey.bytes, 32);
        offset += 32;

        /* Delegation: stake */
        memcpy(data + offset, &state->delegation.stake, 8);
        offset += 8;

        /* Delegation: activation epoch */
        memcpy(data + offset, &state->delegation.activation_epoch, 8);
        offset += 8;

        /* Delegation: deactivation epoch */
        memcpy(data + offset, &state->delegation.deactivation_epoch, 8);
        offset += 8;

        /* Delegation: warmup_cooldown_rate (deprecated f64, still serialized) */
        memcpy(data + offset, &state->delegation.warmup_cooldown_rate, 8);
        offset += 8;

        /* Credits observed */
        memcpy(data + offset, &state->credits_observed, 8);
        offset += 8;

        /* StakeFlags (u8) */
        data[offset] = state->stake_flags;
        offset += 1;
    }

    /* Zero-fill remaining bytes (padding to SOL_STAKE_STATE_SIZE) */
    if (offset < data_len) {
        memset(data + offset, 0, data_len - offset);
    }

    if (written) {
        *written = offset;
    }

    return SOL_OK;
}

sol_err_t
sol_stake_state_deserialize(sol_stake_state_t* state,
                             const uint8_t* data,
                             size_t data_len) {
    if (!state || !data || data_len < 4) {
        return SOL_ERR_INVAL;
    }

    memset(state, 0, sizeof(sol_stake_state_t));

    size_t offset = 0;

    /* State type */
    uint32_t state_type;
    memcpy(&state_type, data + offset, 4);
    offset += 4;
    state->state = (sol_stake_state_type_t)state_type;

    if (state->state == SOL_STAKE_STATE_UNINITIALIZED) {
        return SOL_OK;
    }

    if (data_len < 124) {
        return SOL_ERR_TRUNCATED;
    }

    /* Meta: rent exempt reserve */
    memcpy(&state->meta.rent_exempt_reserve, data + offset, 8);
    offset += 8;

    /* Meta: authorized staker */
    memcpy(state->meta.authorized.staker.bytes, data + offset, 32);
    offset += 32;

    /* Meta: authorized withdrawer */
    memcpy(state->meta.authorized.withdrawer.bytes, data + offset, 32);
    offset += 32;

    /* Meta: lockup unix_timestamp */
    memcpy(&state->meta.lockup.unix_timestamp, data + offset, 8);
    offset += 8;

    /* Meta: lockup epoch */
    memcpy(&state->meta.lockup.epoch, data + offset, 8);
    offset += 8;

    /* Meta: lockup custodian */
    memcpy(state->meta.lockup.custodian.bytes, data + offset, 32);
    offset += 32;

    state->delegation.warmup_cooldown_rate = DEFAULT_WARMUP_COOLDOWN_RATE;
    state->delegation.deactivation_epoch = UINT64_MAX;

    if (state->state == SOL_STAKE_STATE_STAKE && data_len >= offset + 72) {
        /* Delegation: voter pubkey */
        memcpy(state->delegation.voter_pubkey.bytes, data + offset, 32);
        offset += 32;

        /* Delegation: stake */
        memcpy(&state->delegation.stake, data + offset, 8);
        offset += 8;

        /* Delegation: activation epoch */
        memcpy(&state->delegation.activation_epoch, data + offset, 8);
        offset += 8;

        /* Delegation: deactivation epoch */
        memcpy(&state->delegation.deactivation_epoch, data + offset, 8);
        offset += 8;

        /* Delegation: warmup_cooldown_rate (deprecated f64, still serialized) */
        memcpy(&state->delegation.warmup_cooldown_rate, data + offset, 8);
        offset += 8;

        /* Credits observed */
        if (data_len >= offset + 8) {
            memcpy(&state->credits_observed, data + offset, 8);
            offset += 8;
        }

        /* StakeFlags (u8) */
        if (data_len >= offset + 1) {
            state->stake_flags = data[offset];
            offset += 1;
        }
    }

    return SOL_OK;
}

sol_err_t
sol_stake_delegate(sol_stake_state_t* state,
                    const sol_pubkey_t* vote_pubkey,
                    uint64_t stake_amount,
                    uint64_t current_epoch) {
    if (!state || !vote_pubkey) {
        return SOL_ERR_INVAL;
    }

    if (state->state != SOL_STAKE_STATE_INITIALIZED &&
        state->state != SOL_STAKE_STATE_STAKE) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    if (stake_amount < SOL_MIN_STAKE_DELEGATION) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    state->state = SOL_STAKE_STATE_STAKE;
    state->delegation.voter_pubkey = *vote_pubkey;
    state->delegation.stake = stake_amount;
    state->delegation.activation_epoch = current_epoch;
    state->delegation.deactivation_epoch = UINT64_MAX;

    return SOL_OK;
}

sol_err_t
sol_stake_deactivate(sol_stake_state_t* state, uint64_t current_epoch) {
    if (!state) {
        return SOL_ERR_INVAL;
    }

    if (state->state != SOL_STAKE_STATE_STAKE) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    if (state->delegation.deactivation_epoch != UINT64_MAX) {
        /* Already deactivating */
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    state->delegation.deactivation_epoch = current_epoch;

    return SOL_OK;
}

uint64_t
sol_stake_effective_stake(const sol_stake_state_t* state,
                           uint64_t target_epoch) {
    if (!state || state->state != SOL_STAKE_STATE_STAKE) {
        return 0;
    }

    uint64_t stake = state->delegation.stake;
    uint64_t activation_epoch = state->delegation.activation_epoch;
    uint64_t deactivation_epoch = state->delegation.deactivation_epoch;
    double rate = state->delegation.warmup_cooldown_rate;

    /* Calculate effective stake based on warmup/cooldown */
    uint64_t effective = 0;

    if (target_epoch < activation_epoch) {
        /* Not yet activated */
        return 0;
    }

    if (target_epoch >= deactivation_epoch) {
        /* Deactivating or deactivated */
        uint64_t epochs_deactivating = target_epoch - deactivation_epoch;
        double remaining = 1.0;

        for (uint64_t i = 0; i < epochs_deactivating && remaining > 0; i++) {
            remaining -= rate;
        }

        if (remaining <= 0) {
            return 0;
        }

        /* First calculate fully activated stake, then apply cooldown */
        uint64_t epochs_active = deactivation_epoch - activation_epoch;
        double warmup = 0.0;
        for (uint64_t i = 0; i < epochs_active && warmup < 1.0; i++) {
            warmup += rate;
        }
        if (warmup > 1.0) warmup = 1.0;

        effective = (uint64_t)((double)stake * warmup * remaining);
    } else {
        /* Activating or active */
        uint64_t epochs_active = target_epoch - activation_epoch;
        double warmup = 0.0;

        for (uint64_t i = 0; i < epochs_active && warmup < 1.0; i++) {
            warmup += rate;
        }

        if (warmup > 1.0) warmup = 1.0;
        effective = (uint64_t)((double)stake * warmup);
    }

    return effective;
}

bool
sol_stake_is_active(const sol_stake_state_t* state, uint64_t current_epoch) {
    if (!state || state->state != SOL_STAKE_STATE_STAKE) {
        return false;
    }

    return current_epoch >= state->delegation.activation_epoch &&
           (state->delegation.deactivation_epoch == UINT64_MAX ||
            current_epoch < state->delegation.deactivation_epoch);
}

bool
sol_stake_is_fully_activated(const sol_stake_state_t* state, uint64_t current_epoch) {
    if (!state || state->state != SOL_STAKE_STATE_STAKE) {
        return false;
    }

    /* Simplified: assume fully activated after 4 epochs (100% at 25%/epoch) */
    return current_epoch >= state->delegation.activation_epoch + 4 &&
           state->delegation.deactivation_epoch == UINT64_MAX;
}

bool
sol_stake_is_locked(const sol_stake_state_t* state,
                     uint64_t current_epoch,
                     int64_t unix_timestamp) {
    if (!state) {
        return false;
    }

    if (state->meta.lockup.epoch > 0 && current_epoch < state->meta.lockup.epoch) {
        return true;
    }

    if (state->meta.lockup.unix_timestamp > 0 &&
        unix_timestamp < state->meta.lockup.unix_timestamp) {
        return true;
    }

    return false;
}

uint64_t
sol_stake_calculate_rewards(const sol_stake_state_t* state,
                             uint64_t vote_credits,
                             uint64_t total_stake,
                             uint64_t inflation_rewards) {
    if (!state || state->state != SOL_STAKE_STATE_STAKE || total_stake == 0) {
        return 0;
    }

    /* Calculate stake's share of rewards */
    uint64_t stake = state->delegation.stake;
    uint64_t credits_earned = vote_credits - state->credits_observed;

    /* Rewards proportional to stake and credits earned */
    /* Simplified: rewards = (stake / total_stake) * inflation_rewards * (credits / 1000) */
    double stake_share = (double)stake / (double)total_stake;
    double credit_factor = (double)credits_earned / 1000.0;
    if (credit_factor > 1.0) credit_factor = 1.0;

    return (uint64_t)(stake_share * credit_factor * (double)inflation_rewards);
}

/*
 * Execute Initialize instruction
 */
static sol_err_t
execute_initialize(sol_invoke_context_t* ctx) {
    if (ctx->instruction_data_len < 4 + 32 + 32) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
    if (ctx->account_indices_len < 1) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Parse instruction data */
    const uint8_t* data = ctx->instruction_data + 4;

    sol_stake_authorized_t authorized;
    memcpy(authorized.staker.bytes, data, 32);
    data += 32;
    memcpy(authorized.withdrawer.bytes, data, 32);
    data += 32;

    sol_lockup_t lockup = {0};
    if (ctx->instruction_data_len >= 4 + 32 + 32 + 8 + 8 + 32) {
        memcpy(&lockup.unix_timestamp, data, 8);
        data += 8;
        memcpy(&lockup.epoch, data, 8);
        data += 8;
        memcpy(lockup.custodian.bytes, data, 32);
    }

    /* Get stake account */
    const sol_pubkey_t* stake_pubkey;
    sol_account_t* stake_account;
    SOL_TRY(get_account(ctx, 0, &stake_pubkey, &stake_account));

    if (!stake_account) {
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Must be owned by stake program */
    if (!sol_pubkey_eq(&stake_account->meta.owner, &SOL_STAKE_PROGRAM_ID)) {
        sol_account_destroy(stake_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Must have enough space */
    if (stake_account->meta.data_len < SOL_STAKE_STATE_SIZE) {
        sol_account_destroy(stake_account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Check if already initialized */
    sol_stake_state_t current_state;
    if (sol_stake_state_deserialize(&current_state, stake_account->data,
                                     stake_account->meta.data_len) == SOL_OK &&
        current_state.state != SOL_STAKE_STATE_UNINITIALIZED) {
        sol_account_destroy(stake_account);
        return SOL_ERR_PROGRAM_ACCOUNT_ALREADY_INIT;
    }

    /* Calculate rent exempt reserve using proper rent calculator */
    sol_rent_t rent = SOL_RENT_DEFAULT;
    uint64_t rent_exempt_reserve = sol_rent_minimum_balance(&rent, SOL_STAKE_STATE_SIZE);

    /* Initialize stake state */
    sol_stake_state_t state;
    sol_stake_state_init(&state, &authorized, &lockup, rent_exempt_reserve);

    /* Serialize to account */
    size_t written;
    sol_err_t err = sol_stake_state_serialize(&state, stake_account->data,
                                               stake_account->meta.data_len, &written);
    if (err != SOL_OK) {
        sol_account_destroy(stake_account);
        return err;
    }

    sol_bank_store_account(ctx->bank, stake_pubkey, stake_account);
    sol_account_destroy(stake_account);

    return SOL_OK;
}

/*
 * Execute Delegate instruction
 */
static sol_err_t
execute_delegate(sol_invoke_context_t* ctx) {
    /* Accounts: [0] stake, [1] vote, [2] clock, [3] stake_history, [4] config, [5] authority */
    if (ctx->account_indices_len < 6) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Verify stake authority (account 5) is a signer */
    if (!is_signer(ctx, 5)) {
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    const sol_pubkey_t* authority_pubkey = get_pubkey(ctx, 5);
    if (!authority_pubkey) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Get stake account */
    const sol_pubkey_t* stake_pubkey;
    sol_account_t* stake_account;
    SOL_TRY(get_account(ctx, 0, &stake_pubkey, &stake_account));

    if (!stake_account) {
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Verify stake account is owned by stake program */
    if (!sol_pubkey_eq(&stake_account->meta.owner, &SOL_STAKE_PROGRAM_ID)) {
        sol_account_destroy(stake_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Get vote account */
    const sol_pubkey_t* vote_pubkey;
    sol_account_t* vote_account;
    sol_err_t err = get_account(ctx, 1, &vote_pubkey, &vote_account);
    if (err != SOL_OK) {
        sol_account_destroy(stake_account);
        return err;
    }

    if (!vote_account) {
        sol_account_destroy(stake_account);
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Verify vote account is owned by vote program */
    if (!sol_pubkey_eq(&vote_account->meta.owner, &SOL_VOTE_PROGRAM_ID)) {
        sol_account_destroy(stake_account);
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Deserialize stake state */
    sol_stake_state_t state;
    err = sol_stake_state_deserialize(&state, stake_account->data,
                                       stake_account->meta.data_len);
    if (err != SOL_OK) {
        sol_account_destroy(stake_account);
        sol_account_destroy(vote_account);
        return err;
    }

    /* Verify authority matches authorized staker */
    if (!sol_pubkey_eq(authority_pubkey, &state.meta.authorized.staker)) {
        sol_account_destroy(stake_account);
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Calculate stake amount (balance minus rent exempt reserve) */
    uint64_t stake_amount = stake_account->meta.lamports - state.meta.rent_exempt_reserve;

    /* Delegate */
    uint64_t current_epoch = sol_bank_epoch(ctx->bank);
    err = sol_stake_delegate(&state, vote_pubkey, stake_amount, current_epoch);
    if (err != SOL_OK) {
        sol_account_destroy(stake_account);
        sol_account_destroy(vote_account);
        return err;
    }

    /* Get vote state for credits */
    sol_vote_state_t vote_state;
    if (sol_vote_state_deserialize(&vote_state, vote_account->data,
                                    vote_account->meta.data_len) == SOL_OK) {
        state.credits_observed = sol_vote_state_credits(&vote_state);
    }

    /* Serialize updated state */
    size_t written;
    err = sol_stake_state_serialize(&state, stake_account->data,
                                     stake_account->meta.data_len, &written);
    if (err != SOL_OK) {
        sol_account_destroy(stake_account);
        sol_account_destroy(vote_account);
        return err;
    }

    sol_bank_store_account(ctx->bank, stake_pubkey, stake_account);

    sol_account_destroy(stake_account);
    sol_account_destroy(vote_account);

    return SOL_OK;
}

/*
 * Execute Deactivate instruction
 *
 * Accounts: [0] = stake account, [1] = clock sysvar, [2] = stake authority (signer)
 */
static sol_err_t
execute_deactivate(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 3) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Verify stake authority (account 2) is a signer */
    if (!is_signer(ctx, 2)) {
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    const sol_pubkey_t* authority_pubkey = get_pubkey(ctx, 2);
    if (!authority_pubkey) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Get stake account */
    const sol_pubkey_t* stake_pubkey;
    sol_account_t* stake_account;
    SOL_TRY(get_account(ctx, 0, &stake_pubkey, &stake_account));

    if (!stake_account) {
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Verify stake account is owned by stake program */
    if (!sol_pubkey_eq(&stake_account->meta.owner, &SOL_STAKE_PROGRAM_ID)) {
        sol_account_destroy(stake_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Deserialize stake state */
    sol_stake_state_t state;
    sol_err_t err = sol_stake_state_deserialize(&state, stake_account->data,
                                                 stake_account->meta.data_len);
    if (err != SOL_OK) {
        sol_account_destroy(stake_account);
        return err;
    }

    /* Verify authority matches authorized staker */
    if (!sol_pubkey_eq(authority_pubkey, &state.meta.authorized.staker)) {
        sol_account_destroy(stake_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Deactivate */
    uint64_t current_epoch = sol_bank_epoch(ctx->bank);
    err = sol_stake_deactivate(&state, current_epoch);
    if (err != SOL_OK) {
        sol_account_destroy(stake_account);
        return err;
    }

    /* Serialize updated state */
    size_t written;
    err = sol_stake_state_serialize(&state, stake_account->data,
                                     stake_account->meta.data_len, &written);
    if (err != SOL_OK) {
        sol_account_destroy(stake_account);
        return err;
    }

    sol_bank_store_account(ctx->bank, stake_pubkey, stake_account);
    sol_account_destroy(stake_account);

    return SOL_OK;
}

/*
 * Execute Authorize instruction
 *
 * Changes the staker or withdrawer authority.
 * Accounts: [0] = stake account, [1] = clock sysvar, [2] = authority (signer)
 */
static sol_err_t
execute_authorize(sol_invoke_context_t* ctx, bool checked) {
    if (ctx->instruction_data_len < 4 + 32 + 4) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
    if (ctx->account_indices_len < (checked ? 4 : 3)) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Parse instruction data */
    const uint8_t* data = ctx->instruction_data + 4;

    sol_pubkey_t new_authority;
    memcpy(new_authority.bytes, data, 32);
    data += 32;

    uint32_t authorize_type;
    memcpy(&authorize_type, data, 4);

    /* Get stake account */
    const sol_pubkey_t* stake_pubkey;
    sol_account_t* stake_account;
    SOL_TRY(get_account(ctx, 0, &stake_pubkey, &stake_account));

    if (!stake_account) {
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Verify stake account is owned by stake program */
    if (!sol_pubkey_eq(&stake_account->meta.owner, &SOL_STAKE_PROGRAM_ID)) {
        sol_account_destroy(stake_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Deserialize stake state */
    sol_stake_state_t state;
    sol_err_t err = sol_stake_state_deserialize(&state, stake_account->data,
                                                 stake_account->meta.data_len);
    if (err != SOL_OK) {
        sol_account_destroy(stake_account);
        return err;
    }

    /* Verify authority (account 2) is a signer */
    if (!is_signer(ctx, 2)) {
        sol_account_destroy(stake_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Get authority pubkey and verify it matches the current authority */
    const sol_pubkey_t* authority_pubkey = get_pubkey(ctx, 2);
    if (!authority_pubkey) {
        sol_account_destroy(stake_account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Update the appropriate authority after verifying current authority */
    if (authorize_type == SOL_STAKE_AUTHORIZE_STAKER) {
        /* Verify signer matches current staker */
        if (!sol_pubkey_eq(authority_pubkey, &state.meta.authorized.staker)) {
            sol_account_destroy(stake_account);
            return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
        }
        state.meta.authorized.staker = new_authority;
    } else if (authorize_type == SOL_STAKE_AUTHORIZE_WITHDRAWER) {
        /* Verify signer matches current withdrawer */
        if (!sol_pubkey_eq(authority_pubkey, &state.meta.authorized.withdrawer)) {
            sol_account_destroy(stake_account);
            return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
        }
        state.meta.authorized.withdrawer = new_authority;
    } else {
        sol_account_destroy(stake_account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* For checked variant, verify new authority (account 3) is a signer and matches */
    if (checked) {
        if (!is_signer(ctx, 3)) {
            sol_account_destroy(stake_account);
            return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
        }
        const sol_pubkey_t* new_auth_pubkey = get_pubkey(ctx, 3);
        if (!new_auth_pubkey || !sol_pubkey_eq(new_auth_pubkey, &new_authority)) {
            sol_account_destroy(stake_account);
            return SOL_ERR_PROGRAM_INVALID_INSTR;
        }
    }

    /* Serialize updated state */
    size_t written;
    err = sol_stake_state_serialize(&state, stake_account->data,
                                     stake_account->meta.data_len, &written);
    if (err != SOL_OK) {
        sol_account_destroy(stake_account);
        return err;
    }

    sol_bank_store_account(ctx->bank, stake_pubkey, stake_account);
    sol_account_destroy(stake_account);

    return SOL_OK;
}

/*
 * Execute Split instruction
 *
 * Splits stake account into two accounts.
 * Accounts: [0] = source stake, [1] = destination stake, [2] = authority (signer)
 */
static sol_err_t
execute_split(sol_invoke_context_t* ctx) {
    if (ctx->instruction_data_len < 4 + 8) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
    if (ctx->account_indices_len < 3) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Verify stake authority (account 2) is a signer */
    if (!is_signer(ctx, 2)) {
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    const sol_pubkey_t* authority_pubkey = get_pubkey(ctx, 2);
    if (!authority_pubkey) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Parse lamports to split */
    uint64_t lamports;
    memcpy(&lamports, ctx->instruction_data + 4, 8);

    /* Get source stake account */
    const sol_pubkey_t* source_pubkey;
    sol_account_t* source_account;
    SOL_TRY(get_account(ctx, 0, &source_pubkey, &source_account));

    if (!source_account) {
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Verify source is owned by stake program */
    if (!sol_pubkey_eq(&source_account->meta.owner, &SOL_STAKE_PROGRAM_ID)) {
        sol_account_destroy(source_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Get destination stake account */
    const sol_pubkey_t* dest_pubkey;
    sol_account_t* dest_account;
    sol_err_t err = get_account(ctx, 1, &dest_pubkey, &dest_account);
    if (err != SOL_OK) {
        sol_account_destroy(source_account);
        return err;
    }

    if (!dest_account) {
        sol_account_destroy(source_account);
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Verify destination is owned by stake program and uninitialized */
    if (!sol_pubkey_eq(&dest_account->meta.owner, &SOL_STAKE_PROGRAM_ID)) {
        sol_account_destroy(source_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Deserialize source stake state */
    sol_stake_state_t source_state;
    err = sol_stake_state_deserialize(&source_state, source_account->data,
                                       source_account->meta.data_len);
    if (err != SOL_OK) {
        sol_account_destroy(source_account);
        sol_account_destroy(dest_account);
        return err;
    }

    /* Verify authority matches authorized staker */
    if (!sol_pubkey_eq(authority_pubkey, &source_state.meta.authorized.staker)) {
        sol_account_destroy(source_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Check source has enough balance */
    if (source_account->meta.lamports < lamports) {
        sol_account_destroy(source_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_TX_INSUFFICIENT_FUNDS;
    }

    /* Ensure both accounts have minimum balance after split */
    uint64_t min_balance = source_state.meta.rent_exempt_reserve;
    if (source_account->meta.lamports - lamports < min_balance ||
        lamports < min_balance) {
        sol_account_destroy(source_account);
        sol_account_destroy(dest_account);
        return SOL_ERR_TX_INSUFFICIENT_FUNDS;
    }

    /* Initialize destination with same state but different balance */
    sol_stake_state_t dest_state = source_state;
    /* Rent exempt reserve is the same - based on account size, not lamports */

    /* If source is delegated, split the delegation proportionally */
    if (source_state.state == SOL_STAKE_STATE_STAKE) {
        uint64_t total_stake = source_state.delegation.stake;
        uint64_t source_remaining = source_account->meta.lamports - lamports;
        uint64_t source_stake = (source_remaining > source_state.meta.rent_exempt_reserve)
            ? source_remaining - source_state.meta.rent_exempt_reserve : 0;
        uint64_t dest_stake = (lamports > dest_state.meta.rent_exempt_reserve)
            ? lamports - dest_state.meta.rent_exempt_reserve : 0;

        if (source_stake + dest_stake <= total_stake) {
            source_state.delegation.stake = source_stake;
            dest_state.delegation.stake = dest_stake;
        }
    }

    /* Self-split: no-op for lamports (sub+add on same account = no change) */
    if (sol_pubkey_eq(source_pubkey, dest_pubkey)) {
        sol_bank_store_account(ctx->bank, source_pubkey, source_account);
        sol_account_destroy(source_account);
        sol_account_destroy(dest_account);
        return SOL_OK;
    }

    /* Transfer lamports */
    source_account->meta.lamports -= lamports;
    dest_account->meta.lamports += lamports;

    /* Serialize updated states */
    size_t written;
    err = sol_stake_state_serialize(&source_state, source_account->data,
                                     source_account->meta.data_len, &written);
    if (err != SOL_OK) {
        sol_account_destroy(source_account);
        sol_account_destroy(dest_account);
        return err;
    }

    err = sol_stake_state_serialize(&dest_state, dest_account->data,
                                     dest_account->meta.data_len, &written);
    if (err != SOL_OK) {
        sol_account_destroy(source_account);
        sol_account_destroy(dest_account);
        return err;
    }

    sol_bank_store_account(ctx->bank, source_pubkey, source_account);
    sol_bank_store_account(ctx->bank, dest_pubkey, dest_account);

    sol_account_destroy(source_account);
    sol_account_destroy(dest_account);

    return SOL_OK;
}

/*
 * Execute SetLockup instruction
 *
 * Changes lockup parameters of a stake account.
 * Accounts: [0] = stake account, [1] = lockup authority (signer)
 */
static sol_err_t
execute_set_lockup(sol_invoke_context_t* ctx, bool checked) {
    /* Minimum: type(4), we'll check for optional lockup params */
    if (ctx->account_indices_len < 2) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Verify lockup authority (account 1) is a signer */
    if (!is_signer(ctx, 1)) {
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    const sol_pubkey_t* authority_pubkey = get_pubkey(ctx, 1);
    if (!authority_pubkey) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Parse instruction data - lockup parameters are optional */
    const uint8_t* data = ctx->instruction_data + 4;
    size_t remaining = ctx->instruction_data_len - 4;

    int64_t new_unix_timestamp = 0;
    bool has_timestamp = false;
    uint64_t new_epoch = 0;
    bool has_epoch = false;
    sol_pubkey_t new_custodian = {0};
    bool has_custodian = false;

    /* Parse optional timestamp (1 byte flag + 8 bytes value) */
    if (remaining >= 9) {
        has_timestamp = (data[0] != 0);
        if (has_timestamp) {
            memcpy(&new_unix_timestamp, data + 1, 8);
        }
        data += 9;
        remaining -= 9;
    }

    /* Parse optional epoch (1 byte flag + 8 bytes value) */
    if (remaining >= 9) {
        has_epoch = (data[0] != 0);
        if (has_epoch) {
            memcpy(&new_epoch, data + 1, 8);
        }
        data += 9;
        remaining -= 9;
    }

    /* Parse optional custodian (1 byte flag + 32 bytes value) */
    if (remaining >= 33 && !checked) {
        has_custodian = (data[0] != 0);
        if (has_custodian) {
            memcpy(new_custodian.bytes, data + 1, 32);
        }
    }

    /* Get stake account */
    const sol_pubkey_t* stake_pubkey;
    sol_account_t* stake_account;
    SOL_TRY(get_account(ctx, 0, &stake_pubkey, &stake_account));

    if (!stake_account) {
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Verify stake account is owned by stake program */
    if (!sol_pubkey_eq(&stake_account->meta.owner, &SOL_STAKE_PROGRAM_ID)) {
        sol_account_destroy(stake_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Deserialize stake state */
    sol_stake_state_t state;
    sol_err_t err = sol_stake_state_deserialize(&state, stake_account->data,
                                                 stake_account->meta.data_len);
    if (err != SOL_OK) {
        sol_account_destroy(stake_account);
        return err;
    }

    /* Verify authority: must be custodian if lockup has custodian, otherwise withdrawer */
    static const sol_pubkey_t ZERO_PUBKEY = {0};
    bool has_custodian_set = !sol_pubkey_eq(&state.meta.lockup.custodian, &ZERO_PUBKEY);

    if (has_custodian_set) {
        if (!sol_pubkey_eq(authority_pubkey, &state.meta.lockup.custodian)) {
            sol_account_destroy(stake_account);
            return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
        }
    } else {
        if (!sol_pubkey_eq(authority_pubkey, &state.meta.authorized.withdrawer)) {
            sol_account_destroy(stake_account);
            return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
        }
    }

    /* Update lockup parameters */
    if (has_timestamp) {
        state.meta.lockup.unix_timestamp = new_unix_timestamp;
    }
    if (has_epoch) {
        state.meta.lockup.epoch = new_epoch;
    }
    if (has_custodian) {
        state.meta.lockup.custodian = new_custodian;
    }

    /* For checked variant, get new custodian from account and verify it's a signer */
    if (checked && ctx->account_indices_len >= 3) {
        /* Verify new custodian (account 2) is a signer */
        if (!is_signer(ctx, 2)) {
            sol_account_destroy(stake_account);
            return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
        }

        const sol_pubkey_t* custodian_pubkey = get_pubkey(ctx, 2);
        if (custodian_pubkey) {
            state.meta.lockup.custodian = *custodian_pubkey;
        }
    }

    /* Serialize updated state */
    size_t written;
    err = sol_stake_state_serialize(&state, stake_account->data,
                                     stake_account->meta.data_len, &written);
    if (err != SOL_OK) {
        sol_account_destroy(stake_account);
        return err;
    }

    sol_bank_store_account(ctx->bank, stake_pubkey, stake_account);
    sol_account_destroy(stake_account);

    return SOL_OK;
}

/*
 * Execute Merge instruction
 *
 * Merges two stake accounts into one.
 * Accounts: [0] = destination stake, [1] = source stake, [2] = clock, [3] = stake_history, [4] = authority
 */
static sol_err_t
execute_merge(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 5) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Verify stake authority (account 4) is a signer */
    if (!is_signer(ctx, 4)) {
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    const sol_pubkey_t* authority_pubkey = get_pubkey(ctx, 4);
    if (!authority_pubkey) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Get destination stake account */
    const sol_pubkey_t* dest_pubkey;
    sol_account_t* dest_account;
    SOL_TRY(get_account(ctx, 0, &dest_pubkey, &dest_account));

    if (!dest_account) {
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Verify dest is owned by stake program */
    if (!sol_pubkey_eq(&dest_account->meta.owner, &SOL_STAKE_PROGRAM_ID)) {
        sol_account_destroy(dest_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Get source stake account */
    const sol_pubkey_t* source_pubkey;
    sol_account_t* source_account;
    sol_err_t err = get_account(ctx, 1, &source_pubkey, &source_account);
    if (err != SOL_OK) {
        sol_account_destroy(dest_account);
        return err;
    }

    if (!source_account) {
        sol_account_destroy(dest_account);
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Verify source is owned by stake program */
    if (!sol_pubkey_eq(&source_account->meta.owner, &SOL_STAKE_PROGRAM_ID)) {
        sol_account_destroy(dest_account);
        sol_account_destroy(source_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Deserialize both stake states */
    sol_stake_state_t dest_state;
    err = sol_stake_state_deserialize(&dest_state, dest_account->data,
                                       dest_account->meta.data_len);
    if (err != SOL_OK) {
        sol_account_destroy(dest_account);
        sol_account_destroy(source_account);
        return err;
    }

    sol_stake_state_t source_state;
    err = sol_stake_state_deserialize(&source_state, source_account->data,
                                       source_account->meta.data_len);
    if (err != SOL_OK) {
        sol_account_destroy(dest_account);
        sol_account_destroy(source_account);
        return err;
    }

    /* Verify authority matches staker for both accounts */
    if (!sol_pubkey_eq(authority_pubkey, &dest_state.meta.authorized.staker) ||
        !sol_pubkey_eq(authority_pubkey, &source_state.meta.authorized.staker)) {
        sol_account_destroy(dest_account);
        sol_account_destroy(source_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Both must be delegated to same validator or both be inactive */
    if (dest_state.state == SOL_STAKE_STATE_STAKE &&
        source_state.state == SOL_STAKE_STATE_STAKE) {
        if (!sol_pubkey_eq(&dest_state.delegation.voter_pubkey,
                           &source_state.delegation.voter_pubkey)) {
            sol_account_destroy(dest_account);
            sol_account_destroy(source_account);
            return SOL_ERR_PROGRAM_INVALID_INSTR;
        }
    }

    /* Self-merge: In Agave, the second mutable borrow of the same account
       would fail (BorrowError), so self-merge is rejected. Match that. */
    if (sol_pubkey_eq(dest_pubkey, source_pubkey)) {
        sol_account_destroy(dest_account);
        sol_account_destroy(source_account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Merge lamports and stake */
    dest_account->meta.lamports += source_account->meta.lamports;

    if (dest_state.state == SOL_STAKE_STATE_STAKE &&
        source_state.state == SOL_STAKE_STATE_STAKE) {
        dest_state.delegation.stake += source_state.delegation.stake;

        /* Keep the earlier activation epoch */
        if (source_state.delegation.activation_epoch < dest_state.delegation.activation_epoch) {
            dest_state.delegation.activation_epoch = source_state.delegation.activation_epoch;
        }

        /* Sum credits observed (simplified) */
        dest_state.credits_observed += source_state.credits_observed;
    }

    /* Close source account */
    source_account->meta.lamports = 0;
    memset(source_account->data, 0, source_account->meta.data_len);

    /* Serialize updated destination state */
    size_t written;
    err = sol_stake_state_serialize(&dest_state, dest_account->data,
                                     dest_account->meta.data_len, &written);
    if (err != SOL_OK) {
        sol_account_destroy(dest_account);
        sol_account_destroy(source_account);
        return err;
    }

    sol_bank_store_account(ctx->bank, dest_pubkey, dest_account);
    sol_bank_store_account(ctx->bank, source_pubkey, source_account);

    sol_account_destroy(dest_account);
    sol_account_destroy(source_account);

    return SOL_OK;
}

/*
 * Execute Redelegate instruction
 *
 * Redelegates stake to a different validator.
 * Accounts: [0] = stake, [1] = uninitialized stake, [2] = vote, [3] = config, [4] = authority
 */
static sol_err_t
execute_redelegate(sol_invoke_context_t* ctx) {
    if (ctx->account_indices_len < 5) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Verify stake authority (account 4) is a signer */
    if (!is_signer(ctx, 4)) {
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    const sol_pubkey_t* authority_pubkey = get_pubkey(ctx, 4);
    if (!authority_pubkey) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Get source stake account */
    const sol_pubkey_t* stake_pubkey;
    sol_account_t* stake_account;
    SOL_TRY(get_account(ctx, 0, &stake_pubkey, &stake_account));

    if (!stake_account) {
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Verify stake account is owned by stake program */
    if (!sol_pubkey_eq(&stake_account->meta.owner, &SOL_STAKE_PROGRAM_ID)) {
        sol_account_destroy(stake_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Get new vote account */
    const sol_pubkey_t* vote_pubkey;
    sol_account_t* vote_account;
    sol_err_t err = get_account(ctx, 2, &vote_pubkey, &vote_account);
    if (err != SOL_OK) {
        sol_account_destroy(stake_account);
        return err;
    }

    if (!vote_account) {
        sol_account_destroy(stake_account);
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Verify vote account is owned by vote program */
    if (!sol_pubkey_eq(&vote_account->meta.owner, &SOL_VOTE_PROGRAM_ID)) {
        sol_account_destroy(stake_account);
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Deserialize stake state */
    sol_stake_state_t state;
    err = sol_stake_state_deserialize(&state, stake_account->data,
                                       stake_account->meta.data_len);
    if (err != SOL_OK) {
        sol_account_destroy(stake_account);
        sol_account_destroy(vote_account);
        return err;
    }

    /* Verify authority matches authorized staker */
    if (!sol_pubkey_eq(authority_pubkey, &state.meta.authorized.staker)) {
        sol_account_destroy(stake_account);
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Must be an active delegation */
    if (state.state != SOL_STAKE_STATE_STAKE ||
        state.delegation.deactivation_epoch != UINT64_MAX) {
        sol_account_destroy(stake_account);
        sol_account_destroy(vote_account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Update delegation to new vote account */
    uint64_t current_epoch = sol_bank_epoch(ctx->bank);
    state.delegation.voter_pubkey = *vote_pubkey;
    state.delegation.activation_epoch = current_epoch;

    /* Update credits observed from new vote account */
    sol_vote_state_t vote_state;
    if (sol_vote_state_deserialize(&vote_state, vote_account->data,
                                    vote_account->meta.data_len) == SOL_OK) {
        state.credits_observed = sol_vote_state_credits(&vote_state);
    }

    /* Serialize updated state */
    size_t written;
    err = sol_stake_state_serialize(&state, stake_account->data,
                                     stake_account->meta.data_len, &written);
    if (err != SOL_OK) {
        sol_account_destroy(stake_account);
        sol_account_destroy(vote_account);
        return err;
    }

    sol_bank_store_account(ctx->bank, stake_pubkey, stake_account);

    sol_account_destroy(stake_account);
    sol_account_destroy(vote_account);

    return SOL_OK;
}

/*
 * Execute Withdraw instruction
 *
 * Accounts: [0] = stake, [1] = destination, [2] = clock, [3] = stake_history, [4] = withdrawer
 */
static sol_err_t
execute_withdraw(sol_invoke_context_t* ctx) {
    if (ctx->instruction_data_len < 4 + 8) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
    if (ctx->account_indices_len < 5) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Verify withdrawer authority (account 4) is a signer */
    if (!is_signer(ctx, 4)) {
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    const sol_pubkey_t* withdrawer_pubkey = get_pubkey(ctx, 4);
    if (!withdrawer_pubkey) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Parse amount */
    uint64_t lamports;
    memcpy(&lamports, ctx->instruction_data + 4, 8);

    /* Get stake account */
    const sol_pubkey_t* stake_pubkey;
    sol_account_t* stake_account;
    SOL_TRY(get_account(ctx, 0, &stake_pubkey, &stake_account));

    if (!stake_account) {
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    /* Verify stake account is owned by stake program */
    if (!sol_pubkey_eq(&stake_account->meta.owner, &SOL_STAKE_PROGRAM_ID)) {
        sol_account_destroy(stake_account);
        return SOL_ERR_PROGRAM_INVALID_OWNER;
    }

    /* Get destination account */
    const sol_pubkey_t* dest_pubkey;
    sol_account_t* dest_account;
    sol_err_t err = get_account(ctx, 1, &dest_pubkey, &dest_account);
    if (err != SOL_OK) {
        sol_account_destroy(stake_account);
        return err;
    }

    /* Deserialize stake state */
    sol_stake_state_t state;
    err = sol_stake_state_deserialize(&state, stake_account->data,
                                       stake_account->meta.data_len);
    if (err != SOL_OK) {
        sol_account_destroy(stake_account);
        if (dest_account) sol_account_destroy(dest_account);
        return err;
    }

    /* Verify withdrawer matches authorized withdrawer */
    if (!sol_pubkey_eq(withdrawer_pubkey, &state.meta.authorized.withdrawer)) {
        sol_account_destroy(stake_account);
        if (dest_account) sol_account_destroy(dest_account);
        return SOL_ERR_PROGRAM_MISSING_SIGNATURE;
    }

    /* Check if locked */
    uint64_t current_epoch = sol_bank_epoch(ctx->bank);
    if (sol_stake_is_locked(&state, current_epoch, 0)) {
        sol_account_destroy(stake_account);
        if (dest_account) sol_account_destroy(dest_account);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Check balance */
    if (stake_account->meta.lamports < lamports) {
        sol_account_destroy(stake_account);
        if (dest_account) sol_account_destroy(dest_account);
        return SOL_ERR_TX_INSUFFICIENT_FUNDS;
    }

    /* If active stake, can only withdraw excess */
    if (state.state == SOL_STAKE_STATE_STAKE &&
        state.delegation.deactivation_epoch == UINT64_MAX) {
        uint64_t min_balance = state.meta.rent_exempt_reserve + state.delegation.stake;
        if (stake_account->meta.lamports - lamports < min_balance) {
            sol_account_destroy(stake_account);
            if (dest_account) sol_account_destroy(dest_account);
            return SOL_ERR_TX_INSUFFICIENT_FUNDS;
        }
    }

    /* Self-withdrawal: no-op for lamports (sub+add on same account = no change) */
    if (sol_pubkey_eq(stake_pubkey, dest_pubkey)) {
        sol_bank_store_account(ctx->bank, stake_pubkey, stake_account);
        sol_account_destroy(stake_account);
        if (dest_account) sol_account_destroy(dest_account);
        return SOL_OK;
    }

    /* Create destination if doesn't exist */
    if (!dest_account) {
        dest_account = sol_account_new(0, 0, &SOL_SYSTEM_PROGRAM_ID);
        if (!dest_account) {
            sol_account_destroy(stake_account);
            return SOL_ERR_NOMEM;
        }
    }

    /* Transfer */
    stake_account->meta.lamports -= lamports;
    dest_account->meta.lamports += lamports;

    sol_bank_store_account(ctx->bank, stake_pubkey, stake_account);
    sol_bank_store_account(ctx->bank, dest_pubkey, dest_account);

    sol_account_destroy(stake_account);
    sol_account_destroy(dest_account);

    return SOL_OK;
}

sol_err_t
sol_stake_program_execute(sol_invoke_context_t* ctx) {
    if (!ctx || !ctx->bank || !ctx->instruction_data || ctx->instruction_data_len < 4) {
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    /* Read instruction type */
    uint32_t instr_type;
    memcpy(&instr_type, ctx->instruction_data, 4);

    switch (instr_type) {
    case SOL_STAKE_INSTR_INITIALIZE:
    case SOL_STAKE_INSTR_INITIALIZE_CHECKED:
        return execute_initialize(ctx);

    case SOL_STAKE_INSTR_DELEGATE:
        return execute_delegate(ctx);

    case SOL_STAKE_INSTR_DEACTIVATE:
    case SOL_STAKE_INSTR_DEACTIVATE_DELINQUENT:
        return execute_deactivate(ctx);

    case SOL_STAKE_INSTR_WITHDRAW:
        return execute_withdraw(ctx);

    case SOL_STAKE_INSTR_AUTHORIZE:
        return execute_authorize(ctx, false);

    case SOL_STAKE_INSTR_AUTHORIZE_CHECKED:
        return execute_authorize(ctx, true);

    case SOL_STAKE_INSTR_AUTHORIZE_WITH_SEED:
    case SOL_STAKE_INSTR_AUTHORIZE_CHECKED_WITH_SEED:
        /* These use seeded addresses - similar to authorize but derive address */
        return execute_authorize(ctx, instr_type == SOL_STAKE_INSTR_AUTHORIZE_CHECKED_WITH_SEED);

    case SOL_STAKE_INSTR_SPLIT:
        return execute_split(ctx);

    case SOL_STAKE_INSTR_SET_LOCKUP:
        return execute_set_lockup(ctx, false);

    case SOL_STAKE_INSTR_SET_LOCKUP_CHECKED:
        return execute_set_lockup(ctx, true);

    case SOL_STAKE_INSTR_MERGE:
        return execute_merge(ctx);

    case SOL_STAKE_INSTR_REDELEGATE:
        return execute_redelegate(ctx);

    case SOL_STAKE_INSTR_GET_MINIMUM_DELEGATION:
        /* Return minimum delegation via return data */
        {
            uint64_t min_delegation = SOL_MIN_STAKE_DELEGATION;
            memcpy(ctx->return_data, &min_delegation, 8);
            ctx->return_data_len = 8;
            ctx->return_data_program = SOL_STAKE_PROGRAM_ID;
            return SOL_OK;
        }

    default:
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }
}

sol_err_t
sol_stake_create_account(sol_bank_t* bank,
                          const sol_pubkey_t* stake_pubkey,
                          const sol_stake_authorized_t* authorized,
                          const sol_lockup_t* lockup,
                          uint64_t lamports) {
    if (!bank || !stake_pubkey || !authorized) {
        return SOL_ERR_INVAL;
    }

    /* Create account with stake program as owner */
    sol_account_t* account = sol_account_new(lamports, SOL_STAKE_STATE_SIZE,
                                              &SOL_STAKE_PROGRAM_ID);
    if (!account) {
        return SOL_ERR_NOMEM;
    }

    /* Initialize stake state with proper rent exempt reserve */
    sol_rent_t rent = SOL_RENT_DEFAULT;
    uint64_t rent_exempt_reserve = sol_rent_minimum_balance(&rent, SOL_STAKE_STATE_SIZE);
    sol_stake_state_t state;
    sol_stake_state_init(&state, authorized, lockup, rent_exempt_reserve);

    /* Serialize to account */
    size_t written;
    sol_err_t err = sol_stake_state_serialize(&state, account->data,
                                               account->meta.data_len, &written);
    if (err != SOL_OK) {
        sol_account_destroy(account);
        return err;
    }

    err = sol_bank_store_account(bank, stake_pubkey, account);
    sol_account_destroy(account);

    return err;
}

sol_err_t
sol_stake_get_state(sol_bank_t* bank,
                     const sol_pubkey_t* stake_pubkey,
                     sol_stake_state_t* state) {
    if (!bank || !stake_pubkey || !state) {
        return SOL_ERR_INVAL;
    }

    sol_account_t* account = sol_bank_load_account(bank, stake_pubkey);
    if (!account) {
        return SOL_ERR_TX_ACCOUNT_NOT_FOUND;
    }

    sol_err_t err = sol_stake_state_deserialize(state, account->data,
                                                 account->meta.data_len);
    sol_account_destroy(account);

    return err;
}

/*
 * Context for delegation iteration
 */
typedef struct {
    const sol_pubkey_t* target_vote_pubkey;
    uint64_t            current_epoch;
    uint64_t            total_stake;
    const sol_stake_history_t* history;
} delegation_iter_ctx_t;

/*
 * Callback to sum delegated stake
 */
static bool
delegation_sum_callback(const sol_pubkey_t* pubkey,
                        const sol_account_t* account,
                        void* ctx) {
    (void)pubkey;

    delegation_iter_ctx_t* iter_ctx = (delegation_iter_ctx_t*)ctx;

    /* Only process stake program accounts */
    if (!sol_pubkey_eq(&account->meta.owner, &SOL_STAKE_PROGRAM_ID)) {
        return true;  /* Continue iteration */
    }

    /* Deserialize stake state */
    sol_stake_state_t state;
    if (sol_stake_state_deserialize(&state, account->data,
                                     account->meta.data_len) != SOL_OK) {
        return true;  /* Continue on error */
    }

    /* Only count active delegations to the target vote account */
    if (state.state == SOL_STAKE_STATE_STAKE &&
        sol_pubkey_eq(&state.delegation.voter_pubkey, iter_ctx->target_vote_pubkey)) {
        /* Get effective stake at current epoch */
        uint64_t effective = iter_ctx->history
            ? sol_stake_effective_stake_with_history(&state, iter_ctx->current_epoch, iter_ctx->history)
            : sol_stake_effective_stake(&state, iter_ctx->current_epoch);
        iter_ctx->total_stake += effective;
    }

    return true;  /* Continue iteration */
}

uint64_t
sol_stake_get_delegated_stake(sol_bank_t* bank,
                               const sol_pubkey_t* vote_pubkey,
                               uint64_t current_epoch) {
    if (!bank || !vote_pubkey) {
        return 0;
    }

    /* Get accounts_db from bank - need to add accessor or use internal knowledge */
    sol_accounts_db_t* accounts_db = sol_bank_get_accounts_db(bank);
    if (!accounts_db) {
        return 0;
    }

    sol_stake_history_t history;
    sol_stake_history_init(&history);
    const sol_stake_history_t* history_ptr = NULL;
    sol_account_t* stake_history_acct =
        sol_bank_load_account(bank, &SOL_SYSVAR_STAKE_HISTORY_ID);
    if (stake_history_acct && stake_history_acct->meta.data_len >= 8) {
        if (sol_stake_history_deserialize(&history,
                                          stake_history_acct->data,
                                          stake_history_acct->meta.data_len) == SOL_OK) {
            history_ptr = &history;
        }
    }
    sol_account_destroy(stake_history_acct);

    delegation_iter_ctx_t ctx = {
        .target_vote_pubkey = vote_pubkey,
        .current_epoch = current_epoch,
        .total_stake = 0,
        .history = history_ptr,
    };

    sol_accounts_db_iterate_owner(accounts_db, &SOL_STAKE_PROGRAM_ID, delegation_sum_callback, &ctx);

    return ctx.total_stake;
}

typedef struct {
    sol_pubkey_map_t* map;
    uint64_t          epoch;
    uint64_t          total_stake;
    sol_err_t         err;
    const sol_stake_history_t* history;
} vote_stake_map_ctx_t;

static bool
build_vote_stake_map_cb(const sol_pubkey_t* pubkey,
                        const sol_account_t* account,
                        void* ctx) {
    (void)pubkey;

    vote_stake_map_ctx_t* mctx = (vote_stake_map_ctx_t*)ctx;
    if (!mctx || !mctx->map || !account) {
        return false;
    }

    if (account->meta.lamports == 0) {
        return true;
    }

    if (!sol_pubkey_eq(&account->meta.owner, &SOL_STAKE_PROGRAM_ID)) {
        return true;
    }

    sol_stake_state_t state;
    if (sol_stake_state_deserialize(&state, account->data,
                                     account->meta.data_len) != SOL_OK) {
        return true;
    }

    if (state.state != SOL_STAKE_STATE_STAKE) {
        return true;
    }

    uint64_t effective = mctx->history
        ? sol_stake_effective_stake_with_history(&state, mctx->epoch, mctx->history)
        : sol_stake_effective_stake(&state, mctx->epoch);
    if (effective == 0) {
        return true;
    }

    const sol_pubkey_t* vote_key = &state.delegation.voter_pubkey;
    uint64_t* existing = (uint64_t*)sol_pubkey_map_get(mctx->map, vote_key);
    if (existing) {
        *existing += effective;
    } else {
        if (!sol_pubkey_map_insert(mctx->map, vote_key, &effective)) {
            mctx->err = SOL_ERR_NOMEM;
            return false;
        }
    }

    mctx->total_stake += effective;
    return true;
}

sol_pubkey_map_t*
sol_stake_build_vote_stake_map(sol_bank_t* bank,
                               uint64_t current_epoch,
                               uint64_t* out_total_stake) {
    if (out_total_stake) {
        *out_total_stake = 0;
    }
    if (!bank) {
        return NULL;
    }

    sol_accounts_db_t* accounts_db = sol_bank_get_accounts_db(bank);
    if (!accounts_db) {
        return NULL;
    }

    sol_pubkey_map_t* map = sol_pubkey_map_new(sizeof(uint64_t), 8192);
    if (!map) {
        return NULL;
    }

    sol_stake_history_t history;
    sol_stake_history_init(&history);
    const sol_stake_history_t* history_ptr = NULL;
    sol_account_t* stake_history_acct =
        sol_bank_load_account(bank, &SOL_SYSVAR_STAKE_HISTORY_ID);
    if (stake_history_acct && stake_history_acct->meta.data_len >= 8) {
        if (sol_stake_history_deserialize(&history,
                                          stake_history_acct->data,
                                          stake_history_acct->meta.data_len) == SOL_OK) {
            history_ptr = &history;
        }
    }
    sol_account_destroy(stake_history_acct);

    vote_stake_map_ctx_t ctx = {
        .map = map,
        .epoch = current_epoch,
        .total_stake = 0,
        .err = SOL_OK,
        .history = history_ptr,
    };

    /* Prefer the owner index when available (RocksDB) to avoid scanning the
     * entire accounts set. Falls back to full iteration automatically. */
    sol_accounts_db_iterate_owner(accounts_db, &SOL_STAKE_PROGRAM_ID, build_vote_stake_map_cb, &ctx);

    if (ctx.err != SOL_OK) {
        sol_pubkey_map_destroy(map);
        return NULL;
    }

    if (out_total_stake) {
        *out_total_stake = ctx.total_stake;
    }

    return map;
}

static uint64_t
stake_mul_div_u64(uint64_t numerator, uint64_t room, uint64_t denom) {
    if (denom == 0) {
        return 0;
    }
    __uint128_t num = (__uint128_t)numerator * (__uint128_t)room;
    return (uint64_t)(num / denom);
}

static uint64_t
stake_simple_rate_step(uint64_t amount, double rate) {
    if (amount == 0) return 0;
    if (!(rate > 0.0)) return 0;
    uint64_t step = (uint64_t)((double)amount * rate);
    if (step > amount) step = amount;
    return step;
}

static uint64_t
stake_history_warmup_step(uint64_t activating,
                          const sol_stake_history_entry_t* entry,
                          double rate) {
    if (!entry) return 0;
    if (activating == 0) return 0;
    if (entry->activating == 0) return 0;

    uint64_t room = (uint64_t)((double)entry->effective * rate);
    if (room > entry->activating) room = entry->activating;
    if (room == 0) return 0;

    uint64_t delta = stake_mul_div_u64(activating, room, entry->activating);
    if (delta > activating) delta = activating;
    return delta;
}

static uint64_t
stake_history_cooldown_step(uint64_t deactivating,
                            const sol_stake_history_entry_t* entry,
                            double rate) {
    if (!entry) return 0;
    if (deactivating == 0) return 0;
    if (entry->deactivating == 0) return 0;

    uint64_t room = (uint64_t)((double)entry->effective * rate);
    if (room > entry->deactivating) room = entry->deactivating;
    if (room == 0) return 0;

    uint64_t delta = stake_mul_div_u64(deactivating, room, entry->deactivating);
    if (delta > deactivating) delta = deactivating;
    return delta;
}

/*
 * Calculate stake activation status using stake history
 *
 * The warmup/cooldown calculation follows Solana's stake activation algorithm:
 * 1. Stake activates gradually over multiple epochs
 * 2. The rate is limited by how much total stake is activating network-wide
 * 3. At most 25% of activating stake can become effective per epoch
 * 4. Same applies to deactivation (cooldown)
 */
sol_err_t
sol_stake_get_activation_status(const sol_stake_state_t* state,
                                 uint64_t target_epoch,
                                 const sol_stake_history_t* history,
                                 sol_stake_activation_t* out_status) {
    if (!state || !out_status) {
        return SOL_ERR_INVAL;
    }

    memset(out_status, 0, sizeof(sol_stake_activation_t));

    /* Must be a delegated stake account */
    if (state->state != SOL_STAKE_STATE_STAKE) {
        return SOL_OK;
    }

    uint64_t stake = state->delegation.stake;
    uint64_t activation_epoch = state->delegation.activation_epoch;
    uint64_t deactivation_epoch = state->delegation.deactivation_epoch;
    double warmup_cooldown_rate = state->delegation.warmup_cooldown_rate;

    /* Before activation epoch: nothing effective */
    if (target_epoch < activation_epoch) {
        out_status->activating = stake;
        return SOL_OK;
    }

    const bool is_deactivating = (deactivation_epoch != UINT64_MAX) &&
                                 (target_epoch >= deactivation_epoch);

    uint64_t effective = 0;
    uint64_t activating = stake;

    /* Warmup: apply transitions from `epoch` -> `epoch+1` using the stake
     * history entry for `epoch`. */
    uint64_t warmup_end = is_deactivating ? deactivation_epoch : target_epoch;
    for (uint64_t epoch = activation_epoch; epoch < warmup_end; epoch++) {
        if (activating == 0) break;

        const sol_stake_history_entry_t* entry = NULL;
        if (history && history->len > 0) {
            entry = sol_stake_history_get(history, epoch);
        }

        uint64_t delta = entry
            ? stake_history_warmup_step(activating, entry, warmup_cooldown_rate)
            : stake_simple_rate_step(activating, warmup_cooldown_rate);

        if (delta > activating) delta = activating;
        effective += delta;
        activating -= delta;
    }

    if (!is_deactivating) {
        out_status->effective = effective;
        out_status->activating = activating;
        out_status->deactivating = 0;
        return SOL_OK;
    }

    /* Cooldown: once deactivated, remaining activating stake is treated as
     * inactive (withdrawable); only the currently-effective portion cools down. */
    uint64_t still_effective = effective;
    for (uint64_t epoch = deactivation_epoch; epoch < target_epoch; epoch++) {
        if (still_effective == 0) break;

        const sol_stake_history_entry_t* entry = NULL;
        if (history && history->len > 0) {
            entry = sol_stake_history_get(history, epoch);
        }

        uint64_t delta = entry
            ? stake_history_cooldown_step(still_effective, entry, warmup_cooldown_rate)
            : stake_simple_rate_step(still_effective, warmup_cooldown_rate);

        if (delta > still_effective) delta = still_effective;
        still_effective -= delta;
    }

    out_status->effective = still_effective;
    out_status->activating = 0;
    out_status->deactivating = still_effective;
    return SOL_OK;
}

/*
 * Calculate effective stake with stake history
 */
uint64_t
sol_stake_effective_stake_with_history(const sol_stake_state_t* state,
                                        uint64_t target_epoch,
                                        const sol_stake_history_t* history) {
    sol_stake_activation_t status;

    if (sol_stake_get_activation_status(state, target_epoch, history, &status) != SOL_OK) {
        return 0;
    }

    return status.effective;
}

/*
 * Calculate rewards with credits update
 *
 * This is called during epoch rewards distribution to:
 * 1. Calculate rewards based on vote credits earned
 * 2. Update the stake account's credits_observed
 * 3. Apply commission
 */
uint64_t
sol_stake_calculate_rewards_with_credits(sol_stake_state_t* state,
                                          uint64_t new_vote_credits,
                                          uint64_t total_stake,
                                          uint64_t inflation_rewards,
                                          uint8_t vote_commission) {
    if (!state || state->state != SOL_STAKE_STATE_STAKE || total_stake == 0) {
        return 0;
    }

    uint64_t stake = state->delegation.stake;

    /* Calculate credits earned since last update */
    uint64_t credits_earned = 0;
    if (new_vote_credits > state->credits_observed) {
        credits_earned = new_vote_credits - state->credits_observed;
    }

    if (credits_earned == 0) {
        return 0;
    }

    /* Update credits observed */
    state->credits_observed = new_vote_credits;

    /*
     * Calculate points: stake * credits_earned
     *
     * Rewards are proportional to:
     * - Stake amount (more stake = more rewards)
     * - Credits earned (more votes = more rewards)
     */
    uint128 points = (uint128)stake * (uint128)credits_earned;

    /*
     * For simplicity, assume total_points = total_stake * avg_credits
     * In practice, this should come from the rewards calculator.
     * Here we approximate with credits_earned as avg.
     */
    uint128 total_points = (uint128)total_stake * (uint128)credits_earned;

    if (total_points == 0) {
        return 0;
    }

    /* Calculate gross rewards: (points / total_points) * inflation_rewards */
    uint128 gross_numerator = points * (uint128)inflation_rewards;
    uint64_t gross_rewards = (uint64_t)(gross_numerator / total_points);

    /* Apply commission */
    uint64_t commission_amount = 0;
    if (vote_commission > 0 && vote_commission <= 100) {
        commission_amount = (gross_rewards * vote_commission) / 100;
    }

    uint64_t net_rewards = gross_rewards - commission_amount;

    return net_rewards;
}
