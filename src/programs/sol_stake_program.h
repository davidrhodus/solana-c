/*
 * sol_stake_program.h - Stake Program Implementation
 *
 * The Stake Program manages stake accounts for:
 * - Delegating stake to validators
 * - Earning staking rewards
 * - Participating in leader schedule selection
 */

#ifndef SOL_STAKE_PROGRAM_H
#define SOL_STAKE_PROGRAM_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../util/sol_map.h"
#include "../txn/sol_pubkey.h"
#include "../runtime/sol_bank.h"
#include "../runtime/sol_sysvar.h"
#include "sol_system_program.h"

/*
 * Stake Program ID
 * Stake11111111111111111111111111111111111111
 */
extern const sol_pubkey_t SOL_STAKE_PROGRAM_ID;

/*
 * Stake Config Program ID
 */
extern const sol_pubkey_t SOL_STAKE_CONFIG_ID;

/*
 * Stake instruction types
 */
typedef enum {
    SOL_STAKE_INSTR_INITIALIZE = 0,
    SOL_STAKE_INSTR_AUTHORIZE = 1,
    SOL_STAKE_INSTR_DELEGATE = 2,
    SOL_STAKE_INSTR_SPLIT = 3,
    SOL_STAKE_INSTR_WITHDRAW = 4,
    SOL_STAKE_INSTR_DEACTIVATE = 5,
    SOL_STAKE_INSTR_SET_LOCKUP = 6,
    SOL_STAKE_INSTR_MERGE = 7,
    SOL_STAKE_INSTR_AUTHORIZE_WITH_SEED = 8,
    SOL_STAKE_INSTR_INITIALIZE_CHECKED = 9,
    SOL_STAKE_INSTR_AUTHORIZE_CHECKED = 10,
    SOL_STAKE_INSTR_AUTHORIZE_CHECKED_WITH_SEED = 11,
    SOL_STAKE_INSTR_SET_LOCKUP_CHECKED = 12,
    SOL_STAKE_INSTR_GET_MINIMUM_DELEGATION = 13,
    SOL_STAKE_INSTR_DEACTIVATE_DELINQUENT = 14,
    SOL_STAKE_INSTR_REDELEGATE = 15,
} sol_stake_instr_type_t;

/*
 * Stake authorization type
 */
typedef enum {
    SOL_STAKE_AUTHORIZE_STAKER = 0,
    SOL_STAKE_AUTHORIZE_WITHDRAWER = 1,
} sol_stake_authorize_t;

/*
 * Stake state type
 */
typedef enum {
    SOL_STAKE_STATE_UNINITIALIZED = 0,
    SOL_STAKE_STATE_INITIALIZED = 1,
    SOL_STAKE_STATE_STAKE = 2,
    SOL_STAKE_STATE_REWARDS_POOL = 3,
} sol_stake_state_type_t;

/*
 * Lockup configuration
 */
typedef struct {
    int64_t         unix_timestamp;     /* Lockup until timestamp (0 = no lockup) */
    uint64_t        epoch;              /* Lockup until epoch (0 = no lockup) */
    sol_pubkey_t    custodian;          /* Authority that can change lockup */
} sol_lockup_t;

/*
 * Stake authorized accounts
 */
typedef struct {
    sol_pubkey_t    staker;             /* Can delegate/deactivate */
    sol_pubkey_t    withdrawer;         /* Can withdraw */
} sol_stake_authorized_t;

/*
 * Stake metadata
 */
typedef struct {
    uint64_t        rent_exempt_reserve; /* Minimum balance for rent exemption */
    sol_stake_authorized_t authorized;
    sol_lockup_t    lockup;
} sol_stake_meta_t;

/*
 * Delegation info
 */
typedef struct {
    sol_pubkey_t    voter_pubkey;       /* Vote account delegated to */
    uint64_t        stake;              /* Delegated stake amount */
    uint64_t        activation_epoch;   /* Epoch when delegation activated */
    uint64_t        deactivation_epoch; /* Epoch when deactivation requested */
    double          warmup_cooldown_rate; /* Rate of warmup/cooldown */
} sol_delegation_t;

/*
 * Stake state (stored in stake account data)
 */
typedef struct {
    sol_stake_state_type_t  state;
    sol_stake_meta_t        meta;
    sol_delegation_t        delegation;
    uint64_t                credits_observed; /* Vote credits at last update */
    uint8_t                 stake_flags;      /* StakeFlags (u8) */
} sol_stake_state_t;

/*
 * Stake account size
 */
#define SOL_STAKE_STATE_SIZE 200

/*
 * Minimum delegation (lamports)
 */
#define SOL_MIN_STAKE_DELEGATION 1  /* 1 lamport (feature stake_raise_minimum_delegation_to_1_sol NOT active on mainnet) */

/*
 * Process a stake program instruction
 */
sol_err_t sol_stake_program_execute(sol_invoke_context_t* ctx);

/*
 * Initialize stake state
 */
void sol_stake_state_init(
    sol_stake_state_t*              state,
    const sol_stake_authorized_t*   authorized,
    const sol_lockup_t*             lockup,
    uint64_t                        rent_exempt_reserve
);

/*
 * Serialize stake state to account data
 */
sol_err_t sol_stake_state_serialize(
    const sol_stake_state_t*    state,
    uint8_t*                    data,
    size_t                      data_len,
    size_t*                     written
);

/*
 * Deserialize stake state from account data
 */
sol_err_t sol_stake_state_deserialize(
    sol_stake_state_t*  state,
    const uint8_t*      data,
    size_t              data_len
);

/*
 * Delegate stake to a validator
 */
sol_err_t sol_stake_delegate(
    sol_stake_state_t*      state,
    const sol_pubkey_t*     vote_pubkey,
    uint64_t                stake_amount,
    uint64_t                current_epoch
);

/*
 * Deactivate stake
 */
sol_err_t sol_stake_deactivate(
    sol_stake_state_t*  state,
    uint64_t            current_epoch
);

/*
 * Calculate effective stake at an epoch
 *
 * Takes into account warmup/cooldown periods.
 */
uint64_t sol_stake_effective_stake(
    const sol_stake_state_t*    state,
    uint64_t                    target_epoch
);

/*
 * Check if stake is active
 */
bool sol_stake_is_active(
    const sol_stake_state_t*    state,
    uint64_t                    current_epoch
);

/*
 * Check if stake is fully activated
 */
bool sol_stake_is_fully_activated(
    const sol_stake_state_t*    state,
    uint64_t                    current_epoch
);

/*
 * Check if lockup is in effect
 */
bool sol_stake_is_locked(
    const sol_stake_state_t*    state,
    uint64_t                    current_epoch,
    int64_t                     unix_timestamp
);

/*
 * Calculate staking rewards
 */
uint64_t sol_stake_calculate_rewards(
    const sol_stake_state_t*    state,
    uint64_t                    vote_credits,
    uint64_t                    total_stake,
    uint64_t                    inflation_rewards
);

/*
 * Create a stake account
 */
sol_err_t sol_stake_create_account(
    sol_bank_t*                     bank,
    const sol_pubkey_t*             stake_pubkey,
    const sol_stake_authorized_t*   authorized,
    const sol_lockup_t*             lockup,
    uint64_t                        lamports
);

/*
 * Get stake state from account
 */
sol_err_t sol_stake_get_state(
    sol_bank_t*             bank,
    const sol_pubkey_t*     stake_pubkey,
    sol_stake_state_t*      state
);

/*
 * Get total active stake delegated to a vote account
 */
uint64_t sol_stake_get_delegated_stake(
    sol_bank_t*             bank,
    const sol_pubkey_t*     vote_pubkey,
    uint64_t                current_epoch
);

/*
 * Build a map of vote-account pubkey -> effective delegated stake for an epoch.
 *
 * This aggregates all stake accounts in a single pass and is appropriate for
 * leader-schedule computation and vote weighting.
 *
 * Returns a pubkey map holding uint64_t stake values, or NULL on error.
 * Caller must destroy the returned map with sol_pubkey_map_destroy().
 */
sol_pubkey_map_t* sol_stake_build_vote_stake_map(
    sol_bank_t* bank,
    uint64_t current_epoch,
    uint64_t* out_total_stake
);

/*
 * Stake activation status
 *
 * Used to track warmup/cooldown progress with stake history.
 */
typedef struct {
    uint64_t    effective;      /* Currently effective stake */
    uint64_t    activating;     /* Stake still warming up */
    uint64_t    deactivating;   /* Stake cooling down */
} sol_stake_activation_t;

/*
 * Calculate stake activation status using stake history
 *
 * This is the proper way to calculate effective stake, taking into
 * account the network-wide stake activation/deactivation rates from
 * stake history sysvar.
 *
 * @param state         Stake account state
 * @param target_epoch  Epoch to calculate for
 * @param history       Stake history sysvar (may be NULL for simplified calc)
 * @param out_status    Output activation status
 * @return              SOL_OK on success
 */
sol_err_t sol_stake_get_activation_status(
    const sol_stake_state_t*        state,
    uint64_t                        target_epoch,
    const sol_stake_history_t*      history,
    sol_stake_activation_t*         out_status
);

/*
 * Calculate effective stake with stake history
 *
 * Enhanced version of sol_stake_effective_stake() that properly uses
 * stake history for accurate warmup/cooldown calculation.
 */
uint64_t sol_stake_effective_stake_with_history(
    const sol_stake_state_t*        state,
    uint64_t                        target_epoch,
    const sol_stake_history_t*      history
);

/*
 * Update stake account credits and calculate pending rewards
 *
 * Called during rewards distribution to update the stake account's
 * credits_observed field and calculate the rewards earned.
 *
 * @param state             Stake state (modified in place)
 * @param new_vote_credits  Current vote credits from vote account
 * @param total_stake       Total stake in the network
 * @param inflation_rewards Total inflation rewards for the epoch
 * @param vote_commission   Vote account commission percentage (0-100)
 * @return                  Rewards earned (after commission)
 */
uint64_t sol_stake_calculate_rewards_with_credits(
    sol_stake_state_t*      state,
    uint64_t                new_vote_credits,
    uint64_t                total_stake,
    uint64_t                inflation_rewards,
    uint8_t                 vote_commission
);

#endif /* SOL_STAKE_PROGRAM_H */
