/*
 * sol_rewards.h - Stake Rewards Distribution
 *
 * At each epoch boundary, staking rewards are calculated and distributed
 * to validators and their delegators based on:
 *   - Inflation schedule
 *   - Stake weight
 *   - Vote credits earned
 *   - Commission rate
 */

#ifndef SOL_REWARDS_H
#define SOL_REWARDS_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "sol_accounts_db.h"

/*
 * Inflation parameters
 * These control how new lamports are minted.
 */
typedef struct {
    double      initial;            /* Initial inflation rate (e.g., 8%) */
    double      terminal;           /* Terminal inflation rate (e.g., 1.5%) */
    double      taper;              /* Rate at which inflation decreases */
    double      foundation;         /* Portion to foundation (e.g., 5%) */
    double      foundation_term;    /* Years for foundation allocation */
} sol_inflation_t;

#define SOL_INFLATION_DEFAULT {             \
    .initial = 0.08,                        \
    .terminal = 0.015,                      \
    .taper = 0.15,                          \
    .foundation = 0.05,                     \
    .foundation_term = 7.0,                 \
}

/*
 * Rewards calculation configuration
 */
typedef struct {
    sol_inflation_t inflation;
    uint64_t        slots_per_year;     /* For rate calculations */
    uint64_t        slots_per_epoch;    /* Slots in one epoch */
    bool            enable_partitioned; /* Enable partitioned rewards */
} sol_rewards_config_t;

#define SOL_REWARDS_CONFIG_DEFAULT {                    \
    .inflation = SOL_INFLATION_DEFAULT,                 \
    .slots_per_year = 78892314,                         \
    .slots_per_epoch = 432000,                          \
    .enable_partitioned = false,                        \
}

/*
 * Vote rewards for a single validator
 */
typedef struct {
    sol_pubkey_t    vote_pubkey;        /* Validator's vote account */
    sol_pubkey_t    node_pubkey;        /* Validator's identity */
    uint64_t        commission;         /* Commission rate (0-100) */
    uint64_t        vote_credits;       /* Credits earned in epoch */
    uint64_t        prev_credits;       /* Credits at epoch start */
    uint64_t        rewards;            /* Total rewards earned */
    uint64_t        commission_amount;  /* Commission taken */
} sol_vote_rewards_t;

/*
 * Stake rewards for a single delegation
 */
typedef struct {
    sol_pubkey_t    stake_pubkey;       /* Stake account */
    sol_pubkey_t    vote_pubkey;        /* Vote account delegated to */
    uint64_t        stake;              /* Delegated stake */
    uint64_t        rewards;            /* Rewards earned */
    uint64_t        new_credits;        /* Credits processed */
} sol_stake_rewards_t;

/*
 * Epoch rewards summary
 */
typedef struct {
    sol_epoch_t     epoch;              /* Epoch rewards were calculated for */
    uint64_t        total_rewards;      /* Total rewards distributed */
    uint64_t        validator_rewards;  /* Rewards to validators */
    uint64_t        staker_rewards;     /* Rewards to stakers */
    uint64_t        foundation_rewards; /* Rewards to foundation */
    size_t          num_validators;     /* Number of validators rewarded */
    size_t          num_stakers;        /* Number of stake accounts rewarded */
    uint64_t        total_stake;        /* Total active stake */
    uint64_t        compute_time_ns;    /* Time to calculate */
} sol_epoch_rewards_t;

/*
 * Calculate inflation rate for a given slot
 */
double sol_inflation_rate(
    const sol_inflation_t* inflation,
    uint64_t slot,
    uint64_t slots_per_year
);

/*
 * Calculate validator portion (vs foundation)
 */
double sol_inflation_validator_rate(
    const sol_inflation_t* inflation,
    uint64_t year
);

/*
 * Calculate total rewards for an epoch
 */
uint64_t sol_epoch_total_rewards(
    const sol_rewards_config_t* config,
    uint64_t slot,
    uint64_t capitalization
);

/*
 * Rewards calculator context
 */
typedef struct sol_rewards_calc sol_rewards_calc_t;

/*
 * Create a new rewards calculator
 */
sol_rewards_calc_t* sol_rewards_calc_new(
    const sol_rewards_config_t* config
);

/*
 * Destroy rewards calculator
 */
void sol_rewards_calc_destroy(sol_rewards_calc_t* calc);

/*
 * Add a vote account to the calculation
 */
sol_err_t sol_rewards_calc_add_vote(
    sol_rewards_calc_t* calc,
    const sol_pubkey_t* vote_pubkey,
    const sol_pubkey_t* node_pubkey,
    uint64_t commission,
    uint64_t vote_credits,
    uint64_t prev_credits
);

/*
 * Add a stake account to the calculation
 */
sol_err_t sol_rewards_calc_add_stake(
    sol_rewards_calc_t* calc,
    const sol_pubkey_t* stake_pubkey,
    const sol_pubkey_t* vote_pubkey,
    uint64_t stake
);

/*
 * Calculate rewards for all added accounts
 */
sol_err_t sol_rewards_calc_compute(
    sol_rewards_calc_t* calc,
    uint64_t slot,
    uint64_t capitalization,
    sol_epoch_rewards_t* out_summary
);

/*
 * Get vote rewards (call after compute)
 */
sol_err_t sol_rewards_calc_get_vote_rewards(
    const sol_rewards_calc_t* calc,
    sol_vote_rewards_t* out_rewards,
    size_t* out_count,
    size_t max_count
);

/*
 * Get stake rewards (call after compute)
 */
sol_err_t sol_rewards_calc_get_stake_rewards(
    const sol_rewards_calc_t* calc,
    sol_stake_rewards_t* out_rewards,
    size_t* out_count,
    size_t max_count
);

/*
 * Apply computed rewards to accounts database
 * This credits the lamports to the stake and vote accounts.
 */
sol_err_t sol_rewards_apply(
    sol_rewards_calc_t* calc,
    sol_accounts_db_t* db
);

/*
 * Point value calculation
 * Points = stake * credits
 * Reward = (points / total_points) * total_rewards
 */
typedef struct {
    uint64_t    total_points;       /* Sum of all stake * credits */
    uint64_t    total_stake;        /* Sum of all stake */
    uint64_t    total_credits;      /* Sum of all vote credits */
} sol_rewards_points_t;

/*
 * Calculate point values for an epoch
 */
sol_err_t sol_rewards_calc_points(
    const sol_rewards_calc_t* calc,
    sol_rewards_points_t* out_points
);

#endif /* SOL_REWARDS_H */
