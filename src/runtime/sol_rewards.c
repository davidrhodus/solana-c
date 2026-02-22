/*
 * sol_rewards.c - Stake Rewards Distribution Implementation
 */

#include "sol_rewards.h"
#include "sol_account.h"
#include "../util/sol_alloc.h"
#include <string.h>
#include <math.h>
#include <time.h>

/*
 * Get time in nanoseconds
 */
static uint64_t
get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/*
 * Internal vote account info
 */
typedef struct {
    sol_pubkey_t    vote_pubkey;
    sol_pubkey_t    node_pubkey;
    uint64_t        commission;
    uint64_t        vote_credits;
    uint64_t        prev_credits;
    uint64_t        rewards;
    uint64_t        commission_amount;
} vote_info_t;

/*
 * Internal stake account info
 */
typedef struct {
    sol_pubkey_t    stake_pubkey;
    sol_pubkey_t    vote_pubkey;
    uint64_t        stake;
    uint64_t        rewards;
    uint64_t        credits_observed;
} stake_info_t;

/*
 * Rewards calculator structure
 */
struct sol_rewards_calc {
    sol_rewards_config_t    config;
    vote_info_t*            votes;
    size_t                  num_votes;
    size_t                  cap_votes;
    stake_info_t*           stakes;
    size_t                  num_stakes;
    size_t                  cap_stakes;
    bool                    computed;
    sol_epoch_rewards_t     summary;
};

/*
 * Inflation rate calculation
 *
 * rate(t) = initial * (1 - taper)^year + terminal
 * Decays from initial rate to terminal rate over time.
 */
double
sol_inflation_rate(const sol_inflation_t* inflation,
                   uint64_t slot,
                   uint64_t slots_per_year) {
    if (!inflation || slots_per_year == 0) {
        return 0.0;
    }

    double year = (double)slot / (double)slots_per_year;
    double taper_factor = pow(1.0 - inflation->taper, year);
    double rate = inflation->initial * taper_factor;

    /* Clamp to terminal rate */
    if (rate < inflation->terminal) {
        rate = inflation->terminal;
    }

    return rate;
}

/*
 * Validator portion of inflation
 *
 * In early years, some goes to foundation.
 * After foundation_term years, 100% to validators.
 */
double
sol_inflation_validator_rate(const sol_inflation_t* inflation,
                             uint64_t year) {
    if (!inflation) {
        return 1.0;
    }

    if ((double)year >= inflation->foundation_term) {
        return 1.0;
    }

    return 1.0 - inflation->foundation;
}

/*
 * Calculate total rewards for an epoch
 */
uint64_t
sol_epoch_total_rewards(const sol_rewards_config_t* config,
                        uint64_t slot,
                        uint64_t capitalization) {
    if (!config || capitalization == 0) {
        return 0;
    }

    /* Get inflation rate */
    double rate = sol_inflation_rate(&config->inflation, slot, config->slots_per_year);

    /* Get validator portion */
    uint64_t year = slot / config->slots_per_year;
    double validator_rate = sol_inflation_validator_rate(&config->inflation, year);

    /* Calculate rewards for one epoch
     * epochs_per_year = slots_per_year / slots_per_epoch
     */
    uint64_t slots_per_epoch = config->slots_per_epoch > 0 ? config->slots_per_epoch : 432000;
    double epochs_per_year = (double)config->slots_per_year / (double)slots_per_epoch;

    /* Rewards = capitalization * rate * validator_rate / epochs_per_year */
    double rewards = (double)capitalization * rate * validator_rate / epochs_per_year;

    return (uint64_t)rewards;
}

/*
 * Create rewards calculator
 */
sol_rewards_calc_t*
sol_rewards_calc_new(const sol_rewards_config_t* config) {
    sol_rewards_calc_t* calc = sol_alloc(sizeof(sol_rewards_calc_t));
    if (!calc) return NULL;

    memset(calc, 0, sizeof(sol_rewards_calc_t));

    if (config) {
        calc->config = *config;
    } else {
        calc->config = (sol_rewards_config_t)SOL_REWARDS_CONFIG_DEFAULT;
    }

    /* Initial capacity */
    calc->cap_votes = 64;
    calc->cap_stakes = 256;

    calc->votes = sol_alloc(calc->cap_votes * sizeof(vote_info_t));
    calc->stakes = sol_alloc(calc->cap_stakes * sizeof(stake_info_t));

    if (!calc->votes || !calc->stakes) {
        sol_free(calc->votes);
        sol_free(calc->stakes);
        sol_free(calc);
        return NULL;
    }

    return calc;
}

/*
 * Destroy calculator
 */
void
sol_rewards_calc_destroy(sol_rewards_calc_t* calc) {
    if (!calc) return;

    sol_free(calc->votes);
    sol_free(calc->stakes);
    sol_free(calc);
}

/*
 * Add vote account
 */
sol_err_t
sol_rewards_calc_add_vote(sol_rewards_calc_t* calc,
                          const sol_pubkey_t* vote_pubkey,
                          const sol_pubkey_t* node_pubkey,
                          uint64_t commission,
                          uint64_t vote_credits,
                          uint64_t prev_credits) {
    if (!calc || !vote_pubkey) {
        return SOL_ERR_INVAL;
    }

    /* Grow array if needed */
    if (calc->num_votes >= calc->cap_votes) {
        size_t new_cap = calc->cap_votes * 2;
        vote_info_t* new_votes = sol_realloc(calc->votes, new_cap * sizeof(vote_info_t));
        if (!new_votes) {
            return SOL_ERR_NOMEM;
        }
        calc->votes = new_votes;
        calc->cap_votes = new_cap;
    }

    vote_info_t* vote = &calc->votes[calc->num_votes++];
    vote->vote_pubkey = *vote_pubkey;
    if (node_pubkey) {
        vote->node_pubkey = *node_pubkey;
    } else {
        memset(&vote->node_pubkey, 0, sizeof(sol_pubkey_t));
    }
    vote->commission = commission > 100 ? 100 : commission;
    vote->vote_credits = vote_credits;
    vote->prev_credits = prev_credits;
    vote->rewards = 0;
    vote->commission_amount = 0;

    calc->computed = false;

    return SOL_OK;
}

/*
 * Add stake account
 */
sol_err_t
sol_rewards_calc_add_stake(sol_rewards_calc_t* calc,
                           const sol_pubkey_t* stake_pubkey,
                           const sol_pubkey_t* vote_pubkey,
                           uint64_t stake) {
    if (!calc || !stake_pubkey || !vote_pubkey) {
        return SOL_ERR_INVAL;
    }

    if (stake == 0) {
        return SOL_OK;  /* Skip zero-stake accounts */
    }

    /* Grow array if needed */
    if (calc->num_stakes >= calc->cap_stakes) {
        size_t new_cap = calc->cap_stakes * 2;
        stake_info_t* new_stakes = sol_realloc(calc->stakes, new_cap * sizeof(stake_info_t));
        if (!new_stakes) {
            return SOL_ERR_NOMEM;
        }
        calc->stakes = new_stakes;
        calc->cap_stakes = new_cap;
    }

    stake_info_t* st = &calc->stakes[calc->num_stakes++];
    st->stake_pubkey = *stake_pubkey;
    st->vote_pubkey = *vote_pubkey;
    st->stake = stake;
    st->rewards = 0;
    st->credits_observed = 0;

    calc->computed = false;

    return SOL_OK;
}

/*
 * Compute rewards
 */
sol_err_t
sol_rewards_calc_compute(sol_rewards_calc_t* calc,
                         uint64_t slot,
                         uint64_t capitalization,
                         sol_epoch_rewards_t* out_summary) {
    if (!calc) {
        return SOL_ERR_INVAL;
    }

    uint64_t start_time = get_time_ns();

    /* Calculate total rewards for this epoch */
    uint64_t total_rewards = sol_epoch_total_rewards(&calc->config, slot, capitalization);

    /* Calculate total points
     * Points = sum(stake * (vote_credits - prev_credits))
     */
    uint64_t total_points = 0;
    uint64_t total_stake = 0;

    for (size_t i = 0; i < calc->num_stakes; i++) {
        stake_info_t* st = &calc->stakes[i];

        /* Find the vote account for this stake */
        vote_info_t* vote = NULL;
        for (size_t j = 0; j < calc->num_votes; j++) {
            if (sol_pubkey_eq(&calc->votes[j].vote_pubkey, &st->vote_pubkey)) {
                vote = &calc->votes[j];
                break;
            }
        }

        if (!vote) {
            continue;  /* No matching vote account */
        }

        uint64_t credits_earned = 0;
        if (vote->vote_credits > vote->prev_credits) {
            credits_earned = vote->vote_credits - vote->prev_credits;
        }

        st->credits_observed = credits_earned;
        uint64_t points = st->stake * credits_earned;
        total_points += points;
        total_stake += st->stake;
    }

    /* Distribute rewards proportionally */
    uint64_t validator_rewards = 0;
    uint64_t staker_rewards = 0;

    if (total_points > 0) {
        for (size_t i = 0; i < calc->num_stakes; i++) {
            stake_info_t* st = &calc->stakes[i];

            if (st->credits_observed == 0) {
                continue;
            }

            uint64_t points = st->stake * st->credits_observed;

            /* stake_rewards = (points / total_points) * total_rewards */
            /* Use 128-bit math to avoid overflow */
            uint128 numerator = (uint128)points * (uint128)total_rewards;
            uint64_t gross_rewards = (uint64_t)(numerator / total_points);

            /* Find vote account for commission */
            vote_info_t* vote = NULL;
            for (size_t j = 0; j < calc->num_votes; j++) {
                if (sol_pubkey_eq(&calc->votes[j].vote_pubkey, &st->vote_pubkey)) {
                    vote = &calc->votes[j];
                    break;
                }
            }

            uint64_t commission_amount = 0;
            if (vote) {
                commission_amount = (gross_rewards * vote->commission) / 100;
                vote->rewards += gross_rewards;
                vote->commission_amount += commission_amount;
            }

            st->rewards = gross_rewards - commission_amount;
            staker_rewards += st->rewards;
            validator_rewards += commission_amount;
        }
    }

    /* Foundation rewards (in early years) */
    uint64_t year = slot / calc->config.slots_per_year;
    double validator_rate = sol_inflation_validator_rate(&calc->config.inflation, year);
    uint64_t foundation_rewards = 0;
    if (validator_rate < 1.0) {
        double foundation_rate = 1.0 - validator_rate;
        foundation_rewards = (uint64_t)((double)total_rewards * foundation_rate / validator_rate);
    }

    uint64_t end_time = get_time_ns();

    /* Store summary */
    uint64_t spe = calc->config.slots_per_epoch > 0 ? calc->config.slots_per_epoch : 432000;
    calc->summary.epoch = slot / spe;
    calc->summary.total_rewards = staker_rewards + validator_rewards;
    calc->summary.validator_rewards = validator_rewards;
    calc->summary.staker_rewards = staker_rewards;
    calc->summary.foundation_rewards = foundation_rewards;
    calc->summary.num_validators = calc->num_votes;
    calc->summary.num_stakers = calc->num_stakes;
    calc->summary.total_stake = total_stake;
    calc->summary.compute_time_ns = end_time - start_time;

    calc->computed = true;

    if (out_summary) {
        *out_summary = calc->summary;
    }

    return SOL_OK;
}

/*
 * Get vote rewards
 */
sol_err_t
sol_rewards_calc_get_vote_rewards(const sol_rewards_calc_t* calc,
                                   sol_vote_rewards_t* out_rewards,
                                   size_t* out_count,
                                   size_t max_count) {
    if (!calc || !calc->computed) {
        return SOL_ERR_INVAL;
    }

    size_t count = calc->num_votes;
    if (count > max_count) {
        count = max_count;
    }

    if (out_rewards) {
        for (size_t i = 0; i < count; i++) {
            const vote_info_t* v = &calc->votes[i];
            out_rewards[i].vote_pubkey = v->vote_pubkey;
            out_rewards[i].node_pubkey = v->node_pubkey;
            out_rewards[i].commission = v->commission;
            out_rewards[i].vote_credits = v->vote_credits;
            out_rewards[i].prev_credits = v->prev_credits;
            out_rewards[i].rewards = v->rewards;
            out_rewards[i].commission_amount = v->commission_amount;
        }
    }

    if (out_count) {
        *out_count = count;
    }

    return SOL_OK;
}

/*
 * Get stake rewards
 */
sol_err_t
sol_rewards_calc_get_stake_rewards(const sol_rewards_calc_t* calc,
                                    sol_stake_rewards_t* out_rewards,
                                    size_t* out_count,
                                    size_t max_count) {
    if (!calc || !calc->computed) {
        return SOL_ERR_INVAL;
    }

    size_t count = calc->num_stakes;
    if (count > max_count) {
        count = max_count;
    }

    if (out_rewards) {
        for (size_t i = 0; i < count; i++) {
            const stake_info_t* s = &calc->stakes[i];
            out_rewards[i].stake_pubkey = s->stake_pubkey;
            out_rewards[i].vote_pubkey = s->vote_pubkey;
            out_rewards[i].stake = s->stake;
            out_rewards[i].rewards = s->rewards;
            out_rewards[i].new_credits = s->credits_observed;
        }
    }

    if (out_count) {
        *out_count = count;
    }

    return SOL_OK;
}

/*
 * Apply rewards to accounts
 */
sol_err_t
sol_rewards_apply(sol_rewards_calc_t* calc,
                  sol_accounts_db_t* db) {
    if (!calc || !db || !calc->computed) {
        return SOL_ERR_INVAL;
    }

    /* Apply stake rewards */
    for (size_t i = 0; i < calc->num_stakes; i++) {
        const stake_info_t* st = &calc->stakes[i];

        if (st->rewards == 0) {
            continue;
        }

        /* Load account, add rewards, store back */
        sol_account_t* account = sol_accounts_db_load(db, &st->stake_pubkey);
        if (!account) {
            continue;  /* Account not found */
        }

        account->meta.lamports += st->rewards;
        sol_accounts_db_store(db, &st->stake_pubkey, account);

        sol_account_destroy(account);
    }

    /* Apply validator commission to vote accounts */
    for (size_t i = 0; i < calc->num_votes; i++) {
        const vote_info_t* v = &calc->votes[i];

        if (v->commission_amount == 0) {
            continue;
        }

        sol_account_t* account = sol_accounts_db_load(db, &v->vote_pubkey);
        if (!account) {
            continue;  /* Account not found */
        }

        account->meta.lamports += v->commission_amount;
        sol_accounts_db_store(db, &v->vote_pubkey, account);

        sol_account_destroy(account);
    }

    return SOL_OK;
}

/*
 * Calculate points
 */
sol_err_t
sol_rewards_calc_points(const sol_rewards_calc_t* calc,
                        sol_rewards_points_t* out_points) {
    if (!calc || !out_points) {
        return SOL_ERR_INVAL;
    }

    uint64_t total_points = 0;
    uint64_t total_stake = 0;
    uint64_t total_credits = 0;

    for (size_t i = 0; i < calc->num_stakes; i++) {
        const stake_info_t* st = &calc->stakes[i];

        /* Find vote account */
        for (size_t j = 0; j < calc->num_votes; j++) {
            if (sol_pubkey_eq(&calc->votes[j].vote_pubkey, &st->vote_pubkey)) {
                uint64_t credits = 0;
                if (calc->votes[j].vote_credits > calc->votes[j].prev_credits) {
                    credits = calc->votes[j].vote_credits - calc->votes[j].prev_credits;
                }
                total_points += st->stake * credits;
                total_stake += st->stake;
                total_credits += credits;
                break;
            }
        }
    }

    out_points->total_points = total_points;
    out_points->total_stake = total_stake;
    out_points->total_credits = total_credits;

    return SOL_OK;
}
