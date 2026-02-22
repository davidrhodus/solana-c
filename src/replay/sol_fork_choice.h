/*
 * sol_fork_choice.h - Fork Choice Algorithm
 *
 * Implements the heaviest subtree fork choice rule used by Solana.
 * The fork with the most stake-weighted votes is selected as the best fork.
 */

#ifndef SOL_FORK_CHOICE_H
#define SOL_FORK_CHOICE_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "sol_bank_forks.h"

/*
 * Fork vote entry for tracking validator votes in fork choice
 */
typedef struct {
    sol_pubkey_t    validator;          /* Validator identity */
    sol_slot_t      last_voted_slot;    /* Most recent voted slot */
    sol_slot_t      root_slot;          /* Validator's root */
    uint64_t        stake;              /* Validator's stake weight */
} sol_fork_vote_t;

/*
 * Fork weight information
 */
typedef struct {
    sol_slot_t      slot;
    sol_hash_t      bank_hash;          /* Bank hash for this fork (may be zero) */
    uint64_t        stake_weight;       /* Direct stake voting for this slot */
    uint64_t        subtree_weight;     /* Total stake in subtree */
    uint32_t        vote_count;         /* Number of validators voting */
} sol_fork_weight_t;

/*
 * Fork choice configuration
 */
typedef struct {
    uint32_t    max_votes;              /* Maximum vote states to track */
    uint64_t    threshold_stake;        /* Minimum stake for supermajority */
} sol_fork_choice_config_t;

#define SOL_FORK_CHOICE_CONFIG_DEFAULT {    \
    .max_votes = 10000,                     \
    .threshold_stake = 0,                   \
}

/*
 * Fork choice handle (opaque)
 */
typedef struct sol_fork_choice sol_fork_choice_t;

/*
 * Create a new fork choice tracker
 *
 * @param bank_forks    Bank forks to track
 * @param config        Configuration (NULL for defaults)
 * @return              Fork choice handle or NULL on error
 */
sol_fork_choice_t* sol_fork_choice_new(
    sol_bank_forks_t*               bank_forks,
    const sol_fork_choice_config_t* config
);

/*
 * Destroy fork choice tracker
 */
void sol_fork_choice_destroy(sol_fork_choice_t* fc);

/*
 * Record a validator vote
 *
 * @param fc            Fork choice handle
 * @param validator     Validator pubkey
 * @param slot          Voted slot
 * @param stake         Validator's stake weight
 * @return              SOL_OK on success
 */
sol_err_t sol_fork_choice_record_vote(
    sol_fork_choice_t*      fc,
    const sol_pubkey_t*     validator,
    sol_slot_t              slot,
    uint64_t                stake
);

/*
 * Record a validator vote for a specific bank hash
 *
 * @param fc            Fork choice handle
 * @param validator     Validator pubkey (typically vote account)
 * @param slot          Voted slot
 * @param bank_hash     Bank hash being voted on (required)
 * @param stake         Validator's stake weight
 * @return              SOL_OK on success
 */
sol_err_t sol_fork_choice_record_vote_hash(
    sol_fork_choice_t*      fc,
    const sol_pubkey_t*     validator,
    sol_slot_t              slot,
    const sol_hash_t*       bank_hash,
    uint64_t                stake
);

/*
 * Get the best fork tip as a (slot, bank_hash) pair.
 *
 * This is required for duplicate-slot support where multiple banks can exist
 * at the same slot with different bank hashes.
 *
 * @return true on success.
 */
bool sol_fork_choice_best_bank(
    sol_fork_choice_t*  fc,
    sol_slot_t*         out_slot,
    sol_hash_t*         out_bank_hash
);

/*
 * Get the best fork (heaviest subtree)
 *
 * @param fc            Fork choice handle
 * @return              Best slot (heaviest fork tip)
 */
sol_slot_t sol_fork_choice_best_slot(sol_fork_choice_t* fc);

/*
 * Get the best fork starting from a given slot
 *
 * @param fc            Fork choice handle
 * @param start_slot    Starting slot
 * @return              Best slot in subtree
 */
sol_slot_t sol_fork_choice_best_slot_from(
    sol_fork_choice_t*  fc,
    sol_slot_t          start_slot
);

/*
 * Get direct stake weight for a specific (slot, bank_hash).
 */
uint64_t sol_fork_choice_stake_weight_hash(
    sol_fork_choice_t*      fc,
    sol_slot_t              slot,
    const sol_hash_t*       bank_hash
);

/*
 * Get subtree stake weight for a specific (slot, bank_hash).
 */
uint64_t sol_fork_choice_subtree_weight_hash(
    sol_fork_choice_t*      fc,
    sol_slot_t              slot,
    const sol_hash_t*       bank_hash
);

/*
 * Compute fork weights for all forks
 *
 * @param fc            Fork choice handle
 * @param out_weights   Output array for weights
 * @param max_forks     Maximum forks to return
 * @return              Number of forks written
 */
size_t sol_fork_choice_compute_weights(
    sol_fork_choice_t*  fc,
    sol_fork_weight_t*  out_weights,
    size_t              max_forks
);

/*
 * Get stake weight for a slot
 */
uint64_t sol_fork_choice_stake_weight(
    sol_fork_choice_t*  fc,
    sol_slot_t          slot
);

/*
 * Get subtree stake weight for a slot
 */
uint64_t sol_fork_choice_subtree_weight(
    sol_fork_choice_t*  fc,
    sol_slot_t          slot
);

/*
 * Get the most-staked voted bank hash at a given slot.
 *
 * This inspects observed (slot, bank_hash) votes and returns the hash with the
 * highest direct stake weight at `slot`. If multiple hashes tie on stake, the
 * hash with the highest vote count wins; if still tied, the lexicographically
 * larger hash wins (stable tie-break).
 *
 * Returns false when there are no votes for `slot`.
 */
bool sol_fork_choice_best_voted_hash(
    sol_fork_choice_t*  fc,
    sol_slot_t          slot,
    sol_hash_t*         out_bank_hash,
    uint64_t*           out_stake_weight,
    uint32_t*           out_vote_count,
    uint64_t*           out_total_stake_weight,
    uint32_t*           out_total_vote_count
);

/*
 * Set/get configured supermajority threshold stake.
 *
 * Threshold is compared against subtree weights when checking for supermajority.
 */
void sol_fork_choice_set_threshold_stake(sol_fork_choice_t* fc, uint64_t threshold_stake);
uint64_t sol_fork_choice_threshold_stake(const sol_fork_choice_t* fc);

/*
 * Check if slot has supermajority stake
 *
 * @param fc            Fork choice handle
 * @param slot          Slot to check
 * @param threshold     Stake threshold (e.g., 2/3 of total stake)
 * @return              true if supermajority
 */
bool sol_fork_choice_has_supermajority(
    sol_fork_choice_t*  fc,
    sol_slot_t          slot,
    uint64_t            threshold
);

/*
 * Get the latest vote for a validator
 */
sol_slot_t sol_fork_choice_latest_vote(
    sol_fork_choice_t*      fc,
    const sol_pubkey_t*     validator
);

/*
 * Update after root change
 *
 * Prunes votes for slots before the new root.
 */
sol_err_t sol_fork_choice_set_root(
    sol_fork_choice_t*  fc,
    sol_slot_t          root_slot
);

/*
 * Get total stake tracked
 */
uint64_t sol_fork_choice_total_stake(const sol_fork_choice_t* fc);

/*
 * Get number of validators voting
 */
size_t sol_fork_choice_voter_count(const sol_fork_choice_t* fc);

#endif /* SOL_FORK_CHOICE_H */
