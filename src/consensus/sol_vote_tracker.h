/*
 * sol_vote_tracker.h - Vote Tracking for Consensus
 *
 * Tracks votes from all validators for fork choice and consensus.
 * Collects votes received via gossip and replay.
 */

#ifndef SOL_VOTE_TRACKER_H
#define SOL_VOTE_TRACKER_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../txn/sol_pubkey.h"
#include "../programs/sol_vote_program.h"
#include <stdbool.h>
#include <pthread.h>

/*
 * Maximum number of validators to track
 */
#define SOL_MAX_TRACKED_VALIDATORS 10000

/*
 * Maximum slots to track votes for
 */
#define SOL_MAX_TRACKED_SLOTS 1024

/*
 * Vote record for a single validator
 */
typedef struct {
    sol_pubkey_t    vote_pubkey;        /* Vote account pubkey */
    sol_pubkey_t    node_pubkey;        /* Validator identity */
    sol_slot_t      last_voted_slot;    /* Most recent voted slot */
    sol_slot_t      root_slot;          /* Most recent root */
    uint64_t        stake;              /* Validator's stake */
    uint64_t        last_update;        /* Wallclock of last update */
    bool            active;             /* Is validator active */
} sol_vote_record_t;

/*
 * Vote aggregate for a slot
 */
typedef struct {
    sol_slot_t      slot;
    uint64_t        total_stake;        /* Total stake that voted for slot */
    uint64_t        validator_count;    /* Number of validators */
    bool            is_confirmed;       /* 2/3 supermajority */
    bool            is_finalized;       /* Root for all validators */
} sol_slot_votes_t;

/*
 * Vote tracker configuration
 */
typedef struct {
    size_t      max_validators;
    size_t      max_slots;
    bool        enable_pruning;     /* Prune old vote data */
} sol_vote_tracker_config_t;

#define SOL_VOTE_TRACKER_CONFIG_DEFAULT {       \
    .max_validators = SOL_MAX_TRACKED_VALIDATORS, \
    .max_slots = SOL_MAX_TRACKED_SLOTS,         \
    .enable_pruning = true,                     \
}

/*
 * Vote tracker stats
 */
typedef struct {
    uint64_t    votes_received;
    uint64_t    votes_processed;
    uint64_t    validators_tracked;
    uint64_t    slots_tracked;
    uint64_t    slots_confirmed;
    uint64_t    slots_finalized;
} sol_vote_tracker_stats_t;

/*
 * Vote tracker handle (opaque)
 */
typedef struct sol_vote_tracker sol_vote_tracker_t;

/*
 * Create vote tracker
 */
sol_vote_tracker_t* sol_vote_tracker_new(
    const sol_vote_tracker_config_t* config
);

/*
 * Destroy vote tracker
 */
void sol_vote_tracker_destroy(sol_vote_tracker_t* tracker);

/*
 * Record a vote from a validator
 *
 * @param tracker       Vote tracker
 * @param vote_pubkey   Vote account pubkey
 * @param node_pubkey   Validator identity
 * @param slot          Slot voted for
 * @param root_slot     Validator's root slot
 * @param stake         Validator's stake
 * @return              SOL_OK on success
 */
sol_err_t sol_vote_tracker_record_vote(
    sol_vote_tracker_t*     tracker,
    const sol_pubkey_t*     vote_pubkey,
    const sol_pubkey_t*     node_pubkey,
    sol_slot_t              slot,
    sol_slot_t              root_slot,
    uint64_t                stake
);

/*
 * Record multiple votes from vote state
 */
sol_err_t sol_vote_tracker_record_vote_state(
    sol_vote_tracker_t*         tracker,
    const sol_pubkey_t*         vote_pubkey,
    const sol_vote_state_t*     state,
    uint64_t                    stake
);

/*
 * Get total stake voting for a slot
 */
uint64_t sol_vote_tracker_get_slot_stake(
    const sol_vote_tracker_t*   tracker,
    sol_slot_t                  slot
);

/*
 * Check if slot has supermajority (2/3 stake)
 */
bool sol_vote_tracker_has_supermajority(
    const sol_vote_tracker_t*   tracker,
    sol_slot_t                  slot,
    uint64_t                    total_stake
);

/*
 * Get highest slot with supermajority
 */
sol_slot_t sol_vote_tracker_highest_confirmed_slot(
    const sol_vote_tracker_t* tracker
);

/*
 * Get highest finalized slot (2/3 have as root)
 */
sol_slot_t sol_vote_tracker_highest_finalized_slot(
    const sol_vote_tracker_t* tracker
);

/*
 * Get all validators that voted for a slot
 *
 * @param tracker       Vote tracker
 * @param slot          Slot to query
 * @param out_records   Output array
 * @param max_records   Max records to return
 * @return              Number of records written
 */
size_t sol_vote_tracker_get_slot_voters(
    const sol_vote_tracker_t*   tracker,
    sol_slot_t                  slot,
    sol_vote_record_t*          out_records,
    size_t                      max_records
);

/*
 * Get vote record for a validator
 */
sol_err_t sol_vote_tracker_get_validator(
    const sol_vote_tracker_t*   tracker,
    const sol_pubkey_t*         vote_pubkey,
    sol_vote_record_t*          out_record
);

/*
 * Get vote aggregate for a slot
 */
sol_err_t sol_vote_tracker_get_slot_votes(
    const sol_vote_tracker_t*   tracker,
    sol_slot_t                  slot,
    sol_slot_votes_t*           out_votes
);

/*
 * Update stake for a validator
 */
sol_err_t sol_vote_tracker_update_stake(
    sol_vote_tracker_t*     tracker,
    const sol_pubkey_t*     vote_pubkey,
    uint64_t                stake
);

/*
 * Prune old vote data
 * Removes vote data for slots before root_slot
 */
void sol_vote_tracker_prune(
    sol_vote_tracker_t*     tracker,
    sol_slot_t              root_slot
);

/*
 * Get tracker statistics
 */
sol_vote_tracker_stats_t sol_vote_tracker_stats(
    const sol_vote_tracker_t* tracker
);

/*
 * Get total stake of all tracked validators
 */
uint64_t sol_vote_tracker_total_stake(
    const sol_vote_tracker_t* tracker
);

/*
 * Get number of active validators
 */
size_t sol_vote_tracker_active_validators(
    const sol_vote_tracker_t* tracker
);

/*
 * Check if a slot is confirmed (2/3 voted)
 */
bool sol_vote_tracker_is_slot_confirmed(
    const sol_vote_tracker_t*   tracker,
    sol_slot_t                  slot
);

/*
 * Check if a slot is finalized (2/3 have as root)
 */
bool sol_vote_tracker_is_slot_finalized(
    const sol_vote_tracker_t*   tracker,
    sol_slot_t                  slot
);

#endif /* SOL_VOTE_TRACKER_H */
