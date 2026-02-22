/*
 * sol_tower.h - Tower BFT Consensus
 *
 * Tower BFT is Solana's consensus mechanism based on PBFT:
 *
 * - Validators vote on blocks they believe are valid
 * - Votes have lockouts that double with each confirmation
 * - Validators must wait for lockouts to expire before switching forks
 * - This creates exponential rollback difficulty
 *
 * Key concepts:
 * - Vote: A validator's attestation that a slot is valid
 * - Lockout: Time a validator must wait before switching forks
 * - Confirmation: A vote that has been included in the chain
 * - Root: A slot that has received enough confirmations to be final
 */

#ifndef SOL_TOWER_H
#define SOL_TOWER_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../txn/sol_pubkey.h"
#include "../runtime/sol_bank.h"
#include "../replay/sol_fork_choice.h"
#include "../programs/sol_vote_program.h"
#include <pthread.h>

/*
 * Initial lockout value (2^1 = 2 slots)
 */
#define SOL_INITIAL_LOCKOUT 2

/*
 * Maximum lockout (2^31 slots)
 */
#define SOL_MAX_LOCKOUT (1UL << 31)

/*
 * Tower configuration
 */
typedef struct {
    sol_pubkey_t    vote_account;       /* Vote account pubkey */
    sol_pubkey_t    node_identity;      /* Validator identity */
    uint32_t        threshold_depth;    /* Confirmation threshold depth */
    uint32_t        threshold_size;     /* Supermajority threshold */
    bool            disable_lockout;    /* Disable lockouts (testing) */
} sol_tower_config_t;

#define SOL_TOWER_CONFIG_DEFAULT {              \
    .vote_account = {{0}},                      \
    .node_identity = {{0}},                     \
    .threshold_depth = 8,                       \
    .threshold_size = 2,                        \
    .disable_lockout = false,                   \
}

/*
 * Vote decision result
 */
typedef enum {
    SOL_VOTE_DECISION_VOTE,         /* Should vote for this slot */
    SOL_VOTE_DECISION_WAIT,         /* Wait for more confirmations */
    SOL_VOTE_DECISION_LOCKOUT,      /* Locked out, cannot vote */
    SOL_VOTE_DECISION_SKIP,         /* Skip this slot */
} sol_vote_decision_t;

/*
 * Tower handle
 */
typedef struct sol_tower sol_tower_t;

/*
 * Create tower
 *
 * @param config        Configuration
 * @return              Tower or NULL on error
 */
sol_tower_t* sol_tower_new(const sol_tower_config_t* config);

/*
 * Destroy tower
 */
void sol_tower_destroy(sol_tower_t* tower);

/*
 * Initialize tower from vote account state
 *
 * @param tower         Tower handle
 * @param vote_state    Vote state from account
 * @return              SOL_OK or error
 */
sol_err_t sol_tower_initialize(
    sol_tower_t*            tower,
    const sol_vote_state_t* vote_state
);

/*
 * Check if we should vote for a slot
 *
 * @param tower         Tower handle
 * @param slot          Slot to consider
 * @param bank          Bank at this slot
 * @param fork_choice   Fork choice state
 * @return              Vote decision
 */
sol_vote_decision_t sol_tower_check_vote(
    sol_tower_t*            tower,
    sol_slot_t              slot,
    const sol_bank_t*       bank,
    const sol_fork_choice_t* fork_choice
);

/*
 * Record a vote
 *
 * @param tower         Tower handle
 * @param slot          Slot voted for
 * @param hash          Block hash
 * @return              SOL_OK or error
 */
sol_err_t sol_tower_record_vote(
    sol_tower_t*        tower,
    sol_slot_t          slot,
    const sol_hash_t*   hash
);

/*
 * Record a bank vote (includes processing confirmations)
 *
 * @param tower         Tower handle
 * @param bank          Bank to vote for
 * @return              SOL_OK or error
 */
sol_err_t sol_tower_record_bank_vote(
    sol_tower_t*        tower,
    const sol_bank_t*   bank
);

/*
 * Get lockout for a slot
 *
 * @param tower         Tower handle
 * @param slot          Slot to check
 * @return              Lockout duration in slots, or 0 if not locked
 */
uint64_t sol_tower_lockout(const sol_tower_t* tower, sol_slot_t slot);

/*
 * Check if we would be locked out by voting for a slot
 *
 * @param tower         Tower handle
 * @param slot          Slot to vote for
 * @return              true if locked out
 */
bool sol_tower_would_be_locked_out(
    const sol_tower_t*  tower,
    sol_slot_t          slot
);

/*
 * Get last voted slot
 */
sol_slot_t sol_tower_last_voted_slot(const sol_tower_t* tower);

/*
 * Get last voted hash
 */
sol_hash_t sol_tower_last_voted_hash(const sol_tower_t* tower);

/*
 * Get root slot
 */
sol_slot_t sol_tower_root(const sol_tower_t* tower);

/*
 * Get vote stack
 */
size_t sol_tower_vote_stack(
    const sol_tower_t*  tower,
    sol_lockout_t*      out_votes,
    size_t              max_votes
);

/*
 * Check if a slot has been voted on
 */
bool sol_tower_has_voted(const sol_tower_t* tower, sol_slot_t slot);

/*
 * Calculate the threshold confirmation count
 *
 * Returns the confirmation count at the threshold depth.
 */
uint32_t sol_tower_threshold_confirmation(const sol_tower_t* tower);

/*
 * Get vote state for serialization
 */
sol_err_t sol_tower_get_vote_state(
    const sol_tower_t*  tower,
    sol_vote_state_t*   out_state
);

/*
 * Apply vote to vote state (for vote transaction construction)
 */
sol_err_t sol_tower_apply_vote(
    sol_vote_state_t*   state,
    sol_slot_t          slot,
    const sol_hash_t*   hash
);

/*
 * Process vote confirmation (called when vote lands on chain)
 */
sol_err_t sol_tower_process_confirmation(
    sol_tower_t*    tower,
    sol_slot_t      slot
);

/*
 * Persist tower state to disk
 *
 * Stores the vote state plus last voted hash. Intended for validator restarts.
 * The file format is internal and may change; callers should treat it as opaque.
 *
 * @param tower     Tower handle
 * @param path      Output file path
 * @return          SOL_OK or error
 */
sol_err_t sol_tower_save_file(const sol_tower_t* tower, const char* path);

/*
 * Load tower state from disk
 *
 * @param tower     Tower handle
 * @param path      Input file path
 * @return          SOL_OK, SOL_ERR_NOTFOUND if missing, or error
 */
sol_err_t sol_tower_load_file(sol_tower_t* tower, const char* path);

/*
 * Refresh tower state for a given slot
 *
 * Expires old votes and advances root as needed.
 * Call this when catching up after being offline.
 *
 * @param tower         Tower handle
 * @param current_slot  Current slot to evaluate against
 */
void sol_tower_refresh(
    sol_tower_t*    tower,
    sol_slot_t      current_slot
);

/* Vote state serialize/deserialize - see sol_vote_program.h */

/*
 * Calculate lockout for a confirmation count
 */
static inline uint64_t
sol_lockout_duration(uint32_t confirmation_count) {
    if (confirmation_count >= 32) return SOL_MAX_LOCKOUT;
    return 1UL << confirmation_count;
}

/*
 * Check if lockout has expired
 */
static inline bool
sol_lockout_expired(const sol_lockout_t* lockout, sol_slot_t current_slot) {
    uint64_t duration = sol_lockout_duration(lockout->confirmation_count);
    return current_slot >= lockout->slot + duration;
}

#endif /* SOL_TOWER_H */
