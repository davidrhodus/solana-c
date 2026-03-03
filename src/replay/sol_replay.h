/*
 * sol_replay.h - Replay Stage
 *
 * The replay stage is responsible for:
 * - Replaying blocks from the blockstore through the bank
 * - Managing the bank forks tree
 * - Determining fork choice (heaviest fork)
 * - Coordinating with voting and consensus
 */

#ifndef SOL_REPLAY_H
#define SOL_REPLAY_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../blockstore/sol_blockstore.h"
#include "../entry/sol_entry.h"
#include "sol_bank_forks.h"
#include "sol_fork_choice.h"

/*
 * Replay result for a slot
 */
typedef enum {
    SOL_REPLAY_SUCCESS = 0,         /* Slot replayed successfully */
    SOL_REPLAY_INCOMPLETE,          /* Slot not complete yet */
    SOL_REPLAY_DEAD,                /* Slot failed validation */
    SOL_REPLAY_DUPLICATE,           /* Slot already replayed */
    SOL_REPLAY_PARENT_MISSING,      /* Parent slot not available */
} sol_replay_result_t;

/*
 * Replay slot info
 */
typedef struct {
    sol_slot_t          slot;
    sol_slot_t          parent_slot;
    sol_replay_result_t result;
    uint32_t            num_entries;
    uint32_t            num_transactions;
    uint64_t            compute_units;
    uint64_t            replay_time_ns;     /* Time to replay */
    uint64_t            fetch_time_ns;      /* Block fetch/read time */
    uint64_t            decode_time_ns;     /* Entry decode/parse time */
    uint64_t            execute_time_ns;    /* Bank execution time */
    uint64_t            commit_time_ns;     /* Freeze/hash/insert time */
    uint64_t            verify_time_ns;     /* Entry-hash verification time */
} sol_replay_slot_info_t;

/*
 * Replay stage configuration
 */
typedef struct {
    uint32_t    max_pending_slots;          /* Max slots waiting for parent */
    uint32_t    replay_threads;             /* Parallel replay threads */
    bool        verify_entries;             /* Verify entry hashes */
    bool        verify_signatures;          /* Verify transaction signatures */
    bool        replay_all_variants;        /* Replay all complete block variants (slow); otherwise stop after first success */
} sol_replay_config_t;

#define SOL_REPLAY_CONFIG_DEFAULT {         \
    .max_pending_slots = 100,               \
    .replay_threads = 1,                    \
    .verify_entries = true,                 \
    .verify_signatures = true,              \
    .replay_all_variants = false,           \
}

/*
 * Replay stage statistics
 */
typedef struct {
    uint64_t    slots_replayed;
    uint64_t    slots_dead;
    uint64_t    entries_processed;
    uint64_t    transactions_processed;
    uint64_t    transactions_succeeded;
    uint64_t    transactions_failed;
    uint64_t    total_replay_time_ns;
    sol_slot_t  highest_replayed_slot;
} sol_replay_stats_t;

/*
 * Replay stage handle (opaque)
 */
typedef struct sol_replay sol_replay_t;

/*
 * Atomically swap leader schedule used for slot->leader lookups.
 *
 * Replay does not take ownership; caller remains responsible for freeing the
 * returned schedule once it is no longer in use.
 */
struct sol_leader_schedule;
struct sol_leader_schedule* sol_replay_swap_leader_schedule(
    sol_replay_t*                replay,
    struct sol_leader_schedule*  schedule
);

/*
 * Callback for slot replay completion
 */
typedef void (*sol_replay_slot_cb)(
    sol_slot_t              slot,
    sol_replay_result_t     result,
    void*                   ctx
);

/*
 * Create a new replay stage
 *
 * @param bank_forks    Bank forks manager
 * @param blockstore    Blockstore for reading blocks
 * @param config        Configuration (NULL for defaults)
 * @return              Replay stage handle or NULL on error
 */
sol_replay_t* sol_replay_new(
    sol_bank_forks_t*           bank_forks,
    sol_blockstore_t*           blockstore,
    const sol_replay_config_t*  config
);

/*
 * Destroy replay stage
 */
void sol_replay_destroy(sol_replay_t* replay);

/*
 * Replay a single slot
 *
 * @param replay    Replay stage handle
 * @param slot      Slot to replay
 * @param info      Output info about replay (optional)
 * @return          Replay result
 */
sol_replay_result_t sol_replay_slot(
    sol_replay_t*           replay,
    sol_slot_t              slot,
    sol_replay_slot_info_t* info
);

/*
 * Replay all available slots
 *
 * Replays all complete slots that haven't been replayed yet.
 *
 * @param replay        Replay stage handle
 * @param max_slots     Maximum slots to replay (0 = unlimited)
 * @return              Number of slots replayed
 */
size_t sol_replay_available(
    sol_replay_t*   replay,
    size_t          max_slots
);

/*
 * Check if a slot has been replayed
 */
bool sol_replay_is_replayed(
    sol_replay_t*   replay,
    sol_slot_t      slot
);

/*
 * Check if a slot has at least one successful frozen bank candidate.
 *
 * This is intentionally weaker than `sol_replay_is_replayed()`: it remains
 * true even if new duplicate block variants are discovered for the slot.
 * Used for parent-availability gating during live catchup.
 */
bool sol_replay_has_frozen_bank(
    sol_replay_t*   replay,
    sol_slot_t      slot
);

/*
 * Check whether a slot's parent is currently available for replay.
 *
 * Returns true when the slot's parent bank is already available/frozen in
 * bank-forks (or the slot is a root-style self-parent). This is useful for
 * parent-aware scheduling in TVU.
 */
bool sol_replay_parent_ready(
    sol_replay_t*   replay,
    sol_slot_t      slot,
    sol_slot_t*     out_parent_slot
);

/*
 * Best-effort pre-replay warming for a slot.
 *
 * This runs lightweight asynchronous work ahead of replay (block fetch/decode,
 * parse, and optional account-cache warming when parent context is available)
 * without mutating consensus state.
 */
bool sol_replay_prewarm_slot(
    sol_replay_t*   replay,
    sol_slot_t      slot
);

/*
 * Check if a slot is dead (failed validation)
 */
bool sol_replay_is_dead(
    sol_replay_t*   replay,
    sol_slot_t      slot
);

/*
 * Get the best slot (heaviest fork tip)
 */
sol_slot_t sol_replay_best_slot(sol_replay_t* replay);

/*
 * Get the highest slot replayed successfully (lock-free best-effort).
 *
 * This is intended for hot-path consumers (TVU repair prefetch, validator main
 * loop) that must not block on the replay mutex while a large slot is replaying.
 */
sol_slot_t sol_replay_highest_replayed_slot(const sol_replay_t* replay);

/*
 * Get the root slot
 */
sol_slot_t sol_replay_root_slot(sol_replay_t* replay);

/*
 * Set the root slot (finalize)
 *
 * Marks a slot as finalized, pruning forks that are not
 * descendants of this slot.
 */
sol_err_t sol_replay_set_root(
    sol_replay_t*   replay,
    sol_slot_t      slot
);

/*
 * Set the root slot to a specific bank hash (duplicate-slot safe).
 */
sol_err_t sol_replay_set_root_hash(
    sol_replay_t*       replay,
    sol_slot_t          slot,
    const sol_hash_t*   bank_hash
);

/*
 * Record a vote for fork choice
 */
sol_err_t sol_replay_record_vote(
    sol_replay_t*       replay,
    const sol_pubkey_t* validator,
    sol_slot_t          slot,
    uint64_t            stake
);

/*
 * Record a vote for a specific bank hash for fork choice
 */
sol_err_t sol_replay_record_vote_hash(
    sol_replay_t*       replay,
    const sol_pubkey_t* validator,
    sol_slot_t          slot,
    const sol_hash_t*   bank_hash,
    uint64_t            stake
);

/*
 * Get the fork choice tracker
 */
sol_fork_choice_t* sol_replay_fork_choice(sol_replay_t* replay);

/*
 * Get the bank forks manager
 */
sol_bank_forks_t* sol_replay_bank_forks(sol_replay_t* replay);

/*
 * Get bank for a slot
 */
sol_bank_t* sol_replay_get_bank(
    sol_replay_t*   replay,
    sol_slot_t      slot
);

/*
 * Get the working bank
 */
sol_bank_t* sol_replay_working_bank(sol_replay_t* replay);

/*
 * Set slot replay callback
 */
void sol_replay_set_callback(
    sol_replay_t*       replay,
    sol_replay_slot_cb  callback,
    void*               ctx
);

/*
 * Get statistics
 */
void sol_replay_stats(
    const sol_replay_t* replay,
    sol_replay_stats_t* stats
);

#endif /* SOL_REPLAY_H */
