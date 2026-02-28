/*
 * sol_leader_schedule.h - Leader Schedule Computation
 *
 * The leader schedule determines which validator produces blocks for each slot.
 * It is computed from stake weights using a deterministic algorithm.
 */

#ifndef SOL_LEADER_SCHEDULE_H
#define SOL_LEADER_SCHEDULE_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../util/sol_map.h"
#include "../txn/sol_pubkey.h"
#include "sol_bank.h"

/*
 * Slots per leader slot
 */
#define SOL_LEADER_SCHEDULE_SLOT_OFFSET 4

/*
 * Default slots per epoch
 */
#define SOL_DEFAULT_SLOTS_PER_EPOCH 432000

/*
 * Leader schedule lookahead (in epochs)
 */
#define SOL_LEADER_SCHEDULE_LOOKAHEAD 2

/*
 * Stake weight entry
 */
typedef struct {
    sol_pubkey_t    pubkey;         /* Validator identity */
    uint64_t        stake;          /* Active stake */
} sol_stake_weight_t;

/*
 * Leader schedule entry
 */
typedef struct {
    sol_slot_t      first_slot;     /* First slot in range */
    sol_pubkey_t    leader;         /* Leader for this range */
} sol_leader_entry_t;

/*
 * Leader schedule configuration
 */
typedef struct {
    uint64_t    slots_per_epoch;
    uint64_t    leader_schedule_slot_offset;
} sol_leader_schedule_config_t;

#define SOL_LEADER_SCHEDULE_CONFIG_DEFAULT {        \
    .slots_per_epoch = SOL_DEFAULT_SLOTS_PER_EPOCH, \
    .leader_schedule_slot_offset = SOL_LEADER_SCHEDULE_SLOT_OFFSET, \
}

/*
 * Leader schedule handle (opaque)
 */
typedef struct sol_leader_schedule sol_leader_schedule_t;

/*
 * Create a new leader schedule
 *
 * @param epoch             Epoch this schedule is for
 * @param stakes            Array of stake weights
 * @param stakes_len        Number of stake entries
 * @param config            Configuration (NULL for defaults)
 * @return                  Leader schedule or NULL on error
 */
sol_leader_schedule_t* sol_leader_schedule_new(
    uint64_t                            epoch,
    const sol_stake_weight_t*           stakes,
    size_t                              stakes_len,
    const sol_leader_schedule_config_t* config
);

/*
 * Create leader schedule from bank state
 *
 * Extracts stake weights from the bank and computes schedule.
 */
sol_leader_schedule_t* sol_leader_schedule_from_bank(
    sol_bank_t*                         bank,
    uint64_t                            epoch,
    const sol_leader_schedule_config_t* config
);

/*
 * Create leader schedule from bank state using a precomputed vote stake map.
 *
 * @param bank          Bank to extract vote accounts from
 * @param epoch         Epoch to compute schedule for
 * @param vote_stakes   Map of vote-account pubkey -> effective stake (may be NULL)
 * @param config        Configuration (NULL for defaults)
 */
sol_leader_schedule_t* sol_leader_schedule_from_bank_with_vote_stakes(
    sol_bank_t*                         bank,
    uint64_t                            epoch,
    const sol_pubkey_map_t*             vote_stakes,
    const sol_leader_schedule_config_t* config
);

/*
 * Create a leader schedule from an explicit per-slot leader list.
 *
 * This is primarily intended for bootstrap via RPC (getSlotLeaders), and
 * produces a schedule valid for slots [first_slot, first_slot + leaders_len).
 */
sol_leader_schedule_t* sol_leader_schedule_from_slot_leaders(
    sol_slot_t              first_slot,
    const sol_pubkey_t*     leaders,
    size_t                  leaders_len
);

/*
 * Clone an existing leader schedule (deep copy).
 */
sol_leader_schedule_t* sol_leader_schedule_clone(
    const sol_leader_schedule_t* schedule
);

/*
 * Destroy leader schedule
 */
void sol_leader_schedule_destroy(sol_leader_schedule_t* schedule);

/*
 * Get leader for a slot
 *
 * @param schedule      Leader schedule
 * @param slot          Slot to query
 * @return              Leader pubkey or NULL if not in schedule
 */
const sol_pubkey_t* sol_leader_schedule_get_leader(
    const sol_leader_schedule_t*    schedule,
    sol_slot_t                      slot
);

/*
 * Check if pubkey is leader at slot
 */
bool sol_leader_schedule_is_leader(
    const sol_leader_schedule_t*    schedule,
    sol_slot_t                      slot,
    const sol_pubkey_t*             pubkey
);

/*
 * Get all leader slots for a pubkey in this epoch
 *
 * @param schedule      Leader schedule
 * @param pubkey        Validator pubkey
 * @param out_slots     Output array for slots
 * @param max_slots     Maximum slots to return
 * @return              Number of slots written
 */
size_t sol_leader_schedule_get_slots(
    const sol_leader_schedule_t*    schedule,
    const sol_pubkey_t*             pubkey,
    sol_slot_t*                     out_slots,
    size_t                          max_slots
);

/*
 * Get first slot in schedule
 */
sol_slot_t sol_leader_schedule_first_slot(
    const sol_leader_schedule_t* schedule
);

/*
 * Get last slot in schedule
 */
sol_slot_t sol_leader_schedule_last_slot(
    const sol_leader_schedule_t* schedule
);

/*
 * Get epoch for schedule
 */
uint64_t sol_leader_schedule_epoch(
    const sol_leader_schedule_t* schedule
);

/*
 * Get number of unique leaders
 */
size_t sol_leader_schedule_num_leaders(
    const sol_leader_schedule_t* schedule
);

/*
 * Get all unique leaders in schedule
 *
 * @param schedule      Leader schedule
 * @param out_leaders   Output array for leader pubkeys
 * @param max_leaders   Maximum leaders to return
 * @return              Number of leaders written
 */
size_t sol_leader_schedule_get_leaders(
    const sol_leader_schedule_t*    schedule,
    sol_pubkey_t*                   out_leaders,
    size_t                          max_leaders
);

/*
 * Epoch schedule default (sol_epoch_schedule_t defined in sol_types.h)
 */
#define SOL_EPOCH_SCHEDULE_DEFAULT {                    \
    .slots_per_epoch = SOL_DEFAULT_SLOTS_PER_EPOCH,     \
    .leader_schedule_slot_offset = SOL_LEADER_SCHEDULE_SLOT_OFFSET, \
    .warmup = false,                                    \
    .first_normal_epoch = 0,                            \
    .first_normal_slot = 0,                             \
}

/*
 * Get epoch for a slot
 */
uint64_t sol_epoch_schedule_get_epoch(
    const sol_epoch_schedule_t* schedule,
    sol_slot_t                  slot
);

/*
 * Get first slot of an epoch
 */
sol_slot_t sol_epoch_schedule_get_first_slot_in_epoch(
    const sol_epoch_schedule_t* schedule,
    uint64_t                    epoch
);

/*
 * Get last slot of an epoch
 */
sol_slot_t sol_epoch_schedule_get_last_slot_in_epoch(
    const sol_epoch_schedule_t* schedule,
    uint64_t                    epoch
);

/*
 * Get slots per epoch (may vary during warmup)
 */
uint64_t sol_epoch_schedule_get_slots_per_epoch(
    const sol_epoch_schedule_t* schedule,
    uint64_t                    epoch
);

#endif /* SOL_LEADER_SCHEDULE_H */
