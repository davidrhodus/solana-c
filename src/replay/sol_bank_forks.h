/*
 * sol_bank_forks.h - Bank Forks Management
 *
 * Manages the tree of banks representing different forks of the chain.
 * The validator maintains multiple forks until consensus determines
 * which fork to finalize.
 */

#ifndef SOL_BANK_FORKS_H
#define SOL_BANK_FORKS_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../runtime/sol_bank.h"
#include <pthread.h>

/*
 * Maximum number of banks to keep in the forks tree
 */
#define SOL_MAX_BANK_FORKS 4096

/*
 * Bank forks configuration
 */
typedef struct {
    uint32_t    max_banks;              /* Maximum banks to track */
    uint32_t    snapshot_interval;      /* Slots between snapshots */
} sol_bank_forks_config_t;

#define SOL_BANK_FORKS_CONFIG_DEFAULT { \
    .max_banks = SOL_MAX_BANK_FORKS,    \
    .snapshot_interval = 100,           \
}

/*
 * Fork info for a bank
 */
typedef struct {
    sol_slot_t      slot;
    sol_slot_t      parent_slot;
    sol_hash_t      bank_hash;
    uint64_t        stake_weight;       /* Total stake voting for this fork */
    bool            is_frozen;
    bool            is_dead;            /* Fork failed validation */
} sol_fork_info_t;

/*
 * Bank forks statistics
 */
typedef struct {
    uint64_t    banks_created;
    uint64_t    banks_frozen;
    uint64_t    banks_pruned;
    uint64_t    forks_switched;
    sol_slot_t  highest_slot;
    sol_slot_t  root_slot;
} sol_bank_forks_stats_t;

/*
 * Bank forks handle (opaque)
 */
typedef struct sol_bank_forks sol_bank_forks_t;

/*
 * Create a new bank forks manager
 *
 * @param root_bank     The root bank (genesis or snapshot)
 * @param config        Configuration (NULL for defaults)
 * @return              Bank forks handle or NULL on error
 */
sol_bank_forks_t* sol_bank_forks_new(
    sol_bank_t*                     root_bank,
    const sol_bank_forks_config_t*  config
);

/*
 * Destroy bank forks and all managed banks
 */
void sol_bank_forks_destroy(sol_bank_forks_t* forks);

/*
 * Get bank for a specific slot
 *
 * @param forks     Bank forks handle
 * @param slot      Slot to look up
 * @return          Bank or NULL if not found
 */
sol_bank_t* sol_bank_forks_get(
    sol_bank_forks_t*   forks,
    sol_slot_t          slot
);

/*
 * Get bank for a specific (slot, bank_hash)
 *
 * @param forks     Bank forks handle
 * @param slot      Slot to look up
 * @param bank_hash Bank hash to match (required)
 * @return          Bank or NULL if not found
 */
sol_bank_t* sol_bank_forks_get_hash(
    sol_bank_forks_t*       forks,
    sol_slot_t              slot,
    const sol_hash_t*       bank_hash
);

/*
 * Get the root bank
 */
sol_bank_t* sol_bank_forks_root(sol_bank_forks_t* forks);

/*
 * Get the root slot
 */
sol_slot_t sol_bank_forks_root_slot(const sol_bank_forks_t* forks);

/*
 * Get the working bank (highest unfrozen bank on best fork)
 */
sol_bank_t* sol_bank_forks_working_bank(sol_bank_forks_t* forks);

/*
 * Get the highest slot in the forks tree
 */
sol_slot_t sol_bank_forks_highest_slot(const sol_bank_forks_t* forks);

/*
 * Insert a new bank into the forks tree
 *
 * @param forks     Bank forks handle
 * @param bank      Bank to insert (takes ownership)
 * @return          SOL_OK on success
 */
sol_err_t sol_bank_forks_insert(
    sol_bank_forks_t*   forks,
    sol_bank_t*         bank
);

/*
 * Create a new bank as child of parent
 *
 * @param forks         Bank forks handle
 * @param parent_slot   Parent slot
 * @param slot          New slot
 * @return              New bank or NULL on error
 */
sol_bank_t* sol_bank_forks_new_from_parent(
    sol_bank_forks_t*   forks,
    sol_slot_t          parent_slot,
    sol_slot_t          slot
);

/*
 * Set the root bank (prunes ancestors)
 *
 * This is called when a slot is finalized. All banks that are
 * not descendants of the new root will be removed.
 *
 * @param forks     Bank forks handle
 * @param slot      New root slot
 * @return          SOL_OK on success
 */
sol_err_t sol_bank_forks_set_root(
    sol_bank_forks_t*   forks,
    sol_slot_t          slot
);

/*
 * Set the root bank to a specific (slot, bank_hash) pair.
 *
 * Required for duplicate-slot support where multiple banks can exist at the
 * same slot with different hashes.
 */
sol_err_t sol_bank_forks_set_root_hash(
    sol_bank_forks_t*       forks,
    sol_slot_t              slot,
    const sol_hash_t*       bank_hash
);

/*
 * Mark a bank as frozen (completed)
 */
sol_err_t sol_bank_forks_freeze(
    sol_bank_forks_t*   forks,
    sol_slot_t          slot
);

/*
 * Mark a fork as dead (failed validation)
 */
sol_err_t sol_bank_forks_mark_dead(
    sol_bank_forks_t*   forks,
    sol_slot_t          slot
);

/*
 * Mark a specific bank as dead (failed validation)
 */
sol_err_t sol_bank_forks_mark_dead_hash(
    sol_bank_forks_t*       forks,
    sol_slot_t              slot,
    const sol_hash_t*       bank_hash
);

/*
 * Check if a slot exists in the forks tree
 */
bool sol_bank_forks_contains(
    const sol_bank_forks_t* forks,
    sol_slot_t              slot
);

/*
 * Check if slot is an ancestor of descendant
 */
bool sol_bank_forks_is_ancestor(
    const sol_bank_forks_t* forks,
    sol_slot_t              ancestor,
    sol_slot_t              descendant
);

/*
 * Get fork info for a slot
 */
sol_err_t sol_bank_forks_get_info(
    const sol_bank_forks_t* forks,
    sol_slot_t              slot,
    sol_fork_info_t*        info
);

/*
 * Get fork info for a specific (slot, bank_hash)
 */
sol_err_t sol_bank_forks_get_info_hash(
    const sol_bank_forks_t* forks,
    sol_slot_t              slot,
    const sol_hash_t*       bank_hash,
    sol_fork_info_t*        info
);

/*
 * Iterate over all banks in the forks set.
 *
 * Callback receives (slot, parent_slot, bank_hash, parent_hash, bank, is_dead, ctx).
 * Return false to stop iteration early.
 */
typedef bool (*sol_bank_forks_iter_cb)(
    sol_slot_t              slot,
    sol_slot_t              parent_slot,
    const sol_hash_t*       bank_hash,
    const sol_hash_t*       parent_hash,
    sol_bank_t*             bank,
    bool                    is_dead,
    void*                   ctx
);

void sol_bank_forks_iterate(
    const sol_bank_forks_t* forks,
    sol_bank_forks_iter_cb  callback,
    void*                   ctx
);

/*
 * Iterate banks for a specific slot only.
 *
 * Callback receives (bank_hash, bank, is_dead, ctx).
 * Return false to stop iteration early.
 */
typedef bool (*sol_bank_forks_slot_iter_cb)(
    const sol_hash_t*       bank_hash,
    sol_bank_t*             bank,
    bool                    is_dead,
    void*                   ctx
);

void sol_bank_forks_iter_slot(
    const sol_bank_forks_t*     forks,
    sol_slot_t                  slot,
    sol_bank_forks_slot_iter_cb callback,
    void*                       ctx
);

/*
 * Check whether a slot has at least one non-dead frozen bank.
 */
bool sol_bank_forks_has_frozen_slot(
    const sol_bank_forks_t* forks,
    sol_slot_t              slot
);

/*
 * Get all frozen banks (for voting)
 *
 * @param forks         Bank forks handle
 * @param out_slots     Output array for slots
 * @param max_slots     Maximum slots to return
 * @return              Number of slots written
 */
size_t sol_bank_forks_frozen_banks(
    const sol_bank_forks_t* forks,
    sol_slot_t*             out_slots,
    size_t                  max_slots
);

/*
 * Update stake weight for a fork (from votes)
 */
sol_err_t sol_bank_forks_update_stake(
    sol_bank_forks_t*   forks,
    sol_slot_t          slot,
    uint64_t            stake_delta
);

/*
 * Get statistics
 */
void sol_bank_forks_stats(
    const sol_bank_forks_t* forks,
    sol_bank_forks_stats_t* stats
);

/*
 * Get number of banks
 */
size_t sol_bank_forks_count(const sol_bank_forks_t* forks);

/*
 * Get configured bank-forks capacity.
 */
size_t sol_bank_forks_capacity(const sol_bank_forks_t* forks);

#endif /* SOL_BANK_FORKS_H */
