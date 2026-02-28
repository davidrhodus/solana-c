/*
 * sol_crds.h - Cluster Replicated Data Store
 *
 * The CRDS stores signed values that are replicated across the cluster
 * via the gossip protocol. It supports:
 *
 * - Insertion with duplicate/older value detection
 * - Lookup by key (type + pubkey + index)
 * - Iteration over all values
 * - Pruning of old entries
 * - Origin tracking for protocol routing
 */

#ifndef SOL_CRDS_H
#define SOL_CRDS_H

#include "sol_crds_value.h"
#include "../util/sol_arena.h"

/*
 * Maximum number of entries in the CRDS
 */
#define SOL_CRDS_MAX_ENTRIES 65536

/*
 * Default timeout for entries (10 minutes)
 */
#define SOL_CRDS_TIMEOUT_MS (10 * 60 * 1000)

/*
 * Maximum wallclock drift allowed (10 minutes)
 *
 * Gossip values with wallclock timestamps more than this far from
 * the current time (either past or future) are rejected.
 */
#define SOL_CRDS_MAX_WALLCLOCK_DRIFT_MS (10 * 60 * 1000)

/*
 * CRDS entry - Value with metadata
 */
typedef struct {
    sol_crds_value_t  value;
    sol_crds_key_t    key;
    uint64_t          insert_timestamp;  /* Local timestamp when inserted */
    uint64_t          local_timestamp;   /* Timestamp for ordering */
    sol_pubkey_t      origin;            /* Node we received this from */
    bool              is_push;           /* Received via push (vs pull) */
} sol_crds_entry_t;

/*
 * CRDS statistics
 */
typedef struct {
    uint64_t inserts;           /* Total insertions */
    uint64_t updates;           /* Updates to existing entries */
    uint64_t duplicates;        /* Duplicate values ignored */
    uint64_t stale;             /* Stale (older) values ignored */
    uint64_t evictions;         /* Entries evicted for space */
    uint64_t prunes;            /* Entries pruned by timeout */
} sol_crds_stats_t;

/*
 * CRDS store
 */
typedef struct sol_crds sol_crds_t;

/*
 * Create a new CRDS store
 *
 * Parameters:
 *   max_entries - Maximum number of entries (0 = default)
 *
 * Returns NULL on allocation failure.
 */
sol_crds_t* sol_crds_new(size_t max_entries);

/*
 * Destroy a CRDS store
 */
void sol_crds_destroy(sol_crds_t* crds);

/*
 * Insert a value into the CRDS
 *
 * The value is copied into the store. If a newer value exists,
 * the insertion is ignored.
 *
 * Parameters:
 *   crds - The CRDS store
 *   value - Value to insert (copied)
 *   origin - Node we received this from
 *   now_ms - Current time in milliseconds
 *
 * Returns:
 *   SOL_OK - Value inserted or updated
 *   SOL_ERR_EXIST - Duplicate value (same wallclock)
 *   SOL_ERR_OLD - Stale value (older wallclock)
 *   SOL_ERR_FULL - Store is full (consider pruning)
 */
sol_err_t sol_crds_insert(
    sol_crds_t*           crds,
    const sol_crds_value_t* value,
    const sol_pubkey_t*   origin,
    uint64_t              now_ms
);

/*
 * Lookup a value by key
 *
 * Returns a pointer to the entry, or NULL if not found.
 * The pointer is valid until the next insert/prune operation.
 */
const sol_crds_entry_t* sol_crds_get(
    sol_crds_t*           crds,
    const sol_crds_key_t* key
);

/*
 * Lookup contact info by pubkey
 *
 * Convenience function for the common case of looking up a node's
 * contact information.
 */
const sol_contact_info_t* sol_crds_get_contact_info(
    sol_crds_t*         crds,
    const sol_pubkey_t* pubkey
);

/*
 * Check if a key exists
 */
bool sol_crds_contains(
    sol_crds_t*           crds,
    const sol_crds_key_t* key
);

/*
 * Get the number of entries
 */
size_t sol_crds_len(const sol_crds_t* crds);

/*
 * Prune old entries
 *
 * Removes entries older than the specified timeout.
 *
 * Parameters:
 *   crds - The CRDS store
 *   now_ms - Current time in milliseconds
 *   timeout_ms - Entries older than (now - timeout) are removed
 *
 * Returns number of entries removed.
 */
size_t sol_crds_prune(
    sol_crds_t* crds,
    uint64_t    now_ms,
    uint64_t    timeout_ms
);

/*
 * Get statistics
 */
void sol_crds_stats(const sol_crds_t* crds, sol_crds_stats_t* stats);

/*
 * Reset statistics
 */
void sol_crds_stats_reset(sol_crds_t* crds);

/*
 * Callback for iteration
 *
 * Return false to stop iteration.
 */
typedef bool (*sol_crds_iter_fn)(
    const sol_crds_entry_t* entry,
    void*                   ctx
);

/*
 * Iterate over all entries
 *
 * The callback receives each entry. Entries should not be modified
 * during iteration.
 */
void sol_crds_foreach(
    sol_crds_t*      crds,
    sol_crds_iter_fn fn,
    void*            ctx
);

/*
 * Iterate over entries of a specific type
 */
void sol_crds_foreach_type(
    sol_crds_t*      crds,
    sol_crds_type_t  type,
    sol_crds_iter_fn fn,
    void*            ctx
);

/*
 * Get all contact infos
 *
 * Fills the array with pointers to contact info entries.
 * Returns number of entries filled.
 */
size_t sol_crds_get_all_contact_info(
    sol_crds_t*              crds,
    const sol_contact_info_t** out,
    size_t                   max_count
);

/*
 * Get version info by pubkey
 *
 * Returns a pointer to the version info, or NULL if not found.
 */
const sol_crds_version_t* sol_crds_get_version(
    sol_crds_t*         crds,
    const sol_pubkey_t* pubkey
);

/*
 * Get all votes for a slot
 */
size_t sol_crds_get_votes_for_slot(
    sol_crds_t*            crds,
    sol_slot_t             slot,
    const sol_crds_vote_t** out,
    size_t                 max_count
);

/*
 * Get entries newer than timestamp
 *
 * Used for pull responses - returns entries that the requester
 * might not have.
 *
 * Parameters:
 *   crds - The CRDS store
 *   since - Return entries with insert_timestamp > since (wallclock ms)
 *   out - Array to fill with entry pointers
 *   max_count - Maximum entries to return
 *
 * Returns number of entries filled.
 */
size_t sol_crds_get_entries_since(
    sol_crds_t*             crds,
    uint64_t                since,
    const sol_crds_entry_t** out,
    size_t                  max_count
);

#endif /* SOL_CRDS_H */
