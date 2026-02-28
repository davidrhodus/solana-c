/*
 * sol_turbine.h - Turbine Block Propagation
 *
 * Turbine is Solana's protocol for propagating blocks (as shreds) across
 * the cluster. It organizes validators into a tree structure where:
 *
 * - The leader broadcasts shreds to root nodes
 * - Each node retransmits to its children
 * - Erasure coding allows recovery from missing shreds
 *
 * Tree construction uses stake-weighted shuffling so that higher-stake
 * validators are closer to the root and more likely to receive shreds.
 */

#ifndef SOL_TURBINE_H
#define SOL_TURBINE_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../txn/sol_pubkey.h"
#include "../shred/sol_shred.h"
#include "../gossip/sol_gossip.h"
#include "../net/sol_udp.h"

/*
 * Turbine constants
 */
#define SOL_TURBINE_DATA_PLANE_FANOUT   200     /* Max children per node */
#define SOL_TURBINE_MAX_TREE_DEPTH      10      /* Max tree depth */
#define SOL_TURBINE_RETRANSMIT_TIMEOUT  100     /* ms before retransmit */

/*
 * Turbine node - represents a validator in the tree
 */
typedef struct {
    sol_pubkey_t    pubkey;         /* Validator identity */
    sol_sockaddr_t  tvu_addr;       /* TVU (Turbine) address */
    uint64_t        stake;          /* Validator stake */
    uint32_t        index;          /* Position in shuffled order */
} sol_turbine_node_t;

/*
 * Turbine tree - the propagation tree for a slot
 */
typedef struct {
    sol_slot_t          slot;
    sol_pubkey_t        leader;         /* Slot leader */

    /* All nodes in stake-weighted order */
    sol_turbine_node_t* nodes;
    size_t              num_nodes;

    /* Our position in the tree */
    uint32_t            self_index;     /* Our index in nodes array */
    uint32_t            parent_index;   /* Parent's index (-1 if root) */

    /* Children indices */
    uint32_t*           children;
    size_t              num_children;

    /* Tree parameters */
    uint32_t            fanout;
    uint32_t            depth;
} sol_turbine_tree_t;

/*
 * Retransmit slot state - tracks shreds for a slot
 */
typedef struct {
    sol_slot_t      slot;
    uint64_t        received_time;

    /* Received shreds bitmap */
    uint8_t*        data_received;      /* Bitmap of received data shreds */
    uint8_t*        code_received;      /* Bitmap of received code shreds */
    size_t          data_bitmap_size;
    size_t          code_bitmap_size;

    /* Shred storage */
    sol_shred_t**   data_shreds;
    sol_shred_t**   code_shreds;
    size_t          max_data_index;
    size_t          max_code_index;

    /* Completion tracking */
    bool            complete;
    uint32_t        last_data_index;    /* Index of last data shred */
} sol_retransmit_slot_t;

/*
 * Turbine configuration
 */
typedef struct {
    uint32_t    fanout;                 /* Children per node (default 200) */
    uint32_t    max_slots;              /* Max concurrent slots to track */
    bool        enable_retransmit;      /* Whether to retransmit to children */
} sol_turbine_config_t;

#define SOL_TURBINE_CONFIG_DEFAULT {    \
    .fanout = SOL_TURBINE_DATA_PLANE_FANOUT, \
    .max_slots = 64,                    \
    .enable_retransmit = true,          \
}

/*
 * Turbine statistics
 */
typedef struct {
    uint64_t    shreds_received;
    uint64_t    shreds_retransmitted;
    uint64_t    duplicate_shreds;
    uint64_t    invalid_shreds;
    uint64_t    slots_completed;
    uint64_t    bytes_received;
    uint64_t    bytes_sent;
} sol_turbine_stats_t;

/*
 * Turbine service handle
 */
typedef struct sol_turbine sol_turbine_t;

/*
 * Callback for completed slots
 */
typedef void (*sol_turbine_slot_cb)(
    sol_slot_t              slot,
    sol_retransmit_slot_t*  slot_state,
    void*                   ctx
);

/*
 * Callback for received shreds (after basic parsing/dedup)
 */
typedef void (*sol_turbine_shred_cb)(
    void*                   ctx,
    const uint8_t*          data,
    size_t                  len,
    const sol_sockaddr_t*   from
);

/*
 * Callback for a batch of received shreds (after basic parsing/dedup)
 *
 * For high packet rates, batching avoids per-shred callback overhead and
 * enables downstream stages (e.g. TVU ingress queues) to amortize locking.
 */
typedef void (*sol_turbine_shred_batch_cb)(
    void*                   ctx,
    const sol_udp_pkt_t*    pkts,
    int                     count
);

/*
 * Create turbine service
 */
sol_turbine_t* sol_turbine_new(
    const sol_turbine_config_t* config,
    sol_gossip_t*               gossip,
    const sol_pubkey_t*         self_pubkey
);

/*
 * Set bank for stake weight lookups
 *
 * When set, turbine will use stake-weighted tree construction.
 * Without a bank, uniform weights are used.
 */
struct sol_bank;
void sol_turbine_set_bank(
    sol_turbine_t*      turbine,
    struct sol_bank*    bank
);

/*
 * Set leader schedule for slot->leader lookups.
 *
 * Returns the previously configured schedule (caller owns).
 */
struct sol_leader_schedule;
struct sol_leader_schedule* sol_turbine_swap_leader_schedule(
    sol_turbine_t*              turbine,
    struct sol_leader_schedule* schedule
);

/*
 * Destroy turbine service
 */
void sol_turbine_destroy(sol_turbine_t* turbine);

/*
 * Start the turbine service
 *
 * Binds the TVU socket and begins processing shreds.
 */
sol_err_t sol_turbine_start(sol_turbine_t* turbine, uint16_t tvu_port);

/*
 * Stop the turbine service
 */
void sol_turbine_stop(sol_turbine_t* turbine);

/*
 * Check if running
 */
bool sol_turbine_is_running(const sol_turbine_t* turbine);

/*
 * Run one iteration
 *
 * Receives and processes incoming shreds.
 */
sol_err_t sol_turbine_run_once(sol_turbine_t* turbine, uint32_t timeout_ms);

/*
 * Process a received shred
 *
 * Called when a shred is received from the network.
 * Validates, stores, and retransmits to children.
 */
sol_err_t sol_turbine_receive_shred(
    sol_turbine_t*      turbine,
    const uint8_t*      data,
    size_t              len,
    const sol_sockaddr_t* from
);

/*
 * Set slot completion callback
 */
void sol_turbine_set_slot_callback(
    sol_turbine_t*      turbine,
    sol_turbine_slot_cb callback,
    void*               ctx
);

/*
 * Set per-shred callback
 *
 * Invoked for each new shred received (duplicates are skipped).
 */
void sol_turbine_set_shred_callback(
    sol_turbine_t*          turbine,
    sol_turbine_shred_cb    callback,
    void*                   ctx
);

/*
 * Set batched shred callback
 *
 * When set, turbine may invoke this callback in place of the per-shred
 * callback for fast-ingress configurations.
 */
void sol_turbine_set_shred_batch_callback(
    sol_turbine_t*               turbine,
    sol_turbine_shred_batch_cb   callback,
    void*                        ctx
);

/*
 * Broadcast a shred from the leader to first-hop nodes
 */
sol_err_t sol_turbine_broadcast_shred(
    sol_turbine_t*      turbine,
    sol_slot_t          slot,
    const sol_pubkey_t* leader,
    const uint8_t*      data,
    size_t              len
);

/*
 * Get statistics
 */
void sol_turbine_stats(const sol_turbine_t* turbine, sol_turbine_stats_t* stats);

/*
 * Reset statistics
 */
void sol_turbine_stats_reset(sol_turbine_t* turbine);

/*
 * Build turbine tree for a slot
 *
 * Constructs the propagation tree using stake-weighted shuffling.
 * The seed ensures deterministic tree construction across all validators.
 */
sol_turbine_tree_t* sol_turbine_tree_new(
    sol_slot_t              slot,
    const sol_pubkey_t*     leader,
    const sol_turbine_node_t* nodes,
    size_t                  num_nodes,
    const sol_pubkey_t*     self_pubkey,
    uint32_t                fanout
);

/*
 * Destroy turbine tree
 */
void sol_turbine_tree_destroy(sol_turbine_tree_t* tree);

/*
 * Get parent node
 */
const sol_turbine_node_t* sol_turbine_tree_parent(
    const sol_turbine_tree_t* tree
);

/*
 * Get children nodes
 */
size_t sol_turbine_tree_children(
    const sol_turbine_tree_t* tree,
    const sol_turbine_node_t** children,
    size_t                   max_children
);

/*
 * Get tree depth for our node
 */
uint32_t sol_turbine_tree_depth(const sol_turbine_tree_t* tree);

/*
 * Check if we are a root node (direct child of leader)
 */
bool sol_turbine_tree_is_root(const sol_turbine_tree_t* tree);

/*
 * Create retransmit slot state
 */
sol_retransmit_slot_t* sol_retransmit_slot_new(sol_slot_t slot);

/*
 * Destroy retransmit slot state
 */
void sol_retransmit_slot_destroy(sol_retransmit_slot_t* slot_state);

/*
 * Record a received shred
 *
 * Returns true if this is a new shred, false if duplicate.
 */
bool sol_retransmit_slot_record(
    sol_retransmit_slot_t* slot_state,
    const sol_shred_t*     shred
);

/*
 * Check if slot is complete
 */
bool sol_retransmit_slot_is_complete(const sol_retransmit_slot_t* slot_state);

/*
 * Get missing shred indices for repair
 */
size_t sol_retransmit_slot_missing(
    const sol_retransmit_slot_t* slot_state,
    uint32_t*                   indices,
    size_t                      max_indices,
    bool                        data_shreds
);

/*
 * Weighted shuffle for tree construction
 *
 * Shuffles nodes based on stake weights using slot+leader as seed.
 * Higher stake nodes appear earlier in the shuffled order.
 */
void sol_turbine_weighted_shuffle(
    sol_turbine_node_t* nodes,
    size_t              num_nodes,
    sol_slot_t          slot,
    const sol_pubkey_t* leader
);

#endif /* SOL_TURBINE_H */
