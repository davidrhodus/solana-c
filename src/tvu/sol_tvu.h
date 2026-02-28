/*
 * sol_tvu.h - Transaction Validation Unit
 *
 * The TVU validates blocks received from the network:
 *
 * 1. Shred Fetch: Receives shreds via turbine/repair
 * 2. Shred Verify: Verifies shred signatures and FEC
 * 3. Block Assembly: Reconstructs blocks from shreds
 * 4. Replay: Replays blocks to update bank state
 * 5. Vote: Votes on valid blocks (Tower BFT)
 *
 * The TVU runs continuously to validate blocks from the leader.
 */

#ifndef SOL_TVU_H
#define SOL_TVU_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../shred/sol_shred.h"
#include "../blockstore/sol_blockstore.h"
#include "../replay/sol_replay.h"
#include "../turbine/sol_turbine.h"
#include "../repair/sol_repair.h"
#include <pthread.h>

/*
 * TVU ports (relative to base port)
 */
#define SOL_TVU_PORT_OFFSET             3
#define SOL_TVU_FORWARDS_PORT_OFFSET    4
#define SOL_TVU_REPAIR_PORT_OFFSET      5

/*
 * TVU configuration
 */
typedef struct {
    uint16_t    base_port;              /* Base port for TVU */
    uint32_t    max_shreds_per_slot;    /* Max shreds per slot */
    uint32_t    shred_verify_threads;   /* Shred verification threads */
    uint32_t    replay_threads;         /* Replay threads */
    uint32_t    repair_threads;         /* Repair threads */
    bool        enable_repair;          /* Enable repair requests */
    uint64_t    repair_timeout_ms;      /* Repair request timeout */
    bool        skip_shred_verify;      /* Skip shred signature verification (unsafe) */
} sol_tvu_config_t;

#define SOL_TVU_CONFIG_DEFAULT {            \
    .base_port = 8000,                      \
    .max_shreds_per_slot = 32768,           \
    .shred_verify_threads = 0,              \
    .replay_threads = 0,                    \
    .repair_threads = 0,                    \
    .enable_repair = true,                  \
    .repair_timeout_ms = 50,                \
    .skip_shred_verify = false,             \
}

/*
 * TVU statistics
 */
typedef struct {
    uint64_t    shreds_received;        /* Total shreds received */
    uint64_t    shreds_verified;        /* Shreds that passed verification */
    uint64_t    shreds_failed;          /* Shreds that failed verification */
    uint64_t    shreds_duplicate;       /* Duplicate shreds */
    uint64_t    blocks_completed;       /* Blocks fully assembled */
    uint64_t    blocks_replayed;        /* Blocks successfully replayed */
    uint64_t    blocks_failed;          /* Blocks that failed replay */
    uint64_t    repairs_requested;      /* Repair requests sent */
    uint64_t    repairs_received;       /* Repair responses received */
} sol_tvu_stats_t;

/*
 * Block completion callback
 */
typedef void (*sol_block_complete_callback_t)(
    void*               ctx,
    sol_slot_t          slot,
    const sol_hash_t*   blockhash,
    bool                success
);

/*
 * TVU handle
 */
typedef struct sol_tvu sol_tvu_t;

/*
 * Create TVU
 *
 * @param blockstore    Blockstore for shred storage
 * @param replay        Replay stage for block processing
 * @param turbine       Turbine for shred reception
 * @param repair        Repair service for missing shreds
 * @param config        Configuration (NULL for defaults)
 * @return              TVU or NULL on error
 */
sol_tvu_t* sol_tvu_new(
    sol_blockstore_t*           blockstore,
    sol_replay_t*               replay,
    sol_turbine_t*              turbine,
    sol_repair_t*               repair,
    const sol_tvu_config_t*     config
);

/*
 * Destroy TVU
 */
void sol_tvu_destroy(sol_tvu_t* tvu);

/*
 * Start TVU
 */
sol_err_t sol_tvu_start(sol_tvu_t* tvu);

/*
 * Stop TVU
 */
sol_err_t sol_tvu_stop(sol_tvu_t* tvu);

/*
 * Check if TVU is running
 */
bool sol_tvu_is_running(const sol_tvu_t* tvu);

/*
 * Process a received shred
 *
 * @param tvu           TVU handle
 * @param shred         Shred data
 * @param len           Shred length
 * @return              SOL_OK or error
 */
sol_err_t sol_tvu_process_shred(
    sol_tvu_t*          tvu,
    const uint8_t*      shred,
    size_t              len
);

/*
 * Process a batch of received shreds
 *
 * Used for high-throughput ingress paths to amortize locking and per-shred
 * overhead. Semantics match sol_tvu_process_shred() for each packet.
 */
sol_err_t sol_tvu_process_shreds_batch(
    sol_tvu_t*          tvu,
    const sol_udp_pkt_t* pkts,
    int                 count
);

/*
 * Request repair for a slot
 *
 * @param tvu           TVU handle
 * @param slot          Slot to repair
 * @return              SOL_OK or error
 */
sol_err_t sol_tvu_request_repair(
    sol_tvu_t*          tvu,
    sol_slot_t          slot
);

/*
 * Set block completion callback
 */
void sol_tvu_set_block_callback(
    sol_tvu_t*                      tvu,
    sol_block_complete_callback_t   callback,
    void*                           ctx
);

/*
 * Set leader schedule for shred signature verification
 */
struct sol_leader_schedule;
void sol_tvu_set_leader_schedule(
    sol_tvu_t*                      tvu,
    struct sol_leader_schedule*     schedule
);

/*
 * Atomically swap leader schedule (returns previous pointer).
 *
 * The TVU does not take ownership; the caller remains responsible for freeing
 * the returned schedule (if non-NULL) once it is no longer in use.
 */
struct sol_leader_schedule* sol_tvu_swap_leader_schedule(
    sol_tvu_t*                      tvu,
    struct sol_leader_schedule*     schedule
);

/*
 * Get TVU statistics
 */
sol_tvu_stats_t sol_tvu_stats(const sol_tvu_t* tvu);

/*
 * Reset statistics
 */
void sol_tvu_stats_reset(sol_tvu_t* tvu);

/*
 * Get slot status
 */
typedef enum {
    SOL_SLOT_STATUS_UNKNOWN,
    SOL_SLOT_STATUS_RECEIVING,
    SOL_SLOT_STATUS_COMPLETE,
    SOL_SLOT_STATUS_WAITING_PARENT,
    SOL_SLOT_STATUS_REPLAYING,
    SOL_SLOT_STATUS_REPLAYED,
    SOL_SLOT_STATUS_DEAD,
} sol_slot_status_t;

sol_slot_status_t sol_tvu_slot_status(
    const sol_tvu_t*    tvu,
    sol_slot_t          slot
);

/*
 * Get shred reception progress for a slot
 *
 * @param tvu           TVU handle
 * @param slot          Slot to check
 * @param out_received  Number of shreds received
 * @param out_expected  Expected total shreds
 * @return              SOL_OK or error
 */
sol_err_t sol_tvu_slot_progress(
    const sol_tvu_t*    tvu,
    sol_slot_t          slot,
    uint32_t*           out_received,
    uint32_t*           out_expected
);

#endif /* SOL_TVU_H */
