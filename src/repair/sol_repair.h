/*
 * sol_repair.h - Shred Repair Protocol
 *
 * The repair protocol allows validators to request missing shreds from
 * peers when they don't receive them through the Turbine tree.
 *
 * Repair request types:
 * - Shred: Request a specific shred by (slot, index)
 * - HighestShred: Request the highest shred index for a slot
 * - Orphan: Request shreds for an orphaned slot
 * - AncestorHashes: Request ancestor hash chain
 */

#ifndef SOL_REPAIR_H
#define SOL_REPAIR_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../txn/sol_pubkey.h"
#include "../txn/sol_signature.h"
#include "../net/sol_udp.h"
#include "../gossip/sol_gossip.h"
#include "../shred/sol_shred.h"

/*
 * Repair constants
 */
#define SOL_REPAIR_MAX_REQUESTS     8192    /* Max concurrent requests */
#define SOL_REPAIR_REQUEST_TIMEOUT  1000    /* Request timeout in ms */
#define SOL_REPAIR_MAX_RESPONSE     64      /* Max shreds per response */

/*
 * Repair request types
 */
typedef enum {
    SOL_REPAIR_SHRED            = 0,    /* Request specific shred */
    SOL_REPAIR_HIGHEST_SHRED    = 1,    /* Request highest shred index */
    SOL_REPAIR_ORPHAN           = 2,    /* Request orphan slot shreds */
    SOL_REPAIR_ANCESTOR_HASHES  = 3,    /* Request ancestor hashes */
} sol_repair_type_t;

/*
 * Repair request header
 */
typedef struct {
    sol_signature_t signature;      /* Request signature */
    sol_pubkey_t    sender;         /* Sender's pubkey */
    sol_pubkey_t    recipient;      /* Recipient's pubkey */
    uint64_t        timestamp;      /* Request timestamp */
    uint32_t        nonce;          /* Random nonce */
} sol_repair_header_t;

/*
 * Shred repair request
 *
 * Request a specific shred by slot and index.
 */
typedef struct {
    sol_repair_header_t header;
    sol_slot_t          slot;
    uint64_t            shred_index;
} sol_repair_shred_request_t;

/*
 * Highest shred request
 *
 * Request the highest shred index for a slot.
 */
typedef struct {
    sol_repair_header_t header;
    sol_slot_t          slot;
} sol_repair_highest_request_t;

/*
 * Orphan repair request
 *
 * Request shreds for an orphaned slot (slot with no parent).
 */
typedef struct {
    sol_repair_header_t header;
    sol_slot_t          slot;
} sol_repair_orphan_request_t;

/*
 * Ancestor hashes request
 *
 * Request the ancestor hash chain for slot verification.
 */
typedef struct {
    sol_repair_header_t header;
    sol_slot_t          slot;
} sol_repair_ancestor_request_t;

/*
 * Maximum ancestor hashes in a response
 */
#define SOL_REPAIR_MAX_ANCESTOR_HASHES 256

/*
 * Ancestor hash entry
 */
typedef struct {
    sol_slot_t      slot;
    sol_hash_t      hash;
} sol_ancestor_hash_t;

/*
 * Ancestor hash validation result
 */
typedef enum {
    SOL_ANCESTOR_VALID = 0,             /* Chain is valid */
    SOL_ANCESTOR_INVALID_ORDER,         /* Slots not in descending order */
    SOL_ANCESTOR_INVALID_HASH,          /* Hash chain break detected */
    SOL_ANCESTOR_INCOMPLETE,            /* Chain doesn't reach expected root */
} sol_ancestor_validation_t;

/*
 * Ancestor hashes response
 */
typedef struct {
    sol_slot_t                  requested_slot;
    sol_ancestor_hash_t         ancestors[SOL_REPAIR_MAX_ANCESTOR_HASHES];
    uint16_t                    ancestors_len;
    sol_ancestor_validation_t   validation;     /* Validation result */
    bool                        validated;      /* Whether validation was performed */
} sol_repair_ancestor_response_t;

/*
 * Pending repair request
 */
typedef struct {
    sol_repair_type_t   type;
    sol_slot_t          slot;
    uint64_t            shred_index;    /* For shred requests */
    bool                is_data;        /* true=data shred, false=coding shred */
    sol_sockaddr_t      peer;           /* Peer we sent to */
    sol_pubkey_t        peer_pubkey;    /* Peer identity (recipient) */
    uint32_t            nonce;          /* Request nonce (echoed in responses) */
    uint64_t            sent_time;      /* When request was sent */
    uint32_t            retries;        /* Number of retries */
    /* Hedged repair sends (best-effort) are rate-limited to once per retry. */
    uint32_t            hedge_retry_mark; /* retries value when we last hedged */
    bool                active;
} sol_repair_pending_t;

/*
 * Repair statistics
 */
typedef struct {
    uint64_t    requests_sent;
    uint64_t    responses_received;
    uint64_t    shreds_repaired;
    uint64_t    timeouts;
    uint64_t    duplicates;
    uint64_t    invalid_responses;
} sol_repair_stats_t;

/*
 * Pending request summary for a specific slot (best-effort diagnostics)
 */
typedef struct {
    size_t      total;          /* Total pending entries matching slot */
    size_t      shreds;         /* Pending SHRED requests */
    size_t      highest;        /* Pending HIGHEST_SHRED requests */
    size_t      orphan;         /* Pending ORPHAN requests */
    size_t      ancestor_hashes;/* Pending ANCESTOR_HASHES requests */
    uint32_t    max_retries;    /* Max retries across matching entries */
    uint64_t    oldest_sent_ms; /* Oldest sent_time among matching entries */
    uint64_t    newest_sent_ms; /* Newest sent_time among matching entries */
} sol_repair_pending_slot_stats_t;

/*
 * Repair configuration
 */
typedef struct {
    uint32_t    request_timeout_ms;     /* Timeout for requests */
    uint32_t    max_pending_requests;   /* Max concurrent requests */
    uint32_t    max_retries;            /* Max retries per request */
    bool        serve_repairs;          /* Whether to serve repair requests */
} sol_repair_config_t;

#define SOL_REPAIR_CONFIG_DEFAULT {         \
    .request_timeout_ms = 200,              \
    .max_pending_requests = 8192,           \
    .max_retries = 7,                       \
    .serve_repairs = true,                  \
}

/*
 * Repair service handle
 */
typedef struct sol_repair sol_repair_t;

/*
 * Leader schedule (used to target repair requests at the slot leader).
 *
 * The repair service does not take ownership of the schedule pointer.
 */
struct sol_leader_schedule;

/*
 * Seed repair peers (serve-repair socket + identity) for bootstrap.
 *
 * This is a pragmatic fallback used when gossip CRDS contact-info is not yet
 * populated (or not interoperable), but we still want to begin requesting
 * shreds via repair. Requests are signed to the recipient pubkey.
 */
typedef struct {
    sol_pubkey_t    pubkey;
    sol_sockaddr_t  serve_repair_addr;
} sol_repair_seed_peer_t;

/*
 * Callback for repaired shreds
 */
typedef void (*sol_repair_shred_cb)(
    const sol_shred_t*  shred,
    void*               ctx
);

/*
 * Callback for ancestor hash responses
 */
typedef void (*sol_repair_ancestor_cb)(
    const sol_repair_ancestor_response_t*   response,
    void*                                   ctx
);

/*
 * Create repair service
 */
sol_repair_t* sol_repair_new(
    const sol_repair_config_t* config,
    sol_gossip_t*              gossip,
    const sol_keypair_t*       identity
);

/*
 * Destroy repair service
 */
void sol_repair_destroy(sol_repair_t* repair);

/*
 * Start repair service
 */
sol_err_t sol_repair_start(sol_repair_t* repair, uint16_t port);

/*
 * Stop repair service
 */
void sol_repair_stop(sol_repair_t* repair);

/*
 * Check if running
 */
bool sol_repair_is_running(const sol_repair_t* repair);

/*
 * Run one iteration
 */
sol_err_t sol_repair_run_once(sol_repair_t* repair, uint32_t timeout_ms);

/*
 * Get local address of the repair socket (for responses).
 */
sol_err_t sol_repair_local_addr(const sol_repair_t* repair, sol_sockaddr_t* addr);

/*
 * Set/Swap leader schedule.
 *
 * When set, repair peer selection will prefer the slot leader's serve-repair
 * socket (when present in gossip CRDS) to reduce timeouts during catchup.
 */
void sol_repair_set_leader_schedule(
    sol_repair_t*                   repair,
    struct sol_leader_schedule*     schedule
);

struct sol_leader_schedule* sol_repair_swap_leader_schedule(
    sol_repair_t*                   repair,
    struct sol_leader_schedule*     schedule
);

/*
 * Request a specific shred
 */
sol_err_t sol_repair_request_shred(
    sol_repair_t*   repair,
    sol_slot_t      slot,
    uint64_t        shred_index,
    bool            is_data
);

/*
 * Request a specific shred, with optional fanout (hedged requests).
 *
 * `fanout` includes the primary request. When `fanout` > 1, additional copies
 * of the request are sent to other peers (best-effort) using the same nonce to
 * reduce tail latency when we're missing only a few shreds on the critical
 * catchup slot.
 */
sol_err_t sol_repair_request_shred_fanout(
    sol_repair_t*   repair,
    sol_slot_t      slot,
    uint64_t        shred_index,
    bool            is_data,
    uint32_t        fanout
);

/*
 * Request highest shred for slot at or above shred_index
 */
sol_err_t sol_repair_request_highest(
    sol_repair_t*   repair,
    sol_slot_t      slot,
    uint64_t        shred_index
);

/*
 * Request highest shred for slot at or above shred_index, with optional fanout
 * (hedged requests).
 *
 * `fanout` includes the primary request. When `fanout` > 1, additional copies
 * of the request are sent to other peers (best-effort) using the same nonce to
 * reduce tail latency for catchup.
 */
sol_err_t sol_repair_request_highest_fanout(
    sol_repair_t*   repair,
    sol_slot_t      slot,
    uint64_t        shred_index,
    uint32_t        fanout
);

/*
 * Request orphan slot repair
 */
sol_err_t sol_repair_request_orphan(
    sol_repair_t*   repair,
    sol_slot_t      slot
);

/*
 * Request ancestor hashes for a slot
 *
 * Returns the hash chain from the requested slot back to a recent root.
 * Used to verify slot ancestry and detect forks.
 */
sol_err_t sol_repair_request_ancestor_hashes(
    sol_repair_t*   repair,
    sol_slot_t      slot
);

/*
 * Set seed peers to use when gossip does not provide suitable contact-info.
 *
 * The repair module copies the list; callers can free their buffer after.
 */
sol_err_t sol_repair_set_seed_peers(
    sol_repair_t*                 repair,
    const sol_repair_seed_peer_t* peers,
    size_t                        peers_len
);

/*
 * Set shred callback
 */
void sol_repair_set_shred_callback(
    sol_repair_t*       repair,
    sol_repair_shred_cb callback,
    void*               ctx
);

/*
 * Set ancestor hash callback
 */
void sol_repair_set_ancestor_callback(
    sol_repair_t*           repair,
    sol_repair_ancestor_cb  callback,
    void*                   ctx
);

/*
 * Get statistics
 */
void sol_repair_stats(const sol_repair_t* repair, sol_repair_stats_t* stats);

/*
 * Reset statistics
 */
void sol_repair_stats_reset(sol_repair_t* repair);

/*
 * Get number of active pending requests.
 */
size_t sol_repair_pending_count(sol_repair_t* repair);

/*
 * Summarize pending requests for a given slot.
 *
 * This is intended for debugging / stats and is O(max_pending_requests).
 */
bool sol_repair_pending_slot_stats(sol_repair_t* repair,
                                  sol_slot_t slot,
                                  sol_repair_pending_slot_stats_t* out);

/*
 * Get configured maximum number of pending requests.
 */
size_t sol_repair_max_pending(const sol_repair_t* repair);

/*
 * Set blockstore for serving repair requests
 *
 * @param repair      Repair service
 * @param blockstore  Blockstore for serving shreds (can be NULL to disable)
 */
void sol_repair_set_blockstore(sol_repair_t* repair, void* blockstore);

/*
 * Get repair request type name
 */
static inline const char*
sol_repair_type_name(sol_repair_type_t type) {
    switch (type) {
    case SOL_REPAIR_SHRED:           return "Shred";
    case SOL_REPAIR_HIGHEST_SHRED:   return "HighestShred";
    case SOL_REPAIR_ORPHAN:          return "Orphan";
    case SOL_REPAIR_ANCESTOR_HASHES: return "AncestorHashes";
    default:                         return "Unknown";
    }
}

#endif /* SOL_REPAIR_H */
