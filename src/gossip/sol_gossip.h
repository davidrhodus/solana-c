/*
 * sol_gossip.h - Gossip Service
 *
 * The gossip service maintains cluster membership and propagates
 * CRDS values across the network. It handles:
 *
 * - Peer discovery and management
 * - Push/Pull protocol for value propagation
 * - Ping/Pong for liveness checking
 * - Prune messages for protocol optimization
 */

#ifndef SOL_GOSSIP_H
#define SOL_GOSSIP_H

#include "sol_crds.h"
#include "sol_gossip_msg.h"
#include "../net/sol_udp.h"
#include "../crypto/sol_ed25519.h"

/*
 * Gossip configuration
 */
typedef struct {
    /* Identity */
    sol_keypair_t       identity;       /* Node's identity keypair */
    uint16_t            shred_version;  /* Expected shred version */

    /* Contact-info advertisement */
    const char*         advertise_ip;   /* Public IP to advertise (NULL = infer) */
    uint16_t            tpu_port;       /* TPU port to advertise (0 = omit) */
    uint16_t            tpu_quic_port;  /* TPU QUIC port to advertise (0 = omit) */
    uint16_t            tvu_port;       /* TVU (turbine) port to advertise (0 = omit) */
    uint16_t            serve_repair_port; /* Serve-repair port to advertise (0 = omit) */
    uint16_t            rpc_port;       /* RPC port to advertise (0 = omit) */

    /* Network */
    const char*         bind_ip;        /* IP to bind to (NULL = any) */
    uint16_t            gossip_port;    /* Gossip UDP port */

    /* Entrypoints (bootstrap nodes) */
    sol_sockaddr_t*     entrypoints;
    size_t              entrypoints_len;

    /* Tuning */
    size_t              max_peers;          /* Max tracked peers (default 1000) */
    uint32_t            push_fanout;        /* Nodes to push to (default 6) */
    uint32_t            pull_interval_ms;   /* Pull request interval (default 5000) */
    uint32_t            push_interval_ms;   /* Push interval (default 100) */
    uint32_t            ping_interval_ms;   /* Ping interval (default 1000) */
    uint32_t            prune_timeout_ms;   /* CRDS entry timeout (default 600000) */
} sol_gossip_config_t;

/*
 * Default configuration
 */
#define SOL_GOSSIP_CONFIG_DEFAULT {         \
    .identity = {{0}},                      \
    .shred_version = 0,                     \
    .advertise_ip = NULL,                   \
    .tpu_port = 0,                          \
    .tpu_quic_port = 0,                     \
    .tvu_port = 0,                          \
    .serve_repair_port = 0,                 \
    .rpc_port = 0,                          \
    .bind_ip = NULL,                        \
    .gossip_port = 8001,                    \
    .entrypoints = NULL,                    \
    .entrypoints_len = 0,                   \
    .max_peers = 1000,                      \
    .push_fanout = 6,                       \
    .pull_interval_ms = 5000,               \
    .push_interval_ms = 100,                \
    .ping_interval_ms = 1000,               \
    .prune_timeout_ms = 600000,             \
}

/*
 * Peer state
 */
typedef enum {
    SOL_PEER_STATE_UNKNOWN = 0,
    SOL_PEER_STATE_PENDING,     /* Sent ping, awaiting pong */
    SOL_PEER_STATE_ACTIVE,      /* Verified and active */
    SOL_PEER_STATE_FAILED,      /* Failed liveness check */
} sol_peer_state_t;

/*
 * Maximum pruned origins per peer
 */
#define SOL_MAX_PRUNED_ORIGINS 64

/*
 * Peer entry
 */
typedef struct {
    sol_pubkey_t        pubkey;
    sol_sockaddr_t      gossip_addr;
    sol_peer_state_t    state;
    uint64_t            last_seen;      /* Timestamp of last activity */
    uint64_t            last_ping;      /* Timestamp of last ping sent */
    sol_hash_t          ping_token;     /* Token from our last ping */
    uint32_t            ping_failures;  /* Consecutive ping failures */
    sol_pubkey_t        pruned_origins[SOL_MAX_PRUNED_ORIGINS];  /* Origins to not push */
    uint8_t             pruned_origins_len;
} sol_peer_t;

/*
 * Gossip statistics
 */
typedef struct {
    uint64_t    msgs_sent;
    uint64_t    msgs_received;
    uint64_t    bytes_sent;
    uint64_t    bytes_received;
    uint64_t    pings_sent;
    uint64_t    pongs_received;
    uint64_t    pushes_sent;
    uint64_t    pushes_received;
    uint64_t    pulls_sent;
    uint64_t    pulls_received;
    uint64_t    prunes_sent;
    uint64_t    prunes_received;
    uint64_t    invalid_msgs;
    uint64_t    active_peers;
} sol_gossip_stats_t;

/*
 * Gossip service handle
 */
typedef struct sol_gossip sol_gossip_t;

/*
 * Callback for new CRDS values
 */
typedef void (*sol_gossip_value_cb)(
    const sol_crds_value_t* value,
    void*                   ctx
);

/*
 * Create a new gossip service
 *
 * Returns NULL on failure.
 */
sol_gossip_t* sol_gossip_new(const sol_gossip_config_t* config);

/*
 * Destroy the gossip service
 */
void sol_gossip_destroy(sol_gossip_t* gossip);

/*
 * Start the gossip service
 *
 * Binds the UDP socket and begins processing messages.
 * Does NOT spawn a thread - caller must call sol_gossip_run().
 */
sol_err_t sol_gossip_start(sol_gossip_t* gossip);

/*
 * Stop the gossip service
 */
void sol_gossip_stop(sol_gossip_t* gossip);

/*
 * Check if service is running
 */
bool sol_gossip_is_running(const sol_gossip_t* gossip);

/*
 * Run one iteration of the gossip loop
 *
 * Processes incoming messages and performs periodic tasks.
 * Call this in a loop or from an event loop.
 *
 * Parameters:
 *   gossip - The gossip service
 *   timeout_ms - Max time to wait for messages (0 = non-blocking)
 *
 * Returns SOL_OK on success, SOL_ERR_SHUTDOWN if stopped.
 */
sol_err_t sol_gossip_run_once(sol_gossip_t* gossip, uint32_t timeout_ms);

/*
 * Run the gossip service (blocking)
 *
 * Runs until sol_gossip_stop() is called.
 */
sol_err_t sol_gossip_run(sol_gossip_t* gossip);

/*
 * Get our contact info
 */
const sol_contact_info_t* sol_gossip_self(const sol_gossip_t* gossip);

/*
 * Get our pubkey
 */
const sol_pubkey_t* sol_gossip_pubkey(const sol_gossip_t* gossip);

/*
 * Get the CRDS store
 */
sol_crds_t* sol_gossip_crds(sol_gossip_t* gossip);

/*
 * Push a value to the cluster
 *
 * The value will be signed and propagated to peers.
 */
sol_err_t sol_gossip_push_value(
    sol_gossip_t*           gossip,
    const sol_crds_value_t* value
);

/*
 * Get known peers
 *
 * Fills the array with active peers.
 * Returns number of peers written.
 */
size_t sol_gossip_get_peers(
    sol_gossip_t*   gossip,
    sol_peer_t*     peers,
    size_t          max_peers
);

/*
 * Get number of active peers
 */
size_t sol_gossip_num_peers(const sol_gossip_t* gossip);

/*
 * Get contact info for all known nodes
 */
size_t sol_gossip_get_cluster_nodes(
    sol_gossip_t*              gossip,
    const sol_contact_info_t** nodes,
    size_t                     max_nodes
);

/*
 * Get version info for a node
 */
const sol_crds_version_t* sol_gossip_get_version(
    sol_gossip_t*       gossip,
    const sol_pubkey_t* pubkey
);

/*
 * Set callback for new values
 */
void sol_gossip_set_value_callback(
    sol_gossip_t*        gossip,
    sol_gossip_value_cb  callback,
    void*                ctx
);

/*
 * Get statistics
 */
void sol_gossip_stats(const sol_gossip_t* gossip, sol_gossip_stats_t* stats);

/*
 * Reset statistics
 */
void sol_gossip_stats_reset(sol_gossip_t* gossip);

/*
 * Add an entrypoint
 */
sol_err_t sol_gossip_add_entrypoint(
    sol_gossip_t*         gossip,
    const sol_sockaddr_t* addr
);

/*
 * Manually trigger a pull request
 */
sol_err_t sol_gossip_pull(sol_gossip_t* gossip);

/*
 * Get current time in milliseconds
 */
uint64_t sol_gossip_now_ms(void);

#endif /* SOL_GOSSIP_H */
