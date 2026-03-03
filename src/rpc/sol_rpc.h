/*
 * sol_rpc.h - JSON-RPC Server
 *
 * Implements Solana's JSON-RPC API for client interaction.
 */

#ifndef SOL_RPC_H
#define SOL_RPC_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../txn/sol_pubkey.h"
#include "../txn/sol_signature.h"
#include "../util/sol_json.h"
#include "../runtime/sol_bank.h"
#include "../replay/sol_bank_forks.h"

#include "sol_health.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct sol_leader_schedule sol_leader_schedule_t;

/*
 * RPC configuration
 */
typedef struct {
    char        bind_address[64];       /* Listen address */
    uint16_t    port;                   /* Listen port (HTTP JSON-RPC) */
    uint16_t    ws_port;                /* WebSocket port (0 to disable) */
    size_t      max_connections;        /* Max concurrent connections */
    size_t      request_timeout_ms;     /* Request timeout */
    bool        enable_health_check;    /* Enable health endpoint */
    bool        enable_rpc_full;        /* Enable full RPC (vs limited) */
    uint32_t    rate_limit_rps;         /* Requests/sec (0 to disable) */
    uint32_t    rate_limit_burst;       /* Burst size (0 = auto) */
} sol_rpc_config_t;

#define SOL_RPC_CONFIG_DEFAULT {                \
    .bind_address = "127.0.0.1",                \
    .port = 8899,                               \
    .ws_port = 8900,                            \
    .max_connections = 256,                     \
    .request_timeout_ms = 30000,                \
    .enable_health_check = true,                \
    .enable_rpc_full = true,                    \
    .rate_limit_rps = 0,                        \
    .rate_limit_burst = 0,                      \
}

/*
 * RPC error codes (JSON-RPC 2.0 standard + Solana extensions)
 */
typedef enum {
    SOL_RPC_ERR_PARSE_ERROR = -32700,
    SOL_RPC_ERR_INVALID_REQUEST = -32600,
    SOL_RPC_ERR_METHOD_NOT_FOUND = -32601,
    SOL_RPC_ERR_INVALID_PARAMS = -32602,
    SOL_RPC_ERR_INTERNAL_ERROR = -32603,

    /* Solana-specific errors */
    SOL_RPC_ERR_BLOCK_NOT_AVAILABLE = -32004,
    SOL_RPC_ERR_NODE_UNHEALTHY = -32005,
    SOL_RPC_ERR_TRANSACTION_PRECOMPILE_FAILURE = -32006,
    SOL_RPC_ERR_SLOT_SKIPPED = -32007,
    SOL_RPC_ERR_NO_SNAPSHOT = -32008,
    SOL_RPC_ERR_LONG_TERM_STORAGE_SLOT_SKIPPED = -32009,
    SOL_RPC_ERR_KEY_EXCLUDED_FROM_SECONDARY_INDEX = -32010,
    SOL_RPC_ERR_TRANSACTION_HISTORY_NOT_AVAILABLE = -32011,
    SOL_RPC_ERR_SCAN_ERROR = -32012,
    SOL_RPC_ERR_TRANSACTION_SIGNATURE_LEN_MISMATCH = -32013,
    SOL_RPC_ERR_BLOCK_STATUS_NOT_YET_AVAILABLE = -32014,
    SOL_RPC_ERR_UNSUPPORTED_TRANSACTION_VERSION = -32015,
    SOL_RPC_ERR_MIN_CONTEXT_SLOT_NOT_REACHED = -32016,
    SOL_RPC_ERR_RATE_LIMITED = -32020,
} sol_rpc_error_t;

/*
 * Commitment levels
 */
typedef enum {
    SOL_COMMITMENT_PROCESSED = 0,   /* Optimistic confirmation */
    SOL_COMMITMENT_CONFIRMED = 1,   /* 2/3 supermajority */
    SOL_COMMITMENT_FINALIZED = 2,   /* Max lockout reached */
} sol_commitment_t;

/*
 * Encoding formats
 */
typedef enum {
    SOL_ENCODING_BASE58 = 0,
    SOL_ENCODING_BASE64 = 1,
    SOL_ENCODING_BASE64_ZSTD = 2,
    SOL_ENCODING_JSON = 3,
    SOL_ENCODING_JSON_PARSED = 4,
} sol_encoding_t;

/*
 * Account info response
 */
typedef struct {
    uint64_t        lamports;
    sol_pubkey_t    owner;
    bool            executable;
    uint64_t        rent_epoch;
    uint8_t*        data;
    size_t          data_len;
} sol_rpc_account_info_t;

/*
 * Block response (simplified)
 */
typedef struct {
    sol_slot_t      slot;
    sol_hash_t      blockhash;
    sol_hash_t      previous_blockhash;
    sol_slot_t      parent_slot;
    uint64_t        block_time;
    uint64_t        block_height;
    size_t          transaction_count;
} sol_rpc_block_info_t;

/*
 * Transaction status response
 */
typedef struct {
    sol_signature_t signature;
    sol_slot_t      slot;
    sol_err_t       err;
    bool            confirmed;
} sol_rpc_tx_status_t;

/*
 * RPC stats
 */
typedef struct {
    uint64_t    requests_total;
    uint64_t    requests_success;
    uint64_t    requests_failed;
    uint64_t    bytes_received;
    uint64_t    bytes_sent;
    uint64_t    active_connections;
    uint64_t    ws_connections;
    uint64_t    ws_subscriptions;
} sol_rpc_stats_t;

/*
 * RPC backpressure drop counters (monotonic)
 */
typedef struct {
    uint64_t    dropped_total;
    uint64_t    dropped_get_program_accounts;
    uint64_t    dropped_get_token_accounts_by_owner;
    uint64_t    dropped_get_signatures_for_address;
    uint64_t    dropped_get_multiple_accounts;
    uint64_t    dropped_get_blocks;
    uint64_t    dropped_get_blocks_with_limit;
    uint64_t    dropped_get_block;
    uint64_t    dropped_get_transaction;
    uint64_t    dropped_simulate_transaction;
    uint64_t    dropped_other;
} sol_rpc_backpressure_stats_t;

/*
 * WebSocket subscription types
 */
typedef enum {
    SOL_WS_SUB_ACCOUNT = 0,         /* Account change notifications */
    SOL_WS_SUB_LOGS = 1,            /* Program log notifications */
    SOL_WS_SUB_PROGRAM = 2,         /* Program account notifications */
    SOL_WS_SUB_SIGNATURE = 3,       /* Transaction signature notifications */
    SOL_WS_SUB_SLOT = 4,            /* Slot notifications */
    SOL_WS_SUB_SLOTS_UPDATES = 5,   /* Slot update notifications */
    SOL_WS_SUB_ROOT = 6,            /* Root notifications */
    SOL_WS_SUB_BLOCK = 7,           /* Block notifications */
} sol_ws_subscription_type_t;

/*
 * Subscription callback
 */
typedef void (*sol_ws_notify_fn)(
    uint64_t            subscription_id,
    const uint8_t*      data,
    size_t              data_len,
    void*               user_data
);

/*
 * RPC server handle (opaque)
 */
typedef struct sol_rpc sol_rpc_t;

/*
 * Create RPC server
 *
 * @param bank_forks    Bank forks for state queries
 * @param config        Server configuration (NULL for defaults)
 * @return              RPC server or NULL on error
 */
sol_rpc_t* sol_rpc_new(
    sol_bank_forks_t*       bank_forks,
    const sol_rpc_config_t* config
);

/*
 * Destroy RPC server
 */
void sol_rpc_destroy(sol_rpc_t* rpc);

/*
 * Start RPC server (begins listening)
 */
sol_err_t sol_rpc_start(sol_rpc_t* rpc);

/*
 * Stop RPC server
 */
sol_err_t sol_rpc_stop(sol_rpc_t* rpc);

/*
 * Check if server is running
 */
bool sol_rpc_is_running(const sol_rpc_t* rpc);

/*
 * Get server stats
 */
sol_rpc_stats_t sol_rpc_stats(const sol_rpc_t* rpc);

/*
 * Get RPC backpressure drop counters.
 */
void sol_rpc_backpressure_stats(
    const sol_rpc_t*               rpc,
    sol_rpc_backpressure_stats_t*  stats
);

/*
 * Set bank forks for state queries.
 *
 * This can be called after the RPC server has started (e.g. when the validator
 * finishes snapshot loading and initializes BankForks).
 */
void sol_rpc_set_bank_forks(sol_rpc_t* rpc, sol_bank_forks_t* bank_forks);

/*
 * Set blockstore for block queries
 */
void sol_rpc_set_blockstore(sol_rpc_t* rpc, void* blockstore);

/*
 * Set gossip for cluster node queries
 */
void sol_rpc_set_gossip(sol_rpc_t* rpc, void* gossip);

/*
 * Set node identity pubkey
 */
void sol_rpc_set_identity(sol_rpc_t* rpc, const sol_pubkey_t* identity);

/*
 * Set leader schedule snapshot for RPC (deep-copied).
 */
void sol_rpc_set_leader_schedule(sol_rpc_t* rpc, const sol_leader_schedule_t* schedule);

/*
 * Set transaction sender callback
 */
typedef sol_err_t (*sol_rpc_send_tx_fn)(
    const sol_transaction_t* tx,
    void* user_data
);

void sol_rpc_set_send_transaction(
    sol_rpc_t*          rpc,
    sol_rpc_send_tx_fn  callback,
    void*               user_data
);

/*
 * Set health callback (used by /health endpoints and getHealth RPC method).
 *
 * When provided, the RPC server will answer /health, /health/live, and
 * /health/ready on the same HTTP port.
 */
void sol_rpc_set_health_callback(
    sol_rpc_t*              rpc,
    sol_health_callback_t   callback,
    void*                   callback_ctx
);

/*
 * Update global JSON-RPC rate limits at runtime.
 *
 * @param rate_limit_rps    Requests per second (0 disables rate limiting)
 * @param rate_limit_burst  Burst tokens (0 = auto/based on rps)
 */
void sol_rpc_set_rate_limit(
    sol_rpc_t*      rpc,
    uint32_t        rate_limit_rps,
    uint32_t        rate_limit_burst
);

/*
 * Update max concurrent HTTP connections at runtime.
 *
 * @param max_connections   Max active HTTP client connections (0 disables cap)
 */
void sol_rpc_set_max_connections(
    sol_rpc_t*  rpc,
    size_t      max_connections
);

/*
 * Set RPC backpressure mode (used for method-level load shedding).
 *
 * mode:
 *   0 = normal
 *   1 = high backlog
 *   2 = severe backlog
 */
void sol_rpc_set_backpressure_mode(
    sol_rpc_t*  rpc,
    uint8_t     mode
);

/*
 * WebSocket subscription notifications
 *
 * These functions notify subscribed clients of state changes.
 * Call these from the validator when relevant events occur.
 */

/*
 * Notify account change to subscribed clients
 */
void sol_rpc_notify_account(
    sol_rpc_t*              rpc,
    const sol_pubkey_t*     pubkey,
    const sol_account_t*    account,
    sol_slot_t              slot
);

/*
 * Notify slot change to subscribed clients
 */
void sol_rpc_notify_slot(
    sol_rpc_t*      rpc,
    sol_slot_t      slot,
    sol_slot_t      parent,
    const char*     status  /* "processed", "confirmed", "finalized" */
);

/*
 * Notify transaction signature status to subscribed clients
 */
void sol_rpc_notify_signature(
    sol_rpc_t*              rpc,
    const sol_signature_t*  signature,
    sol_slot_t              slot,
    sol_err_t               err
);

/*
 * Notify program logs to subscribed clients
 */
void sol_rpc_notify_logs(
    sol_rpc_t*              rpc,
    const sol_signature_t*  signature,
    const sol_pubkey_t*     program_id,
    const char* const*      logs,
    size_t                  logs_count,
    sol_err_t               err
);

/*
 * JSON helpers
 */

/* Simple JSON builder */
typedef struct sol_json_builder sol_json_builder_t;

sol_json_builder_t* sol_json_builder_new(size_t initial_capacity);
void sol_json_builder_destroy(sol_json_builder_t* builder);

void sol_json_builder_object_begin(sol_json_builder_t* builder);
void sol_json_builder_object_end(sol_json_builder_t* builder);
void sol_json_builder_array_begin(sol_json_builder_t* builder);
void sol_json_builder_array_end(sol_json_builder_t* builder);

void sol_json_builder_key(sol_json_builder_t* builder, const char* key);
void sol_json_builder_string(sol_json_builder_t* builder, const char* value);
void sol_json_builder_int(sol_json_builder_t* builder, int64_t value);
void sol_json_builder_uint(sol_json_builder_t* builder, uint64_t value);
void sol_json_builder_bool(sol_json_builder_t* builder, bool value);
void sol_json_builder_null(sol_json_builder_t* builder);

const char* sol_json_builder_str(sol_json_builder_t* builder);
size_t sol_json_builder_len(sol_json_builder_t* builder);

/*
 * Process a single JSON-RPC request body and write the JSON response.
 *
 * This is used by the HTTP server and is also helpful for unit testing.
 */
void sol_rpc_handle_request_json(
    sol_rpc_t*           rpc,
    const char*          request_json,
    size_t               request_len,
    sol_json_builder_t*  response
);

/* Simple JSON parser */
/* Provided by util/sol_json.h */

#endif /* SOL_RPC_H */
