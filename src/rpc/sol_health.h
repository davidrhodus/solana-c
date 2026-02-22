/*
 * sol_health.h - Health Check Endpoints
 *
 * Provides health check endpoints for monitoring and orchestration.
 * Supports liveness, readiness, and detailed health status.
 */

#ifndef SOL_HEALTH_H
#define SOL_HEALTH_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Health status
 */
typedef enum {
    SOL_HEALTH_OK,          /* Healthy */
    SOL_HEALTH_DEGRADED,    /* Partially healthy */
    SOL_HEALTH_UNHEALTHY,   /* Unhealthy */
} sol_health_status_t;

/*
 * Health check result
 */
typedef struct {
    sol_health_status_t status;
    const char*         message;

    /* Validator state */
    bool                is_syncing;
    bool                is_voting;
    bool                is_leader;
    bool                has_identity;

    /* Sync status */
    uint64_t            current_slot;
    uint64_t            highest_slot;
    uint64_t            slots_behind;

    /* Network status */
    uint32_t            connected_peers;
    uint32_t            rpc_connections;

    /* Resource status */
    uint64_t            memory_used_bytes;
    double              cpu_percent;

    /* Uptime */
    uint64_t            uptime_seconds;
} sol_health_result_t;

/*
 * Health check callback - called to get current validator state
 */
typedef sol_health_result_t (*sol_health_callback_t)(void* ctx);

/*
 * Health check configuration
 */
typedef struct {
    const char*             bind_addr;      /* Address to bind (default: 0.0.0.0) */
    uint16_t                port;           /* Port for health endpoints */
    sol_health_callback_t   callback;       /* Status callback */
    void*                   callback_ctx;   /* Context for callback */
    uint64_t                max_slot_lag;   /* Max slots behind before unhealthy (default: 100) */
    uint32_t                min_peers;      /* Min peers before unhealthy (default: 1) */
} sol_health_config_t;

#define SOL_HEALTH_CONFIG_DEFAULT { \
    .bind_addr = "0.0.0.0",         \
    .port = 8899,                    \
    .callback = NULL,                \
    .callback_ctx = NULL,            \
    .max_slot_lag = 100,             \
    .min_peers = 1,                  \
}

/*
 * Health server handle
 */
typedef struct sol_health_server sol_health_server_t;

/*
 * Create health server
 */
sol_health_server_t* sol_health_server_new(const sol_health_config_t* config);

/*
 * Destroy health server
 */
void sol_health_server_destroy(sol_health_server_t* server);

/*
 * Start health server
 */
sol_err_t sol_health_server_start(sol_health_server_t* server);

/*
 * Stop health server
 */
sol_err_t sol_health_server_stop(sol_health_server_t* server);

/*
 * Check if running
 */
bool sol_health_server_is_running(const sol_health_server_t* server);

/*
 * Get health status (for internal use or combined RPC server)
 */
sol_health_result_t sol_health_check(sol_health_server_t* server);

/*
 * Render health status as JSON
 *
 * @param result    Health check result
 * @param buf       Output buffer
 * @param buf_len   Buffer size
 * @return          Bytes written
 */
size_t sol_health_render_json(const sol_health_result_t* result, char* buf, size_t buf_len);

/*
 * Get health status name
 */
const char* sol_health_status_name(sol_health_status_t status);

/*
 * Endpoint paths (for integration with existing RPC server)
 */
#define SOL_HEALTH_PATH         "/health"
#define SOL_HEALTH_LIVE_PATH    "/health/live"
#define SOL_HEALTH_READY_PATH   "/health/ready"

#ifdef __cplusplus
}
#endif

#endif /* SOL_HEALTH_H */
