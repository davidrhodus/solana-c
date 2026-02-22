/*
 * sol_prometheus.h - Prometheus Metrics Exporter
 *
 * Exposes validator metrics in Prometheus format for monitoring.
 * Supports counters, gauges, and histograms.
 *
 * Usage:
 *   1. Initialize with sol_prometheus_init()
 *   2. Register metrics with sol_metric_*_register()
 *   3. Update metrics with sol_metric_*_set/inc/observe()
 *   4. Expose via HTTP endpoint /metrics
 */

#ifndef SOL_PROMETHEUS_H
#define SOL_PROMETHEUS_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Metric types
 */
typedef enum {
    SOL_METRIC_COUNTER,     /* Monotonically increasing counter */
    SOL_METRIC_GAUGE,       /* Value that can go up or down */
    SOL_METRIC_HISTOGRAM,   /* Distribution of values */
} sol_metric_type_t;

/*
 * Metric handle
 */
typedef struct sol_metric sol_metric_t;

/*
 * Prometheus exporter handle
 */
typedef struct sol_prometheus sol_prometheus_t;

/*
 * Histogram bucket configuration
 */
typedef struct {
    double*     boundaries;     /* Upper boundaries for buckets */
    size_t      count;          /* Number of buckets */
} sol_histogram_buckets_t;

/*
 * Default histogram buckets for latency (milliseconds)
 */
#define SOL_HISTOGRAM_LATENCY_BUCKETS \
    (sol_histogram_buckets_t){ \
        .boundaries = (double[]){0.1, 0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000}, \
        .count = 12 \
    }

/*
 * Default histogram buckets for sizes (bytes)
 */
#define SOL_HISTOGRAM_SIZE_BUCKETS \
    (sol_histogram_buckets_t){ \
        .boundaries = (double[]){64, 256, 1024, 4096, 16384, 65536, 262144, 1048576}, \
        .count = 8 \
    }

/*
 * Prometheus configuration
 */
typedef struct {
    const char*     bind_addr;      /* Address to bind (default: 0.0.0.0) */
    uint16_t        port;           /* Port for /metrics endpoint */
    const char*     path;           /* Path (default: /metrics) */
    bool            include_help;   /* Include HELP comments */
    bool            include_type;   /* Include TYPE comments */
} sol_prometheus_config_t;

#define SOL_PROMETHEUS_CONFIG_DEFAULT { \
    .bind_addr = "0.0.0.0",             \
    .port = 9090,                        \
    .path = "/metrics",                  \
    .include_help = true,                \
    .include_type = true,                \
}

/*
 * Lifecycle
 */

/*
 * Create Prometheus exporter
 */
sol_prometheus_t* sol_prometheus_new(const sol_prometheus_config_t* config);

/*
 * Destroy Prometheus exporter
 */
void sol_prometheus_destroy(sol_prometheus_t* prom);

/*
 * Start HTTP server for metrics endpoint
 */
sol_err_t sol_prometheus_start(sol_prometheus_t* prom);

/*
 * Stop HTTP server
 */
sol_err_t sol_prometheus_stop(sol_prometheus_t* prom);

/*
 * Check if running
 */
bool sol_prometheus_is_running(const sol_prometheus_t* prom);

/*
 * Metric Registration
 */

/*
 * Register a counter metric
 *
 * @param prom      Prometheus exporter
 * @param name      Metric name (e.g., "solana_transactions_total")
 * @param help      Help text describing the metric
 * @param labels    Label names (NULL-terminated array, or NULL for no labels)
 * @return          Metric handle or NULL on error
 */
sol_metric_t* sol_metric_counter_register(
    sol_prometheus_t*   prom,
    const char*         name,
    const char*         help,
    const char* const*  labels
);

/*
 * Register a gauge metric
 */
sol_metric_t* sol_metric_gauge_register(
    sol_prometheus_t*   prom,
    const char*         name,
    const char*         help,
    const char* const*  labels
);

/*
 * Register a histogram metric
 */
sol_metric_t* sol_metric_histogram_register(
    sol_prometheus_t*           prom,
    const char*                 name,
    const char*                 help,
    const char* const*          labels,
    const sol_histogram_buckets_t* buckets
);

/*
 * Metric Operations - Counters
 */

/*
 * Increment counter by 1
 */
void sol_metric_counter_inc(sol_metric_t* metric, const char* const* label_values);

/*
 * Add value to counter
 */
void sol_metric_counter_add(sol_metric_t* metric, double value, const char* const* label_values);

/*
 * Metric Operations - Gauges
 */

/*
 * Set gauge value
 */
void sol_metric_gauge_set(sol_metric_t* metric, double value, const char* const* label_values);

/*
 * Increment gauge by 1
 */
void sol_metric_gauge_inc(sol_metric_t* metric, const char* const* label_values);

/*
 * Decrement gauge by 1
 */
void sol_metric_gauge_dec(sol_metric_t* metric, const char* const* label_values);

/*
 * Add to gauge (can be negative)
 */
void sol_metric_gauge_add(sol_metric_t* metric, double value, const char* const* label_values);

/*
 * Metric Operations - Histograms
 */

/*
 * Observe a value in histogram
 */
void sol_metric_histogram_observe(sol_metric_t* metric, double value, const char* const* label_values);

/*
 * Output
 */

/*
 * Generate metrics output in Prometheus format
 *
 * @param prom      Prometheus exporter
 * @param buf       Output buffer
 * @param buf_len   Buffer capacity
 * @return          Bytes written (excluding null terminator)
 */
size_t sol_prometheus_render(
    sol_prometheus_t*   prom,
    char*               buf,
    size_t              buf_len
);

/*
 * Get metrics as newly allocated string
 *
 * Caller must free the returned string.
 */
char* sol_prometheus_render_alloc(sol_prometheus_t* prom);

/*
 * Convenience macros for common Solana validator metrics
 */

/* Slot metrics */
#define SOL_METRIC_SLOT_HEIGHT          "solana_slot_height"
#define SOL_METRIC_SLOT_LEADER          "solana_slot_leader"
#define SOL_METRIC_SLOT_PROCESSED       "solana_slots_processed_total"
#define SOL_METRIC_SLOT_SKIPPED         "solana_slots_skipped_total"

/* Epoch metrics */
#define SOL_METRIC_EPOCH                "solana_epoch"
#define SOL_METRIC_EPOCH_FIRST_SLOT     "solana_epoch_first_slot"

/* Transaction metrics */
#define SOL_METRIC_TXN_RECEIVED         "solana_transactions_received_total"
#define SOL_METRIC_TXN_PROCESSED        "solana_transactions_processed_total"
#define SOL_METRIC_TXN_SUCCESS          "solana_transactions_success_total"
#define SOL_METRIC_TXN_FAILED           "solana_transactions_failed_total"
#define SOL_METRIC_TXN_LATENCY          "solana_transaction_latency_ms"

/* Vote metrics */
#define SOL_METRIC_VOTES_SUBMITTED      "solana_votes_submitted_total"
#define SOL_METRIC_VOTE_CREDITS         "solana_vote_credits"
#define SOL_METRIC_VOTE_CREDITS_EPOCH   "solana_vote_credits_epoch"

/* Stake metrics */
#define SOL_METRIC_ACTIVE_STAKE         "solana_active_stake_lamports"
#define SOL_METRIC_DELINQUENT           "solana_validator_delinquent"

/* Network metrics */
#define SOL_METRIC_PEERS_CONNECTED      "solana_peers_connected"
#define SOL_METRIC_GOSSIP_PUSH_COUNT    "solana_gossip_push_total"
#define SOL_METRIC_GOSSIP_PULL_COUNT    "solana_gossip_pull_total"

/* Replay metrics */
#define SOL_METRIC_REPLAY_SLOT          "solana_replay_slot"
#define SOL_METRIC_REPLAY_FORKS         "solana_replay_forks_active"

/* TPU/TVU metrics */
#define SOL_METRIC_TPU_PACKETS          "solana_tpu_packets_received_total"
#define SOL_METRIC_TPU_DROPPED          "solana_tpu_packets_dropped_total"
#define SOL_METRIC_TVU_SHREDS           "solana_tvu_shreds_received_total"

/* Resource metrics */
#define SOL_METRIC_MEMORY_USED          "solana_memory_used_bytes"
#define SOL_METRIC_ACCOUNTS_COUNT       "solana_accounts_count"
#define SOL_METRIC_BLOCKSTORE_SIZE      "solana_blockstore_size_bytes"

#ifdef __cplusplus
}
#endif

#endif /* SOL_PROMETHEUS_H */
