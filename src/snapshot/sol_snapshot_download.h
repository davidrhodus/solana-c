/*
 * sol_snapshot_download.h - Snapshot Download
 *
 * Enables downloading snapshot archives for fast sync.
 *
 * Features:
 * - Query available snapshots from RPC nodes
 * - Query available snapshots from snapshot services (manifest JSON)
 * - Download full and incremental snapshots
 * - Resume interrupted downloads
 * - Progress reporting
 */

#ifndef SOL_SNAPSHOT_DOWNLOAD_H
#define SOL_SNAPSHOT_DOWNLOAD_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "sol_snapshot.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Download progress callback
 *
 * @param ctx               User context
 * @param bytes_downloaded  Bytes downloaded so far
 * @param total_bytes       Total bytes to download
 * @param speed_bps         Current download speed in bytes/sec
 */
typedef void (*sol_download_progress_fn)(
    void*       ctx,
    uint64_t    bytes_downloaded,
    uint64_t    total_bytes,
    uint64_t    speed_bps
);

/*
 * Snapshot source (RPC node)
 */
typedef struct {
    char*           url;            /* RPC URL (e.g., "http://api.mainnet-beta.solana.com") */
    sol_pubkey_t    identity;       /* Node identity (optional, for known_validators) */
    bool            trusted;        /* Is this a trusted/known validator? */
} sol_snapshot_source_t;

/*
 * Available snapshot info from RPC
 */
typedef struct {
    sol_slot_t              base_slot;      /* Incremental base slot (0 for full) */
    sol_slot_t              slot;
    sol_hash_t              hash;
    sol_snapshot_type_t     type;
    uint64_t                size;           /* Archive size in bytes */
    char*                   url;            /* Direct download URL */
    sol_pubkey_t            source_node;    /* Node providing this snapshot */
} sol_available_snapshot_t;

/*
 * Snapshot download options
 */
typedef struct {
    const char*             output_dir;         /* Directory to save snapshot */
    sol_download_progress_fn progress_callback; /* Progress callback */
    void*                   progress_ctx;       /* Callback context */
    uint64_t                max_size;           /* Max snapshot size to download (0=unlimited) */
    uint32_t                timeout_secs;       /* Download timeout (0=default) */
    uint32_t                parallel_connections; /* Max in-flight HTTP range requests (>=2 enables) */
    uint64_t                parallel_min_size;  /* Only parallelize when size >= this (0=always if known) */
    bool                    allow_incremental;  /* Allow incremental snapshots */
    bool                    verify_after;       /* Verify after download */
    bool                    resume;             /* Resume partial downloads */
} sol_snapshot_download_opts_t;

/* Hard upper bound on parallel range downloads. This is intentionally kept
 * conservative because the current implementation spawns one `curl` process per
 * in-flight range request. The downloader may split large files into more parts
 * and schedule them across these connections. */
#define SOL_SNAPSHOT_DOWNLOAD_MAX_PARALLEL_CONNECTIONS (128U)

#define SOL_SNAPSHOT_DOWNLOAD_OPTS_DEFAULT {    \
    .output_dir = NULL,                         \
    .progress_callback = NULL,                  \
    .progress_ctx = NULL,                       \
    .max_size = 0,                              \
    .timeout_secs = 0,                          \
    .parallel_connections = 64,                 \
    .parallel_min_size = 256ULL * 1024ULL * 1024ULL, \
    .allow_incremental = true,                  \
    .verify_after = true,                       \
    .resume = true,                             \
}

/*
 * Query available snapshots from an RPC node
 *
 * @param rpc_url       RPC endpoint URL
 * @param out_snapshots Output array of available snapshots
 * @param max_count     Maximum snapshots to return
 * @return              Number of snapshots found, or 0 on error
 */
size_t sol_snapshot_query_available(
    const char*                 rpc_url,
    sol_available_snapshot_t*   out_snapshots,
    size_t                      max_count
);

/*
 * Query available snapshots from a snapshot service manifest.
 *
 * This is a common deployment pattern for "snapshot services" that publish a
 * JSON manifest containing the latest full snapshot and a list of incremental
 * snapshots. Example manifest: https://data.pipedev.network/snapshot-manifest.json
 *
 * @param manifest_url   URL to manifest JSON
 * @param out_snapshots  Output array of available snapshots
 * @param max_count      Maximum snapshots to return
 * @return               Number of snapshots found, or 0 on error
 */
size_t sol_snapshot_service_query_available(
    const char*                 manifest_url,
    sol_available_snapshot_t*   out_snapshots,
    size_t                      max_count
);

/*
 * Parse snapshot service manifest JSON (no network).
 *
 * @param manifest_url   URL the manifest was fetched from (used to resolve relative filenames)
 * @param json           Manifest JSON buffer
 * @param json_len       Length of JSON buffer
 * @param out_snapshots  Output array of available snapshots
 * @param max_count      Maximum snapshots to return
 * @return               Number of snapshots found, or 0 on error
 */
size_t sol_snapshot_service_parse_manifest_json(
    const char*                 manifest_url,
    const char*                 json,
    size_t                      json_len,
    sol_available_snapshot_t*   out_snapshots,
    size_t                      max_count
);

/*
 * Find best snapshots from a snapshot service manifest.
 *
 * Selects:
 * - The advertised full snapshot
 * - The highest-slot incremental snapshot whose base_slot matches the full slot
 *   (if opts->allow_incremental is true)
 *
 * @param manifest_url       URL to manifest JSON
 * @param opts               Download options (optional)
 * @param out_full           Output full snapshot (required)
 * @param out_incremental    Output incremental snapshot (optional; may remain zeroed)
 * @return                   SOL_OK if full snapshot found
 */
sol_err_t sol_snapshot_service_find_best_download(
    const char*                     manifest_url,
    const sol_snapshot_download_opts_t* opts,
    sol_available_snapshot_t*       out_full,
    sol_available_snapshot_t*       out_incremental
);

/*
 * Find best snapshots from a snapshot service manifest JSON (no network).
 *
 * @param manifest_url       URL the manifest was fetched from (used to resolve relative filenames)
 * @param json               Manifest JSON buffer
 * @param json_len           Length of JSON buffer
 * @param opts               Download options (optional)
 * @param out_full           Output full snapshot (required)
 * @param out_incremental    Output incremental snapshot (optional; may remain zeroed)
 * @return                   SOL_OK if full snapshot found
 */
sol_err_t sol_snapshot_service_find_best_from_manifest_json(
    const char*                     manifest_url,
    const char*                     json,
    size_t                          json_len,
    const sol_snapshot_download_opts_t* opts,
    sol_available_snapshot_t*       out_full,
    sol_available_snapshot_t*       out_incremental
);

/*
 * Find the best snapshot to download
 *
 * Queries multiple RPC nodes and selects the best snapshot based on:
 * - Most recent slot
 * - From trusted/known validator (if configured)
 * - Reasonable size
 *
 * @param sources           Array of RPC sources to query
 * @param source_count      Number of sources
 * @param known_validators  Array of trusted validator pubkeys (optional)
 * @param known_count       Number of known validators
 * @param out_snapshot      Output best snapshot info
 * @return                  SOL_OK if found
 */
sol_err_t sol_snapshot_find_best_download(
    const sol_snapshot_source_t*    sources,
    size_t                          source_count,
    const sol_pubkey_t*             known_validators,
    size_t                          known_count,
    sol_available_snapshot_t*       out_snapshot
);

/*
 * Download a snapshot
 *
 * @param snapshot      Snapshot to download
 * @param opts          Download options
 * @param out_path      Output path to downloaded file
 * @param max_path_len  Path buffer size
 * @return              SOL_OK on success
 */
sol_err_t sol_snapshot_download(
    const sol_available_snapshot_t* snapshot,
    const sol_snapshot_download_opts_t* opts,
    char*                           out_path,
    size_t                          max_path_len
);

/*
 * Calculate effective parallel download parameters.
 *
 * This clamps overly-large requested parallelism to
 * SOL_SNAPSHOT_DOWNLOAD_MAX_PARALLEL_CONNECTIONS and ensures we never create
 * more parts than remaining bytes.
 */
sol_err_t sol_snapshot_download_calc_parallel_params(
    uint64_t    total_size,
    uint64_t    start_offset,
    uint32_t    requested_connections,
    uint32_t*   out_parts,
    uint32_t*   out_inflight_max
);

/*
 * Download and extract snapshot in one operation
 *
 * @param snapshot      Snapshot to download
 * @param opts          Download options
 * @param extract_dir   Directory to extract to
 * @return              SOL_OK on success
 */
sol_err_t sol_snapshot_download_and_extract(
    const sol_available_snapshot_t* snapshot,
    const sol_snapshot_download_opts_t* opts,
    const char*                     extract_dir
);

/*
 * Free available snapshot info
 */
void sol_available_snapshot_free(sol_available_snapshot_t* snapshot);

/*
 * Free array of available snapshots
 */
void sol_available_snapshots_free(sol_available_snapshot_t* snapshots, size_t count);

/*
 * Default RPC endpoints for each network
 */

#define SOL_MAINNET_RPC     "https://api.mainnet-beta.solana.com"
#define SOL_TESTNET_RPC     "https://api.testnet.solana.com"
#define SOL_DEVNET_RPC      "https://api.devnet.solana.com"

/* Default snapshot service manifest (mainnet) */
#define SOL_MAINNET_SNAPSHOT_MANIFEST_URL "https://data.pipedev.network/snapshot-manifest.json"

/*
 * Get default entrypoints for a network
 *
 * @param network       "mainnet", "testnet", or "devnet"
 * @param out_sources   Output array of sources
 * @param max_count     Maximum sources to return
 * @return              Number of sources
 */
size_t sol_snapshot_get_default_sources(
    const char*             network,
    sol_snapshot_source_t*  out_sources,
    size_t                  max_count
);

#ifdef __cplusplus
}
#endif

#endif /* SOL_SNAPSHOT_DOWNLOAD_H */
