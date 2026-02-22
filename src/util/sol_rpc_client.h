/*
 * sol_rpc_client.h - Minimal RPC client helpers
 *
 * Used for one-off bootstrap queries (e.g., discovering shred version)
 * without pulling in a full HTTP client dependency.
 *
 * Implementation uses the `curl` binary (same approach as snapshot download).
 */

#ifndef SOL_RPC_CLIENT_H
#define SOL_RPC_CLIENT_H

#include "sol_err.h"
#include "sol_types.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Parse Solana JSON-RPC getClusterNodes response and extract the first
 * `shredVersion` observed.
 *
 * Returns SOL_OK and writes to out_shred_version on success.
 */
sol_err_t sol_rpc_parse_cluster_nodes_shred_version(
    const char* json,
    size_t      json_len,
    uint16_t*   out_shred_version
);

/*
 * Query getClusterNodes on an RPC endpoint and return the current shred version.
 *
 * This is intended for validator bootstrapping when shred_version is not
 * configured explicitly.
 */
sol_err_t sol_rpc_get_cluster_shred_version(
    const char* rpc_url,
    uint32_t    timeout_secs,
    uint16_t*   out_shred_version
);

/*
 * Query getClusterNodes on an RPC endpoint and return the raw JSON response.
 *
 * Caller must free `*out_json` with sol_free().
 */
sol_err_t sol_rpc_get_cluster_nodes_json(
    const char* rpc_url,
    uint32_t    timeout_secs,
    char**      out_json,
    size_t*     out_json_len
);

/*
 * Parse Solana JSON-RPC getGenesisHash response and extract the base58 string.
 *
 * This function does not decode base58; callers can use sol_pubkey_from_base58.
 */
sol_err_t sol_rpc_parse_genesis_hash_base58(
    const char* json,
    size_t      json_len,
    char*       out,
    size_t      out_len
);

/*
 * Query getGenesisHash on an RPC endpoint and return the base58 string.
 */
sol_err_t sol_rpc_get_genesis_hash_base58(
    const char* rpc_url,
    uint32_t    timeout_secs,
    char*       out,
    size_t      out_len
);

/*
 * Query getSlotLeaders on an RPC endpoint and return the leader identity for
 * a contiguous range of slots.
 *
 * Caller must free `*out_leaders` with sol_free().
 */
sol_err_t sol_rpc_get_slot_leaders(
    const char*     rpc_url,
    uint32_t        timeout_secs,
    uint64_t        start_slot,
    uint64_t        limit,
    sol_pubkey_t**  out_leaders,
    size_t*         out_leaders_len
);

#ifdef __cplusplus
}
#endif

#endif /* SOL_RPC_CLIENT_H */
