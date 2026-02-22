/*
 * sol_config.h - Configuration File Parser
 *
 * Simple TOML-like configuration file parser for validator settings.
 * Supports sections, key-value pairs, strings, integers, booleans, and arrays.
 */

#ifndef SOL_CONFIG_H
#define SOL_CONFIG_H

#include "sol_types.h"
#include "sol_err.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Configuration value types
 */
typedef enum {
    SOL_CONFIG_STRING,
    SOL_CONFIG_INT,
    SOL_CONFIG_BOOL,
    SOL_CONFIG_FLOAT,
    SOL_CONFIG_ARRAY,
} sol_config_type_t;

/*
 * Configuration value
 */
typedef struct sol_config_value {
    sol_config_type_t   type;
    union {
        char*           string;
        int64_t         integer;
        bool            boolean;
        double          floating;
        struct {
            struct sol_config_value* items;
            size_t          count;
        } array;
    } data;
} sol_config_value_t;

/*
 * Configuration entry (key-value pair)
 */
typedef struct {
    char*               key;
    sol_config_value_t  value;
} sol_config_entry_t;

/*
 * Configuration section
 */
typedef struct {
    char*               name;
    sol_config_entry_t* entries;
    size_t              num_entries;
    size_t              capacity;
} sol_config_section_t;

/*
 * Configuration handle
 */
typedef struct {
    sol_config_section_t*   sections;
    size_t                  num_sections;
    size_t                  capacity;
    char*                   error_msg;
    int                     error_line;
} sol_config_t;

/*
 * Create empty configuration
 */
sol_config_t* sol_config_new(void);

/*
 * Destroy configuration
 */
void sol_config_destroy(sol_config_t* config);

/*
 * Parse configuration from file
 *
 * @param path      Path to configuration file
 * @param config    Output configuration
 * @return          SOL_OK on success, error code on failure
 */
sol_err_t sol_config_load(const char* path, sol_config_t** config);

/*
 * Parse configuration from string
 *
 * @param content   Configuration content
 * @param len       Content length (0 for null-terminated)
 * @param config    Output configuration
 * @return          SOL_OK on success, error code on failure
 */
sol_err_t sol_config_parse(const char* content, size_t len, sol_config_t** config);

/*
 * Get parse error message
 */
const char* sol_config_error(const sol_config_t* config);

/*
 * Get parse error line number
 */
int sol_config_error_line(const sol_config_t* config);

/*
 * Get section by name
 *
 * @param config    Configuration
 * @param name      Section name (e.g., "identity", "network")
 * @return          Section or NULL if not found
 */
sol_config_section_t* sol_config_section(sol_config_t* config, const char* name);

/*
 * Get value from section
 *
 * @param section   Configuration section
 * @param key       Key name
 * @return          Value or NULL if not found
 */
sol_config_value_t* sol_config_get(sol_config_section_t* section, const char* key);

/*
 * Convenience getters with defaults
 */

const char* sol_config_get_string(
    sol_config_t*   config,
    const char*     section,
    const char*     key,
    const char*     default_value
);

int64_t sol_config_get_int(
    sol_config_t*   config,
    const char*     section,
    const char*     key,
    int64_t         default_value
);

bool sol_config_get_bool(
    sol_config_t*   config,
    const char*     section,
    const char*     key,
    bool            default_value
);

double sol_config_get_float(
    sol_config_t*   config,
    const char*     section,
    const char*     key,
    double          default_value
);

/*
 * Get string array from configuration
 *
 * @param config    Configuration
 * @param section   Section name
 * @param key       Key name
 * @param out       Output array of strings (caller must free each string and array)
 * @param count     Output count
 * @return          SOL_OK on success
 */
sol_err_t sol_config_get_string_array(
    sol_config_t*   config,
    const char*     section,
    const char*     key,
    char***         out,
    size_t*         count
);

/*
 * Validator configuration structure
 *
 * This is a convenience structure that holds all validator settings
 * parsed from a configuration file.
 */
typedef struct {
    /* Identity */
    char*       identity_keypair;       /* Path to identity keypair */
    char*       vote_account;           /* Vote account address */

    /* Ledger */
    char*       ledger_path;            /* Path to ledger directory */
    char*       rocksdb_path;           /* Path to RocksDB directory */
    char*       snapshot_path;          /* Path to snapshots */

    /* Consensus */
    char*       tower_path;             /* Path to tower persistence file (optional) */

    /* Network */
    char**      entrypoints;            /* Entrypoint addresses */
    size_t      entrypoints_count;
    char*       advertise_ip;           /* Public IP to advertise in gossip contact-info (optional) */
    uint16_t    shred_version;          /* Cluster shred version (0 = auto-discover) */
    char*       shred_version_rpc_url;  /* RPC URL used to auto-discover shred version (optional) */
    uint16_t    gossip_port;            /* Gossip port */
    uint16_t    tpu_port;               /* TPU port */
    uint16_t    tvu_port;               /* TVU port */
    uint16_t    rpc_port;               /* RPC port */
    bool        enable_quic;            /* Enable QUIC transport */

    /* RPC */
    bool        rpc_enable;             /* Enable RPC server */
    char*       rpc_bind;               /* RPC bind address */

    /* Snapshots */
    uint64_t    snapshot_interval;      /* Full snapshot interval (slots) */
    uint64_t    incremental_interval;   /* Incremental snapshot interval */
    char*       snapshot_manifest_url;  /* Snapshot service manifest URL (optional) */
    char**      snapshot_rpc_urls;      /* Optional RPC URLs for snapshot download fallback */
    size_t      snapshot_rpc_urls_count;
    bool        snapshot_verify_accounts_hash; /* Verify snapshot accounts hash at load time (very expensive) */
    uint64_t    snapshot_max_bootstrap_lag_slots; /* Max lag vs best snapshot before forcing fresh snapshot load (0=disabled) */

    /* Logging */
    char*       log_level;              /* Log level (trace/debug/info/warn/error) */
    char*       log_format;             /* Log format (text/json) */
    char*       log_file;               /* Log file path (NULL for stderr) */

    /* Metrics */
    bool        metrics_enable;         /* Enable metrics server */
    uint16_t    metrics_port;           /* Metrics port */
} sol_validator_config_t;

/*
 * Load validator configuration from file
 *
 * @param path      Path to configuration file
 * @param config    Output configuration
 * @return          SOL_OK on success
 */
sol_err_t sol_validator_config_load(const char* path, sol_validator_config_t* config);

/*
 * Initialize validator config with defaults
 */
void sol_validator_config_init(sol_validator_config_t* config);

/*
 * Free validator configuration
 */
void sol_validator_config_cleanup(sol_validator_config_t* config);

#ifdef __cplusplus
}
#endif

#endif /* SOL_CONFIG_H */
