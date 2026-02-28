/*
 * main.c - Solana validator entry point
 *
 * This is the main entry point for the solana-validator binary.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "util/sol_base.h"
#include "util/sol_types.h"
#include "util/sol_err.h"
#include "util/sol_log.h"
#include "util/sol_alloc.h"
#include "util/sol_crash.h"
#include "util/sol_config.h"
#include "util/sol_json.h"
#include "util/sol_rpc_client.h"
#include "util/sol_io.h"
#include "crypto/sol_ed25519.h"
#include "txn/sol_pubkey.h"
#include "gossip/sol_gossip.h"
#include "shred/sol_shred.h"
#include "blockstore/sol_blockstore.h"
#include "turbine/sol_turbine.h"
#include "repair/sol_repair.h"
#include "replay/sol_replay.h"
#include "replay/sol_bank_forks.h"
#include "runtime/sol_bank.h"
#include "runtime/sol_accounts_db.h"
#include "runtime/sol_leader_schedule.h"
#include "programs/sol_stake_program.h"
#include "poh/sol_poh.h"
#include "poh/sol_block_producer.h"
#include "consensus/sol_tower.h"
#include "consensus/sol_vote_tx.h"
#include "tpu/sol_tpu.h"
#include "tvu/sol_tvu.h"
#include "metrics/sol_prometheus.h"
#include "rpc/sol_health.h"
#include "rpc/sol_rpc.h"
#include "snapshot/sol_snapshot.h"
#include "snapshot/sol_snapshot_download.h"

static uint64_t
validator_phys_mem_bytes(void) {
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGESIZE);
    if (pages <= 0 || page_size <= 0) return 0;
    return (uint64_t)pages * (uint64_t)page_size;
}

static size_t
validator_default_accountsdb_rocksdb_cache_mb(void) {
    /* AccountsDB index lookups are extremely latency sensitive during replay.
     * On validator-grade hosts we can safely spend tens of GiB on RocksDB's
     * block cache to avoid disk-bound random reads. */
    uint64_t mem_bytes = validator_phys_mem_bytes();
    uint64_t mem_gib = mem_bytes / (1024ull * 1024ull * 1024ull);
    if (mem_gib >= 1024ull) return 65536u; /* 64 GiB */
    if (mem_gib >= 512ull) return 32768u;  /* 32 GiB */
    if (mem_gib >= 256ull) return 16384u;  /* 16 GiB */
    if (mem_gib >= 128ull) return 8192u;   /* 8 GiB */
    if (mem_gib >= 64ull) return 4096u;    /* 4 GiB */
    return 512u;
}

static size_t
validator_default_blockstore_rocksdb_cache_mb(void) {
    uint64_t mem_bytes = validator_phys_mem_bytes();
    uint64_t mem_gib = mem_bytes / (1024ull * 1024ull * 1024ull);
    if (mem_gib >= 1024ull) return 16384u; /* 16 GiB */
    if (mem_gib >= 512ull) return 8192u;   /* 8 GiB */
    if (mem_gib >= 256ull) return 4096u;   /* 4 GiB */
    if (mem_gib >= 128ull) return 2048u;   /* 2 GiB */
    if (mem_gib >= 64ull) return 1024u;    /* 1 GiB */
    return 512u;
}

static sol_err_t
rm_dir_recursive(const char* path) {
    if (!path || path[0] == '\0') return SOL_ERR_INVAL;

    DIR* dir = opendir(path);
    if (!dir) return SOL_ERR_NOTFOUND;

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char full_path[PATH_MAX];
        int n = snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
        if (n < 0 || (size_t)n >= sizeof(full_path)) {
            continue;
        }

        struct stat st;
        if (lstat(full_path, &st) != 0) {
            continue;
        }

        if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
            (void)rm_dir_recursive(full_path);
            continue;
        }

        (void)unlink(full_path);
    }

    closedir(dir);
    if (rmdir(path) != 0) {
        return SOL_ERR_IO;
    }

    return SOL_OK;
}

static sol_slot_t
snapshot_effective_slot_from_paths(const char* full_snapshot_path,
                                   const char* incremental_snapshot_path) {
    sol_snapshot_info_t info = {0};
    if (incremental_snapshot_path &&
        incremental_snapshot_path[0] != '\0' &&
        sol_snapshot_get_info(incremental_snapshot_path, &info) == SOL_OK &&
        info.slot != 0) {
        return info.slot;
    }

    memset(&info, 0, sizeof(info));
    if (full_snapshot_path &&
        full_snapshot_path[0] != '\0' &&
        sol_snapshot_get_info(full_snapshot_path, &info) == SOL_OK &&
        info.slot != 0) {
        return info.slot;
    }

    return 0;
}

/*
 * Version information
 */
#define SOLANA_C_VERSION_MAJOR 0
#define SOLANA_C_VERSION_MINOR 1
#define SOLANA_C_VERSION_PATCH 0
#define SOLANA_C_VERSION_STRING "0.1.0"

#define SOL_DEFAULT_RPC_PORT     8899
#define SOL_DEFAULT_GOSSIP_PORT  8001
#define SOL_DEFAULT_TPU_PORT     8003
#define SOL_DEFAULT_TVU_PORT     8004
#define SOL_DEFAULT_METRICS_PORT 9090

#define OPT_VERIFY_SNAPSHOT_ACCOUNTS_HASH 1000
#define OPT_DEV_HALT_AT_SLOT 1001
#define OPT_FULL_OWNER_INDEX 1002
#define OPT_AUTO_SNAPSHOT_MAX_LAG_SLOTS 1003
#define OPT_IO_BACKEND 1004
#define OPT_IO_QUEUE_DEPTH 1005
#define OPT_IO_SQPOLL 1006
#define OPT_NO_IO_URING 1007
#define OPT_FAST_REPLAY 1008
#define OPT_TX_INDEX 1009
#define OPT_NO_TX_INDEX 1010

/*
 * Validator configuration
 */
typedef struct {
    const char*     config_file;        /* Path to config file (optional) */
    const char*     identity_path;      /* Path to identity keypair */
    const char*     vote_account_path;  /* Path to vote account keypair */
    const char*     ledger_path;        /* Path to ledger directory */
    const char*     rocksdb_path;       /* Path to RocksDB dir (optional) */
    const char*     tower_path;         /* Path to tower persistence file (optional) */
    const char*     snapshot_path;      /* Path to snapshot to load */
    const char*     snapshot_manifest_url; /* Snapshot service manifest URL */
    char**          snapshot_rpc_urls;  /* Optional RPC URLs for snapshot download fallback */
    size_t          snapshot_rpc_urls_count;
    bool            snapshot_verify_accounts_hash; /* Verify snapshot accounts hash at load time (very expensive) */
    sol_slot_t      snapshot_max_bootstrap_lag_slots; /* Max lag vs best snapshot before forcing fresh snapshot load (0=disabled) */
    const char**    entrypoints;        /* Gossip entrypoints */
    size_t          entrypoints_count;
    const char*     advertise_ip;       /* Public IP to advertise in gossip contact-info (optional) */
    const char*     shred_version_rpc_url; /* RPC URL used to auto-discover shred version (optional) */
    uint16_t        shred_version;      /* Cluster shred version (0 = auto-discover) */
    const char*     rpc_bind;           /* RPC bind address */
    uint16_t        rpc_port;           /* RPC port */
    uint16_t        gossip_port;        /* Gossip port */
    uint16_t        tpu_port;           /* TPU port */
    uint16_t        tvu_port;           /* TVU port */
    bool            enable_quic;        /* Enable QUIC transport for TPU */
    bool            enable_rpc;         /* Enable RPC server */
    bool            full_owner_index;   /* Build full accounts owner index (slow) */
    bool            no_voting;          /* Disable voting */
    bool            fast_replay;        /* Skip instruction exec/signature verify during replay (unsafe) */
    bool            enable_tx_index;    /* Enable address-signature transaction index (expensive) */
    bool            no_wait_for_vote;   /* Don't wait for vote account */
    sol_log_level_t log_level;          /* Log level */
    sol_log_format_t log_format;        /* Log format (text/json) */
    const char*     log_file;           /* Log file path (NULL for stderr) */
    bool            enable_metrics;     /* Enable Prometheus metrics */
    uint16_t        metrics_port;       /* Prometheus metrics port */
    sol_slot_t      dev_halt_at_slot;   /* Halt once this slot is replayed (dev/test) */
    sol_io_backend_t io_backend;        /* IO backend selection */
    uint32_t        io_queue_depth;     /* io_uring queue depth (if enabled) */
    bool            io_sqpoll;          /* io_uring SQPOLL submit thread */
} validator_config_t;

typedef struct {
    pthread_t              thread;
    pthread_mutex_t        lock;
    pthread_cond_t         cond;
    bool                   started;
    bool                   shutdown;
    bool                   request_pending;
    sol_slot_t             requested_start;
    uint64_t               last_request_ns;
    sol_leader_schedule_t* ready_schedule;
    char                   ready_rpc_url[256];
} validator_leader_schedule_refresh_t;

/*
 * Validator state
 */
typedef struct {
    /* Identity */
    sol_keypair_t       identity;
    sol_pubkey_t        identity_pubkey;

    /* Vote account */
    sol_pubkey_t        vote_account;
    sol_vote_tx_builder_t vote_tx_builder;
    bool                vote_account_initialized;

    /* Core components */
    sol_gossip_t*       gossip;
    sol_blockstore_t*   blockstore;
    sol_accounts_db_t*  accounts_db;
    sol_bank_forks_t*   bank_forks;
    sol_replay_t*       replay;
    sol_turbine_t*      turbine;
    sol_repair_t*       repair;
    sol_tower_t*        tower;
    bool               tower_initialized;
    sol_tpu_t*          tpu;
    sol_tvu_t*          tvu;

    /* Service pump threads */
    pthread_t           repair_pump_thread;
    bool                repair_pump_started;

    /* Block production */
    sol_poh_recorder_t*   poh;
    sol_block_producer_t* block_producer;
    sol_leader_schedule_t* leader_schedule;
    sol_pubkey_map_t*       vote_stakes;       /* vote account -> stake (epoch cache) */
    uint64_t                vote_stakes_epoch;
    uint64_t                vote_stakes_total;

    /* Operational */
    sol_prometheus_t*     prometheus;
    sol_health_server_t*  health;
    sol_rpc_t*            rpc;
    sol_io_ctx_t*         io_ctx;
    validator_leader_schedule_refresh_t leader_schedule_refresh;

    /* Metrics handles */
    sol_metric_t*         metric_slot_height;
    sol_metric_t*         metric_txn_received;
    sol_metric_t*         metric_txn_processed;
    sol_metric_t*         metric_shreds_received;
    sol_metric_t*         metric_peers_connected;
    sol_metric_t*         metric_votes_submitted;

    /* State */
    bool                is_leader;
    bool                is_syncing;
    sol_slot_t          current_slot;
    sol_slot_t          highest_slot;
    uint64_t            start_time;

    /* Snapshot verification (vote-based) */
    bool                snapshot_verified;
    sol_slot_t          snapshot_start_slot;
    sol_hash_t          snapshot_start_hash;
    uint64_t            last_snapshot_verify_ns;

    /* Diagnostics */
    uint64_t            last_vote_hash_diag_ns;
    sol_slot_t          last_vote_hash_diag_slot;
} validator_t;

static void validator_refresh_epoch_caches(validator_t* v, sol_bank_t* bank);

static validator_config_t g_config = {
    .config_file = NULL,
    .identity_path = NULL,
    .vote_account_path = NULL,
    .ledger_path = "./ledger",
    .rocksdb_path = NULL,
    .tower_path = NULL,
    .snapshot_path = NULL,
    .snapshot_manifest_url = SOL_MAINNET_SNAPSHOT_MANIFEST_URL,
    .snapshot_rpc_urls = NULL,
    .snapshot_rpc_urls_count = 0,
    .snapshot_verify_accounts_hash = false,
    .snapshot_max_bootstrap_lag_slots = 1,
    .entrypoints = NULL,
    .entrypoints_count = 0,
    .advertise_ip = NULL,
    .shred_version_rpc_url = NULL,
    .shred_version = 0,
    .rpc_bind = "127.0.0.1",
    .rpc_port = SOL_DEFAULT_RPC_PORT,
    .gossip_port = SOL_DEFAULT_GOSSIP_PORT,
    .tpu_port = SOL_DEFAULT_TPU_PORT,
    .tvu_port = SOL_DEFAULT_TVU_PORT,
    .enable_quic = true,
    .enable_rpc = true,
    .full_owner_index = false,
    .no_voting = false,
    .fast_replay = false,
    .enable_tx_index = false,
    .no_wait_for_vote = false,
    .log_level = SOL_LOG_INFO,
    .log_format = SOL_LOG_FORMAT_TEXT,
    .log_file = NULL,
    .enable_metrics = true,
    .metrics_port = SOL_DEFAULT_METRICS_PORT,
    .dev_halt_at_slot = 0,
#ifdef __linux__
    .io_backend = SOL_IO_BACKEND_URING,
#else
    .io_backend = SOL_IO_BACKEND_POSIX,
#endif
    .io_queue_depth = 256,
    .io_sqpoll = false,
};

static bool g_snapshot_max_lag_cli_overridden = false;
static bool g_entrypoints_cli_overridden = false;
static bool g_io_backend_cli_overridden = false;
static bool g_tx_index_cli_overridden = false;
static bool g_rpc_port_is_bound = false;

/* Default snapshot RPC fallback (owned for process lifetime). */
static char* g_default_snapshot_rpc_url_owned = NULL;
static char* g_default_snapshot_rpc_urls[1] = {NULL};

/* Global validator pointer for health callback */
static validator_t* g_validator = NULL;

#ifdef SOL_HAS_ROCKSDB
static char g_default_rocksdb_path[PATH_MAX] = {0};
#endif
static char g_default_tower_path[PATH_MAX] = {0};

static bool
path_exists(const char* path) {
    if (!path) return false;
    struct stat st;
    return stat(path, &st) == 0;
}

static bool
path_is_symlink(const char* path) {
    if (!path || path[0] == '\0') return false;
    struct stat st;
    if (lstat(path, &st) != 0) return false;
    return S_ISLNK(st.st_mode);
}

static bool
path_parent_is_symlink(const char* path) {
    if (!path || path[0] == '\0') return false;
    char buf[PATH_MAX];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(buf)) return false;
    memcpy(buf, path, len + 1);
    char* slash = strrchr(buf, '/');
    if (!slash) return false;
    if (slash == buf) {
        return false;
    }
    *slash = '\0';
    return path_is_symlink(buf);
}

static bool
rocksdb_dir_looks_like_db(const char* dir) {
    if (!dir) return false;

    char current_path[PATH_MAX];
    int n = snprintf(current_path, sizeof(current_path), "%s/CURRENT", dir);
    if (n < 0 || (size_t)n >= sizeof(current_path)) return false;
    return access(current_path, F_OK) == 0;
}

static bool
dir_has_any_regular_file(const char* dir_path) {
    if (!dir_path || dir_path[0] == '\0') return false;

    DIR* dir = opendir(dir_path);
    if (!dir) return false;

    bool found = false;
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char path[PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);
        if (n < 0 || (size_t)n >= sizeof(path)) continue;

        struct stat st;
        if (stat(path, &st) != 0) continue;
        if (S_ISREG(st.st_mode)) {
            found = true;
            break;
        }
    }

    closedir(dir);
    return found;
}

static bool
udp_port_available(uint16_t port) {
    if (port == 0) return true;

    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) return false;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int ok = bind(fd, (struct sockaddr*)&addr, sizeof(addr));
    close(fd);
    return ok == 0;
}

static bool
tcp_port_available(const char* bind_ip, uint16_t port) {
    if (port == 0) return true;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;

    int opt = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (bind_ip && bind_ip[0] != '\0') {
        if (inet_pton(AF_INET, bind_ip, &addr.sin_addr) != 1) {
            close(fd);
            return false;
        }
    } else {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    int ok = bind(fd, (struct sockaddr*)&addr, sizeof(addr));
    close(fd);
    return ok == 0;
}

static uint16_t
pick_free_tcp_port(const char* bind_ip, uint16_t start, uint16_t span, uint16_t avoid0, uint16_t avoid1) {
    for (uint32_t i = 0; i < span; i++) {
        uint16_t p = (uint16_t)(start + i);
        if (p == 0 || p == avoid0 || p == avoid1) continue;
        if (tcp_port_available(bind_ip, p)) return p;
    }
    return 0;
}

static void
validator_autoselect_default_ports(void) {
    const uint16_t auto_span = 2000;

    /* Port 0 (ephemeral) is not supported by our gossip/contact-info model yet.
     * Treat it as "use default + auto-select if occupied". */
    if (g_config.gossip_port == 0) g_config.gossip_port = SOL_DEFAULT_GOSSIP_PORT;
    if (g_config.tpu_port == 0) g_config.tpu_port = SOL_DEFAULT_TPU_PORT;
    if (g_config.tvu_port == 0) g_config.tvu_port = SOL_DEFAULT_TVU_PORT;
    if (g_config.enable_rpc && g_config.rpc_port == 0) g_config.rpc_port = SOL_DEFAULT_RPC_PORT;
    if (g_config.enable_metrics && g_config.metrics_port == 0) g_config.metrics_port = SOL_DEFAULT_METRICS_PORT;

    /* Gossip (UDP) */
    if ((g_config.gossip_port == 0 ||
         (g_config.gossip_port >= SOL_DEFAULT_GOSSIP_PORT &&
          g_config.gossip_port < (uint16_t)(SOL_DEFAULT_GOSSIP_PORT + auto_span))) &&
        !udp_port_available(g_config.gossip_port ? g_config.gossip_port : SOL_DEFAULT_GOSSIP_PORT)) {
        uint16_t tpu_quic = (uint16_t)(g_config.tpu_port + SOL_TPU_QUIC_PORT_OFFSET);
        uint16_t serve_repair = (uint16_t)(g_config.tvu_port + 2);
        uint16_t base = g_config.gossip_port ? g_config.gossip_port : SOL_DEFAULT_GOSSIP_PORT;
        if (base < SOL_DEFAULT_GOSSIP_PORT) base = SOL_DEFAULT_GOSSIP_PORT;
        for (uint32_t i = 1; i < auto_span; i++) {
            uint16_t candidate = (uint16_t)(base + i);
            if (candidate == 0) continue;
            if (candidate == g_config.tpu_port || candidate == g_config.tvu_port || candidate == serve_repair) continue;
            if (g_config.enable_quic && candidate == tpu_quic) continue;
            if (!udp_port_available(candidate)) continue;

            sol_log_warn("Gossip port %u is in use; using %u",
                         (unsigned)base, (unsigned)candidate);
            g_config.gossip_port = candidate;
            break;
        }
    }

    /* TVU + serve-repair (UDP) */
    if ((g_config.tvu_port == 0 ||
         (g_config.tvu_port >= SOL_DEFAULT_TVU_PORT &&
          g_config.tvu_port < (uint16_t)(SOL_DEFAULT_TVU_PORT + auto_span))) &&
        (!udp_port_available(g_config.tvu_port ? g_config.tvu_port : SOL_DEFAULT_TVU_PORT) ||
         !udp_port_available((uint16_t)((g_config.tvu_port ? g_config.tvu_port : SOL_DEFAULT_TVU_PORT) + 2)))) {
        uint16_t tpu_quic = (uint16_t)(g_config.tpu_port + SOL_TPU_QUIC_PORT_OFFSET);
        uint16_t base = g_config.tvu_port ? g_config.tvu_port : SOL_DEFAULT_TVU_PORT;
        if (base < SOL_DEFAULT_TVU_PORT) base = SOL_DEFAULT_TVU_PORT;
        for (uint32_t i = 1; i < auto_span; i++) {
            uint16_t candidate = (uint16_t)(base + i);
            uint16_t serve_repair = (uint16_t)(candidate + 2);
            if (candidate == 0 || serve_repair == 0) continue;
            if (candidate == g_config.gossip_port || serve_repair == g_config.gossip_port) continue;
            if (candidate == g_config.tpu_port || serve_repair == g_config.tpu_port) continue;
            if (g_config.enable_quic &&
                (candidate == tpu_quic || serve_repair == tpu_quic)) {
                continue;
            }
            if (!udp_port_available(candidate) || !udp_port_available(serve_repair)) continue;

            sol_log_warn("TVU port %u is in use; using %u (serve-repair %u)",
                         (unsigned)base,
                         (unsigned)candidate,
                         (unsigned)serve_repair);
            g_config.tvu_port = candidate;
            break;
        }
    }

    /* TPU UDP/QUIC (UDP) */
    uint16_t tpu_quic_port = (uint16_t)(g_config.tpu_port + SOL_TPU_QUIC_PORT_OFFSET);
    if ((g_config.tpu_port == 0 ||
         (g_config.tpu_port >= SOL_DEFAULT_TPU_PORT &&
          g_config.tpu_port < (uint16_t)(SOL_DEFAULT_TPU_PORT + auto_span))) &&
        (!udp_port_available(g_config.tpu_port) ||
         (g_config.enable_quic && !udp_port_available(tpu_quic_port)))) {
        uint16_t base = g_config.tpu_port ? g_config.tpu_port : SOL_DEFAULT_TPU_PORT;
        if (base < SOL_DEFAULT_TPU_PORT) base = SOL_DEFAULT_TPU_PORT;
        for (uint32_t i = 1; i < auto_span; i++) {
            uint16_t candidate = (uint16_t)(base + i);
            uint16_t candidate_quic = (uint16_t)(candidate + SOL_TPU_QUIC_PORT_OFFSET);
            if (candidate == 0 || candidate_quic == 0) continue;
            if (candidate == g_config.gossip_port || candidate_quic == g_config.gossip_port) continue;
            if (candidate == g_config.tvu_port || candidate_quic == g_config.tvu_port) continue;
            if (candidate == (uint16_t)(g_config.tvu_port + 2) ||
                candidate_quic == (uint16_t)(g_config.tvu_port + 2)) {
                continue;
            }
            if (!udp_port_available(candidate)) continue;
            if (g_config.enable_quic && !udp_port_available(candidate_quic)) continue;

            sol_log_warn("TPU port %u is in use; using %u (QUIC %u)",
                         (unsigned)base,
                         (unsigned)candidate,
                         (unsigned)candidate_quic);
            g_config.tpu_port = candidate;
            break;
        }
    }

    /* RPC (TCP) */
    if (g_config.enable_rpc && !g_rpc_port_is_bound &&
        (g_config.rpc_port == 0 ||
         (g_config.rpc_port >= SOL_DEFAULT_RPC_PORT &&
          g_config.rpc_port < (uint16_t)(SOL_DEFAULT_RPC_PORT + auto_span)))) {
        uint16_t ws_port = (g_config.rpc_port < UINT16_MAX) ? (uint16_t)(g_config.rpc_port + 1) : 0;
        if (!tcp_port_available(g_config.rpc_bind, g_config.rpc_port) ||
            (ws_port && !tcp_port_available(g_config.rpc_bind, ws_port))) {
            uint16_t base = g_config.rpc_port ? g_config.rpc_port : SOL_DEFAULT_RPC_PORT;
            if (base < SOL_DEFAULT_RPC_PORT) base = SOL_DEFAULT_RPC_PORT;
            for (uint32_t i = 2; i < auto_span; i += 2) {
                uint16_t candidate = (uint16_t)(base + i);
                uint16_t candidate_ws = (candidate < UINT16_MAX) ? (uint16_t)(candidate + 1) : 0;
                if (!tcp_port_available(g_config.rpc_bind, candidate)) continue;
                if (candidate_ws && !tcp_port_available(g_config.rpc_bind, candidate_ws)) continue;

                sol_log_warn("RPC port %u is in use; using %u (ws %u)",
                             (unsigned)base,
                             (unsigned)candidate,
                             (unsigned)candidate_ws);
                g_config.rpc_port = candidate;
                break;
            }
        }
    }

    /* Metrics (TCP, default bind-any) */
    if (g_config.enable_metrics &&
        (g_config.metrics_port == 0 ||
         (g_config.metrics_port >= SOL_DEFAULT_METRICS_PORT &&
          g_config.metrics_port < (uint16_t)(SOL_DEFAULT_METRICS_PORT + auto_span))) &&
        !tcp_port_available(NULL, g_config.metrics_port ? g_config.metrics_port : SOL_DEFAULT_METRICS_PORT)) {
        uint16_t base = g_config.metrics_port ? g_config.metrics_port : SOL_DEFAULT_METRICS_PORT;
        if (base < SOL_DEFAULT_METRICS_PORT) base = SOL_DEFAULT_METRICS_PORT;
        uint16_t p = pick_free_tcp_port(NULL, (uint16_t)(base + 1), auto_span, g_config.rpc_port,
                                        (g_config.rpc_port < UINT16_MAX) ? (uint16_t)(g_config.rpc_port + 1) : 0);
        if (p) {
            sol_log_warn("Metrics port %u is in use; using %u",
                         (unsigned)base, (unsigned)p);
            g_config.metrics_port = p;
        }
    }
}

static bool
snapshot_archive_has_known_ext(const char* name) {
    if (!name) return false;

    const char* exts[] = {
        ".tar.zst",
        ".tar.gz",
        ".tar.bz2",
        ".tar.lz4",
        ".tar",
        NULL,
    };

    size_t nlen = strlen(name);
    for (size_t i = 0; exts[i] != NULL; i++) {
        size_t elen = strlen(exts[i]);
        if (nlen >= elen && memcmp(name + (nlen - elen), exts[i], elen) == 0) {
            return true;
        }
    }
    return false;
}

static sol_err_t
find_latest_full_snapshot_archive(const char* archive_dir,
                                  char* out_path,
                                  size_t out_path_len,
                                  sol_slot_t* out_slot) {
    if (!archive_dir || !out_path || out_path_len == 0) return SOL_ERR_INVAL;

    DIR* dir = opendir(archive_dir);
    if (!dir) return SOL_ERR_NOTFOUND;

    sol_slot_t best_slot = 0;
    char best_name[PATH_MAX] = {0};

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char full_path[PATH_MAX];
        int n = snprintf(full_path, sizeof(full_path), "%s/%s", archive_dir, entry->d_name);
        if (n < 0 || (size_t)n >= sizeof(full_path)) continue;

        struct stat st;
        if (stat(full_path, &st) != 0 || !S_ISREG(st.st_mode)) continue;

        if (!snapshot_archive_has_known_ext(entry->d_name)) continue;

        sol_snapshot_info_t info;
        if (sol_snapshot_get_info(entry->d_name, &info) != SOL_OK) continue;
        if (info.type != SOL_SNAPSHOT_FULL) continue;

        if (info.slot > best_slot) {
            best_slot = info.slot;
            snprintf(best_name, sizeof(best_name), "%s", entry->d_name);
        }
    }

    closedir(dir);

    if (best_slot == 0 || best_name[0] == '\0') {
        return SOL_ERR_NOTFOUND;
    }

    int n = snprintf(out_path, out_path_len, "%s/%s", archive_dir, best_name);
    if (n < 0 || (size_t)n >= out_path_len) return SOL_ERR_TOO_LARGE;
    if (out_slot) *out_slot = best_slot;
    return SOL_OK;
}

static sol_err_t
find_best_incremental_snapshot_archive(const char* archive_dir,
                                       sol_slot_t base_slot,
                                       char* out_path,
                                       size_t out_path_len,
                                       sol_slot_t* out_slot) {
    if (!archive_dir || !out_path || out_path_len == 0) return SOL_ERR_INVAL;

    DIR* dir = opendir(archive_dir);
    if (!dir) return SOL_ERR_NOTFOUND;

    sol_slot_t best_slot = 0;
    char best_name[PATH_MAX] = {0};

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char full_path[PATH_MAX];
        int n = snprintf(full_path, sizeof(full_path), "%s/%s", archive_dir, entry->d_name);
        if (n < 0 || (size_t)n >= sizeof(full_path)) continue;

        struct stat st;
        if (stat(full_path, &st) != 0 || !S_ISREG(st.st_mode)) continue;

        if (!snapshot_archive_has_known_ext(entry->d_name)) continue;

        sol_snapshot_info_t info;
        if (sol_snapshot_get_info(entry->d_name, &info) != SOL_OK) continue;
        if (info.type != SOL_SNAPSHOT_INCREMENTAL) continue;
        if (info.base_slot != base_slot) continue;

        if (info.slot > best_slot) {
            best_slot = info.slot;
            snprintf(best_name, sizeof(best_name), "%s", entry->d_name);
        }
    }

    closedir(dir);

    if (best_slot == 0 || best_name[0] == '\0') {
        return SOL_ERR_NOTFOUND;
    }

    int n = snprintf(out_path, out_path_len, "%s/%s", archive_dir, best_name);
    if (n < 0 || (size_t)n >= out_path_len) return SOL_ERR_TOO_LARGE;
    if (out_slot) *out_slot = best_slot;
    return SOL_OK;
}

/* Infer the base slot for a persisted bootstrap slot by locating the incremental
 * snapshot archive that produced it.
 *
 * This is intentionally conservative: we only trust an exact filename match
 * (incremental-snapshot-<base>-<slot>-...). Without knowing the true base slot
 * of the AccountsDB contents, applying an arbitrary incremental snapshot risks
 * corrupting or rewinding state. */
static sol_err_t
find_incremental_base_for_bootstrap_slot(const char* archive_dir,
                                        sol_slot_t bootstrap_slot,
                                        sol_slot_t* out_base_slot,
                                        char* out_path,
                                        size_t out_path_len) {
    if (!archive_dir || bootstrap_slot == 0 || !out_base_slot) return SOL_ERR_INVAL;
    if (out_path && out_path_len > 0) out_path[0] = '\0';

    DIR* dir = opendir(archive_dir);
    if (!dir) return SOL_ERR_NOTFOUND;

    sol_err_t rc = SOL_ERR_NOTFOUND;
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char full_path[PATH_MAX];
        int n = snprintf(full_path, sizeof(full_path), "%s/%s", archive_dir, entry->d_name);
        if (n < 0 || (size_t)n >= sizeof(full_path)) continue;

        struct stat st;
        if (stat(full_path, &st) != 0 || !S_ISREG(st.st_mode)) continue;

        if (!snapshot_archive_has_known_ext(entry->d_name)) continue;

        sol_snapshot_info_t info = {0};
        if (sol_snapshot_get_info(entry->d_name, &info) != SOL_OK) continue;
        if (info.type != SOL_SNAPSHOT_INCREMENTAL) continue;
        if (info.slot != bootstrap_slot) continue;
        if (info.base_slot == 0) continue;

        *out_base_slot = info.base_slot;
        if (out_path && out_path_len > 0) {
            (void)snprintf(out_path, out_path_len, "%s/%s", archive_dir, entry->d_name);
        }
        rc = SOL_OK;
        break;
    }

    closedir(dir);
    return rc;
}

static sol_err_t
auto_download_snapshot_archives(const char* manifest_url,
                                const char* archive_dir,
                                char* out_full_path,
                                size_t out_full_path_len,
                                char* out_incremental_path,
                                size_t out_incremental_path_len,
                                sol_io_ctx_t* io_ctx) {
    if (!manifest_url || !archive_dir || !out_full_path || out_full_path_len == 0) return SOL_ERR_INVAL;
    if (out_incremental_path && out_incremental_path_len > 0) {
        out_incremental_path[0] = '\0';
    }

    sol_available_snapshot_t full = {0};
    sol_available_snapshot_t incr = {0};
    sol_snapshot_download_opts_t opts = SOL_SNAPSHOT_DOWNLOAD_OPTS_DEFAULT;
    opts.allow_incremental = true;
    opts.verify_after = true;
    opts.resume = true;
    opts.output_dir = archive_dir;
    opts.io_ctx = io_ctx;

    sol_err_t err = sol_snapshot_service_find_best_download(manifest_url, &opts, &full, &incr);
    if (err != SOL_OK) {
        return err;
    }

    err = sol_snapshot_download(&full, &opts, out_full_path, out_full_path_len);
    if (err == SOL_OK && incr.type == SOL_SNAPSHOT_INCREMENTAL && incr.url &&
        out_incremental_path && out_incremental_path_len > 0) {
        sol_err_t ierr = sol_snapshot_download(&incr, &opts, out_incremental_path, out_incremental_path_len);
        if (ierr != SOL_OK) {
            sol_log_warn("Incremental snapshot download failed (continuing with full): %s", sol_err_str(ierr));
            out_incremental_path[0] = '\0';
        }
    }

    sol_available_snapshot_free(&full);
    sol_available_snapshot_free(&incr);
    return err;
}

static sol_err_t
auto_download_snapshot_archives_from_rpc_urls(char* const* rpc_urls,
                                              size_t rpc_url_count,
                                              const char* archive_dir,
                                              char* out_full_path,
                                              size_t out_full_path_len,
                                              char* out_incremental_path,
                                              size_t out_incremental_path_len,
                                              sol_io_ctx_t* io_ctx) {
    if (!rpc_urls || rpc_url_count == 0 || !archive_dir || !out_full_path || out_full_path_len == 0) {
        return SOL_ERR_INVAL;
    }
    if (out_incremental_path && out_incremental_path_len > 0) {
        out_incremental_path[0] = '\0';
    }

    sol_available_snapshot_t best_full = {0};
    sol_available_snapshot_t best_incr = {0};
    bool have_full = false;
    sol_slot_t best_effective_slot = 0;

    for (size_t i = 0; i < rpc_url_count; i++) {
        const char* rpc_url = rpc_urls[i];
        if (!rpc_url || rpc_url[0] == '\0') continue;

        sol_available_snapshot_t candidates[4];
        memset(candidates, 0, sizeof(candidates));

        size_t n = sol_snapshot_query_available(rpc_url, candidates, 4);
        if (n == 0) {
            sol_available_snapshots_free(candidates, 4);
            continue;
        }

        sol_available_snapshot_t* full = NULL;
        sol_available_snapshot_t* incr = NULL;
        for (size_t j = 0; j < n; j++) {
            if (candidates[j].type == SOL_SNAPSHOT_FULL) full = &candidates[j];
            else if (candidates[j].type == SOL_SNAPSHOT_INCREMENTAL) incr = &candidates[j];
        }

        if (!full || !full->url) {
            sol_available_snapshots_free(candidates, 4);
            continue;
        }

        sol_slot_t effective_slot = full->slot;
        bool take_incr = false;
        if (incr && incr->url && incr->base_slot == full->slot && incr->slot > effective_slot) {
            effective_slot = incr->slot;
            take_incr = true;
        }

        if (!have_full || effective_slot > best_effective_slot) {
            sol_available_snapshot_free(&best_full);
            sol_available_snapshot_free(&best_incr);

            best_full = *full;
            full->url = NULL; /* transfer ownership */

            if (take_incr) {
                best_incr = *incr;
                incr->url = NULL; /* transfer ownership */
            }

            have_full = true;
            best_effective_slot = effective_slot;
        }

        for (size_t j = 0; j < n; j++) {
            sol_available_snapshot_free(&candidates[j]);
        }
    }

    if (!have_full || !best_full.url) {
        sol_available_snapshot_free(&best_full);
        sol_available_snapshot_free(&best_incr);
        return SOL_ERR_NOTFOUND;
    }

    sol_snapshot_download_opts_t opts = SOL_SNAPSHOT_DOWNLOAD_OPTS_DEFAULT;
    opts.allow_incremental = true;
    opts.verify_after = true;
    opts.resume = true;
    opts.output_dir = archive_dir;
    opts.io_ctx = io_ctx;

    sol_err_t err = sol_snapshot_download(&best_full, &opts, out_full_path, out_full_path_len);
    if (err == SOL_OK && best_incr.url && out_incremental_path && out_incremental_path_len > 0) {
        sol_err_t ierr = sol_snapshot_download(&best_incr, &opts, out_incremental_path, out_incremental_path_len);
        if (ierr != SOL_OK) {
            sol_log_warn("Incremental snapshot download failed (continuing with full): %s", sol_err_str(ierr));
            out_incremental_path[0] = '\0';
        }
    }

    sol_available_snapshot_free(&best_full);
    sol_available_snapshot_free(&best_incr);
    return err;
}

static sol_slot_t
query_snapshot_service_best_slot(const char* manifest_url) {
    if (!manifest_url || manifest_url[0] == '\0') return 0;

    sol_snapshot_download_opts_t qopts = SOL_SNAPSHOT_DOWNLOAD_OPTS_DEFAULT;
    qopts.allow_incremental = true;
    qopts.verify_after = false;
    qopts.resume = false;

    sol_available_snapshot_t full = {0};
    sol_available_snapshot_t incr = {0};
    sol_slot_t best_slot = 0;

    sol_err_t err = sol_snapshot_service_find_best_download(manifest_url, &qopts, &full, &incr);
    if (err == SOL_OK && full.slot != 0) {
        if (incr.type == SOL_SNAPSHOT_INCREMENTAL && incr.slot != 0) {
            best_slot = incr.slot;
        } else {
            best_slot = full.slot;
        }
    }

    sol_available_snapshot_free(&full);
    sol_available_snapshot_free(&incr);
    return best_slot;
}

static sol_err_t
query_rpc_best_slot(char* const* rpc_urls,
                    size_t rpc_url_count,
                    sol_slot_t* out_best_slot) {
    if (!out_best_slot) return SOL_ERR_INVAL;
    *out_best_slot = 0;
    if (!rpc_urls || rpc_url_count == 0) return SOL_ERR_INVAL;

    sol_slot_t best = 0;

    for (size_t i = 0; i < rpc_url_count; i++) {
        const char* rpc_url = rpc_urls[i];
        if (!rpc_url || rpc_url[0] == '\0') continue;

        sol_available_snapshot_t candidates[4];
        memset(candidates, 0, sizeof(candidates));
        size_t n = sol_snapshot_query_available(rpc_url, candidates, 4);
        if (n == 0) {
            sol_available_snapshots_free(candidates, 4);
            continue;
        }

        sol_available_snapshot_t* full = NULL;
        sol_available_snapshot_t* incr = NULL;
        for (size_t j = 0; j < n; j++) {
            if (candidates[j].type == SOL_SNAPSHOT_FULL) full = &candidates[j];
            else if (candidates[j].type == SOL_SNAPSHOT_INCREMENTAL) incr = &candidates[j];
        }

        if (full && full->url) {
            sol_slot_t effective = full->slot;
            if (incr && incr->url && incr->base_slot == full->slot && incr->slot > effective) {
                effective = incr->slot;
            }
            if (effective > best) {
                best = effective;
            }
        }

        sol_available_snapshots_free(candidates, 4);
    }

    if (best == 0) return SOL_ERR_NOTFOUND;
    *out_best_slot = best;
    return SOL_OK;
}

static sol_err_t
auto_download_incremental_snapshot_for_base_best_effort(const char* manifest_url,
                                                        char* const* rpc_urls,
                                                        size_t rpc_url_count,
                                                        const char* archive_dir,
                                                        sol_slot_t base_slot,
                                                        char* out_incremental_path,
                                                        size_t out_incremental_path_len,
                                                        sol_slot_t* out_incremental_slot,
                                                        sol_io_ctx_t* io_ctx);

static sol_err_t
auto_download_snapshot_archives_best_effort(const char* manifest_url,
                                            char* const* rpc_urls,
                                            size_t rpc_url_count,
                                            const char* archive_dir,
                                            char* out_full_path,
                                            size_t out_full_path_len,
                                            char* out_incremental_path,
                                            size_t out_incremental_path_len,
                                            sol_io_ctx_t* io_ctx) {
    const bool have_manifest = manifest_url && manifest_url[0] != '\0';
    const bool have_rpc = rpc_urls && rpc_url_count > 0;
    if (!have_manifest && !have_rpc) return SOL_ERR_INVAL;

    sol_slot_t manifest_best_slot = 0;
    if (have_manifest) {
        manifest_best_slot = query_snapshot_service_best_slot(manifest_url);
    }

    sol_slot_t rpc_best_slot = 0;
    if (have_rpc) {
        (void)query_rpc_best_slot(rpc_urls, rpc_url_count, &rpc_best_slot);
    }

    /* Default: prefer the snapshot service when configured.
     *
     * Snapshot services are typically tuned for high-throughput archive
     * delivery (range requests), while RPC endpoints are primarily for
     * JSON-RPC and may rate-limit large archive downloads. */
    bool prefer_rpc = (!have_manifest && have_rpc);
    /* Allow operators to opt into preferring fresher RPC snapshots (at the cost
     * of slower/more fragile large archive downloads). */
    const char* prefer_rpc_env = getenv("SOL_SNAPSHOT_PREFER_RPC_IF_FRESHER");
    bool prefer_rpc_if_fresher =
        (prefer_rpc_env && prefer_rpc_env[0] != '\0' && strcmp(prefer_rpc_env, "0") != 0);
    if (prefer_rpc_if_fresher && have_manifest && have_rpc && rpc_best_slot != 0) {
        /* Prefer the source that is actually fresher. Snapshot services can lag
         * RPC-reported highest snapshots by many minutes/hours if uploads stall. */
        if (manifest_best_slot == 0 || rpc_best_slot > manifest_best_slot) {
            prefer_rpc = true;
        }
    }

    /* Optional behavior: prefer RPC snapshots when the manifest is stale.
     *
     * This is disabled by default because large archive downloads from public
     * JSON-RPC endpoints are often rate-limited or do not support byte-range
     * requests. Operators can opt into this behavior via
     * SOL_SNAPSHOT_AUTO_PREFER_RPC_LAG_SLOTS (set to a positive slot lag). */
    sol_slot_t auto_prefer_rpc_lag = 0;
    const char* auto_prefer_rpc_env = getenv("SOL_SNAPSHOT_AUTO_PREFER_RPC_LAG_SLOTS");
    if (auto_prefer_rpc_env && auto_prefer_rpc_env[0] != '\0') {
        errno = 0;
        char* end = NULL;
        unsigned long long lag = strtoull(auto_prefer_rpc_env, &end, 10);
        if (errno == 0 && end && end != auto_prefer_rpc_env) {
            while (*end && isspace((unsigned char)*end)) end++;
            if (*end == '\0') {
                auto_prefer_rpc_lag = (sol_slot_t)lag;
            }
        }
    }

    if (!prefer_rpc &&
        have_manifest &&
        have_rpc &&
        auto_prefer_rpc_lag != 0 &&
        manifest_best_slot != 0 &&
        rpc_best_slot > manifest_best_slot &&
        (rpc_best_slot - manifest_best_slot) > auto_prefer_rpc_lag) {
        sol_log_warn("Snapshot manifest best slot %lu lags RPC best slot %lu by %lu slots; preferring RPC download",
                     (unsigned long)manifest_best_slot,
                     (unsigned long)rpc_best_slot,
                     (unsigned long)(rpc_best_slot - manifest_best_slot));
        prefer_rpc = true;
    }

    sol_err_t dl_err = SOL_ERR_NOTFOUND;

    if (prefer_rpc) {
        if (rpc_best_slot != 0) {
            sol_log_info("Auto-downloading latest snapshot from RPC sources (slot %lu)",
                         (unsigned long)rpc_best_slot);
        } else {
            sol_log_info("Auto-downloading latest snapshot from RPC sources");
        }

        dl_err = auto_download_snapshot_archives_from_rpc_urls(
            (char* const*)rpc_urls,
            rpc_url_count,
            archive_dir,
            out_full_path,
            out_full_path_len,
            out_incremental_path,
            out_incremental_path_len,
            io_ctx);

        if (dl_err == SOL_ERR_SHUTDOWN) {
            return dl_err;
        }

        if (dl_err != SOL_OK && have_manifest) {
            sol_log_warn("RPC snapshot download failed (%s); falling back to snapshot service",
                         sol_err_str(dl_err));
            dl_err = auto_download_snapshot_archives(
                manifest_url,
                archive_dir,
                out_full_path,
                out_full_path_len,
                out_incremental_path,
                out_incremental_path_len,
                io_ctx);
        }
    } else {
        if (have_manifest) {
            if (manifest_best_slot != 0) {
                sol_log_info("Auto-downloading latest snapshot from service (slot %lu): %s",
                             (unsigned long)manifest_best_slot,
                             manifest_url);
            } else {
                sol_log_info("Auto-downloading latest snapshot from service: %s", manifest_url);
            }

            dl_err = auto_download_snapshot_archives(
                manifest_url,
                archive_dir,
                out_full_path,
                out_full_path_len,
                out_incremental_path,
                out_incremental_path_len,
                io_ctx);
        }

        if (dl_err == SOL_ERR_SHUTDOWN) {
            return dl_err;
        }

        if (dl_err != SOL_OK && have_rpc) {
            sol_log_warn("Snapshot service download failed (%s); falling back to RPC sources",
                         sol_err_str(dl_err));
            dl_err = auto_download_snapshot_archives_from_rpc_urls(
                (char* const*)rpc_urls,
                rpc_url_count,
                archive_dir,
                out_full_path,
                out_full_path_len,
                out_incremental_path,
                out_incremental_path_len,
                io_ctx);
        }

        /* If the manifest doesn't advertise incremental snapshots, opportunistically
         * fetch the newest incremental snapshot for the downloaded full snapshot
         * base slot from RPC sources. This significantly reduces catchup time on
         * networks where only full snapshots are published via the manifest. */
        if (dl_err == SOL_OK &&
            have_rpc &&
            out_full_path && out_full_path[0] != '\0' &&
            out_incremental_path && out_incremental_path_len > 0 &&
            out_incremental_path[0] == '\0') {
            sol_snapshot_info_t full_info = {0};
            sol_slot_t base_slot = 0;
            if (sol_snapshot_get_info(out_full_path, &full_info) == SOL_OK && full_info.slot != 0) {
                base_slot = full_info.slot;
            }
            if (base_slot != 0) {
                sol_slot_t incr_slot = 0;
                sol_err_t ierr = auto_download_incremental_snapshot_for_base_best_effort(
                    NULL,
                    (char* const*)rpc_urls,
                    rpc_url_count,
                    archive_dir,
                    base_slot,
                    out_incremental_path,
                    out_incremental_path_len,
                    &incr_slot,
                    io_ctx);
                if (ierr == SOL_OK && out_incremental_path[0] != '\0') {
                    sol_log_info("Auto-downloaded incremental snapshot from RPC (base=%lu slot=%lu): %s",
                                 (unsigned long)base_slot,
                                 (unsigned long)(incr_slot ? incr_slot : base_slot),
                                 out_incremental_path);
                } else if (ierr != SOL_OK && ierr != SOL_ERR_NOTFOUND) {
                    sol_log_warn("Incremental snapshot RPC fetch failed (base=%lu): %s",
                                 (unsigned long)base_slot,
                                 sol_err_str(ierr));
                }
            }
        }

        if (dl_err != SOL_OK && have_rpc) {
            sol_log_warn("Snapshot service download failed (%s); trying RPC fallback",
                         sol_err_str(dl_err));
            dl_err = auto_download_snapshot_archives_from_rpc_urls(
                (char* const*)rpc_urls,
                rpc_url_count,
                archive_dir,
                out_full_path,
                out_full_path_len,
                out_incremental_path,
                out_incremental_path_len,
                io_ctx);
        }
    }

    return dl_err;
}

static sol_err_t
auto_download_incremental_snapshot_for_base_best_effort(const char* manifest_url,
                                                        char* const* rpc_urls,
                                                        size_t rpc_url_count,
                                                        const char* archive_dir,
                                                        sol_slot_t base_slot,
                                                        char* out_incremental_path,
                                                        size_t out_incremental_path_len,
                                                        sol_slot_t* out_incremental_slot,
                                                        sol_io_ctx_t* io_ctx) {
    if (!archive_dir || !out_incremental_path || out_incremental_path_len == 0) return SOL_ERR_INVAL;
    out_incremental_path[0] = '\0';
    if (out_incremental_slot) *out_incremental_slot = 0;

    sol_snapshot_download_opts_t opts = SOL_SNAPSHOT_DOWNLOAD_OPTS_DEFAULT;
    opts.allow_incremental = true;
    opts.verify_after = true;
    opts.resume = true;
    opts.output_dir = archive_dir;
    opts.io_ctx = io_ctx;

    if (manifest_url && manifest_url[0] != '\0') {
        sol_available_snapshot_t full = {0};
        sol_available_snapshot_t incr = {0};
        sol_err_t err = sol_snapshot_service_find_best_download(manifest_url, &opts, &full, &incr);
        if (err == SOL_OK &&
            full.type == SOL_SNAPSHOT_FULL &&
            full.slot == base_slot &&
            incr.type == SOL_SNAPSHOT_INCREMENTAL &&
            incr.url &&
            incr.base_slot == base_slot &&
            incr.slot > base_slot) {
            err = sol_snapshot_download(&incr, &opts, out_incremental_path, out_incremental_path_len);
            if (err == SOL_OK && out_incremental_slot) {
                *out_incremental_slot = incr.slot;
            }
            sol_available_snapshot_free(&full);
            sol_available_snapshot_free(&incr);
            return err;
        }

        sol_available_snapshot_free(&full);
        sol_available_snapshot_free(&incr);
    }

    if (rpc_urls && rpc_url_count > 0) {
        sol_available_snapshot_t best_incr = {0};
        bool have_best = false;

        for (size_t i = 0; i < rpc_url_count; i++) {
            const char* rpc_url = rpc_urls[i];
            if (!rpc_url || rpc_url[0] == '\0') continue;

            sol_available_snapshot_t candidates[4];
            memset(candidates, 0, sizeof(candidates));
            size_t n = sol_snapshot_query_available(rpc_url, candidates, 4);
            if (n == 0) {
                sol_available_snapshots_free(candidates, 4);
                continue;
            }

            sol_available_snapshot_t* full = NULL;
            sol_available_snapshot_t* incr = NULL;
            for (size_t j = 0; j < n; j++) {
                if (candidates[j].type == SOL_SNAPSHOT_FULL) full = &candidates[j];
                else if (candidates[j].type == SOL_SNAPSHOT_INCREMENTAL) incr = &candidates[j];
            }

            if (full &&
                full->url &&
                full->slot == base_slot &&
                incr &&
                incr->url &&
                incr->base_slot == base_slot &&
                incr->slot > base_slot) {
                if (!have_best || incr->slot > best_incr.slot) {
                    sol_available_snapshot_free(&best_incr);
                    best_incr = *incr;
                    incr->url = NULL; /* transfer ownership */
                    have_best = true;
                }
            }

            sol_available_snapshots_free(candidates, 4);
        }

        if (have_best && best_incr.url) {
            sol_err_t err = sol_snapshot_download(&best_incr, &opts, out_incremental_path, out_incremental_path_len);
            if (err == SOL_OK && out_incremental_slot) {
                *out_incremental_slot = best_incr.slot;
            }
            sol_available_snapshot_free(&best_incr);
            return err;
        }

        sol_available_snapshot_free(&best_incr);
    }

    return SOL_ERR_NOTFOUND;
}

/* Forward declaration (defined below). */
static volatile sig_atomic_t g_shutdown;

/* After loading a snapshot (full + optional incremental) we may still be far
 * behind cluster head if the configured snapshot service is stale.  Opportunistically
 * fetch and apply a follow-up incremental snapshot whose base slot matches the
 * current bank slot. This avoids downloading a huge newer full snapshot when an
 * incremental-on-top exists via RPC. */
static sol_err_t
validator_maybe_apply_followup_incremental_snapshot(validator_t* v,
                                                    sol_bank_t** io_root_bank,
                                                    sol_slot_t expected_base_slot,
                                                    const char* manifest_url,
                                                    char* const* rpc_urls,
                                                    size_t rpc_url_count,
                                                    const char* archive_dir) {
    if (!v || !io_root_bank || !*io_root_bank || !v->accounts_db || !archive_dir) {
        return SOL_OK;
    }

    const sol_slot_t base_slot = expected_base_slot;
    const sol_slot_t cur_slot = sol_bank_slot(*io_root_bank);
    if (base_slot == 0 || cur_slot == 0) {
        return SOL_OK;
    }
    if (cur_slot < base_slot) {
        return SOL_OK;
    }

    /* Prefer an existing local incremental for this base slot, but try to
     * download a newer one when possible. */
    char local_incr_path[PATH_MAX] = {0};
    sol_slot_t local_incr_slot = 0;
    if (find_best_incremental_snapshot_archive(archive_dir,
                                               base_slot,
                                               local_incr_path,
                                               sizeof(local_incr_path),
                                               &local_incr_slot) != SOL_OK) {
        local_incr_path[0] = '\0';
        local_incr_slot = 0;
    }

    char dl_incr_path[PATH_MAX] = {0};
    sol_slot_t dl_incr_slot = 0;
    if ((manifest_url && manifest_url[0] != '\0') ||
        (rpc_urls && rpc_url_count > 0)) {
        sol_err_t dl_err = auto_download_incremental_snapshot_for_base_best_effort(
            manifest_url,
            rpc_urls,
            rpc_url_count,
            archive_dir,
            base_slot,
            dl_incr_path,
            sizeof(dl_incr_path),
            &dl_incr_slot,
            v->io_ctx);
        if (dl_err == SOL_ERR_SHUTDOWN || g_shutdown) {
            return SOL_ERR_SHUTDOWN;
        }
        if (dl_err != SOL_OK && dl_err != SOL_ERR_NOTFOUND) {
            sol_log_warn("Follow-up incremental snapshot download failed (base=%lu current=%lu): %s",
                         (unsigned long)base_slot,
                         (unsigned long)cur_slot,
                         sol_err_str(dl_err));
            dl_incr_path[0] = '\0';
            dl_incr_slot = 0;
        }
    }

    const char* apply_path = NULL;
    sol_slot_t apply_slot = 0;

    if (dl_incr_path[0] != '\0' && dl_incr_slot > apply_slot) {
        apply_path = dl_incr_path;
        apply_slot = dl_incr_slot;
    }
    if (local_incr_path[0] != '\0' && local_incr_slot > apply_slot) {
        apply_path = local_incr_path;
        apply_slot = local_incr_slot;
    }

    if (!apply_path || apply_slot <= cur_slot) {
        return SOL_OK;
    }

    sol_snapshot_config_t snapshot_cfg = SOL_SNAPSHOT_CONFIG_DEFAULT;
    snapshot_cfg.verify_accounts_hash = g_config.snapshot_verify_accounts_hash;
    snapshot_cfg.io_ctx = v->io_ctx;

    sol_snapshot_mgr_t* snapshot_mgr = sol_snapshot_mgr_new(&snapshot_cfg);
    if (!snapshot_mgr) {
        sol_log_warn("Failed to create snapshot manager for follow-up incremental apply");
        return SOL_OK;
    }

    /* Prefer extracting temp files under the ledger path (large disk). */
    if (g_config.ledger_path) {
        if (mkdir(g_config.ledger_path, 0755) != 0 && errno != EEXIST) {
            sol_log_warn("Failed to create ledger dir %s: %s",
                         g_config.ledger_path, strerror(errno));
        } else {
            struct stat st = {0};
            if (stat(g_config.ledger_path, &st) == 0 && S_ISDIR(st.st_mode)) {
                sol_err_t serr = sol_snapshot_mgr_set_dirs(snapshot_mgr, g_config.ledger_path, NULL);
                if (serr != SOL_OK) {
                    sol_log_warn("Failed to set snapshot dirs: %s", sol_err_str(serr));
                }
            }
        }
    }

    sol_bank_t* new_bank = NULL;
    sol_err_t err = sol_snapshot_apply_incremental_to_accounts_db(snapshot_mgr,
                                                                  apply_path,
                                                                  base_slot,
                                                                  v->accounts_db,
                                                                  &new_bank);
    sol_snapshot_mgr_destroy(snapshot_mgr);

    if (err == SOL_ERR_SHUTDOWN || g_shutdown) {
        return SOL_ERR_SHUTDOWN;
    }

    if (err != SOL_OK || !new_bank) {
        sol_log_warn("Follow-up incremental apply failed (base=%lu current=%lu path=%s): %s",
                     (unsigned long)base_slot,
                     (unsigned long)cur_slot,
                     apply_path,
                     sol_err_str(err));
        if (new_bank) {
            sol_bank_destroy(new_bank);
        }
        return SOL_OK;
    }

    sol_log_info("Follow-up incremental snapshot applied (slot=%lu -> %lu, base=%lu): %s",
                 (unsigned long)cur_slot,
                 (unsigned long)sol_bank_slot(new_bank),
                 (unsigned long)base_slot,
                 apply_path);

    sol_bank_destroy(*io_root_bank);
    *io_root_bank = new_bank;
    return SOL_OK;
}

static int
mkdir_recursive(const char* path) {
    if (!path || *path == '\0') return -1;

    char tmp[PATH_MAX];
    if (strlen(path) >= sizeof(tmp)) return -1;
    snprintf(tmp, sizeof(tmp), "%s", path);

    for (char* p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                return -1;
            }
            *p = '/';
        }
    }

    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        return -1;
    }

    return 0;
}

/*
 * Shutdown flag
 */
static volatile sig_atomic_t g_shutdown = 0;

/*
 * Signal handler
 */
static void
signal_handler(int sig) {
    (void)sig;
    g_shutdown = 1;
}

static void
turbine_shred_callback(void* ctx,
                       const uint8_t* data,
                       size_t len,
                       const sol_sockaddr_t* from) {
    (void)from;
    sol_tvu_t* tvu = (sol_tvu_t*)ctx;
    if (!tvu) return;
    sol_tvu_process_shred(tvu, data, len);
}

static void
turbine_shred_batch_callback(void* ctx,
                             const sol_udp_pkt_t* pkts,
                             int count) {
    sol_tvu_t* tvu = (sol_tvu_t*)ctx;
    if (!tvu || !pkts || count <= 0) return;
    (void)sol_tvu_process_shreds_batch(tvu, pkts, count);
}

static void
repair_shred_callback(const sol_shred_t* shred, void* ctx) {
    sol_tvu_t* tvu = (sol_tvu_t*)ctx;
    if (!tvu || !shred || !shred->raw_data || shred->raw_len == 0) return;
    sol_tvu_process_shred(tvu, shred->raw_data, shred->raw_len);
}

static void*
repair_pump_thread_main(void* arg) {
    validator_t* v = (validator_t*)arg;
    if (!v || !v->repair) return NULL;

    while (!g_shutdown && sol_repair_is_running(v->repair)) {
        sol_err_t err = sol_repair_run_once(v->repair, 0);
        if (err == SOL_ERR_SHUTDOWN) {
            break;
        }
        /* Keep the thread cooperative when there is no work; under load,
         * recvmmsg loops dominate and sched_yield is effectively free. */
        sched_yield();
    }

    return NULL;
}

static void
gossip_value_callback(const sol_crds_value_t* value, void* ctx) {
    validator_t* v = (validator_t*)ctx;
    if (!v || !value || !v->replay) {
        return;
    }

    if (value->type != SOL_CRDS_VOTE) {
        return;
    }

    const sol_crds_vote_t* vote = &value->data.vote;

    /* Ignore votes until we have an epoch stake map, otherwise any vote would
     * incorrectly count as stake=1 and skew fork choice/snapshot verification. */
    if (!v->vote_stakes) {
        return;
    }

    const uint64_t* stake_ptr =
        (const uint64_t*)sol_pubkey_map_get(v->vote_stakes, &vote->from);
    if (!stake_ptr || *stake_ptr == 0) {
        return; /* Unknown / zero-stake vote account */
    }
    uint64_t stake = *stake_ptr;

    (void)sol_replay_record_vote_hash(
        v->replay, &vote->from, vote->slot, &vote->hash, stake);
}

static void
block_producer_slot_callback(void* ctx,
                             sol_slot_t slot,
                             const sol_hash_t* blockhash,
                             uint64_t num_entries,
                             uint64_t num_transactions) {
    (void)blockhash;
    (void)num_entries;
    (void)num_transactions;

    validator_t* v = (validator_t*)ctx;
    if (!v || !v->bank_forks || !v->block_producer) return;

    /* Freeze the completed bank */
    sol_bank_forks_freeze(v->bank_forks, slot);

    /* Create next slot bank and hand it to the block producer */
    sol_bank_t* next = sol_bank_forks_new_from_parent(v->bank_forks, slot, slot + 1);
    if (next) {
        if (v->leader_schedule) {
            const sol_pubkey_t* leader =
                sol_leader_schedule_get_leader(v->leader_schedule, slot + 1);
            if (leader && !sol_pubkey_is_zero(leader)) {
                sol_bank_set_fee_collector(next, leader);
            }
        }
        sol_block_producer_set_bank(v->block_producer, next);
    }
}

static void
block_producer_block_data_callback(void* ctx,
                                   sol_slot_t slot,
                                   const sol_hash_t* blockhash,
                                   const uint8_t* block_data,
                                   size_t block_data_len,
                                   uint64_t num_entries,
                                   uint64_t num_transactions) {
    (void)blockhash;
    (void)num_entries;
    (void)num_transactions;

    validator_t* v = (validator_t*)ctx;
    if (!v || !v->tvu || !block_data || block_data_len == 0) return;

    sol_slot_t parent_slot = (slot > 0) ? (slot - 1) : slot;

    uint32_t shred_index = 0;
    size_t offset = 0;

    while (offset < block_data_len) {
        size_t chunk = block_data_len - offset;
        if (chunk > SOL_SHRED_MAX_DATA_SIZE) {
            chunk = SOL_SHRED_MAX_DATA_SIZE;
        }

        uint8_t flags = 0;
        if (offset + chunk == block_data_len) {
            flags |= SOL_SHRED_FLAG_DATA_COMPLETE;
            flags |= SOL_SHRED_FLAG_LAST_IN_SLOT;
        }

        uint8_t raw[SOL_SHRED_SIZE];
        size_t written = 0;
        sol_err_t err = sol_shred_build_legacy_data(
            &v->identity,
            slot,
            parent_slot,
            shred_index,
            g_config.shred_version, /* version */
            0, /* fec_set_index */
            flags,
            block_data + offset,
            chunk,
            raw,
            sizeof(raw),
            &written
        );
        if (err != SOL_OK) {
            sol_log_warn("Failed to build shred slot=%lu index=%u: %s",
                         (unsigned long)slot, shred_index, sol_err_str(err));
            break;
        }

        /* Feed local TVU for blockstore/replay */
        sol_tvu_process_shred(v->tvu, raw, written);

        /* Broadcast to network (first hop) */
        if (v->turbine) {
            sol_turbine_broadcast_shred(v->turbine, slot, &v->identity_pubkey, raw, written);
        }

        shred_index++;
        offset += chunk;
    }
}

/*
 * Print usage
 */
static void
	print_usage(const char* progname) {
	    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "\n"
        "Solana validator written in pure C\n"
        "\n"
        "Options:\n"
        "  -c, --config PATH         Path to configuration file (TOML format)\n"
        "  -i, --identity PATH       Path to identity keypair\n"
        "  -v, --vote-account PATH   Path to vote account address file\n"
        "  -l, --ledger PATH         Path to ledger directory (default: ./ledger)\n"
        "  --rocksdb-path PATH       Path to RocksDB base directory (defaults to <ledger>/rocksdb when built with RocksDB)\n"
        "  --tower-path PATH         Path to tower persistence file (defaults to <ledger>/tower.bin)\n"
        "  -s, --snapshot PATH       Path to snapshot to load (optional)\n"
        "  --verify-snapshot-accounts-hash Verify snapshot accounts hash at load time (very expensive)\n"
        "  --auto-snapshot-max-lag-slots N  Force fresh snapshot load when persisted AccountsDB lags by >N slots (0=disable; default: 1)\n"
        "  -e, --entrypoint HOST:PORT  Gossip entrypoint (repeatable; defaults to entrypoint.<cluster>.solana.com:8001)\n"
        "  --advertise-ip IP         Public IP to advertise in gossip contact-info (optional)\n"
        "  --shred-version N         Cluster shred version (optional; 0 = auto-discover)\n"
        "  --shred-version-rpc URL   RPC URL for shred version auto-discovery (optional)\n"
        "  --rpc-bind ADDRESS        RPC bind address (default: 127.0.0.1)\n"
        "  --rpc-port PORT           RPC port (default: 8899)\n"
        "  --gossip-port PORT        Gossip port (default: 8001)\n"
        "  --tpu-port PORT           TPU port (default: 8003)\n"
        "  --tvu-port PORT           TVU port (default: 8004)\n"
	        "  --no-quic                 Disable TPU QUIC receiver\n"
	        "  --no-rpc                  Disable RPC server\n"
#ifdef __linux__
	        "  --io-backend BACKEND      IO backend: uring|posix (default: uring; falls back to posix if unavailable)\n"
#else
	        "  --io-backend BACKEND      IO backend: posix|uring (default: posix)\n"
#endif
	        "  --io-queue-depth N        io_uring queue depth (default: 256)\n"
	        "  --io-sqpoll               Enable io_uring SQPOLL submit thread\n"
#ifdef __linux__
	        "  --no-io-uring             Disable io_uring (force POSIX IO)\n"
#endif
        "  --full-owner-index        Build full accounts owner index (slow; improves getProgramAccounts)\n"
        "  --no-voting               Disable voting\n"
        "  --fast-replay             Skip tx processing/exec/signature verify + tx index (unsafe; fastest)\n"
        "  --tx-index                Enable address/signature tx index (enables getSignaturesForAddress; expensive)\n"
        "  --no-tx-index             Disable tx index (default)\n"
        "  --log-level LEVEL         Log level: trace, debug, info, warn, error\n"
        "  --log-format FORMAT       Log format: text, json (default: text)\n"
        "  --log-file PATH           Log to file instead of stderr\n"
        "  --metrics-port PORT       Prometheus metrics port (default: 9090)\n"
        "  --no-metrics              Disable Prometheus metrics\n"
        "  --dev-halt-at-slot SLOT   Halt once SLOT is replayed (dev/testing)\n"
        "  -h, --help                Print this help message\n"
        "  -V, --version             Print version information\n"
        "\n",
        progname
    );
}

/*
 * Print version
 */
static void
print_version(void) {
    printf("solana-validator %s\n", SOLANA_C_VERSION_STRING);
    printf("Built with: GCC/Clang\n");
#if defined(__APPLE__)
    printf("Target: arm64-darwin\n");
#else
    printf("Target: x86_64-linux\n");
#endif

    /* Tower persistence default */
    if ((!g_config.tower_path || g_config.tower_path[0] == '\0') &&
        g_config.ledger_path && g_config.ledger_path[0] != '\0') {
        int n = snprintf(g_default_tower_path, sizeof(g_default_tower_path), "%s/tower.bin", g_config.ledger_path);
        if (n > 0 && (size_t)n < sizeof(g_default_tower_path)) {
            g_config.tower_path = g_default_tower_path;
            sol_log_info("No --tower-path configured; defaulting to %s", g_config.tower_path);
        }
    }
}

static int
config_add_entrypoint(const char* entrypoint) {
    if (!entrypoint || entrypoint[0] == '\0') return 0;

    size_t new_count = g_config.entrypoints_count + 1;
    const char** new_eps =
        sol_realloc((void*)g_config.entrypoints, new_count * sizeof(*new_eps));
    if (!new_eps) {
        sol_log_error("Failed to allocate entrypoints list");
        return -1;
    }

    new_eps[g_config.entrypoints_count] = entrypoint;
    g_config.entrypoints = new_eps;
    g_config.entrypoints_count = new_count;
    return 0;
}

/*
 * Load configuration from file
 */
static int
load_config_file(const char* path) {
    sol_validator_config_t file_config;
    sol_validator_config_init(&file_config);

    sol_err_t err = sol_validator_config_load(path, &file_config);
    if (err != SOL_OK) {
        fprintf(stderr, "Failed to load config file: %s\n", path);
        return -1;
    }

    /* Apply file config (file values override defaults, CLI overrides file) */
    if (file_config.identity_keypair) {
        g_config.identity_path = file_config.identity_keypair;
    }
    if (file_config.vote_account) {
        g_config.vote_account_path = file_config.vote_account;
    }
    if (file_config.ledger_path) {
        g_config.ledger_path = file_config.ledger_path;
    }
    if (file_config.rocksdb_path) {
        g_config.rocksdb_path = file_config.rocksdb_path;
    }
    if (file_config.tower_path) {
        g_config.tower_path = file_config.tower_path;
    }
    if (file_config.snapshot_path) {
        g_config.snapshot_path = file_config.snapshot_path;
    }
    if (file_config.snapshot_manifest_url) {
        g_config.snapshot_manifest_url = file_config.snapshot_manifest_url;
    }
    if (file_config.snapshot_rpc_urls && file_config.snapshot_rpc_urls_count > 0) {
        g_config.snapshot_rpc_urls = file_config.snapshot_rpc_urls;
        g_config.snapshot_rpc_urls_count = file_config.snapshot_rpc_urls_count;
    }
    g_config.snapshot_verify_accounts_hash = file_config.snapshot_verify_accounts_hash;
    g_config.snapshot_max_bootstrap_lag_slots = (sol_slot_t)file_config.snapshot_max_bootstrap_lag_slots;
    if (file_config.advertise_ip) {
        g_config.advertise_ip = file_config.advertise_ip;
    }
    if (file_config.shred_version_rpc_url) {
        g_config.shred_version_rpc_url = file_config.shred_version_rpc_url;
    }
    if (file_config.shred_version) {
        g_config.shred_version = file_config.shred_version;
    }
    if (file_config.entrypoints && file_config.entrypoints_count > 0 &&
        (!g_config.entrypoints || g_config.entrypoints_count == 0)) {
        g_config.entrypoints = (const char**)file_config.entrypoints;
        g_config.entrypoints_count = file_config.entrypoints_count;
    }
    if (file_config.rpc_bind) {
        g_config.rpc_bind = file_config.rpc_bind;
    }
    if (file_config.rpc_port > 0) {
        g_config.rpc_port = file_config.rpc_port;
    }
    if (file_config.gossip_port > 0) {
        g_config.gossip_port = file_config.gossip_port;
    }
    if (file_config.tpu_port > 0) {
        g_config.tpu_port = file_config.tpu_port;
    }
    if (file_config.tvu_port > 0) {
        g_config.tvu_port = file_config.tvu_port;
    }
    g_config.enable_quic = file_config.enable_quic;
    g_config.enable_rpc = file_config.rpc_enable;
    if (file_config.log_level) {
        g_config.log_level = sol_log_level_from_name(file_config.log_level);
    }
    if (file_config.log_format) {
        g_config.log_format = sol_log_format_from_name(file_config.log_format);
    }
    if (file_config.log_file) {
        g_config.log_file = file_config.log_file;
    }
    g_config.enable_metrics = file_config.metrics_enable;
    if (file_config.metrics_port > 0) {
        g_config.metrics_port = file_config.metrics_port;
    }

    return 0;
}

/*
 * Parse command line arguments
 */
static int
parse_args(int argc, char* argv[]) {
    static struct option long_options[] = {
        {"config",       required_argument, 0, 'c'},
        {"identity",     required_argument, 0, 'i'},
        {"vote-account", required_argument, 0, 'v'},
        {"ledger",       required_argument, 0, 'l'},
        {"rocksdb-path", required_argument, 0, 'D'},
        {"tower-path",   required_argument, 0, 'T'},
        {"snapshot",     required_argument, 0, 's'},
        {"verify-snapshot-accounts-hash", no_argument, 0, OPT_VERIFY_SNAPSHOT_ACCOUNTS_HASH},
        {"auto-snapshot-max-lag-slots", required_argument, 0, OPT_AUTO_SNAPSHOT_MAX_LAG_SLOTS},
        {"io-backend",   required_argument, 0, OPT_IO_BACKEND},
        {"io-queue-depth", required_argument, 0, OPT_IO_QUEUE_DEPTH},
        {"io-sqpoll",    no_argument,       0, OPT_IO_SQPOLL},
        {"no-io-uring",  no_argument,       0, OPT_NO_IO_URING},
        {"entrypoint",   required_argument, 0, 'e'},
        {"advertise-ip", required_argument, 0, 'A'},
        {"shred-version", required_argument, 0, 'S'},
        {"shred-version-rpc", required_argument, 0, 'Z'},
        {"rpc-bind",    required_argument, 0, 'b'},
        {"rpc-port",    required_argument, 0, 'p'},
        {"gossip-port", required_argument, 0, 'g'},
        {"tpu-port",    required_argument, 0, 't'},
        {"tvu-port",    required_argument, 0, 'u'},
        {"no-quic",     no_argument,       0, 'Q'},
        {"no-rpc",      no_argument,       0, 'R'},
        {"full-owner-index", no_argument,  0, OPT_FULL_OWNER_INDEX},
        {"no-voting",   no_argument,       0, 'N'},
        {"fast-replay", no_argument,       0, OPT_FAST_REPLAY},
        {"tx-index",    no_argument,       0, OPT_TX_INDEX},
        {"no-tx-index", no_argument,       0, OPT_NO_TX_INDEX},
        {"log-level",   required_argument, 0, 'L'},
        {"log-format",  required_argument, 0, 'F'},
        {"log-file",    required_argument, 0, 'f'},
        {"metrics-port", required_argument, 0, 'M'},
        {"no-metrics",  no_argument,       0, 'm'},
        {"dev-halt-at-slot", required_argument, 0, OPT_DEV_HALT_AT_SLOT},
        {"help",        no_argument,       0, 'h'},
        {"version",     no_argument,       0, 'V'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;

    /* First pass: look for config file */
    while ((opt = getopt_long(argc, argv, "c:i:v:l:s:e:hV", long_options, &option_index)) != -1) {
        if (opt == 'c') {
            g_config.config_file = optarg;
            if (load_config_file(optarg) != 0) {
                return -1;
            }
            break;
        }
    }

    /* Reset getopt */
    optind = 1;

    /* Second pass: CLI options override file config */
    while ((opt = getopt_long(argc, argv, "c:i:v:l:s:e:hV", long_options, &option_index)) != -1) {
        switch (opt) {
        case 'c':
            /* Already handled */
            break;
        case 'i':
            g_config.identity_path = optarg;
            break;
        case 'v':
            g_config.vote_account_path = optarg;
            break;
        case 'l':
            g_config.ledger_path = optarg;
            break;
        case 'D':
            g_config.rocksdb_path = optarg;
            break;
        case 'T':
            g_config.tower_path = optarg;
            break;
        case 's':
            g_config.snapshot_path = optarg;
            break;
        case OPT_VERIFY_SNAPSHOT_ACCOUNTS_HASH:
            g_config.snapshot_verify_accounts_hash = true;
            break;
        case OPT_AUTO_SNAPSHOT_MAX_LAG_SLOTS: {
            errno = 0;
            char* end = NULL;
            unsigned long long v = strtoull(optarg, &end, 10);
            if (errno != 0 || !end || end == optarg) {
                sol_log_error("Invalid --auto-snapshot-max-lag-slots value: %s", optarg);
                return -1;
            }
            while (*end && isspace((unsigned char)*end)) end++;
            if (*end != '\0') {
                sol_log_error("Invalid --auto-snapshot-max-lag-slots value: %s", optarg);
                return -1;
            }
            g_config.snapshot_max_bootstrap_lag_slots = (sol_slot_t)v;
            g_snapshot_max_lag_cli_overridden = true;
            break;
        }
        case OPT_IO_BACKEND:
            if (strcmp(optarg, "posix") == 0) {
                g_config.io_backend = SOL_IO_BACKEND_POSIX;
            } else if (strcmp(optarg, "uring") == 0) {
                g_config.io_backend = SOL_IO_BACKEND_URING;
            } else {
                sol_log_error("Invalid --io-backend value: %s", optarg);
                return -1;
            }
            g_io_backend_cli_overridden = true;
            break;
        case OPT_NO_IO_URING:
            g_config.io_backend = SOL_IO_BACKEND_POSIX;
            g_io_backend_cli_overridden = true;
            break;
        case OPT_IO_QUEUE_DEPTH: {
            errno = 0;
            char* end = NULL;
            unsigned long long v = strtoull(optarg, &end, 10);
            if (errno != 0 || !end || end == optarg) {
                sol_log_error("Invalid --io-queue-depth value: %s", optarg);
                return -1;
            }
            while (*end && isspace((unsigned char)*end)) end++;
            if (*end != '\0' || v == 0 || v > UINT32_MAX) {
                sol_log_error("Invalid --io-queue-depth value: %s", optarg);
                return -1;
            }
            g_config.io_queue_depth = (uint32_t)v;
            break;
        }
        case OPT_IO_SQPOLL:
            g_config.io_sqpoll = true;
            break;
        case 'e':
            if (!g_entrypoints_cli_overridden) {
                /* CLI overrides any config-file entrypoints. */
                g_entrypoints_cli_overridden = true;
                g_config.entrypoints = NULL;
                g_config.entrypoints_count = 0;
            }
            if (config_add_entrypoint(optarg) != 0) {
                return -1;
            }
            break;
        case 'A':
            g_config.advertise_ip = optarg;
            break;
        case 'S':
            g_config.shred_version = (uint16_t)atoi(optarg);
            break;
        case 'Z':
            g_config.shred_version_rpc_url = optarg;
            break;
        case 'b':
            g_config.rpc_bind = optarg;
            break;
        case 'p':
            g_config.rpc_port = (uint16_t)atoi(optarg);
            break;
        case 'g':
            g_config.gossip_port = (uint16_t)atoi(optarg);
            break;
        case 't':
            g_config.tpu_port = (uint16_t)atoi(optarg);
            break;
        case 'u':
            g_config.tvu_port = (uint16_t)atoi(optarg);
            break;
        case 'Q':
            g_config.enable_quic = false;
            break;
        case 'R':
            g_config.enable_rpc = false;
            break;
        case OPT_FULL_OWNER_INDEX:
            g_config.full_owner_index = true;
            break;
        case 'N':
            g_config.no_voting = true;
            break;
        case OPT_FAST_REPLAY:
            g_config.fast_replay = true;
            break;
        case OPT_TX_INDEX:
            g_config.enable_tx_index = true;
            g_tx_index_cli_overridden = true;
            break;
        case OPT_NO_TX_INDEX:
            g_config.enable_tx_index = false;
            g_tx_index_cli_overridden = true;
            break;
        case 'L':
            g_config.log_level = sol_log_level_from_name(optarg);
            break;
        case 'F':
            g_config.log_format = sol_log_format_from_name(optarg);
            break;
        case 'f':
            g_config.log_file = optarg;
            break;
        case 'M':
            g_config.metrics_port = (uint16_t)atoi(optarg);
            break;
        case 'm':
            g_config.enable_metrics = false;
            break;
        case OPT_DEV_HALT_AT_SLOT: {
            errno = 0;
            char* end = NULL;
            unsigned long long v = strtoull(optarg, &end, 10);
            if (errno != 0 || !end || end == optarg) {
                sol_log_error("Invalid --dev-halt-at-slot value: %s", optarg);
                return -1;
            }
            while (*end && isspace((unsigned char)*end)) end++;
            if (*end != '\0') {
                sol_log_error("Invalid --dev-halt-at-slot value: %s", optarg);
                return -1;
            }
            g_config.dev_halt_at_slot = (sol_slot_t)v;
            break;
        }
        case 'h':
            print_usage(argv[0]);
            exit(0);
        case 'V':
            print_version();
            exit(0);
        default:
            print_usage(argv[0]);
            return -1;
        }
    }

    return 0;
}

/*
 * Get current time in seconds
 */
static uint64_t
get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec;
}

static uint64_t monotonic_time_ns(void);
static bool leader_schedule_is_usable(const sol_leader_schedule_t* schedule);

static void
validator_replay_slot_callback(sol_slot_t slot, sol_replay_result_t result, void* ctx) {
    (void)ctx;

    if (g_shutdown) return;
    if (result != SOL_REPLAY_SUCCESS) return;
    if (g_config.dev_halt_at_slot == 0) return;

    /* Be robust to slots with no block: halt once we have replayed at-or-above
     * the target slot. */
    if (slot < g_config.dev_halt_at_slot) return;

    static int triggered = 0;
    int expected = 0;
    if (!__atomic_compare_exchange_n(&triggered,
                                     &expected,
                                     1,
                                     false,
                                     __ATOMIC_RELAXED,
                                     __ATOMIC_RELAXED)) {
        return;
    }

    sol_log_info("Dev halt: reached slot %lu (target=%lu)",
                 (unsigned long)slot,
                 (unsigned long)g_config.dev_halt_at_slot);
    g_shutdown = 1;
}

static const char*
infer_cluster_network_name(void) {
    /* Best-effort heuristics based on configured entrypoint/manifest. */
    for (size_t i = 0; i < g_config.entrypoints_count; i++) {
        const char* ep = g_config.entrypoints ? g_config.entrypoints[i] : NULL;
        if (!ep || ep[0] == '\0') continue;
        if (strstr(ep, "devnet")) return "devnet";
        if (strstr(ep, "testnet")) return "testnet";
        if (strstr(ep, "mainnet")) return "mainnet-beta";
    }
    if (g_config.snapshot_manifest_url) {
        if (strstr(g_config.snapshot_manifest_url, "devnet")) return "devnet";
        if (strstr(g_config.snapshot_manifest_url, "testnet")) return "testnet";
        if (strstr(g_config.snapshot_manifest_url, "mainnet")) return "mainnet-beta";
    }
    return "mainnet-beta";
}

static void
validator_apply_implicit_defaults(void) {
    /* Entry point defaults */
    if (!g_config.entrypoints || g_config.entrypoints_count == 0) {
        const char* network = infer_cluster_network_name();
        if (network && strcmp(network, "devnet") == 0) {
            (void)config_add_entrypoint("entrypoint.devnet.solana.com:8001");
        } else if (network && strcmp(network, "testnet") == 0) {
            (void)config_add_entrypoint("entrypoint.testnet.solana.com:8001");
        } else {
            (void)config_add_entrypoint("entrypoint.mainnet-beta.solana.com:8001");
        }
        if (g_config.entrypoints && g_config.entrypoints_count > 0) {
            sol_log_info("No entrypoint configured; defaulting to %s", g_config.entrypoints[0]);
        }
    }

    /* Snapshot bootstrap defaults:
     *
     * - Prefer snapshot service manifests by default (configured via
     *   snapshots.manifest_url).
     * - Do not implicitly add snapshot RPC URLs when a manifest is present.
     *   Public RPC endpoints are often not optimized for (or may outright
     *   block) large archive downloads, while the snapshot service is tuned
     *   for high-throughput ranged downloads.
     *
     * Operators can still configure snapshots.rpc_urls explicitly for fallback
     * / incremental fetches. */
    if ((!g_config.snapshot_rpc_urls || g_config.snapshot_rpc_urls_count == 0) &&
        (!g_config.snapshot_manifest_url || g_config.snapshot_manifest_url[0] == '\0')) {
        const char* network = infer_cluster_network_name();
        sol_snapshot_source_t src = {0};
        size_t n = sol_snapshot_get_default_sources(network ? network : "mainnet-beta", &src, 1);
        if (n > 0 && src.url && src.url[0] != '\0') {
            g_default_snapshot_rpc_url_owned = src.url;
            g_default_snapshot_rpc_urls[0] = g_default_snapshot_rpc_url_owned;
            g_config.snapshot_rpc_urls = g_default_snapshot_rpc_urls;
            g_config.snapshot_rpc_urls_count = 1;
            sol_log_info("No snapshot manifest configured; defaulting snapshot RPC source to %s",
                         g_default_snapshot_rpc_url_owned);
        } else {
            sol_free(src.url);
        }
    }

    /* Allow tuning the bootstrap refresh threshold via env without needing a flag. */
    if (!g_snapshot_max_lag_cli_overridden) {
        const char* env = getenv("SOL_AUTO_SNAPSHOT_MAX_LAG_SLOTS");
        if (env && env[0] != '\0') {
            errno = 0;
            char* end = NULL;
            unsigned long long v = strtoull(env, &end, 10);
            if (errno == 0 && end && end != env) {
                while (*end && isspace((unsigned char)*end)) end++;
                if (*end == '\0') {
                    g_config.snapshot_max_bootstrap_lag_slots = (sol_slot_t)v;
                    sol_log_info("Auto snapshot bootstrap lag threshold: %lu slots (env SOL_AUTO_SNAPSHOT_MAX_LAG_SLOTS)",
                                 (unsigned long)g_config.snapshot_max_bootstrap_lag_slots);
                }
            }
        }
    }

#ifdef SOL_HAS_ROCKSDB
    /* RocksDB default (production sensible) */
    if ((!g_config.rocksdb_path || g_config.rocksdb_path[0] == '\0') &&
        g_config.ledger_path && g_config.ledger_path[0] != '\0') {
        int n = snprintf(g_default_rocksdb_path, sizeof(g_default_rocksdb_path), "%s/rocksdb", g_config.ledger_path);
        if (n > 0 && (size_t)n < sizeof(g_default_rocksdb_path)) {
            g_config.rocksdb_path = g_default_rocksdb_path;
            sol_log_info("No --rocksdb-path configured; defaulting to %s", g_config.rocksdb_path);
        }
    }
#endif
}

static void
validator_apply_fast_replay(void) {
    if (!g_config.fast_replay) {
        return;
    }

    /* Fast replay is unsafe: it preserves block layout/ticks but skips exec/verification. */
    setenv("SOL_SKIP_TX_PROCESSING", "1", 1);
    setenv("SOL_SKIP_INSTRUCTION_EXEC", "1", 1);
    setenv("SOL_SKIP_SIGNATURE_VERIFY", "1", 1);
    setenv("SOL_SKIP_TX_INDEX", "1", 1);
    setenv("SOL_FAST_REPLAY_FORCE_ADVANCE", "1", 1);

    sol_log_warn("Fast replay enabled: skipping transaction processing, instruction execution, shred/transaction signature verification, and tx index; state will be incorrect");
}

static void
validator_apply_tx_index_defaults(void) {
    if (g_config.fast_replay) {
        /* Fast replay forcibly disables tx indexing; let that code path drive
         * the env var so logs remain consistent. */
        return;
    }

    const char* env = getenv("SOL_SKIP_TX_INDEX");
    if (g_tx_index_cli_overridden) {
        (void)setenv("SOL_SKIP_TX_INDEX", g_config.enable_tx_index ? "0" : "1", 1);
        sol_log_info("TX index: %s (cli)", g_config.enable_tx_index ? "enabled" : "disabled");
        return;
    }

    if (env && env[0] != '\0') {
        bool enabled = (strcmp(env, "0") == 0);
        sol_log_info("TX index: %s (env SOL_SKIP_TX_INDEX=%s)", enabled ? "enabled" : "disabled", env);
        return;
    }

    /* Default: disable tx indexing for replay throughput. Users can enable it
     * explicitly via --tx-index or SOL_SKIP_TX_INDEX=0. */
    (void)setenv("SOL_SKIP_TX_INDEX", "1", 1);
    sol_log_info("TX index: disabled (default; pass --tx-index to enable)");
}

static sol_err_t
validator_fixup_builtin_accounts(validator_t* v, sol_bank_t* root_bank) {
    if (!v || !v->accounts_db || !root_bank) {
        return SOL_OK;
    }

    sol_account_t* before = sol_accounts_db_load(v->accounts_db, &SOL_SYSTEM_PROGRAM_ID);
    sol_lt_hash_t before_hash;
    sol_lt_hash_identity(&before_hash);
    if (before) {
        sol_account_lt_hash(&SOL_SYSTEM_PROGRAM_ID, before, &before_hash);
    }

    sol_err_t ferr = sol_accounts_db_fixup_builtin_program_accounts(v->accounts_db);
    if (ferr != SOL_OK) {
        if (before) sol_account_destroy(before);
        return ferr;
    }

    sol_account_t* after = sol_accounts_db_load(v->accounts_db, &SOL_SYSTEM_PROGRAM_ID);
    sol_lt_hash_t after_hash;
    sol_lt_hash_identity(&after_hash);
    if (after) {
        sol_account_lt_hash(&SOL_SYSTEM_PROGRAM_ID, after, &after_hash);
    }

    bool changed = memcmp(before_hash.v, after_hash.v, sizeof(before_hash.v)) != 0;
    if (changed) {
        bool updated = sol_bank_apply_accounts_lt_hash_delta(root_bank,
                                                             &SOL_SYSTEM_PROGRAM_ID,
                                                             before,
                                                             after);
        if (!updated) {
            sol_log_warn("System Program fixup applied but bank LtHash was not updated; bank hash may be stale");
        } else {
            sol_hash_t new_hash = {0};
            sol_bank_compute_hash(root_bank, &new_hash);
            sol_log_warn("System Program fixup updated bank LtHash; recomputed root bank hash");
        }
    }

    if (before) sol_account_destroy(before);
    if (after) sol_account_destroy(after);
    return SOL_OK;
}

static void
validator_try_raise_fd_limit(void) {
#ifdef RLIMIT_NOFILE
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
        sol_log_debug("getrlimit(RLIMIT_NOFILE) failed: %s", strerror(errno));
        return;
    }

    const rlim_t target = 1000000;
    if (rl.rlim_cur >= target) {
        return;
    }

    rlim_t new_cur = target;
    if (rl.rlim_max != RLIM_INFINITY && new_cur > rl.rlim_max) {
        new_cur = rl.rlim_max;
    }

    if (new_cur <= rl.rlim_cur) {
        sol_log_warn("Open-file limit is low (RLIMIT_NOFILE=%llu max=%llu); consider raising it (ulimit -n)",
                     (unsigned long long)rl.rlim_cur,
                     (unsigned long long)rl.rlim_max);
        return;
    }

    struct rlimit next = rl;
    next.rlim_cur = new_cur;

    if (setrlimit(RLIMIT_NOFILE, &next) == 0) {
        sol_log_info("Raised open-file limit (RLIMIT_NOFILE) to %llu",
                     (unsigned long long)new_cur);
    } else {
        sol_log_warn("Failed to raise open-file limit (RLIMIT_NOFILE) to %llu: %s",
                     (unsigned long long)new_cur,
                     strerror(errno));
    }
#endif
}

static size_t
validator_collect_rpc_urls(const char* out_urls[], size_t max_urls, char** out_owned_url) {
    if (!out_urls || max_urls == 0 || !out_owned_url) return 0;
    *out_owned_url = NULL;

    size_t count = 0;

    if (g_config.shred_version_rpc_url && g_config.shred_version_rpc_url[0] != '\0') {
        out_urls[count++] = g_config.shred_version_rpc_url;
        return count;
    }

    if (g_config.snapshot_rpc_urls && g_config.snapshot_rpc_urls_count > 0) {
        for (size_t i = 0; i < g_config.snapshot_rpc_urls_count && count < max_urls; i++) {
            const char* url = g_config.snapshot_rpc_urls[i];
            if (!url || url[0] == '\0') continue;
            out_urls[count++] = url;
        }
        if (count > 0) {
            return count;
        }
    }

    sol_snapshot_source_t src = {0};
    size_t n = sol_snapshot_get_default_sources(infer_cluster_network_name(), &src, 1);
    if (n > 0 && src.url && src.url[0] != '\0') {
        *out_owned_url = src.url;
        out_urls[count++] = src.url;
    } else {
        sol_free(src.url);
    }

    return count;
}

static void
maybe_autodiscover_shred_version_and_genesis_hash(sol_bank_t* root_bank) {
    const char* rpc_urls[16];
    char* owned_rpc_url = NULL;
    size_t rpc_url_count = validator_collect_rpc_urls(rpc_urls, sizeof(rpc_urls) / sizeof(rpc_urls[0]), &owned_rpc_url);
    if (rpc_url_count == 0) return;

    bool want_shred_version = (g_config.shred_version == 0);
    if (want_shred_version) {
        sol_err_t last_err = SOL_ERR_NOTFOUND;
        const char* last_url = NULL;
        for (size_t i = 0; i < rpc_url_count; i++) {
            const char* rpc_url = rpc_urls[i];
            if (!rpc_url) continue;
            last_url = rpc_url;

            uint16_t sv = 0;
            last_err = sol_rpc_get_cluster_shred_version(rpc_url, 15, &sv);
            if (last_err == SOL_OK && sv != 0) {
                g_config.shred_version = sv;
                sol_log_info("Discovered shred version %u from %s", (unsigned)sv, rpc_url);
                want_shred_version = false;
                break;
            }
        }

        if (want_shred_version && last_url) {
            sol_log_warn("Failed to discover shred version from RPC endpoints (last %s): %s",
                         last_url, sol_err_str(last_err));
        }
    }

    if (root_bank) {
        const sol_hash_t* existing = sol_bank_genesis_hash(root_bank);
        bool want_genesis = !existing || sol_hash_is_zero(existing);
        if (want_genesis) {
            sol_err_t last_err = SOL_ERR_NOTFOUND;
            const char* last_url = NULL;
            for (size_t i = 0; i < rpc_url_count; i++) {
                const char* rpc_url = rpc_urls[i];
                if (!rpc_url) continue;
                last_url = rpc_url;

                char genesis_b58[128] = {0};
                last_err = sol_rpc_get_genesis_hash_base58(
                    rpc_url, 15, genesis_b58, sizeof(genesis_b58));
                if (last_err == SOL_OK && genesis_b58[0] != '\0') {
                    sol_pubkey_t pk = {{0}};
                    sol_err_t derr = sol_pubkey_from_base58(genesis_b58, &pk);
                    if (derr == SOL_OK) {
                        sol_hash_t gh = {0};
                        memcpy(gh.bytes, pk.bytes, SOL_HASH_SIZE);
                        sol_bank_set_genesis_hash(root_bank, &gh);
                        sol_log_info("Set genesis hash from %s", rpc_url);
                        want_genesis = false;
                        break;
                    }
                }
            }

            if (want_genesis && last_url) {
                sol_log_warn("Failed to fetch genesis hash from RPC endpoints (last %s): %s",
                             last_url, sol_err_str(last_err));
            }
        }
    }

    /* Best-effort: persist any auto-discovered cluster constants so fast
     * restarts can run without hitting external RPC endpoints. */
    if (root_bank) {
        sol_accounts_db_t* accounts_db = sol_bank_get_accounts_db(root_bank);
        if (accounts_db) {
            sol_accounts_db_bootstrap_state_t bs = {0};
            if (sol_accounts_db_get_bootstrap_state(accounts_db, &bs)) {
                bool changed = false;

                if (g_config.shred_version != 0 &&
                    ((bs.flags & SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_SHRED_VERSION) == 0 ||
                     bs.shred_version != (uint32_t)g_config.shred_version)) {
                    bs.flags |= SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_SHRED_VERSION;
                    bs.shred_version = (uint32_t)g_config.shred_version;
                    changed = true;
                }

                const sol_hash_t* gh = sol_bank_genesis_hash(root_bank);
                if (gh && !sol_hash_is_zero(gh) &&
                    ((bs.flags & SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_GENESIS_HASH) == 0 ||
                     memcmp(bs.genesis_hash.bytes, gh->bytes, SOL_HASH_SIZE) != 0)) {
                    bs.flags |= SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_GENESIS_HASH;
                    bs.genesis_hash = *gh;
                    changed = true;
                }

                if (changed) {
                    sol_err_t berr = sol_accounts_db_set_bootstrap_state(accounts_db, &bs);
                    if (berr != SOL_OK) {
                        sol_log_warn("Failed to persist updated bootstrap state: %s", sol_err_str(berr));
                    }
                }
            }
        }
    }

    sol_free(owned_rpc_url);
}

static bool
parse_host_port(const char* in, char* host, size_t host_len, uint16_t* port) {
    if (!in || !host || host_len == 0 || !port) {
        return false;
    }

    host[0] = '\0';
    *port = 0;

    if (in[0] == '[') {
        /* Bracketed IPv6: [addr]:port */
        const char* end = strchr(in, ']');
        if (!end || end[1] != ':') return false;
        size_t hlen = (size_t)(end - (in + 1));
        if (hlen == 0 || hlen >= host_len) return false;
        memcpy(host, in + 1, hlen);
        host[hlen] = '\0';
        long p = strtol(end + 2, NULL, 10);
        if (p <= 0 || p > 65535) return false;
        *port = (uint16_t)p;
        return true;
    }

    const char* colon = strrchr(in, ':');
    if (!colon) return false;

    size_t hlen = (size_t)(colon - in);
    if (hlen == 0 || hlen >= host_len) return false;
    memcpy(host, in, hlen);
    host[hlen] = '\0';

    long p = strtol(colon + 1, NULL, 10);
    if (p <= 0 || p > 65535) return false;
    *port = (uint16_t)p;
    return true;
}

static bool
host_is_public_ip(const char* host) {
    if (!host || host[0] == '\0') return false;

    struct in_addr a4;
    if (inet_pton(AF_INET, host, &a4) == 1) {
        uint32_t ip = ntohl(a4.s_addr);

        /* Reject unroutable/localhost/private ranges for bootstrap peer seeding. */
        if ((ip & 0xFF000000u) == 0x0A000000u) return false;         /* 10.0.0.0/8 */
        if ((ip & 0xFFF00000u) == 0xAC100000u) return false;         /* 172.16.0.0/12 */
        if ((ip & 0xFFFF0000u) == 0xC0A80000u) return false;         /* 192.168.0.0/16 */
        if ((ip & 0xFF000000u) == 0x7F000000u) return false;         /* 127.0.0.0/8 */
        if ((ip & 0xFFFF0000u) == 0xA9FE0000u) return false;         /* 169.254.0.0/16 */
        if ((ip & 0xFFC00000u) == 0x64400000u) return false;         /* 100.64.0.0/10 */
        if ((ip & 0xFF000000u) == 0x00000000u) return false;         /* 0.0.0.0/8 */

        if ((ip & 0xF0000000u) == 0xE0000000u) return false;         /* multicast/reserved */

        return true;
    }

    struct in6_addr a6;
    if (inet_pton(AF_INET6, host, &a6) == 1) {
        /* Reject loopback, link-local, and unique-local ranges. */
        static const struct in6_addr loopback = IN6ADDR_LOOPBACK_INIT;
        if (memcmp(&a6, &loopback, sizeof(a6)) == 0) return false;

        if ((a6.s6_addr[0] == 0xfe) && ((a6.s6_addr[1] & 0xc0) == 0x80)) return false; /* fe80::/10 */
        if ((a6.s6_addr[0] & 0xfe) == 0xfc) return false;                               /* fc00::/7 */

        if (a6.s6_addr[0] == 0xff) return false; /* multicast */

        return true;
    }

    /* Not a numeric IP; assume it is a DNS hostname and allow it. */
    return true;
}

static void
maybe_seed_repair_peers_from_rpc(validator_t* v) {
    if (!v || !v->repair) return;

    const char* rpc_urls[16];
    char* owned_rpc_url = NULL;
    size_t rpc_url_count = validator_collect_rpc_urls(rpc_urls, sizeof(rpc_urls) / sizeof(rpc_urls[0]), &owned_rpc_url);
    if (rpc_url_count == 0) return;

    char* json = NULL;
    size_t json_len = 0;
    sol_err_t err = SOL_ERR_NOTFOUND;
    const char* used_rpc_url = NULL;
    for (size_t i = 0; i < rpc_url_count; i++) {
        const char* rpc_url = rpc_urls[i];
        if (!rpc_url || rpc_url[0] == '\0') continue;
        err = sol_rpc_get_cluster_nodes_json(rpc_url, 15, &json, &json_len);
        if (err == SOL_OK && json && json_len > 0) {
            used_rpc_url = rpc_url;
            break;
        }
        sol_free(json);
        json = NULL;
        json_len = 0;
    }

    if (!used_rpc_url) {
        sol_log_warn("Failed to fetch cluster nodes from RPC endpoints: %s", sol_err_str(err));
        sol_free(owned_rpc_url);
        sol_free(json);
        return;
    }

    enum { SOL_REPAIR_SEED_PEERS_MAX = 1024 };
    sol_repair_seed_peer_t peers[SOL_REPAIR_SEED_PEERS_MAX];
    size_t peer_count = 0;

    sol_json_parser_t p;
    sol_json_parser_init(&p, json, json_len);
    if (sol_json_parser_object_begin(&p)) {
        char key[64];
        while (sol_json_parser_key(&p, key, sizeof(key))) {
            if (strcmp(key, "result") != 0) {
                sol_json_parser_skip(&p);
                continue;
            }

            if (!sol_json_parser_array_begin(&p)) {
                sol_json_parser_skip(&p);
                continue;
            }

            while (!sol_json_parser_array_end(&p) && peer_count < SOL_REPAIR_SEED_PEERS_MAX) {
                if (!sol_json_parser_object_begin(&p)) {
                    if (!sol_json_parser_skip(&p)) break;
                    continue;
                }

                char pubkey_str[64] = {0};
                char serve_str[128] = {0};
                bool have_pubkey = false;
                bool have_serve = false;

                char k2[64];
                while (sol_json_parser_key(&p, k2, sizeof(k2))) {
                    if (strcmp(k2, "pubkey") == 0) {
                        if (sol_json_parser_string(&p, pubkey_str, sizeof(pubkey_str))) {
                            have_pubkey = true;
                        } else {
                            sol_json_parser_skip(&p);
                        }
                        continue;
                    }

                    if (strcmp(k2, "serveRepair") == 0) {
                        if (sol_json_parser_string(&p, serve_str, sizeof(serve_str))) {
                            have_serve = true;
                        } else {
                            /* null or unexpected type */
                            sol_json_parser_skip(&p);
                        }
                        continue;
                    }

                    sol_json_parser_skip(&p);
                }

                (void)sol_json_parser_object_end(&p);

                if (!have_pubkey || !have_serve) {
                    continue;
                }

                sol_pubkey_t peer_pk = {{0}};
                if (sol_pubkey_from_base58(pubkey_str, &peer_pk) != SOL_OK) {
                    continue;
                }

                if (sol_pubkey_eq(&peer_pk, &v->identity_pubkey)) {
                    continue;
                }

                char host[256] = {0};
                uint16_t port = 0;
                if (!parse_host_port(serve_str, host, sizeof(host), &port)) {
                    continue;
                }
                if (!host_is_public_ip(host)) {
                    continue;
                }

                sol_sockaddr_t addr;
                if (sol_sockaddr_from_host(host, port, &addr) != SOL_OK) {
                    continue;
                }

                /* De-duplicate by pubkey. */
                bool dup = false;
                for (size_t i = 0; i < peer_count; i++) {
                    if (sol_pubkey_eq(&peers[i].pubkey, &peer_pk)) {
                        dup = true;
                        break;
                    }
                }
                if (dup) continue;

                peers[peer_count].pubkey = peer_pk;
                peers[peer_count].serve_repair_addr = addr;
                peer_count++;
            }
        }
    }

    sol_free(json);

    if (peer_count > 0) {
        (void)sol_repair_set_seed_peers(v->repair, peers, peer_count);
        sol_log_info("Seeded %zu repair peers from %s", peer_count, used_rpc_url);
    } else {
        sol_log_warn("No serveRepair peers found via %s", used_rpc_url);
    }

    sol_free(owned_rpc_url);
}

static bool
maybe_seed_leader_schedule_from_rpc(validator_t* v) {
    if (g_config.fast_replay) {
        return false;
    }

    if (!v || !v->tvu || !v->turbine || !v->bank_forks) return false;

    const char* rpc_urls[16];
    char* owned_rpc_url = NULL;
    size_t rpc_url_count = validator_collect_rpc_urls(rpc_urls, sizeof(rpc_urls) / sizeof(rpc_urls[0]), &owned_rpc_url);
    if (rpc_url_count == 0) return false;

    sol_slot_t root_slot = sol_bank_forks_root_slot(v->bank_forks);
    uint64_t start_slot = (uint64_t)root_slot;
    uint64_t limit = 4096; /* ~27 minutes at 400ms slots */

    sol_pubkey_t* leaders = NULL;
    size_t leaders_len = 0;
    sol_err_t err = SOL_ERR_NOTFOUND;
    const char* used_rpc_url = NULL;
    for (size_t i = 0; i < rpc_url_count; i++) {
        const char* rpc_url = rpc_urls[i];
        if (!rpc_url || rpc_url[0] == '\0') continue;
        err = sol_rpc_get_slot_leaders(rpc_url, 2, start_slot, limit, &leaders, &leaders_len);
        if (err == SOL_OK && leaders && leaders_len > 0) {
            used_rpc_url = rpc_url;
            break;
        }
        sol_free(leaders);
        leaders = NULL;
        leaders_len = 0;
    }

    if (!used_rpc_url) {
        sol_log_warn("Failed to seed leader schedule from RPC endpoints: %s", sol_err_str(err));
        sol_free(owned_rpc_url);
        return false;
    }

    sol_leader_schedule_t* schedule =
        sol_leader_schedule_from_slot_leaders(root_slot, leaders, leaders_len);
    sol_free(leaders);

    if (!schedule) {
        sol_log_warn("Failed to build leader schedule from RPC slot leaders");
        sol_free(owned_rpc_url);
        return false;
    }

    sol_slot_t first = sol_leader_schedule_first_slot(schedule);
    sol_slot_t last = sol_leader_schedule_last_slot(schedule);

    sol_leader_schedule_t* prev = v->leader_schedule;
    sol_leader_schedule_t* old_tvu = sol_tvu_swap_leader_schedule(v->tvu, schedule);
    sol_leader_schedule_t* old_turbine = sol_turbine_swap_leader_schedule(v->turbine, schedule);
    sol_leader_schedule_t* old_replay = NULL;
    if (v->replay) {
        old_replay = sol_replay_swap_leader_schedule(v->replay, schedule);
    }
    sol_leader_schedule_t* old_repair = NULL;
    if (v->repair) {
        old_repair = (sol_leader_schedule_t*)sol_repair_swap_leader_schedule(v->repair, schedule);
    }
    v->leader_schedule = schedule;
    if (v->rpc) {
        sol_rpc_set_leader_schedule(v->rpc, v->leader_schedule);
    }

    sol_leader_schedule_t* to_free[5] = { old_tvu, old_turbine, old_replay, old_repair, prev };
    for (size_t i = 0; i < 5; i++) {
        sol_leader_schedule_t* s = to_free[i];
        if (!s || s == schedule) continue;
        bool seen = false;
        for (size_t j = 0; j < i; j++) {
            if (to_free[j] == s) {
                seen = true;
                break;
            }
        }
        if (!seen) {
            sol_leader_schedule_destroy(s);
        }
    }

    sol_log_info("Leader schedule seeded from %s for slots [%lu..%lu]",
                 used_rpc_url,
                 (unsigned long)first,
                 (unsigned long)last);

    sol_free(owned_rpc_url);
    return true;
}

static void
validator_maybe_refresh_rpc_leader_schedule(validator_t* v) {
    if (g_config.fast_replay) return;
    if (!v || !v->tvu || !v->turbine || !v->bank_forks || !v->replay) return;

    validator_leader_schedule_refresh_t* r = &v->leader_schedule_refresh;
    if (!r->started) return;

    /* Apply any completed refresh without blocking the main loop. */
    sol_leader_schedule_t* ready = NULL;
    char ready_rpc_url[256] = {0};
    pthread_mutex_lock(&r->lock);
    if (r->ready_schedule) {
        ready = r->ready_schedule;
        r->ready_schedule = NULL;
        strncpy(ready_rpc_url, r->ready_rpc_url, sizeof(ready_rpc_url) - 1);
        ready_rpc_url[sizeof(ready_rpc_url) - 1] = '\0';
    }
    pthread_mutex_unlock(&r->lock);

    if (ready) {
        if (!leader_schedule_is_usable(ready)) {
            sol_leader_schedule_destroy(ready);
        } else {
            sol_slot_t first = sol_leader_schedule_first_slot(ready);
            sol_slot_t last = sol_leader_schedule_last_slot(ready);

            sol_leader_schedule_t* prev = v->leader_schedule;
            sol_leader_schedule_t* old_tvu = sol_tvu_swap_leader_schedule(v->tvu, ready);
            sol_leader_schedule_t* old_turbine = sol_turbine_swap_leader_schedule(v->turbine, ready);
            sol_leader_schedule_t* old_replay = sol_replay_swap_leader_schedule(v->replay, ready);
            sol_leader_schedule_t* old_repair = NULL;
            if (v->repair) {
                old_repair = (sol_leader_schedule_t*)sol_repair_swap_leader_schedule(v->repair, ready);
            }
            v->leader_schedule = ready;
            if (v->rpc) {
                sol_rpc_set_leader_schedule(v->rpc, v->leader_schedule);
            }

            sol_leader_schedule_t* to_free[5] = { old_tvu, old_turbine, old_replay, old_repair, prev };
            for (size_t i = 0; i < 5; i++) {
                sol_leader_schedule_t* s = to_free[i];
                if (!s || s == ready) continue;
                bool seen = false;
                for (size_t j = 0; j < i; j++) {
                    if (to_free[j] == s) {
                        seen = true;
                        break;
                    }
                }
                if (!seen) {
                    sol_leader_schedule_destroy(s);
                }
            }

            sol_log_info("Leader schedule refreshed from %s for slots [%lu..%lu]",
                         ready_rpc_url[0] ? ready_rpc_url : "(rpc)",
                         (unsigned long)first,
                         (unsigned long)last);
        }
    }

    /* Throttle refresh requests. */
    uint64_t now_ns = monotonic_time_ns();
    if (r->last_request_ns != 0 &&
        (now_ns - r->last_request_ns) < (5ULL * 1000ULL * 1000ULL * 1000ULL)) {
        return;
    }

    sol_slot_t replay_cursor = sol_replay_highest_replayed_slot(v->replay);
    sol_slot_t desired_start = replay_cursor;
    sol_slot_t desired_end = replay_cursor + 4096;

    if (v->leader_schedule) {
        sol_slot_t first = sol_leader_schedule_first_slot(v->leader_schedule);
        sol_slot_t last = sol_leader_schedule_last_slot(v->leader_schedule);
        if (desired_start >= first && desired_end <= last) {
            return;
        }
    }

    r->last_request_ns = now_ns;

    pthread_mutex_lock(&r->lock);
    if (!r->shutdown) {
        r->requested_start = desired_start;
        r->request_pending = true;
        pthread_cond_signal(&r->cond);
    }
    pthread_mutex_unlock(&r->lock);
}

static sol_leader_schedule_t*
validator_fetch_rpc_leader_schedule(sol_slot_t desired_start,
                                    char* out_rpc_url,
                                    size_t out_rpc_url_len) {
    if (out_rpc_url && out_rpc_url_len > 0) {
        out_rpc_url[0] = '\0';
    }

    const char* rpc_urls[16];
    char* owned_rpc_url = NULL;
    size_t rpc_url_count = validator_collect_rpc_urls(rpc_urls,
                                                     sizeof(rpc_urls) / sizeof(rpc_urls[0]),
                                                     &owned_rpc_url);
    if (rpc_url_count == 0) return NULL;

    const uint64_t start_slot = (uint64_t)desired_start;
    const uint64_t limit = 16384;

    sol_pubkey_t* leaders = NULL;
    size_t leaders_len = 0;
    sol_err_t err = SOL_ERR_NOTFOUND;
    const char* used_rpc_url = NULL;
    for (size_t i = 0; i < rpc_url_count; i++) {
        const char* rpc_url = rpc_urls[i];
        if (!rpc_url || rpc_url[0] == '\0') continue;
        err = sol_rpc_get_slot_leaders(rpc_url, 2, start_slot, limit, &leaders, &leaders_len);
        if (err == SOL_OK && leaders && leaders_len > 0) {
            used_rpc_url = rpc_url;
            break;
        }
        sol_free(leaders);
        leaders = NULL;
        leaders_len = 0;
    }

    if (!used_rpc_url) {
        sol_free(owned_rpc_url);
        return NULL;
    }

    if (out_rpc_url && out_rpc_url_len > 0) {
        strncpy(out_rpc_url, used_rpc_url, out_rpc_url_len - 1);
        out_rpc_url[out_rpc_url_len - 1] = '\0';
    }

    sol_leader_schedule_t* schedule =
        sol_leader_schedule_from_slot_leaders(desired_start, leaders, leaders_len);
    sol_free(leaders);
    sol_free(owned_rpc_url);

    if (!schedule) return NULL;
    if (!leader_schedule_is_usable(schedule)) {
        sol_leader_schedule_destroy(schedule);
        return NULL;
    }

    return schedule;
}

static void*
validator_leader_schedule_refresh_thread(void* arg) {
    validator_t* v = (validator_t*)arg;
    if (!v) return NULL;

    validator_leader_schedule_refresh_t* r = &v->leader_schedule_refresh;

    for (;;) {
        sol_slot_t desired_start = 0;

        pthread_mutex_lock(&r->lock);
        while (!r->shutdown && !r->request_pending) {
            pthread_cond_wait(&r->cond, &r->lock);
        }
        if (r->shutdown) {
            pthread_mutex_unlock(&r->lock);
            break;
        }
        desired_start = r->requested_start;
        r->request_pending = false;
        pthread_mutex_unlock(&r->lock);

        char used_rpc_url[256] = {0};
        sol_leader_schedule_t* schedule =
            validator_fetch_rpc_leader_schedule(desired_start, used_rpc_url, sizeof(used_rpc_url));
        if (!schedule) {
            continue;
        }

        pthread_mutex_lock(&r->lock);
        if (r->shutdown) {
            pthread_mutex_unlock(&r->lock);
            sol_leader_schedule_destroy(schedule);
            break;
        }

        if (r->ready_schedule) {
            sol_leader_schedule_destroy(r->ready_schedule);
        }
        r->ready_schedule = schedule;
        strncpy(r->ready_rpc_url, used_rpc_url, sizeof(r->ready_rpc_url) - 1);
        r->ready_rpc_url[sizeof(r->ready_rpc_url) - 1] = '\0';
        pthread_mutex_unlock(&r->lock);
    }

    return NULL;
}

static void
validator_leader_schedule_refresh_start(validator_t* v) {
    if (!v) return;
    if (g_config.fast_replay) return;

    validator_leader_schedule_refresh_t* r = &v->leader_schedule_refresh;
    if (r->started) return;

    pthread_mutex_lock(&r->lock);
    r->shutdown = false;
    r->request_pending = false;
    r->requested_start = 0;
    r->last_request_ns = 0;
    r->ready_rpc_url[0] = '\0';
    pthread_mutex_unlock(&r->lock);

    if (pthread_create(&r->thread, NULL, validator_leader_schedule_refresh_thread, v) != 0) {
        sol_log_warn("Failed to start leader schedule refresh thread");
        return;
    }

    r->started = true;
}

static void
validator_leader_schedule_refresh_stop(validator_t* v) {
    if (!v) return;

    validator_leader_schedule_refresh_t* r = &v->leader_schedule_refresh;
    if (!r->started) return;

    pthread_mutex_lock(&r->lock);
    r->shutdown = true;
    pthread_cond_signal(&r->cond);
    pthread_mutex_unlock(&r->lock);

    pthread_join(r->thread, NULL);
    r->started = false;

    sol_leader_schedule_t* stale = NULL;
    pthread_mutex_lock(&r->lock);
    stale = r->ready_schedule;
    r->ready_schedule = NULL;
    pthread_mutex_unlock(&r->lock);

    if (stale) {
        sol_leader_schedule_destroy(stale);
    }
}

static bool
sockaddr_to_ipv4(const sol_sockaddr_t* sa, uint32_t* out_addr, uint16_t* out_port) {
    if (!sa || !out_addr || !out_port) return false;
    if (sa->addr.sa.sa_family != AF_INET) return false;
    *out_addr = sa->addr.sin.sin_addr.s_addr;
    *out_port = ntohs(sa->addr.sin.sin_port);
    return true;
}

static bool
validator_resolve_forwarding_target(validator_t* v,
                                    const sol_pubkey_t* leader_pubkey,
                                    uint32_t* out_addr,
                                    uint16_t* out_port) {
    if (!v || !v->gossip || !leader_pubkey || !out_addr || !out_port) return false;

    sol_crds_t* crds = sol_gossip_crds(v->gossip);
    if (!crds) return false;

    const sol_contact_info_t* ci = sol_crds_get_contact_info(crds, leader_pubkey);
    if (!ci) return false;

    const sol_sockaddr_t* sa = sol_contact_info_socket(ci, SOL_SOCKET_TAG_TPU_FORWARDS);
    if (!sa) {
        sa = sol_contact_info_socket(ci, SOL_SOCKET_TAG_TPU);
    }
    if (!sa) return false;

    return sockaddr_to_ipv4(sa, out_addr, out_port);
}

static bool
validator_resolve_vote_forwarding_target(validator_t* v,
                                         const sol_pubkey_t* leader_pubkey,
                                         uint32_t* out_addr,
                                         uint16_t* out_port) {
    if (!v || !v->gossip || !leader_pubkey || !out_addr || !out_port) return false;

    sol_crds_t* crds = sol_gossip_crds(v->gossip);
    if (!crds) return false;

    const sol_contact_info_t* ci = sol_crds_get_contact_info(crds, leader_pubkey);
    if (!ci) return false;

    const sol_sockaddr_t* sa = sol_contact_info_socket(ci, SOL_SOCKET_TAG_TPU_VOTE);
    if (!sa) {
        sa = sol_contact_info_socket(ci, SOL_SOCKET_TAG_TPU);
    }
    if (!sa) return false;

    return sockaddr_to_ipv4(sa, out_addr, out_port);
}

static void
validator_maybe_update_tpu_forwarding(validator_t* v, uint64_t now_ns) {
    if (!v || !v->tpu || !v->gossip || !v->leader_schedule) return;

    static uint64_t last_update_ns = 0;
    const uint64_t min_interval_ns = 200ULL * 1000ULL * 1000ULL; /* 200ms */
    if (last_update_ns != 0 && (now_ns - last_update_ns) < min_interval_ns) {
        return;
    }
    last_update_ns = now_ns;

    sol_slot_t start_slot = v->current_slot + 1;
    /* Avoid forwarding loops by never selecting our own identity as the target. */
    for (sol_slot_t slot = start_slot; slot < start_slot + 32; slot++) {
        const sol_pubkey_t* leader = sol_leader_schedule_get_leader(v->leader_schedule, slot);
        if (!leader || sol_pubkey_is_zero(leader)) continue;
        if (sol_pubkey_eq(leader, &v->identity_pubkey)) continue;

        uint32_t leader_addr = 0;
        uint16_t leader_port = 0;
        if (validator_resolve_forwarding_target(v, leader, &leader_addr, &leader_port)) {
            uint32_t vote_addr = 0;
            uint16_t vote_port = 0;
            (void)validator_resolve_vote_forwarding_target(v, leader, &vote_addr, &vote_port);

            (void)sol_tpu_set_vote_forwarding_target(v->tpu, vote_addr, vote_port);
            (void)sol_tpu_set_leader_mode(v->tpu, false, leader_addr, leader_port);
            return;
        }
    }
}

/*
 * Health check callback
 */
static sol_health_result_t
health_callback(void* ctx) {
    validator_t* v = (validator_t*)ctx;
    sol_health_result_t result = {0};

    if (v == NULL) {
        result.status = SOL_HEALTH_UNHEALTHY;
        result.message = "Validator not initialized";
        return result;
    }

    /* Get current state */
    result.current_slot = v->current_slot;
    result.highest_slot = v->highest_slot;
    result.slots_behind = (v->highest_slot > v->current_slot) ?
                          (v->highest_slot - v->current_slot) : 0;
    result.is_syncing = v->is_syncing;
    /* Voting can be disabled either explicitly via --no-voting or implicitly by
     * omitting/invalid vote account configuration. Report the effective state. */
    result.is_voting = (!g_config.no_voting) && v->vote_account_initialized;
    result.is_leader = v->is_leader;
    result.has_identity = true;
    result.uptime_seconds = get_time_sec() - v->start_time;

    /* Get peer count from gossip */
    if (v->gossip) {
        result.connected_peers = sol_gossip_num_peers(v->gossip);
    }

    /* Get active RPC connections */
    if (v->rpc) {
        sol_rpc_stats_t stats = sol_rpc_stats(v->rpc);
        result.rpc_connections = (uint32_t)stats.active_connections;
    }

    /* Determine health status */
    if (result.slots_behind > 100) {
        result.status = SOL_HEALTH_UNHEALTHY;
        result.message = "Too far behind cluster";
    } else if (result.slots_behind > 10 || result.is_syncing) {
        result.status = SOL_HEALTH_DEGRADED;
        result.message = "Catching up with cluster";
    } else if (result.connected_peers == 0) {
        result.status = SOL_HEALTH_DEGRADED;
        result.message = "No connected peers";
    } else {
        result.status = SOL_HEALTH_OK;
        result.message = "Validator healthy";
    }

    return result;
}

static sol_err_t
rpc_send_transaction(const sol_transaction_t* tx, void* user_data) {
    validator_t* v = (validator_t*)user_data;
    if (!v || !v->tpu || !tx) return SOL_ERR_UNINITIALIZED;
    return sol_tpu_submit(v->tpu, tx);
}

static void
validator_persist_tower_best_effort(validator_t* v) {
    if (!v || !v->tower) return;
    if (g_config.no_voting || !v->vote_account_initialized || !v->tower_initialized) return;
    if (!g_config.tower_path || g_config.tower_path[0] == '\0') return;

    static uint64_t last_log_sec = 0;

    sol_err_t err = sol_tower_save_file(v->tower, g_config.tower_path);
    if (err != SOL_OK) {
        uint64_t now_sec = get_time_sec();
        if (last_log_sec == 0 || now_sec - last_log_sec >= 10) {
            sol_log_warn("Failed to persist tower state to %s: %s",
                         g_config.tower_path, sol_err_str(err));
            last_log_sec = now_sec;
        }
    }
}

static void
validator_maybe_initialize_tower(validator_t* v) {
    if (!v || !v->tower) return;
    if (v->tower_initialized) return;
    if (g_config.no_voting || !v->vote_account_initialized) return;
    if (!g_config.tower_path || g_config.tower_path[0] == '\0') return;

    static uint64_t last_attempt_sec = 0;
    uint64_t now_sec = get_time_sec();
    if (last_attempt_sec != 0 && now_sec - last_attempt_sec < 5) {
        return;
    }
    last_attempt_sec = now_sec;

    /* First try local tower file. */
    sol_err_t err = sol_tower_load_file(v->tower, g_config.tower_path);
    if (err == SOL_OK) {
        v->tower_initialized = true;
        sol_log_info("Loaded tower state: %s", g_config.tower_path);
        return;
    }
    if (err != SOL_ERR_NOTFOUND) {
        sol_log_warn("Failed to load tower state from %s: %s (falling back to on-chain vote state)",
                     g_config.tower_path, sol_err_str(err));
    }

    /* Fallback: initialize from the vote account state in the current root bank. */
    sol_bank_t* root_bank = v->bank_forks ? sol_bank_forks_root(v->bank_forks) : NULL;
    if (!root_bank) {
        sol_log_warn("Cannot initialize tower: root bank unavailable");
        return;
    }

    sol_vote_state_t vote_state;
    err = sol_vote_get_state(root_bank, &v->vote_account, &vote_state);
    if (err != SOL_OK) {
        if (!g_config.no_wait_for_vote) {
            sol_log_info("Waiting for vote account to be available for tower initialization: %s",
                         sol_err_str(err));
        }
        return;
    }

    err = sol_tower_initialize(v->tower, &vote_state);
    if (err != SOL_OK) {
        sol_log_warn("Failed to initialize tower from vote account state: %s", sol_err_str(err));
        return;
    }

    v->tower_initialized = true;

    /* Persist the initialized state so restarts are safe. */
    validator_persist_tower_best_effort(v);
}

/*
 * Initialize validator components
 */
static sol_err_t
validator_init(validator_t* v) {
    memset(v, 0, sizeof(*v));
    v->start_time = get_time_sec();
    v->is_syncing = true;  /* Start in syncing mode */

    pthread_mutex_init(&v->leader_schedule_refresh.lock, NULL);
    pthread_cond_init(&v->leader_schedule_refresh.cond, NULL);
    v->leader_schedule_refresh.ready_rpc_url[0] = '\0';

    sol_io_options_t io_opts = SOL_IO_OPTIONS_DEFAULT;
    io_opts.backend = g_config.io_backend;
    io_opts.queue_depth = g_config.io_queue_depth;
    io_opts.sqpoll = g_config.io_sqpoll;
    v->io_ctx = sol_io_ctx_new(&io_opts);
    if (!v->io_ctx) {
        return SOL_ERR_NOMEM;
    }
    if (g_config.io_backend == SOL_IO_BACKEND_URING &&
        sol_io_ctx_backend(v->io_ctx) != SOL_IO_BACKEND_URING) {
        if (g_io_backend_cli_overridden) {
            sol_log_warn("io_uring requested but unavailable; falling back to POSIX IO");
        } else {
            sol_log_info("io_uring unavailable; falling back to POSIX IO");
        }
    }

    /* Generate or load identity */
    if (g_config.identity_path != NULL) {
        sol_log_info("Loading identity from %s", g_config.identity_path);
        sol_err_t err = sol_ed25519_keypair_load(g_config.identity_path, &v->identity);
        if (err != SOL_OK) {
            sol_log_error("Failed to load identity keypair: %s", sol_err_str(err));
            sol_log_warn("Generating ephemeral identity keypair instead");
            sol_ed25519_keypair_generate(&v->identity);
        }
    } else {
        sol_log_warn("No identity keypair specified, generating ephemeral keypair");
        sol_ed25519_keypair_generate(&v->identity);
    }

    /* Extract pubkey from identity */
    sol_ed25519_pubkey_from_keypair(&v->identity, &v->identity_pubkey);

    char pubkey_str[SOL_PUBKEY_BASE58_LEN];
    sol_pubkey_to_base58(&v->identity_pubkey, pubkey_str, sizeof(pubkey_str));
    sol_log_info("Identity: %s", pubkey_str);

    /* Load vote account address */
    v->vote_account_initialized = false;
    if (g_config.vote_account_path != NULL && !g_config.no_voting) {
        sol_log_info("Loading vote account (path or base58): %s", g_config.vote_account_path);
        sol_err_t err = sol_pubkey_load(g_config.vote_account_path, &v->vote_account);
        if (err != SOL_OK) {
            /* Allow specifying a base58 pubkey string directly in config. */
            err = sol_pubkey_from_base58(g_config.vote_account_path, &v->vote_account);
        }
        if (err != SOL_OK) {
            sol_log_error("Failed to load vote account: %s", sol_err_str(err));
            sol_log_warn("Voting disabled - no valid vote account");
        } else {
            char vote_str[SOL_PUBKEY_BASE58_LEN];
            sol_pubkey_to_base58(&v->vote_account, vote_str, sizeof(vote_str));
            sol_log_info("Vote account: %s", vote_str);

            /* Initialize vote transaction builder */
            sol_vote_tx_builder_init(&v->vote_tx_builder, &v->vote_account, &v->identity);
            v->vote_account_initialized = true;
        }
    } else if (!g_config.no_voting) {
        sol_log_warn("No vote account specified, voting disabled");
    }

    /* Determine RocksDB paths (optional). */
    const char* accounts_db_path = NULL;
    const char* blockstore_db_path = NULL;
    char accounts_rocksdb_path[PATH_MAX] = {0};
    char blockstore_rocksdb_path[PATH_MAX] = {0};

    const char* ledger_root_dir = g_config.ledger_path ? g_config.ledger_path : ".";
    char appendvec_dir[PATH_MAX] = {0};
    const char* appendvec_path = NULL;
    if (ledger_root_dir) {
        int n = snprintf(appendvec_dir, sizeof(appendvec_dir), "%s/accounts", ledger_root_dir);
        if (n > 0 && (size_t)n < sizeof(appendvec_dir)) {
            appendvec_path = appendvec_dir;
        }
    }

    if (g_config.rocksdb_path) {
        if (rocksdb_dir_looks_like_db(g_config.rocksdb_path)) {
            /* Backward-compatible mode: --rocksdb-path points directly at a DB. */
            accounts_db_path = g_config.rocksdb_path;
            int n = snprintf(blockstore_rocksdb_path, sizeof(blockstore_rocksdb_path),
                             "%s_blockstore", g_config.rocksdb_path);
            if (n < 0 || (size_t)n >= sizeof(blockstore_rocksdb_path)) {
                sol_log_error("Blockstore RocksDB path too long");
                return SOL_ERR_INVAL;
            }
            blockstore_db_path = blockstore_rocksdb_path;
        } else {
            /* Preferred mode: treat --rocksdb-path as a base directory. */
            int n1 = snprintf(accounts_rocksdb_path, sizeof(accounts_rocksdb_path),
                              "%s/accounts", g_config.rocksdb_path);
            int n2 = snprintf(blockstore_rocksdb_path, sizeof(blockstore_rocksdb_path),
                              "%s/blockstore", g_config.rocksdb_path);
            if (n1 < 0 || (size_t)n1 >= sizeof(accounts_rocksdb_path) ||
                n2 < 0 || (size_t)n2 >= sizeof(blockstore_rocksdb_path)) {
                sol_log_error("RocksDB path too long");
                return SOL_ERR_INVAL;
            }
            accounts_db_path = accounts_rocksdb_path;
            blockstore_db_path = blockstore_rocksdb_path;
        }

        /* Create directories (best-effort; RocksDB also creates as needed). */
        if (!path_exists(g_config.rocksdb_path)) {
            (void)mkdir_recursive(g_config.rocksdb_path);
        }
        if (accounts_db_path && accounts_db_path != g_config.rocksdb_path) {
            (void)mkdir_recursive(accounts_db_path);
        }
        if (blockstore_db_path) {
            (void)mkdir_recursive(blockstore_db_path);
        }
    }

    /* Initialize blockstore */
    sol_log_info("Initializing blockstore...");
    sol_blockstore_config_t bs_config = SOL_BLOCKSTORE_CONFIG_DEFAULT;
    if (blockstore_db_path) {
        bs_config.storage_type = SOL_BLOCKSTORE_STORAGE_ROCKSDB;
        bs_config.rocksdb_path = blockstore_db_path;
        bs_config.rocksdb_cache_mb = validator_default_blockstore_rocksdb_cache_mb();
        sol_log_info("Blockstore RocksDB cache: %lu MB", (unsigned long)bs_config.rocksdb_cache_mb);
    }
    v->blockstore = sol_blockstore_new(&bs_config);
    if (!v->blockstore) {
        if (errno == EBUSY || errno == EAGAIN) {
            sol_log_error("Blockstore RocksDB appears locked (another validator is using it). "
                          "Stop the other process or use a different --rocksdb-path");
        }
        sol_log_error("Failed to create blockstore");
        return SOL_ERR_IO;
    }

    /* Initialize RPC / health endpoints early so local RPC is available during
     * long snapshot download/extraction/ingestion. */
    v->rpc = NULL;
    v->health = NULL;
    if (g_config.enable_rpc) {
        for (int attempt = 0; attempt < 2; attempt++) {
            sol_log_info("Initializing RPC server on %s:%u...", g_config.rpc_bind, g_config.rpc_port);

            sol_rpc_config_t rpc_config = SOL_RPC_CONFIG_DEFAULT;
            strncpy(rpc_config.bind_address, g_config.rpc_bind, sizeof(rpc_config.bind_address) - 1);
            rpc_config.bind_address[sizeof(rpc_config.bind_address) - 1] = '\0';
            rpc_config.port = g_config.rpc_port;
            rpc_config.ws_port = (g_config.rpc_port < UINT16_MAX) ? (uint16_t)(g_config.rpc_port + 1) : 0;
            rpc_config.enable_health_check = true;

            v->rpc = sol_rpc_new(NULL, &rpc_config);
            if (!v->rpc) {
                sol_log_error("Failed to create RPC server");
                return SOL_ERR_NOMEM;
            }

            sol_rpc_set_blockstore(v->rpc, v->blockstore);
            sol_rpc_set_identity(v->rpc, &v->identity_pubkey);
            sol_rpc_set_send_transaction(v->rpc, rpc_send_transaction, v);
            sol_rpc_set_health_callback(v->rpc, health_callback, v);

            errno = 0;
            sol_err_t err = sol_rpc_start(v->rpc);
            if (err == SOL_OK) {
                g_rpc_port_is_bound = true;
                break;
            }

            sol_rpc_destroy(v->rpc);
            v->rpc = NULL;

            if (err == SOL_ERR_IO && errno == EADDRINUSE && attempt + 1 < 2) {
                sol_log_warn("RPC bind failed (address already in use); selecting new ports and retrying");
                validator_autoselect_default_ports();
                continue;
            }

            sol_log_error("Failed to start RPC: %s", sol_err_str(err));
            return err;
        }
    }

    /* Initialize accounts and root bank (from snapshot or empty genesis) */
    sol_bank_t* root_bank = NULL;
    const char* snapshot_path = g_config.snapshot_path;
    const char* incremental_snapshot_path = NULL;
    char auto_snapshot_path[PATH_MAX] = {0};
    char auto_incremental_snapshot_path[PATH_MAX] = {0};
    char auto_snapshot_refresh_path[PATH_MAX] = {0};
    char auto_incremental_snapshot_refresh_path[PATH_MAX] = {0};
    bool auto_snapshot_bootstrap = false;

    bool have_snapshot_manifest =
        g_config.snapshot_manifest_url && g_config.snapshot_manifest_url[0] != '\0';
    bool have_snapshot_rpc_fallback =
        g_config.snapshot_rpc_urls && g_config.snapshot_rpc_urls_count > 0;
    if (have_snapshot_rpc_fallback) {
        sol_log_info("Snapshot RPC fallback enabled (%lu endpoints)",
                     (unsigned long)g_config.snapshot_rpc_urls_count);
    }

    /* Default: auto-download a full snapshot when no snapshot is provided. */
    if (!snapshot_path && (have_snapshot_manifest || have_snapshot_rpc_fallback)) {
        auto_snapshot_bootstrap = true;
        const char* ledger_dir = g_config.ledger_path ? g_config.ledger_path : ".";

        /* Ensure ledger dir exists (best-effort). */
        if (!path_exists(ledger_dir)) {
            (void)mkdir_recursive(ledger_dir);
        }

        char archive_dir[PATH_MAX];
        int n = snprintf(archive_dir, sizeof(archive_dir), "%s/snapshot-archives", ledger_dir);
        if (n < 0 || (size_t)n >= sizeof(archive_dir)) {
            sol_log_error("Snapshot archive dir path too long");
            return SOL_ERR_INVAL;
        }

        if (!path_exists(archive_dir)) {
            (void)mkdir_recursive(archive_dir);
        }

        /* Prefer a local snapshot as a fallback.
         *
         * If local archives exist, defer refresh/download until after the
         * AccountsDB fast-restart bootstrap-state check so restarts don't block
         * on snapshot downloads. */
        sol_slot_t existing_slot = 0;
        sol_err_t found = find_latest_full_snapshot_archive(
            archive_dir, auto_snapshot_path, sizeof(auto_snapshot_path), &existing_slot);

        if (found == SOL_OK) {
            sol_log_info("Found existing snapshot archive (slot %lu): %s",
                         (unsigned long)existing_slot, auto_snapshot_path);
            snapshot_path = auto_snapshot_path;

            sol_slot_t existing_incr_slot = 0;
            if (find_best_incremental_snapshot_archive(
                    archive_dir, existing_slot,
                    auto_incremental_snapshot_path, sizeof(auto_incremental_snapshot_path),
                    &existing_incr_slot) == SOL_OK) {
                sol_log_info("Found existing incremental snapshot archive (slot %lu): %s",
                             (unsigned long)existing_incr_slot, auto_incremental_snapshot_path);
                incremental_snapshot_path = auto_incremental_snapshot_path;
            }
        }

        /* No local snapshot archives: download now. */
        if (!snapshot_path) {
            sol_err_t dl_err = auto_download_snapshot_archives_best_effort(
                have_snapshot_manifest ? g_config.snapshot_manifest_url : NULL,
                have_snapshot_rpc_fallback ? g_config.snapshot_rpc_urls : NULL,
                have_snapshot_rpc_fallback ? g_config.snapshot_rpc_urls_count : 0,
                archive_dir,
                auto_snapshot_refresh_path,
                sizeof(auto_snapshot_refresh_path),
                auto_incremental_snapshot_refresh_path,
                sizeof(auto_incremental_snapshot_refresh_path),
                v->io_ctx);
            if (dl_err == SOL_ERR_SHUTDOWN) {
                return dl_err;
            }
            if (dl_err == SOL_OK && auto_snapshot_refresh_path[0] != '\0') {
                snapshot_path = auto_snapshot_refresh_path;
                incremental_snapshot_path = NULL;
                if (auto_incremental_snapshot_refresh_path[0] != '\0') {
                    incremental_snapshot_path = auto_incremental_snapshot_refresh_path;
                }
            } else {
                sol_log_error("Auto snapshot download failed (%s) and no local snapshot archives found",
                              sol_err_str(dl_err));
                return dl_err;
            }
        }
	    }

    if (snapshot_path) {
        sol_err_t err = SOL_OK;
        bool used_bootstrap_state = false;
        sol_slot_t best_bootstrap_slot = 0;

        if (auto_snapshot_bootstrap && (have_snapshot_manifest || have_snapshot_rpc_fallback)) {
            sol_slot_t manifest_best_slot = 0;
            sol_slot_t rpc_best_slot = 0;

            if (have_snapshot_manifest) {
                manifest_best_slot = query_snapshot_service_best_slot(g_config.snapshot_manifest_url);
            }
            if (have_snapshot_rpc_fallback) {
                (void)query_rpc_best_slot(g_config.snapshot_rpc_urls,
                                          g_config.snapshot_rpc_urls_count,
                                          &rpc_best_slot);
            }

            bool prefer_rpc = (!have_snapshot_manifest && have_snapshot_rpc_fallback);
            const char* prefer_rpc_env = getenv("SOL_SNAPSHOT_PREFER_RPC_IF_FRESHER");
            bool prefer_rpc_if_fresher =
                (prefer_rpc_env && prefer_rpc_env[0] != '\0' && strcmp(prefer_rpc_env, "0") != 0);

            /* Default: keep bootstrap near the chain head by preferring RPC when
             * the configured manifest is clearly stale.
             *
             * Override via SOL_SNAPSHOT_AUTO_PREFER_RPC_LAG_SLOTS (set to 0 to disable). */
            sol_slot_t auto_prefer_rpc_lag = 5000;
            const char* auto_prefer_rpc_env = getenv("SOL_SNAPSHOT_AUTO_PREFER_RPC_LAG_SLOTS");
            if (auto_prefer_rpc_env && auto_prefer_rpc_env[0] != '\0') {
                errno = 0;
                char* end = NULL;
                unsigned long long lag = strtoull(auto_prefer_rpc_env, &end, 10);
                if (errno == 0 && end && end != auto_prefer_rpc_env) {
                    while (*end && isspace((unsigned char)*end)) end++;
                    if (*end == '\0') {
                        auto_prefer_rpc_lag = (sol_slot_t)lag;
                    }
                }
            }

            if (have_snapshot_manifest && have_snapshot_rpc_fallback && rpc_best_slot != 0) {
                if (prefer_rpc_if_fresher) {
                    if (manifest_best_slot == 0 || rpc_best_slot > manifest_best_slot) {
                        prefer_rpc = true;
                    }
                } else if (!prefer_rpc &&
                           auto_prefer_rpc_lag != 0 &&
                           manifest_best_slot != 0 &&
                           rpc_best_slot > manifest_best_slot &&
                           (rpc_best_slot - manifest_best_slot) > auto_prefer_rpc_lag) {
                    prefer_rpc = true;
                }
            }

            /* For bootstrap target selection, default to the manifest slot when
             * available.  This keeps auto-snapshot-max-lag logic from forcing
             * fresh snapshot loads when the configured snapshot service lags
             * the RPC-reported best slot.
             *
             * Set SOL_SNAPSHOT_TARGET_USE_FRESHEST=1 to explicitly use the
             * freshest known slot (typically RPC). */
            const char* use_freshest_env = getenv("SOL_SNAPSHOT_TARGET_USE_FRESHEST");
            const bool use_freshest_for_target =
                (use_freshest_env && use_freshest_env[0] != '\0' && strcmp(use_freshest_env, "0") != 0);
            if (use_freshest_for_target && rpc_best_slot != 0) {
                if (manifest_best_slot == 0 || rpc_best_slot > manifest_best_slot) {
                    prefer_rpc = true;
                }
            }

            if (manifest_best_slot != 0 && rpc_best_slot != 0 &&
                rpc_best_slot > manifest_best_slot) {
                sol_slot_t lag = rpc_best_slot - manifest_best_slot;
                if (prefer_rpc) {
                    sol_log_warn("Snapshot manifest best slot %lu lags RPC best slot %lu by %lu slots; using RPC for bootstrap target",
                                 (unsigned long)manifest_best_slot,
                                 (unsigned long)rpc_best_slot,
                                 (unsigned long)lag);
                } else {
                    sol_log_info("Snapshot manifest best slot %lu lags RPC best slot %lu by %lu slots; using manifest for bootstrap target (set SOL_SNAPSHOT_PREFER_RPC_IF_FRESHER=1 to force RPC)",
                                 (unsigned long)manifest_best_slot,
                                 (unsigned long)rpc_best_slot,
                                 (unsigned long)lag);
                }
            } else if (manifest_best_slot != 0 && rpc_best_slot != 0 &&
                       manifest_best_slot > rpc_best_slot) {
                sol_log_info("Snapshot manifest best slot %lu is ahead of RPC best slot %lu; using manifest for bootstrap target",
                             (unsigned long)manifest_best_slot,
                             (unsigned long)rpc_best_slot);
            }

            if (prefer_rpc) {
                best_bootstrap_slot = rpc_best_slot;
            } else {
                best_bootstrap_slot = manifest_best_slot ? manifest_best_slot : rpc_best_slot;
            }
        }

        /* Fast restart: if the AccountsDB already contains a persisted bootstrap
         * bank state, use it and skip snapshot extraction/ingestion. */
        if (accounts_db_path) {
            sol_accounts_db_config_t db_config = SOL_ACCOUNTS_DB_CONFIG_DEFAULT;
            db_config.storage_type = SOL_ACCOUNTS_STORAGE_APPENDVEC;
            db_config.rocksdb_path = accounts_db_path;
            db_config.rocksdb_cache_mb = validator_default_accountsdb_rocksdb_cache_mb();
            db_config.appendvec_path = appendvec_path;

            sol_accounts_db_t* existing_db = sol_accounts_db_new(&db_config);
            if (existing_db) {
                sol_accounts_db_set_io_ctx(existing_db, v->io_ctx);
                sol_accounts_db_bootstrap_state_t bs = {0};
                bool has_appendvec_files = appendvec_path ? dir_has_any_regular_file(appendvec_path) : false;
                if (has_appendvec_files &&
                    sol_accounts_db_get_bootstrap_state(existing_db, &bs) &&
                    bs.slot != 0) {
                    if (!bs.hashes_per_tick) {
                        sol_log_warn("AccountsDB bootstrap state is missing hashes_per_tick (old format); "
                                     "attempting to recover it from snapshot archive header");

                        const char* probe_archive = NULL;
                        if (incremental_snapshot_path && incremental_snapshot_path[0] != '\0') {
                            probe_archive = incremental_snapshot_path;
                        } else {
                            probe_archive = snapshot_path;
                        }

                        sol_snapshot_info_t probe_info = {0};
                        sol_slot_t probe_slot = 0;
                        if (probe_archive &&
                            sol_snapshot_get_info(probe_archive, &probe_info) == SOL_OK &&
                            probe_info.slot != 0) {
                            probe_slot = probe_info.slot;
                        }

                        sol_bank_fields_t bank_fields = {0};
                        sol_err_t ferr = SOL_ERR_INVAL;
                        if (probe_archive && probe_slot != 0) {
                            ferr = sol_snapshot_read_bank_fields_from_archive(
                                probe_archive, probe_slot, &bank_fields);
                        }

                        if (ferr == SOL_OK && bank_fields.hashes_per_tick != 0) {
                            bs.hashes_per_tick = bank_fields.hashes_per_tick;
                            sol_err_t uerr = sol_accounts_db_set_bootstrap_state(existing_db, &bs);
                            if (uerr != SOL_OK) {
                                sol_log_warn("Recovered hashes_per_tick=%lu but failed to persist upgraded bootstrap state: %s",
                                             (unsigned long)bs.hashes_per_tick,
                                             sol_err_str(uerr));
                            } else {
                                sol_log_info("Recovered hashes_per_tick=%lu from snapshot archive and upgraded bootstrap state",
                                             (unsigned long)bs.hashes_per_tick);
                            }
                        } else {
                            sol_log_warn("Failed to recover hashes_per_tick from snapshot archive (%s); "
                                         "falling back to full snapshot load",
                                         sol_err_str(ferr));
                            sol_accounts_db_destroy(existing_db);
                            existing_db = NULL;
                        }
	                    }

	                    if (existing_db && bs.hashes_per_tick) {
	                        sol_snapshot_info_t full_info = {0};
	                        sol_slot_t full_slot = bs.slot;
	                        if (sol_snapshot_get_info(snapshot_path, &full_info) == SOL_OK && full_info.slot != 0) {
	                            full_slot = full_info.slot;
	                        }

	                        if (incremental_snapshot_path && incremental_snapshot_path[0] != '\0') {
	                            sol_snapshot_info_t local_incr = {0};
	                            if (sol_snapshot_get_info(incremental_snapshot_path, &local_incr) == SOL_OK &&
	                                local_incr.slot != 0 &&
	                                local_incr.slot > bs.slot) {
	                                sol_log_info("AccountsDB bootstrap state at slot %lu is behind incremental snapshot slot %lu; applying incremental refresh",
	                                             (unsigned long)bs.slot,
	                                             (unsigned long)local_incr.slot);

	                                sol_bank_t* refreshed_bank = NULL;

	                                sol_snapshot_config_t snapshot_cfg = SOL_SNAPSHOT_CONFIG_DEFAULT;
	                                snapshot_cfg.verify_accounts_hash =
	                                    g_config.snapshot_verify_accounts_hash;
	                                snapshot_cfg.io_ctx = v->io_ctx;

	                                sol_snapshot_mgr_t* snapshot_mgr = sol_snapshot_mgr_new(&snapshot_cfg);
	                                if (snapshot_mgr) {
	                                    if (g_config.ledger_path) {
	                                        if (mkdir(g_config.ledger_path, 0755) != 0 && errno != EEXIST) {
	                                            sol_log_warn("Failed to create ledger dir %s: %s",
	                                                         g_config.ledger_path, strerror(errno));
	                                        } else {
	                                            struct stat st = {0};
	                                            if (stat(g_config.ledger_path, &st) == 0 && S_ISDIR(st.st_mode)) {
	                                                sol_err_t serr = sol_snapshot_mgr_set_dirs(
	                                                    snapshot_mgr, g_config.ledger_path, NULL);
	                                                if (serr != SOL_OK) {
	                                                    sol_log_warn("Failed to set snapshot dirs: %s",
	                                                                 sol_err_str(serr));
	                                                }
	                                            }
	                                        }
	                                    }

	                                    sol_err_t rerr =
	                                        sol_snapshot_apply_incremental_to_accounts_db(snapshot_mgr,
	                                                                                      incremental_snapshot_path,
	                                                                                      full_slot,
	                                                                                      existing_db,
	                                                                                      &refreshed_bank);
	                                    sol_snapshot_mgr_destroy(snapshot_mgr);
	                                    snapshot_mgr = NULL;

	                                    if (rerr == SOL_OK && refreshed_bank) {
	                                        root_bank = refreshed_bank;

	                                        if (!g_config.shred_version &&
	                                            (bs.flags & SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_SHRED_VERSION) &&
	                                            bs.shred_version != 0) {
	                                            g_config.shred_version = (uint16_t)bs.shred_version;
	                                            sol_log_info("Using persisted shred version %u from AccountsDB bootstrap state",
	                                                         (unsigned)g_config.shred_version);
	                                        }
	                                        if ((bs.flags & SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_GENESIS_HASH) &&
	                                            !sol_hash_is_zero(&bs.genesis_hash)) {
	                                            sol_bank_set_genesis_hash(root_bank, &bs.genesis_hash);
	                                        }

	                                        v->accounts_db = existing_db;
	                                        used_bootstrap_state = true;
	                                        sol_log_info("Incremental refresh applied (bootstrap=%lu -> %lu)",
	                                                     (unsigned long)bs.slot,
	                                                     (unsigned long)sol_bank_slot(root_bank));
	                                    } else {
	                                        sol_log_warn("Incremental refresh failed (%s); forcing fresh snapshot load",
	                                                     sol_err_str(rerr));
	                                    }
	                                } else {
	                                    sol_log_warn("Failed to create snapshot manager; forcing fresh snapshot load");
	                                }

	                                if (!used_bootstrap_state) {
	                                    sol_accounts_db_destroy(existing_db);
	                                    existing_db = NULL;
	                                }
	                            }
	                        }

		                        if (existing_db && !used_bootstrap_state && best_bootstrap_slot != 0) {
		                            const sol_slot_t max_bootstrap_lag = g_config.snapshot_max_bootstrap_lag_slots;
		                            if (max_bootstrap_lag != 0 &&
		                                best_bootstrap_slot > bs.slot &&
		                                (best_bootstrap_slot - bs.slot) > max_bootstrap_lag) {
	                                sol_log_warn("Persisted AccountsDB bootstrap state lags best snapshot slot by %lu "
	                                             "slots (bootstrap=%lu best=%lu); attempting incremental refresh",
	                                             (unsigned long)(best_bootstrap_slot - bs.slot),
	                                             (unsigned long)bs.slot,
	                                             (unsigned long)best_bootstrap_slot);

	                                sol_bank_t* refreshed_bank = NULL;
	                                bool refreshed = false;

	                                const char* ledger_dir = g_config.ledger_path ? g_config.ledger_path : ".";
	                                char archive_dir[PATH_MAX];
	                                int an = snprintf(archive_dir, sizeof(archive_dir), "%s/snapshot-archives", ledger_dir);
	                                if (an >= 0 && (size_t)an < sizeof(archive_dir)) {
	                                    if (!path_exists(archive_dir)) {
	                                        (void)mkdir_recursive(archive_dir);
	                                    }

		                                    sol_slot_t refresh_base_slot = 0;
		                                    if (bs.slot == full_slot) {
		                                        refresh_base_slot = full_slot;
		                                    } else if (bs.slot > full_slot) {
		                                        sol_slot_t inferred_base = 0;
		                                        char inferred_path[PATH_MAX] = {0};
		                                        if (find_incremental_base_for_bootstrap_slot(archive_dir,
		                                                                                     bs.slot,
		                                                                                     &inferred_base,
		                                                                                     inferred_path,
		                                                                                     sizeof(inferred_path)) == SOL_OK &&
		                                            inferred_base != 0) {
		                                            refresh_base_slot = inferred_base;
		                                            sol_log_info("Inferred bootstrap incremental base slot %lu for slot %lu from %s",
		                                                         (unsigned long)refresh_base_slot,
		                                                         (unsigned long)bs.slot,
		                                                         inferred_path[0] ? inferred_path : "(unknown)");
		                                        } else {
		                                            sol_log_warn("Unable to infer incremental base slot for persisted bootstrap slot %lu; skipping incremental refresh",
		                                                         (unsigned long)bs.slot);
		                                        }
		                                    } else {
		                                        /* Persisted bootstrap state predates the selected full snapshot. */
		                                        sol_log_warn("Persisted bootstrap slot %lu predates selected snapshot full slot %lu; skipping incremental refresh",
		                                                     (unsigned long)bs.slot,
		                                                     (unsigned long)full_slot);
		                                    }

		                                    char incr_path[PATH_MAX] = {0};
		                                    sol_slot_t incr_slot = 0;
		                                    if (refresh_base_slot == 0 ||
		                                        find_best_incremental_snapshot_archive(archive_dir,
		                                                                               refresh_base_slot,
		                                                                               incr_path,
		                                                                               sizeof(incr_path),
		                                                                               &incr_slot) != SOL_OK ||
		                                        incr_slot <= bs.slot) {
		                                        incr_path[0] = '\0';
		                                        incr_slot = 0;
		                                    }

		                                    char dl_incr_path[PATH_MAX] = {0};
		                                    sol_slot_t dl_incr_slot = 0;
		                                    if (refresh_base_slot != 0 &&
		                                        (incr_slot == 0 || incr_slot < best_bootstrap_slot) &&
		                                        (have_snapshot_manifest || have_snapshot_rpc_fallback)) {
		                                        sol_err_t dl_err =
		                                            auto_download_incremental_snapshot_for_base_best_effort(
		                                                have_snapshot_manifest ? g_config.snapshot_manifest_url : NULL,
		                                                have_snapshot_rpc_fallback ? g_config.snapshot_rpc_urls : NULL,
		                                                have_snapshot_rpc_fallback ? g_config.snapshot_rpc_urls_count : 0,
		                                                archive_dir,
		                                                refresh_base_slot,
		                                                dl_incr_path,
		                                                sizeof(dl_incr_path),
		                                                &dl_incr_slot,
		                                                v->io_ctx);
		                                        if (dl_err == SOL_ERR_SHUTDOWN || g_shutdown) {
		                                            sol_accounts_db_destroy(existing_db);
		                                            return SOL_ERR_SHUTDOWN;
		                                        }
		                                        if (dl_err != SOL_OK) {
		                                            dl_incr_path[0] = '\0';
		                                            dl_incr_slot = 0;
		                                        }
		                                    }

		                                    /* Never apply an incremental snapshot that doesn't advance the persisted slot. */
		                                    if (dl_incr_slot <= bs.slot) {
		                                        dl_incr_path[0] = '\0';
		                                        dl_incr_slot = 0;
		                                    }

		                                    const char* apply_incr_path = NULL;
		                                    sol_slot_t apply_incr_slot = 0;
		                                    if (dl_incr_path[0] != '\0' && dl_incr_slot > apply_incr_slot) {
		                                        apply_incr_path = dl_incr_path;
		                                        apply_incr_slot = dl_incr_slot;
		                                    }
		                                    if (incr_path[0] != '\0' && incr_slot > apply_incr_slot) {
		                                        apply_incr_path = incr_path;
		                                        apply_incr_slot = incr_slot;
		                                    }

		                                    if (apply_incr_path && refresh_base_slot != 0 && apply_incr_slot > bs.slot) {
		                                        sol_snapshot_config_t snapshot_cfg = SOL_SNAPSHOT_CONFIG_DEFAULT;
		                                        snapshot_cfg.verify_accounts_hash =
		                                            g_config.snapshot_verify_accounts_hash;
		                                        snapshot_cfg.io_ctx = v->io_ctx;

                                        sol_snapshot_mgr_t* snapshot_mgr = sol_snapshot_mgr_new(&snapshot_cfg);
                                        if (snapshot_mgr) {
                                            if (g_config.ledger_path) {
                                                if (mkdir(g_config.ledger_path, 0755) != 0 && errno != EEXIST) {
                                                    sol_log_warn("Failed to create ledger dir %s: %s",
                                                                 g_config.ledger_path, strerror(errno));
                                                } else {
                                                    struct stat st = {0};
                                                    if (stat(g_config.ledger_path, &st) == 0 && S_ISDIR(st.st_mode)) {
                                                        sol_err_t serr = sol_snapshot_mgr_set_dirs(
                                                            snapshot_mgr, g_config.ledger_path, NULL);
                                                        if (serr != SOL_OK) {
                                                            sol_log_warn("Failed to set snapshot dirs: %s",
                                                                         sol_err_str(serr));
                                                        }
                                                    }
                                                }
                                            }

		                                            sol_err_t rerr =
		                                                sol_snapshot_apply_incremental_to_accounts_db(snapshot_mgr,
		                                                                                              apply_incr_path,
		                                                                                              refresh_base_slot,
		                                                                                              existing_db,
		                                                                                              &refreshed_bank);
		                                            sol_snapshot_mgr_destroy(snapshot_mgr);
		                                            snapshot_mgr = NULL;

                                            if (rerr == SOL_OK && refreshed_bank) {
                                                root_bank = refreshed_bank;

                                                if (!g_config.shred_version &&
                                                    (bs.flags & SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_SHRED_VERSION) &&
                                                    bs.shred_version != 0) {
                                                    g_config.shred_version = (uint16_t)bs.shred_version;
                                                    sol_log_info("Using persisted shred version %u from AccountsDB bootstrap state",
                                                                 (unsigned)g_config.shred_version);
                                                }
                                                if ((bs.flags & SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_GENESIS_HASH) &&
                                                    !sol_hash_is_zero(&bs.genesis_hash)) {
                                                    sol_bank_set_genesis_hash(root_bank, &bs.genesis_hash);
                                                }

                                                v->accounts_db = existing_db;
                                                used_bootstrap_state = true;
                                                refreshed = true;
                                                sol_log_info("Incremental refresh applied (bootstrap=%lu -> %lu)",
                                                             (unsigned long)bs.slot,
                                                             (unsigned long)sol_bank_slot(root_bank));
                                            } else {
                                                if (rerr == SOL_ERR_SNAPSHOT_CORRUPT && apply_incr_path &&
                                                    apply_incr_path[0] != '\0') {
                                                    if (path_parent_is_symlink(apply_incr_path)) {
                                                        sol_log_warn("Not removing corrupt incremental snapshot archive because parent dir is a symlink: %s",
                                                                     apply_incr_path);
                                                    } else {
                                                        sol_log_warn("Removing corrupt incremental snapshot archive: %s",
                                                                     apply_incr_path);
                                                        (void)unlink(apply_incr_path);
                                                    }
                                                }
                                                sol_log_warn("Incremental refresh failed (%s); skipping incremental refresh",
                                                             sol_err_str(rerr));
                                            }
                                        } else {
                                            sol_log_warn("Failed to create snapshot manager; skipping incremental refresh");
                                        }
                                    }
                                }

                                if (!refreshed) {
                                    sol_log_warn("Incremental refresh unavailable; forcing fresh snapshot load (bootstrap=%lu best=%lu)",
                                                 (unsigned long)bs.slot,
                                                 (unsigned long)best_bootstrap_slot);
                                    sol_accounts_db_destroy(existing_db);
                                    existing_db = NULL;
                                }
                            }
                        }

                        if (existing_db && !used_bootstrap_state) {
                            sol_snapshot_info_t expect_full = {0};
                            sol_snapshot_info_t expect_incr = {0};
                            sol_slot_t expected_slot = 0;
                            if (sol_snapshot_get_info(snapshot_path, &expect_full) == SOL_OK && expect_full.slot != 0) {
                                expected_slot = expect_full.slot;
                            }
                            if (incremental_snapshot_path && incremental_snapshot_path[0] != '\0' &&
                                sol_snapshot_get_info(incremental_snapshot_path, &expect_incr) == SOL_OK &&
                                expect_incr.slot != 0) {
                                expected_slot = expect_incr.slot;
                            }

                            if (expected_slot != 0 && bs.slot != expected_slot) {
                                /* If the persisted bootstrap state is BEHIND the selected
                                 * snapshot archive, it may be incompatible (stale/partial) and
                                 * we should fall back to snapshot extraction.
                                 *
                                 * If it is AHEAD, accept it: the node has already applied a
                                 * newer incremental snapshot on a prior run.  Forcing a reload
                                 * would unnecessarily purge a large AppendVec directory. */
                                if (bs.slot < expected_slot) {
                                    sol_log_warn("AccountsDB bootstrap slot %lu lags snapshot archive slot %lu; "
                                                 "forcing fresh snapshot load",
                                                 (unsigned long)bs.slot,
                                                 (unsigned long)expected_slot);
                                    sol_accounts_db_destroy(existing_db);
                                    existing_db = NULL;
                                } else {
                                    sol_log_warn("AccountsDB bootstrap slot %lu is ahead of snapshot archive slot %lu; "
                                                 "using persisted state",
                                                 (unsigned long)bs.slot,
                                                 (unsigned long)expected_slot);
                                }
                            }

                            if (!existing_db) {
                                /* Fall back to snapshot extraction below. */
                            } else {
                                sol_log_info("Using persisted AccountsDB bootstrap state at slot %lu (skipping snapshot load)",
                                             (unsigned long)bs.slot);
                            }

                            if (existing_db) {
                                sol_bank_config_t bank_config = SOL_BANK_CONFIG_DEFAULT;
                            if (bs.ticks_per_slot) bank_config.ticks_per_slot = bs.ticks_per_slot;
                            if (bs.hashes_per_tick) bank_config.hashes_per_tick = bs.hashes_per_tick;
                            if (bs.slots_per_epoch) bank_config.slots_per_epoch = bs.slots_per_epoch;
                            if (bs.lamports_per_signature) bank_config.lamports_per_signature = bs.lamports_per_signature;
                            if (bs.rent_per_byte_year) bank_config.rent_per_byte_year = bs.rent_per_byte_year;
                            if (bs.rent_exemption_threshold) bank_config.rent_exemption_threshold = bs.rent_exemption_threshold;

                            root_bank = sol_bank_new(bs.slot, NULL, existing_db, &bank_config);
                            if (!root_bank) {
                                sol_accounts_db_destroy(existing_db);
                                sol_log_error("Failed to create root bank from persisted bootstrap state");
                                return SOL_ERR_NOMEM;
                            }

                            sol_hash_t bh_hashes[SOL_MAX_RECENT_BLOCKHASHES];
                            uint64_t bh_fees[SOL_MAX_RECENT_BLOCKHASHES];
                            size_t bh_len = 0;
                            bool seeded_blockhash_queue = false;
                            if (sol_accounts_db_get_bootstrap_blockhash_queue(existing_db,
                                                                             bh_hashes,
                                                                             bh_fees,
                                                                             SOL_MAX_RECENT_BLOCKHASHES,
                                                                             &bh_len) &&
                                bh_len > 0) {
                                sol_err_t qerr = sol_bank_set_recent_blockhash_queue(root_bank,
                                                                                     bh_hashes,
                                                                                     bh_fees,
                                                                                     bh_len);
                                if (qerr != SOL_OK) {
                                    sol_log_warn("Failed to seed recent blockhash queue from AccountsDB: %s",
                                                 sol_err_str(qerr));
                                } else {
                                    seeded_blockhash_queue = true;
                                    sol_log_info("Seeded recent blockhash queue from AccountsDB (len=%lu)",
                                                 (unsigned long)bh_len);
                                }
                            }

                            if (!seeded_blockhash_queue) {
                                const char* probe_archive = NULL;
                                if (incremental_snapshot_path && incremental_snapshot_path[0] != '\0') {
                                    probe_archive = incremental_snapshot_path;
                                } else {
                                    probe_archive = snapshot_path;
                                }

                                sol_snapshot_info_t probe_info = {0};
                                if (probe_archive &&
                                    sol_snapshot_get_info(probe_archive, &probe_info) == SOL_OK &&
                                    probe_info.slot != 0 &&
                                    probe_info.slot == bs.slot) {
                                    bh_len = 0;
                                    sol_err_t qerr = sol_snapshot_read_blockhash_queue_from_archive(
                                        probe_archive,
                                        bs.slot,
                                        bh_hashes,
                                        bh_fees,
                                        SOL_MAX_RECENT_BLOCKHASHES,
                                        &bh_len);
                                    if (qerr == SOL_OK && bh_len > 0) {
                                        sol_err_t perr = sol_accounts_db_set_bootstrap_blockhash_queue(existing_db,
                                                                                                       bh_hashes,
                                                                                                       bh_fees,
                                                                                                       bh_len);
                                        if (perr != SOL_OK) {
                                            sol_log_warn("Recovered blockhash queue from snapshot archive but failed to persist it: %s",
                                                         sol_err_str(perr));
                                        }

                                        qerr = sol_bank_set_recent_blockhash_queue(root_bank,
                                                                                   bh_hashes,
                                                                                   bh_fees,
                                                                                   bh_len);
                                        if (qerr != SOL_OK) {
                                            sol_log_warn("Recovered blockhash queue from snapshot archive but failed to seed bank: %s",
                                                         sol_err_str(qerr));
                                        } else {
                                            seeded_blockhash_queue = true;
                                            sol_log_info("Recovered recent blockhash queue from snapshot archive (len=%lu)",
                                                         (unsigned long)bh_len);
                                        }
                                    } else if (qerr != SOL_OK && qerr != SOL_ERR_NOTFOUND) {
                                        sol_log_warn("Failed to recover recent blockhash queue from snapshot archive: %s",
                                                     sol_err_str(qerr));
                                    }
                                }
                            }

                            if (bs.flags & SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_BLOCKHASH) {
                                sol_bank_set_blockhash(root_bank, &bs.blockhash);
                            }
                            if (!g_config.shred_version &&
                                (bs.flags & SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_SHRED_VERSION) &&
                                bs.shred_version != 0) {
                                g_config.shred_version = (uint16_t)bs.shred_version;
                                sol_log_info("Using persisted shred version %u from AccountsDB bootstrap state",
                                             (unsigned)g_config.shred_version);
                            }
                            if ((bs.flags & SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_GENESIS_HASH) &&
                                !sol_hash_is_zero(&bs.genesis_hash)) {
                                sol_bank_set_genesis_hash(root_bank, &bs.genesis_hash);
                            }
                            if (bs.flags & SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_ACCOUNTS_LT_HASH) {
                                sol_bank_set_accounts_lt_hash(root_bank, &bs.accounts_lt_hash);
                            } else {
                                sol_log_warn("No persisted accounts LtHash available for slot %lu; replay/bank-hash may be slow",
                                             (unsigned long)bs.slot);
                            }

                            sol_bank_freeze(root_bank);
                            sol_bank_set_signature_count(root_bank, bs.signature_count);
                            sol_bank_set_parent_slot(root_bank, bs.parent_slot);

                            if (bs.flags & SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_BANK_HASH) {
                                sol_bank_set_parent_bank_hash(root_bank, &bs.parent_bank_hash);
                                sol_bank_set_bank_hash(root_bank, &bs.bank_hash);
                            } else {
                                sol_log_warn("No persisted bank hash available for slot %lu; replay/voting may be incorrect",
                                             (unsigned long)bs.slot);
                            }

                            v->accounts_db = existing_db;
                            used_bootstrap_state = true;

                            sol_err_t idx_err = sol_accounts_db_maybe_build_appendvec_index(existing_db);
                            if (idx_err != SOL_OK) {
                                sol_log_warn("AccountsDB: AppendVec in-memory index build failed; continuing without it: %s",
                                             sol_err_str(idx_err));
                            }
                            }
                        }
                    }
                } else {
                    sol_accounts_db_destroy(existing_db);
                }
            }
        }

        const bool can_auto_redownload = have_snapshot_manifest || have_snapshot_rpc_fallback;
        if (!used_bootstrap_state) {
            if (auto_snapshot_bootstrap && best_bootstrap_slot != 0 && can_auto_redownload) {
                const sol_slot_t max_snapshot_lag = g_config.snapshot_max_bootstrap_lag_slots;
                sol_slot_t effective_slot = snapshot_effective_slot_from_paths(snapshot_path, incremental_snapshot_path);
                if (max_snapshot_lag != 0 &&
                    effective_slot != 0 &&
                    best_bootstrap_slot > effective_slot &&
                    (best_bootstrap_slot - effective_slot) > max_snapshot_lag) {
                    sol_log_warn("Local snapshot archives lag best snapshot slot by %lu slots (local=%lu best=%lu); "
                                 "re-downloading snapshot archives",
                                 (unsigned long)(best_bootstrap_slot - effective_slot),
                                 (unsigned long)effective_slot,
                                 (unsigned long)best_bootstrap_slot);

                    const char* ledger_dir = g_config.ledger_path ? g_config.ledger_path : ".";
                    char archive_dir[PATH_MAX];
                    int n = snprintf(archive_dir, sizeof(archive_dir), "%s/snapshot-archives", ledger_dir);
                    if (n < 0 || (size_t)n >= sizeof(archive_dir)) {
                        sol_log_error("Snapshot archive dir path too long");
                        return SOL_ERR_INVAL;
                    }

                    (void)mkdir_recursive(archive_dir);

                    auto_snapshot_refresh_path[0] = '\0';
                    auto_incremental_snapshot_refresh_path[0] = '\0';

                    sol_err_t dl_err = auto_download_snapshot_archives_best_effort(
                        have_snapshot_manifest ? g_config.snapshot_manifest_url : NULL,
                        have_snapshot_rpc_fallback ? g_config.snapshot_rpc_urls : NULL,
                        have_snapshot_rpc_fallback ? g_config.snapshot_rpc_urls_count : 0,
                        archive_dir,
                        auto_snapshot_refresh_path,
                        sizeof(auto_snapshot_refresh_path),
                        auto_incremental_snapshot_refresh_path,
                        sizeof(auto_incremental_snapshot_refresh_path),
                        v->io_ctx);
                    if (dl_err == SOL_ERR_SHUTDOWN || g_shutdown) {
                        return SOL_ERR_SHUTDOWN;
                    }
                    if (dl_err == SOL_OK && auto_snapshot_refresh_path[0] != '\0') {
                        snprintf(auto_snapshot_path, sizeof(auto_snapshot_path), "%s", auto_snapshot_refresh_path);
                        snprintf(auto_incremental_snapshot_path, sizeof(auto_incremental_snapshot_path),
                                 "%s", auto_incremental_snapshot_refresh_path);
                        snapshot_path = auto_snapshot_path;
                        incremental_snapshot_path = (auto_incremental_snapshot_path[0] != '\0') ?
                                                    auto_incremental_snapshot_path : NULL;
                    } else if (dl_err != SOL_OK) {
                        sol_log_warn("Snapshot archive refresh failed (%s); continuing with existing archives",
                                     sol_err_str(dl_err));
                    }
                }
            }

            if (auto_snapshot_bootstrap) {
                /* Snapshot ingestion expects an empty AccountsDB/AppendVec. If the
                 * on-disk state is stale or partially initialized, purge it so we
                 * don't merge incompatible account versions. */
                if (appendvec_path && dir_has_any_regular_file(appendvec_path)) {
                    if (path_parent_is_symlink(appendvec_path) || path_is_symlink(appendvec_path)) {
                        sol_log_warn("Not removing AppendVec accounts dir because it is (or is under) a symlink: %s",
                                     appendvec_path);
                    } else {
                        sol_log_warn("Removing existing AppendVec accounts dir: %s", appendvec_path);
                        (void)rm_dir_recursive(appendvec_path);
                        (void)mkdir_recursive(appendvec_path);
                    }
                }

                if (accounts_db_path && rocksdb_dir_looks_like_db(accounts_db_path)) {
                    if (path_parent_is_symlink(accounts_db_path) || path_is_symlink(accounts_db_path)) {
                        sol_log_warn("Not removing AccountsDB RocksDB dir because it is (or is under) a symlink: %s",
                                     accounts_db_path);
                    } else {
                        sol_log_warn("Removing existing AccountsDB RocksDB dir: %s", accounts_db_path);
                        (void)rm_dir_recursive(accounts_db_path);
                        (void)mkdir_recursive(accounts_db_path);
                    }
                }
            }

            const int max_attempts = can_auto_redownload ? 2 : 1;

            for (int attempt = 0; attempt < max_attempts; attempt++) {
                sol_log_info("Loading snapshot from %s", snapshot_path);

                sol_snapshot_config_t snapshot_cfg = SOL_SNAPSHOT_CONFIG_DEFAULT;
                snapshot_cfg.verify_accounts_hash = g_config.snapshot_verify_accounts_hash;
                snapshot_cfg.io_ctx = v->io_ctx;

                sol_snapshot_mgr_t* snapshot_mgr = sol_snapshot_mgr_new(&snapshot_cfg);
                if (!snapshot_mgr) {
                    sol_log_error("Failed to create snapshot manager");
                    return SOL_ERR_NOMEM;
                }

                /* Prefer extracting temporary files under the ledger path (usually on a large disk). */
                if (g_config.ledger_path) {
                    if (mkdir(g_config.ledger_path, 0755) != 0 && errno != EEXIST) {
                        sol_log_warn("Failed to create ledger dir %s: %s",
                                     g_config.ledger_path, strerror(errno));
                    } else {
                        struct stat st = {0};
                        if (stat(g_config.ledger_path, &st) == 0 && S_ISDIR(st.st_mode)) {
                            sol_err_t serr = sol_snapshot_mgr_set_dirs(snapshot_mgr, g_config.ledger_path, NULL);
                            if (serr != SOL_OK) {
                                sol_log_warn("Failed to set snapshot dirs: %s", sol_err_str(serr));
                            }
                        }
                    }
                }

                sol_accounts_db_config_t snapshot_db_config = SOL_ACCOUNTS_DB_CONFIG_DEFAULT;
                if (accounts_db_path) {
                    snapshot_db_config.storage_type = SOL_ACCOUNTS_STORAGE_APPENDVEC;
                    snapshot_db_config.rocksdb_path = accounts_db_path;
                    snapshot_db_config.rocksdb_cache_mb = validator_default_accountsdb_rocksdb_cache_mb();
                    snapshot_db_config.appendvec_path = appendvec_path;
                }

                if (auto_snapshot_bootstrap) {
                    err = sol_snapshot_load_full_and_incremental(snapshot_mgr,
                                                                 snapshot_path,
                                                                 incremental_snapshot_path,
                                                                 &snapshot_db_config,
                                                                 &root_bank,
                                                                 &v->accounts_db);
                } else {
                    err = sol_snapshot_load_with_accounts_db_config(snapshot_mgr,
                                                                   snapshot_path,
                                                                   &snapshot_db_config,
                                                                   &root_bank,
                                                                   &v->accounts_db);
                }

                sol_snapshot_mgr_destroy(snapshot_mgr);

                if (err == SOL_ERR_SHUTDOWN || g_shutdown) {
                    return SOL_ERR_SHUTDOWN;
                }

                if (err == SOL_OK) {
                    break;
                }

                if (err != SOL_ERR_SNAPSHOT_CORRUPT || attempt + 1 >= max_attempts ||
                    !can_auto_redownload) {
                    break;
                }

                /* Avoid repeatedly attempting to extract a known-corrupt auto-selected archive. */
                if (snapshot_path == auto_snapshot_path && auto_snapshot_path[0] != '\0') {
                    if (path_parent_is_symlink(snapshot_path)) {
                        sol_log_warn("Not removing snapshot archive because parent dir is a symlink: %s",
                                     snapshot_path);
                    } else {
                        sol_log_warn("Removing corrupt snapshot archive: %s", snapshot_path);
                        (void)unlink(snapshot_path);
                    }
                }
                if (incremental_snapshot_path == auto_incremental_snapshot_path &&
                    auto_incremental_snapshot_path[0] != '\0') {
                    if (path_parent_is_symlink(incremental_snapshot_path)) {
                        sol_log_warn("Not removing incremental snapshot archive because parent dir is a symlink: %s",
                                     incremental_snapshot_path);
                    } else {
                        sol_log_warn("Removing corrupt incremental snapshot archive: %s",
                                     incremental_snapshot_path);
                        (void)unlink(incremental_snapshot_path);
                    }
                    auto_incremental_snapshot_path[0] = '\0';
                    incremental_snapshot_path = NULL;
                }

                sol_log_warn("Snapshot load failed (%s); re-downloading snapshot archives and retrying",
                             sol_err_str(err));

                const char* ledger_dir = g_config.ledger_path ? g_config.ledger_path : ".";
                char archive_dir[PATH_MAX];
                int n = snprintf(archive_dir, sizeof(archive_dir), "%s/snapshot-archives", ledger_dir);
                if (n < 0 || (size_t)n >= sizeof(archive_dir)) {
                    sol_log_error("Snapshot archive dir path too long");
                    return SOL_ERR_INVAL;
                }

                if (!path_exists(archive_dir)) {
                    (void)mkdir_recursive(archive_dir);
                }

                auto_snapshot_path[0] = '\0';
                auto_incremental_snapshot_path[0] = '\0';

                sol_err_t dl_err = auto_download_snapshot_archives_best_effort(
                    have_snapshot_manifest ? g_config.snapshot_manifest_url : NULL,
                    have_snapshot_rpc_fallback ? g_config.snapshot_rpc_urls : NULL,
                    have_snapshot_rpc_fallback ? g_config.snapshot_rpc_urls_count : 0,
                    archive_dir,
                    auto_snapshot_path,
                    sizeof(auto_snapshot_path),
                    auto_incremental_snapshot_path,
                    sizeof(auto_incremental_snapshot_path),
                    v->io_ctx);
                if (dl_err == SOL_ERR_SHUTDOWN || g_shutdown) {
                    return SOL_ERR_SHUTDOWN;
                }

                if (dl_err != SOL_OK) {
                    sol_log_error("Auto snapshot re-download failed: %s", sol_err_str(dl_err));
                    return dl_err;
                }

                snapshot_path = auto_snapshot_path;
                incremental_snapshot_path = (auto_incremental_snapshot_path[0] != '\0') ?
                                            auto_incremental_snapshot_path : NULL;
                auto_snapshot_bootstrap = true;
            }
        }

        if (err != SOL_OK) {
            sol_log_error("Failed to load snapshot: %s", sol_err_str(err));
            return err;
        }

        /* Opportunistic: apply a follow-up incremental snapshot on top of the
         * loaded bank when possible (usually via RPC). This helps when the
         * snapshot service is stale but an incremental-on-top exists. */
        if (auto_snapshot_bootstrap && (have_snapshot_manifest || have_snapshot_rpc_fallback)) {
            const char* ledger_dir = g_config.ledger_path ? g_config.ledger_path : ".";
            char archive_dir[PATH_MAX];
            int n = snprintf(archive_dir, sizeof(archive_dir), "%s/snapshot-archives", ledger_dir);
            if (n > 0 && (size_t)n < sizeof(archive_dir)) {
                if (!path_exists(archive_dir)) {
                    (void)mkdir_recursive(archive_dir);
                }

                /* Incremental snapshots are taken relative to a full snapshot base slot.
                 * After loading full(+incr), try to fetch and apply a newer incremental
                 * for the same full base slot (when available). */
                sol_slot_t follow_base_slot = 0;
                if (incremental_snapshot_path && incremental_snapshot_path[0] != '\0') {
                    sol_snapshot_info_t ii = {0};
                    if (sol_snapshot_get_info(incremental_snapshot_path, &ii) == SOL_OK &&
                        ii.base_slot != 0) {
                        follow_base_slot = ii.base_slot;
                    }
                }
                if (follow_base_slot == 0 && snapshot_path) {
                    sol_snapshot_info_t fi = {0};
                    if (sol_snapshot_get_info(snapshot_path, &fi) == SOL_OK && fi.slot != 0) {
                        follow_base_slot = fi.slot;
                    }
                }

                if (follow_base_slot != 0) {
                    sol_err_t ferr = validator_maybe_apply_followup_incremental_snapshot(
                        v,
                        &root_bank,
                        follow_base_slot,
                        have_snapshot_manifest ? g_config.snapshot_manifest_url : NULL,
                        have_snapshot_rpc_fallback ? g_config.snapshot_rpc_urls : NULL,
                        have_snapshot_rpc_fallback ? g_config.snapshot_rpc_urls_count : 0,
                        archive_dir);
                    if (ferr == SOL_ERR_SHUTDOWN || g_shutdown) {
                        return SOL_ERR_SHUTDOWN;
                    }
                }

                /* Hop onto a newer base slot when possible. It is common for
                 * snapshot services to publish an incremental that lands on a
                 * slot which is itself a full snapshot base on RPC. Applying
                 * a base-matching incremental for that slot avoids replaying
                 * tens of minutes of history without downloading another full
                 * snapshot archive. */
                enum { SOL_FOLLOWUP_INCREMENTAL_HOPS_MAX = 2 };
                for (int hop = 0; hop < SOL_FOLLOWUP_INCREMENTAL_HOPS_MAX; hop++) {
                    sol_slot_t base = root_bank ? sol_bank_slot(root_bank) : 0;
                    if (base == 0) {
                        break;
                    }
                    sol_err_t herr = validator_maybe_apply_followup_incremental_snapshot(
                        v,
                        &root_bank,
                        base,
                        have_snapshot_manifest ? g_config.snapshot_manifest_url : NULL,
                        have_snapshot_rpc_fallback ? g_config.snapshot_rpc_urls : NULL,
                        have_snapshot_rpc_fallback ? g_config.snapshot_rpc_urls_count : 0,
                        archive_dir);
                    if (herr == SOL_ERR_SHUTDOWN || g_shutdown) {
                        return SOL_ERR_SHUTDOWN;
                    }
                    sol_slot_t after = root_bank ? sol_bank_slot(root_bank) : 0;
                    if (after <= base) {
                        break;
                    }
                }
            }
        }

        v->current_slot = sol_bank_slot(root_bank);
        v->highest_slot = v->current_slot;
        v->is_syncing = false;

        v->snapshot_start_slot = v->current_slot;
        v->snapshot_start_hash = (sol_hash_t){0};
        sol_bank_compute_hash(root_bank, &v->snapshot_start_hash);
        v->snapshot_verified = g_config.no_voting;
        v->last_snapshot_verify_ns = 0;
    } else {
        /* Initialize accounts database */
        sol_log_info("Initializing accounts database...");
        sol_accounts_db_config_t db_config = SOL_ACCOUNTS_DB_CONFIG_DEFAULT;
        if (accounts_db_path) {
            db_config.storage_type = SOL_ACCOUNTS_STORAGE_APPENDVEC;
            db_config.rocksdb_path = accounts_db_path;
            db_config.rocksdb_cache_mb = validator_default_accountsdb_rocksdb_cache_mb();
            db_config.appendvec_path = appendvec_path;
        }

        v->accounts_db = sol_accounts_db_new(&db_config);
        if (!v->accounts_db) {
            sol_log_error("Failed to create accounts database");
            return SOL_ERR_NOMEM;
        }
        sol_accounts_db_set_io_ctx(v->accounts_db, v->io_ctx);

        /* Initialize root bank */
        sol_log_info("Initializing root bank...");
        sol_hash_t genesis_hash = {0};  /* Would come from genesis */
        sol_bank_config_t bank_config = SOL_BANK_CONFIG_DEFAULT;
        root_bank = sol_bank_new(0, &genesis_hash, v->accounts_db, &bank_config);
        if (!root_bank) {
            sol_log_error("Failed to create root bank");
            return SOL_ERR_NOMEM;
        }

        v->snapshot_start_slot = 0;
        v->snapshot_start_hash = (sol_hash_t){0};
        v->snapshot_verified = true;
        v->last_snapshot_verify_ns = 0;
    }

    /* Ensure builtin program accounts are present and update bank LtHash if needed. */
    {
        sol_err_t fixerr = validator_fixup_builtin_accounts(v, root_bank);
        if (fixerr != SOL_OK) {
            sol_log_error("Builtin program fixup failed: %s", sol_err_str(fixerr));
            return fixerr;
        }
    }

    /* Ensure a minimal owner index is available for replay/consensus.
     * A full owner index is optional (slow to build) and primarily improves
     * RPC program-account queries. */
    if (v->accounts_db) {
        bool wal_disabled = false;
        bool bulk_load_mode = false;

        if (sol_accounts_db_set_disable_wal(v->accounts_db, true) == SOL_OK) {
            wal_disabled = true;
        }
        if (sol_accounts_db_set_bulk_load_mode(v->accounts_db, true) == SOL_OK) {
            bulk_load_mode = true;
        }

        if (g_config.enable_rpc && !g_config.full_owner_index) {
            sol_log_info("RPC owner index: core (stake+vote); pass --full-owner-index for faster getProgramAccounts");
        }

        sol_err_t idx_err = g_config.full_owner_index
            ? sol_accounts_db_ensure_owner_index(v->accounts_db)
            : sol_accounts_db_ensure_core_owner_index(v->accounts_db);

        if (wal_disabled) {
            (void)sol_accounts_db_set_disable_wal(v->accounts_db, false);
        }
        if (bulk_load_mode) {
            (void)sol_accounts_db_set_bulk_load_mode(v->accounts_db, false);
        }

        if (idx_err != SOL_OK) {
            sol_log_error("Failed to build accounts owner index: %s", sol_err_str(idx_err));
            return idx_err;
        }
    }

    /* Performance: during bootstrap/catchup, prioritize throughput over
     * durability for the AccountsDB RocksDB index. This can materially reduce
     * replay latency on disk-heavy workloads.
     *
     * NOTE: Disabling WAL means recent index updates may be lost on crash; the
     * node can recover by reloading a snapshot. */
    if (v->accounts_db) {
        bool wal_disabled = (sol_accounts_db_set_disable_wal(v->accounts_db, true) == SOL_OK);
        bool bulk_enabled = (sol_accounts_db_set_bulk_load_mode(v->accounts_db, true) == SOL_OK);
        if (wal_disabled || bulk_enabled) {
            sol_log_info("AccountsDB index mode: wal=%s bulk=%s",
                         wal_disabled ? "disabled" : "default",
                         bulk_enabled ? "enabled" : "default");
        }
    }

    /* Auto-discover gossip shred version and genesis hash when not configured. */
    maybe_autodiscover_shred_version_and_genesis_hash(root_bank);

    sol_bank_forks_config_t forks_config = SOL_BANK_FORKS_CONFIG_DEFAULT;
    sol_log_info("Initializing bank forks...");
    v->bank_forks = sol_bank_forks_new(root_bank, &forks_config);
    if (!v->bank_forks) {
        sol_log_error("Failed to create bank forks");
        sol_bank_destroy(root_bank);
        return SOL_ERR_NOMEM;
    }
    if (v->rpc) {
        sol_rpc_set_bank_forks(v->rpc, v->bank_forks);
    }

    /* Initialize replay stage */
    sol_log_info("Initializing replay stage...");
    sol_replay_config_t replay_config = SOL_REPLAY_CONFIG_DEFAULT;
    v->replay = sol_replay_new(v->bank_forks, v->blockstore, &replay_config);
    if (!v->replay) {
        sol_log_error("Failed to create replay stage");
        return SOL_ERR_NOMEM;
    }
    sol_replay_set_callback(v->replay, validator_replay_slot_callback, v);
    if (g_config.dev_halt_at_slot > 0) {
        sol_log_info("Dev halt armed at slot %lu", (unsigned long)g_config.dev_halt_at_slot);
    }

    /* Seed epoch-scoped caches immediately so gossip vote weighting is correct
     * from the first packet (snapshot verification + fork choice). */
    validator_refresh_epoch_caches(v, sol_bank_forks_root(v->bank_forks));

    /* Snapshot download/ingestion can take minutes; ports may become occupied
     * after initial startup checks (e.g. a second validator process). Re-run
     * auto-selection right before binding sockets to avoid spurious EADDRINUSE. */
    validator_autoselect_default_ports();

    /* Initialize gossip */
    for (int attempt = 0; attempt < 2; attempt++) {
        sol_log_info("Initializing gossip on port %u...", g_config.gossip_port);

        sol_gossip_config_t gossip_config = SOL_GOSSIP_CONFIG_DEFAULT;
        gossip_config.gossip_port = g_config.gossip_port;
        gossip_config.identity = v->identity;
        gossip_config.shred_version = g_config.shred_version;
        gossip_config.advertise_ip = g_config.advertise_ip;
        gossip_config.tpu_port = (uint16_t)(g_config.tpu_port + SOL_TPU_PORT_OFFSET);
        gossip_config.tpu_quic_port = g_config.enable_quic ?
            (uint16_t)(g_config.tpu_port + SOL_TPU_QUIC_PORT_OFFSET) : 0;
        gossip_config.tvu_port = g_config.tvu_port;
        gossip_config.serve_repair_port = (uint16_t)(g_config.tvu_port + 2);
        gossip_config.rpc_port = g_config.enable_rpc ? g_config.rpc_port : 0;

        errno = 0;
        v->gossip = sol_gossip_new(&gossip_config);
        if (v->gossip) break;

        if (errno != EADDRINUSE || attempt + 1 >= 2) {
            sol_log_error("Failed to create gossip");
            return SOL_ERR_NOMEM;
        }

        sol_log_warn("Gossip bind failed (address already in use); selecting new ports and retrying");
        validator_autoselect_default_ports();
    }
    sol_gossip_set_value_callback(v->gossip, gossip_value_callback, v);
    if (v->rpc) {
        sol_rpc_set_gossip(v->rpc, v->gossip);
    }

    /* Add entrypoints. */
    for (size_t ei = 0; ei < g_config.entrypoints_count; ei++) {
        const char* entrypoint = g_config.entrypoints ? g_config.entrypoints[ei] : NULL;
        if (!entrypoint || entrypoint[0] == '\0') continue;

        sol_log_info("Adding entrypoint: %s", entrypoint);

        /* Parse host:port */
        char host[256] = {0};
        uint16_t port = 8001;  /* Default gossip port */

        const char* colon = strrchr(entrypoint, ':');
        if (colon != NULL) {
            size_t host_len = (size_t)(colon - entrypoint);
            if (host_len >= sizeof(host)) host_len = sizeof(host) - 1;
            memcpy(host, entrypoint, host_len);
            host[host_len] = '\0';
            port = (uint16_t)atoi(colon + 1);
        } else {
            strncpy(host, entrypoint, sizeof(host) - 1);
        }

        /* Resolve hostname and add entrypoint */
        sol_sockaddr_t entrypoint_addr;
        sol_err_t err = sol_sockaddr_from_host(host, port, &entrypoint_addr);
        if (err == SOL_OK) {
            err = sol_gossip_add_entrypoint(v->gossip, &entrypoint_addr);
            if (err != SOL_OK) {
                sol_log_warn("Failed to add entrypoint: %s", sol_err_str(err));
            } else {
                sol_log_info("Entrypoint added: %s:%u", host, port);
            }
        } else {
            sol_log_warn("Failed to resolve entrypoint hostname '%s': %s",
                         host, sol_err_str(err));
        }
    }

    /* Initialize turbine */
    sol_log_info("Initializing turbine...");
    sol_turbine_config_t turbine_config = SOL_TURBINE_CONFIG_DEFAULT;
    /* When running in a non-voting / bootstrap mode, prioritize ingesting and
     * verifying the full shred feed over best-effort retransmit. */
    if (g_config.no_voting) {
        turbine_config.enable_retransmit = false;
    }
    v->turbine = sol_turbine_new(&turbine_config, v->gossip, &v->identity_pubkey);
    if (!v->turbine) {
        sol_log_error("Failed to create turbine");
        return SOL_ERR_NOMEM;
    }

    /* Initialize repair */
    sol_log_info("Initializing repair service...");
    sol_repair_config_t repair_config = SOL_REPAIR_CONFIG_DEFAULT;
    /* Catchup is tail-latency sensitive. A tighter timeout improves retry
     * responsiveness; the repair thread also uses fanout to hedge. */
    repair_config.request_timeout_ms = 100;
    /* Large machines can sustain a much larger in-flight repair set, which is
     * critical when we are missing the Turbine stream (e.g. zero-stake bootstrap)
     * and must pull shreds over repair. */
    repair_config.max_pending_requests = 32768;
    sol_log_info("Repair config: request_timeout_ms=%u max_pending_requests=%u max_retries=%u",
                 (unsigned)repair_config.request_timeout_ms,
                 (unsigned)repair_config.max_pending_requests,
                 (unsigned)repair_config.max_retries);
    v->repair = sol_repair_new(&repair_config, v->gossip, &v->identity);
    if (!v->repair) {
        sol_log_error("Failed to create repair service");
        return SOL_ERR_NOMEM;
    }
    maybe_seed_repair_peers_from_rpc(v);

    /* Initialize Tower BFT */
    sol_log_info("Initializing Tower BFT consensus...");
    sol_tower_config_t tower_config = SOL_TOWER_CONFIG_DEFAULT;
    tower_config.node_identity = v->identity_pubkey;
    if (v->vote_account_initialized) {
        tower_config.vote_account = v->vote_account;
    }
    v->tower = sol_tower_new(&tower_config);
    if (!v->tower) {
        sol_log_error("Failed to create tower");
        return SOL_ERR_NOMEM;
    }
    validator_maybe_initialize_tower(v);

    /* Initialize PoH recorder */
    sol_log_info("Initializing PoH...");
    sol_hash_t initial_hash = {0};  /* Would come from snapshot/genesis */
    sol_poh_config_t poh_config = SOL_POH_CONFIG_DEFAULT;
    v->poh = sol_poh_recorder_new(&initial_hash, 0, &poh_config);
    if (!v->poh) {
        sol_log_error("Failed to create PoH recorder");
        return SOL_ERR_NOMEM;
    }

    /* Initialize block producer */
    sol_log_info("Initializing block producer...");
    sol_block_producer_config_t bp_config = SOL_BLOCK_PRODUCER_CONFIG_DEFAULT;
    v->block_producer = sol_block_producer_new(v->poh, &bp_config);
    if (!v->block_producer) {
        sol_log_error("Failed to create block producer");
        return SOL_ERR_NOMEM;
    }

    /* Initialize TPU (Transaction Processing Unit) */
    sol_log_info("Initializing TPU on port %u...", g_config.tpu_port);
    sol_tpu_config_t tpu_config = SOL_TPU_CONFIG_DEFAULT;
    tpu_config.base_port = g_config.tpu_port;
    tpu_config.enable_quic = g_config.enable_quic;
    v->tpu = sol_tpu_new(v->block_producer, &tpu_config);
    if (!v->tpu) {
        sol_log_error("Failed to create TPU");
        return SOL_ERR_NOMEM;
    }

    /* Initialize TVU (Transaction Validation Unit) */
    sol_log_info("Initializing TVU on port %u...", g_config.tvu_port);
    sol_tvu_config_t tvu_config = SOL_TVU_CONFIG_DEFAULT;
    tvu_config.base_port = g_config.tvu_port;
    tvu_config.skip_shred_verify = g_config.fast_replay;
    /* Replay is sequential at the bank-forks level; running many concurrent
     * replay threads just adds contention with the tx-exec pool and increases
     * per-slot latency. */
    tvu_config.replay_threads = 1;
    v->tvu = sol_tvu_new(v->blockstore, v->replay, v->turbine, v->repair, &tvu_config);
    if (!v->tvu) {
        sol_log_error("Failed to create TVU");
        return SOL_ERR_NOMEM;
    }

    /* Leader schedule used for shred signature verification. If unavailable,
     * TVU will skip signature verification (startup/testing mode). */
    sol_bank_t* schedule_bank = sol_bank_forks_root(v->bank_forks);
    if (schedule_bank) {
        uint64_t epoch = sol_bank_epoch(schedule_bank);
        v->vote_stakes = sol_stake_build_vote_stake_map(
            schedule_bank, epoch, &v->vote_stakes_total);
        v->vote_stakes_epoch = epoch;

        if (v->vote_stakes) {
            v->leader_schedule = sol_leader_schedule_from_bank_with_vote_stakes(
                schedule_bank, epoch, v->vote_stakes, NULL);
        }
    }

    /* Prefer an RPC-derived leader list for bootstrap correctness.
     * Local schedule generation is still a fallback. */
    bool seeded = maybe_seed_leader_schedule_from_rpc(v);
    if (!seeded) {
        if (v->leader_schedule) {
            sol_tvu_set_leader_schedule(v->tvu, v->leader_schedule);
            (void)sol_turbine_swap_leader_schedule(v->turbine, v->leader_schedule);
            (void)sol_replay_swap_leader_schedule(v->replay, v->leader_schedule);
            if (v->repair) {
                (void)sol_repair_swap_leader_schedule(v->repair, v->leader_schedule);
            }
            sol_log_info("Leader schedule initialized for epoch %lu",
                         (unsigned long)sol_leader_schedule_epoch(v->leader_schedule));
        } else {
            sol_log_warn("Leader schedule unavailable - shred signature verification disabled");
        }
    }

    if (v->rpc && v->leader_schedule) {
        sol_rpc_set_leader_schedule(v->rpc, v->leader_schedule);
    }

    /* Initialize Prometheus metrics */
    if (g_config.enable_metrics) {
        sol_log_info("Initializing Prometheus metrics on port %u...", g_config.metrics_port);
        sol_prometheus_config_t prom_config = SOL_PROMETHEUS_CONFIG_DEFAULT;
        prom_config.port = g_config.metrics_port;
        v->prometheus = sol_prometheus_new(&prom_config);
        if (!v->prometheus) {
            sol_log_warn("Failed to create Prometheus exporter, metrics disabled");
        } else {
            /* Register validator metrics */
            v->metric_slot_height = sol_metric_gauge_register(
                v->prometheus, SOL_METRIC_SLOT_HEIGHT,
                "Current slot height", NULL);
            v->metric_txn_received = sol_metric_counter_register(
                v->prometheus, SOL_METRIC_TXN_RECEIVED,
                "Total transactions received", NULL);
            v->metric_txn_processed = sol_metric_counter_register(
                v->prometheus, SOL_METRIC_TXN_PROCESSED,
                "Total transactions processed", NULL);
            v->metric_shreds_received = sol_metric_counter_register(
                v->prometheus, SOL_METRIC_TVU_SHREDS,
                "Total shreds received", NULL);
            v->metric_peers_connected = sol_metric_gauge_register(
                v->prometheus, SOL_METRIC_PEERS_CONNECTED,
                "Number of connected peers", NULL);
            v->metric_votes_submitted = sol_metric_counter_register(
                v->prometheus, SOL_METRIC_VOTES_SUBMITTED,
                "Total votes submitted", NULL);
        }
    }

    /* Initialize RPC / health endpoints */
    if (g_config.enable_rpc) {
        if (!v->rpc) {
            sol_log_error("RPC enabled but server is not initialized");
            return SOL_ERR_UNINITIALIZED;
        }
        sol_rpc_set_bank_forks(v->rpc, v->bank_forks);
        sol_rpc_set_blockstore(v->rpc, v->blockstore);
        sol_rpc_set_gossip(v->rpc, v->gossip);
        sol_rpc_set_identity(v->rpc, &v->identity_pubkey);
        if (v->leader_schedule) {
            sol_rpc_set_leader_schedule(v->rpc, v->leader_schedule);
        }
        sol_rpc_set_send_transaction(v->rpc, rpc_send_transaction, v);
        sol_rpc_set_health_callback(v->rpc, health_callback, v);
    } else {
        sol_log_info("Initializing standalone health server...");
        sol_health_config_t health_config = SOL_HEALTH_CONFIG_DEFAULT;
        health_config.port = g_config.rpc_port;
        health_config.callback = health_callback;
        health_config.callback_ctx = v;
        v->health = sol_health_server_new(&health_config);
        if (!v->health) {
            sol_log_warn("Failed to create health server");
        }
    }

    /* Set global validator pointer for health checks */
    g_validator = v;

    sol_log_info("Validator initialization complete");
    return SOL_OK;
}

/*
 * Start validator services
 */
static sol_err_t
validator_start(validator_t* v) {
    sol_err_t err;

    /* Start gossip */
    sol_log_info("Starting gossip service...");
    err = sol_gossip_start(v->gossip);
    if (err != SOL_OK) {
        sol_log_error("Failed to start gossip: %s", sol_err_str(err));
        return err;
    }

    /* Start turbine */
    sol_log_info("Starting turbine...");
    sol_turbine_set_shred_batch_callback(v->turbine, turbine_shred_batch_callback, v->tvu);
    sol_turbine_set_shred_callback(v->turbine, turbine_shred_callback, v->tvu);
    err = sol_turbine_start(v->turbine, g_config.tvu_port);
    if (err != SOL_OK) {
        sol_log_error("Failed to start turbine: %s", sol_err_str(err));
        return err;
    }

    /* Start repair service */
    sol_log_info("Starting repair service...");
    sol_repair_set_blockstore(v->repair, v->blockstore);
    sol_repair_set_shred_callback(v->repair, repair_shred_callback, v->tvu);
    err = sol_repair_start(v->repair, g_config.tvu_port + 2);
    if (err != SOL_OK) {
        sol_log_error("Failed to start repair: %s", sol_err_str(err));
        return err;
    }
    if (!v->repair_pump_started) {
        int rc = pthread_create(&v->repair_pump_thread, NULL, repair_pump_thread_main, v);
        if (rc != 0) {
            sol_log_error("Failed to start repair pump thread: %s", strerror(rc));
            return SOL_ERR_IO;
        }
        v->repair_pump_started = true;
    }

    /* Start TVU */
    sol_log_info("Starting TVU...");
    err = sol_tvu_start(v->tvu);
    if (err != SOL_OK) {
        sol_log_error("Failed to start TVU: %s", sol_err_str(err));
        return err;
    }

    /* Start block producer */
    sol_log_info("Starting block producer...");
    sol_bank_t* start_bank = sol_replay_working_bank(v->replay);
    if (start_bank) {
        sol_block_producer_set_bank(v->block_producer, start_bank);
    }
    sol_block_producer_set_slot_callback(v->block_producer, block_producer_slot_callback, v);
    sol_block_producer_set_block_data_callback(v->block_producer, block_producer_block_data_callback, v);
    err = sol_block_producer_start(v->block_producer);
    if (err != SOL_OK) {
        sol_log_error("Failed to start block producer: %s", sol_err_str(err));
        return err;
    }

    /* Start TPU */
    sol_log_info("Starting TPU...");
    sol_tpu_set_leader_mode(v->tpu, false, 0, 0);
    err = sol_tpu_start(v->tpu);
    if (err != SOL_OK) {
        sol_log_error("Failed to start TPU: %s", sol_err_str(err));
        return err;
    }

    /* Start PoH service */
    sol_log_info("Starting PoH service...");
    err = sol_poh_recorder_start(v->poh);
    if (err != SOL_OK) {
        sol_log_error("Failed to start PoH: %s", sol_err_str(err));
        return err;
    }

    /* Start Prometheus metrics server */
    if (v->prometheus) {
        sol_log_info("Starting Prometheus metrics server...");
        err = sol_prometheus_start(v->prometheus);
        if (err != SOL_OK) {
            sol_log_warn("Failed to start Prometheus: %s", sol_err_str(err));
            /* Non-fatal, continue without metrics */
        }
    }

    /* Start RPC server */
    if (v->rpc && !sol_rpc_is_running(v->rpc)) {
        sol_log_info("Starting RPC server...");
        err = sol_rpc_start(v->rpc);
        if (err != SOL_OK) {
            sol_log_error("Failed to start RPC: %s", sol_err_str(err));
            return err;
        }
        g_rpc_port_is_bound = true;
    }

    /* Start health server */
    if (v->health) {
        sol_log_info("Starting health server...");
        err = sol_health_server_start(v->health);
        if (err != SOL_OK) {
            sol_log_warn("Failed to start health server: %s", sol_err_str(err));
            /* Non-fatal, continue without health endpoints */
        }
    }

    /* Keep leader schedule refreshed without stalling the packet pump. */
    validator_leader_schedule_refresh_start(v);

    sol_log_info("All validator services started");
    return SOL_OK;
}

/*
 * Stop validator services
 */
static void
validator_stop(validator_t* v) {
    sol_log_info("Stopping validator services...");

    /* Stop background refresh workers before tearing down dependencies. */
    validator_leader_schedule_refresh_stop(v);

    /* Stop RPC server */
    if (v->rpc) {
        sol_rpc_stop(v->rpc);
    }

    /* Stop health server */
    if (v->health) {
        sol_health_server_stop(v->health);
    }

    /* Stop Prometheus */
    if (v->prometheus) {
        sol_prometheus_stop(v->prometheus);
    }

    /* Stop PoH */
    if (v->poh) {
        sol_poh_recorder_stop(v->poh);
    }

    /* Stop block producer */
    if (v->block_producer) {
        sol_block_producer_stop(v->block_producer);
    }

    /* Stop TPU */
    if (v->tpu) {
        sol_tpu_stop(v->tpu);
    }

    /* Stop TVU */
    if (v->tvu) {
        sol_tvu_stop(v->tvu);
    }

    /* Stop turbine */
    if (v->turbine) {
        sol_turbine_stop(v->turbine);
    }

    /* Stop repair */
    if (v->repair) {
        sol_repair_stop(v->repair);
    }
    if (v->repair_pump_started) {
        (void)pthread_join(v->repair_pump_thread, NULL);
        v->repair_pump_started = false;
    }

    /* Stop gossip */
    if (v->gossip) {
        sol_gossip_stop(v->gossip);
    }

    sol_log_info("All services stopped");
}

/*
 * Cleanup validator components
 */
static void
validator_cleanup(validator_t* v) {
    sol_log_info("Cleaning up validator resources...");

    /* Clear global pointer */
    g_validator = NULL;

    validator_leader_schedule_refresh_stop(v);
    pthread_cond_destroy(&v->leader_schedule_refresh.cond);
    pthread_mutex_destroy(&v->leader_schedule_refresh.lock);

    if (v->rpc) sol_rpc_destroy(v->rpc);
    if (v->health) sol_health_server_destroy(v->health);
    if (v->prometheus) sol_prometheus_destroy(v->prometheus);
    if (v->block_producer) sol_block_producer_destroy(v->block_producer);
    if (v->poh) sol_poh_recorder_destroy(v->poh);
    if (v->tpu) sol_tpu_destroy(v->tpu);
    if (v->tvu) sol_tvu_destroy(v->tvu);
    if (v->leader_schedule) sol_leader_schedule_destroy(v->leader_schedule);
    if (v->vote_stakes) sol_pubkey_map_destroy(v->vote_stakes);
    validator_persist_tower_best_effort(v);
    if (v->tower) sol_tower_destroy(v->tower);
    if (v->repair) sol_repair_destroy(v->repair);
    if (v->turbine) sol_turbine_destroy(v->turbine);
    if (v->gossip) sol_gossip_destroy(v->gossip);
    if (v->replay) sol_replay_destroy(v->replay);
    if (v->bank_forks) sol_bank_forks_destroy(v->bank_forks);
    if (v->accounts_db) sol_accounts_db_destroy(v->accounts_db);
    if (v->blockstore) sol_blockstore_destroy(v->blockstore);
    if (v->io_ctx) sol_io_ctx_destroy(v->io_ctx);

    sol_log_info("Cleanup complete");
}

static bool
leader_schedule_is_usable(const sol_leader_schedule_t* schedule) {
    if (!schedule) return false;

    sol_slot_t first = sol_leader_schedule_first_slot(schedule);
    const sol_pubkey_t* leader = sol_leader_schedule_get_leader(schedule, first);
    if (!leader) return false;
    return !sol_pubkey_is_zero(leader);
}

static uint64_t
monotonic_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t
supermajority_threshold(uint64_t total_stake) {
    /* Return ceil(2/3 * total_stake). */
    if (total_stake == 0) {
        return 0;
    }

    __uint128_t num = (__uint128_t)total_stake * 2u + 2u;
    return (uint64_t)(num / 3u);
}

static void
validator_maybe_verify_snapshot(validator_t* v, uint64_t now_ns) {
    if (!v || v->snapshot_verified) {
        return;
    }

    /* Poll at a low rate to avoid excess work. */
    const uint64_t min_interval_ns = 1ULL * 1000ULL * 1000ULL * 1000ULL;
    if (v->last_snapshot_verify_ns != 0 &&
        (now_ns - v->last_snapshot_verify_ns) < min_interval_ns) {
        return;
    }
    v->last_snapshot_verify_ns = now_ns;

    if (!v->vote_stakes || v->vote_stakes_total == 0 || !v->replay || !v->bank_forks) {
        return;
    }

    sol_fork_choice_t* fc = sol_replay_fork_choice(v->replay);
    if (!fc) return;

    uint64_t total_stake = v->vote_stakes_total;
    uint64_t threshold = supermajority_threshold(total_stake);

    sol_slot_t best_slot = 0;
    sol_hash_t best_hash = {0};
    if (!sol_fork_choice_best_bank(fc, &best_slot, &best_hash) ||
        sol_hash_is_zero(&best_hash)) {
        return;
    }

    sol_bank_t* bank = sol_bank_forks_get_hash(v->bank_forks, best_slot, &best_hash);
    while (bank) {
        if (sol_bank_is_frozen(bank)) {
            sol_hash_t bank_hash = {0};
            sol_bank_compute_hash(bank, &bank_hash);
            if (!sol_hash_is_zero(&bank_hash)) {
                uint64_t weight =
                    sol_fork_choice_subtree_weight_hash(fc, sol_bank_slot(bank), &bank_hash);
                if (weight >= threshold) {
                    v->snapshot_verified = true;
                    sol_log_info("Snapshot verified via gossip votes at slot %lu (stake=%lu/%lu)",
                                 (unsigned long)sol_bank_slot(bank),
                                 (unsigned long)weight,
                                 (unsigned long)total_stake);
                    return;
                }
            }
        }

        sol_slot_t slot = sol_bank_slot(bank);
        sol_slot_t parent_slot = sol_bank_parent_slot(bank);
        const sol_hash_t* parent_hash = sol_bank_parent_hash(bank);
        if (!parent_hash || sol_hash_is_zero(parent_hash) || parent_slot == slot) {
            break;
        }
        bank = sol_bank_forks_get_hash(v->bank_forks, parent_slot, parent_hash);
    }
}

static void
validator_refresh_epoch_caches(validator_t* v, sol_bank_t* bank) {
    if (!v || !bank) return;

    uint64_t epoch = sol_bank_epoch(bank);

    bool need_vote_stakes = !v->vote_stakes || v->vote_stakes_epoch != epoch;
    bool need_schedule = !v->leader_schedule ||
                         sol_leader_schedule_epoch(v->leader_schedule) != epoch;

    if (!need_vote_stakes && !need_schedule) {
        return;
    }

    if (need_vote_stakes) {
        uint64_t total_stake = 0;
        sol_pubkey_map_t* new_vote_stakes =
            sol_stake_build_vote_stake_map(bank, epoch, &total_stake);

        if (!new_vote_stakes) {
            sol_log_warn("Failed to rebuild vote stake cache for epoch %lu",
                         (unsigned long)epoch);
        } else {
            sol_pubkey_map_destroy(v->vote_stakes);
            v->vote_stakes = new_vote_stakes;
            v->vote_stakes_epoch = epoch;
            v->vote_stakes_total = total_stake;

            sol_log_info("Vote stake cache updated for epoch %lu (total=%lu)",
                         (unsigned long)epoch, (unsigned long)total_stake);

            /* Seed bank sysvar refresh cache so the first replayed slot does
             * not spend seconds rebuilding the same map in Clock median
             * timestamp computation. */
            sol_err_t seed_err =
                sol_bank_seed_vote_stakes_cache(sol_bank_get_accounts_db(bank),
                                                epoch,
                                                v->vote_stakes,
                                                v->vote_stakes_total);
            if (seed_err != SOL_OK) {
                sol_log_warn("Failed to seed bank vote-stakes cache for epoch %lu: %s",
                             (unsigned long)epoch,
                             sol_err_str(seed_err));
            }

            sol_err_t ts_seed_err =
                sol_bank_seed_vote_timestamp_cache(sol_bank_get_accounts_db(bank),
                                                   v->vote_stakes);
            if (ts_seed_err != SOL_OK) {
                sol_log_warn("Failed to seed bank vote-timestamp cache for epoch %lu: %s",
                             (unsigned long)epoch,
                             sol_err_str(ts_seed_err));
            }
        }

        if (v->turbine) {
            sol_turbine_set_bank(v->turbine, bank);
        }
    }

    if (need_schedule) {
        static uint64_t last_schedule_attempt_epoch = UINT64_MAX;
        static uint64_t last_schedule_attempt_ns = 0;

        uint64_t now_ns = monotonic_time_ns();
        const uint64_t min_attempt_interval_ns = 10ULL * 1000ULL * 1000ULL * 1000ULL; /* 10s */
        if (last_schedule_attempt_epoch == epoch &&
            (now_ns - last_schedule_attempt_ns) < min_attempt_interval_ns) {
            return;
        }
        last_schedule_attempt_epoch = epoch;
        last_schedule_attempt_ns = now_ns;

        if (v->vote_stakes && v->vote_stakes_total == 0) {
            sol_log_warn("Leader schedule rebuild skipped for epoch %lu (no active stake)",
                         (unsigned long)epoch);
            return;
        }

        sol_leader_schedule_t* new_schedule =
            sol_leader_schedule_from_bank_with_vote_stakes(
                bank, epoch, v->vote_stakes, NULL);

        if (new_schedule && !leader_schedule_is_usable(new_schedule)) {
            sol_leader_schedule_destroy(new_schedule);
            new_schedule = NULL;
        }

        if (!new_schedule) {
            sol_log_warn("Failed to rebuild leader schedule for epoch %lu (continuing without strict shred verification)",
                         (unsigned long)epoch);
            return;
        }

        sol_leader_schedule_t* prev = v->leader_schedule;
        sol_leader_schedule_t* old_tvu = NULL;
        sol_leader_schedule_t* old_turbine = NULL;
        sol_leader_schedule_t* old_replay = NULL;
        sol_leader_schedule_t* old_repair = NULL;
        if (v->tvu) {
            old_tvu = sol_tvu_swap_leader_schedule(v->tvu, new_schedule);
        }
        if (v->turbine) {
            old_turbine = sol_turbine_swap_leader_schedule(v->turbine, new_schedule);
        }
        if (v->replay) {
            old_replay = sol_replay_swap_leader_schedule(v->replay, new_schedule);
        }
        if (v->repair) {
            old_repair = (sol_leader_schedule_t*)sol_repair_swap_leader_schedule(v->repair, new_schedule);
        }
        v->leader_schedule = new_schedule;

        sol_leader_schedule_t* to_free[5] = { old_tvu, old_turbine, old_replay, old_repair, prev };
        for (size_t i = 0; i < 5; i++) {
            sol_leader_schedule_t* s = to_free[i];
            if (!s || s == new_schedule) continue;
            bool seen = false;
            for (size_t j = 0; j < i; j++) {
                if (to_free[j] == s) {
                    seen = true;
                    break;
                }
            }
            if (!seen) {
                sol_leader_schedule_destroy(s);
            }
        }

        sol_log_info("Leader schedule updated for epoch %lu",
                     (unsigned long)sol_leader_schedule_epoch(new_schedule));
    }
}

typedef struct {
    sol_hash_t hash;
    uint64_t   stake;
    uint32_t   votes;
} slot_vote_weight_t;

static int
slot_vote_weight_cmp_desc(const void* a, const void* b) {
    const slot_vote_weight_t* va = (const slot_vote_weight_t*)a;
    const slot_vote_weight_t* vb = (const slot_vote_weight_t*)b;
    if (va->stake < vb->stake) return 1;
    if (va->stake > vb->stake) return -1;
    if (va->votes < vb->votes) return 1;
    if (va->votes > vb->votes) return -1;
    return memcmp(va->hash.bytes, vb->hash.bytes, SOL_HASH_SIZE);
}

static size_t
collect_slot_vote_weights(validator_t* v,
                          sol_slot_t slot,
                          slot_vote_weight_t* out,
                          size_t max_out) {
    if (!v || !out || max_out == 0 || !v->gossip) return 0;

    sol_crds_t* crds = sol_gossip_crds(v->gossip);
    if (!crds) return 0;

    const sol_crds_vote_t* votes[2048];
    size_t n = sol_crds_get_votes_for_slot(crds, slot, votes, sizeof(votes) / sizeof(votes[0]));
    if (n == 0) return 0;

    size_t count = 0;
    for (size_t i = 0; i < n; i++) {
        const sol_crds_vote_t* vote = votes[i];
        if (!vote) continue;

        uint64_t stake = 1;
        if (v->vote_stakes) {
            const uint64_t* stake_ptr =
                (const uint64_t*)sol_pubkey_map_get(v->vote_stakes, &vote->from);
            if (!stake_ptr || *stake_ptr == 0) {
                continue;
            }
            stake = *stake_ptr;
        }

        bool found = false;
        for (size_t j = 0; j < count; j++) {
            if (memcmp(out[j].hash.bytes, vote->hash.bytes, SOL_HASH_SIZE) == 0) {
                out[j].stake += stake;
                out[j].votes += 1;
                found = true;
                break;
            }
        }
        if (found) continue;

        if (count >= max_out) {
            continue;
        }

        out[count].hash = vote->hash;
        out[count].stake = stake;
        out[count].votes = 1;
        count++;
    }

    qsort(out, count, sizeof(out[0]), slot_vote_weight_cmp_desc);
    return count;
}

typedef struct {
    sol_slot_t slot;
    sol_hash_t hashes[8];
    size_t     count;
} slot_hashes_t;

static bool
collect_slot_hashes_cb(sol_slot_t slot,
                       sol_slot_t parent_slot,
                       const sol_hash_t* bank_hash,
                       const sol_hash_t* parent_hash,
                       sol_bank_t* bank,
                       bool is_dead,
                       void* ctx) {
    (void)parent_slot;
    (void)parent_hash;

    slot_hashes_t* out = (slot_hashes_t*)ctx;
    if (!out || slot != out->slot) return true;
    if (out->count >= sizeof(out->hashes) / sizeof(out->hashes[0])) return true;
    if (is_dead || !bank || !sol_bank_is_frozen(bank)) return true;

    sol_hash_t h = {0};
    if (bank_hash) {
        h = *bank_hash;
    }
    if (sol_hash_is_zero(&h)) {
        sol_bank_compute_hash(bank, &h);
    }
    if (sol_hash_is_zero(&h)) {
        return true;
    }

    for (size_t i = 0; i < out->count; i++) {
        if (memcmp(out->hashes[i].bytes, h.bytes, SOL_HASH_SIZE) == 0) {
            return true;
        }
    }

    out->hashes[out->count++] = h;
    return true;
}

static void
validator_maybe_log_vote_hash_mismatch(validator_t* v,
                                       sol_slot_t slot,
                                       const sol_hash_t* voted_hash) {
    if (!v || !v->bank_forks || !voted_hash || sol_hash_is_zero(voted_hash)) return;

    slot_hashes_t local = {0};
    local.slot = slot;
    sol_bank_forks_iterate(v->bank_forks, collect_slot_hashes_cb, &local);
    if (local.count == 0) {
        return; /* We simply haven't replayed this slot yet. */
    }

    bool have_voted_hash = false;
    for (size_t i = 0; i < local.count; i++) {
        if (memcmp(local.hashes[i].bytes, voted_hash->bytes, SOL_HASH_SIZE) == 0) {
            have_voted_hash = true;
            break;
        }
    }
    if (have_voted_hash) {
        return;
    }

    uint64_t now_ns = monotonic_time_ns();
    if (v->last_vote_hash_diag_slot == slot &&
        (now_ns - v->last_vote_hash_diag_ns) < (10ULL * 1000ULL * 1000ULL * 1000ULL)) {
        return;
    }
    v->last_vote_hash_diag_slot = slot;
    v->last_vote_hash_diag_ns = now_ns;

    char voted_hex[65] = {0};
    (void)sol_hash_to_hex(voted_hash, voted_hex, sizeof(voted_hex));

    char local_buf[8 * 68] = {0};
    size_t off = 0;
    for (size_t i = 0; i < local.count; i++) {
        char h[65] = {0};
        (void)sol_hash_to_hex(&local.hashes[i], h, sizeof(h));
        int n = snprintf(local_buf + off, sizeof(local_buf) - off,
                         "%s%s", (i == 0) ? "" : ",", h);
        if (n < 0 || (size_t)n >= sizeof(local_buf) - off) break;
        off += (size_t)n;
    }

    slot_vote_weight_t weights[8];
    memset(weights, 0, sizeof(weights));
    size_t wcount = collect_slot_vote_weights(v, slot, weights,
                                              sizeof(weights) / sizeof(weights[0]));

    char votes_buf[8 * 90] = {0};
    off = 0;
    for (size_t i = 0; i < wcount; i++) {
        char h[65] = {0};
        (void)sol_hash_to_hex(&weights[i].hash, h, sizeof(h));
        int n = snprintf(votes_buf + off, sizeof(votes_buf) - off,
                         "%s%s:%lu(%u)",
                         (i == 0) ? "" : ",",
                         h,
                         (unsigned long)weights[i].stake,
                         (unsigned)weights[i].votes);
        if (n < 0 || (size_t)n >= sizeof(votes_buf) - off) break;
        off += (size_t)n;
    }

    sol_log_warn("Vote-hash mismatch at slot %lu: voted=%s local={%s} votes={%s}",
                 (unsigned long)slot,
                 voted_hex,
                 local_buf[0] ? local_buf : "-",
                 votes_buf[0] ? votes_buf : "-");
}

/*
 * Main validator loop
 */
static void
validator_run(validator_t* v) {
    sol_log_info("Entering main validator loop");

    uint64_t votes_count = 0;
    uint64_t last_stats_ns = 0;
    uint64_t last_root_ns = 0;
    uint64_t last_dev_halt_check_ns = 0;
    bool dev_halt_logged = false;
    const uint64_t stats_period_ns = 10ULL * 1000ULL * 1000ULL * 1000ULL;
    const uint64_t root_period_ns = 1ULL * 1000ULL * 1000ULL * 1000ULL;

    while (!g_shutdown) {
        uint64_t now_ns = monotonic_time_ns();
        bool did_work = false;

        /* Pump gossip + repair sockets (both are non-blocking). */
        if (v->gossip) {
            sol_err_t err = sol_gossip_run_once(v->gossip, 0);
            if (err == SOL_OK) did_work = true;
        }
        if (v->repair && !v->repair_pump_started) {
            sol_err_t err = sol_repair_run_once(v->repair, 0);
            if (err == SOL_OK) did_work = true;
        }

        /* Pump turbine/shred ingress */
        if (v->turbine) {
            sol_err_t err = sol_turbine_run_once(v->turbine, 0);
            if (err == SOL_OK) did_work = true;
        }

        /* Check for new slots */
        sol_slot_t new_slot = sol_replay_best_slot(v->replay);
        if (new_slot != v->current_slot) {
            did_work = true;
            v->current_slot = new_slot;
            if (new_slot > v->highest_slot) {
                v->highest_slot = new_slot;
            }
            sol_log_debug("Current slot: %lu", (unsigned long)new_slot);

            /* Update slot metric */
            if (v->metric_slot_height) {
                sol_metric_gauge_set(v->metric_slot_height, (double)new_slot, NULL);
            }

            /* Refresh epoch-scoped caches (leader schedule, vote stakes). */
            sol_bank_t* epoch_bank = sol_replay_working_bank(v->replay);
            if (!epoch_bank) {
                epoch_bank = sol_bank_forks_root(v->bank_forks);
            }
            validator_refresh_epoch_caches(v, epoch_bank);
        }

        /* Keep leader schedule populated for upcoming catchup slots. */
        validator_maybe_refresh_rpc_leader_schedule(v);
        validator_maybe_update_tpu_forwarding(v, now_ns);

        /* Non-voting or fast-replay mode: advance root based on replay progress
         * so bank_forks doesn't grow without bound. */
        /* If we aren't actually voting (either via --no-voting or because no
         * vote account is configured), fork-choice roots may not advance and
         * AccountsDB fork chains can grow without bound, which tanks replay
         * throughput. Keep the root moving in that case. */
        if ((g_config.no_voting || g_config.fast_replay || !v->vote_account_initialized) &&
            v->replay && v->bank_forks) {
            static uint64_t last_auto_root_ns = 0;
            const uint64_t auto_root_period_ns = 2ULL * 1000ULL * 1000ULL * 1000ULL; /* 2s */
            static sol_slot_t auto_root_window = 0;
            static bool auto_root_window_logged = false;

            if (auto_root_window == 0) {
                /* Smaller window keeps AccountsDB fork chains shallow, which
                 * materially improves replay throughput in --no-voting mode. */
                sol_slot_t window = 64;

                const char* env = getenv("SOL_AUTO_ROOT_WINDOW");
                if (env && env[0] != '\0') {
                    errno = 0;
                    char* end = NULL;
                    unsigned long long v = strtoull(env, &end, 10);
                    if (errno == 0 && end && end != env) {
                        while (*end && isspace((unsigned char)*end)) end++;
                        if (*end == '\0') {
                            window = (sol_slot_t)v;
                        }
                    }
                }

                if (window < 16) window = 16;
                if (window > 4096) window = 4096;

                auto_root_window = window;
            }

            if (last_auto_root_ns == 0 || (now_ns - last_auto_root_ns) >= auto_root_period_ns) {
                last_auto_root_ns = now_ns;

                sol_slot_t highest_replayed = sol_replay_highest_replayed_slot(v->replay);
                sol_slot_t current_root = sol_replay_root_slot(v->replay);

                if (!auto_root_window_logged) {
                    auto_root_window_logged = true;
                    sol_log_info("Auto root window: %lu slots%s",
                                 (unsigned long)auto_root_window,
                                 getenv("SOL_AUTO_ROOT_WINDOW") ? " (env SOL_AUTO_ROOT_WINDOW)" : "");
                }

                if (highest_replayed > current_root + auto_root_window) {
                    sol_slot_t target_root = highest_replayed - auto_root_window;
                    sol_err_t err = sol_replay_set_root(v->replay, target_root);
                    if (err == SOL_OK) {
                        sol_log_info("Auto root advanced to slot %lu (highest_replayed=%lu)",
                                     (unsigned long)target_root,
                                     (unsigned long)highest_replayed);
                        if (v->blockstore) {
                            (void)sol_blockstore_set_rooted(v->blockstore, target_root);
                            (void)sol_blockstore_purge_slots_below(v->blockstore, target_root);
                        }
                    } else if (err != SOL_ERR_NOTFOUND) {
                        sol_log_warn("Auto root advance failed for slot %lu: %s",
                                     (unsigned long)target_root,
                                     sol_err_str(err));
                    }
                }
            }
        }

        /* Advance root (best-effort) based on fork-choice supermajority.
         * Uses (slot, bank_hash) to remain safe under duplicate slots. */
        if (now_ns - last_root_ns >= root_period_ns) {
            last_root_ns = now_ns;

            sol_fork_choice_t* fc = sol_replay_fork_choice(v->replay);
            if (fc && v->bank_forks) {
                uint64_t total_stake = v->vote_stakes_total;
                if (total_stake == 0) {
                    total_stake = sol_fork_choice_total_stake(fc);
                }
                if (total_stake > 0) {
                    uint64_t threshold = supermajority_threshold(total_stake);

                    sol_slot_t best_slot = 0;
                    sol_hash_t best_hash = {0};
                    if (sol_fork_choice_best_bank(fc, &best_slot, &best_hash)) {
                        validator_maybe_log_vote_hash_mismatch(v, best_slot, &best_hash);
                        sol_slot_t current_root = sol_replay_root_slot(v->replay);

                        if (best_slot > current_root &&
                            best_slot > SOL_MAX_LOCKOUT_HISTORY) {
                            sol_slot_t min_rootable = best_slot - SOL_MAX_LOCKOUT_HISTORY;

                            sol_bank_t* bank = sol_bank_forks_get_hash(
                                v->bank_forks, best_slot, &best_hash);

                            sol_slot_t candidate_slot = 0;
                            sol_hash_t candidate_hash = {0};

                            while (bank) {
                                sol_slot_t slot = sol_bank_slot(bank);
                                if (slot <= current_root) break;

                                if (slot <= min_rootable && sol_bank_is_frozen(bank)) {
                                    sol_hash_t bank_hash = {0};
                                    sol_bank_compute_hash(bank, &bank_hash);

                                    uint64_t weight =
                                        sol_fork_choice_subtree_weight_hash(fc, slot, &bank_hash);

                                    if (weight >= threshold) {
                                        candidate_slot = slot;
                                        candidate_hash = bank_hash;
                                        break;
                                    }
                                }

                                sol_slot_t parent_slot = sol_bank_parent_slot(bank);
                                const sol_hash_t* parent_hash = sol_bank_parent_hash(bank);
                                if (!parent_hash || sol_hash_is_zero(parent_hash) ||
                                    parent_slot == slot) {
                                    break;
                                }

                                bank = sol_bank_forks_get_hash(
                                    v->bank_forks, parent_slot, parent_hash);
                            }

                            if (candidate_slot > current_root &&
                                !sol_hash_is_zero(&candidate_hash)) {
                                sol_err_t err = sol_replay_set_root_hash(
                                    v->replay, candidate_slot, &candidate_hash);

                                if (err == SOL_OK) {
                                    sol_log_info("Root advanced to slot %lu",
                                                 (unsigned long)candidate_slot);

                                    if (v->blockstore) {
                                        (void)sol_blockstore_set_rooted(v->blockstore, candidate_slot);
                                        (void)sol_blockstore_purge_slots_below(v->blockstore, candidate_slot);
                                    }
                                } else {
                                    sol_log_warn("Failed to advance root to slot %lu: %s",
                                                 (unsigned long)candidate_slot, sol_err_str(err));
                                }
                            }
                        }
                    }
                }
            }
        }

        /* Snapshot verification gate: don't start voting until we observe a
         * supermajority building on one of our replayed bank hashes. */
        if (!g_config.no_voting && !v->snapshot_verified) {
            validator_maybe_verify_snapshot(v, now_ns);
        }

        /* Check if we should vote (Tower BFT) */
        if (!g_config.no_voting && v->vote_account_initialized) {
            validator_maybe_initialize_tower(v);
        }

        if (!g_config.no_voting && v->vote_account_initialized && v->tower_initialized &&
            v->snapshot_verified) {
            sol_fork_choice_t* fc = sol_replay_fork_choice(v->replay);
            sol_slot_t vote_slot = 0;
            sol_hash_t vote_hash = {0};
            sol_bank_t* bank = NULL;
            if (fc && sol_fork_choice_best_bank(fc, &vote_slot, &vote_hash) &&
                !sol_hash_is_zero(&vote_hash)) {
                bank = sol_bank_forks_get_hash(v->bank_forks, vote_slot, &vote_hash);
                if (!bank) {
                    validator_maybe_log_vote_hash_mismatch(v, vote_slot, &vote_hash);
                }
            }
            if (bank && sol_bank_is_frozen(bank)) {
                sol_vote_decision_t decision = sol_tower_check_vote(
                    v->tower, vote_slot, bank, sol_replay_fork_choice(v->replay));

                if (decision == SOL_VOTE_DECISION_VOTE) {
                    sol_err_t terr = sol_tower_record_bank_vote(v->tower, bank);
                    if (terr != SOL_OK) {
                        sol_log_warn("Failed to record tower vote for slot %lu: %s",
                                     (unsigned long)vote_slot,
                                     sol_err_str(terr));
                        continue;
                    }
                    validator_persist_tower_best_effort(v);

                    /* Build and submit vote transaction */
                    const sol_hash_t* recent_blockhash = sol_bank_blockhash(bank);
                    if (!recent_blockhash) {
                        sol_log_warn("No recent blockhash available for vote slot %lu",
                                     (unsigned long)vote_slot);
                        continue;
                    }
                    sol_vote_tx_builder_set_blockhash(&v->vote_tx_builder, recent_blockhash);

                    uint8_t vote_tx_data[1232];  /* MTU size */
                    size_t vote_tx_len = 0;

                    sol_err_t err = sol_vote_tx_from_tower(
                        &v->vote_tx_builder, v->tower, bank,
                        vote_tx_data, sizeof(vote_tx_data), &vote_tx_len
                    );

                    if (err == SOL_OK) {
                        /* Submit vote to TPU */
                        err = sol_tpu_submit_vote_raw(v->tpu, vote_tx_data, vote_tx_len);
                        if (err == SOL_OK) {
                            votes_count++;
                            sol_log_debug("Vote submitted for slot %lu (%zu bytes)",
                                (unsigned long)vote_slot, vote_tx_len);

                            /* Update votes metric */
                            if (v->metric_votes_submitted) {
                                sol_metric_counter_inc(v->metric_votes_submitted, NULL);
                            }
                        } else {
                            sol_log_warn("Failed to submit vote: %s", sol_err_str(err));
                        }
                    } else {
                        sol_log_warn("Failed to build vote transaction: %s", sol_err_str(err));
                    }
                }
            }
        }

        if (!dev_halt_logged && !g_shutdown && g_config.dev_halt_at_slot > 0 && v->replay) {
            /* Dev/testing: halt once we've replayed at-or-above the target slot.
             * Throttle the check to avoid contending on the replay mutex. */
            if (last_dev_halt_check_ns == 0 ||
                (now_ns - last_dev_halt_check_ns) >= (100ULL * 1000ULL * 1000ULL)) { /* 100ms */
                last_dev_halt_check_ns = now_ns;

                sol_slot_t highest_replayed = sol_replay_highest_replayed_slot(v->replay);
                if (highest_replayed >= g_config.dev_halt_at_slot) {
                    sol_log_info("Dev halt: reached slot %lu (highest_replayed=%lu)",
                                 (unsigned long)g_config.dev_halt_at_slot,
                                 (unsigned long)highest_replayed);
                    dev_halt_logged = true;
                    g_shutdown = 1;
                    continue;
                }
            }
        }

        /* Print stats and update metrics periodically */
        if (now_ns - last_stats_ns >= stats_period_ns) {
            last_stats_ns = now_ns;

            sol_tpu_stats_t tpu_stats = sol_tpu_stats(v->tpu);
            sol_tvu_stats_t tvu_stats = sol_tvu_stats(v->tvu);
            sol_turbine_stats_t turbine_stats = {0};
            if (v->turbine) {
                sol_turbine_stats(v->turbine, &turbine_stats);
            }
            sol_repair_stats_t repair_stats = {0};
            size_t repair_pending = 0;
            if (v->repair) {
                sol_repair_stats(v->repair, &repair_stats);
                repair_pending = sol_repair_pending_count(v->repair);
            }

	            sol_slot_t highest_replayed = v->replay ? sol_replay_highest_replayed_slot(v->replay) : 0;
	            sol_slot_t catchup_next = highest_replayed ? (highest_replayed + 1) : 0;
	            bool catchup_have_meta = false;
	            uint32_t catchup_rx = 0;
	            uint32_t catchup_last = 0;
	            const char* catchup_full = "-";
	            uint32_t catchup_missing = 0;
	            uint32_t catchup_missing_first = 0;
	            uint32_t catchup_missing_last = 0;

	            size_t catchup_repair_pending_total = 0;
	            size_t catchup_repair_pending_shreds = 0;
	            uint32_t catchup_repair_max_retries = 0;

	            if (catchup_next && v->blockstore) {
	                sol_slot_meta_t meta;
	                if (sol_blockstore_get_slot_meta(v->blockstore, catchup_next, &meta) == SOL_OK) {
	                    catchup_have_meta = true;
	                    catchup_rx = meta.received_data;
	                    catchup_last = meta.last_shred_index;
	                    catchup_full = meta.is_full ? "yes" : "no";

	                    uint32_t expected = 0;
	                    if (meta.is_full && meta.num_data_shreds > 0) {
	                        expected = meta.num_data_shreds;
	                    } else if (meta.last_shred_index > 0) {
	                        expected = meta.last_shred_index + 1;
	                    }
	                    if (expected > catchup_rx) {
	                        catchup_missing = expected - catchup_rx;
	                    }

	                    /* Debugging aid: enumerate missing indices for catchup-next. */
	                    if (catchup_missing > 0) {
	                        uint32_t missing_idx[4096];
	                        size_t missing_len = sol_blockstore_get_missing_shreds(
	                            v->blockstore,
	                            catchup_next,
	                            missing_idx,
	                            sizeof(missing_idx) / sizeof(missing_idx[0]));
	                        if (missing_len > 0) {
	                            catchup_missing_first = missing_idx[0];
	                            catchup_missing_last = missing_idx[missing_len - 1];
	                        }
	                    }
	                }
	            }

	            if (catchup_next && v->repair) {
	                sol_repair_pending_slot_stats_t pst;
	                if (sol_repair_pending_slot_stats(v->repair, catchup_next, &pst)) {
	                    catchup_repair_pending_total = pst.total;
	                    catchup_repair_pending_shreds = pst.shreds;
	                    catchup_repair_max_retries = pst.max_retries;
	                }
	            }

            /* Update is_syncing based on slot lag */
            v->is_syncing = (v->highest_slot > v->current_slot + 10);

            /* Update metrics */
            if (v->prometheus) {
                if (v->metric_txn_received) {
                    sol_metric_counter_add(v->metric_txn_received,
                        (double)tpu_stats.packets_received, NULL);
                }
                if (v->metric_txn_processed) {
                    sol_metric_counter_add(v->metric_txn_processed,
                        (double)tpu_stats.signatures_verified, NULL);
                }
                if (v->metric_shreds_received) {
                    sol_metric_counter_add(v->metric_shreds_received,
                        (double)tvu_stats.shreds_received, NULL);
                }
                if (v->metric_peers_connected && v->gossip) {
                    sol_metric_gauge_set(v->metric_peers_connected,
                        (double)sol_gossip_num_peers(v->gossip), NULL);
                }
            }

            size_t peers = v->gossip ? sol_gossip_num_peers(v->gossip) : 0;
            sol_slot_t highest = v->highest_slot;
            sol_slot_t behind = (highest > v->current_slot) ? (highest - v->current_slot) : 0;

	            sol_log_info("Stats: slot=%lu (highest=%lu behind=%lu peers=%zu sync=%s), Catchup(next=%lu meta=%s rx=%u last=%u full=%s missing=%u miss_first=%u miss_last=%u repair_pending=%zu/%zu repair_retry=%u), TPU(rx=%lu,verify=%lu), TVU(rx=%lu,ok=%lu,bad=%lu,dup=%lu,complete=%lu,replayed=%lu,failed=%lu), Turbine(rx=%lu,rtx=%lu,dup=%lu,bad=%lu,slots=%lu), Repair(sent=%lu,pending=%zu,recv=%lu,repaired=%lu,timeouts=%lu,dups=%lu,invalid=%lu), votes=%lu",
	                (unsigned long)v->current_slot,
	                (unsigned long)highest,
	                (unsigned long)behind,
	                peers,
                v->is_syncing ? "yes" : "no",
                (unsigned long)catchup_next,
                catchup_have_meta ? "yes" : "no",
                (unsigned)catchup_rx,
                (unsigned)catchup_last,
	                catchup_full,
	                (unsigned)catchup_missing,
	                (unsigned)catchup_missing_first,
	                (unsigned)catchup_missing_last,
	                catchup_repair_pending_total,
	                catchup_repair_pending_shreds,
	                (unsigned)catchup_repair_max_retries,
	                (unsigned long)tpu_stats.packets_received,
	                (unsigned long)tpu_stats.signatures_verified,
	                (unsigned long)tvu_stats.shreds_received,
                (unsigned long)tvu_stats.shreds_verified,
                (unsigned long)tvu_stats.shreds_failed,
                (unsigned long)tvu_stats.shreds_duplicate,
                (unsigned long)tvu_stats.blocks_completed,
                (unsigned long)tvu_stats.blocks_replayed,
                (unsigned long)tvu_stats.blocks_failed,
                (unsigned long)turbine_stats.shreds_received,
                (unsigned long)turbine_stats.shreds_retransmitted,
                (unsigned long)turbine_stats.duplicate_shreds,
                (unsigned long)turbine_stats.invalid_shreds,
                (unsigned long)turbine_stats.slots_completed,
                (unsigned long)repair_stats.requests_sent,
                repair_pending,
                (unsigned long)repair_stats.responses_received,
                (unsigned long)repair_stats.shreds_repaired,
                (unsigned long)repair_stats.timeouts,
                (unsigned long)repair_stats.duplicates,
                (unsigned long)repair_stats.invalid_responses,
                (unsigned long)votes_count);

        }

        /* Keep the loop responsive enough for mainnet packet rates.
         *
         * A non-trivial sleep here adds an artificial ~200us bubble each
         * iteration when idle, which can accumulate into visible slot pacing
         * jitter. Prefer yielding when there's no immediate work; optionally
         * sleep when explicitly configured for lower CPU usage. */
        static int idle_sleep_us_cached = -1;
        if (__builtin_expect(idle_sleep_us_cached < 0, 0)) {
            const char* env = getenv("SOL_IDLE_SLEEP_US");
            int v = 0;
            if (env && env[0] != '\0') {
                v = atoi(env);
                if (v < 0) v = 0;
                if (v > 1000000) v = 1000000;
            }
            idle_sleep_us_cached = v;
            if (idle_sleep_us_cached > 0) {
                sol_log_info("Idle loop sleep: %dus (env SOL_IDLE_SLEEP_US)", idle_sleep_us_cached);
            }
        }

        if (did_work) {
            sched_yield();
        } else if (idle_sleep_us_cached > 0) {
            usleep((useconds_t)idle_sleep_us_cached);
        } else {
            sched_yield();
        }
    }
}

/*
 * Main entry point
 */
int
main(int argc, char* argv[]) {
    /* Parse command line */
    if (parse_args(argc, argv) != 0) {
        return 1;
    }

    /* Initialize logging */
    sol_log_config_t log_config = SOL_LOG_CONFIG_DEFAULT;
    log_config.level = g_config.log_level;
    log_config.format = g_config.log_format;
    if (g_config.log_file) {
        log_config.log_file = g_config.log_file;
        /* --log-file means "instead of stderr" (also matches --help text). */
        log_config.backends = SOL_LOG_BACKEND_FILE;
    }
    /* Disable colors for JSON format */
    if (g_config.log_format == SOL_LOG_FORMAT_JSON) {
        log_config.use_colors = false;
    }
    sol_log_init(&log_config);

    /* Install best-effort crash handlers (stack traces). */
    sol_crash_install_handlers();

    /* Apply any implicit defaults that should not require flags. */
    validator_apply_implicit_defaults();

    /* Performance default: disable the tx index unless explicitly enabled. */
    validator_apply_tx_index_defaults();

    /* Apply fast-replay overrides before any bank/replay initialization. */
    validator_apply_fast_replay();

    /* Best-effort production default: raise fd limit so RocksDB, networking,
     * and snapshot extraction don't fail on low ulimit settings. */
    validator_try_raise_fd_limit();

    /* Avoid startup failures from default-port conflicts by auto-selecting
     * alternative ports when the defaults are already in use. */
    validator_autoselect_default_ports();

    /* Print startup message */
    sol_log_info("Starting solana-validator %s", SOLANA_C_VERSION_STRING);
    if (g_config.config_file) {
        sol_log_info("Config file: %s", g_config.config_file);
    }
    sol_log_info("Ledger: %s", g_config.ledger_path);
    if (g_config.rocksdb_path) {
        sol_log_info("RocksDB: %s", g_config.rocksdb_path);
    }
    if (g_config.tower_path) {
        sol_log_info("Tower: %s", g_config.tower_path);
    }
    sol_log_info("Log format: %s", sol_log_format_name(g_config.log_format));
    if (g_config.enable_metrics) {
        sol_log_info("Metrics: enabled on port %u", g_config.metrics_port);
    }
    sol_log_info("RPC: %s on %s:%u", g_config.enable_rpc ? "enabled" : "disabled",
                 g_config.rpc_bind, g_config.rpc_port);
    sol_log_info("TPU QUIC: %s", g_config.enable_quic ? "enabled" : "disabled");
    sol_log_info("IO: %s (qd=%u sqpoll=%u)",
                 sol_io_backend_str(g_config.io_backend),
                 (unsigned)g_config.io_queue_depth,
                 g_config.io_sqpoll ? 1u : 0u);

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Initialize validator */
    validator_t validator;
    sol_err_t err = validator_init(&validator);
    if (err != SOL_OK) {
        sol_log_error("Failed to initialize validator: %s", sol_err_str(err));
        return 1;
    }

    /* Snapshot download/extraction may take minutes; re-check default port
     * availability right before binding sockets. */
    validator_autoselect_default_ports();

    /* Start services */
    err = validator_start(&validator);
    if (err != SOL_OK) {
        sol_log_error("Failed to start validator: %s", sol_err_str(err));
        validator_cleanup(&validator);
        return 1;
    }

    /* Run main loop */
    validator_run(&validator);

    /* Stop and cleanup */
    validator_stop(&validator);

    /* Fast exit for dev-halt mode to avoid cleanup hangs */
    if (g_config.dev_halt_at_slot > 0) {
        /* Default: fast-exit to avoid shutdown hangs in dev loops.
         * For profiling/atexit hooks, set SOL_DEV_HALT_FAST_EXIT=0. */
        const char* env = getenv("SOL_DEV_HALT_FAST_EXIT");
        bool fast_exit = true;
        if (env && env[0] != '\0' && strcmp(env, "0") == 0) {
            fast_exit = false;
        }
        if (fast_exit) {
            sol_log_info("Dev halt: fast exit (skipping cleanup)");
            _exit(0);
        }
    }

    validator_cleanup(&validator);

    /* Print final stats */
    sol_log_info("Shutting down...");
    sol_alloc_stats_print();
    sol_log_fini();

    return 0;
}
