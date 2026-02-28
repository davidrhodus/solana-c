/*
 * sol_snapshot_fetch_tool.c - Download latest Solana snapshots
 *
 * Usage:
 *   sol-snapshot-fetch --output-dir DIR [--network mainnet-beta|testnet|devnet]
 *                     [--manifest-url URL] [--rpc-url URL]... [--no-incremental]
 *                     [--connections N] [--timeout SECS]
 *
 * This tool downloads a full snapshot (and optional incremental snapshot)
 * into the provided directory. Snapshot downloads are sourced only from the
 * snapshot-service manifest; RPC snapshot URLs are ignored.
 */

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>

#include "snapshot/sol_snapshot_download.h"
#include "util/sol_alloc.h"
#include "util/sol_err.h"
#include "util/sol_io.h"
#include "util/sol_log.h"

#define VERSION "0.1.0"

static void
print_usage(const char* prog) {
    sol_snapshot_download_opts_t defaults = SOL_SNAPSHOT_DOWNLOAD_OPTS_DEFAULT;
    fprintf(stderr,
            "sol-snapshot-fetch %s - Download latest Solana snapshots\n"
            "\n"
            "Usage:\n"
            "  %s --output-dir DIR [options]\n"
            "\n"
            "Options:\n"
            "  --output-dir DIR     Directory to write snapshot archives\n"
            "  --network NET        mainnet-beta|testnet|devnet (default: mainnet-beta)\n"
            "  --manifest-url URL   Snapshot manifest URL (default: %s)\n"
            "  --rpc-url URL        (ignored) RPC URL (snapshot downloads use manifest only)\n"
            "  --no-incremental     Only download full snapshot\n"
            "  --connections N      Parallel range request limit (default: %u)\n"
            "  --timeout SECS       Download timeout per request (default: %u)\n"
            "  -h, --help           Show help\n"
            "  -V, --version        Show version\n",
            VERSION,
            prog,
            SOL_MAINNET_SNAPSHOT_MANIFEST_URL,
            (unsigned)defaults.parallel_connections,
            (unsigned)defaults.timeout_secs);
}

static int
mkdir_recursive(const char* path) {
    if (!path || path[0] == '\0') return -1;

    char tmp[PATH_MAX];
    size_t len = strlen(path);
    if (len >= sizeof(tmp)) return -1;
    memcpy(tmp, path, len + 1);

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

static const char*
normalize_network(const char* network) {
    if (!network || network[0] == '\0') return "mainnet-beta";
    if (strcmp(network, "mainnet") == 0) return "mainnet-beta";
    return network;
}

int
main(int argc, char** argv) {
    const char* output_dir = NULL;
    const char* network = "mainnet-beta";
    const char* manifest_url = SOL_MAINNET_SNAPSHOT_MANIFEST_URL;
    bool manifest_url_set = false;
    bool no_incremental = false;
    bool connections_set = false;
    uint32_t connections = 0;
    bool timeout_set = false;
    uint32_t timeout_secs = 0;

    const char** rpc_urls = NULL;
    size_t rpc_url_count = 0;

    static const struct option long_opts[] = {
        {"output-dir", required_argument, NULL, 'o'},
        {"network", required_argument, NULL, 'n'},
        {"manifest-url", required_argument, NULL, 'm'},
        {"rpc-url", required_argument, NULL, 'r'},
        {"no-incremental", no_argument, NULL, 1000},
        {"connections", required_argument, NULL, 1001},
        {"timeout", required_argument, NULL, 1002},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {NULL, 0, NULL, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "ho:n:m:r:V", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'o':
            output_dir = optarg;
            break;
        case 'n':
            network = optarg;
            break;
        case 'm':
            manifest_url = optarg;
            manifest_url_set = true;
            break;
        case 'r': {
            const char** next = (const char**)sol_realloc(rpc_urls, (rpc_url_count + 1) * sizeof(const char*));
            if (!next) {
                sol_free(rpc_urls);
                fprintf(stderr, "error: out of memory\n");
                return 1;
            }
            rpc_urls = next;
            rpc_urls[rpc_url_count++] = optarg;
            break;
        }
        case 1000:
            no_incremental = true;
            break;
        case 1001: {
            char* end = NULL;
            errno = 0;
            unsigned long v = strtoul(optarg, &end, 10);
            if (errno != 0 || !end || end == optarg || *end != '\0' || v < 2 || v > 1000000) {
                fprintf(stderr, "error: --connections must be an integer >=2\n");
                return 2;
            }
            connections = (uint32_t)v;
            connections_set = true;
            break;
        }
        case 1002: {
            char* end = NULL;
            errno = 0;
            unsigned long v = strtoul(optarg, &end, 10);
            if (errno != 0 || !end || end == optarg || *end != '\0' || v > 1000000) {
                fprintf(stderr, "error: --timeout must be a non-negative integer\n");
                return 2;
            }
            timeout_secs = (uint32_t)v;
            timeout_set = true;
            break;
        }
        case 'h':
            print_usage(argv[0]);
            return 0;
        case 'V':
            printf("%s\n", VERSION);
            return 0;
        default:
            print_usage(argv[0]);
            return 2;
        }
    }

    if (!output_dir || output_dir[0] == '\0') {
        print_usage(argv[0]);
        return 2;
    }

    network = normalize_network(network);
    if (!manifest_url_set && strcmp(network, "mainnet-beta") != 0) {
        /* Only mainnet has a default snapshot-service manifest configured. */
        manifest_url = NULL;
    }

    sol_log_config_t log_cfg = (sol_log_config_t)SOL_LOG_CONFIG_DEFAULT;
    log_cfg.level = SOL_LOG_INFO;
    sol_log_init(&log_cfg);

    if (rpc_url_count > 0) {
        sol_log_warn("RPC snapshot URLs are ignored; downloads use the manifest only");
    }

    if (mkdir_recursive(output_dir) != 0) {
        sol_log_error("Failed to create output dir: %s", output_dir);
        sol_free(rpc_urls);
        return 1;
    }

    sol_snapshot_download_opts_t opts = SOL_SNAPSHOT_DOWNLOAD_OPTS_DEFAULT;
    opts.output_dir = output_dir;
    opts.allow_incremental = !no_incremental;
    if (connections_set) {
        opts.parallel_connections = connections;
    }
    if (timeout_set) {
        opts.timeout_secs = timeout_secs;
    }

    sol_io_options_t io_opts = SOL_IO_OPTIONS_DEFAULT;
#ifdef __linux__
    io_opts.backend = SOL_IO_BACKEND_URING;
#endif
    sol_io_ctx_t* io_ctx = sol_io_ctx_new(&io_opts);
    opts.io_ctx = io_ctx;
    sol_log_info("Disk IO backend: %s", sol_io_backend_str(sol_io_ctx_backend(io_ctx)));

    sol_available_snapshot_t manifest_full = {0};
    sol_available_snapshot_t manifest_incr = {0};
    sol_slot_t manifest_best_slot = 0;
    bool have_manifest = false;
    if (manifest_url && manifest_url[0] != '\0') {
        sol_snapshot_download_opts_t qopts = opts;
        qopts.verify_after = false;
        qopts.resume = false;
        sol_err_t qerr = sol_snapshot_service_find_best_download(
            manifest_url, &qopts, &manifest_full, &manifest_incr);
        if (qerr == SOL_OK && manifest_full.slot != 0) {
            have_manifest = true;
            if (!no_incremental &&
                manifest_incr.type == SOL_SNAPSHOT_INCREMENTAL && manifest_incr.slot != 0) {
                manifest_best_slot = manifest_incr.slot;
            } else {
                manifest_best_slot = manifest_full.slot;
            }
        }
    }

    if (!have_manifest) {
        sol_log_error("No snapshots available from manifest (set --manifest-url)");
        sol_available_snapshot_free(&manifest_full);
        sol_available_snapshot_free(&manifest_incr);
        sol_free(rpc_urls);
        sol_io_ctx_destroy(io_ctx);
        return 1;
    }

    char full_path[PATH_MAX] = {0};
    char incr_path[PATH_MAX] = {0};

    sol_log_info("Selecting manifest snapshots (slot %lu): %s",
                 (unsigned long)manifest_best_slot,
                 manifest_url ? manifest_url : "(none)");
    sol_err_t dl_err = sol_snapshot_download(&manifest_full, &opts, full_path, sizeof(full_path));
    if (dl_err == SOL_OK && !no_incremental &&
        manifest_incr.type == SOL_SNAPSHOT_INCREMENTAL && manifest_incr.url) {
        sol_err_t ierr = sol_snapshot_download(&manifest_incr, &opts, incr_path, sizeof(incr_path));
        if (ierr != SOL_OK) {
            sol_log_warn("Incremental download failed (continuing with full): %s", sol_err_str(ierr));
            incr_path[0] = '\0';
        }
    }

    if (dl_err != SOL_OK) {
        sol_log_error("Snapshot download failed: %s", sol_err_str(dl_err));
        sol_available_snapshot_free(&manifest_full);
        sol_available_snapshot_free(&manifest_incr);
        sol_free(rpc_urls);
        sol_io_ctx_destroy(io_ctx);
        return 1;
    }

    printf("full=%s\n", full_path);
    if (incr_path[0] != '\0') {
        printf("incremental=%s\n", incr_path);
    }

    sol_available_snapshot_free(&manifest_full);
    sol_available_snapshot_free(&manifest_incr);
    sol_free(rpc_urls);
    sol_io_ctx_destroy(io_ctx);
    return 0;
}
