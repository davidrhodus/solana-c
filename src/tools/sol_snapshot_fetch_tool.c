/*
 * sol_snapshot_fetch_tool.c - Download latest Solana snapshots
 *
 * Usage:
 *   sol-snapshot-fetch --output-dir DIR [--network mainnet-beta|testnet|devnet]
 *                     [--manifest-url URL] [--rpc-url URL]... [--no-incremental]
 *                     [--connections N] [--timeout SECS]
 *
 * This tool downloads a full snapshot (and optional incremental snapshot)
 * into the provided directory. By default it prefers the freshest advertised
 * snapshot among the configured sources (snapshot-service manifest + RPC URLs).
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
            "  --rpc-url URL        RPC URL used for snapshot download (repeatable)\n"
            "  --no-incremental     Only download full snapshot\n"
            "  --connections N      Parallel range request limit (default: %u)\n"
            "  --timeout SECS       Curl timeout per request (default: %u)\n"
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

static const char*
default_rpc_for_network(const char* network) {
    network = normalize_network(network);
    if (strcmp(network, "devnet") == 0) return SOL_DEVNET_RPC;
    if (strcmp(network, "testnet") == 0) return SOL_TESTNET_RPC;
    return SOL_MAINNET_RPC;
}

static sol_err_t
query_rpc_best(const char* const* rpc_urls,
               size_t rpc_url_count,
               bool allow_incremental,
               sol_available_snapshot_t* out_full,
               sol_available_snapshot_t* out_incr,
               sol_slot_t* out_best_slot) {
    if (!out_full || !out_incr || !out_best_slot) return SOL_ERR_INVAL;

    *out_full = (sol_available_snapshot_t){0};
    *out_incr = (sol_available_snapshot_t){0};
    *out_best_slot = 0;

    bool have = false;

    for (size_t i = 0; i < rpc_url_count; i++) {
        const char* rpc_url = rpc_urls[i];
        if (!rpc_url || rpc_url[0] == '\0') continue;

        sol_available_snapshot_t candidates[4];
        memset(candidates, 0, sizeof(candidates));
        size_t n = sol_snapshot_query_available(rpc_url, candidates, 4);

        sol_available_snapshot_t* full = NULL;
        sol_available_snapshot_t* incr = NULL;
        for (size_t j = 0; j < n; j++) {
            if (candidates[j].type == SOL_SNAPSHOT_FULL) {
                full = &candidates[j];
            } else if (candidates[j].type == SOL_SNAPSHOT_INCREMENTAL) {
                incr = &candidates[j];
            }
        }

        sol_slot_t best_slot = 0;
        if (full && full->url && full->slot != 0) {
            best_slot = full->slot;
            if (allow_incremental && incr && incr->url && incr->slot != 0 &&
                incr->base_slot == full->slot && incr->slot > full->slot) {
                best_slot = incr->slot;
            }
        }

        if (best_slot != 0 && (!have || best_slot > *out_best_slot)) {
            sol_available_snapshot_free(out_full);
            sol_available_snapshot_free(out_incr);

            if (full) {
                *out_full = *full;
                full->url = NULL; /* transfer ownership */
            }
            if (allow_incremental && incr && incr->url && incr->base_slot == out_full->slot) {
                *out_incr = *incr;
                incr->url = NULL; /* transfer ownership */
            } else {
                *out_incr = (sol_available_snapshot_t){0};
            }

            *out_best_slot = best_slot;
            have = true;
        }

        for (size_t j = 0; j < n; j++) {
            sol_available_snapshot_free(&candidates[j]);
        }
    }

    return have ? SOL_OK : SOL_ERR_NOTFOUND;
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

    /* Default: always have at least one RPC URL available for staleness checks
     * and as a fallback download source. We still prefer the snapshot-service
     * manifest unless it lags significantly, to avoid public RPC rate limits. */
    if (rpc_url_count == 0) {
        rpc_urls = (const char**)sol_alloc(sizeof(const char*));
        if (!rpc_urls) {
            fprintf(stderr, "error: out of memory\n");
            return 1;
        }
        rpc_urls[0] = default_rpc_for_network(network);
        rpc_url_count = 1;
    }

    sol_log_config_t log_cfg = (sol_log_config_t)SOL_LOG_CONFIG_DEFAULT;
    log_cfg.level = SOL_LOG_INFO;
    sol_log_init(&log_cfg);

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

    sol_available_snapshot_t rpc_full = {0};
    sol_available_snapshot_t rpc_incr = {0};
    sol_slot_t rpc_best_slot = 0;
    sol_err_t rpc_qerr = query_rpc_best(
        rpc_urls, rpc_url_count, !no_incremental, &rpc_full, &rpc_incr, &rpc_best_slot);
    bool have_rpc = (rpc_qerr == SOL_OK && rpc_full.slot != 0);

    if (!have_manifest && !have_rpc) {
        sol_log_error("No snapshots available from configured sources");
        sol_available_snapshot_free(&manifest_full);
        sol_available_snapshot_free(&manifest_incr);
        sol_available_snapshot_free(&rpc_full);
        sol_available_snapshot_free(&rpc_incr);
        sol_free(rpc_urls);
        return 1;
    }

    /* Default behavior: prefer the snapshot-service manifest when available.
     * Public RPC snapshot endpoints are often rate-limited (429) and may be
     * less reliable.
     *
     * However, if the manifest lags the freshest RPC snapshot by a large
     * margin, the older snapshot may fail to catch up due to shred pruning.
     * In that case, prefer RPC and fall back to the manifest on failure. */
    bool prefer_rpc = (!have_manifest && have_rpc);
    if (have_manifest && have_rpc && manifest_best_slot != 0 && rpc_best_slot != 0) {
        const sol_slot_t max_manifest_lag = 50000; /* ~5.5 hours @ ~400ms/slot */
        if (rpc_best_slot > manifest_best_slot &&
            (rpc_best_slot - manifest_best_slot) > max_manifest_lag) {
            sol_log_warn("Snapshot service manifest lags RPC by %lu slots (manifest=%lu rpc=%lu); preferring RPC",
                         (unsigned long)(rpc_best_slot - manifest_best_slot),
                         (unsigned long)manifest_best_slot,
                         (unsigned long)rpc_best_slot);
            prefer_rpc = true;
        }
    }

    char full_path[PATH_MAX] = {0};
    char incr_path[PATH_MAX] = {0};

    sol_err_t dl_err = SOL_ERR_IO;
    if (prefer_rpc) {
        sol_log_info("Selecting RPC snapshots (slot %lu)", (unsigned long)rpc_best_slot);
        dl_err = sol_snapshot_download(&rpc_full, &opts, full_path, sizeof(full_path));
        if (dl_err == SOL_OK && !no_incremental && rpc_incr.url) {
            sol_err_t ierr = sol_snapshot_download(&rpc_incr, &opts, incr_path, sizeof(incr_path));
            if (ierr != SOL_OK) {
                sol_log_warn("Incremental download failed (continuing with full): %s", sol_err_str(ierr));
                incr_path[0] = '\0';
            }
        }

        if (dl_err != SOL_OK && have_manifest) {
            sol_log_warn("RPC snapshot download failed (%s); falling back to manifest",
                         sol_err_str(dl_err));
            prefer_rpc = false;
        }
    }

    if (!prefer_rpc) {
        sol_log_info("Selecting manifest snapshots (slot %lu): %s",
                     (unsigned long)manifest_best_slot,
                     manifest_url ? manifest_url : "(none)");
        dl_err = sol_snapshot_download(&manifest_full, &opts, full_path, sizeof(full_path));
        if (dl_err == SOL_OK && !no_incremental &&
            manifest_incr.type == SOL_SNAPSHOT_INCREMENTAL && manifest_incr.url) {
            sol_err_t ierr = sol_snapshot_download(&manifest_incr, &opts, incr_path, sizeof(incr_path));
            if (ierr != SOL_OK) {
                sol_log_warn("Incremental download failed (continuing with full): %s", sol_err_str(ierr));
                incr_path[0] = '\0';
            }
        }

        /* If the snapshot service manifest does not advertise an incremental
         * snapshot (common for some services), fall back to any matching RPC
         * incremental snapshot so bootstrap doesn't have to repair an older
         * base slot window. */
        if (dl_err == SOL_OK && !no_incremental && incr_path[0] == '\0' &&
            have_rpc &&
            rpc_incr.type == SOL_SNAPSHOT_INCREMENTAL &&
            rpc_incr.url &&
            rpc_incr.base_slot == manifest_full.slot &&
            rpc_incr.slot > manifest_full.slot) {
            sol_log_info("Manifest did not provide incremental for base slot %lu; downloading RPC incremental (slot %lu)",
                         (unsigned long)manifest_full.slot,
                         (unsigned long)rpc_incr.slot);
            sol_err_t ierr = sol_snapshot_download(&rpc_incr, &opts, incr_path, sizeof(incr_path));
            if (ierr != SOL_OK) {
                sol_log_warn("RPC incremental download failed (continuing with full): %s", sol_err_str(ierr));
                incr_path[0] = '\0';
            }
        }

        if (dl_err != SOL_OK && have_rpc) {
            sol_log_warn("Manifest snapshot download failed (%s); trying RPC fallback",
                         sol_err_str(dl_err));
            dl_err = sol_snapshot_download(&rpc_full, &opts, full_path, sizeof(full_path));
            if (dl_err == SOL_OK && !no_incremental && rpc_incr.url) {
                sol_err_t ierr = sol_snapshot_download(&rpc_incr, &opts, incr_path, sizeof(incr_path));
                if (ierr != SOL_OK) {
                    sol_log_warn("Incremental download failed (continuing with full): %s", sol_err_str(ierr));
                    incr_path[0] = '\0';
                }
            }
        }
    }

    if (dl_err != SOL_OK) {
        sol_log_error("Snapshot download failed: %s", sol_err_str(dl_err));
        sol_available_snapshot_free(&manifest_full);
        sol_available_snapshot_free(&manifest_incr);
        sol_available_snapshot_free(&rpc_full);
        sol_available_snapshot_free(&rpc_incr);
        sol_free(rpc_urls);
        return 1;
    }

    printf("full=%s\n", full_path);
    if (incr_path[0] != '\0') {
        printf("incremental=%s\n", incr_path);
    }

    sol_available_snapshot_free(&manifest_full);
    sol_available_snapshot_free(&manifest_incr);
    sol_available_snapshot_free(&rpc_full);
    sol_available_snapshot_free(&rpc_incr);
    sol_free(rpc_urls);
    return 0;
}
