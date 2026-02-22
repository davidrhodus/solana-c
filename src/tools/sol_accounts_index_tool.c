/*
 * sol_accounts_index_tool.c - Build/verify AccountsDB owner index metadata
 *
 * Usage:
 *   sol-accounts-index --rocksdb-path PATH
 *
 * This tool opens AccountsDB at PATH/accounts and runs the one-time owner index
 * initialization (if needed). It is useful for prebuilding the index offline
 * after snapshot ingestion.
 */

#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "runtime/sol_accounts_db.h"
#include "util/sol_err.h"
#include "util/sol_log.h"

#define VERSION "0.1.0"

static void
print_usage(const char* prog) {
    fprintf(stderr,
            "sol-accounts-index %s - Build AccountsDB owner index\n"
            "\n"
            "Usage:\n"
            "  %s --rocksdb-path PATH\n"
            "\n"
            "Options:\n"
            "  --rocksdb-path PATH   RocksDB base directory (contains accounts/)\n"
            "  -h, --help            Show help\n"
            "  -V, --version         Show version\n",
            VERSION,
            prog);
}

static uint64_t
now_ms(void) {
    struct timespec ts = {0};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000u);
}

int
main(int argc, char** argv) {
    const char* rocksdb_path = NULL;

    static const struct option long_opts[] = {
        {"rocksdb-path", required_argument, NULL, 'r'},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {NULL, 0, NULL, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "hr:V", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'r':
            rocksdb_path = optarg;
            break;
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

    if (!rocksdb_path || rocksdb_path[0] == '\0') {
        print_usage(argv[0]);
        return 2;
    }

    char accounts_path[4096];
    int n = snprintf(accounts_path, sizeof(accounts_path), "%s/accounts", rocksdb_path);
    if (n < 0 || (size_t)n >= sizeof(accounts_path)) {
        sol_log_error("Accounts RocksDB path too long");
        return 2;
    }

    sol_accounts_db_config_t cfg = SOL_ACCOUNTS_DB_CONFIG_DEFAULT;
    cfg.storage_type = SOL_ACCOUNTS_STORAGE_ROCKSDB;
    cfg.rocksdb_path = accounts_path;

    sol_accounts_db_t* db = sol_accounts_db_new(&cfg);
    if (!db) {
        sol_log_error("Failed to open AccountsDB at %s", accounts_path);
        return 1;
    }

    bool wal_disabled = false;
    bool bulk_load_mode = false;
    if (sol_accounts_db_set_disable_wal(db, true) == SOL_OK) {
        wal_disabled = true;
    }
    if (sol_accounts_db_set_bulk_load_mode(db, true) == SOL_OK) {
        bulk_load_mode = true;
    }

    uint64_t start_ms = now_ms();
    sol_err_t err = sol_accounts_db_ensure_owner_index(db);
    uint64_t elapsed_ms = now_ms() - start_ms;

    if (wal_disabled) {
        (void)sol_accounts_db_set_disable_wal(db, false);
    }
    if (bulk_load_mode) {
        (void)sol_accounts_db_set_bulk_load_mode(db, false);
    }

    if (err != SOL_OK) {
        sol_log_error("Owner index build failed: %s", sol_err_str(err));
        sol_accounts_db_destroy(db);
        return 1;
    }

    sol_accounts_db_stats_t stats = {0};
    sol_accounts_db_stats(db, &stats);
    sol_accounts_db_destroy(db);

    printf("ok elapsed_ms=%" PRIu64 " accounts=%" PRIu64 " lamports=%" PRIu64 " data_bytes=%" PRIu64 "\n",
           elapsed_ms,
           stats.accounts_count,
           stats.total_lamports,
           stats.total_data_bytes);
    return 0;
}

