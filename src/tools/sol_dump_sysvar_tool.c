/*
 * sol_dump_sysvar_tool.c - Dump sysvar account bytes from a ledger
 *
 * Usage:
 *   sol-dump-sysvar --ledger DIR --sysvar slot-history
 */

#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "runtime/sol_accounts_db.h"
#include "runtime/sol_sysvar.h"
#include "util/sol_err.h"
#include "util/sol_log.h"

#define VERSION "0.1.0"

static void
print_usage(const char* prog) {
    fprintf(stderr,
            "sol-dump-sysvar %s - Dump sysvar account bytes from a ledger\n"
            "\n"
            "Usage:\n"
            "  %s --ledger DIR --sysvar slot-history\n"
            "\n"
            "Options:\n"
            "  --ledger DIR          Ledger directory (contains rocksdb/ and accounts/)\n"
            "  --sysvar NAME         slot-history (only)\n"
            "  --bytes N             Number of bytes to dump (default: 128)\n"
            "  -h, --help            Show help\n"
            "  -V, --version         Show version\n",
            VERSION,
            prog);
}

static void
dump_hex(const uint8_t* data, size_t len, size_t max) {
    size_t n = len < max ? len : max;
    for (size_t i = 0; i < n; i++) {
        if (i && (i % 16u) == 0u) printf("\n");
        printf("%02x ", (unsigned)data[i]);
    }
    if (n) printf("\n");
}

int
main(int argc, char** argv) {
    const char* ledger_dir = NULL;
    const char* sysvar_name = NULL;
    size_t dump_bytes = 128;

    static const struct option long_opts[] = {
        {"ledger", required_argument, NULL, 'l'},
        {"sysvar", required_argument, NULL, 's'},
        {"bytes", required_argument, NULL, 'b'},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {NULL, 0, NULL, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "hl:s:b:V", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'l':
            ledger_dir = optarg;
            break;
        case 's':
            sysvar_name = optarg;
            break;
        case 'b':
            dump_bytes = (size_t)strtoull(optarg, NULL, 10);
            if (dump_bytes == 0) dump_bytes = 128;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        case 'V':
            printf("%s\n", VERSION);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!ledger_dir || !sysvar_name) {
        print_usage(argv[0]);
        return 1;
    }

    const sol_pubkey_t* sysvar = NULL;
    if (strcmp(sysvar_name, "slot-history") == 0) {
        sysvar = &SOL_SYSVAR_SLOT_HISTORY_ID;
    } else {
        fprintf(stderr, "error: unsupported sysvar: %s\n", sysvar_name);
        return 1;
    }

    char rocksdb_accounts[PATH_MAX];
    char appendvec_dir[PATH_MAX];
    int n1 = snprintf(rocksdb_accounts, sizeof(rocksdb_accounts), "%s/rocksdb/accounts", ledger_dir);
    int n2 = snprintf(appendvec_dir, sizeof(appendvec_dir), "%s/accounts", ledger_dir);
    if (n1 < 0 || n2 < 0 || (size_t)n1 >= sizeof(rocksdb_accounts) || (size_t)n2 >= sizeof(appendvec_dir)) {
        fprintf(stderr, "error: ledger path too long\n");
        return 1;
    }

    sol_accounts_db_config_t cfg = SOL_ACCOUNTS_DB_CONFIG_DEFAULT;
    cfg.storage_type = SOL_ACCOUNTS_STORAGE_APPENDVEC;
    cfg.rocksdb_path = rocksdb_accounts;
    cfg.appendvec_path = appendvec_dir;
    cfg.enable_snapshots = true;

    sol_accounts_db_t* db = sol_accounts_db_new(&cfg);
    if (!db) {
        fprintf(stderr, "error: failed to open accounts db (%s)\n", rocksdb_accounts);
        return 1;
    }

    sol_account_t* acct = sol_accounts_db_load(db, sysvar);
    if (!acct) {
        sol_accounts_db_destroy(db);
        fprintf(stderr, "error: sysvar not found\n");
        return 1;
    }

    printf("data_len=%zu lamports=%" PRIu64 "\n", acct->meta.data_len, acct->meta.lamports);

    if (acct->data && acct->meta.data_len > 0) {
        dump_hex((const uint8_t*)acct->data, acct->meta.data_len, dump_bytes);
    }

    sol_account_destroy(acct);
    sol_accounts_db_destroy(db);
    return 0;
}

