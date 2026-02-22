/*
 * sol_dump_account_tool.c - Dump account bytes from a ledger
 *
 * Usage:
 *   sol-dump-account --ledger DIR --pubkey PUBKEY
 *   sol-dump-account --ledger DIR --owner OWNER_PUBKEY [--limit N]
 *
 * This tool is intended for debugging snapshot/account encodings (e.g. vote
 * state versions) without needing RPC.
 */

#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "runtime/sol_accounts_db.h"
#include "txn/sol_pubkey.h"
#include "util/sol_err.h"
#include "util/sol_log.h"

#define VERSION "0.1.0"

static void
print_usage(const char* prog) {
    fprintf(stderr,
            "sol-dump-account %s - Dump account bytes from a ledger\n"
            "\n"
            "Usage:\n"
            "  %s --ledger DIR --pubkey PUBKEY [--bytes N]\n"
            "  %s --ledger DIR --owner OWNER_PUBKEY [--limit N] [--bytes N]\n"
            "\n"
            "Options:\n"
            "  --ledger DIR          Ledger directory (contains rocksdb/ and accounts/)\n"
            "  --pubkey PUBKEY       Base58 pubkey to dump\n"
            "  --owner PUBKEY        Dump first N accounts owned by PUBKEY\n"
            "  --limit N             Number of owner accounts to dump (default: 1)\n"
            "  --bytes N             Number of bytes to dump (default: 256)\n"
            "  --raw-out FILE        Write raw account data bytes to FILE (pubkey mode only)\n"
            "  -h, --help            Show help\n"
            "  -V, --version         Show version\n",
            VERSION,
            prog,
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

static void
print_prefix_u32(const uint8_t* data, size_t len) {
    if (!data || len < 4) return;
    uint32_t v = (uint32_t)data[0] |
                 ((uint32_t)data[1] << 8) |
                 ((uint32_t)data[2] << 16) |
                 ((uint32_t)data[3] << 24);
    printf("prefix_u32=%" PRIu32 "\n", v);
}

typedef struct {
    size_t dump_bytes;
    uint32_t remaining;
} owner_dump_ctx_t;

static bool
owner_dump_cb(const sol_pubkey_t* pubkey, const sol_account_t* account, void* ctx) {
    owner_dump_ctx_t* c = (owner_dump_ctx_t*)ctx;
    if (!pubkey || !account || !c) return false;

    char pk_str[SOL_PUBKEY_BASE58_LEN] = {0};
    (void)sol_pubkey_to_base58(pubkey, pk_str, sizeof(pk_str));

    char owner_str[SOL_PUBKEY_BASE58_LEN] = {0};
    (void)sol_pubkey_to_base58(&account->meta.owner, owner_str, sizeof(owner_str));

    printf("pubkey=%s owner=%s lamports=%" PRIu64 " data_len=%zu exec=%s rent_epoch=%" PRIu64 "\n",
           pk_str,
           owner_str,
           account->meta.lamports,
           account->meta.data_len,
           account->meta.executable ? "yes" : "no",
           account->meta.rent_epoch);

    if (account->data && account->meta.data_len > 0) {
        print_prefix_u32((const uint8_t*)account->data, account->meta.data_len);
        dump_hex((const uint8_t*)account->data, account->meta.data_len, c->dump_bytes);
    }

    if (c->remaining > 0) {
        c->remaining--;
    }
    return c->remaining > 0;
}

int
main(int argc, char** argv) {
    const char* ledger_dir = NULL;
    const char* pubkey_str = NULL;
    const char* owner_str = NULL;
    const char* raw_out = NULL;
    size_t dump_bytes = 256;
    uint32_t limit = 1;

    static const struct option long_opts[] = {
        {"ledger", required_argument, NULL, 'l'},
        {"pubkey", required_argument, NULL, 'p'},
        {"owner", required_argument, NULL, 'o'},
        {"limit", required_argument, NULL, 'n'},
        {"bytes", required_argument, NULL, 'b'},
        {"raw-out", required_argument, NULL, 'r'},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {NULL, 0, NULL, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "hl:p:o:n:b:r:V", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'l':
            ledger_dir = optarg;
            break;
        case 'p':
            pubkey_str = optarg;
            break;
        case 'o':
            owner_str = optarg;
            break;
        case 'n': {
            unsigned long v = strtoul(optarg, NULL, 10);
            if (v == 0) v = 1;
            if (v > UINT32_MAX) v = UINT32_MAX;
            limit = (uint32_t)v;
            break;
        }
        case 'b': {
            unsigned long long v = strtoull(optarg, NULL, 10);
            if (v == 0) v = 256;
            if (v > SIZE_MAX) v = SIZE_MAX;
            dump_bytes = (size_t)v;
            break;
        }
        case 'r':
            raw_out = optarg;
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

    if (!ledger_dir || (pubkey_str && owner_str) || (!pubkey_str && !owner_str) ||
        (raw_out && !pubkey_str)) {
        print_usage(argv[0]);
        return 2;
    }

    char rocksdb_accounts[PATH_MAX];
    char appendvec_dir[PATH_MAX];
    int n1 = snprintf(rocksdb_accounts, sizeof(rocksdb_accounts), "%s/rocksdb/accounts", ledger_dir);
    int n2 = snprintf(appendvec_dir, sizeof(appendvec_dir), "%s/accounts", ledger_dir);
    if (n1 < 0 || n2 < 0 || (size_t)n1 >= sizeof(rocksdb_accounts) || (size_t)n2 >= sizeof(appendvec_dir)) {
        fprintf(stderr, "error: ledger path too long\n");
        return 2;
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

    if (pubkey_str) {
        sol_pubkey_t pk;
        sol_err_t err = sol_pubkey_from_base58(pubkey_str, &pk);
        if (err != SOL_OK) {
            fprintf(stderr, "error: invalid pubkey: %s\n", pubkey_str);
            sol_accounts_db_destroy(db);
            return 2;
        }

        sol_account_t* acct = sol_accounts_db_load(db, &pk);
        if (!acct) {
            fprintf(stderr, "error: account not found\n");
            sol_accounts_db_destroy(db);
            return 1;
        }

        char owner_out[SOL_PUBKEY_BASE58_LEN] = {0};
        (void)sol_pubkey_to_base58(&acct->meta.owner, owner_out, sizeof(owner_out));

        printf("owner=%s lamports=%" PRIu64 " data_len=%zu exec=%s rent_epoch=%" PRIu64 "\n",
               owner_out,
               acct->meta.lamports,
               acct->meta.data_len,
               acct->meta.executable ? "yes" : "no",
               acct->meta.rent_epoch);

        if (raw_out) {
            FILE* f = fopen(raw_out, "wb");
            if (!f) {
                fprintf(stderr, "error: failed to open %s\n", raw_out);
                sol_account_destroy(acct);
                sol_accounts_db_destroy(db);
                return 1;
            }
            size_t n = fwrite(acct->data, 1, acct->meta.data_len, f);
            fclose(f);
            if (n != acct->meta.data_len) {
                fprintf(stderr, "error: short write to %s\n", raw_out);
                sol_account_destroy(acct);
                sol_accounts_db_destroy(db);
                return 1;
            }
        }

        if (acct->data && acct->meta.data_len > 0) {
            print_prefix_u32((const uint8_t*)acct->data, acct->meta.data_len);
            dump_hex((const uint8_t*)acct->data, acct->meta.data_len, dump_bytes);
        }

        sol_account_destroy(acct);
        sol_accounts_db_destroy(db);
        return 0;
    }

    sol_pubkey_t owner;
    sol_err_t err = sol_pubkey_from_base58(owner_str, &owner);
    if (err != SOL_OK) {
        fprintf(stderr, "error: invalid owner pubkey: %s\n", owner_str);
        sol_accounts_db_destroy(db);
        return 2;
    }

    owner_dump_ctx_t ctx = {
        .dump_bytes = dump_bytes,
        .remaining = limit,
    };

    sol_accounts_db_iterate_owner(db, &owner, owner_dump_cb, &ctx);
    sol_accounts_db_destroy(db);

    if (ctx.remaining == limit) {
        fprintf(stderr, "warn: no matching accounts found\n");
    }

    return 0;
}
