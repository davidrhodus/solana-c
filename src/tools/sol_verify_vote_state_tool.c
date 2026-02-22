/*
 * sol_verify_vote_state_tool.c - Verify VoteState (de)serialization roundtrips
 *
 * Usage:
 *   sol-verify-vote-state --ledger DIR [--limit N]
 *
 * Iterates vote program-owned accounts and checks that:
 *   deserialize(bytes) -> state -> serialize(state) == original bytes
 *
 * This is an offline sanity check to catch encoding regressions before running
 * full mainnet replay/parity.
 */

#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "programs/sol_vote_program.h"
#include "runtime/sol_accounts_db.h"
#include "txn/sol_pubkey.h"
#include "util/sol_err.h"

#define VERSION "0.1.0"

static void
print_usage(const char* prog) {
    fprintf(stderr,
            "sol-verify-vote-state %s - Verify vote state roundtrip encoding\n"
            "\n"
            "Usage:\n"
            "  %s --ledger DIR [--limit N] [--stop-on-mismatch]\n"
            "\n"
            "Options:\n"
            "  --ledger DIR          Ledger directory (contains rocksdb/ and accounts/)\n"
            "  --limit N             Number of vote accounts to check (default: 1000)\n"
            "  --stop-on-mismatch    Exit on first mismatch\n"
            "  -h, --help            Show help\n"
            "  -V, --version         Show version\n",
            VERSION,
            prog);
}

typedef struct {
    uint64_t limit;
    uint64_t checked;
    uint64_t parsed_ok;
    uint64_t parsed_err;
    uint64_t mismatches;
    bool     stop_on_mismatch;
    bool     should_stop;
} verify_ctx_t;

static bool
verify_vote_roundtrip_cb(const sol_pubkey_t* pubkey, const sol_account_t* account, void* ctx) {
    verify_ctx_t* c = (verify_ctx_t*)ctx;
    if (!c || !pubkey || !account) return false;
    if (c->should_stop) return false;
    if (c->checked >= c->limit) return false;

    if (!sol_pubkey_eq(&account->meta.owner, &SOL_VOTE_PROGRAM_ID)) {
        return true;
    }

    c->checked++;

    if (!account->data || account->meta.data_len < 4 || account->meta.data_len > 4096) {
        c->parsed_err++;
        return true;
    }

    sol_vote_state_t state = {0};
    sol_err_t err = sol_vote_state_deserialize(&state, account->data, account->meta.data_len);
    if (err != SOL_OK) {
        /* Version 0/uninitialized vote accounts exist; treat as non-fatal. */
        c->parsed_err++;
        return true;
    }

    uint8_t tmp[4096];
    memcpy(tmp, account->data, account->meta.data_len);
    size_t written = 0;
    err = sol_vote_state_serialize(&state, tmp, account->meta.data_len, &written);
    if (err != SOL_OK) {
        c->parsed_err++;
        return true;
    }

    if (memcmp(tmp, account->data, account->meta.data_len) != 0) {
        c->mismatches++;

        size_t first = 0;
        for (; first < account->meta.data_len; first++) {
            if (tmp[first] != account->data[first]) break;
        }

        char pk_str[SOL_PUBKEY_BASE58_LEN] = {0};
        (void)sol_pubkey_to_base58(pubkey, pk_str, sizeof(pk_str));

        fprintf(stderr,
                "mismatch pubkey=%s onchain_ver=%" PRIu32 " data_len=%zu first_diff=%zu\n",
                pk_str,
                state.onchain_version,
                account->meta.data_len,
                first);

        if (c->stop_on_mismatch) {
            c->should_stop = true;
            return false;
        }
    } else {
        c->parsed_ok++;
    }

    return true;
}

int
main(int argc, char** argv) {
    const char* ledger_dir = NULL;
    uint64_t limit = 1000;
    bool stop_on_mismatch = false;

    static const struct option long_opts[] = {
        {"ledger", required_argument, NULL, 'l'},
        {"limit", required_argument, NULL, 'n'},
        {"stop-on-mismatch", no_argument, NULL, 's'},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {NULL, 0, NULL, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "hl:n:sV", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'l':
            ledger_dir = optarg;
            break;
        case 'n':
            limit = strtoull(optarg, NULL, 10);
            if (limit == 0) limit = 1;
            break;
        case 's':
            stop_on_mismatch = true;
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

    if (!ledger_dir || ledger_dir[0] == '\0') {
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

    verify_ctx_t ctx = {
        .limit = limit,
        .checked = 0,
        .parsed_ok = 0,
        .parsed_err = 0,
        .mismatches = 0,
        .stop_on_mismatch = stop_on_mismatch,
        .should_stop = false,
    };

    sol_accounts_db_iterate_owner(db, &SOL_VOTE_PROGRAM_ID, verify_vote_roundtrip_cb, &ctx);
    sol_accounts_db_destroy(db);

    printf("checked=%" PRIu64 " ok=%" PRIu64 " err=%" PRIu64 " mismatches=%" PRIu64 "\n",
           ctx.checked, ctx.parsed_ok, ctx.parsed_err, ctx.mismatches);

    return ctx.mismatches == 0 ? 0 : 1;
}
