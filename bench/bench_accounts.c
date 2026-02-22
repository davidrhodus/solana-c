/*
 * bench_accounts.c - AccountsDB load/store benchmark (memory backend)
 */

#include "bench_common.h"

#include "runtime/sol_account.h"
#include "runtime/sol_accounts_db.h"
#include "util/sol_log.h"

int
main(int argc, char** argv) {
    sol_log_config_t log_cfg = SOL_LOG_CONFIG_DEFAULT;
    log_cfg.level = SOL_LOG_OFF;
    sol_log_init(&log_cfg);

    uint64_t iters = bench_parse_u64_arg(argc, argv, "--iters", 500000ULL);
    uint64_t data_len = bench_parse_u64_arg(argc, argv, "--data-len", 0ULL);

    if (data_len > SOL_ACCOUNT_MAX_DATA_SIZE) {
        fprintf(stderr, "invalid --data-len (max %u)\n", (unsigned)SOL_ACCOUNT_MAX_DATA_SIZE);
        return 2;
    }

    sol_accounts_db_t* db = sol_accounts_db_new(NULL);
    if (!db) {
        fprintf(stderr, "sol_accounts_db_new failed\n");
        return 2;
    }

    sol_pubkey_t key = {0};
    for (size_t i = 0; i < sizeof(key.bytes); i++) {
        key.bytes[i] = (uint8_t)(i + 1);
    }

    sol_account_t* account = sol_account_new(1, (size_t)data_len, &SOL_SYSTEM_PROGRAM_ID);
    if (!account) {
        fprintf(stderr, "sol_account_new failed\n");
        sol_accounts_db_destroy(db);
        return 2;
    }

    if (sol_accounts_db_store(db, &key, account) != SOL_OK) {
        fprintf(stderr, "sol_accounts_db_store failed\n");
        sol_account_destroy(account);
        sol_accounts_db_destroy(db);
        return 2;
    }

    volatile uint64_t accum = 0;

    uint64_t start = bench_now_ns();
    for (uint64_t i = 0; i < iters; i++) {
        sol_account_t* loaded = sol_accounts_db_load(db, &key);
        if (!loaded) {
            fprintf(stderr, "sol_accounts_db_load returned NULL\n");
            sol_account_destroy(account);
            sol_accounts_db_destroy(db);
            return 2;
        }

        accum += loaded->meta.lamports;
        sol_account_destroy(loaded);
    }
    uint64_t end = bench_now_ns();
    bench_print_rate("accounts_load", iters, end - start);

    start = bench_now_ns();
    for (uint64_t i = 0; i < iters; i++) {
        account->meta.lamports++;
        if (sol_accounts_db_store(db, &key, account) != SOL_OK) {
            fprintf(stderr, "sol_accounts_db_store failed\n");
            sol_account_destroy(account);
            sol_accounts_db_destroy(db);
            return 2;
        }
        accum += account->meta.lamports;
    }
    end = bench_now_ns();
    bench_print_rate("accounts_store", iters, end - start);

    printf("accum: %" PRIu64 "\n", accum);

    sol_account_destroy(account);
    sol_accounts_db_destroy(db);
    sol_log_fini();
    return 0;
}
