#include "blockstore/sol_blockstore.h"
#include "entry/sol_entry.h"
#include "util/sol_err.h"
#include "util/sol_log.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t
now_ns(void) {
    struct timespec ts = {0};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

int
main(int argc, char** argv) {
    const char* rocksdb_base = "ledger.mainnet/rocksdb";
    uint64_t slot = 402349668ull;
    uint32_t variant = 0;
    int iters = 3;

    if (argc > 1 && argv[1] && argv[1][0] != '\0') {
        rocksdb_base = argv[1];
    }
    if (argc > 2 && argv[2] && argv[2][0] != '\0') {
        slot = strtoull(argv[2], NULL, 10);
    }
    if (argc > 3 && argv[3] && argv[3][0] != '\0') {
        iters = (int)strtol(argv[3], NULL, 10);
        if (iters < 1) iters = 1;
    }

    sol_log_config_t log_cfg = (sol_log_config_t)SOL_LOG_CONFIG_DEFAULT;
    log_cfg.level = SOL_LOG_OFF;
    sol_log_init(&log_cfg);

    char blockstore_path[512];
    if (snprintf(blockstore_path, sizeof(blockstore_path), "%s/blockstore", rocksdb_base) < 0) {
        fprintf(stderr, "error: failed to build blockstore path\n");
        return 1;
    }

    sol_blockstore_config_t bs_cfg = SOL_BLOCKSTORE_CONFIG_DEFAULT;
    bs_cfg.storage_type = SOL_BLOCKSTORE_STORAGE_ROCKSDB;
    bs_cfg.rocksdb_path = blockstore_path;
    sol_blockstore_t* bs = sol_blockstore_new(&bs_cfg);
    if (!bs) {
        fprintf(stderr, "error: failed to open blockstore at %s\n", blockstore_path);
        return 1;
    }

    sol_block_t* block = sol_blockstore_get_block_variant(bs, (sol_slot_t)slot, variant);
    if (!block || !block->data || block->data_len == 0) {
        fprintf(stderr, "error: failed to load block slot=%" PRIu64 " variant=%u\n", slot, variant);
        sol_block_destroy(block);
        sol_blockstore_destroy(bs);
        return 1;
    }

    sol_entry_batch_t* batch = sol_entry_batch_new(0);
    if (!batch) {
        fprintf(stderr, "error: OOM\n");
        sol_block_destroy(block);
        sol_blockstore_destroy(bs);
        return 1;
    }

    sol_err_t perr = sol_entry_batch_parse(batch, block->data, block->data_len);
    if (perr != SOL_OK) {
        fprintf(stderr, "error: failed to parse entries: %s\n", sol_err_str(perr));
        sol_entry_batch_destroy(batch);
        sol_block_destroy(block);
        sol_blockstore_destroy(bs);
        return 1;
    }

    sol_hash_t start_hash = {0};
    sol_err_t herr = sol_blockstore_get_block_hash_variant(bs, block->parent_slot, 0, &start_hash);
    if (herr != SOL_OK) {
        fprintf(stderr, "error: failed to get parent block hash: %s\n", sol_err_str(herr));
        sol_entry_batch_destroy(batch);
        sol_block_destroy(block);
        sol_blockstore_destroy(bs);
        return 1;
    }

    uint64_t t0 = now_ns();
    uint32_t verified = 0;
    uint32_t failed = 0;
    for (int i = 0; i < iters; i++) {
        sol_entry_verify_result_t vr = sol_entry_batch_verify(batch, &start_hash);
        verified = vr.num_verified;
        failed = vr.failed_entry;
        if (!vr.valid) {
            fprintf(stderr, "error: verify failed at entry=%u err=%s\n",
                    (unsigned)vr.failed_entry, sol_err_str(vr.error));
            break;
        }
    }
    uint64_t t1 = now_ns();

    double sec = (double)(t1 - t0) / 1000000000.0;
    double per = sec / (double)iters;

    printf("entry_batch_verify: slot=%" PRIu64 " entries=%zu iters=%d total=%.6fs per=%.6fs verified=%u failed=%u\n",
           slot,
           batch->num_entries,
           iters,
           sec,
           per,
           (unsigned)verified,
           (unsigned)failed);

    sol_entry_batch_destroy(batch);
    sol_block_destroy(block);
    sol_blockstore_destroy(bs);
    sol_log_fini();
    return 0;
}

