/*
 * test_tvu.c - Tests for Transaction Validation Unit
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "../src/tvu/sol_tvu.h"
#include "../src/blockstore/sol_blockstore.h"
#include "../src/replay/sol_replay.h"
#include "../src/replay/sol_bank_forks.h"
#include "../src/runtime/sol_bank.h"
#include "../src/runtime/sol_accounts_db.h"
#include "../src/runtime/sol_leader_schedule.h"
#include "../src/crypto/sol_ed25519.h"
#include "../src/util/sol_alloc.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    printf("  Testing %s...", #name); \
    fflush(stdout); \
    tests_run++; \
    test_##name(); \
    tests_passed++; \
    printf(" PASSED\n"); \
} while(0)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf(" FAILED\n    Assert failed: %s at %s:%d\n", \
               #cond, __FILE__, __LINE__); \
        exit(1); \
    } \
} while(0)

static size_t
build_mock_legacy_data_shred(uint8_t* out, size_t out_len, sol_slot_t slot, uint32_t index) {
    const size_t len = 200;
    if (!out || out_len < len) return 0;

    memset(out, 0, len);

    out[64] = SOL_SHRED_VARIANT_LEGACY_DATA;

    for (int i = 0; i < 8; i++) {
        out[65 + i] = (uint8_t)((slot >> (i * 8)) & 0xFFu);
    }

    for (int i = 0; i < 4; i++) {
        out[73 + i] = (uint8_t)((index >> (i * 8)) & 0xFFu);
    }

    sol_slot_t parent_slot = slot > 0 ? slot - 1 : 0;
    uint16_t parent_offset = (uint16_t)(slot - parent_slot);
    out[SOL_SHRED_HEADER_SIZE + 0] = (uint8_t)(parent_offset & 0xFFu);
    out[SOL_SHRED_HEADER_SIZE + 1] = (uint8_t)((parent_offset >> 8) & 0xFFu);
    out[SOL_SHRED_HEADER_SIZE + 2] = 0; /* flags */

    out[SOL_SHRED_HEADER_SIZE + 3] = (uint8_t)(len & 0xFFu);
    out[SOL_SHRED_HEADER_SIZE + 4] = (uint8_t)((len >> 8) & 0xFFu);

    for (size_t i = SOL_SHRED_HEADER_SIZE + SOL_SHRED_DATA_HEADER_SIZE; i < len; i++) {
        out[i] = (uint8_t)(i + index);
    }

    return len;
}

/*
 * Test TVU creation
 */
TEST(tvu_new) {
    sol_tvu_config_t config = SOL_TVU_CONFIG_DEFAULT;
    sol_tvu_t* tvu = sol_tvu_new(NULL, NULL, NULL, NULL, &config);
    ASSERT(tvu != NULL);
    ASSERT(sol_tvu_is_running(tvu) == false);
    sol_tvu_destroy(tvu);
}

/*
 * Test TVU with default config
 */
TEST(tvu_default_config) {
    sol_tvu_t* tvu = sol_tvu_new(NULL, NULL, NULL, NULL, NULL);
    ASSERT(tvu != NULL);
    sol_tvu_destroy(tvu);
}

/*
 * Test TVU with blockstore
 */
TEST(tvu_with_blockstore) {
    sol_blockstore_config_t bs_config = SOL_BLOCKSTORE_CONFIG_DEFAULT;
    sol_blockstore_t* blockstore = sol_blockstore_new(&bs_config);
    ASSERT(blockstore != NULL);

    sol_tvu_config_t tvu_config = SOL_TVU_CONFIG_DEFAULT;
    sol_tvu_t* tvu = sol_tvu_new(blockstore, NULL, NULL, NULL, &tvu_config);
    ASSERT(tvu != NULL);

    sol_tvu_destroy(tvu);
    sol_blockstore_destroy(blockstore);
}

/*
 * Test TVU stats
 */
TEST(tvu_stats) {
    sol_tvu_config_t config = SOL_TVU_CONFIG_DEFAULT;
    sol_tvu_t* tvu = sol_tvu_new(NULL, NULL, NULL, NULL, &config);
    ASSERT(tvu != NULL);

    sol_tvu_stats_t stats = sol_tvu_stats(tvu);
    ASSERT(stats.shreds_received == 0);
    ASSERT(stats.shreds_verified == 0);
    ASSERT(stats.blocks_completed == 0);
    ASSERT(stats.blocks_replayed == 0);

    sol_tvu_destroy(tvu);
}

/*
 * Test TVU slot status
 */
TEST(tvu_slot_status) {
    sol_tvu_config_t config = SOL_TVU_CONFIG_DEFAULT;
    sol_tvu_t* tvu = sol_tvu_new(NULL, NULL, NULL, NULL, &config);
    ASSERT(tvu != NULL);

    /* Unknown slot should return UNKNOWN status */
    sol_slot_status_t status = sol_tvu_slot_status(tvu, 100);
    ASSERT(status == SOL_SLOT_STATUS_UNKNOWN);

    sol_tvu_destroy(tvu);
}

/*
 * Test TVU start/stop
 */
TEST(tvu_start_stop) {
    sol_tvu_config_t config = SOL_TVU_CONFIG_DEFAULT;
    sol_tvu_t* tvu = sol_tvu_new(NULL, NULL, NULL, NULL, &config);
    ASSERT(tvu != NULL);
    ASSERT(sol_tvu_is_running(tvu) == false);

    sol_err_t err = sol_tvu_start(tvu);
    ASSERT(err == SOL_OK);
    ASSERT(sol_tvu_is_running(tvu) == true);

    err = sol_tvu_stop(tvu);
    ASSERT(err == SOL_OK);
    ASSERT(sol_tvu_is_running(tvu) == false);

    sol_tvu_destroy(tvu);
}

/*
 * Test TVU process shred (with NULL shred should fail)
 */
TEST(tvu_process_shred_null) {
    sol_tvu_config_t config = SOL_TVU_CONFIG_DEFAULT;
    sol_tvu_t* tvu = sol_tvu_new(NULL, NULL, NULL, NULL, &config);
    ASSERT(tvu != NULL);

    sol_err_t err = sol_tvu_process_shred(tvu, NULL, 0);
    ASSERT(err == SOL_ERR_INVAL);

    sol_tvu_destroy(tvu);
}

TEST(tvu_process_shred_too_large) {
    sol_tvu_config_t config = SOL_TVU_CONFIG_DEFAULT;
    sol_tvu_t* tvu = sol_tvu_new(NULL, NULL, NULL, NULL, &config);
    ASSERT(tvu != NULL);

    uint8_t buf[2048];
    memset(buf, 0, sizeof(buf));

    sol_err_t err = sol_tvu_process_shred(tvu, buf, sizeof(buf));
    ASSERT(err == SOL_ERR_TOO_LARGE);

    sol_tvu_destroy(tvu);
}

TEST(tvu_leader_schedule_swap) {
    sol_tvu_config_t config = SOL_TVU_CONFIG_DEFAULT;
    sol_tvu_t* tvu = sol_tvu_new(NULL, NULL, NULL, NULL, &config);
    ASSERT(tvu != NULL);

    sol_pubkey_t pk1 = {{1}};
    sol_stake_weight_t w1 = {
        .pubkey = pk1,
        .stake = 1,
    };
    sol_leader_schedule_t* s1 = sol_leader_schedule_new(0, &w1, 1, NULL);
    ASSERT(s1 != NULL);

    sol_pubkey_t pk2 = {{2}};
    sol_stake_weight_t w2 = {
        .pubkey = pk2,
        .stake = 1,
    };
    sol_leader_schedule_t* s2 = sol_leader_schedule_new(0, &w2, 1, NULL);
    ASSERT(s2 != NULL);

    sol_leader_schedule_t* old = sol_tvu_swap_leader_schedule(tvu, s1);
    ASSERT(old == NULL);

    old = sol_tvu_swap_leader_schedule(tvu, s2);
    ASSERT(old == s1);
    sol_leader_schedule_destroy(old);

    old = sol_tvu_swap_leader_schedule(tvu, NULL);
    ASSERT(old == s2);
    sol_leader_schedule_destroy(old);

    sol_tvu_destroy(tvu);
}

TEST(tvu_replay_duplicate_not_dead) {
    sol_blockstore_t* blockstore = sol_blockstore_new(NULL);
    ASSERT(blockstore != NULL);

    sol_bank_config_t bank_cfg = SOL_BANK_CONFIG_DEFAULT;
    bank_cfg.ticks_per_slot = 2;
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, &bank_cfg);
    ASSERT(root != NULL);

    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);
    ASSERT(forks != NULL);

    sol_replay_t* replay = sol_replay_new(forks, blockstore, NULL);
    ASSERT(replay != NULL);

    sol_bank_t* bank1 = sol_bank_new_from_parent(root, 1);
    ASSERT(bank1 != NULL);
    sol_hash_t tick_hash = {{1}};
    ASSERT(sol_bank_register_tick(bank1, &tick_hash) == SOL_OK);
    ASSERT(sol_bank_register_tick(bank1, &tick_hash) == SOL_OK);
    ASSERT(sol_bank_forks_insert(forks, bank1) == SOL_OK);

    /* Make slot 1 complete in blockstore so sol_replay_slot can mark it replayed. */
    uint8_t seed[SOL_ED25519_SEED_SIZE] = {1};
    sol_keypair_t leader;
    sol_ed25519_keypair_from_seed(seed, &leader);

    uint8_t payload[1] = {0};
    uint8_t raw[SOL_SHRED_SIZE];
    size_t raw_len = 0;
    sol_err_t berr = sol_shred_build_legacy_data(
        &leader,
        1, /* slot */
        0, /* parent_slot */
        0, /* index */
        0, /* version */
        0, /* fec_set_index */
        (uint8_t)(SOL_SHRED_FLAG_DATA_COMPLETE | SOL_SHRED_FLAG_LAST_IN_SLOT),
        payload,
        sizeof(payload),
        raw,
        sizeof(raw),
        &raw_len
    );
    ASSERT(berr == SOL_OK);

    sol_shred_t shred;
    ASSERT(sol_shred_parse(&shred, raw, raw_len) == SOL_OK);
    ASSERT(sol_blockstore_insert_shred(blockstore, &shred, raw, raw_len) == SOL_OK);

    /* First replay marks the slot as replayed based on the existing bank. */
    ASSERT(sol_replay_slot(replay, 1, NULL) == SOL_REPLAY_SUCCESS);
    ASSERT(sol_replay_is_replayed(replay, 1));

    /* Now feed the same shred through TVU; replay returns DUPLICATE and should
     * not mark the slot DEAD. */
    sol_tvu_t* tvu = sol_tvu_new(blockstore, replay, NULL, NULL, NULL);
    ASSERT(tvu != NULL);
    ASSERT(sol_tvu_start(tvu) == SOL_OK);

    ASSERT(sol_tvu_process_shred(tvu, raw, raw_len) == SOL_OK);

    sol_slot_status_t status = SOL_SLOT_STATUS_UNKNOWN;
    for (int i = 0; i < 200; i++) { /* ~2s */
        status = sol_tvu_slot_status(tvu, 1);
        if (status == SOL_SLOT_STATUS_REPLAYED || status == SOL_SLOT_STATUS_DEAD) {
            break;
        }
        usleep(10000);
    }

    ASSERT(status == SOL_SLOT_STATUS_REPLAYED);

    sol_tvu_destroy(tvu);
    sol_replay_destroy(replay);
    sol_blockstore_destroy(blockstore);
    sol_bank_forks_destroy(forks);
}

TEST(tvu_tracker_eviction_preserves_low_slot) {
    /* When the slot-tracker table is full and we see shreds far ahead of the
     * replay cursor, the eviction policy should preserve low-numbered slots
     * (catchup window) instead of evicting them. */
    enum { TVU_MAX_TRACKED_SLOTS = 4096 };

    sol_tvu_t* tvu = sol_tvu_new(NULL, NULL, NULL, NULL, NULL);
    ASSERT(tvu != NULL);
    ASSERT(sol_tvu_start(tvu) == SOL_OK);

    uint8_t raw[256];

    size_t len = build_mock_legacy_data_shred(raw, sizeof(raw), 1, 0);
    ASSERT(len > 0);
    ASSERT(sol_tvu_process_shred(tvu, raw, len) == SOL_OK);

    /* Wait for slot 1 tracker to be created */
    for (int i = 0; i < 200; i++) { /* ~2s */
        if (sol_tvu_slot_status(tvu, 1) != SOL_SLOT_STATUS_UNKNOWN) {
            break;
        }
        usleep(10000);
    }
    ASSERT(sol_tvu_slot_status(tvu, 1) != SOL_SLOT_STATUS_UNKNOWN);

    const sol_slot_t slots_to_send = (sol_slot_t)(TVU_MAX_TRACKED_SLOTS + 1024);
    for (sol_slot_t slot = 2; slot <= slots_to_send; slot++) {
        len = build_mock_legacy_data_shred(raw, sizeof(raw), slot, 0);
        ASSERT(len > 0);
        sol_err_t err = sol_tvu_process_shred(tvu, raw, len);
        while (err == SOL_ERR_FULL) {
            usleep(1000);
            err = sol_tvu_process_shred(tvu, raw, len);
        }
        ASSERT(err == SOL_OK);
    }

    /* Wait for shred verification thread to process the queue */
    for (int i = 0; i < 1000; i++) { /* ~10s */
        sol_tvu_stats_t stats = sol_tvu_stats(tvu);
        if (stats.shreds_verified >= (uint64_t)slots_to_send) {
            break;
        }
        usleep(10000);
    }

    ASSERT(sol_tvu_slot_status(tvu, 1) != SOL_SLOT_STATUS_UNKNOWN);

    sol_tvu_destroy(tvu);
}

/*
 * Main
 */
int main(void) {
    printf("\n=== TVU Tests ===\n");

    RUN_TEST(tvu_new);
    RUN_TEST(tvu_default_config);
    RUN_TEST(tvu_with_blockstore);
    RUN_TEST(tvu_stats);
    RUN_TEST(tvu_slot_status);
    RUN_TEST(tvu_start_stop);
    RUN_TEST(tvu_process_shred_null);
    RUN_TEST(tvu_process_shred_too_large);
    RUN_TEST(tvu_leader_schedule_swap);
    RUN_TEST(tvu_replay_duplicate_not_dead);
    RUN_TEST(tvu_tracker_eviction_preserves_low_slot);

    printf("\nResults: %d/%d passed\n\n", tests_passed, tests_run);

    sol_alloc_stats_print();
    return tests_passed == tests_run ? 0 : 1;
}
