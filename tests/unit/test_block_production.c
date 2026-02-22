/*
 * test_block_production.c - End-to-end-ish block production path tests
 */

#include "../test_framework.h"
#include "sol_poh.h"
#include "sol_block_producer.h"
#include "sol_shred.h"
#include "sol_tvu.h"
#include "sol_blockstore.h"
#include "sol_replay.h"
#include "sol_bank_forks.h"
#include "sol_bank.h"
#include "sol_leader_schedule.h"
#include "sol_ed25519.h"

#include <string.h>
#include <unistd.h>

typedef struct {
    sol_tvu_t*        tvu;
    sol_keypair_t     leader_kp;
} block_data_ctx_t;

static void
on_block_data(void* ctx,
              sol_slot_t slot,
              const sol_hash_t* blockhash,
              const uint8_t* block_data,
              size_t block_data_len,
              uint64_t num_entries,
              uint64_t num_transactions) {
    (void)blockhash;
    (void)num_entries;
    (void)num_transactions;

    block_data_ctx_t* c = (block_data_ctx_t*)ctx;
    if (!c || !c->tvu || !block_data || block_data_len == 0) return;

    sol_slot_t parent_slot = (slot > 0) ? (slot - 1) : slot;

    uint32_t shred_index = 0;
    size_t off = 0;
    while (off < block_data_len) {
        size_t chunk = block_data_len - off;
        if (chunk > SOL_SHRED_MAX_DATA_SIZE) {
            chunk = SOL_SHRED_MAX_DATA_SIZE;
        }

        uint8_t flags = 0;
        if (off + chunk == block_data_len) {
            flags |= SOL_SHRED_FLAG_DATA_COMPLETE;
            flags |= SOL_SHRED_FLAG_LAST_IN_SLOT;
        }

        uint8_t raw[SOL_SHRED_SIZE];
        size_t written = 0;
        sol_err_t err = sol_shred_build_legacy_data(
            &c->leader_kp,
            slot,
            parent_slot,
            shred_index,
            0,
            0,
            flags,
            block_data + off,
            chunk,
            raw,
            sizeof(raw),
            &written
        );
        TEST_ASSERT_EQ(err, SOL_OK);
        TEST_ASSERT(written > 0);

        TEST_ASSERT_EQ(sol_tvu_process_shred(c->tvu, raw, written), SOL_OK);

        shred_index++;
        off += chunk;
    }
}

TEST(block_producer_block_data_replays) {
    /* Fast PoH config for test */
    sol_poh_config_t poh_cfg = SOL_POH_CONFIG_DEFAULT;
    poh_cfg.hashes_per_tick = 1;
    poh_cfg.ticks_per_slot = 2;
    poh_cfg.target_tick_ns = 0;

    sol_hash_t start_hash = {0};
    sol_poh_recorder_t* poh = sol_poh_recorder_new(&start_hash, 2, &poh_cfg); /* start at slot 1 */
    TEST_ASSERT_NOT_NULL(poh);
    TEST_ASSERT_EQ(sol_poh_recorder_set_leader_slots(poh, 1, 1), SOL_OK);

    sol_blockstore_t* blockstore = sol_blockstore_new(NULL);
    TEST_ASSERT_NOT_NULL(blockstore);

    sol_bank_config_t bank_cfg = SOL_BANK_CONFIG_DEFAULT;
    bank_cfg.ticks_per_slot = 2;
    bank_cfg.hashes_per_tick = 1;

    sol_bank_t* root_bank = sol_bank_new(0, &start_hash, NULL, &bank_cfg);
    TEST_ASSERT_NOT_NULL(root_bank);

    sol_bank_forks_t* forks = sol_bank_forks_new(root_bank, NULL);
    TEST_ASSERT_NOT_NULL(forks);

    sol_replay_t* replay = sol_replay_new(forks, blockstore, NULL);
    TEST_ASSERT_NOT_NULL(replay);

    sol_tvu_t* tvu = sol_tvu_new(blockstore, replay, NULL, NULL, NULL);
    TEST_ASSERT_NOT_NULL(tvu);

    /* Leader schedule (single validator) */
    sol_keypair_t leader_kp;
    TEST_ASSERT_EQ(sol_ed25519_keypair_generate(&leader_kp), SOL_OK);
    sol_pubkey_t leader_pk;
    sol_ed25519_pubkey_from_keypair(&leader_kp, &leader_pk);

    sol_stake_weight_t stake = {0};
    stake.pubkey = leader_pk;
    stake.stake = 1;
    sol_leader_schedule_t* schedule = sol_leader_schedule_new(0, &stake, 1, NULL);
    TEST_ASSERT_NOT_NULL(schedule);
    sol_tvu_set_leader_schedule(tvu, schedule);

    TEST_ASSERT_EQ(sol_tvu_start(tvu), SOL_OK);

    sol_block_producer_t* producer = sol_block_producer_new(poh, NULL);
    TEST_ASSERT_NOT_NULL(producer);

    /* Produce slot 1 (bank is not inserted into forks; replay will create its own bank) */
    sol_bank_t* producer_bank = sol_bank_new_from_parent(root_bank, 1);
    TEST_ASSERT_NOT_NULL(producer_bank);
    TEST_ASSERT_EQ(sol_block_producer_set_bank(producer, producer_bank), SOL_OK);

    block_data_ctx_t cb_ctx = {
        .tvu = tvu,
        .leader_kp = leader_kp,
    };

    sol_block_producer_set_block_data_callback(producer, on_block_data, &cb_ctx);

    /* Two ticks completes one slot with ticks_per_slot=2. */
    TEST_ASSERT_EQ(sol_poh_recorder_tick(poh), SOL_OK);
    TEST_ASSERT_EQ(sol_poh_recorder_tick(poh), SOL_OK);

    /* Wait for TVU replay */
    bool replayed = false;
    for (int i = 0; i < 2000; i++) { /* ~2s */
        sol_tvu_stats_t stats = sol_tvu_stats(tvu);
        if (stats.blocks_replayed >= 1) {
            replayed = true;
            break;
        }
        usleep(1000);
    }
    TEST_ASSERT(replayed);

    sol_tvu_stop(tvu);
    sol_tvu_destroy(tvu);
    sol_leader_schedule_destroy(schedule);
    sol_replay_destroy(replay);
    sol_bank_destroy(producer_bank);
    sol_blockstore_destroy(blockstore);
    sol_bank_forks_destroy(forks);
    sol_block_producer_destroy(producer);
    sol_poh_recorder_destroy(poh);
}

TEST(replay_existing_bank_skips_processing) {
    sol_blockstore_t* blockstore = sol_blockstore_new(NULL);
    TEST_ASSERT_NOT_NULL(blockstore);

    sol_hash_t genesis = {0};
    sol_bank_config_t bank_cfg = SOL_BANK_CONFIG_DEFAULT;
    bank_cfg.ticks_per_slot = 2;
    bank_cfg.hashes_per_tick = 1;
    sol_bank_t* root_bank = sol_bank_new(0, &genesis, NULL, &bank_cfg);
    TEST_ASSERT_NOT_NULL(root_bank);

    sol_bank_forks_t* forks = sol_bank_forks_new(root_bank, NULL);
    TEST_ASSERT_NOT_NULL(forks);

    sol_replay_t* replay = sol_replay_new(forks, blockstore, NULL);
    TEST_ASSERT_NOT_NULL(replay);

    /* Insert a bank for slot 1 so replay should skip creating/processing. */
    sol_bank_t* bank1 = sol_bank_forks_new_from_parent(forks, 0, 1);
    TEST_ASSERT_NOT_NULL(bank1);
    sol_hash_t tick_hash = {{1}};
    TEST_ASSERT_EQ(sol_bank_register_tick(bank1, &tick_hash), SOL_OK);
    TEST_ASSERT_EQ(sol_bank_register_tick(bank1, &tick_hash), SOL_OK);
    sol_bank_freeze(bank1);

    /* Mark slot 1 as complete in blockstore with a minimal valid shred. */
    sol_keypair_t leader_kp;
    TEST_ASSERT_EQ(sol_ed25519_keypair_generate(&leader_kp), SOL_OK);
    uint8_t payload[16] = {0};
    uint8_t raw[SOL_SHRED_SIZE];
    size_t written = 0;
    TEST_ASSERT_EQ(sol_shred_build_legacy_data(&leader_kp, 1, 0, 0, 0, 0,
                                               SOL_SHRED_FLAG_LAST_IN_SLOT,
                                               payload, sizeof(payload),
                                               raw, sizeof(raw), &written),
                   SOL_OK);

    sol_shred_t parsed;
    TEST_ASSERT_EQ(sol_shred_parse(&parsed, raw, written), SOL_OK);
    TEST_ASSERT_EQ(sol_blockstore_insert_shred(blockstore, &parsed, raw, written), SOL_OK);

    TEST_ASSERT_EQ(sol_replay_slot(replay, 1, NULL), SOL_REPLAY_SUCCESS);

    sol_replay_destroy(replay);
    sol_blockstore_destroy(blockstore);
    sol_bank_forks_destroy(forks);
}

int
main(void) {
    test_case_t tests[] = {
        TEST_CASE(block_producer_block_data_replays),
        TEST_CASE(replay_existing_bank_skips_processing),
    };

    return RUN_TESTS("Block Production Tests", tests);
}
