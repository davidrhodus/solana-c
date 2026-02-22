/*
 * test_poh.c - Tests for Proof of History and Block Production
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "../src/poh/sol_poh.h"
#include "../src/poh/sol_block_producer.h"
#include "../src/runtime/sol_bank.h"
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

/*
 * Test sequential hashing
 */
TEST(poh_hash_n) {
    sol_hash_t start = {0};
    sol_hash_t result;

    /* Hash 0 times should return the same value */
    sol_poh_hash_n(&start, 0, &result);
    ASSERT(memcmp(&start, &result, sizeof(sol_hash_t)) == 0);

    /* Hash 1 time */
    sol_poh_hash_n(&start, 1, &result);
    ASSERT(memcmp(&start, &result, sizeof(sol_hash_t)) != 0);

    /* Verify deterministic */
    sol_hash_t result2;
    sol_poh_hash_n(&start, 1, &result2);
    ASSERT(memcmp(&result, &result2, sizeof(sol_hash_t)) == 0);

    /* Hash 100 times */
    sol_poh_hash_n(&start, 100, &result);
    ASSERT(memcmp(&start, &result, sizeof(sol_hash_t)) != 0);
}

/*
 * Test hash mixin
 */
TEST(poh_hash_mixin) {
    sol_hash_t prev = {0};
    sol_hash_t result1, result2;
    uint8_t data1[] = "transaction1";
    uint8_t data2[] = "transaction2";

    /* Mixing different data should produce different results */
    sol_poh_hash_mixin(&prev, data1, sizeof(data1), &result1);
    sol_poh_hash_mixin(&prev, data2, sizeof(data2), &result2);
    ASSERT(memcmp(&result1, &result2, sizeof(sol_hash_t)) != 0);

    /* Mixing same data should produce same result */
    sol_hash_t result3;
    sol_poh_hash_mixin(&prev, data1, sizeof(data1), &result3);
    ASSERT(memcmp(&result1, &result3, sizeof(sol_hash_t)) == 0);
}

/*
 * Test single entry verification
 */
TEST(poh_verify_entry) {
    sol_hash_t start = {0};
    sol_hash_t expected;

    /* Create an entry by hashing N times */
    sol_poh_hash_n(&start, 100, &expected);

    sol_poh_entry_t entry = {
        .num_hashes = 100,
        .hash = expected,
        .transactions = NULL,
        .num_transactions = 0,
    };

    /* Verification should pass */
    ASSERT(sol_poh_verify_entry(&start, &entry) == true);

    /* Wrong num_hashes should fail */
    entry.num_hashes = 99;
    ASSERT(sol_poh_verify_entry(&start, &entry) == false);

    entry.num_hashes = 100;

    /* Wrong hash should fail */
    entry.hash.bytes[0] ^= 0xFF;
    ASSERT(sol_poh_verify_entry(&start, &entry) == false);
}

/*
 * Test entry verification with transactions
 */
TEST(poh_verify_entry_with_tx) {
    sol_hash_t start = {0};
    sol_hash_t tx_hash = {{1, 2, 3, 4, 5, 6, 7, 8}};
    sol_hash_t expected;

    /*
     * With num_hashes=50 and num_transactions=1, the verifier does:
     * - Hash (50-1) = 49 times
     * - Mix in the transaction
     * So compute expected the same way
     */
    sol_poh_hash_n(&start, 49, &expected);
    sol_poh_hash_mixin(&expected, tx_hash.bytes, 32, &expected);

    sol_poh_entry_t entry = {
        .num_hashes = 50,
        .hash = expected,
        .transactions = &tx_hash,
        .num_transactions = 1,
    };

    /* Verification should pass */
    ASSERT(sol_poh_verify_entry(&start, &entry) == true);
}

/*
 * Test multiple entry verification
 */
TEST(poh_verify_entries) {
    sol_hash_t hash = {0};
    sol_poh_entry_t entries[3];

    /* Create chain of entries */
    sol_poh_hash_n(&hash, 10, &entries[0].hash);
    entries[0].num_hashes = 10;
    entries[0].transactions = NULL;
    entries[0].num_transactions = 0;

    sol_poh_hash_n(&entries[0].hash, 20, &entries[1].hash);
    entries[1].num_hashes = 20;
    entries[1].transactions = NULL;
    entries[1].num_transactions = 0;

    sol_poh_hash_n(&entries[1].hash, 15, &entries[2].hash);
    entries[2].num_hashes = 15;
    entries[2].transactions = NULL;
    entries[2].num_transactions = 0;

    /* Verification should pass */
    sol_hash_t start = {0};
    ASSERT(sol_poh_verify_entries(&start, entries, 3) == true);

    /* Corrupted entry should fail */
    entries[1].hash.bytes[0] ^= 0xFF;
    ASSERT(sol_poh_verify_entries(&start, entries, 3) == false);
}

/*
 * Test parallel verification
 */
TEST(poh_verify_entries_parallel) {
    sol_hash_t hash = {0};
    #define NUM_ENTRIES 10
    sol_poh_entry_t entries[NUM_ENTRIES];

    /* Create chain of entries */
    for (int i = 0; i < NUM_ENTRIES; i++) {
        sol_hash_t prev = (i == 0) ? hash : entries[i-1].hash;
        sol_poh_hash_n(&prev, 100, &entries[i].hash);
        entries[i].num_hashes = 100;
        entries[i].transactions = NULL;
        entries[i].num_transactions = 0;
    }

    /* Parallel verification should pass */
    ASSERT(sol_poh_verify_entries_parallel(&hash, entries, NUM_ENTRIES, 4) == true);

    /* Single-threaded should also pass */
    ASSERT(sol_poh_verify_entries_parallel(&hash, entries, NUM_ENTRIES, 1) == true);

    /* Corrupted entry should fail */
    entries[5].hash.bytes[0] ^= 0xFF;
    ASSERT(sol_poh_verify_entries_parallel(&hash, entries, NUM_ENTRIES, 4) == false);
}

/*
 * Test PoH recorder creation
 */
TEST(poh_recorder_new) {
    sol_hash_t start = {0};
    sol_poh_recorder_t* recorder = sol_poh_recorder_new(&start, 0, NULL);
    ASSERT(recorder != NULL);

    /* Verify initial state */
    ASSERT(sol_poh_recorder_tick_height(recorder) == 0);
    ASSERT(sol_poh_recorder_slot(recorder) == 0);
    ASSERT(sol_poh_recorder_is_leader(recorder) == false);

    sol_hash_t hash = sol_poh_recorder_hash(recorder);
    ASSERT(memcmp(&hash, &start, sizeof(sol_hash_t)) == 0);

    sol_poh_recorder_destroy(recorder);
}

/*
 * Test PoH recorder with custom config
 */
TEST(poh_recorder_config) {
    sol_hash_t start = {0};
    sol_poh_config_t config = {
        .hashes_per_tick = 1000,
        .ticks_per_slot = 32,
        .target_tick_ns = 100000000,  /* 100ms */
    };

    sol_poh_recorder_t* recorder = sol_poh_recorder_new(&start, 100, &config);
    ASSERT(recorder != NULL);

    ASSERT(sol_poh_recorder_tick_height(recorder) == 100);

    sol_poh_recorder_destroy(recorder);
}

/*
 * Test manual tick
 */
TEST(poh_recorder_tick) {
    sol_hash_t start = {0};
    sol_poh_recorder_t* recorder = sol_poh_recorder_new(&start, 0, NULL);
    ASSERT(recorder != NULL);

    uint64_t initial_tick = sol_poh_recorder_tick_height(recorder);
    sol_hash_t initial_hash = sol_poh_recorder_hash(recorder);

    /* Tick should advance tick height and change hash */
    sol_err_t err = sol_poh_recorder_tick(recorder);
    ASSERT(err == SOL_OK);

    ASSERT(sol_poh_recorder_tick_height(recorder) == initial_tick + 1);
    sol_hash_t new_hash = sol_poh_recorder_hash(recorder);
    ASSERT(memcmp(&initial_hash, &new_hash, sizeof(sol_hash_t)) != 0);

    sol_poh_recorder_destroy(recorder);
}

/*
 * Test leader slot management
 */
TEST(poh_recorder_leader) {
    sol_hash_t start = {0};
    sol_poh_recorder_t* recorder = sol_poh_recorder_new(&start, 0, NULL);
    ASSERT(recorder != NULL);

    /* Initially not a leader */
    ASSERT(sol_poh_recorder_is_leader(recorder) == false);

    /* Set leader slots */
    sol_err_t err = sol_poh_recorder_set_leader_slots(recorder, 0, 10);
    ASSERT(err == SOL_OK);
    ASSERT(sol_poh_recorder_is_leader(recorder) == true);

    /* Clear leader */
    err = sol_poh_recorder_clear_leader(recorder);
    ASSERT(err == SOL_OK);
    ASSERT(sol_poh_recorder_is_leader(recorder) == false);

    sol_poh_recorder_destroy(recorder);
}

/*
 * Test recording transactions
 */
TEST(poh_recorder_record) {
    sol_hash_t start = {0};
    sol_poh_recorder_t* recorder = sol_poh_recorder_new(&start, 0, NULL);
    ASSERT(recorder != NULL);

    /* Set as leader to enable recording */
    sol_poh_recorder_set_leader_slots(recorder, 0, 10);

    sol_hash_t initial_hash = sol_poh_recorder_hash(recorder);

    /* Record a transaction */
    sol_hash_t tx_hash = {{1, 2, 3, 4, 5, 6, 7, 8}};
    sol_err_t err = sol_poh_recorder_record(recorder, &tx_hash);
    ASSERT(err == SOL_OK);

    /* Hash should have changed */
    sol_hash_t new_hash = sol_poh_recorder_hash(recorder);
    ASSERT(memcmp(&initial_hash, &new_hash, sizeof(sol_hash_t)) != 0);

    sol_poh_recorder_destroy(recorder);
}

/*
 * Test recording batch of transactions
 */
TEST(poh_recorder_record_batch) {
    sol_hash_t start = {0};
    sol_poh_recorder_t* recorder = sol_poh_recorder_new(&start, 0, NULL);
    ASSERT(recorder != NULL);

    sol_poh_recorder_set_leader_slots(recorder, 0, 10);

    sol_hash_t tx_hashes[3] = {
        {{1, 2, 3}},
        {{4, 5, 6}},
        {{7, 8, 9}},
    };

    sol_err_t err = sol_poh_recorder_record_batch(recorder, tx_hashes, 3);
    ASSERT(err == SOL_OK);

    sol_poh_recorder_destroy(recorder);
}

/*
 * Test flush entries
 */
TEST(poh_recorder_flush) {
    sol_hash_t start = {0};
    sol_poh_config_t config = {
        .hashes_per_tick = 10,
        .ticks_per_slot = 64,
        .target_tick_ns = 1000000,
    };

    sol_poh_recorder_t* recorder = sol_poh_recorder_new(&start, 0, &config);
    ASSERT(recorder != NULL);

    sol_poh_recorder_set_leader_slots(recorder, 0, 10);

    /* Record some transactions and tick */
    sol_hash_t tx_hash = {{1, 2, 3}};
    sol_poh_recorder_record(recorder, &tx_hash);
    sol_poh_recorder_tick(recorder);

    /* Flush and check entries */
    sol_poh_entry_t entries[10];
    size_t count = sol_poh_recorder_flush_entries(recorder, entries, 10);

    /* Should have at least one entry (the tick) */
    ASSERT(count >= 1);

    /* Free entry resources */
    for (size_t i = 0; i < count; i++) {
        sol_poh_entry_free(&entries[i]);
    }

    sol_poh_recorder_destroy(recorder);
}

/*
 * Tick callback test state
 */
static int tick_callback_count = 0;
static uint64_t last_tick_height = 0;

static void test_tick_callback(void* ctx, const sol_poh_entry_t* tick, uint64_t tick_height) {
    (void)ctx;
    (void)tick;
    tick_callback_count++;
    last_tick_height = tick_height;
}

/*
 * Test tick callback
 */
TEST(poh_recorder_tick_callback) {
    tick_callback_count = 0;
    last_tick_height = 0;

    sol_hash_t start = {0};
    sol_poh_recorder_t* recorder = sol_poh_recorder_new(&start, 0, NULL);
    ASSERT(recorder != NULL);

    sol_poh_recorder_set_tick_callback(recorder, test_tick_callback, NULL);

    /* Manual ticks should trigger callback */
    sol_poh_recorder_tick(recorder);
    ASSERT(tick_callback_count == 1);
    ASSERT(last_tick_height == 1);

    sol_poh_recorder_tick(recorder);
    ASSERT(tick_callback_count == 2);
    ASSERT(last_tick_height == 2);

    sol_poh_recorder_destroy(recorder);
}

/*
 * Test block producer creation
 */
TEST(block_producer_new) {
    sol_hash_t start = {0};
    sol_poh_recorder_t* recorder = sol_poh_recorder_new(&start, 0, NULL);
    ASSERT(recorder != NULL);

    sol_block_producer_t* producer = sol_block_producer_new(recorder, NULL);
    ASSERT(producer != NULL);

    /* Verify initial state */
    ASSERT(sol_block_producer_is_producing(producer) == false);
    ASSERT(sol_block_producer_entry_count(producer) == 0);
    ASSERT(sol_block_producer_tx_count(producer) == 0);

    sol_block_producer_destroy(producer);
    sol_poh_recorder_destroy(recorder);
}

/*
 * Test block producer with custom config
 */
TEST(block_producer_config) {
    sol_hash_t start = {0};
    sol_poh_recorder_t* recorder = sol_poh_recorder_new(&start, 0, NULL);
    ASSERT(recorder != NULL);

    sol_block_producer_config_t config = {
        .max_txs_per_entry = 32,
        .max_entries_per_slot = 2048,
        .target_ns_per_entry = 5000000,
        .skip_verification = true,
    };

    sol_block_producer_t* producer = sol_block_producer_new(recorder, &config);
    ASSERT(producer != NULL);

    sol_block_producer_destroy(producer);
    sol_poh_recorder_destroy(recorder);
}

/*
 * Test setting bank
 */
TEST(block_producer_set_bank) {
    sol_hash_t start = {0};
    sol_poh_recorder_t* recorder = sol_poh_recorder_new(&start, 0, NULL);
    sol_block_producer_t* producer = sol_block_producer_new(recorder, NULL);
    ASSERT(producer != NULL);

    /* Create a mock bank */
    sol_bank_config_t config = SOL_BANK_CONFIG_DEFAULT;
    sol_bank_t* bank = sol_bank_new(0, &start, NULL, &config);
    ASSERT(bank != NULL);

    sol_err_t err = sol_block_producer_set_bank(producer, bank);
    ASSERT(err == SOL_OK);

    /* Clear bank */
    err = sol_block_producer_clear_bank(producer);
    ASSERT(err == SOL_OK);

    sol_bank_destroy(bank);
    sol_block_producer_destroy(producer);
    sol_poh_recorder_destroy(recorder);
}

/*
 * Test start/stop
 */
TEST(block_producer_start_stop) {
    sol_hash_t start = {0};
    sol_poh_recorder_t* recorder = sol_poh_recorder_new(&start, 0, NULL);
    sol_block_producer_t* producer = sol_block_producer_new(recorder, NULL);
    ASSERT(producer != NULL);

    /* Start */
    sol_err_t err = sol_block_producer_start(producer);
    ASSERT(err == SOL_OK);

    /* Give thread time to start */
    usleep(10000);

    /* Stop */
    err = sol_block_producer_stop(producer);
    ASSERT(err == SOL_OK);

    sol_block_producer_destroy(producer);
    sol_poh_recorder_destroy(recorder);
}

/*
 * Test statistics
 */
TEST(block_producer_stats) {
    sol_hash_t start = {0};
    sol_poh_recorder_t* recorder = sol_poh_recorder_new(&start, 0, NULL);
    sol_block_producer_t* producer = sol_block_producer_new(recorder, NULL);
    ASSERT(producer != NULL);

    sol_block_producer_stats_t stats = sol_block_producer_stats(producer);
    ASSERT(stats.entries_produced == 0);
    ASSERT(stats.transactions_processed == 0);
    ASSERT(stats.transactions_failed == 0);
    ASSERT(stats.slots_completed == 0);
    ASSERT(stats.ticks_produced == 0);

    sol_block_producer_destroy(producer);
    sol_poh_recorder_destroy(recorder);
}

/*
 * Test flush entry
 */
TEST(block_producer_flush) {
    sol_hash_t start = {0};
    sol_poh_recorder_t* recorder = sol_poh_recorder_new(&start, 0, NULL);
    sol_block_producer_t* producer = sol_block_producer_new(recorder, NULL);
    ASSERT(producer != NULL);

    /* Flush when empty should succeed */
    sol_err_t err = sol_block_producer_flush_entry(producer);
    ASSERT(err == SOL_OK);

    sol_block_producer_destroy(producer);
    sol_poh_recorder_destroy(recorder);
}

/*
 * Test get entries
 */
TEST(block_producer_get_entries) {
    sol_hash_t start = {0};
    sol_poh_recorder_t* recorder = sol_poh_recorder_new(&start, 0, NULL);
    sol_block_producer_t* producer = sol_block_producer_new(recorder, NULL);
    ASSERT(producer != NULL);

    sol_entry_t entries[10];
    size_t count = sol_block_producer_get_entries(producer, entries, 10);
    ASSERT(count == 0);  /* No entries yet */

    sol_block_producer_destroy(producer);
    sol_poh_recorder_destroy(recorder);
}

/*
 * Test entry callback
 */
static int entry_callback_count = 0;

static void test_entry_callback(void* ctx, const sol_entry_t* entry,
                                sol_slot_t slot, uint64_t entry_index) {
    (void)ctx;
    (void)entry;
    (void)slot;
    (void)entry_index;
    entry_callback_count++;
}

TEST(block_producer_entry_callback) {
    entry_callback_count = 0;

    sol_hash_t start = {0};
    sol_poh_recorder_t* recorder = sol_poh_recorder_new(&start, 0, NULL);
    sol_block_producer_t* producer = sol_block_producer_new(recorder, NULL);
    ASSERT(producer != NULL);

    sol_block_producer_set_entry_callback(producer, test_entry_callback, NULL);

    /* Callback set - would be triggered when entries are produced */

    sol_block_producer_destroy(producer);
    sol_poh_recorder_destroy(recorder);
}

/*
 * Test slot callback
 */
static int slot_callback_count = 0;

static void test_slot_callback(void* ctx, sol_slot_t slot,
                               const sol_hash_t* blockhash,
                               uint64_t num_entries, uint64_t num_transactions) {
    (void)ctx;
    (void)slot;
    (void)blockhash;
    (void)num_entries;
    (void)num_transactions;
    slot_callback_count++;
}

TEST(block_producer_slot_callback) {
    slot_callback_count = 0;

    sol_hash_t start = {0};
    sol_poh_recorder_t* recorder = sol_poh_recorder_new(&start, 0, NULL);
    sol_block_producer_t* producer = sol_block_producer_new(recorder, NULL);
    ASSERT(producer != NULL);

    sol_block_producer_set_slot_callback(producer, test_slot_callback, NULL);

    sol_block_producer_destroy(producer);
    sol_poh_recorder_destroy(recorder);
}

int main(void) {
    printf("Running PoH tests...\n");

    /* PoH hash tests */
    RUN_TEST(poh_hash_n);
    RUN_TEST(poh_hash_mixin);

    /* PoH verification tests */
    RUN_TEST(poh_verify_entry);
    RUN_TEST(poh_verify_entry_with_tx);
    RUN_TEST(poh_verify_entries);
    RUN_TEST(poh_verify_entries_parallel);

    /* PoH recorder tests */
    RUN_TEST(poh_recorder_new);
    RUN_TEST(poh_recorder_config);
    RUN_TEST(poh_recorder_tick);
    RUN_TEST(poh_recorder_leader);
    RUN_TEST(poh_recorder_record);
    RUN_TEST(poh_recorder_record_batch);
    RUN_TEST(poh_recorder_flush);
    RUN_TEST(poh_recorder_tick_callback);

    /* Block producer tests */
    RUN_TEST(block_producer_new);
    RUN_TEST(block_producer_config);
    RUN_TEST(block_producer_set_bank);
    RUN_TEST(block_producer_start_stop);
    RUN_TEST(block_producer_stats);
    RUN_TEST(block_producer_flush);
    RUN_TEST(block_producer_get_entries);
    RUN_TEST(block_producer_entry_callback);
    RUN_TEST(block_producer_slot_callback);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
