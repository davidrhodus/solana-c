/*
 * test_vote_tracker.c - Tests for Vote Tracker
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/consensus/sol_vote_tracker.h"
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
 * Test vote tracker creation
 */
TEST(vote_tracker_new) {
    sol_vote_tracker_t* tracker = sol_vote_tracker_new(NULL);
    ASSERT(tracker != NULL);
    sol_vote_tracker_destroy(tracker);
}

/*
 * Test vote tracker with config
 */
TEST(vote_tracker_config) {
    sol_vote_tracker_config_t config = SOL_VOTE_TRACKER_CONFIG_DEFAULT;
    config.max_validators = 100;
    sol_vote_tracker_t* tracker = sol_vote_tracker_new(&config);
    ASSERT(tracker != NULL);
    sol_vote_tracker_destroy(tracker);
}

/*
 * Test record vote
 */
TEST(vote_tracker_record_vote) {
    sol_vote_tracker_t* tracker = sol_vote_tracker_new(NULL);
    ASSERT(tracker != NULL);

    sol_pubkey_t vote_pubkey = {0};
    vote_pubkey.bytes[0] = 1;
    sol_pubkey_t node_pubkey = {0};
    node_pubkey.bytes[0] = 2;

    sol_err_t err = sol_vote_tracker_record_vote(
        tracker, &vote_pubkey, &node_pubkey, 100, 50, 1000);
    ASSERT(err == SOL_OK);

    /* Check stats */
    sol_vote_tracker_stats_t stats = sol_vote_tracker_stats(tracker);
    ASSERT(stats.votes_received == 1);
    ASSERT(stats.votes_processed == 1);
    ASSERT(stats.validators_tracked == 1);

    sol_vote_tracker_destroy(tracker);
}

/*
 * Test get slot stake
 */
TEST(vote_tracker_get_slot_stake) {
    sol_vote_tracker_t* tracker = sol_vote_tracker_new(NULL);
    ASSERT(tracker != NULL);

    /* Record votes from multiple validators */
    for (int i = 0; i < 5; i++) {
        sol_pubkey_t vote_pubkey = {0};
        vote_pubkey.bytes[0] = (uint8_t)i;
        sol_pubkey_t node_pubkey = {0};
        node_pubkey.bytes[0] = (uint8_t)(i + 10);

        sol_err_t err = sol_vote_tracker_record_vote(
            tracker, &vote_pubkey, &node_pubkey, 100, 50, 1000);
        ASSERT(err == SOL_OK);
    }

    /* Check stake for slot 100 */
    uint64_t stake = sol_vote_tracker_get_slot_stake(tracker, 100);
    ASSERT(stake == 5000);  /* 5 validators * 1000 stake each */

    sol_vote_tracker_destroy(tracker);
}

/*
 * Test supermajority check
 */
TEST(vote_tracker_supermajority) {
    sol_vote_tracker_t* tracker = sol_vote_tracker_new(NULL);
    ASSERT(tracker != NULL);

    uint64_t total_stake = 9000;  /* Total stake in cluster */

    /* Record votes from validators totaling 6000 stake (2/3 of 9000) */
    for (int i = 0; i < 6; i++) {
        sol_pubkey_t vote_pubkey = {0};
        vote_pubkey.bytes[0] = (uint8_t)i;
        sol_pubkey_t node_pubkey = {0};
        node_pubkey.bytes[0] = (uint8_t)(i + 10);

        sol_err_t err = sol_vote_tracker_record_vote(
            tracker, &vote_pubkey, &node_pubkey, 100, 50, 1000);
        ASSERT(err == SOL_OK);
    }

    /* Check supermajority - 6000 >= 6000 (2/3 of 9000) */
    bool has_majority = sol_vote_tracker_has_supermajority(tracker, 100, total_stake);
    ASSERT(has_majority == true);

    sol_vote_tracker_destroy(tracker);
}

/*
 * Test no supermajority
 */
TEST(vote_tracker_no_supermajority) {
    sol_vote_tracker_t* tracker = sol_vote_tracker_new(NULL);
    ASSERT(tracker != NULL);

    uint64_t total_stake = 9000;

    /* Record votes from validators totaling 5000 stake (< 2/3 of 9000) */
    for (int i = 0; i < 5; i++) {
        sol_pubkey_t vote_pubkey = {0};
        vote_pubkey.bytes[0] = (uint8_t)i;
        sol_pubkey_t node_pubkey = {0};
        node_pubkey.bytes[0] = (uint8_t)(i + 10);

        sol_err_t err = sol_vote_tracker_record_vote(
            tracker, &vote_pubkey, &node_pubkey, 100, 50, 1000);
        ASSERT(err == SOL_OK);
    }

    /* Check supermajority - 5000 < 6000 (2/3 of 9000) */
    bool has_majority = sol_vote_tracker_has_supermajority(tracker, 100, total_stake);
    ASSERT(has_majority == false);

    sol_vote_tracker_destroy(tracker);
}

/*
 * Test get validator
 */
TEST(vote_tracker_get_validator) {
    sol_vote_tracker_t* tracker = sol_vote_tracker_new(NULL);
    ASSERT(tracker != NULL);

    sol_pubkey_t vote_pubkey = {0};
    vote_pubkey.bytes[0] = 1;
    sol_pubkey_t node_pubkey = {0};
    node_pubkey.bytes[0] = 2;

    sol_vote_tracker_record_vote(tracker, &vote_pubkey, &node_pubkey, 100, 50, 1000);

    sol_vote_record_t record;
    sol_err_t err = sol_vote_tracker_get_validator(tracker, &vote_pubkey, &record);
    ASSERT(err == SOL_OK);
    ASSERT(record.last_voted_slot == 100);
    ASSERT(record.root_slot == 50);
    ASSERT(record.stake == 1000);

    sol_vote_tracker_destroy(tracker);
}

/*
 * Test total stake
 */
TEST(vote_tracker_total_stake) {
    sol_vote_tracker_t* tracker = sol_vote_tracker_new(NULL);
    ASSERT(tracker != NULL);

    for (int i = 0; i < 10; i++) {
        sol_pubkey_t vote_pubkey = {0};
        vote_pubkey.bytes[0] = (uint8_t)i;
        sol_vote_tracker_record_vote(tracker, &vote_pubkey, NULL, 100, 0, 1000);
    }

    uint64_t total = sol_vote_tracker_total_stake(tracker);
    ASSERT(total == 10000);

    sol_vote_tracker_destroy(tracker);
}

/*
 * Test prune
 */
TEST(vote_tracker_prune) {
    sol_vote_tracker_config_t config = SOL_VOTE_TRACKER_CONFIG_DEFAULT;
    config.enable_pruning = true;
    sol_vote_tracker_t* tracker = sol_vote_tracker_new(&config);
    ASSERT(tracker != NULL);

    /* Record votes for slots 100, 200, 300 */
    sol_pubkey_t vote_pubkey = {0};
    sol_vote_tracker_record_vote(tracker, &vote_pubkey, NULL, 100, 0, 1000);

    vote_pubkey.bytes[0] = 1;
    sol_vote_tracker_record_vote(tracker, &vote_pubkey, NULL, 200, 0, 1000);

    vote_pubkey.bytes[0] = 2;
    sol_vote_tracker_record_vote(tracker, &vote_pubkey, NULL, 300, 0, 1000);

    /* Prune slots before 150 */
    sol_vote_tracker_prune(tracker, 150);

    /* Slot 100 should be gone, 200 and 300 should remain */
    uint64_t stake_100 = sol_vote_tracker_get_slot_stake(tracker, 100);
    uint64_t stake_200 = sol_vote_tracker_get_slot_stake(tracker, 200);
    uint64_t stake_300 = sol_vote_tracker_get_slot_stake(tracker, 300);

    ASSERT(stake_100 == 0);
    ASSERT(stake_200 == 1000);
    ASSERT(stake_300 == 1000);

    sol_vote_tracker_destroy(tracker);
}

/*
 * Test finalization tracking
 */
TEST(vote_tracker_finalization) {
    sol_vote_tracker_t* tracker = sol_vote_tracker_new(NULL);
    ASSERT(tracker != NULL);

    /*
     * Record votes from 6 validators each with 1000 stake
     * They all vote for slot 100 and have slot 50 as root
     */
    for (int i = 0; i < 6; i++) {
        sol_pubkey_t vote_pubkey = {0};
        vote_pubkey.bytes[0] = (uint8_t)i;
        sol_pubkey_t node_pubkey = {0};
        node_pubkey.bytes[0] = (uint8_t)(i + 10);

        /* Vote for slot 100, root is slot 50 */
        sol_err_t err = sol_vote_tracker_record_vote(
            tracker, &vote_pubkey, &node_pubkey, 100, 50, 1000);
        ASSERT(err == SOL_OK);
    }

    /* Check slot votes for slot 50 (the root) */
    sol_slot_votes_t slot_votes;
    sol_err_t err = sol_vote_tracker_get_slot_votes(tracker, 50, &slot_votes);
    ASSERT(err == SOL_OK);

    /* Slot 50 should be finalized (6 validators have it as root, 6000 stake)
     * Total stake is 6000, so 6000 * 3 >= 6000 * 2 = true */
    ASSERT(slot_votes.is_finalized == true);

    /* Check highest finalized slot */
    sol_slot_t highest_finalized = sol_vote_tracker_highest_finalized_slot(tracker);
    ASSERT(highest_finalized == 50);

    sol_vote_tracker_destroy(tracker);
}

/*
 * Test no finalization (not enough root stake)
 */
TEST(vote_tracker_no_finalization) {
    sol_vote_tracker_t* tracker = sol_vote_tracker_new(NULL);
    ASSERT(tracker != NULL);

    /* First, add 6 validators without root votes to establish total stake */
    for (int i = 0; i < 6; i++) {
        sol_pubkey_t vote_pubkey = {0};
        vote_pubkey.bytes[0] = (uint8_t)i;
        sol_pubkey_t node_pubkey = {0};
        node_pubkey.bytes[0] = (uint8_t)(i + 10);

        /* Vote for slot 100, no root */
        sol_err_t err = sol_vote_tracker_record_vote(
            tracker, &vote_pubkey, &node_pubkey, 100, 0, 1000);
        ASSERT(err == SOL_OK);
    }

    /* Now add 3 validators with root=50 (3000 stake < 4000 needed for 2/3) */
    for (int i = 6; i < 9; i++) {
        sol_pubkey_t vote_pubkey = {0};
        vote_pubkey.bytes[0] = (uint8_t)i;
        sol_pubkey_t node_pubkey = {0};
        node_pubkey.bytes[0] = (uint8_t)(i + 10);

        /* Vote for slot 100, root is slot 50 */
        sol_err_t err = sol_vote_tracker_record_vote(
            tracker, &vote_pubkey, &node_pubkey, 100, 50, 1000);
        ASSERT(err == SOL_OK);
    }

    /* Total stake is 9000, need 6000 root stake for finalization
     * Only 3000 have slot 50 as root, so not finalized */
    sol_slot_votes_t slot_votes;
    sol_err_t err = sol_vote_tracker_get_slot_votes(tracker, 50, &slot_votes);
    ASSERT(err == SOL_OK);
    ASSERT(slot_votes.is_finalized == false);

    /* Highest finalized should be 0 (none finalized) */
    sol_slot_t highest_finalized = sol_vote_tracker_highest_finalized_slot(tracker);
    ASSERT(highest_finalized == 0);

    sol_vote_tracker_destroy(tracker);
}

/*
 * Main
 */
int main(void) {
    printf("\n=== Vote Tracker Tests ===\n");

    RUN_TEST(vote_tracker_new);
    RUN_TEST(vote_tracker_config);
    RUN_TEST(vote_tracker_record_vote);
    RUN_TEST(vote_tracker_get_slot_stake);
    RUN_TEST(vote_tracker_supermajority);
    RUN_TEST(vote_tracker_no_supermajority);
    RUN_TEST(vote_tracker_get_validator);
    RUN_TEST(vote_tracker_total_stake);
    RUN_TEST(vote_tracker_prune);
    RUN_TEST(vote_tracker_finalization);
    RUN_TEST(vote_tracker_no_finalization);

    printf("\nResults: %d/%d passed\n\n", tests_passed, tests_run);

    sol_alloc_stats_print();
    return tests_passed == tests_run ? 0 : 1;
}
