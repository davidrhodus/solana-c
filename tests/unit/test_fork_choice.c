/*
 * test_fork_choice.c - Tests for fork choice vote/hash tracking helpers
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/replay/sol_fork_choice.h"

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

static void
fill_hash(sol_hash_t* h, uint8_t v) {
    memset(h, 0, sizeof(*h));
    h->bytes[0] = v;
}

TEST(best_voted_hash_basic) {
    sol_fork_choice_t* fc = sol_fork_choice_new(NULL, NULL);
    ASSERT(fc != NULL);

    sol_pubkey_t v1 = {0};
    sol_pubkey_t v2 = {0};
    sol_pubkey_t v3 = {0};
    v1.bytes[0] = 1;
    v2.bytes[0] = 2;
    v3.bytes[0] = 3;

    sol_hash_t h1;
    sol_hash_t h2;
    fill_hash(&h1, 11);
    fill_hash(&h2, 22);

    ASSERT(sol_fork_choice_record_vote_hash(fc, &v1, 100, &h1, 1000) == SOL_OK);
    ASSERT(sol_fork_choice_record_vote_hash(fc, &v2, 100, &h1, 2000) == SOL_OK);
    ASSERT(sol_fork_choice_record_vote_hash(fc, &v3, 100, &h2, 5000) == SOL_OK);

    sol_hash_t best = {0};
    uint64_t best_stake = 0;
    uint32_t best_votes = 0;
    uint64_t total_stake = 0;
    uint32_t total_votes = 0;
    ASSERT(sol_fork_choice_best_voted_hash(fc,
                                          100,
                                          &best,
                                          &best_stake,
                                          &best_votes,
                                          &total_stake,
                                          &total_votes));
    ASSERT(memcmp(best.bytes, h2.bytes, SOL_HASH_SIZE) == 0);
    ASSERT(best_stake == 5000);
    ASSERT(best_votes == 1);
    ASSERT(total_stake == 8000);
    ASSERT(total_votes == 3);

    /* Change v3 vote to h1 at same slot */
    ASSERT(sol_fork_choice_record_vote_hash(fc, &v3, 100, &h1, 5000) == SOL_OK);
    memset(&best, 0, sizeof(best));
    best_stake = 0;
    best_votes = 0;
    total_stake = 0;
    total_votes = 0;
    ASSERT(sol_fork_choice_best_voted_hash(fc,
                                          100,
                                          &best,
                                          &best_stake,
                                          &best_votes,
                                          &total_stake,
                                          &total_votes));
    ASSERT(memcmp(best.bytes, h1.bytes, SOL_HASH_SIZE) == 0);
    ASSERT(best_stake == 8000);
    ASSERT(best_votes == 3);
    ASSERT(total_stake == 8000);
    ASSERT(total_votes == 3);

    sol_fork_choice_destroy(fc);
}

TEST(best_voted_hash_tiebreak_vote_count) {
    sol_fork_choice_t* fc = sol_fork_choice_new(NULL, NULL);
    ASSERT(fc != NULL);

    sol_pubkey_t a = {0};
    sol_pubkey_t b = {0};
    sol_pubkey_t c = {0};
    a.bytes[0] = 1;
    b.bytes[0] = 2;
    c.bytes[0] = 3;

    sol_hash_t h1;
    sol_hash_t h2;
    fill_hash(&h1, 1);
    fill_hash(&h2, 2);

    /* Same total stake for both hashes (5000), but h1 has 2 votes */
    ASSERT(sol_fork_choice_record_vote_hash(fc, &a, 77, &h1, 2500) == SOL_OK);
    ASSERT(sol_fork_choice_record_vote_hash(fc, &b, 77, &h1, 2500) == SOL_OK);
    ASSERT(sol_fork_choice_record_vote_hash(fc, &c, 77, &h2, 5000) == SOL_OK);

    sol_hash_t best = {0};
    uint64_t best_stake = 0;
    uint32_t best_votes = 0;
    ASSERT(sol_fork_choice_best_voted_hash(fc, 77, &best, &best_stake, &best_votes, NULL, NULL));
    ASSERT(memcmp(best.bytes, h1.bytes, SOL_HASH_SIZE) == 0);
    ASSERT(best_stake == 5000);
    ASSERT(best_votes == 2);

    sol_fork_choice_destroy(fc);
}

TEST(best_voted_hash_tiebreak_hash_bytes) {
    sol_fork_choice_t* fc = sol_fork_choice_new(NULL, NULL);
    ASSERT(fc != NULL);

    sol_pubkey_t a = {0};
    sol_pubkey_t b = {0};
    a.bytes[0] = 1;
    b.bytes[0] = 2;

    sol_hash_t h1;
    sol_hash_t h2;
    fill_hash(&h1, 1);
    fill_hash(&h2, 2);

    ASSERT(sol_fork_choice_record_vote_hash(fc, &a, 9, &h1, 1000) == SOL_OK);
    ASSERT(sol_fork_choice_record_vote_hash(fc, &b, 9, &h2, 1000) == SOL_OK);

    sol_hash_t best = {0};
    ASSERT(sol_fork_choice_best_voted_hash(fc, 9, &best, NULL, NULL, NULL, NULL));
    ASSERT(memcmp(best.bytes, h2.bytes, SOL_HASH_SIZE) == 0);

    sol_fork_choice_destroy(fc);
}

int main(void) {
    printf("Fork choice tests:\n");

    RUN_TEST(best_voted_hash_basic);
    RUN_TEST(best_voted_hash_tiebreak_vote_count);
    RUN_TEST(best_voted_hash_tiebreak_hash_bytes);

    printf("\nFork choice tests passed: %d/%d\n", tests_passed, tests_run);
    return 0;
}

