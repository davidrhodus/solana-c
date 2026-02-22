/*
 * test_consensus.c - Tests for Tower BFT Consensus
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "../src/consensus/sol_tower.h"
#include "../src/consensus/sol_vote_tx.h"
#include "../src/runtime/sol_sysvar.h"
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
 * Test lockout duration calculation
 */
TEST(lockout_duration) {
    /* 2^1 = 2 for confirmation_count = 1 */
    ASSERT(sol_lockout_duration(1) == 2);

    /* 2^2 = 4 for confirmation_count = 2 */
    ASSERT(sol_lockout_duration(2) == 4);

    /* 2^10 = 1024 */
    ASSERT(sol_lockout_duration(10) == 1024);

    /* Max lockout for 32+ confirmations */
    ASSERT(sol_lockout_duration(32) == SOL_MAX_LOCKOUT);
    ASSERT(sol_lockout_duration(100) == SOL_MAX_LOCKOUT);
}

/*
 * Test lockout expiration
 */
TEST(lockout_expired) {
    sol_lockout_t lockout = {
        .slot = 100,
        .confirmation_count = 2  /* 2^2 = 4 slot lockout */
    };

    /* Not expired yet */
    ASSERT(sol_lockout_expired(&lockout, 100) == false);
    ASSERT(sol_lockout_expired(&lockout, 101) == false);
    ASSERT(sol_lockout_expired(&lockout, 103) == false);

    /* Should be expired at slot 104 (100 + 4) */
    ASSERT(sol_lockout_expired(&lockout, 104) == true);
    ASSERT(sol_lockout_expired(&lockout, 105) == true);
}

/*
 * Test tower creation
 */
TEST(tower_new) {
    sol_tower_config_t config = SOL_TOWER_CONFIG_DEFAULT;
    sol_tower_t* tower = sol_tower_new(&config);
    ASSERT(tower != NULL);

    ASSERT(sol_tower_root(tower) == 0);
    ASSERT(sol_tower_last_voted_slot(tower) == 0);

    sol_tower_destroy(tower);
}

/*
 * Test tower with default config
 */
TEST(tower_default_config) {
    sol_tower_t* tower = sol_tower_new(NULL);
    ASSERT(tower != NULL);
    sol_tower_destroy(tower);
}

/*
 * Test tower record vote
 */
TEST(tower_record_vote) {
    sol_tower_t* tower = sol_tower_new(NULL);
    ASSERT(tower != NULL);

    sol_hash_t hash1 = {0};
    hash1.bytes[0] = 1;

    sol_err_t err = sol_tower_record_vote(tower, 100, &hash1);
    ASSERT(err == SOL_OK);
    ASSERT(sol_tower_last_voted_slot(tower) == 100);

    sol_hash_t last_hash = sol_tower_last_voted_hash(tower);
    ASSERT(memcmp(&last_hash, &hash1, sizeof(sol_hash_t)) == 0);

    sol_tower_destroy(tower);
}

/*
 * Test tower vote stack
 */
TEST(tower_vote_stack) {
    sol_tower_t* tower = sol_tower_new(NULL);
    ASSERT(tower != NULL);

    /* Record votes for slots 1, 2, 3 */
    sol_hash_t hash = {0};
    sol_tower_record_vote(tower, 1, &hash);
    sol_tower_record_vote(tower, 2, &hash);
    sol_tower_record_vote(tower, 3, &hash);

    /* Get vote stack */
    sol_lockout_t votes[SOL_MAX_LOCKOUT_HISTORY];
    size_t count = sol_tower_vote_stack(tower, votes, SOL_MAX_LOCKOUT_HISTORY);
    ASSERT(count == 3);

    /* Check confirmations increase for older votes */
    /* Most recent vote has 1 confirmation */
    ASSERT(votes[2].slot == 3);
    ASSERT(votes[2].confirmation_count == 1);

    /* Earlier votes have more confirmations */
    ASSERT(votes[1].slot == 2);
    ASSERT(votes[1].confirmation_count == 2);

    ASSERT(votes[0].slot == 1);
    ASSERT(votes[0].confirmation_count == 3);

    sol_tower_destroy(tower);
}

/*
 * Test tower has_voted
 */
TEST(tower_has_voted) {
    sol_tower_t* tower = sol_tower_new(NULL);
    ASSERT(tower != NULL);

    sol_hash_t hash = {0};
    sol_tower_record_vote(tower, 100, &hash);
    sol_tower_record_vote(tower, 200, &hash);

    ASSERT(sol_tower_has_voted(tower, 100) == true);
    ASSERT(sol_tower_has_voted(tower, 200) == true);
    ASSERT(sol_tower_has_voted(tower, 150) == false);
    ASSERT(sol_tower_has_voted(tower, 300) == false);

    sol_tower_destroy(tower);
}

/*
 * Test tower lockout calculation
 */
TEST(tower_lockout) {
    sol_tower_t* tower = sol_tower_new(NULL);
    ASSERT(tower != NULL);

    sol_hash_t hash = {0};

    /* Record a vote */
    sol_tower_record_vote(tower, 100, &hash);

    /* Get lockout for that slot */
    uint64_t lockout = sol_tower_lockout(tower, 100);
    ASSERT(lockout == 2);  /* 2^1 = 2 for 1 confirmation */

    /* Non-voted slot has no lockout */
    lockout = sol_tower_lockout(tower, 50);
    ASSERT(lockout == 0);

    sol_tower_destroy(tower);
}

/*
 * Test tower root advancement
 */
TEST(tower_root_advance) {
    sol_tower_t* tower = sol_tower_new(NULL);
    ASSERT(tower != NULL);

    sol_hash_t hash = {0};

    /* Vote on enough slots to advance root */
    /* After 31 votes: slot 1 has 31 confirmations → becomes root */
    /* After 32 votes: slot 2 has 31 confirmations → becomes root */
    for (sol_slot_t i = 1; i <= SOL_MAX_LOCKOUT_HISTORY + 1; i++) {
        sol_tower_record_vote(tower, i, &hash);
    }

    /* After 32 votes, slot 2 should be root (slot 1 was root after vote 31) */
    sol_slot_t root = sol_tower_root(tower);
    ASSERT(root == 2);

    sol_tower_destroy(tower);
}

/*
 * Test tower would_be_locked_out
 */
TEST(tower_would_be_locked_out) {
    sol_tower_config_t config = SOL_TOWER_CONFIG_DEFAULT;
    config.disable_lockout = false;
    sol_tower_t* tower = sol_tower_new(&config);
    ASSERT(tower != NULL);

    sol_hash_t hash = {0};
    sol_tower_record_vote(tower, 100, &hash);

    /* Voting for earlier slot should be locked out */
    ASSERT(sol_tower_would_be_locked_out(tower, 99) == true);
    ASSERT(sol_tower_would_be_locked_out(tower, 50) == true);

    /* Future slot should not be locked out */
    ASSERT(sol_tower_would_be_locked_out(tower, 200) == false);

    sol_tower_destroy(tower);
}

/*
 * Test tower check vote decision
 */
TEST(tower_check_vote) {
    sol_tower_config_t config = SOL_TOWER_CONFIG_DEFAULT;
    config.disable_lockout = false;
    sol_tower_t* tower = sol_tower_new(&config);
    ASSERT(tower != NULL);

    /* First vote should pass */
    sol_vote_decision_t decision = sol_tower_check_vote(tower, 100, NULL, NULL);
    ASSERT(decision == SOL_VOTE_DECISION_VOTE);

    sol_hash_t hash = {0};
    sol_tower_record_vote(tower, 100, &hash);

    /* Same slot should be skipped */
    decision = sol_tower_check_vote(tower, 100, NULL, NULL);
    ASSERT(decision == SOL_VOTE_DECISION_SKIP);

    /* Earlier slot should be skipped */
    decision = sol_tower_check_vote(tower, 50, NULL, NULL);
    ASSERT(decision == SOL_VOTE_DECISION_SKIP);

    /* Future slot should pass */
    decision = sol_tower_check_vote(tower, 200, NULL, NULL);
    ASSERT(decision == SOL_VOTE_DECISION_VOTE);

    sol_tower_destroy(tower);
}

TEST(tower_check_vote_respects_fork_choice_best_bank) {
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, NULL);
    ASSERT(root != NULL);

    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);
    ASSERT(forks != NULL);

    sol_bank_t* root_bank = sol_bank_forks_root(forks);
    ASSERT(root_bank != NULL);

    sol_bank_t* b1 = sol_bank_new_from_parent(root_bank, 1);
    sol_bank_t* b2 = sol_bank_new_from_parent(root_bank, 1);
    ASSERT(b1 != NULL);
    ASSERT(b2 != NULL);

    sol_pubkey_t k1;
    memset(k1.bytes, 0xA1, 32);
    sol_pubkey_t k2;
    memset(k2.bytes, 0xB2, 32);

    sol_account_t* a1 = sol_account_new(1, 0, NULL);
    sol_account_t* a2 = sol_account_new(2, 0, NULL);
    ASSERT(a1 != NULL);
    ASSERT(a2 != NULL);

    ASSERT(sol_bank_store_account(b1, &k1, a1) == SOL_OK);
    ASSERT(sol_bank_store_account(b2, &k2, a2) == SOL_OK);

    sol_account_destroy(a1);
    sol_account_destroy(a2);

    sol_bank_freeze(b1);
    sol_bank_freeze(b2);

    ASSERT(sol_bank_forks_insert(forks, b1) == SOL_OK);
    ASSERT(sol_bank_forks_insert(forks, b2) == SOL_OK);

    sol_fork_choice_t* fc = sol_fork_choice_new(forks, NULL);
    ASSERT(fc != NULL);

    sol_hash_t b2_hash = {0};
    sol_bank_compute_hash(b2, &b2_hash);

    sol_pubkey_t validator;
    memset(validator.bytes, 0xCC, 32);
    ASSERT(sol_fork_choice_record_vote_hash(fc, &validator, 1, &b2_hash, 1000) == SOL_OK);

    sol_tower_t* tower = sol_tower_new(NULL);
    ASSERT(tower != NULL);

    sol_vote_decision_t d1 = sol_tower_check_vote(tower, 1, b1, fc);
    ASSERT(d1 == SOL_VOTE_DECISION_WAIT);

    sol_vote_decision_t d2 = sol_tower_check_vote(tower, 1, b2, fc);
    ASSERT(d2 == SOL_VOTE_DECISION_VOTE);

    sol_tower_destroy(tower);
    sol_fork_choice_destroy(fc);
    sol_bank_forks_destroy(forks);
}

/*
 * Test vote state serialization
 */
TEST(vote_state_serialize) {
    sol_tower_t* tower = sol_tower_new(NULL);
    ASSERT(tower != NULL);

    sol_hash_t hash = {0};
    sol_tower_record_vote(tower, 100, &hash);
    sol_tower_record_vote(tower, 200, &hash);

    /* Get vote state */
    sol_vote_state_t state;
    sol_err_t err = sol_tower_get_vote_state(tower, &state);
    ASSERT(err == SOL_OK);
    ASSERT(state.votes_len == 2);

    /* Serialize */
    uint8_t buffer[4096];  /* sol_vote_state_t is ~2KB with epoch_credits */
    size_t len = 0;
    err = sol_vote_state_serialize(&state, buffer, sizeof(buffer), &len);
    ASSERT(err == SOL_OK);
    ASSERT(len > 0);

    /* Deserialize */
    sol_vote_state_t state2;
    err = sol_vote_state_deserialize(&state2, buffer, len);
    ASSERT(err == SOL_OK);
    ASSERT(state2.votes_len == state.votes_len);
    ASSERT(state2.votes[0].slot == state.votes[0].slot);
    ASSERT(state2.votes[1].slot == state.votes[1].slot);

    sol_tower_destroy(tower);
}

/*
 * Test tower apply vote
 */
TEST(tower_apply_vote) {
    sol_vote_state_t state = {0};

    sol_hash_t hash = {0};
    sol_err_t err = sol_tower_apply_vote(&state, 100, &hash);
    ASSERT(err == SOL_OK);
    ASSERT(state.votes_len == 1);
    ASSERT(state.votes[0].slot == 100);
    ASSERT(state.votes[0].confirmation_count == 1);

    err = sol_tower_apply_vote(&state, 200, &hash);
    ASSERT(err == SOL_OK);
    ASSERT(state.votes_len == 2);
    ASSERT(state.votes[1].slot == 200);
    ASSERT(state.votes[0].confirmation_count == 2);  /* Older vote got confirmed */
}

TEST(vote_tx_includes_required_accounts) {
    uint8_t seed[32];
    for (size_t i = 0; i < sizeof(seed); i++) seed[i] = (uint8_t)i;

    sol_keypair_t kp;
    sol_ed25519_keypair_from_seed(seed, &kp);

    sol_pubkey_t authorized;
    sol_keypair_pubkey(&kp, &authorized);

    sol_pubkey_t vote_account;
    memset(vote_account.bytes, 0x11, sizeof(vote_account.bytes));

    sol_vote_tx_builder_t builder;
    sol_vote_tx_builder_init(&builder, &vote_account, &kp);

    sol_hash_t recent_blockhash;
    memset(recent_blockhash.bytes, 0x22, sizeof(recent_blockhash.bytes));
    sol_vote_tx_builder_set_blockhash(&builder, &recent_blockhash);

    sol_lockout_t lockouts[2] = {
        {.slot = 1, .confirmation_count = 1},
        {.slot = 2, .confirmation_count = 1},
    };

    sol_hash_t bank_hash;
    memset(bank_hash.bytes, 0x33, sizeof(bank_hash.bytes));

    uint8_t tx_bytes[SOL_MAX_TX_SIZE];
    size_t tx_len = 0;
    sol_err_t err = sol_vote_tx_create_compact(
        &builder, lockouts, 2, 0, &bank_hash, 0,
        tx_bytes, sizeof(tx_bytes), &tx_len);
    ASSERT(err == SOL_OK);
    ASSERT(tx_len > 0);

    sol_transaction_t tx;
    sol_transaction_init(&tx);
    err = sol_transaction_decode(tx_bytes, tx_len, &tx);
    ASSERT(err == SOL_OK);

    ASSERT(tx.signatures_len == 1);
    ASSERT(tx.message.header.num_required_signatures == 1);
    ASSERT(tx.message.header.num_readonly_signed == 1);
    ASSERT(tx.message.header.num_readonly_unsigned == 3);

    ASSERT(tx.message.account_keys_len == 5);
    ASSERT(memcmp(tx.message.account_keys[0].bytes, authorized.bytes, 32) == 0);
    ASSERT(memcmp(tx.message.account_keys[1].bytes, vote_account.bytes, 32) == 0);
    ASSERT(memcmp(tx.message.account_keys[2].bytes, SOL_SYSVAR_SLOT_HASHES_ID.bytes, 32) == 0);
    ASSERT(memcmp(tx.message.account_keys[3].bytes, SOL_SYSVAR_CLOCK_ID.bytes, 32) == 0);
    ASSERT(memcmp(tx.message.account_keys[4].bytes, SOL_VOTE_PROGRAM_ID.bytes, 32) == 0);

    ASSERT(tx.message.instructions_len == 1);
    const sol_compiled_instruction_t* instr = &tx.message.instructions[0];
    ASSERT(instr->program_id_index == 4);
    ASSERT(instr->account_indices_len == 4);
    ASSERT(instr->account_indices[0] == 1);  /* vote account */
    ASSERT(instr->account_indices[1] == 2);  /* slot hashes */
    ASSERT(instr->account_indices[2] == 3);  /* clock */
    ASSERT(instr->account_indices[3] == 0);  /* authorized voter */
    ASSERT(memcmp(tx.message.recent_blockhash.bytes, recent_blockhash.bytes, 32) == 0);
}

TEST(tower_persist_roundtrip) {
    sol_tower_t* tower1 = sol_tower_new(NULL);
    ASSERT(tower1 != NULL);

    sol_hash_t hash = {0};
    hash.bytes[0] = 0x42;

    for (sol_slot_t i = 1; i <= SOL_MAX_LOCKOUT_HISTORY + 1; i++) {
        ASSERT(sol_tower_record_vote(tower1, i, &hash) == SOL_OK);
    }
    ASSERT(sol_tower_root(tower1) == 2);

    char path[256];
    snprintf(path, sizeof(path), "/tmp/solana-c.tower.%d.bin", (int)getpid());

    (void)unlink(path);
    char tmp_path[260];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
    (void)unlink(tmp_path);

    ASSERT(sol_tower_save_file(tower1, path) == SOL_OK);

    sol_tower_t* tower2 = sol_tower_new(NULL);
    ASSERT(tower2 != NULL);
    ASSERT(sol_tower_load_file(tower2, path) == SOL_OK);

    ASSERT(sol_tower_root(tower2) == sol_tower_root(tower1));
    ASSERT(sol_tower_last_voted_slot(tower2) == sol_tower_last_voted_slot(tower1));

    sol_hash_t h1 = sol_tower_last_voted_hash(tower1);
    sol_hash_t h2 = sol_tower_last_voted_hash(tower2);
    ASSERT(memcmp(&h1, &h2, sizeof(sol_hash_t)) == 0);

    sol_lockout_t votes1[SOL_MAX_LOCKOUT_HISTORY];
    sol_lockout_t votes2[SOL_MAX_LOCKOUT_HISTORY];
    size_t n1 = sol_tower_vote_stack(tower1, votes1, SOL_MAX_LOCKOUT_HISTORY);
    size_t n2 = sol_tower_vote_stack(tower2, votes2, SOL_MAX_LOCKOUT_HISTORY);
    ASSERT(n1 == n2);
    ASSERT(memcmp(votes1, votes2, n1 * sizeof(sol_lockout_t)) == 0);

    sol_tower_destroy(tower1);
    sol_tower_destroy(tower2);
    (void)unlink(path);
    (void)unlink(tmp_path);
}

/*
 * Main
 */
int main(void) {
    printf("\n=== Tower BFT Consensus Tests ===\n");

    RUN_TEST(lockout_duration);
    RUN_TEST(lockout_expired);
    RUN_TEST(tower_new);
    RUN_TEST(tower_default_config);
    RUN_TEST(tower_record_vote);
    RUN_TEST(tower_vote_stack);
    RUN_TEST(tower_has_voted);
    RUN_TEST(tower_lockout);
    RUN_TEST(tower_root_advance);
    RUN_TEST(tower_would_be_locked_out);
    RUN_TEST(tower_check_vote);
    RUN_TEST(tower_check_vote_respects_fork_choice_best_bank);
    RUN_TEST(vote_state_serialize);
    RUN_TEST(tower_apply_vote);
    RUN_TEST(vote_tx_includes_required_accounts);
    RUN_TEST(tower_persist_roundtrip);

    printf("\nResults: %d/%d passed\n\n", tests_passed, tests_run);

    sol_alloc_stats_print();
    return tests_passed == tests_run ? 0 : 1;
}
