/*
 * test_replay.c - Replay module unit tests
 */

#include "../test_framework.h"
#include "sol_bank_forks.h"
#include "sol_fork_choice.h"
#include "sol_replay.h"
#include "sol_bank.h"
#include "sol_blockstore.h"
#include "sol_shred.h"
#include "sol_entry.h"
#include "sol_alloc.h"
#include <string.h>

static void
create_mock_shred(sol_shred_t* shred, uint8_t* data, size_t* len,
                  sol_slot_t slot, uint32_t index, bool is_last) {
    memset(shred, 0, sizeof(*shred));
    shred->slot = slot;
    shred->index = index;
    shred->type = SOL_SHRED_TYPE_DATA;
    shred->header.data.parent_slot = slot > 0 ? slot - 1 : 0;

    if (is_last) {
        shred->header.data.flags = SOL_SHRED_FLAG_LAST_IN_SLOT;
    }

    memset(data, 0, 1024);

    data[64] = SOL_SHRED_VARIANT_LEGACY_DATA;

    for (int i = 0; i < 8; i++) {
        data[65 + i] = (uint8_t)((slot >> (i * 8)) & 0xFFu);
    }

    for (int i = 0; i < 4; i++) {
        data[73 + i] = (uint8_t)((index >> (i * 8)) & 0xFFu);
    }

    uint16_t parent_offset = (uint16_t)(slot - shred->header.data.parent_slot);
    data[SOL_SHRED_HEADER_SIZE + 0] = (uint8_t)(parent_offset & 0xFFu);
    data[SOL_SHRED_HEADER_SIZE + 1] = (uint8_t)((parent_offset >> 8) & 0xFFu);
    data[SOL_SHRED_HEADER_SIZE + 2] = shred->header.data.flags;

    uint16_t payload_len = 200 - (uint16_t)SOL_SHRED_DATA_HEADERS_SIZE;
    uint16_t total_size = (uint16_t)((uint16_t)SOL_SHRED_DATA_HEADERS_SIZE + payload_len);
    data[SOL_SHRED_HEADER_SIZE + 3] = (uint8_t)(total_size & 0xFFu);
    data[SOL_SHRED_HEADER_SIZE + 4] = (uint8_t)((total_size >> 8) & 0xFFu);

    size_t payload_off = SOL_SHRED_HEADER_SIZE + SOL_SHRED_DATA_HEADER_SIZE;
    for (size_t i = payload_off; i < 200; i++) {
        data[i] = (uint8_t)(0xA5u ^ (uint8_t)index ^ (uint8_t)i);
    }

    *len = 200;
}

static size_t
build_mock_legacy_data_shred(uint8_t* out, size_t out_len,
                             sol_slot_t slot, uint32_t index,
                             uint16_t version, uint32_t fec_set_index,
                             uint8_t flags,
                             const uint8_t* payload, size_t payload_len) {
    size_t needed = SOL_SHRED_HEADER_SIZE + SOL_SHRED_DATA_HEADER_SIZE + payload_len;
    if (needed > out_len) return 0;
    if (payload_len > UINT16_MAX) return 0;

    memset(out, 0, needed);

    out[64] = SOL_SHRED_VARIANT_LEGACY_DATA;

    for (int i = 0; i < 8; i++) {
        out[65 + i] = (uint8_t)((slot >> (i * 8)) & 0xFFu);
    }

    for (int i = 0; i < 4; i++) {
        out[73 + i] = (uint8_t)((index >> (i * 8)) & 0xFFu);
    }

    out[77] = (uint8_t)(version & 0xFFu);
    out[78] = (uint8_t)((version >> 8) & 0xFFu);

    for (int i = 0; i < 4; i++) {
        out[79 + i] = (uint8_t)((fec_set_index >> (i * 8)) & 0xFFu);
    }

    sol_slot_t parent_slot = slot > 0 ? slot - 1 : 0;
    uint16_t parent_offset = (uint16_t)(slot - parent_slot);
    out[SOL_SHRED_HEADER_SIZE + 0] = (uint8_t)(parent_offset & 0xFFu);
    out[SOL_SHRED_HEADER_SIZE + 1] = (uint8_t)((parent_offset >> 8) & 0xFFu);
    out[SOL_SHRED_HEADER_SIZE + 2] = flags;

    out[SOL_SHRED_HEADER_SIZE + 3] = (uint8_t)(needed & 0xFFu);
    out[SOL_SHRED_HEADER_SIZE + 4] = (uint8_t)((needed >> 8) & 0xFFu);

    if (payload_len > 0) {
        memcpy(out + SOL_SHRED_HEADER_SIZE + SOL_SHRED_DATA_HEADER_SIZE, payload, payload_len);
    }

    return needed;
}

/*
 * Bank forks tests
 */

TEST(bank_forks_create_destroy) {
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, NULL);
    TEST_ASSERT(root != NULL);

    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);
    TEST_ASSERT(forks != NULL);
    TEST_ASSERT_EQ(sol_bank_forks_count(forks), 1);
    TEST_ASSERT_EQ(sol_bank_forks_root_slot(forks), 0);

    sol_bank_forks_destroy(forks);
}

TEST(bank_forks_get_root) {
    sol_bank_t* root = sol_bank_new(10, NULL, NULL, NULL);
    TEST_ASSERT(root != NULL);

    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);
    TEST_ASSERT(forks != NULL);

    sol_bank_t* got_root = sol_bank_forks_root(forks);
    TEST_ASSERT(got_root != NULL);
    TEST_ASSERT_EQ(sol_bank_slot(got_root), 10);

    sol_bank_forks_destroy(forks);
}

TEST(bank_forks_new_from_parent) {
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, NULL);
    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);
    TEST_ASSERT(forks != NULL);

    /* Create child bank */
    sol_bank_t* child = sol_bank_forks_new_from_parent(forks, 0, 1);
    TEST_ASSERT(child != NULL);
    TEST_ASSERT_EQ(sol_bank_slot(child), 1);
    TEST_ASSERT_EQ(sol_bank_forks_count(forks), 2);

    /* Create grandchild */
    sol_bank_t* grandchild = sol_bank_forks_new_from_parent(forks, 1, 2);
    TEST_ASSERT(grandchild != NULL);
    TEST_ASSERT_EQ(sol_bank_slot(grandchild), 2);
    TEST_ASSERT_EQ(sol_bank_forks_count(forks), 3);

    sol_bank_forks_destroy(forks);
}

TEST(bank_forks_account_isolation) {
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, NULL);
    TEST_ASSERT_NOT_NULL(root);

    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);
    TEST_ASSERT_NOT_NULL(forks);

    sol_pubkey_t key;
    memset(key.bytes, 0xAC, 32);

    sol_account_t* acc0 = sol_account_new(100, 0, NULL);
    sol_account_t* acc1 = sol_account_new(90, 0, NULL);
    sol_account_t* acc2 = sol_account_new(80, 0, NULL);
    TEST_ASSERT_NOT_NULL(acc0);
    TEST_ASSERT_NOT_NULL(acc1);
    TEST_ASSERT_NOT_NULL(acc2);

    TEST_ASSERT_EQ(sol_bank_store_account(root, &key, acc0), SOL_OK);

    sol_bank_t* bank1 = sol_bank_forks_new_from_parent(forks, 0, 1);
    sol_bank_t* bank2 = sol_bank_forks_new_from_parent(forks, 0, 2);
    TEST_ASSERT_NOT_NULL(bank1);
    TEST_ASSERT_NOT_NULL(bank2);

    TEST_ASSERT_EQ(sol_bank_store_account(bank1, &key, acc1), SOL_OK);
    TEST_ASSERT_EQ(sol_bank_store_account(bank2, &key, acc2), SOL_OK);

    sol_account_t* loaded_root = sol_bank_load_account(root, &key);
    sol_account_t* loaded1 = sol_bank_load_account(bank1, &key);
    sol_account_t* loaded2 = sol_bank_load_account(bank2, &key);
    TEST_ASSERT_NOT_NULL(loaded_root);
    TEST_ASSERT_NOT_NULL(loaded1);
    TEST_ASSERT_NOT_NULL(loaded2);
    TEST_ASSERT_EQ(loaded_root->meta.lamports, 100);
    TEST_ASSERT_EQ(loaded1->meta.lamports, 90);
    TEST_ASSERT_EQ(loaded2->meta.lamports, 80);

    sol_account_destroy(acc0);
    sol_account_destroy(acc1);
    sol_account_destroy(acc2);
    sol_account_destroy(loaded_root);
    sol_account_destroy(loaded1);
    sol_account_destroy(loaded2);
    sol_bank_forks_destroy(forks);
}

TEST(bank_forks_get_bank) {
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, NULL);
    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);

    sol_bank_forks_new_from_parent(forks, 0, 1);
    sol_bank_forks_new_from_parent(forks, 1, 2);

    /* Get existing banks */
    TEST_ASSERT(sol_bank_forks_get(forks, 0) != NULL);
    TEST_ASSERT(sol_bank_forks_get(forks, 1) != NULL);
    TEST_ASSERT(sol_bank_forks_get(forks, 2) != NULL);

    /* Get non-existent bank */
    TEST_ASSERT(sol_bank_forks_get(forks, 99) == NULL);

    sol_bank_forks_destroy(forks);
}

TEST(bank_forks_contains) {
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, NULL);
    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);

    sol_bank_forks_new_from_parent(forks, 0, 1);

    TEST_ASSERT(sol_bank_forks_contains(forks, 0));
    TEST_ASSERT(sol_bank_forks_contains(forks, 1));
    TEST_ASSERT(!sol_bank_forks_contains(forks, 2));

    sol_bank_forks_destroy(forks);
}

TEST(bank_forks_freeze) {
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, NULL);
    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);

    sol_bank_t* child = sol_bank_forks_new_from_parent(forks, 0, 1);
    TEST_ASSERT(!sol_bank_is_frozen(child));

    sol_err_t err = sol_bank_forks_freeze(forks, 1);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT(sol_bank_is_frozen(child));

    sol_bank_forks_destroy(forks);
}

TEST(bank_forks_set_root) {
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, NULL);

    /* Seed an account in the root bank */
    sol_pubkey_t key;
    memset(key.bytes, 0xAB, 32);
    sol_account_t* acc0 = sol_account_new(100, 0, NULL);
    TEST_ASSERT_NOT_NULL(acc0);
    TEST_ASSERT_EQ(sol_bank_store_account(root, &key, acc0), SOL_OK);

    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);
    TEST_ASSERT_NOT_NULL(forks);

    /* Create a chain: 0 -> 1 -> 2 */
    sol_bank_t* bank1 = sol_bank_forks_new_from_parent(forks, 0, 1);
    TEST_ASSERT_NOT_NULL(bank1);
    sol_bank_t* bank2 = sol_bank_forks_new_from_parent(forks, 1, 2);
    TEST_ASSERT_NOT_NULL(bank2);
    /* Create a competing branch off the old root */
    sol_bank_t* bank3 = sol_bank_forks_new_from_parent(forks, 0, 3);
    TEST_ASSERT_NOT_NULL(bank3);

    /* Modify the account on each forked bank */
    sol_account_t* acc1 = sol_account_new(90, 0, NULL);
    sol_account_t* acc2 = sol_account_new(80, 0, NULL);
    TEST_ASSERT_NOT_NULL(acc1);
    TEST_ASSERT_NOT_NULL(acc2);
    TEST_ASSERT_EQ(sol_bank_store_account(bank1, &key, acc1), SOL_OK);
    TEST_ASSERT_EQ(sol_bank_store_account(bank2, &key, acc2), SOL_OK);

    TEST_ASSERT_EQ(sol_bank_forks_count(forks), 4);

    /* Set root to slot 1 */
    sol_err_t err = sol_bank_forks_set_root(forks, 1);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_EQ(sol_bank_forks_root_slot(forks), 1);

    /* Remaining banks must still be able to access rooted state after pruning slot 0 */
    sol_bank_t* new_root = sol_bank_forks_root(forks);
    TEST_ASSERT_NOT_NULL(new_root);
    sol_account_t* loaded1 = sol_bank_load_account(new_root, &key);
    sol_account_t* loaded2 = sol_bank_load_account(sol_bank_forks_get(forks, 2), &key);
    TEST_ASSERT_NOT_NULL(loaded1);
    TEST_ASSERT_NOT_NULL(loaded2);
    TEST_ASSERT_EQ(loaded1->meta.lamports, 90);
    TEST_ASSERT_EQ(loaded2->meta.lamports, 80);

    /* Slot 0 should be pruned */
    TEST_ASSERT(!sol_bank_forks_contains(forks, 0));
    TEST_ASSERT(sol_bank_forks_contains(forks, 1));
    TEST_ASSERT(sol_bank_forks_contains(forks, 2));
    TEST_ASSERT(!sol_bank_forks_contains(forks, 3));
    TEST_ASSERT_EQ(sol_bank_forks_highest_slot(forks), 2);

    sol_account_destroy(acc0);
    sol_account_destroy(acc1);
    sol_account_destroy(acc2);
    sol_account_destroy(loaded1);
    sol_account_destroy(loaded2);
    sol_bank_forks_destroy(forks);
}

TEST(bank_forks_set_root_hash_prunes_duplicate_slot) {
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, NULL);
    TEST_ASSERT_NOT_NULL(root);

    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);
    TEST_ASSERT_NOT_NULL(forks);

    sol_bank_t* parent = sol_bank_forks_get(forks, 0);
    TEST_ASSERT_NOT_NULL(parent);

    sol_bank_t* bank_a = sol_bank_new_from_parent(parent, 1);
    sol_bank_t* bank_b = sol_bank_new_from_parent(parent, 1);
    TEST_ASSERT_NOT_NULL(bank_a);
    TEST_ASSERT_NOT_NULL(bank_b);

    sol_pubkey_t key;
    memset(key.bytes, 0xCD, 32);
    sol_account_t* acc = sol_account_new(123, 0, NULL);
    TEST_ASSERT_NOT_NULL(acc);
    TEST_ASSERT_EQ(sol_bank_store_account(bank_b, &key, acc), SOL_OK);
    sol_account_destroy(acc);

    sol_bank_freeze(bank_a);
    sol_bank_freeze(bank_b);

    sol_hash_t hash_a = {0};
    sol_hash_t hash_b = {0};
    sol_bank_compute_hash(bank_a, &hash_a);
    sol_bank_compute_hash(bank_b, &hash_b);
    TEST_ASSERT(memcmp(hash_a.bytes, hash_b.bytes, SOL_HASH_SIZE) != 0);

    TEST_ASSERT_EQ(sol_bank_forks_insert(forks, bank_a), SOL_OK);
    TEST_ASSERT_EQ(sol_bank_forks_insert(forks, bank_b), SOL_OK);
    TEST_ASSERT_EQ(sol_bank_forks_count(forks), 3);

    TEST_ASSERT_EQ(sol_bank_forks_set_root_hash(forks, 1, &hash_b), SOL_OK);
    TEST_ASSERT_EQ(sol_bank_forks_root_slot(forks), 1);

    /* Duplicate bank at slot 1 should be pruned */
    TEST_ASSERT(sol_bank_forks_get_hash(forks, 1, &hash_a) == NULL);
    TEST_ASSERT(sol_bank_forks_get_hash(forks, 1, &hash_b) != NULL);
    TEST_ASSERT_EQ(sol_bank_forks_count(forks), 1);

    sol_bank_t* new_root = sol_bank_forks_root(forks);
    TEST_ASSERT_NOT_NULL(new_root);
    sol_account_t* loaded = sol_bank_load_account(new_root, &key);
    TEST_ASSERT_NOT_NULL(loaded);
    TEST_ASSERT_EQ(loaded->meta.lamports, 123);
    sol_account_destroy(loaded);

    sol_bank_forks_destroy(forks);
}

TEST(bank_forks_highest_slot) {
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, NULL);
    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);

    TEST_ASSERT_EQ(sol_bank_forks_highest_slot(forks), 0);

    sol_bank_forks_new_from_parent(forks, 0, 5);
    TEST_ASSERT_EQ(sol_bank_forks_highest_slot(forks), 5);

    sol_bank_forks_new_from_parent(forks, 0, 3);
    TEST_ASSERT_EQ(sol_bank_forks_highest_slot(forks), 5);

    sol_bank_forks_new_from_parent(forks, 5, 10);
    TEST_ASSERT_EQ(sol_bank_forks_highest_slot(forks), 10);

    sol_bank_forks_destroy(forks);
}

TEST(bank_forks_mark_dead) {
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, NULL);
    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);

    sol_bank_t* child = sol_bank_forks_new_from_parent(forks, 0, 1);
    TEST_ASSERT_NOT_NULL(child);
    TEST_ASSERT_EQ(sol_bank_forks_freeze(forks, 1), SOL_OK);

    sol_hash_t child_hash = {0};
    sol_bank_compute_hash(child, &child_hash);

    sol_fork_info_t info;
    sol_bank_forks_get_info_hash(forks, 1, &child_hash, &info);
    TEST_ASSERT(!info.is_dead);

    sol_bank_forks_mark_dead_hash(forks, 1, &child_hash);

    sol_bank_forks_get_info_hash(forks, 1, &child_hash, &info);
    TEST_ASSERT(info.is_dead);

    sol_bank_forks_destroy(forks);
}

/*
 * Fork choice tests
 */

TEST(fork_choice_create_destroy) {
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, NULL);
    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);

    sol_fork_choice_t* fc = sol_fork_choice_new(forks, NULL);
    TEST_ASSERT(fc != NULL);
    TEST_ASSERT_EQ(sol_fork_choice_voter_count(fc), 0);
    TEST_ASSERT_EQ(sol_fork_choice_total_stake(fc), 0);

    sol_fork_choice_destroy(fc);
    sol_bank_forks_destroy(forks);
}

TEST(fork_choice_record_vote) {
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, NULL);
    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);
    sol_fork_choice_t* fc = sol_fork_choice_new(forks, NULL);

    sol_pubkey_t validator1, validator2;
    memset(validator1.bytes, 0x11, 32);
    memset(validator2.bytes, 0x22, 32);

    /* Record votes */
    sol_err_t err = sol_fork_choice_record_vote(fc, &validator1, 5, 1000);
    TEST_ASSERT_EQ(err, SOL_OK);

    err = sol_fork_choice_record_vote(fc, &validator2, 5, 2000);
    TEST_ASSERT_EQ(err, SOL_OK);

    TEST_ASSERT_EQ(sol_fork_choice_voter_count(fc), 2);
    TEST_ASSERT_EQ(sol_fork_choice_total_stake(fc), 3000);
    TEST_ASSERT_EQ(sol_fork_choice_stake_weight(fc, 5), 3000);

    sol_fork_choice_destroy(fc);
    sol_bank_forks_destroy(forks);
}

TEST(fork_choice_update_vote) {
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, NULL);
    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);
    sol_fork_choice_t* fc = sol_fork_choice_new(forks, NULL);

    sol_pubkey_t validator;
    memset(validator.bytes, 0x33, 32);

    /* Initial vote */
    sol_fork_choice_record_vote(fc, &validator, 5, 1000);
    TEST_ASSERT_EQ(sol_fork_choice_stake_weight(fc, 5), 1000);

    /* Update vote to higher slot */
    sol_fork_choice_record_vote(fc, &validator, 10, 1000);
    TEST_ASSERT_EQ(sol_fork_choice_stake_weight(fc, 5), 0);
    TEST_ASSERT_EQ(sol_fork_choice_stake_weight(fc, 10), 1000);

    /* Old vote should not update */
    sol_fork_choice_record_vote(fc, &validator, 8, 1000);
    TEST_ASSERT_EQ(sol_fork_choice_stake_weight(fc, 10), 1000);
    TEST_ASSERT_EQ(sol_fork_choice_stake_weight(fc, 8), 0);

    sol_fork_choice_destroy(fc);
    sol_bank_forks_destroy(forks);
}

TEST(fork_choice_latest_vote) {
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, NULL);
    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);
    sol_fork_choice_t* fc = sol_fork_choice_new(forks, NULL);

    sol_pubkey_t validator;
    memset(validator.bytes, 0x44, 32);

    sol_fork_choice_record_vote(fc, &validator, 5, 1000);
    TEST_ASSERT_EQ(sol_fork_choice_latest_vote(fc, &validator), 5);

    sol_fork_choice_record_vote(fc, &validator, 10, 1000);
    TEST_ASSERT_EQ(sol_fork_choice_latest_vote(fc, &validator), 10);

    sol_fork_choice_destroy(fc);
    sol_bank_forks_destroy(forks);
}

TEST(fork_choice_best_slot_single_fork) {
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, NULL);
    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);

    /* Create chain: 0 -> 1 -> 2 -> 3 */
    sol_bank_forks_new_from_parent(forks, 0, 1);
    sol_bank_forks_new_from_parent(forks, 1, 2);
    sol_bank_forks_new_from_parent(forks, 2, 3);

    sol_fork_choice_t* fc = sol_fork_choice_new(forks, NULL);

    sol_pubkey_t validator;
    memset(validator.bytes, 0x55, 32);

    /* Vote for slot 3 */
    sol_fork_choice_record_vote(fc, &validator, 3, 1000);

    sol_slot_t best = sol_fork_choice_best_slot(fc);
    TEST_ASSERT_EQ(best, 3);

    sol_fork_choice_destroy(fc);
    sol_bank_forks_destroy(forks);
}

TEST(fork_choice_best_slot_multi_fork_subtree) {
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, NULL);
    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);

    /* Create a fork:
     *   0 -> 1 -> 3
     *   0 -> 2 -> 4
     */
    sol_bank_forks_new_from_parent(forks, 0, 1);
    sol_bank_forks_new_from_parent(forks, 1, 3);
    sol_bank_forks_new_from_parent(forks, 0, 2);
    sol_bank_forks_new_from_parent(forks, 2, 4);

    sol_fork_choice_t* fc = sol_fork_choice_new(forks, NULL);

    sol_pubkey_t v1, v2;
    memset(v1.bytes, 0x11, 32);
    memset(v2.bytes, 0x22, 32);

    /* Only vote on leaf slots: intermediate slots have no direct stake */
    sol_fork_choice_record_vote(fc, &v1, 3, 1000);
    sol_fork_choice_record_vote(fc, &v2, 4, 2000);

    /* Heaviest subtree should pick fork ending at slot 4 */
    sol_slot_t best = sol_fork_choice_best_slot(fc);
    TEST_ASSERT_EQ(best, 4);

    /* Subtree weights should propagate through intermediate nodes */
    TEST_ASSERT_EQ(sol_fork_choice_subtree_weight(fc, 1), 1000);
    TEST_ASSERT_EQ(sol_fork_choice_subtree_weight(fc, 2), 2000);

    sol_fork_choice_destroy(fc);
    sol_bank_forks_destroy(forks);
}

TEST(fork_choice_supermajority) {
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, NULL);
    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);

    /* Create chain: 0 -> 5 so that slot 5 exists in forks tree */
    sol_bank_forks_new_from_parent(forks, 0, 5);

    sol_fork_choice_t* fc = sol_fork_choice_new(forks, NULL);

    sol_pubkey_t v1, v2, v3;
    memset(v1.bytes, 0x11, 32);
    memset(v2.bytes, 0x22, 32);
    memset(v3.bytes, 0x33, 32);

    /* 3 validators with 1000 stake each = 3000 total */
    sol_fork_choice_record_vote(fc, &v1, 5, 1000);
    sol_fork_choice_record_vote(fc, &v2, 5, 1000);
    sol_fork_choice_record_vote(fc, &v3, 5, 1000);

    /* Check direct stake weight */
    TEST_ASSERT_EQ(sol_fork_choice_stake_weight(fc, 5), 3000);

    /* Subtree weight should also be 3000 (leaf node) */
    uint64_t subtree = sol_fork_choice_subtree_weight(fc, 5);
    TEST_ASSERT_EQ(subtree, 3000);

    /* 2/3 threshold = 2000 */
    TEST_ASSERT(sol_fork_choice_has_supermajority(fc, 5, 2000));

    /* 3001 threshold - not met */
    TEST_ASSERT(!sol_fork_choice_has_supermajority(fc, 5, 3001));

    sol_fork_choice_destroy(fc);
    sol_bank_forks_destroy(forks);
}

TEST(fork_choice_set_root) {
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, NULL);
    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);
    sol_fork_choice_t* fc = sol_fork_choice_new(forks, NULL);

    sol_pubkey_t validator;
    memset(validator.bytes, 0x66, 32);

    /* Vote for slot before root */
    sol_fork_choice_record_vote(fc, &validator, 5, 1000);
    TEST_ASSERT_EQ(sol_fork_choice_stake_weight(fc, 5), 1000);

    /* Set root to slot 10 */
    sol_fork_choice_set_root(fc, 10);

    /* Vote for slot 5 should be pruned */
    TEST_ASSERT_EQ(sol_fork_choice_stake_weight(fc, 5), 0);

    sol_fork_choice_destroy(fc);
    sol_bank_forks_destroy(forks);
}

/*
 * Replay tests (basic - without full blockstore integration)
 */

TEST(replay_create_destroy) {
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, NULL);
    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);
    sol_blockstore_t* blockstore = sol_blockstore_new(NULL);

    sol_replay_t* replay = sol_replay_new(forks, blockstore, NULL);
    TEST_ASSERT(replay != NULL);

    TEST_ASSERT(sol_replay_bank_forks(replay) == forks);
    TEST_ASSERT(sol_replay_fork_choice(replay) != NULL);
    TEST_ASSERT_EQ(sol_replay_root_slot(replay), 0);

    sol_replay_destroy(replay);
    sol_blockstore_destroy(blockstore);
    sol_bank_forks_destroy(forks);
}

TEST(replay_is_replayed) {
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, NULL);
    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);
    sol_blockstore_t* blockstore = sol_blockstore_new(NULL);

    sol_replay_t* replay = sol_replay_new(forks, blockstore, NULL);

    /* Root should be marked as replayed */
    TEST_ASSERT(sol_replay_is_replayed(replay, 0));
    TEST_ASSERT(!sol_replay_is_replayed(replay, 1));
    TEST_ASSERT(!sol_replay_is_dead(replay, 0));

    sol_replay_destroy(replay);
    sol_blockstore_destroy(blockstore);
    sol_bank_forks_destroy(forks);
}

TEST(replay_record_vote) {
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, NULL);
    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);
    sol_blockstore_t* blockstore = sol_blockstore_new(NULL);

    sol_replay_t* replay = sol_replay_new(forks, blockstore, NULL);

    sol_pubkey_t validator;
    memset(validator.bytes, 0x77, 32);

    sol_err_t err = sol_replay_record_vote(replay, &validator, 5, 1000);
    TEST_ASSERT_EQ(err, SOL_OK);

    sol_fork_choice_t* fc = sol_replay_fork_choice(replay);
    TEST_ASSERT_EQ(sol_fork_choice_latest_vote(fc, &validator), 5);

    sol_replay_destroy(replay);
    sol_blockstore_destroy(blockstore);
    sol_bank_forks_destroy(forks);
}

TEST(replay_get_bank) {
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, NULL);
    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);
    sol_blockstore_t* blockstore = sol_blockstore_new(NULL);

    sol_replay_t* replay = sol_replay_new(forks, blockstore, NULL);

    sol_bank_t* bank = sol_replay_get_bank(replay, 0);
    TEST_ASSERT(bank != NULL);
    TEST_ASSERT_EQ(sol_bank_slot(bank), 0);

    sol_bank_t* missing = sol_replay_get_bank(replay, 99);
    TEST_ASSERT(missing == NULL);

    sol_replay_destroy(replay);
    sol_blockstore_destroy(blockstore);
    sol_bank_forks_destroy(forks);
}

TEST(replay_stats) {
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, NULL);
    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);
    sol_blockstore_t* blockstore = sol_blockstore_new(NULL);

    sol_replay_t* replay = sol_replay_new(forks, blockstore, NULL);

    sol_replay_stats_t stats;
    sol_replay_stats(replay, &stats);

    TEST_ASSERT_EQ(stats.slots_replayed, 0);
    TEST_ASSERT_EQ(stats.slots_dead, 0);
    TEST_ASSERT_EQ(stats.highest_replayed_slot, 0);

    sol_replay_destroy(replay);
    sol_blockstore_destroy(blockstore);
    sol_bank_forks_destroy(forks);
}

TEST(replay_reattempts_when_new_variants_arrive) {
    sol_bank_config_t bank_cfg = SOL_BANK_CONFIG_DEFAULT;
    bank_cfg.ticks_per_slot = 2;
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, &bank_cfg);
    TEST_ASSERT_NOT_NULL(root);

    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);
    TEST_ASSERT_NOT_NULL(forks);

    sol_bank_t* bank1 = sol_bank_forks_new_from_parent(forks, 0, 1);
    TEST_ASSERT_NOT_NULL(bank1);
    /* sol_replay_slot will treat existing banks as replayed; ensure it is complete. */
    sol_hash_t tick_hash = {{1}};
    TEST_ASSERT_EQ(sol_bank_register_tick(bank1, &tick_hash), SOL_OK);
    TEST_ASSERT_EQ(sol_bank_register_tick(bank1, &tick_hash), SOL_OK);

    sol_blockstore_t* blockstore = sol_blockstore_new(NULL);
    TEST_ASSERT_NOT_NULL(blockstore);

    sol_shred_t shred;
    uint8_t raw[1024];
    size_t raw_len = 0;

    for (uint32_t i = 0; i < 3; i++) {
        create_mock_shred(&shred, raw, &raw_len, 1, i, i == 2);
        TEST_ASSERT_EQ(sol_blockstore_insert_shred(blockstore, &shred, raw, raw_len), SOL_OK);
    }

    sol_replay_t* replay = sol_replay_new(forks, blockstore, NULL);
    TEST_ASSERT_NOT_NULL(replay);

    TEST_ASSERT_EQ(sol_replay_slot(replay, 1, NULL), SOL_REPLAY_SUCCESS);
    TEST_ASSERT(sol_replay_is_replayed(replay, 1));

    /* Introduce a new conflicting data shred => new variant */
    sol_shred_t conflict;
    uint8_t raw_conflict[1024];
    size_t raw_conflict_len = 0;
    create_mock_shred(&conflict, raw_conflict, &raw_conflict_len, 1, 0, false);
    raw_conflict[199] ^= 0x5Au;
    TEST_ASSERT_EQ(sol_blockstore_insert_shred(blockstore, &conflict, raw_conflict, raw_conflict_len), SOL_OK);
    TEST_ASSERT_EQ(sol_blockstore_num_variants(blockstore, 1), 2);

    TEST_ASSERT(!sol_replay_is_replayed(replay, 1));
    TEST_ASSERT_EQ(sol_replay_slot(replay, 1, NULL), SOL_REPLAY_DUPLICATE);
    TEST_ASSERT(sol_replay_is_replayed(replay, 1));
    TEST_ASSERT(!sol_replay_is_dead(replay, 1));

    sol_replay_destroy(replay);
    sol_blockstore_destroy(blockstore);
    sol_bank_forks_destroy(forks);
}

TEST(replay_incomplete_ticks_not_dead) {
    sol_bank_config_t bank_cfg = SOL_BANK_CONFIG_DEFAULT;
    bank_cfg.ticks_per_slot = 2;
    bank_cfg.hashes_per_tick = 1;

    sol_bank_t* root = sol_bank_new(0, NULL, NULL, &bank_cfg);
    TEST_ASSERT_NOT_NULL(root);

    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);
    TEST_ASSERT_NOT_NULL(forks);

    sol_blockstore_t* blockstore = sol_blockstore_new(NULL);
    TEST_ASSERT_NOT_NULL(blockstore);

    sol_entry_t entry;
    sol_entry_init(&entry);
    entry.num_hashes = 1;
    entry.num_transactions = 0;

    const sol_hash_t* start_hash = sol_bank_blockhash(root);
    TEST_ASSERT_NOT_NULL(start_hash);
    sol_entry_compute_hash(&entry, start_hash, &entry.hash);

    uint8_t entry_buf[256];
    size_t entry_len = 0;
    TEST_ASSERT_EQ(sol_entry_serialize(&entry, entry_buf, sizeof(entry_buf), &entry_len), SOL_OK);

    uint8_t payload[512];
    size_t payload_len = 0;
    uint64_t entry_count = 1;
    memcpy(payload + payload_len, &entry_count, 8);
    payload_len += 8;
    memcpy(payload + payload_len, entry_buf, entry_len);
    payload_len += entry_len;

    uint8_t raw[1024];
    size_t raw_len = build_mock_legacy_data_shred(raw, sizeof(raw),
                                                  1, 0, 0, 0,
                                                  SOL_SHRED_FLAG_LAST_IN_SLOT,
                                                  payload, payload_len);
    TEST_ASSERT(raw_len > 0);

    sol_shred_t shred;
    TEST_ASSERT_EQ(sol_shred_parse(&shred, raw, raw_len), SOL_OK);
    TEST_ASSERT_EQ(sol_blockstore_insert_shred(blockstore, &shred, raw, raw_len), SOL_OK);
    TEST_ASSERT(sol_blockstore_is_slot_complete(blockstore, 1));

    sol_replay_t* replay = sol_replay_new(forks, blockstore, NULL);
    TEST_ASSERT_NOT_NULL(replay);

    sol_replay_result_t result = sol_replay_slot(replay, 1, NULL);
    TEST_ASSERT_EQ(result, SOL_REPLAY_INCOMPLETE);
    TEST_ASSERT(!sol_replay_is_dead(replay, 1));

    sol_replay_destroy(replay);
    sol_blockstore_destroy(blockstore);
    sol_bank_forks_destroy(forks);
    sol_entry_cleanup(&entry);
}

TEST(replay_start_hash_mismatch_not_dead) {
    sol_bank_config_t bank_cfg = SOL_BANK_CONFIG_DEFAULT;
    bank_cfg.ticks_per_slot = 1;
    bank_cfg.hashes_per_tick = 1;

    sol_bank_t* root = sol_bank_new(0, NULL, NULL, &bank_cfg);
    TEST_ASSERT_NOT_NULL(root);

    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);
    TEST_ASSERT_NOT_NULL(forks);

    sol_blockstore_t* blockstore = sol_blockstore_new(NULL);
    TEST_ASSERT_NOT_NULL(blockstore);

    sol_entry_t entry;
    sol_entry_init(&entry);
    entry.num_hashes = 1;
    entry.num_transactions = 0;

    sol_hash_t fake_start = {{9}};
    sol_entry_compute_hash(&entry, &fake_start, &entry.hash);

    uint8_t entry_buf[256];
    size_t entry_len = 0;
    TEST_ASSERT_EQ(sol_entry_serialize(&entry, entry_buf, sizeof(entry_buf), &entry_len), SOL_OK);

    uint8_t payload[512];
    size_t payload_len = 0;
    uint64_t entry_count = 1;
    memcpy(payload + payload_len, &entry_count, 8);
    payload_len += 8;
    memcpy(payload + payload_len, entry_buf, entry_len);
    payload_len += entry_len;

    uint8_t raw[1024];
    size_t raw_len = build_mock_legacy_data_shred(raw, sizeof(raw),
                                                  1, 0, 0, 0,
                                                  SOL_SHRED_FLAG_LAST_IN_SLOT,
                                                  payload, payload_len);
    TEST_ASSERT(raw_len > 0);

    sol_shred_t shred;
    TEST_ASSERT_EQ(sol_shred_parse(&shred, raw, raw_len), SOL_OK);
    TEST_ASSERT_EQ(sol_blockstore_insert_shred(blockstore, &shred, raw, raw_len), SOL_OK);
    TEST_ASSERT(sol_blockstore_is_slot_complete(blockstore, 1));

    sol_replay_t* replay = sol_replay_new(forks, blockstore, NULL);
    TEST_ASSERT_NOT_NULL(replay);

    sol_replay_result_t result = sol_replay_slot(replay, 1, NULL);
    TEST_ASSERT_EQ(result, SOL_REPLAY_INCOMPLETE);
    TEST_ASSERT(!sol_replay_is_dead(replay, 1));

    sol_replay_destroy(replay);
    sol_blockstore_destroy(blockstore);
    sol_bank_forks_destroy(forks);
    sol_entry_cleanup(&entry);
}

TEST(replay_parent_ready_requires_available_parent) {
    sol_bank_t* root = sol_bank_new(0, NULL, NULL, NULL);
    TEST_ASSERT_NOT_NULL(root);

    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);
    TEST_ASSERT_NOT_NULL(forks);

    sol_blockstore_t* blockstore = sol_blockstore_new(NULL);
    TEST_ASSERT_NOT_NULL(blockstore);

    /* Insert an otherwise complete slot=2 block whose parent slot is 1. */
    sol_shred_t shred;
    uint8_t raw[1024];
    size_t raw_len = 0;
    create_mock_shred(&shred, raw, &raw_len, 2, 0, true);
    TEST_ASSERT_EQ(sol_blockstore_insert_shred(blockstore, &shred, raw, raw_len), SOL_OK);
    TEST_ASSERT(sol_blockstore_is_slot_complete(blockstore, 2));

    sol_replay_t* replay = sol_replay_new(forks, blockstore, NULL);
    TEST_ASSERT_NOT_NULL(replay);

    sol_slot_t parent_slot = 0;
    TEST_ASSERT(!sol_replay_parent_ready(replay, 2, &parent_slot));
    TEST_ASSERT_EQ(parent_slot, 1);

    sol_bank_t* bank1 = sol_bank_forks_new_from_parent(forks, 0, 1);
    TEST_ASSERT_NOT_NULL(bank1);
    TEST_ASSERT_EQ(sol_bank_forks_freeze(forks, 1), SOL_OK);

    TEST_ASSERT(sol_replay_parent_ready(replay, 2, &parent_slot));
    TEST_ASSERT_EQ(parent_slot, 1);

    sol_replay_destroy(replay);
    sol_blockstore_destroy(blockstore);
    sol_bank_forks_destroy(forks);
}

TEST(replay_prewarm_slot_parses_valid_slot) {
    sol_bank_config_t bank_cfg = SOL_BANK_CONFIG_DEFAULT;
    bank_cfg.ticks_per_slot = 1;
    bank_cfg.hashes_per_tick = 1;

    sol_bank_t* root = sol_bank_new(0, NULL, NULL, &bank_cfg);
    TEST_ASSERT_NOT_NULL(root);

    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);
    TEST_ASSERT_NOT_NULL(forks);

    sol_blockstore_t* blockstore = sol_blockstore_new(NULL);
    TEST_ASSERT_NOT_NULL(blockstore);

    sol_entry_t entry;
    sol_entry_init(&entry);
    entry.num_hashes = 1;
    entry.num_transactions = 0;
    const sol_hash_t* start_hash = sol_bank_blockhash(root);
    TEST_ASSERT_NOT_NULL(start_hash);
    sol_entry_compute_hash(&entry, start_hash, &entry.hash);

    uint8_t entry_buf[256];
    size_t entry_len = 0;
    TEST_ASSERT_EQ(sol_entry_serialize(&entry, entry_buf, sizeof(entry_buf), &entry_len), SOL_OK);

    uint8_t payload[512];
    size_t payload_len = 0;
    uint64_t entry_count = 1;
    memcpy(payload + payload_len, &entry_count, 8);
    payload_len += 8;
    memcpy(payload + payload_len, entry_buf, entry_len);
    payload_len += entry_len;

    uint8_t raw[1024];
    size_t raw_len = build_mock_legacy_data_shred(raw, sizeof(raw),
                                                  1, 0, 0, 0,
                                                  SOL_SHRED_FLAG_LAST_IN_SLOT,
                                                  payload, payload_len);
    TEST_ASSERT(raw_len > 0);

    sol_shred_t shred;
    TEST_ASSERT_EQ(sol_shred_parse(&shred, raw, raw_len), SOL_OK);
    TEST_ASSERT_EQ(sol_blockstore_insert_shred(blockstore, &shred, raw, raw_len), SOL_OK);
    TEST_ASSERT(sol_blockstore_is_slot_complete(blockstore, 1));

    sol_replay_t* replay = sol_replay_new(forks, blockstore, NULL);
    TEST_ASSERT_NOT_NULL(replay);
    TEST_ASSERT(sol_replay_prewarm_slot(replay, 1));
    TEST_ASSERT(!sol_replay_prewarm_slot(replay, 999999));

    sol_replay_destroy(replay);
    sol_blockstore_destroy(blockstore);
    sol_bank_forks_destroy(forks);
    sol_entry_cleanup(&entry);
}

/*
 * Null handling tests
 */

TEST(replay_null_handling) {
    sol_bank_forks_destroy(NULL);
    sol_fork_choice_destroy(NULL);
    sol_replay_destroy(NULL);

    TEST_ASSERT_EQ(sol_bank_forks_count(NULL), 0);
    TEST_ASSERT_EQ(sol_bank_forks_root_slot(NULL), 0);
    TEST_ASSERT(sol_bank_forks_get(NULL, 0) == NULL);

    TEST_ASSERT_EQ(sol_fork_choice_voter_count(NULL), 0);
    TEST_ASSERT_EQ(sol_fork_choice_total_stake(NULL), 0);

    TEST_ASSERT_EQ(sol_replay_root_slot(NULL), 0);
    TEST_ASSERT(sol_replay_get_bank(NULL, 0) == NULL);
}

/*
 * Test runner
 */
static test_case_t replay_tests[] = {
    /* Bank forks tests */
    TEST_CASE(bank_forks_create_destroy),
    TEST_CASE(bank_forks_get_root),
    TEST_CASE(bank_forks_new_from_parent),
    TEST_CASE(bank_forks_get_bank),
    TEST_CASE(bank_forks_contains),
    TEST_CASE(bank_forks_freeze),
    TEST_CASE(bank_forks_set_root),
    TEST_CASE(bank_forks_set_root_hash_prunes_duplicate_slot),
    TEST_CASE(bank_forks_highest_slot),
    TEST_CASE(bank_forks_mark_dead),
    /* Fork choice tests */
    TEST_CASE(fork_choice_create_destroy),
    TEST_CASE(fork_choice_record_vote),
    TEST_CASE(fork_choice_update_vote),
    TEST_CASE(fork_choice_latest_vote),
    TEST_CASE(fork_choice_best_slot_single_fork),
    TEST_CASE(fork_choice_best_slot_multi_fork_subtree),
    TEST_CASE(fork_choice_supermajority),
    TEST_CASE(fork_choice_set_root),
    /* Replay tests */
    TEST_CASE(replay_create_destroy),
    TEST_CASE(replay_is_replayed),
    TEST_CASE(replay_record_vote),
    TEST_CASE(replay_get_bank),
    TEST_CASE(replay_stats),
    TEST_CASE(replay_reattempts_when_new_variants_arrive),
    TEST_CASE(replay_incomplete_ticks_not_dead),
    TEST_CASE(replay_start_hash_mismatch_not_dead),
    TEST_CASE(replay_parent_ready_requires_available_parent),
    TEST_CASE(replay_prewarm_slot_parses_valid_slot),
    /* Null handling */
    TEST_CASE(replay_null_handling),
};

int main(void) {
    int result = RUN_TESTS("Replay Tests", replay_tests);
    sol_alloc_dump_leaks();
    return result;
}
