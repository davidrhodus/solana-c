/*
 * test_turbine.c - Turbine module unit tests
 */

#include "../test_framework.h"
#include "sol_turbine.h"
#include "sol_alloc.h"
#include "sol_log.h"
#include "sol_ed25519.h"
#include <string.h>

/*
 * Helper to create test nodes
 */
static void
create_test_nodes(sol_turbine_node_t* nodes, size_t num_nodes) {
    for (size_t i = 0; i < num_nodes; i++) {
        memset(&nodes[i].pubkey, (uint8_t)i, sizeof(sol_pubkey_t));
        sol_sockaddr_init(&nodes[i].tvu_addr, "127.0.0.1", 8000 + (uint16_t)i);
        nodes[i].stake = 1;
        nodes[i].index = (uint32_t)i;
    }
}

/*
 * Turbine tree tests
 */

TEST(turbine_tree_create_destroy) {
    sol_turbine_node_t nodes[10];
    create_test_nodes(nodes, 10);

    sol_pubkey_t leader;
    memset(&leader, 0xFF, sizeof(leader));

    /* We are node 0 */
    sol_turbine_tree_t* tree = sol_turbine_tree_new(
        1000, &leader, nodes, 10, &nodes[0].pubkey, 200);

    TEST_ASSERT(tree != NULL);
    TEST_ASSERT_EQ(tree->slot, 1000);
    TEST_ASSERT_EQ(tree->num_nodes, 10);
    TEST_ASSERT_EQ(tree->fanout, 200);

    sol_turbine_tree_destroy(tree);
}

TEST(turbine_tree_root_node) {
    sol_turbine_node_t nodes[10];
    create_test_nodes(nodes, 10);

    sol_pubkey_t leader;
    memset(&leader, 0xFF, sizeof(leader));

    /* Set high stake for node 0 to ensure it's shuffled to front */
    nodes[0].stake = 1000;

    sol_turbine_tree_t* tree = sol_turbine_tree_new(
        1000, &leader, nodes, 10, &nodes[0].pubkey, 200);

    TEST_ASSERT(tree != NULL);

    /* With high stake, node 0 should be near root (depth 0 or 1) */
    uint32_t depth = sol_turbine_tree_depth(tree);
    TEST_ASSERT(depth <= 1);

    sol_turbine_tree_destroy(tree);
}

TEST(turbine_tree_children) {
    sol_turbine_node_t nodes[20];
    create_test_nodes(nodes, 20);

    sol_pubkey_t leader;
    memset(&leader, 0xFF, sizeof(leader));

    /* Use small fanout so we have multiple levels */
    sol_turbine_tree_t* tree = sol_turbine_tree_new(
        1000, &leader, nodes, 20, &nodes[0].pubkey, 3);

    TEST_ASSERT(tree != NULL);

    /* Get children */
    const sol_turbine_node_t* children[10];
    size_t num_children = sol_turbine_tree_children(tree, children, 10);

    /* Should have children if not at leaf level */
    sol_log_debug("Tree depth: %u, num_children: %zu", tree->depth, num_children);

    sol_turbine_tree_destroy(tree);
}

TEST(turbine_tree_parent) {
    sol_turbine_node_t nodes[10];
    create_test_nodes(nodes, 10);

    sol_pubkey_t leader;
    memset(&leader, 0xFF, sizeof(leader));

    /* Use node 5 to test non-root case */
    sol_turbine_tree_t* tree = sol_turbine_tree_new(
        1000, &leader, nodes, 10, &nodes[5].pubkey, 3);

    TEST_ASSERT(tree != NULL);

    const sol_turbine_node_t* parent = sol_turbine_tree_parent(tree);

    /* Should have a parent (unless shuffled to root) */
    if (tree->depth > 0) {
        TEST_ASSERT(parent != NULL);
    }

    sol_turbine_tree_destroy(tree);
}

/*
 * Weighted shuffle tests
 */

TEST(turbine_weighted_shuffle_deterministic) {
    sol_turbine_node_t nodes1[10];
    sol_turbine_node_t nodes2[10];

    create_test_nodes(nodes1, 10);
    create_test_nodes(nodes2, 10);

    /* Same slot should give same shuffle */
    sol_pubkey_t leader;
    memset(&leader, 0xFF, sizeof(leader));
    sol_turbine_weighted_shuffle(nodes1, 10, 12345, &leader);
    sol_turbine_weighted_shuffle(nodes2, 10, 12345, &leader);

    for (size_t i = 0; i < 10; i++) {
        TEST_ASSERT(sol_pubkey_eq(&nodes1[i].pubkey, &nodes2[i].pubkey));
    }
}

TEST(turbine_weighted_shuffle_different_slots) {
    sol_turbine_node_t nodes1[10];
    sol_turbine_node_t nodes2[10];

    create_test_nodes(nodes1, 10);
    create_test_nodes(nodes2, 10);

    /* Different slots should give different shuffles */
    sol_pubkey_t leader;
    memset(&leader, 0xFF, sizeof(leader));
    sol_turbine_weighted_shuffle(nodes1, 10, 12345, &leader);
    sol_turbine_weighted_shuffle(nodes2, 10, 12346, &leader);

    bool different = false;
    for (size_t i = 0; i < 10; i++) {
        if (!sol_pubkey_eq(&nodes1[i].pubkey, &nodes2[i].pubkey)) {
            different = true;
            break;
        }
    }
    TEST_ASSERT(different);
}

TEST(turbine_weighted_shuffle_stake) {
    sol_turbine_node_t nodes[10];
    create_test_nodes(nodes, 10);

    /* Give node 9 very high stake */
    nodes[9].stake = 10000;

    sol_pubkey_t leader;
    memset(&leader, 0xFF, sizeof(leader));
    sol_turbine_weighted_shuffle(nodes, 10, 42, &leader);

    /* Node 9 should be near the front more often than not */
    /* Find where node 9 ended up */
    size_t node9_pos = 0;
    for (size_t i = 0; i < 10; i++) {
        if (nodes[i].pubkey.bytes[0] == 9) {
            node9_pos = i;
            break;
        }
    }

    /* With high stake, should be in first half */
    TEST_ASSERT(node9_pos < 5);
}

TEST(turbine_tree_leader_is_root) {
    sol_turbine_node_t nodes[10];
    create_test_nodes(nodes, 10);

    sol_pubkey_t leader = nodes[3].pubkey;

    sol_turbine_tree_t* tree = sol_turbine_tree_new(
        1000, &leader, nodes, 10, &nodes[0].pubkey, 3);
    TEST_ASSERT(tree != NULL);
    TEST_ASSERT(sol_pubkey_eq(&tree->nodes[0].pubkey, &leader));

    sol_turbine_tree_destroy(tree);
}

/*
 * Retransmit slot tests
 */

TEST(retransmit_slot_create_destroy) {
    sol_retransmit_slot_t* state = sol_retransmit_slot_new(1000);
    TEST_ASSERT(state != NULL);
    TEST_ASSERT_EQ(state->slot, 1000);
    TEST_ASSERT(!state->complete);

    sol_retransmit_slot_destroy(state);
}

TEST(retransmit_slot_record) {
    sol_retransmit_slot_t* state = sol_retransmit_slot_new(1000);
    TEST_ASSERT(state != NULL);

    /* Create a mock shred */
    sol_shred_t shred;
    memset(&shred, 0, sizeof(shred));
    shred.slot = 1000;
    shred.index = 5;
    shred.type = SOL_SHRED_TYPE_DATA;

    /* First record should succeed */
    bool is_new = sol_retransmit_slot_record(state, &shred);
    TEST_ASSERT(is_new);

    /* Second record of same shred should return false (duplicate) */
    is_new = sol_retransmit_slot_record(state, &shred);
    TEST_ASSERT(!is_new);

    sol_retransmit_slot_destroy(state);
}

TEST(retransmit_slot_record_many) {
    sol_retransmit_slot_t* state = sol_retransmit_slot_new(1000);
    TEST_ASSERT(state != NULL);

    /* Record many shreds */
    for (uint32_t i = 0; i < 1000; i++) {
        sol_shred_t shred;
        memset(&shred, 0, sizeof(shred));
        shred.slot = 1000;
        shred.index = i;
        shred.type = SOL_SHRED_TYPE_DATA;

        bool is_new = sol_retransmit_slot_record(state, &shred);
        TEST_ASSERT(is_new);
    }

    /* All should be marked as received */
    for (uint32_t i = 0; i < 1000; i++) {
        sol_shred_t shred;
        memset(&shred, 0, sizeof(shred));
        shred.slot = 1000;
        shred.index = i;
        shred.type = SOL_SHRED_TYPE_DATA;

        bool is_new = sol_retransmit_slot_record(state, &shred);
        TEST_ASSERT(!is_new);
    }

    sol_retransmit_slot_destroy(state);
}

TEST(retransmit_slot_missing) {
    sol_retransmit_slot_t* state = sol_retransmit_slot_new(1000);
    TEST_ASSERT(state != NULL);

    /* Record some shreds with gaps */
    uint32_t recorded[] = {0, 1, 3, 4, 7, 8, 9};
    for (size_t i = 0; i < sizeof(recorded)/sizeof(recorded[0]); i++) {
        sol_shred_t shred;
        memset(&shred, 0, sizeof(shred));
        shred.slot = 1000;
        shred.index = recorded[i];
        shred.type = SOL_SHRED_TYPE_DATA;

        /* Mark last one as complete */
        if (recorded[i] == 9) {
            shred.header.data.flags = SOL_SHRED_FLAG_DATA_COMPLETE;
        }

        sol_retransmit_slot_record(state, &shred);
    }

    /* Get missing */
    uint32_t missing[10];
    size_t num_missing = sol_retransmit_slot_missing(state, missing, 10, true);

    /* Should be missing 2, 5, 6 */
    TEST_ASSERT_EQ(num_missing, 3);
    TEST_ASSERT_EQ(missing[0], 2);
    TEST_ASSERT_EQ(missing[1], 5);
    TEST_ASSERT_EQ(missing[2], 6);

    sol_retransmit_slot_destroy(state);
}

TEST(retransmit_slot_complete) {
    sol_retransmit_slot_t* state = sol_retransmit_slot_new(1000);
    TEST_ASSERT(state != NULL);

    /* Record all shreds 0-9 */
    for (uint32_t i = 0; i <= 9; i++) {
        sol_shred_t shred;
        memset(&shred, 0, sizeof(shred));
        shred.slot = 1000;
        shred.index = i;
        shred.type = SOL_SHRED_TYPE_DATA;

        /* Mark last one as complete */
        if (i == 9) {
            shred.header.data.flags = SOL_SHRED_FLAG_DATA_COMPLETE;
        }

        sol_retransmit_slot_record(state, &shred);
    }

    /* Should be complete */
    TEST_ASSERT(sol_retransmit_slot_is_complete(state));

    sol_retransmit_slot_destroy(state);
}

/*
 * Turbine service tests
 */

TEST(turbine_create_destroy) {
    sol_turbine_config_t config = SOL_TURBINE_CONFIG_DEFAULT;

    sol_pubkey_t self;
    sol_pubkey_init(&self);

    sol_turbine_t* turbine = sol_turbine_new(&config, NULL, &self);
    TEST_ASSERT(turbine != NULL);

    sol_turbine_destroy(turbine);
}

TEST(turbine_stats) {
    sol_turbine_config_t config = SOL_TURBINE_CONFIG_DEFAULT;

    sol_pubkey_t self;
    sol_pubkey_init(&self);

    sol_turbine_t* turbine = sol_turbine_new(&config, NULL, &self);
    TEST_ASSERT(turbine != NULL);

    sol_turbine_stats_t stats;
    sol_turbine_stats(turbine, &stats);

    TEST_ASSERT_EQ(stats.shreds_received, 0);
    TEST_ASSERT_EQ(stats.slots_completed, 0);

    sol_turbine_destroy(turbine);
}

/*
 * Test runner
 */
static test_case_t turbine_tests[] = {
    TEST_CASE(turbine_tree_create_destroy),
    TEST_CASE(turbine_tree_root_node),
    TEST_CASE(turbine_tree_children),
    TEST_CASE(turbine_tree_parent),
    TEST_CASE(turbine_tree_leader_is_root),
    TEST_CASE(turbine_weighted_shuffle_deterministic),
    TEST_CASE(turbine_weighted_shuffle_different_slots),
    TEST_CASE(turbine_weighted_shuffle_stake),
    TEST_CASE(retransmit_slot_create_destroy),
    TEST_CASE(retransmit_slot_record),
    TEST_CASE(retransmit_slot_record_many),
    TEST_CASE(retransmit_slot_missing),
    TEST_CASE(retransmit_slot_complete),
    TEST_CASE(turbine_create_destroy),
    TEST_CASE(turbine_stats),
};

int main(void) {
    int result = RUN_TESTS("Turbine Tests", turbine_tests);
    sol_alloc_dump_leaks();
    return result;
}
