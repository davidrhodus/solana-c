/*
 * test_tpu.c - Tests for Transaction Processing Unit
 *
 * Tests for:
 *   - Dedup filter
 *   - TPU service
 *   - Sigverify service (parallel signature verification)
 *   - Compute Budget and Cost Model
 *   - Banking Stage (transaction batching)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../src/tpu/sol_tpu.h"
#include "../src/tpu/sol_sigverify.h"
#include "../src/tpu/sol_banking_stage.h"
#include "../src/runtime/sol_compute_budget.h"
#include "../src/util/sol_alloc.h"
#include "../src/crypto/sol_ed25519.h"
#include "../src/txn/sol_bincode.h"
#include "../src/txn/sol_message.h"

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
 * ====================
 * Dedup Filter Tests
 * ====================
 */

TEST(dedup_filter_new) {
    sol_dedup_filter_t* filter = sol_dedup_filter_new(1000);
    ASSERT(filter != NULL);
    ASSERT(sol_dedup_filter_size(filter) == 0);
    sol_dedup_filter_destroy(filter);
}

TEST(dedup_filter_check) {
    sol_dedup_filter_t* filter = sol_dedup_filter_new(1000);
    ASSERT(filter != NULL);

    sol_signature_t sig1 = {0};
    sig1.bytes[0] = 1;
    sol_signature_t sig2 = {0};
    sig2.bytes[0] = 2;

    /* First check should return false (not duplicate) */
    ASSERT(sol_dedup_filter_check(filter, &sig1) == false);
    ASSERT(sol_dedup_filter_size(filter) == 1);

    /* Second check of same signature should return true (duplicate) */
    ASSERT(sol_dedup_filter_check(filter, &sig1) == true);
    ASSERT(sol_dedup_filter_size(filter) == 1);

    /* Different signature should return false */
    ASSERT(sol_dedup_filter_check(filter, &sig2) == false);
    ASSERT(sol_dedup_filter_size(filter) == 2);

    sol_dedup_filter_destroy(filter);
}

TEST(dedup_filter_many) {
    sol_dedup_filter_t* filter = sol_dedup_filter_new(10000);
    ASSERT(filter != NULL);

    /* Add 1000 unique signatures */
    for (int i = 0; i < 1000; i++) {
        sol_signature_t sig = {0};
        memcpy(sig.bytes, &i, sizeof(i));
        ASSERT(sol_dedup_filter_check(filter, &sig) == false);
    }

    ASSERT(sol_dedup_filter_size(filter) == 1000);

    /* All should now be duplicates */
    for (int i = 0; i < 1000; i++) {
        sol_signature_t sig = {0};
        memcpy(sig.bytes, &i, sizeof(i));
        ASSERT(sol_dedup_filter_check(filter, &sig) == true);
    }

    sol_dedup_filter_destroy(filter);
}

/*
 * ====================
 * TPU Tests
 * ====================
 */

TEST(tpu_new) {
    sol_tpu_config_t config = SOL_TPU_CONFIG_DEFAULT;
    sol_tpu_t* tpu = sol_tpu_new(NULL, &config);
    ASSERT(tpu != NULL);
    ASSERT(sol_tpu_is_running(tpu) == false);
    sol_tpu_destroy(tpu);
}

TEST(tpu_default_config) {
    sol_tpu_t* tpu = sol_tpu_new(NULL, NULL);
    ASSERT(tpu != NULL);
    sol_tpu_destroy(tpu);
}

TEST(tpu_stats) {
    sol_tpu_config_t config = SOL_TPU_CONFIG_DEFAULT;
    sol_tpu_t* tpu = sol_tpu_new(NULL, &config);
    ASSERT(tpu != NULL);

    sol_tpu_stats_t stats = sol_tpu_stats(tpu);
    ASSERT(stats.packets_received == 0);
    ASSERT(stats.transactions_received == 0);
    ASSERT(stats.signatures_verified == 0);

    sol_tpu_destroy(tpu);
}

TEST(tpu_start_stop_no_net) {
    sol_tpu_config_t config = SOL_TPU_CONFIG_DEFAULT;
    config.enable_udp = false;
    config.enable_quic = false;
    config.sigverify_threads = 2;
    config.banking_threads = 2;

    sol_tpu_t* tpu = sol_tpu_new(NULL, &config);
    ASSERT(tpu != NULL);

    sol_err_t err = sol_tpu_start(tpu);
    ASSERT(err == SOL_OK);
    ASSERT(sol_tpu_is_running(tpu) == true);

    err = sol_tpu_stop(tpu);
    ASSERT(err == SOL_OK);
    ASSERT(sol_tpu_is_running(tpu) == false);

    sol_tpu_destroy(tpu);
}

TEST(tpu_submit_forwards_to_leader_udp) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT(fd >= 0);

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind_addr.sin_port = htons(0); /* ephemeral */

    ASSERT(bind(fd, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) == 0);

    socklen_t addrlen = sizeof(bind_addr);
    ASSERT(getsockname(fd, (struct sockaddr*)&bind_addr, &addrlen) == 0);
    uint16_t leader_port = ntohs(bind_addr.sin_port);

    sol_keypair_t kp;
    ASSERT(sol_ed25519_keypair_generate(&kp) == SOL_OK);
    sol_pubkey_t pk;
    sol_ed25519_pubkey_from_keypair(&kp, &pk);

    /* Build minimal legacy message: 1 signer, 1 key, 0 instructions */
    sol_message_t msg;
    sol_message_init(&msg);
    msg.version = SOL_MESSAGE_VERSION_LEGACY;
    msg.header.num_required_signatures = 1;
    msg.header.num_readonly_signed = 0;
    msg.header.num_readonly_unsigned = 0;

    sol_pubkey_t keys[1];
    keys[0] = pk;
    msg.account_keys = keys;
    msg.account_keys_len = 1;
    msg.resolved_accounts = keys;
    msg.resolved_accounts_len = 1;

    memset(&msg.recent_blockhash, 0, sizeof(msg.recent_blockhash));

    sol_compiled_instruction_t ix;
    memset(&ix, 0, sizeof(ix));
    ix.program_id_index = 0;
    ix.account_indices = NULL;
    ix.account_indices_len = 0;
    ix.data = NULL;
    ix.data_len = 0;

    msg.instructions = &ix;
    msg.instructions_len = 1;
    msg.address_lookups = NULL;
    msg.address_lookups_len = 0;

    uint8_t msg_bytes[256];
    sol_encoder_t enc;
    sol_encoder_init(&enc, msg_bytes, sizeof(msg_bytes));
    ASSERT(sol_message_encode_legacy(&enc, &msg) == SOL_OK);
    size_t msg_len = sol_encoder_len(&enc);
    ASSERT(msg_len > 0);

    sol_signature_t sig;
    sol_ed25519_sign(&kp, msg_bytes, msg_len, &sig);

    sol_transaction_t tx;
    sol_transaction_init(&tx);
    tx.signatures = &sig;
    tx.signatures_len = 1;
    tx.message = msg;
    tx.message_data = msg_bytes;
    tx.message_data_len = msg_len;

    uint8_t tx_bytes[SOL_MAX_TX_SIZE];
    size_t tx_len = 0;
    ASSERT(sol_transaction_encode(&tx, tx_bytes, sizeof(tx_bytes), &tx_len) == SOL_OK);
    ASSERT(tx_len > 0);

    sol_tpu_config_t config = SOL_TPU_CONFIG_DEFAULT;
    config.base_port = 0;     /* bind ephemeral */
    config.enable_quic = false;
    config.sigverify_threads = 1;
    config.banking_threads = 1;
    sol_tpu_t* tpu = sol_tpu_new(NULL, &config);
    ASSERT(tpu != NULL);
    ASSERT(sol_tpu_start(tpu) == SOL_OK);

    uint32_t leader_addr = inet_addr("127.0.0.1");
    ASSERT(leader_addr != INADDR_NONE);
    ASSERT(sol_tpu_set_leader_mode(tpu, false, leader_addr, leader_port) == SOL_OK);

    ASSERT(sol_tpu_submit_raw(tpu, tx_bytes, tx_len) == SOL_OK);

    struct pollfd pfd = {
        .fd = fd,
        .events = POLLIN,
        .revents = 0,
    };
    int pr = poll(&pfd, 1, 2000);
    ASSERT(pr > 0);
    ASSERT((pfd.revents & POLLIN) != 0);

    uint8_t recv_buf[SOL_MAX_TX_SIZE];
    ssize_t n = recv(fd, recv_buf, sizeof(recv_buf), 0);
    ASSERT(n > 0);

    sol_transaction_t rx;
    sol_transaction_init(&rx);
    ASSERT(sol_transaction_decode(recv_buf, (size_t)n, &rx) == SOL_OK);
    ASSERT(sol_sigverify_transaction(&rx) == true);

    sol_tpu_stop(tpu);
    sol_tpu_destroy(tpu);
    close(fd);
}

TEST(tpu_submit_vote_forwards_to_vote_port) {
    int tx_fd = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT(tx_fd >= 0);

    struct sockaddr_in tx_bind_addr;
    memset(&tx_bind_addr, 0, sizeof(tx_bind_addr));
    tx_bind_addr.sin_family = AF_INET;
    tx_bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    tx_bind_addr.sin_port = htons(0); /* ephemeral */

    ASSERT(bind(tx_fd, (struct sockaddr*)&tx_bind_addr, sizeof(tx_bind_addr)) == 0);

    socklen_t tx_addrlen = sizeof(tx_bind_addr);
    ASSERT(getsockname(tx_fd, (struct sockaddr*)&tx_bind_addr, &tx_addrlen) == 0);
    uint16_t leader_tx_port = ntohs(tx_bind_addr.sin_port);

    int vote_fd = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT(vote_fd >= 0);

    struct sockaddr_in vote_bind_addr;
    memset(&vote_bind_addr, 0, sizeof(vote_bind_addr));
    vote_bind_addr.sin_family = AF_INET;
    vote_bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    vote_bind_addr.sin_port = htons(0); /* ephemeral */

    ASSERT(bind(vote_fd, (struct sockaddr*)&vote_bind_addr, sizeof(vote_bind_addr)) == 0);

    socklen_t vote_addrlen = sizeof(vote_bind_addr);
    ASSERT(getsockname(vote_fd, (struct sockaddr*)&vote_bind_addr, &vote_addrlen) == 0);
    uint16_t leader_vote_port = ntohs(vote_bind_addr.sin_port);

    sol_keypair_t kp;
    ASSERT(sol_ed25519_keypair_generate(&kp) == SOL_OK);
    sol_pubkey_t pk;
    sol_ed25519_pubkey_from_keypair(&kp, &pk);

    sol_message_t msg;
    sol_message_init(&msg);
    msg.version = SOL_MESSAGE_VERSION_LEGACY;
    msg.header.num_required_signatures = 1;
    msg.header.num_readonly_signed = 0;
    msg.header.num_readonly_unsigned = 0;

    sol_pubkey_t keys[1];
    keys[0] = pk;
    msg.account_keys = keys;
    msg.account_keys_len = 1;
    msg.resolved_accounts = keys;
    msg.resolved_accounts_len = 1;

    memset(&msg.recent_blockhash, 0, sizeof(msg.recent_blockhash));

    sol_compiled_instruction_t ix;
    memset(&ix, 0, sizeof(ix));
    ix.program_id_index = 0;
    ix.account_indices = NULL;
    ix.account_indices_len = 0;
    ix.data = NULL;
    ix.data_len = 0;

    msg.instructions = &ix;
    msg.instructions_len = 1;
    msg.address_lookups = NULL;
    msg.address_lookups_len = 0;

    uint8_t msg_bytes[256];
    sol_encoder_t enc;
    sol_encoder_init(&enc, msg_bytes, sizeof(msg_bytes));
    ASSERT(sol_message_encode_legacy(&enc, &msg) == SOL_OK);
    size_t msg_len = sol_encoder_len(&enc);
    ASSERT(msg_len > 0);

    sol_signature_t sig;
    sol_ed25519_sign(&kp, msg_bytes, msg_len, &sig);

    sol_transaction_t tx;
    sol_transaction_init(&tx);
    tx.signatures = &sig;
    tx.signatures_len = 1;
    tx.message = msg;
    tx.message_data = msg_bytes;
    tx.message_data_len = msg_len;

    uint8_t tx_bytes[SOL_MAX_TX_SIZE];
    size_t tx_len = 0;
    ASSERT(sol_transaction_encode(&tx, tx_bytes, sizeof(tx_bytes), &tx_len) == SOL_OK);
    ASSERT(tx_len > 0);

    sol_tpu_config_t config = SOL_TPU_CONFIG_DEFAULT;
    config.base_port = 0;     /* bind ephemeral */
    config.enable_quic = false;
    config.sigverify_threads = 1;
    config.banking_threads = 1;
    sol_tpu_t* tpu = sol_tpu_new(NULL, &config);
    ASSERT(tpu != NULL);
    ASSERT(sol_tpu_start(tpu) == SOL_OK);

    uint32_t leader_addr = inet_addr("127.0.0.1");
    ASSERT(leader_addr != INADDR_NONE);
    ASSERT(sol_tpu_set_leader_mode(tpu, false, leader_addr, leader_tx_port) == SOL_OK);
    ASSERT(sol_tpu_set_vote_forwarding_target(tpu, leader_addr, leader_vote_port) == SOL_OK);

    ASSERT(sol_tpu_submit_vote_raw(tpu, tx_bytes, tx_len) == SOL_OK);

    struct pollfd pfd = {
        .fd = vote_fd,
        .events = POLLIN,
        .revents = 0,
    };
    int pr = poll(&pfd, 1, 2000);
    ASSERT(pr > 0);
    ASSERT((pfd.revents & POLLIN) != 0);

    uint8_t recv_buf[SOL_MAX_TX_SIZE];
    ssize_t n = recv(vote_fd, recv_buf, sizeof(recv_buf), 0);
    ASSERT(n > 0);

    sol_transaction_t rx;
    sol_transaction_init(&rx);
    ASSERT(sol_transaction_decode(recv_buf, (size_t)n, &rx) == SOL_OK);
    ASSERT(sol_sigverify_transaction(&rx) == true);

    /* Ensure we didn't accidentally send to the non-vote port. */
    struct pollfd tx_pfd = {
        .fd = tx_fd,
        .events = POLLIN,
        .revents = 0,
    };
    ASSERT(poll(&tx_pfd, 1, 0) == 0);

    sol_tpu_stop(tpu);
    sol_tpu_destroy(tpu);
    close(vote_fd);
    close(tx_fd);
}

/*
 * ====================
 * Compute Budget Tests
 * ====================
 */

TEST(compute_budget_init) {
    sol_compute_budget_t budget;
    sol_compute_budget_init(&budget);

    ASSERT(budget.compute_unit_limit == SOL_DEFAULT_COMPUTE_UNITS);
    ASSERT(budget.compute_unit_price == 0);
    ASSERT(budget.heap_size == SOL_DEFAULT_HEAP_BYTES);
    ASSERT(budget.uses_request_heap_frame == false);
}

TEST(compute_budget_parse_modern_instructions) {
    sol_transaction_t tx;
    sol_transaction_init(&tx);

    sol_pubkey_t keys[] = { SOL_COMPUTE_BUDGET_ID };
    tx.message.account_keys = keys;
    tx.message.account_keys_len = 1;

    uint8_t heap_data[5] = {1, 0, 0, 0, 0};
    uint32_t heap_bytes = 64 * 1024;
    memcpy(heap_data + 1, &heap_bytes, 4);

    uint8_t limit_data[5] = {2, 0, 0, 0, 0};
    uint32_t limit = 500000;
    memcpy(limit_data + 1, &limit, 4);

    uint8_t price_data[9] = {3, 0, 0, 0, 0, 0, 0, 0, 0};
    uint64_t price = 1234;
    memcpy(price_data + 1, &price, 8);

    uint8_t loaded_data[5] = {4, 0, 0, 0, 0};
    uint32_t loaded_bytes = 123456;
    memcpy(loaded_data + 1, &loaded_bytes, 4);

    sol_compiled_instruction_t ix[4] = {0};
    ix[0].program_id_index = 0;
    ix[0].data = heap_data;
    ix[0].data_len = (uint16_t)sizeof(heap_data);

    ix[1].program_id_index = 0;
    ix[1].data = limit_data;
    ix[1].data_len = (uint16_t)sizeof(limit_data);

    ix[2].program_id_index = 0;
    ix[2].data = price_data;
    ix[2].data_len = (uint16_t)sizeof(price_data);

    ix[3].program_id_index = 0;
    ix[3].data = loaded_data;
    ix[3].data_len = (uint16_t)sizeof(loaded_data);

    tx.message.instructions = ix;
    tx.message.instructions_len = 4;

    sol_compute_budget_t budget;
    sol_err_t err = sol_compute_budget_parse(&budget, &tx);
    ASSERT(err == SOL_OK);

    ASSERT(budget.heap_size == heap_bytes);
    ASSERT(budget.uses_request_heap_frame == true);
    ASSERT(budget.compute_unit_limit == limit);
    ASSERT(budget.compute_unit_price == price);
    ASSERT(budget.loaded_accounts_data_size == loaded_bytes);
}

TEST(compute_budget_parse_request_units_deprecated) {
    sol_transaction_t tx;
    sol_transaction_init(&tx);

    sol_pubkey_t keys[] = { SOL_COMPUTE_BUDGET_ID };
    tx.message.account_keys = keys;
    tx.message.account_keys_len = 1;

    uint8_t data[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint32_t units = 200000;
    uint32_t additional_fee = 400; /* lamports */
    memcpy(data + 1, &units, 4);
    memcpy(data + 5, &additional_fee, 4);

    sol_compiled_instruction_t ix = {0};
    ix.program_id_index = 0;
    ix.data = data;
    ix.data_len = (uint16_t)sizeof(data);

    tx.message.instructions = &ix;
    tx.message.instructions_len = 1;

    sol_compute_budget_t budget;
    sol_err_t err = sol_compute_budget_parse(&budget, &tx);
    ASSERT(err == SOL_OK);

    ASSERT(budget.compute_unit_limit == units);
    ASSERT(budget.compute_unit_price == 2000); /* 400 lamports over 200k CUs */
    ASSERT(sol_compute_budget_priority_fee(&budget) == additional_fee);
}

TEST(compute_budget_priority_fee) {
    sol_compute_budget_t budget;
    sol_compute_budget_init(&budget);

    /* Default budget, no priority */
    uint64_t fee = sol_compute_budget_priority_fee(&budget);
    ASSERT(fee == 0);

    /* Set price (micro-lamports per CU) */
    budget.compute_unit_price = 1000;  /* 1000 micro-lamports per CU */
    budget.compute_unit_limit = 200000;

    /* Fee = 200000 * 1000 / 1,000,000 = 200 lamports */
    fee = sol_compute_budget_priority_fee(&budget);
    ASSERT(fee == 200);
}

TEST(compute_meter_init) {
    sol_compute_meter_t meter;
    sol_compute_meter_init(&meter, 1000000);

    ASSERT(meter.limit == 1000000);
    ASSERT(meter.remaining == 1000000);
    ASSERT(meter.consumed == 0);
}

TEST(compute_meter_consume) {
    sol_compute_meter_t meter;
    sol_compute_meter_init(&meter, 1000);

    /* Consume some units */
    sol_err_t err = sol_compute_meter_consume(&meter, 100);
    ASSERT(err == SOL_OK);
    ASSERT(meter.remaining == 900);
    ASSERT(meter.consumed == 100);

    /* Consume more */
    err = sol_compute_meter_consume(&meter, 500);
    ASSERT(err == SOL_OK);
    ASSERT(meter.remaining == 400);
    ASSERT(meter.consumed == 600);

    /* Try to consume too much */
    err = sol_compute_meter_consume(&meter, 500);
    ASSERT(err == SOL_ERR_PROGRAM_COMPUTE);
    ASSERT(meter.remaining == 0);
}

TEST(compute_meter_check) {
    sol_compute_meter_t meter;
    sol_compute_meter_init(&meter, 100);

    ASSERT(sol_compute_meter_check(&meter, 50) == true);
    ASSERT(sol_compute_meter_check(&meter, 100) == true);
    ASSERT(sol_compute_meter_check(&meter, 101) == false);

    sol_compute_meter_consume(&meter, 60);
    ASSERT(sol_compute_meter_check(&meter, 40) == true);
    ASSERT(sol_compute_meter_check(&meter, 41) == false);
}

TEST(cost_model_init) {
    sol_cost_model_t model;
    sol_cost_model_init(&model, NULL);

    ASSERT(model.block_cost == 0);
    ASSERT(model.vote_cost == 0);
    ASSERT(model.config.max_block_units == 48000000);  /* Default block limit */
    ASSERT(model.config.signature_cost == SOL_CU_PER_SIGNATURE);
}

TEST(cost_model_custom_config) {
    sol_cost_model_config_t config = {
        .max_block_units = 1000000,
        .max_vote_units = 500000,
        .max_writable_accounts = 100,
        .max_account_data_bytes = 64 * 1024 * 1024,
        .signature_cost = 200,
        .write_lock_cost = 50,
        .data_byte_cost = 1
    };

    sol_cost_model_t model;
    sol_cost_model_init(&model, &config);

    ASSERT(model.config.max_block_units == 1000000);
    ASSERT(model.config.signature_cost == 200);
}

TEST(cost_model_reset) {
    sol_cost_model_t model;
    sol_cost_model_init(&model, NULL);

    /* Simulate some usage */
    model.block_cost = 500000;
    model.vote_cost = 100000;

    sol_cost_model_reset(&model);

    ASSERT(model.block_cost == 0);
    ASSERT(model.vote_cost == 0);
}

/*
 * ====================
 * Sigverify Service Tests
 * ====================
 */

TEST(sigverify_new) {
    sol_sigverify_config_t config = SOL_SIGVERIFY_CONFIG_DEFAULT;
    sol_sigverify_t* sv = sol_sigverify_new(&config);
    ASSERT(sv != NULL);
    sol_sigverify_destroy(sv);
}

TEST(sigverify_default_config) {
    sol_sigverify_t* sv = sol_sigverify_new(NULL);
    ASSERT(sv != NULL);
    sol_sigverify_destroy(sv);
}

TEST(sigverify_batch_new) {
    sol_sigverify_batch_t* batch = sol_sigverify_batch_new(100);
    ASSERT(batch != NULL);
    ASSERT(batch->count == 0);
    ASSERT(batch->capacity == 100);
    sol_sigverify_batch_destroy(batch);
}

TEST(sigverify_batch_clear) {
    sol_sigverify_batch_t* batch = sol_sigverify_batch_new(100);
    ASSERT(batch != NULL);

    /* Simulate adding entries */
    batch->count = 10;
    batch->valid = 5;
    batch->invalid = 5;

    sol_sigverify_batch_clear(batch);
    ASSERT(batch->count == 0);
    ASSERT(batch->valid == 0);
    ASSERT(batch->invalid == 0);

    sol_sigverify_batch_destroy(batch);
}

TEST(sigverify_stats) {
    sol_sigverify_t* sv = sol_sigverify_new(NULL);
    ASSERT(sv != NULL);

    sol_sigverify_stats_t stats;
    sol_sigverify_stats(sv, &stats);

    ASSERT(stats.transactions_verified == 0);
    ASSERT(stats.signatures_verified == 0);
    ASSERT(stats.valid_count == 0);
    ASSERT(stats.invalid_count == 0);

    sol_sigverify_destroy(sv);
}

TEST(sigverify_stats_reset) {
    sol_sigverify_t* sv = sol_sigverify_new(NULL);
    ASSERT(sv != NULL);

    /* Get initial stats */
    sol_sigverify_stats_t stats;
    sol_sigverify_stats(sv, &stats);

    sol_sigverify_stats_reset(sv);
    sol_sigverify_stats(sv, &stats);
    ASSERT(stats.transactions_verified == 0);

    sol_sigverify_destroy(sv);
}

/*
 * ====================
 * Transaction Queue Tests
 * ====================
 */

TEST(tx_queue_new) {
    sol_tx_queue_t* queue = sol_tx_queue_new(100);
    ASSERT(queue != NULL);
    ASSERT(sol_tx_queue_len(queue) == 0);
    ASSERT(sol_tx_queue_is_empty(queue) == true);
    sol_tx_queue_destroy(queue);
}

TEST(tx_queue_push_pop) {
    sol_tx_queue_t* queue = sol_tx_queue_new(100);
    ASSERT(queue != NULL);

    /* Create dummy transaction pointers */
    sol_transaction_t tx1 = {0}, tx2 = {0}, tx3 = {0};

    /* Push */
    ASSERT(sol_tx_queue_push(queue, &tx1) == SOL_OK);
    ASSERT(sol_tx_queue_len(queue) == 1);
    ASSERT(sol_tx_queue_push(queue, &tx2) == SOL_OK);
    ASSERT(sol_tx_queue_len(queue) == 2);
    ASSERT(sol_tx_queue_push(queue, &tx3) == SOL_OK);
    ASSERT(sol_tx_queue_len(queue) == 3);

    /* Pop (FIFO order) */
    ASSERT(sol_tx_queue_pop(queue) == &tx1);
    ASSERT(sol_tx_queue_len(queue) == 2);
    ASSERT(sol_tx_queue_pop(queue) == &tx2);
    ASSERT(sol_tx_queue_pop(queue) == &tx3);
    ASSERT(sol_tx_queue_len(queue) == 0);
    ASSERT(sol_tx_queue_is_empty(queue) == true);

    /* Pop from empty */
    ASSERT(sol_tx_queue_pop(queue) == NULL);

    sol_tx_queue_destroy(queue);
}

TEST(tx_queue_full) {
    sol_tx_queue_t* queue = sol_tx_queue_new(3);
    ASSERT(queue != NULL);

    sol_transaction_t tx1 = {0}, tx2 = {0}, tx3 = {0}, tx4 = {0};

    ASSERT(sol_tx_queue_push(queue, &tx1) == SOL_OK);
    ASSERT(sol_tx_queue_push(queue, &tx2) == SOL_OK);
    ASSERT(sol_tx_queue_push(queue, &tx3) == SOL_OK);
    ASSERT(sol_tx_queue_is_full(queue) == true);

    /* Should fail when full */
    ASSERT(sol_tx_queue_push(queue, &tx4) == SOL_ERR_FULL);

    sol_tx_queue_destroy(queue);
}

TEST(tx_queue_clear) {
    sol_tx_queue_t* queue = sol_tx_queue_new(100);
    ASSERT(queue != NULL);

    sol_transaction_t tx1 = {0}, tx2 = {0};
    sol_tx_queue_push(queue, &tx1);
    sol_tx_queue_push(queue, &tx2);
    ASSERT(sol_tx_queue_len(queue) == 2);

    sol_tx_queue_clear(queue);
    ASSERT(sol_tx_queue_len(queue) == 0);
    ASSERT(sol_tx_queue_is_empty(queue) == true);

    sol_tx_queue_destroy(queue);
}

/*
 * ====================
 * Priority Queue Tests
 * ====================
 */

TEST(priority_queue_new) {
    sol_priority_queue_t* pq = sol_priority_queue_new(100);
    ASSERT(pq != NULL);
    ASSERT(sol_priority_queue_len(pq) == 0);
    sol_priority_queue_destroy(pq);
}

TEST(priority_queue_ordering) {
    sol_priority_queue_t* pq = sol_priority_queue_new(100);
    ASSERT(pq != NULL);

    sol_transaction_t tx_low = {0}, tx_med = {0}, tx_high = {0};

    /* Push in non-priority order */
    ASSERT(sol_priority_queue_push(pq, &tx_med, 50) == SOL_OK);
    ASSERT(sol_priority_queue_push(pq, &tx_low, 10) == SOL_OK);
    ASSERT(sol_priority_queue_push(pq, &tx_high, 100) == SOL_OK);
    ASSERT(sol_priority_queue_len(pq) == 3);

    /* Pop should return highest priority first */
    ASSERT(sol_priority_queue_pop(pq) == &tx_high);
    ASSERT(sol_priority_queue_pop(pq) == &tx_med);
    ASSERT(sol_priority_queue_pop(pq) == &tx_low);
    ASSERT(sol_priority_queue_len(pq) == 0);

    sol_priority_queue_destroy(pq);
}

/*
 * ====================
 * Account Locks Tests
 * ====================
 */

TEST(account_locks_new) {
    sol_account_locks_t* locks = sol_account_locks_new();
    ASSERT(locks != NULL);
    sol_account_locks_destroy(locks);
}

/*
 * ====================
 * Banking Stage Tests
 * ====================
 */

TEST(banking_stage_new) {
    sol_banking_stage_config_t config = SOL_BANKING_STAGE_CONFIG_DEFAULT;
    sol_banking_stage_t* stage = sol_banking_stage_new(NULL, NULL, &config);
    ASSERT(stage != NULL);
    sol_banking_stage_destroy(stage);
}

TEST(banking_stage_default_config) {
    sol_banking_stage_t* stage = sol_banking_stage_new(NULL, NULL, NULL);
    ASSERT(stage != NULL);
    sol_banking_stage_destroy(stage);
}

TEST(banking_stage_pending_count) {
    sol_banking_stage_t* stage = sol_banking_stage_new(NULL, NULL, NULL);
    ASSERT(stage != NULL);
    ASSERT(sol_banking_stage_pending_count(stage) == 0);
    sol_banking_stage_destroy(stage);
}

TEST(banking_stage_stats) {
    sol_banking_stage_t* stage = sol_banking_stage_new(NULL, NULL, NULL);
    ASSERT(stage != NULL);

    sol_banking_stage_stats_t stats;
    sol_banking_stage_stats(stage, &stats);

    ASSERT(stats.transactions_received == 0);
    ASSERT(stats.transactions_processed == 0);
    ASSERT(stats.batches_processed == 0);

    sol_banking_stage_destroy(stage);
}

TEST(banking_stage_stats_reset) {
    sol_banking_stage_t* stage = sol_banking_stage_new(NULL, NULL, NULL);
    ASSERT(stage != NULL);

    sol_banking_stage_stats_reset(stage);

    sol_banking_stage_stats_t stats;
    sol_banking_stage_stats(stage, &stats);
    ASSERT(stats.transactions_received == 0);

    sol_banking_stage_destroy(stage);
}

/*
 * Main
 */
int main(void) {
    printf("\n=== TPU Tests ===\n");

    /* Dedup filter */
    RUN_TEST(dedup_filter_new);
    RUN_TEST(dedup_filter_check);
    RUN_TEST(dedup_filter_many);

    /* TPU */
    RUN_TEST(tpu_new);
    RUN_TEST(tpu_default_config);
    RUN_TEST(tpu_stats);
    RUN_TEST(tpu_start_stop_no_net);
    RUN_TEST(tpu_submit_forwards_to_leader_udp);
    RUN_TEST(tpu_submit_vote_forwards_to_vote_port);

    printf("\n=== Compute Budget Tests ===\n");
    RUN_TEST(compute_budget_init);
    RUN_TEST(compute_budget_parse_modern_instructions);
    RUN_TEST(compute_budget_parse_request_units_deprecated);
    RUN_TEST(compute_budget_priority_fee);
    RUN_TEST(compute_meter_init);
    RUN_TEST(compute_meter_consume);
    RUN_TEST(compute_meter_check);
    RUN_TEST(cost_model_init);
    RUN_TEST(cost_model_custom_config);
    RUN_TEST(cost_model_reset);

    printf("\n=== Sigverify Tests ===\n");
    RUN_TEST(sigverify_new);
    RUN_TEST(sigverify_default_config);
    RUN_TEST(sigverify_batch_new);
    RUN_TEST(sigverify_batch_clear);
    RUN_TEST(sigverify_stats);
    RUN_TEST(sigverify_stats_reset);

    printf("\n=== Transaction Queue Tests ===\n");
    RUN_TEST(tx_queue_new);
    RUN_TEST(tx_queue_push_pop);
    RUN_TEST(tx_queue_full);
    RUN_TEST(tx_queue_clear);

    printf("\n=== Priority Queue Tests ===\n");
    RUN_TEST(priority_queue_new);
    RUN_TEST(priority_queue_ordering);

    printf("\n=== Account Locks Tests ===\n");
    RUN_TEST(account_locks_new);

    printf("\n=== Banking Stage Tests ===\n");
    RUN_TEST(banking_stage_new);
    RUN_TEST(banking_stage_default_config);
    RUN_TEST(banking_stage_pending_count);
    RUN_TEST(banking_stage_stats);
    RUN_TEST(banking_stage_stats_reset);

    printf("\nResults: %d/%d passed\n\n", tests_passed, tests_run);

    sol_alloc_stats_print();
    return tests_passed == tests_run ? 0 : 1;
}
