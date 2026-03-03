/*
 * test_rpc.c - Tests for JSON-RPC Server
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/rpc/sol_rpc.h"
#include "../src/runtime/sol_accounts_db.h"
#include "../src/programs/sol_token_program.h"
#include "../src/blockstore/sol_blockstore.h"
#include "../src/txn/sol_bincode.h"
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
 * Test JSON builder creation
 */
TEST(json_builder_new) {
    sol_json_builder_t* b = sol_json_builder_new(256);
    ASSERT(b != NULL);
    sol_json_builder_destroy(b);
}

/*
 * Test JSON builder object
 */
TEST(json_builder_object) {
    sol_json_builder_t* b = sol_json_builder_new(256);
    ASSERT(b != NULL);

    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "name");
    sol_json_builder_string(b, "test");
    sol_json_builder_key(b, "value");
    sol_json_builder_int(b, 42);
    sol_json_builder_object_end(b);

    const char* json = sol_json_builder_str(b);
    ASSERT(json != NULL);
    ASSERT(strcmp(json, "{\"name\":\"test\",\"value\":42}") == 0);

    sol_json_builder_destroy(b);
}

/*
 * Test JSON builder array
 */
TEST(json_builder_array) {
    sol_json_builder_t* b = sol_json_builder_new(256);
    ASSERT(b != NULL);

    sol_json_builder_array_begin(b);
    sol_json_builder_int(b, 1);
    sol_json_builder_int(b, 2);
    sol_json_builder_int(b, 3);
    sol_json_builder_array_end(b);

    const char* json = sol_json_builder_str(b);
    ASSERT(json != NULL);
    ASSERT(strcmp(json, "[1,2,3]") == 0);

    sol_json_builder_destroy(b);
}

/*
 * Test JSON builder nested
 */
TEST(json_builder_nested) {
    sol_json_builder_t* b = sol_json_builder_new(256);
    ASSERT(b != NULL);

    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "items");
    sol_json_builder_array_begin(b);
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "id");
    sol_json_builder_int(b, 1);
    sol_json_builder_object_end(b);
    sol_json_builder_array_end(b);
    sol_json_builder_object_end(b);

    const char* json = sol_json_builder_str(b);
    ASSERT(json != NULL);
    ASSERT(strcmp(json, "{\"items\":[{\"id\":1}]}") == 0);

    sol_json_builder_destroy(b);
}

/*
 * Test JSON parser object
 */
TEST(json_parser_object) {
    const char* json = "{\"name\":\"test\",\"value\":42}";
    sol_json_parser_t p;
    sol_json_parser_init(&p, json, strlen(json));

    ASSERT(sol_json_parser_object_begin(&p));

    char key[32];
    ASSERT(sol_json_parser_key(&p, key, sizeof(key)));
    ASSERT(strcmp(key, "name") == 0);

    char value[32];
    ASSERT(sol_json_parser_string(&p, value, sizeof(value)));
    ASSERT(strcmp(value, "test") == 0);

    ASSERT(sol_json_parser_key(&p, key, sizeof(key)));
    ASSERT(strcmp(key, "value") == 0);

    int64_t num;
    ASSERT(sol_json_parser_int(&p, &num));
    ASSERT(num == 42);

    ASSERT(sol_json_parser_object_end(&p));
}

/*
 * Test JSON parser array
 */
TEST(json_parser_array) {
    const char* json = "[1,2,3]";
    sol_json_parser_t p;
    sol_json_parser_init(&p, json, strlen(json));

    ASSERT(sol_json_parser_array_begin(&p));

    int64_t n;
    ASSERT(sol_json_parser_int(&p, &n));
    ASSERT(n == 1);
    ASSERT(sol_json_parser_int(&p, &n));
    ASSERT(n == 2);
    ASSERT(sol_json_parser_int(&p, &n));
    ASSERT(n == 3);

    ASSERT(sol_json_parser_array_end(&p));
}

TEST(json_parser_string_zero_len) {
    const char* json = "\"hello\"";
    sol_json_parser_t p;
    sol_json_parser_init(&p, json, strlen(json));

    char sentinel = 'X';
    ASSERT(sol_json_parser_string(&p, &sentinel, 0));
    ASSERT(sentinel == 'X');
}

/*
 * Test RPC server creation
 */
TEST(rpc_new) {
    sol_rpc_config_t config = SOL_RPC_CONFIG_DEFAULT;
    sol_rpc_t* rpc = sol_rpc_new(NULL, &config);
    ASSERT(rpc != NULL);
    ASSERT(sol_rpc_is_running(rpc) == false);
    sol_rpc_destroy(rpc);
}

/*
 * Test RPC server default config
 */
TEST(rpc_default_config) {
    sol_rpc_t* rpc = sol_rpc_new(NULL, NULL);
    ASSERT(rpc != NULL);
    sol_rpc_destroy(rpc);
}

/*
 * Test RPC stats
 */
TEST(rpc_stats) {
    sol_rpc_config_t config = SOL_RPC_CONFIG_DEFAULT;
    sol_rpc_t* rpc = sol_rpc_new(NULL, &config);
    ASSERT(rpc != NULL);

    sol_rpc_stats_t stats = sol_rpc_stats(rpc);
    ASSERT(stats.requests_total == 0);
    ASSERT(stats.active_connections == 0);

    sol_rpc_destroy(rpc);
}

TEST(rpc_rate_limiting) {
    sol_rpc_config_t config = SOL_RPC_CONFIG_DEFAULT;
    config.rate_limit_rps = 1;
    config.rate_limit_burst = 1;

    sol_rpc_t* rpc = sol_rpc_new(NULL, &config);
    ASSERT(rpc != NULL);

    const char* req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getVersion\"}";

    sol_json_builder_t* b1 = sol_json_builder_new(512);
    ASSERT(b1 != NULL);
    sol_rpc_handle_request_json(rpc, req, strlen(req), b1);
    const char* resp1 = sol_json_builder_str(b1);
    ASSERT(resp1 != NULL);
    ASSERT(strstr(resp1, "\"result\"") != NULL);
    sol_json_builder_destroy(b1);

    sol_json_builder_t* b2 = sol_json_builder_new(512);
    ASSERT(b2 != NULL);
    sol_rpc_handle_request_json(rpc, req, strlen(req), b2);
    const char* resp2 = sol_json_builder_str(b2);
    ASSERT(resp2 != NULL);
    ASSERT(strstr(resp2, "\"error\"") != NULL);
    ASSERT(strstr(resp2, "\"code\":-32020") != NULL);
    sol_json_builder_destroy(b2);

    sol_rpc_destroy(rpc);
}

TEST(rpc_dynamic_rate_limit) {
    sol_rpc_t* rpc = sol_rpc_new(NULL, NULL);
    ASSERT(rpc != NULL);

    const char* req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getVersion\"}";

    sol_json_builder_t* b1 = sol_json_builder_new(512);
    ASSERT(b1 != NULL);
    sol_rpc_handle_request_json(rpc, req, strlen(req), b1);
    const char* resp1 = sol_json_builder_str(b1);
    ASSERT(resp1 != NULL);
    ASSERT(strstr(resp1, "\"result\"") != NULL);
    sol_json_builder_destroy(b1);

    sol_rpc_set_rate_limit(rpc, 1u, 1u);

    sol_json_builder_t* b2 = sol_json_builder_new(512);
    ASSERT(b2 != NULL);
    sol_rpc_handle_request_json(rpc, req, strlen(req), b2);
    const char* resp2 = sol_json_builder_str(b2);
    ASSERT(resp2 != NULL);
    ASSERT(strstr(resp2, "\"result\"") != NULL);
    sol_json_builder_destroy(b2);

    sol_json_builder_t* b3 = sol_json_builder_new(512);
    ASSERT(b3 != NULL);
    sol_rpc_handle_request_json(rpc, req, strlen(req), b3);
    const char* resp3 = sol_json_builder_str(b3);
    ASSERT(resp3 != NULL);
    ASSERT(strstr(resp3, "\"error\"") != NULL);
    ASSERT(strstr(resp3, "\"code\":-32020") != NULL);
    sol_json_builder_destroy(b3);

    sol_rpc_set_rate_limit(rpc, 0u, 0u);
    sol_rpc_set_max_connections(rpc, 32u);

    sol_json_builder_t* b4 = sol_json_builder_new(512);
    ASSERT(b4 != NULL);
    sol_rpc_handle_request_json(rpc, req, strlen(req), b4);
    const char* resp4 = sol_json_builder_str(b4);
    ASSERT(resp4 != NULL);
    ASSERT(strstr(resp4, "\"result\"") != NULL);
    sol_json_builder_destroy(b4);

    sol_rpc_destroy(rpc);
}

static size_t
test_base64_encode(const uint8_t* input, size_t input_len, char* output, size_t output_max) {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    size_t out_len = ((input_len + 2) / 3) * 4;
    if (!output || output_max < out_len + 1) {
        return 0;
    }

    size_t i = 0;
    size_t o = 0;
    while (i < input_len) {
        size_t rem = input_len - i;
        uint32_t b0 = input[i++];
        uint32_t b1 = (rem > 1) ? input[i++] : 0;
        uint32_t b2 = (rem > 2) ? input[i++] : 0;
        uint32_t triple = (b0 << 16) | (b1 << 8) | b2;

        output[o++] = table[(triple >> 18) & 0x3F];
        output[o++] = table[(triple >> 12) & 0x3F];
        output[o++] = (rem > 1) ? table[(triple >> 6) & 0x3F] : '=';
        output[o++] = (rem > 2) ? table[triple & 0x3F] : '=';
    }

    output[o] = '\0';
    return o;
}

static size_t
build_minimal_legacy_tx(uint8_t* out, size_t out_max) {
    sol_encoder_t enc;
    sol_encoder_init(&enc, out, out_max);

    /* Signature count: 1 */
    sol_encode_compact_u16(&enc, 1);

    /* Signature (64 bytes of zeros for testing - won't verify) */
    uint8_t fake_sig[64] = {0};
    sol_encode_bytes(&enc, fake_sig, 64);

    /* Message header: 1 signer, 0 readonly signed, 1 readonly unsigned */
    sol_encode_u8(&enc, 1);
    sol_encode_u8(&enc, 0);
    sol_encode_u8(&enc, 1);

    /* Account keys: 2 accounts */
    sol_encode_compact_u16(&enc, 2);

    /* Account 0: fee payer (random pubkey) */
    uint8_t fee_payer[32];
    for (int i = 0; i < 32; i++) fee_payer[i] = (uint8_t)(i + 1);
    sol_encode_bytes(&enc, fee_payer, 32);

    /* Account 1: system program */
    sol_encode_bytes(&enc, SOL_SYSTEM_PROGRAM_ID.bytes, 32);

    /* Recent blockhash (32 bytes) */
    uint8_t blockhash[32];
    for (int i = 0; i < 32; i++) blockhash[i] = (uint8_t)(255 - i);
    sol_encode_bytes(&enc, blockhash, 32);

    /* Instructions: 1 instruction */
    sol_encode_compact_u16(&enc, 1);

    /* Instruction 0 */
    sol_encode_u8(&enc, 1);               /* program_id_index = 1 (system program) */
    sol_encode_compact_u16(&enc, 1);      /* 1 account */
    sol_encode_u8(&enc, 0);               /* account index 0 */
    sol_encode_compact_u16(&enc, 4);      /* 4 bytes of data */
    uint8_t instr_data[] = {0x02, 0x00, 0x00, 0x00};
    sol_encode_bytes(&enc, instr_data, sizeof(instr_data));

    return sol_encoder_len(&enc);
}

static sol_err_t
send_tx_stub(const sol_transaction_t* tx, void* user_data) {
    (void)tx;
    int* called = (int*)user_data;
    (*called)++;
    return SOL_OK;
}

TEST(rpc_send_transaction_invokes_callback) {
    sol_rpc_config_t config = SOL_RPC_CONFIG_DEFAULT;
    sol_rpc_t* rpc = sol_rpc_new(NULL, &config);
    ASSERT(rpc != NULL);

    uint8_t tx_bytes[256];
    size_t tx_len = build_minimal_legacy_tx(tx_bytes, sizeof(tx_bytes));
    ASSERT(tx_len > 0);

    char tx_b64[512];
    ASSERT(test_base64_encode(tx_bytes, tx_len, tx_b64, sizeof(tx_b64)) > 0);

    int called = 0;
    sol_rpc_set_send_transaction(rpc, send_tx_stub, &called);

    char req[1024];
    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"sendTransaction\",\"params\":[\"%s\"]}",
             tx_b64);

    sol_json_builder_t* b = sol_json_builder_new(2048);
    ASSERT(b != NULL);
    sol_rpc_handle_request_json(rpc, req, strlen(req), b);
    const char* resp = sol_json_builder_str(b);
    ASSERT(resp != NULL);
    ASSERT(strstr(resp, "\"result\"") != NULL);
    ASSERT(called == 1);

    sol_json_builder_destroy(b);
    sol_rpc_destroy(rpc);
}

static sol_health_result_t
unhealthy_health_cb(void* ctx) {
    (void)ctx;
    sol_health_result_t r = {0};
    r.status = SOL_HEALTH_UNHEALTHY;
    r.message = "unhealthy";
    return r;
}

TEST(rpc_get_health_uses_callback) {
    sol_rpc_config_t config = SOL_RPC_CONFIG_DEFAULT;
    sol_rpc_t* rpc = sol_rpc_new(NULL, &config);
    ASSERT(rpc != NULL);

    sol_rpc_set_health_callback(rpc, unhealthy_health_cb, NULL);

    const char* req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getHealth\"}";

    sol_json_builder_t* b = sol_json_builder_new(512);
    ASSERT(b != NULL);
    sol_rpc_handle_request_json(rpc, req, strlen(req), b);
    const char* resp = sol_json_builder_str(b);
    ASSERT(resp != NULL);
    ASSERT(strstr(resp, "\"error\"") != NULL);
    ASSERT(strstr(resp, "\"code\":-32005") != NULL);
    ASSERT(strstr(resp, "unhealthy") != NULL);
    sol_json_builder_destroy(b);

    sol_rpc_destroy(rpc);
}

static void
fill_pubkey(sol_pubkey_t* out, uint8_t seed) {
    memset(out->bytes, seed, SOL_PUBKEY_SIZE);
}

TEST(rpc_get_epoch_schedule) {
    sol_bank_t* root = sol_bank_new(123, NULL, NULL, NULL);
    ASSERT(root != NULL);

    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);
    ASSERT(forks != NULL);

    sol_rpc_t* rpc = sol_rpc_new(forks, NULL);
    ASSERT(rpc != NULL);

    const char* req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getEpochSchedule\"}";
    sol_json_builder_t* b = sol_json_builder_new(1024);
    ASSERT(b != NULL);
    sol_rpc_handle_request_json(rpc, req, strlen(req), b);
    const char* resp = sol_json_builder_str(b);
    ASSERT(resp != NULL);
    ASSERT(strstr(resp, "\"slotsPerEpoch\"") != NULL);
    ASSERT(strstr(resp, "\"leaderScheduleSlotOffset\"") != NULL);
    sol_json_builder_destroy(b);

    sol_rpc_destroy(rpc);
    sol_bank_forks_destroy(forks);
}

TEST(rpc_get_inflation_governor) {
    sol_rpc_t* rpc = sol_rpc_new(NULL, NULL);
    ASSERT(rpc != NULL);

    const char* req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getInflationGovernor\"}";
    sol_json_builder_t* b = sol_json_builder_new(1024);
    ASSERT(b != NULL);
    sol_rpc_handle_request_json(rpc, req, strlen(req), b);
    const char* resp = sol_json_builder_str(b);
    ASSERT(resp != NULL);
    ASSERT(strstr(resp, "\"initial\"") != NULL);
    ASSERT(strstr(resp, "\"foundationTerm\"") != NULL);
    sol_json_builder_destroy(b);

    sol_rpc_destroy(rpc);
}

TEST(rpc_get_recent_performance_samples) {
    sol_bank_t* root = sol_bank_new(123, NULL, NULL, NULL);
    ASSERT(root != NULL);

    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);
    ASSERT(forks != NULL);

    sol_rpc_t* rpc = sol_rpc_new(forks, NULL);
    ASSERT(rpc != NULL);

    const char* req =
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getRecentPerformanceSamples\",\"params\":[5]}";
    sol_json_builder_t* b = sol_json_builder_new(1024);
    ASSERT(b != NULL);
    sol_rpc_handle_request_json(rpc, req, strlen(req), b);
    const char* resp = sol_json_builder_str(b);
    ASSERT(resp != NULL);
    ASSERT(strstr(resp, "\"numTransactions\"") != NULL);
    ASSERT(strstr(resp, "\"samplePeriodSecs\"") != NULL);
    sol_json_builder_destroy(b);

    sol_rpc_destroy(rpc);
    sol_bank_forks_destroy(forks);
}

TEST(rpc_get_blocks_with_limit) {
    sol_bank_t* root = sol_bank_new(20, NULL, NULL, NULL);
    ASSERT(root != NULL);
    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);
    ASSERT(forks != NULL);

    sol_blockstore_t* bs = sol_blockstore_new(NULL);
    ASSERT(bs != NULL);

    /* Create 3 complete slots: 5, 6, 7 */
    uint8_t raw = 0;
    for (sol_slot_t slot = 5; slot <= 7; slot++) {
        sol_shred_t shred = {0};
        shred.type = SOL_SHRED_TYPE_DATA;
        shred.slot = slot;
        shred.index = 0;
        shred.header.data.parent_slot = slot > 0 ? slot - 1 : 0;
        shred.header.data.flags = SOL_SHRED_FLAG_LAST_IN_SLOT;
        ASSERT(sol_blockstore_insert_shred(bs, &shred, &raw, sizeof(raw)) == SOL_OK);
    }

    sol_rpc_t* rpc = sol_rpc_new(forks, NULL);
    ASSERT(rpc != NULL);
    sol_rpc_set_blockstore(rpc, bs);

    const char* req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getBlocksWithLimit\",\"params\":[5,2]}";
    sol_json_builder_t* b = sol_json_builder_new(1024);
    ASSERT(b != NULL);
    sol_rpc_handle_request_json(rpc, req, strlen(req), b);
    const char* resp = sol_json_builder_str(b);
    ASSERT(resp != NULL);
    ASSERT(strstr(resp, "\"result\":[5,6]") != NULL);
    sol_json_builder_destroy(b);

    sol_rpc_destroy(rpc);
    sol_blockstore_destroy(bs);
    sol_bank_forks_destroy(forks);
}

TEST(rpc_get_token_account_balance) {
    sol_accounts_db_t* db = sol_accounts_db_new(NULL);
    ASSERT(db != NULL);

    sol_pubkey_t mint_pubkey;
    sol_pubkey_t wallet_pubkey;
    sol_pubkey_t token_account_pubkey;
    fill_pubkey(&mint_pubkey, 1);
    fill_pubkey(&wallet_pubkey, 2);
    fill_pubkey(&token_account_pubkey, 3);

    /* Mint account */
    sol_account_t* mint_acc = sol_account_new(1, SOL_TOKEN_MINT_SIZE, &SOL_TOKEN_PROGRAM_ID);
    ASSERT(mint_acc != NULL);
    sol_token_mint_t mint = {0};
    mint.is_initialized = true;
    mint.decimals = 6;
    mint.supply = 1000;
    ASSERT(sol_token_pack_mint(&mint, mint_acc->data, mint_acc->meta.data_len) == SOL_TOKEN_MINT_SIZE);
    ASSERT(sol_accounts_db_store(db, &mint_pubkey, mint_acc) == SOL_OK);
    sol_account_destroy(mint_acc);

    /* Token account */
    sol_account_t* token_acc = sol_account_new(1, SOL_TOKEN_ACCOUNT_SIZE, &SOL_TOKEN_PROGRAM_ID);
    ASSERT(token_acc != NULL);
    sol_token_account_t token = {0};
    token.mint = mint_pubkey;
    token.owner = wallet_pubkey;
    token.amount = 42;
    token.state = SOL_TOKEN_ACCOUNT_STATE_INITIALIZED;
    ASSERT(sol_token_pack_account(&token, token_acc->data, token_acc->meta.data_len) == SOL_TOKEN_ACCOUNT_SIZE);
    ASSERT(sol_accounts_db_store(db, &token_account_pubkey, token_acc) == SOL_OK);
    sol_account_destroy(token_acc);

    sol_bank_t* root = sol_bank_new(123, NULL, db, NULL);
    ASSERT(root != NULL);
    sol_bank_forks_t* forks = sol_bank_forks_new(root, NULL);
    ASSERT(forks != NULL);

    sol_rpc_t* rpc = sol_rpc_new(forks, NULL);
    ASSERT(rpc != NULL);

    char pk_str[64];
    sol_pubkey_to_base58(&token_account_pubkey, pk_str, sizeof(pk_str));

    char req[256];
    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getTokenAccountBalance\",\"params\":[\"%s\"]}",
             pk_str);

    sol_json_builder_t* b = sol_json_builder_new(1024);
    ASSERT(b != NULL);
    sol_rpc_handle_request_json(rpc, req, strlen(req), b);
    const char* resp = sol_json_builder_str(b);
    ASSERT(resp != NULL);
    ASSERT(strstr(resp, "\"amount\":\"42\"") != NULL);
    ASSERT(strstr(resp, "\"decimals\":6") != NULL);
    ASSERT(strstr(resp, "\"slot\":123") != NULL);
    sol_json_builder_destroy(b);

    sol_rpc_destroy(rpc);
    sol_bank_forks_destroy(forks);
    sol_accounts_db_destroy(db);
}

/*
 * Main
 */
int main(void) {
    printf("\n=== RPC Tests ===\n");

    RUN_TEST(json_builder_new);
    RUN_TEST(json_builder_object);
    RUN_TEST(json_builder_array);
    RUN_TEST(json_builder_nested);
    RUN_TEST(json_parser_object);
    RUN_TEST(json_parser_array);
    RUN_TEST(json_parser_string_zero_len);
    RUN_TEST(rpc_new);
    RUN_TEST(rpc_default_config);
    RUN_TEST(rpc_stats);
    RUN_TEST(rpc_rate_limiting);
    RUN_TEST(rpc_dynamic_rate_limit);
    RUN_TEST(rpc_send_transaction_invokes_callback);
    RUN_TEST(rpc_get_health_uses_callback);
    RUN_TEST(rpc_get_epoch_schedule);
    RUN_TEST(rpc_get_inflation_governor);
    RUN_TEST(rpc_get_recent_performance_samples);
    RUN_TEST(rpc_get_blocks_with_limit);
    RUN_TEST(rpc_get_token_account_balance);

    printf("\nResults: %d/%d passed\n\n", tests_passed, tests_run);

    sol_alloc_stats_print();
    return tests_passed == tests_run ? 0 : 1;
}
