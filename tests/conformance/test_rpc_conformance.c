/*
 * test_rpc_conformance.c - HTTP-level RPC conformance tests
 *
 * These tests exercise the RPC server over HTTP and validate response
 * shapes/behavior against Solana's documented/expected RPC semantics.
 */

#include "../test_framework.h"

#include "../src/rpc/sol_rpc.h"
#include "../src/replay/sol_bank_forks.h"
#include "../src/runtime/sol_accounts_db.h"
#include "../src/runtime/sol_bank.h"
#include "../src/blockstore/sol_blockstore.h"
#include "../src/shred/sol_shred.h"
#include "../src/programs/sol_token_program.h"
#include "../src/txn/sol_bincode.h"

#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

static sol_rpc_t*        g_rpc = NULL;
static sol_bank_forks_t* g_forks = NULL;
static sol_blockstore_t* g_blockstore = NULL;
static sol_accounts_db_t* g_accounts_db = NULL;
static uint16_t          g_port = 0;
static sol_bank_t*       g_root_bank = NULL;

static sol_pubkey_t g_system_account = {0};
static sol_pubkey_t g_token_mint = {0};
static sol_pubkey_t g_token_owner = {0};
static sol_pubkey_t g_token_account = {0};
static sol_hash_t   g_genesis_hash = {0};
static sol_pubkey_t g_identity = {0};
static sol_hash_t   g_blockhash = {0};

static void
fill_pubkey(sol_pubkey_t* out, uint8_t seed) {
    memset(out->bytes, seed, SOL_PUBKEY_SIZE);
}

static void
hash_to_base58(const sol_hash_t* h, char* out, size_t out_sz) {
    /* Avoid strict-aliasing UB from casting sol_hash_t* to sol_pubkey_t*. */
    sol_pubkey_t pk;
    memcpy(pk.bytes, h->bytes, SOL_HASH_SIZE);
    sol_pubkey_to_base58(&pk, out, out_sz);
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
build_minimal_legacy_message(uint8_t* out, size_t out_max) {
    sol_encoder_t enc;
    sol_encoder_init(&enc, out, out_max);

    /* Message header: 1 signer, 0 readonly signed, 1 readonly unsigned */
    if (sol_encode_u8(&enc, 1) != SOL_OK) return 0;
    if (sol_encode_u8(&enc, 0) != SOL_OK) return 0;
    if (sol_encode_u8(&enc, 1) != SOL_OK) return 0;

    /* Account keys: 2 accounts */
    if (sol_encode_compact_u16(&enc, 2) != SOL_OK) return 0;

    /* Account 0: fee payer (deterministic, not a real key) */
    uint8_t fee_payer[32];
    for (int i = 0; i < 32; i++) fee_payer[i] = (uint8_t)(i + 1);
    if (sol_encode_bytes(&enc, fee_payer, 32) != SOL_OK) return 0;

    /* Account 1: system program */
    if (sol_encode_bytes(&enc, SOL_SYSTEM_PROGRAM_ID.bytes, 32) != SOL_OK) return 0;

    /* Recent blockhash (32 bytes) */
    uint8_t blockhash[32];
    for (int i = 0; i < 32; i++) blockhash[i] = (uint8_t)(255 - i);
    if (sol_encode_bytes(&enc, blockhash, 32) != SOL_OK) return 0;

    /* Instructions: 1 instruction */
    if (sol_encode_compact_u16(&enc, 1) != SOL_OK) return 0;

    /* Instruction 0 */
    if (sol_encode_u8(&enc, 1) != SOL_OK) return 0;          /* program_id_index = 1 (system program) */
    if (sol_encode_compact_u16(&enc, 1) != SOL_OK) return 0; /* 1 account */
    if (sol_encode_u8(&enc, 0) != SOL_OK) return 0;          /* account index 0 */
    if (sol_encode_compact_u16(&enc, 4) != SOL_OK) return 0; /* 4 bytes of data */
    uint8_t instr_data[] = {0x02, 0x00, 0x00, 0x00};
    if (sol_encode_bytes(&enc, instr_data, sizeof(instr_data)) != SOL_OK) return 0;

    return sol_encoder_len(&enc);
}

static size_t
build_minimal_legacy_tx(uint8_t* out, size_t out_max) {
    sol_encoder_t enc;
    sol_encoder_init(&enc, out, out_max);

    /* Signature count: 1 */
    if (sol_encode_compact_u16(&enc, 1) != SOL_OK) return 0;

    /* Signature (64 bytes of zeros for testing - won't verify) */
    uint8_t fake_sig[64] = {0};
    if (sol_encode_bytes(&enc, fake_sig, 64) != SOL_OK) return 0;

    uint8_t msg[512];
    size_t msg_len = build_minimal_legacy_message(msg, sizeof(msg));
    if (msg_len == 0) return 0;

    if (sol_encode_bytes(&enc, msg, msg_len) != SOL_OK) return 0;
    return sol_encoder_len(&enc);
}

static char*
http_post_json(const char* host, uint16_t port, const char* body, size_t body_len) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NULL;

    union {
        struct sockaddr    sa;
        struct sockaddr_in in;
    } addr;
    memset(&addr, 0, sizeof(addr));

    addr.in.sin_family = AF_INET;
    addr.in.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.in.sin_addr) != 1) {
        close(fd);
        return NULL;
    }

    if (connect(fd, &addr.sa, sizeof(addr.in)) < 0) {
        close(fd);
        return NULL;
    }

    char header[512];
    int header_len = snprintf(header, sizeof(header),
        "POST / HTTP/1.1\r\n"
        "Host: %s:%u\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        host, (unsigned)port, body_len);

    if (header_len <= 0 || (size_t)header_len >= sizeof(header)) {
        close(fd);
        return NULL;
    }

    ssize_t sent = send(fd, header, (size_t)header_len, 0);
    if (sent != header_len) {
        close(fd);
        return NULL;
    }

    sent = send(fd, body, body_len, 0);
    if (sent != (ssize_t)body_len) {
        close(fd);
        return NULL;
    }

    shutdown(fd, SHUT_WR);

    size_t cap = 16384;
    size_t len = 0;
    char* buf = (char*)malloc(cap);
    if (!buf) {
        close(fd);
        return NULL;
    }

    for (;;) {
        if (len + 4096 > cap) {
            size_t new_cap = cap * 2;
            char* new_buf = (char*)realloc(buf, new_cap);
            if (!new_buf) {
                free(buf);
                close(fd);
                return NULL;
            }
            buf = new_buf;
            cap = new_cap;
        }

        ssize_t n = recv(fd, buf + len, cap - len - 1, 0);
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            free(buf);
            close(fd);
            return NULL;
        }
        len += (size_t)n;
    }
    buf[len] = '\0';
    close(fd);

    const char* body_ptr = strstr(buf, "\r\n\r\n");
    if (!body_ptr) {
        free(buf);
        return NULL;
    }
    body_ptr += 4;

    char* out = strdup(body_ptr);
    free(buf);
    return out;
}

static void
setup_rpc_fixture(void) {
    /* Accounts DB */
    g_accounts_db = sol_accounts_db_new(NULL);
    TEST_ASSERT_NOT_NULL(g_accounts_db);

    fill_pubkey(&g_system_account, 1);
    fill_pubkey(&g_token_mint, 2);
    fill_pubkey(&g_token_owner, 3);
    fill_pubkey(&g_token_account, 4);

    /* System account with lamports */
    sol_account_t* sys_acc = sol_account_new(1234, 0, &SOL_SYSTEM_PROGRAM_ID);
    TEST_ASSERT_NOT_NULL(sys_acc);
    TEST_ASSERT_EQ(sol_accounts_db_store(g_accounts_db, &g_system_account, sys_acc), SOL_OK);
    sol_account_destroy(sys_acc);

    /* Token mint */
    sol_account_t* mint_acc = sol_account_new(1, SOL_TOKEN_MINT_SIZE, &SOL_TOKEN_PROGRAM_ID);
    TEST_ASSERT_NOT_NULL(mint_acc);
    sol_token_mint_t mint = {0};
    mint.is_initialized = true;
    mint.decimals = 6;
    mint.supply = 1000;
    TEST_ASSERT_EQ(sol_token_pack_mint(&mint, mint_acc->data, mint_acc->meta.data_len), SOL_TOKEN_MINT_SIZE);
    TEST_ASSERT_EQ(sol_accounts_db_store(g_accounts_db, &g_token_mint, mint_acc), SOL_OK);
    sol_account_destroy(mint_acc);

    /* Token account */
    sol_account_t* token_acc = sol_account_new(1, SOL_TOKEN_ACCOUNT_SIZE, &SOL_TOKEN_PROGRAM_ID);
    TEST_ASSERT_NOT_NULL(token_acc);
    sol_token_account_t token = {0};
    token.mint = g_token_mint;
    token.owner = g_token_owner;
    token.amount = 42;
    token.state = SOL_TOKEN_ACCOUNT_STATE_INITIALIZED;
    TEST_ASSERT_EQ(sol_token_pack_account(&token, token_acc->data, token_acc->meta.data_len), SOL_TOKEN_ACCOUNT_SIZE);
    TEST_ASSERT_EQ(sol_accounts_db_store(g_accounts_db, &g_token_account, token_acc), SOL_OK);
    sol_account_destroy(token_acc);

    /* Bank + forks */
    sol_bank_t* root_bank = sol_bank_new(123, NULL, g_accounts_db, NULL);
    TEST_ASSERT_NOT_NULL(root_bank);
    g_root_bank = root_bank;

    memset(&g_genesis_hash, 7, sizeof(g_genesis_hash));
    sol_bank_set_genesis_hash(root_bank, &g_genesis_hash);

    /* Seed a deterministic blockhash so getLatestBlockhash is stable. */
    memset(&g_blockhash, 11, sizeof(g_blockhash));
    sol_bank_set_blockhash(root_bank, &g_blockhash);

    g_forks = sol_bank_forks_new(root_bank, NULL);
    TEST_ASSERT_NOT_NULL(g_forks);

    /* Blockstore with a few complete slots */
    g_blockstore = sol_blockstore_new(NULL);
    TEST_ASSERT_NOT_NULL(g_blockstore);

    uint8_t raw = 0;
    for (sol_slot_t slot = 5; slot <= 7; slot++) {
        sol_shred_t shred = {0};
        shred.type = SOL_SHRED_TYPE_DATA;
        shred.slot = slot;
        shred.index = 0;
        shred.header.data.parent_slot = slot > 0 ? slot - 1 : 0;
        shred.header.data.flags = SOL_SHRED_FLAG_LAST_IN_SLOT;
        TEST_ASSERT_EQ(sol_blockstore_insert_shred(g_blockstore, &shred, &raw, sizeof(raw)), SOL_OK);
    }

    /* Start RPC server on an available port */
    for (uint16_t port = 18888; port < 18950; port++) {
        sol_rpc_config_t cfg = SOL_RPC_CONFIG_DEFAULT;
        cfg.port = port;
        cfg.ws_port = 0; /* disable websockets for this suite */

        g_rpc = sol_rpc_new(g_forks, &cfg);
        if (!g_rpc) continue;
        sol_rpc_set_blockstore(g_rpc, g_blockstore);

        fill_pubkey(&g_identity, 9);
        sol_rpc_set_identity(g_rpc, &g_identity);

        if (sol_rpc_start(g_rpc) == SOL_OK) {
            g_port = port;
            break;
        }

        sol_rpc_destroy(g_rpc);
        g_rpc = NULL;
    }

    TEST_ASSERT_NOT_NULL(g_rpc);
    TEST_ASSERT_NE(g_port, 0);

    usleep(10 * 1000);
}

static void
teardown_rpc_fixture(void) {
    if (g_rpc) {
        sol_rpc_stop(g_rpc);
        sol_rpc_destroy(g_rpc);
        g_rpc = NULL;
    }
    if (g_blockstore) {
        sol_blockstore_destroy(g_blockstore);
        g_blockstore = NULL;
    }
    if (g_forks) {
        sol_bank_forks_destroy(g_forks);
        g_forks = NULL;
    }
    g_root_bank = NULL;
    if (g_accounts_db) {
        sol_accounts_db_destroy(g_accounts_db);
        g_accounts_db = NULL;
    }
    g_port = 0;
}

static void
rpc_smoke_call(const char* method, const char* req) {
    char* resp = http_post_json("127.0.0.1", g_port, req, strlen(req));
    TEST_ASSERT_MSG(resp != NULL, "RPC smoke: no response");

    char msg[256];

    snprintf(msg, sizeof(msg), "%s: missing jsonrpc", method);
    TEST_ASSERT_MSG(strstr(resp, "\"jsonrpc\":\"2.0\"") != NULL, msg);

    snprintf(msg, sizeof(msg), "%s: missing id", method);
    TEST_ASSERT_MSG(strstr(resp, "\"id\":") != NULL, msg);

    snprintf(msg, sizeof(msg), "%s: method not found", method);
    TEST_ASSERT_MSG(strstr(resp, "\"code\":-32601") == NULL, msg);

    snprintf(msg, sizeof(msg), "%s: missing result/error", method);
    TEST_ASSERT_MSG(strstr(resp, "\"result\"") != NULL || strstr(resp, "\"error\"") != NULL, msg);

    free(resp);
}

TEST(rpc_id_echo_number) {
    const char* req = "{\"jsonrpc\":\"2.0\",\"id\":12345,\"method\":\"getVersion\"}";
    char* resp = http_post_json("127.0.0.1", g_port, req, strlen(req));
    TEST_ASSERT_NOT_NULL(resp);
    TEST_ASSERT(strstr(resp, "\"id\":12345") != NULL);
    TEST_ASSERT(strstr(resp, "\"id\":\"12345\"") == NULL);
    free(resp);
}

TEST(rpc_id_echo_string) {
    const char* req = "{\"jsonrpc\":\"2.0\",\"id\":\"abc\",\"method\":\"getVersion\"}";
    char* resp = http_post_json("127.0.0.1", g_port, req, strlen(req));
    TEST_ASSERT_NOT_NULL(resp);
    TEST_ASSERT(strstr(resp, "\"id\":\"abc\"") != NULL);
    free(resp);
}

TEST(rpc_invalid_pubkey_errors) {
    const char* req1 = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getBalance\",\"params\":[\"invalid9999\"]}";
    char* resp1 = http_post_json("127.0.0.1", g_port, req1, strlen(req1));
    TEST_ASSERT_NOT_NULL(resp1);
    TEST_ASSERT(strstr(resp1, "\"code\":-32602") != NULL);
    TEST_ASSERT(strstr(resp1, "Invalid param: Invalid") != NULL);
    free(resp1);

    const char* req2 = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"getAccountInfo\",\"params\":[\"invalid9999\"]}";
    char* resp2 = http_post_json("127.0.0.1", g_port, req2, strlen(req2));
    TEST_ASSERT_NOT_NULL(resp2);
    TEST_ASSERT(strstr(resp2, "\"code\":-32602") != NULL);
    TEST_ASSERT(strstr(resp2, "Invalid param: Invalid") != NULL);
    free(resp2);
}

TEST(rpc_get_account_info_missing_is_null) {
    sol_pubkey_t missing;
    fill_pubkey(&missing, 99);
    char missing_str[64];
    sol_pubkey_to_base58(&missing, missing_str, sizeof(missing_str));

    char req[256];
    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getAccountInfo\",\"params\":[\"%s\"]}",
             missing_str);

    char* resp = http_post_json("127.0.0.1", g_port, req, strlen(req));
    TEST_ASSERT_NOT_NULL(resp);
    TEST_ASSERT(strstr(resp, "\"value\":null") != NULL);
    free(resp);
}

TEST(rpc_get_balance_existing) {
    char pk_str[64];
    sol_pubkey_to_base58(&g_system_account, pk_str, sizeof(pk_str));

    char req[256];
    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getBalance\",\"params\":[\"%s\"]}",
             pk_str);

    char* resp = http_post_json("127.0.0.1", g_port, req, strlen(req));
    TEST_ASSERT_NOT_NULL(resp);
    TEST_ASSERT(strstr(resp, "\"value\":1234") != NULL);
    free(resp);
}

TEST(rpc_get_token_account_balance) {
    char pk_str[64];
    sol_pubkey_to_base58(&g_token_account, pk_str, sizeof(pk_str));

    char req[256];
    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getTokenAccountBalance\",\"params\":[\"%s\"]}",
             pk_str);

    char* resp = http_post_json("127.0.0.1", g_port, req, strlen(req));
    TEST_ASSERT_NOT_NULL(resp);
    TEST_ASSERT(strstr(resp, "\"amount\":\"42\"") != NULL);
    TEST_ASSERT(strstr(resp, "\"decimals\":6") != NULL);
    free(resp);
}

TEST(rpc_get_blocks_with_limit) {
    const char* req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getBlocksWithLimit\",\"params\":[5,2]}";
    char* resp = http_post_json("127.0.0.1", g_port, req, strlen(req));
    TEST_ASSERT_NOT_NULL(resp);
    TEST_ASSERT(strstr(resp, "\"result\":[5,6]") != NULL);
    free(resp);
}

TEST(rpc_parse_error_has_null_id) {
    const char* req = "{not json";
    char* resp = http_post_json("127.0.0.1", g_port, req, strlen(req));
    TEST_ASSERT_NOT_NULL(resp);
    TEST_ASSERT(strstr(resp, "\"code\":-32700") != NULL);
    TEST_ASSERT(strstr(resp, "Parse error") != NULL);
    TEST_ASSERT(strstr(resp, "\"id\":null") != NULL);
    free(resp);
}

TEST(rpc_method_not_found) {
    const char* req = "{\"jsonrpc\":\"2.0\",\"id\":77,\"method\":\"noSuchMethod\"}";
    char* resp = http_post_json("127.0.0.1", g_port, req, strlen(req));
    TEST_ASSERT_NOT_NULL(resp);
    TEST_ASSERT(strstr(resp, "\"code\":-32601") != NULL);
    TEST_ASSERT(strstr(resp, "Method not found") != NULL);
    TEST_ASSERT(strstr(resp, "\"id\":77") != NULL);
    free(resp);
}

TEST(rpc_get_health_ok) {
    const char* req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getHealth\"}";
    char* resp = http_post_json("127.0.0.1", g_port, req, strlen(req));
    TEST_ASSERT_NOT_NULL(resp);
    TEST_ASSERT(strstr(resp, "\"result\":\"ok\"") != NULL);
    free(resp);
}

TEST(rpc_get_slot_returns_working_bank_slot) {
    const char* req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getSlot\"}";
    char* resp = http_post_json("127.0.0.1", g_port, req, strlen(req));
    TEST_ASSERT_NOT_NULL(resp);
    TEST_ASSERT(strstr(resp, "\"result\":123") != NULL);
    free(resp);
}

TEST(rpc_get_block_height_returns_tick_height) {
    TEST_ASSERT_NOT_NULL(g_root_bank);
    uint64_t expected = sol_bank_tick_height(g_root_bank);

    char want[64];
    snprintf(want, sizeof(want), "\"result\":%lu", (unsigned long)expected);

    const char* req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getBlockHeight\"}";
    char* resp = http_post_json("127.0.0.1", g_port, req, strlen(req));
    TEST_ASSERT_NOT_NULL(resp);
    TEST_ASSERT(strstr(resp, want) != NULL);
    free(resp);
}

TEST(rpc_get_genesis_hash_matches_fixture) {
    char expected[64];
    hash_to_base58(&g_genesis_hash, expected, sizeof(expected));

    const char* req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getGenesisHash\"}";
    char* resp = http_post_json("127.0.0.1", g_port, req, strlen(req));
    TEST_ASSERT_NOT_NULL(resp);
    TEST_ASSERT(strstr(resp, expected) != NULL);
    free(resp);
}

TEST(rpc_get_identity_matches_fixture) {
    char expected[64];
    sol_pubkey_to_base58(&g_identity, expected, sizeof(expected));

    const char* req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getIdentity\"}";
    char* resp = http_post_json("127.0.0.1", g_port, req, strlen(req));
    TEST_ASSERT_NOT_NULL(resp);
    TEST_ASSERT(strstr(resp, expected) != NULL);
    free(resp);
}

TEST(rpc_get_latest_blockhash_contains_fixture) {
    char expected[64];
    hash_to_base58(&g_blockhash, expected, sizeof(expected));

    const char* req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getLatestBlockhash\"}";
    char* resp = http_post_json("127.0.0.1", g_port, req, strlen(req));
    TEST_ASSERT_NOT_NULL(resp);
    TEST_ASSERT(strstr(resp, "\"blockhash\"") != NULL);
    TEST_ASSERT(strstr(resp, expected) != NULL);
    TEST_ASSERT(strstr(resp, "lastValidBlockHeight") != NULL);
    free(resp);
}

TEST(rpc_get_balance_missing_params_is_error) {
    const char* req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getBalance\"}";
    char* resp = http_post_json("127.0.0.1", g_port, req, strlen(req));
    TEST_ASSERT_NOT_NULL(resp);
    TEST_ASSERT(strstr(resp, "\"code\":-32602") != NULL);
    TEST_ASSERT(strstr(resp, "Expected array") != NULL);
    free(resp);
}

TEST(rpc_all_methods_smoke) {
    /* Precompute commonly-used addresses */
    char system_pk[64];
    char token_mint_pk[64];
    char token_owner_pk[64];
    char token_account_pk[64];
    char token_program_pk[64];
    char blockhash_str[64];

    sol_pubkey_to_base58(&g_system_account, system_pk, sizeof(system_pk));
    sol_pubkey_to_base58(&g_token_mint, token_mint_pk, sizeof(token_mint_pk));
    sol_pubkey_to_base58(&g_token_owner, token_owner_pk, sizeof(token_owner_pk));
    sol_pubkey_to_base58(&g_token_account, token_account_pk, sizeof(token_account_pk));
    sol_pubkey_to_base58(&SOL_TOKEN_PROGRAM_ID, token_program_pk, sizeof(token_program_pk));
    hash_to_base58(&g_blockhash, blockhash_str, sizeof(blockhash_str));

    /* A syntactically-valid signature: 64 zero bytes -> base58 "111...." (64 chars). */
    const char* zero_sig = "1111111111111111111111111111111111111111111111111111111111111111";

    /* Build a minimal, decodable legacy transaction and message */
    uint8_t tx_bytes[256];
    size_t tx_len = build_minimal_legacy_tx(tx_bytes, sizeof(tx_bytes));
    TEST_ASSERT_MSG(tx_len > 0, "Failed to build minimal tx");

    char tx_b64[512];
    TEST_ASSERT_MSG(test_base64_encode(tx_bytes, tx_len, tx_b64, sizeof(tx_b64)) > 0, "Failed to base64-encode tx");

    uint8_t msg_bytes[256];
    size_t msg_len = build_minimal_legacy_message(msg_bytes, sizeof(msg_bytes));
    TEST_ASSERT_MSG(msg_len > 0, "Failed to build minimal message");

    char msg_b64[512];
    TEST_ASSERT_MSG(test_base64_encode(msg_bytes, msg_len, msg_b64, sizeof(msg_b64)) > 0, "Failed to base64-encode message");

    char req[2048];

    /* Core/info */
    rpc_smoke_call("getVersion", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getVersion\"}");
    rpc_smoke_call("getHealth", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getHealth\"}");
    rpc_smoke_call("getSlot", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getSlot\"}");
    rpc_smoke_call("getBlockHeight", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getBlockHeight\"}");
    rpc_smoke_call("getEpochInfo", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getEpochInfo\"}");
    rpc_smoke_call("getEpochSchedule", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getEpochSchedule\"}");
    rpc_smoke_call("getGenesisHash", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getGenesisHash\"}");
    rpc_smoke_call("getIdentity", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getIdentity\"}");

    /* Accounts */
    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getBalance\",\"params\":[\"%s\"]}",
             system_pk);
    rpc_smoke_call("getBalance", req);

    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getAccountInfo\",\"params\":[\"%s\"]}",
             system_pk);
    rpc_smoke_call("getAccountInfo", req);

    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getMultipleAccounts\",\"params\":[[\"%s\",\"%s\"]]}",
             system_pk, token_account_pk);
    rpc_smoke_call("getMultipleAccounts", req);

    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getProgramAccounts\",\"params\":[\"%s\"]}",
             token_program_pk);
    rpc_smoke_call("getProgramAccounts", req);

    /* Token */
    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getTokenAccountBalance\",\"params\":[\"%s\"]}",
             token_account_pk);
    rpc_smoke_call("getTokenAccountBalance", req);

    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getTokenSupply\",\"params\":[\"%s\"]}",
             token_mint_pk);
    rpc_smoke_call("getTokenSupply", req);

    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getTokenLargestAccounts\",\"params\":[\"%s\"]}",
             token_mint_pk);
    rpc_smoke_call("getTokenLargestAccounts", req);

    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getTokenAccountsByOwner\",\"params\":[\"%s\",{\"mint\":\"%s\"}]}",
             token_owner_pk, token_mint_pk);
    rpc_smoke_call("getTokenAccountsByOwner", req);

    /* Blockstore */
    rpc_smoke_call("getLatestBlockhash", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getLatestBlockhash\"}");
    rpc_smoke_call("getFirstAvailableBlock", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getFirstAvailableBlock\"}");
    rpc_smoke_call("getBlocksWithLimit", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getBlocksWithLimit\",\"params\":[5,2]}");
    rpc_smoke_call("getBlocks", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getBlocks\",\"params\":[5,7]}");
    rpc_smoke_call("getBlock", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getBlock\",\"params\":[5]}");
    rpc_smoke_call("getBlockTime", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getBlockTime\",\"params\":[5]}");
    rpc_smoke_call("getBlockCommitment", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getBlockCommitment\",\"params\":[5]}");

    /* Cluster/consensus-ish */
    rpc_smoke_call("getSlotLeader", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getSlotLeader\"}");
    rpc_smoke_call("getLeaderSchedule", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getLeaderSchedule\",\"params\":[123]}");
    rpc_smoke_call("getVoteAccounts", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getVoteAccounts\"}");
    rpc_smoke_call("getClusterNodes", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getClusterNodes\"}");

    /* Inflation/supply */
    rpc_smoke_call("getInflationGovernor", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getInflationGovernor\"}");
    rpc_smoke_call("getInflationRate", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getInflationRate\"}");
    rpc_smoke_call("getSupply", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getSupply\"}");

    /* Fees, rent, status */
    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getMinimumBalanceForRentExemption\",\"params\":[0]}");
    rpc_smoke_call("getMinimumBalanceForRentExemption", req);

    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getFeeForMessage\",\"params\":[\"%s\"]}",
             msg_b64);
    rpc_smoke_call("getFeeForMessage", req);

    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"isBlockhashValid\",\"params\":[\"%s\"]}",
             blockhash_str);
    rpc_smoke_call("isBlockhashValid", req);

    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getStakeActivation\",\"params\":[\"%s\"]}",
             system_pk);
    rpc_smoke_call("getStakeActivation", req);

    rpc_smoke_call("getTransactionCount", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getTransactionCount\"}");
    rpc_smoke_call("getRecentPrioritizationFees", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getRecentPrioritizationFees\"}");

    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getSignaturesForAddress\",\"params\":[\"%s\"]}",
             system_pk);
    rpc_smoke_call("getSignaturesForAddress", req);

    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getSignatureStatuses\",\"params\":[[\"%s\"]]}",
             zero_sig);
    rpc_smoke_call("getSignatureStatuses", req);

    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getTransaction\",\"params\":[\"%s\"]}",
             zero_sig);
    rpc_smoke_call("getTransaction", req);

    /* TX submit/sim */
    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"sendTransaction\",\"params\":[\"%s\"]}",
             tx_b64);
    rpc_smoke_call("sendTransaction", req);

    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"simulateTransaction\",\"params\":[\"%s\"]}",
             tx_b64);
    rpc_smoke_call("simulateTransaction", req);

    /* Misc */
    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"requestAirdrop\",\"params\":[\"%s\",1]}",
             system_pk);
    rpc_smoke_call("requestAirdrop", req);

    rpc_smoke_call("getBlockProduction", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getBlockProduction\"}");
    rpc_smoke_call("getHighestSnapshotSlot", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getHighestSnapshotSlot\"}");

    /* Subscription methods (accountSubscribe/logsSubscribe/...) are websocket-only in practice and
     * intentionally not covered by this HTTP smoke test. */
}

int
main(void) {
    setup_rpc_fixture();

    test_case_t tests[] = {
        TEST_CASE(rpc_id_echo_number),
        TEST_CASE(rpc_id_echo_string),
        TEST_CASE(rpc_invalid_pubkey_errors),
        TEST_CASE(rpc_get_account_info_missing_is_null),
        TEST_CASE(rpc_get_balance_existing),
        TEST_CASE(rpc_get_token_account_balance),
        TEST_CASE(rpc_get_blocks_with_limit),
        TEST_CASE(rpc_parse_error_has_null_id),
        TEST_CASE(rpc_method_not_found),
        TEST_CASE(rpc_get_health_ok),
        TEST_CASE(rpc_get_slot_returns_working_bank_slot),
        TEST_CASE(rpc_get_block_height_returns_tick_height),
        TEST_CASE(rpc_get_genesis_hash_matches_fixture),
        TEST_CASE(rpc_get_identity_matches_fixture),
        TEST_CASE(rpc_get_latest_blockhash_contains_fixture),
        TEST_CASE(rpc_get_balance_missing_params_is_error),
        TEST_CASE(rpc_all_methods_smoke),
    };

    int failed = RUN_TESTS("RPC Conformance (HTTP)", tests);

    teardown_rpc_fixture();
    return failed == 0 ? 0 : 1;
}
