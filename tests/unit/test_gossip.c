/*
 * test_gossip.c - Gossip module unit tests
 *
 * Tests CRDS, bloom filters, and gossip message types.
 */

#include "../test_framework.h"
#include "sol_crds.h"
#include "sol_crds_value.h"
#include "sol_gossip_msg.h"
#include "sol_gossip.h"
#include "sol_alloc.h"
#include "sol_ed25519.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * CRDS Value tests
 */

TEST(crds_value_pubkey) {
    sol_crds_value_t value;
    memset(&value, 0, sizeof(value));

    /* ContactInfo type */
    value.type = SOL_CRDS_CONTACT_INFO;
    for (int i = 0; i < 32; i++) {
        value.data.contact_info.pubkey.bytes[i] = (uint8_t)i;
    }

    const sol_pubkey_t* pk = sol_crds_value_pubkey(&value);
    TEST_ASSERT(pk != NULL);
    TEST_ASSERT_EQ(pk->bytes[0], 0);
    TEST_ASSERT_EQ(pk->bytes[31], 31);
}

TEST(crds_value_wallclock) {
    sol_crds_value_t value;
    memset(&value, 0, sizeof(value));

    value.type = SOL_CRDS_VOTE;
    value.data.vote.wallclock = 1234567890ULL;

    TEST_ASSERT_EQ(sol_crds_value_wallclock(&value), 1234567890ULL);
}

TEST(crds_key_from_value) {
    sol_crds_value_t value;
    memset(&value, 0, sizeof(value));

    value.type = SOL_CRDS_CONTACT_INFO;
    value.data.contact_info.pubkey.bytes[0] = 0xAB;

    sol_crds_key_t key;
    sol_crds_key_from_value(&key, &value);

    TEST_ASSERT_EQ(key.type, SOL_CRDS_CONTACT_INFO);
    TEST_ASSERT_EQ(key.pubkey.bytes[0], 0xAB);
    TEST_ASSERT_EQ(key.index, 0);
}

TEST(crds_type_name) {
    TEST_ASSERT_STR_EQ(sol_crds_type_name(SOL_CRDS_CONTACT_INFO), "ContactInfo");
    TEST_ASSERT_STR_EQ(sol_crds_type_name(SOL_CRDS_VOTE), "Vote");
    TEST_ASSERT_STR_EQ(sol_crds_type_name(SOL_CRDS_VERSION), "Version");
}

TEST(contact_info_add_socket_replaces_tag) {
    sol_contact_info_t ci;
    sol_contact_info_init(&ci);

    sol_sockaddr_t a;
    sol_sockaddr_t b;
    TEST_ASSERT_EQ(sol_sockaddr_init(&a, "1.2.3.4", 8001), SOL_OK);
    TEST_ASSERT_EQ(sol_sockaddr_init(&b, "1.2.3.4", 8004), SOL_OK);

    TEST_ASSERT_EQ(sol_contact_info_add_socket(&ci, SOL_SOCKET_TAG_TVU, &a), SOL_OK);
    TEST_ASSERT_EQ(ci.num_sockets, 1);
    TEST_ASSERT_EQ(sol_sockaddr_port(&ci.sockets[0].addr), 8001);

    /* Same tag should replace the existing entry, not append. */
    TEST_ASSERT_EQ(sol_contact_info_add_socket(&ci, SOL_SOCKET_TAG_TVU, &b), SOL_OK);
    TEST_ASSERT_EQ(ci.num_sockets, 1);
    TEST_ASSERT_EQ(sol_sockaddr_port(&ci.sockets[0].addr), 8004);
}

/*
 * CRDS Store tests
 */

TEST(crds_create_destroy) {
    sol_crds_t* crds = sol_crds_new(0);
    TEST_ASSERT(crds != NULL);
    TEST_ASSERT_EQ(sol_crds_len(crds), 0);
    sol_crds_destroy(crds);
}

TEST(crds_insert_lookup) {
    sol_crds_t* crds = sol_crds_new(100);
    TEST_ASSERT(crds != NULL);

    /* Create a contact info value */
    sol_crds_value_t value;
    memset(&value, 0, sizeof(value));
    value.type = SOL_CRDS_CONTACT_INFO;
    value.data.contact_info.wallclock = 1000;
    value.data.contact_info.pubkey.bytes[0] = 0x42;

    /* Insert */
    sol_pubkey_t origin;
    sol_pubkey_init(&origin);
    sol_err_t err = sol_crds_insert(crds, &value, &origin, 1000);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_EQ(sol_crds_len(crds), 1);

    /* Lookup by key */
    sol_crds_key_t key;
    sol_crds_key_from_value(&key, &value);
    const sol_crds_entry_t* entry = sol_crds_get(crds, &key);
    TEST_ASSERT(entry != NULL);
    TEST_ASSERT_EQ(entry->value.type, SOL_CRDS_CONTACT_INFO);
    TEST_ASSERT_EQ(entry->value.data.contact_info.pubkey.bytes[0], 0x42);

    sol_crds_destroy(crds);
}

TEST(crds_get_contact_info) {
    sol_crds_t* crds = sol_crds_new(100);

    sol_crds_value_t value;
    memset(&value, 0, sizeof(value));
    value.type = SOL_CRDS_CONTACT_INFO;
    value.data.contact_info.wallclock = 1000;
    value.data.contact_info.shred_version = 12345;
    for (int i = 0; i < 32; i++) {
        value.data.contact_info.pubkey.bytes[i] = (uint8_t)(i + 1);
    }

    sol_crds_insert(crds, &value, NULL, 1000);

    /* Lookup by pubkey */
    const sol_contact_info_t* ci = sol_crds_get_contact_info(
        crds, &value.data.contact_info.pubkey);
    TEST_ASSERT(ci != NULL);
    TEST_ASSERT_EQ(ci->shred_version, 12345);
    TEST_ASSERT_EQ(ci->pubkey.bytes[0], 1);

    sol_crds_destroy(crds);
}

TEST(crds_update_newer) {
    sol_crds_t* crds = sol_crds_new(100);

    sol_crds_value_t value;
    memset(&value, 0, sizeof(value));
    value.type = SOL_CRDS_CONTACT_INFO;
    value.data.contact_info.wallclock = 1000;
    value.data.contact_info.shred_version = 100;

    sol_crds_insert(crds, &value, NULL, 1000);

    /* Update with newer value */
    value.data.contact_info.wallclock = 2000;
    value.data.contact_info.shred_version = 200;
    sol_err_t err = sol_crds_insert(crds, &value, NULL, 2000);
    TEST_ASSERT_EQ(err, SOL_OK);

    /* Verify update */
    sol_crds_key_t key;
    sol_crds_key_from_value(&key, &value);
    const sol_crds_entry_t* entry = sol_crds_get(crds, &key);
    TEST_ASSERT(entry != NULL);
    TEST_ASSERT_EQ(entry->value.data.contact_info.shred_version, 200);

    sol_crds_destroy(crds);
}

TEST(crds_reject_stale) {
    sol_crds_t* crds = sol_crds_new(100);

    sol_crds_value_t value;
    memset(&value, 0, sizeof(value));
    value.type = SOL_CRDS_CONTACT_INFO;
    value.data.contact_info.wallclock = 2000;

    sol_crds_insert(crds, &value, NULL, 2000);

    /* Try to insert older value */
    value.data.contact_info.wallclock = 1000;
    sol_err_t err = sol_crds_insert(crds, &value, NULL, 2000);
    TEST_ASSERT_EQ(err, SOL_ERR_STALE);

    sol_crds_destroy(crds);
}

TEST(crds_reject_duplicate) {
    sol_crds_t* crds = sol_crds_new(100);

    sol_crds_value_t value;
    memset(&value, 0, sizeof(value));
    value.type = SOL_CRDS_CONTACT_INFO;
    value.data.contact_info.wallclock = 1000;

    sol_crds_insert(crds, &value, NULL, 1000);

    /* Try to insert duplicate */
    sol_err_t err = sol_crds_insert(crds, &value, NULL, 1000);
    TEST_ASSERT_EQ(err, SOL_ERR_EXISTS);

    sol_crds_destroy(crds);
}

TEST(crds_prune) {
    sol_crds_t* crds = sol_crds_new(100);

    /* Insert 5 values at different times */
    for (int i = 0; i < 5; i++) {
        sol_crds_value_t value;
        memset(&value, 0, sizeof(value));
        value.type = SOL_CRDS_CONTACT_INFO;
        value.data.contact_info.wallclock = (uint64_t)i;
        value.data.contact_info.pubkey.bytes[0] = (uint8_t)i;

        sol_crds_insert(crds, &value, NULL, (uint64_t)(i * 100));
    }

    TEST_ASSERT_EQ(sol_crds_len(crds), 5);

    /* Prune entries older than time 250 */
    size_t pruned = sol_crds_prune(crds, 500, 250);
    TEST_ASSERT_EQ(pruned, 3);  /* Entries at 0, 100, 200 should be pruned */
    TEST_ASSERT_EQ(sol_crds_len(crds), 2);

    sol_crds_destroy(crds);
}

/*
 * Bloom filter tests
 */

TEST(bloom_init) {
    sol_bloom_t bloom;
    sol_bloom_init(&bloom);
    TEST_ASSERT_EQ(bloom.num_bits_set, 0);
}

TEST(bloom_add_contains) {
    sol_bloom_t bloom;
    sol_bloom_init(&bloom);

    uint8_t key1[] = "hello";
    uint8_t key2[] = "world";

    sol_bloom_add(&bloom, key1, 5);
    sol_bloom_add(&bloom, key2, 5);

    TEST_ASSERT(sol_bloom_contains(&bloom, key1, 5));
    TEST_ASSERT(sol_bloom_contains(&bloom, key2, 5));
}

TEST(bloom_clear) {
    sol_bloom_t bloom;
    sol_bloom_init(&bloom);

    uint8_t key[] = "test";
    sol_bloom_add(&bloom, key, 4);
    TEST_ASSERT(bloom.num_bits_set > 0);

    sol_bloom_clear(&bloom);
    TEST_ASSERT_EQ(bloom.num_bits_set, 0);
}

/*
 * Ping/Pong tests
 */

TEST(ping_create) {
    sol_ping_t ping;
    sol_pubkey_t from;
    uint8_t token[32];

    for (int i = 0; i < 32; i++) {
        from.bytes[i] = (uint8_t)i;
        token[i] = (uint8_t)(255 - i);
    }

    sol_err_t err = sol_ping_create(&ping, &from, token);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT(sol_pubkey_eq(&ping.from, &from));
    TEST_ASSERT_MEM_EQ(ping.token.bytes, token, 32);
}

TEST(pong_create) {
    sol_ping_t ping;
    sol_pong_t pong;
    sol_pubkey_t from;
    uint8_t token[32];

    for (int i = 0; i < 32; i++) {
        from.bytes[i] = (uint8_t)i;
        token[i] = (uint8_t)(255 - i);
    }

    sol_ping_create(&ping, &from, token);

    sol_pubkey_t responder;
    memset(&responder, 0xAA, 32);

    sol_err_t err = sol_pong_create(&pong, &responder, &ping);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT(sol_pubkey_eq(&pong.from, &responder));
}

TEST(pong_verify_hash) {
    sol_ping_t ping;
    sol_pong_t pong;
    uint8_t token[32];
    uint8_t seed[32];

    /* Create deterministic seed for keypair */
    for (int i = 0; i < 32; i++) {
        seed[i] = (uint8_t)i;
        token[i] = (uint8_t)i;
    }

    /* Generate keypair from seed */
    sol_keypair_t keypair;
    sol_ed25519_keypair_from_seed(seed, &keypair);

    /* Extract pubkey for ping/pong */
    sol_pubkey_t from;
    sol_ed25519_pubkey_from_keypair(&keypair, &from);

    sol_ping_create(&ping, &from, token);
    sol_pong_create(&pong, &from, &ping);

    /* Sign the pong */
    sol_pong_sign(&pong, &keypair);

    /* Verify pong hash matches ping token hash and signature is valid */
    TEST_ASSERT(sol_pong_verify(&pong, &ping));
}

TEST(ping_verify) {
    sol_ping_t ping;
    uint8_t token[32];
    uint8_t seed[32];

    /* Create deterministic seed for keypair */
    for (int i = 0; i < 32; i++) {
        seed[i] = (uint8_t)(i + 100);
        token[i] = (uint8_t)(i * 2);
    }

    /* Generate keypair from seed */
    sol_keypair_t keypair;
    sol_ed25519_keypair_from_seed(seed, &keypair);

    /* Extract pubkey for ping */
    sol_pubkey_t from;
    sol_ed25519_pubkey_from_keypair(&keypair, &from);

    sol_ping_create(&ping, &from, token);

    /* Sign the ping */
    sol_ping_sign(&ping, &keypair);

    /* Verify ping signature */
    TEST_ASSERT(sol_ping_verify(&ping));

    /* Tamper with token - verification should fail */
    ping.token.bytes[0] ^= 0xFF;
    TEST_ASSERT(!sol_ping_verify(&ping));
}

/*
 * Message type name tests
 */

TEST(gossip_msg_type_name) {
    TEST_ASSERT_STR_EQ(sol_gossip_msg_type_name(SOL_GOSSIP_MSG_PING), "Ping");
    TEST_ASSERT_STR_EQ(sol_gossip_msg_type_name(SOL_GOSSIP_MSG_PONG), "Pong");
    TEST_ASSERT_STR_EQ(sol_gossip_msg_type_name(SOL_GOSSIP_MSG_PUSH), "Push");
}

/*
 * Contact info socket tests
 */

TEST(contact_info_socket) {
    sol_contact_info_t ci;
    sol_contact_info_init(&ci);

    sol_sockaddr_t addr;
    sol_sockaddr_init(&addr, "192.168.1.1", 8001);

    sol_err_t err = sol_contact_info_add_socket(&ci, SOL_SOCKET_TAG_GOSSIP, &addr);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_EQ(ci.num_sockets, 1);

    const sol_sockaddr_t* found = sol_contact_info_socket(&ci, SOL_SOCKET_TAG_GOSSIP);
    TEST_ASSERT(found != NULL);
    TEST_ASSERT_EQ(sol_sockaddr_port(found), 8001);

    /* Non-existent socket */
    found = sol_contact_info_socket(&ci, SOL_SOCKET_TAG_RPC);
    TEST_ASSERT(found == NULL);
}

/*
 * Gossip service tests
 */

TEST(gossip_create_destroy) {
    sol_gossip_config_t config = SOL_GOSSIP_CONFIG_DEFAULT;

    /* Generate a keypair */
    sol_ed25519_keypair_generate(&config.identity);
    config.gossip_port = 0;  /* Use any available port */

    sol_gossip_t* gossip = sol_gossip_new(&config);
    TEST_ASSERT(gossip != NULL);

    /* Check pubkey extraction */
    const sol_pubkey_t* pk = sol_gossip_pubkey(gossip);
    TEST_ASSERT(pk != NULL);

    /* Check CRDS access */
    sol_crds_t* crds = sol_gossip_crds(gossip);
    TEST_ASSERT(crds != NULL);

    /* Check self contact info */
    const sol_contact_info_t* self = sol_gossip_self(gossip);
    TEST_ASSERT(self != NULL);
    TEST_ASSERT(sol_pubkey_eq(&self->pubkey, pk));

    /* Check initial peer count */
    TEST_ASSERT_EQ(sol_gossip_num_peers(gossip), 0);

    sol_gossip_destroy(gossip);
}

TEST(gossip_default_config) {
    /* Create with NULL config (uses defaults) */
    sol_gossip_t* gossip = sol_gossip_new(NULL);
    TEST_ASSERT(gossip != NULL);

    /* All-zero pubkey expected with default config */
    TEST_ASSERT_EQ(sol_gossip_num_peers(gossip), 0);

    sol_gossip_destroy(gossip);
}

TEST(gossip_add_entrypoint) {
    sol_gossip_config_t config = SOL_GOSSIP_CONFIG_DEFAULT;
    sol_ed25519_keypair_generate(&config.identity);

    sol_gossip_t* gossip = sol_gossip_new(&config);
    TEST_ASSERT(gossip != NULL);

    /* Add an entrypoint */
    sol_sockaddr_t ep;
    sol_sockaddr_init(&ep, "127.0.0.1", 8001);
    sol_err_t err = sol_gossip_add_entrypoint(gossip, &ep);
    TEST_ASSERT_EQ(err, SOL_OK);

    /* Add another */
    sol_sockaddr_init(&ep, "127.0.0.1", 8002);
    err = sol_gossip_add_entrypoint(gossip, &ep);
    TEST_ASSERT_EQ(err, SOL_OK);

    sol_gossip_destroy(gossip);
}

TEST(gossip_stats) {
    sol_gossip_config_t config = SOL_GOSSIP_CONFIG_DEFAULT;
    sol_ed25519_keypair_generate(&config.identity);

    sol_gossip_t* gossip = sol_gossip_new(&config);
    TEST_ASSERT(gossip != NULL);

    /* Get initial stats */
    sol_gossip_stats_t stats;
    sol_gossip_stats(gossip, &stats);
    TEST_ASSERT_EQ(stats.msgs_sent, 0);
    TEST_ASSERT_EQ(stats.msgs_received, 0);

    /* Reset stats */
    sol_gossip_stats_reset(gossip);
    sol_gossip_stats(gossip, &stats);
    TEST_ASSERT_EQ(stats.msgs_sent, 0);

    sol_gossip_destroy(gossip);
}

TEST(gossip_value_callback) {
    sol_gossip_config_t config = SOL_GOSSIP_CONFIG_DEFAULT;
    sol_ed25519_keypair_generate(&config.identity);

    sol_gossip_t* gossip = sol_gossip_new(&config);
    TEST_ASSERT(gossip != NULL);

    /* Set callback (just test that it doesn't crash) */
    int callback_data = 42;
    sol_gossip_set_value_callback(gossip, NULL, &callback_data);

    sol_gossip_destroy(gossip);
}

TEST(gossip_push_value) {
    sol_gossip_config_t config = SOL_GOSSIP_CONFIG_DEFAULT;
    sol_ed25519_keypair_generate(&config.identity);

    sol_gossip_t* gossip = sol_gossip_new(&config);
    TEST_ASSERT(gossip != NULL);

    /* Create a value */
    sol_crds_value_t value;
    memset(&value, 0, sizeof(value));
    value.type = SOL_CRDS_VERSION;
    value.data.version.major = 1;
    value.data.version.minor = 18;
    value.data.version.wallclock = sol_gossip_now_ms();

    /* Push it */
    sol_err_t err = sol_gossip_push_value(gossip, &value);
    TEST_ASSERT_EQ(err, SOL_OK);

    /* Check stats */
    sol_gossip_stats_t stats;
    sol_gossip_stats(gossip, &stats);
    TEST_ASSERT_EQ(stats.pushes_sent, 1);

    sol_gossip_destroy(gossip);
}

TEST(gossip_start_port_fallback_on_eaddrinuse) {
    /* Hold a UDP port open without SO_REUSEADDR so gossip binding fails
     * deterministically with EADDRINUSE. */
    int hold_fd = -1;
    uint16_t hold_port = 0;

    for (int attempt = 0; attempt < 32; attempt++) {
        int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fd < 0) continue;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons(0);

        if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
            close(fd);
            continue;
        }

        struct sockaddr_in bound;
        socklen_t bound_len = sizeof(bound);
        if (getsockname(fd, (struct sockaddr*)&bound, &bound_len) != 0) {
            close(fd);
            continue;
        }

        uint16_t p = ntohs(bound.sin_port);
        if (p != 0 && p <= (uint16_t)(UINT16_MAX - 2000U - 1U)) {
            hold_fd = fd;
            hold_port = p;
            break;
        }

        close(fd);
    }

    TEST_ASSERT(hold_fd >= 0);
    TEST_ASSERT(hold_port != 0);

    sol_gossip_config_t config = SOL_GOSSIP_CONFIG_DEFAULT;
    sol_ed25519_keypair_generate(&config.identity);
    config.gossip_port = hold_port;
    config.tpu_port = 0;
    config.tpu_quic_port = 0;
    config.tvu_port = 0;
    config.serve_repair_port = 0;
    config.rpc_port = 0;

    sol_gossip_t* gossip = sol_gossip_new(&config);
    TEST_ASSERT(gossip != NULL);

    sol_err_t err = sol_gossip_start(gossip);
    TEST_ASSERT_EQ(err, SOL_OK);

    const sol_contact_info_t* self = sol_gossip_self(gossip);
    TEST_ASSERT(self != NULL);
    const sol_sockaddr_t* bound = sol_contact_info_socket(self, SOL_SOCKET_TAG_GOSSIP);
    TEST_ASSERT(bound != NULL);

    uint16_t actual = sol_sockaddr_port(bound);
    TEST_ASSERT(actual != 0);
    TEST_ASSERT(actual != hold_port);

    close(hold_fd);

    sol_gossip_stop(gossip);
    sol_gossip_destroy(gossip);
}

/*
 * Test runner
 */
static test_case_t gossip_tests[] = {
    TEST_CASE(crds_value_pubkey),
    TEST_CASE(crds_value_wallclock),
    TEST_CASE(crds_key_from_value),
    TEST_CASE(crds_type_name),
    TEST_CASE(contact_info_add_socket_replaces_tag),
    TEST_CASE(crds_create_destroy),
    TEST_CASE(crds_insert_lookup),
    TEST_CASE(crds_get_contact_info),
    TEST_CASE(crds_update_newer),
    TEST_CASE(crds_reject_stale),
    TEST_CASE(crds_reject_duplicate),
    TEST_CASE(crds_prune),
    TEST_CASE(bloom_init),
    TEST_CASE(bloom_add_contains),
    TEST_CASE(bloom_clear),
    TEST_CASE(ping_create),
    TEST_CASE(pong_create),
    TEST_CASE(pong_verify_hash),
    TEST_CASE(ping_verify),
    TEST_CASE(gossip_msg_type_name),
    TEST_CASE(contact_info_socket),
    /* Gossip service tests */
    TEST_CASE(gossip_create_destroy),
    TEST_CASE(gossip_default_config),
    TEST_CASE(gossip_add_entrypoint),
    TEST_CASE(gossip_stats),
    TEST_CASE(gossip_value_callback),
    TEST_CASE(gossip_push_value),
    TEST_CASE(gossip_start_port_fallback_on_eaddrinuse),
};

int main(void) {
    int result = RUN_TESTS("Gossip Tests", gossip_tests);
    sol_alloc_dump_leaks();
    return result;
}
