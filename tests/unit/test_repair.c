/*
 * test_repair.c - Repair module unit tests
 */

#include "../test_framework.h"
#include "sol_repair.h"
#include "sol_alloc.h"
#include "sol_log.h"
#include "sol_gossip.h"
#include "sol_crds.h"
#include "sol_crds_value.h"
#include "sol_ed25519.h"
#include "sol_shred.h"
#include "sol_bits.h"
#include "sol_udp.h"
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/*
 * Repair creation tests
 */

TEST(repair_create_destroy) {
    sol_repair_config_t config = SOL_REPAIR_CONFIG_DEFAULT;

    sol_keypair_t identity;
    sol_ed25519_keypair_generate(&identity);

    sol_repair_t* repair = sol_repair_new(&config, NULL, &identity);
    TEST_ASSERT(repair != NULL);

    sol_repair_destroy(repair);
}

TEST(repair_create_null_config) {
    sol_keypair_t identity;
    sol_ed25519_keypair_generate(&identity);

    /* NULL config should use defaults */
    sol_repair_t* repair = sol_repair_new(NULL, NULL, &identity);
    TEST_ASSERT(repair != NULL);

    sol_repair_destroy(repair);
}

TEST(repair_create_null_identity) {
    sol_repair_config_t config = SOL_REPAIR_CONFIG_DEFAULT;

    /* NULL identity is allowed */
    sol_repair_t* repair = sol_repair_new(&config, NULL, NULL);
    TEST_ASSERT(repair != NULL);

    sol_repair_destroy(repair);
}

/*
 * Repair lifecycle tests
 */

static int
udp_available(void) {
    sol_udp_config_t cfg = SOL_UDP_CONFIG_DEFAULT;
    cfg.bind_port = 0;

    sol_udp_sock_t* sock = sol_udp_new(&cfg);
    if (sock != NULL) {
        sol_udp_destroy(sock);
        return 1;
    }

    if (errno == EPERM || errno == EACCES) {
        return 0;
    }

    return -1;
}

static int g_shred_cb_called = 0;
static sol_slot_t g_shred_cb_slot = 0;
static uint32_t g_shred_cb_index = 0;

static void
test_repair_shred_callback(const sol_shred_t* shred, void* ctx) {
    (void)ctx;
    if (!shred) {
        return;
    }
    g_shred_cb_called++;
    g_shred_cb_slot = shred->slot;
    g_shred_cb_index = shred->index;
}

static bool
send_udp_payload(const uint8_t* data, size_t len, uint16_t port) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return false;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    ssize_t sent = sendto(sock, data, len, 0, (struct sockaddr*)&addr, sizeof(addr));
    close(sock);
    return sent == (ssize_t)len;
}

TEST(repair_start_stop) {
    int udp = udp_available();
    if (udp == 0) {
        TEST_SKIP("UDP sockets not permitted in this environment");
    }
    TEST_ASSERT_MSG(udp > 0, "Failed to create UDP socket for repair tests");

    sol_repair_config_t config = SOL_REPAIR_CONFIG_DEFAULT;

    sol_keypair_t identity;
    sol_ed25519_keypair_generate(&identity);

    sol_repair_t* repair = sol_repair_new(&config, NULL, &identity);
    TEST_ASSERT(repair != NULL);

    /* Start should succeed */
    sol_err_t err = sol_repair_start(repair, 0);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT(sol_repair_is_running(repair));

    /* Stop */
    sol_repair_stop(repair);
    TEST_ASSERT(!sol_repair_is_running(repair));

    sol_repair_destroy(repair);
}

TEST(repair_double_start) {
    int udp = udp_available();
    if (udp == 0) {
        TEST_SKIP("UDP sockets not permitted in this environment");
    }
    TEST_ASSERT_MSG(udp > 0, "Failed to create UDP socket for repair tests");

    sol_repair_config_t config = SOL_REPAIR_CONFIG_DEFAULT;

    sol_keypair_t identity;
    sol_ed25519_keypair_generate(&identity);

    sol_repair_t* repair = sol_repair_new(&config, NULL, &identity);
    TEST_ASSERT(repair != NULL);

    /* First start */
    sol_err_t err = sol_repair_start(repair, 0);
    TEST_ASSERT_EQ(err, SOL_OK);

    /* Second start should be OK (idempotent) */
    err = sol_repair_start(repair, 0);
    TEST_ASSERT_EQ(err, SOL_OK);

    sol_repair_destroy(repair);
}

/*
 * Request tests (without gossip - will fail to find peers)
 */

TEST(repair_request_shred_no_peers) {
    int udp = udp_available();
    if (udp == 0) {
        TEST_SKIP("UDP sockets not permitted in this environment");
    }
    TEST_ASSERT_MSG(udp > 0, "Failed to create UDP socket for repair tests");

    sol_repair_config_t config = SOL_REPAIR_CONFIG_DEFAULT;

    sol_keypair_t identity;
    sol_ed25519_keypair_generate(&identity);

    sol_repair_t* repair = sol_repair_new(&config, NULL, &identity);
    TEST_ASSERT(repair != NULL);

    sol_err_t err = sol_repair_start(repair, 0);
    TEST_ASSERT_EQ(err, SOL_OK);

    /* Request should fail - no peers available */
    err = sol_repair_request_shred(repair, 1000, 5, true);
    TEST_ASSERT_EQ(err, SOL_ERR_PEER_UNAVAILABLE);

    sol_repair_destroy(repair);
}

TEST(repair_request_highest_no_peers) {
    int udp = udp_available();
    if (udp == 0) {
        TEST_SKIP("UDP sockets not permitted in this environment");
    }
    TEST_ASSERT_MSG(udp > 0, "Failed to create UDP socket for repair tests");

    sol_repair_config_t config = SOL_REPAIR_CONFIG_DEFAULT;

    sol_keypair_t identity;
    sol_ed25519_keypair_generate(&identity);

    sol_repair_t* repair = sol_repair_new(&config, NULL, &identity);
    TEST_ASSERT(repair != NULL);

    sol_err_t err = sol_repair_start(repair, 0);
    TEST_ASSERT_EQ(err, SOL_OK);

    /* Request should fail - no peers available */
    err = sol_repair_request_highest(repair, 1000, 0);
    TEST_ASSERT_EQ(err, SOL_ERR_PEER_UNAVAILABLE);

    sol_repair_destroy(repair);
}

TEST(repair_request_orphan_no_peers) {
    int udp = udp_available();
    if (udp == 0) {
        TEST_SKIP("UDP sockets not permitted in this environment");
    }
    TEST_ASSERT_MSG(udp > 0, "Failed to create UDP socket for repair tests");

    sol_repair_config_t config = SOL_REPAIR_CONFIG_DEFAULT;

    sol_keypair_t identity;
    sol_ed25519_keypair_generate(&identity);

    sol_repair_t* repair = sol_repair_new(&config, NULL, &identity);
    TEST_ASSERT(repair != NULL);

    sol_err_t err = sol_repair_start(repair, 0);
    TEST_ASSERT_EQ(err, SOL_OK);

    /* Request should fail - no peers available */
    err = sol_repair_request_orphan(repair, 1000);
    TEST_ASSERT_EQ(err, SOL_ERR_PEER_UNAVAILABLE);

    sol_repair_destroy(repair);
}

TEST(repair_response_bincode_shred_unwrap) {
    int udp = udp_available();
    if (udp == 0) {
        TEST_SKIP("UDP sockets not permitted in this environment");
    }
    TEST_ASSERT_MSG(udp > 0, "Failed to create UDP socket for repair tests");

    sol_repair_config_t config = SOL_REPAIR_CONFIG_DEFAULT;
    config.serve_repairs = false;

    sol_keypair_t identity;
    sol_ed25519_keypair_generate(&identity);

    sol_repair_t* repair = sol_repair_new(&config, NULL, &identity);
    TEST_ASSERT(repair != NULL);

    sol_repair_set_shred_callback(repair, test_repair_shred_callback, NULL);

    sol_err_t err = sol_repair_start(repair, 0);
    TEST_ASSERT_EQ(err, SOL_OK);

    sol_sockaddr_t local_addr;
    err = sol_repair_local_addr(repair, &local_addr);
    TEST_ASSERT_EQ(err, SOL_OK);

    uint16_t port = sol_sockaddr_port(&local_addr);
    TEST_ASSERT_MSG(port != 0, "Failed to resolve repair socket port");

    sol_keypair_t leader;
    sol_ed25519_keypair_generate(&leader);

    uint8_t shred_buf[SOL_SHRED_SIZE];
    size_t shred_len = 0;
    const uint8_t payload[] = { 0x01, 0x02, 0x03, 0x04 };
    err = sol_shred_build_legacy_data(&leader,
                                      500,
                                      499,
                                      3,
                                      1,
                                      3,
                                      0,
                                      payload,
                                      sizeof(payload),
                                      shred_buf,
                                      sizeof(shred_buf),
                                      &shred_len);
    TEST_ASSERT_EQ(err, SOL_OK);

    uint8_t pkt[4 + 8 + SOL_SHRED_SIZE + 4];
    size_t pkt_len = 0;
    sol_store_u32_le(pkt + pkt_len, 2u);
    pkt_len += 4;
    sol_store_u64_le(pkt + pkt_len, (uint64_t)shred_len);
    pkt_len += 8;
    memcpy(pkt + pkt_len, shred_buf, shred_len);
    pkt_len += shred_len;
    sol_store_u32_le(pkt + pkt_len, 0xA1B2C3D4u);
    pkt_len += 4;

    g_shred_cb_called = 0;
    g_shred_cb_slot = 0;
    g_shred_cb_index = 0;

    TEST_ASSERT(send_udp_payload(pkt, pkt_len, port));

    for (int i = 0; i < 10 && g_shred_cb_called == 0; i++) {
        sol_repair_run_once(repair, 0);
        usleep(1000);
    }

    TEST_ASSERT_EQ(g_shred_cb_called, 1);
    TEST_ASSERT_EQ(g_shred_cb_slot, 500);
    TEST_ASSERT_EQ(g_shred_cb_index, 3);

    sol_repair_destroy(repair);
}

/*
 * Prioritization tests
 */

TEST(repair_prioritization_evict_low_priority) {
    int udp = udp_available();
    if (udp == 0) {
        TEST_SKIP("UDP sockets not permitted in this environment");
    }
    TEST_ASSERT_MSG(udp > 0, "Failed to create UDP socket for repair tests");

    /* Create a gossip instance and inject a contact with a serve_repair socket */
    sol_gossip_config_t gossip_config = SOL_GOSSIP_CONFIG_DEFAULT;
    sol_ed25519_keypair_generate(&gossip_config.identity);
    sol_gossip_t* gossip = sol_gossip_new(&gossip_config);
    TEST_ASSERT(gossip != NULL);

    sol_crds_t* crds = sol_gossip_crds(gossip);
    TEST_ASSERT(crds != NULL);

    sol_crds_value_t val = {0};
    val.type = SOL_CRDS_CONTACT_INFO;
    sol_contact_info_t* ci = &val.data.contact_info;
    sol_contact_info_init(ci);
    memset(ci->pubkey.bytes, 0x99, 32);
    ci->wallclock = sol_gossip_now_ms();

    sol_sockaddr_t serve_repair_addr = {0};
    serve_repair_addr.addr.sin.sin_family = AF_INET;
    serve_repair_addr.addr.sin.sin_port = htons(12345);
    inet_pton(AF_INET, "127.0.0.1", &serve_repair_addr.addr.sin.sin_addr);
    serve_repair_addr.len = sizeof(struct sockaddr_in);

    sol_err_t err = sol_contact_info_add_socket(
        ci, SOL_SOCKET_TAG_SERVE_REPAIR, &serve_repair_addr);
    TEST_ASSERT_EQ(err, SOL_OK);

    err = sol_crds_insert(crds, &val, NULL, ci->wallclock);
    TEST_ASSERT_EQ(err, SOL_OK);

    sol_repair_config_t config = SOL_REPAIR_CONFIG_DEFAULT;
    config.max_pending_requests = 2;
    config.serve_repairs = false;

    sol_keypair_t identity;
    sol_ed25519_keypair_generate(&identity);

    sol_repair_t* repair = sol_repair_new(&config, gossip, &identity);
    TEST_ASSERT(repair != NULL);

    err = sol_repair_start(repair, 0);
    TEST_ASSERT_EQ(err, SOL_OK);

    /* Fill queue with low-priority requests */
    err = sol_repair_request_ancestor_hashes(repair, 100);
    TEST_ASSERT_EQ(err, SOL_OK);
    err = sol_repair_request_ancestor_hashes(repair, 101);
    TEST_ASSERT_EQ(err, SOL_OK);

    /* High-priority shred request should evict a lower-priority pending request */
    err = sol_repair_request_shred(repair, 200, 1, true);
    TEST_ASSERT_EQ(err, SOL_OK);

    sol_repair_destroy(repair);
    sol_gossip_destroy(gossip);
}

TEST(repair_request_wire_format_signed) {
    int udp = udp_available();
    if (udp == 0) {
        TEST_SKIP("UDP sockets not permitted in this environment");
    }
    TEST_ASSERT_MSG(udp > 0, "Failed to create UDP socket for repair tests");

    /* Bind a UDP socket to receive the outgoing repair request. */
    int recv_fd = socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT_MSG(recv_fd >= 0, "Failed to create UDP recv socket");

    struct sockaddr_in recv_addr;
    memset(&recv_addr, 0, sizeof(recv_addr));
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_port = htons(0);
    recv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    TEST_ASSERT_MSG(bind(recv_fd, (struct sockaddr*)&recv_addr, sizeof(recv_addr)) == 0,
                    "Failed to bind UDP recv socket");

    socklen_t recv_len = sizeof(recv_addr);
    TEST_ASSERT_MSG(getsockname(recv_fd, (struct sockaddr*)&recv_addr, &recv_len) == 0,
                    "Failed to getsockname UDP recv socket");

    struct timeval tv = {0};
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    (void)setsockopt(recv_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Create a gossip instance and inject a contact with a serve_repair socket. */
    sol_gossip_config_t gossip_config = SOL_GOSSIP_CONFIG_DEFAULT;
    sol_ed25519_keypair_generate(&gossip_config.identity);
    sol_gossip_t* gossip = sol_gossip_new(&gossip_config);
    TEST_ASSERT(gossip != NULL);

    sol_crds_t* crds = sol_gossip_crds(gossip);
    TEST_ASSERT(crds != NULL);

    sol_crds_value_t val = {0};
    val.type = SOL_CRDS_CONTACT_INFO;
    sol_contact_info_t* ci = &val.data.contact_info;
    sol_contact_info_init(ci);
    memset(ci->pubkey.bytes, 0x77, 32);
    ci->wallclock = sol_gossip_now_ms();

    sol_sockaddr_t serve_repair_addr = {0};
    serve_repair_addr.addr.sin.sin_family = AF_INET;
    serve_repair_addr.addr.sin.sin_port = recv_addr.sin_port;
    inet_pton(AF_INET, "127.0.0.1", &serve_repair_addr.addr.sin.sin_addr);
    serve_repair_addr.len = sizeof(struct sockaddr_in);

    sol_err_t err = sol_contact_info_add_socket(
        ci, SOL_SOCKET_TAG_SERVE_REPAIR, &serve_repair_addr);
    TEST_ASSERT_EQ(err, SOL_OK);

    err = sol_crds_insert(crds, &val, NULL, ci->wallclock);
    TEST_ASSERT_EQ(err, SOL_OK);

    sol_repair_config_t config = SOL_REPAIR_CONFIG_DEFAULT;
    config.serve_repairs = false;

    sol_keypair_t identity;
    sol_ed25519_keypair_generate(&identity);

    sol_repair_t* repair = sol_repair_new(&config, gossip, &identity);
    TEST_ASSERT(repair != NULL);

    err = sol_repair_start(repair, 0);
    TEST_ASSERT_EQ(err, SOL_OK);

    const sol_slot_t slot = 42;
    const uint64_t shred_index = 7;
    err = sol_repair_request_shred(repair, slot, shred_index, true);
    TEST_ASSERT_EQ(err, SOL_OK);

    uint8_t buf[512];
    ssize_t n = -1;
    uint32_t disc = 0;
    for (int attempt = 0; attempt < 3; attempt++) {
        n = recvfrom(recv_fd, buf, sizeof(buf), 0, NULL, NULL);
        TEST_ASSERT_MSG(n > 0, "Did not receive repair request packet");
        if ((size_t)n < 4) continue;

        /* RepairProtocol discriminant (u32 LE). */
        disc = (uint32_t)buf[0] |
               ((uint32_t)buf[1] << 8) |
               ((uint32_t)buf[2] << 16) |
               ((uint32_t)buf[3] << 24);

        /* Skip ping/pong envelopes that may be sent ahead of the request. */
        if (disc == 0u || disc == 6u || disc == 7u) {
            continue;
        }
        break;
    }

    TEST_ASSERT_EQ(disc, 8u);
    TEST_ASSERT_EQ((size_t)n, 160u);

    /* Verify sender/recipient and signature. */
    sol_pubkey_t expected_sender;
    sol_keypair_pubkey(&identity, &expected_sender);

    sol_pubkey_t sender = {0};
    memcpy(sender.bytes, buf + 4 + SOL_SIGNATURE_SIZE, SOL_PUBKEY_SIZE);
    TEST_ASSERT(memcmp(sender.bytes, expected_sender.bytes, SOL_PUBKEY_SIZE) == 0);

    sol_pubkey_t recipient = {0};
    memcpy(recipient.bytes, buf + 4 + SOL_SIGNATURE_SIZE + SOL_PUBKEY_SIZE, SOL_PUBKEY_SIZE);
    TEST_ASSERT(memcmp(recipient.bytes, ci->pubkey.bytes, SOL_PUBKEY_SIZE) == 0);

    uint64_t got_slot = 0;
    memcpy(&got_slot, buf + 144, 8);
    TEST_ASSERT_EQ((sol_slot_t)got_slot, slot);

    uint64_t got_index = 0;
    memcpy(&got_index, buf + 152, 8);
    TEST_ASSERT_EQ(got_index, shred_index);

    sol_signature_t sig = {0};
    memcpy(sig.bytes, buf + 4, SOL_SIGNATURE_SIZE);

    uint8_t signable[512];
    memcpy(signable, buf, 4);
    memcpy(signable + 4, buf + 4 + SOL_SIGNATURE_SIZE, (size_t)n - (4 + SOL_SIGNATURE_SIZE));
    size_t signable_len = (size_t)n - SOL_SIGNATURE_SIZE;

    TEST_ASSERT(sol_ed25519_verify(&sender, signable, signable_len, &sig));

    sol_repair_destroy(repair);
    sol_gossip_destroy(gossip);
    (void)close(recv_fd);
}

/*
 * Statistics tests
 */

TEST(repair_stats) {
    sol_repair_config_t config = SOL_REPAIR_CONFIG_DEFAULT;

    sol_keypair_t identity;
    sol_ed25519_keypair_generate(&identity);

    sol_repair_t* repair = sol_repair_new(&config, NULL, &identity);
    TEST_ASSERT(repair != NULL);

    sol_repair_stats_t stats;
    sol_repair_stats(repair, &stats);

    /* Initial stats should be zero */
    TEST_ASSERT_EQ(stats.requests_sent, 0);
    TEST_ASSERT_EQ(stats.responses_received, 0);
    TEST_ASSERT_EQ(stats.shreds_repaired, 0);
    TEST_ASSERT_EQ(stats.timeouts, 0);
    TEST_ASSERT_EQ(stats.duplicates, 0);
    TEST_ASSERT_EQ(stats.invalid_responses, 0);

    sol_repair_destroy(repair);
}

TEST(repair_stats_reset) {
    sol_repair_config_t config = SOL_REPAIR_CONFIG_DEFAULT;

    sol_keypair_t identity;
    sol_ed25519_keypair_generate(&identity);

    sol_repair_t* repair = sol_repair_new(&config, NULL, &identity);
    TEST_ASSERT(repair != NULL);

    /* Reset stats */
    sol_repair_stats_reset(repair);

    sol_repair_stats_t stats;
    sol_repair_stats(repair, &stats);

    TEST_ASSERT_EQ(stats.requests_sent, 0);

    sol_repair_destroy(repair);
}

/*
 * Callback tests
 */

static int callback_count = 0;
static sol_slot_t callback_slot = 0;

static void
test_shred_callback(const sol_shred_t* shred, void* ctx) {
    (void)ctx;
    callback_count++;
    callback_slot = shred->slot;
}

TEST(repair_callback) {
    sol_repair_config_t config = SOL_REPAIR_CONFIG_DEFAULT;

    sol_keypair_t identity;
    sol_ed25519_keypair_generate(&identity);

    sol_repair_t* repair = sol_repair_new(&config, NULL, &identity);
    TEST_ASSERT(repair != NULL);

    /* Set callback */
    sol_repair_set_shred_callback(repair, test_shred_callback, NULL);

    /* Callback should be set (can't easily test without simulating response) */

    sol_repair_destroy(repair);
}

/*
 * Run once tests
 */

TEST(repair_run_once_not_running) {
    sol_repair_config_t config = SOL_REPAIR_CONFIG_DEFAULT;

    sol_keypair_t identity;
    sol_ed25519_keypair_generate(&identity);

    sol_repair_t* repair = sol_repair_new(&config, NULL, &identity);
    TEST_ASSERT(repair != NULL);

    /* Run once without starting - should return shutdown */
    sol_err_t err = sol_repair_run_once(repair, 0);
    TEST_ASSERT_EQ(err, SOL_ERR_SHUTDOWN);

    sol_repair_destroy(repair);
}

TEST(repair_run_once_running) {
    int udp = udp_available();
    if (udp == 0) {
        TEST_SKIP("UDP sockets not permitted in this environment");
    }
    TEST_ASSERT_MSG(udp > 0, "Failed to create UDP socket for repair tests");

    sol_repair_config_t config = SOL_REPAIR_CONFIG_DEFAULT;

    sol_keypair_t identity;
    sol_ed25519_keypair_generate(&identity);

    sol_repair_t* repair = sol_repair_new(&config, NULL, &identity);
    TEST_ASSERT(repair != NULL);

    sol_err_t err = sol_repair_start(repair, 0);
    TEST_ASSERT_EQ(err, SOL_OK);

    /* Run once while running - should succeed */
    err = sol_repair_run_once(repair, 0);
    TEST_ASSERT_EQ(err, SOL_OK);

    sol_repair_destroy(repair);
}

/*
 * Repair type name tests
 */

TEST(repair_type_name) {
    TEST_ASSERT_STR_EQ(sol_repair_type_name(SOL_REPAIR_SHRED), "Shred");
    TEST_ASSERT_STR_EQ(sol_repair_type_name(SOL_REPAIR_HIGHEST_SHRED), "HighestShred");
    TEST_ASSERT_STR_EQ(sol_repair_type_name(SOL_REPAIR_ORPHAN), "Orphan");
    TEST_ASSERT_STR_EQ(sol_repair_type_name(SOL_REPAIR_ANCESTOR_HASHES), "AncestorHashes");
    TEST_ASSERT_STR_EQ(sol_repair_type_name(99), "Unknown");
}

/*
 * Null pointer tests
 */

TEST(repair_null_handling) {
    /* Destroy with NULL should be safe */
    sol_repair_destroy(NULL);

    /* Start with NULL should return error */
    sol_err_t err = sol_repair_start(NULL, 0);
    TEST_ASSERT_EQ(err, SOL_ERR_INVAL);

    /* Stop with NULL should be safe */
    sol_repair_stop(NULL);

    /* Is running with NULL should return false */
    TEST_ASSERT(!sol_repair_is_running(NULL));

    /* Request with NULL should return error */
    err = sol_repair_request_shred(NULL, 1000, 5, true);
    TEST_ASSERT_EQ(err, SOL_ERR_INVAL);

    err = sol_repair_request_highest(NULL, 1000, 0);
    TEST_ASSERT_EQ(err, SOL_ERR_INVAL);

    err = sol_repair_request_orphan(NULL, 1000);
    TEST_ASSERT_EQ(err, SOL_ERR_INVAL);

    /* Set callback with NULL should be safe */
    sol_repair_set_shred_callback(NULL, NULL, NULL);

    /* Stats with NULL should be safe */
    sol_repair_stats(NULL, NULL);
    sol_repair_stats_reset(NULL);
}

/*
 * Test runner
 */
static test_case_t repair_tests[] = {
    TEST_CASE(repair_create_destroy),
    TEST_CASE(repair_create_null_config),
    TEST_CASE(repair_create_null_identity),
    TEST_CASE(repair_start_stop),
    TEST_CASE(repair_double_start),
    TEST_CASE(repair_request_shred_no_peers),
    TEST_CASE(repair_request_highest_no_peers),
    TEST_CASE(repair_request_orphan_no_peers),
    TEST_CASE(repair_response_bincode_shred_unwrap),
    TEST_CASE(repair_prioritization_evict_low_priority),
    TEST_CASE(repair_request_wire_format_signed),
    TEST_CASE(repair_stats),
    TEST_CASE(repair_stats_reset),
    TEST_CASE(repair_callback),
    TEST_CASE(repair_run_once_not_running),
    TEST_CASE(repair_run_once_running),
    TEST_CASE(repair_type_name),
    TEST_CASE(repair_null_handling),
};

int main(void) {
    int result = RUN_TESTS("Repair Tests", repair_tests);
    sol_alloc_dump_leaks();
    return result;
}
