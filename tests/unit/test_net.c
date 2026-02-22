/*
 * test_net.c - Network module unit tests
 *
 * Tests UDP socket creation, send/receive, and address handling.
 */

#include "../test_framework.h"
#include "sol_net.h"
#include "sol_udp.h"
#include "sol_quic.h"
#include "sol_alloc.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * Sockaddr tests
 */

TEST(sockaddr_init_ipv4) {
    sol_sockaddr_t sa;
    TEST_ASSERT_EQ(sol_sockaddr_init(&sa, "127.0.0.1", 8000), SOL_OK);
    TEST_ASSERT_EQ(sol_sockaddr_family(&sa), AF_INET);
    TEST_ASSERT_EQ(sol_sockaddr_port(&sa), 8000);
}

TEST(sockaddr_init_ipv6) {
    sol_sockaddr_t sa;
    TEST_ASSERT_EQ(sol_sockaddr_init(&sa, "::1", 8000), SOL_OK);
    TEST_ASSERT_EQ(sol_sockaddr_family(&sa), AF_INET6);
    TEST_ASSERT_EQ(sol_sockaddr_port(&sa), 8000);
}

TEST(sockaddr_init_invalid) {
    sol_sockaddr_t sa;
    TEST_ASSERT(sol_sockaddr_init(&sa, "not.an.ip", 8000) != SOL_OK);
}

TEST(sockaddr_init_any) {
    sol_sockaddr_t sa;
    TEST_ASSERT_EQ(sol_sockaddr_init_any(&sa, AF_INET, 0), SOL_OK);
    TEST_ASSERT_EQ(sol_sockaddr_family(&sa), AF_INET);
    TEST_ASSERT_EQ(sol_sockaddr_port(&sa), 0);
}

TEST(sockaddr_to_string) {
    sol_sockaddr_t sa;
    sol_sockaddr_init(&sa, "192.168.1.1", 12345);

    char buf[64];
    TEST_ASSERT_EQ(sol_sockaddr_to_string(&sa, buf, sizeof(buf)), SOL_OK);
    TEST_ASSERT_STR_EQ(buf, "192.168.1.1:12345");
}

TEST(sockaddr_eq) {
    sol_sockaddr_t sa1, sa2, sa3;
    sol_sockaddr_init(&sa1, "127.0.0.1", 8000);
    sol_sockaddr_init(&sa2, "127.0.0.1", 8000);
    sol_sockaddr_init(&sa3, "127.0.0.1", 8001);

    TEST_ASSERT(sol_sockaddr_eq(&sa1, &sa2));
    TEST_ASSERT(!sol_sockaddr_eq(&sa1, &sa3));
}

TEST(sockaddr_copy) {
    sol_sockaddr_t sa1, sa2;
    sol_sockaddr_init(&sa1, "10.0.0.1", 9999);

    sol_sockaddr_copy(&sa2, &sa1);
    TEST_ASSERT(sol_sockaddr_eq(&sa1, &sa2));
}

/*
 * Endpoint tests
 */

TEST(endpoint_from_sockaddr) {
    sol_sockaddr_t sa;
    sol_sockaddr_init(&sa, "192.168.0.1", 1234);

    sol_endpoint_t ep;
    TEST_ASSERT_EQ(sol_endpoint_from_sockaddr(&ep, &sa), SOL_OK);
    TEST_ASSERT_STR_EQ(ep.ip, "192.168.0.1");
    TEST_ASSERT_EQ(ep.port, 1234);
}

/*
 * UDP socket tests
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

TEST(udp_create_destroy) {
    int udp = udp_available();
    if (udp == 0) {
        TEST_SKIP("UDP sockets not permitted in this environment");
    }
    TEST_ASSERT_MSG(udp > 0, "Failed to create UDP socket for tests");

    sol_udp_config_t cfg = SOL_UDP_CONFIG_DEFAULT;
    cfg.bind_port = 0;  /* Let OS assign port */

    sol_udp_sock_t* sock = sol_udp_new(&cfg);
    TEST_ASSERT(sock != NULL);

    int fd = sol_udp_fd(sock);
    TEST_ASSERT(fd >= 0);

    sol_sockaddr_t local;
    TEST_ASSERT_EQ(sol_udp_local_addr(sock, &local), SOL_OK);
    TEST_ASSERT(sol_sockaddr_port(&local) > 0);  /* OS assigned a port */

    sol_udp_destroy(sock);
}

TEST(udp_create_default) {
    int udp = udp_available();
    if (udp == 0) {
        TEST_SKIP("UDP sockets not permitted in this environment");
    }
    TEST_ASSERT_MSG(udp > 0, "Failed to create UDP socket for tests");

    /* Test with NULL config (uses defaults) */
    sol_udp_sock_t* sock = sol_udp_new(NULL);
    TEST_ASSERT(sock != NULL);
    sol_udp_destroy(sock);
}

TEST(udp_loopback_send_recv) {
    int udp = udp_available();
    if (udp == 0) {
        TEST_SKIP("UDP sockets not permitted in this environment");
    }
    TEST_ASSERT_MSG(udp > 0, "Failed to create UDP socket for tests");

    /* Create two sockets */
    sol_udp_config_t cfg = SOL_UDP_CONFIG_DEFAULT;
    cfg.bind_port = 0;

    sol_udp_sock_t* sender = sol_udp_new(&cfg);
    sol_udp_sock_t* receiver = sol_udp_new(&cfg);
    TEST_ASSERT(sender != NULL);
    TEST_ASSERT(receiver != NULL);

    /* Get receiver address */
    sol_sockaddr_t recv_addr;
    sol_udp_local_addr(receiver, &recv_addr);
    /* Change to loopback IP (local_addr might be 0.0.0.0) */
    recv_addr.addr.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    /* Send a packet */
    const char* msg = "Hello, Solana!";
    TEST_ASSERT_EQ(sol_udp_send(sender, (const uint8_t*)msg, strlen(msg), &recv_addr), SOL_OK);

    /* Small delay for packet to arrive */
    usleep(1000);

    /* Receive the packet */
    uint8_t buf[256];
    size_t len = sizeof(buf);
    sol_sockaddr_t src;
    sol_err_t err = sol_udp_recv(receiver, buf, &len, &src);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_EQ(len, strlen(msg));
    TEST_ASSERT_MEM_EQ(buf, msg, len);

    sol_udp_destroy(sender);
    sol_udp_destroy(receiver);
}

TEST(udp_recv_nonblocking) {
    int udp = udp_available();
    if (udp == 0) {
        TEST_SKIP("UDP sockets not permitted in this environment");
    }
    TEST_ASSERT_MSG(udp > 0, "Failed to create UDP socket for tests");

    sol_udp_config_t cfg = SOL_UDP_CONFIG_DEFAULT;
    cfg.bind_port = 0;
    cfg.nonblocking = true;

    sol_udp_sock_t* sock = sol_udp_new(&cfg);
    TEST_ASSERT(sock != NULL);

    /* Try to receive on empty socket - should return EAGAIN */
    uint8_t buf[256];
    size_t len = sizeof(buf);
    sol_sockaddr_t src;
    sol_err_t err = sol_udp_recv(sock, buf, &len, &src);
    TEST_ASSERT_EQ(err, SOL_ERR_AGAIN);

    sol_udp_destroy(sock);
}

TEST(udp_batch_send_recv) {
    int udp = udp_available();
    if (udp == 0) {
        TEST_SKIP("UDP sockets not permitted in this environment");
    }
    TEST_ASSERT_MSG(udp > 0, "Failed to create UDP socket for tests");

    sol_udp_config_t cfg = SOL_UDP_CONFIG_DEFAULT;
    cfg.bind_port = 0;

    sol_udp_sock_t* sender = sol_udp_new(&cfg);
    sol_udp_sock_t* receiver = sol_udp_new(&cfg);
    TEST_ASSERT(sender != NULL);
    TEST_ASSERT(receiver != NULL);

    /* Get receiver address */
    sol_sockaddr_t recv_addr;
    sol_udp_local_addr(receiver, &recv_addr);
    recv_addr.addr.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    /* Prepare batch of packets */
    sol_udp_pkt_t send_pkts[3];
    for (int i = 0; i < 3; i++) {
        snprintf((char*)send_pkts[i].data, SOL_NET_MTU, "Packet %d", i);
        send_pkts[i].len = strlen((char*)send_pkts[i].data);
        sol_sockaddr_copy(&send_pkts[i].addr, &recv_addr);
    }

    /* Send batch */
    int sent = sol_udp_send_batch(sender, send_pkts, 3);
    TEST_ASSERT_EQ(sent, 3);

    /* Small delay */
    usleep(5000);

    /* Receive batch */
    sol_udp_pkt_t recv_pkts[3];
    int received = sol_udp_recv_batch(receiver, recv_pkts, 3);
    TEST_ASSERT_EQ(received, 3);

    /* Verify packets (may arrive in any order) */
    for (int i = 0; i < 3; i++) {
        TEST_ASSERT(recv_pkts[i].len > 0);
        TEST_ASSERT(memcmp(recv_pkts[i].data, "Packet", 6) == 0);
    }

    sol_udp_destroy(sender);
    sol_udp_destroy(receiver);
}

TEST(udp_set_nonblocking) {
    int udp = udp_available();
    if (udp == 0) {
        TEST_SKIP("UDP sockets not permitted in this environment");
    }
    TEST_ASSERT_MSG(udp > 0, "Failed to create UDP socket for tests");

    sol_udp_config_t cfg = SOL_UDP_CONFIG_DEFAULT;
    cfg.bind_port = 0;
    cfg.nonblocking = false;  /* Start blocking */

    sol_udp_sock_t* sock = sol_udp_new(&cfg);
    TEST_ASSERT(sock != NULL);

    /* Switch to non-blocking */
    TEST_ASSERT_EQ(sol_udp_set_nonblocking(sock, true), SOL_OK);

    /* Verify by trying recv (should return EAGAIN, not block) */
    uint8_t buf[256];
    size_t len = sizeof(buf);
    sol_err_t err = sol_udp_recv(sock, buf, &len, NULL);
    TEST_ASSERT_EQ(err, SOL_ERR_AGAIN);

    sol_udp_destroy(sock);
}

TEST(quic_create_start_stop) {
    int udp = udp_available();
    if (udp == 0) {
        TEST_SKIP("UDP sockets not permitted in this environment");
    }
    TEST_ASSERT_MSG(udp > 0, "Failed to create UDP socket for tests");

    char cert_template[] = "/tmp/solana-c-quic-cert-XXXXXX";
    char key_template[] = "/tmp/solana-c-quic-key-XXXXXX";

    int cert_fd = mkstemp(cert_template);
    int key_fd = mkstemp(key_template);
    if (cert_fd >= 0) close(cert_fd);
    if (key_fd >= 0) close(key_fd);

    if (cert_fd < 0 || key_fd < 0) {
        if (cert_fd >= 0) unlink(cert_template);
        if (key_fd >= 0) unlink(key_template);
        TEST_SKIP("mkstemp failed (no writable /tmp?)");
    }

    /* Remove placeholders so openssl can create the actual files */
    unlink(cert_template);
    unlink(key_template);

    sol_err_t err = sol_quic_generate_test_cert(cert_template, key_template);
    if (err != SOL_OK) {
        unlink(cert_template);
        unlink(key_template);
        TEST_SKIP("Failed to generate test certificate (openssl required)");
    }

    sol_quic_config_t cfg = SOL_QUIC_CONFIG_DEFAULT;
    cfg.bind_ip = "127.0.0.1";
    cfg.bind_port = 0;
    cfg.cert_path = cert_template;
    cfg.key_path = key_template;

    sol_quic_t* quic = sol_quic_new(&cfg);
    if (!quic) {
        unlink(cert_template);
        unlink(key_template);
        TEST_ASSERT_MSG(false, "sol_quic_new failed");
    }

    err = sol_quic_start(quic);
    if (err == SOL_ERR_UNSUPPORTED) {
        sol_quic_destroy(quic);
        unlink(cert_template);
        unlink(key_template);
        TEST_SKIP("QUIC not available in this build");
    }

    if (err != SOL_OK) {
        sol_quic_destroy(quic);
        unlink(cert_template);
        unlink(key_template);
        TEST_ASSERT_MSG(false, "sol_quic_start failed");
    }

    TEST_ASSERT(sol_quic_is_running(quic));
    TEST_ASSERT_EQ(sol_quic_stop(quic), SOL_OK);
    TEST_ASSERT(!sol_quic_is_running(quic));

    sol_quic_destroy(quic);
    unlink(cert_template);
    unlink(key_template);
}

/*
 * Test runner
 */
static test_case_t net_tests[] = {
    TEST_CASE(sockaddr_init_ipv4),
    TEST_CASE(sockaddr_init_ipv6),
    TEST_CASE(sockaddr_init_invalid),
    TEST_CASE(sockaddr_init_any),
    TEST_CASE(sockaddr_to_string),
    TEST_CASE(sockaddr_eq),
    TEST_CASE(sockaddr_copy),
    TEST_CASE(endpoint_from_sockaddr),
    TEST_CASE(udp_create_destroy),
    TEST_CASE(udp_create_default),
    TEST_CASE(udp_loopback_send_recv),
    TEST_CASE(udp_recv_nonblocking),
    TEST_CASE(udp_batch_send_recv),
    TEST_CASE(udp_set_nonblocking),
    TEST_CASE(quic_create_start_stop),
};

int main(void) {
    int result = RUN_TESTS("Network Tests", net_tests);
    sol_alloc_dump_leaks();
    return result;
}
