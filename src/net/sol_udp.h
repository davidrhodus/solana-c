/*
 * sol_udp.h - UDP socket abstraction
 *
 * High-performance UDP socket with batched send/receive operations.
 * Uses sendmmsg/recvmmsg on Linux for optimal performance.
 */

#ifndef SOL_UDP_H
#define SOL_UDP_H

#include "sol_net.h"
#include "../util/sol_alloc.h"

/*
 * UDP socket handle
 */
typedef struct sol_udp_sock sol_udp_sock_t;

/*
 * UDP socket configuration
 */
typedef struct {
    const char* bind_ip;      /* IP to bind to (NULL = any) */
    uint16_t    bind_port;    /* Port to bind to */
    int         family;       /* AF_INET or AF_INET6 (0 = auto) */
    size_t      recv_buf;     /* Receive buffer size (0 = default) */
    size_t      send_buf;     /* Send buffer size (0 = default) */
    bool        nonblocking;  /* Non-blocking mode */
    bool        reuse_addr;   /* SO_REUSEADDR */
    bool        reuse_port;   /* SO_REUSEPORT */
} sol_udp_config_t;

/*
 * Default configuration
 */
#define SOL_UDP_CONFIG_DEFAULT { \
    .bind_ip     = NULL,         \
    .bind_port   = 0,            \
    .family      = AF_INET,      \
    .recv_buf    = 64 * 1024 * 1024, \
    .send_buf    = 64 * 1024 * 1024, \
    .nonblocking = true,         \
    .reuse_addr  = true,         \
    .reuse_port  = false,        \
}

/*
 * Create a new UDP socket
 *
 * Returns NULL on failure.
 */
sol_udp_sock_t* sol_udp_new(const sol_udp_config_t* config);

/*
 * Destroy UDP socket
 */
void sol_udp_destroy(sol_udp_sock_t* sock);

/*
 * Get the file descriptor (for use with poll/epoll)
 */
int sol_udp_fd(sol_udp_sock_t* sock);

/*
 * Get local address
 */
sol_err_t sol_udp_local_addr(sol_udp_sock_t* sock, sol_sockaddr_t* addr);

/*
 * Send a single packet
 *
 * Returns:
 *   SOL_OK on success
 *   SOL_ERR_AGAIN if socket would block
 *   SOL_ERR_IO on error
 */
sol_err_t sol_udp_send(
    sol_udp_sock_t*       sock,
    const uint8_t*        data,
    size_t                len,
    const sol_sockaddr_t* dest
);

/*
 * Receive a single packet
 *
 * Returns:
 *   SOL_OK on success (len updated with actual size)
 *   SOL_ERR_AGAIN if no data available
 *   SOL_ERR_IO on error
 */
sol_err_t sol_udp_recv(
    sol_udp_sock_t* sock,
    uint8_t*        data,
    size_t*         len,
    sol_sockaddr_t* src
);

/*
 * Send multiple packets in a batch
 *
 * This uses sendmmsg on Linux for better performance.
 *
 * Returns number of packets sent, or -1 on error.
 * Partial sends are possible - caller should retry remaining packets.
 */
int sol_udp_send_batch(
    sol_udp_sock_t*      sock,
    const sol_udp_pkt_t* pkts,
    int                  count
);

/*
 * Receive multiple packets in a batch
 *
 * This uses recvmmsg on Linux for better performance.
 *
 * Returns number of packets received, or -1 on error.
 * Returns 0 if no data available (EAGAIN).
 */
int sol_udp_recv_batch(
    sol_udp_sock_t* sock,
    sol_udp_pkt_t*  pkts,
    int             max_pkts
);

/*
 * Set socket to blocking or non-blocking mode
 */
sol_err_t sol_udp_set_nonblocking(sol_udp_sock_t* sock, bool nonblocking);

/*
 * Join a multicast group (for gossip)
 */
sol_err_t sol_udp_join_multicast(
    sol_udp_sock_t* sock,
    const char*     group_ip
);

/*
 * Leave a multicast group
 */
sol_err_t sol_udp_leave_multicast(
    sol_udp_sock_t* sock,
    const char*     group_ip
);

#endif /* SOL_UDP_H */
