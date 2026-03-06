/*
 * sol_net.h - Common networking types and utilities
 *
 * Provides fundamental networking abstractions including socket addresses,
 * packet structures, and network utility functions.
 */

#ifndef SOL_NET_H
#define SOL_NET_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

/*
 * Maximum UDP packet size for Solana
 * MTU is typically 1500, minus IP header (20) and UDP header (8) = 1472
 * Solana uses 1232 as max packet size for safety across networks
 */
#define SOL_NET_MTU 1232

/*
 * Maximum packets to send/receive in a batch
 */
#define SOL_NET_BATCH_SIZE 128

/*
 * Socket address abstraction
 * Supports both IPv4 and IPv6
 */
typedef struct {
    union {
        struct sockaddr     sa;
        struct sockaddr_in  sin;
        struct sockaddr_in6 sin6;
    } addr;
    socklen_t len;
} sol_sockaddr_t;

/*
 * UDP packet structure for batched operations
 */
typedef struct {
    uint8_t         data[SOL_NET_MTU];
    size_t          len;
    sol_sockaddr_t  addr;
} sol_udp_pkt_t;

/*
 * Socket endpoint (IP:port)
 */
typedef struct {
    char     ip[INET6_ADDRSTRLEN];
    uint16_t port;
} sol_endpoint_t;

/*
 * Initialize sockaddr from IP string and port
 */
static inline sol_err_t
sol_sockaddr_init(sol_sockaddr_t* sa, const char* ip, uint16_t port) {
    memset(sa, 0, sizeof(*sa));

    /* Try IPv4 first */
    struct sockaddr_in* sin = &sa->addr.sin;
    if (inet_pton(AF_INET, ip, &sin->sin_addr) == 1) {
        sin->sin_family = AF_INET;
        sin->sin_port = htons(port);
        sa->len = sizeof(struct sockaddr_in);
        return SOL_OK;
    }

    /* Try IPv6 */
    struct sockaddr_in6* sin6 = &sa->addr.sin6;
    if (inet_pton(AF_INET6, ip, &sin6->sin6_addr) == 1) {
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(port);
        sa->len = sizeof(struct sockaddr_in6);
        return SOL_OK;
    }

    return SOL_ERR_INVAL;
}

/*
 * Initialize sockaddr for any address (0.0.0.0 or ::)
 */
static inline sol_err_t
sol_sockaddr_init_any(sol_sockaddr_t* sa, int family, uint16_t port) {
    memset(sa, 0, sizeof(*sa));

    if (family == AF_INET) {
        struct sockaddr_in* sin = &sa->addr.sin;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = INADDR_ANY;
        sin->sin_port = htons(port);
        sa->len = sizeof(struct sockaddr_in);
        return SOL_OK;
    }

    if (family == AF_INET6) {
        struct sockaddr_in6* sin6 = &sa->addr.sin6;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = in6addr_any;
        sin6->sin6_port = htons(port);
        sa->len = sizeof(struct sockaddr_in6);
        return SOL_OK;
    }

    return SOL_ERR_INVAL;
}

/*
 * Get address family
 */
static inline int
sol_sockaddr_family(const sol_sockaddr_t* sa) {
    return sa->addr.sa.sa_family;
}

/*
 * Get port (host byte order)
 */
static inline uint16_t
sol_sockaddr_port(const sol_sockaddr_t* sa) {
    if (sa->addr.sa.sa_family == AF_INET) {
        return ntohs(sa->addr.sin.sin_port);
    }
    if (sa->addr.sa.sa_family == AF_INET6) {
        return ntohs(sa->addr.sin6.sin6_port);
    }
    return 0;
}

/*
 * Convert sockaddr to string (IP:port format)
 */
static inline sol_err_t
sol_sockaddr_to_string(const sol_sockaddr_t* sa, char* buf, size_t buf_len) {
    char ip[INET6_ADDRSTRLEN];

    if (sa->addr.sa.sa_family == AF_INET) {
        if (inet_ntop(AF_INET, &sa->addr.sin.sin_addr, ip, sizeof(ip)) == NULL) {
            return SOL_ERR_IO;
        }
        snprintf(buf, buf_len, "%s:%u", ip, ntohs(sa->addr.sin.sin_port));
        return SOL_OK;
    }

    if (sa->addr.sa.sa_family == AF_INET6) {
        if (inet_ntop(AF_INET6, &sa->addr.sin6.sin6_addr, ip, sizeof(ip)) == NULL) {
            return SOL_ERR_IO;
        }
        snprintf(buf, buf_len, "[%s]:%u", ip, ntohs(sa->addr.sin6.sin6_port));
        return SOL_OK;
    }

    return SOL_ERR_INVAL;
}

/*
 * Compare two sockaddrs for equality
 */
static inline bool
sol_sockaddr_eq(const sol_sockaddr_t* a, const sol_sockaddr_t* b) {
    if (a->addr.sa.sa_family != b->addr.sa.sa_family) {
        return false;
    }

    if (a->addr.sa.sa_family == AF_INET) {
        return a->addr.sin.sin_addr.s_addr == b->addr.sin.sin_addr.s_addr &&
               a->addr.sin.sin_port == b->addr.sin.sin_port;
    }

    if (a->addr.sa.sa_family == AF_INET6) {
        return memcmp(&a->addr.sin6.sin6_addr, &b->addr.sin6.sin6_addr, 16) == 0 &&
               a->addr.sin6.sin6_port == b->addr.sin6.sin6_port;
    }

    return false;
}

/*
 * Copy sockaddr
 */
static inline void
sol_sockaddr_copy(sol_sockaddr_t* dst, const sol_sockaddr_t* src) {
    memcpy(dst, src, sizeof(*dst));
}

/*
 * Initialize sockaddr from hostname (with DNS resolution)
 *
 * Resolves the hostname and initializes the sockaddr with the result.
 * Supports both IPv4 and IPv6 addresses.
 */
static inline sol_err_t
sol_sockaddr_from_host(const char* host, uint16_t port, sol_sockaddr_t* sa) {
    if (!host || !sa) return SOL_ERR_INVAL;

    struct addrinfo hints = {0};
    struct addrinfo* result = NULL;

    hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM;  /* UDP */

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    int ret = getaddrinfo(host, port_str, &hints, &result);
    if (ret != 0 || result == NULL) {
        return SOL_ERR_IO;
    }

    /* Use the first result */
    memset(sa, 0, sizeof(*sa));
    if (result->ai_family == AF_INET) {
        memcpy(&sa->addr.sin, result->ai_addr, sizeof(sa->addr.sin));
        sa->len = sizeof(struct sockaddr_in);
    } else if (result->ai_family == AF_INET6) {
        memcpy(&sa->addr.sin6, result->ai_addr, sizeof(sa->addr.sin6));
        sa->len = sizeof(struct sockaddr_in6);
    } else {
        freeaddrinfo(result);
        return SOL_ERR_INVAL;
    }

    freeaddrinfo(result);
    return SOL_OK;
}

/*
 * Initialize endpoint from sockaddr
 */
static inline sol_err_t
sol_endpoint_from_sockaddr(sol_endpoint_t* ep, const sol_sockaddr_t* sa) {
    if (sa->addr.sa.sa_family == AF_INET) {
        if (inet_ntop(AF_INET, &sa->addr.sin.sin_addr, ep->ip, sizeof(ep->ip)) == NULL) {
            return SOL_ERR_IO;
        }
        ep->port = ntohs(sa->addr.sin.sin_port);
        return SOL_OK;
    }

    if (sa->addr.sa.sa_family == AF_INET6) {
        if (inet_ntop(AF_INET6, &sa->addr.sin6.sin6_addr, ep->ip, sizeof(ep->ip)) == NULL) {
            return SOL_ERR_IO;
        }
        ep->port = ntohs(sa->addr.sin6.sin6_port);
        return SOL_OK;
    }

    return SOL_ERR_INVAL;
}

#endif /* SOL_NET_H */
