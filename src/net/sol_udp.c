/*
 * sol_udp.c - UDP socket implementation
 */

#include "sol_udp.h"
#include "../util/sol_log.h"

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>

#ifdef __linux__
#include <sys/sendfile.h>
#endif

struct sol_udp_sock {
    int            fd;
    sol_sockaddr_t local_addr;
    bool           nonblocking;
};

static size_t
udp_buf_env_override(const char* env_name, size_t current) {
    const char* env = getenv(env_name);
    if (!env || env[0] == '\0') {
        return current;
    }

    errno = 0;
    char* end = NULL;
    unsigned long long parsed = strtoull(env, &end, 10);
    if (errno != 0 || end == env) {
        return current;
    }

    while (*end && isspace((unsigned char)*end)) end++;
    unsigned long long mul = 1ull;
    if (*end == 'k' || *end == 'K') {
        mul = 1024ull;
        end++;
    } else if (*end == 'm' || *end == 'M') {
        mul = 1024ull * 1024ull;
        end++;
    } else if (*end == 'g' || *end == 'G') {
        mul = 1024ull * 1024ull * 1024ull;
        end++;
    }
    while (*end && isspace((unsigned char)*end)) end++;
    if (*end != '\0') {
        return current;
    }

    if (parsed > ULLONG_MAX / mul) {
        parsed = ULLONG_MAX / mul;
    }
    unsigned long long bytes = parsed * mul;
    if (bytes > (unsigned long long)SIZE_MAX) {
        bytes = (unsigned long long)SIZE_MAX;
    }
    if (bytes < 65536ull) {
        bytes = 65536ull;
    }

    return (size_t)bytes;
}

sol_udp_sock_t*
sol_udp_new(const sol_udp_config_t* config) {
    sol_udp_config_t cfg;
    if (config == NULL) {
        cfg = (sol_udp_config_t)SOL_UDP_CONFIG_DEFAULT;
    } else {
        cfg = *config;
    }

    cfg.recv_buf = udp_buf_env_override("SOL_UDP_RECVBUF", cfg.recv_buf);
    cfg.send_buf = udp_buf_env_override("SOL_UDP_SNDBUF", cfg.send_buf);

    /* Default to IPv4 */
    int family = cfg.family ? cfg.family : AF_INET;

    /* Create socket */
    int fd = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        sol_log_error("socket() failed: %s", strerror(errno));
        return NULL;
    }

    /* Ensure sockets aren't inherited by snapshot helper processes (curl/zstd). */
    {
        int fd_flags = fcntl(fd, F_GETFD, 0);
        if (fd_flags >= 0) {
            (void)fcntl(fd, F_SETFD, fd_flags | FD_CLOEXEC);
        }
    }

    /* Set socket options */
    int opt = 1;

    if (cfg.reuse_addr) {
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            sol_log_warn("SO_REUSEADDR failed: %s", strerror(errno));
        }
    }

#ifdef SO_REUSEPORT
    if (cfg.reuse_port) {
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
            sol_log_warn("SO_REUSEPORT failed: %s", strerror(errno));
        }
    }
#endif

    /* Set buffer sizes */
    if (cfg.recv_buf > 0) {
        int buf_size = (int)cfg.recv_buf;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size)) < 0) {
            sol_log_warn("SO_RCVBUF failed: %s", strerror(errno));
        }
    }

    if (cfg.send_buf > 0) {
        int buf_size = (int)cfg.send_buf;
        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) < 0) {
            sol_log_warn("SO_SNDBUF failed: %s", strerror(errno));
        }
    }

    /* Set non-blocking mode */
    if (cfg.nonblocking) {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            sol_log_error("fcntl() failed: %s", strerror(errno));
            close(fd);
            return NULL;
        }
    }

    /* Prepare bind address */
    sol_sockaddr_t bind_addr;
    if (cfg.bind_ip != NULL) {
        if (sol_sockaddr_init(&bind_addr, cfg.bind_ip, cfg.bind_port) != SOL_OK) {
            sol_log_error("Invalid bind address: %s", cfg.bind_ip);
            close(fd);
            return NULL;
        }
    } else {
        if (sol_sockaddr_init_any(&bind_addr, family, cfg.bind_port) != SOL_OK) {
            sol_log_error("Failed to init bind address");
            close(fd);
            return NULL;
        }
    }

    /* Bind socket */
    if (bind(fd, &bind_addr.addr.sa, bind_addr.len) < 0) {
        int saved_errno = errno;
        char addr_str[64];
        addr_str[0] = '\0';
        if (sol_sockaddr_to_string(&bind_addr, addr_str, sizeof(addr_str)) == SOL_OK) {
            if (saved_errno == EADDRINUSE) {
                sol_log_error("bind(%s) failed: address already in use", addr_str);
            } else {
                sol_log_error("bind(%s) failed: %s", addr_str, strerror(saved_errno));
            }
        } else {
            sol_log_error("bind() failed: %s", strerror(saved_errno));
        }
        close(fd);
        errno = saved_errno;
        return NULL;
    }

    /* Allocate socket structure */
    sol_udp_sock_t* sock = sol_alloc(sizeof(sol_udp_sock_t));
    if (sock == NULL) {
        close(fd);
        return NULL;
    }

    sock->fd = fd;
    sock->nonblocking = cfg.nonblocking;

    /* Get actual local address (in case port was 0) */
    sock->local_addr.len = sizeof(sock->local_addr.addr);
    if (getsockname(fd, &sock->local_addr.addr.sa, &sock->local_addr.len) < 0) {
        sol_log_warn("getsockname() failed: %s", strerror(errno));
    }

    return sock;
}

void
sol_udp_destroy(sol_udp_sock_t* sock) {
    if (sock == NULL) return;

    if (sock->fd >= 0) {
        close(sock->fd);
    }
    sol_free(sock);
}

int
sol_udp_fd(sol_udp_sock_t* sock) {
    return sock ? sock->fd : -1;
}

sol_err_t
sol_udp_local_addr(sol_udp_sock_t* sock, sol_sockaddr_t* addr) {
    if (sock == NULL || addr == NULL) {
        return SOL_ERR_INVAL;
    }
    sol_sockaddr_copy(addr, &sock->local_addr);
    return SOL_OK;
}

sol_err_t
sol_udp_send(
    sol_udp_sock_t*       sock,
    const uint8_t*        data,
    size_t                len,
    const sol_sockaddr_t* dest
) {
    if (sock == NULL || data == NULL || dest == NULL) {
        return SOL_ERR_INVAL;
    }

    ssize_t sent = sendto(sock->fd, data, len, 0, &dest->addr.sa, dest->len);
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return SOL_ERR_AGAIN;
        }
        return SOL_ERR_IO;
    }

    return SOL_OK;
}

sol_err_t
sol_udp_recv(
    sol_udp_sock_t* sock,
    uint8_t*        data,
    size_t*         len,
    sol_sockaddr_t* src
) {
    if (sock == NULL || data == NULL || len == NULL) {
        return SOL_ERR_INVAL;
    }

    socklen_t src_len = sizeof(src->addr);
    ssize_t received = recvfrom(sock->fd, data, *len, 0,
                                src ? &src->addr.sa : NULL,
                                src ? &src_len : NULL);

    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return SOL_ERR_AGAIN;
        }
        return SOL_ERR_IO;
    }

    *len = (size_t)received;
    if (src) {
        src->len = src_len;
    }

    return SOL_OK;
}

#ifdef __linux__
/*
 * Linux: Use sendmmsg/recvmmsg for batched operations
 */

int
sol_udp_send_batch(
    sol_udp_sock_t*      sock,
    const sol_udp_pkt_t* pkts,
    int                  count
) {
    if (sock == NULL || pkts == NULL || count <= 0) {
        return -1;
    }

    if (count > SOL_NET_BATCH_SIZE) {
        count = SOL_NET_BATCH_SIZE;
    }

    struct mmsghdr msgs[SOL_NET_BATCH_SIZE];
    struct iovec iovs[SOL_NET_BATCH_SIZE];

    for (int i = 0; i < count; i++) {
        iovs[i].iov_base = (void*)pkts[i].data;
        iovs[i].iov_len = pkts[i].len;

        msgs[i].msg_hdr.msg_name = (void*)&pkts[i].addr.addr;
        msgs[i].msg_hdr.msg_namelen = pkts[i].addr.len;
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_control = NULL;
        msgs[i].msg_hdr.msg_controllen = 0;
        msgs[i].msg_hdr.msg_flags = 0;
        msgs[i].msg_len = 0;
    }

    int sent = sendmmsg(sock->fd, msgs, count, 0);
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }

    return sent;
}

int
sol_udp_recv_batch(
    sol_udp_sock_t* sock,
    sol_udp_pkt_t*  pkts,
    int             max_pkts
) {
    if (sock == NULL || pkts == NULL || max_pkts <= 0) {
        return -1;
    }

    if (max_pkts > SOL_NET_BATCH_SIZE) {
        max_pkts = SOL_NET_BATCH_SIZE;
    }

    struct mmsghdr msgs[SOL_NET_BATCH_SIZE];
    struct iovec iovs[SOL_NET_BATCH_SIZE];

    for (int i = 0; i < max_pkts; i++) {
        iovs[i].iov_base = pkts[i].data;
        iovs[i].iov_len = SOL_NET_MTU;

        msgs[i].msg_hdr.msg_name = &pkts[i].addr.addr;
        msgs[i].msg_hdr.msg_namelen = sizeof(pkts[i].addr.addr);
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_control = NULL;
        msgs[i].msg_hdr.msg_controllen = 0;
        msgs[i].msg_hdr.msg_flags = 0;
        msgs[i].msg_len = 0;
    }

    int received = recvmmsg(sock->fd, msgs, max_pkts, MSG_DONTWAIT, NULL);
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }

    /* Update packet lengths and address lengths */
    for (int i = 0; i < received; i++) {
        pkts[i].len = msgs[i].msg_len;
        pkts[i].addr.len = msgs[i].msg_hdr.msg_namelen;
    }

    return received;
}

#else
/*
 * Non-Linux (macOS, BSD): Fallback to loop
 */

int
sol_udp_send_batch(
    sol_udp_sock_t*      sock,
    const sol_udp_pkt_t* pkts,
    int                  count
) {
    if (sock == NULL || pkts == NULL || count <= 0) {
        return -1;
    }

    int sent = 0;
    for (int i = 0; i < count; i++) {
        ssize_t ret = sendto(sock->fd, pkts[i].data, pkts[i].len, 0,
                            &pkts[i].addr.addr.sa, pkts[i].addr.len);
        if (ret < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            if (sent == 0) {
                return -1;
            }
            break;
        }
        sent++;
    }

    return sent;
}

int
sol_udp_recv_batch(
    sol_udp_sock_t* sock,
    sol_udp_pkt_t*  pkts,
    int             max_pkts
) {
    if (sock == NULL || pkts == NULL || max_pkts <= 0) {
        return -1;
    }

    int received = 0;
    for (int i = 0; i < max_pkts; i++) {
        pkts[i].addr.len = sizeof(pkts[i].addr.addr);
        ssize_t ret = recvfrom(sock->fd, pkts[i].data, SOL_NET_MTU, 0,
                               &pkts[i].addr.addr.sa, &pkts[i].addr.len);
        if (ret < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            if (received == 0) {
                return -1;
            }
            break;
        }
        pkts[i].len = (size_t)ret;
        received++;
    }

    return received;
}

#endif /* __linux__ */

sol_err_t
sol_udp_set_nonblocking(sol_udp_sock_t* sock, bool nonblocking) {
    if (sock == NULL) {
        return SOL_ERR_INVAL;
    }

    int flags = fcntl(sock->fd, F_GETFL, 0);
    if (flags < 0) {
        return SOL_ERR_IO;
    }

    if (nonblocking) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }

    if (fcntl(sock->fd, F_SETFL, flags) < 0) {
        return SOL_ERR_IO;
    }

    sock->nonblocking = nonblocking;
    return SOL_OK;
}

sol_err_t
sol_udp_join_multicast(sol_udp_sock_t* sock, const char* group_ip) {
    if (sock == NULL || group_ip == NULL) {
        return SOL_ERR_INVAL;
    }

    struct ip_mreq mreq;
    if (inet_pton(AF_INET, group_ip, &mreq.imr_multiaddr) != 1) {
        return SOL_ERR_INVAL;
    }
    mreq.imr_interface.s_addr = INADDR_ANY;

    if (setsockopt(sock->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   &mreq, sizeof(mreq)) < 0) {
        sol_log_error("IP_ADD_MEMBERSHIP failed: %s", strerror(errno));
        return SOL_ERR_IO;
    }

    return SOL_OK;
}

sol_err_t
sol_udp_leave_multicast(sol_udp_sock_t* sock, const char* group_ip) {
    if (sock == NULL || group_ip == NULL) {
        return SOL_ERR_INVAL;
    }

    struct ip_mreq mreq;
    if (inet_pton(AF_INET, group_ip, &mreq.imr_multiaddr) != 1) {
        return SOL_ERR_INVAL;
    }
    mreq.imr_interface.s_addr = INADDR_ANY;

    if (setsockopt(sock->fd, IPPROTO_IP, IP_DROP_MEMBERSHIP,
                   &mreq, sizeof(mreq)) < 0) {
        sol_log_error("IP_DROP_MEMBERSHIP failed: %s", strerror(errno));
        return SOL_ERR_IO;
    }

    return SOL_OK;
}
