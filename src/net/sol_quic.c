/*
 * sol_quic.c - QUIC transport implementation
 *
 * Uses the quiche library (Cloudflare) for QUIC protocol handling.
 * Falls back to stub implementation when quiche is not available.
 */

#include "sol_quic.h"
#include "sol_udp.h"
#include "../util/sol_log.h"
#include "../util/sol_alloc.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>

#ifdef SOL_HAS_QUIC
#include <quiche.h>
#endif

/*
 * Get current time in nanoseconds
 */
static uint64_t
get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/*
 * Get current time in milliseconds
 */
__attribute__((unused))
static uint64_t
get_time_ms(void) {
    return get_time_ns() / 1000000ULL;
}

#ifdef SOL_HAS_QUIC

/*
 * Connection entry in hash table
 */
typedef struct sol_quic_conn {
    sol_quic_conn_id_t      id;             /* Connection ID */
    quiche_conn*            qconn;          /* quiche connection */
    sol_sockaddr_t          peer_addr;      /* Peer address */
    void*                   user_data;      /* User data */
    struct sol_quic_conn*   next;           /* Hash chain */
} sol_quic_conn_t;

/*
 * QUIC server structure
 */
struct sol_quic {
    sol_quic_config_t       config;
    quiche_config*          qconfig;        /* quiche config */
    sol_udp_sock_t*         udp;            /* Underlying UDP socket */

    /* Connection table */
    sol_quic_conn_t**       conns;
    size_t                  conn_table_size;
    size_t                  conn_count;

    /* Callbacks */
    sol_quic_stream_cb      stream_cb;
    void*                   stream_ctx;
    sol_quic_conn_cb        conn_cb;
    void*                   conn_ctx;

    /* Statistics */
    sol_quic_stats_t        stats;

    /* State */
    bool                    running;
    pthread_mutex_t         lock;
};

/*
 * Hash connection ID
 */
static size_t
conn_id_hash(const sol_quic_conn_id_t* id, size_t table_size) {
    uint64_t hash = 0;
    for (size_t i = 0; i < id->len && i < 8; i++) {
        hash = (hash << 8) | id->data[i];
    }
    return (size_t)(hash % table_size);
}

/*
 * Find connection by ID
 */
static sol_quic_conn_t*
find_conn(sol_quic_t* quic, const sol_quic_conn_id_t* id) {
    size_t idx = conn_id_hash(id, quic->conn_table_size);
    sol_quic_conn_t* conn = quic->conns[idx];

    while (conn) {
        if (conn->id.len == id->len &&
            memcmp(conn->id.data, id->data, id->len) == 0) {
            return conn;
        }
        conn = conn->next;
    }

    return NULL;
}

/*
 * Add connection to table
 */
static void
add_conn(sol_quic_t* quic, sol_quic_conn_t* conn) {
    size_t idx = conn_id_hash(&conn->id, quic->conn_table_size);
    conn->next = quic->conns[idx];
    quic->conns[idx] = conn;
    quic->conn_count++;
    quic->stats.connections_accepted++;
    quic->stats.connections_active++;
}

/*
 * Remove connection from table
 */
static void
remove_conn(sol_quic_t* quic, sol_quic_conn_t* conn) {
    size_t idx = conn_id_hash(&conn->id, quic->conn_table_size);
    sol_quic_conn_t** prev = &quic->conns[idx];

    while (*prev) {
        if (*prev == conn) {
            *prev = conn->next;
            quic->conn_count--;
            quic->stats.connections_active--;
            return;
        }
        prev = &(*prev)->next;
    }
}

/*
 * Destroy connection
 */
static void
destroy_conn(sol_quic_conn_t* conn) {
    if (!conn) return;
    if (conn->qconn) {
        quiche_conn_free(conn->qconn);
    }
    sol_free(conn);
}

/*
 * Generate random connection ID
 */
static void
generate_conn_id(sol_quic_conn_id_t* id) {
    id->len = 16;
    /* Simple random - in production use crypto random */
    uint64_t r1 = (uint64_t)get_time_ns() ^ (uint64_t)rand();
    uint64_t r2 = (uint64_t)rand() ^ ((uint64_t)rand() << 32);
    memcpy(id->data, &r1, 8);
    memcpy(id->data + 8, &r2, 8);
}

/*
 * Process incoming packet
 */
static int
process_packet(sol_quic_t* quic, const uint8_t* buf, size_t len,
               const sol_sockaddr_t* from) {
    sol_sockaddr_t local_addr;
    if (sol_udp_local_addr(quic->udp, &local_addr) != SOL_OK) {
        sol_log_error("Failed to get local UDP address for QUIC");
        return -1;
    }

    /* Parse QUIC header to get connection ID */
    uint8_t type;
    uint32_t version;
    uint8_t scid[SOL_QUIC_MAX_CONN_ID_LEN];
    size_t scid_len = sizeof(scid);
    uint8_t dcid[SOL_QUIC_MAX_CONN_ID_LEN];
    size_t dcid_len = sizeof(dcid);
    uint8_t token[256];
    size_t token_len = sizeof(token);

    int rc = quiche_header_info(buf, len, SOL_QUIC_MAX_CONN_ID_LEN,
                                &version, &type,
                                scid, &scid_len,
                                dcid, &dcid_len,
                                token, &token_len);
    if (rc < 0) {
        sol_log_debug("Failed to parse QUIC header: %d", rc);
        return -1;
    }

    /* Find existing connection */
    sol_quic_conn_id_t conn_id;
    memcpy(conn_id.data, dcid, dcid_len);
    conn_id.len = dcid_len;

    sol_quic_conn_t* conn = find_conn(quic, &conn_id);

    if (!conn) {
        /* New connection - need to accept */
        if (!quiche_version_is_supported(version)) {
            sol_log_debug("Unsupported QUIC version: 0x%x", version);
            /* Send version negotiation */
            uint8_t out[SOL_QUIC_MAX_DATAGRAM_SIZE];
            ssize_t written = quiche_negotiate_version(scid, scid_len,
                                                       dcid, dcid_len,
                                                       out, sizeof(out));
            if (written > 0) {
                sol_udp_send(quic->udp, out, (size_t)written, from);
            }
            return 0;
        }

        /* Check if this is a new connection (Initial packet) */
        if (type != 0x00) {  /* Not Initial packet */
            sol_log_debug("Received non-Initial packet for unknown connection");
            return 0;
        }

        /* Token validation - for now accept without token */
        /* In production, implement proper token validation */

        /* Generate new connection ID for server */
        sol_quic_conn_id_t new_id;
        generate_conn_id(&new_id);

        /* Create new quiche connection */
        quiche_conn* qconn = quiche_accept(new_id.data, new_id.len,
                                           dcid, dcid_len,
                                           (const struct sockaddr*)&local_addr.addr,
                                           local_addr.len,
                                           (const struct sockaddr*)&from->addr,
                                           from->len,
                                           quic->qconfig);
        if (!qconn) {
            sol_log_error("Failed to create QUIC connection");
            return -1;
        }

        /* Create connection wrapper */
        conn = sol_calloc(1, sizeof(sol_quic_conn_t));
        if (!conn) {
            quiche_conn_free(qconn);
            return -1;
        }

        conn->id = new_id;
        conn->qconn = qconn;
        sol_sockaddr_copy(&conn->peer_addr, from);

        add_conn(quic, conn);

        sol_log_debug("New QUIC connection from %s",
                     inet_ntoa(from->addr.sin.sin_addr));
    }

    /* Feed packet to connection */
    quiche_recv_info recv_info = {
        .from = (struct sockaddr*)&from->addr,
        .from_len = from->len,
        .to = (struct sockaddr*)&local_addr.addr,
        .to_len = local_addr.len,
    };

    ssize_t done = quiche_conn_recv(conn->qconn, (uint8_t*)buf, len, &recv_info);
    if (done < 0) {
        sol_log_debug("quiche_conn_recv failed: %zd", done);
        return -1;
    }

    quic->stats.packets_received++;
    quic->stats.bytes_received += len;

    /* Check if connection is established */
    if (quiche_conn_is_established(conn->qconn)) {
        /* Process readable streams */
        uint64_t stream_id;
        quiche_stream_iter* iter = quiche_conn_readable(conn->qconn);

        while (quiche_stream_iter_next(iter, &stream_id)) {
            uint8_t stream_buf[65536];
            bool fin = false;
            uint64_t error_code = 0;

            ssize_t recv_len = quiche_conn_stream_recv(conn->qconn, stream_id,
                                                       stream_buf, sizeof(stream_buf),
                                                       &fin, &error_code);
            if (recv_len > 0 && quic->stream_cb) {
                bool cont = quic->stream_cb(conn, stream_id,
                                           stream_buf, (size_t)recv_len,
                                           fin, quic->stream_ctx);
                if (!cont) {
                    quiche_conn_stream_shutdown(conn->qconn, stream_id,
                                               QUICHE_SHUTDOWN_READ, 0);
                }
            }

            if (fin) {
                quic->stats.streams_opened++;
            }
        }

        quiche_stream_iter_free(iter);
    }

    /* Check for connection close */
    if (quiche_conn_is_closed(conn->qconn)) {
        if (quic->conn_cb) {
            quic->conn_cb(conn, SOL_QUIC_EVENT_CLOSED, quic->conn_ctx);
        }
        remove_conn(quic, conn);
        destroy_conn(conn);
        quic->stats.connections_closed++;
    }

    return 1;
}

/*
 * Send pending data for all connections
 */
static void
flush_connections(sol_quic_t* quic) {
    for (size_t i = 0; i < quic->conn_table_size; i++) {
        sol_quic_conn_t* conn = quic->conns[i];

        while (conn) {
            sol_quic_conn_t* next = conn->next;

            uint8_t out[SOL_QUIC_MAX_DATAGRAM_SIZE];
            quiche_send_info send_info;

            while (1) {
                ssize_t written = quiche_conn_send(conn->qconn, out, sizeof(out),
                                                   &send_info);
                if (written == QUICHE_ERR_DONE) {
                    break;
                }

                if (written < 0) {
                    sol_log_debug("quiche_conn_send failed: %zd", written);
                    break;
                }

                /* Send via UDP */
                sol_sockaddr_t dest;
                if (send_info.to_len > sizeof(dest.addr)) {
                    sol_log_debug("QUIC send destination address too large: %u",
                                  (unsigned)send_info.to_len);
                    break;
                }

                memcpy(&dest.addr, &send_info.to, send_info.to_len);
                dest.len = send_info.to_len;

                sol_err_t err = sol_udp_send(quic->udp, out, (size_t)written, &dest);
                if (err != SOL_OK && err != SOL_ERR_AGAIN) {
                    sol_log_debug("UDP send failed: %d", err);
                    break;
                }

                quic->stats.packets_sent++;
                quic->stats.bytes_sent += written;
            }

            /* Check for connection timeout */
            if (quiche_conn_is_timed_out(conn->qconn)) {
                sol_log_debug("Connection timed out");
                if (quic->conn_cb) {
                    quic->conn_cb(conn, SOL_QUIC_EVENT_TIMEOUT, quic->conn_ctx);
                }
                remove_conn(quic, conn);
                destroy_conn(conn);
                quic->stats.connections_timeout++;
            }

            conn = next;
        }
    }
}

sol_quic_t*
sol_quic_new(const sol_quic_config_t* config) {
    sol_quic_t* quic = sol_calloc(1, sizeof(sol_quic_t));
    if (!quic) return NULL;

    if (config) {
        quic->config = *config;
    } else {
        quic->config = (sol_quic_config_t)SOL_QUIC_CONFIG_DEFAULT;
    }

    if (pthread_mutex_init(&quic->lock, NULL) != 0) {
        sol_free(quic);
        return NULL;
    }

    /* Create quiche config */
    quic->qconfig = quiche_config_new(QUICHE_PROTOCOL_VERSION);
    if (!quic->qconfig) {
        sol_log_error("Failed to create quiche config");
        pthread_mutex_destroy(&quic->lock);
        sol_free(quic);
        return NULL;
    }

    /* Load TLS certificates */
    if (quic->config.cert_path && quic->config.key_path) {
        if (quiche_config_load_cert_chain_from_pem_file(
                quic->qconfig, quic->config.cert_path) < 0) {
            sol_log_error("Failed to load certificate: %s", quic->config.cert_path);
            quiche_config_free(quic->qconfig);
            pthread_mutex_destroy(&quic->lock);
            sol_free(quic);
            return NULL;
        }

        if (quiche_config_load_priv_key_from_pem_file(
                quic->qconfig, quic->config.key_path) < 0) {
            sol_log_error("Failed to load private key: %s", quic->config.key_path);
            quiche_config_free(quic->qconfig);
            pthread_mutex_destroy(&quic->lock);
            sol_free(quic);
            return NULL;
        }
    }

    /* Configure QUIC parameters */
    quiche_config_set_application_protos(quic->qconfig,
        (uint8_t *)"\x0asolana-tpu", 11);
    quiche_config_set_max_idle_timeout(quic->qconfig, quic->config.idle_timeout_ms);
    quiche_config_set_max_recv_udp_payload_size(quic->qconfig, SOL_QUIC_MAX_DATAGRAM_SIZE);
    quiche_config_set_max_send_udp_payload_size(quic->qconfig, SOL_QUIC_MAX_DATAGRAM_SIZE);
    quiche_config_set_initial_max_data(quic->qconfig, quic->config.max_data);
    quiche_config_set_initial_max_stream_data_bidi_local(quic->qconfig,
        quic->config.max_stream_data);
    quiche_config_set_initial_max_stream_data_bidi_remote(quic->qconfig,
        quic->config.max_stream_data);
    quiche_config_set_initial_max_stream_data_uni(quic->qconfig,
        quic->config.max_stream_data);
    quiche_config_set_initial_max_streams_bidi(quic->qconfig,
        quic->config.max_streams);
    quiche_config_set_initial_max_streams_uni(quic->qconfig,
        quic->config.max_streams);

    /* Allocate connection table */
    quic->conn_table_size = quic->config.max_connections * 2;
    quic->conns = sol_calloc(quic->conn_table_size, sizeof(sol_quic_conn_t*));
    if (!quic->conns) {
        quiche_config_free(quic->qconfig);
        pthread_mutex_destroy(&quic->lock);
        sol_free(quic);
        return NULL;
    }

    sol_log_info("QUIC server created (quiche)");
    return quic;
}

void
sol_quic_destroy(sol_quic_t* quic) {
    if (!quic) return;

    sol_quic_stop(quic);

    /* Destroy all connections */
    for (size_t i = 0; i < quic->conn_table_size; i++) {
        sol_quic_conn_t* conn = quic->conns[i];
        while (conn) {
            sol_quic_conn_t* next = conn->next;
            destroy_conn(conn);
            conn = next;
        }
    }

    sol_free(quic->conns);

    if (quic->qconfig) {
        quiche_config_free(quic->qconfig);
    }

    pthread_mutex_destroy(&quic->lock);
    sol_free(quic);
}

sol_err_t
sol_quic_start(sol_quic_t* quic) {
    if (!quic) return SOL_ERR_INVAL;

    pthread_mutex_lock(&quic->lock);

    if (quic->running) {
        pthread_mutex_unlock(&quic->lock);
        return SOL_OK;
    }

    /* Create UDP socket */
    sol_udp_config_t udp_config = SOL_UDP_CONFIG_DEFAULT;
    udp_config.bind_ip = quic->config.bind_ip;
    udp_config.bind_port = quic->config.bind_port;
    udp_config.nonblocking = true;

    quic->udp = sol_udp_new(&udp_config);
    if (!quic->udp) {
        sol_log_error("Failed to create UDP socket for QUIC");
        pthread_mutex_unlock(&quic->lock);
        return SOL_ERR_IO;
    }

    quic->running = true;
    pthread_mutex_unlock(&quic->lock);

    sol_log_info("QUIC server started on port %u", quic->config.bind_port);
    return SOL_OK;
}

sol_err_t
sol_quic_stop(sol_quic_t* quic) {
    if (!quic) return SOL_ERR_INVAL;

    pthread_mutex_lock(&quic->lock);

    if (!quic->running) {
        pthread_mutex_unlock(&quic->lock);
        return SOL_OK;
    }

    quic->running = false;

    if (quic->udp) {
        sol_udp_destroy(quic->udp);
        quic->udp = NULL;
    }

    pthread_mutex_unlock(&quic->lock);

    sol_log_info("QUIC server stopped");
    return SOL_OK;
}

bool
sol_quic_is_running(const sol_quic_t* quic) {
    if (!quic) return false;
    return quic->running;
}

int
sol_quic_fd(sol_quic_t* quic) {
    if (!quic || !quic->udp) return -1;
    return sol_udp_fd(quic->udp);
}

int
sol_quic_process(sol_quic_t* quic) {
    if (!quic || !quic->running) return -1;

    pthread_mutex_lock(&quic->lock);

    int processed = 0;
    uint8_t buf[SOL_QUIC_MAX_DATAGRAM_SIZE];
    sol_sockaddr_t from;
    size_t len;

    /* Process incoming packets */
    while (1) {
        len = sizeof(buf);
        sol_err_t err = sol_udp_recv(quic->udp, buf, &len, &from);

        if (err == SOL_ERR_AGAIN) {
            break;  /* No more data */
        }

        if (err != SOL_OK) {
            sol_log_debug("UDP recv error: %d", err);
            break;
        }

        if (process_packet(quic, buf, len, &from) >= 0) {
            processed++;
        }
    }

    /* Flush outgoing data */
    flush_connections(quic);

    pthread_mutex_unlock(&quic->lock);
    return processed;
}

uint64_t
sol_quic_timeout(sol_quic_t* quic) {
    if (!quic || !quic->running) return UINT64_MAX;

    pthread_mutex_lock(&quic->lock);

    uint64_t min_timeout = UINT64_MAX;

    for (size_t i = 0; i < quic->conn_table_size; i++) {
        sol_quic_conn_t* conn = quic->conns[i];
        while (conn) {
            uint64_t timeout = quiche_conn_timeout_as_millis(conn->qconn);
            if (timeout < min_timeout) {
                min_timeout = timeout;
            }

            /* Trigger timeout handling */
            quiche_conn_on_timeout(conn->qconn);

            conn = conn->next;
        }
    }

    /* Flush any data generated by timeout handling */
    flush_connections(quic);

    pthread_mutex_unlock(&quic->lock);
    return min_timeout;
}

void
sol_quic_set_stream_callback(sol_quic_t* quic, sol_quic_stream_cb callback,
                              void* ctx) {
    if (!quic) return;
    quic->stream_cb = callback;
    quic->stream_ctx = ctx;
}

void
sol_quic_set_connection_callback(sol_quic_t* quic, sol_quic_conn_cb callback,
                                  void* ctx) {
    if (!quic) return;
    quic->conn_cb = callback;
    quic->conn_ctx = ctx;
}

sol_err_t
sol_quic_conn_peer_addr(sol_quic_conn_t* conn, sol_sockaddr_t* addr) {
    if (!conn || !addr) return SOL_ERR_INVAL;
    sol_sockaddr_copy(addr, &conn->peer_addr);
    return SOL_OK;
}

sol_err_t
sol_quic_conn_id(sol_quic_conn_t* conn, sol_quic_conn_id_t* id) {
    if (!conn || !id) return SOL_ERR_INVAL;
    *id = conn->id;
    return SOL_OK;
}

sol_err_t
sol_quic_conn_close(sol_quic_conn_t* conn, uint64_t app_error,
                     const char* reason) {
    if (!conn) return SOL_ERR_INVAL;

    size_t reason_len = reason ? strlen(reason) : 0;
    int rc = quiche_conn_close(conn->qconn, true, app_error,
                               (const uint8_t*)reason, reason_len);
    if (rc < 0 && rc != QUICHE_ERR_DONE) {
        return SOL_ERR_IO;
    }

    return SOL_OK;
}

sol_err_t
sol_quic_conn_send(sol_quic_conn_t* conn, uint64_t stream_id,
                    const uint8_t* data, size_t len, bool fin) {
    if (!conn || (!data && len > 0)) return SOL_ERR_INVAL;

    uint64_t error_code = 0;
    ssize_t written = quiche_conn_stream_send(conn->qconn, stream_id,
                                               data, len, fin, &error_code);
    if (written < 0) {
        return SOL_ERR_IO;
    }

    return SOL_OK;
}

void*
sol_quic_conn_get_data(sol_quic_conn_t* conn) {
    return conn ? conn->user_data : NULL;
}

void
sol_quic_conn_set_data(sol_quic_conn_t* conn, void* data) {
    if (conn) {
        conn->user_data = data;
    }
}

sol_quic_stats_t
sol_quic_stats(const sol_quic_t* quic) {
    if (!quic) {
        return (sol_quic_stats_t){0};
    }
    return quic->stats;
}

void
sol_quic_stats_reset(sol_quic_t* quic) {
    if (!quic) return;
    memset(&quic->stats, 0, sizeof(quic->stats));
    quic->stats.connections_active = quic->conn_count;
}

#else /* !SOL_HAS_QUIC */

/*
 * Stub implementation when quiche is not available
 */

struct sol_quic {
    sol_quic_config_t   config;
    bool                running;
};

struct sol_quic_conn {
    void* dummy;
};

sol_quic_t*
sol_quic_new(const sol_quic_config_t* config) {
    sol_quic_t* quic = sol_calloc(1, sizeof(sol_quic_t));
    if (!quic) return NULL;

    if (config) {
        quic->config = *config;
    } else {
        quic->config = (sol_quic_config_t)SOL_QUIC_CONFIG_DEFAULT;
    }

    sol_log_warn("QUIC not available (quiche not installed)");
    return quic;
}

void
sol_quic_destroy(sol_quic_t* quic) {
    sol_free(quic);
}

sol_err_t
sol_quic_start(sol_quic_t* quic) {
    if (!quic) return SOL_ERR_INVAL;
    sol_log_warn("QUIC start called but quiche not available");
    return SOL_ERR_UNSUPPORTED;
}

sol_err_t
sol_quic_stop(sol_quic_t* quic) {
    if (!quic) return SOL_ERR_INVAL;
    quic->running = false;
    return SOL_OK;
}

bool
sol_quic_is_running(const sol_quic_t* quic) {
    return quic ? quic->running : false;
}

int
sol_quic_fd(sol_quic_t* quic) {
    (void)quic;
    return -1;
}

int
sol_quic_process(sol_quic_t* quic) {
    (void)quic;
    return 0;
}

uint64_t
sol_quic_timeout(sol_quic_t* quic) {
    (void)quic;
    return UINT64_MAX;
}

void
sol_quic_set_stream_callback(sol_quic_t* quic, sol_quic_stream_cb callback,
                              void* ctx) {
    (void)quic;
    (void)callback;
    (void)ctx;
}

void
sol_quic_set_connection_callback(sol_quic_t* quic, sol_quic_conn_cb callback,
                                  void* ctx) {
    (void)quic;
    (void)callback;
    (void)ctx;
}

sol_err_t
sol_quic_conn_peer_addr(sol_quic_conn_t* conn, sol_sockaddr_t* addr) {
    (void)conn;
    (void)addr;
    return SOL_ERR_UNSUPPORTED;
}

sol_err_t
sol_quic_conn_id(sol_quic_conn_t* conn, sol_quic_conn_id_t* id) {
    (void)conn;
    (void)id;
    return SOL_ERR_UNSUPPORTED;
}

sol_err_t
sol_quic_conn_close(sol_quic_conn_t* conn, uint64_t app_error,
                     const char* reason) {
    (void)conn;
    (void)app_error;
    (void)reason;
    return SOL_ERR_UNSUPPORTED;
}

sol_err_t
sol_quic_conn_send(sol_quic_conn_t* conn, uint64_t stream_id,
                    const uint8_t* data, size_t len, bool fin) {
    (void)conn;
    (void)stream_id;
    (void)data;
    (void)len;
    (void)fin;
    return SOL_ERR_UNSUPPORTED;
}

void*
sol_quic_conn_get_data(sol_quic_conn_t* conn) {
    (void)conn;
    return NULL;
}

void
sol_quic_conn_set_data(sol_quic_conn_t* conn, void* data) {
    (void)conn;
    (void)data;
}

sol_quic_stats_t
sol_quic_stats(const sol_quic_t* quic) {
    (void)quic;
    return (sol_quic_stats_t){0};
}

void
sol_quic_stats_reset(sol_quic_t* quic) {
    (void)quic;
}

#endif /* SOL_HAS_QUIC */

/*
 * Generate self-signed test certificate (common to both implementations)
 */
sol_err_t
sol_quic_generate_test_cert(const char* cert_path, const char* key_path) {
    if (!cert_path || !key_path) return SOL_ERR_INVAL;

    /* Use openssl command to generate test certificate */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "openssl req -x509 -newkey rsa:2048 -keyout '%s' -out '%s' "
        "-days 365 -nodes -subj '/CN=localhost' 2>/dev/null",
        key_path, cert_path);

    int rc = system(cmd);
    if (rc != 0) {
        sol_log_error("Failed to generate test certificate (openssl required)");
        return SOL_ERR_IO;
    }

    sol_log_info("Generated test certificate: %s, %s", cert_path, key_path);
    return SOL_OK;
}
