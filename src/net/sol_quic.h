/*
 * sol_quic.h - QUIC transport for TPU
 *
 * QUIC transport implementation using the quiche library (Cloudflare).
 * Provides reliable, encrypted transaction transport with:
 * - Connection multiplexing
 * - Stream-based transaction delivery
 * - TLS 1.3 encryption
 * - Connection migration support
 *
 * Solana uses QUIC for the TPU to handle high transaction throughput
 * with better congestion control than UDP.
 */

#ifndef SOL_QUIC_H
#define SOL_QUIC_H

#include "sol_net.h"
#include "../util/sol_alloc.h"
#include "../util/sol_err.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * QUIC constants
 */
#define SOL_QUIC_MAX_CONN_ID_LEN    20
#define SOL_QUIC_MAX_DATAGRAM_SIZE  1350
#define SOL_QUIC_MAX_STREAMS        1024
#define SOL_QUIC_IDLE_TIMEOUT_MS    30000
#define SOL_QUIC_MAX_DATA           (10 * 1024 * 1024)  /* 10MB per connection */
#define SOL_QUIC_MAX_STREAM_DATA    (1 * 1024 * 1024)   /* 1MB per stream */

/*
 * QUIC connection ID
 */
typedef struct {
    uint8_t data[SOL_QUIC_MAX_CONN_ID_LEN];
    size_t  len;
} sol_quic_conn_id_t;

/*
 * QUIC server configuration
 */
typedef struct {
    const char*     bind_ip;            /* IP to bind (NULL = any) */
    uint16_t        bind_port;          /* Port to bind */
    const char*     cert_path;          /* TLS certificate file path */
    const char*     key_path;           /* TLS private key file path */
    size_t          max_connections;    /* Max concurrent connections */
    size_t          max_streams;        /* Max streams per connection */
    uint64_t        idle_timeout_ms;    /* Connection idle timeout */
    size_t          max_data;           /* Max data per connection */
    size_t          max_stream_data;    /* Max data per stream */
    bool            verify_peer;        /* Verify client certificates */
} sol_quic_config_t;

#define SOL_QUIC_CONFIG_DEFAULT {           \
    .bind_ip          = NULL,               \
    .bind_port        = 8006,               \
    .cert_path        = NULL,               \
    .key_path         = NULL,               \
    .max_connections  = 10000,              \
    .max_streams      = SOL_QUIC_MAX_STREAMS, \
    .idle_timeout_ms  = SOL_QUIC_IDLE_TIMEOUT_MS, \
    .max_data         = SOL_QUIC_MAX_DATA,  \
    .max_stream_data  = SOL_QUIC_MAX_STREAM_DATA, \
    .verify_peer      = false,              \
}

/*
 * QUIC server handle
 */
typedef struct sol_quic sol_quic_t;

/*
 * QUIC connection handle
 */
typedef struct sol_quic_conn sol_quic_conn_t;

/*
 * QUIC stream handle
 */
typedef struct sol_quic_stream sol_quic_stream_t;

/*
 * QUIC statistics
 */
typedef struct {
    uint64_t    connections_accepted;   /* Total connections accepted */
    uint64_t    connections_active;     /* Currently active connections */
    uint64_t    connections_closed;     /* Connections closed */
    uint64_t    connections_timeout;    /* Connections timed out */
    uint64_t    streams_opened;         /* Total streams opened */
    uint64_t    streams_active;         /* Currently active streams */
    uint64_t    bytes_received;         /* Total bytes received */
    uint64_t    bytes_sent;             /* Total bytes sent */
    uint64_t    packets_received;       /* Total packets received */
    uint64_t    packets_sent;           /* Total packets sent */
    uint64_t    packets_lost;           /* Packets lost (retransmitted) */
} sol_quic_stats_t;

/*
 * Stream data callback
 *
 * Called when data is available on a stream.
 *
 * @param conn      Connection handle
 * @param stream_id Stream ID
 * @param data      Stream data
 * @param len       Data length
 * @param fin       True if stream is finished
 * @param ctx       User context
 * @return          true to continue receiving, false to close stream
 */
typedef bool (*sol_quic_stream_cb)(
    sol_quic_conn_t*    conn,
    uint64_t            stream_id,
    const uint8_t*      data,
    size_t              len,
    bool                fin,
    void*               ctx
);

/*
 * Connection event callback
 *
 * Called on connection events (connect, close, timeout).
 *
 * @param conn      Connection handle
 * @param event     Event type
 * @param ctx       User context
 */
typedef enum {
    SOL_QUIC_EVENT_CONNECTED,       /* Connection established */
    SOL_QUIC_EVENT_CLOSED,          /* Connection closed gracefully */
    SOL_QUIC_EVENT_TIMEOUT,         /* Connection timed out */
    SOL_QUIC_EVENT_ERROR,           /* Connection error */
} sol_quic_event_t;

typedef void (*sol_quic_conn_cb)(
    sol_quic_conn_t*    conn,
    sol_quic_event_t    event,
    void*               ctx
);

/*
 * Server lifecycle
 */

/*
 * Create QUIC server
 *
 * @param config    Configuration (NULL for defaults)
 * @return          Server handle or NULL on error
 */
sol_quic_t* sol_quic_new(const sol_quic_config_t* config);

/*
 * Destroy QUIC server
 */
void sol_quic_destroy(sol_quic_t* quic);

/*
 * Start QUIC server (bind and listen)
 */
sol_err_t sol_quic_start(sol_quic_t* quic);

/*
 * Stop QUIC server
 */
sol_err_t sol_quic_stop(sol_quic_t* quic);

/*
 * Check if server is running
 */
bool sol_quic_is_running(const sol_quic_t* quic);

/*
 * Get the underlying UDP socket fd (for poll/epoll)
 */
int sol_quic_fd(sol_quic_t* quic);

/*
 * Process incoming packets
 *
 * Should be called when the socket is readable.
 * Processes incoming packets and calls callbacks.
 *
 * @param quic      QUIC server
 * @return          Number of packets processed, or -1 on error
 */
int sol_quic_process(sol_quic_t* quic);

/*
 * Drive connection timeouts
 *
 * Should be called periodically (e.g., every 10ms) to handle
 * connection timeouts and retransmissions.
 *
 * @param quic      QUIC server
 * @return          Time until next timeout in ms
 */
uint64_t sol_quic_timeout(sol_quic_t* quic);

/*
 * Callbacks
 */

/*
 * Set stream data callback
 */
void sol_quic_set_stream_callback(
    sol_quic_t*         quic,
    sol_quic_stream_cb  callback,
    void*               ctx
);

/*
 * Set connection event callback
 */
void sol_quic_set_connection_callback(
    sol_quic_t*         quic,
    sol_quic_conn_cb    callback,
    void*               ctx
);

/*
 * Connection operations
 */

/*
 * Get connection peer address
 */
sol_err_t sol_quic_conn_peer_addr(
    sol_quic_conn_t*    conn,
    sol_sockaddr_t*     addr
);

/*
 * Get connection ID
 */
sol_err_t sol_quic_conn_id(
    sol_quic_conn_t*    conn,
    sol_quic_conn_id_t* id
);

/*
 * Close connection
 *
 * @param conn          Connection to close
 * @param app_error     Application error code (0 for normal close)
 * @param reason        Close reason string (can be NULL)
 */
sol_err_t sol_quic_conn_close(
    sol_quic_conn_t*    conn,
    uint64_t            app_error,
    const char*         reason
);

/*
 * Send data on a stream
 *
 * @param conn          Connection
 * @param stream_id     Stream ID (or 0 to create new stream)
 * @param data          Data to send
 * @param len           Data length
 * @param fin           True to close stream after sending
 * @return              SOL_OK on success
 */
sol_err_t sol_quic_conn_send(
    sol_quic_conn_t*    conn,
    uint64_t            stream_id,
    const uint8_t*      data,
    size_t              len,
    bool                fin
);

/*
 * Get connection user data
 */
void* sol_quic_conn_get_data(sol_quic_conn_t* conn);

/*
 * Set connection user data
 */
void sol_quic_conn_set_data(sol_quic_conn_t* conn, void* data);

/*
 * Statistics
 */

/*
 * Get QUIC server statistics
 */
sol_quic_stats_t sol_quic_stats(const sol_quic_t* quic);

/*
 * Reset statistics
 */
void sol_quic_stats_reset(sol_quic_t* quic);

/*
 * TLS Certificate utilities
 */

/*
 * Generate self-signed certificate for testing
 *
 * Creates a self-signed certificate and private key for testing.
 * NOT for production use.
 *
 * @param cert_path     Output certificate file path
 * @param key_path      Output private key file path
 * @return              SOL_OK on success
 */
sol_err_t sol_quic_generate_test_cert(
    const char*         cert_path,
    const char*         key_path
);

#ifdef __cplusplus
}
#endif

#endif /* SOL_QUIC_H */
