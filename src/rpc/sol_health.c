/*
 * sol_health.c - Health Check Implementation
 */

#include "sol_health.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>
#include <time.h>

/*
 * Health server state
 */
struct sol_health_server {
    sol_health_config_t     config;
    int                     server_fd;
    pthread_t               thread;
    volatile bool           running;
    uint64_t                start_time;
};

/*
 * Get current time in seconds
 */
static uint64_t
get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec;
}

/*
 * Status names
 */
const char*
sol_health_status_name(sol_health_status_t status) {
    switch (status) {
        case SOL_HEALTH_OK:        return "ok";
        case SOL_HEALTH_DEGRADED:  return "degraded";
        case SOL_HEALTH_UNHEALTHY: return "unhealthy";
        default:                   return "unknown";
    }
}

/*
 * Render health status as JSON
 */
size_t
sol_health_render_json(const sol_health_result_t* result, char* buf, size_t buf_len) {
    if (result == NULL || buf == NULL || buf_len == 0) {
        return 0;
    }

    int written = snprintf(buf, buf_len,
        "{\n"
        "  \"status\": \"%s\",\n"
        "  \"message\": \"%s\",\n"
        "  \"validator\": {\n"
        "    \"syncing\": %s,\n"
        "    \"voting\": %s,\n"
        "    \"leader\": %s,\n"
        "    \"has_identity\": %s\n"
        "  },\n"
        "  \"sync\": {\n"
        "    \"current_slot\": %llu,\n"
        "    \"highest_slot\": %llu,\n"
        "    \"slots_behind\": %llu\n"
        "  },\n"
        "  \"network\": {\n"
        "    \"connected_peers\": %u,\n"
        "    \"rpc_connections\": %u\n"
        "  },\n"
        "  \"resources\": {\n"
        "    \"memory_used_bytes\": %llu,\n"
        "    \"cpu_percent\": %.2f\n"
        "  },\n"
        "  \"uptime_seconds\": %llu\n"
        "}\n",
        sol_health_status_name(result->status),
        result->message ? result->message : "",
        result->is_syncing ? "true" : "false",
        result->is_voting ? "true" : "false",
        result->is_leader ? "true" : "false",
        result->has_identity ? "true" : "false",
        (unsigned long long)result->current_slot,
        (unsigned long long)result->highest_slot,
        (unsigned long long)result->slots_behind,
        result->connected_peers,
        result->rpc_connections,
        (unsigned long long)result->memory_used_bytes,
        result->cpu_percent,
        (unsigned long long)result->uptime_seconds
    );

    if (written < 0) {
        return 0;
    }
    if ((size_t)written >= buf_len) {
        return buf_len - 1;
    }
    return (size_t)written;
}

/*
 * Get health status
 */
sol_health_result_t
sol_health_check(sol_health_server_t* server) {
    sol_health_result_t result = {0};

    if (server == NULL) {
        result.status = SOL_HEALTH_UNHEALTHY;
        result.message = "Server not initialized";
        return result;
    }

    /* Get uptime */
    result.uptime_seconds = get_time_sec() - server->start_time;

    /* Call user callback if provided */
    if (server->config.callback != NULL) {
        result = server->config.callback(server->config.callback_ctx);
        result.uptime_seconds = get_time_sec() - server->start_time;
        return result;
    }

    /* Default: just report as healthy if running */
    if (server->running) {
        result.status = SOL_HEALTH_OK;
        result.message = "Validator running";
        result.has_identity = true;
    } else {
        result.status = SOL_HEALTH_UNHEALTHY;
        result.message = "Validator not running";
    }

    return result;
}

/*
 * Parse HTTP request path
 */
static const char*
parse_request_path(const char* request, size_t len) {
    /* Find "GET " or "HEAD " */
    if (len < 5) return NULL;

    const char* path_start = NULL;
    if (strncmp(request, "GET ", 4) == 0) {
        path_start = request + 4;
    } else if (strncmp(request, "HEAD ", 5) == 0) {
        path_start = request + 5;
    } else {
        return NULL;
    }

    /* Path ends at space or end of line */
    static char path_buf[256];
    size_t i = 0;
    while (path_start[i] != ' ' && path_start[i] != '\r' &&
           path_start[i] != '\n' && path_start[i] != '\0' &&
           i < sizeof(path_buf) - 1) {
        path_buf[i] = path_start[i];
        i++;
    }
    path_buf[i] = '\0';

    return path_buf;
}

/*
 * Send HTTP response
 */
static void
send_response(int client_fd, int status_code, const char* status_text,
              const char* content_type, const char* body, size_t body_len) {
    char header[512];
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        status_code, status_text,
        content_type,
        body_len
    );

    /* Send header */
    send(client_fd, header, header_len, 0);

    /* Send body */
    if (body != NULL && body_len > 0) {
        send(client_fd, body, body_len, 0);
    }
}

/*
 * Handle client connection
 */
static void
handle_client(sol_health_server_t* server, int client_fd) {
    char request[1024];
    ssize_t n = recv(client_fd, request, sizeof(request) - 1, 0);

    if (n <= 0) {
        close(client_fd);
        return;
    }
    request[n] = '\0';

    const char* path = parse_request_path(request, n);
    if (path == NULL) {
        send_response(client_fd, 400, "Bad Request",
                     "text/plain", "Bad Request\n", 12);
        close(client_fd);
        return;
    }

    sol_health_result_t result = sol_health_check(server);

    /* Route to appropriate handler */
    if (strcmp(path, SOL_HEALTH_PATH) == 0 || strcmp(path, "/") == 0) {
        /* Full health status */
        char body[4096];
        size_t body_len = sol_health_render_json(&result, body, sizeof(body));

        int status_code = (result.status == SOL_HEALTH_OK) ? 200 :
                          (result.status == SOL_HEALTH_DEGRADED) ? 200 : 503;

        send_response(client_fd, status_code,
                     (status_code == 200) ? "OK" : "Service Unavailable",
                     "application/json", body, body_len);

    } else if (strcmp(path, SOL_HEALTH_LIVE_PATH) == 0) {
        /* Liveness probe - always return OK if server is running */
        if (server->running) {
            send_response(client_fd, 200, "OK", "text/plain", "ok\n", 3);
        } else {
            send_response(client_fd, 503, "Service Unavailable",
                         "text/plain", "not ok\n", 7);
        }

    } else if (strcmp(path, SOL_HEALTH_READY_PATH) == 0) {
        /* Readiness probe - check if validator is ready to serve */
        bool ready = (result.status == SOL_HEALTH_OK) &&
                     !result.is_syncing &&
                     result.has_identity;

        if (ready) {
            send_response(client_fd, 200, "OK", "text/plain", "ready\n", 6);
        } else {
            send_response(client_fd, 503, "Service Unavailable",
                         "text/plain", "not ready\n", 10);
        }

    } else {
        send_response(client_fd, 404, "Not Found",
                     "text/plain", "Not Found\n", 10);
    }

    close(client_fd);
}

/*
 * Server thread
 */
static void*
health_server_thread(void* arg) {
    sol_health_server_t* server = (sol_health_server_t*)arg;

    sol_log_info("Health server listening on %s:%u",
                 server->config.bind_addr, server->config.port);

	    while (server->running) {
	        struct sockaddr_in client_addr;
	        socklen_t addr_len = sizeof(client_addr);

	        /* Accept with timeout */
	        struct pollfd pfd;
	        memset(&pfd, 0, sizeof(pfd));
	        pfd.fd = server->server_fd;
	        pfd.events = POLLIN;

	        int ret = poll(&pfd, 1, 1000);
	        if (ret <= 0) {
	            continue;
	        }
	        if (!(pfd.revents & POLLIN)) {
	            continue;
	        }

	        int client_fd = accept(server->server_fd,
                               (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (errno != EINTR && errno != EAGAIN) {
                sol_log_error("Health server accept failed: %s", strerror(errno));
            }
            continue;
        }

        handle_client(server, client_fd);
    }

    return NULL;
}

/*
 * Create health server
 */
sol_health_server_t*
sol_health_server_new(const sol_health_config_t* config) {
    sol_health_server_t* server = sol_calloc(1, sizeof(sol_health_server_t));
    if (server == NULL) {
        return NULL;
    }

    if (config != NULL) {
        server->config = *config;
    } else {
        server->config = (sol_health_config_t)SOL_HEALTH_CONFIG_DEFAULT;
    }

    if (server->config.bind_addr == NULL) {
        server->config.bind_addr = "0.0.0.0";
    }

    server->server_fd = -1;
    server->running = false;
    server->start_time = get_time_sec();

    return server;
}

/*
 * Destroy health server
 */
void
sol_health_server_destroy(sol_health_server_t* server) {
    if (server == NULL) {
        return;
    }

    if (server->running) {
        sol_health_server_stop(server);
    }

    sol_free(server);
}

/*
 * Start health server
 */
sol_err_t
sol_health_server_start(sol_health_server_t* server) {
    if (server == NULL) {
        return SOL_ERR_INVAL;
    }

    if (server->running) {
        return SOL_OK;  /* Already running */
    }

    /* Create socket */
    server->server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->server_fd < 0) {
        sol_log_error("Health server socket creation failed: %s", strerror(errno));
        return SOL_ERR_IO;
    }

    /* Set socket options */
    int opt = 1;
    setsockopt(server->server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Bind */
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(server->config.port),
    };

    if (inet_pton(AF_INET, server->config.bind_addr, &addr.sin_addr) <= 0) {
        sol_log_error("Health server invalid bind address: %s", server->config.bind_addr);
        close(server->server_fd);
        server->server_fd = -1;
        return SOL_ERR_INVAL;
    }

    if (bind(server->server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        sol_log_error("Health server bind failed: %s", strerror(errno));
        close(server->server_fd);
        server->server_fd = -1;
        return SOL_ERR_IO;
    }

    /* Listen */
    if (listen(server->server_fd, 16) < 0) {
        sol_log_error("Health server listen failed: %s", strerror(errno));
        close(server->server_fd);
        server->server_fd = -1;
        return SOL_ERR_IO;
    }

    /* Start thread */
    server->running = true;
    server->start_time = get_time_sec();

    if (pthread_create(&server->thread, NULL, health_server_thread, server) != 0) {
        sol_log_error("Health server thread creation failed: %s", strerror(errno));
        server->running = false;
        close(server->server_fd);
        server->server_fd = -1;
        return SOL_ERR_IO;
    }

    return SOL_OK;
}

/*
 * Stop health server
 */
sol_err_t
sol_health_server_stop(sol_health_server_t* server) {
    if (server == NULL) {
        return SOL_ERR_INVAL;
    }

    if (!server->running) {
        return SOL_OK;  /* Already stopped */
    }

    server->running = false;

    /* Close socket to unblock accept */
    if (server->server_fd >= 0) {
        close(server->server_fd);
        server->server_fd = -1;
    }

    /* Wait for thread */
    pthread_join(server->thread, NULL);

    sol_log_info("Health server stopped");

    return SOL_OK;
}

/*
 * Check if running
 */
bool
sol_health_server_is_running(const sol_health_server_t* server) {
    if (server == NULL) {
        return false;
    }
    return server->running;
}
