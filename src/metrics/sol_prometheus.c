/*
 * sol_prometheus.c - Prometheus Metrics Exporter Implementation
 */

#include "sol_prometheus.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/*
 * Maximum metrics and labels
 */
#define MAX_METRICS         256
#define MAX_LABELS          8
#define MAX_LABEL_VALUES    64
#define MAX_HISTOGRAM_BUCKETS 16
#define MAX_NAME_LEN        128
#define MAX_HELP_LEN        256
#define MAX_HTTP_REQUEST    4096
#define MAX_HTTP_RESPONSE   (1024 * 1024)  /* 1MB max response */

/*
 * Label value entry
 */
typedef struct {
    char*   values[MAX_LABELS];     /* Label values */
    double  value;                  /* Metric value (counter/gauge) */
    /* Histogram data */
    double  histogram_sum;
    uint64_t histogram_count;
    uint64_t histogram_buckets[MAX_HISTOGRAM_BUCKETS];
} sol_metric_entry_t;

/*
 * Metric structure
 */
struct sol_metric {
    char                name[MAX_NAME_LEN];
    char                help[MAX_HELP_LEN];
    sol_metric_type_t   type;

    /* Labels */
    char*               labels[MAX_LABELS];
    size_t              num_labels;

    /* Histogram buckets (for histogram type) */
    double              bucket_boundaries[MAX_HISTOGRAM_BUCKETS];
    size_t              num_buckets;

    /* Metric entries (one per unique label combination) */
    sol_metric_entry_t  entries[MAX_LABEL_VALUES];
    size_t              num_entries;

    pthread_mutex_t     lock;
};

/*
 * Prometheus exporter structure
 */
struct sol_prometheus {
    sol_prometheus_config_t config;

    sol_metric_t*       metrics[MAX_METRICS];
    size_t              num_metrics;
    pthread_mutex_t     metrics_lock;

    /* HTTP server */
    int                 server_fd;
    pthread_t           server_thread;
    bool                server_thread_started;
    bool                running;
};

/*
 * Find or create metric entry for given label values
 */
static sol_metric_entry_t*
find_or_create_entry(sol_metric_t* metric, const char* const* label_values) {
    /* Build key from label values */
    size_t num_labels = metric->num_labels;

    /* If no labels, use first entry */
    if (num_labels == 0 || label_values == NULL) {
        if (metric->num_entries == 0) {
            metric->num_entries = 1;
            memset(&metric->entries[0], 0, sizeof(sol_metric_entry_t));
        }
        return &metric->entries[0];
    }

    /* Search for existing entry */
    for (size_t i = 0; i < metric->num_entries; i++) {
        sol_metric_entry_t* entry = &metric->entries[i];
        bool match = true;
        for (size_t j = 0; j < num_labels && match; j++) {
            if (entry->values[j] == NULL || label_values[j] == NULL) {
                match = (entry->values[j] == label_values[j]);
            } else {
                match = (strcmp(entry->values[j], label_values[j]) == 0);
            }
        }
        if (match) {
            return entry;
        }
    }

    /* Create new entry */
    if (metric->num_entries >= MAX_LABEL_VALUES) {
        return NULL;  /* Too many unique label combinations */
    }

    sol_metric_entry_t* entry = &metric->entries[metric->num_entries++];
    memset(entry, 0, sizeof(*entry));

    for (size_t j = 0; j < num_labels; j++) {
        if (label_values[j] != NULL) {
            size_t len = strlen(label_values[j]);
            entry->values[j] = sol_alloc(len + 1);
            if (entry->values[j]) {
                memcpy(entry->values[j], label_values[j], len + 1);
            }
        }
    }

    return entry;
}

/*
 * Create Prometheus exporter
 */
sol_prometheus_t*
sol_prometheus_new(const sol_prometheus_config_t* config) {
    sol_prometheus_t* prom = sol_calloc(1, sizeof(sol_prometheus_t));
    if (prom == NULL) {
        return NULL;
    }

    if (config != NULL) {
        prom->config = *config;
    } else {
        prom->config = (sol_prometheus_config_t)SOL_PROMETHEUS_CONFIG_DEFAULT;
    }

    pthread_mutex_init(&prom->metrics_lock, NULL);
    prom->server_fd = -1;
    prom->server_thread_started = false;
    prom->running = false;

    return prom;
}

/*
 * Destroy metric
 */
static void
metric_destroy(sol_metric_t* metric) {
    if (metric == NULL) return;

    /* Free label names */
    for (size_t i = 0; i < metric->num_labels; i++) {
        sol_free(metric->labels[i]);
    }

    /* Free label values in entries */
    for (size_t i = 0; i < metric->num_entries; i++) {
        for (size_t j = 0; j < metric->num_labels; j++) {
            sol_free(metric->entries[i].values[j]);
        }
    }

    pthread_mutex_destroy(&metric->lock);
    sol_free(metric);
}

/*
 * Destroy Prometheus exporter
 */
void
sol_prometheus_destroy(sol_prometheus_t* prom) {
    if (prom == NULL) return;

    sol_prometheus_stop(prom);

    pthread_mutex_lock(&prom->metrics_lock);
    for (size_t i = 0; i < prom->num_metrics; i++) {
        metric_destroy(prom->metrics[i]);
    }
    pthread_mutex_unlock(&prom->metrics_lock);

    pthread_mutex_destroy(&prom->metrics_lock);
    sol_free(prom);
}

/*
 * HTTP server thread
 */
static void*
http_server_thread(void* arg) {
    sol_prometheus_t* prom = (sol_prometheus_t*)arg;
    uint32_t accept_error_burst = 0;

    while (prom->running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(prom->server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            int err = errno;
            if (!prom->running) {
                break;
            }
            if (err == EINTR || err == EAGAIN || err == EWOULDBLOCK || err == ECONNABORTED) {
                continue;
            }
            if (err == EBADF || err == ENOTSOCK || err == EINVAL) {
                sol_log_error("Prometheus: accept failed: %s (stopping metrics thread)", strerror(err));
                prom->running = false;
                if (prom->server_fd >= 0) {
                    shutdown(prom->server_fd, SHUT_RDWR);
                    close(prom->server_fd);
                    prom->server_fd = -1;
                }
                break;
            }

            accept_error_burst++;
            if (accept_error_burst == 1 || (accept_error_burst % 100u) == 0u) {
                sol_log_warn("Prometheus: accept failed: %s (burst=%u)",
                             strerror(err),
                             (unsigned)accept_error_burst);
            }
            usleep(1000);
            continue;
        }
        accept_error_burst = 0;

        /* Don't leak client sockets into snapshot helper processes (curl/zstd). */
        {
            int fd_flags = fcntl(client_fd, F_GETFD, 0);
            if (fd_flags >= 0) {
                (void)fcntl(client_fd, F_SETFD, fd_flags | FD_CLOEXEC);
            }
        }

        /* Read HTTP request */
        char request[MAX_HTTP_REQUEST];
        ssize_t n = read(client_fd, request, sizeof(request) - 1);
        if (n <= 0) {
            close(client_fd);
            continue;
        }
        request[n] = '\0';

        /* Check if it's a GET request for /metrics */
        bool is_metrics = (strncmp(request, "GET ", 4) == 0 &&
                          strstr(request, prom->config.path) != NULL);

        char* response = NULL;
        const char* status = NULL;
        const char* content_type = NULL;

        if (is_metrics) {
            response = sol_prometheus_render_alloc(prom);
            status = "200 OK";
            content_type = "text/plain; version=0.0.4; charset=utf-8";
        } else if (strncmp(request, "GET /health", 11) == 0) {
            response = sol_alloc(32);
            if (response) {
                strcpy(response, "{\"status\":\"healthy\"}");
            }
            status = "200 OK";
            content_type = "application/json";
        } else {
            status = "404 Not Found";
            content_type = "text/plain";
            response = sol_alloc(32);
            if (response) {
                strcpy(response, "Not Found\n");
            }
        }

        /* Send HTTP response */
        if (response != NULL) {
            size_t body_len = strlen(response);
            char header[512];
            int header_len = snprintf(header, sizeof(header),
                "HTTP/1.1 %s\r\n"
                "Content-Type: %s\r\n"
                "Content-Length: %zu\r\n"
                "Connection: close\r\n"
                "\r\n",
                status, content_type, body_len);

            write(client_fd, header, header_len);
            write(client_fd, response, body_len);
            sol_free(response);
        }

        close(client_fd);
    }

    return NULL;
}

/*
 * Start HTTP server
 */
sol_err_t
sol_prometheus_start(sol_prometheus_t* prom) {
    if (prom == NULL) return SOL_ERR_INVAL;
    if (prom->running) return SOL_OK;

    /* Create socket */
    prom->server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (prom->server_fd < 0) {
        sol_log_error("Prometheus: socket failed: %s", strerror(errno));
        return SOL_ERR_IO;
    }

    /* Ensure listen socket isn't inherited by snapshot helper processes (curl/zstd). */
    {
        int fd_flags = fcntl(prom->server_fd, F_GETFD, 0);
        if (fd_flags < 0 || fcntl(prom->server_fd, F_SETFD, fd_flags | FD_CLOEXEC) < 0) {
            sol_log_warn("Prometheus: fcntl(FD_CLOEXEC) failed: %s", strerror(errno));
        }
    }

    /* Allow reuse */
    int opt = 1;
    setsockopt(prom->server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Bind */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(prom->config.port);

    if (prom->config.bind_addr != NULL) {
        inet_pton(AF_INET, prom->config.bind_addr, &addr.sin_addr);
    } else {
        addr.sin_addr.s_addr = INADDR_ANY;
    }

    if (bind(prom->server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        sol_log_error("Prometheus: bind failed on port %u: %s",
                     prom->config.port, strerror(errno));
        close(prom->server_fd);
        prom->server_fd = -1;
        return SOL_ERR_IO;
    }

    /* Listen */
    if (listen(prom->server_fd, 16) < 0) {
        sol_log_error("Prometheus: listen failed: %s", strerror(errno));
        close(prom->server_fd);
        prom->server_fd = -1;
        return SOL_ERR_IO;
    }

    prom->running = true;
    prom->server_thread_started = false;

    /* Start server thread */
    if (pthread_create(&prom->server_thread, NULL, http_server_thread, prom) != 0) {
        sol_log_error("Prometheus: failed to start server thread");
        prom->running = false;
        close(prom->server_fd);
        prom->server_fd = -1;
        return SOL_ERR_IO;
    }
    prom->server_thread_started = true;

    sol_log_info("Prometheus metrics server started on port %u", prom->config.port);
    return SOL_OK;
}

/*
 * Stop HTTP server
 */
sol_err_t
sol_prometheus_stop(sol_prometheus_t* prom) {
    if (prom == NULL) return SOL_ERR_INVAL;
    if (!prom->running && !prom->server_thread_started) return SOL_OK;

    prom->running = false;

    /* Close server socket to unblock accept() */
    if (prom->server_fd >= 0) {
        shutdown(prom->server_fd, SHUT_RDWR);
        close(prom->server_fd);
        prom->server_fd = -1;
    }

    if (prom->server_thread_started) {
        pthread_join(prom->server_thread, NULL);
        prom->server_thread_started = false;
    }

    sol_log_info("Prometheus metrics server stopped");
    return SOL_OK;
}

/*
 * Check if running
 */
bool
sol_prometheus_is_running(const sol_prometheus_t* prom) {
    return prom != NULL && prom->running;
}

/*
 * Register counter
 */
sol_metric_t*
sol_metric_counter_register(
    sol_prometheus_t*   prom,
    const char*         name,
    const char*         help,
    const char* const*  labels
) {
    if (prom == NULL || name == NULL) return NULL;

    pthread_mutex_lock(&prom->metrics_lock);

    if (prom->num_metrics >= MAX_METRICS) {
        pthread_mutex_unlock(&prom->metrics_lock);
        return NULL;
    }

    sol_metric_t* metric = sol_calloc(1, sizeof(sol_metric_t));
    if (metric == NULL) {
        pthread_mutex_unlock(&prom->metrics_lock);
        return NULL;
    }

    strncpy(metric->name, name, MAX_NAME_LEN - 1);
    if (help != NULL) {
        strncpy(metric->help, help, MAX_HELP_LEN - 1);
    }
    metric->type = SOL_METRIC_COUNTER;

    /* Copy label names */
    if (labels != NULL) {
        for (size_t i = 0; labels[i] != NULL && i < MAX_LABELS; i++) {
            size_t len = strlen(labels[i]);
            metric->labels[i] = sol_alloc(len + 1);
            if (metric->labels[i]) {
                memcpy(metric->labels[i], labels[i], len + 1);
            }
            metric->num_labels++;
        }
    }

    pthread_mutex_init(&metric->lock, NULL);

    prom->metrics[prom->num_metrics++] = metric;
    pthread_mutex_unlock(&prom->metrics_lock);

    return metric;
}

/*
 * Register gauge
 */
sol_metric_t*
sol_metric_gauge_register(
    sol_prometheus_t*   prom,
    const char*         name,
    const char*         help,
    const char* const*  labels
) {
    if (prom == NULL || name == NULL) return NULL;

    pthread_mutex_lock(&prom->metrics_lock);

    if (prom->num_metrics >= MAX_METRICS) {
        pthread_mutex_unlock(&prom->metrics_lock);
        return NULL;
    }

    sol_metric_t* metric = sol_calloc(1, sizeof(sol_metric_t));
    if (metric == NULL) {
        pthread_mutex_unlock(&prom->metrics_lock);
        return NULL;
    }

    strncpy(metric->name, name, MAX_NAME_LEN - 1);
    if (help != NULL) {
        strncpy(metric->help, help, MAX_HELP_LEN - 1);
    }
    metric->type = SOL_METRIC_GAUGE;

    /* Copy label names */
    if (labels != NULL) {
        for (size_t i = 0; labels[i] != NULL && i < MAX_LABELS; i++) {
            size_t len = strlen(labels[i]);
            metric->labels[i] = sol_alloc(len + 1);
            if (metric->labels[i]) {
                memcpy(metric->labels[i], labels[i], len + 1);
            }
            metric->num_labels++;
        }
    }

    pthread_mutex_init(&metric->lock, NULL);

    prom->metrics[prom->num_metrics++] = metric;
    pthread_mutex_unlock(&prom->metrics_lock);

    return metric;
}

/*
 * Register histogram
 */
sol_metric_t*
sol_metric_histogram_register(
    sol_prometheus_t*           prom,
    const char*                 name,
    const char*                 help,
    const char* const*          labels,
    const sol_histogram_buckets_t* buckets
) {
    if (prom == NULL || name == NULL) return NULL;

    pthread_mutex_lock(&prom->metrics_lock);

    if (prom->num_metrics >= MAX_METRICS) {
        pthread_mutex_unlock(&prom->metrics_lock);
        return NULL;
    }

    sol_metric_t* metric = sol_calloc(1, sizeof(sol_metric_t));
    if (metric == NULL) {
        pthread_mutex_unlock(&prom->metrics_lock);
        return NULL;
    }

    strncpy(metric->name, name, MAX_NAME_LEN - 1);
    if (help != NULL) {
        strncpy(metric->help, help, MAX_HELP_LEN - 1);
    }
    metric->type = SOL_METRIC_HISTOGRAM;

    /* Copy label names */
    if (labels != NULL) {
        for (size_t i = 0; labels[i] != NULL && i < MAX_LABELS; i++) {
            size_t len = strlen(labels[i]);
            metric->labels[i] = sol_alloc(len + 1);
            if (metric->labels[i]) {
                memcpy(metric->labels[i], labels[i], len + 1);
            }
            metric->num_labels++;
        }
    }

    /* Copy bucket boundaries */
    if (buckets != NULL && buckets->count > 0) {
        metric->num_buckets = buckets->count < MAX_HISTOGRAM_BUCKETS ?
                             buckets->count : MAX_HISTOGRAM_BUCKETS;
        for (size_t i = 0; i < metric->num_buckets; i++) {
            metric->bucket_boundaries[i] = buckets->boundaries[i];
        }
    }

    pthread_mutex_init(&metric->lock, NULL);

    prom->metrics[prom->num_metrics++] = metric;
    pthread_mutex_unlock(&prom->metrics_lock);

    return metric;
}

/*
 * Counter operations
 */
void
sol_metric_counter_inc(sol_metric_t* metric, const char* const* label_values) {
    sol_metric_counter_add(metric, 1.0, label_values);
}

void
sol_metric_counter_add(sol_metric_t* metric, double value, const char* const* label_values) {
    if (metric == NULL || metric->type != SOL_METRIC_COUNTER || value < 0) return;

    pthread_mutex_lock(&metric->lock);
    sol_metric_entry_t* entry = find_or_create_entry(metric, label_values);
    if (entry != NULL) {
        entry->value += value;
    }
    pthread_mutex_unlock(&metric->lock);
}

/*
 * Gauge operations
 */
void
sol_metric_gauge_set(sol_metric_t* metric, double value, const char* const* label_values) {
    if (metric == NULL || metric->type != SOL_METRIC_GAUGE) return;

    pthread_mutex_lock(&metric->lock);
    sol_metric_entry_t* entry = find_or_create_entry(metric, label_values);
    if (entry != NULL) {
        entry->value = value;
    }
    pthread_mutex_unlock(&metric->lock);
}

void
sol_metric_gauge_inc(sol_metric_t* metric, const char* const* label_values) {
    sol_metric_gauge_add(metric, 1.0, label_values);
}

void
sol_metric_gauge_dec(sol_metric_t* metric, const char* const* label_values) {
    sol_metric_gauge_add(metric, -1.0, label_values);
}

void
sol_metric_gauge_add(sol_metric_t* metric, double value, const char* const* label_values) {
    if (metric == NULL || metric->type != SOL_METRIC_GAUGE) return;

    pthread_mutex_lock(&metric->lock);
    sol_metric_entry_t* entry = find_or_create_entry(metric, label_values);
    if (entry != NULL) {
        entry->value += value;
    }
    pthread_mutex_unlock(&metric->lock);
}

/*
 * Histogram operations
 */
void
sol_metric_histogram_observe(sol_metric_t* metric, double value, const char* const* label_values) {
    if (metric == NULL || metric->type != SOL_METRIC_HISTOGRAM) return;

    pthread_mutex_lock(&metric->lock);
    sol_metric_entry_t* entry = find_or_create_entry(metric, label_values);
    if (entry != NULL) {
        entry->histogram_sum += value;
        entry->histogram_count++;

        /* Increment appropriate bucket counters */
        for (size_t i = 0; i < metric->num_buckets; i++) {
            if (value <= metric->bucket_boundaries[i]) {
                entry->histogram_buckets[i]++;
            }
        }
    }
    pthread_mutex_unlock(&metric->lock);
}

/*
 * Render labels
 */
static size_t
render_labels(char* buf, size_t buf_len, sol_metric_t* metric, sol_metric_entry_t* entry) {
    if (metric->num_labels == 0) {
        return 0;
    }

    size_t written = 0;
    written += snprintf(buf + written, buf_len - written, "{");

    for (size_t i = 0; i < metric->num_labels; i++) {
        if (i > 0) {
            written += snprintf(buf + written, buf_len - written, ",");
        }
        written += snprintf(buf + written, buf_len - written, "%s=\"%s\"",
                           metric->labels[i],
                           entry->values[i] ? entry->values[i] : "");
    }

    written += snprintf(buf + written, buf_len - written, "}");
    return written;
}

/*
 * Render metrics to buffer
 */
size_t
sol_prometheus_render(sol_prometheus_t* prom, char* buf, size_t buf_len) {
    if (prom == NULL || buf == NULL || buf_len == 0) {
        return 0;
    }

    size_t written = 0;
    char label_buf[1024];

    pthread_mutex_lock(&prom->metrics_lock);

    for (size_t m = 0; m < prom->num_metrics && written < buf_len - 256; m++) {
        sol_metric_t* metric = prom->metrics[m];
        pthread_mutex_lock(&metric->lock);

        /* HELP comment */
        if (prom->config.include_help && metric->help[0] != '\0') {
            written += snprintf(buf + written, buf_len - written,
                               "# HELP %s %s\n", metric->name, metric->help);
        }

        /* TYPE comment */
        if (prom->config.include_type) {
            const char* type_str = "untyped";
            switch (metric->type) {
                case SOL_METRIC_COUNTER:   type_str = "counter"; break;
                case SOL_METRIC_GAUGE:     type_str = "gauge"; break;
                case SOL_METRIC_HISTOGRAM: type_str = "histogram"; break;
            }
            written += snprintf(buf + written, buf_len - written,
                               "# TYPE %s %s\n", metric->name, type_str);
        }

        /* Metric values */
        for (size_t e = 0; e < metric->num_entries; e++) {
            sol_metric_entry_t* entry = &metric->entries[e];

            size_t label_len = render_labels(label_buf, sizeof(label_buf), metric, entry);

            if (metric->type == SOL_METRIC_HISTOGRAM) {
                /* Render histogram buckets */
                uint64_t cumulative = 0;
                for (size_t b = 0; b < metric->num_buckets; b++) {
                    cumulative += entry->histogram_buckets[b];

                    if (metric->num_labels > 0) {
                        /* Insert le label before closing brace */
                        char bucket_labels[1024];
                        size_t bl = 0;
                        bl += snprintf(bucket_labels, sizeof(bucket_labels), "{");
                        for (size_t i = 0; i < metric->num_labels; i++) {
                            if (i > 0) bl += snprintf(bucket_labels + bl, sizeof(bucket_labels) - bl, ",");
                            bl += snprintf(bucket_labels + bl, sizeof(bucket_labels) - bl, "%s=\"%s\"",
                                         metric->labels[i], entry->values[i] ? entry->values[i] : "");
                        }
                        bl += snprintf(bucket_labels + bl, sizeof(bucket_labels) - bl, ",le=\"%.6g\"}",
                                     metric->bucket_boundaries[b]);

                        written += snprintf(buf + written, buf_len - written,
                                           "%s_bucket%s %llu\n",
                                           metric->name, bucket_labels,
                                           (unsigned long long)cumulative);
                    } else {
                        written += snprintf(buf + written, buf_len - written,
                                           "%s_bucket{le=\"%.6g\"} %llu\n",
                                           metric->name, metric->bucket_boundaries[b],
                                           (unsigned long long)cumulative);
                    }
                }

                /* +Inf bucket */
                cumulative = entry->histogram_count;
                if (metric->num_labels > 0) {
                    char bucket_labels[1024];
                    size_t bl = 0;
                    bl += snprintf(bucket_labels, sizeof(bucket_labels), "{");
                    for (size_t i = 0; i < metric->num_labels; i++) {
                        if (i > 0) bl += snprintf(bucket_labels + bl, sizeof(bucket_labels) - bl, ",");
                        bl += snprintf(bucket_labels + bl, sizeof(bucket_labels) - bl, "%s=\"%s\"",
                                     metric->labels[i], entry->values[i] ? entry->values[i] : "");
                    }
                    bl += snprintf(bucket_labels + bl, sizeof(bucket_labels) - bl, ",le=\"+Inf\"}");

                    written += snprintf(buf + written, buf_len - written,
                                       "%s_bucket%s %llu\n", metric->name, bucket_labels,
                                       (unsigned long long)cumulative);
                } else {
                    written += snprintf(buf + written, buf_len - written,
                                       "%s_bucket{le=\"+Inf\"} %llu\n", metric->name,
                                       (unsigned long long)cumulative);
                }

                /* Sum and count */
                written += snprintf(buf + written, buf_len - written,
                                   "%s_sum%s %.6g\n",
                                   metric->name, label_len > 0 ? label_buf : "",
                                   entry->histogram_sum);
                written += snprintf(buf + written, buf_len - written,
                                   "%s_count%s %llu\n",
                                   metric->name, label_len > 0 ? label_buf : "",
                                   (unsigned long long)entry->histogram_count);
            } else {
                /* Counter or gauge */
                written += snprintf(buf + written, buf_len - written,
                                   "%s%s %.6g\n",
                                   metric->name, label_len > 0 ? label_buf : "",
                                   entry->value);
            }
        }

        pthread_mutex_unlock(&metric->lock);
    }

    pthread_mutex_unlock(&prom->metrics_lock);

    return written;
}

/*
 * Render metrics to allocated string
 */
char*
sol_prometheus_render_alloc(sol_prometheus_t* prom) {
    if (prom == NULL) return NULL;

    char* buf = sol_alloc(MAX_HTTP_RESPONSE);
    if (buf == NULL) return NULL;

    size_t len = sol_prometheus_render(prom, buf, MAX_HTTP_RESPONSE);
    buf[len] = '\0';

    return buf;
}
