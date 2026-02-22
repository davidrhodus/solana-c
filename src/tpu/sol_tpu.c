/*
 * sol_tpu.c - Transaction Processing Unit Implementation
 *
 * Supports both UDP and QUIC transports for receiving transactions.
 */

#include "sol_tpu.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include "../crypto/sol_ed25519.h"
#include "../txn/sol_transaction.h"
#include "../net/sol_quic.h"
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <poll.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * Packet queue for received transactions
 */
#define PACKET_QUEUE_SIZE 65536

typedef struct {
    sol_tx_packet_t*    packets;
    size_t              head;
    size_t              tail;
    size_t              capacity;
    pthread_mutex_t     lock;
    pthread_cond_t      not_empty;
    pthread_cond_t      not_full;
} packet_queue_t;

/*
 * TPU internal state
 */
struct sol_tpu {
    sol_tpu_config_t        config;

    /* Block producer */
    sol_block_producer_t*   producer;

    /* Network sockets */
    sol_udp_sock_t*         udp_socket;
    sol_quic_t*             quic;
    char*                   generated_quic_cert_path;
    char*                   generated_quic_key_path;

    /* Packet queue */
    packet_queue_t          packet_queue;
    packet_queue_t          verified_queue;

    /* Deduplication */
    sol_dedup_filter_t*     dedup_filter;

    /* Leader state */
    bool                    is_leader;
    uint32_t                leader_addr;
    uint16_t                leader_port;
    uint32_t                leader_vote_addr;
    uint16_t                leader_vote_port;

    /* Statistics */
    sol_tpu_stats_t         stats;

    /* Thread control */
    pthread_t               fetch_thread;
    pthread_t               quic_thread;
    bool                    quic_thread_started;
    pthread_t*              sigverify_threads;
    size_t                  num_sigverify_threads;
    pthread_t*              banking_threads;
    size_t                  num_banking_threads;

    pthread_mutex_t         lock;
    bool                    running;
    bool                    threads_started;
};

static char*
tpu_strdup(const char* s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char* out = sol_alloc(n);
    if (!out) return NULL;
    memcpy(out, s, n);
    return out;
}

/*
 * Dedup filter implementation using hash table
 */
struct sol_dedup_filter {
    sol_signature_t*    sigs;
    sol_slot_t*         slots;
    bool*               valid;
    size_t              capacity;
    size_t              count;
    pthread_mutex_t     lock;
};

/*
 * Initialize packet queue
 */
static sol_err_t
packet_queue_init(packet_queue_t* queue, size_t capacity) {
    queue->packets = sol_calloc(capacity, sizeof(sol_tx_packet_t));
    if (!queue->packets) return SOL_ERR_NOMEM;

    queue->capacity = capacity;
    queue->head = 0;
    queue->tail = 0;
    pthread_mutex_init(&queue->lock, NULL);
    pthread_cond_init(&queue->not_empty, NULL);
    pthread_cond_init(&queue->not_full, NULL);

    return SOL_OK;
}

/*
 * Cleanup packet queue
 */
static void
packet_queue_cleanup(packet_queue_t* queue) {
    sol_free(queue->packets);
    pthread_mutex_destroy(&queue->lock);
    pthread_cond_destroy(&queue->not_empty);
    pthread_cond_destroy(&queue->not_full);
}

/*
 * Push packet to queue
 */
static bool
packet_queue_push(packet_queue_t* queue, const sol_tx_packet_t* packet) {
    pthread_mutex_lock(&queue->lock);

    size_t next_tail = (queue->tail + 1) % queue->capacity;
    if (next_tail == queue->head) {
        /* Queue full */
        pthread_mutex_unlock(&queue->lock);
        return false;
    }

    queue->packets[queue->tail] = *packet;
    queue->tail = next_tail;

    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->lock);
    return true;
}

/*
 * Pop packet from queue (blocking with timeout)
 */
static bool
packet_queue_pop(packet_queue_t* queue, sol_tx_packet_t* out, int timeout_ms) {
    pthread_mutex_lock(&queue->lock);

    while (queue->head == queue->tail) {
        if (timeout_ms == 0) {
            pthread_mutex_unlock(&queue->lock);
            return false;
        }

        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += timeout_ms * 1000000L;
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec += ts.tv_nsec / 1000000000L;
            ts.tv_nsec %= 1000000000L;
        }

        int ret = pthread_cond_timedwait(&queue->not_empty, &queue->lock, &ts);
        if (ret != 0) {
            pthread_mutex_unlock(&queue->lock);
            return false;
        }
    }

    *out = queue->packets[queue->head];
    queue->head = (queue->head + 1) % queue->capacity;

    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->lock);
    return true;
}

/*
 * Get queue size
 */
static size_t
packet_queue_size(packet_queue_t* queue) {
    pthread_mutex_lock(&queue->lock);
    size_t size = (queue->tail - queue->head + queue->capacity) % queue->capacity;
    pthread_mutex_unlock(&queue->lock);
    return size;
}

/*
 * Sigverify thread - verifies and forwards to verified queue
 */
static void*
sigverify_thread_func(void* arg) {
    sol_tpu_t* tpu = (sol_tpu_t*)arg;

    while (tpu->running) {
        sol_tx_packet_t packet;

        if (!packet_queue_pop(&tpu->packet_queue, &packet, 100)) {
            continue;
        }

        /* Parse transaction */
        sol_transaction_t tx;
        sol_err_t err = sol_transaction_decode(packet.data, packet.len, &tx);
        if (err != SOL_OK) {
            continue;
        }

        /* Check for duplicate */
        if (tx.signatures && tx.signatures_len > 0) {
            if (sol_dedup_filter_check(tpu->dedup_filter, &tx.signatures[0])) {
                __atomic_fetch_add(&tpu->stats.duplicates_filtered, 1, __ATOMIC_RELAXED);
                continue;
            }
        }

        __atomic_fetch_add(&tpu->stats.transactions_received, 1, __ATOMIC_RELAXED);

        /* Verify signature */
        if (!sol_sigverify_transaction(&tx)) {
            __atomic_fetch_add(&tpu->stats.signatures_failed, 1, __ATOMIC_RELAXED);
            continue;
        }

        __atomic_fetch_add(&tpu->stats.signatures_verified, 1, __ATOMIC_RELAXED);

        if (!packet_queue_push(&tpu->verified_queue, &packet)) {
            __atomic_fetch_add(&tpu->stats.packets_dropped, 1, __ATOMIC_RELAXED);
            continue;
        }
    }

    return NULL;
}

/*
 * Verify a single transaction's signatures
 */
bool
sol_sigverify_transaction(const sol_transaction_t* tx) {
    if (!tx || !tx->signatures || tx->signatures_len == 0) {
        return false;
    }

    if (!tx->message_data || tx->message_data_len == 0) {
        return false;
    }

    /* Get the pubkeys that should have signed */
    const sol_message_t* msg = &tx->message;
    if (msg->header.num_required_signatures > tx->signatures_len) {
        return false;
    }

    /* Verify each required signature */
    for (uint8_t i = 0; i < msg->header.num_required_signatures; i++) {
        if (i >= msg->account_keys_len) {
            return false;
        }

        const sol_pubkey_t* pubkey = &msg->account_keys[i];
        const sol_signature_t* sig = &tx->signatures[i];

        if (!sol_ed25519_verify(pubkey, tx->message_data, tx->message_data_len, sig)) {
            return false;
        }
    }

    return true;
}

/*
 * Batch signature verification worker
 */
typedef struct {
    sol_transaction_t* const*   txs;
    sol_sigverify_result_t*     results;
    size_t                      start;
    size_t                      count;
} sigverify_work_t;

static void*
sigverify_worker(void* arg) {
    sigverify_work_t* work = (sigverify_work_t*)arg;

    for (size_t i = 0; i < work->count; i++) {
        size_t idx = work->start + i;
        work->results[idx].tx = (sol_transaction_t*)work->txs[idx];
        work->results[idx].valid = sol_sigverify_transaction(work->txs[idx]);
        work->results[idx].error = work->results[idx].valid ? SOL_OK : SOL_ERR_INVALID_SIGNATURE;
    }

    return NULL;
}

/*
 * Batch signature verification
 */
void
sol_sigverify_batch(sol_transaction_t* const* txs,
                    sol_sigverify_result_t* results,
                    size_t count,
                    size_t num_threads) {
    if (!txs || !results || count == 0) return;

    if (num_threads == 0 || num_threads > 16) {
        num_threads = 4;
    }
    if (num_threads > count) {
        num_threads = count;
    }

    /* For small batches, do serial */
    if (count < 10 || num_threads <= 1) {
        sigverify_work_t work = {txs, results, 0, count};
        sigverify_worker(&work);
        return;
    }

    /* Parallel verification */
    pthread_t* threads = sol_alloc(num_threads * sizeof(pthread_t));
    sigverify_work_t* works = sol_alloc(num_threads * sizeof(sigverify_work_t));
    if (!threads || !works) {
        sol_free(threads);
        sol_free(works);
        sigverify_work_t work = {txs, results, 0, count};
        sigverify_worker(&work);
        return;
    }

    size_t per_thread = count / num_threads;
    size_t remainder = count % num_threads;

    size_t offset = 0;
    for (size_t i = 0; i < num_threads; i++) {
        works[i].txs = txs;
        works[i].results = results;
        works[i].start = offset;
        works[i].count = per_thread + (i < remainder ? 1 : 0);
        offset += works[i].count;

        pthread_create(&threads[i], NULL, sigverify_worker, &works[i]);
    }

    for (size_t i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    sol_free(threads);
    sol_free(works);
}

/*
 * Create dedup filter
 */
sol_dedup_filter_t*
sol_dedup_filter_new(size_t capacity) {
    sol_dedup_filter_t* filter = sol_calloc(1, sizeof(sol_dedup_filter_t));
    if (!filter) return NULL;

    filter->sigs = sol_calloc(capacity, sizeof(sol_signature_t));
    filter->slots = sol_calloc(capacity, sizeof(sol_slot_t));
    filter->valid = sol_calloc(capacity, sizeof(bool));

    if (!filter->sigs || !filter->slots || !filter->valid) {
        sol_free(filter->sigs);
        sol_free(filter->slots);
        sol_free(filter->valid);
        sol_free(filter);
        return NULL;
    }

    filter->capacity = capacity;
    filter->count = 0;
    pthread_mutex_init(&filter->lock, NULL);

    return filter;
}

/*
 * Destroy dedup filter
 */
void
sol_dedup_filter_destroy(sol_dedup_filter_t* filter) {
    if (!filter) return;

    sol_free(filter->sigs);
    sol_free(filter->slots);
    sol_free(filter->valid);
    pthread_mutex_destroy(&filter->lock);
    sol_free(filter);
}

/*
 * Hash signature to index
 */
static size_t
sig_hash(const sol_signature_t* sig, size_t capacity) {
    uint64_t h = 0;
    for (int i = 0; i < 8; i++) {
        h = (h << 8) | sig->bytes[i];
    }
    return h % capacity;
}

/*
 * Check if transaction is duplicate
 */
bool
sol_dedup_filter_check(sol_dedup_filter_t* filter, const sol_signature_t* sig) {
    if (!filter || !sig) return false;

    pthread_mutex_lock(&filter->lock);

    size_t idx = sig_hash(sig, filter->capacity);
    size_t start_idx = idx;

    /* Linear probing */
    do {
        if (!filter->valid[idx]) {
            /* Empty slot - not duplicate, add it */
            filter->sigs[idx] = *sig;
            filter->valid[idx] = true;
            filter->count++;
            pthread_mutex_unlock(&filter->lock);
            return false;
        }

        if (memcmp(&filter->sigs[idx], sig, sizeof(sol_signature_t)) == 0) {
            /* Found duplicate */
            pthread_mutex_unlock(&filter->lock);
            return true;
        }

        idx = (idx + 1) % filter->capacity;
    } while (idx != start_idx);

    /* Table full - evict oldest and add */
    filter->sigs[start_idx] = *sig;
    pthread_mutex_unlock(&filter->lock);
    return false;
}

/*
 * Purge old entries
 */
void
sol_dedup_filter_purge(sol_dedup_filter_t* filter, sol_slot_t min_slot) {
    if (!filter) return;

    pthread_mutex_lock(&filter->lock);

    for (size_t i = 0; i < filter->capacity; i++) {
        if (filter->valid[i] && filter->slots[i] < min_slot) {
            filter->valid[i] = false;
            filter->count--;
        }
    }

    pthread_mutex_unlock(&filter->lock);
}

/*
 * Get filter size
 */
size_t
sol_dedup_filter_size(const sol_dedup_filter_t* filter) {
    if (!filter) return 0;
    return filter->count;
}

/*
 * QUIC stream callback - receives transactions from QUIC connections
 */
static bool
quic_stream_callback(sol_quic_conn_t* conn, uint64_t stream_id,
                     const uint8_t* data, size_t len, bool fin, void* ctx) {
    (void)conn;
    (void)stream_id;
    (void)fin;

    sol_tpu_t* tpu = (sol_tpu_t*)ctx;
    if (!tpu || !tpu->running) return false;

    /* Only process complete transactions (fin = true) */
    if (!fin || len == 0 || len > sizeof(((sol_tx_packet_t*)0)->data)) {
        return true;  /* Continue receiving */
    }

    /* Create packet from QUIC stream data */
    sol_tx_packet_t packet;
    memcpy(packet.data, data, len);
    packet.len = len;
    packet.src_ip = 0;  /* QUIC doesn't expose raw IP easily */
    packet.src_port = 0;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    packet.received_ns = ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    if (!packet_queue_push(&tpu->packet_queue, &packet)) {
        __atomic_fetch_add(&tpu->stats.packets_dropped, 1, __ATOMIC_RELAXED);
    } else {
        __atomic_fetch_add(&tpu->stats.packets_received, 1, __ATOMIC_RELAXED);
    }

    return true;  /* Keep connection open */
}

/*
 * QUIC processing thread - handles QUIC event loop
 */
static void*
quic_thread_func(void* arg) {
    sol_tpu_t* tpu = (sol_tpu_t*)arg;

    while (tpu->running && tpu->quic) {
        /* Process incoming packets */
        int processed = sol_quic_process(tpu->quic);
        if (processed < 0) {
            /* Error - sleep briefly and retry */
            struct timespec ts = {0, 1000000};  /* 1ms */
            nanosleep(&ts, NULL);
            continue;
        }

        /* Get next timeout */
        uint64_t timeout_ms = sol_quic_timeout(tpu->quic);
        if (timeout_ms > 100) timeout_ms = 100;  /* Cap at 100ms */

        /* Poll on the QUIC socket */
        int fd = sol_quic_fd(tpu->quic);
        if (fd >= 0) {
            struct pollfd pfd = {
                .fd = fd,
                .events = POLLIN,
                .revents = 0
            };
            poll(&pfd, 1, (int)timeout_ms);
        } else {
            /* No socket, just sleep */
            struct timespec ts = {0, timeout_ms * 1000000};
            nanosleep(&ts, NULL);
        }
    }

    return NULL;
}

/*
 * Fetch thread - receives packets from network
 */
static void*
fetch_thread_func(void* arg) {
    sol_tpu_t* tpu = (sol_tpu_t*)arg;

    while (tpu->running) {
        if (!tpu->udp_socket) {
            struct timespec ts = {0, 10000000};  /* 10ms */
            nanosleep(&ts, NULL);
            continue;
        }

        sol_tx_packet_t packet;
        sol_sockaddr_t src_addr;
        size_t recv_len = sizeof(packet.data);

        sol_err_t err = sol_udp_recv(tpu->udp_socket, packet.data, &recv_len, &src_addr);

        if (err == SOL_OK && recv_len > 0) {
            packet.len = recv_len;
            packet.src_ip = src_addr.addr.sin.sin_addr.s_addr;
            packet.src_port = ntohs(src_addr.addr.sin.sin_port);

            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            packet.received_ns = ts.tv_sec * 1000000000ULL + ts.tv_nsec;

            if (!packet_queue_push(&tpu->packet_queue, &packet)) {
                __atomic_fetch_add(&tpu->stats.packets_dropped, 1, __ATOMIC_RELAXED);
            } else {
                __atomic_fetch_add(&tpu->stats.packets_received, 1, __ATOMIC_RELAXED);
            }
        }
    }

    return NULL;
}

/*
 * Banking thread - processes transactions
 */
static void*
banking_thread_func(void* arg) {
    sol_tpu_t* tpu = (sol_tpu_t*)arg;

    while (tpu->running) {
        sol_tx_packet_t packet;

        if (!packet_queue_pop(&tpu->verified_queue, &packet, 100)) {
            continue;
        }

        /* Parse transaction */
        sol_transaction_t tx;
        sol_err_t err = sol_transaction_decode(packet.data, packet.len, &tx);
        if (err != SOL_OK) {
            continue;
        }

        /* If leader, process transaction; otherwise forward */
        pthread_mutex_lock(&tpu->lock);
        bool is_leader = tpu->is_leader;
        pthread_mutex_unlock(&tpu->lock);

        if (is_leader && tpu->producer) {
            err = sol_block_producer_submit(tpu->producer, &tx);
            if (err == SOL_OK) {
                __atomic_fetch_add(&tpu->stats.transactions_processed, 1, __ATOMIC_RELAXED);
            }
        } else if (tpu->config.forward_transactions) {
            /* Forward to leader */
            pthread_mutex_lock(&tpu->lock);
            uint32_t leader_addr = tpu->leader_addr;
            uint16_t leader_port = tpu->leader_port;
            pthread_mutex_unlock(&tpu->lock);

            if (leader_addr != 0 && tpu->udp_socket) {
                sol_sockaddr_t dest;
                memset(&dest, 0, sizeof(dest));
                dest.addr.sin.sin_family = AF_INET;
                dest.addr.sin.sin_addr.s_addr = leader_addr;
                dest.addr.sin.sin_port = htons(leader_port);
                dest.len = sizeof(struct sockaddr_in);
                sol_udp_send(tpu->udp_socket, packet.data, packet.len, &dest);
                __atomic_fetch_add(&tpu->stats.transactions_forwarded, 1, __ATOMIC_RELAXED);
            }
        }
    }

    return NULL;
}

/*
 * Create TPU
 */
sol_tpu_t*
sol_tpu_new(sol_block_producer_t* producer, const sol_tpu_config_t* config) {
    sol_tpu_t* tpu = sol_calloc(1, sizeof(sol_tpu_t));
    if (!tpu) return NULL;

    if (config) {
        tpu->config = *config;
    } else {
        tpu->config = (sol_tpu_config_t)SOL_TPU_CONFIG_DEFAULT;
    }

    tpu->producer = producer;

    /* Initialize packet queue */
    if (packet_queue_init(&tpu->packet_queue, PACKET_QUEUE_SIZE) != SOL_OK) {
        sol_free(tpu);
        return NULL;
    }

    if (packet_queue_init(&tpu->verified_queue, PACKET_QUEUE_SIZE) != SOL_OK) {
        packet_queue_cleanup(&tpu->packet_queue);
        sol_free(tpu);
        return NULL;
    }

    /* Create dedup filter */
    tpu->dedup_filter = sol_dedup_filter_new(tpu->config.max_pending_txs);
    if (!tpu->dedup_filter) {
        packet_queue_cleanup(&tpu->packet_queue);
        packet_queue_cleanup(&tpu->verified_queue);
        sol_free(tpu);
        return NULL;
    }

    pthread_mutex_init(&tpu->lock, NULL);
    tpu->running = false;
    tpu->threads_started = false;
    tpu->is_leader = false;

    return tpu;
}

/*
 * Destroy TPU
 */
void
sol_tpu_destroy(sol_tpu_t* tpu) {
    if (!tpu) return;

    sol_tpu_stop(tpu);

    if (tpu->generated_quic_cert_path) {
        unlink(tpu->generated_quic_cert_path);
        sol_free(tpu->generated_quic_cert_path);
        tpu->generated_quic_cert_path = NULL;
    }
    if (tpu->generated_quic_key_path) {
        unlink(tpu->generated_quic_key_path);
        sol_free(tpu->generated_quic_key_path);
        tpu->generated_quic_key_path = NULL;
    }

    sol_dedup_filter_destroy(tpu->dedup_filter);
    packet_queue_cleanup(&tpu->packet_queue);
    packet_queue_cleanup(&tpu->verified_queue);

    if (tpu->udp_socket) {
        sol_udp_destroy(tpu->udp_socket);
    }

    /* QUIC is cleaned up in sol_tpu_stop() */

    sol_free(tpu->sigverify_threads);
    sol_free(tpu->banking_threads);

    pthread_mutex_destroy(&tpu->lock);
    sol_free(tpu);
}

/*
 * Start TPU
 */
sol_err_t
sol_tpu_start(sol_tpu_t* tpu) {
    if (!tpu) return SOL_ERR_INVAL;
    if (tpu->running) return SOL_OK;

    /* Clean up any stale state from a prior start/stop cycle */
    sol_free(tpu->sigverify_threads);
    tpu->sigverify_threads = NULL;
    tpu->num_sigverify_threads = 0;
    sol_free(tpu->banking_threads);
    tpu->banking_threads = NULL;
    tpu->num_banking_threads = 0;
    tpu->threads_started = false;
    tpu->quic_thread_started = false;

    if (tpu->quic) {
        sol_quic_stop(tpu->quic);
        sol_quic_destroy(tpu->quic);
        tpu->quic = NULL;
    }

    if (tpu->udp_socket) {
        sol_udp_destroy(tpu->udp_socket);
        tpu->udp_socket = NULL;
    }

    /* Create UDP socket if enabled */
    if (tpu->config.enable_udp) {
        sol_udp_config_t udp_config = SOL_UDP_CONFIG_DEFAULT;
        udp_config.bind_port = tpu->config.base_port + SOL_TPU_PORT_OFFSET;
        tpu->udp_socket = sol_udp_new(&udp_config);
        if (!tpu->udp_socket) {
            sol_log_warn("Failed to bind TPU UDP socket on port %u",
                         tpu->config.base_port + SOL_TPU_PORT_OFFSET);
        }
    }

    /* Create QUIC server if enabled */
    if (tpu->config.enable_quic) {
        if ((tpu->config.quic_cert_path == NULL) != (tpu->config.quic_key_path == NULL)) {
            sol_log_warn("TPU QUIC enabled but TLS cert/key configuration is incomplete; disabling QUIC");
            tpu->config.enable_quic = false;
        } else if (tpu->config.quic_cert_path == NULL && tpu->config.quic_key_path == NULL) {
            /* Auto-generate self-signed cert/key for development if none configured */
            if (!tpu->generated_quic_cert_path || !tpu->generated_quic_key_path) {
                char cert_template[] = "/tmp/solana-c-quic-cert-XXXXXX";
                char key_template[] = "/tmp/solana-c-quic-key-XXXXXX";

                int cert_fd = mkstemp(cert_template);
                int key_fd = mkstemp(key_template);
                if (cert_fd >= 0) close(cert_fd);
                if (key_fd >= 0) close(key_fd);

                if (cert_fd < 0 || key_fd < 0) {
                    if (cert_fd >= 0) unlink(cert_template);
                    if (key_fd >= 0) unlink(key_template);
                    sol_log_warn("Failed to create temporary QUIC TLS files; disabling QUIC");
                    tpu->config.enable_quic = false;
                } else {
                    /* Remove placeholders so openssl can create the actual files */
                    unlink(cert_template);
                    unlink(key_template);

                    sol_err_t gerr = sol_quic_generate_test_cert(cert_template, key_template);
                    if (gerr != SOL_OK) {
                        unlink(cert_template);
                        unlink(key_template);
                        sol_log_warn("Failed to generate QUIC test certificate; disabling QUIC");
                        tpu->config.enable_quic = false;
                    } else {
                        tpu->generated_quic_cert_path = tpu_strdup(cert_template);
                        tpu->generated_quic_key_path = tpu_strdup(key_template);
                        if (!tpu->generated_quic_cert_path || !tpu->generated_quic_key_path) {
                            unlink(cert_template);
                            unlink(key_template);
                            sol_free(tpu->generated_quic_cert_path);
                            sol_free(tpu->generated_quic_key_path);
                            tpu->generated_quic_cert_path = NULL;
                            tpu->generated_quic_key_path = NULL;
                            sol_log_warn("Failed to store generated QUIC TLS paths; disabling QUIC");
                            tpu->config.enable_quic = false;
                        } else {
                            tpu->config.quic_cert_path = tpu->generated_quic_cert_path;
                            tpu->config.quic_key_path = tpu->generated_quic_key_path;
                            sol_log_info("TPU QUIC TLS: generated self-signed certificate for testing");
                        }
                    }
                }
            } else {
                tpu->config.quic_cert_path = tpu->generated_quic_cert_path;
                tpu->config.quic_key_path = tpu->generated_quic_key_path;
            }
        }

        if (!tpu->config.enable_quic) {
            /* disabled above */
        } else {
        sol_quic_config_t quic_config = SOL_QUIC_CONFIG_DEFAULT;
        quic_config.bind_port = tpu->config.base_port + SOL_TPU_QUIC_PORT_OFFSET;
        quic_config.cert_path = tpu->config.quic_cert_path;
        quic_config.key_path = tpu->config.quic_key_path;
        quic_config.max_connections = tpu->config.max_pending_txs / 100;  /* Reasonable limit */
        quic_config.max_streams = SOL_QUIC_MAX_STREAMS;

        tpu->quic = sol_quic_new(&quic_config);
        if (tpu->quic) {
            /* Set stream callback to receive transactions */
            sol_quic_set_stream_callback(tpu->quic, quic_stream_callback, tpu);

            /* Start QUIC server */
            sol_err_t err = sol_quic_start(tpu->quic);
            if (err != SOL_OK) {
                sol_log_warn("Failed to start QUIC server on port %u: %s",
                             quic_config.bind_port, sol_err_str(err));
                sol_quic_destroy(tpu->quic);
                tpu->quic = NULL;
            } else {
                sol_log_info("TPU QUIC transport enabled on port %u",
                             quic_config.bind_port);
            }
        } else {
            sol_log_warn("Failed to create QUIC server");
        }
        }
    }

    tpu->running = true;

    bool fetch_thread_started = false;
    size_t sigverify_threads_started = 0;
    size_t banking_threads_started = 0;

    /* Start fetch thread (for UDP) */
    if (pthread_create(&tpu->fetch_thread, NULL, fetch_thread_func, tpu) != 0) {
        sol_err_t ret = SOL_ERR_IO;
        tpu->running = false;
        if (tpu->quic) {
            sol_quic_stop(tpu->quic);
            sol_quic_destroy(tpu->quic);
            tpu->quic = NULL;
        }
        if (tpu->udp_socket) {
            sol_udp_destroy(tpu->udp_socket);
            tpu->udp_socket = NULL;
        }
        return ret;
    }
    fetch_thread_started = true;

    /* Start sigverify threads */
    tpu->num_sigverify_threads = tpu->config.sigverify_threads;
    if (tpu->num_sigverify_threads == 0) {
        tpu->num_sigverify_threads = 1;
    }

    tpu->sigverify_threads = sol_calloc(tpu->num_sigverify_threads, sizeof(pthread_t));
    if (!tpu->sigverify_threads) {
        sol_err_t ret = SOL_ERR_NOMEM;
        tpu->running = false;
        pthread_cond_broadcast(&tpu->packet_queue.not_empty);
        pthread_cond_broadcast(&tpu->verified_queue.not_empty);
        if (fetch_thread_started) {
            pthread_join(tpu->fetch_thread, NULL);
        }
        if (tpu->quic_thread_started) {
            pthread_join(tpu->quic_thread, NULL);
            tpu->quic_thread_started = false;
        }
        if (tpu->quic) {
            sol_quic_stop(tpu->quic);
            sol_quic_destroy(tpu->quic);
            tpu->quic = NULL;
        }
        if (tpu->udp_socket) {
            sol_udp_destroy(tpu->udp_socket);
            tpu->udp_socket = NULL;
        }
        return ret;
    }

    for (size_t i = 0; i < tpu->num_sigverify_threads; i++) {
        if (pthread_create(&tpu->sigverify_threads[i], NULL, sigverify_thread_func, tpu) != 0) {
            tpu->running = false;
            pthread_cond_broadcast(&tpu->packet_queue.not_empty);
            pthread_cond_broadcast(&tpu->verified_queue.not_empty);
            for (size_t j = 0; j < sigverify_threads_started; j++) {
                pthread_join(tpu->sigverify_threads[j], NULL);
            }
            sol_free(tpu->sigverify_threads);
            tpu->sigverify_threads = NULL;
            tpu->num_sigverify_threads = 0;

            if (fetch_thread_started) {
                pthread_join(tpu->fetch_thread, NULL);
            }

            if (tpu->quic_thread_started) {
                pthread_join(tpu->quic_thread, NULL);
                tpu->quic_thread_started = false;
            }

            if (tpu->quic) {
                sol_quic_stop(tpu->quic);
                sol_quic_destroy(tpu->quic);
                tpu->quic = NULL;
            }

            if (tpu->udp_socket) {
                sol_udp_destroy(tpu->udp_socket);
                tpu->udp_socket = NULL;
            }

            return SOL_ERR_IO;
        }
        sigverify_threads_started++;
    }

    /* Start QUIC thread if QUIC is enabled */
    if (tpu->quic) {
        if (pthread_create(&tpu->quic_thread, NULL, quic_thread_func, tpu) != 0) {
            sol_log_warn("Failed to start QUIC thread");
            sol_quic_stop(tpu->quic);
            sol_quic_destroy(tpu->quic);
            tpu->quic = NULL;
        } else {
            tpu->quic_thread_started = true;
        }
    }

    /* Start banking threads */
    tpu->num_banking_threads = tpu->config.banking_threads;
    if (tpu->num_banking_threads == 0) {
        tpu->num_banking_threads = 1;
    }
    tpu->banking_threads = sol_calloc(tpu->num_banking_threads, sizeof(pthread_t));
    if (!tpu->banking_threads) {
        sol_err_t ret = SOL_ERR_NOMEM;
        tpu->running = false;
        pthread_cond_broadcast(&tpu->packet_queue.not_empty);
        pthread_cond_broadcast(&tpu->verified_queue.not_empty);

        if (fetch_thread_started) {
            pthread_join(tpu->fetch_thread, NULL);
        }

        for (size_t i = 0; i < sigverify_threads_started; i++) {
            pthread_join(tpu->sigverify_threads[i], NULL);
        }

        if (tpu->quic_thread_started) {
            pthread_join(tpu->quic_thread, NULL);
            tpu->quic_thread_started = false;
        }

        if (tpu->quic) {
            sol_quic_stop(tpu->quic);
            sol_quic_destroy(tpu->quic);
            tpu->quic = NULL;
        }

        if (tpu->udp_socket) {
            sol_udp_destroy(tpu->udp_socket);
            tpu->udp_socket = NULL;
        }

        sol_free(tpu->sigverify_threads);
        tpu->sigverify_threads = NULL;
        tpu->num_sigverify_threads = 0;

        return ret;
    }

    for (size_t i = 0; i < tpu->num_banking_threads; i++) {
        if (pthread_create(&tpu->banking_threads[i], NULL, banking_thread_func, tpu) != 0) {
            tpu->running = false;
            pthread_cond_broadcast(&tpu->packet_queue.not_empty);
            pthread_cond_broadcast(&tpu->verified_queue.not_empty);

            for (size_t j = 0; j < banking_threads_started; j++) {
                pthread_join(tpu->banking_threads[j], NULL);
            }

            if (fetch_thread_started) {
                pthread_join(tpu->fetch_thread, NULL);
            }

            for (size_t j = 0; j < sigverify_threads_started; j++) {
                pthread_join(tpu->sigverify_threads[j], NULL);
            }

            if (tpu->quic_thread_started) {
                pthread_join(tpu->quic_thread, NULL);
                tpu->quic_thread_started = false;
            }

            if (tpu->quic) {
                sol_quic_stop(tpu->quic);
                sol_quic_destroy(tpu->quic);
                tpu->quic = NULL;
            }

            if (tpu->udp_socket) {
                sol_udp_destroy(tpu->udp_socket);
                tpu->udp_socket = NULL;
            }

            sol_free(tpu->banking_threads);
            tpu->banking_threads = NULL;
            tpu->num_banking_threads = 0;
            sol_free(tpu->sigverify_threads);
            tpu->sigverify_threads = NULL;
            tpu->num_sigverify_threads = 0;

            return SOL_ERR_IO;
        }
        banking_threads_started++;
    }

    tpu->threads_started = true;
    sol_log_info("TPU started on port %u", tpu->config.base_port);

    return SOL_OK;
}

/*
 * Stop TPU
 */
sol_err_t
sol_tpu_stop(sol_tpu_t* tpu) {
    if (!tpu) return SOL_ERR_INVAL;
    if (!tpu->running) return SOL_OK;

    tpu->running = false;

    /* Wake up any blocked threads */
    pthread_cond_broadcast(&tpu->packet_queue.not_empty);
    pthread_cond_broadcast(&tpu->verified_queue.not_empty);

    if (tpu->threads_started) {
        pthread_join(tpu->fetch_thread, NULL);

        for (size_t i = 0; i < tpu->num_sigverify_threads; i++) {
            pthread_join(tpu->sigverify_threads[i], NULL);
        }

        for (size_t i = 0; i < tpu->num_banking_threads; i++) {
            pthread_join(tpu->banking_threads[i], NULL);
        }

        tpu->threads_started = false;
    }

    /* Stop QUIC thread */
    if (tpu->quic_thread_started) {
        pthread_join(tpu->quic_thread, NULL);
        tpu->quic_thread_started = false;
    }

    /* Stop and destroy QUIC server */
    if (tpu->quic) {
        sol_quic_stop(tpu->quic);
        sol_quic_destroy(tpu->quic);
        tpu->quic = NULL;
    }

    if (tpu->udp_socket) {
        sol_udp_destroy(tpu->udp_socket);
        tpu->udp_socket = NULL;
    }

    sol_free(tpu->sigverify_threads);
    tpu->sigverify_threads = NULL;
    tpu->num_sigverify_threads = 0;

    sol_free(tpu->banking_threads);
    tpu->banking_threads = NULL;
    tpu->num_banking_threads = 0;

    sol_log_info("TPU stopped");
    return SOL_OK;
}

/*
 * Check if running
 */
bool
sol_tpu_is_running(const sol_tpu_t* tpu) {
    if (!tpu) return false;
    return tpu->running;
}

/*
 * Set leader mode
 */
sol_err_t
sol_tpu_set_leader_mode(sol_tpu_t* tpu, bool is_leader,
                         uint32_t leader_addr, uint16_t leader_port) {
    if (!tpu) return SOL_ERR_INVAL;

    bool changed = false;
    pthread_mutex_lock(&tpu->lock);
    changed = (tpu->is_leader != is_leader) ||
              (tpu->leader_addr != leader_addr) ||
              (tpu->leader_port != leader_port);
    tpu->is_leader = is_leader;
    tpu->leader_addr = leader_addr;
    tpu->leader_port = leader_port;
    pthread_mutex_unlock(&tpu->lock);

    if (changed) {
        if (is_leader) {
            sol_log_info("TPU: Now leader");
        } else if (leader_addr != 0 && leader_port != 0) {
            char ip[INET_ADDRSTRLEN] = {0};
            struct in_addr a = { .s_addr = leader_addr };
            const char* res = inet_ntop(AF_INET, &a, ip, sizeof(ip));
            sol_log_info("TPU: Forwarding to leader %s:%u",
                         res ? res : "unknown", (unsigned)leader_port);
        } else {
            sol_log_info("TPU: Forwarding enabled (leader unknown)");
        }
    }

    return SOL_OK;
}

sol_err_t
sol_tpu_set_vote_forwarding_target(sol_tpu_t* tpu, uint32_t leader_addr, uint16_t leader_port) {
    if (!tpu) return SOL_ERR_INVAL;

    bool changed = false;
    pthread_mutex_lock(&tpu->lock);
    changed = (tpu->leader_vote_addr != leader_addr) ||
              (tpu->leader_vote_port != leader_port);
    tpu->leader_vote_addr = leader_addr;
    tpu->leader_vote_port = leader_port;
    pthread_mutex_unlock(&tpu->lock);

    if (changed) {
        if (leader_addr != 0 && leader_port != 0) {
            char ip[INET_ADDRSTRLEN] = {0};
            struct in_addr a = { .s_addr = leader_addr };
            const char* res = inet_ntop(AF_INET, &a, ip, sizeof(ip));
            sol_log_debug("TPU: Vote forwarding to leader %s:%u",
                          res ? res : "unknown", (unsigned)leader_port);
        } else {
            sol_log_debug("TPU: Vote forwarding enabled (leader unknown)");
        }
    }

    return SOL_OK;
}

static sol_err_t
tpu_submit_common(sol_tpu_t* tpu, const sol_transaction_t* tx, bool is_vote) {
    if (!tpu || !tx) return SOL_ERR_INVAL;

    pthread_mutex_lock(&tpu->lock);
    bool is_leader = tpu->is_leader;
    uint32_t leader_addr = tpu->leader_addr;
    uint16_t leader_port = tpu->leader_port;
    uint32_t leader_vote_addr = tpu->leader_vote_addr;
    uint16_t leader_vote_port = tpu->leader_vote_port;
    sol_udp_sock_t* udp_socket = tpu->udp_socket;
    bool forward_transactions = tpu->config.forward_transactions;
    pthread_mutex_unlock(&tpu->lock);

    /* Check duplicate */
    if (tx->signatures && tx->signatures_len > 0) {
        if (sol_dedup_filter_check(tpu->dedup_filter, &tx->signatures[0])) {
            __atomic_fetch_add(&tpu->stats.duplicates_filtered, 1, __ATOMIC_RELAXED);
            return SOL_ERR_TX_DUPLICATE;
        }
    }

    __atomic_fetch_add(&tpu->stats.transactions_received, 1, __ATOMIC_RELAXED);

    /* Verify signature */
    if (!sol_sigverify_transaction(tx)) {
        __atomic_fetch_add(&tpu->stats.signatures_failed, 1, __ATOMIC_RELAXED);
        return SOL_ERR_TX_SIGNATURE;
    }

    __atomic_fetch_add(&tpu->stats.signatures_verified, 1, __ATOMIC_RELAXED);

    /* If leader, submit to local banking/producer. */
    if (is_leader) {
        if (tpu->producer) {
            sol_err_t err = sol_block_producer_submit(tpu->producer, tx);
            if (err == SOL_OK) {
                __atomic_fetch_add(&tpu->stats.transactions_processed, 1, __ATOMIC_RELAXED);
            }
            return err;
        }

        return SOL_ERR_UNINITIALIZED;
    }

    /* Otherwise forward to current leader. */
    if (!forward_transactions) {
        return SOL_ERR_PERM;
    }

    uint32_t dest_addr = leader_addr;
    uint16_t dest_port = leader_port;
    if (is_vote && leader_vote_addr != 0 && leader_vote_port != 0) {
        dest_addr = leader_vote_addr;
        dest_port = leader_vote_port;
    }

    if (dest_addr == 0 || dest_port == 0 || !udp_socket) {
        return SOL_ERR_PEER_UNAVAILABLE;
    }

    uint8_t buf[SOL_MAX_TX_SIZE];
    size_t written = 0;
    sol_err_t err = sol_transaction_encode(tx, buf, sizeof(buf), &written);
    if (err != SOL_OK) return err;

    sol_sockaddr_t dest;
    memset(&dest, 0, sizeof(dest));
    dest.addr.sin.sin_family = AF_INET;
    dest.addr.sin.sin_addr.s_addr = dest_addr;
    dest.addr.sin.sin_port = htons(dest_port);
    dest.len = sizeof(struct sockaddr_in);

    err = sol_udp_send(udp_socket, buf, written, &dest);
    if (err == SOL_OK) {
        __atomic_fetch_add(&tpu->stats.transactions_forwarded, 1, __ATOMIC_RELAXED);
    }
    return err;
}

/*
 * Submit transaction directly
 */
sol_err_t
sol_tpu_submit(sol_tpu_t* tpu, const sol_transaction_t* tx) {
    return tpu_submit_common(tpu, tx, false);
}

/*
 * Submit raw transaction
 */
sol_err_t
sol_tpu_submit_raw(sol_tpu_t* tpu, const uint8_t* data, size_t len) {
    if (!tpu || !data || len == 0) return SOL_ERR_INVAL;

    sol_transaction_t tx;
    sol_err_t err = sol_transaction_decode(data, len, &tx);
    if (err != SOL_OK) return err;

    return sol_tpu_submit(tpu, &tx);
}

sol_err_t
sol_tpu_submit_vote_raw(sol_tpu_t* tpu, const uint8_t* data, size_t len) {
    if (!tpu || !data || len == 0) return SOL_ERR_INVAL;

    sol_transaction_t tx;
    sol_err_t err = sol_transaction_decode(data, len, &tx);
    if (err != SOL_OK) return err;

    return tpu_submit_common(tpu, &tx, true);
}

/*
 * Get statistics
 */
sol_tpu_stats_t
sol_tpu_stats(const sol_tpu_t* tpu) {
    sol_tpu_stats_t stats = {0};
    if (!tpu) return stats;

    stats.packets_received = __atomic_load_n(&tpu->stats.packets_received, __ATOMIC_RELAXED);
    stats.packets_dropped = __atomic_load_n(&tpu->stats.packets_dropped, __ATOMIC_RELAXED);
    stats.transactions_received = __atomic_load_n(&tpu->stats.transactions_received, __ATOMIC_RELAXED);
    stats.transactions_processed = __atomic_load_n(&tpu->stats.transactions_processed, __ATOMIC_RELAXED);
    stats.transactions_forwarded = __atomic_load_n(&tpu->stats.transactions_forwarded, __ATOMIC_RELAXED);
    stats.signatures_verified = __atomic_load_n(&tpu->stats.signatures_verified, __ATOMIC_RELAXED);
    stats.signatures_failed = __atomic_load_n(&tpu->stats.signatures_failed, __ATOMIC_RELAXED);
    stats.duplicates_filtered = __atomic_load_n(&tpu->stats.duplicates_filtered, __ATOMIC_RELAXED);

    return stats;
}

/*
 * Reset statistics
 */
void
sol_tpu_stats_reset(sol_tpu_t* tpu) {
    if (!tpu) return;
    memset(&tpu->stats, 0, sizeof(tpu->stats));
}

/*
 * Get pending count
 */
size_t
sol_tpu_pending_count(const sol_tpu_t* tpu) {
    if (!tpu) return 0;
    return packet_queue_size((packet_queue_t*)&tpu->packet_queue);
}
