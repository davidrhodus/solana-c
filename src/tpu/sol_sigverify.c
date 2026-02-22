/*
 * sol_sigverify.c - Parallel Signature Verification Implementation
 */

#include "sol_sigverify.h"
#include "../crypto/sol_ed25519.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include <string.h>
#include <time.h>

/*
 * Get time in nanoseconds
 */
static uint64_t
get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/*
 * Worker thread state
 */
typedef struct {
    pthread_t           thread;
    sol_sigverify_t*    sv;
    bool                running;
    int                 worker_id;
} worker_t;

/*
 * Work item for verification queue
 */
typedef struct work_item {
    sol_sigverify_batch_t*  batch;
    size_t                  start_idx;
    size_t                  end_idx;
    struct work_item*       next;
} work_item_t;

/*
 * Sigverify service structure
 */
struct sol_sigverify {
    sol_sigverify_config_t  config;
    worker_t*               workers;
    size_t                  num_workers;

    /* Work queue */
    work_item_t*            work_head;
    work_item_t*            work_tail;
    pthread_mutex_t         work_lock;
    pthread_cond_t          work_cond;
    pthread_cond_t          done_cond;
    size_t                  pending_items;
    bool                    shutdown;

    /* Statistics */
    sol_sigverify_stats_t   stats;
    pthread_mutex_t         stats_lock;
};

/*
 * Verify a single transaction's signatures
 */
sol_sigverify_status_t
sol_sigverify_verify_tx(const sol_transaction_t* tx) {
    if (!tx) {
        return SOL_SIGVERIFY_MALFORMED;
    }

    /* Validate basic structure */
    if (tx->signatures_len == 0 || tx->signatures_len > tx->message.account_keys_len) {
        return SOL_SIGVERIFY_MALFORMED;
    }

    if (!tx->signatures || !tx->message.account_keys) {
        return SOL_SIGVERIFY_MALFORMED;
    }

    /* Use pre-serialized message data if available */
    const uint8_t* msg_data = tx->message_data;
    size_t msg_len = tx->message_data_len;

    /* If no pre-serialized data, we can't verify */
    if (!msg_data || msg_len == 0) {
        return SOL_SIGVERIFY_MALFORMED;
    }

    /* Verify each signature */
    for (size_t i = 0; i < tx->signatures_len; i++) {
        const sol_signature_t* sig = &tx->signatures[i];
        const sol_pubkey_t* pubkey = &tx->message.account_keys[i];

        /* Ed25519 verification: (pubkey, msg, msg_len, sig) */
        bool valid = sol_ed25519_verify(
            pubkey,
            msg_data,
            msg_len,
            sig
        );

        if (!valid) {
            return SOL_SIGVERIFY_INVALID;
        }
    }

    return SOL_SIGVERIFY_OK;
}

/*
 * Worker thread function
 */
static void*
worker_thread(void* arg) {
    worker_t* worker = (worker_t*)arg;
    sol_sigverify_t* sv = worker->sv;

    while (true) {
        pthread_mutex_lock(&sv->work_lock);

        /* Wait for work */
        while (!sv->shutdown && sv->work_head == NULL) {
            pthread_cond_wait(&sv->work_cond, &sv->work_lock);
        }

        if (sv->shutdown) {
            pthread_mutex_unlock(&sv->work_lock);
            break;
        }

        /* Get work item */
        work_item_t* item = sv->work_head;
        if (item) {
            sv->work_head = item->next;
            if (!sv->work_head) {
                sv->work_tail = NULL;
            }
        }

        pthread_mutex_unlock(&sv->work_lock);

        if (!item) continue;

        /* Process work item */
        sol_sigverify_batch_t* batch = item->batch;
        uint64_t start_time = get_time_ns();
        uint64_t sigs_verified = 0;

        for (size_t i = item->start_idx; i < item->end_idx && i < batch->count; i++) {
            sol_sigverify_entry_t* entry = &batch->entries[i];

            if (entry->status == SOL_SIGVERIFY_PENDING) {
                uint64_t tx_start = get_time_ns();
                entry->status = sol_sigverify_verify_tx(entry->tx);
                entry->verify_time_ns = get_time_ns() - tx_start;

                if (entry->tx) {
                    sigs_verified += entry->tx->signatures_len;
                }
            }
        }

        uint64_t elapsed = get_time_ns() - start_time;

        /* Update batch counters */
        pthread_mutex_lock(&sv->work_lock);
        for (size_t i = item->start_idx; i < item->end_idx && i < batch->count; i++) {
            batch->verified++;
            if (batch->entries[i].status == SOL_SIGVERIFY_OK) {
                batch->valid++;
            } else {
                batch->invalid++;
            }
        }
        sv->pending_items--;
        if (sv->pending_items == 0) {
            pthread_cond_broadcast(&sv->done_cond);
        }
        pthread_mutex_unlock(&sv->work_lock);

        /* Update stats */
        pthread_mutex_lock(&sv->stats_lock);
        sv->stats.signatures_verified += sigs_verified;
        sv->stats.total_time_ns += elapsed;
        pthread_mutex_unlock(&sv->stats_lock);

        sol_free(item);
    }

    return NULL;
}

/*
 * Create sigverify service
 */
sol_sigverify_t*
sol_sigverify_new(const sol_sigverify_config_t* config) {
    sol_sigverify_t* sv = sol_alloc(sizeof(sol_sigverify_t));
    if (!sv) return NULL;

    memset(sv, 0, sizeof(sol_sigverify_t));

    if (config) {
        sv->config = *config;
    } else {
        sv->config = (sol_sigverify_config_t)SOL_SIGVERIFY_CONFIG_DEFAULT;
    }

    pthread_mutex_init(&sv->work_lock, NULL);
    pthread_cond_init(&sv->work_cond, NULL);
    pthread_cond_init(&sv->done_cond, NULL);
    pthread_mutex_init(&sv->stats_lock, NULL);

    /* Create worker threads */
    sv->num_workers = sv->config.num_threads;
    if (sv->num_workers == 0) {
        sv->num_workers = 1;
    }

    sv->workers = sol_alloc(sv->num_workers * sizeof(worker_t));
    if (!sv->workers) {
        sol_sigverify_destroy(sv);
        return NULL;
    }

    for (size_t i = 0; i < sv->num_workers; i++) {
        sv->workers[i].sv = sv;
        sv->workers[i].running = true;
        sv->workers[i].worker_id = (int)i;

        int err = pthread_create(&sv->workers[i].thread, NULL, worker_thread, &sv->workers[i]);
        if (err != 0) {
            sv->workers[i].running = false;
        }
    }

    return sv;
}

/*
 * Destroy sigverify service
 */
void
sol_sigverify_destroy(sol_sigverify_t* sv) {
    if (!sv) return;

    /* Signal shutdown */
    pthread_mutex_lock(&sv->work_lock);
    sv->shutdown = true;
    pthread_cond_broadcast(&sv->work_cond);
    pthread_mutex_unlock(&sv->work_lock);

    /* Join workers */
    if (sv->workers) {
        for (size_t i = 0; i < sv->num_workers; i++) {
            if (sv->workers[i].running) {
                pthread_join(sv->workers[i].thread, NULL);
            }
        }
        sol_free(sv->workers);
    }

    /* Cleanup work queue */
    while (sv->work_head) {
        work_item_t* item = sv->work_head;
        sv->work_head = item->next;
        sol_free(item);
    }

    pthread_mutex_destroy(&sv->work_lock);
    pthread_cond_destroy(&sv->work_cond);
    pthread_cond_destroy(&sv->done_cond);
    pthread_mutex_destroy(&sv->stats_lock);

    sol_free(sv);
}

/*
 * Verify a single transaction
 */
sol_sigverify_status_t
sol_sigverify_verify_one(sol_sigverify_t* sv, sol_transaction_t* tx) {
    if (!sv || !tx) {
        return SOL_SIGVERIFY_MALFORMED;
    }

    uint64_t start = get_time_ns();
    sol_sigverify_status_t status = sol_sigverify_verify_tx(tx);
    uint64_t elapsed = get_time_ns() - start;

    /* Update stats */
    pthread_mutex_lock(&sv->stats_lock);
    sv->stats.transactions_verified++;
    sv->stats.signatures_verified += tx->signatures_len;
    sv->stats.total_time_ns += elapsed;
    if (status == SOL_SIGVERIFY_OK) {
        sv->stats.valid_count++;
    } else {
        sv->stats.invalid_count++;
    }
    pthread_mutex_unlock(&sv->stats_lock);

    return status;
}

/*
 * Create verification batch
 */
sol_sigverify_batch_t*
sol_sigverify_batch_new(size_t capacity) {
    sol_sigverify_batch_t* batch = sol_alloc(sizeof(sol_sigverify_batch_t));
    if (!batch) return NULL;

    batch->entries = sol_alloc(capacity * sizeof(sol_sigverify_entry_t));
    if (!batch->entries) {
        sol_free(batch);
        return NULL;
    }

    batch->count = 0;
    batch->capacity = capacity;
    batch->verified = 0;
    batch->valid = 0;
    batch->invalid = 0;

    return batch;
}

/*
 * Destroy batch
 */
void
sol_sigverify_batch_destroy(sol_sigverify_batch_t* batch) {
    if (!batch) return;
    sol_free(batch->entries);
    sol_free(batch);
}

/*
 * Add transaction to batch
 */
sol_err_t
sol_sigverify_batch_add(sol_sigverify_batch_t* batch, sol_transaction_t* tx) {
    if (!batch || !tx) {
        return SOL_ERR_INVAL;
    }

    if (batch->count >= batch->capacity) {
        return SOL_ERR_FULL;
    }

    sol_sigverify_entry_t* entry = &batch->entries[batch->count++];
    entry->tx = tx;
    entry->status = SOL_SIGVERIFY_PENDING;
    entry->verify_time_ns = 0;

    return SOL_OK;
}

/*
 * Clear batch for reuse
 */
void
sol_sigverify_batch_clear(sol_sigverify_batch_t* batch) {
    if (!batch) return;
    batch->count = 0;
    batch->verified = 0;
    batch->valid = 0;
    batch->invalid = 0;
}

/*
 * Verify all transactions in batch
 */
sol_err_t
sol_sigverify_verify_batch(sol_sigverify_t* sv, sol_sigverify_batch_t* batch) {
    if (!sv || !batch) {
        return SOL_ERR_INVAL;
    }

    if (batch->count == 0) {
        return SOL_OK;
    }

    /* Divide work among threads */
    size_t items_per_worker = (batch->count + sv->num_workers - 1) / sv->num_workers;

    pthread_mutex_lock(&sv->work_lock);
    batch->verified = 0;
    batch->valid = 0;
    batch->invalid = 0;

    for (size_t i = 0; i < sv->num_workers; i++) {
        size_t start_idx = i * items_per_worker;
        if (start_idx >= batch->count) break;

        size_t end_idx = start_idx + items_per_worker;
        if (end_idx > batch->count) end_idx = batch->count;

        work_item_t* item = sol_alloc(sizeof(work_item_t));
        if (!item) continue;

        item->batch = batch;
        item->start_idx = start_idx;
        item->end_idx = end_idx;
        item->next = NULL;

        if (sv->work_tail) {
            sv->work_tail->next = item;
        } else {
            sv->work_head = item;
        }
        sv->work_tail = item;
        sv->pending_items++;
    }

    /* Signal workers */
    pthread_cond_broadcast(&sv->work_cond);

    /* Wait for completion */
    while (sv->pending_items > 0) {
        pthread_cond_wait(&sv->done_cond, &sv->work_lock);
    }

    pthread_mutex_unlock(&sv->work_lock);

    /* Update stats */
    pthread_mutex_lock(&sv->stats_lock);
    sv->stats.transactions_verified += batch->count;
    sv->stats.valid_count += batch->valid;
    sv->stats.invalid_count += batch->invalid;
    pthread_mutex_unlock(&sv->stats_lock);

    return SOL_OK;
}

/*
 * Submit batch for async verification
 */
sol_err_t
sol_sigverify_submit_batch(sol_sigverify_t* sv, sol_sigverify_batch_t* batch) {
    if (!sv || !batch) {
        return SOL_ERR_INVAL;
    }

    if (batch->count == 0) {
        return SOL_OK;
    }

    size_t items_per_worker = (batch->count + sv->num_workers - 1) / sv->num_workers;

    pthread_mutex_lock(&sv->work_lock);
    batch->verified = 0;
    batch->valid = 0;
    batch->invalid = 0;

    for (size_t i = 0; i < sv->num_workers; i++) {
        size_t start_idx = i * items_per_worker;
        if (start_idx >= batch->count) break;

        size_t end_idx = start_idx + items_per_worker;
        if (end_idx > batch->count) end_idx = batch->count;

        work_item_t* item = sol_alloc(sizeof(work_item_t));
        if (!item) continue;

        item->batch = batch;
        item->start_idx = start_idx;
        item->end_idx = end_idx;
        item->next = NULL;

        if (sv->work_tail) {
            sv->work_tail->next = item;
        } else {
            sv->work_head = item;
        }
        sv->work_tail = item;
        sv->pending_items++;
    }

    pthread_cond_broadcast(&sv->work_cond);
    pthread_mutex_unlock(&sv->work_lock);

    return SOL_OK;
}

/*
 * Wait for batch completion
 */
sol_err_t
sol_sigverify_wait_batch(sol_sigverify_t* sv, sol_sigverify_batch_t* batch,
                         uint64_t timeout_ms) {
    if (!sv || !batch) {
        return SOL_ERR_INVAL;
    }

    pthread_mutex_lock(&sv->work_lock);

    if (timeout_ms > 0) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout_ms / 1000;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000;
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000;
        }

        while (batch->verified < batch->count) {
            int ret = pthread_cond_timedwait(&sv->done_cond, &sv->work_lock, &ts);
            if (ret != 0) {
                pthread_mutex_unlock(&sv->work_lock);
                return SOL_ERR_TIMEOUT;
            }
        }
    } else {
        while (batch->verified < batch->count) {
            pthread_cond_wait(&sv->done_cond, &sv->work_lock);
        }
    }

    pthread_mutex_unlock(&sv->work_lock);
    return SOL_OK;
}

/*
 * Get statistics
 */
void
sol_sigverify_stats(const sol_sigverify_t* sv, sol_sigverify_stats_t* out_stats) {
    if (!sv || !out_stats) return;

    pthread_mutex_lock((pthread_mutex_t*)&sv->stats_lock);
    *out_stats = sv->stats;
    if (sv->stats.signatures_verified > 0) {
        out_stats->avg_time_per_sig_ns =
            (double)sv->stats.total_time_ns / (double)sv->stats.signatures_verified;
    }
    pthread_mutex_unlock((pthread_mutex_t*)&sv->stats_lock);
}

/*
 * Reset statistics
 */
void
sol_sigverify_stats_reset(sol_sigverify_t* sv) {
    if (!sv) return;
    pthread_mutex_lock(&sv->stats_lock);
    memset(&sv->stats, 0, sizeof(sol_sigverify_stats_t));
    pthread_mutex_unlock(&sv->stats_lock);
}

/*
 * Filter batch to only valid transactions
 */
size_t
sol_sigverify_batch_filter_valid(sol_sigverify_batch_t* batch) {
    if (!batch) return 0;

    size_t write_idx = 0;
    for (size_t read_idx = 0; read_idx < batch->count; read_idx++) {
        if (batch->entries[read_idx].status == SOL_SIGVERIFY_OK) {
            if (write_idx != read_idx) {
                batch->entries[write_idx] = batch->entries[read_idx];
            }
            write_idx++;
        }
    }

    batch->count = write_idx;
    return write_idx;
}

/*
 * Get valid transactions
 */
sol_transaction_t**
sol_sigverify_batch_get_valid(const sol_sigverify_batch_t* batch, size_t* out_count) {
    if (!batch) {
        if (out_count) *out_count = 0;
        return NULL;
    }

    /* Count valid */
    size_t valid_count = 0;
    for (size_t i = 0; i < batch->count; i++) {
        if (batch->entries[i].status == SOL_SIGVERIFY_OK) {
            valid_count++;
        }
    }

    if (valid_count == 0) {
        if (out_count) *out_count = 0;
        return NULL;
    }

    /* Allocate array */
    sol_transaction_t** txs = sol_alloc(valid_count * sizeof(sol_transaction_t*));
    if (!txs) {
        if (out_count) *out_count = 0;
        return NULL;
    }

    /* Fill array */
    size_t idx = 0;
    for (size_t i = 0; i < batch->count; i++) {
        if (batch->entries[i].status == SOL_SIGVERIFY_OK) {
            txs[idx++] = batch->entries[i].tx;
        }
    }

    if (out_count) *out_count = valid_count;
    return txs;
}
