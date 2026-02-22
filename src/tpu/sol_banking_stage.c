/*
 * sol_banking_stage.c - Banking Stage Implementation
 */

#include "sol_banking_stage.h"
#include "../util/sol_alloc.h"
#include "../util/sol_map.h"
#include "../util/sol_hash_fn.h"
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
 * Hash function for pubkeys
 */
static uint64_t
pubkey_hash(const void* p) {
    return sol_hash_bytes(p, SOL_PUBKEY_SIZE);
}

/*
 * Equality function for pubkeys
 */
static bool
pubkey_eq(const void* a, const void* b) {
    return memcmp(a, b, SOL_PUBKEY_SIZE) == 0;
}

/*
 * Hash function for signatures
 */
static uint64_t
signature_hash(const void* p) {
    return sol_hash_bytes(p, SOL_SIGNATURE_SIZE);
}

/*
 * Equality function for signatures
 */
static bool
signature_eq(const void* a, const void* b) {
    return memcmp(a, b, SOL_SIGNATURE_SIZE) == 0;
}

/*
 * Deduplication entry with timestamp for expiration
 */
typedef struct {
    uint64_t    timestamp_ns;   /* When entry was added */
    uint8_t     marker;         /* Presence marker */
} dedup_entry_t;

/*
 * Deduplication window in nanoseconds (2 minutes)
 */
#define DEDUP_WINDOW_NS (2ULL * 60ULL * 1000000000ULL)

/*
 * Maximum dedup map size before forced cleanup
 */
#define DEDUP_MAX_ENTRIES 100000

/*
 * Transaction queue implementation
 */
struct sol_tx_queue {
    sol_transaction_t** txs;
    size_t              head;
    size_t              tail;
    size_t              count;
    size_t              capacity;
    pthread_mutex_t     lock;
    pthread_cond_t      not_empty;
    pthread_cond_t      not_full;
};

sol_tx_queue_t*
sol_tx_queue_new(size_t capacity) {
    sol_tx_queue_t* queue = sol_alloc(sizeof(sol_tx_queue_t));
    if (!queue) return NULL;

    queue->txs = sol_alloc(capacity * sizeof(sol_transaction_t*));
    if (!queue->txs) {
        sol_free(queue);
        return NULL;
    }

    queue->head = 0;
    queue->tail = 0;
    queue->count = 0;
    queue->capacity = capacity;
    pthread_mutex_init(&queue->lock, NULL);
    pthread_cond_init(&queue->not_empty, NULL);
    pthread_cond_init(&queue->not_full, NULL);

    return queue;
}

void
sol_tx_queue_destroy(sol_tx_queue_t* queue) {
    if (!queue) return;
    pthread_mutex_destroy(&queue->lock);
    pthread_cond_destroy(&queue->not_empty);
    pthread_cond_destroy(&queue->not_full);
    sol_free(queue->txs);
    sol_free(queue);
}

sol_err_t
sol_tx_queue_push(sol_tx_queue_t* queue, sol_transaction_t* tx) {
    if (!queue || !tx) return SOL_ERR_INVAL;

    pthread_mutex_lock(&queue->lock);
    if (queue->count >= queue->capacity) {
        pthread_mutex_unlock(&queue->lock);
        return SOL_ERR_FULL;
    }

    queue->txs[queue->tail] = tx;
    queue->tail = (queue->tail + 1) % queue->capacity;
    queue->count++;
    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->lock);

    return SOL_OK;
}

sol_transaction_t*
sol_tx_queue_pop(sol_tx_queue_t* queue) {
    if (!queue) return NULL;

    pthread_mutex_lock(&queue->lock);
    if (queue->count == 0) {
        pthread_mutex_unlock(&queue->lock);
        return NULL;
    }

    sol_transaction_t* tx = queue->txs[queue->head];
    queue->head = (queue->head + 1) % queue->capacity;
    queue->count--;
    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->lock);

    return tx;
}

size_t
sol_tx_queue_len(const sol_tx_queue_t* queue) {
    if (!queue) return 0;
    return queue->count;
}

bool
sol_tx_queue_is_empty(const sol_tx_queue_t* queue) {
    return queue ? queue->count == 0 : true;
}

bool
sol_tx_queue_is_full(const sol_tx_queue_t* queue) {
    return queue ? queue->count >= queue->capacity : true;
}

void
sol_tx_queue_clear(sol_tx_queue_t* queue) {
    if (!queue) return;
    pthread_mutex_lock(&queue->lock);
    queue->head = 0;
    queue->tail = 0;
    queue->count = 0;
    pthread_mutex_unlock(&queue->lock);
}

/*
 * Priority queue entry
 */
typedef struct {
    sol_transaction_t*  tx;
    uint64_t            priority;
} pq_entry_t;

struct sol_priority_queue {
    pq_entry_t*         entries;
    size_t              count;
    size_t              capacity;
    pthread_mutex_t     lock;
};

sol_priority_queue_t*
sol_priority_queue_new(size_t capacity) {
    sol_priority_queue_t* pq = sol_alloc(sizeof(sol_priority_queue_t));
    if (!pq) return NULL;

    pq->entries = sol_alloc(capacity * sizeof(pq_entry_t));
    if (!pq->entries) {
        sol_free(pq);
        return NULL;
    }

    pq->count = 0;
    pq->capacity = capacity;
    pthread_mutex_init(&pq->lock, NULL);

    return pq;
}

void
sol_priority_queue_destroy(sol_priority_queue_t* pq) {
    if (!pq) return;
    pthread_mutex_destroy(&pq->lock);
    sol_free(pq->entries);
    sol_free(pq);
}

/* Heap helpers */
static void
pq_bubble_up(sol_priority_queue_t* pq, size_t idx) {
    while (idx > 0) {
        size_t parent = (idx - 1) / 2;
        if (pq->entries[idx].priority <= pq->entries[parent].priority) {
            break;
        }
        pq_entry_t tmp = pq->entries[idx];
        pq->entries[idx] = pq->entries[parent];
        pq->entries[parent] = tmp;
        idx = parent;
    }
}

static void
pq_bubble_down(sol_priority_queue_t* pq, size_t idx) {
    while (true) {
        size_t largest = idx;
        size_t left = 2 * idx + 1;
        size_t right = 2 * idx + 2;

        if (left < pq->count && pq->entries[left].priority > pq->entries[largest].priority) {
            largest = left;
        }
        if (right < pq->count && pq->entries[right].priority > pq->entries[largest].priority) {
            largest = right;
        }

        if (largest == idx) break;

        pq_entry_t tmp = pq->entries[idx];
        pq->entries[idx] = pq->entries[largest];
        pq->entries[largest] = tmp;
        idx = largest;
    }
}

sol_err_t
sol_priority_queue_push(sol_priority_queue_t* pq, sol_transaction_t* tx, uint64_t priority) {
    if (!pq || !tx) return SOL_ERR_INVAL;

    pthread_mutex_lock(&pq->lock);
    if (pq->count >= pq->capacity) {
        pthread_mutex_unlock(&pq->lock);
        return SOL_ERR_FULL;
    }

    pq->entries[pq->count].tx = tx;
    pq->entries[pq->count].priority = priority;
    pq_bubble_up(pq, pq->count);
    pq->count++;
    pthread_mutex_unlock(&pq->lock);

    return SOL_OK;
}

sol_transaction_t*
sol_priority_queue_pop(sol_priority_queue_t* pq) {
    if (!pq) return NULL;

    pthread_mutex_lock(&pq->lock);
    if (pq->count == 0) {
        pthread_mutex_unlock(&pq->lock);
        return NULL;
    }

    sol_transaction_t* tx = pq->entries[0].tx;
    pq->entries[0] = pq->entries[pq->count - 1];
    pq->count--;
    if (pq->count > 0) {
        pq_bubble_down(pq, 0);
    }
    pthread_mutex_unlock(&pq->lock);

    return tx;
}

size_t
sol_priority_queue_len(const sol_priority_queue_t* pq) {
    return pq ? pq->count : 0;
}

/*
 * Account locks implementation
 */
struct sol_account_locks {
    sol_map_t*          write_locks;    /* pubkey -> lock count */
    sol_map_t*          read_locks;     /* pubkey -> lock count */
    pthread_mutex_t     lock;
};

static bool
account_is_writable(const sol_message_t* msg, size_t index) {
    if (!msg) {
        return true;
    }

    if (msg->is_writable && index < msg->resolved_accounts_len) {
        return msg->is_writable[index];
    }

    if (index < msg->account_keys_len) {
        return sol_message_is_writable_index(msg, (uint8_t)index);
    }

    /* If we can't determine writability, be conservative. */
    return true;
}

sol_account_locks_t*
sol_account_locks_new(void) {
    sol_account_locks_t* locks = sol_alloc(sizeof(sol_account_locks_t));
    if (!locks) return NULL;

    /* Create maps with pubkey keys and uint64_t values */
    locks->write_locks = sol_map_new(SOL_PUBKEY_SIZE, sizeof(uint64_t),
                                      pubkey_hash, pubkey_eq, 256);
    locks->read_locks = sol_map_new(SOL_PUBKEY_SIZE, sizeof(uint64_t),
                                     pubkey_hash, pubkey_eq, 256);

    if (!locks->write_locks || !locks->read_locks) {
        sol_map_destroy(locks->write_locks);
        sol_map_destroy(locks->read_locks);
        sol_free(locks);
        return NULL;
    }

    pthread_mutex_init(&locks->lock, NULL);
    return locks;
}

void
sol_account_locks_destroy(sol_account_locks_t* locks) {
    if (!locks) return;
    sol_map_destroy(locks->write_locks);
    sol_map_destroy(locks->read_locks);
    pthread_mutex_destroy(&locks->lock);
    sol_free(locks);
}

bool
sol_account_locks_try_lock(sol_account_locks_t* locks, const sol_transaction_t* tx) {
    if (!locks || !tx) return false;

    pthread_mutex_lock(&locks->lock);

    const sol_pubkey_t* account_keys = tx->message.resolved_accounts_len
        ? tx->message.resolved_accounts
        : tx->message.account_keys;
    size_t account_keys_len = tx->message.resolved_accounts_len
        ? (size_t)tx->message.resolved_accounts_len
        : (size_t)tx->message.account_keys_len;

    if (!account_keys || account_keys_len == 0) {
        pthread_mutex_unlock(&locks->lock);
        return false;
    }

    /* Check for conflicts */
    for (size_t i = 0; i < account_keys_len; i++) {
        bool writable = account_is_writable(&tx->message, i);
        const sol_pubkey_t* pubkey = &account_keys[i];
        uint64_t* count = (uint64_t*)sol_map_get(locks->write_locks, pubkey->bytes);
        if (count && *count > 0) {
            pthread_mutex_unlock(&locks->lock);
            return false;
        }

        if (writable) {
            count = (uint64_t*)sol_map_get(locks->read_locks, pubkey->bytes);
            if (count && *count > 0) {
                pthread_mutex_unlock(&locks->lock);
                return false;
            }
        }
    }

    /* Acquire all locks */
    for (size_t i = 0; i < account_keys_len; i++) {
        const sol_pubkey_t* pubkey = &account_keys[i];

        if (account_is_writable(&tx->message, i)) {
            uint64_t* count = (uint64_t*)sol_map_get(locks->write_locks, pubkey->bytes);
            if (count) {
                (*count)++;
            } else {
                uint64_t one = 1;
                sol_map_insert(locks->write_locks, pubkey->bytes, &one);
            }
        } else {
            uint64_t* count = (uint64_t*)sol_map_get(locks->read_locks, pubkey->bytes);
            if (count) {
                (*count)++;
            } else {
                uint64_t one = 1;
                sol_map_insert(locks->read_locks, pubkey->bytes, &one);
            }
        }
    }

    pthread_mutex_unlock(&locks->lock);
    return true;
}

void
sol_account_locks_unlock(sol_account_locks_t* locks, const sol_transaction_t* tx) {
    if (!locks || !tx) return;

    pthread_mutex_lock(&locks->lock);

    const sol_pubkey_t* account_keys = tx->message.resolved_accounts_len
        ? tx->message.resolved_accounts
        : tx->message.account_keys;
    size_t account_keys_len = tx->message.resolved_accounts_len
        ? (size_t)tx->message.resolved_accounts_len
        : (size_t)tx->message.account_keys_len;

    if (!account_keys || account_keys_len == 0) {
        pthread_mutex_unlock(&locks->lock);
        return;
    }

    for (size_t i = 0; i < account_keys_len; i++) {
        const sol_pubkey_t* pubkey = &account_keys[i];

        if (account_is_writable(&tx->message, i)) {
            uint64_t* count = (uint64_t*)sol_map_get(locks->write_locks, pubkey->bytes);
            if (count && *count > 0) {
                (*count)--;
                if (*count == 0) {
                    sol_map_remove(locks->write_locks, pubkey->bytes);
                }
            }
        } else {
            uint64_t* count = (uint64_t*)sol_map_get(locks->read_locks, pubkey->bytes);
            if (count && *count > 0) {
                (*count)--;
                if (*count == 0) {
                    sol_map_remove(locks->read_locks, pubkey->bytes);
                }
            }
        }
    }

    pthread_mutex_unlock(&locks->lock);
}

/*
 * Banking stage structure
 */
struct sol_banking_stage {
    sol_banking_stage_config_t  config;
    sol_bank_t*                 bank;
    sol_sigverify_t*            sigverify;
    sol_tx_queue_t*             pending_queue;
    sol_account_locks_t*        account_locks;
    sol_cost_model_t            cost_model;

    /* Deduplication - signature -> marker */
    sol_map_t*                  seen_txs;
    pthread_mutex_t             seen_lock;

    /* Worker threads */
    pthread_t*                  workers;
    size_t                      num_workers;
    bool                        running;
    pthread_mutex_t             state_lock;
    pthread_cond_t              state_cond;

    /* Statistics */
    sol_banking_stage_stats_t   stats;
    pthread_mutex_t             stats_lock;
    uint64_t                    start_time;
};

/*
 * Worker thread function
 */
static void*
banking_worker(void* arg) {
    sol_banking_stage_t* stage = (sol_banking_stage_t*)arg;

    while (stage->running) {
        sol_banking_batch_result_t result;
        sol_err_t err = sol_banking_stage_process_batch(stage, &result);

        if (err == SOL_OK && result.count > 0) {
            /* Update stats */
            pthread_mutex_lock(&stage->stats_lock);
            stage->stats.batches_processed++;
            stage->stats.transactions_processed += result.count;
            stage->stats.transactions_successful += result.successful;
            stage->stats.transactions_failed += result.failed;
            stage->stats.transactions_dropped += result.dropped;
            stage->stats.total_cu_consumed += result.total_cu_used;
            stage->stats.total_fees_collected += result.total_fees;
            stage->stats.total_process_time_ns += result.process_time_ns;
            pthread_mutex_unlock(&stage->stats_lock);

            if (result.results) {
                sol_free(result.results);
            }
        } else {
            /* No work, sleep briefly */
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };  /* 1ms */
            nanosleep(&ts, NULL);
        }
    }

    return NULL;
}

/*
 * Create banking stage
 */
sol_banking_stage_t*
sol_banking_stage_new(sol_bank_t* bank, sol_sigverify_t* sigverify,
                      const sol_banking_stage_config_t* config) {
    sol_banking_stage_t* stage = sol_alloc(sizeof(sol_banking_stage_t));
    if (!stage) return NULL;

    memset(stage, 0, sizeof(sol_banking_stage_t));

    if (config) {
        stage->config = *config;
    } else {
        stage->config = (sol_banking_stage_config_t)SOL_BANKING_STAGE_CONFIG_DEFAULT;
    }

    stage->bank = bank;
    stage->sigverify = sigverify;

    stage->pending_queue = sol_tx_queue_new(stage->config.max_pending_txs);
    stage->account_locks = sol_account_locks_new();

    /* Create deduplication map with signature keys and timestamped entries */
    stage->seen_txs = sol_map_new(SOL_SIGNATURE_SIZE, sizeof(dedup_entry_t),
                                   signature_hash, signature_eq, 1024);

    if (!stage->pending_queue || !stage->account_locks || !stage->seen_txs) {
        sol_banking_stage_destroy(stage);
        return NULL;
    }

    sol_cost_model_init(&stage->cost_model, NULL);

    pthread_mutex_init(&stage->seen_lock, NULL);
    pthread_mutex_init(&stage->state_lock, NULL);
    pthread_cond_init(&stage->state_cond, NULL);
    pthread_mutex_init(&stage->stats_lock, NULL);

    stage->num_workers = stage->config.num_threads;
    if (stage->num_workers == 0) {
        stage->num_workers = 1;
    }

    stage->workers = sol_alloc(stage->num_workers * sizeof(pthread_t));
    if (!stage->workers) {
        sol_banking_stage_destroy(stage);
        return NULL;
    }

    return stage;
}

/*
 * Destroy banking stage
 */
void
sol_banking_stage_destroy(sol_banking_stage_t* stage) {
    if (!stage) return;

    sol_banking_stage_stop(stage);

    sol_free(stage->workers);
    sol_tx_queue_destroy(stage->pending_queue);
    sol_account_locks_destroy(stage->account_locks);
    sol_map_destroy(stage->seen_txs);

    pthread_mutex_destroy(&stage->seen_lock);
    pthread_mutex_destroy(&stage->state_lock);
    pthread_cond_destroy(&stage->state_cond);
    pthread_mutex_destroy(&stage->stats_lock);

    sol_free(stage);
}

/*
 * Start banking stage
 */
sol_err_t
sol_banking_stage_start(sol_banking_stage_t* stage) {
    if (!stage) return SOL_ERR_INVAL;

    pthread_mutex_lock(&stage->state_lock);
    if (stage->running) {
        pthread_mutex_unlock(&stage->state_lock);
        return SOL_OK;
    }

    stage->running = true;
    stage->start_time = get_time_ns();

    for (size_t i = 0; i < stage->num_workers; i++) {
        pthread_create(&stage->workers[i], NULL, banking_worker, stage);
    }

    pthread_mutex_unlock(&stage->state_lock);
    return SOL_OK;
}

/*
 * Stop banking stage
 */
void
sol_banking_stage_stop(sol_banking_stage_t* stage) {
    if (!stage) return;

    pthread_mutex_lock(&stage->state_lock);
    if (!stage->running) {
        pthread_mutex_unlock(&stage->state_lock);
        return;
    }

    stage->running = false;
    pthread_cond_broadcast(&stage->state_cond);
    pthread_mutex_unlock(&stage->state_lock);

    for (size_t i = 0; i < stage->num_workers; i++) {
        pthread_join(stage->workers[i], NULL);
    }
}

/*
 * Submit transaction
 */
sol_err_t
sol_banking_stage_submit(sol_banking_stage_t* stage, sol_transaction_t* tx) {
    if (!stage || !tx) return SOL_ERR_INVAL;

    /* Check for duplicate */
    if (sol_banking_stage_is_duplicate(stage, tx)) {
        pthread_mutex_lock(&stage->stats_lock);
        stage->stats.duplicates_filtered++;
        pthread_mutex_unlock(&stage->stats_lock);
        return SOL_ERR_EXISTS;
    }

    /* Add to pending queue */
    sol_err_t err = sol_tx_queue_push(stage->pending_queue, tx);
    if (err != SOL_OK) {
        return err;
    }

    /* Mark as seen */
    sol_banking_stage_mark_seen(stage, tx);

    pthread_mutex_lock(&stage->stats_lock);
    stage->stats.transactions_received++;
    pthread_mutex_unlock(&stage->stats_lock);

    return SOL_OK;
}

/*
 * Submit batch
 */
sol_err_t
sol_banking_stage_submit_batch(sol_banking_stage_t* stage,
                               sol_transaction_t** txs, size_t count) {
    if (!stage || !txs) return SOL_ERR_INVAL;

    for (size_t i = 0; i < count; i++) {
        sol_banking_stage_submit(stage, txs[i]);
    }

    return SOL_OK;
}

/*
 * Process a batch of transactions
 */
sol_err_t
sol_banking_stage_process_batch(sol_banking_stage_t* stage,
                                 sol_banking_batch_result_t* out_result) {
    if (!stage || !out_result) return SOL_ERR_INVAL;

    memset(out_result, 0, sizeof(sol_banking_batch_result_t));

    /* Collect batch */
    sol_transaction_t** batch = sol_alloc(stage->config.batch_size * sizeof(sol_transaction_t*));
    if (!batch) return SOL_ERR_NOMEM;

    size_t batch_count = 0;
    while (batch_count < stage->config.batch_size) {
        sol_transaction_t* tx = sol_tx_queue_pop(stage->pending_queue);
        if (!tx) break;
        batch[batch_count++] = tx;
    }

    if (batch_count == 0) {
        sol_free(batch);
        return SOL_OK;
    }

    uint64_t start_time = get_time_ns();

    /* Allocate results */
    out_result->results = sol_alloc(batch_count * sizeof(sol_banking_tx_result_t));
    if (!out_result->results) {
        sol_free(batch);
        return SOL_ERR_NOMEM;
    }
    out_result->count = batch_count;

    /* Process each transaction */
    for (size_t i = 0; i < batch_count; i++) {
        sol_transaction_t* tx = batch[i];
        sol_banking_tx_result_t* result = &out_result->results[i];
        result->tx = tx;

        bool resolved_override = false;
        const sol_pubkey_t* saved_resolved_accounts = NULL;
        uint16_t saved_resolved_accounts_len = 0;
        bool* saved_is_writable = NULL;
        bool* saved_is_signer = NULL;
        sol_pubkey_t resolved_accounts[SOL_MAX_MESSAGE_ACCOUNTS];
        bool resolved_is_writable[SOL_MAX_MESSAGE_ACCOUNTS];
        bool resolved_is_signer[SOL_MAX_MESSAGE_ACCOUNTS];

        if (stage->bank &&
            tx->message.version == SOL_MESSAGE_VERSION_V0 &&
            tx->message.resolved_accounts_len == 0) {
            size_t resolved_len = 0;
            sol_err_t resolve_err =
                sol_bank_resolve_transaction_accounts(stage->bank,
                                                     tx,
                                                     resolved_accounts,
                                                     resolved_is_writable,
                                                     resolved_is_signer,
                                                     SOL_MAX_MESSAGE_ACCOUNTS,
                                                     &resolved_len);
            if (resolve_err != SOL_OK) {
                result->result = SOL_BANKING_FAILED;
                result->error = resolve_err;
                out_result->failed++;
                continue;
            }

            sol_message_t* msg = (sol_message_t*)&tx->message;
            saved_resolved_accounts = msg->resolved_accounts;
            saved_resolved_accounts_len = msg->resolved_accounts_len;
            saved_is_writable = msg->is_writable;
            saved_is_signer = msg->is_signer;
            msg->resolved_accounts = resolved_accounts;
            msg->resolved_accounts_len = (uint16_t)resolved_len;
            msg->is_writable = resolved_is_writable;
            msg->is_signer = resolved_is_signer;
            resolved_override = true;
        }

        /* Try to acquire account locks */
        if (!sol_account_locks_try_lock(stage->account_locks, tx)) {
            result->result = SOL_BANKING_ACCOUNT_LOCKED;
            out_result->dropped++;
            if (resolved_override) {
                sol_message_t* msg = (sol_message_t*)&tx->message;
                msg->resolved_accounts = saved_resolved_accounts;
                msg->resolved_accounts_len = saved_resolved_accounts_len;
                msg->is_writable = saved_is_writable;
                msg->is_signer = saved_is_signer;
            }
            continue;
        }

        /* Parse compute budget */
        sol_compute_budget_t budget;
        sol_compute_budget_parse(&budget, tx);

        /* Check cost model */
        sol_tx_cost_t tx_cost;
        sol_cost_model_calculate(&stage->cost_model, tx, &budget, &tx_cost);

        if (!sol_cost_model_would_fit(&stage->cost_model, &tx_cost)) {
            sol_account_locks_unlock(stage->account_locks, tx);
            result->result = SOL_BANKING_COST_LIMIT;
            out_result->dropped++;
            if (resolved_override) {
                sol_message_t* msg = (sol_message_t*)&tx->message;
                msg->resolved_accounts = saved_resolved_accounts;
                msg->resolved_accounts_len = saved_resolved_accounts_len;
                msg->is_writable = saved_is_writable;
                msg->is_signer = saved_is_signer;
            }
            continue;
        }

        /* Execute transaction */
        if (stage->bank) {
            sol_tx_result_t tx_result = sol_bank_process_transaction(stage->bank, tx);
            if (tx_result.status == SOL_OK) {
                result->result = SOL_BANKING_SUCCESS;
                result->compute_used = tx_result.compute_units_used;
                result->fee_paid = tx_result.fee;
                out_result->successful++;
                out_result->total_cu_used += result->compute_used;
                out_result->total_fees += result->fee_paid;

                /* Add to cost model */
                sol_cost_model_add(&stage->cost_model, &tx_cost);
            } else {
                result->result = SOL_BANKING_FAILED;
                result->error = tx_result.status;
                out_result->failed++;
            }
        } else {
            result->result = SOL_BANKING_DROPPED;
            out_result->dropped++;
        }

        /* Release locks */
        sol_account_locks_unlock(stage->account_locks, tx);

        if (resolved_override) {
            sol_message_t* msg = (sol_message_t*)&tx->message;
            msg->resolved_accounts = saved_resolved_accounts;
            msg->resolved_accounts_len = saved_resolved_accounts_len;
            msg->is_writable = saved_is_writable;
            msg->is_signer = saved_is_signer;
        }
    }

    out_result->process_time_ns = get_time_ns() - start_time;

    sol_free(batch);
    return SOL_OK;
}

/*
 * Get pending count
 */
size_t
sol_banking_stage_pending_count(const sol_banking_stage_t* stage) {
    if (!stage) return 0;
    return sol_tx_queue_len(stage->pending_queue);
}

/*
 * Set bank
 */
void
sol_banking_stage_set_bank(sol_banking_stage_t* stage, sol_bank_t* bank) {
    if (!stage) return;
    stage->bank = bank;
    sol_cost_model_reset(&stage->cost_model);
}

/*
 * Get statistics
 */
void
sol_banking_stage_stats(const sol_banking_stage_t* stage,
                        sol_banking_stage_stats_t* out_stats) {
    if (!stage || !out_stats) return;

    pthread_mutex_lock((pthread_mutex_t*)&stage->stats_lock);
    *out_stats = stage->stats;
    pthread_mutex_unlock((pthread_mutex_t*)&stage->stats_lock);

    /* Calculate derived stats */
    if (out_stats->batches_processed > 0) {
        out_stats->avg_batch_time_ns =
            (double)out_stats->total_process_time_ns / (double)out_stats->batches_processed;
    }

    uint64_t elapsed_ns = get_time_ns() - stage->start_time;
    if (elapsed_ns > 0) {
        out_stats->tps = (double)out_stats->transactions_successful * 1e9 / (double)elapsed_ns;
    }
}

/*
 * Reset statistics
 */
void
sol_banking_stage_stats_reset(sol_banking_stage_t* stage) {
    if (!stage) return;
    pthread_mutex_lock(&stage->stats_lock);
    memset(&stage->stats, 0, sizeof(sol_banking_stage_stats_t));
    stage->start_time = get_time_ns();
    pthread_mutex_unlock(&stage->stats_lock);
}

/*
 * Prune expired deduplication entries (must be called with lock held)
 */
static void
prune_expired_dedup_entries(sol_banking_stage_t* stage, uint64_t now_ns) {
    /* Only prune if map is getting large */
    if (sol_map_size(stage->seen_txs) < DEDUP_MAX_ENTRIES / 2) {
        return;
    }

    /* Collect keys to remove */
    uint8_t keys_to_remove[1024][SOL_SIGNATURE_SIZE];
    size_t num_to_remove = 0;

    sol_map_iter_t iter = sol_map_iter(stage->seen_txs);

    void* key;
    void* value;
    while (sol_map_iter_next(&iter, &key, &value) && num_to_remove < 1024) {
        dedup_entry_t* entry = (dedup_entry_t*)value;
        if (now_ns - entry->timestamp_ns > DEDUP_WINDOW_NS) {
            memcpy(keys_to_remove[num_to_remove], key, SOL_SIGNATURE_SIZE);
            num_to_remove++;
        }
    }

    /* Remove expired entries */
    for (size_t i = 0; i < num_to_remove; i++) {
        sol_map_remove(stage->seen_txs, keys_to_remove[i]);
    }
}

/*
 * Check for duplicate
 */
bool
sol_banking_stage_is_duplicate(sol_banking_stage_t* stage, const sol_transaction_t* tx) {
    if (!stage || !tx || tx->signatures_len == 0) return false;

    uint64_t now_ns = get_time_ns();

    pthread_mutex_lock(&stage->seen_lock);

    dedup_entry_t* entry = sol_map_get(stage->seen_txs, tx->signatures[0].bytes);
    bool found = false;

    if (entry) {
        /* Check if entry is still valid (within dedup window) */
        if (now_ns - entry->timestamp_ns <= DEDUP_WINDOW_NS) {
            found = true;
        } else {
            /* Entry expired - remove it */
            sol_map_remove(stage->seen_txs, tx->signatures[0].bytes);
        }
    }

    pthread_mutex_unlock(&stage->seen_lock);

    return found;
}

/*
 * Mark transaction as seen
 */
void
sol_banking_stage_mark_seen(sol_banking_stage_t* stage, const sol_transaction_t* tx) {
    if (!stage || !tx || tx->signatures_len == 0) return;

    uint64_t now_ns = get_time_ns();

    pthread_mutex_lock(&stage->seen_lock);

    /* Prune old entries if map is getting large */
    if (sol_map_size(stage->seen_txs) >= DEDUP_MAX_ENTRIES) {
        prune_expired_dedup_entries(stage, now_ns);
    }

    /* Insert new entry with timestamp */
    dedup_entry_t entry = {
        .timestamp_ns = now_ns,
        .marker = 1
    };
    sol_map_insert(stage->seen_txs, tx->signatures[0].bytes, &entry);

    pthread_mutex_unlock(&stage->seen_lock);
}
