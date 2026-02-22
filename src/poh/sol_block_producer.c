/*
 * sol_block_producer.c - Block Production Implementation
 */

#include "sol_block_producer.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include "../crypto/sol_sha256.h"
#include <string.h>

/*
 * Clone a transaction (deep copy including data)
 */
static sol_transaction_t*
clone_transaction(const sol_transaction_t* tx) {
    if (!tx) return NULL;
    if (!tx->signatures || tx->signatures_len == 0) return NULL;
    if (!tx->message_data || tx->message_data_len == 0) return NULL;

    sol_transaction_t* copy = sol_calloc(1, sizeof(sol_transaction_t));
    if (!copy) return NULL;

    sol_transaction_init(copy);

    size_t sig_bytes = (size_t)tx->signatures_len * sizeof(sol_signature_t);
    sol_signature_t* sig_copy = sol_alloc(sig_bytes);
    if (!sig_copy) {
        sol_free(copy);
        return NULL;
    }
    memcpy(sig_copy, tx->signatures, sig_bytes);

    uint8_t* msg_copy = sol_alloc(tx->message_data_len);
    if (!msg_copy) {
        sol_free(sig_copy);
        sol_free(copy);
        return NULL;
    }
    memcpy(msg_copy, tx->message_data, tx->message_data_len);

    copy->signatures = sig_copy;
    copy->signatures_len = tx->signatures_len;
    copy->message_data = msg_copy;
    copy->message_data_len = tx->message_data_len;

    /* Re-decode the message so pointers reference the copied message bytes. */
    sol_decoder_t dec;
    sol_decoder_init(&dec, copy->message_data, copy->message_data_len);
    if (sol_message_decode_versioned(&dec, &copy->message) != SOL_OK) {
        sol_free(sig_copy);
        sol_free(msg_copy);
        sol_free(copy);
        return NULL;
    }

    if (copy->signatures_len != copy->message.header.num_required_signatures) {
        sol_free(sig_copy);
        sol_free(msg_copy);
        sol_free(copy);
        return NULL;
    }

    return copy;
}

/*
 * Free a cloned transaction
 */
static void
free_transaction(sol_transaction_t* tx) {
    if (!tx) return;
    sol_free((void*)tx->message_data);
    sol_free((void*)tx->signatures);
    sol_free(tx);
}

/*
 * Transaction queue size
 */
#define TX_QUEUE_SIZE 10000

/*
 * Transaction queue entry
 */
typedef struct {
    sol_transaction_t*  tx;
    bool                valid;
} tx_queue_entry_t;

/*
 * Block producer internal state
 */
struct sol_block_producer {
    sol_block_producer_config_t config;

    /* PoH recorder */
    sol_poh_recorder_t*         poh;

    /* Working bank */
    sol_bank_t*                 bank;
    sol_slot_t                  slot;
    sol_hash_t                  prev_entry_hash;
    bool                        prev_entry_hash_set;
    uint64_t                    slot_tx_count;

    /* Transaction queue (circular buffer) */
    tx_queue_entry_t*           tx_queue;
    size_t                      tx_queue_head;
    size_t                      tx_queue_tail;
    size_t                      tx_queue_size;

    /* Current entry being built */
    sol_transaction_t**         entry_txs;
    sol_hash_t*                 entry_tx_hashes;
    size_t                      entry_tx_count;

    /* Produced entries */
    sol_entry_t*                entries;
    size_t                      entry_count;
    size_t                      entry_capacity;

    /* Statistics */
    sol_block_producer_stats_t  stats;

    /* Thread control */
    pthread_t                   thread;
    pthread_mutex_t             lock;
    pthread_cond_t              tx_available;
    bool                        running;
    bool                        thread_started;

    /* Callbacks */
    sol_entry_callback_t        entry_callback;
    void*                       entry_callback_ctx;
    sol_slot_complete_callback_t slot_callback;
    void*                       slot_callback_ctx;
    sol_block_data_callback_t   block_data_callback;
    void*                       block_data_callback_ctx;
};

/*
 * Hash a transaction for PoH recording
 */
static void
hash_transaction(const sol_transaction_t* tx, sol_hash_t* out) {
    /* Use the first signature as the transaction hash */
    if (tx->signatures && tx->signatures_len > 0) {
        memcpy(out->bytes, tx->signatures[0].bytes, 32);
    } else {
        /* Hash the message if no signature */
        sol_sha256_bytes(tx->message_data, tx->message_data_len, out->bytes);
    }
}

/*
 * Process a single transaction
 */
static sol_err_t
process_transaction(sol_block_producer_t* producer, sol_transaction_t* tx) {
    if (!producer->bank) {
        return SOL_ERR_UNINITIALIZED;
    }

    /* Process through bank */
    sol_tx_result_t result = sol_bank_process_transaction(producer->bank, tx);

    if (result.status != SOL_OK) {
        producer->stats.transactions_failed++;
        return result.status;
    }

    sol_hash_t tx_hash;
    hash_transaction(tx, &tx_hash);

    /* Add to current entry */
    if (producer->entry_tx_count < producer->config.max_txs_per_entry) {
        producer->entry_txs[producer->entry_tx_count] = tx;
        producer->entry_tx_hashes[producer->entry_tx_count] = tx_hash;
        producer->entry_tx_count++;
    }

    producer->slot_tx_count++;
    producer->stats.transactions_processed++;
    return SOL_OK;
}

/*
 * Create an entry from current transactions
 */
static void
create_entry(sol_block_producer_t* producer) {
    if (producer->entry_tx_count == 0) {
        return;
    }

    if (!producer->prev_entry_hash_set) {
        memset(producer->prev_entry_hash.bytes, 0, sizeof(producer->prev_entry_hash.bytes));
        producer->prev_entry_hash_set = true;
    }

    /* Build entry */
    sol_entry_t entry;
    sol_entry_init(&entry);

    entry.num_hashes = 0;
    entry.num_transactions = (uint32_t)producer->entry_tx_count;

    /* Compute entry hash using the runtime entry hash algorithm */
    sol_transaction_t* txs = sol_alloc(producer->entry_tx_count * sizeof(sol_transaction_t));
    if (!txs) {
        return;
    }

    for (size_t i = 0; i < producer->entry_tx_count; i++) {
        txs[i] = *producer->entry_txs[i];
    }

    sol_entry_t tmp = {
        .num_hashes = entry.num_hashes,
        .hash = {0},
        .num_transactions = entry.num_transactions,
        .transactions = txs,
        .transactions_capacity = producer->entry_tx_count,
        .raw_data = NULL,
        .raw_data_len = 0,
    };

    sol_entry_compute_hash(&tmp, &producer->prev_entry_hash, &entry.hash);
    sol_free(txs);

    /* Serialize transactions into entry.raw_data */
    uint8_t* raw = NULL;
    size_t raw_len = 0;
    size_t raw_cap = 0;

    for (size_t i = 0; i < producer->entry_tx_count; i++) {
        uint8_t buf[SOL_MAX_TX_SIZE];
        size_t written = 0;
        sol_err_t err = sol_transaction_encode(producer->entry_txs[i],
                                               buf, sizeof(buf), &written);
        if (err != SOL_OK) {
            sol_free(raw);
            raw = NULL;
            raw_len = 0;
            raw_cap = 0;
            break;
        }

        if (raw_len + written > raw_cap) {
            size_t new_cap = raw_cap ? raw_cap * 2 : 512;
            if (new_cap < raw_len + written) {
                new_cap = raw_len + written;
            }
            uint8_t* new_raw = sol_realloc(raw, new_cap);
            if (!new_raw) {
                sol_free(raw);
                raw = NULL;
                raw_len = 0;
                raw_cap = 0;
                break;
            }
            raw = new_raw;
            raw_cap = new_cap;
        }

        memcpy(raw + raw_len, buf, written);
        raw_len += written;
    }

    entry.raw_data = raw;
    entry.raw_data_len = raw_len;

    /* If we couldn't serialize any transaction data, the entry would be invalid. */
    if (entry.num_transactions > 0 && entry.raw_data_len == 0) {
        sol_entry_cleanup(&entry);
        /* Free processed transactions */
        for (size_t i = 0; i < producer->entry_tx_count; i++) {
            free_transaction(producer->entry_txs[i]);
            producer->entry_txs[i] = NULL;
        }
        producer->entry_tx_count = 0;
        return;
    }

    /* Store entry */
    if (producer->entry_count < producer->entry_capacity) {
        producer->entries[producer->entry_count++] = entry;
        producer->prev_entry_hash = entry.hash;
        producer->stats.entries_produced++;

        /* Invoke callback */
        if (producer->entry_callback) {
            producer->entry_callback(producer->entry_callback_ctx,
                                     &entry, producer->slot,
                                     producer->entry_count - 1);
        }
    } else {
        sol_entry_cleanup(&entry);
    }

    /* Free processed transactions (we've serialized them into entry.raw_data). */
    for (size_t i = 0; i < producer->entry_tx_count; i++) {
        free_transaction(producer->entry_txs[i]);
        producer->entry_txs[i] = NULL;
    }

    /* Reset current entry */
    producer->entry_tx_count = 0;
}

/*
 * Create a tick entry
 */
static void
create_tick_entry(sol_block_producer_t* producer) {
    if (!producer->prev_entry_hash_set) {
        memset(producer->prev_entry_hash.bytes, 0, sizeof(producer->prev_entry_hash.bytes));
        producer->prev_entry_hash_set = true;
    }

    sol_entry_t tick;
    sol_entry_init(&tick);
    tick.num_hashes = 1;
    tick.num_transactions = 0;

    sol_entry_compute_hash(&tick, &producer->prev_entry_hash, &tick.hash);

    if (producer->entry_count < producer->entry_capacity) {
        producer->entries[producer->entry_count++] = tick;
        producer->prev_entry_hash = tick.hash;
        producer->stats.ticks_produced++;
        producer->stats.entries_produced++;

        if (producer->bank) {
            sol_bank_register_tick(producer->bank, &tick.hash);
        }
    }
}

/*
 * PoH tick callback
 */
static void
on_poh_tick(void* ctx, const sol_poh_entry_t* tick, uint64_t tick_height) {
    sol_block_producer_t* producer = (sol_block_producer_t*)ctx;
    (void)tick;
    (void)tick_height;

    if (!producer || !producer->bank || !producer->poh) {
        return;
    }

    /* Only mutate bank / build entries while actively producing for the
     * slot we're assigned. PoH ticks continue even outside leader slots. */
    if (!sol_poh_recorder_is_leader_slot(producer->poh, producer->slot)) {
        return;
    }

    pthread_mutex_lock(&producer->lock);

    /* Flush current entry on tick */
    if (producer->entry_tx_count > 0) {
        create_entry(producer);
    }

    /* Create tick entry */
    create_tick_entry(producer);

    /* Check if slot is complete */
    uint64_t tick_in_slot = sol_poh_recorder_tick_in_slot(producer->poh);
    if (tick_in_slot == 0 && producer->entry_count > 0) {
        sol_slot_t completed_slot = producer->slot;
        sol_hash_t blockhash = producer->prev_entry_hash;
        uint64_t num_entries = producer->entry_count;
        uint64_t num_transactions = producer->slot_tx_count;

        /* Build serialized block data for callbacks. */
        uint8_t* block_data = NULL;
        size_t block_data_len = 0;

        if (producer->block_data_callback) {
            size_t total = 0;
            total += 8; /* bincode Vec<Entry> length prefix */
            for (size_t i = 0; i < producer->entry_count; i++) {
                /* Entry header:
                 *   num_hashes:u64 (8) + hash:32 + tx_len:u64 (8) */
                total += (8u + 32u + 8u) + producer->entries[i].raw_data_len;
            }

            if (total > 0) {
                block_data = sol_alloc(total);
                if (block_data) {
                    size_t off = 0;
                    uint64_t entry_count = producer->entry_count;
                    memcpy(block_data, &entry_count, 8);
                    off += 8;
                    for (size_t i = 0; i < producer->entry_count; i++) {
                        size_t written = 0;
                        if (sol_entry_serialize(&producer->entries[i],
                                                block_data + off,
                                                total - off,
                                                &written) != SOL_OK) {
                            sol_free(block_data);
                            block_data = NULL;
                            block_data_len = 0;
                            break;
                        }
                        off += written;
                    }
                    if (block_data) {
                        block_data_len = off;
                    }
                }
            }
        }

        sol_slot_complete_callback_t slot_cb = producer->slot_callback;
        void* slot_cb_ctx = producer->slot_callback_ctx;
        sol_block_data_callback_t block_cb = producer->block_data_callback;
        void* block_cb_ctx = producer->block_data_callback_ctx;

        /* Reset for new slot */
        for (size_t i = 0; i < producer->entry_count; i++) {
            sol_entry_cleanup(&producer->entries[i]);
        }
        producer->entry_count = 0;
        producer->slot_tx_count = 0;

        producer->stats.slots_completed++;
        producer->slot = sol_poh_recorder_slot(producer->poh);

        pthread_mutex_unlock(&producer->lock);

        /* Invoke callbacks outside the producer lock. */
        if (slot_cb) {
            slot_cb(slot_cb_ctx, completed_slot, &blockhash, num_entries, num_transactions);
        }
        if (block_cb && block_data && block_data_len > 0) {
            block_cb(block_cb_ctx, completed_slot, &blockhash,
                     block_data, block_data_len,
                     num_entries, num_transactions);
        }
        sol_free(block_data);

        return;
    }

    pthread_mutex_unlock(&producer->lock);
}

/*
 * Producer thread function
 */
static void*
producer_thread_func(void* arg) {
    sol_block_producer_t* producer = (sol_block_producer_t*)arg;

    while (producer->running) {
        pthread_mutex_lock(&producer->lock);

        /* Wait for transactions */
        while (producer->running &&
               producer->tx_queue_head == producer->tx_queue_tail) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_nsec += 1000000;  /* 1ms timeout */
            if (ts.tv_nsec >= 1000000000) {
                ts.tv_sec++;
                ts.tv_nsec -= 1000000000;
            }
            pthread_cond_timedwait(&producer->tx_available, &producer->lock, &ts);
        }

        if (!producer->running) {
            pthread_mutex_unlock(&producer->lock);
            break;
        }

        /* Process transactions from queue */
        while (producer->tx_queue_head != producer->tx_queue_tail &&
               producer->entry_tx_count < producer->config.max_txs_per_entry) {

            tx_queue_entry_t* entry = &producer->tx_queue[producer->tx_queue_head];
            producer->tx_queue_head = (producer->tx_queue_head + 1) % producer->tx_queue_size;

            if (entry->valid && entry->tx) {
                process_transaction(producer, entry->tx);
                entry->valid = false;
            }
        }

        /* Create entry if full */
        if (producer->entry_tx_count >= producer->config.max_txs_per_entry) {
            create_entry(producer);
        }

        pthread_mutex_unlock(&producer->lock);
    }

    return NULL;
}

/*
 * Create a new block producer
 */
sol_block_producer_t*
sol_block_producer_new(sol_poh_recorder_t* poh_recorder,
                       const sol_block_producer_config_t* config) {
    if (!poh_recorder) return NULL;

    sol_block_producer_t* producer = sol_calloc(1, sizeof(sol_block_producer_t));
    if (!producer) return NULL;

    if (config) {
        producer->config = *config;
    } else {
        producer->config = (sol_block_producer_config_t)SOL_BLOCK_PRODUCER_CONFIG_DEFAULT;
    }

    producer->poh = poh_recorder;
    producer->bank = NULL;
    producer->slot = 0;
    producer->prev_entry_hash_set = false;
    producer->slot_tx_count = 0;

    /* Allocate transaction queue */
    producer->tx_queue_size = TX_QUEUE_SIZE;
    producer->tx_queue = sol_calloc(producer->tx_queue_size, sizeof(tx_queue_entry_t));
    if (!producer->tx_queue) {
        sol_free(producer);
        return NULL;
    }
    producer->tx_queue_head = 0;
    producer->tx_queue_tail = 0;

    /* Allocate current entry buffers */
    producer->entry_txs = sol_calloc(producer->config.max_txs_per_entry,
                                     sizeof(sol_transaction_t*));
    producer->entry_tx_hashes = sol_calloc(producer->config.max_txs_per_entry,
                                           sizeof(sol_hash_t));
    if (!producer->entry_txs || !producer->entry_tx_hashes) {
        sol_free(producer->tx_queue);
        sol_free(producer->entry_txs);
        sol_free(producer->entry_tx_hashes);
        sol_free(producer);
        return NULL;
    }
    producer->entry_tx_count = 0;

    /* Allocate entries array */
    producer->entry_capacity = producer->config.max_entries_per_slot;
    producer->entries = sol_calloc(producer->entry_capacity, sizeof(sol_entry_t));
    if (!producer->entries) {
        sol_free(producer->tx_queue);
        sol_free(producer->entry_txs);
        sol_free(producer->entry_tx_hashes);
        sol_free(producer);
        return NULL;
    }
    producer->entry_count = 0;

    pthread_mutex_init(&producer->lock, NULL);
    pthread_cond_init(&producer->tx_available, NULL);
    producer->running = false;
    producer->thread_started = false;

    /* Set up PoH tick callback */
    sol_poh_recorder_set_tick_callback(poh_recorder, on_poh_tick, producer);

    return producer;
}

/*
 * Destroy block producer
 */
void
sol_block_producer_destroy(sol_block_producer_t* producer) {
    if (!producer) return;

    sol_block_producer_stop(producer);

    /* Free entries */
    for (size_t i = 0; i < producer->entry_count; i++) {
        sol_entry_cleanup(&producer->entries[i]);
    }
    sol_free(producer->entries);

    /* Free transaction queue */
    for (size_t i = 0; i < producer->tx_queue_size; i++) {
        if (producer->tx_queue[i].valid) {
            free_transaction((sol_transaction_t*)producer->tx_queue[i].tx);
        }
    }
    sol_free(producer->tx_queue);

    /* Free any pending transactions not yet flushed into an entry */
    for (size_t i = 0; i < producer->entry_tx_count; i++) {
        free_transaction(producer->entry_txs[i]);
        producer->entry_txs[i] = NULL;
    }

    sol_free(producer->entry_txs);
    sol_free(producer->entry_tx_hashes);

    pthread_mutex_destroy(&producer->lock);
    pthread_cond_destroy(&producer->tx_available);

    sol_free(producer);
}

/*
 * Set the working bank
 */
sol_err_t
sol_block_producer_set_bank(sol_block_producer_t* producer, sol_bank_t* bank) {
    if (!producer) return SOL_ERR_INVAL;

    pthread_mutex_lock(&producer->lock);

    producer->bank = bank;
    if (bank) {
        producer->slot = sol_bank_slot(bank);
        const sol_hash_t* start = sol_bank_blockhash(bank);
        if (start) {
            producer->prev_entry_hash = *start;
            producer->prev_entry_hash_set = true;
        } else {
            memset(producer->prev_entry_hash.bytes, 0, sizeof(producer->prev_entry_hash.bytes));
            producer->prev_entry_hash_set = true;
        }
        producer->slot_tx_count = 0;
    } else {
        producer->prev_entry_hash_set = false;
        producer->slot_tx_count = 0;
    }

    /* Reset entry state for new slot */
    producer->entry_count = 0;
    producer->entry_tx_count = 0;

    pthread_mutex_unlock(&producer->lock);
    return SOL_OK;
}

/*
 * Clear the working bank
 */
sol_err_t
sol_block_producer_clear_bank(sol_block_producer_t* producer) {
    return sol_block_producer_set_bank(producer, NULL);
}

/*
 * Start block production
 */
sol_err_t
sol_block_producer_start(sol_block_producer_t* producer) {
    if (!producer) return SOL_ERR_INVAL;
    if (producer->running) return SOL_OK;

    producer->running = true;

    if (pthread_create(&producer->thread, NULL, producer_thread_func, producer) != 0) {
        producer->running = false;
        return SOL_ERR_IO;
    }

    producer->thread_started = true;
    return SOL_OK;
}

/*
 * Stop block production
 */
sol_err_t
sol_block_producer_stop(sol_block_producer_t* producer) {
    if (!producer) return SOL_ERR_INVAL;
    if (!producer->running) return SOL_OK;

    producer->running = false;
    pthread_cond_signal(&producer->tx_available);

    if (producer->thread_started) {
        pthread_join(producer->thread, NULL);
        producer->thread_started = false;
    }

    return SOL_OK;
}

/*
 * Check if currently producing
 */
bool
sol_block_producer_is_producing(const sol_block_producer_t* producer) {
    if (!producer) return false;
    return producer->running && producer->bank != NULL;
}

/*
 * Submit a transaction
 */
sol_err_t
sol_block_producer_submit(sol_block_producer_t* producer,
                          const sol_transaction_t* tx) {
    if (!producer || !tx) return SOL_ERR_INVAL;

    pthread_mutex_lock(&producer->lock);

    /* Check if queue is full */
    size_t next_tail = (producer->tx_queue_tail + 1) % producer->tx_queue_size;
    if (next_tail == producer->tx_queue_head) {
        pthread_mutex_unlock(&producer->lock);
        return SOL_ERR_FULL;
    }

    /* Clone transaction */
    sol_transaction_t* tx_copy = clone_transaction(tx);
    if (!tx_copy) {
        pthread_mutex_unlock(&producer->lock);
        return SOL_ERR_NOMEM;
    }

    /* Add to queue */
    producer->tx_queue[producer->tx_queue_tail].tx = tx_copy;
    producer->tx_queue[producer->tx_queue_tail].valid = true;
    producer->tx_queue_tail = next_tail;

    pthread_cond_signal(&producer->tx_available);
    pthread_mutex_unlock(&producer->lock);

    return SOL_OK;
}

/*
 * Submit a batch of transactions
 */
sol_err_t
sol_block_producer_submit_batch(sol_block_producer_t* producer,
                                 const sol_transaction_t** txs,
                                 size_t count) {
    if (!producer || !txs) return SOL_ERR_INVAL;

    for (size_t i = 0; i < count; i++) {
        sol_err_t err = sol_block_producer_submit(producer, txs[i]);
        if (err != SOL_OK) return err;
    }

    return SOL_OK;
}

/*
 * Flush current entry
 */
sol_err_t
sol_block_producer_flush_entry(sol_block_producer_t* producer) {
    if (!producer) return SOL_ERR_INVAL;

    pthread_mutex_lock(&producer->lock);

    if (producer->entry_tx_count > 0) {
        create_entry(producer);
    }

    pthread_mutex_unlock(&producer->lock);
    return SOL_OK;
}

/*
 * Get produced entries
 */
size_t
sol_block_producer_get_entries(sol_block_producer_t* producer,
                                sol_entry_t* out_entries,
                                size_t max_entries) {
    if (!producer || !out_entries || max_entries == 0) return 0;

    pthread_mutex_lock(&producer->lock);

    size_t count = producer->entry_count;
    if (count > max_entries) count = max_entries;

    memcpy(out_entries, producer->entries, count * sizeof(sol_entry_t));

    pthread_mutex_unlock(&producer->lock);
    return count;
}

/*
 * Get current slot
 */
sol_slot_t
sol_block_producer_slot(const sol_block_producer_t* producer) {
    if (!producer) return 0;
    return producer->slot;
}

/*
 * Get entry count
 */
uint64_t
sol_block_producer_entry_count(const sol_block_producer_t* producer) {
    if (!producer) return 0;
    return producer->entry_count;
}

/*
 * Get transaction count
 */
uint64_t
sol_block_producer_tx_count(const sol_block_producer_t* producer) {
    if (!producer) return 0;
    return producer->stats.transactions_processed;
}

/*
 * Set entry callback
 */
void
sol_block_producer_set_entry_callback(sol_block_producer_t* producer,
                                       sol_entry_callback_t callback,
                                       void* ctx) {
    if (!producer) return;

    pthread_mutex_lock(&producer->lock);
    producer->entry_callback = callback;
    producer->entry_callback_ctx = ctx;
    pthread_mutex_unlock(&producer->lock);
}

/*
 * Set slot callback
 */
void
sol_block_producer_set_slot_callback(sol_block_producer_t* producer,
                                      sol_slot_complete_callback_t callback,
                                      void* ctx) {
    if (!producer) return;

    pthread_mutex_lock(&producer->lock);
    producer->slot_callback = callback;
    producer->slot_callback_ctx = ctx;
    pthread_mutex_unlock(&producer->lock);
}

void
sol_block_producer_set_block_data_callback(sol_block_producer_t* producer,
                                           sol_block_data_callback_t callback,
                                           void* ctx) {
    if (!producer) return;

    pthread_mutex_lock(&producer->lock);
    producer->block_data_callback = callback;
    producer->block_data_callback_ctx = ctx;
    pthread_mutex_unlock(&producer->lock);
}

/*
 * Get statistics
 */
sol_block_producer_stats_t
sol_block_producer_stats(const sol_block_producer_t* producer) {
    sol_block_producer_stats_t stats = {0};
    if (!producer) return stats;

    pthread_mutex_lock((pthread_mutex_t*)&producer->lock);
    stats = producer->stats;
    pthread_mutex_unlock((pthread_mutex_t*)&producer->lock);

    return stats;
}
