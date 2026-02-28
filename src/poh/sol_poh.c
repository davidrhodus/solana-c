/*
 * sol_poh.c - Proof of History Implementation
 */

#include "sol_poh.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include <string.h>
#include <time.h>

/*
 * Maximum pending entries before flush
 */
#define MAX_PENDING_ENTRIES 1024

/*
 * Maximum transactions per entry
 */
#define MAX_TXS_PER_ENTRY 64

/*
 * PoH recorder internal state
 */
struct sol_poh_recorder {
    sol_poh_config_t        config;

    /* Current state */
    sol_hash_t              hash;               /* Current PoH hash */
    uint64_t                tick_height;        /* Current tick height */
    uint64_t                num_hashes;         /* Hashes since last entry */

    /* Leader state */
    bool                    is_leader;
    sol_slot_t              leader_start_slot;
    sol_slot_t              leader_end_slot;

    /* Pending entries */
    sol_poh_entry_t*        pending_entries;
    size_t                  pending_count;
    size_t                  pending_capacity;

    /* Current entry being built */
    sol_hash_t*             current_tx_hashes;
    size_t                  current_tx_count;
    size_t                  current_tx_capacity;

    /* Thread control */
    pthread_t               thread;
    pthread_mutex_t         lock;
    pthread_cond_t          cond;
    bool                    running;
    bool                    thread_started;

    /* Tick callback */
    sol_poh_tick_callback_t tick_callback;
    void*                   tick_callback_ctx;
};

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
 * Compute N sequential hashes
 */
void
sol_poh_hash_n(const sol_hash_t* start, uint64_t num_hashes, sol_hash_t* out) {
    if (num_hashes == 0) {
        *out = *start;
        return;
    }

    sol_hash_t current = *start;

    sol_sha256_32bytes_repeated(current.bytes, num_hashes);

    *out = current;
}

/*
 * Mix in data to PoH hash
 */
void
sol_poh_hash_mixin(const sol_hash_t* prev,
                   const void* mixin,
                   size_t mixin_len,
                   sol_hash_t* out) {
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    sol_sha256_update(&ctx, prev->bytes, 32);
    sol_sha256_update(&ctx, mixin, mixin_len);
    sol_sha256_final_bytes(&ctx, out->bytes);
}

/*
 * Internal: do one hash step
 */
static void
poh_hash_step(sol_poh_recorder_t* recorder) {
    sol_sha256_32bytes(recorder->hash.bytes, recorder->hash.bytes);
    recorder->num_hashes++;
}

static sol_slot_t
poh_current_slot(const sol_poh_recorder_t* recorder);

/*
 * Internal: create a tick entry
 */
static void
poh_create_tick_locked(sol_poh_recorder_t* recorder,
                       sol_poh_entry_t* out_tick,
                       uint64_t* out_tick_height,
                       sol_poh_tick_callback_t* out_cb,
                       void** out_cb_ctx) {
    sol_slot_t current = poh_current_slot(recorder);
    bool in_leader_slot = recorder->is_leader &&
                          current >= recorder->leader_start_slot &&
                          current <= recorder->leader_end_slot;

    /* Flush any pending transactions as an entry first */
    if (recorder->current_tx_count > 0 && in_leader_slot) {
        sol_poh_entry_t entry = {
            .num_hashes = recorder->num_hashes,
            .hash = recorder->hash,
            .transactions = recorder->current_tx_hashes,
            .num_transactions = recorder->current_tx_count,
        };

        if (recorder->pending_count < recorder->pending_capacity) {
            recorder->pending_entries[recorder->pending_count++] = entry;
        }

        /* Allocate new tx array */
        recorder->current_tx_hashes = sol_calloc(MAX_TXS_PER_ENTRY, sizeof(sol_hash_t));
        recorder->current_tx_count = 0;
        recorder->num_hashes = 0;
    }

    /* Create tick entry */
    sol_poh_entry_t tick = {
        .num_hashes = recorder->num_hashes,
        .hash = recorder->hash,
        .transactions = NULL,
        .num_transactions = 0,
    };

    if (recorder->pending_count < recorder->pending_capacity) {
        recorder->pending_entries[recorder->pending_count++] = tick;
    }

    recorder->num_hashes = 0;
    recorder->tick_height++;

    if (out_tick) {
        *out_tick = tick;
    }
    if (out_tick_height) {
        *out_tick_height = recorder->tick_height;
    }
    if (out_cb) {
        *out_cb = recorder->tick_callback;
    }
    if (out_cb_ctx) {
        *out_cb_ctx = recorder->tick_callback_ctx;
    }
}

/*
 * Internal: compute current slot from tick height
 */
static sol_slot_t
poh_current_slot(const sol_poh_recorder_t* recorder) {
    return recorder->tick_height / recorder->config.ticks_per_slot;
}

/*
 * PoH thread function
 */
static void*
poh_thread_func(void* arg) {
    sol_poh_recorder_t* recorder = (sol_poh_recorder_t*)arg;
    uint64_t hashes_this_tick = 0;
    uint64_t last_tick_time = get_time_ns();

    while (recorder->running) {
        sol_poh_tick_callback_t cb = NULL;
        void* cb_ctx = NULL;
        sol_poh_entry_t tick;
        uint64_t tick_height = 0;
        bool call_cb = false;

        pthread_mutex_lock(&recorder->lock);

        /* Do a batch of hashes */
        for (int i = 0; i < 100 && recorder->running; i++) {
            poh_hash_step(recorder);
            hashes_this_tick++;

            /* Check if we should tick */
            if (hashes_this_tick >= recorder->config.hashes_per_tick) {
                poh_create_tick_locked(recorder, &tick, &tick_height, &cb, &cb_ctx);
                hashes_this_tick = 0;
                last_tick_time = get_time_ns();
                call_cb = (cb != NULL);
                break;  /* invoke callback outside the recorder lock */
            }
        }

        pthread_mutex_unlock(&recorder->lock);

        if (call_cb) {
            cb(cb_ctx, &tick, tick_height);
        }

        /* Yield to other threads */
        if (hashes_this_tick % 1000 == 0) {
            /* Check timing - sleep if ahead of schedule */
            uint64_t now = get_time_ns();
            uint64_t elapsed = now - last_tick_time;
            uint64_t expected = (hashes_this_tick * recorder->config.target_tick_ns) /
                               recorder->config.hashes_per_tick;

            if (elapsed < expected) {
                struct timespec ts = {
                    .tv_sec = 0,
                    .tv_nsec = (long)(expected - elapsed) / 10,
                };
                nanosleep(&ts, NULL);
            }
        }
    }

    return NULL;
}

/*
 * Create a new PoH recorder
 */
sol_poh_recorder_t*
sol_poh_recorder_new(const sol_hash_t* start_hash,
                     uint64_t start_tick,
                     const sol_poh_config_t* config) {
    sol_poh_recorder_t* recorder = sol_calloc(1, sizeof(sol_poh_recorder_t));
    if (!recorder) return NULL;

    if (config) {
        recorder->config = *config;
    } else {
        recorder->config = (sol_poh_config_t)SOL_POH_CONFIG_DEFAULT;
    }

    if (start_hash) {
        recorder->hash = *start_hash;
    } else {
        memset(recorder->hash.bytes, 0, 32);
    }

    recorder->tick_height = start_tick;
    recorder->num_hashes = 0;
    recorder->is_leader = false;

    /* Allocate pending entries */
    recorder->pending_capacity = MAX_PENDING_ENTRIES;
    recorder->pending_entries = sol_calloc(recorder->pending_capacity, sizeof(sol_poh_entry_t));
    if (!recorder->pending_entries) {
        sol_free(recorder);
        return NULL;
    }
    recorder->pending_count = 0;

    /* Allocate current tx array */
    recorder->current_tx_capacity = MAX_TXS_PER_ENTRY;
    recorder->current_tx_hashes = sol_calloc(recorder->current_tx_capacity, sizeof(sol_hash_t));
    if (!recorder->current_tx_hashes) {
        sol_free(recorder->pending_entries);
        sol_free(recorder);
        return NULL;
    }
    recorder->current_tx_count = 0;

    pthread_mutex_init(&recorder->lock, NULL);
    pthread_cond_init(&recorder->cond, NULL);
    recorder->running = false;
    recorder->thread_started = false;

    return recorder;
}

/*
 * Destroy PoH recorder
 */
void
sol_poh_recorder_destroy(sol_poh_recorder_t* recorder) {
    if (!recorder) return;

    sol_poh_recorder_stop(recorder);

    /* Free pending entries */
    for (size_t i = 0; i < recorder->pending_count; i++) {
        sol_poh_entry_free(&recorder->pending_entries[i]);
    }
    sol_free(recorder->pending_entries);

    /* Free current tx array */
    sol_free(recorder->current_tx_hashes);

    pthread_mutex_destroy(&recorder->lock);
    pthread_cond_destroy(&recorder->cond);

    sol_free(recorder);
}

/*
 * Start the PoH recorder thread
 */
sol_err_t
sol_poh_recorder_start(sol_poh_recorder_t* recorder) {
    if (!recorder) return SOL_ERR_INVAL;
    if (recorder->running) return SOL_OK;

    recorder->running = true;

    if (pthread_create(&recorder->thread, NULL, poh_thread_func, recorder) != 0) {
        recorder->running = false;
        return SOL_ERR_IO;
    }

    recorder->thread_started = true;
    return SOL_OK;
}

/*
 * Stop the PoH recorder thread
 */
sol_err_t
sol_poh_recorder_stop(sol_poh_recorder_t* recorder) {
    if (!recorder) return SOL_ERR_INVAL;
    if (!recorder->running) return SOL_OK;

    recorder->running = false;

    if (recorder->thread_started) {
        pthread_join(recorder->thread, NULL);
        recorder->thread_started = false;
    }

    return SOL_OK;
}

/*
 * Set the leader slot range
 */
sol_err_t
sol_poh_recorder_set_leader_slots(sol_poh_recorder_t* recorder,
                                   sol_slot_t start_slot,
                                   sol_slot_t end_slot) {
    if (!recorder) return SOL_ERR_INVAL;

    pthread_mutex_lock(&recorder->lock);

    recorder->is_leader = true;
    recorder->leader_start_slot = start_slot;
    recorder->leader_end_slot = end_slot;

    pthread_mutex_unlock(&recorder->lock);
    return SOL_OK;
}

/*
 * Clear leader status
 */
sol_err_t
sol_poh_recorder_clear_leader(sol_poh_recorder_t* recorder) {
    if (!recorder) return SOL_ERR_INVAL;

    pthread_mutex_lock(&recorder->lock);
    recorder->is_leader = false;
    pthread_mutex_unlock(&recorder->lock);

    return SOL_OK;
}

/*
 * Check if currently in a leader slot
 */
bool
sol_poh_recorder_is_leader(const sol_poh_recorder_t* recorder) {
    if (!recorder) return false;

    pthread_mutex_lock((pthread_mutex_t*)&recorder->lock);
    sol_slot_t current = poh_current_slot(recorder);
    bool is_leader = recorder->is_leader &&
                     current >= recorder->leader_start_slot &&
                     current <= recorder->leader_end_slot;
    pthread_mutex_unlock((pthread_mutex_t*)&recorder->lock);
    return is_leader;
}

bool
sol_poh_recorder_is_leader_slot(const sol_poh_recorder_t* recorder, sol_slot_t slot) {
    if (!recorder) return false;

    pthread_mutex_lock((pthread_mutex_t*)&recorder->lock);
    bool is_leader = recorder->is_leader &&
                     slot >= recorder->leader_start_slot &&
                     slot <= recorder->leader_end_slot;
    pthread_mutex_unlock((pthread_mutex_t*)&recorder->lock);
    return is_leader;
}

/*
 * Record a transaction hash
 */
sol_err_t
sol_poh_recorder_record(sol_poh_recorder_t* recorder, const sol_hash_t* tx_hash) {
    if (!recorder || !tx_hash) return SOL_ERR_INVAL;

    pthread_mutex_lock(&recorder->lock);

    sol_slot_t current = poh_current_slot(recorder);
    bool in_leader_slot = recorder->is_leader &&
                          current >= recorder->leader_start_slot &&
                          current <= recorder->leader_end_slot;

    if (!in_leader_slot) {
        pthread_mutex_unlock(&recorder->lock);
        return SOL_ERR_PERM;
    }

    /* Check if we need a new entry (too many transactions) */
    if (recorder->current_tx_count >= recorder->current_tx_capacity) {
        /* Flush current entry */
        sol_poh_entry_t entry = {
            .num_hashes = recorder->num_hashes,
            .hash = recorder->hash,
            .transactions = recorder->current_tx_hashes,
            .num_transactions = recorder->current_tx_count,
        };

        if (recorder->pending_count < recorder->pending_capacity) {
            recorder->pending_entries[recorder->pending_count++] = entry;
        }

        recorder->current_tx_hashes = sol_calloc(MAX_TXS_PER_ENTRY, sizeof(sol_hash_t));
        recorder->current_tx_count = 0;
        recorder->num_hashes = 0;
    }

    /* Mix in the transaction hash */
    sol_poh_hash_mixin(&recorder->hash, tx_hash->bytes, 32, &recorder->hash);
    recorder->num_hashes++;

    /* Store transaction hash */
    recorder->current_tx_hashes[recorder->current_tx_count++] = *tx_hash;

    pthread_mutex_unlock(&recorder->lock);
    return SOL_OK;
}

/*
 * Record multiple transaction hashes
 */
sol_err_t
sol_poh_recorder_record_batch(sol_poh_recorder_t* recorder,
                               const sol_hash_t* tx_hashes,
                               size_t count) {
    if (!recorder || !tx_hashes) return SOL_ERR_INVAL;

    for (size_t i = 0; i < count; i++) {
        sol_err_t err = sol_poh_recorder_record(recorder, &tx_hashes[i]);
        if (err != SOL_OK) return err;
    }

    return SOL_OK;
}

/*
 * Force a tick
 */
sol_err_t
sol_poh_recorder_tick(sol_poh_recorder_t* recorder) {
    if (!recorder) return SOL_ERR_INVAL;

    sol_poh_tick_callback_t cb = NULL;
    void* cb_ctx = NULL;
    sol_poh_entry_t tick;
    uint64_t tick_height = 0;

    pthread_mutex_lock(&recorder->lock);

    /* Hash until we reach hashes_per_tick */
    while (recorder->num_hashes < recorder->config.hashes_per_tick) {
        poh_hash_step(recorder);
    }

    poh_create_tick_locked(recorder, &tick, &tick_height, &cb, &cb_ctx);

    pthread_mutex_unlock(&recorder->lock);

    if (cb) {
        cb(cb_ctx, &tick, tick_height);
    }
    return SOL_OK;
}

/*
 * Get current PoH hash
 */
sol_hash_t
sol_poh_recorder_hash(const sol_poh_recorder_t* recorder) {
    sol_hash_t hash = {0};
    if (!recorder) return hash;

    pthread_mutex_lock((pthread_mutex_t*)&recorder->lock);
    hash = recorder->hash;
    pthread_mutex_unlock((pthread_mutex_t*)&recorder->lock);

    return hash;
}

/*
 * Get current tick height
 */
uint64_t
sol_poh_recorder_tick_height(const sol_poh_recorder_t* recorder) {
    if (!recorder) return 0;

    pthread_mutex_lock((pthread_mutex_t*)&recorder->lock);
    uint64_t height = recorder->tick_height;
    pthread_mutex_unlock((pthread_mutex_t*)&recorder->lock);

    return height;
}

/*
 * Get current slot
 */
sol_slot_t
sol_poh_recorder_slot(const sol_poh_recorder_t* recorder) {
    if (!recorder) return 0;

    pthread_mutex_lock((pthread_mutex_t*)&recorder->lock);
    sol_slot_t slot = poh_current_slot(recorder);
    pthread_mutex_unlock((pthread_mutex_t*)&recorder->lock);

    return slot;
}

/*
 * Get tick within current slot
 */
uint64_t
sol_poh_recorder_tick_in_slot(const sol_poh_recorder_t* recorder) {
    if (!recorder) return 0;

    pthread_mutex_lock((pthread_mutex_t*)&recorder->lock);
    uint64_t tick = recorder->tick_height % recorder->config.ticks_per_slot;
    pthread_mutex_unlock((pthread_mutex_t*)&recorder->lock);

    return tick;
}

/*
 * Set tick callback
 */
void
sol_poh_recorder_set_tick_callback(sol_poh_recorder_t* recorder,
                                    sol_poh_tick_callback_t callback,
                                    void* ctx) {
    if (!recorder) return;

    pthread_mutex_lock(&recorder->lock);
    recorder->tick_callback = callback;
    recorder->tick_callback_ctx = ctx;
    pthread_mutex_unlock(&recorder->lock);
}

/*
 * Flush pending entries
 */
size_t
sol_poh_recorder_flush_entries(sol_poh_recorder_t* recorder,
                                sol_poh_entry_t* out_entries,
                                size_t max_entries) {
    if (!recorder || !out_entries || max_entries == 0) return 0;

    pthread_mutex_lock(&recorder->lock);

    size_t count = recorder->pending_count;
    if (count > max_entries) count = max_entries;

    memcpy(out_entries, recorder->pending_entries, count * sizeof(sol_poh_entry_t));

    /* Shift remaining entries */
    if (count < recorder->pending_count) {
        memmove(recorder->pending_entries,
                recorder->pending_entries + count,
                (recorder->pending_count - count) * sizeof(sol_poh_entry_t));
    }
    recorder->pending_count -= count;

    pthread_mutex_unlock(&recorder->lock);
    return count;
}

/*
 * Verify a single PoH entry
 */
bool
sol_poh_verify_entry(const sol_hash_t* prev_hash, const sol_poh_entry_t* entry) {
    if (!prev_hash || !entry) return false;

    sol_hash_t computed = *prev_hash;

    if (entry->num_transactions == 0) {
        /* Pure tick - just sequential hashes */
        sol_poh_hash_n(prev_hash, entry->num_hashes, &computed);
    } else {
        /* Entry with transactions mixed in */
        uint64_t hashes_before_txs = entry->num_hashes > entry->num_transactions ?
                                     entry->num_hashes - entry->num_transactions : 0;

        /* Hash before transactions */
        if (hashes_before_txs > 0) {
            sol_poh_hash_n(&computed, hashes_before_txs, &computed);
        }

        /* Mix in each transaction */
        for (size_t i = 0; i < entry->num_transactions; i++) {
            sol_poh_hash_mixin(&computed, entry->transactions[i].bytes, 32, &computed);
        }
    }

    return memcmp(computed.bytes, entry->hash.bytes, 32) == 0;
}

/*
 * Verify a sequence of PoH entries
 */
bool
sol_poh_verify_entries(const sol_hash_t* start_hash,
                       const sol_poh_entry_t* entries,
                       size_t count) {
    if (!start_hash || !entries || count == 0) return false;

    sol_hash_t prev = *start_hash;

    for (size_t i = 0; i < count; i++) {
        if (!sol_poh_verify_entry(&prev, &entries[i])) {
            return false;
        }
        prev = entries[i].hash;
    }

    return true;
}

/*
 * Verification work item for parallel verification
 */
typedef struct {
    const sol_hash_t*       start_hash;
    const sol_poh_entry_t*  entries;
    size_t                  start_idx;
    size_t                  count;
    bool                    result;
} poh_verify_work_t;

static void*
poh_verify_worker(void* arg) {
    poh_verify_work_t* work = (poh_verify_work_t*)arg;

    sol_hash_t prev = *work->start_hash;

    for (size_t i = 0; i < work->count; i++) {
        const sol_poh_entry_t* entry = &work->entries[work->start_idx + i];

        if (!sol_poh_verify_entry(&prev, entry)) {
            work->result = false;
            return NULL;
        }
        prev = entry->hash;
    }

    work->result = true;
    return NULL;
}

/*
 * Parallel PoH verification
 */
bool
sol_poh_verify_entries_parallel(const sol_hash_t* start_hash,
                                 const sol_poh_entry_t* entries,
                                 size_t count,
                                 size_t num_threads) {
    if (!start_hash || !entries || count == 0) return false;

    /* For small counts, just do serial verification */
    if (count < 100 || num_threads <= 1) {
        return sol_poh_verify_entries(start_hash, entries, count);
    }

    /* Limit threads */
    if (num_threads == 0 || num_threads > 16) {
        num_threads = 4;
    }
    if (num_threads > count) {
        num_threads = count;
    }

    /* Divide work */
    size_t entries_per_thread = count / num_threads;
    poh_verify_work_t* work = sol_calloc(num_threads, sizeof(poh_verify_work_t));
    pthread_t* threads = sol_calloc(num_threads, sizeof(pthread_t));

    if (!work || !threads) {
        sol_free(work);
        sol_free(threads);
        return sol_poh_verify_entries(start_hash, entries, count);
    }

    /* Set up work items */
    sol_hash_t current_hash = *start_hash;
    size_t current_idx = 0;

    for (size_t t = 0; t < num_threads; t++) {
        work[t].start_hash = sol_alloc(sizeof(sol_hash_t));
        if (!work[t].start_hash) {
            /* Cleanup and fall back to serial */
            for (size_t j = 0; j < t; j++) {
                sol_free((void*)work[j].start_hash);
            }
            sol_free(work);
            sol_free(threads);
            return sol_poh_verify_entries(start_hash, entries, count);
        }

        *(sol_hash_t*)work[t].start_hash = current_hash;
        work[t].entries = entries;
        work[t].start_idx = current_idx;

        size_t this_count = entries_per_thread;
        if (t == num_threads - 1) {
            this_count = count - current_idx;  /* Last thread gets remainder */
        }
        work[t].count = this_count;

        /* Compute the hash at the end of this segment for next thread */
        for (size_t i = 0; i < this_count; i++) {
            current_hash = entries[current_idx + i].hash;
        }
        current_idx += this_count;

        pthread_create(&threads[t], NULL, poh_verify_worker, &work[t]);
    }

    /* Wait for all threads */
    bool all_valid = true;
    for (size_t t = 0; t < num_threads; t++) {
        pthread_join(threads[t], NULL);
        if (!work[t].result) {
            all_valid = false;
        }
        sol_free((void*)work[t].start_hash);
    }

    sol_free(work);
    sol_free(threads);

    return all_valid;
}

/*
 * Free entry resources
 */
void
sol_poh_entry_free(sol_poh_entry_t* entry) {
    if (!entry) return;

    sol_free(entry->transactions);
    entry->transactions = NULL;
    entry->num_transactions = 0;
}
