/*
 * sol_tvu.c - Transaction Validation Unit Implementation
 */

#include "sol_tvu.h"
#include "../util/sol_alloc.h"
#include "../util/sol_bits.h"
#include "../util/sol_log.h"
#include "../runtime/sol_leader_schedule.h"
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * Slot tracking entry
 */
typedef struct {
    sol_slot_t          slot;
    sol_slot_status_t   status;
    uint32_t            shreds_received;
    uint32_t            shreds_expected;
    uint64_t            first_received_ns;
    uint64_t            last_received_ns;
    /* Timestamp of the most recent shred that successfully inserted new bytes
     * into the blockstore (best-effort, monotonic). This is used to decide
     * whether to retry replay-incomplete slots without being fooled by pure
     * duplicate shred reception. */
    uint64_t            last_inserted_ns;
    uint64_t            last_repair_request_ns;
    bool                replay_retry_requested;
    sol_slot_t          waiting_parent_slot;
    sol_replay_result_t last_replay_result;
    uint64_t            last_replay_ns;
    /* Snapshot of blockstore variant state at the last replay attempt.
     *
     * Used to avoid tight replay loops on "complete" slots that fail replay
     * validation (e.g. missing ticks). Such slots should only be retried when
     * a *new complete* block variant arrives. */
    uint32_t            last_replay_complete_variants;
    /* Best-effort restart probe:
     * After a restart, the persisted blockstore may already contain shreds/meta
     * for some slots even before we receive any new shreds in this run. Probing
     * RocksDB for every tracked slot on every replay loop iteration is extremely
     * expensive, so we probe at most once per slot (and only for slots that have
     * not received any shreds in this run). */
    bool                restart_probed;
    int32_t             hash_next; /* next index in slot hash bucket (-1 if none) */
} slot_tracker_t;

#define MAX_TRACKED_SLOTS 4096
/* Slot tracker lookup is in the hot path (per-shred). Avoid O(N) scans of the
 * slot array by maintaining a simple chained hash table (indices into slots[]). */
#define SOL_TVU_SLOT_HASH_SIZE 8192u /* must be power-of-two */

/*
 * Shred queue entry
 */
typedef struct {
    uint8_t     data[1232];
    size_t      len;
    uint64_t    received_ns;
} shred_queue_entry_t;

#define SHRED_QUEUE_SIZE 262144
/* Auto-thread selection used to default to saturating the machine (clamped by
 * these caps). On high-core servers, that created hundreds of threads across
 * TVU roles and the tx-exec pool, leading to contention and worse replay
 * latency.  Prefer more conservative defaults; users can still override via
 * config/flags once exposed. */
#define SOL_TVU_MAX_VERIFY_THREADS 64
/* Replay is inherently sequential at the bank-forks level (parent->child),
 * but parallel replay threads can still improve throughput when multiple
 * complete forks/variants are available (duplicates, catchup backfill, etc.). */
#define SOL_TVU_MAX_REPLAY_THREADS 16
#define SOL_TVU_MAX_REPAIR_THREADS 32

typedef struct tvu_repair_thread_ctx {
    struct sol_tvu* tvu;
    uint32_t        thread_idx;
} tvu_repair_thread_ctx_t;

/*
 * TVU internal state
 */
struct sol_tvu {
    sol_tvu_config_t        config;

    /* Components */
    sol_blockstore_t*       blockstore;
    sol_replay_t*           replay;
    sol_turbine_t*          turbine;
    sol_repair_t*           repair;
    sol_leader_schedule_t*  leader_schedule;

    /* Slot tracking */
    slot_tracker_t          slots[MAX_TRACKED_SLOTS];
    size_t                  num_slots;
    pthread_mutex_t         slots_lock;
    int32_t                 slot_hash_heads[SOL_TVU_SLOT_HASH_SIZE];

    /* Shred queue */
    shred_queue_entry_t*    shred_queue;
    size_t                  shred_queue_head;
    size_t                  shred_queue_tail;
    pthread_mutex_t         shred_queue_lock;
    pthread_cond_t          shred_queue_cond;

    /* Statistics */
    sol_tvu_stats_t         stats;

    /* Callbacks */
    sol_block_complete_callback_t   block_callback;
    void*                           block_callback_ctx;

    /* Thread control */
    pthread_t*              shred_verify_threads;
    size_t                  shred_verify_thread_count;
    pthread_t*              replay_threads;
    size_t                  replay_thread_count;
    pthread_t*              repair_threads;
    size_t                  repair_thread_count;
    tvu_repair_thread_ctx_t* repair_thread_ctx;

    pthread_mutex_t         lock;
    bool                    running;
    bool                    threads_started;
};

/*
 * Get current time in nanoseconds
 */
static uint64_t
now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static uint32_t
tvu_count_complete_variants(sol_blockstore_t* bs, sol_slot_t slot) {
    if (!bs) return 0;

    size_t variants = sol_blockstore_num_variants(bs, slot);
    if (variants == 0) {
        /* If we have slot meta but no explicit variants record, variant 0 is
         * still addressable via get_slot_meta_variant(). */
        variants = 1;
    }

    uint32_t complete = 0;
    for (uint32_t variant_id = 0; variant_id < (uint32_t)variants; variant_id++) {
        sol_slot_meta_t meta;
        if (sol_blockstore_get_slot_meta_variant(bs, slot, variant_id, &meta) != SOL_OK) {
            continue;
        }
        if (meta.is_complete) {
            complete++;
        }
    }
    return complete;
}

static uint32_t
tvu_cpu_count(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n < 1) {
        return 1;
    }
    if (n > (long)UINT32_MAX) {
        return UINT32_MAX;
    }
    return (uint32_t)n;
}

static uint32_t
tvu_pick_threads(uint32_t requested, uint32_t max_threads, uint32_t min_auto) {
    uint32_t threads = requested;
    if (threads == 0) {
        uint32_t cpu_count = tvu_cpu_count();
        threads = cpu_count;
        if (threads < min_auto && cpu_count > 1) {
            threads = min_auto;
        }
    }
    if (threads == 0) {
        threads = 1;
    }
    if (threads > max_threads) {
        threads = max_threads;
    }
    return threads;
}

static bool
tvu_fast_mode(void) {
    static int cached = -1;
    if (cached >= 0) {
        return cached != 0;
    }

    const char* env = getenv("SOL_SKIP_TX_PROCESSING");
    cached = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    return cached != 0;
}

static bool
tvu_log_replayed_slots(void) {
    static int cached = -1;
    if (cached >= 0) return cached != 0;

    const char* env = getenv("SOL_LOG_REPLAY_SLOTS");
    cached = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    return cached != 0;
}

static sol_slot_t
tvu_max_shred_ahead_slots(void) {
    static long cached = -1;
    if (cached >= 0) {
        return (sol_slot_t)cached;
    }

    /* During bootstrap/catchup, turbine can deliver shreds far ahead of the
     * current replay cursor. Accepting all of them can easily saturate the
     * shred queue and blockstore, preventing catchup from making forward
     * progress. Cap how far ahead we admit shreds by default. */
    const char* env = getenv("SOL_TVU_MAX_SHRED_AHEAD_SLOTS");
    long v = 4096; /* default */
    if (env && env[0] != '\0') {
        char* end = NULL;
        long parsed = strtol(env, &end, 10);
        if (end && end != env) {
            v = parsed;
        }
    }

    if (v < 0) {
        v = 0;
    }
    if (v > 65536) {
        v = 65536;
    }
    cached = v;
    return (sol_slot_t)cached;
}

/*
 * Find or create slot tracker
 */
static inline uint32_t
tvu_slot_hash(sol_slot_t slot) {
    uint64_t x = (uint64_t)slot;
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return (uint32_t)x;
}

static inline uint32_t
tvu_slot_bucket(sol_slot_t slot) {
    return tvu_slot_hash(slot) & (SOL_TVU_SLOT_HASH_SIZE - 1u);
}

static inline void
tvu_slot_tracker_init(slot_tracker_t* tracker, sol_slot_t slot) {
    memset(tracker, 0, sizeof(*tracker));
    tracker->slot = slot;
    tracker->status = SOL_SLOT_STATUS_RECEIVING;
    tracker->first_received_ns = now_ns();
    tracker->last_replay_result = SOL_REPLAY_INCOMPLETE;
    tracker->restart_probed = false;
    tracker->hash_next = -1;
}

static int32_t
tvu_slot_map_find_idx(sol_tvu_t* tvu, sol_slot_t slot) {
    if (!tvu) return -1;
    uint32_t b = tvu_slot_bucket(slot);
    int32_t idx = tvu->slot_hash_heads[b];
    while (idx >= 0) {
        if (tvu->slots[(size_t)idx].slot == slot) {
            return idx;
        }
        idx = tvu->slots[(size_t)idx].hash_next;
    }
    return -1;
}

static slot_tracker_t*
tvu_slot_map_find(sol_tvu_t* tvu, sol_slot_t slot) {
    int32_t idx = tvu_slot_map_find_idx(tvu, slot);
    if (idx < 0) return NULL;
    return &tvu->slots[(size_t)idx];
}

static void
tvu_slot_map_insert(sol_tvu_t* tvu, int32_t idx, sol_slot_t slot) {
    uint32_t b = tvu_slot_bucket(slot);
    tvu->slots[(size_t)idx].hash_next = tvu->slot_hash_heads[b];
    tvu->slot_hash_heads[b] = idx;
}

static void
tvu_slot_map_remove(sol_tvu_t* tvu, int32_t idx, sol_slot_t slot) {
    uint32_t b = tvu_slot_bucket(slot);
    int32_t cur = tvu->slot_hash_heads[b];
    int32_t prev = -1;
    while (cur >= 0) {
        if (cur == idx) {
            int32_t next = tvu->slots[(size_t)cur].hash_next;
            if (prev < 0) {
                tvu->slot_hash_heads[b] = next;
            } else {
                tvu->slots[(size_t)prev].hash_next = next;
            }
            break;
        }
        prev = cur;
        cur = tvu->slots[(size_t)cur].hash_next;
    }
    tvu->slots[(size_t)idx].hash_next = -1;
}

static slot_tracker_t*
find_or_create_slot(sol_tvu_t* tvu, sol_slot_t slot) {
    /* Find existing */
    slot_tracker_t* existing = tvu_slot_map_find(tvu, slot);
    if (existing) return existing;

    /* Create new if space available */
    if (tvu->num_slots < MAX_TRACKED_SLOTS) {
        int32_t idx = (int32_t)tvu->num_slots++;
        slot_tracker_t* tracker = &tvu->slots[(size_t)idx];
        tvu_slot_tracker_init(tracker, slot);
        tvu_slot_map_insert(tvu, idx, slot);
        return tracker;
    }

    /* Evict a slot tracker */
    sol_slot_t oldest_slot = UINT64_MAX;
    size_t oldest_idx = 0;
    bool have_completed_victim = false;

    /* Prefer evicting already-processed slots to preserve catchup progress. */
    for (size_t i = 0; i < tvu->num_slots; i++) {
        if (tvu->slots[i].status != SOL_SLOT_STATUS_REPLAYED &&
            tvu->slots[i].status != SOL_SLOT_STATUS_DEAD) {
            continue;
        }
        if (!have_completed_victim || tvu->slots[i].slot < oldest_slot) {
            oldest_slot = tvu->slots[i].slot;
            oldest_idx = i;
            have_completed_victim = true;
        }
    }

    if (!have_completed_victim) {
        /* During bootstrap/catchup we tend to see shreds far ahead of the replay
         * cursor. Prefer keeping low-numbered slots (catchup window) and evict
         * the farthest-ahead slot instead. */
        sol_slot_t newest_slot = 0;
        size_t newest_idx = 0;
        for (size_t i = 0; i < tvu->num_slots; i++) {
            if (tvu->slots[i].slot > newest_slot) {
                newest_slot = tvu->slots[i].slot;
                newest_idx = i;
            }
        }
        oldest_slot = newest_slot;
        oldest_idx = newest_idx;
    }

    slot_tracker_t* tracker = &tvu->slots[oldest_idx];
    sol_slot_t evicted_slot = tracker->slot;
    tvu_slot_map_remove(tvu, (int32_t)oldest_idx, evicted_slot);

    tvu_slot_tracker_init(tracker, slot);
    tvu_slot_map_insert(tvu, (int32_t)oldest_idx, slot);
    return tracker;
}

/*
 * Find slot tracker
 */
static slot_tracker_t*
find_slot(sol_tvu_t* tvu, sol_slot_t slot) {
    return tvu_slot_map_find(tvu, slot);
}

/*
 * Push shred to queue
 */
static bool
shred_queue_push(sol_tvu_t* tvu, const uint8_t* data, size_t len) {
    pthread_mutex_lock(&tvu->shred_queue_lock);

    size_t next_tail = (tvu->shred_queue_tail + 1) % SHRED_QUEUE_SIZE;
    if (next_tail == tvu->shred_queue_head) {
        pthread_mutex_unlock(&tvu->shred_queue_lock);
        return false;
    }

    shred_queue_entry_t* entry = &tvu->shred_queue[tvu->shred_queue_tail];
    if (len > sizeof(entry->data)) {
        pthread_mutex_unlock(&tvu->shred_queue_lock);
        return false;
    }
    memcpy(entry->data, data, len);
    entry->len = len;
    entry->received_ns = now_ns();

    tvu->shred_queue_tail = next_tail;

    pthread_cond_signal(&tvu->shred_queue_cond);
    pthread_mutex_unlock(&tvu->shred_queue_lock);
    return true;
}

/*
 * Push a batch of shreds to the queue (single lock acquisition)
 *
 * Applies the same "too far ahead" backpressure policy as
 * sol_tvu_process_shred(). Returns number of shreds pushed. Any shreds that
 * are too large, or dropped due to queue full, are counted in the respective
 * out-params when provided.  Shreds dropped due to backpressure are not
 * counted as failures.
 */
static size_t
shred_queue_push_batch(sol_tvu_t* tvu,
                       const sol_udp_pkt_t* pkts,
                       int count,
                       sol_slot_t cursor,
                       sol_slot_t max_ahead,
                       uint64_t received_ns,
                       size_t* dropped_full_out,
                       size_t* dropped_too_large_out) {
    if (!tvu || !pkts || count <= 0) return 0;

    size_t pushed = 0;
    size_t dropped_full = 0;
    size_t dropped_too_large = 0;
    int full_from = -1;

    pthread_mutex_lock(&tvu->shred_queue_lock);

    bool was_empty = (tvu->shred_queue_head == tvu->shred_queue_tail);

    for (int i = 0; i < count; i++) {
        size_t len = pkts[i].len;
        if (len == 0) continue;

        if (len > sizeof(((shred_queue_entry_t*)0)->data)) {
            dropped_too_large++;
            continue;
        }

        if (max_ahead != 0 && cursor != 0 && len >= SOL_SHRED_COMMON_HEADER_SIZE) {
            sol_slot_t slot = (sol_slot_t)sol_load_u64_le(pkts[i].data + 65);
            if (slot > cursor && (slot - cursor) > max_ahead) {
                continue;
            }
        }

        size_t next_tail = (tvu->shred_queue_tail + 1) % SHRED_QUEUE_SIZE;
        if (next_tail == tvu->shred_queue_head) {
            full_from = i;
            break;
        }

        shred_queue_entry_t* entry = &tvu->shred_queue[tvu->shred_queue_tail];
        memcpy(entry->data, pkts[i].data, len);
        entry->len = len;
        entry->received_ns = received_ns;
        tvu->shred_queue_tail = next_tail;
        pushed++;
    }

    if (pushed > 0) {
        if (was_empty) {
            pthread_cond_broadcast(&tvu->shred_queue_cond);
        } else {
            pthread_cond_signal(&tvu->shred_queue_cond);
        }
    }

    pthread_mutex_unlock(&tvu->shred_queue_lock);

    if (full_from >= 0) {
        /* Count queue-full drops outside the lock. */
        for (int i = full_from; i < count; i++) {
            size_t len = pkts[i].len;
            if (len == 0) continue;

            if (len > sizeof(((shred_queue_entry_t*)0)->data)) {
                dropped_too_large++;
                continue;
            }

            if (max_ahead != 0 && cursor != 0 && len >= SOL_SHRED_COMMON_HEADER_SIZE) {
                sol_slot_t slot = (sol_slot_t)sol_load_u64_le(pkts[i].data + 65);
                if (slot > cursor && (slot - cursor) > max_ahead) {
                    continue;
                }
            }

            dropped_full++;
        }
    }

    if (dropped_full_out) *dropped_full_out = dropped_full;
    if (dropped_too_large_out) *dropped_too_large_out = dropped_too_large;
    return pushed;
}

/*
 * Pop shred from queue
 */
static bool
shred_queue_pop(sol_tvu_t* tvu, shred_queue_entry_t* out, int timeout_ms) {
    pthread_mutex_lock(&tvu->shred_queue_lock);

    while (tvu->shred_queue_head == tvu->shred_queue_tail) {
        if (!tvu->running || timeout_ms == 0) {
            pthread_mutex_unlock(&tvu->shred_queue_lock);
            return false;
        }

        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += timeout_ms * 1000000L;
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec += ts.tv_nsec / 1000000000L;
            ts.tv_nsec %= 1000000000L;
        }

        int ret = pthread_cond_timedwait(&tvu->shred_queue_cond,
                                          &tvu->shred_queue_lock, &ts);
        if (ret != 0) {
            pthread_mutex_unlock(&tvu->shred_queue_lock);
            return false;
        }
    }

    *out = tvu->shred_queue[tvu->shred_queue_head];
    tvu->shred_queue_head = (tvu->shred_queue_head + 1) % SHRED_QUEUE_SIZE;

    pthread_mutex_unlock(&tvu->shred_queue_lock);
    return true;
}

/*
 * Pop up to max entries from the queue (single lock acquisition).
 *
 * Returns number of entries popped.
 */
static size_t
shred_queue_pop_batch(sol_tvu_t* tvu,
                      shred_queue_entry_t* out,
                      size_t max,
                      int timeout_ms) {
    if (!tvu || !out || max == 0) return 0;

    pthread_mutex_lock(&tvu->shred_queue_lock);

    while (tvu->shred_queue_head == tvu->shred_queue_tail) {
        if (!tvu->running || timeout_ms == 0) {
            pthread_mutex_unlock(&tvu->shred_queue_lock);
            return 0;
        }

        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += timeout_ms * 1000000L;
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec += ts.tv_nsec / 1000000000L;
            ts.tv_nsec %= 1000000000L;
        }

        int ret = pthread_cond_timedwait(&tvu->shred_queue_cond,
                                        &tvu->shred_queue_lock, &ts);
        if (ret != 0) {
            pthread_mutex_unlock(&tvu->shred_queue_lock);
            return 0;
        }
    }

    size_t n = 0;
    while (n < max && tvu->shred_queue_head != tvu->shred_queue_tail) {
        out[n++] = tvu->shred_queue[tvu->shred_queue_head];
        tvu->shred_queue_head = (tvu->shred_queue_head + 1) % SHRED_QUEUE_SIZE;
    }

    pthread_mutex_unlock(&tvu->shred_queue_lock);
    return n;
}

/*
 * Shred verification thread
 */
static void*
shred_verify_thread_func(void* arg) {
    sol_tvu_t* tvu = (sol_tvu_t*)arg;

    while (tvu->running) {
        enum { SOL_TVU_VERIFY_BATCH = 32 };
        shred_queue_entry_t batch[SOL_TVU_VERIFY_BATCH];
        size_t batch_n = shred_queue_pop_batch(tvu, batch, SOL_TVU_VERIFY_BATCH, 100);
        if (batch_n == 0) {
            continue;
        }

        bool fast_mode = tvu_fast_mode();

        for (size_t bi = 0; bi < batch_n; bi++) {
            shred_queue_entry_t entry = batch[bi];

            /* Parse the shred */
            sol_shred_t shred;
            if (sol_shred_parse(&shred, entry.data, entry.len) != SOL_OK) {
                __atomic_fetch_add(&tvu->stats.shreds_failed, 1, __ATOMIC_RELAXED);
                continue;
            }

            /* Track the slot */
            pthread_mutex_lock(&tvu->slots_lock);
            slot_tracker_t* tracker = find_or_create_slot(tvu, shred.slot);
            tracker->shreds_received++;
            tracker->last_received_ns = entry.received_ns;
            if (shred.index + 1 > tracker->shreds_expected) {
                tracker->shreds_expected = shred.index + 1;
            }
            pthread_mutex_unlock(&tvu->slots_lock);

            /* Verify shred signature against slot leader */
            bool sig_valid = tvu->config.skip_shred_verify;
            bool have_leader = false;
            sol_pubkey_t leader_pk;

            if (!sig_valid) {
                /* Load leader schedule under lock and copy leader pubkey out so the
                 * schedule pointer can be safely swapped/freed concurrently. */
                pthread_mutex_lock(&tvu->lock);
                if (tvu->leader_schedule) {
                    const sol_pubkey_t* leader = sol_leader_schedule_get_leader(
                        tvu->leader_schedule, shred.slot);
                    if (leader) {
                        leader_pk = *leader;
                        have_leader = true;
                    } else {
                        /* Schedule doesn't cover this slot (e.g., epoch boundary). */
                        sig_valid = true;
                    }
                } else {
                    /* No leader schedule - skip verification (startup/testing) */
                    sig_valid = true;
                }
                pthread_mutex_unlock(&tvu->lock);

                if (!sig_valid && have_leader) {
                    sig_valid = sol_shred_verify(&shred, &leader_pk);
                }
            }

            if (!sig_valid) {
                __atomic_fetch_add(&tvu->stats.shreds_failed, 1, __ATOMIC_RELAXED);
                sol_log_debug("Shred signature verification failed for slot %lu index %u",
                              (unsigned long)shred.slot, shred.index);
                continue;
            }
            __atomic_fetch_add(&tvu->stats.shreds_verified, 1, __ATOMIC_RELAXED);

            /* Store in blockstore */
            sol_err_t insert_err = SOL_OK;
            bool inserted = false;
            if (tvu->blockstore) {
                insert_err = sol_blockstore_insert_shred(tvu->blockstore, &shred, entry.data, shred.raw_len);
                if (insert_err == SOL_OK) {
                    inserted = true;
                } else if (insert_err == SOL_ERR_EXISTS) {
                    __atomic_fetch_add(&tvu->stats.shreds_duplicate, 1, __ATOMIC_RELAXED);
                } else {
                    __atomic_fetch_add(&tvu->stats.shreds_failed, 1, __ATOMIC_RELAXED);
                    sol_log_debug("Blockstore insert failed for slot %lu index %u: %d",
                                  (unsigned long)shred.slot,
                                  (unsigned)shred.index,
                                  insert_err);
                    continue;
                }
            }

            /* Check if slot is complete */
            bool slot_complete = tvu->blockstore &&
                                 sol_blockstore_is_slot_complete(tvu->blockstore, shred.slot);

            pthread_mutex_lock(&tvu->slots_lock);
            tracker = find_slot(tvu, shred.slot);
            if (tracker) {
                if (inserted) {
                    tracker->last_inserted_ns = entry.received_ns;
                }
                if (tracker->status == SOL_SLOT_STATUS_RECEIVING &&
                    (slot_complete || (fast_mode && tracker->shreds_received > 0))) {
                    bool promote = true;
                    if (slot_complete && tvu->replay) {
                        sol_slot_t cursor = sol_replay_highest_replayed_slot(tvu->replay);
                        if (cursor != 0 &&
                            shred.slot <= cursor &&
                            sol_replay_is_replayed(tvu->replay, shred.slot)) {
                            /* Slot already replayed and no new complete variants
                             * exist; don't waste replay bandwidth. */
                            tracker->status = SOL_SLOT_STATUS_REPLAYED;
                            tracker->replay_retry_requested = false;
                            tracker->waiting_parent_slot = 0;
                            promote = false;
                        }
                    }
                    if (slot_complete &&
                        tracker->last_replay_result == SOL_REPLAY_INCOMPLETE &&
                        tracker->last_replay_ns != 0 &&
                        tvu->blockstore) {
                        /* Prevent tight replay loops on a "complete" slot that
                         * replay already found incomplete (e.g. missing ticks).
                         * Only requeue once a new complete block variant appears
                         * OR new non-duplicate shreds were inserted since the last
                         * replay attempt (e.g. repaired ticks). */
                        uint32_t complete_variants =
                            tvu_count_complete_variants(tvu->blockstore, shred.slot);
                        if (complete_variants <= tracker->last_replay_complete_variants &&
                            (tracker->last_inserted_ns == 0 ||
                             tracker->last_inserted_ns <= tracker->last_replay_ns)) {
                            promote = false;
                        }
                    }

                        if (promote) {
                            tracker->status = SOL_SLOT_STATUS_COMPLETE;
                            if (slot_complete) {
                                __atomic_fetch_add(&tvu->stats.blocks_completed, 1, __ATOMIC_RELAXED);
                            sol_log_debug("Slot %lu complete", (unsigned long)shred.slot);
                        } else {
                            sol_log_debug("Fast replay: slot %lu queued with %u shreds",
                                          (unsigned long)shred.slot,
                                          (unsigned)tracker->shreds_received);
                        }
                    }
                } else if (slot_complete && tracker->status == SOL_SLOT_STATUS_REPLAYING) {
                    /* Request a replay retry only if a new complete block variant
                     * arrives while we're replaying. This avoids tight replay loops
                     * caused by duplicate shred reception. */
                    if (tvu->blockstore) {
                        uint32_t complete_variants =
                            tvu_count_complete_variants(tvu->blockstore, shred.slot);
                        if (complete_variants > tracker->last_replay_complete_variants) {
                            tracker->replay_retry_requested = true;
                        }
                    } else {
                        tracker->replay_retry_requested = true;
                    }
                } else if (slot_complete && tracker->status == SOL_SLOT_STATUS_REPLAYED) {
                    /* Re-queue replay if a new complete variant arrives later. */
                    if (tvu->replay && !sol_replay_is_replayed(tvu->replay, shred.slot)) {
                        tracker->status = SOL_SLOT_STATUS_COMPLETE;
                        tracker->replay_retry_requested = false;
                        tracker->waiting_parent_slot = 0;
                    }
                } else if (slot_complete && tracker->status == SOL_SLOT_STATUS_DEAD) {
                    /* Allow dead slots to be retried when new variants appear. */
                    if (tvu->replay && !sol_replay_is_dead(tvu->replay, shred.slot)) {
                        tracker->status = SOL_SLOT_STATUS_COMPLETE;
                        tracker->replay_retry_requested = false;
                        tracker->waiting_parent_slot = 0;
                    }
                }
            }
            pthread_mutex_unlock(&tvu->slots_lock);
        }
    }

    return NULL;
}

/*
 * Replay thread
 */
static void*
replay_thread_func(void* arg) {
    sol_tvu_t* tvu = (sol_tvu_t*)arg;
    const bool log_slots = tvu_log_replayed_slots();

    /* Report replay performance periodically without emitting per-slot logs by
     * default (log I/O can dominate replay time on fast machines). */
    uint64_t report_last_ns = now_ns();
    uint64_t report_sum_ns = 0;
    uint64_t report_count = 0;
    double   report_last_ms = 0.0;
    sol_slot_t report_last_slot = 0;
    uint32_t report_last_txs = 0;
    uint32_t report_last_entries = 0;

    while (tvu->running) {
        /* Find slots ready for replay */
        sol_slot_t replay_slot = 0;
        bool found = false;
        bool fast_mode = tvu_fast_mode();
        enum { SOL_TVU_RESTART_PROBE_PER_LOOP = 16 };
        sol_slot_t probe_slots[SOL_TVU_RESTART_PROBE_PER_LOOP];
        size_t probe_count = 0;

        pthread_mutex_lock(&tvu->slots_lock);
        /* Promote any slots waiting on a now-replayed parent. */
        if (tvu->replay) {
            for (size_t i = 0; i < tvu->num_slots; i++) {
                if (tvu->slots[i].status != SOL_SLOT_STATUS_WAITING_PARENT) {
                    continue;
                }
                sol_slot_t parent_slot = tvu->slots[i].waiting_parent_slot;
                if (parent_slot == 0 || sol_replay_has_frozen_bank(tvu->replay, parent_slot)) {
                    tvu->slots[i].status = SOL_SLOT_STATUS_COMPLETE;
                    tvu->slots[i].waiting_parent_slot = 0;
                }
            }
        }

        size_t best_idx = SIZE_MAX;
        for (size_t i = 0; i < tvu->num_slots; i++) {
            if (tvu->slots[i].status != SOL_SLOT_STATUS_COMPLETE) {
                continue;
            }
            if (best_idx == SIZE_MAX || tvu->slots[i].slot < tvu->slots[best_idx].slot) {
                best_idx = i;
            }
        }
        if (best_idx != SIZE_MAX) {
            replay_slot = tvu->slots[best_idx].slot;
            /* Snapshot complete-variant count at replay start so we can
             * distinguish "new variants arrived" from pure duplicates. */
            if (tvu->blockstore) {
                tvu->slots[best_idx].last_replay_complete_variants =
                    tvu_count_complete_variants(tvu->blockstore, replay_slot);
            }
            tvu->slots[best_idx].status = SOL_SLOT_STATUS_REPLAYING;
            found = true;
        } else {
            /* Best-effort restart probe: identify a small number of RECEIVING
             * slots with no shreds observed in this run and check persisted
             * blockstore state outside the slot lock. */
            if (tvu->blockstore) {
                for (size_t i = 0; i < tvu->num_slots && probe_count < SOL_TVU_RESTART_PROBE_PER_LOOP; i++) {
                    slot_tracker_t* t = &tvu->slots[i];
                    if (t->status != SOL_SLOT_STATUS_RECEIVING) continue;
                    if (t->slot == 0) continue;
                    if (t->shreds_received != 0u) continue;
                    if (t->restart_probed) continue;
                    t->restart_probed = true;
                    probe_slots[probe_count++] = t->slot;
                }
            }
        }
        pthread_mutex_unlock(&tvu->slots_lock);

        if (!found) {
            if (tvu->blockstore && probe_count > 0) {
                bool probed_complete[SOL_TVU_RESTART_PROBE_PER_LOOP];
                bool probed_anydata[SOL_TVU_RESTART_PROBE_PER_LOOP];

                for (size_t i = 0; i < probe_count; i++) {
                    probed_complete[i] = sol_blockstore_is_slot_complete(tvu->blockstore, probe_slots[i]);
                    probed_anydata[i] = false;
                    if (!probed_complete[i] && fast_mode) {
                        sol_slot_meta_t meta;
                        if (sol_blockstore_get_slot_meta(tvu->blockstore, probe_slots[i], &meta) == SOL_OK &&
                            meta.received_data > 0) {
                            probed_anydata[i] = true;
                        }
                    }
                }

                pthread_mutex_lock(&tvu->slots_lock);
                for (size_t i = 0; i < probe_count; i++) {
                    sol_slot_t s = probe_slots[i];
                    slot_tracker_t* t = find_slot(tvu, s);
                    if (!t) continue;
                    if (t->status != SOL_SLOT_STATUS_RECEIVING) continue;
                    if (t->shreds_received != 0u) continue; /* new shreds arrived since selection */

                    const bool can_queue = probed_complete[i] || (fast_mode && probed_anydata[i]);
                    if (!can_queue) continue;

                    if (!probed_complete[i] && fast_mode) {
                        /* Don't tight-loop replay on fast-mode persisted partial slots unless
                         * new shreds were observed since the last replay attempt. */
                        if (t->last_replay_result == SOL_REPLAY_INCOMPLETE &&
                            t->last_replay_ns != 0 &&
                            (t->last_received_ns == 0 ||
                             t->last_received_ns <= t->last_replay_ns)) {
                            continue;
                        }
                    } else if (probed_complete[i] &&
                               t->last_replay_result == SOL_REPLAY_INCOMPLETE &&
                               t->last_replay_ns != 0) {
                        /* Avoid tight replay loops on persisted complete slots that still
                         * fail replay validation (e.g. missing ticks). */
                        uint32_t complete_variants = tvu_count_complete_variants(tvu->blockstore, s);
                        if (complete_variants <= t->last_replay_complete_variants &&
                            (t->last_inserted_ns == 0 ||
                             t->last_inserted_ns <= t->last_replay_ns)) {
                            continue;
                        }
                    }

                    if (tvu->replay && sol_replay_is_replayed(tvu->replay, s)) {
                        t->status = SOL_SLOT_STATUS_REPLAYED;
                        t->replay_retry_requested = false;
                        t->waiting_parent_slot = 0;
                        continue;
                    }

                    t->status = SOL_SLOT_STATUS_COMPLETE;
                    if (probed_complete[i]) {
                        __atomic_fetch_add(&tvu->stats.blocks_completed, 1, __ATOMIC_RELAXED);
                    }
                }
                pthread_mutex_unlock(&tvu->slots_lock);

                /* We may have queued slots as COMPLETE; loop again without sleeping. */
                continue;
            }

            struct timespec ts = {0, 1000000};  /* 1ms */
            nanosleep(&ts, NULL);
            continue;
        }

        /* Replay the slot */
        sol_hash_t blockhash = {0};
        sol_replay_result_t replay_result = SOL_REPLAY_DEAD;
        bool ok = false;
        sol_replay_slot_info_t replay_info;
        memset(&replay_info, 0, sizeof(replay_info));

        if (tvu->replay) {
            replay_result = sol_replay_slot(tvu->replay, replay_slot, &replay_info);
            ok = (replay_result == SOL_REPLAY_SUCCESS || replay_result == SOL_REPLAY_DUPLICATE);

            if (replay_result == SOL_REPLAY_SUCCESS) {
                __atomic_fetch_add(&tvu->stats.blocks_replayed, 1, __ATOMIC_RELAXED);
                double ms = (double)replay_info.replay_time_ns / 1000000.0;
                report_sum_ns += replay_info.replay_time_ns;
                report_count++;
                report_last_ms = ms;
                report_last_slot = replay_slot;
                report_last_txs = replay_info.num_transactions;
                report_last_entries = replay_info.num_entries;

                if (log_slots) {
                    sol_log_info("Slot %lu replayed successfully (tx=%u entries=%u time=%.2fms)",
                                 (unsigned long)replay_slot,
                                 (unsigned)replay_info.num_transactions,
                                 (unsigned)replay_info.num_entries,
                                 ms);
                } else {
                    uint64_t now = now_ns();
                    if (report_count > 0 && (now - report_last_ns) >= 1000000000ULL) {
                        double avg_ms = ((double)report_sum_ns / (double)report_count) / 1000000.0;
                        sol_log_info("Replay: last_slot=%lu slots=%lu avg=%.2fms last=%.2fms (tx=%u entries=%u)",
                                     (unsigned long)report_last_slot,
                                     (unsigned long)report_count,
                                     avg_ms,
                                     report_last_ms,
                                     (unsigned)report_last_txs,
                                     (unsigned)report_last_entries);
                        report_last_ns = now;
                        report_sum_ns = 0;
                        report_count = 0;
                    }
                }
            } else if (replay_result == SOL_REPLAY_DUPLICATE) {
                sol_log_debug("Slot %lu replay already complete", (unsigned long)replay_slot);
            } else if (replay_result == SOL_REPLAY_DEAD) {
                __atomic_fetch_add(&tvu->stats.blocks_failed, 1, __ATOMIC_RELAXED);
                sol_log_warn("Slot %lu replay failed: %d", (unsigned long)replay_slot, replay_result);
            } else if (replay_result == SOL_REPLAY_PARENT_MISSING) {
                sol_log_debug("Slot %lu waiting for parent %lu",
                              (unsigned long)replay_slot,
                              (unsigned long)replay_info.parent_slot);
            }
        }

        /* Update slot status */
        pthread_mutex_lock(&tvu->slots_lock);
        slot_tracker_t* tracker = find_slot(tvu, replay_slot);
        uint64_t prev_replay_ns = tracker ? tracker->last_replay_ns : 0;
        if (tracker) {
            bool retry_requested = tracker->replay_retry_requested;
            tracker->replay_retry_requested = false;
            tracker->waiting_parent_slot = 0;
            tracker->last_replay_result = replay_result;
            tracker->last_replay_ns = now_ns();

            if (replay_result == SOL_REPLAY_PARENT_MISSING) {
                tracker->status = SOL_SLOT_STATUS_WAITING_PARENT;
                tracker->waiting_parent_slot = replay_info.parent_slot;
            } else if (ok) {
                if (retry_requested &&
                    tvu->replay &&
                    !sol_replay_is_replayed(tvu->replay, replay_slot) &&
                    tvu->blockstore &&
                    sol_blockstore_is_slot_complete(tvu->blockstore, replay_slot)) {
                    tracker->status = SOL_SLOT_STATUS_COMPLETE;
                } else {
                    tracker->status = SOL_SLOT_STATUS_REPLAYED;
                }
            } else {
                if (retry_requested &&
                    tvu->replay &&
                    !sol_replay_is_dead(tvu->replay, replay_slot) &&
                    tvu->blockstore &&
                    sol_blockstore_is_slot_complete(tvu->blockstore, replay_slot)) {
                    tracker->status = SOL_SLOT_STATUS_COMPLETE;
                } else if (replay_result == SOL_REPLAY_INCOMPLETE) {
                    tracker->status = SOL_SLOT_STATUS_RECEIVING;
                } else {
                    tracker->status = SOL_SLOT_STATUS_DEAD;
                }
            }
        }
        pthread_mutex_unlock(&tvu->slots_lock);

        if (replay_result == SOL_REPLAY_INCOMPLETE) {
            uint64_t now = now_ns();
            if (prev_replay_ns == 0 || (now - prev_replay_ns) >= 1000000000ULL) {
                sol_log_debug("Slot %lu replay incomplete (throttled)", (unsigned long)replay_slot);
            }
        } else if (replay_result != SOL_REPLAY_SUCCESS &&
                   replay_result != SOL_REPLAY_DUPLICATE &&
                   replay_result != SOL_REPLAY_DEAD &&
                   replay_result != SOL_REPLAY_PARENT_MISSING) {
            sol_log_warn("Slot %lu replay returned: %d", (unsigned long)replay_slot, replay_result);
        }

        /* Invoke callback */
        if (tvu->block_callback) {
            tvu->block_callback(tvu->block_callback_ctx, replay_slot, &blockhash, ok);
        }
    }

    return NULL;
}

/*
 * Repair thread
 */
static void*
repair_thread_func(void* arg) {
    tvu_repair_thread_ctx_t* ctx = (tvu_repair_thread_ctx_t*)arg;
    sol_tvu_t* tvu = ctx ? ctx->tvu : NULL;
    uint32_t thread_idx = ctx ? ctx->thread_idx : 0;
    if (!tvu) {
        return NULL;
    }
    uint64_t last_primary_diag_ns = 0;
    uint64_t last_thread_diag_ns = 0;

    while (tvu->running) {
        struct timespec ts = {0, 1000000};  /* 1ms */
        nanosleep(&ts, NULL);

        if (!tvu->config.enable_repair || !tvu->repair) {
            continue;
        }

        uint64_t now = now_ns();
        size_t pending = sol_repair_pending_count(tvu->repair);
        size_t max_pending = sol_repair_max_pending(tvu->repair);
        size_t headroom = (max_pending > pending) ? (max_pending - pending) : 0;
        if (headroom == 0) {
            continue;
        }
        uint32_t thread_count = (uint32_t)tvu->repair_thread_count;
        if (thread_count == 0) {
            thread_count = 1;
        }

	        /* Proactively backfill a window of slots ahead of the highest replayed
	         * slot. This is critical for bootstrap/catchup, where turbine may not
	         * deliver historical shreds. */
	        sol_slot_t replay_cursor = 0;
	        sol_slot_t catchup_start = 0;
	        sol_slot_t catchup_end = 0;
	        enum {
	            /* Only repair within a bounded window ahead of replay. Repairing
	             * far-ahead slots creates huge pending sets and increases tail
	             * latency for the critical next slot. */
	            SOL_TVU_CATCHUP_WINDOW_SLOTS = 512,
	            /* When the primary (next) slot is incomplete, shrink the repair
	             * window further to keep requests tightly focused. */
	            SOL_TVU_PRIMARY_REPAIR_WINDOW_SLOTS = 128,
	        };

	        if (tvu->replay) {
	            replay_cursor = sol_replay_highest_replayed_slot(tvu->replay);
	            catchup_start = replay_cursor + 1;
	            catchup_end = replay_cursor + (sol_slot_t)SOL_TVU_CATCHUP_WINDOW_SLOTS;
        }

	        sol_slot_t primary_slot = catchup_start;
	        bool focus_primary = false;
	        if (primary_slot != 0 && tvu->blockstore) {
	            /* When we're behind, focus repair bandwidth on the next slot to be
	             * replayed. Repairing far-ahead slots doesn't help until the replay
	             * cursor advances. */
	            focus_primary = !sol_blockstore_is_slot_complete(tvu->blockstore, primary_slot);
	            if (focus_primary && catchup_end != 0) {
	                sol_slot_t end = primary_slot + (sol_slot_t)SOL_TVU_PRIMARY_REPAIR_WINDOW_SLOTS;
	                if (end >= primary_slot && end < catchup_end) {
	                    catchup_end = end;
	                }
	            }
	        }

        typedef struct {
            sol_repair_type_t type;
            sol_slot_t        slot;
            uint64_t          shred_index;
            uint32_t          fanout; /* Best-effort hedged repair requests (SHRED/HIGHEST). */
        } repair_action_t;

	        enum {
	            SOL_TVU_MAX_REPAIR_ACTIONS = 16384,
	            SOL_TVU_MAX_MISSING_SHREDS = 8192,
	            SOL_TVU_CATCHUP_MIN_INTERVAL_MS = 2,
	            SOL_TVU_INITIAL_SHRED_BURST_PRIMARY = 512,
	            SOL_TVU_INITIAL_SHRED_BURST_OTHER = 128,
	            /* When the primary slot is incomplete, we still want to prefetch a
	             * small lookahead window so replay doesn't immediately stall on the
	             * next slot.  HighestShred is cheap and deduped by the repair service. */
	            SOL_TVU_PRIMARY_PREFETCH_SLOTS = 8,
	        };

        repair_action_t actions[SOL_TVU_MAX_REPAIR_ACTIONS];
        size_t action_count = 0;
        size_t action_budget = headroom;
        if (thread_count > 1) {
            if (focus_primary && primary_slot != 0) {
                /* Prioritize repairing the next replay slot, but keep a small
                 * portion of bandwidth for prefetching ahead so replay doesn't
                 * stall between slots. */
                size_t primary_budget = (headroom * 3u) / 4u;
                if (primary_budget == 0u) primary_budget = 1u;
                if (primary_budget > headroom) primary_budget = headroom;

                size_t secondary_budget = headroom - primary_budget;

                if (thread_idx == 0) {
                    action_budget = primary_budget;
                } else {
                    uint32_t sec_threads = thread_count - 1u;
                    if (sec_threads == 0u || secondary_budget == 0u) {
                        action_budget = 0;
                    } else {
                        size_t base = secondary_budget / (size_t)sec_threads;
                        size_t rem = secondary_budget % (size_t)sec_threads;
                        uint32_t sec_idx = thread_idx - 1u;
                        action_budget = base + (sec_idx < rem ? 1u : 0u);
                    }
                }
            } else {
                size_t base = headroom / thread_count;
                size_t rem = headroom % thread_count;
                action_budget = base + (thread_idx < rem ? 1u : 0u);
            }
        }
        if (action_budget > SOL_TVU_MAX_REPAIR_ACTIONS) {
            action_budget = SOL_TVU_MAX_REPAIR_ACTIONS;
        }
        if (action_budget == 0) {
            continue;
        }

        pthread_mutex_lock(&tvu->slots_lock);

        /* Ensure slot trackers exist for upcoming catchup slots so the repair
         * loop can drive forward progress even if no shreds have arrived yet. */
        if (thread_idx == 0 && tvu->replay && tvu->num_slots < MAX_TRACKED_SLOTS) {
            sol_slot_t start = replay_cursor + 1;
            sol_slot_t end = catchup_end + 1;
            for (sol_slot_t slot = start;
                 slot != 0 && slot < end && tvu->num_slots < MAX_TRACKED_SLOTS;
                 slot++) {
                (void)find_or_create_slot(tvu, slot);
            }
        } else if (focus_primary && primary_slot != 0) {
            (void)find_or_create_slot(tvu, primary_slot);
        }

        for (size_t i = 0; i < tvu->num_slots && action_count < action_budget; i++) {
            slot_tracker_t* tracker = &tvu->slots[i];
            if (!tracker || tracker->slot == 0) {
                continue;
            }
            bool is_primary_slot = (primary_slot != 0 && tracker->slot == primary_slot);
            if (primary_slot != 0) {
                if (is_primary_slot) {
                    if (thread_idx != 0) {
                        continue;
                    }
                } else {
                    if (thread_idx == 0) {
                        continue;
                    }
                    uint32_t sec_threads = thread_count > 1u ? (thread_count - 1u) : 0u;
                    if (sec_threads == 0u) {
                        continue;
                    }
                    if ((i % sec_threads) != (thread_idx - 1u)) {
                        continue;
                    }
                }
            } else {
                if ((i % thread_count) != thread_idx) {
                    continue;
                }
            }

            uint64_t since_req_ms = tracker->last_repair_request_ns
                                        ? (now - tracker->last_repair_request_ns) / 1000000
                                        : UINT64_MAX;

            uint64_t min_interval_ms = tvu->config.repair_timeout_ms;
            bool is_catchup_slot = (tvu->replay &&
                                    tracker->slot != 0 &&
                                    tracker->slot >= catchup_start &&
                                    tracker->slot <= catchup_end);
            if (is_catchup_slot && SOL_TVU_CATCHUP_MIN_INTERVAL_MS < min_interval_ms) {
                min_interval_ms = SOL_TVU_CATCHUP_MIN_INTERVAL_MS;
            }

            if (!(focus_primary && is_primary_slot) && since_req_ms < min_interval_ms) {
                continue;
            }

            if (tracker->status == SOL_SLOT_STATUS_WAITING_PARENT &&
                tracker->waiting_parent_slot != 0) {
                /* Backfill missing parents so replay can advance. */
                (void)find_or_create_slot(tvu, tracker->waiting_parent_slot);
                tracker->last_repair_request_ns = now;

                actions[action_count++] = (repair_action_t){
                    .type = SOL_REPAIR_HIGHEST_SHRED,
                    .slot = tracker->waiting_parent_slot,
                    .shred_index = 0,
                    .fanout = 1,
                };
                continue;
            }

	            if (tracker->status == SOL_SLOT_STATUS_DEAD &&
	                is_catchup_slot &&
	                tvu->replay &&
	                sol_replay_is_dead(tvu->replay, tracker->slot)) {
                /* The slot replayed as DEAD, but a new duplicate variant could
                 * still arrive later (especially during bootstrap). Continue
                 * to solicit additional shreds so blockstore can surface new
                 * variants and replay can retry. */
                tracker->last_repair_request_ns = now;

                sol_slot_meta_t meta;
                uint32_t first_idx = 0;
                uint32_t last_idx = 0;
                bool have_meta = tvu->blockstore &&
                                 sol_blockstore_get_slot_meta(tvu->blockstore, tracker->slot, &meta) == SOL_OK;
                if (have_meta) {
                    first_idx = meta.first_shred_index;
                    last_idx = meta.last_shred_index;
                }

                /* Request a couple of deterministic indices to encourage peers
                 * to return any conflicting shreds we might have missed. */
                actions[action_count++] = (repair_action_t){
                    .type = SOL_REPAIR_SHRED,
                    .slot = tracker->slot,
                    .shred_index = first_idx,
                    .fanout = 1,
                };

                if (action_count < action_budget &&
                    have_meta &&
                    last_idx != first_idx) {
                    actions[action_count++] = (repair_action_t){
                        .type = SOL_REPAIR_SHRED,
                        .slot = tracker->slot,
                        .shred_index = last_idx,
                        .fanout = 1,
                    };
                }

                if (action_count < action_budget) {
                    actions[action_count++] = (repair_action_t){
                        .type = SOL_REPAIR_HIGHEST_SHRED,
                        .slot = tracker->slot,
                        .shred_index = 0,
                        .fanout = 1,
                    };
                }

	                continue;
	            }

	            /* Only drive repair for the active catchup window (plus explicit
	             * waiting-parent backfill above). Repairing far-ahead slots is
	             * counterproductive when the replay cursor is blocked by a small
	             * number of missing shreds. */
	            if (!is_catchup_slot) {
	                continue;
	            }

	            if (tracker->status != SOL_SLOT_STATUS_RECEIVING) {
	                continue;
	            }

            tracker->last_repair_request_ns = now;

            /* If we haven't received anything yet for a catchup slot, kick off
             * initial requests immediately instead of waiting for "idle".
             *
             * Note: shreds can arrive via repair/turbine even if this slot
             * tracker was evicted/recreated, so use blockstore metadata as
             * the source of truth instead of relying on tracker counters. */
            uint32_t observed_rx = tracker->shreds_received;
            if (observed_rx == 0 && is_catchup_slot && tvu->blockstore) {
                sol_slot_meta_t meta;
                if (sol_blockstore_get_slot_meta(tvu->blockstore, tracker->slot, &meta) == SOL_OK) {
                    observed_rx = meta.received_data;
                }
            }

            if (observed_rx == 0 && is_catchup_slot) {
                uint64_t burst = (tracker->slot == catchup_start)
                                     ? (uint64_t)SOL_TVU_INITIAL_SHRED_BURST_PRIMARY
                                     : (uint64_t)SOL_TVU_INITIAL_SHRED_BURST_OTHER;
	                if (tracker->slot == primary_slot && (last_primary_diag_ns == 0 || (now - last_primary_diag_ns) >= 1000000000ULL)) {
	                    sol_log_debug("TVU repair primary slot=%lu initial_burst=%lu pending=%zu/%zu",
	                                  (unsigned long)tracker->slot,
	                                  (unsigned long)burst,
	                                  pending,
	                                  max_pending);
	                    last_primary_diag_ns = now;
	                }
		                for (uint64_t idx = 0;
		                     idx < burst && action_count < action_budget;
		                     idx++) {
			                    actions[action_count++] = (repair_action_t){
			                        .type = SOL_REPAIR_SHRED,
			                        .slot = tracker->slot,
			                        .shred_index = idx,
		                        .fanout = 1,
		                    };
		                }
	                if (action_count < action_budget &&
	                    (!focus_primary || !is_primary_slot || thread_idx == 0)) {
		                    actions[action_count++] = (repair_action_t){
		                        .type = SOL_REPAIR_HIGHEST_SHRED,
		                        .slot = tracker->slot,
		                        .shred_index = 0,
		                        .fanout = 1,
		                    };
		                }
                continue;
            }

            if (!is_catchup_slot) {
                uint64_t last_rx = tracker->last_received_ns ? tracker->last_received_ns : tracker->first_received_ns;
                uint64_t idle_ms = last_rx ? (now - last_rx) / 1000000 : UINT64_MAX;
                if (idle_ms <= tvu->config.repair_timeout_ms) {
                    continue;
                }
            }

            uint32_t missing[SOL_TVU_MAX_MISSING_SHREDS];
            size_t missing_count = 0;
            if (tvu->blockstore) {
                missing_count = sol_blockstore_get_missing_shreds(
                    tvu->blockstore, tracker->slot, missing, SOL_TVU_MAX_MISSING_SHREDS);
            }

            if (missing_count == 0 && is_catchup_slot && tvu->blockstore) {
                /* When using a persistent blockstore, the slot might exist
                 * only in RocksDB (no in-memory bitmap). Fall back to
                 * scanning indices via `has_shred` to drive catchup forward
                 * instead of getting stuck on HighestShred. */
                sol_slot_meta_t meta;
                if (sol_blockstore_get_slot_meta(tvu->blockstore, tracker->slot, &meta) == SOL_OK) {
                    uint32_t last = meta.last_shred_index;
                    if (!meta.is_full && last == 0 && meta.received_data > 0) {
                        last = meta.received_data;
                    }
                    if (tvu->config.max_shreds_per_slot > 0 &&
                        last >= tvu->config.max_shreds_per_slot) {
                        last = tvu->config.max_shreds_per_slot - 1;
                    }

                    if (meta.received_data > 0 && (uint64_t)meta.received_data < ((uint64_t)last + 1ULL)) {
                        for (uint32_t idx = 0;
                             idx <= last && missing_count < SOL_TVU_MAX_MISSING_SHREDS;
                             idx++) {
                            if (!sol_blockstore_has_shred(tvu->blockstore, tracker->slot, idx, true)) {
                                missing[missing_count++] = idx;
                            }
                        }
                    }
                }
            }

            if (tracker->slot == primary_slot &&
                (last_primary_diag_ns == 0 || (now - last_primary_diag_ns) >= 1000000000ULL)) {
                sol_slot_meta_t meta;
                bool have_meta = tvu->blockstore &&
                                 sol_blockstore_get_slot_meta(tvu->blockstore, tracker->slot, &meta) == SOL_OK;
                sol_log_debug("TVU repair primary slot=%lu meta=%s rx=%u last=%u full=%s missing=%zu pending=%zu/%zu budget=%zu",
                              (unsigned long)tracker->slot,
                              have_meta ? "yes" : "no",
                              have_meta ? (unsigned)meta.received_data : 0u,
                              have_meta ? (unsigned)meta.last_shred_index : 0u,
                              have_meta ? (meta.is_full ? "yes" : "no") : "-",
                              missing_count,
                              pending,
                              max_pending,
                              action_budget);
                last_primary_diag_ns = now;
            }

	            if (missing_count == 0) {
	                uint32_t highest_fanout = 1;
	                if (focus_primary && is_primary_slot) {
	                    /* When the critical slot is otherwise "full", tail latency often
	                     * comes down to a single HighestWindowIndex response. */
	                    highest_fanout = 8;
	                }

                bool request_duplicates = false;
                sol_slot_meta_t meta;
                uint32_t first_idx = 0;
                uint32_t last_idx = 0;
                bool have_meta = false;

                if (tvu->blockstore &&
                    sol_blockstore_get_slot_meta(tvu->blockstore, tracker->slot, &meta) == SOL_OK) {
                    have_meta = true;
                    first_idx = meta.first_shred_index;
                    last_idx = meta.last_shred_index;
                }

                if (is_catchup_slot &&
                    tracker->last_replay_ns != 0 &&
                    tracker->last_replay_result == SOL_REPLAY_INCOMPLETE &&
                    tvu->blockstore &&
                    sol_blockstore_is_slot_complete(tvu->blockstore, tracker->slot)) {
                    request_duplicates = true;
                }

                /* Use last_shred_index+1 as the starting index for
                 * HighestWindowIndex so the peer returns a shred we
                 * don't already have (the actual last shred of the slot).
                 * With shred_index=0 the peer just returns the highest
                 * shred which we may already have, causing endless dups. */
                uint64_t highest_start = 0;
                if (have_meta) {
                    highest_start = (uint64_t)last_idx + 1;
                }

                if (have_meta &&
                    !meta.is_full &&
                    meta.received_data > 0 &&
                    action_count < action_budget) {
                    uint32_t tail_fanout = 1;
	                    if (is_primary_slot && focus_primary) {
	                        /* If we're stuck behind the head, the critical next slot
	                         * might be missing only the LAST_IN_SLOT variant. Hedge
	                         * tail refreshes across a few peers to avoid multi-second
	                         * stalls. */
	                        tail_fanout = 8;
	                    } else if (is_catchup_slot) {
	                        tail_fanout = 4;
	                    }

                    /* When meta.is_full is false but we have contiguous shreds,
                     * we might be missing the terminal LAST_IN_SLOT variant at
                     * the last index we already have. Explicitly refresh the
                     * tail indices to solicit duplicate/alternative shreds. */
                    uint32_t tail = last_idx;
                    if (!meta.is_full && tail == 0 && meta.received_data > 0) {
                        tail = meta.received_data;
                    }

                    uint32_t start = tail;
                    uint32_t end = tail;
                    if (tail > 0) {
                        start = tail - 1;
                    }

                    for (uint32_t idx = start; idx <= end && action_count < action_budget; idx++) {
                        actions[action_count++] = (repair_action_t){
                            .type = SOL_REPAIR_SHRED,
                            .slot = tracker->slot,
                            .shred_index = idx,
                            .fanout = tail_fanout,
                        };
                    }
                }

                if (request_duplicates) {
		                    actions[action_count++] = (repair_action_t){
		                        .type = SOL_REPAIR_SHRED,
		                        .slot = tracker->slot,
		                        .shred_index = first_idx,
	                        .fanout = 1,
	                    };
                    if (action_count < action_budget &&
                        have_meta &&
                        last_idx != first_idx) {
	                        actions[action_count++] = (repair_action_t){
	                            .type = SOL_REPAIR_SHRED,
	                            .slot = tracker->slot,
	                            .shred_index = last_idx,
	                            .fanout = 1,
	                        };
	                    }
                    if (action_count < action_budget) {
		                        actions[action_count++] = (repair_action_t){
		                            .type = SOL_REPAIR_HIGHEST_SHRED,
		                            .slot = tracker->slot,
		                            .shred_index = highest_start,
		                            .fanout = highest_fanout,
		                        };
		                    }
		                } else {
		                    actions[action_count++] = (repair_action_t){
		                        .type = SOL_REPAIR_HIGHEST_SHRED,
		                        .slot = tracker->slot,
		                        .shred_index = highest_start,
		                        .fanout = highest_fanout,
		                    };
		                }
            } else {
                bool request_highest = false;
                bool allow_highest = true;
                uint64_t highest_idx = 0;
	                if (is_catchup_slot && tvu->blockstore) {
	                    sol_slot_meta_t meta;
	                    if (sol_blockstore_get_slot_meta(tvu->blockstore, tracker->slot, &meta) == SOL_OK) {
	                        if (!meta.is_full || is_primary_slot) {
	                            request_highest = true;
	                            highest_idx = (uint64_t)meta.last_shred_index + 1;
	                            if (focus_primary && is_primary_slot && thread_idx != 0) {
	                                allow_highest = false;
	                            }
	                        }
	                    }
	                }

				                uint32_t shred_fanout = 1;
				                uint32_t highest_fanout = 1;
					                if (focus_primary && is_primary_slot) {
				                    /* Tail latency dominates catchup. When we're missing only
				                     * a handful of shreds on the primary slot, send hedged
				                     * requests to multiple peers to avoid multi-second stalls
				                     * waiting for a single slow/unhelpful repair peer. */
				                    /* Default to modest fanout even when many shreds are
				                     * missing; it doesn't increase pending slots (only
				                     * duplicates the wire request) and helps eliminate tail
				                     * stalls due to a single bad repair peer. */
					                    shred_fanout = 4;
					                    highest_fanout = 4;
						                    if (missing_count <= 16) {
						                        shred_fanout = 32;
						                        highest_fanout = 16;
		                    } else if (missing_count <= 64) {
		                        shred_fanout = 32;
		                        highest_fanout = 8;
		                    }
		                }

	                for (size_t m = 0; m < missing_count && action_count < action_budget; m++) {
	                    actions[action_count++] = (repair_action_t){
	                        .type = SOL_REPAIR_SHRED,
	                        .slot = tracker->slot,
		                        .shred_index = missing[m],
		                        .fanout = shred_fanout,
	                    };
	                }

	                /* FEC assist: when we're stuck missing a tiny number of data shreds on
	                 * the primary slot, proactively request a few additional indices that
	                 * are likely to return coding shreds for the same erasure batch.
	                 *
	                 * RepairProtocol::WindowIndex doesn't encode shred type; requesting
	                 * indices that are "present" as data can still yield coding shreds.
	                 * This helps unblock cases where a single missing data shred would be
	                 * recoverable via one coding shred, but turbine never delivered the
	                 * needed coding shred. */
	                if (focus_primary && is_primary_slot &&
	                    is_catchup_slot &&
	                    tvu->blockstore &&
	                    missing_count > 0 &&
	                    missing_count <= 16) {
	                    sol_slot_meta_t meta;
	                    if (sol_blockstore_get_slot_meta(tvu->blockstore, tracker->slot, &meta) == SOL_OK &&
	                        meta.is_full) {
	                        uint32_t last = meta.last_shred_index;
	                        uint32_t helper_fanout = shred_fanout;
	                        if (helper_fanout > 8u) helper_fanout = 8u;
	                        if (helper_fanout < 2u) helper_fanout = 2u;

	                        uint32_t extra[64];
	                        size_t extra_len = 0;

	                        for (size_t mi = 0; mi < missing_count && action_count < action_budget; mi++) {
	                            uint32_t idx = missing[mi];
	                            /* Heuristic: fec_set_index is typically aligned to 32 data shreds. */
	                            uint32_t base = idx & ~31u;
	                            uint32_t cand[4] = {base, base + 32u, base + 33u, base + 34u};

	                            for (size_t ci = 0; ci < (sizeof(cand) / sizeof(cand[0])) &&
	                                                action_count < action_budget;
	                                 ci++) {
	                                uint32_t h = cand[ci];
	                                if (h == idx) continue;
	                                /* Don't probe too far past the known tail. */
	                                if (h > last + 256u) continue;

	                                bool dup = false;
	                                for (size_t mj = 0; mj < missing_count; mj++) {
	                                    if (missing[mj] == h) {
	                                        dup = true;
	                                        break;
	                                    }
	                                }
	                                if (!dup) {
	                                    for (size_t ej = 0; ej < extra_len; ej++) {
	                                        if (extra[ej] == h) {
	                                            dup = true;
	                                            break;
	                                        }
	                                    }
	                                }
	                                if (dup) continue;

	                                if (extra_len < (sizeof(extra) / sizeof(extra[0]))) {
	                                    extra[extra_len++] = h;
	                                }

	                                actions[action_count++] = (repair_action_t){
	                                    .type = SOL_REPAIR_SHRED,
	                                    .slot = tracker->slot,
	                                    .shred_index = (uint64_t)h,
	                                    .fanout = helper_fanout,
	                                };
	                            }
	                        }
	                    }
	                }

	                if (request_highest && allow_highest && action_count < action_budget) {
	                    actions[action_count++] = (repair_action_t){
	                        .type = SOL_REPAIR_HIGHEST_SHRED,
	                        .slot = tracker->slot,
	                        .shred_index = highest_idx,
		                        .fanout = highest_fanout,
		                    };
		                }

	                        /* Primary-slot lookahead: request HighestShred for a small
	                         * window ahead so replay can keep running once this slot
	                         * completes (especially when a consecutive run of slots
	                         * are missing tail indices). */
	                        if (focus_primary && is_primary_slot && thread_idx == 0) {
	                            for (uint32_t di = 1;
	                                 di <= SOL_TVU_PRIMARY_PREFETCH_SLOTS && action_count < action_budget;
	                                 di++) {
	                                sol_slot_t next_slot = tracker->slot + (sol_slot_t)di;
	                                if (next_slot == 0 || (catchup_end != 0 && next_slot > catchup_end)) {
	                                    break;
	                                }
	                                actions[action_count++] = (repair_action_t){
	                                    .type = SOL_REPAIR_HIGHEST_SHRED,
	                                    .slot = next_slot,
	                                    .shred_index = 0,
	                                    .fanout = 1,
	                                };
	                            }
	                        }
			            }
	        }
        pthread_mutex_unlock(&tvu->slots_lock);

	        if (action_count == 0 && catchup_start && action_budget) {
	            actions[action_count++] = (repair_action_t){
	                .type = SOL_REPAIR_HIGHEST_SHRED,
	                .slot = catchup_start,
	                .shred_index = 0,
	                .fanout = 1,
	            };
	        }

        for (size_t i = 0; i < action_count; i++) {
            sol_err_t err = SOL_ERR_INVAL;
            const repair_action_t* a = &actions[i];
            switch (a->type) {
            case SOL_REPAIR_SHRED:
                if (a->fanout > 1) {
                    err = sol_repair_request_shred_fanout(tvu->repair,
                                                         a->slot,
                                                         a->shred_index,
                                                         true,
                                                         a->fanout);
                } else {
                    err = sol_repair_request_shred(tvu->repair, a->slot, a->shred_index, true);
                }
                break;
            case SOL_REPAIR_HIGHEST_SHRED:
                if (a->fanout > 1) {
                    err = sol_repair_request_highest_fanout(tvu->repair,
                                                            a->slot,
                                                            a->shred_index,
                                                            a->fanout);
                } else {
                    err = sol_repair_request_highest(tvu->repair, a->slot, a->shred_index);
                }
                break;
            case SOL_REPAIR_ORPHAN:
                err = sol_repair_request_orphan(tvu->repair, a->slot);
                break;
            case SOL_REPAIR_ANCESTOR_HASHES:
                err = sol_repair_request_ancestor_hashes(tvu->repair, a->slot);
                break;
            }

            if (err == SOL_OK) {
                __atomic_fetch_add(&tvu->stats.repairs_requested, 1, __ATOMIC_RELAXED);
            }
        }

        if (action_count > 0 &&
            (last_thread_diag_ns == 0 || (now - last_thread_diag_ns) >= 1000000000ULL)) {
            sol_log_debug("TVU repair thread=%u actions=%zu budget=%zu pending=%zu/%zu catchup=[%lu..%lu] primary=%lu",
                          (unsigned)thread_idx,
                          action_count,
                          action_budget,
                          pending,
                          max_pending,
                          (unsigned long)catchup_start,
                          (unsigned long)catchup_end,
                          (unsigned long)catchup_start);
            last_thread_diag_ns = now;
        }
    }

    return NULL;
}

/*
 * Create TVU
 */
sol_tvu_t*
sol_tvu_new(sol_blockstore_t* blockstore,
            sol_replay_t* replay,
            sol_turbine_t* turbine,
            sol_repair_t* repair,
            const sol_tvu_config_t* config) {

    sol_tvu_t* tvu = sol_calloc(1, sizeof(sol_tvu_t));
    if (!tvu) return NULL;

    if (config) {
        tvu->config = *config;
    } else {
        tvu->config = (sol_tvu_config_t)SOL_TVU_CONFIG_DEFAULT;
    }

    tvu->blockstore = blockstore;
    tvu->replay = replay;
    tvu->turbine = turbine;
    tvu->repair = repair;

    uint32_t verify_threads =
        tvu_pick_threads(tvu->config.shred_verify_threads, SOL_TVU_MAX_VERIFY_THREADS, 2);
    tvu->shred_verify_thread_count = verify_threads;
    tvu->shred_verify_threads = sol_calloc(verify_threads, sizeof(pthread_t));
    if (!tvu->shred_verify_threads) {
        sol_free(tvu);
        return NULL;
    }

    uint32_t replay_threads =
        tvu_pick_threads(tvu->config.replay_threads, SOL_TVU_MAX_REPLAY_THREADS, 2);
    tvu->replay_thread_count = replay_threads;
    tvu->replay_threads = sol_calloc(replay_threads, sizeof(pthread_t));
    if (!tvu->replay_threads) {
        sol_free(tvu->shred_verify_threads);
        sol_free(tvu);
        return NULL;
    }

    uint32_t repair_threads =
        tvu_pick_threads(tvu->config.repair_threads, SOL_TVU_MAX_REPAIR_THREADS, 2);
    tvu->repair_thread_count = repair_threads;
    tvu->repair_threads = sol_calloc(repair_threads, sizeof(pthread_t));
    tvu->repair_thread_ctx = sol_calloc(repair_threads, sizeof(tvu_repair_thread_ctx_t));
    if (!tvu->repair_threads || !tvu->repair_thread_ctx) {
        sol_free(tvu->repair_thread_ctx);
        sol_free(tvu->repair_threads);
        sol_free(tvu->replay_threads);
        sol_free(tvu->shred_verify_threads);
        sol_free(tvu);
        return NULL;
    }

    /* Initialize shred queue */
    tvu->shred_queue = sol_calloc(SHRED_QUEUE_SIZE, sizeof(shred_queue_entry_t));
    if (!tvu->shred_queue) {
        sol_free(tvu->repair_thread_ctx);
        sol_free(tvu->repair_threads);
        sol_free(tvu->replay_threads);
        sol_free(tvu->shred_verify_threads);
        sol_free(tvu);
        return NULL;
    }

    pthread_mutex_init(&tvu->shred_queue_lock, NULL);
    pthread_cond_init(&tvu->shred_queue_cond, NULL);
    pthread_mutex_init(&tvu->slots_lock, NULL);
    pthread_mutex_init(&tvu->lock, NULL);

    tvu->running = false;
    tvu->threads_started = false;

    /* Hash heads are -1 for empty (calloc gives 0). */
    for (size_t i = 0; i < SOL_TVU_SLOT_HASH_SIZE; i++) {
        tvu->slot_hash_heads[i] = -1;
    }

    return tvu;
}

/*
 * Destroy TVU
 */
void
sol_tvu_destroy(sol_tvu_t* tvu) {
    if (!tvu) return;

    sol_tvu_stop(tvu);

    sol_free(tvu->shred_queue);
    sol_free(tvu->shred_verify_threads);
    sol_free(tvu->replay_threads);
    sol_free(tvu->repair_thread_ctx);
    sol_free(tvu->repair_threads);

    pthread_mutex_destroy(&tvu->shred_queue_lock);
    pthread_cond_destroy(&tvu->shred_queue_cond);
    pthread_mutex_destroy(&tvu->slots_lock);
    pthread_mutex_destroy(&tvu->lock);

    sol_free(tvu);
}

/*
 * Start TVU
 */
sol_err_t
sol_tvu_start(sol_tvu_t* tvu) {
    if (!tvu) return SOL_ERR_INVAL;
    if (tvu->running) return SOL_OK;

    tvu->running = true;

    /* Start shred verification threads */
    size_t started = 0;
    for (size_t i = 0; i < tvu->shred_verify_thread_count; i++) {
        if (pthread_create(&tvu->shred_verify_threads[i], NULL, shred_verify_thread_func, tvu) != 0) {
            tvu->running = false;
            for (size_t j = 0; j < i; j++) {
                pthread_join(tvu->shred_verify_threads[j], NULL);
            }
            return SOL_ERR_IO;
        }
        started++;
    }

    /* Start replay threads */
    size_t replay_started = 0;
    for (size_t i = 0; i < tvu->replay_thread_count; i++) {
        if (pthread_create(&tvu->replay_threads[i], NULL, replay_thread_func, tvu) != 0) {
            tvu->running = false;
            for (size_t j = 0; j < started; j++) {
                pthread_join(tvu->shred_verify_threads[j], NULL);
            }
            for (size_t j = 0; j < replay_started; j++) {
                pthread_join(tvu->replay_threads[j], NULL);
            }
            return SOL_ERR_IO;
        }
        replay_started++;
    }

    /* Start repair threads */
    size_t repair_started = 0;
    for (size_t i = 0; i < tvu->repair_thread_count; i++) {
        tvu->repair_thread_ctx[i].tvu = tvu;
        tvu->repair_thread_ctx[i].thread_idx = (uint32_t)i;
        if (pthread_create(&tvu->repair_threads[i], NULL, repair_thread_func,
                           &tvu->repair_thread_ctx[i]) != 0) {
            tvu->running = false;
            for (size_t j = 0; j < started; j++) {
                pthread_join(tvu->shred_verify_threads[j], NULL);
            }
            for (size_t j = 0; j < replay_started; j++) {
                pthread_join(tvu->replay_threads[j], NULL);
            }
            for (size_t j = 0; j < repair_started; j++) {
                pthread_join(tvu->repair_threads[j], NULL);
            }
            return SOL_ERR_IO;
        }
        repair_started++;
    }

    tvu->threads_started = true;
    sol_log_info("TVU started (shred_verify_threads=%zu, replay_threads=%zu, repair_threads=%zu)",
                 tvu->shred_verify_thread_count,
                 tvu->replay_thread_count,
                 tvu->repair_thread_count);

    return SOL_OK;
}

/*
 * Stop TVU
 */
sol_err_t
sol_tvu_stop(sol_tvu_t* tvu) {
    if (!tvu) return SOL_ERR_INVAL;
    if (!tvu->running) return SOL_OK;

    tvu->running = false;

    /* Wake up blocked threads */
    pthread_cond_broadcast(&tvu->shred_queue_cond);

    if (tvu->threads_started) {
        for (size_t i = 0; i < tvu->shred_verify_thread_count; i++) {
            pthread_join(tvu->shred_verify_threads[i], NULL);
        }
        for (size_t i = 0; i < tvu->replay_thread_count; i++) {
            pthread_join(tvu->replay_threads[i], NULL);
        }
        for (size_t i = 0; i < tvu->repair_thread_count; i++) {
            pthread_join(tvu->repair_threads[i], NULL);
        }
        tvu->threads_started = false;
    }

    sol_log_info("TVU stopped");
    return SOL_OK;
}

/*
 * Check if running
 */
bool
sol_tvu_is_running(const sol_tvu_t* tvu) {
    if (!tvu) return false;
    return tvu->running;
}

/*
 * Process received shred
 */
sol_err_t
sol_tvu_process_shred(sol_tvu_t* tvu, const uint8_t* shred, size_t len) {
    if (!tvu || !shred || len == 0) return SOL_ERR_INVAL;

    if (len > sizeof(((shred_queue_entry_t*)0)->data)) {
        __atomic_fetch_add(&tvu->stats.shreds_failed, 1, __ATOMIC_RELAXED);
        return SOL_ERR_TOO_LARGE;
    }

    /* Backpressure: drop shreds that are far ahead of our replay cursor. */
    sol_slot_t max_ahead = tvu_max_shred_ahead_slots();
    if (max_ahead != 0 && tvu->replay && len >= SOL_SHRED_COMMON_HEADER_SIZE) {
        sol_slot_t cursor = sol_replay_highest_replayed_slot(tvu->replay);
        if (cursor != 0) {
            sol_slot_t slot = (sol_slot_t)sol_load_u64_le(shred + 65);
            if (slot > cursor && (slot - cursor) > max_ahead) {
                return SOL_OK;
            }
        }
    }

    __atomic_fetch_add(&tvu->stats.shreds_received, 1, __ATOMIC_RELAXED);

    if (!shred_queue_push(tvu, shred, len)) {
        __atomic_fetch_add(&tvu->stats.shreds_failed, 1, __ATOMIC_RELAXED);
        return SOL_ERR_FULL;
    }

    return SOL_OK;
}

sol_err_t
sol_tvu_process_shreds_batch(sol_tvu_t* tvu, const sol_udp_pkt_t* pkts, int count) {
    if (!tvu || !pkts || count <= 0) return SOL_ERR_INVAL;

    /* Backpressure: drop shreds that are far ahead of our replay cursor. */
    sol_slot_t max_ahead = tvu_max_shred_ahead_slots();
    sol_slot_t cursor = 0;
    if (max_ahead != 0 && tvu->replay) {
        cursor = sol_replay_highest_replayed_slot(tvu->replay);
    }

    size_t dropped_full = 0;
    size_t dropped_too_large = 0;
    uint64_t received_ns = now_ns();

    size_t pushed =
        shred_queue_push_batch(tvu,
                               pkts,
                               count,
                               cursor,
                               max_ahead,
                               received_ns,
                               &dropped_full,
                               &dropped_too_large);

    /* Match sol_tvu_process_shred() semantics:
     * - "received" counts shreds admitted past backpressure + size checks
     * - "failed" counts shreds dropped due to queue full or too large */
    size_t received = pushed + dropped_full;
    if (received > 0) {
        __atomic_fetch_add(&tvu->stats.shreds_received, received, __ATOMIC_RELAXED);
    }
    size_t failed = dropped_full + dropped_too_large;
    if (failed > 0) {
        __atomic_fetch_add(&tvu->stats.shreds_failed, failed, __ATOMIC_RELAXED);
    }

    return SOL_OK;
}

/*
 * Request repair for slot
 */
sol_err_t
sol_tvu_request_repair(sol_tvu_t* tvu, sol_slot_t slot) {
    if (!tvu) return SOL_ERR_INVAL;

    if (tvu->repair) {
        sol_repair_request_orphan(tvu->repair, slot);
        __atomic_fetch_add(&tvu->stats.repairs_requested, 1, __ATOMIC_RELAXED);
    }

    return SOL_OK;
}

/*
 * Set block completion callback
 */
void
sol_tvu_set_block_callback(sol_tvu_t* tvu,
                            sol_block_complete_callback_t callback,
                            void* ctx) {
    if (!tvu) return;

    pthread_mutex_lock(&tvu->lock);
    tvu->block_callback = callback;
    tvu->block_callback_ctx = ctx;
    pthread_mutex_unlock(&tvu->lock);
}

void
sol_tvu_set_leader_schedule(sol_tvu_t* tvu, sol_leader_schedule_t* schedule) {
    (void)sol_tvu_swap_leader_schedule(tvu, schedule);
}

sol_leader_schedule_t*
sol_tvu_swap_leader_schedule(sol_tvu_t* tvu, sol_leader_schedule_t* schedule) {
    if (!tvu) return NULL;

    pthread_mutex_lock(&tvu->lock);
    sol_leader_schedule_t* old = tvu->leader_schedule;
    tvu->leader_schedule = schedule;
    pthread_mutex_unlock(&tvu->lock);

    return old;
}

/*
 * Get statistics
 */
sol_tvu_stats_t
sol_tvu_stats(const sol_tvu_t* tvu) {
    sol_tvu_stats_t stats = {0};
    if (!tvu) return stats;

    stats.shreds_received = __atomic_load_n(&tvu->stats.shreds_received, __ATOMIC_RELAXED);
    stats.shreds_verified = __atomic_load_n(&tvu->stats.shreds_verified, __ATOMIC_RELAXED);
    stats.shreds_failed = __atomic_load_n(&tvu->stats.shreds_failed, __ATOMIC_RELAXED);
    stats.shreds_duplicate = __atomic_load_n(&tvu->stats.shreds_duplicate, __ATOMIC_RELAXED);
    stats.blocks_completed = __atomic_load_n(&tvu->stats.blocks_completed, __ATOMIC_RELAXED);
    stats.blocks_replayed = __atomic_load_n(&tvu->stats.blocks_replayed, __ATOMIC_RELAXED);
    stats.blocks_failed = __atomic_load_n(&tvu->stats.blocks_failed, __ATOMIC_RELAXED);
    stats.repairs_requested = __atomic_load_n(&tvu->stats.repairs_requested, __ATOMIC_RELAXED);
    stats.repairs_received = __atomic_load_n(&tvu->stats.repairs_received, __ATOMIC_RELAXED);

    return stats;
}

/*
 * Reset statistics
 */
void
sol_tvu_stats_reset(sol_tvu_t* tvu) {
    if (!tvu) return;
    memset(&tvu->stats, 0, sizeof(tvu->stats));
}

/*
 * Get slot status
 */
sol_slot_status_t
sol_tvu_slot_status(const sol_tvu_t* tvu, sol_slot_t slot) {
    if (!tvu) return SOL_SLOT_STATUS_UNKNOWN;

    pthread_mutex_lock((pthread_mutex_t*)&tvu->slots_lock);
    slot_tracker_t* tracker = find_slot((sol_tvu_t*)tvu, slot);
    sol_slot_status_t status = tracker ? tracker->status : SOL_SLOT_STATUS_UNKNOWN;
    pthread_mutex_unlock((pthread_mutex_t*)&tvu->slots_lock);

    return status;
}

/*
 * Get slot progress
 */
sol_err_t
sol_tvu_slot_progress(const sol_tvu_t* tvu, sol_slot_t slot,
                       uint32_t* out_received, uint32_t* out_expected) {
    if (!tvu) return SOL_ERR_INVAL;

    pthread_mutex_lock((pthread_mutex_t*)&tvu->slots_lock);
    slot_tracker_t* tracker = find_slot((sol_tvu_t*)tvu, slot);

    if (!tracker) {
        pthread_mutex_unlock((pthread_mutex_t*)&tvu->slots_lock);
        return SOL_ERR_NOTFOUND;
    }

    if (out_received) *out_received = tracker->shreds_received;
    if (out_expected) *out_expected = tracker->shreds_expected;

    pthread_mutex_unlock((pthread_mutex_t*)&tvu->slots_lock);
    return SOL_OK;
}
