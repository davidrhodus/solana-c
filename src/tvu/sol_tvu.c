/*
 * sol_tvu.c - Transaction Validation Unit Implementation
 */

#include "sol_tvu.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include "../runtime/sol_leader_schedule.h"
#include <string.h>
#include <pthread.h>
#include <time.h>

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
    uint64_t            last_repair_request_ns;
    bool                replay_retry_requested;
    sol_slot_t          waiting_parent_slot;
    sol_replay_result_t last_replay_result;
    uint64_t            last_replay_ns;
} slot_tracker_t;

#define MAX_TRACKED_SLOTS 4096

/*
 * Shred queue entry
 */
typedef struct {
    uint8_t     data[1232];
    size_t      len;
    uint64_t    received_ns;
} shred_queue_entry_t;

#define SHRED_QUEUE_SIZE 16384

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
    pthread_t               shred_verify_thread;
    pthread_t               replay_thread;
    pthread_t               repair_thread;

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

/*
 * Find or create slot tracker
 */
static slot_tracker_t*
find_or_create_slot(sol_tvu_t* tvu, sol_slot_t slot) {
    /* Find existing */
    for (size_t i = 0; i < tvu->num_slots; i++) {
        if (tvu->slots[i].slot == slot) {
            return &tvu->slots[i];
        }
    }

    /* Create new if space available */
    if (tvu->num_slots < MAX_TRACKED_SLOTS) {
        slot_tracker_t* tracker = &tvu->slots[tvu->num_slots++];
        memset(tracker, 0, sizeof(*tracker));
        tracker->slot = slot;
        tracker->status = SOL_SLOT_STATUS_RECEIVING;
        tracker->first_received_ns = now_ns();
        tracker->last_replay_result = SOL_REPLAY_INCOMPLETE;
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
    memset(tracker, 0, sizeof(*tracker));
    tracker->slot = slot;
    tracker->status = SOL_SLOT_STATUS_RECEIVING;
    tracker->first_received_ns = now_ns();
    return tracker;
}

/*
 * Find slot tracker
 */
static slot_tracker_t*
find_slot(sol_tvu_t* tvu, sol_slot_t slot) {
    for (size_t i = 0; i < tvu->num_slots; i++) {
        if (tvu->slots[i].slot == slot) {
            return &tvu->slots[i];
        }
    }
    return NULL;
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
 * Shred verification thread
 */
static void*
shred_verify_thread_func(void* arg) {
    sol_tvu_t* tvu = (sol_tvu_t*)arg;

    while (tvu->running) {
        shred_queue_entry_t entry;
        if (!shred_queue_pop(tvu, &entry, 100)) {
            continue;
        }

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
        bool sig_valid = false;
        bool have_leader = false;
        sol_pubkey_t leader_pk;

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

        if (!sig_valid) {
            __atomic_fetch_add(&tvu->stats.shreds_failed, 1, __ATOMIC_RELAXED);
            sol_log_debug("Shred signature verification failed for slot %lu index %u",
                         (unsigned long)shred.slot, shred.index);
            continue;
        }
        __atomic_fetch_add(&tvu->stats.shreds_verified, 1, __ATOMIC_RELAXED);

        /* Store in blockstore */
        if (tvu->blockstore) {
            sol_blockstore_insert_shred(tvu->blockstore, &shred, entry.data, shred.raw_len);
        }

        /* Check if slot is complete */
        bool slot_complete = tvu->blockstore &&
                             sol_blockstore_is_slot_complete(tvu->blockstore, shred.slot);

        pthread_mutex_lock(&tvu->slots_lock);
        tracker = find_slot(tvu, shred.slot);
        if (tracker) {
            if (tracker->status == SOL_SLOT_STATUS_RECEIVING && slot_complete) {
                tracker->status = SOL_SLOT_STATUS_COMPLETE;
                __atomic_fetch_add(&tvu->stats.blocks_completed, 1, __ATOMIC_RELAXED);
                sol_log_info("Slot %lu complete", (unsigned long)shred.slot);
            } else if (slot_complete && tracker->status == SOL_SLOT_STATUS_REPLAYING) {
                tracker->replay_retry_requested = true;
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

    return NULL;
}

/*
 * Replay thread
 */
static void*
replay_thread_func(void* arg) {
    sol_tvu_t* tvu = (sol_tvu_t*)arg;

    while (tvu->running) {
        /* Find slots ready for replay */
        sol_slot_t replay_slot = 0;
        bool found = false;

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

        /* On restarts, blockstore may already contain complete slots from a
         * previous run. Ensure those slots get queued for replay even when no
         * new shreds arrive to trigger the normal COMPLETE transition. */
        if (tvu->blockstore) {
            for (size_t i = 0; i < tvu->num_slots; i++) {
                if (tvu->slots[i].status != SOL_SLOT_STATUS_RECEIVING) {
                    continue;
                }
                if (tvu->slots[i].slot == 0) {
                    continue;
                }
                if (sol_blockstore_is_slot_complete(tvu->blockstore, tvu->slots[i].slot)) {
                    tvu->slots[i].status = SOL_SLOT_STATUS_COMPLETE;
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
            tvu->slots[best_idx].status = SOL_SLOT_STATUS_REPLAYING;
            found = true;
        }
        pthread_mutex_unlock(&tvu->slots_lock);

        if (!found) {
            struct timespec ts = {0, 10000000};  /* 10ms */
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
                sol_log_info("Slot %lu replayed successfully", (unsigned long)replay_slot);
            } else if (replay_result == SOL_REPLAY_DUPLICATE) {
                sol_log_debug("Slot %lu replay already complete", (unsigned long)replay_slot);
            } else if (replay_result == SOL_REPLAY_DEAD) {
                __atomic_fetch_add(&tvu->stats.blocks_failed, 1, __ATOMIC_RELAXED);
                sol_log_warn("Slot %lu replay failed: %d", (unsigned long)replay_slot, replay_result);
            } else if (replay_result == SOL_REPLAY_PARENT_MISSING) {
                sol_log_debug("Slot %lu waiting for parent %lu",
                              (unsigned long)replay_slot,
                              (unsigned long)replay_info.parent_slot);
            } else {
                sol_log_warn("Slot %lu replay returned: %d", (unsigned long)replay_slot, replay_result);
            }
        }

        /* Update slot status */
        pthread_mutex_lock(&tvu->slots_lock);
        slot_tracker_t* tracker = find_slot(tvu, replay_slot);
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
    sol_tvu_t* tvu = (sol_tvu_t*)arg;
    uint64_t last_primary_diag_ns = 0;

    while (tvu->running) {
        struct timespec ts = {0, 20000000};  /* 20ms */
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

        /* Proactively backfill a window of slots ahead of the highest replayed
         * slot. This is critical for bootstrap/catchup, where turbine may not
         * deliver historical shreds. */
        sol_slot_t replay_cursor = 0;
        sol_slot_t catchup_start = 0;
        sol_slot_t catchup_end = 0;
        enum { SOL_TVU_CATCHUP_WINDOW_SLOTS = 8 };

        if (tvu->replay) {
            replay_cursor = sol_replay_highest_replayed_slot(tvu->replay);
            catchup_start = replay_cursor + 1;
            catchup_end = replay_cursor + (sol_slot_t)SOL_TVU_CATCHUP_WINDOW_SLOTS;
        }

        typedef struct {
            sol_repair_type_t type;
            sol_slot_t        slot;
            uint64_t          shred_index;
        } repair_action_t;

        enum {
            SOL_TVU_MAX_REPAIR_ACTIONS = 512,
            SOL_TVU_MAX_MISSING_SHREDS = 256,
            SOL_TVU_CATCHUP_MIN_INTERVAL_MS = 20,
            SOL_TVU_INITIAL_SHRED_BURST_PRIMARY = 64,
            SOL_TVU_INITIAL_SHRED_BURST_OTHER = 8,
        };

        repair_action_t actions[SOL_TVU_MAX_REPAIR_ACTIONS];
        size_t action_count = 0;
        size_t action_budget = headroom;
        if (action_budget > SOL_TVU_MAX_REPAIR_ACTIONS) {
            action_budget = SOL_TVU_MAX_REPAIR_ACTIONS;
        }

        pthread_mutex_lock(&tvu->slots_lock);

        /* Ensure slot trackers exist for upcoming catchup slots so the repair
         * loop can drive forward progress even if no shreds have arrived yet. */
        sol_slot_t primary_slot = catchup_start;
        if (primary_slot != 0) {
            (void)find_or_create_slot(tvu, primary_slot);
        }
        if (tvu->replay && tvu->num_slots < MAX_TRACKED_SLOTS) {
            sol_slot_t start = replay_cursor + 1;
            sol_slot_t end = catchup_end + 1;
            for (sol_slot_t slot = start;
                 slot != 0 && slot < end && tvu->num_slots < MAX_TRACKED_SLOTS;
                 slot++) {
                (void)find_or_create_slot(tvu, slot);
            }
        }

        int passes = (primary_slot != 0) ? 1 : 2;
        for (int pass = 0; pass < passes && action_count < action_budget; pass++) {
            for (size_t i = 0; i < tvu->num_slots && action_count < action_budget; i++) {
                slot_tracker_t* tracker = &tvu->slots[i];
                if (pass == 0) {
                    if (primary_slot == 0 || tracker->slot != primary_slot) {
                        continue;
                    }
                } else {
                    if (primary_slot != 0 && tracker->slot == primary_slot) {
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

                if (since_req_ms < min_interval_ms) {
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
                    };

                    if (action_count < action_budget &&
                        have_meta &&
                        last_idx != first_idx) {
                        actions[action_count++] = (repair_action_t){
                            .type = SOL_REPAIR_SHRED,
                            .slot = tracker->slot,
                            .shred_index = last_idx,
                        };
                    }

                    if (action_count < action_budget) {
                        actions[action_count++] = (repair_action_t){
                            .type = SOL_REPAIR_HIGHEST_SHRED,
                            .slot = tracker->slot,
                            .shred_index = 0,
                        };
                    }

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
                        };
                    }
                    if (action_count < action_budget) {
                        actions[action_count++] = (repair_action_t){
                            .type = SOL_REPAIR_HIGHEST_SHRED,
                            .slot = tracker->slot,
                            .shred_index = 0,
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
                    bool request_duplicates = false;
                    sol_slot_meta_t meta;
                    uint32_t first_idx = 0;
                    uint32_t last_idx = 0;
                    bool have_meta = false;

                    if (is_catchup_slot &&
                        tracker->last_replay_ns != 0 &&
                        tracker->last_replay_result == SOL_REPLAY_INCOMPLETE &&
                        tvu->blockstore &&
                        sol_blockstore_is_slot_complete(tvu->blockstore, tracker->slot)) {
                        have_meta = sol_blockstore_get_slot_meta(tvu->blockstore, tracker->slot, &meta) == SOL_OK;
                        if (have_meta) {
                            first_idx = meta.first_shred_index;
                            last_idx = meta.last_shred_index;
                        }
                        request_duplicates = true;
                    }

                    /* Use last_shred_index+1 as the starting index for
                     * HighestWindowIndex so the peer returns a shred we
                     * don't already have (the actual last shred of the slot).
                     * With shred_index=0 the peer just returns the highest
                     * shred which we may already have, causing endless dups. */
                    uint64_t highest_start = 0;
                    if (!have_meta && tvu->blockstore) {
                        sol_slot_meta_t m;
                        if (sol_blockstore_get_slot_meta(tvu->blockstore, tracker->slot, &m) == SOL_OK) {
                            highest_start = (uint64_t)m.last_shred_index + 1;
                        }
                    } else if (have_meta) {
                        highest_start = (uint64_t)last_idx + 1;
                    }

                    if (request_duplicates) {
                        actions[action_count++] = (repair_action_t){
                            .type = SOL_REPAIR_SHRED,
                            .slot = tracker->slot,
                            .shred_index = first_idx,
                        };
                        if (action_count < action_budget &&
                            have_meta &&
                            last_idx != first_idx) {
                            actions[action_count++] = (repair_action_t){
                                .type = SOL_REPAIR_SHRED,
                                .slot = tracker->slot,
                                .shred_index = last_idx,
                            };
                        }
                        if (action_count < action_budget) {
                            actions[action_count++] = (repair_action_t){
                                .type = SOL_REPAIR_HIGHEST_SHRED,
                                .slot = tracker->slot,
                                .shred_index = highest_start,
                            };
                        }
                    } else {
                        actions[action_count++] = (repair_action_t){
                            .type = SOL_REPAIR_HIGHEST_SHRED,
                            .slot = tracker->slot,
                            .shred_index = highest_start,
                        };
                    }
                } else {
                    bool request_highest = false;
                    uint64_t highest_idx = 0;
                    if (is_catchup_slot && tvu->blockstore) {
                        sol_slot_meta_t meta;
                        if (sol_blockstore_get_slot_meta(tvu->blockstore, tracker->slot, &meta) == SOL_OK) {
                            if (!meta.is_full) {
                                request_highest = true;
                                highest_idx = (uint64_t)meta.last_shred_index + 1;
                            }
                        }
                    }

                    for (size_t m = 0; m < missing_count && action_count < action_budget; m++) {
                        actions[action_count++] = (repair_action_t){
                            .type = SOL_REPAIR_SHRED,
                            .slot = tracker->slot,
                            .shred_index = missing[m],
                        };
                    }

                    if (request_highest && action_count < action_budget) {
                        actions[action_count++] = (repair_action_t){
                            .type = SOL_REPAIR_HIGHEST_SHRED,
                            .slot = tracker->slot,
                            .shred_index = highest_idx,
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
            };
        }

        for (size_t i = 0; i < action_count; i++) {
            sol_err_t err = SOL_ERR_INVAL;
            const repair_action_t* a = &actions[i];
            switch (a->type) {
            case SOL_REPAIR_SHRED:
                err = sol_repair_request_shred(tvu->repair, a->slot, a->shred_index, true);
                break;
            case SOL_REPAIR_HIGHEST_SHRED:
                err = sol_repair_request_highest(tvu->repair, a->slot, a->shred_index);
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

    /* Initialize shred queue */
    tvu->shred_queue = sol_calloc(SHRED_QUEUE_SIZE, sizeof(shred_queue_entry_t));
    if (!tvu->shred_queue) {
        sol_free(tvu);
        return NULL;
    }

    pthread_mutex_init(&tvu->shred_queue_lock, NULL);
    pthread_cond_init(&tvu->shred_queue_cond, NULL);
    pthread_mutex_init(&tvu->slots_lock, NULL);
    pthread_mutex_init(&tvu->lock, NULL);

    tvu->running = false;
    tvu->threads_started = false;

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

    /* Start shred verification thread */
    if (pthread_create(&tvu->shred_verify_thread, NULL, shred_verify_thread_func, tvu) != 0) {
        tvu->running = false;
        return SOL_ERR_IO;
    }

    /* Start replay thread */
    if (pthread_create(&tvu->replay_thread, NULL, replay_thread_func, tvu) != 0) {
        tvu->running = false;
        pthread_join(tvu->shred_verify_thread, NULL);
        return SOL_ERR_IO;
    }

    /* Start repair thread */
    if (pthread_create(&tvu->repair_thread, NULL, repair_thread_func, tvu) != 0) {
        tvu->running = false;
        pthread_join(tvu->shred_verify_thread, NULL);
        pthread_join(tvu->replay_thread, NULL);
        return SOL_ERR_IO;
    }

    tvu->threads_started = true;
    sol_log_info("TVU started");

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
        pthread_join(tvu->shred_verify_thread, NULL);
        pthread_join(tvu->replay_thread, NULL);
        pthread_join(tvu->repair_thread, NULL);
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

    __atomic_fetch_add(&tvu->stats.shreds_received, 1, __ATOMIC_RELAXED);

    if (!shred_queue_push(tvu, shred, len)) {
        return SOL_ERR_FULL;
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
