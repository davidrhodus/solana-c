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
#include <errno.h>
#include <ctype.h>

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
    /* Round-robin cursor used when missing sets are too large to request in a
     * single loop. This avoids repeatedly hammering low indices only. */
    uint32_t            repair_missing_cursor;
    uint64_t            first_complete_ns;
    bool                replay_retry_requested;
    sol_slot_t          waiting_parent_slot;
    sol_replay_result_t last_replay_result;
    uint64_t            last_replay_ns;
    uint64_t            replay_started_ns;
    uint64_t            replay_attempt_id;
    /* Snapshot of blockstore variant state at the last replay attempt.
     *
     * Used to avoid tight replay loops on "complete" slots that fail replay
     * validation (e.g. missing ticks). Such slots should only be retried when
     * a *new complete* block variant arrives. */
    uint32_t            last_replay_complete_variants;
    /* Best-effort restart probe:
     * After a restart, the persisted blockstore may already contain shreds/meta
     * for some slots even before we receive any new shreds in this run. Keep
     * probing bounded by cadence, but do not probe only once: slots can become
     * replayable later via repair responses without local shred ingestion. */
    uint64_t            last_restart_probe_ns;
    uint64_t            last_prewarm_ns;
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

#define SHRED_QUEUE_SIZE 524288
/* Auto-thread selection used to default to saturating the machine (clamped by
 * these caps). On high-core servers, that created hundreds of threads across
 * TVU roles and the tx-exec pool, leading to contention and worse replay
 * latency.  Prefer more conservative defaults; users can still override via
 * config/flags once exposed. */
#define SOL_TVU_MAX_VERIFY_THREADS 64
/* Replay is inherently sequential at the bank-forks level (parent->child),
 * but parallel replay threads can still improve throughput when multiple
 * complete forks/variants are available (duplicates, catchup backfill, etc.). */
#define SOL_TVU_MAX_REPLAY_THREADS 64
#define SOL_TVU_MAX_REPAIR_THREADS 64
#define SOL_TVU_VERIFY_BATCH_MAX 256
#define SOL_TVU_REPLAY_STAGE_SAMPLES 4096

typedef struct {
    double total_ms;
    double repair_wait_ms;
    double fetch_ms;
    double decode_ms;
    double execute_ms;
    double commit_ms;
} replay_stage_sample_t;

typedef struct tvu_repair_thread_ctx {
    struct sol_tvu* tvu;
    uint32_t        thread_idx;
} tvu_repair_thread_ctx_t;

typedef struct tvu_prewarm_thread_ctx {
    struct sol_tvu* tvu;
    uint32_t        thread_idx;
} tvu_prewarm_thread_ctx_t;

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
    pthread_t*              prewarm_threads;
    size_t                  prewarm_thread_count;
    tvu_prewarm_thread_ctx_t* prewarm_thread_ctx;

    pthread_mutex_t         lock;
    bool                    running;
    bool                    threads_started;
    uint64_t                replay_attempt_seq;

    /* Sliding-window replay stage latency samples (for percentile reporting). */
    replay_stage_sample_t   replay_samples[SOL_TVU_REPLAY_STAGE_SAMPLES];
    size_t                  replay_samples_len;
    size_t                  replay_samples_next;
    uint64_t                replay_stage_last_report_ns;
    pthread_mutex_t         replay_metrics_lock;
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

static long
tvu_replay_idle_sleep_ns(void) {
    static long cached = -1;
    long v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (v >= 0) {
        return v;
    }

    /* Default to short idle sleeps on large hosts to reduce replay slot
     * handoff bubbles. */
    long ns = 1000000L; /* 1ms */
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu >= 64) {
        ns = 50000L; /* 50us */
    }

    const char* env = getenv("SOL_TVU_REPLAY_IDLE_NS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        long parsed = strtol(env, &end, 10);
        if (end && end != env) {
            ns = parsed;
        }
    }

    if (ns < 0) ns = 0;
    if (ns > 10000000L) ns = 10000000L; /* cap at 10ms */

    __atomic_store_n(&cached, ns, __ATOMIC_RELEASE);
    return ns;
}

static int
tvu_double_cmp(const void* a, const void* b) {
    double da = *(const double*)a;
    double db = *(const double*)b;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

static double
tvu_percentile_sorted(const double* sorted, size_t n, double pct) {
    if (!sorted || n == 0) return 0.0;
    if (n == 1) return sorted[0];

    double pos = (pct / 100.0) * (double)(n - 1);
    size_t lo = (size_t)pos;
    size_t hi = (lo + 1u < n) ? (lo + 1u) : lo;
    if (lo == hi) return sorted[lo];

    double frac = pos - (double)lo;
    return sorted[lo] + (sorted[hi] - sorted[lo]) * frac;
}

static void
tvu_mark_slot_complete_locked(sol_tvu_t* tvu,
                              slot_tracker_t* tracker,
                              bool count_completed) {
    if (!tvu || !tracker) return;

    tracker->status = SOL_SLOT_STATUS_COMPLETE;
    tracker->waiting_parent_slot = 0;
    tracker->replay_started_ns = 0;
    tracker->replay_attempt_id = 0;
    if (tracker->first_complete_ns == 0) {
        tracker->first_complete_ns = now_ns();
    }
    if (count_completed) {
        __atomic_fetch_add(&tvu->stats.blocks_completed, 1, __ATOMIC_RELAXED);
    }
}

static void
tvu_record_replay_stage_metrics(sol_tvu_t* tvu,
                                const sol_replay_slot_info_t* info,
                                double repair_wait_ms) {
    if (!tvu || !info) return;

    replay_stage_sample_t sample = {
        .total_ms = (double)info->replay_time_ns / 1000000.0,
        .repair_wait_ms = repair_wait_ms,
        .fetch_ms = (double)info->fetch_time_ns / 1000000.0,
        .decode_ms = (double)info->decode_time_ns / 1000000.0,
        .execute_ms = (double)info->execute_time_ns / 1000000.0,
        .commit_ms = (double)info->commit_time_ns / 1000000.0,
    };

    pthread_mutex_lock(&tvu->replay_metrics_lock);

    size_t idx = tvu->replay_samples_next;
    if (idx >= SOL_TVU_REPLAY_STAGE_SAMPLES) {
        idx %= SOL_TVU_REPLAY_STAGE_SAMPLES;
    }
    tvu->replay_samples[idx] = sample;
    tvu->replay_samples_next = (idx + 1u) % SOL_TVU_REPLAY_STAGE_SAMPLES;
    if (tvu->replay_samples_len < SOL_TVU_REPLAY_STAGE_SAMPLES) {
        tvu->replay_samples_len++;
    }

    uint64_t now = now_ns();
    bool should_report =
        (tvu->replay_samples_len >= 64u) &&
        (tvu->replay_stage_last_report_ns == 0 ||
         (now - tvu->replay_stage_last_report_ns) >= 5000000000ULL);
    if (!should_report) {
        pthread_mutex_unlock(&tvu->replay_metrics_lock);
        return;
    }
    tvu->replay_stage_last_report_ns = now;

    size_t n = tvu->replay_samples_len;
    double vals[SOL_TVU_REPLAY_STAGE_SAMPLES];

#define TVU_STAGE_PCTS(field, out_p50, out_p90, out_p95, out_p99)                  \
    do {                                                                             \
        for (size_t i = 0; i < n; i++) {                                            \
            vals[i] = tvu->replay_samples[i].field;                                 \
        }                                                                            \
        qsort(vals, n, sizeof(vals[0]), tvu_double_cmp);                            \
        out_p50 = tvu_percentile_sorted(vals, n, 50.0);                             \
        out_p90 = tvu_percentile_sorted(vals, n, 90.0);                             \
        out_p95 = tvu_percentile_sorted(vals, n, 95.0);                             \
        out_p99 = tvu_percentile_sorted(vals, n, 99.0);                             \
    } while (0)

    double total_p50, total_p90, total_p95, total_p99;
    double repair_p50, repair_p90, repair_p95, repair_p99;
    double fetch_p50, fetch_p90, fetch_p95, fetch_p99;
    double decode_p50, decode_p90, decode_p95, decode_p99;
    double exec_p50, exec_p90, exec_p95, exec_p99;
    double commit_p50, commit_p90, commit_p95, commit_p99;

    TVU_STAGE_PCTS(total_ms, total_p50, total_p90, total_p95, total_p99);
    TVU_STAGE_PCTS(repair_wait_ms, repair_p50, repair_p90, repair_p95, repair_p99);
    TVU_STAGE_PCTS(fetch_ms, fetch_p50, fetch_p90, fetch_p95, fetch_p99);
    TVU_STAGE_PCTS(decode_ms, decode_p50, decode_p90, decode_p95, decode_p99);
    TVU_STAGE_PCTS(execute_ms, exec_p50, exec_p90, exec_p95, exec_p99);
    TVU_STAGE_PCTS(commit_ms, commit_p50, commit_p90, commit_p95, commit_p99);

#undef TVU_STAGE_PCTS

    pthread_mutex_unlock(&tvu->replay_metrics_lock);

    sol_log_info(
        "Replay stages: n=%zu "
        "total(p50=%.2f p90=%.2f p95=%.2f p99=%.2f) "
        "repair(p50=%.2f p90=%.2f p95=%.2f p99=%.2f) "
        "fetch(p50=%.2f p90=%.2f p95=%.2f p99=%.2f) "
        "decode(p50=%.2f p90=%.2f p95=%.2f p99=%.2f) "
        "execute(p50=%.2f p90=%.2f p95=%.2f p99=%.2f) "
        "commit(p50=%.2f p90=%.2f p95=%.2f p99=%.2f)",
        n,
        total_p50, total_p90, total_p95, total_p99,
        repair_p50, repair_p90, repair_p95, repair_p99,
        fetch_p50, fetch_p90, fetch_p95, fetch_p99,
        decode_p50, decode_p90, decode_p95, decode_p99,
        exec_p50, exec_p90, exec_p95, exec_p99,
        commit_p50, commit_p90, commit_p95, commit_p99);
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

typedef enum {
    TVU_THREAD_ROLE_VERIFY = 0,
    TVU_THREAD_ROLE_REPLAY = 1,
    TVU_THREAD_ROLE_REPAIR = 2,
} tvu_thread_role_t;

static const char*
tvu_thread_override_env(tvu_thread_role_t role) {
    switch (role) {
        case TVU_THREAD_ROLE_VERIFY:
            return "SOL_TVU_SHRED_VERIFY_THREADS";
        case TVU_THREAD_ROLE_REPLAY:
            return "SOL_TVU_REPLAY_THREADS";
        case TVU_THREAD_ROLE_REPAIR:
            return "SOL_TVU_REPAIR_THREADS";
        default:
            return NULL;
    }
}

static uint32_t
tvu_auto_threads_for_role(uint32_t cpu_count, tvu_thread_role_t role) {
    uint32_t threads = cpu_count;

    if (role == TVU_THREAD_ROLE_REPLAY) {
        /* Replay slot selection has shared locks and parent checks; keep
         * defaults tighter than verify/repair to reduce scheduler contention
         * on large-core machines. For replay-heavy mainnet catchup, lower
         * fanout reduces long-tail convoy stalls between replay workers. */
        if (threads >= 128u) {
            threads /= 32u; /* 128c -> 4 threads */
        } else if (threads >= 96u) {
            threads /= 24u; /* 96c -> 4 threads */
        } else if (threads >= 64u) {
            threads /= 16u; /* 64c -> 4 threads */
        } else if (threads >= 48u) {
            threads /= 12u; /* 48c -> 4 threads */
        } else if (threads >= 24u) {
            threads /= 6u;  /* 24c -> 4 threads */
        } else if (threads >= 12u) {
            threads /= 4u;
        } else if (threads >= 4u) {
            threads /= 2u;
        }
    } else if (role == TVU_THREAD_ROLE_REPAIR) {
        /* Catchup at the replay frontier is often repair-bound. On large-core
         * hosts, keep a larger repair pool than verify so missing-shred gaps
         * close quickly instead of stalling replay on the next slot. */
        if (threads >= 128u) {
            threads /= 4u;  /* 128c -> 32 threads */
        } else if (threads >= 96u) {
            threads /= 4u;  /* 96c -> 24 threads */
        } else if (threads >= 64u) {
            threads /= 3u;  /* 64c -> 21 threads */
        } else if (threads >= 48u) {
            threads /= 2u;  /* 48c -> 24 threads */
        } else if (threads >= 24u) {
            threads /= 2u;  /* 24c -> 12 threads */
        }
    } else {
        /* Avoid oversubscription: replay also runs a large tx worker pool.
         * Very high TVU worker counts can increase tail latency via scheduler
         * contention even when median slot time looks healthy. */
        if (threads >= 128u) {
            threads /= 8u; /* 128c -> 16 threads */
        } else if (threads >= 96u) {
            threads /= 6u; /* 96c -> 16 threads */
        } else if (threads >= 64u) {
            threads /= 4u; /* 64c -> 16 threads */
        } else if (threads >= 48u) {
            threads /= 3u;
        } else if (threads >= 24u) {
            threads /= 2u;
        }
    }

    return threads;
}

static uint32_t
tvu_pick_threads(uint32_t requested,
                 uint32_t max_threads,
                 uint32_t min_auto,
                 tvu_thread_role_t role) {
    uint32_t threads = requested;
    if (threads == 0) {
        uint32_t cpu_count = tvu_cpu_count();
        bool env_override = false;
        threads = tvu_auto_threads_for_role(cpu_count, role);

        const char* env_name = tvu_thread_override_env(role);
        const char* env = env_name ? getenv(env_name) : NULL;
        if (env && env[0] != '\0') {
            char* end = NULL;
            unsigned long parsed = strtoul(env, &end, 10);
            if (end && end != env) {
                threads = (uint32_t)parsed;
                env_override = true;
            }
        }

        if (!env_override && threads < min_auto && cpu_count > 1) {
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

static void
tvu_slot_maxheap_sift_up(sol_slot_t* heap, size_t heap_len, size_t idx) {
    if (!heap || heap_len == 0 || idx >= heap_len) {
        return;
    }

    while (idx > 0) {
        size_t parent = (idx - 1u) / 2u;
        if (heap[parent] >= heap[idx]) {
            break;
        }
        sol_slot_t tmp = heap[parent];
        heap[parent] = heap[idx];
        heap[idx] = tmp;
        idx = parent;
    }
}

static void
tvu_slot_maxheap_sift_down(sol_slot_t* heap, size_t heap_len, size_t idx) {
    if (!heap || heap_len == 0 || idx >= heap_len) {
        return;
    }

    for (;;) {
        size_t left = idx * 2u + 1u;
        if (left >= heap_len) {
            break;
        }

        size_t right = left + 1u;
        size_t largest = left;
        if (right < heap_len && heap[right] > heap[left]) {
            largest = right;
        }

        if (heap[idx] >= heap[largest]) {
            break;
        }

        sol_slot_t tmp = heap[idx];
        heap[idx] = heap[largest];
        heap[largest] = tmp;
        idx = largest;
    }
}

static void
tvu_collect_smallest_slot_candidates(sol_slot_t* slots,
                                     size_t* count,
                                     size_t cap,
                                     sol_slot_t slot) {
    if (!slots || !count || cap == 0 || slot == 0) {
        return;
    }

    /* Maintain a bounded max-heap of the smallest `cap` slots seen so far.
     * Root contains the current largest candidate. */
    if (*count < cap) {
        size_t idx = *count;
        slots[idx] = slot;
        (*count)++;
        tvu_slot_maxheap_sift_up(slots, *count, idx);
        return;
    }

    if (slot >= slots[0]) {
        return;
    }

    slots[0] = slot;
    tvu_slot_maxheap_sift_down(slots, *count, 0);
}

static uint32_t
tvu_pick_prewarm_threads(uint32_t replay_threads) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (v >= 0) {
        return (uint32_t)v;
    }

    uint32_t threads = replay_threads;
    if (threads == 0) {
        threads = 1;
    }
    if (threads > 8u) {
        threads = 8u;
    }

    const char* env = getenv("SOL_TVU_PREWARM_THREADS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long parsed = strtoul(env, &end, 10);
        if (end && end != env) {
            threads = (uint32_t)parsed;
        }
    }

    if (threads > 32u) {
        threads = 32u;
    }
    if (threads == 0u) {
        threads = 1u;
    }

    __atomic_store_n(&cached, (int)threads, __ATOMIC_RELEASE);
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

static sol_slot_t
tvu_max_shred_ahead_high_lag(void) {
    static long cached = -1;
    if (cached >= 0) {
        return (sol_slot_t)cached;
    }

    /* When replay lag exceeds this threshold, tighten far-ahead shred intake
     * to keep queue/blockstore pressure near the replay-critical window.
     * Set to 0 to disable this tier. */
    const char* env = getenv("SOL_TVU_MAX_SHRED_AHEAD_HIGH_LAG");
    long v = 2048; /* default */
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

static sol_slot_t
tvu_max_shred_ahead_high_slots(void) {
    static long cached = -1;
    if (cached >= 0) {
        return (sol_slot_t)cached;
    }

    /* Effective max-ahead slots used when high-lag tier is active.
     * Set to 0 to disable high-tier tightening. */
    const char* env = getenv("SOL_TVU_MAX_SHRED_AHEAD_HIGH_SLOTS");
    long v = 1024; /* default */
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

static sol_slot_t
tvu_max_shred_ahead_severe_lag(void) {
    static long cached = -1;
    if (cached >= 0) {
        return (sol_slot_t)cached;
    }

    /* When replay lag is very high, tighten far-ahead intake further.
     * Set to 0 to disable this tier. */
    const char* env = getenv("SOL_TVU_MAX_SHRED_AHEAD_SEVERE_LAG");
    long v = 8192; /* default */
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

static sol_slot_t
tvu_max_shred_ahead_severe_slots(void) {
    static long cached = -1;
    if (cached >= 0) {
        return (sol_slot_t)cached;
    }

    /* Effective max-ahead slots used when severe-lag tier is active.
     * Set to 0 to disable severe-tier tightening. */
    const char* env = getenv("SOL_TVU_MAX_SHRED_AHEAD_SEVERE_SLOTS");
    long v = 512; /* default */
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

static sol_slot_t
tvu_effective_max_shred_ahead(sol_tvu_t* tvu, sol_slot_t replay_cursor) {
    sol_slot_t base = tvu_max_shred_ahead_slots();
    if (base == 0 || !tvu || !tvu->blockstore || replay_cursor == 0) {
        return base;
    }

    sol_slot_t highest = sol_blockstore_highest_slot(tvu->blockstore);
    sol_slot_t lag = (highest > replay_cursor) ? (highest - replay_cursor) : 0;
    if (lag == 0) {
        return base;
    }

    sol_slot_t effective = base;
    sol_slot_t high_lag = tvu_max_shred_ahead_high_lag();
    sol_slot_t severe_lag = tvu_max_shred_ahead_severe_lag();
    if (severe_lag != 0 && high_lag != 0 && severe_lag < high_lag) {
        severe_lag = high_lag;
    }

    if (severe_lag != 0 && lag >= severe_lag) {
        sol_slot_t severe_slots = tvu_max_shred_ahead_severe_slots();
        if (severe_slots != 0 && severe_slots < effective) {
            effective = severe_slots;
        }
    } else if (high_lag != 0 && lag >= high_lag) {
        sol_slot_t high_slots = tvu_max_shred_ahead_high_slots();
        if (high_slots != 0 && high_slots < effective) {
            effective = high_slots;
        }
    }

    return effective;
}

static sol_slot_t
tvu_max_replay_ahead_slots(void) {
    static long cached = -1;
    if (cached >= 0) {
        return (sol_slot_t)cached;
    }

    /* Bound how far ahead of highest-replayed the replay scheduler may pick
     * COMPLETE slots. This prevents far-ahead replay storms from starving the
     * frontier slot during catchup. Set to 0 to disable this guard. */
    const char* env = getenv("SOL_TVU_MAX_REPLAY_AHEAD_SLOTS");
    long v = 1024; /* default */
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

static sol_slot_t
tvu_max_replay_ahead_high_lag(void) {
    static long cached = -1;
    if (cached >= 0) {
        return (sol_slot_t)cached;
    }

    /* When replay lag is high, shrink replay-ahead window to keep CPU focused
     * on near-frontier progress. Set to 0 to disable this tier. */
    const char* env = getenv("SOL_TVU_MAX_REPLAY_AHEAD_HIGH_LAG");
    long v = 512; /* default */
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

static sol_slot_t
tvu_max_replay_ahead_high_slots(void) {
    static long cached = -1;
    if (cached >= 0) {
        return (sol_slot_t)cached;
    }

    const char* env = getenv("SOL_TVU_MAX_REPLAY_AHEAD_HIGH_SLOTS");
    long v = 64; /* default */
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

static sol_slot_t
tvu_max_replay_ahead_severe_lag(void) {
    static long cached = -1;
    if (cached >= 0) {
        return (sol_slot_t)cached;
    }

    /* Severe backlog: keep replay tightly centered around the frontier.
     * Set to 0 to disable this tier. */
    const char* env = getenv("SOL_TVU_MAX_REPLAY_AHEAD_SEVERE_LAG");
    long v = 1024; /* default */
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

    long high = (long)tvu_max_replay_ahead_high_lag();
    if (v != 0 && high != 0 && v < high) {
        v = high;
    }

    cached = v;
    return (sol_slot_t)cached;
}

static sol_slot_t
tvu_max_replay_ahead_severe_slots(void) {
    static long cached = -1;
    if (cached >= 0) {
        return (sol_slot_t)cached;
    }

    const char* env = getenv("SOL_TVU_MAX_REPLAY_AHEAD_SEVERE_SLOTS");
    long v = 24; /* default */
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

static sol_slot_t
tvu_effective_max_replay_ahead(sol_tvu_t* tvu, sol_slot_t replay_cursor) {
    sol_slot_t base = tvu_max_replay_ahead_slots();
    if (base == 0 || !tvu || !tvu->blockstore || replay_cursor == 0) {
        return base;
    }

    sol_slot_t highest = sol_blockstore_highest_slot(tvu->blockstore);
    sol_slot_t lag = (highest > replay_cursor) ? (highest - replay_cursor) : 0;
    if (lag == 0) {
        return base;
    }

    sol_slot_t effective = base;
    sol_slot_t high_lag = tvu_max_replay_ahead_high_lag();
    sol_slot_t severe_lag = tvu_max_replay_ahead_severe_lag();
    if (severe_lag != 0 && high_lag != 0 && severe_lag < high_lag) {
        severe_lag = high_lag;
    }

    if (severe_lag != 0 && lag >= severe_lag) {
        sol_slot_t severe_slots = tvu_max_replay_ahead_severe_slots();
        if (severe_slots != 0 && severe_slots < effective) {
            effective = severe_slots;
        }
    } else if (high_lag != 0 && lag >= high_lag) {
        sol_slot_t high_slots = tvu_max_replay_ahead_high_slots();
        if (high_slots != 0 && high_slots < effective) {
            effective = high_slots;
        }
    }

    return effective;
}

static inline bool
tvu_slot_in_replay_window(sol_slot_t slot, sol_slot_t replay_cursor, sol_slot_t max_ahead) {
    if (slot == 0) {
        return false;
    }
    if (replay_cursor == 0 || max_ahead == 0) {
        return true;
    }
    if (slot <= replay_cursor) {
        return true;
    }
    return (slot - replay_cursor) <= max_ahead;
}

static sol_slot_t
tvu_primary_dead_replay_ahead_slots(void) {
    static long cached = -1;
    if (cached >= 0) {
        return (sol_slot_t)cached;
    }

    /* When the replay-primary slot (highest_replayed+1) is marked DEAD, keep
     * replay candidate selection tightly centered near the frontier so replay
     * threads don't burn CPU on far-ahead slots while duplicate repair is
     * trying to recover the primary. Set to 0 to disable this tightening. */
    const char* env = getenv("SOL_TVU_PRIMARY_DEAD_REPLAY_AHEAD_SLOTS");
    long v = 8; /* default */
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
    if (v > 4096) {
        v = 4096;
    }
    cached = v;
    return (sol_slot_t)cached;
}

static uint32_t
tvu_dead_primary_duplicate_fanout(void) {
    static long cached = -1;
    if (cached >= 0) {
        return (uint32_t)cached;
    }

    const char* env = getenv("SOL_TVU_DEAD_PRIMARY_DUPLICATE_FANOUT");
    long v = 48; /* default */
    if (env && env[0] != '\0') {
        char* end = NULL;
        long parsed = strtol(env, &end, 10);
        if (end && end != env) {
            v = parsed;
        }
    }
    if (v < 1) v = 1;
    if (v > 256) v = 256;
    cached = v;
    return (uint32_t)cached;
}

static uint32_t
tvu_dead_primary_highest_fanout(void) {
    static long cached = -1;
    if (cached >= 0) {
        return (uint32_t)cached;
    }

    const char* env = getenv("SOL_TVU_DEAD_PRIMARY_HIGHEST_FANOUT");
    long v = 32; /* default */
    if (env && env[0] != '\0') {
        char* end = NULL;
        long parsed = strtol(env, &end, 10);
        if (end && end != env) {
            v = parsed;
        }
    }
    if (v < 1) v = 1;
    if (v > 256) v = 256;
    cached = v;
    return (uint32_t)cached;
}

static uint32_t
tvu_dead_primary_orphan_fanout(void) {
    static long cached = -1;
    if (cached >= 0) {
        return (uint32_t)cached;
    }

    const char* env = getenv("SOL_TVU_DEAD_PRIMARY_ORPHAN_FANOUT");
    long v = 4; /* default */
    if (env && env[0] != '\0') {
        char* end = NULL;
        long parsed = strtol(env, &end, 10);
        if (end && end != env) {
            v = parsed;
        }
    }
    if (v < 1) v = 1;
    if (v > 64) v = 64;
    cached = v;
    return (uint32_t)cached;
}

static uint32_t
tvu_dead_primary_ancestor_fanout(void) {
    static long cached = -1;
    if (cached >= 0) {
        return (uint32_t)cached;
    }

    const char* env = getenv("SOL_TVU_DEAD_PRIMARY_ANCESTOR_FANOUT");
    long v = 4; /* default */
    if (env && env[0] != '\0') {
        char* end = NULL;
        long parsed = strtol(env, &end, 10);
        if (end && end != env) {
            v = parsed;
        }
    }
    if (v < 1) v = 1;
    if (v > 64) v = 64;
    cached = v;
    return (uint32_t)cached;
}

static uint64_t
tvu_primary_incomplete_retry_ns(void) {
    static long cached = -1;
    if (cached >= 0) {
        return (uint64_t)cached * 1000000ULL;
    }

    /* Primary-slot safety valve: when the replay-critical slot was marked
     * INCOMPLETE earlier, periodically allow a retry even if no new shreds
     * arrived. This prevents permanent stalls when parent/fork state changed
     * after the previous attempt. Set to 0 to disable. */
    const char* env = getenv("SOL_TVU_PRIMARY_INCOMPLETE_RETRY_MS");
    long v = 750; /* default */
    if (env && env[0] != '\0') {
        char* end = NULL;
        long parsed = strtol(env, &end, 10);
        if (end && end != env) {
            v = parsed;
        }
    }
    if (v < 0) v = 0;
    if (v > 60000) v = 60000;
    cached = v;
    return (uint64_t)cached * 1000000ULL;
}

static uint64_t
tvu_primary_incomplete_same_variant_backoff_ns(void) {
    static long cached = -1;
    if (cached >= 0) {
        return (uint64_t)cached * 1000000ULL;
    }

    /* When primary replay repeatedly returns INCOMPLETE without any new
     * complete variants or new inserted shreds, apply a longer retry backoff
     * to avoid pinning replay on the same stale block variant. Set to 0 to
     * disable and keep retry cadence controlled only by
     * SOL_TVU_PRIMARY_INCOMPLETE_RETRY_MS. */
    const char* env = getenv("SOL_TVU_PRIMARY_INCOMPLETE_SAME_VARIANT_BACKOFF_MS");
    long v = 5000; /* default */
    if (env && env[0] != '\0') {
        char* end = NULL;
        long parsed = strtol(env, &end, 10);
        if (end && end != env) {
            v = parsed;
        }
    }
    if (v < 0) v = 0;
    if (v > 60000) v = 60000;
    cached = v;
    return (uint64_t)cached * 1000000ULL;
}

static uint64_t
tvu_primary_replaying_timeout_ns(void) {
    static long cached = -1;
    if (cached >= 0) {
        return (uint64_t)cached * 1000000ULL;
    }

    /* If a replay worker pins the primary slot in REPLAYING for too long,
     * force it back to COMPLETE so another worker can reclaim the attempt. */
    const char* env = getenv("SOL_TVU_PRIMARY_REPLAYING_TIMEOUT_MS");
    long v = 15000; /* default */
    if (env && env[0] != '\0') {
        char* end = NULL;
        long parsed = strtol(env, &end, 10);
        if (end && end != env) {
            v = parsed;
        }
    }
    if (v < 0) v = 0;
    if (v > 300000) v = 300000;
    cached = v;
    return (uint64_t)cached * 1000000ULL;
}

static inline uint64_t
tvu_next_replay_attempt_id_locked(sol_tvu_t* tvu) {
    tvu->replay_attempt_seq++;
    if (__builtin_expect(tvu->replay_attempt_seq == 0u, 0)) {
        tvu->replay_attempt_seq = 1u;
    }
    return tvu->replay_attempt_seq;
}

static size_t
tvu_replay_parent_probe_limit(void) {
    static long cached = -1;
    if (cached >= 0) {
        return (size_t)cached;
    }

    /* Parent-ready checks can dominate replay-loop CPU under backlog. Probe
     * only a bounded number of lowest complete slots per loop iteration. */
    const char* env = getenv("SOL_TVU_REPLAY_PARENT_PROBE_LIMIT");
    long v = 64; /* default */
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
    if (v > 512) {
        v = 512;
    }
    cached = v;
    return (size_t)cached;
}

static sol_slot_t
tvu_replay_parent_probe_high_lag(void) {
    static long cached = -1;
    if (cached >= 0) {
        return (sol_slot_t)cached;
    }

    /* When replay lag is above this threshold, reduce parent-ready probes
     * aggressively to prioritize replay execution throughput. Set to 0 to
     * disable this reduction tier. */
    const char* env = getenv("SOL_TVU_REPLAY_PARENT_PROBE_HIGH_LAG");
    long v = 256; /* default */
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

static sol_slot_t
tvu_replay_parent_probe_severe_lag(void) {
    static long cached = -1;
    if (cached >= 0) {
        return (sol_slot_t)cached;
    }

    /* When replay lag is above this threshold, skip parent-ready probes and
     * replay strictly by lowest complete slot to avoid scheduler overhead.
     * Set to 0 to disable severe-tier probe skipping. */
    const char* env = getenv("SOL_TVU_REPLAY_PARENT_PROBE_SEVERE_LAG");
    long v = 1024; /* default */
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

    long high = (long)tvu_replay_parent_probe_high_lag();
    if (v != 0 && high != 0 && v < high) {
        v = high;
    }

    cached = v;
    return (sol_slot_t)cached;
}

static size_t
tvu_replay_parent_probe_budget(sol_slot_t replay_lag, size_t complete_count) {
    size_t budget = tvu_replay_parent_probe_limit();
    if (budget == 0 || complete_count == 0) {
        return 0;
    }
    if (budget > complete_count) {
        budget = complete_count;
    }

    sol_slot_t severe_lag = tvu_replay_parent_probe_severe_lag();
    if (severe_lag != 0 && replay_lag >= severe_lag) {
        return 0;
    }

    sol_slot_t high_lag = tvu_replay_parent_probe_high_lag();
    if (high_lag != 0 && replay_lag >= high_lag) {
        const size_t reduced_budget = 16u;
        if (budget > reduced_budget) {
            budget = reduced_budget;
        }
    }

    return budget;
}

static bool
tvu_pick_smallest_unprobed_slot(const sol_slot_t* complete_slots,
                                size_t complete_count,
                                const bool* probed,
                                sol_slot_t* out_slot,
                                size_t* out_idx) {
    if (!complete_slots || !probed || !out_slot || !out_idx || complete_count == 0) {
        return false;
    }

    sol_slot_t best = 0;
    size_t best_idx = 0;
    bool found = false;
    for (size_t i = 0; i < complete_count; i++) {
        if (probed[i]) continue;
        sol_slot_t s = complete_slots[i];
        if (s == 0) continue;
        if (!found || s < best) {
            best = s;
            best_idx = i;
            found = true;
        }
    }

    if (!found) {
        return false;
    }
    *out_slot = best;
    *out_idx = best_idx;
    return true;
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
    tracker->first_received_ns = 0;
    tracker->repair_missing_cursor = 0;
    tracker->last_replay_result = SOL_REPLAY_INCOMPLETE;
    tracker->last_restart_probe_ns = 0;
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

    static size_t verify_batch_cached = 0u;
    size_t verify_batch = __atomic_load_n(&verify_batch_cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(verify_batch == 0u, 0)) {
        verify_batch = 32u;
        long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
        if (ncpu >= 128) {
            verify_batch = 192u;
        } else if (ncpu >= 64) {
            verify_batch = 128u;
        } else if (ncpu >= 32) {
            verify_batch = 64u;
        }

        const char* env = getenv("SOL_TVU_VERIFY_BATCH");
        if (env && env[0] != '\0') {
            errno = 0;
            char* end = NULL;
            unsigned long parsed = strtoul(env, &end, 10);
            if (errno == 0 && end && end != env) {
                while (*end && isspace((unsigned char)*end)) end++;
                if (*end == '\0') {
                    verify_batch = (size_t)parsed;
                }
            }
        }

        if (verify_batch < 8u) verify_batch = 8u;
        if (verify_batch > SOL_TVU_VERIFY_BATCH_MAX) {
            verify_batch = SOL_TVU_VERIFY_BATCH_MAX;
        }
        __atomic_store_n(&verify_batch_cached, verify_batch, __ATOMIC_RELEASE);
    }

    while (tvu->running) {
        shred_queue_entry_t batch[SOL_TVU_VERIFY_BATCH_MAX];
        size_t batch_n = shred_queue_pop_batch(tvu, batch, verify_batch, 100);
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
            if (tracker->first_received_ns == 0) {
                tracker->first_received_ns = entry.received_ns;
            }
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
                        tvu_mark_slot_complete_locked(tvu, tracker, slot_complete);
                        if (slot_complete) {
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
                        tvu_mark_slot_complete_locked(tvu, tracker, false);
                        tracker->replay_retry_requested = false;
                    }
                } else if (slot_complete && tracker->status == SOL_SLOT_STATUS_DEAD) {
                    /* Allow dead slots to be retried when new variants appear. */
                    if (tvu->replay && !sol_replay_is_dead(tvu->replay, shred.slot)) {
                        tvu_mark_slot_complete_locked(tvu, tracker, false);
                        tracker->replay_retry_requested = false;
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
    uint64_t replay_window_diag_ns = 0;
    uint64_t parent_missing_diag_ns = 0;
    uint64_t replay_scheduler_diag_ns = 0;
    uint64_t replay_primary_result_diag_ns = 0;
    uint64_t replay_primary_stale_diag_ns = 0;
    uint64_t replay_primary_backoff_diag_ns = 0;
    uint64_t replay_stale_result_diag_ns = 0;

    while (tvu->running) {
        /* Find slots ready for replay */
        sol_slot_t replay_slot = 0;
        uint64_t replay_attempt_id = 0;
        double replay_repair_wait_ms = 0.0;
        bool found = false;
        bool fast_mode = tvu_fast_mode();
        enum {
            SOL_TVU_RESTART_PROBE_PER_LOOP = 16,
            SOL_TVU_RESTART_PROBE_INTERVAL_NS = 250000000ULL,        /* 250ms */
            SOL_TVU_PRIMARY_RESTART_PROBE_INTERVAL_NS = 50000000ULL, /* 50ms */
            /* Keep parent-ready checks bounded under backlog. We track the
             * lowest-N complete slots, which preserves strict min-slot replay
             * ordering while avoiding expensive parent probes across all
             * tracked slots every loop. */
            SOL_TVU_REPLAY_CANDIDATE_SLOTS = 512,
        };
        sol_slot_t probe_slots[SOL_TVU_RESTART_PROBE_PER_LOOP];
        size_t probe_count = 0;
        sol_slot_t complete_slots[SOL_TVU_REPLAY_CANDIDATE_SLOTS];
        size_t complete_count = 0;
        sol_slot_t replay_window_slots[SOL_TVU_REPLAY_CANDIDATE_SLOTS];
        size_t replay_window_count = 0;
        sol_slot_t replay_cursor = 0;
        sol_slot_t replay_max_ahead = 0;
        sol_slot_t replay_primary_slot = 0;
        size_t replay_candidate_count_diag = 0;
        uint64_t loop_now_ns = now_ns();

        if (tvu->replay) {
            replay_cursor = sol_replay_highest_replayed_slot(tvu->replay);
            if (replay_cursor == 0) {
                /* During early startup, highest_replayed can be zero even though
                 * a non-zero snapshot/root exists. Use root as the replay cursor
                 * fallback so replay-window filtering is active immediately. */
                replay_cursor = sol_replay_root_slot(tvu->replay);
            }
            replay_max_ahead = tvu_effective_max_replay_ahead(tvu, replay_cursor);
            if (replay_cursor != 0) {
                sol_slot_t primary_slot = replay_cursor + 1u;
                if (primary_slot != 0 &&
                    sol_replay_is_dead(tvu->replay, primary_slot)) {
                    sol_slot_t dead_primary_ahead = tvu_primary_dead_replay_ahead_slots();
                    if (dead_primary_ahead != 0 &&
                        (replay_max_ahead == 0 || dead_primary_ahead < replay_max_ahead)) {
                        replay_max_ahead = dead_primary_ahead;
                    }
                }
            }
            replay_primary_slot = replay_cursor + 1u;
            if (replay_primary_slot == 0) {
                replay_primary_slot = replay_cursor;
            }
        }

        pthread_mutex_lock(&tvu->slots_lock);
        /* Promote any slots waiting on a now-replayed parent. */
        if (tvu->replay) {
            for (size_t i = 0; i < tvu->num_slots; i++) {
                if (tvu->slots[i].status != SOL_SLOT_STATUS_WAITING_PARENT) {
                    continue;
                }
                sol_slot_t parent_slot = tvu->slots[i].waiting_parent_slot;
                if (parent_slot == 0 || sol_replay_has_frozen_bank(tvu->replay, parent_slot)) {
                    tvu_mark_slot_complete_locked(tvu, &tvu->slots[i], false);
                }
            }
        }

        /* Safety valve: tracker churn under heavy ingress can evict the replay
         * frontier slot even when blockstore already has it complete. Ensure the
         * frontier slot remains represented so replay can make forward progress. */
        if (tvu->replay && tvu->blockstore && replay_primary_slot != 0) {
            slot_tracker_t* primary_tracker = find_slot(tvu, replay_primary_slot);
            if (!primary_tracker) {
                bool primary_slot_complete =
                    sol_blockstore_is_slot_complete(tvu->blockstore, replay_primary_slot);
                bool primary_full_contiguous = false;
                bool primary_has_data = false;
                if (!primary_slot_complete) {
                    sol_slot_meta_t meta;
                    if (sol_blockstore_get_slot_meta(tvu->blockstore, replay_primary_slot, &meta) == SOL_OK &&
                        meta.is_full) {
                        uint32_t missing_idx = 0;
                        size_t missing_count = sol_blockstore_get_missing_shreds(
                            tvu->blockstore, replay_primary_slot, &missing_idx, 1u);
                        primary_full_contiguous = (missing_count == 0);
                    }
                }
                if (!primary_slot_complete && fast_mode) {
                    sol_slot_meta_t meta;
                    if (sol_blockstore_get_slot_meta(tvu->blockstore, replay_primary_slot, &meta) == SOL_OK &&
                        meta.received_data > 0) {
                        primary_has_data = true;
                    }
                }

                if (primary_slot_complete ||
                    primary_full_contiguous ||
                    (fast_mode && primary_has_data)) {
                    primary_tracker = find_or_create_slot(tvu, replay_primary_slot);
                    if (primary_tracker) {
                        if (primary_tracker->first_received_ns == 0) {
                            primary_tracker->first_received_ns = loop_now_ns;
                        }
                        primary_tracker->last_received_ns = loop_now_ns;
                        primary_tracker->last_inserted_ns = loop_now_ns;
                        tvu_mark_slot_complete_locked(tvu, primary_tracker, false);
                    }
                }
            }
        }

        for (size_t i = 0; i < tvu->num_slots; i++) {
            slot_tracker_t* tracker = &tvu->slots[i];

            if (tvu->replay &&
                replay_primary_slot != 0 &&
                tracker->slot == replay_primary_slot &&
                tracker->status == SOL_SLOT_STATUS_REPLAYING) {
                uint64_t timeout_ns = tvu_primary_replaying_timeout_ns();
                if (timeout_ns != 0 &&
                    tracker->replay_started_ns != 0 &&
                    loop_now_ns >= tracker->replay_started_ns &&
                    (loop_now_ns - tracker->replay_started_ns) >= timeout_ns &&
                    !sol_replay_is_replayed(tvu->replay, tracker->slot) &&
                    !sol_replay_is_dead(tvu->replay, tracker->slot)) {
                    uint64_t age_ms = (loop_now_ns - tracker->replay_started_ns) / 1000000ULL;
                    tvu_mark_slot_complete_locked(tvu, tracker, false);
                    tracker->replay_retry_requested = false;
                    if (replay_primary_stale_diag_ns == 0 ||
                        (loop_now_ns - replay_primary_stale_diag_ns) >= 1000000000ULL) {
                        sol_log_warn("Replay primary stale in REPLAYING: slot=%lu age_ms=%lu; forcing reschedule",
                                     (unsigned long)tracker->slot,
                                     (unsigned long)age_ms);
                        replay_primary_stale_diag_ns = loop_now_ns;
                    }
                }
            }

            if (tvu->replay &&
                tvu->blockstore &&
                replay_primary_slot != 0 &&
                tracker->slot == replay_primary_slot &&
                tracker->status == SOL_SLOT_STATUS_RECEIVING) {
                bool primary_slot_complete =
                    sol_blockstore_is_slot_complete(tvu->blockstore, tracker->slot);
                bool primary_full_contiguous = false;
                bool primary_meta_full_noncontiguous = false;
                if (!primary_slot_complete) {
                    sol_slot_meta_t meta;
                    if (sol_blockstore_get_slot_meta(tvu->blockstore, tracker->slot, &meta) == SOL_OK &&
                        meta.is_full) {
                        uint32_t missing_idx = 0;
                        size_t missing_count = sol_blockstore_get_missing_shreds(
                            tvu->blockstore, tracker->slot, &missing_idx, 1u);
                        primary_full_contiguous = (missing_count == 0);
                        primary_meta_full_noncontiguous = (missing_count > 0);
                    }
                }

                uint64_t retry_ns = tvu_primary_incomplete_retry_ns();
                uint64_t since_last_replay_ns = 0;
                if (tracker->last_replay_ns != 0 && loop_now_ns >= tracker->last_replay_ns) {
                    since_last_replay_ns = loop_now_ns - tracker->last_replay_ns;
                }

                uint64_t last_progress_ns = tracker->last_inserted_ns
                    ? tracker->last_inserted_ns
                    : (tracker->last_received_ns
                        ? tracker->last_received_ns
                        : tracker->first_received_ns);
                uint64_t stall_ns = 0;
                if (last_progress_ns != 0 && loop_now_ns >= last_progress_ns) {
                    stall_ns = loop_now_ns - last_progress_ns;
                }

                bool retry_due_incomplete =
                    tracker->last_replay_result == SOL_REPLAY_INCOMPLETE &&
                    tracker->last_replay_ns != 0 &&
                    (retry_ns == 0 || since_last_replay_ns >= retry_ns) &&
                    (tracker->last_inserted_ns == 0 ||
                     tracker->last_inserted_ns <= tracker->last_replay_ns);

                /* Safety valve: if the primary slot is complete in blockstore but
                 * replay scheduling state lost track of it (e.g. tracker churn),
                 * periodically force it back into COMPLETE so replay can retry. */
                uint64_t stall_retry_ns = retry_ns ? retry_ns : 750000000ULL;
                bool retry_due_stall =
                    (stall_ns >= stall_retry_ns) &&
                    (tracker->last_replay_ns == 0 ||
                     retry_ns == 0 ||
                     since_last_replay_ns >= retry_ns);

                bool retry_due_initial = (tracker->last_replay_ns == 0);

                bool stale_variant_backoff = false;
                if (tracker->last_replay_result == SOL_REPLAY_INCOMPLETE &&
                    tracker->last_replay_ns != 0 &&
                    (tracker->last_inserted_ns == 0 ||
                     tracker->last_inserted_ns <= tracker->last_replay_ns)) {
                    uint32_t complete_variants =
                        tvu_count_complete_variants(tvu->blockstore, tracker->slot);
                    if (complete_variants <= tracker->last_replay_complete_variants) {
                        uint64_t backoff_ns = tvu_primary_incomplete_same_variant_backoff_ns();
                        stale_variant_backoff = (backoff_ns != 0 &&
                                                 since_last_replay_ns < backoff_ns);
                        if (stale_variant_backoff &&
                            (replay_primary_backoff_diag_ns == 0 ||
                             (loop_now_ns - replay_primary_backoff_diag_ns) >= 1000000000ULL)) {
                            uint64_t remaining_ms =
                                (backoff_ns - since_last_replay_ns) / 1000000ULL;
                            sol_log_debug("Replay primary backoff: slot=%lu result=%d variants=%u prev_variants=%u wait_ms=%lu",
                                          (unsigned long)tracker->slot,
                                          (int)tracker->last_replay_result,
                                          (unsigned)complete_variants,
                                          (unsigned)tracker->last_replay_complete_variants,
                                          (unsigned long)remaining_ms);
                            replay_primary_backoff_diag_ns = loop_now_ns;
                        }
                    }
                }

                bool primary_consider_replay = primary_slot_complete || primary_full_contiguous;
                if (!primary_consider_replay &&
                    primary_meta_full_noncontiguous &&
                    stall_ns >= 1500000000ULL &&
                    (tracker->last_replay_ns == 0 ||
                     retry_ns == 0 ||
                     since_last_replay_ns >= retry_ns)) {
                    /* Some duplicate-variant states report "full" metadata while
                     * still exposing sparse missing sets. Probe replay under deep
                     * stall to avoid waiting indefinitely on repair convergence. */
                    primary_consider_replay = true;
                }

                if (stale_variant_backoff) {
                    retry_due_incomplete = false;
                    retry_due_stall = false;
                }

                if (primary_consider_replay &&
                    (retry_due_initial || retry_due_incomplete || retry_due_stall)) {
                    tvu_mark_slot_complete_locked(tvu, tracker, false);
                }
            }

            if (tracker->status != SOL_SLOT_STATUS_COMPLETE) {
                continue;
            }
            sol_slot_t slot = tracker->slot;
            tvu_collect_smallest_slot_candidates(complete_slots,
                                                 &complete_count,
                                                 SOL_TVU_REPLAY_CANDIDATE_SLOTS,
                                                 slot);
            if (tvu_slot_in_replay_window(slot, replay_cursor, replay_max_ahead)) {
                tvu_collect_smallest_slot_candidates(replay_window_slots,
                                                     &replay_window_count,
                                                     SOL_TVU_REPLAY_CANDIDATE_SLOTS,
                                                     slot);
            }
        }
        if (complete_count == 0) {
            /* Best-effort restart probe: identify a small number of RECEIVING
             * slots with no shreds observed in this run and check persisted
             * blockstore state outside the slot lock. */
            if (tvu->blockstore) {
                if (replay_primary_slot != 0 && probe_count < SOL_TVU_RESTART_PROBE_PER_LOOP) {
                    slot_tracker_t* t = find_slot(tvu, replay_primary_slot);
                    if (t &&
                        t->status == SOL_SLOT_STATUS_RECEIVING &&
                        t->slot != 0 &&
                        t->shreds_received == 0u) {
                        bool primary_probe_due =
                            (t->last_restart_probe_ns == 0) ||
                            (loop_now_ns >= t->last_restart_probe_ns &&
                             (loop_now_ns - t->last_restart_probe_ns) >=
                                 SOL_TVU_PRIMARY_RESTART_PROBE_INTERVAL_NS);
                        if (primary_probe_due) {
                            t->last_restart_probe_ns = loop_now_ns;
                            probe_slots[probe_count++] = t->slot;
                        }
                    }
                }
                for (size_t i = 0; i < tvu->num_slots && probe_count < SOL_TVU_RESTART_PROBE_PER_LOOP; i++) {
                    slot_tracker_t* t = &tvu->slots[i];
                    if (t->status != SOL_SLOT_STATUS_RECEIVING) continue;
                    if (t->slot == 0) continue;
                    if (t->shreds_received != 0u) continue;
                    if (replay_primary_slot != 0 && t->slot == replay_primary_slot) continue;
                    if (t->last_restart_probe_ns != 0 &&
                        loop_now_ns >= t->last_restart_probe_ns &&
                        (loop_now_ns - t->last_restart_probe_ns) <
                            SOL_TVU_RESTART_PROBE_INTERVAL_NS) {
                        continue;
                    }
                    t->last_restart_probe_ns = loop_now_ns;
                    probe_slots[probe_count++] = t->slot;
                }
            }
        }
        pthread_mutex_unlock(&tvu->slots_lock);

        if (complete_count > 0) {
            const sol_slot_t* replay_candidates = complete_slots;
            size_t replay_candidate_count = complete_count;
            if (replay_cursor != 0 && replay_max_ahead != 0) {
                replay_candidates = replay_window_slots;
                replay_candidate_count = replay_window_count;
                if (replay_candidate_count == 0) {
                    uint64_t now = now_ns();
                    if (replay_window_diag_ns == 0 ||
                        (now - replay_window_diag_ns) >= 1000000000ULL) {
                        sol_log_debug("TVU replay window filtered all complete slots: "
                                      "cursor=%lu max_ahead=%lu complete=%zu",
                                      (unsigned long)replay_cursor,
                                      (unsigned long)replay_max_ahead,
                                      complete_count);
                        replay_window_diag_ns = now;
                    }
                }
            }
            replay_candidate_count_diag = replay_candidate_count;

            sol_slot_t best_any = 0;
            sol_slot_t best_parent_ready = 0;
            for (size_t i = 0; i < replay_candidate_count; i++) {
                sol_slot_t s = replay_candidates[i];
                if (s == 0) continue;
                if (best_any == 0 || s < best_any) {
                    best_any = s;
                }
            }

            if (best_any != 0 && tvu->replay) {
                sol_slot_t replay_lag = 0;
                if (tvu->blockstore) {
                    sol_slot_t highest_blockstore = sol_blockstore_highest_slot(tvu->blockstore);
                    sol_slot_t highest_replayed = sol_replay_highest_replayed_slot(tvu->replay);
                    replay_lag = highest_blockstore > highest_replayed
                        ? (highest_blockstore - highest_replayed)
                        : 0;
                }

                size_t parent_probe_budget =
                    tvu_replay_parent_probe_budget(replay_lag, replay_candidate_count);
                if (parent_probe_budget > 0) {
                    bool probed[SOL_TVU_REPLAY_CANDIDATE_SLOTS];
                    memset(probed, 0, sizeof(probed));

                    for (size_t probe_i = 0; probe_i < parent_probe_budget; probe_i++) {
                        sol_slot_t probe_slot = 0;
                        size_t probe_idx = 0;
                        if (!tvu_pick_smallest_unprobed_slot(replay_candidates,
                                                             replay_candidate_count,
                                                             probed,
                                                             &probe_slot,
                                                             &probe_idx)) {
                            break;
                        }

                        probed[probe_idx] = true;
                        if (sol_replay_parent_ready(tvu->replay, probe_slot, NULL)) {
                            best_parent_ready = probe_slot;
                            break;
                        }
                    }
                }
            }

            replay_slot = best_parent_ready ? best_parent_ready : best_any;
            if (replay_slot != 0) {
                pthread_mutex_lock(&tvu->slots_lock);
                slot_tracker_t* tracker = find_slot(tvu, replay_slot);
                if (tracker && tracker->status == SOL_SLOT_STATUS_COMPLETE) {
                    if (tracker->first_received_ns != 0) {
                        uint64_t done_ns = tracker->first_complete_ns;
                        if (done_ns == 0) {
                            done_ns = now_ns();
                        }
                        if (done_ns >= tracker->first_received_ns) {
                            replay_repair_wait_ms =
                                (double)(done_ns - tracker->first_received_ns) / 1000000.0;
                        }
                    }
                    if (tvu->blockstore) {
                        tracker->last_replay_complete_variants =
                            tvu_count_complete_variants(tvu->blockstore, replay_slot);
                    }
                    tracker->status = SOL_SLOT_STATUS_REPLAYING;
                    tracker->waiting_parent_slot = 0;
                    tracker->replay_started_ns = now_ns();
                    tracker->replay_attempt_id = tvu_next_replay_attempt_id_locked(tvu);
                    replay_attempt_id = tracker->replay_attempt_id;
                    found = true;
                }
                pthread_mutex_unlock(&tvu->slots_lock);
            }
        }

        if ((complete_count > 0 || replay_candidate_count_diag > 0) &&
            (replay_scheduler_diag_ns == 0 ||
             (loop_now_ns - replay_scheduler_diag_ns) >= 1000000000ULL)) {
            if (!found) {
                sol_log_info("Replay scheduler stalled: complete=%zu candidates=%zu replay_slot=%lu primary=%lu",
                             complete_count,
                             replay_candidate_count_diag,
                             (unsigned long)replay_slot,
                             (unsigned long)replay_primary_slot);
            } else if (replay_slot == replay_primary_slot && replay_primary_slot != 0) {
                sol_log_info("Replay primary scheduled: slot=%lu complete=%zu candidates=%zu",
                             (unsigned long)replay_slot,
                             complete_count,
                             replay_candidate_count_diag);
            }
            replay_scheduler_diag_ns = loop_now_ns;
        }

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

                    tvu_mark_slot_complete_locked(tvu, t, probed_complete[i]);
                }
                pthread_mutex_unlock(&tvu->slots_lock);

                /* We may have queued slots as COMPLETE; loop again without sleeping. */
                continue;
            }

            long idle_ns = tvu_replay_idle_sleep_ns();
            if (idle_ns > 0) {
                struct timespec ts = {
                    .tv_sec = idle_ns / 1000000000L,
                    .tv_nsec = idle_ns % 1000000000L,
                };
                nanosleep(&ts, NULL);
            }
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
                tvu_record_replay_stage_metrics(tvu, &replay_info, replay_repair_wait_ms);
            } else if (replay_result == SOL_REPLAY_DUPLICATE) {
                sol_log_debug("Slot %lu replay already complete", (unsigned long)replay_slot);
            } else if (replay_result == SOL_REPLAY_DEAD) {
                __atomic_fetch_add(&tvu->stats.blocks_failed, 1, __ATOMIC_RELAXED);
                sol_log_warn("Slot %lu replay failed: %d", (unsigned long)replay_slot, replay_result);
            } else if (replay_result == SOL_REPLAY_PARENT_MISSING) {
                uint64_t now = now_ns();
                if (replay_slot == replay_primary_slot &&
                    (parent_missing_diag_ns == 0 ||
                     (now - parent_missing_diag_ns) >= 1000000000ULL)) {
                    bool parent_frozen =
                        sol_replay_has_frozen_bank(tvu->replay, replay_info.parent_slot);
                    sol_log_info("Replay primary blocked: slot=%lu parent=%lu parent_frozen=%s",
                                 (unsigned long)replay_slot,
                                 (unsigned long)replay_info.parent_slot,
                                 parent_frozen ? "yes" : "no");
                    parent_missing_diag_ns = now;
                }
                sol_log_debug("Slot %lu waiting for parent %lu",
                              (unsigned long)replay_slot,
                              (unsigned long)replay_info.parent_slot);
            }

            if (replay_slot == replay_primary_slot &&
                replay_result != SOL_REPLAY_SUCCESS &&
                replay_result != SOL_REPLAY_DUPLICATE) {
                uint64_t now = now_ns();
                if (replay_primary_result_diag_ns == 0 ||
                    (now - replay_primary_result_diag_ns) >= 1000000000ULL) {
                    sol_log_info("Replay primary result: slot=%lu result=%d parent=%lu",
                                 (unsigned long)replay_slot,
                                 (int)replay_result,
                                 (unsigned long)replay_info.parent_slot);
                    replay_primary_result_diag_ns = now;
                }
            }
        }

        /* Update slot status */
        pthread_mutex_lock(&tvu->slots_lock);
        slot_tracker_t* tracker = find_slot(tvu, replay_slot);
        uint64_t prev_replay_ns = tracker ? tracker->last_replay_ns : 0;
        uint64_t current_attempt_id = tracker ? tracker->replay_attempt_id : 0;
        bool stale_attempt_result =
            tracker && replay_attempt_id != 0 && current_attempt_id != replay_attempt_id;
        if (tracker && !stale_attempt_result) {
            bool retry_requested = tracker->replay_retry_requested;
            tracker->replay_retry_requested = false;
            tracker->waiting_parent_slot = 0;
            tracker->last_replay_result = replay_result;
            tracker->last_replay_ns = now_ns();
            tracker->replay_started_ns = 0;
            tracker->replay_attempt_id = 0;

            if (replay_result == SOL_REPLAY_PARENT_MISSING) {
                tracker->status = SOL_SLOT_STATUS_WAITING_PARENT;
                tracker->waiting_parent_slot = replay_info.parent_slot;
            } else if (ok) {
                if (retry_requested &&
                    tvu->replay &&
                    !sol_replay_is_replayed(tvu->replay, replay_slot) &&
                    tvu->blockstore &&
                    sol_blockstore_is_slot_complete(tvu->blockstore, replay_slot)) {
                    tvu_mark_slot_complete_locked(tvu, tracker, false);
                } else {
                    tracker->status = SOL_SLOT_STATUS_REPLAYED;
                }
            } else {
                if (retry_requested &&
                    tvu->replay &&
                    !sol_replay_is_dead(tvu->replay, replay_slot) &&
                    tvu->blockstore &&
                    sol_blockstore_is_slot_complete(tvu->blockstore, replay_slot)) {
                    tvu_mark_slot_complete_locked(tvu, tracker, false);
                } else if (replay_result == SOL_REPLAY_INCOMPLETE) {
                    tracker->status = SOL_SLOT_STATUS_RECEIVING;
                    tracker->first_complete_ns = 0;
                } else {
                    tracker->status = SOL_SLOT_STATUS_DEAD;
                }
            }
        }
        pthread_mutex_unlock(&tvu->slots_lock);

        if (stale_attempt_result) {
            uint64_t now = now_ns();
            if (replay_stale_result_diag_ns == 0 ||
                (now - replay_stale_result_diag_ns) >= 1000000000ULL) {
                sol_log_debug("Replay stale attempt result ignored: slot=%lu attempt=%lu current_attempt=%lu result=%d",
                              (unsigned long)replay_slot,
                              (unsigned long)replay_attempt_id,
                              (unsigned long)current_attempt_id,
                              (int)replay_result);
                replay_stale_result_diag_ns = now;
            }
            continue;
        }

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
 * Async pre-replay warming thread
 */
static void*
prewarm_thread_func(void* arg) {
    tvu_prewarm_thread_ctx_t* ctx = (tvu_prewarm_thread_ctx_t*)arg;
    sol_tvu_t* tvu = ctx ? ctx->tvu : NULL;
    uint32_t thread_idx = ctx ? ctx->thread_idx : 0;
    if (!tvu) {
        return NULL;
    }

    uint64_t last_diag_ns = 0;
    while (tvu->running) {
        struct timespec ts = {0, 250000}; /* 250us */
        nanosleep(&ts, NULL);

        if (!tvu->replay || !tvu->blockstore) {
            continue;
        }

        enum {
            SOL_TVU_PREWARM_LOOKAHEAD_SLOTS = 512,
            SOL_TVU_PREWARM_BATCH_SLOTS = 32,
            SOL_TVU_PREWARM_MIN_INTERVAL_NS = 20000000ULL, /* 20ms */
            SOL_TVU_PREWARM_REVISIT_NS = 250000000ULL,     /* 250ms */
        };

        uint32_t thread_count = (uint32_t)tvu->prewarm_thread_count;
        if (thread_count == 0) {
            thread_count = 1;
        }

        uint64_t now = now_ns();
        sol_slot_t replay_cursor = sol_replay_highest_replayed_slot(tvu->replay);
        if (replay_cursor == 0) {
            continue;
        }
        sol_slot_t start_slot = replay_cursor + 1;
        sol_slot_t end_slot = replay_cursor + (sol_slot_t)SOL_TVU_PREWARM_LOOKAHEAD_SLOTS;

        sol_slot_t slots[SOL_TVU_PREWARM_BATCH_SLOTS];
        size_t slots_len = 0;

        pthread_mutex_lock(&tvu->slots_lock);
        for (size_t i = 0; i < tvu->num_slots && slots_len < SOL_TVU_PREWARM_BATCH_SLOTS; i++) {
            slot_tracker_t* tracker = &tvu->slots[i];
            if (!tracker || tracker->slot == 0) continue;
            if (tracker->slot < start_slot || tracker->slot > end_slot) continue;
            if (tracker->status != SOL_SLOT_STATUS_RECEIVING &&
                tracker->status != SOL_SLOT_STATUS_COMPLETE &&
                tracker->status != SOL_SLOT_STATUS_WAITING_PARENT) {
                continue;
            }
            if ((tracker->slot % thread_count) != thread_idx) {
                continue;
            }

            uint64_t since_warm_ns = tracker->last_prewarm_ns
                ? (now >= tracker->last_prewarm_ns ? (now - tracker->last_prewarm_ns) : 0)
                : UINT64_MAX;
            if (tracker->last_prewarm_ns != 0 && since_warm_ns < SOL_TVU_PREWARM_MIN_INTERVAL_NS) {
                continue;
            }

            bool has_new_inserted =
                tracker->last_inserted_ns != 0 &&
                tracker->last_inserted_ns > tracker->last_prewarm_ns;
            bool initial = tracker->last_prewarm_ns == 0;
            bool revisit_completeish =
                tracker->status != SOL_SLOT_STATUS_RECEIVING &&
                since_warm_ns >= SOL_TVU_PREWARM_REVISIT_NS;

            if (!(initial || has_new_inserted || revisit_completeish)) {
                continue;
            }

            tracker->last_prewarm_ns = now;
            slots[slots_len++] = tracker->slot;
        }
        pthread_mutex_unlock(&tvu->slots_lock);

        size_t warmed = 0;
        for (size_t i = 0; i < slots_len; i++) {
            if (!tvu->running) {
                break;
            }
            if (sol_replay_prewarm_slot(tvu->replay, slots[i])) {
                warmed++;
            }
        }

        if (warmed > 0 &&
            (last_diag_ns == 0 || (now - last_diag_ns) >= 1000000000ULL)) {
            sol_log_debug("TVU prewarm thread=%u warmed=%zu cursor=%lu",
                          (unsigned)thread_idx,
                          warmed,
                          (unsigned long)replay_cursor);
            last_diag_ns = now;
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
    uint64_t last_primary_pending_reset_ns = 0;

    while (tvu->running) {
        struct timespec ts = {0, 250000};  /* 250us */
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
        size_t pending_target = max_pending / 4u;
        if (pending_target < 2048u) {
            pending_target = 2048u;
        }
        bool pending_saturated = pending >= pending_target;
        uint32_t thread_count = (uint32_t)tvu->repair_thread_count;
        if (thread_count == 0) {
            thread_count = 1;
        }

        bool strict_primary = false;
        bool strict_due_pending = false;
        uint64_t primary_stall_ms_hint = 0;
        size_t primary_missing_hint = 0;
        bool primary_missing_hint_valid = false;
        bool primary_meta_full_hint = false;

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
                    SOL_TVU_CATCHUP_WINDOW_SLOTS = 128,
                    /* When the primary (next) slot is incomplete, shrink the repair
                     * window further to keep requests tightly focused. */
                    SOL_TVU_PRIMARY_REPAIR_WINDOW_SLOTS = 96,
                    /* Enter strict-primary mode sooner so far-ahead requests don't
                     * starve the blocked replay-critical slot. */
                    SOL_TVU_PRIMARY_STRICT_PENDING_MIN = 2048,
                    SOL_TVU_PRIMARY_STRICT_STALL_MS = 1000,
                    SOL_TVU_PRIMARY_STRICT_KEEP_SLOTS = 16,
                    SOL_TVU_PRIMARY_STRICT_KEEP_STALLED_SLOTS = 8,
                    /* Missing-heavy primary slots need tighter focus than
                     * stall/pending checks alone; otherwise far-ahead repair
                     * churn can dominate request bandwidth. */
                    SOL_TVU_PRIMARY_STRICT_MISSING_MIN = 1024,
                    SOL_TVU_PRIMARY_STRICT_KEEP_HEAVY_SLOTS = 16,
                    SOL_TVU_PRIMARY_STRICT_KEEP_SEVERE_SLOTS = 8,
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
                    if (focus_primary) {
                        /* If the replay-critical slot hasn't progressed recently,
                         * tighten repair scope even before pending grows huge. */
                        pthread_mutex_lock(&tvu->slots_lock);
                        slot_tracker_t* primary_tracker = find_slot(tvu, primary_slot);
                        if (primary_tracker) {
                            uint64_t last_progress_ns = primary_tracker->last_inserted_ns
                                ? primary_tracker->last_inserted_ns
                                : (primary_tracker->last_received_ns
                                    ? primary_tracker->last_received_ns
                                    : primary_tracker->first_received_ns);
                            if (last_progress_ns != 0 &&
                                now >= last_progress_ns) {
                                primary_stall_ms_hint =
                                    (now - last_progress_ns) / 1000000ULL;
                            }
                        }
                        pthread_mutex_unlock(&tvu->slots_lock);

                        /* Missing-heavy primaries should enter strict mode
                         * immediately, even if they are still receiving some
                         * progress and therefore do not look "stalled". */
                        if (tvu->blockstore) {
                            uint32_t missing_probe[SOL_TVU_PRIMARY_STRICT_MISSING_MIN];
                            primary_missing_hint = sol_blockstore_get_missing_shreds(
                                tvu->blockstore,
                                primary_slot,
                                missing_probe,
                                SOL_TVU_PRIMARY_STRICT_MISSING_MIN);
                            primary_missing_hint_valid = true;

                            sol_slot_meta_t primary_meta;
                            if (sol_blockstore_get_slot_meta(tvu->blockstore, primary_slot, &primary_meta) == SOL_OK) {
                                primary_meta_full_hint = primary_meta.is_full;
                            }
                        }

                        /* When pending backlog grows too large, aggressive
                         * lookahead can starve the blocked next slot. */
                        size_t strict_threshold = max_pending / 3u;
                        if (strict_threshold < (size_t)SOL_TVU_PRIMARY_STRICT_PENDING_MIN) {
                            strict_threshold = (size_t)SOL_TVU_PRIMARY_STRICT_PENDING_MIN;
                        }
                        if (pending >= strict_threshold ||
                            primary_stall_ms_hint >= (uint64_t)SOL_TVU_PRIMARY_STRICT_STALL_MS ||
                            (primary_missing_hint_valid &&
                             primary_missing_hint >= (size_t)SOL_TVU_PRIMARY_STRICT_MISSING_MIN) ||
                            (primary_meta_full_hint &&
                             primary_missing_hint_valid &&
                             primary_missing_hint >= 32u)) {
                            strict_primary = true;
                            if (pending >= strict_threshold) {
                                strict_due_pending = true;
                            }
                        }
                    }
		            if (focus_primary && catchup_end != 0) {
		                sol_slot_t end = primary_slot + (sol_slot_t)SOL_TVU_PRIMARY_REPAIR_WINDOW_SLOTS;
		                if (end >= primary_slot && end < catchup_end) {
		                    catchup_end = end;
		                }
		            }
		        }

        bool pending_pressure_medium =
            (max_pending > 0u) && (pending >= ((max_pending * 5u) / 10u));
        bool pending_pressure_high =
            (max_pending > 0u) && (pending >= ((max_pending * 7u) / 10u));
        if (pending_saturated && !pending_pressure_medium) {
            pending_pressure_medium = true;
        }

        if (catchup_start != 0 && catchup_end >= catchup_start && pending_pressure_medium) {
            sol_slot_t pressure_keep = focus_primary ? 48u : 64u;
            sol_slot_t pressure_end = catchup_start + pressure_keep;
            if (pressure_end >= catchup_start && pressure_end < catchup_end) {
                catchup_end = pressure_end;
            }
        }

        if (strict_primary && focus_primary && primary_slot != 0 && thread_idx == 0) {
            /* Keep repair queue centered on the replay-critical window. */
            sol_slot_t keep_span =
                (primary_stall_ms_hint >= (uint64_t)SOL_TVU_PRIMARY_STRICT_STALL_MS)
                    ? (sol_slot_t)SOL_TVU_PRIMARY_STRICT_KEEP_STALLED_SLOTS
                    : (sol_slot_t)SOL_TVU_PRIMARY_STRICT_KEEP_SLOTS;
            if (strict_due_pending && keep_span > 8u) {
                keep_span = 8u;
            }
            if (primary_missing_hint_valid &&
                primary_missing_hint >= (size_t)(SOL_TVU_PRIMARY_STRICT_MISSING_MIN * 2u)) {
                keep_span = (sol_slot_t)SOL_TVU_PRIMARY_STRICT_KEEP_SEVERE_SLOTS;
            } else if (primary_missing_hint_valid &&
                       primary_missing_hint >= (size_t)SOL_TVU_PRIMARY_STRICT_MISSING_MIN) {
                keep_span = (sol_slot_t)SOL_TVU_PRIMARY_STRICT_KEEP_HEAVY_SLOTS;
            }
            sol_slot_t keep_max = primary_slot + keep_span;
            if (keep_max < primary_slot) keep_max = 0;
            size_t pruned = sol_repair_prune_pending_outside_window(tvu->repair, primary_slot, keep_max);
            if (pruned > 0 &&
                (last_thread_diag_ns == 0 || (now - last_thread_diag_ns) >= 1000000000ULL)) {
                sol_log_debug("TVU strict-primary prune: primary=%lu kept=[%lu..%lu] pruned=%zu",
                              (unsigned long)primary_slot,
                              (unsigned long)primary_slot,
                              (unsigned long)keep_max,
                              pruned);
                last_thread_diag_ns = now;
            }
            pending = sol_repair_pending_count(tvu->repair);
            headroom = (max_pending > pending) ? (max_pending - pending) : 0;
            if (headroom == 0) {
                continue;
            }
        }

        if (!strict_primary &&
            thread_idx == 0 &&
            catchup_start != 0 &&
            catchup_end >= catchup_start &&
            pending_pressure_high) {
            /* Under sustained high pending pressure, aggressively evict
             * far-ahead requests to preserve headroom for the replay frontier. */
            sol_slot_t keep_span = focus_primary ? 48u : 64u;
            sol_slot_t keep_max = catchup_start + keep_span;
            if (keep_max < catchup_start) {
                keep_max = 0;
            }
            size_t pruned = sol_repair_prune_pending_outside_window(tvu->repair, catchup_start, keep_max);
            if (pruned > 0 &&
                (last_thread_diag_ns == 0 || (now - last_thread_diag_ns) >= 1000000000ULL)) {
                sol_log_debug("TVU pressure prune: keep=[%lu..%lu] pruned=%zu pending=%zu/%zu",
                              (unsigned long)catchup_start,
                              (unsigned long)keep_max,
                              pruned,
                              pending,
                              max_pending);
                last_thread_diag_ns = now;
            }
            pending = sol_repair_pending_count(tvu->repair);
            headroom = (max_pending > pending) ? (max_pending - pending) : 0;
            if (headroom == 0) {
                continue;
            }
            pending_saturated = pending >= pending_target;
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
                    SOL_TVU_CATCHUP_MIN_INTERVAL_MS = 1,
                    SOL_TVU_INITIAL_SHRED_BURST_PRIMARY = 256,
                    SOL_TVU_INITIAL_SHRED_BURST_OTHER = 32,
                    /* When the primary slot is incomplete, we still want to prefetch a
                     * small lookahead window so replay doesn't immediately stall on the
                     * next slot.  HighestShred is cheap and deduped by the repair service. */
                    SOL_TVU_PRIMARY_PREFETCH_SLOTS = 12,
                    SOL_TVU_PRIMARY_PREFETCH_FANOUT = 6,
                };

	        repair_action_t actions[SOL_TVU_MAX_REPAIR_ACTIONS];
        size_t action_count = 0;
        size_t action_budget = headroom;
        bool primary_pending_reset = false;
        sol_slot_t primary_pending_reset_slot = 0;
        size_t primary_pending_reset_missing = 0;
        bool primary_missing_heavy = focus_primary && primary_slot != 0 &&
                                     primary_missing_hint_valid &&
                                     primary_missing_hint >= 96u;
        bool primary_missing_severe = focus_primary && primary_slot != 0 &&
                                      primary_missing_hint_valid &&
                                      primary_missing_hint >= 192u;

        uint32_t primary_prefetch_slots = (uint32_t)SOL_TVU_PRIMARY_PREFETCH_SLOTS;
        if (max_pending > 0u && pending >= ((max_pending * 3u) / 4u)) {
            primary_prefetch_slots = 0u;
        }
        if (primary_missing_severe) {
            if (primary_prefetch_slots > 4u) primary_prefetch_slots = 4u;
        } else if (primary_missing_heavy && primary_prefetch_slots > 8u) {
            primary_prefetch_slots = 8u;
        }
        if (thread_count > 1) {
            if (strict_primary &&
                focus_primary && primary_slot != 0) {
                action_budget = (thread_idx == 0) ? headroom : 0;
            } else if (focus_primary && primary_slot != 0) {
                /* Prioritize repairing the next replay slot, but keep a small
                 * portion of bandwidth for prefetching ahead so replay doesn't
                 * stall between slots. */
                size_t primary_budget = (headroom * 80u) / 100u;
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
        if (pending_saturated && thread_idx != 0) {
            action_budget = 0;
        }
        if (pending_pressure_medium && thread_idx != 0) {
            action_budget = 0;
        }
        {
            /* Bound per-loop request generation to avoid saturating pending
             * with far-ahead requests under high ingress. */
            size_t loop_cap = 256u;
            if (focus_primary && primary_slot != 0) {
                loop_cap = (strict_primary || primary_missing_heavy) ? 1024u : 768u;
            }
            if (pending_pressure_medium) {
                loop_cap = focus_primary ? 256u : 96u;
            }
            if (action_budget > loop_cap) {
                action_budget = loop_cap;
            }
        }
        if (pending_saturated) {
            size_t sat_cap = focus_primary ? 128u : 32u;
            if (action_budget > sat_cap) {
                action_budget = sat_cap;
            }
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
                    if (strict_primary) {
                        continue;
                    }
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

            uint64_t primary_interval_ms = 0;
            if (focus_primary && is_primary_slot && primary_missing_hint_valid) {
                if (primary_missing_hint >= 96u) {
                    primary_interval_ms = strict_primary ? 2u : 1u;
                } else if (primary_missing_hint >= 32u) {
                    primary_interval_ms = 1u;
                }
            }

            if (focus_primary && is_primary_slot) {
                if (since_req_ms < primary_interval_ms) {
                    continue;
                }
            } else if (since_req_ms < min_interval_ms) {
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
                bool dead_primary = focus_primary && is_primary_slot;

                sol_slot_meta_t meta;
                uint32_t first_idx = 0;
                uint32_t last_idx = 0;
                bool have_meta = tvu->blockstore &&
                                 sol_blockstore_get_slot_meta(tvu->blockstore, tracker->slot, &meta) == SOL_OK;
                if (have_meta) {
                    first_idx = meta.first_shred_index;
                    last_idx = meta.last_shred_index;
                }

                uint32_t duplicate_fanout = dead_primary
                    ? tvu_dead_primary_duplicate_fanout()
                    : 6u;
                uint32_t highest_fanout = dead_primary
                    ? tvu_dead_primary_highest_fanout()
                    : 6u;
                uint64_t highest_start = have_meta ? ((uint64_t)last_idx + 1u) : 0u;

                /* Request a couple of deterministic indices to encourage peers
                 * to return any conflicting shreds we might have missed. */
                actions[action_count++] = (repair_action_t){
                    .type = SOL_REPAIR_SHRED,
                    .slot = tracker->slot,
                    .shred_index = first_idx,
                    .fanout = duplicate_fanout,
                };

                if (action_count < action_budget &&
                    have_meta &&
                    last_idx != first_idx) {
                    actions[action_count++] = (repair_action_t){
                        .type = SOL_REPAIR_SHRED,
                        .slot = tracker->slot,
                        .shred_index = last_idx,
                        .fanout = duplicate_fanout,
                    };
                }

                if (action_count < action_budget &&
                    have_meta &&
                    last_idx > first_idx + 1u) {
                    uint32_t mid_idx = first_idx + ((last_idx - first_idx) / 2u);
                    actions[action_count++] = (repair_action_t){
                        .type = SOL_REPAIR_SHRED,
                        .slot = tracker->slot,
                        .shred_index = mid_idx,
                        .fanout = duplicate_fanout,
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

                if (dead_primary && action_count < action_budget) {
                    actions[action_count++] = (repair_action_t){
                        .type = SOL_REPAIR_ORPHAN,
                        .slot = tracker->slot,
                        .shred_index = 0,
                        .fanout = tvu_dead_primary_orphan_fanout(),
                    };
                }
                if (dead_primary && action_count < action_budget) {
                    actions[action_count++] = (repair_action_t){
                        .type = SOL_REPAIR_ANCESTOR_HASHES,
                        .slot = tracker->slot,
                        .shred_index = 0,
                        .fanout = tvu_dead_primary_ancestor_fanout(),
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

            uint64_t last_progress_ns = tracker->last_inserted_ns
                ? tracker->last_inserted_ns
                : (tracker->last_received_ns
                    ? tracker->last_received_ns
                    : tracker->first_received_ns);
            uint64_t stall_ms = last_progress_ns
                ? (now >= last_progress_ns ? (now - last_progress_ns) / 1000000ULL : 0ULL)
                : UINT64_MAX;
            bool stalled_primary = focus_primary &&
                                   is_primary_slot &&
                                   is_catchup_slot &&
                                   stall_ms >= 40ULL;
            bool stalled_primary_deep = stalled_primary && (stall_ms >= 1500ULL);

            /* Keep missing detection variant-aware by trusting
             * `sol_blockstore_get_missing_shreds()`. Global index existence
             * checks can be false positives when duplicate slot variants are
             * present, which suppresses needed repair for the active fork. */

            if (tracker->slot == primary_slot &&
                (last_primary_diag_ns == 0 || (now - last_primary_diag_ns) >= 1000000000ULL)) {
                sol_slot_meta_t meta;
                bool have_meta = tvu->blockstore &&
                                 sol_blockstore_get_slot_meta(tvu->blockstore, tracker->slot, &meta) == SOL_OK;
                sol_log_debug("TVU repair primary slot=%lu meta=%s rx=%u last=%u full=%s missing=%zu stall_ms=%lu pending=%zu/%zu budget=%zu",
                              (unsigned long)tracker->slot,
                              have_meta ? "yes" : "no",
                              have_meta ? (unsigned)meta.received_data : 0u,
                              have_meta ? (unsigned)meta.last_shred_index : 0u,
                              have_meta ? (meta.is_full ? "yes" : "no") : "-",
                              missing_count,
                              (unsigned long)stall_ms,
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
                    highest_fanout = stalled_primary ? 24u : 12u;
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
                if (!request_duplicates &&
                    stalled_primary_deep &&
                    have_meta &&
                    meta.is_full) {
                    /* If the replay-critical slot is "full" but replay is still
                     * stalled for a long interval, proactively solicit duplicate
                     * variants to break potential fork/parent ambiguity stalls. */
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
                        tail_fanout = stalled_primary ? 24u : 12u;
                    } else if (is_catchup_slot) {
                        tail_fanout = 6;
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
                        .fanout = stalled_primary_deep ? 12u : 1u,
                    };
                    if (action_count < action_budget &&
                        have_meta &&
                        last_idx != first_idx) {
                        actions[action_count++] = (repair_action_t){
                            .type = SOL_REPAIR_SHRED,
                            .slot = tracker->slot,
                            .shred_index = last_idx,
                            .fanout = stalled_primary_deep ? 12u : 1u,
                        };
                    }
                    if (action_count < action_budget &&
                        have_meta &&
                        last_idx > first_idx + 1u) {
                        uint32_t mid_idx = first_idx + ((last_idx - first_idx) / 2u);
                        actions[action_count++] = (repair_action_t){
                            .type = SOL_REPAIR_SHRED,
                            .slot = tracker->slot,
                            .shred_index = mid_idx,
                            .fanout = stalled_primary_deep ? 12u : 1u,
                        };
                    }
                    if (stalled_primary_deep &&
                        have_meta &&
                        last_idx > first_idx &&
                        action_count < action_budget) {
                        /* Deep-stall sweep: sample multiple indices across the
                         * slot to solicit alternate duplicate variants. */
                        uint32_t sweep_points = 8u;
                        uint32_t span = last_idx - first_idx;
                        uint32_t step = span / (sweep_points + 1u);
                        if (step == 0u) step = 1u;
                        uint32_t idx = first_idx + step;
                        for (uint32_t s = 0; s < sweep_points &&
                                            idx < last_idx &&
                                            action_count < action_budget;
                             s++, idx += step) {
                            actions[action_count++] = (repair_action_t){
                                .type = SOL_REPAIR_SHRED,
                                .slot = tracker->slot,
                                .shred_index = idx,
                                .fanout = 16u,
                            };
                        }
                    }
                    if (action_count < action_budget) {
		                        actions[action_count++] = (repair_action_t){
		                            .type = SOL_REPAIR_HIGHEST_SHRED,
		                            .slot = tracker->slot,
		                            .shred_index = highest_start,
		                            .fanout = highest_fanout,
		                        };
		                    }
                    if (stalled_primary_deep && action_count < action_budget) {
                        actions[action_count++] = (repair_action_t){
                            .type = SOL_REPAIR_ORPHAN,
                            .slot = tracker->slot,
                            .shred_index = 0,
                            .fanout = tvu_dead_primary_orphan_fanout(),
                        };
                    }
                    if (stalled_primary_deep && action_count < action_budget) {
                        actions[action_count++] = (repair_action_t){
                            .type = SOL_REPAIR_ANCESTOR_HASHES,
                            .slot = tracker->slot,
                            .shred_index = 0,
                            .fanout = tvu_dead_primary_ancestor_fanout(),
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

                /* Primary-slot lookahead should also run on the "no missing
                 * bitmap" path. Otherwise catchup tends to serialize per-slot:
                 * we repair/replay one slot, then only start asking for the
                 * next slot afterward. Prefetching ahead keeps a small backlog
                 * of upcoming slot metadata/shreds warm. */
                if (focus_primary && is_primary_slot && thread_idx == 0 && primary_prefetch_slots > 0u) {
                    for (uint32_t di = 1;
                         di <= primary_prefetch_slots && action_count < action_budget;
                         di++) {
                        sol_slot_t next_slot = tracker->slot + (sol_slot_t)di;
                        if (next_slot == 0 || (catchup_end != 0 && next_slot > catchup_end)) {
                            break;
                        }
                        actions[action_count++] = (repair_action_t){
                            .type = SOL_REPAIR_HIGHEST_SHRED,
                            .slot = next_slot,
                            .shred_index = 0,
                            .fanout = SOL_TVU_PRIMARY_PREFETCH_FANOUT,
                        };
                    }
                }
            } else {
                bool request_highest = false;
                bool allow_highest = true;
                uint64_t highest_idx = 0;
                bool have_meta = false;
                bool meta_is_full = false;
                uint32_t meta_first_idx = 0;
                uint32_t meta_last_idx = 0;
                if (is_catchup_slot && tvu->blockstore) {
                    sol_slot_meta_t meta;
                    if (sol_blockstore_get_slot_meta(tvu->blockstore, tracker->slot, &meta) == SOL_OK) {
	                        have_meta = true;
	                        meta_is_full = meta.is_full;
	                        meta_first_idx = meta.first_shred_index;
	                        meta_last_idx = meta.last_shred_index;
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
                    /* Use high fanout only for small tail gaps. Large sparse gaps are
                     * throughput-bound and oversized fanout amplifies duplicate/timeout
                     * churn without improving unique shred acquisition. */
                    shred_fanout = 8;
                    highest_fanout = 4;
                    if (missing_count <= 16) {
                        shred_fanout = 24;
                        highest_fanout = 12;
                    } else if (missing_count <= 64) {
                        shred_fanout = 16;
                        highest_fanout = 10;
                    } else if (missing_count <= 256) {
                        shred_fanout = 12;
                        highest_fanout = 8;
                    }
                    if (stalled_primary) {
                        if (missing_count <= 8) {
                            shred_fanout = 28;
                            highest_fanout = 14;
                        } else if (missing_count <= 32) {
                            shred_fanout = 24;
                            highest_fanout = 12;
                        } else if (missing_count <= 128) {
                            shred_fanout = 16;
                            highest_fanout = 10;
                        } else {
                            shred_fanout = 12;
                            highest_fanout = 8;
                        }
                    }
                }
                if (stalled_primary) {
                    request_highest = true;
                }

                bool heavy_sparse_primary = focus_primary &&
                                            is_primary_slot &&
                                            missing_count >= 256u;

                if (focus_primary &&
                    is_primary_slot &&
                    thread_idx == 0 &&
                    stalled_primary_deep &&
                    have_meta &&
                    meta_is_full &&
                    missing_count >= 1024u) {
                    /* Deep sparse stalls can pin many stale in-flight requests to
                     * unresponsive peers. Periodically reset this slot's pending
                     * set so fresh peer selection can make forward progress. */
                    const uint64_t reset_interval_ns = 5000000000ULL; /* 5s */
                    if (last_primary_pending_reset_ns == 0 ||
                        (now >= last_primary_pending_reset_ns &&
                         (now - last_primary_pending_reset_ns) >= reset_interval_ns)) {
                        primary_pending_reset = true;
                        primary_pending_reset_slot = tracker->slot;
                        primary_pending_reset_missing = missing_count;
                        last_primary_pending_reset_ns = now;
                    }
                }

                size_t missing_budget = action_budget - action_count;
                if (missing_budget > 0u && missing_count > 0u) {
                    size_t missing_burst = missing_count;
                    if (heavy_sparse_primary) {
                        if (missing_count >= 1024u) {
                            missing_burst = 256u;
                        } else if (missing_count >= 512u) {
                            missing_burst = 320u;
                        } else {
                            missing_burst = 384u;
                        }
                    } else if (focus_primary && is_primary_slot && missing_count >= 128u) {
                        missing_burst = 256u;
                    } else if (missing_count > 96u) {
                        missing_burst = 128u;
                    }

                    if (missing_burst > missing_budget) {
                        missing_burst = missing_budget;
                    }
                    if (missing_burst > missing_count) {
                        missing_burst = missing_count;
                    }

                    size_t start = 0;
                    if (missing_count > missing_burst) {
                        start = (size_t)(tracker->repair_missing_cursor % (uint32_t)missing_count);
                    }

                    for (size_t m = 0; m < missing_burst && action_count < action_budget; m++) {
                        size_t idx = start + m;
                        if (idx >= missing_count) {
                            idx -= missing_count;
                        }
                        actions[action_count++] = (repair_action_t){
                            .type = SOL_REPAIR_SHRED,
                            .slot = tracker->slot,
                            .shred_index = missing[idx],
                            .fanout = shred_fanout,
                        };
                    }

                    if (missing_count > missing_burst) {
                        /* Prime increment to rotate probes across the sparse set. */
                        tracker->repair_missing_cursor += (uint32_t)missing_burst + 17u;
                    } else {
                        tracker->repair_missing_cursor = 0u;
                    }
                }

                if (stalled_primary_deep &&
                    have_meta &&
                    meta_is_full &&
                    missing_count >= 64 &&
                    missing_count <= 384 &&
                    action_count < action_budget) {
                    /* Deep-stall duplicate probe: if the primary slot is marked
                     * full but remains highly sparse for a long interval, solicit
                     * alternate variants by sampling deterministic indices across
                     * the slot, not only currently-missing indices. */
                    uint32_t probe_fanout = (missing_count >= 256) ? 8u : 6u;

                    actions[action_count++] = (repair_action_t){
                        .type = SOL_REPAIR_SHRED,
                        .slot = tracker->slot,
                        .shred_index = meta_first_idx,
                        .fanout = probe_fanout,
                    };

                    if (action_count < action_budget && meta_last_idx != meta_first_idx) {
                        actions[action_count++] = (repair_action_t){
                            .type = SOL_REPAIR_SHRED,
                            .slot = tracker->slot,
                            .shred_index = meta_last_idx,
                            .fanout = probe_fanout,
                        };
                    }

                    if (action_count < action_budget && meta_last_idx > meta_first_idx + 1u) {
                        uint32_t mid_idx = meta_first_idx + ((meta_last_idx - meta_first_idx) / 2u);
                        actions[action_count++] = (repair_action_t){
                            .type = SOL_REPAIR_SHRED,
                            .slot = tracker->slot,
                            .shred_index = mid_idx,
                            .fanout = probe_fanout,
                        };
                    }

                    if (meta_last_idx > meta_first_idx + 2u) {
                        uint32_t sweep_points = 4u;
                        uint32_t span = meta_last_idx - meta_first_idx;
                        uint32_t step = span / (sweep_points + 1u);
                        if (step == 0u) step = 1u;
                        uint32_t idx = meta_first_idx + step;
                        for (uint32_t s = 0; s < sweep_points &&
                                            idx < meta_last_idx &&
                                            action_count < action_budget;
                             s++, idx += step) {
                            actions[action_count++] = (repair_action_t){
                                .type = SOL_REPAIR_SHRED,
                                .slot = tracker->slot,
                                .shred_index = idx,
                                .fanout = probe_fanout,
                            };
                        }
                    }

                    if (highest_fanout < (probe_fanout / 2u)) {
                        highest_fanout = probe_fanout / 2u;
                    }
                    request_highest = true;
                }

                if (stalled_primary && action_count < action_budget) {
                    actions[action_count++] = (repair_action_t){
                        .type = SOL_REPAIR_ANCESTOR_HASHES,
                        .slot = tracker->slot,
                        .shred_index = 0,
                        .fanout = 1,
                    };
                }
                if (stalled_primary && action_count < action_budget) {
                    actions[action_count++] = (repair_action_t){
                        .type = SOL_REPAIR_ORPHAN,
                        .slot = tracker->slot,
                        .shred_index = 0,
                        .fanout = 1,
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
                        if (helper_fanout > (stalled_primary ? 24u : 12u)) {
                            helper_fanout = stalled_primary ? 24u : 12u;
                        }
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
	                        if (focus_primary && is_primary_slot && thread_idx == 0 && primary_prefetch_slots > 0u) {
	                            for (uint32_t di = 1;
	                                 di <= primary_prefetch_slots && action_count < action_budget;
	                                 di++) {
		                                sol_slot_t next_slot = tracker->slot + (sol_slot_t)di;
		                                if (next_slot == 0 || (catchup_end != 0 && next_slot > catchup_end)) {
		                                    break;
		                                }
                                actions[action_count++] = (repair_action_t){
                                    .type = SOL_REPAIR_HIGHEST_SHRED,
                                    .slot = next_slot,
                                    .shred_index = 0,
                                    .fanout = SOL_TVU_PRIMARY_PREFETCH_FANOUT,
                                };
	                            }
	                        }
			            }
	        }
        pthread_mutex_unlock(&tvu->slots_lock);

        if (primary_pending_reset && primary_pending_reset_slot != 0) {
            size_t dropped = sol_repair_prune_pending_slot(tvu->repair, primary_pending_reset_slot);
            if (dropped > 0 &&
                (last_thread_diag_ns == 0 || (now - last_thread_diag_ns) >= 1000000000ULL)) {
                sol_log_debug("TVU repair primary reset: slot=%lu missing=%zu dropped=%zu",
                              (unsigned long)primary_pending_reset_slot,
                              primary_pending_reset_missing,
                              dropped);
                last_thread_diag_ns = now;
            }
        }

        uint32_t fanout_cap = UINT32_MAX;
        if (pending_saturated) {
            fanout_cap = focus_primary ? 8u : 4u;
        } else if (pending_pressure_high) {
            fanout_cap = focus_primary ? 12u : 6u;
        } else if (pending_pressure_medium) {
            fanout_cap = focus_primary ? 16u : 8u;
        }

        uint32_t emergency_fanout = 8u;
        if (fanout_cap != UINT32_MAX && emergency_fanout > fanout_cap) {
            emergency_fanout = fanout_cap;
        }

        if (action_count == 0 && catchup_start && action_budget) {
            actions[action_count++] = (repair_action_t){
                .type = SOL_REPAIR_HIGHEST_SHRED,
                .slot = catchup_start,
                .shred_index = 0,
                .fanout = emergency_fanout,
            };
        }

        for (size_t i = 0; i < action_count; i++) {
            sol_err_t err = SOL_ERR_INVAL;
            const repair_action_t* a = &actions[i];
            uint32_t fanout = a->fanout;
            if (fanout_cap != UINT32_MAX && fanout > fanout_cap) {
                fanout = fanout_cap;
            }
            if (fanout == 0u) {
                fanout = 1u;
            }
            switch (a->type) {
            case SOL_REPAIR_SHRED:
                if (fanout > 1u) {
                    err = sol_repair_request_shred_fanout(tvu->repair,
                                                         a->slot,
                                                         a->shred_index,
                                                         true,
                                                         fanout);
                } else {
                    err = sol_repair_request_shred(tvu->repair, a->slot, a->shred_index, true);
                }
                break;
            case SOL_REPAIR_HIGHEST_SHRED:
                if (fanout > 1u) {
                    err = sol_repair_request_highest_fanout(tvu->repair,
                                                            a->slot,
                                                            a->shred_index,
                                                            fanout);
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
        tvu_pick_threads(tvu->config.shred_verify_threads,
                         SOL_TVU_MAX_VERIFY_THREADS,
                         2,
                         TVU_THREAD_ROLE_VERIFY);
    tvu->shred_verify_thread_count = verify_threads;
    tvu->shred_verify_threads = sol_calloc(verify_threads, sizeof(pthread_t));
    if (!tvu->shred_verify_threads) {
        sol_free(tvu);
        return NULL;
    }

    uint32_t replay_threads =
        tvu_pick_threads(tvu->config.replay_threads,
                         SOL_TVU_MAX_REPLAY_THREADS,
                         2,
                         TVU_THREAD_ROLE_REPLAY);
    tvu->replay_thread_count = replay_threads;
    tvu->replay_threads = sol_calloc(replay_threads, sizeof(pthread_t));
    if (!tvu->replay_threads) {
        sol_free(tvu->shred_verify_threads);
        sol_free(tvu);
        return NULL;
    }

    uint32_t repair_threads =
        tvu_pick_threads(tvu->config.repair_threads,
                         SOL_TVU_MAX_REPAIR_THREADS,
                         2,
                         TVU_THREAD_ROLE_REPAIR);
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

    uint32_t prewarm_threads = tvu_pick_prewarm_threads(replay_threads);
    tvu->prewarm_thread_count = prewarm_threads;
    tvu->prewarm_threads = sol_calloc(prewarm_threads, sizeof(pthread_t));
    tvu->prewarm_thread_ctx = sol_calloc(prewarm_threads, sizeof(tvu_prewarm_thread_ctx_t));
    if (!tvu->prewarm_threads || !tvu->prewarm_thread_ctx) {
        sol_free(tvu->prewarm_thread_ctx);
        sol_free(tvu->prewarm_threads);
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
        sol_free(tvu->prewarm_thread_ctx);
        sol_free(tvu->prewarm_threads);
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
    pthread_mutex_init(&tvu->replay_metrics_lock, NULL);

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
    sol_free(tvu->prewarm_thread_ctx);
    sol_free(tvu->prewarm_threads);
    sol_free(tvu->repair_thread_ctx);
    sol_free(tvu->repair_threads);

    pthread_mutex_destroy(&tvu->shred_queue_lock);
    pthread_cond_destroy(&tvu->shred_queue_cond);
    pthread_mutex_destroy(&tvu->slots_lock);
    pthread_mutex_destroy(&tvu->lock);
    pthread_mutex_destroy(&tvu->replay_metrics_lock);

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

    /* Start prewarm threads */
    size_t prewarm_started = 0;
    for (size_t i = 0; i < tvu->prewarm_thread_count; i++) {
        tvu->prewarm_thread_ctx[i].tvu = tvu;
        tvu->prewarm_thread_ctx[i].thread_idx = (uint32_t)i;
        if (pthread_create(&tvu->prewarm_threads[i], NULL, prewarm_thread_func,
                           &tvu->prewarm_thread_ctx[i]) != 0) {
            tvu->running = false;
            for (size_t j = 0; j < started; j++) {
                pthread_join(tvu->shred_verify_threads[j], NULL);
            }
            for (size_t j = 0; j < replay_started; j++) {
                pthread_join(tvu->replay_threads[j], NULL);
            }
            for (size_t j = 0; j < prewarm_started; j++) {
                pthread_join(tvu->prewarm_threads[j], NULL);
            }
            return SOL_ERR_IO;
        }
        prewarm_started++;
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
            for (size_t j = 0; j < prewarm_started; j++) {
                pthread_join(tvu->prewarm_threads[j], NULL);
            }
            for (size_t j = 0; j < repair_started; j++) {
                pthread_join(tvu->repair_threads[j], NULL);
            }
            return SOL_ERR_IO;
        }
        repair_started++;
    }

    tvu->threads_started = true;
    sol_log_info("TVU started (shred_verify_threads=%zu, replay_threads=%zu, prewarm_threads=%zu, repair_threads=%zu)",
                 tvu->shred_verify_thread_count,
                 tvu->replay_thread_count,
                 tvu->prewarm_thread_count,
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
        for (size_t i = 0; i < tvu->prewarm_thread_count; i++) {
            pthread_join(tvu->prewarm_threads[i], NULL);
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
            max_ahead = tvu_effective_max_shred_ahead(tvu, cursor);
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
        if (cursor != 0) {
            max_ahead = tvu_effective_max_shred_ahead(tvu, cursor);
        }
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
