/*
 * sol_replay.c - Replay Stage Implementation
 */

#include "sol_replay.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include "../entry/sol_entry.h"
#include "../runtime/sol_bank.h"
#include "../runtime/sol_account.h"
#include "../runtime/sol_leader_schedule.h"
#include "../programs/sol_bpf_loader_program.h"
#include "../txn/sol_pubkey.h"
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

typedef struct sol_replay_verify_worker {
    pthread_mutex_t             mu;
    pthread_cond_t              cv;
    pthread_cond_t              done;
    pthread_t                   thread;
    bool                        inited;
    bool                        started;
    bool                        stop;
    bool                        has_job;
    bool                        job_done;
    bool                        done_clock_monotonic;
    const sol_entry_batch_t*    batch;
    sol_hash_t                  start_hash;
    sol_entry_verify_result_t   verify;
    bool                        start_hash_mismatch;
    bool                        verify_signatures;
} sol_replay_verify_worker_t;

static bool
replay_verify_tail_ok(const sol_entry_batch_t* batch) {
    if (!batch || batch->num_entries == 0) return false;

    /* If the batch verifies when starting from entry[0].hash, the slot likely
     * belongs to a different parent hash/fork. */
    bool tail_ok = true;
    sol_hash_t prev = batch->entries[0].hash;
    for (size_t i = 1; i < batch->num_entries; i++) {
        const sol_entry_t* entry = &batch->entries[i];
        sol_hash_t expected_hash;
        sol_entry_compute_hash(entry, &prev, &expected_hash);
        if (memcmp(expected_hash.bytes, entry->hash.bytes, 32) != 0) {
            tail_ok = false;
            break;
        }
        prev = entry->hash;
    }
    return tail_ok;
}

typedef struct replay_sigverify_chunk {
    const sol_entry_batch_t* batch;
    size_t                   start_entry;
    size_t                   end_entry;
    bool                     valid;
} replay_sigverify_chunk_t;

static bool
replay_sigverify_range(const sol_entry_batch_t* batch,
                       size_t start_entry,
                       size_t end_entry) {
    if (!batch) return false;
    if (start_entry >= end_entry || end_entry > batch->num_entries) return true;

    for (size_t ei = start_entry; ei < end_entry; ei++) {
        const sol_entry_t* entry = &batch->entries[ei];
        for (uint32_t ti = 0; ti < entry->num_transactions; ti++) {
            if (!sol_transaction_verify_signatures(&entry->transactions[ti], NULL)) {
                return false;
            }
        }
    }

    return true;
}

static void*
replay_sigverify_chunk_main(void* arg) {
    replay_sigverify_chunk_t* chunk = (replay_sigverify_chunk_t*)arg;
    if (!chunk) return NULL;
    chunk->valid =
        replay_sigverify_range(chunk->batch, chunk->start_entry, chunk->end_entry);
    return NULL;
}

static size_t
replay_sigverify_parallel_threads(void) {
    static _Atomic size_t cached = 0u;
    size_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != 0u, 1)) return v;

    size_t threads = 1u;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu >= 128) threads = 24u;
    else if (ncpu >= 96) threads = 16u;
    else if (ncpu >= 64) threads = 12u;
    else if (ncpu >= 32) threads = 8u;
    else if (ncpu >= 16) threads = 4u;
    else if (ncpu >= 8) threads = 2u;

    const char* env = getenv("SOL_REPLAY_SIGVERIFY_THREADS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long parsed = strtoul(env, &end, 10);
        if (end && end != env) {
            threads = (size_t)parsed;
        }
    }

    if (threads < 1u) threads = 1u;
    if (threads > 64u) threads = 64u;
    __atomic_store_n(&cached, threads, __ATOMIC_RELEASE);
    return threads;
}

static size_t
replay_sigverify_parallel_min_txs(void) {
    static _Atomic size_t cached = 0u;
    size_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != 0u, 1)) return v;

    size_t min_txs = 1024u;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu > 0 && ncpu < 64) min_txs = 2048u;

    const char* env = getenv("SOL_REPLAY_SIGVERIFY_MIN_TX");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long parsed = strtoul(env, &end, 10);
        if (end && end != env) {
            min_txs = (size_t)parsed;
        }
    }

    if (min_txs < 128u) min_txs = 128u;
    if (min_txs > 262144u) min_txs = 262144u;
    __atomic_store_n(&cached, min_txs, __ATOMIC_RELEASE);
    return min_txs;
}

static bool
replay_sigverify_all_valid(const sol_entry_batch_t* batch) {
    if (!batch) return false;

    size_t tx_count = (size_t)sol_entry_batch_transaction_count(batch);
    if (tx_count == 0u || batch->num_entries == 0u) return true;

    size_t workers = replay_sigverify_parallel_threads();
    size_t min_txs = replay_sigverify_parallel_min_txs();
    if (workers <= 1u || tx_count < min_txs || batch->num_entries < 2u) {
        return replay_sigverify_range(batch, 0u, batch->num_entries);
    }

    if (workers > batch->num_entries) workers = batch->num_entries;
    if (workers > 64u) workers = 64u;
    if (workers <= 1u) {
        return replay_sigverify_range(batch, 0u, batch->num_entries);
    }

    replay_sigverify_chunk_t chunks[64];
    pthread_t threads[63];
    size_t chunk_count = 0u;
    size_t start = 0u;
    size_t remaining_txs = tx_count;

    while (start < batch->num_entries && chunk_count < workers) {
        size_t remaining_chunks = workers - chunk_count;
        size_t target_txs = (remaining_txs + remaining_chunks - 1u) / remaining_chunks;
        if (target_txs == 0u) target_txs = 1u;

        size_t end = start;
        size_t taken_txs = 0u;
        while (end < batch->num_entries) {
            taken_txs += (size_t)batch->entries[end].num_transactions;
            end++;
            if (taken_txs >= target_txs) break;
            if ((batch->num_entries - end) <= (remaining_chunks - 1u)) break;
        }
        if (end <= start) end = start + 1u;

        chunks[chunk_count].batch = batch;
        chunks[chunk_count].start_entry = start;
        chunks[chunk_count].end_entry = end;
        chunks[chunk_count].valid = false;
        chunk_count++;

        start = end;
        if (taken_txs >= remaining_txs) remaining_txs = 0u;
        else remaining_txs -= taken_txs;
    }

    if (chunk_count <= 1u) {
        return replay_sigverify_range(batch, 0u, batch->num_entries);
    }

    size_t started = 0u;
    bool create_failed = false;
    for (size_t i = 1u; i < chunk_count; i++) {
        if (pthread_create(&threads[i - 1u], NULL, replay_sigverify_chunk_main, &chunks[i]) != 0) {
            create_failed = true;
            break;
        }
        started++;
    }

    (void)replay_sigverify_chunk_main(&chunks[0]);

    for (size_t i = 0u; i < started; i++) {
        (void)pthread_join(threads[i], NULL);
    }

    if (create_failed) {
        return replay_sigverify_range(batch, 0u, batch->num_entries);
    }

    for (size_t i = 0u; i < chunk_count; i++) {
        if (!chunks[i].valid) return false;
    }
    return true;
}

static sol_entry_verify_result_t
replay_entry_batch_verify(const sol_entry_batch_t* batch,
                          const sol_hash_t* start_hash,
                          bool verify_signatures) {
    sol_entry_verify_result_t result = sol_entry_batch_verify(batch, start_hash);
    if (!result.valid || !verify_signatures || !batch) {
        return result;
    }

    if (replay_sigverify_all_valid(batch)) {
        return result;
    }

    /* Rare invalid-signature path: scan serially to keep deterministic
     * first-failure diagnostics. */
    for (size_t ei = 0; ei < batch->num_entries; ei++) {
        const sol_entry_t* entry = &batch->entries[ei];
        for (uint32_t ti = 0; ti < entry->num_transactions; ti++) {
            if (!sol_transaction_verify_signatures(&entry->transactions[ti], NULL)) {
                result.valid = false;
                result.error = SOL_ERR_TX_SIGNATURE;
                result.failed_entry =
                    (ei > (size_t)UINT32_MAX) ? UINT32_MAX : (uint32_t)ei;
                result.num_verified =
                    (ei > (size_t)UINT32_MAX) ? UINT32_MAX : (uint32_t)ei;
                return result;
            }
        }
    }

    return result;
}

static void*
replay_verify_worker_main(void* arg) {
    sol_replay_verify_worker_t* w = (sol_replay_verify_worker_t*)arg;
    if (!w) return NULL;

    pthread_mutex_lock(&w->mu);
    for (;;) {
        while (!w->stop && !w->has_job) {
            pthread_cond_wait(&w->cv, &w->mu);
        }
        if (w->stop) {
            break;
        }

        const sol_entry_batch_t* batch = w->batch;
        sol_hash_t start_hash = w->start_hash;

        /* Mark the job as consumed so submitters can enqueue a new one after
         * observing job_done. */
        w->has_job = false;
        pthread_mutex_unlock(&w->mu);

        sol_entry_verify_result_t verify =
            replay_entry_batch_verify(batch, &start_hash, w->verify_signatures);
        bool mismatch = false;
        if (!verify.valid &&
            verify.failed_entry == 0 &&
            verify.error == SOL_ERR_INVALID_HASH) {
            mismatch = replay_verify_tail_ok(batch);
        }

        pthread_mutex_lock(&w->mu);
        w->verify = verify;
        w->start_hash_mismatch = mismatch;
        w->job_done = true;
        pthread_cond_signal(&w->done);
    }
    pthread_mutex_unlock(&w->mu);

    return NULL;
}

/*
 * Pending slot entry
 */
typedef struct sol_pending_slot {
    sol_slot_t                  slot;
    sol_slot_t                  parent_slot;
    struct sol_pending_slot*    next;
} sol_pending_slot_t;

/*
 * Replayed slot entry
 */
typedef struct sol_replayed_slot {
    sol_slot_t                  slot;
    bool                        is_dead;
    bool                        in_progress;
    uint64_t                    in_progress_since_ns;
    uint64_t                    in_progress_lease_id;
    _Atomic uint32_t            in_progress_stage;
    uint32_t                    variant_count; /* Variants observed when last attempted */
    uint32_t                    complete_variant_count; /* Complete variants observed when last attempted */
    struct sol_replayed_slot*   next;
} sol_replayed_slot_t;

/*
 * Replay stage structure
 */
struct sol_replay {
    sol_replay_config_t     config;

    /* Components */
    sol_bank_forks_t*       bank_forks;
    sol_blockstore_t*       blockstore;
    sol_fork_choice_t*      fork_choice;
    sol_leader_schedule_t*  leader_schedule;

    /* Pending slots (waiting for parent) */
    sol_pending_slot_t*     pending_slots;
    size_t                  pending_count;

    /* Replayed slots tracking (hash table) */
    sol_replayed_slot_t**   replayed_buckets;
    size_t                  replayed_bucket_count;

    /* Callback */
    sol_replay_slot_cb      callback;
    void*                   callback_ctx;

    /* Statistics */
    sol_replay_stats_t      stats;
    sol_slot_t              highest_replayed_slot_atomic;

    /* Thread safety */
    pthread_mutex_t         lock;

    /* Best-effort async entry-hash verification workers. */
    sol_replay_verify_worker_t* verify_workers;
    uint32_t                    verify_worker_count;

    /* Throttle expensive root-prune attempts under bank-forks pressure. */
    uint64_t                    last_full_prune_ns;
    /* Monotonic lease id for replay in-progress ownership. Guarded by lock. */
    uint64_t                    replay_lease_seq;
    uint64_t                    last_in_progress_steal_log_ns;
};

static bool
replay_skip_tx_index(void) {
    const char* env = getenv("SOL_SKIP_TX_INDEX");
    if (!env || env[0] == '\0') {
        /* Default to skipping tx indexing for replay throughput. */
        return true;
    }
    return strcmp(env, "0") != 0;
}

static size_t
replay_parse_size_env(const char* env_name, size_t def, size_t min_v, size_t max_v) {
    const char* env = getenv(env_name);
    if (!env || env[0] == '\0') return def;

    errno = 0;
    char* end = NULL;
    unsigned long long parsed = strtoull(env, &end, 10);
    if (errno != 0 || end == env) {
        return def;
    }
    if (parsed > (unsigned long long)SIZE_MAX) {
        parsed = (unsigned long long)SIZE_MAX;
    }

    size_t v = (size_t)parsed;
    if (v < min_v) v = min_v;
    if (v > max_v) v = max_v;
    return v;
}

static size_t
replay_prewarm_max_txs(void) {
    static _Atomic size_t cached = 0;
    size_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != 0, 1)) return v;
    size_t parsed = replay_parse_size_env("SOL_REPLAY_PREWARM_MAX_TX", 8192u, 1u, 131072u);
    __atomic_store_n(&cached, parsed, __ATOMIC_RELEASE);
    return parsed;
}

static size_t
replay_prewarm_max_accounts(void) {
    static _Atomic size_t cached = 0;
    size_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != 0, 1)) return v;
    size_t parsed = replay_parse_size_env("SOL_REPLAY_PREWARM_MAX_ACCOUNTS", 65536u, 1u, 1048576u);
    __atomic_store_n(&cached, parsed, __ATOMIC_RELEASE);
    return parsed;
}

static size_t
replay_prewarm_max_keys_per_tx(void) {
    static _Atomic size_t cached = 0;
    size_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != 0, 1)) return v;
    size_t parsed = replay_parse_size_env("SOL_REPLAY_PREWARM_MAX_KEYS_PER_TX",
                                          64u,
                                          1u,
                                          SOL_MAX_MESSAGE_ACCOUNTS);
    __atomic_store_n(&cached, parsed, __ATOMIC_RELEASE);
    return parsed;
}

static bool
replay_prewarm_include_readonly(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v >= 0, 1)) return v != 0;
    const char* env = getenv("SOL_REPLAY_PREWARM_INCLUDE_READONLY");
    int enabled = 0;
    if (!env || env[0] == '\0') {
        /* On large-memory/high-core validators, readonly account misses inside
         * deep CPI trees can cause multi-second stalls. Default to warming
         * readonly keys there; keep smaller hosts conservative. */
        long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
        enabled = (ncpu >= 64) ? 1 : 0;
    } else {
        enabled = (strcmp(env, "0") != 0) ? 1 : 0;
    }
    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled != 0;
}

static bool
replay_prewarm_bpf_programs(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v >= 0, 1)) return v != 0;

    const char* env = getenv("SOL_REPLAY_PREWARM_BPF_PROGRAMS");
    int enabled = 1;
    if (env && env[0] != '\0') {
        enabled = (strcmp(env, "0") != 0) ? 1 : 0;
    }

    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled != 0;
}

static size_t
replay_prewarm_max_programs(void) {
    static _Atomic size_t cached = 0;
    size_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != 0, 1)) return v;
    size_t def = 512u;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu >= 128) {
        def = 16384u;
    } else if (ncpu >= 64) {
        def = 8192u;
    } else if (ncpu >= 32) {
        def = 2048u;
    }
    size_t parsed = replay_parse_size_env("SOL_REPLAY_PREWARM_MAX_PROGRAMS", def, 1u, 65536u);
    __atomic_store_n(&cached, parsed, __ATOMIC_RELEASE);
    return parsed;
}

static size_t
replay_prewarm_max_variants(void) {
    static _Atomic size_t cached = 0;
    size_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != 0, 1)) return v;
    size_t def = 8u;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu >= 128) {
        def = 64u;
    } else if (ncpu >= 64) {
        def = 32u;
    } else if (ncpu >= 32) {
        def = 16u;
    }
    size_t parsed = replay_parse_size_env("SOL_REPLAY_PREWARM_MAX_VARIANTS", def, 1u, 128u);
    __atomic_store_n(&cached, parsed, __ATOMIC_RELEASE);
    return parsed;
}

static bool
replay_sync_prewarm_programs(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v >= 0, 1)) return v != 0;

    const char* env = getenv("SOL_REPLAY_SYNC_PREWARM_BPF_PROGRAMS");
    int enabled = 0;
    if (!env || env[0] == '\0') {
        /* Keep synchronous program prewarm opt-in by default.
         *
         * Even with a nominal per-slot budget, single account/program loads can
         * block long enough to create multi-second replay outliers on hot slots.
         * Asynchronous prewarm remains enabled and can warm the same programs
         * off the replay critical path. */
        enabled = 0;
    } else {
        enabled = (strcmp(env, "0") != 0) ? 1 : 0;
    }

    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled != 0;
}

static uint64_t
replay_sync_prewarm_budget_ns(void) {
    static _Atomic uint64_t cached = UINT64_MAX;
    uint64_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != UINT64_MAX, 1)) return v;

    /* Bound synchronous replay prewarm to avoid multi-second slot tails.
     * Set SOL_REPLAY_SYNC_PREWARM_BUDGET_MS=0 for unbounded behavior. */
    uint64_t budget_ms = 100u;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu >= 128) {
        budget_ms = 250u;
    } else if (ncpu >= 64) {
        budget_ms = 200u;
    }

    const char* env = getenv("SOL_REPLAY_SYNC_PREWARM_BUDGET_MS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long parsed = strtoul(env, &end, 10);
        if (end != env) {
            budget_ms = (uint64_t)parsed;
        }
    }

    if (budget_ms > 5000u) budget_ms = 5000u;
    uint64_t budget_ns = budget_ms * 1000000ULL;
    __atomic_store_n(&cached, budget_ns, __ATOMIC_RELEASE);
    return budget_ns;
}

static uint64_t
replay_in_progress_timeout_ns(void) {
    static _Atomic uint64_t cached = 0;
    uint64_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != 0, 1)) {
        return v - 1u;
    }

    uint64_t timeout_ms = 15000u;
    const char* env = getenv("SOL_REPLAY_IN_PROGRESS_TIMEOUT_MS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        errno = 0;
        unsigned long long parsed = strtoull(env, &end, 10);
        if (errno == 0 && end != env) {
            timeout_ms = (uint64_t)parsed;
        }
    }

    if (timeout_ms > 600000u) timeout_ms = 600000u;
    uint64_t timeout_ns = timeout_ms * 1000000ULL;
    __atomic_store_n(&cached, timeout_ns + 1u, __ATOMIC_RELEASE);
    return timeout_ns;
}

enum {
    REPLAY_STAGE_NONE = 0u,
    REPLAY_STAGE_PREPARE = 1u,
    REPLAY_STAGE_BUILD_BANK = 2u,
    REPLAY_STAGE_EXECUTE = 3u,
    REPLAY_STAGE_FINALIZE = 4u,
};

static const char*
replay_stage_name(uint32_t stage) {
    switch (stage) {
        case REPLAY_STAGE_PREPARE: return "prepare";
        case REPLAY_STAGE_BUILD_BANK: return "build_bank";
        case REPLAY_STAGE_EXECUTE: return "execute";
        case REPLAY_STAGE_FINALIZE: return "finalize";
        default: return "none";
    }
}

static inline void
replay_set_stage(sol_replayed_slot_t* replayed, uint32_t stage) {
    if (!replayed) return;
    __atomic_store_n(&replayed->in_progress_stage, stage, __ATOMIC_RELEASE);
}

static uint64_t get_time_ns(void);

static inline bool
replay_pubkey_in_list(const sol_pubkey_t* list, size_t len, const sol_pubkey_t* key) {
    if (!list || !key) return false;
    for (size_t i = 0; i < len; i++) {
        if (sol_pubkey_eq(&list[i], key)) {
            return true;
        }
    }
    return false;
}

static inline bool
replay_is_bpf_loader_owner(const sol_pubkey_t* owner) {
    if (!owner) return false;
    return sol_pubkey_eq(owner, &SOL_BPF_LOADER_UPGRADEABLE_ID) ||
           sol_pubkey_eq(owner, &SOL_BPF_LOADER_V2_ID) ||
           sol_pubkey_eq(owner, &SOL_BPF_LOADER_V3_ID);
}

static bool
replay_try_prewarm_program_key(sol_bank_t* parent_bank,
                               const sol_pubkey_t* key,
                               sol_pubkey_t* attempted_keys,
                               size_t* attempted_len,
                               size_t attempted_cap,
                               sol_pubkey_t* warmed_programs,
                               size_t* warmed_len,
                               size_t warmed_cap,
                               bool allow_program_elf_prewarm,
                               uint64_t prewarm_deadline_ns) {
    if (!parent_bank || !key || !attempted_keys || !attempted_len || !warmed_programs || !warmed_len) {
        return true;
    }
    if (prewarm_deadline_ns != 0u &&
        __builtin_expect(get_time_ns() >= prewarm_deadline_ns, 0)) {
        return false;
    }

    if (replay_pubkey_in_list(attempted_keys, *attempted_len, key)) {
        return true;
    }
    if (*attempted_len < attempted_cap) {
        attempted_keys[(*attempted_len)++] = *key;
    } else {
        return true;
    }

    if (*warmed_len >= warmed_cap || replay_pubkey_in_list(warmed_programs, *warmed_len, key)) {
        return true;
    }
    if (prewarm_deadline_ns != 0u &&
        __builtin_expect(get_time_ns() >= prewarm_deadline_ns, 0)) {
        return false;
    }

    sol_account_t* program_account = sol_bank_load_account_view(parent_bank, key);
    if (!program_account) {
        return true;
    }

    bool should_prewarm =
        program_account->meta.executable &&
        replay_is_bpf_loader_owner(&program_account->meta.owner);
    sol_account_destroy(program_account);
    if (!should_prewarm) {
        return true;
    }

    warmed_programs[(*warmed_len)++] = *key;
    if (allow_program_elf_prewarm) {
        uint64_t wait_budget_ns = UINT64_MAX;
        if (prewarm_deadline_ns != 0u) {
            uint64_t now_ns = get_time_ns();
            if (__builtin_expect(now_ns >= prewarm_deadline_ns, 0)) {
                return false;
            }
            wait_budget_ns = prewarm_deadline_ns - now_ns;
        }
        (void)sol_bpf_loader_prewarm_program_budget(parent_bank, key, wait_budget_ns);
    }
    return true;
}

static bool
replay_fast_mode(void) {
    static int cached = -1;
    if (cached >= 0) {
        return cached != 0;
    }

    const char* env = getenv("SOL_SKIP_TX_PROCESSING");
    cached = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    return cached != 0;
}

static bool
replay_force_advance(void) {
    static int cached = -1;
    if (cached >= 0) {
        return cached != 0;
    }

    const char* env = getenv("SOL_FAST_REPLAY_FORCE_ADVANCE");
    cached = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    return cached != 0;
}

static bool
replay_prune_on_full(void) {
    static int cached = -1;
    if (cached >= 0) {
        return cached != 0;
    }

    const char* env = getenv("SOL_REPLAY_PRUNE_ON_FULL");
    if (!env || env[0] == '\0') {
        cached = 1;
    } else {
        cached = (strcmp(env, "0") != 0) ? 1 : 0;
    }
    return cached != 0;
}

static sol_slot_t
replay_prune_on_full_window(void) {
    static sol_slot_t cached = 0;
    if (cached != 0) {
        return cached;
    }

    sol_slot_t window = 96u;
    const char* env = getenv("SOL_REPLAY_PRUNE_ON_FULL_WINDOW");
    if (env && env[0] != '\0') {
        errno = 0;
        char* end = NULL;
        unsigned long long parsed = strtoull(env, &end, 10);
        if (errno == 0 && end && end != env) {
            while (*end && isspace((unsigned char)*end)) end++;
            if (*end == '\0') {
                window = (sol_slot_t)parsed;
            }
        }
    }

    if (window < 16u) window = 16u;
    if (window > 4096u) window = 4096u;
    cached = window;
    return cached;
}

static uint64_t
replay_prune_on_full_cooldown_ns(void) {
    static uint64_t cached = 0;
    if (cached != 0) {
        return cached;
    }

    uint64_t cooldown_ms = 250u;
    const char* env = getenv("SOL_REPLAY_PRUNE_ON_FULL_COOLDOWN_MS");
    if (env && env[0] != '\0') {
        errno = 0;
        char* end = NULL;
        unsigned long long parsed = strtoull(env, &end, 10);
        if (errno == 0 && end && end != env) {
            while (*end && isspace((unsigned char)*end)) end++;
            if (*end == '\0') {
                cooldown_ms = (uint64_t)parsed;
            }
        }
    }

    if (cooldown_ms > 10000u) cooldown_ms = 10000u;
    cached = cooldown_ms * 1000ull * 1000ull;
    return cached;
}

static sol_slot_t
replay_prune_on_full_search_limit(void) {
    static sol_slot_t cached = 0;
    if (cached != 0) {
        return cached;
    }

    sol_slot_t limit = 4096u;
    const char* env = getenv("SOL_REPLAY_PRUNE_ON_FULL_SEARCH_LIMIT");
    if (env && env[0] != '\0') {
        errno = 0;
        char* end = NULL;
        unsigned long long parsed = strtoull(env, &end, 10);
        if (errno == 0 && end && end != env) {
            while (*end && isspace((unsigned char)*end)) end++;
            if (*end == '\0') {
                limit = (sol_slot_t)parsed;
            }
        }
    }

    if (limit < 128u) limit = 128u;
    if (limit > 65536u) limit = 65536u;
    cached = limit;
    return cached;
}

static bool
replay_find_frozen_root_candidate(sol_replay_t* replay,
                                  sol_slot_t upper,
                                  sol_slot_t lower,
                                  sol_slot_t* out_slot,
                                  sol_hash_t* out_hash) {
    if (!replay || !out_slot || !out_hash) return false;
    if (upper < lower) return false;

    for (sol_slot_t slot = upper;; slot--) {
        sol_bank_t* bank = sol_bank_forks_get(replay->bank_forks, slot);
        if (bank && sol_bank_is_frozen(bank)) {
            sol_bank_compute_hash(bank, out_hash);
            *out_slot = slot;
            return true;
        }

        if (slot == lower) break;
    }
    return false;
}

static bool
replay_verify_entries(const sol_replay_t* replay) {
    if (!replay) return false;
    if (!replay->config.verify_entries) return false;
    if (replay_fast_mode()) return false;
    return true;
}

static bool
replay_verify_signatures(const sol_replay_t* replay) {
    if (!replay) return false;
    if (!replay->config.verify_signatures) return false;
    if (replay_fast_mode()) return false;
    return true;
}

static bool
replay_verify_async(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (v >= 0) {
        return v != 0;
    }

    /* Keep historical env override behavior, but default to sync verification
     * on large-core hosts where async worker starvation can inflate replay
     * tail latency under heavy tx-worker load. */
    const char* env = getenv("SOL_REPLAY_VERIFY_ASYNC");
    int enabled;
    if (!env || env[0] == '\0') {
        long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
        enabled = (ncpu >= 64) ? 0 : 1;
    } else {
        enabled = (strcmp(env, "0") != 0) ? 1 : 0;
    }
    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled != 0;
}

static uint32_t
replay_verify_worker_count(void) {
    static uint32_t cached = 0;
    uint32_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (v != 0) {
        return v;
    }

    /* Scale verify workers with CPU count by default, but keep enough headroom
     * for tx execution/replay workers on high-core boxes. */
    uint32_t workers = 8;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu > 0) {
        uint32_t scaled = (uint32_t)(ncpu / 4);
        if (scaled < 8u) scaled = 8u;
        workers = scaled;
    }
    const char* env = getenv("SOL_REPLAY_VERIFY_WORKERS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long parsed = strtoul(env, &end, 10);
        if (end && end != env) {
            workers = (uint32_t)parsed;
        }
    }

    if (workers < 1u) workers = 1u;
    if (workers > 64u) workers = 64u;
    __atomic_store_n(&cached, workers, __ATOMIC_RELEASE);
    return workers;
}

static uint64_t
replay_verify_wait_budget_ns(void) {
    static uint64_t cached = UINT64_MAX;
    uint64_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (v != UINT64_MAX) {
        return v;
    }

    /* In async verify mode, replay overlaps tx execution + PoH verification.
     * A very small wait budget forces frequent sync fallback, negating overlap
     * and causing duplicate verify work on outliers. */
    uint64_t budget_ms = 256u;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu > 0 && ncpu < 64) {
        budget_ms = 384u;
    }

    const char* env = getenv("SOL_REPLAY_VERIFY_WAIT_BUDGET_MS");
    if (env && env[0] != '\0') {
        errno = 0;
        char* end = NULL;
        unsigned long long parsed = strtoull(env, &end, 10);
        if (errno == 0 && end && end != env) {
            while (*end && isspace((unsigned char)*end)) end++;
            if (*end == '\0') {
                budget_ms = (uint64_t)parsed;
            }
        }
    }

    /* Allow 0ms budget for "no-wait" mode (immediate sync-fallback). */
    if (budget_ms > 1000u) budget_ms = 1000u;
    uint64_t budget_ns = budget_ms * 1000ull * 1000ull;
    __atomic_store_n(&cached, budget_ns, __ATOMIC_RELEASE);
    return budget_ns;
}

static bool
replay_get_leader_pubkey(sol_replay_t* replay, sol_slot_t slot, sol_pubkey_t* out) {
    if (!replay || !out) return false;

    bool found = false;
    pthread_mutex_lock(&replay->lock);
    if (replay->leader_schedule) {
        const sol_pubkey_t* leader =
            sol_leader_schedule_get_leader(replay->leader_schedule, slot);
        if (leader && !sol_pubkey_is_zero(leader)) {
            *out = *leader;
            found = true;
        }
    }
    pthread_mutex_unlock(&replay->lock);
    return found;
}

static void
replay_set_highest_replayed_locked(sol_replay_t* replay, sol_slot_t slot) {
    if (!replay) return;

    if (slot > replay->stats.highest_replayed_slot) {
        replay->stats.highest_replayed_slot = slot;
    }

    sol_slot_t cur = __atomic_load_n(&replay->highest_replayed_slot_atomic, __ATOMIC_RELAXED);
    if (slot > cur) {
        __atomic_store_n(&replay->highest_replayed_slot_atomic, slot, __ATOMIC_RELAXED);
    }
}

static inline void
replay_store_u64_be(uint8_t* dst, uint64_t v) {
    dst[0] = (uint8_t)(v >> 56);
    dst[1] = (uint8_t)(v >> 48);
    dst[2] = (uint8_t)(v >> 40);
    dst[3] = (uint8_t)(v >> 32);
    dst[4] = (uint8_t)(v >> 24);
    dst[5] = (uint8_t)(v >> 16);
    dst[6] = (uint8_t)(v >> 8);
    dst[7] = (uint8_t)(v);
}

/*
 * Hash function for slot
 */
static size_t
slot_hash(sol_slot_t slot, size_t bucket_count) {
    return (size_t)(slot % bucket_count);
}

/*
 * Find replayed slot entry
 */
static sol_replayed_slot_t*
find_replayed(sol_replay_t* replay, sol_slot_t slot) {
    size_t idx = slot_hash(slot, replay->replayed_bucket_count);
    sol_replayed_slot_t* entry = replay->replayed_buckets[idx];

    while (entry) {
        if (entry->slot == slot) {
            return entry;
        }
        entry = entry->next;
    }

    return NULL;
}

static uint32_t
count_complete_variants(sol_blockstore_t* bs, sol_slot_t slot, uint32_t variant_count) {
    if (!bs || variant_count == 0) return 0;

    uint32_t complete = 0;
    for (uint32_t variant_id = 0; variant_id < variant_count; variant_id++) {
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

static bool
replay_has_any_shreds(const sol_replay_t* replay, sol_slot_t slot) {
    if (!replay || !replay->blockstore) return false;

    sol_slot_meta_t meta;
    if (sol_blockstore_get_slot_meta(replay->blockstore, slot, &meta) != SOL_OK) {
        return false;
    }

    return meta.received_data > 0;
}

static bool
replay_parent_available(sol_replay_t* replay, sol_slot_t slot, sol_slot_t parent_slot);

static bool
replay_find_slot_parent(sol_replay_t* replay, sol_slot_t slot, sol_slot_t* out_parent_slot) {
    if (!replay || !replay->blockstore || !out_parent_slot) return false;

    /* Parent readiness is variant-sensitive under duplicate forks.  Track the
     * first observed parent for diagnostics/fallback, but prefer returning a
     * parent that is currently replay-available if any variant provides one. */
    sol_slot_t first_parent_slot = 0;
    bool have_first_parent = false;

    size_t num_variants = sol_blockstore_num_variants(replay->blockstore, slot);
    if (num_variants == 0) {
        num_variants = 1;
    }

    /* Prefer metadata-only lookup: this avoids assembling/loading full block
     * payloads in the replay scheduling hot path. */
    for (uint32_t variant_id = 0; variant_id < (uint32_t)num_variants; variant_id++) {
        sol_slot_meta_t meta;
        if (sol_blockstore_get_slot_meta_variant(replay->blockstore, slot, variant_id, &meta) != SOL_OK) {
            continue;
        }
        if (!have_first_parent) {
            first_parent_slot = meta.parent_slot;
            have_first_parent = true;
        }
        if (replay_parent_available(replay, slot, meta.parent_slot)) {
            *out_parent_slot = meta.parent_slot;
            return true;
        }
    }

    /* Fallback for ledgers that may have block data without variant metadata. */
    for (uint32_t variant_id = 0; variant_id < (uint32_t)num_variants; variant_id++) {
        sol_block_t* block = sol_blockstore_get_block_variant(replay->blockstore, slot, variant_id);
        if (!block) continue;
        if (!block->data || block->data_len == 0) {
            sol_block_destroy(block);
            continue;
        }
        if (!have_first_parent) {
            first_parent_slot = block->parent_slot;
            have_first_parent = true;
        }
        if (replay_parent_available(replay, slot, block->parent_slot)) {
            *out_parent_slot = block->parent_slot;
            sol_block_destroy(block);
            return true;
        }
        sol_block_destroy(block);
    }

    if (have_first_parent) {
        *out_parent_slot = first_parent_slot;
        return true;
    }

    return false;
}

static bool
replay_parent_available(sol_replay_t* replay, sol_slot_t slot, sol_slot_t parent_slot) {
    if (!replay) return false;
    if (parent_slot == slot) return true;
    /* Parent is considered available only once a frozen parent bank exists.
     * A replay-tracking entry alone is insufficient because the parent may be
     * concurrently in-progress and not yet inserted/frozen in bank-forks. */
    return sol_replay_has_frozen_bank(replay, parent_slot);
}

static void
replay_prewarm_accounts_for_batch(sol_bank_t* parent_bank,
                                  const sol_entry_batch_t* batch,
                                  bool warm_account_views) {
    if (!parent_bank || !batch || batch->num_entries == 0) return;

    const size_t max_txs = replay_prewarm_max_txs();
    const size_t max_accounts = warm_account_views ? replay_prewarm_max_accounts() : 0u;
    const size_t max_keys_per_tx = warm_account_views ? replay_prewarm_max_keys_per_tx() : 0u;
    const bool include_readonly = warm_account_views ? replay_prewarm_include_readonly() : false;
    bool prewarm_programs = replay_prewarm_bpf_programs();
    bool allow_program_elf_prewarm = warm_account_views;
    if (!allow_program_elf_prewarm && replay_sync_prewarm_programs()) {
        /* In sync-prewarm mode we intentionally avoid account-view warming,
         * but still allow bounded BPF ELF prewarm to smooth tx execution tails. */
        allow_program_elf_prewarm = true;
    }
    const size_t max_programs = prewarm_programs ? replay_prewarm_max_programs() : 0;
    const uint64_t prewarm_budget_ns = replay_sync_prewarm_budget_ns();
    const uint64_t prewarm_t0 = prewarm_budget_ns ? get_time_ns() : 0u;
    uint64_t prewarm_deadline_ns = 0u;
    if (prewarm_budget_ns != 0u) {
        prewarm_deadline_ns = prewarm_t0 + prewarm_budget_ns;
        if (prewarm_deadline_ns < prewarm_t0) {
            prewarm_deadline_ns = UINT64_MAX;
        }
    }

    sol_pubkey_t resolved_keys[SOL_MAX_MESSAGE_ACCOUNTS];
    bool resolved_writable[SOL_MAX_MESSAGE_ACCOUNTS];
    bool resolved_signer[SOL_MAX_MESSAGE_ACCOUNTS];
    sol_pubkey_t* warmed_programs = NULL;
    size_t warmed_programs_len = 0;
    sol_pubkey_t* attempted_program_candidates = NULL;
    size_t attempted_program_candidates_len = 0;
    size_t attempted_program_candidates_cap = 0;

    if (prewarm_programs && max_programs > 0) {
        warmed_programs = sol_alloc(max_programs * sizeof(sol_pubkey_t));
        if (!warmed_programs) {
            prewarm_programs = false;
        } else {
            /* Track all candidate keys we probed so we don't repeatedly load
             * non-program readonly accounts. Keep this bounded and proportional
             * to the program prewarm budget. */
            attempted_program_candidates_cap = max_programs * 8u;
            if (attempted_program_candidates_cap < max_programs) {
                attempted_program_candidates_cap = max_programs;
            }
            if (attempted_program_candidates_cap > 262144u) {
                attempted_program_candidates_cap = 262144u;
            }
            attempted_program_candidates =
                sol_alloc(attempted_program_candidates_cap * sizeof(sol_pubkey_t));
            if (!attempted_program_candidates) {
                prewarm_programs = false;
            }
        }
    }

    size_t warmed_txs = 0;
    size_t warmed_accounts = 0;

    for (size_t ei = 0; ei < batch->num_entries && warmed_txs < max_txs; ei++) {
        const sol_entry_t* entry = &batch->entries[ei];
        for (size_t ti = 0; ti < entry->num_transactions && warmed_txs < max_txs; ti++) {
            if (__builtin_expect(prewarm_budget_ns != 0u, 0) &&
                __builtin_expect((get_time_ns() - prewarm_t0) >= prewarm_budget_ns, 0)) {
                goto prewarm_done;
            }

            const sol_transaction_t* tx = &entry->transactions[ti];
            size_t resolved_len = 0;
            sol_err_t rerr = sol_bank_resolve_transaction_accounts(
                parent_bank,
                tx,
                resolved_keys,
                resolved_writable,
                resolved_signer,
                SOL_MAX_MESSAGE_ACCOUNTS,
                &resolved_len);

            const sol_pubkey_t* account_keys = tx->message.account_keys;
            size_t account_keys_len = tx->message.account_keys_len;
            const bool* writable_flags = NULL;
            const bool* signer_flags = NULL;

            if (rerr == SOL_OK && resolved_len > 0) {
                account_keys = resolved_keys;
                account_keys_len = resolved_len;
                writable_flags = resolved_writable;
                signer_flags = resolved_signer;
            }

            if (prewarm_programs &&
                warmed_programs &&
                attempted_program_candidates &&
                warmed_programs_len < max_programs &&
                account_keys &&
                account_keys_len > 0 &&
                tx->message.instructions &&
                tx->message.instructions_len > 0) {
                for (size_t ii = 0;
                     ii < tx->message.instructions_len && warmed_programs_len < max_programs;
                     ii++) {
                    if (__builtin_expect(prewarm_budget_ns != 0u, 0) &&
                        __builtin_expect((ii & 7u) == 0u, 1) &&
                        __builtin_expect((get_time_ns() - prewarm_t0) >= prewarm_budget_ns, 0)) {
                        goto prewarm_done;
                    }

                    const sol_compiled_instruction_t* ix = &tx->message.instructions[ii];
                    size_t pid_index = (size_t)ix->program_id_index;
                    if (pid_index >= account_keys_len) {
                        continue;
                    }

                    if (!replay_try_prewarm_program_key(parent_bank,
                                                        &account_keys[pid_index],
                                                        attempted_program_candidates,
                                                        &attempted_program_candidates_len,
                                                        attempted_program_candidates_cap,
                                                        warmed_programs,
                                                        &warmed_programs_len,
                                                        max_programs,
                                                        allow_program_elf_prewarm,
                                                        prewarm_deadline_ns)) {
                        goto prewarm_done;
                    }

                    for (size_t ai = 0;
                         ai < ix->account_indices_len && warmed_programs_len < max_programs;
                         ai++) {
                        if (__builtin_expect(prewarm_budget_ns != 0u, 0) &&
                            __builtin_expect((ai & 15u) == 0u, 1) &&
                            __builtin_expect((get_time_ns() - prewarm_t0) >= prewarm_budget_ns, 0)) {
                            goto prewarm_done;
                        }

                        size_t acct_index = (size_t)ix->account_indices[ai];
                        if (acct_index >= account_keys_len) {
                            continue;
                        }

                        bool writable = false;
                        bool signer = false;
                        if (writable_flags && signer_flags) {
                            writable = writable_flags[acct_index];
                            signer = signer_flags[acct_index];
                        } else if (acct_index <= UINT8_MAX) {
                            writable = sol_message_is_writable_index(&tx->message, (uint8_t)acct_index);
                            signer = sol_message_is_signer(&tx->message, (uint8_t)acct_index);
                        }

                        /* CPI program accounts are typically readonly/non-signer.
                         * Probe these as candidate executable program IDs so they
                         * are warmed before tx execution starts. */
                        if (writable || signer) {
                            continue;
                        }

                        if (!replay_try_prewarm_program_key(parent_bank,
                                                            &account_keys[acct_index],
                                                            attempted_program_candidates,
                                                            &attempted_program_candidates_len,
                                                            attempted_program_candidates_cap,
                                                            warmed_programs,
                                                            &warmed_programs_len,
                                                            max_programs,
                                                            allow_program_elf_prewarm,
                                                            prewarm_deadline_ns)) {
                            goto prewarm_done;
                        }
                    }
                }
            }

            if (!warm_account_views || !account_keys || account_keys_len == 0) {
                warmed_txs++;
                continue;
            }

            size_t keys_to_warm = account_keys_len;
            if (keys_to_warm > max_keys_per_tx) {
                keys_to_warm = max_keys_per_tx;
            }

            for (size_t ki = 0; ki < keys_to_warm && warmed_accounts < max_accounts; ki++) {
                if (__builtin_expect(prewarm_budget_ns != 0u, 0) &&
                    __builtin_expect((ki & 15u) == 0u, 1) &&
                    __builtin_expect((get_time_ns() - prewarm_t0) >= prewarm_budget_ns, 0)) {
                    goto prewarm_done;
                }

                bool writable = false;
                bool signer = false;
                if (writable_flags && signer_flags) {
                    writable = writable_flags[ki];
                    signer = signer_flags[ki];
                } else if (ki <= UINT8_MAX) {
                    writable = sol_message_is_writable_index(&tx->message, (uint8_t)ki);
                    signer = sol_message_is_signer(&tx->message, (uint8_t)ki);
                }

                if (!include_readonly &&
                    !writable &&
                    !signer) {
                    /* Skip cold readonly/non-signer tails by default. */
                    continue;
                }
                sol_account_t* view = sol_bank_load_account_view(parent_bank, &account_keys[ki]);
                if (view) {
                    sol_account_destroy(view);
                }
                warmed_accounts++;
            }
            warmed_txs++;
        }
    }

prewarm_done:
    sol_free(attempted_program_candidates);
    sol_free(warmed_programs);
}

static inline uint64_t
replay_next_lease_id_locked(sol_replay_t* replay) {
    replay->replay_lease_seq++;
    if (__builtin_expect(replay->replay_lease_seq == 0u, 0)) {
        replay->replay_lease_seq = 1u;
    }
    return replay->replay_lease_seq;
}

static inline void
replay_clear_in_progress_locked(sol_replayed_slot_t* entry) {
    if (!entry) return;
    entry->in_progress = false;
    entry->in_progress_since_ns = 0;
    entry->in_progress_lease_id = 0;
    replay_set_stage(entry, REPLAY_STAGE_NONE);
}

static bool
remove_replayed_entry(sol_replay_t* replay, sol_slot_t slot);

static bool
replay_release_slot_attempt_locked(sol_replay_t* replay,
                                   sol_slot_t slot,
                                   bool entry_created,
                                   uint64_t lease_id,
                                   bool remove_if_created) {
    sol_replayed_slot_t* cur = find_replayed(replay, slot);
    if (!cur) return false;
    if (__builtin_expect(cur->in_progress_lease_id != lease_id, 0)) {
        return false;
    }

    if (remove_if_created && entry_created) {
        return remove_replayed_entry(replay, slot);
    }

    replay_clear_in_progress_locked(cur);
    return true;
}

/*
 * Mark slot as replayed (or update existing entry)
 */
static void
mark_replayed(sol_replay_t* replay,
              sol_slot_t slot,
              bool is_dead,
              uint32_t variant_count,
              uint32_t complete_variant_count) {
    sol_replayed_slot_t* existing = find_replayed(replay, slot);
    if (existing) {
        existing->is_dead = is_dead;
        existing->variant_count = variant_count;
        existing->complete_variant_count = complete_variant_count;
        replay_clear_in_progress_locked(existing);
        return;
    }

    sol_replayed_slot_t* entry = sol_calloc(1, sizeof(sol_replayed_slot_t));
    if (!entry) return;

    entry->slot = slot;
    entry->is_dead = is_dead;
    entry->in_progress = false;
    entry->in_progress_since_ns = 0;
    entry->in_progress_lease_id = 0;
    entry->variant_count = variant_count;
    entry->complete_variant_count = complete_variant_count;

    size_t idx = slot_hash(slot, replay->replayed_bucket_count);
    entry->next = replay->replayed_buckets[idx];
    replay->replayed_buckets[idx] = entry;
}

static sol_replayed_slot_t*
ensure_replayed_entry(sol_replay_t* replay, sol_slot_t slot) {
    sol_replayed_slot_t* entry = find_replayed(replay, slot);
    if (entry) {
        return entry;
    }

    entry = sol_calloc(1, sizeof(sol_replayed_slot_t));
    if (!entry) return NULL;

    entry->slot = slot;
    entry->is_dead = false;
    entry->in_progress = false;
    entry->in_progress_since_ns = 0;
    entry->in_progress_lease_id = 0;
    entry->variant_count = 0;
    entry->complete_variant_count = 0;

    size_t idx = slot_hash(slot, replay->replayed_bucket_count);
    entry->next = replay->replayed_buckets[idx];
    replay->replayed_buckets[idx] = entry;
    return entry;
}

static bool
remove_replayed_entry(sol_replay_t* replay, sol_slot_t slot) {
    size_t idx = slot_hash(slot, replay->replayed_bucket_count);
    sol_replayed_slot_t** prev = &replay->replayed_buckets[idx];
    sol_replayed_slot_t* entry = *prev;
    while (entry) {
        if (entry->slot == slot) {
            *prev = entry->next;
            sol_free(entry);
            return true;
        }
        prev = &entry->next;
        entry = entry->next;
    }
    return false;
}

/*
 * Get current time in nanoseconds
 */
static uint64_t
get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static bool
replay_timing_enable(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (v >= 0) {
        return v != 0;
    }

    const char* env = getenv("SOL_REPLAY_TIMING");
    int enabled = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled != 0;
}

static long
replay_timing_threshold_ms(void) {
    static long cached = -1;
    long v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (v >= 0) {
        return v;
    }

    long threshold = 300; /* default */
    const char* env = getenv("SOL_REPLAY_TIMING_THRESHOLD_MS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        long parsed = strtol(env, &end, 10);
        if (end && end != env) {
            threshold = parsed;
        }
    }

    if (threshold < 0) {
        threshold = 0;
    }

    __atomic_store_n(&cached, threshold, __ATOMIC_RELEASE);
    return threshold;
}

static long
replay_slow_stage_threshold_ms(void) {
    static long cached = LONG_MIN;
    long v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (v != LONG_MIN) {
        return v;
    }

    /* Default off: per-slot stage attribution logs are expensive on mainnet and
     * can become self-inflicted replay backpressure. Operators can still enable
     * these logs explicitly via SOL_REPLAY_SLOW_STAGE_THRESHOLD_MS, while
     * Replay slow (>=1s) diagnostics remain always-on. */
    long threshold = -1; /* default */
    const char* env = getenv("SOL_REPLAY_SLOW_STAGE_THRESHOLD_MS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        long parsed = strtol(env, &end, 10);
        if (end && end != env) {
            threshold = parsed;
        }
    }

    /* Negative disables default-on slow-stage attribution logging. */
    __atomic_store_n(&cached, threshold, __ATOMIC_RELEASE);
    return threshold;
}

static bool
replay_parent_recheck_enable(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (v >= 0) {
        return v != 0;
    }

    /* Default off to avoid rare multi-second stalls on bank-forks read lock.
     * Enable strict re-check explicitly when debugging/prioritizing races. */
    const char* env = getenv("SOL_REPLAY_PARENT_RECHECK");
    int enabled = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled != 0;
}

static void
bytes32_to_base58(const uint8_t bytes[32], char* out, size_t out_len) {
    if (!out || out_len == 0) return;
    out[0] = '\0';
    if (!bytes) return;

    sol_pubkey_t pk;
    memcpy(pk.bytes, bytes, sizeof(pk.bytes));
    (void)sol_pubkey_to_base58(&pk, out, out_len);
}

static bool
bank_frozen_log_enable_lt_hash_checksum(void) {
    static int cached = -1;
    if (cached >= 0) {
        return cached != 0;
    }

    const char* env = getenv("SOL_LOG_BANK_FROZEN_LT_HASH");
    cached = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    return cached != 0;
}

static bool
bank_frozen_log_enable_accounts_delta_hash(void) {
    static int cached = -1;
    if (cached >= 0) {
        return cached != 0;
    }

    const char* env = getenv("SOL_LOG_BANK_FROZEN_ACCOUNTS_DELTA_HASH");
    cached = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    return cached != 0;
}

static bool
bank_frozen_log_enable_vote_parity(void) {
    static int cached = -1;
    if (cached >= 0) {
        return cached != 0;
    }

    const char* env = getenv("SOL_LOG_BANK_FROZEN_VOTE_PARITY");
    cached = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    return cached != 0;
}

static bool
bank_frozen_log_force_info(void) {
    static int cached = -1;
    if (cached >= 0) {
        return cached != 0;
    }

    const char* env = getenv("SOL_LOG_BANK_FROZEN");
    cached = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    return cached != 0;
}

static void
log_bank_frozen(sol_bank_t* bank) {
    if (!bank || !sol_bank_is_frozen(bank)) return;
    if (replay_fast_mode()) return;

    /* These logs are helpful for parity debugging but far too verbose for
     * mainnet replay. Default: only emit when log-level is DEBUG/TRACE or when
     * explicitly forced via SOL_LOG_BANK_FROZEN=1. */
    const bool force_info = bank_frozen_log_force_info();
    if (!force_info && sol_log_get_level() > SOL_LOG_DEBUG) {
        return;
    }

    sol_slot_t slot = sol_bank_slot(bank);
    uint64_t signature_count = sol_bank_signature_count(bank);

    sol_bank_stats_t bank_stats;
    sol_bank_stats(bank, &bank_stats);

    sol_hash_t bank_hash = {0};
    sol_bank_compute_hash(bank, &bank_hash);

    char bank_hash_b58[SOL_PUBKEY_BASE58_LEN] = {0};
    bytes32_to_base58(bank_hash.bytes, bank_hash_b58, sizeof(bank_hash_b58));

    char last_blockhash_b58[SOL_PUBKEY_BASE58_LEN] = {0};
    const sol_hash_t* last_blockhash = sol_bank_blockhash(bank);
    if (last_blockhash) {
        bytes32_to_base58(last_blockhash->bytes, last_blockhash_b58, sizeof(last_blockhash_b58));
    }

    char accounts_delta_hash_b58[SOL_PUBKEY_BASE58_LEN] = {0};
    sol_hash_t accounts_delta_hash = {0};
    if (bank_frozen_log_enable_accounts_delta_hash()) {
        if (sol_bank_get_accounts_delta_hash(bank, &accounts_delta_hash) &&
            !sol_hash_is_zero(&accounts_delta_hash)) {
            bytes32_to_base58(accounts_delta_hash.bytes,
                              accounts_delta_hash_b58,
                              sizeof(accounts_delta_hash_b58));
        }
    }

    sol_blake3_t lt_checksum = {0};
    char lt_checksum_b58[SOL_PUBKEY_BASE58_LEN] = {0};
    if (bank_frozen_log_enable_lt_hash_checksum()) {
        sol_bank_accounts_lt_hash_checksum(bank, &lt_checksum);
        bytes32_to_base58(lt_checksum.bytes, lt_checksum_b58, sizeof(lt_checksum_b58));
    }

    if (force_info) {
        sol_log_info("bank frozen: %lu hash: %s signature_count: %lu tx_processed: %lu tx_succeeded: %lu tx_failed: %lu last_blockhash: %s accounts_delta_hash: %s accounts_lt_hash checksum: %s",
                     (unsigned long)slot,
                     bank_hash_b58[0] ? bank_hash_b58 : "-",
                     (unsigned long)signature_count,
                     (unsigned long)bank_stats.transactions_processed,
                     (unsigned long)bank_stats.transactions_succeeded,
                     (unsigned long)bank_stats.transactions_failed,
                     last_blockhash_b58[0] ? last_blockhash_b58 : "-",
                     accounts_delta_hash_b58[0] ? accounts_delta_hash_b58 : "-",
                     lt_checksum_b58[0] ? lt_checksum_b58 : "-");
    } else {
        sol_log_debug("bank frozen: %lu hash: %s signature_count: %lu tx_processed: %lu tx_succeeded: %lu tx_failed: %lu last_blockhash: %s accounts_delta_hash: %s accounts_lt_hash checksum: %s",
                      (unsigned long)slot,
                      bank_hash_b58[0] ? bank_hash_b58 : "-",
                      (unsigned long)signature_count,
                      (unsigned long)bank_stats.transactions_processed,
                      (unsigned long)bank_stats.transactions_succeeded,
                      (unsigned long)bank_stats.transactions_failed,
                      last_blockhash_b58[0] ? last_blockhash_b58 : "-",
                      accounts_delta_hash_b58[0] ? accounts_delta_hash_b58 : "-",
                      lt_checksum_b58[0] ? lt_checksum_b58 : "-");
    }

    uint64_t total_prevalidation_rejected =
        bank_stats.rejected_sanitize +
        bank_stats.rejected_duplicate +
        bank_stats.rejected_v0_resolve +
        bank_stats.rejected_compute_budget +
        bank_stats.rejected_blockhash +
        bank_stats.rejected_fee_payer_missing +
        bank_stats.rejected_insufficient_funds +
        bank_stats.rejected_signature;
    if (total_prevalidation_rejected > 0 || bank_stats.transactions_failed > 0) {
        if (force_info) {
            sol_log_info("bank frozen: %lu rejection_breakdown: sanitize=%lu duplicate=%lu v0_resolve=%lu compute_budget=%lu blockhash=%lu fee_payer_missing=%lu insufficient_funds=%lu signature=%lu (total_prevalidation=%lu execution_failed=%lu)",
                         (unsigned long)slot,
                         (unsigned long)bank_stats.rejected_sanitize,
                         (unsigned long)bank_stats.rejected_duplicate,
                         (unsigned long)bank_stats.rejected_v0_resolve,
                         (unsigned long)bank_stats.rejected_compute_budget,
                         (unsigned long)bank_stats.rejected_blockhash,
                         (unsigned long)bank_stats.rejected_fee_payer_missing,
                         (unsigned long)bank_stats.rejected_insufficient_funds,
                         (unsigned long)bank_stats.rejected_signature,
                         (unsigned long)total_prevalidation_rejected,
                         (unsigned long)(bank_stats.transactions_failed - total_prevalidation_rejected));
        } else {
            sol_log_debug("bank frozen: %lu rejection_breakdown: sanitize=%lu duplicate=%lu v0_resolve=%lu compute_budget=%lu blockhash=%lu fee_payer_missing=%lu insufficient_funds=%lu signature=%lu (total_prevalidation=%lu execution_failed=%lu)",
                          (unsigned long)slot,
                          (unsigned long)bank_stats.rejected_sanitize,
                          (unsigned long)bank_stats.rejected_duplicate,
                          (unsigned long)bank_stats.rejected_v0_resolve,
                          (unsigned long)bank_stats.rejected_compute_budget,
                          (unsigned long)bank_stats.rejected_blockhash,
                          (unsigned long)bank_stats.rejected_fee_payer_missing,
                          (unsigned long)bank_stats.rejected_insufficient_funds,
                          (unsigned long)bank_stats.rejected_signature,
                          (unsigned long)total_prevalidation_rejected,
                          (unsigned long)(bank_stats.transactions_failed - total_prevalidation_rejected));
        }
    }

    /* BankHashStats (compare with Agave's bank frozen stats) */
    if (force_info) {
        sol_log_info("bank frozen: %lu stats: { num_updated_accounts: %lu, num_removed_accounts: %lu, num_lamports_stored: %lu, total_data_len: %lu, num_executable_accounts: %lu }",
                     (unsigned long)slot,
                     (unsigned long)bank_stats.num_updated_accounts,
                     (unsigned long)bank_stats.num_removed_accounts,
                     (unsigned long)bank_stats.num_lamports_stored,
                     (unsigned long)bank_stats.total_data_len,
                     (unsigned long)bank_stats.num_executable_accounts);
    } else {
        sol_log_debug("bank frozen: %lu stats: { num_updated_accounts: %lu, num_removed_accounts: %lu, num_lamports_stored: %lu, total_data_len: %lu, num_executable_accounts: %lu }",
                      (unsigned long)slot,
                      (unsigned long)bank_stats.num_updated_accounts,
                      (unsigned long)bank_stats.num_removed_accounts,
                      (unsigned long)bank_stats.num_lamports_stored,
                      (unsigned long)bank_stats.total_data_len,
                      (unsigned long)bank_stats.num_executable_accounts);
    }
}

static void
log_bank_frozen_vote_parity(sol_replay_t* replay, sol_bank_t* bank) {
    if (replay_fast_mode()) return;
    if (!bank_frozen_log_enable_vote_parity()) return;
    if (!replay || !replay->fork_choice || !bank || !sol_bank_is_frozen(bank)) return;

    sol_slot_t slot = sol_bank_slot(bank);

    sol_hash_t local_hash = {0};
    sol_bank_compute_hash(bank, &local_hash);

    uint64_t total_stake = sol_fork_choice_total_stake(replay->fork_choice);
    size_t voter_count = sol_fork_choice_voter_count(replay->fork_choice);

    sol_hash_t best_hash = {0};
    uint64_t best_stake = 0;
    uint32_t best_votes = 0;
    uint64_t slot_total_stake = 0;
    uint32_t slot_total_votes = 0;
    bool have_votes = sol_fork_choice_best_voted_hash(replay->fork_choice,
                                                      slot,
                                                      &best_hash,
                                                      &best_stake,
                                                      &best_votes,
                                                      &slot_total_stake,
                                                      &slot_total_votes);

    uint64_t local_stake = 0;
    if (!sol_hash_is_zero(&local_hash)) {
        local_stake = sol_fork_choice_stake_weight_hash(replay->fork_choice, slot, &local_hash);
    }

    char local_hash_b58[SOL_PUBKEY_BASE58_LEN] = {0};
    if (!sol_hash_is_zero(&local_hash)) {
        bytes32_to_base58(local_hash.bytes, local_hash_b58, sizeof(local_hash_b58));
    }

    char best_hash_b58[SOL_PUBKEY_BASE58_LEN] = {0};
    if (have_votes && !sol_hash_is_zero(&best_hash)) {
        bytes32_to_base58(best_hash.bytes, best_hash_b58, sizeof(best_hash_b58));
    }

    const char* match =
        (have_votes &&
         !sol_hash_is_zero(&local_hash) &&
         !sol_hash_is_zero(&best_hash) &&
         memcmp(local_hash.bytes, best_hash.bytes, SOL_HASH_SIZE) == 0) ? "yes" : "no";

    sol_log_info("bank frozen votes: slot=%lu match=%s local_hash=%s local_stake=%lu best_hash=%s best_stake=%lu best_votes=%u slot_stake=%lu slot_votes=%u total_stake=%lu voters=%zu",
                 (unsigned long)slot,
                 match,
                 local_hash_b58[0] ? local_hash_b58 : "-",
                 (unsigned long)local_stake,
                 best_hash_b58[0] ? best_hash_b58 : "-",
                 (unsigned long)best_stake,
                 (unsigned)best_votes,
                 (unsigned long)slot_total_stake,
                 (unsigned)slot_total_votes,
                 (unsigned long)total_stake,
                 voter_count);
}

typedef struct {
    sol_hash_t* hashes;
    size_t      count;
    size_t      cap;
} bank_hash_list_t;

static bool
collect_bank_hashes_cb(const sol_hash_t* bank_hash,
                       sol_bank_t* bank,
                       bool is_dead,
                       void* ctx) {
    bank_hash_list_t* list = (bank_hash_list_t*)ctx;
    if (!list) {
        return true;
    }

    if (is_dead || !bank || !sol_bank_is_frozen(bank)) {
        return true;
    }

    sol_hash_t h = {0};
    if (bank_hash) {
        h = *bank_hash;
    }
    if (sol_hash_is_zero(&h)) {
        sol_bank_compute_hash(bank, &h);
    }
    if (sol_hash_is_zero(&h)) {
        return true;
    }

    for (size_t i = 0; i < list->count; i++) {
        if (memcmp(list->hashes[i].bytes, h.bytes, SOL_HASH_SIZE) == 0) {
            return true;
        }
    }

    if (list->count == list->cap) {
        size_t new_cap = list->cap ? (list->cap * 2) : 4;
        if (new_cap < list->cap) {
            return false;
        }
        sol_hash_t* new_hashes = sol_realloc(list->hashes, new_cap * sizeof(*new_hashes));
        if (!new_hashes) {
            return false;
        }
        list->hashes = new_hashes;
        list->cap = new_cap;
    }

    list->hashes[list->count++] = h;
    return true;
}

sol_replay_t*
sol_replay_new(sol_bank_forks_t* bank_forks,
               sol_blockstore_t* blockstore,
               const sol_replay_config_t* config) {
    if (!bank_forks || !blockstore) return NULL;

    sol_replay_t* replay = sol_calloc(1, sizeof(sol_replay_t));
    if (!replay) return NULL;

    if (config) {
        replay->config = *config;
    } else {
        replay->config = (sol_replay_config_t)SOL_REPLAY_CONFIG_DEFAULT;
    }

    const char* replay_all_variants_env = getenv("SOL_REPLAY_ALL_VARIANTS");
    if (replay_all_variants_env &&
        replay_all_variants_env[0] != '\0' &&
        strcmp(replay_all_variants_env, "0") != 0) {
        replay->config.replay_all_variants = true;
    }

    replay->bank_forks = bank_forks;
    replay->blockstore = blockstore;

    /* Create fork choice tracker */
    replay->fork_choice = sol_fork_choice_new(bank_forks, NULL);
    if (!replay->fork_choice) {
        sol_free(replay);
        return NULL;
    }

    /* Initialize replayed slots tracking */
    replay->replayed_bucket_count = 256;
    replay->replayed_buckets = sol_calloc(replay->replayed_bucket_count,
                                           sizeof(sol_replayed_slot_t*));
    if (!replay->replayed_buckets) {
        sol_fork_choice_destroy(replay->fork_choice);
        sol_free(replay);
        return NULL;
    }

    if (pthread_mutex_init(&replay->lock, NULL) != 0) {
        sol_free(replay->replayed_buckets);
        sol_fork_choice_destroy(replay->fork_choice);
        sol_free(replay);
        return NULL;
    }

    replay->verify_workers = NULL;
    replay->verify_worker_count = 0;
    uint32_t verify_workers_monotonic = 0;
    if (replay_verify_async()) {
        replay->verify_worker_count = replay_verify_worker_count();
        replay->verify_workers =
            sol_calloc(replay->verify_worker_count, sizeof(sol_replay_verify_worker_t));

        if (!replay->verify_workers) {
            replay->verify_worker_count = 0;
        } else {
            uint32_t started = 0;
            for (uint32_t i = 0; i < replay->verify_worker_count; i++) {
                sol_replay_verify_worker_t* w = &replay->verify_workers[i];
                memset(w, 0, sizeof(*w));

                if (pthread_mutex_init(&w->mu, NULL) != 0) break;
                if (pthread_cond_init(&w->cv, NULL) != 0) {
                    pthread_mutex_destroy(&w->mu);
                    break;
                }

                pthread_condattr_t done_attr;
                bool done_attr_inited = false;
                bool done_clock_monotonic = false;
                if (pthread_condattr_init(&done_attr) == 0) {
                    done_attr_inited = true;
#if defined(CLOCK_MONOTONIC)
                    if (pthread_condattr_setclock(&done_attr, CLOCK_MONOTONIC) == 0) {
                        done_clock_monotonic = true;
                    }
#endif
                }

                if (pthread_cond_init(&w->done, done_clock_monotonic ? &done_attr : NULL) != 0) {
                    if (done_attr_inited) {
                        pthread_condattr_destroy(&done_attr);
                    }
                    pthread_cond_destroy(&w->cv);
                    pthread_mutex_destroy(&w->mu);
                    break;
                }
                if (done_attr_inited) {
                    pthread_condattr_destroy(&done_attr);
                }

                w->inited = true;
                w->stop = false;
                w->has_job = false;
                w->job_done = true;
                w->done_clock_monotonic = done_clock_monotonic;

                if (pthread_create(&w->thread, NULL, replay_verify_worker_main, w) != 0) {
                    pthread_cond_destroy(&w->done);
                    pthread_cond_destroy(&w->cv);
                    pthread_mutex_destroy(&w->mu);
                    w->inited = false;
                    break;
                }

                w->started = true;
                started++;
                if (done_clock_monotonic) {
                    verify_workers_monotonic++;
                }
            }

            if (started == 0) {
                sol_free(replay->verify_workers);
                replay->verify_workers = NULL;
                replay->verify_worker_count = 0;
            } else if (started < replay->verify_worker_count) {
                replay->verify_worker_count = started;
            }
        }
    }

    if (replay_verify_async()) {
        if (replay->verify_worker_count > 0) {
            uint64_t wait_budget_ms = replay_verify_wait_budget_ns() / 1000000ull;
            sol_log_info("Replay verify: async=on workers=%u monotonic_done=%u wait_budget_ms=%llu",
                         (unsigned)replay->verify_worker_count,
                         (unsigned)verify_workers_monotonic,
                         (unsigned long long)wait_budget_ms);
            if (verify_workers_monotonic != replay->verify_worker_count) {
                sol_log_warn("Replay verify: %u/%u workers missing CLOCK_MONOTONIC condvar support; timed waits use realtime fallback",
                             (unsigned)(replay->verify_worker_count - verify_workers_monotonic),
                             (unsigned)replay->verify_worker_count);
            }
        } else {
            sol_log_warn("Replay verify: async requested but workers unavailable; using inline verification");
        }
    } else {
        sol_log_info("Replay verify: async=off");
    }
    sol_log_info("Replay prewarm config: bpf_programs=%s sync_programs=%s sync_budget_ms=%llu max_programs=%zu max_variants=%zu include_readonly=%s",
                 replay_prewarm_bpf_programs() ? "on" : "off",
                 replay_sync_prewarm_programs() ? "on" : "off",
                 (unsigned long long)(replay_sync_prewarm_budget_ns() / 1000000ull),
                 replay_prewarm_max_programs(),
                 replay_prewarm_max_variants(),
                 replay_prewarm_include_readonly() ? "on" : "off");

    /* Mark root slot as replayed */
    sol_slot_t root = sol_bank_forks_root_slot(bank_forks);
    if (root != 0) {
        /* Replay parent-availability checks require a frozen parent bank in
         * bank-forks. Snapshot bootstrap can seed root/highest_replayed before
         * the root entry is explicitly frozen, which can stall replay at
         * root+1 with repeated PARENT_MISSING. */
        sol_bank_t* root_bank = sol_bank_forks_get(bank_forks, root);
        if (root_bank) {
            if (!sol_bank_is_frozen(root_bank)) {
                sol_bank_freeze(root_bank);
            }
            /* Precompute hash once at bootstrap so the first child bank build
             * doesn't pay a full parent-hash cost in the replay hot path. */
            sol_hash_t root_hash = {0};
            sol_bank_compute_hash(root_bank, &root_hash);
            (void)sol_bank_forks_freeze(bank_forks, root);
        }
    }
    uint32_t root_variants = (uint32_t)sol_blockstore_num_variants(blockstore, root);
    uint32_t root_complete = count_complete_variants(blockstore, root, root_variants);
    mark_replayed(replay, root, false, root_variants, root_complete);
    replay->stats.highest_replayed_slot = root;
    replay->highest_replayed_slot_atomic = root;
    if (root != 0 && !sol_bank_forks_has_frozen_slot(bank_forks, root)) {
        sol_log_warn("Replay bootstrap: root slot %lu has no frozen bank; parent gating may stall catchup",
                     (unsigned long)root);
    }

    return replay;
}

sol_leader_schedule_t*
sol_replay_swap_leader_schedule(sol_replay_t* replay, sol_leader_schedule_t* schedule) {
    if (!replay) return NULL;

    pthread_mutex_lock(&replay->lock);
    sol_leader_schedule_t* old = replay->leader_schedule;
    replay->leader_schedule = schedule;
    pthread_mutex_unlock(&replay->lock);
    return old;
}

void
sol_replay_destroy(sol_replay_t* replay) {
    if (!replay) return;

    if (replay->verify_workers && replay->verify_worker_count > 0) {
        for (uint32_t i = 0; i < replay->verify_worker_count; i++) {
            sol_replay_verify_worker_t* w = &replay->verify_workers[i];
            if (!w->inited) continue;

            if (w->started) {
                pthread_mutex_lock(&w->mu);
                w->stop = true;
                pthread_cond_broadcast(&w->cv);
                pthread_cond_broadcast(&w->done);
                pthread_mutex_unlock(&w->mu);
                (void)pthread_join(w->thread, NULL);
                w->started = false;
            }

            pthread_cond_destroy(&w->done);
            pthread_cond_destroy(&w->cv);
            pthread_mutex_destroy(&w->mu);
            w->inited = false;
        }
        sol_free(replay->verify_workers);
        replay->verify_workers = NULL;
        replay->verify_worker_count = 0;
    }

    /* Free pending slots */
    sol_pending_slot_t* pending = replay->pending_slots;
    while (pending) {
        sol_pending_slot_t* next = pending->next;
        sol_free(pending);
        pending = next;
    }

    /* Free replayed slots tracking */
    for (size_t i = 0; i < replay->replayed_bucket_count; i++) {
        sol_replayed_slot_t* entry = replay->replayed_buckets[i];
        while (entry) {
            sol_replayed_slot_t* next = entry->next;
            sol_free(entry);
            entry = next;
        }
    }
    sol_free(replay->replayed_buckets);

    sol_fork_choice_destroy(replay->fork_choice);
    pthread_mutex_destroy(&replay->lock);
    sol_free(replay);
}

typedef struct replay_entries_timing {
    uint64_t    process_entries_ns;
    uint64_t    process_prep_ns;
    uint64_t    process_tx_exec_ns;
    uint64_t    process_poh_ns;
    uint64_t    freeze_ns;
    uint64_t    compute_hash_ns;
    uint64_t    verify_sync_ns;
    uint64_t    verify_wait_ns;
    uint64_t    tx_index_ns;
} replay_entries_timing_t;

static sol_replay_result_t
replay_entries(sol_replay_t* replay,
               sol_bank_t* bank,
               sol_slot_t slot,
               const sol_entry_batch_t* batch,
               replay_entries_timing_t* timing) {
    if (!replay || !bank || !batch) {
        return SOL_REPLAY_DEAD;
    }

    if (timing) {
        memset(timing, 0, sizeof(*timing));
    }

    /* Verify entry hash chain (skip in fast-replay mode).
     *
     * This is PoH-heavy and can be overlapped with transaction execution.
     * Verification reads the entry batch only; bank processing mutates the
     * bank overlay. If verification fails, the caller destroys the bank and
     * discards the work. */
    bool verify_enabled = replay_verify_entries(replay);
    bool verify_signatures = verify_enabled && replay_verify_signatures(replay);
    bool verify_async = false;
    sol_entry_verify_result_t verify = {0};
    bool start_hash_mismatch = false;
    sol_replay_verify_worker_t* verify_worker = NULL;
    sol_hash_t verify_start_hash = {0};
    bool verify_start_hash_set = false;

    if (verify_enabled) {
        const sol_hash_t* start_hash = sol_bank_blockhash(bank);
        if (!start_hash) {
            sol_log_warn("Missing start blockhash for slot %llu; cannot verify entry hash chain",
                         (unsigned long long)slot);
            return SOL_REPLAY_DEAD;
        }
        verify_start_hash = *start_hash;
        verify_start_hash_set = true;

        if (replay->verify_workers && replay->verify_worker_count > 0) {
            uint32_t worker_count = replay->verify_worker_count;
            uint32_t start_idx = (uint32_t)(slot % worker_count);
            for (uint32_t probe = 0; probe < worker_count; probe++) {
                uint32_t idx = (start_idx + probe) % worker_count;
                sol_replay_verify_worker_t* cand = &replay->verify_workers[idx];
                if (!cand->started) continue;
                if (pthread_mutex_trylock(&cand->mu) != 0) continue;

                if (!cand->stop && cand->job_done) {
                    cand->batch = batch;
                    cand->start_hash = *start_hash;
                    cand->verify_signatures = verify_signatures;
                    cand->job_done = false;
                    cand->has_job = true;
                    pthread_cond_signal(&cand->cv);
                    pthread_mutex_unlock(&cand->mu);
                    verify_worker = cand;
                    verify_async = true;
                    break;
                }

                pthread_mutex_unlock(&cand->mu);
            }
        }

        if (!verify_async) {
            uint64_t t0 = timing ? get_time_ns() : 0;
            sol_hash_t h = *start_hash;
            verify = replay_entry_batch_verify(batch, &h, verify_signatures);
            if (timing) {
                timing->verify_sync_ns = get_time_ns() - t0;
            }
            if (!verify.valid &&
                verify.failed_entry == 0 &&
                verify.error == SOL_ERR_INVALID_HASH) {
                start_hash_mismatch = replay_verify_tail_ok(batch);
            }
        }
    }

    /* Process entries through bank */
    uint64_t t_process0 = timing ? get_time_ns() : 0;
    sol_bank_process_entries_timing_t bank_timing = {0};
    sol_bank_set_replay_context(true);
    if (verify_signatures) {
        sol_bank_set_replay_signatures_preverified(true);
    }
    sol_err_t err = sol_bank_process_entries_ex(bank, batch, timing ? &bank_timing : NULL);
    if (verify_signatures) {
        sol_bank_set_replay_signatures_preverified(false);
    }
    sol_bank_set_replay_context(false);
    if (timing) {
        timing->process_entries_ns = get_time_ns() - t_process0;
        timing->process_prep_ns = bank_timing.prep_ns;
        timing->process_tx_exec_ns = bank_timing.tx_exec_ns;
        timing->process_poh_ns = bank_timing.poh_ns;
    }
    if (err != SOL_OK) {
        sol_log_warn("Failed to process entries for slot %llu: %s",
                     (unsigned long long)slot, sol_err_str(err));
        if (verify_async) {
            pthread_mutex_lock(&verify_worker->mu);
            while (!verify_worker->job_done && !verify_worker->stop) {
                pthread_cond_wait(&verify_worker->done, &verify_worker->mu);
            }
            pthread_mutex_unlock(&verify_worker->mu);
        }
        return SOL_REPLAY_DEAD;
    }

    /* A slot is only valid once it reaches max tick height. */
    if (!sol_bank_has_full_ticks(bank)) {
        if (!replay_fast_mode()) {
            sol_log_warn("Slot %llu did not reach max tick height (tick_height=%llu max_tick_height=%llu)",
                         (unsigned long long)slot,
                         (unsigned long long)sol_bank_tick_height(bank),
                         (unsigned long long)sol_bank_max_tick_height(bank));
            if (verify_async) {
                pthread_mutex_lock(&verify_worker->mu);
                while (!verify_worker->job_done && !verify_worker->stop) {
                    pthread_cond_wait(&verify_worker->done, &verify_worker->mu);
                }
                pthread_mutex_unlock(&verify_worker->mu);
            }
            return SOL_REPLAY_INCOMPLETE;
        }
        sol_log_debug("Fast replay: slot %llu missing ticks (tick_height=%llu max_tick_height=%llu)",
                      (unsigned long long)slot,
                      (unsigned long long)sol_bank_tick_height(bank),
                      (unsigned long long)sol_bank_max_tick_height(bank));
    }

    /* If entry verification is running asynchronously, overlap freeze + bank
     * hash computation with that work. On large-core hosts, transaction
     * execution and bank hashing parallelize well; PoH verification can become
     * the critical path. */
    if (verify_async) {
        uint64_t t0 = timing ? get_time_ns() : 0;
        sol_bank_freeze(bank);
        if (timing) {
            uint64_t t1 = get_time_ns();
            timing->freeze_ns = t1 - t0;
            t0 = t1;
        }

        /* Precompute bank hash (includes accounts lt-hash). This is also
         * required for duplicate-safe insert into bank forks. */
        sol_hash_t tmp = {0};
        sol_bank_compute_hash(bank, &tmp);
        if (timing) {
            timing->compute_hash_ns = get_time_ns() - t0;
        }
    }

    /* Ensure verification completes (if enabled) before we accept the slot. */
    if (verify_async) {
        uint64_t t0 = timing ? get_time_ns() : 0;
        bool worker_ready = false;
        uint64_t wait_budget_ns = replay_verify_wait_budget_ns();

        pthread_mutex_lock(&verify_worker->mu);
        if (wait_budget_ns > 0) {
            /* Bound waits with short timed slices so clock/condvar edge cases
             * cannot stretch a nominal budget into multi-second stalls. */
            uint64_t wait_start_ns = get_time_ns();
            uint64_t waited_ns = 0;
            const uint64_t wait_slice_ns = 8ull * 1000ull * 1000ull; /* 8ms */

            while (!verify_worker->job_done && !verify_worker->stop &&
                   waited_ns < wait_budget_ns) {
                uint64_t remaining_ns = wait_budget_ns - waited_ns;
                uint64_t slice_ns =
                    (remaining_ns < wait_slice_ns) ? remaining_ns : wait_slice_ns;

                struct timespec deadline = {0};
                if (verify_worker->done_clock_monotonic) {
                    clock_gettime(CLOCK_MONOTONIC, &deadline);
                } else {
                    clock_gettime(CLOCK_REALTIME, &deadline);
                }
                deadline.tv_sec += (time_t)(slice_ns / 1000000000ull);
                deadline.tv_nsec += (long)(slice_ns % 1000000000ull);
                if (deadline.tv_nsec >= 1000000000l) {
                    deadline.tv_sec++;
                    deadline.tv_nsec -= 1000000000l;
                }

                int wrc = pthread_cond_timedwait(&verify_worker->done,
                                                 &verify_worker->mu,
                                                 &deadline);
                if (wrc != 0 && wrc != ETIMEDOUT && wrc != EINTR) {
                    break;
                }

                uint64_t now_ns = get_time_ns();
                waited_ns = (now_ns >= wait_start_ns) ? (now_ns - wait_start_ns) : wait_budget_ns;
            }
        }
        if (verify_worker->job_done) {
            verify = verify_worker->verify;
            start_hash_mismatch = verify_worker->start_hash_mismatch;
            worker_ready = true;
        }
        pthread_mutex_unlock(&verify_worker->mu);
        if (timing) {
            timing->verify_wait_ns = get_time_ns() - t0;
        }

        if (!worker_ready) {
            uint64_t t_sync0 = timing ? get_time_ns() : 0;
            if (!verify_start_hash_set) {
                return SOL_REPLAY_DEAD;
            }
            sol_hash_t h = verify_start_hash;
            verify = replay_entry_batch_verify(batch, &h, verify_signatures);
            if (!verify.valid &&
                verify.failed_entry == 0 &&
                verify.error == SOL_ERR_INVALID_HASH) {
                start_hash_mismatch = replay_verify_tail_ok(batch);
            }
            if (timing) {
                timing->verify_sync_ns += get_time_ns() - t_sync0;
            }
        }
    }

    if (verify_enabled) {
        if (!verify.valid) {
            if (start_hash_mismatch) {
                sol_log_warn("Entry hash chain mismatch at start for slot %llu (likely wrong parent hash)",
                             (unsigned long long)slot);
                return SOL_REPLAY_INCOMPLETE;
            }

            sol_log_warn("Entry hash chain verification failed for slot %llu at entry %u",
                         (unsigned long long)slot, verify.failed_entry);
            return SOL_REPLAY_DEAD;
        }
    }

    /* Best-effort transaction signature indexing for RPC queries. */
    uint64_t t_tx_index0 = timing ? get_time_ns() : 0;
    if (replay->blockstore && !replay_skip_tx_index()) {
        sol_blockstore_t* bs = replay->blockstore;

        if (sol_blockstore_address_sig_batch_supported(bs)) {
            enum {
                ADDR_SIG_KEY_LEN = 32 + 8 + 64,
                ADDR_SIG_VAL_LEN = 4,
            };

            /* Chunked batches to cap memory and RocksDB write batch size. */
            const size_t max_ops_per_batch = 65536;
            sol_batch_op_t* ops = sol_alloc(max_ops_per_batch * sizeof(*ops));
            uint8_t* keys = sol_alloc(max_ops_per_batch * ADDR_SIG_KEY_LEN);
            uint8_t* vals = sol_alloc(max_ops_per_batch * ADDR_SIG_VAL_LEN);

            if (ops && keys && vals) {
                const uint64_t inv_slot = UINT64_MAX - (uint64_t)slot;
                size_t op_count = 0;
                sol_err_t first_err = SOL_OK;

                for (size_t ei = 0; ei < batch->num_entries && first_err == SOL_OK; ei++) {
                    const sol_entry_t* entry = &batch->entries[ei];
                    for (uint32_t ti = 0; ti < entry->num_transactions && first_err == SOL_OK; ti++) {
                        const sol_transaction_t* tx = &entry->transactions[ti];
                        const sol_signature_t* sig = sol_transaction_signature(tx);
                        if (!sig) continue;

                        sol_err_t tx_err = SOL_OK;
                        sol_tx_status_entry_t st = {0};
                        if (sol_bank_get_tx_status(bank, sig, &st)) {
                            tx_err = st.status;
                        }

                        const sol_pubkey_t* account_keys = tx->message.account_keys;
                        size_t account_keys_len = tx->message.account_keys_len;

                        sol_pubkey_t resolved_keys[SOL_MAX_MESSAGE_ACCOUNTS];
                        bool resolved_writable[SOL_MAX_MESSAGE_ACCOUNTS];
                        bool resolved_signer[SOL_MAX_MESSAGE_ACCOUNTS];
                        size_t resolved_len = 0;

                        if (tx->message.version == SOL_MESSAGE_VERSION_V0) {
                            if (sol_bank_resolve_transaction_accounts(bank,
                                                                      tx,
                                                                      resolved_keys,
                                                                      resolved_writable,
                                                                      resolved_signer,
                                                                      SOL_MAX_MESSAGE_ACCOUNTS,
                                                                      &resolved_len) == SOL_OK) {
                                account_keys = resolved_keys;
                                account_keys_len = resolved_len;
                            }
                        }

                        int32_t err32 = (int32_t)tx_err;

                        for (size_t ai = 0; ai < account_keys_len; ai++) {
                            if (op_count == max_ops_per_batch) {
                                sol_storage_batch_t wbatch = {
                                    .ops = ops,
                                    .count = op_count,
                                    .capacity = op_count,
                                };
                                sol_err_t werr = sol_blockstore_address_sig_batch_write(bs, &wbatch);
                                if (werr != SOL_OK) {
                                    first_err = werr;
                                    break;
                                }
                                op_count = 0;
                            }

                            uint8_t* key = keys + (op_count * ADDR_SIG_KEY_LEN);
                            uint8_t* val = vals + (op_count * ADDR_SIG_VAL_LEN);

                            memcpy(key, account_keys[ai].bytes, 32);
                            replay_store_u64_be(key + 32, inv_slot);
                            memcpy(key + 32 + 8, sig->bytes, 64);

                            memcpy(val, &err32, sizeof(err32));

                            ops[op_count] = (sol_batch_op_t){
                                .op = SOL_BATCH_OP_PUT,
                                .key = key,
                                .key_len = ADDR_SIG_KEY_LEN,
                                .value = val,
                                .value_len = ADDR_SIG_VAL_LEN,
                            };
                            op_count++;
                        }
                    }
                }

                if (first_err == SOL_OK && op_count > 0) {
                    sol_storage_batch_t wbatch = {
                        .ops = ops,
                        .count = op_count,
                        .capacity = op_count,
                    };
                    first_err = sol_blockstore_address_sig_batch_write(bs, &wbatch);
                }

                if (first_err != SOL_OK) {
                    sol_log_debug("Transaction indexing batch-write failed for slot %llu: %s",
                                  (unsigned long long)slot,
                                  sol_err_str(first_err));
                }
            } else {
                sol_log_debug("Transaction indexing batch-write skipped for slot %llu: OOM",
                              (unsigned long long)slot);
            }

            sol_free(ops);
            sol_free(keys);
            sol_free(vals);
        } else {
            for (size_t ei = 0; ei < batch->num_entries; ei++) {
                const sol_entry_t* entry = &batch->entries[ei];
                for (uint32_t ti = 0; ti < entry->num_transactions; ti++) {
                    const sol_transaction_t* tx = &entry->transactions[ti];
                    const sol_signature_t* sig = sol_transaction_signature(tx);
                    if (!sig) continue;

                    sol_err_t tx_err = SOL_OK;
                    sol_tx_status_entry_t st = {0};
                    if (sol_bank_get_tx_status(bank, sig, &st)) {
                        tx_err = st.status;
                    }

                    const sol_pubkey_t* account_keys = tx->message.account_keys;
                    size_t account_keys_len = tx->message.account_keys_len;

                    sol_pubkey_t resolved_keys[SOL_MAX_MESSAGE_ACCOUNTS];
                    bool resolved_writable[SOL_MAX_MESSAGE_ACCOUNTS];
                    bool resolved_signer[SOL_MAX_MESSAGE_ACCOUNTS];
                    size_t resolved_len = 0;

                    if (tx->message.version == SOL_MESSAGE_VERSION_V0) {
                        if (sol_bank_resolve_transaction_accounts(bank,
                                                                  tx,
                                                                  resolved_keys,
                                                                  resolved_writable,
                                                                  resolved_signer,
                                                                  SOL_MAX_MESSAGE_ACCOUNTS,
                                                                  &resolved_len) == SOL_OK) {
                            account_keys = resolved_keys;
                            account_keys_len = resolved_len;
                        }
                    }

                    (void)sol_blockstore_index_transaction(
                        replay->blockstore,
                        slot,
                        sig,
                        account_keys,
                        account_keys_len,
                        tx_err
                    );
                }
            }
        }
    }
    if (timing) {
        timing->tx_index_ns = get_time_ns() - t_tx_index0;
    }

    __atomic_fetch_add(&replay->stats.entries_processed, batch->num_entries, __ATOMIC_RELAXED);

    return SOL_REPLAY_SUCCESS;
}

sol_replay_result_t
sol_replay_slot(sol_replay_t* replay, sol_slot_t slot,
                sol_replay_slot_info_t* info) {
    if (!replay) return SOL_REPLAY_DEAD;

    sol_replay_result_t result = SOL_REPLAY_DEAD;
    bool previously_replayed = false;
    bool previously_success = false;
    bool entry_created = false;
    bool in_progress_stolen = false;
    uint32_t current_variants = 0;
    uint32_t current_complete_variants = 0;
    uint64_t lease_id = 0;
    sol_replayed_slot_t* replayed = NULL;

    pthread_mutex_lock(&replay->lock);

    /* Initialize info */
    if (info) {
        memset(info, 0, sizeof(sol_replay_slot_info_t));
        info->slot = slot;
    }

    replayed = find_replayed(replay, slot);
    previously_replayed = (replayed != NULL);
    previously_success = (replayed != NULL) && !replayed->is_dead;

    if (replayed && replayed->in_progress) {
        uint64_t now = get_time_ns();
        uint64_t timeout_ns = replay_in_progress_timeout_ns();
        bool stale_lease = timeout_ns != 0 &&
                           replayed->in_progress_since_ns != 0 &&
                           now >= replayed->in_progress_since_ns &&
                           (now - replayed->in_progress_since_ns) >= timeout_ns;
        if (!stale_lease) {
            if (info) {
                info->result = SOL_REPLAY_INCOMPLETE;
            }
            pthread_mutex_unlock(&replay->lock);
            return SOL_REPLAY_INCOMPLETE;
        }

        in_progress_stolen = true;
        if (replay->last_in_progress_steal_log_ns == 0 ||
            (now - replay->last_in_progress_steal_log_ns) >= 1000000000ULL) {
            uint64_t age_ms = (now - replayed->in_progress_since_ns) / 1000000ULL;
            uint32_t stage = __atomic_load_n(&replayed->in_progress_stage, __ATOMIC_ACQUIRE);
            sol_log_warn("Replay in-progress lease timeout: slot=%llu age_ms=%llu stage=%s; reclaiming slot",
                         (unsigned long long)slot,
                         (unsigned long long)age_ms,
                         replay_stage_name(stage));
            replay->last_in_progress_steal_log_ns = now;
        }
        replay_clear_in_progress_locked(replayed);
    }

    /* If a new block variant shows up later (duplicate slot), or a previously
     * incomplete variant becomes complete, we want to replay again to insert
     * additional candidate banks. */
    current_variants = (uint32_t)sol_blockstore_num_variants(replay->blockstore, slot);
    current_complete_variants =
        count_complete_variants(replay->blockstore, slot, current_variants);

    bool has_new_variants =
        replayed && current_variants > replayed->variant_count && current_variants > 0;
    bool has_new_complete_variants =
        replayed && current_complete_variants > replayed->complete_variant_count;

    /* Fast-path: already replayed successfully. Only allow a reattempt when
     * a new variant or newly completed variant appears, so we can refresh
     * the observed variant counters. */
    if (previously_success) {
        /* New *complete* variants may belong to a different fork. Those must be
         * replayed to insert additional (slot, bank_hash) candidates so children
         * can validate against the correct parent hash. */
        if (!has_new_complete_variants) {
            if (info) {
                info->result = SOL_REPLAY_DUPLICATE;
            }
            pthread_mutex_unlock(&replay->lock);
            return SOL_REPLAY_DUPLICATE;
        }
    }

    /* Fast-path: already replayed (dead) and no new variants to consider. */
    if (replayed && !has_new_variants && !has_new_complete_variants) {
        if (info) {
            info->result = SOL_REPLAY_DEAD;
        }
        pthread_mutex_unlock(&replay->lock);
        return SOL_REPLAY_DEAD;
    }

    /* Check if slot is complete in blockstore */
    if (!sol_blockstore_is_slot_complete(replay->blockstore, slot) &&
        !replay_fast_mode()) {
        if (info) info->result = SOL_REPLAY_INCOMPLETE;
        pthread_mutex_unlock(&replay->lock);
        return SOL_REPLAY_INCOMPLETE;
    }

    /* If a bank for this slot already exists (e.g. we produced it locally),
     * treat it as replayed to avoid double-processing transactions.
     *
     * Note: if we are reprocessing this slot due to newly observed duplicate
     * block variants, do not early-return here; we want to insert additional
     * (slot, bank_hash) candidates. */
    sol_bank_t* existing_bank = sol_bank_forks_get(replay->bank_forks, slot);
    if (existing_bank && !previously_replayed) {
        /* Don't mark the slot as replayed until the bank has full ticks. */
        if (!sol_bank_has_full_ticks(existing_bank) && !replay_fast_mode()) {
            if (info) info->result = SOL_REPLAY_INCOMPLETE;
            pthread_mutex_unlock(&replay->lock);
            return SOL_REPLAY_INCOMPLETE;
        }

        if (!sol_bank_is_frozen(existing_bank)) {
            sol_bank_freeze(existing_bank);
        }
        sol_bank_forks_freeze(replay->bank_forks, slot);
        log_bank_frozen(existing_bank);
        log_bank_frozen_vote_parity(replay, existing_bank);

        mark_replayed(replay, slot, false, current_variants, current_complete_variants);
        if (!previously_success) {
            replay->stats.slots_replayed++;
        }

        replay_set_highest_replayed_locked(replay, slot);

        /* Get bank stats */
        sol_bank_stats_t bank_stats;
        sol_bank_stats(existing_bank, &bank_stats);
        replay->stats.transactions_succeeded += bank_stats.transactions_succeeded;
        replay->stats.transactions_failed += bank_stats.transactions_failed;

        if (info) {
            info->parent_slot = sol_bank_parent_slot(existing_bank);
            info->result = SOL_REPLAY_SUCCESS;
        }

        if (replay->callback) {
            replay->callback(slot, SOL_REPLAY_SUCCESS, replay->callback_ctx);
        }

        pthread_mutex_unlock(&replay->lock);
        return SOL_REPLAY_SUCCESS;
    }

    replayed = ensure_replayed_entry(replay, slot);
    if (!replayed) {
        if (info) info->result = SOL_REPLAY_DEAD;
        pthread_mutex_unlock(&replay->lock);
        return SOL_REPLAY_DEAD;
    }
    if (!previously_replayed) {
        entry_created = true;
    }
    lease_id = replay_next_lease_id_locked(replay);
    replayed->in_progress = true;
    replayed->in_progress_since_ns = get_time_ns();
    replayed->in_progress_lease_id = lease_id;
    replay_set_stage(replayed, REPLAY_STAGE_PREPARE);
    pthread_mutex_unlock(&replay->lock);

    /* Find a complete block variant to learn the parent slot. */
    size_t num_variants = current_variants ? current_variants :
                         sol_blockstore_num_variants(replay->blockstore, slot);
    if (num_variants == 0) {
        if (info) {
            info->result = replay_fast_mode() ? SOL_REPLAY_INCOMPLETE : SOL_REPLAY_DEAD;
        }
        pthread_mutex_lock(&replay->lock);
        (void)replay_release_slot_attempt_locked(replay, slot, entry_created, lease_id, true);
        pthread_mutex_unlock(&replay->lock);
        return replay_fast_mode() ? SOL_REPLAY_INCOMPLETE : SOL_REPLAY_DEAD;
    }

    sol_block_t* first_block = NULL;
    uint32_t first_variant_id = 0;
    bool first_parent_available = false;
    for (uint32_t variant_id = 0; variant_id < num_variants; variant_id++) {
        sol_block_t* block = sol_blockstore_get_block_variant(replay->blockstore, slot, variant_id);
        if (!block) continue;
        if (!block->data || block->data_len == 0) {
            sol_block_destroy(block);
            continue;
        }
        bool parent_available = replay_parent_available(replay, slot, block->parent_slot);
        if (!first_block) {
            first_block = block;
            first_variant_id = variant_id;
            first_parent_available = parent_available;
            if (first_parent_available) {
                break;
            }
            continue;
        }

        if (!first_parent_available && parent_available) {
            sol_block_destroy(first_block);
            first_block = block;
            first_variant_id = variant_id;
            first_parent_available = true;
            break;
        }

        sol_block_destroy(block);
    }

    if (!first_block) {
        if (info) {
            info->result = replay_fast_mode() ? SOL_REPLAY_INCOMPLETE : SOL_REPLAY_DEAD;
        }
        pthread_mutex_lock(&replay->lock);
        (void)replay_release_slot_attempt_locked(replay, slot, entry_created, lease_id, true);
        pthread_mutex_unlock(&replay->lock);
        return replay_fast_mode() ? SOL_REPLAY_INCOMPLETE : SOL_REPLAY_DEAD;
    }

    sol_slot_t parent_slot = first_block->parent_slot;
    if (info) {
        info->parent_slot = parent_slot;
    }

    /* Check if parent is available.
     *
     * Important: banks can exist in bank-forks (e.g. snapshot root, locally
     * produced banks) before we create a "replayed slot" tracking entry. Use a
     * weaker parent-availability predicate so live catchup doesn't stall waiting
     * for replay bookkeeping that may never be created for snapshot banks. */
    bool parent_available = first_parent_available;

    if (!parent_available) {
        /* Parent not available yet - add to pending */
        sol_pending_slot_t* pending = sol_calloc(1, sizeof(sol_pending_slot_t));
        pthread_mutex_lock(&replay->lock);
        if (pending) {
            pending->slot = slot;
            pending->parent_slot = parent_slot;
            pending->next = replay->pending_slots;
            replay->pending_slots = pending;
            replay->pending_count++;
        }
        (void)replay_release_slot_attempt_locked(replay, slot, entry_created, lease_id, true);
        pthread_mutex_unlock(&replay->lock);

        if (info) info->result = SOL_REPLAY_PARENT_MISSING;
        sol_block_destroy(first_block);
        return SOL_REPLAY_PARENT_MISSING;
    }

    /* Gather all parent bank candidates (slot, bank_hash) for replay. */
    bank_hash_list_t parents = {
        .hashes = NULL,
        .count = 0,
        .cap = 0,
    };

    sol_bank_forks_iter_slot(replay->bank_forks, parent_slot, collect_bank_hashes_cb, &parents);
    if (parents.count == 0) {
        sol_free(parents.hashes);
        parents.hashes = NULL;
        parents.cap = 0;

        if (!replay_fast_mode()) {
            sol_block_destroy(first_block);
            if (info) info->result = SOL_REPLAY_PARENT_MISSING;
            pthread_mutex_lock(&replay->lock);
            (void)replay_release_slot_attempt_locked(replay, slot, entry_created, lease_id, true);
            pthread_mutex_unlock(&replay->lock);
            return SOL_REPLAY_PARENT_MISSING;
        }
    }

    sol_bank_t* fast_parent_bank = NULL;
    if (replay_fast_mode() && parents.count == 0) {
        fast_parent_bank = sol_bank_forks_get(replay->bank_forks, parent_slot);
    }

    uint64_t start_time = get_time_ns();
    uint64_t tx_succeeded = 0;
    uint64_t tx_failed = 0;

    bool timing_verbose = replay_timing_enable();
    long timing_thresh_ms = timing_verbose ? replay_timing_threshold_ms() : 0;
    long slow_stage_thresh_ms = replay_slow_stage_threshold_ms();
    bool timing_collect = timing_verbose || (slow_stage_thresh_ms >= 0);
    bool timing_collect_stage_metrics = timing_collect || (info != NULL);
    uint64_t timing_block_ns = 0;
    uint64_t timing_parse_ns = 0;
    uint64_t timing_parent_lookup_ns = 0;
    uint64_t timing_parent_recheck_ns = 0;
    uint64_t timing_bank_new_ns = 0;
    uint64_t timing_entries_wall_ns = 0;
    uint64_t timing_entries_known_ns = 0;
    uint64_t timing_freeze2_ns = 0;
    uint64_t timing_insert_ns = 0;
    uint64_t timing_post_success_ns = 0;
    uint64_t timing_cleanup_ns = 0;
    uint64_t timing_sync_prewarm_ns = 0;
    uint64_t timing_has_shreds_ns = 0;
    replay_entries_timing_t timing_entries = {0};
    bool timing_entries_set = false;
    replay_entries_timing_t timing_entries_slow = {0};
    uint64_t timing_entries_slow_total_ns = 0;

    bool any_success = false;
    bool info_set = false;
    bool any_parsed = false;
    bool any_incomplete = false;
    bool stop_after_first_success = !replay->config.replay_all_variants;
    if (previously_success) {
        /* Backfill additional duplicate variants for an already-success slot. */
        stop_after_first_success = false;
    } else if (current_complete_variants > 1) {
        /* Duplicate slots: avoid picking an arbitrary first-success variant. */
        stop_after_first_success = false;
    }
    bool stop_replay = false;

    /* Replay all complete block variants against all parent bank candidates. */
    for (uint32_t variant_id = 0; variant_id < num_variants; variant_id++) {
        sol_block_t* block = NULL;
        if (variant_id == first_variant_id) {
            block = first_block;
            first_block = NULL;
        } else {
            uint64_t t0 = timing_collect_stage_metrics ? get_time_ns() : 0;
            block = sol_blockstore_get_block_variant(replay->blockstore, slot, variant_id);
            if (timing_collect_stage_metrics) {
                timing_block_ns += get_time_ns() - t0;
            }
        }

        if (!block) continue;

        if (!block->data || block->data_len == 0) {
            sol_block_destroy(block);
            continue;
        }

        sol_entry_batch_t* batch = sol_entry_batch_new(64);
        if (!batch) {
            sol_log_error("Failed to allocate entry batch");
            sol_block_destroy(block);
            continue;
        }

        uint64_t t_parse0 = timing_collect_stage_metrics ? get_time_ns() : 0;
        sol_err_t perr = sol_entry_batch_parse_ex(batch, block->data, block->data_len, false);
        if (perr != SOL_OK) {
            sol_log_warn("Failed to parse entries for slot %llu (variant %u): %s",
                         (unsigned long long)slot, (unsigned)variant_id, sol_err_str(perr));
            sol_entry_batch_destroy(batch);
            sol_block_destroy(block);

            /* Robustness: if the slot cache assembled a corrupt block, retry
             * using the persisted RocksDB read path before dropping the variant. */
            if (timing_collect_stage_metrics) {
                timing_parse_ns += get_time_ns() - t_parse0;
                t_parse0 = get_time_ns();
            }
            block = sol_blockstore_get_block_variant_rocksdb(replay->blockstore, slot, variant_id);
            if (!block || !block->data || block->data_len == 0) {
                sol_block_destroy(block);
                continue;
            }

            batch = sol_entry_batch_new(64);
            if (!batch) {
                sol_log_error("Failed to allocate entry batch");
                sol_block_destroy(block);
                continue;
            }

            sol_err_t perr2 = sol_entry_batch_parse_ex(batch, block->data, block->data_len, false);
            if (perr2 != SOL_OK) {
                sol_log_warn("Failed to parse entries for slot %llu (variant %u) from RocksDB: %s",
                             (unsigned long long)slot, (unsigned)variant_id, sol_err_str(perr2));
                sol_entry_batch_destroy(batch);
                sol_block_destroy(block);
                continue;
            }
        }
        if (timing_collect_stage_metrics) {
            timing_parse_ns += get_time_ns() - t_parse0;
        }

        any_parsed = true;

        if (info && !info_set) {
            info->num_entries = batch->num_entries;
            info->num_transactions = sol_entry_batch_transaction_count(batch);
            info_set = true;
        }

        size_t parent_count = parents.count;
        if (parent_count == 0 && fast_parent_bank) {
            parent_count = 1;
        }
        bool sync_program_prewarm_done = false;

        for (size_t i = 0; i < parent_count; i++) {
            uint64_t t_parent0 = timing_collect ? get_time_ns() : 0;
            sol_bank_t* parent_bank = NULL;
            if (parents.count > 0) {
                parent_bank =
                    sol_bank_forks_get_hash(replay->bank_forks, parent_slot, &parents.hashes[i]);
                if (!parent_bank && replay_fast_mode()) {
                    parent_bank = sol_bank_forks_get(replay->bank_forks, parent_slot);
                }
            } else {
                parent_bank = fast_parent_bank;
            }
            if (timing_collect) {
                timing_parent_lookup_ns += get_time_ns() - t_parent0;
            }

            if (!parent_bank) continue;
            if (!sol_bank_is_frozen(parent_bank)) {
                /* Avoid replaying children from an in-flight parent bank.
                 * Waiting for the parent to finalize is both safer and avoids
                 * multi-second stalls inside sol_bank_new_from_parent(). */
                any_incomplete = true;
                continue;
            }

            replay_set_stage(replayed, REPLAY_STAGE_BUILD_BANK);
            uint64_t t_new0 = timing_collect ? get_time_ns() : 0;
            sol_bank_t* bank = sol_bank_new_from_parent(parent_bank, slot);
            if (timing_collect) {
                timing_bank_new_ns += get_time_ns() - t_new0;
            }
            if (!bank) {
                sol_log_error("Failed to create bank for slot %llu (parent=%llu)",
                              (unsigned long long)slot, (unsigned long long)parent_slot);
                continue;
            }

            if (!replay_fast_mode()) {
                sol_pubkey_t leader_pk;
                if (replay_get_leader_pubkey(replay, slot, &leader_pk)) {
                    sol_bank_set_fee_collector(bank, &leader_pk);
                }
            }

            if (!sync_program_prewarm_done && replay_sync_prewarm_programs()) {
                uint64_t t_prewarm0 = timing_collect ? get_time_ns() : 0;
                replay_prewarm_accounts_for_batch(parent_bank, batch, false);
                if (timing_collect) {
                    timing_sync_prewarm_ns += get_time_ns() - t_prewarm0;
                }
                sync_program_prewarm_done = true;
            }

            replay_entries_timing_t local_timing = {0};
            uint64_t t_entries_wall0 = timing_collect ? get_time_ns() : 0;
            replay_set_stage(replayed, REPLAY_STAGE_EXECUTE);
            sol_replay_result_t r = replay_entries(replay, bank, slot, batch,
                                                   timing_collect_stage_metrics ? &local_timing : NULL);
            if (timing_collect) {
                timing_entries_wall_ns += get_time_ns() - t_entries_wall0;
                uint64_t local_total_ns =
                    local_timing.process_entries_ns +
                    local_timing.verify_sync_ns +
                    local_timing.verify_wait_ns +
                    local_timing.freeze_ns +
                    local_timing.compute_hash_ns +
                    local_timing.tx_index_ns;
                timing_entries_known_ns += local_total_ns;
                if (local_total_ns > timing_entries_slow_total_ns) {
                    timing_entries_slow = local_timing;
                    timing_entries_slow_total_ns = local_total_ns;
                }
            }
                if (r == SOL_REPLAY_SUCCESS) {
                    /* Strict parent gating for commit/freeze: even if execution
                     * succeeded, never finalize a child when the parent became
                     * unavailable during races (root pruning/duplicate churn). */
                    sol_slot_t produced_parent_slot = sol_bank_parent_slot(bank);
                    bool parent_still_available = true;
                    bool need_parent_recheck =
                        replay_parent_recheck_enable() ||
                        !parent_bank ||
                        !sol_bank_is_frozen(parent_bank) ||
                        (produced_parent_slot != parent_slot);

                    if (need_parent_recheck) {
                        uint64_t t_parent_recheck0 = timing_collect ? get_time_ns() : 0;
                        parent_still_available =
                            replay_parent_available(replay, slot, produced_parent_slot);
                        if (timing_collect) {
                            timing_parent_recheck_ns += get_time_ns() - t_parent_recheck0;
                        }
                    }

                    if (!parent_still_available) {
                        any_incomplete = true;
                        sol_bank_destroy(bank);
                        continue;
                    }

                if (timing_collect_stage_metrics && !timing_entries_set) {
                    timing_entries = local_timing;
                    timing_entries_set = true;
                }
                uint64_t t_freeze0 = timing_collect_stage_metrics ? get_time_ns() : 0;
                sol_bank_freeze(bank);
                if (timing_collect_stage_metrics) {
                    timing_freeze2_ns += get_time_ns() - t_freeze0;
                }

                uint64_t t_ins0 = timing_collect_stage_metrics ? get_time_ns() : 0;
                sol_err_t ierr = sol_bank_forks_insert(replay->bank_forks, bank);
                if (timing_collect_stage_metrics) {
                    timing_insert_ns += get_time_ns() - t_ins0;
                }
                bool inserted = false;
                bool inserted_exists = false;
                bool full_deferred = false;

                if (ierr == SOL_OK) {
                    inserted = true;
                } else if (ierr == SOL_ERR_EXISTS) {
                    inserted_exists = true;
                } else if (ierr == SOL_ERR_FULL) {
                    /* Bank forks is at capacity; best-effort prune and retry. */
                    any_incomplete = true;
                    full_deferred = true;

                    if (replay_prune_on_full()) {
                        uint64_t now_ns = get_time_ns();
                        uint64_t cooldown_ns = replay_prune_on_full_cooldown_ns();
                        if (cooldown_ns == 0 ||
                            replay->last_full_prune_ns == 0 ||
                            (now_ns - replay->last_full_prune_ns) >= cooldown_ns) {
                            sol_err_t root_err = SOL_ERR_NOTFOUND;
                            bool rooted = false;
                            sol_slot_t rooted_slot = 0;

                            /* First preference: root to the active parent fork by hash. */
                            if (parent_bank && parent_slot > 0 && sol_bank_is_frozen(parent_bank)) {
                                sol_hash_t parent_hash;
                                sol_bank_compute_hash(parent_bank, &parent_hash);
                                root_err = sol_bank_forks_set_root_hash(replay->bank_forks,
                                                                        parent_slot,
                                                                        &parent_hash);
                                if (root_err == SOL_OK) {
                                    rooted = true;
                                    rooted_slot = parent_slot;
                                }
                            }

                            if (!rooted) {
                                sol_slot_t current_root = sol_bank_forks_root_slot(replay->bank_forks);
                                sol_slot_t min_candidate = current_root + 1u;
                                if (slot > min_candidate) {
                                    sol_slot_t search_limit = replay_prune_on_full_search_limit();
                                    if (slot > search_limit) {
                                        sol_slot_t bounded_low = slot - search_limit;
                                        if (bounded_low > min_candidate) {
                                            min_candidate = bounded_low;
                                        }
                                    }

                                    sol_slot_t preferred = slot - 1u;
                                    sol_slot_t window = replay_prune_on_full_window();
                                    if (slot > window) {
                                        sol_slot_t window_slot = slot - window;
                                        if (window_slot < preferred) {
                                            preferred = window_slot;
                                        }
                                    }
                                    if (preferred < min_candidate) preferred = min_candidate;

                                    sol_slot_t target_slot = 0;
                                    sol_hash_t target_hash;
                                    bool found =
                                        replay_find_frozen_root_candidate(replay,
                                                                          preferred,
                                                                          min_candidate,
                                                                          &target_slot,
                                                                          &target_hash);
                                    if (!found && preferred < (slot - 1u)) {
                                        found =
                                            replay_find_frozen_root_candidate(replay,
                                                                              slot - 1u,
                                                                              preferred + 1u,
                                                                              &target_slot,
                                                                              &target_hash);
                                    }

                                    if (found) {
                                        root_err = sol_bank_forks_set_root_hash(replay->bank_forks,
                                                                                target_slot,
                                                                                &target_hash);
                                        if (root_err == SOL_OK) {
                                            rooted = true;
                                            rooted_slot = target_slot;
                                        }
                                    }
                                }
                            }

                            if (rooted) {
                                replay->last_full_prune_ns = now_ns;
                                sol_log_warn("Bank forks full at slot %llu; auto-advanced root to "
                                             "%llu and retrying insert",
                                             (unsigned long long)slot,
                                             (unsigned long long)rooted_slot);
                                ierr = sol_bank_forks_insert(replay->bank_forks, bank);
                                if (ierr == SOL_OK) {
                                    inserted = true;
                                    full_deferred = false;
                                } else if (ierr == SOL_ERR_EXISTS) {
                                    inserted_exists = true;
                                    full_deferred = false;
                                } else {
                                    full_deferred = (ierr == SOL_ERR_FULL);
                                }
                            } else if (root_err != SOL_ERR_NOTFOUND) {
                                sol_log_warn("Bank forks full at slot %llu; auto-root failed: %s",
                                             (unsigned long long)slot,
                                             sol_err_str(root_err));
                            }
                        }
                    }
                }

                if (inserted || inserted_exists) {
                    uint64_t t_post_success0 = timing_collect ? get_time_ns() : 0;
                    any_success = true;
                    if (inserted) {
                        log_bank_frozen(bank);
                        log_bank_frozen_vote_parity(replay, bank);
                        if (stop_after_first_success) {
                            if (timing_collect) {
                                timing_post_success_ns += get_time_ns() - t_post_success0;
                            }
                            stop_replay = true;
                            break;
                        }

                        sol_bank_stats_t bank_stats;
                        sol_bank_stats(bank, &bank_stats);
                        tx_succeeded += bank_stats.transactions_succeeded;
                        tx_failed += bank_stats.transactions_failed;
                    }
                    if (timing_collect) {
                        timing_post_success_ns += get_time_ns() - t_post_success0;
                    }
                } else {
                    if (ierr == SOL_ERR_FULL || full_deferred) {
                        sol_log_warn("Bank forks full while inserting slot %llu; deferring replay",
                                     (unsigned long long)slot);
                    }
                    sol_bank_destroy(bank);
                }
            } else {
                if (r == SOL_REPLAY_INCOMPLETE) {
                    any_incomplete = true;
                }
                sol_bank_destroy(bank);
            }

            if (stop_replay) {
                break;
            }
        }

        uint64_t t_cleanup0 = timing_collect ? get_time_ns() : 0;
        sol_entry_batch_destroy(batch);
        sol_block_destroy(block);
        if (timing_collect) {
            timing_cleanup_ns += get_time_ns() - t_cleanup0;
        }

        if (stop_replay) {
            break;
        }
    }

    if (first_block) {
        uint64_t t_cleanup0 = timing_collect ? get_time_ns() : 0;
        sol_block_destroy(first_block);
        if (timing_collect) {
            timing_cleanup_ns += get_time_ns() - t_cleanup0;
        }
        first_block = NULL;
    }

    /* Fast-replay override: if we parsed any entries but failed to replay
     * successfully, force-advance by inserting a frozen child bank from the
     * first available parent. This keeps catchup moving when shreds are
     * incomplete or malformed. */
    bool has_shreds = any_parsed;
    if (!any_success && !has_shreds) {
        uint64_t t_has_shreds0 = timing_collect ? get_time_ns() : 0;
        has_shreds = replay_has_any_shreds(replay, slot);
        if (timing_collect) {
            timing_has_shreds_ns += get_time_ns() - t_has_shreds0;
        }
    }
    if (!any_success &&
        replay_fast_mode() &&
        replay_force_advance() &&
        (any_parsed || has_shreds)) {
        sol_bank_t* parent_bank = NULL;
        for (size_t i = 0; i < parents.count; i++) {
            parent_bank = sol_bank_forks_get_hash(replay->bank_forks,
                                                  parent_slot,
                                                  &parents.hashes[i]);
            if (parent_bank) break;
        }
        if (!parent_bank && replay_fast_mode()) {
            parent_bank = sol_bank_forks_get(replay->bank_forks, parent_slot);
        }
        if (!parent_bank) {
            parent_bank = sol_bank_forks_root(replay->bank_forks);
        }
        if (parent_bank) {
            sol_bank_t* forced = sol_bank_new_from_parent(parent_bank, slot);
            if (forced) {
                sol_bank_freeze(forced);
                if (sol_bank_forks_insert(replay->bank_forks, forced) == SOL_OK) {
                    any_success = true;
                    sol_log_debug("Fast replay: forced advance slot %llu (parsed=%s shreds=%s)",
                                  (unsigned long long)slot,
                                  any_parsed ? "yes" : "no",
                                  has_shreds ? "yes" : "no");
                } else {
                    sol_bank_destroy(forced);
                }
            }
        }
    }

    uint64_t elapsed = get_time_ns() - start_time;
    uint64_t timing_entries_extra_ns =
        (timing_entries_wall_ns > timing_entries_known_ns)
            ? (timing_entries_wall_ns - timing_entries_known_ns)
            : 0u;
    if (info) {
        info->replay_time_ns = elapsed;
        info->fetch_time_ns = timing_block_ns;
        info->decode_time_ns = timing_parse_ns;
        info->execute_time_ns = timing_entries.process_entries_ns;
        info->commit_time_ns =
            timing_entries.freeze_ns +
            timing_entries.compute_hash_ns +
            timing_freeze2_ns +
            timing_insert_ns;
        info->verify_time_ns = timing_entries.verify_sync_ns + timing_entries.verify_wait_ns;
    }

    bool emitted_verbose_timing = false;
    if (timing_verbose && any_success) {
        double total_ms = (double)elapsed / 1000000.0;
        if ((long)total_ms >= timing_thresh_ms) {
            sol_log_info(
                "Replay timing: slot=%llu total=%.2fms block=%.2fms parse=%.2fms parent_lookup=%.2fms parent_recheck=%.2fms bank_new=%.2fms sync_prewarm=%.2fms entries_wall=%.2fms entries_extra=%.2fms process=%.2fms process_prep=%.2fms process_tx=%.2fms process_poh=%.2fms freeze=%.2fms hash=%.2fms verify_sync=%.2fms verify_wait=%.2fms tx_index=%.2fms freeze2=%.2fms insert=%.2fms post_success=%.2fms cleanup=%.2fms has_shreds_lookup=%.2fms tx=%u entries=%u",
                (unsigned long long)slot,
                total_ms,
                (double)timing_block_ns / 1000000.0,
                (double)timing_parse_ns / 1000000.0,
                (double)timing_parent_lookup_ns / 1000000.0,
                (double)timing_parent_recheck_ns / 1000000.0,
                (double)timing_bank_new_ns / 1000000.0,
                (double)timing_sync_prewarm_ns / 1000000.0,
                (double)timing_entries_wall_ns / 1000000.0,
                (double)timing_entries_extra_ns / 1000000.0,
                (double)timing_entries.process_entries_ns / 1000000.0,
                (double)timing_entries.process_prep_ns / 1000000.0,
                (double)timing_entries.process_tx_exec_ns / 1000000.0,
                (double)timing_entries.process_poh_ns / 1000000.0,
                (double)timing_entries.freeze_ns / 1000000.0,
                (double)timing_entries.compute_hash_ns / 1000000.0,
                (double)timing_entries.verify_sync_ns / 1000000.0,
                (double)timing_entries.verify_wait_ns / 1000000.0,
                (double)timing_entries.tx_index_ns / 1000000.0,
                (double)timing_freeze2_ns / 1000000.0,
                (double)timing_insert_ns / 1000000.0,
                (double)timing_post_success_ns / 1000000.0,
                (double)timing_cleanup_ns / 1000000.0,
                (double)timing_has_shreds_ns / 1000000.0,
                info ? (unsigned)info->num_transactions : 0u,
                info ? (unsigned)info->num_entries : 0u
            );
            emitted_verbose_timing = true;
        }
    }

    if (slow_stage_thresh_ms >= 0) {
        double total_ms = (double)elapsed / 1000000.0;
        if ((long)total_ms >= slow_stage_thresh_ms && !emitted_verbose_timing) {
            const replay_entries_timing_t* stage_timing =
                timing_entries_set ? &timing_entries : &timing_entries_slow;
            uint64_t accounted_ns =
                timing_block_ns +
                timing_parse_ns +
                timing_parent_lookup_ns +
                timing_parent_recheck_ns +
                timing_bank_new_ns +
                timing_sync_prewarm_ns +
                stage_timing->process_entries_ns +
                stage_timing->freeze_ns +
                stage_timing->compute_hash_ns +
                stage_timing->verify_sync_ns +
                stage_timing->verify_wait_ns +
                stage_timing->tx_index_ns +
                timing_freeze2_ns +
                timing_insert_ns +
                timing_post_success_ns +
                timing_cleanup_ns +
                timing_has_shreds_ns;
            uint64_t unattributed_ns = (elapsed > accounted_ns) ? (elapsed - accounted_ns) : 0;
            sol_log_info(
                "Replay stages: slot=%llu total=%.2fms block=%.2fms parse=%.2fms parent_lookup=%.2fms parent_recheck=%.2fms bank_new=%.2fms sync_prewarm=%.2fms entries_wall=%.2fms entries_extra=%.2fms process=%.2fms process_prep=%.2fms process_tx=%.2fms process_poh=%.2fms freeze=%.2fms hash=%.2fms verify_sync=%.2fms verify_wait=%.2fms tx_index=%.2fms freeze2=%.2fms insert=%.2fms post_success=%.2fms cleanup=%.2fms has_shreds_lookup=%.2fms unattributed=%.2fms variants=%u complete_variants=%u parent_candidates=%zu parsed=%s success=%s incomplete=%s",
                (unsigned long long)slot,
                total_ms,
                (double)timing_block_ns / 1000000.0,
                (double)timing_parse_ns / 1000000.0,
                (double)timing_parent_lookup_ns / 1000000.0,
                (double)timing_parent_recheck_ns / 1000000.0,
                (double)timing_bank_new_ns / 1000000.0,
                (double)timing_sync_prewarm_ns / 1000000.0,
                (double)timing_entries_wall_ns / 1000000.0,
                (double)timing_entries_extra_ns / 1000000.0,
                (double)stage_timing->process_entries_ns / 1000000.0,
                (double)stage_timing->process_prep_ns / 1000000.0,
                (double)stage_timing->process_tx_exec_ns / 1000000.0,
                (double)stage_timing->process_poh_ns / 1000000.0,
                (double)stage_timing->freeze_ns / 1000000.0,
                (double)stage_timing->compute_hash_ns / 1000000.0,
                (double)stage_timing->verify_sync_ns / 1000000.0,
                (double)stage_timing->verify_wait_ns / 1000000.0,
                (double)stage_timing->tx_index_ns / 1000000.0,
                (double)timing_freeze2_ns / 1000000.0,
                (double)timing_insert_ns / 1000000.0,
                (double)timing_post_success_ns / 1000000.0,
                (double)timing_cleanup_ns / 1000000.0,
                (double)timing_has_shreds_ns / 1000000.0,
                (double)unattributed_ns / 1000000.0,
                (unsigned)num_variants,
                (unsigned)count_complete_variants(replay->blockstore, slot, num_variants),
                parents.count,
                any_parsed ? "yes" : "no",
                any_success ? "yes" : "no",
                any_incomplete ? "yes" : "no");
        }
    }

    sol_free(parents.hashes);

    uint32_t observed_variants = (uint32_t)num_variants;
    uint32_t observed_complete_variants =
        count_complete_variants(replay->blockstore, slot, observed_variants);

    /* Always emit structural context for very slow slots, even when
     * SOL_REPLAY_TIMING is disabled. This keeps tail-latency debugging
     * actionable in production runs. */
    if (elapsed >= 1000000000ULL) {
        sol_log_info(
            "Replay slow: slot=%llu total=%.2fms variants=%u complete_variants=%u parent_candidates=%zu parsed=%s success=%s incomplete=%s",
            (unsigned long long)slot,
            (double)elapsed / 1000000.0,
            (unsigned)observed_variants,
            (unsigned)observed_complete_variants,
            parents.count,
            any_parsed ? "yes" : "no",
            any_success ? "yes" : "no",
            any_incomplete ? "yes" : "no");
    }

    result = SOL_REPLAY_DEAD;
    if (any_success) {
        result = SOL_REPLAY_SUCCESS;
    } else {
        /* If we already have a valid bank for this slot, don't mark the slot
         * dead just because a new duplicate variant failed to replay. */
        if (previously_success) {
            result = SOL_REPLAY_DUPLICATE;
        } else if (any_incomplete) {
            /* At least one variant replayed but lacked full ticks. Keep repairing. */
            result = SOL_REPLAY_INCOMPLETE;
        } else if (!any_parsed) {
            /* We were unable to decode any block variant. This can happen
             * transiently while the slot is still being repaired (e.g. when a
             * DATA_COMPLETE shred is observed but the assembled payload is
             * malformed or incomplete). Don't permanently mark the slot dead;
             * allow TVU/repair to deliver a complete, parseable variant later. */
            result = SOL_REPLAY_INCOMPLETE;
        } else {
            /* Parsed variants can still be transiently wrong/fork-mismatched
             * while duplicate repair converges. Avoid poisoning progress by
             * marking the slot dead too early when we do have shreds. */
            result = has_shreds ? SOL_REPLAY_INCOMPLETE : SOL_REPLAY_DEAD;
        }
    }

    if (replay_fast_mode() && result == SOL_REPLAY_DEAD) {
        result = SOL_REPLAY_INCOMPLETE;
    }

    replay_set_stage(replayed, REPLAY_STAGE_FINALIZE);
    pthread_mutex_lock(&replay->lock);
    replayed = find_replayed(replay, slot);
    bool owns_lease = replayed &&
                      replayed->in_progress &&
                      replayed->in_progress_lease_id == lease_id;
    if (!owns_lease) {
        pthread_mutex_unlock(&replay->lock);
        if (info) {
            info->result = SOL_REPLAY_INCOMPLETE;
        }
        if (in_progress_stolen) {
            sol_log_debug("Replay stale lease result ignored after reclaim: slot=%llu lease=%llu",
                          (unsigned long long)slot,
                          (unsigned long long)lease_id);
        }
        return SOL_REPLAY_INCOMPLETE;
    }

    replay_clear_in_progress_locked(replayed);
    replay->stats.total_replay_time_ns += elapsed;

    if (any_success) {
        mark_replayed(replay, slot, false, observed_variants, observed_complete_variants);
        if (!previously_success) {
            replay->stats.slots_replayed++;
        }
        replay_set_highest_replayed_locked(replay, slot);
        replay->stats.transactions_succeeded += tx_succeeded;
        replay->stats.transactions_failed += tx_failed;
    } else if (previously_success) {
        mark_replayed(replay, slot, false, observed_variants, observed_complete_variants);
    } else if (result == SOL_REPLAY_DEAD) {
        mark_replayed(replay, slot, true, observed_variants, observed_complete_variants);
        sol_bank_forks_mark_dead(replay->bank_forks, slot);
        if (!previously_replayed) {
            replay->stats.slots_dead++;
        }
    } else {
        if (entry_created) {
            remove_replayed_entry(replay, slot);
        }
    }

    pthread_mutex_unlock(&replay->lock);

    if (info) {
        info->result = result;
    }

    /* Invoke callback */
    if (replay->callback) {
        replay->callback(slot, result, replay->callback_ctx);
    }

    return result;
}

size_t
sol_replay_available(sol_replay_t* replay, size_t max_slots) {
    if (!replay) return 0;

    size_t replayed = 0;
    sol_slot_t highest = sol_blockstore_highest_slot(replay->blockstore);
    sol_slot_t current = sol_bank_forks_root_slot(replay->bank_forks);

    /* Replay slots in order */
    while (current <= highest && (max_slots == 0 || replayed < max_slots)) {
        if (!sol_replay_is_replayed(replay, current) &&
            (replay_fast_mode() ||
             sol_blockstore_is_slot_complete(replay->blockstore, current))) {

            sol_replay_result_t result = sol_replay_slot(replay, current, NULL);

            if (result == SOL_REPLAY_SUCCESS) {
                replayed++;
            }
        }

        current++;
    }

    /* Try to replay pending slots whose parents are now available */
    pthread_mutex_lock(&replay->lock);

    sol_pending_slot_t** prev_ptr = &replay->pending_slots;
    sol_pending_slot_t* pending = replay->pending_slots;

    while (pending && (max_slots == 0 || replayed < max_slots)) {
        sol_pending_slot_t* next = pending->next;
        sol_slot_t pending_slot = pending->slot;

        if (replay_parent_available(replay, pending->slot, pending->parent_slot)) {
            /* Parent available, try to replay */
            *prev_ptr = next;
            sol_free(pending);
            replay->pending_count--;

            pthread_mutex_unlock(&replay->lock);

            sol_replay_result_t result = sol_replay_slot(replay, pending_slot, NULL);
            if (result == SOL_REPLAY_SUCCESS) {
                replayed++;
            }

            pthread_mutex_lock(&replay->lock);
            /* Restart iteration as list may have changed */
            prev_ptr = &replay->pending_slots;
            pending = replay->pending_slots;
            continue;
        }

        prev_ptr = &pending->next;
        pending = next;
    }

    pthread_mutex_unlock(&replay->lock);
    return replayed;
}

bool
sol_replay_is_replayed(sol_replay_t* replay, sol_slot_t slot) {
    if (!replay) return false;

    pthread_mutex_lock(&replay->lock);
    sol_replayed_slot_t* entry = find_replayed(replay, slot);
    bool has_entry = (entry != NULL);
    bool is_dead = has_entry && entry->is_dead;
    bool in_progress = has_entry && entry->in_progress;
    uint32_t variant_count = has_entry ? entry->variant_count : 0;
    uint32_t complete_variant_count = has_entry ? entry->complete_variant_count : 0;
    pthread_mutex_unlock(&replay->lock);

    /* Once a slot has been successfully replayed (frozen), it should never
       be re-replayed.  New blockstore variants from continued shred reception
       do not change the deterministic replay result. */
    if (!has_entry || is_dead || in_progress) {
        return false;
    }

    uint32_t current_variants = (uint32_t)sol_blockstore_num_variants(replay->blockstore, slot);
    uint32_t current_complete_variants =
        count_complete_variants(replay->blockstore, slot, current_variants);

    /* Only new complete variants warrant reprocessing. New incomplete variants
     * are expected during shred repair and should not force a replay attempt. */
    (void)variant_count;
    if (current_complete_variants > complete_variant_count) {
        return false;
    }

    return true;
}

bool
sol_replay_has_frozen_bank(sol_replay_t* replay, sol_slot_t slot) {
    if (!replay) return false;
    return sol_bank_forks_has_frozen_slot(replay->bank_forks, slot);
}

bool
sol_replay_parent_ready(sol_replay_t* replay, sol_slot_t slot, sol_slot_t* out_parent_slot) {
    if (!replay || slot == 0) return false;

    sol_slot_t parent_slot = 0;
    if (!replay_find_slot_parent(replay, slot, &parent_slot)) {
        return false;
    }

    if (out_parent_slot) {
        *out_parent_slot = parent_slot;
    }
    return replay_parent_available(replay, slot, parent_slot);
}

bool
sol_replay_prewarm_slot(sol_replay_t* replay, sol_slot_t slot) {
    if (!replay || !replay->blockstore || slot == 0) return false;

    size_t num_variants = sol_blockstore_num_variants(replay->blockstore, slot);
    if (num_variants == 0) {
        num_variants = 1;
    }
    if (num_variants == 0) {
        return false;
    }

    size_t variants_to_try = num_variants;
    size_t max_variants = replay_prewarm_max_variants();
    if (variants_to_try > max_variants) {
        variants_to_try = max_variants;
    }

    sol_slot_t parent_slot = 0;
    bool have_parent = replay_find_slot_parent(replay, slot, &parent_slot);
    bool parent_ready = have_parent && replay_parent_available(replay, slot, parent_slot);
    sol_bank_t* parent_bank = NULL;
    if (parent_ready && parent_slot != slot) {
        parent_bank = sol_bank_forks_get(replay->bank_forks, parent_slot);
    }

    bool any_parsed = false;
    for (uint32_t variant_id = 0; variant_id < (uint32_t)variants_to_try; variant_id++) {
        sol_block_t* block = sol_blockstore_get_block_variant(replay->blockstore, slot, variant_id);
        if (!block || !block->data || block->data_len == 0) {
            sol_block_destroy(block);
            continue;
        }

        sol_entry_batch_t* batch = sol_entry_batch_new(64);
        if (!batch) {
            sol_block_destroy(block);
            continue;
        }

        sol_err_t perr = sol_entry_batch_parse_ex(batch, block->data, block->data_len, false);
        if (perr != SOL_OK) {
            sol_entry_batch_destroy(batch);
            sol_block_destroy(block);

            block = sol_blockstore_get_block_variant_rocksdb(replay->blockstore, slot, variant_id);
            if (!block || !block->data || block->data_len == 0) {
                sol_block_destroy(block);
                continue;
            }

            batch = sol_entry_batch_new(64);
            if (!batch) {
                sol_block_destroy(block);
                continue;
            }
            perr = sol_entry_batch_parse_ex(batch, block->data, block->data_len, false);
            if (perr != SOL_OK) {
                sol_entry_batch_destroy(batch);
                sol_block_destroy(block);
                continue;
            }
        }

        any_parsed = true;
        (void)replay_verify_tail_ok(batch);

        if (parent_ready && parent_bank) {
            replay_prewarm_accounts_for_batch(parent_bank, batch, true);
        }

        sol_entry_batch_destroy(batch);
        sol_block_destroy(block);
    }

    return any_parsed;
}

bool
sol_replay_is_dead(sol_replay_t* replay, sol_slot_t slot) {
    if (!replay) return false;

    bool has_entry = false;
    bool is_dead = false;
    uint32_t variant_count = 0;
    uint32_t complete_variant_count = 0;

    pthread_mutex_lock(&replay->lock);
    sol_replayed_slot_t* entry = find_replayed(replay, slot);
    if (entry) {
        has_entry = true;
        is_dead = entry->is_dead;
        variant_count = entry->variant_count;
        complete_variant_count = entry->complete_variant_count;
    }
    pthread_mutex_unlock(&replay->lock);

    if (!has_entry || !is_dead) {
        return false;
    }

    uint32_t current_variants = (uint32_t)sol_blockstore_num_variants(replay->blockstore, slot);
    if (current_variants > variant_count && current_variants > 0) {
        return false;
    }

    uint32_t current_complete = count_complete_variants(replay->blockstore, slot, current_variants);
    if (current_complete > complete_variant_count) {
        return false;
    }

    return true;
}

sol_slot_t
sol_replay_best_slot(sol_replay_t* replay) {
    if (!replay) return 0;
    return sol_fork_choice_best_slot(replay->fork_choice);
}

sol_slot_t
sol_replay_highest_replayed_slot(const sol_replay_t* replay) {
    if (!replay) return 0;
    return __atomic_load_n(&replay->highest_replayed_slot_atomic, __ATOMIC_RELAXED);
}

sol_slot_t
sol_replay_root_slot(sol_replay_t* replay) {
    if (!replay) return 0;
    return sol_bank_forks_root_slot(replay->bank_forks);
}

sol_err_t
sol_replay_set_root(sol_replay_t* replay, sol_slot_t slot) {
    if (!replay) return SOL_ERR_INVAL;

    sol_err_t err = sol_bank_forks_set_root(replay->bank_forks, slot);
    if (err != SOL_OK) return err;

    return sol_fork_choice_set_root(replay->fork_choice, slot);
}

sol_err_t
sol_replay_set_root_hash(sol_replay_t* replay,
                         sol_slot_t slot,
                         const sol_hash_t* bank_hash) {
    if (!replay || !bank_hash) return SOL_ERR_INVAL;

    sol_err_t err = sol_bank_forks_set_root_hash(replay->bank_forks, slot, bank_hash);
    if (err != SOL_OK) return err;

    return sol_fork_choice_set_root(replay->fork_choice, slot);
}

sol_err_t
sol_replay_record_vote(sol_replay_t* replay,
                       const sol_pubkey_t* validator,
                       sol_slot_t slot,
                       uint64_t stake) {
    if (!replay) return SOL_ERR_INVAL;
    return sol_fork_choice_record_vote(replay->fork_choice, validator, slot, stake);
}

sol_err_t
sol_replay_record_vote_hash(sol_replay_t* replay,
                            const sol_pubkey_t* validator,
                            sol_slot_t slot,
                            const sol_hash_t* bank_hash,
                            uint64_t stake) {
    if (!replay) return SOL_ERR_INVAL;
    return sol_fork_choice_record_vote_hash(replay->fork_choice, validator, slot, bank_hash, stake);
}

sol_fork_choice_t*
sol_replay_fork_choice(sol_replay_t* replay) {
    return replay ? replay->fork_choice : NULL;
}

sol_bank_forks_t*
sol_replay_bank_forks(sol_replay_t* replay) {
    return replay ? replay->bank_forks : NULL;
}

sol_bank_t*
sol_replay_get_bank(sol_replay_t* replay, sol_slot_t slot) {
    if (!replay) return NULL;
    return sol_bank_forks_get(replay->bank_forks, slot);
}

sol_bank_t*
sol_replay_working_bank(sol_replay_t* replay) {
    if (!replay) return NULL;
    return sol_bank_forks_working_bank(replay->bank_forks);
}

void
sol_replay_set_callback(sol_replay_t* replay,
                        sol_replay_slot_cb callback,
                        void* ctx) {
    if (!replay) return;

    pthread_mutex_lock(&replay->lock);
    replay->callback = callback;
    replay->callback_ctx = ctx;
    pthread_mutex_unlock(&replay->lock);
}

void
sol_replay_stats(const sol_replay_t* replay, sol_replay_stats_t* stats) {
    if (!replay || !stats) return;

    pthread_mutex_lock((pthread_mutex_t*)&replay->lock);
    *stats = replay->stats;
    pthread_mutex_unlock((pthread_mutex_t*)&replay->lock);
}
