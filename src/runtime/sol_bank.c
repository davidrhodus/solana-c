/*
 * sol_bank.c - Bank State Machine Implementation
 */

#include "sol_bank.h"
#include "../util/sol_alloc.h"
#include "../util/sol_arena.h"
#include "../util/sol_log.h"
#include "../crypto/sol_sha256.h"
#include "../crypto/sol_ed25519.h"
#include "../crypto/sol_lt_hash.h"
#include "../programs/sol_system_program.h"
#include "../programs/sol_vote_program.h"
#include "../programs/sol_stake_program.h"
#include "../programs/sol_config_program.h"
#include "../programs/sol_address_lookup_table_program.h"
#include "../programs/sol_token_program.h"
#include "../programs/sol_bpf_loader_program.h"
#include "../programs/sol_ed25519_program.h"
#include "../programs/sol_secp256k1_program.h"
#include "sol_compute_budget.h"
#include "sol_program.h"
#include "sol_sysvar.h"
#include "../util/sol_bits.h"
#include "../util/sol_map.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include <errno.h>

/* ---- Concurrency helpers (bank hot path) ---- */

static inline uint64_t bank_monotonic_ns(void);
static bool lthash_parallel_enabled(void);
static uint32_t signature_hash(const sol_signature_t* sig);
static void sol_bank_record_tx_status_batch(sol_bank_t* bank,
                                            const sol_transaction_t* const* tx_ptrs,
                                            size_t count,
                                            const sol_tx_result_t* results);

#define BANK_STAT_ADD(bank, field, val) \
    (__atomic_fetch_add(&(bank)->stats.field, (uint64_t)(val), __ATOMIC_RELAXED))

#define BANK_STAT_INC(bank, field) BANK_STAT_ADD((bank), field, 1u)

#define BANK_FLAG_CLEAR(bank, field) \
    (__atomic_store_n(&(bank)->field, false, __ATOMIC_RELAXED))

#define BANK_U64_ADD(bank, field, val) \
    (__atomic_fetch_add(&(bank)->field, (uint64_t)(val), __ATOMIC_RELAXED))

/*
 * Reserved account keys - accounts that are NEVER writable even if the
 * transaction header declares them as writable.  Matches Agave's
 * `reserved_account_keys` (active set + pending set when the
 * add_new_reserved_account_keys feature is active).
 */

/* Missing pubkey constants defined inline */
static const sol_pubkey_t SOL_BPF_LOADER_DEPRECATED_ID = {{ /* BPFLoader1111111111111111111111111111111111 */
    0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x88, 0xa1, 0x6b,
    0xbd, 0x23, 0x95, 0x85, 0x5f, 0x64, 0x04, 0xd9,
    0xb4, 0xf4, 0x56, 0xb7, 0x82, 0x1b, 0xb0, 0x14,
    0x57, 0x49, 0x42, 0x8c, 0x00, 0x00, 0x00, 0x00
}};

static const sol_pubkey_t SOL_FEATURE_PROGRAM_ID = {{ /* Feature111111111111111111111111111111111111 */
    0x03, 0xc0, 0xa0, 0xcd, 0xcb, 0x06, 0xd2, 0xda,
    0xef, 0xae, 0x82, 0xd1, 0x6f, 0xee, 0x7a, 0xcf,
    0x61, 0xec, 0x73, 0x7b, 0x23, 0x48, 0x1b, 0x21,
    0x94, 0x6a, 0x76, 0x70, 0x00, 0x00, 0x00, 0x00
}};

/* SOL_STAKE_CONFIG_ID: provided by sol_stake_program.h */

static const sol_pubkey_t SOL_SYSVAR_REWARDS_ID = {{ /* SysvarRewards111111111111111111111111111111 */
    0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2c, 0x61, 0x37,
    0xce, 0xe0, 0x92, 0xd9, 0xb6, 0x92, 0x3e, 0xe1,
    0xcc, 0xd6, 0x19, 0x03, 0xfa, 0x82, 0xb8, 0xa1,
    0x61, 0x91, 0x57, 0x8d, 0x80, 0x00, 0x00, 0x00
}};

static const sol_pubkey_t SOL_LOADER_V4_ID = {{ /* LoaderV411111111111111111111111111111111111 */
    0x05, 0x12, 0xb4, 0x11, 0x51, 0x51, 0xe3, 0x7a,
    0xad, 0x0a, 0x8b, 0xc5, 0xd3, 0x88, 0x2e, 0x7b,
    0x7f, 0xda, 0x4c, 0xf3, 0xd2, 0xc0, 0x28, 0xc8,
    0xcf, 0x83, 0x36, 0x18, 0x00, 0x00, 0x00, 0x00
}};

static const sol_pubkey_t SOL_ZK_ELGAMAL_PROOF_ID = {{ /* ZkE1Gama1Proof11111111111111111111111111111 */
    0x08, 0x63, 0x75, 0xac, 0xe2, 0xae, 0xea, 0x28,
    0x1a, 0x6b, 0x37, 0x4d, 0x68, 0x1b, 0xa7, 0x6a,
    0x53, 0xcc, 0xf6, 0x38, 0xc0, 0x74, 0x55, 0x93,
    0x6c, 0x05, 0xd0, 0x65, 0x40, 0x00, 0x00, 0x00
}};

static const sol_pubkey_t SOL_ZK_TOKEN_PROOF_ID = {{ /* ZkTokenProof1111111111111111111111111111111 */
    0x08, 0x63, 0xba, 0x8d, 0xd9, 0xc4, 0xc2, 0xfb,
    0x17, 0x4a, 0x05, 0xcb, 0xa2, 0x7e, 0x2a, 0x2c,
    0xd6, 0x23, 0x57, 0x3d, 0x79, 0xe9, 0x0b, 0x35,
    0xb5, 0x79, 0xfc, 0x0d, 0x00, 0x00, 0x00, 0x00
}};

/* SOL_SECP256R1_PROGRAM_ID: provided by sol_types.h */

static bool
is_reserved_account_key(const sol_pubkey_t* key) {
    if (!key) return false;

    /* Active reserved keys - builtins (16) */
    if (sol_pubkey_eq(key, &SOL_SYSTEM_PROGRAM_ID))         return true;
    if (sol_pubkey_eq(key, &SOL_VOTE_PROGRAM_ID))           return true;
    if (sol_pubkey_eq(key, &SOL_STAKE_PROGRAM_ID))          return true;
    if (sol_pubkey_eq(key, &SOL_CONFIG_PROGRAM_ID))         return true;
    if (sol_pubkey_eq(key, &SOL_BPF_LOADER_V2_ID))          return true;
    if (sol_pubkey_eq(key, &SOL_BPF_LOADER_DEPRECATED_ID))  return true;
    if (sol_pubkey_eq(key, &SOL_BPF_LOADER_UPGRADEABLE_ID)) return true;
    if (sol_pubkey_eq(key, &SOL_FEATURE_PROGRAM_ID))        return true;
    if (sol_pubkey_eq(key, &SOL_STAKE_CONFIG_ID))           return true;
    if (sol_pubkey_eq(key, &SOL_NATIVE_LOADER_ID))          return true;
    if (sol_pubkey_eq(key, &SOL_ADDRESS_LOOKUP_TABLE_ID))   return true;
    if (sol_pubkey_eq(key, &SOL_COMPUTE_BUDGET_ID))         return true;
    if (sol_pubkey_eq(key, &SOL_ED25519_PROGRAM_ID))        return true;
    if (sol_pubkey_eq(key, &SOL_SECP256K1_PROGRAM_ID))      return true;
    if (sol_pubkey_eq(key, &SOL_LOADER_V4_ID))              return true;
    if (sol_pubkey_eq(key, &SOL_ZK_ELGAMAL_PROOF_ID))       return true;
    if (sol_pubkey_eq(key, &SOL_ZK_TOKEN_PROOF_ID))         return true;

    /* Active reserved keys - sysvars (12) */
    if (sol_pubkey_eq(key, &SOL_SYSVAR_CLOCK_ID))               return true;
    if (sol_pubkey_eq(key, &SOL_SYSVAR_EPOCH_SCHEDULE_ID))       return true;
    if (sol_pubkey_eq(key, &SOL_SYSVAR_FEES_ID))                 return true;
    if (sol_pubkey_eq(key, &SOL_SYSVAR_RECENT_BLOCKHASHES_ID))   return true;
    if (sol_pubkey_eq(key, &SOL_SYSVAR_RENT_ID))                 return true;
    if (sol_pubkey_eq(key, &SOL_SYSVAR_REWARDS_ID))              return true;
    if (sol_pubkey_eq(key, &SOL_SYSVAR_SLOT_HASHES_ID))          return true;
    if (sol_pubkey_eq(key, &SOL_SYSVAR_SLOT_HISTORY_ID))         return true;
    if (sol_pubkey_eq(key, &SOL_SYSVAR_STAKE_HISTORY_ID))        return true;
    if (sol_pubkey_eq(key, &SOL_SYSVAR_INSTRUCTIONS_ID))         return true;
    if (sol_pubkey_eq(key, &SOL_SYSVAR_EPOCH_REWARDS_ID))        return true;
    if (sol_pubkey_eq(key, &SOL_SYSVAR_LAST_RESTART_SLOT_ID))    return true;

    /* Active reserved keys - other (1) */
    if (sol_pubkey_eq(key, &SOL_SYSVAR_PROGRAM_ID))              return true;

    /* Pending reserved key (feature-gated, active at slot ~345M) */
    if (sol_pubkey_eq(key, &SOL_SECP256R1_PROGRAM_ID))           return true;

    return false;
}

static bool
bank_skip_instruction_exec(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (v >= 0) return v != 0;

    const char* env = getenv("SOL_SKIP_INSTRUCTION_EXEC");
    int enabled = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled != 0;
}

static bool
bank_skip_signature_verify(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (v >= 0) return v != 0;

    const char* env = getenv("SOL_SKIP_SIGNATURE_VERIFY");
    int enabled = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled != 0;
}

static bool
bank_record_tx_status_batch_enabled(void) {
    /* Default: when tx indexing is disabled, skip replay batch tx-status cache
     * writes to avoid long mutex-held updates in the replay hot path.
     *
     * Override:
     *   SOL_TX_STATUS_BATCH_RECORD=1  force-enable
     *   SOL_TX_STATUS_BATCH_RECORD=0  force-disable
     */
    const char* env = getenv("SOL_TX_STATUS_BATCH_RECORD");
    if (env && env[0] != '\0') {
        while (*env && isspace((unsigned char)*env)) env++;
        if (*env == '0' || *env == 'n' || *env == 'N' || *env == 'f' || *env == 'F') {
            return false;
        }
        return true;
    }

    const char* skip_tx_index = getenv("SOL_SKIP_TX_INDEX");
    if (skip_tx_index && skip_tx_index[0] != '\0') {
        while (*skip_tx_index && isspace((unsigned char)*skip_tx_index)) skip_tx_index++;
        if (*skip_tx_index == '0' || *skip_tx_index == 'n' || *skip_tx_index == 'N' ||
            *skip_tx_index == 'f' || *skip_tx_index == 'F') {
            return true;
        }
        return false;
    }

    return true;
}

/* Replay-only thread-local hint: when set, the current thread is processing
 * entries whose transaction signatures are being verified by replay entry
 * verification (sync or async-then-joined) and can skip redundant per-tx
 * signature re-verification in the bank hot path. */
static __thread int g_tls_replay_signatures_preverified = 0;
/* Replay-only thread-local hint: set for the replay hot path regardless of
 * whether signature preverification is enabled. */
static __thread int g_tls_replay_context = 0;

void
sol_bank_set_replay_context(bool enabled) {
    g_tls_replay_context = enabled ? 1 : 0;
}

void
sol_bank_set_replay_signatures_preverified(bool enabled) {
    g_tls_replay_signatures_preverified = enabled ? 1 : 0;
}

static uint64_t
bank_slow_tx_threshold_ns(void) {
    /* Returns 0 when disabled. Cached after first call. */
    static _Atomic uint64_t cached = UINT64_MAX;
    uint64_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != UINT64_MAX, 1)) {
        return v;
    }

    uint64_t ns = 0;
    const char* env = getenv("SOL_SLOW_TX_MS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long ms = strtoul(env, &end, 10);
        if (end != env && ms > 0ul) {
            ns = (uint64_t)ms * 1000000ull;
        }
    }

    __atomic_store_n(&cached, ns, __ATOMIC_RELEASE);
    return ns;
}

static uint64_t
bank_slow_instr_threshold_ns(void) {
    /* Returns 0 when disabled. Cached after first call. */
    static _Atomic uint64_t cached = UINT64_MAX;
    uint64_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != UINT64_MAX, 1)) {
        return v;
    }

    uint64_t ns = 0;
    const char* env = getenv("SOL_SLOW_INSTR_MS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long ms = strtoul(env, &end, 10);
        if (end != env && ms > 0ul) {
            ns = (uint64_t)ms * 1000000ull;
        }
    }

    __atomic_store_n(&cached, ns, __ATOMIC_RELEASE);
    return ns;
}

static bool
bank_slow_tx_phase_diag_enabled(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (v >= 0) return v != 0;

    const char* env = getenv("SOL_SLOW_TX_PHASES");
    int enabled = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled != 0;
}

static bool
bank_skip_transaction_processing(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (v >= 0) return v != 0;

    const char* env = getenv("SOL_SKIP_TX_PROCESSING");
    int enabled = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled != 0;
}

static bool
bank_strict_poh_rehash(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (v >= 0) return v != 0;

    /* Default: disabled. Replay already verifies entry hash chains, so we can
     * trust entry->hash and avoid rehashing every intermediate PoH step inside
     * bank processing. Set SOL_STRICT_POH_REHASH=1 to restore legacy behavior. */
    const char* env = getenv("SOL_STRICT_POH_REHASH");
    int enabled = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled != 0;
}

static bool
bank_sysvar_diag_enable(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (v >= 0) return v != 0;

    const char* env = getenv("SOL_SYSVAR_DIAG");
    int enabled = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled != 0;
}

static bool
bank_lt_hash_diag_enable(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (v >= 0) return v != 0;

    const char* env = getenv("SOL_LT_HASH_DIAG");
    int enabled = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled != 0;
}

static bool
bank_lt_hash_timing_enable(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (v >= 0) return v != 0;

    const char* env = getenv("SOL_LT_HASH_TIMING");
    int enabled = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled != 0;
}

static bool
bank_rent_diag_enable(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (v >= 0) return v != 0;

    const char* env = getenv("SOL_RENT_DIAG");
    int enabled = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled != 0;
}

static bool
bank_fee_payer_trace_enable(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (v >= 0) return v != 0;

    const char* env = getenv("SOL_FEE_PAYER_TRACE");
    int enabled = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled != 0;
}

static bool
bank_lamport_diag_enable(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (v >= 0) return v != 0;

    const char* env = getenv("SOL_LAMPORT_DIAG");
    int enabled = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled != 0;
}

/*
 * Recent blockhash entry
 */
typedef struct {
    sol_hash_t  hash;
    uint64_t    fee_calculator;     /* Lamports per signature at this hash */
    uint64_t    timestamp;
} sol_blockhash_entry_t;

/*
 * Maximum recent blockhashes to keep
 */
#define MAX_RECENT_BLOCKHASHES 300
#define RECENT_BLOCKHASHES_SYSVAR_MAX_ENTRIES 150

/*
 * Default ticks per second (Solana mainnet default is 160).
 *
 * Used to derive deterministic Clock sysvar timestamps from the genesis
 * creation time and slot.
 */
#define SOL_DEFAULT_TICKS_PER_SECOND 160ULL

/* Default transaction fee burn percent (Solana FeeRateGovernor default). */
#define SOL_FEE_BURN_PERCENT_DEFAULT 50ULL

/*
 * Transaction status cache entry (internal)
 */
typedef struct sol_tx_status_node {
    sol_tx_status_entry_t       entry;
    struct sol_tx_status_node*  next;
} sol_tx_status_node_t;

/*
 * Transaction status cache hash table size
 */
#define TX_STATUS_HASH_SIZE 4096

/* ---- Address Lookup Table cache (v0 message resolution) ---- */

typedef struct {
    sol_alt_state_t state;
} bank_alt_cache_entry_t;

/*
 * Bank structure
 */
struct sol_bank {
    sol_bank_config_t       config;

    /* Slot/epoch state */
    sol_slot_t              slot;
    sol_slot_t              parent_slot;
    uint64_t                epoch;
    sol_unix_timestamp_t    genesis_creation_time;
    bool                    genesis_creation_time_set;
    sol_hash_t              parent_hash;         /* Parent bank hash (for voting) */
    sol_hash_t              poh_hash;            /* PoH hash at the end of the last processed entry */
    sol_hash_t              blockhash;
    sol_hash_t              genesis_hash;       /* Genesis hash for this chain */
    bool                    genesis_hash_set;
    uint64_t                tick_height;
    uint64_t                max_tick_height;
    uint64_t                hashes_in_tick;      /* PoH hashes since last tick boundary */
    uint64_t                signature_count;

    /* Fee distribution */
    sol_pubkey_t            fee_collector;
    bool                    fee_collector_set;
    bool                    fees_distributed;

    /* Accounts */
    sol_accounts_db_t*      accounts_db;
    bool                    owns_accounts_db;
    sol_lt_hash_t           accounts_lt_hash_base;
    sol_lt_hash_t           accounts_lt_hash;
    bool                    accounts_lt_hash_base_valid;
    bool                    accounts_lt_hash_computed;

    /* Zombie account filter: accounts with lamports==0 stored at or before
     * this slot are treated as invisible (matching Agave's clean_accounts).
     * Accounts closed AFTER this slot (during replay) remain visible. */
    sol_slot_t              zombie_filter_slot;

    /* Recent blockhashes */
    sol_blockhash_entry_t   recent_blockhashes[MAX_RECENT_BLOCKHASHES];
    size_t                  recent_blockhash_count;
    /* Fast lookup: blockhash -> lamports_per_signature */
    sol_map_t*              recent_blockhash_map;

    /* Cache frequently accessed sysvars/derived values to avoid repeated
     * AccountsDB loads in the hot execution path. */
    sol_clock_t             cached_clock;
    bool                    cached_clock_valid;
    sol_slot_hashes_t       cached_slot_hashes;
    bool                    cached_slot_hashes_valid;

    /* Transaction status cache */
    sol_tx_status_node_t*   tx_status_buckets[TX_STATUS_HASH_SIZE];
    size_t                  tx_status_count;
    pthread_mutex_t         tx_status_lock;

    /* State */
    bool                    frozen;
    sol_hash_t              bank_hash;
    sol_hash_t              accounts_delta_hash;
    bool                    hash_computed;
    bool                    accounts_delta_hash_computed;

    /* Statistics */
    sol_bank_stats_t        stats;

    /* Cached parsed ALT tables (pubkey -> bank_alt_cache_entry_t*). */
    sol_pubkey_map_t*       alt_cache;
    pthread_rwlock_t        alt_cache_lock;
    bool                    alt_cache_lock_init;
    uint64_t                alt_cache_hits;
    uint64_t                alt_cache_misses;

    /* Thread safety */
    pthread_mutex_t         lock;
};

static uint64_t
bank_recent_blockhash_hash(const void* key) {
    const sol_hash_t* h = (const sol_hash_t*)key;
    return sol_hash_bytes(h->bytes, SOL_HASH_SIZE);
}

static bool
bank_recent_blockhash_eq(const void* a, const void* b) {
    return memcmp(a, b, SOL_HASH_SIZE) == 0;
}

static void
bank_recent_blockhash_map_rebuild(sol_bank_t* bank) {
    if (!bank) return;

    size_t count = bank->recent_blockhash_count;
    if (count == 0) {
        if (bank->recent_blockhash_map) {
            sol_map_clear(bank->recent_blockhash_map);
        }
        return;
    }

    if (!bank->recent_blockhash_map) {
        size_t cap = count * 2u;
        if (cap < 16u) cap = 16u;
        bank->recent_blockhash_map = sol_map_new(sizeof(sol_hash_t),
                                                 sizeof(uint64_t),
                                                 bank_recent_blockhash_hash,
                                                 bank_recent_blockhash_eq,
                                                 cap);
        if (!bank->recent_blockhash_map) {
            return;
        }
    } else {
        sol_map_clear(bank->recent_blockhash_map);
    }

    for (size_t i = 0; i < count; i++) {
        (void)sol_map_insert(bank->recent_blockhash_map,
                             &bank->recent_blockhashes[i].hash,
                             &bank->recent_blockhashes[i].fee_calculator);
    }
}

static void
bank_alt_cache_destroy(sol_bank_t* bank) {
    if (!bank || !bank->alt_cache_lock_init) return;

    pthread_rwlock_wrlock(&bank->alt_cache_lock);
    if (bank->alt_cache) {
        sol_map_iter_t it = sol_map_iter(bank->alt_cache->inner);
        void* key = NULL;
        void* val = NULL;
        while (sol_map_iter_next(&it, &key, &val)) {
            bank_alt_cache_entry_t* entry =
                val ? *(bank_alt_cache_entry_t* const*)val : NULL;
            if (entry) {
                sol_alt_state_free(&entry->state);
                sol_free(entry);
            }
        }
        sol_pubkey_map_destroy(bank->alt_cache);
        bank->alt_cache = NULL;
    }
    pthread_rwlock_unlock(&bank->alt_cache_lock);

    pthread_rwlock_destroy(&bank->alt_cache_lock);
    bank->alt_cache_lock_init = false;
}

static void
bank_alt_cache_init(sol_bank_t* bank) {
    if (!bank || bank->alt_cache_lock_init) return;

    if (pthread_rwlock_init(&bank->alt_cache_lock, NULL) != 0) {
        return;
    }
    bank->alt_cache_lock_init = true;
    bank->alt_cache = sol_pubkey_map_new(sizeof(void*), 256u);
    if (!bank->alt_cache) {
        pthread_rwlock_destroy(&bank->alt_cache_lock);
        bank->alt_cache_lock_init = false;
    }
}

static void
bank_alt_cache_invalidate(sol_bank_t* bank, const sol_pubkey_t* key) {
    if (!bank || !key || !bank->alt_cache_lock_init || !bank->alt_cache) return;

    bank_alt_cache_entry_t* entry = NULL;

    /* Optimistic read path: avoid taking the exclusive lock unless we
     * actually have a cached entry for this key. */
    pthread_rwlock_rdlock(&bank->alt_cache_lock);
    bank_alt_cache_entry_t** found =
        (bank_alt_cache_entry_t**)sol_pubkey_map_get(bank->alt_cache, key);
    bool present = (found && *found);
    pthread_rwlock_unlock(&bank->alt_cache_lock);

    if (!present) return;

    pthread_rwlock_wrlock(&bank->alt_cache_lock);
    found = (bank_alt_cache_entry_t**)sol_pubkey_map_get(bank->alt_cache, key);
    if (found && *found) {
        entry = *found;
        (void)sol_pubkey_map_remove(bank->alt_cache, key);
    }
    pthread_rwlock_unlock(&bank->alt_cache_lock);

    if (entry) {
        sol_alt_state_free(&entry->state);
        sol_free(entry);
    }
}

static sol_err_t
bank_alt_cache_get(sol_bank_t* bank, const sol_pubkey_t* key, const sol_alt_state_t** out_state) {
    if (!bank || !key || !out_state) return SOL_ERR_INVAL;

    bank_alt_cache_init(bank);
    if (!bank->alt_cache_lock_init || !bank->alt_cache) {
        return SOL_ERR_NOT_IMPLEMENTED;
    }

    /* If this table was modified in the current bank overlay, bypass the cache
     * and re-load from AccountsDB (which will observe the local layer). */
    if (sol_accounts_db_is_overlay(bank->accounts_db)) {
        sol_accounts_db_local_kind_t kind =
            sol_accounts_db_get_local_kind(bank->accounts_db, key, NULL);
        if (kind == SOL_ACCOUNTS_DB_LOCAL_TOMBSTONE) {
            return SOL_ERR_TX_SANITIZE;
        }
        if (kind == SOL_ACCOUNTS_DB_LOCAL_ACCOUNT) {
            goto load_and_insert;
        }
    }

    pthread_rwlock_rdlock(&bank->alt_cache_lock);
    bank_alt_cache_entry_t** found =
        (bank_alt_cache_entry_t**)sol_pubkey_map_get(bank->alt_cache, key);
    if (found && *found) {
        __atomic_fetch_add(&bank->alt_cache_hits, 1, __ATOMIC_RELAXED);
        *out_state = &(*found)->state;
        pthread_rwlock_unlock(&bank->alt_cache_lock);
        return SOL_OK;
    }
    pthread_rwlock_unlock(&bank->alt_cache_lock);
    __atomic_fetch_add(&bank->alt_cache_misses, 1, __ATOMIC_RELAXED);

    /* Miss: load and parse outside lock, then insert. */
load_and_insert: ;
    sol_account_t* table_account = sol_accounts_db_load(bank->accounts_db, key);
    if (!table_account) {
        return SOL_ERR_TX_SANITIZE;
    }

    if (!sol_pubkey_eq(&table_account->meta.owner, &SOL_ADDRESS_LOOKUP_TABLE_ID)) {
        sol_account_destroy(table_account);
        return SOL_ERR_TX_SANITIZE;
    }

    bank_alt_cache_entry_t* entry = sol_calloc(1, sizeof(*entry));
    if (!entry) {
        sol_account_destroy(table_account);
        return SOL_ERR_NOMEM;
    }
    sol_alt_state_init(&entry->state);

    sol_err_t deser_err =
        sol_alt_deserialize(&entry->state, table_account->data, (size_t)table_account->meta.data_len);
    sol_account_destroy(table_account);
    if (deser_err != SOL_OK) {
        sol_alt_state_free(&entry->state);
        sol_free(entry);
        return SOL_ERR_TX_SANITIZE;
    }

    if (!sol_alt_is_active(&entry->state, sol_bank_slot(bank))) {
        sol_alt_state_free(&entry->state);
        sol_free(entry);
        return SOL_ERR_TX_SANITIZE;
    }

    pthread_rwlock_wrlock(&bank->alt_cache_lock);
    bank_alt_cache_entry_t** existing =
        (bank_alt_cache_entry_t**)sol_pubkey_map_get(bank->alt_cache, key);
    if (existing && *existing) {
        *out_state = &(*existing)->state;
        pthread_rwlock_unlock(&bank->alt_cache_lock);
        sol_alt_state_free(&entry->state);
        sol_free(entry);
        return SOL_OK;
    }

    void* v = entry;
    (void)sol_pubkey_map_insert(bank->alt_cache, key, &v);
    *out_state = &entry->state;
    pthread_rwlock_unlock(&bank->alt_cache_lock);
    return SOL_OK;
}

static sol_err_t refresh_sysvar_accounts(sol_bank_t* bank, bool overwrite_existing);
static sol_err_t update_recent_blockhashes_sysvar(sol_bank_t* bank);
static sol_err_t update_slot_history_sysvar(sol_bank_t* bank);
static bool bank_is_blockhash_valid_locked(const sol_bank_t* bank, const sol_hash_t* blockhash);
static uint64_t bank_lamports_per_signature_for_blockhash_locked(
    const sol_bank_t* bank,
    const sol_hash_t* blockhash
);
static bool bank_try_get_durable_nonce_fee_calculator(const sol_bank_t* bank,
                                                      const sol_transaction_t* tx,
                                                      uint64_t* out_lamports_per_signature);

static bool
bank_log_fee_dist(void) {
    static int cached = -1;
    if (cached >= 0) return cached != 0;

    const char* env = getenv("SOL_LOG_FEE_DIST");
    cached = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    return cached != 0;
}

static sol_err_t
distribute_slot_fees(sol_bank_t* bank) {
    if (!bank) return SOL_ERR_INVAL;
    if (bank->fees_distributed) return SOL_OK;

    bank->fees_distributed = true;

    uint64_t total_fees = bank->stats.total_fees_collected;
    uint64_t priority_fees = bank->stats.total_priority_fees_collected;
    if (total_fees == 0) {
        return SOL_OK;
    }

    if (!bank->fee_collector_set || sol_pubkey_is_zero(&bank->fee_collector)) {
        return SOL_OK;
    }

    uint64_t base_fees = 0;
    if (priority_fees <= total_fees) {
        base_fees = total_fees - priority_fees;
    } else {
        /* Defensive: should never happen, but avoid underflow. */
        priority_fees = total_fees;
        base_fees = 0;
    }

    uint64_t burned = (base_fees * SOL_FEE_BURN_PERCENT_DEFAULT) / 100ULL;
    uint64_t to_collector = (base_fees - burned) + priority_fees;
    if (to_collector == 0) {
        return SOL_OK;
    }

    sol_account_t* collector =
        sol_accounts_db_load(bank->accounts_db, &bank->fee_collector);
    if (!collector) {
        collector = sol_account_new(0, 0, &SOL_SYSTEM_PROGRAM_ID);
        if (!collector) {
            return SOL_ERR_NOMEM;
        }
    }

    /* Agave's deposit_fees() validates the collector account.
     * If validation fails, the fee is burned instead of deposited
     * (see fee_distribution.rs deposit_or_burn_fee). */
    bool deposit_ok = true;
    if (!sol_pubkey_eq(&collector->meta.owner, &SOL_SYSTEM_PROGRAM_ID)) {
        deposit_ok = false;
    }
    if (collector->meta.lamports > UINT64_MAX - to_collector) {
        deposit_ok = false;
    }

    if (!deposit_ok) {
        char coll_b58[SOL_PUBKEY_BASE58_LEN] = {0};
        sol_pubkey_to_base58(&bank->fee_collector, coll_b58, sizeof(coll_b58));
        if (bank_log_fee_dist()) {
            sol_log_info("FEE_DIST: slot=%lu BURNED %lu lamports (collector=%s failed validation)",
                         (unsigned long)bank->slot, (unsigned long)to_collector, coll_b58);
        } else {
            sol_log_debug("FEE_DIST: slot=%lu BURNED %lu lamports (collector=%s failed validation)",
                          (unsigned long)bank->slot, (unsigned long)to_collector, coll_b58);
        }
        sol_account_destroy(collector);
        return SOL_OK;
    }
    collector->meta.lamports += to_collector;

    {
        char coll_b58[SOL_PUBKEY_BASE58_LEN] = {0};
        sol_pubkey_to_base58(&bank->fee_collector, coll_b58, sizeof(coll_b58));
        if (bank_log_fee_dist()) {
            sol_log_info("FEE_DIST: slot=%lu collector=%s total_fees=%lu priority=%lu burned=%lu to_collector=%lu",
                         (unsigned long)bank->slot, coll_b58,
                         (unsigned long)total_fees, (unsigned long)priority_fees,
                         (unsigned long)burned, (unsigned long)to_collector);
        } else {
            sol_log_debug("FEE_DIST: slot=%lu collector=%s total_fees=%lu priority=%lu burned=%lu to_collector=%lu",
                          (unsigned long)bank->slot, coll_b58,
                          (unsigned long)total_fees, (unsigned long)priority_fees,
                          (unsigned long)burned, (unsigned long)to_collector);
        }
    }

    sol_err_t err = sol_bank_store_account(bank, &bank->fee_collector, collector);
    sol_account_destroy(collector);
    return err;
}

static bool
restore_recent_blockhashes_from_sysvar(sol_bank_t* bank) {
    if (!bank || !bank->accounts_db) {
        return false;
    }

    sol_account_t* account =
        sol_accounts_db_load(bank->accounts_db, &SOL_SYSVAR_RECENT_BLOCKHASHES_ID);
    if (!account) {
        sol_log_debug("RecentBlockhashes sysvar account not found; cannot restore blockhash");
        return false;
    }

    sol_recent_blockhashes_t rbh;
    sol_recent_blockhashes_init(&rbh);
    sol_err_t err = sol_recent_blockhashes_deserialize(
        &rbh, account->data, account->meta.data_len);
    if (sol_log_get_level() <= SOL_LOG_DEBUG) {
        if (err != SOL_OK) {
            sol_log_debug("Failed to deserialize RecentBlockhashes sysvar (len=%lu): %s",
                          (unsigned long)account->meta.data_len,
                          sol_err_str(err));
            sol_log_hexdump(SOL_LOG_DEBUG,
                            "RecentBlockhashes sysvar (first 64 bytes)",
                            account->data,
                            account->meta.data_len < 64 ? (size_t)account->meta.data_len : 64);
        } else if (rbh.len == 0) {
            sol_log_debug("RecentBlockhashes sysvar deserialized but had no entries (len=%lu)",
                          (unsigned long)account->meta.data_len);
            sol_log_hexdump(SOL_LOG_DEBUG,
                            "RecentBlockhashes sysvar (first 64 bytes)",
                            account->data,
                            account->meta.data_len < 64 ? (size_t)account->meta.data_len : 64);
        }
    }

    sol_account_destroy(account);
    if (err != SOL_OK || rbh.len == 0) {
        return false;
    }

    size_t count = rbh.len;
    if (count > MAX_RECENT_BLOCKHASHES) {
        count = MAX_RECENT_BLOCKHASHES;
    }

    for (size_t i = 0; i < count; i++) {
        bank->recent_blockhashes[i].hash = rbh.entries[i].blockhash;
        bank->recent_blockhashes[i].fee_calculator =
            rbh.entries[i].fee_calculator.lamports_per_signature;
        bank->recent_blockhashes[i].timestamp = 0;
    }
    bank->recent_blockhash_count = count;
    bank->blockhash = bank->recent_blockhashes[0].hash;
    bank_recent_blockhash_map_rebuild(bank);
    if (sol_log_get_level() <= SOL_LOG_DEBUG) {
        char hex[65] = {0};
        (void)sol_hash_to_hex(&bank->blockhash, hex, sizeof(hex));
        sol_log_debug("Restored %lu recent blockhashes (latest=%s)", (unsigned long)count, hex);
    }
    return true;
}

static sol_unix_timestamp_t
unix_timestamp_for_slot(const sol_bank_t* bank, sol_slot_t slot) {
    if (!bank) {
        return 0;
    }

    if (!bank->genesis_creation_time_set) {
        return (sol_unix_timestamp_t)slot;
    }

    uint64_t ns_per_slot =
        (1000000000ULL * bank->config.ticks_per_slot) / SOL_DEFAULT_TICKS_PER_SECOND;

    uint64_t offset_ns = 0;
    if (__builtin_mul_overflow((uint64_t)slot, ns_per_slot, &offset_ns)) {
        return bank->genesis_creation_time;
    }
    sol_unix_timestamp_t offset_s = (sol_unix_timestamp_t)(offset_ns / 1000000000ULL);
    return bank->genesis_creation_time + offset_s;
}

static uint64_t
bank_ns_per_slot(const sol_bank_t* bank) {
    if (!bank) return 0;
    __uint128_t num = (__uint128_t)1000000000ULL * (__uint128_t)bank->config.ticks_per_slot;
    num /= (__uint128_t)SOL_DEFAULT_TICKS_PER_SECOND;
    if (num > UINT64_MAX) {
        return 0;
    }
    return (uint64_t)num;
}

static bool
load_visible_clock_sysvar(sol_bank_t* bank, sol_clock_t* out) {
    if (!bank || !out || !bank->accounts_db) {
        return false;
    }

    sol_account_t* acct =
        sol_accounts_db_load(bank->accounts_db, &SOL_SYSVAR_CLOCK_ID);
    if (!acct) {
        return false;
    }

    bool ok = false;
    sol_clock_t clock;
    sol_clock_init(&clock);
    if (acct->meta.data_len >= SOL_CLOCK_SIZE &&
        sol_clock_deserialize(&clock, acct->data, acct->meta.data_len) == SOL_OK) {
        *out = clock;
        ok = true;
    }

    sol_account_destroy(acct);
    return ok;
}

typedef struct {
    uint64_t            root_id;
    uint64_t            epoch;
    sol_pubkey_map_t*   vote_stakes;
    uint64_t            total_stake;
    uint64_t            gen;
    bool                valid;
} vote_stakes_cache_entry_t;

#define VOTE_STAKES_CACHE_ENTRIES 4
static vote_stakes_cache_entry_t g_vote_stakes_cache[VOTE_STAKES_CACHE_ENTRIES];
static uint64_t g_vote_stakes_cache_gen = 1;
static pthread_mutex_t g_vote_stakes_cache_lock = PTHREAD_MUTEX_INITIALIZER;

static sol_pubkey_map_t*
pubkey_u64_map_clone(const sol_pubkey_map_t* src) {
    if (!src || !src->inner) return NULL;

    size_t src_size = sol_map_size(src->inner);
    size_t src_cap = sol_map_capacity(src->inner);
    size_t cap = src_cap;
    if (cap < src_size * 2) {
        cap = src_size * 2;
    }
    if (cap < 1024u) {
        cap = 1024u;
    }

    sol_pubkey_map_t* dst = sol_pubkey_map_new(sizeof(uint64_t), cap);
    if (!dst) return NULL;

    sol_map_iter_t it = sol_map_iter(src->inner);
    void* k = NULL;
    void* v = NULL;
    while (sol_map_iter_next(&it, &k, &v)) {
        if (!k || !v) continue;
        sol_pubkey_t key = *(const sol_pubkey_t*)k;
        uint64_t stake = *(const uint64_t*)v;
        if (!sol_pubkey_map_insert(dst, &key, &stake)) {
            sol_pubkey_map_destroy(dst);
            return NULL;
        }
    }

    return dst;
}

sol_err_t
sol_bank_seed_vote_stakes_cache(sol_accounts_db_t* accounts_db,
                                uint64_t epoch,
                                const sol_pubkey_map_t* vote_stakes,
                                uint64_t total_stake) {
    if (!accounts_db || !vote_stakes) return SOL_ERR_INVAL;

    uint64_t root_id = sol_accounts_db_root_id(accounts_db);
    if (root_id == 0) {
        root_id = sol_accounts_db_id(accounts_db);
    }
    if (root_id == 0) {
        return SOL_ERR_INVAL;
    }

    sol_pubkey_map_t* clone = pubkey_u64_map_clone(vote_stakes);
    if (!clone) {
        return SOL_ERR_NOMEM;
    }

    pthread_mutex_lock(&g_vote_stakes_cache_lock);

    /* Replace existing entry if present. */
    for (size_t i = 0; i < VOTE_STAKES_CACHE_ENTRIES; i++) {
        vote_stakes_cache_entry_t* e = &g_vote_stakes_cache[i];
        if (e->valid && e->root_id == root_id && e->epoch == epoch) {
            if (e->vote_stakes) {
                sol_pubkey_map_destroy(e->vote_stakes);
            }
            e->vote_stakes = clone;
            e->total_stake = total_stake;
            e->gen = ++g_vote_stakes_cache_gen;
            pthread_mutex_unlock(&g_vote_stakes_cache_lock);
            return SOL_OK;
        }
    }

    /* Find eviction slot (first invalid, else least-recently-used). */
    size_t evict = 0;
    uint64_t oldest = UINT64_MAX;
    for (size_t i = 0; i < VOTE_STAKES_CACHE_ENTRIES; i++) {
        vote_stakes_cache_entry_t* e = &g_vote_stakes_cache[i];
        if (!e->valid || !e->vote_stakes) {
            evict = i;
            oldest = 0;
            break;
        }
        if (e->gen < oldest) {
            oldest = e->gen;
            evict = i;
        }
    }

    vote_stakes_cache_entry_t* slot = &g_vote_stakes_cache[evict];
    if (slot->vote_stakes) {
        sol_pubkey_map_destroy(slot->vote_stakes);
    }

    *slot = (vote_stakes_cache_entry_t){
        .root_id = root_id,
        .epoch = epoch,
        .vote_stakes = clone,
        .total_stake = total_stake,
        .gen = ++g_vote_stakes_cache_gen,
        .valid = true,
    };

    pthread_mutex_unlock(&g_vote_stakes_cache_lock);
    return SOL_OK;
}

static sol_pubkey_map_t*
bank_get_vote_stakes_cached(sol_bank_t* bank, uint64_t epoch, uint64_t* out_total_stake) {
    if (out_total_stake) {
        *out_total_stake = 0;
    }
    if (!bank || !bank->accounts_db) {
        return NULL;
    }

    uint64_t root_id = sol_accounts_db_root_id(bank->accounts_db);
    if (root_id == 0) {
        root_id = sol_accounts_db_id(bank->accounts_db);
    }

    pthread_mutex_lock(&g_vote_stakes_cache_lock);
    for (size_t i = 0; i < VOTE_STAKES_CACHE_ENTRIES; i++) {
        vote_stakes_cache_entry_t* e = &g_vote_stakes_cache[i];
        if (e->valid && e->vote_stakes && e->root_id == root_id && e->epoch == epoch) {
            e->gen = ++g_vote_stakes_cache_gen;
            if (out_total_stake) {
                *out_total_stake = e->total_stake;
            }
            sol_pubkey_map_t* map = e->vote_stakes;
            pthread_mutex_unlock(&g_vote_stakes_cache_lock);
            return map;
        }
    }

    /* Overlay/forked AccountsDB instances can carry a different root-id while
     * still sharing the same effective epoch stake map. If we miss on the
     * strict (root, epoch) key, fall back to any cached entry for this epoch
     * to avoid rebuilding vote stakes in replay hot paths. */
    vote_stakes_cache_entry_t* epoch_fallback = NULL;
    for (size_t i = 0; i < VOTE_STAKES_CACHE_ENTRIES; i++) {
        vote_stakes_cache_entry_t* e = &g_vote_stakes_cache[i];
        if (!e->valid || !e->vote_stakes || e->epoch != epoch) {
            continue;
        }
        if (!epoch_fallback || e->gen > epoch_fallback->gen) {
            epoch_fallback = e;
        }
    }
    if (epoch_fallback) {
        epoch_fallback->gen = ++g_vote_stakes_cache_gen;
        if (out_total_stake) {
            *out_total_stake = epoch_fallback->total_stake;
        }
        sol_pubkey_map_t* map = epoch_fallback->vote_stakes;
        pthread_mutex_unlock(&g_vote_stakes_cache_lock);
        return map;
    }

    /* Find eviction slot (first invalid, else least-recently-used). */
    size_t evict = 0;
    uint64_t oldest = UINT64_MAX;
    for (size_t i = 0; i < VOTE_STAKES_CACHE_ENTRIES; i++) {
        vote_stakes_cache_entry_t* e = &g_vote_stakes_cache[i];
        if (!e->valid || !e->vote_stakes) {
            evict = i;
            oldest = 0;
            break;
        }
        if (e->gen < oldest) {
            oldest = e->gen;
            evict = i;
        }
    }
    pthread_mutex_unlock(&g_vote_stakes_cache_lock);

    uint64_t total_stake = 0;
    sol_pubkey_map_t* new_map = sol_stake_build_vote_stake_map(bank, epoch, &total_stake);
    if (!new_map) {
        return NULL;
    }

    pthread_mutex_lock(&g_vote_stakes_cache_lock);
    for (size_t i = 0; i < VOTE_STAKES_CACHE_ENTRIES; i++) {
        vote_stakes_cache_entry_t* e = &g_vote_stakes_cache[i];
        if (e->valid && e->vote_stakes && e->root_id == root_id && e->epoch == epoch) {
            e->gen = ++g_vote_stakes_cache_gen;
            if (out_total_stake) {
                *out_total_stake = e->total_stake;
            }
            sol_pubkey_map_t* map = e->vote_stakes;
            pthread_mutex_unlock(&g_vote_stakes_cache_lock);
            sol_pubkey_map_destroy(new_map);
            return map;
        }
    }

    /* Re-check epoch-only fallback in case another thread seeded it while we
     * were building. */
    for (size_t i = 0; i < VOTE_STAKES_CACHE_ENTRIES; i++) {
        vote_stakes_cache_entry_t* e = &g_vote_stakes_cache[i];
        if (!e->valid || !e->vote_stakes || e->epoch != epoch) {
            continue;
        }
        e->gen = ++g_vote_stakes_cache_gen;
        if (out_total_stake) {
            *out_total_stake = e->total_stake;
        }
        sol_pubkey_map_t* map = e->vote_stakes;
        pthread_mutex_unlock(&g_vote_stakes_cache_lock);
        sol_pubkey_map_destroy(new_map);
        return map;
    }

    vote_stakes_cache_entry_t* slot = &g_vote_stakes_cache[evict];
    if (slot->vote_stakes) {
        sol_pubkey_map_destroy(slot->vote_stakes);
    }
    *slot = (vote_stakes_cache_entry_t){
        .root_id = root_id,
        .epoch = epoch,
        .vote_stakes = new_map,
        .total_stake = total_stake,
        .gen = ++g_vote_stakes_cache_gen,
        .valid = true,
    };
    if (out_total_stake) {
        *out_total_stake = total_stake;
    }
    pthread_mutex_unlock(&g_vote_stakes_cache_lock);
    return new_map;
}

/* ---- Vote timestamp cache (Clock sysvar median timestamp) ---- */

typedef struct {
    uint64_t last_timestamp_slot;
    int64_t  last_timestamp;
} vote_timestamp_cache_val_t;

static pthread_once_t   g_vote_ts_cache_once = PTHREAD_ONCE_INIT;
static pthread_rwlock_t g_vote_ts_cache_lock;
static sol_pubkey_map_t* g_vote_ts_cache = NULL;
static uint64_t         g_vote_ts_cache_root_id = 0;

static void
vote_ts_cache_do_init(void) {
    (void)pthread_rwlock_init(&g_vote_ts_cache_lock, NULL);
}

static inline void
vote_ts_cache_init(void) {
    (void)pthread_once(&g_vote_ts_cache_once, vote_ts_cache_do_init);
}

static inline uint64_t
vote_ts_cache_root_id_for_db(const sol_accounts_db_t* db) {
    uint64_t root_id = sol_accounts_db_root_id(db);
    if (root_id == 0) {
        root_id = sol_accounts_db_id(db);
    }
    return root_id;
}

sol_err_t
sol_bank_seed_vote_timestamp_cache(sol_accounts_db_t* accounts_db,
                                   const sol_pubkey_map_t* vote_stakes) {
    if (!accounts_db || !vote_stakes || !vote_stakes->inner) {
        return SOL_ERR_INVAL;
    }

    vote_ts_cache_init();

    uint64_t root_id = vote_ts_cache_root_id_for_db(accounts_db);
    if (root_id == 0) {
        return SOL_ERR_INVAL;
    }

    size_t src_size = sol_map_size(vote_stakes->inner);
    size_t src_cap = sol_map_capacity(vote_stakes->inner);
    size_t cap = src_cap;
    if (cap < src_size * 2) {
        cap = src_size * 2;
    }
    if (cap < 1024u) {
        cap = 1024u;
    }

    sol_pubkey_map_t* tmp = sol_pubkey_map_new(sizeof(vote_timestamp_cache_val_t), cap);
    if (!tmp) {
        return SOL_ERR_NOMEM;
    }

    sol_map_iter_t it = sol_map_iter(vote_stakes->inner);
    void* k = NULL;
    void* v = NULL;
    while (sol_map_iter_next(&it, &k, &v)) {
        if (!k || !v) continue;
        const sol_pubkey_t* vote_pubkey = (const sol_pubkey_t*)k;
        uint64_t stake = *(const uint64_t*)v;
        if (stake == 0) continue;

        sol_account_t* account = sol_accounts_db_load_view(accounts_db, vote_pubkey);
        if (!account) continue;
        if (account->meta.lamports == 0 ||
            !sol_pubkey_eq(&account->meta.owner, &SOL_VOTE_PROGRAM_ID)) {
            sol_account_destroy(account);
            continue;
        }

        sol_vote_state_t vote_state;
        if (sol_vote_state_deserialize(&vote_state, account->data, account->meta.data_len) == SOL_OK) {
            vote_timestamp_cache_val_t val = {
                .last_timestamp_slot = vote_state.last_timestamp_slot,
                .last_timestamp = vote_state.last_timestamp,
            };
            (void)sol_pubkey_map_insert(tmp, vote_pubkey, &val);
        }
        sol_account_destroy(account);
    }

    pthread_rwlock_wrlock(&g_vote_ts_cache_lock);
    if (g_vote_ts_cache) {
        sol_pubkey_map_destroy(g_vote_ts_cache);
    }
    g_vote_ts_cache = tmp;
    g_vote_ts_cache_root_id = root_id;
    pthread_rwlock_unlock(&g_vote_ts_cache_lock);
    return SOL_OK;
}

void
sol_bank_vote_timestamp_cache_update(sol_bank_t* bank,
                                     const sol_pubkey_t* vote_pubkey,
                                     uint64_t last_timestamp_slot,
                                     int64_t last_timestamp) {
    if (!bank || !bank->accounts_db || !vote_pubkey) {
        return;
    }

    vote_ts_cache_init();
    uint64_t root_id = vote_ts_cache_root_id_for_db(bank->accounts_db);
    if (root_id == 0) {
        return;
    }

    pthread_rwlock_wrlock(&g_vote_ts_cache_lock);
    if (!g_vote_ts_cache) {
        g_vote_ts_cache = sol_pubkey_map_new(sizeof(vote_timestamp_cache_val_t), 4096u);
    }
    g_vote_ts_cache_root_id = root_id;

    if (g_vote_ts_cache) {
        vote_timestamp_cache_val_t* cur =
            (vote_timestamp_cache_val_t*)sol_pubkey_map_get(g_vote_ts_cache, vote_pubkey);
        if (!cur ||
            cur->last_timestamp_slot != last_timestamp_slot ||
            cur->last_timestamp != last_timestamp) {
            vote_timestamp_cache_val_t val = {
                .last_timestamp_slot = last_timestamp_slot,
                .last_timestamp = last_timestamp,
            };
            (void)sol_pubkey_map_insert(g_vote_ts_cache, vote_pubkey, &val);
        }
    }

    pthread_rwlock_unlock(&g_vote_ts_cache_lock);
}

typedef struct {
    int64_t     timestamp;
    uint64_t    stake;
} timestamp_sample_t;

static int
cmp_timestamp_sample(const void* a, const void* b) {
    const timestamp_sample_t* sa = (const timestamp_sample_t*)a;
    const timestamp_sample_t* sb = (const timestamp_sample_t*)b;
    if (sa->timestamp < sb->timestamp) return -1;
    if (sa->timestamp > sb->timestamp) return 1;
    return 0;
}

static bool
stake_weighted_median_timestamp(sol_bank_t* bank,
                                const sol_pubkey_map_t* vote_stakes,
                                uint64_t ns_per_slot,
                                int64_t* out_timestamp) {
    if (out_timestamp) {
        *out_timestamp = 0;
    }
    if (!bank || !vote_stakes || !bank->accounts_db || !out_timestamp) {
        return false;
    }

    /* The vote-stakes map already contains only vote accounts with non-zero
     * effective stake. Iterate it directly to avoid scanning all Vote-owned
     * accounts and then checking stake weights. */
    static __thread timestamp_sample_t* tls_samples = NULL;
    static __thread size_t tls_cap = 0;
    timestamp_sample_t* samples = tls_samples;
    size_t len = 0;
    size_t cap = tls_cap;
    __uint128_t total_stake = 0;

    vote_ts_cache_init();

    sol_pubkey_map_t* ts_map = NULL;
    pthread_rwlock_rdlock(&g_vote_ts_cache_lock);
    /* Overlay/forked AccountsDB instances can report different root-ids while
     * still sharing the same effective vote timestamp set. Use the cache as a
     * best-effort hint even when root-id changed, and lazily refresh entries
     * from AccountsDB on misses. */
    if (g_vote_ts_cache) {
        ts_map = g_vote_ts_cache;
    }

    sol_map_iter_t it = sol_map_iter(vote_stakes->inner);
    void* k = NULL;
    void* v = NULL;
    while (sol_map_iter_next(&it, &k, &v)) {
        if (!k || !v) continue;
        const sol_pubkey_t* vote_pubkey = (const sol_pubkey_t*)k;
        uint64_t stake = *(const uint64_t*)v;
        if (stake == 0) continue;

        vote_timestamp_cache_val_t cached = {0};
        bool have_cached = false;
        if (ts_map) {
            vote_timestamp_cache_val_t* p =
                (vote_timestamp_cache_val_t*)sol_pubkey_map_get(ts_map, vote_pubkey);
            if (p) {
                cached = *p;
                have_cached = true;
            }
        }

        uint64_t last_slot = cached.last_timestamp_slot;
        int64_t last_ts = cached.last_timestamp;

        if (!have_cached) {
            sol_account_t* account = sol_accounts_db_load_view(bank->accounts_db, vote_pubkey);
            if (!account) continue;
            if (account->meta.lamports == 0 ||
                !sol_pubkey_eq(&account->meta.owner, &SOL_VOTE_PROGRAM_ID)) {
                sol_account_destroy(account);
                continue;
            }

            sol_vote_state_t vote_state;
            if (sol_vote_state_deserialize(&vote_state, account->data, account->meta.data_len) != SOL_OK) {
                sol_account_destroy(account);
                continue;
            }
            sol_account_destroy(account);

            last_slot = vote_state.last_timestamp_slot;
            last_ts = vote_state.last_timestamp;
        }

        if (last_slot == 0 || last_ts == 0) {
            continue;
        }
        if ((sol_slot_t)last_slot > bank->slot) {
            continue;
        }

        sol_slot_t age = bank->slot - (sol_slot_t)last_slot;
        if ((uint64_t)age > bank->config.slots_per_epoch) {
            continue;
        }

        __uint128_t delta_ns = (__uint128_t)(uint64_t)age * (__uint128_t)ns_per_slot;
        uint64_t delta_s = (uint64_t)(delta_ns / 1000000000ULL);

        if (delta_s > (uint64_t)INT64_MAX) {
            continue;
        }
        if (last_ts > INT64_MAX - (int64_t)delta_s) {
            continue;
        }

        int64_t estimate = last_ts + (int64_t)delta_s;

        if (len == cap) {
            size_t new_cap = cap ? (cap * 2) : 256;
            if (new_cap < cap) {
                pthread_rwlock_unlock(&g_vote_ts_cache_lock);
                return false;
            }
            timestamp_sample_t* next = sol_realloc(samples, new_cap * sizeof(*next));
            if (!next) {
                pthread_rwlock_unlock(&g_vote_ts_cache_lock);
                return false;
            }
            samples = next;
            cap = new_cap;
            tls_samples = samples;
            tls_cap = cap;
        }

        samples[len++] = (timestamp_sample_t){
            .timestamp = estimate,
            .stake = stake,
        };
        total_stake += (__uint128_t)stake;
    }

    pthread_rwlock_unlock(&g_vote_ts_cache_lock);

    if (len == 0 || total_stake == 0) {
        return false;
    }

    qsort(samples, len, sizeof(*samples), cmp_timestamp_sample);

    /* Agave: stake_accumulator > total_stake / 2  (strictly greater than) */
    __uint128_t half_stake = total_stake / 2;
    __uint128_t cum = 0;
    int64_t median = samples[len - 1].timestamp;
    for (size_t i = 0; i < len; i++) {
        cum += (__uint128_t)samples[i].stake;
        if (cum > half_stake) {
            median = samples[i].timestamp;
            break;
        }
    }

    *out_timestamp = median;
    return true;
}

static bool
tx_status_exists_locked(const sol_bank_t* bank, const sol_signature_t* signature) {
    if (!bank || !signature) {
        return false;
    }

    uint32_t bucket = 0;
    bucket |= (uint32_t)signature->bytes[0];
    bucket |= (uint32_t)signature->bytes[1] << 8;
    bucket |= (uint32_t)signature->bytes[2] << 16;
    bucket |= (uint32_t)signature->bytes[3] << 24;
    bucket %= TX_STATUS_HASH_SIZE;

    const sol_tx_status_node_t* node = bank->tx_status_buckets[bucket];
    while (node) {
        if (memcmp(&node->entry.signature, signature, sizeof(sol_signature_t)) == 0) {
            return true;
        }
        node = node->next;
    }
    return false;
}

/* Thread-safe wrapper. */
static bool
tx_status_exists(const sol_bank_t* bank, const sol_signature_t* signature) {
    if (!bank || !signature) return false;
    pthread_mutex_lock((pthread_mutex_t*)&bank->tx_status_lock);
    bool exists = tx_status_exists_locked(bank, signature);
    pthread_mutex_unlock((pthread_mutex_t*)&bank->tx_status_lock);
    return exists;
}

/* Reserve a tx-status slot early so duplicates in the same slot are rejected
 * deterministically even under parallel execution. */
static bool
tx_status_reserve(sol_bank_t* bank, const sol_signature_t* signature) {
    if (!bank || !signature) return true;

    pthread_mutex_lock(&bank->tx_status_lock);

    bool exists = tx_status_exists_locked(bank, signature);
    if (exists) {
        pthread_mutex_unlock(&bank->tx_status_lock);
        return false;
    }

    if (bank->tx_status_count >= SOL_TX_STATUS_CACHE_SIZE) {
        pthread_mutex_unlock(&bank->tx_status_lock);
        return true; /* cache full: skip reserving */
    }

    uint32_t bucket = 0;
    bucket |= (uint32_t)signature->bytes[0];
    bucket |= (uint32_t)signature->bytes[1] << 8;
    bucket |= (uint32_t)signature->bytes[2] << 16;
    bucket |= (uint32_t)signature->bytes[3] << 24;
    bucket %= TX_STATUS_HASH_SIZE;

    sol_tx_status_node_t* node = sol_calloc(1, sizeof(sol_tx_status_node_t));
    if (!node) {
        pthread_mutex_unlock(&bank->tx_status_lock);
        return true; /* best-effort */
    }

    node->entry.signature = *signature;
    node->entry.slot = bank->slot;
    node->entry.status = SOL_ERR_INVAL; /* placeholder; updated on completion */
    node->entry.fee = 0;
    node->entry.compute_units = 0;

    node->next = bank->tx_status_buckets[bucket];
    bank->tx_status_buckets[bucket] = node;
    bank->tx_status_count++;

    pthread_mutex_unlock(&bank->tx_status_lock);
    return true;
}

static bool
accounts_equal_for_lt_hash(const sol_account_t* a, const sol_account_t* b) {
    if (a == NULL && b == NULL) {
        return true;
    }
    if (a == NULL || b == NULL) {
        return false;
    }

    /* LtHash inputs: lamports, data, executable, owner, pubkey (provided separately).
       Note: rent_epoch is NOT included in the lt_hash. */
    if (a->meta.lamports != b->meta.lamports) return false;
    if (a->meta.executable != b->meta.executable) return false;
    if (!sol_pubkey_eq(&a->meta.owner, &b->meta.owner)) return false;
    if (a->meta.data_len != b->meta.data_len) return false;
    if (a->meta.data_len > 0) {
        if (!a->data || !b->data) return false;
        if (memcmp(a->data, b->data, (size_t)a->meta.data_len) != 0) return false;
    }
    return true;
}

static bool
mix_account_into_accounts_lt_hash(const sol_pubkey_t* pubkey,
                                 const sol_account_t* account,
                                 void* ctx) {
    sol_lt_hash_t* acc = (sol_lt_hash_t*)ctx;
    if (!acc || !pubkey || !account) return true;

    sol_lt_hash_t h;
    sol_account_lt_hash(pubkey, account, &h);
    sol_lt_hash_mix_in(acc, &h);
    return true;
}

static size_t
bank_lt_hash_full_recompute_threads(void) {
    const char* env = getenv("SOL_LT_HASH_FULL_RECOMP_THREADS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long v = strtoul(env, &end, 10);
        if (end != env) {
            if (v <= 1ul) return 1u;
            return (size_t)v;
        }
    }

    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n < 1) n = 1;
    size_t threads = (size_t)n;

    /* Full lt_hash recompute is memory-bandwidth heavy. A conservative default
     * avoids oversubscribing the host when multiple validators run. */
    if (threads > 8u) threads = 8u;
    return threads;
}

typedef struct {
    sol_accounts_db_t* db;
    uint32_t           prefixes_per_task; /* number of leading-byte prefixes per task */
    uint32_t           task_count;         /* total tasks */
    uint32_t           next_task;          /* atomic via __atomic builtins */
    sol_lt_hash_t*     partials;           /* [threads] */
} lt_hash_full_recompute_ctx_t;

typedef struct {
    lt_hash_full_recompute_ctx_t* ctx;
    size_t                        idx;
} lt_hash_full_recompute_thread_arg_t;

static void*
lt_hash_full_recompute_thread_main(void* arg) {
    lt_hash_full_recompute_thread_arg_t* a = (lt_hash_full_recompute_thread_arg_t*)arg;
    if (!a || !a->ctx || !a->ctx->db || !a->ctx->partials) return NULL;

    lt_hash_full_recompute_ctx_t* ctx = a->ctx;
    sol_lt_hash_t* acc = &ctx->partials[a->idx];
    sol_lt_hash_identity(acc);

    for (;;) {
        uint32_t task = __atomic_fetch_add(&ctx->next_task, 1u, __ATOMIC_RELAXED);
        if (task >= ctx->task_count) {
            break;
        }

        uint32_t start_prefix = task * ctx->prefixes_per_task;
        uint32_t end_prefix = start_prefix + (ctx->prefixes_per_task - 1u);
        if (end_prefix > 255u) end_prefix = 255u;

        sol_pubkey_t start = {0};
        sol_pubkey_t end = {0};
        start.bytes[0] = (uint8_t)start_prefix;
        memset(start.bytes + 1, 0x00, 31);
        end.bytes[0] = (uint8_t)end_prefix;
        memset(end.bytes + 1, 0xFF, 31);

        sol_accounts_db_iterate_pubkey_range(ctx->db,
                                             &start,
                                             &end,
                                             mix_account_into_accounts_lt_hash,
                                             acc);
    }

    return NULL;
}

typedef struct {
    sol_lt_hash_t* out;
    uint64_t       n_updated;    /* prev and curr exist, differ */
    uint64_t       n_created;    /* prev NULL, curr exists */
    uint64_t       n_removed;    /* curr NULL (zero lamports) */
    uint64_t       n_unchanged;  /* accounts_equal_for_lt_hash */
    uint64_t       total_lamports_stored;
    uint64_t       total_data_len;
    FILE*          dump_fp;      /* optional delta dump file */
    FILE*          dump_bin_fp;  /* optional binary per-account lt_hash dump */
    sol_lt_hash_t  sysvar_delta; /* lt_hash delta from sysvar accounts only */
    uint64_t       n_sysvar;     /* count of changed sysvar accounts */
    uint64_t       slot;         /* current slot for sysvar dump filenames */
    /* Per-owner lt_hash deltas for diagnostics */
    sol_lt_hash_t  vote_delta;
    uint64_t       n_vote;
    sol_lt_hash_t  system_delta;
    uint64_t       n_system;
    sol_lt_hash_t  token_delta;
    uint64_t       n_token;
    sol_lt_hash_t  stake_delta;
    uint64_t       n_stake;
    sol_lt_hash_t  other_delta;
    uint64_t       n_other;
} accounts_lt_hash_delta_ctx_t;

typedef struct {
    sol_lt_hash_t* out;
} accounts_lt_hash_fast_ctx_t;

static bool
apply_local_delta_to_accounts_lt_hash_fast(sol_accounts_db_t* parent,
                                           const sol_pubkey_t* pubkey,
                                           const sol_account_t* local_account,
                                           void* vctx) {
    accounts_lt_hash_fast_ctx_t* ctx = (accounts_lt_hash_fast_ctx_t*)vctx;
    if (!ctx || !ctx->out || !pubkey) return false;

    const sol_account_t* curr = local_account;
    sol_account_t* prev = parent ? sol_accounts_db_load(parent, pubkey) : NULL;

    if (accounts_equal_for_lt_hash(prev, curr)) {
        sol_account_destroy(prev);
        return true;
    }

    sol_lt_hash_t prev_hash;
    sol_lt_hash_t curr_hash;

    if (prev) {
        sol_account_lt_hash(pubkey, prev, &prev_hash);
    } else {
        sol_lt_hash_identity(&prev_hash);
    }

    if (curr) {
        sol_account_lt_hash(pubkey, curr, &curr_hash);
    } else {
        sol_lt_hash_identity(&curr_hash);
    }

    sol_lt_hash_mix_out(ctx->out, &prev_hash);
    sol_lt_hash_mix_in(ctx->out, &curr_hash);

    sol_account_destroy(prev);
    return true;
}

static bool
apply_local_delta_to_accounts_lt_hash(sol_accounts_db_t* parent,
                                      const sol_pubkey_t* pubkey,
                                      const sol_account_t* local_account,
                                      void* vctx) {
    accounts_lt_hash_delta_ctx_t* ctx = (accounts_lt_hash_delta_ctx_t*)vctx;
    if (!ctx || !ctx->out || !pubkey) return false;

    /* Zero-lamport accounts have identity lt_hash (sol_account_lt_hash
     * returns all-zeros when lamports==0), so keeping them here is harmless
     * but correct — they may have had non-zero lamports previously. */
    const sol_account_t* curr = local_account;

    sol_account_t* prev = parent ? sol_accounts_db_load(parent, pubkey) : NULL;

    if (accounts_equal_for_lt_hash(prev, curr)) {
        ctx->n_unchanged++;
        sol_account_destroy(prev);
        return true;
    }

    /* Categorize the change */
    if (!prev && curr)       ctx->n_created++;
    else if (prev && !curr)  ctx->n_removed++;
    else                     ctx->n_updated++;

    if (curr) {
        ctx->total_lamports_stored += curr->meta.lamports;
        ctx->total_data_len += curr->meta.data_len;
    }

    sol_lt_hash_t prev_hash;
    sol_lt_hash_t curr_hash;

    if (prev) {
        sol_account_lt_hash(pubkey, prev, &prev_hash);
    } else {
        sol_lt_hash_identity(&prev_hash);
    }

    if (curr) {
        sol_account_lt_hash(pubkey, curr, &curr_hash);
    } else {
        sol_lt_hash_identity(&curr_hash);
    }

    sol_lt_hash_mix_out(ctx->out, &prev_hash);
    sol_lt_hash_mix_in(ctx->out, &curr_hash);

    /* Track per-owner deltas for diagnostics */
    {
        const sol_pubkey_t* owner = curr ? &curr->meta.owner
                                         : (prev ? &prev->meta.owner : NULL);
        if (owner && sol_pubkey_eq(owner, &SOL_SYSVAR_PROGRAM_ID)) {
            sol_lt_hash_mix_out(&ctx->sysvar_delta, &prev_hash);
            sol_lt_hash_mix_in(&ctx->sysvar_delta, &curr_hash);
            ctx->n_sysvar++;
        } else if (owner && sol_pubkey_eq(owner, &SOL_VOTE_PROGRAM_ID)) {
            sol_lt_hash_mix_out(&ctx->vote_delta, &prev_hash);
            sol_lt_hash_mix_in(&ctx->vote_delta, &curr_hash);
            ctx->n_vote++;
        } else if (owner && sol_pubkey_eq(owner, &SOL_SYSTEM_PROGRAM_ID)) {
            sol_lt_hash_mix_out(&ctx->system_delta, &prev_hash);
            sol_lt_hash_mix_in(&ctx->system_delta, &curr_hash);
            ctx->n_system++;
        } else if (owner && sol_pubkey_eq(owner, &SOL_TOKEN_PROGRAM_ID)) {
            sol_lt_hash_mix_out(&ctx->token_delta, &prev_hash);
            sol_lt_hash_mix_in(&ctx->token_delta, &curr_hash);
            ctx->n_token++;
        } else if (owner && sol_pubkey_eq(owner, &SOL_STAKE_PROGRAM_ID)) {
            sol_lt_hash_mix_out(&ctx->stake_delta, &prev_hash);
            sol_lt_hash_mix_in(&ctx->stake_delta, &curr_hash);
            ctx->n_stake++;
        } else {
            sol_lt_hash_mix_out(&ctx->other_delta, &prev_hash);
            sol_lt_hash_mix_in(&ctx->other_delta, &curr_hash);
            ctx->n_other++;
        }
    }

    /* Dump to file if enabled */
    if (ctx->dump_fp) {
        char pk_b58[SOL_PUBKEY_BASE58_LEN] = {0};
        sol_pubkey_to_base58(pubkey, pk_b58, sizeof(pk_b58));
        char owner_b58[SOL_PUBKEY_BASE58_LEN] = {0};
        if (curr) {
            sol_pubkey_to_base58(&curr->meta.owner, owner_b58, sizeof(owner_b58));
        } else if (prev) {
            sol_pubkey_to_base58(&prev->meta.owner, owner_b58, sizeof(owner_b58));
        }
        /* Compute SHA256 of curr data for content verification */
        char data_hash_hex[17] = {0};
        if (curr && curr->data && curr->meta.data_len > 0) {
            sol_sha256_t dh;
            sol_sha256(curr->data, curr->meta.data_len, &dh);
            for (int hi = 0; hi < 8; hi++)
                snprintf(data_hash_hex + hi*2, 3, "%02x", dh.bytes[hi]);
        } else {
            snprintf(data_hash_hex, sizeof(data_hash_hex), "0000000000000000");
        }
        /* Hex-encode first 16 bytes of curr and prev BLAKE3 lt_hash */
        char curr_lth[33] = {0};
        char prev_lth[33] = {0};
        for (int hi = 0; hi < 16; hi++) {
            snprintf(curr_lth + hi*2, 3, "%02x", ((const uint8_t*)curr_hash.v)[hi]);
            snprintf(prev_lth + hi*2, 3, "%02x", ((const uint8_t*)prev_hash.v)[hi]);
        }
        /* Hex-encode first 8 bytes of prev data SHA256 */
        char prev_data_hash_hex[17] = {0};
        if (prev && prev->data && prev->meta.data_len > 0) {
            sol_sha256_t pdh;
            sol_sha256(prev->data, prev->meta.data_len, &pdh);
            for (int hi = 0; hi < 8; hi++)
                snprintf(prev_data_hash_hex + hi*2, 3, "%02x", pdh.bytes[hi]);
        } else {
            snprintf(prev_data_hash_hex, sizeof(prev_data_hash_hex), "0000000000000000");
        }
        char prev_owner_b58[SOL_PUBKEY_BASE58_LEN] = {0};
        if (prev) {
            sol_pubkey_to_base58(&prev->meta.owner, prev_owner_b58, sizeof(prev_owner_b58));
        }
        fprintf(ctx->dump_fp, "%s\t%lu\t%lu\t%lu\t%lu\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%d\n",
                pk_b58,
                (unsigned long)(prev ? prev->meta.lamports : 0),
                (unsigned long)(curr ? curr->meta.lamports : 0),
                (unsigned long)(prev ? prev->meta.data_len : 0),
                (unsigned long)(curr ? curr->meta.data_len : 0),
                owner_b58[0] ? owner_b58 : "-",
                !prev ? "created" : !curr ? "removed" : "updated",
                curr ? (int)curr->meta.executable : 0,
                data_hash_hex,
                curr_lth,
                prev_lth,
                prev_data_hash_hex,
                prev_owner_b58[0] ? prev_owner_b58 : "-",
                prev ? (int)prev->meta.executable : 0);

        /* Write full per-account lt_hash to binary file:
           [pubkey(32) + prev_hash(2048) + curr_hash(2048)] per record */
        if (ctx->dump_bin_fp) {
            fwrite(pubkey->bytes, 1, 32, ctx->dump_bin_fp);
            fwrite(prev_hash.v, 1, SOL_LT_HASH_SIZE_BYTES, ctx->dump_bin_fp);
            fwrite(curr_hash.v, 1, SOL_LT_HASH_SIZE_BYTES, ctx->dump_bin_fp);
        }

        /* Dump raw account data to binary files for comparison */
        const char* dump_env = getenv("SOL_DUMP_DELTA_ACCOUNTS");
        if (dump_env && dump_env[0]) {
            const sol_pubkey_t* acct_owner = curr ? &curr->meta.owner
                                                  : (prev ? &prev->meta.owner : NULL);
            bool is_sysvar = acct_owner && sol_pubkey_eq(acct_owner, &SOL_SYSVAR_PROGRAM_ID);
            bool is_vote = acct_owner && sol_pubkey_eq(acct_owner, &SOL_VOTE_PROGRAM_ID);

            {
                const char* prefix = is_sysvar ? "solanac_sysvar"
                                   : is_vote   ? "solanac_vote"
                                               : "solanac_acct";
                if (curr && curr->data && curr->meta.data_len > 0) {
                    char apath[512];
                    snprintf(apath, sizeof(apath), "%s/%s_%lu_%s.bin",
                             dump_env, prefix, (unsigned long)ctx->slot, pk_b58);
                    FILE* afp = fopen(apath, "wb");
                    if (afp) {
                        fwrite(curr->data, 1, (size_t)curr->meta.data_len, afp);
                        fclose(afp);
                    }
                }
                if (prev && prev->data && prev->meta.data_len > 0) {
                    char apath[512];
                    snprintf(apath, sizeof(apath), "%s/%s_prev_%lu_%s.bin",
                             dump_env, prefix, (unsigned long)ctx->slot, pk_b58);
                    FILE* afp = fopen(apath, "wb");
                    if (afp) {
                        fwrite(prev->data, 1, (size_t)prev->meta.data_len, afp);
                        fclose(afp);
                    }
                }
            }
        }
    }

    sol_account_destroy(prev);
    return true;
}

static void
tx_pool_run_lthash_delta(sol_accounts_db_t* parent,
                         const sol_accounts_db_local_entry_t* entries,
                         size_t count,
                         sol_lt_hash_t* out_delta);

static void
bank_compute_accounts_lt_hash_locked(sol_bank_t* bank) {
    if (!bank || !bank->accounts_db) return;
    if (bank->accounts_lt_hash_computed) return;

    const bool timing = bank_lt_hash_timing_enable();
    uint64_t t0_ns = 0;
    if (timing) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        t0_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    }

    const char* timing_method = "none";
    size_t timing_local_entries = 0;

    sol_lt_hash_t lt;
    sol_lt_hash_identity(&lt);

    if (sol_accounts_db_is_overlay(bank->accounts_db) && bank->accounts_lt_hash_base_valid) {
        lt = bank->accounts_lt_hash_base;

        /* Optionally dump delta accounts to a TSV file for debugging */
        const char* dump_dir = getenv("SOL_DUMP_DELTA_ACCOUNTS");
        const char* dump_slot_str = getenv("SOL_DUMP_DELTA_SLOT");
        uint64_t dump_slot = dump_slot_str ? strtoull(dump_slot_str, NULL, 10) : 0;
        bool should_dump = dump_dir && dump_dir[0] && (!dump_slot || bank->slot == dump_slot);
        if (!should_dump && !bank_lt_hash_diag_enable()) {
            /* Freeze-time fast path: avoid cloning local overlay accounts when
             * computing the lt-hash delta. This is safe only once the bank is
             * frozen (no further overlay mutations). */
            if (__atomic_load_n(&bank->frozen, __ATOMIC_ACQUIRE)) {
                sol_accounts_db_local_snapshot_view_t snap = {0};
                sol_err_t err = sol_accounts_db_snapshot_local_view_immutable(bank->accounts_db, &snap);
                if (err == SOL_OK) {
                    sol_lt_hash_t delta;
                    tx_pool_run_lthash_delta(snap.parent, snap.entries, snap.len, &delta);
                    sol_lt_hash_mix_in(&lt, &delta);
                    timing_method = "delta_view";
                    timing_local_entries = snap.len;
                    sol_accounts_db_local_snapshot_view_free(&snap);
                } else {
                    /* Fall back to the clone-based snapshot on failure. */
                    sol_accounts_db_local_snapshot_t cloned = {0};
                    sol_err_t cerr = sol_accounts_db_snapshot_local(bank->accounts_db, &cloned);
                    if (cerr == SOL_OK) {
                        sol_lt_hash_t delta;
                        tx_pool_run_lthash_delta(cloned.parent, cloned.entries, cloned.len, &delta);
                        sol_lt_hash_mix_in(&lt, &delta);
                        timing_method = "delta_clone_fallback";
                        timing_local_entries = cloned.len;
                        sol_accounts_db_local_snapshot_free(&cloned);
                    } else {
                        /* Fallback to a full recompute over the merged view. */
                        sol_lt_hash_identity(&lt);
                        sol_accounts_db_iterate(bank->accounts_db, mix_account_into_accounts_lt_hash, &lt);
                        timing_method = "full_recompute_fallback";
                    }
                }
            } else {
                sol_accounts_db_local_snapshot_t snap = {0};
                sol_err_t err = sol_accounts_db_snapshot_local(bank->accounts_db, &snap);
                if (err == SOL_OK) {
                    sol_lt_hash_t delta;
                    tx_pool_run_lthash_delta(snap.parent, snap.entries, snap.len, &delta);
                    sol_lt_hash_mix_in(&lt, &delta);
                    timing_method = "delta_clone";
                    timing_local_entries = snap.len;
                    sol_accounts_db_local_snapshot_free(&snap);
                } else {
                    /* Fallback to a full recompute over the merged view. */
                    sol_lt_hash_identity(&lt);
                    sol_accounts_db_iterate(bank->accounts_db, mix_account_into_accounts_lt_hash, &lt);
                    timing_method = "full_recompute_fallback";
                }
            }
        } else {
            accounts_lt_hash_delta_ctx_t ctx = {.out = &lt, .slot = bank->slot};

            if (should_dump) {
                char path[512];
                snprintf(path, sizeof(path), "%s/delta_accounts.%lu.tsv",
                         dump_dir, (unsigned long)bank->slot);
                ctx.dump_fp = fopen(path, "w");
            if (ctx.dump_fp) {
                fprintf(ctx.dump_fp, "pubkey\tprev_lamports\tcurr_lamports\tprev_data_len\tcurr_data_len\towner\ttype\texecutable\tdata_hash\tcurr_lthash\tprev_lthash\tprev_data_hash\tprev_owner\tprev_executable\n");
            }
            /* Open binary file for full per-account lt_hash records */
            char binpath2[512];
            snprintf(binpath2, sizeof(binpath2), "%s/delta_lthash.%lu.bin",
                     dump_dir, (unsigned long)bank->slot);
                ctx.dump_bin_fp = fopen(binpath2, "wb");
            }

            sol_err_t err = sol_accounts_db_iterate_local(
                bank->accounts_db, apply_local_delta_to_accounts_lt_hash, &ctx);

            if (ctx.dump_fp) fclose(ctx.dump_fp);
            if (ctx.dump_bin_fp) fclose(ctx.dump_bin_fp);

            if (err != SOL_OK) {
                /* Fallback to a full recompute over the merged view. */
                sol_lt_hash_identity(&lt);
                sol_accounts_db_iterate(bank->accounts_db, mix_account_into_accounts_lt_hash, &lt);
                timing_method = "full_recompute_fallback";
            } else {
                timing_method = "delta_iterate_local";
            }
            timing_local_entries = (size_t)(ctx.n_updated + ctx.n_created + ctx.n_removed + ctx.n_unchanged);

            /* Dump binary lt_hash files for debugging */
            if (should_dump) {
                char binpath[512];

            /* Base lt_hash */
            snprintf(binpath, sizeof(binpath), "%s/lt_hash_base.%lu.bin",
                     dump_dir, (unsigned long)bank->slot);
            FILE* bfp = fopen(binpath, "wb");
            if (bfp) {
                fwrite(bank->accounts_lt_hash_base.v, 1, SOL_LT_HASH_SIZE_BYTES, bfp);
                fclose(bfp);
            }

            /* Final lt_hash (after deltas) */
            snprintf(binpath, sizeof(binpath), "%s/lt_hash_final.%lu.bin",
                     dump_dir, (unsigned long)bank->slot);
            bfp = fopen(binpath, "wb");
            if (bfp) {
                fwrite(lt.v, 1, SOL_LT_HASH_SIZE_BYTES, bfp);
                fclose(bfp);
            }

            /* Verify: log checksums of both */
            sol_blake3_t base_cksum, final_cksum;
            sol_lt_hash_checksum(&bank->accounts_lt_hash_base, &base_cksum);
            sol_lt_hash_checksum(&lt, &final_cksum);
            char base_b58[64], final_b58[64];
            sol_pubkey_to_base58((const sol_pubkey_t*)&base_cksum, base_b58, sizeof(base_b58));
            sol_pubkey_to_base58((const sol_pubkey_t*)&final_cksum, final_b58, sizeof(final_b58));
            if (bank_lt_hash_diag_enable()) {
                sol_log_info("lt_hash dump: slot=%lu base_checksum=%s final_checksum=%s",
                             (unsigned long)bank->slot, base_b58, final_b58);
            }
        }

            if (bank_lt_hash_diag_enable()) {
                sol_log_info("lt_hash delta: slot=%lu updated=%lu created=%lu removed=%lu unchanged=%lu lamports_stored=%lu data_len=%lu",
                             (unsigned long)bank->slot,
                             (unsigned long)ctx.n_updated,
                             (unsigned long)ctx.n_created,
                             (unsigned long)ctx.n_removed,
                             (unsigned long)ctx.n_unchanged,
                             (unsigned long)ctx.total_lamports_stored,
                             (unsigned long)ctx.total_data_len);
            }

            /* Log sysvar-only lt_hash contribution for diagnostics */
            if (ctx.n_sysvar > 0 && bank_lt_hash_diag_enable()) {
                /* Compute sysvar-only final: base + sysvar_delta */
                sol_lt_hash_t sysvar_only_final = bank->accounts_lt_hash_base;
                sol_lt_hash_mix_in(&sysvar_only_final, &ctx.sysvar_delta);
                sol_blake3_t sysvar_cksum;
                sol_lt_hash_checksum(&sysvar_only_final, &sysvar_cksum);
                char sysvar_b58[64];
                sol_pubkey_to_base58((const sol_pubkey_t*)&sysvar_cksum, sysvar_b58, sizeof(sysvar_b58));

            /* Also compute non-sysvar delta checksum */
            sol_lt_hash_t nonsysvar_delta;
            sol_lt_hash_identity(&nonsysvar_delta);
            for (size_t i = 0; i < SOL_LT_HASH_NUM_ELEMENTS; i++) {
                /* total_delta = sysvar_delta + nonsysvar_delta
                 * where total_delta = final - base
                 * So nonsysvar_delta = (final - base) - sysvar_delta */
                uint16_t total_delta_i = (uint16_t)(lt.v[i] - bank->accounts_lt_hash_base.v[i]);
                nonsysvar_delta.v[i] = (uint16_t)(total_delta_i - ctx.sysvar_delta.v[i]);
            }
            sol_blake3_t nonsysvar_cksum;
            sol_lt_hash_checksum(&nonsysvar_delta, &nonsysvar_cksum);
            char nonsysvar_b58[64];
            sol_pubkey_to_base58((const sol_pubkey_t*)&nonsysvar_cksum, nonsysvar_b58, sizeof(nonsysvar_b58));

                sol_log_info("lt_hash sysvar_diag: slot=%lu n_sysvar=%lu sysvar_only_checksum=%s nonsysvar_delta_checksum=%s",
                             (unsigned long)bank->slot,
                             (unsigned long)ctx.n_sysvar,
                             sysvar_b58,
                             nonsysvar_b58);

                /* Per-owner delta checksums */
                {
                    sol_blake3_t ck; char b58[64];

                    sol_lt_hash_checksum(&ctx.vote_delta, &ck);
                    sol_pubkey_to_base58((const sol_pubkey_t*)&ck, b58, sizeof(b58));
                    sol_log_info("lt_hash owner_diag: slot=%lu vote n=%lu cksum=%s",
                                 (unsigned long)bank->slot, (unsigned long)ctx.n_vote, b58);

                    sol_lt_hash_checksum(&ctx.system_delta, &ck);
                    sol_pubkey_to_base58((const sol_pubkey_t*)&ck, b58, sizeof(b58));
                    sol_log_info("lt_hash owner_diag: slot=%lu system n=%lu cksum=%s",
                                 (unsigned long)bank->slot, (unsigned long)ctx.n_system, b58);

                    sol_lt_hash_checksum(&ctx.token_delta, &ck);
                    sol_pubkey_to_base58((const sol_pubkey_t*)&ck, b58, sizeof(b58));
                    sol_log_info("lt_hash owner_diag: slot=%lu token n=%lu cksum=%s",
                                 (unsigned long)bank->slot, (unsigned long)ctx.n_token, b58);

                    sol_lt_hash_checksum(&ctx.stake_delta, &ck);
                    sol_pubkey_to_base58((const sol_pubkey_t*)&ck, b58, sizeof(b58));
                    sol_log_info("lt_hash owner_diag: slot=%lu stake n=%lu cksum=%s",
                                 (unsigned long)bank->slot, (unsigned long)ctx.n_stake, b58);

                    sol_lt_hash_checksum(&ctx.other_delta, &ck);
                    sol_pubkey_to_base58((const sol_pubkey_t*)&ck, b58, sizeof(b58));
                    sol_log_info("lt_hash owner_diag: slot=%lu other n=%lu cksum=%s",
                                 (unsigned long)bank->slot, (unsigned long)ctx.n_other, b58);
                }

                /* Dump sysvar-only and nonsysvar deltas as binary files */
                if (dump_dir && dump_dir[0]) {
                    char binpath[512];
                    snprintf(binpath, sizeof(binpath), "%s/lt_hash_sysvar_delta.%lu.bin",
                             dump_dir, (unsigned long)bank->slot);
                    FILE* bfp = fopen(binpath, "wb");
                    if (bfp) {
                        fwrite(ctx.sysvar_delta.v, 1, SOL_LT_HASH_SIZE_BYTES, bfp);
                        fclose(bfp);
                    }
                    snprintf(binpath, sizeof(binpath), "%s/lt_hash_nonsysvar_delta.%lu.bin",
                             dump_dir, (unsigned long)bank->slot);
                    bfp = fopen(binpath, "wb");
                    if (bfp) {
                        fwrite(nonsysvar_delta.v, 1, SOL_LT_HASH_SIZE_BYTES, bfp);
                        fclose(bfp);
                    }

                    /* Per-owner delta binary dumps */
                    const char* owner_names[] = {"vote", "system", "token", "stake", "other"};
                    const sol_lt_hash_t* owner_ptrs[] = {
                        &ctx.vote_delta, &ctx.system_delta, &ctx.token_delta,
                        &ctx.stake_delta, &ctx.other_delta
                    };
                    for (size_t oi = 0; oi < 5; oi++) {
                        snprintf(binpath, sizeof(binpath), "%s/lt_hash_%s_delta.%lu.bin",
                                 dump_dir, owner_names[oi], (unsigned long)bank->slot);
                        bfp = fopen(binpath, "wb");
                        if (bfp) {
                            fwrite(owner_ptrs[oi]->v, 1, SOL_LT_HASH_SIZE_BYTES, bfp);
                            fclose(bfp);
                        }
                    }
                }
            }
        }
    } else {
        bool used_parallel = false;
        if (!sol_accounts_db_is_overlay(bank->accounts_db) &&
            sol_accounts_db_iterate_pubkey_range_supported(bank->accounts_db)) {
            size_t threads = bank_lt_hash_full_recompute_threads();
            if (threads > 1u) {
                const uint32_t prefixes_per_task = 4u; /* 64 tasks total */
                const uint32_t task_count = (256u + prefixes_per_task - 1u) / prefixes_per_task;

                lt_hash_full_recompute_ctx_t ctx = {
                    .db = bank->accounts_db,
                    .prefixes_per_task = prefixes_per_task,
                    .task_count = task_count,
                    .next_task = 0u,
                    .partials = sol_calloc(threads, sizeof(sol_lt_hash_t)),
                };

                if (ctx.partials) {
                    lt_hash_full_recompute_thread_arg_t* args =
                        sol_calloc(threads, sizeof(*args));
                    pthread_t* tids = sol_calloc(threads > 1u ? (threads - 1u) : 0u, sizeof(*tids));

                    if (args && (threads == 1u || tids)) {
                        /* Spawn worker threads [1..threads-1], and run worker 0 inline. */
                        for (size_t i = 0; i < threads; i++) {
                            args[i] = (lt_hash_full_recompute_thread_arg_t){
                                .ctx = &ctx,
                                .idx = i,
                            };
                        }

                        for (size_t i = 1; i < threads; i++) {
                            (void)pthread_create(&tids[i - 1u], NULL,
                                                 lt_hash_full_recompute_thread_main,
                                                 &args[i]);
                        }
                        (void)lt_hash_full_recompute_thread_main(&args[0]);

                        for (size_t i = 1; i < threads; i++) {
                            (void)pthread_join(tids[i - 1u], NULL);
                        }

                        for (size_t i = 0; i < threads; i++) {
                            sol_lt_hash_mix_in(&lt, &ctx.partials[i]);
                        }
                        used_parallel = true;
                        timing_method = "full_recompute_parallel";

                        sol_free(tids);
                        sol_free(args);
                    } else {
                        sol_free(tids);
                        sol_free(args);
                    }
                    sol_free(ctx.partials);
                }
            }
        }

        if (!used_parallel) {
            sol_accounts_db_iterate(bank->accounts_db, mix_account_into_accounts_lt_hash, &lt);
            timing_method = "full_recompute";
        }

        /* For non-overlay banks, the full recompute is the only option. For
         * overlay banks, `accounts_lt_hash_base` must represent the parent
         * bank's accounts LtHash (copied at fork creation). */
        if (!sol_accounts_db_is_overlay(bank->accounts_db)) {
            bank->accounts_lt_hash_base = lt;
            bank->accounts_lt_hash_base_valid = true;
        }
    }

    if (timing) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t t1_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
        uint64_t dt_ns = t1_ns - t0_ns;
        sol_log_info("lt_hash timing: slot=%lu method=%s local_entries=%zu dt=%.2fms",
                     (unsigned long)bank->slot,
                     timing_method ? timing_method : "-",
                     timing_local_entries,
                     (double)dt_ns / 1000000.0);
    }

    bank->accounts_lt_hash = lt;
    bank->accounts_lt_hash_computed = true;
}

sol_bank_t*
sol_bank_new(sol_slot_t slot, const sol_hash_t* parent_hash,
             sol_accounts_db_t* accounts_db, const sol_bank_config_t* config) {
    sol_bank_t* bank = sol_calloc(1, sizeof(sol_bank_t));
    if (!bank) return NULL;

    if (config) {
        bank->config = *config;
    } else {
        bank->config = (sol_bank_config_t)SOL_BANK_CONFIG_DEFAULT;
    }
    if (bank->config.hashes_per_tick == 0) {
        bank->config.hashes_per_tick = SOL_HASHES_PER_TICK;
    }

    bank->slot = slot;
    bank->parent_slot = (slot > 0) ? (slot - 1) : 0;
    bank->epoch = slot / bank->config.slots_per_epoch;

    /* Use provided accounts DB or create new one */
    if (accounts_db) {
        bank->accounts_db = accounts_db;
        bank->owns_accounts_db = false;
    } else {
        bank->accounts_db = sol_accounts_db_new(NULL);
        if (!bank->accounts_db) {
            sol_free(bank);
            return NULL;
        }
        bank->owns_accounts_db = true;
    }

    /* Derive genesis creation time from an existing Clock sysvar (snapshots). */
    sol_account_t* clock_acct = sol_accounts_db_load(bank->accounts_db, &SOL_SYSVAR_CLOCK_ID);
    if (clock_acct && clock_acct->meta.data_len >= SOL_CLOCK_SIZE) {
        sol_clock_t clock;
        sol_clock_init(&clock);
        if (sol_clock_deserialize(&clock, clock_acct->data, clock_acct->meta.data_len) == SOL_OK) {
            uint64_t ns_per_slot =
                (1000000000ULL * bank->config.ticks_per_slot) / SOL_DEFAULT_TICKS_PER_SECOND;

            uint64_t offset_ns = 0;
            if (!__builtin_mul_overflow((uint64_t)clock.slot, ns_per_slot, &offset_ns)) {
                sol_unix_timestamp_t offset_s =
                    (sol_unix_timestamp_t)(offset_ns / 1000000000ULL);

                bank->genesis_creation_time = clock.unix_timestamp - offset_s;
                bank->genesis_creation_time_set = true;
            }
        }
    }
    sol_account_destroy(clock_acct);

    bank->max_tick_height = (slot + 1) * bank->config.ticks_per_slot;
    bank->tick_height = slot * bank->config.ticks_per_slot;
    bank->hashes_in_tick = 0;

    /* Prefer restoring recent blockhash queue from sysvar (snapshots). */
    bool restored_blockhashes = false;
    if (!parent_hash) {
        restored_blockhashes = restore_recent_blockhashes_from_sysvar(bank);
    }

    /* Initialize blockhash from parent hash */
    if (!restored_blockhashes && parent_hash) {
        bank->blockhash = *parent_hash;

        /* Add parent hash to recent blockhashes */
        bank->recent_blockhashes[0].hash = *parent_hash;
        bank->recent_blockhashes[0].fee_calculator = bank->config.lamports_per_signature;
        bank->recent_blockhash_count = 1;
    }

    /* Build fast lookup for the recent blockhash queue. */
    bank_recent_blockhash_map_rebuild(bank);

    /* PoH starts from the parent blockhash (or restored latest blockhash).
     * This is distinct from the end-of-slot last entry hash. */
    bank->poh_hash = bank->blockhash;

    if (pthread_mutex_init(&bank->lock, NULL) != 0) {
        if (bank->recent_blockhash_map) {
            sol_map_destroy(bank->recent_blockhash_map);
            bank->recent_blockhash_map = NULL;
        }
        if (bank->owns_accounts_db) {
            sol_accounts_db_destroy(bank->accounts_db);
        }
        sol_free(bank);
        return NULL;
    }
    if (pthread_mutex_init(&bank->tx_status_lock, NULL) != 0) {
        if (bank->recent_blockhash_map) {
            sol_map_destroy(bank->recent_blockhash_map);
            bank->recent_blockhash_map = NULL;
        }
        pthread_mutex_destroy(&bank->lock);
        if (bank->owns_accounts_db) {
            sol_accounts_db_destroy(bank->accounts_db);
        }
        sol_free(bank);
        return NULL;
    }

    bank_alt_cache_init(bank);

    if (refresh_sysvar_accounts(bank, false) != SOL_OK) {
        if (bank->recent_blockhash_map) {
            sol_map_destroy(bank->recent_blockhash_map);
            bank->recent_blockhash_map = NULL;
        }
        bank_alt_cache_destroy(bank);
        pthread_mutex_destroy(&bank->tx_status_lock);
        pthread_mutex_destroy(&bank->lock);
        if (bank->owns_accounts_db) {
            sol_accounts_db_destroy(bank->accounts_db);
        }
        sol_free(bank);
        return NULL;
    }

    return bank;
}

sol_bank_t*
sol_bank_new_from_parent(sol_bank_t* parent, sol_slot_t slot) {
    if (!parent) return NULL;

    uint64_t t_total0 = bank_monotonic_ns();
    uint64_t phase_fork_ns = 0;
    uint64_t phase_new_ns = 0;
    uint64_t phase_parent_hash_ns = 0;
    uint64_t phase_copy_ns = 0;
    uint64_t phase_sysvar_ns = 0;

    /* Create child bank with a forked AccountsDB view */
    uint64_t t0 = bank_monotonic_ns();
    sol_accounts_db_t* forked_db = sol_accounts_db_fork(parent->accounts_db);
    phase_fork_ns = bank_monotonic_ns() - t0;
    if (!forked_db) return NULL;

    t0 = bank_monotonic_ns();
    sol_bank_t* child = sol_bank_new(slot, &parent->blockhash,
                                     forked_db, &parent->config);
    phase_new_ns = bank_monotonic_ns() - t0;
    if (!child) {
        sol_accounts_db_destroy(forked_db);
        return NULL;
    }
    child->owns_accounts_db = true;

    /* Wire parent bank hash for voting/bank-hash computation. Parent is expected
     * to be frozen when used as an ancestor for replay.
     *
     * Fast path: freeze() precomputes and publishes bank_hash for frozen banks,
     * so child creation can copy it under parent lock without triggering an
     * expensive hash compute in the bank_new path. */
    t0 = bank_monotonic_ns();
    bool parent_hash_ready = false;
    pthread_mutex_lock(&parent->lock);
    if (parent->hash_computed) {
        child->parent_hash = parent->bank_hash;
        parent_hash_ready = true;
    }
    pthread_mutex_unlock(&parent->lock);
    if (!parent_hash_ready) {
        sol_bank_compute_hash(parent, &child->parent_hash);
    }
    phase_parent_hash_ns = bank_monotonic_ns() - t0;
    child->parent_slot = parent->slot;

    /* Ticks can be "caught up" when intermediate slots are skipped. In that
     * case, the child slot's entry stream may contain multiple slots worth of
     * ticks and we must start tick accounting from the parent's tick height.
     *
     * If we instead assume tick_height == slot * ticks_per_slot, the bank will
     * reach max_tick_height too early, overflow subsequent ticks, and fail to
     * update the final blockhash for the slot. That breaks PoH start hash
     * validation for the next slot (replay stalls with "Entry hash chain
     * mismatch at start"). */
    {
        uint64_t parent_tick_height = 0;
        pthread_mutex_lock(&parent->lock);
        parent_tick_height = parent->tick_height;
        pthread_mutex_unlock(&parent->lock);

        child->tick_height = parent_tick_height;

        uint64_t delta_slots = 0;
        if (slot > parent->slot) {
            delta_slots = (uint64_t)(slot - parent->slot);
        } else {
            /* Defensive: ensure we don't underflow when given an unexpected
             * slot ordering. Keep the default tick ranges in that case. */
            delta_slots = 1;
        }

        uint64_t ticks_per_slot = (uint64_t)child->config.ticks_per_slot;
        if (ticks_per_slot == 0) {
            ticks_per_slot = 64u;
        }

        uint64_t max_tick = 0;
        if (__builtin_mul_overflow(delta_slots, ticks_per_slot, &max_tick) ||
            __builtin_add_overflow(parent_tick_height, max_tick, &max_tick) ||
            max_tick < parent_tick_height) {
            /* Fallback: use the legacy absolute calculation. */
            child->max_tick_height =
                (uint64_t)(slot + 1u) * (uint64_t)child->config.ticks_per_slot;
        } else {
            child->max_tick_height = max_tick;
        }
    }

    /* Set zombie filter to the parent slot.  Zero-lamport accounts stored
     * at or before the parent slot are treated as non-existent (matching
     * Agave's is_loadable() which returns false for all 0-lamport accounts).
     * Accounts stored in the current (child) slot are NOT filtered, since
     * they may have been modified within the same slot's transaction batch. */
    child->zombie_filter_slot = parent->slot;

    /* Copy genesis hash from parent */
    if (parent->genesis_hash_set) {
        child->genesis_hash = parent->genesis_hash;
        child->genesis_hash_set = true;
    }

    /* Copy recent blockhashes from parent */
    t0 = bank_monotonic_ns();
    pthread_mutex_lock(&parent->lock);

    size_t copy_count = parent->recent_blockhash_count;
    if (copy_count > MAX_RECENT_BLOCKHASHES) {
        copy_count = MAX_RECENT_BLOCKHASHES;
    }

    /* Signature count is per-bank (used in the frozen bank-hash). Start each
     * derived bank at 0 and increment as transactions are executed in this
     * slot. */
    child->signature_count = 0;

    /* Seed the overlay bank with the parent accounts LtHash so bank hashing can
     * efficiently apply local deltas instead of recomputing over the full
     * merged view. */
    child->accounts_lt_hash_base = parent->accounts_lt_hash;
    child->accounts_lt_hash_base_valid = parent->accounts_lt_hash_computed;

    /* Copy directly (child starts with same queue as parent) */
    for (size_t i = 0; i < copy_count; i++) {
        child->recent_blockhashes[i] = parent->recent_blockhashes[i];
    }
    child->recent_blockhash_count = copy_count;

    /* Seed child sysvar caches from parent to avoid cold AccountsDB loads in
     * the new_from_parent() hot path. */
    if (parent->cached_clock_valid) {
        child->cached_clock = parent->cached_clock;
        child->cached_clock_valid = true;
    }
    if (parent->cached_slot_hashes_valid) {
        child->cached_slot_hashes = parent->cached_slot_hashes;
        child->cached_slot_hashes_valid = true;
    }

    pthread_mutex_unlock(&parent->lock);

    bank_recent_blockhash_map_rebuild(child);
    phase_copy_ns = bank_monotonic_ns() - t0;

    /* Sysvars like Clock/SlotHashes must advance for each derived bank.
     * Do this after wiring parent hash so SlotHashes can include parent bank
     * hash immediately (needed for vote verification). */
    t0 = bank_monotonic_ns();
    if (refresh_sysvar_accounts(child, true) != SOL_OK) {
        sol_bank_destroy(child);
        return NULL;
    }
    phase_sysvar_ns = bank_monotonic_ns() - t0;

    uint64_t total_ns = bank_monotonic_ns() - t_total0;
    if (total_ns >= 1000000000ull) {
        sol_log_info("bank_new_slow: slot=%lu parent=%lu total=%.2fms fork=%.2fms new=%.2fms parent_hash=%.2fms copy=%.2fms sysvar=%.2fms",
                     (unsigned long)slot,
                     (unsigned long)parent->slot,
                     (double)total_ns / 1000000.0,
                     (double)phase_fork_ns / 1000000.0,
                     (double)phase_new_ns / 1000000.0,
                     (double)phase_parent_hash_ns / 1000000.0,
                     (double)phase_copy_ns / 1000000.0,
                     (double)phase_sysvar_ns / 1000000.0);
    }

    return child;
}

void
sol_bank_destroy(sol_bank_t* bank) {
    if (!bank) return;

    /* Free transaction status cache */
    for (size_t i = 0; i < TX_STATUS_HASH_SIZE; i++) {
        sol_tx_status_node_t* node = bank->tx_status_buckets[i];
        while (node) {
            sol_tx_status_node_t* next = node->next;
            sol_free(node);
            node = next;
        }
    }

    if (bank->owns_accounts_db) {
        sol_accounts_db_destroy(bank->accounts_db);
    }

    if (bank->recent_blockhash_map) {
        sol_map_destroy(bank->recent_blockhash_map);
        bank->recent_blockhash_map = NULL;
    }

    bank_alt_cache_destroy(bank);
    pthread_mutex_destroy(&bank->tx_status_lock);
    pthread_mutex_destroy(&bank->lock);
    sol_free(bank);
}

sol_slot_t
sol_bank_slot(const sol_bank_t* bank) {
    return bank ? bank->slot : 0;
}

sol_slot_t
sol_bank_parent_slot(const sol_bank_t* bank) {
    return bank ? bank->parent_slot : 0;
}

void
sol_bank_set_parent_slot(sol_bank_t* bank, sol_slot_t parent_slot) {
    if (!bank) return;

    pthread_mutex_lock(&bank->lock);
    bank->parent_slot = parent_slot;
    pthread_mutex_unlock(&bank->lock);
}

uint64_t
sol_bank_epoch(const sol_bank_t* bank) {
    return bank ? bank->epoch : 0;
}

uint64_t
sol_bank_slots_per_epoch(const sol_bank_t* bank) {
    return bank ? bank->config.slots_per_epoch : 0;
}

uint64_t
sol_bank_lamports_per_signature(const sol_bank_t* bank) {
    return bank ? bank->config.lamports_per_signature : 5000;
}

void
sol_bank_set_fee_collector(sol_bank_t* bank, const sol_pubkey_t* collector) {
    if (!bank) return;

    pthread_mutex_lock(&bank->lock);
    if (collector) {
        bank->fee_collector = *collector;
        bank->fee_collector_set = !sol_pubkey_is_zero(collector);
    } else {
        memset(bank->fee_collector.bytes, 0, SOL_PUBKEY_SIZE);
        bank->fee_collector_set = false;
    }
    pthread_mutex_unlock(&bank->lock);
}

const sol_pubkey_t*
sol_bank_fee_collector(const sol_bank_t* bank) {
    if (!bank || !bank->fee_collector_set) return NULL;
    return &bank->fee_collector;
}

const sol_hash_t*
sol_bank_parent_hash(const sol_bank_t* bank) {
    return bank ? &bank->parent_hash : NULL;
}

void
sol_bank_set_parent_bank_hash(sol_bank_t* bank, const sol_hash_t* parent_bank_hash) {
    if (!bank || !parent_bank_hash) return;

    pthread_mutex_lock(&bank->lock);
    bank->parent_hash = *parent_bank_hash;
    bank->hash_computed = false;
    bank->accounts_delta_hash_computed = false;
    pthread_mutex_unlock(&bank->lock);
}

const sol_hash_t*
sol_bank_blockhash(const sol_bank_t* bank) {
    return bank ? &bank->blockhash : NULL;
}

void
sol_bank_set_blockhash(sol_bank_t* bank, const sol_hash_t* blockhash) {
    if (!bank || !blockhash) return;

    pthread_mutex_lock(&bank->lock);

    bank->blockhash = *blockhash;
    bank->poh_hash = *blockhash;
    bank->hashes_in_tick = 0;

    /* Ensure the recent blockhash queue contains this hash at the front.
     * Snapshot loading may have already restored a full queue from sysvars;
     * avoid clobbering it. */
    if (bank->recent_blockhash_count == 0) {
        bank->recent_blockhashes[0].hash = *blockhash;
        bank->recent_blockhashes[0].fee_calculator = bank->config.lamports_per_signature;
        bank->recent_blockhashes[0].timestamp = 0;
        bank->recent_blockhash_count = 1;
    } else if (memcmp(bank->recent_blockhashes[0].hash.bytes, blockhash->bytes, SOL_HASH_SIZE) != 0) {
        size_t existing = SIZE_MAX;
        for (size_t i = 1; i < bank->recent_blockhash_count; i++) {
            if (memcmp(bank->recent_blockhashes[i].hash.bytes, blockhash->bytes, SOL_HASH_SIZE) == 0) {
                existing = i;
                break;
            }
        }

        if (existing != SIZE_MAX) {
            sol_blockhash_entry_t entry = bank->recent_blockhashes[existing];
            memmove(&bank->recent_blockhashes[1],
                    &bank->recent_blockhashes[0],
                    existing * sizeof(sol_blockhash_entry_t));
            bank->recent_blockhashes[0] = entry;
        } else {
            if (bank->recent_blockhash_count >= MAX_RECENT_BLOCKHASHES) {
                memmove(&bank->recent_blockhashes[1],
                        &bank->recent_blockhashes[0],
                        (MAX_RECENT_BLOCKHASHES - 1) * sizeof(sol_blockhash_entry_t));
                bank->recent_blockhash_count = MAX_RECENT_BLOCKHASHES;
            } else {
                memmove(&bank->recent_blockhashes[1],
                        &bank->recent_blockhashes[0],
                        bank->recent_blockhash_count * sizeof(sol_blockhash_entry_t));
                bank->recent_blockhash_count++;
            }

            bank->recent_blockhashes[0].hash = *blockhash;
            bank->recent_blockhashes[0].fee_calculator = bank->config.lamports_per_signature;
            bank->recent_blockhashes[0].timestamp = 0;
        }
    }

    bank_recent_blockhash_map_rebuild(bank);

    bank->hash_computed = false;
    bank->accounts_delta_hash_computed = false;

    pthread_mutex_unlock(&bank->lock);
}

sol_err_t
sol_bank_set_recent_blockhash_queue(sol_bank_t* bank,
                                    const sol_hash_t* hashes,
                                    const uint64_t* lamports_per_signature,
                                    size_t count) {
    if (!bank || !hashes || !lamports_per_signature || count == 0) {
        return SOL_ERR_INVAL;
    }

    if (count > MAX_RECENT_BLOCKHASHES) {
        count = MAX_RECENT_BLOCKHASHES;
    }

    pthread_mutex_lock(&bank->lock);

    for (size_t i = 0; i < count; i++) {
        bank->recent_blockhashes[i].hash = hashes[i];
        uint64_t fee = lamports_per_signature[i];
        bank->recent_blockhashes[i].fee_calculator =
            (fee != 0) ? fee : bank->config.lamports_per_signature;
        bank->recent_blockhashes[i].timestamp = 0;
    }
    bank->recent_blockhash_count = count;

    /* Keep bank->blockhash consistent with the most recent queue entry. */
    bank->blockhash = bank->recent_blockhashes[0].hash;
    bank->poh_hash = bank->blockhash;
    bank->hashes_in_tick = 0;

    bank_recent_blockhash_map_rebuild(bank);

    bank->hash_computed = false;
    bank->accounts_delta_hash_computed = false;

    pthread_mutex_unlock(&bank->lock);
    return SOL_OK;
}

void
sol_bank_set_bank_hash(sol_bank_t* bank, const sol_hash_t* bank_hash) {
    if (!bank || !bank_hash) return;

    pthread_mutex_lock(&bank->lock);
    bank->bank_hash = *bank_hash;
    bank->hash_computed = true;
    memset(bank->accounts_delta_hash.bytes, 0, sizeof(bank->accounts_delta_hash.bytes));
    bank->accounts_delta_hash_computed = false;
    pthread_mutex_unlock(&bank->lock);
}

void
sol_bank_set_accounts_lt_hash(sol_bank_t* bank, const sol_lt_hash_t* accounts_lt_hash) {
    if (!bank || !accounts_lt_hash) return;

    pthread_mutex_lock(&bank->lock);

    bank->accounts_lt_hash = *accounts_lt_hash;
    bank->accounts_lt_hash_computed = true;

    if (!sol_accounts_db_is_overlay(bank->accounts_db)) {
        bank->accounts_lt_hash_base = *accounts_lt_hash;
        bank->accounts_lt_hash_base_valid = true;
    }

    pthread_mutex_unlock(&bank->lock);
}

bool
sol_bank_apply_accounts_lt_hash_delta(sol_bank_t* bank,
                                      const sol_pubkey_t* pubkey,
                                      const sol_account_t* prev,
                                      const sol_account_t* curr) {
    if (!bank || !pubkey) return false;

    sol_lt_hash_t prev_hash;
    sol_lt_hash_t curr_hash;
    sol_lt_hash_identity(&prev_hash);
    sol_lt_hash_identity(&curr_hash);

    if (prev) {
        sol_account_lt_hash(pubkey, prev, &prev_hash);
    }
    if (curr) {
        sol_account_lt_hash(pubkey, curr, &curr_hash);
    }

    if (memcmp(prev_hash.v, curr_hash.v, sizeof(prev_hash.v)) == 0) {
        return true;
    }

    pthread_mutex_lock(&bank->lock);
    if (!bank->accounts_lt_hash_computed) {
        pthread_mutex_unlock(&bank->lock);
        return false;
    }

    sol_lt_hash_mix_out(&bank->accounts_lt_hash, &prev_hash);
    sol_lt_hash_mix_in(&bank->accounts_lt_hash, &curr_hash);

    if (!sol_accounts_db_is_overlay(bank->accounts_db) && bank->accounts_lt_hash_base_valid) {
        sol_lt_hash_mix_out(&bank->accounts_lt_hash_base, &prev_hash);
        sol_lt_hash_mix_in(&bank->accounts_lt_hash_base, &curr_hash);
    }

    /* Bank hash depends on accounts_lt_hash; force recomputation. */
    bank->hash_computed = false;
    bank->accounts_delta_hash_computed = false;

    pthread_mutex_unlock(&bank->lock);
    return true;
}

void
sol_bank_accounts_lt_hash_checksum(sol_bank_t* bank, sol_blake3_t* out_checksum) {
    if (!bank || !out_checksum) return;

    pthread_mutex_lock(&bank->lock);
    bank_compute_accounts_lt_hash_locked(bank);
    sol_lt_hash_checksum(&bank->accounts_lt_hash, out_checksum);
    pthread_mutex_unlock(&bank->lock);
}

bool
sol_bank_get_accounts_lt_hash(sol_bank_t* bank, sol_lt_hash_t* out_lt_hash) {
    if (!bank || !out_lt_hash) return false;

    pthread_mutex_lock(&bank->lock);
    bank_compute_accounts_lt_hash_locked(bank);
    *out_lt_hash = bank->accounts_lt_hash;
    pthread_mutex_unlock(&bank->lock);
    return true;
}

const sol_hash_t*
sol_bank_genesis_hash(const sol_bank_t* bank) {
    if (!bank || !bank->genesis_hash_set) return NULL;
    return &bank->genesis_hash;
}

void
sol_bank_set_genesis_hash(sol_bank_t* bank, const sol_hash_t* genesis_hash) {
    if (!bank || !genesis_hash) return;
    memcpy(&bank->genesis_hash, genesis_hash, sizeof(sol_hash_t));
    bank->genesis_hash_set = true;
}

uint64_t
sol_bank_signature_count(const sol_bank_t* bank) {
    if (!bank) return 0;
    return __atomic_load_n(&bank->signature_count, __ATOMIC_RELAXED);
}

void
sol_bank_set_signature_count(sol_bank_t* bank, uint64_t signature_count) {
    if (!bank) return;
    __atomic_store_n(&bank->signature_count, signature_count, __ATOMIC_RELAXED);
    BANK_FLAG_CLEAR(bank, hash_computed);
    BANK_FLAG_CLEAR(bank, accounts_delta_hash_computed);
}

uint64_t
sol_bank_tick_height(const sol_bank_t* bank) {
    return bank ? bank->tick_height : 0;
}

uint64_t
sol_bank_max_tick_height(const sol_bank_t* bank) {
    return bank ? bank->max_tick_height : 0;
}

bool
sol_bank_has_full_ticks(const sol_bank_t* bank) {
    if (!bank) return false;

    pthread_mutex_lock((pthread_mutex_t*)&bank->lock);
    bool full = (bank->tick_height == bank->max_tick_height);
    pthread_mutex_unlock((pthread_mutex_t*)&bank->lock);

    return full;
}

/* Per-thread override for transaction-local Instructions sysvar.
 *
 * Agave exposes the Instructions sysvar via AccountOverrides (virtual account)
 * so it never becomes shared mutable global state. We use a TLS override to
 * make parallel transaction execution safe and cheap. */
static __thread sol_account_t* g_tls_instructions_sysvar = NULL;

/* Cache of "previous visible meta" for accounts loaded during a transaction.
 * This is used to avoid an extra parent meta lookup during the first store to a
 * pubkey in an overlay bank (which otherwise hits RocksDB+AppendVec again). */
typedef struct {
    uint64_t lamports;
    uint64_t data_len;
} bank_prev_meta_hint_t;

static __thread sol_pubkey_map_t* g_tls_prev_meta_hints = NULL;

static inline void
bank_prev_meta_hints_reset(void) {
    if (g_tls_prev_meta_hints && g_tls_prev_meta_hints->inner) {
        sol_map_clear(g_tls_prev_meta_hints->inner);
    }
}

static inline void
bank_prev_meta_hints_record(const sol_pubkey_t* pubkey, const sol_account_t* account) {
    if (!pubkey || !account) return;
    if (!g_tls_prev_meta_hints) {
        g_tls_prev_meta_hints = sol_pubkey_map_new(sizeof(bank_prev_meta_hint_t), 256u);
        if (!g_tls_prev_meta_hints) return;
    }
    bank_prev_meta_hint_t hint = {
        .lamports = account->meta.lamports,
        .data_len = account->meta.data_len,
    };
    (void)sol_pubkey_map_insert(g_tls_prev_meta_hints, pubkey, &hint);
}

static inline bool
bank_prev_meta_hints_get(const sol_pubkey_t* pubkey, bank_prev_meta_hint_t* out) {
    if (out) {
        out->lamports = 0;
        out->data_len = 0;
    }
    if (!pubkey || !out || !g_tls_prev_meta_hints) return false;
    bank_prev_meta_hint_t* hint =
        (bank_prev_meta_hint_t*)sol_pubkey_map_get(g_tls_prev_meta_hints, pubkey);
    if (!hint) return false;
    *out = *hint;
    return true;
}

/* Transaction-local undo log.
 *
 * This codebase historically implemented rollback by pre-snapshotting every
 * writable account in the message before execution. That is correct but very
 * expensive. Instead, record the pre-state lazily on first write and rollback
 * by restoring only the touched accounts. */
typedef enum {
    BANK_TX_UNDO_KIND_MISSING = 0,
    BANK_TX_UNDO_KIND_TOMBSTONE = 1,
    BANK_TX_UNDO_KIND_ACCOUNT = 2,
} bank_tx_undo_kind_t;

typedef struct {
    sol_pubkey_t         key;
    bank_tx_undo_kind_t  kind;
    sol_account_t*       account; /* clone when kind==ACCOUNT */
    /* Post-state meta for rent-state transition checks. Updated on every store/delete
     * during an active tx undo scope so we don't re-load accounts from AccountsDB. */
    uint64_t             post_lamports;
    size_t               post_data_len;
    sol_pubkey_t         post_owner;
    uint8_t              post_executable;
    uint8_t              post_valid;
} bank_tx_undo_entry_t;

typedef struct {
    bool                active;
    bool                overlay;
    size_t              len;
    size_t              cap;
    bank_tx_undo_entry_t* entries;
} bank_tx_undo_log_t;

static __thread bank_tx_undo_log_t g_tls_tx_undo = {0};

typedef struct {
    sol_account_t* view; /* Owned cache entry; view->data may be borrowed */
    sol_slot_t     stored_slot;
    uint8_t        has_stored_slot;
} bank_tx_view_cache_entry_t;

static __thread sol_pubkey_map_t* g_tls_tx_view_cache = NULL;

static inline bool
bank_tx_view_cache_is_active(void) {
    return g_tls_tx_undo.active;
}

static inline sol_account_t*
bank_tx_view_cache_make_view(const sol_account_t* src) {
    if (!src) return NULL;
    sol_account_t* v = sol_calloc(1u, sizeof(*v));
    if (!v) return NULL;
    v->meta = src->meta;
    v->data = src->data;
    v->data_borrowed = true;
    return v;
}

static inline void
bank_tx_view_cache_reset(void) {
    if (!g_tls_tx_view_cache || !g_tls_tx_view_cache->inner) return;

    void* key = NULL;
    void* val = NULL;
    sol_map_iter_t it = sol_map_iter(g_tls_tx_view_cache->inner);
    while (sol_map_iter_next(&it, &key, &val)) {
        (void)key;
        bank_tx_view_cache_entry_t* e = (bank_tx_view_cache_entry_t*)val;
        if (e && e->view) {
            sol_account_destroy(e->view);
            e->view = NULL;
        }
    }
    sol_map_clear(g_tls_tx_view_cache->inner);
}

static inline void
bank_tx_view_cache_invalidate(const sol_pubkey_t* pubkey) {
    if (!pubkey || !g_tls_tx_view_cache) return;
    bank_tx_view_cache_entry_t* e =
        (bank_tx_view_cache_entry_t*)sol_pubkey_map_get(g_tls_tx_view_cache, pubkey);
    if (e && e->view) {
        sol_account_destroy(e->view);
        e->view = NULL;
    }
    (void)sol_pubkey_map_remove(g_tls_tx_view_cache, pubkey);
}

static inline const bank_tx_view_cache_entry_t*
bank_tx_view_cache_entry_get(const sol_pubkey_t* pubkey) {
    if (!pubkey || !bank_tx_view_cache_is_active() || !g_tls_tx_view_cache) return NULL;
    bank_tx_view_cache_entry_t* e =
        (bank_tx_view_cache_entry_t*)sol_pubkey_map_get(g_tls_tx_view_cache, pubkey);
    if (!e || !e->view) return NULL;
    return e;
}

static inline bool
bank_tx_view_cache_lookup(const sol_pubkey_t* pubkey,
                          sol_account_t** out_view,
                          sol_slot_t* out_slot,
                          bool* out_has_slot) {
    if (out_view) *out_view = NULL;
    if (out_slot) *out_slot = 0;
    if (out_has_slot) *out_has_slot = false;
    if (!out_view) return false;
    const bank_tx_view_cache_entry_t* e = bank_tx_view_cache_entry_get(pubkey);
    if (!e) return false;

    sol_account_t* v = bank_tx_view_cache_make_view(e->view);
    if (!v) return false;

    *out_view = v;
    if (out_slot) *out_slot = e->stored_slot;
    if (out_has_slot) *out_has_slot = (e->has_stored_slot != 0);
    return true;
}

static inline bool
bank_tx_view_cache_insert(const sol_pubkey_t* pubkey,
                          sol_account_t* view,
                          bool has_stored_slot,
                          sol_slot_t stored_slot) {
    if (!pubkey || !view || !bank_tx_view_cache_is_active()) return false;

    if (!g_tls_tx_view_cache) {
        g_tls_tx_view_cache = sol_pubkey_map_new(sizeof(bank_tx_view_cache_entry_t), 256u);
        if (!g_tls_tx_view_cache) return false;
    }

    bank_tx_view_cache_entry_t* existing =
        (bank_tx_view_cache_entry_t*)sol_pubkey_map_get(g_tls_tx_view_cache, pubkey);
    if (existing && existing->view) {
        sol_account_destroy(existing->view);
        existing->view = NULL;
    }

    bank_tx_view_cache_entry_t val = {
        .view = view,
        .stored_slot = stored_slot,
        .has_stored_slot = has_stored_slot ? 1u : 0u,
    };
    bank_tx_view_cache_entry_t* inserted =
        (bank_tx_view_cache_entry_t*)sol_pubkey_map_insert(g_tls_tx_view_cache, pubkey, &val);
    return inserted != NULL;
}

/* CPI-time account overrides (see sol_bank.h). */
static __thread sol_bank_account_overrides_t* g_tls_account_overrides = NULL;

static inline void
bank_tx_view_cache_store_written_account_if_cpi(const sol_pubkey_t* pubkey,
                                                const sol_account_t* account,
                                                sol_slot_t stored_slot) {
    if (!pubkey || !account) return;
    if (!bank_tx_view_cache_is_active()) return;
    /* Hot-path optimization for CPI post-update:
     * when callee writes an account, cache the post-write view so the caller's
     * AccountInfo sync doesn't need to reload from AccountsDB. */
    if (__builtin_expect(g_tls_account_overrides == NULL, 1)) return;

    sol_account_t* cached = sol_account_clone(account);
    if (!cached) return;
    if (!bank_tx_view_cache_insert(pubkey, cached, true, stored_slot)) {
        sol_account_destroy(cached);
    }
}

sol_bank_account_overrides_t*
sol_bank_overrides_push(sol_bank_account_overrides_t* overrides) {
    sol_bank_account_overrides_t* prev = g_tls_account_overrides;
    if (overrides != NULL) {
        overrides->prev = prev;
    }
    g_tls_account_overrides = overrides;
    return prev;
}

void
sol_bank_overrides_pop(sol_bank_account_overrides_t* prev) {
    g_tls_account_overrides = prev;
}

static inline int
bank_overrides_lookup_idx(const sol_bank_account_overrides_t* ov, const sol_pubkey_t* pubkey) {
    if (!ov || !pubkey || !ov->keys || !ov->accounts || ov->len == 0) return -1;
    /* CPI account sets are typically small (<<128); linear scan is fine and branch-friendly. */
    for (size_t i = 0; i < ov->len; i++) {
        if (sol_pubkey_eq(&ov->keys[i], pubkey)) {
            return (int)i;
        }
    }
    return -1;
}

static inline const sol_account_t*
bank_overrides_lookup_ro(const sol_pubkey_t* pubkey) {
    const sol_bank_account_overrides_t* ov = g_tls_account_overrides;
    if (!ov) return NULL;
    int idx = bank_overrides_lookup_idx(ov, pubkey);
    if (idx < 0) return NULL;
    if (ov->written && ov->written[(size_t)idx]) {
        /* Callee wrote this account; bank state is now authoritative. */
        return NULL;
    }
    return &ov->accounts[(size_t)idx];
}

static inline void
bank_overrides_mark_written(const sol_pubkey_t* pubkey) {
    for (sol_bank_account_overrides_t* ov = g_tls_account_overrides;
         ov != NULL;
         ov = ov->prev) {
        if (!ov->written) continue;
        int idx = bank_overrides_lookup_idx(ov, pubkey);
        if (idx < 0) continue;
        ov->written[(size_t)idx] = 1u;
    }
}

static inline void
bank_tx_undo_end(void) {
    bank_tx_undo_log_t* u = &g_tls_tx_undo;
    for (size_t i = 0; i < u->len; i++) {
        if (u->entries[i].account) {
            sol_account_destroy(u->entries[i].account);
            u->entries[i].account = NULL;
        }
    }
    u->len = 0;
    u->active = false;
    u->overlay = false;
    bank_tx_view_cache_reset();
}

static inline void
bank_tx_undo_begin(sol_bank_t* bank) {
    bank_tx_undo_end();
    bank_tx_undo_log_t* u = &g_tls_tx_undo;
    u->overlay = (bank && bank->accounts_db) ? sol_accounts_db_is_overlay(bank->accounts_db) : false;
    u->active = true;
}

static inline sol_err_t
bank_tx_undo_record(sol_bank_t* bank,
                    const sol_pubkey_t* pubkey,
                    bank_tx_undo_entry_t** out_entry) {
    bank_tx_undo_log_t* u = &g_tls_tx_undo;
    if (out_entry) *out_entry = NULL;
    if (!u->active) return SOL_OK;
    if (!bank || !bank->accounts_db || !pubkey) return SOL_ERR_INVAL;

    for (size_t i = 0; i < u->len; i++) {
        if (sol_pubkey_eq(&u->entries[i].key, pubkey)) {
            if (out_entry) *out_entry = &u->entries[i];
            return SOL_OK;
        }
    }

    if (u->len == u->cap) {
        size_t new_cap = u->cap ? (u->cap * 2u) : 32u;
        bank_tx_undo_entry_t* next = sol_realloc_array(bank_tx_undo_entry_t, u->entries, new_cap);
        if (!next) return SOL_ERR_NOMEM;
        u->entries = next;
        u->cap = new_cap;
    }

    bank_tx_undo_entry_t* e = &u->entries[u->len++];
    memset(e, 0, sizeof(*e));
    e->key = *pubkey;
    if (out_entry) *out_entry = e;

    if (u->overlay) {
        sol_account_t* local = NULL;
        sol_accounts_db_local_kind_t kind =
            sol_accounts_db_get_local_kind(bank->accounts_db, pubkey, &local);
        if (kind == SOL_ACCOUNTS_DB_LOCAL_ACCOUNT) {
            e->kind = BANK_TX_UNDO_KIND_ACCOUNT;
            e->account = local;
            local = NULL;
        } else if (kind == SOL_ACCOUNTS_DB_LOCAL_TOMBSTONE) {
            e->kind = BANK_TX_UNDO_KIND_TOMBSTONE;
        } else {
            e->kind = BANK_TX_UNDO_KIND_MISSING;
        }
        if (local) {
            sol_account_destroy(local);
        }
        return SOL_OK;
    }

    /* Non-overlay: capture visible state. */
    sol_account_t* prev = sol_accounts_db_load(bank->accounts_db, pubkey);
    if (prev) {
        e->kind = BANK_TX_UNDO_KIND_ACCOUNT;
        e->account = prev;
    } else {
        e->kind = BANK_TX_UNDO_KIND_MISSING;
    }
    return SOL_OK;
}

sol_account_t*
sol_bank_load_account(sol_bank_t* bank, const sol_pubkey_t* pubkey) {
    if (!bank || !pubkey) return NULL;

    /* The Instructions sysvar is virtual in Agave (transaction-local, not
     * stored in AccountsDB). When executing transactions (possibly in parallel),
     * expose it via a per-thread override so programs can read it without a
     * global shared mutable sysvar account. */
    if (sol_pubkey_eq(pubkey, &SOL_SYSVAR_INSTRUCTIONS_ID) &&
        __builtin_expect(g_tls_instructions_sysvar != NULL, 0)) {
        return sol_account_clone(g_tls_instructions_sysvar);
    }

    const sol_account_t* ov_acct = bank_overrides_lookup_ro(pubkey);
    if (__builtin_expect(ov_acct != NULL, 0)) {
        return sol_account_clone(ov_acct); /* owned clone */
    }

    const bank_tx_view_cache_entry_t* cached = bank_tx_view_cache_entry_get(pubkey);
    if (cached) {
        sol_account_t* account = sol_account_clone(cached->view);
        if (account && sol_accounts_db_is_overlay(bank->accounts_db)) {
            bank_prev_meta_hints_record(pubkey, account);
        }
        if (account) return account;
    }

    sol_account_t* account = sol_accounts_db_load(bank->accounts_db, pubkey);
    if (account && sol_accounts_db_is_overlay(bank->accounts_db)) {
        bank_prev_meta_hints_record(pubkey, account);
    }
    return account;
}

sol_account_t*
sol_bank_load_account_ex(sol_bank_t* bank, const sol_pubkey_t* pubkey,
                         sol_slot_t* out_stored_slot) {
    if (!bank || !pubkey) return NULL;

    if (sol_pubkey_eq(pubkey, &SOL_SYSVAR_INSTRUCTIONS_ID) &&
        __builtin_expect(g_tls_instructions_sysvar != NULL, 0)) {
        if (out_stored_slot) *out_stored_slot = bank->slot;
        return sol_account_clone(g_tls_instructions_sysvar);
    }

    const sol_account_t* ov_acct = bank_overrides_lookup_ro(pubkey);
    if (__builtin_expect(ov_acct != NULL, 0)) {
        if (out_stored_slot) *out_stored_slot = bank->slot;
        return sol_account_clone(ov_acct); /* owned clone */
    }

    const bank_tx_view_cache_entry_t* cached = bank_tx_view_cache_entry_get(pubkey);
    if (cached) {
        sol_account_t* account = sol_account_clone(cached->view);
        if (account && sol_accounts_db_is_overlay(bank->accounts_db)) {
            bank_prev_meta_hints_record(pubkey, account);
        }
        if (account) {
            if (out_stored_slot && cached->has_stored_slot) *out_stored_slot = cached->stored_slot;
            return account;
        }
    }

    sol_account_t* account = sol_accounts_db_load_ex(bank->accounts_db, pubkey, out_stored_slot);
    if (account && sol_accounts_db_is_overlay(bank->accounts_db)) {
        bank_prev_meta_hints_record(pubkey, account);
    }
    return account;
}

sol_account_t*
sol_bank_load_account_view(sol_bank_t* bank, const sol_pubkey_t* pubkey) {
    if (!bank || !pubkey) return NULL;

    if (sol_pubkey_eq(pubkey, &SOL_SYSVAR_INSTRUCTIONS_ID) &&
        __builtin_expect(g_tls_instructions_sysvar != NULL, 0)) {
        return sol_account_clone(g_tls_instructions_sysvar);
    }

    const sol_account_t* ov_acct = bank_overrides_lookup_ro(pubkey);
    if (__builtin_expect(ov_acct != NULL, 0)) {
        sol_account_t* view = sol_calloc(1u, sizeof(*view));
        if (!view) return NULL;
        view->meta = ov_acct->meta;
        view->data = ov_acct->data;
        view->data_borrowed = true;
        return view;
    }

    sol_account_t* cached_view = NULL;
    if (bank_tx_view_cache_lookup(pubkey, &cached_view, NULL, NULL)) {
        return cached_view;
    }

    sol_account_t* account = sol_accounts_db_load_view(bank->accounts_db, pubkey);
    if (account && sol_accounts_db_is_overlay(bank->accounts_db)) {
        bank_prev_meta_hints_record(pubkey, account);
    }

    if (account && bank_tx_view_cache_is_active()) {
        sol_account_t* ret = bank_tx_view_cache_make_view(account);
        if (ret && bank_tx_view_cache_insert(pubkey, account, false, 0)) {
            return ret;
        }
        if (ret) sol_account_destroy(ret);
    }
    return account;
}

sol_account_t*
sol_bank_load_account_view_ex(sol_bank_t* bank, const sol_pubkey_t* pubkey,
                              sol_slot_t* out_stored_slot) {
    if (!bank || !pubkey) return NULL;

    if (sol_pubkey_eq(pubkey, &SOL_SYSVAR_INSTRUCTIONS_ID) &&
        __builtin_expect(g_tls_instructions_sysvar != NULL, 0)) {
        if (out_stored_slot) *out_stored_slot = bank->slot;
        return sol_account_clone(g_tls_instructions_sysvar);
    }

    const sol_account_t* ov_acct = bank_overrides_lookup_ro(pubkey);
    if (__builtin_expect(ov_acct != NULL, 0)) {
        if (out_stored_slot) *out_stored_slot = bank->slot;
        sol_account_t* view = sol_calloc(1u, sizeof(*view));
        if (!view) return NULL;
        view->meta = ov_acct->meta;
        view->data = ov_acct->data;
        view->data_borrowed = true;
        return view;
    }

    sol_account_t* cached_view = NULL;
    sol_slot_t cached_slot = 0;
    bool cached_has_slot = false;
    if (bank_tx_view_cache_lookup(pubkey, &cached_view, &cached_slot, &cached_has_slot)) {
        if (out_stored_slot && cached_has_slot) *out_stored_slot = cached_slot;
        return cached_view;
    }

    sol_slot_t stored_slot_tmp = 0;
    sol_slot_t* stored_slot_ptr = out_stored_slot ? out_stored_slot : &stored_slot_tmp;
    sol_account_t* account =
        sol_accounts_db_load_view_ex(bank->accounts_db, pubkey, stored_slot_ptr);
    if (account && sol_accounts_db_is_overlay(bank->accounts_db)) {
        bank_prev_meta_hints_record(pubkey, account);
    }

    if (account && bank_tx_view_cache_is_active()) {
        sol_account_t* ret = bank_tx_view_cache_make_view(account);
        if (ret && bank_tx_view_cache_insert(pubkey, account, true, *stored_slot_ptr)) {
            return ret;
        }
        if (ret) sol_account_destroy(ret);
    }
    return account;
}

void
sol_bank_set_zombie_filter_slot(sol_bank_t* bank, sol_slot_t slot) {
    if (bank) bank->zombie_filter_slot = slot;
}

sol_slot_t
sol_bank_zombie_filter_slot(const sol_bank_t* bank) {
    return bank ? bank->zombie_filter_slot : 0;
}

sol_err_t
sol_bank_store_account(sol_bank_t* bank, const sol_pubkey_t* pubkey,
                       const sol_account_t* account) {
    if (!bank || !pubkey || !account) return SOL_ERR_INVAL;
    if (__atomic_load_n(&bank->frozen, __ATOMIC_ACQUIRE)) return SOL_ERR_SHUTDOWN;

    /* If CPI overrides are active, this pubkey is now written by the callee. */
    bank_overrides_mark_written(pubkey);
    bank_tx_view_cache_invalidate(pubkey);
    bank_tx_view_cache_store_written_account_if_cpi(pubkey, account, bank->slot);

    bank_tx_undo_entry_t* undo_e = NULL;
    sol_err_t undo_err = bank_tx_undo_record(bank, pubkey, &undo_e);
    if (undo_err != SOL_OK) return undo_err;

    /* Writes to a non-overlay AccountsDB can invalidate cached ALT table state.
     * For overlay banks, bank_alt_cache_get() detects local writes by checking
     * the overlay layer before serving from cache. */
    if (!sol_accounts_db_is_overlay(bank->accounts_db)) {
        bank_alt_cache_invalidate(bank, pubkey);
    }

    /* Track BankHashStats for parity debugging.
     * Agave's BankHashStats::update() counts 0-lamport stores as "removed",
     * non-zero as "updated".  executable/data_len/lamports_stored are always
     * accumulated regardless of lamport value. */
    if (account->meta.lamports == 0) {
        BANK_STAT_INC(bank, num_removed_accounts);
    } else {
        BANK_STAT_INC(bank, num_updated_accounts);
    }
    BANK_STAT_ADD(bank, num_lamports_stored, account->meta.lamports);
    BANK_STAT_ADD(bank, total_data_len, account->meta.data_len);
    if (account->meta.executable) BANK_STAT_INC(bank, num_executable_accounts);

    BANK_FLAG_CLEAR(bank, hash_computed);
    BANK_FLAG_CLEAR(bank, accounts_delta_hash_computed);
    BANK_FLAG_CLEAR(bank, accounts_lt_hash_computed);

    /* First write to a pubkey in an overlay triggers a parent meta lookup to
     * adjust stats.  If we already loaded the prior version during this tx, use
     * that meta to avoid duplicate RocksDB+AppendVec IO. */
    if (sol_accounts_db_is_overlay(bank->accounts_db)) {
        bank_prev_meta_hint_t prev = {0};
        if (bank_prev_meta_hints_get(pubkey, &prev)) {
            bool prev_exists = (prev.lamports != 0);
            sol_err_t err = sol_accounts_db_store_versioned_with_prev_meta(bank->accounts_db,
                                                                           pubkey,
                                                                           account,
                                                                           bank->slot,
                                                                           0,
                                                                           prev_exists,
                                                                           prev.lamports,
                                                                           prev.data_len);
            if (err == SOL_OK && undo_e) {
                undo_e->post_lamports = account->meta.lamports;
                undo_e->post_data_len = account->meta.data_len;
                undo_e->post_owner = account->meta.owner;
                undo_e->post_executable = account->meta.executable ? 1u : 0u;
                undo_e->post_valid = 1u;
            }
            return err;
        }
    }

    sol_err_t err = sol_accounts_db_store_versioned(bank->accounts_db,
                                                    pubkey,
                                                    account,
                                                    bank->slot,
                                                    0);
    if (err == SOL_OK && undo_e) {
        undo_e->post_lamports = account->meta.lamports;
        undo_e->post_data_len = account->meta.data_len;
        undo_e->post_owner = account->meta.owner;
        undo_e->post_executable = account->meta.executable ? 1u : 0u;
        undo_e->post_valid = 1u;
    }
    return err;
}

static sol_err_t
bank_delete_account(sol_bank_t* bank, const sol_pubkey_t* pubkey) {
    if (!bank || !pubkey) return SOL_ERR_INVAL;
    if (__atomic_load_n(&bank->frozen, __ATOMIC_ACQUIRE)) return SOL_ERR_SHUTDOWN;

    /* Deleting also counts as a write for CPI override purposes. */
    bank_overrides_mark_written(pubkey);
    bank_tx_view_cache_invalidate(pubkey);

    bank_tx_undo_entry_t* undo_e = NULL;
    sol_err_t undo_err = bank_tx_undo_record(bank, pubkey, &undo_e);
    if (undo_err != SOL_OK) return undo_err;

    /* Track BankHashStats for parity debugging */
    BANK_STAT_INC(bank, num_removed_accounts);

    BANK_FLAG_CLEAR(bank, hash_computed);
    BANK_FLAG_CLEAR(bank, accounts_delta_hash_computed);
    BANK_FLAG_CLEAR(bank, accounts_lt_hash_computed);
    sol_err_t err = sol_accounts_db_delete_versioned(bank->accounts_db, pubkey, bank->slot, 0);
    if (err == SOL_OK && undo_e) {
        undo_e->post_lamports = 0;
        undo_e->post_data_len = 0;
        undo_e->post_owner = (sol_pubkey_t){{0}};
        undo_e->post_executable = 0u;
        undo_e->post_valid = 1u;
    }
    return err;
}

static void
bank_tx_undo_rollback(sol_bank_t* bank) {
    bank_tx_undo_log_t* u = &g_tls_tx_undo;
    if (!u->active || u->len == 0) {
        bank_tx_undo_end();
        return;
    }

    /* Disable recording while we apply the rollback. */
    u->active = false;

    if (!bank || !bank->accounts_db) {
        bank_tx_undo_end();
        return;
    }

    for (size_t i = u->len; i > 0; i--) {
        bank_tx_undo_entry_t* e = &u->entries[i - 1u];
        switch (e->kind) {
            case BANK_TX_UNDO_KIND_ACCOUNT:
                if (e->account) {
                    (void)sol_bank_store_account(bank, &e->key, e->account);
                } else {
                    /* Defensive: treat missing account snapshot as delete. */
                    (void)bank_delete_account(bank, &e->key);
                }
                break;
            case BANK_TX_UNDO_KIND_TOMBSTONE:
                (void)bank_delete_account(bank, &e->key);
                break;
            case BANK_TX_UNDO_KIND_MISSING:
            default:
                if (u->overlay) {
                    (void)sol_accounts_db_clear_override(bank->accounts_db, &e->key);
                } else {
                    (void)bank_delete_account(bank, &e->key);
                }
                break;
        }
    }

    bank_tx_undo_end();
}

static uint64_t
bank_count_precompile_signatures(const sol_transaction_t* tx) {
    if (!tx) return 0;
    if (!tx->message.instructions || tx->message.instructions_len == 0) return 0;

    const sol_pubkey_t* account_keys = tx->message.resolved_accounts_len
        ? tx->message.resolved_accounts
        : tx->message.account_keys;
    size_t account_keys_len = tx->message.resolved_accounts_len
        ? (size_t)tx->message.resolved_accounts_len
        : (size_t)tx->message.account_keys_len;

    if (!account_keys || account_keys_len == 0) return 0;

    uint64_t signatures = 0;
    for (uint8_t i = 0; i < tx->message.instructions_len; i++) {
        const sol_compiled_instruction_t* instr = &tx->message.instructions[i];
        if (instr->program_id_index >= account_keys_len) continue;
        const sol_pubkey_t* program_id = &account_keys[instr->program_id_index];
        if (!instr->data || instr->data_len < 1) continue;

        if (sol_pubkey_eq(program_id, &SOL_ED25519_PROGRAM_ID) ||
            sol_pubkey_eq(program_id, &SOL_SECP256K1_PROGRAM_ID) ||
            sol_pubkey_eq(program_id, &SOL_SECP256R1_PROGRAM_ID)) {
            signatures += (uint64_t)instr->data[0];
        }
    }

    return signatures;
}

static sol_err_t
bank_resolve_v0_message_accounts(const sol_bank_t* bank,
                                 const sol_transaction_t* tx,
                                 sol_pubkey_t* out_keys,
                                 bool* out_writable,
                                 bool* out_signer,
                                 uint16_t out_cap,
                                 uint16_t* out_len) {
    if (!bank || !tx || !out_keys || !out_writable || !out_signer || !out_len) {
        return SOL_ERR_INVAL;
    }

    if (tx->message.version != SOL_MESSAGE_VERSION_V0) {
        return SOL_ERR_INVAL;
    }

    if (out_cap == 0) {
        return SOL_ERR_INVAL;
    }

    if (!tx->message.account_keys || tx->message.account_keys_len == 0) {
        return SOL_ERR_TX_MALFORMED;
    }

    uint16_t static_len = (uint16_t)tx->message.account_keys_len;
    if (static_len > SOL_MAX_MESSAGE_ACCOUNTS) {
        return SOL_ERR_TX_MALFORMED;
    }
    if (static_len > out_cap) {
        return SOL_ERR_OVERFLOW;
    }

    /* Copy static keys and seed signer/writable flags from the header. */
    uint8_t num_signers = tx->message.header.num_required_signatures;
    uint8_t num_readonly_signed = tx->message.header.num_readonly_signed;
    uint8_t num_readonly_unsigned = tx->message.header.num_readonly_unsigned;

    uint8_t writable_signed = 0;
    if (num_signers >= num_readonly_signed) {
        writable_signed = (uint8_t)(num_signers - num_readonly_signed);
    }

    uint16_t unsigned_start = num_signers;
    uint16_t unsigned_count = static_len > unsigned_start ? (uint16_t)(static_len - unsigned_start) : 0;
    uint16_t writable_unsigned = unsigned_count > num_readonly_unsigned
        ? (uint16_t)(unsigned_count - num_readonly_unsigned)
        : 0;

    for (uint16_t i = 0; i < static_len; i++) {
        out_keys[i] = tx->message.account_keys[i];
        out_signer[i] = (i < num_signers);
        if (i < num_signers) {
            out_writable[i] = (i < writable_signed);
        } else {
            out_writable[i] =
                (i >= unsigned_start) && ((uint16_t)(i - unsigned_start) < writable_unsigned);
        }
    }

    uint16_t resolved_len = static_len;

    /* Parse the serialized v0 message to locate and read address lookups. */
    sol_decoder_t dec;
    sol_decoder_init(&dec, tx->message_data, tx->message_data_len);

    uint8_t version_byte = 0;
    if (sol_decode_u8(&dec, &version_byte) != SOL_OK) {
        return SOL_ERR_TX_MALFORMED;
    }
    if ((version_byte & 0x80U) == 0U || (version_byte & 0x7FU) != 0U) {
        return SOL_ERR_TX_MALFORMED;
    }

    /* Header (already parsed into tx->message.header) */
    for (size_t i = 0; i < 3; i++) {
        uint8_t tmp = 0;
        if (sol_decode_u8(&dec, &tmp) != SOL_OK) {
            return SOL_ERR_TX_MALFORMED;
        }
    }

    /* Static account keys */
    uint16_t decoded_static_len = 0;
    if (sol_decode_compact_u16(&dec, &decoded_static_len) != SOL_OK) {
        return SOL_ERR_TX_MALFORMED;
    }
    if (decoded_static_len != static_len) {
        return SOL_ERR_TX_MALFORMED;
    }

    const uint8_t* ignored = NULL;
    if (sol_decode_bytes(&dec, (size_t)decoded_static_len * SOL_PUBKEY_SIZE, &ignored) != SOL_OK) {
        return SOL_ERR_TX_MALFORMED;
    }

    /* Recent blockhash */
    if (sol_decode_bytes(&dec, SOL_HASH_SIZE, &ignored) != SOL_OK) {
        return SOL_ERR_TX_MALFORMED;
    }

    /* Instructions */
    uint16_t ix_len = 0;
    if (sol_decode_compact_u16(&dec, &ix_len) != SOL_OK) {
        return SOL_ERR_TX_MALFORMED;
    }

    for (uint16_t i = 0; i < ix_len; i++) {
        uint8_t tmp_u8 = 0;
        if (sol_decode_u8(&dec, &tmp_u8) != SOL_OK) {
            return SOL_ERR_TX_MALFORMED;
        }

        uint16_t acc_len = 0;
        if (sol_decode_compact_u16(&dec, &acc_len) != SOL_OK) {
            return SOL_ERR_TX_MALFORMED;
        }
        if (sol_decode_bytes(&dec, acc_len, &ignored) != SOL_OK) {
            return SOL_ERR_TX_MALFORMED;
        }

        uint16_t data_len = 0;
        if (sol_decode_compact_u16(&dec, &data_len) != SOL_OK) {
            return SOL_ERR_TX_MALFORMED;
        }
        if (sol_decode_bytes(&dec, data_len, &ignored) != SOL_OK) {
            return SOL_ERR_TX_MALFORMED;
        }
    }

    /* Address lookup tables.
     *
     * Solana v0 message resolution order is:
     *   static keys + loaded writable + loaded readonly
     *
     * Where loaded writable is the concatenation of each lookup table's
     * writable indices (in lookup order) and loaded readonly is the
     * concatenation of each lookup table's readonly indices (in lookup order).
     *
     * NOTE: This is *not* an interleaving of (writable, readonly) per table.
     */
    uint16_t lookup_len = 0;
    if (sol_decode_compact_u16(&dec, &lookup_len) != SOL_OK) {
        return SOL_ERR_TX_MALFORMED;
    }

    if (lookup_len > SOL_MAX_ADDRESS_LOOKUP_TABLES) {
        return SOL_ERR_TX_MALFORMED;
    }

    typedef struct {
        sol_pubkey_t    table_key;
        const uint8_t*  writable_indices;
        uint16_t        writable_indices_len;
        const uint8_t*  readonly_indices;
        uint16_t        readonly_indices_len;
    } v0_lookup_ref_t;

    v0_lookup_ref_t lookups[SOL_MAX_ADDRESS_LOOKUP_TABLES];
    uint16_t total_writable = 0;
    uint16_t total_readonly = 0;

    for (uint16_t li = 0; li < lookup_len; li++) {
        const uint8_t* table_bytes = NULL;
        if (sol_decode_bytes(&dec, SOL_PUBKEY_SIZE, &table_bytes) != SOL_OK) {
            return SOL_ERR_TX_MALFORMED;
        }
        memcpy(lookups[li].table_key.bytes, table_bytes, SOL_PUBKEY_SIZE);

        uint16_t writable_idx_len = 0;
        if (sol_decode_compact_u16(&dec, &writable_idx_len) != SOL_OK) {
            return SOL_ERR_TX_MALFORMED;
        }
        const uint8_t* writable_indices = NULL;
        if (sol_decode_bytes(&dec, writable_idx_len, &writable_indices) != SOL_OK) {
            return SOL_ERR_TX_MALFORMED;
        }
        lookups[li].writable_indices = writable_indices;
        lookups[li].writable_indices_len = writable_idx_len;

        uint16_t readonly_idx_len = 0;
        if (sol_decode_compact_u16(&dec, &readonly_idx_len) != SOL_OK) {
            return SOL_ERR_TX_MALFORMED;
        }
        const uint8_t* readonly_indices = NULL;
        if (sol_decode_bytes(&dec, readonly_idx_len, &readonly_indices) != SOL_OK) {
            return SOL_ERR_TX_MALFORMED;
        }
        lookups[li].readonly_indices = readonly_indices;
        lookups[li].readonly_indices_len = readonly_idx_len;

        if ((uint32_t)total_writable + (uint32_t)writable_idx_len > UINT16_MAX) {
            return SOL_ERR_TX_MALFORMED;
        }
        if ((uint32_t)total_readonly + (uint32_t)readonly_idx_len > UINT16_MAX) {
            return SOL_ERR_TX_MALFORMED;
        }
        total_writable = (uint16_t)(total_writable + writable_idx_len);
        total_readonly = (uint16_t)(total_readonly + readonly_idx_len);
    }

    if ((uint32_t)static_len + (uint32_t)total_writable + (uint32_t)total_readonly > out_cap) {
        return SOL_ERR_OVERFLOW;
    }

    /* Fill loaded addresses into their final offsets. */
    uint16_t writable_base = static_len;
    uint16_t readonly_base = (uint16_t)(static_len + total_writable);
    uint16_t writable_cursor = 0;
    uint16_t readonly_cursor = 0;

    for (uint16_t li = 0; li < lookup_len; li++) {
        const sol_alt_state_t* state = NULL;
        sol_err_t cache_err =
            bank_alt_cache_get((sol_bank_t*)bank, &lookups[li].table_key, &state);
        if (cache_err == SOL_ERR_NOT_IMPLEMENTED) {
            sol_account_t* table_account =
                sol_accounts_db_load(bank->accounts_db, &lookups[li].table_key);
            if (!table_account) {
                return SOL_ERR_TX_SANITIZE;
            }

            if (!sol_pubkey_eq(&table_account->meta.owner, &SOL_ADDRESS_LOOKUP_TABLE_ID)) {
                sol_account_destroy(table_account);
                return SOL_ERR_TX_SANITIZE;
            }

            sol_alt_state_t tmp_state;
            sol_alt_state_init(&tmp_state);

            sol_err_t deser_err = sol_alt_deserialize(&tmp_state,
                                                      table_account->data,
                                                      (size_t)table_account->meta.data_len);
            sol_account_destroy(table_account);
            if (deser_err != SOL_OK) {
                sol_alt_state_free(&tmp_state);
                return SOL_ERR_TX_SANITIZE;
            }

            if (!sol_alt_is_active(&tmp_state, sol_bank_slot(bank))) {
                sol_alt_state_free(&tmp_state);
                return SOL_ERR_TX_SANITIZE;
            }
            state = &tmp_state;

            for (uint16_t wi = 0; wi < lookups[li].writable_indices_len; wi++) {
                if ((uint32_t)writable_base + (uint32_t)writable_cursor >= out_cap) {
                    sol_alt_state_free(&tmp_state);
                    return SOL_ERR_OVERFLOW;
                }
                const sol_pubkey_t* addr =
                    sol_alt_get_address(state, lookups[li].writable_indices[wi]);
                if (!addr) {
                    sol_alt_state_free(&tmp_state);
                    return SOL_ERR_TX_SANITIZE;
                }
                uint16_t out_idx = (uint16_t)(writable_base + writable_cursor);
                out_keys[out_idx] = *addr;
                out_signer[out_idx] = false;
                out_writable[out_idx] = true;
                writable_cursor++;
            }

            for (uint16_t ri = 0; ri < lookups[li].readonly_indices_len; ri++) {
                if ((uint32_t)readonly_base + (uint32_t)readonly_cursor >= out_cap) {
                    sol_alt_state_free(&tmp_state);
                    return SOL_ERR_OVERFLOW;
                }
                const sol_pubkey_t* addr =
                    sol_alt_get_address(state, lookups[li].readonly_indices[ri]);
                if (!addr) {
                    sol_alt_state_free(&tmp_state);
                    return SOL_ERR_TX_SANITIZE;
                }
                uint16_t out_idx = (uint16_t)(readonly_base + readonly_cursor);
                out_keys[out_idx] = *addr;
                out_signer[out_idx] = false;
                out_writable[out_idx] = false;
                readonly_cursor++;
            }

            sol_alt_state_free(&tmp_state);
            continue;
        }
        if (cache_err != SOL_OK || !state) {
            return SOL_ERR_TX_SANITIZE;
        }

        for (uint16_t wi = 0; wi < lookups[li].writable_indices_len; wi++) {
            if ((uint32_t)writable_base + (uint32_t)writable_cursor >= out_cap) {
                return SOL_ERR_OVERFLOW;
            }
            const sol_pubkey_t* addr =
                sol_alt_get_address(state, lookups[li].writable_indices[wi]);
            if (!addr) {
                return SOL_ERR_TX_SANITIZE;
            }
            uint16_t out_idx = (uint16_t)(writable_base + writable_cursor);
            out_keys[out_idx] = *addr;
            out_signer[out_idx] = false;
            out_writable[out_idx] = true;
            writable_cursor++;
        }

        for (uint16_t ri = 0; ri < lookups[li].readonly_indices_len; ri++) {
            if ((uint32_t)readonly_base + (uint32_t)readonly_cursor >= out_cap) {
                return SOL_ERR_OVERFLOW;
            }
            const sol_pubkey_t* addr =
                sol_alt_get_address(state, lookups[li].readonly_indices[ri]);
            if (!addr) {
                return SOL_ERR_TX_SANITIZE;
            }
            uint16_t out_idx = (uint16_t)(readonly_base + readonly_cursor);
            out_keys[out_idx] = *addr;
            out_signer[out_idx] = false;
            out_writable[out_idx] = false;
            readonly_cursor++;
        }

    }

    if (writable_cursor != total_writable || readonly_cursor != total_readonly) {
        return SOL_ERR_TX_MALFORMED;
    }

    resolved_len = (uint16_t)(static_len + total_writable + total_readonly);

    /* Apply writable demotion for reserved account keys and program IDs.
     * Matches Agave's ResolvedTransactionView::cache_is_writable(). */
    bool upgradeable_loader_present = false;
    for (uint16_t i = 0; i < resolved_len; i++) {
        if (sol_pubkey_eq(&out_keys[i], &SOL_BPF_LOADER_UPGRADEABLE_ID)) {
            upgradeable_loader_present = true;
            break;
        }
    }

    /* Skip fee payer (index 0) — always writable in Agave */
    for (uint16_t i = 1; i < resolved_len; i++) {
        if (!out_writable[i]) continue;

        /* Demote reserved account keys (sysvars, builtins, native loader) */
        if (is_reserved_account_key(&out_keys[i])) {
            out_writable[i] = false;
            continue;
        }

        /* Demote program_id accounts when upgradeable loader not present */
        if (!upgradeable_loader_present) {
            for (uint8_t j = 0; j < tx->message.instructions_len; j++) {
                if (tx->message.instructions[j].program_id_index == (uint8_t)i) {
                    out_writable[i] = false;
                    break;
                }
            }
        }
    }

    *out_len = resolved_len;
    return SOL_OK;
}

sol_err_t
sol_bank_resolve_transaction_accounts(const sol_bank_t* bank,
                                      const sol_transaction_t* tx,
                                      sol_pubkey_t* out_keys,
                                      bool* out_writable,
                                      bool* out_signer,
                                      size_t out_cap,
                                      size_t* out_len) {
    if (!tx || !out_keys || !out_writable || !out_signer || !out_len) {
        return SOL_ERR_INVAL;
    }
    if (out_cap == 0) {
        return SOL_ERR_INVAL;
    }
    if (out_cap > UINT16_MAX) {
        return SOL_ERR_OVERFLOW;
    }

    if (tx->message.version == SOL_MESSAGE_VERSION_V0) {
        if (!bank) return SOL_ERR_INVAL;

        uint16_t resolved_len = 0;
        sol_err_t err = bank_resolve_v0_message_accounts(bank,
                                                         tx,
                                                         out_keys,
                                                         out_writable,
                                                         out_signer,
                                                         (uint16_t)out_cap,
                                                         &resolved_len);
        if (err != SOL_OK) {
            return err;
        }

        *out_len = (size_t)resolved_len;
        return SOL_OK;
    }

    if (!tx->message.account_keys || tx->message.account_keys_len == 0) {
        return SOL_ERR_TX_MALFORMED;
    }

    size_t n = (size_t)tx->message.account_keys_len;
    if (n > out_cap) {
        return SOL_ERR_OVERFLOW;
    }

    for (size_t i = 0; i < n; i++) {
        out_keys[i] = tx->message.account_keys[i];
        out_signer[i] = (i < tx->message.header.num_required_signatures);
        out_writable[i] = sol_message_is_writable_index(&tx->message, (uint8_t)i);
    }

    /* Apply writable demotion for reserved account keys and program IDs. */
    bool upgradeable_loader_present = false;
    for (size_t i = 0; i < n; i++) {
        if (sol_pubkey_eq(&out_keys[i], &SOL_BPF_LOADER_UPGRADEABLE_ID)) {
            upgradeable_loader_present = true;
            break;
        }
    }
    /* Skip fee payer (index 0) — always writable in Agave */
    for (size_t i = 1; i < n; i++) {
        if (!out_writable[i]) continue;
        if (is_reserved_account_key(&out_keys[i])) {
            out_writable[i] = false;
            continue;
        }
        if (!upgradeable_loader_present) {
            for (uint8_t j = 0; j < tx->message.instructions_len; j++) {
                if (tx->message.instructions[j].program_id_index == (uint8_t)i) {
                    out_writable[i] = false;
                    break;
                }
            }
        }
    }

    *out_len = n;
    return SOL_OK;
}

/* ---- v0 message resolution caching (scheduler fast path) ----
 *
 * The deterministic batching scheduler must resolve v0 account keys to build
 * lock sets. Transaction execution also needs resolved keys/flags. Resolving
 * twice per tx (scheduler + execution) is expensive, so we opportunistically
 * cache resolved v0 accounts/flags in the transaction's sol_message_t for the
 * duration of the scheduling call.
 *
 * These caches are ephemeral: we restore the message fields before returning so
 * callers never observe dangling pointers.
 */

typedef struct {
    sol_message_t*       msg;
    const sol_pubkey_t*  saved_resolved_accounts;
    uint16_t             saved_resolved_accounts_len;
    bool*                saved_is_writable;
    bool*                saved_is_signer;
} bank_v0_msg_patch_t;

typedef struct {
    sol_arena_t*          arena;
    bank_v0_msg_patch_t*  patches;
    size_t                patches_len;
    size_t                patches_cap;
} bank_v0_resolve_cache_t;

static uint16_t
bank_v0_resolved_len_hint(const sol_transaction_t* tx, sol_err_t* out_err) {
    if (out_err) *out_err = SOL_OK;
    if (!tx) {
        if (out_err) *out_err = SOL_ERR_INVAL;
        return 0;
    }
    if (tx->message.version != SOL_MESSAGE_VERSION_V0) {
        if (out_err) *out_err = SOL_ERR_INVAL;
        return 0;
    }
    if (!tx->message.account_keys || tx->message.account_keys_len == 0) {
        if (out_err) *out_err = SOL_ERR_TX_MALFORMED;
        return 0;
    }

    size_t static_len = (size_t)tx->message.account_keys_len;
    size_t total_writable = 0;
    size_t total_readonly = 0;

    if (tx->message.address_lookups_len > 0) {
        if (!tx->message.address_lookups) {
            if (out_err) *out_err = SOL_ERR_TX_MALFORMED;
            return 0;
        }
        for (uint8_t i = 0; i < tx->message.address_lookups_len; i++) {
            total_writable += (size_t)tx->message.address_lookups[i].writable_indices_len;
            total_readonly += (size_t)tx->message.address_lookups[i].readonly_indices_len;
        }
    }

    size_t resolved = static_len + total_writable + total_readonly;
    if (resolved == 0 || resolved > SOL_MAX_MESSAGE_ACCOUNTS || resolved > UINT16_MAX) {
        if (out_err) *out_err = SOL_ERR_TX_TOO_LARGE;
        return 0;
    }

    return (uint16_t)resolved;
}

static sol_err_t
bank_v0_cache_resolve(sol_bank_t* bank,
                      const sol_transaction_t* tx,
                      bank_v0_resolve_cache_t* cache) {
    if (!bank || !tx) return SOL_ERR_INVAL;
    if (tx->message.version != SOL_MESSAGE_VERSION_V0) return SOL_ERR_INVAL;
    if (!cache || !cache->patches || cache->patches_cap == 0) return SOL_ERR_NOMEM;

    sol_message_t* msg = (sol_message_t*)&tx->message;

    /* If already resolved (by caller or earlier fast path), reuse it. */
    if (msg->resolved_accounts_len != 0 &&
        msg->resolved_accounts &&
        msg->is_writable &&
        msg->is_signer) {
        return SOL_OK;
    }

    if (cache->patches_len >= cache->patches_cap) {
        return SOL_ERR_OVERFLOW;
    }

    sol_err_t hint_err = SOL_OK;
    uint16_t hint_len = bank_v0_resolved_len_hint(tx, &hint_err);
    if (hint_err != SOL_OK) {
        return hint_err;
    }

    if (!cache->arena) {
        /* Larger chunks reduce allocator overhead for big blocks. */
        cache->arena = sol_arena_new(4u * 1024u * 1024u);
        if (!cache->arena) return SOL_ERR_NOMEM;
    }

    sol_pubkey_t* resolved_keys = sol_arena_alloc_array(cache->arena, sol_pubkey_t, hint_len);
    bool* resolved_writable = sol_arena_alloc_array(cache->arena, bool, hint_len);
    bool* resolved_signer = sol_arena_alloc_array(cache->arena, bool, hint_len);
    if (!resolved_keys || !resolved_writable || !resolved_signer) {
        return SOL_ERR_NOMEM;
    }

    uint16_t resolved_len = 0;
    sol_err_t err = bank_resolve_v0_message_accounts(bank,
                                                     tx,
                                                     resolved_keys,
                                                     resolved_writable,
                                                     resolved_signer,
                                                     hint_len,
                                                     &resolved_len);
    if (err != SOL_OK) {
        return err;
    }
    if (resolved_len == 0 || resolved_len > hint_len) {
        return SOL_ERR_TX_MALFORMED;
    }

    bank_v0_msg_patch_t* p = &cache->patches[cache->patches_len++];
    p->msg = msg;
    p->saved_resolved_accounts = msg->resolved_accounts;
    p->saved_resolved_accounts_len = msg->resolved_accounts_len;
    p->saved_is_writable = msg->is_writable;
    p->saved_is_signer = msg->is_signer;

    msg->resolved_accounts = resolved_keys;
    msg->resolved_accounts_len = resolved_len;
    msg->is_writable = resolved_writable;
    msg->is_signer = resolved_signer;

    return SOL_OK;
}

static void
bank_v0_cache_restore(bank_v0_resolve_cache_t* cache) {
    if (!cache || !cache->patches) return;
    for (size_t i = cache->patches_len; i > 0; i--) {
        bank_v0_msg_patch_t* p = &cache->patches[i - 1u];
        if (!p->msg) continue;
        p->msg->resolved_accounts = p->saved_resolved_accounts;
        p->msg->resolved_accounts_len = p->saved_resolved_accounts_len;
        p->msg->is_writable = p->saved_is_writable;
        p->msg->is_signer = p->saved_is_signer;
    }
    cache->patches_len = 0;
}

static void
bank_v0_cache_destroy(bank_v0_resolve_cache_t* cache) {
    if (!cache) return;
    bank_v0_cache_restore(cache);
    if (cache->arena) {
        sol_arena_destroy(cache->arena);
        cache->arena = NULL;
    }
    sol_free(cache->patches);
    cache->patches = NULL;
    cache->patches_cap = 0;
}

/* Reset the cache for reuse: restore patched messages, then reset the arena.
 * This avoids per-slot allocations/free churn during replay. */
static void
bank_v0_cache_reset(bank_v0_resolve_cache_t* cache) {
    if (!cache) return;
    bank_v0_cache_restore(cache);
    if (cache->arena) {
        sol_arena_reset(cache->arena);
    }
}

uint64_t
sol_bank_calculate_fee(const sol_bank_t* bank, const sol_transaction_t* tx) {
    if (!bank || !tx) return 0;

    bool resolved_override = false;
    const sol_pubkey_t* saved_resolved_accounts = NULL;
    uint16_t saved_resolved_accounts_len = 0;
    bool* saved_is_writable = NULL;
    bool* saved_is_signer = NULL;
    sol_pubkey_t resolved_accounts[SOL_MAX_MESSAGE_ACCOUNTS];
    bool resolved_is_writable[SOL_MAX_MESSAGE_ACCOUNTS];
    bool resolved_is_signer[SOL_MAX_MESSAGE_ACCOUNTS];

    if (tx->message.version == SOL_MESSAGE_VERSION_V0 &&
        tx->message.resolved_accounts_len == 0) {
        uint16_t resolved_len = 0;
        sol_err_t resolve_err = bank_resolve_v0_message_accounts(bank,
                                                                 tx,
                                                                 resolved_accounts,
                                                                 resolved_is_writable,
                                                                 resolved_is_signer,
                                                                 SOL_MAX_MESSAGE_ACCOUNTS,
                                                                 &resolved_len);
        if (resolve_err != SOL_OK) {
            return 0;
        }

        sol_message_t* msg = (sol_message_t*)&tx->message;
        saved_resolved_accounts = msg->resolved_accounts;
        saved_resolved_accounts_len = msg->resolved_accounts_len;
        saved_is_writable = msg->is_writable;
        saved_is_signer = msg->is_signer;
        msg->resolved_accounts = resolved_accounts;
        msg->resolved_accounts_len = resolved_len;
        msg->is_writable = resolved_is_writable;
        msg->is_signer = resolved_is_signer;
        resolved_override = true;
    }

    uint64_t precompile_signatures = bank_count_precompile_signatures(tx);

    /* Base fee is deterministic per blockhash. */
    pthread_mutex_lock((pthread_mutex_t*)&bank->lock);
    bool recent_ok = bank_is_blockhash_valid_locked(bank, &tx->message.recent_blockhash);
    uint64_t lamports_per_signature = recent_ok
        ? bank_lamports_per_signature_for_blockhash_locked(bank, &tx->message.recent_blockhash)
        : bank->config.lamports_per_signature;
    pthread_mutex_unlock((pthread_mutex_t*)&bank->lock);

    if (!recent_ok) {
        uint64_t nonce_lamports_per_signature = 0;
        if (bank_try_get_durable_nonce_fee_calculator(bank, tx, &nonce_lamports_per_signature)) {
            lamports_per_signature = nonce_lamports_per_signature;
        }
    }

    uint64_t signature_fee_count = (uint64_t)tx->signatures_len + precompile_signatures;
    uint64_t fee = lamports_per_signature * signature_fee_count;

    /* Add prioritization fee from ComputeBudget instructions (if any) */
    sol_compute_budget_t budget;
    if (sol_compute_budget_parse(&budget, tx) == SOL_OK) {
        fee += sol_compute_budget_priority_fee(&budget);
    }

    if (resolved_override) {
        sol_message_t* msg = (sol_message_t*)&tx->message;
        msg->resolved_accounts = saved_resolved_accounts;
        msg->resolved_accounts_len = saved_resolved_accounts_len;
        msg->is_writable = saved_is_writable;
        msg->is_signer = saved_is_signer;
    }

    return fee;
}

static bool
bank_is_blockhash_valid_locked(const sol_bank_t* bank, const sol_hash_t* blockhash) {
    if (!bank || !blockhash) {
        return false;
    }

    if (__builtin_expect(bank->recent_blockhash_map != NULL, 1)) {
        return sol_map_get(bank->recent_blockhash_map, blockhash) != NULL;
    }

    for (size_t i = 0; i < bank->recent_blockhash_count; i++) {
        if (memcmp(bank->recent_blockhashes[i].hash.bytes,
                   blockhash->bytes, 32) == 0) {
            return true;
        }
    }
    return false;
}

static bool
bank_message_is_writable_resolved_index(const sol_message_t* msg, uint8_t index) {
    if (!msg) return false;
    if (msg->version == SOL_MESSAGE_VERSION_V0 &&
        msg->resolved_accounts_len != 0 &&
        msg->is_writable &&
        index < msg->resolved_accounts_len) {
        return msg->is_writable[index];
    }
    return sol_message_is_writable_index(msg, index);
}

static bool
bank_try_get_durable_nonce_fee_calculator(const sol_bank_t* bank,
                                          const sol_transaction_t* tx,
                                          uint64_t* out_lamports_per_signature) {
    if (out_lamports_per_signature) {
        *out_lamports_per_signature = 0;
    }
    if (!bank || !tx || !out_lamports_per_signature) {
        return false;
    }
    if (!bank->accounts_db) {
        return false;
    }

    const sol_message_t* msg = &tx->message;
    if (!msg->instructions || msg->instructions_len == 0) {
        return false;
    }
    if (!msg->resolved_accounts || msg->resolved_accounts_len == 0) {
        return false;
    }

    const sol_compiled_instruction_t* ix0 = NULL;
    for (uint8_t i = 0; i < msg->instructions_len; i++) {
        const sol_compiled_instruction_t* ix = &msg->instructions[i];
        if (ix->program_id_index >= msg->resolved_accounts_len) {
            return false;
        }
        const sol_pubkey_t* pid = &msg->resolved_accounts[ix->program_id_index];
        if (sol_pubkey_eq(pid, &SOL_COMPUTE_BUDGET_ID)) {
            continue;
        }
        ix0 = ix;
        break;
    }

    if (!ix0) {
        return false;
    }

    if (!ix0->data || ix0->data_len < 4) {
        return false;
    }
    if (ix0->program_id_index >= msg->resolved_accounts_len) {
        return false;
    }

    const sol_pubkey_t* program_id = &msg->resolved_accounts[ix0->program_id_index];
    if (!sol_pubkey_eq(program_id, &SOL_SYSTEM_PROGRAM_ID)) {
        return false;
    }

    uint32_t instr_type = 0;
    memcpy(&instr_type, ix0->data, 4);
    if (instr_type != SOL_SYSTEM_INSTR_ADVANCE_NONCE) {
        return false;
    }

    if (!ix0->account_indices || ix0->account_indices_len < 1) {
        return false;
    }

    uint8_t nonce_index = ix0->account_indices[0];
    if (nonce_index >= msg->resolved_accounts_len) {
        return false;
    }
    if (!bank_message_is_writable_resolved_index(msg, nonce_index)) {
        return false;
    }

    const sol_pubkey_t* nonce_pubkey = &msg->resolved_accounts[nonce_index];
    sol_account_t* nonce_account = sol_accounts_db_load(bank->accounts_db, nonce_pubkey);
    if (!nonce_account) {
        return false;
    }

    bool ok = false;
    if (sol_pubkey_eq(&nonce_account->meta.owner, &SOL_SYSTEM_PROGRAM_ID) &&
        nonce_account->meta.data_len >= SOL_NONCE_DATA_SIZE &&
        nonce_account->data) {
        sol_nonce_data_t nonce_data;
        memcpy(&nonce_data, nonce_account->data, sizeof(nonce_data));

        if (nonce_data.state == SOL_NONCE_STATE_INITIALIZED &&
            memcmp(nonce_data.blockhash.bytes,
                   msg->recent_blockhash.bytes,
                   SOL_HASH_SIZE) == 0 &&
            nonce_data.lamports_per_signature != 0) {
            *out_lamports_per_signature = nonce_data.lamports_per_signature;
            ok = true;
        }
    }

    sol_account_destroy(nonce_account);
    return ok;
}

static uint64_t
bank_lamports_per_signature_for_blockhash_locked(const sol_bank_t* bank,
                                                 const sol_hash_t* blockhash) {
    if (!bank || !blockhash) {
        return 0;
    }

    if (__builtin_expect(bank->recent_blockhash_map != NULL, 1)) {
        uint64_t* fee = (uint64_t*)sol_map_get(bank->recent_blockhash_map, blockhash);
        if (fee) {
            return *fee;
        }
        /* Fallback to current bank config if the blockhash isn't found. */
        return bank->config.lamports_per_signature;
    }

    for (size_t i = 0; i < bank->recent_blockhash_count; i++) {
        if (memcmp(bank->recent_blockhashes[i].hash.bytes,
                   blockhash->bytes, SOL_HASH_SIZE) == 0) {
            return bank->recent_blockhashes[i].fee_calculator;
        }
    }

    /* Fallback to current bank config if the blockhash isn't found. */
    return bank->config.lamports_per_signature;
}

bool
sol_bank_is_blockhash_valid(const sol_bank_t* bank, const sol_hash_t* blockhash) {
    if (!bank || !blockhash) return false;

    pthread_mutex_lock((pthread_mutex_t*)&bank->lock);
    bool valid = bank_is_blockhash_valid_locked(bank, blockhash);
    pthread_mutex_unlock((pthread_mutex_t*)&bank->lock);
    return valid;
}

bool
sol_bank_can_afford_fee(sol_bank_t* bank, const sol_pubkey_t* payer,
                        uint64_t fee) {
    if (!bank || !payer) return false;

    sol_account_t* account = sol_bank_load_account(bank, payer);
    if (!account) return false;

    bool can_afford = account->meta.lamports >= fee;
    sol_account_destroy(account);

    return can_afford;
}

sol_err_t
sol_bank_verify_hash_against_slot_hashes(sol_bank_t* bank, sol_slot_t slot, const sol_hash_t* hash) {
    if (!bank || !hash) {
        return SOL_ERR_INVAL;
    }

    if (__builtin_expect(bank->cached_slot_hashes_valid, 1)) {
        const sol_hash_t* expected = sol_slot_hashes_get(&bank->cached_slot_hashes, slot);
        if (!expected || !sol_hash_eq(expected, hash)) {
            return SOL_ERR_SLOT_HASH_MISMATCH;
        }
        return SOL_OK;
    }

    /* Slow path (should be rare): load+deserialize SlotHashes directly. Do NOT
     * populate the cache here to avoid races in the parallel transaction path. */
    sol_account_t* slot_hashes_account =
        sol_bank_load_account_view(bank, &SOL_SYSVAR_SLOT_HASHES_ID);
    if (!slot_hashes_account) {
        return SOL_ERR_SLOT_HASH_MISMATCH;
    }

    sol_slot_hashes_t slot_hashes;
    sol_slot_hashes_init(&slot_hashes);
    sol_err_t err = sol_slot_hashes_deserialize(
        &slot_hashes, slot_hashes_account->data, slot_hashes_account->meta.data_len);
    sol_account_destroy(slot_hashes_account);
    if (err != SOL_OK) {
        return err;
    }

    const sol_hash_t* expected = sol_slot_hashes_get(&slot_hashes, slot);
    if (!expected || !sol_hash_eq(expected, hash)) {
        return SOL_ERR_SLOT_HASH_MISMATCH;
    }
    return SOL_OK;
}

static void
fill_invoke_sysvars(sol_invoke_context_t* ctx, const sol_bank_t* bank) {
    if (!ctx || !bank) {
        return;
    }

    sol_clock_t clock;
    sol_clock_init(&clock);

    if (__builtin_expect(bank->cached_clock_valid, 1)) {
        clock = bank->cached_clock;
    } else if (bank->accounts_db) {
        /* Fallback (should be rare): load Clock sysvar from AccountsDB. */
        sol_account_t* clock_acct =
            sol_accounts_db_load(bank->accounts_db, &SOL_SYSVAR_CLOCK_ID);
        if (clock_acct && clock_acct->meta.data_len >= SOL_CLOCK_SIZE) {
            (void)sol_clock_deserialize(&clock, clock_acct->data, clock_acct->meta.data_len);
        } else {
            clock.slot = bank->slot;
            clock.epoch = bank->epoch;
            clock.unix_timestamp = unix_timestamp_for_slot(bank, bank->slot);
            uint64_t epoch_start_slot_u64 = 0;
            if (__builtin_mul_overflow((uint64_t)bank->epoch,
                                       bank->config.slots_per_epoch,
                                       &epoch_start_slot_u64)) {
                epoch_start_slot_u64 = 0;
            }
            clock.epoch_start_timestamp =
                (ulong)unix_timestamp_for_slot(bank, (sol_slot_t)epoch_start_slot_u64);
            clock.leader_schedule_epoch = clock.epoch;
        }
        sol_account_destroy(clock_acct);
    }
    ctx->clock = clock;

    sol_rent_t rent;
    sol_rent_init(&rent);
    rent.lamports_per_byte_year = bank->config.rent_per_byte_year;
    rent.exemption_threshold = (double)bank->config.rent_exemption_threshold;
    ctx->rent = rent;

    sol_epoch_schedule_t epoch_schedule;
    sol_epoch_schedule_init(&epoch_schedule);
    epoch_schedule.slots_per_epoch = bank->config.slots_per_epoch;
    ctx->epoch_schedule = epoch_schedule;

    ctx->lamports_per_signature = bank->config.lamports_per_signature;
}

static sol_err_t
store_sysvar_account(sol_bank_t* bank,
                     const sol_pubkey_t* pubkey,
                     const uint8_t* data,
                     size_t data_len) {
    if (!bank || !bank->accounts_db || !pubkey) {
        return SOL_ERR_INVAL;
    }

    sol_account_t* account = sol_accounts_db_load(bank->accounts_db, pubkey);
    if (!account) {
        /* Create missing sysvar account. For snapshot-based bootstraps these
         * should already exist, but allow tests/genesis to seed them. */
        account = sol_account_new(1, data_len, &SOL_SYSVAR_PROGRAM_ID);
        if (!account) {
            return SOL_ERR_NOMEM;
        }
    } else {
        /* Preserve existing meta (lamports/owner/rent_epoch). Only update data. */
        sol_err_t resize_err = sol_account_resize(account, data_len);
        if (resize_err != SOL_OK) {
            sol_account_destroy(account);
            return resize_err;
        }
    }

    if (data_len > 0 && data) {
        memcpy(account->data, data, data_len);
    }

    sol_err_t err = sol_bank_store_account(bank, pubkey, account);
    sol_account_destroy(account);
    return err;
}

static inline void
bank_set_instructions_sysvar_current(sol_account_t* account,
                                     uint16_t current_idx) {
    if (!account || !account->data) {
        return;
    }

    size_t len = (size_t)account->meta.data_len;
    if (len < 4u) {
        return;
    }

    uint16_t count = 0;
    memcpy(&count, account->data, 2);

    /* Current instruction index is stored in the header after the offset table. */
    size_t current_off = 2u + (size_t)count * 2u;
    if (len < current_off + 2u) {
        return;
    }
    memcpy(account->data + current_off, &current_idx, 2u);
}

static sol_err_t
bank_build_instructions_sysvar_override(sol_bank_t* bank,
                                        const sol_transaction_t* tx,
                                        const bool* demoted_is_writable,
                                        uint16_t demoted_is_writable_len,
                                        sol_account_t** out_account) {
    if (!bank || !bank->accounts_db || !tx || !out_account) {
        return SOL_ERR_INVAL;
    }

    /* Determine required buffer size. */
    uint8_t scratch[1];
    size_t needed = sizeof(scratch);
    sol_err_t err = sol_instructions_sysvar_serialize(tx, 0u,
                                                      demoted_is_writable,
                                                      demoted_is_writable_len,
                                                      scratch,
                                                      &needed);
    if (err != SOL_OK && err != SOL_ERR_INVAL) {
        return err;
    }

    /* Clone existing sysvar meta (lamports/owner/rent_epoch) when present. */
    sol_account_t* account =
        sol_accounts_db_load(bank->accounts_db, &SOL_SYSVAR_INSTRUCTIONS_ID);
    if (!account) {
        account = sol_account_new(1, needed, &SOL_SYSVAR_PROGRAM_ID);
        if (!account) {
            return SOL_ERR_NOMEM;
        }
    } else {
        sol_err_t resize_err = sol_account_resize(account, needed);
        if (resize_err != SOL_OK) {
            sol_account_destroy(account);
            return resize_err;
        }
    }

    /* Serialize directly into the tx-local override account. */
    size_t written = needed;
    err = sol_instructions_sysvar_serialize(tx, 0u,
                                            demoted_is_writable,
                                            demoted_is_writable_len,
                                            account->data,
                                            &written);
    if (err != SOL_OK) {
        sol_account_destroy(account);
        return err;
    }
    account->meta.data_len = (ulong)written;

    *out_account = account;
    return SOL_OK;
}

static sol_err_t
store_sysvar_account_if_needed(sol_bank_t* bank,
                               const sol_pubkey_t* pubkey,
                               const uint8_t* data,
                               size_t data_len,
                               bool overwrite_existing) {
    if (!bank || !bank->accounts_db || !pubkey) {
        return SOL_ERR_INVAL;
    }

    if (sol_accounts_db_exists(bank->accounts_db, pubkey)) {
        if (!overwrite_existing) {
            return SOL_OK;
        }

        /* Avoid rewriting unchanged sysvar accounts. Solana's bank hash depends
         * on the set of accounts written during a slot; rewriting constant
         * sysvars (Rent/EpochSchedule/etc.) would cause bank hash divergence. */
        sol_account_t* existing = sol_accounts_db_load(bank->accounts_db, pubkey);
        if (existing) {
            bool same_len = existing->meta.data_len == data_len;
            bool same_data = false;
            if (same_len) {
                if (data_len == 0) {
                    same_data = true;
                } else if (existing->data && data) {
                    same_data = memcmp(existing->data, data, data_len) == 0;
                }
            }
            if (!(same_len && same_data) && bank_sysvar_diag_enable()) {
                char pk_b58[SOL_PUBKEY_BASE58_LEN] = {0};
                sol_pubkey_to_base58(pubkey, pk_b58, sizeof(pk_b58));
                sol_log_warn("sysvar_data_mismatch: pubkey=%s old_len=%lu new_len=%lu",
                             pk_b58,
                             (unsigned long)existing->meta.data_len,
                             (unsigned long)data_len);
                if (data_len <= 64 && existing->data) {
                    char hex_old[200] = {0}, hex_new[200] = {0};
                    size_t min_len = existing->meta.data_len < data_len
                                   ? existing->meta.data_len : data_len;
                    for (size_t hi = 0; hi < min_len && hi < 64; hi++) {
                        snprintf(hex_old + hi*3, 4, "%02x ", existing->data[hi]);
                        snprintf(hex_new + hi*3, 4, "%02x ", data[hi]);
                    }
                    sol_log_warn("  existing: %s", hex_old);
                    sol_log_warn("  proposed: %s", hex_new);
                } else if (existing->data && same_len) {
                    /* For large sysvars, find first differing byte offset and dump context */
                    size_t first_diff = 0;
                    for (size_t di = 0; di < data_len; di++) {
                        if (existing->data[di] != data[di]) {
                            first_diff = di;
                            break;
                        }
                    }
                    size_t ctx_start = first_diff >= 16 ? first_diff - 16 : 0;
                    size_t ctx_end = first_diff + 48;
                    if (ctx_end > data_len) ctx_end = data_len;
                    char hex_old[200] = {0}, hex_new[200] = {0};
                    size_t hpos = 0;
                    for (size_t di = ctx_start; di < ctx_end && hpos < 190; di++) {
                        hpos += (size_t)snprintf(hex_old + hpos, 4, "%02x ", existing->data[di]);
                    }
                    hpos = 0;
                    for (size_t di = ctx_start; di < ctx_end && hpos < 190; di++) {
                        hpos += (size_t)snprintf(hex_new + hpos, 4, "%02x ", data[di]);
                    }
                    sol_log_warn("  first_diff_offset=%lu context[%lu..%lu]:",
                                 (unsigned long)first_diff,
                                 (unsigned long)ctx_start,
                                 (unsigned long)ctx_end);
                    sol_log_warn("  existing: %s", hex_old);
                    sol_log_warn("  proposed: %s", hex_new);
                }
            }
            sol_account_destroy(existing);
            if (same_len && same_data) {
                return SOL_OK;
            }
        }
    }

    return store_sysvar_account(bank, pubkey, data, data_len);
}

typedef struct {
    uint64_t epoch;
    const sol_stake_history_t* history;
    sol_stake_history_entry_t sum;
    sol_err_t err;
} stake_history_sum_ctx_t;

static bool
sum_stake_history_cb(const sol_pubkey_t* pubkey,
                     const sol_account_t* account,
                     void* ctx) {
    (void)pubkey;

    stake_history_sum_ctx_t* sctx = (stake_history_sum_ctx_t*)ctx;
    if (!sctx || !account) {
        return false;
    }

    if (account->meta.lamports == 0) {
        return true;
    }

    /* iterate_owner() should already filter by owner, but keep this defensively. */
    if (!sol_pubkey_eq(&account->meta.owner, &SOL_STAKE_PROGRAM_ID)) {
        return true;
    }

    sol_stake_state_t state;
    if (sol_stake_state_deserialize(&state, account->data,
                                    account->meta.data_len) != SOL_OK) {
        return true;
    }

    if (state.state != SOL_STAKE_STATE_STAKE) {
        return true;
    }

    sol_stake_activation_t status;
    sol_err_t err = sol_stake_get_activation_status(&state, sctx->epoch,
                                                    sctx->history, &status);
    if (err != SOL_OK) {
        sctx->err = err;
        return false;
    }

    if (__builtin_add_overflow(sctx->sum.effective, status.effective,
                               &sctx->sum.effective) ||
        __builtin_add_overflow(sctx->sum.activating, status.activating,
                               &sctx->sum.activating) ||
        __builtin_add_overflow(sctx->sum.deactivating, status.deactivating,
                               &sctx->sum.deactivating)) {
        sctx->err = SOL_ERR_OVERFLOW;
        return false;
    }

    return true;
}

static sol_err_t
compute_epoch_stake_history_entry(sol_bank_t* bank,
                                  uint64_t epoch,
                                  const sol_stake_history_t* history,
                                  sol_stake_history_entry_t* out_entry) {
    if (!bank || !out_entry) {
        return SOL_ERR_INVAL;
    }

    stake_history_sum_ctx_t ctx = {
        .epoch = epoch,
        .history = history,
        .sum = {0},
        .err = SOL_OK,
    };

    sol_accounts_db_iterate_owner(bank->accounts_db, &SOL_STAKE_PROGRAM_ID,
                                  sum_stake_history_cb, &ctx);

    if (ctx.err != SOL_OK) {
        return ctx.err;
    }

    *out_entry = ctx.sum;
    return SOL_OK;
}

static sol_err_t
refresh_sysvar_accounts(sol_bank_t* bank, bool overwrite_existing) {
    if (!bank) {
        return SOL_ERR_INVAL;
    }

    /* Clock
     *
     * When `overwrite_existing` is false, we only need to ensure the sysvar
     * exists. Avoid computing stake-weighted timestamps in that case because
     * the store helper will no-op on existing accounts anyway. */

    /* Cache the currently visible Clock sysvar once per bank. Many instructions
     * consult it and repeated AccountsDB loads are expensive. */
    sol_clock_t prev_clock;
    sol_clock_init(&prev_clock);
    bool have_prev_clock = false;
    if (bank->cached_clock_valid) {
        prev_clock = bank->cached_clock;
        have_prev_clock = true;
    } else {
        have_prev_clock = load_visible_clock_sysvar(bank, &prev_clock);
    }

    if (overwrite_existing ||
        !sol_accounts_db_exists(bank->accounts_db, &SOL_SYSVAR_CLOCK_ID)) {
        sol_clock_t clock;
        sol_clock_init(&clock);

        /* The Clock sysvar should be computed once per bank at slot boundary.
         * `refresh_sysvar_accounts()` is also called on the last tick to update
         * other sysvars (RecentBlockhashes, SlotHistory). Avoid recomputing the
         * timestamp after vote transactions have executed within this slot by
         * reusing the already-updated Clock sysvar when it matches this bank slot. */
        bool clock_already_updated = overwrite_existing &&
                                     have_prev_clock &&
                                     prev_clock.slot == bank->slot;

        if (clock_already_updated) {
            clock = prev_clock;
        } else {
            clock.slot = bank->slot;
            clock.epoch = bank->epoch;
            /* In Agave: leader_schedule_epoch = epoch_schedule.get_leader_schedule_epoch(slot)
             *         = get_epoch(slot + leader_schedule_slot_offset)
             * For mainnet (warmup=false), leader_schedule_slot_offset = slots_per_epoch */
            {
                sol_epoch_schedule_t es;
                sol_epoch_schedule_init(&es);
                es.slots_per_epoch = bank->config.slots_per_epoch;
                es.leader_schedule_slot_offset = es.slots_per_epoch;
                clock.leader_schedule_epoch = sol_slot_to_epoch(
                    &es, bank->slot + es.leader_schedule_slot_offset);
            }

            uint64_t ns_per_slot = bank_ns_per_slot(bank);
            if (ns_per_slot == 0) {
                ns_per_slot = (1000000000ULL * bank->config.ticks_per_slot) / SOL_DEFAULT_TICKS_PER_SECOND;
            }

            uint64_t epoch_start_slot_u64 = 0;
            if (__builtin_mul_overflow((uint64_t)bank->epoch,
                                       bank->config.slots_per_epoch,
                                       &epoch_start_slot_u64)) {
                epoch_start_slot_u64 = 0;
            }

            sol_slot_t epoch_start_slot = (sol_slot_t)epoch_start_slot_u64;
            bool is_epoch_start = bank->slot == epoch_start_slot;

            int64_t epoch_start_ts = 0;
            if (have_prev_clock &&
                prev_clock.epoch == bank->epoch &&
                prev_clock.epoch_start_timestamp != 0) {
                epoch_start_ts = prev_clock.epoch_start_timestamp;
            } else if (bank->genesis_creation_time_set) {
                epoch_start_ts = unix_timestamp_for_slot(bank, epoch_start_slot);
            } else if (have_prev_clock && prev_clock.epoch_start_timestamp != 0) {
                epoch_start_ts = prev_clock.epoch_start_timestamp;
            } else {
                epoch_start_ts = unix_timestamp_for_slot(bank, epoch_start_slot);
            }

        int64_t proposed_ts = 0;
        bool have_median = false;
        if (!bank_skip_instruction_exec()) {
            uint64_t total_stake = 0;
            sol_pubkey_map_t* vote_stakes =
                bank_get_vote_stakes_cached(bank, bank->epoch, &total_stake);
            if (vote_stakes && total_stake > 0 && ns_per_slot > 0) {
                have_median = stake_weighted_median_timestamp(bank, vote_stakes, ns_per_slot, &proposed_ts);
            }
        }

        if (!have_median) {
            proposed_ts = unix_timestamp_for_slot(bank, bank->slot);
        }

            /* Bound timestamp drift - asymmetric bounds matching Agave.
             * "Fast" drift (timestamp too low): max 25% deviation.
             * "Slow" drift (timestamp too high): max 150% deviation.
             * All arithmetic uses Duration (nanoseconds) with .as_secs()
             * integer truncation matching Agave's Rust Duration. */
            if (!is_epoch_start && ns_per_slot > 0) {
                sol_slot_t delta_slots = (bank->slot >= epoch_start_slot)
                    ? (bank->slot - epoch_start_slot)
                    : 0;

                __uint128_t poh_offset_ns =
                    (__uint128_t)(uint64_t)delta_slots * (__uint128_t)ns_per_slot;

                /* Agave: estimate_offset = Duration::from_secs(estimate as u64)
                 *          .checked_sub(Duration::from_secs(epoch_start_ts as u64))
                 * The cast to u64 matches fix_estimate_into_u64 feature. */
                uint64_t estimate_u64 = (uint64_t)proposed_ts;
                uint64_t epoch_start_u64 = (uint64_t)epoch_start_ts;

                if (estimate_u64 >= epoch_start_u64) {
                    __uint128_t estimate_offset_ns =
                        (__uint128_t)(estimate_u64 - epoch_start_u64) * 1000000000ULL;

                    if (estimate_offset_ns > poh_offset_ns) {
                        /* Timestamp ahead of PoH — slow drift limit (150%) */
                        __uint128_t max_slow_drift_ns = poh_offset_ns * 150 / 100;
                        if (estimate_offset_ns - poh_offset_ns > max_slow_drift_ns) {
                            /* Agave: epoch_start_ts + (poh_offset + max_slow_drift).as_secs() */
                            uint64_t clamped_secs = (uint64_t)(
                                (poh_offset_ns + max_slow_drift_ns) / 1000000000ULL);
                            proposed_ts = epoch_start_ts + (int64_t)clamped_secs;
                        }
                    } else {
                        /* Timestamp behind PoH — fast drift limit (25%) */
                        __uint128_t max_fast_drift_ns = poh_offset_ns * 25 / 100;
                        if (poh_offset_ns - estimate_offset_ns > max_fast_drift_ns) {
                            /* Agave: epoch_start_ts + poh_offset.as_secs() - max_fast_drift.as_secs() */
                            uint64_t poh_secs = (uint64_t)(poh_offset_ns / 1000000000ULL);
                            uint64_t fast_secs = (uint64_t)(max_fast_drift_ns / 1000000000ULL);
                            proposed_ts = epoch_start_ts + (int64_t)poh_secs - (int64_t)fast_secs;
                        }
                    }
                }
                /* If estimate < epoch_start, Agave's checked_sub returns None,
                 * meaning no clamping is applied. */
            }

            /* Time should never go backwards. */
            if (have_prev_clock && proposed_ts < prev_clock.unix_timestamp) {
                proposed_ts = prev_clock.unix_timestamp;
            }

            clock.unix_timestamp = proposed_ts;
            if (is_epoch_start) {
                clock.epoch_start_timestamp = proposed_ts;
            } else {
                clock.epoch_start_timestamp = epoch_start_ts;
            }

            if (bank_sysvar_diag_enable()) {
                sol_log_info("CLOCK_DIAG: slot=%lu epoch=%lu unix_ts=%ld epoch_start_ts=%ld leader_sched_epoch=%lu have_median=%d",
                             (unsigned long)clock.slot,
                             (unsigned long)clock.epoch,
                             (long)clock.unix_timestamp,
                             (long)clock.epoch_start_timestamp,
                             (unsigned long)clock.leader_schedule_epoch,
                             (int)have_median);
            }
        }

        uint8_t clock_data[SOL_CLOCK_SIZE];
        SOL_TRY(sol_clock_serialize(&clock, clock_data, sizeof(clock_data)));
        SOL_TRY(store_sysvar_account_if_needed(bank, &SOL_SYSVAR_CLOCK_ID,
                                               clock_data, sizeof(clock_data),
                                               overwrite_existing));

        bank->cached_clock = clock;
        bank->cached_clock_valid = true;
    } else {
        /* Clock exists and we intentionally did not recompute it. Use the
         * visible value as the bank's cached Clock. */
        if (have_prev_clock) {
            bank->cached_clock = prev_clock;
            bank->cached_clock_valid = true;
        }
    }

    /* Rent, EpochSchedule, and Fees are static sysvars that Agave only writes
     * at genesis (or during rare feature activations).  They must NOT be
     * re-stored during normal slot processing because any account store
     * participates in the accounts_lt_hash delta computation.  Only create
     * them when missing (overwrite_existing=false). */
    if (!overwrite_existing) {
        /* Rent — bincode serialized size is 17 (no #[repr(C)] padding). */
        sol_rent_t rent;
        sol_rent_init(&rent);
        rent.lamports_per_byte_year = bank->config.rent_per_byte_year;
        rent.exemption_threshold = (double)bank->config.rent_exemption_threshold;

        uint8_t rent_data[SOL_RENT_SERIALIZED_SIZE];
        SOL_TRY(sol_rent_serialize(&rent, rent_data, sizeof(rent_data)));
        SOL_TRY(store_sysvar_account_if_needed(bank, &SOL_SYSVAR_RENT_ID,
                                               rent_data, sizeof(rent_data),
                                               false));

        /* Epoch schedule — bincode serialized size is 33 (no #[repr(C)] padding). */
        sol_epoch_schedule_t epoch_schedule;
        sol_epoch_schedule_init(&epoch_schedule);
        epoch_schedule.slots_per_epoch = bank->config.slots_per_epoch;

        uint8_t epoch_schedule_data[SOL_EPOCH_SCHEDULE_SERIALIZED_SIZE];
        SOL_TRY(sol_epoch_schedule_serialize(&epoch_schedule, epoch_schedule_data,
                                             sizeof(epoch_schedule_data)));
        SOL_TRY(store_sysvar_account_if_needed(bank, &SOL_SYSVAR_EPOCH_SCHEDULE_ID,
                                               epoch_schedule_data,
                                               sizeof(epoch_schedule_data),
                                               false));

        /* Fees (deprecated but used by conformance + some programs) */
        sol_fees_t fees;
        sol_fees_init(&fees);
        fees.fee_calculator.lamports_per_signature = bank->config.lamports_per_signature;

        uint8_t fees_data[SOL_FEES_SIZE];
        SOL_TRY(sol_fees_serialize(&fees, fees_data, sizeof(fees_data)));
        SOL_TRY(store_sysvar_account_if_needed(bank, &SOL_SYSVAR_FEES_ID,
                                               fees_data, sizeof(fees_data),
                                               false));
    }

    /* Recent blockhashes — In Agave, the RecentBlockhashes sysvar is updated
     * at register_tick() on the last tick (block boundary), NOT at
     * new_from_parent().  Only create the sysvar if it doesn't exist yet
     * (genesis/test path).  The actual per-slot update happens in
     * update_recent_blockhashes_sysvar() called from sol_bank_register_tick(). */
    if (!overwrite_existing) {
        sol_recent_blockhashes_t rbh;
        sol_recent_blockhashes_init(&rbh);
        if (bank->recent_blockhash_count > SOL_MAX_RECENT_BLOCKHASHES) {
            return SOL_ERR_RANGE;
        }
        size_t sysvar_count = bank->recent_blockhash_count;
        if (sysvar_count > RECENT_BLOCKHASHES_SYSVAR_MAX_ENTRIES) {
            sysvar_count = RECENT_BLOCKHASHES_SYSVAR_MAX_ENTRIES;
        }
        rbh.len = sysvar_count;
        for (size_t i = 0; i < sysvar_count; i++) {
            rbh.entries[i].blockhash = bank->recent_blockhashes[i].hash;
            rbh.entries[i].fee_calculator.lamports_per_signature = bank->recent_blockhashes[i].fee_calculator;
        }

        size_t rbh_size = 8 + rbh.len * (32 + 8);
        uint8_t* rbh_data = sol_alloc(rbh_size);
        if (!rbh_data) {
            return SOL_ERR_NOMEM;
        }
        sol_err_t err = sol_recent_blockhashes_serialize(&rbh, rbh_data, rbh_size);
        if (err != SOL_OK) {
            sol_free(rbh_data);
            return err;
        }
        err = store_sysvar_account_if_needed(bank, &SOL_SYSVAR_RECENT_BLOCKHASHES_ID,
                                             rbh_data, rbh_size, false);
        sol_free(rbh_data);
        SOL_TRY(err);
    }

    /* Slot hashes: updated every slot, contains recent parent bank hashes. */
    {
        bool need_update =
            overwrite_existing ||
            !sol_accounts_db_exists(bank->accounts_db, &SOL_SYSVAR_SLOT_HASHES_ID);

        sol_slot_hashes_t slot_hashes;
        sol_slot_hashes_init(&slot_hashes);
        bool cache_valid = false;
        bool have_slot_hashes_base = false;

        if (bank->cached_slot_hashes_valid) {
            slot_hashes = bank->cached_slot_hashes;
            cache_valid = true;
            have_slot_hashes_base = true;
        }

        if (!have_slot_hashes_base) {
            sol_account_t* slot_hashes_acct =
                sol_accounts_db_load(bank->accounts_db, &SOL_SYSVAR_SLOT_HASHES_ID);
            if (slot_hashes_acct) {
                sol_err_t sh_err = sol_slot_hashes_deserialize(
                    &slot_hashes, slot_hashes_acct->data, slot_hashes_acct->meta.data_len);
                sol_account_destroy(slot_hashes_acct);
                if (sh_err == SOL_OK) {
                    cache_valid = true;
                } else if (need_update) {
                    /* If we're overwriting/creating anyway, treat corrupt/missing
                     * data as empty and proceed. */
                    sol_slot_hashes_init(&slot_hashes);
                    cache_valid = true;
                }
            } else if (need_update) {
                cache_valid = true;
            }
        }

        if (need_update) {
            if (bank->slot != 0 && !sol_hash_is_zero(&bank->parent_hash)) {
                (void)sol_slot_hashes_add(&slot_hashes, bank->parent_slot, &bank->parent_hash);
            }

            size_t slot_hashes_size = 8 + slot_hashes.len * (8 + 32);
            uint8_t* slot_hashes_data = sol_alloc(slot_hashes_size);
            if (!slot_hashes_data) {
                return SOL_ERR_NOMEM;
            }

            sol_err_t sh_ser_err =
                sol_slot_hashes_serialize(&slot_hashes, slot_hashes_data, slot_hashes_size);
            if (sh_ser_err != SOL_OK) {
                sol_free(slot_hashes_data);
                return sh_ser_err;
            }

            sol_err_t sh_store_err =
                store_sysvar_account(bank, &SOL_SYSVAR_SLOT_HASHES_ID,
                                     slot_hashes_data, slot_hashes_size);
            sol_free(slot_hashes_data);
            SOL_TRY(sh_store_err);

            /* We just (re)built it, so it's safe to cache. */
            cache_valid = true;
        }

        if (cache_valid) {
            bank->cached_slot_hashes = slot_hashes;
            bank->cached_slot_hashes_valid = true;
        } else {
            bank->cached_slot_hashes_valid = false;
        }
    }

    /* Slot history — In Agave, the SlotHistory sysvar is updated at freeze()
     * time, NOT at new_from_parent().  Only create the sysvar if missing
     * (genesis/test path).  The actual per-slot update happens in
     * update_slot_history_sysvar() called from sol_bank_freeze(). */
    if (!sol_accounts_db_exists(bank->accounts_db, &SOL_SYSVAR_SLOT_HISTORY_ID)) {
        uint8_t* slot_history_data = sol_alloc(SOL_SLOT_HISTORY_SIZE);
        if (!slot_history_data) {
            return SOL_ERR_NOMEM;
        }

        sol_err_t init_err =
            sol_slot_history_serialize_default(slot_history_data, SOL_SLOT_HISTORY_SIZE);
        if (init_err != SOL_OK) {
            sol_free(slot_history_data);
            return init_err;
        }

        sol_err_t store_err = store_sysvar_account(
            bank, &SOL_SYSVAR_SLOT_HISTORY_ID, slot_history_data, SOL_SLOT_HISTORY_SIZE);
        sol_free(slot_history_data);
        SOL_TRY(store_err);
    }

    /* StakeHistory sysvar: updated at the start of every epoch. Snapshot
     * loading may provide a populated sysvar; do not overwrite it unless we
     * are advancing epochs. */
    sol_stake_history_t stake_history;
    sol_stake_history_init(&stake_history);
    bool have_stake_history = false;

    sol_account_t* stake_history_acct =
        sol_accounts_db_load(bank->accounts_db, &SOL_SYSVAR_STAKE_HISTORY_ID);
    if (stake_history_acct && stake_history_acct->meta.data_len >= 8) {
        if (sol_stake_history_deserialize(&stake_history,
                                          stake_history_acct->data,
                                          stake_history_acct->meta.data_len) == SOL_OK) {
            have_stake_history = true;
        }
    }
    sol_account_destroy(stake_history_acct);

    if (!have_stake_history) {
        uint8_t empty_data[8];
        sol_stake_history_t empty;
        sol_stake_history_init(&empty);
        SOL_TRY(sol_stake_history_serialize(&empty, empty_data, sizeof(empty_data)));
        SOL_TRY(store_sysvar_account_if_needed(bank, &SOL_SYSVAR_STAKE_HISTORY_ID,
                                               empty_data, sizeof(empty_data),
                                               false));
        stake_history = empty;
        have_stake_history = true;
    }

    /* Only update once per bank at the slot boundary (during bank creation). */
    bool at_slot_start =
        overwrite_existing;
    bool is_epoch_start_slot =
        bank->config.slots_per_epoch > 0 &&
        ((uint64_t)bank->slot % bank->config.slots_per_epoch) == 0;

    if (at_slot_start && is_epoch_start_slot && bank->epoch > 0) {
        uint64_t prev_epoch = bank->epoch - 1;

        if (!sol_stake_history_get(&stake_history, prev_epoch)) {
            sol_stake_history_entry_t entry = {0};
            SOL_TRY(compute_epoch_stake_history_entry(bank, prev_epoch,
                                                      &stake_history, &entry));

            SOL_TRY(sol_stake_history_add(&stake_history, prev_epoch, &entry));

            size_t needed = 8 + stake_history.len * (8 + 24);
            uint8_t* data = sol_alloc(needed);
            if (!data) {
                return SOL_ERR_NOMEM;
            }

            sol_err_t ser_err =
                sol_stake_history_serialize(&stake_history, data, needed);
            if (ser_err != SOL_OK) {
                sol_free(data);
                return ser_err;
            }

            sol_err_t store_err =
                store_sysvar_account(bank, &SOL_SYSVAR_STAKE_HISTORY_ID,
                                     data, needed);
            sol_free(data);
            SOL_TRY(store_err);
        }
    }

    /* Instructions sysvar (empty placeholder; populated per-tx as needed).
     * In Agave, the Instructions sysvar is virtual/synthetic — injected via
     * AccountOverrides and never stored to the accounts DB.  Only create
     * the placeholder when missing. */
    if (!overwrite_existing) {
        uint8_t instructions_data[4] = {0};
        SOL_TRY(store_sysvar_account_if_needed(bank, &SOL_SYSVAR_INSTRUCTIONS_ID,
                                               instructions_data,
                                               sizeof(instructions_data),
                                               false));
    }

    return SOL_OK;
}

/* Update the RecentBlockhashes sysvar account in AccountsDB.
 * Called from register_tick() on the last tick (block boundary), matching
 * Agave's register_recent_blockhash() → update_recent_blockhashes_locked(). */
static sol_err_t
update_recent_blockhashes_sysvar(sol_bank_t* bank) {
    if (!bank || !bank->accounts_db) return SOL_ERR_INVAL;

    sol_recent_blockhashes_t rbh;
    sol_recent_blockhashes_init(&rbh);
    if (bank->recent_blockhash_count > SOL_MAX_RECENT_BLOCKHASHES) {
        return SOL_ERR_RANGE;
    }
    size_t sysvar_count = bank->recent_blockhash_count;
    if (sysvar_count > RECENT_BLOCKHASHES_SYSVAR_MAX_ENTRIES) {
        sysvar_count = RECENT_BLOCKHASHES_SYSVAR_MAX_ENTRIES;
    }
    rbh.len = sysvar_count;
    for (size_t i = 0; i < sysvar_count; i++) {
        rbh.entries[i].blockhash = bank->recent_blockhashes[i].hash;
        rbh.entries[i].fee_calculator.lamports_per_signature =
            bank->recent_blockhashes[i].fee_calculator;
    }

    size_t rbh_size = 8 + rbh.len * (32 + 8);
    uint8_t* rbh_data = sol_alloc(rbh_size);
    if (!rbh_data) {
        return SOL_ERR_NOMEM;
    }
    sol_err_t err = sol_recent_blockhashes_serialize(&rbh, rbh_data, rbh_size);
    if (err != SOL_OK) {
        sol_free(rbh_data);
        return err;
    }
    err = store_sysvar_account(bank, &SOL_SYSVAR_RECENT_BLOCKHASHES_ID,
                               rbh_data, rbh_size);
    sol_free(rbh_data);
    return err;
}

/* Update the SlotHistory sysvar account in AccountsDB.
 * Called from sol_bank_freeze(), matching Agave's update_slot_history(). */
static sol_err_t
update_slot_history_sysvar(sol_bank_t* bank) {
    if (!bank || !bank->accounts_db) return SOL_ERR_INVAL;

    sol_account_t* slot_history_acct =
        sol_accounts_db_load(bank->accounts_db, &SOL_SYSVAR_SLOT_HISTORY_ID);

    uint8_t* slot_history_data = NULL;
    size_t slot_history_len = 0;
    if (slot_history_acct) {
        slot_history_data = slot_history_acct->data;
        slot_history_len = slot_history_acct->meta.data_len;
    }

    uint8_t* fallback = NULL;
    if (!slot_history_data || slot_history_len < 16) {
        fallback = sol_alloc(SOL_SLOT_HISTORY_SIZE);
        if (!fallback) {
            sol_account_destroy(slot_history_acct);
            return SOL_ERR_NOMEM;
        }
        sol_err_t init_err =
            sol_slot_history_serialize_default(fallback, SOL_SLOT_HISTORY_SIZE);
        if (init_err != SOL_OK) {
            sol_free(fallback);
            sol_account_destroy(slot_history_acct);
            return init_err;
        }
        slot_history_data = fallback;
        slot_history_len = SOL_SLOT_HISTORY_SIZE;
    }

    sol_err_t err = sol_slot_history_add(slot_history_data, slot_history_len,
                                          bank->slot);
    if (err != SOL_OK) {
        sol_log_warn("Failed to update SlotHistory sysvar: %s", sol_err_str(err));
        sol_free(fallback);
        sol_account_destroy(slot_history_acct);
        return err;
    }

    err = store_sysvar_account(bank, &SOL_SYSVAR_SLOT_HISTORY_ID,
                               slot_history_data, slot_history_len);
    sol_free(fallback);
    sol_account_destroy(slot_history_acct);
    return err;
}

/*
 * Execute system program instruction
 */
/*
 * Execute a single instruction
 */
static inline void
invoke_ctx_reset_top_level(sol_invoke_context_t* ctx) {
    if (!ctx) return;
    /* Each top-level instruction starts a fresh CPI stack and has no prior
     * return data (Agave semantics). */
    ctx->stack_height = 1;
    ctx->compute_units_accounted = 0;
    ctx->return_data_len = 0;
    memset(&ctx->return_data_program, 0, sizeof(ctx->return_data_program));
}

static sol_err_t
execute_instruction_prepared(sol_invoke_context_t* ctx,
                             const sol_compiled_instruction_t* instr,
                             uint8_t instruction_index) {
    if (!ctx || !instr || !ctx->account_keys) {
        return SOL_ERR_INVAL;
    }

    if (instr->program_id_index >= ctx->account_keys_len) {
        return SOL_ERR_PROGRAM_NOT_FOUND;
    }

    /* Reset per-top-level-instruction context. */
    invoke_ctx_reset_top_level(ctx);

    ctx->account_indices = instr->account_indices;
    ctx->account_indices_len = instr->account_indices_len;
    ctx->instruction_data = instr->data;
    ctx->instruction_data_len = instr->data_len;
    ctx->program_id = ctx->account_keys[instr->program_id_index];
    ctx->current_instruction_index = instruction_index;

    return sol_program_execute(ctx);
}

static void
rollback_snapshot_restore(sol_bank_t* bank,
                          const sol_transaction_t* tx,
                          sol_account_t* const* rollback_accounts,
                          const uint8_t* rollback_mask,
                          const uint8_t* rollback_local_kinds,
                          size_t rollback_accounts_len) {
    if (!bank || !tx) {
        return;
    }

    const sol_pubkey_t* account_keys = tx->message.resolved_accounts_len
        ? tx->message.resolved_accounts
        : tx->message.account_keys;
    size_t account_keys_len = tx->message.resolved_accounts_len
        ? (size_t)tx->message.resolved_accounts_len
        : (size_t)tx->message.account_keys_len;

    bool overlay = rollback_local_kinds != NULL;

    for (size_t i = 0; i < rollback_accounts_len; i++) {
        if (!account_keys || i >= account_keys_len) {
            break;
        }
        const sol_pubkey_t* key = &account_keys[i];

        /* For non-snapshotted accounts, we still want to clean up any new local
         * overrides created during a failed transaction for accounts that were
         * NOT previously in the overlay. This prevents the overlay from
         * accumulating read-only entries on repeated failures. */
        if (rollback_mask && rollback_mask[i] == 0) {
            if (overlay && rollback_local_kinds) {
                sol_accounts_db_local_kind_t kind =
                    (sol_accounts_db_local_kind_t)rollback_local_kinds[i];
                if (kind == SOL_ACCOUNTS_DB_LOCAL_MISSING) {
                    (void)sol_accounts_db_clear_override(bank->accounts_db, key);
                }
            }
            continue; /* not snapshotted */
        }

        if (!overlay) {
            if (rollback_accounts && rollback_accounts[i]) {
                (void)sol_bank_store_account(bank, key, rollback_accounts[i]);
            } else {
                (void)bank_delete_account(bank, key);
            }
            continue;
        }

        sol_accounts_db_local_kind_t kind =
            (sol_accounts_db_local_kind_t)rollback_local_kinds[i];
        switch (kind) {
            case SOL_ACCOUNTS_DB_LOCAL_ACCOUNT:
                if (rollback_accounts && rollback_accounts[i]) {
                    (void)sol_bank_store_account(bank, key, rollback_accounts[i]);
                } else {
                    (void)sol_accounts_db_clear_override(bank->accounts_db, key);
                }
                break;
            case SOL_ACCOUNTS_DB_LOCAL_TOMBSTONE:
                (void)bank_delete_account(bank, key);
                break;
            case SOL_ACCOUNTS_DB_LOCAL_MISSING:
            default:
                (void)sol_accounts_db_clear_override(bank->accounts_db, key);
                break;
        }
    }
}

/* Advance the nonce account after a failed durable nonce transaction.
 * In Agave the nonce is pre-advanced during validation and the advanced
 * state persists even on failure (to prevent fee theft via replay).
 * This must be called AFTER rollback_snapshot_restore so the nonce
 * account is back to its pre-execution state. */
static void
advance_nonce_on_failure(sol_bank_t* bank, const sol_transaction_t* tx) {
    const sol_message_t* msg = &tx->message;
    if (!msg->instructions || msg->instructions_len == 0) return;
    if (!msg->resolved_accounts || msg->resolved_accounts_len == 0) return;

    /* Find the first non-ComputeBudget instruction (must be AdvanceNonce) */
    const sol_compiled_instruction_t* nonce_ix = NULL;
    for (uint8_t i = 0; i < msg->instructions_len; i++) {
        const sol_compiled_instruction_t* ix = &msg->instructions[i];
        if (ix->program_id_index >= msg->resolved_accounts_len) return;
        const sol_pubkey_t* pid = &msg->resolved_accounts[ix->program_id_index];
        if (sol_pubkey_eq(pid, &SOL_COMPUTE_BUDGET_ID)) continue;
        nonce_ix = ix;
        break;
    }
    if (!nonce_ix) return;
    if (!nonce_ix->account_indices || nonce_ix->account_indices_len < 1) return;

    uint8_t nonce_idx = nonce_ix->account_indices[0];
    if (nonce_idx >= msg->resolved_accounts_len) return;

    const sol_pubkey_t* nonce_pubkey = &msg->resolved_accounts[nonce_idx];
    sol_account_t* nonce_acct = sol_accounts_db_load(bank->accounts_db, nonce_pubkey);
    if (!nonce_acct) return;

    if (!sol_pubkey_eq(&nonce_acct->meta.owner, &SOL_SYSTEM_PROGRAM_ID) ||
        nonce_acct->meta.data_len < SOL_NONCE_DATA_SIZE ||
        !nonce_acct->data) {
        sol_account_destroy(nonce_acct);
        return;
    }

    sol_nonce_data_t nd;
    memcpy(&nd, nonce_acct->data, sizeof(nd));
    if (nd.state != SOL_NONCE_STATE_INITIALIZED) {
        sol_account_destroy(nonce_acct);
        return;
    }

    /* Compute DurableNonce = SHA256("DURABLE_NONCE" || bank_blockhash) */
    const sol_hash_t* bh = sol_bank_blockhash(bank);
    if (!bh) {
        sol_account_destroy(nonce_acct);
        return;
    }

    sol_sha256_ctx_t sha_ctx;
    sol_sha256_init(&sha_ctx);
    sol_sha256_update(&sha_ctx, "DURABLE_NONCE", 13);
    sol_sha256_update(&sha_ctx, bh->bytes, 32);
    sol_sha256_final_bytes(&sha_ctx, nd.blockhash.bytes);
    nd.lamports_per_signature = bank->config.lamports_per_signature;

    memcpy(nonce_acct->data, &nd, sizeof(nd));

    /* Fix rent_epoch for nonce account (same as Agave's collect_rent_from_account) */
    if (nonce_acct->meta.rent_epoch != UINT64_MAX &&
        nonce_acct->meta.lamports > 0 &&
        sol_account_is_rent_exempt(nonce_acct,
                                    bank->config.rent_per_byte_year,
                                    bank->config.rent_exemption_threshold)) {
        nonce_acct->meta.rent_epoch = UINT64_MAX;
    }

    (void)sol_bank_store_account(bank, nonce_pubkey, nonce_acct);
    sol_account_destroy(nonce_acct);
}

static void
rollback_snapshot_free(sol_account_t** rollback_accounts,
                       size_t rollback_accounts_len,
                       uint8_t* rollback_mask,
                       uint8_t* rollback_local_kinds) {
    for (size_t i = 0; i < rollback_accounts_len; i++) {
        if (rollback_accounts && rollback_accounts[i]) {
            sol_account_destroy(rollback_accounts[i]);
        }
    }
    sol_free(rollback_accounts);
    sol_free(rollback_mask);
    sol_free(rollback_local_kinds);
}

/* Debug: log the first N pre-validation rejections per bank */
static void
log_prevalidation_rejection(const sol_bank_t* bank,
                            const sol_transaction_t* tx,
                            const char* reason,
                            sol_err_t err) {
    /* This is expensive (base58 formatting); keep it at debug level. */
    if (sol_log_get_level() > SOL_LOG_DEBUG) {
        return;
    }

    uint64_t total_rejected =
        __atomic_load_n(&bank->stats.rejected_sanitize, __ATOMIC_RELAXED) +
        __atomic_load_n(&bank->stats.rejected_duplicate, __ATOMIC_RELAXED) +
        __atomic_load_n(&bank->stats.rejected_v0_resolve, __ATOMIC_RELAXED) +
        __atomic_load_n(&bank->stats.rejected_compute_budget, __ATOMIC_RELAXED) +
        __atomic_load_n(&bank->stats.rejected_blockhash, __ATOMIC_RELAXED) +
        __atomic_load_n(&bank->stats.rejected_fee_payer_missing, __ATOMIC_RELAXED) +
        __atomic_load_n(&bank->stats.rejected_insufficient_funds, __ATOMIC_RELAXED) +
        __atomic_load_n(&bank->stats.rejected_signature, __ATOMIC_RELAXED);
    if (total_rejected > 50) return; /* limit logging */

    const sol_signature_t* sig = sol_transaction_signature(tx);
    char sig_b58[128] = {0};
    if (sig) {
        sol_signature_to_base58(sig, sig_b58, sizeof(sig_b58));
    }
    /* Also log fee payer pubkey and blockhash for targeted diagnostics */
    char payer_b58[64] = {0};
    const sol_pubkey_t* fee_payer = sol_message_fee_payer(&tx->message);
    if (fee_payer) {
        sol_pubkey_to_base58(fee_payer, payer_b58, sizeof(payer_b58));
    }
    char bh_b58[64] = {0};
    sol_pubkey_to_base58((const sol_pubkey_t*)&tx->message.recent_blockhash,
                         bh_b58, sizeof(bh_b58));

    sol_log_debug("prevalidation_reject: slot=%lu reason=%s err=%d sig=%s nsigs=%u ver=%s payer=%s blockhash=%s",
                  (unsigned long)bank->slot,
                  reason, (int)err,
                  sig_b58[0] ? sig_b58 : "?",
                  (unsigned)tx->signatures_len,
                  tx->message.version == SOL_MESSAGE_VERSION_V0 ? "v0" : "legacy",
                  payer_b58[0] ? payer_b58 : "?",
                  bh_b58[0] ? bh_b58 : "?");
}

static sol_tx_result_t
sol_bank_process_transaction_impl(sol_bank_t* bank,
                                  const sol_transaction_t* tx,
                                  bool enable_tx_status_cache) {
    sol_tx_result_t result = {0};
    sol_compute_budget_t compute_budget = {0};
    sol_compute_meter_t compute_meter = {0};
    sol_err_t budget_err = SOL_OK;
    sol_account_t* tx_instructions_sysvar = NULL;
    bool resolved_override = false;
    const sol_pubkey_t* saved_resolved_accounts = NULL;
    uint16_t saved_resolved_accounts_len = 0;
    bool* saved_is_writable = NULL;
    bool* saved_is_signer = NULL;
    sol_pubkey_t resolved_accounts[SOL_MAX_MESSAGE_ACCOUNTS];
    bool resolved_is_writable[SOL_MAX_MESSAGE_ACCOUNTS];
    bool resolved_is_signer[SOL_MAX_MESSAGE_ACCOUNTS];
    sol_instruction_trace_t instruction_trace = {0};
    const sol_signature_t* tx_sig = NULL;
    bool reserved_tx_status = false;

    uint64_t slow_tx_thresh_ns = bank_slow_tx_threshold_ns();
    uint64_t slow_tx_t0 = slow_tx_thresh_ns ? bank_monotonic_ns() : 0;
    bool slow_tx_phase_diag = slow_tx_t0 && bank_slow_tx_phase_diag_enabled();
    uint8_t slow_tx_phase = 0u; /* 0=pre, 1=exec, 2=post */
    uint64_t slow_tx_phase_t0 = slow_tx_phase_diag ? slow_tx_t0 : 0u;
    uint64_t slow_tx_pre_ns = 0u;
    uint64_t slow_tx_exec_ns = 0u;
    uint64_t slow_tx_post_ns = 0u;
    uint64_t slow_tx_pre_mark_ns = slow_tx_phase_diag ? slow_tx_t0 : 0u;
    uint64_t slow_tx_pre_validate_ns = 0u;
    uint64_t slow_tx_pre_sanitize_ns = 0u;
    uint64_t slow_tx_pre_tx_status_reserve_ns = 0u;
    uint64_t slow_tx_pre_v0_resolve_ns = 0u;
    uint64_t slow_tx_pre_fee_payer_load_ns = 0u;
    uint64_t slow_tx_pre_sig_verify_ns = 0u;
    uint64_t slow_tx_pre_blockhash_fee_ns = 0u;
    uint64_t slow_tx_pre_payer_sig_ns = 0u;
    uint64_t slow_tx_pre_fee_commit_ns = 0u;
    uint64_t slow_tx_pre_setup_ns = 0u;
    uint64_t slow_tx_pre_setup_stage_t0 = 0u;
    uint64_t slow_tx_pre_setup_demote_ns = 0u;
    uint64_t slow_tx_pre_setup_instr_sysvar_ns = 0u;
    uint64_t slow_tx_pre_setup_undo_ns = 0u;
    uint64_t slow_tx_pre_setup_rent_fixup_ns = 0u;
    uint64_t slow_tx_pre_setup_invoke_ctx_ns = 0u;
    uint64_t slow_instr_thresh_ns = bank_slow_instr_threshold_ns();

    /* Clear TLS overrides in case the caller reuses a worker thread. */
    g_tls_instructions_sysvar = NULL;
    bank_prev_meta_hints_reset();
    bank_tx_undo_end();

    if (!bank || !tx) {
        result.status = SOL_ERR_INVAL;
        return result;
    }

    if (__atomic_load_n(&bank->frozen, __ATOMIC_ACQUIRE)) {
        result.status = SOL_ERR_SHUTDOWN;
        return result;
    }

    /* Transaction execution can be parallelized. Avoid holding the bank mutex
     * across instruction execution; only use it for tx-status bookkeeping. */
    BANK_FLAG_CLEAR(bank, hash_computed);
    BANK_FLAG_CLEAR(bank, accounts_delta_hash_computed);
    BANK_FLAG_CLEAR(bank, accounts_lt_hash_computed);

    BANK_STAT_INC(bank, transactions_processed);

    /* Basic transaction validation */
    uint64_t sanitize_t0 = slow_tx_phase_diag ? bank_monotonic_ns() : 0u;
    sol_err_t sanitize_err = sol_transaction_sanitize(tx);
    if (sanitize_t0) {
        slow_tx_pre_sanitize_ns += (bank_monotonic_ns() - sanitize_t0);
    }
    if (sanitize_err != SOL_OK) {
        result.status = sanitize_err;
        BANK_STAT_INC(bank, transactions_failed);
        BANK_STAT_INC(bank, rejected_sanitize);
        log_prevalidation_rejection(bank, tx, "sanitize", sanitize_err);
        goto unlock_and_return;
    }

    /* Reject duplicate transactions (in parallel processing this is handled
     * before execution to avoid lock contention in the hot path). */
    tx_sig = sol_transaction_signature(tx);
    if (enable_tx_status_cache && tx_sig) {
        uint64_t reserve_t0 = slow_tx_phase_diag ? bank_monotonic_ns() : 0u;
        bool reserve_ok = tx_status_reserve(bank, tx_sig);
        if (reserve_t0) {
            slow_tx_pre_tx_status_reserve_ns += (bank_monotonic_ns() - reserve_t0);
        }
        if (!reserve_ok) {
            result.status = SOL_ERR_TX_ALREADY_PROCESSED;
            BANK_STAT_INC(bank, transactions_failed);
            BANK_STAT_INC(bank, rejected_duplicate);
            log_prevalidation_rejection(bank, tx, "duplicate", SOL_ERR_TX_ALREADY_PROCESSED);
            goto unlock_and_return;
        }
        reserved_tx_status = true;
    }

    /* Agave's per-bank signature_count (hashed into the frozen bank-hash)
     * counts signatures for ALL non-duplicate sanitized transactions,
     * regardless of whether they pass subsequent pre-validation checks
     * (blockhash, fee payer, balance, etc.).  In Agave, signature_count
     * is computed from all SanitizedTransactions entering
     * load_and_execute_transactions, which is after dedup but before
     * blockhash/fee-payer/balance checks.  Precompile signature counts
     * are used for fee calculation but are *not* included here. */
    BANK_U64_ADD(bank, signature_count, (uint64_t)tx->signatures_len);

    if (tx->message.version == SOL_MESSAGE_VERSION_V0) {
        sol_message_t* msg = (sol_message_t*)&tx->message;
        uint16_t resolved_len = msg->resolved_accounts_len;

        bool have_cached =
            (resolved_len != 0 &&
             msg->resolved_accounts &&
             msg->is_writable &&
             msg->is_signer);

        if (!have_cached) {
            resolved_len = 0;
            uint64_t resolve_t0 = slow_tx_phase_diag ? bank_monotonic_ns() : 0u;
            sol_err_t resolve_err = bank_resolve_v0_message_accounts(bank,
                                                                     tx,
                                                                     resolved_accounts,
                                                                     resolved_is_writable,
                                                                     resolved_is_signer,
                                                                     SOL_MAX_MESSAGE_ACCOUNTS,
                                                                     &resolved_len);
            if (resolve_t0) {
                slow_tx_pre_v0_resolve_ns += (bank_monotonic_ns() - resolve_t0);
            }
            if (resolve_err != SOL_OK) {
                result.status = resolve_err;
                BANK_STAT_INC(bank, transactions_failed);
                BANK_STAT_INC(bank, rejected_v0_resolve);
                log_prevalidation_rejection(bank, tx, "v0_resolve", resolve_err);
                goto unlock_and_return;
            }

            /* Our invoke context uses u8 lengths. Bail out if the message is too large. */
            if (resolved_len > UINT8_MAX) {
                result.status = SOL_ERR_TX_TOO_LARGE;
                BANK_STAT_INC(bank, transactions_failed);
                BANK_STAT_INC(bank, rejected_v0_resolve);
                goto unlock_and_return;
            }

            /* Validate compiled instruction indices against resolved account keys. */
            for (uint8_t i = 0; i < tx->message.instructions_len; i++) {
                const sol_compiled_instruction_t* ix = &tx->message.instructions[i];
                if (ix->program_id_index >= resolved_len) {
                    result.status = SOL_ERR_TX_MALFORMED;
                    BANK_STAT_INC(bank, transactions_failed);
                    BANK_STAT_INC(bank, rejected_v0_resolve);
                    goto unlock_and_return;
                }
                for (uint8_t j = 0; j < ix->account_indices_len; j++) {
                    if (ix->account_indices[j] >= resolved_len) {
                        result.status = SOL_ERR_TX_MALFORMED;
                        BANK_STAT_INC(bank, transactions_failed);
                        BANK_STAT_INC(bank, rejected_v0_resolve);
                        goto unlock_and_return;
                    }
                }
            }

            /* Temporarily attach resolved keys/flags for execution. */
            saved_resolved_accounts = msg->resolved_accounts;
            saved_resolved_accounts_len = msg->resolved_accounts_len;
            saved_is_writable = msg->is_writable;
            saved_is_signer = msg->is_signer;
            msg->resolved_accounts = resolved_accounts;
            msg->resolved_accounts_len = resolved_len;
            msg->is_writable = resolved_is_writable;
            msg->is_signer = resolved_is_signer;
            resolved_override = true;
        } else {
            /* Cached resolution path: validate indices and continue. */
            if (resolved_len > UINT8_MAX) {
                result.status = SOL_ERR_TX_TOO_LARGE;
                BANK_STAT_INC(bank, transactions_failed);
                BANK_STAT_INC(bank, rejected_v0_resolve);
                goto unlock_and_return;
            }

            for (uint8_t i = 0; i < tx->message.instructions_len; i++) {
                const sol_compiled_instruction_t* ix = &tx->message.instructions[i];
                if (ix->program_id_index >= resolved_len) {
                    result.status = SOL_ERR_TX_MALFORMED;
                    BANK_STAT_INC(bank, transactions_failed);
                    BANK_STAT_INC(bank, rejected_v0_resolve);
                    goto unlock_and_return;
                }
                for (uint8_t j = 0; j < ix->account_indices_len; j++) {
                    if (ix->account_indices[j] >= resolved_len) {
                        result.status = SOL_ERR_TX_MALFORMED;
                        BANK_STAT_INC(bank, transactions_failed);
                        BANK_STAT_INC(bank, rejected_v0_resolve);
                        goto unlock_and_return;
                    }
                }
            }
        }
    }

    if (slow_tx_pre_mark_ns) {
        uint64_t now = bank_monotonic_ns();
        slow_tx_pre_validate_ns += (now - slow_tx_pre_mark_ns);
        slow_tx_pre_mark_ns = now;
    }

    /* 1. Verify blockhash is recent (and fetch lamports_per_signature). */
    bool recent_ok = false;
    uint64_t lamports_per_signature = bank->config.lamports_per_signature;
    if (bank->recent_blockhash_map) {
        uint64_t* fee = (uint64_t*)sol_map_get(bank->recent_blockhash_map, &tx->message.recent_blockhash);
        if (fee) {
            recent_ok = true;
            lamports_per_signature = *fee;
        }
    } else {
        /* Fallback (should be rare): linear scan. */
        recent_ok = bank_is_blockhash_valid_locked(bank, &tx->message.recent_blockhash);
        if (recent_ok) {
            lamports_per_signature =
                bank_lamports_per_signature_for_blockhash_locked(bank, &tx->message.recent_blockhash);
        }
    }

    uint64_t nonce_lamports_per_signature = 0;
    bool use_nonce_fee = false;
    if (!recent_ok) {
        if (bank_try_get_durable_nonce_fee_calculator(bank, tx, &nonce_lamports_per_signature)) {
            recent_ok = true;
            use_nonce_fee = true;
            lamports_per_signature = nonce_lamports_per_signature;
        }
    }
    if (!recent_ok) {
        result.status = SOL_ERR_TX_BLOCKHASH;
        BANK_STAT_INC(bank, transactions_failed);
        BANK_STAT_INC(bank, rejected_blockhash);
        log_prevalidation_rejection(bank, tx, "blockhash", SOL_ERR_TX_BLOCKHASH);
        goto unlock_and_return;
    }

    /* 2. Parse compute budget and initialize compute meter.
     * In Agave, CB parse errors (duplicate instructions, deprecated type 0)
     * are checked AFTER fee charging. Store the error and continue so that
     * fee deduction still occurs.
     *
     * Doing this after blockhash validation avoids work for transactions that
     * fail the blockhash check (common in some replay datasets). */
    budget_err = sol_compute_budget_parse(&compute_budget, tx);
    sol_compute_meter_init(&compute_meter, compute_budget.compute_unit_limit);

    /* 3. Calculate fee (deterministic per blockhash). */
    uint64_t precompile_signatures = bank_count_precompile_signatures(tx);

    uint64_t signature_fee_count = (uint64_t)tx->signatures_len + precompile_signatures;
    uint64_t base_fee = lamports_per_signature * signature_fee_count;
    uint64_t priority_fee = sol_compute_budget_priority_fee(&compute_budget);
    result.fee = base_fee + priority_fee;

    if (slow_tx_pre_mark_ns) {
        uint64_t now = bank_monotonic_ns();
        slow_tx_pre_blockhash_fee_ns += (now - slow_tx_pre_mark_ns);
        slow_tx_pre_mark_ns = now;
    }

    /* 4. Get fee payer */
    const sol_pubkey_t* fee_payer = sol_message_fee_payer(&tx->message);
    if (!fee_payer) {
        result.status = SOL_ERR_TX_MALFORMED;
        BANK_STAT_INC(bank, transactions_failed);
        BANK_STAT_INC(bank, rejected_fee_payer_missing);
        goto unlock_and_return;
    }

    /* 5. Check fee payer can afford fee */
    /* Fee payer data is not mutated (only lamports/rent_epoch), so avoid the
     * owned/copying load path (AppendVec pread) and use a view when possible. */
    uint64_t payer_load_t0 = slow_tx_phase_diag ? bank_monotonic_ns() : 0u;
    sol_account_t* payer_account = sol_bank_load_account_view(bank, fee_payer);
    if (payer_load_t0) {
        slow_tx_pre_fee_payer_load_ns += (bank_monotonic_ns() - payer_load_t0);
    }
    if (!payer_account) {
        result.status = SOL_ERR_TX_ACCOUNT_NOT_FOUND;
        BANK_STAT_INC(bank, transactions_failed);
        BANK_STAT_INC(bank, rejected_fee_payer_missing);
        if (bank_fee_payer_trace_enable()) {
            /* Debug: trace the chain to understand why account is missing. */
            char b58[45];
            sol_pubkey_to_base58(fee_payer, b58, sizeof(b58));
            sol_log_warn("FEE_PAYER_TRACE slot=%lu pubkey=%s",
                         (unsigned long)bank->slot, b58);
            sol_accounts_db_trace_load(bank->accounts_db, fee_payer);
        }
        log_prevalidation_rejection(bank, tx, "fee_payer_missing", SOL_ERR_TX_ACCOUNT_NOT_FOUND);
        goto unlock_and_return;
    }

    if (payer_account->meta.lamports < result.fee) {
        result.status = SOL_ERR_TX_INSUFFICIENT_FUNDS;
        BANK_STAT_INC(bank, transactions_failed);
        BANK_STAT_INC(bank, rejected_insufficient_funds);
        log_prevalidation_rejection(bank, tx, "insufficient_funds", SOL_ERR_TX_INSUFFICIENT_FUNDS);
        sol_account_destroy(payer_account);
        goto unlock_and_return;
    }

    /* 6. Verify signatures */
    BANK_STAT_ADD(bank, signatures_verified, (uint64_t)tx->signatures_len);

    if (!bank_skip_signature_verify() &&
        !g_tls_replay_signatures_preverified) {
        uint64_t sig_verify_t0 = slow_tx_phase_diag ? bank_monotonic_ns() : 0u;
        bool sig_ok = sol_transaction_verify_signatures(tx, NULL);
        if (sig_verify_t0) {
            slow_tx_pre_sig_verify_ns += (bank_monotonic_ns() - sig_verify_t0);
        }
        if (!sig_ok) {
            result.status = SOL_ERR_TX_SIGNATURE;
            BANK_STAT_INC(bank, transactions_failed);
            BANK_STAT_INC(bank, rejected_signature);
            log_prevalidation_rejection(bank, tx, "signature", SOL_ERR_TX_SIGNATURE);
            sol_account_destroy(payer_account);
            goto unlock_and_return;
        }
    }

    if (slow_tx_pre_mark_ns) {
        uint64_t now = bank_monotonic_ns();
        slow_tx_pre_payer_sig_ns += (now - slow_tx_pre_mark_ns);
        slow_tx_pre_mark_ns = now;
    }

    /* 6.5 Fix rent_epoch for fee payer.
     * In Agave, collect_rent_from_account() is called during account loading.
     * For rent-exempt accounts with rent_epoch != UINT64_MAX, it sets
     * rent_epoch to UINT64_MAX.  This must happen before fee deduction so the
     * rent-exemption check uses the pre-fee balance. */
    if (payer_account->meta.rent_epoch != UINT64_MAX &&
        payer_account->meta.lamports > 0 &&
        sol_account_is_rent_exempt(payer_account,
                                    bank->config.rent_per_byte_year,
                                    bank->config.rent_exemption_threshold)) {
        payer_account->meta.rent_epoch = UINT64_MAX;
    }

    /* 6. Deduct fee and check rent state transition (validate_fee_payer).
     * After deducting the fee, the fee payer must not transition into an
     * invalid rent state (e.g., RentExempt → RentPaying). */
    {
        uint64_t pre_lamports = payer_account->meta.lamports;
        size_t   payer_data_len = payer_account->meta.data_len;
        uint64_t rent_min = sol_account_rent_exempt_minimum(
            payer_data_len,
            bank->config.rent_per_byte_year,
            bank->config.rent_exemption_threshold);

        enum { RS_UNINIT, RS_RENT_PAYING, RS_RENT_EXEMPT } pre_rs, post_rs;
        if (pre_lamports == 0)           pre_rs = RS_UNINIT;
        else if (pre_lamports >= rent_min) pre_rs = RS_RENT_EXEMPT;
        else                              pre_rs = RS_RENT_PAYING;

        uint64_t post_lamports = pre_lamports - result.fee;
        if (post_lamports == 0)            post_rs = RS_UNINIT;
        else if (post_lamports >= rent_min) post_rs = RS_RENT_EXEMPT;
        else                                post_rs = RS_RENT_PAYING;

        bool fee_rent_ok;
        if (post_rs == RS_UNINIT || post_rs == RS_RENT_EXEMPT) {
            fee_rent_ok = true;
        } else {
            /* post_rs == RS_RENT_PAYING */
            fee_rent_ok = (pre_rs == RS_RENT_PAYING &&
                           post_lamports <= pre_lamports);
        }

        if (!fee_rent_ok) {
            result.status = SOL_ERR_TX_INSUFFICIENT_FUNDS_FOR_RENT;
            BANK_STAT_INC(bank, transactions_failed);
            sol_account_destroy(payer_account);
            goto unlock_and_return;
        }
    }

    payer_account->meta.lamports -= result.fee;
    uint64_t expected_post_fee_lamports = payer_account->meta.lamports;
    (void)sol_bank_store_account(bank, fee_payer, payer_account);
    sol_account_destroy(payer_account);

    BANK_STAT_ADD(bank, total_fees_collected, result.fee);
    BANK_STAT_ADD(bank, total_priority_fees_collected, priority_fee);

    /* Check deferred compute budget parse error AFTER fee deduction.
     * In Agave, DuplicateInstruction / InvalidInstructionData from the CB
     * processor still charges the fee but skips execution. */
    if (budget_err != SOL_OK) {
        result.status = budget_err;
        BANK_STAT_INC(bank, transactions_failed);
        BANK_STAT_INC(bank, rejected_compute_budget);
        log_prevalidation_rejection(bank, tx, "compute_budget", budget_err);
        goto unlock_and_return;
    }

    if (bank_skip_instruction_exec()) {
        /* Debug/analysis mode: stop after fee charging and signature counting.
         * This preserves signature_count semantics and helps isolate early
         * validation errors without executing programs. */
        result.status = SOL_OK;
        BANK_STAT_INC(bank, transactions_succeeded);
        goto unlock_and_return;
    }

    if (slow_tx_pre_mark_ns) {
        uint64_t now = bank_monotonic_ns();
        slow_tx_pre_fee_commit_ns += (now - slow_tx_pre_mark_ns);
        slow_tx_pre_mark_ns = now;
        slow_tx_pre_setup_stage_t0 = now;
    }

    /* 6.5 Prepare for instruction execution (after fee deduction). */
    const sol_pubkey_t* tx_account_keys = tx->message.resolved_accounts_len
        ? tx->message.resolved_accounts
        : tx->message.account_keys;
    size_t tx_account_keys_len = tx->message.resolved_accounts_len
        ? (size_t)tx->message.resolved_accounts_len
        : (size_t)tx->message.account_keys_len;

    /* Compute demoted is_writable flags matching Agave's SanitizedMessage::is_writable().
     * This is used for rollback snapshotting and other post-fee checks. */
    bool demoted_is_writable[SOL_MAX_MESSAGE_ACCOUNTS];
    memset(demoted_is_writable, 0, sizeof(demoted_is_writable));

    bool upgradeable_loader_present = false;
    for (size_t i = 0; i < tx_account_keys_len && i < SOL_MAX_MESSAGE_ACCOUNTS; i++) {
        if (sol_pubkey_eq(&tx_account_keys[i], &SOL_BPF_LOADER_UPGRADEABLE_ID)) {
            upgradeable_loader_present = true;
            break;
        }
    }

    for (size_t i = 0; i < tx_account_keys_len && i < SOL_MAX_MESSAGE_ACCOUNTS; i++) {
        bool raw_writable;
        if (tx->message.version == SOL_MESSAGE_VERSION_V0 &&
            tx->message.resolved_accounts_len != 0 &&
            tx->message.is_writable &&
            i < (size_t)tx->message.resolved_accounts_len) {
            raw_writable = tx->message.is_writable[i];
        } else {
            raw_writable = sol_message_is_writable_index(&tx->message, (uint8_t)i);
        }

        demoted_is_writable[i] = raw_writable;
        if (!raw_writable) continue;

        /* Fee payer (index 0) is always writable — skip demotion */
        if (i == 0) continue;

        /* Demote reserved account keys */
        if (is_reserved_account_key(&tx_account_keys[i])) {
            demoted_is_writable[i] = false;
            continue;
        }

        /* Demote program_id accounts when upgradeable loader not present */
        if (!upgradeable_loader_present) {
            for (uint8_t j = 0; j < tx->message.instructions_len; j++) {
                if (tx->message.instructions[j].program_id_index == (uint8_t)i) {
                    demoted_is_writable[i] = false;
                    break;
                }
            }
        }
    }

    if (slow_tx_pre_mark_ns) {
        uint64_t now = bank_monotonic_ns();
        slow_tx_pre_setup_demote_ns += (now - slow_tx_pre_mark_ns);
        slow_tx_pre_mark_ns = now;
    }

    /* The Instructions sysvar is virtual in Agave. Our implementation updates it
     * by storing a real account into AccountsDB, which is expensive. Only do so
     * when a program may actually read it (precompiles or explicitly passed as
     * an account). */
    bool needs_instructions_sysvar = false;
    for (size_t i = 0; i < tx_account_keys_len && i < SOL_MAX_MESSAGE_ACCOUNTS; i++) {
        if (sol_pubkey_eq(&tx_account_keys[i], &SOL_SYSVAR_INSTRUCTIONS_ID)) {
            needs_instructions_sysvar = true;
            break;
        }
    }
    if (!needs_instructions_sysvar) {
        for (uint8_t i = 0; i < tx->message.instructions_len; i++) {
            const sol_compiled_instruction_t* ix = &tx->message.instructions[i];
            if (!tx_account_keys || (size_t)ix->program_id_index >= tx_account_keys_len) continue;
            const sol_pubkey_t* pid = &tx_account_keys[ix->program_id_index];
            if (sol_pubkey_eq(pid, &SOL_ED25519_PROGRAM_ID) ||
                sol_pubkey_eq(pid, &SOL_SECP256K1_PROGRAM_ID) ||
                sol_pubkey_eq(pid, &SOL_SECP256R1_PROGRAM_ID)) {
                needs_instructions_sysvar = true;
                break;
            }
        }
    }

    /* Build a tx-local Instructions sysvar override if required. This avoids
     * a global mutable sysvar account (needed for parallel tx execution) and
     * eliminates per-instruction AccountsDB stores. */
    if (needs_instructions_sysvar) {
        sol_err_t sysvar_err = bank_build_instructions_sysvar_override(
            bank,
            tx,
            demoted_is_writable,
            (uint16_t)tx_account_keys_len,
            &tx_instructions_sysvar);
        if (sysvar_err != SOL_OK) {
            result.status = sysvar_err;
            result.compute_units_used = compute_meter.consumed;
            BANK_STAT_ADD(bank, compute_units_used, result.compute_units_used);
            BANK_STAT_INC(bank, transactions_failed);
            if (use_nonce_fee) advance_nonce_on_failure(bank, tx);
            goto unlock_and_return;
        }

        g_tls_instructions_sysvar = tx_instructions_sysvar;
    }

    if (slow_tx_pre_mark_ns) {
        uint64_t now = bank_monotonic_ns();
        slow_tx_pre_setup_instr_sysvar_ns += (now - slow_tx_pre_mark_ns);
        slow_tx_pre_mark_ns = now;
    }

    /* From here onward, account stores/deletes must be rollbackable if an
     * instruction fails. Use a tx-local undo log recorded on first write. */
    bank_tx_undo_begin(bank);

    if (slow_tx_pre_mark_ns) {
        uint64_t now = bank_monotonic_ns();
        slow_tx_pre_setup_undo_ns += (now - slow_tx_pre_mark_ns);
        slow_tx_pre_mark_ns = now;
    }

    /* Fix rent_epoch for all writable accounts before execution.
     * In Agave, collect_rent_from_account() is called during account loading
     * (before execution).  For rent-exempt accounts with rent_epoch !=
     * UINT64_MAX, it sets rent_epoch to UINT64_MAX.
     * The rollback snapshot was taken before this fixup, so on failure,
     * rollback correctly restores the accounts to their pre-fix state
     * (matching Agave, where only fee payer and nonce retain their fixup).
     * Skip fee payer (index 0) since it was already fixed above. */
    for (size_t ri = 1; ri < tx_account_keys_len; ri++) {
        if (ri < SOL_MAX_MESSAGE_ACCOUNTS && !demoted_is_writable[ri])
            continue;
        bool meta_found = false;
        uint64_t meta_lamports = 0;
        uint64_t meta_data_len = 0;
        uint64_t meta_rent_epoch = 0;
        sol_err_t meta_err =
            sol_accounts_db_lookup_visible_rent_meta(bank->accounts_db,
                                                     &tx_account_keys[ri],
                                                     &meta_found,
                                                     &meta_lamports,
                                                     &meta_data_len,
                                                     &meta_rent_epoch);
        if (meta_err == SOL_OK) {
            if (!meta_found || meta_lamports == 0 || meta_rent_epoch == UINT64_MAX) {
                continue;
            }
            if (meta_data_len <= (uint64_t)SIZE_MAX) {
                uint64_t rent_min = sol_account_rent_exempt_minimum(
                    (size_t)meta_data_len,
                    bank->config.rent_per_byte_year,
                    bank->config.rent_exemption_threshold);
                if (meta_lamports < rent_min) {
                    continue;
                }

                /* Only load an owned account when metadata indicates a possible fixup. */
                sol_account_t* wa = sol_bank_load_account(bank, &tx_account_keys[ri]);
                if (wa && wa->meta.lamports != 0 &&
                    wa->meta.rent_epoch != UINT64_MAX &&
                    sol_account_is_rent_exempt(wa,
                                              bank->config.rent_per_byte_year,
                                              bank->config.rent_exemption_threshold)) {
                    wa->meta.rent_epoch = UINT64_MAX;
                    (void)sol_bank_store_account(bank, &tx_account_keys[ri], wa);
                }
                if (wa) sol_account_destroy(wa);
                continue;
            }
            meta_err = SOL_ERR_TOO_LARGE;
        }

        /* Fallback path for transient metadata lookup failures. */
        if (meta_err != SOL_OK) {
            sol_account_t* wa_view = sol_bank_load_account_view(bank, &tx_account_keys[ri]);
            if (!wa_view || wa_view->meta.lamports == 0) {
                if (wa_view) sol_account_destroy(wa_view);
                continue;
            }

            bool needs_fix =
                (wa_view->meta.rent_epoch != UINT64_MAX) &&
                sol_account_is_rent_exempt(wa_view,
                                          bank->config.rent_per_byte_year,
                                          bank->config.rent_exemption_threshold);

            if (needs_fix) {
                if (!wa_view->data_borrowed) {
                    /* We already have an owned copy (e.g. overlay/in-memory). */
                    wa_view->meta.rent_epoch = UINT64_MAX;
                    (void)sol_bank_store_account(bank, &tx_account_keys[ri], wa_view);
                    sol_account_destroy(wa_view);
                    continue;
                }

                /* Borrowed view (AppendVec mmap). Reload an owned copy only when needed. */
                sol_account_destroy(wa_view);
                wa_view = NULL;

                sol_account_t* wa = sol_bank_load_account(bank, &tx_account_keys[ri]);
                if (wa && wa->meta.lamports != 0 &&
                    wa->meta.rent_epoch != UINT64_MAX &&
                    sol_account_is_rent_exempt(wa,
                                              bank->config.rent_per_byte_year,
                                              bank->config.rent_exemption_threshold)) {
                    wa->meta.rent_epoch = UINT64_MAX;
                    (void)sol_bank_store_account(bank, &tx_account_keys[ri], wa);
                }
                if (wa) sol_account_destroy(wa);
                continue;
            }

            sol_account_destroy(wa_view);
        }
    }

    if (slow_tx_pre_mark_ns) {
        uint64_t now = bank_monotonic_ns();
        slow_tx_pre_setup_rent_fixup_ns += (now - slow_tx_pre_mark_ns);
        slow_tx_pre_mark_ns = now;
    }

    /* Prepare an invoke context template once per transaction and reuse it for
     * all top-level instructions. This avoids re-deriving demoted writable and
     * signer flags per instruction (hot path). */
    bool local_is_signer[SOL_MAX_MESSAGE_ACCOUNTS];
    const bool* is_signer_view = NULL;
    if (tx->message.version == SOL_MESSAGE_VERSION_V0 &&
        tx->message.resolved_accounts_len != 0 &&
        tx->message.is_signer &&
        tx_account_keys_len == (size_t)tx->message.resolved_accounts_len) {
        is_signer_view = tx->message.is_signer;
    } else {
        for (size_t si = 0; si < tx_account_keys_len && si < SOL_MAX_MESSAGE_ACCOUNTS; si++) {
            local_is_signer[si] = sol_message_is_signer(&tx->message, (uint8_t)si);
        }
        is_signer_view = local_is_signer;
    }

    sol_invoke_context_t invoke_ctx = {
        .bank = bank,
        .account_keys = tx_account_keys,
        .account_keys_len = (uint8_t)tx_account_keys_len,
        .is_writable = demoted_is_writable,
        .is_signer = is_signer_view,
        .tx_signature = sol_transaction_signature(tx),
        .num_signers = tx->message.header.num_required_signatures,
        .stack_height = 1,
        .compute_budget = &compute_budget,
        .compute_meter = &compute_meter,
        .compute_units_accounted = 0,
        .transaction = tx,
        .current_instruction_index = 0,
        .instruction_trace = &instruction_trace,
    };
    fill_invoke_sysvars(&invoke_ctx, bank);

    if (slow_tx_pre_mark_ns) {
        uint64_t now = bank_monotonic_ns();
        slow_tx_pre_setup_invoke_ctx_ns += (now - slow_tx_pre_mark_ns);
        if (slow_tx_pre_setup_stage_t0) {
            slow_tx_pre_setup_ns += (now - slow_tx_pre_setup_stage_t0);
        }
        slow_tx_pre_mark_ns = now;
    }

    /* 7. Execute instructions */
    if (slow_tx_phase_t0) {
        uint64_t now = bank_monotonic_ns();
        slow_tx_pre_ns += (now - slow_tx_phase_t0);
        slow_tx_phase = 1u;
        slow_tx_phase_t0 = now;
    }
    for (uint8_t i = 0; i < tx->message.instructions_len; i++) {
        const sol_compiled_instruction_t* instr = &tx->message.instructions[i];
        if (tx_instructions_sysvar) {
            bank_set_instructions_sysvar_current(tx_instructions_sysvar, (uint16_t)i);
        }

        uint64_t instr_t0 = slow_instr_thresh_ns ? bank_monotonic_ns() : 0u;
        uint64_t cu_before = compute_meter.consumed;
        sol_err_t instr_err = execute_instruction_prepared(&invoke_ctx, instr, i);
        if (instr_t0) {
            uint64_t instr_ns = bank_monotonic_ns() - instr_t0;
            if (instr_ns >= slow_instr_thresh_ns) {
                char sig_b58[SOL_SIGNATURE_BASE58_LEN] = {0};
                if (tx_sig) {
                    sol_signature_to_base58(tx_sig, sig_b58, sizeof(sig_b58));
                }

                const sol_pubkey_t* pid = NULL;
                if (tx_account_keys &&
                    (size_t)instr->program_id_index < tx_account_keys_len) {
                    pid = &tx_account_keys[instr->program_id_index];
                }
                char pid_b58[SOL_PUBKEY_BASE58_LEN] = {0};
                if (pid) {
                    sol_pubkey_to_base58(pid, pid_b58, sizeof(pid_b58));
                }

                uint64_t cu_after = compute_meter.consumed;
                uint64_t cu_delta = (cu_after >= cu_before) ? (cu_after - cu_before) : 0u;
                sol_log_info("SLOW_INSTR: slot=%lu ix=%u dur_ms=%.3f cu_before=%lu cu_after=%lu cu_delta=%lu err=%d program=%s sig=%s data_len=%u accs=%u",
                             (unsigned long)bank->slot,
                             (unsigned)i,
                             (double)instr_ns / 1e6,
                             (unsigned long)cu_before,
                             (unsigned long)cu_after,
                             (unsigned long)cu_delta,
                             instr_err,
                             pid_b58[0] ? pid_b58 : "unknown",
                             sig_b58[0] ? sig_b58 : "none",
                             (unsigned)instr->data_len,
                             (unsigned)instr->account_indices_len);
            }
        }
        if (instr_err != SOL_OK) {
            result.status = instr_err;
            result.compute_units_used = compute_meter.consumed;
            BANK_STAT_ADD(bank, compute_units_used, result.compute_units_used);
            BANK_STAT_INC(bank, transactions_failed);

            /* Log execution failure details for debugging */
            {
                const sol_pubkey_t* account_keys_dbg = tx->message.resolved_accounts_len
                    ? tx->message.resolved_accounts : tx->message.account_keys;
                uint16_t account_keys_len_dbg = tx->message.resolved_accounts_len
                    ? tx->message.resolved_accounts_len : (uint16_t)tx->message.account_keys_len;
                const char* prog_b58 = "unknown";
                char prog_buf[SOL_PUBKEY_BASE58_LEN] = {0};
                if (instr->program_id_index < account_keys_len_dbg) {
                    sol_pubkey_to_base58(&account_keys_dbg[instr->program_id_index],
                                        prog_buf, sizeof(prog_buf));
                    prog_b58 = prog_buf;
                }
                const sol_signature_t* dbg_sig = sol_transaction_signature(tx);
                char sig_b58[SOL_SIGNATURE_BASE58_LEN] = {0};
                if (dbg_sig) {
                    sol_signature_to_base58(dbg_sig, sig_b58, sizeof(sig_b58));
                }
                sol_log_debug("execution_failed: slot=%lu instr=%u program=%s err=%d(%s) "
                             "cu=%lu sig=%s",
                             (unsigned long)bank->slot, (unsigned)i, prog_b58,
                             instr_err, sol_err_str(instr_err),
                             (unsigned long)compute_meter.consumed,
                             sig_b58[0] ? sig_b58 : "none");
            }
            /* Roll back all account writes from this transaction. */
            bank_tx_undo_rollback(bank);
            if (use_nonce_fee) advance_nonce_on_failure(bank, tx);

            goto unlock_and_return;
        }
    }

    if (slow_tx_phase_t0) {
        uint64_t now = bank_monotonic_ns();
        slow_tx_exec_ns += (now - slow_tx_phase_t0);
        slow_tx_phase = 2u;
        slow_tx_phase_t0 = now;
    }

    /* Post-execution rent state transition check (InsufficientFundsForRent).
     *
     * The exact Agave logic checks all writable accounts in the message. We can
     * safely restrict this to accounts that were actually written during this
     * transaction (i.e., entries in the undo log). An account that did not have
     * any store/delete cannot have changed lamports/data_len, so it cannot have
     * transitioned into an invalid rent state. */
    {
        sol_err_t rent_err = SOL_OK;
        uint8_t rent_fail_index = 0;
        sol_pubkey_t rent_fail_key = {0};
        uint64_t rent_pre_lamports = 0;
        size_t rent_pre_data_len = 0;
        uint64_t rent_post_lamports = 0;
        size_t rent_post_data_len = 0;

        const bank_tx_undo_log_t* undo = &g_tls_tx_undo;
        for (size_t ui = 0; ui < undo->len; ui++) {
            const bank_tx_undo_entry_t* ue = &undo->entries[ui];

            /* Find key in message account list (for writability). */
            size_t ri = (size_t)-1;
            for (size_t ti = 0; ti < tx_account_keys_len && ti < SOL_MAX_MESSAGE_ACCOUNTS; ti++) {
                if (sol_pubkey_eq(&tx_account_keys[ti], &ue->key)) {
                    ri = ti;
                    break;
                }
            }
            if (ri == (size_t)-1) continue;
            if (ri < SOL_MAX_MESSAGE_ACCOUNTS && !demoted_is_writable[ri]) continue;

            /* Skip the incinerator account */
            if (sol_pubkey_eq(&ue->key, &SOL_INCINERATOR_ID)) continue;

            uint64_t pre_lamports = 0;
            size_t pre_data_len = 0;

            if (ue->kind == BANK_TX_UNDO_KIND_ACCOUNT && ue->account) {
                pre_lamports = ue->account->meta.lamports;
                pre_data_len = ue->account->meta.data_len;
            } else if (ue->kind == BANK_TX_UNDO_KIND_TOMBSTONE) {
                pre_lamports = 0;
                pre_data_len = 0;
            } else {
                if (undo->overlay) {
                    bank_prev_meta_hint_t prev = {0};
                    if (bank_prev_meta_hints_get(&ue->key, &prev)) {
                        pre_lamports = prev.lamports;
                        pre_data_len = prev.data_len;
                    } else {
                        sol_accounts_db_t* parent_db = sol_accounts_db_get_parent(bank->accounts_db);
                        sol_account_t* pre_acc = parent_db ? sol_accounts_db_load_view(parent_db, &ue->key) : NULL;
                        if (pre_acc) {
                            pre_lamports = pre_acc->meta.lamports;
                            pre_data_len = pre_acc->meta.data_len;
                            sol_account_destroy(pre_acc);
                        }
                    }
                }
            }

            uint64_t post_lamports = 0;
            size_t post_data_len = 0;
            sol_pubkey_t post_owner = (sol_pubkey_t){{0}};
            bool post_executable = false;
            if (ue->post_valid) {
                post_lamports = ue->post_lamports;
                post_data_len = ue->post_data_len;
                post_owner = ue->post_owner;
                post_executable = ue->post_executable != 0;
            } else {
                /* Defensive fallback: should not happen for undo-tracked writes. */
                sol_account_t* post_acc = sol_accounts_db_load_view(bank->accounts_db, &ue->key);
                if (post_acc) {
                    post_lamports = post_acc->meta.lamports;
                    post_data_len = post_acc->meta.data_len;
                    post_owner = post_acc->meta.owner;
                    post_executable = post_acc->meta.executable;
                    sol_account_destroy(post_acc);
                }
            }

            uint64_t rent_per_byte = bank->config.rent_per_byte_year;
            uint64_t rent_thresh   = bank->config.rent_exemption_threshold;
            uint64_t pre_min = sol_account_rent_exempt_minimum(pre_data_len,
                                                               rent_per_byte,
                                                               rent_thresh);
            uint64_t post_min = sol_account_rent_exempt_minimum(post_data_len,
                                                                rent_per_byte,
                                                                rent_thresh);

            enum { RS_UNINIT, RS_RENT_PAYING, RS_RENT_EXEMPT } pre_state, post_state;
            if (pre_lamports == 0)           pre_state = RS_UNINIT;
            else if (pre_lamports >= pre_min) pre_state = RS_RENT_EXEMPT;
            else                              pre_state = RS_RENT_PAYING;

            if (post_lamports == 0)            post_state = RS_UNINIT;
            else if (post_lamports >= post_min) post_state = RS_RENT_EXEMPT;
            else                                post_state = RS_RENT_PAYING;

            bool transition_ok;
            if (post_state == RS_UNINIT || post_state == RS_RENT_EXEMPT) {
                transition_ok = true;
            } else {
                /* Prevent transactions from creating rent-paying accounts
                 * with data (or changing a rent-exempt account into rent-paying).
                 *
                 * Exception: system-owned, non-executable, zero-data "dust"
                 * accounts can be created via SystemProgram::Transfer. */
                bool is_system_dust =
                    (pre_state == RS_UNINIT) &&
                    (post_data_len == 0) &&
                    (!post_executable) &&
                    sol_pubkey_eq(&post_owner, &SOL_SYSTEM_PROGRAM_ID);

                bool was_rent_paying_no_resize =
                    (pre_state == RS_RENT_PAYING) &&
                    (post_data_len == pre_data_len);

                transition_ok = is_system_dust || was_rent_paying_no_resize;
            }

            if (!transition_ok) {
                rent_err = SOL_ERR_TX_INSUFFICIENT_FUNDS_FOR_RENT;
                rent_fail_index = (uint8_t)ri;
                rent_fail_key = ue->key;
                rent_pre_lamports = pre_lamports;
                rent_pre_data_len = pre_data_len;
                rent_post_lamports = post_lamports;
                rent_post_data_len = post_data_len;
                break;
            }
        }

        if (rent_err != SOL_OK) {
            result.status = rent_err;
            result.compute_units_used = compute_meter.consumed;
            BANK_STAT_ADD(bank, compute_units_used, result.compute_units_used);
            BANK_STAT_INC(bank, transactions_failed);

            if (bank_rent_diag_enable()) {
                const sol_signature_t* rent_sig = sol_transaction_signature(tx);
                char rent_sig_b58[SOL_SIGNATURE_BASE58_LEN] = {0};
                if (rent_sig) sol_signature_to_base58(rent_sig, rent_sig_b58, sizeof(rent_sig_b58));
                char acct_b58[45] = {0};
                sol_pubkey_to_base58(&rent_fail_key, acct_b58, sizeof(acct_b58));
                sol_log_info("rent_state_check_failed: slot=%lu account_index=%u sig=%s "
                             "account=%s pre_lamports=%lu pre_data_len=%zu "
                             "post_lamports=%lu post_data_len=%zu is_writable=%d",
                             (unsigned long)bank->slot, (unsigned)rent_fail_index,
                             rent_sig_b58[0] ? rent_sig_b58 : "none",
                             acct_b58,
                             (unsigned long)rent_pre_lamports,
                             rent_pre_data_len,
                             (unsigned long)rent_post_lamports,
                             rent_post_data_len,
                             (int)((rent_fail_index < SOL_MAX_MESSAGE_ACCOUNTS)
                                   ? demoted_is_writable[rent_fail_index]
                                   : 0));
            }

            /* Roll back all account writes from this transaction. */
            bank_tx_undo_rollback(bank);
            if (use_nonce_fee) advance_nonce_on_failure(bank, tx);
            goto unlock_and_return;
        }
    }

    /* Success */
    result.status = SOL_OK;
    result.compute_units_used = compute_meter.consumed;
    BANK_STAT_ADD(bank, compute_units_used, result.compute_units_used);
    BANK_STAT_INC(bank, transactions_succeeded);

    /* Instructions sysvar is tx-local and provided via TLS override (not stored
     * into AccountsDB), so no post-tx cleanup is necessary here. */

    goto unlock_and_return;

unlock_and_return:
    sol_instruction_trace_destroy(&instruction_trace);
    g_tls_instructions_sysvar = NULL;
    bank_prev_meta_hints_reset();
    bank_tx_undo_end();
    if (tx_instructions_sysvar) {
        sol_account_destroy(tx_instructions_sysvar);
        tx_instructions_sysvar = NULL;
    }
    if (resolved_override) {
        sol_message_t* msg = (sol_message_t*)&tx->message;
        msg->resolved_accounts = saved_resolved_accounts;
        msg->resolved_accounts_len = saved_resolved_accounts_len;
        msg->is_writable = saved_is_writable;
        msg->is_signer = saved_is_signer;
    }

    /* Update the reserved tx-status entry for all non-duplicate sanitized txs,
     * including early-exit paths like SOL_SKIP_INSTRUCTION_EXEC. */
    if (enable_tx_status_cache && reserved_tx_status && tx_sig) {
        sol_bank_record_tx_status(bank,
                                  tx_sig,
                                  result.status,
                                  result.fee,
                                  result.compute_units_used);
    }

    if (slow_tx_phase_t0) {
        uint64_t now = bank_monotonic_ns();
        if (slow_tx_phase == 0u) {
            slow_tx_pre_ns += (now - slow_tx_phase_t0);
        } else if (slow_tx_phase == 1u) {
            slow_tx_exec_ns += (now - slow_tx_phase_t0);
        } else {
            slow_tx_post_ns += (now - slow_tx_phase_t0);
        }
        slow_tx_phase_t0 = 0u;
    }

    if (slow_tx_t0) {
        uint64_t dt_ns = bank_monotonic_ns() - slow_tx_t0;
        if (dt_ns >= slow_tx_thresh_ns) {
            char sig_b58[SOL_SIGNATURE_BASE58_LEN] = {0};
            if (tx_sig) {
                sol_signature_to_base58(tx_sig, sig_b58, sizeof(sig_b58));
            }

            const sol_pubkey_t* payer = sol_message_fee_payer(&tx->message);
            char payer_b58[SOL_PUBKEY_BASE58_LEN] = {0};
            if (payer) {
                sol_pubkey_to_base58(payer, payer_b58, sizeof(payer_b58));
            }

            if (slow_tx_phase_diag) {
                sol_log_info("SLOW_TX: slot=%lu dur_ms=%.3f pre_ms=%.3f pre_validate_ms=%.3f pre_sanitize_ms=%.3f pre_tx_status_reserve_ms=%.3f pre_v0_resolve_ms=%.3f pre_blockhash_fee_ms=%.3f pre_fee_payer_load_ms=%.3f pre_sig_verify_ms=%.3f pre_payer_sig_ms=%.3f pre_fee_commit_ms=%.3f pre_setup_ms=%.3f pre_setup_demote_ms=%.3f pre_setup_instr_sysvar_ms=%.3f pre_setup_undo_ms=%.3f pre_setup_rent_fixup_ms=%.3f pre_setup_invoke_ctx_ms=%.3f exec_ms=%.3f post_ms=%.3f err=%d cu=%lu fee=%lu payer=%s sig=%s",
                             (unsigned long)bank->slot,
                             (double)dt_ns / 1e6,
                             (double)slow_tx_pre_ns / 1e6,
                             (double)slow_tx_pre_validate_ns / 1e6,
                             (double)slow_tx_pre_sanitize_ns / 1e6,
                             (double)slow_tx_pre_tx_status_reserve_ns / 1e6,
                             (double)slow_tx_pre_v0_resolve_ns / 1e6,
                             (double)slow_tx_pre_blockhash_fee_ns / 1e6,
                             (double)slow_tx_pre_fee_payer_load_ns / 1e6,
                             (double)slow_tx_pre_sig_verify_ns / 1e6,
                             (double)slow_tx_pre_payer_sig_ns / 1e6,
                             (double)slow_tx_pre_fee_commit_ns / 1e6,
                             (double)slow_tx_pre_setup_ns / 1e6,
                             (double)slow_tx_pre_setup_demote_ns / 1e6,
                             (double)slow_tx_pre_setup_instr_sysvar_ns / 1e6,
                             (double)slow_tx_pre_setup_undo_ns / 1e6,
                             (double)slow_tx_pre_setup_rent_fixup_ns / 1e6,
                             (double)slow_tx_pre_setup_invoke_ctx_ns / 1e6,
                             (double)slow_tx_exec_ns / 1e6,
                             (double)slow_tx_post_ns / 1e6,
                             result.status,
                             (unsigned long)result.compute_units_used,
                             (unsigned long)result.fee,
                             payer_b58[0] ? payer_b58 : "none",
                             sig_b58[0] ? sig_b58 : "none");
            } else {
                sol_log_info("SLOW_TX: slot=%lu dur_ms=%.3f err=%d cu=%lu fee=%lu payer=%s sig=%s",
                             (unsigned long)bank->slot,
                             (double)dt_ns / 1e6,
                             result.status,
                             (unsigned long)result.compute_units_used,
                             (unsigned long)result.fee,
                             payer_b58[0] ? payer_b58 : "none",
                             sig_b58[0] ? sig_b58 : "none");
            }
        }
    }

    /* Log per-transaction result for parity comparison.
     * Only enabled when SOL_LOG_TX_RESULTS env var is set (checked once). */
    {
        static int log_tx_results = -1;
        int ltr = __atomic_load_n(&log_tx_results, __ATOMIC_ACQUIRE);
        if (__builtin_expect(ltr < 0, 0)) {
            const char* env = getenv("SOL_LOG_TX_RESULTS");
            int enabled = (env && env[0] && env[0] != '0') ? 1 : 0;
            __atomic_store_n(&log_tx_results, enabled, __ATOMIC_RELEASE);
            ltr = enabled;
        }
        if (__builtin_expect(ltr != 0, 0)) {
            const sol_signature_t* tx_sig = sol_transaction_signature(tx);
            char tx_sig_b58[SOL_SIGNATURE_BASE58_LEN] = {0};
            if (tx_sig) {
                sol_signature_to_base58(tx_sig, tx_sig_b58, sizeof(tx_sig_b58));
            }
            const sol_pubkey_t* tx_fp = sol_message_fee_payer(&tx->message);
            char tx_fp_b58[SOL_PUBKEY_BASE58_LEN] = {0};
            if (tx_fp) sol_pubkey_to_base58(tx_fp, tx_fp_b58, sizeof(tx_fp_b58));
            sol_log_info("tx_result: slot=%lu err=%d cu=%lu fee=%lu payer=%s sig=%s",
                         (unsigned long)bank->slot,
                         result.status,
                         (unsigned long)result.compute_units_used,
                         (unsigned long)result.fee,
                         tx_fp_b58[0] ? tx_fp_b58 : "none",
                         tx_sig_b58[0] ? tx_sig_b58 : "none");
        }
    }

    return result;
}

sol_tx_result_t
sol_bank_process_transaction(sol_bank_t* bank, const sol_transaction_t* tx) {
    return sol_bank_process_transaction_impl(bank, tx, true);
}

static sol_tx_result_t
sol_bank_process_transaction_parallel(sol_bank_t* bank, const sol_transaction_t* tx) {
    return sol_bank_process_transaction_impl(bank, tx, false);
}

/* ---- Upgradeable ProgramData address cache (for parallel scheduling) ---- */

typedef struct {
    pthread_rwlock_t  lock;
    bool              inited;
    sol_pubkey_map_t* map; /* program_id -> programdata pubkey (all-zero = not upgradeable/unknown) */
} bank_progdata_cache_t;

static bank_progdata_cache_t g_bank_progdata_cache;
static pthread_once_t        g_bank_progdata_cache_once = PTHREAD_ONCE_INIT;

static void
bank_progdata_cache_destroy(void) {
    bank_progdata_cache_t* c = &g_bank_progdata_cache;
    if (!c->inited) return;
    if (c->map) {
        sol_pubkey_map_destroy(c->map);
        c->map = NULL;
    }
    pthread_rwlock_destroy(&c->lock);
    c->inited = false;
}

static void
bank_progdata_cache_init_once(void) {
    bank_progdata_cache_t* c = &g_bank_progdata_cache;
    memset(c, 0, sizeof(*c));
    if (pthread_rwlock_init(&c->lock, NULL) != 0) {
        return;
    }
    c->map = sol_pubkey_map_new(sizeof(sol_pubkey_t), 1024u);
    c->inited = true;
    atexit(bank_progdata_cache_destroy);
}

static inline bool
bank_progdata_cache_available(void) {
    (void)pthread_once(&g_bank_progdata_cache_once, bank_progdata_cache_init_once);
    return g_bank_progdata_cache.inited && g_bank_progdata_cache.map != NULL;
}

/* Returns: 1 = hit with non-zero ProgramData pubkey
 *          0 = hit with negative cache (zero pubkey)
 *         -1 = miss / cache unavailable */
static int
bank_progdata_cache_get(const sol_pubkey_t* program_id, sol_pubkey_t* out_programdata) {
    if (out_programdata) {
        memset(out_programdata, 0, sizeof(*out_programdata));
    }
    if (!program_id || !out_programdata) return -1;
    if (!bank_progdata_cache_available()) return -1;

    bank_progdata_cache_t* c = &g_bank_progdata_cache;
    pthread_rwlock_rdlock(&c->lock);
    sol_pubkey_t* slot = (sol_pubkey_t*)sol_pubkey_map_get(c->map, program_id);
    if (!slot) {
        pthread_rwlock_unlock(&c->lock);
        return -1;
    }
    *out_programdata = *slot;
    pthread_rwlock_unlock(&c->lock);
    return sol_pubkey_is_zero(out_programdata) ? 0 : 1;
}

static void
bank_progdata_cache_put(const sol_pubkey_t* program_id, const sol_pubkey_t* programdata) {
    if (!program_id || !programdata) return;
    if (!bank_progdata_cache_available()) return;

    bank_progdata_cache_t* c = &g_bank_progdata_cache;
    pthread_rwlock_wrlock(&c->lock);
    sol_pubkey_t val = *programdata;
    (void)sol_pubkey_map_insert(c->map, program_id, &val);
    pthread_rwlock_unlock(&c->lock);
}

void
sol_bank_programdata_cache_invalidate_program(const sol_pubkey_t* program_id) {
    if (!program_id) return;
    if (!bank_progdata_cache_available()) return;

    bank_progdata_cache_t* c = &g_bank_progdata_cache;
    pthread_rwlock_wrlock(&c->lock);
    if (c->map) {
        (void)sol_pubkey_map_remove(c->map, program_id);
    }
    pthread_rwlock_unlock(&c->lock);
}

void
sol_bank_programdata_cache_invalidate_programdata(const sol_pubkey_t* programdata_id) {
    (void)programdata_id;
    /* Conservatively clear the cache. Upgrades/extensions are rare and the cache
     * is tiny (hot programs). Keeping a reverse map isn't worth it. */
    if (!bank_progdata_cache_available()) return;

    bank_progdata_cache_t* c = &g_bank_progdata_cache;
    pthread_rwlock_wrlock(&c->lock);
    if (c->map) {
        sol_map_clear(c->map->inner);
    }
    pthread_rwlock_unlock(&c->lock);
}

/* Best-effort: for an upgradeable BPF program account, extract its ProgramData
 * address (which is implicitly read when executing the program). */
static bool
bank_get_upgradeable_programdata_pubkey(sol_bank_t* bank,
                                        const sol_pubkey_t* program_id,
                                        sol_pubkey_t* out_programdata) {
    if (out_programdata) {
        memset(out_programdata, 0, sizeof(*out_programdata));
    }
    if (!bank || !bank->accounts_db || !program_id || !out_programdata) {
        return false;
    }

    /* Hot path: program-id -> ProgramData is stable and reused for many txs.
     * Avoid re-loading the program account for every transaction. */
    int cached = bank_progdata_cache_get(program_id, out_programdata);
    if (cached == 1) return true;
    if (cached == 0) return false;

    sol_account_t* program_account = sol_accounts_db_load(bank->accounts_db, program_id);
    if (!program_account) {
        sol_pubkey_t zero = {0};
        bank_progdata_cache_put(program_id, &zero);
        return false;
    }

    bool ok = false;
    if (sol_pubkey_eq(&program_account->meta.owner, &SOL_BPF_LOADER_UPGRADEABLE_ID) &&
        program_account->data &&
        program_account->meta.data_len >= (4u + 32u)) {
        uint32_t typ = 0;
        memcpy(&typ, program_account->data, 4u);
        if (typ == 2u) { /* UpgradeableLoaderState::Program */
            memcpy(out_programdata->bytes, program_account->data + 4u, 32u);
            ok = !sol_pubkey_is_zero(out_programdata);
        }
    }

    if (ok) {
        bank_progdata_cache_put(program_id, out_programdata);
    } else {
        sol_pubkey_t zero = {0};
        bank_progdata_cache_put(program_id, &zero);
    }

    sol_account_destroy(program_account);
    return ok;
}

/* ---- Parallel transaction execution (deterministic batching) ---- */

static inline uint64_t
bank_monotonic_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

typedef struct {
    uint64_t seq_calls;
    uint64_t seq_txs;
    uint64_t seq_ns;
    uint64_t par_calls;
    uint64_t par_txs;
    uint64_t par_ns;
    uint64_t par_lock_ns;
    uint64_t par_wait_ns;
    uint64_t par_caller_ns;
    uint64_t par_join_ns;
} tx_pool_stats_t;

static __thread tx_pool_stats_t* g_tls_tx_pool_stats = NULL;

static bool
tx_pool_stats_enabled(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v >= 0, 1)) return v != 0;
    const char* env = getenv("SOL_TX_POOL_STATS");
    int enabled = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled != 0;
}

typedef enum {
    TX_POOL_JOB_NONE = 0,
    TX_POOL_JOB_TXS = 1,
    TX_POOL_JOB_TX_PTRS = 2,
    TX_POOL_JOB_LT_HASH_DELTA = 3,
    TX_POOL_JOB_TX_DAG_PTRS = 4,
} tx_pool_job_kind_t;

struct sol_tx_pool;

typedef struct {
    struct sol_tx_pool* p;
    size_t              thread_idx;
} tx_pool_worker_ctx_t;

typedef struct sol_tx_pool {
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    pthread_cond_t  done;
    bool            done_clock_monotonic;
    pthread_t*      threads;
    tx_pool_worker_ctx_t* worker_ctx;
    size_t          nthreads; /* worker threads (excluding caller thread) */
    bool            stop;
    bool            has_job;
    bool            inited;
    uint64_t        job_id; /* increments per job; prevents worker re-entering same job */
    tx_pool_job_kind_t job_kind;

    /* Job (valid while has_job==true) */
    sol_bank_t*              bank;
    const sol_transaction_t* txs;
    const sol_transaction_t* const* tx_ptrs;
    bool                     use_ptrs;
    bool                     skip_tx_status;
    bool                     replay_sigs_preverified;
    sol_tx_result_t*         results;
    size_t                   start;
    size_t                   end;
    /* DAG scheduler job */
    const uint32_t*          dag_adj_head;   /* [end) tx-indexed adjacency list heads */
    const uint32_t*          dag_edge_to;    /* [edge_count) */
    const uint32_t*          dag_edge_next;  /* [edge_count) */
    uint32_t*                dag_indegree;   /* [end) */
    uint32_t*                dag_ready_next; /* [end) tx-indexed ready-stack next pointers */
    volatile uint32_t        dag_ready_head; /* tx index or UINT32_MAX */
    volatile uint32_t        dag_remaining;  /* number of txs remaining in this DAG segment */
    /* LtHash delta job */
    const sol_accounts_db_local_entry_t* lthash_entries;
    sol_accounts_db_t*                  lthash_parent;
    sol_lt_hash_t*                      lthash_partials; /* [nthreads + 1] incl caller */
    size_t                   next;   /* atomic fetch-add cursor (0..len) */
    size_t                   active; /* participants remaining (threads + caller) */
    size_t                   wake;   /* number of worker threads permitted to join this job */
} sol_tx_pool_t;

enum { SOL_TX_POOL_SHARDS_MAX = 16 };
static sol_tx_pool_t      g_tx_pools[SOL_TX_POOL_SHARDS_MAX];
static size_t             g_tx_pool_count = 0u;
static pthread_once_t     g_tx_pool_once = PTHREAD_ONCE_INIT;

static size_t
tx_pool_shard_target(size_t workers_total) {
    size_t shards = 1u;
    const char* env = getenv("SOL_TX_POOL_SHARDS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long v = strtoul(env, &end, 10);
        if (end != env && v > 0ul) {
            shards = (size_t)v;
        }
    } else {
        /* Favor deeper per-shard worker pools on large hosts so replay-heavy
         * slots keep enough intra-slot parallelism and avoid long tails. */
        if (workers_total >= 128u) {
            shards = 8u;
        } else if (workers_total >= 96u) {
            shards = 8u;
        } else if (workers_total >= 64u) {
            shards = 4u;
        } else if (workers_total >= 32u) {
            shards = 2u;
        }
    }
    if (shards < 1u) shards = 1u;
    if (shards > SOL_TX_POOL_SHARDS_MAX) shards = SOL_TX_POOL_SHARDS_MAX;
    if (workers_total > 0u && shards > workers_total) shards = workers_total;
    if (shards < 1u) shards = 1u;
    return shards;
}

static inline size_t
tx_pool_shard_index(const sol_bank_t* bank, size_t count) {
    if (count <= 1u || !bank) return 0u;
    return (size_t)(bank->slot % (sol_slot_t)count);
}

static inline sol_tx_pool_t*
tx_pool_select(const sol_bank_t* bank) {
    size_t count = g_tx_pool_count;
    if (count == 0u) return NULL;
    size_t idx = tx_pool_shard_index(bank, count);
    return &g_tx_pools[idx];
}

static size_t
tx_pool_busy_fallback_batch(void) {
    /* If every tx-pool shard is busy, small/medium tx ranges are better run
     * locally than queued behind another slot's pool work. Queueing in that
     * state causes convoy behavior and multi-second replay outliers. */
    static size_t cached = SIZE_MAX;
    size_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != SIZE_MAX, 1)) return v;

    size_t threshold = 512u;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu >= 128) {
        threshold = 4096u;
    } else if (ncpu >= 96) {
        threshold = 3072u;
    } else if (ncpu >= 64) {
        threshold = 2048u;
    } else if (ncpu >= 32) {
        threshold = 1024u;
    } else {
        threshold = 256u;
    }

    const char* env = getenv("SOL_TX_POOL_BUSY_FALLBACK_BATCH");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long x = strtoul(env, &end, 10);
        if (end != env) {
            threshold = (size_t)x;
        }
    }

    if (threshold > 8192u) threshold = 8192u;
    __atomic_store_n(&cached, threshold, __ATOMIC_RELEASE);
    return threshold;
}

static size_t
tx_pool_replay_busy_fallback_batch(void) {
    static size_t cached = SIZE_MAX;
    size_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != SIZE_MAX, 1)) return v;

    /* Replay throughput mode: if all shards are busy, medium ranges should
     * prefer local execution over queueing behind an in-flight shard job.
     * This cuts long-tail convoy stalls on high-core hosts. */
    size_t threshold = 64u;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu >= 128) {
        threshold = 256u;
    } else if (ncpu >= 96) {
        threshold = 224u;
    } else if (ncpu >= 64) {
        threshold = 192u;
    } else if (ncpu >= 32) {
        threshold = 128u;
    }
    const char* env = getenv("SOL_TX_POOL_REPLAY_BUSY_FALLBACK_BATCH");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long x = strtoul(env, &end, 10);
        if (end != env) {
            threshold = (size_t)x;
        }
    }

    if (threshold > 8192u) threshold = 8192u;
    __atomic_store_n(&cached, threshold, __ATOMIC_RELEASE);
    return threshold;
}

static uint64_t
tx_pool_queue_wait_budget_ns(void) {
    static uint64_t cached = UINT64_MAX;
    uint64_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != UINT64_MAX, 1)) return v;

    /* Bound convoy delay when a shard is already running a job. If queue wait
     * exceeds this budget, callers fall back to local execution. */
    uint64_t budget_ms = 2u;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu < 64) {
        budget_ms = 8u;
    }

    const char* env = getenv("SOL_TX_POOL_QUEUE_WAIT_BUDGET_MS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long x = strtoul(env, &end, 10);
        if (end != env) {
            budget_ms = (uint64_t)x;
        }
    }

    if (budget_ms > 1000u) budget_ms = 1000u;
    uint64_t budget_ns = budget_ms * 1000000ULL;
    __atomic_store_n(&cached, budget_ns, __ATOMIC_RELEASE);
    return budget_ns;
}

static uint64_t
tx_pool_replay_queue_wait_budget_ns(void) {
    static uint64_t cached = UINT64_MAX;
    uint64_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != UINT64_MAX, 1)) return v;

    /* Replay throughput mode: keep queueing bias, but bound wait so replay can
     * fall back for stubbornly busy shards. 1ms proved too aggressive on
     * high-throughput slots: transient shard busy periods often exceed that and
     * trigger expensive sequential fallback. */
    uint64_t budget_ms = 4u;
    const char* env = getenv("SOL_TX_POOL_REPLAY_QUEUE_WAIT_BUDGET_MS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long x = strtoul(env, &end, 10);
        if (end != env) {
            budget_ms = (uint64_t)x;
        }
    }

    if (budget_ms > 2000u) budget_ms = 2000u;
    uint64_t budget_ns = budget_ms * 1000000ULL;
    __atomic_store_n(&cached, budget_ns, __ATOMIC_RELEASE);
    return budget_ns;
}

static size_t
tx_pool_replay_no_seq_fallback_batch(void) {
    static size_t cached = SIZE_MAX;
    size_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != SIZE_MAX, 1)) return v;

    /* For replay, only large ranges should use extended wait windows on busy
     * shards. Medium ranges typically do better with quick local fallback. */
    size_t threshold = 128u;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu >= 128) {
        threshold = 384u;
    } else if (ncpu >= 96) {
        threshold = 320u;
    } else if (ncpu >= 64) {
        threshold = 256u;
    } else if (ncpu >= 32) {
        threshold = 192u;
    }
    const char* env = getenv("SOL_TX_POOL_REPLAY_NO_SEQ_FALLBACK_BATCH");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long x = strtoul(env, &end, 10);
        if (end != env) {
            threshold = (size_t)x;
        }
    }

    if (threshold > 16384u) threshold = 16384u;
    __atomic_store_n(&cached, threshold, __ATOMIC_RELEASE);
    return threshold;
}

static size_t
tx_pool_replay_max_batch_txs(void) {
    static size_t cached = SIZE_MAX;
    size_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != SIZE_MAX, 1)) return v;

    /* Cap per-dispatch replay batch size to avoid oversized no-conflict
     * batches creating long-tail stragglers on busy shards. */
    size_t threshold = 0u; /* 0 disables the cap. */
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu >= 128) {
        threshold = 384u;
    } else if (ncpu >= 96) {
        threshold = 320u;
    } else if (ncpu >= 64) {
        threshold = 256u;
    }

    const char* env = getenv("SOL_TX_POOL_REPLAY_MAX_BATCH_TXS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long x = strtoul(env, &end, 10);
        if (end != env) {
            threshold = (size_t)x;
        }
    }

    if (threshold > 16384u) threshold = 16384u;
    __atomic_store_n(&cached, threshold, __ATOMIC_RELEASE);
    return threshold;
}

static uint64_t
tx_pool_replay_queue_wait_long_budget_ns(void) {
    static uint64_t cached = UINT64_MAX;
    uint64_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != UINT64_MAX, 1)) return v;

    /* Secondary queue-wait budget used for large replay batches after the
     * short wait expires. Keep this tight to avoid convoy amplification. */
    uint64_t budget_ms = 64u;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu >= 128) {
        budget_ms = 160u;
    } else if (ncpu >= 96) {
        budget_ms = 144u;
    } else if (ncpu >= 64) {
        budget_ms = 128u;
    } else if (ncpu >= 32) {
        budget_ms = 96u;
    }
    const char* env = getenv("SOL_TX_POOL_REPLAY_QUEUE_WAIT_LONG_BUDGET_MS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long x = strtoul(env, &end, 10);
        if (end != env) {
            budget_ms = (uint64_t)x;
        }
    }

    if (budget_ms > 2000u) budget_ms = 2000u;
    uint64_t budget_ns = budget_ms * 1000000ULL;
    __atomic_store_n(&cached, budget_ns, __ATOMIC_RELEASE);
    return budget_ns;
}

static uint64_t
lthash_queue_wait_budget_ns(void) {
    static uint64_t cached = UINT64_MAX;
    uint64_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != UINT64_MAX, 1)) return v;

    /* Lt-hash delta fallback-to-sequential is expensive, but very long waits
     * create replay tails when shards are saturated. Use a bounded middle
     * ground and keep env override hooks for host-specific tuning. */
    uint64_t budget_ms = 400u;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu >= 128) {
        budget_ms = 1200u;
    } else if (ncpu >= 96) {
        budget_ms = 1000u;
    } else if (ncpu >= 64) {
        budget_ms = 800u;
    } else if (ncpu >= 32) {
        budget_ms = 600u;
    }

    const char* env = getenv("SOL_LT_HASH_QUEUE_WAIT_BUDGET_MS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long x = strtoul(env, &end, 10);
        if (end != env) {
            budget_ms = (uint64_t)x;
        }
    }

    if (budget_ms > 10000u) budget_ms = 10000u;
    uint64_t budget_ns = budget_ms * 1000000ULL;
    __atomic_store_n(&cached, budget_ns, __ATOMIC_RELEASE);
    return budget_ns;
}

static bool
tx_pool_replay_force_wait_on_busy(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v >= 0, 1)) return v != 0;

    /* Keep this opt-in by default. Forcing extra waits on already-busy shards
     * can compound queue convoy stalls into multi-second replay tails. */
    int enabled = 0;

    const char* env = getenv("SOL_TX_POOL_REPLAY_FORCE_WAIT_ON_BUSY");
    if (env && env[0] != '\0') {
        enabled = (strcmp(env, "0") != 0) ? 1 : 0;
    }

    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled != 0;
}

static uint64_t
tx_pool_replay_force_wait_cap_ns(void) {
    static uint64_t cached = UINT64_MAX;
    uint64_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != UINT64_MAX, 1)) return v;

    /* Cap extra forced waits so replay can fail over instead of stalling a
     * slot behind one long-running shard job. */
    uint64_t cap_ms = 0u; /* 0 preserves legacy unbounded wait behavior. */
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu >= 128) {
        cap_ms = 800u;
    } else if (ncpu >= 96) {
        cap_ms = 700u;
    } else if (ncpu >= 64) {
        cap_ms = 600u;
    }

    const char* env = getenv("SOL_TX_POOL_REPLAY_FORCE_WAIT_CAP_MS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long x = strtoul(env, &end, 10);
        if (end != env) {
            cap_ms = (uint64_t)x;
        }
    }

    if (cap_ms > 10000u) cap_ms = 10000u;
    uint64_t cap_ns = cap_ms * 1000000ULL;
    __atomic_store_n(&cached, cap_ns, __ATOMIC_RELEASE);
    return cap_ns;
}

static bool
tx_pool_wait_idle_locked(sol_tx_pool_t* p, uint64_t budget_ns) {
    if (!p) return false;
    if (budget_ns == 0u) {
        while (!p->stop && p->has_job) {
            pthread_cond_wait(&p->done, &p->mu);
        }
        return !p->stop && !p->has_job;
    }

    struct timespec deadline = {0};
    if (p->done_clock_monotonic) {
        clock_gettime(CLOCK_MONOTONIC, &deadline);
    } else {
        clock_gettime(CLOCK_REALTIME, &deadline);
    }
    deadline.tv_sec += (time_t)(budget_ns / 1000000000ull);
    deadline.tv_nsec += (long)(budget_ns % 1000000000ull);
    if (deadline.tv_nsec >= 1000000000l) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000l;
    }

    while (!p->stop && p->has_job) {
        int rc = pthread_cond_timedwait(&p->done, &p->mu, &deadline);
        if (rc == ETIMEDOUT) {
            return false;
        }
        if (rc != 0 && rc != EINTR) {
            return false;
        }
    }

    return !p->stop && !p->has_job;
}

static sol_tx_pool_t*
tx_pool_try_lock_idle_shard(const sol_bank_t* bank, const sol_tx_pool_t* skip) {
    size_t count = g_tx_pool_count;
    if (count <= 1u) return NULL;

    size_t start = tx_pool_shard_index(bank, count);
    for (size_t probe = 0u; probe < count; probe++) {
        size_t idx = (start + probe) % count;
        sol_tx_pool_t* alt = &g_tx_pools[idx];
        if (alt == skip || alt->nthreads == 0u) continue;
        if (pthread_mutex_trylock(&alt->mu) != 0) continue;
        if (!alt->stop && !alt->has_job) {
            return alt;
        }
        pthread_mutex_unlock(&alt->mu);
    }
    return NULL;
}

static unsigned
tx_pool_lock_probe_rounds(void) {
    static unsigned cached = 0u;
    unsigned v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != 0u, 1)) return v;

    unsigned rounds = 64u;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu >= 128) {
        rounds = 96u;
    } else if (ncpu >= 96) {
        rounds = 80u;
    } else if (ncpu >= 64) {
        rounds = 64u;
    } else if (ncpu >= 32) {
        rounds = 48u;
    } else {
        rounds = 32u;
    }

    const char* env = getenv("SOL_TX_POOL_LOCK_PROBE_ROUNDS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long x = strtoul(env, &end, 10);
        if (end != env && x > 0ul) {
            rounds = (unsigned)x;
        }
    }

    if (rounds > 4096u) rounds = 4096u;
    __atomic_store_n(&cached, rounds, __ATOMIC_RELEASE);
    return rounds;
}

static sol_tx_pool_t*
tx_pool_lock_for_job(sol_tx_pool_t* preferred,
                     const sol_bank_t* bank,
                     size_t len,
                     bool throughput_mode) {
    if (!preferred) return NULL;

    size_t count = g_tx_pool_count;
    if (count <= 1u) {
        pthread_mutex_lock(&preferred->mu);
        return preferred;
    }

    size_t start = tx_pool_shard_index(bank, count);

    if (pthread_mutex_trylock(&preferred->mu) == 0) {
        if (!preferred->stop && !preferred->has_job) {
            return preferred;
        }
        pthread_mutex_unlock(&preferred->mu);
    }

    for (size_t probe = 1u; probe < count; probe++) {
        size_t idx = (start + probe) % count;
        sol_tx_pool_t* alt = &g_tx_pools[idx];
        if (alt->nthreads == 0u) continue;
        if (pthread_mutex_trylock(&alt->mu) != 0) continue;
        if (!alt->stop && !alt->has_job) {
            return alt;
        }
        pthread_mutex_unlock(&alt->mu);
    }

    /* All shards are busy. For small/medium ranges, fall back to local
     * execution to avoid queueing convoys across replay threads. */
    size_t fallback_batch = throughput_mode
        ? tx_pool_replay_busy_fallback_batch()
        : tx_pool_busy_fallback_batch();
    if (fallback_batch > 0u && len <= fallback_batch) {
        return NULL;
    }

    /* For larger ranges, briefly keep probing all shards before we commit to
     * queueing behind the preferred shard. This avoids long convoy waits when
     * shards are only transiently busy. */
    unsigned probe_rounds = tx_pool_lock_probe_rounds();
    for (unsigned round = 0u; round < probe_rounds; round++) {
        size_t offset = (size_t)(round % (unsigned)count);
        for (size_t probe = 0u; probe < count; probe++) {
            size_t idx = (start + offset + probe) % count;
            sol_tx_pool_t* alt = &g_tx_pools[idx];
            if (alt->nthreads == 0u) continue;
            if (pthread_mutex_trylock(&alt->mu) != 0) continue;
            if (!alt->stop && !alt->has_job) {
                return alt;
            }
            pthread_mutex_unlock(&alt->mu);
        }
        if ((round & 7u) == 7u) {
            sched_yield();
        }
    }

    /* For large ranges, queue behind the preferred shard. */
    pthread_mutex_lock(&preferred->mu);
    return preferred;
}

static bool
tx_parallel_enabled(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v >= 0, 1)) {
        return v != 0;
    }

    /* Default: enabled. Set SOL_TX_PARALLEL=0 to disable. */
    int enabled = 1;
    const char* env = getenv("SOL_TX_PARALLEL");
    if (env && env[0] != '\0') {
        while (*env && isspace((unsigned char)*env)) env++;
        if (*env == '0' || *env == 'n' || *env == 'N' || *env == 'f' || *env == 'F') {
            enabled = 0;
        }
    }

    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled != 0;
}

static bool
tx_replay_parallel_enabled(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v >= 0, 1)) {
        return v != 0;
    }

    /* Default to sequential tx execution during replay.
     * This avoids rare tx-pool join stalls that can pin the replay frontier.
     * Set SOL_TX_REPLAY_PARALLEL=1 to force replay through the tx pool. */
    int enabled = 0;
    const char* env = getenv("SOL_TX_REPLAY_PARALLEL");
    if (env && env[0] != '\0') {
        while (*env && isspace((unsigned char)*env)) env++;
        if (*env == '0' || *env == 'n' || *env == 'N' || *env == 'f' || *env == 'F') {
            enabled = 0;
        } else {
            enabled = 1;
        }
    }

    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled != 0;
}

static size_t
tx_replay_seq_max_txs(void) {
    static size_t cached = SIZE_MAX;
    size_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != SIZE_MAX, 1)) {
        return v;
    }

    /* Replay default is sequential for stability, but very large batches can
     * become multi-second stragglers. Cap sequential mode by tx count and let
     * oversized batches use tx-pool parallel execution. 0 disables the cap. */
    size_t max_txs = 0u;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu >= 128) {
        max_txs = 1024u;
    } else if (ncpu >= 96) {
        max_txs = 896u;
    } else if (ncpu >= 64) {
        max_txs = 640u;
    }

    const char* env = getenv("SOL_TX_REPLAY_SEQ_MAX_TXS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long x = strtoul(env, &end, 10);
        if (end != env) {
            max_txs = (size_t)x;
        }
    }

    if (max_txs > 65536u) max_txs = 65536u;
    __atomic_store_n(&cached, max_txs, __ATOMIC_RELEASE);
    return max_txs;
}

static bool
tx_wave_sched_enabled(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v >= 0, 1)) return v != 0;

    /* Default: enabled. Set SOL_TX_WAVE_SCHED=0 to use the legacy contiguous
     * batching scheduler. */
    int enabled = 1;
    const char* env = getenv("SOL_TX_WAVE_SCHED");
    if (env && env[0] != '\0') {
        while (*env && isspace((unsigned char)*env)) env++;
        if (*env == '0' || *env == 'n' || *env == 'N' || *env == 'f' || *env == 'F') {
            enabled = 0;
        }
    }
    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled != 0;
}

static bool
tx_dag_sched_enabled(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v >= 0, 1)) return v != 0;

    /* Default: enable on large-core hosts where barrier-heavy waves often
     * dominate replay tail latency. Keep env as an explicit override. */
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    int enabled = (ncpu >= 64) ? 1 : 0;
    const char* env = getenv("SOL_TX_DAG_SCHED");
    if (env && env[0] != '\0') {
        while (*env && isspace((unsigned char)*env)) env++;
        if (*env == '0' || *env == 'n' || *env == 'N' || *env == 'f' || *env == 'F') {
            enabled = 0;
        } else {
            enabled = 1;
        }
    }

    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled != 0;
}

static size_t
tx_dag_min_batch(void) {
    static size_t cached = 0u;
    size_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != 0u, 1)) return v;

    /* DAG graph construction has non-trivial overhead. Keep a moderate floor on
     * big-core hosts so scheduling work doesn't dominate execution on small
     * batches. */
    size_t min_batch = 1024u;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu >= 128) {
        min_batch = 96u;
    } else if (ncpu >= 96) {
        min_batch = 96u;
    } else if (ncpu >= 64) {
        min_batch = 128u;
    }
    const char* env = getenv("SOL_TX_DAG_MIN_BATCH");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long x = strtoul(env, &end, 10);
        if (end != env && x > 0ul) {
            min_batch = (size_t)x;
        }
    }

    if (min_batch < 32u) min_batch = 32u;
    if (min_batch > 65536u) min_batch = 65536u;
    __atomic_store_n(&cached, min_batch, __ATOMIC_RELEASE);
    return min_batch;
}

static size_t
tx_dag_edge_cap_limit(size_t tx_count) {
    size_t limit = 0u;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    size_t mul = 128u;
    if (ncpu >= 128) {
        /* Large-core hosts see dense conflict graphs on hot slots. Keep a
         * much higher edge ceiling to avoid aborting into sequential replay. */
        mul = 512u;
    } else if (ncpu >= 96) {
        mul = 384u;
    } else if (ncpu >= 64) {
        mul = 256u;
    }

    if (tx_count > 0u && tx_count <= (SIZE_MAX / mul)) {
        limit = tx_count * mul;
    } else {
        limit = SIZE_MAX;
    }

    const char* env = getenv("SOL_TX_DAG_EDGE_CAP_LIMIT");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long long x = strtoull(env, &end, 10);
        if (end != env && x > 0ull) {
            limit = (size_t)x;
        }
    }

    if (limit < 4096u) limit = 4096u;
    /* Hard safety cap: 32M edges ~256 MiB across edge arrays. */
    if (limit > (size_t)(1u << 25)) limit = (size_t)(1u << 25);
    return limit;
}

static void
tx_dag_abort_log_once(const sol_bank_t* bank,
                      size_t tx_count,
                      size_t abort_at,
                      size_t seg_len,
                      size_t segments_done,
                      size_t edge_len,
                      size_t edge_cap,
                      size_t edge_cap_limit,
                      const char* path) {
    static uint32_t warned = 0u;
    uint32_t n = __atomic_fetch_add(&warned, 1u, __ATOMIC_RELAXED);
    if (n >= 32u) return;

    sol_log_warn("tx_dag_abort: slot=%lu txs=%zu abort_at=%zu seg_len=%zu segments_done=%zu edge_len=%zu edge_cap=%zu edge_cap_limit=%zu path=%s",
                 bank ? (unsigned long)bank->slot : 0ul,
                 tx_count,
                 abort_at,
                 seg_len,
                 segments_done,
                 edge_len,
                 edge_cap,
                 edge_cap_limit,
                 path ? path : "unknown");
}

static size_t
tx_sched_lockset_reserve(size_t tx_count) {
    /* Keep lock-set maps large enough to avoid repeated growth/rehash when
     * replaying dense batches on large-core hosts. */
    size_t reserve = 1024u;
    size_t mul = 16u;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu >= 128) {
        mul = 20u;
    } else if (ncpu >= 64) {
        mul = 18u;
    }
    if (tx_count > 0u && tx_count <= (SIZE_MAX / mul)) {
        reserve = tx_count * mul;
    } else if (tx_count > 0u) {
        reserve = SIZE_MAX;
    }

    if (reserve < 1024u) reserve = 1024u;
    if (reserve > (size_t)(1u << 22)) reserve = (size_t)(1u << 22);
    return reserve;
}

static size_t
tx_worker_target(void) {
    const char* env = getenv("SOL_TX_WORKERS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long v = strtoul(env, &end, 10);
        if (end != env) {
            if (v <= 1ul) return 1u;
            return (size_t)v;
        }
    }

    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n < 1) n = 1;
    /* Default to a moderate worker count.
     *
     * Replay on mainnet is extremely CPU-heavy (SBF execution + account loads),
     * but driving one tx worker per logical CPU can over-saturate shared
     * queues/locks and hurt tail latency. Keep high parallelism while leaving
     * headroom for replay/repair/rocksdb threads on large machines.
     *
     * Users can still override via SOL_TX_WORKERS. */
    size_t workers = (size_t)n;
    /* Use a more aggressive default worker budget on large-core hosts.
     * Replay latency is typically bounded by tx execution throughput, and
     * under-provisioning workers leaves CPUs idle while slots queue up. */
    if (workers >= 128u) {
        /* Prefer higher replay execution parallelism on 128-thread hosts.
         * Remaining cores are still available to networking/repair/replay
         * threads due tx-pool sharding and caller-participation. */
        workers = 96u;
    } else if (workers >= 96u) {
        workers = 80u;
    } else if (workers >= 64u) {
        workers = 56u;
    } else if (workers >= 48u) {
        workers = 32u;
    } else if (workers >= 24u) {
        workers /= 2u;
    }
    if (n >= 24 && workers < 8u) workers = 8u;
    if (workers > 128u) workers = 128u;
    if (workers < 1u) workers = 1u;
    return workers;
}

static size_t
tx_pool_min_batch(void) {
    /* Minimum range size to dispatch onto the tx thread-pool.  The default is
     * conservative: many small "waves" are highly contended, and waking threads
     * can be more expensive than just running them sequentially. */
    static size_t cached = 0;
    size_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != 0u, 1)) return v;

    /* Default: balance pool coordination overhead vs parallelism.
     *
     * Mainnet workloads often produce many small waves. Parallelizing extremely
     * small waves (e.g. 2-3 txs) can cost more in wake/sync overhead than it
     * saves; but leaving medium waves (4-7 txs) sequential leaves a lot of
     * throughput on the table. Users can still override via
     * SOL_TX_POOL_MIN_BATCH for experimentation. */
    size_t min_batch = 2u;
    const char* env = getenv("SOL_TX_POOL_MIN_BATCH");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long x = strtoul(env, &end, 10);
        if (end != env && x > 0ul) {
            min_batch = (size_t)x;
        }
    }

    /* Parallelizing a single tx range does not help and adds overhead. */
    if (min_batch < 2u) min_batch = 2u;
    if (min_batch > 1024u) min_batch = 1024u;

    __atomic_store_n(&cached, min_batch, __ATOMIC_RELEASE);
    return min_batch;
}

static size_t
tx_pool_target_txs_per_worker(void) {
    static size_t cached = 0u;
    size_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != 0u, 1)) return v;

    /* Keep enough work per worker to amortize wake/sync overhead while still
     * exposing high concurrency on large-core hosts. */
    size_t tx_per_worker = 8u;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu >= 128) {
        tx_per_worker = 8u;
    } else if (ncpu >= 96) {
        tx_per_worker = 4u;
    } else if (ncpu >= 64) {
        tx_per_worker = 4u;
    } else if (ncpu >= 32) {
        tx_per_worker = 6u;
    }
    const char* env = getenv("SOL_TX_PER_WORKER");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long x = strtoul(env, &end, 10);
        if (end != env && x > 0ul) tx_per_worker = (size_t)x;
    }

    if (tx_per_worker < 1u) tx_per_worker = 1u;
    if (tx_per_worker > 256u) tx_per_worker = 256u;
    __atomic_store_n(&cached, tx_per_worker, __ATOMIC_RELEASE);
    return tx_per_worker;
}

static inline size_t
tx_pool_worker_threads_for_len(const sol_tx_pool_t* p, size_t len) {
    if (!p || p->nthreads == 0u || len <= 1u) return 0u;

    size_t max_workers = len - 1u; /* caller thread always participates */
    size_t workers = p->nthreads;
    if (workers > max_workers) workers = max_workers;
    if (workers == 0u) return 0u;

    size_t tx_per_worker = tx_pool_target_txs_per_worker();
    size_t desired_total = (len + tx_per_worker - 1u) / tx_per_worker;
    if (desired_total < 1u) desired_total = 1u;
    size_t desired_workers = desired_total - 1u;
    if (desired_workers < 1u) desired_workers = 1u;

    if (workers > desired_workers) workers = desired_workers;
    return workers;
}

static bool
tx_pool_replay_interleave_order(void) {
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v >= 0, 1)) return v != 0;

    /* Replay-only scheduling: spread early work across both ends of the batch.
     * This reduces long-tail stragglers when a few very expensive txs cluster
     * near the end of a replay segment. */
    int enabled = 1;
    const char* env = getenv("SOL_TX_POOL_REPLAY_INTERLEAVE_ORDER");
    if (env && env[0] != '\0') {
        while (*env && isspace((unsigned char)*env)) env++;
        if (*env == '0' || *env == 'n' || *env == 'N' || *env == 'f' || *env == 'F') {
            enabled = 0;
        }
    }

    __atomic_store_n(&cached, enabled, __ATOMIC_RELEASE);
    return enabled != 0;
}

static inline size_t
tx_pool_job_index(size_t start, size_t len, size_t off, bool replay_throughput_mode) {
    if (!replay_throughput_mode || len < 32u || !tx_pool_replay_interleave_order()) {
        return start + off;
    }

    /* Deterministic interleave: 0, n-1, 1, n-2, ... */
    size_t half = off >> 1;
    if ((off & 1u) == 0u) {
        return start + half;
    }
    return start + (len - 1u - half);
}

/* ---- Parallel transaction execution (DAG scheduler) ---- */

#define TX_POOL_DAG_NONE UINT32_MAX

static inline void
tx_pool_dag_ready_push(volatile uint32_t* head, uint32_t* next, uint32_t node) {
    if (!head || !next) return;
    uint32_t old = __atomic_load_n(head, __ATOMIC_RELAXED);
    for (;;) {
        next[node] = old;
        if (__atomic_compare_exchange_n(head,
                                        &old,
                                        node,
                                        false,
                                        __ATOMIC_RELEASE,
                                        __ATOMIC_RELAXED)) {
            return;
        }
        /* old updated with current head; retry */
    }
}

/* Push a pre-linked chain (head..tail) onto the global ready stack using a single
 * CAS. This reduces contention on `ready_head` under high worker counts. */
static inline void
tx_pool_dag_ready_push_chain(volatile uint32_t* head,
                             uint32_t* next,
                             uint32_t chain_head,
                             uint32_t chain_tail) {
    if (!head || !next) return;
    if (chain_head == TX_POOL_DAG_NONE || chain_tail == TX_POOL_DAG_NONE) return;

    uint32_t old = __atomic_load_n(head, __ATOMIC_RELAXED);
    for (;;) {
        next[chain_tail] = old;
        if (__atomic_compare_exchange_n(head,
                                        &old,
                                        chain_head,
                                        false,
                                        __ATOMIC_RELEASE,
                                        __ATOMIC_RELAXED)) {
            return;
        }
        /* old updated with current head; retry */
    }
}

static inline bool
tx_pool_dag_ready_pop(volatile uint32_t* head, uint32_t* next, uint32_t* out_node) {
    if (!head || !next || !out_node) return false;
    uint32_t old = __atomic_load_n(head, __ATOMIC_ACQUIRE);
    for (;;) {
        if (old == TX_POOL_DAG_NONE) return false;
        uint32_t nxt = next[old];
        if (__atomic_compare_exchange_n(head,
                                        &old,
                                        nxt,
                                        false,
                                        __ATOMIC_ACQUIRE,
                                        __ATOMIC_RELAXED)) {
            *out_node = old;
            return true;
        }
        /* old updated with current head; retry */
    }
}

/* Pop up to `max_nodes` nodes from the global ready stack in one CAS.
 *
 * This reduces contention on `ready_head` under high worker counts.
 *
 * The returned list is terminated by `out_stop` (which is the new global head
 * after the pop). Callers should treat the local list as:
 *   node = out_head;
 *   while (node != out_stop) { ...; node = next[node]; }
 *
 * NOTE: We deliberately do NOT mutate next[tail] to terminate the list because
 * other threads may still be traversing the old list prior to a failed CAS. */
static inline bool
tx_pool_dag_ready_pop_chain(volatile uint32_t* head,
                            uint32_t* next,
                            uint32_t* out_head,
                            uint32_t* out_stop,
                            unsigned max_nodes) {
    if (!head || !next || !out_head || !out_stop || max_nodes == 0u) return false;

    uint32_t old = __atomic_load_n(head, __ATOMIC_ACQUIRE);
    for (;;) {
        if (old == TX_POOL_DAG_NONE) return false;

        uint32_t tail = old;
        unsigned n = 1u;
        while (n < max_nodes) {
            uint32_t nxt = next[tail];
            if (nxt == TX_POOL_DAG_NONE) break;
            tail = nxt;
            n++;
        }

        uint32_t new_head = next[tail];

        if (__atomic_compare_exchange_n(head,
                                        &old,
                                        new_head,
                                        false,
                                        __ATOMIC_ACQUIRE,
                                        __ATOMIC_RELAXED)) {
            *out_head = old;
            *out_stop = new_head;
            return true;
        }

        /* old updated with current head; retry */
    }
}

static inline void
tx_pool_cpu_pause(void) {
#if defined(__x86_64__) || defined(__i386__)
    __asm__ __volatile__("pause");
#elif defined(__aarch64__)
    __asm__ __volatile__("yield");
#else
    __asm__ __volatile__("" ::: "memory");
#endif
}

static inline bool
tx_pool_big_core_host(void) {
    /* Avoid scheduler yields on big hosts: `sched_yield()` can introduce
     * millisecond-scale latency when the runqueue is saturated, which shows up
     * as replay "pauses" and inflates p95/p99 slot times. */
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v >= 0, 1)) return v != 0;

    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    int big = (ncpu >= 64) ? 1 : 0;
    __atomic_store_n(&cached, big, __ATOMIC_RELEASE);
    return big != 0;
}

static inline unsigned
tx_pool_dag_pop_batch(void) {
    /* Tuning knob for the DAG scheduler. Very large pop batches cause work
     * hoarding (few workers active, others spin on an empty global queue) and
     * amplify ready-queue traversal costs. Keep the default small on big-core
     * machines; allow override for experimentation. */
    static unsigned cached = 0u;
    unsigned v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != 0u, 1)) return v;

    unsigned pop = 16u;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu > 0 && ncpu <= 16) pop = 64u;
    else if (ncpu > 0 && ncpu <= 32) pop = 32u;
    else if (ncpu >= 128) pop = 16u;
    else if (ncpu >= 64) pop = 8u;

    const char* env = getenv("SOL_TX_DAG_POP_BATCH");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long x = strtoul(env, &end, 10);
        if (end != env && x > 0ul) pop = (unsigned)x;
    }

    if (pop < 1u) pop = 1u;
    if (pop > 256u) pop = 256u;

    __atomic_store_n(&cached, pop, __ATOMIC_RELEASE);
    return pop;
}

static size_t
tx_parallel_min_batch(void) {
    static size_t cached = 0u;
    size_t v = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v != 0u, 1)) return v;

    size_t min_batch = 16u;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu >= 128) {
        min_batch = 4u;
    } else if (ncpu >= 64) {
        min_batch = 8u;
    }

    const char* env = getenv("SOL_TX_PARALLEL_MIN_BATCH");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long x = strtoul(env, &end, 10);
        if (end != env && x > 0ul) min_batch = (size_t)x;
    }

    if (min_batch < 2u) min_batch = 2u;
    if (min_batch > 1024u) min_batch = 1024u;
    __atomic_store_n(&cached, min_batch, __ATOMIC_RELEASE);
    return min_batch;
}

static void
tx_pool_run_dag_worker(sol_bank_t* bank,
                       const sol_transaction_t* const* tx_ptrs,
                       sol_tx_result_t* results,
                       bool skip_tx_status,
                       const uint32_t* adj_head,
                       const uint32_t* edge_to,
                       const uint32_t* edge_next,
                       uint32_t* indegree,
                       uint32_t* ready_next,
                       volatile uint32_t* ready_head,
                       volatile uint32_t* remaining) {
    if (!bank || !tx_ptrs || !results || !adj_head || !edge_to || !edge_next ||
        !indegree || !ready_next || !ready_head || !remaining) {
        return;
    }

    /* Each worker keeps a small local list of ready nodes to reduce contention
     * on the global ready stack (ready_head). The list is terminated by
     * `local_stop` (the global head value after the batch pop). */
    uint32_t local_head = TX_POOL_DAG_NONE;
    uint32_t local_stop = TX_POOL_DAG_NONE;

    unsigned idle_spins = 0;
    const bool big_core_host = tx_pool_big_core_host();
    const unsigned idle_spin_cap = big_core_host ? 8192u : 4096u;
    const unsigned pop_batch = tx_pool_dag_pop_batch();
    for (;;) {
        uint32_t node = TX_POOL_DAG_NONE;

        if (local_head != local_stop) {
            node = local_head;
            local_head = ready_next[node];
        } else {
            /* Refill from the global ready stack in batches.
             *
             * On large machines, popping a longer chain reduces contention on
             * ready_head and lowers tail latency (fewer CAS loops). */
            if (!tx_pool_dag_ready_pop_chain(ready_head,
                                             ready_next,
                                             &local_head,
                                             &local_stop,
                                             pop_batch)) {
                /* No ready work at the moment. If remaining>0, other txs must be
                 * executing. Avoid `sched_yield()` hot-looping: a short PAUSE
                 * spin reduces context switch overhead when the ready queue
                 * refills quickly. */
                if (__atomic_load_n(remaining, __ATOMIC_RELAXED) == 0u) return;

                /* Keep spin windows short enough to avoid starving replay
                 * verify/network threads under sustained contention. */
                if (idle_spins < idle_spin_cap) {
                    tx_pool_cpu_pause();
                    idle_spins++;
                } else {
                    idle_spins = 0;
                    sched_yield();
                }
                continue;
            }

            node = local_head;
            local_head = ready_next[node];
        }
        idle_spins = 0;

        const sol_transaction_t* tx = tx_ptrs[node];
        if (tx) {
            results[node] = skip_tx_status
                ? sol_bank_process_transaction_parallel(bank, tx)
                : sol_bank_process_transaction(bank, tx);
        }

        /* Publish dependents that have reached indegree==0. */
        uint32_t ready_chain_head = TX_POOL_DAG_NONE;
        uint32_t ready_chain_tail = TX_POOL_DAG_NONE;
        for (uint32_t e = adj_head[node]; e != TX_POOL_DAG_NONE; e = edge_next[e]) {
            uint32_t succ = edge_to[e];
            if (__atomic_sub_fetch(&indegree[succ], 1u, __ATOMIC_RELAXED) == 0u) {
                if (ready_chain_head == TX_POOL_DAG_NONE) {
                    ready_chain_head = succ;
                    ready_chain_tail = succ;
                    /* tail->next will be filled on flush */
                    ready_next[succ] = TX_POOL_DAG_NONE;
                } else {
                    ready_next[succ] = ready_chain_head;
                    ready_chain_head = succ;
                }
            }
        }

        if (ready_chain_head != TX_POOL_DAG_NONE) {
            tx_pool_dag_ready_push_chain(ready_head, ready_next, ready_chain_head, ready_chain_tail);
        }

        if (__atomic_fetch_sub(remaining, 1u, __ATOMIC_RELAXED) == 1u) {
            return;
        }
    }
}

static void*
tx_pool_worker_main(void* arg) {
    tx_pool_worker_ctx_t* w = (tx_pool_worker_ctx_t*)arg;
    sol_tx_pool_t* p = w ? (sol_tx_pool_t*)w->p : NULL;
    size_t worker_idx = w ? w->thread_idx : 0u;
    if (!p) return NULL;
    uint64_t seen_job_id = 0;
    for (;;) {
        tx_pool_job_kind_t kind = TX_POOL_JOB_NONE;
        sol_bank_t* bank = NULL;
        const sol_transaction_t* txs = NULL;
        const sol_transaction_t* const* tx_ptrs = NULL;
        bool use_ptrs = false;
        bool skip_tx_status = false;
        bool replay_sigs_preverified = false;
        sol_tx_result_t* results = NULL;
        const uint32_t* dag_adj_head = NULL;
        const uint32_t* dag_edge_to = NULL;
        const uint32_t* dag_edge_next = NULL;
        uint32_t* dag_indegree = NULL;
        uint32_t* dag_ready_next = NULL;
        volatile uint32_t* dag_ready_head = NULL;
        volatile uint32_t* dag_remaining = NULL;
        const sol_accounts_db_local_entry_t* lthash_entries = NULL;
        sol_accounts_db_t* lthash_parent = NULL;
        sol_lt_hash_t* lthash_partials = NULL;
        size_t start = 0;
        size_t end = 0;

        pthread_mutex_lock(&p->mu);
        while (!p->stop && (!p->has_job || p->job_id == seen_job_id || p->wake == 0u)) {
            pthread_cond_wait(&p->cv, &p->mu);
        }
        if (p->stop) {
            pthread_mutex_unlock(&p->mu);
            return NULL;
        }
        /* Snapshot job fields under the mutex so we never re-read shared state
         * while the main thread prepares the next job. */
        p->wake--;
        seen_job_id = p->job_id;
        kind = p->job_kind;
        bank = p->bank;
        txs = p->txs;
        tx_ptrs = p->tx_ptrs;
        use_ptrs = p->use_ptrs;
        skip_tx_status = p->skip_tx_status;
        replay_sigs_preverified = p->replay_sigs_preverified;
        results = p->results;
        dag_adj_head = p->dag_adj_head;
        dag_edge_to = p->dag_edge_to;
        dag_edge_next = p->dag_edge_next;
        dag_indegree = p->dag_indegree;
        dag_ready_next = p->dag_ready_next;
        dag_ready_head = &p->dag_ready_head;
        dag_remaining = &p->dag_remaining;
        lthash_entries = p->lthash_entries;
        lthash_parent = p->lthash_parent;
        lthash_partials = p->lthash_partials;
        start = p->start;
        end = p->end;
        pthread_mutex_unlock(&p->mu);

        bool tx_job =
            (kind == TX_POOL_JOB_TXS ||
             kind == TX_POOL_JOB_TX_PTRS ||
             kind == TX_POOL_JOB_TX_DAG_PTRS);
        int prev_sigverify_tls = g_tls_replay_signatures_preverified;
        if (tx_job) {
            g_tls_replay_signatures_preverified = replay_sigs_preverified ? 1 : 0;
        }

        size_t len = end - start;
        if (kind == TX_POOL_JOB_LT_HASH_DELTA) {
            sol_lt_hash_t* delta = NULL;
            if (lthash_partials && worker_idx < (p->nthreads + 1u)) {
                delta = &lthash_partials[worker_idx];
            }
            for (;;) {
                size_t off = __atomic_fetch_add(&p->next, 1u, __ATOMIC_RELAXED);
                if (off >= len) break;
                size_t idx = start + off;
                const sol_accounts_db_local_entry_t* e =
                    lthash_entries ? &lthash_entries[idx] : NULL;
                if (!e || !delta) continue;

                const sol_account_t* curr = e->account;
                sol_account_t* prev = lthash_parent ? sol_accounts_db_load_view(lthash_parent, &e->pubkey) : NULL;

                if (accounts_equal_for_lt_hash(prev, curr)) {
                    sol_account_destroy(prev);
                    continue;
                }

                sol_lt_hash_t prev_hash;
                sol_lt_hash_t curr_hash;
                if (prev) sol_account_lt_hash(&e->pubkey, prev, &prev_hash);
                else      sol_lt_hash_identity(&prev_hash);
                if (curr) sol_account_lt_hash(&e->pubkey, curr, &curr_hash);
                else      sol_lt_hash_identity(&curr_hash);

                sol_lt_hash_mix_out(delta, &prev_hash);
                sol_lt_hash_mix_in(delta, &curr_hash);
                sol_account_destroy(prev);
            }
        } else if (kind == TX_POOL_JOB_TX_DAG_PTRS) {
            tx_pool_run_dag_worker(bank,
                                   tx_ptrs,
                                   results,
                                   skip_tx_status,
                                   dag_adj_head,
                                   dag_edge_to,
                                   dag_edge_next,
                                   dag_indegree,
                                   dag_ready_next,
                                   dag_ready_head,
                                   dag_remaining);
        } else {
            bool replay_throughput_mode = use_ptrs && skip_tx_status;
            for (;;) {
                size_t off = __atomic_fetch_add(&p->next, 1u, __ATOMIC_RELAXED);
                if (off >= len) break;
                size_t idx = tx_pool_job_index(start, len, off, replay_throughput_mode);
                if (use_ptrs) {
                    const sol_transaction_t* tx = tx_ptrs[idx];
                    if (!tx) {
                        /* A NULL tx pointer means the caller already filled results[idx]. */
                        continue;
                    }
                    results[idx] = skip_tx_status
                        ? sol_bank_process_transaction_parallel(bank, tx)
                        : sol_bank_process_transaction(bank, tx);
                } else {
                    results[idx] = sol_bank_process_transaction(bank, &txs[idx]);
                }
            }
        }

        if (tx_job) {
            g_tls_replay_signatures_preverified = prev_sigverify_tls;
        }

        pthread_mutex_lock(&p->mu);
        if (--p->active == 0) {
            p->has_job = false;
            pthread_cond_signal(&p->done);
        }
        pthread_mutex_unlock(&p->mu);
    }
}

static void
tx_pool_shutdown(void) {
    for (size_t shard = 0; shard < g_tx_pool_count; shard++) {
        sol_tx_pool_t* p = &g_tx_pools[shard];
        if (!p->inited) continue;

        pthread_mutex_lock(&p->mu);
        p->stop = true;
        pthread_cond_broadcast(&p->cv);
        pthread_mutex_unlock(&p->mu);

        for (size_t i = 0; i < p->nthreads; i++) {
            (void)pthread_join(p->threads[i], NULL);
        }
        sol_free(p->threads);
        p->threads = NULL;
        sol_free(p->worker_ctx);
        p->worker_ctx = NULL;
        p->nthreads = 0;

        pthread_mutex_destroy(&p->mu);
        pthread_cond_destroy(&p->cv);
        pthread_cond_destroy(&p->done);
        p->inited = false;
    }
    g_tx_pool_count = 0u;
}

static void
tx_pool_init_once(void) {
    size_t workers_total = tx_worker_target();
    size_t shards = tx_pool_shard_target(workers_total);
    if (shards < 1u) shards = 1u;
    if (shards > SOL_TX_POOL_SHARDS_MAX) shards = SOL_TX_POOL_SHARDS_MAX;
    if (workers_total > 0u && shards > workers_total) shards = workers_total;
    if (shards < 1u) shards = 1u;
    g_tx_pool_count = shards;

    size_t base_workers = (workers_total >= shards) ? (workers_total / shards) : 1u;
    size_t rem_workers = (workers_total >= shards) ? (workers_total % shards) : 0u;
    size_t total_spawned_workers = 0u;

    for (size_t shard = 0; shard < shards; shard++) {
        sol_tx_pool_t* p = &g_tx_pools[shard];
        memset(p, 0, sizeof(*p));

        (void)pthread_mutex_init(&p->mu, NULL);
        (void)pthread_cond_init(&p->cv, NULL);
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
        (void)pthread_cond_init(&p->done, done_clock_monotonic ? &done_attr : NULL);
        if (done_attr_inited) {
            pthread_condattr_destroy(&done_attr);
        }
        p->done_clock_monotonic = done_clock_monotonic;
        p->inited = true;
        p->job_id = 0;

        size_t workers = base_workers + (shard < rem_workers ? 1u : 0u);
        if (workers < 1u) workers = 1u;
        if (workers <= 1u) {
            p->nthreads = 0u;
            continue;
        }

        /* Use caller thread as a worker too. */
        p->nthreads = workers - 1u;
        total_spawned_workers += workers;

        p->threads = sol_calloc(p->nthreads, sizeof(pthread_t));
        if (!p->threads) {
            p->nthreads = 0u;
            continue;
        }
        p->worker_ctx = sol_calloc(p->nthreads, sizeof(tx_pool_worker_ctx_t));
        if (!p->worker_ctx) {
            sol_free(p->threads);
            p->threads = NULL;
            p->nthreads = 0u;
            continue;
        }

        for (size_t i = 0; i < p->nthreads; i++) {
            p->worker_ctx[i].p = p;
            p->worker_ctx[i].thread_idx = i;
            if (pthread_create(&p->threads[i], NULL, tx_pool_worker_main, &p->worker_ctx[i]) != 0) {
                p->nthreads = i;
                break;
            }
        }
    }

    sol_log_info("TX pool: workers=%lu shards=%lu (dag=%d dag_min_batch=%lu min_batch=%lu replay_busy_fallback=%lu replay_no_seq_wait=%lu replay_max_batch=%lu replay_wait_ms=%.1f replay_wait_long_ms=%.1f lthash_wait_ms=%.1f)",
                 (unsigned long)(total_spawned_workers ? total_spawned_workers : workers_total),
                 (unsigned long)g_tx_pool_count,
                 tx_dag_sched_enabled() ? 1 : 0,
                 (unsigned long)tx_dag_min_batch(),
                 (unsigned long)tx_pool_min_batch(),
                 (unsigned long)tx_pool_replay_busy_fallback_batch(),
                 (unsigned long)tx_pool_replay_no_seq_fallback_batch(),
                 (unsigned long)tx_pool_replay_max_batch_txs(),
                 (double)tx_pool_replay_queue_wait_budget_ns() / 1000000.0,
                 (double)tx_pool_replay_queue_wait_long_budget_ns() / 1000000.0,
                 (double)lthash_queue_wait_budget_ns() / 1000000.0);
    atexit(tx_pool_shutdown);
}

void
sol_bank_tx_pool_prewarm(void) {
    if (!tx_parallel_enabled() && !lthash_parallel_enabled()) {
        return;
    }

    uint64_t t0 = bank_monotonic_ns();
    (void)pthread_once(&g_tx_pool_once, tx_pool_init_once);
    uint64_t dt_ns = bank_monotonic_ns() - t0;

    if (dt_ns >= 1000000ULL) {
        sol_log_info("TX pool prewarm: %.2fms", (double)dt_ns / 1000000.0);
    }
}

static inline bool
tx_pool_available(const sol_tx_pool_t* p) {
    return p && p->nthreads > 0;
}

static void
tx_pool_run_range(sol_bank_t* bank,
                  const sol_transaction_t* txs,
                  sol_tx_result_t* results,
                  size_t start,
                  size_t end) {
    if (start >= end) return;

    size_t len = end - start;
    tx_pool_stats_t* stats = g_tls_tx_pool_stats;
    uint64_t t0 = stats ? bank_monotonic_ns() : 0;
    uint64_t phase_lock_ns = 0;
    uint64_t phase_wait_ns = 0;
    uint64_t phase_caller_ns = 0;
    uint64_t phase_join_ns = 0;
    bool ran_parallel = false;

    size_t min_batch = tx_pool_min_batch();
    sol_tx_pool_t* p = tx_pool_select(bank);

    /* Parallelize only when the batch is large enough to amortize coordination. */
    if (!tx_pool_available(p) || len < min_batch) {
        for (size_t i = start; i < end; i++) {
            results[i] = sol_bank_process_transaction(bank, &txs[i]);
        }
        if (stats) {
            uint64_t dt = bank_monotonic_ns() - t0;
            stats->seq_calls++;
            stats->seq_txs += (uint64_t)len;
            stats->seq_ns += dt;
        }
        return;
    }

    ran_parallel = true;

    uint64_t t_lock0 = stats ? bank_monotonic_ns() : 0;
    p = tx_pool_lock_for_job(p, bank, len, false);
    if (stats && p) {
        phase_lock_ns = bank_monotonic_ns() - t_lock0;
    }
    if (!p) {
        for (size_t i = start; i < end; i++) {
            results[i] = sol_bank_process_transaction(bank, &txs[i]);
        }
        if (stats) {
            uint64_t dt = bank_monotonic_ns() - t0;
            stats->seq_calls++;
            stats->seq_txs += (uint64_t)len;
            stats->seq_ns += dt;
        }
        return;
    }

    uint64_t t_wait0 = stats ? bank_monotonic_ns() : 0;
    bool idle_ready = tx_pool_wait_idle_locked(p, tx_pool_queue_wait_budget_ns());
    if (stats) {
        phase_wait_ns = bank_monotonic_ns() - t_wait0;
    }
    if (!idle_ready) {
        pthread_mutex_unlock(&p->mu);
        for (size_t i = start; i < end; i++) {
            results[i] = sol_bank_process_transaction(bank, &txs[i]);
        }
        if (stats) {
            uint64_t dt = bank_monotonic_ns() - t0;
            stats->seq_calls++;
            stats->seq_txs += (uint64_t)len;
            stats->seq_ns += dt;
        }
        return;
    }

    /* Wake only the number of worker threads we can use for this job. Waking the
     * full pool for tiny batches is extremely expensive and can dominate replay. */
    size_t workers = tx_pool_worker_threads_for_len(p, len);
    p->job_kind = TX_POOL_JOB_TXS;
    p->bank = bank;
    p->txs = txs;
    p->tx_ptrs = NULL;
    p->use_ptrs = false;
    p->skip_tx_status = false;
    p->replay_sigs_preverified = (g_tls_replay_signatures_preverified != 0);
    p->results = results;
    p->lthash_entries = NULL;
    p->lthash_parent = NULL;
    p->lthash_partials = NULL;
    p->start = start;
    p->end = end;
    __atomic_store_n(&p->next, 0u, __ATOMIC_RELAXED);
    p->active = workers + 1u;
    p->wake = workers;
    p->job_id++;
    p->has_job = true;
    for (size_t i = 0; i < workers; i++) {
        pthread_cond_signal(&p->cv);
    }
    pthread_mutex_unlock(&p->mu);

    /* Caller thread participates. */
    uint64_t t_caller0 = stats ? bank_monotonic_ns() : 0;
    for (;;) {
        size_t off = __atomic_fetch_add(&p->next, 1u, __ATOMIC_RELAXED);
        if (off >= len) break;
        size_t idx = tx_pool_job_index(start, len, off, false);
        results[idx] = sol_bank_process_transaction(bank, &txs[idx]);
    }
    if (stats) {
        phase_caller_ns = bank_monotonic_ns() - t_caller0;
    }

    uint64_t t_join0 = stats ? bank_monotonic_ns() : 0;
    pthread_mutex_lock(&p->mu);
    if (--p->active == 0) {
        p->has_job = false;
        pthread_cond_signal(&p->done);
    }
    while (p->has_job) {
        pthread_cond_wait(&p->done, &p->mu);
    }
    pthread_mutex_unlock(&p->mu);
    if (stats) {
        phase_join_ns = bank_monotonic_ns() - t_join0;
    }

    if (stats && ran_parallel) {
        uint64_t dt = bank_monotonic_ns() - t0;
        stats->par_calls++;
        stats->par_txs += (uint64_t)len;
        stats->par_ns += dt;
        stats->par_lock_ns += phase_lock_ns;
        stats->par_wait_ns += phase_wait_ns;
        stats->par_caller_ns += phase_caller_ns;
        stats->par_join_ns += phase_join_ns;
    }
}

static void
tx_pool_run_range_ptrs(sol_bank_t* bank,
                       const sol_transaction_t* const* tx_ptrs,
                       sol_tx_result_t* results,
                       size_t start,
                       size_t end,
                       bool skip_tx_status) {
    if (start >= end) return;
    if (!bank || !tx_ptrs || !results) return;

    size_t len = end - start;
    tx_pool_stats_t* stats = g_tls_tx_pool_stats;
    uint64_t t0 = stats ? bank_monotonic_ns() : 0;
    uint64_t phase_lock_ns = 0;
    uint64_t phase_wait_ns = 0;
    uint64_t phase_caller_ns = 0;
    uint64_t phase_join_ns = 0;
    bool ran_parallel = false;
    size_t exec_txs = len;
    if (stats) {
        exec_txs = 0;
        for (size_t i = start; i < end; i++) {
            if (tx_ptrs[i]) exec_txs++;
        }
    }

    size_t min_batch = tx_pool_min_batch();
    sol_tx_pool_t* p = tx_pool_select(bank);

    /* Parallelize only when the batch is large enough to amortize coordination. */
    if (!tx_pool_available(p) || len < min_batch) {
        for (size_t i = start; i < end; i++) {
            const sol_transaction_t* tx = tx_ptrs[i];
            if (!tx) {
                /* A NULL tx pointer means the caller already filled results[i]. */
                continue;
            }
            results[i] = skip_tx_status
                ? sol_bank_process_transaction_parallel(bank, tx)
                : sol_bank_process_transaction(bank, tx);
        }
        if (stats) {
            uint64_t dt = bank_monotonic_ns() - t0;
            stats->seq_calls++;
            stats->seq_txs += (uint64_t)exec_txs;
            stats->seq_ns += dt;
        }
        return;
    }

    ran_parallel = true;

    bool throughput_mode = skip_tx_status;
    uint64_t t_lock0 = stats ? bank_monotonic_ns() : 0;
    p = tx_pool_lock_for_job(p, bank, len, throughput_mode);
    if (stats && p) {
        phase_lock_ns = bank_monotonic_ns() - t_lock0;
    }
    if (!p) {
        for (size_t i = start; i < end; i++) {
            const sol_transaction_t* tx = tx_ptrs[i];
            if (!tx) continue;
            results[i] = skip_tx_status
                ? sol_bank_process_transaction_parallel(bank, tx)
                : sol_bank_process_transaction(bank, tx);
        }
        if (stats) {
            uint64_t dt = bank_monotonic_ns() - t0;
            stats->seq_calls++;
            stats->seq_txs += (uint64_t)exec_txs;
            stats->seq_ns += dt;
        }
        return;
    }

    uint64_t queue_wait_budget_ns = throughput_mode
        ? tx_pool_replay_queue_wait_budget_ns()
        : tx_pool_queue_wait_budget_ns();
    uint64_t t_wait0 = stats ? bank_monotonic_ns() : 0;
    bool idle_ready = tx_pool_wait_idle_locked(p, queue_wait_budget_ns);
    if (!idle_ready &&
        throughput_mode &&
        len >= tx_pool_replay_no_seq_fallback_batch()) {
        uint64_t long_budget_ns = tx_pool_replay_queue_wait_long_budget_ns();
        if (long_budget_ns > queue_wait_budget_ns) {
            idle_ready = tx_pool_wait_idle_locked(p, long_budget_ns);
        }
        if (!idle_ready && tx_pool_replay_force_wait_on_busy()) {
            uint64_t cap_ns = tx_pool_replay_force_wait_cap_ns();
            if (cap_ns == 0u) {
                while (!p->stop && p->has_job) {
                    pthread_cond_wait(&p->done, &p->mu);
                }
                idle_ready = !p->stop && !p->has_job;
            } else {
                idle_ready = tx_pool_wait_idle_locked(p, cap_ns);
            }
        }
        if (!idle_ready) {
            sol_tx_pool_t* alt = tx_pool_try_lock_idle_shard(bank, p);
            if (alt) {
                pthread_mutex_unlock(&p->mu);
                p = alt;
                idle_ready = true;
            }
        }
    }
    if (stats) {
        phase_wait_ns = bank_monotonic_ns() - t_wait0;
    }
    if (!idle_ready) {
        pthread_mutex_unlock(&p->mu);
        for (size_t i = start; i < end; i++) {
            const sol_transaction_t* tx = tx_ptrs[i];
            if (!tx) continue;
            results[i] = skip_tx_status
                ? sol_bank_process_transaction_parallel(bank, tx)
                : sol_bank_process_transaction(bank, tx);
        }
        if (stats) {
            uint64_t dt = bank_monotonic_ns() - t0;
            stats->seq_calls++;
            stats->seq_txs += (uint64_t)exec_txs;
            stats->seq_ns += dt;
        }
        return;
    }

    size_t workers = tx_pool_worker_threads_for_len(p, len);
    p->job_kind = TX_POOL_JOB_TX_PTRS;
    p->bank = bank;
    p->txs = NULL;
    p->tx_ptrs = tx_ptrs;
    p->use_ptrs = true;
    p->skip_tx_status = skip_tx_status;
    p->replay_sigs_preverified = (g_tls_replay_signatures_preverified != 0);
    p->results = results;
    p->lthash_entries = NULL;
    p->lthash_parent = NULL;
    p->lthash_partials = NULL;
    p->start = start;
    p->end = end;
    __atomic_store_n(&p->next, 0u, __ATOMIC_RELAXED);
    p->active = workers + 1u;
    p->wake = workers;
    p->job_id++;
    p->has_job = true;
    for (size_t i = 0; i < workers; i++) {
        pthread_cond_signal(&p->cv);
    }
    pthread_mutex_unlock(&p->mu);

    /* Caller thread participates. */
    uint64_t t_caller0 = stats ? bank_monotonic_ns() : 0;
    for (;;) {
        size_t off = __atomic_fetch_add(&p->next, 1u, __ATOMIC_RELAXED);
        if (off >= len) break;
        size_t idx = tx_pool_job_index(start, len, off, throughput_mode);
        const sol_transaction_t* tx = tx_ptrs[idx];
        if (!tx) {
            /* A NULL tx pointer means the caller already filled results[idx]. */
            continue;
        }
        results[idx] = skip_tx_status
            ? sol_bank_process_transaction_parallel(bank, tx)
            : sol_bank_process_transaction(bank, tx);
    }
    if (stats) {
        phase_caller_ns = bank_monotonic_ns() - t_caller0;
    }

    uint64_t t_join0 = stats ? bank_monotonic_ns() : 0;
    pthread_mutex_lock(&p->mu);
    if (--p->active == 0) {
        p->has_job = false;
        pthread_cond_signal(&p->done);
    }
    while (p->has_job) {
        pthread_cond_wait(&p->done, &p->mu);
    }
    pthread_mutex_unlock(&p->mu);
    if (stats) {
        phase_join_ns = bank_monotonic_ns() - t_join0;
    }

    if (stats && ran_parallel) {
        uint64_t dt = bank_monotonic_ns() - t0;
        stats->par_calls++;
        stats->par_txs += (uint64_t)exec_txs;
        stats->par_ns += dt;
        stats->par_lock_ns += phase_lock_ns;
        stats->par_wait_ns += phase_wait_ns;
        stats->par_caller_ns += phase_caller_ns;
        stats->par_join_ns += phase_join_ns;
    }
}

static void
tx_pool_run_dag_ptrs(sol_bank_t* bank,
                     const sol_transaction_t* const* tx_ptrs,
                     sol_tx_result_t* results,
                     const uint32_t* seg_nodes,
                     size_t seg_len,
                     const uint32_t* adj_head,
                     const uint32_t* edge_to,
                     const uint32_t* edge_next,
                     uint32_t* indegree,
                     uint32_t* ready_next,
                     bool skip_tx_status) {
    if (seg_len == 0) return;
    if (!bank || !tx_ptrs || !results || !seg_nodes || !adj_head || !edge_to || !edge_next ||
        !indegree || !ready_next) {
        return;
    }

    tx_pool_stats_t* stats = g_tls_tx_pool_stats;
    uint64_t t0 = stats ? bank_monotonic_ns() : 0;
    uint64_t phase_lock_ns = 0;
    uint64_t phase_wait_ns = 0;
    uint64_t phase_caller_ns = 0;
    uint64_t phase_join_ns = 0;

    size_t min_batch = tx_pool_min_batch();
    sol_tx_pool_t* p = tx_pool_select(bank);

    /* Sequential fallback for small segments or when the pool isn't available. */
    if (!tx_pool_available(p) || seg_len < min_batch) {
        for (size_t i = 0; i < seg_len; i++) {
            uint32_t node = seg_nodes[i];
            const sol_transaction_t* tx = tx_ptrs[node];
            if (!tx) continue;
            results[node] = skip_tx_status
                ? sol_bank_process_transaction_parallel(bank, tx)
                : sol_bank_process_transaction(bank, tx);
        }
        if (stats) {
            uint64_t dt = bank_monotonic_ns() - t0;
            stats->seq_calls++;
            stats->seq_txs += (uint64_t)seg_len;
            stats->seq_ns += dt;
        }
        return;
    }

    if (seg_len > (size_t)UINT32_MAX) {
        /* Defensive: our DAG node indices are uint32_t. */
        for (size_t i = 0; i < seg_len; i++) {
            uint32_t node = seg_nodes[i];
            const sol_transaction_t* tx = tx_ptrs[node];
            if (!tx) continue;
            results[node] = skip_tx_status
                ? sol_bank_process_transaction_parallel(bank, tx)
                : sol_bank_process_transaction(bank, tx);
        }
        if (stats) {
            uint64_t dt = bank_monotonic_ns() - t0;
            stats->seq_calls++;
            stats->seq_txs += (uint64_t)seg_len;
            stats->seq_ns += dt;
        }
        return;
    }

    /* Initialize ready stack from indegree==0 nodes. */
    uint32_t init_head = TX_POOL_DAG_NONE;
    for (size_t i = 0; i < seg_len; i++) {
        uint32_t node = seg_nodes[i];
        if (indegree[node] == 0u) {
            ready_next[node] = init_head;
            init_head = node;
        }
    }
    /* If nothing is ready, something is wrong (cycle or bad graph). Avoid
     * deadlocking by falling back to sequential execution. */
    if (init_head == TX_POOL_DAG_NONE) {
        for (size_t i = 0; i < seg_len; i++) {
            uint32_t node = seg_nodes[i];
            const sol_transaction_t* tx = tx_ptrs[node];
            if (!tx) continue;
            results[node] = skip_tx_status
                ? sol_bank_process_transaction_parallel(bank, tx)
                : sol_bank_process_transaction(bank, tx);
        }
        if (stats) {
            uint64_t dt = bank_monotonic_ns() - t0;
            stats->seq_calls++;
            stats->seq_txs += (uint64_t)seg_len;
            stats->seq_ns += dt;
        }
        return;
    }

    bool throughput_mode = skip_tx_status;
    uint64_t t_lock0 = stats ? bank_monotonic_ns() : 0;
    p = tx_pool_lock_for_job(p, bank, seg_len, throughput_mode);
    if (stats && p) {
        phase_lock_ns = bank_monotonic_ns() - t_lock0;
    }
    if (!p) {
        for (size_t i = 0; i < seg_len; i++) {
            uint32_t node = seg_nodes[i];
            const sol_transaction_t* tx = tx_ptrs[node];
            if (!tx) continue;
            results[node] = skip_tx_status
                ? sol_bank_process_transaction_parallel(bank, tx)
                : sol_bank_process_transaction(bank, tx);
        }
        if (stats) {
            uint64_t dt = bank_monotonic_ns() - t0;
            stats->seq_calls++;
            stats->seq_txs += (uint64_t)seg_len;
            stats->seq_ns += dt;
        }
        return;
    }

    uint64_t queue_wait_budget_ns = throughput_mode
        ? tx_pool_replay_queue_wait_budget_ns()
        : tx_pool_queue_wait_budget_ns();
    uint64_t t_wait0 = stats ? bank_monotonic_ns() : 0;
    bool idle_ready = tx_pool_wait_idle_locked(p, queue_wait_budget_ns);
    if (!idle_ready &&
        throughput_mode &&
        seg_len >= tx_pool_replay_no_seq_fallback_batch()) {
        uint64_t long_budget_ns = tx_pool_replay_queue_wait_long_budget_ns();
        if (long_budget_ns > queue_wait_budget_ns) {
            idle_ready = tx_pool_wait_idle_locked(p, long_budget_ns);
        }
        if (!idle_ready && tx_pool_replay_force_wait_on_busy()) {
            uint64_t cap_ns = tx_pool_replay_force_wait_cap_ns();
            if (cap_ns == 0u) {
                while (!p->stop && p->has_job) {
                    pthread_cond_wait(&p->done, &p->mu);
                }
                idle_ready = !p->stop && !p->has_job;
            } else {
                idle_ready = tx_pool_wait_idle_locked(p, cap_ns);
            }
        }
        if (!idle_ready) {
            sol_tx_pool_t* alt = tx_pool_try_lock_idle_shard(bank, p);
            if (alt) {
                pthread_mutex_unlock(&p->mu);
                p = alt;
                idle_ready = true;
            }
        }
    }
    if (stats) {
        phase_wait_ns = bank_monotonic_ns() - t_wait0;
    }
    if (!idle_ready) {
        pthread_mutex_unlock(&p->mu);
        for (size_t i = 0; i < seg_len; i++) {
            uint32_t node = seg_nodes[i];
            const sol_transaction_t* tx = tx_ptrs[node];
            if (!tx) continue;
            results[node] = skip_tx_status
                ? sol_bank_process_transaction_parallel(bank, tx)
                : sol_bank_process_transaction(bank, tx);
        }
        if (stats) {
            uint64_t dt = bank_monotonic_ns() - t0;
            stats->seq_calls++;
            stats->seq_txs += (uint64_t)seg_len;
            stats->seq_ns += dt;
        }
        return;
    }
    size_t workers = tx_pool_worker_threads_for_len(p, seg_len);
    p->job_kind = TX_POOL_JOB_TX_DAG_PTRS;
    p->bank = bank;
    p->txs = NULL;
    p->tx_ptrs = tx_ptrs;
    p->use_ptrs = true;
    p->skip_tx_status = skip_tx_status;
    p->replay_sigs_preverified = (g_tls_replay_signatures_preverified != 0);
    p->results = results;
    p->dag_adj_head = adj_head;
    p->dag_edge_to = edge_to;
    p->dag_edge_next = edge_next;
    p->dag_indegree = indegree;
    p->dag_ready_next = ready_next;
    p->lthash_entries = NULL;
    p->lthash_parent = NULL;
    p->lthash_partials = NULL;
    p->start = 0;
    p->end = 0;
    __atomic_store_n(&p->dag_ready_head, init_head, __ATOMIC_RELEASE);
    __atomic_store_n(&p->dag_remaining, (uint32_t)seg_len, __ATOMIC_RELEASE);
    __atomic_store_n(&p->next, 0u, __ATOMIC_RELAXED);
    p->active = workers + 1u;
    p->wake = workers;
    p->job_id++;
    p->has_job = true;
    for (size_t i = 0; i < workers; i++) {
        pthread_cond_signal(&p->cv);
    }
    pthread_mutex_unlock(&p->mu);

    /* Caller thread participates. */
    uint64_t t_caller0 = stats ? bank_monotonic_ns() : 0;
    tx_pool_run_dag_worker(bank,
                           tx_ptrs,
                           results,
                           skip_tx_status,
                           adj_head,
                           edge_to,
                           edge_next,
                           indegree,
                           ready_next,
                           &p->dag_ready_head,
                           &p->dag_remaining);
    if (stats) {
        phase_caller_ns = bank_monotonic_ns() - t_caller0;
    }

    uint64_t t_join0 = stats ? bank_monotonic_ns() : 0;
    pthread_mutex_lock(&p->mu);
    if (--p->active == 0) {
        p->has_job = false;
        pthread_cond_signal(&p->done);
    }
    while (p->has_job) {
        pthread_cond_wait(&p->done, &p->mu);
    }
    pthread_mutex_unlock(&p->mu);
    if (stats) {
        phase_join_ns = bank_monotonic_ns() - t_join0;
    }

    if (stats) {
        uint64_t dt = bank_monotonic_ns() - t0;
        stats->par_calls++;
        stats->par_txs += (uint64_t)seg_len;
        stats->par_ns += dt;
        stats->par_lock_ns += phase_lock_ns;
        stats->par_wait_ns += phase_wait_ns;
        stats->par_caller_ns += phase_caller_ns;
        stats->par_join_ns += phase_join_ns;
    }
}

static bool
lthash_parallel_enabled(void) {
    const char* env = getenv("SOL_LT_HASH_PARALLEL");
    if (env && env[0] != '\0') {
        while (*env && isspace((unsigned char)*env)) env++;
        if (*env == '0' || *env == 'n' || *env == 'N' || *env == 'f' || *env == 'F') {
            return false;
        }
    }
    return true;
}

static void
lthash_delta_seq(sol_accounts_db_t* parent,
                 const sol_accounts_db_local_entry_t* entries,
                 size_t count,
                 sol_lt_hash_t* out_delta) {
    if (!out_delta) return;
    if (!entries || count == 0) return;

    for (size_t i = 0; i < count; i++) {
        const sol_accounts_db_local_entry_t* e = &entries[i];
        const sol_account_t* curr = e->account;
        sol_account_t* prev = parent ? sol_accounts_db_load_view(parent, &e->pubkey) : NULL;

        if (accounts_equal_for_lt_hash(prev, curr)) {
            sol_account_destroy(prev);
            continue;
        }

        sol_lt_hash_t prev_hash;
        sol_lt_hash_t curr_hash;
        if (prev) sol_account_lt_hash(&e->pubkey, prev, &prev_hash);
        else      sol_lt_hash_identity(&prev_hash);
        if (curr) sol_account_lt_hash(&e->pubkey, curr, &curr_hash);
        else      sol_lt_hash_identity(&curr_hash);

        sol_lt_hash_mix_out(out_delta, &prev_hash);
        sol_lt_hash_mix_in(out_delta, &curr_hash);
        sol_account_destroy(prev);
    }
}

static void
tx_pool_run_lthash_delta(sol_accounts_db_t* parent,
                         const sol_accounts_db_local_entry_t* entries,
                         size_t count,
                         sol_lt_hash_t* out_delta) {
    if (!out_delta) return;
    sol_lt_hash_identity(out_delta);
    if (!entries || count == 0) return;

    if (!lthash_parallel_enabled()) {
        lthash_delta_seq(parent, entries, count, out_delta);
        return;
    }

    /* Parallelize only when large enough to amortize coordination. */
    if (count < 64u) {
        lthash_delta_seq(parent, entries, count, out_delta);
        return;
    }

    (void)pthread_once(&g_tx_pool_once, tx_pool_init_once);
    sol_tx_pool_t* p = tx_pool_select(NULL);
    if (!tx_pool_available(p)) {
        lthash_delta_seq(parent, entries, count, out_delta);
        return;
    }
    size_t len = count;

    /* Avoid immediate sequential fallback on transiently-busy shards.
     * Queueing briefly behind an in-flight job is typically much cheaper than
     * running a large lt-hash delta fully sequentially on the replay thread. */
    p = tx_pool_lock_for_job(p, NULL, len, true);
    if (!p) {
        lthash_delta_seq(parent, entries, count, out_delta);
        return;
    }

    size_t workers = tx_pool_worker_threads_for_len(p, len);
    if (workers == 0u) {
        pthread_mutex_unlock(&p->mu);
        lthash_delta_seq(parent, entries, count, out_delta);
        return;
    }

    sol_lt_hash_t* partials = sol_calloc(p->nthreads + 1u, sizeof(*partials));
    if (!partials) {
        pthread_mutex_unlock(&p->mu);
        lthash_delta_seq(parent, entries, count, out_delta);
        return;
    }

    size_t no_seq_fallback_batch = tx_pool_replay_no_seq_fallback_batch();
    uint64_t queue_wait_budget_ns = tx_pool_queue_wait_budget_ns();
    if (len >= no_seq_fallback_batch) {
        uint64_t long_budget_ns = tx_pool_replay_queue_wait_long_budget_ns();
        if (long_budget_ns > queue_wait_budget_ns) {
            queue_wait_budget_ns = long_budget_ns;
        }
        uint64_t lt_budget_ns = lthash_queue_wait_budget_ns();
        if (lt_budget_ns == 0u || lt_budget_ns > queue_wait_budget_ns) {
            queue_wait_budget_ns = lt_budget_ns;
        }
    }
    bool idle_ready = tx_pool_wait_idle_locked(p, queue_wait_budget_ns);
    if (!idle_ready || p->stop || p->has_job) {
        static uint32_t warned_seq_fallback = 0;
        if (len >= no_seq_fallback_batch) {
            uint32_t n = __atomic_fetch_add(&warned_seq_fallback, 1u, __ATOMIC_RELAXED);
            if (n < 8u) {
                sol_log_warn("lt_hash_delta: sequential fallback (len=%zu wait_budget_ms=%.1f has_job=%d)",
                             len,
                             (double)queue_wait_budget_ns / 1000000.0,
                             p ? (int)p->has_job : -1);
            }
        }
        pthread_mutex_unlock(&p->mu);
        sol_free(partials);
        lthash_delta_seq(parent, entries, count, out_delta);
        return;
    }

    p->job_kind = TX_POOL_JOB_LT_HASH_DELTA;
    p->bank = NULL;
    p->txs = NULL;
    p->tx_ptrs = NULL;
    p->use_ptrs = false;
    p->skip_tx_status = false;
    p->replay_sigs_preverified = false;
    p->results = NULL;
    p->lthash_entries = entries;
    p->lthash_parent = parent;
    p->lthash_partials = partials;
    p->start = 0;
    p->end = count;
    __atomic_store_n(&p->next, 0u, __ATOMIC_RELAXED);
    p->active = workers + 1u;
    p->wake = workers;
    p->job_id++;
    p->has_job = true;
    for (size_t i = 0; i < workers; i++) {
        pthread_cond_signal(&p->cv);
    }
    pthread_mutex_unlock(&p->mu);

    /* Caller thread participates (use the last partial slot). */
    sol_lt_hash_t* caller_delta = &partials[p->nthreads];
    for (;;) {
        size_t off = __atomic_fetch_add(&p->next, 1u, __ATOMIC_RELAXED);
        if (off >= len) break;
        const sol_accounts_db_local_entry_t* e = &entries[off];
        const sol_account_t* curr = e->account;
        sol_account_t* prev = parent ? sol_accounts_db_load_view(parent, &e->pubkey) : NULL;

        if (accounts_equal_for_lt_hash(prev, curr)) {
            sol_account_destroy(prev);
            continue;
        }

        sol_lt_hash_t prev_hash;
        sol_lt_hash_t curr_hash;
        if (prev) sol_account_lt_hash(&e->pubkey, prev, &prev_hash);
        else      sol_lt_hash_identity(&prev_hash);
        if (curr) sol_account_lt_hash(&e->pubkey, curr, &curr_hash);
        else      sol_lt_hash_identity(&curr_hash);

        sol_lt_hash_mix_out(caller_delta, &prev_hash);
        sol_lt_hash_mix_in(caller_delta, &curr_hash);
        sol_account_destroy(prev);
    }

    pthread_mutex_lock(&p->mu);
    if (--p->active == 0) {
        p->has_job = false;
        pthread_cond_signal(&p->done);
    }
    while (p->has_job) {
        pthread_cond_wait(&p->done, &p->mu);
    }
    pthread_mutex_unlock(&p->mu);

    for (size_t i = 0; i < (p->nthreads + 1u); i++) {
        sol_lt_hash_mix_in(out_delta, &partials[i]);
    }

    sol_free(partials);
}

sol_err_t
sol_bank_process_transactions(sol_bank_t* bank, const sol_transaction_t* txs,
                              size_t count, sol_tx_result_t* results) {
    if (!bank || !txs || !results) return SOL_ERR_INVAL;
    if (count == 0) return SOL_OK;

    if (!tx_parallel_enabled() || count < tx_parallel_min_batch()) {
        for (size_t i = 0; i < count; i++) {
            results[i] = sol_bank_process_transaction(bank, &txs[i]);
        }
        return SOL_OK;
    }

    (void)pthread_once(&g_tx_pool_once, tx_pool_init_once);

    /* Deterministic batching: execute maximal contiguous ranges of
     * non-conflicting transactions in parallel. */
    sol_pubkey_map_t* batch_reads = sol_pubkey_map_new(sizeof(uint8_t), 1024u);
    sol_pubkey_map_t* batch_writes = sol_pubkey_map_new(sizeof(uint8_t), 1024u);
    if (!batch_reads || !batch_writes) {
        if (batch_reads) sol_pubkey_map_destroy(batch_reads);
        if (batch_writes) sol_pubkey_map_destroy(batch_writes);
        for (size_t i = 0; i < count; i++) {
            results[i] = sol_bank_process_transaction(bank, &txs[i]);
        }
        return SOL_OK;
    }

    sol_pubkey_t keys[SOL_MAX_MESSAGE_ACCOUNTS];
    bool writable[SOL_MAX_MESSAGE_ACCOUNTS];
    bool signer[SOL_MAX_MESSAGE_ACCOUNTS];
    (void)signer;

    uint8_t one = 1u;
    size_t batch_start = 0;

    bank_v0_resolve_cache_t v0_cache = {0};
    v0_cache.patches = sol_calloc(count, sizeof(*v0_cache.patches));
    if (v0_cache.patches) {
        v0_cache.patches_cap = count;
    }

    for (size_t i = 0; i < count; i++) {
        const sol_transaction_t* tx = &txs[i];

        /* Address lookup table resolution depends on on-chain ALT account data.
         * If a prior transaction in the current batch wrote any ALT table that
         * this transaction needs to read for resolution, flush first so we
         * resolve against the correct post-write state. */
        if (tx->message.version == SOL_MESSAGE_VERSION_V0 &&
            tx->message.address_lookups_len > 0 &&
            tx->message.address_lookups) {
            bool alt_conflict = false;
            for (uint8_t li = 0; li < tx->message.address_lookups_len; li++) {
                const sol_pubkey_t* table = &tx->message.address_lookups[li].account_key;
                if (sol_pubkey_map_get(batch_writes, table)) {
                    alt_conflict = true;
                    break;
                }
            }
            if (alt_conflict && batch_start < i) {
                tx_pool_run_range(bank, txs, results, batch_start, i);
                sol_map_clear(batch_reads->inner);
                sol_map_clear(batch_writes->inner);
                batch_start = i;
            }
        }

        size_t key_len = 0;
        const sol_pubkey_t* keys_view = NULL;
        const bool* writable_view = NULL;

        sol_err_t rerr = SOL_OK;
        if (tx->message.version == SOL_MESSAGE_VERSION_V0 && v0_cache.patches) {
            sol_err_t cerr = bank_v0_cache_resolve(bank, tx, &v0_cache);
            if (cerr == SOL_OK) {
                const sol_message_t* msg = &tx->message;
                key_len = (size_t)msg->resolved_accounts_len;
                keys_view = msg->resolved_accounts;
                writable_view = msg->is_writable;
            } else {
                rerr = cerr;
            }
        }

        if (!keys_view) {
            rerr = sol_bank_resolve_transaction_accounts(bank,
                                                        tx,
                                                        keys,
                                                        writable,
                                                        signer,
                                                        SOL_MAX_MESSAGE_ACCOUNTS,
                                                        &key_len);
            if (rerr == SOL_OK) {
                keys_view = keys;
                writable_view = writable;
            }
        }

        if (rerr != SOL_OK || !keys_view || !writable_view) {
            /* Can't build a lock set; execute sequentially after flushing. */
            if (batch_start < i) {
                tx_pool_run_range(bank, txs, results, batch_start, i);
                sol_map_clear(batch_reads->inner);
                sol_map_clear(batch_writes->inner);
            }

            results[i] = sol_bank_process_transaction(bank, &txs[i]);
            batch_start = i + 1;
            continue;
        }

        /* Include implicit read locks for upgradeable program ProgramData
         * accounts. These are read during BPF execution but are not part of the
         * resolved account list, so without them parallel scheduling can run
         * upgrades concurrently with invocations. */
        sol_pubkey_t progdata_keys[64];
        size_t progdata_len = 0;
        sol_pubkey_t seen_progids[64];
        size_t seen_progids_len = 0;

        /* If a prior tx wrote an invoked program account, flush before we
         * inspect it for ProgramData so we read the post-write state. */
        bool prog_barrier = false;
        for (uint8_t ix_i = 0; ix_i < tx->message.instructions_len; ix_i++) {
            const sol_compiled_instruction_t* ix = &tx->message.instructions[ix_i];
            if ((size_t)ix->program_id_index >= key_len) {
                continue;
            }
            const sol_pubkey_t* pid = &keys_view[ix->program_id_index];
            if (sol_pubkey_eq(pid, &SOL_SYSTEM_PROGRAM_ID) ||
                sol_pubkey_eq(pid, &SOL_VOTE_PROGRAM_ID) ||
                sol_pubkey_eq(pid, &SOL_COMPUTE_BUDGET_ID) ||
                sol_pubkey_eq(pid, &SOL_ED25519_PROGRAM_ID) ||
                sol_pubkey_eq(pid, &SOL_SECP256K1_PROGRAM_ID) ||
                sol_pubkey_eq(pid, &SOL_SECP256R1_PROGRAM_ID) ||
                sol_pubkey_eq(pid, &SOL_BPF_LOADER_UPGRADEABLE_ID) ||
                sol_pubkey_eq(pid, &SOL_BPF_LOADER_V2_ID)) {
                continue;
            }
            if (sol_pubkey_map_get(batch_writes, pid)) {
                prog_barrier = true;
                break;
            }
        }
        if (prog_barrier && batch_start < i) {
            tx_pool_run_range(bank, txs, results, batch_start, i);
            sol_map_clear(batch_reads->inner);
            sol_map_clear(batch_writes->inner);
            batch_start = i;
        }

        for (uint8_t ix_i = 0; ix_i < tx->message.instructions_len; ix_i++) {
            const sol_compiled_instruction_t* ix = &tx->message.instructions[ix_i];
            if ((size_t)ix->program_id_index >= key_len) {
                continue;
            }
            const sol_pubkey_t* pid = &keys_view[ix->program_id_index];
            if (sol_pubkey_eq(pid, &SOL_SYSTEM_PROGRAM_ID) ||
                sol_pubkey_eq(pid, &SOL_VOTE_PROGRAM_ID) ||
                sol_pubkey_eq(pid, &SOL_COMPUTE_BUDGET_ID) ||
                sol_pubkey_eq(pid, &SOL_ED25519_PROGRAM_ID) ||
                sol_pubkey_eq(pid, &SOL_SECP256K1_PROGRAM_ID) ||
                sol_pubkey_eq(pid, &SOL_SECP256R1_PROGRAM_ID) ||
                sol_pubkey_eq(pid, &SOL_BPF_LOADER_UPGRADEABLE_ID) ||
                sol_pubkey_eq(pid, &SOL_BPF_LOADER_V2_ID)) {
                continue;
            }

            bool seen = false;
            for (size_t si = 0; si < seen_progids_len; si++) {
                if (sol_pubkey_eq(&seen_progids[si], pid)) {
                    seen = true;
                    break;
                }
            }
            if (seen) {
                continue;
            }
            if (seen_progids_len < (sizeof(seen_progids) / sizeof(seen_progids[0]))) {
                seen_progids[seen_progids_len++] = *pid;
            }

            sol_pubkey_t pd = {0};
            if (bank_get_upgradeable_programdata_pubkey(bank, pid, &pd)) {
                if (progdata_len < (sizeof(progdata_keys) / sizeof(progdata_keys[0]))) {
                    progdata_keys[progdata_len++] = pd;
                }
            }
        }

        bool conflict = false;
        for (size_t k = 0; k < key_len; k++) {
            if (writable_view[k]) {
                if (sol_pubkey_map_get(batch_writes, &keys_view[k]) ||
                    sol_pubkey_map_get(batch_reads, &keys_view[k])) {
                    conflict = true;
                    break;
                }
            } else {
                if (sol_pubkey_map_get(batch_writes, &keys_view[k])) {
                    conflict = true;
                    break;
                }
            }
        }

        if (!conflict) {
            for (size_t pk = 0; pk < progdata_len; pk++) {
                if (sol_pubkey_map_get(batch_writes, &progdata_keys[pk])) {
                    conflict = true;
                    break;
                }
            }
        }

        if (conflict && batch_start < i) {
            /* Execute prior batch. */
            tx_pool_run_range(bank, txs, results, batch_start, i);
            sol_map_clear(batch_reads->inner);
            sol_map_clear(batch_writes->inner);
            batch_start = i;
        }

        /* Add tx accounts to batch set. */
        for (size_t k = 0; k < key_len; k++) {
            if (writable_view[k]) {
                (void)sol_pubkey_map_insert(batch_writes, &keys_view[k], &one);
            } else {
                (void)sol_pubkey_map_insert(batch_reads, &keys_view[k], &one);
            }
        }

        /* Lock ALT table accounts as read-only for scheduling purposes. They are
         * not part of the resolved account list passed to programs, but they are
         * read during v0 account resolution. */
        if (tx->message.version == SOL_MESSAGE_VERSION_V0 &&
            tx->message.address_lookups_len > 0 &&
            tx->message.address_lookups) {
            for (uint8_t li = 0; li < tx->message.address_lookups_len; li++) {
                (void)sol_pubkey_map_insert(batch_reads,
                                            &tx->message.address_lookups[li].account_key,
                    &one);
            }
        }

        for (size_t pk = 0; pk < progdata_len; pk++) {
            (void)sol_pubkey_map_insert(batch_reads, &progdata_keys[pk], &one);
        }
    }

    /* Execute last batch. */
    if (batch_start < count) {
        tx_pool_run_range(bank, txs, results, batch_start, count);
    }

    bank_v0_cache_destroy(&v0_cache);

    sol_pubkey_map_destroy(batch_reads);
    sol_pubkey_map_destroy(batch_writes);
    return SOL_OK;
}

static uint64_t
tx_seen_sig_hash(const void* key) {
    const sol_signature_t* sig = (const sol_signature_t*)key;
    return sol_hash_bytes(sig->bytes, sizeof(sig->bytes));
}

static bool
tx_seen_sig_eq(const void* a, const void* b) {
    return memcmp(a, b, sizeof(sol_signature_t)) == 0;
}

/* Wave scheduler barrier: transactions that can mutate state required for lock-set
 * construction (e.g. ALT tables, program upgrades). These are rare on mainnet,
 * but must be processed in-order to keep v0 resolution and implicit ProgramData
 * locks correct. */
static bool
tx_is_wave_barrier(const sol_transaction_t* tx) {
    if (!tx) return false;
    const sol_message_t* msg = &tx->message;
    if (!msg->account_keys || msg->account_keys_len == 0) return false;

    const sol_pubkey_t* keys = msg->account_keys;
    size_t keys_len = (size_t)msg->account_keys_len;

    for (uint8_t ix_i = 0; ix_i < msg->instructions_len; ix_i++) {
        const sol_compiled_instruction_t* ix = &msg->instructions[ix_i];
        if (!ix) continue;
        if ((size_t)ix->program_id_index >= keys_len) continue;
        const sol_pubkey_t* pid = &keys[ix->program_id_index];
        if (sol_pubkey_eq(pid, &SOL_ADDRESS_LOOKUP_TABLE_ID) ||
            sol_pubkey_eq(pid, &SOL_BPF_LOADER_UPGRADEABLE_ID) ||
            sol_pubkey_eq(pid, &SOL_BPF_LOADER_V2_ID) ||
            sol_pubkey_eq(pid, &SOL_BPF_LOADER_DEPRECATED_ID)) {
            return true;
        }
    }
    return false;
}

typedef struct {
    uint32_t last_write; /* wave index + 1, 0 = none */
    uint32_t last_read;  /* wave index + 1, 0 = none */
} tx_wave_last_t;

typedef struct {
    size_t*           tx_indices;
    size_t            tx_len;
    size_t            tx_cap;
} tx_wave_t;

static void
tx_wave_destroy(tx_wave_t* w) {
    if (!w) return;
    sol_free(w->tx_indices);
    memset(w, 0, sizeof(*w));
}

static inline void
tx_wave_reset(tx_wave_t* w) {
    if (!w) return;
    w->tx_len = 0;
}

static bool
tx_wave_push(tx_wave_t* w, size_t tx_index) {
    if (!w) return false;
    if (w->tx_len == w->tx_cap) {
        size_t new_cap = w->tx_cap ? (w->tx_cap * 2u) : 64u;
        size_t* next = sol_realloc_array(size_t, w->tx_indices, new_cap);
        if (!next) return false;
        w->tx_indices = next;
        w->tx_cap = new_cap;
    }
    w->tx_indices[w->tx_len++] = tx_index;
    return true;
}

typedef struct {
    /* Legacy contiguous batching scratch (also used by DAG/wave paths). */
    sol_pubkey_map_t* batch_reads;
    sol_pubkey_map_t* batch_writes;
    sol_map_t*        seen_sigs;

    /* v0 account resolution scratch (avoid per-slot arena churn). */
    bank_v0_resolve_cache_t v0_cache;

    /* sol_bank_process_entries scratch (flattened tx pointers/results). */
    const sol_transaction_t**  batch_tx_ptrs;
    sol_tx_result_t*           batch_results;
    size_t                     batch_buf_cap;

    /* Shared for DAG + wave schedulers (account last-access tracking). */
    sol_pubkey_map_t* last_access;

    /* Wave scheduler scratch. */
    tx_wave_t*                 waves;
    size_t                     waves_cap;
    const sol_transaction_t**  wave_ptrs;
    sol_tx_result_t*           wave_results;
    size_t                     wave_buf_cap;

    /* DAG scheduler scratch. */
    uint32_t*  dag_adj_head;
    uint32_t*  dag_indegree;
    uint32_t*  dag_ready_next;
    uint32_t*  dag_seg_nodes;
    size_t     dag_node_cap;
    uint32_t*  dag_edge_to;
    uint32_t*  dag_edge_next;
    size_t     dag_edge_cap;
} tx_sched_scratch_t;

static __thread tx_sched_scratch_t g_tls_tx_sched_scratch = {0};

static bool
tx_sched_ensure_pubkey_map(sol_pubkey_map_t** map,
                           size_t val_size,
                           size_t reserve_cap) {
    if (!map) return false;
    if (!*map) {
        *map = sol_pubkey_map_new(val_size, reserve_cap);
        return *map != NULL;
    }
    if ((*map)->inner) {
        (void)sol_map_reserve((*map)->inner, reserve_cap);
    }
    return true;
}

static bool
tx_sched_ensure_seen_sigs(sol_map_t** map, size_t reserve_cap) {
    if (!map) return false;
    if (!*map) {
        *map = sol_map_new(sizeof(sol_signature_t),
                           sizeof(uint8_t),
                           tx_seen_sig_hash,
                           tx_seen_sig_eq,
                           reserve_cap);
        return *map != NULL;
    }
    (void)sol_map_reserve(*map, reserve_cap);
    return true;
}

static bool
tx_sched_ensure_v0_patches(bank_v0_resolve_cache_t* cache, size_t count) {
    if (!cache) return false;
    if (cache->patches_cap >= count) return true;
    bank_v0_msg_patch_t* next = sol_realloc_array(bank_v0_msg_patch_t, cache->patches, count);
    if (!next) return false;
    if (count > cache->patches_cap) {
        memset(next + cache->patches_cap,
               0,
               (count - cache->patches_cap) * sizeof(*next));
    }
    cache->patches = next;
    cache->patches_cap = count;
    return true;
}

static bool
tx_sched_ensure_waves(tx_sched_scratch_t* sc, size_t count) {
    if (!sc) return false;

    if (sc->waves_cap < count) {
        tx_wave_t* next = sol_realloc_array(tx_wave_t, sc->waves, count);
        if (!next) return false;
        /* New slots must start zeroed so tx_indices pointers are NULL. */
        if (count > sc->waves_cap) {
            memset(next + sc->waves_cap, 0, (count - sc->waves_cap) * sizeof(*next));
        }
        sc->waves = next;
        sc->waves_cap = count;
    }

    if (sc->wave_buf_cap < count) {
        const sol_transaction_t** next_ptrs =
            sol_realloc_array(const sol_transaction_t*, sc->wave_ptrs, count);
        if (!next_ptrs) return false;
        sc->wave_ptrs = next_ptrs;

        sol_tx_result_t* next_results =
            sol_realloc_array(sol_tx_result_t, sc->wave_results, count);
        if (!next_results) return false;
        sc->wave_results = next_results;

        sc->wave_buf_cap = count;
    }

    return true;
}

static bool
tx_sched_ensure_batch_bufs(tx_sched_scratch_t* sc, size_t count) {
    if (!sc) return false;

    if (sc->batch_buf_cap < count) {
        const sol_transaction_t** next_ptrs =
            sol_realloc_array(const sol_transaction_t*, sc->batch_tx_ptrs, count);
        if (!next_ptrs) return false;
        sc->batch_tx_ptrs = next_ptrs;

        sol_tx_result_t* next_results =
            sol_realloc_array(sol_tx_result_t, sc->batch_results, count);
        if (!next_results) return false;
        sc->batch_results = next_results;

        sc->batch_buf_cap = count;
    }

    return true;
}

static bool
tx_sched_ensure_dag(tx_sched_scratch_t* sc, size_t count, size_t edge_cap) {
    if (!sc) return false;
    if (sc->dag_node_cap < count) {
        uint32_t* next_adj = sol_realloc_array(uint32_t, sc->dag_adj_head, count);
        if (!next_adj) return false;
        sc->dag_adj_head = next_adj;

        uint32_t* next_indeg = sol_realloc_array(uint32_t, sc->dag_indegree, count);
        if (!next_indeg) return false;
        sc->dag_indegree = next_indeg;

        uint32_t* next_ready = sol_realloc_array(uint32_t, sc->dag_ready_next, count);
        if (!next_ready) return false;
        sc->dag_ready_next = next_ready;

        uint32_t* next_seg = sol_realloc_array(uint32_t, sc->dag_seg_nodes, count);
        if (!next_seg) return false;
        sc->dag_seg_nodes = next_seg;

        sc->dag_node_cap = count;
    }
    if (sc->dag_edge_cap < edge_cap) {
        uint32_t* next_to = sol_realloc_array(uint32_t, sc->dag_edge_to, edge_cap);
        if (!next_to) return false;
        sc->dag_edge_to = next_to;

        uint32_t* next_next = sol_realloc_array(uint32_t, sc->dag_edge_next, edge_cap);
        if (!next_next) return false;
        sc->dag_edge_next = next_next;

        sc->dag_edge_cap = edge_cap;
    }
    return true;
}

static sol_err_t
sol_bank_process_transactions_ptrs(sol_bank_t* bank,
                                   const sol_transaction_t** tx_ptrs,
                                   size_t count,
                                   sol_tx_result_t* results) {
    if (!bank || !tx_ptrs || !results) return SOL_ERR_INVAL;
    if (count == 0) return SOL_OK;

    tx_pool_stats_t pool_stats = {0};
    bool tx_pool_stats = tx_pool_stats_enabled();
    if (__builtin_expect(tx_pool_stats, 0)) {
        g_tls_tx_pool_stats = &pool_stats;
    }

    if (!tx_parallel_enabled() || count < tx_parallel_min_batch()) {
        for (size_t i = 0; i < count; i++) {
            results[i] = sol_bank_process_transaction(bank, tx_ptrs[i]);
        }
        if (__builtin_expect(tx_pool_stats, 0)) {
            /* No batching/pool usage in this path; clear TLS pointer. */
            g_tls_tx_pool_stats = NULL;
        }
        return SOL_OK;
    }

    (void)pthread_once(&g_tx_pool_once, tx_pool_init_once);

    /* Deterministic batching: execute maximal contiguous ranges of
     * non-conflicting transactions in parallel. */
    tx_sched_scratch_t* sc = &g_tls_tx_sched_scratch;

    size_t lockset_reserve = tx_sched_lockset_reserve(count);
    if (!tx_sched_ensure_pubkey_map(&sc->batch_reads, sizeof(uint8_t), lockset_reserve) ||
        !tx_sched_ensure_pubkey_map(&sc->batch_writes, sizeof(uint8_t), lockset_reserve)) {
        for (size_t i = 0; i < count; i++) {
            results[i] = sol_bank_process_transaction(bank, tx_ptrs[i]);
        }
        if (__builtin_expect(tx_pool_stats, 0)) {
            g_tls_tx_pool_stats = NULL;
        }
        return SOL_OK;
    }

    sol_pubkey_map_t* batch_reads = sc->batch_reads;
    sol_pubkey_map_t* batch_writes = sc->batch_writes;
    sol_map_clear(batch_reads->inner);
    sol_map_clear(batch_writes->inner);

    sol_pubkey_t keys[SOL_MAX_MESSAGE_ACCOUNTS];
    bool writable[SOL_MAX_MESSAGE_ACCOUNTS];
    bool signer[SOL_MAX_MESSAGE_ACCOUNTS];
    (void)signer;

    uint8_t one = 1u;
    size_t batch_start = 0;

    bank_v0_resolve_cache_t* v0_cache = &sc->v0_cache;
    /* Ensure message patches from a prior call are reverted. */
    bank_v0_cache_reset(v0_cache);
    bank_v0_msg_patch_t* saved_v0_patches = v0_cache->patches;
    size_t saved_v0_patches_cap = v0_cache->patches_cap;
    bool v0_cache_disabled = false;
    if (g_tls_replay_context) {
        /* Replay can overlap transaction processing with async entry
         * verification. Avoid mutating v0 message fields in-place in this
         * context so verifier threads never race with scheduler patch/reset. */
        v0_cache_disabled = true;
        v0_cache->patches = NULL;
        v0_cache->patches_cap = 0;
    } else if (!tx_sched_ensure_v0_patches(v0_cache, count)) {
        /* Fall back to resolving v0 messages without caching. */
        v0_cache_disabled = true;
        v0_cache->patches = NULL;
        v0_cache->patches_cap = 0;
    }

    static int tx_batch_stats_cached = -1;
    if (__builtin_expect(tx_batch_stats_cached < 0, 0)) {
        const char* env = getenv("SOL_TX_BATCH_STATS");
        tx_batch_stats_cached = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    }
    bool tx_batch_stats = tx_batch_stats_cached != 0;
    size_t tx_batch_cnt = 0;
    size_t tx_batch_txs = 0;
    size_t tx_batch_min = SIZE_MAX;
    size_t tx_batch_max = 0;
    size_t tx_batch_lt8_cnt = 0;
    size_t tx_batch_lt8_txs = 0;
    size_t tx_batch_seq_txs = 0;
    size_t tx_batch_hist[8] = {0}; /* sizes 0..7; we use 1..7 */

#define TX_BATCH_STATS_ADD(len_) do {               \
        size_t _l = (len_);                         \
        if (_l == 0) break;                         \
        tx_batch_cnt++;                             \
        tx_batch_txs += _l;                         \
        if (_l < tx_batch_min) tx_batch_min = _l;   \
        if (_l > tx_batch_max) tx_batch_max = _l;   \
        if (_l < 8u) {                              \
            tx_batch_lt8_cnt++;                     \
            tx_batch_lt8_txs += _l;                 \
            if (_l < (sizeof(tx_batch_hist) / sizeof(tx_batch_hist[0]))) { \
                tx_batch_hist[_l]++;                \
            }                                       \
        }                                           \
    } while (0)

    /* In the parallel path, avoid bank->lock contention from tx-status
     * reserve/record by doing duplicate filtering up-front and recording tx
     * statuses after execution in a single thread. */
    bool skip_tx_status = true;
    sol_map_t* seen_sigs = NULL;
    if (tx_sched_ensure_seen_sigs(&sc->seen_sigs, count * 2u)) {
        seen_sigs = sc->seen_sigs;
        sol_map_clear(seen_sigs);
    } else {
        skip_tx_status = false;
    }
    size_t replay_max_batch_txs = 0u;
    if (skip_tx_status && g_tls_replay_context) {
        replay_max_batch_txs = tx_pool_replay_max_batch_txs();
    }

    if (tx_wave_sched_enabled()) {
        static int tx_wave_diag_cached = -1;
        if (__builtin_expect(tx_wave_diag_cached < 0, 0)) {
            const char* env = getenv("SOL_TX_WAVE_DIAG");
            tx_wave_diag_cached = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
        }
        bool tx_wave_diag = tx_wave_diag_cached != 0;
        uint64_t wave_total_t0 = tx_wave_diag ? bank_monotonic_ns() : 0;
        uint64_t wave_exec_ns = 0;
        size_t wave_flushes = 0;
        size_t wave_waves_created = 0;
        size_t wave_waves_peak = 0;
        size_t wave_txs_scheduled = 0;

        /* Wave scheduler: build independent "waves" separated by barriers that can
         * change lock-set construction (ALT updates, program upgrades). Execute
         * waves sequentially; each wave runs in parallel. */
        sol_pubkey_map_t* last_access = NULL;
        if (!tx_sched_ensure_pubkey_map(&sc->last_access,
                                        sizeof(tx_wave_last_t),
                                        count * 16u)) {
            goto legacy_sched;
        }
        last_access = sc->last_access;
        sol_map_clear(last_access->inner);

        bool use_dag =
            tx_dag_sched_enabled() &&
            count >= tx_dag_min_batch() &&
            count <= (size_t)UINT32_MAX;

        /* Pre-pass for duplicate filtering and NULL tx pointers. Must happen before
         * any parallel execution in skip_tx_status mode. */
	        for (size_t i = 0; i < count; i++) {
	            const sol_transaction_t* tx = tx_ptrs[i];
	            if (!tx) {
	                sol_tx_result_t r = {0};
	                r.status = SOL_ERR_INVAL;
                results[i] = r;
                continue;
            }

            if (skip_tx_status) {
                const sol_signature_t* sig = sol_transaction_signature(tx);
                if (sig && sol_map_contains(seen_sigs, sig)) {
                    sol_tx_result_t r = {0};
                    r.status = SOL_ERR_TX_ALREADY_PROCESSED;
                    results[i] = r;
                    tx_ptrs[i] = NULL;

                    BANK_STAT_INC(bank, transactions_processed);
                    BANK_STAT_INC(bank, transactions_failed);
                    BANK_STAT_INC(bank, rejected_duplicate);
                    log_prevalidation_rejection(bank, tx, "duplicate", SOL_ERR_TX_ALREADY_PROCESSED);
                    continue;
                }
                if (sig) {
                    (void)sol_map_insert(seen_sigs, sig, &one);
	                }
	            }
	        }

	        /* DAG scheduler: build a tx-index dependency graph and execute ready txs
	         * as soon as their (account-lock) predecessors complete. This removes the
	         * full barrier between "waves" and significantly improves throughput
	         * when the workload contains a few long-running txs that would otherwise
	         * stall unrelated dependent chains. */
	        if (use_dag) {
                    size_t edge_cap_mul = 32u;
                    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
                    if (ncpu >= 128) {
                        edge_cap_mul = 96u;
                    } else if (ncpu >= 96) {
                        edge_cap_mul = 80u;
                    } else if (ncpu >= 64) {
                        edge_cap_mul = 64u;
                    }
                    size_t edge_cap =
                        (count > (SIZE_MAX / edge_cap_mul)) ? SIZE_MAX : (count * edge_cap_mul);
                    if (edge_cap < 1024u) edge_cap = 1024u;
                    size_t edge_cap_limit = tx_dag_edge_cap_limit(count);
                    if (edge_cap > edge_cap_limit) edge_cap = edge_cap_limit;
                    if (!tx_sched_ensure_dag(sc, count, edge_cap)) {
	                /* Allocation failed; fall back to the barriered wave scheduler. */
	                use_dag = false;
	            } else {
	                uint32_t* adj_head = sc->dag_adj_head;
	                uint32_t* indegree = sc->dag_indegree;
	                uint32_t* ready_next = sc->dag_ready_next;
	                uint32_t* seg_nodes = sc->dag_seg_nodes;
	                uint32_t* edge_to = sc->dag_edge_to;
	                uint32_t* edge_next = sc->dag_edge_next;
	                edge_cap = sc->dag_edge_cap;

	                memset(adj_head, 0xFF, count * sizeof(*adj_head));
	                memset(indegree, 0, count * sizeof(*indegree));
	                memset(ready_next, 0xFF, count * sizeof(*ready_next));
	                sol_map_clear(last_access->inner);

		                size_t seg_len = 0;
		                size_t edge_len = 0;
		                size_t seg_begin = SIZE_MAX;
		                size_t seg_end = 0;
		                size_t dag_segments = 0;
		                size_t dag_edges_total = 0;
		                size_t dag_txs_scheduled = 0;
		                uint64_t dag_exec_ns = 0;
		                bool dag_abort = false;
                        bool dag_fallback_to_wave = false;
                        size_t dag_abort_at = SIZE_MAX;

#define TX_DAG_SEG_RESET() do {                                           \
		                        seg_len = 0;                                    \
		                        edge_len = 0;                                   \
		                        seg_begin = SIZE_MAX;                            \
		                        seg_end = 0;                                    \
		                        memset(adj_head, 0xFF, count * sizeof(*adj_head)); \
		                        memset(indegree, 0, count * sizeof(*indegree)); \
		                        sol_map_clear(last_access->inner);              \
		                    } while (0)

#define TX_DAG_FLUSH_EXEC() do {                                          \
		                        if (seg_len == 0) break;                        \
		                        if (__builtin_expect(tx_batch_stats, 0)) {      \
		                            TX_BATCH_STATS_ADD(seg_len);                \
		                        }                                                \
		                        uint64_t _exec0 = __builtin_expect(tx_wave_diag, 0) ? bank_monotonic_ns() : 0; \
		                        if (edge_len == 0 && seg_begin != SIZE_MAX && seg_end > seg_begin) { \
		                            /* Fast path: no dependencies => execute as a plain parallel range. */ \
		                            tx_pool_run_range_ptrs(bank,                 \
		                                                   tx_ptrs,              \
		                                                   results,              \
		                                                   seg_begin,            \
		                                                   seg_end,              \
		                                                   skip_tx_status);      \
		                        } else {                                        \
		                            tx_pool_run_dag_ptrs(bank,                  \
		                                                 tx_ptrs,               \
		                                                 results,               \
		                                                 seg_nodes,             \
		                                                 seg_len,               \
		                                                 adj_head,              \
		                                                 edge_to,               \
		                                                 edge_next,             \
		                                                 indegree,              \
		                                                 ready_next,            \
		                                                 skip_tx_status);       \
		                        }                                               \
		                        if (__builtin_expect(tx_wave_diag, 0)) {        \
		                            dag_exec_ns += bank_monotonic_ns() - _exec0; \
		                        }                                                \
		                        dag_segments++;                                  \
	                        dag_edges_total += edge_len;                     \
		                        TX_DAG_SEG_RESET();                              \
		                    } while (0)

#define TX_DAG_ENSURE_EDGE_CAP_OR_ABORT() do {                             \
                                if (edge_len < edge_cap) break;             \
                                if (edge_cap >= edge_cap_limit) {           \
                                    dag_abort = true;                       \
                                    break;                                  \
                                }                                           \
                                size_t new_cap = edge_cap * 2u;             \
                                if (new_cap < edge_cap || new_cap > edge_cap_limit) { \
                                    new_cap = edge_cap_limit;               \
                                }                                           \
                                uint32_t* new_to = sol_alloc(new_cap * sizeof(*new_to)); \
                                uint32_t* new_next = sol_alloc(new_cap * sizeof(*new_next)); \
                                if (!new_to || !new_next) {                 \
                                    sol_free(new_to);                       \
                                    sol_free(new_next);                     \
                                    dag_abort = true;                       \
                                    break;                                  \
                                }                                           \
                                memcpy(new_to, edge_to, edge_len * sizeof(*new_to)); \
                                memcpy(new_next, edge_next, edge_len * sizeof(*new_next)); \
                                sol_free(edge_to);                          \
                                sol_free(edge_next);                        \
                                edge_to = new_to;                           \
                                edge_next = new_next;                       \
                                edge_cap = new_cap;                         \
                            } while (0)

                    for (size_t i = 0; i < count; i++) {
	                    const sol_transaction_t* tx = tx_ptrs[i];
	                    if (!tx) continue;

	                    if (tx_is_wave_barrier(tx)) {
	                        TX_DAG_FLUSH_EXEC();
	                        results[i] = skip_tx_status
	                            ? sol_bank_process_transaction_parallel(bank, tx)
	                            : sol_bank_process_transaction(bank, tx);
	                        if (__builtin_expect(tx_batch_stats, 0)) {
	                            TX_BATCH_STATS_ADD(1u);
	                            tx_batch_seq_txs++;
	                        }
	                        continue;
	                    }

	                    size_t key_len = 0;
	                    const sol_pubkey_t* keys_view = NULL;
	                    const bool* writable_view = NULL;

	                    sol_err_t rerr = SOL_OK;
	                    if (tx->message.version == SOL_MESSAGE_VERSION_V0 && v0_cache->patches) {
	                        sol_err_t cerr = bank_v0_cache_resolve(bank, tx, v0_cache);
	                        if (cerr == SOL_OK) {
	                            const sol_message_t* msg = &tx->message;
	                            key_len = (size_t)msg->resolved_accounts_len;
	                            keys_view = msg->resolved_accounts;
	                            writable_view = msg->is_writable;
	                        } else {
	                            rerr = cerr;
	                        }
	                    }

	                    if (!keys_view) {
	                        rerr = sol_bank_resolve_transaction_accounts(bank,
	                                                                    tx,
	                                                                    keys,
	                                                                    writable,
	                                                                    signer,
	                                                                    SOL_MAX_MESSAGE_ACCOUNTS,
	                                                                    &key_len);
	                        if (rerr == SOL_OK) {
	                            keys_view = keys;
	                            writable_view = writable;
	                        }
	                    }

	                    if (rerr != SOL_OK || !keys_view || !writable_view) {
	                        /* Can't build a lock set; flush and execute sequentially. */
	                        TX_DAG_FLUSH_EXEC();
	                        results[i] = skip_tx_status
	                            ? sol_bank_process_transaction_parallel(bank, tx)
	                            : sol_bank_process_transaction(bank, tx);
	                        if (__builtin_expect(tx_batch_stats, 0)) {
	                            TX_BATCH_STATS_ADD(1u);
	                            tx_batch_seq_txs++;
	                        }
	                        continue;
	                    }

	                    sol_pubkey_t progdata_keys[64];
	                    size_t progdata_len = 0;
	                    sol_pubkey_t seen_progids[64];
	                    size_t seen_progids_len = 0;

	                    for (uint8_t ix_i = 0; ix_i < tx->message.instructions_len; ix_i++) {
	                        const sol_compiled_instruction_t* ix = &tx->message.instructions[ix_i];
	                        if ((size_t)ix->program_id_index >= key_len) {
	                            continue;
	                        }
	                        const sol_pubkey_t* pid = &keys_view[ix->program_id_index];
	                        if (sol_pubkey_eq(pid, &SOL_SYSTEM_PROGRAM_ID) ||
	                            sol_pubkey_eq(pid, &SOL_VOTE_PROGRAM_ID) ||
	                            sol_pubkey_eq(pid, &SOL_COMPUTE_BUDGET_ID) ||
	                            sol_pubkey_eq(pid, &SOL_ED25519_PROGRAM_ID) ||
	                            sol_pubkey_eq(pid, &SOL_SECP256K1_PROGRAM_ID) ||
	                            sol_pubkey_eq(pid, &SOL_SECP256R1_PROGRAM_ID) ||
	                            sol_pubkey_eq(pid, &SOL_BPF_LOADER_UPGRADEABLE_ID) ||
	                            sol_pubkey_eq(pid, &SOL_BPF_LOADER_V2_ID)) {
	                            continue;
	                        }

	                        bool seen = false;
	                        for (size_t si = 0; si < seen_progids_len; si++) {
	                            if (sol_pubkey_eq(&seen_progids[si], pid)) {
	                                seen = true;
	                                break;
	                            }
	                        }
	                        if (seen) continue;
	                        if (seen_progids_len < (sizeof(seen_progids) / sizeof(seen_progids[0]))) {
	                            seen_progids[seen_progids_len++] = *pid;
	                        }

	                        sol_pubkey_t pd = {0};
	                        if (bank_get_upgradeable_programdata_pubkey(bank, pid, &pd)) {
	                            if (progdata_len < (sizeof(progdata_keys) / sizeof(progdata_keys[0]))) {
	                                progdata_keys[progdata_len++] = pd;
	                            }
	                        }
	                    }

	                    uint32_t to = (uint32_t)i;

	                    /* Add dependency edges derived from account locks. */
	                    for (size_t k = 0; k < key_len; k++) {
	                        const sol_pubkey_t* key = &keys_view[k];
	                        const tx_wave_last_t* last =
	                            (const tx_wave_last_t*)sol_pubkey_map_get(last_access, key);
	                        if (!last) continue;

	                        uint32_t dep = writable_view[k]
	                            ? ((last->last_write > last->last_read) ? last->last_write : last->last_read)
	                            : last->last_write;
	                        if (dep == 0u) continue;
	                        uint32_t from = dep - 1u;

                            TX_DAG_ENSURE_EDGE_CAP_OR_ABORT();
                            if (dag_abort) break;

                            edge_to[edge_len] = to;
	                        edge_next[edge_len] = adj_head[from];
	                        adj_head[from] = (uint32_t)edge_len;
	                        edge_len++;
	                        indegree[to]++;
	                    }

	                    if (dag_abort) {
                            if (dag_segments == 0u) {
                                /* No DAG segment was executed yet; fall back to
                                 * the wave scheduler instead of full sequential
                                 * replay for the entire slot. */
                                tx_dag_abort_log_once(bank,
                                                      count,
                                                      i,
                                                      seg_len,
                                                      dag_segments,
                                                      edge_len,
                                                      edge_cap,
                                                      edge_cap_limit,
                                                      "fallback_wave");
                                dag_fallback_to_wave = true;
                                dag_abort_at = i;
                            } else {
                                tx_dag_abort_log_once(bank,
                                                      count,
                                                      i,
                                                      seg_len,
                                                      dag_segments,
                                                      edge_len,
                                                      edge_cap,
                                                      edge_cap_limit,
                                                      "finish_sequential");
	                            /* A prior segment already ran via DAG; preserve
                                 * correctness by finishing in-order. */
	                            for (size_t si = 0; si < seg_len; si++) {
	                                uint32_t node = seg_nodes[si];
	                                const sol_transaction_t* tx2 = tx_ptrs[node];
	                                if (!tx2) continue;
	                                results[node] = skip_tx_status
	                                    ? sol_bank_process_transaction_parallel(bank, tx2)
	                                    : sol_bank_process_transaction(bank, tx2);
	                            }
	                            seg_len = 0;
	                            for (size_t j = i; j < count; j++) {
	                                const sol_transaction_t* tx2 = tx_ptrs[j];
	                                if (!tx2) continue;
	                                results[j] = skip_tx_status
	                                    ? sol_bank_process_transaction_parallel(bank, tx2)
	                                    : sol_bank_process_transaction(bank, tx2);
	                            }
                            }
                            goto tx_dag_build_done;
	                    }

	                    /* ALT table accounts are read during v0 resolution. */
	                    if (tx->message.version == SOL_MESSAGE_VERSION_V0 &&
	                        tx->message.address_lookups_len > 0 &&
	                        tx->message.address_lookups) {
	                        for (uint8_t li = 0; li < tx->message.address_lookups_len; li++) {
	                            const sol_pubkey_t* table = &tx->message.address_lookups[li].account_key;
	                            const tx_wave_last_t* last =
	                                (const tx_wave_last_t*)sol_pubkey_map_get(last_access, table);
	                            if (last && last->last_write != 0u) {
	                                uint32_t from = last->last_write - 1u;
                                TX_DAG_ENSURE_EDGE_CAP_OR_ABORT();
                                if (dag_abort) break;
                                edge_to[edge_len] = to;
	                                edge_next[edge_len] = adj_head[from];
	                                adj_head[from] = (uint32_t)edge_len;
	                                edge_len++;
	                                indegree[to]++;
	                            }
	                        }
	                        if (dag_abort) {
                                if (dag_segments == 0u) {
                                    tx_dag_abort_log_once(bank,
                                                          count,
                                                          i,
                                                          seg_len,
                                                          dag_segments,
                                                          edge_len,
                                                          edge_cap,
                                                          edge_cap_limit,
                                                          "fallback_wave");
                                    dag_fallback_to_wave = true;
                                    dag_abort_at = i;
                                } else {
                                    tx_dag_abort_log_once(bank,
                                                          count,
                                                          i,
                                                          seg_len,
                                                          dag_segments,
                                                          edge_len,
                                                          edge_cap,
                                                          edge_cap_limit,
                                                          "finish_sequential");
	                                for (size_t si = 0; si < seg_len; si++) {
	                                    uint32_t node = seg_nodes[si];
	                                    const sol_transaction_t* tx2 = tx_ptrs[node];
	                                    if (!tx2) continue;
	                                    results[node] = skip_tx_status
	                                        ? sol_bank_process_transaction_parallel(bank, tx2)
	                                        : sol_bank_process_transaction(bank, tx2);
	                                }
	                                seg_len = 0;
	                                for (size_t j = i; j < count; j++) {
	                                    const sol_transaction_t* tx2 = tx_ptrs[j];
	                                    if (!tx2) continue;
	                                    results[j] = skip_tx_status
	                                        ? sol_bank_process_transaction_parallel(bank, tx2)
	                                        : sol_bank_process_transaction(bank, tx2);
	                                }
                                }
                                goto tx_dag_build_done;
	                        }
	                    }

	                    for (size_t pk = 0; pk < progdata_len; pk++) {
	                        const sol_pubkey_t* key = &progdata_keys[pk];
	                        const tx_wave_last_t* last =
	                            (const tx_wave_last_t*)sol_pubkey_map_get(last_access, key);
	                        if (last && last->last_write != 0u) {
	                            uint32_t from = last->last_write - 1u;
                            TX_DAG_ENSURE_EDGE_CAP_OR_ABORT();
                            if (dag_abort) break;
                            edge_to[edge_len] = to;
	                            edge_next[edge_len] = adj_head[from];
	                            adj_head[from] = (uint32_t)edge_len;
	                            edge_len++;
	                            indegree[to]++;
	                        }
	                    }

	                    if (dag_abort) {
                        if (dag_segments == 0u) {
                            tx_dag_abort_log_once(bank,
                                                  count,
                                                  i,
                                                  seg_len,
                                                  dag_segments,
                                                  edge_len,
                                                  edge_cap,
                                                  edge_cap_limit,
                                                  "fallback_wave");
                            dag_fallback_to_wave = true;
                            dag_abort_at = i;
                        } else {
                            tx_dag_abort_log_once(bank,
                                                  count,
                                                  i,
                                                  seg_len,
                                                  dag_segments,
                                                  edge_len,
                                                  edge_cap,
                                                  edge_cap_limit,
                                                  "finish_sequential");
	                        for (size_t si = 0; si < seg_len; si++) {
	                            uint32_t node = seg_nodes[si];
	                            const sol_transaction_t* tx2 = tx_ptrs[node];
	                            if (!tx2) continue;
	                            results[node] = skip_tx_status
	                                ? sol_bank_process_transaction_parallel(bank, tx2)
	                                : sol_bank_process_transaction(bank, tx2);
	                        }
	                        seg_len = 0;
	                        for (size_t j = i; j < count; j++) {
	                            const sol_transaction_t* tx2 = tx_ptrs[j];
	                            if (!tx2) continue;
	                            results[j] = skip_tx_status
	                                ? sol_bank_process_transaction_parallel(bank, tx2)
	                                : sol_bank_process_transaction(bank, tx2);
	                        }
                        }
                        goto tx_dag_build_done;
	                    }

		                    /* Mark scheduled and update last-access map with tx-index stamps. */
		                    if (seg_len == 0) {
		                        seg_begin = (size_t)to;
		                    }
		                    seg_end = (size_t)to + 1u;
		                    seg_nodes[seg_len++] = to;
		                    dag_txs_scheduled++;

	                    uint32_t stamp = to + 1u;
	                    for (size_t k = 0; k < key_len; k++) {
	                        const sol_pubkey_t* key = &keys_view[k];
	                        tx_wave_last_t* last =
	                            (tx_wave_last_t*)sol_pubkey_map_insert(last_access, key, NULL);
	                        if (!last) continue;
	                        if (writable_view[k]) {
	                            if (last->last_write < stamp) last->last_write = stamp;
	                        } else {
	                            if (last->last_read < stamp) last->last_read = stamp;
	                        }
	                    }

	                    if (tx->message.version == SOL_MESSAGE_VERSION_V0 &&
	                        tx->message.address_lookups_len > 0 &&
	                        tx->message.address_lookups) {
	                        for (uint8_t li = 0; li < tx->message.address_lookups_len; li++) {
	                            const sol_pubkey_t* table = &tx->message.address_lookups[li].account_key;
	                            tx_wave_last_t* last =
	                                (tx_wave_last_t*)sol_pubkey_map_insert(last_access, table, NULL);
	                            if (last && last->last_read < stamp) last->last_read = stamp;
	                        }
	                    }

	                    for (size_t pk = 0; pk < progdata_len; pk++) {
	                        const sol_pubkey_t* key = &progdata_keys[pk];
	                        tx_wave_last_t* last =
	                            (tx_wave_last_t*)sol_pubkey_map_insert(last_access, key, NULL);
	                        if (last && last->last_read < stamp) last->last_read = stamp;
	                    }
	                }

tx_dag_build_done:
	                if (!dag_abort) {
	                    TX_DAG_FLUSH_EXEC();
	                }

#undef TX_DAG_FLUSH_EXEC
#undef TX_DAG_SEG_RESET
#undef TX_DAG_ENSURE_EDGE_CAP_OR_ABORT
                /* Clear last-access tracking for reuse next call. */
                sol_map_clear(last_access->inner);

	                /* If we grew edge buffers during this run, keep them. */
	                sc->dag_edge_to = edge_to;
	                sc->dag_edge_next = edge_next;
	                sc->dag_edge_cap = edge_cap;

	                if (__builtin_expect(tx_wave_diag, 0)) {
	                    uint64_t dag_total_ns = bank_monotonic_ns() - wave_total_t0;
	                    uint64_t dag_build_ns = dag_total_ns - dag_exec_ns;
	                    sol_log_info("tx_dag_diag: txs=%zu scheduled=%zu segments=%zu edges=%zu build_ms=%.3f exec_ms=%.3f total_ms=%.3f",
	                                 count,
	                                 dag_txs_scheduled,
	                                 dag_segments,
	                                 dag_edges_total,
	                                 (double)dag_build_ns / 1e6,
	                                 (double)dag_exec_ns / 1e6,
	                                 (double)dag_total_ns / 1e6);
	                }
                    if (dag_fallback_to_wave) {
                        if (__builtin_expect(tx_wave_diag, 0)) {
                            sol_log_info("tx_dag_fallback_wave: slot=%lu txs=%zu abort_at=%zu segments=%zu edges=%zu",
                                         (unsigned long)bank->slot,
                                         count,
                                         dag_abort_at,
                                         dag_segments,
                                         dag_edges_total);
                        }
                        use_dag = false;
                    } else {
	                    goto tx_sched_done;
                    }
	            }
	        }

            if (!tx_sched_ensure_waves(sc, count)) {
                goto legacy_sched;
            }

            tx_wave_t* waves = sc->waves;
            const sol_transaction_t** wave_ptrs = sc->wave_ptrs;
            sol_tx_result_t* wave_results = sc->wave_results;

#define TX_WAVE_FLUSH_EXEC() do {                                                          \
            if (__builtin_expect(tx_wave_diag, 0)) {                                        \
                wave_flushes++;                                                             \
                if (waves_len > wave_waves_peak) wave_waves_peak = waves_len;               \
            }                                                                               \
            for (size_t _wi = 0; _wi < waves_len; _wi++) {                                 \
                tx_wave_t* _w = &waves[_wi];                                                \
                size_t _len = _w->tx_len;                                                   \
                if (_len == 0) continue;                                                    \
                if (__builtin_expect(tx_batch_stats, 0)) {                                  \
                    TX_BATCH_STATS_ADD(_len);                                               \
                }                                                                           \
                for (size_t _j = 0; _j < _len; _j++) {                                      \
                    size_t _ti = _w->tx_indices[_j];                                        \
                    wave_ptrs[_j] = tx_ptrs[_ti];                                           \
                }                                                                           \
                uint64_t _exec0 = __builtin_expect(tx_wave_diag, 0) ? bank_monotonic_ns() : 0; \
                tx_pool_run_range_ptrs(bank, wave_ptrs, wave_results, 0, _len, skip_tx_status); \
                if (__builtin_expect(tx_wave_diag, 0)) {                                    \
                    wave_exec_ns += bank_monotonic_ns() - _exec0;                            \
                }                                                                           \
                for (size_t _j = 0; _j < _len; _j++) {                                      \
                    size_t _ti = _w->tx_indices[_j];                                        \
                    results[_ti] = wave_results[_j];                                        \
                }                                                                           \
            }                                                                               \
            for (size_t _wi = 0; _wi < waves_len; _wi++) {                                  \
                tx_wave_reset(&waves[_wi]);                                                 \
            }                                                                               \
            waves_len = 0;                                                                  \
            sol_map_clear(last_access->inner);                                              \
        } while (0)

	        size_t waves_len = 0;

	        for (size_t i = 0; i < count; i++) {
	            const sol_transaction_t* tx = tx_ptrs[i];
            if (!tx) continue;

            if (tx_is_wave_barrier(tx)) {
                TX_WAVE_FLUSH_EXEC();
                results[i] = skip_tx_status
                    ? sol_bank_process_transaction_parallel(bank, tx)
                    : sol_bank_process_transaction(bank, tx);
                if (__builtin_expect(tx_batch_stats, 0)) {
                    TX_BATCH_STATS_ADD(1u);
                    tx_batch_seq_txs++;
                }
                continue;
            }

            size_t key_len = 0;
            const sol_pubkey_t* keys_view = NULL;
            const bool* writable_view = NULL;

            sol_err_t rerr = SOL_OK;
            if (tx->message.version == SOL_MESSAGE_VERSION_V0 && v0_cache->patches) {
                sol_err_t cerr = bank_v0_cache_resolve(bank, tx, v0_cache);
                if (cerr == SOL_OK) {
                    const sol_message_t* msg = &tx->message;
                    key_len = (size_t)msg->resolved_accounts_len;
                    keys_view = msg->resolved_accounts;
                    writable_view = msg->is_writable;
                } else {
                    rerr = cerr;
                }
            }

            if (!keys_view) {
                rerr = sol_bank_resolve_transaction_accounts(bank,
                                                            tx,
                                                            keys,
                                                            writable,
                                                            signer,
                                                            SOL_MAX_MESSAGE_ACCOUNTS,
                                                            &key_len);
                if (rerr == SOL_OK) {
                    keys_view = keys;
                    writable_view = writable;
                }
            }

            if (rerr != SOL_OK || !keys_view || !writable_view) {
                /* Can't build a lock set; execute sequentially after flushing. */
                TX_WAVE_FLUSH_EXEC();
                results[i] = skip_tx_status
                    ? sol_bank_process_transaction_parallel(bank, tx)
                    : sol_bank_process_transaction(bank, tx);
                if (__builtin_expect(tx_batch_stats, 0)) {
                    TX_BATCH_STATS_ADD(1u);
                    tx_batch_seq_txs++;
                }
                continue;
            }

            sol_pubkey_t progdata_keys[64];
            size_t progdata_len = 0;
            sol_pubkey_t seen_progids[64];
            size_t seen_progids_len = 0;

            for (uint8_t ix_i = 0; ix_i < tx->message.instructions_len; ix_i++) {
                const sol_compiled_instruction_t* ix = &tx->message.instructions[ix_i];
                if ((size_t)ix->program_id_index >= key_len) {
                    continue;
                }
                const sol_pubkey_t* pid = &keys_view[ix->program_id_index];
                if (sol_pubkey_eq(pid, &SOL_SYSTEM_PROGRAM_ID) ||
                    sol_pubkey_eq(pid, &SOL_VOTE_PROGRAM_ID) ||
                    sol_pubkey_eq(pid, &SOL_COMPUTE_BUDGET_ID) ||
                    sol_pubkey_eq(pid, &SOL_ED25519_PROGRAM_ID) ||
                    sol_pubkey_eq(pid, &SOL_SECP256K1_PROGRAM_ID) ||
                    sol_pubkey_eq(pid, &SOL_SECP256R1_PROGRAM_ID) ||
                    sol_pubkey_eq(pid, &SOL_BPF_LOADER_UPGRADEABLE_ID) ||
                    sol_pubkey_eq(pid, &SOL_BPF_LOADER_V2_ID)) {
                    continue;
                }

                bool seen = false;
                for (size_t si = 0; si < seen_progids_len; si++) {
                    if (sol_pubkey_eq(&seen_progids[si], pid)) {
                        seen = true;
                        break;
                    }
                }
                if (seen) {
                    continue;
                }
                if (seen_progids_len < (sizeof(seen_progids) / sizeof(seen_progids[0]))) {
                    seen_progids[seen_progids_len++] = *pid;
                }

                sol_pubkey_t pd = {0};
                if (bank_get_upgradeable_programdata_pubkey(bank, pid, &pd)) {
                    if (progdata_len < (sizeof(progdata_keys) / sizeof(progdata_keys[0]))) {
                        progdata_keys[progdata_len++] = pd;
                    }
                }
            }

            uint32_t min_wave = 0;

            /* Account locks from the resolved account list. */
            for (size_t k = 0; k < key_len; k++) {
                const sol_pubkey_t* key = &keys_view[k];
                const tx_wave_last_t* last = (const tx_wave_last_t*)sol_pubkey_map_get(last_access, key);
                if (!last) continue;
                uint32_t dep = writable_view[k]
                    ? ((last->last_write > last->last_read) ? last->last_write : last->last_read)
                    : last->last_write;
                if (dep > min_wave) min_wave = dep;
            }

            /* Lock ALT table accounts as read-only (used during v0 resolution). */
            if (tx->message.version == SOL_MESSAGE_VERSION_V0 &&
                tx->message.address_lookups_len > 0 &&
                tx->message.address_lookups) {
                for (uint8_t li = 0; li < tx->message.address_lookups_len; li++) {
                    const sol_pubkey_t* table = &tx->message.address_lookups[li].account_key;
                    const tx_wave_last_t* last = (const tx_wave_last_t*)sol_pubkey_map_get(last_access, table);
                    if (!last) continue;
                    if (last->last_write > min_wave) min_wave = last->last_write;
                }
            }

            for (size_t pk = 0; pk < progdata_len; pk++) {
                const sol_pubkey_t* key = &progdata_keys[pk];
                const tx_wave_last_t* last = (const tx_wave_last_t*)sol_pubkey_map_get(last_access, key);
                if (!last) continue;
                if (last->last_write > min_wave) min_wave = last->last_write;
            }

            size_t wave_index = (size_t)min_wave;

            if (wave_index == waves_len) {
                if (waves_len >= count) {
                    /* Should not happen, but stay safe. */
                    TX_WAVE_FLUSH_EXEC();
                    results[i] = skip_tx_status
                        ? sol_bank_process_transaction_parallel(bank, tx)
                        : sol_bank_process_transaction(bank, tx);
                    if (__builtin_expect(tx_batch_stats, 0)) {
                        TX_BATCH_STATS_ADD(1u);
                        tx_batch_seq_txs++;
                    }
                    continue;
                }

                tx_wave_t* w = &waves[waves_len];
                tx_wave_reset(w);
                waves_len++;
                if (__builtin_expect(tx_wave_diag, 0)) {
                    wave_waves_created++;
                    if (waves_len > wave_waves_peak) wave_waves_peak = waves_len;
                }
            }

            tx_wave_t* w = &waves[wave_index];

            if (!tx_wave_push(w, i)) {
                TX_WAVE_FLUSH_EXEC();
                results[i] = skip_tx_status
                    ? sol_bank_process_transaction_parallel(bank, tx)
                    : sol_bank_process_transaction(bank, tx);
                if (__builtin_expect(tx_batch_stats, 0)) {
                    TX_BATCH_STATS_ADD(1u);
                    tx_batch_seq_txs++;
                }
                continue;
            }
            if (__builtin_expect(tx_wave_diag, 0)) {
                wave_txs_scheduled++;
            }

            uint32_t wave_stamp = (uint32_t)wave_index + 1u;

            /* Update last-access map. */
            for (size_t k = 0; k < key_len; k++) {
                const sol_pubkey_t* key = &keys_view[k];
                if (writable_view[k]) {
                    tx_wave_last_t* last = (tx_wave_last_t*)sol_pubkey_map_insert(last_access, key, NULL);
                    if (last && last->last_write < wave_stamp) {
                        last->last_write = wave_stamp;
                    }
                } else {
                    tx_wave_last_t* last = (tx_wave_last_t*)sol_pubkey_map_insert(last_access, key, NULL);
                    if (last && last->last_read < wave_stamp) {
                        last->last_read = wave_stamp;
                    }
                }
            }

            if (tx->message.version == SOL_MESSAGE_VERSION_V0 &&
                tx->message.address_lookups_len > 0 &&
                tx->message.address_lookups) {
                for (uint8_t li = 0; li < tx->message.address_lookups_len; li++) {
                    const sol_pubkey_t* table = &tx->message.address_lookups[li].account_key;
                    tx_wave_last_t* last = (tx_wave_last_t*)sol_pubkey_map_insert(last_access, table, NULL);
                    if (last && last->last_read < wave_stamp) {
                        last->last_read = wave_stamp;
                    }
                }
            }

            for (size_t pk = 0; pk < progdata_len; pk++) {
                const sol_pubkey_t* key = &progdata_keys[pk];
                tx_wave_last_t* last = (tx_wave_last_t*)sol_pubkey_map_insert(last_access, key, NULL);
                if (last && last->last_read < wave_stamp) {
                    last->last_read = wave_stamp;
                }
            }
        }

        /* Execute remaining waves. */
        TX_WAVE_FLUSH_EXEC();

#undef TX_WAVE_FLUSH_EXEC
        sol_map_clear(last_access->inner);

        if (__builtin_expect(tx_wave_diag, 0)) {
            uint64_t wave_total_ns = bank_monotonic_ns() - wave_total_t0;
            uint64_t wave_build_ns = wave_total_ns - wave_exec_ns;
            sol_log_info("tx_wave_diag: txs=%zu scheduled=%zu flushes=%zu waves_created=%zu waves_peak=%zu build_ms=%.3f exec_ms=%.3f total_ms=%.3f",
                         count,
                         wave_txs_scheduled,
                         wave_flushes,
                         wave_waves_created,
                         wave_waves_peak,
                         (double)wave_build_ns / 1e6,
                         (double)wave_exec_ns / 1e6,
                         (double)wave_total_ns / 1e6);
        }
        goto tx_sched_done;
    }

legacy_sched:
    for (size_t i = 0; i < count; i++) {
        const sol_transaction_t* tx = tx_ptrs[i];
        if (!tx) {
            sol_tx_result_t r = {0};
            r.status = SOL_ERR_INVAL;
            results[i] = r;
            continue;
        }

        if (skip_tx_status) {
            const sol_signature_t* sig = sol_transaction_signature(tx);
            if (sig && sol_map_contains(seen_sigs, sig)) {
                sol_tx_result_t r = {0};
                r.status = SOL_ERR_TX_ALREADY_PROCESSED;
                results[i] = r;
                tx_ptrs[i] = NULL;

                BANK_STAT_INC(bank, transactions_processed);
                BANK_STAT_INC(bank, transactions_failed);
                BANK_STAT_INC(bank, rejected_duplicate);
                log_prevalidation_rejection(bank, tx, "duplicate", SOL_ERR_TX_ALREADY_PROCESSED);
                continue;
            }
            if (sig) {
                (void)sol_map_insert(seen_sigs, sig, &one);
            }
        }

        /* Address lookup table resolution depends on on-chain ALT account data.
         * Flush if this tx needs to read a table written earlier in the batch. */
        if (tx &&
            tx->message.version == SOL_MESSAGE_VERSION_V0 &&
            tx->message.address_lookups_len > 0 &&
            tx->message.address_lookups) {
            bool alt_conflict = false;
            for (uint8_t li = 0; li < tx->message.address_lookups_len; li++) {
                const sol_pubkey_t* table = &tx->message.address_lookups[li].account_key;
                if (sol_pubkey_map_get(batch_writes, table)) {
                    alt_conflict = true;
                    break;
                }
            }
            if (alt_conflict && batch_start < i) {
                if (__builtin_expect(tx_batch_stats, 0)) {
                    TX_BATCH_STATS_ADD(i - batch_start);
                }
                tx_pool_run_range_ptrs(bank, tx_ptrs, results, batch_start, i, skip_tx_status);
                sol_map_clear(batch_reads->inner);
                sol_map_clear(batch_writes->inner);
                batch_start = i;
            }
        }

        size_t key_len = 0;
        const sol_pubkey_t* keys_view = NULL;
        const bool* writable_view = NULL;

        sol_err_t rerr = SOL_OK;
        if (tx->message.version == SOL_MESSAGE_VERSION_V0 && v0_cache->patches) {
            sol_err_t cerr = bank_v0_cache_resolve(bank, tx, v0_cache);
            if (cerr == SOL_OK) {
                const sol_message_t* msg = &tx->message;
                key_len = (size_t)msg->resolved_accounts_len;
                keys_view = msg->resolved_accounts;
                writable_view = msg->is_writable;
            } else {
                rerr = cerr;
            }
        }

        if (!keys_view) {
            rerr = sol_bank_resolve_transaction_accounts(bank,
                                                        tx,
                                                        keys,
                                                        writable,
                                                        signer,
                                                        SOL_MAX_MESSAGE_ACCOUNTS,
                                                        &key_len);
            if (rerr == SOL_OK) {
                keys_view = keys;
                writable_view = writable;
            }
        }

        if (rerr != SOL_OK || !keys_view || !writable_view) {
            /* Can't build a lock set; execute sequentially after flushing. */
            if (batch_start < i) {
                if (__builtin_expect(tx_batch_stats, 0)) {
                    TX_BATCH_STATS_ADD(i - batch_start);
                }
                tx_pool_run_range_ptrs(bank, tx_ptrs, results, batch_start, i, skip_tx_status);
                sol_map_clear(batch_reads->inner);
                sol_map_clear(batch_writes->inner);
            }

            results[i] = skip_tx_status
                ? sol_bank_process_transaction_parallel(bank, tx_ptrs[i])
                : sol_bank_process_transaction(bank, tx_ptrs[i]);
            if (__builtin_expect(tx_batch_stats, 0)) {
                TX_BATCH_STATS_ADD(1u);
                tx_batch_seq_txs++;
            }
            batch_start = i + 1;
            continue;
        }

        sol_pubkey_t progdata_keys[64];
        size_t progdata_len = 0;
        sol_pubkey_t seen_progids[64];
        size_t seen_progids_len = 0;

        /* If a prior tx wrote an invoked program account, flush before we
         * inspect it for ProgramData so we read the post-write state. */
        bool prog_barrier = false;
        if (tx) {
            for (uint8_t ix_i = 0; ix_i < tx->message.instructions_len; ix_i++) {
                const sol_compiled_instruction_t* ix = &tx->message.instructions[ix_i];
                if ((size_t)ix->program_id_index >= key_len) {
                    continue;
                }
                const sol_pubkey_t* pid = &keys_view[ix->program_id_index];
                if (sol_pubkey_eq(pid, &SOL_SYSTEM_PROGRAM_ID) ||
                    sol_pubkey_eq(pid, &SOL_VOTE_PROGRAM_ID) ||
                    sol_pubkey_eq(pid, &SOL_COMPUTE_BUDGET_ID) ||
                    sol_pubkey_eq(pid, &SOL_ED25519_PROGRAM_ID) ||
                    sol_pubkey_eq(pid, &SOL_SECP256K1_PROGRAM_ID) ||
                    sol_pubkey_eq(pid, &SOL_SECP256R1_PROGRAM_ID) ||
                    sol_pubkey_eq(pid, &SOL_BPF_LOADER_UPGRADEABLE_ID) ||
                    sol_pubkey_eq(pid, &SOL_BPF_LOADER_V2_ID)) {
                    continue;
                }
                if (sol_pubkey_map_get(batch_writes, pid)) {
                    prog_barrier = true;
                    break;
                }
            }
        }
        if (prog_barrier && batch_start < i) {
            if (__builtin_expect(tx_batch_stats, 0)) {
                TX_BATCH_STATS_ADD(i - batch_start);
            }
            tx_pool_run_range_ptrs(bank, tx_ptrs, results, batch_start, i, skip_tx_status);
            sol_map_clear(batch_reads->inner);
            sol_map_clear(batch_writes->inner);
            batch_start = i;
        }

        if (tx) {
            for (uint8_t ix_i = 0; ix_i < tx->message.instructions_len; ix_i++) {
                const sol_compiled_instruction_t* ix = &tx->message.instructions[ix_i];
                if ((size_t)ix->program_id_index >= key_len) {
                    continue;
                }
                const sol_pubkey_t* pid = &keys_view[ix->program_id_index];
                if (sol_pubkey_eq(pid, &SOL_SYSTEM_PROGRAM_ID) ||
                    sol_pubkey_eq(pid, &SOL_VOTE_PROGRAM_ID) ||
                    sol_pubkey_eq(pid, &SOL_COMPUTE_BUDGET_ID) ||
                    sol_pubkey_eq(pid, &SOL_ED25519_PROGRAM_ID) ||
                    sol_pubkey_eq(pid, &SOL_SECP256K1_PROGRAM_ID) ||
                    sol_pubkey_eq(pid, &SOL_SECP256R1_PROGRAM_ID) ||
                    sol_pubkey_eq(pid, &SOL_BPF_LOADER_UPGRADEABLE_ID) ||
                    sol_pubkey_eq(pid, &SOL_BPF_LOADER_V2_ID)) {
                    continue;
                }

                bool seen = false;
                for (size_t si = 0; si < seen_progids_len; si++) {
                    if (sol_pubkey_eq(&seen_progids[si], pid)) {
                        seen = true;
                        break;
                    }
                }
                if (seen) {
                    continue;
                }
                if (seen_progids_len < (sizeof(seen_progids) / sizeof(seen_progids[0]))) {
                    seen_progids[seen_progids_len++] = *pid;
                }

                sol_pubkey_t pd = {0};
                if (bank_get_upgradeable_programdata_pubkey(bank, pid, &pd)) {
                    if (progdata_len < (sizeof(progdata_keys) / sizeof(progdata_keys[0]))) {
                        progdata_keys[progdata_len++] = pd;
                    }
                }
            }
        }

        bool conflict = false;
        for (size_t k = 0; k < key_len; k++) {
            if (writable_view[k]) {
                if (sol_pubkey_map_get(batch_writes, &keys_view[k]) ||
                    sol_pubkey_map_get(batch_reads, &keys_view[k])) {
                    conflict = true;
                    break;
                }
            } else {
                if (sol_pubkey_map_get(batch_writes, &keys_view[k])) {
                    conflict = true;
                    break;
                }
            }
        }

        if (!conflict) {
            for (size_t pk = 0; pk < progdata_len; pk++) {
                if (sol_pubkey_map_get(batch_writes, &progdata_keys[pk])) {
                    conflict = true;
                    break;
                }
            }
        }

        if (conflict && batch_start < i) {
            /* Execute prior batch. */
            if (__builtin_expect(tx_batch_stats, 0)) {
                TX_BATCH_STATS_ADD(i - batch_start);
            }
            tx_pool_run_range_ptrs(bank, tx_ptrs, results, batch_start, i, skip_tx_status);
            sol_map_clear(batch_reads->inner);
            sol_map_clear(batch_writes->inner);
            batch_start = i;
        }

        /* Add tx accounts to batch set. */
        for (size_t k = 0; k < key_len; k++) {
            if (writable_view[k]) {
                (void)sol_pubkey_map_insert(batch_writes, &keys_view[k], &one);
            } else {
                (void)sol_pubkey_map_insert(batch_reads, &keys_view[k], &one);
            }
        }

        if (tx &&
            tx->message.version == SOL_MESSAGE_VERSION_V0 &&
            tx->message.address_lookups_len > 0 &&
            tx->message.address_lookups) {
            for (uint8_t li = 0; li < tx->message.address_lookups_len; li++) {
                (void)sol_pubkey_map_insert(batch_reads,
                                            &tx->message.address_lookups[li].account_key,
                                            &one);
            }
        }

        for (size_t pk = 0; pk < progdata_len; pk++) {
            (void)sol_pubkey_map_insert(batch_reads, &progdata_keys[pk], &one);
        }

        if (replay_max_batch_txs > 0u &&
            (i + 1u - batch_start) >= replay_max_batch_txs) {
            if (__builtin_expect(tx_batch_stats, 0)) {
                TX_BATCH_STATS_ADD((i + 1u) - batch_start);
            }
            tx_pool_run_range_ptrs(bank, tx_ptrs, results, batch_start, i + 1u, skip_tx_status);
            sol_map_clear(batch_reads->inner);
            sol_map_clear(batch_writes->inner);
            batch_start = i + 1u;
        }
    }

    /* Execute last batch. */
    if (batch_start < count) {
        if (__builtin_expect(tx_batch_stats, 0)) {
            TX_BATCH_STATS_ADD(count - batch_start);
        }
        tx_pool_run_range_ptrs(bank, tx_ptrs, results, batch_start, count, skip_tx_status);
    }

tx_sched_done:
    if (skip_tx_status) {
        if (bank_record_tx_status_batch_enabled()) {
            uint64_t tx_status_t0 = bank_monotonic_ns();
            sol_bank_record_tx_status_batch(bank, tx_ptrs, count, results);
            uint64_t tx_status_ns = bank_monotonic_ns() - tx_status_t0;
            if (__builtin_expect(tx_status_ns >= 500000000ull, 0)) {
                sol_log_info("tx_status_slow: slot=%lu txs=%zu time=%.2fms",
                             (unsigned long)bank->slot,
                             count,
                             (double)tx_status_ns / 1000000.0);
            }
        }
    }

    if (seen_sigs) {
        sol_map_clear(seen_sigs);
    }

    if (__builtin_expect(tx_batch_stats, 0)) {
        size_t min_len = (tx_batch_min == SIZE_MAX) ? 0u : tx_batch_min;
        double avg = tx_batch_cnt ? ((double)tx_batch_txs / (double)tx_batch_cnt) : 0.0;
        fprintf(stderr,
                "tx_batch_stats(ptrs): txs=%zu batches=%zu avg=%.2f min=%zu max=%zu lt8_batches=%zu lt8_txs=%zu seq_txs=%zu\n",
                count,
                tx_batch_cnt,
                avg,
                min_len,
                tx_batch_max,
                tx_batch_lt8_cnt,
                tx_batch_lt8_txs,
                tx_batch_seq_txs);
        fprintf(stderr,
                "tx_batch_hist_lt8(ptrs): 1=%zu 2=%zu 3=%zu 4=%zu 5=%zu 6=%zu 7=%zu\n",
                tx_batch_hist[1],
                tx_batch_hist[2],
                tx_batch_hist[3],
                tx_batch_hist[4],
                tx_batch_hist[5],
                tx_batch_hist[6],
                tx_batch_hist[7]);
    }

    if (__builtin_expect(tx_pool_stats, 0)) {
        double seq_ms = (double)pool_stats.seq_ns / 1e6;
        double par_ms = (double)pool_stats.par_ns / 1e6;
        double par_lock_ms = (double)pool_stats.par_lock_ns / 1e6;
        double par_wait_ms = (double)pool_stats.par_wait_ns / 1e6;
        double par_caller_ms = (double)pool_stats.par_caller_ns / 1e6;
        double par_join_ms = (double)pool_stats.par_join_ns / 1e6;
        fprintf(stderr,
                "tx_pool_stats(ptrs): slot=%lu seq_calls=%lu seq_txs=%lu seq_ms=%.3f par_calls=%lu par_txs=%lu par_ms=%.3f lock_ms=%.3f wait_ms=%.3f caller_ms=%.3f join_ms=%.3f\n",
                (unsigned long)bank->slot,
                (unsigned long)pool_stats.seq_calls,
                (unsigned long)pool_stats.seq_txs,
                seq_ms,
                (unsigned long)pool_stats.par_calls,
                (unsigned long)pool_stats.par_txs,
                par_ms,
                par_lock_ms,
                par_wait_ms,
                par_caller_ms,
                par_join_ms);
        g_tls_tx_pool_stats = NULL;
    }

    bank_v0_cache_reset(v0_cache);
    if (v0_cache_disabled) {
        v0_cache->patches = saved_v0_patches;
        v0_cache->patches_cap = saved_v0_patches_cap;
    }

    sol_map_clear(batch_reads->inner);
    sol_map_clear(batch_writes->inner);
#undef TX_BATCH_STATS_ADD
    return SOL_OK;
}

static sol_err_t
bank_advance_poh_and_register_ticks(sol_bank_t* bank, const sol_entry_t* entry) {
    if (!bank || !entry) return SOL_ERR_INVAL;

    /* Defensive: a zero hashes_per_tick would make tick tracking impossible. */
    const uint64_t hashes_per_tick =
        bank->config.hashes_per_tick ? bank->config.hashes_per_tick : SOL_HASHES_PER_TICK;
    if (hashes_per_tick == 0) return SOL_ERR_INVAL;

    sol_hash_t current = {0};
    uint64_t hashes_in_tick = 0;
    pthread_mutex_lock(&bank->lock);
    current = bank->poh_hash;
    hashes_in_tick = bank->hashes_in_tick;
    pthread_mutex_unlock(&bank->lock);

    /* Default fast path: trust entry->hash and advance tick counters arithmetically.
     * This avoids replay-time rehashing of every intermediate PoH step, which can
     * dominate slot latency on heavy mainnet slots. */
    {
        uint64_t total_hashes = 0;
        bool oflow = __builtin_add_overflow(hashes_in_tick, entry->num_hashes, &total_hashes);
        if (!oflow && !bank_strict_poh_rehash()) {
            uint64_t ticks_crossed = total_hashes / hashes_per_tick;
            uint64_t rem_hashes = total_hashes % hashes_per_tick;
            for (uint64_t i = 0; i < ticks_crossed; i++) {
                /* For the final boundary that lands exactly at entry end, use
                 * entry->hash as the tick hash; intermediate tick hashes are not
                 * consumed by bank state updates. */
                const sol_hash_t* tick_hash = &current;
                if ((i + 1u == ticks_crossed) && rem_hashes == 0u) {
                    tick_hash = &entry->hash;
                }
                sol_err_t err = sol_bank_register_tick(bank, tick_hash);
                if (err != SOL_OK && err != SOL_ERR_OVERFLOW) {
                    return err;
                }
            }

            current = entry->hash;
            hashes_in_tick = rem_hashes;

            pthread_mutex_lock(&bank->lock);
            bank->poh_hash = current;
            bank->hashes_in_tick = hashes_in_tick;
            pthread_mutex_unlock(&bank->lock);
            return SOL_OK;
        }

        /* Legacy fast path for strict mode when this entry does not cross a
         * tick boundary. */
        if (!oflow && total_hashes <= hashes_per_tick) {
            current = entry->hash;
            if (total_hashes == hashes_per_tick) {
                sol_err_t err = sol_bank_register_tick(bank, &current);
                if (err != SOL_OK && err != SOL_ERR_OVERFLOW) {
                    return err;
                }
                hashes_in_tick = 0;
            } else {
                hashes_in_tick = total_hashes;
            }

            pthread_mutex_lock(&bank->lock);
            bank->poh_hash = current;
            bank->hashes_in_tick = hashes_in_tick;
            pthread_mutex_unlock(&bank->lock);
            return SOL_OK;
        }
    }

    uint64_t plain_hashes = entry->num_hashes;
    const bool has_record = entry->num_transactions > 0;
    if (has_record && plain_hashes > 0) {
        /* One of the hashes is the record(mixin) hash. */
        plain_hashes -= 1;
    }

    while (plain_hashes > 0) {
        const uint64_t remaining = hashes_per_tick - hashes_in_tick;
        const uint64_t chunk = (plain_hashes < remaining) ? plain_hashes : remaining;

        sol_sha256_32bytes_repeated(current.bytes, chunk);

        hashes_in_tick += chunk;
        plain_hashes -= chunk;

        if (hashes_in_tick == hashes_per_tick) {
            sol_err_t err = sol_bank_register_tick(bank, &current);
            if (err != SOL_OK && err != SOL_ERR_OVERFLOW) {
                return err;
            }
            hashes_in_tick = 0;
        }
    }

    if (has_record) {
        /* The record hash is already present in the ledger entry. Count it as
         * a PoH hash step and advance the local PoH state. */
        current = entry->hash;
        hashes_in_tick++;
        if (hashes_in_tick == hashes_per_tick) {
            sol_err_t err = sol_bank_register_tick(bank, &current);
            if (err != SOL_OK && err != SOL_ERR_OVERFLOW) {
                return err;
            }
            hashes_in_tick = 0;
        }
    } else {
        /* Tick-only entries advance PoH purely via hash_n and end at entry.hash. */
        current = entry->hash;
    }

    pthread_mutex_lock(&bank->lock);
    bank->poh_hash = current;
    bank->hashes_in_tick = hashes_in_tick;
    pthread_mutex_unlock(&bank->lock);

    return SOL_OK;
}

sol_err_t
sol_bank_process_entry(sol_bank_t* bank, const sol_entry_t* entry) {
    if (!bank || !entry) return SOL_ERR_INVAL;
    if (__atomic_load_n(&bank->frozen, __ATOMIC_ACQUIRE)) return SOL_ERR_SHUTDOWN;

    if (bank_skip_transaction_processing()) {
        return bank_advance_poh_and_register_ticks(bank, entry);
    }

    /* Process transactions in entry */
    if (entry->num_transactions > 0) {
        /* Use a small stack buffer for the common case to avoid heap churn. */
        sol_tx_result_t stack_results[64];
        sol_tx_result_t* results = stack_results;
        bool heap_results = false;

        if (entry->num_transactions > (uint32_t)(sizeof(stack_results) / sizeof(stack_results[0]))) {
            results = sol_alloc((size_t)entry->num_transactions * sizeof(sol_tx_result_t));
            if (!results) return SOL_ERR_NOMEM;
            heap_results = true;
        }

        sol_err_t terr = sol_bank_process_transactions(bank,
                                                      entry->transactions,
                                                      (size_t)entry->num_transactions,
                                                      results);
        if (terr != SOL_OK) {
            if (heap_results) sol_free(results);
            return terr;
        }

        for (uint32_t i = 0; i < entry->num_transactions; i++) {
            if (results[i].status != SOL_OK) {
                sol_log_debug("Transaction %u failed: %d", i, results[i].status);
            }
        }

        if (heap_results) sol_free(results);
    }

    return bank_advance_poh_and_register_ticks(bank, entry);
}

sol_err_t
sol_bank_process_entries_ex(sol_bank_t* bank,
                            const sol_entry_batch_t* batch,
                            sol_bank_process_entries_timing_t* timing) {
    if (!bank || !batch) return SOL_ERR_INVAL;
    if (timing) {
        timing->prep_ns = 0;
        timing->tx_exec_ns = 0;
        timing->poh_ns = 0;
    }

    /* When skipping transaction execution, keep the original ordering: advance
     * PoH/ticks entry-by-entry and return. */
    if (bank_skip_transaction_processing()) {
        uint64_t poh_t0 = timing ? bank_monotonic_ns() : 0;
        for (size_t i = 0; i < batch->num_entries; i++) {
            sol_err_t err = bank_advance_poh_and_register_ticks(bank, &batch->entries[i]);
            if (err != SOL_OK) return err;
        }
        if (timing) {
            timing->poh_ns += bank_monotonic_ns() - poh_t0;
        }
        return SOL_OK;
    }

    /* Flatten all transactions for the batch to enable parallelism when
     * entries contain small numbers of transactions. The deterministic lock-set
     * scheduler preserves correctness by flushing on conflicts. */
    size_t total_txs = 0;
    for (size_t i = 0; i < batch->num_entries; i++) {
        total_txs += (size_t)batch->entries[i].num_transactions;
    }

    if (total_txs == 0) {
        uint64_t poh_t0 = timing ? bank_monotonic_ns() : 0;
        for (size_t i = 0; i < batch->num_entries; i++) {
            sol_err_t err = bank_advance_poh_and_register_ticks(bank, &batch->entries[i]);
            if (err != SOL_OK) return err;
        }
        if (timing) {
            timing->poh_ns += bank_monotonic_ns() - poh_t0;
        }
        return SOL_OK;
    }

    /* Replay calls mark signatures as preverified in TLS. Prefer sequential
     * execution there by default to avoid tx-pool join stalls that can pin
     * replay on a single primary slot. */
    if (g_tls_replay_context &&
        !tx_replay_parallel_enabled()) {
        size_t max_seq_txs = tx_replay_seq_max_txs();
        uint32_t total_replay_txs = sol_entry_batch_transaction_count(batch);
        if (max_seq_txs != 0u && (size_t)total_replay_txs >= max_seq_txs) {
            static _Atomic int replay_hybrid_logged = 0;
            if (__atomic_exchange_n(&replay_hybrid_logged, 1, __ATOMIC_ACQ_REL) == 0) {
                sol_log_info("Replay tx execution mode: hybrid (sequential<=%zu tx, parallel above; set SOL_TX_REPLAY_PARALLEL=1 for full parallel replay)",
                             max_seq_txs);
            }
        } else {
            static _Atomic int replay_seq_logged = 0;
            if (__atomic_exchange_n(&replay_seq_logged, 1, __ATOMIC_ACQ_REL) == 0) {
                sol_log_info("Replay tx execution mode: sequential (set SOL_TX_REPLAY_PARALLEL=1 to re-enable tx-pool parallel replay)");
            }
            uint64_t exec_t0 = timing ? bank_monotonic_ns() : 0;
            for (size_t i = 0; i < batch->num_entries; i++) {
                sol_err_t err = sol_bank_process_entry(bank, &batch->entries[i]);
                if (err != SOL_OK) {
                    return err;
                }
            }
            if (timing) {
                timing->tx_exec_ns += bank_monotonic_ns() - exec_t0;
            }
            return SOL_OK;
        }
    }

    tx_sched_scratch_t* sc = &g_tls_tx_sched_scratch;
    const sol_transaction_t** tx_ptrs = NULL;
    sol_tx_result_t* results = NULL;
    bool heap_bufs = false;
    uint64_t prep_t0 = timing ? bank_monotonic_ns() : 0;

    if (tx_sched_ensure_batch_bufs(sc, total_txs)) {
        tx_ptrs = sc->batch_tx_ptrs;
        results = sc->batch_results;
    } else {
        tx_ptrs = sol_alloc(total_txs * sizeof(*tx_ptrs));
        results = sol_alloc(total_txs * sizeof(*results));
        heap_bufs = true;
        if (!tx_ptrs || !results) {
            if (tx_ptrs) sol_free((void*)tx_ptrs);
            if (results) sol_free(results);
            if (timing) {
                timing->prep_ns += bank_monotonic_ns() - prep_t0;
            }
            /* Fall back to conservative entry-by-entry behavior. */
            uint64_t exec_t0 = timing ? bank_monotonic_ns() : 0;
            for (size_t i = 0; i < batch->num_entries; i++) {
                sol_err_t err = sol_bank_process_entry(bank, &batch->entries[i]);
                if (err != SOL_OK) return err;
            }
            if (timing) {
                timing->tx_exec_ns += bank_monotonic_ns() - exec_t0;
            }
            return SOL_OK;
        }
    }

    size_t cursor = 0;
    for (size_t ei = 0; ei < batch->num_entries; ei++) {
        const sol_entry_t* entry = &batch->entries[ei];
        for (uint32_t ti = 0; ti < entry->num_transactions; ti++) {
            tx_ptrs[cursor++] = &entry->transactions[ti];
        }
    }
    if (timing) {
        timing->prep_ns += bank_monotonic_ns() - prep_t0;
    }

    uint64_t exec_t0 = timing ? bank_monotonic_ns() : 0;
    sol_err_t terr = sol_bank_process_transactions_ptrs(bank, tx_ptrs, total_txs, results);
    if (timing) {
        timing->tx_exec_ns += bank_monotonic_ns() - exec_t0;
    }
    if (terr != SOL_OK) {
        if (heap_bufs) {
            sol_free((void*)tx_ptrs);
            sol_free(results);
        }
        return terr;
    }

    /* Preserve per-entry logging and PoH advancement. */
    uint64_t poh_t0 = timing ? bank_monotonic_ns() : 0;
    cursor = 0;
    for (size_t ei = 0; ei < batch->num_entries; ei++) {
        const sol_entry_t* entry = &batch->entries[ei];
        for (uint32_t ti = 0; ti < entry->num_transactions; ti++) {
            if (results[cursor].status != SOL_OK) {
                sol_log_debug("Transaction %u failed: %d", ti, results[cursor].status);
            }
            cursor++;
        }

        sol_err_t aerr = bank_advance_poh_and_register_ticks(bank, entry);
        if (aerr != SOL_OK) {
            if (heap_bufs) {
                sol_free((void*)tx_ptrs);
                sol_free(results);
            }
            return aerr;
        }
    }
    if (timing) {
        timing->poh_ns += bank_monotonic_ns() - poh_t0;
    }

    if (heap_bufs) {
        sol_free((void*)tx_ptrs);
        sol_free(results);
    }
    return SOL_OK;
}

sol_err_t
sol_bank_process_entries(sol_bank_t* bank, const sol_entry_batch_t* batch) {
    return sol_bank_process_entries_ex(bank, batch, NULL);
}

sol_err_t
sol_bank_register_tick(sol_bank_t* bank, const sol_hash_t* tick_hash) {
    if (!bank || !tick_hash) return SOL_ERR_INVAL;
    if (__atomic_load_n(&bank->frozen, __ATOMIC_ACQUIRE)) return SOL_ERR_SHUTDOWN;

    pthread_mutex_lock(&bank->lock);

    if (bank->tick_height >= bank->max_tick_height) {
        pthread_mutex_unlock(&bank->lock);
        return SOL_ERR_OVERFLOW;
    }

    bank->tick_height++;
    bank->hash_computed = false;
    bank->accounts_delta_hash_computed = false;

    /* Add to recent blockhashes if last tick of slot.
     * IMPORTANT: Only update bank->blockhash on the LAST tick to match Agave's
     * last_blockhash() behavior.  Agave's blockhash_queue.last_hash() is only
     * updated when register_recent_blockhash() is called (last tick).  During
     * intermediate ticks, last_blockhash() still returns the parent's blockhash.
     * This is critical for nonce derivation which uses last_blockhash(). */
    if (bank->tick_height == bank->max_tick_height) {
        bank->blockhash = *tick_hash;
        bank->accounts_lt_hash_computed = false;

        /* Shift existing entries */
        if (bank->recent_blockhash_count >= MAX_RECENT_BLOCKHASHES) {
            memmove(&bank->recent_blockhashes[1],
                    &bank->recent_blockhashes[0],
                    (MAX_RECENT_BLOCKHASHES - 1) * sizeof(sol_blockhash_entry_t));
        } else {
            memmove(&bank->recent_blockhashes[1],
                    &bank->recent_blockhashes[0],
                    bank->recent_blockhash_count * sizeof(sol_blockhash_entry_t));
            bank->recent_blockhash_count++;
        }

        bank->recent_blockhashes[0].hash = *tick_hash;
        bank->recent_blockhashes[0].fee_calculator = bank->config.lamports_per_signature;
        bank_recent_blockhash_map_rebuild(bank);

        /* In Agave, register_recent_blockhash() is called at the block boundary
         * (last tick). It adds the new hash to the blockhash_queue AND updates the
         * RecentBlockhashes sysvar account in AccountsDB. This must happen here
         * (not in new_from_parent) so the sysvar includes the current slot's
         * blockhash and participates in the correct slot's lt_hash delta. */
        sol_err_t rbh_err = update_recent_blockhashes_sysvar(bank);
        if (rbh_err != SOL_OK) {
            sol_log_warn("Failed to update RecentBlockhashes sysvar: %s", sol_err_str(rbh_err));
        }

        /* NOTE: Fee distribution moved to sol_bank_freeze() to match Agave's
         * ordering (distribute_transaction_fee_details is called inside freeze). */
    }

    pthread_mutex_unlock(&bank->lock);
    return SOL_OK;
}

static void
run_incinerator(sol_bank_t* bank) {
    /* Check if the incinerator account was modified in this slot.
       If so, zero it out.  The store of a zero-lamport account automatically
       adjusts total_lamports (capitalization) via the accounts DB.
       This matches Agave's Bank::run_incinerator(). */
    sol_account_t* incinerator_acct = NULL;
    sol_accounts_db_local_kind_t kind =
        sol_accounts_db_get_local_kind(bank->accounts_db, &SOL_INCINERATOR_ID,
                                       &incinerator_acct);
    if (kind == SOL_ACCOUNTS_DB_LOCAL_ACCOUNT && incinerator_acct) {
        uint64_t lamports = incinerator_acct->meta.lamports;
        if (lamports > 0) {
            sol_log_info("incinerator: burning %lu lamports in slot %lu",
                         (unsigned long)lamports, (unsigned long)bank->slot);
            /* Store a zero-lamport account (becomes a tombstone/delete).
               This subtracts the old lamports from db->stats.total_lamports. */
            sol_account_t zero_acct = {0};
            (void)sol_bank_store_account(bank, &SOL_INCINERATOR_ID, &zero_acct);
        }
        sol_account_destroy(incinerator_acct);
    }
}

/*
 * Eager rent collection: sweep a partition of accounts by pubkey range
 * and fix rent_epoch to UINT64_MAX for rent-exempt accounts.
 *
 * In Agave, collect_rent_eagerly() is called during freeze().  With
 * disable_rent_fees_collection active (since epoch 756), no rent is
 * actually charged, but rent_epoch is set to UINT64_MAX for accounts
 * that are rent-exempt.  This affects the lt_hash and bank hash.
 *
 * Partition computation matches Agave's single-epoch variable cycle:
 *   partition = (parent_slot_index, current_slot_index, slots_per_epoch)
 *   pubkey_range = pubkey_range_from_partition(partition)
 */

typedef struct {
    sol_bank_t* bank;
    size_t      fixed;
} rent_collect_ctx_t;

static bool
rent_collect_iter_cb(const sol_pubkey_t* pubkey, const sol_account_t* account, void* ctx) {
    rent_collect_ctx_t* rctx = (rent_collect_ctx_t*)ctx;
    if (!rctx || !pubkey || !account) return false;

    if (account->meta.lamports == 0) return true;
    if (account->meta.rent_epoch == UINT64_MAX) return true;

    if (sol_account_is_rent_exempt(account,
                                    rctx->bank->config.rent_per_byte_year,
                                    rctx->bank->config.rent_exemption_threshold)) {
        /* Load a mutable copy and fix rent_epoch */
        sol_account_t* mutable_acct = sol_accounts_db_load(rctx->bank->accounts_db, pubkey);
        if (mutable_acct && mutable_acct->meta.rent_epoch != UINT64_MAX &&
            mutable_acct->meta.lamports > 0) {
            mutable_acct->meta.rent_epoch = UINT64_MAX;
            (void)sol_bank_store_account(rctx->bank, pubkey, mutable_acct);
            rctx->fixed++;
        }
        if (mutable_acct) sol_account_destroy(mutable_acct);
    }
    return true;
}

static void __attribute__((unused))
collect_rent_eagerly(sol_bank_t* bank) {
    if (!bank || !bank->accounts_db) return;

    uint64_t slots_per_epoch = bank->config.slots_per_epoch;
    if (slots_per_epoch == 0) return;

    uint64_t current_slot = bank->slot;
    uint64_t parent_slot = bank->parent_slot;

    /* Compute epoch and slot index for single-epoch cycle (mainnet) */
    uint64_t current_epoch = current_slot / slots_per_epoch;
    uint64_t parent_epoch = parent_slot / slots_per_epoch;
    uint64_t current_slot_index = current_slot % slots_per_epoch;
    uint64_t parent_slot_index = parent_slot % slots_per_epoch;

    /* Handle epoch boundary: if we crossed an epoch, reset parent index */
    if (parent_epoch < current_epoch) {
        parent_slot_index = 0;
    }

    /* For this simplified single-epoch cycle:
     * partition_count = slots_per_epoch
     * start_index = parent_slot_index
     * end_index = current_slot_index
     *
     * pubkey_range_from_partition(start_index, end_index, partition_count):
     * partition_width = (UINT64_MAX - partition_count + 1) / partition_count + 1
     */
    uint64_t partition_count = slots_per_epoch;
    uint64_t start_index = parent_slot_index;
    uint64_t end_index = current_slot_index;

    if (partition_count <= 1) return; /* single partition = all accounts (not used on mainnet) */

    uint64_t partition_width = (UINT64_MAX - partition_count + 1) / partition_count + 1;

    uint64_t start_key_prefix;
    if (start_index == 0 && end_index == 0) {
        start_key_prefix = 0;
    } else if (start_index + 1 == partition_count) {
        start_key_prefix = UINT64_MAX;
    } else {
        start_key_prefix = (start_index + 1) * partition_width;
    }

    uint64_t end_key_prefix;
    if (end_index + 1 == partition_count) {
        end_key_prefix = UINT64_MAX;
    } else {
        end_key_prefix = (end_index + 1) * partition_width - 1;
    }

    /* Handle noop partition (n..=n, n != 0) */
    if (start_index != 0 && start_index == end_index) {
        if (end_key_prefix == UINT64_MAX) {
            start_key_prefix = end_key_prefix;
        } else {
            end_key_prefix = start_key_prefix;
        }
    }

    /* Build start/end pubkeys: prefix as big-endian u64 in first 8 bytes */
    sol_pubkey_t start_pubkey;
    memset(start_pubkey.bytes, 0x00, 32);
    sol_pubkey_t end_pubkey;
    memset(end_pubkey.bytes, 0xFF, 32);

    /* Write prefix as big-endian u64 */
    for (int i = 0; i < 8; i++) {
        start_pubkey.bytes[i] = (uint8_t)(start_key_prefix >> (56 - i * 8));
        end_pubkey.bytes[i]   = (uint8_t)(end_key_prefix >> (56 - i * 8));
    }

    rent_collect_ctx_t rctx = { .bank = bank, .fixed = 0 };

    sol_accounts_db_iterate_pubkey_range(
        bank->accounts_db,
        &start_pubkey,
        &end_pubkey,
        rent_collect_iter_cb,
        &rctx
    );

    if (rctx.fixed > 0) {
        sol_log_info("collect_rent_eagerly: slot=%lu partition=(%lu,%lu,%lu) fixed=%zu rent_epochs",
                     (unsigned long)current_slot,
                     (unsigned long)start_index,
                     (unsigned long)end_index,
                     (unsigned long)partition_count,
                     rctx.fixed);
    }
}

/* Bank hash computation helper.
 * Caller must hold bank->lock. */
static inline void
bank_compute_hash_locked(sol_bank_t* bank) {
    if (!bank || bank->hash_computed) return;

    /* Ensure accounts_lt_hash is available for hashing (and for child banks
     * to inherit as their base). */
    bank_compute_accounts_lt_hash_locked(bank);

    uint8_t signature_count_le[8];
    sol_store_u64_le(signature_count_le, bank->signature_count);

    /* hash1 = sha256(parent_hash || signature_count || last_blockhash) */
    sol_hash_t hash1 = {0};
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    sol_sha256_update(&ctx, bank->parent_hash.bytes, SOL_HASH_SIZE);
    sol_sha256_update(&ctx, signature_count_le, sizeof(signature_count_le));
    sol_sha256_update(&ctx, bank->blockhash.bytes, SOL_HASH_SIZE);
    sol_sha256_final_bytes(&ctx, hash1.bytes);

    /* bank_hash = sha256(hash1 || accounts_lt_hash_bytes) */
    sol_sha256_init(&ctx);
    sol_sha256_update(&ctx, hash1.bytes, SOL_HASH_SIZE);
    sol_sha256_update(&ctx,
                      (const uint8_t*)bank->accounts_lt_hash.v,
                      SOL_LT_HASH_SIZE_BYTES);
    sol_sha256_final_bytes(&ctx, bank->bank_hash.bytes);

    bank->hash_computed = true;
}

void
sol_bank_freeze(sol_bank_t* bank) {
    if (!bank) return;

    pthread_mutex_lock(&bank->lock);

    if (__atomic_load_n(&bank->frozen, __ATOMIC_ACQUIRE)) {
        pthread_mutex_unlock(&bank->lock);
        return;
    }

    /* Freeze-time updates should only run once the slot has reached its max
     * tick height. Snapshot/root banks may be frozen without local replay, so
     * tick_height can be less than max_tick_height. */
    const bool full_ticks = (bank->tick_height == bank->max_tick_height);

    if (full_ticks) {
        /* Match Agave's freeze() ordering (bank.rs lines 2542-2569):
         *   1. distribute_transaction_fee_details()
         *   2. update_slot_history()
         *   3. run_incinerator()
         */

        /* 1. Distribute accumulated transaction fees to the slot leader. */
        (void)distribute_slot_fees(bank);

        /* 2. Update SlotHistory sysvar — adds current slot.
         *    In Agave, this is done at freeze() time, not new_from_parent(). */
        (void)update_slot_history_sysvar(bank);

        /* 3. Burn incinerator lamports. */
        run_incinerator(bank);
    }

    /* Publish frozen=true before hash computation. This enables the
     * freeze-time immutable delta-view fast path in accounts_lt_hash
     * computation and avoids expensive clone-based snapshots on the replay
     * hot path. We still hold bank->lock here, so no externally visible
     * partial freeze state is released until after hash computation finishes. */
    __atomic_store_n(&bank->frozen, true, __ATOMIC_RELEASE);

    /* Precompute frozen bank hash while we already own bank->lock. Child-bank
     * construction relies on parent bank hash and tail latency improves when
     * this work is done at freeze-time instead of first child creation. */
    bank_compute_hash_locked(bank);
    pthread_mutex_unlock(&bank->lock);
}

bool
sol_bank_is_frozen(const sol_bank_t* bank) {
    if (!bank) return false;
    return __atomic_load_n(&bank->frozen, __ATOMIC_ACQUIRE);
}

void
sol_bank_compute_hash(sol_bank_t* bank, sol_hash_t* out_hash) {
    if (!bank || !out_hash) return;

    pthread_mutex_lock(&bank->lock);

    if (!bank->hash_computed) {
        /* Bank hash (Agave/Solana v3.1.x):
         *   hash1 = sha256(parent_bank_hash || signature_count_le || last_blockhash)
         *   bank_hash = sha256(hash1 || accounts_lt_hash_bytes)
         *
         * Note: snapshots may seed bank->bank_hash via sol_bank_set_bank_hash(). */
        bank_compute_hash_locked(bank);
    }

    *out_hash = bank->bank_hash;

    pthread_mutex_unlock(&bank->lock);
}

bool
sol_bank_get_accounts_delta_hash(sol_bank_t* bank, sol_hash_t* out_hash) {
    if (!bank || !out_hash) return false;

    pthread_mutex_lock(&bank->lock);
    if (!bank->accounts_delta_hash_computed &&
        sol_accounts_db_is_overlay(bank->accounts_db)) {
        sol_hash_t accounts_delta_hash = {0};
        sol_accounts_db_hash_delta(bank->accounts_db, &accounts_delta_hash);
        bank->accounts_delta_hash = accounts_delta_hash;
        bank->accounts_delta_hash_computed = true;
    }
    bool ok = bank->accounts_delta_hash_computed;
    if (ok) {
        *out_hash = bank->accounts_delta_hash;
    }
    pthread_mutex_unlock(&bank->lock);
    return ok;
}

void
sol_bank_stats(const sol_bank_t* bank, sol_bank_stats_t* stats) {
    if (!bank || !stats) return;

    pthread_mutex_lock((pthread_mutex_t*)&bank->lock);
    *stats = bank->stats;
    pthread_mutex_unlock((pthread_mutex_t*)&bank->lock);
}

void
sol_bank_stats_reset(sol_bank_t* bank) {
    if (!bank) return;

    pthread_mutex_lock(&bank->lock);
    memset(&bank->stats, 0, sizeof(bank->stats));
    pthread_mutex_unlock(&bank->lock);
}

size_t
sol_bank_account_count(const sol_bank_t* bank) {
    if (!bank) return 0;
    return sol_accounts_db_count(bank->accounts_db);
}

uint64_t
sol_bank_capitalization(const sol_bank_t* bank) {
    if (!bank) return 0;
    return sol_accounts_db_total_lamports(bank->accounts_db);
}

uint64_t
sol_bank_rent_exempt_minimum(const sol_bank_t* bank, size_t data_len) {
    if (!bank) return 0;

    /*
     * Calculate rent-exempt minimum based on bank config.
     * Formula: (data_len + 128) * lamports_per_byte_year * exemption_threshold
     *
     * The 128 bytes is the account metadata overhead.
     * exemption_threshold is typically 2 years worth of rent.
     */
    size_t account_size = data_len + 128;

    uint64_t lamports = (uint64_t)account_size *
                        bank->config.rent_per_byte_year *
                        bank->config.rent_exemption_threshold;

    return lamports;
}

sol_accounts_db_t*
sol_bank_get_accounts_db(sol_bank_t* bank) {
    if (!bank) return NULL;
    return bank->accounts_db;
}

bool
sol_bank_owns_accounts_db(const sol_bank_t* bank) {
    if (!bank) return false;
    pthread_mutex_lock((pthread_mutex_t*)&bank->lock);
    bool owns = bank->owns_accounts_db;
    pthread_mutex_unlock((pthread_mutex_t*)&bank->lock);
    return owns;
}

void
sol_bank_set_owns_accounts_db(sol_bank_t* bank, bool owns) {
    if (!bank) return;
    pthread_mutex_lock(&bank->lock);
    bank->owns_accounts_db = owns;
    pthread_mutex_unlock(&bank->lock);
}

/*
 * Hash function for signature -> bucket index
 */
static uint32_t
signature_hash(const sol_signature_t* sig) {
    /* Use first 4 bytes of signature as hash */
    uint32_t h = 0;
    h |= (uint32_t)sig->bytes[0];
    h |= (uint32_t)sig->bytes[1] << 8;
    h |= (uint32_t)sig->bytes[2] << 16;
    h |= (uint32_t)sig->bytes[3] << 24;
    return h % TX_STATUS_HASH_SIZE;
}

static void
sol_bank_record_tx_status_batch(sol_bank_t* bank,
                                const sol_transaction_t* const* tx_ptrs,
                                size_t count,
                                const sol_tx_result_t* results) {
    if (!bank || !tx_ptrs || !results || count == 0) return;

    pthread_mutex_lock(&bank->tx_status_lock);

    for (size_t i = 0; i < count; i++) {
        const sol_transaction_t* tx = tx_ptrs[i];
        if (!tx) continue;

        const sol_signature_t* signature = sol_transaction_signature(tx);
        if (!signature) continue;

        uint32_t bucket = signature_hash(signature);
        sol_tx_status_node_t* node = bank->tx_status_buckets[bucket];
        bool found = false;

        while (node) {
            if (memcmp(&node->entry.signature, signature, sizeof(sol_signature_t)) == 0) {
                node->entry.status = results[i].status;
                node->entry.fee = results[i].fee;
                node->entry.compute_units = results[i].compute_units_used;
                found = true;
                break;
            }
            node = node->next;
        }
        if (found) continue;

        if (bank->tx_status_count >= SOL_TX_STATUS_CACHE_SIZE) {
            continue;
        }

        node = sol_calloc(1, sizeof(sol_tx_status_node_t));
        if (!node) continue;

        node->entry.signature = *signature;
        node->entry.slot = bank->slot;
        node->entry.status = results[i].status;
        node->entry.fee = results[i].fee;
        node->entry.compute_units = results[i].compute_units_used;

        node->next = bank->tx_status_buckets[bucket];
        bank->tx_status_buckets[bucket] = node;
        bank->tx_status_count++;
    }

    pthread_mutex_unlock(&bank->tx_status_lock);
}

void
sol_bank_record_tx_status(sol_bank_t* bank,
                          const sol_signature_t* signature,
                          sol_err_t status,
                          uint64_t fee,
                          uint64_t compute_units) {
    if (!bank || !signature) return;

    uint32_t bucket = signature_hash(signature);

    pthread_mutex_lock(&bank->tx_status_lock);

    /* Check if already exists */
    sol_tx_status_node_t* node = bank->tx_status_buckets[bucket];
    while (node) {
        if (memcmp(&node->entry.signature, signature, sizeof(sol_signature_t)) == 0) {
            /* Update existing entry */
            node->entry.status = status;
            node->entry.fee = fee;
            node->entry.compute_units = compute_units;
            pthread_mutex_unlock(&bank->tx_status_lock);
            return;
        }
        node = node->next;
    }

    /* Cache full: allow updates of existing entries above, but skip inserts. */
    if (bank->tx_status_count >= SOL_TX_STATUS_CACHE_SIZE) {
        pthread_mutex_unlock(&bank->tx_status_lock);
        return;
    }

    /* Create new entry */
    node = sol_calloc(1, sizeof(sol_tx_status_node_t));
    if (!node) {
        pthread_mutex_unlock(&bank->tx_status_lock);
        return;
    }

    node->entry.signature = *signature;
    node->entry.slot = bank->slot;
    node->entry.status = status;
    node->entry.fee = fee;
    node->entry.compute_units = compute_units;

    /* Insert at head of bucket */
    node->next = bank->tx_status_buckets[bucket];
    bank->tx_status_buckets[bucket] = node;
    bank->tx_status_count++;

    pthread_mutex_unlock(&bank->tx_status_lock);
}

bool
sol_bank_get_tx_status(const sol_bank_t* bank,
                       const sol_signature_t* signature,
                       sol_tx_status_entry_t* out_status) {
    if (!bank || !signature) return false;

    uint32_t bucket = signature_hash(signature);

    pthread_mutex_lock((pthread_mutex_t*)&bank->tx_status_lock);

    sol_tx_status_node_t* node = bank->tx_status_buckets[bucket];
    while (node) {
        if (memcmp(&node->entry.signature, signature, sizeof(sol_signature_t)) == 0) {
            if (out_status) {
                *out_status = node->entry;
            }
            pthread_mutex_unlock((pthread_mutex_t*)&bank->tx_status_lock);
            return true;
        }
        node = node->next;
    }

    pthread_mutex_unlock((pthread_mutex_t*)&bank->tx_status_lock);
    return false;
}

size_t
sol_bank_purge_tx_status(sol_bank_t* bank, sol_slot_t min_slot) {
    if (!bank) return 0;

    size_t removed = 0;

    pthread_mutex_lock(&bank->tx_status_lock);

    for (size_t i = 0; i < TX_STATUS_HASH_SIZE; i++) {
        sol_tx_status_node_t** ptr = &bank->tx_status_buckets[i];
        while (*ptr) {
            if ((*ptr)->entry.slot < min_slot) {
                sol_tx_status_node_t* to_remove = *ptr;
                *ptr = (*ptr)->next;
                sol_free(to_remove);
                removed++;
                bank->tx_status_count--;
            } else {
                ptr = &(*ptr)->next;
            }
        }
    }

    pthread_mutex_unlock(&bank->tx_status_lock);
    return removed;
}

size_t
sol_bank_tx_status_count(const sol_bank_t* bank) {
    if (!bank) return 0;
    pthread_mutex_lock((pthread_mutex_t*)&bank->tx_status_lock);
    size_t n = bank->tx_status_count;
    pthread_mutex_unlock((pthread_mutex_t*)&bank->tx_status_lock);
    return n;
}

/*
 * Add a log message to simulation result
 */
static void
sim_add_log(sol_sim_result_t* result, const char* fmt, ...) {
    if (result->logs_count >= SOL_SIM_MAX_LOGS) return;

    va_list args;
    va_start(args, fmt);
    vsnprintf(result->logs[result->logs_count], SOL_SIM_MAX_LOG_LEN, fmt, args);
    va_end(args);
    result->logs_count++;
}

/*
 * Execute instruction in simulation mode
 */
static sol_err_t
simulate_instruction(sol_bank_t* bank, const sol_transaction_t* tx,
                     const sol_compiled_instruction_t* instr,
                     sol_sim_result_t* result, uint8_t instr_idx) {
    const sol_message_t* msg = &tx->message;
    const sol_pubkey_t* account_keys = tx->message.resolved_accounts_len
        ? tx->message.resolved_accounts
        : tx->message.account_keys;
    uint16_t account_keys_len = tx->message.resolved_accounts_len
        ? tx->message.resolved_accounts_len
        : (uint16_t)tx->message.account_keys_len;

    if (account_keys_len > UINT8_MAX) {
        sim_add_log(result, "Program failed: too many account keys");
        return SOL_ERR_TX_TOO_LARGE;
    }

    bool local_is_writable[SOL_MAX_MESSAGE_ACCOUNTS];
    bool local_is_signer[SOL_MAX_MESSAGE_ACCOUNTS];
    const bool* is_writable = NULL;
    const bool* is_signer = NULL;

    /* Apply Agave-compatible is_writable demotion (same as execute_instruction) */
    if (msg->version == SOL_MESSAGE_VERSION_V0 &&
        msg->resolved_accounts_len != 0 &&
        msg->is_writable &&
        account_keys_len == msg->resolved_accounts_len) {
        memcpy(local_is_writable, msg->is_writable,
               account_keys_len * sizeof(bool));
    } else {
        for (uint16_t i = 0; i < account_keys_len; i++) {
            local_is_writable[i] = sol_message_is_writable_index(msg, (uint8_t)i);
        }
    }

    bool upgradeable_loader_present = false;
    for (uint16_t i = 0; i < account_keys_len; i++) {
        if (sol_pubkey_eq(&account_keys[i], &SOL_BPF_LOADER_UPGRADEABLE_ID)) {
            upgradeable_loader_present = true;
            break;
        }
    }

    for (uint16_t i = 1; i < account_keys_len; i++) {
        if (!local_is_writable[i]) continue;
        if (is_reserved_account_key(&account_keys[i])) {
            local_is_writable[i] = false;
            continue;
        }
        if (!upgradeable_loader_present) {
            for (uint8_t j = 0; j < msg->instructions_len; j++) {
                if (msg->instructions[j].program_id_index == (uint8_t)i) {
                    local_is_writable[i] = false;
                    break;
                }
            }
        }
    }
    is_writable = local_is_writable;

    if (msg->version == SOL_MESSAGE_VERSION_V0 &&
        msg->resolved_accounts_len != 0 &&
        msg->is_signer &&
        account_keys_len == msg->resolved_accounts_len) {
        is_signer = msg->is_signer;
    } else {
        for (uint16_t i = 0; i < account_keys_len; i++) {
            local_is_signer[i] = sol_message_is_signer(msg, (uint8_t)i);
        }
        is_signer = local_is_signer;
    }

    /* Get program ID */
    if (!account_keys || instr->program_id_index >= account_keys_len) {
        sim_add_log(result, "Program failed: invalid program id");
        return SOL_ERR_PROGRAM_NOT_FOUND;
    }

    const sol_pubkey_t* program_id = &account_keys[instr->program_id_index];
    char program_str[45];
    sol_pubkey_to_base58(program_id, program_str, sizeof(program_str));

    sim_add_log(result, "Program %s invoke [%u]", program_str, instr_idx + 1);

    /* Build invoke context */
    sol_invoke_context_t ctx = {
        .bank = bank,
        .account_keys = account_keys,
        .account_keys_len = (uint8_t)account_keys_len,
        .is_writable = is_writable,
        .is_signer = is_signer,
        .account_indices = instr->account_indices,
        .account_indices_len = instr->account_indices_len,
        .instruction_data = instr->data,
        .instruction_data_len = instr->data_len,
        .program_id = *program_id,
        .tx_signature = sol_transaction_signature(tx),
        .num_signers = tx->message.header.num_required_signatures,
        .stack_height = 1,
    };
    fill_invoke_sysvars(&ctx, bank);

    sol_err_t err = sol_program_execute(&ctx);

    /* Estimate compute units per instruction */
    result->units_consumed += 50000;

    if (err == SOL_OK) {
        sim_add_log(result, "Program %s success", program_str);
    } else {
        sim_add_log(result, "Program %s failed: %s", program_str, sol_err_str(err));
    }

    return err;
}

sol_sim_result_t
sol_bank_simulate_transaction(sol_bank_t* bank, const sol_transaction_t* tx,
                              bool sig_verify, bool replace_blockhash) {
    sol_sim_result_t result = {0};
    bool resolved_override = false;
    const sol_pubkey_t* saved_resolved_accounts = NULL;
    uint16_t saved_resolved_accounts_len = 0;
    bool* saved_is_writable = NULL;
    bool* saved_is_signer = NULL;
    sol_pubkey_t resolved_accounts[SOL_MAX_MESSAGE_ACCOUNTS];
    bool resolved_is_writable[SOL_MAX_MESSAGE_ACCOUNTS];
    bool resolved_is_signer[SOL_MAX_MESSAGE_ACCOUNTS];

    if (!bank || !tx) {
        result.status = SOL_ERR_INVAL;
        sim_add_log(&result, "Simulation failed: invalid input");
        return result;
    }

    /* 1. Basic validation */
    if (tx->signatures_len == 0) {
        result.status = SOL_ERR_TX_MALFORMED;
        sim_add_log(&result, "Transaction has no signatures");
        return result;
    }

    if (sol_transaction_num_instructions(tx) == 0 || tx->message.instructions == NULL) {
        result.status = SOL_ERR_TX_MALFORMED;
        sim_add_log(&result, "Transaction has no instructions");
        return result;
    }

    /* 2. Verify signatures if requested */
    if (sig_verify && !sol_transaction_verify_signatures(tx, NULL)) {
        result.status = SOL_ERR_TX_SIGNATURE;
        sim_add_log(&result, "Signature verification failed");
        return result;
    }

    if (tx->message.version == SOL_MESSAGE_VERSION_V0 &&
        tx->message.resolved_accounts_len == 0) {
        uint16_t resolved_len = 0;
        sol_err_t resolve_err = bank_resolve_v0_message_accounts(bank,
                                                                 tx,
                                                                 resolved_accounts,
                                                                 resolved_is_writable,
                                                                 resolved_is_signer,
                                                                 SOL_MAX_MESSAGE_ACCOUNTS,
                                                                 &resolved_len);
        if (resolve_err != SOL_OK) {
            result.status = resolve_err;
            sim_add_log(&result, "Failed to resolve address lookup tables");
            goto cleanup;
        }

        if (resolved_len > UINT8_MAX) {
            result.status = SOL_ERR_TX_TOO_LARGE;
            sim_add_log(&result, "Too many account keys");
            goto cleanup;
        }

        sol_message_t* msg = (sol_message_t*)&tx->message;
        saved_resolved_accounts = msg->resolved_accounts;
        saved_resolved_accounts_len = msg->resolved_accounts_len;
        saved_is_writable = msg->is_writable;
        saved_is_signer = msg->is_signer;
        msg->resolved_accounts = resolved_accounts;
        msg->resolved_accounts_len = resolved_len;
        msg->is_writable = resolved_is_writable;
        msg->is_signer = resolved_is_signer;
        resolved_override = true;
    }

    /* 3. Verify blockhash (unless replacing) */
    if (!replace_blockhash) {
        bool ok = sol_bank_is_blockhash_valid(bank, &tx->message.recent_blockhash);
        if (!ok) {
            uint64_t nonce_lamports_per_signature = 0;
            ok = bank_try_get_durable_nonce_fee_calculator(bank, tx, &nonce_lamports_per_signature);
        }
        if (!ok) {
            result.status = SOL_ERR_TX_BLOCKHASH;
            sim_add_log(&result, "Blockhash not found in recent blockhashes");
            goto cleanup;
        }
    }

    /* 4. Verify fee payer has sufficient funds */
    const sol_pubkey_t* fee_payer = sol_message_fee_payer(&tx->message);
    if (!fee_payer) {
        result.status = SOL_ERR_TX_MALFORMED;
        sim_add_log(&result, "Missing fee payer");
        goto cleanup;
    }

    uint64_t fee = sol_bank_calculate_fee(bank, tx);
    sol_account_t* payer_account = sol_bank_load_account(bank, fee_payer);

    if (!payer_account) {
        result.status = SOL_ERR_TX_ACCOUNT_NOT_FOUND;
        sim_add_log(&result, "Fee payer account not found");
        goto cleanup;
    }

    if (payer_account->meta.lamports < fee) {
        result.status = SOL_ERR_TX_INSUFFICIENT_FUNDS;
        sim_add_log(&result, "Insufficient funds for fee: have %lu, need %lu",
                    (unsigned long)payer_account->meta.lamports, (unsigned long)fee);
        sol_account_destroy(payer_account);
        goto cleanup;
    }

    sol_account_destroy(payer_account);

    /* 5. Execute instructions in simulation mode */
    sim_add_log(&result, "Simulation started at slot %lu", (unsigned long)sol_bank_slot(bank));

    for (uint8_t i = 0; i < tx->message.instructions_len; i++) {
        const sol_compiled_instruction_t* instr = &tx->message.instructions[i];
        sol_err_t instr_err = simulate_instruction(bank, tx, instr, &result, i);

        if (instr_err != SOL_OK) {
            result.status = instr_err;
            sim_add_log(&result, "Transaction simulation failed at instruction %u", i);
            goto cleanup;
        }
    }

    /* Success */
    result.status = SOL_OK;
    sim_add_log(&result, "Simulation completed successfully");
    sim_add_log(&result, "Compute units consumed: %lu", (unsigned long)result.units_consumed);

cleanup:
    if (resolved_override) {
        sol_message_t* msg = (sol_message_t*)&tx->message;
        msg->resolved_accounts = saved_resolved_accounts;
        msg->resolved_accounts_len = saved_resolved_accounts_len;
        msg->is_writable = saved_is_writable;
        msg->is_signer = saved_is_signer;
    }

    return result;
}

void
sol_sim_result_cleanup(sol_sim_result_t* result) {
    if (!result) return;

    /* Free any account states that were allocated */
    for (size_t i = 0; i < result->accounts_count; i++) {
        if (result->accounts[i]) {
            sol_account_destroy(result->accounts[i]);
            result->accounts[i] = NULL;
        }
    }
    result->accounts_count = 0;
}
