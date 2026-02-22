/*
 * sol_bank.c - Bank State Machine Implementation
 */

#include "sol_bank.h"
#include "../util/sol_alloc.h"
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
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include <stdio.h>
#include <pthread.h>

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
    if (cached >= 0) {
        return cached != 0;
    }

    const char* env = getenv("SOL_SKIP_INSTRUCTION_EXEC");
    cached = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    return cached != 0;
}

static bool
bank_skip_signature_verify(void) {
    static int cached = -1;
    if (cached >= 0) {
        return cached != 0;
    }

    const char* env = getenv("SOL_SKIP_SIGNATURE_VERIFY");
    cached = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    return cached != 0;
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

    /* Transaction status cache */
    sol_tx_status_node_t*   tx_status_buckets[TX_STATUS_HASH_SIZE];
    size_t                  tx_status_count;

    /* State */
    bool                    frozen;
    sol_hash_t              bank_hash;
    sol_hash_t              accounts_delta_hash;
    bool                    hash_computed;
    bool                    accounts_delta_hash_computed;

    /* Statistics */
    sol_bank_stats_t        stats;

    /* Thread safety */
    pthread_mutex_t         lock;
};

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
        sol_log_info("FEE_DIST: slot=%lu BURNED %lu lamports (collector=%s failed validation)",
                     (unsigned long)bank->slot, (unsigned long)to_collector, coll_b58);
        sol_account_destroy(collector);
        return SOL_OK;
    }
    collector->meta.lamports += to_collector;

    {
        char coll_b58[SOL_PUBKEY_BASE58_LEN] = {0};
        sol_pubkey_to_base58(&bank->fee_collector, coll_b58, sizeof(coll_b58));
        sol_log_info("FEE_DIST: slot=%lu collector=%s total_fees=%lu priority=%lu burned=%lu to_collector=%lu",
                     (unsigned long)bank->slot, coll_b58,
                     (unsigned long)total_fees, (unsigned long)priority_fees,
                     (unsigned long)burned, (unsigned long)to_collector);
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

typedef struct {
    const sol_pubkey_map_t* vote_stakes;
    sol_slot_t              slot;
    uint64_t                ns_per_slot;
    uint64_t                slots_per_epoch;
    timestamp_sample_t*     samples;
    size_t                  len;
    size_t                  cap;
    __uint128_t             total_stake;
    bool                    oom;
} timestamp_collect_ctx_t;

static bool
collect_vote_timestamp_cb(const sol_pubkey_t* pubkey,
                          const sol_account_t* account,
                          void* ctx) {
    timestamp_collect_ctx_t* c = (timestamp_collect_ctx_t*)ctx;
    if (!c || c->oom) {
        return false;
    }
    if (!pubkey || !account) {
        return true;
    }
    if (account->meta.lamports == 0) {
        return true;
    }

    /* Iterate-owner should already filter by owner, but keep the check for
     * safety on fallback paths. */
    if (!sol_pubkey_eq(&account->meta.owner, &SOL_VOTE_PROGRAM_ID)) {
        return true;
    }

    const uint64_t* stake_ptr = (const uint64_t*)sol_pubkey_map_get(c->vote_stakes, pubkey);
    if (!stake_ptr || *stake_ptr == 0) {
        return true;
    }

    sol_vote_state_t vote_state;
    if (sol_vote_state_deserialize(&vote_state, account->data, account->meta.data_len) != SOL_OK) {
        return true;
    }

    if (vote_state.last_timestamp_slot == 0 || vote_state.last_timestamp == 0) {
        return true;
    }
    if ((sol_slot_t)vote_state.last_timestamp_slot > c->slot) {
        return true;
    }

    sol_slot_t age = c->slot - (sol_slot_t)vote_state.last_timestamp_slot;
    if ((uint64_t)age > c->slots_per_epoch) {
        return true;
    }

    __uint128_t delta_ns = (__uint128_t)(uint64_t)age * (__uint128_t)c->ns_per_slot;
    uint64_t delta_s = (uint64_t)(delta_ns / 1000000000ULL);

    if (delta_s > (uint64_t)INT64_MAX) {
        return true;
    }
    if (vote_state.last_timestamp > INT64_MAX - (int64_t)delta_s) {
        return true;
    }

    int64_t estimate = vote_state.last_timestamp + (int64_t)delta_s;

    if (c->len == c->cap) {
        size_t new_cap = c->cap ? (c->cap * 2) : 256;
        if (new_cap < c->cap) {
            c->oom = true;
            return false;
        }
        timestamp_sample_t* next = sol_realloc(c->samples, new_cap * sizeof(*next));
        if (!next) {
            c->oom = true;
            return false;
        }
        c->samples = next;
        c->cap = new_cap;
    }

    c->samples[c->len++] = (timestamp_sample_t){
        .timestamp = estimate,
        .stake = *stake_ptr,
    };
    c->total_stake += (__uint128_t)(*stake_ptr);
    return true;
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

    timestamp_collect_ctx_t ctx = {
        .vote_stakes = vote_stakes,
        .slot = bank->slot,
        .ns_per_slot = ns_per_slot,
        .slots_per_epoch = bank->config.slots_per_epoch,
        .samples = NULL,
        .len = 0,
        .cap = 0,
        .total_stake = 0,
        .oom = false,
    };

    sol_accounts_db_iterate_owner(bank->accounts_db,
                                  &SOL_VOTE_PROGRAM_ID,
                                  collect_vote_timestamp_cb,
                                  &ctx);

    if (ctx.oom || ctx.len == 0 || ctx.total_stake == 0) {
        sol_free(ctx.samples);
        return false;
    }

    qsort(ctx.samples, ctx.len, sizeof(*ctx.samples), cmp_timestamp_sample);

    /* Agave: stake_accumulator > total_stake / 2  (strictly greater than) */
    __uint128_t half_stake = ctx.total_stake / 2;
    __uint128_t cum = 0;
    int64_t median = ctx.samples[ctx.len - 1].timestamp;
    for (size_t i = 0; i < ctx.len; i++) {
        cum += (__uint128_t)ctx.samples[i].stake;
        if (cum > half_stake) {
            median = ctx.samples[i].timestamp;
            break;
        }
    }

    sol_free(ctx.samples);
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
bank_compute_accounts_lt_hash_locked(sol_bank_t* bank) {
    if (!bank || !bank->accounts_db) return;
    if (bank->accounts_lt_hash_computed) return;

    sol_lt_hash_t lt;
    sol_lt_hash_identity(&lt);

    if (sol_accounts_db_is_overlay(bank->accounts_db) && bank->accounts_lt_hash_base_valid) {
        lt = bank->accounts_lt_hash_base;
        accounts_lt_hash_delta_ctx_t ctx = {.out = &lt, .slot = bank->slot};

        /* Optionally dump delta accounts to a TSV file for debugging */
        const char* dump_dir = getenv("SOL_DUMP_DELTA_ACCOUNTS");
        const char* dump_slot_str = getenv("SOL_DUMP_DELTA_SLOT");
        uint64_t dump_slot = dump_slot_str ? strtoull(dump_slot_str, NULL, 10) : 0;
        bool should_dump = dump_dir && dump_dir[0] && (!dump_slot || bank->slot == dump_slot);
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
        }

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
            sol_log_info("lt_hash dump: slot=%lu base_checksum=%s final_checksum=%s",
                         (unsigned long)bank->slot, base_b58, final_b58);
        }

        sol_log_info("lt_hash delta: slot=%lu updated=%lu created=%lu removed=%lu unchanged=%lu lamports_stored=%lu data_len=%lu",
                     (unsigned long)bank->slot,
                     (unsigned long)ctx.n_updated,
                     (unsigned long)ctx.n_created,
                     (unsigned long)ctx.n_removed,
                     (unsigned long)ctx.n_unchanged,
                     (unsigned long)ctx.total_lamports_stored,
                     (unsigned long)ctx.total_data_len);

        /* Log sysvar-only lt_hash contribution for diagnostics */
        if (ctx.n_sysvar > 0) {
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
    } else {
        sol_accounts_db_iterate(bank->accounts_db, mix_account_into_accounts_lt_hash, &lt);

        /* For non-overlay banks, the full recompute is the only option. For
         * overlay banks, `accounts_lt_hash_base` must represent the parent
         * bank's accounts LtHash (copied at fork creation). */
        if (!sol_accounts_db_is_overlay(bank->accounts_db)) {
            bank->accounts_lt_hash_base = lt;
            bank->accounts_lt_hash_base_valid = true;
        }
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

    /* PoH starts from the parent blockhash (or restored latest blockhash).
     * This is distinct from the end-of-slot last entry hash. */
    bank->poh_hash = bank->blockhash;

    if (pthread_mutex_init(&bank->lock, NULL) != 0) {
        if (bank->owns_accounts_db) {
            sol_accounts_db_destroy(bank->accounts_db);
        }
        sol_free(bank);
        return NULL;
    }

    if (refresh_sysvar_accounts(bank, false) != SOL_OK) {
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

    /* DEBUG: verify System Program accessible in parent before fork */
    {
        sol_account_t* sp = sol_bank_load_account(parent, &SOL_SYSTEM_PROGRAM_ID);
        if (!sp) {
            sol_log_error("FORK-DEBUG: System Program NOT FOUND in parent bank (slot=%lu) accounts_db!",
                          (unsigned long)parent->slot);
        } else {
            sol_log_info("FORK-DEBUG: System Program in parent (slot=%lu): lamports=%lu exec=%d",
                         (unsigned long)parent->slot,
                         (unsigned long)sp->meta.lamports,
                         (int)sp->meta.executable);
            sol_account_destroy(sp);
        }
    }

    /* Create child bank with a forked AccountsDB view */
    sol_accounts_db_t* forked_db = sol_accounts_db_fork(parent->accounts_db);
    if (!forked_db) return NULL;

    sol_bank_t* child = sol_bank_new(slot, &parent->blockhash,
                                     forked_db, &parent->config);
    if (!child) {
        sol_accounts_db_destroy(forked_db);
        return NULL;
    }
    child->owns_accounts_db = true;

    /* Wire parent bank hash for voting/bank-hash computation. Parent is expected
     * to be frozen when used as an ancestor for replay. */
    sol_bank_compute_hash(parent, &child->parent_hash);
    child->parent_slot = parent->slot;

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

    pthread_mutex_unlock(&parent->lock);

    /* Sysvars like Clock/SlotHashes must advance for each derived bank.
     * Do this after wiring parent hash so SlotHashes can include parent bank
     * hash immediately (needed for vote verification). */
    if (refresh_sysvar_accounts(child, true) != SOL_OK) {
        sol_bank_destroy(child);
        return NULL;
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

void
sol_bank_accounts_lt_hash_checksum(sol_bank_t* bank, sol_blake3_t* out_checksum) {
    if (!bank || !out_checksum) return;

    pthread_mutex_lock(&bank->lock);
    bank_compute_accounts_lt_hash_locked(bank);
    sol_lt_hash_checksum(&bank->accounts_lt_hash, out_checksum);
    pthread_mutex_unlock(&bank->lock);
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

    pthread_mutex_lock((pthread_mutex_t*)&bank->lock);
    uint64_t count = bank->signature_count;
    pthread_mutex_unlock((pthread_mutex_t*)&bank->lock);

    return count;
}

void
sol_bank_set_signature_count(sol_bank_t* bank, uint64_t signature_count) {
    if (!bank) return;

    pthread_mutex_lock(&bank->lock);
    bank->signature_count = signature_count;
    bank->hash_computed = false;
    bank->accounts_delta_hash_computed = false;
    pthread_mutex_unlock(&bank->lock);
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

sol_account_t*
sol_bank_load_account(sol_bank_t* bank, const sol_pubkey_t* pubkey) {
    if (!bank || !pubkey) return NULL;
    return sol_accounts_db_load(bank->accounts_db, pubkey);
}

sol_account_t*
sol_bank_load_account_ex(sol_bank_t* bank, const sol_pubkey_t* pubkey,
                         sol_slot_t* out_stored_slot) {
    if (!bank || !pubkey) return NULL;
    return sol_accounts_db_load_ex(bank->accounts_db, pubkey, out_stored_slot);
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
    if (bank->frozen) return SOL_ERR_SHUTDOWN;

    /* Track BankHashStats for parity debugging.
     * Agave's BankHashStats::update() counts 0-lamport stores as "removed",
     * non-zero as "updated".  executable/data_len/lamports_stored are always
     * accumulated regardless of lamport value. */
    if (account->meta.lamports == 0) {
        bank->stats.num_removed_accounts++;
    } else {
        bank->stats.num_updated_accounts++;
    }
    bank->stats.num_lamports_stored += account->meta.lamports;
    bank->stats.total_data_len += account->meta.data_len;
    if (account->meta.executable) bank->stats.num_executable_accounts++;

    /* This can be called from within `sol_bank_process_transaction` while
     * holding `bank->lock` (e.g., native programs). Avoid deadlocking by
     * opportunistically taking the lock if available. */
    if (pthread_mutex_trylock(&bank->lock) == 0) {
        bank->hash_computed = false;
        bank->accounts_delta_hash_computed = false;
        bank->accounts_lt_hash_computed = false;
        sol_err_t err = sol_accounts_db_store_versioned(bank->accounts_db,
                                                        pubkey,
                                                        account,
                                                        bank->slot,
                                                        0);
        pthread_mutex_unlock(&bank->lock);
        return err;
    }

    bank->hash_computed = false;
    bank->accounts_delta_hash_computed = false;
    bank->accounts_lt_hash_computed = false;
    return sol_accounts_db_store_versioned(bank->accounts_db,
                                           pubkey,
                                           account,
                                           bank->slot,
                                           0);
}

static sol_err_t
bank_delete_account(sol_bank_t* bank, const sol_pubkey_t* pubkey) {
    if (!bank || !pubkey) return SOL_ERR_INVAL;
    if (bank->frozen) return SOL_ERR_SHUTDOWN;

    /* Track BankHashStats for parity debugging */
    bank->stats.num_removed_accounts++;

    if (pthread_mutex_trylock(&bank->lock) == 0) {
        bank->hash_computed = false;
        bank->accounts_delta_hash_computed = false;
        bank->accounts_lt_hash_computed = false;
        sol_err_t err = sol_accounts_db_delete_versioned(bank->accounts_db, pubkey, bank->slot, 0);
        pthread_mutex_unlock(&bank->lock);
        return err;
    }

    bank->hash_computed = false;
    bank->accounts_delta_hash_computed = false;
    bank->accounts_lt_hash_computed = false;
    return sol_accounts_db_delete_versioned(bank->accounts_db, pubkey, bank->slot, 0);
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
        sol_account_t* table_account = sol_accounts_db_load(bank->accounts_db, &lookups[li].table_key);
        if (!table_account) {
            return SOL_ERR_TX_SANITIZE;
        }

        if (!sol_pubkey_eq(&table_account->meta.owner, &SOL_ADDRESS_LOOKUP_TABLE_ID)) {
            sol_account_destroy(table_account);
            return SOL_ERR_TX_SANITIZE;
        }

        sol_alt_state_t state;
        sol_alt_state_init(&state);

        sol_err_t deser_err = sol_alt_deserialize(&state,
                                                  table_account->data,
                                                  (size_t)table_account->meta.data_len);
        sol_account_destroy(table_account);
        if (deser_err != SOL_OK) {
            sol_alt_state_free(&state);
            return SOL_ERR_TX_SANITIZE;
        }

        if (!sol_alt_is_active(&state, sol_bank_slot(bank))) {
            sol_alt_state_free(&state);
            return SOL_ERR_TX_SANITIZE;
        }

        for (uint16_t wi = 0; wi < lookups[li].writable_indices_len; wi++) {
            if ((uint32_t)writable_base + (uint32_t)writable_cursor >= out_cap) {
                sol_alt_state_free(&state);
                return SOL_ERR_OVERFLOW;
            }
            const sol_pubkey_t* addr =
                sol_alt_get_address(&state, lookups[li].writable_indices[wi]);
            if (!addr) {
                sol_alt_state_free(&state);
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
                sol_alt_state_free(&state);
                return SOL_ERR_OVERFLOW;
            }
            const sol_pubkey_t* addr =
                sol_alt_get_address(&state, lookups[li].readonly_indices[ri]);
            if (!addr) {
                sol_alt_state_free(&state);
                return SOL_ERR_TX_SANITIZE;
            }
            uint16_t out_idx = (uint16_t)(readonly_base + readonly_cursor);
            out_keys[out_idx] = *addr;
            out_signer[out_idx] = false;
            out_writable[out_idx] = false;
            readonly_cursor++;
        }

        sol_alt_state_free(&state);
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

static void
fill_invoke_sysvars(sol_invoke_context_t* ctx, const sol_bank_t* bank) {
    if (!ctx || !bank) {
        return;
    }

    sol_clock_t clock;
    sol_clock_init(&clock);
    bool have_clock = false;
    if (bank->accounts_db) {
        sol_account_t* clock_acct =
            sol_accounts_db_load(bank->accounts_db, &SOL_SYSVAR_CLOCK_ID);
        if (clock_acct && clock_acct->meta.data_len >= SOL_CLOCK_SIZE) {
            if (sol_clock_deserialize(&clock, clock_acct->data, clock_acct->meta.data_len) == SOL_OK) {
                have_clock = true;
            }
        }
        sol_account_destroy(clock_acct);
    }

    if (!have_clock) {
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

static sol_err_t
update_instructions_sysvar_account(sol_bank_t* bank,
                                   const sol_transaction_t* tx,
                                   uint16_t current_idx) {
    if (!bank || !tx) {
        return SOL_ERR_INVAL;
    }

    const sol_message_t* msg = &tx->message;
    const sol_pubkey_t* account_keys = msg->resolved_accounts_len
        ? msg->resolved_accounts : msg->account_keys;
    uint16_t account_keys_len = msg->resolved_accounts_len
        ? msg->resolved_accounts_len : (uint16_t)msg->account_keys_len;

    /* Compute demoted is_writable flags matching Agave's SanitizedMessage::is_writable().
     * Demotions: reserved account keys → not writable,
     *            program_id accounts → not writable (when upgradeable loader not present). */
    bool demoted_is_writable[SOL_MAX_MESSAGE_ACCOUNTS];

    bool upgradeable_loader_present = false;
    for (uint16_t k = 0; k < account_keys_len; k++) {
        if (sol_pubkey_eq(&account_keys[k], &SOL_BPF_LOADER_UPGRADEABLE_ID)) {
            upgradeable_loader_present = true;
            break;
        }
    }

    for (uint16_t i = 0; i < account_keys_len && i < SOL_MAX_MESSAGE_ACCOUNTS; i++) {
        bool raw_writable;
        if (msg->is_writable && i < account_keys_len) {
            raw_writable = msg->is_writable[i];
        } else {
            raw_writable = sol_message_is_writable_index(msg, (uint8_t)i);
        }
        demoted_is_writable[i] = raw_writable;
        if (!raw_writable) continue;
        /* Fee payer (index 0) is always writable — skip demotion */
        if (i == 0) continue;

        /* Demote reserved account keys */
        if (is_reserved_account_key(&account_keys[i])) {
            demoted_is_writable[i] = false;
            continue;
        }

        /* Demote program_id accounts when upgradeable loader not present */
        if (!upgradeable_loader_present) {
            for (uint8_t j = 0; j < msg->instructions_len; j++) {
                if (msg->instructions[j].program_id_index == (uint8_t)i) {
                    demoted_is_writable[i] = false;
                    break;
                }
            }
        }
    }

    uint8_t scratch[1];
    size_t needed = sizeof(scratch);
    sol_err_t err = sol_instructions_sysvar_serialize(tx, current_idx,
                        demoted_is_writable, account_keys_len, scratch, &needed);
    if (err != SOL_OK && err != SOL_ERR_INVAL) {
        return err;
    }

    uint8_t* data = sol_alloc(needed);
    if (!data) {
        return SOL_ERR_NOMEM;
    }

    size_t written = needed;
    err = sol_instructions_sysvar_serialize(tx, current_idx,
              demoted_is_writable, account_keys_len, data, &written);
    if (err == SOL_OK) {
        err = store_sysvar_account(bank, &SOL_SYSVAR_INSTRUCTIONS_ID, data, written);
    }

    sol_free(data);
    return err;
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
            if (!(same_len && same_data)) {
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
    if (overwrite_existing ||
        !sol_accounts_db_exists(bank->accounts_db, &SOL_SYSVAR_CLOCK_ID)) {
        sol_clock_t clock;
        sol_clock_init(&clock);
        sol_clock_t prev_clock;
        sol_clock_init(&prev_clock);
        bool have_prev_clock = load_visible_clock_sysvar(bank, &prev_clock);

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

            sol_log_info("CLOCK_DIAG: slot=%lu epoch=%lu unix_ts=%ld epoch_start_ts=%ld leader_sched_epoch=%lu have_median=%d",
                         (unsigned long)clock.slot,
                         (unsigned long)clock.epoch,
                         (long)clock.unix_timestamp,
                         (long)clock.epoch_start_timestamp,
                         (unsigned long)clock.leader_schedule_epoch,
                         (int)have_median);
        }

        uint8_t clock_data[SOL_CLOCK_SIZE];
        SOL_TRY(sol_clock_serialize(&clock, clock_data, sizeof(clock_data)));
        SOL_TRY(store_sysvar_account_if_needed(bank, &SOL_SYSVAR_CLOCK_ID,
                                               clock_data, sizeof(clock_data),
                                               overwrite_existing));
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
    if (overwrite_existing || !sol_accounts_db_exists(bank->accounts_db, &SOL_SYSVAR_SLOT_HASHES_ID)) {
        sol_slot_hashes_t slot_hashes;
        sol_slot_hashes_init(&slot_hashes);

        sol_account_t* slot_hashes_acct =
            sol_accounts_db_load(bank->accounts_db, &SOL_SYSVAR_SLOT_HASHES_ID);
        if (slot_hashes_acct) {
            sol_err_t sh_err = sol_slot_hashes_deserialize(
                &slot_hashes, slot_hashes_acct->data, slot_hashes_acct->meta.data_len);
            sol_account_destroy(slot_hashes_acct);
            if (sh_err != SOL_OK) {
                sol_slot_hashes_init(&slot_hashes);
            }
        }

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
        overwrite_existing &&
        bank->tick_height == (uint64_t)bank->slot * bank->config.ticks_per_slot;
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
static sol_err_t
execute_instruction(sol_bank_t* bank, const sol_transaction_t* tx,
                   const sol_compiled_instruction_t* instr,
                   uint8_t instruction_index,
                   const sol_compute_budget_t* compute_budget,
                   sol_compute_meter_t* compute_meter,
                   sol_instruction_trace_t* instruction_trace) {
    const sol_message_t* msg = &tx->message;
    const sol_pubkey_t* account_keys = tx->message.resolved_accounts_len
        ? tx->message.resolved_accounts
        : tx->message.account_keys;
    uint16_t account_keys_len = tx->message.resolved_accounts_len
        ? tx->message.resolved_accounts_len
        : (uint16_t)tx->message.account_keys_len;

    if (account_keys_len > UINT8_MAX) {
        return SOL_ERR_TX_TOO_LARGE;
    }

    bool local_is_writable[SOL_MAX_MESSAGE_ACCOUNTS];
    bool local_is_signer[SOL_MAX_MESSAGE_ACCOUNTS];
    const bool* is_writable = NULL;
    const bool* is_signer = NULL;

    /* Build is_writable from base flags, then apply Agave-compatible demotion.
     * Agave's SanitizedMessage::is_writable() demotes reserved account keys
     * (sysvars, builtins) and accounts used as program_id unless the
     * upgradeable loader is present.  Fee payer (index 0) is always writable. */
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

    /* Check if upgradeable loader is present in account keys */
    bool upgradeable_loader_present = false;
    for (uint16_t i = 0; i < account_keys_len; i++) {
        if (sol_pubkey_eq(&account_keys[i], &SOL_BPF_LOADER_UPGRADEABLE_ID)) {
            upgradeable_loader_present = true;
            break;
        }
    }

    /* Demote reserved keys and program IDs (skip fee payer at index 0) */
    for (uint16_t i = 1; i < account_keys_len; i++) {
        if (!local_is_writable[i]) continue;

        /* Demote reserved account keys (sysvars, builtins, native loader) */
        if (is_reserved_account_key(&account_keys[i])) {
            local_is_writable[i] = false;
            continue;
        }

        /* Demote accounts used as program_id when upgradeable loader not present */
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
        return SOL_ERR_PROGRAM_NOT_FOUND;
    }

    const sol_pubkey_t* program_id = &account_keys[instr->program_id_index];

    /* Build invoke context for native programs */
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
        .compute_budget = compute_budget,
        .compute_meter = compute_meter,
        .compute_units_accounted = 0,
        .transaction = tx,
        .current_instruction_index = instruction_index,
        .instruction_trace = instruction_trace,
    };
    fill_invoke_sysvars(&ctx, bank);

    return sol_program_execute(&ctx);
}

static void
rollback_snapshot_restore(sol_bank_t* bank,
                          const sol_transaction_t* tx,
                          sol_account_t* const* rollback_accounts,
                          const uint8_t* rollback_local_kinds,
                          size_t rollback_accounts_len,
                          sol_account_t* rollback_instructions_sysvar,
                          sol_accounts_db_local_kind_t rollback_instructions_sysvar_kind) {
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

    if (!overlay) {
        if (rollback_instructions_sysvar) {
            (void)sol_bank_store_account(bank,
                                         &SOL_SYSVAR_INSTRUCTIONS_ID,
                                         rollback_instructions_sysvar);
        } else {
            (void)bank_delete_account(bank, &SOL_SYSVAR_INSTRUCTIONS_ID);
        }
        return;
    }

    switch (rollback_instructions_sysvar_kind) {
        case SOL_ACCOUNTS_DB_LOCAL_ACCOUNT:
            if (rollback_instructions_sysvar) {
                (void)sol_bank_store_account(bank,
                                             &SOL_SYSVAR_INSTRUCTIONS_ID,
                                             rollback_instructions_sysvar);
            } else {
                (void)sol_accounts_db_clear_override(bank->accounts_db,
                                                    &SOL_SYSVAR_INSTRUCTIONS_ID);
            }
            break;
        case SOL_ACCOUNTS_DB_LOCAL_TOMBSTONE:
            (void)bank_delete_account(bank, &SOL_SYSVAR_INSTRUCTIONS_ID);
            break;
        case SOL_ACCOUNTS_DB_LOCAL_MISSING:
        default:
            (void)sol_accounts_db_clear_override(bank->accounts_db, &SOL_SYSVAR_INSTRUCTIONS_ID);
            break;
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
                       uint8_t* rollback_local_kinds,
                       sol_account_t* rollback_instructions_sysvar) {
    for (size_t i = 0; i < rollback_accounts_len; i++) {
        if (rollback_accounts && rollback_accounts[i]) {
            sol_account_destroy(rollback_accounts[i]);
        }
    }
    sol_free(rollback_accounts);
    sol_free(rollback_local_kinds);

    if (rollback_instructions_sysvar) {
        sol_account_destroy(rollback_instructions_sysvar);
    }
}

/* Debug: log the first N pre-validation rejections per bank */
static void
log_prevalidation_rejection(const sol_bank_t* bank,
                            const sol_transaction_t* tx,
                            const char* reason,
                            sol_err_t err) {
    uint64_t total_rejected =
        bank->stats.rejected_sanitize +
        bank->stats.rejected_duplicate +
        bank->stats.rejected_v0_resolve +
        bank->stats.rejected_compute_budget +
        bank->stats.rejected_blockhash +
        bank->stats.rejected_fee_payer_missing +
        bank->stats.rejected_insufficient_funds +
        bank->stats.rejected_signature;
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

    sol_log_info("prevalidation_reject: slot=%lu reason=%s err=%d sig=%s nsigs=%u ver=%s payer=%s blockhash=%s",
                 (unsigned long)bank->slot,
                 reason, (int)err,
                 sig_b58[0] ? sig_b58 : "?",
                 (unsigned)tx->signatures_len,
                 tx->message.version == SOL_MESSAGE_VERSION_V0 ? "v0" : "legacy",
                 payer_b58[0] ? payer_b58 : "?",
                 bh_b58[0] ? bh_b58 : "?");
}

sol_tx_result_t
sol_bank_process_transaction(sol_bank_t* bank, const sol_transaction_t* tx) {
    sol_tx_result_t result = {0};
    sol_compute_budget_t compute_budget = {0};
    sol_compute_meter_t compute_meter = {0};
    sol_account_t** rollback_accounts = NULL;
    size_t rollback_accounts_len = 0;
    sol_account_t* rollback_instructions_sysvar = NULL;
    uint8_t* rollback_local_kinds = NULL;
    sol_accounts_db_local_kind_t rollback_instructions_sysvar_kind = SOL_ACCOUNTS_DB_LOCAL_MISSING;
    bool resolved_override = false;
    const sol_pubkey_t* saved_resolved_accounts = NULL;
    uint16_t saved_resolved_accounts_len = 0;
    bool* saved_is_writable = NULL;
    bool* saved_is_signer = NULL;
    sol_pubkey_t resolved_accounts[SOL_MAX_MESSAGE_ACCOUNTS];
    bool resolved_is_writable[SOL_MAX_MESSAGE_ACCOUNTS];
    bool resolved_is_signer[SOL_MAX_MESSAGE_ACCOUNTS];
    sol_instruction_trace_t instruction_trace = {0};

    if (!bank || !tx) {
        result.status = SOL_ERR_INVAL;
        return result;
    }

    if (bank->frozen) {
        result.status = SOL_ERR_SHUTDOWN;
        return result;
    }

    pthread_mutex_lock(&bank->lock);
    bank->hash_computed = false;
    bank->accounts_delta_hash_computed = false;
    bank->accounts_lt_hash_computed = false;

    /* Ensure sysvar accounts exist. Bank creation paths already refresh sysvars
     * at slot boundaries; avoid recomputing stake-weighted timestamps on every
     * transaction. */
    if (!sol_accounts_db_exists(bank->accounts_db, &SOL_SYSVAR_CLOCK_ID)) {
        sol_err_t sysvar_err = refresh_sysvar_accounts(bank, false);
        if (sysvar_err != SOL_OK) {
            result.status = sysvar_err;
            bank->stats.transactions_failed++;
            goto unlock_and_return;
        }
    }

    bank->stats.transactions_processed++;

    /* Basic transaction validation */
    sol_err_t sanitize_err = sol_transaction_sanitize(tx);
    if (sanitize_err != SOL_OK) {
        result.status = sanitize_err;
        bank->stats.transactions_failed++;
        bank->stats.rejected_sanitize++;
        log_prevalidation_rejection(bank, tx, "sanitize", sanitize_err);
        goto unlock_and_return;
    }

    /* Reject duplicate transactions */
    const sol_signature_t* tx_sig = sol_transaction_signature(tx);
    if (tx_sig && tx_status_exists_locked(bank, tx_sig)) {
        result.status = SOL_ERR_TX_ALREADY_PROCESSED;
        bank->stats.transactions_failed++;
        bank->stats.rejected_duplicate++;
        log_prevalidation_rejection(bank, tx, "duplicate", SOL_ERR_TX_ALREADY_PROCESSED);
        goto unlock_and_return;
    }

    /* Agave's per-bank signature_count (hashed into the frozen bank-hash)
     * counts signatures for ALL non-duplicate sanitized transactions,
     * regardless of whether they pass subsequent pre-validation checks
     * (blockhash, fee payer, balance, etc.).  In Agave, signature_count
     * is computed from all SanitizedTransactions entering
     * load_and_execute_transactions, which is after dedup but before
     * blockhash/fee-payer/balance checks.  Precompile signature counts
     * are used for fee calculation but are *not* included here. */
    bank->signature_count += (uint64_t)tx->signatures_len;

    if (tx->message.version == SOL_MESSAGE_VERSION_V0) {
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
            bank->stats.transactions_failed++;
            bank->stats.rejected_v0_resolve++;
            log_prevalidation_rejection(bank, tx, "v0_resolve", resolve_err);
            goto unlock_and_return;
        }

        /* Our invoke context uses u8 lengths. Bail out if the message is too large. */
        if (resolved_len > UINT8_MAX) {
            result.status = SOL_ERR_TX_TOO_LARGE;
            bank->stats.transactions_failed++;
            bank->stats.rejected_v0_resolve++;
            goto unlock_and_return;
        }

        /* Validate compiled instruction indices against resolved account keys. */
        for (uint8_t i = 0; i < tx->message.instructions_len; i++) {
            const sol_compiled_instruction_t* ix = &tx->message.instructions[i];
            if (ix->program_id_index >= resolved_len) {
                result.status = SOL_ERR_TX_MALFORMED;
                bank->stats.transactions_failed++;
                bank->stats.rejected_v0_resolve++;
                goto unlock_and_return;
            }
            for (uint8_t j = 0; j < ix->account_indices_len; j++) {
                if (ix->account_indices[j] >= resolved_len) {
                    result.status = SOL_ERR_TX_MALFORMED;
                    bank->stats.transactions_failed++;
                    bank->stats.rejected_v0_resolve++;
                    goto unlock_and_return;
                }
            }
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

    /* 0. Parse compute budget and initialize compute meter.
     * In Agave, CB parse errors (duplicate instructions, deprecated type 0)
     * are checked AFTER fee charging.  Store the error and continue so that
     * fee deduction still occurs. */
    sol_err_t budget_err = sol_compute_budget_parse(&compute_budget, tx);
    sol_compute_meter_init(&compute_meter, compute_budget.compute_unit_limit);

    /* 1. Verify blockhash is recent */
    bool recent_ok = bank_is_blockhash_valid_locked(bank, &tx->message.recent_blockhash);
    uint64_t nonce_lamports_per_signature = 0;
    bool use_nonce_fee = false;
    if (!recent_ok) {
        if (bank_try_get_durable_nonce_fee_calculator(bank, tx, &nonce_lamports_per_signature)) {
            recent_ok = true;
            use_nonce_fee = true;
        }
    }
    if (!recent_ok) {
        result.status = SOL_ERR_TX_BLOCKHASH;
        bank->stats.transactions_failed++;
        bank->stats.rejected_blockhash++;
        log_prevalidation_rejection(bank, tx, "blockhash", SOL_ERR_TX_BLOCKHASH);
        goto unlock_and_return;
    }

    /* 2. Calculate fee (deterministic per blockhash). */
    uint64_t lamports_per_signature = use_nonce_fee
        ? nonce_lamports_per_signature
        : bank_lamports_per_signature_for_blockhash_locked(bank, &tx->message.recent_blockhash);
    uint64_t precompile_signatures = bank_count_precompile_signatures(tx);

    uint64_t signature_fee_count = (uint64_t)tx->signatures_len + precompile_signatures;
    uint64_t base_fee = lamports_per_signature * signature_fee_count;
    uint64_t priority_fee = sol_compute_budget_priority_fee(&compute_budget);
    result.fee = base_fee + priority_fee;

    /* 3. Get fee payer */
    const sol_pubkey_t* fee_payer = sol_message_fee_payer(&tx->message);
    if (!fee_payer) {
        result.status = SOL_ERR_TX_MALFORMED;
        bank->stats.transactions_failed++;
        bank->stats.rejected_fee_payer_missing++;
        goto unlock_and_return;
    }

    /* 4. Check fee payer can afford fee */
    sol_account_t* payer_account = sol_bank_load_account(bank, fee_payer);
    if (!payer_account) {
        result.status = SOL_ERR_TX_ACCOUNT_NOT_FOUND;
        bank->stats.transactions_failed++;
        bank->stats.rejected_fee_payer_missing++;
        /* Debug: trace the chain to understand why account is missing */
        char b58[45];
        sol_pubkey_to_base58(fee_payer, b58, sizeof(b58));
        sol_log_warn("FEE_PAYER_TRACE slot=%lu pubkey=%s",
                     (unsigned long)bank->slot, b58);
        sol_accounts_db_trace_load(bank->accounts_db, fee_payer);
        log_prevalidation_rejection(bank, tx, "fee_payer_missing", SOL_ERR_TX_ACCOUNT_NOT_FOUND);
        goto unlock_and_return;
    }

    if (payer_account->meta.lamports < result.fee) {
        result.status = SOL_ERR_TX_INSUFFICIENT_FUNDS;
        bank->stats.transactions_failed++;
        bank->stats.rejected_insufficient_funds++;
        log_prevalidation_rejection(bank, tx, "insufficient_funds", SOL_ERR_TX_INSUFFICIENT_FUNDS);
        sol_account_destroy(payer_account);
        goto unlock_and_return;
    }

    /* 5. Verify signatures */
    bank->stats.signatures_verified += tx->signatures_len;

    if (!bank_skip_signature_verify() &&
        !sol_transaction_verify_signatures(tx, NULL)) {
        result.status = SOL_ERR_TX_SIGNATURE;
        bank->stats.transactions_failed++;
        bank->stats.rejected_signature++;
        log_prevalidation_rejection(bank, tx, "signature", SOL_ERR_TX_SIGNATURE);
        sol_account_destroy(payer_account);
        goto unlock_and_return;
    }

    /* 5.5 Fix rent_epoch for fee payer.
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
            bank->stats.transactions_failed++;
            sol_account_destroy(payer_account);
            goto unlock_and_return;
        }
    }

    payer_account->meta.lamports -= result.fee;
    uint64_t expected_post_fee_lamports = payer_account->meta.lamports;
    (void)sol_bank_store_account(bank, fee_payer, payer_account);
    sol_account_destroy(payer_account);

    bank->stats.total_fees_collected += result.fee;
    bank->stats.total_priority_fees_collected += priority_fee;

    /* Check deferred compute budget parse error AFTER fee deduction.
     * In Agave, DuplicateInstruction / InvalidInstructionData from the CB
     * processor still charges the fee but skips execution. */
    if (budget_err != SOL_OK) {
        result.status = budget_err;
        bank->stats.transactions_failed++;
        bank->stats.rejected_compute_budget++;
        log_prevalidation_rejection(bank, tx, "compute_budget", budget_err);
        goto unlock_and_return;
    }

    if (bank_skip_instruction_exec()) {
        /* Debug/analysis mode: stop after fee charging and signature counting.
         * This preserves signature_count semantics and helps isolate early
         * validation errors without executing programs. */
        result.status = SOL_OK;
        bank->stats.transactions_succeeded++;
        goto unlock_and_return;
    }

    /* 6.5 Snapshot accounts for rollback (after fee deduction) */
    const sol_pubkey_t* tx_account_keys = tx->message.resolved_accounts_len
        ? tx->message.resolved_accounts
        : tx->message.account_keys;
    size_t tx_account_keys_len = tx->message.resolved_accounts_len
        ? (size_t)tx->message.resolved_accounts_len
        : (size_t)tx->message.account_keys_len;

    rollback_accounts_len = tx_account_keys_len;
    rollback_accounts = sol_calloc(rollback_accounts_len, sizeof(sol_account_t*));
    if (!rollback_accounts) {
        result.status = SOL_ERR_NOMEM;
        bank->stats.transactions_failed++;
        goto unlock_and_return;
    }

    bool overlay = sol_accounts_db_is_overlay(bank->accounts_db);
    if (overlay) {
        rollback_local_kinds = sol_calloc(rollback_accounts_len, sizeof(uint8_t));
        if (!rollback_local_kinds) {
            result.status = SOL_ERR_NOMEM;
            bank->stats.transactions_failed++;
            sol_free(rollback_accounts);
            rollback_accounts = NULL;
            goto unlock_and_return;
        }
    }

    for (size_t i = 0; i < rollback_accounts_len; i++) {
        if (!tx_account_keys || i >= tx_account_keys_len) {
            break;
        }
        const sol_pubkey_t* key = &tx_account_keys[i];
        if (!overlay) {
            rollback_accounts[i] = sol_accounts_db_load(bank->accounts_db, key);
            continue;
        }

        sol_account_t* local = NULL;
        sol_accounts_db_local_kind_t kind =
            sol_accounts_db_get_local_kind(bank->accounts_db, key, &local);
        rollback_local_kinds[i] = (uint8_t)kind;
        rollback_accounts[i] = (kind == SOL_ACCOUNTS_DB_LOCAL_ACCOUNT) ? local : NULL;

        (void)expected_post_fee_lamports; /* used by diagnostics when enabled */
    }

    if (!overlay) {
        rollback_instructions_sysvar =
            sol_accounts_db_load(bank->accounts_db, &SOL_SYSVAR_INSTRUCTIONS_ID);
    } else {
        rollback_instructions_sysvar_kind = sol_accounts_db_get_local_kind(
            bank->accounts_db, &SOL_SYSVAR_INSTRUCTIONS_ID, &rollback_instructions_sysvar);
        if (rollback_instructions_sysvar_kind != SOL_ACCOUNTS_DB_LOCAL_ACCOUNT) {
            rollback_instructions_sysvar = NULL;
        }
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
        if (!bank_message_is_writable_resolved_index(&tx->message, (uint8_t)ri))
            continue;
        sol_account_t* wa = sol_accounts_db_load(bank->accounts_db, &tx_account_keys[ri]);
        if (!wa || wa->meta.lamports == 0) {
            if (wa) sol_account_destroy(wa);
            continue;
        }
        if (wa->meta.rent_epoch != UINT64_MAX &&
            sol_account_is_rent_exempt(wa,
                                        bank->config.rent_per_byte_year,
                                        bank->config.rent_exemption_threshold)) {
            wa->meta.rent_epoch = UINT64_MAX;
            (void)sol_bank_store_account(bank, &tx_account_keys[ri], wa);
        }
        sol_account_destroy(wa);
    }

    /* 7. Execute instructions */
    for (uint8_t i = 0; i < tx->message.instructions_len; i++) {
        const sol_compiled_instruction_t* instr = &tx->message.instructions[i];

        sol_err_t instr_sysvar_err = update_instructions_sysvar_account(bank, tx, i);
        if (instr_sysvar_err != SOL_OK) {
            result.status = instr_sysvar_err;
            result.compute_units_used = compute_meter.consumed;
            bank->stats.compute_units_used += result.compute_units_used;
            bank->stats.transactions_failed++;
            /* Roll back all account writes from this transaction */
            rollback_snapshot_restore(bank, tx, rollback_accounts, rollback_local_kinds,
                                     rollback_accounts_len, rollback_instructions_sysvar,
                                     rollback_instructions_sysvar_kind);
            if (use_nonce_fee) advance_nonce_on_failure(bank, tx);

            /* Record failed transaction status */
            const sol_signature_t* sig = sol_transaction_signature(tx);
            if (sig) {
                pthread_mutex_unlock(&bank->lock);
                sol_bank_record_tx_status(bank, sig, result.status,
                                         result.fee, result.compute_units_used);
                pthread_mutex_lock(&bank->lock);
            }

            rollback_snapshot_free(rollback_accounts, rollback_accounts_len,
                                   rollback_local_kinds,
                                   rollback_instructions_sysvar);
            rollback_accounts = NULL;
            rollback_accounts_len = 0;
            rollback_instructions_sysvar = NULL;
            rollback_local_kinds = NULL;

            goto unlock_and_return;
        }

        sol_err_t instr_err = execute_instruction(bank, tx, instr, i, &compute_budget, &compute_meter, &instruction_trace);
        if (instr_err != SOL_OK) {
            result.status = instr_err;
            result.compute_units_used = compute_meter.consumed;
            bank->stats.compute_units_used += result.compute_units_used;
            bank->stats.transactions_failed++;

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
                sol_log_info("execution_failed: slot=%lu instr=%u program=%s err=%d(%s) "
                             "cu=%lu sig=%s",
                             (unsigned long)bank->slot, (unsigned)i, prog_b58,
                             instr_err, sol_err_str(instr_err),
                             (unsigned long)compute_meter.consumed,
                             sig_b58[0] ? sig_b58 : "none");
            }
            /* Roll back all account writes from this transaction */
            rollback_snapshot_restore(bank, tx, rollback_accounts, rollback_local_kinds,
                                     rollback_accounts_len, rollback_instructions_sysvar,
                                     rollback_instructions_sysvar_kind);
            if (use_nonce_fee) advance_nonce_on_failure(bank, tx);

            /* Record failed transaction status */
            const sol_signature_t* sig = sol_transaction_signature(tx);
            if (sig) {
                pthread_mutex_unlock(&bank->lock);
                sol_bank_record_tx_status(bank, sig, result.status,
                                         result.fee, result.compute_units_used);
                pthread_mutex_lock(&bank->lock);
            }

            rollback_snapshot_free(rollback_accounts, rollback_accounts_len,
                                   rollback_local_kinds,
                                   rollback_instructions_sysvar);
            rollback_accounts = NULL;
            rollback_accounts_len = 0;
            rollback_instructions_sysvar = NULL;
            rollback_local_kinds = NULL;

            goto unlock_and_return;
        }
    }

    /* Post-execution rent state transition check (InsufficientFundsForRent).
     * After all instructions execute successfully, verify that no writable
     * account transitioned into an invalid rent state.  Agave performs this
     * check in TransactionAccountStateInfo::verify_changes(). */
    {
        sol_err_t rent_err = SOL_OK;
        uint8_t rent_fail_index = 0;

        for (size_t ri = 0; ri < tx_account_keys_len; ri++) {
            if (!bank_message_is_writable_resolved_index(&tx->message, (uint8_t)ri))
                continue;

            /* Skip the incinerator account */
            if (sol_pubkey_eq(&tx_account_keys[ri], &SOL_INCINERATOR_ID))
                continue;

            /* Get pre-execution state from rollback snapshot.
             * In overlay mode, rollback_accounts[ri] is NULL when the
             * account was not in the local overlay before execution.
             * In that case, load the pre-state from the PARENT DB
             * (which includes changes from prior slots in the chain). */
            const sol_account_t* pre = rollback_accounts[ri];
            sol_account_t* pre_from_root = NULL;
            if (!pre && rollback_local_kinds &&
                rollback_local_kinds[ri] == (uint8_t)SOL_ACCOUNTS_DB_LOCAL_MISSING) {
                sol_accounts_db_t* parent_db = sol_accounts_db_get_parent(bank->accounts_db);
                pre_from_root = parent_db ? sol_accounts_db_load(parent_db, &tx_account_keys[ri]) : NULL;
                pre = pre_from_root;
            }
            uint64_t pre_lamports = pre ? pre->meta.lamports : 0;
            size_t   pre_data_len = pre ? pre->meta.data_len : 0;

            /* Get post-execution state from current accounts DB */
            sol_account_t* post = sol_accounts_db_load(bank->accounts_db,
                                                        &tx_account_keys[ri]);
            uint64_t post_lamports = post ? post->meta.lamports : 0;
            size_t   post_data_len = post ? post->meta.data_len : 0;

            uint64_t rent_per_byte = bank->config.rent_per_byte_year;
            uint64_t rent_thresh   = bank->config.rent_exemption_threshold;
            uint64_t pre_min = sol_account_rent_exempt_minimum(pre_data_len,
                                                               rent_per_byte,
                                                               rent_thresh);
            uint64_t post_min = sol_account_rent_exempt_minimum(post_data_len,
                                                                rent_per_byte,
                                                                rent_thresh);

            /* Determine pre and post rent states:
             *   Uninitialized = lamports == 0
             *   RentExempt    = lamports >= minimum
             *   RentPaying    = 0 < lamports < minimum */
            enum { RS_UNINIT, RS_RENT_PAYING, RS_RENT_EXEMPT } pre_state, post_state;
            if (pre_lamports == 0)           pre_state = RS_UNINIT;
            else if (pre_lamports >= pre_min) pre_state = RS_RENT_EXEMPT;
            else                              pre_state = RS_RENT_PAYING;

            if (post_lamports == 0)            post_state = RS_UNINIT;
            else if (post_lamports >= post_min) post_state = RS_RENT_EXEMPT;
            else                                post_state = RS_RENT_PAYING;

            /* Check transition validity:
             *   -> Uninitialized: always OK
             *   -> RentExempt:    always OK
             *   -> RentPaying:    only OK if was already RentPaying with same
             *                     data_size and lamports did not increase */
            bool transition_ok;
            if (post_state == RS_UNINIT || post_state == RS_RENT_EXEMPT) {
                transition_ok = true;
            } else {
                /* post_state == RS_RENT_PAYING */
                if (pre_state == RS_RENT_PAYING &&
                    post_data_len == pre_data_len &&
                    post_lamports <= pre_lamports) {
                    transition_ok = true;
                } else {
                    transition_ok = false;
                }
            }

            if (post) sol_account_destroy(post);
            if (pre_from_root) sol_account_destroy(pre_from_root);

            if (!transition_ok) {
                rent_err = SOL_ERR_TX_INSUFFICIENT_FUNDS_FOR_RENT;
                rent_fail_index = (uint8_t)ri;
                break;
            }
        }

        if (rent_err != SOL_OK) {
            result.status = rent_err;
            result.compute_units_used = compute_meter.consumed;
            bank->stats.compute_units_used += result.compute_units_used;
            bank->stats.transactions_failed++;

            {
                const sol_signature_t* rent_sig = sol_transaction_signature(tx);
                char rent_sig_b58[SOL_SIGNATURE_BASE58_LEN] = {0};
                if (rent_sig) sol_signature_to_base58(rent_sig, rent_sig_b58, sizeof(rent_sig_b58));
                char acct_b58[45] = {0};
                sol_pubkey_to_base58(&tx_account_keys[rent_fail_index], acct_b58, sizeof(acct_b58));
                /* Load pre/post for diagnostic */
                const sol_account_t* diag_pre = rollback_accounts[rent_fail_index];
                sol_account_t* diag_post = sol_accounts_db_load(bank->accounts_db,
                                                                 &tx_account_keys[rent_fail_index]);
                sol_log_info("rent_state_check_failed: slot=%lu account_index=%u sig=%s "
                             "account=%s pre_lamports=%lu pre_data_len=%zu "
                             "post_lamports=%lu post_data_len=%zu is_writable=%d",
                             (unsigned long)bank->slot, (unsigned)rent_fail_index,
                             rent_sig_b58[0] ? rent_sig_b58 : "none",
                             acct_b58,
                             diag_pre ? (unsigned long)diag_pre->meta.lamports : 0UL,
                             diag_pre ? diag_pre->meta.data_len : 0UL,
                             diag_post ? (unsigned long)diag_post->meta.lamports : 0UL,
                             diag_post ? diag_post->meta.data_len : 0UL,
                             (int)bank_message_is_writable_resolved_index(&tx->message,
                                                                          (uint8_t)rent_fail_index));
                if (diag_post) sol_account_destroy(diag_post);
            }

            /* Roll back all account writes from this transaction */
            rollback_snapshot_restore(bank, tx, rollback_accounts, rollback_local_kinds,
                                     rollback_accounts_len, rollback_instructions_sysvar,
                                     rollback_instructions_sysvar_kind);
            if (use_nonce_fee) advance_nonce_on_failure(bank, tx);

            /* Record failed transaction status */
            const sol_signature_t* sig = sol_transaction_signature(tx);
            if (sig) {
                pthread_mutex_unlock(&bank->lock);
                sol_bank_record_tx_status(bank, sig, result.status,
                                         result.fee, result.compute_units_used);
                pthread_mutex_lock(&bank->lock);
            }

            rollback_snapshot_free(rollback_accounts, rollback_accounts_len,
                                   rollback_local_kinds,
                                   rollback_instructions_sysvar);
            rollback_accounts = NULL;
            rollback_accounts_len = 0;
            rollback_instructions_sysvar = NULL;
            rollback_local_kinds = NULL;

            goto unlock_and_return;
        }
    }

    /* Success */
    result.status = SOL_OK;
    result.compute_units_used = compute_meter.consumed;
    bank->stats.compute_units_used += result.compute_units_used;
    bank->stats.transactions_succeeded++;

    /* Restore Instructions sysvar to pre-transaction state.
     * In Agave the Instructions sysvar is virtual (only available during
     * instruction execution) and never persists in the accounts DB.  Our
     * implementation stores it as a real account via
     * update_instructions_sysvar_account(), so we must clean it up after
     * the transaction to avoid polluting the lt_hash. */
    {
        bool overlay = rollback_local_kinds != NULL;
        if (!overlay) {
            if (rollback_instructions_sysvar) {
                (void)sol_bank_store_account(bank,
                                             &SOL_SYSVAR_INSTRUCTIONS_ID,
                                             rollback_instructions_sysvar);
            } else {
                (void)bank_delete_account(bank, &SOL_SYSVAR_INSTRUCTIONS_ID);
            }
        } else {
            switch (rollback_instructions_sysvar_kind) {
                case SOL_ACCOUNTS_DB_LOCAL_ACCOUNT:
                    if (rollback_instructions_sysvar) {
                        (void)sol_bank_store_account(bank,
                                                     &SOL_SYSVAR_INSTRUCTIONS_ID,
                                                     rollback_instructions_sysvar);
                    } else {
                        (void)sol_accounts_db_clear_override(bank->accounts_db,
                                                            &SOL_SYSVAR_INSTRUCTIONS_ID);
                    }
                    break;
                case SOL_ACCOUNTS_DB_LOCAL_TOMBSTONE:
                    (void)bank_delete_account(bank, &SOL_SYSVAR_INSTRUCTIONS_ID);
                    break;
                case SOL_ACCOUNTS_DB_LOCAL_MISSING:
                default:
                    (void)sol_accounts_db_clear_override(bank->accounts_db,
                                                        &SOL_SYSVAR_INSTRUCTIONS_ID);
                    break;
            }
        }
    }

    /* Per-transaction lamport conservation check (diagnostic).
     * Use the rollback snapshot for accounts that WERE in the overlay
     * (LOCAL_ACCOUNT), and load from parent DB for accounts that were
     * NOT in the overlay (LOCAL_MISSING). This avoids false positives
     * from pre-existing parent DB accounts. */
    {
        bool has_overlay = rollback_local_kinds != NULL;
        int128 pre_total = 0;
        int128 post_total = 0;
        for (size_t ci = 0; ci < rollback_accounts_len && ci < tx_account_keys_len; ci++) {
            uint64_t pre_lam;
            if (rollback_accounts[ci]) {
                pre_lam = rollback_accounts[ci]->meta.lamports;
            } else if (has_overlay && rollback_local_kinds[ci] == (uint8_t)SOL_ACCOUNTS_DB_LOCAL_MISSING) {
                /* Account was not in overlay before execution — load from PARENT DB
                 * (not root!) to get correct pre-lamports. The parent chain includes
                 * changes from prior slots. For successful txns (no rollback), the
                 * current overlay contains post-execution state, so we must skip it. */
                sol_accounts_db_t* parent_db = sol_accounts_db_get_parent(bank->accounts_db);
                sol_account_t* parent_acc = parent_db ? sol_accounts_db_load(parent_db, &tx_account_keys[ci]) : NULL;
                pre_lam = parent_acc ? parent_acc->meta.lamports : 0;
                if (parent_acc) sol_account_destroy(parent_acc);
            } else {
                pre_lam = 0;
            }
            pre_total += (int128)pre_lam;
            sol_account_t* post_acc = sol_accounts_db_load(bank->accounts_db, &tx_account_keys[ci]);
            uint64_t post_lam = post_acc ? post_acc->meta.lamports : 0;
            post_total += (int128)post_lam;
            if (post_acc) sol_account_destroy(post_acc);
        }
        int128 lamport_delta = post_total - pre_total;
        if (lamport_delta != 0) {
            const sol_signature_t* csig = sol_transaction_signature(tx);
            char csig_b58[SOL_SIGNATURE_BASE58_LEN] = {0};
            if (csig) sol_signature_to_base58(csig, csig_b58, sizeof(csig_b58));
            char fp_b58[SOL_PUBKEY_BASE58_LEN] = {0};
            sol_pubkey_to_base58(fee_payer, fp_b58, sizeof(fp_b58));
            sol_log_info("LAMPORT_VIOLATION: slot=%lu delta=%lld fee=%lu payer=%s sig=%s accounts=%zu",
                         (unsigned long)bank->slot, (long long)(int64_t)lamport_delta,
                         (unsigned long)result.fee, fp_b58,
                         csig_b58[0] ? csig_b58 : "none",
                         rollback_accounts_len);
            for (size_t ci = 0; ci < rollback_accounts_len && ci < tx_account_keys_len && ci < 32; ci++) {
                uint64_t pre_lam;
                const char* pre_src;
                if (rollback_accounts[ci]) {
                    pre_lam = rollback_accounts[ci]->meta.lamports;
                    pre_src = "clone";
                } else if (has_overlay && rollback_local_kinds[ci] == (uint8_t)SOL_ACCOUNTS_DB_LOCAL_MISSING) {
                    sol_accounts_db_t* parent_db2 = sol_accounts_db_get_parent(bank->accounts_db);
                    sol_account_t* parent_acc = parent_db2 ? sol_accounts_db_load(parent_db2, &tx_account_keys[ci]) : NULL;
                    pre_lam = parent_acc ? parent_acc->meta.lamports : 0;
                    if (parent_acc) sol_account_destroy(parent_acc);
                    pre_src = "parent";
                } else {
                    pre_lam = 0;
                    pre_src = has_overlay ? "tomb/0" : "noovl";
                }
                sol_account_t* post_acc = sol_accounts_db_load(bank->accounts_db, &tx_account_keys[ci]);
                uint64_t post_lam = post_acc ? post_acc->meta.lamports : 0;
                if (pre_lam != post_lam) {
                    char ak_b58[SOL_PUBKEY_BASE58_LEN] = {0};
                    sol_pubkey_to_base58(&tx_account_keys[ci], ak_b58, sizeof(ak_b58));
                    sol_log_info("  account[%zu] %s pre=%lu post=%lu diff=%lld src=%s",
                                ci, ak_b58, (unsigned long)pre_lam, (unsigned long)post_lam,
                                (long long)((int64_t)post_lam - (int64_t)pre_lam), pre_src);
                }
                if (post_acc) sol_account_destroy(post_acc);
            }
        }
    }

    /* Discard rollback snapshot */
    rollback_snapshot_free(rollback_accounts, rollback_accounts_len,
                           rollback_local_kinds,
                           rollback_instructions_sysvar);
    rollback_accounts = NULL;
    rollback_accounts_len = 0;
    rollback_instructions_sysvar = NULL;
    rollback_local_kinds = NULL;

    /* Record successful transaction status */
    const sol_signature_t* sig = sol_transaction_signature(tx);
    if (sig) {
        pthread_mutex_unlock(&bank->lock);
        sol_bank_record_tx_status(bank, sig, result.status,
                                 result.fee, result.compute_units_used);
        pthread_mutex_lock(&bank->lock);
    }

    goto unlock_and_return;

unlock_and_return:
    sol_instruction_trace_destroy(&instruction_trace);
    if (resolved_override) {
        sol_message_t* msg = (sol_message_t*)&tx->message;
        msg->resolved_accounts = saved_resolved_accounts;
        msg->resolved_accounts_len = saved_resolved_accounts_len;
        msg->is_writable = saved_is_writable;
        msg->is_signer = saved_is_signer;
    }

    /* Log per-transaction result for parity comparison.
     * Only enabled when SOL_LOG_TX_RESULTS env var is set (checked once). */
    {
        static int log_tx_results = -1;
        if (__builtin_expect(log_tx_results < 0, 0)) {
            const char* env = getenv("SOL_LOG_TX_RESULTS");
            log_tx_results = (env && env[0] && env[0] != '0') ? 1 : 0;
        }
        if (__builtin_expect(log_tx_results, 0)) {
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

    pthread_mutex_unlock(&bank->lock);
    return result;
}

sol_err_t
sol_bank_process_transactions(sol_bank_t* bank, const sol_transaction_t* txs,
                              size_t count, sol_tx_result_t* results) {
    if (!bank || !txs || !results) return SOL_ERR_INVAL;

    for (size_t i = 0; i < count; i++) {
        results[i] = sol_bank_process_transaction(bank, &txs[i]);
    }

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

    uint64_t plain_hashes = entry->num_hashes;
    const bool has_record = entry->num_transactions > 0;
    if (has_record && plain_hashes > 0) {
        /* One of the hashes is the record(mixin) hash. */
        plain_hashes -= 1;
    }

    while (plain_hashes > 0) {
        const uint64_t remaining = hashes_per_tick - hashes_in_tick;
        const uint64_t chunk = (plain_hashes < remaining) ? plain_hashes : remaining;

        for (uint64_t i = 0; i < chunk; i++) {
            sol_sha256_32bytes(current.bytes, current.bytes);
        }

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
    if (bank->frozen) return SOL_ERR_SHUTDOWN;

    /* Process transactions in entry */
    for (uint32_t i = 0; i < entry->num_transactions; i++) {
        sol_tx_result_t result = sol_bank_process_transaction(
            bank, &entry->transactions[i]);

        if (result.status != SOL_OK) {
            sol_log_debug("Transaction %u failed: %d", i, result.status);
            /* Continue processing other transactions */
        }
    }

    return bank_advance_poh_and_register_ticks(bank, entry);
}

sol_err_t
sol_bank_process_entries(sol_bank_t* bank, const sol_entry_batch_t* batch) {
    if (!bank || !batch) return SOL_ERR_INVAL;

    for (size_t i = 0; i < batch->num_entries; i++) {
        sol_err_t err = sol_bank_process_entry(bank, &batch->entries[i]);
        if (err != SOL_OK) {
            return err;
        }
    }

    return SOL_OK;
}

sol_err_t
sol_bank_register_tick(sol_bank_t* bank, const sol_hash_t* tick_hash) {
    if (!bank || !tick_hash) return SOL_ERR_INVAL;
    if (bank->frozen) return SOL_ERR_SHUTDOWN;

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
            sol_accounts_db_store(bank->accounts_db, &SOL_INCINERATOR_ID, &zero_acct);
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

void
sol_bank_freeze(sol_bank_t* bank) {
    if (!bank) return;

    pthread_mutex_lock(&bank->lock);

    /* Snapshot banks are already frozen; skip sysvar/fee updates.
     * Only child banks (overlay) need freeze-time updates. */
    if (sol_accounts_db_is_overlay(bank->accounts_db)) {
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

    bank->frozen = true;
    pthread_mutex_unlock(&bank->lock);
}

bool
sol_bank_is_frozen(const sol_bank_t* bank) {
    if (!bank) return false;

    pthread_mutex_lock((pthread_mutex_t*)&bank->lock);
    bool frozen = bank->frozen;
    pthread_mutex_unlock((pthread_mutex_t*)&bank->lock);

    return frozen;
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

        /* Best-effort: keep accounts_delta_hash available for debug logs, but
         * it is not part of the bank-hash inputs in modern Agave.
         * Only compute for overlay (child) banks; for non-overlay banks the
         * "delta" is the entire DB which is prohibitively expensive (~1B accts). */
        if (sol_accounts_db_is_overlay(bank->accounts_db)) {
            sol_hash_t accounts_delta_hash = {0};
            sol_accounts_db_hash_delta(bank->accounts_db, &accounts_delta_hash);
            bank->accounts_delta_hash = accounts_delta_hash;
            bank->accounts_delta_hash_computed = true;
        }

        bank->hash_computed = true;
    }

    *out_hash = bank->bank_hash;

    pthread_mutex_unlock(&bank->lock);
}

bool
sol_bank_get_accounts_delta_hash(sol_bank_t* bank, sol_hash_t* out_hash) {
    if (!bank || !out_hash) return false;

    pthread_mutex_lock(&bank->lock);
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

void
sol_bank_record_tx_status(sol_bank_t* bank,
                          const sol_signature_t* signature,
                          sol_err_t status,
                          uint64_t fee,
                          uint64_t compute_units) {
    if (!bank || !signature) return;

    /* Limit cache size */
    if (bank->tx_status_count >= SOL_TX_STATUS_CACHE_SIZE) {
        return;  /* Cache full, skip recording */
    }

    uint32_t bucket = signature_hash(signature);

    pthread_mutex_lock(&bank->lock);

    /* Check if already exists */
    sol_tx_status_node_t* node = bank->tx_status_buckets[bucket];
    while (node) {
        if (memcmp(&node->entry.signature, signature, sizeof(sol_signature_t)) == 0) {
            /* Update existing entry */
            node->entry.status = status;
            node->entry.fee = fee;
            node->entry.compute_units = compute_units;
            pthread_mutex_unlock(&bank->lock);
            return;
        }
        node = node->next;
    }

    /* Create new entry */
    node = sol_calloc(1, sizeof(sol_tx_status_node_t));
    if (!node) {
        pthread_mutex_unlock(&bank->lock);
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

    pthread_mutex_unlock(&bank->lock);
}

bool
sol_bank_get_tx_status(const sol_bank_t* bank,
                       const sol_signature_t* signature,
                       sol_tx_status_entry_t* out_status) {
    if (!bank || !signature) return false;

    uint32_t bucket = signature_hash(signature);

    pthread_mutex_lock((pthread_mutex_t*)&bank->lock);

    sol_tx_status_node_t* node = bank->tx_status_buckets[bucket];
    while (node) {
        if (memcmp(&node->entry.signature, signature, sizeof(sol_signature_t)) == 0) {
            if (out_status) {
                *out_status = node->entry;
            }
            pthread_mutex_unlock((pthread_mutex_t*)&bank->lock);
            return true;
        }
        node = node->next;
    }

    pthread_mutex_unlock((pthread_mutex_t*)&bank->lock);
    return false;
}

size_t
sol_bank_purge_tx_status(sol_bank_t* bank, sol_slot_t min_slot) {
    if (!bank) return 0;

    size_t removed = 0;

    pthread_mutex_lock(&bank->lock);

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

    pthread_mutex_unlock(&bank->lock);
    return removed;
}

size_t
sol_bank_tx_status_count(const sol_bank_t* bank) {
    if (!bank) return 0;
    return bank->tx_status_count;
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
