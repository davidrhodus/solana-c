/*
 * sol_replay.c - Replay Stage Implementation
 */

#include "sol_replay.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include "../entry/sol_entry.h"
#include "../runtime/sol_leader_schedule.h"
#include "../txn/sol_pubkey.h"
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>

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
};

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
        return;
    }

    sol_replayed_slot_t* entry = sol_calloc(1, sizeof(sol_replayed_slot_t));
    if (!entry) return;

    entry->slot = slot;
    entry->is_dead = is_dead;
    entry->variant_count = variant_count;
    entry->complete_variant_count = complete_variant_count;

    size_t idx = slot_hash(slot, replay->replayed_bucket_count);
    entry->next = replay->replayed_buckets[idx];
    replay->replayed_buckets[idx] = entry;
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
bank_frozen_log_enable_vote_parity(void) {
    static int cached = -1;
    if (cached >= 0) {
        return cached != 0;
    }

    const char* env = getenv("SOL_LOG_BANK_FROZEN_VOTE_PARITY");
    cached = (env && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    return cached != 0;
}

static void
log_bank_frozen(sol_bank_t* bank) {
    if (!bank || !sol_bank_is_frozen(bank)) return;

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
    if (sol_bank_get_accounts_delta_hash(bank, &accounts_delta_hash) &&
        !sol_hash_is_zero(&accounts_delta_hash)) {
        bytes32_to_base58(accounts_delta_hash.bytes,
                          accounts_delta_hash_b58,
                          sizeof(accounts_delta_hash_b58));
    }

    sol_blake3_t lt_checksum = {0};
    char lt_checksum_b58[SOL_PUBKEY_BASE58_LEN] = {0};
    if (bank_frozen_log_enable_lt_hash_checksum()) {
        sol_bank_accounts_lt_hash_checksum(bank, &lt_checksum);
        bytes32_to_base58(lt_checksum.bytes, lt_checksum_b58, sizeof(lt_checksum_b58));
    }

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
    }

    /* BankHashStats (compare with Agave's bank frozen stats) */
    sol_log_info("bank frozen: %lu stats: { num_updated_accounts: %lu, num_removed_accounts: %lu, num_lamports_stored: %lu, total_data_len: %lu, num_executable_accounts: %lu }",
                 (unsigned long)slot,
                 (unsigned long)bank_stats.num_updated_accounts,
                 (unsigned long)bank_stats.num_removed_accounts,
                 (unsigned long)bank_stats.num_lamports_stored,
                 (unsigned long)bank_stats.total_data_len,
                 (unsigned long)bank_stats.num_executable_accounts);
}

static void
log_bank_frozen_vote_parity(sol_replay_t* replay, sol_bank_t* bank) {
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
    sol_slot_t  target_slot;
    sol_hash_t* hashes;
    size_t      count;
    size_t      cap;
} bank_hash_list_t;

static bool
collect_bank_hashes_cb(sol_slot_t slot,
                       sol_slot_t parent_slot,
                       const sol_hash_t* bank_hash,
                       const sol_hash_t* parent_hash,
                       sol_bank_t* bank,
                       bool is_dead,
                       void* ctx) {
    (void)parent_slot;
    (void)parent_hash;

    bank_hash_list_t* list = (bank_hash_list_t*)ctx;
    if (!list || slot != list->target_slot) {
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

    /* Mark root slot as replayed */
    sol_slot_t root = sol_bank_forks_root_slot(bank_forks);
    uint32_t root_variants = (uint32_t)sol_blockstore_num_variants(blockstore, root);
    uint32_t root_complete = count_complete_variants(blockstore, root, root_variants);
    mark_replayed(replay, root, false, root_variants, root_complete);
    replay->stats.highest_replayed_slot = root;
    replay->highest_replayed_slot_atomic = root;

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

static sol_replay_result_t
replay_entries(sol_replay_t* replay,
               sol_bank_t* bank,
               sol_slot_t slot,
               const sol_entry_batch_t* batch) {
    if (!replay || !bank || !batch) {
        return SOL_REPLAY_DEAD;
    }

    /* Verify entry hash chain */
    const sol_hash_t* start_hash = sol_bank_blockhash(bank);

    sol_entry_verify_result_t verify = sol_entry_batch_verify(batch, start_hash);
    if (!verify.valid) {
        bool start_hash_mismatch = false;
        if (verify.failed_entry == 0 && batch->num_entries > 0) {
            /* If the batch verifies when starting from entry[0].hash, the
             * slot likely belongs to a different parent hash/fork. */
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
            if (tail_ok) {
                start_hash_mismatch = true;
            }
        }

        if (start_hash_mismatch) {
            sol_log_warn("Entry hash chain mismatch at start for slot %llu (likely wrong parent hash)",
                         (unsigned long long)slot);
            return SOL_REPLAY_INCOMPLETE;
        }

        sol_log_warn("Entry hash chain verification failed for slot %llu at entry %u",
                     (unsigned long long)slot, verify.failed_entry);
        return SOL_REPLAY_DEAD;
    }

    /* Process entries through bank */
    sol_err_t err = sol_bank_process_entries(bank, batch);
    if (err != SOL_OK) {
        sol_log_warn("Failed to process entries for slot %llu: %s",
                     (unsigned long long)slot, sol_err_str(err));
        return SOL_REPLAY_DEAD;
    }

    /* A slot is only valid once it reaches max tick height. */
    if (!sol_bank_has_full_ticks(bank)) {
        sol_log_warn("Slot %llu did not reach max tick height (tick_height=%llu max_tick_height=%llu)",
                     (unsigned long long)slot,
                     (unsigned long long)sol_bank_tick_height(bank),
                     (unsigned long long)sol_bank_max_tick_height(bank));
        return SOL_REPLAY_INCOMPLETE;
    }

    /* Best-effort transaction signature indexing for RPC queries. */
    if (replay->blockstore) {
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

    replay->stats.entries_processed += batch->num_entries;

    return SOL_REPLAY_SUCCESS;
}

sol_replay_result_t
sol_replay_slot(sol_replay_t* replay, sol_slot_t slot,
                sol_replay_slot_info_t* info) {
    if (!replay) return SOL_REPLAY_DEAD;

    pthread_mutex_lock(&replay->lock);

    /* Initialize info */
    if (info) {
        memset(info, 0, sizeof(sol_replay_slot_info_t));
        info->slot = slot;
    }

    sol_replayed_slot_t* replayed = find_replayed(replay, slot);
    bool previously_replayed = (replayed != NULL);
    bool previously_success = (replayed != NULL) && !replayed->is_dead;

    /* Fast-path: if a slot was already successfully replayed, never replay it
     * again.  Replay results are deterministic for a given parent bank and
     * transaction set, so new block variants (duplicate shreds) cannot change
     * the outcome.  Re-replaying was causing 5x duplicate work because the
     * blockstore can accumulate up to 5 variants per slot. */
    if (previously_success) {
        if (info) {
            info->result = SOL_REPLAY_DUPLICATE;
        }
        pthread_mutex_unlock(&replay->lock);
        return SOL_REPLAY_DUPLICATE;
    }

    /* If a new block variant shows up later (duplicate slot), or a previously
     * incomplete variant becomes complete, we want to replay again to insert
     * additional candidate banks. */
    uint32_t current_variants = (uint32_t)sol_blockstore_num_variants(replay->blockstore, slot);
    uint32_t current_complete_variants =
        count_complete_variants(replay->blockstore, slot, current_variants);

    bool has_new_variants =
        replayed && current_variants > replayed->variant_count && current_variants > 0;
    bool has_new_complete_variants =
        replayed && current_complete_variants > replayed->complete_variant_count;

    bool has_new_work = has_new_variants || has_new_complete_variants;

    /* Fast-path: already replayed (dead) and no new variants to consider. */
    if (replayed && !has_new_work) {
        if (info) {
            info->result = SOL_REPLAY_DEAD;
        }
        pthread_mutex_unlock(&replay->lock);
        return SOL_REPLAY_DEAD;
    }

    /* Check if slot is complete in blockstore */
    if (!sol_blockstore_is_slot_complete(replay->blockstore, slot)) {
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
        if (!sol_bank_has_full_ticks(existing_bank)) {
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

    /* Find a complete block variant to learn the parent slot. */
    size_t num_variants = current_variants ? current_variants :
                         sol_blockstore_num_variants(replay->blockstore, slot);
    if (num_variants == 0) {
        if (info) info->result = SOL_REPLAY_DEAD;
        pthread_mutex_unlock(&replay->lock);
        return SOL_REPLAY_DEAD;
    }

    sol_block_t* first_block = NULL;
    uint32_t first_variant_id = 0;
    for (uint32_t variant_id = 0; variant_id < num_variants; variant_id++) {
        sol_block_t* block = sol_blockstore_get_block_variant(replay->blockstore, slot, variant_id);
        if (!block) continue;
        if (!block->data || block->data_len == 0) {
            sol_block_destroy(block);
            continue;
        }
        first_block = block;
        first_variant_id = variant_id;
        break;
    }

    if (!first_block) {
        if (info) info->result = SOL_REPLAY_DEAD;
        pthread_mutex_unlock(&replay->lock);
        return SOL_REPLAY_DEAD;
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
    bool parent_available = false;
    if (parent_slot == slot) { /* Root slot has parent = self */
        parent_available = true;
    } else if (sol_replay_has_frozen_bank(replay, parent_slot)) {
        parent_available = true;
    } else {
        sol_replayed_slot_t* parent_replayed = find_replayed(replay, parent_slot);
        if (parent_replayed && !parent_replayed->is_dead) {
            parent_available = true;
        }
    }

    if (!parent_available) {
        /* Parent not available yet - add to pending */
        sol_pending_slot_t* pending = sol_calloc(1, sizeof(sol_pending_slot_t));
        if (pending) {
            pending->slot = slot;
            pending->parent_slot = parent_slot;
            pending->next = replay->pending_slots;
            replay->pending_slots = pending;
            replay->pending_count++;
        }

        if (info) info->result = SOL_REPLAY_PARENT_MISSING;
        sol_block_destroy(first_block);
        pthread_mutex_unlock(&replay->lock);
        return SOL_REPLAY_PARENT_MISSING;
    }

    /* Gather all parent bank candidates (slot, bank_hash) for replay. */
    bank_hash_list_t parents = {
        .target_slot = parent_slot,
        .hashes = NULL,
        .count = 0,
        .cap = 0,
    };

    sol_bank_forks_iterate(replay->bank_forks, collect_bank_hashes_cb, &parents);
    if (parents.count == 0) {
        sol_free(parents.hashes);
        sol_block_destroy(first_block);
        if (info) info->result = SOL_REPLAY_DEAD;
        pthread_mutex_unlock(&replay->lock);
        return SOL_REPLAY_DEAD;
    }

    uint64_t start_time = get_time_ns();

    bool any_success = false;
    bool info_set = false;
    bool any_parsed = false;
    bool any_incomplete = false;
    bool stop_after_first_success = !replay->config.replay_all_variants;
    bool stop_replay = false;

    /* Replay all complete block variants against all parent bank candidates. */
    for (uint32_t variant_id = 0; variant_id < num_variants; variant_id++) {
        sol_block_t* block = NULL;
        if (variant_id == first_variant_id) {
            block = first_block;
            first_block = NULL;
        } else {
            block = sol_blockstore_get_block_variant(replay->blockstore, slot, variant_id);
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

        sol_err_t perr = sol_entry_batch_parse(batch, block->data, block->data_len);
        if (perr != SOL_OK) {
            sol_log_warn("Failed to parse entries for slot %llu (variant %u): %s",
                         (unsigned long long)slot, (unsigned)variant_id, sol_err_str(perr));
            sol_entry_batch_destroy(batch);
            sol_block_destroy(block);

            /* Robustness: if the slot cache assembled a corrupt block, retry
             * using the persisted RocksDB read path before dropping the variant. */
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

            sol_err_t perr2 = sol_entry_batch_parse(batch, block->data, block->data_len);
            if (perr2 != SOL_OK) {
                sol_log_warn("Failed to parse entries for slot %llu (variant %u) from RocksDB: %s",
                             (unsigned long long)slot, (unsigned)variant_id, sol_err_str(perr2));
                sol_entry_batch_destroy(batch);
                sol_block_destroy(block);
                continue;
            }
        }

        any_parsed = true;

        if (info && !info_set) {
            info->num_entries = batch->num_entries;
            info->num_transactions = sol_entry_batch_transaction_count(batch);
            info_set = true;
        }

        for (size_t i = 0; i < parents.count; i++) {
            sol_bank_t* parent_bank =
                sol_bank_forks_get_hash(replay->bank_forks, parent_slot, &parents.hashes[i]);
            if (!parent_bank) continue;

            sol_bank_t* bank = sol_bank_new_from_parent(parent_bank, slot);
            if (!bank) {
                sol_log_error("Failed to create bank for slot %llu (parent=%llu)",
                              (unsigned long long)slot, (unsigned long long)parent_slot);
                continue;
            }

            if (replay->leader_schedule) {
                const sol_pubkey_t* leader =
                    sol_leader_schedule_get_leader(replay->leader_schedule, slot);
                if (leader && !sol_pubkey_is_zero(leader)) {
                    sol_bank_set_fee_collector(bank, leader);
                }
            }

            sol_replay_result_t r = replay_entries(replay, bank, slot, batch);
            if (r == SOL_REPLAY_SUCCESS) {
                sol_bank_freeze(bank);

                sol_err_t ierr = sol_bank_forks_insert(replay->bank_forks, bank);
                if (ierr == SOL_OK) {
                    any_success = true;
                    log_bank_frozen(bank);
                    log_bank_frozen_vote_parity(replay, bank);
                    replay_set_highest_replayed_locked(replay, slot);
                    if (stop_after_first_success) {
                        stop_replay = true;
                        break;
                    }

                    sol_bank_stats_t bank_stats;
                    sol_bank_stats(bank, &bank_stats);
                    replay->stats.transactions_succeeded += bank_stats.transactions_succeeded;
                    replay->stats.transactions_failed += bank_stats.transactions_failed;
                } else {
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

        sol_entry_batch_destroy(batch);
        sol_block_destroy(block);

        if (stop_replay) {
            break;
        }
    }

    if (first_block) {
        sol_block_destroy(first_block);
        first_block = NULL;
    }

    uint64_t elapsed = get_time_ns() - start_time;
    if (info) {
        info->replay_time_ns = elapsed;
    }
    replay->stats.total_replay_time_ns += elapsed;

    sol_free(parents.hashes);

    uint32_t observed_variants = (uint32_t)num_variants;
    uint32_t observed_complete_variants =
        count_complete_variants(replay->blockstore, slot, observed_variants);

    sol_replay_result_t result = SOL_REPLAY_DEAD;
    if (any_success) {
        result = SOL_REPLAY_SUCCESS;
        mark_replayed(replay, slot, false, observed_variants, observed_complete_variants);
        if (!previously_success) {
            replay->stats.slots_replayed++;
        }
        replay_set_highest_replayed_locked(replay, slot);
    } else {
        /* If we already have a valid bank for this slot, don't mark the slot
         * dead just because a new duplicate variant failed to replay. */
        if (previously_success) {
            result = SOL_REPLAY_DUPLICATE;
            mark_replayed(replay, slot, false, observed_variants, observed_complete_variants);
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
            result = SOL_REPLAY_DEAD;
            mark_replayed(replay, slot, true, observed_variants, observed_complete_variants);
            sol_bank_forks_mark_dead(replay->bank_forks, slot);
            if (!previously_replayed) {
                replay->stats.slots_dead++;
            }
        }
    }

    if (info) {
        info->result = result;
    }

    /* Invoke callback */
    if (replay->callback) {
        replay->callback(slot, result, replay->callback_ctx);
    }

    pthread_mutex_unlock(&replay->lock);
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
            sol_blockstore_is_slot_complete(replay->blockstore, current)) {

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

        sol_replayed_slot_t* parent_entry = find_replayed(replay, pending->parent_slot);
        if (parent_entry && !parent_entry->is_dead) {
            /* Parent available, try to replay */
            *prev_ptr = next;
            sol_free(pending);
            replay->pending_count--;

            pthread_mutex_unlock(&replay->lock);

            sol_replay_result_t result = sol_replay_slot(replay, pending->slot, NULL);
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
    pthread_mutex_unlock(&replay->lock);

    /* Once a slot has been successfully replayed (frozen), it should never
       be re-replayed.  New blockstore variants from continued shred reception
       do not change the deterministic replay result. */
    return has_entry && !is_dead;
}

typedef struct {
    sol_slot_t target_slot;
    bool       found;
} replay_has_frozen_bank_ctx_t;

static bool
replay_has_frozen_bank_cb(sol_slot_t slot,
                          sol_slot_t parent_slot,
                          const sol_hash_t* bank_hash,
                          const sol_hash_t* parent_hash,
                          sol_bank_t* bank,
                          bool is_dead,
                          void* ctx) {
    (void)parent_slot;
    (void)bank_hash;
    (void)parent_hash;

    replay_has_frozen_bank_ctx_t* c = (replay_has_frozen_bank_ctx_t*)ctx;
    if (!c || slot != c->target_slot) {
        return true;
    }

    if (!is_dead && bank && sol_bank_is_frozen(bank)) {
        c->found = true;
        return false; /* stop iteration early */
    }

    return true;
}

bool
sol_replay_has_frozen_bank(sol_replay_t* replay, sol_slot_t slot) {
    if (!replay) return false;

    replay_has_frozen_bank_ctx_t ctx = {
        .target_slot = slot,
        .found = false,
    };

    sol_bank_forks_iterate(replay->bank_forks, replay_has_frozen_bank_cb, &ctx);
    return ctx.found;
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
