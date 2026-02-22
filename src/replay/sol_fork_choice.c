/*
 * sol_fork_choice.c - Fork Choice Implementation
 *
 * Implements the heaviest subtree fork choice algorithm.
 */

#include "sol_fork_choice.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include "../txn/sol_pubkey.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

static bool
fork_choice_log_vote_hash_mismatch_enabled(void) {
    static int enabled = -1;
    if (enabled != -1) return enabled != 0;

    const char* env = getenv("SOL_FORK_CHOICE_LOG_VOTE_HASH_MISMATCH");
    if (!env || env[0] == '\0') {
        enabled = 0;
        return false;
    }

    while (*env && isspace((unsigned char)*env)) env++;
    if (*env == '\0') {
        enabled = 1;
        return true;
    }

    if (env[0] == '0') {
        enabled = 0;
        return false;
    }
    if (env[0] == 'n' || env[0] == 'N') {
        enabled = 0;
        return false;
    }
    if (env[0] == 'f' || env[0] == 'F') {
        enabled = 0;
        return false;
    }

    enabled = 1;
    return true;
}

static sol_slot_t g_vote_hash_mismatch_last_slot = 0;
static uint32_t g_vote_hash_mismatch_logged = 0;

/*
 * Vote entry for tracking validator votes
 */
typedef struct sol_vote_entry {
    sol_pubkey_t            validator;
    sol_slot_t              voted_slot;
    sol_hash_t              voted_hash;
    uint64_t                stake;
    struct sol_vote_entry*  next;
} sol_vote_entry_t;

/*
 * Slot stake entry
 */
typedef struct sol_stake_entry {
    sol_slot_t              slot;
    sol_hash_t              bank_hash;
    uint64_t                direct_stake;   /* Stake voting directly for this slot */
    uint64_t                subtree_stake;  /* Total stake in subtree (cached) */
    uint32_t                vote_count;
    struct sol_stake_entry* next;
} sol_stake_entry_t;

/*
 * Fork choice structure
 */
struct sol_fork_choice {
    sol_fork_choice_config_t    config;
    sol_bank_forks_t*           bank_forks;

    /* Vote tracking by validator (hash table) */
    sol_vote_entry_t**          vote_buckets;
    size_t                      vote_bucket_count;
    size_t                      voter_count;

    /* Stake by slot (hash table) */
    sol_stake_entry_t**         stake_buckets;
    size_t                      stake_bucket_count;

    /* Totals */
    uint64_t                    total_stake;

    /* Root slot */
    sol_slot_t                  root_slot;
    sol_hash_t                  root_hash;

    /* Cache validity */
    bool                        subtree_cache_valid;
    size_t                      cached_bank_count;
    sol_slot_t                  cached_best_slot;
    sol_hash_t                  cached_best_hash;

    /* Thread safety */
    pthread_rwlock_t            lock;
};

/*
 * Hash functions
 */
static size_t
pubkey_hash(const sol_pubkey_t* pubkey, size_t bucket_count) {
    uint64_t h;
    memcpy(&h, pubkey->bytes, 8);
    return (size_t)(h % bucket_count);
}

static size_t
stake_key_hash(sol_slot_t slot, const sol_hash_t* bank_hash, size_t bucket_count) {
    uint64_t h = 0;
    if (bank_hash) {
        memcpy(&h, bank_hash->bytes, sizeof(h));
    }
    return (size_t)((slot ^ h) % bucket_count);
}

/*
 * Find vote entry for validator
 */
static sol_vote_entry_t*
find_vote(sol_fork_choice_t* fc, const sol_pubkey_t* validator) {
    size_t idx = pubkey_hash(validator, fc->vote_bucket_count);
    sol_vote_entry_t* entry = fc->vote_buckets[idx];

    while (entry) {
        if (sol_pubkey_eq(&entry->validator, validator)) {
            return entry;
        }
        entry = entry->next;
    }

    return NULL;
}

/*
 * Find or create stake entry for slot
 */
static sol_stake_entry_t*
find_or_create_stake(sol_fork_choice_t* fc, sol_slot_t slot, const sol_hash_t* bank_hash) {
    sol_hash_t zero = {0};
    if (!bank_hash) {
        bank_hash = &zero;
    }

    size_t idx = stake_key_hash(slot, bank_hash, fc->stake_bucket_count);
    sol_stake_entry_t* entry = fc->stake_buckets[idx];

    while (entry) {
        if (entry->slot == slot &&
            memcmp(entry->bank_hash.bytes, bank_hash->bytes, SOL_HASH_SIZE) == 0) {
            return entry;
        }
        entry = entry->next;
    }

    /* Create new entry */
    entry = sol_calloc(1, sizeof(sol_stake_entry_t));
    if (!entry) return NULL;

    entry->slot = slot;
    entry->bank_hash = *bank_hash;
    entry->next = fc->stake_buckets[idx];
    fc->stake_buckets[idx] = entry;

    return entry;
}

/*
 * Find stake entry for slot
 */
static sol_stake_entry_t*
find_stake(sol_fork_choice_t* fc, sol_slot_t slot, const sol_hash_t* bank_hash) {
    sol_hash_t zero = {0};
    if (!bank_hash) {
        bank_hash = &zero;
    }

    size_t idx = stake_key_hash(slot, bank_hash, fc->stake_bucket_count);
    sol_stake_entry_t* entry = fc->stake_buckets[idx];

    while (entry) {
        if (entry->slot == slot &&
            memcmp(entry->bank_hash.bytes, bank_hash->bytes, SOL_HASH_SIZE) == 0) {
            return entry;
        }
        entry = entry->next;
    }

    return NULL;
}

sol_fork_choice_t*
sol_fork_choice_new(sol_bank_forks_t* bank_forks,
                    const sol_fork_choice_config_t* config) {
    sol_fork_choice_t* fc = sol_calloc(1, sizeof(sol_fork_choice_t));
    if (!fc) return NULL;

    if (config) {
        fc->config = *config;
    } else {
        fc->config = (sol_fork_choice_config_t)SOL_FORK_CHOICE_CONFIG_DEFAULT;
    }

    fc->bank_forks = bank_forks;

    /* Initialize vote hash table */
    fc->vote_bucket_count = fc->config.max_votes / 4;
    if (fc->vote_bucket_count < 16) fc->vote_bucket_count = 16;

    fc->vote_buckets = sol_calloc(fc->vote_bucket_count, sizeof(sol_vote_entry_t*));
    if (!fc->vote_buckets) {
        sol_free(fc);
        return NULL;
    }

    /* Initialize stake hash table */
    fc->stake_bucket_count = 256;
    fc->stake_buckets = sol_calloc(fc->stake_bucket_count, sizeof(sol_stake_entry_t*));
    if (!fc->stake_buckets) {
        sol_free(fc->vote_buckets);
        sol_free(fc);
        return NULL;
    }

    if (pthread_rwlock_init(&fc->lock, NULL) != 0) {
        sol_free(fc->stake_buckets);
        sol_free(fc->vote_buckets);
        sol_free(fc);
        return NULL;
    }

    if (bank_forks) {
        fc->root_slot = sol_bank_forks_root_slot(bank_forks);
        sol_bank_t* root_bank = sol_bank_forks_root(bank_forks);
        if (root_bank) {
            sol_bank_compute_hash(root_bank, &fc->root_hash);
        } else {
            memset(&fc->root_hash, 0, sizeof(fc->root_hash));
        }
        fc->cached_bank_count = sol_bank_forks_count(bank_forks);
    }

    fc->cached_best_slot = fc->root_slot;
    fc->cached_best_hash = fc->root_hash;

    return fc;
}

void
sol_fork_choice_destroy(sol_fork_choice_t* fc) {
    if (!fc) return;

    /* Free vote entries */
    for (size_t i = 0; i < fc->vote_bucket_count; i++) {
        sol_vote_entry_t* entry = fc->vote_buckets[i];
        while (entry) {
            sol_vote_entry_t* next = entry->next;
            sol_free(entry);
            entry = next;
        }
    }
    sol_free(fc->vote_buckets);

    /* Free stake entries */
    for (size_t i = 0; i < fc->stake_bucket_count; i++) {
        sol_stake_entry_t* entry = fc->stake_buckets[i];
        while (entry) {
            sol_stake_entry_t* next = entry->next;
            sol_free(entry);
            entry = next;
        }
    }
    sol_free(fc->stake_buckets);

    pthread_rwlock_destroy(&fc->lock);
    sol_free(fc);
}

sol_err_t
sol_fork_choice_record_vote(sol_fork_choice_t* fc,
                            const sol_pubkey_t* validator,
                            sol_slot_t slot,
                            uint64_t stake) {
    sol_hash_t bank_hash = {0};
    if (fc && fc->bank_forks) {
        sol_bank_t* bank = sol_bank_forks_get(fc->bank_forks, slot);
        if (bank) {
            sol_bank_compute_hash(bank, &bank_hash);
        }
    }
    return sol_fork_choice_record_vote_hash(fc, validator, slot, &bank_hash, stake);
}

sol_err_t
sol_fork_choice_record_vote_hash(sol_fork_choice_t* fc,
                                 const sol_pubkey_t* validator,
                                 sol_slot_t slot,
                                 const sol_hash_t* bank_hash,
                                 uint64_t stake) {
    if (!fc || !validator) return SOL_ERR_INVAL;
    if (!bank_hash) return SOL_ERR_INVAL;

    pthread_rwlock_wrlock(&fc->lock);

    /* Ignore votes for slots before root */
    if (slot < fc->root_slot) {
        pthread_rwlock_unlock(&fc->lock);
        return SOL_OK;
    }

    if (fork_choice_log_vote_hash_mismatch_enabled() &&
        fc->bank_forks &&
        !sol_hash_is_zero(bank_hash)) {
        /* When we have already replayed (frozen) a bank at this slot, a vote
         * for an unknown bank hash is a strong parity signal: either we are on
         * the other duplicate-slot fork, or our bank-hash inputs differ. */
        sol_bank_t* have = sol_bank_forks_get_hash(fc->bank_forks, slot, bank_hash);
        if (!have) {
            sol_bank_t* local = sol_bank_forks_get(fc->bank_forks, slot);
            if (local && sol_bank_is_frozen(local)) {
                sol_hash_t local_hash = {0};
                sol_bank_compute_hash(local, &local_hash);
                if (memcmp(local_hash.bytes, bank_hash->bytes, SOL_HASH_SIZE) != 0) {
                    if (g_vote_hash_mismatch_logged < 20 && slot != g_vote_hash_mismatch_last_slot) {
                        char vote_pk_b58[SOL_PUBKEY_BASE58_LEN] = {0};
                        char voted_hash_b58[SOL_PUBKEY_BASE58_LEN] = {0};
                        char local_hash_b58[SOL_PUBKEY_BASE58_LEN] = {0};
                        (void)sol_pubkey_to_base58(validator, vote_pk_b58, sizeof(vote_pk_b58));
                        (void)sol_pubkey_to_base58((const sol_pubkey_t*)bank_hash,
                                                   voted_hash_b58,
                                                   sizeof(voted_hash_b58));
                        (void)sol_pubkey_to_base58((const sol_pubkey_t*)&local_hash,
                                                   local_hash_b58,
                                                   sizeof(local_hash_b58));
                        sol_log_warn("Vote bank-hash mismatch: slot=%lu vote_pubkey=%s stake=%lu voted_hash=%s local_hash=%s",
                                     (unsigned long)slot,
                                     vote_pk_b58[0] ? vote_pk_b58 : "-",
                                     (unsigned long)stake,
                                     voted_hash_b58[0] ? voted_hash_b58 : "-",
                                     local_hash_b58[0] ? local_hash_b58 : "-");
                        g_vote_hash_mismatch_last_slot = slot;
                        g_vote_hash_mismatch_logged++;
                        if (g_vote_hash_mismatch_logged == 20) {
                            sol_log_warn("Vote bank-hash mismatch: suppressing further logs");
                        }
                    }
                }
            }
        }
    }

    /* Find existing vote */
    sol_vote_entry_t* vote = find_vote(fc, validator);

    if (vote) {
        /* Update existing vote */
        bool hash_changed = memcmp(vote->voted_hash.bytes, bank_hash->bytes, SOL_HASH_SIZE) != 0;
        if (slot > vote->voted_slot || (slot == vote->voted_slot && hash_changed)) {
            /* Remove stake from old slot */
            sol_stake_entry_t* old_stake = find_stake(fc, vote->voted_slot, &vote->voted_hash);
            if (old_stake) {
                if (old_stake->direct_stake >= vote->stake) {
                    old_stake->direct_stake -= vote->stake;
                }
                if (old_stake->vote_count > 0) {
                    old_stake->vote_count--;
                }
            }

            /* Add stake to new slot */
            sol_stake_entry_t* new_stake = find_or_create_stake(fc, slot, bank_hash);
            if (new_stake) {
                new_stake->direct_stake += stake;
                new_stake->vote_count++;
            }

            /* Update total stake if stake changed */
            fc->total_stake = fc->total_stake - vote->stake + stake;

            vote->voted_slot = slot;
            vote->voted_hash = *bank_hash;
            vote->stake = stake;
            fc->subtree_cache_valid = false;
        }
    } else {
        /* New voter */
        if (fc->voter_count >= fc->config.max_votes) {
            pthread_rwlock_unlock(&fc->lock);
            return SOL_ERR_FULL;
        }

        vote = sol_calloc(1, sizeof(sol_vote_entry_t));
        if (!vote) {
            pthread_rwlock_unlock(&fc->lock);
            return SOL_ERR_NOMEM;
        }

        vote->validator = *validator;
        vote->voted_slot = slot;
        vote->voted_hash = *bank_hash;
        vote->stake = stake;

        /* Insert into hash table */
        size_t idx = pubkey_hash(validator, fc->vote_bucket_count);
        vote->next = fc->vote_buckets[idx];
        fc->vote_buckets[idx] = vote;
        fc->voter_count++;

        /* Add stake to slot */
        sol_stake_entry_t* slot_stake = find_or_create_stake(fc, slot, bank_hash);
        if (slot_stake) {
            slot_stake->direct_stake += stake;
            slot_stake->vote_count++;
        }

        fc->total_stake += stake;
        fc->subtree_cache_valid = false;
    }

    pthread_rwlock_unlock(&fc->lock);
    return SOL_OK;
}

typedef struct {
    sol_slot_t  slot;
    sol_slot_t  parent_slot;
    sol_hash_t  bank_hash;
    sol_hash_t  parent_hash;
    bool        is_dead;
} fork_node_t;

static uint64_t
compute_subtree_weight(sol_fork_choice_t* fc,
                       const fork_node_t* nodes,
                       size_t node_count,
                       sol_slot_t slot,
                       const sol_hash_t* bank_hash) {
    /* Ensure a stake entry exists so subtree weights propagate through
     * intermediate slots that have no direct votes. */
    sol_stake_entry_t* stake = find_or_create_stake(fc, slot, bank_hash);
    uint64_t weight = stake ? stake->direct_stake : 0;

    /* Sum all children whose parent identity matches (slot,parent_hash). */
    for (size_t i = 0; i < node_count; i++) {
        const fork_node_t* child = &nodes[i];
        if (child->is_dead) continue;
        if (child->slot == slot) continue;
        if (child->parent_slot != slot) continue;
        if (memcmp(child->parent_hash.bytes, bank_hash->bytes, SOL_HASH_SIZE) != 0) continue;

        weight += compute_subtree_weight(fc, nodes, node_count, child->slot, &child->bank_hash);
    }

    if (stake) {
        stake->subtree_stake = weight;
    }

    return weight;
}

static void
best_bank_from_snapshot(sol_fork_choice_t* fc,
                        const fork_node_t* nodes,
                        size_t node_count,
                        sol_slot_t start_slot,
                        const sol_hash_t* start_hash,
                        sol_slot_t* out_slot,
                        sol_hash_t* out_hash) {
    sol_slot_t cur_slot = start_slot;
    sol_hash_t cur_hash = start_hash ? *start_hash : (sol_hash_t){0};

    while (true) {
        bool found = false;
        uint64_t best_weight = 0;
        sol_slot_t best_slot = 0;
        sol_hash_t best_hash = {0};

        for (size_t i = 0; i < node_count; i++) {
            const fork_node_t* child = &nodes[i];
            if (child->is_dead) continue;
            if (child->slot == cur_slot) continue;
            if (child->parent_slot != cur_slot) continue;
            if (memcmp(child->parent_hash.bytes, cur_hash.bytes, SOL_HASH_SIZE) != 0) continue;

            sol_stake_entry_t* stake = find_stake(fc, child->slot, &child->bank_hash);
            uint64_t weight = stake ? stake->subtree_stake : 0;

            if (!found || weight > best_weight ||
                (weight == best_weight && (child->slot > best_slot ||
                                           (child->slot == best_slot &&
                                            memcmp(child->bank_hash.bytes, best_hash.bytes, SOL_HASH_SIZE) > 0)))) {
                found = true;
                best_weight = weight;
                best_slot = child->slot;
                best_hash = child->bank_hash;
            }
        }

        if (!found) break;
        cur_slot = best_slot;
        cur_hash = best_hash;
    }

    if (out_slot) *out_slot = cur_slot;
    if (out_hash) *out_hash = cur_hash;
}

typedef struct {
    fork_node_t* nodes;
    size_t       cap;
    size_t       len;
} fork_snapshot_ctx_t;

static bool
fork_snapshot_cb(sol_slot_t slot,
                 sol_slot_t parent_slot,
                 const sol_hash_t* bank_hash,
                 const sol_hash_t* parent_hash,
                 sol_bank_t* bank,
                 bool is_dead,
                 void* ctx) {
    (void)bank;
    fork_snapshot_ctx_t* snap = (fork_snapshot_ctx_t*)ctx;
    if (!snap || !snap->nodes) return false;
    if (snap->len >= snap->cap) return false;

    fork_node_t* n = &snap->nodes[snap->len++];
    n->slot = slot;
    n->parent_slot = parent_slot;
    if (bank_hash) {
        n->bank_hash = *bank_hash;
    } else {
        memset(&n->bank_hash, 0, sizeof(n->bank_hash));
    }
    if (sol_hash_is_zero(&n->bank_hash) && bank) {
        sol_bank_compute_hash(bank, &n->bank_hash);
    }
    if (parent_hash) {
        n->parent_hash = *parent_hash;
    } else {
        memset(&n->parent_hash, 0, sizeof(n->parent_hash));
    }
    n->is_dead = is_dead;
    return true;
}

/*
 * Ensure subtree cache is valid
 */
static void
ensure_subtree_cache(sol_fork_choice_t* fc) {
    if (fc->bank_forks) {
        size_t count = sol_bank_forks_count(fc->bank_forks);
        if (count != fc->cached_bank_count) {
            fc->cached_bank_count = count;
            fc->subtree_cache_valid = false;
        }
    }

    if (fc->subtree_cache_valid) return;

    fork_node_t* nodes = NULL;
    size_t node_count = 0;

    if (fc->bank_forks) {
        size_t cap = sol_bank_forks_count(fc->bank_forks);
        if (cap == 0) cap = 1;
        nodes = sol_calloc(cap, sizeof(*nodes));
        if (nodes) {
            fork_snapshot_ctx_t snap = {
                .nodes = nodes,
                .cap = cap,
                .len = 0,
            };
            sol_bank_forks_iterate(fc->bank_forks, fork_snapshot_cb, &snap);
            node_count = snap.len;
        }
    }

    /* Recompute from root */
    compute_subtree_weight(fc, nodes, node_count, fc->root_slot, &fc->root_hash);

    /* Cache best tip from root */
    fc->cached_best_slot = fc->root_slot;
    fc->cached_best_hash = fc->root_hash;
    best_bank_from_snapshot(fc, nodes, node_count,
                            fc->root_slot, &fc->root_hash,
                            &fc->cached_best_slot, &fc->cached_best_hash);

    sol_free(nodes);
    fc->subtree_cache_valid = true;
}

sol_slot_t
sol_fork_choice_best_slot(sol_fork_choice_t* fc) {
    sol_slot_t slot = 0;
    sol_hash_t hash = {0};
    if (!sol_fork_choice_best_bank(fc, &slot, &hash)) {
        return 0;
    }
    return slot;
}

bool
sol_fork_choice_best_bank(sol_fork_choice_t* fc,
                          sol_slot_t* out_slot,
                          sol_hash_t* out_bank_hash) {
    if (!fc) return false;

    pthread_rwlock_wrlock(&fc->lock);
    ensure_subtree_cache(fc);

    if (out_slot) *out_slot = fc->cached_best_slot;
    if (out_bank_hash) *out_bank_hash = fc->cached_best_hash;

    pthread_rwlock_unlock(&fc->lock);
    return true;
}

sol_slot_t
sol_fork_choice_best_slot_from(sol_fork_choice_t* fc, sol_slot_t start_slot) {
    if (!fc || !fc->bank_forks) return start_slot;

    pthread_rwlock_wrlock(&fc->lock);

    ensure_subtree_cache(fc);

    if (start_slot == fc->root_slot) {
        sol_slot_t best = fc->cached_best_slot;
        pthread_rwlock_unlock(&fc->lock);
        return best;
    }

    sol_bank_t* start_bank = sol_bank_forks_get(fc->bank_forks, start_slot);
    if (!start_bank) {
        pthread_rwlock_unlock(&fc->lock);
        return start_slot;
    }

    sol_hash_t start_hash = {0};
    sol_bank_compute_hash(start_bank, &start_hash);

    fork_node_t* nodes = NULL;
    size_t node_count = 0;
    size_t cap = sol_bank_forks_count(fc->bank_forks);
    if (cap == 0) cap = 1;
    nodes = sol_calloc(cap, sizeof(*nodes));
    if (nodes) {
        fork_snapshot_ctx_t snap = {
            .nodes = nodes,
            .cap = cap,
            .len = 0,
        };
        sol_bank_forks_iterate(fc->bank_forks, fork_snapshot_cb, &snap);
        node_count = snap.len;
    }

    sol_slot_t best = start_slot;
    sol_hash_t best_hash = start_hash;
    best_bank_from_snapshot(fc, nodes, node_count,
                            start_slot, &start_hash,
                            &best, &best_hash);

    sol_free(nodes);

    pthread_rwlock_unlock(&fc->lock);
    return best;
}

size_t
sol_fork_choice_compute_weights(sol_fork_choice_t* fc,
                                sol_fork_weight_t* out_weights,
                                size_t max_forks) {
    if (!fc || !out_weights || max_forks == 0) return 0;

    pthread_rwlock_wrlock(&fc->lock);

    ensure_subtree_cache(fc);

    size_t count = 0;
    for (size_t i = 0; i < fc->stake_bucket_count && count < max_forks; i++) {
        sol_stake_entry_t* entry = fc->stake_buckets[i];
        while (entry && count < max_forks) {
            out_weights[count].slot = entry->slot;
            out_weights[count].bank_hash = entry->bank_hash;
            out_weights[count].stake_weight = entry->direct_stake;
            out_weights[count].subtree_weight = entry->subtree_stake;
            out_weights[count].vote_count = entry->vote_count;
            count++;
            entry = entry->next;
        }
    }

    pthread_rwlock_unlock(&fc->lock);
    return count;
}

uint64_t
sol_fork_choice_stake_weight_hash(sol_fork_choice_t* fc,
                                  sol_slot_t slot,
                                  const sol_hash_t* bank_hash) {
    if (!fc || !bank_hash) return 0;

    pthread_rwlock_rdlock(&fc->lock);
    sol_stake_entry_t* stake = find_stake(fc, slot, bank_hash);
    uint64_t weight = stake ? stake->direct_stake : 0;
    pthread_rwlock_unlock(&fc->lock);
    return weight;
}

uint64_t
sol_fork_choice_subtree_weight_hash(sol_fork_choice_t* fc,
                                    sol_slot_t slot,
                                    const sol_hash_t* bank_hash) {
    if (!fc || !bank_hash) return 0;

    pthread_rwlock_wrlock(&fc->lock);
    ensure_subtree_cache(fc);
    sol_stake_entry_t* stake = find_stake(fc, slot, bank_hash);
    uint64_t weight = stake ? stake->subtree_stake : 0;
    pthread_rwlock_unlock(&fc->lock);
    return weight;
}

uint64_t
sol_fork_choice_stake_weight(sol_fork_choice_t* fc, sol_slot_t slot) {
    if (!fc) return 0;

    pthread_rwlock_rdlock(&fc->lock);

    uint64_t weight = 0;
    sol_hash_t slot_hash = {0};
    sol_stake_entry_t* stake = NULL;

    if (fc->bank_forks) {
        sol_bank_t* bank = sol_bank_forks_get(fc->bank_forks, slot);
        if (bank) {
            sol_bank_compute_hash(bank, &slot_hash);
            stake = find_stake(fc, slot, &slot_hash);
            weight = stake ? stake->direct_stake : 0;
            pthread_rwlock_unlock(&fc->lock);
            return weight;
        }
    }

    /* No bank for slot: sum across all hashes at this slot (best-effort). */
    for (size_t i = 0; i < fc->stake_bucket_count; i++) {
        stake = fc->stake_buckets[i];
        while (stake) {
            if (stake->slot == slot) {
                weight += stake->direct_stake;
            }
            stake = stake->next;
        }
    }

    pthread_rwlock_unlock(&fc->lock);
    return weight;
}

uint64_t
sol_fork_choice_subtree_weight(sol_fork_choice_t* fc, sol_slot_t slot) {
    if (!fc) return 0;

    pthread_rwlock_wrlock(&fc->lock);

    ensure_subtree_cache(fc);

    uint64_t weight = 0;
    sol_hash_t slot_hash = {0};
    sol_stake_entry_t* stake = NULL;

    if (fc->bank_forks) {
        sol_bank_t* bank = sol_bank_forks_get(fc->bank_forks, slot);
        if (bank) {
            sol_bank_compute_hash(bank, &slot_hash);
            stake = find_stake(fc, slot, &slot_hash);
            weight = stake ? stake->subtree_stake : 0;
            pthread_rwlock_unlock(&fc->lock);
            return weight;
        }
    }

    /* No bank for slot: sum across all hashes at this slot (best-effort). */
    for (size_t i = 0; i < fc->stake_bucket_count; i++) {
        stake = fc->stake_buckets[i];
        while (stake) {
            if (stake->slot == slot) {
                weight += stake->subtree_stake;
            }
            stake = stake->next;
        }
    }

    pthread_rwlock_unlock(&fc->lock);
    return weight;
}

bool
sol_fork_choice_best_voted_hash(sol_fork_choice_t* fc,
                                sol_slot_t slot,
                                sol_hash_t* out_bank_hash,
                                uint64_t* out_stake_weight,
                                uint32_t* out_vote_count,
                                uint64_t* out_total_stake_weight,
                                uint32_t* out_total_vote_count) {
    if (!fc) return false;

    pthread_rwlock_rdlock(&fc->lock);

    bool found = false;
    sol_hash_t best_hash = {0};
    uint64_t best_stake = 0;
    uint32_t best_votes = 0;

    uint64_t total_stake = 0;
    uint32_t total_votes = 0;

    for (size_t i = 0; i < fc->stake_bucket_count; i++) {
        sol_stake_entry_t* stake = fc->stake_buckets[i];
        while (stake) {
            if (stake->slot == slot) {
                total_stake += stake->direct_stake;
                total_votes += stake->vote_count;

                if (!found ||
                    stake->direct_stake > best_stake ||
                    (stake->direct_stake == best_stake && stake->vote_count > best_votes) ||
                    (stake->direct_stake == best_stake && stake->vote_count == best_votes &&
                     memcmp(stake->bank_hash.bytes, best_hash.bytes, SOL_HASH_SIZE) > 0)) {
                    found = true;
                    best_hash = stake->bank_hash;
                    best_stake = stake->direct_stake;
                    best_votes = stake->vote_count;
                }
            }
            stake = stake->next;
        }
    }

    pthread_rwlock_unlock(&fc->lock);

    if (!found) return false;

    if (out_bank_hash) *out_bank_hash = best_hash;
    if (out_stake_weight) *out_stake_weight = best_stake;
    if (out_vote_count) *out_vote_count = best_votes;
    if (out_total_stake_weight) *out_total_stake_weight = total_stake;
    if (out_total_vote_count) *out_total_vote_count = total_votes;

    return true;
}

bool
sol_fork_choice_has_supermajority(sol_fork_choice_t* fc,
                                  sol_slot_t slot,
                                  uint64_t threshold) {
    if (!fc) return false;

    pthread_rwlock_wrlock(&fc->lock);

    ensure_subtree_cache(fc);

    uint64_t weight = 0;
    sol_hash_t slot_hash = {0};
    sol_stake_entry_t* stake = NULL;

    if (fc->bank_forks) {
        sol_bank_t* bank = sol_bank_forks_get(fc->bank_forks, slot);
        if (bank) {
            sol_bank_compute_hash(bank, &slot_hash);
            stake = find_stake(fc, slot, &slot_hash);
            weight = stake ? stake->subtree_stake : 0;
        } else {
            /* No bank for slot: sum across all hashes at this slot (best-effort). */
            for (size_t i = 0; i < fc->stake_bucket_count; i++) {
                stake = fc->stake_buckets[i];
                while (stake) {
                    if (stake->slot == slot) {
                        weight += stake->subtree_stake;
                    }
                    stake = stake->next;
                }
            }
        }
    }

    pthread_rwlock_unlock(&fc->lock);

    return weight >= threshold;
}

sol_slot_t
sol_fork_choice_latest_vote(sol_fork_choice_t* fc,
                            const sol_pubkey_t* validator) {
    if (!fc || !validator) return 0;

    pthread_rwlock_rdlock(&fc->lock);

    sol_vote_entry_t* vote = find_vote(fc, validator);
    sol_slot_t slot = vote ? vote->voted_slot : 0;

    pthread_rwlock_unlock(&fc->lock);
    return slot;
}

sol_err_t
sol_fork_choice_set_root(sol_fork_choice_t* fc, sol_slot_t root_slot) {
    if (!fc) return SOL_ERR_INVAL;

    pthread_rwlock_wrlock(&fc->lock);

    /* Remove votes and stakes for slots before new root */
    for (size_t i = 0; i < fc->stake_bucket_count; i++) {
        sol_stake_entry_t** prev_ptr = &fc->stake_buckets[i];
        sol_stake_entry_t* entry = fc->stake_buckets[i];

        while (entry) {
            sol_stake_entry_t* next = entry->next;

            if (entry->slot < root_slot) {
                *prev_ptr = next;
                sol_free(entry);
            } else {
                prev_ptr = &entry->next;
            }

            entry = next;
        }
    }

    fc->root_slot = root_slot;
    if (fc->bank_forks) {
        sol_bank_t* root_bank = sol_bank_forks_get(fc->bank_forks, root_slot);
        if (root_bank) {
            sol_bank_compute_hash(root_bank, &fc->root_hash);
        } else {
            memset(&fc->root_hash, 0, sizeof(fc->root_hash));
        }
    }
    fc->cached_best_slot = fc->root_slot;
    fc->cached_best_hash = fc->root_hash;
    fc->subtree_cache_valid = false;

    pthread_rwlock_unlock(&fc->lock);
    return SOL_OK;
}

uint64_t
sol_fork_choice_total_stake(const sol_fork_choice_t* fc) {
    if (!fc) return 0;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&fc->lock);
    uint64_t stake = fc->total_stake;
    pthread_rwlock_unlock((pthread_rwlock_t*)&fc->lock);

    return stake;
}

size_t
sol_fork_choice_voter_count(const sol_fork_choice_t* fc) {
    if (!fc) return 0;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&fc->lock);
    size_t count = fc->voter_count;
    pthread_rwlock_unlock((pthread_rwlock_t*)&fc->lock);

    return count;
}

void
sol_fork_choice_set_threshold_stake(sol_fork_choice_t* fc, uint64_t threshold_stake) {
    if (!fc) return;

    pthread_rwlock_wrlock(&fc->lock);
    fc->config.threshold_stake = threshold_stake;
    pthread_rwlock_unlock(&fc->lock);
}

uint64_t
sol_fork_choice_threshold_stake(const sol_fork_choice_t* fc) {
    if (!fc) return 0;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&fc->lock);
    uint64_t threshold = fc->config.threshold_stake;
    pthread_rwlock_unlock((pthread_rwlock_t*)&fc->lock);

    return threshold;
}
