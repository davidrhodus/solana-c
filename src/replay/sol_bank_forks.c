/*
 * sol_bank_forks.c - Bank Forks Implementation
 */

#include "sol_bank_forks.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include <string.h>

/*
 * Bank entry in the forks tree
 */
typedef struct sol_bank_entry {
    sol_slot_t              slot;
    sol_slot_t              parent_slot;
    sol_hash_t              bank_hash;   /* Cached bank hash (zero if unknown/unfrozen) */
    sol_hash_t              parent_hash; /* Parent bank hash for fork linkage */
    sol_bank_t*             bank;
    uint64_t                stake_weight;
    bool                    is_dead;
    struct sol_bank_entry*  next;       /* Hash chain */
} sol_bank_entry_t;

/*
 * Bank forks structure
 */
struct sol_bank_forks {
    sol_bank_forks_config_t config;

    /* Rooted AccountsDB (shared base state) */
    sol_accounts_db_t*      accounts_db;
    bool                    owns_accounts_db;

    /* Hash table of banks by slot */
    sol_bank_entry_t**      buckets;
    size_t                  bucket_count;
    size_t                  bank_count;

    /* Root slot (finalized) */
    sol_slot_t              root_slot;

    /* Highest slot seen */
    sol_slot_t              highest_slot;

    /* Statistics */
    sol_bank_forks_stats_t  stats;

    /* Thread safety */
    pthread_rwlock_t        lock;
};

/*
 * Hash function for slot
 */
static size_t
slot_hash(sol_slot_t slot, size_t bucket_count) {
    return (size_t)(slot % bucket_count);
}

/*
 * Find entry by slot
 */
static sol_bank_entry_t*
find_entry(sol_bank_forks_t* forks, sol_slot_t slot) {
    size_t idx = slot_hash(slot, forks->bucket_count);
    sol_bank_entry_t* entry = forks->buckets[idx];
    sol_bank_entry_t* best = NULL;

    while (entry) {
        if (entry->slot == slot && !entry->is_dead) {
            /* Prefer frozen banks, then banks with known hash, then any. */
            if (!best) {
                best = entry;
            } else {
                bool best_frozen = best->bank && sol_bank_is_frozen(best->bank);
                bool entry_frozen = entry->bank && sol_bank_is_frozen(entry->bank);
                if (entry_frozen && !best_frozen) {
                    best = entry;
                } else if (entry_frozen == best_frozen) {
                    bool best_hash = !sol_hash_is_zero(&best->bank_hash);
                    bool entry_hash = !sol_hash_is_zero(&entry->bank_hash);
                    if (entry_hash && !best_hash) {
                        best = entry;
                    } else if (entry_hash == best_hash) {
                        if (entry->stake_weight > best->stake_weight) {
                            best = entry;
                        }
                    }
                }
            }
        }
        entry = entry->next;
    }

    return best;
}

static sol_bank_entry_t*
find_entry_hash(sol_bank_forks_t* forks, sol_slot_t slot, const sol_hash_t* bank_hash) {
    if (!forks || !bank_hash) return NULL;

    size_t idx = slot_hash(slot, forks->bucket_count);
    sol_bank_entry_t* entry = forks->buckets[idx];

    while (entry) {
        if (entry->slot == slot &&
            memcmp(entry->bank_hash.bytes, bank_hash->bytes, SOL_HASH_SIZE) == 0) {
            return entry;
        }
        entry = entry->next;
    }

    return NULL;
}

static sol_slot_t
recompute_highest_slot(sol_bank_forks_t* forks) {
    if (!forks) return 0;

    sol_slot_t highest = forks->root_slot;
    for (size_t i = 0; i < forks->bucket_count; i++) {
        sol_bank_entry_t* entry = forks->buckets[i];
        while (entry) {
            if (!entry->is_dead && entry->slot > highest) {
                highest = entry->slot;
            }
            entry = entry->next;
        }
    }
    return highest;
}

sol_bank_forks_t*
sol_bank_forks_new(sol_bank_t* root_bank,
                   const sol_bank_forks_config_t* config) {
    if (!root_bank) return NULL;

    sol_bank_forks_t* forks = sol_calloc(1, sizeof(sol_bank_forks_t));
    if (!forks) return NULL;

    if (config) {
        forks->config = *config;
    } else {
        forks->config = (sol_bank_forks_config_t)SOL_BANK_FORKS_CONFIG_DEFAULT;
    }

    /* Initialize hash table */
    forks->bucket_count = forks->config.max_banks / 4;
    if (forks->bucket_count < 16) forks->bucket_count = 16;

    forks->buckets = sol_calloc(forks->bucket_count, sizeof(sol_bank_entry_t*));
    if (!forks->buckets) {
        sol_free(forks);
        return NULL;
    }

    if (pthread_rwlock_init(&forks->lock, NULL) != 0) {
        sol_free(forks->buckets);
        sol_free(forks);
        return NULL;
    }

    /* Insert root bank */
    sol_slot_t root_slot = sol_bank_slot(root_bank);
    forks->root_slot = root_slot;
    forks->highest_slot = root_slot;

    /* The rooted AccountsDB must outlive pruned banks. If the provided root
     * bank owns its AccountsDB (common in unit tests), transfer ownership to
     * the forks manager so pruning does not free shared state. */
    forks->accounts_db = sol_bank_get_accounts_db(root_bank);
    forks->owns_accounts_db = sol_bank_owns_accounts_db(root_bank);
    if (forks->owns_accounts_db) {
        sol_bank_set_owns_accounts_db(root_bank, false);
    }

    sol_bank_entry_t* entry = sol_calloc(1, sizeof(sol_bank_entry_t));
    if (!entry) {
        if (forks->owns_accounts_db) {
            sol_bank_set_owns_accounts_db(root_bank, true);
        }
        pthread_rwlock_destroy(&forks->lock);
        sol_free(forks->buckets);
        sol_free(forks);
        return NULL;
    }

    entry->slot = root_slot;
    entry->parent_slot = root_slot;  /* Root has no parent */
    entry->bank = root_bank;
    sol_bank_compute_hash(root_bank, &entry->bank_hash);
    entry->parent_hash = entry->bank_hash;
    sol_bank_freeze(root_bank);

    size_t idx = slot_hash(root_slot, forks->bucket_count);
    entry->next = forks->buckets[idx];
    forks->buckets[idx] = entry;
    forks->bank_count = 1;

    forks->stats.banks_created = 1;

    return forks;
}

void
sol_bank_forks_destroy(sol_bank_forks_t* forks) {
    if (!forks) return;

    /* Free all entries and banks */
    for (size_t i = 0; i < forks->bucket_count; i++) {
        sol_bank_entry_t* entry = forks->buckets[i];
        while (entry) {
            sol_bank_entry_t* next = entry->next;
            sol_bank_destroy(entry->bank);
            sol_free(entry);
            entry = next;
        }
    }

    if (forks->owns_accounts_db && forks->accounts_db) {
        sol_accounts_db_destroy(forks->accounts_db);
        forks->accounts_db = NULL;
    }

    sol_free(forks->buckets);
    pthread_rwlock_destroy(&forks->lock);
    sol_free(forks);
}

sol_bank_t*
sol_bank_forks_get(sol_bank_forks_t* forks, sol_slot_t slot) {
    if (!forks) return NULL;

    pthread_rwlock_rdlock(&forks->lock);

    sol_bank_entry_t* entry = find_entry(forks, slot);
    sol_bank_t* bank = entry ? entry->bank : NULL;

    pthread_rwlock_unlock(&forks->lock);
    return bank;
}

sol_bank_t*
sol_bank_forks_get_hash(sol_bank_forks_t* forks, sol_slot_t slot, const sol_hash_t* bank_hash) {
    if (!forks || !bank_hash) return NULL;

    pthread_rwlock_rdlock(&forks->lock);

    sol_bank_entry_t* entry = find_entry_hash(forks, slot, bank_hash);
    sol_bank_t* bank = (entry && !entry->is_dead) ? entry->bank : NULL;

    pthread_rwlock_unlock(&forks->lock);
    return bank;
}

sol_bank_t*
sol_bank_forks_root(sol_bank_forks_t* forks) {
    if (!forks) return NULL;
    return sol_bank_forks_get(forks, forks->root_slot);
}

sol_slot_t
sol_bank_forks_root_slot(const sol_bank_forks_t* forks) {
    return forks ? forks->root_slot : 0;
}

sol_bank_t*
sol_bank_forks_working_bank(sol_bank_forks_t* forks) {
    if (!forks) return NULL;

    pthread_rwlock_rdlock(&forks->lock);

    /* Find highest unfrozen bank */
    sol_bank_t* best = NULL;
    sol_slot_t best_slot = 0;

    for (size_t i = 0; i < forks->bucket_count; i++) {
        sol_bank_entry_t* entry = forks->buckets[i];
        while (entry) {
            if (!entry->is_dead && entry->bank && !sol_bank_is_frozen(entry->bank)) {
                if (entry->slot > best_slot) {
                    best = entry->bank;
                    best_slot = entry->slot;
                }
            }
            entry = entry->next;
        }
    }

    /* If no unfrozen bank, return highest frozen */
    if (!best) {
        sol_bank_entry_t* entry = find_entry(forks, forks->highest_slot);
        best = entry ? entry->bank : NULL;
    }

    pthread_rwlock_unlock(&forks->lock);
    return best;
}

sol_slot_t
sol_bank_forks_highest_slot(const sol_bank_forks_t* forks) {
    return forks ? forks->highest_slot : 0;
}

sol_err_t
sol_bank_forks_insert(sol_bank_forks_t* forks, sol_bank_t* bank) {
    if (!forks || !bank) return SOL_ERR_INVAL;

    sol_slot_t slot = sol_bank_slot(bank);

    pthread_rwlock_wrlock(&forks->lock);

    /* Check if already exists */
    sol_hash_t bank_hash = {0};
    if (sol_bank_is_frozen(bank)) {
        sol_bank_compute_hash(bank, &bank_hash);
        if (find_entry_hash(forks, slot, &bank_hash)) {
            pthread_rwlock_unlock(&forks->lock);
            return SOL_ERR_EXISTS;
        }
    } else {
        /* Unfrozen banks have no stable hash; disallow ambiguous duplicates. */
        if (find_entry(forks, slot)) {
            pthread_rwlock_unlock(&forks->lock);
            return SOL_ERR_EXISTS;
        }
    }

    /* Check capacity */
    if (forks->bank_count >= forks->config.max_banks) {
        pthread_rwlock_unlock(&forks->lock);
        return SOL_ERR_FULL;
    }

    /* Create entry */
    sol_bank_entry_t* entry = sol_calloc(1, sizeof(sol_bank_entry_t));
    if (!entry) {
        pthread_rwlock_unlock(&forks->lock);
        return SOL_ERR_NOMEM;
    }

    entry->slot = slot;
    entry->bank = bank;
    entry->bank_hash = bank_hash; /* may be zero if unfrozen */

    const sol_hash_t* parent_hash = sol_bank_parent_hash(bank);
    if (parent_hash) {
        entry->parent_hash = *parent_hash;
    } else {
        memset(&entry->parent_hash, 0, sizeof(entry->parent_hash));
    }

    entry->parent_slot = sol_bank_parent_slot(bank);

    /* Insert into hash table */
    size_t idx = slot_hash(slot, forks->bucket_count);
    entry->next = forks->buckets[idx];
    forks->buckets[idx] = entry;
    forks->bank_count++;

    /* Update highest slot */
    if (slot > forks->highest_slot) {
        forks->highest_slot = slot;
        forks->stats.highest_slot = slot;
    }

    forks->stats.banks_created++;

    pthread_rwlock_unlock(&forks->lock);
    return SOL_OK;
}

sol_bank_t*
sol_bank_forks_new_from_parent(sol_bank_forks_t* forks,
                                sol_slot_t parent_slot,
                                sol_slot_t slot) {
    if (!forks) return NULL;

    pthread_rwlock_wrlock(&forks->lock);

    /* Find parent */
    sol_bank_entry_t* parent_entry = find_entry(forks, parent_slot);
    if (!parent_entry || !parent_entry->bank) {
        pthread_rwlock_unlock(&forks->lock);
        return NULL;
    }

    /* Check if slot already exists */
    if (find_entry(forks, slot)) {
        pthread_rwlock_unlock(&forks->lock);
        return NULL;
    }

    /* Check capacity */
    if (forks->bank_count >= forks->config.max_banks) {
        pthread_rwlock_unlock(&forks->lock);
        return NULL;
    }

    /* Create new bank */
    sol_bank_t* bank = sol_bank_new_from_parent(parent_entry->bank, slot);
    if (!bank) {
        pthread_rwlock_unlock(&forks->lock);
        return NULL;
    }

    /* Create entry */
    sol_bank_entry_t* entry = sol_calloc(1, sizeof(sol_bank_entry_t));
    if (!entry) {
        sol_bank_destroy(bank);
        pthread_rwlock_unlock(&forks->lock);
        return NULL;
    }

    entry->slot = slot;
    entry->parent_slot = parent_slot;
    entry->bank = bank;
    memset(&entry->bank_hash, 0, sizeof(entry->bank_hash)); /* computed when frozen */
    const sol_hash_t* p_hash = sol_bank_parent_hash(bank);
    if (p_hash) {
        entry->parent_hash = *p_hash;
    } else {
        memset(&entry->parent_hash, 0, sizeof(entry->parent_hash));
    }

    /* Insert into hash table */
    size_t idx = slot_hash(slot, forks->bucket_count);
    entry->next = forks->buckets[idx];
    forks->buckets[idx] = entry;
    forks->bank_count++;

    /* Update highest slot */
    if (slot > forks->highest_slot) {
        forks->highest_slot = slot;
        forks->stats.highest_slot = slot;
    }

    forks->stats.banks_created++;

    pthread_rwlock_unlock(&forks->lock);
    return bank;
}

/*
 * Check if slot is a descendant of ancestor (helper)
 */
static bool
is_descendant_of(sol_bank_forks_t* forks, sol_slot_t slot, sol_slot_t ancestor) {
    if (slot == ancestor) return true;
    if (slot < ancestor) return false;

    sol_bank_entry_t* entry = find_entry(forks, slot);
    while (entry && entry->slot > ancestor) {
        if (entry->parent_slot == ancestor) return true;
        entry = find_entry(forks, entry->parent_slot);
    }

    return false;
}

static bool
is_descendant_of_hash(sol_bank_forks_t* forks,
                      const sol_bank_entry_t* entry,
                      sol_slot_t ancestor_slot,
                      const sol_hash_t* ancestor_hash) {
    if (!forks || !entry || !ancestor_hash) return false;
    if (entry->slot < ancestor_slot) return false;

    const sol_bank_entry_t* cur = entry;
    size_t safety = 0;

    while (cur && cur->slot > ancestor_slot) {
        if (cur->parent_slot == cur->slot) {
            return false;
        }

        sol_bank_entry_t* parent = find_entry_hash(forks, cur->parent_slot, &cur->parent_hash);
        if (!parent) {
            return false;
        }

        cur = parent;
        if (++safety > forks->bank_count) {
            return false;
        }
    }

    if (!cur) return false;
    if (cur->slot != ancestor_slot) return false;

    sol_hash_t cur_hash = cur->bank_hash;
    if (sol_hash_is_zero(&cur_hash) && cur->bank) {
        sol_bank_compute_hash(cur->bank, &cur_hash);
    }

    return memcmp(cur_hash.bytes, ancestor_hash->bytes, SOL_HASH_SIZE) == 0;
}

sol_err_t
sol_bank_forks_set_root(sol_bank_forks_t* forks, sol_slot_t slot) {
    if (!forks) return SOL_ERR_INVAL;

    pthread_rwlock_wrlock(&forks->lock);

    /* Verify slot exists */
    sol_bank_entry_t* new_root = find_entry(forks, slot);
    if (!new_root) {
        pthread_rwlock_unlock(&forks->lock);
        return SOL_ERR_NOTFOUND;
    }

    /* Can only advance root, not go backwards */
    if (slot < forks->root_slot) {
        pthread_rwlock_unlock(&forks->lock);
        return SOL_ERR_INVAL;
    }

    /* Commit AccountsDB deltas along the rooted chain before pruning.
     *
     * With forked AccountsDB views, each bank holds only its local delta.
     * Advancing root materializes those deltas into the rooted base so the
     * new root no longer depends on pruned ancestors. */
    if (slot > forks->root_slot && forks->accounts_db) {
        sol_bank_entry_t** chain = NULL;
        size_t chain_len = 0;
        size_t chain_cap = 0;

        sol_slot_t cur = slot;
        size_t safety = 0;
        while (1) {
            sol_bank_entry_t* e = find_entry(forks, cur);
            if (!e || !e->bank) {
                sol_free(chain);
                pthread_rwlock_unlock(&forks->lock);
                return SOL_ERR_NOTFOUND;
            }

            if (chain_len == chain_cap) {
                size_t new_cap = chain_cap ? (chain_cap * 2) : 8;
                if (new_cap < chain_cap) {
                    sol_free(chain);
                    pthread_rwlock_unlock(&forks->lock);
                    return SOL_ERR_OVERFLOW;
                }
                sol_bank_entry_t** new_chain = sol_realloc(chain, new_cap * sizeof(*new_chain));
                if (!new_chain) {
                    sol_free(chain);
                    pthread_rwlock_unlock(&forks->lock);
                    return SOL_ERR_NOMEM;
                }
                chain = new_chain;
                chain_cap = new_cap;
            }

            chain[chain_len++] = e;

            if (cur == forks->root_slot) {
                break;
            }

            if (e->parent_slot == cur) {
                sol_free(chain);
                pthread_rwlock_unlock(&forks->lock);
                return SOL_ERR_INVAL;
            }

            cur = e->parent_slot;
            if (++safety > forks->bank_count) {
                sol_free(chain);
                pthread_rwlock_unlock(&forks->lock);
                return SOL_ERR_INVAL;
            }
        }

        if (chain_len > 1) {
            /* chain[0] = new root ... chain[chain_len-1] = old root.
             * Apply deltas from old-root-child to new-root. */
            sol_log_warn("ROOT_ADVANCE old=%lu new=%lu chain_len=%zu",
                         (unsigned long)forks->root_slot, (unsigned long)slot, chain_len);
            for (size_t i = chain_len - 1; i-- > 0;) {
                sol_accounts_db_t* bank_db = sol_bank_get_accounts_db(chain[i]->bank);
                sol_err_t err = sol_accounts_db_apply_delta_default_slot(forks->accounts_db,
                                                                        bank_db,
                                                                        chain[i]->slot);
                if (err != SOL_OK) {
                    sol_free(chain);
                    pthread_rwlock_unlock(&forks->lock);
                    return err;
                }
            }

            /* Rebase the new root AccountsDB onto the rooted base and clear its local delta. */
            sol_accounts_db_t* new_root_db = sol_bank_get_accounts_db(new_root->bank);
            if (new_root_db && new_root_db != forks->accounts_db) {
                sol_accounts_db_set_parent(new_root_db, forks->accounts_db);
                sol_accounts_db_clear_local(new_root_db);
            }

            /* Mark the newly-rooted slots' AppendVec immutable so they can be mmap'd.
             * Do this only after all deltas apply successfully to avoid leaving the
             * rooted DB in a partially-sealed state on error. */
            for (size_t i = chain_len - 1; i-- > 0;) {
                (void)sol_accounts_db_appendvec_seal_slot(forks->accounts_db, chain[i]->slot);
            }
        }

        sol_free(chain);
    }

    /* Prune banks that are not descendants of new root */
    for (size_t i = 0; i < forks->bucket_count; i++) {
        sol_bank_entry_t** prev_ptr = &forks->buckets[i];
        sol_bank_entry_t* entry = forks->buckets[i];

        while (entry) {
            sol_bank_entry_t* next = entry->next;

            /* Keep if it's the new root or a descendant */
            bool keep = (entry->slot == slot) ||
                        is_descendant_of(forks, entry->slot, slot);

            if (!keep) {
                *prev_ptr = next;
                sol_bank_destroy(entry->bank);
                sol_free(entry);
                forks->bank_count--;
                forks->stats.banks_pruned++;
            } else {
                prev_ptr = &entry->next;
            }

            entry = next;
        }
    }

    forks->root_slot = slot;
    forks->stats.root_slot = slot;
    forks->highest_slot = recompute_highest_slot(forks);
    forks->stats.highest_slot = forks->highest_slot;

    pthread_rwlock_unlock(&forks->lock);
    return SOL_OK;
}

sol_err_t
sol_bank_forks_set_root_hash(sol_bank_forks_t* forks,
                             sol_slot_t slot,
                             const sol_hash_t* bank_hash) {
    if (!forks || !bank_hash) return SOL_ERR_INVAL;

    pthread_rwlock_wrlock(&forks->lock);

    sol_bank_entry_t* new_root = find_entry_hash(forks, slot, bank_hash);
    if (!new_root || !new_root->bank || new_root->is_dead) {
        pthread_rwlock_unlock(&forks->lock);
        return SOL_ERR_NOTFOUND;
    }

    if (slot < forks->root_slot) {
        pthread_rwlock_unlock(&forks->lock);
        return SOL_ERR_INVAL;
    }

    if (!sol_bank_is_frozen(new_root->bank)) {
        pthread_rwlock_unlock(&forks->lock);
        return SOL_ERR_INVAL;
    }

    /* Ensure cached hash matches */
    if (sol_hash_is_zero(&new_root->bank_hash)) {
        sol_bank_compute_hash(new_root->bank, &new_root->bank_hash);
    }
    if (memcmp(new_root->bank_hash.bytes, bank_hash->bytes, SOL_HASH_SIZE) != 0) {
        pthread_rwlock_unlock(&forks->lock);
        return SOL_ERR_INVAL;
    }

    /* Commit AccountsDB deltas along the rooted chain before pruning. */
    if (slot > forks->root_slot && forks->accounts_db) {
        sol_bank_entry_t** chain = NULL;
        size_t chain_len = 0;
        size_t chain_cap = 0;

        sol_bank_entry_t* cur = new_root;
        size_t safety = 0;
        while (cur) {
            if (chain_len == chain_cap) {
                size_t new_cap = chain_cap ? (chain_cap * 2) : 8;
                if (new_cap < chain_cap) {
                    sol_free(chain);
                    pthread_rwlock_unlock(&forks->lock);
                    return SOL_ERR_OVERFLOW;
                }

                sol_bank_entry_t** new_chain =
                    sol_realloc(chain, new_cap * sizeof(*new_chain));
                if (!new_chain) {
                    sol_free(chain);
                    pthread_rwlock_unlock(&forks->lock);
                    return SOL_ERR_NOMEM;
                }
                chain = new_chain;
                chain_cap = new_cap;
            }

            chain[chain_len++] = cur;

            if (cur->slot == forks->root_slot) {
                break;
            }

            if (cur->parent_slot == cur->slot) {
                sol_free(chain);
                pthread_rwlock_unlock(&forks->lock);
                return SOL_ERR_INVAL;
            }

            cur = find_entry_hash(forks, cur->parent_slot, &cur->parent_hash);
            if (++safety > forks->bank_count) {
                sol_free(chain);
                pthread_rwlock_unlock(&forks->lock);
                return SOL_ERR_INVAL;
            }
        }

        if (!cur || cur->slot != forks->root_slot) {
            sol_free(chain);
            pthread_rwlock_unlock(&forks->lock);
            return SOL_ERR_INVAL;
        }

        if (chain_len > 1) {
            for (size_t i = chain_len - 1; i-- > 0;) {
                sol_accounts_db_t* bank_db = sol_bank_get_accounts_db(chain[i]->bank);
                sol_err_t err = sol_accounts_db_apply_delta_default_slot(forks->accounts_db,
                                                                        bank_db,
                                                                        chain[i]->slot);
                if (err != SOL_OK) {
                    sol_free(chain);
                    pthread_rwlock_unlock(&forks->lock);
                    return err;
                }
            }

            sol_accounts_db_t* new_root_db = sol_bank_get_accounts_db(new_root->bank);
            if (new_root_db && new_root_db != forks->accounts_db) {
                sol_accounts_db_set_parent(new_root_db, forks->accounts_db);
                sol_accounts_db_clear_local(new_root_db);
            }

            /* Mark the newly-rooted slots' AppendVec immutable so they can be mmap'd.
             * Do this only after all deltas apply successfully to avoid leaving the
             * rooted DB in a partially-sealed state on error. */
            for (size_t i = chain_len - 1; i-- > 0;) {
                (void)sol_accounts_db_appendvec_seal_slot(forks->accounts_db, chain[i]->slot);
            }
        }

        sol_free(chain);
    }

    /* Snapshot all entries before pruning so descendant checks see a consistent view. */
    size_t max_entries = forks->bank_count;
    sol_bank_entry_t** entries = sol_alloc(max_entries * sizeof(*entries));
    bool* keep = sol_calloc(max_entries, sizeof(*keep));
    if (!entries || !keep) {
        sol_free(entries);
        sol_free(keep);
        pthread_rwlock_unlock(&forks->lock);
        return SOL_ERR_NOMEM;
    }

    size_t entry_count = 0;
    for (size_t i = 0; i < forks->bucket_count; i++) {
        for (sol_bank_entry_t* e = forks->buckets[i]; e; e = e->next) {
            if (entry_count < max_entries) {
                entries[entry_count++] = e;
            }
        }
    }

    for (size_t i = 0; i < entry_count; i++) {
        sol_bank_entry_t* e = entries[i];
        keep[i] = (e == new_root) ||
                  is_descendant_of_hash(forks, e, slot, bank_hash);
    }

    for (size_t i = 0; i < forks->bucket_count; i++) {
        sol_bank_entry_t** prev_ptr = &forks->buckets[i];
        sol_bank_entry_t* entry = forks->buckets[i];

        while (entry) {
            sol_bank_entry_t* next = entry->next;

            bool keep_entry = false;
            for (size_t j = 0; j < entry_count; j++) {
                if (entries[j] == entry) {
                    keep_entry = keep[j];
                    break;
                }
            }

            if (!keep_entry) {
                *prev_ptr = next;
                sol_bank_destroy(entry->bank);
                sol_free(entry);
                forks->bank_count--;
                forks->stats.banks_pruned++;
            } else {
                prev_ptr = &entry->next;
            }

            entry = next;
        }
    }

    sol_free(entries);
    sol_free(keep);

    forks->root_slot = slot;
    forks->stats.root_slot = slot;
    forks->highest_slot = recompute_highest_slot(forks);
    forks->stats.highest_slot = forks->highest_slot;

    pthread_rwlock_unlock(&forks->lock);
    return SOL_OK;
}

sol_err_t
sol_bank_forks_freeze(sol_bank_forks_t* forks, sol_slot_t slot) {
    if (!forks) return SOL_ERR_INVAL;

    pthread_rwlock_wrlock(&forks->lock);

    sol_bank_entry_t* entry = find_entry(forks, slot);
    if (!entry || !entry->bank) {
        pthread_rwlock_unlock(&forks->lock);
        return SOL_ERR_NOTFOUND;
    }

    sol_bank_freeze(entry->bank);
    sol_bank_compute_hash(entry->bank, &entry->bank_hash);
    forks->stats.banks_frozen++;

    pthread_rwlock_unlock(&forks->lock);
    return SOL_OK;
}

sol_err_t
sol_bank_forks_mark_dead(sol_bank_forks_t* forks, sol_slot_t slot) {
    if (!forks) return SOL_ERR_INVAL;

    pthread_rwlock_wrlock(&forks->lock);

    sol_bank_entry_t* entry = find_entry(forks, slot);
    if (!entry) {
        pthread_rwlock_unlock(&forks->lock);
        return SOL_ERR_NOTFOUND;
    }

    entry->is_dead = true;

    pthread_rwlock_unlock(&forks->lock);
    return SOL_OK;
}

sol_err_t
sol_bank_forks_mark_dead_hash(sol_bank_forks_t* forks, sol_slot_t slot, const sol_hash_t* bank_hash) {
    if (!forks || !bank_hash) return SOL_ERR_INVAL;

    pthread_rwlock_wrlock(&forks->lock);

    sol_bank_entry_t* entry = find_entry_hash(forks, slot, bank_hash);
    if (!entry) {
        pthread_rwlock_unlock(&forks->lock);
        return SOL_ERR_NOTFOUND;
    }

    entry->is_dead = true;

    pthread_rwlock_unlock(&forks->lock);
    return SOL_OK;
}

bool
sol_bank_forks_contains(const sol_bank_forks_t* forks, sol_slot_t slot) {
    if (!forks) return false;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&forks->lock);
    bool found = find_entry((sol_bank_forks_t*)forks, slot) != NULL;
    pthread_rwlock_unlock((pthread_rwlock_t*)&forks->lock);

    return found;
}

bool
sol_bank_forks_is_ancestor(const sol_bank_forks_t* forks,
                           sol_slot_t ancestor,
                           sol_slot_t descendant) {
    if (!forks) return false;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&forks->lock);
    bool result = is_descendant_of((sol_bank_forks_t*)forks, descendant, ancestor);
    pthread_rwlock_unlock((pthread_rwlock_t*)&forks->lock);

    return result;
}

sol_err_t
sol_bank_forks_get_info(const sol_bank_forks_t* forks,
                        sol_slot_t slot,
                        sol_fork_info_t* info) {
    if (!forks || !info) return SOL_ERR_INVAL;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&forks->lock);

    sol_bank_entry_t* entry = find_entry((sol_bank_forks_t*)forks, slot);
    if (!entry) {
        pthread_rwlock_unlock((pthread_rwlock_t*)&forks->lock);
        return SOL_ERR_NOTFOUND;
    }

    info->slot = entry->slot;
    info->parent_slot = entry->parent_slot;
    info->stake_weight = entry->stake_weight;
    info->is_dead = entry->is_dead;
    info->bank_hash = entry->bank_hash;
    info->is_frozen = entry->bank ? sol_bank_is_frozen(entry->bank) : false;

    pthread_rwlock_unlock((pthread_rwlock_t*)&forks->lock);
    return SOL_OK;
}

sol_err_t
sol_bank_forks_get_info_hash(const sol_bank_forks_t* forks,
                             sol_slot_t slot,
                             const sol_hash_t* bank_hash,
                             sol_fork_info_t* info) {
    if (!forks || !bank_hash || !info) return SOL_ERR_INVAL;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&forks->lock);

    sol_bank_entry_t* entry = find_entry_hash((sol_bank_forks_t*)forks, slot, bank_hash);
    if (!entry) {
        pthread_rwlock_unlock((pthread_rwlock_t*)&forks->lock);
        return SOL_ERR_NOTFOUND;
    }

    info->slot = entry->slot;
    info->parent_slot = entry->parent_slot;
    info->bank_hash = entry->bank_hash;
    info->stake_weight = entry->stake_weight;
    info->is_dead = entry->is_dead;
    info->is_frozen = entry->bank ? sol_bank_is_frozen(entry->bank) : false;

    pthread_rwlock_unlock((pthread_rwlock_t*)&forks->lock);
    return SOL_OK;
}

void
sol_bank_forks_iterate(const sol_bank_forks_t* forks,
                       sol_bank_forks_iter_cb callback,
                       void* ctx) {
    if (!forks || !callback) return;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&forks->lock);

    for (size_t i = 0; i < forks->bucket_count; i++) {
        sol_bank_entry_t* entry = forks->buckets[i];
        while (entry) {
            if (!callback(entry->slot,
                          entry->parent_slot,
                          &entry->bank_hash,
                          &entry->parent_hash,
                          entry->bank,
                          entry->is_dead,
                          ctx)) {
                pthread_rwlock_unlock((pthread_rwlock_t*)&forks->lock);
                return;
            }
            entry = entry->next;
        }
    }

    pthread_rwlock_unlock((pthread_rwlock_t*)&forks->lock);
}

size_t
sol_bank_forks_frozen_banks(const sol_bank_forks_t* forks,
                            sol_slot_t* out_slots,
                            size_t max_slots) {
    if (!forks || !out_slots || max_slots == 0) return 0;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&forks->lock);

    size_t count = 0;
    for (size_t i = 0; i < forks->bucket_count && count < max_slots; i++) {
        sol_bank_entry_t* entry = forks->buckets[i];
        while (entry && count < max_slots) {
            if (entry->bank && sol_bank_is_frozen(entry->bank) && !entry->is_dead) {
                out_slots[count++] = entry->slot;
            }
            entry = entry->next;
        }
    }

    pthread_rwlock_unlock((pthread_rwlock_t*)&forks->lock);
    return count;
}

sol_err_t
sol_bank_forks_update_stake(sol_bank_forks_t* forks,
                            sol_slot_t slot,
                            uint64_t stake_delta) {
    if (!forks) return SOL_ERR_INVAL;

    pthread_rwlock_wrlock(&forks->lock);

    sol_bank_entry_t* entry = find_entry(forks, slot);
    if (!entry) {
        pthread_rwlock_unlock(&forks->lock);
        return SOL_ERR_NOTFOUND;
    }

    entry->stake_weight += stake_delta;

    pthread_rwlock_unlock(&forks->lock);
    return SOL_OK;
}

void
sol_bank_forks_stats(const sol_bank_forks_t* forks,
                     sol_bank_forks_stats_t* stats) {
    if (!forks || !stats) return;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&forks->lock);
    *stats = forks->stats;
    pthread_rwlock_unlock((pthread_rwlock_t*)&forks->lock);
}

size_t
sol_bank_forks_count(const sol_bank_forks_t* forks) {
    if (!forks) return 0;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&forks->lock);
    size_t count = forks->bank_count;
    pthread_rwlock_unlock((pthread_rwlock_t*)&forks->lock);

    return count;
}
