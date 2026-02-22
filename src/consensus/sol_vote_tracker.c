/*
 * sol_vote_tracker.c - Vote Tracking Implementation
 */

#include "sol_vote_tracker.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include <string.h>
#include <pthread.h>

/*
 * Slot vote entry (for per-slot tracking)
 */
typedef struct {
    sol_slot_t      slot;
    uint64_t        total_stake;        /* Stake that voted for this slot */
    uint64_t        root_stake;         /* Stake that has this slot as root */
    size_t          voter_count;
    bool            confirmed;          /* 2/3 voted for slot */
    bool            finalized;          /* 2/3 have slot as root */
} slot_vote_entry_t;

/*
 * Vote tracker structure
 */
struct sol_vote_tracker {
    sol_vote_tracker_config_t   config;

    /* Validator records (hash map by vote_pubkey) */
    sol_vote_record_t*          validators;
    size_t                      num_validators;
    size_t                      validators_capacity;

    /* Slot vote tracking */
    slot_vote_entry_t*          slot_votes;
    size_t                      num_slots;
    size_t                      slots_capacity;

    /* Total stake */
    uint64_t                    total_stake;

    /* Stats */
    sol_vote_tracker_stats_t    stats;

    /* Thread safety */
    pthread_rwlock_t            lock;
};

/*
 * Find validator by vote pubkey
 */
static sol_vote_record_t*
find_validator(sol_vote_tracker_t* tracker, const sol_pubkey_t* vote_pubkey) {
    for (size_t i = 0; i < tracker->num_validators; i++) {
        if (sol_pubkey_eq(&tracker->validators[i].vote_pubkey, vote_pubkey)) {
            return &tracker->validators[i];
        }
    }
    return NULL;
}

/*
 * Find or create slot vote entry
 */
static slot_vote_entry_t*
find_or_create_slot_entry(sol_vote_tracker_t* tracker, sol_slot_t slot) {
    /* Find existing */
    for (size_t i = 0; i < tracker->num_slots; i++) {
        if (tracker->slot_votes[i].slot == slot) {
            return &tracker->slot_votes[i];
        }
    }

    /* Create new */
    if (tracker->num_slots >= tracker->slots_capacity) {
        /* Replace oldest slot */
        sol_slot_t oldest_slot = UINT64_MAX;
        size_t oldest_idx = 0;
        for (size_t i = 0; i < tracker->num_slots; i++) {
            if (tracker->slot_votes[i].slot < oldest_slot) {
                oldest_slot = tracker->slot_votes[i].slot;
                oldest_idx = i;
            }
        }
        tracker->slot_votes[oldest_idx].slot = slot;
        tracker->slot_votes[oldest_idx].total_stake = 0;
        tracker->slot_votes[oldest_idx].root_stake = 0;
        tracker->slot_votes[oldest_idx].voter_count = 0;
        tracker->slot_votes[oldest_idx].confirmed = false;
        tracker->slot_votes[oldest_idx].finalized = false;
        return &tracker->slot_votes[oldest_idx];
    }

    slot_vote_entry_t* entry = &tracker->slot_votes[tracker->num_slots++];
    entry->slot = slot;
    entry->total_stake = 0;
    entry->root_stake = 0;
    entry->voter_count = 0;
    entry->confirmed = false;
    entry->finalized = false;
    return entry;
}

sol_vote_tracker_t*
sol_vote_tracker_new(const sol_vote_tracker_config_t* config) {
    sol_vote_tracker_t* tracker = sol_calloc(1, sizeof(sol_vote_tracker_t));
    if (!tracker) return NULL;

    if (config) {
        tracker->config = *config;
    } else {
        tracker->config = (sol_vote_tracker_config_t)SOL_VOTE_TRACKER_CONFIG_DEFAULT;
    }

    /* Allocate validator array */
    tracker->validators_capacity = tracker->config.max_validators;
    tracker->validators = sol_calloc(tracker->validators_capacity,
                                     sizeof(sol_vote_record_t));
    if (!tracker->validators) {
        sol_free(tracker);
        return NULL;
    }

    /* Allocate slot votes array */
    tracker->slots_capacity = tracker->config.max_slots;
    tracker->slot_votes = sol_calloc(tracker->slots_capacity,
                                     sizeof(slot_vote_entry_t));
    if (!tracker->slot_votes) {
        sol_free(tracker->validators);
        sol_free(tracker);
        return NULL;
    }

    pthread_rwlock_init(&tracker->lock, NULL);

    return tracker;
}

void
sol_vote_tracker_destroy(sol_vote_tracker_t* tracker) {
    if (!tracker) return;

    pthread_rwlock_destroy(&tracker->lock);
    sol_free(tracker->validators);
    sol_free(tracker->slot_votes);
    sol_free(tracker);
}

sol_err_t
sol_vote_tracker_record_vote(sol_vote_tracker_t* tracker,
                              const sol_pubkey_t* vote_pubkey,
                              const sol_pubkey_t* node_pubkey,
                              sol_slot_t slot,
                              sol_slot_t root_slot,
                              uint64_t stake) {
    if (!tracker || !vote_pubkey) return SOL_ERR_INVAL;

    pthread_rwlock_wrlock(&tracker->lock);

    tracker->stats.votes_received++;

    /* Find or create validator record */
    sol_vote_record_t* record = find_validator(tracker, vote_pubkey);
    if (!record) {
        if (tracker->num_validators >= tracker->validators_capacity) {
            pthread_rwlock_unlock(&tracker->lock);
            return SOL_ERR_FULL;
        }
        record = &tracker->validators[tracker->num_validators++];
        record->vote_pubkey = *vote_pubkey;
        if (node_pubkey) {
            record->node_pubkey = *node_pubkey;
        }
        record->stake = stake;
        record->active = true;
        tracker->total_stake += stake;
        tracker->stats.validators_tracked++;
    }

    /* Update vote record */
    sol_slot_t prev_slot = record->last_voted_slot;
    record->last_voted_slot = slot;
    record->root_slot = root_slot;
    record->last_update = (uint64_t)time(NULL) * 1000;  /* ms */

    /* Update stake if changed */
    if (stake != record->stake) {
        tracker->total_stake -= record->stake;
        tracker->total_stake += stake;
        record->stake = stake;
    }

    /* Update slot vote tracking */
    slot_vote_entry_t* slot_entry = find_or_create_slot_entry(tracker, slot);
    if (slot_entry) {
        /* Only count once per validator */
        if (prev_slot != slot) {
            slot_entry->total_stake += stake;
            slot_entry->voter_count++;

            /* Check for supermajority */
            if (!slot_entry->confirmed &&
                slot_entry->total_stake * 3 >= tracker->total_stake * 2) {
                slot_entry->confirmed = true;
                tracker->stats.slots_confirmed++;
            }
        }
    }

    /* Track root slot for finalization */
    if (root_slot > 0) {
        slot_vote_entry_t* root_entry = find_or_create_slot_entry(tracker, root_slot);
        if (root_entry) {
            /* Add stake to root tracking (validator has this as root) */
            /* Note: We accumulate root_stake; in practice we'd track per-validator */
            root_entry->root_stake += stake;

            /* Check for finalization (2/3 of stake has this as root) */
            if (!root_entry->finalized &&
                root_entry->root_stake * 3 >= tracker->total_stake * 2) {
                root_entry->finalized = true;
                tracker->stats.slots_finalized++;
            }
        }
    }

    tracker->stats.votes_processed++;

    pthread_rwlock_unlock(&tracker->lock);

    return SOL_OK;
}

sol_err_t
sol_vote_tracker_record_vote_state(sol_vote_tracker_t* tracker,
                                    const sol_pubkey_t* vote_pubkey,
                                    const sol_vote_state_t* state,
                                    uint64_t stake) {
    if (!tracker || !vote_pubkey || !state) return SOL_ERR_INVAL;

    /* Record the most recent vote */
    sol_slot_t last_slot = sol_vote_state_last_voted_slot(state);
    sol_slot_t root_slot = state->has_root ? state->root_slot : 0;

    return sol_vote_tracker_record_vote(
        tracker,
        vote_pubkey,
        &state->node_pubkey,
        last_slot,
        root_slot,
        stake
    );
}

uint64_t
sol_vote_tracker_get_slot_stake(const sol_vote_tracker_t* tracker,
                                 sol_slot_t slot) {
    if (!tracker) return 0;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&tracker->lock);

    uint64_t stake = 0;
    for (size_t i = 0; i < tracker->num_slots; i++) {
        if (tracker->slot_votes[i].slot == slot) {
            stake = tracker->slot_votes[i].total_stake;
            break;
        }
    }

    pthread_rwlock_unlock((pthread_rwlock_t*)&tracker->lock);

    return stake;
}

bool
sol_vote_tracker_has_supermajority(const sol_vote_tracker_t* tracker,
                                    sol_slot_t slot,
                                    uint64_t total_stake) {
    if (!tracker) return false;

    uint64_t slot_stake = sol_vote_tracker_get_slot_stake(tracker, slot);

    /* 2/3 supermajority */
    return slot_stake * 3 >= total_stake * 2;
}

sol_slot_t
sol_vote_tracker_highest_confirmed_slot(const sol_vote_tracker_t* tracker) {
    if (!tracker) return 0;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&tracker->lock);

    sol_slot_t highest = 0;
    for (size_t i = 0; i < tracker->num_slots; i++) {
        if (tracker->slot_votes[i].confirmed &&
            tracker->slot_votes[i].slot > highest) {
            highest = tracker->slot_votes[i].slot;
        }
    }

    pthread_rwlock_unlock((pthread_rwlock_t*)&tracker->lock);

    return highest;
}

sol_slot_t
sol_vote_tracker_highest_finalized_slot(const sol_vote_tracker_t* tracker) {
    if (!tracker) return 0;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&tracker->lock);

    sol_slot_t highest = 0;
    for (size_t i = 0; i < tracker->num_slots; i++) {
        if (tracker->slot_votes[i].finalized &&
            tracker->slot_votes[i].slot > highest) {
            highest = tracker->slot_votes[i].slot;
        }
    }

    pthread_rwlock_unlock((pthread_rwlock_t*)&tracker->lock);

    return highest;
}

size_t
sol_vote_tracker_get_slot_voters(const sol_vote_tracker_t* tracker,
                                  sol_slot_t slot,
                                  sol_vote_record_t* out_records,
                                  size_t max_records) {
    if (!tracker || !out_records || max_records == 0) return 0;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&tracker->lock);

    size_t count = 0;
    for (size_t i = 0; i < tracker->num_validators && count < max_records; i++) {
        if (tracker->validators[i].last_voted_slot >= slot) {
            out_records[count++] = tracker->validators[i];
        }
    }

    pthread_rwlock_unlock((pthread_rwlock_t*)&tracker->lock);

    return count;
}

sol_err_t
sol_vote_tracker_get_validator(const sol_vote_tracker_t* tracker,
                                const sol_pubkey_t* vote_pubkey,
                                sol_vote_record_t* out_record) {
    if (!tracker || !vote_pubkey || !out_record) return SOL_ERR_INVAL;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&tracker->lock);

    sol_vote_record_t* record = find_validator(
        (sol_vote_tracker_t*)tracker, vote_pubkey);
    if (!record) {
        pthread_rwlock_unlock((pthread_rwlock_t*)&tracker->lock);
        return SOL_ERR_NOTFOUND;
    }

    *out_record = *record;

    pthread_rwlock_unlock((pthread_rwlock_t*)&tracker->lock);

    return SOL_OK;
}

sol_err_t
sol_vote_tracker_get_slot_votes(const sol_vote_tracker_t* tracker,
                                 sol_slot_t slot,
                                 sol_slot_votes_t* out_votes) {
    if (!tracker || !out_votes) return SOL_ERR_INVAL;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&tracker->lock);

    for (size_t i = 0; i < tracker->num_slots; i++) {
        if (tracker->slot_votes[i].slot == slot) {
            out_votes->slot = slot;
            out_votes->total_stake = tracker->slot_votes[i].total_stake;
            out_votes->validator_count = tracker->slot_votes[i].voter_count;
            out_votes->is_confirmed = tracker->slot_votes[i].confirmed;
            out_votes->is_finalized = tracker->slot_votes[i].finalized;
            pthread_rwlock_unlock((pthread_rwlock_t*)&tracker->lock);
            return SOL_OK;
        }
    }

    pthread_rwlock_unlock((pthread_rwlock_t*)&tracker->lock);
    return SOL_ERR_NOTFOUND;
}

sol_err_t
sol_vote_tracker_update_stake(sol_vote_tracker_t* tracker,
                               const sol_pubkey_t* vote_pubkey,
                               uint64_t stake) {
    if (!tracker || !vote_pubkey) return SOL_ERR_INVAL;

    pthread_rwlock_wrlock(&tracker->lock);

    sol_vote_record_t* record = find_validator(tracker, vote_pubkey);
    if (!record) {
        pthread_rwlock_unlock(&tracker->lock);
        return SOL_ERR_NOTFOUND;
    }

    tracker->total_stake -= record->stake;
    record->stake = stake;
    tracker->total_stake += stake;

    pthread_rwlock_unlock(&tracker->lock);

    return SOL_OK;
}

void
sol_vote_tracker_prune(sol_vote_tracker_t* tracker, sol_slot_t root_slot) {
    if (!tracker || !tracker->config.enable_pruning) return;

    pthread_rwlock_wrlock(&tracker->lock);

    /* Remove old slot entries */
    size_t write_idx = 0;
    for (size_t i = 0; i < tracker->num_slots; i++) {
        if (tracker->slot_votes[i].slot >= root_slot) {
            if (write_idx != i) {
                tracker->slot_votes[write_idx] = tracker->slot_votes[i];
            }
            write_idx++;
        }
    }
    tracker->num_slots = write_idx;
    tracker->stats.slots_tracked = write_idx;

    pthread_rwlock_unlock(&tracker->lock);
}

sol_vote_tracker_stats_t
sol_vote_tracker_stats(const sol_vote_tracker_t* tracker) {
    sol_vote_tracker_stats_t stats = {0};
    if (!tracker) return stats;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&tracker->lock);
    stats = tracker->stats;
    stats.validators_tracked = tracker->num_validators;
    stats.slots_tracked = tracker->num_slots;
    pthread_rwlock_unlock((pthread_rwlock_t*)&tracker->lock);

    return stats;
}

uint64_t
sol_vote_tracker_total_stake(const sol_vote_tracker_t* tracker) {
    if (!tracker) return 0;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&tracker->lock);
    uint64_t stake = tracker->total_stake;
    pthread_rwlock_unlock((pthread_rwlock_t*)&tracker->lock);

    return stake;
}

size_t
sol_vote_tracker_active_validators(const sol_vote_tracker_t* tracker) {
    if (!tracker) return 0;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&tracker->lock);

    size_t count = 0;
    for (size_t i = 0; i < tracker->num_validators; i++) {
        if (tracker->validators[i].active) {
            count++;
        }
    }

    pthread_rwlock_unlock((pthread_rwlock_t*)&tracker->lock);

    return count;
}

bool
sol_vote_tracker_is_slot_confirmed(const sol_vote_tracker_t* tracker,
                                    sol_slot_t slot) {
    if (!tracker) return false;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&tracker->lock);

    bool confirmed = false;
    for (size_t i = 0; i < tracker->num_slots; i++) {
        if (tracker->slot_votes[i].slot == slot) {
            confirmed = tracker->slot_votes[i].confirmed;
            break;
        }
    }

    pthread_rwlock_unlock((pthread_rwlock_t*)&tracker->lock);

    return confirmed;
}

bool
sol_vote_tracker_is_slot_finalized(const sol_vote_tracker_t* tracker,
                                    sol_slot_t slot) {
    if (!tracker) return false;

    pthread_rwlock_rdlock((pthread_rwlock_t*)&tracker->lock);

    bool finalized = false;
    for (size_t i = 0; i < tracker->num_slots; i++) {
        if (tracker->slot_votes[i].slot == slot) {
            finalized = tracker->slot_votes[i].finalized;
            break;
        }
    }

    pthread_rwlock_unlock((pthread_rwlock_t*)&tracker->lock);

    return finalized;
}
