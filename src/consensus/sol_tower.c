/*
 * sol_tower.c - Tower BFT Consensus Implementation
 */

#include "sol_tower.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Tower internal state
 */
struct sol_tower {
    sol_tower_config_t  config;

    /* Vote stack */
    sol_lockout_t       votes[SOL_MAX_LOCKOUT_HISTORY];
    size_t              num_votes;

    /* Last vote */
    sol_slot_t          last_voted_slot;
    sol_hash_t          last_voted_hash;

    /* Root */
    sol_slot_t          root_slot;
    sol_hash_t          root_hash;

    /* Epoch tracking */
    sol_epoch_t         epoch;
    uint64_t            credits;

    pthread_mutex_t     lock;
};

/*
 * Pop expired votes from the stack
 *
 * Removes votes whose lockout has expired, allowing fork switches.
 * Also advances root if the oldest vote would have sufficient confirmations.
 */
static void
pop_expired_votes(sol_tower_t* tower, sol_slot_t current_slot) {
    if (tower->num_votes == 0) {
        return;
    }

    /* First, check if oldest vote(s) should become root based on confirmation */
    while (tower->num_votes > 0 &&
           tower->votes[0].confirmation_count >= SOL_MAX_LOCKOUT_HISTORY) {
        /* Advance root to this vote */
        tower->root_slot = tower->votes[0].slot;

        /* Remove from stack */
        memmove(&tower->votes[0], &tower->votes[1],
                (tower->num_votes - 1) * sizeof(sol_lockout_t));
        tower->num_votes--;
    }

    /* Now pop expired votes from the top of the stack */
    while (tower->num_votes > 0) {
        sol_lockout_t* top = &tower->votes[tower->num_votes - 1];
        if (!sol_lockout_expired(top, current_slot)) {
            break;
        }

        /* This vote has expired, pop it */
        tower->num_votes--;
    }

    /* If all votes expired, log it */
    if (tower->num_votes == 0 && tower->last_voted_slot > 0) {
        sol_log_debug("All tower votes expired at slot %lu",
                      (unsigned long)current_slot);
    }
}

/*
 * Check if we can switch to a new slot
 */
static bool
can_switch(sol_tower_t* tower, sol_slot_t new_slot) {
    if (tower->config.disable_lockout) {
        return true;
    }

    /* Check if any vote would lock us out */
    for (size_t i = 0; i < tower->num_votes; i++) {
        sol_lockout_t* vote = &tower->votes[i];

        /* If the new slot is before our vote, we're locked out */
        if (new_slot < vote->slot) {
            uint64_t lockout = sol_lockout_duration(vote->confirmation_count);
            if (new_slot < vote->slot + lockout) {
                return false;
            }
        }
    }

    return true;
}

/*
 * Find common ancestor between vote stack and new slot
 */
static size_t
find_common_ancestor(sol_tower_t* tower, sol_slot_t slot) {
    /* Find how many votes need to be popped */
    for (size_t i = tower->num_votes; i > 0; i--) {
        if (tower->votes[i-1].slot <= slot) {
            return i;
        }
    }
    return 0;
}

/*
 * Apply a new vote to the stack
 */
static sol_err_t
apply_vote_internal(sol_tower_t* tower, sol_slot_t slot) {
    /* Pop votes that are on a different fork */
    size_t common = find_common_ancestor(tower, slot);
    tower->num_votes = common;

    /* First pass: increment confirmation count for all remaining votes */
    for (size_t i = 0; i < tower->num_votes; i++) {
        tower->votes[i].confirmation_count++;
    }

    /* Second pass: check for root advancement (oldest votes first) */
    while (tower->num_votes > 0 &&
           tower->votes[0].confirmation_count >= SOL_MAX_LOCKOUT_HISTORY) {
        /* Oldest vote becomes root */
        tower->root_slot = tower->votes[0].slot;

        /* Remove this vote */
        memmove(&tower->votes[0], &tower->votes[1],
                (tower->num_votes - 1) * sizeof(sol_lockout_t));
        tower->num_votes--;
    }

    /* Push new vote */
    if (tower->num_votes < SOL_MAX_LOCKOUT_HISTORY) {
        tower->votes[tower->num_votes].slot = slot;
        tower->votes[tower->num_votes].confirmation_count = 1;
        tower->num_votes++;
    }

    tower->last_voted_slot = slot;
    tower->credits++;

    return SOL_OK;
}

/*
 * Create tower
 */
sol_tower_t*
sol_tower_new(const sol_tower_config_t* config) {
    sol_tower_t* tower = sol_calloc(1, sizeof(sol_tower_t));
    if (!tower) return NULL;

    if (config) {
        tower->config = *config;
    } else {
        tower->config = (sol_tower_config_t)SOL_TOWER_CONFIG_DEFAULT;
    }

    pthread_mutex_init(&tower->lock, NULL);

    return tower;
}

/*
 * Destroy tower
 */
void
sol_tower_destroy(sol_tower_t* tower) {
    if (!tower) return;

    pthread_mutex_destroy(&tower->lock);
    sol_free(tower);
}

/*
 * Initialize from vote state
 */
sol_err_t
sol_tower_initialize(sol_tower_t* tower, const sol_vote_state_t* vote_state) {
    if (!tower || !vote_state) return SOL_ERR_INVAL;

    pthread_mutex_lock(&tower->lock);

    /* Copy votes */
    tower->num_votes = vote_state->votes_len;
    if (tower->num_votes > SOL_MAX_LOCKOUT_HISTORY) {
        tower->num_votes = SOL_MAX_LOCKOUT_HISTORY;
    }
    memcpy(tower->votes, vote_state->votes,
           tower->num_votes * sizeof(sol_lockout_t));

    /* Copy root */
    tower->root_slot = vote_state->root_slot;
    memset(&tower->root_hash, 0, sizeof(tower->root_hash));  /* Not in new vote state */

    /* Copy last vote */
    if (tower->num_votes > 0) {
        tower->last_voted_slot = tower->votes[tower->num_votes - 1].slot;
    }

    /* Epoch/credits tracked separately in epoch_credits array */
    tower->epoch = 0;
    tower->credits = 0;

    pthread_mutex_unlock(&tower->lock);

    sol_log_info("Tower initialized: root=%lu, votes=%zu",
                 (unsigned long)tower->root_slot, tower->num_votes);

    return SOL_OK;
}

/*
 * Check if we should vote
 */
sol_vote_decision_t
sol_tower_check_vote(sol_tower_t* tower, sol_slot_t slot,
                      const sol_bank_t* bank,
                      const sol_fork_choice_t* fork_choice) {
    if (!tower) return SOL_VOTE_DECISION_SKIP;

    pthread_mutex_lock(&tower->lock);

    /* Don't vote for slots we've already voted for */
    if (slot <= tower->last_voted_slot) {
        pthread_mutex_unlock(&tower->lock);
        return SOL_VOTE_DECISION_SKIP;
    }

    /* Pop expired votes */
    pop_expired_votes(tower, slot);

    /* Check if we're locked out */
    if (!can_switch(tower, slot)) {
        pthread_mutex_unlock(&tower->lock);
        return SOL_VOTE_DECISION_LOCKOUT;
    }

    /* Check threshold if we have enough votes */
    if (tower->num_votes >= tower->config.threshold_depth) {
        sol_lockout_t* threshold_vote = &tower->votes[tower->num_votes - tower->config.threshold_depth];
        if (threshold_vote->confirmation_count < tower->config.threshold_size) {
            pthread_mutex_unlock(&tower->lock);
            return SOL_VOTE_DECISION_WAIT;
        }
    }

    /* Duplicate-slot safety: only vote the current fork-choice best bank. */
    if (bank && fork_choice) {
        sol_slot_t best_slot = 0;
        sol_hash_t best_hash = {0};
        if (sol_fork_choice_best_bank((sol_fork_choice_t*)fork_choice, &best_slot, &best_hash)) {
            sol_hash_t bank_hash = {0};
            sol_bank_compute_hash((sol_bank_t*)bank, &bank_hash);

            if (best_slot != slot ||
                memcmp(best_hash.bytes, bank_hash.bytes, SOL_HASH_SIZE) != 0) {
                pthread_mutex_unlock(&tower->lock);
                return SOL_VOTE_DECISION_WAIT;
            }
        }
    }

    pthread_mutex_unlock(&tower->lock);
    return SOL_VOTE_DECISION_VOTE;
}

/*
 * Record a vote
 */
sol_err_t
sol_tower_record_vote(sol_tower_t* tower, sol_slot_t slot, const sol_hash_t* hash) {
    if (!tower) return SOL_ERR_INVAL;

    pthread_mutex_lock(&tower->lock);

    sol_err_t err = apply_vote_internal(tower, slot);
    if (err == SOL_OK && hash) {
        tower->last_voted_hash = *hash;
    }

    pthread_mutex_unlock(&tower->lock);

    if (err == SOL_OK) {
        sol_log_debug("Recorded vote for slot %lu (stack depth: %zu)",
                      (unsigned long)slot, tower->num_votes);
    }

    return err;
}

/*
 * Record bank vote
 */
sol_err_t
sol_tower_record_bank_vote(sol_tower_t* tower, const sol_bank_t* bank) {
    if (!tower || !bank) return SOL_ERR_INVAL;

    sol_slot_t slot = sol_bank_slot(bank);
    sol_hash_t hash = {0};
    sol_bank_compute_hash((sol_bank_t*)bank, &hash);

    return sol_tower_record_vote(tower, slot, &hash);
}

/*
 * Get lockout for a slot
 */
uint64_t
sol_tower_lockout(const sol_tower_t* tower, sol_slot_t slot) {
    if (!tower) return 0;

    pthread_mutex_lock((pthread_mutex_t*)&tower->lock);

    for (size_t i = 0; i < tower->num_votes; i++) {
        if (tower->votes[i].slot == slot) {
            uint64_t lockout = sol_lockout_duration(tower->votes[i].confirmation_count);
            pthread_mutex_unlock((pthread_mutex_t*)&tower->lock);
            return lockout;
        }
    }

    pthread_mutex_unlock((pthread_mutex_t*)&tower->lock);
    return 0;
}

/*
 * Check if would be locked out
 */
bool
sol_tower_would_be_locked_out(const sol_tower_t* tower, sol_slot_t slot) {
    if (!tower) return false;

    pthread_mutex_lock((pthread_mutex_t*)&tower->lock);
    bool locked = !can_switch((sol_tower_t*)tower, slot);
    pthread_mutex_unlock((pthread_mutex_t*)&tower->lock);

    return locked;
}

/*
 * Get last voted slot
 */
sol_slot_t
sol_tower_last_voted_slot(const sol_tower_t* tower) {
    if (!tower) return 0;
    return tower->last_voted_slot;
}

/*
 * Get last voted hash
 */
sol_hash_t
sol_tower_last_voted_hash(const sol_tower_t* tower) {
    sol_hash_t hash = {0};
    if (tower) hash = tower->last_voted_hash;
    return hash;
}

/*
 * Get root slot
 */
sol_slot_t
sol_tower_root(const sol_tower_t* tower) {
    if (!tower) return 0;
    return tower->root_slot;
}

/*
 * Get vote stack
 */
size_t
sol_tower_vote_stack(const sol_tower_t* tower, sol_lockout_t* out_votes, size_t max_votes) {
    if (!tower || !out_votes) return 0;

    pthread_mutex_lock((pthread_mutex_t*)&tower->lock);

    size_t count = tower->num_votes;
    if (count > max_votes) count = max_votes;

    memcpy(out_votes, tower->votes, count * sizeof(sol_lockout_t));

    pthread_mutex_unlock((pthread_mutex_t*)&tower->lock);
    return count;
}

/*
 * Check if voted for slot
 */
bool
sol_tower_has_voted(const sol_tower_t* tower, sol_slot_t slot) {
    if (!tower) return false;

    pthread_mutex_lock((pthread_mutex_t*)&tower->lock);

    for (size_t i = 0; i < tower->num_votes; i++) {
        if (tower->votes[i].slot == slot) {
            pthread_mutex_unlock((pthread_mutex_t*)&tower->lock);
            return true;
        }
    }

    pthread_mutex_unlock((pthread_mutex_t*)&tower->lock);
    return false;
}

/*
 * Get threshold confirmation
 */
uint32_t
sol_tower_threshold_confirmation(const sol_tower_t* tower) {
    if (!tower) return 0;

    pthread_mutex_lock((pthread_mutex_t*)&tower->lock);

    uint32_t conf = 0;
    if (tower->num_votes >= tower->config.threshold_depth) {
        conf = tower->votes[tower->num_votes - tower->config.threshold_depth].confirmation_count;
    }

    pthread_mutex_unlock((pthread_mutex_t*)&tower->lock);
    return conf;
}

/*
 * Get vote state
 */
sol_err_t
sol_tower_get_vote_state(const sol_tower_t* tower, sol_vote_state_t* out_state) {
    if (!tower || !out_state) return SOL_ERR_INVAL;

    pthread_mutex_lock((pthread_mutex_t*)&tower->lock);

    memset(out_state, 0, sizeof(*out_state));

    out_state->node_pubkey = tower->config.node_identity;
    out_state->root_slot = tower->root_slot;
    out_state->has_root = (tower->root_slot > 0);

    /* Copy votes - cap at max */
    size_t vote_count = tower->num_votes;
    if (vote_count > SOL_MAX_LOCKOUT_HISTORY) {
        vote_count = SOL_MAX_LOCKOUT_HISTORY;
    }
    out_state->votes_len = (uint8_t)vote_count;
    memcpy(out_state->votes, tower->votes, vote_count * sizeof(sol_lockout_t));

    pthread_mutex_unlock((pthread_mutex_t*)&tower->lock);
    return SOL_OK;
}

/*
 * Apply vote to vote state
 */
sol_err_t
sol_tower_apply_vote(sol_vote_state_t* state, sol_slot_t slot, const sol_hash_t* hash) {
    (void)hash;  /* Not stored in current vote state version */
    if (!state) return SOL_ERR_INVAL;

    /* Pop votes on different fork */
    while (state->votes_len > 0 && state->votes[state->votes_len - 1].slot >= slot) {
        state->votes_len--;
    }

    /* Increment confirmations */
    for (size_t i = 0; i < state->votes_len; i++) {
        state->votes[i].confirmation_count++;

        /* Check for root */
        if (state->votes[i].confirmation_count >= SOL_MAX_LOCKOUT_HISTORY) {
            state->root_slot = state->votes[i].slot;
            state->has_root = true;

            uint8_t new_count = state->votes_len - (uint8_t)i - 1;
            memmove(&state->votes[0], &state->votes[i + 1],
                    new_count * sizeof(sol_lockout_t));
            state->votes_len = new_count;
            i = (size_t)-1;
        }
    }

    /* Push new vote */
    if (state->votes_len < SOL_MAX_LOCKOUT_HISTORY) {
        state->votes[state->votes_len].slot = slot;
        state->votes[state->votes_len].confirmation_count = 1;
        state->votes_len++;
    }

    return SOL_OK;
}

/*
 * Process confirmation
 */
sol_err_t
sol_tower_process_confirmation(sol_tower_t* tower, sol_slot_t slot) {
    if (!tower) return SOL_ERR_INVAL;

    pthread_mutex_lock(&tower->lock);

    for (size_t i = 0; i < tower->num_votes; i++) {
        if (tower->votes[i].slot == slot) {
            tower->votes[i].confirmation_count++;

            /* Check for root */
            if (tower->votes[i].confirmation_count >= SOL_MAX_LOCKOUT_HISTORY) {
                tower->root_slot = slot;

                /* Remove this and older votes */
                size_t new_count = tower->num_votes - i - 1;
                memmove(&tower->votes[0], &tower->votes[i + 1],
                        new_count * sizeof(sol_lockout_t));
                tower->num_votes = new_count;
            }
            break;
        }
    }

    pthread_mutex_unlock(&tower->lock);
    return SOL_OK;
}

/*
 * Refresh tower state
 */
void
sol_tower_refresh(sol_tower_t* tower, sol_slot_t current_slot) {
    if (!tower) return;

    pthread_mutex_lock(&tower->lock);

    size_t old_num_votes = tower->num_votes;
    sol_slot_t old_root = tower->root_slot;

    pop_expired_votes(tower, current_slot);

    if (tower->num_votes != old_num_votes || tower->root_slot != old_root) {
        sol_log_debug("Tower refreshed at slot %lu: votes %zu -> %zu, root %lu -> %lu",
                      (unsigned long)current_slot,
                      old_num_votes, tower->num_votes,
                      (unsigned long)old_root, (unsigned long)tower->root_slot);
    }

    pthread_mutex_unlock(&tower->lock);
}

/* Vote state serialize/deserialize functions are in sol_vote_program.c */

#define SOL_TOWER_FILE_MAGIC "SOLTOWER"
#define SOL_TOWER_FILE_MAGIC_LEN 8
#define SOL_TOWER_FILE_VERSION 1u

static sol_err_t
write_all(int fd, const void* buf, size_t len) {
    const uint8_t* p = (const uint8_t*)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, p + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return SOL_ERR_IO;
        }
        off += (size_t)w;
    }
    return SOL_OK;
}

static sol_err_t
read_all(int fd, void* buf, size_t len) {
    uint8_t* p = (uint8_t*)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, p + off, len - off);
        if (r < 0) {
            if (errno == EINTR) continue;
            return SOL_ERR_IO;
        }
        if (r == 0) {
            return SOL_ERR_TRUNCATED;
        }
        off += (size_t)r;
    }
    return SOL_OK;
}

static void
tower_snapshot_locked(const sol_tower_t* tower,
                      sol_vote_state_t* out_state,
                      sol_hash_t* out_last_hash) {
    memset(out_state, 0, sizeof(*out_state));
    out_state->node_pubkey = tower->config.node_identity;
    out_state->root_slot = tower->root_slot;
    out_state->has_root = (tower->root_slot > 0);

    size_t vote_count = tower->num_votes;
    if (vote_count > SOL_MAX_LOCKOUT_HISTORY) vote_count = SOL_MAX_LOCKOUT_HISTORY;
    out_state->votes_len = (uint8_t)vote_count;
    memcpy(out_state->votes, tower->votes, vote_count * sizeof(sol_lockout_t));

    *out_last_hash = tower->last_voted_hash;
}

static sol_err_t
tower_apply_loaded_state(sol_tower_t* tower,
                         const sol_vote_state_t* state,
                         const sol_hash_t* last_hash) {
    if (!tower || !state || !last_hash) return SOL_ERR_INVAL;

    pthread_mutex_lock(&tower->lock);

    tower->num_votes = state->votes_len;
    if (tower->num_votes > SOL_MAX_LOCKOUT_HISTORY) {
        tower->num_votes = SOL_MAX_LOCKOUT_HISTORY;
    }
    memcpy(tower->votes, state->votes, tower->num_votes * sizeof(sol_lockout_t));

    tower->root_slot = state->root_slot;
    memset(&tower->root_hash, 0, sizeof(tower->root_hash));

    if (tower->num_votes > 0) {
        tower->last_voted_slot = tower->votes[tower->num_votes - 1].slot;
    } else {
        tower->last_voted_slot = 0;
    }
    tower->last_voted_hash = *last_hash;

    pthread_mutex_unlock(&tower->lock);
    return SOL_OK;
}

sol_err_t
sol_tower_save_file(const sol_tower_t* tower, const char* path) {
    if (!tower || !path || path[0] == '\0') return SOL_ERR_INVAL;

    sol_vote_state_t state;
    sol_hash_t last_hash;

    pthread_mutex_lock((pthread_mutex_t*)&tower->lock);
    tower_snapshot_locked(tower, &state, &last_hash);
    pthread_mutex_unlock((pthread_mutex_t*)&tower->lock);

    uint8_t* buf = sol_alloc(SOL_VOTE_STATE_SIZE + 1024);
    if (!buf) return SOL_ERR_NOMEM;

    size_t state_len = 0;
    sol_err_t err = sol_vote_state_serialize(&state, buf, SOL_VOTE_STATE_SIZE + 1024, &state_len);
    if (err != SOL_OK) {
        sol_free(buf);
        return err;
    }

    char tmp_path[PATH_MAX];
    int n = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
    if (n < 0 || (size_t)n >= sizeof(tmp_path)) {
        sol_free(buf);
        return SOL_ERR_INVAL;
    }

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        sol_free(buf);
        return SOL_ERR_IO;
    }

    /* Header */
    uint32_t version = SOL_TOWER_FILE_VERSION;
    uint32_t state_len_u32 = (uint32_t)state_len;

    err = write_all(fd, SOL_TOWER_FILE_MAGIC, SOL_TOWER_FILE_MAGIC_LEN);
    if (err == SOL_OK) err = write_all(fd, &version, sizeof(version));
    if (err == SOL_OK) err = write_all(fd, last_hash.bytes, SOL_HASH_SIZE);
    if (err == SOL_OK) err = write_all(fd, &state_len_u32, sizeof(state_len_u32));
    if (err == SOL_OK) err = write_all(fd, buf, state_len);

    sol_free(buf);

    if (err != SOL_OK) {
        (void)close(fd);
        (void)unlink(tmp_path);
        return err;
    }

    if (fsync(fd) != 0) {
        (void)close(fd);
        (void)unlink(tmp_path);
        return SOL_ERR_IO;
    }

    if (close(fd) != 0) {
        (void)unlink(tmp_path);
        return SOL_ERR_IO;
    }

    if (rename(tmp_path, path) != 0) {
        (void)unlink(tmp_path);
        return SOL_ERR_IO;
    }

    return SOL_OK;
}

sol_err_t
sol_tower_load_file(sol_tower_t* tower, const char* path) {
    if (!tower || !path || path[0] == '\0') return SOL_ERR_INVAL;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return (errno == ENOENT) ? SOL_ERR_NOTFOUND : SOL_ERR_IO;
    }

    char magic[SOL_TOWER_FILE_MAGIC_LEN];
    uint32_t version = 0;
    sol_hash_t last_hash;
    uint32_t state_len_u32 = 0;

    sol_err_t err = read_all(fd, magic, sizeof(magic));
    if (err == SOL_OK && memcmp(magic, SOL_TOWER_FILE_MAGIC, sizeof(magic)) != 0) {
        err = SOL_ERR_MALFORMED;
    }
    if (err == SOL_OK) err = read_all(fd, &version, sizeof(version));
    if (err == SOL_OK && version != SOL_TOWER_FILE_VERSION) {
        err = SOL_ERR_UNSUPPORTED;
    }
    if (err == SOL_OK) err = read_all(fd, last_hash.bytes, SOL_HASH_SIZE);
    if (err == SOL_OK) err = read_all(fd, &state_len_u32, sizeof(state_len_u32));

    if (err != SOL_OK) {
        (void)close(fd);
        return err;
    }

    size_t state_len = state_len_u32;
    if (state_len == 0 || state_len > (SOL_VOTE_STATE_SIZE + 1024)) {
        (void)close(fd);
        return SOL_ERR_MALFORMED;
    }

    uint8_t* buf = sol_alloc(state_len);
    if (!buf) {
        (void)close(fd);
        return SOL_ERR_NOMEM;
    }

    err = read_all(fd, buf, state_len);
    (void)close(fd);
    if (err != SOL_OK) {
        sol_free(buf);
        return err;
    }

    sol_vote_state_t state;
    err = sol_vote_state_deserialize(&state, buf, state_len);
    sol_free(buf);
    if (err != SOL_OK) {
        return err;
    }

    return tower_apply_loaded_state(tower, &state, &last_hash);
}
