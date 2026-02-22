/*
 * sol_leader_schedule.c - Leader Schedule Implementation
 */

#include "sol_leader_schedule.h"
#include "../util/sol_alloc.h"
#include "../util/sol_bits.h"
#include "../util/sol_log.h"
#include "../programs/sol_vote_program.h"
#include "../programs/sol_stake_program.h"
#include <string.h>
#include <stdlib.h>

/*
 * Leader schedule structure
 */
struct sol_leader_schedule {
    sol_leader_schedule_config_t    config;
    uint64_t                        epoch;
    sol_slot_t                      first_slot;
    sol_slot_t                      last_slot;

    /* Schedule array - one entry per slot */
    sol_pubkey_t*                   leaders;
    size_t                          num_slots;

    /* Unique leaders for quick lookup */
    sol_pubkey_t*                   unique_leaders;
    size_t                          num_unique_leaders;
};

/*
 * Comparison function for stake sorting (descending)
 */
static int
stake_compare(const void* a, const void* b) {
    const sol_stake_weight_t* wa = (const sol_stake_weight_t*)a;
    const sol_stake_weight_t* wb = (const sol_stake_weight_t*)b;

    if (wb->stake > wa->stake) return 1;
    if (wb->stake < wa->stake) return -1;

    /* Tie-breaker: sort by pubkey */
    return memcmp(wb->pubkey.bytes, wa->pubkey.bytes, 32);
}

/*
 * ChaCha20 quarter round
 */
#define CHACHA_ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define CHACHA_QR(a, b, c, d) do {  \
    a += b; d ^= a; d = CHACHA_ROTL32(d, 16); \
    c += d; b ^= c; b = CHACHA_ROTL32(b, 12); \
    a += b; d ^= a; d = CHACHA_ROTL32(d, 8);  \
    c += d; b ^= c; b = CHACHA_ROTL32(b, 7);  \
} while(0)

/*
 * ChaCha20 RNG state
 */
typedef struct {
    uint32_t state[16];     /* ChaCha state */
    uint32_t output[16];    /* Current output block */
    size_t   index;         /* Index into output block */
} chacha_rng_t;

/*
 * Initialize ChaCha20 RNG from 32-byte seed
 */
static void
chacha_rng_init(chacha_rng_t* rng, const uint8_t seed[32]) {
    /* ChaCha constants: "expand 32-byte k" */
    rng->state[0] = 0x61707865;
    rng->state[1] = 0x3320646e;
    rng->state[2] = 0x79622d32;
    rng->state[3] = 0x6b206574;

    /* Key (seed) - 8 words */
    for (int i = 0; i < 8; i++) {
        rng->state[4 + i] = ((uint32_t)seed[i*4]) |
                           ((uint32_t)seed[i*4 + 1] << 8) |
                           ((uint32_t)seed[i*4 + 2] << 16) |
                           ((uint32_t)seed[i*4 + 3] << 24);
    }

    /* Counter starts at 0 */
    rng->state[12] = 0;
    rng->state[13] = 0;

    /* Nonce (zeros for deterministic RNG) */
    rng->state[14] = 0;
    rng->state[15] = 0;

    rng->index = 16;  /* Force generation of first block */
}

/*
 * Generate ChaCha20 block
 */
static void
chacha_block(chacha_rng_t* rng) {
    uint32_t x[16];

    /* Copy state to working buffer */
    memcpy(x, rng->state, sizeof(x));

    /* 20 rounds (10 double-rounds) */
    for (int i = 0; i < 10; i++) {
        /* Column rounds */
        CHACHA_QR(x[0], x[4], x[8],  x[12]);
        CHACHA_QR(x[1], x[5], x[9],  x[13]);
        CHACHA_QR(x[2], x[6], x[10], x[14]);
        CHACHA_QR(x[3], x[7], x[11], x[15]);
        /* Diagonal rounds */
        CHACHA_QR(x[0], x[5], x[10], x[15]);
        CHACHA_QR(x[1], x[6], x[11], x[12]);
        CHACHA_QR(x[2], x[7], x[8],  x[13]);
        CHACHA_QR(x[3], x[4], x[9],  x[14]);
    }

    /* Add original state */
    for (int i = 0; i < 16; i++) {
        rng->output[i] = x[i] + rng->state[i];
    }

    /* Increment counter */
    rng->state[12]++;
    if (rng->state[12] == 0) {
        rng->state[13]++;  /* Handle overflow */
    }

    rng->index = 0;
}

/*
 * Generate random uint64 from ChaCha20 RNG
 */
static uint64_t
chacha_rng_next_u64(chacha_rng_t* rng) {
    /* Generate new block if needed */
    if (rng->index >= 16) {
        chacha_block(rng);
    }

    /* Take two uint32s to make uint64 */
    uint64_t lo = rng->output[rng->index++];
    if (rng->index >= 16) {
        chacha_block(rng);
    }
    uint64_t hi = rng->output[rng->index++];

    return lo | (hi << 32);
}

/*
 * Generate an unbiased random uint64 in range [0, upper).
 *
 * This uses Lemire's method to match `rand`-style bounded sampling.
 */
static uint64_t
chacha_rng_next_u64_bounded(chacha_rng_t* rng, uint64_t upper) {
    if (upper == 0) return 0;

    uint64_t x = chacha_rng_next_u64(rng);
    __uint128_t m = (__uint128_t)x * (__uint128_t)upper;
    uint64_t l = (uint64_t)m;

    if (l < upper) {
        uint64_t t = (uint64_t)(-upper) % upper;
        while (l < t) {
            x = chacha_rng_next_u64(rng);
            m = (__uint128_t)x * (__uint128_t)upper;
            l = (uint64_t)m;
        }
    }

    return (uint64_t)(m >> 64);
}

sol_leader_schedule_t*
sol_leader_schedule_new(uint64_t epoch,
                         const sol_stake_weight_t* stakes,
                         size_t stakes_len,
                         const sol_leader_schedule_config_t* config) {
    if (!stakes || stakes_len == 0) {
        return NULL;
    }

    sol_leader_schedule_t* schedule = sol_calloc(1, sizeof(sol_leader_schedule_t));
    if (!schedule) return NULL;

    if (config) {
        schedule->config = *config;
    } else {
        schedule->config = (sol_leader_schedule_config_t)SOL_LEADER_SCHEDULE_CONFIG_DEFAULT;
    }

    schedule->epoch = epoch;
    schedule->num_slots = schedule->config.slots_per_epoch;
    schedule->first_slot = epoch * schedule->config.slots_per_epoch;
    schedule->last_slot = schedule->first_slot + schedule->num_slots - 1;

    /* Allocate leaders array */
    schedule->leaders = sol_calloc(schedule->num_slots, sizeof(sol_pubkey_t));
    if (!schedule->leaders) {
        sol_free(schedule);
        return NULL;
    }

    /* Copy and sort stakes by weight (descending) */
    sol_stake_weight_t* sorted_stakes = sol_calloc(stakes_len, sizeof(sol_stake_weight_t));
    if (!sorted_stakes) {
        sol_free(schedule->leaders);
        sol_free(schedule);
        return NULL;
    }
    memcpy(sorted_stakes, stakes, stakes_len * sizeof(sol_stake_weight_t));
    qsort(sorted_stakes, stakes_len, sizeof(sol_stake_weight_t), stake_compare);

    /* Match Agave: remove exact duplicate (pubkey, stake) entries */
    size_t unique_stakes_len = 0;
    for (size_t i = 0; i < stakes_len; i++) {
        if (unique_stakes_len == 0) {
            sorted_stakes[unique_stakes_len++] = sorted_stakes[i];
            continue;
        }

        const sol_stake_weight_t* prev = &sorted_stakes[unique_stakes_len - 1];
        const sol_stake_weight_t* cur  = &sorted_stakes[i];
        if (prev->stake == cur->stake &&
            memcmp(prev->pubkey.bytes, cur->pubkey.bytes, 32) == 0) {
            continue;
        }

        sorted_stakes[unique_stakes_len++] = *cur;
    }
    stakes_len = unique_stakes_len;

    /* Calculate total stake */
    uint64_t total_stake = 0;
    uint64_t* cumulative_stakes = sol_calloc(stakes_len, sizeof(uint64_t));
    if (!cumulative_stakes) {
        sol_free(sorted_stakes);
        sol_free(schedule->leaders);
        sol_free(schedule);
        return NULL;
    }
    for (size_t i = 0; i < stakes_len; i++) {
        total_stake += sorted_stakes[i].stake;
        cumulative_stakes[i] = total_stake;
    }

    if (total_stake == 0) {
        sol_free(cumulative_stakes);
        sol_free(sorted_stakes);
        sol_free(schedule->leaders);
        sol_free(schedule);
        return NULL;
    }

    /*
     * Generate leader schedule using stake-weighted selection.
     *
     * Algorithm:
     * 1. Create seed from epoch using LE bytes (epoch in first 8 bytes, rest zero)
     * 2. Initialize ChaCha20 RNG with the seed
     * 3. For each slot group (4 slots per leader):
     *    - Generate random number using ChaCha20
     *    - Select leader based on stake weight
     */

    /* Initialize ChaCha20 RNG with the 32-byte seed */
    uint8_t seed[32] = {0};
    uint64_t epoch_le = sol_htole64(epoch);
    memcpy(seed, &epoch_le, sizeof(epoch_le));

    chacha_rng_t rng;
    chacha_rng_init(&rng, seed);

    /* Generate schedule */
    size_t slot_offset = schedule->config.leader_schedule_slot_offset;
    size_t num_leader_slots = (schedule->num_slots + slot_offset - 1) / slot_offset;

    for (size_t i = 0; i < num_leader_slots; i++) {
        /* Generate random stake point using ChaCha20 */
        uint64_t stake_point = chacha_rng_next_u64_bounded(&rng, total_stake);

        /* Find leader for this stake point (first cumulative > stake_point) */
        size_t lo = 0;
        size_t hi = stakes_len;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (stake_point < cumulative_stakes[mid]) {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        size_t leader_idx = lo < stakes_len ? lo : (stakes_len - 1);

        /* Assign leader to slots */
        for (size_t s = 0; s < slot_offset && (i * slot_offset + s) < schedule->num_slots; s++) {
            schedule->leaders[i * slot_offset + s] = sorted_stakes[leader_idx].pubkey;
        }
    }

    /* Build unique leaders list */
    schedule->unique_leaders = sol_calloc(stakes_len, sizeof(sol_pubkey_t));
    if (schedule->unique_leaders) {
        sol_pubkey_map_t* seen = sol_pubkey_map_new(sizeof(uint8_t), stakes_len * 2);
        if (seen) {
            uint8_t one = 1;
            for (size_t i = 0; i < stakes_len; i++) {
                if (sol_pubkey_map_get(seen, &sorted_stakes[i].pubkey)) {
                    continue;
                }
                (void)sol_pubkey_map_insert(seen, &sorted_stakes[i].pubkey, &one);
                schedule->unique_leaders[schedule->num_unique_leaders++] =
                    sorted_stakes[i].pubkey;
            }
            sol_pubkey_map_destroy(seen);
        } else {
            /* Fallback */
            for (size_t i = 0; i < stakes_len; i++) {
                bool found = false;
                for (size_t j = 0; j < schedule->num_unique_leaders; j++) {
                    if (sol_pubkey_eq(&sorted_stakes[i].pubkey,
                                      &schedule->unique_leaders[j])) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    schedule->unique_leaders[schedule->num_unique_leaders++] =
                        sorted_stakes[i].pubkey;
                }
            }
        }
    }

    sol_free(cumulative_stakes);
    sol_free(sorted_stakes);
    return schedule;
}

sol_leader_schedule_t*
sol_leader_schedule_from_slot_leaders(sol_slot_t first_slot,
                                      const sol_pubkey_t* leaders,
                                      size_t leaders_len) {
    if (!leaders || leaders_len == 0) {
        return NULL;
    }

    sol_leader_schedule_t* schedule = sol_calloc(1, sizeof(sol_leader_schedule_t));
    if (!schedule) return NULL;

    schedule->config = (sol_leader_schedule_config_t)SOL_LEADER_SCHEDULE_CONFIG_DEFAULT;
    schedule->epoch = (uint64_t)(first_slot / schedule->config.slots_per_epoch);
    schedule->first_slot = first_slot;
    schedule->num_slots = leaders_len;
    schedule->last_slot = first_slot + (sol_slot_t)leaders_len - 1;

    schedule->leaders = sol_calloc(schedule->num_slots, sizeof(sol_pubkey_t));
    if (!schedule->leaders) {
        sol_free(schedule);
        return NULL;
    }
    memcpy(schedule->leaders, leaders, schedule->num_slots * sizeof(sol_pubkey_t));

    /* Build unique leaders list (best-effort). */
    schedule->unique_leaders = sol_calloc(leaders_len, sizeof(sol_pubkey_t));
    if (schedule->unique_leaders) {
        sol_pubkey_map_t* seen = sol_pubkey_map_new(sizeof(uint8_t), 8192);
        if (seen) {
            uint8_t one = 1;
            for (size_t i = 0; i < leaders_len; i++) {
                if (sol_pubkey_map_get(seen, &leaders[i])) {
                    continue;
                }
                (void)sol_pubkey_map_insert(seen, &leaders[i], &one);
                schedule->unique_leaders[schedule->num_unique_leaders++] = leaders[i];
            }
            sol_pubkey_map_destroy(seen);
        } else {
            /* Fallback */
            for (size_t i = 0; i < leaders_len; i++) {
                bool found = false;
                for (size_t j = 0; j < schedule->num_unique_leaders; j++) {
                    if (sol_pubkey_eq(&leaders[i], &schedule->unique_leaders[j])) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    schedule->unique_leaders[schedule->num_unique_leaders++] = leaders[i];
                }
            }
        }
    }

    return schedule;
}

/*
 * Context for stake extraction iteration
 */
typedef struct {
    sol_bank_t*         bank;
    uint64_t            current_epoch;
    const sol_pubkey_map_t* vote_stakes;
    sol_stake_weight_t* weights;
    size_t              num_weights;
    size_t              capacity;
} stake_extract_ctx_t;

/*
 * Find or add a validator to the weights array
 */
static sol_stake_weight_t*
find_or_add_validator(stake_extract_ctx_t* ctx, const sol_pubkey_t* node_pubkey) {
    /* Search existing */
    for (size_t i = 0; i < ctx->num_weights; i++) {
        if (sol_pubkey_eq(&ctx->weights[i].pubkey, node_pubkey)) {
            return &ctx->weights[i];
        }
    }

    /* Add new if capacity allows */
    if (ctx->num_weights >= ctx->capacity) {
        return NULL;
    }

    sol_stake_weight_t* entry = &ctx->weights[ctx->num_weights++];
    entry->pubkey = *node_pubkey;
    entry->stake = 0;
    return entry;
}

/*
 * Callback to extract vote accounts and their stake
 */
static bool
extract_vote_accounts_callback(const sol_pubkey_t* pubkey,
                               const sol_account_t* account,
                               void* ctx) {
    stake_extract_ctx_t* extract_ctx = (stake_extract_ctx_t*)ctx;

    /* Only process vote program accounts */
    if (!sol_pubkey_eq(&account->meta.owner, &SOL_VOTE_PROGRAM_ID)) {
        return true;  /* Continue */
    }

    /* Deserialize vote state to get node identity */
    sol_vote_state_t vote_state;
    if (sol_vote_state_deserialize(&vote_state, account->data,
                                    account->meta.data_len) != SOL_OK) {
        return true;  /* Skip on error */
    }

    /* Get delegated stake for this vote account */
    uint64_t delegated_stake = 0;
    if (extract_ctx->vote_stakes) {
        const uint64_t* stake_ptr =
            (const uint64_t*)sol_pubkey_map_get(extract_ctx->vote_stakes, pubkey);
        if (stake_ptr) {
            delegated_stake = *stake_ptr;
        }
    } else {
        delegated_stake = sol_stake_get_delegated_stake(
            extract_ctx->bank, pubkey, extract_ctx->current_epoch);
    }

    /* Only include validators with non-zero stake */
    if (delegated_stake == 0) {
        return true;
    }

    /* Find or add this validator (using node_pubkey as identity) */
    sol_stake_weight_t* weight = find_or_add_validator(
        extract_ctx, &vote_state.node_pubkey);
    if (weight) {
        weight->stake += delegated_stake;
    }

    return true;  /* Continue */
}

sol_leader_schedule_t*
sol_leader_schedule_from_bank_with_vote_stakes(sol_bank_t* bank,
                                               uint64_t epoch,
                                               const sol_pubkey_map_t* vote_stakes,
                                               const sol_leader_schedule_config_t* config) {
    if (!bank) return NULL;

    /* Get accounts db for iteration */
    sol_accounts_db_t* accounts_db = sol_bank_get_accounts_db(bank);
    if (!accounts_db) {
        /* Fallback to default schedule */
        sol_stake_weight_t default_stake = {
            .pubkey = {{0}},
            .stake = 1000000000000,
        };
        return sol_leader_schedule_new(epoch, &default_stake, 1, config);
    }

    /* Allocate space for stake weights (max 10000 validators) */
    size_t max_validators = 10000;
    sol_stake_weight_t* weights = sol_calloc(max_validators, sizeof(sol_stake_weight_t));
    if (!weights) {
        /* Fallback to default schedule */
        sol_stake_weight_t default_stake = {
            .pubkey = {{0}},
            .stake = 1000000000000,
        };
        return sol_leader_schedule_new(epoch, &default_stake, 1, config);
    }

    /* Extract stakes by iterating vote program accounts (uses owner index when available). */
    stake_extract_ctx_t ctx = {
        .bank = bank,
        .current_epoch = epoch,
        .vote_stakes = vote_stakes,
        .weights = weights,
        .num_weights = 0,
        .capacity = max_validators
    };

    sol_accounts_db_iterate_owner(accounts_db, &SOL_VOTE_PROGRAM_ID, extract_vote_accounts_callback, &ctx);

    /* If no validators found, use default */
    if (ctx.num_weights == 0) {
        sol_free(weights);
        sol_stake_weight_t default_stake = {
            .pubkey = {{0}},
            .stake = 1000000000000,
        };
        return sol_leader_schedule_new(epoch, &default_stake, 1, config);
    }

    sol_log_info("Leader schedule: found %zu validators with stake", ctx.num_weights);

    /* Create schedule from extracted weights */
    sol_leader_schedule_t* schedule = sol_leader_schedule_new(
        epoch, weights, ctx.num_weights, config);

    sol_free(weights);
    return schedule;
}

sol_leader_schedule_t*
sol_leader_schedule_from_bank(sol_bank_t* bank,
                              uint64_t epoch,
                              const sol_leader_schedule_config_t* config) {
    if (!bank) return NULL;

    uint64_t total_stake = 0;
    sol_pubkey_map_t* vote_stakes =
        sol_stake_build_vote_stake_map(bank, epoch, &total_stake);

    sol_leader_schedule_t* schedule =
        sol_leader_schedule_from_bank_with_vote_stakes(bank, epoch, vote_stakes, config);

    sol_pubkey_map_destroy(vote_stakes);
    return schedule;
}

void
sol_leader_schedule_destroy(sol_leader_schedule_t* schedule) {
    if (!schedule) return;

    sol_free(schedule->leaders);
    sol_free(schedule->unique_leaders);
    sol_free(schedule);
}

const sol_pubkey_t*
sol_leader_schedule_get_leader(const sol_leader_schedule_t* schedule,
                                sol_slot_t slot) {
    if (!schedule) return NULL;

    if (slot < schedule->first_slot || slot > schedule->last_slot) {
        return NULL;
    }

    size_t idx = slot - schedule->first_slot;
    return &schedule->leaders[idx];
}

bool
sol_leader_schedule_is_leader(const sol_leader_schedule_t* schedule,
                               sol_slot_t slot,
                               const sol_pubkey_t* pubkey) {
    if (!schedule || !pubkey) return false;

    const sol_pubkey_t* leader = sol_leader_schedule_get_leader(schedule, slot);
    if (!leader) return false;

    return sol_pubkey_eq(leader, pubkey);
}

size_t
sol_leader_schedule_get_slots(const sol_leader_schedule_t* schedule,
                               const sol_pubkey_t* pubkey,
                               sol_slot_t* out_slots,
                               size_t max_slots) {
    if (!schedule || !pubkey || !out_slots || max_slots == 0) {
        return 0;
    }

    size_t count = 0;
    for (size_t i = 0; i < schedule->num_slots && count < max_slots; i++) {
        if (sol_pubkey_eq(&schedule->leaders[i], pubkey)) {
            out_slots[count++] = schedule->first_slot + i;
        }
    }

    return count;
}

sol_slot_t
sol_leader_schedule_first_slot(const sol_leader_schedule_t* schedule) {
    return schedule ? schedule->first_slot : 0;
}

sol_slot_t
sol_leader_schedule_last_slot(const sol_leader_schedule_t* schedule) {
    return schedule ? schedule->last_slot : 0;
}

uint64_t
sol_leader_schedule_epoch(const sol_leader_schedule_t* schedule) {
    return schedule ? schedule->epoch : 0;
}

size_t
sol_leader_schedule_num_leaders(const sol_leader_schedule_t* schedule) {
    return schedule ? schedule->num_unique_leaders : 0;
}

size_t
sol_leader_schedule_get_leaders(
    const sol_leader_schedule_t*    schedule,
    sol_pubkey_t*                   out_leaders,
    size_t                          max_leaders
) {
    if (!schedule || !out_leaders || max_leaders == 0) return 0;

    size_t count = schedule->num_unique_leaders;
    if (count > max_leaders) count = max_leaders;

    for (size_t i = 0; i < count; i++) {
        memcpy(&out_leaders[i], &schedule->unique_leaders[i], sizeof(sol_pubkey_t));
    }

    return count;
}

/*
 * Epoch schedule functions
 */

uint64_t
sol_epoch_schedule_get_epoch(const sol_epoch_schedule_t* schedule,
                              sol_slot_t slot) {
    if (!schedule || schedule->slots_per_epoch == 0) {
        return 0;
    }

    if (schedule->warmup && slot < schedule->first_normal_slot) {
        /* During warmup, epochs are shorter */
        /* Simplified: just divide by a smaller value */
        return slot / (schedule->slots_per_epoch / 64);
    }

    if (slot < schedule->first_normal_slot) {
        return slot / schedule->slots_per_epoch;
    }

    return schedule->first_normal_epoch +
           (slot - schedule->first_normal_slot) / schedule->slots_per_epoch;
}

sol_slot_t
sol_epoch_schedule_get_first_slot_in_epoch(const sol_epoch_schedule_t* schedule,
                                            uint64_t epoch) {
    if (!schedule) {
        return 0;
    }

    if (schedule->warmup && epoch < schedule->first_normal_epoch) {
        /* During warmup */
        return epoch * (schedule->slots_per_epoch / 64);
    }

    if (epoch < schedule->first_normal_epoch) {
        return epoch * schedule->slots_per_epoch;
    }

    return schedule->first_normal_slot +
           (epoch - schedule->first_normal_epoch) * schedule->slots_per_epoch;
}

sol_slot_t
sol_epoch_schedule_get_last_slot_in_epoch(const sol_epoch_schedule_t* schedule,
                                           uint64_t epoch) {
    if (!schedule) {
        return 0;
    }

    return sol_epoch_schedule_get_first_slot_in_epoch(schedule, epoch + 1) - 1;
}

uint64_t
sol_epoch_schedule_get_slots_per_epoch(const sol_epoch_schedule_t* schedule,
                                        uint64_t epoch) {
    if (!schedule) {
        return SOL_DEFAULT_SLOTS_PER_EPOCH;
    }

    if (schedule->warmup && epoch < schedule->first_normal_epoch) {
        /* Simplified warmup: half the normal */
        return schedule->slots_per_epoch / 64;
    }

    return schedule->slots_per_epoch;
}
