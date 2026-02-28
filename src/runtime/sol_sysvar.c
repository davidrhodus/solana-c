/*
 * sol_sysvar.c - System Variable Accounts Implementation
 *
 * Note: SOL_SYSVAR_CLOCK_ID, SOL_SYSVAR_RENT_ID, SOL_SYSVAR_EPOCH_SCHEDULE_ID,
 *       SOL_SYSVAR_RECENT_BLOCKHASHES_ID, and SOL_SYSVAR_INSTRUCTIONS_ID are
 *       defined in sol_types.c. We only define the additional sysvars here.
 */

#include "sol_sysvar.h"
#include "../util/sol_alloc.h"
#include "../txn/sol_transaction.h"
#include <string.h>
#include <math.h>

/*
 * Additional sysvar account addresses (not in sol_types.c)
 * These match Solana's well-known sysvar pubkeys.
 */
const sol_pubkey_t SOL_SYSVAR_FEES_ID = {{
    0x06, 0xa7, 0xd5, 0x17, 0x18, 0xe2, 0x5a, 0x8d,
    0x83, 0x50, 0x3c, 0x25, 0x1a, 0x7a, 0xf0, 0x71,
    0x26, 0xfd, 0x72, 0x00, 0xdf, 0x6f, 0xc4, 0xed,
    0x52, 0x6a, 0x9c, 0x90, 0x00, 0x00, 0x00, 0x00
}};

const sol_pubkey_t SOL_SYSVAR_SLOT_HASHES_ID = {{
    0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2f, 0x0a, 0xaf,
    0xc6, 0xf2, 0x65, 0xe3, 0xfb, 0x77, 0xcc, 0x7a,
    0xda, 0x82, 0xc5, 0x29, 0xd0, 0xbe, 0x3b, 0x13,
    0x6e, 0x2d, 0x00, 0x55, 0x20, 0x00, 0x00, 0x00
}};

const sol_pubkey_t SOL_SYSVAR_STAKE_HISTORY_ID = {{
    0x06, 0xa7, 0xd5, 0x17, 0x19, 0x35, 0x84, 0xd0,
    0xfe, 0xed, 0x9b, 0xb3, 0x43, 0x1d, 0x13, 0x20,
    0x6b, 0xe5, 0x44, 0x28, 0x1b, 0x57, 0xb8, 0x56,
    0x6c, 0xc5, 0x37, 0x5f, 0xf4, 0x00, 0x00, 0x00
}};

const sol_pubkey_t SOL_SYSVAR_SLOT_HISTORY_ID = {{
    0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2f, 0x0a, 0xaf,
    0xc8, 0x75, 0xe2, 0xe1, 0x84, 0x57, 0x7c, 0x50,
    0x69, 0xcf, 0xc8, 0x46, 0x49, 0xe3, 0xeb, 0x92,
    0x78, 0x2f, 0x95, 0x8d, 0x48, 0x00, 0x00, 0x00
}};

const sol_pubkey_t SOL_SYSVAR_LAST_RESTART_SLOT_ID = {{
    0x06, 0xa7, 0xd5, 0x17, 0x19, 0x06, 0xdd, 0xe1,
    0xcd, 0x3f, 0x94, 0x7d, 0xca, 0xb4, 0xc8, 0xf4,
    0xf4, 0xf5, 0x1b, 0xad, 0x0f, 0x98, 0x13, 0xb8,
    0x00, 0xd2, 0x89, 0x47, 0x1f, 0xc0, 0x00, 0x00
}};

const sol_pubkey_t SOL_SYSVAR_EPOCH_REWARDS_ID = {{
    0x06, 0xa7, 0xd5, 0x17, 0x18, 0xdc, 0x3f, 0xee,
    0x02, 0xa5, 0x58, 0xbf, 0x83, 0xce, 0x66, 0xe1,
    0x44, 0x42, 0x2a, 0x1c, 0x34, 0x95, 0x0b, 0x27,
    0xc1, 0x86, 0x9b, 0x5a, 0x9c, 0x00, 0x00, 0x00
}};

bool
sol_is_sysvar(const sol_pubkey_t* pubkey) {
    if (!pubkey) return false;

    return sol_pubkey_eq(pubkey, &SOL_SYSVAR_CLOCK_ID) ||
           sol_pubkey_eq(pubkey, &SOL_SYSVAR_RENT_ID) ||
           sol_pubkey_eq(pubkey, &SOL_SYSVAR_EPOCH_SCHEDULE_ID) ||
           sol_pubkey_eq(pubkey, &SOL_SYSVAR_FEES_ID) ||
           sol_pubkey_eq(pubkey, &SOL_SYSVAR_RECENT_BLOCKHASHES_ID) ||
           sol_pubkey_eq(pubkey, &SOL_SYSVAR_SLOT_HASHES_ID) ||
           sol_pubkey_eq(pubkey, &SOL_SYSVAR_STAKE_HISTORY_ID) ||
           sol_pubkey_eq(pubkey, &SOL_SYSVAR_INSTRUCTIONS_ID) ||
           sol_pubkey_eq(pubkey, &SOL_SYSVAR_SLOT_HISTORY_ID) ||
           sol_pubkey_eq(pubkey, &SOL_SYSVAR_LAST_RESTART_SLOT_ID) ||
           sol_pubkey_eq(pubkey, &SOL_SYSVAR_EPOCH_REWARDS_ID);
}

const char*
sol_sysvar_name(const sol_pubkey_t* pubkey) {
    if (!pubkey) return "Unknown";

    if (sol_pubkey_eq(pubkey, &SOL_SYSVAR_CLOCK_ID)) return "Clock";
    if (sol_pubkey_eq(pubkey, &SOL_SYSVAR_RENT_ID)) return "Rent";
    if (sol_pubkey_eq(pubkey, &SOL_SYSVAR_EPOCH_SCHEDULE_ID)) return "EpochSchedule";
    if (sol_pubkey_eq(pubkey, &SOL_SYSVAR_FEES_ID)) return "Fees";
    if (sol_pubkey_eq(pubkey, &SOL_SYSVAR_RECENT_BLOCKHASHES_ID)) return "RecentBlockhashes";
    if (sol_pubkey_eq(pubkey, &SOL_SYSVAR_SLOT_HASHES_ID)) return "SlotHashes";
    if (sol_pubkey_eq(pubkey, &SOL_SYSVAR_STAKE_HISTORY_ID)) return "StakeHistory";
    if (sol_pubkey_eq(pubkey, &SOL_SYSVAR_INSTRUCTIONS_ID)) return "Instructions";
    if (sol_pubkey_eq(pubkey, &SOL_SYSVAR_SLOT_HISTORY_ID)) return "SlotHistory";

    return "Unknown";
}

/*
 * Clock sysvar
 *
 * Binary format (Solana spec):
 *   slot: u64
 *   epoch_start_timestamp: i64
 *   epoch: u64
 *   leader_schedule_epoch: u64
 *   unix_timestamp: i64
 *
 * Note: sol_types.h struct has different field order, but we serialize
 *       in the Solana binary format order.
 */

void
sol_clock_init(sol_clock_t* clock) {
    if (!clock) return;
    memset(clock, 0, sizeof(sol_clock_t));
}

sol_err_t
sol_clock_serialize(const sol_clock_t* clock, uint8_t* data, size_t len) {
    if (!clock || !data || len < SOL_CLOCK_SIZE) {
        return SOL_ERR_INVAL;
    }

    size_t offset = 0;

    /* Solana binary format order */
    memcpy(data + offset, &clock->slot, 8);
    offset += 8;

    memcpy(data + offset, &clock->epoch_start_timestamp, 8);
    offset += 8;

    memcpy(data + offset, &clock->epoch, 8);
    offset += 8;

    memcpy(data + offset, &clock->leader_schedule_epoch, 8);
    offset += 8;

    memcpy(data + offset, &clock->unix_timestamp, 8);
    offset += 8;

    return SOL_OK;
}

sol_err_t
sol_clock_deserialize(sol_clock_t* clock, const uint8_t* data, size_t len) {
    if (!clock || !data || len < SOL_CLOCK_SIZE) {
        return SOL_ERR_INVAL;
    }

    size_t offset = 0;

    /* Solana binary format order */
    memcpy(&clock->slot, data + offset, 8);
    offset += 8;

    memcpy(&clock->epoch_start_timestamp, data + offset, 8);
    offset += 8;

    memcpy(&clock->epoch, data + offset, 8);
    offset += 8;

    memcpy(&clock->leader_schedule_epoch, data + offset, 8);
    offset += 8;

    memcpy(&clock->unix_timestamp, data + offset, 8);
    offset += 8;

    return SOL_OK;
}

/*
 * Rent sysvar
 */

void
sol_rent_init(sol_rent_t* rent) {
    if (!rent) return;
    *rent = (sol_rent_t)SOL_RENT_DEFAULT;
}

sol_err_t
sol_rent_serialize(const sol_rent_t* rent, uint8_t* data, size_t len) {
    if (!rent || !data || len < SOL_RENT_SERIALIZED_SIZE) {
        return SOL_ERR_INVAL;
    }

    size_t offset = 0;

    memcpy(data + offset, &rent->lamports_per_byte_year, 8);
    offset += 8;

    memcpy(data + offset, &rent->exemption_threshold, 8);
    offset += 8;

    data[offset] = rent->burn_percent;
    offset += 1;

    return SOL_OK;
}

sol_err_t
sol_rent_deserialize(sol_rent_t* rent, const uint8_t* data, size_t len) {
    if (!rent || !data || len < SOL_RENT_SERIALIZED_SIZE) {
        return SOL_ERR_INVAL;
    }

    size_t offset = 0;

    memcpy(&rent->lamports_per_byte_year, data + offset, 8);
    offset += 8;

    memcpy(&rent->exemption_threshold, data + offset, 8);
    offset += 8;

    rent->burn_percent = data[offset];
    offset += 1;

    return SOL_OK;
}

uint64_t
sol_rent_minimum_balance(const sol_rent_t* rent, size_t data_len) {
    if (!rent) return 0;

    /* Account overhead: 128 bytes for metadata */
    size_t account_size = data_len + 128;

    /* Minimum balance = (lamports_per_byte_year * account_size * exemption_threshold) */
    double min = (double)rent->lamports_per_byte_year *
                 (double)account_size *
                 rent->exemption_threshold;

    return (uint64_t)ceil(min);
}

uint64_t
sol_rent_due(const sol_rent_t* rent, uint64_t lamports,
             size_t data_len, double years_elapsed) {
    if (!rent || years_elapsed <= 0) return 0;

    uint64_t min_balance = sol_rent_minimum_balance(rent, data_len);

    /* If rent-exempt, no rent due */
    if (lamports >= min_balance) {
        return 0;
    }

    /* Calculate rent due */
    size_t account_size = data_len + 128;
    double rent_due = (double)rent->lamports_per_byte_year *
                      (double)account_size *
                      years_elapsed;

    return (uint64_t)ceil(rent_due);
}

/*
 * Epoch schedule sysvar
 */

void
sol_epoch_schedule_init(sol_epoch_schedule_t* schedule) {
    if (!schedule) return;

    schedule->slots_per_epoch = 432000;  /* Default slots per epoch */
    schedule->leader_schedule_slot_offset = 432000;  /* Same as slots_per_epoch for mainnet */
    schedule->warmup = false;
    schedule->first_normal_epoch = 0;
    schedule->first_normal_slot = 0;
}

sol_err_t
sol_epoch_schedule_serialize(const sol_epoch_schedule_t* schedule,
                              uint8_t* data, size_t len) {
    if (!schedule || !data || len < SOL_EPOCH_SCHEDULE_SERIALIZED_SIZE) {
        return SOL_ERR_INVAL;
    }

    size_t offset = 0;

    memcpy(data + offset, &schedule->slots_per_epoch, 8);
    offset += 8;

    memcpy(data + offset, &schedule->leader_schedule_slot_offset, 8);
    offset += 8;

    data[offset] = schedule->warmup ? 1 : 0;
    offset += 1;

    memcpy(data + offset, &schedule->first_normal_epoch, 8);
    offset += 8;

    memcpy(data + offset, &schedule->first_normal_slot, 8);
    offset += 8;

    return SOL_OK;
}

sol_err_t
sol_epoch_schedule_deserialize(sol_epoch_schedule_t* schedule,
                                const uint8_t* data, size_t len) {
    if (!schedule || !data || len < SOL_EPOCH_SCHEDULE_SERIALIZED_SIZE) {
        return SOL_ERR_INVAL;
    }

    size_t offset = 0;

    memcpy(&schedule->slots_per_epoch, data + offset, 8);
    offset += 8;

    memcpy(&schedule->leader_schedule_slot_offset, data + offset, 8);
    offset += 8;

    schedule->warmup = data[offset] != 0;
    offset += 1;

    memcpy(&schedule->first_normal_epoch, data + offset, 8);
    offset += 8;

    memcpy(&schedule->first_normal_slot, data + offset, 8);
    offset += 8;

    return SOL_OK;
}

/*
 * Fees sysvar
 */

void
sol_fees_init(sol_fees_t* fees) {
    if (!fees) return;
    fees->fee_calculator.lamports_per_signature = 5000;  /* Default fee */
}

sol_err_t
sol_fees_serialize(const sol_fees_t* fees, uint8_t* data, size_t len) {
    if (!fees || !data || len < SOL_FEES_SIZE) {
        return SOL_ERR_INVAL;
    }

    memcpy(data, &fees->fee_calculator.lamports_per_signature, 8);
    return SOL_OK;
}

sol_err_t
sol_fees_deserialize(sol_fees_t* fees, const uint8_t* data, size_t len) {
    if (!fees || !data || len < SOL_FEES_SIZE) {
        return SOL_ERR_INVAL;
    }

    memcpy(&fees->fee_calculator.lamports_per_signature, data, 8);
    return SOL_OK;
}

/*
 * Recent blockhashes sysvar
 */

void
sol_recent_blockhashes_init(sol_recent_blockhashes_t* rbh) {
    if (!rbh) return;
    memset(rbh, 0, sizeof(sol_recent_blockhashes_t));
}

sol_err_t
sol_recent_blockhashes_add(sol_recent_blockhashes_t* rbh,
                            const sol_hash_t* blockhash,
                            uint64_t lamports_per_signature) {
    if (!rbh || !blockhash) return SOL_ERR_INVAL;

    /* Shift entries down */
    if (rbh->len >= SOL_MAX_RECENT_BLOCKHASHES) {
        memmove(&rbh->entries[1], &rbh->entries[0],
                (SOL_MAX_RECENT_BLOCKHASHES - 1) * sizeof(sol_recent_blockhash_entry_t));
        rbh->len = SOL_MAX_RECENT_BLOCKHASHES - 1;
    }

    /* Insert at front */
    memmove(&rbh->entries[1], &rbh->entries[0],
            rbh->len * sizeof(sol_recent_blockhash_entry_t));

    rbh->entries[0].blockhash = *blockhash;
    rbh->entries[0].fee_calculator.lamports_per_signature = lamports_per_signature;
    rbh->len++;

    return SOL_OK;
}

bool
sol_recent_blockhashes_contains(const sol_recent_blockhashes_t* rbh,
                                 const sol_hash_t* blockhash) {
    if (!rbh || !blockhash) return false;

    for (size_t i = 0; i < rbh->len; i++) {
        if (memcmp(&rbh->entries[i].blockhash, blockhash, sizeof(sol_hash_t)) == 0) {
            return true;
        }
    }

    return false;
}

sol_err_t
sol_recent_blockhashes_serialize(const sol_recent_blockhashes_t* rbh,
                                  uint8_t* data, size_t len) {
    if (!rbh || !data) return SOL_ERR_INVAL;

    size_t needed = 8 + rbh->len * (32 + 8);  /* len + entries */
    if (len < needed) return SOL_ERR_INVAL;

    size_t offset = 0;

    /* Write length */
    uint64_t count = rbh->len;
    memcpy(data + offset, &count, 8);
    offset += 8;

    /* Write entries */
    for (size_t i = 0; i < rbh->len; i++) {
        memcpy(data + offset, &rbh->entries[i].blockhash, 32);
        offset += 32;
        memcpy(data + offset, &rbh->entries[i].fee_calculator.lamports_per_signature, 8);
        offset += 8;
    }

    return SOL_OK;
}

sol_err_t
sol_recent_blockhashes_deserialize(sol_recent_blockhashes_t* rbh,
                                    const uint8_t* data, size_t len) {
    if (!rbh || !data || len < 8) return SOL_ERR_INVAL;

    size_t offset = 0;

    uint64_t count;
    memcpy(&count, data + offset, 8);
    offset += 8;

    if (count > SOL_MAX_RECENT_BLOCKHASHES) {
        return SOL_ERR_RANGE;
    }

    size_t needed = 8 + count * (32 + 8);
    if (len < needed) return SOL_ERR_TRUNCATED;

    rbh->len = (size_t)count;

    for (size_t i = 0; i < rbh->len; i++) {
        memcpy(&rbh->entries[i].blockhash, data + offset, 32);
        offset += 32;
        memcpy(&rbh->entries[i].fee_calculator.lamports_per_signature, data + offset, 8);
        offset += 8;
    }

    return SOL_OK;
}

/*
 * Slot hashes sysvar
 */

void
sol_slot_hashes_init(sol_slot_hashes_t* sh) {
    if (!sh) return;
    memset(sh, 0, sizeof(sol_slot_hashes_t));
}

sol_err_t
sol_slot_hashes_add(sol_slot_hashes_t* sh, sol_slot_t slot,
                     const sol_hash_t* hash) {
    if (!sh || !hash) return SOL_ERR_INVAL;

    /* Check if already exists */
    for (size_t i = 0; i < sh->len; i++) {
        if (sh->entries[i].slot == slot) {
            sh->entries[i].hash = *hash;
            return SOL_OK;
        }
    }

    /* If full, drop the oldest (last) entry to make room */
    if (sh->len >= SOL_MAX_SLOT_HASHES) {
        sh->len = SOL_MAX_SLOT_HASHES - 1;
    }

    /* Insert at front (newest first) by shifting existing entries right */
    memmove(&sh->entries[1], &sh->entries[0],
            sh->len * sizeof(sol_slot_hash_t));

    sh->entries[0].slot = slot;
    sh->entries[0].hash = *hash;
    sh->len++;

    return SOL_OK;
}

const sol_hash_t*
sol_slot_hashes_get(const sol_slot_hashes_t* sh, sol_slot_t slot) {
    if (!sh) return NULL;

    for (size_t i = 0; i < sh->len; i++) {
        if (sh->entries[i].slot == slot) {
            return &sh->entries[i].hash;
        }
    }

    return NULL;
}

sol_err_t
sol_slot_hashes_serialize(const sol_slot_hashes_t* sh,
                           uint8_t* data, size_t len) {
    if (!sh || !data) return SOL_ERR_INVAL;

    size_t needed = 8 + sh->len * (8 + 32);  /* len + entries */
    if (len < needed) return SOL_ERR_INVAL;

    size_t offset = 0;

    uint64_t count = sh->len;
    memcpy(data + offset, &count, 8);
    offset += 8;

    for (size_t i = 0; i < sh->len; i++) {
        memcpy(data + offset, &sh->entries[i].slot, 8);
        offset += 8;
        memcpy(data + offset, &sh->entries[i].hash, 32);
        offset += 32;
    }

    return SOL_OK;
}

sol_err_t
sol_slot_hashes_deserialize(sol_slot_hashes_t* sh,
                             const uint8_t* data, size_t len) {
    if (!sh || !data || len < 8) return SOL_ERR_INVAL;

    size_t offset = 0;

    uint64_t count;
    memcpy(&count, data + offset, 8);
    offset += 8;

    if (count > SOL_MAX_SLOT_HASHES) {
        return SOL_ERR_RANGE;
    }

    size_t needed = 8 + count * (8 + 32);
    if (len < needed) return SOL_ERR_TRUNCATED;

    sh->len = (size_t)count;

    for (size_t i = 0; i < sh->len; i++) {
        memcpy(&sh->entries[i].slot, data + offset, 8);
        offset += 8;
        memcpy(&sh->entries[i].hash, data + offset, 32);
        offset += 32;
    }

    return SOL_OK;
}

/*
 * Slot history sysvar
 *
 * Bincode/serde encoding (see sol_sysvar.h):
 *   [u8 option_tag][u64 blocks_len][u64 blocks...][u64 bit_len][u64 next_slot]
 */

sol_err_t
sol_slot_history_serialize_default(uint8_t* data, size_t len) {
    if (!data || len < SOL_SLOT_HISTORY_SIZE) {
        return SOL_ERR_INVAL;
    }

    const uint64_t blocks = (uint64_t)SOL_SLOT_HISTORY_WORDS;
    const uint64_t bit_len = (uint64_t)SOL_SLOT_HISTORY_MAX_ENTRIES;

    data[0] = 1; /* Some(Box<[u64]>) */
    memcpy(data + 1, &blocks, 8);

    uint8_t* blocks_bytes = data + 1 + 8;
    memset(blocks_bytes, 0, (size_t)blocks * 8);

    /* SlotHistory::default() sets bit 0 and next_slot=1. */
    uint64_t first = 1ULL;
    memcpy(blocks_bytes, &first, 8);

    size_t bit_len_off = 1 + 8 + (size_t)blocks * 8;
    memcpy(data + bit_len_off, &bit_len, 8);

    uint64_t next_slot = 1;
    memcpy(data + bit_len_off + 8, &next_slot, 8);
    return SOL_OK;
}

static void
slot_history_bit_set(uint8_t* blocks_bytes, uint64_t block_count, uint64_t bit_idx, bool value) {
    if (!blocks_bytes) return;
    uint64_t word_idx = bit_idx / 64;
    uint64_t bit = bit_idx % 64;
    if (word_idx >= block_count) return;

    size_t offset = (size_t)word_idx * 8;
    uint64_t word = 0;
    memcpy(&word, blocks_bytes + offset, 8);

    uint64_t mask = 1ULL << bit;
    if (value) {
        word |= mask;
    } else {
        word &= ~mask;
    }

    memcpy(blocks_bytes + offset, &word, 8);
}

sol_err_t
sol_slot_history_add(uint8_t* data, size_t len, sol_slot_t slot) {
    if (!data || len < 25) {
        return SOL_ERR_INVAL;
    }

    /* New (mainnet) format: bincode/serde for bv::BitVec<u64>. */
    uint8_t opt_tag = data[0];
    if (opt_tag != 1) {
        return SOL_ERR_INVAL;
    }

    uint64_t block_count = 0;
    memcpy(&block_count, data + 1, 8);

    if (block_count == 0 || block_count > (uint64_t)SOL_SLOT_HISTORY_WORDS) {
        return SOL_ERR_RANGE;
    }

    size_t blocks_off = 1 + 8;
    size_t bit_len_off = blocks_off + (size_t)block_count * 8;
    size_t next_slot_off = bit_len_off + 8;

    if (len < next_slot_off + 8) {
        return SOL_ERR_TRUNCATED;
    }

    uint64_t bit_len = 0;
    memcpy(&bit_len, data + bit_len_off, 8);
    if (bit_len == 0 || bit_len != (uint64_t)SOL_SLOT_HISTORY_MAX_ENTRIES) {
        return SOL_ERR_RANGE;
    }

    uint64_t next_slot = 0;
    memcpy(&next_slot, data + next_slot_off, 8);

    uint8_t* blocks_bytes = data + blocks_off;
    uint64_t slot_u64 = (uint64_t)slot;

    if (slot_u64 > next_slot && (slot_u64 - next_slot) >= bit_len) {
        /* Wrapped past current history; clear entire bitvec. */
        memset(blocks_bytes, 0, (size_t)block_count * 8);
    } else {
        for (uint64_t skipped = next_slot; skipped < slot_u64; skipped++) {
            slot_history_bit_set(blocks_bytes, block_count, skipped % bit_len, false);
        }
    }

    slot_history_bit_set(blocks_bytes, block_count, slot_u64 % bit_len, true);
    next_slot = slot_u64 + 1;
    memcpy(data + next_slot_off, &next_slot, 8);
    return SOL_OK;
}

/*
 * Stake history sysvar
 */

void
sol_stake_history_init(sol_stake_history_t* sh) {
    if (!sh) return;
    memset(sh, 0, sizeof(sol_stake_history_t));
}

sol_err_t
sol_stake_history_add(sol_stake_history_t* sh, uint64_t epoch,
                       const sol_stake_history_entry_t* entry) {
    if (!sh || !entry) return SOL_ERR_INVAL;

    /* Check if epoch already exists */
    for (size_t i = 0; i < sh->len; i++) {
        if (sh->entries[i].epoch == epoch) {
            sh->entries[i].entry = *entry;
            return SOL_OK;
        }
    }

    /* Remove oldest if full */
    if (sh->len >= SOL_MAX_STAKE_HISTORY) {
        memmove(&sh->entries[0], &sh->entries[1],
                (SOL_MAX_STAKE_HISTORY - 1) * sizeof(sh->entries[0]));
        sh->len = SOL_MAX_STAKE_HISTORY - 1;
    }

    /* Add at end */
    sh->entries[sh->len].epoch = epoch;
    sh->entries[sh->len].entry = *entry;
    sh->len++;

    return SOL_OK;
}

const sol_stake_history_entry_t*
sol_stake_history_get(const sol_stake_history_t* sh, uint64_t epoch) {
    if (!sh) return NULL;

    for (size_t i = 0; i < sh->len; i++) {
        if (sh->entries[i].epoch == epoch) {
            return &sh->entries[i].entry;
        }
    }

    return NULL;
}

sol_err_t
sol_stake_history_serialize(const sol_stake_history_t* sh,
                             uint8_t* data, size_t len) {
    if (!sh || !data) return SOL_ERR_INVAL;

    size_t needed = 8 + sh->len * (8 + 24);  /* len + entries (epoch + 3*uint64) */
    if (len < needed) return SOL_ERR_INVAL;

    size_t offset = 0;

    uint64_t count = sh->len;
    memcpy(data + offset, &count, 8);
    offset += 8;

    for (size_t i = 0; i < sh->len; i++) {
        memcpy(data + offset, &sh->entries[i].epoch, 8);
        offset += 8;
        memcpy(data + offset, &sh->entries[i].entry.effective, 8);
        offset += 8;
        memcpy(data + offset, &sh->entries[i].entry.activating, 8);
        offset += 8;
        memcpy(data + offset, &sh->entries[i].entry.deactivating, 8);
        offset += 8;
    }

    return SOL_OK;
}

sol_err_t
sol_stake_history_deserialize(sol_stake_history_t* sh,
                               const uint8_t* data, size_t len) {
    if (!sh || !data || len < 8) return SOL_ERR_INVAL;

    size_t offset = 0;

    uint64_t count;
    memcpy(&count, data + offset, 8);
    offset += 8;

    if (count > SOL_MAX_STAKE_HISTORY) {
        return SOL_ERR_RANGE;
    }

    size_t needed = 8 + count * (8 + 24);
    if (len < needed) return SOL_ERR_TRUNCATED;

    sh->len = (size_t)count;

    for (size_t i = 0; i < sh->len; i++) {
        memcpy(&sh->entries[i].epoch, data + offset, 8);
        offset += 8;
        memcpy(&sh->entries[i].entry.effective, data + offset, 8);
        offset += 8;
        memcpy(&sh->entries[i].entry.activating, data + offset, 8);
        offset += 8;
        memcpy(&sh->entries[i].entry.deactivating, data + offset, 8);
        offset += 8;
    }

    return SOL_OK;
}

/*
 * Instructions sysvar
 *
 * Provides transaction introspection for programs.
 */

sol_err_t
sol_instructions_sysvar_serialize(const sol_transaction_t* txn,
                                   uint16_t current_idx,
                                   const bool* demoted_is_writable,
                                   uint16_t demoted_is_writable_len,
                                   uint8_t* out_data,
                                   size_t* out_len) {
    if (!txn || !out_data || !out_len) {
        return SOL_ERR_INVAL;
    }

    const sol_message_t* msg = &txn->message;
    uint16_t num_ix = (uint16_t)msg->instructions_len;

    /*
     * Instructions sysvar format (matches Agave):
     *
     * HEADER:
     *   u16: num_instructions
     *   u16[num_ix]: offset table (byte offsets to each instruction)
     *   u16: current instruction index
     *
     * PER INSTRUCTION (at recorded offset):
     *   u8: num_accounts
     *   For each account:
     *     u8: pubkey index (into message account keys)
     *     u8: is_signer (0/1)
     *     u8: is_writable (0/1)
     *   [u8; 32]: program_id (full pubkey)
     *   u16: data_len
     *   [u8; data_len]: data
     */

    /* Resolve account keys */
    const sol_pubkey_t* acct_keys = msg->resolved_accounts_len
        ? msg->resolved_accounts : msg->account_keys;
    uint16_t acct_keys_len = msg->resolved_accounts_len
        ? msg->resolved_accounts_len : (uint16_t)msg->account_keys_len;

    /* Calculate required size */
    size_t header_size = 2u + (size_t)num_ix * 2u + 2u;  /* count + offsets + current */
    size_t instr_data_size = 0;

    for (size_t i = 0; i < num_ix; i++) {
        const sol_compiled_instruction_t* ix = &msg->instructions[i];
        /* num_accounts(1) + accounts(3*n) + program_id(32) + data_len(2) + data */
        instr_data_size += 1u + ((size_t)ix->account_indices_len * 3u) + 32u + 2u + (size_t)ix->data_len;
    }

    size_t total_size = header_size + instr_data_size;
    if (total_size > UINT16_MAX) {
        /* Offsets are serialized as u16, so the sysvar cannot exceed 64KiB. */
        return SOL_ERR_OVERFLOW;
    }
    if (*out_len < total_size) {
        *out_len = total_size;
        return SOL_ERR_INVAL;
    }

    size_t offset = 0;

    /* Write number of instructions (u16 LE) */
    memcpy(out_data + offset, &num_ix, 2);
    offset += 2;

    /* Calculate and write offset table */
    size_t ix_data_start = header_size;
    for (size_t i = 0; i < num_ix; i++) {
        uint16_t off16 = (uint16_t)ix_data_start;
        memcpy(out_data + offset, &off16, 2);
        offset += 2;

        const sol_compiled_instruction_t* ix = &msg->instructions[i];
        ix_data_start += 1u + ((size_t)ix->account_indices_len * 3u) + 32u + 2u + (size_t)ix->data_len;
    }

    /* Write current instruction index (u16 LE) */
    memcpy(out_data + offset, &current_idx, 2);
    offset += 2;

    /* Write each instruction */
    for (size_t i = 0; i < num_ix; i++) {
        const sol_compiled_instruction_t* ix = &msg->instructions[i];

        /* Number of accounts (u8) */
        out_data[offset++] = (uint8_t)ix->account_indices_len;

        /* Account metas: (pubkey_index, is_signer, is_writable) = 3 bytes each */
        for (uint8_t j = 0; j < ix->account_indices_len; j++) {
            uint8_t key_index = ix->account_indices[j];

            bool key_is_signer = false;
            if (msg->is_signer && key_index < acct_keys_len) {
                key_is_signer = msg->is_signer[key_index];
            } else {
                key_is_signer = key_index < msg->header.num_required_signatures;
            }

            bool key_is_writable = false;
            if (demoted_is_writable && key_index < demoted_is_writable_len) {
                key_is_writable = demoted_is_writable[key_index];
            } else if (msg->is_writable && key_index < acct_keys_len) {
                key_is_writable = msg->is_writable[key_index];
            } else {
                key_is_writable = sol_message_is_writable_index(msg, key_index);
            }

            out_data[offset++] = key_index;
            out_data[offset++] = (uint8_t)(key_is_signer ? 1 : 0);
            out_data[offset++] = (uint8_t)(key_is_writable ? 1 : 0);
        }

        /* Program ID (full 32-byte pubkey) */
        if (acct_keys && ix->program_id_index < acct_keys_len) {
            memcpy(out_data + offset, acct_keys[ix->program_id_index].bytes, 32);
        } else {
            memset(out_data + offset, 0, 32);
        }
        offset += 32;

        /* Data length (u16 LE) and data */
        uint16_t data_len = (uint16_t)ix->data_len;
        memcpy(out_data + offset, &data_len, 2);
        offset += 2;

        if (data_len > 0) {
            if (ix->data) {
                memcpy(out_data + offset, ix->data, data_len);
            } else {
                memset(out_data + offset, 0, data_len);
            }
            offset += (size_t)data_len;
        }
    }

    *out_len = offset;
    return SOL_OK;
}

uint16_t
sol_instructions_sysvar_get_count(const uint8_t* data, size_t len) {
    if (!data || len < 2) {
        return 0;
    }

    uint16_t count;
    memcpy(&count, data, 2);
    return count;
}

uint16_t
sol_instructions_sysvar_get_current(const uint8_t* data, size_t len) {
    if (!data || len < 4) {
        return 0;
    }

    uint16_t count;
    memcpy(&count, data, 2);

    size_t current_off = 2u + (size_t)count * 2u;
    if (len < current_off + 2u) {
        return 0;
    }

    uint16_t current = 0;
    memcpy(&current, data + current_off, 2);
    return current;
}

sol_err_t
sol_instructions_sysvar_load_instruction(const uint8_t* data,
                                          size_t len,
                                          uint16_t index,
                                          sol_pubkey_t* out_program_id,
                                          const uint8_t** out_data,
                                          size_t* out_data_len) {
    if (!data || len < 2) {
        return SOL_ERR_INVAL;
    }

    uint16_t count;
    memcpy(&count, data, 2);

    if (index >= count) {
        return SOL_ERR_RANGE;
    }

    /* Get offset for this instruction */
    size_t offset_table_pos = 2 + (index * 2);
    if (len < offset_table_pos + 2) {
        return SOL_ERR_TRUNCATED;
    }

    uint16_t ix_offset;
    memcpy(&ix_offset, data + offset_table_pos, 2);

    if (len < (size_t)ix_offset + 2) {
        return SOL_ERR_TRUNCATED;
    }

    size_t pos = ix_offset;

    /* Read number of accounts (u8) */
    if (len < pos + 1) {
        return SOL_ERR_TRUNCATED;
    }
    uint8_t num_accounts = data[pos++];

    /* Skip account metas: 3 bytes each (index, is_signer, is_writable) */
    size_t meta_size = (size_t)num_accounts * 3u;
    if (len < pos + meta_size) {
        return SOL_ERR_TRUNCATED;
    }
    pos += meta_size;

    if (len < pos + 32) {
        return SOL_ERR_TRUNCATED;
    }

    /* Read program ID */
    if (out_program_id) {
        memcpy(out_program_id->bytes, data + pos, 32);
    }
    pos += 32;

    if (len < pos + 2) {
        return SOL_ERR_TRUNCATED;
    }

    /* Read data length */
    uint16_t data_len;
    memcpy(&data_len, data + pos, 2);
    pos += 2;

    if (len < pos + data_len) {
        return SOL_ERR_TRUNCATED;
    }

    /* Return data pointer and length */
    if (out_data) {
        *out_data = data + pos;
    }
    if (out_data_len) {
        *out_data_len = data_len;
    }

    return SOL_OK;
}
