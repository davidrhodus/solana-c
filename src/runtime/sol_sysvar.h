/*
 * sol_sysvar.h - System Variable Accounts
 *
 * Sysvars are special accounts that provide cluster state to programs.
 * They are updated by the runtime at specific points (slot boundaries, etc.).
 *
 * Note: sol_clock_t, sol_rent_t, and sol_epoch_schedule_t are defined in sol_types.h
 */

#ifndef SOL_SYSVAR_H
#define SOL_SYSVAR_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../txn/sol_pubkey.h"
#include "../txn/sol_transaction.h"
#include <stdbool.h>

/*
 * Additional sysvar account addresses (some already in sol_types.h)
 */
extern const sol_pubkey_t SOL_SYSVAR_FEES_ID;
extern const sol_pubkey_t SOL_SYSVAR_SLOT_HASHES_ID;
extern const sol_pubkey_t SOL_SYSVAR_STAKE_HISTORY_ID;
extern const sol_pubkey_t SOL_SYSVAR_SLOT_HISTORY_ID;
extern const sol_pubkey_t SOL_SYSVAR_LAST_RESTART_SLOT_ID;
extern const sol_pubkey_t SOL_SYSVAR_EPOCH_REWARDS_ID;

/*
 * Serialized sizes
 *
 * Two sizes exist for some sysvars:
 *   - "SIZE" = #[repr(C)] in-memory struct size, used for sysvar syscall CU
 *     charging (sol_get_clock_sysvar etc.) and direct struct transfer.
 *   - "SERIALIZED_SIZE" = bincode serialized size (no struct padding), used
 *     for sysvar account data storage.
 *
 * For types with no padding (Clock, Fees) the two are identical.
 */
#define SOL_CLOCK_SIZE          40   /* 5 x u64, no padding */
#define SOL_RENT_SIZE           24   /* u64 + f64 + u8 + 7 pad, #[repr(C)] */
#define SOL_RENT_SERIALIZED_SIZE 17  /* bincode: u64(8) + f64(8) + u8(1), no padding */
#define SOL_EPOCH_SCHEDULE_SIZE 40   /* u64 + u64 + bool + 7pad + u64 + u64, #[repr(C)] */
#define SOL_EPOCH_SCHEDULE_SERIALIZED_SIZE 33  /* bincode: u64(8)+u64(8)+bool(1)+u64(8)+u64(8) */
#define SOL_FEES_SIZE           8    /* FeeCalculator(u64), no padding */
/* EpochRewards: #[repr(C, align(16))]
 *   u64(8) + u64(8) + Hash(32) + u128(16) + u64(8) + u64(8) + bool(1) + 15pad = 96 */
#define SOL_EPOCH_REWARDS_SIZE  96

/*
 * Slot history sysvar
 *
 * Solana serializes SlotHistory via bincode/serde as:
 *   SlotHistory { bits: bv::BitVec<u64>, next_slot: u64 }
 *
 * Where bv::BitVec<u64> is:
 *   struct BitVec { bits: Inner<u64>, len: u64 }
 *   Inner<u64> = Option<Box<[u64]>>
 *
 * With bincode's default (fixint) encoding on x86_64 this becomes:
 *   - u8  option tag (0=None, 1=Some)
 *   - u64 blocks_len (serialized usize; number of u64 blocks)
 *   - [u64; blocks_len] blocks
 *   - u64 bit_len (number of bits)
 *   - u64 next_slot
 */
#define SOL_SLOT_HISTORY_MAX_ENTRIES (1024UL * 1024UL)
#define SOL_SLOT_HISTORY_WORDS       (SOL_SLOT_HISTORY_MAX_ENTRIES / 64UL)
#define SOL_SLOT_HISTORY_SIZE        (1UL + 8UL + SOL_SLOT_HISTORY_WORDS * 8UL + 8UL + 8UL)

/* Default rent parameters */
#define SOL_RENT_DEFAULT {                      \
    .lamports_per_byte_year = 3480,             \
    .exemption_threshold = 2.0,                 \
    .burn_percent = 50,                         \
}

/*
 * Fee calculator (deprecated but still used)
 */
typedef struct {
    uint64_t        lamports_per_signature;
} sol_fee_calculator_t;

/*
 * Fees sysvar
 */
typedef struct {
    sol_fee_calculator_t fee_calculator;
} sol_fees_t;

/*
 * Recent blockhash entry
 */
typedef struct {
    sol_hash_t              blockhash;
    sol_fee_calculator_t    fee_calculator;
} sol_recent_blockhash_entry_t;

/*
 * Recent blockhashes sysvar
 * Uses SOL_MAX_RECENT_BLOCKHASHES from sol_types.h (300)
 */
typedef struct {
    sol_recent_blockhash_entry_t entries[SOL_MAX_RECENT_BLOCKHASHES];
    size_t                       len;
} sol_recent_blockhashes_t;

/*
 * Slot hash entry
 */
typedef struct {
    sol_slot_t      slot;
    sol_hash_t      hash;
} sol_slot_hash_t;

/*
 * Slot hashes sysvar
 */
#define SOL_MAX_SLOT_HASHES 512

typedef struct {
    sol_slot_hash_t entries[SOL_MAX_SLOT_HASHES];
    size_t          len;
} sol_slot_hashes_t;

/*
 * Stake history entry
 */
typedef struct {
    uint64_t        effective;      /* Effective stake */
    uint64_t        activating;     /* Stake activating */
    uint64_t        deactivating;   /* Stake deactivating */
} sol_stake_history_entry_t;

/*
 * Stake history sysvar
 */
#define SOL_MAX_STAKE_HISTORY 512

typedef struct {
    struct {
        uint64_t                    epoch;
        sol_stake_history_entry_t   entry;
    } entries[SOL_MAX_STAKE_HISTORY];
    size_t len;
} sol_stake_history_t;

/*
 * Check if pubkey is a sysvar
 */
bool sol_is_sysvar(const sol_pubkey_t* pubkey);

/*
 * Get sysvar name from pubkey
 */
const char* sol_sysvar_name(const sol_pubkey_t* pubkey);

/*
 * Clock sysvar functions
 */
void sol_clock_init(sol_clock_t* clock);
sol_err_t sol_clock_serialize(const sol_clock_t* clock, uint8_t* data, size_t len);
sol_err_t sol_clock_deserialize(sol_clock_t* clock, const uint8_t* data, size_t len);

/*
 * Rent sysvar functions
 */
void sol_rent_init(sol_rent_t* rent);
sol_err_t sol_rent_serialize(const sol_rent_t* rent, uint8_t* data, size_t len);
sol_err_t sol_rent_deserialize(sol_rent_t* rent, const uint8_t* data, size_t len);

/*
 * Calculate minimum balance for rent exemption
 */
uint64_t sol_rent_minimum_balance(const sol_rent_t* rent, size_t data_len);

/*
 * Calculate rent due for an account
 */
uint64_t sol_rent_due(const sol_rent_t* rent, uint64_t lamports,
                      size_t data_len, double years_elapsed);

/*
 * Epoch schedule sysvar functions
 */
void sol_epoch_schedule_init(sol_epoch_schedule_t* schedule);
sol_err_t sol_epoch_schedule_serialize(const sol_epoch_schedule_t* schedule,
                                        uint8_t* data, size_t len);
sol_err_t sol_epoch_schedule_deserialize(sol_epoch_schedule_t* schedule,
                                          const uint8_t* data, size_t len);

/*
 * Fees sysvar functions
 */
void sol_fees_init(sol_fees_t* fees);
sol_err_t sol_fees_serialize(const sol_fees_t* fees, uint8_t* data, size_t len);
sol_err_t sol_fees_deserialize(sol_fees_t* fees, const uint8_t* data, size_t len);

/*
 * Recent blockhashes functions
 */
void sol_recent_blockhashes_init(sol_recent_blockhashes_t* rbh);
sol_err_t sol_recent_blockhashes_add(sol_recent_blockhashes_t* rbh,
                                      const sol_hash_t* blockhash,
                                      uint64_t lamports_per_signature);
bool sol_recent_blockhashes_contains(const sol_recent_blockhashes_t* rbh,
                                      const sol_hash_t* blockhash);
sol_err_t sol_recent_blockhashes_serialize(const sol_recent_blockhashes_t* rbh,
                                            uint8_t* data, size_t len);
sol_err_t sol_recent_blockhashes_deserialize(sol_recent_blockhashes_t* rbh,
                                              const uint8_t* data, size_t len);

/*
 * Slot hashes functions
 */
void sol_slot_hashes_init(sol_slot_hashes_t* sh);
sol_err_t sol_slot_hashes_add(sol_slot_hashes_t* sh, sol_slot_t slot,
                               const sol_hash_t* hash);
const sol_hash_t* sol_slot_hashes_get(const sol_slot_hashes_t* sh, sol_slot_t slot);
sol_err_t sol_slot_hashes_serialize(const sol_slot_hashes_t* sh,
                                     uint8_t* data, size_t len);
sol_err_t sol_slot_hashes_deserialize(sol_slot_hashes_t* sh,
                                       const uint8_t* data, size_t len);

/*
 * Slot history sysvar helpers
 */
sol_err_t sol_slot_history_serialize_default(uint8_t* data, size_t len);
sol_err_t sol_slot_history_add(uint8_t* data, size_t len, sol_slot_t slot);

/*
 * Stake history functions
 */
void sol_stake_history_init(sol_stake_history_t* sh);
sol_err_t sol_stake_history_add(sol_stake_history_t* sh, uint64_t epoch,
                                 const sol_stake_history_entry_t* entry);
const sol_stake_history_entry_t* sol_stake_history_get(
    const sol_stake_history_t* sh, uint64_t epoch);
sol_err_t sol_stake_history_serialize(const sol_stake_history_t* sh,
                                       uint8_t* data, size_t len);
sol_err_t sol_stake_history_deserialize(sol_stake_history_t* sh,
                                         const uint8_t* data, size_t len);

/*
 * Instructions sysvar
 *
 * The Instructions sysvar is a pseudo-sysvar that provides transaction
 * introspection. Programs can use it to examine other instructions in
 * the current transaction. The data is serialized in a specific format:
 *
 * Format:
 *   - u16: number of instructions
 *   - u16[num_instructions]: offset table (byte offset for each instruction)
 *   - u16: current instruction index
 *   - Serialized instructions (each instruction at its offset)
 *
 * Each serialized instruction contains:
 *   - u8: number of accounts
 *   - Account meta entries (pubkey index, is_signer, is_writable)
 *   - Pubkey: program id
 *   - u16: data length
 *   - u8[data_length]: instruction data
 */

/*
 * Instructions sysvar entry for a single instruction
 */
typedef struct {
    sol_pubkey_t    program_id;
    uint8_t*        accounts;       /* Account indices */
    size_t          num_accounts;
    uint8_t*        data;
    size_t          data_len;
} sol_instructions_entry_t;

/*
 * Instructions sysvar context
 */
typedef struct {
    sol_instructions_entry_t*   entries;
    size_t                      num_entries;
    size_t                      current_index;
} sol_instructions_sysvar_t;

/*
 * Serialize transaction instructions into sysvar format
 *
 * @param txn           Transaction containing instructions
 * @param current_idx   Current instruction index
 * @param out_data      Output buffer for serialized data
 * @param out_len       Input: buffer size, Output: bytes written
 * @return              SOL_OK on success
 */
sol_err_t sol_instructions_sysvar_serialize(
    const sol_transaction_t* txn,
    uint16_t current_idx,
    const bool* demoted_is_writable,
    uint16_t demoted_is_writable_len,
    uint8_t* out_data,
    size_t* out_len
);

/*
 * Get number of instructions from serialized sysvar data
 */
uint16_t sol_instructions_sysvar_get_count(const uint8_t* data, size_t len);

/*
 * Get current instruction index from serialized sysvar data
 */
uint16_t sol_instructions_sysvar_get_current(const uint8_t* data, size_t len);

/*
 * Load instruction data from serialized sysvar
 *
 * @param data          Serialized sysvar data
 * @param len           Length of data
 * @param index         Instruction index to load
 * @param out_program_id Output: program id
 * @param out_data      Output: instruction data pointer (within data buffer)
 * @param out_data_len  Output: instruction data length
 * @return              SOL_OK on success
 */
sol_err_t sol_instructions_sysvar_load_instruction(
    const uint8_t* data,
    size_t len,
    uint16_t index,
    sol_pubkey_t* out_program_id,
    const uint8_t** out_data,
    size_t* out_data_len
);

#endif /* SOL_SYSVAR_H */
