/*
 * sol_bank.h - Bank State Machine
 *
 * The Bank is the core state machine that:
 * - Processes transactions
 * - Maintains account state
 * - Tracks slot/epoch information
 * - Handles fees and rent
 */

#ifndef SOL_BANK_H
#define SOL_BANK_H

#include "sol_account.h"
#include "sol_accounts_db.h"
#include "../crypto/sol_lt_hash.h"
#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../txn/sol_transaction.h"
#include "../entry/sol_entry.h"

/*
 * Bank configuration
 */
typedef struct {
    uint64_t    ticks_per_slot;         /* Ticks per slot (64 default) */
    uint64_t    hashes_per_tick;        /* PoH hashes per tick (12500 mainnet) */
    uint64_t    slots_per_epoch;        /* Slots per epoch */
    uint64_t    lamports_per_signature; /* Fee per signature */
    uint64_t    rent_per_byte_year;     /* Rent cost per byte-year */
    uint64_t    rent_exemption_threshold; /* Multiplier for rent exemption */
} sol_bank_config_t;

#define SOL_BANK_CONFIG_DEFAULT {               \
    .ticks_per_slot = 64,                       \
    .hashes_per_tick = SOL_HASHES_PER_TICK,     \
    .slots_per_epoch = 432000,                  \
    .lamports_per_signature = 5000,             \
    .rent_per_byte_year = 3480,                 \
    .rent_exemption_threshold = 2,              \
}

/*
 * Transaction execution result
 */
typedef struct {
    sol_err_t       status;             /* Execution status */
    uint64_t        fee;                /* Fee charged */
    uint64_t        compute_units_used; /* Compute units consumed */
    uint32_t        logs_count;         /* Number of log messages */
    char**          logs;               /* Log messages (if enabled) */
} sol_tx_result_t;

/*
 * Bank statistics
 */
typedef struct {
    uint64_t    transactions_processed;
    uint64_t    transactions_succeeded;
    uint64_t    transactions_failed;
    uint64_t    signatures_verified;
    uint64_t    total_fees_collected;
    uint64_t    total_priority_fees_collected;
    uint64_t    compute_units_used;

    /* Per-reason pre-validation rejection counters (before signature_count increment) */
    uint64_t    rejected_sanitize;
    uint64_t    rejected_duplicate;
    uint64_t    rejected_v0_resolve;
    uint64_t    rejected_compute_budget;
    uint64_t    rejected_blockhash;
    uint64_t    rejected_fee_payer_missing;
    uint64_t    rejected_insufficient_funds;
    uint64_t    rejected_signature;

    /* BankHashStats-equivalent counters (for Agave parity debugging) */
    uint64_t    num_updated_accounts;
    uint64_t    num_removed_accounts;
    uint64_t    num_lamports_stored;
    uint64_t    total_data_len;
    uint64_t    num_executable_accounts;
} sol_bank_stats_t;

/*
 * Bank handle
 */
typedef struct sol_bank sol_bank_t;

/*
 * Create a new bank for a slot
 */
sol_bank_t* sol_bank_new(
    sol_slot_t                  slot,
    const sol_hash_t*           parent_hash,
    sol_accounts_db_t*          accounts_db,
    const sol_bank_config_t*    config
);

/*
 * Create a child bank (for next slot)
 */
sol_bank_t* sol_bank_new_from_parent(
    sol_bank_t*     parent,
    sol_slot_t      slot
);

/*
 * Destroy bank
 */
void sol_bank_destroy(sol_bank_t* bank);

/*
 * Get bank slot
 */
sol_slot_t sol_bank_slot(const sol_bank_t* bank);

/*
 * Get parent slot
 */
sol_slot_t sol_bank_parent_slot(const sol_bank_t* bank);

/*
 * Set parent slot (used for sysvar SlotHashes).
 *
 * This should be initialized when loading from snapshots.
 */
void sol_bank_set_parent_slot(
    sol_bank_t* bank,
    sol_slot_t  parent_slot
);

/*
 * Get bank epoch
 */
uint64_t sol_bank_epoch(const sol_bank_t* bank);

/*
 * Get slots per epoch (epoch schedule parameter)
 */
uint64_t sol_bank_slots_per_epoch(const sol_bank_t* bank);

/*
 * Get lamports per signature (fee rate)
 */
uint64_t sol_bank_lamports_per_signature(const sol_bank_t* bank);

/*
 * Set fee collector for this bank (typically the slot leader identity).
 *
 * If unset, fee distribution will be skipped (fees remain burned).
 */
void sol_bank_set_fee_collector(
    sol_bank_t*             bank,
    const sol_pubkey_t*     collector
);

/*
 * Get fee collector for this bank (NULL if unset).
 */
const sol_pubkey_t* sol_bank_fee_collector(const sol_bank_t* bank);

/*
 * Get parent hash
 */
const sol_hash_t* sol_bank_parent_hash(const sol_bank_t* bank);

/*
 * Set parent bank hash (used for bank hash computation/voting).
 *
 * This should be initialized when loading from snapshots.
 */
void sol_bank_set_parent_bank_hash(
    sol_bank_t*         bank,
    const sol_hash_t*   parent_bank_hash
);

/*
 * Get blockhash for this bank
 */
const sol_hash_t* sol_bank_blockhash(const sol_bank_t* bank);

/*
 * Set the current bank blockhash and seed the recent blockhash queue.
 *
 * Used when bootstrapping from snapshots to ensure replay uses the correct
 * PoH start hash and to accept transactions that reference this blockhash.
 */
void sol_bank_set_blockhash(
    sol_bank_t*         bank,
    const sol_hash_t*   blockhash
);

/*
 * Seed the bank's recent blockhash queue (BlockhashQueue snapshot state).
 *
 * This is required for Solana-accurate blockhash validation and fee
 * calculation when bootstrapping from snapshots, because the on-chain
 * RecentBlockhashes sysvar may not include every valid entry.
 *
 * @param bank                   Bank to update
 * @param hashes                 Array of recent blockhashes (most recent first)
 * @param lamports_per_signature Fee rate for each corresponding hash
 * @param count                  Number of entries
 * @return                       SOL_OK on success
 */
sol_err_t sol_bank_set_recent_blockhash_queue(
    sol_bank_t*       bank,
    const sol_hash_t* hashes,
    const uint64_t*   lamports_per_signature,
    size_t            count
);

/*
 * Seed the cached bank hash and mark it computed.
 *
 * This is required when bootstrapping from snapshots, as the accounts delta
 * for the snapshot slot is not available.
 */
void sol_bank_set_bank_hash(
    sol_bank_t*         bank,
    const sol_hash_t*   bank_hash
);

/*
 * Seed the accounts LtHash and mark it computed.
 *
 * This is required when bootstrapping from snapshots; otherwise the first
 * forked bank would need to recompute the LtHash over the full accounts set.
 */
void sol_bank_set_accounts_lt_hash(
    sol_bank_t*             bank,
    const sol_lt_hash_t*    accounts_lt_hash
);

/*
 * Compute the accounts LtHash checksum (BLAKE3 digest of LtHash bytes).
 *
 * Useful for logging and parity checks against Agave.
 */
void sol_bank_accounts_lt_hash_checksum(sol_bank_t* bank, sol_blake3_t* out_checksum);

/*
 * Get genesis hash (returns NULL if not set)
 */
const sol_hash_t* sol_bank_genesis_hash(const sol_bank_t* bank);

/*
 * Set genesis hash
 */
void sol_bank_set_genesis_hash(sol_bank_t* bank, const sol_hash_t* genesis_hash);

/*
 * Get the cumulative signature count for this bank.
 *
 * This value is hashed into the bank hash (Solana formula).
 */
uint64_t sol_bank_signature_count(const sol_bank_t* bank);

/*
 * Set the cumulative signature count for this bank.
 *
 * Used when bootstrapping from snapshots to seed the correct count so that
 * future replayed bank hashes match the cluster.
 */
void sol_bank_set_signature_count(sol_bank_t* bank, uint64_t signature_count);

/*
 * Get tick height
 */
uint64_t sol_bank_tick_height(const sol_bank_t* bank);

/*
 * Get the max tick height for the bank (end of slot).
 */
uint64_t sol_bank_max_tick_height(const sol_bank_t* bank);

/*
 * Returns true if the bank has observed all ticks for the slot.
 */
bool sol_bank_has_full_ticks(const sol_bank_t* bank);

/*
 * Load account from bank
 *
 * Returns a clone. Caller must destroy.
 */
sol_account_t* sol_bank_load_account(
    sol_bank_t*             bank,
    const sol_pubkey_t*     pubkey
);

/*
 * Load account from bank, optionally returning stored slot.
 * out_stored_slot may be NULL.
 */
sol_account_t* sol_bank_load_account_ex(
    sol_bank_t*             bank,
    const sol_pubkey_t*     pubkey,
    sol_slot_t*             out_stored_slot
);

/*
 * Set/get the zombie filter slot.  Accounts with lamports==0 and
 * stored_slot <= zombie_filter_slot are treated as non-existent
 * (simulates Agave's clean_accounts).
 */
void sol_bank_set_zombie_filter_slot(sol_bank_t* bank, sol_slot_t slot);
sol_slot_t sol_bank_zombie_filter_slot(const sol_bank_t* bank);

/*
 * Store account in bank
 */
sol_err_t sol_bank_store_account(
    sol_bank_t*             bank,
    const sol_pubkey_t*     pubkey,
    const sol_account_t*    account
);

/*
 * Resolve the full account key list for a transaction.
 *
 * For legacy messages, this returns the static account keys from the message
 * header.
 *
 * For v0 messages, this expands Address Lookup Tables and returns:
 *   static keys + loaded writable + loaded readonly
 *
 * Outputs must have capacity for up to SOL_MAX_MESSAGE_ACCOUNTS entries.
 */
sol_err_t sol_bank_resolve_transaction_accounts(
    const sol_bank_t*           bank,
    const sol_transaction_t*    tx,
    sol_pubkey_t*               out_keys,
    bool*                       out_writable,
    bool*                       out_signer,
    size_t                      out_cap,
    size_t*                     out_len
);

/*
 * Process a single transaction
 */
sol_tx_result_t sol_bank_process_transaction(
    sol_bank_t*                 bank,
    const sol_transaction_t*    tx
);

/*
 * Process multiple transactions (batch)
 */
sol_err_t sol_bank_process_transactions(
    sol_bank_t*                     bank,
    const sol_transaction_t*        txs,
    size_t                          count,
    sol_tx_result_t*                results
);

/*
 * Process an entry (tick or transactions)
 */
sol_err_t sol_bank_process_entry(
    sol_bank_t*             bank,
    const sol_entry_t*      entry
);

/*
 * Process entry batch
 */
sol_err_t sol_bank_process_entries(
    sol_bank_t*                 bank,
    const sol_entry_batch_t*    batch
);

/*
 * Register a tick (PoH advancement)
 */
sol_err_t sol_bank_register_tick(
    sol_bank_t*         bank,
    const sol_hash_t*   tick_hash
);

/*
 * Freeze the bank (no more transactions)
 */
void sol_bank_freeze(sol_bank_t* bank);

/*
 * Check if bank is frozen
 */
bool sol_bank_is_frozen(const sol_bank_t* bank);

/*
 * Compute bank hash
 */
void sol_bank_compute_hash(sol_bank_t* bank, sol_hash_t* out_hash);

/*
 * Get the cached accounts delta hash used for bank-hash computation.
 *
 * Returns false if the delta hash has not been computed/cached (e.g. snapshot
 * bank hash seeded without computing a delta).
 */
bool sol_bank_get_accounts_delta_hash(sol_bank_t* bank, sol_hash_t* out_hash);

/*
 * Get fee for transaction
 */
uint64_t sol_bank_calculate_fee(
    const sol_bank_t*           bank,
    const sol_transaction_t*    tx
);

/*
 * Check if blockhash is valid (recent)
 */
bool sol_bank_is_blockhash_valid(
    const sol_bank_t*   bank,
    const sol_hash_t*   blockhash
);

/*
 * Get statistics
 */
void sol_bank_stats(const sol_bank_t* bank, sol_bank_stats_t* stats);

/*
 * Reset statistics
 */
void sol_bank_stats_reset(sol_bank_t* bank);

/*
 * Get account count
 */
size_t sol_bank_account_count(const sol_bank_t* bank);

/*
 * Get total lamports (capitalization)
 */
uint64_t sol_bank_capitalization(const sol_bank_t* bank);

/*
 * Get minimum balance for rent exemption
 *
 * Calculates the minimum lamports required for an account to be
 * rent-exempt based on its data size and the bank's rent parameters.
 */
uint64_t sol_bank_rent_exempt_minimum(const sol_bank_t* bank, size_t data_len);

/*
 * Check if account can afford fee
 */
bool sol_bank_can_afford_fee(
    sol_bank_t*             bank,
    const sol_pubkey_t*     payer,
    uint64_t                fee
);

/*
 * Get accounts database (for iteration/queries)
 */
sol_accounts_db_t* sol_bank_get_accounts_db(sol_bank_t* bank);

/*
 * AccountsDB ownership helpers
 *
 * Bank forks may need to transfer ownership of the root AccountsDB so that
 * pruning old root banks does not free shared state.
 */
bool sol_bank_owns_accounts_db(const sol_bank_t* bank);
void sol_bank_set_owns_accounts_db(sol_bank_t* bank, bool owns);

/*
 * Transaction status entry
 */
typedef struct {
    sol_signature_t signature;
    sol_slot_t      slot;
    sol_err_t       status;
    uint64_t        fee;
    uint64_t        compute_units;
} sol_tx_status_entry_t;

/*
 * Transaction status cache capacity
 */
#define SOL_TX_STATUS_CACHE_SIZE 10000

/*
 * Record transaction status after execution
 */
void sol_bank_record_tx_status(
    sol_bank_t*             bank,
    const sol_signature_t*  signature,
    sol_err_t               status,
    uint64_t                fee,
    uint64_t                compute_units
);

/*
 * Look up transaction status by signature
 *
 * Returns true if found, false otherwise.
 */
bool sol_bank_get_tx_status(
    const sol_bank_t*       bank,
    const sol_signature_t*  signature,
    sol_tx_status_entry_t*  out_status
);

/*
 * Purge old transaction statuses below a slot
 */
size_t sol_bank_purge_tx_status(
    sol_bank_t*     bank,
    sol_slot_t      min_slot
);

/*
 * Get count of cached transaction statuses
 */
size_t sol_bank_tx_status_count(const sol_bank_t* bank);

/*
 * Simulation result with logs and post-state
 */
#define SOL_SIM_MAX_LOGS 64
#define SOL_SIM_MAX_LOG_LEN 256

typedef struct {
    sol_err_t       status;                 /* Execution status */
    uint64_t        units_consumed;         /* Compute units consumed */
    size_t          logs_count;             /* Number of log messages */
    char            logs[SOL_SIM_MAX_LOGS][SOL_SIM_MAX_LOG_LEN];  /* Log messages */
    size_t          accounts_count;         /* Number of returned accounts */
    sol_account_t*  accounts[8];            /* Post-simulation account states (caller frees) */
} sol_sim_result_t;

/*
 * Simulate transaction execution without committing state
 *
 * This function validates and executes a transaction in simulation mode,
 * collecting logs and returning the simulated result without modifying
 * the accounts database.
 */
sol_sim_result_t sol_bank_simulate_transaction(
    sol_bank_t*                 bank,
    const sol_transaction_t*    tx,
    bool                        sig_verify,
    bool                        replace_blockhash
);

/*
 * Free resources in simulation result
 */
void sol_sim_result_cleanup(sol_sim_result_t* result);

#endif /* SOL_BANK_H */
