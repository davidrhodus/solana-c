/*
 * sol_poh.h - Proof of History Implementation
 *
 * Proof of History (PoH) is Solana's verifiable delay function that creates
 * a cryptographic proof of time passage through sequential SHA-256 hashing.
 *
 * Key concepts:
 * - Each hash is computed from the previous hash: H(n) = SHA256(H(n-1))
 * - Transactions are "mixed in" by hashing with transaction data
 * - Provides a global ordering of events without consensus
 * - Enables parallel transaction processing
 */

#ifndef SOL_POH_H
#define SOL_POH_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../crypto/sol_sha256.h"
#include "../txn/sol_pubkey.h"
#include "../txn/sol_transaction.h"
#include <pthread.h>

/*
 * Default hashes per tick (400ms target)
 * This is tuned for typical hardware to produce ~2.5 ticks per second
 */
#define SOL_DEFAULT_HASHES_PER_TICK     12500

/*
 * Default ticks per slot
 * 64 ticks * 400ms = 25.6 seconds per slot (for development)
 * Mainnet uses 64 ticks at ~6.25ms each = 400ms per slot
 */
#define SOL_DEFAULT_TICKS_PER_SLOT      64

/*
 * Default ticks per second (for timing calculations)
 */
#define SOL_DEFAULT_TICKS_PER_SECOND    160

/*
 * Maximum entries per tick
 */
#define SOL_MAX_ENTRIES_PER_TICK        64

/*
 * PoH entry - represents a tick or transaction mix-in
 */
typedef struct {
    uint64_t        num_hashes;         /* Hashes since last entry */
    sol_hash_t      hash;               /* Resulting hash */
    sol_hash_t*     transactions;       /* Transaction hashes mixed in (NULL for tick) */
    size_t          num_transactions;   /* Number of transactions */
} sol_poh_entry_t;

/*
 * PoH configuration
 */
typedef struct {
    uint64_t        hashes_per_tick;    /* Hashes between ticks */
    uint64_t        ticks_per_slot;     /* Ticks per slot */
    uint64_t        target_tick_ns;     /* Target nanoseconds per tick */
} sol_poh_config_t;

#define SOL_POH_CONFIG_DEFAULT {                        \
    .hashes_per_tick = SOL_DEFAULT_HASHES_PER_TICK,     \
    .ticks_per_slot = SOL_DEFAULT_TICKS_PER_SLOT,       \
    .target_tick_ns = 400000000ULL,  /* 400ms */        \
}

/*
 * PoH recorder state
 */
typedef struct sol_poh_recorder sol_poh_recorder_t;

/*
 * PoH tick callback
 */
typedef void (*sol_poh_tick_callback_t)(
    void*                   ctx,
    const sol_poh_entry_t*  tick,
    uint64_t                tick_height
);

/*
 * Create a new PoH recorder
 *
 * @param start_hash        Initial hash to start from
 * @param start_tick        Starting tick height
 * @param config            Configuration (NULL for defaults)
 * @return                  Recorder or NULL on error
 */
sol_poh_recorder_t* sol_poh_recorder_new(
    const sol_hash_t*           start_hash,
    uint64_t                    start_tick,
    const sol_poh_config_t*     config
);

/*
 * Destroy PoH recorder
 */
void sol_poh_recorder_destroy(sol_poh_recorder_t* recorder);

/*
 * Start the PoH recorder thread
 */
sol_err_t sol_poh_recorder_start(sol_poh_recorder_t* recorder);

/*
 * Stop the PoH recorder thread
 */
sol_err_t sol_poh_recorder_stop(sol_poh_recorder_t* recorder);

/*
 * Set the leader slot range
 *
 * When the recorder is in a leader slot, it will produce entries.
 * Outside leader slots, it just ticks without producing entries.
 */
sol_err_t sol_poh_recorder_set_leader_slots(
    sol_poh_recorder_t*     recorder,
    sol_slot_t              start_slot,
    sol_slot_t              end_slot
);

/*
 * Clear leader status (become a validator)
 */
sol_err_t sol_poh_recorder_clear_leader(sol_poh_recorder_t* recorder);

/*
 * Check if currently in a leader slot
 */
bool sol_poh_recorder_is_leader(const sol_poh_recorder_t* recorder);

/*
 * Check if a specific slot is within the current leader range
 *
 * This is useful for components (e.g., block producer) that are producing
 * for a specific slot and need stable behavior on slot boundaries.
 */
bool sol_poh_recorder_is_leader_slot(const sol_poh_recorder_t* recorder, sol_slot_t slot);

/*
 * Record a transaction hash
 *
 * Mixes the transaction hash into the PoH stream.
 * Only valid when in a leader slot.
 *
 * @param recorder      PoH recorder
 * @param tx_hash       Transaction signature hash
 * @return              SOL_OK or error
 */
sol_err_t sol_poh_recorder_record(
    sol_poh_recorder_t*     recorder,
    const sol_hash_t*       tx_hash
);

/*
 * Record multiple transaction hashes
 */
sol_err_t sol_poh_recorder_record_batch(
    sol_poh_recorder_t*     recorder,
    const sol_hash_t*       tx_hashes,
    size_t                  count
);

/*
 * Force a tick (for testing/synchronization)
 */
sol_err_t sol_poh_recorder_tick(sol_poh_recorder_t* recorder);

/*
 * Get current PoH hash
 */
sol_hash_t sol_poh_recorder_hash(const sol_poh_recorder_t* recorder);

/*
 * Get current tick height
 */
uint64_t sol_poh_recorder_tick_height(const sol_poh_recorder_t* recorder);

/*
 * Get current slot
 */
sol_slot_t sol_poh_recorder_slot(const sol_poh_recorder_t* recorder);

/*
 * Get tick within current slot (0 to ticks_per_slot-1)
 */
uint64_t sol_poh_recorder_tick_in_slot(const sol_poh_recorder_t* recorder);

/*
 * Set tick callback
 */
void sol_poh_recorder_set_tick_callback(
    sol_poh_recorder_t*         recorder,
    sol_poh_tick_callback_t     callback,
    void*                       ctx
);

/*
 * Get pending entries since last flush
 *
 * @param recorder      PoH recorder
 * @param out_entries   Output array for entries
 * @param max_entries   Maximum entries to return
 * @return              Number of entries written
 */
size_t sol_poh_recorder_flush_entries(
    sol_poh_recorder_t*     recorder,
    sol_poh_entry_t*        out_entries,
    size_t                  max_entries
);

/*
 * PoH verifier - verify a sequence of PoH entries
 */

/*
 * Verify a single PoH entry
 *
 * @param prev_hash     Previous hash in the chain
 * @param entry         Entry to verify
 * @return              true if valid
 */
bool sol_poh_verify_entry(
    const sol_hash_t*           prev_hash,
    const sol_poh_entry_t*      entry
);

/*
 * Verify a sequence of PoH entries
 *
 * @param start_hash    Starting hash
 * @param entries       Array of entries
 * @param count         Number of entries
 * @return              true if all entries are valid
 */
bool sol_poh_verify_entries(
    const sol_hash_t*           start_hash,
    const sol_poh_entry_t*      entries,
    size_t                      count
);

/*
 * Parallel PoH verification (for faster validation)
 *
 * @param start_hash    Starting hash
 * @param entries       Array of entries
 * @param count         Number of entries
 * @param num_threads   Number of threads to use (0 = auto)
 * @return              true if all entries are valid
 */
bool sol_poh_verify_entries_parallel(
    const sol_hash_t*           start_hash,
    const sol_poh_entry_t*      entries,
    size_t                      count,
    size_t                      num_threads
);

/*
 * Compute N sequential hashes
 *
 * @param start         Starting hash
 * @param num_hashes    Number of hashes to compute
 * @param out           Output hash
 */
void sol_poh_hash_n(
    const sol_hash_t*   start,
    uint64_t            num_hashes,
    sol_hash_t*         out
);

/*
 * Mix in data to PoH hash
 *
 * @param prev          Previous hash
 * @param mixin         Data to mix in
 * @param mixin_len     Length of mixin data
 * @param out           Output hash
 */
void sol_poh_hash_mixin(
    const sol_hash_t*   prev,
    const void*         mixin,
    size_t              mixin_len,
    sol_hash_t*         out
);

/*
 * Free entry resources (transaction array)
 */
void sol_poh_entry_free(sol_poh_entry_t* entry);

#endif /* SOL_POH_H */
