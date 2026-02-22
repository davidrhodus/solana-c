/*
 * sol_vote_tx.h - Vote Transaction Builder
 *
 * Creates and signs vote transactions for submission to the network.
 */

#ifndef SOL_VOTE_TX_H
#define SOL_VOTE_TX_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../crypto/sol_ed25519.h"
#include "../txn/sol_transaction.h"
#include "../programs/sol_vote_program.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct sol_tower;
struct sol_bank;

/*
 * Vote transaction data (compact format)
 */
typedef struct {
    sol_slot_t      slots[SOL_MAX_LOCKOUT_HISTORY];
    uint8_t         slots_len;
    sol_hash_t      hash;           /* Bank hash being voted for */
    uint64_t        timestamp;      /* Unix timestamp (optional) */
    bool            has_timestamp;
} sol_vote_data_t;

/*
 * Vote transaction builder
 */
typedef struct {
    sol_pubkey_t    vote_account;       /* Vote account address */
    sol_pubkey_t    authorized_voter;   /* Voter authority (signer) */
    sol_keypair_t   voter_keypair;      /* Voter keypair for signing */
    sol_hash_t      recent_blockhash;   /* Recent blockhash */
} sol_vote_tx_builder_t;

/*
 * Initialize vote transaction builder
 */
void sol_vote_tx_builder_init(
    sol_vote_tx_builder_t*  builder,
    const sol_pubkey_t*     vote_account,
    const sol_keypair_t*    voter_keypair
);

/*
 * Set the recent blockhash
 */
void sol_vote_tx_builder_set_blockhash(
    sol_vote_tx_builder_t*  builder,
    const sol_hash_t*       blockhash
);

/*
 * Create a vote transaction (legacy format)
 *
 * @param builder       Vote transaction builder
 * @param slots         Slots to vote for
 * @param slots_len     Number of slots
 * @param bank_hash     Hash of the bank being voted for
 * @param out_data      Output buffer for transaction data
 * @param out_len       Output buffer length
 * @param written       Bytes written
 * @return              SOL_OK on success
 */
sol_err_t sol_vote_tx_create(
    sol_vote_tx_builder_t*  builder,
    const sol_slot_t*       slots,
    uint8_t                 slots_len,
    const sol_hash_t*       bank_hash,
    uint8_t*                out_data,
    size_t                  out_len,
    size_t*                 written
);

/*
 * Create a compact vote state update transaction
 *
 * @param builder       Vote transaction builder
 * @param lockouts      Lockout votes (slot + confirmation)
 * @param lockouts_len  Number of lockouts
 * @param root          Root slot (or 0 if none)
 * @param bank_hash     Hash of the bank being voted for
 * @param timestamp     Unix timestamp (0 for none)
 * @param out_data      Output buffer for transaction data
 * @param out_len       Output buffer length
 * @param written       Bytes written
 * @return              SOL_OK on success
 */
sol_err_t sol_vote_tx_create_compact(
    sol_vote_tx_builder_t*  builder,
    const sol_lockout_t*    lockouts,
    uint8_t                 lockouts_len,
    sol_slot_t              root,
    const sol_hash_t*       bank_hash,
    uint64_t                timestamp,
    uint8_t*                out_data,
    size_t                  out_len,
    size_t*                 written
);

/*
 * Create a vote transaction from tower state
 *
 * Convenience function that extracts the vote data from the tower
 * and creates a properly formatted vote transaction.
 *
 * @param builder       Vote transaction builder
 * @param tower         Tower BFT state
 * @param bank          Bank being voted for
 * @param out_data      Output buffer for transaction data
 * @param out_len       Output buffer length
 * @param written       Bytes written
 * @return              SOL_OK on success
 */
sol_err_t sol_vote_tx_from_tower(
    sol_vote_tx_builder_t*  builder,
    const struct sol_tower* tower,
    struct sol_bank*        bank,
    uint8_t*                out_data,
    size_t                  out_len,
    size_t*                 written
);

/*
 * Serialize vote instruction data (legacy format)
 */
sol_err_t sol_vote_instr_serialize(
    const sol_slot_t*   slots,
    uint8_t             slots_len,
    const sol_hash_t*   bank_hash,
    uint64_t            timestamp,
    uint8_t*            out,
    size_t              out_len,
    size_t*             written
);

/*
 * Serialize compact vote state update instruction data
 */
sol_err_t sol_vote_instr_serialize_compact(
    const sol_lockout_t*    lockouts,
    uint8_t                 lockouts_len,
    sol_slot_t              root,
    const sol_hash_t*       bank_hash,
    uint64_t                timestamp,
    uint8_t*                out,
    size_t                  out_len,
    size_t*                 written
);

/*
 * Vote account program ID
 */
extern const sol_pubkey_t SOL_VOTE_PROGRAM_ID;

#ifdef __cplusplus
}
#endif

#endif /* SOL_VOTE_TX_H */
