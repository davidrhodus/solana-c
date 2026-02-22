/*
 * sol_transaction.h - Solana transaction structure
 *
 * A transaction consists of signatures and a message.
 * The message contains the actual payload (accounts, instructions, blockhash).
 */

#ifndef SOL_TRANSACTION_H
#define SOL_TRANSACTION_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../util/sol_arena.h"
#include "sol_bincode.h"
#include "sol_pubkey.h"
#include "sol_signature.h"
#include "sol_message.h"

/*
 * Maximum transaction size (packet size minus headers)
 */
#define SOL_MAX_TX_SIZE 1232

/*
 * Maximum signatures per transaction
 */
#define SOL_MAX_TX_SIGNATURES 127

/*
 * Parsed transaction structure
 */
typedef struct {
    /* Signatures (zero-copy pointer into original data) */
    const sol_signature_t*  signatures;
    uint8_t                 signatures_len;

    /* Message */
    sol_message_t     message;

    /* Raw message data (for signature verification) */
    const uint8_t*    message_data;
    size_t            message_data_len;

    /* Encoded length of this transaction within the input buffer. */
    size_t            encoded_len;
} sol_transaction_t;

/*
 * Initialize a transaction structure
 */
static inline void
sol_transaction_init(sol_transaction_t* tx) {
    tx->signatures = NULL;
    tx->signatures_len = 0;
    sol_message_init(&tx->message);
    tx->message_data = NULL;
    tx->message_data_len = 0;
    tx->encoded_len = 0;
}

/*
 * Parse a transaction from raw bytes
 *
 * This performs zero-copy parsing where possible. The transaction
 * structure will contain pointers into the input data, so the data
 * must remain valid for the lifetime of the transaction.
 *
 * @param data      Raw transaction bytes
 * @param data_len  Length of transaction data
 * @param tx        Output transaction structure
 * @return          SOL_OK on success, error code otherwise
 */
sol_err_t sol_transaction_decode(
    const uint8_t*      data,
    size_t              data_len,
    sol_transaction_t*  tx
);

/*
 * Encode a transaction to bytes
 *
 * @param tx        Transaction to encode
 * @param out       Output buffer
 * @param out_len   Output buffer capacity
 * @param written   Bytes written (output)
 * @return          SOL_OK on success, error code otherwise
 */
sol_err_t sol_transaction_encode(
    const sol_transaction_t*  tx,
    uint8_t*                  out,
    size_t                    out_len,
    size_t*                   written
);

/*
 * Sanitize a transaction
 *
 * Validates:
 * - Signature count matches header
 * - Message is well-formed
 * - Account indices are valid
 * - No obviously invalid combinations
 *
 * Does NOT verify signatures or check accounts on-chain.
 */
sol_err_t sol_transaction_sanitize(const sol_transaction_t* tx);

/*
 * Get the transaction signature (first signature)
 *
 * The first signature is used as the transaction ID.
 */
static inline const sol_signature_t*
sol_transaction_signature(const sol_transaction_t* tx) {
    if (tx->signatures_len == 0) return NULL;
    return &tx->signatures[0];
}

/*
 * Get the fee payer pubkey
 */
static inline const sol_pubkey_t*
sol_transaction_fee_payer(const sol_transaction_t* tx) {
    return sol_message_fee_payer(&tx->message);
}

/*
 * Check if the transaction uses versioned format
 */
static inline bool
sol_transaction_is_versioned(const sol_transaction_t* tx) {
    return tx->message.version != SOL_MESSAGE_VERSION_LEGACY;
}

/*
 * Get the number of instructions in the transaction
 */
static inline uint8_t
sol_transaction_num_instructions(const sol_transaction_t* tx) {
    return tx->message.instructions_len;
}

/*
 * Transaction verification context
 * Used for parallel signature verification
 */
typedef struct {
    const sol_transaction_t*  tx;
    bool*                     signature_results;  /* Per-signature result */
    bool                      all_valid;          /* Overall result */
} sol_tx_verify_ctx_t;

/*
 * Verify transaction signatures
 *
 * Verifies that all signatures are valid Ed25519 signatures
 * of the message by the corresponding signers.
 *
 * @param tx       Transaction to verify
 * @param results  Per-signature results (optional, can be NULL)
 * @return         true if all signatures valid, false otherwise
 */
bool sol_transaction_verify_signatures(
    const sol_transaction_t*  tx,
    bool*                     results
);

/*
 * Transaction hash (SHA-256 of serialized transaction)
 */
sol_err_t sol_transaction_hash(
    const sol_transaction_t*  tx,
    sol_hash_t*               hash
);

/*
 * Convert transaction signature to base58 (transaction ID)
 */
static inline sol_err_t
sol_transaction_id_to_base58(
    const sol_transaction_t*  tx,
    char*                     out,
    size_t                    out_len
) {
    const sol_signature_t* sig = sol_transaction_signature(tx);
    if (sig == NULL) return SOL_ERR_INVAL;
    return sol_signature_to_base58(sig, out, out_len);
}

#endif /* SOL_TRANSACTION_H */
