/*
 * sol_tpu.h - Transaction Processing Unit
 *
 * The TPU is the validator's transaction ingestion pipeline:
 *
 * 1. Fetch Stage: Receives transactions via UDP/QUIC
 * 2. SigVerify Stage: Verifies transaction signatures in parallel
 * 3. Banking Stage: Processes transactions through the bank
 * 4. Broadcast Stage: Sends entries to the network (when leader)
 *
 * The TPU only actively processes when the validator is the leader.
 * When not leader, transactions are forwarded to the current leader.
 */

#ifndef SOL_TPU_H
#define SOL_TPU_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../txn/sol_transaction.h"
#include "../poh/sol_block_producer.h"
#include "../net/sol_udp.h"
#include "../net/sol_quic.h"
#include <pthread.h>

/*
 * TPU ports (relative to base port)
 */
#define SOL_TPU_PORT_OFFSET         0
#define SOL_TPU_FORWARDS_PORT_OFFSET 1
#define SOL_TPU_VOTE_PORT_OFFSET    2
#define SOL_TPU_QUIC_PORT_OFFSET    6

/*
 * TPU configuration
 */
typedef struct {
    uint16_t    base_port;              /* Base port for TPU */
    uint32_t    max_pending_txs;        /* Max pending transactions */
    uint32_t    sigverify_threads;      /* Signature verification threads */
    uint32_t    banking_threads;        /* Banking stage threads */
    bool        enable_udp;             /* Enable UDP receiver */
    bool        enable_quic;            /* Enable QUIC receiver */
    bool        forward_transactions;   /* Forward txs when not leader */
    const char* quic_cert_path;         /* TLS certificate for QUIC */
    const char* quic_key_path;          /* TLS private key for QUIC */
} sol_tpu_config_t;

#define SOL_TPU_CONFIG_DEFAULT {            \
    .base_port = 8000,                      \
    .max_pending_txs = 100000,              \
    .sigverify_threads = 4,                 \
    .banking_threads = 4,                   \
    .enable_udp = true,                     \
    .enable_quic = true,                    \
    .forward_transactions = true,           \
    .quic_cert_path = NULL,                 \
    .quic_key_path = NULL,                  \
}

/*
 * Transaction packet (received from network)
 */
typedef struct {
    uint8_t     data[1232];             /* Packet data (MTU size) */
    size_t      len;                    /* Actual length */
    uint64_t    received_ns;            /* Receive timestamp */
    uint32_t    src_ip;                 /* Source IP */
    uint16_t    src_port;               /* Source port */
} sol_tx_packet_t;

/*
 * Signature verification result
 */
typedef struct {
    sol_transaction_t*  tx;             /* Parsed transaction */
    bool                valid;          /* Signature valid */
    sol_err_t           error;          /* Error if invalid */
} sol_sigverify_result_t;

/*
 * TPU statistics
 */
typedef struct {
    uint64_t    packets_received;       /* Total packets received */
    uint64_t    packets_dropped;        /* Packets dropped (queue full) */
    uint64_t    transactions_received;  /* Valid transactions received */
    uint64_t    transactions_processed; /* Transactions processed */
    uint64_t    transactions_forwarded; /* Transactions forwarded */
    uint64_t    signatures_verified;    /* Total signatures verified */
    uint64_t    signatures_failed;      /* Failed signature verifications */
    uint64_t    duplicates_filtered;    /* Duplicate transactions filtered */
} sol_tpu_stats_t;

/*
 * TPU handle
 */
typedef struct sol_tpu sol_tpu_t;

/*
 * Create TPU
 *
 * @param producer      Block producer to send transactions to
 * @param config        Configuration (NULL for defaults)
 * @return              TPU or NULL on error
 */
sol_tpu_t* sol_tpu_new(
    sol_block_producer_t*       producer,
    const sol_tpu_config_t*     config
);

/*
 * Destroy TPU
 */
void sol_tpu_destroy(sol_tpu_t* tpu);

/*
 * Start TPU (begin receiving transactions)
 */
sol_err_t sol_tpu_start(sol_tpu_t* tpu);

/*
 * Stop TPU
 */
sol_err_t sol_tpu_stop(sol_tpu_t* tpu);

/*
 * Check if TPU is running
 */
bool sol_tpu_is_running(const sol_tpu_t* tpu);

/*
 * Set leader mode
 *
 * When leader, transactions are processed locally.
 * When not leader, transactions are forwarded.
 *
 * @param tpu           TPU handle
 * @param is_leader     True if we are the leader
 * @param leader_addr   Leader address (for forwarding, when not leader)
 * @param leader_port   Leader port
 */
sol_err_t sol_tpu_set_leader_mode(
    sol_tpu_t*      tpu,
    bool            is_leader,
    uint32_t        leader_addr,
    uint16_t        leader_port
);

/*
 * Set vote forwarding target (TPU_VOTE)
 *
 * When not leader, vote transactions may be forwarded to the leader's
 * TPU vote socket for faster inclusion.
 */
sol_err_t sol_tpu_set_vote_forwarding_target(
    sol_tpu_t*      tpu,
    uint32_t        leader_addr,
    uint16_t        leader_port
);

/*
 * Submit a transaction directly (bypassing network)
 *
 * Useful for RPC submitted transactions.
 */
sol_err_t sol_tpu_submit(
    sol_tpu_t*                  tpu,
    const sol_transaction_t*    tx
);

/*
 * Submit raw transaction bytes
 */
sol_err_t sol_tpu_submit_raw(
    sol_tpu_t*      tpu,
    const uint8_t*  data,
    size_t          len
);

/*
 * Submit a vote transaction (raw bytes)
 *
 * Votes are forwarded using the vote-forwarding target (TPU_VOTE) when set,
 * otherwise they fall back to the normal forwarding target.
 */
sol_err_t sol_tpu_submit_vote_raw(
    sol_tpu_t*      tpu,
    const uint8_t*  data,
    size_t          len
);

/*
 * Get TPU statistics
 */
sol_tpu_stats_t sol_tpu_stats(const sol_tpu_t* tpu);

/*
 * Reset statistics
 */
void sol_tpu_stats_reset(sol_tpu_t* tpu);

/*
 * Get pending transaction count
 */
size_t sol_tpu_pending_count(const sol_tpu_t* tpu);

/*
 * Signature verification stage
 */

/*
 * Verify transaction signatures
 *
 * @param tx            Transaction to verify
 * @return              true if all signatures valid
 */
bool sol_sigverify_transaction(const sol_transaction_t* tx);

/*
 * Verify batch of transactions in parallel
 *
 * @param txs           Transactions to verify
 * @param results       Output results array
 * @param count         Number of transactions
 * @param num_threads   Worker threads (0 = auto)
 */
void sol_sigverify_batch(
    sol_transaction_t* const*   txs,
    sol_sigverify_result_t*     results,
    size_t                      count,
    size_t                      num_threads
);

/*
 * Transaction deduplication
 */

/*
 * Dedup filter handle
 */
typedef struct sol_dedup_filter sol_dedup_filter_t;

/*
 * Create dedup filter
 *
 * @param capacity      Maximum entries to track
 * @return              Filter or NULL on error
 */
sol_dedup_filter_t* sol_dedup_filter_new(size_t capacity);

/*
 * Destroy dedup filter
 */
void sol_dedup_filter_destroy(sol_dedup_filter_t* filter);

/*
 * Check if transaction is duplicate
 *
 * If not duplicate, adds to filter and returns false.
 * If duplicate, returns true.
 *
 * @param filter        Dedup filter
 * @param sig           Transaction signature
 * @return              true if duplicate
 */
bool sol_dedup_filter_check(
    sol_dedup_filter_t*     filter,
    const sol_signature_t*  sig
);

/*
 * Clear filter entries older than given slot
 */
void sol_dedup_filter_purge(
    sol_dedup_filter_t*     filter,
    sol_slot_t              min_slot
);

/*
 * Get filter size
 */
size_t sol_dedup_filter_size(const sol_dedup_filter_t* filter);

#endif /* SOL_TPU_H */
