/*
 * sol_gossip_msg.h - Gossip Protocol Messages
 *
 * Defines the message types used in the Solana gossip protocol:
 * - Pull: Request/Response for fetching CRDS values
 * - Push: Broadcast new values to peers
 * - Prune: Tell peers to stop sending certain origins
 * - Ping/Pong: Liveness checks
 */

#ifndef SOL_GOSSIP_MSG_H
#define SOL_GOSSIP_MSG_H

#include "sol_crds_value.h"
#include "../txn/sol_bincode.h"
#include "../util/sol_arena.h"
#include "../util/sol_types.h"

/*
 * Gossip message types
 */
typedef enum {
    SOL_GOSSIP_MSG_PULL_REQUEST  = 0,
    SOL_GOSSIP_MSG_PULL_RESPONSE = 1,
    SOL_GOSSIP_MSG_PUSH          = 2,
    SOL_GOSSIP_MSG_PRUNE         = 3,
    SOL_GOSSIP_MSG_PING          = 4,
    SOL_GOSSIP_MSG_PONG          = 5,
} sol_gossip_msg_type_t;

/*
 * Maximum values in a single message
 */
#define SOL_GOSSIP_MAX_PUSH_VALUES    64
#define SOL_GOSSIP_MAX_PULL_VALUES    256
#define SOL_GOSSIP_MAX_PRUNE_ORIGINS  64

/*
 * Bloom filter for pull requests
 *
 * Used to efficiently communicate which values we already have.
 */
#define SOL_BLOOM_BITS_SIZE 128  /* 1024 bits = 128 bytes */
#define SOL_BLOOM_NUM_KEYS  10

typedef struct {
    uint64_t keys[SOL_BLOOM_NUM_KEYS];  /* Hash seeds */
    uint8_t  bits[SOL_BLOOM_BITS_SIZE]; /* Bit array */
    uint32_t num_bits_set;
} sol_bloom_t;

/*
 * CRDS filter
 *
 * Mirrors solana_gossip::crds_gossip_pull::CrdsFilter.
 */
typedef struct {
    sol_bloom_t filter;
    uint64_t    mask;
    uint32_t    mask_bits;
} sol_crds_filter_t;

/*
 * Pull Request
 *
 * Requests CRDS values from a peer. Includes a bloom filter of
 * values we already have to avoid redundant transfers.
 */
typedef struct {
    sol_crds_filter_t filter;       /* Bloom filter + mask */
    sol_crds_value_t  self_value;   /* Our contact info for response routing */
} sol_pull_request_t;

/*
 * Pull Response
 *
 * Response to a pull request with CRDS values.
 */
typedef struct {
    sol_pubkey_t      pubkey;       /* Responder's pubkey */
    sol_crds_value_t* values;       /* Array of values */
    uint16_t          values_len;
} sol_pull_response_t;

/*
 * Push Message
 *
 * Pushes new CRDS values to peers.
 */
typedef struct {
    sol_pubkey_t      pubkey;       /* Sender's pubkey */
    sol_crds_value_t* values;       /* Array of values to push */
    uint16_t          values_len;
} sol_push_msg_t;

/*
 * Prune Data
 *
 * Tells a peer to stop forwarding values from certain origins.
 */
typedef struct {
    sol_pubkey_t  pubkey;           /* Sender's pubkey */
    sol_pubkey_t* prunes;           /* Origins to prune */
    uint16_t      prunes_len;
    sol_signature_t signature;      /* Signature over prune data */
    sol_pubkey_t  destination;      /* Peer to prune from */
    uint64_t      wallclock;
} sol_prune_msg_t;

/*
 * Ping Message
 *
 * Liveness check with a random token.
 */
typedef struct {
    sol_pubkey_t    from;           /* Sender's pubkey */
    sol_hash_t      token;          /* Random token */
    sol_signature_t signature;      /* Signature over token */
} sol_ping_t;

/*
 * Pong Message
 *
 * Response to ping with the same token.
 */
typedef struct {
    sol_pubkey_t    from;           /* Responder's pubkey */
    sol_hash_t      hash;           /* Hash of ping token */
    sol_signature_t signature;      /* Signature over hash */
} sol_pong_t;

/*
 * Gossip Protocol Message
 *
 * Union of all message types.
 */
typedef struct {
    sol_gossip_msg_type_t type;

    union {
        sol_pull_request_t  pull_request;
        sol_pull_response_t pull_response;
        sol_push_msg_t      push;
        sol_prune_msg_t     prune;
        sol_ping_t          ping;
        sol_pong_t          pong;
    } data;
} sol_gossip_msg_t;

/*
 * Initialize bloom filter
 */
void sol_bloom_init(sol_bloom_t* bloom);

/*
 * Add a key to the bloom filter
 */
void sol_bloom_add(sol_bloom_t* bloom, const uint8_t* data, size_t len);

/*
 * Check if a key might be in the bloom filter
 */
bool sol_bloom_contains(const sol_bloom_t* bloom, const uint8_t* data, size_t len);

/*
 * Clear bloom filter
 */
void sol_bloom_clear(sol_bloom_t* bloom);

/*
 * Initialize a pull request
 */
void sol_pull_request_init(sol_pull_request_t* req);

/*
 * Initialize a push message
 */
void sol_push_msg_init(sol_push_msg_t* msg);

/*
 * Create a ping message
 */
sol_err_t sol_ping_create(
    sol_ping_t*          ping,
    const sol_pubkey_t*  from,
    const uint8_t        token[32]
);

/*
 * Create a pong response
 */
sol_err_t sol_pong_create(
    sol_pong_t*         pong,
    const sol_pubkey_t* from,
    const sol_ping_t*   ping
);

/*
 * Sign a ping message
 *
 * @param ping     Ping to sign (from and token must be set)
 * @param keypair  Keypair to sign with (pubkey must match ping->from)
 */
void sol_ping_sign(sol_ping_t* ping, const sol_keypair_t* keypair);

/*
 * Sign a pong message
 *
 * @param pong     Pong to sign (from and hash must be set)
 * @param keypair  Keypair to sign with (pubkey must match pong->from)
 */
void sol_pong_sign(sol_pong_t* pong, const sol_keypair_t* keypair);

/*
 * Verify a ping signature
 */
bool sol_ping_verify(const sol_ping_t* ping);

/*
 * Verify a pong signature and token match
 */
bool sol_pong_verify(const sol_pong_t* pong, const sol_ping_t* ping);

/*
 * Message type name
 */
static inline const char*
sol_gossip_msg_type_name(sol_gossip_msg_type_t type) {
    switch (type) {
    case SOL_GOSSIP_MSG_PULL_REQUEST:  return "PullRequest";
    case SOL_GOSSIP_MSG_PULL_RESPONSE: return "PullResponse";
    case SOL_GOSSIP_MSG_PUSH:          return "Push";
    case SOL_GOSSIP_MSG_PRUNE:         return "Prune";
    case SOL_GOSSIP_MSG_PING:          return "Ping";
    case SOL_GOSSIP_MSG_PONG:          return "Pong";
    default:                           return "Unknown";
    }
}

/*
 * Serialize a gossip message
 *
 * Returns SOL_OK on success, error code otherwise.
 */
sol_err_t sol_gossip_msg_encode(
    sol_encoder_t*         enc,
    const sol_gossip_msg_t* msg
);

/*
 * Deserialize a gossip message
 *
 * The arena is used to allocate arrays within the message.
 * Returns SOL_OK on success, error code otherwise.
 */
sol_err_t sol_gossip_msg_decode(
    sol_decoder_t*    dec,
    sol_gossip_msg_t* msg,
    sol_arena_t*      arena
);

/*
 * Free resources in a gossip message
 *
 * Only needed if message was decoded without arena.
 */
void sol_gossip_msg_free(sol_gossip_msg_t* msg);

#endif /* SOL_GOSSIP_MSG_H */
