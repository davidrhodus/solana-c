/*
 * sol_crds_value.h - CRDS Value Types
 *
 * CRDS (Cluster Replicated Data Store) values are signed data items
 * that are replicated across the cluster via gossip.
 *
 * Each value type has:
 * - A pubkey identifying the origin node
 * - A wallclock timestamp for ordering
 * - A signature proving authenticity
 * - Type-specific data
 */

#ifndef SOL_CRDS_VALUE_H
#define SOL_CRDS_VALUE_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../txn/sol_pubkey.h"
#include "../txn/sol_signature.h"
#include "../txn/sol_bincode.h"
#include "../net/sol_net.h"

/*
 * CRDS value types
 */
typedef enum {
    SOL_CRDS_CONTACT_INFO       = 0,
    SOL_CRDS_VOTE               = 1,
    SOL_CRDS_LOWEST_SLOT        = 2,
    SOL_CRDS_SNAPSHOT_HASHES    = 3,
    SOL_CRDS_ACCOUNTS_HASHES    = 4,
    SOL_CRDS_EPOCH_SLOTS        = 5,
    SOL_CRDS_VERSION            = 6,
    SOL_CRDS_NODE_INSTANCE      = 7,
    SOL_CRDS_DUPLICATE_SHRED    = 8,
    SOL_CRDS_INCREMENTAL_SNAPSHOT = 9,
    SOL_CRDS_RESTART_LAST_VOTED_FORK = 10,
    SOL_CRDS_RESTART_HEAVIEST_FORK = 11,

    SOL_CRDS_TYPE_COUNT
} sol_crds_type_t;

/*
 * Socket entry for contact info
 * Maps a socket tag to an endpoint
 */
typedef struct {
    uint8_t         tag;        /* Socket type (see sol_socket_tag_t) */
    sol_sockaddr_t  addr;       /* Socket address */
} sol_socket_entry_t;

/*
 * Socket tags (from Solana protocol)
 */
typedef enum {
    SOL_SOCKET_TAG_GOSSIP             = 0,
    SOL_SOCKET_TAG_SERVE_REPAIR_QUIC  = 1,
    SOL_SOCKET_TAG_RPC                = 2,
    SOL_SOCKET_TAG_RPC_PUBSUB         = 3,
    SOL_SOCKET_TAG_SERVE_REPAIR       = 4,
    SOL_SOCKET_TAG_TPU                = 5,
    SOL_SOCKET_TAG_TPU_FORWARDS       = 6,
    SOL_SOCKET_TAG_TPU_FORWARDS_QUIC  = 7,
    SOL_SOCKET_TAG_TPU_QUIC           = 8,
    SOL_SOCKET_TAG_TPU_VOTE           = 9,
    SOL_SOCKET_TAG_TVU                = 10,
    SOL_SOCKET_TAG_TVU_QUIC           = 11,
    SOL_SOCKET_TAG_TPU_VOTE_QUIC      = 12,
    SOL_SOCKET_TAG_ALPENGLOW          = 13,
} sol_socket_tag_t;

#define SOL_MAX_SOCKETS 14

/*
 * Version info (matches solana_version::Version)
 */
typedef struct {
    uint16_t major;
    uint16_t minor;
    uint16_t patch;
    uint32_t commit;
    uint32_t feature_set;
    uint16_t client;
} sol_version_t;

/*
 * Contact Info - Information about a node
 *
 * This is the v2 format used in recent Solana versions.
 */
typedef struct {
    sol_pubkey_t     pubkey;                    /* Node identity */
    uint64_t         wallclock;                 /* Creation timestamp */
    uint64_t         outset;                    /* Minutes since epoch */
    uint16_t         shred_version;             /* Expected shred version */
    sol_version_t    version;                   /* Software version */
    sol_socket_entry_t sockets[SOL_MAX_SOCKETS]; /* Socket addresses */
    uint8_t          num_sockets;
} sol_contact_info_t;

/*
 * Vote - A node's vote for consensus
 */
typedef struct {
    sol_pubkey_t  from;           /* Voter pubkey */
    uint64_t      wallclock;
    sol_slot_t    slot;           /* Slot being voted on */
    sol_hash_t    hash;           /* Bank hash being voted on */
    uint64_t      timestamp;      /* Optional timestamp */
    /* The actual vote transaction is stored separately */
} sol_crds_vote_t;

/*
 * Lowest Slot - Node's lowest slot it has data for
 */
typedef struct {
    sol_pubkey_t  from;
    uint64_t      wallclock;
    sol_slot_t    lowest;
    sol_slot_t    root;
} sol_crds_lowest_slot_t;

/*
 * Snapshot Hashes - Advertised snapshot slots and hashes
 */
typedef struct {
    sol_pubkey_t  from;
    uint64_t      wallclock;
    sol_slot_t    full_slot;
    sol_hash_t    full_hash;
    /* Incremental snapshots would go here */
} sol_crds_snapshot_hashes_t;

/*
 * Node Version - Software version information
 */
typedef struct {
    sol_pubkey_t  from;
    uint64_t      wallclock;
    uint16_t      major;
    uint16_t      minor;
    uint16_t      patch;
    uint32_t      commit;         /* First 4 bytes of commit hash */
    uint32_t      feature_set;    /* Feature set identifier */
} sol_crds_version_t;

/*
 * Node Instance - Random token for node restart detection
 */
typedef struct {
    sol_pubkey_t  from;
    uint64_t      wallclock;
    uint64_t      token;          /* Random token, changes on restart */
} sol_crds_node_instance_t;

/*
 * CRDS Value - A signed gossip data item
 *
 * This is the wrapper structure that holds any CRDS value type
 * along with its signature.
 */
typedef struct {
    sol_signature_t   signature;    /* Ed25519 signature of serialized data */
    sol_crds_type_t   type;         /* Value type discriminant */

    union {
        sol_contact_info_t          contact_info;
        sol_crds_vote_t             vote;
        sol_crds_lowest_slot_t      lowest_slot;
        sol_crds_snapshot_hashes_t  snapshot_hashes;
        sol_crds_version_t          version;
        sol_crds_node_instance_t    node_instance;
    } data;
} sol_crds_value_t;

/*
 * CRDS value key - Used for indexing values in the store
 *
 * Uniquely identifies a value by (type, pubkey, optional slot/index).
 */
typedef struct {
    sol_crds_type_t type;
    sol_pubkey_t    pubkey;
    uint64_t        index;        /* For types that can have multiple entries */
} sol_crds_key_t;

/*
 * Initialize a contact info structure
 */
static inline void
sol_contact_info_init(sol_contact_info_t* ci) {
    memset(ci, 0, sizeof(*ci));
}

/*
 * Get a socket from contact info by tag
 */
static inline const sol_sockaddr_t*
sol_contact_info_socket(const sol_contact_info_t* ci, sol_socket_tag_t tag) {
    for (uint8_t i = 0; i < ci->num_sockets; i++) {
        if (ci->sockets[i].tag == tag) {
            return &ci->sockets[i].addr;
        }
    }
    return NULL;
}

/*
 * Add a socket to contact info
 */
static inline sol_err_t
sol_contact_info_add_socket(
    sol_contact_info_t* ci,
    sol_socket_tag_t    tag,
    const sol_sockaddr_t* addr
) {
    for (uint8_t i = 0; i < ci->num_sockets; i++) {
        if (ci->sockets[i].tag == tag) {
            sol_sockaddr_copy(&ci->sockets[i].addr, addr);
            return SOL_OK;
        }
    }

    if (ci->num_sockets >= SOL_MAX_SOCKETS) {
        return SOL_ERR_FULL;
    }

    sol_socket_entry_t* entry = &ci->sockets[ci->num_sockets++];
    entry->tag = tag;
    sol_sockaddr_copy(&entry->addr, addr);

    return SOL_OK;
}

/*
 * Get the pubkey from any CRDS value
 */
static inline const sol_pubkey_t*
sol_crds_value_pubkey(const sol_crds_value_t* value) {
    switch (value->type) {
    case SOL_CRDS_CONTACT_INFO:
        return &value->data.contact_info.pubkey;
    case SOL_CRDS_VOTE:
        return &value->data.vote.from;
    case SOL_CRDS_LOWEST_SLOT:
        return &value->data.lowest_slot.from;
    case SOL_CRDS_SNAPSHOT_HASHES:
        return &value->data.snapshot_hashes.from;
    case SOL_CRDS_VERSION:
        return &value->data.version.from;
    case SOL_CRDS_NODE_INSTANCE:
        return &value->data.node_instance.from;
    case SOL_CRDS_ACCOUNTS_HASHES:
    case SOL_CRDS_EPOCH_SLOTS:
    case SOL_CRDS_DUPLICATE_SHRED:
    case SOL_CRDS_INCREMENTAL_SNAPSHOT:
    case SOL_CRDS_RESTART_LAST_VOTED_FORK:
    case SOL_CRDS_RESTART_HEAVIEST_FORK:
    case SOL_CRDS_TYPE_COUNT:
        return NULL;
    }
    return NULL;
}

/*
 * Get the wallclock from any CRDS value
 */
static inline uint64_t
sol_crds_value_wallclock(const sol_crds_value_t* value) {
    switch (value->type) {
    case SOL_CRDS_CONTACT_INFO:
        return value->data.contact_info.wallclock;
    case SOL_CRDS_VOTE:
        return value->data.vote.wallclock;
    case SOL_CRDS_LOWEST_SLOT:
        return value->data.lowest_slot.wallclock;
    case SOL_CRDS_SNAPSHOT_HASHES:
        return value->data.snapshot_hashes.wallclock;
    case SOL_CRDS_VERSION:
        return value->data.version.wallclock;
    case SOL_CRDS_NODE_INSTANCE:
        return value->data.node_instance.wallclock;
    case SOL_CRDS_ACCOUNTS_HASHES:
    case SOL_CRDS_EPOCH_SLOTS:
    case SOL_CRDS_DUPLICATE_SHRED:
    case SOL_CRDS_INCREMENTAL_SNAPSHOT:
    case SOL_CRDS_RESTART_LAST_VOTED_FORK:
    case SOL_CRDS_RESTART_HEAVIEST_FORK:
    case SOL_CRDS_TYPE_COUNT:
        return 0;
    }
    return 0;
}

/*
 * Create a CRDS key from a value
 */
static inline void
sol_crds_key_from_value(sol_crds_key_t* key, const sol_crds_value_t* value) {
    /* Zero the key to ensure consistent hashing (padding bytes) */
    memset(key, 0, sizeof(*key));

    key->type = value->type;
    const sol_pubkey_t* pk = sol_crds_value_pubkey(value);
    if (pk) {
        sol_pubkey_copy(&key->pubkey, pk);
    } else {
        sol_pubkey_init(&key->pubkey);
    }
    key->index = 0;

    /* For vote types, use slot as index */
    if (value->type == SOL_CRDS_VOTE) {
        key->index = value->data.vote.slot;
    }
}

/*
 * Compare CRDS keys
 */
static inline int
sol_crds_key_cmp(const sol_crds_key_t* a, const sol_crds_key_t* b) {
    if (a->type != b->type) {
        return (int)a->type - (int)b->type;
    }
    int pk_cmp = sol_pubkey_cmp(&a->pubkey, &b->pubkey);
    if (pk_cmp != 0) {
        return pk_cmp;
    }
    if (a->index < b->index) return -1;
    if (a->index > b->index) return 1;
    return 0;
}

/*
 * Type name for logging
 */
static inline const char*
sol_crds_type_name(sol_crds_type_t type) {
    switch (type) {
    case SOL_CRDS_CONTACT_INFO: return "ContactInfo";
    case SOL_CRDS_VOTE: return "Vote";
    case SOL_CRDS_LOWEST_SLOT: return "LowestSlot";
    case SOL_CRDS_SNAPSHOT_HASHES: return "SnapshotHashes";
    case SOL_CRDS_ACCOUNTS_HASHES: return "AccountsHashes";
    case SOL_CRDS_EPOCH_SLOTS: return "EpochSlots";
    case SOL_CRDS_VERSION: return "Version";
    case SOL_CRDS_NODE_INSTANCE: return "NodeInstance";
    case SOL_CRDS_DUPLICATE_SHRED: return "DuplicateShred";
    case SOL_CRDS_INCREMENTAL_SNAPSHOT: return "IncrementalSnapshot";
    case SOL_CRDS_RESTART_LAST_VOTED_FORK: return "RestartLastVotedFork";
    case SOL_CRDS_RESTART_HEAVIEST_FORK: return "RestartHeaviestFork";
    case SOL_CRDS_TYPE_COUNT: return "Unknown";
    }
    return "Unknown";
}

#endif /* SOL_CRDS_VALUE_H */
