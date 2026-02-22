/*
 * sol_shred.h - Shred data structure
 *
 * Shreds are the fundamental data units used in Solana's Turbine block
 * propagation protocol. They represent fragments of blocks that are
 * erasure-coded for reliability.
 *
 * There are two types of shreds:
 * - Data shreds: Contain actual transaction data
 * - Code shreds: Contain erasure coding parity for recovery
 *
 * Shreds are organized into FEC sets for Reed-Solomon erasure coding.
 */

#ifndef SOL_SHRED_H
#define SOL_SHRED_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../txn/sol_pubkey.h"
#include "../txn/sol_signature.h"

/*
 * Shred constants
 */
#define SOL_SHRED_SIZE                     1228    /* Max shred size (bytes) */
#define SOL_SHRED_CODE_PAYLOAD_SIZE        1228    /* Merkle code shred payload size */
#define SOL_SHRED_DATA_PAYLOAD_SIZE        1203    /* Merkle data shred payload size */

#define SOL_SHRED_COMMON_HEADER_SIZE       83      /* Signature + common fields */
#define SOL_SHRED_HEADER_SIZE              SOL_SHRED_COMMON_HEADER_SIZE /* Back-compat name */
#define SOL_SHRED_DATA_HEADER_SIZE         5       /* Data shred extra header */
#define SOL_SHRED_CODE_HEADER_SIZE         6       /* Code shred extra header */
#define SOL_SHRED_DATA_HEADERS_SIZE        (SOL_SHRED_COMMON_HEADER_SIZE + SOL_SHRED_DATA_HEADER_SIZE) /* 88 */
#define SOL_SHRED_CODE_HEADERS_SIZE        (SOL_SHRED_COMMON_HEADER_SIZE + SOL_SHRED_CODE_HEADER_SIZE) /* 89 */

/* Legacy builder helper (non-merkle shreds): maximum bytes that fit after headers. */
#define SOL_SHRED_MAX_DATA_SIZE            (SOL_SHRED_SIZE - SOL_SHRED_DATA_HEADERS_SIZE)
#define SOL_SHRED_MAX_CODE_SIZE            (SOL_SHRED_SIZE - SOL_SHRED_CODE_HEADERS_SIZE)

#define SOL_SHRED_MERKLE_ROOT_SIZE  32      /* Size of merkle root */
#define SOL_SHRED_MERKLE_PROOF_ENTRY_SIZE 20 /* Size of each merkle proof entry */
#define SOL_SHRED_MAX_RETRANSMITTER_SLOTS 16

/*
 * Shred variant - encodes type and version
 */
typedef enum {
    /* Legacy shreds (pre-merkle) */
    SOL_SHRED_VARIANT_LEGACY_DATA   = 0x55,
    SOL_SHRED_VARIANT_LEGACY_CODE   = 0x4A,

    /*
     * Merkle shreds (current Solana / Agave):
     * - lower 4 bits encode merkle proof size (number of 20-byte entries)
     * - upper 4 bits encode type + "resigned" flag
     *
     *   0x60 | proof  : MerkleCode (chained)
     *   0x70 | proof  : MerkleCode (chained, resigned)
     *   0x90 | proof  : MerkleData (chained)
     *   0xB0 | proof  : MerkleData (chained, resigned)
     */
    SOL_SHRED_VARIANT_MERKLE_CODE          = 0x60,
    SOL_SHRED_VARIANT_MERKLE_CODE_RESIGNED = 0x70,
    SOL_SHRED_VARIANT_MERKLE_DATA          = 0x90,
    SOL_SHRED_VARIANT_MERKLE_DATA_RESIGNED = 0xB0,
} sol_shred_variant_t;

/*
 * Shred type
 */
typedef enum {
    SOL_SHRED_TYPE_DATA = 0,
    SOL_SHRED_TYPE_CODE = 1,
} sol_shred_type_t;

/*
 * Shred flags
 */
typedef enum {
    SOL_SHRED_FLAG_SHRED_TICK_REFERENCE_MASK = 0x3F,
    SOL_SHRED_FLAG_DATA_COMPLETE             = 0x40,
    SOL_SHRED_FLAG_LAST_IN_SLOT              = 0x80,
} sol_shred_flags_t;

/*
 * Common shred header (83 bytes)
 *
 * This header appears at the start of every shred.
 */
typedef struct SOL_PACKED {
    sol_signature_t signature;      /* Ed25519 signature (64 bytes) */
    uint8_t         variant;        /* Shred variant byte */
    sol_slot_t      slot;           /* Slot number (8 bytes) */
    uint32_t        index;          /* Shred index within slot */
    uint16_t        version;        /* Shred version (for compatibility) */
    uint32_t        fec_set_index;  /* FEC set this shred belongs to */
} sol_shred_header_t;

SOL_STATIC_ASSERT(sizeof(sol_shred_header_t) == SOL_SHRED_COMMON_HEADER_SIZE,
                  "shred common header must be 83 bytes");

/*
 * Data shred header (5 bytes, after common header)
 */
typedef struct SOL_PACKED {
    uint16_t    parent_offset;      /* Parent slot = slot - parent_offset */
    uint8_t     flags;              /* Shred flags */
    uint16_t    size;               /* Payload size */
} sol_data_shred_header_t;

SOL_STATIC_ASSERT(sizeof(sol_data_shred_header_t) == 5, "data shred header must be 5 bytes");

/*
 * Code shred header (6 bytes, after common header)
 */
typedef struct SOL_PACKED {
    uint16_t    num_data_shreds;    /* Number of data shreds in FEC set */
    uint16_t    num_code_shreds;    /* Number of code shreds in FEC set */
    uint16_t    position;           /* Position within code shreds */
} sol_code_shred_header_t;

SOL_STATIC_ASSERT(sizeof(sol_code_shred_header_t) == 6, "code shred header must be 6 bytes");

/*
 * Shred structure
 *
 * This is a parsed view of a shred, not the wire format.
 */
typedef struct {
    /* Common header fields */
    sol_signature_t signature;
    uint8_t         variant;
    sol_shred_type_t type;
    sol_slot_t      slot;
    uint32_t        index;
    uint16_t        version;
    uint32_t        fec_set_index;

    /* Type-specific header */
    union {
        struct {
            sol_slot_t  parent_slot;
            uint8_t     flags;
            uint16_t    size; /* total: headers + data */
        } data;

        struct {
            uint16_t    num_data_shreds;
            uint16_t    num_code_shreds;
            uint16_t    position;
        } code;
    } header;

    /* Payload */
    const uint8_t*  payload;
    size_t          payload_len;

    /* Merkle proof (for merkle shreds) */
    bool            has_merkle;
    uint8_t         merkle_proof_size;
    bool            resigned;
    const uint8_t*  merkle_proof;

    /* Chained reference (for chained merkle shreds) */
    sol_hash_t      chained_merkle_root;
    const uint8_t*  retransmitter_signature;

    /* Raw shred data */
    const uint8_t*  raw_data;
    size_t          raw_len;
} sol_shred_t;

/*
 * FEC set - group of shreds for erasure coding
 */
typedef struct {
    sol_slot_t      slot;
    uint32_t        fec_set_index;
    uint16_t        num_data;
    uint16_t        num_code;

    sol_shred_t**   data_shreds;
    sol_shred_t**   code_shreds;

    /* Recovery state */
    bool            can_recover;
    uint16_t        data_received;
    uint16_t        code_received;
} sol_fec_set_t;

/*
 * Parse a shred from raw bytes
 *
 * Returns SOL_OK on success, error code on failure.
 * The shred structure contains pointers into the raw data, so
 * the raw data must remain valid while the shred is used.
 */
sol_err_t sol_shred_parse(
    sol_shred_t*        shred,
    const uint8_t*      data,
    size_t              len
);

/*
 * Get the shred variant from raw bytes
 */
sol_shred_variant_t sol_shred_get_variant(const uint8_t* data);

/*
 * Check if shred variant is a data shred
 *
 * Data variants:
 * - Legacy: 0x55
 * - Merkle: 0x80 | proof_size
 * - Chained Merkle: 0x90 | proof_size
 */
static inline bool
sol_shred_variant_is_data(uint8_t variant) {
    if (variant == SOL_SHRED_VARIANT_LEGACY_DATA) {
        return true;
    }
    if (variant == SOL_SHRED_VARIANT_LEGACY_CODE) {
        return false;
    }
    uint8_t prefix = variant & 0xF0;
    return prefix == 0x90 || prefix == 0xB0;
}

/*
 * Check if shred variant is a code shred
 *
 * Code variants:
 * - Legacy: 0x4A
 * - Merkle: 0x40 | proof_size
 * - Chained Merkle: 0x60 | proof_size
 */
static inline bool
sol_shred_variant_is_code(uint8_t variant) {
    if (variant == SOL_SHRED_VARIANT_LEGACY_CODE) {
        return true;
    }
    if (variant == SOL_SHRED_VARIANT_LEGACY_DATA) {
        return false;
    }
    uint8_t prefix = variant & 0xF0;
    return prefix == 0x60 || prefix == 0x70;
}

/*
 * Check if this is a merkle shred
 */
static inline bool
sol_shred_variant_is_merkle(uint8_t variant) {
    if (variant == SOL_SHRED_VARIANT_LEGACY_DATA ||
        variant == SOL_SHRED_VARIANT_LEGACY_CODE) {
        return false;
    }
    uint8_t prefix = variant & 0xF0;
    return prefix == 0x60 || prefix == 0x70 ||
           prefix == 0x90 || prefix == 0xB0;
}

/*
 * Check if shred is the last data shred in the slot
 */
static inline bool
sol_shred_is_last_data(const sol_shred_t* shred) {
    return shred->type == SOL_SHRED_TYPE_DATA &&
           (shred->header.data.flags & SOL_SHRED_FLAG_DATA_COMPLETE);
}

/*
 * Check if shred is the last in the slot
 */
static inline bool
sol_shred_is_last_in_slot(const sol_shred_t* shred) {
    return shred->type == SOL_SHRED_TYPE_DATA &&
           ((shred->header.data.flags & SOL_SHRED_FLAG_LAST_IN_SLOT) != 0);
}

/*
 * Get the shred key (slot, index pair for identification)
 */
typedef struct {
    sol_slot_t  slot;
    uint32_t    index;
    bool        is_data;
} sol_shred_key_t;

static inline void
sol_shred_key_from_shred(sol_shred_key_t* key, const sol_shred_t* shred) {
    key->slot = shred->slot;
    key->index = shred->index;
    key->is_data = (shred->type == SOL_SHRED_TYPE_DATA);
}

/*
 * Verify shred signature
 *
 * Returns true if signature is valid.
 */
bool sol_shred_verify(
    const sol_shred_t*  shred,
    const sol_pubkey_t* leader
);

/*
 * Verify merkle proof (for merkle shreds)
 *
 * Returns true if merkle proof is valid.
 */
bool sol_shred_verify_merkle(const sol_shred_t* shred, sol_hash_t* out_merkle_root);

/*
 * Create an FEC set
 */
sol_fec_set_t* sol_fec_set_new(
    sol_slot_t  slot,
    uint32_t    fec_set_index,
    uint16_t    num_data,
    uint16_t    num_code
);

/*
 * Destroy an FEC set
 */
void sol_fec_set_destroy(sol_fec_set_t* fec);

/*
 * Add a shred to an FEC set
 *
 * Returns SOL_OK if added, SOL_ERR_EXISTS if duplicate.
 */
sol_err_t sol_fec_set_add_shred(
    sol_fec_set_t*      fec,
    sol_shred_t*        shred
);

/*
 * Check if FEC set can recover missing shreds
 */
bool sol_fec_set_can_recover(const sol_fec_set_t* fec);

/*
 * Recover missing shreds using erasure coding
 *
 * Reconstructs missing data shreds using available data and code shreds.
 * Returns SOL_OK on success.
 */
sol_err_t sol_fec_set_recover(sol_fec_set_t* fec);

/*
 * Get shred variant name for logging
 */
const char* sol_shred_variant_name(uint8_t variant);

/*
 * Build a legacy data shred (signed)
 *
 * Creates a minimal legacy (non-merkle) data shred wire payload and signs it
 * with the provided leader keypair.
 */
sol_err_t sol_shred_build_legacy_data(
    const sol_keypair_t* leader,
    sol_slot_t           slot,
    sol_slot_t           parent_slot,
    uint32_t             index,
    uint16_t             version,
    uint32_t             fec_set_index,
    uint8_t              flags,
    const uint8_t*       payload,
    size_t               payload_len,
    uint8_t*             out,
    size_t               out_len,
    size_t*              out_written
);

/*
 * Get shred type name
 */
static inline const char*
sol_shred_type_name(sol_shred_type_t type) {
    return type == SOL_SHRED_TYPE_DATA ? "Data" : "Code";
}

#endif /* SOL_SHRED_H */
