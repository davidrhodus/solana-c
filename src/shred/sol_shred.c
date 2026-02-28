/*
 * sol_shred.c - Shred parsing and handling
 */

#include "sol_shred.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include "../util/sol_bits.h"
#include "../crypto/sol_ed25519.h"
#include "../crypto/sol_sha256.h"
#include <string.h>
#include <pthread.h>

/*
 * ==========================================================================
 * Reed-Solomon Erasure Coding over GF(2^8)
 *
 * Uses the irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D)
 * This is the same polynomial used by Solana's Reed-Solomon implementation.
 * ==========================================================================
 */

/* GF(2^8) primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1 */
#define GF_POLY 0x11D
#define GF_SIZE 256

/* Precomputed log and exp tables for fast GF(2^8) multiplication */
static uint8_t gf_log[GF_SIZE];
static uint8_t gf_exp[GF_SIZE * 2];
static pthread_once_t gf_tables_once = PTHREAD_ONCE_INIT;

/*
 * Initialize GF(2^8) log and exp tables
 */
static void
gf_init_tables(void) {
    uint16_t x = 1;
    for (int i = 0; i < 255; i++) {
        gf_exp[i] = (uint8_t)x;
        gf_log[x] = (uint8_t)i;
        x <<= 1;
        if (x & 0x100) {
            x ^= GF_POLY;
        }
    }

    /* Extend exp table for easier multiplication */
    for (int i = 255; i < 512; i++) {
        gf_exp[i] = gf_exp[i - 255];
    }

    gf_log[0] = 0;  /* Log of 0 is undefined, but we set to 0 for safety */
}

static inline void
gf_ensure_tables(void) {
    /* FEC recovery runs on multiple shred verify threads. The GF tables must
     * be initialized exactly once before use to avoid data races and corrupt
     * arithmetic (which can manifest as singular decoding matrices). */
    pthread_once(&gf_tables_once, gf_init_tables);
}

/*
 * GF(2^8) addition (XOR)
 */
static inline uint8_t
gf_add(uint8_t a, uint8_t b) {
    return a ^ b;
}

/*
 * GF(2^8) multiplication using log/exp tables
 */
static inline uint8_t
gf_mul(uint8_t a, uint8_t b) {
    if (a == 0 || b == 0) return 0;
    return gf_exp[gf_log[a] + gf_log[b]];
}

/*
 * GF(2^8) division
 */
__attribute__((unused))
static inline uint8_t
gf_div(uint8_t a, uint8_t b) {
    if (b == 0) return 0;  /* Division by zero */
    if (a == 0) return 0;
    return gf_exp[(gf_log[a] + 255 - gf_log[b]) % 255];
}

/*
 * GF(2^8) multiplicative inverse
 */
static inline uint8_t
gf_inv(uint8_t a) {
    if (a == 0) return 0;
    return gf_exp[255 - gf_log[a]];
}

/*
 * GF(2^8) power
 */
static inline uint8_t
gf_pow(uint8_t a, uint8_t n) {
    if (a == 0) return 0;
    return gf_exp[(gf_log[a] * n) % 255];
}

/*
 * Maximum shreds in an FEC set for static allocation
 */
#define MAX_FEC_SHREDS 128

/*
 * Invert a matrix in-place using Gaussian elimination over GF(2^8)
 *
 * Returns true on success, false if matrix is singular.
 */
static bool
gf_matrix_invert(uint8_t* matrix, uint8_t* inverse, uint16_t n) {
    /* Initialize inverse as identity matrix */
    for (uint16_t i = 0; i < n; i++) {
        for (uint16_t j = 0; j < n; j++) {
            inverse[i * n + j] = (i == j) ? 1 : 0;
        }
    }

    /* Gaussian elimination with partial pivoting */
    for (uint16_t col = 0; col < n; col++) {
        /* Find pivot */
        uint16_t pivot_row = col;
        for (uint16_t row = col + 1; row < n; row++) {
            if (matrix[row * n + col] > matrix[pivot_row * n + col]) {
                pivot_row = row;
            }
        }

        /* Swap rows if needed */
        if (pivot_row != col) {
            for (uint16_t j = 0; j < n; j++) {
                uint8_t tmp = matrix[col * n + j];
                matrix[col * n + j] = matrix[pivot_row * n + j];
                matrix[pivot_row * n + j] = tmp;

                tmp = inverse[col * n + j];
                inverse[col * n + j] = inverse[pivot_row * n + j];
                inverse[pivot_row * n + j] = tmp;
            }
        }

        /* Check for singular matrix */
        if (matrix[col * n + col] == 0) {
            return false;
        }

        /* Scale pivot row */
        uint8_t pivot = matrix[col * n + col];
        uint8_t pivot_inv = gf_inv(pivot);
        for (uint16_t j = 0; j < n; j++) {
            matrix[col * n + j] = gf_mul(matrix[col * n + j], pivot_inv);
            inverse[col * n + j] = gf_mul(inverse[col * n + j], pivot_inv);
        }

        /* Eliminate column */
        for (uint16_t row = 0; row < n; row++) {
            if (row != col && matrix[row * n + col] != 0) {
                uint8_t factor = matrix[row * n + col];
                for (uint16_t j = 0; j < n; j++) {
                    matrix[row * n + j] = gf_add(matrix[row * n + j],
                                                  gf_mul(factor, matrix[col * n + j]));
                    inverse[row * n + j] = gf_add(inverse[row * n + j],
                                                   gf_mul(factor, inverse[col * n + j]));
                }
            }
        }
    }

    return true;
}

/*
 * Build a Vandermonde encoding matrix row for a given index
 *
 * For systematic RS codes:
 * - Rows 0..k-1 are identity (data shreds)
 * - Rows k..n-1 are parity rows using powers of primitive element
 *
 * row[j] = i^j where i is the row index in the full encoding matrix
 */
static void
build_encoding_row(uint8_t* row, uint16_t num_data, uint16_t row_idx) {
    if (row_idx < num_data) {
        /* Identity row for data shreds */
        for (uint16_t j = 0; j < num_data; j++) {
            row[j] = (row_idx == j) ? 1 : 0;
        }
    } else {
        /* Parity row: use Vandermonde structure with generator 2 */
        uint8_t gen = (uint8_t)(row_idx - num_data + 1);
        for (uint16_t j = 0; j < num_data; j++) {
            row[j] = gf_pow(gen, (uint8_t)j);
        }
    }
}

/*
 * Get merkle proof size from variant byte
 */
static uint8_t
get_merkle_proof_size(uint8_t variant) {
    if (variant == SOL_SHRED_VARIANT_LEGACY_DATA ||
        variant == SOL_SHRED_VARIANT_LEGACY_CODE) {
        return 0;
    }

    /* For merkle shreds, lower 4 bits encode proof size */
    return variant & 0x0F;
}

static bool
is_resigned_variant(uint8_t variant) {
    uint8_t prefix = variant & 0xF0;
    return prefix == SOL_SHRED_VARIANT_MERKLE_CODE_RESIGNED ||
           prefix == SOL_SHRED_VARIANT_MERKLE_DATA_RESIGNED;
}

sol_shred_variant_t
sol_shred_get_variant(const uint8_t* data) {
    if (!data) return 0;
    /* Variant is at offset 64 (after signature) */
    return data[64];
}

static sol_err_t
get_merkle_capacity(sol_shred_type_t type, uint8_t proof_size, bool resigned, size_t* out_capacity) {
    if (!out_capacity) return SOL_ERR_INVAL;

    size_t payload_size = (type == SOL_SHRED_TYPE_DATA)
                              ? (size_t)SOL_SHRED_DATA_PAYLOAD_SIZE
                              : (size_t)SOL_SHRED_CODE_PAYLOAD_SIZE;
    size_t headers_size = (type == SOL_SHRED_TYPE_DATA)
                              ? (size_t)SOL_SHRED_DATA_HEADERS_SIZE
                              : (size_t)SOL_SHRED_CODE_HEADERS_SIZE;

    size_t fixed = headers_size + (size_t)SOL_SHRED_MERKLE_ROOT_SIZE +
                   (size_t)proof_size * (size_t)SOL_SHRED_MERKLE_PROOF_ENTRY_SIZE +
                   (resigned ? (size_t)SOL_SIGNATURE_SIZE : 0u);

    if (fixed > payload_size) {
        return SOL_ERR_INVAL;
    }

    *out_capacity = payload_size - fixed;
    return SOL_OK;
}

sol_err_t
sol_shred_parse(sol_shred_t* shred, const uint8_t* data, size_t len) {
    if (!shred || !data) {
        return SOL_ERR_INVAL;
    }

    if (len < SOL_SIGNATURE_SIZE + 1u) {
        return SOL_ERR_TRUNCATED;
    }

    uint8_t variant = data[64];

    sol_shred_type_t type;
    if (sol_shred_variant_is_data(variant)) {
        type = SOL_SHRED_TYPE_DATA;
    } else if (sol_shred_variant_is_code(variant)) {
        type = SOL_SHRED_TYPE_CODE;
    } else {
        return SOL_ERR_INVAL;
    }

    /* Clamp to expected payload size for Merkle shreds. */
    size_t shred_len = len;
    if (sol_shred_variant_is_merkle(variant)) {
        shred_len = (type == SOL_SHRED_TYPE_DATA)
                        ? (size_t)SOL_SHRED_DATA_PAYLOAD_SIZE
                        : (size_t)SOL_SHRED_CODE_PAYLOAD_SIZE;
        if (len < shred_len) {
            return SOL_ERR_TRUNCATED;
        }
    } else if (len > SOL_SHRED_SIZE) {
        shred_len = SOL_SHRED_SIZE;
    }

    memset(shred, 0, sizeof(*shred));
    shred->raw_data = data;
    shred->raw_len = shred_len;

    /* Common header (wire offsets). */
    memcpy(shred->signature.bytes, data, SOL_SIGNATURE_SIZE);
    shred->variant = variant;
    shred->type = type;

    if (shred_len < SOL_SHRED_COMMON_HEADER_SIZE) {
        return SOL_ERR_TRUNCATED;
    }

    shred->slot = sol_load_u64_le(data + 65);
    shred->index = sol_load_u32_le(data + 73);
    shred->version = sol_load_u16_le(data + 77);
    shred->fec_set_index = sol_load_u32_le(data + 79);

    size_t offset = SOL_SHRED_COMMON_HEADER_SIZE;

    if (type == SOL_SHRED_TYPE_DATA) {
        if (shred_len < SOL_SHRED_DATA_HEADERS_SIZE) {
            return SOL_ERR_TRUNCATED;
        }
        uint16_t parent_offset = sol_load_u16_le(data + offset);
        if (parent_offset > shred->slot) return SOL_ERR_INVAL;
        shred->header.data.parent_slot = shred->slot - parent_offset;
        offset += 2;
        shred->header.data.flags = data[offset++];
        shred->header.data.size = sol_load_u16_le(data + offset);
        offset += 2;

        if (sol_shred_variant_is_merkle(variant)) {
            shred->has_merkle = true;
            shred->merkle_proof_size = get_merkle_proof_size(variant);
            shred->resigned = is_resigned_variant(variant);

            size_t capacity = 0;
            SOL_TRY(get_merkle_capacity(type, shred->merkle_proof_size, shred->resigned, &capacity));

            size_t headers_size = SOL_SHRED_DATA_HEADERS_SIZE;
            if (shred->header.data.size < headers_size ||
                shred->header.data.size > headers_size + capacity) {
                return SOL_ERR_INVAL;
            }

            shred->payload = data + headers_size;
            shred->payload_len = (size_t)shred->header.data.size - headers_size;

            size_t chain_off = headers_size + capacity;
            if (chain_off + SOL_SHRED_MERKLE_ROOT_SIZE > shred_len) return SOL_ERR_INVAL;
            memcpy(shred->chained_merkle_root.bytes, data + chain_off, SOL_SHRED_MERKLE_ROOT_SIZE);

            size_t proof_off = chain_off + SOL_SHRED_MERKLE_ROOT_SIZE;
            size_t proof_bytes = (size_t)shred->merkle_proof_size * (size_t)SOL_SHRED_MERKLE_PROOF_ENTRY_SIZE;
            if (proof_off + proof_bytes > shred_len) return SOL_ERR_INVAL;
            shred->merkle_proof = data + proof_off;

            size_t retrans_off = proof_off + proof_bytes;
            if (shred->resigned) {
                if (retrans_off + SOL_SIGNATURE_SIZE > shred_len) return SOL_ERR_INVAL;
                shred->retransmitter_signature = data + retrans_off;
            }
        } else {
            shred->has_merkle = false;
            size_t headers_size = SOL_SHRED_DATA_HEADERS_SIZE;
            shred->payload = data + headers_size;
            size_t size_total = (size_t)shred->header.data.size;
            if (size_total >= headers_size && size_total <= shred_len) {
                shred->payload_len = size_total - headers_size;
            } else {
                shred->payload_len = shred_len - headers_size;
            }
        }
    } else {
        if (shred_len < SOL_SHRED_CODE_HEADERS_SIZE) {
            return SOL_ERR_TRUNCATED;
        }
        shred->header.code.num_data_shreds = sol_load_u16_le(data + offset);
        offset += 2;
        shred->header.code.num_code_shreds = sol_load_u16_le(data + offset);
        offset += 2;
        shred->header.code.position = sol_load_u16_le(data + offset);
        offset += 2;

        if (sol_shred_variant_is_merkle(variant)) {
            shred->has_merkle = true;
            shred->merkle_proof_size = get_merkle_proof_size(variant);
            shred->resigned = is_resigned_variant(variant);

            size_t capacity = 0;
            SOL_TRY(get_merkle_capacity(type, shred->merkle_proof_size, shred->resigned, &capacity));

            size_t headers_size = SOL_SHRED_CODE_HEADERS_SIZE;
            if (headers_size + capacity > shred_len) return SOL_ERR_INVAL;

            shred->payload = data + headers_size;
            shred->payload_len = capacity;

            size_t chain_off = headers_size + capacity;
            if (chain_off + SOL_SHRED_MERKLE_ROOT_SIZE > shred_len) return SOL_ERR_INVAL;
            memcpy(shred->chained_merkle_root.bytes, data + chain_off, SOL_SHRED_MERKLE_ROOT_SIZE);

            size_t proof_off = chain_off + SOL_SHRED_MERKLE_ROOT_SIZE;
            size_t proof_bytes = (size_t)shred->merkle_proof_size * (size_t)SOL_SHRED_MERKLE_PROOF_ENTRY_SIZE;
            if (proof_off + proof_bytes > shred_len) return SOL_ERR_INVAL;
            shred->merkle_proof = data + proof_off;

            size_t retrans_off = proof_off + proof_bytes;
            if (shred->resigned) {
                if (retrans_off + SOL_SIGNATURE_SIZE > shred_len) return SOL_ERR_INVAL;
                shred->retransmitter_signature = data + retrans_off;
            }
        } else {
            shred->has_merkle = false;
            shred->payload = data + SOL_SHRED_CODE_HEADERS_SIZE;
            shred->payload_len = shred_len - SOL_SHRED_CODE_HEADERS_SIZE;
        }
    }

    return SOL_OK;
}

bool
sol_shred_verify(const sol_shred_t* shred, const sol_pubkey_t* leader) {
    if (!shred || !leader || !shred->raw_data) {
        return false;
    }

    if (!shred->has_merkle) {
        /* Legacy: signed portion is everything after the signature. */
        const uint8_t* msg = shred->raw_data + SOL_SIGNATURE_SIZE;
        size_t msg_len = shred->raw_len - SOL_SIGNATURE_SIZE;
        return sol_ed25519_verify(leader, msg, msg_len, &shred->signature);
    }

    sol_hash_t merkle_root;
    if (!sol_shred_verify_merkle(shred, &merkle_root)) {
        return false;
    }

    /* Merkle shreds: leader signs the Merkle root (Hash) of the erasure batch. */
    if (sol_ed25519_verify(leader,
                           merkle_root.bytes,
                           SOL_SHRED_MERKLE_ROOT_SIZE,
                           &shred->signature)) {
        return true;
    }

    /* Some resigned shred formats swap the leader signature into the trailing
     * retransmitter signature field. Accept either layout when verifying
     * against the slot leader. */
    if (shred->resigned && shred->retransmitter_signature) {
        sol_signature_t alt;
        memcpy(alt.bytes, shred->retransmitter_signature, SOL_SIGNATURE_SIZE);
        return sol_ed25519_verify(leader,
                                  merkle_root.bytes,
                                  SOL_SHRED_MERKLE_ROOT_SIZE,
                                  &alt);
    }

    return false;
}

bool
sol_shred_verify_merkle(const sol_shred_t* shred, sol_hash_t* out_merkle_root) {
    if (!shred || !shred->has_merkle || !shred->merkle_proof || !out_merkle_root) {
        return false;
    }

    if (shred->raw_len < SOL_SIGNATURE_SIZE) {
        return false;
    }

    static const uint8_t MERKLE_HASH_PREFIX_LEAF[] = "\x00SOLANA_MERKLE_SHREDS_LEAF";
    static const uint8_t MERKLE_HASH_PREFIX_NODE[] = "\x01SOLANA_MERKLE_SHREDS_NODE";
    const size_t prefix_leaf_len = sizeof(MERKLE_HASH_PREFIX_LEAF) - 1u;
    const size_t prefix_node_len = sizeof(MERKLE_HASH_PREFIX_NODE) - 1u;

    size_t capacity = 0;
    if (get_merkle_capacity(shred->type, shred->merkle_proof_size, shred->resigned, &capacity) != SOL_OK) {
        return false;
    }

    size_t headers_size = (shred->type == SOL_SHRED_TYPE_DATA)
                              ? (size_t)SOL_SHRED_DATA_HEADERS_SIZE
                              : (size_t)SOL_SHRED_CODE_HEADERS_SIZE;

    /* Hash the shred leaf bytes: [signature..proof_offset). */
    size_t chain_off = headers_size + capacity;
    size_t proof_off = chain_off + (size_t)SOL_SHRED_MERKLE_ROOT_SIZE;
    size_t proof_bytes = (size_t)shred->merkle_proof_size * (size_t)SOL_SHRED_MERKLE_PROOF_ENTRY_SIZE;
    size_t resigned_bytes = shred->resigned ? (size_t)SOL_SIGNATURE_SIZE : 0u;

    if (proof_off + proof_bytes + resigned_bytes > shred->raw_len) {
        return false;
    }
    if (proof_off < SOL_SIGNATURE_SIZE) {
        return false;
    }

    const uint8_t* leaf_data = shred->raw_data + SOL_SIGNATURE_SIZE;
    size_t leaf_len = proof_off - SOL_SIGNATURE_SIZE;

    sol_sha256_ctx_t leaf_ctx;
    sol_sha256_init(&leaf_ctx);
    sol_sha256_update(&leaf_ctx, MERKLE_HASH_PREFIX_LEAF, prefix_leaf_len);
    sol_sha256_update(&leaf_ctx, leaf_data, leaf_len);
    sol_sha256_t leaf_digest;
    sol_sha256_final(&leaf_ctx, &leaf_digest);

    sol_hash_t node;
    memcpy(node.bytes, leaf_digest.bytes, SOL_SHRED_MERKLE_ROOT_SIZE);

    /* Shred's leaf index within the erasure batch. */
    uint32_t index = 0;
    if (shred->type == SOL_SHRED_TYPE_DATA) {
        if (shred->index < shred->fec_set_index) return false;
        index = shred->index - shred->fec_set_index;
    } else {
        index = (uint32_t)shred->header.code.num_data_shreds +
                (uint32_t)shred->header.code.position;
    }

    /* Walk up the Merkle proof. Proof entries are 20-byte truncated hashes. */
    for (uint8_t i = 0; i < shred->merkle_proof_size; i++) {
        const uint8_t* other = shred->merkle_proof + (size_t)i * (size_t)SOL_SHRED_MERKLE_PROOF_ENTRY_SIZE;
        const uint8_t* left = (index & 1u) ? other : node.bytes;
        const uint8_t* right = (index & 1u) ? node.bytes : other;

        sol_sha256_ctx_t ctx;
        sol_sha256_init(&ctx);
        sol_sha256_update(&ctx, MERKLE_HASH_PREFIX_NODE, prefix_node_len);
        sol_sha256_update(&ctx, left, SOL_SHRED_MERKLE_PROOF_ENTRY_SIZE);
        sol_sha256_update(&ctx, right, SOL_SHRED_MERKLE_PROOF_ENTRY_SIZE);
        sol_sha256_t digest;
        sol_sha256_final(&ctx, &digest);

        memcpy(node.bytes, digest.bytes, SOL_SHRED_MERKLE_ROOT_SIZE);
        index >>= 1;
    }

    if (index != 0) {
        return false;
    }

    *out_merkle_root = node;
    return true;
}

sol_fec_set_t*
sol_fec_set_new(sol_slot_t slot, uint32_t fec_set_index,
                uint16_t num_data, uint16_t num_code) {
    sol_fec_set_t* fec = sol_calloc(1, sizeof(sol_fec_set_t));
    if (!fec) return NULL;

    fec->slot = slot;
    fec->fec_set_index = fec_set_index;
    fec->num_data = num_data;
    fec->num_code = num_code;

    if (num_data > 0) {
        fec->data_shreds = sol_calloc(num_data, sizeof(sol_shred_t*));
        if (!fec->data_shreds) {
            sol_free(fec);
            return NULL;
        }
    }

    if (num_code > 0) {
        fec->code_shreds = sol_calloc(num_code, sizeof(sol_shred_t*));
        if (!fec->code_shreds) {
            sol_free(fec->data_shreds);
            sol_free(fec);
            return NULL;
        }
    }

    return fec;
}

void
sol_fec_set_destroy(sol_fec_set_t* fec) {
    if (!fec) return;

    sol_free(fec->data_shreds);
    sol_free(fec->code_shreds);
    sol_free(fec);
}

sol_err_t
sol_fec_set_add_shred(sol_fec_set_t* fec, sol_shred_t* shred) {
    if (!fec || !shred) {
        return SOL_ERR_INVAL;
    }

    if (shred->slot != fec->slot ||
        shred->fec_set_index != fec->fec_set_index) {
        return SOL_ERR_INVAL;
    }

    if (shred->type == SOL_SHRED_TYPE_DATA) {
        uint32_t idx = shred->index - fec->fec_set_index;
        if (idx >= fec->num_data) {
            return SOL_ERR_RANGE;
        }

        if (fec->data_shreds[idx]) {
            return SOL_ERR_EXISTS;
        }

        fec->data_shreds[idx] = shred;
        fec->data_received++;

    } else { /* CODE shred */
        uint16_t pos = shred->header.code.position;
        if (pos >= fec->num_code) {
            return SOL_ERR_RANGE;
        }

        if (fec->code_shreds[pos]) {
            return SOL_ERR_EXISTS;
        }

        fec->code_shreds[pos] = shred;
        fec->code_received++;
    }

    /* Update recovery status */
    fec->can_recover = (fec->data_received + fec->code_received) >= fec->num_data;

    return SOL_OK;
}

bool
sol_fec_set_can_recover(const sol_fec_set_t* fec) {
    if (!fec) return false;

    /* Reed-Solomon can recover if we have at least num_data shreds total */
    return (fec->data_received + fec->code_received) >= fec->num_data;
}

sol_err_t
sol_fec_set_recover(sol_fec_set_t* fec) {
    if (!fec) {
        return SOL_ERR_INVAL;
    }

    if (!sol_fec_set_can_recover(fec)) {
        return SOL_ERR_FEC_RECOVERY;
    }

    if (fec->data_received == fec->num_data) {
        /* Already have all data shreds, nothing to recover */
        return SOL_OK;
    }

    /* Initialize GF tables (thread-safe) */
    gf_ensure_tables();

    uint16_t k = fec->num_data;
    uint16_t total = fec->num_data + fec->num_code;

    if (k > MAX_FEC_SHREDS || total > MAX_FEC_SHREDS) {
        sol_log_warn("FEC set too large for recovery: k=%u total=%u", k, total);
        return SOL_ERR_TOO_LARGE;
    }

    /*
     * Build the decoding matrix from received shreds.
     *
     * Select k rows from the encoding matrix corresponding to shreds we have.
     * Then invert this k×k matrix.
     */
    uint8_t* encoding_rows = sol_calloc(k * k, sizeof(uint8_t));
    uint8_t* inverse = sol_calloc(k * k, sizeof(uint8_t));
    uint16_t* row_indices = sol_calloc(k, sizeof(uint16_t));
    sol_shred_t** received_shreds = sol_calloc(k, sizeof(sol_shred_t*));

    if (!encoding_rows || !inverse || !row_indices || !received_shreds) {
        sol_free(encoding_rows);
        sol_free(inverse);
        sol_free(row_indices);
        sol_free(received_shreds);
        return SOL_ERR_NOMEM;
    }

    /* Collect k received shreds and their row indices */
    uint16_t collected = 0;

    /* First, add data shreds we have */
    for (uint16_t i = 0; i < fec->num_data && collected < k; i++) {
        if (fec->data_shreds[i]) {
            row_indices[collected] = i;
            received_shreds[collected] = fec->data_shreds[i];
            collected++;
        }
    }

    /* Then, add code shreds to fill up to k */
    for (uint16_t i = 0; i < fec->num_code && collected < k; i++) {
        if (fec->code_shreds[i]) {
            row_indices[collected] = fec->num_data + i;
            received_shreds[collected] = fec->code_shreds[i];
            collected++;
        }
    }

    if (collected < k) {
        /* Should not happen if can_recover was true */
        sol_free(encoding_rows);
        sol_free(inverse);
        sol_free(row_indices);
        sol_free(received_shreds);
        return SOL_ERR_FEC_RECOVERY;
    }

    /* Build the encoding submatrix from selected rows */
    for (uint16_t i = 0; i < k; i++) {
        build_encoding_row(encoding_rows + i * k, k, row_indices[i]);
    }

    /* Invert the matrix */
    if (!gf_matrix_invert(encoding_rows, inverse, k)) {
        sol_log_debug("FEC matrix inversion failed (singular matrix)");
        sol_free(encoding_rows);
        sol_free(inverse);
        sol_free(row_indices);
        sol_free(received_shreds);
        return SOL_ERR_FEC_RECOVERY;
    }

    sol_shred_t* ref_shred = received_shreds[0];
    if (ref_shred && ref_shred->has_merkle) {
        /* Merkle shred FEC recovery (Agave-compatible): reconstruct missing data/code
         * erasure shards, rebuild Merkle tree, and attach proofs for recovered shreds. */

        sol_shred_t* ref_code = NULL;
        for (uint16_t i = 0; i < fec->num_code; i++) {
            if (fec->code_shreds[i]) {
                ref_code = fec->code_shreds[i];
                break;
            }
        }
        if (!ref_code) {
            sol_free(encoding_rows);
            sol_free(inverse);
            sol_free(row_indices);
            sol_free(received_shreds);
            return SOL_ERR_FEC_RECOVERY;
        }

        uint8_t proof_size = ref_code->merkle_proof_size;
        bool resigned = ref_code->resigned;

        /* Compute the expected Merkle root from any verified shred in the batch. */
        sol_hash_t expected_root;
        if (!sol_shred_verify_merkle(ref_code, &expected_root)) {
            sol_free(encoding_rows);
            sol_free(inverse);
            sol_free(row_indices);
            sol_free(received_shreds);
            return SOL_ERR_FEC_RECOVERY;
        }

        const sol_signature_t leader_sig = ref_code->signature;
        uint16_t version = ref_code->version;

        /* First coding index is common_header.index - coding_header.position. */
        if (ref_code->index < (uint32_t)ref_code->header.code.position) {
            sol_free(encoding_rows);
            sol_free(inverse);
            sol_free(row_indices);
            sol_free(received_shreds);
            return SOL_ERR_FEC_RECOVERY;
        }
        uint32_t first_coding_index = ref_code->index - (uint32_t)ref_code->header.code.position;

        size_t shard_size = 0;
        if (get_merkle_capacity(SOL_SHRED_TYPE_CODE, proof_size, resigned, &shard_size) != SOL_OK || shard_size == 0) {
            sol_free(encoding_rows);
            sol_free(inverse);
            sol_free(row_indices);
            sol_free(received_shreds);
            return SOL_ERR_FEC_RECOVERY;
        }

        size_t data_capacity = 0;
        if (get_merkle_capacity(SOL_SHRED_TYPE_DATA, proof_size, resigned, &data_capacity) != SOL_OK) {
            sol_free(encoding_rows);
            sol_free(inverse);
            sol_free(row_indices);
            sol_free(received_shreds);
            return SOL_ERR_FEC_RECOVERY;
        }

        size_t num_shards = (size_t)fec->num_data + (size_t)fec->num_code;
        if (num_shards == 0) {
            sol_free(encoding_rows);
            sol_free(inverse);
            sol_free(row_indices);
            sol_free(received_shreds);
            return SOL_ERR_FEC_RECOVERY;
        }

        uint8_t data_variant = (uint8_t)((resigned ? SOL_SHRED_VARIANT_MERKLE_DATA_RESIGNED
                                                   : SOL_SHRED_VARIANT_MERKLE_DATA) |
                                         (proof_size & 0x0Fu));
        uint8_t code_variant = (uint8_t)((resigned ? SOL_SHRED_VARIANT_MERKLE_CODE_RESIGNED
                                                   : SOL_SHRED_VARIANT_MERKLE_CODE) |
                                         (proof_size & 0x0Fu));

        /* One retransmitter signature is attached to recovered shreds if resigned. */
        uint8_t retrans_sig_buf[SOL_SIGNATURE_SIZE];
        const uint8_t* retrans_sig = NULL;
        if (resigned) {
            for (uint16_t i = 0; i < k; i++) {
                if (received_shreds[i] && received_shreds[i]->retransmitter_signature) {
                    memcpy(retrans_sig_buf, received_shreds[i]->retransmitter_signature, SOL_SIGNATURE_SIZE);
                    retrans_sig = retrans_sig_buf;
                    break;
                }
            }
            if (!retrans_sig) {
                memset(retrans_sig_buf, 0, sizeof(retrans_sig_buf));
                retrans_sig = retrans_sig_buf;
            }
        }

        /* Build raw buffers for all shreds in the erasure batch (use existing for present shreds). */
        uint8_t** raw = sol_calloc(num_shards, sizeof(uint8_t*));
        bool* present = sol_calloc(num_shards, sizeof(bool));
        bool* owned = sol_calloc(num_shards, sizeof(bool));
        if (!raw || !present || !owned) {
            sol_free(raw);
            sol_free(present);
            sol_free(owned);
            sol_free(encoding_rows);
            sol_free(inverse);
            sol_free(row_indices);
            sol_free(received_shreds);
            return SOL_ERR_NOMEM;
        }

        /* Pre-compute fixed offsets. */
        size_t data_chain_off = (size_t)SOL_SHRED_DATA_HEADERS_SIZE + data_capacity;
        size_t code_chain_off = (size_t)SOL_SHRED_CODE_HEADERS_SIZE + shard_size;
        size_t data_proof_off = data_chain_off + (size_t)SOL_SHRED_MERKLE_ROOT_SIZE;
        size_t code_proof_off = code_chain_off + (size_t)SOL_SHRED_MERKLE_ROOT_SIZE;
        size_t proof_bytes = (size_t)proof_size * (size_t)SOL_SHRED_MERKLE_PROOF_ENTRY_SIZE;

        /* Populate data shreds. */
        for (uint16_t i = 0; i < fec->num_data; i++) {
            if (fec->data_shreds[i]) {
                raw[i] = (uint8_t*)(uintptr_t)fec->data_shreds[i]->raw_data;
                present[i] = true;
                continue;
            }

            uint8_t* buf = sol_calloc(1, SOL_SHRED_DATA_PAYLOAD_SIZE);
            if (!buf) {
                for (size_t j = 0; j < num_shards; j++) {
                    if (owned[j]) sol_free(raw[j]);
                }
                sol_free(raw);
                sol_free(present);
                sol_free(owned);
                sol_free(encoding_rows);
                sol_free(inverse);
                sol_free(row_indices);
                sol_free(received_shreds);
                return SOL_ERR_NOMEM;
            }
            owned[i] = true;
            raw[i] = buf;
            present[i] = false;

            memcpy(buf, leader_sig.bytes, SOL_SIGNATURE_SIZE);
            buf[64] = data_variant;
            sol_store_u64_le(buf + 65, (uint64_t)fec->slot);
            sol_store_u32_le(buf + 73, (uint32_t)(fec->fec_set_index + i));
            sol_store_u16_le(buf + 77, version);
            sol_store_u32_le(buf + 79, fec->fec_set_index);

            /* Chained merkle root (not erasure coded, but hashed). */
            memcpy(buf + data_chain_off, ref_code->chained_merkle_root.bytes, SOL_SHRED_MERKLE_ROOT_SIZE);

            if (resigned) {
                memcpy(buf + data_proof_off + proof_bytes, retrans_sig, SOL_SIGNATURE_SIZE);
            }
        }

        /* Populate coding shreds. */
        for (uint16_t p = 0; p < fec->num_code; p++) {
            size_t shard_index = (size_t)fec->num_data + p;
            if (fec->code_shreds[p]) {
                raw[shard_index] = (uint8_t*)(uintptr_t)fec->code_shreds[p]->raw_data;
                present[shard_index] = true;
                continue;
            }

            uint8_t* buf = sol_calloc(1, SOL_SHRED_CODE_PAYLOAD_SIZE);
            if (!buf) {
                for (size_t j = 0; j < num_shards; j++) {
                    if (owned[j]) sol_free(raw[j]);
                }
                sol_free(raw);
                sol_free(present);
                sol_free(owned);
                sol_free(encoding_rows);
                sol_free(inverse);
                sol_free(row_indices);
                sol_free(received_shreds);
                return SOL_ERR_NOMEM;
            }
            owned[shard_index] = true;
            raw[shard_index] = buf;
            present[shard_index] = false;

            memcpy(buf, leader_sig.bytes, SOL_SIGNATURE_SIZE);
            buf[64] = code_variant;
            sol_store_u64_le(buf + 65, (uint64_t)fec->slot);
            sol_store_u32_le(buf + 73, (uint32_t)(first_coding_index + p));
            sol_store_u16_le(buf + 77, version);
            sol_store_u32_le(buf + 79, fec->fec_set_index);

            /* Coding header (not erasure coded). */
            sol_store_u16_le(buf + 83, fec->num_data);
            sol_store_u16_le(buf + 85, fec->num_code);
            sol_store_u16_le(buf + 87, (uint16_t)p);

            memcpy(buf + code_chain_off, ref_code->chained_merkle_root.bytes, SOL_SHRED_MERKLE_ROOT_SIZE);

            if (resigned) {
                memcpy(buf + code_proof_off + proof_bytes, retrans_sig, SOL_SIGNATURE_SIZE);
            }
        }

        /* Recover all data erasure shards (systematic) using the decoding matrix. */
        uint8_t** data_shards = sol_calloc(k, sizeof(uint8_t*));
        if (!data_shards) {
            for (size_t j = 0; j < num_shards; j++) {
                if (owned[j]) sol_free(raw[j]);
            }
            sol_free(raw);
            sol_free(present);
            sol_free(owned);
            sol_free(encoding_rows);
            sol_free(inverse);
            sol_free(row_indices);
            sol_free(received_shreds);
            return SOL_ERR_NOMEM;
        }
        for (uint16_t i = 0; i < k; i++) {
            data_shards[i] = sol_calloc(1, shard_size);
            if (!data_shards[i]) {
                for (uint16_t j = 0; j < k; j++) sol_free(data_shards[j]);
                sol_free(data_shards);
                for (size_t j = 0; j < num_shards; j++) {
                    if (owned[j]) sol_free(raw[j]);
                }
                sol_free(raw);
                sol_free(present);
                sol_free(owned);
                sol_free(encoding_rows);
                sol_free(inverse);
                sol_free(row_indices);
                sol_free(received_shreds);
                return SOL_ERR_NOMEM;
            }
        }

        for (uint16_t data_idx = 0; data_idx < k; data_idx++) {
            for (size_t byte_pos = 0; byte_pos < shard_size; byte_pos++) {
                uint8_t sum = 0;
                for (uint16_t j = 0; j < k; j++) {
                    const sol_shred_t* in = received_shreds[j];
                    if (!in || !in->raw_data) {
                        for (uint16_t i = 0; i < k; i++) sol_free(data_shards[i]);
                        sol_free(data_shards);
                        for (size_t x = 0; x < num_shards; x++) {
                            if (owned[x]) sol_free(raw[x]);
                        }
                        sol_free(raw);
                        sol_free(present);
                        sol_free(owned);
                        sol_free(encoding_rows);
                        sol_free(inverse);
                        sol_free(row_indices);
                        sol_free(received_shreds);
                        return SOL_ERR_FEC_RECOVERY;
                    }

                    const uint8_t* shard_in = NULL;
                    if (in->type == SOL_SHRED_TYPE_DATA) {
                        if (in->raw_len < SOL_SIGNATURE_SIZE + shard_size) {
                            for (uint16_t i = 0; i < k; i++) sol_free(data_shards[i]);
                            sol_free(data_shards);
                            for (size_t x = 0; x < num_shards; x++) {
                                if (owned[x]) sol_free(raw[x]);
                            }
                            sol_free(raw);
                            sol_free(present);
                            sol_free(owned);
                            sol_free(encoding_rows);
                            sol_free(inverse);
                            sol_free(row_indices);
                            sol_free(received_shreds);
                            return SOL_ERR_FEC_RECOVERY;
                        }
                        shard_in = in->raw_data + SOL_SIGNATURE_SIZE;
                    } else {
                        if (in->raw_len < SOL_SHRED_CODE_HEADERS_SIZE + shard_size) {
                            for (uint16_t i = 0; i < k; i++) sol_free(data_shards[i]);
                            sol_free(data_shards);
                            for (size_t x = 0; x < num_shards; x++) {
                                if (owned[x]) sol_free(raw[x]);
                            }
                            sol_free(raw);
                            sol_free(present);
                            sol_free(owned);
                            sol_free(encoding_rows);
                            sol_free(inverse);
                            sol_free(row_indices);
                            sol_free(received_shreds);
                            return SOL_ERR_FEC_RECOVERY;
                        }
                        shard_in = in->raw_data + SOL_SHRED_CODE_HEADERS_SIZE;
                    }

                    sum = gf_add(sum, gf_mul(inverse[data_idx * k + j], shard_in[byte_pos]));
                }
                data_shards[data_idx][byte_pos] = sum;
            }
        }

        /* Write recovered missing data shreds (erasure shard starts at signature end). */
        for (uint16_t i = 0; i < k; i++) {
            if (present[i]) continue;
            memcpy(raw[i] + SOL_SIGNATURE_SIZE, data_shards[i], shard_size);
        }

        /* Compute missing coding shards from reconstructed data shards. */
        uint8_t* enc_row = sol_alloc(k);
        if (!enc_row) {
            for (uint16_t i = 0; i < k; i++) sol_free(data_shards[i]);
            sol_free(data_shards);
            for (size_t j = 0; j < num_shards; j++) {
                if (owned[j]) sol_free(raw[j]);
            }
            sol_free(raw);
            sol_free(present);
            sol_free(owned);
            sol_free(encoding_rows);
            sol_free(inverse);
            sol_free(row_indices);
            sol_free(received_shreds);
            return SOL_ERR_NOMEM;
        }

        for (uint16_t p = 0; p < fec->num_code; p++) {
            size_t shard_index = (size_t)fec->num_data + p;
            if (present[shard_index]) continue;
            build_encoding_row(enc_row, k, (uint16_t)(k + p));
            uint8_t* out_shard = raw[shard_index] + SOL_SHRED_CODE_HEADERS_SIZE;
            for (size_t byte_pos = 0; byte_pos < shard_size; byte_pos++) {
                uint8_t sum = 0;
                for (uint16_t i = 0; i < k; i++) {
                    sum = gf_add(sum, gf_mul(enc_row[i], data_shards[i][byte_pos]));
                }
                out_shard[byte_pos] = sum;
            }
        }
        sol_free(enc_row);

        /* Rebuild the Merkle tree from all shreds (data + coding). */
        static const uint8_t MERKLE_HASH_PREFIX_LEAF[] = "\x00SOLANA_MERKLE_SHREDS_LEAF";
        static const uint8_t MERKLE_HASH_PREFIX_NODE[] = "\x01SOLANA_MERKLE_SHREDS_NODE";
        const size_t prefix_leaf_len = sizeof(MERKLE_HASH_PREFIX_LEAF) - 1u;
        const size_t prefix_node_len = sizeof(MERKLE_HASH_PREFIX_NODE) - 1u;

        size_t expected_proof = 0;
        if (num_shards > 1) {
            bool pow2 = (num_shards & (num_shards - 1u)) == 0;
            size_t bits = 0;
            for (size_t x = num_shards; x; x >>= 1) bits++;
            expected_proof = pow2 ? (bits - 1u) : bits;
        }
        if (expected_proof != proof_size) {
            for (uint16_t i = 0; i < k; i++) sol_free(data_shards[i]);
            sol_free(data_shards);
            for (size_t j = 0; j < num_shards; j++) {
                if (owned[j]) sol_free(raw[j]);
            }
            sol_free(raw);
            sol_free(present);
            sol_free(owned);
            sol_free(encoding_rows);
            sol_free(inverse);
            sol_free(row_indices);
            sol_free(received_shreds);
            return SOL_ERR_FEC_RECOVERY;
        }

        size_t tree_size = 0;
        for (size_t sz = num_shards; sz > 0; sz = (sz + 1u) >> 1) {
            tree_size += sz;
            if (sz == 1) break;
        }
        sol_hash_t* nodes = sol_calloc(tree_size, sizeof(sol_hash_t));
        if (!nodes) {
            for (uint16_t i = 0; i < k; i++) sol_free(data_shards[i]);
            sol_free(data_shards);
            for (size_t j = 0; j < num_shards; j++) {
                if (owned[j]) sol_free(raw[j]);
            }
            sol_free(raw);
            sol_free(present);
            sol_free(owned);
            sol_free(encoding_rows);
            sol_free(inverse);
            sol_free(row_indices);
            sol_free(received_shreds);
            return SOL_ERR_NOMEM;
        }

        for (size_t i = 0; i < num_shards; i++) {
            bool is_data = i < (size_t)fec->num_data;
            size_t proof_off = is_data ? data_proof_off : code_proof_off;
            if (proof_off > (is_data ? (size_t)SOL_SHRED_DATA_PAYLOAD_SIZE : (size_t)SOL_SHRED_CODE_PAYLOAD_SIZE) ||
                proof_off < SOL_SIGNATURE_SIZE) {
                sol_free(nodes);
                for (uint16_t j = 0; j < k; j++) sol_free(data_shards[j]);
                sol_free(data_shards);
                for (size_t j = 0; j < num_shards; j++) {
                    if (owned[j]) sol_free(raw[j]);
                }
                sol_free(raw);
                sol_free(present);
                sol_free(owned);
                sol_free(encoding_rows);
                sol_free(inverse);
                sol_free(row_indices);
                sol_free(received_shreds);
                return SOL_ERR_FEC_RECOVERY;
            }

            const uint8_t* leaf = raw[i] + SOL_SIGNATURE_SIZE;
            size_t leaf_len = proof_off - SOL_SIGNATURE_SIZE;

            sol_sha256_ctx_t ctx;
            sol_sha256_init(&ctx);
            sol_sha256_update(&ctx, MERKLE_HASH_PREFIX_LEAF, prefix_leaf_len);
            sol_sha256_update(&ctx, leaf, leaf_len);
            sol_sha256_t digest;
            sol_sha256_final(&ctx, &digest);
            memcpy(nodes[i].bytes, digest.bytes, SOL_SHRED_MERKLE_ROOT_SIZE);
        }

        /* Build internal nodes in-place (same layout as Agave). */
        size_t size = num_shards;
        size_t offset = 0;
        size_t write_pos = num_shards;
        while (size > 1) {
            for (size_t idx = 0; idx < size; idx += 2) {
                sol_hash_t* left = &nodes[offset + idx];
                sol_hash_t* right = &nodes[offset + ((idx + 1u) < size ? (idx + 1u) : (size - 1u))];
                sol_sha256_ctx_t ctx;
                sol_sha256_init(&ctx);
                sol_sha256_update(&ctx, MERKLE_HASH_PREFIX_NODE, prefix_node_len);
                sol_sha256_update(&ctx, left->bytes, SOL_SHRED_MERKLE_PROOF_ENTRY_SIZE);
                sol_sha256_update(&ctx, right->bytes, SOL_SHRED_MERKLE_PROOF_ENTRY_SIZE);
                sol_sha256_t digest;
                sol_sha256_final(&ctx, &digest);
                memcpy(nodes[write_pos].bytes, digest.bytes, SOL_SHRED_MERKLE_ROOT_SIZE);
                write_pos++;
            }
            offset += size;
            size = (size + 1u) >> 1;
        }

        sol_hash_t root = nodes[tree_size - 1u];
        if (!sol_hash_eq(&root, &expected_root)) {
            sol_free(nodes);
            for (uint16_t i = 0; i < k; i++) sol_free(data_shards[i]);
            sol_free(data_shards);
            for (size_t j = 0; j < num_shards; j++) {
                if (owned[j]) sol_free(raw[j]);
            }
            sol_free(raw);
            sol_free(present);
            sol_free(owned);
            sol_free(encoding_rows);
            sol_free(inverse);
            sol_free(row_indices);
            sol_free(received_shreds);
            return SOL_ERR_FEC_RECOVERY;
        }

        /* Attach Merkle proofs for recovered shreds. */
        for (size_t shred_index = 0; shred_index < num_shards; shred_index++) {
            if (present[shred_index]) continue;
            bool is_data = shred_index < (size_t)fec->num_data;
            uint8_t* buf = raw[shred_index];
            size_t proof_off = is_data ? data_proof_off : code_proof_off;
            uint8_t* dst = buf + proof_off;

            size_t idx = shred_index;
            size_t sz = num_shards;
            size_t off = 0;
            for (size_t level = 0; sz > 1; level++) {
                size_t sib = (idx ^ 1u);
                if (sib >= sz) sib = sz - 1u;
                memcpy(dst + level * SOL_SHRED_MERKLE_PROOF_ENTRY_SIZE,
                       nodes[off + sib].bytes,
                       SOL_SHRED_MERKLE_PROOF_ENTRY_SIZE);
                off += sz;
                sz = (sz + 1u) >> 1;
                idx >>= 1;
            }
        }

        /* Parse and install recovered data shreds into the FEC set. */
        for (uint16_t i = 0; i < fec->num_data; i++) {
            if (present[i]) continue;

            sol_shred_t* recovered = sol_calloc(1, sizeof(sol_shred_t));
            if (!recovered) {
                sol_free(nodes);
                for (uint16_t j = 0; j < k; j++) sol_free(data_shards[j]);
                sol_free(data_shards);
                for (size_t j = 0; j < num_shards; j++) {
                    if (owned[j]) sol_free(raw[j]);
                }
                sol_free(raw);
                sol_free(present);
                sol_free(owned);
                sol_free(encoding_rows);
                sol_free(inverse);
                sol_free(row_indices);
                sol_free(received_shreds);
                return SOL_ERR_NOMEM;
            }

            sol_err_t perr = sol_shred_parse(recovered, raw[i], SOL_SHRED_DATA_PAYLOAD_SIZE);
            if (perr != SOL_OK) {
                sol_free(recovered);
                continue;
            }

            sol_hash_t recovered_root;
            if (!sol_shred_verify_merkle(recovered, &recovered_root) || !sol_hash_eq(&recovered_root, &expected_root)) {
                sol_free(recovered);
                continue;
            }

            fec->data_shreds[i] = recovered;
            fec->data_received++;

            /* Raw buffer is now owned by the recovered shred and (eventually) the blockstore. */
            owned[i] = false;
        }

        /* Free temporary allocations (keep recovered data buffers). */
        sol_free(nodes);
        for (uint16_t i = 0; i < k; i++) sol_free(data_shards[i]);
        sol_free(data_shards);

        for (size_t j = 0; j < num_shards; j++) {
            if (owned[j]) sol_free(raw[j]);
        }
        sol_free(raw);
        sol_free(present);
        sol_free(owned);

        sol_free(encoding_rows);
        sol_free(inverse);
        sol_free(row_indices);
        sol_free(received_shreds);

        if (fec->data_received < fec->num_data) {
            sol_log_warn("Merkle FEC recovery incomplete: %u/%u data shreds",
                         fec->data_received, fec->num_data);
            return SOL_ERR_FEC_RECOVERY;
        }
        return SOL_OK;
    }

    /* Determine payload size from received shreds (legacy path only). */
    size_t payload_size = 0;
    for (uint16_t i = 0; i < k; i++) {
        if (received_shreds[i] && received_shreds[i]->payload_len > payload_size) {
            payload_size = received_shreds[i]->payload_len;
        }
    }

    if (payload_size == 0) {
        sol_free(encoding_rows);
        sol_free(inverse);
        sol_free(row_indices);
        sol_free(received_shreds);
        return SOL_ERR_FEC_RECOVERY;
    }

    /*
     * Recover missing data shreds.
     *
     * For each missing data shred i:
     *   recovered[i] = sum(inverse[i][j] * received_data[j]) for all j
     */
    for (uint16_t data_idx = 0; data_idx < fec->num_data; data_idx++) {
        if (fec->data_shreds[data_idx]) {
            /* Already have this shred */
            continue;
        }

        /* Allocate buffer for recovered shred */
        size_t shred_size = SOL_SHRED_HEADER_SIZE + SOL_SHRED_DATA_HEADER_SIZE + payload_size;
        uint8_t* recovered_data = sol_calloc(1, shred_size);
        if (!recovered_data) {
            sol_free(encoding_rows);
            sol_free(inverse);
            sol_free(row_indices);
            sol_free(received_shreds);
            return SOL_ERR_NOMEM;
        }

        /* Recover each byte of payload using matrix multiplication */
        uint8_t* payload_out = recovered_data + SOL_SHRED_HEADER_SIZE + SOL_SHRED_DATA_HEADER_SIZE;

        for (size_t byte_pos = 0; byte_pos < payload_size; byte_pos++) {
            uint8_t sum = 0;
            for (uint16_t j = 0; j < k; j++) {
                uint8_t input_byte = 0;
                if (received_shreds[j]->payload_len > byte_pos) {
                    input_byte = received_shreds[j]->payload[byte_pos];
                }
                sum = gf_add(sum, gf_mul(inverse[data_idx * k + j], input_byte));
            }
            payload_out[byte_pos] = sum;
        }

        /* Copy header from a received data shred or construct from code shred info */
        /* Build common header */
        uint8_t* hdr = recovered_data;
        /* Signature - we can't recover this, leave as zeros */

        /* Variant - copy from reference or use legacy data */
        hdr[64] = SOL_SHRED_VARIANT_LEGACY_DATA;

        /* Slot (little-endian) */
        for (int i = 0; i < 8; i++) {
            hdr[65 + i] = (fec->slot >> (i * 8)) & 0xFF;
        }

        /* Index (little-endian) */
        uint32_t shred_index = fec->fec_set_index + data_idx;
        for (int i = 0; i < 4; i++) {
            hdr[73 + i] = (shred_index >> (i * 8)) & 0xFF;
        }

        /* Version */
        hdr[77] = ref_shred->version & 0xFF;
        hdr[78] = (ref_shred->version >> 8) & 0xFF;

        /* FEC set index (little-endian) */
        for (int i = 0; i < 4; i++) {
            hdr[79 + i] = (fec->fec_set_index >> (i * 8)) & 0xFF;
        }

        /* Data shred header */
        uint8_t* data_hdr = recovered_data + SOL_SHRED_HEADER_SIZE;
        /* Parent offset - try to get from another data shred */
        sol_slot_t parent_slot = fec->slot > 0 ? fec->slot - 1 : 0;
        for (uint16_t j = 0; j < k; j++) {
            if (received_shreds[j]->type == SOL_SHRED_TYPE_DATA) {
                parent_slot = received_shreds[j]->header.data.parent_slot;
                break;
            }
        }
        uint16_t parent_offset = (uint16_t)(fec->slot - parent_slot);
        data_hdr[0] = parent_offset & 0xFF;
        data_hdr[1] = (parent_offset >> 8) & 0xFF;

        /* Flags - 0 for recovered middle shreds */
        data_hdr[2] = 0;

        /* Size */
        data_hdr[3] = payload_size & 0xFF;
        data_hdr[4] = (payload_size >> 8) & 0xFF;

        /* Parse the recovered shred */
        sol_shred_t* recovered_shred = sol_calloc(1, sizeof(sol_shred_t));
        if (!recovered_shred) {
            sol_free(recovered_data);
            sol_free(encoding_rows);
            sol_free(inverse);
            sol_free(row_indices);
            sol_free(received_shreds);
            return SOL_ERR_NOMEM;
        }

        sol_err_t err = sol_shred_parse(recovered_shred, recovered_data, shred_size);
        if (err != SOL_OK) {
            sol_log_warn("Failed to parse recovered shred: err=%d", err);
            sol_free(recovered_data);
            sol_free(recovered_shred);
            /* Continue trying to recover other shreds */
            continue;
        }

        /* Store the recovered shred */
        fec->data_shreds[data_idx] = recovered_shred;
        fec->data_received++;

        sol_log_debug("Recovered data shred %u/%u for slot %llu FEC set %u",
                      data_idx, fec->num_data, (unsigned long long)fec->slot, fec->fec_set_index);
    }

    sol_free(encoding_rows);
    sol_free(inverse);
    sol_free(row_indices);
    sol_free(received_shreds);

    /* Verify we recovered all missing data shreds */
    if (fec->data_received < fec->num_data) {
        sol_log_warn("FEC recovery incomplete: %u/%u data shreds",
                     fec->data_received, fec->num_data);
        return SOL_ERR_FEC_RECOVERY;
    }

    return SOL_OK;
}

const char*
sol_shred_variant_name(uint8_t variant) {
    if (variant == SOL_SHRED_VARIANT_LEGACY_DATA) {
        return "LegacyData";
    }
    if (variant == SOL_SHRED_VARIANT_LEGACY_CODE) {
        return "LegacyCode";
    }

    uint8_t prefix = variant & 0xF0;
    switch (prefix) {
    case SOL_SHRED_VARIANT_MERKLE_CODE:           return "MerkleCode";
    case SOL_SHRED_VARIANT_MERKLE_CODE_RESIGNED:  return "MerkleCodeResigned";
    case SOL_SHRED_VARIANT_MERKLE_DATA:           return "MerkleData";
    case SOL_SHRED_VARIANT_MERKLE_DATA_RESIGNED:  return "MerkleDataResigned";
    default:   return "Unknown";
    }
}

static void
write_u16_le(uint8_t* dst, uint16_t v) {
    dst[0] = (uint8_t)(v & 0xFFu);
    dst[1] = (uint8_t)((v >> 8) & 0xFFu);
}

static void
write_u32_le(uint8_t* dst, uint32_t v) {
    dst[0] = (uint8_t)(v & 0xFFu);
    dst[1] = (uint8_t)((v >> 8) & 0xFFu);
    dst[2] = (uint8_t)((v >> 16) & 0xFFu);
    dst[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static void
write_u64_le(uint8_t* dst, uint64_t v) {
    dst[0] = (uint8_t)(v & 0xFFu);
    dst[1] = (uint8_t)((v >> 8) & 0xFFu);
    dst[2] = (uint8_t)((v >> 16) & 0xFFu);
    dst[3] = (uint8_t)((v >> 24) & 0xFFu);
    dst[4] = (uint8_t)((v >> 32) & 0xFFu);
    dst[5] = (uint8_t)((v >> 40) & 0xFFu);
    dst[6] = (uint8_t)((v >> 48) & 0xFFu);
    dst[7] = (uint8_t)((v >> 56) & 0xFFu);
}

sol_err_t
sol_shred_build_legacy_data(
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
) {
    if (!leader || !out || !out_written) {
        return SOL_ERR_INVAL;
    }

    if (payload_len > SOL_SHRED_MAX_DATA_SIZE) {
        return SOL_ERR_OVERFLOW;
    }

    if (parent_slot > slot) {
        return SOL_ERR_INVAL;
    }

    uint64_t parent_delta = slot - parent_slot;
    if (parent_delta > UINT16_MAX) {
        return SOL_ERR_OVERFLOW;
    }

    size_t needed = SOL_SHRED_DATA_HEADERS_SIZE + payload_len;
    if (out_len < needed) {
        return SOL_ERR_OVERFLOW;
    }

    memset(out, 0, needed);

    /* Signature is written last. Variant is at offset 64. */
    out[64] = (uint8_t)SOL_SHRED_VARIANT_LEGACY_DATA;

    /* Common header fields. */
    write_u64_le(out + 65, (uint64_t)slot);
    write_u32_le(out + 73, index);
    write_u16_le(out + 77, version);
    write_u32_le(out + 79, fec_set_index);

    /* Data header fields at offset 83. */
    write_u16_le(out + 83, (uint16_t)parent_delta);
    out[85] = flags;
    write_u16_le(out + 86, (uint16_t)needed);

    if (payload_len > 0 && payload) {
        memcpy(out + SOL_SHRED_DATA_HEADERS_SIZE,
               payload, payload_len);
    }

    /* Sign everything after the signature. */
    sol_signature_t sig;
    const uint8_t* msg = out + SOL_SIGNATURE_SIZE;
    size_t msg_len = needed - SOL_SIGNATURE_SIZE;
    sol_ed25519_sign(leader, msg, msg_len, &sig);
    memcpy(out, sig.bytes, SOL_SIGNATURE_SIZE);

    *out_written = needed;
    return SOL_OK;
}
