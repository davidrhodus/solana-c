/*
 * sol_ed25519.h - Ed25519 signature scheme
 *
 * Implementation of Ed25519 as specified in RFC 8032.
 * Provides signing, verification, and batch verification.
 */

#ifndef SOL_ED25519_H
#define SOL_ED25519_H

#include "../util/sol_base.h"
#include "../util/sol_types.h"
#include "../util/sol_err.h"

/*
 * Ed25519 constants
 */
#define SOL_ED25519_PUBKEY_SIZE     32
#define SOL_ED25519_PRIVKEY_SIZE    32
#define SOL_ED25519_SEED_SIZE       32
#define SOL_ED25519_SIGNATURE_SIZE  64
#define SOL_ED25519_KEYPAIR_SIZE    64  /* seed + pubkey */

/*
 * Generate keypair from seed
 *
 * @param seed      32-byte random seed
 * @param keypair   Output: 64-byte keypair (seed || pubkey)
 */
void sol_ed25519_keypair_from_seed(
    const uint8_t seed[SOL_ED25519_SEED_SIZE],
    sol_keypair_t* keypair
);

/*
 * Generate random keypair
 *
 * Uses system random source for seed generation.
 *
 * @param keypair   Output: 64-byte keypair
 * @return SOL_OK on success, error code on failure
 */
sol_err_t sol_ed25519_keypair_generate(sol_keypair_t* keypair);

/*
 * Extract public key from keypair
 *
 * @param keypair   64-byte keypair
 * @param pubkey    Output: 32-byte public key
 */
void sol_ed25519_pubkey_from_keypair(
    const sol_keypair_t* keypair,
    sol_pubkey_t* pubkey
);

/*
 * Sign a message
 *
 * @param keypair   64-byte keypair (seed || pubkey)
 * @param msg       Message to sign
 * @param msg_len   Length of message
 * @param sig       Output: 64-byte signature
 */
void sol_ed25519_sign(
    const sol_keypair_t* keypair,
    const uint8_t*       msg,
    size_t               msg_len,
    sol_signature_t*     sig
);

/*
 * Verify a signature
 *
 * @param pubkey    32-byte public key
 * @param msg       Message that was signed
 * @param msg_len   Length of message
 * @param sig       64-byte signature
 * @return true if signature is valid, false otherwise
 */
bool sol_ed25519_verify(
    const sol_pubkey_t*    pubkey,
    const uint8_t*         msg,
    size_t                 msg_len,
    const sol_signature_t* sig
);

/*
 * Verification job for batch verification
 */
typedef struct {
    const sol_pubkey_t*    pubkey;   /* 32-byte public key */
    const uint8_t*         msg;      /* Message that was signed */
    size_t                 msg_len;  /* Length of message */
    const sol_signature_t* sig;      /* 64-byte signature */
} sol_ed25519_verify_job_t;

/*
 * Batch verify multiple signatures
 *
 * More efficient than individual verification when checking many signatures.
 * Uses randomized batch verification for security.
 *
 * @param jobs          Array of verification jobs
 * @param job_count     Number of jobs
 * @param results       Output: per-job results (true = valid)
 * @return Number of valid signatures
 */
size_t sol_ed25519_verify_batch(
    const sol_ed25519_verify_job_t* jobs,
    size_t                          job_count,
    bool*                           results
);

/*
 * Check if a point is on the Ed25519 curve
 *
 * Validates that a public key represents a valid curve point.
 *
 * @param pubkey    32-byte public key to validate
 * @return true if valid, false otherwise
 */
bool sol_ed25519_pubkey_is_valid(const sol_pubkey_t* pubkey);

/*
 * Check if bytes represent any Ed25519 curve point (including small-order)
 *
 * This matches Solana's `bytes_are_curve_point()` / Dalek decompression check
 * semantics: return true if the compressed Edwards-Y encoding can be
 * decompressed to a curve point, regardless of subgroup membership.
 *
 * This differs from sol_ed25519_pubkey_is_valid(), which may reject small-order
 * points depending on the crypto backend. PDA derivation must use this
 * "on-curve" check to avoid selecting bump seeds that Solana would reject.
 *
 * @param pubkey    32-byte public key bytes
 * @return true if on-curve, false otherwise
 */
bool sol_ed25519_pubkey_is_on_curve(const sol_pubkey_t* pubkey);

/*
 * Load keypair from JSON file
 *
 * Solana keypair files are JSON arrays of 64 bytes.
 *
 * @param path      Path to keypair JSON file
 * @param keypair   Output: 64-byte keypair
 * @return SOL_OK on success, error code on failure
 */
sol_err_t sol_ed25519_keypair_load(
    const char*     path,
    sol_keypair_t*  keypair
);

/*
 * Save keypair to JSON file
 *
 * @param path      Path to save keypair
 * @param keypair   64-byte keypair to save
 * @return SOL_OK on success, error code on failure
 */
sol_err_t sol_ed25519_keypair_save(
    const char*           path,
    const sol_keypair_t*  keypair
);

/*
 * Derive public key from private key (seed)
 *
 * @param seed      32-byte private key seed
 * @param pubkey    Output: 32-byte public key
 */
void sol_ed25519_pubkey_from_seed(
    const uint8_t seed[SOL_ED25519_SEED_SIZE],
    sol_pubkey_t* pubkey
);

/*
 * Program Derived Address (PDA) generation
 *
 * Solana-specific: derives an address from seeds that is NOT on the curve.
 * This ensures the address has no corresponding private key.
 *
 * @param program_id    The program that owns this PDA
 * @param seeds         Array of seed byte arrays
 * @param seed_lens     Length of each seed
 * @param seed_count    Number of seeds
 * @param pda           Output: derived address
 * @param bump          Output: bump seed that was used (0-255)
 * @return SOL_OK on success, SOL_ERR_CRYPTO if no valid bump found
 */
sol_err_t sol_ed25519_create_pda(
    const sol_pubkey_t*   program_id,
    const uint8_t* const* seeds,
    const size_t*         seed_lens,
    size_t                seed_count,
    sol_pubkey_t*         pda,
    uint8_t*              bump
);

/*
 * Find PDA with specific bump
 *
 * @param program_id    The program that owns this PDA
 * @param seeds         Array of seed byte arrays
 * @param seed_lens     Length of each seed
 * @param seed_count    Number of seeds
 * @param bump          Bump seed to use
 * @param pda           Output: derived address
 * @return SOL_OK if address is off-curve, SOL_ERR_CRYPTO otherwise
 */
sol_err_t sol_ed25519_create_pda_with_bump(
    const sol_pubkey_t*   program_id,
    const uint8_t* const* seeds,
    const size_t*         seed_lens,
    size_t                seed_count,
    uint8_t               bump,
    sol_pubkey_t*         pda
);

#endif /* SOL_ED25519_H */
