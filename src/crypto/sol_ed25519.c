/*
 * sol_ed25519.c - Ed25519 implementation
 *
 * Uses libsodium when available, otherwise falls back to OpenSSL.
 */

#include "sol_ed25519.h"
#include "sol_sha256.h"
#include "../util/sol_alloc.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#if SOL_USE_LIBSODIUM
#include <sodium.h>
#endif
#if SOL_USE_OPENSSL
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

/*
 * Fast Ed25519 curve point decompression check for PDA derivation.
 *
 * This must match Solana's `bytes_are_curve_point()` semantics:
 * - Uses canonical y encoding (y < p), where p = 2^255 - 19
 * - Treats any decompressible point (including torsion points) as "on curve"
 * - No subgroup membership checks
 *
 * Implementation uses fixed-size field arithmetic (fiat-crypto) via
 * Firedancer's ref backend.
 */
#define HEADER_fd_src_ballet_ed25519_fd_f25519_h 1
#define FD_25519_INLINE static inline
#include "../../external/fd-src/src/ballet/ed25519/ref/fd_f25519.h"
#undef FD_25519_INLINE

static inline int
sol_f25519_eq(fd_f25519_t const* a, fd_f25519_t const* b) {
    fd_f25519_t r[1];
    fd_f25519_sub(r, a, b);
    return fd_f25519_is_zero(r);
}

static inline int
sol_f25519_sgn(fd_f25519_t const* a) {
    uchar buf[32];
    fd_f25519_tobytes(buf, a);
    return buf[0] & 1;
}

static inline fd_f25519_t*
sol_f25519_abs(fd_f25519_t* r, fd_f25519_t const* a) {
    fd_f25519_t neg_a[1];
    fd_f25519_neg(neg_a, a);
    return fd_f25519_if(r, sol_f25519_sgn(a), neg_a, a);
}

static fd_f25519_t*
sol_f25519_pow22523(fd_f25519_t* r, fd_f25519_t const* a) {
    fd_f25519_t t0[1];
    fd_f25519_t t1[1];
    fd_f25519_t t2[1];

    fd_f25519_sqr(t0, a);
    fd_f25519_sqr(t1, t0);
    for (int i = 1; i < 2; i++) fd_f25519_sqr(t1, t1);

    fd_f25519_mul(t1, a, t1);
    fd_f25519_mul(t0, t0, t1);
    fd_f25519_sqr(t0, t0);
    fd_f25519_mul(t0, t1, t0);
    fd_f25519_sqr(t1, t0);
    for (int i = 1; i < 5; i++) fd_f25519_sqr(t1, t1);

    fd_f25519_mul(t0, t1, t0);
    fd_f25519_sqr(t1, t0);
    for (int i = 1; i < 10; i++) fd_f25519_sqr(t1, t1);

    fd_f25519_mul(t1, t1, t0);
    fd_f25519_sqr(t2, t1);
    for (int i = 1; i < 20; i++) fd_f25519_sqr(t2, t2);

    fd_f25519_mul(t1, t2, t1);
    fd_f25519_sqr(t1, t1);
    for (int i = 1; i < 10; i++) fd_f25519_sqr(t1, t1);

    fd_f25519_mul(t0, t1, t0);
    fd_f25519_sqr(t1, t0);
    for (int i = 1; i < 50; i++) fd_f25519_sqr(t1, t1);

    fd_f25519_mul(t1, t1, t0);
    fd_f25519_sqr(t2, t1);
    for (int i = 1; i < 100; i++) fd_f25519_sqr(t2, t2);

    fd_f25519_mul(t1, t2, t1);
    fd_f25519_sqr(t1, t1);
    for (int i = 1; i < 50; i++) fd_f25519_sqr(t1, t1);

    fd_f25519_mul(t0, t1, t0);
    fd_f25519_sqr(t0, t0);
    for (int i = 1; i < 2; i++) fd_f25519_sqr(t0, t0);

    fd_f25519_mul(r, t0, a);
    return r;
}

static int
sol_f25519_sqrt_ratio(fd_f25519_t* r, fd_f25519_t const* u, fd_f25519_t const* v) {
    /* r = (u * v^3) * (u * v^7)^((p-5)/8) */
    fd_f25519_t v2[1]; fd_f25519_sqr(v2, v);
    fd_f25519_t v3[1]; fd_f25519_mul(v3, v2, v);
    fd_f25519_t uv3[1]; fd_f25519_mul(uv3, u, v3);
    fd_f25519_t v6[1]; fd_f25519_sqr(v6, v3);
    fd_f25519_t v7[1]; fd_f25519_mul(v7, v6, v);
    fd_f25519_t uv7[1]; fd_f25519_mul(uv7, u, v7);

    sol_f25519_pow22523(r, uv7);
    fd_f25519_mul(r, r, uv3);

    /* check = v * r^2 */
    fd_f25519_t check[1];
    fd_f25519_sqr(check, r);
    fd_f25519_mul(check, check, v);

    fd_f25519_t u_neg[1];        fd_f25519_neg(u_neg, u);
    fd_f25519_t u_neg_sqrtm1[1]; fd_f25519_mul(u_neg_sqrtm1, u_neg, fd_f25519_sqrtm1);
    int correct_sign_sqrt   = sol_f25519_eq(check, u);
    int flipped_sign_sqrt   = sol_f25519_eq(check, u_neg);
    int flipped_sign_sqrt_i = sol_f25519_eq(check, u_neg_sqrtm1);

    /* r_prime = SQRT_M1 * r */
    fd_f25519_t r_prime[1];
    fd_f25519_mul(r_prime, r, fd_f25519_sqrtm1);

    /* r = CT_SELECT(r_prime IF flipped_sign_sqrt | flipped_sign_sqrt_i ELSE r) */
    fd_f25519_if(r, flipped_sign_sqrt | flipped_sign_sqrt_i, r_prime, r);
    sol_f25519_abs(r, r);
    return correct_sign_sqrt | flipped_sign_sqrt;
}

static inline bool
sol_ed25519_is_canonical_y(const uint8_t y_bytes[static 32]) {
    /* p = 2^255 - 19, little endian: ed ff..ff 7f */
    static const uint8_t P_LE[32] = {
        0xed,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x7f,
    };

    for (int i = 31; i >= 0; i--) {
        if (y_bytes[i] < P_LE[i]) return true;
        if (y_bytes[i] > P_LE[i]) return false;
    }
    return false; /* y == p is not canonical */
}

static bool
sol_ed25519_bytes_are_curve_point(const sol_pubkey_t* pubkey) {
    if (!pubkey) return false;

    uint8_t y_bytes[32];
    memcpy(y_bytes, pubkey->bytes, sizeof(y_bytes));

    uint8_t expected_x_sign = (uint8_t)((y_bytes[31] >> 7) & 1);
    y_bytes[31] &= 0x7F;

    if (!sol_ed25519_is_canonical_y(y_bytes)) {
        return false;
    }

    fd_f25519_t x[1], y[1], u[1], v[1];
    fd_f25519_frombytes(y, (uchar const*)y_bytes);

    fd_f25519_sqr(u, y);
    fd_f25519_mul(v, u, fd_f25519_d);
    fd_f25519_sub(u, u, fd_f25519_one); /* u = y^2 - 1 */
    fd_f25519_add(v, v, fd_f25519_one); /* v = d*y^2 + 1 */

    if (!sol_f25519_sqrt_ratio(x, u, v)) {
        return false;
    }

    /* Reject encodings where the sign bit can't be satisfied (x == 0). */
    if (sol_f25519_sgn(x) != expected_x_sign) {
        fd_f25519_neg(x, x);
        if (sol_f25519_sgn(x) != expected_x_sign) {
            return false;
        }
    }

    return true;
}

#if SOL_USE_LIBSODIUM
/*
 * Initialize libsodium (called once)
 */
static bool g_sodium_initialized = false;

static void
ensure_sodium_init(void) {
    if (!g_sodium_initialized) {
        if (sodium_init() < 0) {
            /* Initialization failed - this is fatal */
            abort();
        }
        g_sodium_initialized = true;
    }
}

/*
 * Generate keypair from seed
 */
void
sol_ed25519_keypair_from_seed(
    const uint8_t seed[SOL_ED25519_SEED_SIZE],
    sol_keypair_t* keypair
) {
    ensure_sodium_init();

    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk[crypto_sign_SECRETKEYBYTES];

    /* libsodium generates sk as seed || pk */
    crypto_sign_seed_keypair(pk, sk, seed);

    /* Store as seed || pubkey (Solana format) */
    memcpy(keypair->bytes, seed, 32);
    memcpy(keypair->bytes + 32, pk, 32);

    /* Clear sensitive data */
    sodium_memzero(sk, sizeof(sk));
}

/*
 * Generate random keypair
 */
sol_err_t
sol_ed25519_keypair_generate(sol_keypair_t* keypair) {
    ensure_sodium_init();

    uint8_t seed[SOL_ED25519_SEED_SIZE];
    randombytes_buf(seed, sizeof(seed));

    sol_ed25519_keypair_from_seed(seed, keypair);

    sodium_memzero(seed, sizeof(seed));
    return SOL_OK;
}

/*
 * Extract public key from keypair
 */
void
sol_ed25519_pubkey_from_keypair(
    const sol_keypair_t* keypair,
    sol_pubkey_t* pubkey
) {
    memcpy(pubkey->bytes, keypair->bytes + 32, 32);
}

/*
 * Derive public key from seed
 */
void
sol_ed25519_pubkey_from_seed(
    const uint8_t seed[SOL_ED25519_SEED_SIZE],
    sol_pubkey_t* pubkey
) {
    sol_keypair_t kp;
    sol_ed25519_keypair_from_seed(seed, &kp);
    memcpy(pubkey->bytes, kp.bytes + 32, 32);
    sodium_memzero(&kp, sizeof(kp));
}

/*
 * Sign a message
 */
void
sol_ed25519_sign(
    const sol_keypair_t* keypair,
    const uint8_t*       msg,
    size_t               msg_len,
    sol_signature_t*     sig
) {
    ensure_sodium_init();

    /* Construct libsodium secret key format: seed || pubkey (64 bytes total) */
    uint8_t sk[crypto_sign_SECRETKEYBYTES];

    /* libsodium wants the expanded secret key, but we can derive it */
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    crypto_sign_seed_keypair(pk, sk, keypair->bytes);

    /* Sign the message */
    unsigned long long sig_len;
    crypto_sign_detached(sig->bytes, &sig_len, msg, msg_len, sk);

    /* Clear sensitive data */
    sodium_memzero(sk, sizeof(sk));
}

/*
 * Verify a signature
 */
bool
sol_ed25519_verify(
    const sol_pubkey_t*    pubkey,
    const uint8_t*         msg,
    size_t                 msg_len,
    const sol_signature_t* sig
) {
    ensure_sodium_init();

    int result = crypto_sign_verify_detached(
        sig->bytes,
        msg,
        msg_len,
        pubkey->bytes
    );

    return result == 0;
}

/*
 * Batch verify multiple signatures using random linear combinations.
 *
 * Ed25519 batch verification:
 * For each signature i with (R_i, s_i), pubkey A_i, message m_i:
 *   Verification equation: [s_i]B = R_i + [k_i]A_i where k_i = H(R_i || A_i || m_i)
 *
 * Batch check with random scalars z_i:
 *   [sum(z_i * s_i)]B == sum(z_i * R_i) + sum(z_i * k_i * A_i)
 *
 * If all signatures are valid, this holds. If any is invalid, it fails with
 * overwhelming probability (about 1/2^128 for random z_i).
 *
 * This approach:
 * 1. First try batch verification with random linear combinations
 * 2. If batch fails, fall back to individual verification to identify failures
 * 3. Returns count of valid signatures and sets results array
 */
size_t
sol_ed25519_verify_batch(
    const sol_ed25519_verify_job_t* jobs,
    size_t                          job_count,
    bool*                           results
) {
    ensure_sodium_init();

    if (job_count == 0) {
        return 0;
    }

    /* For small batches, individual verification is fine */
    if (job_count <= 4) {
        size_t valid_count = 0;
        for (size_t i = 0; i < job_count; i++) {
            results[i] = sol_ed25519_verify(
                jobs[i].pubkey,
                jobs[i].msg,
                jobs[i].msg_len,
                jobs[i].sig
            );
            if (results[i]) valid_count++;
        }
        return valid_count;
    }

    /*
     * Batch verification using multi-scalar multiplication.
     *
     * We compute:
     *   LHS = [sum(z_i * s_i)]B
     *   RHS = sum(z_i * R_i) + sum(z_i * k_i * A_i)
     *
     * where:
     *   z_i = random scalar for job i
     *   s_i = signature scalar (last 32 bytes of signature)
     *   R_i = signature point (first 32 bytes of signature)
     *   A_i = public key
     *   k_i = H(R_i || A_i || m_i) - challenge hash
     *   B = Ed25519 base point
     */

    /* Allocate working space */
    uint8_t* z_scalars = malloc(job_count * 32);        /* Random scalars */
    uint8_t* k_scalars = malloc(job_count * 32);        /* Challenge hashes */
    uint8_t* points_R = malloc(job_count * 32);         /* R points */
    uint8_t* points_A = malloc(job_count * 32);         /* Public keys */

    if (!z_scalars || !k_scalars || !points_R || !points_A) {
        free(z_scalars);
        free(k_scalars);
        free(points_R);
        free(points_A);
        /* Fall back to individual verification */
        goto individual_verify;
    }

    /* Generate random scalars and compute challenge hashes */
    for (size_t i = 0; i < job_count; i++) {
        /* Generate random scalar z_i (in range [1, L-1]) */
        randombytes_buf(z_scalars + i * 32, 32);
        crypto_core_ed25519_scalar_reduce(z_scalars + i * 32, z_scalars + i * 32);

        /* Copy R_i (first 32 bytes of signature) and A_i (public key) */
        memcpy(points_R + i * 32, jobs[i].sig->bytes, 32);
        memcpy(points_A + i * 32, jobs[i].pubkey->bytes, 32);

        /* Compute challenge k_i = H(R_i || A_i || m_i) using SHA-512 then reduce mod L */
        crypto_hash_sha512_state state;
        unsigned char hash[64];

        crypto_hash_sha512_init(&state);
        crypto_hash_sha512_update(&state, jobs[i].sig->bytes, 32);  /* R */
        crypto_hash_sha512_update(&state, jobs[i].pubkey->bytes, 32);  /* A */
        crypto_hash_sha512_update(&state, jobs[i].msg, jobs[i].msg_len);  /* m */
        crypto_hash_sha512_final(&state, hash);

        crypto_core_ed25519_scalar_reduce(k_scalars + i * 32, hash);
    }

    /*
     * Compute LHS = [sum(z_i * s_i)]B
     *
     * First compute the aggregate scalar: agg_s = sum(z_i * s_i) mod L
     */
    uint8_t agg_s[32] = {0};
    for (size_t i = 0; i < job_count; i++) {
        uint8_t z_s[32];
        /* z_i * s_i */
        crypto_core_ed25519_scalar_mul(z_s, z_scalars + i * 32, jobs[i].sig->bytes + 32);
        /* agg_s += z_i * s_i */
        crypto_core_ed25519_scalar_add(agg_s, agg_s, z_s);
    }

    /* LHS = [agg_s]B */
    uint8_t LHS[32];
    if (crypto_scalarmult_ed25519_base_noclamp(LHS, agg_s) != 0) {
        free(z_scalars);
        free(k_scalars);
        free(points_R);
        free(points_A);
        goto individual_verify;
    }

    /*
     * Compute RHS = sum(z_i * R_i) + sum(z_i * k_i * A_i)
     *
     * We compute this incrementally as a sum of scaled points.
     */
    uint8_t RHS[32];
    bool rhs_initialized = false;

    for (size_t i = 0; i < job_count; i++) {
        /* First term: z_i * R_i */
        uint8_t term_R[32];
        if (crypto_scalarmult_ed25519_noclamp(term_R, z_scalars + i * 32, points_R + i * 32) != 0) {
            /* Invalid R point - this signature is definitely bad */
            free(z_scalars);
            free(k_scalars);
            free(points_R);
            free(points_A);
            goto individual_verify;
        }

        /* Second term: (z_i * k_i) * A_i */
        uint8_t z_k[32];
        crypto_core_ed25519_scalar_mul(z_k, z_scalars + i * 32, k_scalars + i * 32);

        uint8_t term_A[32];
        if (crypto_scalarmult_ed25519_noclamp(term_A, z_k, points_A + i * 32) != 0) {
            /* Invalid public key point */
            free(z_scalars);
            free(k_scalars);
            free(points_R);
            free(points_A);
            goto individual_verify;
        }

        /* Sum this iteration's contribution */
        uint8_t term_sum[32];
        if (crypto_core_ed25519_add(term_sum, term_R, term_A) != 0) {
            free(z_scalars);
            free(k_scalars);
            free(points_R);
            free(points_A);
            goto individual_verify;
        }

        /* Accumulate into RHS */
        if (!rhs_initialized) {
            memcpy(RHS, term_sum, 32);
            rhs_initialized = true;
        } else {
            if (crypto_core_ed25519_add(RHS, RHS, term_sum) != 0) {
                free(z_scalars);
                free(k_scalars);
                free(points_R);
                free(points_A);
                goto individual_verify;
            }
        }
    }

    free(z_scalars);
    free(k_scalars);
    free(points_R);
    free(points_A);

    /* Compare LHS and RHS */
    if (sodium_memcmp(LHS, RHS, 32) == 0) {
        /* All signatures are valid! */
        for (size_t i = 0; i < job_count; i++) {
            results[i] = true;
        }
        return job_count;
    }

    /* Batch verification failed - fall back to individual to find bad sigs */

individual_verify:
    {
        size_t valid_count = 0;
        for (size_t i = 0; i < job_count; i++) {
            results[i] = sol_ed25519_verify(
                jobs[i].pubkey,
                jobs[i].msg,
                jobs[i].msg_len,
                jobs[i].sig
            );
            if (results[i]) valid_count++;
        }
        return valid_count;
    }
}

/*
 * Check if a point is on the Ed25519 curve
 */
bool
sol_ed25519_pubkey_is_valid(const sol_pubkey_t* pubkey) {
    ensure_sodium_init();

    /* Try to convert to a group element - fails if not on curve */
    unsigned char ge[32];

    /* crypto_core_ed25519_is_valid_point checks if point is on the curve */
    return crypto_core_ed25519_is_valid_point(pubkey->bytes) == 1;

    (void)ge;
}

bool
sol_ed25519_pubkey_is_on_curve(const sol_pubkey_t* pubkey) {
    return sol_ed25519_bytes_are_curve_point(pubkey);
}
#elif SOL_USE_OPENSSL
static void
secure_memzero(void* ptr, size_t len) {
    if (ptr == NULL || len == 0) {
        return;
    }
    OPENSSL_cleanse(ptr, len);
}

static EVP_PKEY*
ed25519_pkey_from_seed(const uint8_t seed[SOL_ED25519_SEED_SIZE]) {
    return EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, SOL_ED25519_SEED_SIZE);
}

static EVP_PKEY*
ed25519_pkey_from_pubkey(const sol_pubkey_t* pubkey) {
    return EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pubkey->bytes, SOL_ED25519_PUBKEY_SIZE);
}

static bool
ed25519_pubkey_is_valid_bn(const sol_pubkey_t* pubkey) {
    bool valid = false;

    uint8_t y_bytes[SOL_ED25519_PUBKEY_SIZE];
    memcpy(y_bytes, pubkey->bytes, sizeof(y_bytes));

    uint8_t sign = (uint8_t)((y_bytes[31] >> 7) & 1);
    y_bytes[31] &= 0x7F;

    uint8_t y_be[SOL_ED25519_PUBKEY_SIZE];
    for (size_t i = 0; i < sizeof(y_be); i++) {
        y_be[sizeof(y_be) - 1 - i] = y_bytes[i];
    }

    BN_CTX* ctx = BN_CTX_new();
    if (ctx == NULL) {
        return false;
    }

    BN_CTX_start(ctx);
    BIGNUM* y = BN_CTX_get(ctx);
    BIGNUM* p = BN_CTX_get(ctx);
    BIGNUM* one = BN_CTX_get(ctx);
    BIGNUM* y2 = BN_CTX_get(ctx);
    BIGNUM* u = BN_CTX_get(ctx);
    BIGNUM* v = BN_CTX_get(ctx);
    BIGNUM* d = BN_CTX_get(ctx);
    BIGNUM* inv = BN_CTX_get(ctx);
    BIGNUM* x2 = BN_CTX_get(ctx);
    BIGNUM* x = BN_CTX_get(ctx);
    BIGNUM* numer = BN_CTX_get(ctx);
    BIGNUM* denom = BN_CTX_get(ctx);
    BIGNUM* x_alt = BN_CTX_get(ctx);

    if (x_alt == NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        return false;
    }

    BN_bin2bn(y_be, sizeof(y_be), y);

    BN_one(p);
    BN_lshift(p, p, 255);
    BN_sub_word(p, 19);
    BN_one(one);

    if (BN_cmp(y, p) >= 0) {
        goto done;
    }

    if (BN_mod_sqr(y2, y, p, ctx) != 1) {
        goto done;
    }
    if (BN_mod_sub(u, y2, one, p, ctx) != 1) {
        goto done;
    }

    BN_set_word(numer, 121665);
    BN_set_word(denom, 121666);
    if (BN_mod_inverse(inv, denom, p, ctx) == NULL) {
        goto done;
    }
    if (BN_mod_mul(d, numer, inv, p, ctx) != 1) {
        goto done;
    }
    if (BN_mod_sub(d, p, d, p, ctx) != 1) {
        goto done;
    }

    if (BN_mod_mul(v, d, y2, p, ctx) != 1) {
        goto done;
    }
    if (BN_mod_add(v, v, one, p, ctx) != 1) {
        goto done;
    }

    if (BN_mod_inverse(inv, v, p, ctx) == NULL) {
        goto done;
    }
    if (BN_mod_mul(x2, u, inv, p, ctx) != 1) {
        goto done;
    }

    if (BN_mod_sqrt(x, x2, p, ctx) == NULL) {
        goto done;
    }

    if ((BN_is_odd(x) ? 1 : 0) != sign) {
        if (BN_mod_sub(x_alt, p, x, p, ctx) != 1) {
            goto done;
        }
        if ((BN_is_odd(x_alt) ? 1 : 0) != sign) {
            goto done;
        }
    }

    valid = true;

done:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return valid;
}

void
sol_ed25519_keypair_from_seed(
    const uint8_t seed[SOL_ED25519_SEED_SIZE],
    sol_keypair_t* keypair
) {
    EVP_PKEY* pkey = ed25519_pkey_from_seed(seed);
    if (!pkey) {
        abort();
    }

    uint8_t pk[SOL_ED25519_PUBKEY_SIZE];
    size_t pk_len = sizeof(pk);
    if (EVP_PKEY_get_raw_public_key(pkey, pk, &pk_len) != 1 || pk_len != sizeof(pk)) {
        EVP_PKEY_free(pkey);
        abort();
    }

    memcpy(keypair->bytes, seed, SOL_ED25519_SEED_SIZE);
    memcpy(keypair->bytes + SOL_ED25519_SEED_SIZE, pk, SOL_ED25519_PUBKEY_SIZE);

    secure_memzero(pk, sizeof(pk));
    EVP_PKEY_free(pkey);
}

sol_err_t
sol_ed25519_keypair_generate(sol_keypair_t* keypair) {
    uint8_t seed[SOL_ED25519_SEED_SIZE];
    if (RAND_bytes(seed, sizeof(seed)) != 1) {
        return SOL_ERR_CRYPTO;
    }

    sol_ed25519_keypair_from_seed(seed, keypair);
    secure_memzero(seed, sizeof(seed));
    return SOL_OK;
}

void
sol_ed25519_pubkey_from_keypair(
    const sol_keypair_t* keypair,
    sol_pubkey_t* pubkey
) {
    memcpy(pubkey->bytes, keypair->bytes + SOL_ED25519_SEED_SIZE, SOL_ED25519_PUBKEY_SIZE);
}

void
sol_ed25519_pubkey_from_seed(
    const uint8_t seed[SOL_ED25519_SEED_SIZE],
    sol_pubkey_t* pubkey
) {
    sol_keypair_t kp;
    sol_ed25519_keypair_from_seed(seed, &kp);
    memcpy(pubkey->bytes, kp.bytes + SOL_ED25519_SEED_SIZE, SOL_ED25519_PUBKEY_SIZE);
    secure_memzero(&kp, sizeof(kp));
}

void
sol_ed25519_sign(
    const sol_keypair_t* keypair,
    const uint8_t*       msg,
    size_t               msg_len,
    sol_signature_t*     sig
) {
    EVP_PKEY* pkey = ed25519_pkey_from_seed(keypair->bytes);
    if (!pkey) {
        abort();
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        abort();
    }

    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        abort();
    }

    size_t sig_len = SOL_ED25519_SIGNATURE_SIZE;
    if (EVP_DigestSign(ctx, sig->bytes, &sig_len, msg, msg_len) != 1 ||
        sig_len != SOL_ED25519_SIGNATURE_SIZE) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        abort();
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
}

bool
sol_ed25519_verify(
    const sol_pubkey_t*    pubkey,
    const uint8_t*         msg,
    size_t                 msg_len,
    const sol_signature_t* sig
) {
    EVP_PKEY* pkey = ed25519_pkey_from_pubkey(pubkey);
    if (!pkey) {
        return false;
    }

    /* Signature verification is hot (bank replay). Avoid per-call EVP_MD_CTX
     * allocation/free by using a per-thread cached context. */
    static __thread EVP_MD_CTX* tls_ctx = NULL;
    if (tls_ctx == NULL) {
        tls_ctx = EVP_MD_CTX_new();
    } else {
        EVP_MD_CTX_reset(tls_ctx);
    }
    if (!tls_ctx) {
        EVP_PKEY_free(pkey);
        return false;
    }

    if (EVP_DigestVerifyInit(tls_ctx, NULL, NULL, NULL, pkey) != 1) {
        EVP_PKEY_free(pkey);
        return false;
    }

    int ok = EVP_DigestVerify(tls_ctx, sig->bytes, SOL_ED25519_SIGNATURE_SIZE, msg, msg_len);
    EVP_PKEY_free(pkey);

    return ok == 1;
}

size_t
sol_ed25519_verify_batch(
    const sol_ed25519_verify_job_t* jobs,
    size_t                          job_count,
    bool*                           results
) {
    size_t valid_count = 0;
    for (size_t i = 0; i < job_count; i++) {
        results[i] = sol_ed25519_verify(
            jobs[i].pubkey,
            jobs[i].msg,
            jobs[i].msg_len,
            jobs[i].sig
        );
        if (results[i]) {
            valid_count++;
        }
    }
    return valid_count;
}

bool
sol_ed25519_pubkey_is_valid(const sol_pubkey_t* pubkey) {
    return ed25519_pubkey_is_valid_bn(pubkey);
}

bool
sol_ed25519_pubkey_is_on_curve(const sol_pubkey_t* pubkey) {
    return sol_ed25519_bytes_are_curve_point(pubkey);
}
#else
#error "No Ed25519 backend available. Install libsodium or enable OpenSSL."
#endif

/*
 * PDA creation - Solana-specific
 *
 * PDAs are addresses that are NOT on the Ed25519 curve, ensuring
 * they have no corresponding private key.
 */
sol_err_t
sol_ed25519_create_pda(
    const sol_pubkey_t*   program_id,
    const uint8_t* const* seeds,
    const size_t*         seed_lens,
    size_t                seed_count,
    sol_pubkey_t*         pda,
    uint8_t*              bump
) {
    sol_sha256_ctx_t base_ctx;
    sol_sha256_init(&base_ctx);
    for (size_t i = 0; i < seed_count; i++) {
        if (seed_lens[i] > 0 && seeds[i] != NULL) {
            sol_sha256_update(&base_ctx, seeds[i], seed_lens[i]);
        }
    }
    static const char PDA_MARKER[] = "ProgramDerivedAddress";

    /* Try bump seeds from 255 down to 0 */
    for (int b = 255; b >= 0; b--) {
        sol_sha256_ctx_t ctx = base_ctx;
        sol_sha256_t hash;
        uint8_t bump_byte = (uint8_t)b;

        /* Hash: seeds || bump || program_id || "ProgramDerivedAddress" */
        sol_sha256_update(&ctx, &bump_byte, 1);
        sol_sha256_update(&ctx, program_id->bytes, 32);
        sol_sha256_update(&ctx, PDA_MARKER, sizeof(PDA_MARKER) - 1);
        sol_sha256_final(&ctx, &hash);

        memcpy(pda->bytes, hash.bytes, 32);
        if (!sol_ed25519_pubkey_is_on_curve(pda)) {
            if (bump != NULL) {
                *bump = bump_byte;
            }
            return SOL_OK;
        }
    }

    return SOL_ERR_CRYPTO;
}

sol_err_t
sol_ed25519_create_pda_with_bump(
    const sol_pubkey_t*   program_id,
    const uint8_t* const* seeds,
    const size_t*         seed_lens,
    size_t                seed_count,
    uint8_t               bump,
    sol_pubkey_t*         pda
) {
    sol_sha256_ctx_t ctx;
    sol_sha256_t hash;

    /* Hash: seeds || bump || program_id || "ProgramDerivedAddress" */
    sol_sha256_init(&ctx);

    for (size_t i = 0; i < seed_count; i++) {
        if (seed_lens[i] > 0 && seeds[i] != NULL) {
            sol_sha256_update(&ctx, seeds[i], seed_lens[i]);
        }
    }
    sol_sha256_update(&ctx, &bump, 1);
    sol_sha256_update(&ctx, program_id->bytes, 32);

    static const char PDA_MARKER[] = "ProgramDerivedAddress";
    sol_sha256_update(&ctx, PDA_MARKER, sizeof(PDA_MARKER) - 1);

    sol_sha256_final(&ctx, &hash);

    /* Copy to PDA */
    memcpy(pda->bytes, hash.bytes, 32);

    /* Verify the address is OFF the curve */
    if (sol_ed25519_pubkey_is_on_curve(pda)) {
        return SOL_ERR_CRYPTO;  /* On curve - invalid PDA */
    }

    return SOL_OK;
}

/*
 * Load keypair from JSON file
 *
 * Solana keypair format: JSON array of 64 bytes
 * Example: [1,2,3,...,64]
 */
sol_err_t
sol_ed25519_keypair_load(const char* path, sol_keypair_t* keypair) {
    if (!path || !keypair) {
        return SOL_ERR_INVAL;
    }

    FILE* f = fopen(path, "r");
    if (!f) {
        return SOL_ERR_IO;
    }

    /* Read file contents */
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size <= 0 || file_size > 4096) {
        fclose(f);
        return SOL_ERR_MALFORMED;
    }

    char* buf = malloc((size_t)file_size + 1);
    if (!buf) {
        fclose(f);
        return SOL_ERR_NOMEM;
    }

    size_t read_len = fread(buf, 1, (size_t)file_size, f);
    fclose(f);

    if (read_len != (size_t)file_size) {
        free(buf);
        return SOL_ERR_IO;
    }
    buf[file_size] = '\0';

    /*
     * Parse JSON array of bytes: [n1, n2, n3, ...]
     * Simple parser - expects exactly 64 numbers
     */
    uint8_t bytes[64];
    size_t byte_count = 0;

    char* p = buf;
    /* Skip to first '[' */
    while (*p && *p != '[') p++;
    if (*p != '[') {
        free(buf);
        return SOL_ERR_MALFORMED;
    }
    p++;

    /* Parse numbers */
    while (*p && byte_count < 64) {
        /* Skip whitespace and commas */
        while (*p && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ',')) {
            p++;
        }

        if (*p == ']') {
            break;
        }

        if (*p < '0' || *p > '9') {
            free(buf);
            return SOL_ERR_MALFORMED;
        }

        /* Parse number */
        int num = 0;
        while (*p >= '0' && *p <= '9') {
            num = num * 10 + (*p - '0');
            p++;
        }

        if (num > 255) {
            free(buf);
            return SOL_ERR_MALFORMED;
        }

        bytes[byte_count++] = (uint8_t)num;
    }

    free(buf);

    if (byte_count != 64) {
        return SOL_ERR_MALFORMED;
    }

    /* Copy to keypair */
    memcpy(keypair->bytes, bytes, 64);

    return SOL_OK;
}

/*
 * Save keypair to JSON file
 */
sol_err_t
sol_ed25519_keypair_save(const char* path, const sol_keypair_t* keypair) {
    if (!path || !keypair) {
        return SOL_ERR_INVAL;
    }

    FILE* f = fopen(path, "w");
    if (!f) {
        return SOL_ERR_IO;
    }

    fprintf(f, "[");
    for (int i = 0; i < 64; i++) {
        if (i > 0) fprintf(f, ",");
        fprintf(f, "%u", keypair->bytes[i]);
    }
    fprintf(f, "]\n");

    fclose(f);
    return SOL_OK;
}
