/*
 * sol_keccak256.c - Keccak-256 hash implementation
 *
 * This is a portable C implementation of Keccak-256.
 * Note: This is Keccak-256 (pre-SHA-3), not SHA3-256.
 * The difference is in the padding: Keccak uses 0x01, SHA-3 uses 0x06.
 */

#include "sol_keccak256.h"
#include <string.h>

/* Rotation offsets for Keccak */
static const unsigned int KECCAK_ROTC[24] = {
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
};

/* Lane indices for pi step */
static const unsigned int KECCAK_PILN[24] = {
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
    15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
};

/* Round constants */
static const uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

/*
 * Rotate left
 */
static inline uint64_t
rotl64(uint64_t x, unsigned int n) {
    return (x << n) | (x >> (64 - n));
}

/*
 * Keccak-f[1600] permutation
 */
static void
keccak_f1600(uint64_t state[25]) {
    uint64_t t, bc[5];

    for (int round = 0; round < 24; round++) {
        /* Theta step */
        for (int i = 0; i < 5; i++) {
            bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^
                    state[i + 15] ^ state[i + 20];
        }

        for (int i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) {
                state[j + i] ^= t;
            }
        }

        /* Rho and Pi steps */
        t = state[1];
        for (int i = 0; i < 24; i++) {
            int j = KECCAK_PILN[i];
            bc[0] = state[j];
            state[j] = rotl64(t, KECCAK_ROTC[i]);
            t = bc[0];
        }

        /* Chi step */
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++) {
                bc[i] = state[j + i];
            }
            for (int i = 0; i < 5; i++) {
                state[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }

        /* Iota step */
        state[0] ^= KECCAK_RC[round];
    }
}

/*
 * XOR data into state (little-endian)
 */
static void
xor_bytes(uint64_t* state, const uint8_t* data, size_t len) {
    uint8_t* state_bytes = (uint8_t*)state;
    for (size_t i = 0; i < len; i++) {
        state_bytes[i] ^= data[i];
    }
}

/*
 * Initialize hasher
 */
void
sol_keccak256_init(sol_keccak256_ctx_t* ctx) {
    memset(ctx->state, 0, sizeof(ctx->state));
    memset(ctx->buf, 0, sizeof(ctx->buf));
    ctx->buf_len = 0;
}

/*
 * Update hasher with data
 */
void
sol_keccak256_update(
    sol_keccak256_ctx_t*  ctx,
    const uint8_t*        data,
    size_t                len
) {
    while (len > 0) {
        /* Fill buffer */
        size_t take = SOL_KECCAK256_RATE - ctx->buf_len;
        if (take > len) take = len;

        memcpy(ctx->buf + ctx->buf_len, data, take);
        ctx->buf_len += take;
        data += take;
        len -= take;

        /* If buffer is full, absorb */
        if (ctx->buf_len == SOL_KECCAK256_RATE) {
            xor_bytes(ctx->state, ctx->buf, SOL_KECCAK256_RATE);
            keccak_f1600(ctx->state);
            ctx->buf_len = 0;
        }
    }
}

/*
 * Finalize and get output
 */
void
sol_keccak256_final(
    sol_keccak256_ctx_t*  ctx,
    sol_keccak256_t*      out
) {
    /* Pad with Keccak padding: 0x01 ... 0x80 */
    ctx->buf[ctx->buf_len] = 0x01;
    memset(ctx->buf + ctx->buf_len + 1, 0, SOL_KECCAK256_RATE - ctx->buf_len - 1);
    ctx->buf[SOL_KECCAK256_RATE - 1] |= 0x80;

    /* Final absorb */
    xor_bytes(ctx->state, ctx->buf, SOL_KECCAK256_RATE);
    keccak_f1600(ctx->state);

    /* Squeeze output */
    memcpy(out->bytes, ctx->state, SOL_KECCAK256_OUT_LEN);
}

/*
 * One-shot hash
 */
void
sol_keccak256_hash(
    const uint8_t*    data,
    size_t            len,
    sol_keccak256_t*  out
) {
    sol_keccak256_ctx_t ctx;
    sol_keccak256_init(&ctx);
    sol_keccak256_update(&ctx, data, len);
    sol_keccak256_final(&ctx, out);
}

/*
 * Hash multiple inputs
 */
void
sol_keccak256_hash_many(
    const uint8_t* const*  inputs,
    const size_t*          input_lens,
    size_t                 input_count,
    sol_keccak256_t*       out
) {
    sol_keccak256_ctx_t ctx;
    sol_keccak256_init(&ctx);

    for (size_t i = 0; i < input_count; i++) {
        sol_keccak256_update(&ctx, inputs[i], input_lens[i]);
    }

    sol_keccak256_final(&ctx, out);
}

/*
 * Constant-time comparison
 */
bool
sol_keccak256_equal(
    const sol_keccak256_t* a,
    const sol_keccak256_t* b
) {
    uint8_t diff = 0;
    for (int i = 0; i < SOL_KECCAK256_OUT_LEN; i++) {
        diff |= a->bytes[i] ^ b->bytes[i];
    }
    return diff == 0;
}
