/*
 * sol_sha512.c - SHA-512 implementation
 *
 * Used for Ed25519 signature scheme.
 */

#include "sol_sha512.h"
#include "../util/sol_bits.h"
#include <string.h>

/*
 * SHA-512 constants (first 64 bits of fractional parts of cube roots of first 80 primes)
 */
static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

/*
 * Initial hash values (first 64 bits of fractional parts of square roots of first 8 primes)
 */
static const uint64_t H512_INIT[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

/*
 * SHA-512 helper macros
 */
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)       (sol_rotr64(x, 28) ^ sol_rotr64(x, 34) ^ sol_rotr64(x, 39))
#define EP1(x)       (sol_rotr64(x, 14) ^ sol_rotr64(x, 18) ^ sol_rotr64(x, 41))
#define SIG0(x)      (sol_rotr64(x, 1) ^ sol_rotr64(x, 8) ^ ((x) >> 7))
#define SIG1(x)      (sol_rotr64(x, 19) ^ sol_rotr64(x, 61) ^ ((x) >> 6))

/*
 * Process a single 128-byte block
 */
static void
sha512_transform(uint64_t state[8], const uint8_t block[128]) {
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t W[80];
    uint64_t t1, t2;

    /* Prepare message schedule */
    for (int i = 0; i < 16; i++) {
        W[i] = ((uint64_t)block[i * 8 + 0] << 56) |
               ((uint64_t)block[i * 8 + 1] << 48) |
               ((uint64_t)block[i * 8 + 2] << 40) |
               ((uint64_t)block[i * 8 + 3] << 32) |
               ((uint64_t)block[i * 8 + 4] << 24) |
               ((uint64_t)block[i * 8 + 5] << 16) |
               ((uint64_t)block[i * 8 + 6] << 8) |
               ((uint64_t)block[i * 8 + 7]);
    }

    for (int i = 16; i < 80; i++) {
        W[i] = SIG1(W[i - 2]) + W[i - 7] + SIG0(W[i - 15]) + W[i - 16];
    }

    /* Initialize working variables */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    /* 80 rounds */
    for (int i = 0; i < 80; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K512[i] + W[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    /* Update state */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void
sol_sha512_init(sol_sha512_ctx_t* ctx) {
    memcpy(ctx->state, H512_INIT, sizeof(H512_INIT));
    ctx->count[0] = 0;
    ctx->count[1] = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void
sol_sha512_update(sol_sha512_ctx_t* ctx, const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    size_t buf_idx = (size_t)(ctx->count[0] / 8) % 128;

    /* Update bit count */
    uint64_t bit_len = (uint64_t)len * 8;
    ctx->count[0] += bit_len;
    if (ctx->count[0] < bit_len) {
        ctx->count[1]++;  /* Overflow */
    }

    /* Fill buffer first */
    if (buf_idx > 0) {
        size_t space = 128 - buf_idx;
        size_t copy = len < space ? len : space;
        memcpy(ctx->buffer + buf_idx, p, copy);
        p += copy;
        len -= copy;

        if (buf_idx + copy == 128) {
            sha512_transform(ctx->state, ctx->buffer);
        }
    }

    /* Process complete blocks */
    while (len >= 128) {
        sha512_transform(ctx->state, p);
        p += 128;
        len -= 128;
    }

    /* Buffer remaining */
    if (len > 0) {
        memcpy(ctx->buffer, p, len);
    }
}

void
sol_sha512_final(sol_sha512_ctx_t* ctx, sol_sha512_t* out) {
    uint8_t pad[128 + 16];
    size_t buf_idx = (size_t)(ctx->count[0] / 8) % 128;
    size_t pad_len;

    /* Padding: 1 bit, then zeros, then 128-bit length in big-endian */
    pad[0] = 0x80;

    if (buf_idx < 112) {
        pad_len = 112 - buf_idx;
        memset(pad + 1, 0, pad_len - 1);
    } else {
        pad_len = 240 - buf_idx;
        memset(pad + 1, 0, pad_len - 1);
    }

    /* Append length in bits (big-endian, 128-bit) */
    uint64_t hi = ctx->count[1];
    uint64_t lo = ctx->count[0];
    pad[pad_len + 0] = (uint8_t)(hi >> 56);
    pad[pad_len + 1] = (uint8_t)(hi >> 48);
    pad[pad_len + 2] = (uint8_t)(hi >> 40);
    pad[pad_len + 3] = (uint8_t)(hi >> 32);
    pad[pad_len + 4] = (uint8_t)(hi >> 24);
    pad[pad_len + 5] = (uint8_t)(hi >> 16);
    pad[pad_len + 6] = (uint8_t)(hi >> 8);
    pad[pad_len + 7] = (uint8_t)(hi);
    pad[pad_len + 8] = (uint8_t)(lo >> 56);
    pad[pad_len + 9] = (uint8_t)(lo >> 48);
    pad[pad_len + 10] = (uint8_t)(lo >> 40);
    pad[pad_len + 11] = (uint8_t)(lo >> 32);
    pad[pad_len + 12] = (uint8_t)(lo >> 24);
    pad[pad_len + 13] = (uint8_t)(lo >> 16);
    pad[pad_len + 14] = (uint8_t)(lo >> 8);
    pad[pad_len + 15] = (uint8_t)(lo);

    sol_sha512_update(ctx, pad, pad_len + 16);

    /* Write output (big-endian) */
    for (int i = 0; i < 8; i++) {
        out->bytes[i * 8 + 0] = (uint8_t)(ctx->state[i] >> 56);
        out->bytes[i * 8 + 1] = (uint8_t)(ctx->state[i] >> 48);
        out->bytes[i * 8 + 2] = (uint8_t)(ctx->state[i] >> 40);
        out->bytes[i * 8 + 3] = (uint8_t)(ctx->state[i] >> 32);
        out->bytes[i * 8 + 4] = (uint8_t)(ctx->state[i] >> 24);
        out->bytes[i * 8 + 5] = (uint8_t)(ctx->state[i] >> 16);
        out->bytes[i * 8 + 6] = (uint8_t)(ctx->state[i] >> 8);
        out->bytes[i * 8 + 7] = (uint8_t)(ctx->state[i]);
    }

    /* Clear sensitive data */
    memset(ctx, 0, sizeof(*ctx));
}

void
sol_sha512(const void* data, size_t len, sol_sha512_t* out) {
    sol_sha512_ctx_t ctx;
    sol_sha512_init(&ctx);
    sol_sha512_update(&ctx, data, len);
    sol_sha512_final(&ctx, out);
}

bool
sol_sha512_eq(const sol_sha512_t* a, const sol_sha512_t* b) {
    volatile uint8_t diff = 0;
    for (int i = 0; i < SOL_SHA512_HASH_SIZE; i++) {
        diff |= a->bytes[i] ^ b->bytes[i];
    }
    return diff == 0;
}

void
sol_sha512_copy(sol_sha512_t* dst, const sol_sha512_t* src) {
    memcpy(dst->bytes, src->bytes, SOL_SHA512_HASH_SIZE);
}
