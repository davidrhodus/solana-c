/*
 * sol_sha256.c - SHA-256 implementation
 *
 * Pure C implementation with optional hardware acceleration.
 * Follows FIPS 180-4 specification.
 */

#include "sol_sha256.h"
#include "../util/sol_bits.h"
#include <string.h>

/*
 * SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes)
 */
static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/*
 * Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
 */
static const uint32_t H256_INIT[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/*
 * SHA-256 helper macros
 */
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)       (sol_rotr32(x, 2) ^ sol_rotr32(x, 13) ^ sol_rotr32(x, 22))
#define EP1(x)       (sol_rotr32(x, 6) ^ sol_rotr32(x, 11) ^ sol_rotr32(x, 25))
#define SIG0(x)      (sol_rotr32(x, 7) ^ sol_rotr32(x, 18) ^ ((x) >> 3))
#define SIG1(x)      (sol_rotr32(x, 17) ^ sol_rotr32(x, 19) ^ ((x) >> 10))

/*
 * Process a single 64-byte block
 */
static void
sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t W[64];
    uint32_t t1, t2;

    /* Prepare message schedule */
    for (int i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[i * 4 + 0] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }

    for (int i = 16; i < 64; i++) {
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

    /* 64 rounds */
    for (int i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K256[i] + W[i];
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

/*
 * Initialize context
 */
void
sol_sha256_init(sol_sha256_ctx_t* ctx) {
    memcpy(ctx->state, H256_INIT, sizeof(H256_INIT));
    ctx->count = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

/*
 * Update with more data
 */
void
sol_sha256_update(sol_sha256_ctx_t* ctx, const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    size_t buf_idx = (size_t)(ctx->count / 8) % 64;

    ctx->count += (uint64_t)len * 8;

    /* Fill buffer first */
    if (buf_idx > 0) {
        size_t space = 64 - buf_idx;
        size_t copy = len < space ? len : space;
        memcpy(ctx->buffer + buf_idx, p, copy);
        p += copy;
        len -= copy;

        if (buf_idx + copy == 64) {
            sha256_transform(ctx->state, ctx->buffer);
        }
    }

    /* Process complete blocks */
    while (len >= 64) {
        sha256_transform(ctx->state, p);
        p += 64;
        len -= 64;
    }

    /* Buffer remaining */
    if (len > 0) {
        memcpy(ctx->buffer, p, len);
    }
}

/*
 * Finalize and get hash
 */
void
sol_sha256_final(sol_sha256_ctx_t* ctx, sol_sha256_t* out) {
    uint8_t pad[64 + 8];
    size_t buf_idx = (size_t)(ctx->count / 8) % 64;
    size_t pad_len;

    /* Padding: 1 bit, then zeros, then 64-bit length in big-endian */
    pad[0] = 0x80;

    if (buf_idx < 56) {
        pad_len = 56 - buf_idx;
        memset(pad + 1, 0, pad_len - 1);
    } else {
        pad_len = 120 - buf_idx;
        memset(pad + 1, 0, pad_len - 1);
    }

    /* Append length in bits (big-endian) */
    uint64_t bits = ctx->count;
    pad[pad_len + 0] = (uint8_t)(bits >> 56);
    pad[pad_len + 1] = (uint8_t)(bits >> 48);
    pad[pad_len + 2] = (uint8_t)(bits >> 40);
    pad[pad_len + 3] = (uint8_t)(bits >> 32);
    pad[pad_len + 4] = (uint8_t)(bits >> 24);
    pad[pad_len + 5] = (uint8_t)(bits >> 16);
    pad[pad_len + 6] = (uint8_t)(bits >> 8);
    pad[pad_len + 7] = (uint8_t)(bits);

    sol_sha256_update(ctx, pad, pad_len + 8);

    /* Write output (big-endian) */
    for (int i = 0; i < 8; i++) {
        out->bytes[i * 4 + 0] = (uint8_t)(ctx->state[i] >> 24);
        out->bytes[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        out->bytes[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        out->bytes[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }

    /* Clear sensitive data */
    memset(ctx, 0, sizeof(*ctx));
}

/*
 * One-shot hash
 */
void
sol_sha256(const void* data, size_t len, sol_sha256_t* out) {
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    sol_sha256_update(&ctx, data, len);
    sol_sha256_final(&ctx, out);
}

void
sol_sha256_32bytes(const uint8_t in[static 32], uint8_t out[static 32]) {
    if (!in || !out) return;

    /* Single-block SHA-256 for a fixed-size 32-byte message. */
    uint32_t state[8];
    memcpy(state, H256_INIT, sizeof(H256_INIT));

    uint8_t block[64];
    memset(block, 0, sizeof(block));
    memcpy(block, in, 32);
    block[32] = 0x80;

    /* Length in bits (32 bytes = 256 bits), big-endian at block[56..63]. */
    block[62] = 0x01;
    block[63] = 0x00;

    sha256_transform(state, block);

    /* Write output (big-endian) */
    for (int i = 0; i < 8; i++) {
        out[i * 4 + 0] = (uint8_t)(state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(state[i]);
    }
}

sol_sha256_t*
sol_sha256_hash(const void* data, size_t len, sol_sha256_t* out) {
    sol_sha256(data, len, out);
    return out;
}

/*
 * Hash multiple buffers
 */
void
sol_sha256_multi(
    const void* const* data,
    const size_t*      lens,
    size_t             count,
    sol_sha256_t*      out
) {
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);

    for (size_t i = 0; i < count; i++) {
        sol_sha256_update(&ctx, data[i], lens[i]);
    }

    sol_sha256_final(&ctx, out);
}

/*
 * Utility functions
 */

bool
sol_sha256_eq(const sol_sha256_t* a, const sol_sha256_t* b) {
    /* Constant-time comparison */
    volatile uint8_t diff = 0;
    for (int i = 0; i < SOL_SHA256_HASH_SIZE; i++) {
        diff |= a->bytes[i] ^ b->bytes[i];
    }
    return diff == 0;
}

bool
sol_sha256_is_zero(const sol_sha256_t* h) {
    volatile uint8_t sum = 0;
    for (int i = 0; i < SOL_SHA256_HASH_SIZE; i++) {
        sum |= h->bytes[i];
    }
    return sum == 0;
}

void
sol_sha256_copy(sol_sha256_t* dst, const sol_sha256_t* src) {
    memcpy(dst->bytes, src->bytes, SOL_SHA256_HASH_SIZE);
}

static const char HEX_CHARS[] = "0123456789abcdef";

void
sol_sha256_to_hex(const sol_sha256_t* h, char* out) {
    for (int i = 0; i < SOL_SHA256_HASH_SIZE; i++) {
        out[i * 2 + 0] = HEX_CHARS[(h->bytes[i] >> 4) & 0xf];
        out[i * 2 + 1] = HEX_CHARS[h->bytes[i] & 0xf];
    }
    out[64] = '\0';
}

static int
hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

sol_err_t
sol_sha256_from_hex(const char* hex, sol_sha256_t* out) {
    if (hex == NULL || out == NULL) {
        return SOL_ERR_INVAL;
    }

    for (int i = 0; i < SOL_SHA256_HASH_SIZE; i++) {
        int hi = hex_digit(hex[i * 2 + 0]);
        int lo = hex_digit(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return SOL_ERR_INVAL;
        }
        out->bytes[i] = (uint8_t)((hi << 4) | lo);
    }

    return SOL_OK;
}

/*
 * HMAC-SHA256
 */

void
sol_hmac_sha256_init(sol_hmac_sha256_ctx_t* ctx, const void* key, size_t key_len) {
    uint8_t pad[SOL_SHA256_BLOCK_SIZE];
    uint8_t key_hash[SOL_SHA256_HASH_SIZE];

    /* If key is longer than block size, hash it first */
    if (key_len > SOL_SHA256_BLOCK_SIZE) {
        sol_sha256_t h;
        sol_sha256(key, key_len, &h);
        memcpy(key_hash, h.bytes, SOL_SHA256_HASH_SIZE);
        key = key_hash;
        key_len = SOL_SHA256_HASH_SIZE;
    }

    /* Prepare inner padding (key XOR 0x36) */
    memset(pad, 0x36, SOL_SHA256_BLOCK_SIZE);
    for (size_t i = 0; i < key_len; i++) {
        pad[i] ^= ((const uint8_t*)key)[i];
    }

    sol_sha256_init(&ctx->inner);
    sol_sha256_update(&ctx->inner, pad, SOL_SHA256_BLOCK_SIZE);

    /* Prepare outer padding (key XOR 0x5c) */
    memset(pad, 0x5c, SOL_SHA256_BLOCK_SIZE);
    for (size_t i = 0; i < key_len; i++) {
        pad[i] ^= ((const uint8_t*)key)[i];
    }

    sol_sha256_init(&ctx->outer);
    sol_sha256_update(&ctx->outer, pad, SOL_SHA256_BLOCK_SIZE);

    /* Clear sensitive data */
    memset(pad, 0, sizeof(pad));
    memset(key_hash, 0, sizeof(key_hash));
}

void
sol_hmac_sha256_update(sol_hmac_sha256_ctx_t* ctx, const void* data, size_t len) {
    sol_sha256_update(&ctx->inner, data, len);
}

void
sol_hmac_sha256_final(sol_hmac_sha256_ctx_t* ctx, sol_sha256_t* out) {
    sol_sha256_t inner_hash;

    /* Get inner hash */
    sol_sha256_final(&ctx->inner, &inner_hash);

    /* Finish outer hash with inner hash */
    sol_sha256_update(&ctx->outer, inner_hash.bytes, SOL_SHA256_HASH_SIZE);
    sol_sha256_final(&ctx->outer, out);

    /* Clear sensitive data */
    memset(&inner_hash, 0, sizeof(inner_hash));
}

void
sol_hmac_sha256(
    const void*   key,
    size_t        key_len,
    const void*   data,
    size_t        data_len,
    sol_sha256_t* out
) {
    sol_hmac_sha256_ctx_t ctx;
    sol_hmac_sha256_init(&ctx, key, key_len);
    sol_hmac_sha256_update(&ctx, data, data_len);
    sol_hmac_sha256_final(&ctx, out);
}

/*
 * HKDF-SHA256
 */

void
sol_hkdf_sha256_extract(
    const void*   salt,
    size_t        salt_len,
    const void*   ikm,
    size_t        ikm_len,
    sol_sha256_t* prk
) {
    /* If no salt, use all zeros */
    uint8_t zero_salt[SOL_SHA256_HASH_SIZE] = {0};
    if (salt == NULL || salt_len == 0) {
        salt = zero_salt;
        salt_len = SOL_SHA256_HASH_SIZE;
    }

    sol_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

sol_err_t
sol_hkdf_sha256_expand(
    const sol_sha256_t* prk,
    const void*         info,
    size_t              info_len,
    void*               okm,
    size_t              okm_len
) {
    if (okm_len > 255 * SOL_SHA256_HASH_SIZE) {
        return SOL_ERR_INVAL;
    }

    uint8_t* out = (uint8_t*)okm;
    sol_sha256_t prev;
    uint8_t counter = 1;

    size_t offset = 0;
    while (offset < okm_len) {
        sol_hmac_sha256_ctx_t ctx;
        sol_hmac_sha256_init(&ctx, prk->bytes, SOL_SHA256_HASH_SIZE);

        /* T(n) = HMAC(PRK, T(n-1) | info | counter) */
        if (counter > 1) {
            sol_hmac_sha256_update(&ctx, prev.bytes, SOL_SHA256_HASH_SIZE);
        }
        if (info != NULL && info_len > 0) {
            sol_hmac_sha256_update(&ctx, info, info_len);
        }
        sol_hmac_sha256_update(&ctx, &counter, 1);

        sol_sha256_t t;
        sol_hmac_sha256_final(&ctx, &t);

        size_t copy_len = okm_len - offset;
        if (copy_len > SOL_SHA256_HASH_SIZE) {
            copy_len = SOL_SHA256_HASH_SIZE;
        }
        memcpy(out + offset, t.bytes, copy_len);

        memcpy(&prev, &t, sizeof(t));
        offset += copy_len;
        counter++;
    }

    /* Clear sensitive data */
    memset(&prev, 0, sizeof(prev));

    return SOL_OK;
}

sol_err_t
sol_hkdf_sha256(
    const void* salt,
    size_t      salt_len,
    const void* ikm,
    size_t      ikm_len,
    const void* info,
    size_t      info_len,
    void*       okm,
    size_t      okm_len
) {
    sol_sha256_t prk;
    sol_hkdf_sha256_extract(salt, salt_len, ikm, ikm_len, &prk);
    sol_err_t err = sol_hkdf_sha256_expand(&prk, info, info_len, okm, okm_len);
    memset(&prk, 0, sizeof(prk));
    return err;
}
