/*
 * sol_blake3.c - BLAKE3 hash implementation
 *
 * This is a portable C implementation of BLAKE3.
 * Based on the BLAKE3 specification and reference implementation.
 */

#include "sol_blake3.h"
#include <string.h>

/* BLAKE3 IV (same as BLAKE2s) */
static const uint32_t BLAKE3_IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

/* BLAKE3 message permutation */
static const uint8_t MSG_PERMUTATION[16] = {
    2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
};

/* Domain separation flags */
#define CHUNK_START         (1 << 0)
#define CHUNK_END           (1 << 1)
#define PARENT              (1 << 2)
#define ROOT                (1 << 3)
#define KEYED_HASH          (1 << 4)
#define DERIVE_KEY_CONTEXT  (1 << 5)
#define DERIVE_KEY_MATERIAL (1 << 6)

/*
 * Right rotate
 */
static inline uint32_t
rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

/*
 * G mixing function
 */
static inline void
g(uint32_t* state, size_t a, size_t b, size_t c, size_t d,
  uint32_t mx, uint32_t my) {
    state[a] = state[a] + state[b] + mx;
    state[d] = rotr32(state[d] ^ state[a], 16);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 12);
    state[a] = state[a] + state[b] + my;
    state[d] = rotr32(state[d] ^ state[a], 8);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 7);
}

/*
 * One round of the compression function
 */
static void
round_fn(uint32_t* state, const uint32_t* m) {
    /* Column step */
    g(state, 0, 4,  8, 12, m[0], m[1]);
    g(state, 1, 5,  9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);

    /* Diagonal step */
    g(state, 0, 5, 10, 15, m[8],  m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7,  8, 13, m[12], m[13]);
    g(state, 3, 4,  9, 14, m[14], m[15]);
}

/*
 * Permute the message words
 */
static void
permute(uint32_t* m) {
    uint32_t permuted[16];
    for (int i = 0; i < 16; i++) {
        permuted[i] = m[MSG_PERMUTATION[i]];
    }
    memcpy(m, permuted, sizeof(permuted));
}

/*
 * Compression function
 */
static void
compress(
    const uint32_t cv[8],
    const uint8_t  block[SOL_BLAKE3_BLOCK_LEN],
    uint8_t        block_len,
    uint64_t       counter,
    uint8_t        flags,
    uint32_t       out[16]
) {
    /* Parse block into 32-bit words (little-endian) */
    uint32_t m[16];
    for (int i = 0; i < 16; i++) {
        m[i] = (uint32_t)block[i * 4 + 0] |
               ((uint32_t)block[i * 4 + 1] << 8) |
               ((uint32_t)block[i * 4 + 2] << 16) |
               ((uint32_t)block[i * 4 + 3] << 24);
    }

    /* Initialize state */
    uint32_t state[16] = {
        cv[0], cv[1], cv[2], cv[3],
        cv[4], cv[5], cv[6], cv[7],
        BLAKE3_IV[0], BLAKE3_IV[1], BLAKE3_IV[2], BLAKE3_IV[3],
        (uint32_t)counter,
        (uint32_t)(counter >> 32),
        (uint32_t)block_len,
        (uint32_t)flags
    };

    /* 7 rounds */
    round_fn(state, m); permute(m);
    round_fn(state, m); permute(m);
    round_fn(state, m); permute(m);
    round_fn(state, m); permute(m);
    round_fn(state, m); permute(m);
    round_fn(state, m); permute(m);
    round_fn(state, m);

    /* XOR the two halves */
    for (int i = 0; i < 8; i++) {
        state[i] ^= state[i + 8];
        state[i + 8] ^= cv[i];
    }

    memcpy(out, state, sizeof(state));
}

/*
 * Compress and return new CV
 */
static void
compress_cv(
    const uint32_t cv[8],
    const uint8_t  block[SOL_BLAKE3_BLOCK_LEN],
    uint8_t        block_len,
    uint64_t       counter,
    uint8_t        flags,
    uint32_t       new_cv[8]
) {
    uint32_t out[16];
    compress(cv, block, block_len, counter, flags, out);
    memcpy(new_cv, out, 32);
}

typedef struct {
    uint32_t input_cv[8];
    uint8_t  block[SOL_BLAKE3_BLOCK_LEN];
    uint8_t  block_len;
    uint64_t counter;
    uint8_t  flags;
} blake3_output_t;

static inline void
store_u32_le(uint8_t out[4], uint32_t v) {
    out[0] = (uint8_t)v;
    out[1] = (uint8_t)(v >> 8);
    out[2] = (uint8_t)(v >> 16);
    out[3] = (uint8_t)(v >> 24);
}

static void
output_chaining_value(const blake3_output_t* output, uint32_t out_cv[8]) {
    uint32_t out_words[16];
    compress(output->input_cv,
             output->block,
             output->block_len,
             output->counter,
             output->flags,
             out_words);
    memcpy(out_cv, out_words, 32);
}

static void
output_root_block(const blake3_output_t* output,
                  uint64_t output_block_counter,
                  uint8_t out_bytes[64]) {
    uint32_t out_words[16];
    compress(output->input_cv,
             output->block,
             output->block_len,
             output_block_counter,
             (uint8_t)(output->flags | ROOT),
             out_words);

    for (int i = 0; i < 16; i++) {
        store_u32_le(&out_bytes[i * 4], out_words[i]);
    }
}

static void
make_parent_output(const sol_blake3_ctx_t* ctx,
                   const uint32_t left_cv[8],
                   const uint32_t right_cv[8],
                   blake3_output_t* out) {
    memset(out, 0, sizeof(*out));
    memcpy(out->input_cv, ctx->key_words, sizeof(out->input_cv));
    out->block_len = SOL_BLAKE3_BLOCK_LEN;
    out->counter = 0;
    out->flags = (uint8_t)(ctx->flags | PARENT);

    for (int i = 0; i < 8; i++) {
        store_u32_le(&out->block[i * 4], left_cv[i]);
        store_u32_le(&out->block[(i + 8) * 4], right_cv[i]);
    }
}

static void
make_chunk_output(const sol_blake3_ctx_t* ctx, blake3_output_t* out) {
    memset(out, 0, sizeof(*out));
    memcpy(out->input_cv, ctx->cv, sizeof(out->input_cv));
    out->counter = ctx->chunk_counter;
    out->flags = (uint8_t)(ctx->flags | CHUNK_END);
    if (ctx->blocks_compressed == 0) {
        out->flags |= CHUNK_START;
    }
    out->block_len = ctx->buf_len;
    if (ctx->buf_len > 0) {
        memcpy(out->block, ctx->buf, ctx->buf_len);
    }
}

static void
push_chunk_cv(sol_blake3_ctx_t* ctx, const uint32_t chunk_cv[8]) {
    uint32_t new_cv[8];
    memcpy(new_cv, chunk_cv, sizeof(new_cv));

    uint64_t total_chunks = ctx->chunk_counter + 1;
    while ((total_chunks & 1ULL) == 0ULL && ctx->cv_stack_len > 0) {
        uint32_t left_cv[8];
        ctx->cv_stack_len--;
        memcpy(left_cv, ctx->cv_stack[ctx->cv_stack_len], sizeof(left_cv));

        blake3_output_t parent_out;
        make_parent_output(ctx, left_cv, new_cv, &parent_out);
        output_chaining_value(&parent_out, new_cv);

        total_chunks >>= 1;
    }

    if (ctx->cv_stack_len < SOL_BLAKE3_MAX_DEPTH) {
        memcpy(ctx->cv_stack[ctx->cv_stack_len], new_cv, sizeof(new_cv));
        ctx->cv_stack_len++;
    }
}

static void
reset_chunk_state(sol_blake3_ctx_t* ctx, uint64_t chunk_counter) {
    memcpy(ctx->cv, ctx->key_words, sizeof(ctx->cv));
    memset(ctx->buf, 0, sizeof(ctx->buf));
    ctx->buf_len = 0;
    ctx->blocks_compressed = 0;
    ctx->chunk_counter = chunk_counter;
}

static void
key_words_from_bytes(const uint8_t bytes[SOL_BLAKE3_KEY_LEN], uint32_t out_words[8]) {
    for (int i = 0; i < 8; i++) {
        out_words[i] = (uint32_t)bytes[i * 4 + 0] |
                       ((uint32_t)bytes[i * 4 + 1] << 8) |
                       ((uint32_t)bytes[i * 4 + 2] << 16) |
                       ((uint32_t)bytes[i * 4 + 3] << 24);
    }
}

static void
blake3_init_internal(sol_blake3_ctx_t* ctx, const uint32_t key_words[8], uint8_t flags) {
    memcpy(ctx->key_words, key_words, sizeof(ctx->key_words));
    ctx->flags = flags;
    ctx->cv_stack_len = 0;
    reset_chunk_state(ctx, 0);
}

static void
blake3_hasher_output(const sol_blake3_ctx_t* ctx, blake3_output_t* out) {
    make_chunk_output(ctx, out);

    uint32_t current_cv[8];
    output_chaining_value(out, current_cv);

    for (uint8_t i = ctx->cv_stack_len; i > 0; i--) {
        blake3_output_t parent_out;
        make_parent_output(ctx, ctx->cv_stack[i - 1], current_cv, &parent_out);
        *out = parent_out;
        output_chaining_value(out, current_cv);
    }
}

/*
 * Initialize hasher
 */
void
sol_blake3_init(sol_blake3_ctx_t* ctx) {
    blake3_init_internal(ctx, BLAKE3_IV, 0);
}

/*
 * Initialize keyed hasher
 */
void
sol_blake3_init_keyed(
    sol_blake3_ctx_t*  ctx,
    const uint8_t      key[SOL_BLAKE3_KEY_LEN]
) {
    uint32_t key_words[8];
    key_words_from_bytes(key, key_words);
    blake3_init_internal(ctx, key_words, KEYED_HASH);
}

/*
 * Initialize for key derivation
 */
void
sol_blake3_init_derive_key(
    sol_blake3_ctx_t*  ctx,
    const char*        context
) {
    sol_blake3_ctx_t context_hasher;
    blake3_init_internal(&context_hasher, BLAKE3_IV, DERIVE_KEY_CONTEXT);

    sol_blake3_update(&context_hasher, (const uint8_t*)context, strlen(context));

    sol_blake3_t tmp;
    sol_blake3_final(&context_hasher, &tmp);
    sol_blake3_init_keyed(ctx, tmp.bytes);
    ctx->flags = DERIVE_KEY_MATERIAL;
}

/*
 * Update hasher with data
 */
void
sol_blake3_update(
    sol_blake3_ctx_t*  ctx,
    const uint8_t*     data,
    size_t             len
) {
    while (len > 0) {
        if (ctx->buf_len == SOL_BLAKE3_BLOCK_LEN) {
            if (ctx->blocks_compressed == 15) {
                blake3_output_t chunk_out;
                make_chunk_output(ctx, &chunk_out);

                uint32_t chunk_cv[8];
                output_chaining_value(&chunk_out, chunk_cv);

                push_chunk_cv(ctx, chunk_cv);
                reset_chunk_state(ctx, ctx->chunk_counter + 1);
            } else {
                uint8_t block_flags = ctx->flags;
                if (ctx->blocks_compressed == 0) {
                    block_flags |= CHUNK_START;
                }
                compress_cv(ctx->cv,
                            ctx->buf,
                            SOL_BLAKE3_BLOCK_LEN,
                            ctx->chunk_counter,
                            block_flags,
                            ctx->cv);
                ctx->blocks_compressed++;
                ctx->buf_len = 0;
            }
            continue;
        }

        size_t take = SOL_BLAKE3_BLOCK_LEN - ctx->buf_len;
        if (take > len) {
            take = len;
        }
        memcpy(ctx->buf + ctx->buf_len, data, take);
        ctx->buf_len += (uint8_t)take;
        data += take;
        len -= take;
    }
}

/*
 * Finalize and get output
 */
void
sol_blake3_final(
    sol_blake3_ctx_t*  ctx,
    sol_blake3_t*      out
) {
    sol_blake3_final_xof(ctx, out->bytes, SOL_BLAKE3_OUT_LEN);
}

/*
 * Finalize with extended output (XOF mode)
 */
void
sol_blake3_final_xof(
    sol_blake3_ctx_t*  ctx,
    uint8_t*           out,
    size_t             out_len
) {
    blake3_output_t root_output;
    blake3_hasher_output(ctx, &root_output);

    uint64_t output_block_counter = 0;

    while (out_len > 0) {
        uint8_t output_block[SOL_BLAKE3_BLOCK_LEN];
        output_root_block(&root_output, output_block_counter, output_block);

        size_t take = out_len < SOL_BLAKE3_BLOCK_LEN ? out_len : SOL_BLAKE3_BLOCK_LEN;
        memcpy(out, output_block, take);

        out += take;
        out_len -= take;
        output_block_counter++;
    }
}

/*
 * One-shot hash
 */
void
sol_blake3_hash(
    const uint8_t*  data,
    size_t          len,
    sol_blake3_t*   out
) {
    sol_blake3_ctx_t ctx;
    sol_blake3_init(&ctx);
    sol_blake3_update(&ctx, data, len);
    sol_blake3_final(&ctx, out);
}

/*
 * One-shot keyed hash
 */
void
sol_blake3_keyed_hash(
    const uint8_t   key[SOL_BLAKE3_KEY_LEN],
    const uint8_t*  data,
    size_t          len,
    sol_blake3_t*   out
) {
    sol_blake3_ctx_t ctx;
    sol_blake3_init_keyed(&ctx, key);
    sol_blake3_update(&ctx, data, len);
    sol_blake3_final(&ctx, out);
}

/*
 * Hash multiple inputs
 */
void
sol_blake3_hash_many(
    const uint8_t* const*  inputs,
    const size_t*          input_lens,
    size_t                 input_count,
    sol_blake3_t*          out
) {
    sol_blake3_ctx_t ctx;
    sol_blake3_init(&ctx);

    for (size_t i = 0; i < input_count; i++) {
        sol_blake3_update(&ctx, inputs[i], input_lens[i]);
    }

    sol_blake3_final(&ctx, out);
}

/*
 * Constant-time comparison
 */
bool
sol_blake3_equal(
    const sol_blake3_t* a,
    const sol_blake3_t* b
) {
    uint8_t diff = 0;
    for (int i = 0; i < SOL_BLAKE3_OUT_LEN; i++) {
        diff |= a->bytes[i] ^ b->bytes[i];
    }
    return diff == 0;
}
