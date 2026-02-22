/*
 * sol_bincode.h - Bincode serialization for Solana
 *
 * Bincode is Solana's primary wire format for transactions and messages.
 * This implementation supports both encoding and decoding.
 */

#ifndef SOL_BINCODE_H
#define SOL_BINCODE_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"

/*
 * Decoder state for reading binary data
 */
typedef struct {
    const uint8_t* data;
    size_t         len;
    size_t         pos;
} sol_decoder_t;

/*
 * Encoder state for writing binary data
 */
typedef struct {
    uint8_t* data;
    size_t   capacity;
    size_t   pos;
} sol_encoder_t;

/*
 * Helper macros
 */
#define SOL_DECODE_TRY(expr) do { \
    sol_err_t _e = (expr); \
    if (_e != SOL_OK) return _e; \
} while(0)

#define SOL_ENCODE_TRY(expr) do { \
    sol_err_t _e = (expr); \
    if (_e != SOL_OK) return _e; \
} while(0)

/*
 * Initialize a decoder with input data
 */
static inline void
sol_decoder_init(sol_decoder_t* dec, const uint8_t* data, size_t len) {
    dec->data = data;
    dec->len = len;
    dec->pos = 0;
}

/*
 * Get remaining bytes in decoder
 */
static inline size_t
sol_decoder_remaining(const sol_decoder_t* dec) {
    return dec->len - dec->pos;
}

/*
 * Check if decoder has at least n bytes remaining
 */
static inline bool
sol_decoder_has(const sol_decoder_t* dec, size_t n) {
    return sol_decoder_remaining(dec) >= n;
}

/*
 * Initialize an encoder with output buffer
 */
static inline void
sol_encoder_init(sol_encoder_t* enc, uint8_t* data, size_t capacity) {
    enc->data = data;
    enc->capacity = capacity;
    enc->pos = 0;
}

/*
 * Get bytes written to encoder
 */
static inline size_t
sol_encoder_len(const sol_encoder_t* enc) {
    return enc->pos;
}

/*
 * Check if encoder has space for n bytes
 */
static inline bool
sol_encoder_has_space(const sol_encoder_t* enc, size_t n) {
    return (enc->capacity - enc->pos) >= n;
}

/*
 * ============================================================
 * Decoding functions (little-endian)
 * ============================================================
 */

/*
 * Decode a single byte
 */
static inline sol_err_t
sol_decode_u8(sol_decoder_t* dec, uint8_t* out) {
    if (!sol_decoder_has(dec, 1)) return SOL_ERR_DECODE;
    *out = dec->data[dec->pos++];
    return SOL_OK;
}

/*
 * Decode uint16 (little-endian)
 */
static inline sol_err_t
sol_decode_u16(sol_decoder_t* dec, uint16_t* out) {
    if (!sol_decoder_has(dec, 2)) return SOL_ERR_DECODE;
    *out = (uint16_t)dec->data[dec->pos] |
           ((uint16_t)dec->data[dec->pos + 1] << 8);
    dec->pos += 2;
    return SOL_OK;
}

/*
 * Decode uint32 (little-endian)
 */
static inline sol_err_t
sol_decode_u32(sol_decoder_t* dec, uint32_t* out) {
    if (!sol_decoder_has(dec, 4)) return SOL_ERR_DECODE;
    *out = (uint32_t)dec->data[dec->pos] |
           ((uint32_t)dec->data[dec->pos + 1] << 8) |
           ((uint32_t)dec->data[dec->pos + 2] << 16) |
           ((uint32_t)dec->data[dec->pos + 3] << 24);
    dec->pos += 4;
    return SOL_OK;
}

/*
 * Decode uint64 (little-endian)
 */
static inline sol_err_t
sol_decode_u64(sol_decoder_t* dec, uint64_t* out) {
    if (!sol_decoder_has(dec, 8)) return SOL_ERR_DECODE;
    *out = (uint64_t)dec->data[dec->pos] |
           ((uint64_t)dec->data[dec->pos + 1] << 8) |
           ((uint64_t)dec->data[dec->pos + 2] << 16) |
           ((uint64_t)dec->data[dec->pos + 3] << 24) |
           ((uint64_t)dec->data[dec->pos + 4] << 32) |
           ((uint64_t)dec->data[dec->pos + 5] << 40) |
           ((uint64_t)dec->data[dec->pos + 6] << 48) |
           ((uint64_t)dec->data[dec->pos + 7] << 56);
    dec->pos += 8;
    return SOL_OK;
}

/*
 * Decode int64 (little-endian)
 */
static inline sol_err_t
sol_decode_i64(sol_decoder_t* dec, int64_t* out) {
    uint64_t u;
    sol_err_t err = sol_decode_u64(dec, &u);
    if (err != SOL_OK) return err;
    *out = (int64_t)u;
    return SOL_OK;
}

/*
 * Decode compact-u16 (Solana's variable-length encoding)
 *
 * Format:
 *   0x00-0x7f: 1 byte, value is the byte itself
 *   0x80-0x3fff: 2 bytes, bits 0-6 of first byte + bits 0-7 of second byte
 *   0x4000-0xffff: 3 bytes, bits 0-6 + bits 0-6 + bits 0-1
 */
static inline sol_err_t
sol_decode_compact_u16(sol_decoder_t* dec, uint16_t* out) {
    uint8_t b1, b2, b3;

    if (!sol_decoder_has(dec, 1)) return SOL_ERR_DECODE;
    b1 = dec->data[dec->pos++];

    if ((b1 & 0x80) == 0) {
        /* Single byte: 0xxxxxxx */
        *out = b1;
        return SOL_OK;
    }

    if (!sol_decoder_has(dec, 1)) return SOL_ERR_DECODE;
    b2 = dec->data[dec->pos++];

    if ((b2 & 0x80) == 0) {
        /* Two bytes: 1xxxxxxx 0xxxxxxx */
        *out = (uint16_t)(b1 & 0x7f) | ((uint16_t)b2 << 7);
        return SOL_OK;
    }

    if (!sol_decoder_has(dec, 1)) return SOL_ERR_DECODE;
    b3 = dec->data[dec->pos++];

    /* Three bytes: 1xxxxxxx 1xxxxxxx xxxxxxxx */
    if (b3 > 0x03) return SOL_ERR_DECODE;  /* Overflow check */
    *out = (uint16_t)(b1 & 0x7f) | ((uint16_t)(b2 & 0x7f) << 7) | ((uint16_t)b3 << 14);
    return SOL_OK;
}

/*
 * Decode varint-encoded u64 (LEB128, 7 bits per byte)
 */
static inline sol_err_t
sol_decode_var_u64(sol_decoder_t* dec, uint64_t* out) {
    if (!out) return SOL_ERR_DECODE;
    uint64_t value = 0;
    unsigned shift = 0;

    for (unsigned i = 0; i < 10; i++) {
        uint8_t byte;
        SOL_DECODE_TRY(sol_decode_u8(dec, &byte));
        value |= (uint64_t)(byte & 0x7f) << shift;
        if ((byte & 0x80) == 0) {
            *out = value;
            return SOL_OK;
        }
        shift += 7;
    }

    return SOL_ERR_DECODE;
}

/*
 * Decode varint-encoded u16 (LEB128, 7 bits per byte)
 */
static inline sol_err_t
sol_decode_var_u16(sol_decoder_t* dec, uint16_t* out) {
    uint64_t value = 0;
    sol_err_t err = sol_decode_var_u64(dec, &value);
    if (err != SOL_OK) return err;
    if (value > 0xFFFFu) return SOL_ERR_DECODE;
    *out = (uint16_t)value;
    return SOL_OK;
}

/*
 * Decode raw bytes (returns pointer into decoder data)
 */
static inline sol_err_t
sol_decode_bytes(sol_decoder_t* dec, size_t len, const uint8_t** out) {
    if (!sol_decoder_has(dec, len)) return SOL_ERR_DECODE;
    *out = dec->data + dec->pos;
    dec->pos += len;
    return SOL_OK;
}

/*
 * Decode length-prefixed bytes (compact-u16 length)
 */
static inline sol_err_t
sol_decode_bytes_prefixed(sol_decoder_t* dec, const uint8_t** out, size_t* len) {
    uint16_t prefix;
    sol_err_t err = sol_decode_compact_u16(dec, &prefix);
    if (err != SOL_OK) return err;
    *len = prefix;
    return sol_decode_bytes(dec, *len, out);
}

/*
 * Skip n bytes in decoder
 */
static inline sol_err_t
sol_decode_skip(sol_decoder_t* dec, size_t n) {
    if (!sol_decoder_has(dec, n)) return SOL_ERR_DECODE;
    dec->pos += n;
    return SOL_OK;
}

/*
 * ============================================================
 * Encoding functions (little-endian)
 * ============================================================
 */

/*
 * Encode a single byte
 */
static inline sol_err_t
sol_encode_u8(sol_encoder_t* enc, uint8_t val) {
    if (!sol_encoder_has_space(enc, 1)) return SOL_ERR_ENCODE;
    enc->data[enc->pos++] = val;
    return SOL_OK;
}

/*
 * Encode uint16 (little-endian)
 */
static inline sol_err_t
sol_encode_u16(sol_encoder_t* enc, uint16_t val) {
    if (!sol_encoder_has_space(enc, 2)) return SOL_ERR_ENCODE;
    enc->data[enc->pos++] = (uint8_t)(val);
    enc->data[enc->pos++] = (uint8_t)(val >> 8);
    return SOL_OK;
}

/*
 * Encode varint-encoded u64 (LEB128, 7 bits per byte)
 */
static inline sol_err_t
sol_encode_var_u64(sol_encoder_t* enc, uint64_t val) {
    while (val >= 0x80u) {
        SOL_ENCODE_TRY(sol_encode_u8(enc, (uint8_t)((val & 0x7f) | 0x80)));
        val >>= 7;
    }
    SOL_ENCODE_TRY(sol_encode_u8(enc, (uint8_t)(val & 0x7f)));
    return SOL_OK;
}

/*
 * Encode varint-encoded u16 (LEB128, 7 bits per byte)
 */
static inline sol_err_t
sol_encode_var_u16(sol_encoder_t* enc, uint16_t val) {
    return sol_encode_var_u64(enc, val);
}

/*
 * Encode uint32 (little-endian)
 */
static inline sol_err_t
sol_encode_u32(sol_encoder_t* enc, uint32_t val) {
    if (!sol_encoder_has_space(enc, 4)) return SOL_ERR_ENCODE;
    enc->data[enc->pos++] = (uint8_t)(val);
    enc->data[enc->pos++] = (uint8_t)(val >> 8);
    enc->data[enc->pos++] = (uint8_t)(val >> 16);
    enc->data[enc->pos++] = (uint8_t)(val >> 24);
    return SOL_OK;
}

/*
 * Encode uint64 (little-endian)
 */
static inline sol_err_t
sol_encode_u64(sol_encoder_t* enc, uint64_t val) {
    if (!sol_encoder_has_space(enc, 8)) return SOL_ERR_ENCODE;
    enc->data[enc->pos++] = (uint8_t)(val);
    enc->data[enc->pos++] = (uint8_t)(val >> 8);
    enc->data[enc->pos++] = (uint8_t)(val >> 16);
    enc->data[enc->pos++] = (uint8_t)(val >> 24);
    enc->data[enc->pos++] = (uint8_t)(val >> 32);
    enc->data[enc->pos++] = (uint8_t)(val >> 40);
    enc->data[enc->pos++] = (uint8_t)(val >> 48);
    enc->data[enc->pos++] = (uint8_t)(val >> 56);
    return SOL_OK;
}

/*
 * Encode int64 (little-endian)
 */
static inline sol_err_t
sol_encode_i64(sol_encoder_t* enc, int64_t val) {
    return sol_encode_u64(enc, (uint64_t)val);
}

/*
 * Encode compact-u16
 */
static inline sol_err_t
sol_encode_compact_u16(sol_encoder_t* enc, uint16_t val) {
    if (val < 0x80) {
        /* Single byte */
        return sol_encode_u8(enc, (uint8_t)val);
    } else if (val < 0x4000) {
        /* Two bytes */
        if (!sol_encoder_has_space(enc, 2)) return SOL_ERR_ENCODE;
        enc->data[enc->pos++] = (uint8_t)(val & 0x7f) | 0x80;
        enc->data[enc->pos++] = (uint8_t)(val >> 7);
        return SOL_OK;
    } else {
        /* Three bytes */
        if (!sol_encoder_has_space(enc, 3)) return SOL_ERR_ENCODE;
        enc->data[enc->pos++] = (uint8_t)(val & 0x7f) | 0x80;
        enc->data[enc->pos++] = (uint8_t)((val >> 7) & 0x7f) | 0x80;
        enc->data[enc->pos++] = (uint8_t)(val >> 14);
        return SOL_OK;
    }
}

/*
 * Encode raw bytes
 */
static inline sol_err_t
sol_encode_bytes(sol_encoder_t* enc, const uint8_t* data, size_t len) {
    if (!sol_encoder_has_space(enc, len)) return SOL_ERR_ENCODE;
    for (size_t i = 0; i < len; i++) {
        enc->data[enc->pos++] = data[i];
    }
    return SOL_OK;
}

/*
 * Encode length-prefixed bytes (compact-u16 length)
 */
static inline sol_err_t
sol_encode_bytes_prefixed(sol_encoder_t* enc, const uint8_t* data, size_t len) {
    if (len > 0xffff) return SOL_ERR_ENCODE;
    sol_err_t err = sol_encode_compact_u16(enc, (uint16_t)len);
    if (err != SOL_OK) return err;
    return sol_encode_bytes(enc, data, len);
}

#endif /* SOL_BINCODE_H */
