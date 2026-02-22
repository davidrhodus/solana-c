/*
 * sol_pb.h - Minimal Protobuf Wire Format Parser/Encoder
 *
 * Implements the protobuf wire format for conformance testing.
 * This is a minimal implementation supporting the protosol schema.
 *
 * Wire format:
 *   Field key = (field_number << 3) | wire_type
 *   Wire types:
 *     0 = Varint (int32, int64, uint32, uint64, bool, enum)
 *     1 = 64-bit (fixed64, sfixed64, double)
 *     2 = Length-delimited (string, bytes, embedded messages)
 *     5 = 32-bit (fixed32, sfixed32, float)
 */

#ifndef SOL_PB_H
#define SOL_PB_H

#include "util/sol_types.h"
#include "util/sol_alloc.h"
#include <string.h>

/*
 * Wire types
 */
#define PB_WIRE_VARINT  0
#define PB_WIRE_64BIT   1
#define PB_WIRE_LEN     2
#define PB_WIRE_32BIT   5

/*
 * Maximum nested message depth
 */
#define PB_MAX_DEPTH 16

/*
 * Protobuf reader context
 */
typedef struct {
    const uint8_t* data;
    size_t         len;
    size_t         pos;
} pb_reader_t;

/*
 * Protobuf writer context
 */
typedef struct {
    uint8_t* data;
    size_t   len;
    size_t   cap;
} pb_writer_t;

/*
 * Field descriptor
 */
typedef struct {
    uint32_t field_num;
    uint8_t  wire_type;
    union {
        uint64_t varint;
        uint64_t fixed64;
        uint32_t fixed32;
        struct {
            const uint8_t* data;
            size_t         len;
        } bytes;
    } value;
} pb_field_t;

/*
 * Initialize reader
 */
static inline void
pb_reader_init(pb_reader_t* r, const uint8_t* data, size_t len) {
    r->data = data;
    r->len = len;
    r->pos = 0;
}

/*
 * Check if more data available
 */
static inline bool
pb_reader_has_more(const pb_reader_t* r) {
    return r->pos < r->len;
}

/*
 * Read varint (up to 64-bit)
 */
static inline bool
pb_read_varint(pb_reader_t* r, uint64_t* out) {
    uint64_t result = 0;
    int shift = 0;

    while (r->pos < r->len && shift < 64) {
        uint8_t b = r->data[r->pos++];
        result |= (uint64_t)(b & 0x7F) << shift;
        if ((b & 0x80) == 0) {
            *out = result;
            return true;
        }
        shift += 7;
    }
    return false;
}

/*
 * Read field key and decode field number + wire type
 */
static inline bool
pb_read_field_key(pb_reader_t* r, uint32_t* field_num, uint8_t* wire_type) {
    uint64_t key;
    if (!pb_read_varint(r, &key)) {
        return false;
    }
    *field_num = (uint32_t)(key >> 3);
    *wire_type = (uint8_t)(key & 0x07);
    return true;
}

/*
 * Read a complete field
 */
static inline bool
pb_read_field(pb_reader_t* r, pb_field_t* f) {
    if (!pb_read_field_key(r, &f->field_num, &f->wire_type)) {
        return false;
    }

    switch (f->wire_type) {
    case PB_WIRE_VARINT:
        return pb_read_varint(r, &f->value.varint);

    case PB_WIRE_64BIT:
        if (r->pos + 8 > r->len) return false;
        memcpy(&f->value.fixed64, r->data + r->pos, 8);
        r->pos += 8;
        return true;

    case PB_WIRE_LEN: {
        uint64_t len;
        if (!pb_read_varint(r, &len)) return false;
        if (r->pos + len > r->len) return false;
        f->value.bytes.data = r->data + r->pos;
        f->value.bytes.len = (size_t)len;
        r->pos += (size_t)len;
        return true;
    }

    case PB_WIRE_32BIT:
        if (r->pos + 4 > r->len) return false;
        memcpy(&f->value.fixed32, r->data + r->pos, 4);
        r->pos += 4;
        return true;

    default:
        return false;  /* Unknown wire type */
    }
}

/*
 * Skip a field (for unknown fields)
 */
static inline bool
pb_skip_field(pb_reader_t* r, uint8_t wire_type) {
    switch (wire_type) {
    case PB_WIRE_VARINT: {
        uint64_t dummy;
        return pb_read_varint(r, &dummy);
    }
    case PB_WIRE_64BIT:
        if (r->pos + 8 > r->len) return false;
        r->pos += 8;
        return true;
    case PB_WIRE_LEN: {
        uint64_t len;
        if (!pb_read_varint(r, &len)) return false;
        if (r->pos + len > r->len) return false;
        r->pos += (size_t)len;
        return true;
    }
    case PB_WIRE_32BIT:
        if (r->pos + 4 > r->len) return false;
        r->pos += 4;
        return true;
    default:
        return false;
    }
}

/*
 * Initialize writer with initial capacity
 */
static inline bool
pb_writer_init(pb_writer_t* w, size_t initial_cap) {
    w->data = sol_alloc(initial_cap);
    if (!w->data) return false;
    w->len = 0;
    w->cap = initial_cap;
    return true;
}

/*
 * Free writer
 */
static inline void
pb_writer_free(pb_writer_t* w) {
    if (w->data) {
        sol_free(w->data);
        w->data = NULL;
    }
    w->len = 0;
    w->cap = 0;
}

/*
 * Ensure capacity
 */
static inline bool
pb_writer_ensure(pb_writer_t* w, size_t additional) {
    if (w->len + additional <= w->cap) {
        return true;
    }
    size_t new_cap = w->cap * 2;
    if (new_cap < w->len + additional) {
        new_cap = w->len + additional;
    }
    uint8_t* new_data = sol_realloc(w->data, new_cap);
    if (!new_data) return false;
    w->data = new_data;
    w->cap = new_cap;
    return true;
}

/*
 * Write raw bytes
 */
static inline bool
pb_write_raw(pb_writer_t* w, const uint8_t* data, size_t len) {
    if (!pb_writer_ensure(w, len)) return false;
    memcpy(w->data + w->len, data, len);
    w->len += len;
    return true;
}

/*
 * Write varint
 */
static inline bool
pb_write_varint(pb_writer_t* w, uint64_t value) {
    uint8_t buf[10];
    size_t len = 0;

    do {
        buf[len] = (uint8_t)(value & 0x7F);
        value >>= 7;
        if (value != 0) {
            buf[len] |= 0x80;
        }
        len++;
    } while (value != 0);

    return pb_write_raw(w, buf, len);
}

/*
 * Write field key
 */
static inline bool
pb_write_field_key(pb_writer_t* w, uint32_t field_num, uint8_t wire_type) {
    uint64_t key = ((uint64_t)field_num << 3) | wire_type;
    return pb_write_varint(w, key);
}

/*
 * Write varint field
 */
static inline bool
pb_write_varint_field(pb_writer_t* w, uint32_t field_num, uint64_t value) {
    if (!pb_write_field_key(w, field_num, PB_WIRE_VARINT)) return false;
    return pb_write_varint(w, value);
}

/*
 * Write fixed64 field
 */
static inline bool
pb_write_fixed64_field(pb_writer_t* w, uint32_t field_num, uint64_t value) {
    if (!pb_write_field_key(w, field_num, PB_WIRE_64BIT)) return false;
    return pb_write_raw(w, (const uint8_t*)&value, 8);
}

/*
 * Write fixed32 field
 */
static inline bool
pb_write_fixed32_field(pb_writer_t* w, uint32_t field_num, uint32_t value) {
    if (!pb_write_field_key(w, field_num, PB_WIRE_32BIT)) return false;
    return pb_write_raw(w, (const uint8_t*)&value, 4);
}

/*
 * Write bytes/string field
 */
static inline bool
pb_write_bytes_field(pb_writer_t* w, uint32_t field_num, const uint8_t* data, size_t len) {
    if (!pb_write_field_key(w, field_num, PB_WIRE_LEN)) return false;
    if (!pb_write_varint(w, len)) return false;
    return pb_write_raw(w, data, len);
}

/*
 * Write embedded message field
 * The message data should already be serialized
 */
static inline bool
pb_write_message_field(pb_writer_t* w, uint32_t field_num, const uint8_t* data, size_t len) {
    return pb_write_bytes_field(w, field_num, data, len);
}

/*
 * Get writer output (transfers ownership)
 */
static inline uint8_t*
pb_writer_finish(pb_writer_t* w, size_t* out_len) {
    *out_len = w->len;
    uint8_t* result = w->data;
    w->data = NULL;
    w->len = 0;
    w->cap = 0;
    return result;
}

/*
 * Signed varint encoding (zigzag)
 */
static inline uint64_t
pb_zigzag_encode(int64_t value) {
    return ((uint64_t)value << 1) ^ (uint64_t)(value >> 63);
}

static inline int64_t
pb_zigzag_decode(uint64_t value) {
    return (int64_t)((value >> 1) ^ -(int64_t)(value & 1));
}

#endif /* SOL_PB_H */
