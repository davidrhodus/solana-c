/*
 * fuzz_blockstore_insert.c - Fuzz blockstore insertion + assembly
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "sol_blockstore.h"

static size_t
write_legacy_data_shred(uint8_t* out, size_t out_cap,
                        sol_slot_t slot, uint32_t index,
                        bool is_last, const uint8_t* payload, size_t payload_len) {
    /* Keep shreds small and always parseable */
    const size_t total_len = 200;
    const size_t payload_off = SOL_SHRED_HEADER_SIZE + SOL_SHRED_DATA_HEADER_SIZE;
    const size_t max_payload = total_len - payload_off;

    if (!out || out_cap < total_len) return 0;

    memset(out, 0, total_len);

    /* Variant byte at offset 64 (after signature) */
    out[64] = SOL_SHRED_VARIANT_LEGACY_DATA;

    /* Slot (little endian) */
    for (int i = 0; i < 8; i++) {
        out[65 + i] = (uint8_t)((slot >> (i * 8)) & 0xFFu);
    }

    /* Index (little endian) */
    for (int i = 0; i < 4; i++) {
        out[73 + i] = (uint8_t)((index >> (i * 8)) & 0xFFu);
    }

    /* Parent offset, flags, payload size */
    uint16_t parent_offset = (slot > 0) ? 1u : 0u;
    out[88] = (uint8_t)(parent_offset & 0xFFu);
    out[89] = (uint8_t)((parent_offset >> 8) & 0xFFu);

    uint8_t flags = is_last ? SOL_SHRED_FLAG_DATA_COMPLETE : 0u;
    out[90] = flags;

    size_t use_payload = payload_len;
    if (use_payload > max_payload) use_payload = max_payload;

    out[91] = (uint8_t)(use_payload & 0xFFu);
    out[92] = (uint8_t)((use_payload >> 8) & 0xFFu);

    if (payload && use_payload > 0) {
        memcpy(out + payload_off, payload, use_payload);
    }

    return total_len;
}

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (!data || size < 10) return 0;

    uint8_t n = (uint8_t)(data[0] & 0x0Fu);
    if (n == 0) n = 1;
    if (n > 12) n = 12;

    sol_slot_t slot = 0;
    for (int i = 0; i < 8; i++) {
        slot |= (sol_slot_t)data[1 + i] << (i * 8);
    }

    sol_blockstore_config_t cfg = SOL_BLOCKSTORE_CONFIG_DEFAULT;
    cfg.max_slots = 16;
    cfg.max_shreds_per_slot = 64;
    cfg.enable_fec_recovery = false;

    sol_blockstore_t* bs = sol_blockstore_new(&cfg);
    if (!bs) return 0;

    /* Insert a small, complete slot worth of shreds */
    size_t pos = 9;
    for (uint32_t i = 0; i < n; i++) {
        uint8_t raw[256];
        size_t payload_len = 0;
        if (pos < size) {
            payload_len = size - pos;
            if (payload_len > 64) payload_len = 64;
        }

        bool is_last = (i == (uint32_t)(n - 1u));
        size_t raw_len = write_legacy_data_shred(raw, sizeof(raw),
                                                 slot, i, is_last,
                                                 data + pos, payload_len);
        if (raw_len == 0) continue;
        pos += payload_len;

        sol_shred_t parsed;
        if (sol_shred_parse(&parsed, raw, raw_len) != SOL_OK) continue;

        (void)sol_blockstore_insert_shred(bs, &parsed, raw, raw_len);
    }

    /* Exercise retrieval + assembly */
    uint8_t buf[256];
    size_t buf_len = sizeof(buf);
    (void)sol_blockstore_get_shred(bs, slot, 0, true, buf, &buf_len);

    sol_block_t* block = sol_blockstore_get_block(bs, slot);
    if (block) {
        sol_block_destroy(block);
    }

    sol_blockstore_destroy(bs);
    return 0;
}

