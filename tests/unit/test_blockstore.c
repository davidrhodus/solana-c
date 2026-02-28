/*
 * test_blockstore.c - Blockstore unit tests
 */

#include "../test_framework.h"
#include "sol_blockstore.h"
#include "sol_shred.h"
#include "sol_alloc.h"
#include "sol_log.h"
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

/*
 * Helper to create a mock data shred
 */
static void
create_mock_shred(sol_shred_t* shred, uint8_t* data, size_t* len,
                  sol_slot_t slot, uint32_t index, bool is_last) {
    memset(shred, 0, sizeof(*shred));
    shred->slot = slot;
    shred->index = index;
    shred->type = SOL_SHRED_TYPE_DATA;
    shred->header.data.parent_slot = slot > 0 ? slot - 1 : 0;  /* Parent is slot - 1 */

    if (is_last) {
        shred->header.data.flags = SOL_SHRED_FLAG_LAST_IN_SLOT;
    }

    /* Create mock raw data */
    memset(data, 0, 1024);

    /* Write a minimal, parseable legacy data shred wire format. */
    data[64] = SOL_SHRED_VARIANT_LEGACY_DATA;

    /* Slot (little endian) */
    for (int i = 0; i < 8; i++) {
        data[65 + i] = (uint8_t)((slot >> (i * 8)) & 0xFFu);
    }

    /* Index (little endian) */
    for (int i = 0; i < 4; i++) {
        data[73 + i] = (uint8_t)((index >> (i * 8)) & 0xFFu);
    }

    /* Parent offset (slot - parent_slot), flags and payload size */
    uint16_t parent_offset = (uint16_t)(slot - shred->header.data.parent_slot);
    data[SOL_SHRED_HEADER_SIZE + 0] = (uint8_t)(parent_offset & 0xFFu);
    data[SOL_SHRED_HEADER_SIZE + 1] = (uint8_t)((parent_offset >> 8) & 0xFFu);
    data[SOL_SHRED_HEADER_SIZE + 2] = shred->header.data.flags;

    uint16_t payload_len = 200 - (uint16_t)SOL_SHRED_DATA_HEADERS_SIZE;
    uint16_t total_size = (uint16_t)((uint16_t)SOL_SHRED_DATA_HEADERS_SIZE + payload_len);
    data[SOL_SHRED_HEADER_SIZE + 3] = (uint8_t)(total_size & 0xFFu);
    data[SOL_SHRED_HEADER_SIZE + 4] = (uint8_t)((total_size >> 8) & 0xFFu);

    /* Add some payload */
    size_t payload_off = SOL_SHRED_HEADER_SIZE + SOL_SHRED_DATA_HEADER_SIZE;
    for (size_t i = payload_off; i < 200; i++) {
        data[i] = (uint8_t)(i + index);
    }

    *len = 200;
}

static size_t
build_mock_legacy_data_shred(uint8_t* out, size_t out_len,
                             sol_slot_t slot, uint32_t index,
                             uint16_t version, uint32_t fec_set_index,
                             uint8_t flags,
                             const uint8_t* payload, size_t payload_len) {
    size_t needed = SOL_SHRED_HEADER_SIZE + SOL_SHRED_DATA_HEADER_SIZE + payload_len;
    if (needed > out_len) return 0;
    if (payload_len > UINT16_MAX) return 0;

    memset(out, 0, needed);

    out[64] = SOL_SHRED_VARIANT_LEGACY_DATA;

    for (int i = 0; i < 8; i++) {
        out[65 + i] = (uint8_t)((slot >> (i * 8)) & 0xFFu);
    }

    for (int i = 0; i < 4; i++) {
        out[73 + i] = (uint8_t)((index >> (i * 8)) & 0xFFu);
    }

    out[77] = (uint8_t)(version & 0xFFu);
    out[78] = (uint8_t)((version >> 8) & 0xFFu);

    for (int i = 0; i < 4; i++) {
        out[79 + i] = (uint8_t)((fec_set_index >> (i * 8)) & 0xFFu);
    }

    sol_slot_t parent_slot = slot > 0 ? slot - 1 : 0;
    uint16_t parent_offset = (uint16_t)(slot - parent_slot);
    out[SOL_SHRED_HEADER_SIZE + 0] = (uint8_t)(parent_offset & 0xFFu);
    out[SOL_SHRED_HEADER_SIZE + 1] = (uint8_t)((parent_offset >> 8) & 0xFFu);
    out[SOL_SHRED_HEADER_SIZE + 2] = flags;

    out[SOL_SHRED_HEADER_SIZE + 3] = (uint8_t)(needed & 0xFFu);
    out[SOL_SHRED_HEADER_SIZE + 4] = (uint8_t)((needed >> 8) & 0xFFu);

    if (payload_len > 0) {
        memcpy(out + SOL_SHRED_HEADER_SIZE + SOL_SHRED_DATA_HEADER_SIZE, payload, payload_len);
    }

    return needed;
}

static size_t
build_mock_legacy_code_shred(uint8_t* out, size_t out_len,
                             sol_slot_t slot, uint32_t index,
                             uint16_t version, uint32_t fec_set_index,
                             uint16_t num_data, uint16_t num_code, uint16_t position,
                             const uint8_t* payload, size_t payload_len) {
    size_t needed = SOL_SHRED_HEADER_SIZE + SOL_SHRED_CODE_HEADER_SIZE + payload_len;
    if (needed > out_len) return 0;

    memset(out, 0, needed);

    out[64] = SOL_SHRED_VARIANT_LEGACY_CODE;

    for (int i = 0; i < 8; i++) {
        out[65 + i] = (uint8_t)((slot >> (i * 8)) & 0xFFu);
    }

    for (int i = 0; i < 4; i++) {
        out[73 + i] = (uint8_t)((index >> (i * 8)) & 0xFFu);
    }

    out[77] = (uint8_t)(version & 0xFFu);
    out[78] = (uint8_t)((version >> 8) & 0xFFu);

    for (int i = 0; i < 4; i++) {
        out[79 + i] = (uint8_t)((fec_set_index >> (i * 8)) & 0xFFu);
    }

    out[SOL_SHRED_HEADER_SIZE + 0] = (uint8_t)(num_data & 0xFFu);
    out[SOL_SHRED_HEADER_SIZE + 1] = (uint8_t)((num_data >> 8) & 0xFFu);
    out[SOL_SHRED_HEADER_SIZE + 2] = (uint8_t)(num_code & 0xFFu);
    out[SOL_SHRED_HEADER_SIZE + 3] = (uint8_t)((num_code >> 8) & 0xFFu);
    out[SOL_SHRED_HEADER_SIZE + 4] = (uint8_t)(position & 0xFFu);
    out[SOL_SHRED_HEADER_SIZE + 5] = (uint8_t)((position >> 8) & 0xFFu);

    if (payload_len > 0) {
        memcpy(out + SOL_SHRED_HEADER_SIZE + SOL_SHRED_CODE_HEADER_SIZE, payload, payload_len);
    }

    return needed;
}

static void
remove_dir_recursive(const char* path) {
    DIR* dir = opendir(path);
    if (!dir) return;

    struct dirent* entry;
    char full_path[512];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

        struct stat st;
        if (stat(full_path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                remove_dir_recursive(full_path);
            } else {
                unlink(full_path);
            }
        }
    }

    closedir(dir);
    rmdir(path);
}

/*
 * Creation tests
 */

TEST(blockstore_create_destroy) {
    sol_blockstore_config_t config = SOL_BLOCKSTORE_CONFIG_DEFAULT;

    sol_blockstore_t* bs = sol_blockstore_new(&config);
    TEST_ASSERT(bs != NULL);

    TEST_ASSERT_EQ(sol_blockstore_slot_count(bs), 0);

    sol_blockstore_destroy(bs);
}

TEST(blockstore_create_null_config) {
    /* NULL config should use defaults */
    sol_blockstore_t* bs = sol_blockstore_new(NULL);
    TEST_ASSERT(bs != NULL);

    sol_blockstore_destroy(bs);
}

TEST(blockstore_address_signature_index) {
    sol_blockstore_t* bs = sol_blockstore_new(NULL);
    TEST_ASSERT(bs != NULL);

    sol_pubkey_t addr = {0};
    addr.bytes[0] = 0xA1;
    sol_pubkey_t other = {0};
    other.bytes[0] = 0xB2;

    sol_pubkey_t keys[2] = {addr, other};

    sol_signature_t sig1 = {0};
    sol_signature_t sig2 = {0};
    sol_signature_t sig3 = {0};
    memset(sig1.bytes, 0x11, sizeof(sig1.bytes));
    memset(sig2.bytes, 0x22, sizeof(sig2.bytes));
    memset(sig3.bytes, 0x33, sizeof(sig3.bytes));

    TEST_ASSERT_EQ(sol_blockstore_index_transaction(bs, 100, &sig1, keys, 2, SOL_OK), SOL_OK);
    TEST_ASSERT_EQ(sol_blockstore_index_transaction(bs, 105, &sig2, keys, 2, SOL_ERR_TX_SIGNATURE), SOL_OK);
    TEST_ASSERT_EQ(sol_blockstore_index_transaction(bs, 101, &sig3, keys, 1, SOL_OK), SOL_OK);

    sol_blockstore_address_signature_t out[10];
    size_t n = sol_blockstore_get_signatures_for_address(bs, &addr, 10, out, 10);
    TEST_ASSERT_EQ(n, 3);

    TEST_ASSERT_EQ(out[0].slot, 105);
    TEST_ASSERT_MEM_EQ(out[0].signature.bytes, sig2.bytes, sizeof(sig2.bytes));
    TEST_ASSERT_EQ(out[0].err, SOL_ERR_TX_SIGNATURE);

    TEST_ASSERT_EQ(out[1].slot, 101);
    TEST_ASSERT_MEM_EQ(out[1].signature.bytes, sig3.bytes, sizeof(sig3.bytes));
    TEST_ASSERT_EQ(out[1].err, SOL_OK);

    TEST_ASSERT_EQ(out[2].slot, 100);
    TEST_ASSERT_MEM_EQ(out[2].signature.bytes, sig1.bytes, sizeof(sig1.bytes));
    TEST_ASSERT_EQ(out[2].err, SOL_OK);

    /* The other address should see only the first two transactions. */
    n = sol_blockstore_get_signatures_for_address(bs, &other, 10, out, 10);
    TEST_ASSERT_EQ(n, 2);
    TEST_ASSERT_EQ(out[0].slot, 105);
    TEST_ASSERT_EQ(out[1].slot, 100);

    sol_blockstore_destroy(bs);
}

/*
 * Shred insertion tests
 */

TEST(blockstore_insert_single_shred) {
    sol_blockstore_t* bs = sol_blockstore_new(NULL);
    TEST_ASSERT(bs != NULL);

    sol_shred_t shred;
    uint8_t data[1024];
    size_t len;

    create_mock_shred(&shred, data, &len, 1000, 0, true);

    sol_err_t err = sol_blockstore_insert_shred(bs, &shred, data, len);
    TEST_ASSERT_EQ(err, SOL_OK);

    /* Slot should exist now */
    TEST_ASSERT_EQ(sol_blockstore_slot_count(bs), 1);
    TEST_ASSERT_EQ(sol_blockstore_highest_slot(bs), 1000);

    sol_blockstore_destroy(bs);
}

TEST(blockstore_insert_duplicate) {
    sol_blockstore_t* bs = sol_blockstore_new(NULL);
    TEST_ASSERT(bs != NULL);

    sol_shred_t shred;
    uint8_t data[1024];
    size_t len;

    create_mock_shred(&shred, data, &len, 1000, 0, true);

    sol_err_t err = sol_blockstore_insert_shred(bs, &shred, data, len);
    TEST_ASSERT_EQ(err, SOL_OK);

    /* Insert same shred again - should return duplicate */
    err = sol_blockstore_insert_shred(bs, &shred, data, len);
    TEST_ASSERT_EQ(err, SOL_ERR_EXISTS);

    sol_blockstore_destroy(bs);
}

TEST(blockstore_signature_only_difference_is_duplicate) {
    sol_blockstore_t* bs = sol_blockstore_new(NULL);
    TEST_ASSERT_NOT_NULL(bs);

    const sol_slot_t slot = 1000;
    const uint32_t index = 0;

    sol_shred_t shred;
    memset(&shred, 0, sizeof(shred));
    shred.slot = slot;
    shred.index = index;
    shred.type = SOL_SHRED_TYPE_DATA;
    shred.header.data.parent_slot = slot - 1;
    shred.header.data.flags = SOL_SHRED_FLAG_LAST_IN_SLOT;

    uint8_t payload[16];
    memset(payload, 0xA5, sizeof(payload));

    uint8_t raw1[256];
    uint8_t raw2[256];
    size_t len = build_mock_legacy_data_shred(raw1, sizeof(raw1),
                                              slot, index,
                                              0, 0,
                                              SOL_SHRED_FLAG_LAST_IN_SLOT,
                                              payload, sizeof(payload));
    TEST_ASSERT(len > 0);
    memcpy(raw2, raw1, len);

    /* Mutate only the signature bytes. The shred content (signed bytes after
     * the signature) is identical, so blockstore should treat it as a duplicate. */
    raw1[0] = 0x11;
    raw2[0] = 0x22;

    sol_err_t err = sol_blockstore_insert_shred(bs, &shred, raw1, len);
    TEST_ASSERT_EQ(err, SOL_OK);

    err = sol_blockstore_insert_shred(bs, &shred, raw2, len);
    TEST_ASSERT_EQ(err, SOL_ERR_EXISTS);

    TEST_ASSERT_EQ(sol_blockstore_num_variants(bs, slot), 1);

    sol_blockstore_destroy(bs);
}

TEST(blockstore_conflicting_data_shred_creates_variant) {
    sol_blockstore_t* bs = sol_blockstore_new(NULL);
    TEST_ASSERT(bs != NULL);

    const sol_slot_t slot = 1000;
    const uint32_t index = 0;

    sol_shred_t shred;
    memset(&shred, 0, sizeof(shred));
    shred.slot = slot;
    shred.index = index;
    shred.type = SOL_SHRED_TYPE_DATA;
    shred.header.data.parent_slot = slot - 1;
    shred.header.data.flags = SOL_SHRED_FLAG_LAST_IN_SLOT;

    uint8_t raw1[256];
    uint8_t raw2[256];
    uint8_t payload1[16];
    uint8_t payload2[16];
    memset(payload1, 0xA1, sizeof(payload1));
    memset(payload2, 0xB2, sizeof(payload2));

    size_t len1 = build_mock_legacy_data_shred(raw1, sizeof(raw1),
                                               slot, index,
                                               0, 0,
                                               SOL_SHRED_FLAG_LAST_IN_SLOT,
                                               payload1, sizeof(payload1));
    size_t len2 = build_mock_legacy_data_shred(raw2, sizeof(raw2),
                                               slot, index,
                                               0, 0,
                                               SOL_SHRED_FLAG_LAST_IN_SLOT,
                                               payload2, sizeof(payload2));
    TEST_ASSERT(len1 > 0);
    TEST_ASSERT(len2 > 0);

    sol_err_t err = sol_blockstore_insert_shred(bs, &shred, raw1, len1);
    TEST_ASSERT_EQ(err, SOL_OK);

    err = sol_blockstore_insert_shred(bs, &shred, raw2, len2);
    TEST_ASSERT_EQ(err, SOL_OK);

    TEST_ASSERT_EQ(sol_blockstore_num_variants(bs, slot), 2);
    TEST_ASSERT(sol_blockstore_is_slot_complete(bs, slot));

    sol_block_t* b0 = sol_blockstore_get_block_variant(bs, slot, 0);
    sol_block_t* b1 = sol_blockstore_get_block_variant(bs, slot, 1);
    TEST_ASSERT_NOT_NULL(b0);
    TEST_ASSERT_NOT_NULL(b1);
    TEST_ASSERT(b0->data_len == b1->data_len);
    TEST_ASSERT(memcmp(b0->data, b1->data, b0->data_len) != 0);

    sol_block_destroy(b0);
    sol_block_destroy(b1);
    sol_blockstore_destroy(bs);
}

TEST(blockstore_variant_can_complete_without_primary_full) {
    sol_blockstore_t* bs = sol_blockstore_new(NULL);
    TEST_ASSERT_NOT_NULL(bs);

    const sol_slot_t slot = 2001;
    const uint32_t last_index = 2;

    uint8_t payload0[16];
    uint8_t payload1[16];
    uint8_t payload2_orig[16];
    uint8_t payload2_conflict[16];
    memset(payload0, 0x10, sizeof(payload0));
    memset(payload1, 0x21, sizeof(payload1));
    memset(payload2_orig, 0x32, sizeof(payload2_orig));
    memset(payload2_conflict, 0x43, sizeof(payload2_conflict));

    uint8_t raw0[256];
    uint8_t raw1[256];
    uint8_t raw2[256];
    uint8_t raw2b[256];

    size_t len0 = build_mock_legacy_data_shred(raw0, sizeof(raw0),
                                               slot, 0,
                                               0, 0,
                                               0,
                                               payload0, sizeof(payload0));
    size_t len1 = build_mock_legacy_data_shred(raw1, sizeof(raw1),
                                               slot, 1,
                                               0, 0,
                                               0,
                                               payload1, sizeof(payload1));
    size_t len2 = build_mock_legacy_data_shred(raw2, sizeof(raw2),
                                               slot, last_index,
                                               0, 0,
                                               0,
                                               payload2_orig, sizeof(payload2_orig));
    size_t len2b = build_mock_legacy_data_shred(raw2b, sizeof(raw2b),
                                                slot, last_index,
                                                0, 0,
                                                SOL_SHRED_FLAG_LAST_IN_SLOT,
                                                payload2_conflict, sizeof(payload2_conflict));
    TEST_ASSERT(len0 > 0);
    TEST_ASSERT(len1 > 0);
    TEST_ASSERT(len2 > 0);
    TEST_ASSERT(len2b > 0);

    sol_shred_t shred;
    memset(&shred, 0, sizeof(shred));
    shred.slot = slot;
    shred.type = SOL_SHRED_TYPE_DATA;
    shred.header.data.parent_slot = slot - 1;

    shred.index = 0;
    shred.header.data.flags = 0;
    TEST_ASSERT_EQ(sol_blockstore_insert_shred(bs, &shred, raw0, len0), SOL_OK);

    shred.index = 1;
    shred.header.data.flags = 0;
    TEST_ASSERT_EQ(sol_blockstore_insert_shred(bs, &shred, raw1, len1), SOL_OK);

    shred.index = last_index;
    shred.header.data.flags = 0;
    TEST_ASSERT_EQ(sol_blockstore_insert_shred(bs, &shred, raw2, len2), SOL_OK);

    /* Insert conflicting "last shred" => variant becomes complete, primary does not */
    shred.index = last_index;
    shred.header.data.flags = SOL_SHRED_FLAG_LAST_IN_SLOT;
    TEST_ASSERT_EQ(sol_blockstore_insert_shred(bs, &shred, raw2b, len2b), SOL_OK);

    sol_slot_meta_t meta = {0};
    TEST_ASSERT_EQ(sol_blockstore_get_slot_meta(bs, slot, &meta), SOL_OK);
    TEST_ASSERT(!meta.is_complete);

    TEST_ASSERT(sol_blockstore_is_slot_complete(bs, slot));
    TEST_ASSERT_EQ(sol_blockstore_num_variants(bs, slot), 2);

    TEST_ASSERT(sol_blockstore_get_block_variant(bs, slot, 0) == NULL);

    sol_block_t* b1 = sol_blockstore_get_block_variant(bs, slot, 1);
    TEST_ASSERT_NOT_NULL(b1);

    uint8_t expected[64];
    size_t expected_len = sizeof(payload0) + sizeof(payload1) + sizeof(payload2_conflict);
    TEST_ASSERT(expected_len <= sizeof(expected));
    memcpy(expected, payload0, sizeof(payload0));
    memcpy(expected + sizeof(payload0), payload1, sizeof(payload1));
    memcpy(expected + sizeof(payload0) + sizeof(payload1), payload2_conflict, sizeof(payload2_conflict));

    TEST_ASSERT_EQ(b1->data_len, expected_len);
    TEST_ASSERT_MEM_EQ(b1->data, expected, expected_len);

    sol_block_destroy(b1);
    sol_blockstore_destroy(bs);
}

TEST(blockstore_conflicting_shred_forks_all_conflicting_variants) {
    sol_blockstore_t* bs = sol_blockstore_new(NULL);
    TEST_ASSERT_NOT_NULL(bs);

    const sol_slot_t slot = 3000;

    uint8_t payload_a0[16];
    uint8_t payload_b0[16];
    uint8_t payload_a1[16];
    uint8_t payload_b1[16];
    memset(payload_a0, 0xA0, sizeof(payload_a0));
    memset(payload_b0, 0xB0, sizeof(payload_b0));
    memset(payload_a1, 0xA1, sizeof(payload_a1));
    memset(payload_b1, 0xB1, sizeof(payload_b1));

    uint8_t raw_a0[256];
    uint8_t raw_b0[256];
    uint8_t raw_a1[256];
    uint8_t raw_b1[256];

    size_t len_a0 = build_mock_legacy_data_shred(raw_a0, sizeof(raw_a0),
                                                 slot, 0,
                                                 0, 0,
                                                 0,
                                                 payload_a0, sizeof(payload_a0));
    size_t len_b0 = build_mock_legacy_data_shred(raw_b0, sizeof(raw_b0),
                                                 slot, 0,
                                                 0, 0,
                                                 0,
                                                 payload_b0, sizeof(payload_b0));
    size_t len_a1 = build_mock_legacy_data_shred(raw_a1, sizeof(raw_a1),
                                                 slot, 1,
                                                 0, 0,
                                                 SOL_SHRED_FLAG_LAST_IN_SLOT,
                                                 payload_a1, sizeof(payload_a1));
    size_t len_b1 = build_mock_legacy_data_shred(raw_b1, sizeof(raw_b1),
                                                 slot, 1,
                                                 0, 0,
                                                 SOL_SHRED_FLAG_LAST_IN_SLOT,
                                                 payload_b1, sizeof(payload_b1));
    TEST_ASSERT(len_a0 > 0);
    TEST_ASSERT(len_b0 > 0);
    TEST_ASSERT(len_a1 > 0);
    TEST_ASSERT(len_b1 > 0);

    sol_shred_t shred;
    memset(&shred, 0, sizeof(shred));
    shred.slot = slot;
    shred.type = SOL_SHRED_TYPE_DATA;
    shred.header.data.parent_slot = slot - 1;

    shred.index = 0;
    shred.header.data.flags = 0;
    TEST_ASSERT_EQ(sol_blockstore_insert_shred(bs, &shred, raw_a0, len_a0), SOL_OK);

    shred.index = 0;
    shred.header.data.flags = 0;
    TEST_ASSERT_EQ(sol_blockstore_insert_shred(bs, &shred, raw_b0, len_b0), SOL_OK);

    shred.index = 1;
    shred.header.data.flags = SOL_SHRED_FLAG_LAST_IN_SLOT;
    TEST_ASSERT_EQ(sol_blockstore_insert_shred(bs, &shred, raw_a1, len_a1), SOL_OK);

    shred.index = 1;
    shred.header.data.flags = SOL_SHRED_FLAG_LAST_IN_SLOT;
    TEST_ASSERT_EQ(sol_blockstore_insert_shred(bs, &shred, raw_b1, len_b1), SOL_OK);

    TEST_ASSERT(sol_blockstore_is_slot_complete(bs, slot));
    TEST_ASSERT_EQ(sol_blockstore_num_variants(bs, slot), 4);

    uint8_t expected[64];
    size_t expected_len = sizeof(payload_b0) + sizeof(payload_b1);
    TEST_ASSERT(expected_len <= sizeof(expected));
    memcpy(expected, payload_b0, sizeof(payload_b0));
    memcpy(expected + sizeof(payload_b0), payload_b1, sizeof(payload_b1));

    bool found = false;
    for (uint32_t variant_id = 0; variant_id < 4; variant_id++) {
        sol_block_t* block = sol_blockstore_get_block_variant(bs, slot, variant_id);
        if (!block) continue;
        if (block->data_len == expected_len &&
            memcmp(block->data, expected, expected_len) == 0) {
            found = true;
        }
        sol_block_destroy(block);
    }

    TEST_ASSERT(found);
    sol_blockstore_destroy(bs);
}

TEST(blockstore_insert_multiple_shreds) {
    sol_blockstore_t* bs = sol_blockstore_new(NULL);
    TEST_ASSERT(bs != NULL);

    sol_shred_t shred;
    uint8_t data[1024];
    size_t len;

    /* Insert 10 shreds */
    for (uint32_t i = 0; i < 10; i++) {
        create_mock_shred(&shred, data, &len, 1000, i, i == 9);

        sol_err_t err = sol_blockstore_insert_shred(bs, &shred, data, len);
        TEST_ASSERT_EQ(err, SOL_OK);
    }

    /* Should have one slot */
    TEST_ASSERT_EQ(sol_blockstore_slot_count(bs), 1);

    /* Slot should be complete */
    TEST_ASSERT(sol_blockstore_is_slot_complete(bs, 1000));

    sol_blockstore_destroy(bs);
}

/*
 * Slot completion tests
 */

TEST(blockstore_slot_incomplete) {
    sol_blockstore_t* bs = sol_blockstore_new(NULL);
    TEST_ASSERT(bs != NULL);

    sol_shred_t shred;
    uint8_t data[1024];
    size_t len;

    /* Insert shreds 0, 1, 2 but not 3 (which would be last) */
    for (uint32_t i = 0; i < 3; i++) {
        create_mock_shred(&shred, data, &len, 1000, i, false);
        sol_blockstore_insert_shred(bs, &shred, data, len);
    }

    /* Not complete yet */
    TEST_ASSERT(!sol_blockstore_is_slot_complete(bs, 1000));

    sol_blockstore_destroy(bs);
}

TEST(blockstore_slot_complete_with_gaps) {
    sol_blockstore_t* bs = sol_blockstore_new(NULL);
    TEST_ASSERT(bs != NULL);

    sol_shred_t shred;
    uint8_t data[1024];
    size_t len;

    /* Insert shreds out of order with gap: 0, 2, 4 (last) */
    create_mock_shred(&shred, data, &len, 1000, 0, false);
    sol_blockstore_insert_shred(bs, &shred, data, len);

    create_mock_shred(&shred, data, &len, 1000, 2, false);
    sol_blockstore_insert_shred(bs, &shred, data, len);

    create_mock_shred(&shred, data, &len, 1000, 4, true);
    sol_blockstore_insert_shred(bs, &shred, data, len);

    /* Not complete - missing 1 and 3 */
    TEST_ASSERT(!sol_blockstore_is_slot_complete(bs, 1000));

    /* Fill gaps */
    create_mock_shred(&shred, data, &len, 1000, 1, false);
    sol_blockstore_insert_shred(bs, &shred, data, len);

    create_mock_shred(&shred, data, &len, 1000, 3, false);
    sol_blockstore_insert_shred(bs, &shred, data, len);

    /* Now complete */
    TEST_ASSERT(sol_blockstore_is_slot_complete(bs, 1000));

    sol_blockstore_destroy(bs);
}

TEST(blockstore_slot_complete_then_extended) {
    sol_blockstore_t* bs = sol_blockstore_new(NULL);
    TEST_ASSERT_NOT_NULL(bs);

    sol_shred_t shred;
    uint8_t data[1024];
    size_t len;

    for (uint32_t i = 0; i < 3; i++) {
        create_mock_shred(&shred, data, &len, 1000, i, i == 2);
        sol_blockstore_insert_shred(bs, &shred, data, len);
    }

    TEST_ASSERT(sol_blockstore_is_slot_complete(bs, 1000));

    sol_slot_meta_t meta;
    TEST_ASSERT_EQ(sol_blockstore_get_slot_meta(bs, 1000, &meta), SOL_OK);
    TEST_ASSERT(meta.is_complete);
    TEST_ASSERT_EQ(meta.last_shred_index, 2);

    /* Insert a higher-index shred without LAST_IN_SLOT; should invalidate completion. */
    create_mock_shred(&shred, data, &len, 1000, 4, false);
    sol_blockstore_insert_shred(bs, &shred, data, len);

    TEST_ASSERT(!sol_blockstore_is_slot_complete(bs, 1000));
    TEST_ASSERT_EQ(sol_blockstore_get_slot_meta(bs, 1000, &meta), SOL_OK);
    TEST_ASSERT(!meta.is_complete);
    TEST_ASSERT(!meta.is_full);
    TEST_ASSERT_EQ(meta.last_shred_index, 4);

    uint32_t missing[8];
    size_t missing_count = sol_blockstore_get_missing_shreds(bs, 1000, missing, 8);
    bool have_missing3 = false;
    for (size_t i = 0; i < missing_count; i++) {
        if (missing[i] == 3u) {
            have_missing3 = true;
            break;
        }
    }
    TEST_ASSERT(have_missing3);

    sol_blockstore_destroy(bs);
}

TEST(blockstore_fec_recovery_single_missing) {
    sol_blockstore_config_t config = SOL_BLOCKSTORE_CONFIG_DEFAULT;
    config.max_slots = 16;
    config.max_shreds_per_slot = 64;
    config.enable_fec_recovery = true;

    sol_blockstore_t* bs = sol_blockstore_new(&config);
    TEST_ASSERT_NOT_NULL(bs);

    const sol_slot_t slot = 2000;
    const uint16_t version = 1;
    const uint32_t fec_set_index = 0;

    enum { NUM_DATA = 4, NUM_CODE = 1, PAYLOAD_LEN = 32 };

    uint8_t payloads[NUM_DATA][PAYLOAD_LEN];
    for (uint32_t i = 0; i < NUM_DATA; i++) {
        for (uint32_t j = 0; j < PAYLOAD_LEN; j++) {
            payloads[i][j] = (uint8_t)((i * 17u) ^ j);
        }
    }

    uint8_t raw_data[NUM_DATA][256];
    size_t raw_lens[NUM_DATA];
    for (uint32_t i = 0; i < NUM_DATA; i++) {
        uint8_t flags = 0;
        if (i == (NUM_DATA - 1)) {
            flags = SOL_SHRED_FLAG_LAST_IN_SLOT;
        }

        raw_lens[i] = build_mock_legacy_data_shred(raw_data[i], sizeof(raw_data[i]),
                                                   slot, i, version, fec_set_index,
                                                   flags,
                                                   payloads[i], PAYLOAD_LEN);
        TEST_ASSERT(raw_lens[i] > 0);
    }

    uint8_t parity[PAYLOAD_LEN];
    memset(parity, 0, sizeof(parity));
    for (uint32_t j = 0; j < PAYLOAD_LEN; j++) {
        for (uint32_t i = 0; i < NUM_DATA; i++) {
            parity[j] ^= payloads[i][j];
        }
    }

    uint8_t raw_code[256];
    size_t raw_code_len = build_mock_legacy_code_shred(raw_code, sizeof(raw_code),
                                                       slot, 0, version, fec_set_index,
                                                       NUM_DATA, NUM_CODE, 0,
                                                       parity, PAYLOAD_LEN);
    TEST_ASSERT(raw_code_len > 0);

    sol_shred_t shred;
    TEST_ASSERT_EQ(sol_shred_parse(&shred, raw_data[0], raw_lens[0]), SOL_OK);
    TEST_ASSERT_EQ(sol_blockstore_insert_shred(bs, &shred, raw_data[0], raw_lens[0]), SOL_OK);

    TEST_ASSERT_EQ(sol_shred_parse(&shred, raw_data[2], raw_lens[2]), SOL_OK);
    TEST_ASSERT_EQ(sol_blockstore_insert_shred(bs, &shred, raw_data[2], raw_lens[2]), SOL_OK);

    TEST_ASSERT_EQ(sol_shred_parse(&shred, raw_data[3], raw_lens[3]), SOL_OK);
    TEST_ASSERT_EQ(sol_blockstore_insert_shred(bs, &shred, raw_data[3], raw_lens[3]), SOL_OK);

    TEST_ASSERT(!sol_blockstore_has_shred(bs, slot, 1, true));
    TEST_ASSERT(!sol_blockstore_is_slot_complete(bs, slot));

    sol_shred_t code_shred;
    TEST_ASSERT_EQ(sol_shred_parse(&code_shred, raw_code, raw_code_len), SOL_OK);
    TEST_ASSERT_EQ(sol_blockstore_insert_shred(bs, &code_shred, raw_code, raw_code_len), SOL_OK);

    TEST_ASSERT(sol_blockstore_has_shred(bs, slot, 1, true));
    TEST_ASSERT(sol_blockstore_is_slot_complete(bs, slot));

    uint8_t buf[256];
    size_t buf_len = sizeof(buf);
    TEST_ASSERT_EQ(sol_blockstore_get_shred(bs, slot, 1, true, buf, &buf_len), SOL_OK);

    sol_shred_t recovered;
    TEST_ASSERT_EQ(sol_shred_parse(&recovered, buf, buf_len), SOL_OK);
    TEST_ASSERT_EQ(recovered.payload_len, (size_t)PAYLOAD_LEN);
    TEST_ASSERT_MEM_EQ(recovered.payload, payloads[1], PAYLOAD_LEN);

    sol_blockstore_destroy(bs);
}

/*
 * Slot metadata tests
 */

TEST(blockstore_slot_meta) {
    sol_blockstore_t* bs = sol_blockstore_new(NULL);
    TEST_ASSERT(bs != NULL);

    sol_shred_t shred;
    uint8_t data[1024];
    size_t len;

    /* Insert some shreds */
    for (uint32_t i = 0; i < 5; i++) {
        create_mock_shred(&shred, data, &len, 1000, i, i == 4);
        sol_blockstore_insert_shred(bs, &shred, data, len);
    }

    sol_slot_meta_t meta;
    sol_err_t err = sol_blockstore_get_slot_meta(bs, 1000, &meta);
    TEST_ASSERT_EQ(err, SOL_OK);

    TEST_ASSERT_EQ(meta.slot, 1000);
    TEST_ASSERT_EQ(meta.parent_slot, 999);  /* slot - 1 */
    TEST_ASSERT_EQ(meta.received_data, 5);
    TEST_ASSERT_EQ(meta.num_data_shreds, 5);
    TEST_ASSERT(meta.is_complete);
    TEST_ASSERT(meta.is_full);

    sol_blockstore_destroy(bs);
}

TEST(blockstore_slot_meta_not_found) {
    sol_blockstore_t* bs = sol_blockstore_new(NULL);
    TEST_ASSERT(bs != NULL);

    sol_slot_meta_t meta;
    sol_err_t err = sol_blockstore_get_slot_meta(bs, 9999, &meta);
    TEST_ASSERT_EQ(err, SOL_ERR_NOTFOUND);

    sol_blockstore_destroy(bs);
}

/*
 * Missing shred tests
 */

TEST(blockstore_get_missing) {
    sol_blockstore_t* bs = sol_blockstore_new(NULL);
    TEST_ASSERT(bs != NULL);

    sol_shred_t shred;
    uint8_t data[1024];
    size_t len;

    /* Insert shreds with gaps: 0, 2, 4, 6, 8, 9 (last) */
    uint32_t inserted[] = {0, 2, 4, 6, 8, 9};
    for (size_t i = 0; i < sizeof(inserted)/sizeof(inserted[0]); i++) {
        create_mock_shred(&shred, data, &len, 1000, inserted[i],
                         inserted[i] == 9);
        sol_blockstore_insert_shred(bs, &shred, data, len);
    }

    uint32_t missing[10];
    size_t num_missing = sol_blockstore_get_missing_shreds(bs, 1000, missing, 10);

    /* Should be missing 1, 3, 5, 7 */
    TEST_ASSERT_EQ(num_missing, 4);
    TEST_ASSERT_EQ(missing[0], 1);
    TEST_ASSERT_EQ(missing[1], 3);
    TEST_ASSERT_EQ(missing[2], 5);
    TEST_ASSERT_EQ(missing[3], 7);

    sol_blockstore_destroy(bs);
}

/*
 * Shred retrieval tests
 */

TEST(blockstore_has_shred) {
    sol_blockstore_t* bs = sol_blockstore_new(NULL);
    TEST_ASSERT(bs != NULL);

    sol_shred_t shred;
    uint8_t data[1024];
    size_t len;

    create_mock_shred(&shred, data, &len, 1000, 5, true);
    sol_blockstore_insert_shred(bs, &shred, data, len);

    TEST_ASSERT(sol_blockstore_has_shred(bs, 1000, 5, true));
    TEST_ASSERT(!sol_blockstore_has_shred(bs, 1000, 4, true));
    TEST_ASSERT(!sol_blockstore_has_shred(bs, 999, 5, true));

    sol_blockstore_destroy(bs);
}

TEST(blockstore_get_shred) {
    sol_blockstore_t* bs = sol_blockstore_new(NULL);
    TEST_ASSERT(bs != NULL);

    sol_shred_t shred;
    uint8_t data[1024];
    size_t len;

    create_mock_shred(&shred, data, &len, 1000, 5, true);
    sol_blockstore_insert_shred(bs, &shred, data, len);

    uint8_t buf[1024];
    size_t buf_len = sizeof(buf);

    sol_err_t err = sol_blockstore_get_shred(bs, 1000, 5, true, buf, &buf_len);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_EQ(buf_len, len);
    TEST_ASSERT_MEM_EQ(buf, data, len);

    sol_blockstore_destroy(bs);
}

/*
 * Block assembly tests
 */

TEST(blockstore_get_block) {
    sol_blockstore_t* bs = sol_blockstore_new(NULL);
    TEST_ASSERT(bs != NULL);

    sol_shred_t shred;
    uint8_t data[1024];
    size_t len;

    /* Insert complete slot */
    for (uint32_t i = 0; i < 5; i++) {
        create_mock_shred(&shred, data, &len, 1000, i, i == 4);
        sol_blockstore_insert_shred(bs, &shred, data, len);
    }

    sol_block_t* block = sol_blockstore_get_block(bs, 1000);
    TEST_ASSERT(block != NULL);
    TEST_ASSERT_EQ(block->slot, 1000);
    TEST_ASSERT_EQ(block->parent_slot, 999);
    TEST_ASSERT(block->data != NULL);
    TEST_ASSERT(block->data_len > 0);

    sol_block_destroy(block);
    sol_blockstore_destroy(bs);
}

TEST(blockstore_get_block_incomplete) {
    sol_blockstore_t* bs = sol_blockstore_new(NULL);
    TEST_ASSERT(bs != NULL);

    sol_shred_t shred;
    uint8_t data[1024];
    size_t len;

    /* Insert incomplete slot */
    create_mock_shred(&shred, data, &len, 1000, 0, false);
    sol_blockstore_insert_shred(bs, &shred, data, len);

    /* Should not be able to get block */
    sol_block_t* block = sol_blockstore_get_block(bs, 1000);
    TEST_ASSERT(block == NULL);

    sol_blockstore_destroy(bs);
}

/*
 * Rooted/dead slot tests
 */

TEST(blockstore_set_rooted) {
    sol_blockstore_t* bs = sol_blockstore_new(NULL);
    TEST_ASSERT(bs != NULL);

    sol_shred_t shred;
    uint8_t data[1024];
    size_t len;

    create_mock_shred(&shred, data, &len, 1000, 0, true);
    sol_blockstore_insert_shred(bs, &shred, data, len);

    sol_err_t err = sol_blockstore_set_rooted(bs, 1000);
    TEST_ASSERT_EQ(err, SOL_OK);

    TEST_ASSERT_EQ(sol_blockstore_highest_rooted_slot(bs), 1000);

    sol_slot_meta_t meta;
    sol_blockstore_get_slot_meta(bs, 1000, &meta);
    TEST_ASSERT(meta.is_rooted);

    sol_blockstore_destroy(bs);
}

TEST(blockstore_set_dead) {
    sol_blockstore_t* bs = sol_blockstore_new(NULL);
    TEST_ASSERT(bs != NULL);

    sol_shred_t shred;
    uint8_t data[1024];
    size_t len;

    create_mock_shred(&shred, data, &len, 1000, 0, true);
    sol_blockstore_insert_shred(bs, &shred, data, len);

    sol_err_t err = sol_blockstore_set_dead(bs, 1000);
    TEST_ASSERT_EQ(err, SOL_OK);

    sol_slot_meta_t meta;
    sol_blockstore_get_slot_meta(bs, 1000, &meta);
    TEST_ASSERT(meta.is_dead);

    sol_blockstore_destroy(bs);
}

/*
 * Purge tests
 */

TEST(blockstore_purge_slots) {
    sol_blockstore_t* bs = sol_blockstore_new(NULL);
    TEST_ASSERT(bs != NULL);

    sol_shred_t shred;
    uint8_t data[1024];
    size_t len;

    /* Insert shreds for slots 100-109 */
    for (sol_slot_t slot = 100; slot < 110; slot++) {
        create_mock_shred(&shred, data, &len, slot, 0, true);
        sol_blockstore_insert_shred(bs, &shred, data, len);
    }

    TEST_ASSERT_EQ(sol_blockstore_slot_count(bs), 10);

    /* Purge slots below 105 */
    size_t purged = sol_blockstore_purge_slots_below(bs, 105);
    TEST_ASSERT_EQ(purged, 5);
    TEST_ASSERT_EQ(sol_blockstore_slot_count(bs), 5);

    /* Verify purged slots don't exist */
    TEST_ASSERT(!sol_blockstore_has_shred(bs, 100, 0, true));
    TEST_ASSERT(!sol_blockstore_has_shred(bs, 104, 0, true));

    /* Verify remaining slots exist */
    TEST_ASSERT(sol_blockstore_has_shred(bs, 105, 0, true));
    TEST_ASSERT(sol_blockstore_has_shred(bs, 109, 0, true));

    sol_blockstore_destroy(bs);
}

/*
 * Statistics tests
 */

TEST(blockstore_stats) {
    sol_blockstore_t* bs = sol_blockstore_new(NULL);
    TEST_ASSERT(bs != NULL);

    sol_shred_t shred;
    uint8_t data[1024];
    size_t len;

    /* Insert some shreds */
    for (uint32_t i = 0; i < 5; i++) {
        create_mock_shred(&shred, data, &len, 1000, i, i == 4);
        sol_blockstore_insert_shred(bs, &shred, data, len);
    }

    /* Insert duplicate */
    create_mock_shred(&shred, data, &len, 1000, 0, false);
    sol_blockstore_insert_shred(bs, &shred, data, len);

    sol_blockstore_stats_t stats;
    sol_blockstore_stats(bs, &stats);

    TEST_ASSERT_EQ(stats.shreds_received, 6);
    TEST_ASSERT_EQ(stats.shreds_inserted, 5);
    TEST_ASSERT_EQ(stats.shreds_duplicate, 1);
    TEST_ASSERT_EQ(stats.slots_created, 1);
    TEST_ASSERT_EQ(stats.slots_completed, 1);

    sol_blockstore_destroy(bs);
}

/*
 * Callback tests
 */

static int callback_called = 0;
static sol_slot_t callback_slot_received = 0;

static void
test_slot_callback(sol_slot_t slot, void* ctx) {
    (void)ctx;
    callback_called++;
    callback_slot_received = slot;
}

TEST(blockstore_callback) {
    sol_blockstore_t* bs = sol_blockstore_new(NULL);
    TEST_ASSERT(bs != NULL);

    callback_called = 0;
    callback_slot_received = 0;

    sol_blockstore_set_slot_callback(bs, test_slot_callback, NULL);

    sol_shred_t shred;
    uint8_t data[1024];
    size_t len;

    /* Insert complete slot */
    for (uint32_t i = 0; i < 5; i++) {
        create_mock_shred(&shred, data, &len, 1000, i, i == 4);
        sol_blockstore_insert_shred(bs, &shred, data, len);
    }

    TEST_ASSERT_EQ(callback_called, 1);
    TEST_ASSERT_EQ(callback_slot_received, 1000);

    sol_blockstore_destroy(bs);
}

/*
 * Null handling tests
 */

TEST(blockstore_null_handling) {
    sol_blockstore_destroy(NULL);

    TEST_ASSERT_EQ(sol_blockstore_insert_shred(NULL, NULL, NULL, 0), SOL_ERR_INVAL);
    TEST_ASSERT(!sol_blockstore_has_shred(NULL, 0, 0, true));
    TEST_ASSERT(!sol_blockstore_is_slot_complete(NULL, 0));
    TEST_ASSERT_EQ(sol_blockstore_highest_slot(NULL), 0);
    TEST_ASSERT(sol_blockstore_get_block(NULL, 0) == NULL);
    TEST_ASSERT_EQ(sol_blockstore_slot_count(NULL), 0);
}

TEST(blockstore_rocksdb_persistence) {
#ifndef SOL_HAS_ROCKSDB
    TEST_SKIP("RocksDB not enabled in build");
#else
    char tmpdir[] = "/tmp/solana_c_blockstore_XXXXXX";
    char* dir = mkdtemp(tmpdir);
    TEST_ASSERT_NOT_NULL(dir);

    sol_blockstore_config_t cfg = SOL_BLOCKSTORE_CONFIG_DEFAULT;
    cfg.storage_type = SOL_BLOCKSTORE_STORAGE_ROCKSDB;
    cfg.rocksdb_path = dir;
    cfg.max_slots = 16;
    cfg.max_shreds_per_slot = 64;

    sol_blockstore_t* bs1 = sol_blockstore_new(&cfg);
    TEST_ASSERT_NOT_NULL(bs1);

    sol_shred_t shred;
    uint8_t data[1024];
    size_t len;

    uint8_t raw0[1024]; size_t raw0_len = 0;
    uint8_t raw1[1024]; size_t raw1_len = 0;
    uint8_t raw2[1024]; size_t raw2_len = 0;

    create_mock_shred(&shred, data, &len, 42, 0, false);
    memcpy(raw0, data, len);
    raw0_len = len;
    TEST_ASSERT_EQ(sol_blockstore_insert_shred(bs1, &shred, data, len), SOL_OK);

    create_mock_shred(&shred, data, &len, 42, 1, false);
    memcpy(raw1, data, len);
    raw1_len = len;
    TEST_ASSERT_EQ(sol_blockstore_insert_shred(bs1, &shred, data, len), SOL_OK);

    create_mock_shred(&shred, data, &len, 42, 2, true);
    memcpy(raw2, data, len);
    raw2_len = len;
    TEST_ASSERT_EQ(sol_blockstore_insert_shred(bs1, &shred, data, len), SOL_OK);

    /* In-memory vs persisted assembly should match. */
    sol_block_t* mem_block = sol_blockstore_get_block(bs1, 42);
    sol_block_t* disk_block = sol_blockstore_get_block_variant_rocksdb(bs1, 42, 0);
    TEST_ASSERT_NOT_NULL(mem_block);
    TEST_ASSERT_NOT_NULL(disk_block);
    TEST_ASSERT_EQ(mem_block->data_len, disk_block->data_len);
    TEST_ASSERT_MEM_EQ(mem_block->data, disk_block->data, mem_block->data_len);
    sol_block_destroy(mem_block);
    sol_block_destroy(disk_block);

    sol_blockstore_destroy(bs1);

    sol_blockstore_t* bs2 = sol_blockstore_new(&cfg);
    TEST_ASSERT_NOT_NULL(bs2);

    sol_slot_meta_t meta = {0};
    TEST_ASSERT_EQ(sol_blockstore_get_slot_meta(bs2, 42, &meta), SOL_OK);
    TEST_ASSERT(meta.is_complete);
    TEST_ASSERT_EQ(meta.last_shred_index, 2);
    TEST_ASSERT(sol_blockstore_is_slot_complete(bs2, 42));

    uint8_t buf[1024];
    size_t buf_len = sizeof(buf);
    TEST_ASSERT_EQ(sol_blockstore_get_shred(bs2, 42, 1, true, buf, &buf_len), SOL_OK);
    TEST_ASSERT_EQ(buf_len, raw1_len);
    TEST_ASSERT_MEM_EQ(buf, raw1, raw1_len);

    sol_block_t* block = sol_blockstore_get_block(bs2, 42);
    TEST_ASSERT_NOT_NULL(block);
    sol_block_t* block2 = sol_blockstore_get_block_variant_rocksdb(bs2, 42, 0);
    TEST_ASSERT_NOT_NULL(block2);

    size_t payload_off = SOL_SHRED_HEADER_SIZE + SOL_SHRED_DATA_HEADER_SIZE;
    size_t payload_len = raw0_len - payload_off;
    TEST_ASSERT_EQ(raw1_len - payload_off, payload_len);
    TEST_ASSERT_EQ(raw2_len - payload_off, payload_len);

    uint8_t expected[4096];
    size_t expected_len = payload_len * 3;
    TEST_ASSERT(expected_len <= sizeof(expected));

    memcpy(expected, raw0 + payload_off, payload_len);
    memcpy(expected + payload_len, raw1 + payload_off, payload_len);
    memcpy(expected + (2 * payload_len), raw2 + payload_off, payload_len);

    TEST_ASSERT_EQ(block->data_len, expected_len);
    TEST_ASSERT_MEM_EQ(block->data, expected, expected_len);
    TEST_ASSERT_EQ(block2->data_len, expected_len);
    TEST_ASSERT_MEM_EQ(block2->data, expected, expected_len);

    sol_block_destroy(block);
    sol_block_destroy(block2);
    sol_blockstore_destroy(bs2);
    remove_dir_recursive(dir);
#endif
}

TEST(blockstore_rocksdb_missing_shreds_without_cache) {
#ifndef SOL_HAS_ROCKSDB
    TEST_SKIP("RocksDB not enabled in build");
#else
    char tmpdir[] = "/tmp/solana_c_blockstore_missing_XXXXXX";
    char* dir = mkdtemp(tmpdir);
    TEST_ASSERT_NOT_NULL(dir);

    sol_blockstore_config_t cfg = SOL_BLOCKSTORE_CONFIG_DEFAULT;
    cfg.storage_type = SOL_BLOCKSTORE_STORAGE_ROCKSDB;
    cfg.rocksdb_path = dir;
    cfg.max_slots = 16;
    cfg.max_shreds_per_slot = 64;

    const sol_slot_t slot = 43;

    sol_blockstore_t* bs1 = sol_blockstore_new(&cfg);
    TEST_ASSERT_NOT_NULL(bs1);

    sol_shred_t shred;
    uint8_t data[1024];
    size_t len;

    /* Persist only the last shred so slot meta reports "full" but incomplete. */
    create_mock_shred(&shred, data, &len, slot, 2, true);
    TEST_ASSERT_EQ(sol_blockstore_insert_shred(bs1, &shred, data, len), SOL_OK);

    sol_blockstore_destroy(bs1);

    sol_blockstore_t* bs2 = sol_blockstore_new(&cfg);
    TEST_ASSERT_NOT_NULL(bs2);

    uint32_t missing[8] = {0};
    size_t missing_count = sol_blockstore_get_missing_shreds(bs2, slot, missing, 8);
    TEST_ASSERT_EQ(missing_count, 2);
    TEST_ASSERT_EQ(missing[0], 0);
    TEST_ASSERT_EQ(missing[1], 1);

    sol_blockstore_destroy(bs2);
    remove_dir_recursive(dir);
#endif
}

TEST(blockstore_rocksdb_lock_conflict_sets_errno) {
#ifndef SOL_HAS_ROCKSDB
    TEST_SKIP("RocksDB not enabled in build");
#else
    char tmpdir[] = "/tmp/solana_c_blockstore_lock_XXXXXX";
    char* dir = mkdtemp(tmpdir);
    TEST_ASSERT_NOT_NULL(dir);

    int ready_pipe[2];
    int done_pipe[2];
    TEST_ASSERT_EQ(pipe(ready_pipe), 0);
    TEST_ASSERT_EQ(pipe(done_pipe), 0);

    pid_t pid = fork();
    TEST_ASSERT(pid >= 0);
    if (pid == 0) {
        close(ready_pipe[0]);
        close(done_pipe[1]);

        sol_blockstore_config_t cfg = SOL_BLOCKSTORE_CONFIG_DEFAULT;
        cfg.storage_type = SOL_BLOCKSTORE_STORAGE_ROCKSDB;
        cfg.rocksdb_path = dir;
        cfg.max_slots = 16;
        cfg.max_shreds_per_slot = 64;

        sol_blockstore_t* bs = sol_blockstore_new(&cfg);
        if (!bs) _exit(2);

        char b = '1';
        (void)write(ready_pipe[1], &b, 1);
        (void)read(done_pipe[0], &b, 1);

        sol_blockstore_destroy(bs);
        _exit(0);
    }

    close(ready_pipe[1]);
    close(done_pipe[0]);

    char b = 0;
    ssize_t r = read(ready_pipe[0], &b, 1);
    TEST_ASSERT_EQ(r, 1);

    sol_blockstore_config_t cfg = SOL_BLOCKSTORE_CONFIG_DEFAULT;
    cfg.storage_type = SOL_BLOCKSTORE_STORAGE_ROCKSDB;
    cfg.rocksdb_path = dir;
    cfg.max_slots = 16;
    cfg.max_shreds_per_slot = 64;

    errno = 0;
    sol_blockstore_t* bs2 = sol_blockstore_new(&cfg);
    TEST_ASSERT_NULL(bs2);
    TEST_ASSERT(errno == EBUSY || errno == EAGAIN);

    b = '1';
    (void)write(done_pipe[1], &b, 1);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) continue;
        break;
    }
    TEST_ASSERT(WIFEXITED(status));
    TEST_ASSERT_EQ(WEXITSTATUS(status), 0);

    close(ready_pipe[0]);
    close(done_pipe[1]);

    remove_dir_recursive(dir);
#endif
}

TEST(blockstore_rocksdb_variant_persistence) {
#ifndef SOL_HAS_ROCKSDB
    TEST_SKIP("RocksDB not enabled in build");
#else
    char tmpdir[] = "/tmp/solana_c_blockstore_variant_XXXXXX";
    char* dir = mkdtemp(tmpdir);
    TEST_ASSERT_NOT_NULL(dir);

    sol_blockstore_config_t cfg = SOL_BLOCKSTORE_CONFIG_DEFAULT;
    cfg.storage_type = SOL_BLOCKSTORE_STORAGE_ROCKSDB;
    cfg.rocksdb_path = dir;
    cfg.max_slots = 16;
    cfg.max_shreds_per_slot = 64;

    const sol_slot_t slot = 43;
    const uint32_t last_index = 2;

    uint8_t payload0[16];
    uint8_t payload1[16];
    uint8_t payload2_orig[16];
    uint8_t payload2_conflict[16];
    memset(payload0, 0x10, sizeof(payload0));
    memset(payload1, 0x21, sizeof(payload1));
    memset(payload2_orig, 0x32, sizeof(payload2_orig));
    memset(payload2_conflict, 0x43, sizeof(payload2_conflict));

    uint8_t raw0[256];
    uint8_t raw1[256];
    uint8_t raw2[256];
    uint8_t raw2b[256];

    size_t len0 = build_mock_legacy_data_shred(raw0, sizeof(raw0),
                                               slot, 0,
                                               0, 0,
                                               0,
                                               payload0, sizeof(payload0));
    size_t len1 = build_mock_legacy_data_shred(raw1, sizeof(raw1),
                                               slot, 1,
                                               0, 0,
                                               0,
                                               payload1, sizeof(payload1));
    size_t len2 = build_mock_legacy_data_shred(raw2, sizeof(raw2),
                                               slot, last_index,
                                               0, 0,
                                               0,
                                               payload2_orig, sizeof(payload2_orig));
    size_t len2b = build_mock_legacy_data_shred(raw2b, sizeof(raw2b),
                                                slot, last_index,
                                                0, 0,
                                                SOL_SHRED_FLAG_LAST_IN_SLOT,
                                                payload2_conflict, sizeof(payload2_conflict));
    TEST_ASSERT(len0 > 0);
    TEST_ASSERT(len1 > 0);
    TEST_ASSERT(len2 > 0);
    TEST_ASSERT(len2b > 0);

    sol_shred_t shred;
    memset(&shred, 0, sizeof(shred));
    shred.slot = slot;
    shred.type = SOL_SHRED_TYPE_DATA;
    shred.header.data.parent_slot = slot - 1;

    sol_blockstore_t* bs1 = sol_blockstore_new(&cfg);
    TEST_ASSERT_NOT_NULL(bs1);

    shred.index = 0;
    shred.header.data.flags = 0;
    TEST_ASSERT_EQ(sol_blockstore_insert_shred(bs1, &shred, raw0, len0), SOL_OK);

    shred.index = 1;
    shred.header.data.flags = 0;
    TEST_ASSERT_EQ(sol_blockstore_insert_shred(bs1, &shred, raw1, len1), SOL_OK);

    shred.index = last_index;
    shred.header.data.flags = 0;
    TEST_ASSERT_EQ(sol_blockstore_insert_shred(bs1, &shred, raw2, len2), SOL_OK);

    shred.index = last_index;
    shred.header.data.flags = SOL_SHRED_FLAG_LAST_IN_SLOT;
    TEST_ASSERT_EQ(sol_blockstore_insert_shred(bs1, &shred, raw2b, len2b), SOL_OK);

    TEST_ASSERT_EQ(sol_blockstore_num_variants(bs1, slot), 2);
    TEST_ASSERT(sol_blockstore_is_slot_complete(bs1, slot));
    TEST_ASSERT(sol_blockstore_get_block_variant(bs1, slot, 0) == NULL);

    sol_block_t* b1 = sol_blockstore_get_block_variant(bs1, slot, 1);
    TEST_ASSERT_NOT_NULL(b1);
    sol_block_t* b1_disk = sol_blockstore_get_block_variant_rocksdb(bs1, slot, 1);
    TEST_ASSERT_NOT_NULL(b1_disk);

    uint8_t expected[64];
    size_t expected_len = sizeof(payload0) + sizeof(payload1) + sizeof(payload2_conflict);
    TEST_ASSERT(expected_len <= sizeof(expected));
    memcpy(expected, payload0, sizeof(payload0));
    memcpy(expected + sizeof(payload0), payload1, sizeof(payload1));
    memcpy(expected + sizeof(payload0) + sizeof(payload1), payload2_conflict, sizeof(payload2_conflict));

    TEST_ASSERT_EQ(b1->data_len, expected_len);
    TEST_ASSERT_MEM_EQ(b1->data, expected, expected_len);
    TEST_ASSERT_EQ(b1_disk->data_len, expected_len);
    TEST_ASSERT_MEM_EQ(b1_disk->data, expected, expected_len);

    sol_block_destroy(b1);
    sol_block_destroy(b1_disk);
    sol_blockstore_destroy(bs1);

    sol_blockstore_t* bs2 = sol_blockstore_new(&cfg);
    TEST_ASSERT_NOT_NULL(bs2);

    TEST_ASSERT_EQ(sol_blockstore_num_variants(bs2, slot), 2);
    TEST_ASSERT(sol_blockstore_is_slot_complete(bs2, slot));
    TEST_ASSERT(sol_blockstore_get_block_variant(bs2, slot, 0) == NULL);

    b1 = sol_blockstore_get_block_variant(bs2, slot, 1);
    TEST_ASSERT_NOT_NULL(b1);
    TEST_ASSERT_EQ(b1->data_len, expected_len);
    TEST_ASSERT_MEM_EQ(b1->data, expected, expected_len);

    sol_block_destroy(b1);
    sol_blockstore_destroy(bs2);
    remove_dir_recursive(dir);
#endif
}

/*
 * Test runner
 */
static test_case_t blockstore_tests[] = {
    TEST_CASE(blockstore_create_destroy),
    TEST_CASE(blockstore_create_null_config),
    TEST_CASE(blockstore_address_signature_index),
    TEST_CASE(blockstore_insert_single_shred),
    TEST_CASE(blockstore_insert_duplicate),
    TEST_CASE(blockstore_signature_only_difference_is_duplicate),
    TEST_CASE(blockstore_conflicting_data_shred_creates_variant),
    TEST_CASE(blockstore_variant_can_complete_without_primary_full),
    TEST_CASE(blockstore_conflicting_shred_forks_all_conflicting_variants),
    TEST_CASE(blockstore_insert_multiple_shreds),
    TEST_CASE(blockstore_slot_incomplete),
    TEST_CASE(blockstore_slot_complete_with_gaps),
    TEST_CASE(blockstore_slot_complete_then_extended),
    TEST_CASE(blockstore_fec_recovery_single_missing),
    TEST_CASE(blockstore_slot_meta),
    TEST_CASE(blockstore_slot_meta_not_found),
    TEST_CASE(blockstore_get_missing),
    TEST_CASE(blockstore_has_shred),
    TEST_CASE(blockstore_get_shred),
    TEST_CASE(blockstore_get_block),
    TEST_CASE(blockstore_get_block_incomplete),
    TEST_CASE(blockstore_set_rooted),
    TEST_CASE(blockstore_set_dead),
    TEST_CASE(blockstore_purge_slots),
    TEST_CASE(blockstore_stats),
    TEST_CASE(blockstore_callback),
    TEST_CASE(blockstore_null_handling),
    TEST_CASE(blockstore_rocksdb_persistence),
    TEST_CASE(blockstore_rocksdb_missing_shreds_without_cache),
    TEST_CASE(blockstore_rocksdb_lock_conflict_sets_errno),
    TEST_CASE(blockstore_rocksdb_variant_persistence),
};

int main(void) {
    int result = RUN_TESTS("Blockstore Tests", blockstore_tests);
    sol_alloc_dump_leaks();
    return result;
}
