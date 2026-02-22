/*
 * test_shred.c - Shred module unit tests
 */

#include "../test_framework.h"
#include "sol_shred.h"
#include "sol_alloc.h"
#include "sol_ed25519.h"
#include "sol_sha256.h"
#include <string.h>

/*
 * Test shred variant detection
 */

TEST(shred_variant_is_data_legacy) {
    TEST_ASSERT(sol_shred_variant_is_data(SOL_SHRED_VARIANT_LEGACY_DATA));
    TEST_ASSERT(!sol_shred_variant_is_code(SOL_SHRED_VARIANT_LEGACY_DATA));
    TEST_ASSERT(!sol_shred_variant_is_merkle(SOL_SHRED_VARIANT_LEGACY_DATA));
}

TEST(shred_variant_is_code_legacy) {
    TEST_ASSERT(!sol_shred_variant_is_data(SOL_SHRED_VARIANT_LEGACY_CODE));
    TEST_ASSERT(sol_shred_variant_is_code(SOL_SHRED_VARIANT_LEGACY_CODE));
    TEST_ASSERT(!sol_shred_variant_is_merkle(SOL_SHRED_VARIANT_LEGACY_CODE));
}

TEST(shred_variant_is_merkle_data) {
    /* 0x90 | proof_size */
    uint8_t variant = (uint8_t)(SOL_SHRED_VARIANT_MERKLE_DATA | 6u);
    TEST_ASSERT(sol_shred_variant_is_data(variant));
    TEST_ASSERT(sol_shred_variant_is_merkle(variant));
}

TEST(shred_variant_is_merkle_code) {
    /* 0x60 | proof_size */
    uint8_t variant = (uint8_t)(SOL_SHRED_VARIANT_MERKLE_CODE | 6u);
    TEST_ASSERT(sol_shred_variant_is_code(variant));
    TEST_ASSERT(sol_shred_variant_is_merkle(variant));
}

TEST(shred_variant_name) {
    TEST_ASSERT_STR_EQ(sol_shred_variant_name(SOL_SHRED_VARIANT_LEGACY_DATA),
                       "LegacyData");
    TEST_ASSERT_STR_EQ(sol_shred_variant_name(SOL_SHRED_VARIANT_LEGACY_CODE),
                       "LegacyCode");
    TEST_ASSERT_STR_EQ(sol_shred_variant_name((uint8_t)(SOL_SHRED_VARIANT_MERKLE_DATA | 6u)), "MerkleData");
    TEST_ASSERT_STR_EQ(sol_shred_variant_name((uint8_t)(SOL_SHRED_VARIANT_MERKLE_DATA_RESIGNED | 6u)), "MerkleDataResigned");
    TEST_ASSERT_STR_EQ(sol_shred_variant_name((uint8_t)(SOL_SHRED_VARIANT_MERKLE_CODE | 6u)), "MerkleCode");
    TEST_ASSERT_STR_EQ(sol_shred_variant_name((uint8_t)(SOL_SHRED_VARIANT_MERKLE_CODE_RESIGNED | 6u)), "MerkleCodeResigned");
}

/*
 * Test shred type name
 */

TEST(shred_type_name) {
    TEST_ASSERT_STR_EQ(sol_shred_type_name(SOL_SHRED_TYPE_DATA), "Data");
    TEST_ASSERT_STR_EQ(sol_shred_type_name(SOL_SHRED_TYPE_CODE), "Code");
}

/*
 * Test shred parse with mock data
 */

TEST(shred_parse_data) {
    /* Create a mock legacy data shred */
    uint8_t raw[256];
    memset(raw, 0, sizeof(raw));

    const size_t payload_len = 100;
    const size_t wire_len = SOL_SHRED_DATA_HEADERS_SIZE + payload_len;

    /* Set variant for legacy data */
    raw[64] = SOL_SHRED_VARIANT_LEGACY_DATA;

    /* Set slot (little endian) - slot 12345 */
    uint64_t slot = 12345;
    for (int i = 0; i < 8; i++) {
        raw[65 + i] = (slot >> (i * 8)) & 0xFF;
    }

    /* Set index - 42 */
    uint32_t index = 42;
    for (int i = 0; i < 4; i++) {
        raw[73 + i] = (index >> (i * 8)) & 0xFF;
    }

    /* Set version - 1 */
    raw[77] = 1;
    raw[78] = 0;

    /* Set FEC set index - 40 */
    raw[79] = 40;
    raw[80] = 0;
    raw[81] = 0;
    raw[82] = 0;

    /* Data shred header starts at 83 */
    /* Parent offset - 1 */
    raw[83] = 1;
    raw[84] = 0;

    /* Flags */
    raw[85] = SOL_SHRED_FLAG_DATA_COMPLETE;

    /* Size - total bytes (headers + data) */
    raw[86] = (uint8_t)(wire_len & 0xFFu);
    raw[87] = (uint8_t)((wire_len >> 8) & 0xFFu);

    /* Parse */
    sol_shred_t shred;
    sol_err_t err = sol_shred_parse(&shred, raw, wire_len);
    TEST_ASSERT_EQ(err, SOL_OK);

    TEST_ASSERT_EQ(shred.type, SOL_SHRED_TYPE_DATA);
    TEST_ASSERT_EQ(shred.variant, SOL_SHRED_VARIANT_LEGACY_DATA);
    TEST_ASSERT_EQ(shred.slot, 12345);
    TEST_ASSERT_EQ(shred.index, 42);
    TEST_ASSERT_EQ(shred.version, 1);
    TEST_ASSERT_EQ(shred.fec_set_index, 40);
    TEST_ASSERT_EQ(shred.header.data.parent_slot, 12344);  /* slot - offset */
    TEST_ASSERT_EQ(shred.header.data.flags, SOL_SHRED_FLAG_DATA_COMPLETE);
    TEST_ASSERT_EQ(shred.header.data.size, wire_len);
    TEST_ASSERT_EQ(shred.payload_len, payload_len);
    TEST_ASSERT(!shred.has_merkle);
}

static size_t
merkle_data_capacity(uint8_t proof_size, bool resigned) {
    size_t fixed = (size_t)SOL_SHRED_DATA_HEADERS_SIZE + (size_t)SOL_SHRED_MERKLE_ROOT_SIZE +
                   (size_t)proof_size * (size_t)SOL_SHRED_MERKLE_PROOF_ENTRY_SIZE +
                   (resigned ? (size_t)SOL_SIGNATURE_SIZE : 0u);
    if (fixed > (size_t)SOL_SHRED_DATA_PAYLOAD_SIZE) return 0;
    return (size_t)SOL_SHRED_DATA_PAYLOAD_SIZE - fixed;
}

static void
merkle_hash_leaf(const uint8_t* shred, size_t proof_off, sol_hash_t* out) {
    static const uint8_t MERKLE_HASH_PREFIX_LEAF[] = "\x00SOLANA_MERKLE_SHREDS_LEAF";
    const size_t prefix_len = sizeof(MERKLE_HASH_PREFIX_LEAF) - 1u;

    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    sol_sha256_update(&ctx, MERKLE_HASH_PREFIX_LEAF, prefix_len);
    sol_sha256_update(&ctx, shred + SOL_SIGNATURE_SIZE, proof_off - SOL_SIGNATURE_SIZE);
    sol_sha256_t digest;
    sol_sha256_final(&ctx, &digest);
    memcpy(out->bytes, digest.bytes, SOL_SHRED_MERKLE_ROOT_SIZE);
}

static void
merkle_hash_node(const sol_hash_t* left, const sol_hash_t* right, sol_hash_t* out) {
    static const uint8_t MERKLE_HASH_PREFIX_NODE[] = "\x01SOLANA_MERKLE_SHREDS_NODE";
    const size_t prefix_len = sizeof(MERKLE_HASH_PREFIX_NODE) - 1u;

    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    sol_sha256_update(&ctx, MERKLE_HASH_PREFIX_NODE, prefix_len);
    sol_sha256_update(&ctx, left->bytes, SOL_SHRED_MERKLE_PROOF_ENTRY_SIZE);
    sol_sha256_update(&ctx, right->bytes, SOL_SHRED_MERKLE_PROOF_ENTRY_SIZE);
    sol_sha256_t digest;
    sol_sha256_final(&ctx, &digest);
    memcpy(out->bytes, digest.bytes, SOL_SHRED_MERKLE_ROOT_SIZE);
}

TEST(shred_parse_merkle_data_proof0_and_verify) {
    sol_keypair_t leader_kp;
    TEST_ASSERT_EQ(sol_ed25519_keypair_generate(&leader_kp), SOL_OK);

    sol_pubkey_t leader_pk;
    sol_ed25519_pubkey_from_keypair(&leader_kp, &leader_pk);

    uint8_t raw[SOL_SHRED_DATA_PAYLOAD_SIZE];
    memset(raw, 0, sizeof(raw));

    uint8_t proof_size = 0;
    bool resigned = false;
    size_t cap = merkle_data_capacity(proof_size, resigned);
    TEST_ASSERT(cap > 0);
    size_t chain_off = (size_t)SOL_SHRED_DATA_HEADERS_SIZE + cap;
    size_t proof_off = chain_off + (size_t)SOL_SHRED_MERKLE_ROOT_SIZE;
    TEST_ASSERT_EQ(proof_off, (size_t)SOL_SHRED_DATA_PAYLOAD_SIZE);

    raw[64] = (uint8_t)(SOL_SHRED_VARIANT_MERKLE_DATA | proof_size);

    uint64_t slot = 4242;
    for (int i = 0; i < 8; i++) raw[65 + i] = (uint8_t)((slot >> (i * 8)) & 0xFFu);

    uint32_t index = 0;
    for (int i = 0; i < 4; i++) raw[73 + i] = (uint8_t)((index >> (i * 8)) & 0xFFu);

    raw[77] = 1;
    raw[78] = 0;

    /* fec_set_index = 0 */
    memset(raw + 79, 0, 4);

    /* Data header at offset 83 */
    raw[83] = 1; /* parent_offset=1 */
    raw[84] = 0;
    raw[85] = SOL_SHRED_FLAG_DATA_COMPLETE;

    const uint16_t data_len = 16;
    const uint16_t total_size = (uint16_t)(SOL_SHRED_DATA_HEADERS_SIZE + data_len);
    raw[86] = (uint8_t)(total_size & 0xFFu);
    raw[87] = (uint8_t)((total_size >> 8) & 0xFFu);

    for (size_t i = 0; i < data_len; i++) raw[SOL_SHRED_DATA_HEADERS_SIZE + i] = (uint8_t)(0xC0u + (uint8_t)i);

    memset(raw + chain_off, 0x11, SOL_SHRED_MERKLE_ROOT_SIZE);

    sol_hash_t leaf = {0};
    merkle_hash_leaf(raw, proof_off, &leaf);

    sol_signature_t sig;
    sol_ed25519_sign(&leader_kp, leaf.bytes, SOL_SHRED_MERKLE_ROOT_SIZE, &sig);
    memcpy(raw, sig.bytes, SOL_SIGNATURE_SIZE);

    sol_shred_t shred;
    TEST_ASSERT_EQ(sol_shred_parse(&shred, raw, sizeof(raw)), SOL_OK);
    TEST_ASSERT(shred.has_merkle);
    TEST_ASSERT_EQ(shred.merkle_proof_size, proof_size);
    TEST_ASSERT(!shred.resigned);

    sol_hash_t merkle_root = {0};
    TEST_ASSERT(sol_shred_verify_merkle(&shred, &merkle_root));
    TEST_ASSERT_MEM_EQ(merkle_root.bytes, leaf.bytes, SOL_SHRED_MERKLE_ROOT_SIZE);
    TEST_ASSERT(sol_shred_verify(&shred, &leader_pk));

    /* Tamper with leaf data: the computed merkle root changes and signature verification fails. */
    raw[SOL_SHRED_DATA_HEADERS_SIZE] ^= 0x01u;
    TEST_ASSERT_EQ(sol_shred_parse(&shred, raw, sizeof(raw)), SOL_OK);
    sol_hash_t tampered_root = {0};
    TEST_ASSERT(sol_shred_verify_merkle(&shred, &tampered_root));
    TEST_ASSERT(memcmp(tampered_root.bytes, leaf.bytes, SOL_SHRED_MERKLE_ROOT_SIZE) != 0);
    TEST_ASSERT(!sol_shred_verify(&shred, &leader_pk));
}

TEST(shred_parse_merkle_data_proof1_two_shreds_and_verify) {
    sol_keypair_t leader_kp;
    TEST_ASSERT_EQ(sol_ed25519_keypair_generate(&leader_kp), SOL_OK);

    sol_pubkey_t leader_pk;
    sol_ed25519_pubkey_from_keypair(&leader_kp, &leader_pk);

    uint8_t proof_size = 1;
    bool resigned = false;
    size_t cap = merkle_data_capacity(proof_size, resigned);
    TEST_ASSERT(cap > 0);
    size_t chain_off = (size_t)SOL_SHRED_DATA_HEADERS_SIZE + cap;
    size_t proof_off = chain_off + (size_t)SOL_SHRED_MERKLE_ROOT_SIZE;
    size_t proof_bytes = (size_t)proof_size * (size_t)SOL_SHRED_MERKLE_PROOF_ENTRY_SIZE;
    TEST_ASSERT_EQ(proof_off + proof_bytes, (size_t)SOL_SHRED_DATA_PAYLOAD_SIZE);

    uint8_t raw0[SOL_SHRED_DATA_PAYLOAD_SIZE];
    uint8_t raw1[SOL_SHRED_DATA_PAYLOAD_SIZE];
    memset(raw0, 0, sizeof(raw0));
    memset(raw1, 0, sizeof(raw1));

    raw0[64] = (uint8_t)(SOL_SHRED_VARIANT_MERKLE_DATA | proof_size);
    raw1[64] = (uint8_t)(SOL_SHRED_VARIANT_MERKLE_DATA | proof_size);

    uint64_t slot = 9001;
    for (int i = 0; i < 8; i++) {
        raw0[65 + i] = (uint8_t)((slot >> (i * 8)) & 0xFFu);
        raw1[65 + i] = (uint8_t)((slot >> (i * 8)) & 0xFFu);
    }

    uint32_t index0 = 0;
    uint32_t index1 = 1;
    for (int i = 0; i < 4; i++) {
        raw0[73 + i] = (uint8_t)((index0 >> (i * 8)) & 0xFFu);
        raw1[73 + i] = (uint8_t)((index1 >> (i * 8)) & 0xFFu);
    }

    raw0[77] = 1;
    raw0[78] = 0;
    raw1[77] = 1;
    raw1[78] = 0;

    /* fec_set_index = 0 */
    memset(raw0 + 79, 0, 4);
    memset(raw1 + 79, 0, 4);

    /* Data header at offset 83 */
    raw0[83] = 1;
    raw0[84] = 0;
    raw0[85] = 0;
    raw1[83] = 1;
    raw1[84] = 0;
    raw1[85] = 0;

    const uint16_t data_len = 8;
    const uint16_t total_size = (uint16_t)(SOL_SHRED_DATA_HEADERS_SIZE + data_len);
    raw0[86] = (uint8_t)(total_size & 0xFFu);
    raw0[87] = (uint8_t)((total_size >> 8) & 0xFFu);
    raw1[86] = (uint8_t)(total_size & 0xFFu);
    raw1[87] = (uint8_t)((total_size >> 8) & 0xFFu);

    for (size_t i = 0; i < data_len; i++) {
        raw0[SOL_SHRED_DATA_HEADERS_SIZE + i] = (uint8_t)(0x10u + (uint8_t)i);
        raw1[SOL_SHRED_DATA_HEADERS_SIZE + i] = (uint8_t)(0x80u + (uint8_t)i);
    }

    memset(raw0 + chain_off, 0x22, SOL_SHRED_MERKLE_ROOT_SIZE);
    memset(raw1 + chain_off, 0x22, SOL_SHRED_MERKLE_ROOT_SIZE);

    sol_hash_t leaf0 = {0};
    sol_hash_t leaf1 = {0};
    merkle_hash_leaf(raw0, proof_off, &leaf0);
    merkle_hash_leaf(raw1, proof_off, &leaf1);

    sol_hash_t root = {0};
    merkle_hash_node(&leaf0, &leaf1, &root);

    memcpy(raw0 + proof_off, leaf1.bytes, SOL_SHRED_MERKLE_PROOF_ENTRY_SIZE);
    memcpy(raw1 + proof_off, leaf0.bytes, SOL_SHRED_MERKLE_PROOF_ENTRY_SIZE);

    sol_signature_t sig;
    sol_ed25519_sign(&leader_kp, root.bytes, SOL_SHRED_MERKLE_ROOT_SIZE, &sig);
    memcpy(raw0, sig.bytes, SOL_SIGNATURE_SIZE);
    memcpy(raw1, sig.bytes, SOL_SIGNATURE_SIZE);

    sol_shred_t shred0;
    sol_shred_t shred1;
    TEST_ASSERT_EQ(sol_shred_parse(&shred0, raw0, sizeof(raw0)), SOL_OK);
    TEST_ASSERT_EQ(sol_shred_parse(&shred1, raw1, sizeof(raw1)), SOL_OK);

    sol_hash_t out0 = {0};
    sol_hash_t out1 = {0};
    TEST_ASSERT(sol_shred_verify_merkle(&shred0, &out0));
    TEST_ASSERT(sol_shred_verify_merkle(&shred1, &out1));
    TEST_ASSERT_MEM_EQ(out0.bytes, root.bytes, SOL_SHRED_MERKLE_ROOT_SIZE);
    TEST_ASSERT_MEM_EQ(out1.bytes, root.bytes, SOL_SHRED_MERKLE_ROOT_SIZE);
    TEST_ASSERT(sol_shred_verify(&shred0, &leader_pk));
    TEST_ASSERT(sol_shred_verify(&shred1, &leader_pk));

    /* Tamper with proof entry: signature verification should fail. */
    raw1[proof_off] ^= 0x01u;
    TEST_ASSERT_EQ(sol_shred_parse(&shred1, raw1, sizeof(raw1)), SOL_OK);
    sol_hash_t tampered_root = {0};
    TEST_ASSERT(sol_shred_verify_merkle(&shred1, &tampered_root));
    TEST_ASSERT(!sol_hash_eq(&tampered_root, &root));
    TEST_ASSERT(!sol_shred_verify(&shred1, &leader_pk));
}

TEST(shred_parse_respects_data_size_with_padding) {
    sol_keypair_t leader_kp;
    TEST_ASSERT_EQ(sol_ed25519_keypair_generate(&leader_kp), SOL_OK);

    sol_pubkey_t leader_pk;
    sol_ed25519_pubkey_from_keypair(&leader_kp, &leader_pk);

    uint8_t raw[SOL_SHRED_SIZE];
    memset(raw, 0, sizeof(raw));

    /* Legacy data shred. */
    raw[64] = SOL_SHRED_VARIANT_LEGACY_DATA;

    /* Slot (8 bytes LE) */
    uint64_t slot = 424242;
    for (int i = 0; i < 8; i++) {
        raw[65 + i] = (uint8_t)((slot >> (i * 8)) & 0xFFu);
    }

    /* Index (4 bytes LE) */
    uint32_t index = 7;
    for (int i = 0; i < 4; i++) {
        raw[73 + i] = (uint8_t)((index >> (i * 8)) & 0xFFu);
    }

    /* Version (2 bytes LE) */
    raw[77] = 1;
    raw[78] = 0;

    /* FEC set index (4 bytes LE) */
    raw[79] = 0;
    raw[80] = 0;
    raw[81] = 0;
    raw[82] = 0;

    /* Data header at offset 83 */
    raw[83] = 1; /* parent_offset=1 */
    raw[84] = 0;
    raw[85] = (uint8_t)(SOL_SHRED_FLAG_DATA_COMPLETE | SOL_SHRED_FLAG_LAST_IN_SLOT);

    uint16_t data_size = 16;
    uint16_t total_size = (uint16_t)(SOL_SHRED_DATA_HEADERS_SIZE + data_size);
    raw[86] = (uint8_t)(total_size & 0xFFu);
    raw[87] = (uint8_t)((total_size >> 8) & 0xFFu);

    uint8_t payload[16];
    for (size_t i = 0; i < sizeof(payload); i++) {
        payload[i] = (uint8_t)(0xD0u + (uint8_t)i);
    }

    size_t payload_off = SOL_SHRED_HEADER_SIZE + SOL_SHRED_DATA_HEADER_SIZE;
    memcpy(raw + payload_off, payload, sizeof(payload));

    /* Sign fixed-size shred (everything after signature). */
    sol_signature_t sig;
    const uint8_t* msg = raw + SOL_SIGNATURE_SIZE;
    size_t msg_len = sizeof(raw) - SOL_SIGNATURE_SIZE;
    sol_ed25519_sign(&leader_kp, msg, msg_len, &sig);
    memcpy(raw, sig.bytes, SOL_SIGNATURE_SIZE);

    sol_shred_t shred;
    TEST_ASSERT_EQ(sol_shred_parse(&shred, raw, sizeof(raw)), SOL_OK);
    TEST_ASSERT_EQ(shred.type, SOL_SHRED_TYPE_DATA);
    TEST_ASSERT_EQ(shred.slot, slot);
    TEST_ASSERT_EQ(shred.index, index);
    TEST_ASSERT_EQ(shred.header.data.parent_slot, slot - 1);
    TEST_ASSERT_EQ(shred.header.data.size, total_size);
    TEST_ASSERT_EQ(shred.payload_len, (size_t)data_size);
    TEST_ASSERT(memcmp(shred.payload, payload, sizeof(payload)) == 0);
    TEST_ASSERT(sol_shred_verify(&shred, &leader_pk));
}

TEST(shred_parse_code) {
    /* Create a mock legacy code shred */
    uint8_t raw[256];
    memset(raw, 0, sizeof(raw));

    /* Set variant for legacy code */
    raw[64] = SOL_SHRED_VARIANT_LEGACY_CODE;

    /* Set slot */
    uint64_t slot = 9999;
    for (int i = 0; i < 8; i++) {
        raw[65 + i] = (slot >> (i * 8)) & 0xFF;
    }

    /* Set index - 100 */
    raw[73] = 100;
    raw[74] = 0;
    raw[75] = 0;
    raw[76] = 0;

    /* Set version - 2 */
    raw[77] = 2;
    raw[78] = 0;

    /* Set FEC set index */
    raw[79] = 96;
    raw[80] = 0;
    raw[81] = 0;
    raw[82] = 0;

    /* Code shred header starts at 83 */
    /* num_data_shreds - 32 */
    raw[83] = 32;
    raw[84] = 0;

    /* num_code_shreds - 32 */
    raw[85] = 32;
    raw[86] = 0;

    /* position - 4 */
    raw[87] = 4;
    raw[88] = 0;

    /* Parse */
    sol_shred_t shred;
    sol_err_t err = sol_shred_parse(&shred, raw, sizeof(raw));
    TEST_ASSERT_EQ(err, SOL_OK);

    TEST_ASSERT_EQ(shred.type, SOL_SHRED_TYPE_CODE);
    TEST_ASSERT_EQ(shred.slot, 9999);
    TEST_ASSERT_EQ(shred.index, 100);
    TEST_ASSERT_EQ(shred.version, 2);
    TEST_ASSERT_EQ(shred.header.code.num_data_shreds, 32);
    TEST_ASSERT_EQ(shred.header.code.num_code_shreds, 32);
    TEST_ASSERT_EQ(shred.header.code.position, 4);
}

TEST(shred_parse_null) {
    sol_shred_t shred;
    TEST_ASSERT_EQ(sol_shred_parse(&shred, NULL, 0), SOL_ERR_INVAL);
    TEST_ASSERT_EQ(sol_shred_parse(NULL, (uint8_t*)"test", 4), SOL_ERR_INVAL);
}

TEST(shred_parse_too_small) {
    uint8_t raw[50];  /* Too small for header */
    memset(raw, 0, sizeof(raw));

    sol_shred_t shred;
    TEST_ASSERT_EQ(sol_shred_parse(&shred, raw, sizeof(raw)), SOL_ERR_TRUNCATED);
}

TEST(shred_build_legacy_data_signed) {
    sol_keypair_t leader_kp;
    TEST_ASSERT_EQ(sol_ed25519_keypair_generate(&leader_kp), SOL_OK);

    sol_pubkey_t leader_pk;
    sol_ed25519_pubkey_from_keypair(&leader_kp, &leader_pk);

    uint8_t payload[32];
    for (size_t i = 0; i < sizeof(payload); i++) {
        payload[i] = (uint8_t)(0xA0u + (uint8_t)i);
    }

    uint8_t raw[256];
    size_t written = 0;

    sol_err_t err = sol_shred_build_legacy_data(
        &leader_kp,
        100, /* slot */
        99,  /* parent_slot */
        5,   /* index */
        1,   /* version */
        0,   /* fec_set_index */
        SOL_SHRED_FLAG_DATA_COMPLETE,
        payload,
        sizeof(payload),
        raw,
        sizeof(raw),
        &written
    );
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT(written > 0);

    sol_shred_t shred;
    TEST_ASSERT_EQ(sol_shred_parse(&shred, raw, written), SOL_OK);

    TEST_ASSERT_EQ(shred.type, SOL_SHRED_TYPE_DATA);
    TEST_ASSERT_EQ(shred.slot, 100);
    TEST_ASSERT_EQ(shred.index, 5);
    TEST_ASSERT_EQ(shred.version, 1);
    TEST_ASSERT_EQ(shred.fec_set_index, 0);
    TEST_ASSERT_EQ(shred.header.data.parent_slot, 99);
    TEST_ASSERT_EQ(shred.header.data.flags, SOL_SHRED_FLAG_DATA_COMPLETE);
    TEST_ASSERT_EQ(shred.header.data.size, (uint16_t)(SOL_SHRED_DATA_HEADERS_SIZE + sizeof(payload)));
    TEST_ASSERT_EQ(shred.payload_len, sizeof(payload));
    TEST_ASSERT(memcmp(shred.payload, payload, sizeof(payload)) == 0);

    TEST_ASSERT(sol_shred_verify(&shred, &leader_pk));
}

/*
 * Test FEC set
 */

TEST(fec_set_create_destroy) {
    sol_fec_set_t* fec = sol_fec_set_new(1000, 0, 32, 32);
    TEST_ASSERT(fec != NULL);
    TEST_ASSERT_EQ(fec->slot, 1000);
    TEST_ASSERT_EQ(fec->fec_set_index, 0);
    TEST_ASSERT_EQ(fec->num_data, 32);
    TEST_ASSERT_EQ(fec->num_code, 32);
    TEST_ASSERT_EQ(fec->data_received, 0);
    TEST_ASSERT_EQ(fec->code_received, 0);
    TEST_ASSERT(!fec->can_recover);

    sol_fec_set_destroy(fec);
}

TEST(fec_set_can_recover) {
    sol_fec_set_t* fec = sol_fec_set_new(1000, 0, 32, 32);
    TEST_ASSERT(fec != NULL);

    /* With no shreds, cannot recover */
    TEST_ASSERT(!sol_fec_set_can_recover(fec));

    /* Simulate receiving enough shreds */
    fec->data_received = 30;
    fec->code_received = 2;
    TEST_ASSERT(sol_fec_set_can_recover(fec));  /* 32 total >= 32 needed */

    fec->data_received = 31;
    fec->code_received = 0;
    TEST_ASSERT(!sol_fec_set_can_recover(fec));  /* 31 < 32 needed */

    sol_fec_set_destroy(fec);
}

TEST(shred_key_from_shred) {
    sol_shred_t shred;
    memset(&shred, 0, sizeof(shred));
    shred.slot = 12345;
    shred.index = 42;
    shred.type = SOL_SHRED_TYPE_DATA;

    sol_shred_key_t key;
    sol_shred_key_from_shred(&key, &shred);

    TEST_ASSERT_EQ(key.slot, 12345);
    TEST_ASSERT_EQ(key.index, 42);
    TEST_ASSERT(key.is_data);
}

TEST(shred_is_last_data) {
    sol_shred_t shred;
    memset(&shred, 0, sizeof(shred));

    /* Not a data shred */
    shred.type = SOL_SHRED_TYPE_CODE;
    TEST_ASSERT(!sol_shred_is_last_data(&shred));

    /* Data shred without flag */
    shred.type = SOL_SHRED_TYPE_DATA;
    shred.header.data.flags = 0;
    TEST_ASSERT(!sol_shred_is_last_data(&shred));

    /* Data shred with flag */
    shred.header.data.flags = SOL_SHRED_FLAG_DATA_COMPLETE;
    TEST_ASSERT(sol_shred_is_last_data(&shred));
}

/*
 * Test runner
 */
static test_case_t shred_tests[] = {
    TEST_CASE(shred_variant_is_data_legacy),
    TEST_CASE(shred_variant_is_code_legacy),
    TEST_CASE(shred_variant_is_merkle_data),
    TEST_CASE(shred_variant_is_merkle_code),
    TEST_CASE(shred_variant_name),
    TEST_CASE(shred_type_name),
    TEST_CASE(shred_parse_data),
    TEST_CASE(shred_parse_merkle_data_proof0_and_verify),
    TEST_CASE(shred_parse_merkle_data_proof1_two_shreds_and_verify),
    TEST_CASE(shred_parse_respects_data_size_with_padding),
    TEST_CASE(shred_parse_code),
    TEST_CASE(shred_parse_null),
    TEST_CASE(shred_parse_too_small),
    TEST_CASE(shred_build_legacy_data_signed),
    TEST_CASE(fec_set_create_destroy),
    TEST_CASE(fec_set_can_recover),
    TEST_CASE(shred_key_from_shred),
    TEST_CASE(shred_is_last_data),
};

int main(void) {
    int result = RUN_TESTS("Shred Tests", shred_tests);
    sol_alloc_dump_leaks();
    return result;
}
