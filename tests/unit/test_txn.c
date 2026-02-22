/*
 * test_txn.c - Transaction module unit tests
 *
 * Tests bincode serialization, pubkey/signature base58, message parsing,
 * and transaction handling.
 */

#include "../test_framework.h"
#include "sol_bincode.h"
#include "sol_pubkey.h"
#include "sol_signature.h"
#include "sol_instruction.h"
#include "sol_message.h"
#include "sol_transaction.h"
#include "sol_alloc.h"
#include <string.h>

/*
 * Bincode encoding/decoding tests
 */

TEST(bincode_u8) {
    uint8_t buf[16];
    sol_encoder_t enc;
    sol_decoder_t dec;

    sol_encoder_init(&enc, buf, sizeof(buf));
    TEST_ASSERT_EQ(sol_encode_u8(&enc, 0x42), SOL_OK);
    TEST_ASSERT_EQ(sol_encoder_len(&enc), 1);
    TEST_ASSERT_EQ(buf[0], 0x42);

    sol_decoder_init(&dec, buf, sol_encoder_len(&enc));
    uint8_t val;
    TEST_ASSERT_EQ(sol_decode_u8(&dec, &val), SOL_OK);
    TEST_ASSERT_EQ(val, 0x42);
}

TEST(bincode_u16) {
    uint8_t buf[16];
    sol_encoder_t enc;
    sol_decoder_t dec;

    sol_encoder_init(&enc, buf, sizeof(buf));
    TEST_ASSERT_EQ(sol_encode_u16(&enc, 0x1234), SOL_OK);
    TEST_ASSERT_EQ(sol_encoder_len(&enc), 2);
    /* Little-endian: low byte first */
    TEST_ASSERT_EQ(buf[0], 0x34);
    TEST_ASSERT_EQ(buf[1], 0x12);

    sol_decoder_init(&dec, buf, sol_encoder_len(&enc));
    uint16_t val;
    TEST_ASSERT_EQ(sol_decode_u16(&dec, &val), SOL_OK);
    TEST_ASSERT_EQ(val, 0x1234);
}

TEST(bincode_u32) {
    uint8_t buf[16];
    sol_encoder_t enc;
    sol_decoder_t dec;

    sol_encoder_init(&enc, buf, sizeof(buf));
    TEST_ASSERT_EQ(sol_encode_u32(&enc, 0x12345678), SOL_OK);
    TEST_ASSERT_EQ(sol_encoder_len(&enc), 4);
    /* Little-endian */
    TEST_ASSERT_EQ(buf[0], 0x78);
    TEST_ASSERT_EQ(buf[1], 0x56);
    TEST_ASSERT_EQ(buf[2], 0x34);
    TEST_ASSERT_EQ(buf[3], 0x12);

    sol_decoder_init(&dec, buf, sol_encoder_len(&enc));
    uint32_t val;
    TEST_ASSERT_EQ(sol_decode_u32(&dec, &val), SOL_OK);
    TEST_ASSERT_EQ(val, 0x12345678);
}

TEST(bincode_u64) {
    uint8_t buf[16];
    sol_encoder_t enc;
    sol_decoder_t dec;

    sol_encoder_init(&enc, buf, sizeof(buf));
    TEST_ASSERT_EQ(sol_encode_u64(&enc, 0x123456789ABCDEF0ULL), SOL_OK);
    TEST_ASSERT_EQ(sol_encoder_len(&enc), 8);

    sol_decoder_init(&dec, buf, sol_encoder_len(&enc));
    uint64_t val;
    TEST_ASSERT_EQ(sol_decode_u64(&dec, &val), SOL_OK);
    TEST_ASSERT_EQ(val, 0x123456789ABCDEF0ULL);
}

TEST(bincode_compact_u16_small) {
    /* Values < 0x80 use 1 byte */
    uint8_t buf[16];
    sol_encoder_t enc;
    sol_decoder_t dec;

    sol_encoder_init(&enc, buf, sizeof(buf));
    TEST_ASSERT_EQ(sol_encode_compact_u16(&enc, 0x7F), SOL_OK);
    TEST_ASSERT_EQ(sol_encoder_len(&enc), 1);
    TEST_ASSERT_EQ(buf[0], 0x7F);

    sol_decoder_init(&dec, buf, sol_encoder_len(&enc));
    uint16_t val;
    TEST_ASSERT_EQ(sol_decode_compact_u16(&dec, &val), SOL_OK);
    TEST_ASSERT_EQ(val, 0x7F);
}

TEST(bincode_compact_u16_medium) {
    /* Values 0x80-0x3FFF use 2 bytes */
    uint8_t buf[16];
    sol_encoder_t enc;
    sol_decoder_t dec;

    sol_encoder_init(&enc, buf, sizeof(buf));
    TEST_ASSERT_EQ(sol_encode_compact_u16(&enc, 0x80), SOL_OK);
    TEST_ASSERT_EQ(sol_encoder_len(&enc), 2);

    sol_decoder_init(&dec, buf, sol_encoder_len(&enc));
    uint16_t val;
    TEST_ASSERT_EQ(sol_decode_compact_u16(&dec, &val), SOL_OK);
    TEST_ASSERT_EQ(val, 0x80);

    /* Test larger 2-byte value */
    sol_encoder_init(&enc, buf, sizeof(buf));
    TEST_ASSERT_EQ(sol_encode_compact_u16(&enc, 0x3FFF), SOL_OK);
    TEST_ASSERT_EQ(sol_encoder_len(&enc), 2);

    sol_decoder_init(&dec, buf, sol_encoder_len(&enc));
    TEST_ASSERT_EQ(sol_decode_compact_u16(&dec, &val), SOL_OK);
    TEST_ASSERT_EQ(val, 0x3FFF);
}

TEST(bincode_compact_u16_large) {
    /* Values 0x4000-0xFFFF use 3 bytes */
    uint8_t buf[16];
    sol_encoder_t enc;
    sol_decoder_t dec;

    sol_encoder_init(&enc, buf, sizeof(buf));
    TEST_ASSERT_EQ(sol_encode_compact_u16(&enc, 0x4000), SOL_OK);
    TEST_ASSERT_EQ(sol_encoder_len(&enc), 3);

    sol_decoder_init(&dec, buf, sol_encoder_len(&enc));
    uint16_t val;
    TEST_ASSERT_EQ(sol_decode_compact_u16(&dec, &val), SOL_OK);
    TEST_ASSERT_EQ(val, 0x4000);

    /* Test maximum value */
    sol_encoder_init(&enc, buf, sizeof(buf));
    TEST_ASSERT_EQ(sol_encode_compact_u16(&enc, 0xFFFF), SOL_OK);
    TEST_ASSERT_EQ(sol_encoder_len(&enc), 3);

    sol_decoder_init(&dec, buf, sol_encoder_len(&enc));
    TEST_ASSERT_EQ(sol_decode_compact_u16(&dec, &val), SOL_OK);
    TEST_ASSERT_EQ(val, 0xFFFF);
}

TEST(bincode_decode_underflow) {
    /* Test decoding with insufficient data */
    uint8_t buf[1] = {0};
    sol_decoder_t dec;

    sol_decoder_init(&dec, buf, 1);
    uint16_t val16;
    TEST_ASSERT_EQ(sol_decode_u16(&dec, &val16), SOL_ERR_DECODE);

    sol_decoder_init(&dec, buf, 1);
    uint32_t val32;
    TEST_ASSERT_EQ(sol_decode_u32(&dec, &val32), SOL_ERR_DECODE);
}

/*
 * Pubkey tests
 */

TEST(pubkey_zero) {
    sol_pubkey_t pk;
    sol_pubkey_init(&pk);
    TEST_ASSERT(sol_pubkey_is_zero(&pk));

    pk.bytes[0] = 1;
    TEST_ASSERT(!sol_pubkey_is_zero(&pk));
}

TEST(pubkey_eq) {
    sol_pubkey_t pk1 = {{0}};
    sol_pubkey_t pk2 = {{0}};

    TEST_ASSERT(sol_pubkey_eq(&pk1, &pk2));

    pk1.bytes[0] = 1;
    TEST_ASSERT(!sol_pubkey_eq(&pk1, &pk2));
}

TEST(pubkey_cmp) {
    sol_pubkey_t pk1 = {{0}};
    sol_pubkey_t pk2 = {{0}};

    TEST_ASSERT_EQ(sol_pubkey_cmp(&pk1, &pk2), 0);

    pk1.bytes[0] = 1;
    TEST_ASSERT(sol_pubkey_cmp(&pk1, &pk2) > 0);
    TEST_ASSERT(sol_pubkey_cmp(&pk2, &pk1) < 0);
}

TEST(pubkey_copy) {
    sol_pubkey_t pk1;
    for (int i = 0; i < 32; i++) pk1.bytes[i] = (uint8_t)i;

    sol_pubkey_t pk2;
    sol_pubkey_copy(&pk2, &pk1);
    TEST_ASSERT(sol_pubkey_eq(&pk1, &pk2));
}

TEST(pubkey_base58_roundtrip) {
    /* Test with a known pubkey */
    sol_pubkey_t pk;
    for (int i = 0; i < 32; i++) pk.bytes[i] = (uint8_t)(i + 1);

    char base58[SOL_PUBKEY_BASE58_LEN];
    TEST_ASSERT_EQ(sol_pubkey_to_base58(&pk, base58, sizeof(base58)), SOL_OK);

    sol_pubkey_t pk2;
    TEST_ASSERT_EQ(sol_pubkey_from_base58(base58, &pk2), SOL_OK);

    TEST_ASSERT(sol_pubkey_eq(&pk, &pk2));
}

TEST(pubkey_base58_known) {
    /* System program ID should be all zeros -> "11111111111111111111111111111111" */
    char base58[SOL_PUBKEY_BASE58_LEN];
    TEST_ASSERT_EQ(sol_pubkey_to_base58(&SOL_SYSTEM_PROGRAM_ID, base58, sizeof(base58)), SOL_OK);
    TEST_ASSERT_STR_EQ(base58, "11111111111111111111111111111111");
}

TEST(pubkey_bincode) {
    sol_pubkey_t pk;
    for (int i = 0; i < 32; i++) pk.bytes[i] = (uint8_t)(255 - i);

    uint8_t buf[64];
    sol_encoder_t enc;
    sol_encoder_init(&enc, buf, sizeof(buf));
    TEST_ASSERT_EQ(sol_pubkey_encode(&enc, &pk), SOL_OK);
    TEST_ASSERT_EQ(sol_encoder_len(&enc), 32);

    sol_decoder_t dec;
    sol_decoder_init(&dec, buf, sol_encoder_len(&enc));
    sol_pubkey_t pk2;
    TEST_ASSERT_EQ(sol_pubkey_decode(&dec, &pk2), SOL_OK);
    TEST_ASSERT(sol_pubkey_eq(&pk, &pk2));
}

/*
 * Signature tests
 */

TEST(signature_zero) {
    sol_signature_t sig;
    sol_signature_init(&sig);
    TEST_ASSERT(sol_signature_is_zero(&sig));

    sig.bytes[0] = 1;
    TEST_ASSERT(!sol_signature_is_zero(&sig));
}

TEST(signature_eq) {
    sol_signature_t sig1 = {{0}};
    sol_signature_t sig2 = {{0}};

    TEST_ASSERT(sol_signature_eq(&sig1, &sig2));

    sig1.bytes[63] = 1;
    TEST_ASSERT(!sol_signature_eq(&sig1, &sig2));
}

TEST(signature_bincode) {
    sol_signature_t sig;
    for (int i = 0; i < 64; i++) sig.bytes[i] = (uint8_t)i;

    uint8_t buf[128];
    sol_encoder_t enc;
    sol_encoder_init(&enc, buf, sizeof(buf));
    TEST_ASSERT_EQ(sol_signature_encode(&enc, &sig), SOL_OK);
    TEST_ASSERT_EQ(sol_encoder_len(&enc), 64);

    sol_decoder_t dec;
    sol_decoder_init(&dec, buf, sol_encoder_len(&enc));
    sol_signature_t sig2;
    TEST_ASSERT_EQ(sol_signature_decode(&dec, &sig2), SOL_OK);
    TEST_ASSERT(sol_signature_eq(&sig, &sig2));
}

/*
 * Message header tests
 */

TEST(message_header_encode_decode) {
    sol_message_header_t hdr = {
        .num_required_signatures = 2,
        .num_readonly_signed = 1,
        .num_readonly_unsigned = 3
    };

    uint8_t buf[16];
    sol_encoder_t enc;
    sol_encoder_init(&enc, buf, sizeof(buf));
    TEST_ASSERT_EQ(sol_message_header_encode(&enc, &hdr), SOL_OK);
    TEST_ASSERT_EQ(sol_encoder_len(&enc), 3);

    sol_decoder_t dec;
    sol_decoder_init(&dec, buf, sol_encoder_len(&enc));
    sol_message_header_t hdr2;
    TEST_ASSERT_EQ(sol_message_header_decode(&dec, &hdr2), SOL_OK);

    TEST_ASSERT_EQ(hdr2.num_required_signatures, 2);
    TEST_ASSERT_EQ(hdr2.num_readonly_signed, 1);
    TEST_ASSERT_EQ(hdr2.num_readonly_unsigned, 3);
}

TEST(message_decode_legacy) {
    uint8_t msg_data[256];
    sol_encoder_t enc;
    sol_encoder_init(&enc, msg_data, sizeof(msg_data));

    /* Header: 1 signer, 0 readonly signed, 1 readonly unsigned */
    sol_encode_u8(&enc, 1);
    sol_encode_u8(&enc, 0);
    sol_encode_u8(&enc, 1);

    /* Account keys: 2 accounts (fee payer, system program) */
    sol_encode_compact_u16(&enc, 2);

    uint8_t fee_payer[32];
    for (int i = 0; i < 32; i++) fee_payer[i] = (uint8_t)(i + 1);
    sol_encode_bytes(&enc, fee_payer, 32);
    sol_encode_bytes(&enc, SOL_SYSTEM_PROGRAM_ID.bytes, 32);

    /* Recent blockhash */
    uint8_t blockhash[32] = {0};
    sol_encode_bytes(&enc, blockhash, 32);

    /* Instructions: 1 instruction (no accounts, no data) */
    sol_encode_compact_u16(&enc, 1);
    sol_encode_u8(&enc, 1);           /* program_id_index (system program) */
    sol_encode_compact_u16(&enc, 0);  /* 0 accounts */
    sol_encode_compact_u16(&enc, 0);  /* 0 data */

    sol_decoder_t dec;
    sol_decoder_init(&dec, msg_data, sol_encoder_len(&enc));

    sol_message_t msg;
    sol_err_t err = sol_message_decode(&dec, &msg);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT(msg.version == SOL_MESSAGE_VERSION_LEGACY);
    TEST_ASSERT_EQ(msg.header.num_required_signatures, 1);
    TEST_ASSERT_EQ(msg.account_keys_len, 2);
    TEST_ASSERT_MEM_EQ(msg.account_keys[0].bytes, fee_payer, 32);
}

TEST(message_decode_v0) {
    uint8_t msg_data[256];
    sol_encoder_t enc;
    sol_encoder_init(&enc, msg_data, sizeof(msg_data));

    /* Version prefix: v0 */
    sol_encode_u8(&enc, 0x80);

    /* Header: 1 signer */
    sol_encode_u8(&enc, 1);
    sol_encode_u8(&enc, 0);
    sol_encode_u8(&enc, 0);

    /* Account keys: 1 account */
    sol_encode_compact_u16(&enc, 1);
    uint8_t key0[32];
    for (int i = 0; i < 32; i++) key0[i] = (uint8_t)(0xA0 + i);
    sol_encode_bytes(&enc, key0, 32);

    /* Recent blockhash */
    uint8_t blockhash[32] = {0};
    sol_encode_bytes(&enc, blockhash, 32);

    /* Instructions: 0 */
    sol_encode_compact_u16(&enc, 0);

    /* Address lookup tables: 0 */
    sol_encode_compact_u16(&enc, 0);

    sol_decoder_t dec;
    sol_decoder_init(&dec, msg_data, sol_encoder_len(&enc));

    sol_message_t msg;
    sol_err_t err = sol_message_decode(&dec, &msg);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT(msg.version == SOL_MESSAGE_VERSION_V0);
    TEST_ASSERT_EQ(msg.header.num_required_signatures, 1);
    TEST_ASSERT_EQ(msg.account_keys_len, 1);
    TEST_ASSERT_MEM_EQ(msg.account_keys[0].bytes, key0, 32);
}

TEST(message_is_signer) {
    sol_message_t msg;
    sol_message_init(&msg);
    msg.header.num_required_signatures = 2;
    msg.header.num_readonly_signed = 0;
    msg.header.num_readonly_unsigned = 1;

    TEST_ASSERT(sol_message_is_signer(&msg, 0));
    TEST_ASSERT(sol_message_is_signer(&msg, 1));
    TEST_ASSERT(!sol_message_is_signer(&msg, 2));
    TEST_ASSERT(!sol_message_is_signer(&msg, 3));
}

TEST(message_is_writable) {
    sol_message_t msg;
    sol_message_init(&msg);
    msg.header.num_required_signatures = 2;
    msg.header.num_readonly_signed = 1;
    msg.header.num_readonly_unsigned = 1;
    msg.account_keys_len = 5;

    /* Account layout:
     * [0] - signer, writable
     * [1] - signer, readonly (readonly_signed = 1)
     * [2] - unsigned, writable
     * [3] - unsigned, writable
     * [4] - unsigned, readonly (readonly_unsigned = 1)
     */

    TEST_ASSERT(sol_message_is_writable_index(&msg, 0));   /* writable signer */
    TEST_ASSERT(!sol_message_is_writable_index(&msg, 1));  /* readonly signer */
    TEST_ASSERT(sol_message_is_writable_index(&msg, 2));   /* writable unsigned */
    TEST_ASSERT(sol_message_is_writable_index(&msg, 3));   /* writable unsigned */
    TEST_ASSERT(!sol_message_is_writable_index(&msg, 4));  /* readonly unsigned */
}

/*
 * Compiled instruction tests
 */

TEST(compiled_instruction_encode_decode) {
    uint8_t account_indices[] = {0, 1, 2};
    uint8_t instr_data[] = {0xDE, 0xAD, 0xBE, 0xEF};

    sol_compiled_instruction_t instr = {
        .program_id_index = 5,
        .account_indices = account_indices,
        .account_indices_len = 3,
        .data = instr_data,
        .data_len = 4
    };

    uint8_t buf[64];
    sol_encoder_t enc;
    sol_encoder_init(&enc, buf, sizeof(buf));
    TEST_ASSERT_EQ(sol_compiled_instruction_encode(&enc, &instr), SOL_OK);

    sol_decoder_t dec;
    sol_decoder_init(&dec, buf, sol_encoder_len(&enc));
    sol_compiled_instruction_t instr2;
    TEST_ASSERT_EQ(sol_compiled_instruction_decode(&dec, &instr2), SOL_OK);

    TEST_ASSERT_EQ(instr2.program_id_index, 5);
    TEST_ASSERT_EQ(instr2.account_indices_len, 3);
    TEST_ASSERT_EQ(instr2.data_len, 4);
    TEST_ASSERT_MEM_EQ(instr2.account_indices, account_indices, 3);
    TEST_ASSERT_MEM_EQ(instr2.data, instr_data, 4);
}

/*
 * Transaction parsing tests
 */

TEST(transaction_decode_minimal) {
    /*
     * Build a minimal valid legacy transaction:
     * - 1 signature
     * - 1 required signer, 0 readonly signed, 0 readonly unsigned
     * - 2 accounts (fee payer, system program)
     * - Recent blockhash (32 bytes)
     * - 1 instruction (transfer)
     */
    uint8_t tx_data[256];
    sol_encoder_t enc;
    sol_encoder_init(&enc, tx_data, sizeof(tx_data));

    /* Signature count: 1 */
    sol_encode_compact_u16(&enc, 1);

    /* Signature (64 bytes of zeros for testing - won't verify) */
    uint8_t fake_sig[64] = {0};
    sol_encode_bytes(&enc, fake_sig, 64);

    /* Message header: 1 signer, 0 readonly signed, 1 readonly unsigned */
    sol_encode_u8(&enc, 1);  /* num_required_signatures */
    sol_encode_u8(&enc, 0);  /* num_readonly_signed */
    sol_encode_u8(&enc, 1);  /* num_readonly_unsigned */

    /* Account keys: 2 accounts */
    sol_encode_compact_u16(&enc, 2);

    /* Account 0: fee payer (random pubkey) */
    uint8_t fee_payer[32];
    for (int i = 0; i < 32; i++) fee_payer[i] = (uint8_t)(i + 1);
    sol_encode_bytes(&enc, fee_payer, 32);

    /* Account 1: system program */
    sol_encode_bytes(&enc, SOL_SYSTEM_PROGRAM_ID.bytes, 32);

    /* Recent blockhash (32 bytes) */
    uint8_t blockhash[32];
    for (int i = 0; i < 32; i++) blockhash[i] = (uint8_t)(255 - i);
    sol_encode_bytes(&enc, blockhash, 32);

    /* Instructions: 1 instruction */
    sol_encode_compact_u16(&enc, 1);

    /* Instruction 0: System program CreateAccount or similar */
    sol_encode_u8(&enc, 1);  /* program_id_index = 1 (system program) */
    sol_encode_compact_u16(&enc, 1);  /* 1 account */
    sol_encode_u8(&enc, 0);  /* account index 0 */
    sol_encode_compact_u16(&enc, 4);  /* 4 bytes of data */
    uint8_t instr_data[] = {0x02, 0x00, 0x00, 0x00};  /* Transfer instruction */
    sol_encode_bytes(&enc, instr_data, 4);

    size_t tx_len = sol_encoder_len(&enc);

    /* Parse the transaction */
    sol_transaction_t tx;
    sol_err_t err = sol_transaction_decode(tx_data, tx_len, &tx);
    TEST_ASSERT_EQ(err, SOL_OK);

    /* Verify structure */
    TEST_ASSERT_EQ(tx.signatures_len, 1);
    TEST_ASSERT_EQ(tx.message.header.num_required_signatures, 1);
    TEST_ASSERT_EQ(tx.message.header.num_readonly_signed, 0);
    TEST_ASSERT_EQ(tx.message.header.num_readonly_unsigned, 1);
    TEST_ASSERT_EQ(tx.message.account_keys_len, 2);
    TEST_ASSERT(tx.message.version == SOL_MESSAGE_VERSION_LEGACY);

    /* Verify fee payer */
    const sol_pubkey_t* payer = sol_transaction_fee_payer(&tx);
    TEST_ASSERT(payer != NULL);
    TEST_ASSERT_MEM_EQ(payer->bytes, fee_payer, 32);

    /* Verify blockhash */
    TEST_ASSERT_MEM_EQ(tx.message.recent_blockhash.bytes, blockhash, 32);
}

TEST(transaction_sanitize_valid) {
    /* Build a valid transaction and verify sanitize passes */
    uint8_t tx_data[256];
    sol_encoder_t enc;
    sol_encoder_init(&enc, tx_data, sizeof(tx_data));

    sol_encode_compact_u16(&enc, 1);  /* 1 signature */
    uint8_t sig[64] = {0};
    sol_encode_bytes(&enc, sig, 64);

    sol_encode_u8(&enc, 1);  /* 1 signer */
    sol_encode_u8(&enc, 0);  /* 0 readonly signed */
    sol_encode_u8(&enc, 1);  /* 1 readonly unsigned */

    sol_encode_compact_u16(&enc, 2);  /* 2 accounts */
    uint8_t pk[32] = {1};
    sol_encode_bytes(&enc, pk, 32);
    sol_encode_bytes(&enc, SOL_SYSTEM_PROGRAM_ID.bytes, 32);

    uint8_t hash[32] = {0};
    sol_encode_bytes(&enc, hash, 32);

    sol_encode_compact_u16(&enc, 1);  /* 1 instruction */
    sol_encode_u8(&enc, 1);           /* program index */
    sol_encode_compact_u16(&enc, 0);  /* 0 accounts */
    sol_encode_compact_u16(&enc, 0);  /* 0 data */

    sol_transaction_t tx;
    TEST_ASSERT_EQ(sol_transaction_decode(tx_data, sol_encoder_len(&enc), &tx), SOL_OK);
    TEST_ASSERT_EQ(sol_transaction_sanitize(&tx), SOL_OK);
}

TEST(transaction_decode_truncated) {
    /* Test that truncated data is rejected */
    uint8_t tx_data[] = {0x01};  /* Just signature count */
    sol_transaction_t tx;
    TEST_ASSERT(sol_transaction_decode(tx_data, sizeof(tx_data), &tx) != SOL_OK);
}

TEST(transaction_decode_invalid_sig_count) {
    /* Test that zero signatures is rejected */
    uint8_t tx_data[128];
    sol_encoder_t enc;
    sol_encoder_init(&enc, tx_data, sizeof(tx_data));

    sol_encode_compact_u16(&enc, 0);  /* 0 signatures - invalid */

    sol_transaction_t tx;
    TEST_ASSERT(sol_transaction_decode(tx_data, sol_encoder_len(&enc), &tx) != SOL_OK);
}

/*
 * Test cases array
 */
static test_case_t txn_tests[] = {
    TEST_CASE(bincode_u8),
    TEST_CASE(bincode_u16),
    TEST_CASE(bincode_u32),
    TEST_CASE(bincode_u64),
    TEST_CASE(bincode_compact_u16_small),
    TEST_CASE(bincode_compact_u16_medium),
    TEST_CASE(bincode_compact_u16_large),
    TEST_CASE(bincode_decode_underflow),
    TEST_CASE(pubkey_zero),
    TEST_CASE(pubkey_eq),
    TEST_CASE(pubkey_cmp),
    TEST_CASE(pubkey_copy),
    TEST_CASE(pubkey_base58_roundtrip),
    TEST_CASE(pubkey_base58_known),
    TEST_CASE(pubkey_bincode),
    TEST_CASE(signature_zero),
    TEST_CASE(signature_eq),
    TEST_CASE(signature_bincode),
    TEST_CASE(message_header_encode_decode),
    TEST_CASE(message_decode_legacy),
    TEST_CASE(message_decode_v0),
    TEST_CASE(message_is_signer),
    TEST_CASE(message_is_writable),
    TEST_CASE(compiled_instruction_encode_decode),
    TEST_CASE(transaction_decode_minimal),
    TEST_CASE(transaction_sanitize_valid),
    TEST_CASE(transaction_decode_truncated),
    TEST_CASE(transaction_decode_invalid_sig_count),
};

int main(void) {
    int result = RUN_TESTS("Transaction Tests", txn_tests);
    sol_alloc_dump_leaks();
    return result;
}
