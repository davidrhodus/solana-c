/*
 * test_crypto.c - Cryptographic primitives unit tests
 *
 * Tests SHA-256, SHA-512, Ed25519, BLAKE3, and Keccak-256 against known test vectors.
 */

#include "../test_framework.h"
#include "sol_sha256.h"
#include "sol_sha512.h"
#include "sol_ed25519.h"
#include "sol_blake3.h"
#include "sol_lt_hash.h"
#include "sol_keccak256.h"
#include "sol_alloc.h"
#include <string.h>

/*
 * SHA-256 test vectors from NIST FIPS 180-4
 */

TEST(sha256_empty) {
    /* SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
    sol_sha256_t hash;
    sol_sha256("", 0, &hash);

    uint8_t expected[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };

    TEST_ASSERT_MEM_EQ(hash.bytes, expected, 32);
}

TEST(sha256_abc) {
    /* SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad */
    sol_sha256_t hash;
    sol_sha256("abc", 3, &hash);

    uint8_t expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };

    TEST_ASSERT_MEM_EQ(hash.bytes, expected, 32);
}

TEST(sha256_long) {
    /* SHA256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") */
    const char* msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sol_sha256_t hash;
    sol_sha256(msg, strlen(msg), &hash);

    uint8_t expected[32] = {
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
        0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
        0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1
    };

    TEST_ASSERT_MEM_EQ(hash.bytes, expected, 32);
}

TEST(sha256_incremental) {
    /* Test incremental hashing gives same result */
    const char* msg = "The quick brown fox jumps over the lazy dog";

    sol_sha256_t hash1, hash2;
    sol_sha256(msg, strlen(msg), &hash1);

    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    sol_sha256_update(&ctx, msg, 10);
    sol_sha256_update(&ctx, msg + 10, 20);
    sol_sha256_update(&ctx, msg + 30, strlen(msg) - 30);
    sol_sha256_final(&ctx, &hash2);

    TEST_ASSERT(sol_sha256_eq(&hash1, &hash2));
}

TEST(sha256_hex) {
    /* Test hex conversion */
    sol_sha256_t hash;
    sol_sha256("test", 4, &hash);

    char hex[65];
    sol_sha256_to_hex(&hash, hex);

    sol_sha256_t parsed;
    sol_err_t err = sol_sha256_from_hex(hex, &parsed);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT(sol_sha256_eq(&hash, &parsed));
}

TEST(sha256_32bytes_specialized) {
    /* Ensure the specialized 32-byte path matches the generic implementation. */
    uint8_t input[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };

    uint8_t generic[32];
    sol_sha256_bytes(input, 32, generic);

    uint8_t fast[32];
    sol_sha256_32bytes(input, fast);
    TEST_ASSERT_MEM_EQ(fast, generic, 32);

    /* Supports in==out */
    uint8_t inplace[32];
    memcpy(inplace, input, sizeof(inplace));
    sol_sha256_32bytes(inplace, inplace);
    TEST_ASSERT_MEM_EQ(inplace, generic, 32);
}

/*
 * HMAC-SHA256 test vectors from RFC 4231
 */

TEST(hmac_sha256) {
    /* Test Case 1 */
    uint8_t key[20];
    memset(key, 0x0b, 20);
    const char* data = "Hi There";

    sol_sha256_t mac;
    sol_hmac_sha256(key, 20, data, 8, &mac);

    uint8_t expected[32] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
    };

    TEST_ASSERT_MEM_EQ(mac.bytes, expected, 32);
}

/*
 * SHA-512 test vectors from NIST
 */

TEST(sha512_empty) {
    sol_sha512_t hash;
    sol_sha512("", 0, &hash);

    /* SHA512("") = cf83e1357eefb8bd... */
    uint8_t expected[64] = {
        0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
        0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
        0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
        0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
        0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
        0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
        0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
        0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
    };

    TEST_ASSERT_MEM_EQ(hash.bytes, expected, 64);
}

TEST(sha512_abc) {
    sol_sha512_t hash;
    sol_sha512("abc", 3, &hash);

    uint8_t expected[64] = {
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
        0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
        0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
        0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
        0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
        0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
        0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
    };

    TEST_ASSERT_MEM_EQ(hash.bytes, expected, 64);
}

/*
 * Ed25519 test vectors from RFC 8032
 */

TEST(ed25519_keypair) {
    /* RFC 8032 Test 1 secret key */
    uint8_t seed[32] = {
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
    };

    /* Expected public key */
    uint8_t expected_pk[32] = {
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
        0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
        0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
    };

    sol_keypair_t kp;
    sol_ed25519_keypair_from_seed(seed, &kp);

    sol_pubkey_t pk;
    sol_ed25519_pubkey_from_keypair(&kp, &pk);

    TEST_ASSERT_MEM_EQ(pk.bytes, expected_pk, 32);
}

TEST(ed25519_sign_verify) {
    /* Generate keypair from seed */
    uint8_t seed[32] = {
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
    };

    sol_keypair_t kp;
    sol_ed25519_keypair_from_seed(seed, &kp);

    sol_pubkey_t pk;
    sol_ed25519_pubkey_from_keypair(&kp, &pk);

    /* Sign a test message */
    const char* msg = "test message";
    sol_signature_t sig;
    sol_ed25519_sign(&kp, (const uint8_t*)msg, strlen(msg), &sig);

    /* Verify signature */
    bool valid = sol_ed25519_verify(&pk, (const uint8_t*)msg, strlen(msg), &sig);
    TEST_ASSERT(valid);
}

TEST(ed25519_verify_invalid) {
    /* Generate a keypair */
    uint8_t seed[32] = {0};
    seed[0] = 1;

    sol_keypair_t kp;
    sol_ed25519_keypair_from_seed(seed, &kp);

    sol_pubkey_t pk;
    sol_ed25519_pubkey_from_keypair(&kp, &pk);

    /* Sign a message */
    const char* msg = "test message";
    sol_signature_t sig;
    sol_ed25519_sign(&kp, (const uint8_t*)msg, strlen(msg), &sig);

    /* Verify with correct message */
    TEST_ASSERT(sol_ed25519_verify(&pk, (const uint8_t*)msg, strlen(msg), &sig));

    /* Verify with wrong message should fail */
    const char* wrong_msg = "wrong message";
    TEST_ASSERT(!sol_ed25519_verify(&pk, (const uint8_t*)wrong_msg, strlen(wrong_msg), &sig));

    /* Modify signature - should fail */
    sol_signature_t bad_sig;
    memcpy(&bad_sig, &sig, sizeof(sig));
    bad_sig.bytes[0] ^= 0x01;
    TEST_ASSERT(!sol_ed25519_verify(&pk, (const uint8_t*)msg, strlen(msg), &bad_sig));
}

TEST(ed25519_pda) {
    /* Test PDA derivation */
    sol_pubkey_t program_id = {{
        0x06, 0xa7, 0xd5, 0x17, 0x18, 0x7b, 0xd1, 0x65,
        0x35, 0x50, 0x7d, 0x6b, 0xef, 0x10, 0xc5, 0x77,
        0x4e, 0x4d, 0x00, 0x6d, 0x73, 0x6c, 0x39, 0x6a,
        0x4c, 0xae, 0xbc, 0x32, 0x99, 0x56, 0x7f, 0xb1
    }};

    const uint8_t seed1[] = "test";
    const uint8_t* seeds[] = { seed1 };
    size_t seed_lens[] = { 4 };

    sol_pubkey_t pda;
    uint8_t bump;
    sol_err_t err = sol_ed25519_create_pda(&program_id, seeds, seed_lens, 1, &pda, &bump);

    /* PDA creation should succeed */
    TEST_ASSERT_EQ(err, SOL_OK);

    /* PDA should be off the curve */
    TEST_ASSERT(!sol_ed25519_pubkey_is_on_curve(&pda));
}

/*
 * BLAKE3 test vectors from the official test suite
 */

TEST(blake3_empty) {
    /* BLAKE3("") known value */
    sol_blake3_t hash;
    sol_blake3_hash((const uint8_t*)"", 0, &hash);

    /* Expected hash of empty input */
    uint8_t expected[32] = {
        0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6,
        0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49,
        0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7,
        0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62
    };

    TEST_ASSERT_MEM_EQ(hash.bytes, expected, 32);
}

TEST(blake3_abc) {
    /* BLAKE3("abc") - verified with b3sum */
    sol_blake3_t hash;
    sol_blake3_hash((const uint8_t*)"abc", 3, &hash);

    uint8_t expected[32] = {
        0x64, 0x37, 0xb3, 0xac, 0x38, 0x46, 0x51, 0x33,
        0xff, 0xb6, 0x3b, 0x75, 0x27, 0x3a, 0x8d, 0xb5,
        0x48, 0xc5, 0x58, 0x46, 0x5d, 0x79, 0xdb, 0x03,
        0xfd, 0x35, 0x9c, 0x6c, 0xd5, 0xbd, 0x9d, 0x85
    };

    TEST_ASSERT_MEM_EQ(hash.bytes, expected, 32);
}

TEST(blake3_incremental) {
    /* Test that incremental hashing works */
    const char* msg = "The quick brown fox jumps over the lazy dog";

    sol_blake3_t hash1, hash2;
    sol_blake3_hash((const uint8_t*)msg, strlen(msg), &hash1);

    sol_blake3_ctx_t ctx;
    sol_blake3_init(&ctx);
    sol_blake3_update(&ctx, (const uint8_t*)msg, 10);
    sol_blake3_update(&ctx, (const uint8_t*)msg + 10, 20);
    sol_blake3_update(&ctx, (const uint8_t*)msg + 30, strlen(msg) - 30);
    sol_blake3_final(&ctx, &hash2);

    TEST_ASSERT(sol_blake3_equal(&hash1, &hash2));
}

TEST(blake3_keyed) {
    /* Test keyed hashing */
    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;

    sol_blake3_t hash;
    sol_blake3_keyed_hash(key, (const uint8_t*)"test", 4, &hash);

    /* Verify hash is not all zeros (basic sanity check) */
    bool all_zero = true;
    for (int i = 0; i < 32; i++) {
        if (hash.bytes[i] != 0) {
            all_zero = false;
            break;
        }
    }
    TEST_ASSERT(!all_zero);
}

TEST(lt_hash_checksum_vectors) {
    typedef struct {
        const char* input;
        uint8_t     checksum[32];
    } test_vec_t;

    /* Vectors copied from Agave's lattice-hash crate (LtHash::checksum). */
    static const test_vec_t vecs[] = {
        {
            .input = "hello",
            .checksum = {
                79, 156, 26, 184, 156, 205, 94, 208, 182, 235, 33, 147, 111, 153, 229, 152,
                207, 133, 75, 109, 182, 198, 119, 61, 11, 81, 41, 70, 24, 87, 100, 85,
            },
        },
        {
            .input = "world!",
            .checksum = {
                171, 53, 185, 10, 179, 49, 48, 151, 87, 43, 141, 13, 43, 152, 121, 1,
                144, 7, 120, 188, 115, 248, 214, 220, 229, 210, 175, 134, 215, 231, 18, 245,
            },
        },
    };

    for (size_t i = 0; i < sizeof(vecs) / sizeof(vecs[0]); i++) {
        const test_vec_t* v = &vecs[i];
        sol_blake3_ctx_t ctx;
        sol_blake3_init(&ctx);
        sol_blake3_update(&ctx, (const uint8_t*)v->input, strlen(v->input));

        sol_lt_hash_t lt;
        sol_lt_hash_from_blake3_hasher(&ctx, &lt);

        sol_blake3_t checksum = {0};
        sol_lt_hash_checksum(&lt, &checksum);
        TEST_ASSERT_MEM_EQ(checksum.bytes, v->checksum, sizeof(v->checksum));
    }
}

/*
 * Keccak-256 test vectors (Ethereum-style)
 */

TEST(keccak256_empty) {
    /* Keccak-256("") - this is the Ethereum-style hash */
    sol_keccak256_t hash;
    sol_keccak256_hash((const uint8_t*)"", 0, &hash);

    uint8_t expected[32] = {
        0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
        0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
        0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
        0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70
    };

    TEST_ASSERT_MEM_EQ(hash.bytes, expected, 32);
}

TEST(keccak256_hello) {
    /* Keccak-256("hello") - commonly used test vector */
    sol_keccak256_t hash;
    sol_keccak256_hash((const uint8_t*)"hello", 5, &hash);

    uint8_t expected[32] = {
        0x1c, 0x8a, 0xff, 0x95, 0x06, 0x85, 0xc2, 0xed,
        0x4b, 0xc3, 0x17, 0x4f, 0x34, 0x72, 0x28, 0x7b,
        0x56, 0xd9, 0x51, 0x7b, 0x9c, 0x94, 0x81, 0x27,
        0x31, 0x9a, 0x09, 0xa7, 0xa3, 0x6d, 0xea, 0xc8
    };

    TEST_ASSERT_MEM_EQ(hash.bytes, expected, 32);
}

TEST(keccak256_incremental) {
    /* Test incremental hashing */
    const char* msg = "The quick brown fox jumps over the lazy dog";

    sol_keccak256_t hash1, hash2;
    sol_keccak256_hash((const uint8_t*)msg, strlen(msg), &hash1);

    sol_keccak256_ctx_t ctx;
    sol_keccak256_init(&ctx);
    sol_keccak256_update(&ctx, (const uint8_t*)msg, 10);
    sol_keccak256_update(&ctx, (const uint8_t*)msg + 10, 20);
    sol_keccak256_update(&ctx, (const uint8_t*)msg + 30, strlen(msg) - 30);
    sol_keccak256_final(&ctx, &hash2);

    TEST_ASSERT(sol_keccak256_equal(&hash1, &hash2));
}

/*
 * Test cases array
 */
static test_case_t crypto_tests[] = {
    TEST_CASE(sha256_empty),
    TEST_CASE(sha256_abc),
    TEST_CASE(sha256_long),
    TEST_CASE(sha256_incremental),
    TEST_CASE(sha256_hex),
    TEST_CASE(sha256_32bytes_specialized),
    TEST_CASE(hmac_sha256),
    TEST_CASE(sha512_empty),
    TEST_CASE(sha512_abc),
    TEST_CASE(ed25519_keypair),
    TEST_CASE(ed25519_sign_verify),
    TEST_CASE(ed25519_verify_invalid),
    TEST_CASE(ed25519_pda),
    TEST_CASE(blake3_empty),
    TEST_CASE(blake3_abc),
    TEST_CASE(blake3_incremental),
    TEST_CASE(blake3_keyed),
    TEST_CASE(lt_hash_checksum_vectors),
    TEST_CASE(keccak256_empty),
    TEST_CASE(keccak256_hello),
    TEST_CASE(keccak256_incremental),
};

int main(void) {
    int result = RUN_TESTS("Crypto Tests", crypto_tests);
    sol_alloc_dump_leaks();
    return result;
}
