/*
 * sol_secp256r1_program.c - Secp256r1 Signature Verification Precompile
 */

#include "sol_secp256r1_program.h"
#include "../crypto/sol_sha256.h"
#include "../runtime/sol_sysvar.h"
#include "../util/sol_log.h"
#include <string.h>

#if SOL_USE_OPENSSL
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#endif

static inline uint16_t
read_u16_le(const uint8_t* data) {
    return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

#if SOL_USE_OPENSSL

static const uint8_t
SECP256R1_ORDER_MINUS_ONE[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x50,
};

static const uint8_t
SECP256R1_HALF_ORDER[32] = {
    0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00,
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42,
    0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
};

static sol_err_t
secp256r1_verify_sig(const uint8_t signature[SOL_SECP256R1_SIGNATURE_SIZE],
                     const uint8_t pubkey[SOL_SECP256R1_PUBKEY_COMPRESSED_SIZE],
                     const uint8_t* message,
                     size_t message_len,
                     const BIGNUM* one,
                     const BIGNUM* order_minus_one,
                     const BIGNUM* half_order,
                     const EC_GROUP* group,
                     BN_CTX* bn_ctx) {
    uint8_t digest[SOL_SHA256_HASH_SIZE];
    sol_sha256_bytes(message, message_len, digest);

    BIGNUM* r = BN_bin2bn(signature, 32, NULL);
    BIGNUM* s = BN_bin2bn(signature + 32, 32, NULL);
    if (!r || !s) {
        if (r) BN_free(r);
        if (s) BN_free(s);
        return SOL_ERR_INVALID_SIGNATURE;
    }

    bool within_range =
        (BN_cmp(r, one) >= 0) &&
        (BN_cmp(r, order_minus_one) <= 0) &&
        (BN_cmp(s, one) >= 0) &&
        (BN_cmp(s, half_order) <= 0);
    if (!within_range) {
        BN_free(r);
        BN_free(s);
        return SOL_ERR_INVALID_SIGNATURE;
    }

    ECDSA_SIG* sig = ECDSA_SIG_new();
    if (!sig) {
        BN_free(r);
        BN_free(s);
        return SOL_ERR_INVALID_SIGNATURE;
    }
    if (ECDSA_SIG_set0(sig, r, s) != 1) {
        ECDSA_SIG_free(sig);
        BN_free(r);
        BN_free(s);
        return SOL_ERR_INVALID_SIGNATURE;
    }

    EC_POINT* point = EC_POINT_new(group);
    if (!point) {
        ECDSA_SIG_free(sig);
        return SOL_ERR_INVALID_SIGNATURE;
    }
    if (EC_POINT_oct2point(group, point, pubkey, SOL_SECP256R1_PUBKEY_COMPRESSED_SIZE, bn_ctx) !=
        1) {
        EC_POINT_free(point);
        ECDSA_SIG_free(sig);
        return SOL_ERR_INVALID_SIGNATURE;
    }

    EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key) {
        EC_POINT_free(point);
        ECDSA_SIG_free(sig);
        return SOL_ERR_INVALID_SIGNATURE;
    }

    if (EC_KEY_set_public_key(key, point) != 1) {
        EC_KEY_free(key);
        EC_POINT_free(point);
        ECDSA_SIG_free(sig);
        return SOL_ERR_INVALID_SIGNATURE;
    }

    if (EC_KEY_check_key(key) != 1) {
        EC_KEY_free(key);
        EC_POINT_free(point);
        ECDSA_SIG_free(sig);
        return SOL_ERR_INVALID_SIGNATURE;
    }

    int ok = ECDSA_do_verify(digest, (int)sizeof(digest), sig, key);

    EC_KEY_free(key);
    EC_POINT_free(point);
    ECDSA_SIG_free(sig);

    return ok == 1 ? SOL_OK : SOL_ERR_INVALID_SIGNATURE;
}

#endif

sol_err_t
sol_secp256r1_program_execute(sol_invoke_context_t* ctx) {
    if (!ctx) {
        return SOL_ERR_INVAL;
    }

    const uint8_t* data = ctx->instruction_data;
    size_t data_len = ctx->instruction_data_len;

    if (!data || data_len < SOL_SECP256R1_SIGNATURE_OFFSETS_START) {
        sol_log_warn("Secp256r1: instruction too short");
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    uint8_t num_signatures = data[0];
    if (num_signatures == 0 || num_signatures > SOL_SECP256R1_MAX_SIGNATURES) {
        sol_log_warn("Secp256r1: invalid signature count %u", num_signatures);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    size_t expected_data_size =
        SOL_SECP256R1_SIGNATURE_OFFSETS_START +
        ((size_t)num_signatures * SOL_SECP256R1_SIGNATURE_OFFSETS_SERIALIZED_SIZE);
    if (data_len < expected_data_size) {
        sol_log_warn("Secp256r1: instruction data too short for %u signatures", num_signatures);
        return SOL_ERR_PROGRAM_INVALID_INSTR;
    }

    sol_account_t* instr_sysvar_account = NULL;
    const uint8_t* instr_sysvar_data = NULL;
    size_t instr_sysvar_len = 0;

#if SOL_USE_OPENSSL
    BIGNUM* one = BN_new();
    BIGNUM* half_order = BN_bin2bn(SECP256R1_HALF_ORDER, 32, NULL);
    BIGNUM* order_minus_one = BN_bin2bn(SECP256R1_ORDER_MINUS_ONE, 32, NULL);
    if (!one || !half_order || !order_minus_one) {
        if (one) BN_free(one);
        if (half_order) BN_free(half_order);
        if (order_minus_one) BN_free(order_minus_one);
        sol_log_warn("Secp256r1: OpenSSL allocation failed");
        return SOL_ERR_INVALID_SIGNATURE;
    }
    BN_set_word(one, 1);

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BN_CTX* bn_ctx = BN_CTX_new();
    if (!group || !bn_ctx) {
        if (group) EC_GROUP_free(group);
        if (bn_ctx) BN_CTX_free(bn_ctx);
        BN_free(one);
        BN_free(half_order);
        BN_free(order_minus_one);
        sol_log_warn("Secp256r1: OpenSSL init failed");
        return SOL_ERR_INVALID_SIGNATURE;
    }
#endif

    const uint8_t* offsets_data = data + SOL_SECP256R1_SIGNATURE_OFFSETS_START;
    for (uint8_t i = 0; i < num_signatures; i++) {
        const uint8_t* entry = offsets_data + (i * SOL_SECP256R1_SIGNATURE_OFFSETS_SERIALIZED_SIZE);

        uint16_t sig_offset = read_u16_le(entry + 0);
        uint16_t sig_ix = read_u16_le(entry + 2);
        uint16_t pk_offset = read_u16_le(entry + 4);
        uint16_t pk_ix = read_u16_le(entry + 6);
        uint16_t msg_offset = read_u16_le(entry + 8);
        uint16_t msg_size = read_u16_le(entry + 10);
        uint16_t msg_ix = read_u16_le(entry + 12);

        if ((sig_ix != 0xFFFF || pk_ix != 0xFFFF || msg_ix != 0xFFFF) && !instr_sysvar_data) {
            instr_sysvar_account = sol_bank_load_account(ctx->bank, &SOL_SYSVAR_INSTRUCTIONS_ID);
            if (!instr_sysvar_account) {
                sol_log_warn("Secp256r1: instructions sysvar missing");
#if SOL_USE_OPENSSL
                EC_GROUP_free(group);
                BN_CTX_free(bn_ctx);
                BN_free(one);
                BN_free(half_order);
                BN_free(order_minus_one);
#endif
                return SOL_ERR_PROGRAM_INVALID_INSTR;
            }
            instr_sysvar_data = instr_sysvar_account->data;
            instr_sysvar_len = instr_sysvar_account->meta.data_len;
        }

        const uint8_t* sig_src = data;
        size_t sig_src_len = data_len;
        if (sig_ix != 0xFFFF) {
            sol_pubkey_t unused_prog = {0};
            sol_err_t err = sol_instructions_sysvar_load_instruction(
                instr_sysvar_data, instr_sysvar_len, sig_ix, &unused_prog, &sig_src, &sig_src_len);
            if (err != SOL_OK) {
                sol_log_warn("Secp256r1: signature %u instruction index out of bounds", i);
                if (instr_sysvar_account) sol_account_destroy(instr_sysvar_account);
#if SOL_USE_OPENSSL
                EC_GROUP_free(group);
                BN_CTX_free(bn_ctx);
                BN_free(one);
                BN_free(half_order);
                BN_free(order_minus_one);
#endif
                return SOL_ERR_PROGRAM_INVALID_INSTR;
            }
        }

        const uint8_t* pk_src = data;
        size_t pk_src_len = data_len;
        if (pk_ix != 0xFFFF) {
            sol_pubkey_t unused_prog = {0};
            sol_err_t err = sol_instructions_sysvar_load_instruction(
                instr_sysvar_data, instr_sysvar_len, pk_ix, &unused_prog, &pk_src, &pk_src_len);
            if (err != SOL_OK) {
                sol_log_warn("Secp256r1: public key %u instruction index out of bounds", i);
                if (instr_sysvar_account) sol_account_destroy(instr_sysvar_account);
#if SOL_USE_OPENSSL
                EC_GROUP_free(group);
                BN_CTX_free(bn_ctx);
                BN_free(one);
                BN_free(half_order);
                BN_free(order_minus_one);
#endif
                return SOL_ERR_PROGRAM_INVALID_INSTR;
            }
        }

        const uint8_t* msg_src = data;
        size_t msg_src_len = data_len;
        if (msg_ix != 0xFFFF) {
            sol_pubkey_t unused_prog = {0};
            sol_err_t err = sol_instructions_sysvar_load_instruction(
                instr_sysvar_data, instr_sysvar_len, msg_ix, &unused_prog, &msg_src, &msg_src_len);
            if (err != SOL_OK) {
                sol_log_warn("Secp256r1: message %u instruction index out of bounds", i);
                if (instr_sysvar_account) sol_account_destroy(instr_sysvar_account);
#if SOL_USE_OPENSSL
                EC_GROUP_free(group);
                BN_CTX_free(bn_ctx);
                BN_free(one);
                BN_free(half_order);
                BN_free(order_minus_one);
#endif
                return SOL_ERR_PROGRAM_INVALID_INSTR;
            }
        }

        if ((size_t)sig_offset + SOL_SECP256R1_SIGNATURE_SIZE > sig_src_len) {
            sol_log_warn("Secp256r1: signature %u offset out of bounds", i);
            if (instr_sysvar_account) sol_account_destroy(instr_sysvar_account);
#if SOL_USE_OPENSSL
            EC_GROUP_free(group);
            BN_CTX_free(bn_ctx);
            BN_free(one);
            BN_free(half_order);
            BN_free(order_minus_one);
#endif
            return SOL_ERR_PROGRAM_INVALID_INSTR;
        }

        if ((size_t)pk_offset + SOL_SECP256R1_PUBKEY_COMPRESSED_SIZE > pk_src_len) {
            sol_log_warn("Secp256r1: public key %u offset out of bounds", i);
            if (instr_sysvar_account) sol_account_destroy(instr_sysvar_account);
#if SOL_USE_OPENSSL
            EC_GROUP_free(group);
            BN_CTX_free(bn_ctx);
            BN_free(one);
            BN_free(half_order);
            BN_free(order_minus_one);
#endif
            return SOL_ERR_PROGRAM_INVALID_INSTR;
        }

        if ((size_t)msg_offset + (size_t)msg_size > msg_src_len) {
            sol_log_warn("Secp256r1: message %u offset/size out of bounds", i);
            if (instr_sysvar_account) sol_account_destroy(instr_sysvar_account);
#if SOL_USE_OPENSSL
            EC_GROUP_free(group);
            BN_CTX_free(bn_ctx);
            BN_free(one);
            BN_free(half_order);
            BN_free(order_minus_one);
#endif
            return SOL_ERR_PROGRAM_INVALID_INSTR;
        }

        const uint8_t* signature = sig_src + sig_offset;
        const uint8_t* pubkey = pk_src + pk_offset;
        const uint8_t* message = msg_size ? (msg_src + msg_offset) : (const uint8_t*)"";

#if SOL_USE_OPENSSL
        sol_err_t verify_err = secp256r1_verify_sig(
            signature, pubkey, message, msg_size, one, order_minus_one, half_order, group, bn_ctx);
        if (verify_err != SOL_OK) {
            sol_log_warn("Secp256r1: signature %u verification failed", i);
            if (instr_sysvar_account) sol_account_destroy(instr_sysvar_account);
            EC_GROUP_free(group);
            BN_CTX_free(bn_ctx);
            BN_free(one);
            BN_free(half_order);
            BN_free(order_minus_one);
            return SOL_ERR_INVALID_SIGNATURE;
        }
#else
        (void)signature;
        (void)pubkey;
        (void)message;
        sol_log_warn("Secp256r1: OpenSSL not available");
        if (instr_sysvar_account) sol_account_destroy(instr_sysvar_account);
        return SOL_ERR_INVALID_SIGNATURE;
#endif
    }

    if (instr_sysvar_account) {
        sol_account_destroy(instr_sysvar_account);
    }

#if SOL_USE_OPENSSL
    EC_GROUP_free(group);
    BN_CTX_free(bn_ctx);
    BN_free(one);
    BN_free(half_order);
    BN_free(order_minus_one);
#endif

    return SOL_OK;
}

