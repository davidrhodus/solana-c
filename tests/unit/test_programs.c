/*
 * test_programs.c - Program module unit tests
 */

#include "../test_framework.h"
#include "sol_system_program.h"
#include "sol_vote_program.h"
#include "sol_stake_program.h"
#include "sol_leader_schedule.h"
#include "sol_ed25519_program.h"
#include "sol_secp256k1_program.h"
#include "sol_bpf_loader_program.h"
#include "sol_token_program.h"
#include "sol_bank.h"
#include "sol_program.h"
#include "sol_account.h"
#include "sol_accounts_db.h"
#include "sol_sysvar.h"
#include "sol_transaction.h"
#include "sol_alloc.h"
#include "crypto/sol_ed25519.h"
#include "crypto/sol_keccak256.h"
#include "crypto/sol_sha256.h"
#include <string.h>

#ifdef SOL_HAS_SECP256K1
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#endif

/*
 * Helper to create test pubkeys
 */
static void make_pubkey(sol_pubkey_t* pk, uint8_t fill) {
    memset(pk->bytes, fill, 32);
}

TEST(associated_token_address_matches_spl) {
    struct {
        const char* wallet;
        const char* mint;
        const char* token_program;
        const char* expected_ata;
    } cases[] = {
        {
            "9N9kkYWdoDNxuEbUcsLUWWf1KdcdP5NLii7KUkpu1Utk",
            "So11111111111111111111111111111111111111112",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "FXhSJqTbNTyqndgKiuULJtXvFpRJUgAeSBEpjoYtbEzg",
        },
        {
            "7oXRGszyfXg4uNDhEonwGg1MoWBfuPDaRPN7v2n5SgVZ",
            "HmMubgKx91Tpq3jmfcKQwsv5HrErqnCTTRJMB6afFR2u",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "6Mh5oN27SBBSFRmBneevo9Py7NGK6oxsnu3qjbZaGe1o",
        },
        {
            "9RfNjLiS9qKbX9mtbLUAt47EvaKDYYNXpmLLN2GDRAaJ",
            "88jWqsLB1sUg6EotZtBjygF7eXRBBv1QRSddrLQkpump",
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
            "5AHKEoqxPBjL1yRjJA3dDmfn7T2FTYyNuB2DVeuE7CcX",
        },
        {
            "5ZvHot3wV8tT7kqCBrYVKvK8yUND1REUDDZ7xR9KPYcJ",
            "Dem8N6Gb1fuR6tSi7ZMVSmYjHMjyvz3gjCtzXvz2VRZc",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "FVtnfuMgW5qwxt1NjHRs5tmp7E6EtpbRJLSffEYB7fXH",
        },
        {
            "8tosnFGWFvLy2Hvgj9uX4wFoYKBkC8mhnrtDJ9iELu1n",
            "So11111111111111111111111111111111111111112",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "BxRDUj9Z761oup1jrGNevjK9Cnw3w8GmQCRWNHXNrbzg",
        },
    };

    for (size_t i = 0; i < (sizeof(cases) / sizeof(cases[0])); i++) {
        sol_pubkey_t wallet = {0};
        sol_pubkey_t mint = {0};
        sol_pubkey_t token_program = {0};

        TEST_ASSERT_EQ(sol_pubkey_from_base58(cases[i].wallet, &wallet), SOL_OK);
        TEST_ASSERT_EQ(sol_pubkey_from_base58(cases[i].mint, &mint), SOL_OK);
        TEST_ASSERT_EQ(sol_pubkey_from_base58(cases[i].token_program, &token_program), SOL_OK);

        sol_pubkey_t ata = {0};
        TEST_ASSERT_EQ(sol_get_associated_token_address(&wallet, &mint, &token_program, &ata), SOL_OK);

        char ata_b58[SOL_PUBKEY_BASE58_LEN] = {0};
        TEST_ASSERT_EQ(sol_pubkey_to_base58(&ata, ata_b58, sizeof(ata_b58)), SOL_OK);
        TEST_ASSERT_STR_EQ(ata_b58, cases[i].expected_ata);
    }
}

TEST(associated_token_create_finds_token_program_by_mint_owner) {
    sol_bank_t* bank = sol_bank_new(0, NULL, NULL, NULL);
    TEST_ASSERT_NOT_NULL(bank);

    sol_pubkey_t payer = {0};
    sol_pubkey_t wallet = {0};
    sol_pubkey_t mint = {0};
    sol_pubkey_t dummy = {0};
    make_pubkey(&payer, 0x11);
    make_pubkey(&wallet, 0x22);
    make_pubkey(&mint, 0x33);
    make_pubkey(&dummy, 0x44);

    sol_pubkey_t token_program = {0};
    TEST_ASSERT_EQ(sol_pubkey_from_base58("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", &token_program), SOL_OK);

    /* Seed payer + mint accounts */
    uint64_t rent_minimum = sol_account_rent_exempt_minimum(SOL_TOKEN_ACCOUNT_SIZE, 3480, 2);
    sol_account_t* payer_account = sol_account_new(rent_minimum + 1234, 0, &SOL_SYSTEM_PROGRAM_ID);
    TEST_ASSERT_NOT_NULL(payer_account);
    TEST_ASSERT_EQ(sol_bank_store_account(bank, &payer, payer_account), SOL_OK);
    sol_account_destroy(payer_account);

    sol_account_t* mint_account = sol_account_new(1, SOL_TOKEN_MINT_SIZE, &token_program);
    TEST_ASSERT_NOT_NULL(mint_account);
    sol_token_mint_t mint_state = {0};
    mint_state.is_initialized = true;
    memcpy(mint_account->data, &mint_state, sizeof(mint_state));
    TEST_ASSERT_EQ(sol_bank_store_account(bank, &mint, mint_account), SOL_OK);
    sol_account_destroy(mint_account);

    /* Build an ATA create with an extra "dummy" program at index 5.
     * The associated token program should locate the real token program by mint owner. */
    sol_pubkey_t ata = {0};
    TEST_ASSERT_EQ(sol_get_associated_token_address(&wallet, &mint, &token_program, &ata), SOL_OK);

    sol_pubkey_t keys[7] = {
        payer,               /* 0 */
        ata,                 /* 1 */
        wallet,              /* 2 */
        mint,                /* 3 */
        SOL_SYSTEM_PROGRAM_ID, /* 4 */
        dummy,               /* 5 */
        token_program,       /* 6 */
    };
    uint8_t indices[7] = {0, 1, 2, 3, 4, 5, 6};

    sol_invoke_context_t ctx = {0};
    ctx.bank = bank;
    ctx.account_keys = keys;
    ctx.account_keys_len = 7;
    ctx.account_indices = indices;
    ctx.account_indices_len = 7;
    ctx.instruction_data = NULL;
    ctx.instruction_data_len = 0;
    ctx.program_id = SOL_ASSOCIATED_TOKEN_PROGRAM_ID;
    ctx.num_signers = 1;
    ctx.stack_height = 1;

    sol_err_t err = sol_program_execute(&ctx);
    TEST_ASSERT_EQ(err, SOL_OK);

    sol_account_t* created = sol_bank_load_account(bank, &ata);
    TEST_ASSERT_NOT_NULL(created);
    TEST_ASSERT(sol_pubkey_eq(&created->meta.owner, &token_program));
    TEST_ASSERT_EQ(created->meta.data_len, SOL_TOKEN_ACCOUNT_SIZE);
    sol_token_account_t* token_acc = (sol_token_account_t*)created->data;
    TEST_ASSERT(sol_pubkey_eq(&token_acc->mint, &mint));
    TEST_ASSERT(sol_pubkey_eq(&token_acc->owner, &wallet));
    sol_account_destroy(created);

    sol_account_t* payer_loaded = sol_bank_load_account(bank, &payer);
    TEST_ASSERT_NOT_NULL(payer_loaded);
    TEST_ASSERT_EQ(payer_loaded->meta.lamports, 1234);
    sol_account_destroy(payer_loaded);

    sol_bank_destroy(bank);
}

static inline void
write_u16_le(uint8_t* out, uint16_t v) {
    out[0] = (uint8_t)(v & 0xFF);
    out[1] = (uint8_t)((v >> 8) & 0xFF);
}

TEST(ed25519_precompile_cross_instruction_offsets) {
    sol_bank_t* bank = sol_bank_new(0, NULL, NULL, NULL);
    TEST_ASSERT_NOT_NULL(bank);

    /* Create a deterministic keypair + signature */
    uint8_t seed[32];
    for (size_t i = 0; i < sizeof(seed); i++) {
        seed[i] = (uint8_t)i;
    }

    sol_keypair_t keypair = {0};
    sol_ed25519_keypair_from_seed(seed, &keypair);

    sol_pubkey_t pubkey = {0};
    sol_ed25519_pubkey_from_keypair(&keypair, &pubkey);

    const uint8_t message[] = "solana-c ed25519 cross-instruction";
    sol_signature_t sig = {0};
    sol_ed25519_sign(&keypair, message, sizeof(message) - 1, &sig);

    /* Instruction 0 packs signature + pubkey + message. */
    size_t ix0_len = SOL_ED25519_SIGNATURE_SIZE + SOL_ED25519_PUBKEY_SIZE + (sizeof(message) - 1);
    uint8_t* ix0_data = sol_alloc(ix0_len);
    TEST_ASSERT_NOT_NULL(ix0_data);
    memcpy(ix0_data + 0, sig.bytes, SOL_ED25519_SIGNATURE_SIZE);
    memcpy(ix0_data + SOL_ED25519_SIGNATURE_SIZE, pubkey.bytes, SOL_ED25519_PUBKEY_SIZE);
    memcpy(ix0_data + SOL_ED25519_SIGNATURE_SIZE + SOL_ED25519_PUBKEY_SIZE, message, sizeof(message) - 1);

    /* Instruction 1 is the Ed25519 precompile, referencing instruction 0. */
    uint8_t ix1_data[2 + SOL_ED25519_SIGNATURE_OFFSETS_SERIALIZED_SIZE] = {0};
    ix1_data[0] = 1; /* one signature */
    ix1_data[1] = 0; /* padding */

    uint8_t* entry = ix1_data + SOL_ED25519_SIGNATURE_OFFSETS_START;
    write_u16_le(entry + 0, 0); /* sig_offset */
    write_u16_le(entry + 2, 0); /* sig_ix */
    write_u16_le(entry + 4, (uint16_t)SOL_ED25519_SIGNATURE_SIZE); /* pk_offset */
    write_u16_le(entry + 6, 0); /* pk_ix */
    write_u16_le(entry + 8, (uint16_t)(SOL_ED25519_SIGNATURE_SIZE + SOL_ED25519_PUBKEY_SIZE)); /* msg_offset */
    write_u16_le(entry + 10, (uint16_t)(sizeof(message) - 1)); /* msg_size */
    write_u16_le(entry + 12, 0); /* msg_ix */

    /* Build a minimal transaction so we can serialize the instructions sysvar. */
    sol_transaction_t tx = {0};
    sol_transaction_init(&tx);

    sol_pubkey_t dummy_program = {0};
    make_pubkey(&dummy_program, 0xAB);

    sol_pubkey_t keys[2] = {dummy_program, SOL_ED25519_PROGRAM_ID};
    tx.message.account_keys = keys;
    tx.message.account_keys_len = 2;
    tx.message.resolved_accounts = keys;
    tx.message.resolved_accounts_len = 2;
    tx.message.header.num_required_signatures = 0;
    tx.message.instructions = tx.message.instructions_storage;
    tx.message.instructions_len = 2;

    uint8_t empty_accounts = 0;
    tx.message.instructions_storage[0] = (sol_compiled_instruction_t){
        .program_id_index = 0,
        .account_indices = &empty_accounts,
        .account_indices_len = 0,
        .data = ix0_data,
        .data_len = (uint16_t)ix0_len,
    };
    tx.message.instructions_storage[1] = (sol_compiled_instruction_t){
        .program_id_index = 1,
        .account_indices = &empty_accounts,
        .account_indices_len = 0,
        .data = ix1_data,
        .data_len = (uint16_t)sizeof(ix1_data),
    };

    uint8_t scratch[1];
    size_t sysvar_len = sizeof(scratch);
    sol_err_t err = sol_instructions_sysvar_serialize(&tx, 1, scratch, &sysvar_len);
    TEST_ASSERT_EQ(err, SOL_ERR_INVAL);
    TEST_ASSERT_GT(sysvar_len, 0);

    uint8_t* sysvar_data = sol_alloc(sysvar_len);
    TEST_ASSERT_NOT_NULL(sysvar_data);
    size_t written = sysvar_len;
    TEST_ASSERT_EQ(sol_instructions_sysvar_serialize(&tx, 1, sysvar_data, &written), SOL_OK);

    sol_account_t* sysvar_account = sol_account_new(1, written, &SOL_SYSVAR_PROGRAM_ID);
    TEST_ASSERT_NOT_NULL(sysvar_account);
    memcpy(sysvar_account->data, sysvar_data, written);
    TEST_ASSERT_EQ(sol_bank_store_account(bank, &SOL_SYSVAR_INSTRUCTIONS_ID, sysvar_account), SOL_OK);
    sol_account_destroy(sysvar_account);

    /* Execute the precompile. */
    sol_invoke_context_t ctx = {0};
    ctx.bank = bank;
    ctx.instruction_data = ix1_data;
    ctx.instruction_data_len = (uint16_t)sizeof(ix1_data);
    ctx.program_id = SOL_ED25519_PROGRAM_ID;

    TEST_ASSERT_EQ(sol_program_execute(&ctx), SOL_OK);

    sol_free(sysvar_data);
    sol_free(ix0_data);
    sol_bank_destroy(bank);
}

TEST(secp256k1_precompile_cross_instruction_offsets) {
#ifndef SOL_HAS_SECP256K1
    TEST_SKIP("libsecp256k1 not available");
#else
    sol_bank_t* bank = sol_bank_new(0, NULL, NULL, NULL);
    TEST_ASSERT_NOT_NULL(bank);

    /* Deterministic secp key */
    uint8_t seckey[32];
    memset(seckey, 7, sizeof(seckey));
    secp256k1_context* secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    TEST_ASSERT_NOT_NULL(secp_ctx);
    TEST_ASSERT(secp256k1_ec_seckey_verify(secp_ctx, seckey));

    const uint8_t message[] = "solana-c secp256k1 cross-instruction";
    sol_keccak256_t msg_hash;
    sol_keccak256_hash(message, sizeof(message) - 1, &msg_hash);

    secp256k1_ecdsa_recoverable_signature sig;
    TEST_ASSERT(secp256k1_ecdsa_sign_recoverable(
        secp_ctx, &sig, msg_hash.bytes, seckey, NULL, NULL));

    uint8_t sig64[SOL_SECP256K1_SIGNATURE_SIZE];
    int recid = 0;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(secp_ctx, sig64, &recid, &sig);

    uint8_t sig65[SOL_SECP256K1_SIGNATURE_SIZE + 1];
    memcpy(sig65, sig64, SOL_SECP256K1_SIGNATURE_SIZE);
    sig65[SOL_SECP256K1_SIGNATURE_SIZE] = (uint8_t)recid;

    /* Compute expected eth address from pubkey */
    secp256k1_pubkey pubkey;
    TEST_ASSERT(secp256k1_ec_pubkey_create(secp_ctx, &pubkey, seckey));

    uint8_t pubkey65[65];
    size_t pubkey65_len = sizeof(pubkey65);
    TEST_ASSERT(secp256k1_ec_pubkey_serialize(
        secp_ctx, pubkey65, &pubkey65_len, &pubkey, SECP256K1_EC_UNCOMPRESSED));
    TEST_ASSERT_EQ(pubkey65_len, sizeof(pubkey65));

    sol_keccak256_t pub_hash;
    sol_keccak256_hash(pubkey65 + 1, 64, &pub_hash);
    uint8_t eth_addr[SOL_SECP256K1_ETH_ADDRESS_SIZE];
    memcpy(eth_addr, pub_hash.bytes + 12, SOL_SECP256K1_ETH_ADDRESS_SIZE);

    size_t ix0_len = (SOL_SECP256K1_SIGNATURE_SIZE + 1) + SOL_SECP256K1_ETH_ADDRESS_SIZE + (sizeof(message) - 1);
    uint8_t* ix0_data = sol_alloc(ix0_len);
    TEST_ASSERT_NOT_NULL(ix0_data);
    size_t off_sig = 0;
    size_t off_addr = off_sig + (SOL_SECP256K1_SIGNATURE_SIZE + 1);
    size_t off_msg = off_addr + SOL_SECP256K1_ETH_ADDRESS_SIZE;
    memcpy(ix0_data + off_sig, sig65, SOL_SECP256K1_SIGNATURE_SIZE + 1);
    memcpy(ix0_data + off_addr, eth_addr, SOL_SECP256K1_ETH_ADDRESS_SIZE);
    memcpy(ix0_data + off_msg, message, sizeof(message) - 1);

    /* Precompile instruction referencing instruction 0 */
    uint8_t ix1_data[1 + SOL_SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE] = {0};
    ix1_data[0] = 1; /* one signature */
    uint8_t* entry = ix1_data + SOL_SECP256K1_SIGNATURE_OFFSETS_START;
    write_u16_le(entry + 0, (uint16_t)off_sig);
    entry[2] = 0; /* sig_ix */
    write_u16_le(entry + 3, (uint16_t)off_addr);
    entry[5] = 0; /* addr_ix */
    write_u16_le(entry + 6, (uint16_t)off_msg);
    write_u16_le(entry + 8, (uint16_t)(sizeof(message) - 1));
    entry[10] = 0; /* msg_ix */

    sol_transaction_t tx = {0};
    sol_transaction_init(&tx);

    sol_pubkey_t dummy_program = {0};
    make_pubkey(&dummy_program, 0xCD);

    sol_pubkey_t keys[2] = {dummy_program, SOL_SECP256K1_PROGRAM_ID};
    tx.message.account_keys = keys;
    tx.message.account_keys_len = 2;
    tx.message.resolved_accounts = keys;
    tx.message.resolved_accounts_len = 2;
    tx.message.header.num_required_signatures = 0;
    tx.message.instructions = tx.message.instructions_storage;
    tx.message.instructions_len = 2;

    uint8_t empty_accounts = 0;
    tx.message.instructions_storage[0] = (sol_compiled_instruction_t){
        .program_id_index = 0,
        .account_indices = &empty_accounts,
        .account_indices_len = 0,
        .data = ix0_data,
        .data_len = (uint16_t)ix0_len,
    };
    tx.message.instructions_storage[1] = (sol_compiled_instruction_t){
        .program_id_index = 1,
        .account_indices = &empty_accounts,
        .account_indices_len = 0,
        .data = ix1_data,
        .data_len = (uint16_t)sizeof(ix1_data),
    };

    uint8_t scratch[1];
    size_t sysvar_len = sizeof(scratch);
    sol_err_t err = sol_instructions_sysvar_serialize(&tx, 1, scratch, &sysvar_len);
    TEST_ASSERT_EQ(err, SOL_ERR_INVAL);
    TEST_ASSERT_GT(sysvar_len, 0);

    uint8_t* sysvar_data = sol_alloc(sysvar_len);
    TEST_ASSERT_NOT_NULL(sysvar_data);
    size_t written = sysvar_len;
    TEST_ASSERT_EQ(sol_instructions_sysvar_serialize(&tx, 1, sysvar_data, &written), SOL_OK);

    sol_account_t* sysvar_account = sol_account_new(1, written, &SOL_SYSVAR_PROGRAM_ID);
    TEST_ASSERT_NOT_NULL(sysvar_account);
    memcpy(sysvar_account->data, sysvar_data, written);
    TEST_ASSERT_EQ(sol_bank_store_account(bank, &SOL_SYSVAR_INSTRUCTIONS_ID, sysvar_account), SOL_OK);
    sol_account_destroy(sysvar_account);

    sol_invoke_context_t ctx = {0};
    ctx.bank = bank;
    ctx.instruction_data = ix1_data;
    ctx.instruction_data_len = (uint16_t)sizeof(ix1_data);
    ctx.program_id = SOL_SECP256K1_PROGRAM_ID;
    TEST_ASSERT_EQ(sol_program_execute(&ctx), SOL_OK);

    sol_free(sysvar_data);
    sol_free(ix0_data);
    secp256k1_context_destroy(secp_ctx);
    sol_bank_destroy(bank);
#endif
}

/*
 * System Program tests
 */

TEST(system_program_id) {
    /* System program ID should be all zeros */
    sol_pubkey_t expected;
    memset(expected.bytes, 0, 32);
    TEST_ASSERT(sol_pubkey_eq(&SOL_SYSTEM_PROGRAM_ID, &expected));
}

TEST(program_dispatch_compute_meter) {
    /* ComputeBudget program base CU (150) */
    {
        sol_compute_meter_t meter;
        sol_compute_meter_init(&meter, 1000);

        sol_invoke_context_t ctx = {0};
        ctx.program_id = SOL_COMPUTE_BUDGET_ID;
        ctx.compute_meter = &meter;

        sol_err_t err = sol_program_execute(&ctx);
        TEST_ASSERT_EQ(err, SOL_OK);
        TEST_ASSERT_EQ(meter.consumed, 150);
        TEST_ASSERT_EQ(meter.remaining, 850);
    }

    /* System program base CU (150) */
    {
        sol_bank_t* bank = sol_bank_new(0, NULL, NULL, NULL);
        TEST_ASSERT_NOT_NULL(bank);

        sol_pubkey_t from;
        sol_pubkey_t to;
        make_pubkey(&from, 0x01);
        make_pubkey(&to, 0x02);

        sol_account_t* from_account = sol_account_new(100, 0, &SOL_SYSTEM_PROGRAM_ID);
        sol_account_t* to_account = sol_account_new(0, 0, &SOL_SYSTEM_PROGRAM_ID);
        TEST_ASSERT_NOT_NULL(from_account);
        TEST_ASSERT_NOT_NULL(to_account);

        sol_err_t err = sol_bank_store_account(bank, &from, from_account);
        TEST_ASSERT_EQ(err, SOL_OK);
        err = sol_bank_store_account(bank, &to, to_account);
        TEST_ASSERT_EQ(err, SOL_OK);

        sol_account_destroy(from_account);
        sol_account_destroy(to_account);

        uint8_t account_indices[2] = {0, 1};
        sol_pubkey_t keys[2] = {from, to};

        uint8_t ix_data[12];
        uint32_t instr = SOL_SYSTEM_INSTR_TRANSFER;
        uint64_t lamports = 1;
        memcpy(ix_data, &instr, 4);
        memcpy(ix_data + 4, &lamports, 8);

        sol_compute_meter_t meter;
        sol_compute_meter_init(&meter, 1000);

        sol_invoke_context_t ctx = {0};
        ctx.bank = bank;
        ctx.account_keys = keys;
        ctx.account_keys_len = 2;
        ctx.account_indices = account_indices;
        ctx.account_indices_len = 2;
        ctx.instruction_data = ix_data;
        ctx.instruction_data_len = sizeof(ix_data);
        ctx.program_id = SOL_SYSTEM_PROGRAM_ID;
        ctx.num_signers = 1;
        ctx.stack_height = 1;
        ctx.compute_meter = &meter;

        err = sol_program_execute(&ctx);
        TEST_ASSERT_EQ(err, SOL_OK);
        TEST_ASSERT_EQ(meter.consumed, 150);
        TEST_ASSERT_EQ(meter.remaining, 850);

        sol_account_t* loaded_from = sol_bank_load_account(bank, &from);
        sol_account_t* loaded_to = sol_bank_load_account(bank, &to);
        TEST_ASSERT_NOT_NULL(loaded_from);
        TEST_ASSERT_NOT_NULL(loaded_to);
        TEST_ASSERT_EQ(loaded_from->meta.lamports, 99);
        TEST_ASSERT_EQ(loaded_to->meta.lamports, 1);
        sol_account_destroy(loaded_from);
        sol_account_destroy(loaded_to);

        sol_bank_destroy(bank);
    }
}

TEST(system_create_account_instruction) {
    sol_pubkey_t from, to, owner;
    make_pubkey(&from, 0x01);
    make_pubkey(&to, 0x02);
    make_pubkey(&owner, 0x03);

    uint8_t data[128];
    size_t len = sizeof(data);  /* Initialize with buffer size */

    sol_err_t err = sol_system_create_account_instruction(
        &from, &to, 1000000000ULL, 100, &owner, data, &len);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_GT(len, 0);

    /* First 4 bytes should be instruction type (0 = CreateAccount) */
    uint32_t instr_type;
    memcpy(&instr_type, data, 4);
    TEST_ASSERT_EQ(instr_type, SOL_SYSTEM_INSTR_CREATE_ACCOUNT);
}

TEST(system_transfer_instruction) {
    sol_pubkey_t from, to;
    make_pubkey(&from, 0x01);
    make_pubkey(&to, 0x02);

    uint8_t data[64];
    size_t len = sizeof(data);  /* Initialize with buffer size */

    sol_err_t err = sol_system_transfer_instruction(
        &from, &to, 500000000ULL, data, &len);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_GT(len, 0);

    /* First 4 bytes should be instruction type (2 = Transfer) */
    uint32_t instr_type;
    memcpy(&instr_type, data, 4);
    TEST_ASSERT_EQ(instr_type, SOL_SYSTEM_INSTR_TRANSFER);
}

TEST(system_assign_instruction) {
    sol_pubkey_t account, owner;
    make_pubkey(&account, 0x01);
    make_pubkey(&owner, 0x02);

    uint8_t data[64];
    size_t len = sizeof(data);  /* Initialize with buffer size */

    sol_err_t err = sol_system_assign_instruction(&account, &owner, data, &len);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_GT(len, 0);

    /* First 4 bytes should be instruction type (1 = Assign) */
    uint32_t instr_type;
    memcpy(&instr_type, data, 4);
    TEST_ASSERT_EQ(instr_type, SOL_SYSTEM_INSTR_ASSIGN);
}

TEST(system_allocate_instruction) {
    sol_pubkey_t account;
    make_pubkey(&account, 0x01);

    uint8_t data[64];
    size_t len = sizeof(data);  /* Initialize with buffer size */

    sol_err_t err = sol_system_allocate_instruction(&account, 200, data, &len);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_GT(len, 0);

    /* First 4 bytes should be instruction type (8 = Allocate) */
    uint32_t instr_type;
    memcpy(&instr_type, data, 4);
    TEST_ASSERT_EQ(instr_type, SOL_SYSTEM_INSTR_ALLOCATE);
}

TEST(system_create_with_seed) {
    sol_pubkey_t base, program_id, result;
    make_pubkey(&base, 0x01);
    make_pubkey(&program_id, 0x02);

    sol_err_t err = sol_create_with_seed(&base, "test_seed", 9, &program_id, &result);
    TEST_ASSERT_EQ(err, SOL_OK);

    /* Result should be deterministic */
    sol_pubkey_t result2;
    err = sol_create_with_seed(&base, "test_seed", 9, &program_id, &result2);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT(sol_pubkey_eq(&result, &result2));

    /* Different seed should give different result */
    sol_pubkey_t result3;
    err = sol_create_with_seed(&base, "other_seed", 10, &program_id, &result3);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT(!sol_pubkey_eq(&result, &result3));
}

/*
 * BPF Upgradeable Loader tests
 */

TEST(bpf_upgradeable_extend_program_reallocates_and_funds_rent) {
    /* Set up a minimal bank + accounts and execute ExtendProgram. */
    sol_bank_t* bank = sol_bank_new(0, NULL, NULL, NULL);
    TEST_ASSERT_NOT_NULL(bank);

    sol_pubkey_t authority;
    sol_pubkey_t payer;
    sol_pubkey_t program_data;
    make_pubkey(&authority, 0xA1);
    make_pubkey(&payer, 0xB2);
    make_pubkey(&program_data, 0xC3);

    /* ProgramData account with upgrade authority set. */
    const size_t programdata_meta_len = 4u + 8u + 32u + 1u;
    uint64_t old_rent_min = sol_bank_rent_exempt_minimum(bank, programdata_meta_len);
    sol_account_t* pd = sol_account_new(old_rent_min, programdata_meta_len, &SOL_BPF_LOADER_UPGRADEABLE_ID);
    TEST_ASSERT_NOT_NULL(pd);
    uint32_t typ = 3; /* PROGRAM_DATA */
    memcpy(pd->data, &typ, 4);
    uint64_t deployed_slot = 0;
    memcpy(pd->data + 4, &deployed_slot, 8);
    memcpy(pd->data + 12, authority.bytes, 32);
    pd->data[12 + 32] = 1; /* has_upgrade_authority */
    TEST_ASSERT_EQ(sol_bank_store_account(bank, &program_data, pd), SOL_OK);
    sol_account_destroy(pd);

    /* Payer and authority accounts. */
    uint64_t payer_start = 10ULL * 1000ULL * 1000ULL * 1000ULL; /* 10B lamports */
    sol_account_t* payer_acct = sol_account_new(payer_start, 0, &SOL_SYSTEM_PROGRAM_ID);
    TEST_ASSERT_NOT_NULL(payer_acct);
    TEST_ASSERT_EQ(sol_bank_store_account(bank, &payer, payer_acct), SOL_OK);
    sol_account_destroy(payer_acct);

    sol_account_t* authority_acct = sol_account_new(0, 0, &SOL_SYSTEM_PROGRAM_ID);
    TEST_ASSERT_NOT_NULL(authority_acct);
    TEST_ASSERT_EQ(sol_bank_store_account(bank, &authority, authority_acct), SOL_OK);
    sol_account_destroy(authority_acct);

    /* Invoke ExtendProgram: accounts = [programdata, payer, authority]. */
    sol_pubkey_t keys[3] = {authority, payer, program_data};
    uint8_t account_indices[3] = {2, 1, 0};

    uint8_t ix_data[8] = {0};
    uint32_t instr = 6; /* ExtendProgram */
    uint32_t additional = 100;
    memcpy(ix_data, &instr, 4);
    memcpy(ix_data + 4, &additional, 4);

    sol_invoke_context_t ctx = {0};
    ctx.bank = bank;
    ctx.program_id = SOL_BPF_LOADER_UPGRADEABLE_ID;
    ctx.account_keys = keys;
    ctx.account_keys_len = 3;
    ctx.account_indices = account_indices;
    ctx.account_indices_len = 3;
    ctx.instruction_data = ix_data;
    ctx.instruction_data_len = sizeof(ix_data);
    ctx.num_signers = 2; /* authority + payer */
    ctx.stack_height = 1;

    sol_err_t err = sol_bpf_upgradeable_loader_process(&ctx);
    TEST_ASSERT_EQ(err, SOL_OK);

    sol_account_t* pd_after = sol_bank_load_account(bank, &program_data);
    TEST_ASSERT_NOT_NULL(pd_after);
    TEST_ASSERT_EQ(pd_after->meta.data_len, programdata_meta_len + (size_t)additional);

    /* Ensure new bytes are zero-initialized. */
    for (size_t i = programdata_meta_len; i < pd_after->meta.data_len; i++) {
        TEST_ASSERT_EQ(pd_after->data[i], 0);
    }

    uint64_t rent_min = sol_bank_rent_exempt_minimum(bank, pd_after->meta.data_len);
    TEST_ASSERT_EQ(pd_after->meta.lamports, rent_min);
    sol_account_destroy(pd_after);

    sol_account_t* payer_after = sol_bank_load_account(bank, &payer);
    TEST_ASSERT_NOT_NULL(payer_after);
    TEST_ASSERT_EQ(payer_after->meta.lamports, payer_start - (rent_min - old_rent_min));
    sol_account_destroy(payer_after);

    sol_bank_destroy(bank);
}

/*
 * Vote Program tests
 */

TEST(vote_program_id) {
    /* Vote program ID check - should be non-zero */
    bool all_zero = true;
    for (int i = 0; i < 32; i++) {
        if (SOL_VOTE_PROGRAM_ID.bytes[i] != 0) {
            all_zero = false;
            break;
        }
    }
    TEST_ASSERT(!all_zero);
}

TEST(vote_state_init) {
    sol_vote_state_t state;
    sol_vote_init_t init;

    make_pubkey(&init.node_pubkey, 0x01);
    make_pubkey(&init.authorized_voter, 0x02);
    make_pubkey(&init.authorized_withdrawer, 0x03);
    init.commission = 10;

    sol_vote_state_init(&state, &init);

    TEST_ASSERT(sol_pubkey_eq(&state.node_pubkey, &init.node_pubkey));
    TEST_ASSERT(sol_pubkey_eq(&state.authorized_voter, &init.authorized_voter));
    TEST_ASSERT(sol_pubkey_eq(&state.authorized_withdrawer, &init.authorized_withdrawer));
    TEST_ASSERT_EQ(state.commission, 10);
    TEST_ASSERT_EQ(state.votes_len, 0);
    TEST_ASSERT_EQ(state.has_root, false);
}

TEST(vote_process_basic) {
    sol_vote_state_t state;
    sol_vote_init_t init;

    make_pubkey(&init.node_pubkey, 0x01);
    init.authorized_voter = init.node_pubkey;
    init.authorized_withdrawer = init.node_pubkey;
    init.commission = 0;

    sol_vote_state_init(&state, &init);

    /* Vote for slot 100 */
    sol_slot_t slots[1] = {100};
    sol_hash_t hash;
    memset(hash.bytes, 0xAB, 32);

    sol_vote_t vote = {
        .slots = slots,
        .slots_len = 1,
        .hash = hash,
        .has_timestamp = false,
    };

    sol_err_t err = sol_vote_state_process_vote(&state, &vote, 100, 0);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_EQ(state.votes_len, 1);
    TEST_ASSERT_EQ(state.votes[0].slot, 100);
    TEST_ASSERT_EQ(state.votes[0].confirmation_count, 1);
}

TEST(vote_process_multiple) {
    sol_vote_state_t state;
    sol_vote_init_t init;

    make_pubkey(&init.node_pubkey, 0x01);
    init.authorized_voter = init.node_pubkey;
    init.authorized_withdrawer = init.node_pubkey;
    init.commission = 0;

    sol_vote_state_init(&state, &init);

    sol_hash_t hash;
    memset(hash.bytes, 0xAB, 32);

    /*
     * Vote for slots that respect lockout periods.
     * Initial lockout is 2, so we can vote for 100, then 102, then 104, etc.
     * After each vote, lockout doubles (Tower BFT).
     */
    sol_slot_t test_slots[] = {100, 102, 104, 108, 116};  /* Each respects previous lockout */

    for (size_t i = 0; i < sizeof(test_slots)/sizeof(test_slots[0]); i++) {
        sol_slot_t slots[1] = {test_slots[i]};
        sol_vote_t vote = {
            .slots = slots,
            .slots_len = 1,
            .hash = hash,
            .has_timestamp = false,
        };
        sol_err_t err = sol_vote_state_process_vote(&state, &vote, test_slots[i], 0);
        (void)err;  /* May fail due to lockouts - that's OK */
    }

    /* Should have at least 1 vote (the first one) */
    TEST_ASSERT_GE(state.votes_len, 1);
}

TEST(vote_lockout_calculation) {
    sol_vote_state_t state;
    sol_vote_init_t init;

    make_pubkey(&init.node_pubkey, 0x01);
    init.authorized_voter = init.node_pubkey;
    init.authorized_withdrawer = init.node_pubkey;
    init.commission = 0;

    sol_vote_state_init(&state, &init);

    sol_hash_t hash;
    memset(hash.bytes, 0xAB, 32);

    /* Add multiple votes to build up confirmations */
    for (sol_slot_t s = 100; s < 110; s++) {
        sol_slot_t slots[1] = {s};
        sol_vote_t vote = {
            .slots = slots,
            .slots_len = 1,
            .hash = hash,
            .has_timestamp = false,
        };
        sol_vote_state_process_vote(&state, &vote, s, 0);
    }

    /* Verify votes were recorded */
    TEST_ASSERT_GT(state.votes_len, 0);

    /* First vote should have confirmation count >= 1 */
    TEST_ASSERT_GE(state.votes[0].confirmation_count, 1);

    /* Check lockout is at least the initial value */
    uint64_t lockout = sol_vote_state_lockout(&state, state.votes[0].slot);
    TEST_ASSERT_GE(lockout, SOL_INITIAL_LOCKOUT);  /* At least 2 */
}

TEST(vote_root_advancement) {
    sol_vote_state_t state;
    sol_vote_init_t init;

    make_pubkey(&init.node_pubkey, 0x01);
    init.authorized_voter = init.node_pubkey;
    init.authorized_withdrawer = init.node_pubkey;
    init.commission = 0;

    sol_vote_state_init(&state, &init);

    sol_hash_t hash;
    memset(hash.bytes, 0xAB, 32);

    /* Vote for many consecutive slots to advance root */
    for (sol_slot_t s = 0; s < SOL_MAX_LOCKOUT_HISTORY + 5; s++) {
        sol_slot_t slots[1] = {s};
        sol_vote_t vote = {
            .slots = slots,
            .slots_len = 1,
            .hash = hash,
            .has_timestamp = false,
        };
        sol_vote_state_process_vote(&state, &vote, s, 0);
    }

    /* Root should have been established */
    TEST_ASSERT(state.has_root);
    TEST_ASSERT_GT(state.root_slot, 0);
}

TEST(vote_serialization) {
    sol_vote_state_t state;
    sol_vote_init_t init;

    make_pubkey(&init.node_pubkey, 0x01);
    init.authorized_voter = init.node_pubkey;
    init.authorized_withdrawer = init.node_pubkey;
    init.commission = 5;

    sol_vote_state_init(&state, &init);

    /* Add some votes */
    sol_hash_t hash;
    memset(hash.bytes, 0xCD, 32);
    sol_slot_t slots[3] = {100, 101, 102};
    sol_vote_t vote = {
        .slots = slots,
        .slots_len = 3,
        .hash = hash,
        .has_timestamp = false,
    };
    sol_vote_state_process_vote(&state, &vote, 102, 0);

    /* Serialize */
    uint8_t buffer[SOL_VOTE_STATE_SIZE];
    size_t written;
    sol_err_t err = sol_vote_state_serialize(&state, buffer, sizeof(buffer), &written);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_GT(written, 0);

    /* Deserialize */
    sol_vote_state_t restored;
    err = sol_vote_state_deserialize(&restored, buffer, written);
    TEST_ASSERT_EQ(err, SOL_OK);

    /* Verify */
    TEST_ASSERT(sol_pubkey_eq(&restored.node_pubkey, &state.node_pubkey));
    TEST_ASSERT_EQ(restored.commission, state.commission);
    TEST_ASSERT_EQ(restored.votes_len, state.votes_len);
}

TEST(vote_state_bincode_v2_layout) {
    sol_vote_state_t state = {0};
    state.onchain_version = 2;

    make_pubkey(&state.node_pubkey, 0x11);
    make_pubkey(&state.authorized_withdrawer, 0x22);
    state.commission = 5;

    state.votes_len = 2;
    state.vote_latencies[0] = 1;
    state.votes[0].slot = 100;
    state.votes[0].confirmation_count = 31;
    state.vote_latencies[1] = 2;
    state.votes[1].slot = 101;
    state.votes[1].confirmation_count = 30;

    state.has_root = true;
    state.root_slot = 99;

    state.authorized_voters_len = 1;
    state.authorized_voters[0].epoch = 7;
    make_pubkey(&state.authorized_voters[0].pubkey, 0x33);
    state.authorized_voter = state.authorized_voters[0].pubkey;

    state.prior_voters_idx = 31;
    state.prior_voters_is_empty = true;

    state.epoch_credits_len = 1;
    state.epoch_credits[0].epoch = 7;
    state.epoch_credits[0].credits = 10;
    state.epoch_credits[0].prev_credits = 5;

    state.last_timestamp_slot = 101;
    state.last_timestamp = 12345;

    uint8_t buf[SOL_VOTE_STATE_SIZE];
    memset(buf, 0, sizeof(buf));
    size_t written = 0;
    TEST_ASSERT_EQ(sol_vote_state_serialize(&state, buf, sizeof(buf), &written), SOL_OK);
    TEST_ASSERT_GT(written, 0);

    /* prefix u32 */
    uint32_t prefix = (uint32_t)buf[0] |
                      ((uint32_t)buf[1] << 8) |
                      ((uint32_t)buf[2] << 16) |
                      ((uint32_t)buf[3] << 24);
    TEST_ASSERT_EQ(prefix, 2);

    /* commission at offset 4 + 32 + 32 */
    TEST_ASSERT_EQ(buf[4 + 32 + 32], 5);

    /* votes_len u64 at offset 4 + 32 + 32 + 1 */
    size_t off_votes_len = 4 + 32 + 32 + 1;
    uint64_t votes_len = 0;
    memcpy(&votes_len, buf + off_votes_len, 8);
    TEST_ASSERT_EQ(votes_len, 2);

    /* first vote begins after votes_len */
    size_t off_v0 = off_votes_len + 8;
    TEST_ASSERT_EQ(buf[off_v0], 1); /* latency */
    uint64_t slot0 = 0;
    memcpy(&slot0, buf + off_v0 + 1, 8);
    TEST_ASSERT_EQ(slot0, 100);
    uint32_t conf0 = 0;
    memcpy(&conf0, buf + off_v0 + 1 + 8, 4);
    TEST_ASSERT_EQ(conf0, 31);

    /* second vote */
    size_t off_v1 = off_v0 + 13;
    TEST_ASSERT_EQ(buf[off_v1], 2);
    uint64_t slot1 = 0;
    memcpy(&slot1, buf + off_v1 + 1, 8);
    TEST_ASSERT_EQ(slot1, 101);
    uint32_t conf1 = 0;
    memcpy(&conf1, buf + off_v1 + 1 + 8, 4);
    TEST_ASSERT_EQ(conf1, 30);

    /* root option tag after votes */
    size_t off_root_tag = off_v0 + 2 * 13;
    TEST_ASSERT_EQ(buf[off_root_tag], 1);
    uint64_t root_slot = 0;
    memcpy(&root_slot, buf + off_root_tag + 1, 8);
    TEST_ASSERT_EQ(root_slot, 99);

    /* authorized_voters map len */
    size_t off_av_len = off_root_tag + 1 + 8;
    uint64_t av_len = 0;
    memcpy(&av_len, buf + off_av_len, 8);
    TEST_ASSERT_EQ(av_len, 1);

    uint64_t av_epoch = 0;
    memcpy(&av_epoch, buf + off_av_len + 8, 8);
    TEST_ASSERT_EQ(av_epoch, 7);

    /* prior voters idx + is_empty are near the end; verify defaults survive */
    sol_vote_state_t roundtrip = {0};
    TEST_ASSERT_EQ(sol_vote_state_deserialize(&roundtrip, buf, sizeof(buf)), SOL_OK);
    TEST_ASSERT_EQ(roundtrip.onchain_version, 2);
    TEST_ASSERT_EQ(roundtrip.votes_len, 2);
    TEST_ASSERT_EQ(roundtrip.vote_latencies[0], 1);
    TEST_ASSERT_EQ(roundtrip.vote_latencies[1], 2);
    TEST_ASSERT(roundtrip.has_root);
    TEST_ASSERT_EQ(roundtrip.root_slot, 99);
    TEST_ASSERT_EQ(roundtrip.authorized_voters_len, 1);
    TEST_ASSERT_EQ(roundtrip.authorized_voters[0].epoch, 7);
    TEST_ASSERT(roundtrip.prior_voters_is_empty);
    TEST_ASSERT_EQ(roundtrip.prior_voters_idx, 31);
}

TEST(vote_state_bincode_v1_roundtrip) {
    sol_vote_state_t state = {0};
    state.onchain_version = 1;

    make_pubkey(&state.node_pubkey, 0x41);
    make_pubkey(&state.authorized_withdrawer, 0x42);
    state.commission = 10;

    state.votes_len = 1;
    state.votes[0].slot = 500;
    state.votes[0].confirmation_count = 3;

    state.has_root = false;

    state.authorized_voters_len = 1;
    state.authorized_voters[0].epoch = 1;
    make_pubkey(&state.authorized_voters[0].pubkey, 0x43);
    state.authorized_voter = state.authorized_voters[0].pubkey;

    state.prior_voters_idx = 31;
    state.prior_voters_is_empty = true;

    state.epoch_credits_len = 0;
    state.last_timestamp_slot = 0;
    state.last_timestamp = 0;

    uint8_t buf[3731];
    memset(buf, 0, sizeof(buf));
    size_t written = 0;
    TEST_ASSERT_EQ(sol_vote_state_serialize(&state, buf, sizeof(buf), &written), SOL_OK);
    TEST_ASSERT_GT(written, 0);

    uint32_t prefix = (uint32_t)buf[0] |
                      ((uint32_t)buf[1] << 8) |
                      ((uint32_t)buf[2] << 16) |
                      ((uint32_t)buf[3] << 24);
    TEST_ASSERT_EQ(prefix, 1);

    sol_vote_state_t restored = {0};
    TEST_ASSERT_EQ(sol_vote_state_deserialize(&restored, buf, sizeof(buf)), SOL_OK);
    TEST_ASSERT_EQ(restored.onchain_version, 1);
    TEST_ASSERT_EQ(restored.votes_len, 1);
    TEST_ASSERT_EQ(restored.votes[0].slot, 500);
    TEST_ASSERT_EQ(restored.votes[0].confirmation_count, 3);
}

TEST(vote_program_verifies_slot_hashes_sysvar) {
    sol_hash_t genesis_blockhash;
    memset(genesis_blockhash.bytes, 0xAA, sizeof(genesis_blockhash.bytes));

    sol_bank_t* parent = sol_bank_new(0, &genesis_blockhash, NULL, NULL);
    TEST_ASSERT_NOT_NULL(parent);

    sol_hash_t parent_bank_hash = {0};
    sol_bank_compute_hash(parent, &parent_bank_hash);
    TEST_ASSERT(!sol_hash_is_zero(&parent_bank_hash));

    sol_bank_t* bank = sol_bank_new_from_parent(parent, 1);
    TEST_ASSERT_NOT_NULL(bank);

    /* SlotHashes should include parent bank hash immediately. */
    sol_account_t* slot_hashes_account =
        sol_bank_load_account(bank, &SOL_SYSVAR_SLOT_HASHES_ID);
    TEST_ASSERT_NOT_NULL(slot_hashes_account);

    sol_slot_hashes_t slot_hashes;
    sol_slot_hashes_init(&slot_hashes);
    TEST_ASSERT_EQ(sol_slot_hashes_deserialize(&slot_hashes,
                                               slot_hashes_account->data,
                                               slot_hashes_account->meta.data_len),
                   SOL_OK);
    sol_account_destroy(slot_hashes_account);

    const sol_hash_t* sh = sol_slot_hashes_get(&slot_hashes, sol_bank_slot(parent));
    TEST_ASSERT_NOT_NULL(sh);
    TEST_ASSERT(sol_hash_eq(sh, &parent_bank_hash));

    /* Create a vote account with a matching authorized voter. */
    sol_pubkey_t authorized_voter;
    sol_pubkey_t vote_pubkey;
    sol_pubkey_t node_pubkey;
    make_pubkey(&authorized_voter, 0x21);
    make_pubkey(&vote_pubkey, 0x22);
    make_pubkey(&node_pubkey, 0x23);

    sol_account_t* vote_account =
        sol_account_new(1, SOL_VOTE_STATE_SIZE, &SOL_VOTE_PROGRAM_ID);
    TEST_ASSERT_NOT_NULL(vote_account);

    sol_vote_state_t state;
    sol_vote_init_t init = {0};
    init.node_pubkey = node_pubkey;
    init.authorized_voter = authorized_voter;
    init.authorized_withdrawer = authorized_voter;
    init.commission = 0;
    sol_vote_state_init(&state, &init);

    size_t written = 0;
    TEST_ASSERT_EQ(sol_vote_state_serialize(&state, vote_account->data,
                                            vote_account->meta.data_len, &written),
                   SOL_OK);
    TEST_ASSERT_GT(written, 0);

    TEST_ASSERT_EQ(sol_bank_store_account(bank, &vote_pubkey, vote_account), SOL_OK);
    sol_account_destroy(vote_account);

    /* Build a minimal legacy Vote instruction voting for parent slot. */
    uint8_t ix_data[4 + 8 + 8 + 32 + 1];
    uint32_t ix = SOL_VOTE_INSTR_VOTE;
    memcpy(ix_data, &ix, 4);
    uint64_t slots_len = 1;
    memcpy(ix_data + 4, &slots_len, 8);
    sol_slot_t voted_slot = sol_bank_slot(parent);
    memcpy(ix_data + 12, &voted_slot, 8);
    memcpy(ix_data + 20, parent_bank_hash.bytes, 32);
    ix_data[52] = 0; /* timestamp: None */

    sol_pubkey_t keys[4] = {
        authorized_voter,
        vote_pubkey,
        SOL_SYSVAR_SLOT_HASHES_ID,
        SOL_SYSVAR_CLOCK_ID,
    };
    uint8_t account_indices[4] = { 1, 2, 3, 0 };

    sol_invoke_context_t ctx = {0};
    ctx.bank = bank;
    ctx.account_keys = keys;
    ctx.account_keys_len = 4;
    ctx.account_indices = account_indices;
    ctx.account_indices_len = 4;
    ctx.instruction_data = ix_data;
    ctx.instruction_data_len = sizeof(ix_data);
    ctx.program_id = SOL_VOTE_PROGRAM_ID;
    ctx.num_signers = 1;
    ctx.stack_height = 1;

    sol_err_t err = sol_vote_program_execute(&ctx);
    TEST_ASSERT_EQ(err, SOL_OK);

    /* Wrong bank hash should be rejected. */
    sol_pubkey_t vote_pubkey_bad;
    make_pubkey(&vote_pubkey_bad, 0x24);
    vote_account = sol_account_new(1, SOL_VOTE_STATE_SIZE, &SOL_VOTE_PROGRAM_ID);
    TEST_ASSERT_NOT_NULL(vote_account);
    TEST_ASSERT_EQ(sol_vote_state_serialize(&state, vote_account->data,
                                            vote_account->meta.data_len, &written),
                   SOL_OK);
    TEST_ASSERT_EQ(sol_bank_store_account(bank, &vote_pubkey_bad, vote_account), SOL_OK);
    sol_account_destroy(vote_account);

    uint8_t ix_data_bad[sizeof(ix_data)];
    memcpy(ix_data_bad, ix_data, sizeof(ix_data_bad));
    ix_data_bad[20] ^= 0x01; /* corrupt hash */

    sol_pubkey_t keys_bad[4] = {
        authorized_voter,
        vote_pubkey_bad,
        SOL_SYSVAR_SLOT_HASHES_ID,
        SOL_SYSVAR_CLOCK_ID,
    };
    ctx.account_keys = keys_bad;
    ctx.instruction_data = ix_data_bad;

    err = sol_vote_program_execute(&ctx);
    TEST_ASSERT_EQ(err, SOL_ERR_SLOT_HASH_MISMATCH);

    sol_bank_destroy(bank);
    sol_bank_destroy(parent);
}

/*
 * Stake Program tests
 */

TEST(stake_program_id) {
    /* Stake program ID check - should be non-zero */
    bool all_zero = true;
    for (int i = 0; i < 32; i++) {
        if (SOL_STAKE_PROGRAM_ID.bytes[i] != 0) {
            all_zero = false;
            break;
        }
    }
    TEST_ASSERT(!all_zero);
}

TEST(stake_state_init) {
    sol_stake_state_t state;
    sol_stake_authorized_t authorized;
    sol_lockup_t lockup = {0};

    make_pubkey(&authorized.staker, 0x01);
    make_pubkey(&authorized.withdrawer, 0x02);

    sol_stake_state_init(&state, &authorized, &lockup, 1000000);

    TEST_ASSERT_EQ(state.state, SOL_STAKE_STATE_INITIALIZED);
    TEST_ASSERT(sol_pubkey_eq(&state.meta.authorized.staker, &authorized.staker));
    TEST_ASSERT(sol_pubkey_eq(&state.meta.authorized.withdrawer, &authorized.withdrawer));
    TEST_ASSERT_EQ(state.meta.rent_exempt_reserve, 1000000);
}

TEST(stake_delegate) {
    sol_stake_state_t state;
    sol_stake_authorized_t authorized;
    sol_lockup_t lockup = {0};
    sol_pubkey_t vote_pubkey;

    make_pubkey(&authorized.staker, 0x01);
    make_pubkey(&authorized.withdrawer, 0x02);
    make_pubkey(&vote_pubkey, 0x03);

    sol_stake_state_init(&state, &authorized, &lockup, 1000000);

    /* Delegate 5 SOL */
    sol_err_t err = sol_stake_delegate(&state, &vote_pubkey, 5000000000ULL, 100);
    TEST_ASSERT_EQ(err, SOL_OK);

    TEST_ASSERT_EQ(state.state, SOL_STAKE_STATE_STAKE);
    TEST_ASSERT(sol_pubkey_eq(&state.delegation.voter_pubkey, &vote_pubkey));
    TEST_ASSERT_EQ(state.delegation.stake, 5000000000ULL);
    TEST_ASSERT_EQ(state.delegation.activation_epoch, 100);
    TEST_ASSERT_EQ(state.delegation.deactivation_epoch, UINT64_MAX);
}

TEST(stake_deactivate) {
    sol_stake_state_t state;
    sol_stake_authorized_t authorized;
    sol_lockup_t lockup = {0};
    sol_pubkey_t vote_pubkey;

    make_pubkey(&authorized.staker, 0x01);
    make_pubkey(&authorized.withdrawer, 0x02);
    make_pubkey(&vote_pubkey, 0x03);

    sol_stake_state_init(&state, &authorized, &lockup, 1000000);
    sol_stake_delegate(&state, &vote_pubkey, 5000000000ULL, 100);

    /* Deactivate at epoch 150 */
    sol_err_t err = sol_stake_deactivate(&state, 150);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_EQ(state.delegation.deactivation_epoch, 150);
}

TEST(stake_effective_stake) {
    sol_stake_state_t state;
    sol_stake_authorized_t authorized;
    sol_lockup_t lockup = {0};
    sol_pubkey_t vote_pubkey;

    make_pubkey(&authorized.staker, 0x01);
    make_pubkey(&authorized.withdrawer, 0x02);
    make_pubkey(&vote_pubkey, 0x03);

    sol_stake_state_init(&state, &authorized, &lockup, 1000000);
    sol_stake_delegate(&state, &vote_pubkey, 5000000000ULL, 100);

    /* Before activation */
    uint64_t effective = sol_stake_effective_stake(&state, 99);
    TEST_ASSERT_EQ(effective, 0);

    /* At activation epoch - warmup starts */
    effective = sol_stake_effective_stake(&state, 100);
    TEST_ASSERT_GE(effective, 0);  /* Could be 0 or partial */

    /* One epoch after activation */
    effective = sol_stake_effective_stake(&state, 101);
    TEST_ASSERT_GT(effective, 0);

    /* Well after activation - should be fully active */
    effective = sol_stake_effective_stake(&state, 200);
    TEST_ASSERT_EQ(effective, 5000000000ULL);
}

TEST(stake_activation_status_with_history) {
    sol_stake_state_t state;
    memset(&state, 0, sizeof(state));
    state.state = SOL_STAKE_STATE_STAKE;
    state.delegation.stake = 1000;
    state.delegation.activation_epoch = 0;
    state.delegation.deactivation_epoch = UINT64_MAX;
    state.delegation.warmup_cooldown_rate = 0.2;

    sol_stake_history_t sh;
    sol_stake_history_init(&sh);

    sol_stake_history_entry_t e0 = {.effective = 2000, .activating = 1000, .deactivating = 0};
    sol_stake_history_entry_t e1 = {.effective = 2400, .activating = 600, .deactivating = 0};
    sol_stake_history_entry_t e2 = {.effective = 2880, .activating = 120, .deactivating = 0};
    sol_stake_history_entry_t e3 = {.effective = 3000, .activating = 0, .deactivating = 1000};
    sol_stake_history_entry_t e4 = {.effective = 2400, .activating = 0, .deactivating = 400};

    TEST_ASSERT_EQ(sol_stake_history_add(&sh, 0, &e0), SOL_OK);
    TEST_ASSERT_EQ(sol_stake_history_add(&sh, 1, &e1), SOL_OK);
    TEST_ASSERT_EQ(sol_stake_history_add(&sh, 2, &e2), SOL_OK);
    TEST_ASSERT_EQ(sol_stake_history_add(&sh, 3, &e3), SOL_OK);
    TEST_ASSERT_EQ(sol_stake_history_add(&sh, 4, &e4), SOL_OK);

    /* Warmup */
    sol_stake_activation_t status;
    TEST_ASSERT_EQ(sol_stake_get_activation_status(&state, 0, &sh, &status), SOL_OK);
    TEST_ASSERT_EQ(status.effective, 0);
    TEST_ASSERT_EQ(status.activating, 1000);
    TEST_ASSERT_EQ(status.deactivating, 0);

    TEST_ASSERT_EQ(sol_stake_get_activation_status(&state, 1, &sh, &status), SOL_OK);
    TEST_ASSERT_EQ(status.effective, 400);
    TEST_ASSERT_EQ(status.activating, 600);
    TEST_ASSERT_EQ(status.deactivating, 0);

    TEST_ASSERT_EQ(sol_stake_get_activation_status(&state, 2, &sh, &status), SOL_OK);
    TEST_ASSERT_EQ(status.effective, 880);
    TEST_ASSERT_EQ(status.activating, 120);
    TEST_ASSERT_EQ(status.deactivating, 0);

    TEST_ASSERT_EQ(sol_stake_get_activation_status(&state, 3, &sh, &status), SOL_OK);
    TEST_ASSERT_EQ(status.effective, 1000);
    TEST_ASSERT_EQ(status.activating, 0);
    TEST_ASSERT_EQ(status.deactivating, 0);

    /* Cooldown (deactivation at epoch 3) */
    state.delegation.deactivation_epoch = 3;

    TEST_ASSERT_EQ(sol_stake_get_activation_status(&state, 3, &sh, &status), SOL_OK);
    TEST_ASSERT_EQ(status.effective, 1000);
    TEST_ASSERT_EQ(status.activating, 0);
    TEST_ASSERT_EQ(status.deactivating, 1000);

    TEST_ASSERT_EQ(sol_stake_get_activation_status(&state, 4, &sh, &status), SOL_OK);
    TEST_ASSERT_EQ(status.effective, 400);
    TEST_ASSERT_EQ(status.activating, 0);
    TEST_ASSERT_EQ(status.deactivating, 400);

    TEST_ASSERT_EQ(sol_stake_get_activation_status(&state, 5, &sh, &status), SOL_OK);
    TEST_ASSERT_EQ(status.effective, 0);
    TEST_ASSERT_EQ(status.activating, 0);
    TEST_ASSERT_EQ(status.deactivating, 0);
}

TEST(stake_is_active) {
    sol_stake_state_t state;
    sol_stake_authorized_t authorized;
    sol_lockup_t lockup = {0};
    sol_pubkey_t vote_pubkey;

    make_pubkey(&authorized.staker, 0x01);
    make_pubkey(&authorized.withdrawer, 0x02);
    make_pubkey(&vote_pubkey, 0x03);

    sol_stake_state_init(&state, &authorized, &lockup, 1000000);

    /* Not delegated yet */
    TEST_ASSERT(!sol_stake_is_active(&state, 100));

    sol_stake_delegate(&state, &vote_pubkey, 5000000000ULL, 100);

    /* Check stake state was set correctly */
    TEST_ASSERT_EQ(state.state, SOL_STAKE_STATE_STAKE);
    TEST_ASSERT_EQ(state.delegation.activation_epoch, 100);
    TEST_ASSERT_EQ(state.delegation.deactivation_epoch, UINT64_MAX);

    /* Active after delegation (some epochs later after warmup) */
    TEST_ASSERT(sol_stake_is_active(&state, 200));

    /* Deactivate */
    sol_stake_deactivate(&state, 250);
    TEST_ASSERT_EQ(state.delegation.deactivation_epoch, 250);

    /* Check behavior at and after deactivation epoch */
    /* During cooldown, stake may or may not be considered "active"
       depending on implementation - just verify no crash */
    (void)sol_stake_is_active(&state, 250);
    (void)sol_stake_is_active(&state, 300);
}

TEST(stake_serialization) {
    sol_stake_state_t state;
    sol_stake_authorized_t authorized;
    sol_lockup_t lockup = {
        .unix_timestamp = 1234567890,
        .epoch = 50,
    };
    sol_pubkey_t vote_pubkey;

    make_pubkey(&authorized.staker, 0x01);
    make_pubkey(&authorized.withdrawer, 0x02);
    make_pubkey(&lockup.custodian, 0x04);
    make_pubkey(&vote_pubkey, 0x03);

    sol_stake_state_init(&state, &authorized, &lockup, 1000000);
    sol_stake_delegate(&state, &vote_pubkey, 5000000000ULL, 100);

    /* Serialize */
    uint8_t buffer[SOL_STAKE_STATE_SIZE];
    size_t written;
    sol_err_t err = sol_stake_state_serialize(&state, buffer, sizeof(buffer), &written);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_GT(written, 0);

    /* Deserialize */
    sol_stake_state_t restored;
    err = sol_stake_state_deserialize(&restored, buffer, written);
    TEST_ASSERT_EQ(err, SOL_OK);

    /* Verify */
    TEST_ASSERT_EQ(restored.state, state.state);
    TEST_ASSERT(sol_pubkey_eq(&restored.meta.authorized.staker, &authorized.staker));
    TEST_ASSERT_EQ(restored.delegation.stake, state.delegation.stake);
}

/*
 * Leader Schedule tests
 */

TEST(leader_schedule_new) {
    sol_stake_weight_t stakes[3] = {
        {.stake = 1000000000000ULL},  /* 1000 SOL */
        {.stake = 500000000000ULL},   /* 500 SOL */
        {.stake = 500000000000ULL},   /* 500 SOL */
    };
    make_pubkey(&stakes[0].pubkey, 0x01);
    make_pubkey(&stakes[1].pubkey, 0x02);
    make_pubkey(&stakes[2].pubkey, 0x03);

    sol_leader_schedule_config_t config = {
        .slots_per_epoch = 1000,
        .leader_schedule_slot_offset = 4,
    };

    sol_leader_schedule_t* schedule = sol_leader_schedule_new(5, stakes, 3, &config);
    TEST_ASSERT(schedule != NULL);

    TEST_ASSERT_EQ(sol_leader_schedule_epoch(schedule), 5);
    TEST_ASSERT_EQ(sol_leader_schedule_first_slot(schedule), 5000);
    TEST_ASSERT_EQ(sol_leader_schedule_last_slot(schedule), 5999);

    sol_leader_schedule_destroy(schedule);
}

TEST(leader_schedule_get_leader) {
    sol_stake_weight_t stakes[2] = {
        {.stake = 1000000000000ULL},
        {.stake = 1000000000000ULL},
    };
    make_pubkey(&stakes[0].pubkey, 0x01);
    make_pubkey(&stakes[1].pubkey, 0x02);

    sol_leader_schedule_config_t config = {
        .slots_per_epoch = 100,
        .leader_schedule_slot_offset = 4,
    };

    sol_leader_schedule_t* schedule = sol_leader_schedule_new(0, stakes, 2, &config);
    TEST_ASSERT(schedule != NULL);

    /* Get leader for various slots */
    const sol_pubkey_t* leader = sol_leader_schedule_get_leader(schedule, 0);
    TEST_ASSERT(leader != NULL);

    /* Slots 0-3 should have same leader (4 slots per leader) */
    const sol_pubkey_t* leader2 = sol_leader_schedule_get_leader(schedule, 1);
    const sol_pubkey_t* leader3 = sol_leader_schedule_get_leader(schedule, 2);
    const sol_pubkey_t* leader4 = sol_leader_schedule_get_leader(schedule, 3);
    TEST_ASSERT(sol_pubkey_eq(leader, leader2));
    TEST_ASSERT(sol_pubkey_eq(leader, leader3));
    TEST_ASSERT(sol_pubkey_eq(leader, leader4));

    /* Out of range should return NULL */
    leader = sol_leader_schedule_get_leader(schedule, 100);
    TEST_ASSERT(leader == NULL);

    sol_leader_schedule_destroy(schedule);
}

TEST(leader_schedule_is_leader) {
    sol_stake_weight_t stakes[1] = {
        {.stake = 1000000000000ULL},
    };
    make_pubkey(&stakes[0].pubkey, 0x01);

    sol_leader_schedule_config_t config = {
        .slots_per_epoch = 100,
        .leader_schedule_slot_offset = 4,
    };

    sol_leader_schedule_t* schedule = sol_leader_schedule_new(0, stakes, 1, &config);
    TEST_ASSERT(schedule != NULL);

    /* With only one validator, they should always be leader */
    TEST_ASSERT(sol_leader_schedule_is_leader(schedule, 0, &stakes[0].pubkey));
    TEST_ASSERT(sol_leader_schedule_is_leader(schedule, 50, &stakes[0].pubkey));

    /* Different pubkey should not be leader */
    sol_pubkey_t other;
    make_pubkey(&other, 0x02);
    TEST_ASSERT(!sol_leader_schedule_is_leader(schedule, 0, &other));

    sol_leader_schedule_destroy(schedule);
}

TEST(leader_schedule_stake_weighted) {
    /* Create validators with different stakes */
    sol_stake_weight_t stakes[2] = {
        {.stake = 900000000000ULL},  /* 90% stake */
        {.stake = 100000000000ULL},  /* 10% stake */
    };
    make_pubkey(&stakes[0].pubkey, 0x01);
    make_pubkey(&stakes[1].pubkey, 0x02);

    sol_leader_schedule_config_t config = {
        .slots_per_epoch = 4000,  /* Large enough for statistical distribution */
        .leader_schedule_slot_offset = 4,
    };

    sol_leader_schedule_t* schedule = sol_leader_schedule_new(0, stakes, 2, &config);
    TEST_ASSERT(schedule != NULL);

    /* Count leader slots for each validator */
    size_t count1 = 0, count2 = 0;
    for (sol_slot_t s = 0; s < 4000; s++) {
        const sol_pubkey_t* leader = sol_leader_schedule_get_leader(schedule, s);
        if (sol_pubkey_eq(leader, &stakes[0].pubkey)) count1++;
        else if (sol_pubkey_eq(leader, &stakes[1].pubkey)) count2++;
    }

    /* Validator with 90% stake should have more slots */
    TEST_ASSERT_GT(count1, count2);

    /* Ratio should be roughly 9:1 (allow some variance) */
    double ratio = (double)count1 / (double)count2;
    TEST_ASSERT_GT(ratio, 3.0);  /* Should be around 9, allow wide margin */

    sol_leader_schedule_destroy(schedule);
}

TEST(leader_schedule_num_leaders) {
    sol_stake_weight_t stakes[3] = {
        {.stake = 1000000000000ULL},
        {.stake = 1000000000000ULL},
        {.stake = 1000000000000ULL},
    };
    make_pubkey(&stakes[0].pubkey, 0x01);
    make_pubkey(&stakes[1].pubkey, 0x02);
    make_pubkey(&stakes[2].pubkey, 0x03);

    sol_leader_schedule_config_t config = {
        .slots_per_epoch = 1000,
        .leader_schedule_slot_offset = 4,
    };

    sol_leader_schedule_t* schedule = sol_leader_schedule_new(0, stakes, 3, &config);
    TEST_ASSERT(schedule != NULL);

    TEST_ASSERT_EQ(sol_leader_schedule_num_leaders(schedule), 3);

    sol_leader_schedule_destroy(schedule);
}

static sol_pubkey_t
pubkey_from_u16(uint16_t n) {
    sol_pubkey_t pk;
    memset(pk.bytes, 0, sizeof(pk.bytes));
    pk.bytes[0] = (uint8_t)(n & 0xffu);
    pk.bytes[1] = (uint8_t)((n >> 8) & 0xffu);
    return pk;
}

static void
run_leader_schedule_exact_order_case(uint64_t epoch,
                                     const uint64_t* stake_values,
                                     size_t stake_values_len,
                                     uint64_t len,
                                     uint64_t repeat,
                                     const uint16_t* expected_order) {
    sol_stake_weight_t* stakes = sol_calloc(stake_values_len, sizeof(sol_stake_weight_t));
    TEST_ASSERT_NOT_NULL(stakes);

    for (size_t i = 0; i < stake_values_len; i++) {
        stakes[i].pubkey = pubkey_from_u16((uint16_t)i);
        stakes[i].stake = stake_values[i];
    }

    sol_leader_schedule_config_t config = {
        .slots_per_epoch = len,
        .leader_schedule_slot_offset = repeat,
    };

    sol_leader_schedule_t* schedule = sol_leader_schedule_new(epoch, stakes, stake_values_len, &config);
    TEST_ASSERT_NOT_NULL(schedule);

    sol_slot_t first_slot = sol_leader_schedule_first_slot(schedule);
    for (uint64_t i = 0; i < len; i++) {
        const sol_pubkey_t* leader = sol_leader_schedule_get_leader(schedule, first_slot + (sol_slot_t)i);
        TEST_ASSERT_NOT_NULL(leader);

        uint16_t leader_idx = (uint16_t)leader->bytes[0] | ((uint16_t)leader->bytes[1] << 8);
        TEST_ASSERT_EQ(leader_idx, expected_order[i]);
    }

    sol_leader_schedule_destroy(schedule);
    sol_free(stakes);
}

TEST(leader_schedule_agave_exact_order) {
    static const uint64_t stakes_3a[] = {10, 20, 30};
    static const uint16_t expected_1[] = {1, 1, 2, 1, 1, 0, 0, 1, 2, 1, 0, 1};
    run_leader_schedule_exact_order_case(1, stakes_3a, 3, 12, 1, expected_1);

    static const uint16_t expected_2[] = {1, 1, 1, 1, 2, 2, 1, 1, 1, 1, 0, 0};
    run_leader_schedule_exact_order_case(1, stakes_3a, 3, 12, 2, expected_2);

    static const uint64_t stakes_3b[] = {30, 10, 20};
    static const uint16_t expected_3[] = {2, 2, 0, 2, 2, 1, 1, 2, 0, 2, 1, 2};
    run_leader_schedule_exact_order_case(1, stakes_3b, 3, 12, 1, expected_3);

    static const uint16_t expected_4[] = {2, 2, 2, 2, 0, 0, 2, 2, 2, 2, 1, 1};
    run_leader_schedule_exact_order_case(1, stakes_3b, 3, 12, 2, expected_4);

    static const uint64_t stakes_4[] = {10, 20, 25, 30};
    static const uint16_t expected_5[] = {2, 2, 3, 1, 2, 0, 1, 1, 3, 2, 1, 2};
    run_leader_schedule_exact_order_case(1, stakes_4, 4, 12, 1, expected_5);

    static const uint64_t stakes_7[] = {10, 20, 25, 30, 35, 40, 100};
    static const uint16_t expected_6[] = {4, 5, 6, 3, 4, 1, 2, 3, 6, 4, 2, 4, 5, 6, 6};
    run_leader_schedule_exact_order_case(1, stakes_7, 7, 15, 1, expected_6);

    static const uint64_t stakes_8[] = {10, 20, 25, 30, 35, 40, 100, 1000};
    static const uint16_t expected_7[] = {7, 7, 7, 7, 7, 4, 6, 7, 7, 7, 6, 7, 7, 7, 7};
    run_leader_schedule_exact_order_case(1, stakes_8, 8, 15, 1, expected_7);

    static const uint64_t stakes_9[] = {10, 20, 25, 30, 35, 40, 100, 1000, 10000};
    static const uint16_t expected_8[] = {8, 8, 8, 8, 8, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 7};
    run_leader_schedule_exact_order_case(1, stakes_9, 9, 20, 1, expected_8);

    static const uint16_t expected_9[] = {8, 8, 8, 8, 8, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 7, 8, 8, 8, 8, 8};
    run_leader_schedule_exact_order_case(1, stakes_9, 9, 25, 1, expected_9);

    static const uint16_t expected_10[] = {2, 2, 0, 1, 0, 2, 1, 2, 1, 2, 2, 2};
    run_leader_schedule_exact_order_case(457468, stakes_3a, 3, 12, 1, expected_10);

    static const uint16_t expected_11[] = {2, 2, 2, 2, 0, 0, 1, 1, 0, 0, 2, 2};
    run_leader_schedule_exact_order_case(457468, stakes_3a, 3, 12, 2, expected_11);

    static const uint16_t expected_12[] = {1, 2, 2, 2, 2, 2, 2, 1, 0, 2, 2, 0};
    run_leader_schedule_exact_order_case(457469, stakes_3a, 3, 12, 1, expected_12);

    static const uint16_t expected_13[] = {2, 1, 1, 1, 1, 1, 1, 1, 1, 2, 0, 2};
    run_leader_schedule_exact_order_case(457470, stakes_3a, 3, 12, 1, expected_13);

    static const uint16_t expected_14[] = {2, 2, 0, 0, 2, 1, 1, 1, 0, 0, 2, 2};
    run_leader_schedule_exact_order_case(3466545, stakes_3a, 3, 12, 1, expected_14);

    static const uint16_t expected_15[] = {2, 2, 0, 0, 2, 1, 1, 1, 0, 0, 2, 2, 1};
    run_leader_schedule_exact_order_case(3466545, stakes_3a, 3, 13, 1, expected_15);

    static const uint16_t expected_16[] = {2, 2, 0, 0, 2, 1, 1, 1, 0, 0, 2, 2, 1, 2};
    run_leader_schedule_exact_order_case(3466545, stakes_3a, 3, 14, 1, expected_16);

    static const uint16_t expected_17[] = {2, 2, 2, 2, 0, 0, 0, 0, 2, 2, 1, 1, 1, 1};
    run_leader_schedule_exact_order_case(3466545, stakes_3a, 3, 14, 2, expected_17);
}

static uint64_t
u64_pow_u32(uint64_t base, uint32_t exp) {
    uint64_t out = 1;
    for (uint32_t i = 0; i < exp; i++) {
        out *= base;
    }
    return out;
}

TEST(leader_schedule_agave_hashed) {
    struct test_case {
        uint64_t epoch;
        uint64_t len;
        uint32_t stake_pow;
        const char* expected_hash;
    };

    static const struct test_case cases[] = {
        {42, 1000, 0, "4XU6LEarBUmBkAvXRsjeyLu3N8CcgrvbRFrNiJi2jECk"},
        {42, 10000, 0, "G2MGFXgdLATXWr1336i8PTcaUMc4GbJRMJdbxiarCttr"},
        {42, 10000, 3, "2oLjZggMwDTQhzdB4KN5VQisyeRw6MZbBBdjosNZK5xR"},
        {454357, 10000, 1, "FyvbdxpVchendERMnzH2KDceqydpXtJarrfFXoLQEXgQ"},
    };

    const size_t n = 65536;
    sol_stake_weight_t* stakes = sol_calloc(n, sizeof(sol_stake_weight_t));
    TEST_ASSERT_NOT_NULL(stakes);

    for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        for (size_t i = 0; i < n; i++) {
            stakes[i].pubkey = pubkey_from_u16((uint16_t)i);
            stakes[i].stake = u64_pow_u32((uint64_t)i, cases[c].stake_pow);
        }

        sol_leader_schedule_config_t config = {
            .slots_per_epoch = cases[c].len,
            .leader_schedule_slot_offset = 1,
        };

        sol_leader_schedule_t* schedule = sol_leader_schedule_new(cases[c].epoch, stakes, n, &config);
        TEST_ASSERT_NOT_NULL(schedule);

        sol_sha256_ctx_t ctx;
        sol_sha256_init(&ctx);

        sol_slot_t first_slot = sol_leader_schedule_first_slot(schedule);
        for (uint64_t i = 0; i < cases[c].len; i++) {
            const sol_pubkey_t* leader = sol_leader_schedule_get_leader(schedule, first_slot + (sol_slot_t)i);
            TEST_ASSERT_NOT_NULL(leader);
            sol_sha256_update(&ctx, leader->bytes, SOL_PUBKEY_SIZE);
        }

        sol_sha256_t digest;
        sol_sha256_final(&ctx, &digest);

        sol_pubkey_t hash_pk;
        memcpy(hash_pk.bytes, digest.bytes, SOL_PUBKEY_SIZE);

        char hash_str[SOL_PUBKEY_BASE58_LEN];
        sol_pubkey_to_base58(&hash_pk, hash_str, sizeof(hash_str));

        TEST_ASSERT_STR_EQ(hash_str, cases[c].expected_hash);

        sol_leader_schedule_destroy(schedule);
    }

    sol_free(stakes);
}

TEST(epoch_schedule_get_epoch) {
    sol_epoch_schedule_t schedule = {
        .slots_per_epoch = 1000,
        .leader_schedule_slot_offset = 4,
        .warmup = false,
        .first_normal_epoch = 0,
        .first_normal_slot = 0,
    };

    TEST_ASSERT_EQ(sol_epoch_schedule_get_epoch(&schedule, 0), 0);
    TEST_ASSERT_EQ(sol_epoch_schedule_get_epoch(&schedule, 999), 0);
    TEST_ASSERT_EQ(sol_epoch_schedule_get_epoch(&schedule, 1000), 1);
    TEST_ASSERT_EQ(sol_epoch_schedule_get_epoch(&schedule, 2500), 2);
}

TEST(epoch_schedule_get_first_slot) {
    sol_epoch_schedule_t schedule = {
        .slots_per_epoch = 1000,
        .leader_schedule_slot_offset = 4,
        .warmup = false,
        .first_normal_epoch = 0,
        .first_normal_slot = 0,
    };

    TEST_ASSERT_EQ(sol_epoch_schedule_get_first_slot_in_epoch(&schedule, 0), 0);
    TEST_ASSERT_EQ(sol_epoch_schedule_get_first_slot_in_epoch(&schedule, 1), 1000);
    TEST_ASSERT_EQ(sol_epoch_schedule_get_first_slot_in_epoch(&schedule, 5), 5000);
}

TEST(epoch_schedule_get_last_slot) {
    sol_epoch_schedule_t schedule = {
        .slots_per_epoch = 1000,
        .leader_schedule_slot_offset = 4,
        .warmup = false,
        .first_normal_epoch = 0,
        .first_normal_slot = 0,
    };

    TEST_ASSERT_EQ(sol_epoch_schedule_get_last_slot_in_epoch(&schedule, 0), 999);
    TEST_ASSERT_EQ(sol_epoch_schedule_get_last_slot_in_epoch(&schedule, 1), 1999);
    TEST_ASSERT_EQ(sol_epoch_schedule_get_last_slot_in_epoch(&schedule, 5), 5999);
}

TEST(secp256k1_precompile_valid) {
#ifndef SOL_HAS_SECP256K1
    TEST_SKIP("libsecp256k1 not available");
#else
    secp256k1_context* secp = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    TEST_ASSERT_NOT_NULL(secp);

    uint8_t seckey[32] = {0};
    seckey[0] = 1;
    TEST_ASSERT(secp256k1_ec_seckey_verify(secp, seckey));

    const uint8_t msg[] = "hello";
    sol_keccak256_t msg_hash;
    sol_keccak256_hash(msg, sizeof(msg) - 1, &msg_hash);

    secp256k1_ecdsa_recoverable_signature sig = {0};
    TEST_ASSERT(secp256k1_ecdsa_sign_recoverable(secp, &sig, msg_hash.bytes, seckey, NULL, NULL));

    uint8_t sig64[64];
    int recid = 0;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(secp, sig64, &recid, &sig);
    TEST_ASSERT(recid >= 0 && recid <= 3);

    uint8_t sig65[65];
    memcpy(sig65, sig64, 64);
    sig65[64] = (uint8_t)recid;

    secp256k1_pubkey pubkey;
    TEST_ASSERT(secp256k1_ec_pubkey_create(secp, &pubkey, seckey));

    uint8_t pubkey_uncompressed[65];
    size_t pubkey_len = sizeof(pubkey_uncompressed);
    TEST_ASSERT(secp256k1_ec_pubkey_serialize(secp, pubkey_uncompressed, &pubkey_len,
                                              &pubkey, SECP256K1_EC_UNCOMPRESSED));
    TEST_ASSERT_EQ(pubkey_len, (size_t)65);

    sol_keccak256_t pubkey_hash;
    sol_keccak256_hash(pubkey_uncompressed + 1, 64, &pubkey_hash);

    uint8_t eth_addr[SOL_SECP256K1_ETH_ADDRESS_SIZE];
    memcpy(eth_addr, pubkey_hash.bytes + (32 - SOL_SECP256K1_ETH_ADDRESS_SIZE), SOL_SECP256K1_ETH_ADDRESS_SIZE);

    const uint8_t* sigs[1] = {sig65};
    const uint8_t* addrs[1] = {eth_addr};
    const uint8_t* msgs[1] = {msg};
    size_t msg_lens[1] = {sizeof(msg) - 1};

    uint8_t ix_data[512];
    size_t ix_len = sizeof(ix_data);
    sol_err_t err = sol_secp256k1_create_instruction(
        sigs, addrs, msgs, msg_lens, 1, ix_data, &ix_len);
    TEST_ASSERT_EQ(err, SOL_OK);

    sol_invoke_context_t invoke_ctx = {0};
    invoke_ctx.program_id = SOL_SECP256K1_PROGRAM_ID;
    invoke_ctx.instruction_data = ix_data;
    invoke_ctx.instruction_data_len = (uint16_t)ix_len;

    err = sol_secp256k1_program_execute(&invoke_ctx);
    TEST_ASSERT_EQ(err, SOL_OK);

    secp256k1_context_destroy(secp);
#endif
}

/*
 * Main
 */

int main(void) {
    test_case_t tests[] = {
        /* Token Program */
        TEST_CASE(associated_token_address_matches_spl),
        TEST_CASE(associated_token_create_finds_token_program_by_mint_owner),

        /* System Program */
        TEST_CASE(system_program_id),
        TEST_CASE(program_dispatch_compute_meter),
        TEST_CASE(system_create_account_instruction),
        TEST_CASE(system_transfer_instruction),
        TEST_CASE(system_assign_instruction),
        TEST_CASE(system_allocate_instruction),
        TEST_CASE(system_create_with_seed),

        /* BPF Upgradeable Loader */
        TEST_CASE(bpf_upgradeable_extend_program_reallocates_and_funds_rent),

        /* Vote Program */
        TEST_CASE(vote_program_id),
        TEST_CASE(vote_state_init),
        TEST_CASE(vote_process_basic),
        TEST_CASE(vote_process_multiple),
        TEST_CASE(vote_lockout_calculation),
        TEST_CASE(vote_root_advancement),
        TEST_CASE(vote_serialization),
        TEST_CASE(vote_state_bincode_v2_layout),
        TEST_CASE(vote_state_bincode_v1_roundtrip),
        TEST_CASE(vote_program_verifies_slot_hashes_sysvar),

        /* Stake Program */
        TEST_CASE(stake_program_id),
        TEST_CASE(stake_state_init),
        TEST_CASE(stake_delegate),
        TEST_CASE(stake_deactivate),
        TEST_CASE(stake_effective_stake),
        TEST_CASE(stake_activation_status_with_history),
        TEST_CASE(stake_is_active),
        TEST_CASE(stake_serialization),

        /* Leader Schedule */
        TEST_CASE(leader_schedule_new),
        TEST_CASE(leader_schedule_get_leader),
        TEST_CASE(leader_schedule_is_leader),
        TEST_CASE(leader_schedule_stake_weighted),
        TEST_CASE(leader_schedule_num_leaders),
        TEST_CASE(leader_schedule_agave_exact_order),
        TEST_CASE(leader_schedule_agave_hashed),
        TEST_CASE(epoch_schedule_get_epoch),
        TEST_CASE(epoch_schedule_get_first_slot),
        TEST_CASE(epoch_schedule_get_last_slot),

        /* Precompiles */
        TEST_CASE(ed25519_precompile_cross_instruction_offsets),
        TEST_CASE(secp256k1_precompile_valid),
        TEST_CASE(secp256k1_precompile_cross_instruction_offsets),
    };

    return RUN_TESTS("Programs Unit Tests", tests);
}
