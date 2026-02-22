/*
 * test_snapshot.c - Tests for Snapshot Support
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../src/snapshot/sol_snapshot.h"
#include "../src/snapshot/sol_snapshot_archive.h"
#include "../src/snapshot/sol_snapshot_download.h"
#include "../src/runtime/sol_bank.h"
#include "../src/storage/sol_rocksdb.h"
#include "../src/txn/sol_bincode.h"
#include "../src/txn/sol_pubkey.h"
#include "../src/crypto/sol_sha256.h"
#include "../src/util/sol_alloc.h"

#ifdef SOL_HAS_ZSTD
#include <zstd.h>
#endif

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    printf("  Testing %s...", #name); \
    fflush(stdout); \
    tests_run++; \
    test_##name(); \
    tests_passed++; \
    printf(" PASSED\n"); \
} while(0)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf(" FAILED\n    Assert failed: %s at %s:%d\n", \
               #cond, __FILE__, __LINE__); \
        exit(1); \
    } \
} while(0)

/*
 * Test snapshot manager creation
 */
TEST(snapshot_mgr_new) {
    sol_snapshot_config_t cfg = SOL_SNAPSHOT_CONFIG_DEFAULT;
    cfg.verify_accounts_hash = true;
    sol_snapshot_mgr_t* mgr = sol_snapshot_mgr_new(&cfg);
    ASSERT(mgr != NULL);
    sol_snapshot_mgr_destroy(mgr);
}

/*
 * Test snapshot manager with config
 */
TEST(snapshot_mgr_config) {
    sol_snapshot_config_t config = SOL_SNAPSHOT_CONFIG_DEFAULT;
    config.full_interval = 10000;
    config.incremental_interval = 2000;
    config.compression = SOL_SNAPSHOT_COMPRESSION_ZSTD;

    sol_snapshot_mgr_t* mgr = sol_snapshot_mgr_new(&config);
    ASSERT(mgr != NULL);
    sol_snapshot_mgr_destroy(mgr);
}

/*
 * Test setting directories
 */
TEST(snapshot_mgr_set_dirs) {
    sol_snapshot_config_t cfg = SOL_SNAPSHOT_CONFIG_DEFAULT;
    cfg.verify_accounts_hash = true;

    sol_snapshot_mgr_t* mgr = sol_snapshot_mgr_new(&cfg);
    ASSERT(mgr != NULL);

    sol_err_t err = sol_snapshot_mgr_set_dirs(mgr, "/tmp/snapshots", "/tmp/archives");
    ASSERT(err == SOL_OK);

    /* Set to NULL should work */
    err = sol_snapshot_mgr_set_dirs(mgr, NULL, NULL);
    ASSERT(err == SOL_OK);

    sol_snapshot_mgr_destroy(mgr);
}

/*
 * Test bank fields serialization
 */
TEST(bank_fields_serialize) {
    sol_hash_t parent_hash = {0};
    sol_bank_config_t bank_config = SOL_BANK_CONFIG_DEFAULT;
    sol_bank_t* bank = sol_bank_new(100, &parent_hash, NULL, &bank_config);
    ASSERT(bank != NULL);

    uint8_t buffer[4096];
    size_t len = sol_bank_fields_serialize(bank, buffer, sizeof(buffer));
    ASSERT(len > 0);
    ASSERT(len == sizeof(sol_bank_fields_t));

    sol_bank_destroy(bank);
}

/*
 * Test bank fields deserialization
 */
TEST(bank_fields_deserialize) {
    sol_hash_t parent_hash = {0};
    sol_bank_config_t bank_config = SOL_BANK_CONFIG_DEFAULT;
    sol_bank_t* bank = sol_bank_new(100, &parent_hash, NULL, &bank_config);
    ASSERT(bank != NULL);

    uint8_t buffer[4096];
    size_t len = sol_bank_fields_serialize(bank, buffer, sizeof(buffer));
    ASSERT(len > 0);

    sol_bank_fields_t fields;
    sol_err_t err = sol_bank_fields_deserialize(buffer, len, &fields);
    ASSERT(err == SOL_OK);
    ASSERT(fields.slot == 100);

    sol_bank_destroy(bank);
}

/*
 * Test bincode-style bank fields decoding
 */
TEST(bank_fields_deserialize_bincode) {
    sol_bank_fields_t in = {0};
    in.slot = 123;
    in.parent_slot = 122;
    for (size_t i = 0; i < sizeof(in.hash.bytes); i++) {
        in.hash.bytes[i] = (uint8_t)(0xA0 + i);
        in.parent_hash.bytes[i] = (uint8_t)(0xB0 + i);
    }
    in.block_height = 555;
    in.epoch = 9;
    in.transaction_count = 777;
    in.capitalization = 888;
    in.max_tick_height = 999;
    in.hashes_per_tick = 12500;
    in.ticks_per_slot = 64;
    in.lamports_per_signature = 5000;
    in.slots_per_epoch = 432000;
    in.target_lamports_per_signature = 10000;
    in.target_signatures_per_slot = 20000;
    in.min_lamports_per_signature = 5000;
    in.max_lamports_per_signature = 100000;
    in.rent_lamports_per_byte_year = 3480;
    in.rent_exemption_threshold = 2.0f;
    in.rent_burn_percent = 50;
    in.inflation_initial = 0.08f;
    in.inflation_terminal = 0.015f;
    in.inflation_taper = 0.15f;
    in.inflation_foundation = 0.05f;
    in.inflation_foundation_term = 7.0f;
    in.inflation_epoch = 7;

    uint8_t buf[512];
    sol_encoder_t enc;
    sol_encoder_init(&enc, buf, sizeof(buf));

    ASSERT(sol_encode_u64(&enc, (uint64_t)in.slot) == SOL_OK);
    ASSERT(sol_encode_u64(&enc, (uint64_t)in.parent_slot) == SOL_OK);
    ASSERT(sol_encode_bytes(&enc, in.hash.bytes, sizeof(in.hash.bytes)) == SOL_OK);
    ASSERT(sol_encode_bytes(&enc, in.parent_hash.bytes, sizeof(in.parent_hash.bytes)) == SOL_OK);
    ASSERT(sol_encode_u64(&enc, in.block_height) == SOL_OK);
    ASSERT(sol_encode_u64(&enc, in.epoch) == SOL_OK);
    ASSERT(sol_encode_u64(&enc, in.transaction_count) == SOL_OK);
    ASSERT(sol_encode_u64(&enc, in.capitalization) == SOL_OK);
    ASSERT(sol_encode_u64(&enc, in.max_tick_height) == SOL_OK);
    ASSERT(sol_encode_u64(&enc, in.hashes_per_tick) == SOL_OK);
    ASSERT(sol_encode_u64(&enc, in.ticks_per_slot) == SOL_OK);
    ASSERT(sol_encode_u64(&enc, in.lamports_per_signature) == SOL_OK);
    ASSERT(sol_encode_u64(&enc, in.slots_per_epoch) == SOL_OK);
    ASSERT(sol_encode_u64(&enc, in.target_lamports_per_signature) == SOL_OK);
    ASSERT(sol_encode_u64(&enc, in.target_signatures_per_slot) == SOL_OK);
    ASSERT(sol_encode_u64(&enc, in.min_lamports_per_signature) == SOL_OK);
    ASSERT(sol_encode_u64(&enc, in.max_lamports_per_signature) == SOL_OK);
    ASSERT(sol_encode_u64(&enc, in.rent_lamports_per_byte_year) == SOL_OK);

    union { float f; uint32_t u; } cvt;
    cvt.f = in.rent_exemption_threshold;
    ASSERT(sol_encode_u32(&enc, cvt.u) == SOL_OK);
    ASSERT(sol_encode_u8(&enc, in.rent_burn_percent) == SOL_OK);

    cvt.f = in.inflation_initial;
    ASSERT(sol_encode_u32(&enc, cvt.u) == SOL_OK);
    cvt.f = in.inflation_terminal;
    ASSERT(sol_encode_u32(&enc, cvt.u) == SOL_OK);
    cvt.f = in.inflation_taper;
    ASSERT(sol_encode_u32(&enc, cvt.u) == SOL_OK);
    cvt.f = in.inflation_foundation;
    ASSERT(sol_encode_u32(&enc, cvt.u) == SOL_OK);
    cvt.f = in.inflation_foundation_term;
    ASSERT(sol_encode_u32(&enc, cvt.u) == SOL_OK);

    ASSERT(sol_encode_u64(&enc, in.inflation_epoch) == SOL_OK);

    sol_bank_fields_t out = {0};
    sol_err_t err = sol_bank_fields_deserialize(buf, sol_encoder_len(&enc), &out);
    ASSERT(err == SOL_OK);
    ASSERT(out.slot == in.slot);
    ASSERT(out.parent_slot == in.parent_slot);
    ASSERT(memcmp(out.hash.bytes, in.hash.bytes, sizeof(in.hash.bytes)) == 0);
    ASSERT(memcmp(out.parent_hash.bytes, in.parent_hash.bytes, sizeof(in.parent_hash.bytes)) == 0);
    ASSERT(out.ticks_per_slot == in.ticks_per_slot);
    ASSERT(out.slots_per_epoch == in.slots_per_epoch);
    ASSERT(out.rent_burn_percent == in.rent_burn_percent);
    ASSERT(out.inflation_epoch == in.inflation_epoch);

    union { float f; uint32_t u; } a, b;
    a.f = in.rent_exemption_threshold;
    b.f = out.rent_exemption_threshold;
    ASSERT(a.u == b.u);
}

/*
 * Test account storage serialization
 */
TEST(account_storage_serialize) {
    sol_account_t accounts[2];
    memset(accounts, 0, sizeof(accounts));

    /* First account */
    accounts[0].meta.lamports = 1000000;
    accounts[0].meta.data_len = 32;
    accounts[0].data = sol_calloc(32, 1);
    memset(accounts[0].data, 0xAA, 32);

    /* Second account */
    accounts[1].meta.lamports = 2000000;
    accounts[1].meta.data_len = 64;
    accounts[1].data = sol_calloc(64, 1);
    memset(accounts[1].data, 0xBB, 64);

    uint8_t buffer[4096];
    size_t len = sol_account_storage_serialize(accounts, 2, 100, 1, buffer, sizeof(buffer));
    ASSERT(len > 0);

    sol_free(accounts[0].data);
    sol_free(accounts[1].data);
}

/*
 * Test account storage deserialization
 */
TEST(account_storage_deserialize) {
    sol_account_t accounts[2];
    memset(accounts, 0, sizeof(accounts));

    accounts[0].meta.lamports = 1000000;
    accounts[0].meta.data_len = 32;
    accounts[0].data = sol_calloc(32, 1);
    memset(accounts[0].data, 0xAA, 32);

    accounts[1].meta.lamports = 2000000;
    accounts[1].meta.data_len = 64;
    accounts[1].data = sol_calloc(64, 1);
    memset(accounts[1].data, 0xBB, 64);

    uint8_t buffer[4096];
    size_t len = sol_account_storage_serialize(accounts, 2, 100, 1, buffer, sizeof(buffer));
    ASSERT(len > 0);

    sol_account_t out_accounts[2];
    memset(out_accounts, 0, sizeof(out_accounts));

    size_t count = sol_account_storage_deserialize(buffer, len, out_accounts, 2);
    ASSERT(count == 2);
    ASSERT(out_accounts[0].meta.lamports == 1000000);
    ASSERT(out_accounts[1].meta.lamports == 2000000);
    ASSERT(out_accounts[0].meta.data_len == 32);
    ASSERT(out_accounts[1].meta.data_len == 64);

    /* Verify data content */
    ASSERT(out_accounts[0].data != NULL);
    ASSERT(out_accounts[0].data[0] == 0xAA);
    ASSERT(out_accounts[1].data != NULL);
    ASSERT(out_accounts[1].data[0] == 0xBB);

    /* Cleanup */
    sol_free(accounts[0].data);
    sol_free(accounts[1].data);
    sol_free(out_accounts[0].data);
    sol_free(out_accounts[1].data);
}

/*
 * Test snapshot archive naming
 */
TEST(snapshot_archive_name) {
    sol_snapshot_info_t info = {0};
    info.slot = 12345;
    info.hash.bytes[0] = 0xDE;
    info.hash.bytes[1] = 0xAD;
    info.hash.bytes[2] = 0xBE;
    info.hash.bytes[3] = 0xEF;
    info.type = SOL_SNAPSHOT_FULL;
    info.compression = SOL_SNAPSHOT_COMPRESSION_ZSTD;

    char name[256];
    size_t len = sol_snapshot_archive_name(&info, name, sizeof(name));
    ASSERT(len > 0);
    ASSERT(strstr(name, "snapshot-12345-") != NULL);
    ASSERT(strstr(name, ".tar.zst") != NULL);
}

/*
 * Test incremental snapshot archive naming
 */
TEST(snapshot_archive_name_incremental) {
    sol_snapshot_info_t info = {0};
    info.slot = 20000;
    info.base_slot = 10000;
    info.hash.bytes[0] = 0xCA;
    info.hash.bytes[1] = 0xFE;
    info.type = SOL_SNAPSHOT_INCREMENTAL;
    info.compression = SOL_SNAPSHOT_COMPRESSION_GZIP;

    char name[256];
    size_t len = sol_snapshot_archive_name(&info, name, sizeof(name));
    ASSERT(len > 0);
    ASSERT(strstr(name, "incremental-snapshot-10000-20000-") != NULL);
    ASSERT(strstr(name, ".tar.gz") != NULL);
}

/*
 * Test snapshot info parsing from filename
 */
TEST(snapshot_get_info) {
    sol_snapshot_info_t info;

    /* Full snapshot */
    sol_err_t err = sol_snapshot_get_info(
        "snapshot-12345-deadbeef00000000.tar.zst", &info);
    ASSERT(err == SOL_OK);
    ASSERT(info.type == SOL_SNAPSHOT_FULL);
    ASSERT(info.slot == 12345);

    /* Incremental snapshot */
    err = sol_snapshot_get_info(
        "incremental-snapshot-10000-20000-cafe0000.tar.zst", &info);
    ASSERT(err == SOL_OK);
    ASSERT(info.type == SOL_SNAPSHOT_INCREMENTAL);
    ASSERT(info.base_slot == 10000);
    ASSERT(info.slot == 20000);

    /* Invalid filename */
    err = sol_snapshot_get_info("invalid.tar.zst", &info);
    ASSERT(err != SOL_OK);
}

/*
 * Test snapshot hash parsing (base58)
 */
TEST(snapshot_get_info_hash_base58) {
    sol_hash_t h = {0};
    for (size_t i = 0; i < sizeof(h.bytes); i++) {
        h.bytes[i] = (uint8_t)(i + 1);
    }

    char hash_str[SOL_PUBKEY_BASE58_LEN];
    sol_pubkey_to_base58((const sol_pubkey_t*)&h, hash_str, sizeof(hash_str));

    char name[256];
    snprintf(name, sizeof(name), "snapshot-42-%s.tar.zst", hash_str);

    sol_snapshot_info_t info;
    sol_err_t err = sol_snapshot_get_info(name, &info);
    ASSERT(err == SOL_OK);
    ASSERT(info.type == SOL_SNAPSHOT_FULL);
    ASSERT(info.slot == 42);
    ASSERT(memcmp(info.hash.bytes, h.bytes, sizeof(h.bytes)) == 0);

    snprintf(name, sizeof(name), "incremental-snapshot-40-43-%s.tar.zst", hash_str);
    err = sol_snapshot_get_info(name, &info);
    ASSERT(err == SOL_OK);
    ASSERT(info.type == SOL_SNAPSHOT_INCREMENTAL);
    ASSERT(info.base_slot == 40);
    ASSERT(info.slot == 43);
    ASSERT(memcmp(info.hash.bytes, h.bytes, sizeof(h.bytes)) == 0);
}

TEST(snapshot_load_seeds_bank_hash_from_solana_bank_snapshot) {
    char tmpdir[] = "/tmp/solana_c_snapshot_seedhash_XXXXXX";
    char* base = mkdtemp(tmpdir);
    ASSERT(base != NULL);

    sol_hash_t filename_hash = {0};
    for (size_t i = 0; i < sizeof(filename_hash.bytes); i++) {
        filename_hash.bytes[i] = (uint8_t)(0x11 + (uint8_t)i);
    }

    sol_hash_t expected_bank_hash = {0};
    for (size_t i = 0; i < sizeof(expected_bank_hash.bytes); i++) {
        expected_bank_hash.bytes[i] = (uint8_t)(0x80 + (uint8_t)i);
    }

    char hash58[SOL_PUBKEY_BASE58_LEN] = {0};
    sol_err_t enc_err =
        sol_pubkey_to_base58((const sol_pubkey_t*)&filename_hash, hash58, sizeof(hash58));
    ASSERT(enc_err == SOL_OK);

    char snapdir[512];
    snprintf(snapdir, sizeof(snapdir), "%s/snapshot-5-%s", base, hash58);
    ASSERT(mkdir(snapdir, 0755) == 0);

    char path[512];
    snprintf(path, sizeof(path), "%s/snapshots", snapdir);
    ASSERT(mkdir(path, 0755) == 0);
    snprintf(path, sizeof(path), "%s/snapshots/5", snapdir);
    ASSERT(mkdir(path, 0755) == 0);

    snprintf(path, sizeof(path), "%s/accounts", snapdir);
    ASSERT(mkdir(path, 0755) == 0);

    /* Write a minimal Solana bank snapshot header + a small Bank fields region
     * that our parser can recognize (v1.2.0-style). */
    char bank_path[512];
    snprintf(bank_path, sizeof(bank_path), "%s/snapshots/5/5", snapdir);
    FILE* bankf = fopen(bank_path, "wb");
    ASSERT(bankf != NULL);

    sol_hash_t latest_blockhash = {0};
    for (size_t i = 0; i < SOL_HASH_SIZE; i++) {
        latest_blockhash.bytes[i] = (uint8_t)(0xA0u + (uint8_t)i);
    }

    uint8_t bank_data[256];
    memset(bank_data, 0, sizeof(bank_data));
    uint64_t block_height = 123;
    memcpy(bank_data, &block_height, sizeof(block_height));
    bank_data[8] = 1; /* Option<Hash> tag */
    memcpy(bank_data + 9, latest_blockhash.bytes, SOL_HASH_SIZE);

    size_t pos = 64; /* keep room for header */
    memcpy(bank_data + pos + 0, (uint8_t[]){5, 0, 0, 0, 0, 0, 0, 0}, 8);     /* slot */
    memcpy(bank_data + pos + 8, (uint8_t[]){0, 0, 0, 0, 0, 0, 0, 0}, 8);     /* epoch */
    uint64_t sigcnt = 1234;
    memcpy(bank_data + pos + 16, &sigcnt, sizeof(sigcnt));                   /* signature_count */
    memcpy(bank_data + pos + 24, expected_bank_hash.bytes, SOL_HASH_SIZE);   /* bank hash */

    uint64_t target_lamports = 10000;
    uint64_t target_sigs = 20000;
    uint64_t min_lamports = 5000;
    uint64_t max_lamports = 100000;
    uint64_t burn_percent = 50;
    memcpy(bank_data + pos + 72, &target_lamports, sizeof(target_lamports));
    memcpy(bank_data + pos + 80, &target_sigs, sizeof(target_sigs));
    memcpy(bank_data + pos + 88, &min_lamports, sizeof(min_lamports));
    memcpy(bank_data + pos + 96, &max_lamports, sizeof(max_lamports));
    memcpy(bank_data + pos + 104, &burn_percent, sizeof(burn_percent));

    ASSERT(fwrite(bank_data, 1, sizeof(bank_data), bankf) == sizeof(bank_data));
    fclose(bankf);

    sol_snapshot_config_t cfg = SOL_SNAPSHOT_CONFIG_DEFAULT;
    cfg.verify_accounts_hash = true;

    sol_snapshot_mgr_t* mgr = sol_snapshot_mgr_new(&cfg);
    ASSERT(mgr != NULL);

    sol_bank_t* loaded_bank = NULL;
    sol_accounts_db_t* loaded_db = NULL;

    sol_err_t err = sol_snapshot_load(mgr, snapdir, &loaded_bank, &loaded_db);
    ASSERT(err == SOL_OK);
    ASSERT(loaded_bank != NULL);
    ASSERT(loaded_db != NULL);

    sol_hash_t got = {0};
    sol_bank_compute_hash(loaded_bank, &got);
    ASSERT(sol_hash_eq(&got, &expected_bank_hash));
    ASSERT(!sol_hash_eq(&got, &filename_hash));
    ASSERT(sol_bank_signature_count(loaded_bank) == 1234);

    sol_bank_destroy(loaded_bank);
    sol_accounts_db_destroy(loaded_db);
    sol_snapshot_mgr_destroy(mgr);

    sol_snapshot_archive_rmdir(base);
}

TEST(snapshot_load_seeds_signature_count_from_bank_fields) {
    char tmpdir[] = "/tmp/solana_c_snapshot_sigcount_XXXXXX";
    char* base = mkdtemp(tmpdir);
    ASSERT(base != NULL);

    sol_hash_t expected_hash = {0};
    for (size_t i = 0; i < sizeof(expected_hash.bytes); i++) {
        expected_hash.bytes[i] = (uint8_t)(0x11 + (uint8_t)i);
    }

    char hash58[SOL_PUBKEY_BASE58_LEN] = {0};
    sol_err_t enc_err =
        sol_pubkey_to_base58((const sol_pubkey_t*)&expected_hash, hash58, sizeof(hash58));
    ASSERT(enc_err == SOL_OK);

    char snapdir[512];
    snprintf(snapdir, sizeof(snapdir), "%s/snapshot-5-%s", base, hash58);
    ASSERT(mkdir(snapdir, 0755) == 0);

    char path[512];
    snprintf(path, sizeof(path), "%s/snapshots", snapdir);
    ASSERT(mkdir(path, 0755) == 0);
    snprintf(path, sizeof(path), "%s/snapshots/5", snapdir);
    ASSERT(mkdir(path, 0755) == 0);

    snprintf(path, sizeof(path), "%s/accounts", snapdir);
    ASSERT(mkdir(path, 0755) == 0);

    /* Create a large (>=64KB) bank fields file with a valid header. */
    char bank_path[512];
    snprintf(bank_path, sizeof(bank_path), "%s/snapshots/5/5", snapdir);
    FILE* bankf = fopen(bank_path, "wb");
    ASSERT(bankf != NULL);

    sol_hash_t parent_hash = {0};
    memset(parent_hash.bytes, 0x22, sizeof(parent_hash.bytes));

    uint8_t header[512];
    sol_encoder_t enc;
    sol_encoder_init(&enc, header, sizeof(header));
    ASSERT(sol_encode_u64(&enc, 5) == SOL_OK);
    ASSERT(sol_encode_u64(&enc, 4) == SOL_OK);
    ASSERT(sol_encode_bytes(&enc, expected_hash.bytes, SOL_HASH_SIZE) == SOL_OK);
    ASSERT(sol_encode_bytes(&enc, parent_hash.bytes, SOL_HASH_SIZE) == SOL_OK);
    ASSERT(sol_encode_u64(&enc, 123) == SOL_OK);    /* block_height */
    ASSERT(sol_encode_u64(&enc, 0) == SOL_OK);      /* epoch */
    ASSERT(sol_encode_u64(&enc, 1234) == SOL_OK);   /* signature/tx count */
    ASSERT(sol_encode_u64(&enc, 0) == SOL_OK);      /* capitalization */
    ASSERT(sol_encode_u64(&enc, 0) == SOL_OK);      /* max_tick_height */
    ASSERT(sol_encode_u64(&enc, 0) == SOL_OK);      /* hashes_per_tick */
    ASSERT(sol_encode_u64(&enc, 64) == SOL_OK);     /* ticks_per_slot */
    ASSERT(sol_encode_u64(&enc, 5000) == SOL_OK);   /* lamports_per_signature */
    ASSERT(sol_encode_u64(&enc, 432000) == SOL_OK); /* slots_per_epoch */

    size_t header_len = sol_encoder_len(&enc);
    ASSERT(fwrite(header, 1, header_len, bankf) == header_len);

    uint8_t pad[128] = {0};
    for (size_t i = 0; i < 1024; i++) {
        ASSERT(fwrite(pad, 1, sizeof(pad), bankf) == sizeof(pad));
    }
    fclose(bankf);

    sol_snapshot_config_t cfg = SOL_SNAPSHOT_CONFIG_DEFAULT;
    cfg.verify_accounts_hash = true;

    sol_snapshot_mgr_t* mgr = sol_snapshot_mgr_new(&cfg);
    ASSERT(mgr != NULL);

    sol_bank_t* loaded_bank = NULL;
    sol_accounts_db_t* loaded_db = NULL;

    sol_err_t err = sol_snapshot_load(mgr, snapdir, &loaded_bank, &loaded_db);
    ASSERT(err == SOL_OK);
    ASSERT(loaded_bank != NULL);
    ASSERT(loaded_db != NULL);

    sol_hash_t got = {0};
    sol_bank_compute_hash(loaded_bank, &got);
    ASSERT(sol_hash_eq(&got, &expected_hash));
    ASSERT(sol_bank_signature_count(loaded_bank) == 1234);

    sol_bank_destroy(loaded_bank);
    sol_accounts_db_destroy(loaded_db);
    sol_snapshot_mgr_destroy(mgr);

    sol_snapshot_archive_rmdir(base);
}

TEST(snapshot_load_seeds_latest_blockhash_from_bank_snapshot_header) {
    char tmpdir[] = "/tmp/solana_c_snapshot_blockhash_XXXXXX";
    char* dir = mkdtemp(tmpdir);
    ASSERT(dir != NULL);

    char path[512];

    snprintf(path, sizeof(path), "%s/snapshots", dir);
    mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/snapshots/5", dir);
    mkdir(path, 0755);

    snprintf(path, sizeof(path), "%s/accounts", dir);
    mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/accounts/5.0", dir);
    mkdir(path, 0755);

    sol_hash_t expected_blockhash = {0};
    for (size_t i = 0; i < SOL_HASH_SIZE; i++) {
        expected_blockhash.bytes[i] = (uint8_t)(0xA0u + (uint8_t)i);
    }

    /* Write a minimal bank snapshot header with:
     * - u64 (ignored)
     * - Option<Hash> at offset 8 (tag=1, then 32 bytes hash)
     */
    snprintf(path, sizeof(path), "%s/snapshots/5/5", dir);
    FILE* bf = fopen(path, "wb");
    ASSERT(bf != NULL);

    uint8_t hdr[64];
    memset(hdr, 0, sizeof(hdr));
    hdr[8] = 1;
    memcpy(hdr + 9, expected_blockhash.bytes, SOL_HASH_SIZE);
    ASSERT(fwrite(hdr, 1, sizeof(hdr), bf) == sizeof(hdr));
    fclose(bf);

    /* Write one account storage file under accounts/5.0 */
    snprintf(path, sizeof(path), "%s/accounts/5.0/storage.bin", dir);
    FILE* af = fopen(path, "wb");
    ASSERT(af != NULL);

    sol_account_storage_header_t ahdr = {
        .slot = 5,
        .id = 1,
        .count = 1,
        .data_len = sizeof(sol_stored_account_t),
    };

    sol_pubkey_t pubkey = {0};
    pubkey.bytes[0] = 0x11;
    pubkey.bytes[1] = 0x22;

    sol_stored_account_t stored = {0};
    stored.write_version = 1;
    stored.data_len = 0;
    stored.pubkey = pubkey;
    stored.owner = SOL_SYSTEM_PROGRAM_ID;
    stored.lamports = 123;
    stored.rent_epoch = 0;
    stored.executable = false;

    ASSERT(fwrite(&ahdr, 1, sizeof(ahdr), af) == sizeof(ahdr));
    ASSERT(fwrite(&stored, 1, sizeof(stored), af) == sizeof(stored));
    fclose(af);

    sol_snapshot_mgr_t* mgr = sol_snapshot_mgr_new(NULL);
    ASSERT(mgr != NULL);

    sol_bank_t* loaded_bank = NULL;
    sol_accounts_db_t* loaded_db = NULL;
    sol_err_t err = sol_snapshot_load(mgr, dir, &loaded_bank, &loaded_db);
    ASSERT(err == SOL_OK);
    ASSERT(loaded_bank != NULL);
    ASSERT(loaded_db != NULL);

    const sol_hash_t* got = sol_bank_blockhash(loaded_bank);
    ASSERT(got != NULL);
    ASSERT(memcmp(got->bytes, expected_blockhash.bytes, SOL_HASH_SIZE) == 0);
    ASSERT(sol_bank_is_blockhash_valid(loaded_bank, &expected_blockhash));

    sol_bank_destroy(loaded_bank);
    sol_accounts_db_destroy(loaded_db);
    sol_snapshot_mgr_destroy(mgr);

    sol_snapshot_archive_rmdir(dir);
}

TEST(snapshot_load_seeds_accounts_lt_hash_from_agave_bank_snapshot_tail) {
    char tmpdir[] = "/tmp/solana_c_snapshot_lthash_XXXXXX";
    char* dir = mkdtemp(tmpdir);
    ASSERT(dir != NULL);

    char path[512];

    snprintf(path, sizeof(path), "%s/snapshots", dir);
    ASSERT(mkdir(path, 0755) == 0);
    snprintf(path, sizeof(path), "%s/snapshots/5", dir);
    ASSERT(mkdir(path, 0755) == 0);
    snprintf(path, sizeof(path), "%s/snapshots/5/snapshots", dir);
    ASSERT(mkdir(path, 0755) == 0);
    snprintf(path, sizeof(path), "%s/snapshots/5/snapshots/5", dir);
    ASSERT(mkdir(path, 0755) == 0);

    snprintf(path, sizeof(path), "%s/accounts", dir);
    ASSERT(mkdir(path, 0755) == 0);

    sol_hash_t blockhash = {0};
    for (size_t i = 0; i < SOL_HASH_SIZE; i++) {
        blockhash.bytes[i] = (uint8_t)(0xA0u + (uint8_t)i);
    }

    sol_lt_hash_t accounts_lt_hash = {0};
    for (size_t i = 0; i < SOL_LT_HASH_NUM_ELEMENTS; i++) {
        accounts_lt_hash.v[i] = (uint16_t)i;
    }

    /* Write a minimal bank snapshot file that matches the Agave bincode prefix
     * parser and ends with accounts_lt_hash (Option<[u16;1024]>). */
    snprintf(path, sizeof(path), "%s/snapshots/5/snapshots/5/5", dir);
    FILE* bf = fopen(path, "wb");
    ASSERT(bf != NULL);

    uint8_t buf[4096];
    sol_encoder_t enc;
    sol_encoder_init(&enc, buf, sizeof(buf));

    /* BlockhashQueue */
    ASSERT(sol_encode_u64(&enc, 1234) == SOL_OK);      /* last_hash_index */
    ASSERT(sol_encode_u8(&enc, 1) == SOL_OK);          /* last_hash tag */
    ASSERT(sol_encode_bytes(&enc, blockhash.bytes, SOL_HASH_SIZE) == SOL_OK);
    ASSERT(sol_encode_u64(&enc, 1) == SOL_OK);         /* hashes len */
    ASSERT(sol_encode_bytes(&enc, blockhash.bytes, SOL_HASH_SIZE) == SOL_OK); /* key */
    ASSERT(sol_encode_u64(&enc, 5000) == SOL_OK);      /* FeeCalculator.lamports_per_signature */
    ASSERT(sol_encode_u64(&enc, 1234) == SOL_OK);      /* hash_index */
    ASSERT(sol_encode_u64(&enc, 0) == SOL_OK);         /* timestamp */
    ASSERT(sol_encode_u64(&enc, 300) == SOL_OK);       /* max_age */

    /* AncestorsForSerialization */
    ASSERT(sol_encode_u64(&enc, 0) == SOL_OK);         /* ancestors len */

    /* Bank fields prefix */
    ASSERT(sol_encode_bytes(&enc, blockhash.bytes, SOL_HASH_SIZE) == SOL_OK); /* bank hash == blockhash */

    sol_hash_t parent_hash = {0};
    memset(parent_hash.bytes, 0xBB, sizeof(parent_hash.bytes));
    ASSERT(sol_encode_bytes(&enc, parent_hash.bytes, SOL_HASH_SIZE) == SOL_OK);

    ASSERT(sol_encode_u64(&enc, 4) == SOL_OK);         /* parent_slot */
    ASSERT(sol_encode_u64(&enc, 0) == SOL_OK);         /* hardforks len */

    ASSERT(sol_encode_u64(&enc, 0) == SOL_OK);         /* transaction_count */
    ASSERT(sol_encode_u64(&enc, 0) == SOL_OK);         /* tick_height */
    ASSERT(sol_encode_u64(&enc, 42) == SOL_OK);        /* signature_count (seeded) */
    ASSERT(sol_encode_u64(&enc, 0) == SOL_OK);         /* capitalization */
    ASSERT(sol_encode_u64(&enc, 0) == SOL_OK);         /* max_tick_height */

    ASSERT(sol_encode_u8(&enc, 0) == SOL_OK);          /* hashes_per_tick: None */
    ASSERT(sol_encode_u64(&enc, 64) == SOL_OK);        /* ticks_per_slot */

    uint8_t zeros16[16] = {0};
    ASSERT(sol_encode_bytes(&enc, zeros16, sizeof(zeros16)) == SOL_OK); /* ns_per_slot */
    ASSERT(sol_encode_u64(&enc, 0) == SOL_OK);         /* genesis_creation_time */

    uint8_t zeros8[8] = {0};
    ASSERT(sol_encode_bytes(&enc, zeros8, sizeof(zeros8)) == SOL_OK);   /* slots_per_year */
    ASSERT(sol_encode_u64(&enc, 0) == SOL_OK);         /* accounts_data_len */

    ASSERT(sol_encode_u64(&enc, 5) == SOL_OK);         /* slot */
    ASSERT(sol_encode_u64(&enc, 0) == SOL_OK);         /* epoch */
    ASSERT(sol_encode_u64(&enc, 0) == SOL_OK);         /* block_height */

    /* accounts_lt_hash tail */
    ASSERT(sol_encode_u8(&enc, 1) == SOL_OK);          /* Some */
    ASSERT(sol_encode_bytes(&enc,
                            (const uint8_t*)&accounts_lt_hash,
                            sizeof(accounts_lt_hash)) == SOL_OK);

    size_t len = sol_encoder_len(&enc);
    ASSERT(fwrite(buf, 1, len, bf) == len);
    fclose(bf);

    sol_snapshot_mgr_t* mgr = sol_snapshot_mgr_new(NULL);
    ASSERT(mgr != NULL);

    sol_bank_t* loaded_bank = NULL;
    sol_accounts_db_t* loaded_db = NULL;
    sol_err_t err = sol_snapshot_load(mgr, dir, &loaded_bank, &loaded_db);
    ASSERT(err == SOL_OK);
    ASSERT(loaded_bank != NULL);
    ASSERT(loaded_db != NULL);

    sol_blake3_t got_checksum = {0};
    sol_bank_accounts_lt_hash_checksum(loaded_bank, &got_checksum);

    sol_blake3_t expected_checksum = {0};
    sol_lt_hash_checksum(&accounts_lt_hash, &expected_checksum);

    ASSERT(memcmp(got_checksum.bytes, expected_checksum.bytes, sizeof(got_checksum.bytes)) == 0);
    ASSERT(sol_bank_signature_count(loaded_bank) == 42);

    sol_bank_destroy(loaded_bank);
    sol_accounts_db_destroy(loaded_db);
    sol_snapshot_mgr_destroy(mgr);

    sol_snapshot_archive_rmdir(dir);
}

TEST(snapshot_load_seeds_bank_fields_with_large_ancestors) {
    char tmpdir[] = "/tmp/solana_c_snapshot_large_ancestors_XXXXXX";
    char* dir = mkdtemp(tmpdir);
    ASSERT(dir != NULL);

    char path[512];

    snprintf(path, sizeof(path), "%s/snapshots", dir);
    ASSERT(mkdir(path, 0755) == 0);
    snprintf(path, sizeof(path), "%s/snapshots/5", dir);
    ASSERT(mkdir(path, 0755) == 0);
    snprintf(path, sizeof(path), "%s/snapshots/5/snapshots", dir);
    ASSERT(mkdir(path, 0755) == 0);
    snprintf(path, sizeof(path), "%s/snapshots/5/snapshots/5", dir);
    ASSERT(mkdir(path, 0755) == 0);

    snprintf(path, sizeof(path), "%s/accounts", dir);
    ASSERT(mkdir(path, 0755) == 0);

    sol_hash_t blockhash = {0};
    for (size_t i = 0; i < SOL_HASH_SIZE; i++) {
        blockhash.bytes[i] = (uint8_t)(0xA0u + (uint8_t)i);
    }

    sol_lt_hash_t accounts_lt_hash = {0};
    for (size_t i = 0; i < SOL_LT_HASH_NUM_ELEMENTS; i++) {
        accounts_lt_hash.v[i] = (uint16_t)i;
    }

    /* Create an Agave-format bank snapshot with a huge ancestors map so the
     * bank fields appear past the old 16MB prefix limit. */
    snprintf(path, sizeof(path), "%s/snapshots/5/snapshots/5/5", dir);
    FILE* bf = fopen(path, "wb");
    ASSERT(bf != NULL);

    uint8_t u64buf[8];
#define STORE_U64_LE(x) do { \
        uint64_t _v = (uint64_t)(x); \
        for (size_t _i = 0; _i < 8; _i++) { \
            u64buf[_i] = (uint8_t)((_v >> (_i * 8)) & 0xFFu); \
        } \
    } while (0)

    /* BlockhashQueue */
    STORE_U64_LE(1234);
    ASSERT(fwrite(u64buf, 1, sizeof(u64buf), bf) == sizeof(u64buf)); /* last_hash_index */
    uint8_t tag = 1;
    ASSERT(fwrite(&tag, 1, 1, bf) == 1); /* last_hash tag */
    ASSERT(fwrite(blockhash.bytes, 1, SOL_HASH_SIZE, bf) == SOL_HASH_SIZE);
    STORE_U64_LE(0);
    ASSERT(fwrite(u64buf, 1, sizeof(u64buf), bf) == sizeof(u64buf)); /* hashes len = 0 */
    STORE_U64_LE(300);
    ASSERT(fwrite(u64buf, 1, sizeof(u64buf), bf) == sizeof(u64buf)); /* max_age */

    /* AncestorsForSerialization */
    const uint64_t ancestors_len = 1100000ULL; /* 17.6MB of pairs */
    STORE_U64_LE(ancestors_len);
    ASSERT(fwrite(u64buf, 1, sizeof(u64buf), bf) == sizeof(u64buf));

    uint8_t zeros[16384];
    memset(zeros, 0, sizeof(zeros));
    uint64_t remaining = ancestors_len * 16ULL;
    while (remaining > 0) {
        size_t chunk = remaining > sizeof(zeros) ? sizeof(zeros) : (size_t)remaining;
        ASSERT(fwrite(zeros, 1, chunk, bf) == chunk);
        remaining -= chunk;
    }

    /* Bank fields prefix */
    ASSERT(fwrite(blockhash.bytes, 1, SOL_HASH_SIZE, bf) == SOL_HASH_SIZE); /* bank hash */
    ASSERT(fwrite(zeros, 1, SOL_HASH_SIZE, bf) == SOL_HASH_SIZE);           /* parent_hash */
    STORE_U64_LE(4);
    ASSERT(fwrite(u64buf, 1, sizeof(u64buf), bf) == sizeof(u64buf)); /* parent_slot */
    STORE_U64_LE(0);
    ASSERT(fwrite(u64buf, 1, sizeof(u64buf), bf) == sizeof(u64buf)); /* hardforks len */

    STORE_U64_LE(0);
    ASSERT(fwrite(u64buf, 1, sizeof(u64buf), bf) == sizeof(u64buf)); /* transaction_count */
    ASSERT(fwrite(u64buf, 1, sizeof(u64buf), bf) == sizeof(u64buf)); /* tick_height */
    STORE_U64_LE(42);
    ASSERT(fwrite(u64buf, 1, sizeof(u64buf), bf) == sizeof(u64buf)); /* signature_count */
    STORE_U64_LE(0);
    ASSERT(fwrite(u64buf, 1, sizeof(u64buf), bf) == sizeof(u64buf)); /* capitalization */
    ASSERT(fwrite(u64buf, 1, sizeof(u64buf), bf) == sizeof(u64buf)); /* max_tick_height */

    tag = 0;
    ASSERT(fwrite(&tag, 1, 1, bf) == 1); /* hashes_per_tick: None */
    STORE_U64_LE(64);
    ASSERT(fwrite(u64buf, 1, sizeof(u64buf), bf) == sizeof(u64buf)); /* ticks_per_slot */

    uint8_t zeros16[16];
    memset(zeros16, 0, sizeof(zeros16));
    ASSERT(fwrite(zeros16, 1, sizeof(zeros16), bf) == sizeof(zeros16)); /* ns_per_slot */
    ASSERT(fwrite(zeros, 1, 8, bf) == 8);                               /* genesis_creation_time */
    ASSERT(fwrite(zeros, 1, 8, bf) == 8);                               /* slots_per_year */
    STORE_U64_LE(0);
    ASSERT(fwrite(u64buf, 1, sizeof(u64buf), bf) == sizeof(u64buf));    /* accounts_data_len */

    STORE_U64_LE(5);
    ASSERT(fwrite(u64buf, 1, sizeof(u64buf), bf) == sizeof(u64buf)); /* slot */
    STORE_U64_LE(0);
    ASSERT(fwrite(u64buf, 1, sizeof(u64buf), bf) == sizeof(u64buf)); /* epoch */
    ASSERT(fwrite(u64buf, 1, sizeof(u64buf), bf) == sizeof(u64buf)); /* block_height */

    /* accounts_lt_hash tail */
    tag = 1;
    ASSERT(fwrite(&tag, 1, 1, bf) == 1); /* Some */
    ASSERT(fwrite(&accounts_lt_hash, 1, sizeof(accounts_lt_hash), bf) == sizeof(accounts_lt_hash));

    fclose(bf);
#undef STORE_U64_LE

    sol_snapshot_mgr_t* mgr = sol_snapshot_mgr_new(NULL);
    ASSERT(mgr != NULL);

    sol_bank_t* loaded_bank = NULL;
    sol_accounts_db_t* loaded_db = NULL;
    sol_err_t err = sol_snapshot_load(mgr, dir, &loaded_bank, &loaded_db);
    ASSERT(err == SOL_OK);
    ASSERT(loaded_bank != NULL);
    ASSERT(loaded_db != NULL);

    sol_blake3_t got_checksum = {0};
    sol_bank_accounts_lt_hash_checksum(loaded_bank, &got_checksum);

    sol_blake3_t expected_checksum = {0};
    sol_lt_hash_checksum(&accounts_lt_hash, &expected_checksum);

    ASSERT(memcmp(got_checksum.bytes, expected_checksum.bytes, sizeof(got_checksum.bytes)) == 0);
    ASSERT(sol_bank_signature_count(loaded_bank) == 42);

    sol_bank_destroy(loaded_bank);
    sol_accounts_db_destroy(loaded_db);
    sol_snapshot_mgr_destroy(mgr);

    sol_snapshot_archive_rmdir(dir);
}

/*
 * Test status cache creation
 */
TEST(status_cache_new) {
    sol_status_cache_t* cache = sol_status_cache_new(1000);
    ASSERT(cache != NULL);
    sol_status_cache_destroy(cache);
}

/*
 * Test status cache add and lookup
 */
TEST(status_cache_add_lookup) {
    sol_status_cache_t* cache = sol_status_cache_new(100);
    ASSERT(cache != NULL);

    sol_signature_t sig = {{1, 2, 3, 4, 5, 6, 7, 8}};
    sol_err_t err = sol_status_cache_add(cache, &sig, 100, SOL_OK);
    ASSERT(err == SOL_OK);

    sol_slot_t slot;
    sol_err_t status;
    bool found = sol_status_cache_lookup(cache, &sig, &slot, &status);
    ASSERT(found == true);
    ASSERT(slot == 100);
    ASSERT(status == SOL_OK);

    /* Lookup nonexistent */
    sol_signature_t other_sig = {{9, 10, 11, 12}};
    found = sol_status_cache_lookup(cache, &other_sig, NULL, NULL);
    ASSERT(found == false);

    sol_status_cache_destroy(cache);
}

/*
 * Test status cache purge
 */
TEST(status_cache_purge) {
    sol_status_cache_t* cache = sol_status_cache_new(100);
    ASSERT(cache != NULL);

    /* Add entries at different slots */
    sol_signature_t sig1 = {{1}};
    sol_signature_t sig2 = {{2}};
    sol_signature_t sig3 = {{3}};

    sol_status_cache_add(cache, &sig1, 100, SOL_OK);
    sol_status_cache_add(cache, &sig2, 200, SOL_OK);
    sol_status_cache_add(cache, &sig3, 300, SOL_OK);

    /* Purge entries before slot 200 */
    size_t removed = sol_status_cache_purge(cache, 200);
    ASSERT(removed == 1);

    /* sig1 should be gone */
    ASSERT(sol_status_cache_lookup(cache, &sig1, NULL, NULL) == false);
    /* sig2 and sig3 should remain */
    ASSERT(sol_status_cache_lookup(cache, &sig2, NULL, NULL) == true);
    ASSERT(sol_status_cache_lookup(cache, &sig3, NULL, NULL) == true);

    sol_status_cache_destroy(cache);
}

/*
 * Test status cache serialization
 */
TEST(status_cache_serialize) {
    sol_status_cache_t* cache = sol_status_cache_new(100);
    ASSERT(cache != NULL);

    sol_signature_t sig1 = {{1, 2, 3}};
    sol_signature_t sig2 = {{4, 5, 6}};
    sol_status_cache_add(cache, &sig1, 100, SOL_OK);
    sol_status_cache_add(cache, &sig2, 200, SOL_ERR_TX_SIGNATURE);

    uint8_t buffer[4096];
    size_t len = sol_status_cache_serialize(cache, buffer, sizeof(buffer));
    ASSERT(len > 0);

    /* Deserialize into new cache */
    sol_status_cache_t* cache2 = sol_status_cache_new(100);
    sol_err_t err = sol_status_cache_deserialize(buffer, len, cache2);
    ASSERT(err == SOL_OK);

    /* Verify entries */
    sol_slot_t slot;
    sol_err_t status;
    ASSERT(sol_status_cache_lookup(cache2, &sig1, &slot, &status) == true);
    ASSERT(slot == 100);
    ASSERT(status == SOL_OK);

    ASSERT(sol_status_cache_lookup(cache2, &sig2, &slot, &status) == true);
    ASSERT(slot == 200);
    ASSERT(status == SOL_ERR_TX_SIGNATURE);

    sol_status_cache_destroy(cache);
    sol_status_cache_destroy(cache2);
}

/*
 * Test snapshot verification
 */
TEST(snapshot_verify) {
    /* Non-existent file should fail */
    sol_err_t err = sol_snapshot_verify("/nonexistent/path/snapshot.tar.zst");
    ASSERT(err == SOL_ERR_NOTFOUND);
}

static void
write_test_tar_header(void* out, const char* name, uint32_t mode, uint64_t size, char typeflag) {
    typedef struct {
        char name[100];
        char mode[8];
        char uid[8];
        char gid[8];
        char size[12];
        char mtime[12];
        char checksum[8];
        char typeflag;
        char linkname[100];
        char magic[6];
        char version[2];
        char uname[32];
        char gname[32];
        char devmajor[8];
        char devminor[8];
        char prefix[155];
        char padding[12];
    } tar_header_t;

    tar_header_t h;
    memset(&h, 0, sizeof(h));

    snprintf(h.name, sizeof(h.name), "%s", name);
    snprintf(h.mode, sizeof(h.mode), "%07o", mode & 0777u);
    snprintf(h.uid, sizeof(h.uid), "%07o", 0);
    snprintf(h.gid, sizeof(h.gid), "%07o", 0);
    snprintf(h.size, sizeof(h.size), "%011llo", (unsigned long long)size);
    snprintf(h.mtime, sizeof(h.mtime), "%011o", 0);
    memset(h.checksum, ' ', sizeof(h.checksum));
    h.typeflag = typeflag;
    memcpy(h.magic, "ustar", 5);
    h.version[0] = '0';
    h.version[1] = '0';

    unsigned int sum = 0;
    const unsigned char* p = (const unsigned char*)&h;
    for (size_t i = 0; i < 512; i++) {
        sum += p[i];
    }
    snprintf(h.checksum, sizeof(h.checksum), "%06o", sum);
    h.checksum[7] = ' ';

    memcpy(out, &h, 512);
}

TEST(snapshot_archive_extract_zstd_streaming) {
#ifndef SOL_HAS_ZSTD
    return;
#else
    char tmpdir[] = "/tmp/solana_c_snapshot_tar_zstd_XXXXXX";
    char* base = mkdtemp(tmpdir);
    ASSERT(base != NULL);

    char archive_path[512];
    snprintf(archive_path, sizeof(archive_path), "%s/test.tar.zst", base);

    /* Build a tiny tar archive in memory. */
    uint8_t tar[4096];
    memset(tar, 0, sizeof(tar));
    size_t off = 0;

    /* Regular file "dir/foo.txt" with contents "hello". */
    write_test_tar_header(tar + off, "dir/foo.txt", 0644, 5, '0');
    off += 512;
    memcpy(tar + off, "hello", 5);
    off += 5;
    off += 512 - 5;

    /* Zero-length file "empty". */
    write_test_tar_header(tar + off, "empty", 0644, 0, '0');
    off += 512;

    /* End-of-archive: two zero blocks. */
    memset(tar + off, 0, 1024);
    off += 1024;

    size_t max_out = ZSTD_compressBound(off);
    void* comp = sol_alloc(max_out);
    ASSERT(comp != NULL);

    size_t comp_sz = ZSTD_compress(comp, max_out, tar, off, 1);
    ASSERT(!ZSTD_isError(comp_sz));

    FILE* f = fopen(archive_path, "wb");
    ASSERT(f != NULL);
    ASSERT(fwrite(comp, 1, comp_sz, f) == comp_sz);
    fclose(f);
    sol_free(comp);

    char out_dir[512];
    snprintf(out_dir, sizeof(out_dir), "%s/out", base);

    sol_archive_extract_opts_t opts = SOL_ARCHIVE_EXTRACT_OPTS_DEFAULT;
    opts.output_dir = out_dir;

    sol_err_t err = sol_snapshot_archive_extract(archive_path, &opts);
    ASSERT(err == SOL_OK);

    /* Validate extracted contents. */
    char p1[512];
    snprintf(p1, sizeof(p1), "%s/dir/foo.txt", out_dir);
    FILE* in = fopen(p1, "rb");
    ASSERT(in != NULL);
    char buf[16] = {0};
    ASSERT(fread(buf, 1, 5, in) == 5);
    fclose(in);
    ASSERT(memcmp(buf, "hello", 5) == 0);
    ASSERT(access(p1, R_OK) == 0);

    char p2[512];
    snprintf(p2, sizeof(p2), "%s/empty", out_dir);
    struct stat st;
    ASSERT(stat(p2, &st) == 0);
    ASSERT(st.st_size == 0);

    sol_snapshot_archive_rmdir(base);
#endif
}

typedef struct {
    int     calls;
    char    path[128];
    size_t  len;
    uint8_t data[16];
} test_stream_cb_ctx_t;

static sol_err_t
test_stream_cb(void* vctx, const char* rel_path, uint8_t* data, size_t len) {
    test_stream_cb_ctx_t* ctx = (test_stream_cb_ctx_t*)vctx;
    if (!ctx || !rel_path) {
        sol_free(data);
        return SOL_ERR_INVAL;
    }

    ctx->calls++;
    snprintf(ctx->path, sizeof(ctx->path), "%s", rel_path);
    ctx->len = len;
    memset(ctx->data, 0, sizeof(ctx->data));
    if (data && len > 0) {
        size_t n = len;
        if (n > sizeof(ctx->data)) n = sizeof(ctx->data);
        memcpy(ctx->data, data, n);
    }

    sol_free(data);
    return SOL_OK;
}

TEST(snapshot_archive_extract_stream_prefix_callback) {
#ifndef SOL_HAS_ZSTD
    return;
#else
    char tmpdir[] = "/tmp/solana_c_snapshot_tar_zstd_cb_XXXXXX";
    char* base = mkdtemp(tmpdir);
    ASSERT(base != NULL);

    char archive_path[512];
    snprintf(archive_path, sizeof(archive_path), "%s/test.tar.zst", base);

    /* Build a tiny tar archive in memory. */
    uint8_t tar[4096];
    memset(tar, 0, sizeof(tar));
    size_t off = 0;

    /* Streamed file "accounts/1.2" with contents "abc". */
    write_test_tar_header(tar + off, "accounts/1.2", 0644, 3, '0');
    off += 512;
    memcpy(tar + off, "abc", 3);
    off += 3;
    off += 512 - 3;

    /* Regular extracted file "dir/keep.txt" with contents "hello". */
    write_test_tar_header(tar + off, "dir/keep.txt", 0644, 5, '0');
    off += 512;
    memcpy(tar + off, "hello", 5);
    off += 5;
    off += 512 - 5;

    /* End-of-archive: two zero blocks. */
    memset(tar + off, 0, 1024);
    off += 1024;

    size_t max_out = ZSTD_compressBound(off);
    void* comp = sol_alloc(max_out);
    ASSERT(comp != NULL);

    size_t comp_sz = ZSTD_compress(comp, max_out, tar, off, 1);
    ASSERT(!ZSTD_isError(comp_sz));

    FILE* f = fopen(archive_path, "wb");
    ASSERT(f != NULL);
    ASSERT(fwrite(comp, 1, comp_sz, f) == comp_sz);
    fclose(f);
    sol_free(comp);

    char out_dir[512];
    snprintf(out_dir, sizeof(out_dir), "%s/out", base);

    test_stream_cb_ctx_t cb_ctx = {0};
    sol_archive_extract_opts_t opts = SOL_ARCHIVE_EXTRACT_OPTS_DEFAULT;
    opts.output_dir = out_dir;
    opts.stream_prefix = "accounts/";
    opts.stream_file_callback = test_stream_cb;
    opts.stream_file_ctx = &cb_ctx;
    opts.stream_max_file_size = 1024 * 1024;

    sol_err_t err = sol_snapshot_archive_extract(archive_path, &opts);
    ASSERT(err == SOL_OK);
    ASSERT(cb_ctx.calls == 1);
    ASSERT(strcmp(cb_ctx.path, "accounts/1.2") == 0);
    ASSERT(cb_ctx.len == 3);
    ASSERT(memcmp(cb_ctx.data, "abc", 3) == 0);

    /* Ensure streamed file was not written to disk. */
    char streamed_path[512];
    snprintf(streamed_path, sizeof(streamed_path), "%s/accounts/1.2", out_dir);
    ASSERT(access(streamed_path, F_OK) != 0);

    /* Ensure regular file still extracted. */
    char keep_path[512];
    snprintf(keep_path, sizeof(keep_path), "%s/dir/keep.txt", out_dir);
    FILE* in = fopen(keep_path, "rb");
    ASSERT(in != NULL);
    char buf[16] = {0};
    ASSERT(fread(buf, 1, 5, in) == 5);
    fclose(in);
    ASSERT(memcmp(buf, "hello", 5) == 0);

    sol_snapshot_archive_rmdir(base);
#endif
}

TEST(snapshot_archive_extract_stream_prefix_skip_unmatched) {
#ifndef SOL_HAS_ZSTD
    return;
#else
    char tmpdir[] = "/tmp/solana_c_snapshot_tar_zstd_skip_unmatched_XXXXXX";
    char* base = mkdtemp(tmpdir);
    ASSERT(base != NULL);

    char archive_path[512];
    snprintf(archive_path, sizeof(archive_path), "%s/test.tar.zst", base);

    /* Build a tiny tar archive in memory. */
    uint8_t tar[4096];
    memset(tar, 0, sizeof(tar));
    size_t off = 0;

    /* Streamed file "accounts/1.2" with contents "abc". */
    write_test_tar_header(tar + off, "accounts/1.2", 0644, 3, '0');
    off += 512;
    memcpy(tar + off, "abc", 3);
    off += 3;
    off += 512 - 3;

    /* Non-matching file "dir/keep.txt" with contents "hello". */
    write_test_tar_header(tar + off, "dir/keep.txt", 0644, 5, '0');
    off += 512;
    memcpy(tar + off, "hello", 5);
    off += 5;
    off += 512 - 5;

    /* End-of-archive: two zero blocks. */
    memset(tar + off, 0, 1024);
    off += 1024;

    size_t max_out = ZSTD_compressBound(off);
    void* comp = sol_alloc(max_out);
    ASSERT(comp != NULL);

    size_t comp_sz = ZSTD_compress(comp, max_out, tar, off, 1);
    ASSERT(!ZSTD_isError(comp_sz));

    FILE* f = fopen(archive_path, "wb");
    ASSERT(f != NULL);
    ASSERT(fwrite(comp, 1, comp_sz, f) == comp_sz);
    fclose(f);
    sol_free(comp);

    char out_dir[512];
    snprintf(out_dir, sizeof(out_dir), "%s/out", base);

    test_stream_cb_ctx_t cb_ctx = {0};
    sol_archive_extract_opts_t opts = SOL_ARCHIVE_EXTRACT_OPTS_DEFAULT;
    opts.output_dir = out_dir;
    opts.stream_prefix = "accounts/";
    opts.stream_file_callback = test_stream_cb;
    opts.stream_file_ctx = &cb_ctx;
    opts.stream_max_file_size = 1024 * 1024;
    opts.skip_unmatched = true;

    sol_err_t err = sol_snapshot_archive_extract(archive_path, &opts);
    ASSERT(err == SOL_OK);
    ASSERT(cb_ctx.calls == 1);
    ASSERT(strcmp(cb_ctx.path, "accounts/1.2") == 0);
    ASSERT(cb_ctx.len == 3);
    ASSERT(memcmp(cb_ctx.data, "abc", 3) == 0);

    /* Ensure streamed file was not written to disk. */
    char streamed_path[512];
    snprintf(streamed_path, sizeof(streamed_path), "%s/accounts/1.2", out_dir);
    ASSERT(access(streamed_path, F_OK) != 0);

    /* Ensure non-matching file was not extracted either. */
    char keep_path[512];
    snprintf(keep_path, sizeof(keep_path), "%s/dir/keep.txt", out_dir);
    ASSERT(access(keep_path, F_OK) != 0);

    sol_snapshot_archive_rmdir(base);
#endif
}

typedef struct {
    int      file_calls;
    int      chunk_calls;
    char     path[128];
    uint64_t file_size;
    uint64_t next_offset;
    uint64_t total_bytes;
    bool     saw_last;
    uint8_t  first_byte;
    uint8_t  last_byte;
} test_stream_mixed_cb_ctx_t;

static sol_err_t
test_stream_file_cb_mixed(void* vctx, const char* rel_path, uint8_t* data, size_t len) {
    test_stream_mixed_cb_ctx_t* ctx = (test_stream_mixed_cb_ctx_t*)vctx;
    if (!ctx || !rel_path) {
        sol_free(data);
        return SOL_ERR_INVAL;
    }
    (void)len;
    ctx->file_calls++;
    sol_free(data);
    return SOL_OK;
}

static sol_err_t
test_stream_chunk_cb_mixed(void* vctx,
                           const char* rel_path,
                           const uint8_t* data,
                           size_t len,
                           uint64_t file_size,
                           uint64_t file_offset,
                           bool is_last) {
    test_stream_mixed_cb_ctx_t* ctx = (test_stream_mixed_cb_ctx_t*)vctx;
    if (!ctx || !rel_path) return SOL_ERR_INVAL;
    if (len > 0 && !data) return SOL_ERR_INVAL;

    if (ctx->chunk_calls == 0) {
        snprintf(ctx->path, sizeof(ctx->path), "%s", rel_path);
        ctx->file_size = file_size;
        ctx->first_byte = (len > 0) ? data[0] : 0;
    }

    ASSERT(file_offset == ctx->next_offset);
    ctx->next_offset += (uint64_t)len;
    ctx->total_bytes += (uint64_t)len;
    ctx->chunk_calls++;

    if (is_last) {
        ctx->saw_last = true;
        ctx->last_byte = (len > 0) ? data[len - 1] : 0;
        ASSERT(ctx->next_offset == file_size);
    }

    return SOL_OK;
}

TEST(snapshot_archive_extract_stream_prefix_chunk_callback) {
#ifndef SOL_HAS_ZSTD
    return;
#else
    char tmpdir[] = "/tmp/solana_c_snapshot_tar_zstd_chunkcb_XXXXXX";
    char* base = mkdtemp(tmpdir);
    ASSERT(base != NULL);

    char archive_path[512];
    snprintf(archive_path, sizeof(archive_path), "%s/test.tar.zst", base);

    /* Build a tar archive in memory. */
    uint8_t tar[8192];
    memset(tar, 0, sizeof(tar));
    size_t off = 0;

    /* Streamed file "accounts/1.2" with deterministic contents. */
    const size_t payload_len = 2048;
    write_test_tar_header(tar + off, "accounts/1.2", 0644, payload_len, '0');
    off += 512;
    for (size_t i = 0; i < payload_len; i++) {
        tar[off + i] = (uint8_t)(i & 0xffu);
    }
    off += payload_len;

    /* Regular extracted file "dir/keep.txt" with contents "hello". */
    write_test_tar_header(tar + off, "dir/keep.txt", 0644, 5, '0');
    off += 512;
    memcpy(tar + off, "hello", 5);
    off += 5;
    off += 512 - 5;

    /* End-of-archive: two zero blocks. */
    memset(tar + off, 0, 1024);
    off += 1024;

    size_t max_out = ZSTD_compressBound(off);
    void* comp = sol_alloc(max_out);
    ASSERT(comp != NULL);

    size_t comp_sz = ZSTD_compress(comp, max_out, tar, off, 1);
    ASSERT(!ZSTD_isError(comp_sz));

    FILE* f = fopen(archive_path, "wb");
    ASSERT(f != NULL);
    ASSERT(fwrite(comp, 1, comp_sz, f) == comp_sz);
    fclose(f);
    sol_free(comp);

    char out_dir[512];
    snprintf(out_dir, sizeof(out_dir), "%s/out", base);

    test_stream_mixed_cb_ctx_t ctx = {0};
    sol_archive_extract_opts_t opts = SOL_ARCHIVE_EXTRACT_OPTS_DEFAULT;
    opts.output_dir = out_dir;
    opts.stream_prefix = "accounts/";
    opts.stream_file_callback = test_stream_file_cb_mixed;
    opts.stream_chunk_callback = test_stream_chunk_cb_mixed;
    opts.stream_file_ctx = &ctx;
    opts.stream_max_file_size = 1024; /* force chunk callback */

    sol_err_t err = sol_snapshot_archive_extract(archive_path, &opts);
    ASSERT(err == SOL_OK);
    ASSERT(ctx.file_calls == 0);
    ASSERT(ctx.chunk_calls > 0);
    ASSERT(strcmp(ctx.path, "accounts/1.2") == 0);
    ASSERT(ctx.file_size == payload_len);
    ASSERT(ctx.total_bytes == payload_len);
    ASSERT(ctx.saw_last);
    ASSERT(ctx.first_byte == 0);
    ASSERT(ctx.last_byte == (uint8_t)((payload_len - 1) & 0xffu));

    /* Ensure streamed file was not written to disk. */
    char streamed_path[512];
    snprintf(streamed_path, sizeof(streamed_path), "%s/accounts/1.2", out_dir);
    ASSERT(access(streamed_path, F_OK) != 0);

    /* Ensure regular file still extracted. */
    char keep_path[512];
    snprintf(keep_path, sizeof(keep_path), "%s/dir/keep.txt", out_dir);
    FILE* in = fopen(keep_path, "rb");
    ASSERT(in != NULL);
    char buf[16] = {0};
    ASSERT(fread(buf, 1, 5, in) == 5);
    fclose(in);
    ASSERT(memcmp(buf, "hello", 5) == 0);

    sol_snapshot_archive_rmdir(base);
#endif
}

TEST(snapshot_load_archive_persists_appendvec_accounts_files) {
#if !defined(SOL_HAS_ZSTD) || !defined(SOL_HAS_ROCKSDB)
    return;
#else
    char tmpdir[] = "/tmp/solana_c_snapshot_appendvec_persist_XXXXXX";
    char* base = mkdtemp(tmpdir);
    ASSERT(base != NULL);

    char archive_path[512];
    snprintf(archive_path, sizeof(archive_path), "%s/test.tar.zst", base);

    uint8_t tar[8192];
    memset(tar, 0, sizeof(tar));
    size_t off = 0;

    /* Minimal bank snapshot header file: snapshots/5/5 */
    uint8_t bank_hdr[64];
    memset(bank_hdr, 0, sizeof(bank_hdr));
    bank_hdr[8] = 1; /* Option<Hash> tag */
    for (size_t i = 0; i < SOL_HASH_SIZE; i++) {
        bank_hdr[9 + i] = (uint8_t)(0xA0u + (uint8_t)i);
    }

    write_test_tar_header(tar + off, "snapshots/5/5", 0644, sizeof(bank_hdr), '0');
    off += 512;
    memcpy(tar + off, bank_hdr, sizeof(bank_hdr));
    off += sizeof(bank_hdr);
    off += 512 - sizeof(bank_hdr);

    /* Accounts file in Solana3 AppendVec layout: accounts/5.0 */
    uint8_t accounts_file[136u * 8u];
    memset(accounts_file, 0, sizeof(accounts_file));

    for (uint64_t i = 0; i < 8; i++) {
        sol_pubkey_t pubkey = {0};
        pubkey.bytes[0] = 0x11;
        pubkey.bytes[1] = 0x22;
        pubkey.bytes[2] = (uint8_t)i;

        size_t rec_off = (size_t)i * 136u;
        uint64_t write_version = i + 1;
        uint64_t data_len = 0;
        uint64_t lamports = 1000 + i;
        uint64_t rent_epoch = 0;

        memcpy(accounts_file + rec_off + 0, &write_version, 8);
        memcpy(accounts_file + rec_off + 8, &data_len, 8);
        memcpy(accounts_file + rec_off + 16, pubkey.bytes, 32);
        memcpy(accounts_file + rec_off + 48, &lamports, 8);
        memcpy(accounts_file + rec_off + 56, &rent_epoch, 8);
        memcpy(accounts_file + rec_off + 64, SOL_SYSTEM_PROGRAM_ID.bytes, 32);
        accounts_file[rec_off + 96] = 0; /* executable */
        /* trailing 32 bytes meta are already zeroed */
    }

    write_test_tar_header(tar + off, "accounts/5.0", 0644, sizeof(accounts_file), '0');
    off += 512;
    memcpy(tar + off, accounts_file, sizeof(accounts_file));
    off += sizeof(accounts_file);
    size_t rem = sizeof(accounts_file) % 512u;
    if (rem) off += 512u - rem;

    memset(tar + off, 0, 1024);
    off += 1024;

    size_t max_out = ZSTD_compressBound(off);
    void* comp = sol_alloc(max_out);
    ASSERT(comp != NULL);

    size_t comp_sz = ZSTD_compress(comp, max_out, tar, off, 1);
    ASSERT(!ZSTD_isError(comp_sz));

    FILE* f = fopen(archive_path, "wb");
    ASSERT(f != NULL);
    ASSERT(fwrite(comp, 1, comp_sz, f) == comp_sz);
    fclose(f);
    sol_free(comp);

    char rocksdb_path[512];
    snprintf(rocksdb_path, sizeof(rocksdb_path), "%s/rocksdb", base);
    ASSERT(mkdir(rocksdb_path, 0755) == 0);

    char appendvec_path[512];
    snprintf(appendvec_path, sizeof(appendvec_path), "%s/appendvec", base);

    sol_accounts_db_config_t db_cfg = SOL_ACCOUNTS_DB_CONFIG_DEFAULT;
    db_cfg.storage_type = SOL_ACCOUNTS_STORAGE_APPENDVEC;
    db_cfg.rocksdb_path = rocksdb_path;
    db_cfg.appendvec_path = appendvec_path;

    sol_snapshot_mgr_t* mgr = sol_snapshot_mgr_new(NULL);
    ASSERT(mgr != NULL);

    sol_bank_t* loaded_bank = NULL;
    sol_accounts_db_t* loaded_db = NULL;
    sol_err_t err = sol_snapshot_load_with_accounts_db_config(mgr,
                                                              archive_path,
                                                              &db_cfg,
                                                              &loaded_bank,
                                                              &loaded_db);
    ASSERT(err == SOL_OK);
    ASSERT(loaded_bank != NULL);
    ASSERT(loaded_db != NULL);
    ASSERT(sol_accounts_db_is_appendvec(loaded_db));

    /* Accounts files should have been moved out of the extracted temp dir. */
    char moved_path[512];
    snprintf(moved_path, sizeof(moved_path), "%s/5.0", appendvec_path);
    ASSERT(access(moved_path, R_OK) == 0);

    sol_pubkey_t want = {0};
    want.bytes[0] = 0x11;
    want.bytes[1] = 0x22;
    want.bytes[2] = 0;

    sol_account_t* acc = sol_accounts_db_load(loaded_db, &want);
    ASSERT(acc != NULL);
    ASSERT(acc->meta.lamports == 1000);
    ASSERT(sol_pubkey_eq(&acc->meta.owner, &SOL_SYSTEM_PROGRAM_ID));
    ASSERT(acc->meta.data_len == 0);
    sol_account_destroy(acc);

    sol_bank_destroy(loaded_bank);
    sol_accounts_db_destroy(loaded_db);
    sol_snapshot_mgr_destroy(mgr);

    sol_snapshot_archive_rmdir(base);
#endif
}

TEST(snapshot_load_from_directory) {
    char tmpdir[] = "/tmp/solana_c_snapshot_XXXXXX";
    char* dir = mkdtemp(tmpdir);
    ASSERT(dir != NULL);

    /* Create minimal snapshot structure */
    char path[512];

    snprintf(path, sizeof(path), "%s/snapshots", dir);
    mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/snapshots/5", dir);
    mkdir(path, 0755);

    snprintf(path, sizeof(path), "%s/accounts", dir);
    mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/accounts/5.0", dir);
    mkdir(path, 0755);

    /* Write bank fields file: snapshots/5/5 */
    snprintf(path, sizeof(path), "%s/snapshots/5/5", dir);
    FILE* bf = fopen(path, "wb");
    ASSERT(bf != NULL);

    sol_hash_t parent_hash = {0};
    parent_hash.bytes[0] = 0xAA;
    sol_bank_config_t bank_config = SOL_BANK_CONFIG_DEFAULT;
    sol_bank_t* bank = sol_bank_new(5, &parent_hash, NULL, &bank_config);
    ASSERT(bank != NULL);

    uint8_t bank_data[4096];
    size_t bank_len = sol_bank_fields_serialize(bank, bank_data, sizeof(bank_data));
    ASSERT(bank_len == sizeof(sol_bank_fields_t));
    ASSERT(fwrite(bank_data, 1, bank_len, bf) == bank_len);
    fclose(bf);

    sol_bank_destroy(bank);

    /* Write one account storage file under accounts/5.0 */
    snprintf(path, sizeof(path), "%s/accounts/5.0/storage.bin", dir);
    FILE* af = fopen(path, "wb");
    ASSERT(af != NULL);

    sol_account_storage_header_t hdr = {
        .slot = 5,
        .id = 1,
        .count = 1,
        .data_len = sizeof(sol_stored_account_t),
    };

    sol_pubkey_t pubkey = {0};
    pubkey.bytes[0] = 0x11;
    pubkey.bytes[1] = 0x22;

    sol_stored_account_t stored = {0};
    stored.write_version = 1;
    stored.data_len = 0;
    stored.pubkey = pubkey;
    stored.owner = SOL_SYSTEM_PROGRAM_ID;
    stored.lamports = 123;
    stored.rent_epoch = 0;
    stored.executable = false;

    ASSERT(fwrite(&hdr, 1, sizeof(hdr), af) == sizeof(hdr));
    ASSERT(fwrite(&stored, 1, sizeof(stored), af) == sizeof(stored));
    fclose(af);

    sol_snapshot_mgr_t* mgr = sol_snapshot_mgr_new(NULL);
    ASSERT(mgr != NULL);

    sol_bank_t* loaded_bank = NULL;
    sol_accounts_db_t* loaded_db = NULL;

    sol_err_t err = sol_snapshot_load(mgr, dir, &loaded_bank, &loaded_db);
    ASSERT(err == SOL_OK);
    ASSERT(loaded_bank != NULL);
    ASSERT(loaded_db != NULL);

    ASSERT(sol_bank_slot(loaded_bank) == 5);
    ASSERT(sol_accounts_db_exists(loaded_db, &pubkey));

    sol_account_t* acct = sol_accounts_db_load(loaded_db, &pubkey);
    ASSERT(acct != NULL);
    ASSERT(acct->meta.lamports == 123);
    sol_account_destroy(acct);

    sol_bank_destroy(loaded_bank);
    sol_accounts_db_destroy(loaded_db);
    sol_snapshot_mgr_destroy(mgr);

    /* Cleanup */
    sol_snapshot_archive_rmdir(dir);
}

TEST(snapshot_archive_filename_hash_verify) {
    char tmpdir[] = "/tmp/solana_c_snapshot_archive_hash_XXXXXX";
    char* base = mkdtemp(tmpdir);
    ASSERT(base != NULL);

    /* Build a minimal snapshot payload (same as directory load tests). */
    sol_hash_t parent_hash = {0};
    parent_hash.bytes[0] = 0xAA;
    sol_bank_config_t bank_config = SOL_BANK_CONFIG_DEFAULT;
    sol_bank_t* bank = sol_bank_new(5, &parent_hash, NULL, &bank_config);
    ASSERT(bank != NULL);

    uint8_t bank_data[4096];
    size_t bank_len = sol_bank_fields_serialize(bank, bank_data, sizeof(bank_data));
    ASSERT(bank_len == sizeof(sol_bank_fields_t));
    sol_bank_destroy(bank);

    sol_account_storage_header_t hdr = {
        .slot = 5,
        .id = 1,
        .count = 2,
        .data_len = 2 * sizeof(sol_stored_account_t),
    };

    sol_pubkey_t pk1 = {0};
    pk1.bytes[0] = 0x22;
    sol_pubkey_t pk2 = {0};
    pk2.bytes[0] = 0x11;

    sol_stored_account_t stored1 = {0};
    stored1.write_version = 1;
    stored1.data_len = 0;
    stored1.pubkey = pk1;
    stored1.owner = SOL_SYSTEM_PROGRAM_ID;
    stored1.lamports = 222;
    stored1.rent_epoch = 0;
    stored1.executable = false;

    sol_stored_account_t stored2 = {0};
    stored2.write_version = 1;
    stored2.data_len = 0;
    stored2.pubkey = pk2;
    stored2.owner = SOL_SYSTEM_PROGRAM_ID;
    stored2.lamports = 111;
    stored2.rent_epoch = 0;
    stored2.executable = false;

    /* Compute expected accounts hash (sorted by pubkey). */
    sol_hash_t h1 = {0};
    sol_hash_t h2 = {0};

    sol_account_t a1 = {0};
    a1.meta.owner = stored1.owner;
    a1.meta.lamports = stored1.lamports;
    a1.meta.rent_epoch = stored1.rent_epoch;
    a1.meta.executable = stored1.executable;
    a1.meta.data_len = stored1.data_len;

    sol_account_t a2 = {0};
    a2.meta.owner = stored2.owner;
    a2.meta.lamports = stored2.lamports;
    a2.meta.rent_epoch = stored2.rent_epoch;
    a2.meta.executable = stored2.executable;
    a2.meta.data_len = stored2.data_len;

    sol_account_hash(&stored1.pubkey, &a1, &h1);
    sol_account_hash(&stored2.pubkey, &a2, &h2);

    const sol_pubkey_t* pubs[2] = {&stored1.pubkey, &stored2.pubkey};
    const sol_hash_t* hashes[2] = {&h1, &h2};
    if (memcmp(pubs[0]->bytes, pubs[1]->bytes, 32) > 0) {
        const sol_pubkey_t* tp = pubs[0];
        pubs[0] = pubs[1];
        pubs[1] = tp;
        const sol_hash_t* th = hashes[0];
        hashes[0] = hashes[1];
        hashes[1] = th;
    }

    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    sol_sha256_update(&ctx, hashes[0]->bytes, SOL_HASH_SIZE);
    sol_sha256_update(&ctx, hashes[1]->bytes, SOL_HASH_SIZE);
    sol_sha256_t digest;
    sol_sha256_final(&ctx, &digest);

    sol_hash_t accounts_hash = {0};
    memcpy(accounts_hash.bytes, digest.bytes, SOL_HASH_SIZE);

    char hash58[SOL_PUBKEY_BASE58_LEN] = {0};
    ASSERT(sol_pubkey_to_base58((const sol_pubkey_t*)&accounts_hash, hash58, sizeof(hash58)) == SOL_OK);

    char archive_path[512];
    snprintf(archive_path, sizeof(archive_path), "%s/snapshot-5-%s.tar", base, hash58);

    /* Build a tiny tar archive in memory. */
    uint8_t tar[16384];
    memset(tar, 0, sizeof(tar));
    size_t off = 0;

    /* snapshots/5/5 */
    write_test_tar_header(tar + off, "snapshots/5/5", 0644, bank_len, '0');
    off += 512;
    memcpy(tar + off, bank_data, bank_len);
    off += bank_len;
    off += (512 - (bank_len % 512)) % 512;

    /* accounts/5.0/storage.bin */
    const size_t acct_len = sizeof(hdr) + (2 * sizeof(sol_stored_account_t));
    write_test_tar_header(tar + off, "accounts/5.0/storage.bin", 0644, acct_len, '0');
    off += 512;
    memcpy(tar + off, &hdr, sizeof(hdr));
    off += sizeof(hdr);
    /* Intentionally write in reverse pubkey order */
    memcpy(tar + off, &stored1, sizeof(stored1));
    off += sizeof(stored1);
    memcpy(tar + off, &stored2, sizeof(stored2));
    off += sizeof(stored2);
    off += (512 - (acct_len % 512)) % 512;

    /* End-of-archive: two zero blocks. */
    memset(tar + off, 0, 1024);
    off += 1024;

    FILE* f = fopen(archive_path, "wb");
    ASSERT(f != NULL);
    ASSERT(fwrite(tar, 1, off, f) == off);
    fclose(f);

    sol_snapshot_config_t cfg = SOL_SNAPSHOT_CONFIG_DEFAULT;
    cfg.verify_accounts_hash = true;

    sol_snapshot_mgr_t* mgr = sol_snapshot_mgr_new(&cfg);
    ASSERT(mgr != NULL);

    sol_bank_t* loaded_bank = NULL;
    sol_accounts_db_t* loaded_db = NULL;

    sol_err_t err = sol_snapshot_load(mgr, archive_path, &loaded_bank, &loaded_db);
    ASSERT(err == SOL_OK);
    ASSERT(loaded_bank != NULL);
    ASSERT(loaded_db != NULL);

    sol_bank_destroy(loaded_bank);
    sol_accounts_db_destroy(loaded_db);
    sol_snapshot_mgr_destroy(mgr);

    /* Corrupt the filename hash and ensure we detect mismatch. */
    accounts_hash.bytes[0] ^= 0x01;
    ASSERT(sol_pubkey_to_base58((const sol_pubkey_t*)&accounts_hash, hash58, sizeof(hash58)) == SOL_OK);
    char bad_archive_path[512];
    snprintf(bad_archive_path, sizeof(bad_archive_path), "%s/snapshot-5-%s.tar", base, hash58);

    ASSERT(rename(archive_path, bad_archive_path) == 0);

    mgr = sol_snapshot_mgr_new(&cfg);
    ASSERT(mgr != NULL);
    loaded_bank = NULL;
    loaded_db = NULL;
    err = sol_snapshot_load(mgr, bad_archive_path, &loaded_bank, &loaded_db);
    ASSERT(err == SOL_ERR_SNAPSHOT_MISMATCH);
    ASSERT(loaded_bank == NULL);
    ASSERT(loaded_db == NULL);
    sol_snapshot_mgr_destroy(mgr);

    sol_snapshot_archive_rmdir(base);
}

static size_t
align_up_8_test(size_t x) {
    return (x + 7u) & ~(size_t)7u;
}

TEST(snapshot_load_accounts_solana_layout_aligned) {
    char tmpdir[] = "/tmp/solana_c_snapshot_solana_layout_XXXXXX";
    char* dir = mkdtemp(tmpdir);
    ASSERT(dir != NULL);

    /* Create minimal snapshot structure */
    char path[512];

    snprintf(path, sizeof(path), "%s/snapshots", dir);
    mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/snapshots/5", dir);
    mkdir(path, 0755);

    snprintf(path, sizeof(path), "%s/accounts", dir);
    mkdir(path, 0755);

    /* Write bank fields file: snapshots/5/5 */
    snprintf(path, sizeof(path), "%s/snapshots/5/5", dir);
    FILE* bf = fopen(path, "wb");
    ASSERT(bf != NULL);

    sol_hash_t parent_hash = {0};
    parent_hash.bytes[0] = 0xCC;
    sol_bank_config_t bank_config = SOL_BANK_CONFIG_DEFAULT;
    sol_bank_t* bank = sol_bank_new(5, &parent_hash, NULL, &bank_config);
    ASSERT(bank != NULL);

    uint8_t bank_data[4096];
    size_t bank_len = sol_bank_fields_serialize(bank, bank_data, sizeof(bank_data));
    ASSERT(bank_len == sizeof(sol_bank_fields_t));
    ASSERT(fwrite(bank_data, 1, bank_len, bf) == bank_len);
    fclose(bf);
    sol_bank_destroy(bank);

    /* Write a headerless, Solana-layout accounts storage file under accounts/5.0 */
    snprintf(path, sizeof(path), "%s/accounts/5.0", dir);
    FILE* af = fopen(path, "wb");
    ASSERT(af != NULL);

    sol_pubkey_t pubkey1 = {0};
    pubkey1.bytes[0] = 0x11;
    pubkey1.bytes[1] = 0x22;

    sol_pubkey_t pubkey2 = {0};
    pubkey2.bytes[0] = 0x33;
    pubkey2.bytes[1] = 0x44;

    sol_pubkey_t owner = SOL_SYSTEM_PROGRAM_ID;

    /* Layout (104 bytes):
     * write_version(u64)
     * pubkey([32])
     * data_len(u64)
     * lamports(u64)
     * owner([32])
     * executable(u8) + padding[7]
     * rent_epoch(u64)
     * then data, then 8-byte alignment padding.
     */
    uint8_t storage[216];
    memset(storage, 0, sizeof(storage));

    size_t off = 0;

    /* Record 1: 1 byte data + 7 bytes alignment padding */
    uint64_t wv = 1;
    uint64_t data_len1 = 1;
    uint64_t lamports1 = 123;
    uint64_t rent_epoch1 = 0;
    memcpy(storage + off + 0, &wv, 8);
    memcpy(storage + off + 8, pubkey1.bytes, 32);
    memcpy(storage + off + 40, &data_len1, 8);
    memcpy(storage + off + 48, &lamports1, 8);
    memcpy(storage + off + 56, owner.bytes, 32);
    storage[off + 88] = 0; /* executable */
    memcpy(storage + off + 96, &rent_epoch1, 8);
    off += 104;
    storage[off++] = 0xAA;
    off = align_up_8_test(off);

    /* Record 2: zero-length data */
    uint64_t data_len2 = 0;
    uint64_t lamports2 = 456;
    uint64_t rent_epoch2 = 0;
    memcpy(storage + off + 0, &wv, 8);
    memcpy(storage + off + 8, pubkey2.bytes, 32);
    memcpy(storage + off + 40, &data_len2, 8);
    memcpy(storage + off + 48, &lamports2, 8);
    memcpy(storage + off + 56, owner.bytes, 32);
    storage[off + 88] = 0; /* executable */
    memcpy(storage + off + 96, &rent_epoch2, 8);
    off += 104;

    ASSERT(off == sizeof(storage));
    ASSERT(fwrite(storage, 1, sizeof(storage), af) == sizeof(storage));
    fclose(af);

    sol_snapshot_mgr_t* mgr = sol_snapshot_mgr_new(NULL);
    ASSERT(mgr != NULL);

    sol_bank_t* loaded_bank = NULL;
    sol_accounts_db_t* loaded_db = NULL;

    sol_err_t err = sol_snapshot_load(mgr, dir, &loaded_bank, &loaded_db);
    ASSERT(err == SOL_OK);
    ASSERT(loaded_bank != NULL);
    ASSERT(loaded_db != NULL);

    ASSERT(sol_bank_slot(loaded_bank) == 5);
    ASSERT(sol_accounts_db_exists(loaded_db, &pubkey1));
    ASSERT(sol_accounts_db_exists(loaded_db, &pubkey2));

    sol_account_t* acct1 = sol_accounts_db_load(loaded_db, &pubkey1);
    ASSERT(acct1 != NULL);
    ASSERT(acct1->meta.lamports == lamports1);
    ASSERT(acct1->meta.data_len == 1);
    ASSERT(acct1->data != NULL);
    ASSERT(acct1->data[0] == 0xAA);
    sol_account_destroy(acct1);

    sol_account_t* acct2 = sol_accounts_db_load(loaded_db, &pubkey2);
    ASSERT(acct2 != NULL);
    ASSERT(acct2->meta.lamports == lamports2);
    ASSERT(acct2->meta.data_len == 0);
    sol_account_destroy(acct2);

    sol_bank_destroy(loaded_bank);
    sol_accounts_db_destroy(loaded_db);
    sol_snapshot_mgr_destroy(mgr);

    /* Cleanup */
    sol_snapshot_archive_rmdir(dir);
}

TEST(snapshot_load_accounts_solana2_layout_aligned) {
    char tmpdir[] = "/tmp/solana_c_snapshot_solana2_layout_XXXXXX";
    char* dir = mkdtemp(tmpdir);
    ASSERT(dir != NULL);

    /* Create minimal snapshot structure */
    char path[512];

    snprintf(path, sizeof(path), "%s/snapshots", dir);
    mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/snapshots/5", dir);
    mkdir(path, 0755);

    snprintf(path, sizeof(path), "%s/accounts", dir);
    mkdir(path, 0755);

    /* Write bank fields file: snapshots/5/5 */
    snprintf(path, sizeof(path), "%s/snapshots/5/5", dir);
    FILE* bf = fopen(path, "wb");
    ASSERT(bf != NULL);

    sol_hash_t parent_hash = {0};
    parent_hash.bytes[0] = 0xCD;
    sol_bank_config_t bank_config = SOL_BANK_CONFIG_DEFAULT;
    sol_bank_t* bank = sol_bank_new(5, &parent_hash, NULL, &bank_config);
    ASSERT(bank != NULL);

    uint8_t bank_data[4096];
    size_t bank_len = sol_bank_fields_serialize(bank, bank_data, sizeof(bank_data));
    ASSERT(bank_len == sizeof(sol_bank_fields_t));
    ASSERT(fwrite(bank_data, 1, bank_len, bf) == bank_len);
    fclose(bf);
    sol_bank_destroy(bank);

    /* Write a headerless, Solana layout variant accounts file under accounts/5.0 */
    snprintf(path, sizeof(path), "%s/accounts/5.0", dir);
    FILE* af = fopen(path, "wb");
    ASSERT(af != NULL);

    sol_pubkey_t pubkey1 = {0};
    pubkey1.bytes[0] = 0x55;
    pubkey1.bytes[1] = 0x66;

    sol_pubkey_t pubkey2 = {0};
    pubkey2.bytes[0] = 0x77;
    pubkey2.bytes[1] = 0x88;

    sol_pubkey_t owner = SOL_SYSTEM_PROGRAM_ID;

    /* Layout (104 bytes):
     * write_version(u64)
     * data_len(u64)
     * pubkey([32])
     * lamports(u64)
     * owner([32])
     * executable(u8) + padding[7]
     * rent_epoch(u64)
     * then data, then 8-byte alignment padding.
     */
    uint8_t storage[216];
    memset(storage, 0, sizeof(storage));

    size_t off = 0;

    uint64_t wv = 1;

    /* Record 1: 1 byte data + 7 bytes alignment padding */
    uint64_t data_len1 = 1;
    uint64_t lamports1 = 111;
    uint64_t rent_epoch1 = 0;
    memcpy(storage + off + 0, &wv, 8);
    memcpy(storage + off + 8, &data_len1, 8);
    memcpy(storage + off + 16, pubkey1.bytes, 32);
    memcpy(storage + off + 48, &lamports1, 8);
    memcpy(storage + off + 56, owner.bytes, 32);
    storage[off + 88] = 0; /* executable */
    memcpy(storage + off + 96, &rent_epoch1, 8);
    off += 104;
    storage[off++] = 0xAB;
    off = align_up_8_test(off);

    /* Record 2: zero-length data */
    uint64_t data_len2 = 0;
    uint64_t lamports2 = 222;
    uint64_t rent_epoch2 = 0;
    memcpy(storage + off + 0, &wv, 8);
    memcpy(storage + off + 8, &data_len2, 8);
    memcpy(storage + off + 16, pubkey2.bytes, 32);
    memcpy(storage + off + 48, &lamports2, 8);
    memcpy(storage + off + 56, owner.bytes, 32);
    storage[off + 88] = 0; /* executable */
    memcpy(storage + off + 96, &rent_epoch2, 8);
    off += 104;

    ASSERT(off == sizeof(storage));
    ASSERT(fwrite(storage, 1, sizeof(storage), af) == sizeof(storage));
    fclose(af);

    sol_snapshot_mgr_t* mgr = sol_snapshot_mgr_new(NULL);
    ASSERT(mgr != NULL);

    sol_bank_t* loaded_bank = NULL;
    sol_accounts_db_t* loaded_db = NULL;

    sol_err_t err = sol_snapshot_load(mgr, dir, &loaded_bank, &loaded_db);
    ASSERT(err == SOL_OK);
    ASSERT(loaded_bank != NULL);
    ASSERT(loaded_db != NULL);

    ASSERT(sol_bank_slot(loaded_bank) == 5);
    ASSERT(sol_accounts_db_exists(loaded_db, &pubkey1));
    ASSERT(sol_accounts_db_exists(loaded_db, &pubkey2));

    sol_account_t* acct1 = sol_accounts_db_load(loaded_db, &pubkey1);
    ASSERT(acct1 != NULL);
    ASSERT(acct1->meta.lamports == lamports1);
    ASSERT(acct1->meta.data_len == 1);
    ASSERT(acct1->data != NULL);
    ASSERT(acct1->data[0] == 0xAB);
    sol_account_destroy(acct1);

    sol_account_t* acct2 = sol_accounts_db_load(loaded_db, &pubkey2);
    ASSERT(acct2 != NULL);
    ASSERT(acct2->meta.lamports == lamports2);
    ASSERT(acct2->meta.data_len == 0);
    sol_account_destroy(acct2);

    sol_bank_destroy(loaded_bank);
    sol_accounts_db_destroy(loaded_db);
    sol_snapshot_mgr_destroy(mgr);

    /* Cleanup */
    sol_snapshot_archive_rmdir(dir);
}

TEST(snapshot_load_accounts_solana3_layout_aligned) {
    char tmpdir[] = "/tmp/solana_c_snapshot_solana3_layout_XXXXXX";
    char* dir = mkdtemp(tmpdir);
    ASSERT(dir != NULL);

    /* Create minimal snapshot structure */
    char path[512];

    snprintf(path, sizeof(path), "%s/snapshots", dir);
    mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/snapshots/5", dir);
    mkdir(path, 0755);

    snprintf(path, sizeof(path), "%s/accounts", dir);
    mkdir(path, 0755);

    /* Write bank fields file: snapshots/5/5 */
    snprintf(path, sizeof(path), "%s/snapshots/5/5", dir);
    FILE* bf = fopen(path, "wb");
    ASSERT(bf != NULL);

    sol_hash_t parent_hash = {0};
    parent_hash.bytes[0] = 0xCE;
    sol_bank_config_t bank_config = SOL_BANK_CONFIG_DEFAULT;
    sol_bank_t* bank = sol_bank_new(5, &parent_hash, NULL, &bank_config);
    ASSERT(bank != NULL);

    uint8_t bank_data[4096];
    size_t bank_len = sol_bank_fields_serialize(bank, bank_data, sizeof(bank_data));
    ASSERT(bank_len == sizeof(sol_bank_fields_t));
    ASSERT(fwrite(bank_data, 1, bank_len, bf) == bank_len);
    fclose(bf);
    sol_bank_destroy(bank);

    /* Write a headerless, Solana layout variant accounts file under accounts/5.0 */
    snprintf(path, sizeof(path), "%s/accounts/5.0", dir);
    FILE* af = fopen(path, "wb");
    ASSERT(af != NULL);

    sol_pubkey_t pubkey = {0};
    pubkey.bytes[0] = 0x99;
    pubkey.bytes[1] = 0x88;

    sol_pubkey_t owner = SOL_SYSTEM_PROGRAM_ID;
    owner.bytes[24] = 0xAA; /* Ensure legacy Solana2 exec-at-88 parsing fails */

    /* Layout (104 bytes):
     * write_version(u64)
     * data_len(u64)
     * pubkey([32])
     * lamports(u64)
     * rent_epoch(u64)
     * owner([32])
     * executable(u8) + padding[7]
     * then data, then 8-byte alignment padding.
     */
    uint8_t storage[112];
    memset(storage, 0, sizeof(storage));

    uint64_t wv = 1;
    uint64_t data_len = 4;
    uint64_t lamports = 42;
    uint64_t rent_epoch = UINT64_MAX;

    memcpy(storage + 0, &wv, 8);
    memcpy(storage + 8, &data_len, 8);
    memcpy(storage + 16, pubkey.bytes, 32);
    memcpy(storage + 48, &lamports, 8);
    memcpy(storage + 56, &rent_epoch, 8);
    memcpy(storage + 64, owner.bytes, 32);
    storage[96] = 0; /* executable */
    storage[104] = 0xAA;
    storage[105] = 0xBB;
    storage[106] = 0xCC;
    storage[107] = 0xDD;

    ASSERT(fwrite(storage, 1, sizeof(storage), af) == sizeof(storage));
    fclose(af);

    sol_snapshot_mgr_t* mgr = sol_snapshot_mgr_new(NULL);
    ASSERT(mgr != NULL);

    sol_bank_t* loaded_bank = NULL;
    sol_accounts_db_t* loaded_db = NULL;

    sol_err_t err = sol_snapshot_load(mgr, dir, &loaded_bank, &loaded_db);
    ASSERT(err == SOL_OK);
    ASSERT(loaded_bank != NULL);
    ASSERT(loaded_db != NULL);

    ASSERT(sol_bank_slot(loaded_bank) == 5);
    ASSERT(sol_accounts_db_exists(loaded_db, &pubkey));

    sol_account_t* acct = sol_accounts_db_load(loaded_db, &pubkey);
    ASSERT(acct != NULL);
    ASSERT(acct->meta.lamports == lamports);
    ASSERT(sol_pubkey_eq(&acct->meta.owner, &owner));
    ASSERT(acct->meta.data_len == data_len);
    ASSERT(acct->data != NULL);
    ASSERT(acct->data[0] == 0xAA);
    ASSERT(acct->data[1] == 0xBB);
    ASSERT(acct->data[2] == 0xCC);
    ASSERT(acct->data[3] == 0xDD);
    ASSERT(acct->meta.executable == false);
    ASSERT(acct->meta.rent_epoch == rent_epoch);
    sol_account_destroy(acct);

    sol_bank_destroy(loaded_bank);
    sol_accounts_db_destroy(loaded_db);
    sol_snapshot_mgr_destroy(mgr);

    /* Cleanup */
    sol_snapshot_archive_rmdir(dir);
}

TEST(snapshot_load_full_and_incremental) {
    char full_tmp[] = "/tmp/solana_c_snapshot_full_XXXXXX";
    char* full_dir = mkdtemp(full_tmp);
    ASSERT(full_dir != NULL);

    char incr_tmp[] = "/tmp/solana_c_snapshot_incr_XXXXXX";
    char* incr_dir = mkdtemp(incr_tmp);
    ASSERT(incr_dir != NULL);

    /* Full snapshot dir */
    char path[512];

    snprintf(path, sizeof(path), "%s/snapshots", full_dir);
    mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/snapshots/5", full_dir);
    mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/accounts", full_dir);
    mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/accounts/5.0", full_dir);
    mkdir(path, 0755);

    /* Bank fields: snapshots/5/5 */
    snprintf(path, sizeof(path), "%s/snapshots/5/5", full_dir);
    FILE* bf = fopen(path, "wb");
    ASSERT(bf != NULL);

    sol_hash_t parent_hash = {0};
    parent_hash.bytes[0] = 0xDD;
    sol_bank_config_t bank_config = SOL_BANK_CONFIG_DEFAULT;
    sol_bank_t* bank = sol_bank_new(5, &parent_hash, NULL, &bank_config);
    ASSERT(bank != NULL);

    uint8_t bank_data[4096];
    size_t bank_len = sol_bank_fields_serialize(bank, bank_data, sizeof(bank_data));
    ASSERT(bank_len == sizeof(sol_bank_fields_t));
    ASSERT(fwrite(bank_data, 1, bank_len, bf) == bank_len);
    fclose(bf);
    sol_bank_destroy(bank);

    sol_pubkey_t pubkey1 = {0};
    pubkey1.bytes[0] = 0x10;
    pubkey1.bytes[1] = 0x20;

    sol_pubkey_t pubkey2 = {0};
    pubkey2.bytes[0] = 0x30;
    pubkey2.bytes[1] = 0x40;

    /* Full accounts file: accounts/5.0/storage.bin */
    snprintf(path, sizeof(path), "%s/accounts/5.0/storage.bin", full_dir);
    FILE* af = fopen(path, "wb");
    ASSERT(af != NULL);

    sol_account_storage_header_t hdr = {
        .slot = 5,
        .id = 0,
        .count = 2,
        .data_len = sizeof(sol_stored_account_t) * 2,
    };

    sol_stored_account_t stored = {0};
    stored.write_version = 1;
    stored.data_len = 0;
    stored.pubkey = pubkey1;
    stored.owner = SOL_SYSTEM_PROGRAM_ID;
    stored.lamports = 123;
    stored.rent_epoch = 0;
    stored.executable = false;

    sol_stored_account_t stored_b = {0};
    stored_b.write_version = 1;
    stored_b.data_len = 0;
    stored_b.pubkey = pubkey2;
    stored_b.owner = SOL_SYSTEM_PROGRAM_ID;
    stored_b.lamports = 456;
    stored_b.rent_epoch = 0;
    stored_b.executable = false;

    ASSERT(fwrite(&hdr, 1, sizeof(hdr), af) == sizeof(hdr));
    ASSERT(fwrite(&stored, 1, sizeof(stored), af) == sizeof(stored));
    ASSERT(fwrite(&stored_b, 1, sizeof(stored_b), af) == sizeof(stored_b));
    fclose(af);

    /* Incremental snapshot dir */
    snprintf(path, sizeof(path), "%s/snapshots", incr_dir);
    mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/snapshots/6", incr_dir);
    mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/accounts", incr_dir);
    mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/accounts/6.0", incr_dir);
    mkdir(path, 0755);

    /* Bank fields: snapshots/6/6 */
    snprintf(path, sizeof(path), "%s/snapshots/6/6", incr_dir);
    bf = fopen(path, "wb");
    ASSERT(bf != NULL);

    parent_hash.bytes[0] = 0xEE;
    bank = sol_bank_new(6, &parent_hash, NULL, &bank_config);
    ASSERT(bank != NULL);

    bank_len = sol_bank_fields_serialize(bank, bank_data, sizeof(bank_data));
    ASSERT(bank_len == sizeof(sol_bank_fields_t));
    ASSERT(fwrite(bank_data, 1, bank_len, bf) == bank_len);
    fclose(bf);
    sol_bank_destroy(bank);

    /* Incremental accounts file: accounts/6.0/storage.bin */
    snprintf(path, sizeof(path), "%s/accounts/6.0/storage.bin", incr_dir);
    af = fopen(path, "wb");
    ASSERT(af != NULL);

    sol_account_storage_header_t hdr2 = {
        .slot = 6,
        .id = 0,
        .count = 2,
        .data_len = sizeof(sol_stored_account_t) * 2,
    };

    sol_stored_account_t upd1 = stored;
    upd1.lamports = 999; /* overwrite pubkey1 */

    sol_stored_account_t del2 = stored_b;
    del2.lamports = 0; /* delete pubkey2 */

    ASSERT(fwrite(&hdr2, 1, sizeof(hdr2), af) == sizeof(hdr2));
    ASSERT(fwrite(&upd1, 1, sizeof(upd1), af) == sizeof(upd1));
    ASSERT(fwrite(&del2, 1, sizeof(del2), af) == sizeof(del2));
    fclose(af);

    sol_snapshot_mgr_t* mgr = sol_snapshot_mgr_new(NULL);
    ASSERT(mgr != NULL);

    sol_bank_t* loaded_bank = NULL;
    sol_accounts_db_t* loaded_db = NULL;

    sol_err_t err = sol_snapshot_load_full_and_incremental(
        mgr, full_dir, incr_dir, NULL, &loaded_bank, &loaded_db);
    ASSERT(err == SOL_OK);
    ASSERT(loaded_bank != NULL);
    ASSERT(loaded_db != NULL);
    ASSERT(sol_bank_slot(loaded_bank) == 6);

    sol_account_t* acct1 = sol_accounts_db_load(loaded_db, &pubkey1);
    ASSERT(acct1 != NULL);
    ASSERT(acct1->meta.lamports == 999);
    sol_account_destroy(acct1);

    sol_account_t* acct2 = sol_accounts_db_load(loaded_db, &pubkey2);
    ASSERT(acct2 == NULL);

    sol_bank_destroy(loaded_bank);
    sol_accounts_db_destroy(loaded_db);
    sol_snapshot_mgr_destroy(mgr);

    sol_snapshot_archive_rmdir(full_dir);
    sol_snapshot_archive_rmdir(incr_dir);
}

TEST(snapshot_manifest_accounts_hash_verify) {
    char tmpdir[] = "/tmp/solana_c_snapshot_manifest_XXXXXX";
    char* dir = mkdtemp(tmpdir);
    ASSERT(dir != NULL);

    /* Create minimal snapshot structure */
    char path[512];

    snprintf(path, sizeof(path), "%s/snapshots", dir);
    mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/snapshots/5", dir);
    mkdir(path, 0755);

    snprintf(path, sizeof(path), "%s/accounts", dir);
    mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/accounts/5.0", dir);
    mkdir(path, 0755);

    /* Write bank fields file: snapshots/5/5 */
    snprintf(path, sizeof(path), "%s/snapshots/5/5", dir);
    FILE* bf = fopen(path, "wb");
    ASSERT(bf != NULL);

    sol_hash_t parent_hash = {0};
    parent_hash.bytes[0] = 0xBB;
    sol_bank_config_t bank_config = SOL_BANK_CONFIG_DEFAULT;
    sol_bank_t* bank = sol_bank_new(5, &parent_hash, NULL, &bank_config);
    ASSERT(bank != NULL);

    uint8_t bank_data[4096];
    size_t bank_len = sol_bank_fields_serialize(bank, bank_data, sizeof(bank_data));
    ASSERT(bank_len == sizeof(sol_bank_fields_t));
    ASSERT(fwrite(bank_data, 1, bank_len, bf) == bank_len);
    fclose(bf);
    sol_bank_destroy(bank);

    /* Write one account storage file under accounts/5.0 */
    snprintf(path, sizeof(path), "%s/accounts/5.0/storage.bin", dir);
    FILE* af = fopen(path, "wb");
    ASSERT(af != NULL);

    sol_account_storage_header_t hdr = {
        .slot = 5,
        .id = 1,
        .count = 2,
        .data_len = 2 * sizeof(sol_stored_account_t),
    };

    sol_pubkey_t pk1 = {0};
    pk1.bytes[0] = 0x22;
    sol_pubkey_t pk2 = {0};
    pk2.bytes[0] = 0x11;

    sol_stored_account_t stored1 = {0};
    stored1.write_version = 1;
    stored1.data_len = 0;
    stored1.pubkey = pk1;
    stored1.owner = SOL_SYSTEM_PROGRAM_ID;
    stored1.lamports = 222;
    stored1.rent_epoch = 0;
    stored1.executable = false;

    sol_stored_account_t stored2 = {0};
    stored2.write_version = 1;
    stored2.data_len = 0;
    stored2.pubkey = pk2;
    stored2.owner = SOL_SYSTEM_PROGRAM_ID;
    stored2.lamports = 111;
    stored2.rent_epoch = 0;
    stored2.executable = false;

    ASSERT(fwrite(&hdr, 1, sizeof(hdr), af) == sizeof(hdr));
    /* Intentionally write in reverse pubkey order */
    ASSERT(fwrite(&stored1, 1, sizeof(stored1), af) == sizeof(stored1));
    ASSERT(fwrite(&stored2, 1, sizeof(stored2), af) == sizeof(stored2));
    fclose(af);

    /* Compute expected accounts hash (sorted by pubkey) */
    sol_hash_t h1 = {0};
    sol_hash_t h2 = {0};

    sol_account_t a1 = {0};
    a1.meta.owner = stored1.owner;
    a1.meta.lamports = stored1.lamports;
    a1.meta.rent_epoch = stored1.rent_epoch;
    a1.meta.executable = stored1.executable;
    a1.meta.data_len = stored1.data_len;

    sol_account_t a2 = {0};
    a2.meta.owner = stored2.owner;
    a2.meta.lamports = stored2.lamports;
    a2.meta.rent_epoch = stored2.rent_epoch;
    a2.meta.executable = stored2.executable;
    a2.meta.data_len = stored2.data_len;

    sol_account_hash(&stored1.pubkey, &a1, &h1);
    sol_account_hash(&stored2.pubkey, &a2, &h2);

    const sol_pubkey_t* pubs[2] = {&stored1.pubkey, &stored2.pubkey};
    const sol_hash_t* hashes[2] = {&h1, &h2};
    if (memcmp(pubs[0]->bytes, pubs[1]->bytes, 32) > 0) {
        const sol_pubkey_t* tp = pubs[0];
        pubs[0] = pubs[1];
        pubs[1] = tp;
        const sol_hash_t* th = hashes[0];
        hashes[0] = hashes[1];
        hashes[1] = th;
    }

    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    sol_sha256_update(&ctx, hashes[0]->bytes, SOL_HASH_SIZE);
    sol_sha256_update(&ctx, hashes[1]->bytes, SOL_HASH_SIZE);

    sol_sha256_t digest;
    sol_sha256_final(&ctx, &digest);
    sol_hash_t accounts_hash;
    memcpy(accounts_hash.bytes, digest.bytes, SOL_HASH_SIZE);

    char hex[65];
    for (size_t i = 0; i < SOL_HASH_SIZE; i++) {
        snprintf(hex + (i * 2), 3, "%02x", accounts_hash.bytes[i]);
    }
    hex[64] = '\0';

    sol_hash_t epoch_accounts_hash = {0};
    memset(epoch_accounts_hash.bytes, 0xEE, sizeof(epoch_accounts_hash.bytes));
    char epoch_hex[65];
    for (size_t i = 0; i < SOL_HASH_SIZE; i++) {
        snprintf(epoch_hex + (i * 2), 3, "%02x", epoch_accounts_hash.bytes[i]);
    }
    epoch_hex[64] = '\0';

    snprintf(path, sizeof(path), "%s/manifest", dir);
    FILE* mf = fopen(path, "w");
    ASSERT(mf != NULL);
    fprintf(mf, "format=solana-c\n");
    fprintf(mf, "slot=5\n");
    fprintf(mf, "accounts_hash=%s\n", hex);
    fprintf(mf, "epoch_accounts_hash=%s\n", epoch_hex);
    fclose(mf);

    sol_snapshot_config_t cfg = SOL_SNAPSHOT_CONFIG_DEFAULT;
    cfg.verify_accounts_hash = true;

    sol_snapshot_mgr_t* mgr = sol_snapshot_mgr_new(&cfg);
    ASSERT(mgr != NULL);

    sol_bank_t* loaded_bank = NULL;
    sol_accounts_db_t* loaded_db = NULL;

    sol_err_t err = sol_snapshot_load(mgr, dir, &loaded_bank, &loaded_db);
    ASSERT(err == SOL_OK);
    ASSERT(loaded_bank != NULL);
    ASSERT(loaded_db != NULL);

    sol_hash_t got_epoch_accounts_hash = {0};
    ASSERT(sol_accounts_db_get_epoch_accounts_hash(
        loaded_db, sol_bank_epoch(loaded_bank), &got_epoch_accounts_hash));
    ASSERT(memcmp(got_epoch_accounts_hash.bytes,
                  epoch_accounts_hash.bytes,
                  SOL_HASH_SIZE) == 0);

    sol_bank_destroy(loaded_bank);
    sol_accounts_db_destroy(loaded_db);
    sol_snapshot_mgr_destroy(mgr);

    /* Corrupt manifest and ensure we detect mismatch */
    snprintf(path, sizeof(path), "%s/manifest", dir);
    mf = fopen(path, "w");
    ASSERT(mf != NULL);
    fprintf(mf, "format=solana-c\n");
    fprintf(mf, "slot=5\n");
    fprintf(mf, "accounts_hash=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n");
    fclose(mf);

    mgr = sol_snapshot_mgr_new(&cfg);
    ASSERT(mgr != NULL);
    loaded_bank = NULL;
    loaded_db = NULL;
    err = sol_snapshot_load(mgr, dir, &loaded_bank, &loaded_db);
    ASSERT(err == SOL_ERR_SNAPSHOT_MISMATCH);
    ASSERT(loaded_bank == NULL);
    ASSERT(loaded_db == NULL);
    sol_snapshot_mgr_destroy(mgr);

    sol_snapshot_archive_rmdir(dir);
}

TEST(accounts_db_versioned_upsert_and_delete) {
    sol_accounts_db_t* db = sol_accounts_db_new(NULL);
    ASSERT(db != NULL);

    sol_pubkey_t pk = {0};
    pk.bytes[0] = 0xAB;

    sol_account_t a_new = {0};
    a_new.meta.owner = SOL_SYSTEM_PROGRAM_ID;
    a_new.meta.lamports = 100;
    a_new.meta.data_len = 0;

    sol_account_t a_old = {0};
    a_old.meta.owner = SOL_SYSTEM_PROGRAM_ID;
    a_old.meta.lamports = 500;
    a_old.meta.data_len = 0;

    /* Store a newer version first */
    ASSERT(sol_accounts_db_store_versioned(db, &pk, &a_new, 5, 10) == SOL_OK);

    /* Older write_version must not overwrite */
    ASSERT(sol_accounts_db_store_versioned(db, &pk, &a_old, 4, 5) == SOL_OK);

    sol_account_t* loaded = sol_accounts_db_load(db, &pk);
    ASSERT(loaded != NULL);
    ASSERT(loaded->meta.lamports == 100);
    sol_account_destroy(loaded);

    /* Newer version overwrites */
    a_new.meta.lamports = 111;
    ASSERT(sol_accounts_db_store_versioned(db, &pk, &a_new, 6, 11) == SOL_OK);
    loaded = sol_accounts_db_load(db, &pk);
    ASSERT(loaded != NULL);
    ASSERT(loaded->meta.lamports == 111);
    sol_account_destroy(loaded);

    /* Older tombstone must not delete */
    sol_account_t tombstone = {0};
    tombstone.meta.lamports = 0;
    ASSERT(sol_accounts_db_store_versioned(db, &pk, &tombstone, 7, 9) == SOL_OK);
    loaded = sol_accounts_db_load(db, &pk);
    ASSERT(loaded != NULL);
    sol_account_destroy(loaded);

    /* Newer tombstone deletes */
    ASSERT(sol_accounts_db_store_versioned(db, &pk, &tombstone, 8, 12) == SOL_OK);
    loaded = sol_accounts_db_load(db, &pk);
    ASSERT(loaded == NULL);

    sol_accounts_db_destroy(db);
}

TEST(accounts_db_bulk_writer_merge_selects_latest) {
#ifndef SOL_HAS_ROCKSDB
    return;
#else
    char tmpdir[] = "/tmp/solana_c_accounts_merge_XXXXXX";
    char* base = mkdtemp(tmpdir);
    ASSERT(base != NULL);

    char rocksdb_path[512];
    snprintf(rocksdb_path, sizeof(rocksdb_path), "%s/rocksdb", base);

    sol_accounts_db_config_t cfg = SOL_ACCOUNTS_DB_CONFIG_DEFAULT;
    cfg.storage_type = SOL_ACCOUNTS_STORAGE_ROCKSDB;
    cfg.rocksdb_path = rocksdb_path;

    sol_accounts_db_t* db = sol_accounts_db_new(&cfg);
    ASSERT(db != NULL);

    sol_pubkey_t pk = {0};
    pk.bytes[0] = 0xAB;

    sol_account_t a_new = {0};
    a_new.meta.owner = SOL_SYSTEM_PROGRAM_ID;
    a_new.meta.lamports = 111;
    a_new.meta.data_len = 0;

    sol_account_t a_old = {0};
    a_old.meta.owner = SOL_SYSTEM_PROGRAM_ID;
    a_old.meta.lamports = 999;
    a_old.meta.data_len = 0;

    sol_accounts_db_bulk_writer_t* w = sol_accounts_db_bulk_writer_new(db, 64);
    ASSERT(w != NULL);
    sol_accounts_db_bulk_writer_set_use_merge(w, true);

    /* Write newer first, then an older version (out-of-order). */
    ASSERT(sol_accounts_db_bulk_writer_put_versioned(w, &pk, &a_new, 5, 10) == SOL_OK);
    ASSERT(sol_accounts_db_bulk_writer_put_versioned(w, &pk, &a_old, 4, 5) == SOL_OK);
    ASSERT(sol_accounts_db_bulk_writer_flush(w) == SOL_OK);
    sol_accounts_db_bulk_writer_destroy(w);

    sol_account_t* loaded = sol_accounts_db_load(db, &pk);
    ASSERT(loaded != NULL);
    ASSERT(loaded->meta.lamports == 111);
    sol_account_destroy(loaded);

    /* Tombstone with higher version wins. */
    sol_accounts_db_bulk_writer_t* w2 = sol_accounts_db_bulk_writer_new(db, 64);
    ASSERT(w2 != NULL);
    sol_accounts_db_bulk_writer_set_use_merge(w2, true);

    ASSERT(sol_accounts_db_bulk_writer_delete_versioned(w2, &pk, 6, 12) == SOL_OK);
    ASSERT(sol_accounts_db_bulk_writer_flush(w2) == SOL_OK);
    sol_accounts_db_bulk_writer_destroy(w2);

    loaded = sol_accounts_db_load(db, &pk);
    ASSERT(loaded == NULL);

    sol_accounts_db_destroy(db);
    sol_snapshot_archive_rmdir(base);
#endif
}

TEST(accounts_db_hash_merkle_three) {
    sol_accounts_db_t* db = sol_accounts_db_new(NULL);
    ASSERT(db != NULL);

    sol_pubkey_t pk1 = {0};
    pk1.bytes[0] = 0x22;
    sol_pubkey_t pk2 = {0};
    pk2.bytes[0] = 0x11;
    sol_pubkey_t pk3 = {0};
    pk3.bytes[0] = 0x33;

    sol_account_t a1 = {0};
    a1.meta.owner = SOL_SYSTEM_PROGRAM_ID;
    a1.meta.lamports = 222;
    a1.meta.data_len = 0;

    sol_account_t a2 = {0};
    a2.meta.owner = SOL_SYSTEM_PROGRAM_ID;
    a2.meta.lamports = 111;
    a2.meta.data_len = 0;

    sol_account_t a3 = {0};
    a3.meta.owner = SOL_SYSTEM_PROGRAM_ID;
    a3.meta.lamports = 333;
    a3.meta.data_len = 0;

    /* Insert in non-sorted order */
    ASSERT(sol_accounts_db_store(db, &pk3, &a3) == SOL_OK);
    ASSERT(sol_accounts_db_store(db, &pk1, &a1) == SOL_OK);
    ASSERT(sol_accounts_db_store(db, &pk2, &a2) == SOL_OK);

    sol_hash_t h1 = {0}, h2 = {0}, h3 = {0};
    sol_account_hash(&pk1, &a1, &h1);
    sol_account_hash(&pk2, &a2, &h2);
    sol_account_hash(&pk3, &a3, &h3);

    /* Sort by pubkey bytes */
    const sol_pubkey_t* pubs[3] = {&pk1, &pk2, &pk3};
    const sol_hash_t* hashes[3] = {&h1, &h2, &h3};
    for (size_t i = 0; i < 3; i++) {
        for (size_t j = i + 1; j < 3; j++) {
            if (memcmp(pubs[i]->bytes, pubs[j]->bytes, 32) > 0) {
                const sol_pubkey_t* tp = pubs[i];
                pubs[i] = pubs[j];
                pubs[j] = tp;
                const sol_hash_t* th = hashes[i];
                hashes[i] = hashes[j];
                hashes[j] = th;
            }
        }
    }

    sol_sha256_ctx_t sha;
    sol_sha256_init(&sha);
    sol_sha256_update(&sha, hashes[0]->bytes, SOL_HASH_SIZE);
    sol_sha256_update(&sha, hashes[1]->bytes, SOL_HASH_SIZE);
    sol_sha256_update(&sha, hashes[2]->bytes, SOL_HASH_SIZE);
    sol_sha256_t root;
    sol_sha256_final(&sha, &root);

    sol_hash_t expected = {0};
    memcpy(expected.bytes, root.bytes, SOL_HASH_SIZE);

    sol_hash_t got = {0};
    sol_accounts_db_hash(db, &got);

    ASSERT(memcmp(expected.bytes, got.bytes, SOL_HASH_SIZE) == 0);

    sol_accounts_db_destroy(db);
}

TEST(accounts_db_hash_merkle_three_rocksdb) {
#ifndef SOL_HAS_ROCKSDB
    return;
#else
    char tmpdir[] = "/tmp/solana_c_accounts_hash_rocksdb_XXXXXX";
    char* base = mkdtemp(tmpdir);
    ASSERT(base != NULL);

    char rocksdb_path[512];
    snprintf(rocksdb_path, sizeof(rocksdb_path), "%s/rocksdb", base);

    sol_accounts_db_config_t cfg = SOL_ACCOUNTS_DB_CONFIG_DEFAULT;
    cfg.storage_type = SOL_ACCOUNTS_STORAGE_ROCKSDB;
    cfg.rocksdb_path = rocksdb_path;

    sol_accounts_db_t* db = sol_accounts_db_new(&cfg);
    ASSERT(db != NULL);

    sol_pubkey_t pk1 = {0};
    pk1.bytes[0] = 0x22;
    sol_pubkey_t pk2 = {0};
    pk2.bytes[0] = 0x11;
    sol_pubkey_t pk3 = {0};
    pk3.bytes[0] = 0x33;

    sol_account_t a1 = {0};
    a1.meta.owner = SOL_SYSTEM_PROGRAM_ID;
    a1.meta.lamports = 222;
    a1.meta.data_len = 0;

    sol_account_t a2 = {0};
    a2.meta.owner = SOL_SYSTEM_PROGRAM_ID;
    a2.meta.lamports = 111;
    a2.meta.data_len = 0;

    sol_account_t a3 = {0};
    a3.meta.owner = SOL_SYSTEM_PROGRAM_ID;
    a3.meta.lamports = 333;
    a3.meta.data_len = 0;

    /* Insert in non-sorted order */
    ASSERT(sol_accounts_db_store(db, &pk3, &a3) == SOL_OK);
    ASSERT(sol_accounts_db_store(db, &pk1, &a1) == SOL_OK);
    ASSERT(sol_accounts_db_store(db, &pk2, &a2) == SOL_OK);

    sol_hash_t h1 = {0}, h2 = {0}, h3 = {0};
    sol_account_hash(&pk1, &a1, &h1);
    sol_account_hash(&pk2, &a2, &h2);
    sol_account_hash(&pk3, &a3, &h3);

    /* Sort by pubkey bytes */
    const sol_pubkey_t* pubs[3] = {&pk1, &pk2, &pk3};
    const sol_hash_t* hashes[3] = {&h1, &h2, &h3};
    for (size_t i = 0; i < 3; i++) {
        for (size_t j = i + 1; j < 3; j++) {
            if (memcmp(pubs[i]->bytes, pubs[j]->bytes, 32) > 0) {
                const sol_pubkey_t* tp = pubs[i];
                pubs[i] = pubs[j];
                pubs[j] = tp;
                const sol_hash_t* th = hashes[i];
                hashes[i] = hashes[j];
                hashes[j] = th;
            }
        }
    }

    sol_sha256_ctx_t sha;
    sol_sha256_init(&sha);
    sol_sha256_update(&sha, hashes[0]->bytes, SOL_HASH_SIZE);
    sol_sha256_update(&sha, hashes[1]->bytes, SOL_HASH_SIZE);
    sol_sha256_update(&sha, hashes[2]->bytes, SOL_HASH_SIZE);
    sol_sha256_t root;
    sol_sha256_final(&sha, &root);

    sol_hash_t expected = {0};
    memcpy(expected.bytes, root.bytes, SOL_HASH_SIZE);

    sol_hash_t got = {0};
    sol_accounts_db_hash(db, &got);
    ASSERT(memcmp(expected.bytes, got.bytes, SOL_HASH_SIZE) == 0);

    sol_accounts_db_destroy(db);
    sol_snapshot_archive_rmdir(base);
#endif
}

typedef struct {
    sol_pubkey_t expected[8];
    bool         seen[8];
    size_t       expected_count;
    size_t       count;
} owner_iter_test_ctx_t;

static bool
owner_iter_test_cb(const sol_pubkey_t* pubkey, const sol_account_t* account, void* ctx) {
    (void)account;
    owner_iter_test_ctx_t* t = (owner_iter_test_ctx_t*)ctx;
    if (!t || !pubkey) return false;

    t->count++;
    for (size_t i = 0; i < t->expected_count; i++) {
        if (memcmp(t->expected[i].bytes, pubkey->bytes, 32) == 0) {
            t->seen[i] = true;
            break;
        }
    }
    return true;
}

TEST(accounts_owner_index_rocksdb_basic) {
#ifndef SOL_HAS_ROCKSDB
    return;
#else
    char tmpdir[] = "/tmp/solana_c_accounts_owner_index_XXXXXX";
    char* base = mkdtemp(tmpdir);
    ASSERT(base != NULL);

    char rocksdb_path[512];
    snprintf(rocksdb_path, sizeof(rocksdb_path), "%s/rocksdb", base);

    sol_accounts_db_config_t cfg = SOL_ACCOUNTS_DB_CONFIG_DEFAULT;
    cfg.storage_type = SOL_ACCOUNTS_STORAGE_ROCKSDB;
    cfg.rocksdb_path = rocksdb_path;

    sol_accounts_db_t* db = sol_accounts_db_new(&cfg);
    ASSERT(db != NULL);

    sol_pubkey_t pk1 = {0};
    pk1.bytes[0] = 0x01;
    sol_pubkey_t pk2 = {0};
    pk2.bytes[0] = 0x02;
    sol_pubkey_t pk3 = {0};
    pk3.bytes[0] = 0x03;

    sol_account_t a1 = {0};
    a1.meta.owner = SOL_SYSTEM_PROGRAM_ID;
    a1.meta.lamports = 1;
    a1.meta.data_len = 0;

    sol_account_t a2 = {0};
    a2.meta.owner = SOL_SYSTEM_PROGRAM_ID;
    a2.meta.lamports = 2;
    a2.meta.data_len = 0;

    sol_account_t a3 = {0};
    a3.meta.owner = SOL_VOTE_PROGRAM_ID;
    a3.meta.lamports = 3;
    a3.meta.data_len = 0;

    ASSERT(sol_accounts_db_store(db, &pk1, &a1) == SOL_OK);
    ASSERT(sol_accounts_db_store(db, &pk2, &a2) == SOL_OK);
    ASSERT(sol_accounts_db_store(db, &pk3, &a3) == SOL_OK);

    owner_iter_test_ctx_t sys_ctx = {0};
    sys_ctx.expected[0] = pk1;
    sys_ctx.expected[1] = pk2;
    sys_ctx.expected_count = 2;
    sol_accounts_db_iterate_owner(db, &SOL_SYSTEM_PROGRAM_ID, owner_iter_test_cb, &sys_ctx);
    ASSERT(sys_ctx.count == 2);
    ASSERT(sys_ctx.seen[0]);
    ASSERT(sys_ctx.seen[1]);

    owner_iter_test_ctx_t vote_ctx = {0};
    vote_ctx.expected[0] = pk3;
    vote_ctx.expected_count = 1;
    sol_accounts_db_iterate_owner(db, &SOL_VOTE_PROGRAM_ID, owner_iter_test_cb, &vote_ctx);
    ASSERT(vote_ctx.count == 1);
    ASSERT(vote_ctx.seen[0]);

    /* Delete removes from index */
    ASSERT(sol_accounts_db_delete(db, &pk1) == SOL_OK);
    owner_iter_test_ctx_t sys_ctx2 = {0};
    sys_ctx2.expected[0] = pk2;
    sys_ctx2.expected_count = 1;
    sol_accounts_db_iterate_owner(db, &SOL_SYSTEM_PROGRAM_ID, owner_iter_test_cb, &sys_ctx2);
    ASSERT(sys_ctx2.count == 1);
    ASSERT(sys_ctx2.seen[0]);

    /* Owner change updates index */
    sol_account_t a2_vote = a2;
    a2_vote.meta.owner = SOL_VOTE_PROGRAM_ID;
    ASSERT(sol_accounts_db_store(db, &pk2, &a2_vote) == SOL_OK);

    owner_iter_test_ctx_t sys_ctx3 = {0};
    sys_ctx3.expected_count = 0;
    sol_accounts_db_iterate_owner(db, &SOL_SYSTEM_PROGRAM_ID, owner_iter_test_cb, &sys_ctx3);
    ASSERT(sys_ctx3.count == 0);

    owner_iter_test_ctx_t vote_ctx2 = {0};
    vote_ctx2.expected[0] = pk2;
    vote_ctx2.expected[1] = pk3;
    vote_ctx2.expected_count = 2;
    sol_accounts_db_iterate_owner(db, &SOL_VOTE_PROGRAM_ID, owner_iter_test_cb, &vote_ctx2);
    ASSERT(vote_ctx2.count == 2);
    ASSERT(vote_ctx2.seen[0]);
    ASSERT(vote_ctx2.seen[1]);

    sol_accounts_db_destroy(db);
    sol_snapshot_archive_rmdir(base);
#endif
}

TEST(accounts_owner_iterate_without_owner_index_meta) {
#ifndef SOL_HAS_ROCKSDB
    return;
#else
    char tmpdir[] = "/tmp/solana_c_accounts_owner_scan_XXXXXX";
    char* base = mkdtemp(tmpdir);
    ASSERT(base != NULL);

    char rocksdb_path[512];
    snprintf(rocksdb_path, sizeof(rocksdb_path), "%s/rocksdb", base);

    sol_accounts_db_config_t cfg = SOL_ACCOUNTS_DB_CONFIG_DEFAULT;
    cfg.storage_type = SOL_ACCOUNTS_STORAGE_ROCKSDB;
    cfg.rocksdb_path = rocksdb_path;

    sol_accounts_db_t* db = sol_accounts_db_new(&cfg);
    ASSERT(db != NULL);

    sol_accounts_db_bulk_writer_t* bulk = sol_accounts_db_bulk_writer_new(db, 4096);
    ASSERT(bulk != NULL);
    sol_accounts_db_bulk_writer_set_use_merge(bulk, true);

    sol_pubkey_t pk1 = {0};
    pk1.bytes[0] = 0x11;
    sol_pubkey_t pk2 = {0};
    pk2.bytes[0] = 0x12;
    sol_pubkey_t pk3 = {0};
    pk3.bytes[0] = 0x13;

    ASSERT(sol_accounts_db_bulk_writer_put_raw_versioned(
               bulk, &pk1, &SOL_SYSTEM_PROGRAM_ID, 1, NULL, 0, false, 0, 1, 1) == SOL_OK);
    ASSERT(sol_accounts_db_bulk_writer_put_raw_versioned(
               bulk, &pk2, &SOL_SYSTEM_PROGRAM_ID, 2, NULL, 0, false, 0, 1, 2) == SOL_OK);
    ASSERT(sol_accounts_db_bulk_writer_put_raw_versioned(
               bulk, &pk3, &SOL_VOTE_PROGRAM_ID, 3, NULL, 0, false, 0, 1, 3) == SOL_OK);

    ASSERT(sol_accounts_db_bulk_writer_flush(bulk) == SOL_OK);
    sol_accounts_db_bulk_writer_destroy(bulk);
    bulk = NULL;

    owner_iter_test_ctx_t sys_ctx = {0};
    sys_ctx.expected[0] = pk1;
    sys_ctx.expected[1] = pk2;
    sys_ctx.expected_count = 2;
    sol_accounts_db_iterate_owner(db, &SOL_SYSTEM_PROGRAM_ID, owner_iter_test_cb, &sys_ctx);
    ASSERT(sys_ctx.count == 2);
    ASSERT(sys_ctx.seen[0]);
    ASSERT(sys_ctx.seen[1]);

    owner_iter_test_ctx_t vote_ctx = {0};
    vote_ctx.expected[0] = pk3;
    vote_ctx.expected_count = 1;
    sol_accounts_db_iterate_owner(db, &SOL_VOTE_PROGRAM_ID, owner_iter_test_cb, &vote_ctx);
    ASSERT(vote_ctx.count == 1);
    ASSERT(vote_ctx.seen[0]);

    sol_accounts_db_destroy(db);
    sol_snapshot_archive_rmdir(base);
#endif
}

TEST(accounts_owner_index_ensure_builds_from_bulk_writer) {
#ifndef SOL_HAS_ROCKSDB
    return;
#else
    char tmpdir[] = "/tmp/solana_c_accounts_owner_ensure_XXXXXX";
    char* base = mkdtemp(tmpdir);
    ASSERT(base != NULL);

    char rocksdb_path[512];
    snprintf(rocksdb_path, sizeof(rocksdb_path), "%s/rocksdb", base);

    sol_accounts_db_config_t cfg = SOL_ACCOUNTS_DB_CONFIG_DEFAULT;
    cfg.storage_type = SOL_ACCOUNTS_STORAGE_ROCKSDB;
    cfg.rocksdb_path = rocksdb_path;

    sol_accounts_db_t* db = sol_accounts_db_new(&cfg);
    ASSERT(db != NULL);

    sol_pubkey_t pk1 = {0};
    pk1.bytes[0] = 0x11;
    sol_pubkey_t pk2 = {0};
    pk2.bytes[0] = 0x22;
    sol_pubkey_t pk3 = {0};
    pk3.bytes[0] = 0x33;

    sol_account_t a1 = {0};
    a1.meta.owner = SOL_SYSTEM_PROGRAM_ID;
    a1.meta.lamports = 10;
    a1.meta.data_len = 0;

    sol_account_t a2 = {0};
    a2.meta.owner = SOL_SYSTEM_PROGRAM_ID;
    a2.meta.lamports = 20;
    a2.meta.data_len = 0;

    sol_account_t a3 = {0};
    a3.meta.owner = SOL_VOTE_PROGRAM_ID;
    a3.meta.lamports = 30;
    a3.meta.data_len = 0;

    sol_accounts_db_bulk_writer_t* w = sol_accounts_db_bulk_writer_new(db, 128);
    ASSERT(w != NULL);
    ASSERT(sol_accounts_db_bulk_writer_put_versioned(w, &pk1, &a1, 0, 1) == SOL_OK);
    ASSERT(sol_accounts_db_bulk_writer_put_versioned(w, &pk2, &a2, 0, 1) == SOL_OK);
    ASSERT(sol_accounts_db_bulk_writer_put_versioned(w, &pk3, &a3, 0, 1) == SOL_OK);
    ASSERT(sol_accounts_db_bulk_writer_flush(w) == SOL_OK);
    sol_accounts_db_bulk_writer_destroy(w);

    ASSERT(sol_accounts_db_ensure_owner_index(db) == SOL_OK);

    owner_iter_test_ctx_t sys_ctx = {0};
    sys_ctx.expected[0] = pk1;
    sys_ctx.expected[1] = pk2;
    sys_ctx.expected_count = 2;
    sol_accounts_db_iterate_owner(db, &SOL_SYSTEM_PROGRAM_ID, owner_iter_test_cb, &sys_ctx);
    ASSERT(sys_ctx.count == 2);
    ASSERT(sys_ctx.seen[0]);
    ASSERT(sys_ctx.seen[1]);

    owner_iter_test_ctx_t vote_ctx = {0};
    vote_ctx.expected[0] = pk3;
    vote_ctx.expected_count = 1;
    sol_accounts_db_iterate_owner(db, &SOL_VOTE_PROGRAM_ID, owner_iter_test_cb, &vote_ctx);
    ASSERT(vote_ctx.count == 1);
    ASSERT(vote_ctx.seen[0]);

    ASSERT(sol_accounts_db_total_lamports(db) == 60);
    sol_accounts_db_destroy(db);

    /* Validate reverse mapping format written by ensure (48-byte value). */
    sol_rocksdb_config_t rocksdb_cfg = SOL_ROCKSDB_CONFIG_DEFAULT;
    rocksdb_cfg.path = rocksdb_path;
    sol_rocksdb_t* rdb = sol_rocksdb_new(&rocksdb_cfg);
    ASSERT(rdb != NULL);
    ASSERT(sol_rocksdb_open_cf(rdb, SOL_ROCKSDB_CF_ACCOUNTS_OWNER_REVERSE) == SOL_OK);
    sol_storage_backend_t* rev = sol_rocksdb_get_backend(rdb, SOL_ROCKSDB_CF_ACCOUNTS_OWNER_REVERSE);
    ASSERT(rev != NULL);
    uint8_t* rev_val = NULL;
    size_t rev_val_len = 0;
    ASSERT(rev->get(rev->ctx, pk1.bytes, 32, &rev_val, &rev_val_len) == SOL_OK);
    ASSERT(rev_val != NULL);
    ASSERT(rev_val_len == 48);
    uint64_t got_lamports = 0;
    uint64_t got_data_len = 0;
    memcpy(&got_lamports, rev_val + 0, 8);
    memcpy(&got_data_len, rev_val + 8, 8);
    ASSERT(got_lamports == 10);
    ASSERT(got_data_len == 0);
    ASSERT(memcmp(rev_val + 16, SOL_SYSTEM_PROGRAM_ID.bytes, 32) == 0);
    sol_free(rev_val);
    sol_rocksdb_destroy(rdb);

    /* Verify stats metadata reload on open. */
    sol_accounts_db_t* db2 = sol_accounts_db_new(&cfg);
    ASSERT(db2 != NULL);
    ASSERT(sol_accounts_db_total_lamports(db2) == 60);
    sol_accounts_db_destroy(db2);

    sol_snapshot_archive_rmdir(base);
#endif
}

TEST(accounts_apply_delta_bulk_updates_owner_index) {
#ifndef SOL_HAS_ROCKSDB
    return;
#else
    char tmpdir[] = "/tmp/solana_c_accounts_apply_delta_XXXXXX";
    char* base = mkdtemp(tmpdir);
    ASSERT(base != NULL);

    char rocksdb_path[512];
    snprintf(rocksdb_path, sizeof(rocksdb_path), "%s/rocksdb", base);

    sol_accounts_db_config_t cfg = SOL_ACCOUNTS_DB_CONFIG_DEFAULT;
    cfg.storage_type = SOL_ACCOUNTS_STORAGE_ROCKSDB;
    cfg.rocksdb_path = rocksdb_path;

    sol_accounts_db_t* root = sol_accounts_db_new(&cfg);
    ASSERT(root != NULL);

    sol_pubkey_t pk1 = {0};
    pk1.bytes[0] = 0xAB;

    sol_account_t a1 = {0};
    a1.meta.owner = SOL_SYSTEM_PROGRAM_ID;
    a1.meta.lamports = 10;
    a1.meta.data_len = 0;
    ASSERT(sol_accounts_db_store(root, &pk1, &a1) == SOL_OK);

    ASSERT(sol_accounts_db_ensure_owner_index(root) == SOL_OK);

    sol_accounts_db_t* fork = sol_accounts_db_fork(root);
    ASSERT(fork != NULL);

    sol_account_t a1_vote = {0};
    a1_vote.meta.owner = SOL_VOTE_PROGRAM_ID;
    a1_vote.meta.lamports = 10;
    a1_vote.meta.data_len = 0;
    ASSERT(sol_accounts_db_store(fork, &pk1, &a1_vote) == SOL_OK);

    ASSERT(sol_accounts_db_apply_delta(root, fork) == SOL_OK);

    owner_iter_test_ctx_t sys_ctx = {0};
    sys_ctx.expected_count = 0;
    sol_accounts_db_iterate_owner(root, &SOL_SYSTEM_PROGRAM_ID, owner_iter_test_cb, &sys_ctx);
    ASSERT(sys_ctx.count == 0);

    owner_iter_test_ctx_t vote_ctx = {0};
    vote_ctx.expected[0] = pk1;
    vote_ctx.expected_count = 1;
    sol_accounts_db_iterate_owner(root, &SOL_VOTE_PROGRAM_ID, owner_iter_test_cb, &vote_ctx);
    ASSERT(vote_ctx.count == 1);
    ASSERT(vote_ctx.seen[0]);

    sol_accounts_db_destroy(fork);
    sol_accounts_db_destroy(root);
    sol_snapshot_archive_rmdir(base);
#endif
}

TEST(accounts_owner_index_ensure_builds_from_reverse_mapping) {
#ifndef SOL_HAS_ROCKSDB
    return;
#else
    char tmpdir[] = "/tmp/solana_c_accounts_owner_index_rev_XXXXXX";
    char* base = mkdtemp(tmpdir);
    ASSERT(base != NULL);

    char rocksdb_path[512];
    snprintf(rocksdb_path, sizeof(rocksdb_path), "%s/rocksdb", base);

    sol_accounts_db_config_t cfg = SOL_ACCOUNTS_DB_CONFIG_DEFAULT;
    cfg.storage_type = SOL_ACCOUNTS_STORAGE_ROCKSDB;
    cfg.rocksdb_path = rocksdb_path;

    sol_pubkey_t pk1 = {0};
    pk1.bytes[0] = 0x11;
    sol_pubkey_t pk2 = {0};
    pk2.bytes[0] = 0x22;
    sol_pubkey_t pk3 = {0};
    pk3.bytes[0] = 0x33;

    sol_account_t a1 = {0};
    a1.meta.owner = SOL_SYSTEM_PROGRAM_ID;
    a1.meta.lamports = 10;
    a1.meta.data_len = 0;

    sol_account_t a2 = {0};
    a2.meta.owner = SOL_SYSTEM_PROGRAM_ID;
    a2.meta.lamports = 20;
    a2.meta.data_len = 0;

    sol_account_t a3 = {0};
    a3.meta.owner = SOL_VOTE_PROGRAM_ID;
    a3.meta.lamports = 30;
    a3.meta.data_len = 0;

    /* Seed accounts + reverse mapping via bulk ingestion. */
    sol_accounts_db_t* db = sol_accounts_db_new(&cfg);
    ASSERT(db != NULL);

    sol_accounts_db_bulk_writer_t* w = sol_accounts_db_bulk_writer_new(db, 128);
    ASSERT(w != NULL);
    ASSERT(sol_accounts_db_bulk_writer_put_versioned(w, &pk1, &a1, 0, 1) == SOL_OK);
    ASSERT(sol_accounts_db_bulk_writer_put_versioned(w, &pk2, &a2, 0, 1) == SOL_OK);
    ASSERT(sol_accounts_db_bulk_writer_put_versioned(w, &pk3, &a3, 0, 1) == SOL_OK);
    ASSERT(sol_accounts_db_bulk_writer_flush(w) == SOL_OK);
    sol_accounts_db_bulk_writer_destroy(w);

    sol_accounts_db_destroy(db);

    /* Corrupt the accounts CF so ensure_owner_index must use reverse mapping. */
    sol_rocksdb_config_t rocksdb_cfg = SOL_ROCKSDB_CONFIG_DEFAULT;
    rocksdb_cfg.path = rocksdb_path;
    sol_rocksdb_t* rdb = sol_rocksdb_new(&rocksdb_cfg);
    ASSERT(rdb != NULL);
    ASSERT(sol_rocksdb_open_cf(rdb, SOL_ROCKSDB_CF_ACCOUNTS) == SOL_OK);
    sol_storage_backend_t* acc = sol_rocksdb_get_backend(rdb, SOL_ROCKSDB_CF_ACCOUNTS);
    ASSERT(acc != NULL);
    uint8_t bad = 0x01;
    ASSERT(acc->put(acc->ctx, pk1.bytes, 32, &bad, 1) == SOL_OK);
    sol_rocksdb_destroy(rdb);

    sol_accounts_db_t* db2 = sol_accounts_db_new(&cfg);
    ASSERT(db2 != NULL);

    ASSERT(sol_accounts_db_mark_owner_reverse_built(db2) == SOL_OK);
    ASSERT(sol_accounts_db_ensure_owner_index(db2) == SOL_OK);
    ASSERT(sol_accounts_db_total_lamports(db2) == 60);
    sol_accounts_db_destroy(db2);

    /* Validate owner index key exists for pk2 (system program). */
    sol_rocksdb_t* rdb2 = sol_rocksdb_new(&rocksdb_cfg);
    ASSERT(rdb2 != NULL);
    ASSERT(sol_rocksdb_open_cf(rdb2, SOL_ROCKSDB_CF_ACCOUNTS_OWNER_INDEX) == SOL_OK);
    sol_storage_backend_t* idx = sol_rocksdb_get_backend(rdb2, SOL_ROCKSDB_CF_ACCOUNTS_OWNER_INDEX);
    ASSERT(idx != NULL);

    uint8_t key[64];
    memcpy(key + 0, SOL_SYSTEM_PROGRAM_ID.bytes, 32);
    memcpy(key + 32, pk2.bytes, 32);
    uint8_t* got = NULL;
    size_t got_len = 0;
    ASSERT(idx->get(idx->ctx, key, sizeof(key), &got, &got_len) == SOL_OK);
    ASSERT(got != NULL);
    sol_free(got);

    sol_rocksdb_destroy(rdb2);
    sol_snapshot_archive_rmdir(base);
#endif
}

TEST(accounts_bulk_writer_core_only_owner_index) {
#ifndef SOL_HAS_ROCKSDB
    return;
#else
    char tmpdir[] = "/tmp/solana_c_accounts_bulk_core_owner_index_XXXXXX";
    char* base = mkdtemp(tmpdir);
    ASSERT(base != NULL);

    char rocksdb_path[512];
    snprintf(rocksdb_path, sizeof(rocksdb_path), "%s/rocksdb", base);

    sol_accounts_db_config_t cfg = SOL_ACCOUNTS_DB_CONFIG_DEFAULT;
    cfg.storage_type = SOL_ACCOUNTS_STORAGE_ROCKSDB;
    cfg.rocksdb_path = rocksdb_path;

    sol_pubkey_t pk_stake = {0};
    pk_stake.bytes[0] = 0x61;
    sol_pubkey_t pk_vote = {0};
    pk_vote.bytes[0] = 0x62;
    sol_pubkey_t pk_other = {0};
    pk_other.bytes[0] = 0x63;

    sol_account_t a_stake = {0};
    a_stake.meta.owner = SOL_STAKE_PROGRAM_ID;
    a_stake.meta.lamports = 1;
    a_stake.meta.data_len = 0;

    sol_account_t a_vote = {0};
    a_vote.meta.owner = SOL_VOTE_PROGRAM_ID;
    a_vote.meta.lamports = 2;
    a_vote.meta.data_len = 0;

    sol_account_t a_other = {0};
    a_other.meta.owner = SOL_SYSTEM_PROGRAM_ID;
    a_other.meta.lamports = 3;
    a_other.meta.data_len = 0;

    sol_accounts_db_t* db = sol_accounts_db_new(&cfg);
    ASSERT(db != NULL);

    sol_accounts_db_bulk_writer_t* w = sol_accounts_db_bulk_writer_new(db, 128);
    ASSERT(w != NULL);
    sol_accounts_db_bulk_writer_set_use_merge(w, true);
    ASSERT(sol_accounts_db_bulk_writer_set_write_owner_index(w, true) == SOL_OK);
    sol_accounts_db_bulk_writer_set_write_owner_index_core_only(w, true);

    ASSERT(sol_accounts_db_bulk_writer_put_versioned(w, &pk_stake, &a_stake, 0, 1) == SOL_OK);
    ASSERT(sol_accounts_db_bulk_writer_put_versioned(w, &pk_vote, &a_vote, 0, 1) == SOL_OK);
    ASSERT(sol_accounts_db_bulk_writer_put_versioned(w, &pk_other, &a_other, 0, 1) == SOL_OK);
    ASSERT(sol_accounts_db_bulk_writer_flush(w) == SOL_OK);
    sol_accounts_db_bulk_writer_destroy(w);

    ASSERT(sol_accounts_db_mark_owner_index_core_built(db) == SOL_OK);
    sol_accounts_db_destroy(db);

    sol_rocksdb_config_t rocksdb_cfg = SOL_ROCKSDB_CONFIG_DEFAULT;
    rocksdb_cfg.path = rocksdb_path;
    sol_rocksdb_t* rdb = sol_rocksdb_new(&rocksdb_cfg);
    ASSERT(rdb != NULL);
    ASSERT(sol_rocksdb_open_cf(rdb, SOL_ROCKSDB_CF_ACCOUNTS_OWNER_INDEX) == SOL_OK);
    sol_storage_backend_t* idx = sol_rocksdb_get_backend(rdb, SOL_ROCKSDB_CF_ACCOUNTS_OWNER_INDEX);
    ASSERT(idx != NULL);

    uint8_t key[64];
    uint8_t* got = NULL;
    size_t got_len = 0;

    memcpy(key + 0, SOL_STAKE_PROGRAM_ID.bytes, 32);
    memcpy(key + 32, pk_stake.bytes, 32);
    ASSERT(idx->get(idx->ctx, key, sizeof(key), &got, &got_len) == SOL_OK);
    sol_free(got);
    got = NULL;
    got_len = 0;

    memcpy(key + 0, SOL_VOTE_PROGRAM_ID.bytes, 32);
    memcpy(key + 32, pk_vote.bytes, 32);
    ASSERT(idx->get(idx->ctx, key, sizeof(key), &got, &got_len) == SOL_OK);
    sol_free(got);
    got = NULL;
    got_len = 0;

    memcpy(key + 0, SOL_SYSTEM_PROGRAM_ID.bytes, 32);
    memcpy(key + 32, pk_other.bytes, 32);
    sol_err_t err = idx->get(idx->ctx, key, sizeof(key), &got, &got_len);
    ASSERT(err == SOL_ERR_NOTFOUND);
    if (got) sol_free(got);

    const char* meta_key = "__meta_owner_index_core_v1";
    got = NULL;
    got_len = 0;
    ASSERT(idx->get(idx->ctx,
                    (const uint8_t*)meta_key,
                    strlen(meta_key),
                    &got,
                    &got_len) == SOL_OK);
    if (got) sol_free(got);

    sol_rocksdb_destroy(rdb);
    sol_snapshot_archive_rmdir(base);
#endif
}

TEST(accounts_owner_index_core_builds_stake_and_vote) {
#ifndef SOL_HAS_ROCKSDB
    return;
#else
    char tmpdir[] = "/tmp/solana_c_accounts_owner_index_core_XXXXXX";
    char* base = mkdtemp(tmpdir);
    ASSERT(base != NULL);

    char rocksdb_path[512];
    snprintf(rocksdb_path, sizeof(rocksdb_path), "%s/rocksdb", base);

    sol_accounts_db_config_t cfg = SOL_ACCOUNTS_DB_CONFIG_DEFAULT;
    cfg.storage_type = SOL_ACCOUNTS_STORAGE_ROCKSDB;
    cfg.rocksdb_path = rocksdb_path;

    sol_pubkey_t pk_stake = {0};
    pk_stake.bytes[0] = 0x41;
    sol_pubkey_t pk_vote = {0};
    pk_vote.bytes[0] = 0x42;
    sol_pubkey_t pk_other = {0};
    pk_other.bytes[0] = 0x43;

    sol_account_t a_stake = {0};
    a_stake.meta.owner = SOL_STAKE_PROGRAM_ID;
    a_stake.meta.lamports = 1;
    a_stake.meta.data_len = 0;

    sol_account_t a_vote = {0};
    a_vote.meta.owner = SOL_VOTE_PROGRAM_ID;
    a_vote.meta.lamports = 2;
    a_vote.meta.data_len = 0;

    sol_account_t a_other = {0};
    a_other.meta.owner = SOL_SYSTEM_PROGRAM_ID;
    a_other.meta.lamports = 3;
    a_other.meta.data_len = 0;

    sol_accounts_db_t* db = sol_accounts_db_new(&cfg);
    ASSERT(db != NULL);

    sol_accounts_db_bulk_writer_t* w = sol_accounts_db_bulk_writer_new(db, 128);
    ASSERT(w != NULL);
    sol_accounts_db_bulk_writer_set_use_merge(w, true);
    ASSERT(sol_accounts_db_bulk_writer_put_versioned(w, &pk_stake, &a_stake, 0, 1) == SOL_OK);
    ASSERT(sol_accounts_db_bulk_writer_put_versioned(w, &pk_vote, &a_vote, 0, 1) == SOL_OK);
    ASSERT(sol_accounts_db_bulk_writer_put_versioned(w, &pk_other, &a_other, 0, 1) == SOL_OK);
    ASSERT(sol_accounts_db_bulk_writer_flush(w) == SOL_OK);
    sol_accounts_db_bulk_writer_destroy(w);
    sol_accounts_db_destroy(db);

    sol_accounts_db_t* db2 = sol_accounts_db_new(&cfg);
    ASSERT(db2 != NULL);
    ASSERT(sol_accounts_db_mark_owner_reverse_built(db2) == SOL_OK);
    ASSERT(sol_accounts_db_ensure_core_owner_index(db2) == SOL_OK);

    owner_iter_test_ctx_t stake_ctx = {0};
    stake_ctx.expected[0] = pk_stake;
    stake_ctx.expected_count = 1;
    sol_accounts_db_iterate_owner(db2, &SOL_STAKE_PROGRAM_ID, owner_iter_test_cb, &stake_ctx);
    ASSERT(stake_ctx.count == 1);
    ASSERT(stake_ctx.seen[0]);

    owner_iter_test_ctx_t vote_ctx = {0};
    vote_ctx.expected[0] = pk_vote;
    vote_ctx.expected_count = 1;
    sol_accounts_db_iterate_owner(db2, &SOL_VOTE_PROGRAM_ID, owner_iter_test_cb, &vote_ctx);
    ASSERT(vote_ctx.count == 1);
    ASSERT(vote_ctx.seen[0]);

    owner_iter_test_ctx_t other_ctx = {0};
    other_ctx.expected[0] = pk_other;
    other_ctx.expected_count = 1;
    sol_accounts_db_iterate_owner(db2, &SOL_SYSTEM_PROGRAM_ID, owner_iter_test_cb, &other_ctx);
    ASSERT(other_ctx.count == 1);
    ASSERT(other_ctx.seen[0]);

    sol_accounts_db_destroy(db2);
    sol_snapshot_archive_rmdir(base);
#endif
}

TEST(accounts_owner_index_core_builds_without_owner_reverse) {
#ifndef SOL_HAS_ROCKSDB
    return;
#else
    char tmpdir[] = "/tmp/solana_c_accounts_owner_index_core_no_rev_XXXXXX";
    char* base = mkdtemp(tmpdir);
    ASSERT(base != NULL);

    char rocksdb_path[512];
    snprintf(rocksdb_path, sizeof(rocksdb_path), "%s/rocksdb", base);

    sol_pubkey_t pk_stake = {0};
    pk_stake.bytes[0] = 0x51;
    sol_pubkey_t pk_vote = {0};
    pk_vote.bytes[0] = 0x52;
    sol_pubkey_t pk_other = {0};
    pk_other.bytes[0] = 0x53;

    sol_account_t a_stake = {0};
    a_stake.meta.owner = SOL_STAKE_PROGRAM_ID;
    a_stake.meta.lamports = 1;
    a_stake.meta.data_len = 0;

    sol_account_t a_vote = {0};
    a_vote.meta.owner = SOL_VOTE_PROGRAM_ID;
    a_vote.meta.lamports = 2;
    a_vote.meta.data_len = 0;

    sol_account_t a_other = {0};
    a_other.meta.owner = SOL_SYSTEM_PROGRAM_ID;
    a_other.meta.lamports = 3;
    a_other.meta.data_len = 0;

    sol_rocksdb_config_t rocksdb_cfg = SOL_ROCKSDB_CONFIG_DEFAULT;
    rocksdb_cfg.path = rocksdb_path;
    sol_rocksdb_t* rdb = sol_rocksdb_new(&rocksdb_cfg);
    ASSERT(rdb != NULL);
    ASSERT(sol_rocksdb_open_cf(rdb, SOL_ROCKSDB_CF_ACCOUNTS) == SOL_OK);
    sol_storage_backend_t* acc = sol_rocksdb_get_backend(rdb, SOL_ROCKSDB_CF_ACCOUNTS);
    ASSERT(acc != NULL);

    uint8_t buf[128];
    size_t written = 0;

    ASSERT(sol_account_serialize(&a_stake, buf, sizeof(buf), &written) == SOL_OK);
    ASSERT(acc->put(acc->ctx, pk_stake.bytes, 32, buf, written) == SOL_OK);

    ASSERT(sol_account_serialize(&a_vote, buf, sizeof(buf), &written) == SOL_OK);
    ASSERT(acc->put(acc->ctx, pk_vote.bytes, 32, buf, written) == SOL_OK);

    ASSERT(sol_account_serialize(&a_other, buf, sizeof(buf), &written) == SOL_OK);
    ASSERT(acc->put(acc->ctx, pk_other.bytes, 32, buf, written) == SOL_OK);

    sol_rocksdb_destroy(rdb);

    sol_accounts_db_config_t cfg = SOL_ACCOUNTS_DB_CONFIG_DEFAULT;
    cfg.storage_type = SOL_ACCOUNTS_STORAGE_ROCKSDB;
    cfg.rocksdb_path = rocksdb_path;

    sol_accounts_db_t* db = sol_accounts_db_new(&cfg);
    ASSERT(db != NULL);
    ASSERT(sol_accounts_db_ensure_core_owner_index(db) == SOL_OK);

    owner_iter_test_ctx_t stake_ctx = {0};
    stake_ctx.expected[0] = pk_stake;
    stake_ctx.expected_count = 1;
    sol_accounts_db_iterate_owner(db, &SOL_STAKE_PROGRAM_ID, owner_iter_test_cb, &stake_ctx);
    ASSERT(stake_ctx.count == 1);
    ASSERT(stake_ctx.seen[0]);

    owner_iter_test_ctx_t vote_ctx = {0};
    vote_ctx.expected[0] = pk_vote;
    vote_ctx.expected_count = 1;
    sol_accounts_db_iterate_owner(db, &SOL_VOTE_PROGRAM_ID, owner_iter_test_cb, &vote_ctx);
    ASSERT(vote_ctx.count == 1);
    ASSERT(vote_ctx.seen[0]);

    owner_iter_test_ctx_t other_ctx = {0};
    other_ctx.expected[0] = pk_other;
    other_ctx.expected_count = 1;
    sol_accounts_db_iterate_owner(db, &SOL_SYSTEM_PROGRAM_ID, owner_iter_test_cb, &other_ctx);
    ASSERT(other_ctx.count == 1);
    ASSERT(other_ctx.seen[0]);

    sol_accounts_db_destroy(db);
    sol_snapshot_archive_rmdir(base);
#endif
}

TEST(accounts_owner_index_reverse_owner_only_fallback) {
#ifndef SOL_HAS_ROCKSDB
    return;
#else
    char tmpdir[] = "/tmp/solana_c_accounts_owner_index_rev_fallback_XXXXXX";
    char* base = mkdtemp(tmpdir);
    ASSERT(base != NULL);

    char rocksdb_path[512];
    snprintf(rocksdb_path, sizeof(rocksdb_path), "%s/rocksdb", base);

    sol_accounts_db_config_t cfg = SOL_ACCOUNTS_DB_CONFIG_DEFAULT;
    cfg.storage_type = SOL_ACCOUNTS_STORAGE_ROCKSDB;
    cfg.rocksdb_path = rocksdb_path;

    sol_pubkey_t pk1 = {0};
    pk1.bytes[0] = 0xa1;

    sol_account_t a1 = {0};
    a1.meta.owner = SOL_SYSTEM_PROGRAM_ID;
    a1.meta.lamports = 42;
    a1.meta.data_len = 0;

    sol_accounts_db_t* db = sol_accounts_db_new(&cfg);
    ASSERT(db != NULL);
    ASSERT(sol_accounts_db_store(db, &pk1, &a1) == SOL_OK);
    sol_accounts_db_destroy(db);

    /* Overwrite reverse mapping with legacy owner-only format (32 bytes). */
    sol_rocksdb_config_t rocksdb_cfg = SOL_ROCKSDB_CONFIG_DEFAULT;
    rocksdb_cfg.path = rocksdb_path;
    sol_rocksdb_t* rdb = sol_rocksdb_new(&rocksdb_cfg);
    ASSERT(rdb != NULL);
    ASSERT(sol_rocksdb_open_cf(rdb, SOL_ROCKSDB_CF_ACCOUNTS_OWNER_REVERSE) == SOL_OK);
    sol_storage_backend_t* rev = sol_rocksdb_get_backend(rdb, SOL_ROCKSDB_CF_ACCOUNTS_OWNER_REVERSE);
    ASSERT(rev != NULL);
    ASSERT(rev->put(rev->ctx, pk1.bytes, 32, SOL_SYSTEM_PROGRAM_ID.bytes, 32) == SOL_OK);
    sol_rocksdb_destroy(rdb);

    sol_accounts_db_t* db2 = sol_accounts_db_new(&cfg);
    ASSERT(db2 != NULL);
    ASSERT(sol_accounts_db_mark_owner_reverse_built(db2) == SOL_OK);
    ASSERT(sol_accounts_db_ensure_owner_index(db2) == SOL_OK);
    ASSERT(sol_accounts_db_total_lamports(db2) == 42);
    sol_accounts_db_destroy(db2);

    sol_snapshot_archive_rmdir(base);
#endif
}

TEST(accounts_owner_iterate_overlay) {
#ifndef SOL_HAS_ROCKSDB
    return;
#else
    char tmpdir[] = "/tmp/solana_c_accounts_owner_overlay_XXXXXX";
    char* base = mkdtemp(tmpdir);
    ASSERT(base != NULL);

    char rocksdb_path[512];
    snprintf(rocksdb_path, sizeof(rocksdb_path), "%s/rocksdb", base);

    sol_accounts_db_config_t cfg = SOL_ACCOUNTS_DB_CONFIG_DEFAULT;
    cfg.storage_type = SOL_ACCOUNTS_STORAGE_ROCKSDB;
    cfg.rocksdb_path = rocksdb_path;

    sol_accounts_db_t* root = sol_accounts_db_new(&cfg);
    ASSERT(root != NULL);

    sol_pubkey_t pk_a = {0};
    pk_a.bytes[0] = 0x0a;
    sol_pubkey_t pk_b = {0};
    pk_b.bytes[0] = 0x0b;
    sol_pubkey_t pk_c = {0};
    pk_c.bytes[0] = 0x0c;

    sol_account_t sys_a = {0};
    sys_a.meta.owner = SOL_SYSTEM_PROGRAM_ID;
    sys_a.meta.lamports = 10;
    sys_a.meta.data_len = 0;

    sol_account_t sys_b = {0};
    sys_b.meta.owner = SOL_SYSTEM_PROGRAM_ID;
    sys_b.meta.lamports = 11;
    sys_b.meta.data_len = 0;

    ASSERT(sol_accounts_db_store(root, &pk_a, &sys_a) == SOL_OK);
    ASSERT(sol_accounts_db_store(root, &pk_b, &sys_b) == SOL_OK);

    sol_accounts_db_t* fork = sol_accounts_db_fork(root);
    ASSERT(fork != NULL);

    /* Delete pk_a and change pk_b owner in fork */
    ASSERT(sol_accounts_db_delete(fork, &pk_a) == SOL_OK);

    sol_account_t vote_b = sys_b;
    vote_b.meta.owner = SOL_VOTE_PROGRAM_ID;
    ASSERT(sol_accounts_db_store(fork, &pk_b, &vote_b) == SOL_OK);

    /* New account only in fork */
    sol_account_t sys_c = {0};
    sys_c.meta.owner = SOL_SYSTEM_PROGRAM_ID;
    sys_c.meta.lamports = 12;
    sys_c.meta.data_len = 0;
    ASSERT(sol_accounts_db_store(fork, &pk_c, &sys_c) == SOL_OK);

    owner_iter_test_ctx_t sys_ctx = {0};
    sys_ctx.expected[0] = pk_c;
    sys_ctx.expected_count = 1;
    sol_accounts_db_iterate_owner(fork, &SOL_SYSTEM_PROGRAM_ID, owner_iter_test_cb, &sys_ctx);
    ASSERT(sys_ctx.count == 1);
    ASSERT(sys_ctx.seen[0]);

    owner_iter_test_ctx_t vote_ctx = {0};
    vote_ctx.expected[0] = pk_b;
    vote_ctx.expected_count = 1;
    sol_accounts_db_iterate_owner(fork, &SOL_VOTE_PROGRAM_ID, owner_iter_test_cb, &vote_ctx);
    ASSERT(vote_ctx.count == 1);
    ASSERT(vote_ctx.seen[0]);

    sol_accounts_db_destroy(fork);
    sol_accounts_db_destroy(root);
    sol_snapshot_archive_rmdir(base);
#endif
}

/*
 * Test snapshot service manifest parsing (no network)
 */
TEST(snapshot_service_manifest_parse) {
    const char* manifest_url = "https://data.pipedev.network/snapshot-manifest.json";
    const char* json =
        "{\n"
        "  \"updated_at\": \"2026-01-17T19:28:19Z\",\n"
        "  \"full_snapshot\": {\n"
        "    \"filename\": \"snapshots/snapshot-10-ABCDEFG.tar.zst\",\n"
        "    \"slot\": 10,\n"
        "    \"size_bytes\": 123\n"
        "  },\n"
        "  \"incremental_snapshots\": [\n"
        "    {\n"
        "      \"filename\": \"snapshots/incremental-snapshot-10-12-XYZ.tar.zst\",\n"
        "      \"base_slot\": 10,\n"
        "      \"slot\": 12,\n"
        "      \"size_bytes\": 456\n"
        "    },\n"
        "    {\n"
        "      \"filename\": \"snapshots/incremental-snapshot-10-11-XYZ.tar.zst\",\n"
        "      \"base_slot\": 10,\n"
        "      \"slot\": 11,\n"
        "      \"size_bytes\": 111\n"
        "    }\n"
        "  ]\n"
        "}\n";

    sol_available_snapshot_t snapshots[8];
    memset(snapshots, 0, sizeof(snapshots));

    size_t n = sol_snapshot_service_parse_manifest_json(
        manifest_url, json, strlen(json), snapshots, 8);
    ASSERT(n == 3);

    ASSERT(snapshots[0].type == SOL_SNAPSHOT_FULL);
    ASSERT(snapshots[0].base_slot == 0);
    ASSERT(snapshots[0].slot == 10);
    ASSERT(snapshots[0].size == 123);
    ASSERT(snapshots[0].url != NULL);
    ASSERT(strcmp(snapshots[0].url,
                  "https://data.pipedev.network/snapshots/snapshot-10-ABCDEFG.tar.zst") == 0);

    ASSERT(snapshots[1].type == SOL_SNAPSHOT_INCREMENTAL);
    ASSERT(snapshots[1].base_slot == 10);
    ASSERT(snapshots[1].slot == 12);
    ASSERT(snapshots[1].size == 456);
    ASSERT(snapshots[1].url != NULL);

    sol_available_snapshots_free(snapshots, n);

    sol_available_snapshot_t full = {0};
    sol_available_snapshot_t incr = {0};
    sol_snapshot_download_opts_t opts = SOL_SNAPSHOT_DOWNLOAD_OPTS_DEFAULT;

    sol_err_t err = sol_snapshot_service_find_best_from_manifest_json(
        manifest_url, json, strlen(json), &opts, &full, &incr);
    ASSERT(err == SOL_OK);
    ASSERT(full.type == SOL_SNAPSHOT_FULL);
    ASSERT(full.slot == 10);
    ASSERT(full.url != NULL);
    ASSERT(incr.type == SOL_SNAPSHOT_INCREMENTAL);
    ASSERT(incr.base_slot == 10);
    ASSERT(incr.slot == 12);
    ASSERT(incr.url != NULL);

    sol_available_snapshot_free(&full);
    sol_available_snapshot_free(&incr);

    opts.max_size = 100;
    err = sol_snapshot_service_find_best_from_manifest_json(
        manifest_url, json, strlen(json), &opts, &full, &incr);
    ASSERT(err == SOL_ERR_TOO_LARGE);
}

TEST(snapshot_download_parallel_params) {
    uint32_t parts = 0;
    uint32_t inflight = 0;

    sol_err_t err = sol_snapshot_download_calc_parallel_params(
        1000, 0, 32, &parts, &inflight);
    ASSERT(err == SOL_OK);
    ASSERT(parts == 32);
    ASSERT(inflight == 32);

    parts = 0;
    inflight = 0;
    err = sol_snapshot_download_calc_parallel_params(
        1000, 0, 128, &parts, &inflight);
    ASSERT(err == SOL_OK);
    ASSERT(parts == SOL_SNAPSHOT_DOWNLOAD_MAX_PARALLEL_CONNECTIONS);
    ASSERT(inflight == SOL_SNAPSHOT_DOWNLOAD_MAX_PARALLEL_CONNECTIONS);

    parts = 0;
    inflight = 0;
    err = sol_snapshot_download_calc_parallel_params(
        10, 0, 64, &parts, &inflight);
    ASSERT(err == SOL_OK);
    ASSERT(parts == 10);
    ASSERT(inflight == 10);

    parts = 0;
    inflight = 0;
    err = sol_snapshot_download_calc_parallel_params(
        10ULL * 1024ULL * 1024ULL * 1024ULL, 0, 8, &parts, &inflight);
    ASSERT(err == SOL_OK);
    ASSERT(inflight == 8);
    ASSERT(parts > inflight);

    err = sol_snapshot_download_calc_parallel_params(
        5, 4, 2, &parts, &inflight);
    ASSERT(err == SOL_ERR_INVAL);

    err = sol_snapshot_download_calc_parallel_params(
        5, 0, 1, &parts, &inflight);
    ASSERT(err == SOL_ERR_INVAL);
}

int main(void) {
    printf("Running Snapshot tests...\n");

    /* Manager tests */
    RUN_TEST(snapshot_mgr_new);
    RUN_TEST(snapshot_mgr_config);
    RUN_TEST(snapshot_mgr_set_dirs);

    /* Bank fields tests */
    RUN_TEST(bank_fields_serialize);
    RUN_TEST(bank_fields_deserialize);
    RUN_TEST(bank_fields_deserialize_bincode);

    /* Account storage tests */
    RUN_TEST(account_storage_serialize);
    RUN_TEST(account_storage_deserialize);

    /* Archive naming tests */
    RUN_TEST(snapshot_archive_name);
    RUN_TEST(snapshot_archive_name_incremental);
    RUN_TEST(snapshot_get_info);
    RUN_TEST(snapshot_get_info_hash_base58);
    RUN_TEST(snapshot_load_seeds_bank_hash_from_solana_bank_snapshot);
    RUN_TEST(snapshot_load_seeds_signature_count_from_bank_fields);
    RUN_TEST(snapshot_load_seeds_latest_blockhash_from_bank_snapshot_header);
    RUN_TEST(snapshot_load_seeds_accounts_lt_hash_from_agave_bank_snapshot_tail);
    RUN_TEST(snapshot_load_seeds_bank_fields_with_large_ancestors);

    /* Status cache tests */
    RUN_TEST(status_cache_new);
    RUN_TEST(status_cache_add_lookup);
    RUN_TEST(status_cache_purge);
    RUN_TEST(status_cache_serialize);

    RUN_TEST(snapshot_load_from_directory);
    RUN_TEST(snapshot_load_archive_persists_appendvec_accounts_files);
    RUN_TEST(snapshot_archive_filename_hash_verify);
    RUN_TEST(snapshot_load_accounts_solana_layout_aligned);
    RUN_TEST(snapshot_load_accounts_solana2_layout_aligned);
    RUN_TEST(snapshot_load_accounts_solana3_layout_aligned);
    RUN_TEST(snapshot_load_full_and_incremental);
    RUN_TEST(snapshot_manifest_accounts_hash_verify);
    RUN_TEST(accounts_db_versioned_upsert_and_delete);
    RUN_TEST(accounts_db_bulk_writer_merge_selects_latest);
    RUN_TEST(accounts_db_hash_merkle_three);
    RUN_TEST(accounts_db_hash_merkle_three_rocksdb);
    RUN_TEST(accounts_owner_index_rocksdb_basic);
    RUN_TEST(accounts_owner_iterate_without_owner_index_meta);
    RUN_TEST(accounts_owner_index_ensure_builds_from_bulk_writer);
    RUN_TEST(accounts_apply_delta_bulk_updates_owner_index);
    RUN_TEST(accounts_owner_index_ensure_builds_from_reverse_mapping);
    RUN_TEST(accounts_bulk_writer_core_only_owner_index);
    RUN_TEST(accounts_owner_index_core_builds_stake_and_vote);
    RUN_TEST(accounts_owner_index_core_builds_without_owner_reverse);
    RUN_TEST(accounts_owner_index_reverse_owner_only_fallback);
    RUN_TEST(accounts_owner_iterate_overlay);
    RUN_TEST(snapshot_service_manifest_parse);
    RUN_TEST(snapshot_download_parallel_params);

    /* Verification tests */
    RUN_TEST(snapshot_verify);
    RUN_TEST(snapshot_archive_extract_zstd_streaming);
    RUN_TEST(snapshot_archive_extract_stream_prefix_callback);
    RUN_TEST(snapshot_archive_extract_stream_prefix_skip_unmatched);
    RUN_TEST(snapshot_archive_extract_stream_prefix_chunk_callback);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
