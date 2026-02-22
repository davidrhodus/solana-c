/*
 * test_runtime.c - Runtime module unit tests
 */

#include "../test_framework.h"
#include "sol_account.h"
#include "sol_accounts_db.h"
#include "sol_bank.h"
#include "sol_sysvar.h"
#include "sol_system_program.h"
#include "sol_address_lookup_table_program.h"
#include "sol_ed25519_program.h"
#include "sol_secp256k1_program.h"
#include "sol_vote_program.h"
#include "sol_stake_program.h"
#include "sol_alloc.h"
#include "sol_ed25519.h"
#include "sol_sha256.h"
#include "sol_lt_hash.h"
#include "sol_bits.h"
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

static void
rm_tree(const char* path) {
    if (!path || path[0] == '\0') return;

    DIR* dir = opendir(path);
    if (!dir) {
        (void)unlink(path);
        return;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char child[1024];
        snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);

        struct stat st;
        if (lstat(child, &st) != 0) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            rm_tree(child);
        } else {
            (void)unlink(child);
        }
    }

    closedir(dir);
    (void)rmdir(path);
}

/*
 * Account tests
 */

TEST(account_new_destroy) {
    sol_pubkey_t owner;
    memset(owner.bytes, 0xAB, 32);

    sol_account_t* account = sol_account_new(1000000, 100, &owner);
    TEST_ASSERT(account != NULL);
    TEST_ASSERT_EQ(account->meta.lamports, 1000000);
    TEST_ASSERT_EQ(account->meta.data_len, 100);
    TEST_ASSERT(account->data != NULL);
    TEST_ASSERT(sol_pubkey_eq(&account->meta.owner, &owner));

    sol_account_destroy(account);
}

TEST(account_new_no_data) {
    sol_account_t* account = sol_account_new(5000, 0, NULL);
    TEST_ASSERT(account != NULL);
    TEST_ASSERT_EQ(account->meta.lamports, 5000);
    TEST_ASSERT_EQ(account->meta.data_len, 0);
    TEST_ASSERT(account->data == NULL);

    sol_account_destroy(account);
}

TEST(account_clone) {
    sol_pubkey_t owner;
    memset(owner.bytes, 0xCD, 32);

    sol_account_t* original = sol_account_new(2000, 50, &owner);
    TEST_ASSERT(original != NULL);

    /* Set some data */
    memset(original->data, 0x42, 50);
    original->meta.executable = true;
    original->meta.rent_epoch = 123;

    sol_account_t* clone = sol_account_clone(original);
    TEST_ASSERT(clone != NULL);
    TEST_ASSERT(clone != original);

    TEST_ASSERT_EQ(clone->meta.lamports, original->meta.lamports);
    TEST_ASSERT_EQ(clone->meta.data_len, original->meta.data_len);
    TEST_ASSERT(clone->data != original->data);
    TEST_ASSERT_MEM_EQ(clone->data, original->data, 50);
    TEST_ASSERT(sol_pubkey_eq(&clone->meta.owner, &original->meta.owner));
    TEST_ASSERT_EQ(clone->meta.executable, original->meta.executable);
    TEST_ASSERT_EQ(clone->meta.rent_epoch, original->meta.rent_epoch);

    sol_account_destroy(original);
    sol_account_destroy(clone);
}

TEST(account_resize) {
    sol_account_t* account = sol_account_new(1000, 10, NULL);
    TEST_ASSERT(account != NULL);

    /* Grow */
    sol_err_t err = sol_account_resize(account, 100);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_EQ(account->meta.data_len, 100);

    /* Shrink */
    err = sol_account_resize(account, 50);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_EQ(account->meta.data_len, 50);

    /* Set to zero */
    err = sol_account_resize(account, 0);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_EQ(account->meta.data_len, 0);

    sol_account_destroy(account);
}

TEST(account_set_data) {
    sol_account_t* account = sol_account_new(1000, 0, NULL);
    TEST_ASSERT(account != NULL);

    uint8_t data[20] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                        11, 12, 13, 14, 15, 16, 17, 18, 19, 20};

    sol_err_t err = sol_account_set_data(account, data, 20);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_EQ(account->meta.data_len, 20);
    TEST_ASSERT_MEM_EQ(account->data, data, 20);

    sol_account_destroy(account);
}

TEST(account_serialize_deserialize) {
    sol_pubkey_t owner;
    memset(owner.bytes, 0xEF, 32);

    sol_account_t* original = sol_account_new(999999, 32, &owner);
    TEST_ASSERT(original != NULL);
    memset(original->data, 0xAA, 32);
    original->meta.executable = true;
    original->meta.rent_epoch = 456;

    /* Serialize */
    uint8_t buf[256];
    size_t written;
    sol_err_t err = sol_account_serialize(original, buf, sizeof(buf), &written);
    TEST_ASSERT_EQ(err, SOL_OK);

    /* Deserialize */
    sol_account_t deserialized;
    sol_account_init(&deserialized);

    size_t consumed;
    err = sol_account_deserialize(&deserialized, buf, written, &consumed);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_EQ(consumed, written);

    TEST_ASSERT_EQ(deserialized.meta.lamports, original->meta.lamports);
    TEST_ASSERT_EQ(deserialized.meta.data_len, original->meta.data_len);
    TEST_ASSERT_MEM_EQ(deserialized.data, original->data, 32);
    TEST_ASSERT(sol_pubkey_eq(&deserialized.meta.owner, &original->meta.owner));
    TEST_ASSERT_EQ(deserialized.meta.executable, original->meta.executable);
    TEST_ASSERT_EQ(deserialized.meta.rent_epoch, original->meta.rent_epoch);

    sol_account_destroy(original);
    sol_account_cleanup(&deserialized);
}

/*
 * AccountsDB tests
 */

TEST(accounts_db_create_destroy) {
    sol_accounts_db_t* db = sol_accounts_db_new(NULL);
    TEST_ASSERT(db != NULL);
    TEST_ASSERT_EQ(sol_accounts_db_count(db), 0);

    sol_accounts_db_destroy(db);
}

#ifdef SOL_HAS_ROCKSDB
TEST(accounts_db_bootstrap_state_roundtrip_rocksdb) {
    char tmpdir[] = "/tmp/solana-c-bootstrap-XXXXXX";
    char* base = mkdtemp(tmpdir);
    TEST_ASSERT(base != NULL);

    char rocksdb_path[512];
    snprintf(rocksdb_path, sizeof(rocksdb_path), "%s/rocksdb", base);
    (void)mkdir(rocksdb_path, 0755);

    sol_accounts_db_config_t cfg = SOL_ACCOUNTS_DB_CONFIG_DEFAULT;
    cfg.storage_type = SOL_ACCOUNTS_STORAGE_ROCKSDB;
    cfg.rocksdb_path = rocksdb_path;

    sol_accounts_db_t* db = sol_accounts_db_new(&cfg);
    TEST_ASSERT(db != NULL);

    sol_accounts_db_bootstrap_state_t state = {0};
    state.slot = 42;
    state.parent_slot = 41;
    state.signature_count = 1234567;
    state.flags = SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_BLOCKHASH |
                  SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_BANK_HASH |
                  SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_ACCOUNTS_LT_HASH;
    state.ticks_per_slot = 64;
    state.slots_per_epoch = 432000;
    state.lamports_per_signature = 5000;
    state.rent_per_byte_year = 3480;
    state.rent_exemption_threshold = 2;

    memset(state.blockhash.bytes, 0x11, sizeof(state.blockhash.bytes));
    memset(state.parent_bank_hash.bytes, 0x22, sizeof(state.parent_bank_hash.bytes));
    memset(state.bank_hash.bytes, 0x33, sizeof(state.bank_hash.bytes));
    for (size_t i = 0; i < SOL_LT_HASH_NUM_ELEMENTS; i++) {
        state.accounts_lt_hash.v[i] = (uint16_t)(i ^ 0xBEEF);
    }

    TEST_ASSERT_EQ(sol_accounts_db_set_bootstrap_state(db, &state), SOL_OK);
    sol_accounts_db_destroy(db);

    sol_accounts_db_t* db2 = sol_accounts_db_new(&cfg);
    TEST_ASSERT(db2 != NULL);

    sol_accounts_db_bootstrap_state_t loaded = {0};
    TEST_ASSERT(sol_accounts_db_get_bootstrap_state(db2, &loaded));

    TEST_ASSERT_EQ(loaded.slot, state.slot);
    TEST_ASSERT_EQ(loaded.parent_slot, state.parent_slot);
    TEST_ASSERT_EQ(loaded.signature_count, state.signature_count);
    TEST_ASSERT_EQ(loaded.flags, state.flags);
    TEST_ASSERT_EQ(loaded.ticks_per_slot, state.ticks_per_slot);
    TEST_ASSERT_EQ(loaded.slots_per_epoch, state.slots_per_epoch);
    TEST_ASSERT_EQ(loaded.lamports_per_signature, state.lamports_per_signature);
    TEST_ASSERT_EQ(loaded.rent_per_byte_year, state.rent_per_byte_year);
    TEST_ASSERT_EQ(loaded.rent_exemption_threshold, state.rent_exemption_threshold);

    TEST_ASSERT_EQ(memcmp(loaded.blockhash.bytes, state.blockhash.bytes, SOL_HASH_SIZE), 0);
    TEST_ASSERT_EQ(memcmp(loaded.parent_bank_hash.bytes, state.parent_bank_hash.bytes, SOL_HASH_SIZE), 0);
    TEST_ASSERT_EQ(memcmp(loaded.bank_hash.bytes, state.bank_hash.bytes, SOL_HASH_SIZE), 0);
    TEST_ASSERT_EQ(memcmp(loaded.accounts_lt_hash.v, state.accounts_lt_hash.v, sizeof(state.accounts_lt_hash.v)), 0);

    sol_accounts_db_destroy(db2);
    rm_tree(base);
}
#endif

TEST(accounts_db_store_load) {
    sol_accounts_db_t* db = sol_accounts_db_new(NULL);
    TEST_ASSERT(db != NULL);

    sol_pubkey_t pubkey;
    memset(pubkey.bytes, 0x11, 32);

    sol_account_t* account = sol_account_new(5000, 10, NULL);
    TEST_ASSERT(account != NULL);

    /* Store */
    sol_err_t err = sol_accounts_db_store(db, &pubkey, account);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_EQ(sol_accounts_db_count(db), 1);

    /* Load */
    sol_account_t* loaded = sol_accounts_db_load(db, &pubkey);
    TEST_ASSERT(loaded != NULL);
    TEST_ASSERT_EQ(loaded->meta.lamports, 5000);

    sol_account_destroy(account);
    sol_account_destroy(loaded);
    sol_accounts_db_destroy(db);
}

TEST(accounts_db_exists) {
    sol_accounts_db_t* db = sol_accounts_db_new(NULL);
    TEST_ASSERT(db != NULL);

    sol_pubkey_t pubkey1, pubkey2;
    memset(pubkey1.bytes, 0x22, 32);
    memset(pubkey2.bytes, 0x33, 32);

    sol_account_t* account = sol_account_new(1000, 0, NULL);

    sol_accounts_db_store(db, &pubkey1, account);

    TEST_ASSERT(sol_accounts_db_exists(db, &pubkey1));
    TEST_ASSERT(!sol_accounts_db_exists(db, &pubkey2));

    sol_account_destroy(account);
    sol_accounts_db_destroy(db);
}

TEST(accounts_db_delete) {
    sol_accounts_db_t* db = sol_accounts_db_new(NULL);
    TEST_ASSERT(db != NULL);

    sol_pubkey_t pubkey;
    memset(pubkey.bytes, 0x44, 32);

    sol_account_t* account = sol_account_new(1000, 0, NULL);
    sol_accounts_db_store(db, &pubkey, account);

    TEST_ASSERT_EQ(sol_accounts_db_count(db), 1);

    sol_err_t err = sol_accounts_db_delete(db, &pubkey);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_EQ(sol_accounts_db_count(db), 0);
    TEST_ASSERT(!sol_accounts_db_exists(db, &pubkey));

    sol_account_destroy(account);
    sol_accounts_db_destroy(db);
}

TEST(accounts_db_total_lamports) {
    sol_accounts_db_t* db = sol_accounts_db_new(NULL);
    TEST_ASSERT(db != NULL);

    sol_pubkey_t pubkey1, pubkey2;
    memset(pubkey1.bytes, 0x55, 32);
    memset(pubkey2.bytes, 0x66, 32);

    sol_account_t* acc1 = sol_account_new(1000, 0, NULL);
    sol_account_t* acc2 = sol_account_new(2000, 0, NULL);

    sol_accounts_db_store(db, &pubkey1, acc1);
    sol_accounts_db_store(db, &pubkey2, acc2);

    TEST_ASSERT_EQ(sol_accounts_db_total_lamports(db), 3000);

    sol_account_destroy(acc1);
    sol_account_destroy(acc2);
    sol_accounts_db_destroy(db);
}

TEST(accounts_db_snapshot) {
    sol_accounts_db_t* db = sol_accounts_db_new(NULL);
    TEST_ASSERT(db != NULL);

    sol_pubkey_t pubkey;
    memset(pubkey.bytes, 0x77, 32);

    sol_account_t* account = sol_account_new(5000, 0, NULL);
    sol_accounts_db_store(db, &pubkey, account);

    /* Create snapshot */
    sol_accounts_db_t* snapshot = sol_accounts_db_snapshot(db);
    TEST_ASSERT(snapshot != NULL);
    TEST_ASSERT_EQ(sol_accounts_db_count(snapshot), 1);

    /* Modify original */
    account->meta.lamports = 10000;
    sol_accounts_db_store(db, &pubkey, account);

    /* Snapshot should be unchanged */
    sol_account_t* snap_acc = sol_accounts_db_load(snapshot, &pubkey);
    TEST_ASSERT(snap_acc != NULL);
    TEST_ASSERT_EQ(snap_acc->meta.lamports, 5000);

    sol_account_destroy(account);
    sol_account_destroy(snap_acc);
    sol_accounts_db_destroy(db);
    sol_accounts_db_destroy(snapshot);
}

TEST(accounts_db_hash_delta_deterministic) {
    sol_accounts_db_t* base = sol_accounts_db_new(NULL);
    TEST_ASSERT_NOT_NULL(base);

    sol_pubkey_t base_key;
    memset(base_key.bytes, 0x01, sizeof(base_key.bytes));
    sol_account_t* base_acc = sol_account_new(10, 0, NULL);
    TEST_ASSERT_NOT_NULL(base_acc);
    TEST_ASSERT_EQ(sol_accounts_db_store(base, &base_key, base_acc), SOL_OK);
    sol_account_destroy(base_acc);

    sol_accounts_db_t* overlay1 = sol_accounts_db_fork(base);
    sol_accounts_db_t* overlay2 = sol_accounts_db_fork(base);
    TEST_ASSERT_NOT_NULL(overlay1);
    TEST_ASSERT_NOT_NULL(overlay2);

    sol_hash_t empty = {0};
    sol_accounts_db_hash_delta(overlay1, &empty);
    TEST_ASSERT(sol_hash_is_zero(&empty));

    /* Deleting a missing account should be a no-op and not perturb the delta hash. */
    sol_accounts_db_t* overlay_noop = sol_accounts_db_fork(base);
    TEST_ASSERT_NOT_NULL(overlay_noop);
    sol_pubkey_t missing_key;
    memset(missing_key.bytes, 0xEE, sizeof(missing_key.bytes));
    TEST_ASSERT_EQ(sol_accounts_db_delete(overlay_noop, &missing_key), SOL_OK);
    sol_hash_t noop_hash = {0};
    sol_accounts_db_hash_delta(overlay_noop, &noop_hash);
    TEST_ASSERT(sol_hash_is_zero(&noop_hash));
    sol_accounts_db_destroy(overlay_noop);

    /* Deleting an existing account must affect the delta hash (tombstones included). */
    sol_accounts_db_t* overlay_del = sol_accounts_db_fork(base);
    TEST_ASSERT_NOT_NULL(overlay_del);
    TEST_ASSERT_EQ(sol_accounts_db_delete(overlay_del, &base_key), SOL_OK);
    sol_hash_t del_hash = {0};
    sol_accounts_db_hash_delta(overlay_del, &del_hash);
    TEST_ASSERT(!sol_hash_is_zero(&del_hash));
    sol_accounts_db_destroy(overlay_del);

    sol_pubkey_t k1, k2;
    memset(k1.bytes, 0xA1, sizeof(k1.bytes));
    memset(k2.bytes, 0xA2, sizeof(k2.bytes));

    sol_account_t* a1 = sol_account_new(111, 0, NULL);
    sol_account_t* a2 = sol_account_new(222, 0, NULL);
    TEST_ASSERT_NOT_NULL(a1);
    TEST_ASSERT_NOT_NULL(a2);

    /* Apply same delta in different order; hash must match (sorted by pubkey). */
    TEST_ASSERT_EQ(sol_accounts_db_store(overlay1, &k1, a1), SOL_OK);
    TEST_ASSERT_EQ(sol_accounts_db_delete(overlay1, &base_key), SOL_OK);
    TEST_ASSERT_EQ(sol_accounts_db_store(overlay1, &k2, a2), SOL_OK);
    TEST_ASSERT_EQ(sol_accounts_db_store(overlay2, &k2, a2), SOL_OK);
    TEST_ASSERT_EQ(sol_accounts_db_store(overlay2, &k1, a1), SOL_OK);
    TEST_ASSERT_EQ(sol_accounts_db_delete(overlay2, &base_key), SOL_OK);

    sol_hash_t h1 = {0}, h2 = {0};
    sol_accounts_db_hash_delta(overlay1, &h1);
    sol_accounts_db_hash_delta(overlay2, &h2);
    TEST_ASSERT(sol_hash_eq(&h1, &h2));
    TEST_ASSERT(!sol_hash_is_zero(&h1));

    sol_account_destroy(a1);
    sol_account_destroy(a2);
    sol_accounts_db_destroy(overlay1);
    sol_accounts_db_destroy(overlay2);
    sol_accounts_db_destroy(base);
}

TEST(accounts_db_clear_override_restores_parent) {
    sol_accounts_db_t* base = sol_accounts_db_new(NULL);
    TEST_ASSERT_NOT_NULL(base);

    sol_pubkey_t key;
    memset(key.bytes, 0x55, sizeof(key.bytes));

    sol_account_t* base_acc = sol_account_new(10, 0, NULL);
    TEST_ASSERT_NOT_NULL(base_acc);
    TEST_ASSERT_EQ(sol_accounts_db_store(base, &key, base_acc), SOL_OK);
    sol_account_destroy(base_acc);

    sol_accounts_db_t* overlay = sol_accounts_db_fork(base);
    TEST_ASSERT_NOT_NULL(overlay);
    TEST_ASSERT(sol_accounts_db_is_overlay(overlay));

    sol_account_t* local = NULL;
    sol_accounts_db_local_kind_t kind =
        sol_accounts_db_get_local_kind(overlay, &key, &local);
    TEST_ASSERT_EQ(kind, SOL_ACCOUNTS_DB_LOCAL_MISSING);
    TEST_ASSERT(local == NULL);

    sol_account_t* visible = sol_accounts_db_load(overlay, &key);
    TEST_ASSERT_NOT_NULL(visible);
    TEST_ASSERT_EQ(visible->meta.lamports, 10);
    sol_account_destroy(visible);

    sol_account_t* updated = sol_account_new(20, 0, NULL);
    TEST_ASSERT_NOT_NULL(updated);
    TEST_ASSERT_EQ(sol_accounts_db_store(overlay, &key, updated), SOL_OK);
    sol_account_destroy(updated);

    kind = sol_accounts_db_get_local_kind(overlay, &key, &local);
    TEST_ASSERT_EQ(kind, SOL_ACCOUNTS_DB_LOCAL_ACCOUNT);
    TEST_ASSERT_NOT_NULL(local);
    TEST_ASSERT_EQ(local->meta.lamports, 20);
    sol_account_destroy(local);

    TEST_ASSERT_EQ(sol_accounts_db_count(overlay), 1);
    TEST_ASSERT_EQ(sol_accounts_db_total_lamports(overlay), 20);

    TEST_ASSERT_EQ(sol_accounts_db_clear_override(overlay, &key), SOL_OK);

    kind = sol_accounts_db_get_local_kind(overlay, &key, &local);
    TEST_ASSERT_EQ(kind, SOL_ACCOUNTS_DB_LOCAL_MISSING);
    TEST_ASSERT(local == NULL);

    visible = sol_accounts_db_load(overlay, &key);
    TEST_ASSERT_NOT_NULL(visible);
    TEST_ASSERT_EQ(visible->meta.lamports, 10);
    sol_account_destroy(visible);
    TEST_ASSERT_EQ(sol_accounts_db_total_lamports(overlay), 10);

    TEST_ASSERT_EQ(sol_accounts_db_delete(overlay, &key), SOL_OK);
    kind = sol_accounts_db_get_local_kind(overlay, &key, &local);
    TEST_ASSERT_EQ(kind, SOL_ACCOUNTS_DB_LOCAL_TOMBSTONE);
    TEST_ASSERT(local == NULL);

    visible = sol_accounts_db_load(overlay, &key);
    TEST_ASSERT(visible == NULL);
    sol_account_destroy(visible);
    TEST_ASSERT_EQ(sol_accounts_db_count(overlay), 0);
    TEST_ASSERT_EQ(sol_accounts_db_total_lamports(overlay), 0);

    TEST_ASSERT_EQ(sol_accounts_db_clear_override(overlay, &key), SOL_OK);
    kind = sol_accounts_db_get_local_kind(overlay, &key, &local);
    TEST_ASSERT_EQ(kind, SOL_ACCOUNTS_DB_LOCAL_MISSING);
    TEST_ASSERT(local == NULL);

    visible = sol_accounts_db_load(overlay, &key);
    TEST_ASSERT_NOT_NULL(visible);
    TEST_ASSERT_EQ(visible->meta.lamports, 10);
    sol_account_destroy(visible);
    TEST_ASSERT_EQ(sol_accounts_db_count(overlay), 1);
    TEST_ASSERT_EQ(sol_accounts_db_total_lamports(overlay), 10);

    sol_accounts_db_destroy(overlay);
    sol_accounts_db_destroy(base);
}

/*
 * Bank tests
 */


TEST(bank_create_destroy) {
    sol_hash_t parent_hash;
    memset(parent_hash.bytes, 0xAA, 32);

    sol_bank_t* bank = sol_bank_new(100, &parent_hash, NULL, NULL);
    TEST_ASSERT(bank != NULL);
    TEST_ASSERT_EQ(sol_bank_slot(bank), 100);
    TEST_ASSERT(!sol_bank_is_frozen(bank));

    sol_bank_destroy(bank);
}

TEST(bank_from_parent) {
    sol_hash_t parent_hash;
    memset(parent_hash.bytes, 0xBB, 32);

    sol_bank_t* parent = sol_bank_new(100, &parent_hash, NULL, NULL);
    TEST_ASSERT(parent != NULL);

    sol_bank_t* child = sol_bank_new_from_parent(parent, 101);
    TEST_ASSERT(child != NULL);
    TEST_ASSERT_EQ(sol_bank_slot(child), 101);

    sol_bank_destroy(child);
    sol_bank_destroy(parent);
}

TEST(bank_store_load_account) {
    sol_bank_t* bank = sol_bank_new(1, NULL, NULL, NULL);
    TEST_ASSERT(bank != NULL);

    sol_pubkey_t pubkey;
    memset(pubkey.bytes, 0xCC, 32);

    sol_account_t* account = sol_account_new(10000, 0, NULL);
    TEST_ASSERT(account != NULL);

    sol_err_t err = sol_bank_store_account(bank, &pubkey, account);
    TEST_ASSERT_EQ(err, SOL_OK);

    sol_account_t* loaded = sol_bank_load_account(bank, &pubkey);
    TEST_ASSERT(loaded != NULL);
    TEST_ASSERT_EQ(loaded->meta.lamports, 10000);

    sol_account_destroy(account);
    sol_account_destroy(loaded);
    sol_bank_destroy(bank);
}

TEST(bank_initializes_sysvar_accounts) {
    sol_bank_t* bank = sol_bank_new(1, NULL, NULL, NULL);
    TEST_ASSERT(bank != NULL);

    sol_account_t* clock = sol_bank_load_account(bank, &SOL_SYSVAR_CLOCK_ID);
    TEST_ASSERT(clock != NULL);
    TEST_ASSERT(clock->meta.lamports > 0);
    TEST_ASSERT_EQ(clock->meta.data_len, SOL_CLOCK_SIZE);
    sol_account_destroy(clock);

    sol_account_t* rent = sol_bank_load_account(bank, &SOL_SYSVAR_RENT_ID);
    TEST_ASSERT(rent != NULL);
    TEST_ASSERT(rent->meta.lamports > 0);
    TEST_ASSERT_EQ(rent->meta.data_len, SOL_RENT_SIZE);
    sol_account_destroy(rent);

    sol_account_t* epoch_schedule = sol_bank_load_account(bank, &SOL_SYSVAR_EPOCH_SCHEDULE_ID);
    TEST_ASSERT(epoch_schedule != NULL);
    TEST_ASSERT(epoch_schedule->meta.lamports > 0);
    TEST_ASSERT_EQ(epoch_schedule->meta.data_len, SOL_EPOCH_SCHEDULE_SIZE);
    sol_account_destroy(epoch_schedule);

    sol_account_t* fees = sol_bank_load_account(bank, &SOL_SYSVAR_FEES_ID);
    TEST_ASSERT(fees != NULL);
    TEST_ASSERT(fees->meta.lamports > 0);
    TEST_ASSERT_EQ(fees->meta.data_len, SOL_FEES_SIZE);
    sol_account_destroy(fees);

    sol_account_t* recent_blockhashes = sol_bank_load_account(bank, &SOL_SYSVAR_RECENT_BLOCKHASHES_ID);
    TEST_ASSERT(recent_blockhashes != NULL);
    TEST_ASSERT(recent_blockhashes->meta.lamports > 0);
    TEST_ASSERT_EQ(recent_blockhashes->meta.data_len, 8);  /* empty list */
    sol_account_destroy(recent_blockhashes);

    sol_account_t* slot_hashes = sol_bank_load_account(bank, &SOL_SYSVAR_SLOT_HASHES_ID);
    TEST_ASSERT(slot_hashes != NULL);
    TEST_ASSERT(slot_hashes->meta.lamports > 0);
    TEST_ASSERT_EQ(slot_hashes->meta.data_len, 8);  /* empty list */
    sol_account_destroy(slot_hashes);

    sol_account_t* stake_history = sol_bank_load_account(bank, &SOL_SYSVAR_STAKE_HISTORY_ID);
    TEST_ASSERT(stake_history != NULL);
    TEST_ASSERT(stake_history->meta.lamports > 0);
    TEST_ASSERT_EQ(stake_history->meta.data_len, 8);  /* empty list */
    sol_account_destroy(stake_history);

    sol_account_t* slot_history = sol_bank_load_account(bank, &SOL_SYSVAR_SLOT_HISTORY_ID);
    TEST_ASSERT(slot_history != NULL);
    TEST_ASSERT(slot_history->meta.lamports > 0);
    TEST_ASSERT_EQ(slot_history->meta.data_len, SOL_SLOT_HISTORY_SIZE);
    sol_account_destroy(slot_history);

    sol_account_t* instructions = sol_bank_load_account(bank, &SOL_SYSVAR_INSTRUCTIONS_ID);
    TEST_ASSERT(instructions != NULL);
    TEST_ASSERT(instructions->meta.lamports > 0);
    TEST_ASSERT_EQ(instructions->meta.data_len, 4);  /* empty placeholder */
    sol_account_destroy(instructions);

    sol_bank_destroy(bank);
}

TEST(bank_clock_timestamp_from_snapshot_sysvar) {
    sol_accounts_db_t* db = sol_accounts_db_new(NULL);
    TEST_ASSERT(db != NULL);

    sol_bank_config_t config = SOL_BANK_CONFIG_DEFAULT;
    config.ticks_per_slot = 64;
    config.slots_per_epoch = 1000;

    /* Seed a Clock sysvar like a snapshot would. */
    sol_clock_t clock = {0};
    sol_clock_init(&clock);
    clock.slot = 50;
    clock.epoch = 0;
    clock.unix_timestamp = (sol_unix_timestamp_t)1000;
    clock.epoch_start_timestamp = 0;
    clock.leader_schedule_epoch = 0;

    uint8_t clock_data[SOL_CLOCK_SIZE];
    TEST_ASSERT_EQ(sol_clock_serialize(&clock, clock_data, sizeof(clock_data)), SOL_OK);

    sol_account_t* clock_acct =
        sol_account_new(1, sizeof(clock_data), &SOL_SYSTEM_PROGRAM_ID);
    TEST_ASSERT(clock_acct != NULL);
    memcpy(clock_acct->data, clock_data, sizeof(clock_data));
    TEST_ASSERT_EQ(sol_accounts_db_store(db, &SOL_SYSVAR_CLOCK_ID, clock_acct), SOL_OK);
    sol_account_destroy(clock_acct);

    /* Create a bank for the next slot and advance it to the end of slot. */
    sol_bank_t* bank = sol_bank_new(51, NULL, db, &config);
    TEST_ASSERT(bank != NULL);

    sol_hash_t tick_hash = {0};
    for (uint64_t i = 0; i < config.ticks_per_slot; i++) {
        tick_hash.bytes[0] = (uint8_t)i;
        TEST_ASSERT_EQ(sol_bank_register_tick(bank, &tick_hash), SOL_OK);
    }

    sol_account_t* updated = sol_bank_load_account(bank, &SOL_SYSVAR_CLOCK_ID);
    TEST_ASSERT(updated != NULL);
    TEST_ASSERT_EQ(updated->meta.data_len, SOL_CLOCK_SIZE);

    sol_clock_t out = {0};
    sol_clock_init(&out);
    TEST_ASSERT_EQ(sol_clock_deserialize(&out, updated->data, updated->meta.data_len), SOL_OK);
    sol_account_destroy(updated);

    TEST_ASSERT_EQ(out.slot, 51);
    TEST_ASSERT_EQ(out.unix_timestamp, (sol_unix_timestamp_t)1000);
    TEST_ASSERT_EQ(out.epoch_start_timestamp, (ulong)980);

    sol_bank_destroy(bank);
    sol_accounts_db_destroy(db);
}

TEST(bank_clock_timestamp_stake_weighted_median) {
    sol_accounts_db_t* db = sol_accounts_db_new(NULL);
    TEST_ASSERT(db != NULL);

    sol_bank_config_t config = SOL_BANK_CONFIG_DEFAULT;
    config.ticks_per_slot = 64;
    config.slots_per_epoch = 100;

    /* Seed a Clock sysvar like a snapshot would (parent slot). */
    sol_clock_t parent_clock = {0};
    sol_clock_init(&parent_clock);
    parent_clock.slot = 150;
    parent_clock.epoch = 1;
    parent_clock.unix_timestamp = (sol_unix_timestamp_t)1023;
    parent_clock.epoch_start_timestamp = (sol_unix_timestamp_t)1000;
    parent_clock.leader_schedule_epoch = 1;

    uint8_t clock_data[SOL_CLOCK_SIZE];
    TEST_ASSERT_EQ(sol_clock_serialize(&parent_clock, clock_data, sizeof(clock_data)), SOL_OK);

    sol_account_t* clock_acct =
        sol_account_new(1, sizeof(clock_data), &SOL_SYSTEM_PROGRAM_ID);
    TEST_ASSERT(clock_acct != NULL);
    memcpy(clock_acct->data, clock_data, sizeof(clock_data));
    TEST_ASSERT_EQ(sol_accounts_db_store(db, &SOL_SYSVAR_CLOCK_ID, clock_acct), SOL_OK);
    sol_account_destroy(clock_acct);

    /* Two vote accounts with timestamps. */
    sol_pubkey_t vote1 = {0};
    sol_pubkey_t vote2 = {0};
    memset(vote1.bytes, 0xA1, sizeof(vote1.bytes));
    memset(vote2.bytes, 0xA2, sizeof(vote2.bytes));

    sol_vote_init_t init = {0};
    sol_vote_state_t vs1;
    sol_vote_state_t vs2;
    sol_vote_state_init(&vs1, &init);
    sol_vote_state_init(&vs2, &init);
    vs1.last_timestamp_slot = 151;
    vs1.last_timestamp = 1016;
    vs2.last_timestamp_slot = 151;
    vs2.last_timestamp = 1024;

    sol_account_t* vote1_acct =
        sol_account_new(1, SOL_VOTE_STATE_SIZE, &SOL_VOTE_PROGRAM_ID);
    sol_account_t* vote2_acct =
        sol_account_new(1, SOL_VOTE_STATE_SIZE, &SOL_VOTE_PROGRAM_ID);
    TEST_ASSERT_NOT_NULL(vote1_acct);
    TEST_ASSERT_NOT_NULL(vote2_acct);

    size_t written = 0;
    TEST_ASSERT_EQ(sol_vote_state_serialize(&vs1, vote1_acct->data, vote1_acct->meta.data_len, &written), SOL_OK);
    TEST_ASSERT_EQ(sol_vote_state_serialize(&vs2, vote2_acct->data, vote2_acct->meta.data_len, &written), SOL_OK);
    TEST_ASSERT_EQ(sol_accounts_db_store(db, &vote1, vote1_acct), SOL_OK);
    TEST_ASSERT_EQ(sol_accounts_db_store(db, &vote2, vote2_acct), SOL_OK);
    sol_account_destroy(vote1_acct);
    sol_account_destroy(vote2_acct);

    /* Two stake accounts delegating (weighted 1x and 2x). */
    sol_pubkey_t stake1 = {0};
    sol_pubkey_t stake2 = {0};
    memset(stake1.bytes, 0xB1, sizeof(stake1.bytes));
    memset(stake2.bytes, 0xB2, sizeof(stake2.bytes));

    sol_stake_state_t st1;
    sol_stake_state_t st2;
    sol_stake_state_init(&st1, NULL, NULL, 0);
    sol_stake_state_init(&st2, NULL, NULL, 0);
    TEST_ASSERT_EQ(sol_stake_delegate(&st1, &vote1, SOL_MIN_STAKE_DELEGATION, 0), SOL_OK);
    TEST_ASSERT_EQ(sol_stake_delegate(&st2, &vote2, SOL_MIN_STAKE_DELEGATION * 2, 0), SOL_OK);

    sol_account_t* stake1_acct =
        sol_account_new(1, SOL_STAKE_STATE_SIZE, &SOL_STAKE_PROGRAM_ID);
    sol_account_t* stake2_acct =
        sol_account_new(1, SOL_STAKE_STATE_SIZE, &SOL_STAKE_PROGRAM_ID);
    TEST_ASSERT_NOT_NULL(stake1_acct);
    TEST_ASSERT_NOT_NULL(stake2_acct);

    TEST_ASSERT_EQ(sol_stake_state_serialize(&st1, stake1_acct->data, stake1_acct->meta.data_len, &written), SOL_OK);
    TEST_ASSERT_EQ(sol_stake_state_serialize(&st2, stake2_acct->data, stake2_acct->meta.data_len, &written), SOL_OK);
    TEST_ASSERT_EQ(sol_accounts_db_store(db, &stake1, stake1_acct), SOL_OK);
    TEST_ASSERT_EQ(sol_accounts_db_store(db, &stake2, stake2_acct), SOL_OK);
    sol_account_destroy(stake1_acct);
    sol_account_destroy(stake2_acct);

    /* Create bank for slot 151 and advance it to end-of-slot so sysvars refresh. */
    sol_bank_t* bank = sol_bank_new(151, NULL, db, &config);
    TEST_ASSERT(bank != NULL);

    sol_hash_t tick_hash = {0};
    for (uint64_t i = 0; i < config.ticks_per_slot; i++) {
        tick_hash.bytes[0] = (uint8_t)i;
        TEST_ASSERT_EQ(sol_bank_register_tick(bank, &tick_hash), SOL_OK);
    }

    sol_account_t* updated = sol_bank_load_account(bank, &SOL_SYSVAR_CLOCK_ID);
    TEST_ASSERT(updated != NULL);
    TEST_ASSERT_EQ(updated->meta.data_len, SOL_CLOCK_SIZE);

    sol_clock_t out = {0};
    sol_clock_init(&out);
    TEST_ASSERT_EQ(sol_clock_deserialize(&out, updated->data, updated->meta.data_len), SOL_OK);
    sol_account_destroy(updated);

    TEST_ASSERT_EQ(out.slot, 151);
    TEST_ASSERT_EQ(out.unix_timestamp, (sol_unix_timestamp_t)1024);
    TEST_ASSERT_EQ(out.epoch_start_timestamp, (sol_unix_timestamp_t)1000);

    sol_bank_destroy(bank);
    sol_accounts_db_destroy(db);
}

TEST(bank_sysvar_meta_preserved_on_refresh) {
    sol_accounts_db_t* db = sol_accounts_db_new(NULL);
    TEST_ASSERT(db != NULL);

    sol_bank_config_t config = SOL_BANK_CONFIG_DEFAULT;
    config.ticks_per_slot = 4;
    config.slots_per_epoch = 1000;

    sol_pubkey_t custom_owner;
    memset(custom_owner.bytes, 0xAB, sizeof(custom_owner.bytes));

    sol_clock_t clock = {0};
    sol_clock_init(&clock);
    clock.slot = 0;
    clock.epoch = 0;
    clock.unix_timestamp = (sol_unix_timestamp_t)1000;
    clock.epoch_start_timestamp = 0;
    clock.leader_schedule_epoch = 0;

    uint8_t clock_data[SOL_CLOCK_SIZE];
    TEST_ASSERT_EQ(sol_clock_serialize(&clock, clock_data, sizeof(clock_data)), SOL_OK);

    sol_account_t* clock_acct =
        sol_account_new(1234567, sizeof(clock_data), &custom_owner);
    TEST_ASSERT(clock_acct != NULL);
    clock_acct->meta.rent_epoch = 999;
    memcpy(clock_acct->data, clock_data, sizeof(clock_data));
    TEST_ASSERT_EQ(sol_accounts_db_store(db, &SOL_SYSVAR_CLOCK_ID, clock_acct), SOL_OK);
    sol_account_destroy(clock_acct);

    sol_bank_t* bank = sol_bank_new(1, NULL, db, &config);
    TEST_ASSERT(bank != NULL);

    sol_hash_t tick_hash = {0};
    for (uint64_t i = 0; i < config.ticks_per_slot; i++) {
        tick_hash.bytes[0] = (uint8_t)i;
        TEST_ASSERT_EQ(sol_bank_register_tick(bank, &tick_hash), SOL_OK);
    }

    sol_account_t* updated = sol_bank_load_account(bank, &SOL_SYSVAR_CLOCK_ID);
    TEST_ASSERT(updated != NULL);
    TEST_ASSERT_EQ(updated->meta.lamports, 1234567);
    TEST_ASSERT(sol_pubkey_eq(&updated->meta.owner, &custom_owner));
    TEST_ASSERT_EQ(updated->meta.rent_epoch, 999);
    sol_account_destroy(updated);

    sol_bank_destroy(bank);
    sol_accounts_db_destroy(db);
}

TEST(bank_calculate_fee) {
    sol_bank_config_t config = SOL_BANK_CONFIG_DEFAULT;
    config.lamports_per_signature = 5000;

    sol_bank_t* bank = sol_bank_new(1, NULL, NULL, &config);
    TEST_ASSERT(bank != NULL);

    /* Mock transaction with 2 signatures */
    sol_transaction_t tx;
    sol_transaction_init(&tx);
    tx.signatures_len = 2;

    uint64_t fee = sol_bank_calculate_fee(bank, &tx);
    TEST_ASSERT_EQ(fee, 10000);  /* 2 * 5000 */

    sol_bank_destroy(bank);
}

TEST(bank_calculate_fee_uses_blockhash_fee_calculator) {
    sol_accounts_db_t* db = sol_accounts_db_new(NULL);
    TEST_ASSERT_NOT_NULL(db);

    sol_hash_t blockhash;
    memset(blockhash.bytes, 0xA7, sizeof(blockhash.bytes));

    sol_recent_blockhashes_t rbh;
    sol_recent_blockhashes_init(&rbh);
    rbh.len = 1;
    rbh.entries[0].blockhash = blockhash;
    rbh.entries[0].fee_calculator.lamports_per_signature = 7000;

    uint8_t rbh_data[8 + (32 + 8)];
    sol_err_t err = sol_recent_blockhashes_serialize(&rbh, rbh_data, sizeof(rbh_data));
    TEST_ASSERT_EQ(err, SOL_OK);

    sol_account_t* rbh_acct = sol_account_new(1, sizeof(rbh_data), &SOL_SYSVAR_PROGRAM_ID);
    TEST_ASSERT_NOT_NULL(rbh_acct);
    memcpy(rbh_acct->data, rbh_data, sizeof(rbh_data));
    err = sol_accounts_db_store(db, &SOL_SYSVAR_RECENT_BLOCKHASHES_ID, rbh_acct);
    TEST_ASSERT_EQ(err, SOL_OK);
    sol_account_destroy(rbh_acct);

    sol_bank_config_t config = SOL_BANK_CONFIG_DEFAULT;
    config.lamports_per_signature = 5000; /* Should be ignored for this blockhash. */
    sol_bank_t* bank = sol_bank_new(1, NULL, db, &config);
    TEST_ASSERT_NOT_NULL(bank);

    sol_transaction_t tx;
    sol_transaction_init(&tx);
    tx.signatures_len = 2;
    tx.message.recent_blockhash = blockhash;

    uint64_t fee = sol_bank_calculate_fee(bank, &tx);
    TEST_ASSERT_EQ(fee, 14000); /* 2 * 7000 */

    sol_bank_destroy(bank);
    sol_accounts_db_destroy(db);
}

TEST(bank_calculate_fee_counts_precompile_signatures) {
    sol_bank_config_t config = SOL_BANK_CONFIG_DEFAULT;
    config.lamports_per_signature = 5000;

    sol_bank_t* bank = sol_bank_new(1, NULL, NULL, &config);
    TEST_ASSERT_NOT_NULL(bank);

    sol_pubkey_t payer;
    memset(payer.bytes, 0x11, sizeof(payer.bytes));

    sol_pubkey_t account_keys[3] = { payer, SOL_ED25519_PROGRAM_ID, SOL_SECP256K1_PROGRAM_ID };

    uint8_t ed25519_data[2] = {2, 0};
    sol_compiled_instruction_t ix0 = {0};
    ix0.program_id_index = 1;
    ix0.data = ed25519_data;
    ix0.data_len = (uint16_t)sizeof(ed25519_data);

    uint8_t secp256k1_data[1] = {3};
    sol_compiled_instruction_t ix1 = {0};
    ix1.program_id_index = 2;
    ix1.data = secp256k1_data;
    ix1.data_len = (uint16_t)sizeof(secp256k1_data);

    sol_compiled_instruction_t instructions[2] = {ix0, ix1};

    sol_transaction_t tx;
    sol_transaction_init(&tx);
    tx.signatures_len = 1;
    tx.message.account_keys = account_keys;
    tx.message.account_keys_len = (uint8_t)(sizeof(account_keys) / sizeof(account_keys[0]));
    tx.message.resolved_accounts = account_keys;
    tx.message.resolved_accounts_len = (uint16_t)tx.message.account_keys_len;
    tx.message.instructions = instructions;
    tx.message.instructions_len = (uint8_t)(sizeof(instructions) / sizeof(instructions[0]));

    uint64_t fee = sol_bank_calculate_fee(bank, &tx);
    TEST_ASSERT_EQ(fee, 30000); /* (1 tx sig + 2 ed25519 + 3 secp256k1) * 5000 */

    sol_bank_destroy(bank);
}

TEST(bank_process_transaction_charges_precompile_signature_fee) {
    sol_hash_t parent_blockhash;
    memset(parent_blockhash.bytes, 0xAA, sizeof(parent_blockhash.bytes));

    sol_bank_config_t config = SOL_BANK_CONFIG_DEFAULT;
    config.ticks_per_slot = 1;
    config.lamports_per_signature = 5000;

    sol_bank_t* bank = sol_bank_new(0, &parent_blockhash, NULL, &config);
    TEST_ASSERT_NOT_NULL(bank);

    /* Fee payer keypair */
    uint8_t seed[SOL_ED25519_SEED_SIZE];
    memset(seed, 0x22, sizeof(seed));

    sol_keypair_t payer_kp;
    sol_ed25519_keypair_from_seed(seed, &payer_kp);

    sol_pubkey_t payer;
    sol_ed25519_pubkey_from_keypair(&payer_kp, &payer);

    uint64_t expected_fee = 15000; /* (1 tx sig + 2 ed25519) * 5000 */
    uint64_t initial_lamports = expected_fee + 100;

    sol_account_t* payer_account = sol_account_new(initial_lamports, 0, &SOL_SYSTEM_PROGRAM_ID);
    TEST_ASSERT_NOT_NULL(payer_account);
    sol_err_t err = sol_bank_store_account(bank, &payer, payer_account);
    TEST_ASSERT_EQ(err, SOL_OK);
    sol_account_destroy(payer_account);

    /* Build a legacy message with an intentionally malformed Ed25519 precompile instruction. */
    sol_pubkey_t account_keys[2] = { payer, SOL_ED25519_PROGRAM_ID };

    uint8_t ed25519_ix_data[2] = {2, 0}; /* Too short for 2 signatures => program should fail. */
    sol_compiled_instruction_t ix = {0};
    ix.program_id_index = 1;
    ix.account_indices = NULL;
    ix.account_indices_len = 0;
    ix.data = ed25519_ix_data;
    ix.data_len = (uint16_t)sizeof(ed25519_ix_data);

    sol_message_t msg;
    sol_message_init(&msg);
    msg.version = SOL_MESSAGE_VERSION_LEGACY;
    msg.header.num_required_signatures = 1;
    msg.header.num_readonly_signed = 0;
    msg.header.num_readonly_unsigned = 1;
    msg.account_keys = account_keys;
    msg.account_keys_len = (uint8_t)(sizeof(account_keys) / sizeof(account_keys[0]));
    msg.resolved_accounts = msg.account_keys;
    msg.resolved_accounts_len = msg.account_keys_len;
    msg.recent_blockhash = parent_blockhash;
    msg.instructions = &ix;
    msg.instructions_len = 1;

    uint8_t message_buf[256];
    sol_encoder_t enc;
    sol_encoder_init(&enc, message_buf, sizeof(message_buf));
    err = sol_message_encode_legacy(&enc, &msg);
    TEST_ASSERT_EQ(err, SOL_OK);
    size_t message_len = sol_encoder_len(&enc);

    sol_signature_t sig;
    sol_ed25519_sign(&payer_kp, message_buf, message_len, &sig);

    sol_transaction_t tx;
    sol_transaction_init(&tx);
    tx.signatures = &sig;
    tx.signatures_len = 1;
    tx.message = msg;
    tx.message_data = message_buf;
    tx.message_data_len = message_len;

    sol_tx_result_t result = sol_bank_process_transaction(bank, &tx);
    TEST_ASSERT_EQ(result.status, SOL_ERR_PROGRAM_INVALID_INSTR);
    TEST_ASSERT_EQ(result.fee, expected_fee);
    TEST_ASSERT_EQ(sol_bank_signature_count(bank), 1);

    sol_account_t* loaded = sol_bank_load_account(bank, &payer);
    TEST_ASSERT_NOT_NULL(loaded);
    TEST_ASSERT_EQ(loaded->meta.lamports, initial_lamports - expected_fee);
    sol_account_destroy(loaded);

    sol_bank_destroy(bank);
}

TEST(bank_process_v0_transaction_with_alt_writable_account) {
    sol_hash_t parent_blockhash;
    memset(parent_blockhash.bytes, 0xAA, sizeof(parent_blockhash.bytes));

    sol_bank_config_t config = SOL_BANK_CONFIG_DEFAULT;
    config.ticks_per_slot = 1;
    config.lamports_per_signature = 5000;

    sol_bank_t* bank = sol_bank_new(0, &parent_blockhash, NULL, &config);
    TEST_ASSERT_NOT_NULL(bank);

    /* Fee payer keypair */
    uint8_t seed[SOL_ED25519_SEED_SIZE];
    memset(seed, 0x22, sizeof(seed));

    sol_keypair_t payer_kp;
    sol_ed25519_keypair_from_seed(seed, &payer_kp);

    sol_pubkey_t payer;
    sol_ed25519_pubkey_from_keypair(&payer_kp, &payer);

    sol_pubkey_t recipient;
    memset(recipient.bytes, 0x55, sizeof(recipient.bytes));

    /* Create an ALT account containing the recipient address. */
    sol_pubkey_t alt_key;
    memset(alt_key.bytes, 0x99, sizeof(alt_key.bytes));

    sol_alt_state_t alt_state;
    sol_alt_state_init(&alt_state);
    alt_state.addresses_len = 1;
    alt_state.addresses = sol_alloc(sizeof(sol_pubkey_t));
    TEST_ASSERT_NOT_NULL(alt_state.addresses);
    alt_state.addresses[0] = recipient;

    size_t alt_data_len = SOL_ALT_METADATA_SIZE + SOL_PUBKEY_SIZE;
    sol_account_t* alt_account = sol_account_new(1, alt_data_len, &SOL_ADDRESS_LOOKUP_TABLE_ID);
    TEST_ASSERT_NOT_NULL(alt_account);

    size_t alt_written = 0;
    sol_err_t err = sol_alt_serialize(&alt_state,
                                      alt_account->data,
                                      alt_account->meta.data_len,
                                      &alt_written);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_EQ(alt_written, alt_data_len);

    err = sol_bank_store_account(bank, &alt_key, alt_account);
    TEST_ASSERT_EQ(err, SOL_OK);

    sol_account_destroy(alt_account);
    sol_alt_state_free(&alt_state);

    uint64_t transfer_lamports = 1234;
    uint64_t expected_fee = sol_bank_lamports_per_signature(bank);
    uint64_t initial_lamports = expected_fee + transfer_lamports + 100;

    sol_account_t* payer_account = sol_account_new(initial_lamports, 0, &SOL_SYSTEM_PROGRAM_ID);
    TEST_ASSERT_NOT_NULL(payer_account);
    err = sol_bank_store_account(bank, &payer, payer_account);
    TEST_ASSERT_EQ(err, SOL_OK);
    sol_account_destroy(payer_account);

    /* Build a v0 transfer message where the recipient is loaded from the ALT. */
    sol_pubkey_t account_keys[2] = {payer, SOL_SYSTEM_PROGRAM_ID};

    uint8_t ix_accounts[2] = {0, 2}; /* payer + ALT-loaded recipient */
    uint8_t ix_data[12];
    size_t ix_data_len = sizeof(ix_data);
    err = sol_system_transfer_instruction(&payer, &recipient, transfer_lamports, ix_data, &ix_data_len);
    TEST_ASSERT_EQ(err, SOL_OK);

    sol_compiled_instruction_t ix = {0};
    ix.program_id_index = 1;
    ix.account_indices = ix_accounts;
    ix.account_indices_len = (uint8_t)sizeof(ix_accounts);
    ix.data = ix_data;
    ix.data_len = (uint16_t)ix_data_len;

    uint8_t lookup_writable_indices[1] = {0};
    sol_address_lookup_t lookups[1] = {0};
    lookups[0].account_key = alt_key;
    lookups[0].writable_indices = lookup_writable_indices;
    lookups[0].writable_indices_len = (uint8_t)sizeof(lookup_writable_indices);
    lookups[0].readonly_indices = NULL;
    lookups[0].readonly_indices_len = 0;

    sol_message_t msg;
    sol_message_init(&msg);
    msg.version = SOL_MESSAGE_VERSION_V0;
    msg.header.num_required_signatures = 1;
    msg.header.num_readonly_signed = 0;
    msg.header.num_readonly_unsigned = 1;
    msg.account_keys = account_keys;
    msg.account_keys_len = (uint8_t)(sizeof(account_keys) / sizeof(account_keys[0]));
    msg.recent_blockhash = parent_blockhash;
    msg.instructions = &ix;
    msg.instructions_len = 1;
    msg.address_lookups = lookups;
    msg.address_lookups_len = 1;

    uint8_t message_buf[512];
    sol_encoder_t enc;
    sol_encoder_init(&enc, message_buf, sizeof(message_buf));
    err = sol_encode_u8(&enc, 0x80); /* Version 0 prefix */
    TEST_ASSERT_EQ(err, SOL_OK);
    err = sol_message_encode_v0(&enc, &msg);
    TEST_ASSERT_EQ(err, SOL_OK);
    size_t message_len = sol_encoder_len(&enc);

    sol_signature_t sig;
    sol_ed25519_sign(&payer_kp, message_buf, message_len, &sig);

    sol_transaction_t tx;
    sol_transaction_init(&tx);
    tx.signatures = &sig;
    tx.signatures_len = 1;
    tx.message = msg;
    tx.message_data = message_buf;
    tx.message_data_len = message_len;

    sol_tx_result_t result = sol_bank_process_transaction(bank, &tx);
    TEST_ASSERT_EQ(result.status, SOL_OK);
    TEST_ASSERT_EQ(result.fee, expected_fee);

    sol_account_t* loaded_payer = sol_bank_load_account(bank, &payer);
    TEST_ASSERT_NOT_NULL(loaded_payer);
    TEST_ASSERT_EQ(loaded_payer->meta.lamports, initial_lamports - expected_fee - transfer_lamports);
    sol_account_destroy(loaded_payer);

    sol_account_t* loaded_recipient = sol_bank_load_account(bank, &recipient);
    TEST_ASSERT_NOT_NULL(loaded_recipient);
    TEST_ASSERT_EQ(loaded_recipient->meta.lamports, transfer_lamports);
    TEST_ASSERT(sol_pubkey_eq(&loaded_recipient->meta.owner, &SOL_SYSTEM_PROGRAM_ID));
    sol_account_destroy(loaded_recipient);

    sol_bank_destroy(bank);
}

TEST(bank_resolve_v0_transaction_accounts_alt_loaded_order) {
    sol_hash_t parent_blockhash;
    memset(parent_blockhash.bytes, 0xAA, sizeof(parent_blockhash.bytes));

    sol_bank_config_t config = SOL_BANK_CONFIG_DEFAULT;
    config.ticks_per_slot = 1;
    config.lamports_per_signature = 5000;

    sol_bank_t* bank = sol_bank_new(0, &parent_blockhash, NULL, &config);
    TEST_ASSERT_NOT_NULL(bank);

    /* Fee payer keypair */
    uint8_t seed[SOL_ED25519_SEED_SIZE];
    memset(seed, 0x44, sizeof(seed));

    sol_keypair_t payer_kp;
    sol_ed25519_keypair_from_seed(seed, &payer_kp);

    sol_pubkey_t payer;
    sol_ed25519_pubkey_from_keypair(&payer_kp, &payer);

    /* Two ALT accounts with (writable, readonly) address pairs. */
    sol_pubkey_t alt1_key;
    memset(alt1_key.bytes, 0x91, sizeof(alt1_key.bytes));
    sol_pubkey_t alt2_key;
    memset(alt2_key.bytes, 0x92, sizeof(alt2_key.bytes));

    sol_pubkey_t w1, r1, w2, r2;
    memset(w1.bytes, 0x11, sizeof(w1.bytes));
    memset(r1.bytes, 0x12, sizeof(r1.bytes));
    memset(w2.bytes, 0x21, sizeof(w2.bytes));
    memset(r2.bytes, 0x22, sizeof(r2.bytes));

    for (int t = 0; t < 2; t++) {
        const sol_pubkey_t* alt_key = t == 0 ? &alt1_key : &alt2_key;
        sol_pubkey_t addrs[2];
        addrs[0] = t == 0 ? w1 : w2;
        addrs[1] = t == 0 ? r1 : r2;

        sol_alt_state_t alt_state;
        sol_alt_state_init(&alt_state);
        alt_state.addresses_len = 2;
        alt_state.addresses = sol_alloc(sizeof(addrs));
        TEST_ASSERT_NOT_NULL(alt_state.addresses);
        alt_state.addresses[0] = addrs[0];
        alt_state.addresses[1] = addrs[1];

        size_t alt_data_len = SOL_ALT_METADATA_SIZE + 2 * SOL_PUBKEY_SIZE;
        sol_account_t* alt_account =
            sol_account_new(1, alt_data_len, &SOL_ADDRESS_LOOKUP_TABLE_ID);
        TEST_ASSERT_NOT_NULL(alt_account);

        size_t alt_written = 0;
        sol_err_t err = sol_alt_serialize(&alt_state,
                                          alt_account->data,
                                          alt_account->meta.data_len,
                                          &alt_written);
        TEST_ASSERT_EQ(err, SOL_OK);
        TEST_ASSERT_EQ(alt_written, alt_data_len);

        err = sol_bank_store_account(bank, alt_key, alt_account);
        TEST_ASSERT_EQ(err, SOL_OK);

        sol_account_destroy(alt_account);
        sol_alt_state_free(&alt_state);
    }

    /* Build a v0 message with two lookups.
     *
     * Expected resolved accounts order:
     *   static keys + all loaded writable + all loaded readonly
     *   [payer, system] + [w1, w2] + [r1, r2]
     */
    sol_pubkey_t static_keys[2] = {payer, SOL_SYSTEM_PROGRAM_ID};

    uint8_t alt1_writable[1] = {0};
    uint8_t alt1_readonly[1] = {1};
    uint8_t alt2_writable[1] = {0};
    uint8_t alt2_readonly[1] = {1};

    sol_address_lookup_t lookups[2] = {0};
    lookups[0].account_key = alt1_key;
    lookups[0].writable_indices = alt1_writable;
    lookups[0].writable_indices_len = (uint8_t)sizeof(alt1_writable);
    lookups[0].readonly_indices = alt1_readonly;
    lookups[0].readonly_indices_len = (uint8_t)sizeof(alt1_readonly);

    lookups[1].account_key = alt2_key;
    lookups[1].writable_indices = alt2_writable;
    lookups[1].writable_indices_len = (uint8_t)sizeof(alt2_writable);
    lookups[1].readonly_indices = alt2_readonly;
    lookups[1].readonly_indices_len = (uint8_t)sizeof(alt2_readonly);

    sol_message_t msg;
    sol_message_init(&msg);
    msg.version = SOL_MESSAGE_VERSION_V0;
    msg.header.num_required_signatures = 1;
    msg.header.num_readonly_signed = 0;
    msg.header.num_readonly_unsigned = 1;
    msg.account_keys = static_keys;
    msg.account_keys_len = (uint8_t)(sizeof(static_keys) / sizeof(static_keys[0]));
    msg.recent_blockhash = parent_blockhash;
    msg.instructions = NULL;
    msg.instructions_len = 0;
    msg.address_lookups = lookups;
    msg.address_lookups_len = (uint8_t)(sizeof(lookups) / sizeof(lookups[0]));

    uint8_t message_buf[512];
    sol_encoder_t enc;
    sol_encoder_init(&enc, message_buf, sizeof(message_buf));
    sol_err_t err = sol_encode_u8(&enc, 0x80); /* Version 0 prefix */
    TEST_ASSERT_EQ(err, SOL_OK);
    err = sol_message_encode_v0(&enc, &msg);
    TEST_ASSERT_EQ(err, SOL_OK);
    size_t message_len = sol_encoder_len(&enc);

    sol_signature_t sig;
    sol_ed25519_sign(&payer_kp, message_buf, message_len, &sig);

    sol_transaction_t tx;
    sol_transaction_init(&tx);
    tx.signatures = &sig;
    tx.signatures_len = 1;
    tx.message = msg;
    tx.message_data = message_buf;
    tx.message_data_len = message_len;

    sol_pubkey_t resolved_keys[SOL_MAX_MESSAGE_ACCOUNTS];
    bool resolved_writable[SOL_MAX_MESSAGE_ACCOUNTS];
    bool resolved_signer[SOL_MAX_MESSAGE_ACCOUNTS];
    size_t resolved_len = 0;

    err = sol_bank_resolve_transaction_accounts(bank,
                                                &tx,
                                                resolved_keys,
                                                resolved_writable,
                                                resolved_signer,
                                                SOL_MAX_MESSAGE_ACCOUNTS,
                                                &resolved_len);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_EQ(resolved_len, 6);

    TEST_ASSERT(sol_pubkey_eq(&resolved_keys[0], &payer));
    TEST_ASSERT(sol_pubkey_eq(&resolved_keys[1], &SOL_SYSTEM_PROGRAM_ID));
    TEST_ASSERT(sol_pubkey_eq(&resolved_keys[2], &w1));
    TEST_ASSERT(sol_pubkey_eq(&resolved_keys[3], &w2));
    TEST_ASSERT(sol_pubkey_eq(&resolved_keys[4], &r1));
    TEST_ASSERT(sol_pubkey_eq(&resolved_keys[5], &r2));

    TEST_ASSERT_EQ(resolved_signer[0], true);
    TEST_ASSERT_EQ(resolved_writable[0], true);

    TEST_ASSERT_EQ(resolved_signer[1], false);
    TEST_ASSERT_EQ(resolved_writable[1], false);

    TEST_ASSERT_EQ(resolved_signer[2], false);
    TEST_ASSERT_EQ(resolved_writable[2], true);
    TEST_ASSERT_EQ(resolved_signer[3], false);
    TEST_ASSERT_EQ(resolved_writable[3], true);

    TEST_ASSERT_EQ(resolved_signer[4], false);
    TEST_ASSERT_EQ(resolved_writable[4], false);
    TEST_ASSERT_EQ(resolved_signer[5], false);
    TEST_ASSERT_EQ(resolved_writable[5], false);

    sol_bank_destroy(bank);
}

TEST(bank_freeze) {
    sol_bank_t* bank = sol_bank_new(1, NULL, NULL, NULL);
    TEST_ASSERT(bank != NULL);

    TEST_ASSERT(!sol_bank_is_frozen(bank));

    sol_bank_freeze(bank);

    TEST_ASSERT(sol_bank_is_frozen(bank));

    /* Should not be able to store after freeze */
    sol_pubkey_t pubkey;
    memset(pubkey.bytes, 0xDD, 32);
    sol_account_t* account = sol_account_new(1000, 0, NULL);

    sol_err_t err = sol_bank_store_account(bank, &pubkey, account);
    TEST_ASSERT_EQ(err, SOL_ERR_SHUTDOWN);

    sol_account_destroy(account);
    sol_bank_destroy(bank);
}

TEST(bank_register_tick) {
    sol_bank_config_t config = SOL_BANK_CONFIG_DEFAULT;
    config.ticks_per_slot = 4;

    sol_bank_t* bank = sol_bank_new(0, NULL, NULL, &config);
    TEST_ASSERT(bank != NULL);

    uint64_t initial_height = sol_bank_tick_height(bank);

    sol_hash_t tick_hash;
    memset(tick_hash.bytes, 0xEE, 32);

    sol_err_t err = sol_bank_register_tick(bank, &tick_hash);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_EQ(sol_bank_tick_height(bank), initial_height + 1);

    sol_bank_destroy(bank);
}

TEST(bank_fee_distribution_credits_collector) {
    sol_hash_t parent_hash;
    memset(parent_hash.bytes, 0xA5, sizeof(parent_hash.bytes));

    sol_bank_config_t config = SOL_BANK_CONFIG_DEFAULT;
    config.ticks_per_slot = 1;
    config.lamports_per_signature = 5000;

    sol_bank_t* bank = sol_bank_new(0, &parent_hash, NULL, &config);
    TEST_ASSERT_NOT_NULL(bank);

    sol_pubkey_t collector;
    memset(collector.bytes, 0x99, sizeof(collector.bytes));
    sol_bank_set_fee_collector(bank, &collector);

    /* Fee payer keypair */
    uint8_t seed[SOL_ED25519_SEED_SIZE];
    memset(seed, 0x01, sizeof(seed));

    sol_keypair_t payer_kp;
    sol_ed25519_keypair_from_seed(seed, &payer_kp);

    sol_pubkey_t payer;
    sol_ed25519_pubkey_from_keypair(&payer_kp, &payer);

    sol_pubkey_t recipient;
    memset(recipient.bytes, 0x02, sizeof(recipient.bytes));

    uint64_t fee = sol_bank_lamports_per_signature(bank);
    uint64_t transfer_lamports = 1234;
    uint64_t initial_lamports = fee + transfer_lamports + 100;

    sol_account_t* payer_account = sol_account_new(initial_lamports, 0, &SOL_SYSTEM_PROGRAM_ID);
    TEST_ASSERT_NOT_NULL(payer_account);
    sol_err_t err = sol_bank_store_account(bank, &payer, payer_account);
    TEST_ASSERT_EQ(err, SOL_OK);
    sol_account_destroy(payer_account);

    /* Build a legacy transfer message. */
    sol_pubkey_t account_keys[3] = { payer, recipient, SOL_SYSTEM_PROGRAM_ID };
    uint8_t ix_accounts[2] = {0, 1};

    uint8_t ix_data[12];
    uint32_t instr = SOL_SYSTEM_INSTR_TRANSFER;
    memcpy(ix_data, &instr, 4);
    memcpy(ix_data + 4, &transfer_lamports, 8);

    sol_compiled_instruction_t ix = {0};
    ix.program_id_index = 2;
    ix.account_indices = ix_accounts;
    ix.account_indices_len = (uint8_t)sizeof(ix_accounts);
    ix.data = ix_data;
    ix.data_len = (uint16_t)sizeof(ix_data);

    sol_message_t msg;
    sol_message_init(&msg);
    msg.version = SOL_MESSAGE_VERSION_LEGACY;
    msg.header.num_required_signatures = 1;
    msg.header.num_readonly_signed = 0;
    msg.header.num_readonly_unsigned = 1;
    msg.account_keys = account_keys;
    msg.account_keys_len = (uint8_t)(sizeof(account_keys) / sizeof(account_keys[0]));
    msg.resolved_accounts = msg.account_keys;
    msg.resolved_accounts_len = msg.account_keys_len;
    msg.recent_blockhash = parent_hash;
    msg.instructions = &ix;
    msg.instructions_len = 1;

    uint8_t message_buf[256];
    sol_encoder_t enc;
    sol_encoder_init(&enc, message_buf, sizeof(message_buf));
    err = sol_message_encode_legacy(&enc, &msg);
    TEST_ASSERT_EQ(err, SOL_OK);
    size_t message_len = sol_encoder_len(&enc);

    sol_signature_t sig;
    sol_ed25519_sign(&payer_kp, message_buf, message_len, &sig);

    sol_transaction_t tx;
    sol_transaction_init(&tx);
    tx.signatures = &sig;
    tx.signatures_len = 1;
    tx.message = msg;
    tx.message_data = message_buf;
    tx.message_data_len = message_len;

    sol_tx_result_t result = sol_bank_process_transaction(bank, &tx);
    TEST_ASSERT_EQ(result.status, SOL_OK);
    TEST_ASSERT_EQ(result.fee, fee);

    /* Collector should not be credited until the slot ends. */
    sol_account_t* pre = sol_bank_load_account(bank, &collector);
    TEST_ASSERT(pre == NULL);
    sol_account_destroy(pre);

    sol_hash_t tick_hash;
    memset(tick_hash.bytes, 0xEE, sizeof(tick_hash.bytes));
    TEST_ASSERT_EQ(sol_bank_register_tick(bank, &tick_hash), SOL_OK);

    uint64_t burned = (fee * 50ULL) / 100ULL;
    uint64_t expected_credit = fee - burned;

    sol_account_t* post = sol_bank_load_account(bank, &collector);
    TEST_ASSERT_NOT_NULL(post);
    TEST_ASSERT_EQ(post->meta.lamports, expected_credit);
    sol_account_destroy(post);

    sol_bank_destroy(bank);
}

TEST(bank_priority_fee_not_burned) {
    sol_hash_t parent_hash;
    memset(parent_hash.bytes, 0xA6, sizeof(parent_hash.bytes));

    sol_bank_config_t config = SOL_BANK_CONFIG_DEFAULT;
    config.ticks_per_slot = 1;
    config.lamports_per_signature = 5000;

    sol_bank_t* bank = sol_bank_new(0, &parent_hash, NULL, &config);
    TEST_ASSERT_NOT_NULL(bank);

    sol_pubkey_t collector;
    memset(collector.bytes, 0x88, sizeof(collector.bytes));
    sol_bank_set_fee_collector(bank, &collector);

    /* Fee payer keypair */
    uint8_t seed[SOL_ED25519_SEED_SIZE];
    memset(seed, 0x03, sizeof(seed));

    sol_keypair_t payer_kp;
    sol_ed25519_keypair_from_seed(seed, &payer_kp);

    sol_pubkey_t payer;
    sol_ed25519_pubkey_from_keypair(&payer_kp, &payer);

    sol_pubkey_t recipient;
    memset(recipient.bytes, 0x04, sizeof(recipient.bytes));

    uint64_t base_fee = sol_bank_lamports_per_signature(bank);
    uint64_t transfer_lamports = 1234;

    /* Priority fee: default CU limit is 200k. Use 1000 micro-lamports/CU => 200 lamports. */
    uint64_t compute_unit_price = 1000ULL; /* micro-lamports per CU */
    uint64_t priority_fee = (200000ULL * compute_unit_price) / 1000000ULL;

    uint64_t initial_lamports = base_fee + priority_fee + transfer_lamports + 100;

    sol_account_t* payer_account = sol_account_new(initial_lamports, 0, &SOL_SYSTEM_PROGRAM_ID);
    TEST_ASSERT_NOT_NULL(payer_account);
    sol_err_t err = sol_bank_store_account(bank, &payer, payer_account);
    TEST_ASSERT_EQ(err, SOL_OK);
    sol_account_destroy(payer_account);

    /* Build a legacy transfer message with a ComputeBudget SetComputeUnitPrice ix. */
    sol_pubkey_t account_keys[4] = { payer, recipient, SOL_SYSTEM_PROGRAM_ID, SOL_COMPUTE_BUDGET_ID };

    uint8_t compute_budget_ix_data[9];
    compute_budget_ix_data[0] = 3; /* SetComputeUnitPrice */
    memcpy(compute_budget_ix_data + 1, &compute_unit_price, 8);

    sol_compiled_instruction_t compute_ix = {0};
    compute_ix.program_id_index = 3;
    compute_ix.account_indices = NULL;
    compute_ix.account_indices_len = 0;
    compute_ix.data = compute_budget_ix_data;
    compute_ix.data_len = (uint16_t)sizeof(compute_budget_ix_data);

    uint8_t transfer_ix_accounts[2] = {0, 1};
    uint8_t transfer_ix_data[12];
    uint32_t instr = SOL_SYSTEM_INSTR_TRANSFER;
    memcpy(transfer_ix_data, &instr, 4);
    memcpy(transfer_ix_data + 4, &transfer_lamports, 8);

    sol_compiled_instruction_t transfer_ix = {0};
    transfer_ix.program_id_index = 2;
    transfer_ix.account_indices = transfer_ix_accounts;
    transfer_ix.account_indices_len = (uint8_t)sizeof(transfer_ix_accounts);
    transfer_ix.data = transfer_ix_data;
    transfer_ix.data_len = (uint16_t)sizeof(transfer_ix_data);

    sol_compiled_instruction_t instructions[2] = { compute_ix, transfer_ix };

    sol_message_t msg;
    sol_message_init(&msg);
    msg.version = SOL_MESSAGE_VERSION_LEGACY;
    msg.header.num_required_signatures = 1;
    msg.header.num_readonly_signed = 0;
    msg.header.num_readonly_unsigned = 2; /* system + compute budget */
    msg.account_keys = account_keys;
    msg.account_keys_len = (uint8_t)(sizeof(account_keys) / sizeof(account_keys[0]));
    msg.resolved_accounts = msg.account_keys;
    msg.resolved_accounts_len = msg.account_keys_len;
    msg.recent_blockhash = parent_hash;
    msg.instructions = instructions;
    msg.instructions_len = (uint8_t)(sizeof(instructions) / sizeof(instructions[0]));

    uint8_t message_buf[256];
    sol_encoder_t enc;
    sol_encoder_init(&enc, message_buf, sizeof(message_buf));
    err = sol_message_encode_legacy(&enc, &msg);
    TEST_ASSERT_EQ(err, SOL_OK);
    size_t message_len = sol_encoder_len(&enc);

    sol_signature_t sig;
    sol_ed25519_sign(&payer_kp, message_buf, message_len, &sig);

    sol_transaction_t tx;
    sol_transaction_init(&tx);
    tx.signatures = &sig;
    tx.signatures_len = 1;
    tx.message = msg;
    tx.message_data = message_buf;
    tx.message_data_len = message_len;

    sol_tx_result_t result = sol_bank_process_transaction(bank, &tx);
    TEST_ASSERT_EQ(result.status, SOL_OK);
    TEST_ASSERT_EQ(result.fee, base_fee + priority_fee);

    sol_hash_t tick_hash;
    memset(tick_hash.bytes, 0xEE, sizeof(tick_hash.bytes));
    TEST_ASSERT_EQ(sol_bank_register_tick(bank, &tick_hash), SOL_OK);

    uint64_t burned = (base_fee * 50ULL) / 100ULL;
    uint64_t expected_credit = (base_fee - burned) + priority_fee;

    sol_account_t* post = sol_bank_load_account(bank, &collector);
    TEST_ASSERT_NOT_NULL(post);
    TEST_ASSERT_EQ(post->meta.lamports, expected_credit);
    sol_account_destroy(post);

    sol_bank_destroy(bank);
}

TEST(bank_stats) {
    sol_bank_t* bank = sol_bank_new(1, NULL, NULL, NULL);
    TEST_ASSERT(bank != NULL);

    sol_bank_stats_t stats;
    sol_bank_stats(bank, &stats);

    TEST_ASSERT_EQ(stats.transactions_processed, 0);
    TEST_ASSERT_EQ(stats.transactions_succeeded, 0);

    sol_bank_destroy(bank);
}

TEST(bank_capitalization) {
    sol_bank_t* bank = sol_bank_new(1, NULL, NULL, NULL);
    TEST_ASSERT(bank != NULL);

    uint64_t baseline = sol_bank_capitalization(bank);

    sol_pubkey_t pubkey1, pubkey2;
    memset(pubkey1.bytes, 0xF1, 32);
    memset(pubkey2.bytes, 0xF2, 32);

    sol_account_t* acc1 = sol_account_new(1000000, 0, NULL);
    sol_account_t* acc2 = sol_account_new(2000000, 0, NULL);

    sol_bank_store_account(bank, &pubkey1, acc1);
    sol_bank_store_account(bank, &pubkey2, acc2);

    TEST_ASSERT_EQ(sol_bank_capitalization(bank), baseline + 3000000);

    sol_account_destroy(acc1);
    sol_account_destroy(acc2);
    sol_bank_destroy(bank);
}

TEST(bank_transaction_rollback) {
    sol_hash_t parent_hash;
    memset(parent_hash.bytes, 0x11, sizeof(parent_hash.bytes));

    sol_bank_t* bank = sol_bank_new(1, &parent_hash, NULL, NULL);
    TEST_ASSERT_NOT_NULL(bank);

    /* Fee payer keypair */
    uint8_t seed[SOL_ED25519_SEED_SIZE];
    memset(seed, 0x22, sizeof(seed));

    sol_keypair_t payer_kp;
    sol_ed25519_keypair_from_seed(seed, &payer_kp);

    sol_pubkey_t payer;
    sol_ed25519_pubkey_from_keypair(&payer_kp, &payer);

    sol_pubkey_t to1;
    sol_pubkey_t to2;
    memset(to1.bytes, 0x33, sizeof(to1.bytes));
    memset(to2.bytes, 0x44, sizeof(to2.bytes));

    uint64_t fee = sol_bank_lamports_per_signature(bank);
    uint64_t initial_lamports = fee + 5;

    sol_account_t* payer_account = sol_account_new(initial_lamports, 0, &SOL_SYSTEM_PROGRAM_ID);
    TEST_ASSERT_NOT_NULL(payer_account);
    sol_err_t err = sol_bank_store_account(bank, &payer, payer_account);
    TEST_ASSERT_EQ(err, SOL_OK);
    sol_account_destroy(payer_account);

    /* Build a 2-instruction transfer tx: first succeeds, second fails. */
    sol_pubkey_t account_keys[4] = { payer, to1, to2, SOL_SYSTEM_PROGRAM_ID };

    uint8_t ix0_accounts[2] = {0, 1};
    uint8_t ix1_accounts[2] = {0, 2};

    uint8_t ix0_data[12];
    uint8_t ix1_data[12];
    uint32_t instr = SOL_SYSTEM_INSTR_TRANSFER;
    uint64_t lamports0 = 3;
    uint64_t lamports1 = 3;
    memcpy(ix0_data, &instr, 4);
    memcpy(ix0_data + 4, &lamports0, 8);
    memcpy(ix1_data, &instr, 4);
    memcpy(ix1_data + 4, &lamports1, 8);

    sol_compiled_instruction_t instructions[2] = {0};
    instructions[0].program_id_index = 3;
    instructions[0].account_indices = ix0_accounts;
    instructions[0].account_indices_len = (uint8_t)sizeof(ix0_accounts);
    instructions[0].data = ix0_data;
    instructions[0].data_len = (uint16_t)sizeof(ix0_data);

    instructions[1].program_id_index = 3;
    instructions[1].account_indices = ix1_accounts;
    instructions[1].account_indices_len = (uint8_t)sizeof(ix1_accounts);
    instructions[1].data = ix1_data;
    instructions[1].data_len = (uint16_t)sizeof(ix1_data);

    sol_message_t msg;
    sol_message_init(&msg);
    msg.version = SOL_MESSAGE_VERSION_LEGACY;
    msg.header.num_required_signatures = 1;
    msg.header.num_readonly_signed = 0;
    msg.header.num_readonly_unsigned = 1;
    msg.account_keys = account_keys;
    msg.account_keys_len = (uint8_t)sizeof(account_keys) / sizeof(account_keys[0]);
    msg.resolved_accounts = msg.account_keys;
    msg.resolved_accounts_len = msg.account_keys_len;
    msg.recent_blockhash = parent_hash;
    msg.instructions = instructions;
    msg.instructions_len = (uint8_t)sizeof(instructions) / sizeof(instructions[0]);

    uint8_t message_buf[256];
    sol_encoder_t enc;
    sol_encoder_init(&enc, message_buf, sizeof(message_buf));
    err = sol_message_encode_legacy(&enc, &msg);
    TEST_ASSERT_EQ(err, SOL_OK);
    size_t message_len = sol_encoder_len(&enc);

    sol_signature_t sig;
    sol_ed25519_sign(&payer_kp, message_buf, message_len, &sig);

    sol_transaction_t tx;
    sol_transaction_init(&tx);
    tx.signatures = &sig;
    tx.signatures_len = 1;
    tx.message = msg;
    tx.message_data = message_buf;
    tx.message_data_len = message_len;

    TEST_ASSERT(sol_transaction_verify_signatures(&tx, NULL));

    sol_tx_result_t result = sol_bank_process_transaction(bank, &tx);
    TEST_ASSERT_EQ(result.fee, fee);
    TEST_ASSERT_EQ(result.status, SOL_ERR_TX_INSUFFICIENT_FUNDS);

    sol_account_t* loaded_payer = sol_bank_load_account(bank, &payer);
    TEST_ASSERT_NOT_NULL(loaded_payer);
    TEST_ASSERT_EQ(loaded_payer->meta.lamports, initial_lamports - fee);
    sol_account_destroy(loaded_payer);

    /* Both transfers should be rolled back (recipients not created). */
    sol_account_t* loaded_to1 = sol_bank_load_account(bank, &to1);
    TEST_ASSERT(loaded_to1 == NULL);
    sol_account_destroy(loaded_to1);

    sol_account_t* loaded_to2 = sol_bank_load_account(bank, &to2);
    TEST_ASSERT(loaded_to2 == NULL);
    sol_account_destroy(loaded_to2);

    sol_bank_destroy(bank);
}

TEST(bank_transaction_rollback_overlay_clears_overrides) {
    sol_hash_t parent_hash;
    memset(parent_hash.bytes, 0x11, sizeof(parent_hash.bytes));

    sol_bank_t* parent = sol_bank_new(0, &parent_hash, NULL, NULL);
    TEST_ASSERT_NOT_NULL(parent);

    sol_bank_t* bank = sol_bank_new_from_parent(parent, 1);
    TEST_ASSERT_NOT_NULL(bank);

    /* Fee payer keypair */
    uint8_t seed[SOL_ED25519_SEED_SIZE];
    memset(seed, 0x22, sizeof(seed));

    sol_keypair_t payer_kp;
    sol_ed25519_keypair_from_seed(seed, &payer_kp);

    sol_pubkey_t payer;
    sol_ed25519_pubkey_from_keypair(&payer_kp, &payer);

    sol_pubkey_t to1;
    sol_pubkey_t to2;
    memset(to1.bytes, 0x33, sizeof(to1.bytes));
    memset(to2.bytes, 0x44, sizeof(to2.bytes));

    uint64_t fee = sol_bank_lamports_per_signature(bank);
    uint64_t initial_lamports = fee + 5;

    sol_account_t* payer_account =
        sol_account_new(initial_lamports, 0, &SOL_SYSTEM_PROGRAM_ID);
    TEST_ASSERT_NOT_NULL(payer_account);
    sol_err_t err = sol_bank_store_account(bank, &payer, payer_account);
    TEST_ASSERT_EQ(err, SOL_OK);
    sol_account_destroy(payer_account);

    /* Build a 2-instruction transfer tx: first succeeds, second fails. */
    sol_pubkey_t account_keys[4] = { payer, to1, to2, SOL_SYSTEM_PROGRAM_ID };

    uint8_t ix0_accounts[2] = {0, 1};
    uint8_t ix1_accounts[2] = {0, 2};

    uint8_t ix0_data[12];
    uint8_t ix1_data[12];
    uint32_t instr = SOL_SYSTEM_INSTR_TRANSFER;
    uint64_t lamports0 = 3;
    uint64_t lamports1 = 3;
    memcpy(ix0_data, &instr, 4);
    memcpy(ix0_data + 4, &lamports0, 8);
    memcpy(ix1_data, &instr, 4);
    memcpy(ix1_data + 4, &lamports1, 8);

    sol_compiled_instruction_t instructions[2] = {0};
    instructions[0].program_id_index = 3;
    instructions[0].account_indices = ix0_accounts;
    instructions[0].account_indices_len = (uint8_t)sizeof(ix0_accounts);
    instructions[0].data = ix0_data;
    instructions[0].data_len = (uint16_t)sizeof(ix0_data);

    instructions[1].program_id_index = 3;
    instructions[1].account_indices = ix1_accounts;
    instructions[1].account_indices_len = (uint8_t)sizeof(ix1_accounts);
    instructions[1].data = ix1_data;
    instructions[1].data_len = (uint16_t)sizeof(ix1_data);

    sol_message_t msg;
    sol_message_init(&msg);
    msg.version = SOL_MESSAGE_VERSION_LEGACY;
    msg.header.num_required_signatures = 1;
    msg.header.num_readonly_signed = 0;
    msg.header.num_readonly_unsigned = 1;
    msg.account_keys = account_keys;
    msg.account_keys_len = (uint8_t)sizeof(account_keys) / sizeof(account_keys[0]);
    msg.resolved_accounts = msg.account_keys;
    msg.resolved_accounts_len = msg.account_keys_len;
    msg.recent_blockhash = parent_hash;
    msg.instructions = instructions;
    msg.instructions_len = (uint8_t)sizeof(instructions) / sizeof(instructions[0]);

    uint8_t message_buf[256];
    sol_encoder_t enc;
    sol_encoder_init(&enc, message_buf, sizeof(message_buf));
    err = sol_message_encode_legacy(&enc, &msg);
    TEST_ASSERT_EQ(err, SOL_OK);
    size_t message_len = sol_encoder_len(&enc);

    sol_signature_t sig;
    sol_ed25519_sign(&payer_kp, message_buf, message_len, &sig);

    sol_transaction_t tx;
    sol_transaction_init(&tx);
    tx.signatures = &sig;
    tx.signatures_len = 1;
    tx.message = msg;
    tx.message_data = message_buf;
    tx.message_data_len = message_len;

    sol_tx_result_t result = sol_bank_process_transaction(bank, &tx);
    TEST_ASSERT_EQ(result.fee, fee);
    TEST_ASSERT_EQ(result.status, SOL_ERR_TX_INSUFFICIENT_FUNDS);

    /* Both transfers should be rolled back (recipients not created). */
    sol_account_t* loaded_to1 = sol_bank_load_account(bank, &to1);
    TEST_ASSERT(loaded_to1 == NULL);
    sol_account_destroy(loaded_to1);

    sol_account_t* loaded_to2 = sol_bank_load_account(bank, &to2);
    TEST_ASSERT(loaded_to2 == NULL);
    sol_account_destroy(loaded_to2);

    /* In an overlay bank, rollback should clear local overrides rather than
     * leaving tombstones behind. */
    sol_accounts_db_t* db = sol_bank_get_accounts_db(bank);
    TEST_ASSERT_NOT_NULL(db);

    sol_account_t* local = NULL;
    sol_accounts_db_local_kind_t kind =
        sol_accounts_db_get_local_kind(db, &to1, &local);
    TEST_ASSERT_EQ(kind, SOL_ACCOUNTS_DB_LOCAL_MISSING);
    TEST_ASSERT(local == NULL);

    kind = sol_accounts_db_get_local_kind(db, &to2, &local);
    TEST_ASSERT_EQ(kind, SOL_ACCOUNTS_DB_LOCAL_MISSING);
    TEST_ASSERT(local == NULL);

    sol_bank_destroy(bank);
    sol_bank_destroy(parent);
}

TEST(bank_process_decoded_transaction) {
    sol_hash_t parent_hash;
    memset(parent_hash.bytes, 0x55, sizeof(parent_hash.bytes));

    sol_bank_t* bank = sol_bank_new(1, &parent_hash, NULL, NULL);
    TEST_ASSERT_NOT_NULL(bank);

    /* Fee payer keypair */
    uint8_t seed[SOL_ED25519_SEED_SIZE];
    memset(seed, 0x66, sizeof(seed));

    sol_keypair_t payer_kp;
    sol_ed25519_keypair_from_seed(seed, &payer_kp);

    sol_pubkey_t payer;
    sol_ed25519_pubkey_from_keypair(&payer_kp, &payer);

    sol_pubkey_t recipient;
    memset(recipient.bytes, 0x77, sizeof(recipient.bytes));

    uint64_t fee = sol_bank_lamports_per_signature(bank);
    uint64_t transfer_lamports = 1234;
    uint64_t initial_lamports = fee + transfer_lamports + 100;

    sol_account_t* payer_account = sol_account_new(initial_lamports, 0, &SOL_SYSTEM_PROGRAM_ID);
    TEST_ASSERT_NOT_NULL(payer_account);
    sol_err_t err = sol_bank_store_account(bank, &payer, payer_account);
    TEST_ASSERT_EQ(err, SOL_OK);
    sol_account_destroy(payer_account);

    /* Build a legacy transfer message. */
    sol_pubkey_t account_keys[3] = { payer, recipient, SOL_SYSTEM_PROGRAM_ID };
    uint8_t ix_accounts[2] = {0, 1};

    uint8_t ix_data[12];
    uint32_t instr = SOL_SYSTEM_INSTR_TRANSFER;
    memcpy(ix_data, &instr, 4);
    memcpy(ix_data + 4, &transfer_lamports, 8);

    sol_compiled_instruction_t ix = {0};
    ix.program_id_index = 2;
    ix.account_indices = ix_accounts;
    ix.account_indices_len = (uint8_t)sizeof(ix_accounts);
    ix.data = ix_data;
    ix.data_len = (uint16_t)sizeof(ix_data);

    sol_message_t msg;
    sol_message_init(&msg);
    msg.version = SOL_MESSAGE_VERSION_LEGACY;
    msg.header.num_required_signatures = 1;
    msg.header.num_readonly_signed = 0;
    msg.header.num_readonly_unsigned = 1;
    msg.account_keys = account_keys;
    msg.account_keys_len = (uint8_t)(sizeof(account_keys) / sizeof(account_keys[0]));
    msg.resolved_accounts = msg.account_keys;
    msg.resolved_accounts_len = msg.account_keys_len;
    msg.recent_blockhash = parent_hash;
    msg.instructions = &ix;
    msg.instructions_len = 1;

    uint8_t message_buf[256];
    sol_encoder_t enc;
    sol_encoder_init(&enc, message_buf, sizeof(message_buf));
    err = sol_message_encode_legacy(&enc, &msg);
    TEST_ASSERT_EQ(err, SOL_OK);
    size_t message_len = sol_encoder_len(&enc);

    sol_signature_t sig;
    sol_ed25519_sign(&payer_kp, message_buf, message_len, &sig);

    uint8_t tx_buf[512];
    sol_encoder_init(&enc, tx_buf, sizeof(tx_buf));
    err = sol_encode_compact_u16(&enc, 1);
    TEST_ASSERT_EQ(err, SOL_OK);
    err = sol_encode_bytes(&enc, sig.bytes, sizeof(sig.bytes));
    TEST_ASSERT_EQ(err, SOL_OK);
    err = sol_encode_bytes(&enc, message_buf, message_len);
    TEST_ASSERT_EQ(err, SOL_OK);
    size_t tx_len = sol_encoder_len(&enc);

    sol_transaction_t parsed;
    err = sol_transaction_decode(tx_buf, tx_len, &parsed);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_NOT_NULL(parsed.message.instructions);
    TEST_ASSERT_EQ(parsed.message.instructions_len, 1);

    sol_tx_result_t result = sol_bank_process_transaction(bank, &parsed);
    TEST_ASSERT_EQ(result.status, SOL_OK);
    TEST_ASSERT_EQ(result.fee, fee);
    TEST_ASSERT_EQ(result.compute_units_used, 150);

    /* Duplicate should be rejected (no state changes). */
    sol_tx_result_t dup_result = sol_bank_process_transaction(bank, &parsed);
    TEST_ASSERT_EQ(dup_result.status, SOL_ERR_TX_ALREADY_PROCESSED);

    sol_account_t* loaded_payer = sol_bank_load_account(bank, &payer);
    sol_account_t* loaded_recipient = sol_bank_load_account(bank, &recipient);
    TEST_ASSERT_NOT_NULL(loaded_payer);
    TEST_ASSERT_NOT_NULL(loaded_recipient);
    TEST_ASSERT_EQ(loaded_payer->meta.lamports, initial_lamports - fee - transfer_lamports);
    TEST_ASSERT_EQ(loaded_recipient->meta.lamports, transfer_lamports);
    sol_account_destroy(loaded_payer);
    sol_account_destroy(loaded_recipient);

    sol_bank_destroy(bank);
}

TEST(bank_hash_matches_solana_formula) {
    sol_hash_t parent_blockhash;
    memset(parent_blockhash.bytes, 0xAA, sizeof(parent_blockhash.bytes));

    sol_bank_t* parent = sol_bank_new(0, &parent_blockhash, NULL, NULL);
    TEST_ASSERT_NOT_NULL(parent);

    sol_bank_t* bank = sol_bank_new_from_parent(parent, 1);
    TEST_ASSERT_NOT_NULL(bank);

    /* Fee payer keypair */
    uint8_t seed[SOL_ED25519_SEED_SIZE];
    memset(seed, 0x10, sizeof(seed));

    sol_keypair_t payer_kp;
    sol_ed25519_keypair_from_seed(seed, &payer_kp);

    sol_pubkey_t payer;
    sol_ed25519_pubkey_from_keypair(&payer_kp, &payer);

    sol_pubkey_t recipient;
    memset(recipient.bytes, 0x20, sizeof(recipient.bytes));

    uint64_t fee = sol_bank_lamports_per_signature(bank);
    uint64_t transfer_lamports = 1234;
    uint64_t initial_lamports = fee + transfer_lamports + 100;

    sol_account_t* payer_account = sol_account_new(initial_lamports, 0, &SOL_SYSTEM_PROGRAM_ID);
    TEST_ASSERT_NOT_NULL(payer_account);
    sol_err_t err = sol_bank_store_account(bank, &payer, payer_account);
    TEST_ASSERT_EQ(err, SOL_OK);
    sol_account_destroy(payer_account);

    /* Build a legacy transfer transaction. */
    sol_pubkey_t account_keys[3] = { payer, recipient, SOL_SYSTEM_PROGRAM_ID };
    uint8_t ix_accounts[2] = {0, 1};

    uint8_t ix_data[12];
    uint32_t instr = SOL_SYSTEM_INSTR_TRANSFER;
    memcpy(ix_data, &instr, 4);
    memcpy(ix_data + 4, &transfer_lamports, 8);

    sol_compiled_instruction_t ix = {0};
    ix.program_id_index = 2;
    ix.account_indices = ix_accounts;
    ix.account_indices_len = (uint8_t)sizeof(ix_accounts);
    ix.data = ix_data;
    ix.data_len = (uint16_t)sizeof(ix_data);

    sol_message_t msg;
    sol_message_init(&msg);
    msg.version = SOL_MESSAGE_VERSION_LEGACY;
    msg.header.num_required_signatures = 1;
    msg.header.num_readonly_signed = 0;
    msg.header.num_readonly_unsigned = 1;
    msg.account_keys = account_keys;
    msg.account_keys_len = (uint8_t)(sizeof(account_keys) / sizeof(account_keys[0]));
    msg.resolved_accounts = msg.account_keys;
    msg.resolved_accounts_len = msg.account_keys_len;
    msg.recent_blockhash = parent_blockhash;
    msg.instructions = &ix;
    msg.instructions_len = 1;

    uint8_t message_buf[256];
    sol_encoder_t enc;
    sol_encoder_init(&enc, message_buf, sizeof(message_buf));
    err = sol_message_encode_legacy(&enc, &msg);
    TEST_ASSERT_EQ(err, SOL_OK);
    size_t message_len = sol_encoder_len(&enc);

    sol_signature_t sig;
    sol_ed25519_sign(&payer_kp, message_buf, message_len, &sig);

    sol_transaction_t tx;
    sol_transaction_init(&tx);
    tx.signatures = &sig;
    tx.signatures_len = 1;
    tx.message = msg;
    tx.message_data = message_buf;
    tx.message_data_len = message_len;

    sol_tx_result_t result = sol_bank_process_transaction(bank, &tx);
    TEST_ASSERT_EQ(result.status, SOL_OK);

    /* Advance PoH hash to a deterministic value. */
    sol_hash_t last_blockhash;
    memset(last_blockhash.bytes, 0xBB, sizeof(last_blockhash.bytes));
    TEST_ASSERT_EQ(sol_bank_register_tick(bank, &last_blockhash), SOL_OK);

    sol_bank_freeze(bank);

    sol_hash_t computed = {0};
    sol_bank_compute_hash(bank, &computed);

    sol_hash_t accounts_delta_hash = {0};
    sol_accounts_db_hash_delta(sol_bank_get_accounts_db(bank), &accounts_delta_hash);

    const sol_hash_t* parent_bank_hash = sol_bank_parent_hash(bank);
    TEST_ASSERT_NOT_NULL(parent_bank_hash);

    uint8_t sig_count_le[8];
    sol_store_u64_le(sig_count_le, 1);

    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    sol_sha256_update(&ctx, parent_bank_hash->bytes, SOL_HASH_SIZE);
    sol_sha256_update(&ctx, accounts_delta_hash.bytes, SOL_HASH_SIZE);
    sol_sha256_update(&ctx, sig_count_le, sizeof(sig_count_le));
    sol_sha256_update(&ctx, last_blockhash.bytes, SOL_HASH_SIZE);
    sol_hash_t expected = {0};
    sol_sha256_final_bytes(&ctx, expected.bytes);

    TEST_ASSERT(sol_hash_eq(&computed, &expected));

    sol_bank_destroy(bank);
    sol_bank_destroy(parent);
}

TEST(bank_hash_signature_count_resets_in_child_bank) {
    sol_hash_t parent_blockhash;
    memset(parent_blockhash.bytes, 0xAA, sizeof(parent_blockhash.bytes));

    sol_bank_t* parent = sol_bank_new(0, &parent_blockhash, NULL, NULL);
    TEST_ASSERT_NOT_NULL(parent);

    /* Fee payer keypair */
    uint8_t seed[SOL_ED25519_SEED_SIZE];
    memset(seed, 0x10, sizeof(seed));

    sol_keypair_t payer_kp;
    sol_ed25519_keypair_from_seed(seed, &payer_kp);

    sol_pubkey_t payer;
    sol_ed25519_pubkey_from_keypair(&payer_kp, &payer);

    sol_pubkey_t recipient;
    memset(recipient.bytes, 0x20, sizeof(recipient.bytes));

    uint64_t fee = sol_bank_lamports_per_signature(parent);
    uint64_t transfer1 = 1234;
    uint64_t transfer2 = 5678;
    uint64_t initial_lamports = (fee * 2) + transfer1 + transfer2 + 100;

    sol_account_t* payer_account = sol_account_new(initial_lamports, 0, &SOL_SYSTEM_PROGRAM_ID);
    TEST_ASSERT_NOT_NULL(payer_account);
    sol_err_t err = sol_bank_store_account(parent, &payer, payer_account);
    TEST_ASSERT_EQ(err, SOL_OK);
    sol_account_destroy(payer_account);

    /* Shared instruction fields. */
    sol_pubkey_t account_keys[3] = { payer, recipient, SOL_SYSTEM_PROGRAM_ID };
    uint8_t ix_accounts[2] = {0, 1};

    sol_compiled_instruction_t ix = {0};
    ix.program_id_index = 2;
    ix.account_indices = ix_accounts;
    ix.account_indices_len = (uint8_t)sizeof(ix_accounts);

    /* Parent tx: transfer1 */
    uint8_t ix_data1[12];
    uint32_t instr = SOL_SYSTEM_INSTR_TRANSFER;
    memcpy(ix_data1, &instr, 4);
    memcpy(ix_data1 + 4, &transfer1, 8);
    ix.data = ix_data1;
    ix.data_len = (uint16_t)sizeof(ix_data1);

    sol_message_t msg1;
    sol_message_init(&msg1);
    msg1.version = SOL_MESSAGE_VERSION_LEGACY;
    msg1.header.num_required_signatures = 1;
    msg1.header.num_readonly_signed = 0;
    msg1.header.num_readonly_unsigned = 1;
    msg1.account_keys = account_keys;
    msg1.account_keys_len = (uint8_t)(sizeof(account_keys) / sizeof(account_keys[0]));
    msg1.resolved_accounts = msg1.account_keys;
    msg1.resolved_accounts_len = msg1.account_keys_len;
    msg1.recent_blockhash = parent_blockhash;
    msg1.instructions = &ix;
    msg1.instructions_len = 1;

    uint8_t message_buf1[256];
    sol_encoder_t enc;
    sol_encoder_init(&enc, message_buf1, sizeof(message_buf1));
    err = sol_message_encode_legacy(&enc, &msg1);
    TEST_ASSERT_EQ(err, SOL_OK);
    size_t message_len1 = sol_encoder_len(&enc);

    sol_signature_t sig1;
    sol_ed25519_sign(&payer_kp, message_buf1, message_len1, &sig1);

    sol_transaction_t tx1;
    sol_transaction_init(&tx1);
    tx1.signatures = &sig1;
    tx1.signatures_len = 1;
    tx1.message = msg1;
    tx1.message_data = message_buf1;
    tx1.message_data_len = message_len1;

    sol_tx_result_t r1 = sol_bank_process_transaction(parent, &tx1);
    TEST_ASSERT_EQ(r1.status, SOL_OK);
    TEST_ASSERT_EQ(sol_bank_signature_count(parent), 1);

    /* Child tx: transfer2 */
    sol_bank_t* bank = sol_bank_new_from_parent(parent, 1);
    TEST_ASSERT_NOT_NULL(bank);
    TEST_ASSERT_EQ(sol_bank_signature_count(bank), 0);

    uint8_t ix_data2[12];
    memcpy(ix_data2, &instr, 4);
    memcpy(ix_data2 + 4, &transfer2, 8);
    ix.data = ix_data2;
    ix.data_len = (uint16_t)sizeof(ix_data2);

    sol_message_t msg2 = msg1;
    msg2.instructions = &ix;

    uint8_t message_buf2[256];
    sol_encoder_init(&enc, message_buf2, sizeof(message_buf2));
    err = sol_message_encode_legacy(&enc, &msg2);
    TEST_ASSERT_EQ(err, SOL_OK);
    size_t message_len2 = sol_encoder_len(&enc);

    sol_signature_t sig2;
    sol_ed25519_sign(&payer_kp, message_buf2, message_len2, &sig2);

    sol_transaction_t tx2;
    sol_transaction_init(&tx2);
    tx2.signatures = &sig2;
    tx2.signatures_len = 1;
    tx2.message = msg2;
    tx2.message_data = message_buf2;
    tx2.message_data_len = message_len2;

    sol_tx_result_t r2 = sol_bank_process_transaction(bank, &tx2);
    TEST_ASSERT_EQ(r2.status, SOL_OK);
    TEST_ASSERT_EQ(sol_bank_signature_count(bank), 1);

    sol_hash_t last_blockhash;
    memset(last_blockhash.bytes, 0xBB, sizeof(last_blockhash.bytes));
    TEST_ASSERT_EQ(sol_bank_register_tick(bank, &last_blockhash), SOL_OK);

    sol_bank_freeze(bank);

    sol_hash_t computed = {0};
    sol_bank_compute_hash(bank, &computed);

    sol_hash_t accounts_delta_hash = {0};
    sol_accounts_db_hash_delta(sol_bank_get_accounts_db(bank), &accounts_delta_hash);

    const sol_hash_t* parent_bank_hash = sol_bank_parent_hash(bank);
    TEST_ASSERT_NOT_NULL(parent_bank_hash);

    /* Signature count is per-bank (slot-local). */
    uint8_t sig_count_le[8];
    sol_store_u64_le(sig_count_le, 1);

    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    sol_sha256_update(&ctx, parent_bank_hash->bytes, SOL_HASH_SIZE);
    sol_sha256_update(&ctx, accounts_delta_hash.bytes, SOL_HASH_SIZE);
    sol_sha256_update(&ctx, sig_count_le, sizeof(sig_count_le));
    sol_sha256_update(&ctx, last_blockhash.bytes, SOL_HASH_SIZE);
    sol_hash_t expected = {0};
    sol_sha256_final_bytes(&ctx, expected.bytes);

    TEST_ASSERT(sol_hash_eq(&computed, &expected));

    sol_bank_destroy(bank);
    sol_bank_destroy(parent);
}

TEST(bank_hash_ignores_obsolete_epoch_accounts_hash) {
    sol_bank_config_t cfg = SOL_BANK_CONFIG_DEFAULT;
    cfg.slots_per_epoch = 100;

    sol_hash_t parent_blockhash;
    memset(parent_blockhash.bytes, 0xAA, sizeof(parent_blockhash.bytes));

    /* Create a parent bank right before the epoch stop-slot boundary. */
    sol_bank_t* parent = sol_bank_new(74, &parent_blockhash, NULL, &cfg);
    TEST_ASSERT_NOT_NULL(parent);

    sol_bank_t* bank = sol_bank_new_from_parent(parent, 75);
    TEST_ASSERT_NOT_NULL(bank);

    sol_hash_t epoch_accounts_hash;
    memset(epoch_accounts_hash.bytes, 0xEE, sizeof(epoch_accounts_hash.bytes));
    TEST_ASSERT_EQ(sol_accounts_db_set_epoch_accounts_hash(
                       sol_bank_get_accounts_db(parent),
                       sol_bank_epoch(parent),
                       &epoch_accounts_hash),
                   SOL_OK);

    /* Fee payer keypair */
    uint8_t seed[SOL_ED25519_SEED_SIZE];
    memset(seed, 0x10, sizeof(seed));

    sol_keypair_t payer_kp;
    sol_ed25519_keypair_from_seed(seed, &payer_kp);

    sol_pubkey_t payer;
    sol_ed25519_pubkey_from_keypair(&payer_kp, &payer);

    sol_pubkey_t recipient;
    memset(recipient.bytes, 0x20, sizeof(recipient.bytes));

    uint64_t fee = sol_bank_lamports_per_signature(bank);
    uint64_t transfer_lamports = 1234;
    uint64_t initial_lamports = fee + transfer_lamports + 100;

    sol_account_t* payer_account = sol_account_new(initial_lamports, 0, &SOL_SYSTEM_PROGRAM_ID);
    TEST_ASSERT_NOT_NULL(payer_account);
    sol_err_t err = sol_bank_store_account(bank, &payer, payer_account);
    TEST_ASSERT_EQ(err, SOL_OK);
    sol_account_destroy(payer_account);

    /* Build a legacy transfer transaction. */
    sol_pubkey_t account_keys[3] = { payer, recipient, SOL_SYSTEM_PROGRAM_ID };
    uint8_t ix_accounts[2] = {0, 1};

    uint8_t ix_data[12];
    uint32_t instr = SOL_SYSTEM_INSTR_TRANSFER;
    memcpy(ix_data, &instr, 4);
    memcpy(ix_data + 4, &transfer_lamports, 8);

    sol_compiled_instruction_t ix = {0};
    ix.program_id_index = 2;
    ix.account_indices = ix_accounts;
    ix.account_indices_len = (uint8_t)sizeof(ix_accounts);
    ix.data = ix_data;
    ix.data_len = (uint16_t)sizeof(ix_data);

    sol_message_t msg;
    sol_message_init(&msg);
    msg.version = SOL_MESSAGE_VERSION_LEGACY;
    msg.header.num_required_signatures = 1;
    msg.header.num_readonly_signed = 0;
    msg.header.num_readonly_unsigned = 1;
    msg.account_keys = account_keys;
    msg.account_keys_len = (uint8_t)(sizeof(account_keys) / sizeof(account_keys[0]));
    msg.resolved_accounts = msg.account_keys;
    msg.resolved_accounts_len = msg.account_keys_len;
    msg.recent_blockhash = parent_blockhash;
    msg.instructions = &ix;
    msg.instructions_len = 1;

    uint8_t message_buf[256];
    sol_encoder_t enc;
    sol_encoder_init(&enc, message_buf, sizeof(message_buf));
    err = sol_message_encode_legacy(&enc, &msg);
    TEST_ASSERT_EQ(err, SOL_OK);
    size_t message_len = sol_encoder_len(&enc);

    sol_signature_t sig;
    sol_ed25519_sign(&payer_kp, message_buf, message_len, &sig);

    sol_transaction_t tx;
    sol_transaction_init(&tx);
    tx.signatures = &sig;
    tx.signatures_len = 1;
    tx.message = msg;
    tx.message_data = message_buf;
    tx.message_data_len = message_len;

    sol_tx_result_t result = sol_bank_process_transaction(bank, &tx);
    TEST_ASSERT_EQ(result.status, SOL_OK);

    /* Advance PoH hash to a deterministic value. */
    sol_hash_t last_blockhash;
    memset(last_blockhash.bytes, 0xBB, sizeof(last_blockhash.bytes));
    TEST_ASSERT_EQ(sol_bank_register_tick(bank, &last_blockhash), SOL_OK);

    sol_bank_freeze(bank);

    sol_hash_t computed = {0};
    sol_bank_compute_hash(bank, &computed);

    sol_hash_t accounts_delta_hash = {0};
    sol_accounts_db_hash_delta(sol_bank_get_accounts_db(bank), &accounts_delta_hash);

    const sol_hash_t* parent_bank_hash = sol_bank_parent_hash(bank);
    TEST_ASSERT_NOT_NULL(parent_bank_hash);

    uint8_t sig_count_le[8];
    sol_store_u64_le(sig_count_le, 1);

    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    sol_sha256_update(&ctx, parent_bank_hash->bytes, SOL_HASH_SIZE);
    sol_sha256_update(&ctx, accounts_delta_hash.bytes, SOL_HASH_SIZE);
    sol_sha256_update(&ctx, sig_count_le, sizeof(sig_count_le));
    sol_sha256_update(&ctx, last_blockhash.bytes, SOL_HASH_SIZE);
    sol_hash_t expected = {0};
    sol_sha256_final_bytes(&ctx, expected.bytes);

    TEST_ASSERT(sol_hash_eq(&computed, &expected));

    sol_bank_destroy(bank);
    sol_bank_destroy(parent);
}

/*
 * Null handling tests
 */

TEST(runtime_null_handling) {
    sol_account_destroy(NULL);
    sol_account_cleanup(NULL);
    sol_accounts_db_destroy(NULL);
    sol_bank_destroy(NULL);

    TEST_ASSERT_EQ(sol_accounts_db_count(NULL), 0);
    TEST_ASSERT_EQ(sol_bank_slot(NULL), 0);
    TEST_ASSERT(!sol_bank_is_frozen(NULL));
}

/*
 * Test runner
 */
static test_case_t runtime_tests[] = {
    /* Account tests */
    TEST_CASE(account_new_destroy),
    TEST_CASE(account_new_no_data),
    TEST_CASE(account_clone),
    TEST_CASE(account_resize),
    TEST_CASE(account_set_data),
    TEST_CASE(account_serialize_deserialize),
    /* AccountsDB tests */
    TEST_CASE(accounts_db_create_destroy),
    TEST_CASE(accounts_db_store_load),
    TEST_CASE(accounts_db_exists),
    TEST_CASE(accounts_db_delete),
    TEST_CASE(accounts_db_total_lamports),
    TEST_CASE(accounts_db_snapshot),
#ifdef SOL_HAS_ROCKSDB
    TEST_CASE(accounts_db_bootstrap_state_roundtrip_rocksdb),
#endif
    TEST_CASE(accounts_db_hash_delta_deterministic),
    TEST_CASE(accounts_db_clear_override_restores_parent),
    /* Bank tests */
    TEST_CASE(bank_create_destroy),
    TEST_CASE(bank_from_parent),
    TEST_CASE(bank_store_load_account),
    TEST_CASE(bank_initializes_sysvar_accounts),
    TEST_CASE(bank_clock_timestamp_from_snapshot_sysvar),
    TEST_CASE(bank_clock_timestamp_stake_weighted_median),
    TEST_CASE(bank_sysvar_meta_preserved_on_refresh),
    TEST_CASE(bank_calculate_fee),
    TEST_CASE(bank_calculate_fee_uses_blockhash_fee_calculator),
    TEST_CASE(bank_calculate_fee_counts_precompile_signatures),
    TEST_CASE(bank_process_transaction_charges_precompile_signature_fee),
    TEST_CASE(bank_process_v0_transaction_with_alt_writable_account),
    TEST_CASE(bank_resolve_v0_transaction_accounts_alt_loaded_order),
    TEST_CASE(bank_freeze),
    TEST_CASE(bank_register_tick),
    TEST_CASE(bank_fee_distribution_credits_collector),
    TEST_CASE(bank_priority_fee_not_burned),
    TEST_CASE(bank_stats),
    TEST_CASE(bank_capitalization),
    TEST_CASE(bank_transaction_rollback),
    TEST_CASE(bank_transaction_rollback_overlay_clears_overrides),
    TEST_CASE(bank_process_decoded_transaction),
    TEST_CASE(bank_hash_matches_solana_formula),
    TEST_CASE(bank_hash_signature_count_resets_in_child_bank),
    TEST_CASE(bank_hash_ignores_obsolete_epoch_accounts_hash),
    /* Null handling */
    TEST_CASE(runtime_null_handling),
};

int main(void) {
    int result = RUN_TESTS("Runtime Tests", runtime_tests);
    sol_alloc_dump_leaks();
    return result;
}
