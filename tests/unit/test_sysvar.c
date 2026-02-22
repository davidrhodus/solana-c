/*
 * test_sysvar.c - Tests for Sysvar Accounts
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../../src/runtime/sol_bank.h"
#include "../../src/runtime/sol_accounts_db.h"
#include "../../src/runtime/sol_sysvar.h"
#include "../../src/runtime/sol_accounts_hash.h"
#include "../../src/runtime/sol_rewards.h"
#include "../../src/util/sol_alloc.h"
#include "../../src/programs/sol_stake_program.h"

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
 * Test sysvar IDs
 */
TEST(sysvar_ids) {
    ASSERT(sol_is_sysvar(&SOL_SYSVAR_CLOCK_ID));
    ASSERT(sol_is_sysvar(&SOL_SYSVAR_RENT_ID));
    ASSERT(sol_is_sysvar(&SOL_SYSVAR_EPOCH_SCHEDULE_ID));
    ASSERT(sol_is_sysvar(&SOL_SYSVAR_FEES_ID));
    ASSERT(sol_is_sysvar(&SOL_SYSVAR_SLOT_HASHES_ID));
    ASSERT(sol_is_sysvar(&SOL_SYSVAR_STAKE_HISTORY_ID));

    /* Non-sysvar should return false */
    sol_pubkey_t random = {0};
    random.bytes[0] = 1;
    ASSERT(!sol_is_sysvar(&random));
}

/*
 * Test sysvar names
 */
TEST(sysvar_names) {
    ASSERT(strcmp(sol_sysvar_name(&SOL_SYSVAR_CLOCK_ID), "Clock") == 0);
    ASSERT(strcmp(sol_sysvar_name(&SOL_SYSVAR_RENT_ID), "Rent") == 0);
    ASSERT(strcmp(sol_sysvar_name(&SOL_SYSVAR_EPOCH_SCHEDULE_ID), "EpochSchedule") == 0);
    ASSERT(strcmp(sol_sysvar_name(&SOL_SYSVAR_FEES_ID), "Fees") == 0);
}

/*
 * Bank hashing depends on the exact set of accounts written during a slot.
 * Rewriting unchanged sysvar accounts (Rent/EpochSchedule/etc.) would cause
 * accounts delta hash (and therefore bank hash) divergence vs Solana.
 */
TEST(sysvar_no_unnecessary_rewrites) {
    sol_hash_t genesis = {0};
    sol_bank_config_t cfg = SOL_BANK_CONFIG_DEFAULT;

    sol_bank_t* parent = sol_bank_new(0, &genesis, NULL, &cfg);
    ASSERT(parent != NULL);
    sol_bank_freeze(parent);

    sol_bank_t* child = sol_bank_new_from_parent(parent, 1);
    ASSERT(child != NULL);

    sol_accounts_db_t* child_db = sol_bank_get_accounts_db(child);
    ASSERT(child_db != NULL);
    ASSERT(sol_accounts_db_is_overlay(child_db));

    sol_account_t* acct = NULL;
    sol_accounts_db_local_kind_t kind;

    kind = sol_accounts_db_get_local_kind(child_db, &SOL_SYSVAR_CLOCK_ID, &acct);
    ASSERT(kind == SOL_ACCOUNTS_DB_LOCAL_ACCOUNT);
    if (acct) sol_account_destroy(acct);

    kind = sol_accounts_db_get_local_kind(child_db, &SOL_SYSVAR_SLOT_HASHES_ID, &acct);
    ASSERT(kind == SOL_ACCOUNTS_DB_LOCAL_ACCOUNT);
    if (acct) sol_account_destroy(acct);

    kind = sol_accounts_db_get_local_kind(child_db, &SOL_SYSVAR_RENT_ID, &acct);
    ASSERT(kind == SOL_ACCOUNTS_DB_LOCAL_MISSING);
    ASSERT(acct == NULL);

    kind = sol_accounts_db_get_local_kind(child_db, &SOL_SYSVAR_EPOCH_SCHEDULE_ID, &acct);
    ASSERT(kind == SOL_ACCOUNTS_DB_LOCAL_MISSING);
    ASSERT(acct == NULL);

    kind = sol_accounts_db_get_local_kind(child_db, &SOL_SYSVAR_FEES_ID, &acct);
    ASSERT(kind == SOL_ACCOUNTS_DB_LOCAL_MISSING);
    ASSERT(acct == NULL);

    kind = sol_accounts_db_get_local_kind(child_db, &SOL_SYSVAR_RECENT_BLOCKHASHES_ID, &acct);
    ASSERT(kind == SOL_ACCOUNTS_DB_LOCAL_MISSING);
    ASSERT(acct == NULL);

    kind = sol_accounts_db_get_local_kind(child_db, &SOL_SYSVAR_INSTRUCTIONS_ID, &acct);
    ASSERT(kind == SOL_ACCOUNTS_DB_LOCAL_MISSING);
    ASSERT(acct == NULL);

    sol_bank_destroy(child);
    sol_bank_destroy(parent);
}

/*
 * Test clock sysvar
 */
TEST(clock_sysvar) {
    sol_clock_t clock;
    sol_clock_init(&clock);

    ASSERT(clock.slot == 0);
    ASSERT(clock.epoch == 0);
    ASSERT(clock.unix_timestamp == 0);

    clock.slot = 12345;
    clock.epoch = 100;
    clock.unix_timestamp = 1609459200;
    clock.epoch_start_timestamp = 1609455600;
    clock.leader_schedule_epoch = 101;

    /* Serialize */
    uint8_t data[SOL_CLOCK_SIZE];
    sol_err_t err = sol_clock_serialize(&clock, data, sizeof(data));
    ASSERT(err == SOL_OK);

    /* Deserialize */
    sol_clock_t clock2;
    err = sol_clock_deserialize(&clock2, data, sizeof(data));
    ASSERT(err == SOL_OK);

    ASSERT(clock2.slot == 12345);
    ASSERT(clock2.epoch == 100);
    ASSERT(clock2.unix_timestamp == 1609459200);
    ASSERT(clock2.epoch_start_timestamp == 1609455600);
    ASSERT(clock2.leader_schedule_epoch == 101);
}

/*
 * Test rent sysvar
 */
TEST(rent_sysvar) {
    sol_rent_t rent;
    sol_rent_init(&rent);

    ASSERT(rent.lamports_per_byte_year == 3480);
    ASSERT(rent.exemption_threshold == 2.0);
    ASSERT(rent.burn_percent == 50);

    /* Serialize */
    uint8_t data[SOL_RENT_SIZE];
    sol_err_t err = sol_rent_serialize(&rent, data, sizeof(data));
    ASSERT(err == SOL_OK);

    /* Deserialize */
    sol_rent_t rent2;
    err = sol_rent_deserialize(&rent2, data, sizeof(data));
    ASSERT(err == SOL_OK);

    ASSERT(rent2.lamports_per_byte_year == rent.lamports_per_byte_year);
    ASSERT(rent2.exemption_threshold == rent.exemption_threshold);
    ASSERT(rent2.burn_percent == rent.burn_percent);
}

/*
 * Test rent minimum balance calculation
 */
TEST(rent_minimum_balance) {
    sol_rent_t rent;
    sol_rent_init(&rent);

    /* Account with 0 data bytes: 128 bytes overhead */
    uint64_t min = sol_rent_minimum_balance(&rent, 0);
    /* 3480 * 128 * 2.0 = 890880 */
    ASSERT(min == 890880);

    /* Account with 100 data bytes: 228 bytes total */
    min = sol_rent_minimum_balance(&rent, 100);
    /* 3480 * 228 * 2.0 = 1586880 */
    ASSERT(min == 1586880);
}

/*
 * Test epoch schedule sysvar
 */
TEST(epoch_schedule_sysvar) {
    sol_epoch_schedule_t schedule;
    sol_epoch_schedule_init(&schedule);

    ASSERT(schedule.slots_per_epoch == 432000);
    ASSERT(schedule.warmup == false);

    /* Serialize */
    uint8_t data[SOL_EPOCH_SCHEDULE_SIZE];
    sol_err_t err = sol_epoch_schedule_serialize(&schedule, data, sizeof(data));
    ASSERT(err == SOL_OK);

    /* Deserialize */
    sol_epoch_schedule_t schedule2;
    err = sol_epoch_schedule_deserialize(&schedule2, data, sizeof(data));
    ASSERT(err == SOL_OK);

    ASSERT(schedule2.slots_per_epoch == schedule.slots_per_epoch);
    ASSERT(schedule2.leader_schedule_slot_offset == schedule.leader_schedule_slot_offset);
}

/*
 * Test fees sysvar
 */
TEST(fees_sysvar) {
    sol_fees_t fees;
    sol_fees_init(&fees);

    ASSERT(fees.fee_calculator.lamports_per_signature == 5000);

    /* Serialize */
    uint8_t data[SOL_FEES_SIZE];
    sol_err_t err = sol_fees_serialize(&fees, data, sizeof(data));
    ASSERT(err == SOL_OK);

    /* Deserialize */
    sol_fees_t fees2;
    err = sol_fees_deserialize(&fees2, data, sizeof(data));
    ASSERT(err == SOL_OK);

    ASSERT(fees2.fee_calculator.lamports_per_signature == 5000);
}

/*
 * Test recent blockhashes
 */
TEST(recent_blockhashes) {
    sol_recent_blockhashes_t rbh;
    sol_recent_blockhashes_init(&rbh);
    ASSERT(rbh.len == 0);

    /* Add some blockhashes */
    sol_hash_t hash1 = {0};
    hash1.bytes[0] = 1;
    sol_err_t err = sol_recent_blockhashes_add(&rbh, &hash1, 5000);
    ASSERT(err == SOL_OK);
    ASSERT(rbh.len == 1);

    sol_hash_t hash2 = {0};
    hash2.bytes[0] = 2;
    err = sol_recent_blockhashes_add(&rbh, &hash2, 5000);
    ASSERT(err == SOL_OK);
    ASSERT(rbh.len == 2);

    /* Check contains */
    ASSERT(sol_recent_blockhashes_contains(&rbh, &hash1));
    ASSERT(sol_recent_blockhashes_contains(&rbh, &hash2));

    sol_hash_t hash3 = {0};
    hash3.bytes[0] = 3;
    ASSERT(!sol_recent_blockhashes_contains(&rbh, &hash3));
}

/*
 * Test slot hashes
 */
TEST(slot_hashes) {
    sol_slot_hashes_t sh;
    sol_slot_hashes_init(&sh);
    ASSERT(sh.len == 0);

    /* Add some slot hashes */
    sol_hash_t hash1 = {0};
    hash1.bytes[0] = 0xAA;
    sol_err_t err = sol_slot_hashes_add(&sh, 100, &hash1);
    ASSERT(err == SOL_OK);
    ASSERT(sh.len == 1);

    sol_hash_t hash2 = {0};
    hash2.bytes[0] = 0xBB;
    err = sol_slot_hashes_add(&sh, 200, &hash2);
    ASSERT(err == SOL_OK);
    ASSERT(sh.len == 2);

    /* Get slot hash */
    const sol_hash_t* found = sol_slot_hashes_get(&sh, 100);
    ASSERT(found != NULL);
    ASSERT(found->bytes[0] == 0xAA);

    found = sol_slot_hashes_get(&sh, 200);
    ASSERT(found != NULL);
    ASSERT(found->bytes[0] == 0xBB);

    found = sol_slot_hashes_get(&sh, 300);
    ASSERT(found == NULL);
}

/*
 * Test stake history
 */
TEST(stake_history) {
    sol_stake_history_t sh;
    sol_stake_history_init(&sh);
    ASSERT(sh.len == 0);

    /* Add entries */
    sol_stake_history_entry_t entry1 = { .effective = 1000, .activating = 100, .deactivating = 50 };
    sol_err_t err = sol_stake_history_add(&sh, 0, &entry1);
    ASSERT(err == SOL_OK);
    ASSERT(sh.len == 1);

    sol_stake_history_entry_t entry2 = { .effective = 2000, .activating = 200, .deactivating = 100 };
    err = sol_stake_history_add(&sh, 1, &entry2);
    ASSERT(err == SOL_OK);
    ASSERT(sh.len == 2);

    /* Get entries */
    const sol_stake_history_entry_t* found = sol_stake_history_get(&sh, 0);
    ASSERT(found != NULL);
    ASSERT(found->effective == 1000);

    found = sol_stake_history_get(&sh, 1);
    ASSERT(found != NULL);
    ASSERT(found->effective == 2000);

    found = sol_stake_history_get(&sh, 2);
    ASSERT(found == NULL);
}

TEST(stake_history_epoch_boundary_update) {
    sol_hash_t genesis = {0};
    sol_bank_config_t cfg = SOL_BANK_CONFIG_DEFAULT;
    cfg.slots_per_epoch = 2;
    cfg.ticks_per_slot = 1;

    sol_bank_t* b0 = sol_bank_new(0, &genesis, NULL, &cfg);
    ASSERT(b0 != NULL);

    sol_pubkey_t stake_pubkey = {0};
    stake_pubkey.bytes[0] = 0x11;

    sol_pubkey_t vote_pubkey = {0};
    vote_pubkey.bytes[0] = 0x22;

    sol_stake_authorized_t auth = {0};
    auth.staker.bytes[0] = 0x33;
    auth.withdrawer.bytes[0] = 0x44;

    sol_lockup_t lockup = {0};
    sol_stake_state_t state;
    sol_stake_state_init(&state, &auth, &lockup, 0);
    ASSERT(sol_stake_delegate(&state, &vote_pubkey, 5000000000ULL, 0) == SOL_OK);

    uint8_t stake_data[SOL_STAKE_STATE_SIZE];
    size_t written = 0;
    ASSERT(sol_stake_state_serialize(&state, stake_data,
                                     sizeof(stake_data), &written) == SOL_OK);
    ASSERT(written > 0);

    sol_account_t* stake_acct =
        sol_account_new(5000000000ULL, written, &SOL_STAKE_PROGRAM_ID);
    ASSERT(stake_acct != NULL);
    memcpy(stake_acct->data, stake_data, written);

    ASSERT(sol_bank_store_account(b0, &stake_pubkey, stake_acct) == SOL_OK);
    sol_account_destroy(stake_acct);

    sol_bank_freeze(b0);

    sol_bank_t* b1 = sol_bank_new_from_parent(b0, 1);
    ASSERT(b1 != NULL);
    sol_bank_freeze(b1);

    /* Slot 2 is the start of epoch 1 when slots_per_epoch=2. */
    sol_bank_t* b2 = sol_bank_new_from_parent(b1, 2);
    ASSERT(b2 != NULL);

    sol_account_t* sh_acct = sol_bank_load_account(b2, &SOL_SYSVAR_STAKE_HISTORY_ID);
    ASSERT(sh_acct != NULL);

    sol_stake_history_t sh;
    sol_stake_history_init(&sh);
    ASSERT(sol_stake_history_deserialize(&sh, sh_acct->data,
                                         sh_acct->meta.data_len) == SOL_OK);

    const sol_stake_history_entry_t* entry = sol_stake_history_get(&sh, 0);
    ASSERT(entry != NULL);
    ASSERT(entry->effective == 0);
    ASSERT(entry->activating == 5000000000ULL);
    ASSERT(entry->deactivating == 0);

    sol_account_destroy(sh_acct);

    sol_bank_destroy(b2);
    sol_bank_destroy(b1);
    sol_bank_destroy(b0);
}

/*
 * Test instructions sysvar serialization and loading
 */
TEST(instructions_sysvar) {
    sol_transaction_t tx;
    sol_transaction_init(&tx);

    sol_message_t* msg = &tx.message;
    msg->header.num_required_signatures = 1;
    msg->header.num_readonly_signed = 0;
    msg->header.num_readonly_unsigned = 1;

    sol_pubkey_t keys[4] = {0};
    keys[0].bytes[0] = 0xA0;  /* signer */
    keys[1].bytes[0] = 0xA1;
    keys[2].bytes[0] = 0xA2;  /* program 0 */
    keys[3].bytes[0] = 0xA3;  /* program 1 */

    msg->account_keys = keys;
    msg->account_keys_len = 4;
    msg->resolved_accounts = keys;
    msg->resolved_accounts_len = 4;

    uint8_t ix0_accounts[2] = {0, 1};
    uint8_t ix0_data[2] = {0xAA, 0xBB};
    uint8_t ix1_accounts[1] = {1};
    uint8_t ix1_data[3] = {0x01, 0x02, 0x03};

    sol_compiled_instruction_t instrs[2] = {0};
    instrs[0].program_id_index = 2;
    instrs[0].account_indices = ix0_accounts;
    instrs[0].account_indices_len = 2;
    instrs[0].data = ix0_data;
    instrs[0].data_len = (uint16_t)sizeof(ix0_data);

    instrs[1].program_id_index = 3;
    instrs[1].account_indices = ix1_accounts;
    instrs[1].account_indices_len = 1;
    instrs[1].data = ix1_data;
    instrs[1].data_len = (uint16_t)sizeof(ix1_data);

    msg->instructions = instrs;
    msg->instructions_len = 2;

    uint8_t buf[256] = {0};
    size_t out_len = sizeof(buf);
    sol_err_t err = sol_instructions_sysvar_serialize(&tx, 1, buf, &out_len);
    ASSERT(err == SOL_OK);

    ASSERT(sol_instructions_sysvar_get_count(buf, out_len) == 2);
    ASSERT(sol_instructions_sysvar_get_current(buf, out_len) == 1);

    /* Validate meta encoding for instruction 0 */
    uint16_t off0 = 0;
    uint16_t off1 = 0;
    memcpy(&off0, buf + 2, 2);
    memcpy(&off1, buf + 4, 2);

    /* Header size = u16 count + u16 offsets[2] + u16 current = 8 */
    ASSERT(off0 == 8);
    ASSERT(off1 > off0);

    size_t pos = off0;
    ASSERT(buf[pos++] == 2);  /* num_accounts */

    /* account 0 */
    ASSERT(buf[pos++] == 0);  /* pubkey index */
    ASSERT(buf[pos++] == 1);  /* signer */
    ASSERT(buf[pos++] == 1);  /* writable */

    /* account 1 */
    ASSERT(buf[pos++] == 1);
    ASSERT(buf[pos++] == 0);
    ASSERT(buf[pos++] == 1);  /* writable unsigned */

    /* program id */
    ASSERT(memcmp(buf + pos, keys[2].bytes, 32) == 0);

    /* Load instruction 0 */
    sol_pubkey_t prog0 = {0};
    const uint8_t* data0 = NULL;
    size_t data0_len = 0;
    err = sol_instructions_sysvar_load_instruction(buf, out_len, 0, &prog0, &data0, &data0_len);
    ASSERT(err == SOL_OK);
    ASSERT(memcmp(prog0.bytes, keys[2].bytes, 32) == 0);
    ASSERT(data0_len == sizeof(ix0_data));
    ASSERT(memcmp(data0, ix0_data, sizeof(ix0_data)) == 0);

    /* Load instruction 1 */
    sol_pubkey_t prog1 = {0};
    const uint8_t* data1 = NULL;
    size_t data1_len = 0;
    err = sol_instructions_sysvar_load_instruction(buf, out_len, 1, &prog1, &data1, &data1_len);
    ASSERT(err == SOL_OK);
    ASSERT(memcmp(prog1.bytes, keys[3].bytes, 32) == 0);
    ASSERT(data1_len == sizeof(ix1_data));
    ASSERT(memcmp(data1, ix1_data, sizeof(ix1_data)) == 0);
}

/*
 * SlotHistory sysvar (bincode/serde encoding)
 */
TEST(slot_history_bincode_layout_and_add) {
    uint8_t* data = (uint8_t*)sol_alloc(SOL_SLOT_HISTORY_SIZE);
    ASSERT(data != NULL);

    sol_err_t err = sol_slot_history_serialize_default(data, SOL_SLOT_HISTORY_SIZE);
    ASSERT(err == SOL_OK);

    /* Encoding: [u8 tag][u64 blocks_len][u64 blocks...][u64 bit_len][u64 next_slot] */
    ASSERT(data[0] == 1);

    uint64_t blocks_len = 0;
    memcpy(&blocks_len, data + 1, 8);
    ASSERT(blocks_len == (uint64_t)SOL_SLOT_HISTORY_WORDS);

    uint64_t block0 = 0;
    memcpy(&block0, data + 1 + 8, 8);
    ASSERT(block0 == 1ULL); /* bit 0 set */

    uint64_t bit_len = 0;
    size_t bit_len_off = 1 + 8 + (size_t)blocks_len * 8;
    memcpy(&bit_len, data + bit_len_off, 8);
    ASSERT(bit_len == (uint64_t)SOL_SLOT_HISTORY_MAX_ENTRIES);

    uint64_t next_slot = 0;
    memcpy(&next_slot, data + bit_len_off + 8, 8);
    ASSERT(next_slot == 1ULL);

    /* Add slot 2: sets bits 0 and 2, advances next_slot to 3. */
    err = sol_slot_history_add(data, SOL_SLOT_HISTORY_SIZE, 2);
    ASSERT(err == SOL_OK);
    memcpy(&block0, data + 1 + 8, 8);
    ASSERT(block0 == 5ULL); /* 0b101 */
    memcpy(&next_slot, data + bit_len_off + 8, 8);
    ASSERT(next_slot == 3ULL);

    /* Add an older slot: should still succeed and move next_slot backwards. */
    err = sol_slot_history_add(data, SOL_SLOT_HISTORY_SIZE, 1);
    ASSERT(err == SOL_OK);
    memcpy(&block0, data + 1 + 8, 8);
    ASSERT(block0 == 7ULL); /* 0b111 */
    memcpy(&next_slot, data + bit_len_off + 8, 8);
    ASSERT(next_slot == 2ULL);

    /* Force wrap clear (slot > next_slot and delta >= MAX_ENTRIES). */
    uint64_t wrap_slot = next_slot + (uint64_t)SOL_SLOT_HISTORY_MAX_ENTRIES + 5ULL;
    err = sol_slot_history_add(data, SOL_SLOT_HISTORY_SIZE, (sol_slot_t)wrap_slot);
    ASSERT(err == SOL_OK);

    memcpy(&block0, data + 1 + 8, 8);
    ASSERT(block0 == (1ULL << (wrap_slot % 64ULL)));

    memcpy(&next_slot, data + bit_len_off + 8, 8);
    ASSERT(next_slot == wrap_slot + 1ULL);

    sol_free(data);
}

/*
 * Test accounts hash accumulator
 */
TEST(accounts_hash_acc) {
    sol_accounts_hash_acc_t acc;
    sol_accounts_hash_acc_init(&acc);
    ASSERT(acc.count == 0);
    ASSERT(acc.lamports == 0);

    /* Add some account hashes */
    sol_hash_t hash1 = {0};
    hash1.bytes[0] = 1;
    sol_accounts_hash_acc_add(&acc, &hash1, 1000);
    ASSERT(acc.count == 1);
    ASSERT(acc.lamports == 1000);

    sol_hash_t hash2 = {0};
    hash2.bytes[0] = 2;
    sol_accounts_hash_acc_add(&acc, &hash2, 2000);
    ASSERT(acc.count == 2);
    ASSERT(acc.lamports == 3000);

    /* Finalize */
    sol_hash_t final;
    sol_accounts_hash_acc_finalize(&acc, &final);
    ASSERT(!sol_hash_is_zero(&final));
}

/*
 * Test hash combine
 */
TEST(hash_combine) {
    sol_hash_t hash1 = {0};
    hash1.bytes[0] = 1;
    sol_hash_t hash2 = {0};
    hash2.bytes[0] = 2;

    sol_hash_t combined;
    sol_accounts_hash_combine(&hash1, &hash2, &combined);
    ASSERT(!sol_hash_is_zero(&combined));

    /* Combining with zero should return the non-zero hash */
    sol_hash_t zero = {0};
    sol_hash_t result;
    sol_accounts_hash_combine(&hash1, &zero, &result);
    ASSERT(sol_hash_eq(&result, &hash1));

    sol_accounts_hash_combine(&zero, &hash2, &result);
    ASSERT(sol_hash_eq(&result, &hash2));
}

/*
 * Test bank hash compute
 */
TEST(bank_hash_compute) {
    sol_hash_t accounts_hash = {0};
    accounts_hash.bytes[0] = 0xAA;

    sol_hash_t last_blockhash = {0};
    last_blockhash.bytes[0] = 0xBB;

    sol_hash_t bank_hash;
    sol_bank_hash_compute(&accounts_hash, 100, &last_blockhash, NULL, &bank_hash);
    ASSERT(!sol_hash_is_zero(&bank_hash));
}

/*
 * Test inflation rate
 */
TEST(inflation_rate) {
    sol_inflation_t inflation = SOL_INFLATION_DEFAULT;

    /* At slot 0, should be initial rate */
    double rate = sol_inflation_rate(&inflation, 0, 78892314);
    ASSERT(rate > 0.079 && rate < 0.081);  /* ~8% */

    /* After many years, should approach terminal rate */
    rate = sol_inflation_rate(&inflation, 78892314UL * 100, 78892314);
    ASSERT(rate < 0.02);  /* Should be near 1.5% terminal */
}

/*
 * Test rewards calculation
 */
TEST(rewards_calc) {
    sol_rewards_calc_t* calc = sol_rewards_calc_new(NULL);
    ASSERT(calc != NULL);

    /* Add a validator */
    sol_pubkey_t vote_pubkey = {0};
    vote_pubkey.bytes[0] = 1;
    sol_pubkey_t node_pubkey = {0};
    node_pubkey.bytes[0] = 2;
    sol_err_t err = sol_rewards_calc_add_vote(calc, &vote_pubkey, &node_pubkey, 10, 1000, 0);
    ASSERT(err == SOL_OK);

    /* Add a staker */
    sol_pubkey_t stake_pubkey = {0};
    stake_pubkey.bytes[0] = 3;
    err = sol_rewards_calc_add_stake(calc, &stake_pubkey, &vote_pubkey, 1000000);
    ASSERT(err == SOL_OK);

    /* Compute rewards */
    sol_epoch_rewards_t summary;
    err = sol_rewards_calc_compute(calc, 432000, 500000000000000UL, &summary);
    ASSERT(err == SOL_OK);
    ASSERT(summary.num_validators == 1);
    ASSERT(summary.num_stakers == 1);
    ASSERT(summary.total_stake == 1000000);
    ASSERT(summary.total_rewards > 0);

    sol_rewards_calc_destroy(calc);
}

/*
 * Test rewards with commission
 */
TEST(rewards_commission) {
    sol_rewards_calc_t* calc = sol_rewards_calc_new(NULL);
    ASSERT(calc != NULL);

    /* Add validator with 10% commission */
    sol_pubkey_t vote_pubkey = {0};
    vote_pubkey.bytes[0] = 1;
    sol_rewards_calc_add_vote(calc, &vote_pubkey, NULL, 10, 1000, 0);

    /* Add staker */
    sol_pubkey_t stake_pubkey = {0};
    stake_pubkey.bytes[0] = 2;
    sol_rewards_calc_add_stake(calc, &stake_pubkey, &vote_pubkey, 1000000);

    /* Compute */
    sol_epoch_rewards_t summary;
    sol_rewards_calc_compute(calc, 432000, 500000000000000UL, &summary);

    /* Validator should get 10% commission */
    ASSERT(summary.validator_rewards > 0);
    ASSERT(summary.staker_rewards > 0);
    /* Approximately 10% should go to validator */
    double commission_ratio = (double)summary.validator_rewards /
                              (double)(summary.validator_rewards + summary.staker_rewards);
    ASSERT(commission_ratio > 0.09 && commission_ratio < 0.11);

    sol_rewards_calc_destroy(calc);
}

/*
 * Test rewards points
 */
TEST(rewards_points) {
    sol_rewards_calc_t* calc = sol_rewards_calc_new(NULL);
    ASSERT(calc != NULL);

    /* Add validator with 1000 credits earned */
    sol_pubkey_t vote_pubkey = {0};
    vote_pubkey.bytes[0] = 1;
    sol_rewards_calc_add_vote(calc, &vote_pubkey, NULL, 0, 1000, 0);

    /* Add staker with 1M stake */
    sol_pubkey_t stake_pubkey = {0};
    stake_pubkey.bytes[0] = 2;
    sol_rewards_calc_add_stake(calc, &stake_pubkey, &vote_pubkey, 1000000);

    /* Get points */
    sol_rewards_points_t points;
    sol_err_t err = sol_rewards_calc_points(calc, &points);
    ASSERT(err == SOL_OK);

    /* Points = stake * credits = 1M * 1000 = 1B */
    ASSERT(points.total_points == 1000000UL * 1000UL);
    ASSERT(points.total_stake == 1000000);
    ASSERT(points.total_credits == 1000);

    sol_rewards_calc_destroy(calc);
}

/*
 * Main
 */
int main(void) {
    printf("\n=== Sysvar, AccountsHash, Rewards Tests ===\n");

    /* Sysvar tests */
    printf("\nSysvar tests:\n");
    RUN_TEST(sysvar_ids);
    RUN_TEST(sysvar_names);
    RUN_TEST(sysvar_no_unnecessary_rewrites);
    RUN_TEST(clock_sysvar);
    RUN_TEST(rent_sysvar);
    RUN_TEST(rent_minimum_balance);
    RUN_TEST(epoch_schedule_sysvar);
    RUN_TEST(fees_sysvar);
    RUN_TEST(recent_blockhashes);
    RUN_TEST(slot_hashes);
    RUN_TEST(slot_history_bincode_layout_and_add);
    RUN_TEST(stake_history);
    RUN_TEST(stake_history_epoch_boundary_update);
    RUN_TEST(instructions_sysvar);

    /* Accounts hash tests */
    printf("\nAccounts hash tests:\n");
    RUN_TEST(accounts_hash_acc);
    RUN_TEST(hash_combine);
    RUN_TEST(bank_hash_compute);

    /* Rewards tests */
    printf("\nRewards tests:\n");
    RUN_TEST(inflation_rate);
    RUN_TEST(rewards_calc);
    RUN_TEST(rewards_commission);
    RUN_TEST(rewards_points);

    printf("\nResults: %d/%d passed\n\n", tests_passed, tests_run);

    sol_alloc_stats_print();
    return tests_passed == tests_run ? 0 : 1;
}
