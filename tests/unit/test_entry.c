/*
 * test_entry.c - Entry module unit tests
 */

#include "../test_framework.h"
#include "sol_entry.h"
#include "sol_alloc.h"
#include "sol_sha256.h"
#include <stdlib.h>
#include <string.h>

/*
 * Helper to create a tick entry (no transactions)
 */
static void
create_tick_entry(sol_entry_t* entry, const sol_hash_t* prev_hash, uint64_t num_hashes) {
    sol_entry_init(entry);
    entry->num_hashes = num_hashes;
    entry->num_transactions = 0;

    /* Compute expected hash */
    sol_entry_compute_hash(entry, prev_hash, &entry->hash);
}

/*
 * Entry initialization tests
 */

TEST(entry_init) {
    sol_entry_t entry;
    sol_entry_init(&entry);

    TEST_ASSERT_EQ(entry.num_hashes, 0);
    TEST_ASSERT_EQ(entry.num_transactions, 0);
    TEST_ASSERT(entry.transactions == NULL);
    TEST_ASSERT(entry.raw_data == NULL);
}

TEST(entry_cleanup) {
    sol_entry_t entry;
    sol_entry_init(&entry);

    /* Allocate some data */
    entry.transactions = sol_calloc(10, sizeof(sol_transaction_t));
    entry.transactions_capacity = 10;
    entry.raw_data = sol_alloc(100);
    entry.raw_data_len = 100;

    sol_entry_cleanup(&entry);

    TEST_ASSERT(entry.transactions == NULL);
    TEST_ASSERT(entry.raw_data == NULL);
    TEST_ASSERT_EQ(entry.num_transactions, 0);
}

/*
 * Tick entry tests
 */

TEST(entry_tick_is_tick) {
    sol_entry_t entry;
    sol_hash_t prev_hash;
    memset(prev_hash.bytes, 0, 32);

    create_tick_entry(&entry, &prev_hash, 100);

    TEST_ASSERT(sol_entry_is_tick(&entry));
    TEST_ASSERT_EQ(sol_entry_transaction_count(&entry), 0);

    sol_entry_cleanup(&entry);
}

TEST(entry_tick_hash_verification) {
    sol_entry_t entry;
    sol_hash_t prev_hash;
    memset(prev_hash.bytes, 0xAB, 32);

    create_tick_entry(&entry, &prev_hash, 12345);

    /* Should verify correctly */
    TEST_ASSERT(sol_entry_verify_hash(&entry, &prev_hash));

    /* Should fail with wrong previous hash */
    sol_hash_t wrong_hash;
    memset(wrong_hash.bytes, 0xCD, 32);
    TEST_ASSERT(!sol_entry_verify_hash(&entry, &wrong_hash));

    sol_entry_cleanup(&entry);
}

/*
 * Entry serialization tests
 */

TEST(entry_serialize_tick) {
    sol_entry_t entry;
    sol_hash_t prev_hash;
    memset(prev_hash.bytes, 0, 32);

    create_tick_entry(&entry, &prev_hash, 100);

    uint8_t buf[256];
    size_t written;

    sol_err_t err = sol_entry_serialize(&entry, buf, sizeof(buf), &written);
    TEST_ASSERT_EQ(err, SOL_OK);

    /* Should be: 8 (num_hashes) + 32 (hash) + 8 (u64 num_transactions=0) = 48 bytes */
    TEST_ASSERT_EQ(written, 48);

    sol_entry_cleanup(&entry);
}

TEST(entry_parse_tick) {
    /* Create serialized tick entry */
    uint8_t buf[256];
    size_t offset = 0;

    /* num_hashes = 100 */
    uint64_t num_hashes = 100;
    memcpy(buf + offset, &num_hashes, 8);
    offset += 8;

    /* hash (32 bytes of 0xAA) */
    memset(buf + offset, 0xAA, 32);
    offset += 32;

    /* num_transactions = 0 (u64) */
    uint64_t num_tx = 0;
    memcpy(buf + offset, &num_tx, 8);
    offset += 8;

    /* Parse */
    sol_entry_t entry;
    sol_entry_init(&entry);

    size_t consumed;
    sol_err_t err = sol_entry_parse(&entry, buf, offset, &consumed);

    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_EQ(consumed, 48);
    TEST_ASSERT_EQ(entry.num_hashes, 100);
    TEST_ASSERT_EQ(entry.num_transactions, 0);
    TEST_ASSERT(sol_entry_is_tick(&entry));

    sol_entry_cleanup(&entry);
}

TEST(entry_serialize_parse_roundtrip) {
    sol_entry_t entry;
    sol_hash_t prev_hash;
    memset(prev_hash.bytes, 0x55, 32);

    create_tick_entry(&entry, &prev_hash, 12345);

    /* Serialize */
    uint8_t buf[256];
    size_t written;
    sol_err_t err = sol_entry_serialize(&entry, buf, sizeof(buf), &written);
    TEST_ASSERT_EQ(err, SOL_OK);

    /* Parse back */
    sol_entry_t parsed;
    sol_entry_init(&parsed);

    size_t consumed;
    err = sol_entry_parse(&parsed, buf, written, &consumed);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_EQ(consumed, written);

    /* Verify fields match */
    TEST_ASSERT_EQ(parsed.num_hashes, entry.num_hashes);
    TEST_ASSERT_MEM_EQ(parsed.hash.bytes, entry.hash.bytes, 32);
    TEST_ASSERT_EQ(parsed.num_transactions, entry.num_transactions);

    sol_entry_cleanup(&entry);
    sol_entry_cleanup(&parsed);
}

/*
 * Entry batch tests
 */

TEST(entry_batch_create_destroy) {
    sol_entry_batch_t* batch = sol_entry_batch_new(10);
    TEST_ASSERT(batch != NULL);
    TEST_ASSERT_EQ(batch->num_entries, 0);
    TEST_ASSERT_EQ(batch->capacity, 10);

    sol_entry_batch_destroy(batch);
}

TEST(entry_batch_default_capacity) {
    sol_entry_batch_t* batch = sol_entry_batch_new(0);
    TEST_ASSERT(batch != NULL);
    TEST_ASSERT(batch->capacity > 0);  /* Should use default */

    sol_entry_batch_destroy(batch);
}

TEST(entry_batch_parse_ticks) {
    /* Create buffer with 3 tick entries */
    uint8_t buf[256];
    size_t offset = 0;

    /* bincode Vec<Entry> length prefix */
    uint64_t entry_count = 3;
    memcpy(buf + offset, &entry_count, 8);
    offset += 8;

    for (int i = 0; i < 3; i++) {
        /* num_hashes */
        uint64_t num_hashes = (i + 1) * 100;
        memcpy(buf + offset, &num_hashes, 8);
        offset += 8;

        /* hash */
        memset(buf + offset, (uint8_t)(i + 1), 32);
        offset += 32;

        /* num_transactions = 0 (u64) */
        uint64_t num_tx = 0;
        memcpy(buf + offset, &num_tx, 8);
        offset += 8;
    }

    sol_entry_batch_t* batch = sol_entry_batch_new(0);
    TEST_ASSERT(batch != NULL);

    sol_err_t err = sol_entry_batch_parse(batch, buf, offset);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_EQ(batch->num_entries, 3);

    /* Verify entries */
    TEST_ASSERT_EQ(batch->entries[0].num_hashes, 100);
    TEST_ASSERT_EQ(batch->entries[1].num_hashes, 200);
    TEST_ASSERT_EQ(batch->entries[2].num_hashes, 300);

    sol_entry_batch_destroy(batch);
}

TEST(entry_batch_parse_allows_trailing_padding_bytes) {
    /* Create a minimal Vec<Entry> with one tick entry and append trailing
     * zero padding bytes. Real shred reconstruction may include padding bytes
     * within fixed-size shred payloads. */
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));

    size_t offset = 0;
    uint64_t entry_count = 1;
    memcpy(buf + offset, &entry_count, 8);
    offset += 8;

    uint64_t num_hashes = 1;
    memcpy(buf + offset, &num_hashes, 8);
    offset += 8;

    memset(buf + offset, 0xAB, 32);
    offset += 32;

    uint64_t num_tx = 0;
    memcpy(buf + offset, &num_tx, 8);
    offset += 8;

    /* Trailing zero bytes (not part of Vec<Entry>) */
    buf[offset++] = 0x00;
    buf[offset++] = 0x00;
    buf[offset++] = 0x00;
    buf[offset++] = 0x00;

    sol_entry_batch_t* batch = sol_entry_batch_new(0);
    TEST_ASSERT(batch != NULL);

    sol_err_t err = sol_entry_batch_parse(batch, buf, offset);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_EQ(batch->num_entries, 1);

    sol_entry_batch_destroy(batch);
}

TEST(entry_batch_parse_multiple_segments) {
    /* Some block payloads are delivered as multiple concatenated Vec<Entry>
     * segments (each with its own bincode length prefix). */
    uint8_t buf[512];
    memset(buf, 0, sizeof(buf));
    size_t offset = 0;

    /* Segment 1: 1 tick entry */
    uint64_t entry_count = 1;
    memcpy(buf + offset, &entry_count, 8);
    offset += 8;

    uint64_t num_hashes = 11;
    memcpy(buf + offset, &num_hashes, 8);
    offset += 8;
    memset(buf + offset, 0xA1, 32);
    offset += 32;
    uint64_t num_tx = 0;
    memcpy(buf + offset, &num_tx, 8);
    offset += 8;

    /* Segment 2: 2 tick entries */
    entry_count = 2;
    memcpy(buf + offset, &entry_count, 8);
    offset += 8;

    num_hashes = 22;
    memcpy(buf + offset, &num_hashes, 8);
    offset += 8;
    memset(buf + offset, 0xB2, 32);
    offset += 32;
    memcpy(buf + offset, &num_tx, 8);
    offset += 8;

    num_hashes = 33;
    memcpy(buf + offset, &num_hashes, 8);
    offset += 8;
    memset(buf + offset, 0xC3, 32);
    offset += 32;
    memcpy(buf + offset, &num_tx, 8);
    offset += 8;

    /* Trailing zero padding (<8 bytes) should be ignored. */
    buf[offset++] = 0x00;
    buf[offset++] = 0x00;
    buf[offset++] = 0x00;
    buf[offset++] = 0x00;

    sol_entry_batch_t* batch = sol_entry_batch_new(0);
    TEST_ASSERT(batch != NULL);

    sol_err_t err = sol_entry_batch_parse(batch, buf, offset);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_EQ(batch->num_entries, 3);
    TEST_ASSERT_EQ(batch->entries[0].num_hashes, 11);
    TEST_ASSERT_EQ(batch->entries[1].num_hashes, 22);
    TEST_ASSERT_EQ(batch->entries[2].num_hashes, 33);

    sol_entry_batch_destroy(batch);
}

TEST(entry_batch_parse_multiple_segments_with_padding) {
    /* Some shreds are padded with zeros between Vec<Entry> segments. The
     * parser should resynchronize rather than treating the remainder as
     * corruption. */
    uint8_t buf[512];
    memset(buf, 0, sizeof(buf));
    size_t offset = 0;

    /* Segment 1: 1 tick entry */
    uint64_t entry_count = 1;
    memcpy(buf + offset, &entry_count, 8);
    offset += 8;

    uint64_t num_hashes = 11;
    memcpy(buf + offset, &num_hashes, 8);
    offset += 8;
    memset(buf + offset, 0xA1, 32);
    offset += 32;
    uint64_t num_tx = 0;
    memcpy(buf + offset, &num_tx, 8);
    offset += 8;

    /* Insert non-8-byte-aligned zero padding between segments. */
    buf[offset++] = 0x00;

    /* Segment 2: 2 tick entries */
    entry_count = 2;
    memcpy(buf + offset, &entry_count, 8);
    offset += 8;

    num_hashes = 22;
    memcpy(buf + offset, &num_hashes, 8);
    offset += 8;
    memset(buf + offset, 0xB2, 32);
    offset += 32;
    memcpy(buf + offset, &num_tx, 8);
    offset += 8;

    num_hashes = 33;
    memcpy(buf + offset, &num_hashes, 8);
    offset += 8;
    memset(buf + offset, 0xC3, 32);
    offset += 32;
    memcpy(buf + offset, &num_tx, 8);
    offset += 8;

    sol_entry_batch_t* batch = sol_entry_batch_new(0);
    TEST_ASSERT(batch != NULL);

    sol_err_t err = sol_entry_batch_parse(batch, buf, offset);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_EQ(batch->num_entries, 3);
    TEST_ASSERT_EQ(batch->entries[0].num_hashes, 11);
    TEST_ASSERT_EQ(batch->entries[1].num_hashes, 22);
    TEST_ASSERT_EQ(batch->entries[2].num_hashes, 33);

    sol_entry_batch_destroy(batch);
}

TEST(entry_batch_parse_multiple_segments_short_padding_straddle_resync_zerocopy) {
    /* Regression: when padding between Vec<Entry> segments is shorter than the
     * 8-byte bincode length prefix, a naive u64 read can straddle the next
     * segment header and produce a plausible (but wrong) entry_count. Ensure
     * the parser resynchronizes rather than failing with a decode error.
     *
     * This test specifically exercises the zero-copy decode path used during
     * replay/catchup (copy_tx_bytes=false). */
    const size_t cap = 32768;
    uint8_t* buf = sol_calloc(1, cap);
    TEST_ASSERT(buf != NULL);

    size_t offset = 0;
    uint64_t num_tx = 0;

    /* Segment 1: 1 tick entry */
    uint64_t entry_count = 1;
    memcpy(buf + offset, &entry_count, 8);
    offset += 8;

    uint64_t num_hashes = 11;
    memcpy(buf + offset, &num_hashes, 8);
    offset += 8;
    memset(buf + offset, 0xA1, 32);
    offset += 32;
    memcpy(buf + offset, &num_tx, 8);
    offset += 8;

    /* Insert 1 byte of padding so the next u64 read straddles the next segment header. */
    buf[offset++] = 0x00;

    /* Segment 2: 2 tick entries */
    entry_count = 2;
    memcpy(buf + offset, &entry_count, 8);
    offset += 8;

    num_hashes = 22;
    memcpy(buf + offset, &num_hashes, 8);
    offset += 8;
    memset(buf + offset, 0xB2, 32);
    offset += 32;
    memcpy(buf + offset, &num_tx, 8);
    offset += 8;

    num_hashes = 33;
    memcpy(buf + offset, &num_hashes, 8);
    offset += 8;
    memset(buf + offset, 0xC3, 32);
    offset += 32;
    memcpy(buf + offset, &num_tx, 8);
    offset += 8;

    /* Place a third segment far enough away to make the straddled entry_count
     * appear plausible under min-size heuristics (segment_remaining is large). */
    size_t seg3_off = 30000;
    TEST_ASSERT(seg3_off + 8 + 48 <= cap);

    offset = seg3_off;
    entry_count = 1;
    memcpy(buf + offset, &entry_count, 8);
    offset += 8;

    num_hashes = 44;
    memcpy(buf + offset, &num_hashes, 8);
    offset += 8;
    memset(buf + offset, 0xD4, 32);
    offset += 32;
    memcpy(buf + offset, &num_tx, 8);
    offset += 8;

    sol_entry_batch_t* batch = sol_entry_batch_new(0);
    TEST_ASSERT(batch != NULL);

    sol_err_t err = sol_entry_batch_parse_ex(batch, buf, offset, false);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_EQ(batch->num_entries, 4);
    TEST_ASSERT_EQ(batch->entries[0].num_hashes, 11);
    TEST_ASSERT_EQ(batch->entries[1].num_hashes, 22);
    TEST_ASSERT_EQ(batch->entries[2].num_hashes, 33);
    TEST_ASSERT_EQ(batch->entries[3].num_hashes, 44);

    sol_entry_batch_destroy(batch);
    sol_free(buf);
}

TEST(entry_batch_transaction_count) {
    sol_entry_batch_t* batch = sol_entry_batch_new(0);
    TEST_ASSERT(batch != NULL);

    /* Empty batch */
    TEST_ASSERT_EQ(sol_entry_batch_transaction_count(batch), 0);

    /* Add some entries with transaction counts */
    batch->entries[0].num_transactions = 5;
    batch->entries[1].num_transactions = 3;
    batch->entries[2].num_transactions = 0;  /* Tick */
    batch->num_entries = 3;

    TEST_ASSERT_EQ(sol_entry_batch_transaction_count(batch), 8);

    sol_entry_batch_destroy(batch);
}

TEST(entry_batch_tick_count) {
    sol_entry_batch_t* batch = sol_entry_batch_new(0);
    TEST_ASSERT(batch != NULL);

    /* Empty batch */
    TEST_ASSERT_EQ(sol_entry_batch_tick_count(batch), 0);

    /* Add entries */
    batch->entries[0].num_transactions = 5;   /* Not tick */
    batch->entries[1].num_transactions = 0;   /* Tick */
    batch->entries[2].num_transactions = 0;   /* Tick */
    batch->entries[3].num_transactions = 2;   /* Not tick */
    batch->num_entries = 4;

    TEST_ASSERT_EQ(sol_entry_batch_tick_count(batch), 2);

    sol_entry_batch_destroy(batch);
}

/*
 * Hash computation tests
 */

static void
hash_leaf_signature_test(const sol_signature_t* sig, sol_hash_t* out) {
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    const uint8_t prefix = 0;
    sol_sha256_update(&ctx, &prefix, 1);
    sol_sha256_update(&ctx, sig->bytes, 64);
    sol_sha256_final_bytes(&ctx, out->bytes);
}

static void
hash_intermediate_test(const sol_hash_t* left, const sol_hash_t* right, sol_hash_t* out) {
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    const uint8_t prefix = 1;
    sol_sha256_update(&ctx, &prefix, 1);
    sol_sha256_update(&ctx, left->bytes, 32);
    sol_sha256_update(&ctx, right->bytes, 32);
    sol_sha256_final_bytes(&ctx, out->bytes);
}

TEST(entry_transaction_merkle_root_single_signature) {
    sol_signature_t sig = {0};
    for (size_t i = 0; i < sizeof(sig.bytes); i++) {
        sig.bytes[i] = (uint8_t)i;
    }

    sol_transaction_t* txs = sol_calloc(1, sizeof(*txs));
    TEST_ASSERT(txs != NULL);
    sol_transaction_init(&txs[0]);
    txs[0].signatures = &sig;
    txs[0].signatures_len = 1;

    sol_entry_t entry;
    sol_entry_init(&entry);
    entry.num_hashes = 0;
    entry.num_transactions = 1;
    entry.transactions = txs;
    entry.transactions_capacity = 1;

    sol_hash_t got = {0};
    sol_entry_transaction_merkle_root(&entry, &got);

    sol_hash_t expected = {0};
    hash_leaf_signature_test(&sig, &expected);

    TEST_ASSERT_MEM_EQ(got.bytes, expected.bytes, 32);

    sol_entry_cleanup(&entry);
}

TEST(entry_transaction_merkle_root_three_signatures_duplicates_last) {
    sol_signature_t sigs[3] = {{0}};
    for (size_t s = 0; s < 3; s++) {
        for (size_t i = 0; i < sizeof(sigs[s].bytes); i++) {
            sigs[s].bytes[i] = (uint8_t)(1u + (uint8_t)(s * 64u + i));
        }
    }

    sol_transaction_t* txs = sol_calloc(1, sizeof(*txs));
    TEST_ASSERT(txs != NULL);
    sol_transaction_init(&txs[0]);
    txs[0].signatures = sigs;
    txs[0].signatures_len = 3;

    sol_entry_t entry;
    sol_entry_init(&entry);
    entry.num_hashes = 0;
    entry.num_transactions = 1;
    entry.transactions = txs;
    entry.transactions_capacity = 1;

    sol_hash_t got = {0};
    sol_entry_transaction_merkle_root(&entry, &got);

    sol_hash_t leaf0 = {0}, leaf1 = {0}, leaf2 = {0};
    hash_leaf_signature_test(&sigs[0], &leaf0);
    hash_leaf_signature_test(&sigs[1], &leaf1);
    hash_leaf_signature_test(&sigs[2], &leaf2);

    sol_hash_t node0 = {0}, node1 = {0};
    hash_intermediate_test(&leaf0, &leaf1, &node0);
    hash_intermediate_test(&leaf2, &leaf2, &node1);

    sol_hash_t expected = {0};
    hash_intermediate_test(&node0, &node1, &expected);

    TEST_ASSERT_MEM_EQ(got.bytes, expected.bytes, 32);

    sol_entry_cleanup(&entry);
}

TEST(entry_compute_hash_transaction_entry_matches_spec) {
    sol_signature_t sig = {0};
    for (size_t i = 0; i < sizeof(sig.bytes); i++) {
        sig.bytes[i] = (uint8_t)(0xA0u + (uint8_t)i);
    }

    sol_transaction_t* txs = sol_calloc(1, sizeof(*txs));
    TEST_ASSERT(txs != NULL);
    sol_transaction_init(&txs[0]);
    txs[0].signatures = &sig;
    txs[0].signatures_len = 1;

    sol_entry_t entry;
    sol_entry_init(&entry);
    entry.num_hashes = 2;
    entry.num_transactions = 1;
    entry.transactions = txs;
    entry.transactions_capacity = 1;

    sol_hash_t prev_hash = {0};
    memset(prev_hash.bytes, 0x11, 32);

    sol_hash_t got = {0};
    sol_entry_compute_hash(&entry, &prev_hash, &got);

    sol_hash_t mixin = {0};
    hash_leaf_signature_test(&sig, &mixin);

    sol_hash_t cur = prev_hash;
    sol_sha256_32bytes_repeated(cur.bytes, 1);

    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    sol_sha256_update(&ctx, cur.bytes, 32);
    sol_sha256_update(&ctx, mixin.bytes, 32);
    sol_sha256_final_bytes(&ctx, cur.bytes);

    TEST_ASSERT_MEM_EQ(got.bytes, cur.bytes, 32);

    sol_entry_cleanup(&entry);
}

TEST(entry_compute_hash_deterministic) {
    sol_entry_t entry1, entry2;
    sol_entry_init(&entry1);
    sol_entry_init(&entry2);

    entry1.num_hashes = 100;
    entry2.num_hashes = 100;

    sol_hash_t prev_hash;
    memset(prev_hash.bytes, 0xAB, 32);

    sol_hash_t hash1, hash2;
    sol_entry_compute_hash(&entry1, &prev_hash, &hash1);
    sol_entry_compute_hash(&entry2, &prev_hash, &hash2);

    /* Same input should produce same hash */
    TEST_ASSERT_MEM_EQ(hash1.bytes, hash2.bytes, 32);

    sol_entry_cleanup(&entry1);
    sol_entry_cleanup(&entry2);
}

TEST(entry_compute_hash_different_num_hashes) {
    sol_entry_t entry1, entry2;
    sol_entry_init(&entry1);
    sol_entry_init(&entry2);

    entry1.num_hashes = 100;
    entry2.num_hashes = 101;

    sol_hash_t prev_hash;
    memset(prev_hash.bytes, 0xAB, 32);

    sol_hash_t hash1, hash2;
    sol_entry_compute_hash(&entry1, &prev_hash, &hash1);
    sol_entry_compute_hash(&entry2, &prev_hash, &hash2);

    /* Different num_hashes should produce different hash */
    TEST_ASSERT(memcmp(hash1.bytes, hash2.bytes, 32) != 0);

    sol_entry_cleanup(&entry1);
    sol_entry_cleanup(&entry2);
}

TEST(entry_compute_hash_different_prev_hash) {
    sol_entry_t entry;
    sol_entry_init(&entry);
    entry.num_hashes = 100;

    sol_hash_t prev1, prev2;
    memset(prev1.bytes, 0xAB, 32);
    memset(prev2.bytes, 0xCD, 32);

    sol_hash_t hash1, hash2;
    sol_entry_compute_hash(&entry, &prev1, &hash1);
    sol_entry_compute_hash(&entry, &prev2, &hash2);

    /* Different prev_hash should produce different hash */
    TEST_ASSERT(memcmp(hash1.bytes, hash2.bytes, 32) != 0);

    sol_entry_cleanup(&entry);
}

TEST(entry_batch_verify_parallel_matches_serial) {
    enum { ENTRY_COUNT = 320 };

    sol_entry_batch_t* batch = sol_entry_batch_new(ENTRY_COUNT);
    TEST_ASSERT(batch != NULL);

    sol_hash_t start_hash = {0};
    memset(start_hash.bytes, 0x42, sizeof(start_hash.bytes));

    sol_hash_t prev = start_hash;
    for (size_t i = 0; i < ENTRY_COUNT; i++) {
        sol_entry_t* entry = &batch->entries[i];
        sol_entry_init(entry);
        entry->num_hashes = (uint64_t)((i % 3u) + 1u);
        entry->num_transactions = 0;
        sol_entry_compute_hash(entry, &prev, &entry->hash);
        prev = entry->hash;
    }
    batch->num_entries = ENTRY_COUNT;

    const char* key_threads = "SOL_ENTRY_VERIFY_PARALLEL_THREADS";
    const char* key_min_entries = "SOL_ENTRY_VERIFY_PARALLEL_MIN_ENTRIES";
    const char* prev_threads = getenv(key_threads);
    const char* prev_min_entries = getenv(key_min_entries);
    char prev_threads_buf[32] = {0};
    char prev_min_entries_buf[32] = {0};
    bool had_prev_threads = false;
    bool had_prev_min_entries = false;

    if (prev_threads && prev_threads[0] != '\0') {
        strncpy(prev_threads_buf, prev_threads, sizeof(prev_threads_buf) - 1u);
        had_prev_threads = true;
    }
    if (prev_min_entries && prev_min_entries[0] != '\0') {
        strncpy(prev_min_entries_buf, prev_min_entries, sizeof(prev_min_entries_buf) - 1u);
        had_prev_min_entries = true;
    }

    setenv(key_threads, "4", 1);
    setenv(key_min_entries, "1", 1);

    sol_entry_verify_result_t vr = sol_entry_batch_verify(batch, &start_hash);
    TEST_ASSERT(vr.valid);
    TEST_ASSERT_EQ(vr.num_verified, ENTRY_COUNT);

    batch->entries[137].hash.bytes[0] ^= 0x80u;
    vr = sol_entry_batch_verify(batch, &start_hash);
    TEST_ASSERT(!vr.valid);
    TEST_ASSERT_EQ(vr.failed_entry, 137u);
    batch->entries[137].hash.bytes[0] ^= 0x80u;

    if (had_prev_threads) {
        setenv(key_threads, prev_threads_buf, 1);
    } else {
        unsetenv(key_threads);
    }
    if (had_prev_min_entries) {
        setenv(key_min_entries, prev_min_entries_buf, 1);
    } else {
        unsetenv(key_min_entries);
    }

    sol_entry_batch_destroy(batch);
}

/*
 * Null handling tests
 */

TEST(entry_null_handling) {
    sol_entry_init(NULL);  /* Should not crash */
    sol_entry_cleanup(NULL);  /* Should not crash */

    TEST_ASSERT(!sol_entry_is_tick(NULL));
    TEST_ASSERT_EQ(sol_entry_transaction_count(NULL), 0);
    TEST_ASSERT(!sol_entry_verify_hash(NULL, NULL));
    TEST_ASSERT(!sol_entry_verify_signatures(NULL));

    TEST_ASSERT_EQ(sol_entry_batch_transaction_count(NULL), 0);
    TEST_ASSERT_EQ(sol_entry_batch_tick_count(NULL), 0);
}

TEST(entry_parse_truncated) {
    sol_entry_t entry;
    sol_entry_init(&entry);

    uint8_t buf[10] = {0};
    size_t consumed;

    /* Too short - should fail */
    sol_err_t err = sol_entry_parse(&entry, buf, 10, &consumed);
    TEST_ASSERT_EQ(err, SOL_ERR_TRUNCATED);

    sol_entry_cleanup(&entry);
}

/*
 * Test runner
 */
static test_case_t entry_tests[] = {
    TEST_CASE(entry_init),
    TEST_CASE(entry_cleanup),
    TEST_CASE(entry_tick_is_tick),
    TEST_CASE(entry_tick_hash_verification),
    TEST_CASE(entry_serialize_tick),
    TEST_CASE(entry_parse_tick),
    TEST_CASE(entry_serialize_parse_roundtrip),
    TEST_CASE(entry_batch_create_destroy),
    TEST_CASE(entry_batch_default_capacity),
    TEST_CASE(entry_batch_parse_ticks),
    TEST_CASE(entry_batch_parse_allows_trailing_padding_bytes),
    TEST_CASE(entry_batch_parse_multiple_segments),
    TEST_CASE(entry_batch_parse_multiple_segments_with_padding),
    TEST_CASE(entry_batch_parse_multiple_segments_short_padding_straddle_resync_zerocopy),
    TEST_CASE(entry_batch_transaction_count),
    TEST_CASE(entry_batch_tick_count),
    TEST_CASE(entry_transaction_merkle_root_single_signature),
    TEST_CASE(entry_transaction_merkle_root_three_signatures_duplicates_last),
    TEST_CASE(entry_compute_hash_transaction_entry_matches_spec),
    TEST_CASE(entry_compute_hash_deterministic),
    TEST_CASE(entry_compute_hash_different_num_hashes),
    TEST_CASE(entry_compute_hash_different_prev_hash),
    TEST_CASE(entry_batch_verify_parallel_matches_serial),
    TEST_CASE(entry_null_handling),
    TEST_CASE(entry_parse_truncated),
};

int main(void) {
    int result = RUN_TESTS("Entry Tests", entry_tests);
    sol_alloc_dump_leaks();
    return result;
}
