/*
 * sol_entry.c - Block Entry Implementation
 */

#include "sol_entry.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include "../crypto/sol_sha256.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

/*
 * Initial transaction capacity for entries
 */
#define INITIAL_TXN_CAPACITY 16

/*
 * Initial entry capacity for batches
 */
#define INITIAL_ENTRY_CAPACITY 64

void
sol_entry_init(sol_entry_t* entry) {
    if (!entry) return;
    memset(entry, 0, sizeof(sol_entry_t));
}

void
sol_entry_cleanup(sol_entry_t* entry) {
    if (!entry) return;

    sol_free(entry->transactions);
    if (entry->raw_data && !entry->raw_data_borrowed) {
        sol_free(entry->raw_data);
    }

    entry->transactions = NULL;
    entry->raw_data = NULL;
    entry->num_transactions = 0;
    entry->transactions_capacity = 0;
    entry->raw_data_len = 0;
    entry->raw_data_borrowed = false;
}

sol_err_t
sol_entry_parse_ex(sol_entry_t* entry, const uint8_t* data, size_t len,
                   size_t* bytes_consumed, bool copy_tx_bytes) {
    if (!entry || !data || !bytes_consumed) {
        return SOL_ERR_INVAL;
    }

    size_t offset = 0;

    /* Read num_hashes (u64 little-endian) */
    if (offset + 8 > len) return SOL_ERR_TRUNCATED;
    memcpy(&entry->num_hashes, data + offset, 8);
    offset += 8;

    /* Read hash (32 bytes) */
    if (offset + 32 > len) return SOL_ERR_TRUNCATED;
    memcpy(entry->hash.bytes, data + offset, 32);
    offset += 32;

    /* Read num_transactions (bincode Vec length: u64 little-endian) */
    if (offset + 8 > len) return SOL_ERR_TRUNCATED;
    uint64_t num_txns = 0;
    memcpy(&num_txns, data + offset, 8);
    offset += 8;

    if (num_txns > SOL_ENTRY_MAX_TRANSACTIONS || num_txns > UINT32_MAX) {
        sol_log_warn("Entry has too many transactions: %llu",
                    (unsigned long long)num_txns);
        return SOL_ERR_TOO_LARGE;
    }

    /* Allocate transaction array if needed */
    if (num_txns > 0) {
        if (num_txns > entry->transactions_capacity) {
            size_t alloc_sz = 0;
            if (__builtin_mul_overflow((size_t)num_txns, sizeof(sol_transaction_t), &alloc_sz)) {
                return SOL_ERR_TOO_LARGE;
            }

            sol_transaction_t* txs = sol_realloc(entry->transactions, alloc_sz);
            if (!txs) return SOL_ERR_NOMEM;
            entry->transactions = txs;
            entry->transactions_capacity = (size_t)num_txns;
        }

        if (copy_tx_bytes) {
            /* First pass: calculate total transaction data size */
            size_t txn_data_start = offset;
            size_t temp_offset = offset;

            for (uint64_t i = 0; i < num_txns; i++) {
                if (temp_offset >= len) return SOL_ERR_TRUNCATED;

                /* Parse transaction to get its size */
                sol_transaction_t temp_tx;

                sol_err_t err = sol_transaction_decode(data + temp_offset,
                                                       len - temp_offset, &temp_tx);
                if (err != SOL_OK) {
                    return err;
                }

                size_t txn_size = temp_tx.encoded_len;
                if (txn_size == 0 || txn_size > (len - temp_offset)) {
                    return SOL_ERR_TX_MALFORMED;
                }
                temp_offset += txn_size;
            }

            size_t txn_data_len = temp_offset - txn_data_start;

            /* Allocate and copy raw transaction data */
            sol_free(entry->raw_data);
            entry->raw_data = sol_alloc(txn_data_len);
            if (!entry->raw_data) return SOL_ERR_NOMEM;
            memcpy(entry->raw_data, data + txn_data_start, txn_data_len);
            entry->raw_data_len = txn_data_len;
            entry->raw_data_borrowed = false;

            /* Parse transactions from our copy */
            size_t raw_offset = 0;
            for (uint64_t i = 0; i < num_txns; i++) {
                sol_err_t err = sol_transaction_decode(entry->raw_data + raw_offset,
                                                       txn_data_len - raw_offset,
                                                       &entry->transactions[i]);
                if (err != SOL_OK) {
                    return err;
                }

                size_t txn_size = entry->transactions[i].encoded_len;
                if (txn_size == 0 || txn_size > (txn_data_len - raw_offset)) {
                    return SOL_ERR_TX_MALFORMED;
                }
                raw_offset += txn_size;
            }

            offset = temp_offset;
        } else {
            /* Zero-copy parse: borrow transaction bytes directly from the input
               buffer and decode each transaction once. */
            size_t txn_data_start = offset;

            for (uint64_t i = 0; i < num_txns; i++) {
                if (offset >= len) return SOL_ERR_TRUNCATED;

                sol_err_t err = sol_transaction_decode(data + offset,
                                                       len - offset,
                                                       &entry->transactions[i]);
                if (err != SOL_OK) {
                    return err;
                }

                size_t txn_size = entry->transactions[i].encoded_len;
                if (txn_size == 0 || txn_size > (len - offset)) {
                    return SOL_ERR_TX_MALFORMED;
                }
                offset += txn_size;
            }

            entry->raw_data = (uint8_t*)(uintptr_t)(data + txn_data_start);
            entry->raw_data_len = offset - txn_data_start;
            entry->raw_data_borrowed = true;
        }
    }

    entry->num_transactions = (uint32_t)num_txns;
    *bytes_consumed = offset;
    return SOL_OK;
}

sol_err_t
sol_entry_parse(sol_entry_t* entry, const uint8_t* data, size_t len,
                size_t* bytes_consumed) {
    return sol_entry_parse_ex(entry, data, len, bytes_consumed, true);
}

sol_err_t
sol_entry_serialize(const sol_entry_t* entry, uint8_t* buf, size_t buf_len,
                    size_t* bytes_written) {
    if (!entry || !buf || !bytes_written) {
        return SOL_ERR_INVAL;
    }

    sol_encoder_t enc;
    sol_encoder_init(&enc, buf, buf_len);

    /* Write num_hashes */
    SOL_ENCODE_TRY(sol_encode_u64(&enc, entry->num_hashes));

    /* Write hash */
    SOL_ENCODE_TRY(sol_encode_bytes(&enc, entry->hash.bytes, SOL_HASH_SIZE));

    /* Write num_transactions (bincode Vec length: u64) */
    if (entry->num_transactions > SOL_ENTRY_MAX_TRANSACTIONS) {
        return SOL_ERR_TOO_LARGE;
    }
    SOL_ENCODE_TRY(sol_encode_u64(&enc, (uint64_t)entry->num_transactions));

    /* Write transaction data */
    if (entry->raw_data && entry->raw_data_len > 0) {
        SOL_ENCODE_TRY(sol_encode_bytes(&enc, entry->raw_data, entry->raw_data_len));
    }

    *bytes_written = sol_encoder_len(&enc);
    return SOL_OK;
}

/*
 * Compute hash of a transaction signature (leaf node)
 */
static void
hash_leaf_signature(const sol_signature_t* sig, sol_hash_t* out) {
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    const uint8_t prefix = 0;
    sol_sha256_update(&ctx, &prefix, 1);
    sol_sha256_update(&ctx, sig->bytes, 64);
    sol_sha256_final_bytes(&ctx, out->bytes);
}

/*
 * Combine two hashes into one (internal node)
 */
static void
hash_intermediate(const sol_hash_t* left, const sol_hash_t* right, sol_hash_t* out) {
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    const uint8_t prefix = 1;
    sol_sha256_update(&ctx, &prefix, 1);
    sol_sha256_update(&ctx, left->bytes, 32);
    sol_sha256_update(&ctx, right->bytes, 32);
    sol_sha256_final_bytes(&ctx, out->bytes);
}

typedef struct {
    sol_hash_t* hashes;
    size_t      cap;
} entry_merkle_scratch_t;

static __thread entry_merkle_scratch_t g_tls_entry_merkle_scratch = {0};

static sol_hash_t*
entry_merkle_scratch_ensure(size_t need) {
    if (need == 0) return NULL;
    entry_merkle_scratch_t* sc = &g_tls_entry_merkle_scratch;
    if (sc->hashes && sc->cap >= need) return sc->hashes;

    size_t new_cap = sc->cap ? sc->cap : 64u;
    while (new_cap < need) {
        if (new_cap > (SIZE_MAX / 2u)) {
            new_cap = need;
            break;
        }
        new_cap *= 2u;
    }

    sol_hash_t* next = sol_realloc_array(sol_hash_t, sc->hashes, new_cap);
    if (!next) return NULL;
    sc->hashes = next;
    sc->cap = new_cap;
    return sc->hashes;
}

void
sol_entry_transaction_merkle_root(const sol_entry_t* entry, sol_hash_t* out_root) {
    if (!entry || !out_root) return;

    if (entry->num_transactions == 0 || !entry->transactions) {
        /* Hash::default() */
        memset(out_root->bytes, 0, 32);
        return;
    }

    /* Solana `hash_transactions()`:
     * Merkle root over ALL transaction signatures (flattened, in order),
     * using solana-merkle-tree domain separation:
     *   leaf = SHA256(0x00 || sig64)
     *   node = SHA256(0x01 || left32 || right32)
     * Odd nodes: duplicate last. */
    size_t sig_total = 0;
    for (uint32_t ti = 0; ti < entry->num_transactions; ti++) {
        const sol_transaction_t* tx = &entry->transactions[ti];
        if (!tx->signatures || tx->signatures_len == 0) {
            memset(out_root->bytes, 0, 32);
            return;
        }
        sig_total += (size_t)tx->signatures_len;
    }

    if (sig_total == 0) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    if (sig_total == 1) {
        /* Common case: single signature -> root is the leaf hash. */
        const sol_signature_t* sig = NULL;
        for (uint32_t ti = 0; ti < entry->num_transactions && !sig; ti++) {
            const sol_transaction_t* tx = &entry->transactions[ti];
            if (tx->signatures && tx->signatures_len > 0) {
                sig = &tx->signatures[0];
            }
        }
        if (!sig) {
            memset(out_root->bytes, 0, 32);
            return;
        }
        hash_leaf_signature(sig, out_root);
        return;
    }

    sol_hash_t* hashes = entry_merkle_scratch_ensure(sig_total);
    if (!hashes) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    size_t leaf_idx = 0;
    for (uint32_t ti = 0; ti < entry->num_transactions; ti++) {
        const sol_transaction_t* tx = &entry->transactions[ti];
        for (uint8_t si = 0; si < tx->signatures_len; si++) {
            hash_leaf_signature(&tx->signatures[si], &hashes[leaf_idx++]);
        }
    }

    size_t level_size = sig_total;
    while (level_size > 1) {
        size_t next_size = (level_size + 1u) / 2u;
        for (size_t i = 0; i < next_size; i++) {
            size_t left = i * 2u;
            size_t right = left + 1u;
            if (right >= level_size) right = left; /* duplicate */
            hash_intermediate(&hashes[left], &hashes[right], &hashes[i]);
        }
        level_size = next_size;
    }

    *out_root = hashes[0];
}

void
sol_entry_compute_hash(const sol_entry_t* entry, const sol_hash_t* prev_hash,
                       sol_hash_t* out_hash) {
    if (!entry || !prev_hash || !out_hash) return;

    /* Agave entry::next_hash:
     * - If num_hashes == 0 and no tx: return prev_hash.
     * - Tick entry: hash prev_hash sequentially num_hashes times.
     * - Transaction entry: hash prev_hash sequentially (num_hashes - 1) times,
     *   then record() once with mixin=hash_transactions(transactions).
     *
     * hash_transactions() is a Merkle root over all transaction signatures
     * (flattened), using the solana-merkle-tree domain-separated hashing. */
    sol_hash_t current = *prev_hash;

    if (entry->num_transactions == 0) {
        sol_sha256_32bytes_repeated(current.bytes, entry->num_hashes);
        *out_hash = current;
        return;
    }

    if (!entry->transactions) {
        memset(out_hash->bytes, 0, 32);
        return;
    }

    sol_hash_t mixin = {0};
    sol_entry_transaction_merkle_root(entry, &mixin);

    uint64_t hashes_before_record = entry->num_hashes ? (entry->num_hashes - 1) : 0;
    sol_sha256_32bytes_repeated(current.bytes, hashes_before_record);

    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    sol_sha256_update(&ctx, current.bytes, 32);
    sol_sha256_update(&ctx, mixin.bytes, 32);
    sol_sha256_final_bytes(&ctx, current.bytes);

    *out_hash = current;
}

bool
sol_entry_verify_hash(const sol_entry_t* entry, const sol_hash_t* prev_hash) {
    if (!entry || !prev_hash) return false;

    sol_hash_t computed;
    sol_entry_compute_hash(entry, prev_hash, &computed);

    return memcmp(computed.bytes, entry->hash.bytes, 32) == 0;
}

bool
sol_entry_verify_signatures(const sol_entry_t* entry) {
    if (!entry) return false;

    for (uint32_t i = 0; i < entry->num_transactions; i++) {
        if (!sol_transaction_verify_signatures(&entry->transactions[i], NULL)) {
            return false;
        }
    }

    return true;
}

sol_entry_batch_t*
sol_entry_batch_new(size_t initial_capacity) {
    if (initial_capacity == 0) {
        initial_capacity = INITIAL_ENTRY_CAPACITY;
    }

    sol_entry_batch_t* batch = sol_calloc(1, sizeof(sol_entry_batch_t));
    if (!batch) return NULL;

    batch->entries = sol_calloc(initial_capacity, sizeof(sol_entry_t));
    if (!batch->entries) {
        sol_free(batch);
        return NULL;
    }

    batch->capacity = initial_capacity;
    return batch;
}

void
sol_entry_batch_destroy(sol_entry_batch_t* batch) {
    if (!batch) return;

    /* Cleanup all entries */
    for (size_t i = 0; i < batch->num_entries; i++) {
        sol_entry_cleanup(&batch->entries[i]);
    }

    sol_free(batch->entries);
    sol_free(batch);
}

sol_err_t
sol_entry_batch_parse_ex(sol_entry_batch_t* batch, const uint8_t* data, size_t len, bool copy_tx_bytes) {
    if (!batch || !data) return SOL_ERR_INVAL;

    /* Clean up any existing entries if the batch is being reused. */
    for (size_t i = 0; i < batch->num_entries; i++) {
        sol_entry_cleanup(&batch->entries[i]);
    }
    batch->num_entries = 0;

    /* Blocks are typically serialized as one or more concatenated bincode
     * Vec<Entry> segments:
     *   entry_count: u64
     *   entries: [Entry; entry_count]
     *
     * Some shred payload reconstruction paths may also include trailing padding
     * bytes that are not part of any Vec<Entry>. These bytes are ignored. */
    if (len < 8) {
        return SOL_ERR_TRUNCATED;
    }

    /* Basic sanity: each entry is at least 48 bytes (no transactions):
     *   num_hashes:u64 (8) + hash:32 + tx_len:u64 (8) */
    const size_t min_entry_size = 8u + 32u + 8u;

    size_t offset = 0;
    bool parsed_any_segment = false;

    while (offset + 8u <= len) {
        const size_t segment_start = offset;
        const size_t segment_remaining = len - offset;
        if (segment_remaining < 8u) break;

        uint64_t entry_count = 0;
        memcpy(&entry_count, data + offset, 8);
        offset += 8;

        if (entry_count == 0) {
            /* Empty vec / padding.
             *
             * On mainnet, DATA_COMPLETE boundaries (end-of-FEC-set) are often
             * padded with zeros. The next Vec<Entry> header is not guaranteed
             * to be 8-byte aligned relative to the end of the previous segment,
             * so once we've successfully parsed at least one segment, scan
             * forward byte-by-byte to resynchronize. */
            if (parsed_any_segment) {
                offset = segment_start + 1u;
            } else if ((segment_start & 7u) != 0u) {
                offset = segment_start + 1u;
            }
            continue;
        }

        /* Sanity: each entry has a minimum size. If this doesn't hold, assume
         * the remainder is padding or a non-entry payload. */
        if (entry_count > (uint64_t)(segment_remaining / min_entry_size)) {
            /* If we already parsed at least one segment, this likely means we
             * are in inter-segment padding and are misaligned. Slide forward
             * by one byte and keep scanning for the next segment header. */
            if (parsed_any_segment) {
                offset = segment_start + 1u;
                continue;
            }

            offset = segment_start;
            return SOL_ERR_TOO_LARGE;
        }

        const size_t before_segment_entries = batch->num_entries;
        sol_err_t segment_err = SOL_OK;

        for (uint64_t ei = 0; ei < entry_count; ei++) {
            /* Ensure capacity */
            if (batch->num_entries >= batch->capacity) {
                size_t new_cap = batch->capacity * 2;
                sol_entry_t* new_entries = sol_realloc(batch->entries,
                                                       new_cap * sizeof(sol_entry_t));
                if (!new_entries) {
                    segment_err = SOL_ERR_NOMEM;
                    break;
                }

                /* Zero the new entries */
                memset(new_entries + batch->capacity, 0,
                       (new_cap - batch->capacity) * sizeof(sol_entry_t));

                batch->entries = new_entries;
                batch->capacity = new_cap;
            }

            /* Initialize entry */
            sol_entry_t* entry = &batch->entries[batch->num_entries];
            sol_entry_init(entry);

            /* Parse entry */
            size_t consumed = 0;
            segment_err = sol_entry_parse_ex(entry, data + offset, len - offset, &consumed, copy_tx_bytes);
            if (segment_err != SOL_OK) {
                sol_entry_cleanup(entry);
                break;
            }

            if (consumed == 0) {
                sol_entry_cleanup(entry);
                segment_err = SOL_ERR_INVAL;
                break;
            }

            batch->num_entries++;
            offset += consumed;
        }

        if (segment_err != SOL_OK) {
            /* Roll back partial segment parsing. */
            for (size_t i = before_segment_entries; i < batch->num_entries; i++) {
                sol_entry_cleanup(&batch->entries[i]);
            }
            batch->num_entries = before_segment_entries;
            offset = segment_start;

            if (segment_err == SOL_ERR_NOMEM) {
                return segment_err;
            }
            if (!parsed_any_segment) {
                return segment_err;
            }

            /* Treat remainder as padding only when it is actually padding.
             *
             * In production (replay/catchup), silently dropping non-zero bytes
             * yields incomplete slots (missing transactions/ticks) that can
             * stall bootstrap. */
            bool all_zero = true;
            for (size_t i = segment_start; i < len; i++) {
                if (data[i] != 0) {
                    all_zero = false;
                    break;
                }
            }
            if (all_zero) {
                break;
            }

            /* Resync: segment parsing failed but we've already successfully
             * parsed earlier segments. This can happen when padding between
             * Vec<Entry> segments is shorter than the 8-byte length prefix,
             * causing a straddled u64 read and a bogus entry_count. Slide
             * forward and keep scanning for the next segment header. */
            offset = segment_start + 1u;
            continue;
        }

        parsed_any_segment = true;

        /* Continue parsing additional Vec<Entry> segments if present. */
        if (offset >= len) break;
    }

    if (!parsed_any_segment) {
        return SOL_ERR_TRUNCATED;
    }

    /* If we stopped early, only accept zero-filled padding. */
    if (offset < len) {
        bool all_zero = true;
        for (size_t i = offset; i < len; i++) {
            if (data[i] != 0) {
                all_zero = false;
                break;
            }
        }
        if (!all_zero) {
            return SOL_ERR_DECODE;
        }
    }

    return SOL_OK;
}

sol_err_t
sol_entry_batch_parse(sol_entry_batch_t* batch, const uint8_t* data, size_t len) {
    return sol_entry_batch_parse_ex(batch, data, len, true);
}

typedef struct {
    const sol_entry_batch_t* batch;
    size_t                   start_idx;
    size_t                   end_idx;
    sol_hash_t               start_hash;
    bool                     valid;
} sol_entry_verify_chunk_t;

static void*
sol_entry_verify_chunk_main(void* arg) {
    sol_entry_verify_chunk_t* chunk = (sol_entry_verify_chunk_t*)arg;
    if (!chunk || !chunk->batch) return NULL;

    sol_hash_t current_hash = chunk->start_hash;
    chunk->valid = true;

    for (size_t i = chunk->start_idx; i < chunk->end_idx; i++) {
        const sol_entry_t* entry = &chunk->batch->entries[i];
        sol_hash_t expected_hash;
        sol_entry_compute_hash(entry, &current_hash, &expected_hash);
        if (memcmp(expected_hash.bytes, entry->hash.bytes, 32) != 0) {
            chunk->valid = false;
            return NULL;
        }
        current_hash = entry->hash;
    }

    return NULL;
}

static inline uint64_t
sol_entry_verify_work_units(const sol_entry_t* entry) {
    if (!entry) return 1u;
    return entry->num_hashes ? entry->num_hashes : 1u;
}

static size_t
sol_entry_verify_parallel_threads(void) {
    size_t threads = 1u;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu >= 128) {
        threads = 32u;
    } else if (ncpu >= 96) {
        threads = 24u;
    } else if (ncpu >= 64) {
        threads = 16u;
    } else if (ncpu >= 32) {
        threads = 8u;
    }

    const char* env = getenv("SOL_ENTRY_VERIFY_PARALLEL_THREADS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long x = strtoul(env, &end, 10);
        if (end != env) {
            threads = (size_t)x;
        }
    }

    if (threads > 64u) threads = 64u;
    return threads;
}

static size_t
sol_entry_verify_parallel_min_entries(void) {
    size_t min_entries = 256u;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu >= 128) min_entries = 128u;
    else if (ncpu >= 64) min_entries = 160u;
    else if (ncpu >= 32) min_entries = 192u;

    const char* env = getenv("SOL_ENTRY_VERIFY_PARALLEL_MIN_ENTRIES");
    if (env && env[0] != '\0') {
        char* end = NULL;
        unsigned long x = strtoul(env, &end, 10);
        if (end != env) {
            min_entries = (size_t)x;
        }
    }

    if (min_entries > 65536u) min_entries = 65536u;
    return min_entries;
}

static sol_entry_verify_result_t
sol_entry_batch_verify_serial(const sol_entry_batch_t* batch, const sol_hash_t* start_hash) {
    sol_entry_verify_result_t result = {0};

    if (!batch || !start_hash) {
        result.error = SOL_ERR_INVAL;
        return result;
    }

    sol_hash_t current_hash = *start_hash;

    for (size_t i = 0; i < batch->num_entries; i++) {
        const sol_entry_t* entry = &batch->entries[i];

        /* Verify hash chain */
        sol_hash_t expected_hash;
        sol_entry_compute_hash(entry, &current_hash, &expected_hash);

        if (memcmp(expected_hash.bytes, entry->hash.bytes, 32) != 0) {
            if (sol_log_get_level() <= SOL_LOG_DEBUG) {
                char start_hex[65] = {0};
                char expected_hex[65] = {0};
                char actual_hex[65] = {0};

                (void)sol_hash_to_hex(&current_hash, start_hex, sizeof(start_hex));
                (void)sol_hash_to_hex(&expected_hash, expected_hex, sizeof(expected_hex));
                (void)sol_hash_to_hex(&entry->hash, actual_hex, sizeof(actual_hex));

                sol_log_debug(
                    "Entry hash mismatch idx=%zu num_hashes=%llu num_tx=%u start=%s expected=%s actual=%s",
                    i,
                    (unsigned long long)entry->num_hashes,
                    (unsigned)entry->num_transactions,
                    start_hex,
                    expected_hex,
                    actual_hex
                );

                /* Extra diagnostics to help pin down PoH hashing differences vs mainnet. */
                if (entry->num_transactions > 0 && entry->transactions) {
                    sol_hash_t mixin = {0};
                    sol_entry_transaction_merkle_root(entry, &mixin);

                    /* Variant: hash prev_hash num_hashes times, then mixin. */
                    sol_hash_t merkle_n = current_hash;
                    for (uint64_t hi = 0; hi < entry->num_hashes; hi++) {
                        sol_sha256_32bytes(merkle_n.bytes, merkle_n.bytes);
                    }
                    sol_sha256_ctx_t ctxn;
                    sol_sha256_init(&ctxn);
                    sol_sha256_update(&ctxn, merkle_n.bytes, 32);
                    sol_sha256_update(&ctxn, mixin.bytes, 32);
                    sol_sha256_final_bytes(&ctxn, merkle_n.bytes);

                    /* Variant: hash prev_hash (num_hashes - 1) times, then mixin (reverse order). */
                    sol_hash_t merkle_sub1_rev = current_hash;
                    uint64_t hashes_before_record = entry->num_hashes ? (entry->num_hashes - 1) : 0;
                    for (uint64_t hi = 0; hi < hashes_before_record; hi++) {
                        sol_sha256_32bytes(merkle_sub1_rev.bytes, merkle_sub1_rev.bytes);
                    }
                    sol_sha256_ctx_t ctx_rev;
                    sol_sha256_init(&ctx_rev);
                    sol_sha256_update(&ctx_rev, mixin.bytes, 32);
                    sol_sha256_update(&ctx_rev, merkle_sub1_rev.bytes, 32);
                    sol_sha256_final_bytes(&ctx_rev, merkle_sub1_rev.bytes);

                    /* Variant: hash prev_hash num_hashes times, then mixin (reverse order). */
                    sol_hash_t merkle_n_rev = current_hash;
                    for (uint64_t hi = 0; hi < entry->num_hashes; hi++) {
                        sol_sha256_32bytes(merkle_n_rev.bytes, merkle_n_rev.bytes);
                    }
                    sol_sha256_ctx_t ctxn_rev;
                    sol_sha256_init(&ctxn_rev);
                    sol_sha256_update(&ctxn_rev, mixin.bytes, 32);
                    sol_sha256_update(&ctxn_rev, merkle_n_rev.bytes, 32);
                    sol_sha256_final_bytes(&ctxn_rev, merkle_n_rev.bytes);

                    /* Variant: hash prev_hash (num_hashes - num_tx) times, then mix in each tx signature (64 bytes). */
                    sol_hash_t per_tx_sig64 = current_hash;
                    uint64_t hashes_before_txs =
                        entry->num_hashes > (uint64_t)entry->num_transactions ?
                        (entry->num_hashes - (uint64_t)entry->num_transactions) : 0;
                    for (uint64_t hi = 0; hi < hashes_before_txs; hi++) {
                        sol_sha256_32bytes(per_tx_sig64.bytes, per_tx_sig64.bytes);
                    }
                    for (uint32_t ti = 0; ti < entry->num_transactions; ti++) {
                        const sol_transaction_t* tx = &entry->transactions[ti];
                        if (!tx->signatures || tx->signatures_len == 0) {
                            memset(per_tx_sig64.bytes, 0, 32);
                            break;
                        }
                        sol_sha256_ctx_t ctx;
                        sol_sha256_init(&ctx);
                        sol_sha256_update(&ctx, per_tx_sig64.bytes, 32);
                        sol_sha256_update(&ctx, tx->signatures[0].bytes, 64);
                        sol_sha256_final_bytes(&ctx, per_tx_sig64.bytes);
                    }

                    /* Variant: same, but mix in sha256(signature) (32 bytes). */
                    sol_hash_t per_tx_sig_hash = current_hash;
                    for (uint64_t hi = 0; hi < hashes_before_txs; hi++) {
                        sol_sha256_32bytes(per_tx_sig_hash.bytes, per_tx_sig_hash.bytes);
                    }
                    for (uint32_t ti = 0; ti < entry->num_transactions; ti++) {
                        const sol_transaction_t* tx = &entry->transactions[ti];
                        if (!tx->signatures || tx->signatures_len == 0) {
                            memset(per_tx_sig_hash.bytes, 0, 32);
                            break;
                        }
                        sol_hash_t sig_hash = {0};
                        hash_leaf_signature(&tx->signatures[0], &sig_hash);

                        sol_sha256_ctx_t ctx;
                        sol_sha256_init(&ctx);
                        sol_sha256_update(&ctx, per_tx_sig_hash.bytes, 32);
                        sol_sha256_update(&ctx, sig_hash.bytes, 32);
                        sol_sha256_final_bytes(&ctx, per_tx_sig_hash.bytes);
                    }

                    /* Variant: per-tx sha256(signature), but reverse order in the hashv. */
                    sol_hash_t per_tx_sig_hash_rev = current_hash;
                    for (uint64_t hi = 0; hi < hashes_before_txs; hi++) {
                        sol_sha256_32bytes(per_tx_sig_hash_rev.bytes, per_tx_sig_hash_rev.bytes);
                    }
                    for (uint32_t ti = 0; ti < entry->num_transactions; ti++) {
                        const sol_transaction_t* tx = &entry->transactions[ti];
                        if (!tx->signatures || tx->signatures_len == 0) {
                            memset(per_tx_sig_hash_rev.bytes, 0, 32);
                            break;
                        }
                        sol_hash_t sig_hash = {0};
                        hash_leaf_signature(&tx->signatures[0], &sig_hash);

                        sol_sha256_ctx_t ctx;
                        sol_sha256_init(&ctx);
                        sol_sha256_update(&ctx, sig_hash.bytes, 32);
                        sol_sha256_update(&ctx, per_tx_sig_hash_rev.bytes, 32);
                        sol_sha256_final_bytes(&ctx, per_tx_sig_hash_rev.bytes);
                    }

                    /* Variant: per-tx mixin uses first 32 bytes of signature. */
                    sol_hash_t per_tx_sig32 = current_hash;
                    for (uint64_t hi = 0; hi < hashes_before_txs; hi++) {
                        sol_sha256_32bytes(per_tx_sig32.bytes, per_tx_sig32.bytes);
                    }
                    for (uint32_t ti = 0; ti < entry->num_transactions; ti++) {
                        const sol_transaction_t* tx = &entry->transactions[ti];
                        if (!tx->signatures || tx->signatures_len == 0) {
                            memset(per_tx_sig32.bytes, 0, 32);
                            break;
                        }
                        sol_sha256_ctx_t ctx;
                        sol_sha256_init(&ctx);
                        sol_sha256_update(&ctx, per_tx_sig32.bytes, 32);
                        sol_sha256_update(&ctx, tx->signatures[0].bytes, 32);
                        sol_sha256_final_bytes(&ctx, per_tx_sig32.bytes);
                    }

                    /* Variant: per-tx mixin uses first 32 bytes of signature, reverse order. */
                    sol_hash_t per_tx_sig32_rev = current_hash;
                    for (uint64_t hi = 0; hi < hashes_before_txs; hi++) {
                        sol_sha256_32bytes(per_tx_sig32_rev.bytes, per_tx_sig32_rev.bytes);
                    }
                    for (uint32_t ti = 0; ti < entry->num_transactions; ti++) {
                        const sol_transaction_t* tx = &entry->transactions[ti];
                        if (!tx->signatures || tx->signatures_len == 0) {
                            memset(per_tx_sig32_rev.bytes, 0, 32);
                            break;
                        }
                        sol_sha256_ctx_t ctx;
                        sol_sha256_init(&ctx);
                        sol_sha256_update(&ctx, tx->signatures[0].bytes, 32);
                        sol_sha256_update(&ctx, per_tx_sig32_rev.bytes, 32);
                        sol_sha256_final_bytes(&ctx, per_tx_sig32_rev.bytes);
                    }

                    char mixin_hex[65] = {0};
                    char merkle_n_hex[65] = {0};
                    char merkle_sub1_rev_hex[65] = {0};
                    char merkle_n_rev_hex[65] = {0};
                    char per_tx_sig64_hex[65] = {0};
                    char per_tx_sig_hash_hex[65] = {0};
                    char per_tx_sig_hash_rev_hex[65] = {0};
                    char per_tx_sig32_hex[65] = {0};
                    char per_tx_sig32_rev_hex[65] = {0};
                    (void)sol_hash_to_hex(&mixin, mixin_hex, sizeof(mixin_hex));
                    (void)sol_hash_to_hex(&merkle_n, merkle_n_hex, sizeof(merkle_n_hex));
                    (void)sol_hash_to_hex(&merkle_sub1_rev, merkle_sub1_rev_hex, sizeof(merkle_sub1_rev_hex));
                    (void)sol_hash_to_hex(&merkle_n_rev, merkle_n_rev_hex, sizeof(merkle_n_rev_hex));
                    (void)sol_hash_to_hex(&per_tx_sig64, per_tx_sig64_hex, sizeof(per_tx_sig64_hex));
                    (void)sol_hash_to_hex(&per_tx_sig_hash, per_tx_sig_hash_hex, sizeof(per_tx_sig_hash_hex));
                    (void)sol_hash_to_hex(&per_tx_sig_hash_rev, per_tx_sig_hash_rev_hex, sizeof(per_tx_sig_hash_rev_hex));
                    (void)sol_hash_to_hex(&per_tx_sig32, per_tx_sig32_hex, sizeof(per_tx_sig32_hex));
                    (void)sol_hash_to_hex(&per_tx_sig32_rev, per_tx_sig32_rev_hex, sizeof(per_tx_sig32_rev_hex));

                    sol_log_debug("PoH candidates mixin=%s merkle_n=%s merkle_sub1_rev=%s merkle_n_rev=%s per_tx_sig64=%s per_tx_sig_hash=%s per_tx_sig_hash_rev=%s per_tx_sig32=%s per_tx_sig32_rev=%s",
                                  mixin_hex,
                                  merkle_n_hex,
                                  merkle_sub1_rev_hex,
                                  merkle_n_rev_hex,
                                  per_tx_sig64_hex,
                                  per_tx_sig_hash_hex,
                                  per_tx_sig_hash_rev_hex,
                                  per_tx_sig32_hex,
                                  per_tx_sig32_rev_hex);
                }
            }

            result.valid = false;
            result.failed_entry = (uint32_t)i;
            result.error = SOL_ERR_INVALID_HASH;
            return result;
        }

        /* Move to next hash */
        current_hash = entry->hash;
        result.num_verified++;
    }

    result.valid = true;
    return result;
}

sol_entry_verify_result_t
sol_entry_batch_verify(const sol_entry_batch_t* batch, const sol_hash_t* start_hash) {
    sol_entry_verify_result_t result = {0};

    if (!batch || !start_hash) {
        result.error = SOL_ERR_INVAL;
        return result;
    }

    const size_t entry_count = batch->num_entries;
    size_t parallel_threads = sol_entry_verify_parallel_threads();
    size_t min_entries = sol_entry_verify_parallel_min_entries();

    if (parallel_threads > 1u && entry_count >= min_entries) {
        if (parallel_threads > entry_count) parallel_threads = entry_count;
        if (parallel_threads > 64u) parallel_threads = 64u;

        if (parallel_threads > 1u) {
            sol_entry_verify_chunk_t chunks[64];
            pthread_t threads[63];
            size_t started = 0;
            size_t cursor = 0;
            uint64_t total_work = 0u;
            for (size_t i = 0; i < entry_count; i++) {
                total_work += sol_entry_verify_work_units(&batch->entries[i]);
            }
            uint64_t remaining_work = total_work;

            for (size_t t = 0; t < parallel_threads; t++) {
                size_t remaining_chunks = parallel_threads - t;
                uint64_t target_work =
                    (remaining_work + (uint64_t)remaining_chunks - 1u) /
                    (uint64_t)remaining_chunks;
                if (target_work == 0u) target_work = 1u;

                size_t end = cursor;
                uint64_t chunk_work = 0u;
                while (end < entry_count) {
                    chunk_work += sol_entry_verify_work_units(&batch->entries[end]);
                    end++;
                    if (chunk_work >= target_work) break;
                    if ((entry_count - end) <= (remaining_chunks - 1u)) break;
                }
                if (end <= cursor) {
                    end = cursor + 1u;
                    chunk_work = sol_entry_verify_work_units(&batch->entries[cursor]);
                }

                chunks[t].batch = batch;
                chunks[t].start_idx = cursor;
                chunks[t].end_idx = end;
                chunks[t].start_hash = (cursor == 0u) ? *start_hash : batch->entries[cursor - 1u].hash;
                chunks[t].valid = false;
                cursor = end;
                if (chunk_work >= remaining_work) {
                    remaining_work = 0u;
                } else {
                    remaining_work -= chunk_work;
                }
            }

            bool thread_create_failed = false;
            for (size_t t = 1; t < parallel_threads; t++) {
                if (pthread_create(&threads[t - 1u], NULL, sol_entry_verify_chunk_main, &chunks[t]) != 0) {
                    thread_create_failed = true;
                    break;
                }
                started++;
            }

            /* Use caller thread for chunk 0 to avoid one extra wakeup. */
            (void)sol_entry_verify_chunk_main(&chunks[0]);

            for (size_t i = 0; i < started; i++) {
                (void)pthread_join(threads[i], NULL);
            }

            if (!thread_create_failed) {
                bool all_valid = true;
                for (size_t t = 0; t < parallel_threads; t++) {
                    if (!chunks[t].valid) {
                        all_valid = false;
                        break;
                    }
                }
                if (all_valid) {
                    result.valid = true;
                    result.num_verified =
                        (entry_count > (size_t)UINT32_MAX) ? UINT32_MAX : (uint32_t)entry_count;
                    return result;
                }
            }
        }
    }

    /* Fallback path preserves first-failure diagnostics. */
    return sol_entry_batch_verify_serial(batch, start_hash);
}

uint32_t
sol_entry_batch_transaction_count(const sol_entry_batch_t* batch) {
    if (!batch) return 0;

    uint32_t count = 0;
    for (size_t i = 0; i < batch->num_entries; i++) {
        count += batch->entries[i].num_transactions;
    }

    return count;
}

uint32_t
sol_entry_batch_tick_count(const sol_entry_batch_t* batch) {
    if (!batch) return 0;

    uint32_t count = 0;
    for (size_t i = 0; i < batch->num_entries; i++) {
        if (batch->entries[i].num_transactions == 0) {
            count++;
        }
    }

    return count;
}
