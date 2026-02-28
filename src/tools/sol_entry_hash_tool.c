/*
 * sol_entry_hash_tool.c - Debug Solana Entry/PoH hashing
 *
 * Usage:
 *   sol-entry-hash --rocksdb-path PATH --slot SLOT [--variant ID] [--start-hash HEX] [--parse-only]
 *
 * If --start-hash is not provided, attempts to derive it from the AccountsDB
 * RecentBlockhashes sysvar at ROCKSDB_PATH/accounts.
 */

#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blockstore/sol_blockstore.h"
#include "crypto/sol_sha256.h"
#include "entry/sol_entry.h"
#include "runtime/sol_accounts_db.h"
#include "runtime/sol_sysvar.h"
#include "shred/sol_shred.h"
#include "txn/sol_transaction.h"
#include "util/sol_err.h"
#include "util/sol_log.h"

#define VERSION "0.1.0"

static bool g_have_leader = false;
static sol_pubkey_t g_leader_pubkey;

static void
dump_data_shred_info(sol_blockstore_t* bs, sol_slot_t slot, uint32_t index) {
    if (!bs) return;

    uint8_t buf[SOL_SHRED_SIZE];
    size_t buf_len = sizeof(buf);
    sol_err_t err = sol_blockstore_get_shred(bs, slot, index, true, buf, &buf_len);
    if (err != SOL_OK) {
        printf("shred[%u].load_err=%s\n", (unsigned)index, sol_err_str(err));
        return;
    }

    sol_shred_t shred = {0};
    sol_err_t perr = sol_shred_parse(&shred, buf, buf_len);
    if (perr != SOL_OK) {
        printf("shred[%u].parse_err=%s\n", (unsigned)index, sol_err_str(perr));
        return;
    }
    if (shred.type != SOL_SHRED_TYPE_DATA) {
        printf("shred[%u].type=%u (not data)\n", (unsigned)index, (unsigned)shred.type);
        return;
    }

    size_t cap = 0;
    if (shred.has_merkle) {
        const size_t payload_size = (size_t)SOL_SHRED_DATA_PAYLOAD_SIZE;
        const size_t headers_size = (size_t)SOL_SHRED_DATA_HEADERS_SIZE;
        const size_t proof_bytes =
            (size_t)shred.merkle_proof_size * (size_t)SOL_SHRED_MERKLE_PROOF_ENTRY_SIZE;
        const size_t fixed = headers_size +
                             (size_t)SOL_SHRED_MERKLE_ROOT_SIZE +
                             proof_bytes +
                             (shred.resigned ? (size_t)SOL_SIGNATURE_SIZE : 0u);
        if (fixed <= payload_size) {
            cap = payload_size - fixed;
        }
    }

    bool sig_ok = false;
    if (g_have_leader) {
        sig_ok = sol_shred_verify(&shred, &g_leader_pubkey);
    }

    printf("shred[%u]: variant=0x%02x flags=0x%02x size=%u payload_len=%zu merkle=%d proof=%u resigned=%d cap=%zu%s%s\n",
           (unsigned)index,
           (unsigned)shred.variant,
           (unsigned)shred.header.data.flags,
           (unsigned)shred.header.data.size,
           (size_t)shred.payload_len,
           shred.has_merkle ? 1 : 0,
           (unsigned)shred.merkle_proof_size,
           shred.resigned ? 1 : 0,
           cap,
           g_have_leader ? " sig_ok=" : "",
           g_have_leader ? (sig_ok ? "1" : "0") : "");
}

static void
print_usage(const char* prog) {
    fprintf(stderr,
            "sol-entry-hash %s - Debug Solana Entry/PoH hashing\n"
            "\n"
            "Usage:\n"
            "  %s --rocksdb-path PATH --slot SLOT [--variant ID] [--start-hash HEX] [--leader PUBKEY] [--parse-only]\n"
            "\n"
            "Options:\n"
            "  --rocksdb-path PATH   RocksDB base directory (contains blockstore/ and accounts/)\n"
            "  --slot SLOT           Slot to inspect\n"
            "  --variant ID          Block variant id (default: 0)\n"
            "  --start-hash HEX      64-char hex start hash (optional)\n"
            "  --leader PUBKEY       Verify shred signatures against this base58 leader pubkey (optional)\n"
            "  --parse-only          Only parse entries and print counts (skip hash derivation/checks)\n"
            "  -h, --help            Show help\n"
            "  -V, --version         Show version\n",
            VERSION,
            prog);
}

static int
hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static bool
parse_hash_hex(const char* hex, sol_hash_t* out) {
    if (!hex || !out) return false;
    size_t n = strlen(hex);
    if (n != 64) return false;
    for (size_t i = 0; i < 32; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out->bytes[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static void
print_hex_bytes(const char* label, const uint8_t* data, size_t len) {
    if (!label) label = "hex";
    if (!data || len == 0) {
        printf("%s=\n", label);
        return;
    }

    printf("%s=", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", (unsigned)data[i]);
    }
    printf("\n");
}

static void
hash_n(const sol_hash_t* start, uint64_t n, sol_hash_t* out) {
    sol_hash_t cur = *start;
    for (uint64_t i = 0; i < n; i++) {
        sol_sha256_bytes(cur.bytes, 32, cur.bytes);
    }
    *out = cur;
}

static void
hash_mixin(const sol_hash_t* prev, const void* mixin, size_t mixin_len, sol_hash_t* out) {
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    sol_sha256_update(&ctx, prev->bytes, 32);
    sol_sha256_update(&ctx, mixin, mixin_len);
    sol_sha256_final_bytes(&ctx, out->bytes);
}

static void
hash_mixin_rev(const sol_hash_t* prev, const void* mixin, size_t mixin_len, sol_hash_t* out) {
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    sol_sha256_update(&ctx, mixin, mixin_len);
    sol_sha256_update(&ctx, prev->bytes, 32);
    sol_sha256_final_bytes(&ctx, out->bytes);
}

static void
hash_mixin_prefixed(const sol_hash_t* prev,
                    const void* mixin,
                    size_t mixin_len,
                    uint8_t prefix,
                    bool reverse_order,
                    sol_hash_t* out) {
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    sol_sha256_update(&ctx, &prefix, 1);
    if (reverse_order) {
        sol_sha256_update(&ctx, mixin, mixin_len);
        sol_sha256_update(&ctx, prev->bytes, 32);
    } else {
        sol_sha256_update(&ctx, prev->bytes, 32);
        sol_sha256_update(&ctx, mixin, mixin_len);
    }
    sol_sha256_final_bytes(&ctx, out->bytes);
}

static int
tx_ptr_cmp_sig64(const void* a, const void* b) {
    const sol_transaction_t* const* ta = (const sol_transaction_t* const*)a;
    const sol_transaction_t* const* tb = (const sol_transaction_t* const*)b;
    const sol_transaction_t* txa = *ta;
    const sol_transaction_t* txb = *tb;

    const sol_signature_t* sa =
        (txa && txa->signatures && txa->signatures_len > 0) ? &txa->signatures[0] : NULL;
    const sol_signature_t* sb =
        (txb && txb->signatures && txb->signatures_len > 0) ? &txb->signatures[0] : NULL;

    if (!sa && !sb) return 0;
    if (!sa) return -1;
    if (!sb) return 1;
    return memcmp(sa->bytes, sb->bytes, 64);
}

static const sol_transaction_t**
sorted_tx_ptrs_by_sig(const sol_entry_t* entry) {
    if (!entry || entry->num_transactions == 0 || !entry->transactions) return NULL;

    uint32_t n = entry->num_transactions;
    const sol_transaction_t** txs = (const sol_transaction_t**)malloc((size_t)n * sizeof(*txs));
    if (!txs) return NULL;

    for (uint32_t i = 0; i < n; i++) txs[i] = &entry->transactions[i];
    qsort(txs, n, sizeof(*txs), tx_ptr_cmp_sig64);
    return txs;
}

static void
hash_concat_sigs64(const sol_entry_t* entry, sol_hash_t* out) {
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    for (uint32_t i = 0; i < entry->num_transactions; i++) {
        const sol_transaction_t* tx = &entry->transactions[i];
        if (!tx->signatures || tx->signatures_len == 0) {
            memset(out->bytes, 0, 32);
            return;
        }
        sol_sha256_update(&ctx, tx->signatures[0].bytes, 64);
    }
    sol_sha256_final_bytes(&ctx, out->bytes);
}

static void
hash_concat_sigs64_sorted(const sol_entry_t* entry, sol_hash_t* out) {
    const sol_transaction_t** txs = sorted_tx_ptrs_by_sig(entry);
    if (!txs) {
        memset(out->bytes, 0, 32);
        return;
    }

    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    for (uint32_t i = 0; i < entry->num_transactions; i++) {
        const sol_transaction_t* tx = txs[i];
        if (!tx || !tx->signatures || tx->signatures_len == 0) {
            memset(out->bytes, 0, 32);
            free(txs);
            return;
        }
        sol_sha256_update(&ctx, tx->signatures[0].bytes, 64);
    }
    sol_sha256_final_bytes(&ctx, out->bytes);
    free(txs);
}

static void
hash_signature32(const sol_signature_t* sig, sol_hash_t* out) {
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    sol_sha256_update(&ctx, sig->bytes, 64);
    sol_sha256_final_bytes(&ctx, out->bytes);
}

static void
hash_pair32(const sol_hash_t* left, const sol_hash_t* right, sol_hash_t* out) {
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    sol_sha256_update(&ctx, left->bytes, 32);
    sol_sha256_update(&ctx, right->bytes, 32);
    sol_sha256_final_bytes(&ctx, out->bytes);
}

static void
hash_sig_leaf_prefix0(const sol_signature_t* sig, sol_hash_t* out) {
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    const uint8_t prefix = 0;
    sol_sha256_update(&ctx, &prefix, 1);
    sol_sha256_update(&ctx, sig->bytes, 64);
    sol_sha256_final_bytes(&ctx, out->bytes);
}

static void
hash_leaf32_prefix0(const sol_hash_t* leaf, sol_hash_t* out) {
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    const uint8_t prefix = 0;
    sol_sha256_update(&ctx, &prefix, 1);
    sol_sha256_update(&ctx, leaf->bytes, 32);
    sol_sha256_final_bytes(&ctx, out->bytes);
}

static void
hash_pair_prefix1(const sol_hash_t* left, const sol_hash_t* right, sol_hash_t* out) {
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    const uint8_t prefix = 1;
    sol_sha256_update(&ctx, &prefix, 1);
    sol_sha256_update(&ctx, left->bytes, 32);
    sol_sha256_update(&ctx, right->bytes, 32);
    sol_sha256_final_bytes(&ctx, out->bytes);
}

typedef struct {
    const sol_transaction_t* tx;
    sol_hash_t raw_hash;
} tx_hash_item_t;

static int
tx_hash_item_cmp_sig64(const void* a, const void* b) {
    const tx_hash_item_t* ia = (const tx_hash_item_t*)a;
    const tx_hash_item_t* ib = (const tx_hash_item_t*)b;
    const sol_signature_t* sa =
        (ia && ia->tx && ia->tx->signatures && ia->tx->signatures_len > 0) ? &ia->tx->signatures[0] : NULL;
    const sol_signature_t* sb =
        (ib && ib->tx && ib->tx->signatures && ib->tx->signatures_len > 0) ? &ib->tx->signatures[0] : NULL;
    if (!sa && !sb) return 0;
    if (!sa) return -1;
    if (!sb) return 1;
    return memcmp(sa->bytes, sb->bytes, 64);
}

static void
merkle_root_raw_tx_hashes_dup_sorted(const sol_entry_t* entry, sol_hash_t* out_root) {
    if (!entry || !out_root) return;
    if (entry->num_transactions == 0 || !entry->transactions || !entry->raw_data) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    uint32_t n = entry->num_transactions;
    tx_hash_item_t* items = (tx_hash_item_t*)malloc((size_t)n * sizeof(*items));
    if (!items) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    size_t off = 0;
    for (uint32_t i = 0; i < n; i++) {
        const sol_transaction_t* tx = &entry->transactions[i];
        if (!tx->signatures || tx->signatures_len == 0 || tx->encoded_len == 0) {
            memset(out_root->bytes, 0, 32);
            free(items);
            return;
        }
        if (off + tx->encoded_len > entry->raw_data_len) {
            memset(out_root->bytes, 0, 32);
            free(items);
            return;
        }
        items[i].tx = tx;
        sol_sha256_bytes(entry->raw_data + off, tx->encoded_len, items[i].raw_hash.bytes);
        off += tx->encoded_len;
    }

    qsort(items, n, sizeof(*items), tx_hash_item_cmp_sig64);

    sol_hash_t* hashes = (sol_hash_t*)malloc((size_t)n * sizeof(sol_hash_t));
    if (!hashes) {
        memset(out_root->bytes, 0, 32);
        free(items);
        return;
    }
    for (uint32_t i = 0; i < n; i++) hashes[i] = items[i].raw_hash;
    free(items);

    uint32_t level_size = n;
    while (level_size > 1) {
        uint32_t next_size = (level_size + 1u) / 2u;
        for (uint32_t i = 0; i < next_size; i++) {
            uint32_t left = i * 2u;
            uint32_t right = left + 1u;
            if (right >= level_size) right = left;
            hash_pair32(&hashes[left], &hashes[right], &hashes[i]);
        }
        level_size = next_size;
    }

    *out_root = hashes[0];
    free(hashes);
}

static void
merkle_root_raw_tx_hashes_dup_sorted_prefix01(const sol_entry_t* entry, sol_hash_t* out_root) {
    if (!entry || !out_root) return;
    if (entry->num_transactions == 0 || !entry->transactions || !entry->raw_data) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    uint32_t n = entry->num_transactions;
    tx_hash_item_t* items = (tx_hash_item_t*)malloc((size_t)n * sizeof(*items));
    if (!items) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    size_t off = 0;
    for (uint32_t i = 0; i < n; i++) {
        const sol_transaction_t* tx = &entry->transactions[i];
        if (!tx->signatures || tx->signatures_len == 0 || tx->encoded_len == 0) {
            memset(out_root->bytes, 0, 32);
            free(items);
            return;
        }
        if (off + tx->encoded_len > entry->raw_data_len) {
            memset(out_root->bytes, 0, 32);
            free(items);
            return;
        }
        items[i].tx = tx;
        sol_sha256_bytes(entry->raw_data + off, tx->encoded_len, items[i].raw_hash.bytes);
        off += tx->encoded_len;
    }

    qsort(items, n, sizeof(*items), tx_hash_item_cmp_sig64);

    sol_hash_t* hashes = (sol_hash_t*)malloc((size_t)n * sizeof(sol_hash_t));
    if (!hashes) {
        memset(out_root->bytes, 0, 32);
        free(items);
        return;
    }

    for (uint32_t i = 0; i < n; i++) {
        hash_leaf32_prefix0(&items[i].raw_hash, &hashes[i]);
    }
    free(items);

    uint32_t level_size = n;
    while (level_size > 1) {
        uint32_t next_size = (level_size + 1u) / 2u;
        for (uint32_t i = 0; i < next_size; i++) {
            uint32_t left = i * 2u;
            uint32_t right = left + 1u;
            if (right >= level_size) right = left;
            hash_pair_prefix1(&hashes[left], &hashes[right], &hashes[i]);
        }
        level_size = next_size;
    }

    *out_root = hashes[0];
    free(hashes);
}

static size_t
count_all_signatures(const sol_entry_t* entry) {
    if (!entry || entry->num_transactions == 0 || !entry->transactions) return 0;
    size_t total = 0;
    for (uint32_t ti = 0; ti < entry->num_transactions; ti++) {
        const sol_transaction_t* tx = &entry->transactions[ti];
        if (!tx->signatures || tx->signatures_len == 0) return 0;
        total += (size_t)tx->signatures_len;
    }
    return total;
}

static int
sig_ptr_cmp_64(const void* a, const void* b) {
    const sol_signature_t* const* pa = (const sol_signature_t* const*)a;
    const sol_signature_t* const* pb = (const sol_signature_t* const*)b;
    const sol_signature_t* sa = *pa;
    const sol_signature_t* sb = *pb;
    if (!sa && !sb) return 0;
    if (!sa) return -1;
    if (!sb) return 1;
    return memcmp(sa->bytes, sb->bytes, 64);
}

static const sol_signature_t**
sorted_sig_ptrs_all(const sol_entry_t* entry, size_t* out_n) {
    if (out_n) *out_n = 0;
    size_t n = count_all_signatures(entry);
    if (n == 0) return NULL;

    const sol_signature_t** sigs = (const sol_signature_t**)malloc(n * sizeof(*sigs));
    if (!sigs) return NULL;

    size_t idx = 0;
    for (uint32_t ti = 0; ti < entry->num_transactions; ti++) {
        const sol_transaction_t* tx = &entry->transactions[ti];
        for (uint8_t si = 0; si < tx->signatures_len; si++) {
            sigs[idx++] = &tx->signatures[si];
        }
    }
    qsort(sigs, n, sizeof(*sigs), sig_ptr_cmp_64);
    if (out_n) *out_n = n;
    return sigs;
}

static void
merkle_root_all_sigs_dup_noprefix(const sol_entry_t* entry, sol_hash_t* out_root) {
    if (!entry || !out_root) return;

    size_t n = count_all_signatures(entry);
    if (n == 0) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    sol_hash_t* hashes = (sol_hash_t*)malloc(n * sizeof(sol_hash_t));
    if (!hashes) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    size_t idx = 0;
    for (uint32_t ti = 0; ti < entry->num_transactions; ti++) {
        const sol_transaction_t* tx = &entry->transactions[ti];
        for (uint8_t si = 0; si < tx->signatures_len; si++) {
            hash_signature32(&tx->signatures[si], &hashes[idx++]);
        }
    }

    uint32_t level_size = (uint32_t)n;
    while (level_size > 1) {
        uint32_t next_size = (level_size + 1u) / 2u;
        for (uint32_t i = 0; i < next_size; i++) {
            uint32_t left = i * 2u;
            uint32_t right = left + 1u;
            if (right >= level_size) right = left;
            hash_pair32(&hashes[left], &hashes[right], &hashes[i]);
        }
        level_size = next_size;
    }

    *out_root = hashes[0];
    free(hashes);
}

static void
merkle_root_all_sigs_dup_noprefix_sorted(const sol_entry_t* entry, sol_hash_t* out_root) {
    if (!entry || !out_root) return;

    size_t n = 0;
    const sol_signature_t** sigs = sorted_sig_ptrs_all(entry, &n);
    if (!sigs || n == 0) {
        memset(out_root->bytes, 0, 32);
        free(sigs);
        return;
    }

    sol_hash_t* hashes = (sol_hash_t*)malloc(n * sizeof(sol_hash_t));
    if (!hashes) {
        memset(out_root->bytes, 0, 32);
        free(sigs);
        return;
    }

    for (size_t i = 0; i < n; i++) {
        hash_signature32(sigs[i], &hashes[i]);
    }
    free(sigs);

    uint32_t level_size = (uint32_t)n;
    while (level_size > 1) {
        uint32_t next_size = (level_size + 1u) / 2u;
        for (uint32_t i = 0; i < next_size; i++) {
            uint32_t left = i * 2u;
            uint32_t right = left + 1u;
            if (right >= level_size) right = left;
            hash_pair32(&hashes[left], &hashes[right], &hashes[i]);
        }
        level_size = next_size;
    }

    *out_root = hashes[0];
    free(hashes);
}

static void
merkle_root_all_sigs_dup_prefix01(const sol_entry_t* entry, sol_hash_t* out_root) {
    if (!entry || !out_root) return;

    size_t n = count_all_signatures(entry);
    if (n == 0) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    sol_hash_t* hashes = (sol_hash_t*)malloc(n * sizeof(sol_hash_t));
    if (!hashes) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    size_t idx = 0;
    for (uint32_t ti = 0; ti < entry->num_transactions; ti++) {
        const sol_transaction_t* tx = &entry->transactions[ti];
        for (uint8_t si = 0; si < tx->signatures_len; si++) {
            hash_sig_leaf_prefix0(&tx->signatures[si], &hashes[idx++]);
        }
    }

    uint32_t level_size = (uint32_t)n;
    while (level_size > 1) {
        uint32_t next_size = (level_size + 1u) / 2u;
        for (uint32_t i = 0; i < next_size; i++) {
            uint32_t left = i * 2u;
            uint32_t right = left + 1u;
            if (right >= level_size) right = left;
            hash_pair_prefix1(&hashes[left], &hashes[right], &hashes[i]);
        }
        level_size = next_size;
    }

    *out_root = hashes[0];
    free(hashes);
}

static void
merkle_root_all_sigs_dup_prefix01_sorted(const sol_entry_t* entry, sol_hash_t* out_root) {
    if (!entry || !out_root) return;

    size_t n = 0;
    const sol_signature_t** sigs = sorted_sig_ptrs_all(entry, &n);
    if (!sigs || n == 0) {
        memset(out_root->bytes, 0, 32);
        free(sigs);
        return;
    }

    sol_hash_t* hashes = (sol_hash_t*)malloc(n * sizeof(sol_hash_t));
    if (!hashes) {
        memset(out_root->bytes, 0, 32);
        free(sigs);
        return;
    }

    for (size_t i = 0; i < n; i++) {
        hash_sig_leaf_prefix0(sigs[i], &hashes[i]);
    }
    free(sigs);

    uint32_t level_size = (uint32_t)n;
    while (level_size > 1) {
        uint32_t next_size = (level_size + 1u) / 2u;
        for (uint32_t i = 0; i < next_size; i++) {
            uint32_t left = i * 2u;
            uint32_t right = left + 1u;
            if (right >= level_size) right = left;
            hash_pair_prefix1(&hashes[left], &hashes[right], &hashes[i]);
        }
        level_size = next_size;
    }

    *out_root = hashes[0];
    free(hashes);
}

static void
merkle_root_all_sigs_dup_sigsha_prefix01(const sol_entry_t* entry, sol_hash_t* out_root) {
    if (!entry || !out_root) return;

    size_t n = count_all_signatures(entry);
    if (n == 0) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    sol_hash_t* hashes = (sol_hash_t*)malloc(n * sizeof(sol_hash_t));
    if (!hashes) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    /* leaf = sha256(0x00 || sha256(sig64)) */
    size_t idx = 0;
    for (uint32_t ti = 0; ti < entry->num_transactions; ti++) {
        const sol_transaction_t* tx = &entry->transactions[ti];
        for (uint8_t si = 0; si < tx->signatures_len; si++) {
            sol_hash_t sigsha = {0};
            hash_signature32(&tx->signatures[si], &sigsha);
            sol_sha256_ctx_t ctx;
            sol_sha256_init(&ctx);
            const uint8_t prefix = 0;
            sol_sha256_update(&ctx, &prefix, 1);
            sol_sha256_update(&ctx, sigsha.bytes, 32);
            sol_sha256_final_bytes(&ctx, hashes[idx++].bytes);
        }
    }

    uint32_t level_size = (uint32_t)n;
    while (level_size > 1) {
        uint32_t next_size = (level_size + 1u) / 2u;
        for (uint32_t i = 0; i < next_size; i++) {
            uint32_t left = i * 2u;
            uint32_t right = left + 1u;
            if (right >= level_size) right = left;
            hash_pair_prefix1(&hashes[left], &hashes[right], &hashes[i]);
        }
        level_size = next_size;
    }

    *out_root = hashes[0];
    free(hashes);
}

static void
merkle_root_sig_hashes_dup_sorted(const sol_entry_t* entry, sol_hash_t* out_root) {
    if (!entry || !out_root) return;
    if (entry->num_transactions == 0 || !entry->transactions) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    const sol_transaction_t** txs = sorted_tx_ptrs_by_sig(entry);
    if (!txs) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    uint32_t n = entry->num_transactions;
    sol_hash_t* hashes = (sol_hash_t*)malloc((size_t)n * sizeof(sol_hash_t));
    if (!hashes) {
        free(txs);
        memset(out_root->bytes, 0, 32);
        return;
    }

    for (uint32_t i = 0; i < n; i++) {
        const sol_transaction_t* tx = txs[i];
        if (!tx || !tx->signatures || tx->signatures_len == 0) {
            memset(out_root->bytes, 0, 32);
            free(hashes);
            free(txs);
            return;
        }
        hash_signature32(&tx->signatures[0], &hashes[i]);
    }

    uint32_t level_size = n;
    while (level_size > 1) {
        uint32_t next_size = (level_size + 1u) / 2u;
        for (uint32_t i = 0; i < next_size; i++) {
            uint32_t left = i * 2u;
            uint32_t right = left + 1u;
            if (right >= level_size) right = left; /* duplicate */
            hash_pair32(&hashes[left], &hashes[right], &hashes[i]);
        }
        level_size = next_size;
    }

    *out_root = hashes[0];
    free(hashes);
    free(txs);
}

static void
merkle_root_sig_hashes_carry_sorted(const sol_entry_t* entry, sol_hash_t* out_root) {
    if (!entry || !out_root) return;
    if (entry->num_transactions == 0 || !entry->transactions) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    const sol_transaction_t** txs = sorted_tx_ptrs_by_sig(entry);
    if (!txs) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    uint32_t n = entry->num_transactions;
    sol_hash_t* hashes = (sol_hash_t*)malloc((size_t)n * sizeof(sol_hash_t));
    if (!hashes) {
        free(txs);
        memset(out_root->bytes, 0, 32);
        return;
    }

    for (uint32_t i = 0; i < n; i++) {
        const sol_transaction_t* tx = txs[i];
        if (!tx || !tx->signatures || tx->signatures_len == 0) {
            memset(out_root->bytes, 0, 32);
            free(hashes);
            free(txs);
            return;
        }
        hash_signature32(&tx->signatures[0], &hashes[i]);
    }

    uint32_t level_size = n;
    while (level_size > 1) {
        uint32_t next_size = (level_size + 1u) / 2u;
        for (uint32_t i = 0; i < next_size; i++) {
            uint32_t left = i * 2u;
            uint32_t right = left + 1u;
            if (right >= level_size) {
                hashes[i] = hashes[left]; /* carry */
            } else {
                hash_pair32(&hashes[left], &hashes[right], &hashes[i]);
            }
        }
        level_size = next_size;
    }

    *out_root = hashes[0];
    free(hashes);
    free(txs);
}

static uint32_t
next_pow2_u32(uint32_t x) {
    if (x <= 1u) return 1u;
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    return x + 1u;
}

static void
merkle_root_sig_hashes_pow2_dup_sorted(const sol_entry_t* entry, sol_hash_t* out_root) {
    if (!entry || !out_root) return;
    if (entry->num_transactions == 0 || !entry->transactions) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    const sol_transaction_t** txs = sorted_tx_ptrs_by_sig(entry);
    if (!txs) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    uint32_t n = entry->num_transactions;
    uint32_t m = next_pow2_u32(n);
    sol_hash_t* hashes = (sol_hash_t*)malloc((size_t)m * sizeof(sol_hash_t));
    if (!hashes) {
        free(txs);
        memset(out_root->bytes, 0, 32);
        return;
    }

    for (uint32_t i = 0; i < n; i++) {
        const sol_transaction_t* tx = txs[i];
        if (!tx || !tx->signatures || tx->signatures_len == 0) {
            memset(out_root->bytes, 0, 32);
            free(hashes);
            free(txs);
            return;
        }
        hash_signature32(&tx->signatures[0], &hashes[i]);
    }

    for (uint32_t i = n; i < m; i++) {
        hashes[i] = hashes[n - 1u]; /* pad with last */
    }

    uint32_t level_size = m;
    while (level_size > 1u) {
        for (uint32_t i = 0; i < (level_size / 2u); i++) {
            hash_pair32(&hashes[i * 2u], &hashes[i * 2u + 1u], &hashes[i]);
        }
        level_size /= 2u;
    }

    *out_root = hashes[0];
    free(hashes);
    free(txs);
}

static void
merkle_root_sig_hashes_pow2_zero_sorted(const sol_entry_t* entry, sol_hash_t* out_root) {
    if (!entry || !out_root) return;
    if (entry->num_transactions == 0 || !entry->transactions) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    const sol_transaction_t** txs = sorted_tx_ptrs_by_sig(entry);
    if (!txs) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    uint32_t n = entry->num_transactions;
    uint32_t m = next_pow2_u32(n);
    sol_hash_t* hashes = (sol_hash_t*)malloc((size_t)m * sizeof(sol_hash_t));
    if (!hashes) {
        free(txs);
        memset(out_root->bytes, 0, 32);
        return;
    }

    for (uint32_t i = 0; i < n; i++) {
        const sol_transaction_t* tx = txs[i];
        if (!tx || !tx->signatures || tx->signatures_len == 0) {
            memset(out_root->bytes, 0, 32);
            free(hashes);
            free(txs);
            return;
        }
        hash_signature32(&tx->signatures[0], &hashes[i]);
    }

    for (uint32_t i = n; i < m; i++) {
        memset(hashes[i].bytes, 0, 32);
    }

    uint32_t level_size = m;
    while (level_size > 1u) {
        for (uint32_t i = 0; i < (level_size / 2u); i++) {
            hash_pair32(&hashes[i * 2u], &hashes[i * 2u + 1u], &hashes[i]);
        }
        level_size /= 2u;
    }

    *out_root = hashes[0];
    free(hashes);
    free(txs);
}

static void
merkle_root_sig_hashes_dup_sorted_prefix01(const sol_entry_t* entry, sol_hash_t* out_root) {
    if (!entry || !out_root) return;
    if (entry->num_transactions == 0 || !entry->transactions) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    const sol_transaction_t** txs = sorted_tx_ptrs_by_sig(entry);
    if (!txs) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    uint32_t n = entry->num_transactions;
    sol_hash_t* hashes = (sol_hash_t*)malloc((size_t)n * sizeof(sol_hash_t));
    if (!hashes) {
        free(txs);
        memset(out_root->bytes, 0, 32);
        return;
    }

    for (uint32_t i = 0; i < n; i++) {
        const sol_transaction_t* tx = txs[i];
        if (!tx || !tx->signatures || tx->signatures_len == 0) {
            memset(out_root->bytes, 0, 32);
            free(hashes);
            free(txs);
            return;
        }
        sol_hash_t sigsha = {0};
        hash_signature32(&tx->signatures[0], &sigsha);
        hash_leaf32_prefix0(&sigsha, &hashes[i]);
    }
    free(txs);

    uint32_t level_size = n;
    while (level_size > 1) {
        uint32_t next_size = (level_size + 1u) / 2u;
        for (uint32_t i = 0; i < next_size; i++) {
            uint32_t left = i * 2u;
            uint32_t right = left + 1u;
            if (right >= level_size) right = left; /* duplicate */
            hash_pair_prefix1(&hashes[left], &hashes[right], &hashes[i]);
        }
        level_size = next_size;
    }

    *out_root = hashes[0];
    free(hashes);
}

static void
merkle_root_tx_hashes_dup_sorted(const sol_entry_t* entry, sol_hash_t* out_root) {
    if (!entry || !out_root) return;
    if (entry->num_transactions == 0 || !entry->transactions) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    const sol_transaction_t** txs = sorted_tx_ptrs_by_sig(entry);
    if (!txs) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    uint32_t n = entry->num_transactions;
    sol_hash_t* hashes = (sol_hash_t*)malloc((size_t)n * sizeof(sol_hash_t));
    if (!hashes) {
        free(txs);
        memset(out_root->bytes, 0, 32);
        return;
    }

    for (uint32_t i = 0; i < n; i++) {
        const sol_transaction_t* tx = txs[i];
        if (!tx || sol_transaction_hash(tx, &hashes[i]) != SOL_OK) {
            memset(out_root->bytes, 0, 32);
            free(hashes);
            free(txs);
            return;
        }
    }

    uint32_t level_size = n;
    while (level_size > 1) {
        uint32_t next_size = (level_size + 1u) / 2u;
        for (uint32_t i = 0; i < next_size; i++) {
            uint32_t left = i * 2u;
            uint32_t right = left + 1u;
            if (right >= level_size) right = left; /* duplicate */
            hash_pair32(&hashes[left], &hashes[right], &hashes[i]);
        }
        level_size = next_size;
    }

    *out_root = hashes[0];
    free(hashes);
    free(txs);
}

static void
merkle_root_tx_hashes_carry_sorted(const sol_entry_t* entry, sol_hash_t* out_root) {
    if (!entry || !out_root) return;
    if (entry->num_transactions == 0 || !entry->transactions) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    const sol_transaction_t** txs = sorted_tx_ptrs_by_sig(entry);
    if (!txs) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    uint32_t n = entry->num_transactions;
    sol_hash_t* hashes = (sol_hash_t*)malloc((size_t)n * sizeof(sol_hash_t));
    if (!hashes) {
        free(txs);
        memset(out_root->bytes, 0, 32);
        return;
    }

    for (uint32_t i = 0; i < n; i++) {
        const sol_transaction_t* tx = txs[i];
        if (!tx || sol_transaction_hash(tx, &hashes[i]) != SOL_OK) {
            memset(out_root->bytes, 0, 32);
            free(hashes);
            free(txs);
            return;
        }
    }

    uint32_t level_size = n;
    while (level_size > 1) {
        uint32_t next_size = (level_size + 1u) / 2u;
        for (uint32_t i = 0; i < next_size; i++) {
            uint32_t left = i * 2u;
            uint32_t right = left + 1u;
            if (right >= level_size) {
                hashes[i] = hashes[left]; /* carry */
            } else {
                hash_pair32(&hashes[left], &hashes[right], &hashes[i]);
            }
        }
        level_size = next_size;
    }

    *out_root = hashes[0];
    free(hashes);
    free(txs);
}

static void
merkle_root_msg_hashes_dup_sorted(const sol_entry_t* entry, sol_hash_t* out_root) {
    if (!entry || !out_root) return;
    if (entry->num_transactions == 0 || !entry->transactions) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    const sol_transaction_t** txs = sorted_tx_ptrs_by_sig(entry);
    if (!txs) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    uint32_t n = entry->num_transactions;
    sol_hash_t* hashes = (sol_hash_t*)malloc((size_t)n * sizeof(sol_hash_t));
    if (!hashes) {
        free(txs);
        memset(out_root->bytes, 0, 32);
        return;
    }

    for (uint32_t i = 0; i < n; i++) {
        const sol_transaction_t* tx = txs[i];
        if (!tx || !tx->message_data || tx->message_data_len == 0) {
            memset(out_root->bytes, 0, 32);
            free(hashes);
            free(txs);
            return;
        }
        sol_sha256_bytes(tx->message_data, tx->message_data_len, hashes[i].bytes);
    }

    uint32_t level_size = n;
    while (level_size > 1) {
        uint32_t next_size = (level_size + 1u) / 2u;
        for (uint32_t i = 0; i < next_size; i++) {
            uint32_t left = i * 2u;
            uint32_t right = left + 1u;
            if (right >= level_size) right = left; /* duplicate */
            hash_pair32(&hashes[left], &hashes[right], &hashes[i]);
        }
        level_size = next_size;
    }

    *out_root = hashes[0];
    free(hashes);
    free(txs);
}

static void
merkle_root_msg_hashes_carry_sorted(const sol_entry_t* entry, sol_hash_t* out_root) {
    if (!entry || !out_root) return;
    if (entry->num_transactions == 0 || !entry->transactions) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    const sol_transaction_t** txs = sorted_tx_ptrs_by_sig(entry);
    if (!txs) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    uint32_t n = entry->num_transactions;
    sol_hash_t* hashes = (sol_hash_t*)malloc((size_t)n * sizeof(sol_hash_t));
    if (!hashes) {
        free(txs);
        memset(out_root->bytes, 0, 32);
        return;
    }

    for (uint32_t i = 0; i < n; i++) {
        const sol_transaction_t* tx = txs[i];
        if (!tx || !tx->message_data || tx->message_data_len == 0) {
            memset(out_root->bytes, 0, 32);
            free(hashes);
            free(txs);
            return;
        }
        sol_sha256_bytes(tx->message_data, tx->message_data_len, hashes[i].bytes);
    }

    uint32_t level_size = n;
    while (level_size > 1) {
        uint32_t next_size = (level_size + 1u) / 2u;
        for (uint32_t i = 0; i < next_size; i++) {
            uint32_t left = i * 2u;
            uint32_t right = left + 1u;
            if (right >= level_size) {
                hashes[i] = hashes[left]; /* carry */
            } else {
                hash_pair32(&hashes[left], &hashes[right], &hashes[i]);
            }
        }
        level_size = next_size;
    }

    *out_root = hashes[0];
    free(hashes);
    free(txs);
}

static void
merkle_root_sig_hashes_carry(const sol_entry_t* entry, sol_hash_t* out_root) {
    if (!entry || !out_root) return;
    if (entry->num_transactions == 0 || !entry->transactions) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    uint32_t n = entry->num_transactions;
    sol_hash_t* hashes = (sol_hash_t*)malloc((size_t)n * sizeof(sol_hash_t));
    if (!hashes) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    for (uint32_t i = 0; i < n; i++) {
        const sol_transaction_t* tx = &entry->transactions[i];
        if (!tx->signatures || tx->signatures_len == 0) {
            memset(out_root->bytes, 0, 32);
            free(hashes);
            return;
        }
        hash_signature32(&tx->signatures[0], &hashes[i]);
    }

    uint32_t level_size = n;
    while (level_size > 1) {
        uint32_t next_size = (level_size + 1u) / 2u;
        for (uint32_t i = 0; i < next_size; i++) {
            uint32_t left = i * 2u;
            uint32_t right = left + 1u;
            if (right >= level_size) {
                hashes[i] = hashes[left]; /* carry */
            } else {
                hash_pair32(&hashes[left], &hashes[right], &hashes[i]);
            }
        }
        level_size = next_size;
    }

    *out_root = hashes[0];
    free(hashes);
}

static void
merkle_root_sig_hashes_dup(const sol_entry_t* entry, sol_hash_t* out_root) {
    if (!entry || !out_root) return;
    if (entry->num_transactions == 0 || !entry->transactions) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    uint32_t n = entry->num_transactions;
    sol_hash_t* hashes = (sol_hash_t*)malloc((size_t)n * sizeof(sol_hash_t));
    if (!hashes) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    for (uint32_t i = 0; i < n; i++) {
        const sol_transaction_t* tx = &entry->transactions[i];
        if (!tx->signatures || tx->signatures_len == 0) {
            memset(out_root->bytes, 0, 32);
            free(hashes);
            return;
        }
        hash_signature32(&tx->signatures[0], &hashes[i]);
    }

    uint32_t level_size = n;
    while (level_size > 1) {
        uint32_t next_size = (level_size + 1u) / 2u;
        for (uint32_t i = 0; i < next_size; i++) {
            uint32_t left = i * 2u;
            uint32_t right = left + 1u;
            if (right >= level_size) right = left; /* duplicate */
            hash_pair32(&hashes[left], &hashes[right], &hashes[i]);
        }
        level_size = next_size;
    }

    *out_root = hashes[0];
    free(hashes);
}

static void
merkle_root_sig_halves_dup(const sol_entry_t* entry, size_t sig_off, sol_hash_t* out_root) {
    if (!entry || !out_root) return;
    if (entry->num_transactions == 0 || !entry->transactions) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    uint32_t n = entry->num_transactions;
    sol_hash_t* hashes = (sol_hash_t*)malloc((size_t)n * sizeof(sol_hash_t));
    if (!hashes) {
        memset(out_root->bytes, 0, 32);
        return;
    }

    for (uint32_t i = 0; i < n; i++) {
        const sol_transaction_t* tx = &entry->transactions[i];
        if (!tx->signatures || tx->signatures_len == 0) {
            memset(out_root->bytes, 0, 32);
            free(hashes);
            return;
        }
        memcpy(hashes[i].bytes, tx->signatures[0].bytes + sig_off, 32);
    }

    uint32_t level_size = n;
    while (level_size > 1) {
        uint32_t next_size = (level_size + 1u) / 2u;
        for (uint32_t i = 0; i < next_size; i++) {
            uint32_t left = i * 2u;
            uint32_t right = left + 1u;
            if (right >= level_size) right = left; /* duplicate */
            hash_pair32(&hashes[left], &hashes[right], &hashes[i]);
        }
        level_size = next_size;
    }

    *out_root = hashes[0];
    free(hashes);
}

static void
hash_concat_sig_hashes32(const sol_entry_t* entry, sol_hash_t* out) {
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    for (uint32_t i = 0; i < entry->num_transactions; i++) {
        const sol_transaction_t* tx = &entry->transactions[i];
        if (!tx->signatures || tx->signatures_len == 0) {
            memset(out->bytes, 0, 32);
            return;
        }
        sol_hash_t h = {0};
        hash_signature32(&tx->signatures[0], &h);
        sol_sha256_update(&ctx, h.bytes, 32);
    }
    sol_sha256_final_bytes(&ctx, out->bytes);
}

static void
hash_concat_sig_hashes32_sorted(const sol_entry_t* entry, sol_hash_t* out) {
    const sol_transaction_t** txs = sorted_tx_ptrs_by_sig(entry);
    if (!txs) {
        memset(out->bytes, 0, 32);
        return;
    }

    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    for (uint32_t i = 0; i < entry->num_transactions; i++) {
        const sol_transaction_t* tx = txs[i];
        if (!tx || !tx->signatures || tx->signatures_len == 0) {
            memset(out->bytes, 0, 32);
            free(txs);
            return;
        }
        sol_hash_t h = {0};
        hash_signature32(&tx->signatures[0], &h);
        sol_sha256_update(&ctx, h.bytes, 32);
    }
    sol_sha256_final_bytes(&ctx, out->bytes);
    free(txs);
}

static void
hash_concat_tx_hashes32(const sol_entry_t* entry, sol_hash_t* out) {
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    for (uint32_t i = 0; i < entry->num_transactions; i++) {
        const sol_transaction_t* tx = &entry->transactions[i];
        sol_hash_t h = {0};
        if (sol_transaction_hash(tx, &h) != SOL_OK) {
            memset(out->bytes, 0, 32);
            return;
        }
        sol_sha256_update(&ctx, h.bytes, 32);
    }
    sol_sha256_final_bytes(&ctx, out->bytes);
}

static void
hash_concat_tx_hashes32_sorted(const sol_entry_t* entry, sol_hash_t* out) {
    const sol_transaction_t** txs = sorted_tx_ptrs_by_sig(entry);
    if (!txs) {
        memset(out->bytes, 0, 32);
        return;
    }

    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    for (uint32_t i = 0; i < entry->num_transactions; i++) {
        const sol_transaction_t* tx = txs[i];
        sol_hash_t h = {0};
        if (!tx || sol_transaction_hash(tx, &h) != SOL_OK) {
            memset(out->bytes, 0, 32);
            free(txs);
            return;
        }
        sol_sha256_update(&ctx, h.bytes, 32);
    }
    sol_sha256_final_bytes(&ctx, out->bytes);
    free(txs);
}

static void
hash_concat_msg_hashes32(const sol_entry_t* entry, sol_hash_t* out) {
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    for (uint32_t i = 0; i < entry->num_transactions; i++) {
        const sol_transaction_t* tx = &entry->transactions[i];
        if (!tx->message_data || tx->message_data_len == 0) {
            memset(out->bytes, 0, 32);
            return;
        }
        sol_hash_t h = {0};
        sol_sha256_bytes(tx->message_data, tx->message_data_len, h.bytes);
        sol_sha256_update(&ctx, h.bytes, 32);
    }
    sol_sha256_final_bytes(&ctx, out->bytes);
}

static void
hash_concat_msg_hashes32_sorted(const sol_entry_t* entry, sol_hash_t* out) {
    const sol_transaction_t** txs = sorted_tx_ptrs_by_sig(entry);
    if (!txs) {
        memset(out->bytes, 0, 32);
        return;
    }

    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    for (uint32_t i = 0; i < entry->num_transactions; i++) {
        const sol_transaction_t* tx = txs[i];
        if (!tx || !tx->message_data || tx->message_data_len == 0) {
            memset(out->bytes, 0, 32);
            free(txs);
            return;
        }
        sol_hash_t h = {0};
        sol_sha256_bytes(tx->message_data, tx->message_data_len, h.bytes);
        sol_sha256_update(&ctx, h.bytes, 32);
    }
    sol_sha256_final_bytes(&ctx, out->bytes);
    free(txs);
}

static void
hash_raw_tx_bytes(const sol_entry_t* entry, sol_hash_t* out) {
    if (!entry || !out) return;
    if (!entry->raw_data || entry->raw_data_len == 0) {
        memset(out->bytes, 0, 32);
        return;
    }
    sol_sha256_bytes(entry->raw_data, entry->raw_data_len, out->bytes);
}

static void
hash_tx_vec_bincode(const sol_entry_t* entry, sol_hash_t* out) {
    if (!entry || !out) return;
    if (!entry->raw_data || entry->raw_data_len == 0) {
        memset(out->bytes, 0, 32);
        return;
    }

    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);

    uint64_t n = (uint64_t)entry->num_transactions;
    sol_sha256_update(&ctx, &n, sizeof(n)); /* bincode Vec len is u64 LE */
    sol_sha256_update(&ctx, entry->raw_data, entry->raw_data_len);
    sol_sha256_final_bytes(&ctx, out->bytes);
}

static void
hash_record_concat_sig64(const sol_hash_t* prev, const sol_entry_t* entry, bool reverse_order, sol_hash_t* out) {
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    if (!reverse_order) {
        sol_sha256_update(&ctx, prev->bytes, 32);
    }
    for (uint32_t i = 0; i < entry->num_transactions; i++) {
        const sol_transaction_t* tx = &entry->transactions[i];
        if (!tx->signatures || tx->signatures_len == 0) {
            memset(out->bytes, 0, 32);
            return;
        }
        sol_sha256_update(&ctx, tx->signatures[0].bytes, 64);
    }
    if (reverse_order) {
        sol_sha256_update(&ctx, prev->bytes, 32);
    }
    sol_sha256_final_bytes(&ctx, out->bytes);
}

static void
hash_record_concat_sig_hash32(const sol_hash_t* prev, const sol_entry_t* entry, bool reverse_order, sol_hash_t* out) {
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    if (!reverse_order) {
        sol_sha256_update(&ctx, prev->bytes, 32);
    }
    for (uint32_t i = 0; i < entry->num_transactions; i++) {
        const sol_transaction_t* tx = &entry->transactions[i];
        if (!tx->signatures || tx->signatures_len == 0) {
            memset(out->bytes, 0, 32);
            return;
        }
        sol_hash_t h = {0};
        hash_signature32(&tx->signatures[0], &h);
        sol_sha256_update(&ctx, h.bytes, 32);
    }
    if (reverse_order) {
        sol_sha256_update(&ctx, prev->bytes, 32);
    }
    sol_sha256_final_bytes(&ctx, out->bytes);
}

static void
hash_record_concat_tx_hash32(const sol_hash_t* prev, const sol_entry_t* entry, bool reverse_order, sol_hash_t* out) {
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    if (!reverse_order) {
        sol_sha256_update(&ctx, prev->bytes, 32);
    }
    for (uint32_t i = 0; i < entry->num_transactions; i++) {
        const sol_transaction_t* tx = &entry->transactions[i];
        sol_hash_t h = {0};
        if (sol_transaction_hash(tx, &h) != SOL_OK) {
            memset(out->bytes, 0, 32);
            return;
        }
        sol_sha256_update(&ctx, h.bytes, 32);
    }
    if (reverse_order) {
        sol_sha256_update(&ctx, prev->bytes, 32);
    }
    sol_sha256_final_bytes(&ctx, out->bytes);
}

static void
hash_record_concat_msg_hash32(const sol_hash_t* prev, const sol_entry_t* entry, bool reverse_order, sol_hash_t* out) {
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    if (!reverse_order) {
        sol_sha256_update(&ctx, prev->bytes, 32);
    }
    for (uint32_t i = 0; i < entry->num_transactions; i++) {
        const sol_transaction_t* tx = &entry->transactions[i];
        if (!tx->message_data || tx->message_data_len == 0) {
            memset(out->bytes, 0, 32);
            return;
        }
        sol_hash_t h = {0};
        sol_sha256_bytes(tx->message_data, tx->message_data_len, h.bytes);
        sol_sha256_update(&ctx, h.bytes, 32);
    }
    if (reverse_order) {
        sol_sha256_update(&ctx, prev->bytes, 32);
    }
    sol_sha256_final_bytes(&ctx, out->bytes);
}

static void
hash_record_raw_tx_bytes(const sol_hash_t* prev, const sol_entry_t* entry, bool reverse_order, sol_hash_t* out) {
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    if (!entry->raw_data || entry->raw_data_len == 0) {
        memset(out->bytes, 0, 32);
        return;
    }
    if (!reverse_order) {
        sol_sha256_update(&ctx, prev->bytes, 32);
        sol_sha256_update(&ctx, entry->raw_data, entry->raw_data_len);
    } else {
        sol_sha256_update(&ctx, entry->raw_data, entry->raw_data_len);
        sol_sha256_update(&ctx, prev->bytes, 32);
    }
    sol_sha256_final_bytes(&ctx, out->bytes);
}

static void
hash_record_tx_vec_bincode(const sol_hash_t* prev, const sol_entry_t* entry, bool reverse_order, sol_hash_t* out) {
    sol_sha256_ctx_t ctx;
    sol_sha256_init(&ctx);
    if (!entry->raw_data || entry->raw_data_len == 0) {
        memset(out->bytes, 0, 32);
        return;
    }

    uint64_t n = (uint64_t)entry->num_transactions;
    if (!reverse_order) {
        sol_sha256_update(&ctx, prev->bytes, 32);
        sol_sha256_update(&ctx, &n, sizeof(n));
        sol_sha256_update(&ctx, entry->raw_data, entry->raw_data_len);
    } else {
        sol_sha256_update(&ctx, &n, sizeof(n));
        sol_sha256_update(&ctx, entry->raw_data, entry->raw_data_len);
        sol_sha256_update(&ctx, prev->bytes, 32);
    }
    sol_sha256_final_bytes(&ctx, out->bytes);
}

static sol_hash_t
per_tx_mix(const sol_hash_t* start,
           uint64_t prehashes,
           const sol_entry_t* entry,
           const uint8_t* (*tx_data)(const sol_transaction_t* tx, size_t* len, sol_hash_t* tmp),
           bool reverse_order) {
    sol_hash_t cur = *start;
    hash_n(&cur, prehashes, &cur);

    for (uint32_t i = 0; i < entry->num_transactions; i++) {
        const sol_transaction_t* tx = &entry->transactions[i];
        size_t len = 0;
        sol_hash_t tmp = {0};
        const uint8_t* data = tx_data(tx, &len, &tmp);
        if (!data || len == 0) {
            memset(cur.bytes, 0, 32);
            return cur;
        }
        if (reverse_order) {
            hash_mixin_rev(&cur, data, len, &cur);
        } else {
            hash_mixin(&cur, data, len, &cur);
        }
    }
    return cur;
}

static const uint8_t*
tx_data_sig64(const sol_transaction_t* tx, size_t* len, sol_hash_t* tmp) {
    (void)tmp;
    if (!tx || !len || !tx->signatures || tx->signatures_len == 0) return NULL;
    *len = 64;
    return tx->signatures[0].bytes;
}

static const uint8_t*
tx_data_sig_hash32(const sol_transaction_t* tx, size_t* len, sol_hash_t* tmp) {
    if (!tx || !len || !tmp || !tx->signatures || tx->signatures_len == 0) return NULL;
    hash_signature32(&tx->signatures[0], tmp);
    *len = 32;
    return tmp->bytes;
}

static const uint8_t*
tx_data_tx_hash32(const sol_transaction_t* tx, size_t* len, sol_hash_t* tmp) {
    if (!tx || !len || !tmp) return NULL;
    if (sol_transaction_hash(tx, tmp) != SOL_OK) return NULL;
    *len = 32;
    return tmp->bytes;
}

static const uint8_t*
tx_data_msg_hash32(const sol_transaction_t* tx, size_t* len, sol_hash_t* tmp) {
    if (!tx || !len || !tmp || !tx->message_data || tx->message_data_len == 0) return NULL;
    sol_sha256_bytes(tx->message_data, tx->message_data_len, tmp->bytes);
    *len = 32;
    return tmp->bytes;
}

static const uint8_t*
tx_data_msg_raw(const sol_transaction_t* tx, size_t* len, sol_hash_t* tmp) {
    (void)tmp;
    if (!tx || !len || !tx->message_data || tx->message_data_len == 0) return NULL;
    *len = tx->message_data_len;
    return tx->message_data;
}

static const uint8_t*
tx_data_sig32_a(const sol_transaction_t* tx, size_t* len, sol_hash_t* tmp) {
    (void)tmp;
    if (!tx || !len || !tx->signatures || tx->signatures_len == 0) return NULL;
    *len = 32;
    return tx->signatures[0].bytes;
}

static const uint8_t*
tx_data_sig32_b(const sol_transaction_t* tx, size_t* len, sol_hash_t* tmp) {
    (void)tmp;
    if (!tx || !len || !tx->signatures || tx->signatures_len == 0) return NULL;
    *len = 32;
    return tx->signatures[0].bytes + 32;
}

static const uint8_t*
tx_data_sigs_all(const sol_transaction_t* tx, size_t* len, sol_hash_t* tmp) {
    (void)tmp;
    if (!tx || !len || !tx->signatures || tx->signatures_len == 0) return NULL;
    *len = (size_t)tx->signatures_len * 64u;
    return tx->signatures[0].bytes;
}

static const uint8_t*
tx_data_sigs_all_hash32(const sol_transaction_t* tx, size_t* len, sol_hash_t* tmp) {
    if (!tx || !len || !tmp || !tx->signatures || tx->signatures_len == 0) return NULL;
    sol_sha256_bytes(tx->signatures[0].bytes, (size_t)tx->signatures_len * 64u, tmp->bytes);
    *len = 32;
    return tmp->bytes;
}

static size_t
compact_u16_encoded_len(uint16_t val) {
    if (val < 0x80u) return 1;
    if (val < 0x4000u) return 2;
    return 3;
}

static const uint8_t*
tx_data_raw_tx_bytes(const sol_transaction_t* tx, size_t* len, sol_hash_t* tmp) {
    (void)tmp;
    if (!tx || !len || !tx->signatures || tx->signatures_len == 0 || !tx->message_data ||
        tx->message_data_len == 0) {
        return NULL;
    }

    size_t prefix_len = compact_u16_encoded_len((uint16_t)tx->signatures_len);
    const uint8_t* sigs = (const uint8_t*)tx->signatures;
    const uint8_t* start = sigs - prefix_len;
    size_t sigs_len = (size_t)tx->signatures_len * 64u;

    /* Sanity: message_data should follow signatures in the original byte stream. */
    if (tx->message_data != sigs + sigs_len) {
        return NULL;
    }

    *len = prefix_len + sigs_len + tx->message_data_len;
    return start;
}

static const uint8_t*
tx_data_raw_tx_hash32(const sol_transaction_t* tx, size_t* len, sol_hash_t* tmp) {
    if (!tx || !len || !tmp) return NULL;
    size_t raw_len = 0;
    const uint8_t* raw = tx_data_raw_tx_bytes(tx, &raw_len, NULL);
    if (!raw || raw_len == 0) return NULL;
    sol_sha256_bytes(raw, raw_len, tmp->bytes);
    *len = 32;
    return tmp->bytes;
}

static void
print_hash(const char* label, const sol_hash_t* h) {
    char hex[65] = {0};
    (void)sol_hash_to_hex(h, hex, sizeof(hex));
    printf("%-24s %s\n", label, hex);
}

static sol_err_t
derive_start_hash_from_accounts(const char* accounts_path, sol_hash_t* out) {
    if (!accounts_path || !out) return SOL_ERR_INVAL;

    sol_accounts_db_config_t cfg = SOL_ACCOUNTS_DB_CONFIG_DEFAULT;
    cfg.storage_type = SOL_ACCOUNTS_STORAGE_ROCKSDB;
    cfg.rocksdb_path = accounts_path;
    cfg.enable_snapshots = true;

    sol_accounts_db_t* db = sol_accounts_db_new(&cfg);
    if (!db) {
        return SOL_ERR_IO;
    }

    sol_account_t* acct = sol_accounts_db_load(db, &SOL_SYSVAR_RECENT_BLOCKHASHES_ID);
    if (!acct) {
        sol_accounts_db_destroy(db);
        return SOL_ERR_NOTFOUND;
    }

    sol_recent_blockhashes_t rbh;
    sol_recent_blockhashes_init(&rbh);
    sol_err_t err = sol_recent_blockhashes_deserialize(&rbh, acct->data, acct->meta.data_len);
    sol_account_destroy(acct);
    sol_accounts_db_destroy(db);

    if (err != SOL_OK) {
        return err;
    }
    if (rbh.len == 0) {
        return SOL_ERR_NOTFOUND;
    }

    *out = rbh.entries[0].blockhash;
    return SOL_OK;
}

static sol_err_t
load_recent_blockhashes(const char* accounts_path, sol_recent_blockhashes_t* out_rbh) {
    if (!accounts_path || !out_rbh) return SOL_ERR_INVAL;

    sol_accounts_db_config_t cfg = SOL_ACCOUNTS_DB_CONFIG_DEFAULT;
    cfg.storage_type = SOL_ACCOUNTS_STORAGE_ROCKSDB;
    cfg.rocksdb_path = accounts_path;
    cfg.enable_snapshots = true;

    sol_accounts_db_t* db = sol_accounts_db_new(&cfg);
    if (!db) return SOL_ERR_IO;

    sol_account_t* acct = sol_accounts_db_load(db, &SOL_SYSVAR_RECENT_BLOCKHASHES_ID);
    if (!acct) {
        sol_accounts_db_destroy(db);
        return SOL_ERR_NOTFOUND;
    }

    sol_recent_blockhashes_init(out_rbh);
    sol_err_t err =
        sol_recent_blockhashes_deserialize(out_rbh, acct->data, acct->meta.data_len);

    sol_account_destroy(acct);
    sol_accounts_db_destroy(db);
    return err;
}

static sol_err_t
load_slot_hashes(const char* accounts_path, sol_slot_hashes_t* out_sh) {
    if (!accounts_path || !out_sh) return SOL_ERR_INVAL;

    sol_accounts_db_config_t cfg = SOL_ACCOUNTS_DB_CONFIG_DEFAULT;
    cfg.storage_type = SOL_ACCOUNTS_STORAGE_ROCKSDB;
    cfg.rocksdb_path = accounts_path;
    cfg.enable_snapshots = true;

    sol_accounts_db_t* db = sol_accounts_db_new(&cfg);
    if (!db) return SOL_ERR_IO;

    sol_account_t* acct = sol_accounts_db_load(db, &SOL_SYSVAR_SLOT_HASHES_ID);
    if (!acct) {
        sol_accounts_db_destroy(db);
        return SOL_ERR_NOTFOUND;
    }

    sol_slot_hashes_init(out_sh);
    sol_err_t err = sol_slot_hashes_deserialize(out_sh, acct->data, acct->meta.data_len);

    sol_account_destroy(acct);
    sol_accounts_db_destroy(db);
    return err;
}

static void
print_bootstrap_state(const char* accounts_path) {
    if (!accounts_path) return;

    sol_accounts_db_config_t cfg = SOL_ACCOUNTS_DB_CONFIG_DEFAULT;
    cfg.storage_type = SOL_ACCOUNTS_STORAGE_ROCKSDB;
    cfg.rocksdb_path = accounts_path;
    cfg.enable_snapshots = true;

    sol_accounts_db_t* db = sol_accounts_db_new(&cfg);
    if (!db) {
        printf("bootstrap_state=ERR(open)\n");
        return;
    }

    sol_accounts_db_bootstrap_state_t bs = {0};
    if (sol_accounts_db_get_bootstrap_state(db, &bs)) {
        char blockhash_hex[65] = {0};
        char bank_hash_hex[65] = {0};
        char parent_hash_hex[65] = {0};
        sol_hash_to_hex(&bs.blockhash, blockhash_hex, sizeof(blockhash_hex));
        sol_hash_to_hex(&bs.bank_hash, bank_hash_hex, sizeof(bank_hash_hex));
        sol_hash_to_hex(&bs.parent_bank_hash, parent_hash_hex, sizeof(parent_hash_hex));

        printf("bootstrap_state.slot=%" PRIu64 " parent_slot=%" PRIu64 " sig_count=%" PRIu64 "\n",
               (uint64_t)bs.slot,
               (uint64_t)bs.parent_slot,
               (uint64_t)bs.signature_count);
        printf("bootstrap_state.ticks_per_slot=%" PRIu64 " hashes_per_tick=%" PRIu64 " slots_per_epoch=%" PRIu64 "\n",
               (uint64_t)bs.ticks_per_slot,
               (uint64_t)bs.hashes_per_tick,
               (uint64_t)bs.slots_per_epoch);
        if (bs.flags & SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_BLOCKHASH) {
            printf("bootstrap_state.blockhash=%s\n", blockhash_hex);
        }
        if (bs.flags & SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_BANK_HASH) {
            printf("bootstrap_state.bank_hash=%s\n", bank_hash_hex);
            printf("bootstrap_state.parent_bank_hash=%s\n", parent_hash_hex);
        }
    } else {
        printf("bootstrap_state=NOT_FOUND\n");
    }

    sol_accounts_db_destroy(db);
}

static sol_hash_t
per_tx_mix_raw_bytes(const sol_hash_t* start,
                     uint64_t prehashes,
                     const sol_entry_t* entry,
                     bool reverse_order) {
    sol_hash_t cur = *start;
    hash_n(&cur, prehashes, &cur);

    if (!entry->raw_data || entry->raw_data_len == 0) {
        memset(cur.bytes, 0, 32);
        return cur;
    }

    size_t off = 0;
    for (uint32_t i = 0; i < entry->num_transactions; i++) {
        sol_transaction_t tmp_tx;
        sol_transaction_init(&tmp_tx);
        sol_err_t err = sol_transaction_decode(entry->raw_data + off,
                                               entry->raw_data_len - off,
                                               &tmp_tx);
        if (err != SOL_OK || tmp_tx.encoded_len == 0 ||
            tmp_tx.encoded_len > (entry->raw_data_len - off)) {
            memset(cur.bytes, 0, 32);
            return cur;
        }

        const uint8_t* tx_bytes = entry->raw_data + off;
        size_t tx_len = tmp_tx.encoded_len;

        if (reverse_order) {
            hash_mixin_rev(&cur, tx_bytes, tx_len, &cur);
        } else {
            hash_mixin(&cur, tx_bytes, tx_len, &cur);
        }

        off += tx_len;
    }

    return cur;
}

int
main(int argc, char** argv) {
    const char* rocksdb_base = NULL;
    uint64_t slot = 0;
    uint32_t variant = 0;
    const char* start_hash_hex = NULL;
    const char* leader_b58 = NULL;
    bool parse_only = false;

    static struct option long_opts[] = {
        {"rocksdb-path", required_argument, 0, 1000},
        {"slot", required_argument, 0, 1001},
        {"variant", required_argument, 0, 1002},
        {"start-hash", required_argument, 0, 1003},
        {"parse-only", no_argument, 0, 1004},
        {"leader", required_argument, 0, 1005},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "hV", long_opts, NULL)) != -1) {
        switch (opt) {
        case 1000:
            rocksdb_base = optarg;
            break;
        case 1001:
            slot = strtoull(optarg, NULL, 10);
            break;
        case 1002:
            variant = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 1003:
            start_hash_hex = optarg;
            break;
        case 1004:
            parse_only = true;
            break;
        case 1005:
            leader_b58 = optarg;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        case 'V':
            printf("%s\n", VERSION);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!rocksdb_base || slot == 0) {
        print_usage(argv[0]);
        return 1;
    }

    if (leader_b58 && leader_b58[0] != '\0') {
        sol_pubkey_t pk = {{0}};
        sol_err_t err = sol_pubkey_from_base58(leader_b58, &pk);
        if (err != SOL_OK) {
            fprintf(stderr, "Invalid --leader pubkey: %s\n", sol_err_str(err));
            return 1;
        }
        g_leader_pubkey = pk;
        g_have_leader = true;
    }

    sol_log_config_t log_cfg = (sol_log_config_t)SOL_LOG_CONFIG_DEFAULT;
    log_cfg.level = SOL_LOG_OFF;
    sol_log_init(&log_cfg);

    char blockstore_path[512];
    char accounts_path[512];
    snprintf(blockstore_path, sizeof(blockstore_path), "%s/blockstore", rocksdb_base);
    snprintf(accounts_path, sizeof(accounts_path), "%s/accounts", rocksdb_base);

    print_bootstrap_state(accounts_path);

    sol_blockstore_config_t bs_cfg = SOL_BLOCKSTORE_CONFIG_DEFAULT;
    bs_cfg.storage_type = SOL_BLOCKSTORE_STORAGE_ROCKSDB;
    bs_cfg.rocksdb_path = blockstore_path;
    sol_blockstore_t* bs = sol_blockstore_new(&bs_cfg);
    if (!bs) {
        fprintf(stderr, "Failed to open blockstore at %s\n", blockstore_path);
        return 1;
    }

    /* Best-effort: slot metadata summary + inspect a couple shreds. */
    sol_slot_meta_t meta = {0};
    sol_err_t meta_err = sol_blockstore_get_slot_meta_variant(bs, (sol_slot_t)slot, variant, &meta);
    if (meta_err == SOL_OK) {
        printf("slot_meta: slot=%" PRIu64 " parent=%" PRIu64 " received_data=%u received_code=%u first=%u last=%u num_data=%u full=%d complete=%d\n",
               (uint64_t)meta.slot,
               (uint64_t)meta.parent_slot,
               (unsigned)meta.received_data,
               (unsigned)meta.received_code,
               (unsigned)meta.first_shred_index,
               (unsigned)meta.last_shred_index,
               (unsigned)meta.num_data_shreds,
               meta.is_full ? 1 : 0,
               meta.is_complete ? 1 : 0);
    } else {
        printf("slot_meta.err=%s\n", sol_err_str(meta_err));
    }

    {
        dump_data_shred_info(bs, (sol_slot_t)slot, 0);
        dump_data_shred_info(bs, (sol_slot_t)slot, 63);
        if (meta_err == SOL_OK && meta.is_full && meta.last_shred_index > 0) {
            dump_data_shred_info(bs, (sol_slot_t)slot, meta.last_shred_index);
        }
    }

    size_t slot_variants = sol_blockstore_num_variants(bs, (sol_slot_t)slot);
    printf("blockstore.variants(slot=%" PRIu64 ")=%zu\n", slot, slot_variants);
    for (uint32_t vid = 0; vid < slot_variants; vid++) {
        sol_hash_t h = {0};
        sol_err_t err = sol_blockstore_get_block_hash_variant(bs, (sol_slot_t)slot, vid, &h);
        if (err == SOL_OK) {
            char label[64];
            snprintf(label, sizeof(label), "slot.block_hash[v%u]", vid);
            print_hash(label, &h);
        }
    }

    sol_block_t* block = sol_blockstore_get_block_variant(bs, (sol_slot_t)slot, variant);
    if (!block) {
        fprintf(stderr, "Failed to load block slot=%" PRIu64 " variant=%u\n", slot, variant);
        sol_blockstore_destroy(bs);
        return 1;
    }

    sol_entry_batch_t* batch = sol_entry_batch_new(0);
    if (!batch) {
        fprintf(stderr, "OOM\n");
        sol_block_destroy(block);
        sol_blockstore_destroy(bs);
        return 1;
    }

    sol_err_t parse_err = sol_entry_batch_parse(batch, block->data, block->data_len);
    if (parse_err != SOL_OK || batch->num_entries == 0) {
        fprintf(stderr, "Failed to parse entries: %s\n", sol_err_str(parse_err));

        if (meta_err == SOL_OK && meta.is_full && meta.last_shred_index < 10000 &&
            block->data && block->data_len > 0) {
            size_t cumulative = 0;
            size_t boundaries = 0;
            size_t boundary_offsets[8] = {0};
            uint64_t boundary_next_u64[8] = {0};
            size_t first_boundary = 0;
            uint64_t first_boundary_next = 0;
            for (uint32_t i = 0; i <= meta.last_shred_index; i++) {
                uint8_t sbuf[SOL_SHRED_SIZE];
                size_t sbuf_len = sizeof(sbuf);
                sol_err_t s_err = sol_blockstore_get_shred(bs, (sol_slot_t)slot, i, true, sbuf, &sbuf_len);
                if (s_err != SOL_OK) break;

                sol_shred_t s = {0};
                if (sol_shred_parse(&s, sbuf, sbuf_len) != SOL_OK || s.type != SOL_SHRED_TYPE_DATA) {
                    break;
                }

                cumulative += (size_t)s.payload_len;
                if ((s.header.data.flags & SOL_SHRED_FLAG_DATA_COMPLETE) != 0) {
                    uint64_t next_u64 = 0;
                    bool have = (cumulative + 8u <= block->data_len);
                    if (have) memcpy(&next_u64, block->data + cumulative, 8);
                    printf("boundary.data_complete@%u cumulative=%zu next_u64=%" PRIu64 "%s\n",
                           (unsigned)i,
                           cumulative,
                           next_u64,
                           have ? "" : " (eof)");
                    if (first_boundary == 0 && have) {
                        first_boundary = cumulative;
                        first_boundary_next = next_u64;
                    }
                    if (boundaries < (sizeof(boundary_offsets) / sizeof(boundary_offsets[0]))) {
                        boundary_offsets[boundaries] = cumulative;
                        boundary_next_u64[boundaries] = next_u64;
                    }
                    boundaries++;
                    if (boundaries >= 8) break;
                }
            }

            if (first_boundary > 0) {
                size_t off = 0;
                uint64_t entry_count = 0;
                if (block->data_len >= 8) {
                    memcpy(&entry_count, block->data, 8);
                    off = 8;
                }
                sol_err_t seg_err = SOL_OK;
                for (uint64_t ei = 0; ei < entry_count; ei++) {
                    sol_entry_t entry;
                    sol_entry_init(&entry);
                    size_t consumed = 0;
                    seg_err = sol_entry_parse(&entry, block->data + off, block->data_len - off, &consumed);
                    sol_entry_cleanup(&entry);
                    if (seg_err != SOL_OK || consumed == 0) {
                        break;
                    }
                    off += consumed;
                    if (off > block->data_len) {
                        seg_err = SOL_ERR_DECODE;
                        break;
                    }
                }

                uint64_t next_at_off = 0;
                bool have_next_at_off = (off + 8u <= block->data_len);
                if (have_next_at_off) memcpy(&next_at_off, block->data + off, 8);

                printf("segment0: entries=%" PRIu64 " consumed=%zu expected=%zu delta=%zd next_u64=%" PRIu64 "%s\n",
                       entry_count,
                       off,
                       first_boundary,
                       (ssize_t)off - (ssize_t)first_boundary,
                       next_at_off,
                       have_next_at_off ? "" : " (eof)");
                printf("segment0.expected_next_u64=%" PRIu64 "\n", first_boundary_next);
                if (seg_err != SOL_OK) {
                    printf("segment0.parse_err=%s\n", sol_err_str(seg_err));
                }
            }

            /* Try to parse additional segments at DATA_COMPLETE boundaries.
             *
             * Each erasure batch may start a new Vec<Entry> segment, and segment
             * headers are often located at the start of the next batch (i.e.
             * right after the boundary). This helps diagnose misalignment vs a
             * truly malformed transaction in a later segment. */
            if (boundaries > 0) {
                size_t seg_count = boundaries < 8 ? boundaries : 8;
                for (size_t si = 0; si < seg_count; si++) {
                    size_t start = (si == 0) ? 0 : boundary_offsets[si - 1];
                    size_t expected_end = boundary_offsets[si];
                    if (start + 8u > block->data_len) {
                        printf("segment%zu: start=%zu (eof)\n", si, start);
                        continue;
                    }

                    uint64_t entry_count = 0;
                    memcpy(&entry_count, block->data + start, 8);
                    size_t off = start + 8u;
                    sol_err_t seg_err = SOL_OK;
                    for (uint64_t ei = 0; ei < entry_count; ei++) {
                        sol_entry_t entry;
                        sol_entry_init(&entry);
                        size_t consumed = 0;
                        seg_err = sol_entry_parse_ex(&entry,
                                                     block->data + off,
                                                     block->data_len - off,
                                                     &consumed,
                                                     false);
                        sol_entry_cleanup(&entry);
                        if (seg_err != SOL_OK || consumed == 0) {
                            break;
                        }
                        off += consumed;
                        if (off > block->data_len) {
                            seg_err = SOL_ERR_DECODE;
                            break;
                        }
                    }

                    uint64_t next_at_off = 0;
                    bool have_next_at_off = (off + 8u <= block->data_len);
                    if (have_next_at_off) {
                        memcpy(&next_at_off, block->data + off, 8);
                    }

                    printf("segment%zu.boundary: start=%zu entries=%" PRIu64 " consumed=%zu expected_end=%zu delta=%zd next_u64=%" PRIu64 "%s\n",
                           si,
                           start,
                           entry_count,
                           off,
                           expected_end,
                           (ssize_t)off - (ssize_t)expected_end,
                           next_at_off,
                           have_next_at_off ? "" : " (eof)");
                    if (seg_err != SOL_OK) {
                        printf("segment%zu.boundary.parse_err=%s\n", si, sol_err_str(seg_err));
                    }
                }
            }
        }

        if (block->data && block->data_len > 0) {
            size_t dump0 = block->data_len < 64 ? block->data_len : 64;
            print_hex_bytes("block.data[0..]", block->data, dump0);

            if (block->data_len >= 8) {
                uint64_t entry_count_u64 = 0;
                memcpy(&entry_count_u64, block->data, 8);
                printf("decode.entry_count_u64=%" PRIu64 "\n", entry_count_u64);

                sol_decoder_t dec;
                sol_decoder_init(&dec, block->data, block->data_len);
                uint16_t entry_count_u16 = 0;
                sol_err_t ec_err = sol_decode_compact_u16(&dec, &entry_count_u16);
                if (ec_err == SOL_OK) {
                    printf("decode.entry_count_compact_u16=%u (bytes=%zu)\n",
                           (unsigned)entry_count_u16, dec.pos);
                } else {
                    printf("decode.entry_count_compact_u16=ERR(%s)\n", sol_err_str(ec_err));
                }

                /* First entry peek, assuming entry_count is a u64 at offset 0. */
                if (block->data_len >= (8 + 8 + 32 + 8)) {
                    size_t off = 8 + 8 + 32;
                    size_t avail = block->data_len - off;
                    size_t dump1 = avail < 16 ? avail : 16;
                    print_hex_bytes("peek.first_entry.after_hash", block->data + off, dump1);

                    uint64_t tx_count_u64 = 0;
                    memcpy(&tx_count_u64, block->data + off, 8);
                    printf("peek.first_entry.num_tx_as_u64=%" PRIu64 "\n", tx_count_u64);

                    sol_decoder_t d2;
                    sol_decoder_init(&d2, block->data + off, block->data_len - off);
                    uint16_t tx_count_u16 = 0;
                    sol_err_t tc_err = sol_decode_compact_u16(&d2, &tx_count_u16);
                    if (tc_err == SOL_OK) {
                        printf("peek.first_entry.num_tx_as_compact_u16=%u (bytes=%zu)\n",
                               (unsigned)tx_count_u16, d2.pos);
                    } else {
                        printf("peek.first_entry.num_tx_as_compact_u16=ERR(%s)\n", sol_err_str(tc_err));
                    }
                }
            }
        }
        sol_entry_batch_destroy(batch);
        sol_block_destroy(block);
        sol_blockstore_destroy(bs);
        return 1;
    }

    const sol_entry_t* e0 = &batch->entries[0];
    const sol_entry_t* elast = &batch->entries[batch->num_entries - 1];
    printf("slot=%" PRIu64 " parent_slot=%" PRIu64 " entries=%u tx_total=%u data_len=%zu\n",
           (uint64_t)block->slot,
           (uint64_t)block->parent_slot,
           block->num_entries,
           block->num_transactions,
           block->data_len);
    printf("parsed_entries=%zu parsed_tx_total=%u\n",
           batch->num_entries,
           sol_entry_batch_transaction_count(batch));

    if (parse_only) {
        print_hash("entry[0].hash", &e0->hash);
        print_hash("entry[last].hash", &elast->hash);
        printf("entry[0]: num_hashes=%" PRIu64 " num_tx=%u\n",
               (uint64_t)e0->num_hashes,
               (unsigned)e0->num_transactions);
        printf("entry[last]: num_hashes=%" PRIu64 " num_tx=%u\n",
               (uint64_t)elast->num_hashes,
               (unsigned)elast->num_transactions);

        uint64_t sig_sum = 0;
        uint64_t sig_hist[32] = {0};
        for (size_t ei = 0; ei < batch->num_entries; ei++) {
            const sol_entry_t* entry = &batch->entries[ei];
            if (!entry->transactions || entry->num_transactions == 0) continue;
            for (uint32_t ti = 0; ti < entry->num_transactions; ti++) {
                const sol_transaction_t* tx = &entry->transactions[ti];
                sig_sum += (uint64_t)tx->signatures_len;
                if (tx->signatures_len < (uint8_t)(sizeof(sig_hist) / sizeof(sig_hist[0]))) {
                    sig_hist[tx->signatures_len]++;
                }
            }
        }
        printf("tx_signatures.sum=%" PRIu64 "\n", sig_sum);
        for (size_t i = 0; i < sizeof(sig_hist) / sizeof(sig_hist[0]); i++) {
            if (sig_hist[i] == 0) continue;
            printf("tx_signatures.count[%zu]=%" PRIu64 "\n", i, sig_hist[i]);
        }

        sol_entry_batch_destroy(batch);
        sol_block_destroy(block);
        sol_blockstore_destroy(bs);
        sol_log_fini();
        return 0;
    }

    size_t parent_variants = sol_blockstore_num_variants(bs, block->parent_slot);
    printf("blockstore.variants(parent_slot=%" PRIu64 ")=%zu\n",
           (uint64_t)block->parent_slot,
           parent_variants);
    for (uint32_t vid = 0; vid < parent_variants; vid++) {
        sol_hash_t h = {0};
        sol_err_t err = sol_blockstore_get_block_hash_variant(bs, block->parent_slot, vid, &h);
        if (err == SOL_OK) {
            char label[64];
            snprintf(label, sizeof(label), "parent.block_hash[v%u]", vid);
            print_hash(label, &h);
        }
    }

    sol_recent_blockhashes_t rbh = {0};
    sol_err_t rbh_err = load_recent_blockhashes(accounts_path, &rbh);
    if (rbh_err == SOL_OK && rbh.len > 0) {
        printf("recent_blockhashes.len=%zu\n", rbh.len);
        print_hash("recent_blockhashes[0]", &rbh.entries[0].blockhash);
        print_hash("recent_blockhashes[last]", &rbh.entries[rbh.len - 1].blockhash);
    } else {
        printf("recent_blockhashes.err=%s\n", sol_err_str(rbh_err));
    }

    sol_slot_hashes_t sh = {0};
    sol_err_t sh_err = load_slot_hashes(accounts_path, &sh);
    if (sh_err == SOL_OK && sh.len > 0) {
        printf("slot_hashes.len=%zu\n", sh.len);
        printf("slot_hashes[0].slot=%" PRIu64 "\n", (uint64_t)sh.entries[0].slot);
        print_hash("slot_hashes[0].hash", &sh.entries[0].hash);

        const sol_hash_t* h = sol_slot_hashes_get(&sh, (sol_slot_t)(slot - 1));
        if (h) {
            print_hash("slot_hashes[parent].hash", h);
        }
    } else {
        printf("slot_hashes.err=%s\n", sol_err_str(sh_err));
    }

    sol_hash_t start_hash = {0};
    bool start_hash_set = false;
    if (start_hash_hex) {
        if (!parse_hash_hex(start_hash_hex, &start_hash)) {
            fprintf(stderr, "Invalid --start-hash (expected 64 hex chars)\n");
            sol_entry_batch_destroy(batch);
            sol_block_destroy(block);
            sol_blockstore_destroy(bs);
            sol_log_fini();
            return 1;
        }
        start_hash_set = true;
    } else {
        /* Prefer parent block hash (last entry hash of parent slot) when available. */
        sol_hash_t parent_block_hash = {0};
        sol_err_t bh_err =
            sol_blockstore_get_block_hash_variant(bs, block->parent_slot, 0, &parent_block_hash);
        if (bh_err == SOL_OK && !sol_hash_is_zero(&parent_block_hash)) {
            print_hash("parent_block_hash", &parent_block_hash);
            if (rbh_err == SOL_OK && rbh.len > 0) {
                bool found = false;
                for (size_t i = 0; i < rbh.len; i++) {
                    if (sol_hash_eq(&rbh.entries[i].blockhash, &parent_block_hash)) {
                        printf("parent_block_hash found in recent_blockhashes at index=%zu\n", i);
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    printf("parent_block_hash not found in recent_blockhashes\n");
                }
            }
            start_hash = parent_block_hash;
            start_hash_set = true;
        } else {
            sol_err_t err = derive_start_hash_from_accounts(accounts_path, &start_hash);
            if (err != SOL_OK) {
                fprintf(stderr,
                        "Failed to derive start hash from parent slot (%s) or RecentBlockhashes sysvar at %s\n",
                        sol_err_str(bh_err),
                        accounts_path);
                sol_entry_batch_destroy(batch);
                sol_block_destroy(block);
                sol_blockstore_destroy(bs);
                sol_log_fini();
                return 1;
            }
            start_hash_set = true;
        }
    }

    if (!start_hash_set) {
        fprintf(stderr, "Failed to determine start hash\n");
        sol_entry_batch_destroy(batch);
        sol_block_destroy(block);
        sol_blockstore_destroy(bs);
        sol_log_fini();
        return 1;
    }

    print_hash("start_hash", &start_hash);
    print_hash("entry[0].hash(actual)", &e0->hash);
    print_hash("entry[last].hash", &elast->hash);
    printf("entry[0]: num_hashes=%" PRIu64 " num_tx=%u\n",
           (uint64_t)e0->num_hashes,
           (unsigned)e0->num_transactions);

    {
        uint64_t total_num_hashes = 0;
        uint32_t tick_entries = 0;
        uint32_t tx_entries = 0;
        for (size_t i = 0; i < batch->num_entries; i++) {
            total_num_hashes += batch->entries[i].num_hashes;
            if (batch->entries[i].num_transactions == 0) tick_entries++;
            else tx_entries++;
        }
        printf("parsed_entries_tick=%u parsed_entries_tx=%u total_num_hashes=%" PRIu64 "\n",
               (unsigned)tick_entries,
               (unsigned)tx_entries,
               (uint64_t)total_num_hashes);
    }

    if (e0->num_transactions > 0) {
        printf("entry[0].signatures_ok=%s\n", sol_entry_verify_signatures(e0) ? "yes" : "no");
    }

    /* Sanity check: tick-only entries must match pure hash_n chain. */
    {
        sol_hash_t prev = start_hash;
        bool tick_ok = true;
        uint32_t first_bad = 0;
        sol_hash_t expected_tick = {0};
        for (size_t i = 0; i < batch->num_entries; i++) {
            const sol_entry_t* e = &batch->entries[i];
            if (e->num_transactions == 0) {
                hash_n(&prev, e->num_hashes, &expected_tick);
                if (memcmp(expected_tick.bytes, e->hash.bytes, 32) != 0) {
                    tick_ok = false;
                    first_bad = (uint32_t)i;
                    break;
                }
            }
            prev = e->hash;
        }
        printf("tick_only_chain_ok=%s", tick_ok ? "yes" : "no");
        if (!tick_ok) {
            printf(" first_bad_entry=%u\n", first_bad);
        } else {
            printf("\n");
        }
    }

    sol_hash_t expected = {0};
    sol_entry_compute_hash(e0, &start_hash, &expected);
    print_hash("compute_hash(current)", &expected);
    printf("matches_current=%s\n", memcmp(expected.bytes, e0->hash.bytes, 32) == 0 ? "yes" : "no");

    sol_entry_verify_result_t vr = sol_entry_batch_verify(batch, &start_hash);
    printf("batch_verify(start_hash).valid=%s verified=%u failed_entry=%u err=%s\n",
           vr.valid ? "yes" : "no",
           (unsigned)vr.num_verified,
           (unsigned)vr.failed_entry,
           sol_err_str(vr.error));

    /* If entry[0] is wrong only due to start_hash, the remainder of the batch
     * should still verify when we start from the actual entry[0].hash. */
    bool tail_ok = true;
    uint32_t tail_bad = 0;
    sol_hash_t prev = e0->hash;
    for (size_t i = 1; i < batch->num_entries; i++) {
        const sol_entry_t* e = &batch->entries[i];
        sol_hash_t ex = {0};
        sol_entry_compute_hash(e, &prev, &ex);
        if (memcmp(ex.bytes, e->hash.bytes, 32) != 0) {
            tail_ok = false;
            tail_bad = (uint32_t)i;
            break;
        }
        prev = e->hash;
    }
    printf("batch_verify(from_entry0_hash).valid=%s", tail_ok ? "yes" : "no");
    if (!tail_ok) {
        printf(" first_bad_entry=%u\n", (unsigned)tail_bad);
    } else {
        printf("\n");
    }

    sol_hash_t tick_n = {0};
    sol_hash_t tick_n1 = {0};
    hash_n(&start_hash, e0->num_hashes, &tick_n);
    hash_n(&start_hash, e0->num_hashes ? (e0->num_hashes - 1) : 0, &tick_n1);
    print_hash("tick.hash_n(n)", &tick_n);
    print_hash("tick.hash_n(n-1)", &tick_n1);
    if (!memcmp(tick_n.bytes, e0->hash.bytes, 32)) {
        printf("MATCH: entry[0].hash == hash_n(start,n) (ignoring tx)\n");
    }
    if (!memcmp(tick_n1.bytes, e0->hash.bytes, 32)) {
        printf("MATCH: entry[0].hash == hash_n(start,n-1) (ignoring tx)\n");
    }

    if (e0->num_transactions > 0 && e0->transactions) {
        sol_hash_t mix_merkle = {0};
        sol_hash_t mix_merkle_carry = {0};
        sol_hash_t mix_merkle_dup = {0};
        sol_hash_t mix_merkle_dup_sorted = {0};
        sol_hash_t mix_merkle_carry_sorted = {0};
        sol_hash_t mix_merkle_pow2_dup_sorted = {0};
        sol_hash_t mix_merkle_pow2_zero_sorted = {0};
        sol_hash_t mix_merkle_all_sigs_dup_noprefix = {0};
        sol_hash_t mix_merkle_all_sigs_dup_noprefix_sorted = {0};
        sol_hash_t mix_merkle_all_sigs_dup_prefix01 = {0};
        sol_hash_t mix_merkle_all_sigs_dup_prefix01_sorted = {0};
        sol_hash_t mix_merkle_all_sigs_sigsha_prefix01 = {0};
        sol_hash_t mix_merkle_sigsha_prefix01_dup_sorted = {0};
        sol_hash_t mix_merkle_tx_dup_sorted = {0};
        sol_hash_t mix_merkle_tx_carry_sorted = {0};
        sol_hash_t mix_merkle_raw_tx_dup_sorted = {0};
        sol_hash_t mix_merkle_raw_tx_prefix01_dup_sorted = {0};
        sol_hash_t mix_merkle_msg_dup_sorted = {0};
        sol_hash_t mix_merkle_msg_carry_sorted = {0};
        sol_hash_t mix_merkle_sig32_a = {0};
        sol_hash_t mix_merkle_sig32_b = {0};
        sol_entry_transaction_merkle_root(e0, &mix_merkle);
        merkle_root_sig_hashes_carry(e0, &mix_merkle_carry);
        merkle_root_sig_hashes_dup(e0, &mix_merkle_dup);
        merkle_root_sig_hashes_dup_sorted(e0, &mix_merkle_dup_sorted);
        merkle_root_sig_hashes_carry_sorted(e0, &mix_merkle_carry_sorted);
        merkle_root_sig_hashes_pow2_dup_sorted(e0, &mix_merkle_pow2_dup_sorted);
        merkle_root_sig_hashes_pow2_zero_sorted(e0, &mix_merkle_pow2_zero_sorted);
        merkle_root_all_sigs_dup_noprefix(e0, &mix_merkle_all_sigs_dup_noprefix);
        merkle_root_all_sigs_dup_noprefix_sorted(e0, &mix_merkle_all_sigs_dup_noprefix_sorted);
        merkle_root_all_sigs_dup_prefix01(e0, &mix_merkle_all_sigs_dup_prefix01);
        merkle_root_all_sigs_dup_prefix01_sorted(e0, &mix_merkle_all_sigs_dup_prefix01_sorted);
        merkle_root_all_sigs_dup_sigsha_prefix01(e0, &mix_merkle_all_sigs_sigsha_prefix01);
        merkle_root_sig_hashes_dup_sorted_prefix01(e0, &mix_merkle_sigsha_prefix01_dup_sorted);
        merkle_root_tx_hashes_dup_sorted(e0, &mix_merkle_tx_dup_sorted);
        merkle_root_tx_hashes_carry_sorted(e0, &mix_merkle_tx_carry_sorted);
        merkle_root_raw_tx_hashes_dup_sorted(e0, &mix_merkle_raw_tx_dup_sorted);
        merkle_root_raw_tx_hashes_dup_sorted_prefix01(e0, &mix_merkle_raw_tx_prefix01_dup_sorted);
        merkle_root_msg_hashes_dup_sorted(e0, &mix_merkle_msg_dup_sorted);
        merkle_root_msg_hashes_carry_sorted(e0, &mix_merkle_msg_carry_sorted);
        merkle_root_sig_halves_dup(e0, 0, &mix_merkle_sig32_a);
        merkle_root_sig_halves_dup(e0, 32, &mix_merkle_sig32_b);
        sol_hash_t mix_concat_sig64 = {0};
        sol_hash_t mix_concat_sig_hash32 = {0};
        sol_hash_t mix_concat_tx_hash32 = {0};
        sol_hash_t mix_concat_msg_hash32 = {0};
        sol_hash_t mix_concat_sig64_sorted = {0};
        sol_hash_t mix_concat_sig_hash32_sorted = {0};
        sol_hash_t mix_concat_tx_hash32_sorted = {0};
        sol_hash_t mix_concat_msg_hash32_sorted = {0};
        sol_hash_t mix_raw_tx_bytes = {0};
        sol_hash_t mix_tx_vec_bincode = {0};
        hash_concat_sigs64(e0, &mix_concat_sig64);
        hash_concat_sig_hashes32(e0, &mix_concat_sig_hash32);
        hash_concat_tx_hashes32(e0, &mix_concat_tx_hash32);
        hash_concat_msg_hashes32(e0, &mix_concat_msg_hash32);
        hash_concat_sigs64_sorted(e0, &mix_concat_sig64_sorted);
        hash_concat_sig_hashes32_sorted(e0, &mix_concat_sig_hash32_sorted);
        hash_concat_tx_hashes32_sorted(e0, &mix_concat_tx_hash32_sorted);
        hash_concat_msg_hashes32_sorted(e0, &mix_concat_msg_hash32_sorted);
        hash_raw_tx_bytes(e0, &mix_raw_tx_bytes);
        hash_tx_vec_bincode(e0, &mix_tx_vec_bincode);

        print_hash("mixin_merkle(sig)", &mix_merkle);
        print_hash("mixin_merkle(sig,carry)", &mix_merkle_carry);
        print_hash("mixin_merkle(sig,dup)", &mix_merkle_dup);
        print_hash("mixin_merkle(sig,dup_sorted)", &mix_merkle_dup_sorted);
        print_hash("mixin_merkle(sig,carry_sorted)", &mix_merkle_carry_sorted);
        print_hash("mixin_merkle(sig,pow2_dup_sorted)", &mix_merkle_pow2_dup_sorted);
        print_hash("mixin_merkle(sig,pow2_zero_sorted)", &mix_merkle_pow2_zero_sorted);
        print_hash("mixin_merkle(all_sigs,dup)", &mix_merkle_all_sigs_dup_noprefix);
        print_hash("mixin_merkle(all_sigs,dup_sorted)", &mix_merkle_all_sigs_dup_noprefix_sorted);
        print_hash("mixin_merkle(all_sigs,prefix01_dup)", &mix_merkle_all_sigs_dup_prefix01);
        print_hash("mixin_merkle(all_sigs,prefix01_dup_sorted)", &mix_merkle_all_sigs_dup_prefix01_sorted);
        print_hash("mixin_merkle(all_sigs,sigsha_prefix01)", &mix_merkle_all_sigs_sigsha_prefix01);
        print_hash("mixin_merkle(sigsha_prefix01_dup_sorted)", &mix_merkle_sigsha_prefix01_dup_sorted);
        print_hash("mixin_merkle(tx_hash,dup_sorted)", &mix_merkle_tx_dup_sorted);
        print_hash("mixin_merkle(tx_hash,carry_sorted)", &mix_merkle_tx_carry_sorted);
        print_hash("mixin_merkle(raw_tx_hash,dup_sorted)", &mix_merkle_raw_tx_dup_sorted);
        print_hash("mixin_merkle(raw_tx_hash,prefix01_dup_sorted)", &mix_merkle_raw_tx_prefix01_dup_sorted);
        print_hash("mixin_merkle(msg_hash,dup_sorted)", &mix_merkle_msg_dup_sorted);
        print_hash("mixin_merkle(msg_hash,carry_sorted)", &mix_merkle_msg_carry_sorted);
        print_hash("mixin_merkle(sig32[0..32])", &mix_merkle_sig32_a);
        print_hash("mixin_merkle(sig32[32..64])", &mix_merkle_sig32_b);
        print_hash("mixin_concat(sig64)", &mix_concat_sig64);
        print_hash("mixin_concat(sha(sig))", &mix_concat_sig_hash32);
        print_hash("mixin_concat(tx_hash)", &mix_concat_tx_hash32);
        print_hash("mixin_concat(msg_hash)", &mix_concat_msg_hash32);
        print_hash("mixin_concat(sig64,sorted)", &mix_concat_sig64_sorted);
        print_hash("mixin_concat(sha(sig),sorted)", &mix_concat_sig_hash32_sorted);
        print_hash("mixin_concat(tx_hash,sorted)", &mix_concat_tx_hash32_sorted);
        print_hash("mixin_concat(msg_hash,sorted)", &mix_concat_msg_hash32_sorted);
        print_hash("mixin_sha(raw_tx_bytes)", &mix_raw_tx_bytes);
        print_hash("mixin_sha(tx_vec_bincode)", &mix_tx_vec_bincode);

        struct {
            const char* name;
            sol_hash_t mixin;
        } mixins[] = {
            {"merkle(sig)", mix_merkle},
            {"merkle(sig,carry)", mix_merkle_carry},
            {"merkle(sig,dup)", mix_merkle_dup},
            {"merkle(sig,dup_sorted)", mix_merkle_dup_sorted},
            {"merkle(sig,carry_sorted)", mix_merkle_carry_sorted},
            {"merkle(sig,pow2_dup_sorted)", mix_merkle_pow2_dup_sorted},
            {"merkle(sig,pow2_zero_sorted)", mix_merkle_pow2_zero_sorted},
            {"merkle(all_sigs,dup)", mix_merkle_all_sigs_dup_noprefix},
            {"merkle(all_sigs,dup_sorted)", mix_merkle_all_sigs_dup_noprefix_sorted},
            {"merkle(all_sigs,prefix01_dup)", mix_merkle_all_sigs_dup_prefix01},
            {"merkle(all_sigs,prefix01_dup_sorted)", mix_merkle_all_sigs_dup_prefix01_sorted},
            {"merkle(all_sigs,sigsha_prefix01)", mix_merkle_all_sigs_sigsha_prefix01},
            {"merkle(sigsha_prefix01_dup_sorted)", mix_merkle_sigsha_prefix01_dup_sorted},
            {"merkle(tx_hash,dup_sorted)", mix_merkle_tx_dup_sorted},
            {"merkle(tx_hash,carry_sorted)", mix_merkle_tx_carry_sorted},
            {"merkle(raw_tx_hash,dup_sorted)", mix_merkle_raw_tx_dup_sorted},
            {"merkle(raw_tx_hash,prefix01_dup_sorted)", mix_merkle_raw_tx_prefix01_dup_sorted},
            {"merkle(msg_hash,dup_sorted)", mix_merkle_msg_dup_sorted},
            {"merkle(msg_hash,carry_sorted)", mix_merkle_msg_carry_sorted},
            {"merkle(sig32[0..32])", mix_merkle_sig32_a},
            {"merkle(sig32[32..64])", mix_merkle_sig32_b},
            {"concat(sig64)", mix_concat_sig64},
            {"concat(sha(sig))", mix_concat_sig_hash32},
            {"concat(tx_hash)", mix_concat_tx_hash32},
            {"concat(msg_hash)", mix_concat_msg_hash32},
            {"concat(sig64,sorted)", mix_concat_sig64_sorted},
            {"concat(sha(sig),sorted)", mix_concat_sig_hash32_sorted},
            {"concat(tx_hash,sorted)", mix_concat_tx_hash32_sorted},
            {"concat(msg_hash,sorted)", mix_concat_msg_hash32_sorted},
            {"sha(raw_tx_bytes)", mix_raw_tx_bytes},
            {"sha(tx_vec_bincode)", mix_tx_vec_bincode},
        };

        printf("\n== single-record candidates ==\n");
        for (size_t mi = 0; mi < sizeof(mixins) / sizeof(mixins[0]); mi++) {
            sol_hash_t pre = {0};
            sol_hash_t out = {0};

            uint64_t prehash_counts[] = {
                e0->num_hashes,
                e0->num_hashes ? (e0->num_hashes - 1) : 0,
            };
            const char* prehash_names[] = {"n", "n-1"};

            for (size_t ci = 0; ci < sizeof(prehash_counts) / sizeof(prehash_counts[0]); ci++) {
                hash_n(&start_hash, prehash_counts[ci], &pre);

                /* forward and reverse hashv order */
                hash_mixin(&pre, mixins[mi].mixin.bytes, 32, &out);
                if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
                    printf("MATCH: record(pre=%s,order=prev||mixin) mixin=%s\n",
                           prehash_names[ci], mixins[mi].name);
                }
                hash_mixin_rev(&pre, mixins[mi].mixin.bytes, 32, &out);
                if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
                    printf("MATCH: record(pre=%s,order=mixin||prev) mixin=%s\n",
                           prehash_names[ci], mixins[mi].name);
                }

                /* Domain-separated record variants (prefix byte before concatenation). */
                for (uint8_t prefix = 0; prefix <= 1; prefix++) {
                    hash_mixin_prefixed(&pre, mixins[mi].mixin.bytes, 32, prefix, false, &out);
                    if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
                        printf("MATCH: record(pre=%s,prefix=%u,order=prev||mixin) mixin=%s\n",
                               prehash_names[ci],
                               (unsigned)prefix,
                               mixins[mi].name);
                    }
                    hash_mixin_prefixed(&pre, mixins[mi].mixin.bytes, 32, prefix, true, &out);
                    if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
                        printf("MATCH: record(pre=%s,prefix=%u,order=mixin||prev) mixin=%s\n",
                               prehash_names[ci],
                               (unsigned)prefix,
                               mixins[mi].name);
                    }
                }

                /* Optional extra hash step after record */
                hash_mixin(&pre, mixins[mi].mixin.bytes, 32, &out);
                sol_sha256_bytes(out.bytes, 32, out.bytes);
                if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
                    printf("MATCH: record+1hash(pre=%s,order=prev||mixin) mixin=%s\n",
                           prehash_names[ci], mixins[mi].name);
                }
                hash_mixin_rev(&pre, mixins[mi].mixin.bytes, 32, &out);
                sol_sha256_bytes(out.bytes, 32, out.bytes);
                if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
                    printf("MATCH: record+1hash(pre=%s,order=mixin||prev) mixin=%s\n",
                           prehash_names[ci], mixins[mi].name);
                }

                for (uint8_t prefix = 0; prefix <= 1; prefix++) {
                    hash_mixin_prefixed(&pre, mixins[mi].mixin.bytes, 32, prefix, false, &out);
                    sol_sha256_bytes(out.bytes, 32, out.bytes);
                    if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
                        printf("MATCH: record+1hash(pre=%s,prefix=%u,order=prev||mixin) mixin=%s\n",
                               prehash_names[ci],
                               (unsigned)prefix,
                               mixins[mi].name);
                    }
                    hash_mixin_prefixed(&pre, mixins[mi].mixin.bytes, 32, prefix, true, &out);
                    sol_sha256_bytes(out.bytes, 32, out.bytes);
                    if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
                        printf("MATCH: record+1hash(pre=%s,prefix=%u,order=mixin||prev) mixin=%s\n",
                               prehash_names[ci],
                               (unsigned)prefix,
                               mixins[mi].name);
                    }
                }
            }

            /* Record-first variants: record mixin, then hash N or N-1 times. */
            sol_hash_t rec = {0};
            hash_mixin(&start_hash, mixins[mi].mixin.bytes, 32, &rec);
            hash_n(&rec, e0->num_hashes, &out);
            if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: record_first(order=prev||mixin) then hash_n(n) mixin=%s\n",
                       mixins[mi].name);
            }
            hash_n(&rec, e0->num_hashes ? (e0->num_hashes - 1) : 0, &out);
            if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: record_first(order=prev||mixin) then hash_n(n-1) mixin=%s\n",
                       mixins[mi].name);
            }

            hash_mixin_rev(&start_hash, mixins[mi].mixin.bytes, 32, &rec);
            hash_n(&rec, e0->num_hashes, &out);
            if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: record_first(order=mixin||prev) then hash_n(n) mixin=%s\n",
                       mixins[mi].name);
            }
            hash_n(&rec, e0->num_hashes ? (e0->num_hashes - 1) : 0, &out);
            if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: record_first(order=mixin||prev) then hash_n(n-1) mixin=%s\n",
                       mixins[mi].name);
            }
        }

        printf("\n== direct-record-bytes candidates ==\n");
        struct {
            const char* name;
            void (*fn)(const sol_hash_t*, const sol_entry_t*, bool, sol_hash_t*);
        } direct[] = {
            {"concat(sig64)", hash_record_concat_sig64},
            {"concat(sha(sig))", hash_record_concat_sig_hash32},
            {"concat(tx_hash)", hash_record_concat_tx_hash32},
            {"concat(msg_hash)", hash_record_concat_msg_hash32},
            {"raw_tx_bytes", hash_record_raw_tx_bytes},
            {"tx_vec_bincode", hash_record_tx_vec_bincode},
        };

        uint64_t prehash_counts[] = {
            e0->num_hashes,
            e0->num_hashes ? (e0->num_hashes - 1) : 0,
        };
        const char* prehash_names[] = {"n", "n-1"};

        for (size_t di = 0; di < sizeof(direct) / sizeof(direct[0]); di++) {
            for (size_t ci = 0; ci < sizeof(prehash_counts) / sizeof(prehash_counts[0]); ci++) {
                sol_hash_t pre = {0};
                hash_n(&start_hash, prehash_counts[ci], &pre);

                sol_hash_t out = {0};
                direct[di].fn(&pre, e0, false, &out);
                if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
                    printf("MATCH: record(pre=%s,order=prev||bytes) bytes=%s\n",
                           prehash_names[ci], direct[di].name);
                }
                direct[di].fn(&pre, e0, true, &out);
                if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
                    printf("MATCH: record(pre=%s,order=bytes||prev) bytes=%s\n",
                           prehash_names[ci], direct[di].name);
                }

                /* Optional extra hash step after record */
                direct[di].fn(&pre, e0, false, &out);
                sol_sha256_bytes(out.bytes, 32, out.bytes);
                if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
                    printf("MATCH: record+1hash(pre=%s,order=prev||bytes) bytes=%s\n",
                           prehash_names[ci], direct[di].name);
                }
                direct[di].fn(&pre, e0, true, &out);
                sol_sha256_bytes(out.bytes, 32, out.bytes);
                if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
                    printf("MATCH: record+1hash(pre=%s,order=bytes||prev) bytes=%s\n",
                           prehash_names[ci], direct[di].name);
                }
            }

            /* Record-first variants for direct bytes: record bytes, then hash N or N-1 times. */
            sol_hash_t rec = {0};
            sol_hash_t out = {0};
            direct[di].fn(&start_hash, e0, false, &rec);
            hash_n(&rec, e0->num_hashes, &out);
            if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: record_first(order=prev||bytes) then hash_n(n) bytes=%s\n",
                       direct[di].name);
            }
            hash_n(&rec, e0->num_hashes ? (e0->num_hashes - 1) : 0, &out);
            if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: record_first(order=prev||bytes) then hash_n(n-1) bytes=%s\n",
                       direct[di].name);
            }

            direct[di].fn(&start_hash, e0, true, &rec);
            hash_n(&rec, e0->num_hashes, &out);
            if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: record_first(order=bytes||prev) then hash_n(n) bytes=%s\n",
                       direct[di].name);
            }
            hash_n(&rec, e0->num_hashes ? (e0->num_hashes - 1) : 0, &out);
            if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: record_first(order=bytes||prev) then hash_n(n-1) bytes=%s\n",
                       direct[di].name);
            }
        }

        uint64_t pre_a = (e0->num_hashes > (uint64_t)e0->num_transactions)
                             ? (e0->num_hashes - (uint64_t)e0->num_transactions)
                             : 0;
        uint64_t pre_b = (pre_a > 0) ? (pre_a - 1) : 0;
        uint64_t pre_n = e0->num_hashes;
        uint64_t pre_n1 = e0->num_hashes ? (e0->num_hashes - 1) : 0;

        printf("\n== per-tx candidates ==\n");
        struct {
            const char* name;
            const uint8_t* (*fn)(const sol_transaction_t*, size_t*, sol_hash_t*);
        } per_tx[] = {
            {"sig64", tx_data_sig64},
            {"sig32[0..32]", tx_data_sig32_a},
            {"sig32[32..64]", tx_data_sig32_b},
            {"sha(sig)", tx_data_sig_hash32},
            {"sha(sigs_all)", tx_data_sigs_all_hash32},
            {"tx_hash", tx_data_tx_hash32},
            {"msg_hash", tx_data_msg_hash32},
            {"msg_raw", tx_data_msg_raw},
            {"sigs_all", tx_data_sigs_all},
            {"raw_tx_bytes", tx_data_raw_tx_bytes},
            {"sha(raw_tx)", tx_data_raw_tx_hash32},
        };

        for (size_t pi = 0; pi < sizeof(per_tx) / sizeof(per_tx[0]); pi++) {
            sol_hash_t a_fwd = per_tx_mix(&start_hash, pre_a, e0, per_tx[pi].fn, false);
            sol_hash_t a_rev = per_tx_mix(&start_hash, pre_a, e0, per_tx[pi].fn, true);
            sol_hash_t b_fwd = per_tx_mix(&start_hash, pre_b, e0, per_tx[pi].fn, false);
            sol_hash_t b_rev = per_tx_mix(&start_hash, pre_b, e0, per_tx[pi].fn, true);
            sol_hash_t n_fwd = per_tx_mix(&start_hash, pre_n, e0, per_tx[pi].fn, false);
            sol_hash_t n_rev = per_tx_mix(&start_hash, pre_n, e0, per_tx[pi].fn, true);
            sol_hash_t n1_fwd = per_tx_mix(&start_hash, pre_n1, e0, per_tx[pi].fn, false);
            sol_hash_t n1_rev = per_tx_mix(&start_hash, pre_n1, e0, per_tx[pi].fn, true);

            if (!memcmp(a_fwd.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: per_tx(pre=num_hashes-num_tx,fwd) data=%s\n", per_tx[pi].name);
            }
            if (!memcmp(a_rev.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: per_tx(pre=num_hashes-num_tx,rev) data=%s\n", per_tx[pi].name);
            }
            if (!memcmp(b_fwd.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: per_tx(pre=num_hashes-num_tx-1,fwd) data=%s\n", per_tx[pi].name);
            }
            if (!memcmp(b_rev.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: per_tx(pre=num_hashes-num_tx-1,rev) data=%s\n", per_tx[pi].name);
            }
            if (!memcmp(n_fwd.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: per_tx(pre=num_hashes,fwd) data=%s\n", per_tx[pi].name);
            }
            if (!memcmp(n_rev.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: per_tx(pre=num_hashes,rev) data=%s\n", per_tx[pi].name);
            }
            if (!memcmp(n1_fwd.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: per_tx(pre=num_hashes-1,fwd) data=%s\n", per_tx[pi].name);
            }
            if (!memcmp(n1_rev.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: per_tx(pre=num_hashes-1,rev) data=%s\n", per_tx[pi].name);
            }

            /* Optional extra final hash after the per-tx loop (some variants do this). */
            sol_hash_t a_fwd_plus = a_fwd;
            sol_hash_t a_rev_plus = a_rev;
            sol_hash_t b_fwd_plus = b_fwd;
            sol_hash_t b_rev_plus = b_rev;
            sol_hash_t n_fwd_plus = n_fwd;
            sol_hash_t n_rev_plus = n_rev;
            sol_hash_t n1_fwd_plus = n1_fwd;
            sol_hash_t n1_rev_plus = n1_rev;
            sol_sha256_bytes(a_fwd_plus.bytes, 32, a_fwd_plus.bytes);
            sol_sha256_bytes(a_rev_plus.bytes, 32, a_rev_plus.bytes);
            sol_sha256_bytes(b_fwd_plus.bytes, 32, b_fwd_plus.bytes);
            sol_sha256_bytes(b_rev_plus.bytes, 32, b_rev_plus.bytes);
            sol_sha256_bytes(n_fwd_plus.bytes, 32, n_fwd_plus.bytes);
            sol_sha256_bytes(n_rev_plus.bytes, 32, n_rev_plus.bytes);
            sol_sha256_bytes(n1_fwd_plus.bytes, 32, n1_fwd_plus.bytes);
            sol_sha256_bytes(n1_rev_plus.bytes, 32, n1_rev_plus.bytes);
            if (!memcmp(a_fwd_plus.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: per_tx+1hash(pre=num_hashes-num_tx,fwd) data=%s\n", per_tx[pi].name);
            }
            if (!memcmp(a_rev_plus.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: per_tx+1hash(pre=num_hashes-num_tx,rev) data=%s\n", per_tx[pi].name);
            }
            if (!memcmp(b_fwd_plus.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: per_tx+1hash(pre=num_hashes-num_tx-1,fwd) data=%s\n", per_tx[pi].name);
            }
            if (!memcmp(b_rev_plus.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: per_tx+1hash(pre=num_hashes-num_tx-1,rev) data=%s\n", per_tx[pi].name);
            }
            if (!memcmp(n_fwd_plus.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: per_tx+1hash(pre=num_hashes,fwd) data=%s\n", per_tx[pi].name);
            }
            if (!memcmp(n_rev_plus.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: per_tx+1hash(pre=num_hashes,rev) data=%s\n", per_tx[pi].name);
            }
            if (!memcmp(n1_fwd_plus.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: per_tx+1hash(pre=num_hashes-1,fwd) data=%s\n", per_tx[pi].name);
            }
            if (!memcmp(n1_rev_plus.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: per_tx+1hash(pre=num_hashes-1,rev) data=%s\n", per_tx[pi].name);
            }

            /* Record-first variant: apply per-tx mix, then hash N or N-1 times. */
            sol_hash_t after_fwd = per_tx_mix(&start_hash, 0, e0, per_tx[pi].fn, false);
            sol_hash_t after_rev = per_tx_mix(&start_hash, 0, e0, per_tx[pi].fn, true);
            sol_hash_t out = {0};
            hash_n(&after_fwd, e0->num_hashes, &out);
            if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: per_tx_first(fwd) then hash_n(n) data=%s\n", per_tx[pi].name);
            }
            hash_n(&after_fwd, e0->num_hashes ? (e0->num_hashes - 1) : 0, &out);
            if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: per_tx_first(fwd) then hash_n(n-1) data=%s\n", per_tx[pi].name);
            }
            hash_n(&after_rev, e0->num_hashes, &out);
            if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: per_tx_first(rev) then hash_n(n) data=%s\n", per_tx[pi].name);
            }
            hash_n(&after_rev, e0->num_hashes ? (e0->num_hashes - 1) : 0, &out);
            if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
                printf("MATCH: per_tx_first(rev) then hash_n(n-1) data=%s\n", per_tx[pi].name);
            }
        }

        sol_hash_t raw_a_fwd = per_tx_mix_raw_bytes(&start_hash, pre_a, e0, false);
        sol_hash_t raw_a_rev = per_tx_mix_raw_bytes(&start_hash, pre_a, e0, true);
        sol_hash_t raw_b_fwd = per_tx_mix_raw_bytes(&start_hash, pre_b, e0, false);
        sol_hash_t raw_b_rev = per_tx_mix_raw_bytes(&start_hash, pre_b, e0, true);
        sol_hash_t raw_n_fwd = per_tx_mix_raw_bytes(&start_hash, pre_n, e0, false);
        sol_hash_t raw_n_rev = per_tx_mix_raw_bytes(&start_hash, pre_n, e0, true);
        sol_hash_t raw_n1_fwd = per_tx_mix_raw_bytes(&start_hash, pre_n1, e0, false);
        sol_hash_t raw_n1_rev = per_tx_mix_raw_bytes(&start_hash, pre_n1, e0, true);

        if (!memcmp(raw_a_fwd.bytes, e0->hash.bytes, 32)) {
            printf("MATCH: per_tx(pre=num_hashes-num_tx,fwd) data=raw_tx_bytes\n");
        }
        if (!memcmp(raw_a_rev.bytes, e0->hash.bytes, 32)) {
            printf("MATCH: per_tx(pre=num_hashes-num_tx,rev) data=raw_tx_bytes\n");
        }
        if (!memcmp(raw_b_fwd.bytes, e0->hash.bytes, 32)) {
            printf("MATCH: per_tx(pre=num_hashes-num_tx-1,fwd) data=raw_tx_bytes\n");
        }
        if (!memcmp(raw_b_rev.bytes, e0->hash.bytes, 32)) {
            printf("MATCH: per_tx(pre=num_hashes-num_tx-1,rev) data=raw_tx_bytes\n");
        }
        if (!memcmp(raw_n_fwd.bytes, e0->hash.bytes, 32)) {
            printf("MATCH: per_tx(pre=num_hashes,fwd) data=raw_tx_bytes\n");
        }
        if (!memcmp(raw_n_rev.bytes, e0->hash.bytes, 32)) {
            printf("MATCH: per_tx(pre=num_hashes,rev) data=raw_tx_bytes\n");
        }
        if (!memcmp(raw_n1_fwd.bytes, e0->hash.bytes, 32)) {
            printf("MATCH: per_tx(pre=num_hashes-1,fwd) data=raw_tx_bytes\n");
        }
        if (!memcmp(raw_n1_rev.bytes, e0->hash.bytes, 32)) {
            printf("MATCH: per_tx(pre=num_hashes-1,rev) data=raw_tx_bytes\n");
        }

        sol_hash_t raw_a_fwd_plus = raw_a_fwd;
        sol_hash_t raw_a_rev_plus = raw_a_rev;
        sol_hash_t raw_b_fwd_plus = raw_b_fwd;
        sol_hash_t raw_b_rev_plus = raw_b_rev;
        sol_hash_t raw_n_fwd_plus = raw_n_fwd;
        sol_hash_t raw_n_rev_plus = raw_n_rev;
        sol_hash_t raw_n1_fwd_plus = raw_n1_fwd;
        sol_hash_t raw_n1_rev_plus = raw_n1_rev;
        sol_sha256_bytes(raw_a_fwd_plus.bytes, 32, raw_a_fwd_plus.bytes);
        sol_sha256_bytes(raw_a_rev_plus.bytes, 32, raw_a_rev_plus.bytes);
        sol_sha256_bytes(raw_b_fwd_plus.bytes, 32, raw_b_fwd_plus.bytes);
        sol_sha256_bytes(raw_b_rev_plus.bytes, 32, raw_b_rev_plus.bytes);
        sol_sha256_bytes(raw_n_fwd_plus.bytes, 32, raw_n_fwd_plus.bytes);
        sol_sha256_bytes(raw_n_rev_plus.bytes, 32, raw_n_rev_plus.bytes);
        sol_sha256_bytes(raw_n1_fwd_plus.bytes, 32, raw_n1_fwd_plus.bytes);
        sol_sha256_bytes(raw_n1_rev_plus.bytes, 32, raw_n1_rev_plus.bytes);
        if (!memcmp(raw_a_fwd_plus.bytes, e0->hash.bytes, 32)) {
            printf("MATCH: per_tx+1hash(pre=num_hashes-num_tx,fwd) data=raw_tx_bytes\n");
        }
        if (!memcmp(raw_a_rev_plus.bytes, e0->hash.bytes, 32)) {
            printf("MATCH: per_tx+1hash(pre=num_hashes-num_tx,rev) data=raw_tx_bytes\n");
        }
        if (!memcmp(raw_b_fwd_plus.bytes, e0->hash.bytes, 32)) {
            printf("MATCH: per_tx+1hash(pre=num_hashes-num_tx-1,fwd) data=raw_tx_bytes\n");
        }
        if (!memcmp(raw_b_rev_plus.bytes, e0->hash.bytes, 32)) {
            printf("MATCH: per_tx+1hash(pre=num_hashes-num_tx-1,rev) data=raw_tx_bytes\n");
        }
        if (!memcmp(raw_n_fwd_plus.bytes, e0->hash.bytes, 32)) {
            printf("MATCH: per_tx+1hash(pre=num_hashes,fwd) data=raw_tx_bytes\n");
        }
        if (!memcmp(raw_n_rev_plus.bytes, e0->hash.bytes, 32)) {
            printf("MATCH: per_tx+1hash(pre=num_hashes,rev) data=raw_tx_bytes\n");
        }
        if (!memcmp(raw_n1_fwd_plus.bytes, e0->hash.bytes, 32)) {
            printf("MATCH: per_tx+1hash(pre=num_hashes-1,fwd) data=raw_tx_bytes\n");
        }
        if (!memcmp(raw_n1_rev_plus.bytes, e0->hash.bytes, 32)) {
            printf("MATCH: per_tx+1hash(pre=num_hashes-1,rev) data=raw_tx_bytes\n");
        }

        /* Record-first for raw tx bytes: mix per-tx bytes from the front, then hash N or N-1. */
        sol_hash_t raw_first_fwd = per_tx_mix_raw_bytes(&start_hash, 0, e0, false);
        sol_hash_t raw_first_rev = per_tx_mix_raw_bytes(&start_hash, 0, e0, true);
        sol_hash_t out = {0};
        hash_n(&raw_first_fwd, e0->num_hashes, &out);
        if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
            printf("MATCH: per_tx_first(fwd) then hash_n(n) data=raw_tx_bytes\n");
        }
        hash_n(&raw_first_fwd, e0->num_hashes ? (e0->num_hashes - 1) : 0, &out);
        if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
            printf("MATCH: per_tx_first(fwd) then hash_n(n-1) data=raw_tx_bytes\n");
        }
        hash_n(&raw_first_rev, e0->num_hashes, &out);
        if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
            printf("MATCH: per_tx_first(rev) then hash_n(n) data=raw_tx_bytes\n");
        }
        hash_n(&raw_first_rev, e0->num_hashes ? (e0->num_hashes - 1) : 0, &out);
        if (!memcmp(out.bytes, e0->hash.bytes, 32)) {
            printf("MATCH: per_tx_first(rev) then hash_n(n-1) data=raw_tx_bytes\n");
        }
    }

    sol_entry_batch_destroy(batch);
    sol_block_destroy(block);
    sol_blockstore_destroy(bs);
    sol_log_fini();

    return 0;
}
