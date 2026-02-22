/*
 * read_tx_status.c - Read transaction statuses from Agave blockstore
 *
 * Usage: ./read_tx_status <rocksdb_path> <slot>
 *
 * Iterates the transaction_status column family and dumps entries
 * for the given slot.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rocksdb/c.h>

static const char BASE58_CHARS[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static void to_base58(const unsigned char* data, size_t len, char* out, size_t out_len) {
    /* Simple base58 encoder for 64-byte signatures */
    unsigned char tmp[128];
    if (len > sizeof(tmp)) { out[0] = 0; return; }
    memcpy(tmp, data, len);

    size_t out_idx = 0;
    /* Count leading zeros */
    size_t leading = 0;
    while (leading < len && tmp[leading] == 0) leading++;

    size_t j = 0;
    unsigned char buf[256];
    memset(buf, 0, sizeof(buf));
    size_t buf_len = 0;

    for (size_t i = 0; i < len; i++) {
        int carry = tmp[i];
        for (size_t k = 0; k < buf_len; k++) {
            carry += 256 * buf[k];
            buf[k] = carry % 58;
            carry /= 58;
        }
        while (carry) {
            if (buf_len >= sizeof(buf)) break;
            buf[buf_len++] = carry % 58;
            carry /= 58;
        }
    }

    for (size_t i = 0; i < leading && out_idx < out_len - 1; i++)
        out[out_idx++] = '1';
    for (size_t i = buf_len; i > 0 && out_idx < out_len - 1; i--)
        out[out_idx++] = BASE58_CHARS[buf[i-1]];
    out[out_idx] = 0;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <rocksdb_path> <slot>\n", argv[0]);
        return 1;
    }

    const char* db_path = argv[1];
    uint64_t target_slot = (uint64_t)atoll(argv[2]);

    /* List column families first */
    rocksdb_options_t* opts = rocksdb_options_create();
    rocksdb_options_set_create_if_missing(opts, 0);

    char* err = NULL;
    size_t cf_count = 0;
    char** cf_names = rocksdb_list_column_families(opts, db_path, &cf_count, &err);
    if (err) {
        fprintf(stderr, "Error listing CFs: %s\n", err);
        free(err);
        return 1;
    }

    printf("Column families (%zu):\n", cf_count);
    int tx_status_idx = -1;
    for (size_t i = 0; i < cf_count; i++) {
        printf("  [%zu] %s\n", i, cf_names[i]);
        if (strcmp(cf_names[i], "transaction_status") == 0) {
            tx_status_idx = (int)i;
        }
    }

    if (tx_status_idx < 0) {
        fprintf(stderr, "No transaction_status column family found\n");
        return 1;
    }

    /* Open DB with all column families */
    rocksdb_options_t** cf_opts = malloc(cf_count * sizeof(rocksdb_options_t*));
    rocksdb_column_family_handle_t** cf_handles = malloc(cf_count * sizeof(rocksdb_column_family_handle_t*));

    for (size_t i = 0; i < cf_count; i++) {
        cf_opts[i] = rocksdb_options_create();
    }

    rocksdb_t* db = rocksdb_open_column_families(
        opts, db_path,
        (int)cf_count,
        (const char* const*)cf_names,
        (const rocksdb_options_t* const*)cf_opts,
        cf_handles,
        &err
    );

    if (err) {
        fprintf(stderr, "Error opening DB: %s\n", err);
        free(err);
        return 1;
    }

    printf("\nScanning transaction_status for slot %lu...\n", (unsigned long)target_slot);

    /* Create iterator on transaction_status CF */
    rocksdb_readoptions_t* read_opts = rocksdb_readoptions_create();
    rocksdb_iterator_t* iter = rocksdb_create_iterator_cf(
        db, read_opts, cf_handles[tx_status_idx]
    );

    int count = 0;
    int match_count = 0;

    rocksdb_iter_seek_to_first(iter);
    while (rocksdb_iter_valid(iter)) {
        size_t key_len = 0, val_len = 0;
        const char* key = rocksdb_iter_key(iter, &key_len);
        const char* val = rocksdb_iter_value(iter, &val_len);
        count++;

        /*
         * Agave transaction_status key format:
         *   - primary_index: u64 (8 bytes, big-endian)
         *   - signature: 64 bytes
         *   - slot: u64 (8 bytes, big-endian)
         *
         * Total: 80 bytes
         *
         * OR it might be:
         *   - slot: u64 (8 bytes)
         *   - signature: 64 bytes
         *
         * Total: 72 bytes
         */

        if (key_len >= 72) {
            /* Try format: primary_index(8) + signature(64) + slot(8) = 80 */
            uint64_t slot_be = 0;
            if (key_len == 80) {
                memcpy(&slot_be, key + 72, 8);
                /* Big-endian to host */
                uint64_t slot = __builtin_bswap64(slot_be);
                if (slot == target_slot) {
                    char sig_b58[128] = {0};
                    to_base58((const unsigned char*)key + 8, 64, sig_b58, sizeof(sig_b58));
                    printf("  [80-byte key] sig=%s slot=%lu val_len=%zu\n",
                           sig_b58, (unsigned long)slot, val_len);

                    /* Dump first bytes of value */
                    if (val_len > 0) {
                        printf("    val[0..%zu]: ", val_len < 32 ? val_len : (size_t)32);
                        for (size_t i = 0; i < val_len && i < 32; i++)
                            printf("%02x ", (unsigned char)val[i]);
                        printf("\n");
                    }
                    match_count++;
                }
            }

            /* Try format: slot(8) + signature(64) = 72 */
            if (key_len >= 72) {
                memcpy(&slot_be, key, 8);
                uint64_t slot = __builtin_bswap64(slot_be);
                if (slot == target_slot && key_len >= 72) {
                    char sig_b58[128] = {0};
                    to_base58((const unsigned char*)key + 8, 64, sig_b58, sizeof(sig_b58));
                    if (match_count == 0) { /* avoid double-reporting */
                        printf("  [72-byte key] sig=%s slot=%lu val_len=%zu\n",
                               sig_b58, (unsigned long)slot, val_len);
                        if (val_len > 0) {
                            printf("    val[0..%zu]: ", val_len < 32 ? val_len : (size_t)32);
                            for (size_t i = 0; i < val_len && i < 32; i++)
                                printf("%02x ", (unsigned char)val[i]);
                            printf("\n");
                        }
                        match_count++;
                    }
                }
            }
        }

        if (count <= 5 || count % 10000 == 0) {
            printf("  entry %d: key_len=%zu val_len=%zu\n", count, key_len, val_len);
            if (key_len > 0) {
                printf("    key[0..%zu]: ", key_len < 16 ? key_len : (size_t)16);
                for (size_t i = 0; i < key_len && i < 16; i++)
                    printf("%02x ", (unsigned char)key[i]);
                printf("\n");
            }
        }

        rocksdb_iter_next(iter);

        /* Don't scan forever */
        if (count > 100000 && match_count == 0) {
            printf("  ... scanned %d entries without match, stopping\n", count);
            break;
        }
    }

    printf("\nTotal entries scanned: %d, matches for slot %lu: %d\n",
           count, (unsigned long)target_slot, match_count);

    rocksdb_iter_destroy(iter);
    rocksdb_readoptions_destroy(read_opts);

    for (size_t i = 0; i < cf_count; i++) {
        rocksdb_column_family_handle_destroy(cf_handles[i]);
        rocksdb_options_destroy(cf_opts[i]);
    }
    rocksdb_close(db);
    rocksdb_options_destroy(opts);
    rocksdb_list_column_families_destroy(cf_names, cf_count);
    free(cf_opts);
    free(cf_handles);

    return 0;
}
