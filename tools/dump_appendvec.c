/* dump_appendvec.c - Parse and dump accounts from an Agave AppendVec file
 * Usage: dump_appendvec <appendvec_file>
 * Output: TSV with pubkey, lamports, data_len, owner, executable, data_sha256
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/sha.h>

/* Base58 encoding */
static const char B58_ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static void to_base58(const uint8_t* data, size_t len, char* out, size_t out_sz) {
    /* Count leading zeros */
    int zeros = 0;
    while (zeros < (int)len && data[zeros] == 0) zeros++;

    /* Allocate enough for base58 result */
    size_t buf_sz = len * 138 / 100 + 1;
    uint8_t* buf = calloc(buf_sz, 1);
    size_t buf_len = 0;

    for (size_t i = zeros; i < len; i++) {
        int carry = data[i];
        for (size_t j = 0; j < buf_len; j++) {
            carry += 256 * buf[j];
            buf[j] = carry % 58;
            carry /= 58;
        }
        while (carry) {
            buf[buf_len++] = carry % 58;
            carry /= 58;
        }
    }

    size_t pos = 0;
    for (int i = 0; i < zeros && pos < out_sz - 1; i++)
        out[pos++] = '1';
    for (size_t i = buf_len; i > 0 && pos < out_sz - 1; i--)
        out[pos++] = B58_ALPHABET[buf[i - 1]];
    out[pos] = '\0';
    free(buf);
}

/* SOLANA3 AppendVec layout (current mainnet):
 * Offset  Field           Size
 * 0-7     write_version   8 bytes (u64)
 * 8-15    data_len        8 bytes (u64)
 * 16-47   pubkey          32 bytes
 * 48-55   lamports        8 bytes (u64)
 * 56-63   rent_epoch      8 bytes (u64)
 * 64-95   owner           32 bytes
 * 96      executable      1 byte
 * 97+     account data    data_len bytes
 * 97+data_len  hash       32 bytes (account hash suffix)
 * Then align to 8 bytes for next record
 */

#define HEADER_SIZE 97
#define HASH_SUFFIX_SIZE 32

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <appendvec_file>\n", argv[0]);
        return 1;
    }

    FILE* fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    uint8_t* data = malloc(file_size);
    if (!data) {
        fprintf(stderr, "malloc failed for %zu bytes\n", file_size);
        fclose(fp);
        return 1;
    }
    size_t nread = fread(data, 1, file_size, fp);
    fclose(fp);

    if (nread != file_size) {
        fprintf(stderr, "Short read: %zu of %zu\n", nread, file_size);
        free(data);
        return 1;
    }

    printf("pubkey\tlamports\tdata_len\towner\texecutable\trent_epoch\tdata_sha256\n");

    size_t offset = 0;
    int count = 0;

    while (offset + HEADER_SIZE <= file_size) {
        /* Parse header */
        uint64_t write_version, data_len, lamports, rent_epoch;
        uint8_t pubkey[32], owner[32];
        uint8_t executable;

        memcpy(&write_version, data + offset + 0, 8);
        memcpy(&data_len, data + offset + 8, 8);
        memcpy(pubkey, data + offset + 16, 32);
        memcpy(&lamports, data + offset + 48, 8);
        memcpy(&rent_epoch, data + offset + 56, 8);
        memcpy(owner, data + offset + 64, 32);
        executable = data[offset + 96];

        /* Sanity checks */
        if (data_len > file_size) break;

        /* Check for all-zero (end of used region) */
        bool all_zero = (write_version == 0 && data_len == 0 && lamports == 0);
        if (all_zero) {
            /* Check if pubkey is also all zeros */
            bool pk_zero = true;
            for (int i = 0; i < 32; i++) {
                if (pubkey[i] != 0) { pk_zero = false; break; }
            }
            if (pk_zero) break;
        }

        size_t data_offset = offset + HEADER_SIZE;
        if (data_offset + data_len > file_size) break;

        /* Compute SHA256 of account data */
        char hash_hex[65] = {0};
        if (data_len > 0) {
            unsigned char hash[32];
            SHA256(data + data_offset, data_len, hash);
            for (int i = 0; i < 32; i++)
                sprintf(hash_hex + i * 2, "%02x", hash[i]);
        } else {
            strcpy(hash_hex, "empty");
        }

        /* Base58 encode pubkey and owner */
        char pk_b58[64], owner_b58[64];
        to_base58(pubkey, 32, pk_b58, sizeof(pk_b58));
        to_base58(owner, 32, owner_b58, sizeof(owner_b58));

        printf("%s\t%lu\t%lu\t%s\t%d\t%lu\t%s\n",
               pk_b58, lamports, data_len, owner_b58, executable,
               rent_epoch, hash_hex);

        count++;

        /* Advance to next record: header + data + 32-byte hash suffix, then align to 8 */
        size_t record_end = data_offset + data_len + HASH_SUFFIX_SIZE;
        offset = (record_end + 7) & ~7UL;
    }

    fprintf(stderr, "Parsed %d accounts from %s (%zu bytes)\n", count, argv[1], file_size);
    free(data);
    return 0;
}
