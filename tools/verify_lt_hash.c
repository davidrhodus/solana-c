/*
 * verify_lt_hash.c — verify lt_hash computation from delta dump data.
 *
 * Usage: verify_lt_hash <dump_dir> <slot>
 *
 * Reads:
 *   - lt_hash_base.<slot>.bin            (2048 bytes)
 *   - lt_hash_final.<slot>.bin           (2048 bytes)
 *   - delta_accounts.<slot>.tsv          (per-account metadata)
 *   - solanac_{acct,vote,sysvar}_<slot>_<pubkey>.bin       (current data)
 *   - solanac_{acct,vote,sysvar}_prev_<slot>_<pubkey>.bin  (previous data)
 *
 * Recomputes the final lt_hash from scratch and compares with the dumped final.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>

/* We'll link against the project's blake3 and lt_hash functions.
 * For standalone compilation, use a simpler approach: include headers. */

/* LT hash is 1024 uint16_t values = 2048 bytes */
#define LT_HASH_ELEMENTS 1024
#define LT_HASH_BYTES    2048
#define PUBKEY_SIZE       32

/* blake3 - use the project's implementation */
#include "../src/crypto/sol_blake3.h"
#include "../src/crypto/sol_sha256.h"
#include "../src/txn/sol_pubkey.h"

typedef struct {
    uint16_t v[LT_HASH_ELEMENTS];
} lt_hash_t;

static void lt_hash_identity(lt_hash_t *h) {
    memset(h, 0, sizeof(*h));
}

static void lt_hash_mix_in(lt_hash_t *self, const lt_hash_t *other) {
    for (int i = 0; i < LT_HASH_ELEMENTS; i++)
        self->v[i] = (uint16_t)(self->v[i] + other->v[i]);
}

static void lt_hash_mix_out(lt_hash_t *self, const lt_hash_t *other) {
    for (int i = 0; i < LT_HASH_ELEMENTS; i++)
        self->v[i] = (uint16_t)(self->v[i] - other->v[i]);
}

static void lt_hash_checksum(const lt_hash_t *h, uint8_t *out32) {
    sol_blake3_t cksum;
    sol_blake3_hash((const uint8_t*)h->v, LT_HASH_BYTES, &cksum);
    memcpy(out32, cksum.bytes, 32);
}

/* Compute per-account lt_hash: BLAKE3-XOF(lamports_le8 || data || exec_u8 || owner_32 || pubkey_32) */
static void account_lt_hash(const uint8_t *pubkey, uint64_t lamports,
                             const uint8_t *data, uint64_t data_len,
                             uint8_t executable, const uint8_t *owner,
                             lt_hash_t *out) {
    if (lamports == 0) {
        lt_hash_identity(out);
        return;
    }

    sol_blake3_ctx_t ctx;
    sol_blake3_init(&ctx);

    uint8_t lam_le[8];
    for (int i = 0; i < 8; i++) lam_le[i] = (uint8_t)(lamports >> (i*8));
    sol_blake3_update(&ctx, lam_le, 8);

    if (data && data_len > 0)
        sol_blake3_update(&ctx, data, (size_t)data_len);

    uint8_t ex = executable ? 1 : 0;
    sol_blake3_update(&ctx, &ex, 1);
    sol_blake3_update(&ctx, owner, PUBKEY_SIZE);
    sol_blake3_update(&ctx, pubkey, PUBKEY_SIZE);

    sol_blake3_final_xof(&ctx, (uint8_t*)out->v, LT_HASH_BYTES);
}

static void b58_encode(const uint8_t *data, size_t len, char *out, size_t out_sz) {
    sol_pubkey_to_base58((const sol_pubkey_t*)data, out, out_sz);
}

/* Read entire file into malloc'd buffer; returns size */
static uint8_t* read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) { *out_len = 0; return NULL; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); *out_len = 0; return NULL; }
    *out_len = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    return buf;
}

/* Base58 decode pubkey */
static int b58_decode_pubkey(const char *b58, uint8_t *out32) {
    sol_pubkey_t pk;
    sol_err_t err = sol_pubkey_from_base58(b58, &pk);
    if (err == SOL_OK) memcpy(out32, pk.bytes, 32);
    return (err == SOL_OK) ? 32 : 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <dump_dir> <slot>\n", argv[0]);
        return 1;
    }

    const char *dump_dir = argv[1];
    uint64_t slot = strtoull(argv[2], NULL, 10);

    /* Read base and final lt_hash */
    char path[512];
    lt_hash_t base_lt, final_lt;

    snprintf(path, sizeof(path), "%s/lt_hash_base.%lu.bin", dump_dir, (unsigned long)slot);
    {
        size_t sz;
        uint8_t *d = read_file(path, &sz);
        if (!d || sz != LT_HASH_BYTES) {
            fprintf(stderr, "Failed to read base lt_hash from %s (got %zu bytes)\n", path, sz);
            return 1;
        }
        memcpy(&base_lt, d, LT_HASH_BYTES);
        free(d);
    }

    snprintf(path, sizeof(path), "%s/lt_hash_final.%lu.bin", dump_dir, (unsigned long)slot);
    {
        size_t sz;
        uint8_t *d = read_file(path, &sz);
        if (!d || sz != LT_HASH_BYTES) {
            fprintf(stderr, "Failed to read final lt_hash from %s\n", path);
            return 1;
        }
        memcpy(&final_lt, d, LT_HASH_BYTES);
        free(d);
    }

    /* Log checksums */
    {
        uint8_t bcs[32], fcs[32];
        lt_hash_checksum(&base_lt, bcs);
        lt_hash_checksum(&final_lt, fcs);
        char bb58[64], fb58[64];
        b58_encode(bcs, 32, bb58, sizeof(bb58));
        b58_encode(fcs, 32, fb58, sizeof(fb58));
        printf("Base lt_hash checksum:  %s\n", bb58);
        printf("Final lt_hash checksum: %s\n", fb58);
    }

    /* Read TSV and process each account */
    snprintf(path, sizeof(path), "%s/delta_accounts.%lu.tsv", dump_dir, (unsigned long)slot);
    FILE *tsv = fopen(path, "r");
    if (!tsv) {
        fprintf(stderr, "Failed to open %s\n", path);
        return 1;
    }

    lt_hash_t recomputed = base_lt;
    char line[4096];
    int line_num = 0;
    int n_accounts = 0;
    int n_mismatches = 0;

    while (fgets(line, sizeof(line), tsv)) {
        line_num++;
        if (line_num == 1) continue; /* skip header */

        /* Parse: pubkey \t prev_lamports \t curr_lamports \t prev_data_len \t curr_data_len \t owner \t type \t executable \t data_hash \t curr_lthash \t prev_lthash \t prev_data_hash */
        char pubkey_b58[64] = {0}, owner_b58[64] = {0}, type_str[16] = {0};
        uint64_t prev_lam = 0, curr_lam = 0, prev_dlen = 0, curr_dlen = 0;
        int executable = 0;
        char data_hash_hex[17] = {0}, curr_lth_hex[33] = {0}, prev_lth_hex[33] = {0}, prev_dh_hex[17] = {0};

        int fields = sscanf(line, "%63s\t%lu\t%lu\t%lu\t%lu\t%63s\t%15s\t%d\t%16s\t%32s\t%32s\t%16s",
                           pubkey_b58, &prev_lam, &curr_lam, &prev_dlen, &curr_dlen,
                           owner_b58, type_str, &executable, data_hash_hex, curr_lth_hex, prev_lth_hex, prev_dh_hex);
        if (fields < 8) continue;

        /* Decode pubkey and owner */
        uint8_t pubkey[32], owner[32];
        if (b58_decode_pubkey(pubkey_b58, pubkey) != 32) {
            fprintf(stderr, "Bad pubkey at line %d: %s\n", line_num, pubkey_b58);
            continue;
        }
        if (b58_decode_pubkey(owner_b58, owner) != 32) {
            fprintf(stderr, "Bad owner at line %d: %s\n", line_num, owner_b58);
            continue;
        }

        /* Determine prefix for data file */
        const char *prefix = "solanac_acct";
        /* Check if sysvar */
        uint8_t sysvar_owner[32];
        b58_decode_pubkey("Sysvar1111111111111111111111111111111111111", sysvar_owner);
        uint8_t vote_owner[32];
        b58_decode_pubkey("Vote111111111111111111111111111111111111111", vote_owner);
        if (memcmp(owner, sysvar_owner, 32) == 0) prefix = "solanac_sysvar";
        else if (memcmp(owner, vote_owner, 32) == 0) prefix = "solanac_vote";

        /* Read current account data */
        uint8_t *curr_data = NULL;
        size_t curr_data_sz = 0;
        if (curr_dlen > 0) {
            snprintf(path, sizeof(path), "%s/%s_%lu_%s.bin", dump_dir, prefix, (unsigned long)slot, pubkey_b58);
            curr_data = read_file(path, &curr_data_sz);
            if (!curr_data || curr_data_sz != (size_t)curr_dlen) {
                fprintf(stderr, "WARN: Cannot read curr data for %s (expected %lu, got %zu from %s)\n",
                        pubkey_b58, (unsigned long)curr_dlen, curr_data_sz, path);
                /* Try with other prefixes */
                if (!curr_data) {
                    snprintf(path, sizeof(path), "%s/solanac_acct_%lu_%s.bin", dump_dir, (unsigned long)slot, pubkey_b58);
                    curr_data = read_file(path, &curr_data_sz);
                }
                if (!curr_data) {
                    snprintf(path, sizeof(path), "%s/solanac_vote_%lu_%s.bin", dump_dir, (unsigned long)slot, pubkey_b58);
                    curr_data = read_file(path, &curr_data_sz);
                }
                if (!curr_data) {
                    snprintf(path, sizeof(path), "%s/solanac_sysvar_%lu_%s.bin", dump_dir, (unsigned long)slot, pubkey_b58);
                    curr_data = read_file(path, &curr_data_sz);
                }
            }
        }

        /* Read previous account data */
        uint8_t *prev_data = NULL;
        size_t prev_data_sz = 0;
        if (prev_dlen > 0) {
            snprintf(path, sizeof(path), "%s/%s_prev_%lu_%s.bin", dump_dir, prefix, (unsigned long)slot, pubkey_b58);
            prev_data = read_file(path, &prev_data_sz);
            if (!prev_data) {
                snprintf(path, sizeof(path), "%s/solanac_acct_prev_%lu_%s.bin", dump_dir, (unsigned long)slot, pubkey_b58);
                prev_data = read_file(path, &prev_data_sz);
            }
            if (!prev_data) {
                snprintf(path, sizeof(path), "%s/solanac_vote_prev_%lu_%s.bin", dump_dir, (unsigned long)slot, pubkey_b58);
                prev_data = read_file(path, &prev_data_sz);
            }
            if (!prev_data) {
                snprintf(path, sizeof(path), "%s/solanac_sysvar_prev_%lu_%s.bin", dump_dir, (unsigned long)slot, pubkey_b58);
                prev_data = read_file(path, &prev_data_sz);
            }
        }

        /* Compute prev and curr lt_hash */
        lt_hash_t prev_h, curr_h;

        if (prev_lam > 0) {
            account_lt_hash(pubkey, prev_lam, prev_data, prev_dlen, 0 /* prev exec unknown, use 0 */, owner, &prev_h);
        } else {
            lt_hash_identity(&prev_h);
        }

        if (curr_lam > 0) {
            account_lt_hash(pubkey, curr_lam, curr_data, curr_dlen, (uint8_t)executable, owner, &curr_h);
        } else {
            lt_hash_identity(&curr_h);
        }

        /* Verify curr lt_hash matches what was logged (first 16 bytes) */
        uint8_t expected_curr_lth[16];
        for (int i = 0; i < 16 && i*2+1 < (int)strlen(curr_lth_hex); i++) {
            unsigned v;
            sscanf(curr_lth_hex + i*2, "%02x", &v);
            expected_curr_lth[i] = (uint8_t)v;
        }
        if (memcmp(expected_curr_lth, curr_h.v, 16) != 0 && curr_lam > 0) {
            printf("MISMATCH curr_lthash for %s: computed=", pubkey_b58);
            for (int i = 0; i < 16; i++) printf("%02x", ((uint8_t*)curr_h.v)[i]);
            printf(" expected=%s\n", curr_lth_hex);
            n_mismatches++;
        }

        /* Apply delta to recomputed hash */
        lt_hash_mix_out(&recomputed, &prev_h);
        lt_hash_mix_in(&recomputed, &curr_h);
        n_accounts++;

        free(curr_data);
        free(prev_data);
    }
    fclose(tsv);

    /* Compare recomputed with final */
    uint8_t rcs[32];
    lt_hash_checksum(&recomputed, rcs);
    char rb58[64];
    b58_encode(rcs, 32, rb58, sizeof(rb58));
    printf("\nRecomputed lt_hash checksum: %s\n", rb58);
    printf("Accounts processed: %d\n", n_accounts);
    printf("Lt_hash mismatches: %d\n", n_mismatches);

    if (memcmp(&recomputed, &final_lt, LT_HASH_BYTES) == 0) {
        printf("RESULT: Recomputed MATCHES final lt_hash ✓\n");
    } else {
        printf("RESULT: Recomputed DOES NOT match final lt_hash ✗\n");

        /* Find the first differing element */
        int diff_count = 0;
        for (int i = 0; i < LT_HASH_ELEMENTS; i++) {
            if (recomputed.v[i] != final_lt.v[i]) {
                if (diff_count < 10) {
                    printf("  Diff at [%d]: recomputed=%u final=%u\n", i, recomputed.v[i], final_lt.v[i]);
                }
                diff_count++;
            }
        }
        printf("  Total differing elements: %d / %d\n", diff_count, LT_HASH_ELEMENTS);
    }

    return 0;
}
