/*
 * sol_pubkey.c - Solana public key extended operations
 */

#include "sol_pubkey.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/*
 * Base58 alphabet (Bitcoin style)
 */
static const char BASE58_ALPHABET[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/*
 * Base58 decode table
 */
static const int8_t BASE58_DECODE[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
};

/*
 * Convert pubkey to base58 string
 */
sol_err_t
sol_pubkey_to_base58(
    const sol_pubkey_t* pk,
    char*               out,
    size_t              out_len
) {
    if (out_len < SOL_PUBKEY_BASE58_LEN) {
        return SOL_ERR_INVAL;
    }

    /* Count leading zeros */
    int leading_zeros = 0;
    while (leading_zeros < SOL_PUBKEY_SIZE && pk->bytes[leading_zeros] == 0) {
        leading_zeros++;
    }

    /* Work buffer for base conversion */
    uint8_t buf[45];  /* Max output size */
    int buf_len = 0;

    /* Convert to base58 (big-endian division) */
    /* Skip if input is all zeros */
    if (leading_zeros < SOL_PUBKEY_SIZE) {
        uint8_t input[SOL_PUBKEY_SIZE];
        memcpy(input, pk->bytes, SOL_PUBKEY_SIZE);

        int input_len = SOL_PUBKEY_SIZE;
        while (input_len > 0) {
            uint32_t carry = 0;
            int new_len = 0;

            for (int i = 0; i < input_len; i++) {
                carry = carry * 256 + input[i];
                if (new_len > 0 || carry >= 58) {
                    input[new_len++] = carry / 58;
                    carry = carry % 58;
                }
            }

            buf[buf_len++] = (uint8_t)carry;
            input_len = new_len;
        }
    }

    /* Add leading '1's for each leading zero byte */
    int out_pos = 0;
    for (int i = 0; i < leading_zeros; i++) {
        out[out_pos++] = '1';
    }

    /* Reverse the result */
    for (int i = buf_len - 1; i >= 0; i--) {
        out[out_pos++] = BASE58_ALPHABET[buf[i]];
    }
    out[out_pos] = '\0';

    return SOL_OK;
}

/*
 * Parse pubkey from base58 string
 */
sol_err_t
sol_pubkey_from_base58(
    const char*   str,
    sol_pubkey_t* pk
) {
    size_t len = strlen(str);
    if (len == 0 || len > 44) {
        return SOL_ERR_INVAL;
    }

    /* Count leading '1's (zeros in output) */
    int leading_ones = 0;
    while (str[leading_ones] == '1') {
        leading_ones++;
    }

    /* Work buffer */
    uint8_t buf[SOL_PUBKEY_SIZE];
    memset(buf, 0, sizeof(buf));

    /* Convert from base58 */
    for (size_t i = leading_ones; i < len; i++) {
        int8_t val = BASE58_DECODE[(uint8_t)str[i]];
        if (val < 0) {
            return SOL_ERR_INVAL;
        }

        /* Multiply existing value by 58 and add new digit */
        uint32_t carry = val;
        for (int j = SOL_PUBKEY_SIZE - 1; j >= 0; j--) {
            carry += (uint32_t)buf[j] * 58;
            buf[j] = carry & 0xff;
            carry >>= 8;
        }

        if (carry != 0) {
            return SOL_ERR_INVAL;  /* Overflow */
        }
    }

    /* Check that leading zeros match */
    int leading_zeros = 0;
    while (leading_zeros < SOL_PUBKEY_SIZE && buf[leading_zeros] == 0) {
        leading_zeros++;
    }

    /* The number of leading zeros should be >= leading_ones */
    if (leading_zeros < leading_ones) {
        return SOL_ERR_INVAL;
    }

    memcpy(pk->bytes, buf, SOL_PUBKEY_SIZE);
    return SOL_OK;
}

/*
 * Hash pubkey for hash tables (using first 8 bytes as uint64)
 */
uint64_t
sol_pubkey_hash(const sol_pubkey_t* pk) {
    /* Use first 8 bytes as a simple hash */
    uint64_t h = 0;
    for (int i = 0; i < 8; i++) {
        h = (h << 8) | pk->bytes[i];
    }
    /* Mix bits a bit */
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    return h;
}

/*
 * Load pubkey from a file containing base58-encoded address
 */
sol_err_t
sol_pubkey_load(const char* path, sol_pubkey_t* pk) {
    if (!path || !pk) {
        return SOL_ERR_INVAL;
    }

    FILE* f = fopen(path, "r");
    if (!f) {
        return SOL_ERR_IO;
    }

    char buf[64];  /* More than enough for base58 */
    size_t len = 0;

    /* Read and skip whitespace */
    int c;
    while ((c = fgetc(f)) != EOF && len < sizeof(buf) - 1) {
        if (!isspace(c)) {
            buf[len++] = (char)c;
        }
    }
    buf[len] = '\0';
    fclose(f);

    if (len == 0) {
        return SOL_ERR_INVAL;
    }

    return sol_pubkey_from_base58(buf, pk);
}

/*
 * Save pubkey to file in base58 format
 */
sol_err_t
sol_pubkey_save(const char* path, const sol_pubkey_t* pk) {
    if (!path || !pk) {
        return SOL_ERR_INVAL;
    }

    char buf[SOL_PUBKEY_BASE58_LEN];
    sol_err_t err = sol_pubkey_to_base58(pk, buf, sizeof(buf));
    if (err != SOL_OK) {
        return err;
    }

    FILE* f = fopen(path, "w");
    if (!f) {
        return SOL_ERR_IO;
    }

    fprintf(f, "%s\n", buf);
    fclose(f);

    return SOL_OK;
}
