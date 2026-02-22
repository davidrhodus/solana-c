/*
 * sol_signature.c - Solana signature operations
 */

#include "sol_signature.h"
#include <string.h>

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
 * Convert signature to base58 string
 */
sol_err_t
sol_signature_to_base58(
    const sol_signature_t* sig,
    char*                  out,
    size_t                 out_len
) {
    if (out_len < SOL_SIGNATURE_BASE58_LEN) {
        return SOL_ERR_INVAL;
    }

    /* Count leading zeros */
    int leading_zeros = 0;
    while (leading_zeros < SOL_SIGNATURE_SIZE && sig->bytes[leading_zeros] == 0) {
        leading_zeros++;
    }

    /* Work buffer for base conversion */
    uint8_t buf[90];  /* Max output size */
    int buf_len = 0;

    /* Convert to base58 (big-endian division) */
    uint8_t input[SOL_SIGNATURE_SIZE];
    memcpy(input, sig->bytes, SOL_SIGNATURE_SIZE);

    int input_len = SOL_SIGNATURE_SIZE;
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
 * Parse signature from base58 string
 */
sol_err_t
sol_signature_from_base58(
    const char*      str,
    sol_signature_t* sig
) {
    size_t len = strlen(str);
    if (len == 0 || len > 88) {
        return SOL_ERR_INVAL;
    }

    /* Count leading '1's (zeros in output) */
    int leading_ones = 0;
    while (str[leading_ones] == '1') {
        leading_ones++;
    }

    /* Work buffer */
    uint8_t buf[SOL_SIGNATURE_SIZE];
    memset(buf, 0, sizeof(buf));

    /* Convert from base58 */
    for (size_t i = leading_ones; i < len; i++) {
        int8_t val = BASE58_DECODE[(uint8_t)str[i]];
        if (val < 0) {
            return SOL_ERR_INVAL;
        }

        /* Multiply existing value by 58 and add new digit */
        uint32_t carry = val;
        for (int j = SOL_SIGNATURE_SIZE - 1; j >= 0; j--) {
            carry += (uint32_t)buf[j] * 58;
            buf[j] = carry & 0xff;
            carry >>= 8;
        }

        if (carry != 0) {
            return SOL_ERR_INVAL;  /* Overflow */
        }
    }

    memcpy(sig->bytes, buf, SOL_SIGNATURE_SIZE);
    return SOL_OK;
}
