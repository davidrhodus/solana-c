/*
 * sol_tx_decode_tool.c - Decode base64-encoded transactions
 *
 * Usage:
 *   cat txs.b64 | sol-tx-decode
 *
 * Each input line should be a single base64-encoded transaction blob.
 * Exits non-zero if any transaction fails to decode.
 */

#include "../txn/sol_transaction.h"
#include "../util/sol_err.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Base64 decoding table (copied from src/rpc/sol_rpc.c).
 */
static const int8_t base64_decode_table[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

/*
 * Decode base64 string.
 * Returns decoded length, or -1 on error.
 */
static ssize_t
base64_decode(const char* input, size_t input_len, uint8_t* output, size_t output_max) {
    size_t out_len = 0;
    uint32_t buf = 0;
    int bits = 0;

    for (size_t i = 0; i < input_len; i++) {
        char c = input[i];

        /* Skip whitespace */
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;

        /* Handle padding */
        if (c == '=') break;

        int8_t val = base64_decode_table[(uint8_t)c];
        if (val < 0) return -1;  /* Invalid character */

        buf = (buf << 6) | (uint32_t)val;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            if (out_len >= output_max) return -1;  /* Output buffer full */
            output[out_len++] = (uint8_t)(buf >> bits);
        }
    }

    return (ssize_t)out_len;
}

int
main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    char* line = NULL;
    size_t cap = 0;
    ssize_t nread = 0;
    size_t line_no = 0;
    size_t ok = 0;
    size_t bad = 0;

    while ((nread = getline(&line, &cap, stdin)) != -1) {
        line_no++;

        /* Trim trailing newlines */
        while (nread > 0 && (line[nread - 1] == '\n' || line[nread - 1] == '\r')) {
            line[--nread] = '\0';
        }
        if (nread == 0) continue;

        uint8_t tx_bytes[4096];
        ssize_t tx_len = base64_decode(line, (size_t)nread, tx_bytes, sizeof(tx_bytes));
        if (tx_len < 0) {
            fprintf(stderr, "line %zu: invalid base64\n", line_no);
            bad++;
            continue;
        }

        sol_transaction_t tx;
        sol_err_t err = sol_transaction_decode(tx_bytes, (size_t)tx_len, &tx);
        if (err != SOL_OK) {
            fprintf(stderr, "line %zu: tx decode failed: %s (len=%zd)\n",
                    line_no, sol_err_str(err), tx_len);
            bad++;
            continue;
        }

        ok++;
    }

    if (ferror(stdin)) {
        fprintf(stderr, "error: failed to read stdin: %s\n", strerror(errno));
        free(line);
        return 2;
    }

    free(line);
    fprintf(stderr, "decoded=%zu failed=%zu\n", ok, bad);
    return bad ? 1 : 0;
}

