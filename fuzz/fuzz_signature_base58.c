/*
 * fuzz_signature_base58.c - Fuzz sol_signature_from_base58
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "txn/sol_signature.h"

static const char BASE58_ALPHABET[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    size_t n = size;
    if (n > 88) n = 88;

    char* s = (char*)malloc(n + 1);
    if (!s) return 0;

    int force_valid = (size > 0) ? (data[0] & 1) : 0;
    for (size_t i = 0; i < n; i++) {
        if (force_valid) {
            s[i] = BASE58_ALPHABET[data[i] % (sizeof(BASE58_ALPHABET) - 1)];
        } else {
            s[i] = (char)data[i];
        }
    }
    s[n] = '\0';

    sol_signature_t sig;
    (void)sol_signature_from_base58(s, &sig);

    free(s);
    return 0;
}

