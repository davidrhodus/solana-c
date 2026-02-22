/*
 * fuzz_transaction_decode.c - Fuzz sol_transaction_decode / sanitize
 */

#include <stddef.h>
#include <stdint.h>

#include "txn/sol_transaction.h"

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    sol_transaction_t tx;
    if (sol_transaction_decode(data, size, &tx) == SOL_OK) {
        (void)sol_transaction_sanitize(&tx);
    }
    return 0;
}

