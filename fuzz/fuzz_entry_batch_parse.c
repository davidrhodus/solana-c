/*
 * fuzz_entry_batch_parse.c - Fuzz sol_entry_batch_parse
 */

#include <stddef.h>
#include <stdint.h>

#include "entry/sol_entry.h"

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    sol_entry_batch_t* batch = sol_entry_batch_new(0);
    if (!batch) return 0;

    (void)sol_entry_batch_parse(batch, data, size);

    sol_entry_batch_destroy(batch);
    return 0;
}

