/*
 * fuzz_shred_parse.c - Fuzz sol_shred_parse
 */

#include <stddef.h>
#include <stdint.h>

#include "shred/sol_shred.h"

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    sol_shred_t shred;
    (void)sol_shred_parse(&shred, data, size);
    return 0;
}

