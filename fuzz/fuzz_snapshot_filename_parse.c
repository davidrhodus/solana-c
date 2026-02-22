/*
 * fuzz_snapshot_filename_parse.c - Fuzz snapshot archive filename parsing
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "snapshot/sol_snapshot.h"

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    /* Ensure NUL-termination so path splitting stays safe. */
    char* buf = (char*)malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    sol_snapshot_info_t info;
    (void)sol_snapshot_get_info(buf, &info);

    char out[256];
    (void)sol_snapshot_archive_name(&info, out, sizeof(out));

    free(buf);
    return 0;
}

