/*
 * fuzz_snapshot_service_manifest_json.c - Fuzz snapshot-service manifest JSON parsing
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "snapshot/sol_snapshot_download.h"

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    /* Ensure NUL-termination so string scanning stays safe. */
    char* buf = (char*)malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    const char* manifest_url = "https://example.com/snapshot-manifest.json";

    sol_available_snapshot_t snapshots[32];
    memset(snapshots, 0, sizeof(snapshots));

    size_t count = sol_snapshot_service_parse_manifest_json(
        manifest_url, buf, size, snapshots, 32);
    sol_available_snapshots_free(snapshots, count);

    sol_available_snapshot_t full = {0};
    sol_available_snapshot_t incr = {0};
    (void)sol_snapshot_service_find_best_from_manifest_json(
        manifest_url, buf, size, NULL, &full, &incr);
    sol_available_snapshot_free(&full);
    sol_available_snapshot_free(&incr);

    free(buf);
    return 0;
}

