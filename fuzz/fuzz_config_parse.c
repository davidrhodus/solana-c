/*
 * fuzz_config_parse.c - Fuzz sol_config_parse and basic getters
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "util/sol_alloc.h"
#include "util/sol_config.h"

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    /* Ensure NUL-termination so internal whitespace scanning is safe. */
    char* buf = (char*)malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    sol_config_t* cfg = NULL;
    sol_err_t err = sol_config_parse(buf, size, &cfg);
    if (err == SOL_OK && cfg) {
        (void)sol_config_get_string(cfg, "identity", "keypair", NULL);
        (void)sol_config_get_int(cfg, "network", "tpu_port", 0);
        (void)sol_config_get_bool(cfg, "network", "enable_quic", false);

        char** entrypoints = NULL;
        size_t entrypoints_count = 0;
        if (sol_config_get_string_array(cfg, "network", "entrypoints",
                                        &entrypoints, &entrypoints_count) == SOL_OK) {
            if (entrypoints) {
                for (size_t i = 0; i < entrypoints_count; i++) {
                    sol_free(entrypoints[i]);
                }
                sol_free(entrypoints);
            }
        }

        sol_config_destroy(cfg);
    } else if (cfg) {
        sol_config_destroy(cfg);
    }

    free(buf);
    return 0;
}
