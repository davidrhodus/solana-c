/*
 * fuzz_rpc_handle_request_json.c - Fuzz sol_rpc_handle_request_json
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "rpc/sol_rpc.h"

static sol_rpc_t* g_rpc = NULL;
static int g_rpc_cleanup_registered = 0;

static void
fuzz_cleanup_rpc(void) {
    sol_rpc_destroy(g_rpc);
    g_rpc = NULL;
}

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (!g_rpc) {
        sol_rpc_config_t cfg = (sol_rpc_config_t)SOL_RPC_CONFIG_DEFAULT;
        cfg.ws_port = 0; /* disable websocket listener in case it is started */
        g_rpc = sol_rpc_new(NULL, &cfg);
        if (!g_rpc) return 0;
        if (!g_rpc_cleanup_registered) {
            atexit(fuzz_cleanup_rpc);
            g_rpc_cleanup_registered = 1;
        }
    }

    sol_json_builder_t* resp = sol_json_builder_new(256);
    if (!resp) return 0;

    sol_rpc_handle_request_json(g_rpc, (const char*)data, size, resp);

    sol_json_builder_destroy(resp);
    return 0;
}

