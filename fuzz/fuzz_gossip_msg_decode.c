/*
 * fuzz_gossip_msg_decode.c - Fuzz sol_gossip_msg_decode
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "gossip/sol_gossip_msg.h"
#include "txn/sol_bincode.h"
#include "util/sol_arena.h"

static sol_arena_t* g_arena = NULL;
static int g_arena_cleanup_registered = 0;

static void
fuzz_cleanup_arena(void) {
    sol_arena_destroy(g_arena);
    g_arena = NULL;
}

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (!g_arena) {
        g_arena = sol_arena_new_default();
        if (!g_arena) {
            return 0;
        }
        if (!g_arena_cleanup_registered) {
            atexit(fuzz_cleanup_arena);
            g_arena_cleanup_registered = 1;
        }
    }

    sol_decoder_t dec;
    sol_decoder_init(&dec, data, size);

    sol_gossip_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    (void)sol_gossip_msg_decode(&dec, &msg, g_arena);

    sol_arena_reset(g_arena);
    return 0;
}
