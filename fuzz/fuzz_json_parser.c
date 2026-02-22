/*
 * fuzz_json_parser.c - Fuzz sol_json_parser_* helpers
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rpc/sol_rpc.h"

static void
fuzz_parse_value(sol_json_parser_t* p) {
    char tmp[64];
    int64_t i64 = 0;
    uint64_t u64 = 0;
    bool b = false;

    size_t before = p->pos;

    if (sol_json_parser_object_begin(p)) {
        for (int i = 0; i < 64; i++) {
            if (sol_json_parser_object_end(p)) break;
            if (!sol_json_parser_key(p, tmp, sizeof(tmp))) break;

            if (sol_json_parser_string(p, tmp, sizeof(tmp))) {
                /* ok */
            } else if (sol_json_parser_int(p, &i64)) {
                /* ok */
            } else if (sol_json_parser_uint(p, &u64)) {
                /* ok */
            } else if (sol_json_parser_bool(p, &b)) {
                /* ok */
            } else if (sol_json_parser_null(p)) {
                /* ok */
            } else {
                (void)sol_json_parser_skip(p);
            }

            if (p->pos == before) break;
            before = p->pos;
        }
        (void)sol_json_parser_object_end(p);
        return;
    }

    if (sol_json_parser_array_begin(p)) {
        for (int i = 0; i < 128; i++) {
            if (sol_json_parser_array_end(p)) break;

            if (sol_json_parser_string(p, tmp, sizeof(tmp))) {
                /* ok */
            } else if (sol_json_parser_int(p, &i64)) {
                /* ok */
            } else if (sol_json_parser_uint(p, &u64)) {
                /* ok */
            } else if (sol_json_parser_bool(p, &b)) {
                /* ok */
            } else if (sol_json_parser_null(p)) {
                /* ok */
            } else {
                (void)sol_json_parser_skip(p);
            }

            if (p->pos == before) break;
            before = p->pos;
        }
        (void)sol_json_parser_array_end(p);
        return;
    }

    /* Primitive */
    if (sol_json_parser_string(p, tmp, sizeof(tmp))) return;
    if (sol_json_parser_int(p, &i64)) return;
    if (sol_json_parser_uint(p, &u64)) return;
    if (sol_json_parser_bool(p, &b)) return;
    if (sol_json_parser_null(p)) return;
    (void)sol_json_parser_skip(p);
}

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    char* json = (char*)malloc(size + 1);
    if (!json) return 0;
    memcpy(json, data, size);
    json[size] = '\0';

    sol_json_parser_t p;
    sol_json_parser_init(&p, json, size);

    for (int i = 0; i < 16 && p.pos < p.len; i++) {
        size_t before = p.pos;
        fuzz_parse_value(&p);
        if (p.pos <= before) break;
    }

    free(json);
    return 0;
}
