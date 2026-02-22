/*
 * sol_json.h - Minimal JSON helpers (parser)
 *
 * A tiny, non-validating JSON parser used throughout the codebase for
 * lightweight JSON tasks (e.g., parsing RPC bodies or service manifests).
 */

#ifndef SOL_JSON_H
#define SOL_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Simple JSON parser */
typedef struct {
    const char* json;
    size_t      len;
    size_t      pos;
} sol_json_parser_t;

void sol_json_parser_init(sol_json_parser_t* parser, const char* json, size_t len);
bool sol_json_parser_object_begin(sol_json_parser_t* parser);
bool sol_json_parser_object_end(sol_json_parser_t* parser);
bool sol_json_parser_array_begin(sol_json_parser_t* parser);
bool sol_json_parser_array_end(sol_json_parser_t* parser);
bool sol_json_parser_key(sol_json_parser_t* parser, char* out, size_t max_len);
bool sol_json_parser_string(sol_json_parser_t* parser, char* out, size_t max_len);
bool sol_json_parser_int(sol_json_parser_t* parser, int64_t* out);
bool sol_json_parser_uint(sol_json_parser_t* parser, uint64_t* out);
bool sol_json_parser_bool(sol_json_parser_t* parser, bool* out);
bool sol_json_parser_null(sol_json_parser_t* parser);
bool sol_json_parser_skip(sol_json_parser_t* parser);

#endif /* SOL_JSON_H */

