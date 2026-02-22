/*
 * sol_json.c - Minimal JSON helpers (parser implementation)
 */

#include "sol_json.h"

#include <stdlib.h>
#include <string.h>

void
sol_json_parser_init(sol_json_parser_t* p, const char* json, size_t len) {
    if (!p) return;
    p->json = json;
    p->len = len;
    p->pos = 0;
}

static void
json_skip_ws(sol_json_parser_t* p) {
    while (p->pos < p->len) {
        char c = p->json[p->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            p->pos++;
        } else {
            break;
        }
    }
}

static void
json_skip_comma(sol_json_parser_t* p) {
    json_skip_ws(p);
    if (p->pos < p->len && p->json[p->pos] == ',') {
        p->pos++;
    }
}

static bool
json_parse_quoted_string(sol_json_parser_t* p, char* out, size_t max_len) {
    if (!p) return false;
    json_skip_ws(p);
    if (p->pos >= p->len || p->json[p->pos] != '"') {
        return false;
    }
    p->pos++;  /* Skip opening quote */

    size_t out_pos = 0;
    while (p->pos < p->len && p->json[p->pos] != '"') {
        char c = p->json[p->pos++];
        if (c == '\\' && p->pos < p->len) {
            char esc = p->json[p->pos++];
            if (esc == 'n') c = '\n';
            else if (esc == 'r') c = '\r';
            else if (esc == 't') c = '\t';
            else c = esc;
        }
        if (out && max_len > 0 && out_pos < max_len - 1) {
            out[out_pos++] = c;
        }
    }

    if (p->pos >= p->len) return false;
    p->pos++;  /* Skip closing quote */

    if (out && max_len > 0) {
        out[out_pos] = '\0';
    }

    return true;
}

bool
sol_json_parser_object_begin(sol_json_parser_t* p) {
    if (!p) return false;
    json_skip_comma(p);
    json_skip_ws(p);
    if (p->pos < p->len && p->json[p->pos] == '{') {
        p->pos++;
        return true;
    }
    return false;
}

bool
sol_json_parser_object_end(sol_json_parser_t* p) {
    if (!p) return false;
    json_skip_ws(p);
    if (p->pos < p->len && p->json[p->pos] == '}') {
        p->pos++;
        return true;
    }
    return false;
}

bool
sol_json_parser_array_begin(sol_json_parser_t* p) {
    if (!p) return false;
    json_skip_comma(p);
    json_skip_ws(p);
    if (p->pos < p->len && p->json[p->pos] == '[') {
        p->pos++;
        return true;
    }
    return false;
}

bool
sol_json_parser_array_end(sol_json_parser_t* p) {
    if (!p) return false;
    json_skip_ws(p);
    if (p->pos < p->len && p->json[p->pos] == ']') {
        p->pos++;
        return true;
    }
    return false;
}

bool
sol_json_parser_key(sol_json_parser_t* p, char* out, size_t max_len) {
    if (!p) return false;
    json_skip_ws(p);

    /* Skip comma if present */
    if (p->pos < p->len && p->json[p->pos] == ',') {
        p->pos++;
    }

    if (!json_parse_quoted_string(p, out, max_len)) {
        return false;
    }

    json_skip_ws(p);
    if (p->pos < p->len && p->json[p->pos] == ':') {
        p->pos++;
        return true;
    }

    return false;
}

bool
sol_json_parser_string(sol_json_parser_t* p, char* out, size_t max_len) {
    if (!p) return false;
    json_skip_comma(p);
    return json_parse_quoted_string(p, out, max_len);
}

bool
sol_json_parser_int(sol_json_parser_t* p, int64_t* out) {
    if (!p || !out) return false;
    json_skip_comma(p);
    json_skip_ws(p);

    char* end;
    int64_t val = strtoll(p->json + p->pos, &end, 10);
    if (end == p->json + p->pos) return false;

    *out = val;
    p->pos = (size_t)(end - p->json);
    return true;
}

bool
sol_json_parser_uint(sol_json_parser_t* p, uint64_t* out) {
    if (!p || !out) return false;
    json_skip_comma(p);
    json_skip_ws(p);

    char* end;
    uint64_t val = strtoull(p->json + p->pos, &end, 10);
    if (end == p->json + p->pos) return false;

    *out = val;
    p->pos = (size_t)(end - p->json);
    return true;
}

bool
sol_json_parser_bool(sol_json_parser_t* p, bool* out) {
    if (!p || !out) return false;
    json_skip_comma(p);
    json_skip_ws(p);

    if (p->pos + 4 <= p->len && strncmp(p->json + p->pos, "true", 4) == 0) {
        *out = true;
        p->pos += 4;
        return true;
    }
    if (p->pos + 5 <= p->len && strncmp(p->json + p->pos, "false", 5) == 0) {
        *out = false;
        p->pos += 5;
        return true;
    }
    return false;
}

bool
sol_json_parser_null(sol_json_parser_t* p) {
    if (!p) return false;
    json_skip_comma(p);
    json_skip_ws(p);

    if (p->pos + 4 <= p->len && strncmp(p->json + p->pos, "null", 4) == 0) {
        p->pos += 4;
        return true;
    }
    return false;
}

bool
sol_json_parser_skip(sol_json_parser_t* p) {
    if (!p) return false;
    json_skip_comma(p);
    json_skip_ws(p);

    if (p->pos >= p->len) return false;

    char c = p->json[p->pos];

    /* String */
    if (c == '"') {
        return json_parse_quoted_string(p, NULL, 0);
    }

    /* Object */
    if (c == '{') {
        p->pos++;
        int depth = 1;
        while (p->pos < p->len && depth > 0) {
            c = p->json[p->pos++];
            if (c == '{') depth++;
            else if (c == '}') depth--;
            else if (c == '"') {
                /* Skip string content */
                while (p->pos < p->len && p->json[p->pos] != '"') {
                    if (p->json[p->pos] == '\\') p->pos++;
                    p->pos++;
                }
                if (p->pos < p->len) p->pos++;
            }
        }
        return depth == 0;
    }

    /* Array */
    if (c == '[') {
        p->pos++;
        int depth = 1;
        while (p->pos < p->len && depth > 0) {
            c = p->json[p->pos++];
            if (c == '[') depth++;
            else if (c == ']') depth--;
            else if (c == '"') {
                while (p->pos < p->len && p->json[p->pos] != '"') {
                    if (p->json[p->pos] == '\\') p->pos++;
                    p->pos++;
                }
                if (p->pos < p->len) p->pos++;
            }
        }
        return depth == 0;
    }

    /* Number or literal */
    while (p->pos < p->len) {
        c = p->json[p->pos];
        if (c == ',' || c == '}' || c == ']' || c == ' ' || c == '\n') {
            break;
        }
        p->pos++;
    }

    return true;
}

