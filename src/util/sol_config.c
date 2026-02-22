/*
 * sol_config.c - Configuration File Parser Implementation
 *
 * Simple TOML-like parser supporting:
 * - Sections: [section_name]
 * - Key-value pairs: key = value
 * - String values: "string" or 'string'
 * - Integer values: 123, 0x7B
 * - Boolean values: true, false
 * - Float values: 1.23
 * - Arrays: [1, 2, 3] or ["a", "b"]
 * - Comments: # comment
 */

#include "sol_config.h"
#include "sol_alloc.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#define MAX_LINE_LEN 4096
#define INITIAL_CAPACITY 16

/*
 * Create empty configuration
 */
sol_config_t*
sol_config_new(void) {
    sol_config_t* config = sol_calloc(1, sizeof(sol_config_t));
    if (config == NULL) return NULL;

    config->sections = sol_calloc(INITIAL_CAPACITY, sizeof(sol_config_section_t));
    if (config->sections == NULL) {
        sol_free(config);
        return NULL;
    }
    config->capacity = INITIAL_CAPACITY;

    return config;
}

/*
 * Free configuration value
 */
static void
value_free(sol_config_value_t* value) {
    switch (value->type) {
        case SOL_CONFIG_STRING:
            sol_free(value->data.string);
            break;
        case SOL_CONFIG_ARRAY:
            for (size_t i = 0; i < value->data.array.count; i++) {
                value_free(&value->data.array.items[i]);
            }
            sol_free(value->data.array.items);
            break;
        case SOL_CONFIG_INT:
        case SOL_CONFIG_BOOL:
        case SOL_CONFIG_FLOAT:
            /* No heap allocations to free */
            break;
    }
}

/*
 * Free section
 */
static void
section_free(sol_config_section_t* section) {
    sol_free(section->name);
    for (size_t i = 0; i < section->num_entries; i++) {
        sol_free(section->entries[i].key);
        value_free(&section->entries[i].value);
    }
    sol_free(section->entries);
}

/*
 * Destroy configuration
 */
void
sol_config_destroy(sol_config_t* config) {
    if (config == NULL) return;

    for (size_t i = 0; i < config->num_sections; i++) {
        section_free(&config->sections[i]);
    }
    sol_free(config->sections);
    sol_free(config->error_msg);
    sol_free(config);
}

/*
 * Skip whitespace
 */
static const char*
skip_ws(const char* p) {
    while (*p && isspace((unsigned char)*p)) p++;
    return p;
}

/*
 * Parse string value
 */
static sol_err_t
parse_string(const char** pp, char** out) {
    const char* p = *pp;
    char quote = *p++;

    const char* start = p;
    while (*p && *p != quote) {
        if (*p == '\\' && p[1]) p += 2;
        else p++;
    }

    if (*p != quote) return SOL_ERR_PARSE;

    size_t len = p - start;
    *out = sol_alloc(len + 1);
    if (*out == NULL) return SOL_ERR_NOMEM;

    /* Copy with escape handling */
    char* d = *out;
    const char* s = start;
    while (s < p) {
        if (*s == '\\' && s + 1 < p) {
            s++;
            switch (*s) {
                case 'n': *d++ = '\n'; break;
                case 't': *d++ = '\t'; break;
                case 'r': *d++ = '\r'; break;
                case '\\': *d++ = '\\'; break;
                case '"': *d++ = '"'; break;
                case '\'': *d++ = '\''; break;
                default: *d++ = *s; break;
            }
            s++;
        } else {
            *d++ = *s++;
        }
    }
    *d = '\0';

    *pp = p + 1;  /* Skip closing quote */
    return SOL_OK;
}

/*
 * Parse array value
 */
static sol_err_t parse_value(const char** pp, sol_config_value_t* value);

static sol_err_t
parse_array(const char** pp, sol_config_value_t* value) {
    const char* p = *pp + 1;  /* Skip '[' */
    p = skip_ws(p);

    value->type = SOL_CONFIG_ARRAY;
    value->data.array.items = NULL;
    value->data.array.count = 0;

    size_t capacity = 8;
    value->data.array.items = sol_calloc(capacity, sizeof(sol_config_value_t));
    if (value->data.array.items == NULL) return SOL_ERR_NOMEM;

    while (*p && *p != ']') {
        p = skip_ws(p);
        if (*p == ']') break;

        /* Grow array if needed */
        if (value->data.array.count >= capacity) {
            capacity *= 2;
            sol_config_value_t* new_items = sol_realloc(value->data.array.items,
                                                        capacity * sizeof(sol_config_value_t));
            if (new_items == NULL) return SOL_ERR_NOMEM;
            value->data.array.items = new_items;
        }

        /* Parse element */
        sol_err_t err = parse_value(&p, &value->data.array.items[value->data.array.count]);
        if (err != SOL_OK) return err;
        value->data.array.count++;

        p = skip_ws(p);
        if (*p == ',') {
            p++;
            p = skip_ws(p);
        }
    }

    if (*p != ']') return SOL_ERR_PARSE;
    *pp = p + 1;
    return SOL_OK;
}

/*
 * Parse a value
 */
static sol_err_t
parse_value(const char** pp, sol_config_value_t* value) {
    const char* p = skip_ws(*pp);

    /* String */
    if (*p == '"' || *p == '\'') {
        value->type = SOL_CONFIG_STRING;
        return parse_string(&p, &value->data.string);
    }

    /* Array */
    if (*p == '[') {
        sol_err_t err = parse_array(&p, value);
        *pp = p;
        return err;
    }

    /* Boolean */
    if (strncmp(p, "true", 4) == 0 && !isalnum((unsigned char)p[4])) {
        value->type = SOL_CONFIG_BOOL;
        value->data.boolean = true;
        *pp = p + 4;
        return SOL_OK;
    }
    if (strncmp(p, "false", 5) == 0 && !isalnum((unsigned char)p[5])) {
        value->type = SOL_CONFIG_BOOL;
        value->data.boolean = false;
        *pp = p + 5;
        return SOL_OK;
    }

    /* Number (integer or float) */
    if (isdigit((unsigned char)*p) || *p == '-' || *p == '+') {
        char* end;
        bool is_hex = (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'));

        if (is_hex) {
            value->type = SOL_CONFIG_INT;
            value->data.integer = strtoll(p, &end, 16);
        } else {
            /* Check if it's a float */
            const char* q = p;
            while (*q && (isdigit((unsigned char)*q) || *q == '-' || *q == '+')) q++;
            if (*q == '.' || *q == 'e' || *q == 'E') {
                value->type = SOL_CONFIG_FLOAT;
                value->data.floating = strtod(p, &end);
            } else {
                value->type = SOL_CONFIG_INT;
                value->data.integer = strtoll(p, &end, 10);
            }
        }
        *pp = end;
        return SOL_OK;
    }

    /* Unquoted string (up to whitespace or comment) */
    const char* start = p;
    while (*p && !isspace((unsigned char)*p) && *p != '#' && *p != ',') p++;
    size_t len = p - start;
    if (len > 0) {
        value->type = SOL_CONFIG_STRING;
        value->data.string = sol_alloc(len + 1);
        if (value->data.string == NULL) return SOL_ERR_NOMEM;
        memcpy(value->data.string, start, len);
        value->data.string[len] = '\0';
        *pp = p;
        return SOL_OK;
    }

    return SOL_ERR_PARSE;
}

/*
 * Get or create section
 */
static sol_config_section_t*
get_or_create_section(sol_config_t* config, const char* name) {
    /* Find existing */
    for (size_t i = 0; i < config->num_sections; i++) {
        if (strcmp(config->sections[i].name, name) == 0) {
            return &config->sections[i];
        }
    }

    /* Create new */
    if (config->num_sections >= config->capacity) {
        if (config->capacity > SIZE_MAX / 2) {
            return NULL;
        }
        size_t new_cap = config->capacity * 2;
        if (new_cap > SIZE_MAX / sizeof(sol_config_section_t)) {
            return NULL;
        }
        sol_config_section_t* new_sections = sol_realloc(config->sections,
                                                         new_cap * sizeof(sol_config_section_t));
        if (new_sections == NULL) return NULL;
        config->sections = new_sections;
        config->capacity = new_cap;
    }

    sol_config_section_t* section = &config->sections[config->num_sections++];
    memset(section, 0, sizeof(*section));

    size_t name_len = strlen(name);
    section->name = sol_alloc(name_len + 1);
    if (section->name == NULL) {
        config->num_sections--;
        return NULL;
    }
    memcpy(section->name, name, name_len + 1);

    section->entries = sol_calloc(INITIAL_CAPACITY, sizeof(sol_config_entry_t));
    if (section->entries == NULL) {
        sol_free(section->name);
        config->num_sections--;
        return NULL;
    }
    section->capacity = INITIAL_CAPACITY;

    return section;
}

/*
 * Add entry to section
 */
static sol_err_t
section_add_entry(sol_config_section_t* section, const char* key, sol_config_value_t* value) {
    if (section->num_entries >= section->capacity) {
        if (section->capacity > SIZE_MAX / 2) {
            return SOL_ERR_NOMEM;
        }
        size_t new_cap = section->capacity * 2;
        if (new_cap > SIZE_MAX / sizeof(sol_config_entry_t)) {
            return SOL_ERR_NOMEM;
        }
        sol_config_entry_t* new_entries = sol_realloc(section->entries,
                                                      new_cap * sizeof(sol_config_entry_t));
        if (new_entries == NULL) return SOL_ERR_NOMEM;
        section->entries = new_entries;
        section->capacity = new_cap;
    }

    sol_config_entry_t* entry = &section->entries[section->num_entries++];
    size_t key_len = strlen(key);
    entry->key = sol_alloc(key_len + 1);
    if (entry->key == NULL) {
        section->num_entries--;
        return SOL_ERR_NOMEM;
    }
    memcpy(entry->key, key, key_len + 1);
    entry->value = *value;

    return SOL_OK;
}

/*
 * Parse configuration from string
 */
sol_err_t
sol_config_parse(const char* content, size_t len, sol_config_t** out_config) {
    if (content == NULL || out_config == NULL) return SOL_ERR_INVAL;
    if (len == 0) len = strlen(content);

    sol_config_t* config = sol_config_new();
    if (config == NULL) return SOL_ERR_NOMEM;

    /* Create default section for entries before any [section] */
    sol_config_section_t* current_section = get_or_create_section(config, "");
    if (current_section == NULL) {
        sol_config_destroy(config);
        return SOL_ERR_NOMEM;
    }

    const char* p = content;
    const char* end = content + len;
    int line_num = 1;

    while (p < end) {
        /* Skip whitespace */
        p = skip_ws(p);
        if (p >= end) break;

        /* Skip comments and empty lines */
        if (*p == '#' || *p == '\n' || *p == '\r') {
            while (p < end && *p != '\n') p++;
            if (p < end) p++;
            line_num++;
            continue;
        }

        /* Section header */
        if (*p == '[') {
            p++;
            const char* name_start = p;
            while (p < end && *p != ']' && *p != '\n') p++;
            if (*p != ']') {
                config->error_line = line_num;
                config->error_msg = sol_alloc(64);
                if (config->error_msg) {
                    snprintf(config->error_msg, 64, "Unclosed section bracket");
                }
                sol_config_destroy(config);
                return SOL_ERR_PARSE;
            }

            size_t name_len = p - name_start;
            char* section_name = sol_alloc(name_len + 1);
            if (section_name == NULL) {
                sol_config_destroy(config);
                return SOL_ERR_NOMEM;
            }
            memcpy(section_name, name_start, name_len);
            section_name[name_len] = '\0';

            current_section = get_or_create_section(config, section_name);
            sol_free(section_name);

            if (current_section == NULL) {
                sol_config_destroy(config);
                return SOL_ERR_NOMEM;
            }

            p++;  /* Skip ']' */
            continue;
        }

        /* Key = value */
        const char* key_start = p;
        while (p < end && *p != '=' && *p != '\n' && !isspace((unsigned char)*p)) p++;
        size_t key_len = p - key_start;
        if (key_len == 0) {
            while (p < end && *p != '\n') p++;
            if (p < end) p++;
            line_num++;
            continue;
        }

        char key[256];
        if (key_len >= sizeof(key)) key_len = sizeof(key) - 1;
        memcpy(key, key_start, key_len);
        key[key_len] = '\0';

        p = skip_ws(p);
        if (*p != '=') {
            config->error_line = line_num;
            config->error_msg = sol_alloc(64);
            if (config->error_msg) {
                snprintf(config->error_msg, 64, "Expected '=' after key '%s'", key);
            }
            sol_config_destroy(config);
            return SOL_ERR_PARSE;
        }
        p++;  /* Skip '=' */
        p = skip_ws(p);

        /* Parse value */
        sol_config_value_t value;
        memset(&value, 0, sizeof(value));

        sol_err_t err = parse_value(&p, &value);
        if (err != SOL_OK) {
            config->error_line = line_num;
            config->error_msg = sol_alloc(64);
            if (config->error_msg) {
                snprintf(config->error_msg, 64, "Invalid value for key '%s'", key);
            }
            sol_config_destroy(config);
            return err;
        }

        err = section_add_entry(current_section, key, &value);
        if (err != SOL_OK) {
            value_free(&value);
            sol_config_destroy(config);
            return err;
        }

        /* Skip to end of line */
        while (p < end && *p != '\n') p++;
        if (p < end) p++;
        line_num++;
    }

    *out_config = config;
    return SOL_OK;
}

/*
 * Parse configuration from file
 */
sol_err_t
sol_config_load(const char* path, sol_config_t** config) {
    if (path == NULL || config == NULL) return SOL_ERR_INVAL;

    FILE* f = fopen(path, "r");
    if (f == NULL) return SOL_ERR_IO;

    /* Get file size */
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0) {
        fclose(f);
        *config = sol_config_new();
        return *config ? SOL_OK : SOL_ERR_NOMEM;
    }

    char* content = sol_alloc(size + 1);
    if (content == NULL) {
        fclose(f);
        return SOL_ERR_NOMEM;
    }

    size_t read = fread(content, 1, size, f);
    fclose(f);
    content[read] = '\0';

    sol_err_t err = sol_config_parse(content, read, config);
    sol_free(content);

    return err;
}

/*
 * Get parse error message
 */
const char*
sol_config_error(const sol_config_t* config) {
    return config ? config->error_msg : NULL;
}

/*
 * Get parse error line
 */
int
sol_config_error_line(const sol_config_t* config) {
    return config ? config->error_line : 0;
}

/*
 * Get section by name
 */
sol_config_section_t*
sol_config_section(sol_config_t* config, const char* name) {
    if (config == NULL || name == NULL) return NULL;

    for (size_t i = 0; i < config->num_sections; i++) {
        if (strcmp(config->sections[i].name, name) == 0) {
            return &config->sections[i];
        }
    }
    return NULL;
}

/*
 * Get value from section
 */
sol_config_value_t*
sol_config_get(sol_config_section_t* section, const char* key) {
    if (section == NULL || key == NULL) return NULL;

    for (size_t i = 0; i < section->num_entries; i++) {
        if (strcmp(section->entries[i].key, key) == 0) {
            return &section->entries[i].value;
        }
    }
    return NULL;
}

/*
 * Get string value
 */
const char*
sol_config_get_string(sol_config_t* config, const char* section_name,
                      const char* key, const char* default_value) {
    sol_config_section_t* section = sol_config_section(config, section_name);
    if (section == NULL) return default_value;

    sol_config_value_t* value = sol_config_get(section, key);
    if (value == NULL || value->type != SOL_CONFIG_STRING) return default_value;

    return value->data.string;
}

/*
 * Get integer value
 */
int64_t
sol_config_get_int(sol_config_t* config, const char* section_name,
                   const char* key, int64_t default_value) {
    sol_config_section_t* section = sol_config_section(config, section_name);
    if (section == NULL) return default_value;

    sol_config_value_t* value = sol_config_get(section, key);
    if (value == NULL) return default_value;

    if (value->type == SOL_CONFIG_INT) return value->data.integer;
    if (value->type == SOL_CONFIG_FLOAT) return (int64_t)value->data.floating;

    return default_value;
}

/*
 * Get boolean value
 */
bool
sol_config_get_bool(sol_config_t* config, const char* section_name,
                    const char* key, bool default_value) {
    sol_config_section_t* section = sol_config_section(config, section_name);
    if (section == NULL) return default_value;

    sol_config_value_t* value = sol_config_get(section, key);
    if (value == NULL || value->type != SOL_CONFIG_BOOL) return default_value;

    return value->data.boolean;
}

/*
 * Get float value
 */
double
sol_config_get_float(sol_config_t* config, const char* section_name,
                     const char* key, double default_value) {
    sol_config_section_t* section = sol_config_section(config, section_name);
    if (section == NULL) return default_value;

    sol_config_value_t* value = sol_config_get(section, key);
    if (value == NULL) return default_value;

    if (value->type == SOL_CONFIG_FLOAT) return value->data.floating;
    if (value->type == SOL_CONFIG_INT) return (double)value->data.integer;

    return default_value;
}

/*
 * Get string array
 */
sol_err_t
sol_config_get_string_array(sol_config_t* config, const char* section_name,
                            const char* key, char*** out, size_t* count) {
    if (out == NULL || count == NULL) return SOL_ERR_INVAL;

    *out = NULL;
    *count = 0;

    sol_config_section_t* section = sol_config_section(config, section_name);
    if (section == NULL) return SOL_OK;

    sol_config_value_t* value = sol_config_get(section, key);
    if (value == NULL) return SOL_OK;

    if (value->type != SOL_CONFIG_ARRAY) return SOL_ERR_INVAL;

    size_t n = value->data.array.count;
    char** arr = sol_calloc(n, sizeof(char*));
    if (arr == NULL) return SOL_ERR_NOMEM;

    for (size_t i = 0; i < n; i++) {
        sol_config_value_t* item = &value->data.array.items[i];
        if (item->type == SOL_CONFIG_STRING) {
            size_t len = strlen(item->data.string);
            arr[i] = sol_alloc(len + 1);
            if (arr[i]) {
                memcpy(arr[i], item->data.string, len + 1);
            }
        }
    }

    *out = arr;
    *count = n;
    return SOL_OK;
}

/*
 * Initialize validator config with defaults
 */
void
sol_validator_config_init(sol_validator_config_t* config) {
    memset(config, 0, sizeof(*config));
    config->gossip_port = 8001;
    config->tpu_port = 8003;
    config->tvu_port = 8004;
    config->rpc_port = 8899;
    config->enable_quic = true;
    config->rpc_enable = true;
    config->snapshot_interval = 25000;
    config->incremental_interval = 5000;
    config->snapshot_verify_accounts_hash = false;
    config->snapshot_max_bootstrap_lag_slots = 50000;
    config->metrics_enable = true;
    config->metrics_port = 9090;
}

/*
 * Free validator configuration
 */
void
sol_validator_config_cleanup(sol_validator_config_t* config) {
    if (config == NULL) return;

    sol_free(config->identity_keypair);
    sol_free(config->vote_account);
    sol_free(config->ledger_path);
    sol_free(config->rocksdb_path);
    sol_free(config->snapshot_path);
    sol_free(config->tower_path);
    sol_free(config->rpc_bind);
    sol_free(config->advertise_ip);
    sol_free(config->shred_version_rpc_url);
    sol_free(config->snapshot_manifest_url);
    sol_free(config->log_level);
    sol_free(config->log_format);
    sol_free(config->log_file);

    if (config->snapshot_rpc_urls) {
        for (size_t i = 0; i < config->snapshot_rpc_urls_count; i++) {
            sol_free(config->snapshot_rpc_urls[i]);
        }
        sol_free(config->snapshot_rpc_urls);
    }

    if (config->entrypoints) {
        for (size_t i = 0; i < config->entrypoints_count; i++) {
            sol_free(config->entrypoints[i]);
        }
        sol_free(config->entrypoints);
    }

    memset(config, 0, sizeof(*config));
}

/*
 * Helper to duplicate string
 */
static char*
str_dup(const char* s) {
    if (s == NULL) return NULL;
    size_t len = strlen(s);
    char* d = sol_alloc(len + 1);
    if (d) memcpy(d, s, len + 1);
    return d;
}

/*
 * Load validator configuration from file
 */
sol_err_t
sol_validator_config_load(const char* path, sol_validator_config_t* config) {
    if (path == NULL || config == NULL) return SOL_ERR_INVAL;

    sol_validator_config_init(config);

    sol_config_t* cfg = NULL;
    sol_err_t err = sol_config_load(path, &cfg);
    if (err != SOL_OK) return err;

    /* Identity section (new format: [identity]; legacy: [validator]) */
    {
        const char* keypair = sol_config_get_string(cfg, "identity", "keypair", NULL);
        if (!keypair) keypair = sol_config_get_string(cfg, "validator", "identity_keypair", NULL);
        config->identity_keypair = str_dup(keypair);

        const char* vote = sol_config_get_string(cfg, "identity", "vote_account", NULL);
        if (!vote) vote = sol_config_get_string(cfg, "validator", "vote_account", NULL);
        config->vote_account = str_dup(vote);
    }

    /* Ledger section (new format: [ledger]; legacy: [validator]) */
    {
        const char* ledger = sol_config_get_string(cfg, "ledger", "path", NULL);
        if (!ledger) ledger = sol_config_get_string(cfg, "validator", "ledger_path", NULL);
        config->ledger_path = str_dup(ledger);

        config->rocksdb_path = str_dup(
            sol_config_get_string(cfg, "ledger", "rocksdb_path", NULL));
        config->snapshot_path = str_dup(
            sol_config_get_string(cfg, "ledger", "snapshot_path", NULL));
    }

    /* Consensus section */
    {
        const char* tower = sol_config_get_string(cfg, "consensus", "tower_path", NULL);
        if (!tower) tower = sol_config_get_string(cfg, "validator", "tower_path", NULL);
        config->tower_path = str_dup(tower);
    }

    /* Network section */
    sol_config_get_string_array(cfg, "network", "entrypoints",
                                &config->entrypoints, &config->entrypoints_count);
    config->advertise_ip = str_dup(
        sol_config_get_string(cfg, "network", "advertise_ip", NULL));
    config->shred_version = (uint16_t)sol_config_get_int(cfg, "network", "shred_version", 0);
    config->shred_version_rpc_url = str_dup(
        sol_config_get_string(cfg, "network", "shred_version_rpc_url", NULL));
    /* Ports: prefer [network] but accept legacy [gossip]/[tpu]/[tvu]. */
    {
        int v = sol_config_get_int(cfg, "network", "gossip_port", 0);
        if (v <= 0) v = sol_config_get_int(cfg, "gossip", "port", 8001);
        config->gossip_port = (uint16_t)v;

        v = sol_config_get_int(cfg, "network", "tpu_port", 0);
        if (v <= 0) v = sol_config_get_int(cfg, "tpu", "port", 8003);
        config->tpu_port = (uint16_t)v;

        v = sol_config_get_int(cfg, "network", "tvu_port", 0);
        if (v <= 0) v = sol_config_get_int(cfg, "tvu", "port", 8004);
        config->tvu_port = (uint16_t)v;
    }
    config->enable_quic = sol_config_get_bool(cfg, "network", "enable_quic", true);

    /* RPC section */
    config->rpc_enable = sol_config_get_bool(cfg, "rpc", "enable", true);
    {
        const char* bind = sol_config_get_string(cfg, "rpc", "bind", NULL);
        if (!bind) bind = sol_config_get_string(cfg, "rpc", "bind_address", NULL);
        if (!bind) bind = "0.0.0.0";
        config->rpc_bind = str_dup(bind);
    }
    config->rpc_port = (uint16_t)sol_config_get_int(cfg, "rpc", "port", 8899);

    /* Snapshots section */
    config->snapshot_interval = (uint64_t)sol_config_get_int(
        cfg, "snapshots", "full_interval", 25000);
    config->incremental_interval = (uint64_t)sol_config_get_int(
        cfg, "snapshots", "incremental_interval", 5000);
    config->snapshot_manifest_url = str_dup(
        sol_config_get_string(cfg, "snapshots", "manifest_url", NULL));
    sol_config_get_string_array(cfg, "snapshots", "rpc_urls",
                                &config->snapshot_rpc_urls, &config->snapshot_rpc_urls_count);
    config->snapshot_verify_accounts_hash = sol_config_get_bool(
        cfg, "snapshots", "verify_accounts_hash", false);
    {
        int64_t lag = sol_config_get_int(cfg, "snapshots", "max_bootstrap_lag_slots", 50000);
        if (lag < 0) lag = 0;
        config->snapshot_max_bootstrap_lag_slots = (uint64_t)lag;
    }

    /* Logging section */
    config->log_level = str_dup(
        sol_config_get_string(cfg, "logging", "level", "info"));
    config->log_format = str_dup(
        sol_config_get_string(cfg, "logging", "format", "text"));
    config->log_file = str_dup(
        sol_config_get_string(cfg, "logging", "file", NULL));

    /* Metrics section */
    config->metrics_enable = sol_config_get_bool(cfg, "metrics", "enable", true);
    config->metrics_port = (uint16_t)sol_config_get_int(cfg, "metrics", "port", 9090);

    sol_config_destroy(cfg);
    return SOL_OK;
}
