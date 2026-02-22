/*
 * sol_log.h - Logging infrastructure
 *
 * High-performance structured logging with multiple output backends.
 */

#ifndef SOL_LOG_H
#define SOL_LOG_H

#include "sol_base.h"
#include "sol_types.h"

/*
 * Log levels
 */
typedef enum {
    SOL_LOG_TRACE = 0,   /* Extremely verbose debugging */
    SOL_LOG_DEBUG = 1,   /* Debug information */
    SOL_LOG_INFO  = 2,   /* General information */
    SOL_LOG_WARN  = 3,   /* Warning conditions */
    SOL_LOG_ERROR = 4,   /* Error conditions */
    SOL_LOG_FATAL = 5,   /* Fatal errors (will abort) */
    SOL_LOG_OFF   = 6,   /* Logging disabled */
} sol_log_level_t;

/*
 * Log output backends
 */
typedef enum {
    SOL_LOG_BACKEND_STDERR = 1 << 0,   /* Write to stderr */
    SOL_LOG_BACKEND_FILE   = 1 << 1,   /* Write to file */
    SOL_LOG_BACKEND_SYSLOG = 1 << 2,   /* Write to syslog */
    SOL_LOG_BACKEND_CUSTOM = 1 << 3,   /* Custom callback */
} sol_log_backend_t;

/*
 * Log entry structure (for custom backends)
 */
typedef struct {
    sol_log_level_t   level;
    uint64_t          timestamp_ns;    /* Nanoseconds since epoch */
    const char*       file;
    int               line;
    const char*       func;
    const char*       message;
    size_t            message_len;
} sol_log_entry_t;

/*
 * Custom log handler callback
 */
typedef void (*sol_log_handler_t)(const sol_log_entry_t* entry, void* ctx);

/*
 * Log format
 */
typedef enum {
    SOL_LOG_FORMAT_TEXT,   /* Human-readable text format */
    SOL_LOG_FORMAT_JSON,   /* Structured JSON format */
} sol_log_format_t;

/*
 * Configuration
 */
typedef struct {
    sol_log_level_t    level;           /* Minimum level to log */
    uint32_t           backends;        /* Bitmask of backends */
    const char*        log_file;        /* Path for file backend */
    sol_log_format_t   format;          /* Output format (text or JSON) */
    bool               include_time;    /* Include timestamp */
    bool               include_file;    /* Include file:line */
    bool               include_func;    /* Include function name */
    bool               use_colors;      /* Use ANSI colors (stderr, text only) */
    sol_log_handler_t  custom_handler;  /* Custom handler callback */
    void*              custom_ctx;      /* Context for custom handler */
} sol_log_config_t;

/*
 * Default configuration
 */
#define SOL_LOG_CONFIG_DEFAULT { \
    .level = SOL_LOG_INFO, \
    .backends = SOL_LOG_BACKEND_STDERR, \
    .log_file = NULL, \
    .format = SOL_LOG_FORMAT_TEXT, \
    .include_time = true, \
    .include_file = true, \
    .include_func = false, \
    .use_colors = true, \
    .custom_handler = NULL, \
    .custom_ctx = NULL, \
}

/*
 * Initialization
 */
void sol_log_init(const sol_log_config_t* config);
void sol_log_fini(void);

/* Reconfigure at runtime */
void sol_log_set_level(sol_log_level_t level);
sol_log_level_t sol_log_get_level(void);

/*
 * Core logging function (don't call directly, use macros)
 */
void sol_log_write(sol_log_level_t level,
                   const char* file, int line, const char* func,
                   const char* fmt, ...) SOL_PRINTF_FMT(5, 6);

/*
 * Logging macros
 */

#define sol_log_trace(...) \
    sol_log_write(SOL_LOG_TRACE, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define sol_log_debug(...) \
    sol_log_write(SOL_LOG_DEBUG, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define sol_log_info(...) \
    sol_log_write(SOL_LOG_INFO, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define sol_log_warn(...) \
    sol_log_write(SOL_LOG_WARN, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define sol_log_error(...) \
    sol_log_write(SOL_LOG_ERROR, __FILE__, __LINE__, __func__, __VA_ARGS__)

/* Fatal logs and aborts */
#define sol_log_fatal(...) do { \
    sol_log_write(SOL_LOG_FATAL, __FILE__, __LINE__, __func__, __VA_ARGS__); \
    sol_trap(); \
} while(0)

/*
 * Conditional logging (compile-time elimination)
 */
#ifdef SOL_DEBUG
#  define sol_log_trace_if(cond, ...) \
      do { if (cond) sol_log_trace(__VA_ARGS__); } while(0)
#  define sol_log_debug_if(cond, ...) \
      do { if (cond) sol_log_debug(__VA_ARGS__); } while(0)
#else
#  define sol_log_trace_if(cond, ...) ((void)0)
#  define sol_log_debug_if(cond, ...) ((void)0)
#endif

/*
 * Hex dump utility
 */
void sol_log_hexdump(sol_log_level_t level,
                     const char* prefix,
                     const void* data, size_t len);

/*
 * Log level name
 */
const char* sol_log_level_name(sol_log_level_t level);
sol_log_level_t sol_log_level_from_name(const char* name);

/*
 * Log format name
 */
const char* sol_log_format_name(sol_log_format_t format);
sol_log_format_t sol_log_format_from_name(const char* name);

/*
 * Pubkey/hash logging helpers
 */
void sol_log_pubkey(sol_log_level_t level, const char* prefix, const sol_pubkey_t* pk);
void sol_log_hash(sol_log_level_t level, const char* prefix, const sol_hash_t* h);
void sol_log_signature(sol_log_level_t level, const char* prefix, const sol_signature_t* sig);

/* Format hash to hex string - caller must provide buffer of at least 65 bytes */
int sol_hash_to_hex(const sol_hash_t* h, char* out, size_t out_len);

#endif /* SOL_LOG_H */
