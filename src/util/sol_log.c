/*
 * sol_log.c - Logging implementation
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sol_log.h"
#include "sol_alloc.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

#ifdef SOL_OS_LINUX
#  include <sys/syscall.h>
#endif

/*
 * Global state
 */
static sol_log_config_t g_config = SOL_LOG_CONFIG_DEFAULT;
static FILE*            g_log_file = NULL;
static pthread_mutex_t  g_log_lock = PTHREAD_MUTEX_INITIALIZER;
static bool             g_initialized = false;

/*
 * Flush policy
 *
 * The previous behavior flushed every log line, which is extremely expensive
 * for disk-heavy workloads like validator replay (it defeats stdio buffering).
 *
 * Env:
 *   SOL_LOG_FLUSH=0|none  -> never fflush() (except SOL_LOG_FATAL)
 *   SOL_LOG_FLUSH=1|all   -> fflush() every log line (legacy behavior)
 *
 * Default:
 *   - stderr: no explicit fflush() (stderr is typically unbuffered)
 *   - file:   fflush() only for WARN+ (and always for FATAL)
 */
static int g_flush_mode = -1; /* -1 unknown, 0 default, 1 never, 2 always */
static uint64_t g_last_file_flush_ns = 0;

static int
flush_mode_get(void) {
    int v = __atomic_load_n(&g_flush_mode, __ATOMIC_ACQUIRE);
    if (__builtin_expect(v >= 0, 1)) {
        return v;
    }

    int mode = 0;
    const char* env = getenv("SOL_LOG_FLUSH");
    if (env && env[0] != '\0') {
        if (strcmp(env, "1") == 0 || strcasecmp(env, "all") == 0) {
            mode = 2;
        } else if (strcmp(env, "0") == 0 || strcasecmp(env, "none") == 0) {
            mode = 1;
        }
    }

    __atomic_store_n(&g_flush_mode, mode, __ATOMIC_RELEASE);
    return mode;
}

static inline void
maybe_flush(FILE* fp, sol_log_level_t level, bool is_file_backend, uint64_t ts_ns) {
    if (!fp) return;

    /* Ensure fatal logs are visible even when buffering is enabled. */
    if (level >= SOL_LOG_FATAL) {
        (void)fflush(fp);
        return;
    }

    int mode = flush_mode_get();
    if (mode == 2) { /* always */
        (void)fflush(fp);
        return;
    }
    if (mode == 1) { /* never */
        return;
    }

    if (is_file_backend) {
        /* Flush warnings/errors immediately, and flush info/debug periodically
         * so log tails stay live without paying per-line flush overhead. */
        if (level >= SOL_LOG_WARN) {
            (void)fflush(fp);
            __atomic_store_n(&g_last_file_flush_ns, ts_ns, __ATOMIC_RELEASE);
            return;
        }

        uint64_t last = __atomic_load_n(&g_last_file_flush_ns, __ATOMIC_ACQUIRE);
        if (ts_ns > last && (ts_ns - last) >= 1000000000ULL) {
            /* At most one flush per second (best-effort). */
            __atomic_store_n(&g_last_file_flush_ns, ts_ns, __ATOMIC_RELEASE);
            (void)fflush(fp);
        }
    }
}

/*
 * ANSI color codes
 */
static const char* g_level_colors[] = {
    [SOL_LOG_TRACE] = "\033[90m",    /* Dark gray */
    [SOL_LOG_DEBUG] = "\033[36m",    /* Cyan */
    [SOL_LOG_INFO]  = "\033[32m",    /* Green */
    [SOL_LOG_WARN]  = "\033[33m",    /* Yellow */
    [SOL_LOG_ERROR] = "\033[31m",    /* Red */
    [SOL_LOG_FATAL] = "\033[35;1m",  /* Bold magenta */
};

static const char* g_level_names[] = {
    [SOL_LOG_TRACE] = "TRACE",
    [SOL_LOG_DEBUG] = "DEBUG",
    [SOL_LOG_INFO]  = "INFO",
    [SOL_LOG_WARN]  = "WARN",
    [SOL_LOG_ERROR] = "ERROR",
    [SOL_LOG_FATAL] = "FATAL",
};

#define ANSI_RESET "\033[0m"

/*
 * JSON string escaping
 */
static size_t
json_escape_string(const char* src, char* dst, size_t dst_len) {
    if (dst == NULL || dst_len == 0) {
        return 0;
    }

    size_t si = 0;
    size_t di = 0;

    while (src[si] != '\0' && di < dst_len - 1) {
        char c = src[si++];

        switch (c) {
            case '"':
                if (di + 2 >= dst_len) goto done;
                dst[di++] = '\\';
                dst[di++] = '"';
                break;
            case '\\':
                if (di + 2 >= dst_len) goto done;
                dst[di++] = '\\';
                dst[di++] = '\\';
                break;
            case '\n':
                if (di + 2 >= dst_len) goto done;
                dst[di++] = '\\';
                dst[di++] = 'n';
                break;
            case '\r':
                if (di + 2 >= dst_len) goto done;
                dst[di++] = '\\';
                dst[di++] = 'r';
                break;
            case '\t':
                if (di + 2 >= dst_len) goto done;
                dst[di++] = '\\';
                dst[di++] = 't';
                break;
            default:
                if ((unsigned char)c < 0x20) {
                    /* Control character - escape as \uXXXX */
                    if (di + 6 >= dst_len) goto done;
                    di += snprintf(dst + di, dst_len - di, "\\u%04x", (unsigned char)c);
                } else {
                    dst[di++] = c;
                }
                break;
        }
    }

done:
    dst[di] = '\0';
    return di;
}

/*
 * Write JSON format log entry
 */
static void
write_json_log(FILE* out, sol_log_level_t level, uint64_t ts_ns,
               const char* time_str, long tid,
               const char* filename, int line, const char* func,
               const char* message) {
    char escaped_msg[4096];
    json_escape_string(message, escaped_msg, sizeof(escaped_msg));

    char escaped_file[256] = "";
    if (filename != NULL) {
        json_escape_string(filename, escaped_file, sizeof(escaped_file));
    }

    char escaped_func[256] = "";
    if (func != NULL) {
        json_escape_string(func, escaped_func, sizeof(escaped_func));
    }

    fprintf(out, "{\"timestamp\":\"%s\",\"timestamp_ns\":%llu,\"level\":\"%s\","
                 "\"thread\":%ld,\"file\":\"%s\",\"line\":%d,\"func\":\"%s\","
                 "\"message\":\"%s\"}\n",
            time_str,
            (unsigned long long)ts_ns,
            g_level_names[level],
            tid,
            escaped_file,
            line,
            escaped_func,
            escaped_msg);
}

/*
 * Get current time in nanoseconds
 */
static uint64_t
get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/*
 * Get thread ID
 */
static long
get_thread_id(void) {
#ifdef SOL_OS_LINUX
    return syscall(SYS_gettid);
#elif defined(SOL_OS_MACOS)
    uint64_t tid;
    pthread_threadid_np(NULL, &tid);
    return (long)tid;
#else
    return (long)pthread_self();
#endif
}

/*
 * Check if stderr is a TTY (for color support)
 */
static bool
is_tty(void) {
    static int cached = -1;
    if (cached < 0) {
        cached = isatty(STDERR_FILENO);
    }
    return cached != 0;
}

/*
 * Initialization
 */

void
sol_log_init(const sol_log_config_t* config) {
    pthread_mutex_lock(&g_log_lock);

    if (config != NULL) {
        g_config = *config;
    }

    /* Open log file if requested */
    if ((g_config.backends & SOL_LOG_BACKEND_FILE) && g_config.log_file != NULL) {
        g_log_file = fopen(g_config.log_file, "a");
        if (g_log_file == NULL) {
            fprintf(stderr, "WARNING: Failed to open log file: %s\n", g_config.log_file);
            g_config.backends &= ~SOL_LOG_BACKEND_FILE;
        } else {
            /* Large buffer for replay performance (avoid fflush() per line). */
            (void)setvbuf(g_log_file, NULL, _IOFBF, 1 << 20);
        }
    }

    /* Disable colors if not a TTY */
    if (g_config.use_colors && !is_tty()) {
        g_config.use_colors = false;
    }

    g_initialized = true;

    pthread_mutex_unlock(&g_log_lock);
}

void
sol_log_fini(void) {
    pthread_mutex_lock(&g_log_lock);

    if (g_log_file != NULL) {
        fclose(g_log_file);
        g_log_file = NULL;
    }

    g_initialized = false;

    pthread_mutex_unlock(&g_log_lock);
}

void
sol_log_set_level(sol_log_level_t level) {
    g_config.level = level;
}

sol_log_level_t
sol_log_get_level(void) {
    return g_config.level;
}

/*
 * Core logging function
 */

void
sol_log_write(sol_log_level_t level,
              const char* file, int line, const char* func,
              const char* fmt, ...) {
    /* Quick level check without lock */
    if (level < g_config.level) {
        return;
    }

    /* Format message */
    char msg_buf[4096];
    va_list args;
    va_start(args, fmt);
    int msg_len = vsnprintf(msg_buf, sizeof(msg_buf), fmt, args);
    va_end(args);

    if (msg_len < 0) {
        msg_len = 0;
    } else if ((size_t)msg_len >= sizeof(msg_buf)) {
        msg_len = sizeof(msg_buf) - 1;
    }

    /* Get timestamp */
    uint64_t ts_ns = get_time_ns();
    time_t ts_sec = ts_ns / 1000000000ULL;
    uint32_t ts_ms = (ts_ns / 1000000ULL) % 1000;

    struct tm tm_buf;
    struct tm* tm = localtime_r(&ts_sec, &tm_buf);

    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm);

    /* Get thread ID */
    long tid = get_thread_id();

    /* Extract filename from path */
    const char* filename = file;
    if (file != NULL) {
        const char* slash = strrchr(file, '/');
        if (slash != NULL) {
            filename = slash + 1;
        }
    }

    /* Create full timestamp with milliseconds for JSON */
    char full_time_buf[64];
    snprintf(full_time_buf, sizeof(full_time_buf), "%s.%03u", time_buf, ts_ms);

    pthread_mutex_lock(&g_log_lock);

    /* Write to stderr */
    if (g_config.backends & SOL_LOG_BACKEND_STDERR) {
        FILE* out = stderr;

        if (g_config.format == SOL_LOG_FORMAT_JSON) {
            /* JSON format */
            write_json_log(out, level, ts_ns, full_time_buf, tid,
                          filename, line, func, msg_buf);
        } else {
            /* Text format */
            if (g_config.use_colors) {
                fprintf(out, "%s", g_level_colors[level]);
            }

            /* Timestamp */
            if (g_config.include_time) {
                fprintf(out, "%s.%03u ", time_buf, ts_ms);
            }

            /* Level and thread */
            fprintf(out, "[%s] [%ld] ", g_level_names[level], tid);

            /* File:line */
            if (g_config.include_file && filename != NULL) {
                fprintf(out, "%s:%d ", filename, line);
            }

            /* Function */
            if (g_config.include_func && func != NULL) {
                fprintf(out, "%s() ", func);
            }

            /* Message */
            fprintf(out, "%s", msg_buf);

            if (g_config.use_colors) {
                fprintf(out, "%s", ANSI_RESET);
            }

            fprintf(out, "\n");
        }
        maybe_flush(out, level, false, ts_ns);
    }

    /* Write to file */
    if ((g_config.backends & SOL_LOG_BACKEND_FILE) && g_log_file != NULL) {
        if (g_config.format == SOL_LOG_FORMAT_JSON) {
            /* JSON format */
            write_json_log(g_log_file, level, ts_ns, full_time_buf, tid,
                          filename, line, func, msg_buf);
        } else {
            /* Text format */
            fprintf(g_log_file, "%s.%03u [%s] [%ld] ",
                    time_buf, ts_ms, g_level_names[level], tid);

            if (g_config.include_file && filename != NULL) {
                fprintf(g_log_file, "%s:%d ", filename, line);
            }

            if (g_config.include_func && func != NULL) {
                fprintf(g_log_file, "%s() ", func);
            }

            fprintf(g_log_file, "%s\n", msg_buf);
        }
        maybe_flush(g_log_file, level, true, ts_ns);
    }

    /* Call custom handler */
    if ((g_config.backends & SOL_LOG_BACKEND_CUSTOM) && g_config.custom_handler != NULL) {
        sol_log_entry_t entry = {
            .level = level,
            .timestamp_ns = ts_ns,
            .file = file,
            .line = line,
            .func = func,
            .message = msg_buf,
            .message_len = (size_t)msg_len,
        };
        g_config.custom_handler(&entry, g_config.custom_ctx);
    }

    pthread_mutex_unlock(&g_log_lock);
}

/*
 * Hex dump
 */

static void
hexdump_appendf(char* buf, size_t buf_len, size_t* pos, const char* fmt, ...) {
    if (!buf || !pos || buf_len == 0 || *pos >= buf_len) {
        return;
    }

    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(buf + *pos, buf_len - *pos, fmt, args);
    va_end(args);

    if (n < 0) {
        return;
    }

    size_t add = (size_t)n;
    if (add >= buf_len - *pos) {
        *pos = buf_len - 1;
    } else {
        *pos += add;
    }
}

void
sol_log_hexdump(sol_log_level_t level,
                const char* prefix,
                const void* data, size_t len) {
    if (level < g_config.level) {
        return;
    }

    const uchar* p = (const uchar*)data;
    char line[256];
    char ascii[17];
    ascii[16] = '\0';

    for (size_t i = 0; i < len; i += 16) {
        size_t pos = 0;
        line[0] = '\0';
        hexdump_appendf(line, sizeof(line), &pos, "%s %04zx: ", prefix ? prefix : "", i);

        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) {
                hexdump_appendf(line, sizeof(line), &pos, "%02x ", p[i + j]);
                ascii[j] = (p[i + j] >= 32 && p[i + j] < 127) ? p[i + j] : '.';
            } else {
                hexdump_appendf(line, sizeof(line), &pos, "   ");
                ascii[j] = ' ';
            }
        }

        hexdump_appendf(line, sizeof(line), &pos, " |%s|", ascii);
        sol_log_write(level, NULL, 0, NULL, "%s", line);
    }
}

/*
 * Level name helpers
 */

const char*
sol_log_level_name(sol_log_level_t level) {
    if (level >= SOL_LOG_TRACE && level <= SOL_LOG_FATAL) {
        return g_level_names[level];
    }
    return "UNKNOWN";
}

sol_log_level_t
sol_log_level_from_name(const char* name) {
    if (name == NULL) {
        return SOL_LOG_INFO;
    }

    for (int i = SOL_LOG_TRACE; i <= SOL_LOG_FATAL; i++) {
        if (strcasecmp(name, g_level_names[i]) == 0) {
            return (sol_log_level_t)i;
        }
    }

    return SOL_LOG_INFO;
}

/*
 * Format name helpers
 */

const char*
sol_log_format_name(sol_log_format_t format) {
    switch (format) {
        case SOL_LOG_FORMAT_TEXT: return "text";
        case SOL_LOG_FORMAT_JSON: return "json";
        default: return "unknown";
    }
}

sol_log_format_t
sol_log_format_from_name(const char* name) {
    if (name == NULL) {
        return SOL_LOG_FORMAT_TEXT;
    }

    if (strcasecmp(name, "json") == 0) {
        return SOL_LOG_FORMAT_JSON;
    }

    return SOL_LOG_FORMAT_TEXT;
}

/*
 * Base58 encoding for pubkeys (local copy to avoid dependency on sol_txn)
 */

static const char BASE58_ALPHABET[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static int
log_pubkey_to_base58(const sol_pubkey_t* pk, char* out, size_t out_len) {
    if (pk == NULL || out == NULL || out_len < 45) {
        return -1;
    }

    /* Simple base58 encoding */
    uchar temp[SOL_PUBKEY_SIZE];
    memcpy(temp, pk->bytes, SOL_PUBKEY_SIZE);

    char encoded[64];
    int encoded_len = 0;

    /* Count leading zeros */
    int leading_zeros = 0;
    for (int i = 0; i < SOL_PUBKEY_SIZE && temp[i] == 0; i++) {
        leading_zeros++;
    }

    /* Convert to base58 */
    while (encoded_len < 64) {
        int carry = 0;
        bool all_zero = true;

        for (int i = 0; i < SOL_PUBKEY_SIZE; i++) {
            int val = carry * 256 + temp[i];
            temp[i] = val / 58;
            carry = val % 58;
            if (temp[i] != 0) all_zero = false;
        }

        if (all_zero && carry == 0) break;
        encoded[encoded_len++] = BASE58_ALPHABET[carry];
    }

    /* Add leading '1's for zeros */
    for (int i = 0; i < leading_zeros; i++) {
        encoded[encoded_len++] = '1';
    }

    /* Ensure output buffer has room for base58 + NUL. */
    if ((size_t)encoded_len >= out_len) {
        return -1;
    }

    /* Reverse */
    for (int i = 0; i < encoded_len; i++) {
        out[i] = encoded[encoded_len - 1 - i];
    }
    out[encoded_len] = '\0';

    return encoded_len;
}

int
sol_hash_to_hex(const sol_hash_t* h, char* out, size_t out_len) {
    if (h == NULL || out == NULL || out_len < 65) {
        return -1;
    }

    static const char hex[] = "0123456789abcdef";

    for (int i = 0; i < SOL_HASH_SIZE; i++) {
        out[i * 2]     = hex[h->bytes[i] >> 4];
        out[i * 2 + 1] = hex[h->bytes[i] & 0x0f];
    }
    out[64] = '\0';

    return 64;
}

void
sol_log_pubkey(sol_log_level_t level, const char* prefix, const sol_pubkey_t* pk) {
    if (level < g_config.level || pk == NULL) {
        return;
    }

    char buf[45];
    log_pubkey_to_base58(pk, buf, sizeof(buf));
    sol_log_write(level, NULL, 0, NULL, "%s%s", prefix ? prefix : "", buf);
}

void
sol_log_hash(sol_log_level_t level, const char* prefix, const sol_hash_t* h) {
    if (level < g_config.level || h == NULL) {
        return;
    }

    char buf[65];
    sol_hash_to_hex(h, buf, sizeof(buf));
    sol_log_write(level, NULL, 0, NULL, "%s%s", prefix ? prefix : "", buf);
}

void
sol_log_signature(sol_log_level_t level, const char* prefix, const sol_signature_t* sig) {
    if (level < g_config.level || sig == NULL) {
        return;
    }

    /* Just show first and last 8 bytes */
    sol_log_write(level, NULL, 0, NULL,
                  "%s%02x%02x%02x%02x%02x%02x%02x%02x...%02x%02x%02x%02x%02x%02x%02x%02x",
                  prefix ? prefix : "",
                  sig->bytes[0], sig->bytes[1], sig->bytes[2], sig->bytes[3],
                  sig->bytes[4], sig->bytes[5], sig->bytes[6], sig->bytes[7],
                  sig->bytes[56], sig->bytes[57], sig->bytes[58], sig->bytes[59],
                  sig->bytes[60], sig->bytes[61], sig->bytes[62], sig->bytes[63]);
}
