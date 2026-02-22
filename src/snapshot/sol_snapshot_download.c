/*
 * sol_snapshot_download.c - Snapshot Download Implementation
 *
 * Uses curl for HTTP requests. For production use, consider integrating
 * a proper HTTP client library (libcurl, etc.)
 */

#include "sol_snapshot_download.h"
#include "sol_snapshot_archive.h"
#include "../util/sol_alloc.h"
#include "../util/sol_json.h"
#include "../util/sol_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>

#ifdef __linux__
#include <sys/prctl.h>
#endif

#define SOL_SUBPROC_MAX_ARGS (64U)

static volatile sig_atomic_t g_snapshot_download_interrupted = 0;

static char*
sol_strdup_local(const char* s);

static void
snapshot_download_cleanup_orphaned_parts(const char* tmp_path) {
    if (!tmp_path || tmp_path[0] == '\0') return;

    struct stat st;
    if (stat(tmp_path, &st) == 0 && st.st_size > 0) {
        /* There's an active partial download; keep parts for resume. */
        return;
    }

    char dir_path[PATH_MAX];
    const char* base = tmp_path;
    const char* slash = strrchr(tmp_path, '/');
    if (slash) {
        size_t dlen = (size_t)(slash - tmp_path);
        if (dlen == 0 || dlen >= sizeof(dir_path)) {
            return;
        }
        memcpy(dir_path, tmp_path, dlen);
        dir_path[dlen] = '\0';
        base = slash + 1;
    } else {
        snprintf(dir_path, sizeof(dir_path), ".");
    }

    if (!base || base[0] == '\0') return;

    char prefix[PATH_MAX];
    int n = snprintf(prefix, sizeof(prefix), "%s.part", base);
    if (n < 0 || (size_t)n >= sizeof(prefix)) return;
    size_t prefix_len = (size_t)n;

    DIR* dir = opendir(dir_path);
    if (!dir) return;

    struct dirent* ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (strncmp(ent->d_name, prefix, prefix_len) != 0) continue;
        /* Only remove our v2 part naming scheme. */
        if (strstr(ent->d_name, ".v2.") == NULL) continue;

        char full_path[PATH_MAX];
        int m = snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, ent->d_name);
        if (m < 0 || (size_t)m >= sizeof(full_path)) continue;
        (void)unlink(full_path);
    }

    closedir(dir);
}

static void
sol_subprocess_set_pdeathsig(void) {
#ifdef __linux__
    /* Best-effort: ensure curl subprocesses don't outlive the validator. */
    (void)prctl(PR_SET_PDEATHSIG, SIGTERM);
    if (getppid() == 1) {
        _exit(127);
    }
#endif
}

static void
sol_snapshot_download_signal_handler(int sig) {
    (void)sig;
    g_snapshot_download_interrupted = 1;
}

typedef void (*sol_sighandler_fn_t)(int);

static void
sol_snapshot_download_install_signal_handlers(sol_sighandler_fn_t* out_old_int,
                                              sol_sighandler_fn_t* out_old_term) {
    g_snapshot_download_interrupted = 0;

    if (out_old_int) {
        *out_old_int = signal(SIGINT, sol_snapshot_download_signal_handler);
    } else {
        (void)signal(SIGINT, sol_snapshot_download_signal_handler);
    }

    if (out_old_term) {
        *out_old_term = signal(SIGTERM, sol_snapshot_download_signal_handler);
    } else {
        (void)signal(SIGTERM, sol_snapshot_download_signal_handler);
    }
}

static void
sol_snapshot_download_restore_signal_handlers(sol_sighandler_fn_t old_int,
                                              sol_sighandler_fn_t old_term) {
    (void)signal(SIGINT, old_int);
    (void)signal(SIGTERM, old_term);
}

static bool
sol_snapshot_download_should_abort(void) {
    return g_snapshot_download_interrupted != 0;
}

static uint32_t
sol_snapshot_download_env_parallel_connections(uint32_t current, bool* out_overridden) {
    if (out_overridden) *out_overridden = false;
    const char* env = getenv("SOL_SNAPSHOT_DOWNLOAD_CONNECTIONS");
    if (!env || env[0] == '\0') return current;

    char* end = NULL;
    errno = 0;
    unsigned long v = strtoul(env, &end, 10);
    if (errno != 0 || !end || end == env) return current;
    while (*end && isspace((unsigned char)*end)) end++;
    if (*end != '\0') return current;

    if (v > SOL_SNAPSHOT_DOWNLOAD_MAX_PARALLEL_CONNECTIONS) {
        v = SOL_SNAPSHOT_DOWNLOAD_MAX_PARALLEL_CONNECTIONS;
    }
    if (out_overridden) *out_overridden = true;
    return (uint32_t)v;
}

static uint32_t
sol_snapshot_download_autoscale_parallel_connections(uint64_t expected_size,
                                                     uint32_t current) {
    if (current < 2 || expected_size == 0) return current;

    /* These thresholds intentionally favor higher concurrency for very large
     * snapshot archives to keep bootstrap time low. */
    uint32_t target = current;

    if (expected_size >= (192ULL * 1024ULL * 1024ULL * 1024ULL) && target < 128) {
        target = 128;
    } else if (expected_size >= (128ULL * 1024ULL * 1024ULL * 1024ULL) && target < 128) {
        target = 128;
    } else if (expected_size >= (96ULL * 1024ULL * 1024ULL * 1024ULL) && target < 96) {
        target = 96;
    } else if (expected_size >= (64ULL * 1024ULL * 1024ULL * 1024ULL) && target < 80) {
        target = 80;
    } else if (expected_size >= (32ULL * 1024ULL * 1024ULL * 1024ULL) && target < 64) {
        target = 64;
    } else if (expected_size >= (16ULL * 1024ULL * 1024ULL * 1024ULL) && target < 32) {
        target = 32;
    }

    if (target > SOL_SNAPSHOT_DOWNLOAD_MAX_PARALLEL_CONNECTIONS) {
        target = SOL_SNAPSHOT_DOWNLOAD_MAX_PARALLEL_CONNECTIONS;
    }

    return target;
}

static void
sol_execvp_const_argv(const char* const* argv) {
    if (!argv || !argv[0]) _exit(127);

    /* execvp expects `char * const argv[]` but we build args as
     * `const char * const[]` to satisfy -Wwrite-strings. Copy the pointer
     * vector into a mutable type without casting away qualifiers. */
    char* argv_mut[SOL_SUBPROC_MAX_ARGS];
    size_t argc = 0;
    while (argv[argc] && argc < (SOL_SUBPROC_MAX_ARGS - 1U)) {
        argc++;
    }
    if (argv[argc] != NULL) {
        /* Too many arguments (missing terminator or exceeded cap). */
        _exit(127);
    }

    memcpy(argv_mut, argv, (argc + 1U) * sizeof(argv_mut[0]));
    execvp(argv_mut[0], argv_mut);
}

/*
 * Spawn a subprocess (no shell). Returns pid or -1.
 */
static pid_t
sol_spawn_process(const char* const* argv) {
    if (!argv || !argv[0]) return (pid_t)-1;

    pid_t pid = fork();
    if (pid < 0) return (pid_t)-1;
    if (pid == 0) {
        sol_subprocess_set_pdeathsig();
        sol_execvp_const_argv(argv);
        _exit(127);
    }

    return pid;
}

static uint64_t
sol_now_ms_monotonic(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static sol_err_t
sol_run_process_capture_stdout_with_exit_code(const char* const* argv,
                                              char** out,
                                              size_t* out_len,
                                              int* out_exit_code) {
    if (!argv || !argv[0] || !out || !out_len) return SOL_ERR_INVAL;
    *out = NULL;
    *out_len = 0;
    if (out_exit_code) *out_exit_code = -1;

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        return SOL_ERR_IO;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return SOL_ERR_IO;
    }

    if (pid == 0) {
        /* Child */
        sol_subprocess_set_pdeathsig();
        close(pipefd[0]);
        (void)dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            (void)dup2(devnull, STDERR_FILENO);
            close(devnull);
        }

        sol_execvp_const_argv(argv);
        _exit(127);
    }

    /* Parent */
    close(pipefd[1]);

    size_t cap = 64 * 1024;
    char* buf = sol_alloc(cap);
    if (!buf) {
        close(pipefd[0]);
        return SOL_ERR_NOMEM;
    }

    size_t len = 0;
    while (1) {
        if (len + 1 >= cap) {
            size_t new_cap = cap * 2;
            char* new_buf = sol_realloc(buf, new_cap);
            if (!new_buf) {
                sol_free(buf);
                close(pipefd[0]);
                return SOL_ERR_NOMEM;
            }
            buf = new_buf;
            cap = new_cap;
        }

        ssize_t n = read(pipefd[0], buf + len, cap - len - 1);
        if (n < 0) {
            if (errno == EINTR) continue;
            sol_free(buf);
            close(pipefd[0]);
            return SOL_ERR_IO;
        }
        if (n == 0) break;
        len += (size_t)n;
    }
    close(pipefd[0]);
    buf[len] = '\0';

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        sol_free(buf);
        return SOL_ERR_IO;
    }
    if (!WIFEXITED(status)) {
        sol_free(buf);
        return SOL_ERR_IO;
    }

    if (out_exit_code) {
        *out_exit_code = WEXITSTATUS(status);
    }

    *out = buf;
    *out_len = len;
    return SOL_OK;
}

static sol_err_t
sol_run_process_capture_stdout(const char* const* argv, char** out, size_t* out_len) {
    int exit_code = 0;
    sol_err_t err = sol_run_process_capture_stdout_with_exit_code(argv, out, out_len, &exit_code);
    if (err != SOL_OK) return err;
    if (exit_code != 0) {
        sol_free(*out);
        *out = NULL;
        *out_len = 0;
        return SOL_ERR_IO;
    }
    return SOL_OK;
}

static bool
parse_header_u64(const char* line, const char* name, uint64_t* out) {
    if (!line || !name || !out) return false;
    size_t name_len = strlen(name);
    if (strncasecmp(line, name, name_len) != 0) return false;

    const char* p = line + name_len;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == ':') p++;
    while (*p == ' ' || *p == '\t') p++;

    char* end = NULL;
    unsigned long long v = strtoull(p, &end, 10);
    if (!end || end == p) return false;
    *out = (uint64_t)v;
    return true;
}

static bool
parse_content_range_total(const char* line, uint64_t* out_total) {
    if (!line || !out_total) return false;
    if (strncasecmp(line, "Content-Range", 13) != 0) return false;

    const char* slash = strchr(line, '/');
    if (!slash) return false;
    slash++;
    while (*slash == ' ' || *slash == '\t') slash++;

    char* end = NULL;
    unsigned long long total = strtoull(slash, &end, 10);
    if (!end || end == slash) return false;
    *out_total = (uint64_t)total;
    return total > 0;
}

static bool
parse_accept_ranges_bytes(const char* line) {
    if (!line) return false;
    if (strncasecmp(line, "Accept-Ranges", 13) != 0) return false;

    const char* p = strchr(line, ':');
    if (!p) return false;
    p++;
    while (*p == ' ' || *p == '\t') p++;

    /* Best-effort: treat any "bytes" token as range support. */
    return strncasecmp(p, "bytes", 5) == 0 || (strcasestr(p, "bytes") != NULL);
}

static bool
parse_http_status_code(const char* line, int* out_status) {
    if (!line || !out_status) return false;
    if (strncasecmp(line, "HTTP/", 5) != 0) return false;

    const char* p = strchr(line, ' ');
    if (!p) return false;
    while (*p == ' ' || *p == '\t') p++;

    char* end = NULL;
    long code = strtol(p, &end, 10);
    if (!end || end == p) return false;
    if (code < 100 || code > 999) return false;

    *out_status = (int)code;
    return true;
}

static sol_err_t
url_probe_size_and_ranges(const char* url,
                          uint32_t timeout_secs,
                          uint64_t* out_size,
                          bool* out_supports_ranges) {
    if (!url || !out_size || !out_supports_ranges) return SOL_ERR_INVAL;

    *out_size = 0;
    *out_supports_ranges = false;

    char timeout_buf[32];
    uint32_t timeout = timeout_secs ? timeout_secs : 10;
    snprintf(timeout_buf, sizeof(timeout_buf), "%u", timeout);

    char* url_arg = sol_strdup_local(url);
    if (!url_arg) return SOL_ERR_NOMEM;

    /* Prefer a tiny range request (works even when HEAD is blocked). */
    const char* argv_range[] = {
        "curl",
        "--http1.1",
        "-fsSL",
        "-L",
        "-m",
        timeout_buf,
        "--max-filesize",
        "1",
        "-r",
        "0-0",
        "-o",
        "/dev/null",
        "-D",
        "-",
        url_arg,
        NULL,
    };

    char* hdrs = NULL;
    size_t hdrs_len = 0;
    int range_exit = -1;
    sol_err_t err = sol_run_process_capture_stdout_with_exit_code(
        argv_range, &hdrs, &hdrs_len, &range_exit);
    sol_free(url_arg);
    if (err != SOL_OK) return err;
    /* If the server ignores Range, curl will exit non-zero due to
     * --max-filesize, but we still got headers to inspect. */
    if (range_exit != 0 && range_exit != 63) {
        sol_free(hdrs);
        return SOL_ERR_IO;
    }

    uint64_t content_length = 0;
    uint64_t range_total = 0;
    int last_status_code = 0;
    bool accept_ranges_bytes = false;

    const char* p = hdrs;
    const char* end = hdrs + hdrs_len;
    while (p < end) {
        const char* nl = memchr(p, '\n', (size_t)(end - p));
        size_t line_len = nl ? (size_t)(nl - p) : (size_t)(end - p);

        /* Trim CR */
        while (line_len > 0 && (p[line_len - 1] == '\r' || p[line_len - 1] == '\n')) {
            line_len--;
        }

        if (line_len > 0) {
            char line[512];
            size_t copy_len = line_len < sizeof(line) - 1 ? line_len : sizeof(line) - 1;
            memcpy(line, p, copy_len);
            line[copy_len] = '\0';

            int code = 0;
            if (parse_http_status_code(line, &code)) {
                /* `curl -D -` with `-L` prints one header block per response.
                 * Reset per-response fields when a new status line appears so
                 * we don't accidentally treat a redirect's Content-Length as
                 * the final object's size. */
                last_status_code = code;
                content_length = 0;
                range_total = 0;
                accept_ranges_bytes = false;
            } else {
                (void)parse_header_u64(line, "Content-Length", &content_length);
                (void)parse_content_range_total(line, &range_total);
                if (parse_accept_ranges_bytes(line)) accept_ranges_bytes = true;
            }
        }

        if (!nl) break;
        p = nl + 1;
    }

    sol_free(hdrs);

    const uint64_t min_plausible_size = 1ULL * 1024ULL * 1024ULL; /* 1 MiB */

    if (range_total > 0) {
        *out_size = range_total;
        *out_supports_ranges = true;
        return SOL_OK;
    }

    /* Range requests were honored if the response status was 206, even when the
     * total size isn't present in Content-Range (e.g. "bytes 0-0/unknown").
     *
     * Some servers also advertise range support via Accept-Ranges: bytes. */
    *out_supports_ranges = (last_status_code == 206) || accept_ranges_bytes;

    /* Heuristic: some servers honor Range but incorrectly return 200 with a
     * 1-byte Content-Length for a 0-0 probe. Treat this as range support. */
    if (!*out_supports_ranges && last_status_code == 200 && content_length == 1) {
        *out_supports_ranges = true;
        content_length = 0;
    }

    if (*out_supports_ranges) {
        /* Some servers omit the total from Content-Range for small probes. Avoid
         * treating the 0-0 probe's Content-Length (typically 1) as the full size. */
        uint64_t head_len = 0;

        char* url_arg2 = sol_strdup_local(url);
        if (!url_arg2) {
            return SOL_OK;
        }

        const char* argv_head[] = {
            "curl",
            "--http1.1",
            "-fsSL",
            "-L",
            "-m",
            timeout_buf,
            "-I",
            url_arg2,
            NULL,
        };

        char* head = NULL;
        size_t head_sz = 0;
        if (sol_run_process_capture_stdout(argv_head, &head, &head_sz) == SOL_OK) {
            const char* hp = head;
            const char* hend = head + head_sz;
            uint64_t last_len = 0;
            while (hp < hend) {
                const char* nl = memchr(hp, '\n', (size_t)(hend - hp));
                size_t line_len = nl ? (size_t)(nl - hp) : (size_t)(hend - hp);

                while (line_len > 0 && (hp[line_len - 1] == '\r' || hp[line_len - 1] == '\n')) {
                    line_len--;
                }

                if (line_len > 0) {
                    char line[512];
                    size_t copy_len = line_len < sizeof(line) - 1 ? line_len : sizeof(line) - 1;
                    memcpy(line, hp, copy_len);
                    line[copy_len] = '\0';
                    (void)parse_header_u64(line, "Content-Length", &last_len);
                }

                if (!nl) break;
                hp = nl + 1;
            }
            head_len = last_len;
        }

        sol_free(head);
        sol_free(url_arg2);

        if (head_len >= min_plausible_size) {
            *out_size = head_len;
        } else if (last_status_code == 200 && content_length >= min_plausible_size) {
            /* If the range probe was ignored and returned 200, Content-Length
             * can still provide the full size even when HEAD is blocked. */
            *out_size = content_length;
        } else {
            *out_size = 0;
        }
        return SOL_OK;
    }

    if (content_length >= min_plausible_size) {
        *out_size = content_length;
    }

    return SOL_OK;
}

static sol_err_t
append_file_to_fd(int out_fd, const char* path) {
    if (out_fd < 0 || !path) return SOL_ERR_INVAL;

    int in_fd = open(path, O_RDONLY);
    if (in_fd < 0) return SOL_ERR_IO;

#ifdef __linux__
    /* Use kernel-assisted copying when possible to reduce CPU overhead when
     * assembling large snapshots from many part files. */
    off_t in_off = 0;
    off_t out_off = lseek(out_fd, 0, SEEK_END);
    if (out_off == (off_t)-1) {
        out_off = 0;
    }

    bool used_copy_range = false;
    while (1) {
        size_t want = 64u * 1024u * 1024u; /* 64 MiB */
        ssize_t n = copy_file_range(in_fd, &in_off, out_fd, &out_off, want, 0);
        if (n > 0) {
            used_copy_range = true;
            continue;
        }
        if (n == 0) {
            close(in_fd);
            return SOL_OK;
        }
        if (errno == EINTR) {
            continue;
        }

        /* copy_file_range can fail for filesystem/FD combinations. Fall back
         * to buffered read/write in those cases. */
        if (errno == EXDEV || errno == ENOSYS || errno == EOPNOTSUPP || errno == EINVAL) {
            break;
        }

        close(in_fd);
        return SOL_ERR_IO;
    }

    if (used_copy_range) {
        /* copy_file_range may partially succeed and then report an error on
         * subsequent iterations. Ensure the fallback continues from the last
         * offsets. */
        if (lseek(in_fd, in_off, SEEK_SET) == (off_t)-1) {
            close(in_fd);
            return SOL_ERR_IO;
        }
        if (lseek(out_fd, out_off, SEEK_SET) == (off_t)-1) {
            close(in_fd);
            return SOL_ERR_IO;
        }
    }
#endif

    uint8_t* buf = sol_alloc(4 * 1024 * 1024);
    if (!buf) {
        close(in_fd);
        return SOL_ERR_NOMEM;
    }

    while (1) {
        ssize_t n = read(in_fd, buf, 4 * 1024 * 1024);
        if (n < 0) {
            if (errno == EINTR) continue;
            sol_free(buf);
            close(in_fd);
            return SOL_ERR_IO;
        }
        if (n == 0) break;

        size_t off = 0;
        while (off < (size_t)n) {
            ssize_t w = write(out_fd, buf + off, (size_t)n - off);
            if (w < 0) {
                if (errno == EINTR) continue;
                sol_free(buf);
                close(in_fd);
                return SOL_ERR_IO;
            }
            off += (size_t)w;
        }
    }

    sol_free(buf);
    close(in_fd);
    return SOL_OK;
}

static sol_err_t
truncate_file_to_size(const char* path, uint64_t size) {
    if (!path) return SOL_ERR_INVAL;
    int fd = open(path, O_CREAT | O_WRONLY, 0644);
    if (fd < 0) return SOL_ERR_IO;
    int rc = ftruncate(fd, (off_t)size);
    close(fd);
    return rc == 0 ? SOL_OK : SOL_ERR_IO;
}

static pid_t
spawn_curl_range_download(const char* url,
                          const char* out_path,
                          uint64_t start,
                          uint64_t end,
                          uint64_t max_filesize,
                          uint32_t timeout,
                          const char* timeout_buf) {
    if (!url || !out_path) return (pid_t)-1;

    char range_buf[64];
    snprintf(range_buf, sizeof(range_buf), "%llu-%llu",
             (unsigned long long)start,
             (unsigned long long)end);

    char max_buf[32];
    snprintf(max_buf, sizeof(max_buf), "%llu", (unsigned long long)max_filesize);

    const char* argv[32];
    size_t argc = 0;
    argv[argc++] = "curl";
    argv[argc++] = "--http1.1";
    argv[argc++] = "-fsSL";
    argv[argc++] = "-L";
    argv[argc++] = "--retry";
    argv[argc++] = "5";
    argv[argc++] = "--retry-delay";
    argv[argc++] = "1";
    argv[argc++] = "--retry-connrefused";
    argv[argc++] = "--max-filesize";
    argv[argc++] = max_buf;
    argv[argc++] = "-r";
    argv[argc++] = range_buf;
    argv[argc++] = "-o";
    argv[argc++] = out_path;
    if (timeout > 0) {
        argv[argc++] = "-m";
        argv[argc++] = timeout_buf;
    }
    argv[argc++] = url;
    argv[argc++] = NULL;

    return sol_spawn_process(argv);
}

sol_err_t
sol_snapshot_download_calc_parallel_params(uint64_t total_size,
                                           uint64_t start_offset,
                                           uint32_t requested_connections,
                                           uint32_t* out_parts,
                                           uint32_t* out_inflight_max) {
    if (!out_parts || !out_inflight_max) return SOL_ERR_INVAL;
    if (total_size == 0) return SOL_ERR_INVAL;
    if (start_offset >= total_size) return SOL_ERR_INVAL;
    if (requested_connections < 2) return SOL_ERR_INVAL;

    uint32_t inflight_max = requested_connections;
    if (inflight_max > SOL_SNAPSHOT_DOWNLOAD_MAX_PARALLEL_CONNECTIONS) {
        inflight_max = SOL_SNAPSHOT_DOWNLOAD_MAX_PARALLEL_CONNECTIONS;
    }

    uint64_t remaining = total_size - start_offset;
    if (remaining < (uint64_t)inflight_max) {
        inflight_max = (uint32_t)remaining;
        if (inflight_max < 2) {
            /* Not worth parallelizing tiny remainder. */
            return SOL_ERR_INVAL;
        }
    }

    uint32_t parts = inflight_max;

    /* Chunk scheduling: use at most `inflight_max` concurrent `curl` processes,
     * but split the file into more pieces so we can keep connections busy and
     * avoid a long tail when one range request is slower than the rest. */
    const uint64_t target_part_size = 512ULL * 1024ULL * 1024ULL; /* 512 MiB */
    const uint32_t max_parts_per_connection = 16U;
    const uint32_t max_parts_cap = 1024U;

    if (target_part_size > 0 &&
        remaining > (uint64_t)parts * target_part_size) {
        uint64_t want_parts = (remaining + target_part_size - 1) / target_part_size;
        uint64_t max_parts = (uint64_t)inflight_max * max_parts_per_connection;
        if (want_parts < (uint64_t)parts) want_parts = (uint64_t)parts;
        if (want_parts > max_parts) want_parts = max_parts;
        if (want_parts > max_parts_cap) want_parts = max_parts_cap;
        if (want_parts > remaining) want_parts = remaining;
        if (want_parts < 2) return SOL_ERR_INVAL;
        parts = (uint32_t)want_parts;
    }

    *out_parts = parts;
    *out_inflight_max = inflight_max;
    return SOL_OK;
}

static sol_err_t
snapshot_download_parallel(const char* url,
                           const char* out_path,
                           uint64_t total_size,
                           uint64_t start_offset,
                           uint32_t requested_connections,
                           bool ranges_confirmed,
                           const sol_snapshot_download_opts_t* options) {
    if (!url || !out_path || !options || requested_connections < 2 || total_size == 0) return SOL_ERR_INVAL;
    if (start_offset >= total_size) return SOL_ERR_INVAL;
    if (sol_snapshot_download_should_abort()) return SOL_ERR_SHUTDOWN;

    uint32_t parts = 0;
    uint32_t inflight_max = 0;
    sol_err_t perr = sol_snapshot_download_calc_parallel_params(
        total_size, start_offset, requested_connections, &parts, &inflight_max);
    if (perr != SOL_OK) return perr;

    if (parts == inflight_max) {
        sol_log_info("Downloading in %u parallel range requests (size=%lu bytes): %s",
                     (unsigned)inflight_max,
                     (unsigned long)total_size,
                     url);
    } else {
        sol_log_info("Downloading using %u connections over %u parts (size=%lu bytes): %s",
                     (unsigned)inflight_max,
                     (unsigned)parts,
                     (unsigned long)total_size,
                     url);
    }

    uint64_t remaining = total_size - start_offset;
    if (remaining == 0) return SOL_OK;

    uint64_t chunk = remaining / parts;
    if (chunk == 0) return SOL_ERR_INVAL;

    typedef struct {
        uint64_t start;
        uint64_t end;
        uint64_t expected;
        uint64_t have;
        char     path[1024];
        char     tmp_path[1024];
        pid_t    pid;
        uint32_t retries;
        bool     running;
        bool     complete;
    } part_t;

    part_t* ps = sol_calloc(parts, sizeof(part_t));
    if (!ps) return SOL_ERR_NOMEM;

    char timeout_buf[32] = {0};
    uint32_t timeout = options->timeout_secs ? options->timeout_secs : 0;
    if (timeout > 0) snprintf(timeout_buf, sizeof(timeout_buf), "%u", timeout);

    /* Parallel range downloads can intermittently fail under load (TCP resets,
     * transient 5xx, etc). Keep the retry budget reasonably high so we don't
     * throw away multi-GB progress and fall back to single-stream unless the
     * server consistently rejects a specific range. */
    const uint32_t max_restarts = 100;

    /* Prepare part metadata (and resume state) */
    size_t running = 0;
    for (uint32_t i = 0; i < parts; i++) {
        uint64_t start = start_offset + ((uint64_t)i * chunk);
        uint64_t end = (i == parts - 1) ? (total_size - 1) : (start + chunk - 1);
        uint64_t expected = end - start + 1;

        ps[i].start = start;
        ps[i].end = end;
        ps[i].expected = expected;
        ps[i].have = 0;
        ps[i].pid = (pid_t)-1;
        ps[i].retries = 0;
        ps[i].running = false;
        ps[i].complete = false;

        int n = snprintf(ps[i].path, sizeof(ps[i].path), "%s.part%02u.v2.%llu.%llu",
                         out_path,
                         (unsigned)i,
                         (unsigned long long)start_offset,
                         (unsigned long long)total_size);
        if (n < 0 || (size_t)n >= sizeof(ps[i].path)) {
            sol_free(ps);
            return SOL_ERR_INVAL;
        }

        n = snprintf(ps[i].tmp_path, sizeof(ps[i].tmp_path), "%s.tmp", ps[i].path);
        if (n < 0 || (size_t)n >= sizeof(ps[i].tmp_path)) {
            sol_free(ps);
            return SOL_ERR_INVAL;
        }

        struct stat st;
        uint64_t have = 0;
        if (stat(ps[i].path, &st) == 0 && st.st_size > 0) {
            have = (uint64_t)st.st_size;
        }
        if (have > expected) {
            /* Corrupt/leftover part from a previous attempt. */
            int fd = open(ps[i].path, O_WRONLY | O_TRUNC);
            if (fd >= 0) close(fd);
            have = 0;
        }
        ps[i].have = have;

        if (options->resume && have == expected) {
            ps[i].complete = true;
            continue;
        }

        if (!options->resume && have > 0) {
            /* Start fresh */
            int fd = open(ps[i].path, O_WRONLY | O_TRUNC);
            if (fd >= 0) close(fd);
            have = 0;
            ps[i].have = 0;
        }
    }

    /* Spawn initial batch */
    for (uint32_t i = 0; i < parts && running < inflight_max; i++) {
        if (ps[i].complete) continue;
        if (ps[i].running) continue;
        if (ps[i].have >= ps[i].expected) {
            ps[i].complete = true;
            continue;
        }

        uint64_t req_start = ps[i].start + ps[i].have;
        uint64_t remaining_bytes = ps[i].expected - ps[i].have;
        if (remaining_bytes == 0) {
            ps[i].complete = true;
            continue;
        }

        int fd = open(ps[i].tmp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) close(fd);

        pid_t pid = spawn_curl_range_download(url,
                                              ps[i].tmp_path,
                                              req_start,
                                              ps[i].end,
                                              remaining_bytes,
                                              timeout,
                                              timeout_buf);
        if (pid < 0) {
            sol_free(ps);
            return SOL_ERR_IO;
        }
        ps[i].pid = pid;
        ps[i].running = true;
        running++;
    }

    if (sol_snapshot_download_should_abort() && running > 0) {
        for (uint32_t i = 0; i < parts; i++) {
            if (ps[i].running) {
                (void)kill(ps[i].pid, SIGTERM);
            }
        }
        for (uint32_t i = 0; i < parts; i++) {
            if (!ps[i].running) continue;
            int status = 0;
            while (waitpid(ps[i].pid, &status, 0) < 0) {
                if (errno == EINTR) continue;
                break;
            }
            ps[i].running = false;
        }
        sol_free(ps);
        return SOL_ERR_SHUTDOWN;
    }

    /* Monitor downloads */
    uint64_t last_log_ms = sol_now_ms_monotonic();
    uint64_t last_bytes = start_offset;
    while (running > 0) {
        if (sol_snapshot_download_should_abort()) {
            for (uint32_t i = 0; i < parts; i++) {
                if (ps[i].running) {
                    (void)kill(ps[i].pid, SIGTERM);
                }
            }
            for (uint32_t i = 0; i < parts; i++) {
                if (!ps[i].running) continue;
                int status = 0;
                while (waitpid(ps[i].pid, &status, 0) < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
                ps[i].running = false;
            }
            sol_free(ps);
            return SOL_ERR_SHUTDOWN;
        }

        bool exhausted = false;

        for (uint32_t i = 0; i < parts; i++) {
            if (!ps[i].running) continue;

            int status = 0;
            pid_t r = waitpid(ps[i].pid, &status, WNOHANG);
            if (r == 0) continue; /* still running */
            int exit_code = -1;
            if (r < 0) {
                /* Treat waitpid errors as failures to be retried. */
                exit_code = -1;
            } else if (WIFEXITED(status)) {
                exit_code = WEXITSTATUS(status);
            }

            ps[i].running = false;
            running--;

            /* Common "range not honored" signal: the server returned more than
             * requested and curl aborted due to --max-filesize.
             *
             * When the server previously confirmed range support (206 probe),
             * treat this as a transient error and retry the part. Some CDNs
             * intermittently ignore Range under load. */
            if (exit_code == 63) {
                sol_log_warn("Parallel download: range request rejected/ignored (curl exit 63) for part %u", i);
                (void)unlink(ps[i].tmp_path);
                if (!ranges_confirmed) {
                    exhausted = true;
                    continue;
                }

                if (ps[i].retries >= max_restarts) {
                    sol_log_error("Parallel download: part %u failed too many times (range rejected)", i);
                    exhausted = true;
                    continue;
                }

                ps[i].retries++;
                sol_log_warn("Parallel download: retrying part %u after range rejection (%u/%u)",
                             i, ps[i].retries, max_restarts);

                if (ps[i].have >= ps[i].expected) {
                    ps[i].complete = true;
                    continue;
                }

                uint64_t req_start = ps[i].start + ps[i].have;
                uint64_t remaining_bytes = ps[i].expected - ps[i].have;
                if (remaining_bytes == 0) {
                    ps[i].complete = true;
                    continue;
                }

                pid_t pid = spawn_curl_range_download(url,
                                                      ps[i].tmp_path,
                                                      req_start,
                                                      ps[i].end,
                                                      remaining_bytes,
                                                      timeout,
                                                      timeout_buf);
                if (pid < 0) {
                    exhausted = true;
                    continue;
                }
                ps[i].pid = pid;
                ps[i].running = true;
                running++;
                continue;
            }

            /* Merge downloaded bytes into the main part file. */
            uint64_t dl_bytes = 0;
            struct stat st;
            if (stat(ps[i].tmp_path, &st) == 0 && st.st_size > 0) {
                dl_bytes = (uint64_t)st.st_size;
            }
            if (dl_bytes > 0) {
                if (ps[i].have + dl_bytes > ps[i].expected) {
                    sol_log_error("Parallel download: part %u exceeded expected size (have=%lu dl=%lu expected=%lu)",
                                  i,
                                  (unsigned long)ps[i].have,
                                  (unsigned long)dl_bytes,
                                  (unsigned long)ps[i].expected);
                    exhausted = true;
                    continue;
                }

                bool merged = false;
                if (ps[i].have == 0) {
                    /* Fast path: avoid copying tmp -> part when starting fresh.
                     * We keep the `.tmp` indirection so we can detect/ignore
                     * partially-written files on crashes. */
                    if (rename(ps[i].tmp_path, ps[i].path) == 0) {
                        ps[i].have = dl_bytes;
                        merged = true;
                    }
                }

                if (!merged) {
                    int out_fd = open(ps[i].path, O_CREAT | O_WRONLY | O_APPEND, 0644);
                    if (out_fd < 0) {
                        sol_log_error("Parallel download: failed to open part file for append: %s", ps[i].path);
                        exhausted = true;
                        continue;
                    }
                    sol_err_t aerr = append_file_to_fd(out_fd, ps[i].tmp_path);
                    close(out_fd);
                    if (aerr != SOL_OK) {
                        sol_log_error("Parallel download: failed to append temp to part %u", i);
                        exhausted = true;
                        continue;
                    }
                    (void)unlink(ps[i].tmp_path);
                    ps[i].have += dl_bytes;
                }
            } else {
                (void)unlink(ps[i].tmp_path);
            }

            if (ps[i].have == ps[i].expected) {
                ps[i].complete = true;
                continue;
            }

            if (ps[i].retries >= max_restarts) {
                sol_log_error("Parallel download: part %u failed too many times", i);
                exhausted = true;
                continue;
            }

            ps[i].retries++;
            sol_log_warn("Parallel download: retrying part %u (%u/%u)",
                         i, ps[i].retries, max_restarts);

            if (ps[i].have >= ps[i].expected) {
                ps[i].complete = true;
                continue;
            }

            uint64_t req_start = ps[i].start + ps[i].have;
            uint64_t remaining_bytes = ps[i].expected - ps[i].have;
            if (remaining_bytes == 0) {
                ps[i].complete = true;
                continue;
            }

            pid_t pid = spawn_curl_range_download(url,
                                                  ps[i].tmp_path,
                                                  req_start,
                                                  ps[i].end,
                                                  remaining_bytes,
                                                  timeout,
                                                  timeout_buf);
            if (pid < 0) {
                exhausted = true;
                continue;
            }
            ps[i].pid = pid;
            ps[i].running = true;
            running++;
        }

        /* Start any remaining parts when slots are available. */
        while (!exhausted && running < inflight_max) {
            int next = -1;
            for (uint32_t j = 0; j < parts; j++) {
                if (ps[j].complete || ps[j].running) continue;
                next = (int)j;
                break;
            }
            if (next < 0) break;

            if (ps[next].have >= ps[next].expected) {
                ps[next].complete = true;
                continue;
            }

            uint64_t req_start = ps[next].start + ps[next].have;
            uint64_t remaining_bytes = ps[next].expected - ps[next].have;
            if (remaining_bytes == 0) {
                ps[next].complete = true;
                continue;
            }

            int fd = open(ps[next].tmp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
            if (fd >= 0) close(fd);

            pid_t pid = spawn_curl_range_download(url,
                                                  ps[next].tmp_path,
                                                  req_start,
                                                  ps[next].end,
                                                  remaining_bytes,
                                                  timeout,
                                                  timeout_buf);
            if (pid < 0) {
                exhausted = true;
                break;
            }
            ps[next].pid = pid;
            ps[next].running = true;
            running++;
        }

        uint64_t now_ms = sol_now_ms_monotonic();
        if (now_ms - last_log_ms >= 5000) {
            uint64_t part_bytes = 0;
            for (uint32_t i = 0; i < parts; i++) {
                struct stat st;
                if (stat(ps[i].path, &st) == 0 && st.st_size > 0) {
                    part_bytes += (uint64_t)st.st_size;
                }
                if (stat(ps[i].tmp_path, &st) == 0 && st.st_size > 0) {
                    part_bytes += (uint64_t)st.st_size;
                }
            }

            uint64_t bytes = start_offset + part_bytes;
            uint64_t delta_ms = now_ms - last_log_ms;
            uint64_t delta_bytes = (bytes >= last_bytes) ? (bytes - last_bytes) : 0;
            uint64_t speed = delta_ms > 0 ? (delta_bytes * 1000) / delta_ms : 0;

            double pct = total_size > 0 ? (double)bytes * 100.0 / (double)total_size : 0.0;
            sol_log_info("Snapshot download progress: %.1f%% (%lu/%lu bytes) (%lu MB/s, %zu/%u conns, %u parts)",
                         pct,
                         (unsigned long)bytes,
                         (unsigned long)total_size,
                         (unsigned long)(speed / (1024 * 1024)),
                         running,
                         (unsigned)inflight_max,
                         (unsigned)parts);

            last_log_ms = now_ms;
            last_bytes = bytes;
        }

        if (exhausted && running > 0) {
            for (uint32_t i = 0; i < parts; i++) {
                if (ps[i].running) {
                    (void)kill(ps[i].pid, SIGTERM);
                }
            }
        }

        if (exhausted) {
            /* Wait for any remaining children to exit and then fail. */
            for (uint32_t i = 0; i < parts; i++) {
                if (!ps[i].running) continue;
                int status = 0;
                while (waitpid(ps[i].pid, &status, 0) < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
                ps[i].running = false;
            }

            /* Best-effort: salvage any contiguous prefix from the part files
             * into out_path so the caller can resume via single-stream (-C).
             *
             * This avoids throwing away multi-GB progress when a server rejects
             * a specific range (e.g. curl exit 63 from --max-filesize). */
            uint64_t salvaged = 0;
            if (truncate_file_to_size(out_path, start_offset) == SOL_OK) {
                int out_fd = open(out_path, O_WRONLY | O_APPEND, 0644);
                if (out_fd >= 0) {
                    for (uint32_t i = 0; i < parts; i++) {
                        struct stat st;
                        if (stat(ps[i].path, &st) != 0 || st.st_size <= 0) {
                            break;
                        }
                        uint64_t have = (uint64_t)st.st_size;
                        if (have > ps[i].expected) {
                            sol_log_warn("Parallel download: refusing to salvage oversized part %u (have=%lu expected=%lu)",
                                         i,
                                         (unsigned long)have,
                                         (unsigned long)ps[i].expected);
                            break;
                        }
                        if (append_file_to_fd(out_fd, ps[i].path) != SOL_OK) {
                            break;
                        }
                        salvaged += have;
                        if (have < ps[i].expected) {
                            /* First incomplete part - stop at a contiguous prefix. */
                            break;
                        }
                    }
                    close(out_fd);
                }
            }

            for (uint32_t i = 0; i < parts; i++) {
                (void)unlink(ps[i].path);
                (void)unlink(ps[i].tmp_path);
            }

            if (salvaged > 0) {
                sol_log_info("Parallel download salvaged %lu bytes of contiguous progress for resume",
                             (unsigned long)salvaged);
            }

            sol_free(ps);
            return SOL_ERR_IO;
        }

        struct timespec ts = {0, 200 * 1000000L}; /* 200ms */
        nanosleep(&ts, NULL);
    }

    if (sol_snapshot_download_should_abort()) {
        sol_free(ps);
        return SOL_ERR_SHUTDOWN;
    }

    /* Verify parts and assemble */
    for (uint32_t i = 0; i < parts; i++) {
        if (ps[i].complete) continue;
        struct stat st;
        if (stat(ps[i].path, &st) != 0 || (uint64_t)st.st_size != ps[i].expected) {
            sol_log_error("Parallel download produced invalid part %u (%s)", i, ps[i].path);
            sol_free(ps);
            return SOL_ERR_IO;
        }
    }

    int out_fd = -1;
    if (start_offset == 0) {
        out_fd = open(out_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    } else {
        /* Append to an existing partial download. */
        struct stat st;
        uint64_t have = 0;
        if (stat(out_path, &st) == 0) have = (uint64_t)st.st_size;
        if (have != start_offset) {
            sol_log_error("Parallel resume requires existing file at expected offset (have=%lu expected=%lu): %s",
                          (unsigned long)have,
                          (unsigned long)start_offset,
                          out_path);
            sol_free(ps);
            return SOL_ERR_IO;
        }

        out_fd = open(out_path, O_WRONLY | O_APPEND, 0644);
    }
    if (out_fd < 0) {
        sol_free(ps);
        return SOL_ERR_IO;
    }

    for (uint32_t i = 0; i < parts; i++) {
        sol_err_t err = append_file_to_fd(out_fd, ps[i].path);
        if (err != SOL_OK) {
            close(out_fd);
            sol_free(ps);
            return err;
        }
        (void)unlink(ps[i].path);
    }

    close(out_fd);
    sol_free(ps);

    struct stat st;
    if (stat(out_path, &st) != 0 || (uint64_t)st.st_size != total_size) {
        sol_log_error("Parallel download assembled wrong size (got %lu expected %lu)",
                      (unsigned long)(st.st_size),
                      (unsigned long)total_size);
        return SOL_ERR_IO;
    }

    return SOL_OK;
}

static char*
sol_strdup_local(const char* s) {
    if (!s) return NULL;
    size_t len = strlen(s);
    char* out = sol_alloc(len + 1);
    if (!out) return NULL;
    memcpy(out, s, len + 1);
    return out;
}

static uint64_t
parse_json_number_simple(const char* json, const char* key) {
    char search[64];
    snprintf(search, sizeof(search), "\"%s\":", key);

    const char* p = strstr(json, search);
    if (!p) return 0;

    p += strlen(search);
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;

    return strtoull(p, NULL, 10);
}

static bool
url_join(char* out, size_t out_len, const char* base, const char* path) {
    if (!out || out_len == 0 || !base || !path) return false;

    size_t base_len = strlen(base);
    bool base_slash = base_len > 0 && base[base_len - 1] == '/';
    bool path_slash = path[0] == '/';

    const char* sep = "";
    if (!base_slash && !path_slash) {
        sep = "/";
    } else if (base_slash && path_slash) {
        path++;
    }

    int n = snprintf(out, out_len, "%s%s%s", base, sep, path);
    return n >= 0 && (size_t)n < out_len;
}

static bool
url_has_prefix(const char* s, const char* prefix) {
    if (!s || !prefix) return false;
    size_t n = strlen(prefix);
    return strncmp(s, prefix, n) == 0;
}

static bool
url_is_generic_snapshot_endpoint(const char* url) {
    if (!url) return false;

    const char* base = strrchr(url, '/');
    base = base ? base + 1 : url;
    if (!base || base[0] == '\0') return false;

    return strcmp(base, "snapshot.tar.zst") == 0 ||
           strcmp(base, "snapshot.tar.bz2") == 0 ||
           strcmp(base, "snapshot.tar.gz") == 0 ||
           strcmp(base, "snapshot.tar") == 0 ||
           strcmp(base, "incremental-snapshot.tar.zst") == 0 ||
           strcmp(base, "incremental-snapshot.tar.bz2") == 0 ||
           strcmp(base, "incremental-snapshot.tar.gz") == 0 ||
           strcmp(base, "incremental-snapshot.tar") == 0;
}

static bool
url_base_root(char* out, size_t out_len, const char* url) {
    if (!out || out_len == 0 || !url) return false;
    out[0] = '\0';

    const char* scheme = strstr(url, "://");
    if (!scheme) return false;

    const char* host = scheme + 3;
    const char* slash = strchr(host, '/');
    size_t base_len = slash ? (size_t)(slash - url) : strlen(url);
    if (base_len == 0 || base_len >= out_len) return false;
    memcpy(out, url, base_len);
    out[base_len] = '\0';
    return true;
}

static bool
url_dir_base(char* out, size_t out_len, const char* url) {
    if (!out || out_len == 0 || !url) return false;
    out[0] = '\0';

    size_t url_len = strlen(url);
    if (url_len == 0) return false;

    size_t end = url_len;
    for (size_t i = 0; i < url_len; i++) {
        if (url[i] == '?' || url[i] == '#') {
            end = i;
            break;
        }
    }

    size_t slash_pos = (size_t)-1;
    for (size_t i = end; i > 0; i--) {
        if (url[i - 1] == '/') {
            slash_pos = i - 1;
            break;
        }
    }

    size_t base_len = (slash_pos == (size_t)-1) ? end : (slash_pos + 1);
    if (base_len == 0 || base_len >= out_len) return false;
    memcpy(out, url, base_len);
    out[base_len] = '\0';
    return true;
}

static sol_err_t
url_resolve_redirect_target(const char* url,
                            uint32_t timeout_secs,
                            char** out_resolved_url) {
    if (!url || !out_resolved_url) return SOL_ERR_INVAL;
    *out_resolved_url = NULL;

    char timeout_buf[32];
    uint32_t timeout = timeout_secs ? timeout_secs : 10;
    snprintf(timeout_buf, sizeof(timeout_buf), "%u", timeout);

    char* url_arg = sol_strdup_local(url);
    if (!url_arg) return SOL_ERR_NOMEM;

    const char* argv_head[] = {
        "curl",
        "--http1.1",
        "-fsS",
        "-m",
        timeout_buf,
        "-I",
        url_arg,
        NULL,
    };

    char* hdrs = NULL;
    size_t hdrs_len = 0;
    sol_err_t err = sol_run_process_capture_stdout(argv_head, &hdrs, &hdrs_len);

    if (err != SOL_OK) {
        /* Some servers block HEAD; fall back to a tiny range request. */
        const char* argv_range[] = {
            "curl",
            "--http1.1",
            "-fsS",
            "-m",
            timeout_buf,
            "--max-filesize",
            "1",
            "-r",
            "0-0",
            "-o",
            "/dev/null",
            "-D",
            "-",
            url_arg,
            NULL,
        };

        int range_exit = -1;
        err = sol_run_process_capture_stdout_with_exit_code(
            argv_range, &hdrs, &hdrs_len, &range_exit);
        if (err != SOL_OK) {
            sol_free(url_arg);
            return err;
        }
        if (range_exit != 0 && range_exit != 63) {
            sol_free(hdrs);
            sol_free(url_arg);
            return SOL_ERR_IO;
        }
    }

    sol_free(url_arg);

    if (!hdrs || hdrs_len == 0) {
        sol_free(hdrs);
        return SOL_ERR_NOTFOUND;
    }

    char location[1024] = {0};
    bool have_location = false;

    const char* p = hdrs;
    const char* end = hdrs + hdrs_len;
    while (p < end) {
        const char* nl = memchr(p, '\n', (size_t)(end - p));
        size_t line_len = nl ? (size_t)(nl - p) : (size_t)(end - p);
        while (line_len > 0 && (p[line_len - 1] == '\r' || p[line_len - 1] == '\n')) {
            line_len--;
        }

        if (line_len > 0) {
            /* Case-insensitive match for "Location:" */
            if (line_len >= 9 &&
                (p[0] == 'L' || p[0] == 'l') &&
                (p[1] == 'o' || p[1] == 'O') &&
                (p[2] == 'c' || p[2] == 'C') &&
                (p[3] == 'a' || p[3] == 'A') &&
                (p[4] == 't' || p[4] == 'T') &&
                (p[5] == 'i' || p[5] == 'I') &&
                (p[6] == 'o' || p[6] == 'O') &&
                (p[7] == 'n' || p[7] == 'N') &&
                p[8] == ':') {
                size_t i = 9;
                while (i < line_len && (p[i] == ' ' || p[i] == '\t')) i++;
                size_t vlen = (i < line_len) ? (line_len - i) : 0;
                if (vlen > 0) {
                    size_t copy = vlen < sizeof(location) - 1 ? vlen : sizeof(location) - 1;
                    memcpy(location, p + i, copy);
                    location[copy] = '\0';
                    have_location = true;
                    break;
                }
            }
        }

        if (!nl) break;
        p = nl + 1;
    }

    sol_free(hdrs);

    if (!have_location || location[0] == '\0') {
        return SOL_ERR_NOTFOUND;
    }

    /* Resolve location against the original URL. */
    if (url_has_prefix(location, "http://") || url_has_prefix(location, "https://")) {
        *out_resolved_url = sol_strdup_local(location);
        return *out_resolved_url ? SOL_OK : SOL_ERR_NOMEM;
    }

    char base[512] = {0};
    char resolved[1024] = {0};

    if (location[0] == '/') {
        if (!url_base_root(base, sizeof(base), url)) {
            return SOL_ERR_INVAL;
        }
        if (!url_join(resolved, sizeof(resolved), base, location)) {
            return SOL_ERR_TOO_LARGE;
        }
    } else {
        if (!url_dir_base(base, sizeof(base), url)) {
            return SOL_ERR_INVAL;
        }
        if (!url_join(resolved, sizeof(resolved), base, location)) {
            return SOL_ERR_TOO_LARGE;
        }
    }

    *out_resolved_url = sol_strdup_local(resolved);
    return *out_resolved_url ? SOL_OK : SOL_ERR_NOMEM;
}

static char*
rpc_pick_snapshot_url(const char* rpc_url, const char* basename, uint32_t timeout_secs) {
    (void)timeout_secs;
    if (!rpc_url || !basename) return NULL;

    /* RPC endpoints often rate-limit or block HEAD/range probes. Since the
     * snapshot download step already follows redirects and reports errors,
     * avoid pre-probing here and instead return the most commonly supported
     * stable endpoints.
     *
     * Most public RPC nodes expose `snapshot.tar.bz2` and
     * `incremental-snapshot.tar.bz2`, which redirect (303) to concrete
     * `.tar.zst` filenames. */
    const char* suffix = ".tar.bz2";

    char url[512];
    char path[128];

    int pn = snprintf(path, sizeof(path), "%s%s", basename, suffix);
    if (pn < 0 || (size_t)pn >= sizeof(path)) return NULL;
    if (!url_join(url, sizeof(url), rpc_url, path)) return NULL;
    return sol_strdup_local(url);
}

static sol_err_t
snapshot_service_base_url(const char* manifest_url, char** out_base) {
    if (!manifest_url || !out_base) return SOL_ERR_INVAL;
    *out_base = NULL;

    size_t url_len = strlen(manifest_url);
    size_t end = url_len;
    for (size_t i = 0; i < url_len; i++) {
        if (manifest_url[i] == '?' || manifest_url[i] == '#') {
            end = i;
            break;
        }
    }

    size_t slash_pos = (size_t)-1;
    for (size_t i = end; i > 0; i--) {
        if (manifest_url[i - 1] == '/') {
            slash_pos = i - 1;
            break;
        }
    }

    size_t base_len = (slash_pos == (size_t)-1) ? end : (slash_pos + 1);
    char* base = sol_alloc(base_len + 1);
    if (!base) return SOL_ERR_NOMEM;
    memcpy(base, manifest_url, base_len);
    base[base_len] = '\0';
    *out_base = base;
    return SOL_OK;
}

static char*
snapshot_service_join_url(const char* base, const char* path) {
    if (!base || !path) return NULL;
    if (strncmp(path, "http://", 7) == 0 || strncmp(path, "https://", 8) == 0) {
        size_t len = strlen(path);
        char* out = sol_alloc(len + 1);
        if (!out) return NULL;
        memcpy(out, path, len + 1);
        return out;
    }

    bool base_slash = base[0] != '\0' && base[strlen(base) - 1] == '/';
    bool path_slash = path[0] == '/';

    size_t base_len = strlen(base);
    size_t path_len = strlen(path);
    size_t extra = 0;
    if (base_slash && path_slash) extra = (size_t)-1; /* drop one slash */
    else if (!base_slash && !path_slash) extra = 1;  /* add one slash */

    size_t out_len = base_len + path_len + (extra == (size_t)-1 ? (size_t)0 : extra);
    char* out = sol_alloc(out_len + 1);
    if (!out) return NULL;

    memcpy(out, base, base_len);
    size_t pos = base_len;

    if (base_slash && path_slash) {
        path++;
        path_len--;
    } else if (!base_slash && !path_slash) {
        out[pos++] = '/';
    }

    memcpy(out + pos, path, path_len);
    pos += path_len;
    out[pos] = '\0';
    return out;
}

static sol_err_t
snapshot_service_fetch_manifest(const char* manifest_url,
                                uint32_t timeout_secs,
                                char** out_json,
                                size_t* out_len) {
    if (!manifest_url || !out_json || !out_len) return SOL_ERR_INVAL;
    *out_json = NULL;
    *out_len = 0;

    char timeout_buf[32];
    uint32_t timeout = timeout_secs ? timeout_secs : 30;
    snprintf(timeout_buf, sizeof(timeout_buf), "%u", timeout);

    char* url_arg = sol_strdup_local(manifest_url);
    if (!url_arg) return SOL_ERR_NOMEM;

    const char* argv[] = {"curl", "--http1.1", "-fsSL", "-m", timeout_buf, url_arg, NULL};
    sol_err_t err = sol_run_process_capture_stdout(argv, out_json, out_len);
    sol_free(url_arg);
    return err;
}

/*
 * Query available snapshots from RPC
 *
 * Uses getHighestSnapshotSlot RPC method
 */
size_t
sol_snapshot_query_available(const char* rpc_url,
                              sol_available_snapshot_t* out_snapshots,
                              size_t max_count) {
    if (!rpc_url || !out_snapshots || max_count == 0) return 0;

    /* Query highest snapshot slot */
    char post_data[] =
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getHighestSnapshotSlot\"}";

    char* url_arg = sol_strdup_local(rpc_url);
    if (!url_arg) return 0;

    const char* argv[] = {
        "curl",
        "--http1.1",
        "-fsSL",
        "--retry",
        "5",
        "--retry-delay",
        "10",
        "--retry-connrefused",
        "-m",
        "120",
        "-X",
        "POST",
        url_arg,
        "-H",
        "Content-Type: application/json",
        "-d",
        post_data,
        NULL,
    };

    char* response = NULL;
    size_t response_len = 0;
    sol_err_t curl_err = sol_run_process_capture_stdout(argv, &response, &response_len);
    sol_free(url_arg);
    if (curl_err != SOL_OK) return 0;

    /* Parse response */
    uint64_t full_slot = parse_json_number_simple(response, "full");
    uint64_t incr_slot = parse_json_number_simple(response, "incremental");
    sol_free(response);

    if (full_slot == 0) {
        sol_log_warn("No snapshots available from %s", rpc_url);
        return 0;
    }

    size_t count = 0;

    /* Full snapshot */
    if (count < max_count) {
        char* full_url = rpc_pick_snapshot_url(rpc_url, "snapshot", 5);
        if (!full_url) {
            sol_log_warn("RPC node %s did not expose a snapshot download endpoint", rpc_url);
            return 0;
        }

        memset(&out_snapshots[count], 0, sizeof(sol_available_snapshot_t));
        out_snapshots[count].base_slot = 0;
        out_snapshots[count].slot = full_slot;
        out_snapshots[count].type = SOL_SNAPSHOT_FULL;
        out_snapshots[count].url = full_url;
        count++;
    }

    /* Incremental snapshot */
    if (incr_slot > full_slot && count < max_count) {
        char* incr_url = rpc_pick_snapshot_url(rpc_url, "incremental-snapshot", 5);
        if (incr_url) {
            memset(&out_snapshots[count], 0, sizeof(sol_available_snapshot_t));
            out_snapshots[count].base_slot = full_slot;
            out_snapshots[count].slot = incr_slot;
            out_snapshots[count].type = SOL_SNAPSHOT_INCREMENTAL;
            out_snapshots[count].url = incr_url;
            count++;
        }
    }

    sol_log_info("Found %zu snapshots from %s (full: %lu, incr: %lu)",
                 count, rpc_url, (unsigned long)full_slot, (unsigned long)incr_slot);

    return count;
}

/*
 * Query snapshots from a snapshot-service manifest JSON
 */
size_t
sol_snapshot_service_query_available(const char* manifest_url,
                                     sol_available_snapshot_t* out_snapshots,
                                     size_t max_count) {
    if (!manifest_url || !out_snapshots || max_count == 0) return 0;

    char* json = NULL;
    size_t json_len = 0;
    sol_err_t err = snapshot_service_fetch_manifest(manifest_url, 30, &json, &json_len);
    if (err != SOL_OK) return 0;

    size_t count = sol_snapshot_service_parse_manifest_json(
        manifest_url, json, json_len, out_snapshots, max_count);
    sol_free(json);
    return count;
}

size_t
sol_snapshot_service_parse_manifest_json(const char* manifest_url,
                                         const char* json,
                                         size_t json_len,
                                         sol_available_snapshot_t* out_snapshots,
                                         size_t max_count) {
    if (!manifest_url || !json || !out_snapshots || max_count == 0) return 0;

    char* base = NULL;
    sol_err_t err = snapshot_service_base_url(manifest_url, &base);
    if (err != SOL_OK) return 0;

    size_t count = 0;
    sol_json_parser_t p;
    sol_json_parser_init(&p, json, json_len);
    if (!sol_json_parser_object_begin(&p)) {
        sol_free(base);
        return 0;
    }

    char key[64];
    while (sol_json_parser_key(&p, key, sizeof(key))) {
        if (strcmp(key, "full_snapshot") == 0) {
            if (!sol_json_parser_object_begin(&p)) {
                sol_available_snapshots_free(out_snapshots, count);
                sol_free(base);
                return 0;
            }

            char filename[512] = {0};
            uint64_t slot = 0;
            uint64_t size_bytes = 0;

            char k2[64];
            while (sol_json_parser_key(&p, k2, sizeof(k2))) {
                if (strcmp(k2, "filename") == 0) {
                    if (!sol_json_parser_string(&p, filename, sizeof(filename))) {
                        sol_json_parser_skip(&p);
                    }
                } else if (strcmp(k2, "slot") == 0) {
                    (void)sol_json_parser_uint(&p, &slot);
                } else if (strcmp(k2, "size_bytes") == 0) {
                    (void)sol_json_parser_uint(&p, &size_bytes);
                } else {
                    sol_json_parser_skip(&p);
                }
            }
            (void)sol_json_parser_object_end(&p);

            if (count < max_count && filename[0] != '\0' && slot != 0) {
                memset(&out_snapshots[count], 0, sizeof(sol_available_snapshot_t));
                out_snapshots[count].type = SOL_SNAPSHOT_FULL;
                out_snapshots[count].base_slot = 0;
                out_snapshots[count].slot = (sol_slot_t)slot;
                out_snapshots[count].size = size_bytes;
                out_snapshots[count].url = snapshot_service_join_url(base, filename);
                if (!out_snapshots[count].url) {
                    sol_available_snapshots_free(out_snapshots, count);
                    sol_free(base);
                    return 0;
                }
                count++;
            }
        } else if (strcmp(key, "incremental_snapshots") == 0) {
            if (!sol_json_parser_array_begin(&p)) {
                sol_json_parser_skip(&p);
                continue;
            }

            while (!sol_json_parser_array_end(&p)) {
                if (!sol_json_parser_object_begin(&p)) {
                    /* Skip non-object entries */
                    if (!sol_json_parser_skip(&p)) break;
                    continue;
                }

                char filename[512] = {0};
                uint64_t base_slot = 0;
                uint64_t slot = 0;
                uint64_t size_bytes = 0;

                char k2[64];
                while (sol_json_parser_key(&p, k2, sizeof(k2))) {
                    if (strcmp(k2, "filename") == 0) {
                        if (!sol_json_parser_string(&p, filename, sizeof(filename))) {
                            sol_json_parser_skip(&p);
                        }
                    } else if (strcmp(k2, "base_slot") == 0) {
                        (void)sol_json_parser_uint(&p, &base_slot);
                    } else if (strcmp(k2, "slot") == 0) {
                        (void)sol_json_parser_uint(&p, &slot);
                    } else if (strcmp(k2, "size_bytes") == 0) {
                        (void)sol_json_parser_uint(&p, &size_bytes);
                    } else {
                        sol_json_parser_skip(&p);
                    }
                }
                (void)sol_json_parser_object_end(&p);

                if (count < max_count && filename[0] != '\0' && slot != 0) {
                    memset(&out_snapshots[count], 0, sizeof(sol_available_snapshot_t));
                    out_snapshots[count].type = SOL_SNAPSHOT_INCREMENTAL;
                    out_snapshots[count].base_slot = (sol_slot_t)base_slot;
                    out_snapshots[count].slot = (sol_slot_t)slot;
                    out_snapshots[count].size = size_bytes;
                    out_snapshots[count].url = snapshot_service_join_url(base, filename);
                    if (!out_snapshots[count].url) {
                        sol_available_snapshots_free(out_snapshots, count);
                        sol_free(base);
                        return 0;
                    }
                    count++;
                }
            }
        } else {
            sol_json_parser_skip(&p);
        }
    }

    sol_free(base);
    return count;
}

sol_err_t
sol_snapshot_service_find_best_download(const char* manifest_url,
                                        const sol_snapshot_download_opts_t* opts,
                                        sol_available_snapshot_t* out_full,
                                        sol_available_snapshot_t* out_incremental) {
    if (!manifest_url || !out_full) return SOL_ERR_INVAL;

    sol_snapshot_download_opts_t options = SOL_SNAPSHOT_DOWNLOAD_OPTS_DEFAULT;
    if (opts) options = *opts;

    memset(out_full, 0, sizeof(*out_full));
    if (out_incremental) memset(out_incremental, 0, sizeof(*out_incremental));

    char* json = NULL;
    size_t json_len = 0;
    sol_err_t err = snapshot_service_fetch_manifest(manifest_url, options.timeout_secs, &json, &json_len);
    if (err != SOL_OK) return err;

    err = sol_snapshot_service_find_best_from_manifest_json(
        manifest_url, json, json_len, &options, out_full, out_incremental);
    sol_free(json);
    return err;
}

sol_err_t
sol_snapshot_service_find_best_from_manifest_json(const char* manifest_url,
                                                  const char* json,
                                                  size_t json_len,
                                                  const sol_snapshot_download_opts_t* opts,
                                                  sol_available_snapshot_t* out_full,
                                                  sol_available_snapshot_t* out_incremental) {
    if (!manifest_url || !json || !out_full) return SOL_ERR_INVAL;

    sol_snapshot_download_opts_t options = SOL_SNAPSHOT_DOWNLOAD_OPTS_DEFAULT;
    if (opts) options = *opts;

    memset(out_full, 0, sizeof(*out_full));
    if (out_incremental) memset(out_incremental, 0, sizeof(*out_incremental));

    char* base = NULL;
    sol_err_t err = snapshot_service_base_url(manifest_url, &base);
    if (err != SOL_OK) return err;

    /* Pass 1: full snapshot */
    char full_filename[512] = {0};
    uint64_t full_slot = 0;
    uint64_t full_size = 0;

    sol_json_parser_t p;
    sol_json_parser_init(&p, json, json_len);
    if (!sol_json_parser_object_begin(&p)) {
        sol_free(base);
        return SOL_ERR_SNAPSHOT_CORRUPT;
    }

    char key[64];
    while (sol_json_parser_key(&p, key, sizeof(key))) {
        if (strcmp(key, "full_snapshot") == 0) {
            if (!sol_json_parser_object_begin(&p)) {
                sol_free(base);
                return SOL_ERR_SNAPSHOT_CORRUPT;
            }

            char k2[64];
            while (sol_json_parser_key(&p, k2, sizeof(k2))) {
                if (strcmp(k2, "filename") == 0) {
                    if (!sol_json_parser_string(&p, full_filename, sizeof(full_filename))) {
                        sol_json_parser_skip(&p);
                    }
                } else if (strcmp(k2, "slot") == 0) {
                    (void)sol_json_parser_uint(&p, &full_slot);
                } else if (strcmp(k2, "size_bytes") == 0) {
                    (void)sol_json_parser_uint(&p, &full_size);
                } else {
                    sol_json_parser_skip(&p);
                }
            }
            (void)sol_json_parser_object_end(&p);
        } else {
            sol_json_parser_skip(&p);
        }
    }

    if (full_slot == 0 || full_filename[0] == '\0') {
        sol_free(base);
        return SOL_ERR_NOTFOUND;
    }
    if (options.max_size > 0 && full_size > options.max_size) {
        sol_free(base);
        return SOL_ERR_TOO_LARGE;
    }

    out_full->type = SOL_SNAPSHOT_FULL;
    out_full->base_slot = 0;
    out_full->slot = (sol_slot_t)full_slot;
    out_full->size = full_size;
    out_full->url = snapshot_service_join_url(base, full_filename);
    if (!out_full->url) {
        sol_free(base);
        return SOL_ERR_NOMEM;
    }

    /* Pass 2: best incremental snapshot (optional) */
    if (out_incremental && options.allow_incremental) {
        uint64_t best_slot = 0;
        uint64_t best_size = 0;
        char best_filename[512] = {0};

        sol_json_parser_init(&p, json, json_len);
        if (sol_json_parser_object_begin(&p)) {
            while (sol_json_parser_key(&p, key, sizeof(key))) {
                if (strcmp(key, "incremental_snapshots") == 0) {
                    if (!sol_json_parser_array_begin(&p)) {
                        sol_json_parser_skip(&p);
                        continue;
                    }

                    while (!sol_json_parser_array_end(&p)) {
                        if (!sol_json_parser_object_begin(&p)) {
                            if (!sol_json_parser_skip(&p)) break;
                            continue;
                        }

                        uint64_t base_slot = 0;
                        uint64_t slot = 0;
                        uint64_t size_bytes = 0;
                        char filename[512] = {0};

                        char k2[64];
                        while (sol_json_parser_key(&p, k2, sizeof(k2))) {
                            if (strcmp(k2, "filename") == 0) {
                                if (!sol_json_parser_string(&p, filename, sizeof(filename))) {
                                    sol_json_parser_skip(&p);
                                }
                            } else if (strcmp(k2, "base_slot") == 0) {
                                (void)sol_json_parser_uint(&p, &base_slot);
                            } else if (strcmp(k2, "slot") == 0) {
                                (void)sol_json_parser_uint(&p, &slot);
                            } else if (strcmp(k2, "size_bytes") == 0) {
                                (void)sol_json_parser_uint(&p, &size_bytes);
                            } else {
                                sol_json_parser_skip(&p);
                            }
                        }
                        (void)sol_json_parser_object_end(&p);

                        if (base_slot != full_slot) continue;
                        if (slot == 0 || filename[0] == '\0') continue;
                        if (options.max_size > 0 && size_bytes > options.max_size) continue;

                        if (slot > best_slot) {
                            best_slot = slot;
                            best_size = size_bytes;
                            snprintf(best_filename, sizeof(best_filename), "%s", filename);
                        }
                    }
                } else {
                    sol_json_parser_skip(&p);
                }
            }
        }

        if (best_slot != 0) {
            out_incremental->type = SOL_SNAPSHOT_INCREMENTAL;
            out_incremental->base_slot = (sol_slot_t)full_slot;
            out_incremental->slot = (sol_slot_t)best_slot;
            out_incremental->size = best_size;
            out_incremental->url = snapshot_service_join_url(base, best_filename);
            if (!out_incremental->url) {
                sol_available_snapshot_free(out_full);
                sol_free(base);
                return SOL_ERR_NOMEM;
            }
        }
    }

    sol_free(base);
    return SOL_OK;
}

/*
 * Find best snapshot from multiple sources
 */
sol_err_t
sol_snapshot_find_best_download(const sol_snapshot_source_t* sources,
                                 size_t source_count,
                                 const sol_pubkey_t* known_validators,
                                 size_t known_count,
                                 sol_available_snapshot_t* out_snapshot) {
    if (!sources || source_count == 0 || !out_snapshot) {
        return SOL_ERR_INVAL;
    }

    sol_available_snapshot_t best = {0};
    best.slot = 0;

    sol_available_snapshot_t candidates[16];

    for (size_t i = 0; i < source_count; i++) {
        size_t n = sol_snapshot_query_available(
            sources[i].url, candidates, 16);

        for (size_t j = 0; j < n; j++) {
            /* Prefer trusted sources */
            bool is_trusted = sources[i].trusted;

            /* Check if from known validator */
            if (!is_trusted && known_validators && known_count > 0) {
                for (size_t k = 0; k < known_count; k++) {
                    if (memcmp(&candidates[j].source_node,
                               &known_validators[k],
                               sizeof(sol_pubkey_t)) == 0) {
                        is_trusted = true;
                        break;
                    }
                }
            }

            /* Select if better than current best */
            if (candidates[j].type == SOL_SNAPSHOT_FULL) {
                if (candidates[j].slot > best.slot ||
                    (candidates[j].slot == best.slot && is_trusted)) {
                    /* Free previous best */
                    sol_free(best.url);

                    best = candidates[j];
                    candidates[j].url = NULL;  /* Transfer ownership */
                }
            }
        }

        /* Free unused candidates */
        for (size_t j = 0; j < n; j++) {
            sol_free(candidates[j].url);
        }
    }

    if (best.slot == 0) {
        return SOL_ERR_NOTFOUND;
    }

    *out_snapshot = best;
    return SOL_OK;
}

/*
 * Download snapshot using curl
 */
sol_err_t
sol_snapshot_download(const sol_available_snapshot_t* snapshot,
                       const sol_snapshot_download_opts_t* opts,
                       char* out_path,
                       size_t max_path_len) {
    if (!snapshot || !snapshot->url || !out_path) {
        return SOL_ERR_INVAL;
    }

    sol_snapshot_download_opts_t options = SOL_SNAPSHOT_DOWNLOAD_OPTS_DEFAULT;
    const sol_snapshot_download_opts_t defaults = SOL_SNAPSHOT_DOWNLOAD_OPTS_DEFAULT;
    if (opts) options = *opts;

    bool env_parallel_overridden = false;
    uint32_t env_parallel = sol_snapshot_download_env_parallel_connections(options.parallel_connections,
                                                                           &env_parallel_overridden);
    if (env_parallel_overridden && env_parallel != options.parallel_connections) {
        sol_log_info("Snapshot download: SOL_SNAPSHOT_DOWNLOAD_CONNECTIONS=%u (was %u)",
                     (unsigned)env_parallel,
                     (unsigned)options.parallel_connections);
        options.parallel_connections = env_parallel;
    }

    /* Build output path */
    const char* output_dir = options.output_dir ? options.output_dir : ".";

    /* Some RPC nodes expose stable endpoints like `snapshot.tar.bz2` that
     * redirect to a concrete `snapshot-<slot>-<hash>.tar.zst`. Resolve the
     * redirect to name archives by their real slot/hash so restarts can reuse
     * them via directory scans. */
    char* resolved_url = NULL;
    const char* effective_url = snapshot->url;
    const char* url_for_name = snapshot->url;
    if (snapshot->url && url_is_generic_snapshot_endpoint(snapshot->url)) {
        if (url_resolve_redirect_target(snapshot->url, options.timeout_secs, &resolved_url) == SOL_OK &&
            resolved_url && resolved_url[0] != '\0') {
            url_for_name = resolved_url;
            effective_url = resolved_url;
        }
    }

    const char* filename = strrchr(url_for_name, '/');
    if (!filename) filename = "snapshot.tar.zst";
    else filename++;

    snprintf(out_path, max_path_len, "%s/%s", output_dir, filename);

    /* Download into a sidecar path and rename on success. This prevents
     * partially-downloaded archives from being treated as usable snapshots by
     * directory scans. */
    char tmp_path[PATH_MAX];
    int tn = snprintf(tmp_path, sizeof(tmp_path), "%s.partial", out_path);
    if (tn < 0 || (size_t)tn >= sizeof(tmp_path)) {
        sol_free(resolved_url);
        return SOL_ERR_TOO_LARGE;
    }

    /* Best-effort: cleanup orphaned parallel-download part files when no
     * active partial download exists. This prevents abandoned `.partial.part*`
     * files from consuming significant disk. */
    snapshot_download_cleanup_orphaned_parts(tmp_path);

    /* Probe size + range support when needed. This is used for:
     * - parallel range downloads
     * - validating/resuming existing partial downloads when manifest size is missing
     */
    uint64_t expected_size = snapshot->size;
    bool supports_ranges = false;
    bool probe_ok = false;
    if (options.parallel_connections >= 2 || (expected_size == 0 && (options.resume || options.verify_after))) {
        uint64_t probed_size = 0;
        bool probed_ranges = false;
        sol_err_t probe_err = url_probe_size_and_ranges(
            effective_url, options.timeout_secs, &probed_size, &probed_ranges);
        if (probe_err == SOL_OK) {
            probe_ok = true;
            if (expected_size == 0 && probed_size > 0) {
                expected_size = probed_size;
            }
            supports_ranges = probed_ranges;
        } else {
            sol_log_debug("Snapshot size/range probe failed (err=%d): %s",
                          probe_err, effective_url);
        }
    }

    /* Some servers return slightly inconsistent Content-Length values (or
     * omit them entirely). Allow a small tolerance for large archives to avoid
     * re-downloading 100GB+ snapshots due to tiny size deltas. */
    uint64_t size_tolerance = 0;
    if (expected_size >= (1ULL * 1024ULL * 1024ULL * 1024ULL)) { /* >= 1 GiB */
        size_tolerance = 1ULL * 1024ULL * 1024ULL;               /* 1 MiB */
    }

    /* Only treat `expected_size` as authoritative when it came from a trusted
     * manifest size or when the server confirmed range support (Content-Range).
     *
     * Some RPC snapshot endpoints return inconsistent Content-Length values or
     * rate-limit HEAD/range probes. In those cases we still use `expected_size`
     * for heuristics but avoid failing downloads on small mismatches. */
    bool enforce_size_match = (expected_size > 0) &&
                              (snapshot->size > 0 || supports_ranges);

    /* Auto-scale parallelism for large archives when the caller did not
     * explicitly configure connections (common in validator bootstrap flows). */
    if (!env_parallel_overridden &&
        options.parallel_connections >= 2 &&
        expected_size > 0 &&
        (!opts || opts->parallel_connections == defaults.parallel_connections)) {
        uint32_t scaled = sol_snapshot_download_autoscale_parallel_connections(
            expected_size, options.parallel_connections);
        if (scaled != options.parallel_connections) {
            sol_log_info("Snapshot download: scaling parallel connections to %u (size=%lu bytes)",
                         (unsigned)scaled,
                         (unsigned long)expected_size);
            options.parallel_connections = scaled;
        }
    }

    /* Fast path: file already present and verified. */
    if (options.verify_after) {
        struct stat st;
        if (stat(out_path, &st) == 0 && st.st_size > 0) {
            uint64_t have = (uint64_t)st.st_size;
            if (expected_size > 0 && have != expected_size) {
                uint64_t diff = have > expected_size ? (have - expected_size) : (expected_size - have);
                if (enforce_size_match && diff > size_tolerance) {
                    sol_log_warn("Snapshot archive size mismatch (got %lu expected %lu); will re-download: %s",
                                 (unsigned long)have,
                                 (unsigned long)expected_size,
                                 out_path);
                } else {
                    sol_log_warn("Snapshot archive size differs slightly (got %lu expected %lu); accepting existing archive: %s",
                                 (unsigned long)have,
                                 (unsigned long)expected_size,
                                 out_path);
                    expected_size = have;
                }
            }

            if (expected_size == 0 || have == expected_size) {
                sol_err_t ok = sol_snapshot_archive_check(out_path);
                if (ok == SOL_OK) {
                    sol_log_info("Snapshot archive already present: %s", out_path);
                    (void)unlink(tmp_path);
                    sol_free(resolved_url);
                    return SOL_OK;
                }

                /* Fully downloaded but invalid -> force a fresh download. */
                if (expected_size > 0 && have == expected_size) {
                    sol_log_warn("Snapshot archive failed verification; re-downloading from scratch: %s", out_path);
                    (void)unlink(out_path);
                }
            }
        }
    }

    /* Prefer parallel range download when possible (large snapshots). */
    uint64_t resume_from = 0;
    bool moved_final_to_partial = false;
    if (options.resume) {
        struct stat st;
        if (stat(tmp_path, &st) == 0 && st.st_size > 0) {
            resume_from = (uint64_t)st.st_size;
        } else if (expected_size > 0 && stat(out_path, &st) == 0 && st.st_size > 0) {
            uint64_t have = (uint64_t)st.st_size;
            uint64_t diff = have > expected_size ? (have - expected_size) : (expected_size - have);
            if (!enforce_size_match || diff <= size_tolerance) {
                expected_size = have;
            } else if (have != expected_size) {
            /* Legacy partial download at the final path; move it aside so scans
             * don't treat it as a usable snapshot. */
            if (rename(out_path, tmp_path) == 0) {
                    resume_from = have;
                    moved_final_to_partial = true;
                }
            }
        }
    }

    if (options.verify_after && expected_size > 0 && resume_from == expected_size) {
        if (rename(tmp_path, out_path) != 0) {
            sol_log_error("Failed to finalize existing snapshot download (rename): %s", strerror(errno));
            sol_free(resolved_url);
            return SOL_ERR_IO;
        }
        sol_err_t ok = sol_snapshot_archive_check(out_path);
        if (ok == SOL_OK) {
            sol_log_info("Snapshot archive already present: %s", out_path);
            sol_free(resolved_url);
            return SOL_OK;
        }
        sol_log_warn("Snapshot archive failed verification; re-downloading from scratch: %s", out_path);
        (void)unlink(out_path);
        resume_from = 0;
    }

    if (options.parallel_connections >= 2) {
        uint64_t total_size = expected_size;

        uint64_t min_size = options.parallel_min_size;
        bool want_parallel = total_size > 0 &&
                             (min_size == 0 || total_size >= min_size);

        if (want_parallel) {
            bool allow_without_ranges =
                url_has_prefix(effective_url, "https://data.pipedev.network") ||
                url_has_prefix(effective_url, "http://data.pipedev.network");

            /* Only parallelize when the server actually supports range
             * requests. Some public RPC endpoints rate-limit range probes and
             * return 429s for parallel range fetches. */
            if (!supports_ranges) {
                if (probe_ok) {
                    if (allow_without_ranges) {
                        sol_log_info("Snapshot server did not advertise HTTP range support; attempting parallel anyway: %s",
                                     effective_url);
                    } else {
                        sol_log_info("Snapshot server did not confirm HTTP range support; using single stream: %s",
                                     effective_url);
                        want_parallel = false;
                    }
                } else {
                    /* Probe failures can be transient (429, head blocked, etc).
                     * Attempt the parallel range download anyway; it will fail
                     * fast if the server ignores Range and then fall back. */
                    sol_log_info("Snapshot range probe failed; attempting parallel download anyway: %s",
                                 effective_url);
                }
            } else if (resume_from > 0 && total_size > resume_from) {
                /* Avoid spawning dozens of tiny range requests when only a
                 * small tail remains to be fetched (common when size probes
                 * are slightly off). */
                uint64_t remaining = total_size - resume_from;
                if (remaining < (8ULL * 1024ULL * 1024ULL)) { /* 8 MiB */
                    want_parallel = false;
                }
            }
        }

        if (want_parallel) {
            sol_sighandler_fn_t old_int = SIG_DFL;
            sol_sighandler_fn_t old_term = SIG_DFL;
            sol_snapshot_download_install_signal_handlers(&old_int, &old_term);

            sol_err_t err = snapshot_download_parallel(
                effective_url,
                tmp_path,
                total_size,
                resume_from,
                options.parallel_connections,
                probe_ok && supports_ranges,
                &options);
            sol_snapshot_download_restore_signal_handlers(old_int, old_term);

            if (err == SOL_ERR_SHUTDOWN) {
                sol_free(resolved_url);
                return err;
            }
            if (err == SOL_OK) {
                if (rename(tmp_path, out_path) != 0) {
                    sol_log_error("Failed to finalize snapshot download (rename): %s", strerror(errno));
                    sol_free(resolved_url);
                    return SOL_ERR_IO;
                }
                if (options.verify_after) {
                    sol_err_t verr = sol_snapshot_archive_check(out_path);
                    if (verr != SOL_OK) {
                        sol_log_error("Downloaded snapshot verification failed");
                        (void)unlink(out_path);
                        sol_free(resolved_url);
                        return verr;
                    }
                }
                sol_log_info("Downloaded to: %s", out_path);
                sol_free(resolved_url);
                return SOL_OK;
            }

            sol_log_warn("Parallel download failed (err=%d), falling back to single stream", err);

            /* Re-probe resume point after a failed parallel attempt. */
            if (options.resume) {
                struct stat st;
                if (stat(tmp_path, &st) == 0 && st.st_size > 0) {
                    resume_from = (uint64_t)st.st_size;
                }
            }
        }
    }

    /* Single-stream download (supports resume). */
    if (options.resume && resume_from > 0) {
        if (expected_size > 0 && resume_from >= expected_size) {
            /* If the size matches, we would have returned via the fast path above.
             * If it's larger, treat as corrupt and start fresh. */
            if (resume_from > expected_size) {
                uint64_t diff = resume_from - expected_size;
                if (!enforce_size_match || diff <= size_tolerance) {
                    /* Treat minor differences as probe noise; accept the local
                     * file size as authoritative. */
                    expected_size = resume_from;
                } else {
                    sol_log_warn("Snapshot archive larger than expected; starting fresh: %s", tmp_path);
                    int fd = open(tmp_path, O_WRONLY | O_TRUNC);
                    if (fd >= 0) close(fd);
                    resume_from = 0;
                }
            }
        }
        if (!supports_ranges) {
            /* Resume requires HTTP range support. If the server doesn't
             * support ranges, a partial file cannot be continued. */
            sol_log_warn("Snapshot server does not support byte ranges; restarting download from scratch: %s", tmp_path);
            int fd = open(tmp_path, O_WRONLY | O_TRUNC);
            if (fd >= 0) close(fd);
            resume_from = 0;
        }
        sol_log_info("Resuming download from byte %lu", (unsigned long)resume_from);
    }

    sol_log_info("Downloading: %s", effective_url);

    char timeout_buf[32];
    uint32_t timeout = options.timeout_secs ? options.timeout_secs : 0;
    if (timeout > 0) snprintf(timeout_buf, sizeof(timeout_buf), "%u", timeout);

    sol_sighandler_fn_t old_int = SIG_DFL;
    sol_sighandler_fn_t old_term = SIG_DFL;
    sol_snapshot_download_install_signal_handlers(&old_int, &old_term);

    int last_exit = -1;
    const int max_attempts = options.resume ? 8 : 1;

    for (int attempt = 1; attempt <= max_attempts; attempt++) {
        if (sol_snapshot_download_should_abort()) {
            sol_snapshot_download_restore_signal_handlers(old_int, old_term);
            return SOL_ERR_SHUTDOWN;
        }

        if (options.resume) {
            struct stat st;
            if (stat(tmp_path, &st) == 0 && st.st_size > 0) {
                resume_from = (uint64_t)st.st_size;
            }
        }

        char resume_buf[32] = {0};
        if (resume_from > 0) snprintf(resume_buf, sizeof(resume_buf), "%lu", (unsigned long)resume_from);

        const char* argv[32];
        size_t argc = 0;
        argv[argc++] = "curl";
        argv[argc++] = "--http1.1";
        argv[argc++] = "-fL";
        argv[argc++] = "--retry";
        argv[argc++] = "5";
        argv[argc++] = "--retry-delay";
        argv[argc++] = "1";
        argv[argc++] = "--retry-connrefused";
        argv[argc++] = "-o";
        argv[argc++] = tmp_path;
        if (resume_from > 0 && supports_ranges) {
            argv[argc++] = "-C";
            argv[argc++] = resume_buf;
        }
        if (timeout > 0) {
            argv[argc++] = "-m";
            argv[argc++] = timeout_buf;
        }
        argv[argc++] = effective_url;
        argv[argc++] = NULL;

        pid_t pid = sol_spawn_process(argv);
        if (pid < 0) {
            sol_snapshot_download_restore_signal_handlers(old_int, old_term);
            sol_free(resolved_url);
            return SOL_ERR_IO;
        }

        int status = 0;
        while (1) {
            if (sol_snapshot_download_should_abort()) {
                (void)kill(pid, SIGTERM);
                while (waitpid(pid, &status, 0) < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
                sol_snapshot_download_restore_signal_handlers(old_int, old_term);
                return SOL_ERR_SHUTDOWN;
            }

            pid_t r = waitpid(pid, &status, WNOHANG);
            if (r == 0) {
                struct timespec ts = {0, 200 * 1000000L}; /* 200ms */
                nanosleep(&ts, NULL);
                continue;
            }
            if (r < 0) {
                if (errno == EINTR) continue;
                sol_snapshot_download_restore_signal_handlers(old_int, old_term);
                sol_free(resolved_url);
                return SOL_ERR_IO;
            }
            break;
        }

        if (WIFEXITED(status)) {
            last_exit = WEXITSTATUS(status);
        } else {
            last_exit = -1;
        }

        if (last_exit == 0) {
            break;
        }

        if (!options.resume || attempt == max_attempts) {
            sol_snapshot_download_restore_signal_handlers(old_int, old_term);
            sol_log_error("Download failed with code %d", last_exit);
            if (moved_final_to_partial) {
                /* Best-effort restore of the original archive when we moved it
                 * to a `.partial` path but couldn't resume/download. */
                if (access(out_path, F_OK) != 0) {
                    (void)rename(tmp_path, out_path);
                }
            }
            sol_free(resolved_url);
            return SOL_ERR_IO;
        }

        sol_log_warn("Download failed with code %d; retrying (attempt %d/%d)",
                     last_exit,
                     attempt,
                     max_attempts);

        /* Best-effort backoff to avoid hammering rate-limited endpoints. */
        uint64_t backoff_ms = 1000ULL * (uint64_t)attempt;
        if (backoff_ms > 15000ULL) backoff_ms = 15000ULL;
        struct timespec ts = {(time_t)(backoff_ms / 1000ULL),
                              (long)((backoff_ms % 1000ULL) * 1000000L)};
        nanosleep(&ts, NULL);
    }

    sol_snapshot_download_restore_signal_handlers(old_int, old_term);

    if (expected_size > 0 && enforce_size_match) {
        struct stat st2;
        if (stat(tmp_path, &st2) != 0) {
            sol_free(resolved_url);
            return SOL_ERR_IO;
        }
        uint64_t have = (uint64_t)st2.st_size;
        uint64_t diff = have > expected_size ? (have - expected_size) : (expected_size - have);
        if (diff > size_tolerance) {
            sol_log_error("Downloaded snapshot size mismatch (got %lu expected %lu)",
                          (unsigned long)have,
                          (unsigned long)expected_size);
            if (moved_final_to_partial) {
                if (access(out_path, F_OK) != 0) {
                    (void)rename(tmp_path, out_path);
                }
            }
            sol_free(resolved_url);
            return SOL_ERR_IO;
        }
    }

    if (rename(tmp_path, out_path) != 0) {
        sol_log_error("Failed to finalize snapshot download (rename): %s", strerror(errno));
        sol_free(resolved_url);
        return SOL_ERR_IO;
    }

    /* Verify download */
    if (options.verify_after) {
        sol_err_t err = sol_snapshot_archive_check(out_path);
        if (err != SOL_OK) {
            sol_log_error("Downloaded snapshot verification failed");
            (void)unlink(out_path);
            sol_free(resolved_url);
            return err;
        }
    }

    sol_log_info("Downloaded to: %s", out_path);
    sol_free(resolved_url);
    return SOL_OK;
}

/*
 * Download and extract in one step
 */
sol_err_t
sol_snapshot_download_and_extract(const sol_available_snapshot_t* snapshot,
                                   const sol_snapshot_download_opts_t* opts,
                                   const char* extract_dir) {
    char archive_path[512];
    sol_err_t err;

    /* Download */
    sol_snapshot_download_opts_t dl_opts = SOL_SNAPSHOT_DOWNLOAD_OPTS_DEFAULT;
    if (opts) dl_opts = *opts;
    dl_opts.output_dir = extract_dir;

    err = sol_snapshot_download(snapshot, &dl_opts, archive_path, sizeof(archive_path));
    if (err != SOL_OK) {
        return err;
    }

    /* Extract */
    sol_archive_extract_opts_t extract_opts = SOL_ARCHIVE_EXTRACT_OPTS_DEFAULT;
    extract_opts.output_dir = extract_dir;

    err = sol_snapshot_archive_extract(archive_path, &extract_opts);
    if (err != SOL_OK) {
        sol_log_error("Extraction failed");
        return err;
    }

    /* Optionally remove archive after extraction */
    /* unlink(archive_path); */

    return SOL_OK;
}

/*
 * Free available snapshot
 */
void
sol_available_snapshot_free(sol_available_snapshot_t* snapshot) {
    if (!snapshot) return;
    sol_free(snapshot->url);
    snapshot->url = NULL;
}

/*
 * Free array of snapshots
 */
void
sol_available_snapshots_free(sol_available_snapshot_t* snapshots, size_t count) {
    if (!snapshots) return;
    for (size_t i = 0; i < count; i++) {
        sol_available_snapshot_free(&snapshots[i]);
    }
}

/*
 * Get default sources for a network
 */
size_t
sol_snapshot_get_default_sources(const char* network,
                                  sol_snapshot_source_t* out_sources,
                                  size_t max_count) {
    if (!network || !out_sources || max_count == 0) return 0;

    const char* urls[5];
    size_t count = 0;

    if (strcmp(network, "mainnet") == 0 ||
        strcmp(network, "mainnet-beta") == 0) {
        urls[0] = "https://api.mainnet-beta.solana.com";
        count = 1;
    } else if (strcmp(network, "testnet") == 0) {
        urls[0] = "https://api.testnet.solana.com";
        count = 1;
    } else if (strcmp(network, "devnet") == 0) {
        urls[0] = "https://api.devnet.solana.com";
        count = 1;
    } else {
        sol_log_warn("Unknown network: %s", network);
        return 0;
    }

    if (count > max_count) count = max_count;

    for (size_t i = 0; i < count; i++) {
        out_sources[i].url = sol_alloc(strlen(urls[i]) + 1);
        if (out_sources[i].url) {
            strcpy(out_sources[i].url, urls[i]);
        }
        memset(&out_sources[i].identity, 0, sizeof(sol_pubkey_t));
        out_sources[i].trusted = true;  /* Official endpoints are trusted */
    }

    return count;
}
