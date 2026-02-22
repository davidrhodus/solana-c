/*
 * sol_snapshot_archive.c - Snapshot Archive Extraction Implementation
 */

#include "sol_snapshot_archive.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>
#include <poll.h>

/* Optional zstd support */
#ifdef SOL_HAS_ZSTD
#include <zstd.h>
#endif

/* Optional lz4 support */
#ifdef SOL_HAS_LZ4
#include <lz4frame.h>
#endif

/*
 * TAR header (POSIX ustar format)
 */
typedef struct {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char checksum[8];
    char typeflag;
    char linkname[100];
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
    char padding[12];
} tar_header_t;

#define TAR_BLOCK_SIZE 512
#define TAR_MAGIC "ustar"

/*
 * Check if zstd is available
 */
bool
sol_snapshot_has_zstd(void) {
#ifdef SOL_HAS_ZSTD
    return true;
#else
    /* Check if zstd command is available */
    return system("which zstd > /dev/null 2>&1") == 0;
#endif
}

/*
 * Check if lz4 is available
 */
bool
sol_snapshot_has_lz4(void) {
#ifdef SOL_HAS_LZ4
    return true;
#else
    return system("which lz4 > /dev/null 2>&1") == 0;
#endif
}

static bool
path_has_executable(const char* exe) {
    if (!exe || exe[0] == '\0') return false;

    const char* path = getenv("PATH");
    if (!path || path[0] == '\0') return false;

    size_t exe_len = strlen(exe);
    const char* p = path;
    while (p && *p) {
        const char* sep = strchr(p, ':');
        size_t dir_len = sep ? (size_t)(sep - p) : strlen(p);

        if (dir_len > 0 && dir_len + 1 + exe_len + 1 <= PATH_MAX) {
            char buf[PATH_MAX];
            memcpy(buf, p, dir_len);
            buf[dir_len] = '/';
            memcpy(buf + dir_len + 1, exe, exe_len);
            buf[dir_len + 1 + exe_len] = '\0';

            if (access(buf, X_OK) == 0) {
                return true;
            }
        }

        p = sep ? (sep + 1) : NULL;
    }

    return false;
}

static bool
snapshot_has_pzstd(void) {
    static int cached = -1;
    if (cached >= 0) return cached != 0;
    cached = path_has_executable("zstd") ? 1 : 0;
    return cached != 0;
}

static bool
snapshot_pzstd_enabled_for_size(uint64_t archive_size) {
    const char* env = getenv("SOL_SNAPSHOT_ARCHIVE_PZSTD");
    if (env && env[0] != '\0') {
        if (env[0] == '0') return false;
        return true;
    }

    /* Auto: only for large mainnet-sized archives. */
    return archive_size >= (8ULL * 1024ULL * 1024ULL * 1024ULL);
}

static void
execvp_const_argv(const char* const* argv) {
    if (!argv || !argv[0]) _exit(127);

    char* argv_mut[32];
    size_t argc = 0;
    while (argv[argc] && argc < (sizeof(argv_mut) / sizeof(argv_mut[0]) - 1U)) {
        argc++;
    }
    if (argv[argc] != NULL) {
        _exit(127);
    }
    memcpy(argv_mut, argv, (argc + 1U) * sizeof(argv_mut[0]));
    execvp(argv_mut[0], argv_mut);
    _exit(127);
}

/*
 * Detect compression from magic bytes
 */
sol_snapshot_compression_t
sol_snapshot_archive_detect_compression(const char* archive_path) {
    FILE* f = fopen(archive_path, "rb");
    if (!f) return SOL_SNAPSHOT_COMPRESSION_NONE;

    uint8_t magic[4];
    size_t n = fread(magic, 1, sizeof(magic), f);
    fclose(f);

    if (n < 4) return SOL_SNAPSHOT_COMPRESSION_NONE;

    /* Zstd magic: 0x28 0xB5 0x2F 0xFD */
    if (magic[0] == 0x28 && magic[1] == 0xB5 &&
        magic[2] == 0x2F && magic[3] == 0xFD) {
        return SOL_SNAPSHOT_COMPRESSION_ZSTD;
    }

    /* Gzip magic: 0x1F 0x8B */
    if (magic[0] == 0x1F && magic[1] == 0x8B) {
        return SOL_SNAPSHOT_COMPRESSION_GZIP;
    }

    /* LZ4 magic: 0x04 0x22 0x4D 0x18 */
    if (magic[0] == 0x04 && magic[1] == 0x22 &&
        magic[2] == 0x4D && magic[3] == 0x18) {
        return SOL_SNAPSHOT_COMPRESSION_LZ4;
    }

    /* Bzip2 magic: 'B' 'Z' 'h' */
    if (magic[0] == 'B' && magic[1] == 'Z' && magic[2] == 'h') {
        return SOL_SNAPSHOT_COMPRESSION_BZIP2;
    }

    return SOL_SNAPSHOT_COMPRESSION_NONE;
}

/*
 * Parse octal number from tar header
 */
static uint64_t
parse_octal(const char* str, size_t len) {
    uint64_t val = 0;
    for (size_t i = 0; i < len && str[i] != '\0' && str[i] != ' '; i++) {
        if (str[i] >= '0' && str[i] <= '7') {
            val = (val << 3) | (str[i] - '0');
        }
    }
    return val;
}

/*
 * Verify tar header checksum
 */
static bool
verify_tar_checksum(const tar_header_t* header) {
    uint32_t checksum = parse_octal(header->checksum, 8);

    /* Calculate unsigned checksum (treating checksum field as spaces) */
    uint32_t calc = 0;
    const uint8_t* p = (const uint8_t*)header;
    for (size_t i = 0; i < TAR_BLOCK_SIZE; i++) {
        if (i >= 148 && i < 156) {
            calc += ' ';  /* Checksum field treated as spaces */
        } else {
            calc += p[i];
        }
    }

    return calc == checksum;
}

/*
 * Create directory path recursively
 */
static sol_err_t
mkdir_recursive(const char* path) {
    char tmp[512];
    char* p = NULL;

    if (strlen(path) >= sizeof(tmp)) {
        return SOL_ERR_INVAL;
    }

    snprintf(tmp, sizeof(tmp), "%s", path);

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                return SOL_ERR_IO;
            }
            *p = '/';
        }
    }

    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        return SOL_ERR_IO;
    }

    return SOL_OK;
}

/*
 * Extract tar archive from file handle
 */
static sol_err_t
SOL_UNUSED extract_tar(FILE* f, const char* output_dir, sol_archive_progress_fn progress, void* ctx) {
    tar_header_t header;
    uint64_t bytes_extracted = 0;
    char path[512];

    while (fread(&header, 1, TAR_BLOCK_SIZE, f) == TAR_BLOCK_SIZE) {
        /* Check for end of archive (two zero blocks) */
        if (header.name[0] == '\0') {
            break;
        }

        /* Verify magic */
        if (strncmp(header.magic, TAR_MAGIC, 5) != 0) {
            sol_log_warn("Invalid tar header magic");
            continue;
        }

        /* Verify checksum */
        if (!verify_tar_checksum(&header)) {
            sol_log_warn("Invalid tar checksum for: %s", header.name);
            continue;
        }

        /* Get file size */
        uint64_t size = parse_octal(header.size, 12);

        /* Build full path */
        if (header.prefix[0]) {
            snprintf(path, sizeof(path), "%s/%.155s/%.100s",
                     output_dir, header.prefix, header.name);
        } else {
            snprintf(path, sizeof(path), "%s/%.100s", output_dir, header.name);
        }

        /* Report progress */
        if (progress) {
            progress(ctx, bytes_extracted, 0, header.name);
        }

        /* Handle based on type flag */
        switch (header.typeflag) {
        case '0':   /* Regular file */
        case '\0':  /* Regular file (old format) */
            {
                /* Create parent directory */
                char* dir_end = strrchr(path, '/');
                if (dir_end) {
                    *dir_end = '\0';
                    mkdir_recursive(path);
                    *dir_end = '/';
                }

                /* Extract file */
                FILE* out = fopen(path, "wb");
                if (!out) {
                    sol_log_error("Failed to create: %s", path);
                    /* Skip file content */
                    uint64_t blocks = (size + TAR_BLOCK_SIZE - 1) / TAR_BLOCK_SIZE;
                    fseek(f, blocks * TAR_BLOCK_SIZE, SEEK_CUR);
                    continue;
                }

                /* Copy content */
                uint64_t remaining = size;
                uint8_t buf[4096];
                while (remaining > 0) {
                    size_t to_read = (remaining > sizeof(buf)) ? sizeof(buf) : remaining;
                    size_t n = fread(buf, 1, to_read, f);
                    if (n == 0) break;
                    fwrite(buf, 1, n, out);
                    remaining -= n;
                    bytes_extracted += n;
                }
                fclose(out);

                /* Skip to next block boundary */
                uint64_t blocks_used = (size + TAR_BLOCK_SIZE - 1) / TAR_BLOCK_SIZE;
                uint64_t padding = blocks_used * TAR_BLOCK_SIZE - size;
                if (padding > 0) {
                    fseek(f, padding, SEEK_CUR);
                }

                /* Set file mode */
                uint32_t mode = parse_octal(header.mode, 8);
                mode &= 0777;
                /* Solana snapshot archives often store account AppendVec files with
                 * mode 000, which prevents subsequent reads by the extracting user.
                 * Ensure the owner read bit is always set so snapshots can be
                 * consumed without requiring elevated privileges. */
                mode |= 0600;
                chmod(path, mode);
            }
            break;

        case '5':   /* Directory */
            mkdir_recursive(path);
            break;

        case '1':   /* Hard link */
        case '2':   /* Symlink */
            {
                char target[256];
                snprintf(target, sizeof(target), "%s/%.100s",
                         output_dir, header.linkname);
                if (header.typeflag == '2') {
                    symlink(header.linkname, path);
                } else {
                    link(target, path);
                }
            }
            break;

        default:
            sol_log_debug("Skipping tar entry type '%c': %s",
                          header.typeflag, header.name);
            /* Skip content */
            if (size > 0) {
                uint64_t blocks = (size + TAR_BLOCK_SIZE - 1) / TAR_BLOCK_SIZE;
                fseek(f, blocks * TAR_BLOCK_SIZE, SEEK_CUR);
            }
            break;
        }
    }

    return SOL_OK;
}

#ifdef SOL_HAS_ZSTD
typedef enum {
    TAR_STREAM_STATE_HEADER = 0,
    TAR_STREAM_STATE_FILE_DATA,
    TAR_STREAM_STATE_SKIP,
} tar_stream_state_t;

typedef struct {
    uint8_t* data;
    size_t   cap;
    size_t   off;
    size_t   len;
} stream_buf_t;

typedef struct {
    tar_stream_state_t       state;
    tar_header_t             header;
    uint64_t                 entry_size;
    uint64_t                 file_remaining;
    uint64_t                 skip_remaining;
    FILE*                    out;
    char                     path[512];
    char                     rel_path[512];
    uint64_t                 bytes_extracted;
    sol_archive_progress_fn  progress;
    void*                    progress_ctx;
    const char*              output_dir;
    bool                     done;
    bool                     skip_unmatched;

    /* Optional in-memory streaming for matching files. */
    const char*                stream_prefix;
    sol_archive_stream_file_cb stream_cb;
    sol_archive_stream_chunk_cb stream_chunk_cb;
    void*                      stream_ctx;
    uint64_t                   stream_max_size;
    bool                       stream_active;
    bool                       stream_chunk_mode;
    uint8_t*                   stream_buf;
    size_t                     stream_buf_len;
    size_t                     stream_buf_written;
} tar_stream_t;

static sol_err_t
stream_buf_grow(stream_buf_t* b, size_t min_cap) {
    if (!b) return SOL_ERR_INVAL;
    if (b->cap >= min_cap) return SOL_OK;

    size_t new_cap = b->cap ? b->cap : 64 * 1024;
    while (new_cap < min_cap) new_cap *= 2;
    uint8_t* p = sol_realloc(b->data, new_cap);
    if (!p) return SOL_ERR_NOMEM;
    b->data = p;
    b->cap = new_cap;
    return SOL_OK;
}

static void
stream_buf_compact(stream_buf_t* b) {
    if (!b) return;
    if (b->off == 0) return;
    if (b->off >= b->len) {
        b->off = 0;
        b->len = 0;
        return;
    }

    size_t remain = b->len - b->off;
    memmove(b->data, b->data + b->off, remain);
    b->off = 0;
    b->len = remain;
}

static sol_err_t
stream_buf_append(stream_buf_t* b, const uint8_t* data, size_t len) {
    if (!b || (!data && len)) return SOL_ERR_INVAL;
    if (len == 0) return SOL_OK;

    if (b->off > 0 && (b->off > (b->cap / 2) || b->len == b->off)) {
        stream_buf_compact(b);
    }

    sol_err_t err = stream_buf_grow(b, b->len + len);
    if (err != SOL_OK) return err;

    memcpy(b->data + b->len, data, len);
    b->len += len;
    return SOL_OK;
}

static size_t
stream_buf_avail(const stream_buf_t* b) {
    if (!b) return 0;
    return b->len - b->off;
}

static const uint8_t*
stream_buf_ptr(const stream_buf_t* b) {
    return b ? (b->data + b->off) : NULL;
}

static void
stream_buf_consume(stream_buf_t* b, size_t n) {
    if (!b || n == 0) return;
    size_t avail = stream_buf_avail(b);
    if (n > avail) n = avail;
    b->off += n;
    if (b->off == b->len) {
        b->off = 0;
        b->len = 0;
    }
}

static bool
rel_path_matches_prefix(const char* rel_path, const char* prefix) {
    if (!rel_path || !prefix) return false;
    size_t plen = strlen(prefix);
    if (plen == 0) return false;
    return strncmp(rel_path, prefix, plen) == 0;
}

static sol_err_t
tar_stream_process(tar_stream_t* ts, stream_buf_t* b) {
    if (!ts || !b) return SOL_ERR_INVAL;

    while (!ts->done) {
        size_t avail = stream_buf_avail(b);

        if (ts->state == TAR_STREAM_STATE_HEADER) {
            if (avail < TAR_BLOCK_SIZE) {
                return SOL_OK;
            }

            memcpy(&ts->header, stream_buf_ptr(b), TAR_BLOCK_SIZE);
            stream_buf_consume(b, TAR_BLOCK_SIZE);

            /* Check for end of archive (two zero blocks) */
            if (ts->header.name[0] == '\0') {
                ts->done = true;
                return SOL_OK;
            }

            /* Verify magic */
            if (strncmp(ts->header.magic, TAR_MAGIC, 5) != 0) {
                sol_log_error("Invalid tar header magic");
                return SOL_ERR_SNAPSHOT_CORRUPT;
            }

            /* Verify checksum */
            if (!verify_tar_checksum(&ts->header)) {
                sol_log_error("Invalid tar checksum for: %.100s", ts->header.name);
                return SOL_ERR_SNAPSHOT_CORRUPT;
            }

            /* Get file size */
            uint64_t size = parse_octal(ts->header.size, 12);
            ts->entry_size = size;

            /* Build relative + full paths */
            if (ts->header.prefix[0]) {
                snprintf(ts->rel_path, sizeof(ts->rel_path), "%.155s/%.100s",
                         ts->header.prefix, ts->header.name);
            } else {
                snprintf(ts->rel_path, sizeof(ts->rel_path), "%.100s", ts->header.name);
            }
            snprintf(ts->path, sizeof(ts->path), "%s/%s", ts->output_dir, ts->rel_path);

            /* Handle based on type flag */
            switch (ts->header.typeflag) {
            case '0':   /* Regular file */
            case '\0':  /* Regular file (old format) */
                {
                    ts->stream_active = false;
                    ts->stream_chunk_mode = false;
                    ts->stream_buf = NULL;
                    ts->stream_buf_len = 0;
                    ts->stream_buf_written = 0;

                    bool want_stream_buf = false;
                    bool want_stream_chunk = false;
                    if (ts->stream_prefix && rel_path_matches_prefix(ts->rel_path, ts->stream_prefix)) {
                        if (ts->stream_cb &&
                            (ts->stream_max_size == 0 || size <= ts->stream_max_size)) {
                            want_stream_buf = true;
                        } else if (ts->stream_chunk_cb) {
                            want_stream_chunk = true;
                        }
                    }

                    if (want_stream_chunk) {
                        ts->stream_active = true;
                        ts->stream_chunk_mode = true;
                        ts->out = NULL;
                        ts->file_remaining = size;
                        ts->state = TAR_STREAM_STATE_FILE_DATA;

                        if (size == 0) {
                            sol_err_t cb_err = ts->stream_chunk_cb(ts->stream_ctx,
                                                                  ts->rel_path,
                                                                  NULL,
                                                                  0,
                                                                  0,
                                                                  0,
                                                                  true);
                            if (cb_err != SOL_OK) {
                                return cb_err;
                            }

                            ts->stream_active = false;
                            ts->stream_chunk_mode = false;
                            ts->state = TAR_STREAM_STATE_HEADER;
                        }
                        break;
                    }

                    if (want_stream_buf) {
                        if (size > (uint64_t)SIZE_MAX) {
                            sol_log_error("Archive entry too large to stream: %s", ts->rel_path);
                            return SOL_ERR_OVERFLOW;
                        }

                        if (size > 0) {
                            ts->stream_buf = sol_alloc((size_t)size);
                            if (!ts->stream_buf) {
                                return SOL_ERR_NOMEM;
                            }
                            ts->stream_buf_len = (size_t)size;
                        } else {
                            ts->stream_buf = NULL;
                            ts->stream_buf_len = 0;
                        }
                        ts->stream_buf_written = 0;
                        ts->stream_active = true;
                        ts->stream_chunk_mode = false;
                        ts->out = NULL;
                        ts->file_remaining = size;
                        ts->state = TAR_STREAM_STATE_FILE_DATA;

                        if (size == 0) {
                            sol_err_t cb_err = ts->stream_cb(ts->stream_ctx,
                                                            ts->rel_path,
                                                            ts->stream_buf,
                                                            ts->stream_buf_len);
                            if (cb_err != SOL_OK) {
                                sol_free(ts->stream_buf);
                                ts->stream_buf = NULL;
                                return cb_err;
                            }
                            /* Callback owns buffer (may be NULL for size 0). */
                            ts->stream_buf = NULL;
                            ts->stream_active = false;
                            ts->stream_chunk_mode = false;
                            ts->state = TAR_STREAM_STATE_HEADER;
                        }
                        break;
                    }

                    if (ts->skip_unmatched) {
                        /* Skip non-streamed files instead of writing them to disk. */
                        uint64_t blocks = (size + TAR_BLOCK_SIZE - 1) / TAR_BLOCK_SIZE;
                        ts->skip_remaining = blocks * TAR_BLOCK_SIZE;
                        ts->state = TAR_STREAM_STATE_SKIP;
                        break;
                    }

                    /* Create parent directory */
                    char* dir_end = strrchr(ts->path, '/');
                    if (dir_end) {
                        *dir_end = '\0';
                        sol_err_t derr = mkdir_recursive(ts->path);
                        *dir_end = '/';
                        if (derr != SOL_OK) return derr;
                    }

                    ts->out = fopen(ts->path, "wb");
                    if (!ts->out) {
                        sol_log_error("Failed to create: %s", ts->path);
                        return SOL_ERR_IO;
                    }

                    ts->file_remaining = size;
                    ts->state = TAR_STREAM_STATE_FILE_DATA;

                    if (size == 0) {
                        fclose(ts->out);
                        ts->out = NULL;

                        uint32_t mode = parse_octal(ts->header.mode, 8);
                        mode &= 0777;
                        mode |= 0600;
                        (void)chmod(ts->path, mode);

                        ts->state = TAR_STREAM_STATE_HEADER;
                    }
                }
                break;

            case '5':   /* Directory */
                {
                    if (ts->skip_unmatched) {
                        /* Skip directory creation in stream-only mode. */
                        if (size > 0) {
                            uint64_t blocks = (size + TAR_BLOCK_SIZE - 1) / TAR_BLOCK_SIZE;
                            ts->skip_remaining = blocks * TAR_BLOCK_SIZE;
                            ts->state = TAR_STREAM_STATE_SKIP;
                        }
                        break;
                    }
                    sol_err_t derr = mkdir_recursive(ts->path);
                    if (derr != SOL_OK) return derr;

                    /* Skip any content blocks (should be 0). */
                    if (size > 0) {
                        uint64_t blocks = (size + TAR_BLOCK_SIZE - 1) / TAR_BLOCK_SIZE;
                        ts->skip_remaining = blocks * TAR_BLOCK_SIZE;
                        ts->state = TAR_STREAM_STATE_SKIP;
                    }
                }
                break;

            case '1':   /* Hard link */
            case '2':   /* Symlink */
                {
                    if (ts->skip_unmatched) {
                        /* Skip link creation in stream-only mode. */
                        if (size > 0) {
                            uint64_t blocks = (size + TAR_BLOCK_SIZE - 1) / TAR_BLOCK_SIZE;
                            ts->skip_remaining = blocks * TAR_BLOCK_SIZE;
                            ts->state = TAR_STREAM_STATE_SKIP;
                        }
                        break;
                    }
                    char target[256];
                    snprintf(target, sizeof(target), "%s/%.100s",
                             ts->output_dir, ts->header.linkname);

                    int link_rc = 0;
                    if (ts->header.typeflag == '2') {
                        link_rc = symlink(ts->header.linkname, ts->path);
                    } else {
                        link_rc = link(target, ts->path);
                    }
                    if (link_rc != 0) {
                        sol_log_error("Failed to create link: %s", ts->path);
                        return SOL_ERR_IO;
                    }

                    if (size > 0) {
                        uint64_t blocks = (size + TAR_BLOCK_SIZE - 1) / TAR_BLOCK_SIZE;
                        ts->skip_remaining = blocks * TAR_BLOCK_SIZE;
                        ts->state = TAR_STREAM_STATE_SKIP;
                    }
                }
                break;

            default:
                sol_log_debug("Skipping tar entry type '%c': %.100s",
                              ts->header.typeflag, ts->header.name);
                if (size > 0) {
                    uint64_t blocks = (size + TAR_BLOCK_SIZE - 1) / TAR_BLOCK_SIZE;
                    ts->skip_remaining = blocks * TAR_BLOCK_SIZE;
                    ts->state = TAR_STREAM_STATE_SKIP;
                }
                break;
            }

            continue;
        }

        if (ts->state == TAR_STREAM_STATE_FILE_DATA) {
            if (ts->file_remaining == 0) {
                ts->state = TAR_STREAM_STATE_HEADER;
                continue;
            }
            if (avail == 0) return SOL_OK;

            size_t to_write = avail;
            if (to_write > ts->file_remaining) to_write = (size_t)ts->file_remaining;

            if (ts->stream_active) {
                if (ts->stream_chunk_mode) {
                    uint64_t file_offset = ts->entry_size - ts->file_remaining;
                    bool is_last = (ts->file_remaining == (uint64_t)to_write);
                    sol_err_t cb_err = ts->stream_chunk_cb(ts->stream_ctx,
                                                          ts->rel_path,
                                                          stream_buf_ptr(b),
                                                          to_write,
                                                          ts->entry_size,
                                                          file_offset,
                                                          is_last);
                    if (cb_err != SOL_OK) {
                        return cb_err;
                    }
                } else {
                    if (!ts->stream_buf && to_write > 0) {
                        sol_log_error("Stream buffer missing for: %s", ts->rel_path);
                        return SOL_ERR_IO;
                    }
                    if (ts->stream_buf_written + to_write > ts->stream_buf_len) {
                        sol_log_error("Stream buffer overflow for: %s", ts->rel_path);
                        return SOL_ERR_OVERFLOW;
                    }
                    memcpy(ts->stream_buf + ts->stream_buf_written, stream_buf_ptr(b), to_write);
                    ts->stream_buf_written += to_write;
                }
            } else {
                size_t n = fwrite(stream_buf_ptr(b), 1, to_write, ts->out);
                if (n != to_write) {
                    sol_log_error("Write failed for: %s", ts->path);
                    return SOL_ERR_IO;
                }
            }

            stream_buf_consume(b, to_write);
            ts->file_remaining -= to_write;
            ts->bytes_extracted += to_write;

            if (ts->progress) {
                ts->progress(ts->progress_ctx, ts->bytes_extracted, 0, ts->header.name);
            }

            if (ts->file_remaining == 0) {
                if (ts->stream_active) {
                    if (ts->stream_chunk_mode) {
                        ts->stream_chunk_mode = false;
                    } else {
                        if (ts->stream_buf_written != ts->stream_buf_len) {
                            sol_log_error("Stream size mismatch for: %s", ts->rel_path);
                            sol_free(ts->stream_buf);
                            ts->stream_buf = NULL;
                            return SOL_ERR_TRUNCATED;
                        }

                        sol_err_t cb_err = ts->stream_cb(ts->stream_ctx,
                                                        ts->rel_path,
                                                        ts->stream_buf,
                                                        ts->stream_buf_len);
                        if (cb_err != SOL_OK) {
                            sol_free(ts->stream_buf);
                            ts->stream_buf = NULL;
                            return cb_err;
                        }

                        /* Callback owns the buffer now. */
                        ts->stream_buf = NULL;
                    }
                    ts->stream_active = false;
                } else if (ts->out) {
                    fclose(ts->out);
                    ts->out = NULL;

                    /* Set file mode */
                    uint32_t mode = parse_octal(ts->header.mode, 8);
                    mode &= 0777;
                    mode |= 0600;
                    (void)chmod(ts->path, mode);
                }

                uint64_t blocks_used = (ts->entry_size + TAR_BLOCK_SIZE - 1) / TAR_BLOCK_SIZE;
                uint64_t pad = blocks_used * TAR_BLOCK_SIZE - ts->entry_size;

                if (pad > 0) {
                    ts->skip_remaining = pad;
                    ts->state = TAR_STREAM_STATE_SKIP;
                } else {
                    ts->state = TAR_STREAM_STATE_HEADER;
                }
            }

            continue;
        }

        if (ts->state == TAR_STREAM_STATE_SKIP) {
            if (ts->skip_remaining == 0) {
                ts->state = TAR_STREAM_STATE_HEADER;
                continue;
            }
            if (avail == 0) return SOL_OK;

            size_t consume = avail;
            if (consume > ts->skip_remaining) consume = (size_t)ts->skip_remaining;
            stream_buf_consume(b, consume);
            ts->skip_remaining -= consume;
            if (ts->skip_remaining == 0) {
                ts->state = TAR_STREAM_STATE_HEADER;
            }
            continue;
        }
    }

    return SOL_OK;
}

/*
 * Decompress zstd stream and extract tar
 */
static sol_err_t
extract_zstd_tar(const char* archive_path, const char* output_dir,
                 sol_archive_progress_fn progress, void* ctx,
                 bool skip_unmatched,
                 const char* stream_prefix,
                 sol_archive_stream_file_cb stream_cb,
                 sol_archive_stream_chunk_cb stream_chunk_cb,
                 void* stream_ctx,
                 uint64_t stream_max_size) {
    struct stat st;
    if (stat(archive_path, &st) != 0) return SOL_ERR_NOTFOUND;
    uint64_t total_size = (uint64_t)st.st_size;

    stream_buf_t tar_buf = {0};
    tar_stream_t tar_stream = {0};
    tar_stream.state = TAR_STREAM_STATE_HEADER;
    tar_stream.out = NULL;
    tar_stream.bytes_extracted = 0;
    tar_stream.progress = progress;
    tar_stream.progress_ctx = ctx;
    tar_stream.output_dir = output_dir;
    tar_stream.done = false;
    tar_stream.rel_path[0] = '\0';
    tar_stream.skip_unmatched = skip_unmatched;
    tar_stream.stream_prefix = stream_prefix;
    tar_stream.stream_cb = stream_cb;
    tar_stream.stream_chunk_cb = stream_chunk_cb;
    tar_stream.stream_ctx = stream_ctx;
    tar_stream.stream_max_size = stream_max_size;
    tar_stream.stream_active = false;
    tar_stream.stream_chunk_mode = false;
    tar_stream.stream_buf = NULL;
    tar_stream.stream_buf_len = 0;
    tar_stream.stream_buf_written = 0;

    sol_err_t ret = SOL_OK;

    bool use_pzstd = snapshot_has_pzstd() && snapshot_pzstd_enabled_for_size(total_size);
    bool pzstd_stalled = false;
    if (use_pzstd) {
        int pipefd[2];
        if (pipe(pipefd) != 0) {
            use_pzstd = false;
        } else {
            sol_log_info("Snapshot archive: using zstd CLI (compressed=%lu bytes): %s",
                         (unsigned long)total_size,
                         archive_path);

            pid_t pid = fork();
            if (pid < 0) {
                close(pipefd[0]);
                close(pipefd[1]);
                use_pzstd = false;
            } else if (pid == 0) {
                (void)dup2(pipefd[1], STDOUT_FILENO);
                close(pipefd[0]);
                close(pipefd[1]);

                int devnull = open("/dev/null", O_WRONLY);
                if (devnull >= 0) {
                    (void)dup2(devnull, STDERR_FILENO);
                    close(devnull);
                }

                const char* argv[16];
                size_t argc = 0;
                argv[argc++] = "zstd";
                argv[argc++] = "-d";
                argv[argc++] = "-c";
                argv[argc++] = "-q";
                argv[argc++] = archive_path;
                argv[argc++] = NULL;
                execvp_const_argv(argv);
                _exit(127);
            }

            close(pipefd[1]);

            const size_t buf_sz = 4u * 1024u * 1024u;
            uint8_t* buf = sol_alloc(buf_sz);
            if (!buf) {
                (void)kill(pid, SIGTERM);
                close(pipefd[0]);
                (void)waitpid(pid, NULL, 0);
                ret = SOL_ERR_NOMEM;
            } else {
                /* Use poll() to detect pzstd hangs: if no data arrives for
                 * 30 seconds, assume pzstd is stuck and fall through to
                 * libzstd path for a clean retry. */
                struct pollfd pfd = { .fd = pipefd[0], .events = POLLIN };
                int stall_count = 0;
                while (1) {
                    int pr = poll(&pfd, 1, 10000 /* 10s timeout */);
                    if (pr < 0) {
                        if (errno == EINTR) continue;
                        ret = SOL_ERR_IO;
                        break;
                    }
                    if (pr == 0) {
                        /* Timeout - no data from pzstd for 10s */
                        stall_count++;
                        if (stall_count >= 3) {
                            sol_log_warn("zstd stalled for 30s, killing");
                            pzstd_stalled = true;
                            break;
                        }
                        continue;
                    }
                    stall_count = 0;

                    ssize_t n = read(pipefd[0], buf, buf_sz);
                    if (n < 0) {
                        if (errno == EINTR) continue;
                        ret = SOL_ERR_IO;
                        break;
                    }
                    if (n == 0) break;

                    if (tar_stream.done) {
                        break;
                    }

                    sol_err_t aerr = stream_buf_append(&tar_buf, buf, (size_t)n);
                    if (aerr != SOL_OK) {
                        ret = aerr;
                        break;
                    }

                    sol_err_t terr = tar_stream_process(&tar_stream, &tar_buf);
                    if (terr != SOL_OK) {
                        ret = terr;
                        break;
                    }

                    if (tar_stream.done) {
                        break;
                    }
                }

                close(pipefd[0]);
                sol_free(buf);

                /* Kill pzstd if tar was fully consumed (it may still be running
                 * and can hang on internal thread synchronization).  If we broke
                 * out of the loop due to an error, also kill it. */
                (void)kill(pid, SIGTERM);
                int status = 0;
                while (waitpid(pid, &status, 0) < 0) {
                    if (errno == EINTR) continue;
                    break;
                }

                if (ret == SOL_OK && !tar_stream.done && !pzstd_stalled) {
                    ret = SOL_ERR_SNAPSHOT_CORRUPT;
                }
            }

            if (pzstd_stalled) {
                /* pzstd stalled - fall through to libzstd path.
                 * Need to clean up partial state first. */
                sol_log_warn("zstd CLI failed, retrying with libzstd");
                use_pzstd = false;
                ret = SOL_OK;
                /* Close any partially-written file */
                if (tar_stream.out) {
                    fclose(tar_stream.out);
                    tar_stream.out = NULL;
                }
                /* Reset tar stream state for retry */
                tar_stream.state = TAR_STREAM_STATE_HEADER;
                tar_stream.done = false;
                tar_stream.bytes_extracted = 0;
                tar_stream.stream_active = false;
                tar_buf.off = 0;
                tar_buf.len = 0;
            } else if (ret != SOL_OK || !tar_stream.done) {
                if (ret == SOL_OK) ret = SOL_ERR_SNAPSHOT_CORRUPT;
            }
        }
    }

    if (!use_pzstd) {
        FILE* in = fopen(archive_path, "rb");
        if (!in) {
            ret = SOL_ERR_NOTFOUND;
            goto cleanup;
        }

        /* Create decompression context */
        ZSTD_DCtx* dctx = ZSTD_createDCtx();
        if (!dctx) {
            fclose(in);
            ret = SOL_ERR_NOMEM;
            goto cleanup;
        }

        /* Allocate buffers */
        size_t in_buf_size = ZSTD_DStreamInSize();
        size_t out_buf_size = ZSTD_DStreamOutSize();
        /* ZSTD_*Stream*Size are conservative (often ~128KB) which leads to a
         * very high number of tar-parse callbacks/allocations when streaming
         * large snapshot archives. Use larger buffers in the fallback
         * single-threaded path to reduce overhead. */
        const size_t min_in_buf_size = 1u * 1024u * 1024u;
        const size_t min_out_buf_size = 4u * 1024u * 1024u;
        if (in_buf_size < min_in_buf_size) in_buf_size = min_in_buf_size;
        if (out_buf_size < min_out_buf_size) out_buf_size = min_out_buf_size;
        uint8_t* in_buf = sol_alloc(in_buf_size);
        uint8_t* out_buf = sol_alloc(out_buf_size);

        if (!in_buf || !out_buf) {
            sol_free(in_buf);
            sol_free(out_buf);
            ZSTD_freeDCtx(dctx);
            fclose(in);
            ret = SOL_ERR_NOMEM;
            goto cleanup;
        }

        /* Decompress + extract in a single pass (no huge temporary tar file). */
        uint64_t bytes_read = 0;
        size_t last_ret = 1;

        while (1) {
            size_t n = fread(in_buf, 1, in_buf_size, in);
            if (n == 0) break;

            bytes_read += n;

            ZSTD_inBuffer input = { in_buf, n, 0 };
            while (input.pos < input.size) {
                ZSTD_outBuffer output = { out_buf, out_buf_size, 0 };
                last_ret = ZSTD_decompressStream(dctx, &output, &input);

                if (ZSTD_isError(last_ret)) {
                    sol_log_error("Zstd decompress error: %s", ZSTD_getErrorName(last_ret));
                    ret = SOL_ERR_SNAPSHOT_CORRUPT;
                    goto zstd_cleanup;
                }

                if (output.pos > 0 && !tar_stream.done) {
                    sol_err_t aerr = stream_buf_append(&tar_buf, out_buf, output.pos);
                    if (aerr != SOL_OK) {
                        ret = aerr;
                        goto zstd_cleanup;
                    }

                    sol_err_t terr = tar_stream_process(&tar_stream, &tar_buf);
                    if (terr != SOL_OK) {
                        ret = terr;
                        goto zstd_cleanup;
                    }

                    if (tar_stream.done) {
                        /* We've reached the end of the tar archive; keep draining zstd. */
                        tar_buf.off = 0;
                        tar_buf.len = 0;
                    }
                }
            }

            /* Report decompression progress (compressed bytes read). */
            if (progress) {
                progress(ctx, bytes_read, total_size, "decompressing");
            }
        }

        if (last_ret != 0 || !tar_stream.done) {
            sol_log_error("Snapshot archive ended unexpectedly during zstd/tar decode");
            ret = SOL_ERR_SNAPSHOT_CORRUPT;
        }

zstd_cleanup:
        sol_free(in_buf);
        sol_free(out_buf);
        ZSTD_freeDCtx(dctx);
        fclose(in);
    }

cleanup:
    if (tar_stream.out) {
        fclose(tar_stream.out);
        tar_stream.out = NULL;
    }
    if (tar_stream.stream_buf) {
        sol_free(tar_stream.stream_buf);
        tar_stream.stream_buf = NULL;
    }

    sol_free(tar_buf.data);

    return ret;
}
#endif /* SOL_HAS_ZSTD */

/*
 * Extract using shell command (fallback)
 */
static sol_err_t
extract_shell(const char* archive_path, const char* output_dir,
              sol_snapshot_compression_t compression) {
    char cmd[1024];

    switch (compression) {
    case SOL_SNAPSHOT_COMPRESSION_ZSTD:
        snprintf(cmd, sizeof(cmd),
                 "zstd -d -c '%s' | tar --no-same-owner --no-same-permissions -xf - -C '%s'",
                 archive_path, output_dir);
        break;

    case SOL_SNAPSHOT_COMPRESSION_GZIP:
        snprintf(cmd, sizeof(cmd),
                 "tar --no-same-owner --no-same-permissions -xzf '%s' -C '%s'",
                 archive_path, output_dir);
        break;

    case SOL_SNAPSHOT_COMPRESSION_BZIP2:
        snprintf(cmd, sizeof(cmd),
                 "tar --no-same-owner --no-same-permissions -xjf '%s' -C '%s'",
                 archive_path, output_dir);
        break;

    case SOL_SNAPSHOT_COMPRESSION_LZ4:
        snprintf(cmd, sizeof(cmd),
                 "lz4 -d '%s' - | tar --no-same-owner --no-same-permissions -xf - -C '%s'",
                 archive_path, output_dir);
        break;

    case SOL_SNAPSHOT_COMPRESSION_NONE:
        snprintf(cmd, sizeof(cmd),
                 "tar --no-same-owner --no-same-permissions -xf '%s' -C '%s'",
                 archive_path, output_dir);
        break;

    default:
        return SOL_ERR_INVAL;
    }

    sol_log_info("Extracting with: %s", cmd);

    int ret = system(cmd);
    if (ret != 0) {
        sol_log_error("Extraction failed with code %d", ret);
        return SOL_ERR_IO;
    }

    return SOL_OK;
}

/*
 * Extract snapshot archive
 */
sol_err_t
sol_snapshot_archive_extract(const char* archive_path,
                              const sol_archive_extract_opts_t* opts) {
    if (!archive_path) return SOL_ERR_INVAL;

    sol_archive_extract_opts_t options = SOL_ARCHIVE_EXTRACT_OPTS_DEFAULT;
    if (opts) options = *opts;

    /* Determine output directory */
    char output_dir[512];
    if (options.output_dir) {
        strncpy(output_dir, options.output_dir, sizeof(output_dir) - 1);
    } else {
        /* Extract to same directory as archive */
        strncpy(output_dir, archive_path, sizeof(output_dir) - 1);
        char* last_slash = strrchr(output_dir, '/');
        if (last_slash) {
            *last_slash = '\0';
        } else {
            strcpy(output_dir, ".");
        }
    }

    /* Create output directory */
    sol_err_t err = mkdir_recursive(output_dir);
    if (err != SOL_OK) {
        sol_log_error("Failed to create output directory: %s", output_dir);
        return err;
    }

    /* Detect compression */
    sol_snapshot_compression_t compression =
        sol_snapshot_archive_detect_compression(archive_path);

    sol_log_info("Extracting snapshot: %s (compression: %d)",
                 archive_path, compression);

#ifdef SOL_HAS_ZSTD
    if (compression == SOL_SNAPSHOT_COMPRESSION_ZSTD) {
        return extract_zstd_tar(archive_path, output_dir,
                                options.progress_callback, options.progress_ctx,
                                options.skip_unmatched,
                                options.stream_prefix,
                                options.stream_file_callback,
                                options.stream_chunk_callback,
                                options.stream_file_ctx,
                                options.stream_max_file_size);
    }
#endif

    if (options.skip_unmatched) {
        sol_log_error("Archive stream-only extraction requires zstd support: %s", archive_path);
        return SOL_ERR_UNSUPPORTED;
    }

    /* Fall back to shell commands */
    return extract_shell(archive_path, output_dir, compression);
}

/*
 * Check if archive can be extracted
 */
sol_err_t
sol_snapshot_archive_check(const char* archive_path) {
    if (!archive_path) return SOL_ERR_INVAL;

    /* Check file exists */
    struct stat st;
    if (stat(archive_path, &st) != 0) {
        return SOL_ERR_NOTFOUND;
    }

    /* Check compression type */
    sol_snapshot_compression_t compression =
        sol_snapshot_archive_detect_compression(archive_path);

    switch (compression) {
    case SOL_SNAPSHOT_COMPRESSION_NONE:
    case SOL_SNAPSHOT_COMPRESSION_GZIP:
    case SOL_SNAPSHOT_COMPRESSION_BZIP2:
        break;

    case SOL_SNAPSHOT_COMPRESSION_ZSTD:
        if (!sol_snapshot_has_zstd()) {
            sol_log_error("Zstd support not available");
            return SOL_ERR_UNSUPPORTED;
        }
        break;

    case SOL_SNAPSHOT_COMPRESSION_LZ4:
        if (!sol_snapshot_has_lz4()) {
            sol_log_error("LZ4 support not available");
            return SOL_ERR_UNSUPPORTED;
        }
        break;

    default:
        break;
    }

    return SOL_OK;
}

/*
 * Get uncompressed size
 */
sol_err_t
sol_snapshot_archive_get_size(const char* archive_path, uint64_t* out_size) {
    if (!archive_path || !out_size) return SOL_ERR_INVAL;

    *out_size = 0;

    sol_snapshot_compression_t compression =
        sol_snapshot_archive_detect_compression(archive_path);

#ifdef SOL_HAS_ZSTD
    if (compression == SOL_SNAPSHOT_COMPRESSION_ZSTD) {
        FILE* f = fopen(archive_path, "rb");
        if (!f) return SOL_ERR_NOTFOUND;

        /* Read header to get frame content size */
        uint8_t header[18];
        size_t n = fread(header, 1, sizeof(header), f);
        fclose(f);

        if (n >= 18) {
            unsigned long long size = ZSTD_getFrameContentSize(header, n);
            if (size != ZSTD_CONTENTSIZE_UNKNOWN &&
                size != ZSTD_CONTENTSIZE_ERROR) {
                *out_size = size;
                return SOL_OK;
            }
        }
    }
#endif

    /* Fall back to file size estimate */
    struct stat st;
    if (stat(archive_path, &st) != 0) {
        return SOL_ERR_NOTFOUND;
    }

    /* Estimate: compressed size * 3 for zstd, * 10 for others */
    if (compression == SOL_SNAPSHOT_COMPRESSION_ZSTD) {
        *out_size = st.st_size * 3;
    } else if (compression == SOL_SNAPSHOT_COMPRESSION_GZIP ||
               compression == SOL_SNAPSHOT_COMPRESSION_BZIP2 ||
               compression == SOL_SNAPSHOT_COMPRESSION_LZ4) {
        *out_size = st.st_size * 5;
    } else {
        *out_size = st.st_size;
    }

    return SOL_OK;
}

/*
 * Create temporary directory
 */
sol_err_t
sol_snapshot_archive_mktemp(const char* base_dir, const char* prefix,
                             char* out_path, size_t max_len) {
    if (!out_path || max_len == 0) return SOL_ERR_INVAL;

    const char* base = base_dir ? base_dir : "/tmp";
    const char* pfx = prefix ? prefix : "snapshot";

    /* Best-effort cleanup: remove stale extraction directories from previously
     * interrupted snapshot loads. These can consume 100s of GB if left around.
     * We only delete directories older than a conservative threshold, and we
     * skip dirs owned by a still-running PID marker. */
    uint64_t max_age_secs = 24ULL * 60ULL * 60ULL;
    const char* env_age = getenv("SOL_SNAPSHOT_EXTRACT_STALE_MAX_AGE_SECS");
    if (env_age && env_age[0] != '\0') {
        char* end = NULL;
        errno = 0;
        unsigned long long v = strtoull(env_age, &end, 10);
        if (errno == 0 && end && end != env_age) {
            while (*end == ' ' || *end == '\t') end++;
            if (*end == '\0') max_age_secs = (uint64_t)v;
        }
    }

    const char* env_disable = getenv("SOL_SNAPSHOT_EXTRACT_CLEANUP");
    bool cleanup_enabled = true;
    if (env_disable && env_disable[0] != '\0') {
        if (strcmp(env_disable, "0") == 0 ||
            strcasecmp(env_disable, "false") == 0 ||
            strcasecmp(env_disable, "no") == 0) {
            cleanup_enabled = false;
        }
    }

    const char* marker_name = ".solana-c-tmpdir";

    if (cleanup_enabled && max_age_secs > 0) {
        time_t now = time(NULL);
        if (now > 0) {
            DIR* dir = opendir(base);
            if (dir) {
                struct dirent* ent;
                size_t pfx_len = strlen(pfx);
                while ((ent = readdir(dir)) != NULL) {
                    if (ent->d_name[0] == '.') continue;
                    if (strncmp(ent->d_name, pfx, pfx_len) != 0) continue;
                    if (ent->d_name[pfx_len] != '_') continue;

                    char full_path[PATH_MAX];
                    int n = snprintf(full_path, sizeof(full_path), "%s/%s", base, ent->d_name);
                    if (n < 0 || (size_t)n >= sizeof(full_path)) continue;

                    struct stat st;
                    if (stat(full_path, &st) != 0 || !S_ISDIR(st.st_mode)) continue;

                    bool have_marker_pid = false;
                    bool owned_by_live_pid = false;
                    char marker_path[PATH_MAX];
                    n = snprintf(marker_path, sizeof(marker_path), "%s/%s", full_path, marker_name);
                    if (n > 0 && (size_t)n < sizeof(marker_path)) {
                        int fd = open(marker_path, O_RDONLY);
                        if (fd >= 0) {
                            char buf[64];
                            ssize_t r = read(fd, buf, sizeof(buf) - 1);
                            close(fd);
                            if (r > 0) {
                                buf[r] = '\0';
                                char* p = buf;
                                while (*p && (*p < '0' || *p > '9')) p++;
                                char* end = NULL;
                                long pid = strtol(p, &end, 10);
                                if (end && end != p && pid > 0 && pid <= INT_MAX) {
                                    have_marker_pid = true;
                                    errno = 0;
                                    if (kill((pid_t)pid, 0) == 0 || errno == EPERM) {
                                        owned_by_live_pid = true;
                                    }
                                }
                            }
                        }
                    }

                    if (owned_by_live_pid) continue;
                    if (!have_marker_pid && (uint64_t)(now - st.st_mtime) < max_age_secs) continue;

                    sol_log_warn("Removing stale snapshot extraction dir: %s", full_path);
                    (void)sol_snapshot_archive_rmdir(full_path);
                }
                closedir(dir);
            }
        }
    }

    snprintf(out_path, max_len, "%s/%s_XXXXXX", base, pfx);

    char* result = mkdtemp(out_path);
    if (!result) {
        return SOL_ERR_IO;
    }

    /* Mark ownership so future cleanup can avoid in-use temp dirs. */
    char marker_path[PATH_MAX];
    int n = snprintf(marker_path, sizeof(marker_path), "%s/%s", out_path, marker_name);
    if (n > 0 && (size_t)n < sizeof(marker_path)) {
        int fd = open(marker_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) {
            (void)dprintf(fd, "%ld\n", (long)getpid());
            close(fd);
        }
    }

    return SOL_OK;
}

/*
 * Remove directory recursively
 */
sol_err_t
sol_snapshot_archive_rmdir(const char* path) {
    if (!path) return SOL_ERR_INVAL;

    DIR* dir = opendir(path);
    if (!dir) return SOL_ERR_NOTFOUND;

    struct dirent* entry;
    char full_path[512];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

        struct stat st;
        if (stat(full_path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                sol_snapshot_archive_rmdir(full_path);
            } else {
                unlink(full_path);
            }
        }
    }

    closedir(dir);
    rmdir(path);

    return SOL_OK;
}
