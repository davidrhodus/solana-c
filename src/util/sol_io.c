/*
 * sol_io.c - Pluggable disk IO (POSIX + io_uring backends)
 */

#include "sol_io_impl.h"
#include "sol_alloc.h"

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

static sol_err_t
posix_preadv_all(int fd,
                 const struct iovec* iov,
                 int iovcnt,
                 uint64_t offset) {
    if (fd < 0) return SOL_ERR_INVAL;
    if (!iov || iovcnt <= 0) return SOL_ERR_INVAL;
    if (offset > (uint64_t)LLONG_MAX) return SOL_ERR_TOO_LARGE;

    enum { STACK_IOV_MAX = 8 };
    struct iovec stack_iov[STACK_IOV_MAX];
    struct iovec* v = stack_iov;
    if (iovcnt > (int)STACK_IOV_MAX) {
        v = sol_alloc((size_t)iovcnt * sizeof(*v));
        if (!v) return SOL_ERR_NOMEM;
    }
    memcpy(v, iov, (size_t)iovcnt * sizeof(*v));

    off_t off = (off_t)offset;
    int cur_cnt = iovcnt;
    struct iovec* cur = v;

    while (cur_cnt > 0) {
        ssize_t n = preadv(fd, cur, cur_cnt, off);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (v != stack_iov) sol_free(v);
            return SOL_ERR_IO;
        }
        if (n == 0) {
            if (v != stack_iov) sol_free(v);
            return SOL_ERR_TRUNCATED;
        }

        off += n;

        size_t consumed = (size_t)n;
        while (cur_cnt > 0 && consumed > 0) {
            if (consumed >= cur[0].iov_len) {
                consumed -= cur[0].iov_len;
                cur++;
                cur_cnt--;
                continue;
            }
            cur[0].iov_base = (uint8_t*)cur[0].iov_base + consumed;
            cur[0].iov_len -= consumed;
            consumed = 0;
        }
    }

    if (v != stack_iov) sol_free(v);
    return SOL_OK;
}

static sol_err_t
posix_pwritev_all(int fd,
                  const struct iovec* iov,
                  int iovcnt,
                  uint64_t offset) {
    if (fd < 0) return SOL_ERR_INVAL;
    if (!iov || iovcnt <= 0) return SOL_ERR_INVAL;
    if (offset > (uint64_t)LLONG_MAX) return SOL_ERR_TOO_LARGE;

    enum { STACK_IOV_MAX = 8 };
    struct iovec stack_iov[STACK_IOV_MAX];
    struct iovec* v = stack_iov;
    if (iovcnt > (int)STACK_IOV_MAX) {
        v = sol_alloc((size_t)iovcnt * sizeof(*v));
        if (!v) return SOL_ERR_NOMEM;
    }
    memcpy(v, iov, (size_t)iovcnt * sizeof(*v));

    off_t off = (off_t)offset;
    int cur_cnt = iovcnt;
    struct iovec* cur = v;

    while (cur_cnt > 0) {
        ssize_t n = pwritev(fd, cur, cur_cnt, off);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (v != stack_iov) sol_free(v);
            return SOL_ERR_IO;
        }
        if (n == 0) {
            if (v != stack_iov) sol_free(v);
            return SOL_ERR_IO;
        }

        off += n;

        size_t consumed = (size_t)n;
        while (cur_cnt > 0 && consumed > 0) {
            if (consumed >= cur[0].iov_len) {
                consumed -= cur[0].iov_len;
                cur++;
                cur_cnt--;
                continue;
            }
            cur[0].iov_base = (uint8_t*)cur[0].iov_base + consumed;
            cur[0].iov_len -= consumed;
            consumed = 0;
        }
    }

    if (v != stack_iov) sol_free(v);
    return SOL_OK;
}

/* io_uring backend (implemented in sol_io_uring.c) */
sol_err_t sol_io_uring_preadv_all(sol_io_ctx_t* ctx,
                                 int fd,
                                 const struct iovec* iov,
                                 int iovcnt,
                                 uint64_t offset);

sol_err_t sol_io_uring_pwritev_all(sol_io_ctx_t* ctx,
                                  int fd,
                                  const struct iovec* iov,
                                  int iovcnt,
                                  uint64_t offset);

sol_err_t sol_io_uring_ctx_init(sol_io_ctx_t* ctx);
void      sol_io_uring_ctx_destroy(sol_io_ctx_t* ctx);

sol_io_ctx_t*
sol_io_ctx_new(const sol_io_options_t* opts) {
    sol_io_options_t o = SOL_IO_OPTIONS_DEFAULT;
    if (opts) o = *opts;

    if (o.queue_depth == 0) o.queue_depth = 1;

    sol_io_ctx_t* ctx = sol_calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    ctx->opts = o;

#ifdef __linux__
    if (ctx->opts.backend == SOL_IO_BACKEND_URING) {
        sol_err_t err = sol_io_uring_ctx_init(ctx);
        if (err != SOL_OK) {
            /* Keep the process running even if io_uring init fails. */
            ctx->opts.backend = SOL_IO_BACKEND_POSIX;
        }
    }
#endif
    return ctx;
}

void
sol_io_ctx_destroy(sol_io_ctx_t* ctx) {
#ifdef __linux__
    sol_io_uring_ctx_destroy(ctx);
#endif
    sol_free(ctx);
}

sol_io_backend_t
sol_io_ctx_backend(const sol_io_ctx_t* ctx) {
    if (!ctx) return SOL_IO_BACKEND_POSIX;
    return ctx->opts.backend;
}

const char*
sol_io_backend_str(sol_io_backend_t backend) {
    switch (backend) {
    case SOL_IO_BACKEND_POSIX: return "posix";
    case SOL_IO_BACKEND_URING: return "uring";
    default: return "unknown";
    }
}

sol_err_t
sol_io_pread_all(sol_io_ctx_t* ctx,
                 int fd,
                 void* buf,
                 size_t len,
                 uint64_t offset) {
    if (len == 0) return SOL_OK;
    if (!buf && len) return SOL_ERR_INVAL;
    struct iovec iov = { .iov_base = buf, .iov_len = len };
    return sol_io_preadv_all(ctx, fd, &iov, 1, offset);
}

sol_err_t
sol_io_pwrite_all(sol_io_ctx_t* ctx,
                  int fd,
                  const void* buf,
                  size_t len,
                  uint64_t offset) {
    if (len == 0) return SOL_OK;
    if (!buf && len) return SOL_ERR_INVAL;
    /* Avoid -Wcast-qual: iovec's iov_base is non-const, but write buffers are. */
    struct iovec iov = { .iov_base = (void*)(uintptr_t)buf, .iov_len = len };
    return sol_io_pwritev_all(ctx, fd, &iov, 1, offset);
}

sol_err_t
sol_io_preadv_all(sol_io_ctx_t* ctx,
                  int fd,
                  const struct iovec* iov,
                  int iovcnt,
                  uint64_t offset) {
    bool any_bytes = false;
    if (iov && iovcnt > 0) {
        for (int i = 0; i < iovcnt; i++) {
            if (iov[i].iov_len != 0) {
                any_bytes = true;
                break;
            }
        }
    }
    if (!any_bytes) return SOL_OK;

    sol_io_backend_t backend = sol_io_ctx_backend(ctx);
    if (backend == SOL_IO_BACKEND_URING) {
        sol_err_t err = sol_io_uring_preadv_all(ctx, fd, iov, iovcnt, offset);
        if (err != SOL_ERR_UNSUPPORTED) return err;
        /* Fall back if io_uring isn't available. */
    }
    return posix_preadv_all(fd, iov, iovcnt, offset);
}

sol_err_t
sol_io_pwritev_all(sol_io_ctx_t* ctx,
                   int fd,
                   const struct iovec* iov,
                   int iovcnt,
                   uint64_t offset) {
    bool any_bytes = false;
    if (iov && iovcnt > 0) {
        for (int i = 0; i < iovcnt; i++) {
            if (iov[i].iov_len != 0) {
                any_bytes = true;
                break;
            }
        }
    }
    if (!any_bytes) return SOL_OK;

    sol_io_backend_t backend = sol_io_ctx_backend(ctx);
    if (backend == SOL_IO_BACKEND_URING) {
        sol_err_t err = sol_io_uring_pwritev_all(ctx, fd, iov, iovcnt, offset);
        if (err != SOL_ERR_UNSUPPORTED) return err;
        /* Fall back if io_uring isn't available. */
    }
    return posix_pwritev_all(fd, iov, iovcnt, offset);
}
