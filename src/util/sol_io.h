#ifndef SOL_IO_H
#define SOL_IO_H

#include "sol_err.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/uio.h>

typedef enum {
    SOL_IO_BACKEND_POSIX = 0,
    SOL_IO_BACKEND_URING = 1,
} sol_io_backend_t;

typedef struct {
    sol_io_backend_t backend;
    uint32_t         queue_depth;
    bool             sqpoll;
} sol_io_options_t;

#ifdef __linux__
#define SOL_IO_OPTIONS_DEFAULT {           \
    .backend = SOL_IO_BACKEND_URING,       \
    .queue_depth = 256,                    \
    .sqpoll = false,                       \
}
#else
#define SOL_IO_OPTIONS_DEFAULT {           \
    .backend = SOL_IO_BACKEND_POSIX,       \
    .queue_depth = 256,                    \
    .sqpoll = false,                       \
}
#endif

typedef struct sol_io_ctx sol_io_ctx_t;

sol_io_ctx_t* sol_io_ctx_new(const sol_io_options_t* opts);
void          sol_io_ctx_destroy(sol_io_ctx_t* ctx);

sol_io_backend_t sol_io_ctx_backend(const sol_io_ctx_t* ctx);
const char*      sol_io_backend_str(sol_io_backend_t backend);

sol_err_t sol_io_pread_all(sol_io_ctx_t* ctx,
                           int fd,
                           void* buf,
                           size_t len,
                           uint64_t offset);

sol_err_t sol_io_pwrite_all(sol_io_ctx_t* ctx,
                            int fd,
                            const void* buf,
                            size_t len,
                            uint64_t offset);

sol_err_t sol_io_preadv_all(sol_io_ctx_t* ctx,
                            int fd,
                            const struct iovec* iov,
                            int iovcnt,
                            uint64_t offset);

sol_err_t sol_io_pwritev_all(sol_io_ctx_t* ctx,
                             int fd,
                             const struct iovec* iov,
                             int iovcnt,
                             uint64_t offset);

#endif /* SOL_IO_H */
