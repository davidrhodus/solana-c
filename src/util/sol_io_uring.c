/*
 * sol_io_uring.c - io_uring backend (Linux)
 */

#include "sol_io_impl.h"
#include "sol_alloc.h"

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __linux__

#include <linux/io_uring.h>
#include <sys/mman.h>
#include <sys/syscall.h>

typedef struct {
    sol_io_uring_t uring;
    bool           sqpoll;
} sol_io_uring_thread_ctx_t;

static void
uring_tls_destructor(void* p);

static sol_io_uring_thread_ctx_t*
uring_thread_ctx_get_or_init(sol_io_ctx_t* ctx);

static int
io_uring_setup_syscall(unsigned entries, struct io_uring_params* p) {
    return (int)syscall(__NR_io_uring_setup, entries, p);
}

static int
io_uring_enter_syscall(int fd, unsigned to_submit, unsigned min_complete, unsigned flags) {
    return (int)syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags, NULL, 0);
}

static void*
mmap_ring(int fd, size_t len, off_t off) {
    return mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, off);
}

static void
uring_ring_close(sol_io_uring_t* u) {
    if (!u) return;

    if (u->sqes_ptr && u->sqes_sz) {
        (void)munmap(u->sqes_ptr, u->sqes_sz);
        u->sqes_ptr = NULL;
        u->sqes_sz = 0;
    }

    if (u->sq_ring_ptr && u->sq_ring_sz) {
        void* ptr = u->sq_ring_ptr;
        size_t sz = u->sq_ring_sz;

        /* If SQ/CQ share the same mapping, unmap once. */
        if (u->cq_ring_ptr == u->sq_ring_ptr) {
            if (u->cq_ring_sz > sz) sz = u->cq_ring_sz;
            u->cq_ring_ptr = NULL;
            u->cq_ring_sz = 0;
        } else if (u->cq_ring_ptr && u->cq_ring_sz) {
            (void)munmap(u->cq_ring_ptr, u->cq_ring_sz);
            u->cq_ring_ptr = NULL;
            u->cq_ring_sz = 0;
        }

        (void)munmap(ptr, sz);
        u->sq_ring_ptr = NULL;
        u->sq_ring_sz = 0;
    } else if (u->cq_ring_ptr && u->cq_ring_sz) {
        (void)munmap(u->cq_ring_ptr, u->cq_ring_sz);
        u->cq_ring_ptr = NULL;
        u->cq_ring_sz = 0;
    }

    if (u->ring_fd >= 0) {
        close(u->ring_fd);
        u->ring_fd = -1;
    }
    memset(u, 0, sizeof(*u));
    u->ring_fd = -1;
}

static sol_err_t
uring_ring_init(sol_io_uring_t* u,
                uint32_t queue_depth,
                bool sqpoll,
                int* out_errno) {
    if (!u) return SOL_ERR_INVAL;
    if (out_errno) *out_errno = 0;

    memset(u, 0, sizeof(*u));
    u->ring_fd = -1;

    struct io_uring_params p;
    memset(&p, 0, sizeof(p));

    if (sqpoll) {
        p.flags |= IORING_SETUP_SQPOLL;
        p.sq_thread_idle = 2000; /* ms */
    }

    unsigned entries = queue_depth;
    if (entries < 2) entries = 2;

    int ring_fd = io_uring_setup_syscall(entries, &p);
    if (ring_fd < 0) {
        if (out_errno) *out_errno = errno;
        return SOL_ERR_UNSUPPORTED;
    }

    u->ring_fd = ring_fd;

    size_t sq_ring_sz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
    size_t cq_ring_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    size_t sqes_sz = p.sq_entries * sizeof(struct io_uring_sqe);

    void* sq_ring_ptr = NULL;
    void* cq_ring_ptr = NULL;

    if (p.features & IORING_FEAT_SINGLE_MMAP) {
        size_t ring_sz = sq_ring_sz > cq_ring_sz ? sq_ring_sz : cq_ring_sz;
        sq_ring_ptr = mmap_ring(ring_fd, ring_sz, IORING_OFF_SQ_RING);
        if (sq_ring_ptr == MAP_FAILED) {
            uring_ring_close(u);
            return SOL_ERR_IO;
        }
        cq_ring_ptr = sq_ring_ptr;
        u->sq_ring_sz = ring_sz;
        u->cq_ring_sz = ring_sz;
    } else {
        sq_ring_ptr = mmap_ring(ring_fd, sq_ring_sz, IORING_OFF_SQ_RING);
        if (sq_ring_ptr == MAP_FAILED) {
            uring_ring_close(u);
            return SOL_ERR_IO;
        }
        cq_ring_ptr = mmap_ring(ring_fd, cq_ring_sz, IORING_OFF_CQ_RING);
        if (cq_ring_ptr == MAP_FAILED) {
            uring_ring_close(u);
            return SOL_ERR_IO;
        }
        u->sq_ring_sz = sq_ring_sz;
        u->cq_ring_sz = cq_ring_sz;
    }

    void* sqes_ptr = mmap_ring(ring_fd, sqes_sz, IORING_OFF_SQES);
    if (sqes_ptr == MAP_FAILED) {
        uring_ring_close(u);
        return SOL_ERR_IO;
    }

    u->sq_ring_ptr = sq_ring_ptr;
    u->cq_ring_ptr = cq_ring_ptr;
    u->sqes_ptr = sqes_ptr;
    u->sqes_sz = sqes_sz;

    u->sq_head = (unsigned*)((uint8_t*)sq_ring_ptr + p.sq_off.head);
    u->sq_tail = (unsigned*)((uint8_t*)sq_ring_ptr + p.sq_off.tail);
    u->sq_ring_mask = (unsigned*)((uint8_t*)sq_ring_ptr + p.sq_off.ring_mask);
    u->sq_ring_entries = (unsigned*)((uint8_t*)sq_ring_ptr + p.sq_off.ring_entries);
    u->sq_flags = (unsigned*)((uint8_t*)sq_ring_ptr + p.sq_off.flags);
    u->sq_dropped = (unsigned*)((uint8_t*)sq_ring_ptr + p.sq_off.dropped);
    u->sq_array = (unsigned*)((uint8_t*)sq_ring_ptr + p.sq_off.array);
    u->sqes = (struct io_uring_sqe*)sqes_ptr;

    u->cq_head = (unsigned*)((uint8_t*)cq_ring_ptr + p.cq_off.head);
    u->cq_tail = (unsigned*)((uint8_t*)cq_ring_ptr + p.cq_off.tail);
    u->cq_ring_mask = (unsigned*)((uint8_t*)cq_ring_ptr + p.cq_off.ring_mask);
    u->cq_ring_entries = (unsigned*)((uint8_t*)cq_ring_ptr + p.cq_off.ring_entries);
    u->cq_overflow = (unsigned*)((uint8_t*)cq_ring_ptr + p.cq_off.overflow);
    u->cqes = (struct io_uring_cqe*)((uint8_t*)cq_ring_ptr + p.cq_off.cqes);

    return SOL_OK;
}

sol_err_t
sol_io_uring_ctx_init(sol_io_ctx_t* ctx) {
    if (!ctx) return SOL_ERR_INVAL;
    if (ctx->uring_enabled) return SOL_OK;
    if (pthread_key_create(&ctx->uring_tls, uring_tls_destructor) != 0) {
        return SOL_ERR_IO;
    }
    ctx->uring_tls_inited = true;

    /* Probe/initialize a ring for this thread so callers can decide early
     * whether to fall back to POSIX IO. */
    sol_io_uring_thread_ctx_t* t = sol_calloc(1, sizeof(*t));
    if (!t) {
        (void)pthread_key_delete(ctx->uring_tls);
        ctx->uring_tls_inited = false;
        return SOL_ERR_NOMEM;
    }

    int setup_errno = 0;
    sol_err_t err = uring_ring_init(&t->uring, ctx->opts.queue_depth, ctx->opts.sqpoll, &setup_errno);
    if (err != SOL_OK && ctx->opts.sqpoll &&
        (setup_errno == EPERM || setup_errno == EINVAL)) {
        /* SQPOLL often requires elevated privileges. Retry without it. */
        ctx->opts.sqpoll = false;
        setup_errno = 0;
        err = uring_ring_init(&t->uring, ctx->opts.queue_depth, false, &setup_errno);
    }

    if (err != SOL_OK) {
        sol_free(t);
        (void)pthread_key_delete(ctx->uring_tls);
        ctx->uring_tls_inited = false;
        return err;
    }

    t->sqpoll = ctx->opts.sqpoll;
    if (pthread_setspecific(ctx->uring_tls, t) != 0) {
        uring_ring_close(&t->uring);
        sol_free(t);
        (void)pthread_key_delete(ctx->uring_tls);
        ctx->uring_tls_inited = false;
        return SOL_ERR_IO;
    }

    ctx->uring_enabled = true;
    return SOL_OK;
}

void
sol_io_uring_ctx_destroy(sol_io_ctx_t* ctx) {
    if (!ctx) return;
    if (!ctx->uring_enabled) return;

    if (ctx->uring_tls_inited) {
        sol_io_uring_thread_ctx_t* t =
            (sol_io_uring_thread_ctx_t*)pthread_getspecific(ctx->uring_tls);
        if (t) {
            uring_ring_close(&t->uring);
            sol_free(t);
            (void)pthread_setspecific(ctx->uring_tls, NULL);
        }
        (void)pthread_key_delete(ctx->uring_tls);
        ctx->uring_tls_inited = false;
    }

    ctx->uring_enabled = false;
}

static sol_err_t
uring_submit_and_wait_one(sol_io_uring_thread_ctx_t* t,
                          uint8_t opcode,
                          int fd,
                          const struct iovec* iov,
                          int iovcnt,
                          uint64_t offset,
                          int* out_res) {
    if (!t) return SOL_ERR_UNSUPPORTED;
    sol_io_uring_t* u = &t->uring;
    if (u->ring_fd < 0) return SOL_ERR_UNSUPPORTED;
    if (fd < 0) return SOL_ERR_INVAL;
    if (!iov || iovcnt <= 0) return SOL_ERR_INVAL;
    if (offset > (uint64_t)LLONG_MAX) return SOL_ERR_TOO_LARGE;
    if (!out_res) return SOL_ERR_INVAL;

    unsigned head = __atomic_load_n(u->sq_head, __ATOMIC_ACQUIRE);
    unsigned tail = __atomic_load_n(u->sq_tail, __ATOMIC_RELAXED);
    unsigned entries = __atomic_load_n(u->sq_ring_entries, __ATOMIC_ACQUIRE);
    if (tail - head >= entries) {
        return SOL_ERR_BUSY;
    }

    unsigned mask = __atomic_load_n(u->sq_ring_mask, __ATOMIC_ACQUIRE);
    unsigned idx = tail & mask;
    struct io_uring_sqe* sqe = &u->sqes[idx];
    memset(sqe, 0, sizeof(*sqe));

    sqe->opcode = opcode;
    sqe->fd = fd;
    sqe->off = (uint64_t)(off_t)offset;
    sqe->addr = (uint64_t)(uintptr_t)iov;
    sqe->len = (uint32_t)iovcnt;
    sqe->user_data = 0;

    u->sq_array[idx] = idx;

    __atomic_store_n(u->sq_tail, tail + 1, __ATOMIC_RELEASE);

    unsigned flags = IORING_ENTER_GETEVENTS;
    if (t->sqpoll) {
        unsigned sq_flags = __atomic_load_n(u->sq_flags, __ATOMIC_ACQUIRE);
        if (sq_flags & IORING_SQ_NEED_WAKEUP) {
            flags |= IORING_ENTER_SQ_WAKEUP;
        }
    }

    for (;;) {
        int rc = io_uring_enter_syscall(u->ring_fd, 1, 1, flags);
        if (rc < 0) {
            if (errno == EINTR) continue;
            return SOL_ERR_IO;
        }
        break;
    }

    unsigned cq_head = __atomic_load_n(u->cq_head, __ATOMIC_ACQUIRE);
    unsigned cq_tail = __atomic_load_n(u->cq_tail, __ATOMIC_ACQUIRE);
    if (cq_head == cq_tail) {
        return SOL_ERR_IO;
    }

    unsigned cq_mask = __atomic_load_n(u->cq_ring_mask, __ATOMIC_ACQUIRE);
    struct io_uring_cqe* cqe = &u->cqes[cq_head & cq_mask];
    int res = cqe->res;
    __atomic_store_n(u->cq_head, cq_head + 1, __ATOMIC_RELEASE);

    *out_res = res;
    return SOL_OK;
}

static void
uring_tls_destructor(void* p) {
    sol_io_uring_thread_ctx_t* t = (sol_io_uring_thread_ctx_t*)p;
    if (!t) return;
    uring_ring_close(&t->uring);
    sol_free(t);
}

static sol_io_uring_thread_ctx_t*
uring_thread_ctx_get_or_init(sol_io_ctx_t* ctx) {
    if (!ctx || !ctx->uring_enabled || !ctx->uring_tls_inited) return NULL;

    sol_io_uring_thread_ctx_t* t =
        (sol_io_uring_thread_ctx_t*)pthread_getspecific(ctx->uring_tls);
    if (t) return t;

    /* Per-thread ring. If this fails, fall back to POSIX at the call site. */
    t = sol_calloc(1, sizeof(*t));
    if (!t) return NULL;

    int setup_errno = 0;
    sol_err_t err = uring_ring_init(&t->uring, ctx->opts.queue_depth, ctx->opts.sqpoll, &setup_errno);
    if (err != SOL_OK) {
        sol_free(t);
        return NULL;
    }

    t->sqpoll = ctx->opts.sqpoll;

    if (pthread_setspecific(ctx->uring_tls, t) != 0) {
        uring_ring_close(&t->uring);
        sol_free(t);
        return NULL;
    }

    return t;
}

static sol_err_t
uring_preadv_all(sol_io_ctx_t* ctx,
                 int fd,
                 const struct iovec* iov,
                 int iovcnt,
                 uint64_t offset) {
    sol_io_uring_thread_ctx_t* t = uring_thread_ctx_get_or_init(ctx);
    if (!t) return SOL_ERR_UNSUPPORTED;

    enum { STACK_IOV_MAX = 8 };
    struct iovec stack_iov[STACK_IOV_MAX];
    struct iovec* v = stack_iov;
    if (iovcnt > (int)STACK_IOV_MAX) {
        v = sol_alloc((size_t)iovcnt * sizeof(*v));
        if (!v) return SOL_ERR_NOMEM;
    }
    memcpy(v, iov, (size_t)iovcnt * sizeof(*v));

    uint64_t off = offset;
    int cur_cnt = iovcnt;
    struct iovec* cur = v;

    while (cur_cnt > 0) {
        int res = 0;
        sol_err_t err = uring_submit_and_wait_one(t, IORING_OP_READV, fd, cur, cur_cnt, off, &res);
        if (err != SOL_OK) {
            if (v != stack_iov) sol_free(v);
            return err;
        }
        if (res < 0) {
            if (v != stack_iov) sol_free(v);
            return SOL_ERR_IO;
        }
        if (res == 0) {
            if (v != stack_iov) sol_free(v);
            return SOL_ERR_TRUNCATED;
        }

        off += (uint64_t)res;

        size_t consumed = (size_t)res;
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
uring_pwritev_all(sol_io_ctx_t* ctx,
                  int fd,
                  const struct iovec* iov,
                  int iovcnt,
                  uint64_t offset) {
    sol_io_uring_thread_ctx_t* t = uring_thread_ctx_get_or_init(ctx);
    if (!t) return SOL_ERR_UNSUPPORTED;

    enum { STACK_IOV_MAX = 8 };
    struct iovec stack_iov[STACK_IOV_MAX];
    struct iovec* v = stack_iov;
    if (iovcnt > (int)STACK_IOV_MAX) {
        v = sol_alloc((size_t)iovcnt * sizeof(*v));
        if (!v) return SOL_ERR_NOMEM;
    }
    memcpy(v, iov, (size_t)iovcnt * sizeof(*v));

    uint64_t off = offset;
    int cur_cnt = iovcnt;
    struct iovec* cur = v;

    while (cur_cnt > 0) {
        int res = 0;
        sol_err_t err = uring_submit_and_wait_one(t, IORING_OP_WRITEV, fd, cur, cur_cnt, off, &res);
        if (err != SOL_OK) {
            if (v != stack_iov) sol_free(v);
            return err;
        }
        if (res < 0) {
            if (v != stack_iov) sol_free(v);
            return SOL_ERR_IO;
        }
        if (res == 0) {
            if (v != stack_iov) sol_free(v);
            return SOL_ERR_IO;
        }

        off += (uint64_t)res;

        size_t consumed = (size_t)res;
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

sol_err_t
sol_io_uring_preadv_all(sol_io_ctx_t* ctx,
                        int fd,
                        const struct iovec* iov,
                        int iovcnt,
                        uint64_t offset) {
    if (!ctx || !ctx->uring_enabled) return SOL_ERR_UNSUPPORTED;
    return uring_preadv_all(ctx, fd, iov, iovcnt, offset);
}

sol_err_t
sol_io_uring_pwritev_all(sol_io_ctx_t* ctx,
                         int fd,
                         const struct iovec* iov,
                         int iovcnt,
                         uint64_t offset) {
    if (!ctx || !ctx->uring_enabled) return SOL_ERR_UNSUPPORTED;
    return uring_pwritev_all(ctx, fd, iov, iovcnt, offset);
}

#else /* !__linux__ */

sol_err_t
sol_io_uring_ctx_init(sol_io_ctx_t* ctx) {
    (void)ctx;
    return SOL_ERR_UNSUPPORTED;
}

void
sol_io_uring_ctx_destroy(sol_io_ctx_t* ctx) {
    (void)ctx;
}

sol_err_t
sol_io_uring_preadv_all(sol_io_ctx_t* ctx,
                        int fd,
                        const struct iovec* iov,
                        int iovcnt,
                        uint64_t offset) {
    (void)ctx;
    (void)fd;
    (void)iov;
    (void)iovcnt;
    (void)offset;
    return SOL_ERR_UNSUPPORTED;
}

sol_err_t
sol_io_uring_pwritev_all(sol_io_ctx_t* ctx,
                         int fd,
                         const struct iovec* iov,
                         int iovcnt,
                         uint64_t offset) {
    (void)ctx;
    (void)fd;
    (void)iov;
    (void)iovcnt;
    (void)offset;
    return SOL_ERR_UNSUPPORTED;
}

#endif
