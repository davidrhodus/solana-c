#ifndef SOL_IO_IMPL_H
#define SOL_IO_IMPL_H

#include "sol_io.h"

#include <pthread.h>

struct io_uring_sqe;
struct io_uring_cqe;

typedef struct {
    int                         ring_fd;
    unsigned*                   sq_head;
    unsigned*                   sq_tail;
    unsigned*                   sq_ring_mask;
    unsigned*                   sq_ring_entries;
    unsigned*                   sq_flags;
    unsigned*                   sq_dropped;
    unsigned*                   sq_array;
    struct io_uring_sqe*        sqes;

    unsigned*                   cq_head;
    unsigned*                   cq_tail;
    unsigned*                   cq_ring_mask;
    unsigned*                   cq_ring_entries;
    unsigned*                   cq_overflow;
    struct io_uring_cqe*        cqes;

    void*                       sq_ring_ptr;
    size_t                      sq_ring_sz;
    void*                       cq_ring_ptr;
    size_t                      cq_ring_sz;
    void*                       sqes_ptr;
    size_t                      sqes_sz;
} sol_io_uring_t;

struct sol_io_ctx {
    sol_io_options_t opts;

#ifdef __linux__
    /* When enabled, each thread lazily creates its own ring via TLS. This
     * avoids a global mutex bottleneck during snapshot ingestion. */
    bool        uring_enabled;
    bool        uring_tls_inited;
    pthread_key_t uring_tls;
#endif
};

#endif /* SOL_IO_IMPL_H */
