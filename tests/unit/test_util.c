/*
 * test_util.c - Unit tests for utility modules
 */

#include "../test_framework.h"
#include "util/sol_base.h"
#include "util/sol_types.h"
#include "util/sol_err.h"
#include "util/sol_bits.h"
#include "util/sol_hash_fn.h"
#include "util/sol_alloc.h"
#include "util/sol_vec.h"
#include "util/sol_map.h"
#include "util/sol_arena.h"
#include "util/sol_slab.h"
#include "util/sol_rpc_client.h"
#include "util/sol_io.h"

#include <fcntl.h>
#include <unistd.h>

/*
 * sol_bits tests
 */

TEST(bits_clz) {
    TEST_ASSERT_EQ(sol_clz32(0), 32);
    TEST_ASSERT_EQ(sol_clz32(1), 31);
    TEST_ASSERT_EQ(sol_clz32(0x80000000), 0);
    TEST_ASSERT_EQ(sol_clz64(0), 64);
    TEST_ASSERT_EQ(sol_clz64(1), 63);
    TEST_ASSERT_EQ(sol_clz64(0x8000000000000000ULL), 0);
}

TEST(bits_ctz) {
    TEST_ASSERT_EQ(sol_ctz32(0), 32);
    TEST_ASSERT_EQ(sol_ctz32(1), 0);
    TEST_ASSERT_EQ(sol_ctz32(0x80000000), 31);
    TEST_ASSERT_EQ(sol_ctz32(0x100), 8);
}

TEST(bits_popcount) {
    TEST_ASSERT_EQ(sol_popcount32(0), 0);
    TEST_ASSERT_EQ(sol_popcount32(1), 1);
    TEST_ASSERT_EQ(sol_popcount32(0xFFFFFFFF), 32);
    TEST_ASSERT_EQ(sol_popcount64(0x5555555555555555ULL), 32);
}

TEST(bits_next_pow2) {
    TEST_ASSERT_EQ(sol_next_pow2_32(0), 1);
    TEST_ASSERT_EQ(sol_next_pow2_32(1), 1);
    TEST_ASSERT_EQ(sol_next_pow2_32(2), 2);
    TEST_ASSERT_EQ(sol_next_pow2_32(3), 4);
    TEST_ASSERT_EQ(sol_next_pow2_32(5), 8);
    TEST_ASSERT_EQ(sol_next_pow2_32(1000), 1024);
}

TEST(bits_align) {
    TEST_ASSERT_EQ(sol_align_up(0, 8), 0);
    TEST_ASSERT_EQ(sol_align_up(1, 8), 8);
    TEST_ASSERT_EQ(sol_align_up(7, 8), 8);
    TEST_ASSERT_EQ(sol_align_up(8, 8), 8);
    TEST_ASSERT_EQ(sol_align_up(9, 8), 16);
    TEST_ASSERT_EQ(sol_align_down(15, 8), 8);
    TEST_ASSERT(sol_is_aligned((void*)0x100, 16));
    TEST_ASSERT(!sol_is_aligned((void*)0x101, 16));
}

TEST(bits_bswap) {
    TEST_ASSERT_EQ(sol_bswap16(0x1234), 0x3412);
    TEST_ASSERT_EQ(sol_bswap32(0x12345678), 0x78563412);
    TEST_ASSERT_EQ(sol_bswap64(0x123456789ABCDEF0ULL), 0xF0DEBC9A78563412ULL);
}

/*
 * sol_hash_fn tests
 */

TEST(hash_wyhash) {
    const char* data = "hello world";
    uint64_t h1 = sol_wyhash(data, strlen(data), 0);
    uint64_t h2 = sol_wyhash(data, strlen(data), 0);
    uint64_t h3 = sol_wyhash(data, strlen(data), 1);

    TEST_ASSERT_EQ(h1, h2);  /* Same seed -> same hash */
    TEST_ASSERT_NE(h1, h3);  /* Different seed -> different hash */
    TEST_ASSERT_NE(h1, 0);
}

TEST(hash_u64) {
    uint64_t h1 = sol_hash_u64(0);
    uint64_t h2 = sol_hash_u64(1);
    uint64_t h3 = sol_hash_u64(0);

    TEST_ASSERT_EQ(h1, h3);
    TEST_ASSERT_NE(h1, h2);
}

/*
 * sol_types tests
 */

TEST(types_pubkey_eq) {
    sol_pubkey_t a = {{0}};
    sol_pubkey_t b = {{0}};
    sol_pubkey_t c = {{1}};

    TEST_ASSERT(sol_pubkey_eq(&a, &b));
    TEST_ASSERT(!sol_pubkey_eq(&a, &c));
    TEST_ASSERT(sol_pubkey_is_zero(&a));
    TEST_ASSERT(!sol_pubkey_is_zero(&c));
}

TEST(types_hash_eq) {
    sol_hash_t a = {{0}};
    sol_hash_t b = {{0}};

    TEST_ASSERT(sol_hash_eq(&a, &b));
    TEST_ASSERT(sol_hash_is_zero(&a));

    a.bytes[0] = 1;
    TEST_ASSERT(!sol_hash_eq(&a, &b));
    TEST_ASSERT(!sol_hash_is_zero(&a));
}

TEST(types_slice) {
    const char* data = "hello";
    sol_slice_t s1 = sol_slice_new(data, 5);
    sol_slice_t s2 = sol_slice_new(data, 5);
    sol_slice_t s3 = sol_slice_new("world", 5);

    TEST_ASSERT(sol_slice_eq(s1, s2));
    TEST_ASSERT(!sol_slice_eq(s1, s3));
}

/*
 * sol_err tests
 */

TEST(err_str) {
    TEST_ASSERT_STR_EQ(sol_err_str(SOL_OK), "OK");
    TEST_ASSERT_STR_EQ(sol_err_str(SOL_ERR_NOMEM), "Out of memory");
    TEST_ASSERT_STR_EQ(sol_err_str(SOL_ERR_INVALID_SIGNATURE), "Invalid signature");
}

/*
 * sol_alloc tests
 */

TEST(alloc_basic) {
    void* p = sol_alloc(100);
    TEST_ASSERT_NOT_NULL(p);
    sol_free(p);

    p = sol_calloc(10, 10);
    TEST_ASSERT_NOT_NULL(p);
    /* Verify zeroed */
    for (int i = 0; i < 100; i++) {
        TEST_ASSERT_EQ(((char*)p)[i], 0);
    }
    sol_free(p);
}

TEST(alloc_realloc) {
    void* p = sol_alloc(100);
    TEST_ASSERT_NOT_NULL(p);
    memset(p, 'A', 100);

    p = sol_realloc(p, 200);
    TEST_ASSERT_NOT_NULL(p);
    /* Verify original data preserved */
    for (int i = 0; i < 100; i++) {
        TEST_ASSERT_EQ(((char*)p)[i], 'A');
    }
    sol_free(p);
}

TEST(alloc_aligned) {
    void* p = sol_alloc_aligned(1000, 64);
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT(sol_is_aligned(p, 64));
    sol_free_aligned(p);
}

/*
 * sol_vec tests
 */

TEST(vec_basic) {
    int* v = sol_vec_new(int);
    TEST_ASSERT_NOT_NULL(v);
    TEST_ASSERT_EQ(sol_vec_len(v), 0);

    sol_vec_push(v, 1);
    sol_vec_push(v, 2);
    sol_vec_push(v, 3);

    TEST_ASSERT_EQ(sol_vec_len(v), 3);
    TEST_ASSERT_EQ(v[0], 1);
    TEST_ASSERT_EQ(v[1], 2);
    TEST_ASSERT_EQ(v[2], 3);

    TEST_ASSERT_EQ(sol_vec_pop(v), 3);
    TEST_ASSERT_EQ(sol_vec_len(v), 2);

    sol_vec_free(v);
}

TEST(vec_grow) {
    int* v = sol_vec_new_cap(int, 4);
    TEST_ASSERT_NOT_NULL(v);

    for (int i = 0; i < 1000; i++) {
        sol_vec_push(v, i);
    }

    TEST_ASSERT_EQ(sol_vec_len(v), 1000);
    for (int i = 0; i < 1000; i++) {
        TEST_ASSERT_EQ(v[i], i);
    }

    sol_vec_free(v);
}

/*
 * sol_map tests
 */

TEST(map_basic) {
    sol_map_t* m = SOL_MAP_NEW(uint64_t, uint64_t, sol_map_hash_u64, sol_map_eq_u64, 0);
    TEST_ASSERT_NOT_NULL(m);
    TEST_ASSERT_EQ(sol_map_size(m), 0);

    /* Insert */
    uint64_t k1 = 1, v1 = 100;
    uint64_t k2 = 2, v2 = 200;
    sol_map_insert(m, &k1, &v1);
    sol_map_insert(m, &k2, &v2);

    TEST_ASSERT_EQ(sol_map_size(m), 2);

    /* Get */
    uint64_t* pv = (uint64_t*)sol_map_get(m, &k1);
    TEST_ASSERT_NOT_NULL(pv);
    TEST_ASSERT_EQ(*pv, 100);

    pv = (uint64_t*)sol_map_get(m, &k2);
    TEST_ASSERT_NOT_NULL(pv);
    TEST_ASSERT_EQ(*pv, 200);

    /* Not found */
    uint64_t k3 = 3;
    TEST_ASSERT_NULL(sol_map_get(m, &k3));

    /* Remove */
    TEST_ASSERT(sol_map_remove(m, &k1));
    TEST_ASSERT_EQ(sol_map_size(m), 1);
    TEST_ASSERT_NULL(sol_map_get(m, &k1));

    sol_map_destroy(m);
}

TEST(map_collision) {
    /* Test with many entries to force collisions */
    sol_map_t* m = SOL_MAP_NEW(uint64_t, uint64_t, sol_map_hash_u64, sol_map_eq_u64, 8);
    TEST_ASSERT_NOT_NULL(m);

    for (uint64_t i = 0; i < 1000; i++) {
        uint64_t v = i * 10;
        sol_map_insert(m, &i, &v);
    }

    TEST_ASSERT_EQ(sol_map_size(m), 1000);

    for (uint64_t i = 0; i < 1000; i++) {
        uint64_t* pv = (uint64_t*)sol_map_get(m, &i);
        TEST_ASSERT_NOT_NULL(pv);
        TEST_ASSERT_EQ(*pv, i * 10);
    }

    sol_map_destroy(m);
}

/*
 * sol_arena tests
 */

TEST(arena_basic) {
    sol_arena_t* a = sol_arena_new(1024);
    TEST_ASSERT_NOT_NULL(a);

    void* p1 = sol_arena_alloc(a, 100);
    TEST_ASSERT_NOT_NULL(p1);

    void* p2 = sol_arena_alloc(a, 200);
    TEST_ASSERT_NOT_NULL(p2);

    /* Allocations should be sequential */
    TEST_ASSERT((char*)p2 >= (char*)p1 + 100);

    sol_arena_reset(a);

    /* After reset, can allocate again */
    void* p3 = sol_arena_alloc(a, 100);
    TEST_ASSERT_NOT_NULL(p3);

    sol_arena_destroy(a);
}

TEST(arena_strdup) {
    sol_arena_t* a = sol_arena_new(1024);
    TEST_ASSERT_NOT_NULL(a);

    char* s = sol_arena_strdup(a, "hello world");
    TEST_ASSERT_NOT_NULL(s);
    TEST_ASSERT_STR_EQ(s, "hello world");

    sol_arena_destroy(a);
}

/*
 * sol_slab tests
 */

TEST(slab_basic) {
    sol_slab_t* s = sol_slab_new_default(64);
    TEST_ASSERT_NOT_NULL(s);

    void* p1 = sol_slab_alloc(s);
    TEST_ASSERT_NOT_NULL(p1);

    void* p2 = sol_slab_alloc(s);
    TEST_ASSERT_NOT_NULL(p2);
    TEST_ASSERT_NE(p1, p2);

    sol_slab_free(s, p1);

    /* Reuse freed slot */
    void* p3 = sol_slab_alloc(s);
    TEST_ASSERT_EQ(p1, p3);

    sol_slab_destroy(s);
}

TEST(slab_many) {
    sol_slab_t* s = sol_slab_new_default(sizeof(uint64_t));
    TEST_ASSERT_NOT_NULL(s);

    void* ptrs[1000];
    for (int i = 0; i < 1000; i++) {
        ptrs[i] = sol_slab_alloc(s);
        TEST_ASSERT_NOT_NULL(ptrs[i]);
    }

    TEST_ASSERT_EQ(sol_slab_used_objects(s), 1000);

    for (int i = 0; i < 1000; i++) {
        sol_slab_free(s, ptrs[i]);
    }

    TEST_ASSERT_EQ(sol_slab_used_objects(s), 0);

    sol_slab_destroy(s);
}

TEST(rpc_parse_cluster_nodes_shred_version) {
    const char* json =
        "{\"jsonrpc\":\"2.0\",\"result\":["
        "{\"pubkey\":\"A\",\"gossip\":\"1.2.3.4:8001\",\"shredVersion\":50093},"
        "{\"pubkey\":\"B\",\"shredVersion\":50093}"
        "],\"id\":1}";

    uint16_t sv = 0;
    sol_err_t err = sol_rpc_parse_cluster_nodes_shred_version(json, strlen(json), &sv);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_EQ(sv, 50093);
}

TEST(rpc_parse_genesis_hash_base58) {
    const char* json =
        "{\"jsonrpc\":\"2.0\",\"result\":\"5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp\",\"id\":1}";

    char out[128] = {0};
    sol_err_t err = sol_rpc_parse_genesis_hash_base58(json, strlen(json), out, sizeof(out));
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_STR_EQ(out, "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp");
}

TEST(io_pread_pwrite_uring) {
#ifdef __linux__
    char path[] = "/tmp/solana-c-io-XXXXXX";
    int fd = mkstemp(path);
    TEST_ASSERT_MSG(fd >= 0, "mkstemp failed");
    (void)unlink(path);

    sol_io_options_t opts = SOL_IO_OPTIONS_DEFAULT;
    opts.backend = SOL_IO_BACKEND_URING;
    opts.queue_depth = 32;
    opts.sqpoll = false;

    sol_io_ctx_t* ctx = sol_io_ctx_new(&opts);
    TEST_ASSERT_NOT_NULL(ctx);

    if (sol_io_ctx_backend(ctx) != SOL_IO_BACKEND_URING) {
        sol_io_ctx_destroy(ctx);
        (void)close(fd);
        TEST_SKIP("io_uring unavailable on this host");
    }

    uint8_t w1[4096];
    for (size_t i = 0; i < sizeof(w1); i++) {
        w1[i] = (uint8_t)(i & 0xFFu);
    }
    sol_err_t err = sol_io_pwrite_all(ctx, fd, w1, sizeof(w1), 0);
    TEST_ASSERT_EQ(err, SOL_OK);

    uint8_t r1[4096];
    memset(r1, 0, sizeof(r1));
    err = sol_io_pread_all(ctx, fd, r1, sizeof(r1), 0);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_MEM_EQ(r1, w1, sizeof(w1));

    char a[] = "hello";
    char b[] = "world";
    struct iovec iov[2];
    iov[0] = (struct iovec){ .iov_base = a, .iov_len = strlen(a) };
    iov[1] = (struct iovec){ .iov_base = b, .iov_len = strlen(b) };

    err = sol_io_pwritev_all(ctx, fd, iov, 2, 4096);
    TEST_ASSERT_EQ(err, SOL_OK);

    char out[11] = {0};
    err = sol_io_pread_all(ctx, fd, out, 10, 4096);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT_MEM_EQ(out, "helloworld", 10);

    char trunc[1];
    err = sol_io_pread_all(ctx, fd, trunc, sizeof(trunc), 4096 + 10 + 12345);
    TEST_ASSERT_EQ(err, SOL_ERR_TRUNCATED);

    sol_io_ctx_destroy(ctx);
    (void)close(fd);
#else
    TEST_SKIP("io_uring test is Linux-only");
#endif
}

/*
 * Test suite
 */
static test_case_t util_tests[] = {
    TEST_CASE(bits_clz),
    TEST_CASE(bits_ctz),
    TEST_CASE(bits_popcount),
    TEST_CASE(bits_next_pow2),
    TEST_CASE(bits_align),
    TEST_CASE(bits_bswap),
    TEST_CASE(hash_wyhash),
    TEST_CASE(hash_u64),
    TEST_CASE(types_pubkey_eq),
    TEST_CASE(types_hash_eq),
    TEST_CASE(types_slice),
    TEST_CASE(err_str),
    TEST_CASE(alloc_basic),
    TEST_CASE(alloc_realloc),
    TEST_CASE(alloc_aligned),
    TEST_CASE(vec_basic),
    TEST_CASE(vec_grow),
    TEST_CASE(map_basic),
    TEST_CASE(map_collision),
    TEST_CASE(arena_basic),
    TEST_CASE(arena_strdup),
    TEST_CASE(slab_basic),
    TEST_CASE(slab_many),
    TEST_CASE(rpc_parse_cluster_nodes_shred_version),
    TEST_CASE(rpc_parse_genesis_hash_base58),
    TEST_CASE(io_pread_pwrite_uring),
};

int main(void) {
    return RUN_TESTS("Utility Tests", util_tests);
}
