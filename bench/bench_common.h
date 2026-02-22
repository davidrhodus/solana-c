/*
 * bench_common.h - Tiny benchmark helpers
 */

#ifndef SOLANA_C_BENCH_COMMON_H
#define SOLANA_C_BENCH_COMMON_H

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static inline uint64_t
bench_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static inline uint64_t
bench_parse_u64_arg(int argc, char** argv, const char* key, uint64_t default_value) {
    size_t key_len = strlen(key);
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], key, key_len) == 0) {
            const char* value = argv[i] + key_len;
            if (*value == '\0' && i + 1 < argc) {
                value = argv[++i];
            }
            if (*value == '=') {
                value++;
            }
            if (*value == '\0') {
                return default_value;
            }
            return strtoull(value, NULL, 10);
        }
    }
    return default_value;
}

static inline void
bench_print_rate(const char* name, uint64_t iters, uint64_t elapsed_ns) {
    double seconds = (double)elapsed_ns / 1e9;
    double ops_per_sec = seconds > 0.0 ? ((double)iters / seconds) : 0.0;
    double ns_per_op = iters > 0 ? ((double)elapsed_ns / (double)iters) : 0.0;

    printf("%-24s  %12" PRIu64 " iters  %8.3f s  %12.0f ops/s  %10.1f ns/op\n",
           name, iters, seconds, ops_per_sec, ns_per_op);
}

#endif /* SOLANA_C_BENCH_COMMON_H */
