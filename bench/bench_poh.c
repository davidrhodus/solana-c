#include "crypto/sol_sha256.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t
now_ns(void) {
    struct timespec ts = {0};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

int
main(int argc, char** argv) {
    uint64_t cnt = 4000000ull;
    if (argc > 1 && argv[1] && argv[1][0] != '\0') {
        cnt = strtoull(argv[1], NULL, 10);
        if (cnt == 0) {
            fprintf(stderr, "usage: %s [count]\n", argv[0]);
            return 1;
        }
    }

    uint8_t data[32];
    memset(data, 0, sizeof(data));

    uint64_t t0 = now_ns();
    sol_sha256_32bytes_repeated(data, cnt);
    uint64_t t1 = now_ns();

    double sec = (double)(t1 - t0) / 1000000000.0;
    double mh_s = (sec > 0.0) ? ((double)cnt / 1000000.0) / sec : 0.0;

    /* Print the digest prefix so the compiler can't elide the work. */
    printf("sha256_32bytes_repeated: cnt=%" PRIu64 " elapsed=%.6f s rate=%.2f MH/s digest=%02x%02x%02x%02x\n",
           cnt,
           sec,
           mh_s,
           (unsigned)data[0],
           (unsigned)data[1],
           (unsigned)data[2],
           (unsigned)data[3]);

    return 0;
}

