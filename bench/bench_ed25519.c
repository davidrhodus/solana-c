/*
 * bench_ed25519.c - Ed25519 verification benchmark
 */

#include "bench_common.h"

#include "crypto/sol_ed25519.h"

int
main(int argc, char** argv) {
    uint64_t iters = bench_parse_u64_arg(argc, argv, "--iters", 1000000ULL);
    uint64_t msg_len = bench_parse_u64_arg(argc, argv, "--msg-len", 32ULL);

    if (msg_len == 0 || msg_len > 65536) {
        fprintf(stderr, "invalid --msg-len (1..65536)\n");
        return 2;
    }

    uint8_t* msg = (uint8_t*)malloc((size_t)msg_len);
    if (!msg) {
        fprintf(stderr, "malloc failed\n");
        return 2;
    }

    for (uint64_t i = 0; i < msg_len; i++) {
        msg[i] = (uint8_t)(i * 131u + 17u);
    }

    sol_keypair_t kp;
    if (sol_ed25519_keypair_generate(&kp) != SOL_OK) {
        fprintf(stderr, "sol_ed25519_keypair_generate failed\n");
        free(msg);
        return 2;
    }

    sol_pubkey_t pk;
    sol_ed25519_pubkey_from_keypair(&kp, &pk);

    sol_signature_t sig;
    sol_ed25519_sign(&kp, msg, (size_t)msg_len, &sig);

    volatile uint64_t valid = 0;

    uint64_t warmup = iters < 10000 ? iters : 10000;
    for (uint64_t i = 0; i < warmup; i++) {
        valid += sol_ed25519_verify(&pk, msg, (size_t)msg_len, &sig);
    }

    uint64_t start = bench_now_ns();
    for (uint64_t i = 0; i < iters; i++) {
        valid += sol_ed25519_verify(&pk, msg, (size_t)msg_len, &sig);
    }
    uint64_t end = bench_now_ns();

    bench_print_rate("ed25519_verify", iters, end - start);
    printf("valid: %" PRIu64 "\n", valid);

    free(msg);
    return 0;
}

