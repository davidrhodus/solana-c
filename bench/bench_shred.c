/*
 * bench_shred.c - Shred parse/verify benchmark
 */

#include "bench_common.h"

#include "crypto/sol_ed25519.h"
#include "shred/sol_shred.h"

int
main(int argc, char** argv) {
    uint64_t iters = bench_parse_u64_arg(argc, argv, "--iters", 1000000ULL);
    uint64_t num_shreds = bench_parse_u64_arg(argc, argv, "--shreds", 1024ULL);
    uint64_t payload_len = bench_parse_u64_arg(argc, argv, "--payload", 1000ULL);
    uint64_t do_verify = bench_parse_u64_arg(argc, argv, "--verify", 0ULL);

    if (num_shreds == 0 || num_shreds > 1000000ULL) {
        fprintf(stderr, "invalid --shreds (1..1000000)\n");
        return 2;
    }

    if (payload_len > SOL_SHRED_MAX_DATA_SIZE) {
        fprintf(stderr, "invalid --payload (max %u)\n", (unsigned)SOL_SHRED_MAX_DATA_SIZE);
        return 2;
    }

    size_t shred_len = SOL_SHRED_HEADER_SIZE + SOL_SHRED_DATA_HEADER_SIZE + (size_t)payload_len;

    uint8_t* payload = (uint8_t*)malloc((size_t)payload_len);
    uint8_t* shreds = (uint8_t*)malloc((size_t)num_shreds * shred_len);
    if ((payload_len > 0 && !payload) || !shreds) {
        fprintf(stderr, "malloc failed\n");
        free(payload);
        free(shreds);
        return 2;
    }

    for (uint64_t i = 0; i < payload_len; i++) {
        payload[i] = (uint8_t)(i * 31u + 7u);
    }

    sol_keypair_t leader;
    if (sol_ed25519_keypair_generate(&leader) != SOL_OK) {
        fprintf(stderr, "sol_ed25519_keypair_generate failed\n");
        free(payload);
        free(shreds);
        return 2;
    }

    sol_pubkey_t leader_pk;
    sol_ed25519_pubkey_from_keypair(&leader, &leader_pk);

    for (uint64_t i = 0; i < num_shreds; i++) {
        uint8_t* out = shreds + i * shred_len;
        size_t written = 0;
        sol_err_t err = sol_shred_build_legacy_data(
            &leader,
            (sol_slot_t)123,
            (sol_slot_t)122,
            (uint32_t)i,
            (uint16_t)1,
            (uint32_t)0,
            (uint8_t)0,
            payload_len ? payload : NULL,
            (size_t)payload_len,
            out,
            shred_len,
            &written);

        if (err != SOL_OK || written != shred_len) {
            fprintf(stderr, "sol_shred_build_legacy_data failed\n");
            free(payload);
            free(shreds);
            return 2;
        }
    }

    volatile uint64_t accum = 0;

    uint64_t start = bench_now_ns();
    for (uint64_t i = 0; i < iters; i++) {
        const uint8_t* raw = shreds + (i % num_shreds) * shred_len;
        sol_shred_t parsed;
        if (sol_shred_parse(&parsed, raw, shred_len) != SOL_OK) {
            fprintf(stderr, "sol_shred_parse failed\n");
            free(payload);
            free(shreds);
            return 2;
        }

        accum += parsed.payload_len;

        if (do_verify) {
            const uint8_t* msg = raw + SOL_SIGNATURE_SIZE;
            size_t msg_len = shred_len - SOL_SIGNATURE_SIZE;
            accum += sol_ed25519_verify(&leader_pk, msg, msg_len, &parsed.signature);
        }
    }
    uint64_t end = bench_now_ns();

    bench_print_rate(do_verify ? "shred_parse+verify" : "shred_parse", iters, end - start);
    printf("accum: %" PRIu64 "\n", accum);

    free(payload);
    free(shreds);
    return 0;
}

