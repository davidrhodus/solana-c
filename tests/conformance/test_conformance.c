/*
 * test_conformance.c - Conformance test runner
 *
 * Runs conformance tests against Firedancer fixtures.
 * Usage: test_conformance [fixture_dir] [component]
 *
 * Components:
 *   all       - Run all conformance tests
 *   txn       - Transaction execution
 *   bpf       - BPF VM execution
 *   syscall   - Syscall behavior
 *   shred     - Shred parsing
 *   serialize - Serialization
 *   blockstore - Blockstore block assembly
 *   selftest  - Run built-in self-tests (no fixtures required)
 */

#include "conformance.h"
#include "sol_log.h"
#include "sol_transaction.h"
#include "sol_message.h"
#include "sol_ed25519.h"
#include "sol_bank_forks.h"
#include "sol_fork_choice.h"
#include <string.h>
#include <stdlib.h>

static uint32_t
read_u32_le(const uint8_t* p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t
read_u64_le(const uint8_t* p) {
    return (uint64_t)p[0] |
           ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}

static void
write_u32_le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void
write_u64_le(uint8_t* p, uint64_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

/*
 * Built-in self-test to verify conformance infrastructure
 * This runs without external fixtures
 */
static sol_err_t
selftest_identity(
    const uint8_t* input,
    size_t         input_len,
    uint8_t**      output,
    size_t*        output_len,
    void*          ctx
) {
    (void)ctx;

    /* Identity test - output should match input */
    *output = sol_alloc(input_len);
    if (*output == NULL) {
        return SOL_ERR_NOMEM;
    }

    memcpy(*output, input, input_len);
    *output_len = input_len;
    return SOL_OK;
}

typedef struct {
    sol_pubkey_t payer;
    sol_pubkey_t recipient;
    uint64_t     payer_lamports;
    uint64_t     recipient_lamports;
} txn_transfer_expect_t;

static bool
compare_txn_transfer_output(
    const uint8_t* expected,
    size_t         expected_len,
    const uint8_t* actual,
    size_t         actual_len,
    void*          ctx
) {
    (void)expected;
    (void)expected_len;

    const txn_transfer_expect_t* exp = (const txn_transfer_expect_t*)ctx;
    if (!exp || !actual || actual_len < 16) {
        return false;
    }

    const uint8_t* p = actual;
    const uint8_t* end = actual + actual_len;

    int32_t status = (int32_t)read_u32_le(p);
    p += 4;

    (void)read_u64_le(p); /* compute units (implementation-defined) */
    p += 8;

    uint32_t num_accounts = read_u32_le(p);
    p += 4;

    bool found_payer = false;
    bool found_recipient = false;
    uint64_t payer_lamports = 0;
    uint64_t recipient_lamports = 0;

    for (uint32_t i = 0; i < num_accounts; i++) {
        if (p + 32 + 8 + 8 > end) {
            return false;
        }

        sol_pubkey_t pubkey;
        memcpy(&pubkey, p, 32);
        p += 32;

        uint64_t lamports = read_u64_le(p);
        p += 8;

        uint64_t data_len = read_u64_le(p);
        p += 8;

        if (p + data_len > end) {
            return false;
        }
        p += data_len;

        if (sol_pubkey_eq(&pubkey, &exp->payer)) {
            found_payer = true;
            payer_lamports = lamports;
        } else if (sol_pubkey_eq(&pubkey, &exp->recipient)) {
            found_recipient = true;
            recipient_lamports = lamports;
        }
    }

    return status == SOL_OK &&
           found_payer &&
           found_recipient &&
           payer_lamports == exp->payer_lamports &&
           recipient_lamports == exp->recipient_lamports;
}

static int
run_selftest(bool verbose) {
    printf("\n=== Running Built-in Self-Tests ===\n\n");

    /* Create test suite */
    conf_suite_t* suite = conf_suite_new("selftest");
    if (suite == NULL) {
        fprintf(stderr, "Failed to create selftest suite\n");
        return 1;
    }

    /* Add test fixtures */
    uint8_t test1[] = {0x01, 0x02, 0x03, 0x04};
    conf_suite_add_fixture(suite, "identity_small", test1, 4, test1, 4);

    uint8_t test2[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
    conf_suite_add_fixture(suite, "identity_deadbeef", test2, 8, test2, 8);

    uint8_t test3[64];
    for (int i = 0; i < 64; i++) test3[i] = (uint8_t)i;
    conf_suite_add_fixture(suite, "identity_sequence", test3, 64, test3, 64);

    /* Configure and run */
    conf_config_t config = {
        .test_fn = selftest_identity,
        .compare_fn = conf_compare_bytes,
        .ctx = NULL,
        .verbose = verbose,
        .stop_on_fail = false,
        .output = stdout,
    };

    conf_results_t results = conf_suite_run(suite, &config);
    conf_suite_destroy(suite);

    if (results.failed > 0 || results.errors > 0) {
        printf("\nSelf-test FAILED\n");
        return 1;
    }

    printf("\nSelf-test PASSED - conformance infrastructure verified\n");

    printf("\n=== Running Transaction Execution Self-Test ===\n\n");

    conf_suite_t* txn_suite = conf_suite_new("txn_selftest");
    if (txn_suite == NULL) {
        fprintf(stderr, "Failed to create txn selftest suite\n");
        return 1;
    }

    /* Deterministic payer keypair */
    static const uint8_t payer_seed[32] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    };

    sol_keypair_t payer_keypair;
    sol_ed25519_keypair_from_seed(payer_seed, &payer_keypair);

    sol_pubkey_t payer_pubkey;
    sol_keypair_pubkey(&payer_keypair, &payer_pubkey);

    /* Deterministic recipient pubkey */
    static const uint8_t recipient_seed[32] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    };

    sol_pubkey_t recipient_pubkey;
    sol_ed25519_pubkey_from_seed(recipient_seed, &recipient_pubkey);

    /* Build a simple system transfer transaction */
    const uint64_t initial_payer_lamports = 100000;
    const uint64_t initial_recipient_lamports = 0;
    const uint64_t transfer_lamports = 1234;
    const uint64_t fee_lamports = 5000;

    uint8_t transfer_data[12];
    write_u32_le(transfer_data, 2);               /* SOL_SYSTEM_INSTR_TRANSFER */
    write_u64_le(transfer_data + 4, transfer_lamports);

    uint8_t account_indices[2] = {0, 1};          /* payer, recipient */
    sol_compiled_instruction_t instr = {
        .program_id_index = 2,                    /* system program */
        .account_indices = account_indices,
        .account_indices_len = 2,
        .data = transfer_data,
        .data_len = (uint16_t)sizeof(transfer_data),
    };

    sol_pubkey_t keys[3] = { payer_pubkey, recipient_pubkey, SOL_SYSTEM_PROGRAM_ID };

    sol_message_t msg;
    sol_message_init(&msg);
    msg.version = SOL_MESSAGE_VERSION_LEGACY;
    msg.header.num_required_signatures = 1;
    msg.header.num_readonly_signed = 0;
    msg.header.num_readonly_unsigned = 1;         /* system program */
    msg.account_keys = keys;
    msg.account_keys_len = 3;
    memset(&msg.recent_blockhash, 0, sizeof(msg.recent_blockhash));
    msg.instructions = &instr;
    msg.instructions_len = 1;

    uint8_t msg_buf[SOL_MAX_TX_SIZE];
    sol_encoder_t msg_enc;
    sol_encoder_init(&msg_enc, msg_buf, sizeof(msg_buf));
    sol_err_t err = sol_message_encode_legacy(&msg_enc, &msg);
    if (err != SOL_OK) {
        conf_suite_destroy(txn_suite);
        return 1;
    }
    size_t msg_len = sol_encoder_len(&msg_enc);

    sol_signature_t sig;
    sol_ed25519_sign(&payer_keypair, msg_buf, msg_len, &sig);

    sol_signature_t sigs[1] = { sig };
    sol_transaction_t tx;
    sol_transaction_init(&tx);
    tx.signatures = sigs;
    tx.signatures_len = 1;
    tx.message = msg;

    uint8_t tx_buf[SOL_MAX_TX_SIZE];
    size_t tx_len = 0;
    err = sol_transaction_encode(&tx, tx_buf, sizeof(tx_buf), &tx_len);
    if (err != SOL_OK) {
        conf_suite_destroy(txn_suite);
        return 1;
    }

    uint8_t input[4096];
    uint8_t* ip = input;

    write_u64_le(ip, 0);                           /* slot */
    ip += 8;
    write_u32_le(ip, 2);                           /* num_accounts */
    ip += 4;

    /* Payer account */
    memcpy(ip, payer_pubkey.bytes, 32);
    ip += 32;
    write_u64_le(ip, initial_payer_lamports);
    ip += 8;
    write_u64_le(ip, 0);                           /* data_len */
    ip += 8;
    memcpy(ip, SOL_SYSTEM_PROGRAM_ID.bytes, 32);   /* owner */
    ip += 32;
    *ip++ = 0;                                     /* executable */
    write_u64_le(ip, 0);                           /* rent_epoch */
    ip += 8;

    /* Recipient account */
    memcpy(ip, recipient_pubkey.bytes, 32);
    ip += 32;
    write_u64_le(ip, initial_recipient_lamports);
    ip += 8;
    write_u64_le(ip, 0);                           /* data_len */
    ip += 8;
    memcpy(ip, SOL_SYSTEM_PROGRAM_ID.bytes, 32);   /* owner */
    ip += 32;
    *ip++ = 0;                                     /* executable */
    write_u64_le(ip, 0);                           /* rent_epoch */
    ip += 8;

    write_u32_le(ip, (uint32_t)tx_len);
    ip += 4;
    memcpy(ip, tx_buf, tx_len);
    ip += tx_len;

    txn_transfer_expect_t expect = {
        .payer = payer_pubkey,
        .recipient = recipient_pubkey,
        .payer_lamports = initial_payer_lamports - transfer_lamports - fee_lamports,
        .recipient_lamports = initial_recipient_lamports + transfer_lamports,
    };

    conf_suite_add_fixture(
        txn_suite,
        "system_transfer",
        input,
        (size_t)(ip - input),
        NULL,
        0
    );

    conf_config_t txn_config = {
        .test_fn = conf_test_txn_execute,
        .compare_fn = compare_txn_transfer_output,
        .ctx = &expect,
        .verbose = verbose,
        .stop_on_fail = false,
        .output = stdout,
    };

    results = conf_suite_run(txn_suite, &txn_config);
    conf_suite_destroy(txn_suite);

    if (results.failed > 0 || results.errors > 0) {
        printf("\nTransaction execution self-test FAILED\n");
        return 1;
    }

    printf("\nTransaction execution self-test PASSED\n");

    printf("\n=== Running Fork Choice Self-Test ===\n\n");

    sol_bank_t* root_bank = sol_bank_new(0, NULL, NULL, NULL);
    if (root_bank == NULL) {
        fprintf(stderr, "Failed to create root bank\n");
        return 1;
    }

    sol_bank_forks_t* forks = sol_bank_forks_new(root_bank, NULL);
    if (forks == NULL) {
        fprintf(stderr, "Failed to create bank forks\n");
        sol_bank_destroy(root_bank);
        return 1;
    }

    /* Create a fork:
     *   0 -> 1 -> 3
     *   0 -> 2 -> 4
     */
    sol_bank_forks_new_from_parent(forks, 0, 1);
    sol_bank_forks_new_from_parent(forks, 1, 3);
    sol_bank_forks_new_from_parent(forks, 0, 2);
    sol_bank_forks_new_from_parent(forks, 2, 4);

    sol_fork_choice_t* fc = sol_fork_choice_new(forks, NULL);
    if (fc == NULL) {
        fprintf(stderr, "Failed to create fork choice\n");
        sol_bank_forks_destroy(forks);
        return 1;
    }

    sol_pubkey_t v1, v2;
    memset(v1.bytes, 0x11, 32);
    memset(v2.bytes, 0x22, 32);

    /* Only vote on leaf slots: intermediate slots have no direct stake */
    sol_fork_choice_record_vote(fc, &v1, 3, 1000);
    sol_fork_choice_record_vote(fc, &v2, 4, 2000);

    sol_slot_t best = sol_fork_choice_best_slot(fc);
    if (best != 4) {
        fprintf(stderr, "Fork choice self-test FAILED (best=%llu)\n",
                (unsigned long long)best);
        sol_fork_choice_destroy(fc);
        sol_bank_forks_destroy(forks);
        return 1;
    }

    if (sol_fork_choice_subtree_weight(fc, 1) != 1000 ||
        sol_fork_choice_subtree_weight(fc, 2) != 2000) {
        fprintf(stderr, "Fork choice self-test FAILED (subtree weights)\n");
        sol_fork_choice_destroy(fc);
        sol_bank_forks_destroy(forks);
        return 1;
    }

    sol_fork_choice_destroy(fc);
    sol_bank_forks_destroy(forks);

    if (verbose) {
        printf("Fork choice self-test PASSED\n");
    }

    return 0;
}

typedef struct {
    const char*    name;
    conf_test_fn   test_fn;
} component_t;

static const component_t COMPONENTS[] = {
    { "txn",       conf_test_txn_execute  },
    { "bpf",       conf_test_bpf_execute  },
    { "syscall",   conf_test_syscall      },
    { "shred",     conf_test_shred_parse  },
    { "serialize", conf_test_serialize    },
    { "blockstore", conf_test_blockstore_assemble },
};

#define NUM_COMPONENTS (sizeof(COMPONENTS) / sizeof(COMPONENTS[0]))

static void
print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s [options] [fixture_dir] [component]\n", prog);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -v, --verbose     Verbose output\n");
    fprintf(stderr, "  -s, --stop        Stop on first failure\n");
    fprintf(stderr, "  -h, --help        Show this help\n");
    fprintf(stderr, "\nComponents:\n");
    fprintf(stderr, "  all       Run all conformance tests (default)\n");
    fprintf(stderr, "  selftest  Run built-in self-tests (no fixtures needed)\n");
    for (size_t i = 0; i < NUM_COMPONENTS; i++) {
        fprintf(stderr, "  %-10s %s tests\n",
                COMPONENTS[i].name, COMPONENTS[i].name);
    }
    fprintf(stderr, "\nExample:\n");
    fprintf(stderr, "  %s ./fixtures txn\n", prog);
    fprintf(stderr, "  %s -v ./fixtures all\n", prog);
    fprintf(stderr, "  %s selftest\n", prog);
}

static int
run_component_tests(
    const char*      fixture_dir,
    const component_t* comp,
    const conf_config_t* base_config
) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", fixture_dir, comp->name);

    /* Create suite */
    conf_suite_t* suite = conf_suite_new(comp->name);
    if (suite == NULL) {
        fprintf(stderr, "Failed to create suite for %s\n", comp->name);
        return 1;
    }

    /* Try to load fixtures */
    sol_err_t err = conf_suite_load(suite, path);
    if (err != SOL_OK) {
        if (base_config->verbose) {
            fprintf(stderr, "No fixtures found for %s at %s\n", comp->name, path);
        }
        conf_suite_destroy(suite);
        return 0;  /* Not an error - just no tests */
    }

    /* Configure test */
    conf_config_t config = *base_config;
    config.test_fn = comp->test_fn;
    config.compare_fn = conf_compare_bytes;

    /* Run tests */
    conf_results_t results = conf_suite_run(suite, &config);

    conf_suite_destroy(suite);

    return results.failed > 0 || results.errors > 0 ? 1 : 0;
}

int
main(int argc, char* argv[]) {
    /* Initialize logging with defaults */
    sol_log_init(NULL);

    /* Parse options */
    bool verbose = false;
    bool stop_on_fail = false;
    const char* fixture_dir = NULL;
    const char* component = "all";

    int arg_idx = 1;
    while (arg_idx < argc && argv[arg_idx][0] == '-') {
        const char* opt = argv[arg_idx];
        if (strcmp(opt, "-v") == 0 || strcmp(opt, "--verbose") == 0) {
            verbose = true;
        } else if (strcmp(opt, "-s") == 0 || strcmp(opt, "--stop") == 0) {
            stop_on_fail = true;
        } else if (strcmp(opt, "-h") == 0 || strcmp(opt, "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", opt);
            print_usage(argv[0]);
            return 1;
        }
        arg_idx++;
    }

    /* Parse positional arguments - check if first arg is a component name */
    if (arg_idx < argc) {
        const char* first_arg = argv[arg_idx];

        /* Check if it's selftest (special case) */
        if (strcmp(first_arg, "selftest") == 0) {
            return run_selftest(verbose);
        }

        /* Check if it's a known component name */
        bool is_component = strcmp(first_arg, "all") == 0;
        for (size_t i = 0; i < NUM_COMPONENTS && !is_component; i++) {
            if (strcmp(COMPONENTS[i].name, first_arg) == 0) {
                is_component = true;
            }
        }

        if (is_component && arg_idx + 1 >= argc) {
            /* Single arg is a component, no fixture dir specified */
            component = first_arg;
            arg_idx++;
        } else {
            /* Treat first arg as fixture dir */
            fixture_dir = argv[arg_idx++];
            if (arg_idx < argc) {
                component = argv[arg_idx++];
            }
        }
    }

    /* Require fixture directory */
    if (fixture_dir == NULL) {
        /* Check for default locations */
        static const char* defaults[] = {
            "./fixtures",
            "../fixtures",
            "../../fixtures",
            "./tests/conformance/fixtures",
            NULL
        };

        for (const char** p = defaults; *p != NULL; p++) {
            DIR* d = opendir(*p);
            if (d != NULL) {
                closedir(d);
                fixture_dir = *p;
                break;
            }
        }

        if (fixture_dir == NULL) {
            fprintf(stderr, "No fixture directory specified and no default found.\n");
            fprintf(stderr, "Please specify a fixture directory or create ./fixtures\n\n");
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Set up base config */
    conf_config_t config = {
        .test_fn = NULL,
        .compare_fn = conf_compare_bytes,
        .ctx = NULL,
        .verbose = verbose,
        .stop_on_fail = stop_on_fail,
        .output = stdout,
    };

    printf("Conformance Test Runner\n");
    printf("Fixture directory: %s\n", fixture_dir ? fixture_dir : "(none)");
    printf("Component: %s\n", component);
    printf("Verbose: %s\n", verbose ? "yes" : "no");
    printf("\n");

    /* Check for fixture directory (not needed for selftest) */
    if (fixture_dir == NULL) {
        printf("No fixture directory found. Running self-test instead.\n");
        return run_selftest(verbose);
    }

    int exit_code = 0;

    if (strcmp(component, "all") == 0) {
        /* Run all components */
        for (size_t i = 0; i < NUM_COMPONENTS; i++) {
            int rc = run_component_tests(fixture_dir, &COMPONENTS[i], &config);
            if (rc != 0) {
                exit_code = 1;
                if (stop_on_fail) {
                    break;
                }
            }
        }
    } else {
        /* Find specific component */
        const component_t* comp = NULL;
        for (size_t i = 0; i < NUM_COMPONENTS; i++) {
            if (strcmp(COMPONENTS[i].name, component) == 0) {
                comp = &COMPONENTS[i];
                break;
            }
        }

        if (comp == NULL) {
            fprintf(stderr, "Unknown component: %s\n", component);
            print_usage(argv[0]);
            return 1;
        }

        exit_code = run_component_tests(fixture_dir, comp, &config);
    }

    printf("\nConformance testing complete.\n");
    return exit_code;
}
