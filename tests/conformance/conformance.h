/*
 * conformance.h - Conformance testing harness
 *
 * Infrastructure for validating implementation against Firedancer's
 * conformance test fixtures. Tests are organized by component and
 * loaded from protobuf fixtures.
 */

#ifndef CONFORMANCE_H
#define CONFORMANCE_H

#include "sol_base.h"
#include "sol_err.h"
#include "sol_alloc.h"
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>

/*
 * Test result codes
 */
typedef enum {
    CONF_PASS = 0,      /* Test passed */
    CONF_FAIL,          /* Test failed - output mismatch */
    CONF_SKIP,          /* Test skipped - feature not implemented */
    CONF_ERROR,         /* Test error - fixture load failed, etc. */
} conf_result_t;

/*
 * Test fixture - input/expected output pair
 */
typedef struct {
    char*    name;          /* Test name (from filename) */
    uint8_t* input;         /* Input data (protobuf encoded) */
    size_t   input_len;     /* Input data length */
    uint8_t* expected;      /* Expected output (protobuf encoded) */
    size_t   expected_len;  /* Expected output length */
} conf_fixture_t;

/*
 * Test suite - collection of related fixtures
 */
typedef struct {
    char*           name;           /* Suite name */
    char*           fixture_dir;    /* Directory containing fixtures */
    conf_fixture_t* fixtures;       /* Array of fixtures */
    size_t          fixture_count;  /* Number of fixtures */
    size_t          fixture_cap;    /* Capacity of fixtures array */
} conf_suite_t;

/*
 * Test execution callback
 *
 * Takes input fixture data, produces output.
 * Returns SOL_OK on success, error code on failure.
 * If output is NULL, test is skipped (feature not implemented).
 */
typedef sol_err_t (*conf_test_fn)(
    const uint8_t* input,
    size_t         input_len,
    uint8_t**      output,
    size_t*        output_len,
    void*          ctx
);

/*
 * Comparison callback
 *
 * Compares actual output to expected output.
 * Returns true if they match, false otherwise.
 */
typedef bool (*conf_compare_fn)(
    const uint8_t* expected,
    size_t         expected_len,
    const uint8_t* actual,
    size_t         actual_len,
    void*          ctx
);

/*
 * Test runner configuration
 */
typedef struct {
    conf_test_fn    test_fn;        /* Test execution function */
    conf_compare_fn compare_fn;     /* Output comparison function */
    void*           ctx;            /* User context */
    bool            verbose;        /* Print detailed output */
    bool            stop_on_fail;   /* Stop after first failure */
    FILE*           output;         /* Output stream (default: stdout) */
} conf_config_t;

/*
 * Test results
 */
typedef struct {
    size_t total;       /* Total tests run */
    size_t passed;      /* Tests passed */
    size_t failed;      /* Tests failed */
    size_t skipped;     /* Tests skipped */
    size_t errors;      /* Tests errored */
} conf_results_t;

/*
 * Suite lifecycle
 */

/* Create new test suite */
conf_suite_t* conf_suite_new(const char* name);

/* Destroy test suite */
void conf_suite_destroy(conf_suite_t* suite);

/* Load fixtures from directory */
sol_err_t conf_suite_load(conf_suite_t* suite, const char* fixture_dir);

/* Add single fixture manually */
sol_err_t conf_suite_add_fixture(
    conf_suite_t* suite,
    const char*   name,
    const uint8_t* input,
    size_t        input_len,
    const uint8_t* expected,
    size_t        expected_len
);

/*
 * Test execution
 */

/* Run all fixtures in suite */
conf_results_t conf_suite_run(conf_suite_t* suite, const conf_config_t* config);

/* Run single fixture */
conf_result_t conf_fixture_run(
    const conf_fixture_t* fixture,
    const conf_config_t*  config
);

/*
 * Default comparators
 */

/* Byte-exact comparison */
bool conf_compare_bytes(
    const uint8_t* expected,
    size_t         expected_len,
    const uint8_t* actual,
    size_t         actual_len,
    void*          ctx
);

/*
 * Utility functions
 */

/* Load binary file */
sol_err_t conf_load_file(const char* path, uint8_t** data, size_t* len);

/* Get result name */
const char* conf_result_str(conf_result_t result);

/*
 * Fixture naming conventions (Firedancer-compatible)
 *
 * Input files:  <test_name>.input
 * Output files: <test_name>.output
 *
 * Files are protobuf-encoded using Firedancer's conformance schemas.
 */

/*
 * Component-specific test harnesses
 */

/* Transaction processing conformance */
sol_err_t conf_test_txn_execute(
    const uint8_t* input,
    size_t         input_len,
    uint8_t**      output,
    size_t*        output_len,
    void*          ctx
);

/* BPF VM execution conformance */
sol_err_t conf_test_bpf_execute(
    const uint8_t* input,
    size_t         input_len,
    uint8_t**      output,
    size_t*        output_len,
    void*          ctx
);

/* Syscall conformance */
sol_err_t conf_test_syscall(
    const uint8_t* input,
    size_t         input_len,
    uint8_t**      output,
    size_t*        output_len,
    void*          ctx
);

/* Shred parsing conformance */
sol_err_t conf_test_shred_parse(
    const uint8_t* input,
    size_t         input_len,
    uint8_t**      output,
    size_t*        output_len,
    void*          ctx
);

/* Serialization conformance */
sol_err_t conf_test_serialize(
    const uint8_t* input,
    size_t         input_len,
    uint8_t**      output,
    size_t*        output_len,
    void*          ctx
);

/* Blockstore block assembly conformance */
sol_err_t conf_test_blockstore_assemble(
    const uint8_t* input,
    size_t         input_len,
    uint8_t**      output,
    size_t*        output_len,
    void*          ctx
);

#endif /* CONFORMANCE_H */
