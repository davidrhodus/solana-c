/*
 * test_framework.h - Lightweight C testing framework
 */

#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>

/*
 * Test state
 */
static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;
static int g_tests_skipped = 0;
static const char* g_current_test = NULL;
static bool g_test_skipped = false;

/*
 * Colors for output
 */
#define TEST_COLOR_RED     "\033[31m"
#define TEST_COLOR_GREEN   "\033[32m"
#define TEST_COLOR_YELLOW  "\033[33m"
#define TEST_COLOR_RESET   "\033[0m"

/*
 * Test function type
 */
typedef void (*test_fn_t)(void);

/*
 * Test case structure
 */
typedef struct {
    const char* name;
    test_fn_t   fn;
} test_case_t;

/*
 * Assertion macros
 */

#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "  " TEST_COLOR_RED "FAIL" TEST_COLOR_RESET \
                " %s:%d: Assertion failed: %s\n", \
                __FILE__, __LINE__, #cond); \
        g_tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_ASSERT_MSG(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "  " TEST_COLOR_RED "FAIL" TEST_COLOR_RESET \
                " %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        g_tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_ASSERT_EQ(a, b) do { \
    long long _a = (long long)(a); \
    long long _b = (long long)(b); \
    if (_a != _b) { \
        fprintf(stderr, "  " TEST_COLOR_RED "FAIL" TEST_COLOR_RESET \
                " %s:%d: Expected %lld == %lld\n", \
                __FILE__, __LINE__, _a, _b); \
        g_tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_ASSERT_NE(a, b) do { \
    long long _a = (long long)(a); \
    long long _b = (long long)(b); \
    if (_a == _b) { \
        fprintf(stderr, "  " TEST_COLOR_RED "FAIL" TEST_COLOR_RESET \
                " %s:%d: Expected %lld != %lld\n", \
                __FILE__, __LINE__, _a, _b); \
        g_tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_ASSERT_LT(a, b) do { \
    long long _a = (long long)(a); \
    long long _b = (long long)(b); \
    if (!(_a < _b)) { \
        fprintf(stderr, "  " TEST_COLOR_RED "FAIL" TEST_COLOR_RESET \
                " %s:%d: Expected %lld < %lld\n", \
                __FILE__, __LINE__, _a, _b); \
        g_tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_ASSERT_LE(a, b) do { \
    long long _a = (long long)(a); \
    long long _b = (long long)(b); \
    if (!(_a <= _b)) { \
        fprintf(stderr, "  " TEST_COLOR_RED "FAIL" TEST_COLOR_RESET \
                " %s:%d: Expected %lld <= %lld\n", \
                __FILE__, __LINE__, _a, _b); \
        g_tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_ASSERT_GT(a, b) TEST_ASSERT_LT(b, a)
#define TEST_ASSERT_GE(a, b) TEST_ASSERT_LE(b, a)

#define TEST_ASSERT_NULL(p) do { \
    if ((p) != NULL) { \
        fprintf(stderr, "  " TEST_COLOR_RED "FAIL" TEST_COLOR_RESET \
                " %s:%d: Expected NULL, got %p\n", \
                __FILE__, __LINE__, (void*)(p)); \
        g_tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_ASSERT_NOT_NULL(p) do { \
    if ((p) == NULL) { \
        fprintf(stderr, "  " TEST_COLOR_RED "FAIL" TEST_COLOR_RESET \
                " %s:%d: Expected non-NULL\n", \
                __FILE__, __LINE__); \
        g_tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_ASSERT_STR_EQ(a, b) do { \
    const char* _a = (a); \
    const char* _b = (b); \
    if (_a == NULL || _b == NULL || strcmp(_a, _b) != 0) { \
        fprintf(stderr, "  " TEST_COLOR_RED "FAIL" TEST_COLOR_RESET \
                " %s:%d: Expected \"%s\" == \"%s\"\n", \
                __FILE__, __LINE__, _a ? _a : "(null)", _b ? _b : "(null)"); \
        g_tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_ASSERT_MEM_EQ(a, b, len) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        fprintf(stderr, "  " TEST_COLOR_RED "FAIL" TEST_COLOR_RESET \
                " %s:%d: Memory comparison failed\n", \
                __FILE__, __LINE__); \
        g_tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_ASSERT_FLOAT_EQ(a, b, eps) do { \
    double _a = (double)(a); \
    double _b = (double)(b); \
    if (fabs(_a - _b) > (eps)) { \
        fprintf(stderr, "  " TEST_COLOR_RED "FAIL" TEST_COLOR_RESET \
                " %s:%d: Expected %f == %f (eps=%f)\n", \
                __FILE__, __LINE__, _a, _b, (double)(eps)); \
        g_tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_SKIP(msg) do { \
    fprintf(stderr, "  " TEST_COLOR_YELLOW "SKIP" TEST_COLOR_RESET \
            " %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
    g_test_skipped = true; \
    return; \
} while(0)

/*
 * Run a single test
 */
static inline void
run_test(const char* name, test_fn_t fn) {
    g_current_test = name;
    g_tests_run++;
    g_test_skipped = false;
    int failed_before = g_tests_failed;

    printf("  Running %s... ", name);
    fflush(stdout);

    fn();

    if (g_test_skipped) {
        g_tests_skipped++;
        printf(TEST_COLOR_YELLOW "SKIP" TEST_COLOR_RESET "\n");
        return;
    }

    if (g_tests_failed == failed_before) {
        g_tests_passed++;
        printf(TEST_COLOR_GREEN "PASS" TEST_COLOR_RESET "\n");
    }
}

/*
 * Run all tests in array
 */
static inline int
run_tests(const char* suite_name, test_case_t* tests, size_t count) {
    printf("\n=== %s ===\n", suite_name);

    for (size_t i = 0; i < count; i++) {
        run_test(tests[i].name, tests[i].fn);
    }

    printf("\n");
    printf("Results: %d/%d passed", g_tests_passed, g_tests_run);
    if (g_tests_skipped > 0) {
        printf(" (%d skipped)", g_tests_skipped);
    }
    if (g_tests_failed > 0) {
        printf(" (" TEST_COLOR_RED "%d failed" TEST_COLOR_RESET ")", g_tests_failed);
    }
    printf("\n\n");

    return g_tests_failed;
}

/*
 * Macros for defining tests
 */
#define TEST(name) static void test_##name(void)

#define TEST_CASE(name) { #name, test_##name }

#define RUN_TESTS(suite, tests) \
    run_tests((suite), (tests), sizeof(tests) / sizeof(tests[0]))

#endif /* TEST_FRAMEWORK_H */
