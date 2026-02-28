/*
 * test_config.c - Config parser unit tests
 */

#include "../test_framework.h"
#include "sol_config.h"
#include "sol_alloc.h"
#include <stddef.h>

static void
free_string_array(char** arr, size_t count) {
    if (!arr) return;
    for (size_t i = 0; i < count; i++) {
        sol_free(arr[i]);
    }
    sol_free(arr);
}

TEST(config_string_array_multiline) {
    const char* text =
        "[snapshots]\n"
        "rpc_urls = [\n"
        "  \"http://one\",\n"
        "  \"http://two\"\n"
        "]\n";

    sol_config_t* cfg = NULL;
    TEST_ASSERT_EQ(sol_config_parse(text, 0, &cfg), SOL_OK);

    char** urls = NULL;
    size_t count = 0;
    TEST_ASSERT_EQ(sol_config_get_string_array(cfg, "snapshots", "rpc_urls", &urls, &count), SOL_OK);
    TEST_ASSERT_EQ(count, 2);
    TEST_ASSERT_STR_EQ(urls[0], "http://one");
    TEST_ASSERT_STR_EQ(urls[1], "http://two");

    free_string_array(urls, count);
    sol_config_destroy(cfg);
}

TEST(config_string_array_single_line) {
    const char* text =
        "[snapshots]\n"
        "rpc_urls = [\"http://alpha\", \"http://beta\"]\n";

    sol_config_t* cfg = NULL;
    TEST_ASSERT_EQ(sol_config_parse(text, 0, &cfg), SOL_OK);

    char** urls = NULL;
    size_t count = 0;
    TEST_ASSERT_EQ(sol_config_get_string_array(cfg, "snapshots", "rpc_urls", &urls, &count), SOL_OK);
    TEST_ASSERT_EQ(count, 2);
    TEST_ASSERT_STR_EQ(urls[0], "http://alpha");
    TEST_ASSERT_STR_EQ(urls[1], "http://beta");

    free_string_array(urls, count);
    sol_config_destroy(cfg);
}

static test_case_t config_tests[] = {
    TEST_CASE(config_string_array_multiline),
    TEST_CASE(config_string_array_single_line),
};

int
main(void) {
    return RUN_TESTS("Config Tests", config_tests);
}
