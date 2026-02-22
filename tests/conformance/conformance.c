/*
 * conformance.c - Conformance testing harness implementation
 */

#include "conformance.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>

/*
 * Create new test suite
 */
conf_suite_t*
conf_suite_new(const char* name) {
    conf_suite_t* suite = sol_calloc(1, sizeof(conf_suite_t));
    if (suite == NULL) {
        return NULL;
    }

    if (name != NULL) {
        size_t len = strlen(name);
        suite->name = sol_alloc(len + 1);
        if (suite->name == NULL) {
            sol_free(suite);
            return NULL;
        }
        memcpy(suite->name, name, len + 1);
    }

    suite->fixtures = NULL;
    suite->fixture_count = 0;
    suite->fixture_cap = 0;

    return suite;
}

/*
 * Destroy test suite
 */
void
conf_suite_destroy(conf_suite_t* suite) {
    if (suite == NULL) {
        return;
    }

    /* Free fixtures */
    for (size_t i = 0; i < suite->fixture_count; i++) {
        conf_fixture_t* f = &suite->fixtures[i];
        sol_free(f->name);
        sol_free(f->input);
        sol_free(f->expected);
    }
    sol_free(suite->fixtures);

    sol_free(suite->name);
    sol_free(suite->fixture_dir);
    sol_free(suite);
}

/*
 * Grow fixtures array
 */
static sol_err_t
suite_grow(conf_suite_t* suite) {
    size_t new_cap = suite->fixture_cap == 0 ? 16 : suite->fixture_cap * 2;

    conf_fixture_t* new_fixtures = sol_realloc(
        suite->fixtures,
        new_cap * sizeof(conf_fixture_t)
    );

    if (new_fixtures == NULL) {
        return SOL_ERR_NOMEM;
    }

    suite->fixtures = new_fixtures;
    suite->fixture_cap = new_cap;
    return SOL_OK;
}

/*
 * Load binary file
 */
sol_err_t
conf_load_file(const char* path, uint8_t** data, size_t* len) {
    if (path == NULL || data == NULL || len == NULL) {
        return SOL_ERR_INVAL;
    }

    FILE* f = fopen(path, "rb");
    if (f == NULL) {
        return SOL_ERR_IO;
    }

    /* Get file size */
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return SOL_ERR_IO;
    }

    long size = ftell(f);
    if (size < 0) {
        fclose(f);
        return SOL_ERR_IO;
    }

    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return SOL_ERR_IO;
    }

    /* Allocate buffer */
    *data = sol_alloc((size_t)size);
    if (*data == NULL) {
        fclose(f);
        return SOL_ERR_NOMEM;
    }

    /* Read file */
    size_t read = fread(*data, 1, (size_t)size, f);
    fclose(f);

    if (read != (size_t)size) {
        sol_free(*data);
        *data = NULL;
        return SOL_ERR_IO;
    }

    *len = (size_t)size;
    return SOL_OK;
}

/*
 * Extract test name from filename
 * e.g., "test_foo.input" -> "test_foo"
 */
static char*
extract_test_name(const char* filename) {
    size_t len = strlen(filename);

    /* Find last dot */
    const char* dot = strrchr(filename, '.');
    if (dot == NULL) {
        dot = filename + len;
    }

    size_t name_len = (size_t)(dot - filename);
    char* name = sol_alloc(name_len + 1);
    if (name == NULL) {
        return NULL;
    }

    memcpy(name, filename, name_len);
    name[name_len] = '\0';
    return name;
}

/*
 * Check if file has extension
 */
static bool
has_extension(const char* filename, const char* ext) {
    size_t fname_len = strlen(filename);
    size_t ext_len = strlen(ext);

    if (fname_len < ext_len + 1) {
        return false;
    }

    return strcmp(filename + fname_len - ext_len, ext) == 0;
}

/*
 * Find fixture by name
 */
static conf_fixture_t*
find_fixture(conf_suite_t* suite, const char* name) {
    for (size_t i = 0; i < suite->fixture_count; i++) {
        if (strcmp(suite->fixtures[i].name, name) == 0) {
            return &suite->fixtures[i];
        }
    }
    return NULL;
}

/*
 * Load fixtures from directory
 */
sol_err_t
conf_suite_load(conf_suite_t* suite, const char* fixture_dir) {
    if (suite == NULL || fixture_dir == NULL) {
        return SOL_ERR_INVAL;
    }

    /* Store fixture directory */
    size_t dir_len = strlen(fixture_dir);
    suite->fixture_dir = sol_alloc(dir_len + 1);
    if (suite->fixture_dir == NULL) {
        return SOL_ERR_NOMEM;
    }
    memcpy(suite->fixture_dir, fixture_dir, dir_len + 1);

    DIR* dir = opendir(fixture_dir);
    if (dir == NULL) {
        return SOL_ERR_IO;
    }

    struct dirent* entry;
    char path_buf[1024];

    while ((entry = readdir(dir)) != NULL) {
        /* Skip directories */
        if (entry->d_type == DT_DIR) {
            continue;
        }

        const char* filename = entry->d_name;
        bool is_input = has_extension(filename, ".input");
        bool is_output = has_extension(filename, ".output");

        if (!is_input && !is_output) {
            continue;
        }

        /* Extract test name */
        char* test_name = extract_test_name(filename);
        if (test_name == NULL) {
            closedir(dir);
            return SOL_ERR_NOMEM;
        }

        /* Build full path */
        snprintf(path_buf, sizeof(path_buf), "%s/%s", fixture_dir, filename);

        /* Load file data */
        uint8_t* data = NULL;
        size_t data_len = 0;
        sol_err_t err = conf_load_file(path_buf, &data, &data_len);
        if (err != SOL_OK) {
            sol_free(test_name);
            closedir(dir);
            return err;
        }

        /* Find or create fixture */
        conf_fixture_t* fixture = find_fixture(suite, test_name);
        if (fixture == NULL) {
            /* Create new fixture */
            if (suite->fixture_count >= suite->fixture_cap) {
                err = suite_grow(suite);
                if (err != SOL_OK) {
                    sol_free(test_name);
                    sol_free(data);
                    closedir(dir);
                    return err;
                }
            }

            fixture = &suite->fixtures[suite->fixture_count++];
            memset(fixture, 0, sizeof(*fixture));
            fixture->name = test_name;
        } else {
            sol_free(test_name);
        }

        /* Store data */
        if (is_input) {
            fixture->input = data;
            fixture->input_len = data_len;
        } else {
            fixture->expected = data;
            fixture->expected_len = data_len;
        }
    }

    closedir(dir);
    return SOL_OK;
}

/*
 * Add single fixture manually
 */
sol_err_t
conf_suite_add_fixture(
    conf_suite_t* suite,
    const char*   name,
    const uint8_t* input,
    size_t        input_len,
    const uint8_t* expected,
    size_t        expected_len
) {
    if (suite == NULL || name == NULL) {
        return SOL_ERR_INVAL;
    }

    /* Grow if needed */
    if (suite->fixture_count >= suite->fixture_cap) {
        sol_err_t err = suite_grow(suite);
        if (err != SOL_OK) {
            return err;
        }
    }

    conf_fixture_t* fixture = &suite->fixtures[suite->fixture_count];
    memset(fixture, 0, sizeof(*fixture));

    /* Copy name */
    size_t name_len = strlen(name);
    fixture->name = sol_alloc(name_len + 1);
    if (fixture->name == NULL) {
        return SOL_ERR_NOMEM;
    }
    memcpy(fixture->name, name, name_len + 1);

    /* Copy input */
    if (input != NULL && input_len > 0) {
        fixture->input = sol_alloc(input_len);
        if (fixture->input == NULL) {
            sol_free(fixture->name);
            return SOL_ERR_NOMEM;
        }
        memcpy(fixture->input, input, input_len);
        fixture->input_len = input_len;
    }

    /* Copy expected */
    if (expected != NULL && expected_len > 0) {
        fixture->expected = sol_alloc(expected_len);
        if (fixture->expected == NULL) {
            sol_free(fixture->name);
            sol_free(fixture->input);
            return SOL_ERR_NOMEM;
        }
        memcpy(fixture->expected, expected, expected_len);
        fixture->expected_len = expected_len;
    }

    suite->fixture_count++;
    return SOL_OK;
}

/*
 * Default byte comparison
 */
bool
conf_compare_bytes(
    const uint8_t* expected,
    size_t         expected_len,
    const uint8_t* actual,
    size_t         actual_len,
    void*          ctx
) {
    (void)ctx;

    if (expected_len != actual_len) {
        return false;
    }

    if (expected_len == 0) {
        return true;
    }

    return memcmp(expected, actual, expected_len) == 0;
}

/*
 * Get result string
 */
const char*
conf_result_str(conf_result_t result) {
    switch (result) {
        case CONF_PASS:  return "PASS";
        case CONF_FAIL:  return "FAIL";
        case CONF_SKIP:  return "SKIP";
        case CONF_ERROR: return "ERROR";
        default:         return "UNKNOWN";
    }
}

/*
 * Run single fixture
 */
conf_result_t
conf_fixture_run(const conf_fixture_t* fixture, const conf_config_t* config) {
    if (fixture == NULL || config == NULL || config->test_fn == NULL) {
        return CONF_ERROR;
    }

    uint8_t* output = NULL;
    size_t output_len = 0;

    /* Execute test */
    sol_err_t err = config->test_fn(
        fixture->input,
        fixture->input_len,
        &output,
        &output_len,
        config->ctx
    );

    /* Check for skip (feature not implemented) */
    if (output == NULL && err == SOL_OK) {
        return CONF_SKIP;
    }

    if (err != SOL_OK) {
        if (config->verbose) {
            FILE* out = config->output ? config->output : stdout;
            fprintf(out, "\n    error: %d (%s)\n", err, sol_err_str(err));
        }
        sol_free(output);
        return CONF_ERROR;
    }

    /* Compare output */
    conf_compare_fn compare = config->compare_fn;
    if (compare == NULL) {
        compare = conf_compare_bytes;
    }

    bool match = compare(
        fixture->expected,
        fixture->expected_len,
        output,
        output_len,
        config->ctx
    );

    sol_free(output);
    return match ? CONF_PASS : CONF_FAIL;
}

/*
 * Run all fixtures in suite
 */
conf_results_t
conf_suite_run(conf_suite_t* suite, const conf_config_t* config) {
    conf_results_t results = { 0 };

    if (suite == NULL || config == NULL) {
        return results;
    }

    FILE* out = config->output ? config->output : stdout;

    fprintf(out, "\n=== Conformance Suite: %s ===\n",
            suite->name ? suite->name : "unnamed");
    fprintf(out, "Fixtures: %zu\n\n", suite->fixture_count);

    for (size_t i = 0; i < suite->fixture_count; i++) {
        conf_fixture_t* fixture = &suite->fixtures[i];
        results.total++;

        if (config->verbose) {
            fprintf(out, "  Running %s... ", fixture->name);
            fflush(out);
        }

        conf_result_t result = conf_fixture_run(fixture, config);

        switch (result) {
            case CONF_PASS:
                results.passed++;
                if (config->verbose) {
                    fprintf(out, "\033[32mPASS\033[0m\n");
                }
                break;

            case CONF_FAIL:
                results.failed++;
                if (config->verbose) {
                    fprintf(out, "\033[31mFAIL\033[0m\n");
                } else {
                    fprintf(out, "  FAIL: %s\n", fixture->name);
                }
                if (config->stop_on_fail) {
                    goto done;
                }
                break;

            case CONF_SKIP:
                results.skipped++;
                if (config->verbose) {
                    fprintf(out, "\033[33mSKIP\033[0m\n");
                }
                break;

            case CONF_ERROR:
                results.errors++;
                if (config->verbose) {
                    fprintf(out, "\033[35mERROR\033[0m\n");
                } else {
                    fprintf(out, "  ERROR: %s\n", fixture->name);
                }
                break;
        }
    }

done:
    fprintf(out, "\nResults: %zu passed, %zu failed, %zu skipped, %zu errors (total: %zu)\n",
            results.passed, results.failed, results.skipped, results.errors, results.total);

    return results;
}

/*
 * Include headers for conformance test implementations
 */
#include "sol_transaction.h"
#include "sol_shred.h"
#include "blockstore/sol_blockstore.h"
#include "sol_bank.h"
#include "sol_accounts_db.h"
#include "sol_account.h"
#include "sol_sha256.h"

/*
 * Simple fixture format for transaction execution:
 *
 * Input format (all little-endian):
 *   [8 bytes] slot
 *   [4 bytes] num_accounts
 *   For each account:
 *     [32 bytes] pubkey
 *     [8 bytes] lamports
 *     [8 bytes] data_len
 *     [data_len bytes] data
 *     [32 bytes] owner
 *     [1 byte] executable
 *     [8 bytes] rent_epoch
 *   [4 bytes] tx_len
 *   [tx_len bytes] transaction
 *
 * Output format:
 *   [4 bytes] status (sol_err_t as int32)
 *   [8 bytes] compute_units_used
 *   [4 bytes] num_accounts
 *   For each modified account:
 *     [32 bytes] pubkey
 *     [8 bytes] lamports
 *     [8 bytes] data_len
 *     [data_len bytes] data
 */

/*
 * Read uint32 little-endian from buffer
 */
static uint32_t
read_u32_le(const uint8_t* p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/*
 * Read uint64 little-endian from buffer
 */
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

/*
 * Write uint32 little-endian to buffer
 */
static void
write_u32_le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/*
 * Write uint64 little-endian to buffer
 */
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
 * Transaction execution conformance test
 */
sol_err_t
conf_test_txn_execute(
    const uint8_t* input,
    size_t         input_len,
    uint8_t**      output,
    size_t*        output_len,
    void*          ctx
) {
    (void)ctx;

    if (input == NULL || input_len < 12) {
        *output = NULL;
        *output_len = 0;
        return SOL_ERR_INVAL;
    }

    const uint8_t* p = input;
    const uint8_t* end = input + input_len;

    /* Read slot */
    if (p + 8 > end) goto truncated;
    sol_slot_t slot = read_u64_le(p);
    p += 8;

    /* Read account count */
    if (p + 4 > end) goto truncated;
    uint32_t num_accounts = read_u32_le(p);
    p += 4;

    /* Sanity check */
    if (num_accounts > 256) {
        return SOL_ERR_TOO_LARGE;
    }

    /* Create accounts DB and bank */
    sol_accounts_db_config_t db_config = SOL_ACCOUNTS_DB_CONFIG_DEFAULT;
    sol_accounts_db_t* db = sol_accounts_db_new(&db_config);
    if (db == NULL) {
        return SOL_ERR_NOMEM;
    }

    sol_bank_config_t bank_config = SOL_BANK_CONFIG_DEFAULT;
    sol_hash_t parent_hash = {0};
    sol_bank_t* bank = sol_bank_new(slot, &parent_hash, db, &bank_config);
    if (bank == NULL) {
        sol_accounts_db_destroy(db);
        return SOL_ERR_NOMEM;
    }

    /* Track pubkeys for output */
    sol_pubkey_t* pubkeys = sol_alloc(num_accounts * sizeof(sol_pubkey_t));
    if (pubkeys == NULL && num_accounts > 0) {
        sol_bank_destroy(bank);
        sol_accounts_db_destroy(db);
        return SOL_ERR_NOMEM;
    }

    /* Read and load accounts */
    for (uint32_t i = 0; i < num_accounts; i++) {
        /* Pubkey */
        if (p + 32 > end) goto truncated_cleanup;
        memcpy(&pubkeys[i], p, 32);
        p += 32;

        /* Lamports */
        if (p + 8 > end) goto truncated_cleanup;
        uint64_t lamports = read_u64_le(p);
        p += 8;

        /* Data length */
        if (p + 8 > end) goto truncated_cleanup;
        uint64_t data_len = read_u64_le(p);
        p += 8;

        /* Data */
        if (data_len > 10 * 1024 * 1024) goto truncated_cleanup; /* 10MB max */
        if (p + data_len > end) goto truncated_cleanup;
        const uint8_t* data = p;
        p += data_len;

        /* Owner */
        if (p + 32 > end) goto truncated_cleanup;
        sol_pubkey_t owner;
        memcpy(&owner, p, 32);
        p += 32;

        /* Executable */
        if (p + 1 > end) goto truncated_cleanup;
        bool executable = (*p++ != 0);

        /* Rent epoch */
        if (p + 8 > end) goto truncated_cleanup;
        uint64_t rent_epoch = read_u64_le(p);
        p += 8;

        /* Create and store account */
        sol_account_t* acc = sol_account_new(lamports, data_len, &owner);
        if (acc == NULL) goto truncated_cleanup;
        if (data_len > 0) {
            sol_account_set_data(acc, data, data_len);
        }
        acc->meta.executable = executable;
        acc->meta.rent_epoch = rent_epoch;

        sol_bank_store_account(bank, &pubkeys[i], acc);
        sol_account_destroy(acc);
    }

    /* Read transaction length */
    if (p + 4 > end) goto truncated_cleanup;
    uint32_t tx_len = read_u32_le(p);
    p += 4;

    /* Read transaction */
    if (p + tx_len > end) goto truncated_cleanup;
    sol_transaction_t tx;
    sol_err_t err = sol_transaction_decode(p, tx_len, &tx);
    if (err != SOL_OK) {
        sol_free(pubkeys);
        sol_bank_destroy(bank);
        sol_accounts_db_destroy(db);
        return err;
    }

    /* Execute transaction */
    sol_tx_result_t result = sol_bank_process_transaction(bank, &tx);

    /* Build output */
    /* Calculate output size */
    size_t out_size = 4 + 8 + 4;  /* status + compute_units + num_accounts */
    for (uint32_t i = 0; i < num_accounts; i++) {
        sol_account_t* acc = sol_bank_load_account(bank, &pubkeys[i]);
        if (acc != NULL) {
            out_size += 32 + 8 + 8 + acc->meta.data_len;
            sol_account_destroy(acc);
        }
    }

    *output = sol_alloc(out_size);
    if (*output == NULL) {
        sol_free(pubkeys);
        sol_bank_destroy(bank);
        sol_accounts_db_destroy(db);
        return SOL_ERR_NOMEM;
    }

    uint8_t* op = *output;

    /* Write status */
    write_u32_le(op, (uint32_t)(int32_t)result.status);
    op += 4;

    /* Write compute units */
    write_u64_le(op, result.compute_units_used);
    op += 8;

    /* Count modified accounts */
    uint32_t out_accounts = 0;
    for (uint32_t i = 0; i < num_accounts; i++) {
        sol_account_t* acc = sol_bank_load_account(bank, &pubkeys[i]);
        if (acc != NULL) {
            out_accounts++;
            sol_account_destroy(acc);
        }
    }

    write_u32_le(op, out_accounts);
    op += 4;

    /* Write accounts */
    for (uint32_t i = 0; i < num_accounts; i++) {
        sol_account_t* acc = sol_bank_load_account(bank, &pubkeys[i]);
        if (acc != NULL) {
            memcpy(op, &pubkeys[i], 32);
            op += 32;

            write_u64_le(op, acc->meta.lamports);
            op += 8;

            write_u64_le(op, acc->meta.data_len);
            op += 8;

            if (acc->meta.data_len > 0 && acc->data != NULL) {
                memcpy(op, acc->data, acc->meta.data_len);
                op += acc->meta.data_len;
            }

            sol_account_destroy(acc);
        }
    }

    *output_len = (size_t)(op - *output);

    sol_free(pubkeys);
    sol_bank_destroy(bank);
    sol_accounts_db_destroy(db);

    return SOL_OK;

truncated_cleanup:
    sol_free(pubkeys);
    sol_bank_destroy(bank);
    sol_accounts_db_destroy(db);
truncated:
    *output = NULL;
    *output_len = 0;
    return SOL_ERR_TRUNCATED;
}

/*
 * BPF execution conformance test
 *
 * BPF/SBF virtual machine execution is not yet implemented.
 * This test is skipped for now.
 */
sol_err_t
conf_test_bpf_execute(
    const uint8_t* input,
    size_t         input_len,
    uint8_t**      output,
    size_t*        output_len,
    void*          ctx
) {
    (void)input;
    (void)input_len;
    (void)ctx;

    /* BPF VM not implemented - signal skip */
    *output = NULL;
    *output_len = 0;
    return SOL_OK;
}

/*
 * Syscall conformance test
 *
 * Tests syscall behavior. Since we don't have a BPF VM, this tests
 * the crypto syscalls directly via their C implementations.
 *
 * Input format:
 *   [1 byte] syscall_id
 *   [remaining] syscall-specific parameters
 *
 * Syscall IDs:
 *   0 = sol_sha256 (input: data, output: 32-byte hash)
 *   1 = sol_ed25519_verify (input: pubkey(32) + msg_len(4) + msg + sig(64), output: 1 byte result)
 */
#include "sol_ed25519.h"

sol_err_t
conf_test_syscall(
    const uint8_t* input,
    size_t         input_len,
    uint8_t**      output,
    size_t*        output_len,
    void*          ctx
) {
    (void)ctx;

    if (input == NULL || input_len < 1) {
        *output = NULL;
        *output_len = 0;
        return SOL_ERR_INVAL;
    }

    uint8_t syscall_id = input[0];
    const uint8_t* data = input + 1;
    size_t data_len = input_len - 1;

    switch (syscall_id) {
    case 0: {
        /* SHA256 */
        *output = sol_alloc(32);
        if (*output == NULL) {
            return SOL_ERR_NOMEM;
        }

        sol_sha256_t hash;
        sol_sha256(data, data_len, &hash);
        memcpy(*output, hash.bytes, 32);
        *output_len = 32;
        return SOL_OK;
    }

    case 1: {
        /* Ed25519 verify */
        /* Format: pubkey(32) + msg_len(4) + msg + sig(64) */
        if (data_len < 32 + 4 + 64) {
            *output = NULL;
            *output_len = 0;
            return SOL_ERR_TRUNCATED;
        }

        sol_pubkey_t pubkey;
        memcpy(&pubkey, data, 32);
        uint32_t msg_len = read_u32_le(data + 32);

        if (data_len < 32 + 4 + msg_len + 64) {
            *output = NULL;
            *output_len = 0;
            return SOL_ERR_TRUNCATED;
        }

        const uint8_t* msg = data + 36;
        sol_signature_t sig;
        memcpy(&sig, data + 36 + msg_len, 64);

        bool valid = sol_ed25519_verify(&pubkey, msg, msg_len, &sig);

        *output = sol_alloc(1);
        if (*output == NULL) {
            return SOL_ERR_NOMEM;
        }

        (*output)[0] = valid ? 1 : 0;
        *output_len = 1;
        return SOL_OK;
    }

    default:
        /* Unknown syscall - skip */
        *output = NULL;
        *output_len = 0;
        return SOL_OK;
    }
}

/*
 * Shred parsing conformance test
 *
 * Input format:
 *   Raw shred bytes
 *
 * Output format:
 *   [1 byte] type (0=data, 1=code)
 *   [1 byte] variant
 *   [8 bytes] slot
 *   [4 bytes] index
 *   [2 bytes] version
 *   [4 bytes] fec_set_index
 *   For data shreds:
 *     [8 bytes] parent_slot
 *     [1 byte] flags
 *     [2 bytes] data_size
 *   For code shreds:
 *     [2 bytes] num_data_shreds
 *     [2 bytes] num_code_shreds
 *     [2 bytes] position
 *   [4 bytes] payload_len
 *   [payload_len bytes] payload
 */
sol_err_t
conf_test_shred_parse(
    const uint8_t* input,
    size_t         input_len,
    uint8_t**      output,
    size_t*        output_len,
    void*          ctx
) {
    (void)ctx;

    if (input == NULL || input_len < SOL_SHRED_HEADER_SIZE) {
        *output = NULL;
        *output_len = 0;
        return SOL_ERR_TRUNCATED;
    }

    /* Parse shred */
    sol_shred_t shred;
    sol_err_t err = sol_shred_parse(&shred, input, input_len);
    if (err != SOL_OK) {
        *output = NULL;
        *output_len = 0;
        return err;
    }

    /* Calculate output size */
    size_t out_size = 1 + 1 + 8 + 4 + 2 + 4;  /* type, variant, slot, index, version, fec_set_index */
    if (shred.type == SOL_SHRED_TYPE_DATA) {
        out_size += 8 + 1 + 2;  /* parent_slot, flags, data_size */
    } else {
        out_size += 2 + 2 + 2;  /* num_data, num_code, position */
    }
    out_size += 4 + shred.payload_len;  /* payload_len + payload */

    /* Allocate output */
    *output = sol_alloc(out_size);
    if (*output == NULL) {
        return SOL_ERR_NOMEM;
    }

    uint8_t* op = *output;

    /* Write type */
    *op++ = (uint8_t)shred.type;

    /* Write variant from raw data */
    *op++ = input[64];  /* Variant is at offset 64 (after signature) */

    /* Write slot */
    write_u64_le(op, shred.slot);
    op += 8;

    /* Write index */
    write_u32_le(op, shred.index);
    op += 4;

    /* Write version */
    op[0] = (uint8_t)(shred.version);
    op[1] = (uint8_t)(shred.version >> 8);
    op += 2;

    /* Write fec_set_index */
    write_u32_le(op, shred.fec_set_index);
    op += 4;

    /* Write type-specific header */
    if (shred.type == SOL_SHRED_TYPE_DATA) {
        write_u64_le(op, shred.header.data.parent_slot);
        op += 8;
        *op++ = shred.header.data.flags;
        op[0] = (uint8_t)(shred.header.data.size);
        op[1] = (uint8_t)(shred.header.data.size >> 8);
        op += 2;
    } else {
        op[0] = (uint8_t)(shred.header.code.num_data_shreds);
        op[1] = (uint8_t)(shred.header.code.num_data_shreds >> 8);
        op += 2;
        op[0] = (uint8_t)(shred.header.code.num_code_shreds);
        op[1] = (uint8_t)(shred.header.code.num_code_shreds >> 8);
        op += 2;
        op[0] = (uint8_t)(shred.header.code.position);
        op[1] = (uint8_t)(shred.header.code.position >> 8);
        op += 2;
    }

    /* Write payload */
    write_u32_le(op, (uint32_t)shred.payload_len);
    op += 4;

    if (shred.payload_len > 0 && shred.payload != NULL) {
        memcpy(op, shred.payload, shred.payload_len);
        op += shred.payload_len;
    }

    *output_len = (size_t)(op - *output);
    return SOL_OK;
}

/*
 * Blockstore block assembly conformance test
 *
 * Input format (little-endian):
 *   [8 bytes] slot
 *   [4 bytes] num_shreds
 *   Repeated num_shreds times:
 *     [4 bytes] shred_len
 *     [shred_len bytes] raw shred bytes
 *
 * Output format:
 *   [assembled block bytes] (payload concatenation)
 */
sol_err_t
conf_test_blockstore_assemble(
    const uint8_t* input,
    size_t         input_len,
    uint8_t**      output,
    size_t*        output_len,
    void*          ctx
) {
    (void)ctx;

    if (!output || !output_len) {
        return SOL_ERR_INVAL;
    }

    *output = NULL;
    *output_len = 0;

    if (input == NULL || input_len < 12) {
        return SOL_ERR_TRUNCATED;
    }

    const uint8_t* p = input;
    const uint8_t* end = input + input_len;

    sol_slot_t slot = read_u64_le(p);
    p += 8;

    uint32_t num_shreds = read_u32_le(p);
    p += 4;

    if (num_shreds == 0) {
        return SOL_ERR_INVAL;
    }

    if (num_shreds > 8192) {
        return SOL_ERR_TOO_LARGE;
    }

    sol_blockstore_config_t cfg = SOL_BLOCKSTORE_CONFIG_DEFAULT;
    cfg.max_slots = 64;
    cfg.max_shreds_per_slot = 2048;
    cfg.enable_fec_recovery = true;
    cfg.storage_type = SOL_BLOCKSTORE_STORAGE_MEMORY;

    sol_blockstore_t* bs = sol_blockstore_new(&cfg);
    if (!bs) {
        return SOL_ERR_NOMEM;
    }

    for (uint32_t i = 0; i < num_shreds; i++) {
        if (p + 4 > end) {
            sol_blockstore_destroy(bs);
            return SOL_ERR_TRUNCATED;
        }

        uint32_t shred_len = read_u32_le(p);
        p += 4;

        if (shred_len == 0) {
            sol_blockstore_destroy(bs);
            return SOL_ERR_INVAL;
        }

        if ((size_t)shred_len > (size_t)(end - p)) {
            sol_blockstore_destroy(bs);
            return SOL_ERR_TRUNCATED;
        }

        sol_shred_t shred;
        sol_err_t err = sol_shred_parse(&shred, p, shred_len);
        if (err != SOL_OK) {
            sol_blockstore_destroy(bs);
            return err;
        }

        err = sol_blockstore_insert_shred(bs, &shred, p, shred_len);
        if (err != SOL_OK && err != SOL_ERR_EXISTS) {
            sol_blockstore_destroy(bs);
            return err;
        }

        p += shred_len;
    }

    sol_block_t* block = sol_blockstore_get_block(bs, slot);
    if (!block) {
        sol_blockstore_destroy(bs);
        return SOL_ERR_NOTFOUND;
    }

    if (block->data_len > 0) {
        *output = sol_alloc(block->data_len);
        if (!*output) {
            sol_block_destroy(block);
            sol_blockstore_destroy(bs);
            return SOL_ERR_NOMEM;
        }

        memcpy(*output, block->data, block->data_len);
        *output_len = block->data_len;
    }

    sol_block_destroy(block);
    sol_blockstore_destroy(bs);
    return SOL_OK;
}

/*
 * Serialization conformance test
 *
 * Tests round-trip serialization of various data types.
 *
 * Input format:
 *   [1 byte] type_id
 *   [remaining] type-specific data
 *
 * Type IDs:
 *   0 = Transaction (input is raw tx, output is re-serialized tx)
 *   1 = Message (input is raw message, output is re-serialized message)
 *   2 = Pubkey (input is 32 bytes, output is 32 bytes)
 *   3 = Signature (input is 64 bytes, output is 64 bytes)
 *   4 = Hash (input is 32 bytes, output is 32 bytes)
 *   5 = Account (custom format, round-trip)
 *
 * For most types, the output should be byte-identical to the input
 * if serialization is correct.
 */
sol_err_t
conf_test_serialize(
    const uint8_t* input,
    size_t         input_len,
    uint8_t**      output,
    size_t*        output_len,
    void*          ctx
) {
    (void)ctx;

    if (input == NULL || input_len < 1) {
        *output = NULL;
        *output_len = 0;
        return SOL_ERR_INVAL;
    }

    uint8_t type_id = input[0];
    const uint8_t* data = input + 1;
    size_t data_len = input_len - 1;

    switch (type_id) {
    case 0: {
        /* Transaction round-trip */
        sol_transaction_t tx;
        sol_err_t err = sol_transaction_decode(data, data_len, &tx);
        if (err != SOL_OK) {
            *output = NULL;
            *output_len = 0;
            return err;
        }

        /* Re-serialize */
        *output = sol_alloc(SOL_MAX_TX_SIZE);
        if (*output == NULL) {
            return SOL_ERR_NOMEM;
        }

        size_t written = 0;
        err = sol_transaction_encode(&tx, *output, SOL_MAX_TX_SIZE, &written);
        if (err != SOL_OK) {
            sol_free(*output);
            *output = NULL;
            *output_len = 0;
            return err;
        }

        *output_len = written;
        return SOL_OK;
    }

    case 2: {
        /* Pubkey round-trip (32 bytes) */
        if (data_len != 32) {
            *output = NULL;
            *output_len = 0;
            return SOL_ERR_INVAL;
        }

        *output = sol_alloc(32);
        if (*output == NULL) {
            return SOL_ERR_NOMEM;
        }

        memcpy(*output, data, 32);
        *output_len = 32;
        return SOL_OK;
    }

    case 3: {
        /* Signature round-trip (64 bytes) */
        if (data_len != 64) {
            *output = NULL;
            *output_len = 0;
            return SOL_ERR_INVAL;
        }

        *output = sol_alloc(64);
        if (*output == NULL) {
            return SOL_ERR_NOMEM;
        }

        memcpy(*output, data, 64);
        *output_len = 64;
        return SOL_OK;
    }

    case 4: {
        /* Hash round-trip (32 bytes) */
        if (data_len != 32) {
            *output = NULL;
            *output_len = 0;
            return SOL_ERR_INVAL;
        }

        *output = sol_alloc(32);
        if (*output == NULL) {
            return SOL_ERR_NOMEM;
        }

        memcpy(*output, data, 32);
        *output_len = 32;
        return SOL_OK;
    }

    case 5: {
        /*
         * Account serialization test
         * Input: lamports(8) + data_len(8) + data(n) + owner(32) + exec(1) + rent_epoch(8)
         * Output: same format
         */
        if (data_len < 8 + 8 + 32 + 1 + 8) {
            *output = NULL;
            *output_len = 0;
            return SOL_ERR_TRUNCATED;
        }

        const uint8_t* p = data;
        uint64_t lamports = read_u64_le(p);
        p += 8;

        uint64_t acc_data_len = read_u64_le(p);
        p += 8;

        if (acc_data_len > 10 * 1024 * 1024 || p + acc_data_len + 32 + 1 + 8 > data + data_len) {
            *output = NULL;
            *output_len = 0;
            return SOL_ERR_TRUNCATED;
        }

        const uint8_t* acc_data = p;
        p += acc_data_len;

        sol_pubkey_t owner;
        memcpy(&owner, p, 32);
        p += 32;

        bool executable = (*p++ != 0);

        uint64_t rent_epoch = read_u64_le(p);

        /* Create account */
        sol_account_t* acc = sol_account_new(lamports, acc_data_len, &owner);
        if (acc == NULL) {
            return SOL_ERR_NOMEM;
        }
        if (acc_data_len > 0) {
            sol_account_set_data(acc, acc_data, acc_data_len);
        }
        acc->meta.executable = executable;
        acc->meta.rent_epoch = rent_epoch;

        /* Serialize back */
        size_t out_size = 8 + 8 + acc->meta.data_len + 32 + 1 + 8;
        *output = sol_alloc(out_size);
        if (*output == NULL) {
            sol_account_destroy(acc);
            return SOL_ERR_NOMEM;
        }

        uint8_t* op = *output;
        write_u64_le(op, acc->meta.lamports);
        op += 8;

        write_u64_le(op, acc->meta.data_len);
        op += 8;

        if (acc->meta.data_len > 0 && acc->data != NULL) {
            memcpy(op, acc->data, acc->meta.data_len);
            op += acc->meta.data_len;
        }

        memcpy(op, &acc->meta.owner, 32);
        op += 32;

        *op++ = acc->meta.executable ? 1 : 0;

        write_u64_le(op, acc->meta.rent_epoch);
        op += 8;

        *output_len = out_size;

        sol_account_destroy(acc);
        return SOL_OK;
    }

    default:
        /* Unknown type - skip */
        *output = NULL;
        *output_len = 0;
        return SOL_OK;
    }
}
