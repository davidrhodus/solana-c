/*
 * sol_rpc_client.c - Minimal RPC client helpers
 */

#include "sol_rpc_client.h"
#include "sol_alloc.h"
#include "sol_json.h"
#include "../txn/sol_pubkey.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

static sol_err_t
run_process_capture_stdout(const char* const* argv, char** out, size_t* out_len) {
    if (!argv || !argv[0] || !out || !out_len) return SOL_ERR_INVAL;
    *out = NULL;
    *out_len = 0;

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        return SOL_ERR_IO;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return SOL_ERR_IO;
    }

    if (pid == 0) {
        close(pipefd[0]);
        (void)dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            (void)dup2(devnull, STDERR_FILENO);
            close(devnull);
        }

        execvp(argv[0], (char* const*)argv);
        _exit(127);
    }

    close(pipefd[1]);

    size_t cap = 64 * 1024;
    char* buf = sol_alloc(cap);
    if (!buf) {
        close(pipefd[0]);
        return SOL_ERR_NOMEM;
    }

    size_t len = 0;
    while (1) {
        if (len + 1 >= cap) {
            size_t new_cap = cap * 2;
            if (new_cap < cap) {
                sol_free(buf);
                close(pipefd[0]);
                return SOL_ERR_OVERFLOW;
            }
            char* new_buf = sol_realloc(buf, new_cap);
            if (!new_buf) {
                sol_free(buf);
                close(pipefd[0]);
                return SOL_ERR_NOMEM;
            }
            buf = new_buf;
            cap = new_cap;
        }

        ssize_t n = read(pipefd[0], buf + len, cap - len - 1);
        if (n < 0) {
            if (errno == EINTR) continue;
            sol_free(buf);
            close(pipefd[0]);
            return SOL_ERR_IO;
        }
        if (n == 0) break;
        len += (size_t)n;
    }

    close(pipefd[0]);
    buf[len] = '\0';

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        sol_free(buf);
        return SOL_ERR_IO;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        sol_free(buf);
        return SOL_ERR_IO;
    }

    *out = buf;
    *out_len = len;
    return SOL_OK;
}

static sol_err_t
rpc_post_json(const char* rpc_url,
              const char* request_json,
              uint32_t timeout_secs,
              char** out,
              size_t* out_len) {
    if (!rpc_url || rpc_url[0] == '\0' || !request_json || !out || !out_len) {
        return SOL_ERR_INVAL;
    }

    char timeout_buf[32];
    uint32_t timeout = timeout_secs ? timeout_secs : 10;
    snprintf(timeout_buf, sizeof(timeout_buf), "%u", timeout);

    const char* argv[] = {
        "curl",
        "-fsSL",
        "-m",
        timeout_buf,
        "-H",
        "Content-Type: application/json",
        "-X",
        "POST",
        "--data",
        request_json,
        rpc_url,
        NULL,
    };

    return run_process_capture_stdout(argv, out, out_len);
}

sol_err_t
sol_rpc_parse_cluster_nodes_shred_version(const char* json,
                                          size_t json_len,
                                          uint16_t* out_shred_version) {
    if (!json || !out_shred_version) return SOL_ERR_INVAL;
    *out_shred_version = 0;

    sol_json_parser_t p;
    sol_json_parser_init(&p, json, json_len);
    if (!sol_json_parser_object_begin(&p)) return SOL_ERR_DECODE;

    char key[64];
    while (sol_json_parser_key(&p, key, sizeof(key))) {
        if (strcmp(key, "result") != 0) {
            sol_json_parser_skip(&p);
            continue;
        }

        if (!sol_json_parser_array_begin(&p)) {
            sol_json_parser_skip(&p);
            continue;
        }

        while (!sol_json_parser_array_end(&p)) {
            if (!sol_json_parser_object_begin(&p)) {
                if (!sol_json_parser_skip(&p)) break;
                continue;
            }

            char k2[64];
            while (sol_json_parser_key(&p, k2, sizeof(k2))) {
                if (strcmp(k2, "shredVersion") == 0) {
                    uint64_t v = 0;
                    if (!sol_json_parser_uint(&p, &v)) {
                        sol_json_parser_skip(&p);
                        continue;
                    }
                    if (v == 0 || v > UINT16_MAX) {
                        return SOL_ERR_RANGE;
                    }
                    *out_shred_version = (uint16_t)v;
                    return SOL_OK;
                }
                sol_json_parser_skip(&p);
            }

            (void)sol_json_parser_object_end(&p);
        }
    }

    return SOL_ERR_NOTFOUND;
}

sol_err_t
sol_rpc_get_cluster_shred_version(const char* rpc_url,
                                  uint32_t timeout_secs,
                                  uint16_t* out_shred_version) {
    if (!rpc_url || !out_shred_version) return SOL_ERR_INVAL;

    const char* req =
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getClusterNodes\"}";

    char* resp = NULL;
    size_t resp_len = 0;
    sol_err_t err = rpc_post_json(rpc_url, req, timeout_secs, &resp, &resp_len);
    if (err != SOL_OK) return err;

    err = sol_rpc_parse_cluster_nodes_shred_version(resp, resp_len, out_shred_version);
    sol_free(resp);
    return err;
}

sol_err_t
sol_rpc_get_cluster_nodes_json(const char* rpc_url,
                               uint32_t timeout_secs,
                               char** out_json,
                               size_t* out_json_len) {
    if (!rpc_url || !out_json || !out_json_len) return SOL_ERR_INVAL;
    *out_json = NULL;
    *out_json_len = 0;

    const char* req =
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getClusterNodes\"}";

    return rpc_post_json(rpc_url, req, timeout_secs, out_json, out_json_len);
}

sol_err_t
sol_rpc_get_slot_leaders(const char* rpc_url,
                         uint32_t timeout_secs,
                         uint64_t start_slot,
                         uint64_t limit,
                         sol_pubkey_t** out_leaders,
                         size_t* out_leaders_len) {
    if (!rpc_url || !out_leaders || !out_leaders_len) return SOL_ERR_INVAL;
    *out_leaders = NULL;
    *out_leaders_len = 0;

    char req[256];
    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getSlotLeaders\",\"params\":[%llu,%llu]}",
             (unsigned long long)start_slot,
             (unsigned long long)limit);

    char* resp = NULL;
    size_t resp_len = 0;
    sol_err_t err = rpc_post_json(rpc_url, req, timeout_secs, &resp, &resp_len);
    if (err != SOL_OK) return err;

    sol_json_parser_t p;
    sol_json_parser_init(&p, resp, resp_len);
    if (!sol_json_parser_object_begin(&p)) {
        sol_free(resp);
        return SOL_ERR_DECODE;
    }

    sol_pubkey_t* leaders = NULL;
    size_t leaders_cap = (limit > 0 && limit <= SIZE_MAX / sizeof(sol_pubkey_t)) ? (size_t)limit : 0;
    if (leaders_cap == 0) {
        sol_free(resp);
        return SOL_ERR_RANGE;
    }

    leaders = sol_calloc(leaders_cap, sizeof(sol_pubkey_t));
    if (!leaders) {
        sol_free(resp);
        return SOL_ERR_NOMEM;
    }

    char key[64];
    while (sol_json_parser_key(&p, key, sizeof(key))) {
        if (strcmp(key, "result") != 0) {
            sol_json_parser_skip(&p);
            continue;
        }

        if (!sol_json_parser_array_begin(&p)) {
            sol_json_parser_skip(&p);
            continue;
        }

        size_t count = 0;
        while (!sol_json_parser_array_end(&p)) {
            if (count >= leaders_cap) {
                /* RPC returned more than requested; stop. */
                sol_json_parser_skip(&p);
                continue;
            }

            char b58[64];
            if (!sol_json_parser_string(&p, b58, sizeof(b58))) {
                sol_json_parser_skip(&p);
                continue;
            }

            sol_pubkey_t pk = {{0}};
            if (sol_pubkey_from_base58(b58, &pk) != SOL_OK) {
                sol_free(leaders);
                sol_free(resp);
                return SOL_ERR_DECODE;
            }

            leaders[count++] = pk;
        }

        *out_leaders = leaders;
        *out_leaders_len = count;
        sol_free(resp);
        return count ? SOL_OK : SOL_ERR_NOTFOUND;
    }

    sol_free(leaders);
    sol_free(resp);
    return SOL_ERR_NOTFOUND;
}

sol_err_t
sol_rpc_parse_genesis_hash_base58(const char* json,
                                  size_t json_len,
                                  char* out,
                                  size_t out_len) {
    if (!json || !out || out_len == 0) return SOL_ERR_INVAL;
    out[0] = '\0';

    sol_json_parser_t p;
    sol_json_parser_init(&p, json, json_len);
    if (!sol_json_parser_object_begin(&p)) return SOL_ERR_DECODE;

    char key[64];
    while (sol_json_parser_key(&p, key, sizeof(key))) {
        if (strcmp(key, "result") != 0) {
            sol_json_parser_skip(&p);
            continue;
        }

        if (!sol_json_parser_string(&p, out, out_len)) {
            sol_json_parser_skip(&p);
            return SOL_ERR_DECODE;
        }
        if (out[0] == '\0') return SOL_ERR_NOTFOUND;
        return SOL_OK;
    }

    return SOL_ERR_NOTFOUND;
}

sol_err_t
sol_rpc_get_genesis_hash_base58(const char* rpc_url,
                                uint32_t timeout_secs,
                                char* out,
                                size_t out_len) {
    if (!rpc_url || !out || out_len == 0) return SOL_ERR_INVAL;

    const char* req =
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getGenesisHash\"}";

    char* resp = NULL;
    size_t resp_len = 0;
    sol_err_t err = rpc_post_json(rpc_url, req, timeout_secs, &resp, &resp_len);
    if (err != SOL_OK) return err;

    err = sol_rpc_parse_genesis_hash_base58(resp, resp_len, out, out_len);
    sol_free(resp);
    return err;
}
