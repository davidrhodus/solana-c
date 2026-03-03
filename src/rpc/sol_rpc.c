/*
 * sol_rpc.c - JSON-RPC Server Implementation
 */

#include "sol_rpc.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include "../txn/sol_transaction.h"
#include "../txn/sol_bincode.h"
#include "../blockstore/sol_blockstore.h"
#include "../gossip/sol_gossip.h"
#include "../runtime/sol_leader_schedule.h"
#include "../runtime/sol_rewards.h"
#include "../runtime/sol_sysvar.h"
#include "../programs/sol_token_program.h"
#include "../programs/sol_vote_program.h"
#include "../programs/sol_stake_program.h"
#include "../entry/sol_entry.h"
#include "../util/sol_map.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

/* Forward declarations for base64 encoding/decoding */
static ssize_t base64_encode(const uint8_t* input, size_t input_len,
                             char* output, size_t output_max);
static ssize_t base64_decode(const char* input, size_t input_len,
                             uint8_t* output, size_t output_max);

static uint64_t
rpc_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

/*
 * JSON builder structure
 */
struct sol_json_builder {
    char*   buffer;
    size_t  capacity;
    size_t  len;
    bool    need_comma;
    int     depth;
    bool    oom;
};

/*
 * WebSocket subscription entry
 */
#define MAX_WS_SUBSCRIPTIONS 1024
#define MAX_WS_CLIENTS 256

typedef struct {
    uint64_t                id;             /* Subscription ID */
    sol_ws_subscription_type_t type;        /* Subscription type */
    int                     client_fd;      /* Client socket */
    sol_pubkey_t            pubkey;         /* For account/program subscriptions */
    sol_signature_t         signature;      /* For signature subscriptions */
    sol_commitment_t        commitment;     /* Commitment level */
    bool                    active;         /* Is subscription active */
} sol_ws_subscription_t;

/*
 * WebSocket client connection
 */
typedef struct {
    int                     fd;             /* Client socket */
    bool                    active;         /* Is connection active */
    uint64_t                last_activity;  /* Last activity timestamp */
} sol_ws_client_t;

/*
 * HTTP client connections (tracked so shutdown can force active client threads
 * to exit before shared state is destroyed).
 */
#define MAX_HTTP_CLIENTS 8192

typedef struct {
    int                     fd;
    bool                    active;
} sol_http_client_t;

/*
 * RPC server structure
 */
struct sol_rpc {
    sol_rpc_config_t        config;
    size_t                  max_connections_runtime;
    sol_bank_forks_t*       bank_forks;
    sol_blockstore_t*       blockstore;
    struct sol_gossip*      gossip;
    sol_leader_schedule_t*  leader_schedule;
    uint32_t                leader_schedule_readers;

    /* Node identity */
    sol_pubkey_t            identity;
    bool                    identity_set;

    /* Send transaction callback */
    sol_rpc_send_tx_fn      send_tx_callback;
    void*                   send_tx_user_data;

    /* Health callback */
    sol_health_callback_t   health_callback;
    void*                   health_callback_ctx;

    /* HTTP server state */
    int                     listen_fd;
    pthread_t               accept_thread;
    bool                    running;
    pthread_mutex_t         lock;
    sol_http_client_t       http_clients[MAX_HTTP_CLIENTS];

    /* WebSocket server state */
    int                     ws_listen_fd;
    pthread_t               ws_accept_thread;
    sol_ws_client_t         ws_clients[MAX_WS_CLIENTS];
    sol_ws_subscription_t   ws_subscriptions[MAX_WS_SUBSCRIPTIONS];
    uint64_t                ws_next_sub_id;
    pthread_mutex_t         ws_lock;

    /* Rate limiting (global token bucket) */
    pthread_mutex_t         rate_lock;
    uint32_t                rate_limit_rps_runtime;
    uint32_t                rate_limit_burst_runtime;
    uint64_t                rate_last_ms;
    uint64_t                rate_tokens_milli;  /* tokens * 1000 */

    /* Stats */
    sol_rpc_stats_t         stats;
};

static void
rpc_rate_limit_reset_locked(sol_rpc_t* rpc, uint32_t rps, uint32_t burst) {
    if (!rpc) return;

    if (rps == 0) {
        burst = 0;
    } else if (burst == 0) {
        burst = rps;
    }

    rpc->rate_limit_rps_runtime = rps;
    rpc->rate_limit_burst_runtime = burst;
    rpc->rate_last_ms = rpc_now_ms();
    rpc->rate_tokens_milli = (uint64_t)burst * 1000ULL;
}

static inline sol_bank_forks_t*
rpc_bank_forks(const sol_rpc_t* rpc) {
    if (!rpc) return NULL;
    return __atomic_load_n(&rpc->bank_forks, __ATOMIC_ACQUIRE);
}

static inline sol_blockstore_t*
rpc_blockstore(const sol_rpc_t* rpc) {
    if (!rpc) return NULL;
    return __atomic_load_n(&rpc->blockstore, __ATOMIC_ACQUIRE);
}

static inline sol_gossip_t*
rpc_gossip(const sol_rpc_t* rpc) {
    if (!rpc) return NULL;
    /* Field type is `struct sol_gossip*` but `sol_gossip_t` is that same type. */
    return (sol_gossip_t*)__atomic_load_n(&rpc->gossip, __ATOMIC_ACQUIRE);
}

static sol_leader_schedule_t*
rpc_leader_schedule_acquire(sol_rpc_t* rpc) {
    if (!rpc) return NULL;
    pthread_mutex_lock(&rpc->lock);
    sol_leader_schedule_t* schedule = rpc->leader_schedule;
    if (schedule) {
        rpc->leader_schedule_readers++;
    }
    pthread_mutex_unlock(&rpc->lock);
    return schedule;
}

static void
rpc_leader_schedule_release(sol_rpc_t* rpc) {
    if (!rpc) return;
    pthread_mutex_lock(&rpc->lock);
    if (rpc->leader_schedule_readers > 0) {
        rpc->leader_schedule_readers--;
    }
    pthread_mutex_unlock(&rpc->lock);
}

static bool
rpc_rate_limit_allow(sol_rpc_t* rpc) {
    if (!rpc) return true;

    pthread_mutex_lock(&rpc->rate_lock);

    uint32_t rps = rpc->rate_limit_rps_runtime;
    if (rps == 0) {
        pthread_mutex_unlock(&rpc->rate_lock);
        return true;
    }

    uint32_t burst = rpc->rate_limit_burst_runtime;
    if (burst == 0) {
        burst = rps;
    }

    uint64_t now_ms = rpc_now_ms();
    uint64_t elapsed_ms = now_ms - rpc->rate_last_ms;

    if (elapsed_ms > 0) {
        uint64_t cap = (uint64_t)burst * 1000ULL;
        uint64_t refill = elapsed_ms * (uint64_t)rps; /* milli-tokens */

        uint64_t tokens = rpc->rate_tokens_milli + refill;
        if (tokens > cap) {
            tokens = cap;
        }

        rpc->rate_tokens_milli = tokens;
        rpc->rate_last_ms = now_ms;
    }

    if (rpc->rate_tokens_milli < 1000ULL) {
        pthread_mutex_unlock(&rpc->rate_lock);
        return false;
    }

    rpc->rate_tokens_milli -= 1000ULL;
    pthread_mutex_unlock(&rpc->rate_lock);
    return true;
}

/*
 * JSON Builder Implementation
 */

sol_json_builder_t*
sol_json_builder_new(size_t initial_capacity) {
    sol_json_builder_t* b = sol_calloc(1, sizeof(sol_json_builder_t));
    if (!b) return NULL;

    b->capacity = initial_capacity > 0 ? initial_capacity : 1024;
    b->buffer = sol_calloc(1, b->capacity);
    if (!b->buffer) {
        sol_free(b);
        return NULL;
    }

    b->len = 0;
    b->need_comma = false;
    b->depth = 0;
    b->oom = false;

    return b;
}

void
sol_json_builder_destroy(sol_json_builder_t* b) {
    if (!b) return;
    sol_free(b->buffer);
    sol_free(b);
}

static bool
json_ensure_capacity(sol_json_builder_t* b, size_t additional) {
    if (!b || b->oom) return false;

    size_t required;
    if (additional > SIZE_MAX - b->len) {
        b->oom = true;
        return false;
    }
    required = b->len + additional;

    if (required <= b->capacity) {
        return true;
    }

    size_t new_cap = b->capacity ? b->capacity : 1024;
    while (new_cap < required) {
        if (new_cap > SIZE_MAX / 2) {
            new_cap = required;
            break;
        }
        new_cap *= 2;
    }

    char* new_buf = sol_realloc(b->buffer, new_cap);
    if (!new_buf) {
        b->oom = true;
        return false;
    }

    b->buffer = new_buf;
    b->capacity = new_cap;
    return true;
}

static void
json_append(sol_json_builder_t* b, const char* str) {
    if (!b || b->oom) return;
    if (!str) str = "";

    size_t len = strlen(str);
    if (!json_ensure_capacity(b, len + 1)) return;
    memcpy(b->buffer + b->len, str, len);
    b->len += len;
    b->buffer[b->len] = '\0';
}

static void
json_maybe_comma(sol_json_builder_t* b) {
    if (!b || b->oom) return;
    if (b->need_comma) {
        json_append(b, ",");
    }
    b->need_comma = false;
}

void
sol_json_builder_object_begin(sol_json_builder_t* b) {
    if (!b || b->oom) return;
    json_maybe_comma(b);
    json_append(b, "{");
    b->need_comma = false;
    b->depth++;
}

void
sol_json_builder_object_end(sol_json_builder_t* b) {
    if (!b || b->oom) return;
    json_append(b, "}");
    b->need_comma = true;
    b->depth--;
}

void
sol_json_builder_array_begin(sol_json_builder_t* b) {
    if (!b || b->oom) return;
    json_maybe_comma(b);
    json_append(b, "[");
    b->need_comma = false;
    b->depth++;
}

void
sol_json_builder_array_end(sol_json_builder_t* b) {
    if (!b || b->oom) return;
    json_append(b, "]");
    b->need_comma = true;
    b->depth--;
}

void
sol_json_builder_key(sol_json_builder_t* b, const char* key) {
    if (!b || b->oom) return;
    json_maybe_comma(b);
    json_append(b, "\"");
    json_append(b, key);
    json_append(b, "\":");
    b->need_comma = false;
}

void
sol_json_builder_string(sol_json_builder_t* b, const char* value) {
    if (!b || b->oom) return;
    if (!value) value = "";
    json_maybe_comma(b);
    json_append(b, "\"");
    /* Escape special characters */
    for (const char* p = value; *p; p++) {
        char c = *p;
        if (c == '"' || c == '\\') {
            char esc[3] = {'\\', c, '\0'};
            json_append(b, esc);
        } else if (c == '\n') {
            json_append(b, "\\n");
        } else if (c == '\r') {
            json_append(b, "\\r");
        } else if (c == '\t') {
            json_append(b, "\\t");
        } else {
            char ch[2] = {c, '\0'};
            json_append(b, ch);
        }
    }
    json_append(b, "\"");
    b->need_comma = true;
}

void
sol_json_builder_int(sol_json_builder_t* b, int64_t value) {
    if (!b || b->oom) return;
    json_maybe_comma(b);
    char buf[32];
    snprintf(buf, sizeof(buf), "%lld", (long long)value);
    json_append(b, buf);
    b->need_comma = true;
}

void
sol_json_builder_uint(sol_json_builder_t* b, uint64_t value) {
    if (!b || b->oom) return;
    json_maybe_comma(b);
    char buf[32];
    snprintf(buf, sizeof(buf), "%llu", (unsigned long long)value);
    json_append(b, buf);
    b->need_comma = true;
}

void
sol_json_builder_double(sol_json_builder_t* b, double value) {
    if (!b || b->oom) return;
    json_maybe_comma(b);
    char buf[64];
    snprintf(buf, sizeof(buf), "%.9g", value);
    json_append(b, buf);
    b->need_comma = true;
}

void
sol_json_builder_bool(sol_json_builder_t* b, bool value) {
    if (!b || b->oom) return;
    json_maybe_comma(b);
    json_append(b, value ? "true" : "false");
    b->need_comma = true;
}

void
sol_json_builder_null(sol_json_builder_t* b) {
    if (!b || b->oom) return;
    json_maybe_comma(b);
    json_append(b, "null");
    b->need_comma = true;
}

const char*
sol_json_builder_str(sol_json_builder_t* b) {
    return b ? b->buffer : "";
}

size_t
sol_json_builder_len(sol_json_builder_t* b) {
    return b ? b->len : 0;
}

/*
 * RPC Method Handlers
 */

typedef enum {
    RPC_ID_NULL   = 0,
    RPC_ID_STRING = 1,
    RPC_ID_NUMBER = 2,
} rpc_id_type_t;

typedef struct {
    rpc_id_type_t type;
    char          str[64];
    int64_t       num;
} rpc_id_t;

static void
rpc_write_id(sol_json_builder_t* b, const rpc_id_t* id) {
    if (!id || id->type == RPC_ID_NULL) {
        sol_json_builder_null(b);
        return;
    }

    if (id->type == RPC_ID_NUMBER) {
        sol_json_builder_int(b, id->num);
        return;
    }

    sol_json_builder_string(b, id->str);
}

static const char*
rpc_invalid_param_msg(void) {
    /* Matches Solana/Agave RPC error message expectation */
    return "Invalid param: Invalid";
}

static void
rpc_error_response(sol_json_builder_t* b, const rpc_id_t* id,
                   int code, const char* message) {
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "jsonrpc");
    sol_json_builder_string(b, "2.0");
    sol_json_builder_key(b, "id");
    rpc_write_id(b, id);
    sol_json_builder_key(b, "error");
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "code");
    sol_json_builder_int(b, code);
    sol_json_builder_key(b, "message");
    sol_json_builder_string(b, message);
    sol_json_builder_object_end(b);
    sol_json_builder_object_end(b);
}

static void
rpc_result_begin(sol_json_builder_t* b, const rpc_id_t* id) {
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "jsonrpc");
    sol_json_builder_string(b, "2.0");
    sol_json_builder_key(b, "id");
    rpc_write_id(b, id);
    sol_json_builder_key(b, "result");
}

static void
rpc_result_end(sol_json_builder_t* b) {
    sol_json_builder_object_end(b);
}

static void
handle_get_version(sol_rpc_t* rpc, sol_json_builder_t* b, const rpc_id_t* id) {
    (void)rpc;
    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "solana-core");
    sol_json_builder_string(b, "1.18.0");
    sol_json_builder_key(b, "feature-set");
    sol_json_builder_uint(b, 0);
    sol_json_builder_object_end(b);
    rpc_result_end(b);
}

static void
handle_get_health(sol_rpc_t* rpc, sol_json_builder_t* b, const rpc_id_t* id) {
    if (rpc && rpc->health_callback) {
        sol_health_result_t result = rpc->health_callback(rpc->health_callback_ctx);
        if (result.status == SOL_HEALTH_OK) {
            rpc_result_begin(b, id);
            sol_json_builder_string(b, "ok");
            rpc_result_end(b);
        } else {
            const char* msg = result.message ? result.message : "Node is unhealthy";
            rpc_error_response(b, id, SOL_RPC_ERR_NODE_UNHEALTHY, msg);
        }
        return;
    }

    rpc_result_begin(b, id);
    sol_json_builder_string(b, "ok");
    rpc_result_end(b);
}

static void
handle_get_slot(sol_rpc_t* rpc, sol_json_builder_t* b, const rpc_id_t* id) {
    sol_slot_t slot = 0;
    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        sol_bank_t* bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            slot = sol_bank_slot(bank);
        }
    }

    rpc_result_begin(b, id);
    sol_json_builder_uint(b, slot);
    rpc_result_end(b);
}

static void
handle_get_block_height(sol_rpc_t* rpc, sol_json_builder_t* b, const rpc_id_t* id) {
    uint64_t height = 0;
    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        sol_bank_t* bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            height = sol_bank_tick_height(bank);
        }
    }

    rpc_result_begin(b, id);
    sol_json_builder_uint(b, height);
    rpc_result_end(b);
}

static void
handle_get_balance(sol_rpc_t* rpc, sol_json_builder_t* b,
                   const rpc_id_t* id, sol_json_parser_t* params) {
    /* Parse pubkey from params */
    char pubkey_str[64] = {0};

    if (!sol_json_parser_array_begin(params)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected array");
        return;
    }

    if (!sol_json_parser_string(params, pubkey_str, sizeof(pubkey_str))) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected pubkey");
        return;
    }

    /* Decode pubkey */
    sol_pubkey_t pubkey;
    if (sol_pubkey_from_base58(pubkey_str, &pubkey) != SOL_OK) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, rpc_invalid_param_msg());
        return;
    }

    /* Get balance */
    uint64_t lamports = 0;
    sol_slot_t slot = 0;
    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        sol_bank_t* bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            slot = sol_bank_slot(bank);
            sol_account_t* account = sol_bank_load_account(bank, &pubkey);
            if (account) {
                lamports = account->meta.lamports;
            }
        }
    }

    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "context");
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "slot");
    sol_json_builder_uint(b, slot);
    sol_json_builder_object_end(b);
    sol_json_builder_key(b, "value");
    sol_json_builder_uint(b, lamports);
    sol_json_builder_object_end(b);
    rpc_result_end(b);
}

static void
handle_get_account_info(sol_rpc_t* rpc, sol_json_builder_t* b,
                        const rpc_id_t* id, sol_json_parser_t* params) {
    char pubkey_str[64] = {0};

    if (!sol_json_parser_array_begin(params)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected array");
        return;
    }

    if (!sol_json_parser_string(params, pubkey_str, sizeof(pubkey_str))) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected pubkey");
        return;
    }

    sol_pubkey_t pubkey;
    if (sol_pubkey_from_base58(pubkey_str, &pubkey) != SOL_OK) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, rpc_invalid_param_msg());
        return;
    }

    sol_account_t* account = NULL;
    sol_slot_t slot = 0;

    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        sol_bank_t* bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            slot = sol_bank_slot(bank);
            account = sol_bank_load_account(bank, &pubkey);
        }
    }

    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "context");
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "slot");
    sol_json_builder_uint(b, slot);
    sol_json_builder_object_end(b);
    sol_json_builder_key(b, "value");

    if (account) {
        sol_json_builder_object_begin(b);
        sol_json_builder_key(b, "lamports");
        sol_json_builder_uint(b, account->meta.lamports);
        sol_json_builder_key(b, "owner");
        char owner_str[64];
        sol_pubkey_to_base58(&account->meta.owner, owner_str, sizeof(owner_str));
        sol_json_builder_string(b, owner_str);
        sol_json_builder_key(b, "executable");
        sol_json_builder_bool(b, account->meta.executable);
        sol_json_builder_key(b, "rentEpoch");
        sol_json_builder_uint(b, account->meta.rent_epoch);
        sol_json_builder_key(b, "data");
        sol_json_builder_array_begin(b);

        /* Encode account data as base64 */
        if (account->data && account->meta.data_len > 0) {
            /* Calculate base64 output size: ceil(len/3)*4 + null */
            size_t b64_size = ((account->meta.data_len + 2) / 3) * 4 + 1;
            char* b64_data = sol_alloc(b64_size);
            if (b64_data) {
                ssize_t encoded_len = base64_encode(
                    account->data, account->meta.data_len,
                    b64_data, b64_size);
                if (encoded_len > 0) {
                    sol_json_builder_string(b, b64_data);
                } else {
                    sol_json_builder_string(b, "");
                }
                sol_free(b64_data);
            } else {
                sol_json_builder_string(b, "");
            }
        } else {
            sol_json_builder_string(b, "");
        }

        sol_json_builder_string(b, "base64");
        sol_json_builder_array_end(b);
        sol_json_builder_object_end(b);
        sol_account_destroy(account);
    } else {
        sol_json_builder_null(b);
    }

    sol_json_builder_object_end(b);
    rpc_result_end(b);
}

/*
 * Helper to encode account info to JSON
 */
static void
encode_account_info(sol_json_builder_t* b, const sol_account_t* account) {
    if (!account) {
        sol_json_builder_null(b);
        return;
    }

    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "lamports");
    sol_json_builder_uint(b, account->meta.lamports);
    sol_json_builder_key(b, "owner");
    char owner_str[64];
    sol_pubkey_to_base58(&account->meta.owner, owner_str, sizeof(owner_str));
    sol_json_builder_string(b, owner_str);
    sol_json_builder_key(b, "executable");
    sol_json_builder_bool(b, account->meta.executable);
    sol_json_builder_key(b, "rentEpoch");
    sol_json_builder_uint(b, account->meta.rent_epoch);
    sol_json_builder_key(b, "data");
    sol_json_builder_array_begin(b);

    /* Encode account data as base64 */
    if (account->data && account->meta.data_len > 0) {
        size_t b64_size = ((account->meta.data_len + 2) / 3) * 4 + 1;
        char* b64_data = sol_alloc(b64_size);
        if (b64_data) {
            ssize_t encoded_len = base64_encode(
                account->data, account->meta.data_len,
                b64_data, b64_size);
            if (encoded_len > 0) {
                sol_json_builder_string(b, b64_data);
            } else {
                sol_json_builder_string(b, "");
            }
            sol_free(b64_data);
        } else {
            sol_json_builder_string(b, "");
        }
    } else {
        sol_json_builder_string(b, "");
    }

    sol_json_builder_string(b, "base64");
    sol_json_builder_array_end(b);
    sol_json_builder_object_end(b);
}

static void
handle_get_multiple_accounts(sol_rpc_t* rpc, sol_json_builder_t* b,
                              const rpc_id_t* id, sol_json_parser_t* params) {
    if (!sol_json_parser_array_begin(params)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected array");
        return;
    }

    /* First element should be array of pubkeys */
    if (!sol_json_parser_array_begin(params)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected pubkeys array");
        return;
    }

    /* Parse pubkeys (max 100) */
    char pubkey_strs[100][64];
    size_t pubkey_count = 0;

    while (pubkey_count < 100) {
        if (!sol_json_parser_string(params, pubkey_strs[pubkey_count], 64)) {
            break;
        }
        pubkey_count++;
    }

    sol_json_parser_array_end(params);

    /* Get current slot */
    sol_slot_t slot = 0;
    sol_bank_t* bank = NULL;
    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            slot = sol_bank_slot(bank);
        }
    }

    /* Build response */
    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "context");
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "slot");
    sol_json_builder_uint(b, slot);
    sol_json_builder_object_end(b);
    sol_json_builder_key(b, "value");
    sol_json_builder_array_begin(b);

    for (size_t i = 0; i < pubkey_count; i++) {
        sol_pubkey_t pubkey;
        if (sol_pubkey_from_base58(pubkey_strs[i], &pubkey) != SOL_OK) {
            sol_json_builder_null(b);
            continue;
        }

        sol_account_t* account = NULL;
        if (bank) {
            account = sol_bank_load_account(bank, &pubkey);
        }

        encode_account_info(b, account);

        if (account) {
            sol_account_destroy(account);
        }
    }

    sol_json_builder_array_end(b);
    sol_json_builder_object_end(b);
    rpc_result_end(b);
}

/*
 * Context for getProgramAccounts iteration
 */
typedef struct {
    sol_json_builder_t* builder;
    const sol_pubkey_t* program_id;
    size_t count;
    size_t max_count;
} program_accounts_iter_ctx_t;

/*
 * Callback for getProgramAccounts iteration
 */
static bool
program_accounts_iter_cb(const sol_pubkey_t* pubkey,
                          const sol_account_t* account,
                          void* ctx) {
    program_accounts_iter_ctx_t* ic = (program_accounts_iter_ctx_t*)ctx;
    if (ic->count >= ic->max_count) return false;

    if (sol_pubkey_eq(&account->meta.owner, ic->program_id)) {
        sol_json_builder_object_begin(ic->builder);
        sol_json_builder_key(ic->builder, "pubkey");
        char pk_str[64];
        sol_pubkey_to_base58(pubkey, pk_str, sizeof(pk_str));
        sol_json_builder_string(ic->builder, pk_str);
        sol_json_builder_key(ic->builder, "account");
        encode_account_info(ic->builder, account);
        sol_json_builder_object_end(ic->builder);
        ic->count++;
    }
    return true;
}

static void
handle_get_program_accounts(sol_rpc_t* rpc, sol_json_builder_t* b,
                             const rpc_id_t* id, sol_json_parser_t* params) {
    if (!sol_json_parser_array_begin(params)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected array");
        return;
    }

    /* Parse program pubkey */
    char program_str[64] = {0};
    if (!sol_json_parser_string(params, program_str, sizeof(program_str))) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected program pubkey");
        return;
    }

    sol_pubkey_t program_id;
    if (sol_pubkey_from_base58(program_str, &program_id) != SOL_OK) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, rpc_invalid_param_msg());
        return;
    }

    /* Get current slot and bank */
    sol_slot_t slot = 0;
    sol_bank_t* bank = NULL;
    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            slot = sol_bank_slot(bank);
        }
    }

    /* Build response */
    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "context");
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "slot");
    sol_json_builder_uint(b, slot);
    sol_json_builder_object_end(b);
    sol_json_builder_key(b, "value");
    sol_json_builder_array_begin(b);

    /* Iterate accounts owned by this program (uses owner index when available). */
    if (bank) {
        sol_accounts_db_t* db = sol_bank_get_accounts_db(bank);
        if (db) {
            program_accounts_iter_ctx_t iter_ctx = {
                .builder = b,
                .program_id = &program_id,
                .count = 0,
                .max_count = 10000
            };

            sol_accounts_db_iterate_owner(db, &program_id, program_accounts_iter_cb, &iter_ctx);
        }
    }

    sol_json_builder_array_end(b);
    sol_json_builder_object_end(b);
    rpc_result_end(b);
}

/*
 * Iterator context for getTokenAccountsByOwner
 */
typedef struct {
    sol_json_builder_t* builder;
    const sol_pubkey_t* owner;       /* Token account owner (wallet) */
    const sol_pubkey_t* mint;        /* Optional mint filter (NULL if not filtering by mint) */
    size_t              count;
    size_t              max_count;
} token_accounts_iter_ctx_t;

/*
 * Iterator context for getTokenLargestAccounts
 */
typedef struct {
    sol_pubkey_t pubkey;
    uint64_t     amount;
} token_largest_entry_t;

typedef struct {
    const sol_pubkey_t* mint;
    token_largest_entry_t top[20];
    size_t count;
} token_largest_ctx_t;

/*
 * Callback for iterating token accounts owned by a wallet
 */
static bool
token_accounts_iter_cb(const sol_pubkey_t* pubkey, const sol_account_t* account, void* user_data) {
    token_accounts_iter_ctx_t* ctx = (token_accounts_iter_ctx_t*)user_data;

    /* Stop if we've hit max count */
    if (ctx->count >= ctx->max_count) {
        return false;
    }

    /* Check if account is owned by Token program */
    if (!sol_pubkey_eq(&account->meta.owner, &SOL_TOKEN_PROGRAM_ID)) {
        return true;  /* Continue iteration */
    }

    /* Check account size matches token account */
    if (account->meta.data_len != SOL_TOKEN_ACCOUNT_SIZE) {
        return true;  /* Not a token account, continue */
    }

    /* Parse token account data */
    const sol_token_account_t* token_acc = (const sol_token_account_t*)account->data;

    /* Check if this token account's owner matches the requested wallet */
    if (!sol_pubkey_eq(&token_acc->owner, ctx->owner)) {
        return true;  /* Different owner, continue */
    }

    /* Check mint filter if specified */
    if (ctx->mint && !sol_pubkey_eq(&token_acc->mint, ctx->mint)) {
        return true;  /* Different mint, continue */
    }

    /* Output this account */
    sol_json_builder_object_begin(ctx->builder);

    /* pubkey */
    char pubkey_str[64];
    sol_pubkey_to_base58(pubkey, pubkey_str, sizeof(pubkey_str));
    sol_json_builder_key(ctx->builder, "pubkey");
    sol_json_builder_string(ctx->builder, pubkey_str);

    /* account */
    sol_json_builder_key(ctx->builder, "account");
    encode_account_info(ctx->builder, account);

    sol_json_builder_object_end(ctx->builder);
    ctx->count++;

    return true;  /* Continue iteration */
}

static bool
token_largest_iter_cb(const sol_pubkey_t* pubkey,
                      const sol_account_t* account,
                      void* user_data) {
    token_largest_ctx_t* ctx = (token_largest_ctx_t*)user_data;
    if (!ctx || !pubkey || !account) return false;

    if (!sol_pubkey_eq(&account->meta.owner, &SOL_TOKEN_PROGRAM_ID)) {
        return true;
    }

    if (account->meta.data_len != SOL_TOKEN_ACCOUNT_SIZE) {
        return true;
    }

    const sol_token_account_t* token_acc = (const sol_token_account_t*)account->data;
    if (!sol_pubkey_eq(&token_acc->mint, ctx->mint)) {
        return true;
    }

    uint64_t amount = token_acc->amount;

    /* Insert into top-20 list (descending by amount). */
    size_t pos = 0;
    while (pos < ctx->count && ctx->top[pos].amount >= amount) {
        pos++;
    }

    if (ctx->count < 20) {
        for (size_t j = ctx->count; j > pos; j--) {
            ctx->top[j] = ctx->top[j - 1];
        }
        ctx->top[pos].pubkey = *pubkey;
        ctx->top[pos].amount = amount;
        ctx->count++;
    } else if (pos < 20) {
        for (size_t j = 19; j > pos; j--) {
            ctx->top[j] = ctx->top[j - 1];
        }
        ctx->top[pos].pubkey = *pubkey;
        ctx->top[pos].amount = amount;
    }

    return true;
}

static void
handle_get_token_accounts_by_owner(sol_rpc_t* rpc, sol_json_builder_t* b,
                                    const rpc_id_t* id, sol_json_parser_t* params) {
    if (!sol_json_parser_array_begin(params)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected array");
        return;
    }

    /* Parse owner pubkey */
    char owner_str[64] = {0};
    if (!sol_json_parser_string(params, owner_str, sizeof(owner_str))) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected owner pubkey");
        return;
    }

    sol_pubkey_t owner;
    if (sol_pubkey_from_base58(owner_str, &owner) != SOL_OK) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, rpc_invalid_param_msg());
        return;
    }

    /* Parse filter object (mint or programId) */
    sol_pubkey_t mint = {0};
    bool has_mint = false;

    if (sol_json_parser_object_begin(params)) {
        char key[64];
        while (sol_json_parser_key(params, key, sizeof(key))) {
            if (strcmp(key, "mint") == 0) {
                char mint_str[64] = {0};
                if (sol_json_parser_string(params, mint_str, sizeof(mint_str))) {
                    if (sol_pubkey_from_base58(mint_str, &mint) == SOL_OK) {
                        has_mint = true;
                    }
                }
            } else if (strcmp(key, "programId") == 0) {
                /* We only support Token program, so just skip the value */
                sol_json_parser_skip(params);
            } else {
                sol_json_parser_skip(params);
            }
        }
    }

    /* Get current slot and bank */
    sol_slot_t slot = 0;
    sol_bank_t* bank = NULL;
    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            slot = sol_bank_slot(bank);
        }
    }

    /* Build response */
    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "context");
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "slot");
    sol_json_builder_uint(b, slot);
    sol_json_builder_object_end(b);
    sol_json_builder_key(b, "value");
    sol_json_builder_array_begin(b);

    /* Iterate token program accounts and filter for this owner */
    if (bank) {
        sol_accounts_db_t* db = sol_bank_get_accounts_db(bank);
        if (db) {
            token_accounts_iter_ctx_t iter_ctx = {
                .builder = b,
                .owner = &owner,
                .mint = has_mint ? &mint : NULL,
                .count = 0,
                .max_count = 1000
            };

            sol_accounts_db_iterate_owner(db, &SOL_TOKEN_PROGRAM_ID, token_accounts_iter_cb, &iter_ctx);
        }
    }

    sol_json_builder_array_end(b);
    sol_json_builder_object_end(b);
    rpc_result_end(b);
}

static void
handle_get_token_supply(sol_rpc_t* rpc, sol_json_builder_t* b,
                        const rpc_id_t* id, sol_json_parser_t* params) {
    if (!sol_json_parser_array_begin(params)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected array");
        return;
    }

    /* Parse mint pubkey */
    char mint_str[64] = {0};
    if (!sol_json_parser_string(params, mint_str, sizeof(mint_str))) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected mint pubkey");
        return;
    }

    sol_pubkey_t mint;
    if (sol_pubkey_from_base58(mint_str, &mint) != SOL_OK) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, rpc_invalid_param_msg());
        return;
    }

    /* Get current slot and bank */
    sol_slot_t slot = 0;
    sol_bank_t* bank = NULL;
    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            slot = sol_bank_slot(bank);
        }
    }

    /* Load mint account */
    uint64_t supply = 0;
    uint8_t decimals = 0;
    bool found = false;

    if (bank) {
        sol_account_t* account = sol_bank_load_account(bank, &mint);
        if (account && account->meta.data_len >= SOL_TOKEN_MINT_SIZE) {
            /* Parse mint data */
            const sol_token_mint_t* mint_data = (const sol_token_mint_t*)account->data;
            if (mint_data->is_initialized) {
                supply = mint_data->supply;
                decimals = mint_data->decimals;
                found = true;
            }
            sol_account_destroy(account);
        } else if (account) {
            sol_account_destroy(account);
        }
    }

    if (!found) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Invalid mint account");
        return;
    }

    /* Format supply as string with UI amount */
    char amount_str[32];
    snprintf(amount_str, sizeof(amount_str), "%lu", (unsigned long)supply);

    /* Calculate UI amount */
    double ui_amount = (double)supply;
    for (uint8_t i = 0; i < decimals; i++) {
        ui_amount /= 10.0;
    }

    /* Build response */
    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "context");
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "slot");
    sol_json_builder_uint(b, slot);
    sol_json_builder_object_end(b);
    sol_json_builder_key(b, "value");
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "amount");
    sol_json_builder_string(b, amount_str);
    sol_json_builder_key(b, "decimals");
    sol_json_builder_uint(b, decimals);
    sol_json_builder_key(b, "uiAmount");
    sol_json_builder_double(b, ui_amount);
    char ui_amount_str[64];
    snprintf(ui_amount_str, sizeof(ui_amount_str), "%.9g", ui_amount);
    sol_json_builder_key(b, "uiAmountString");
    sol_json_builder_string(b, ui_amount_str);
    sol_json_builder_object_end(b);
    sol_json_builder_object_end(b);
    rpc_result_end(b);
}

static void
handle_get_token_account_balance(sol_rpc_t* rpc, sol_json_builder_t* b,
                                 const rpc_id_t* id, sol_json_parser_t* params) {
    if (!sol_json_parser_array_begin(params)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected array");
        return;
    }

    /* Parse token account pubkey */
    char pubkey_str[64] = {0};
    if (!sol_json_parser_string(params, pubkey_str, sizeof(pubkey_str))) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected pubkey");
        return;
    }

    sol_pubkey_t pubkey;
    if (sol_pubkey_from_base58(pubkey_str, &pubkey) != SOL_OK) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, rpc_invalid_param_msg());
        return;
    }

    /* Get current slot and bank */
    sol_slot_t slot = 0;
    sol_bank_t* bank = NULL;
    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            slot = sol_bank_slot(bank);
        }
    }

    uint64_t amount = 0;
    uint8_t decimals = 0;
    bool found = false;

    if (bank) {
        sol_account_t* account = sol_bank_load_account(bank, &pubkey);
        if (account &&
            sol_pubkey_eq(&account->meta.owner, &SOL_TOKEN_PROGRAM_ID) &&
            account->meta.data_len >= SOL_TOKEN_ACCOUNT_SIZE) {
            const sol_token_account_t* token_acc = (const sol_token_account_t*)account->data;
            amount = token_acc->amount;

            /* Load mint for decimals */
            sol_account_t* mint_account = sol_bank_load_account(bank, &token_acc->mint);
            if (mint_account &&
                sol_pubkey_eq(&mint_account->meta.owner, &SOL_TOKEN_PROGRAM_ID) &&
                mint_account->meta.data_len >= SOL_TOKEN_MINT_SIZE) {
                const sol_token_mint_t* mint = (const sol_token_mint_t*)mint_account->data;
                if (mint->is_initialized) {
                    decimals = mint->decimals;
                }
            }
            if (mint_account) {
                sol_account_destroy(mint_account);
            }

            found = true;
        }
        if (account) {
            sol_account_destroy(account);
        }
    }

    if (!found) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Invalid token account");
        return;
    }

    char amount_str[32];
    snprintf(amount_str, sizeof(amount_str), "%lu", (unsigned long)amount);

    double ui_amount = (double)amount;
    for (uint8_t i = 0; i < decimals; i++) {
        ui_amount /= 10.0;
    }

    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "context");
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "slot");
    sol_json_builder_uint(b, slot);
    sol_json_builder_object_end(b);
    sol_json_builder_key(b, "value");
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "amount");
    sol_json_builder_string(b, amount_str);
    sol_json_builder_key(b, "decimals");
    sol_json_builder_uint(b, decimals);
    sol_json_builder_key(b, "uiAmount");
    sol_json_builder_double(b, ui_amount);
    char ui_amount_str[64];
    snprintf(ui_amount_str, sizeof(ui_amount_str), "%.9g", ui_amount);
    sol_json_builder_key(b, "uiAmountString");
    sol_json_builder_string(b, ui_amount_str);
    sol_json_builder_object_end(b);
    sol_json_builder_object_end(b);
    rpc_result_end(b);
}

static void
handle_get_slot_leader(sol_rpc_t* rpc, sol_json_builder_t* b, const rpc_id_t* id) {
    sol_slot_t slot = 0;
    sol_pubkey_t leader = {0};

    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        sol_bank_t* bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            slot = sol_bank_slot(bank);
            /* Get leader for current slot from leader schedule */
            const sol_pubkey_t* slot_leader = sol_leader_schedule_get_leader(
                NULL, slot);  /* NULL schedule uses default/cached */
            if (slot_leader) {
                leader = *slot_leader;
            }
        }
    }

    char leader_str[64];
    sol_pubkey_to_base58(&leader, leader_str, sizeof(leader_str));

    rpc_result_begin(b, id);
    sol_json_builder_string(b, leader_str);
    rpc_result_end(b);
}

static void
handle_get_leader_schedule(sol_rpc_t* rpc, sol_json_builder_t* b,
                           const rpc_id_t* id, sol_json_parser_t* params) {
    sol_slot_t slot = 0;
    uint64_t epoch = 0;
    char identity_filter[64] = {0};
    sol_pubkey_t filter_pubkey;
    bool has_filter = false;

    /* Parse optional parameters */
    if (params && sol_json_parser_array_begin(params)) {
        /* First param: slot (or null) */
        uint64_t param_slot;
        if (sol_json_parser_uint(params, &param_slot)) {
            slot = param_slot;
        } else {
            sol_json_parser_null(params);  /* Skip null */
        }

        /* Second param: config object with optional identity filter */
        if (sol_json_parser_object_begin(params)) {
            char key[32];
            while (sol_json_parser_key(params, key, sizeof(key))) {
                if (strcmp(key, "identity") == 0) {
                    if (sol_json_parser_string(params, identity_filter, sizeof(identity_filter))) {
                        if (sol_pubkey_from_base58(identity_filter, &filter_pubkey) == SOL_OK) {
                            has_filter = true;
                        }
                    }
                } else {
                    sol_json_parser_skip(params);
                }
            }
        }
    }

    sol_bank_t* bank = NULL;
    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            if (slot == 0) {
                slot = sol_bank_slot(bank);
            }
            epoch = sol_bank_epoch(bank);
        }
    }

    if (!bank) {
        rpc_result_begin(b, id);
        sol_json_builder_null(b);
        rpc_result_end(b);
        return;
    }

    /* Get epoch for the requested slot */
    sol_epoch_schedule_t epoch_sched = SOL_EPOCH_SCHEDULE_DEFAULT;
    epoch = sol_epoch_schedule_get_epoch(&epoch_sched, slot);

    /* Get leader schedule for this epoch (prefer cached RPC copy) */
    sol_leader_schedule_t* schedule = NULL;
    bool schedule_cached = false;
    if (rpc) {
        schedule = rpc_leader_schedule_acquire(rpc);
        if (schedule) {
            sol_slot_t cached_first = sol_leader_schedule_first_slot(schedule);
            sol_slot_t cached_last = sol_leader_schedule_last_slot(schedule);
            if (slot < cached_first || slot > cached_last) {
                rpc_leader_schedule_release(rpc);
                schedule = NULL;
            } else {
                schedule_cached = true;
            }
        }
    }

    if (!schedule) {
        schedule = sol_leader_schedule_from_bank(bank, epoch, NULL);
    }

    if (!schedule) {
        rpc_result_begin(b, id);
        sol_json_builder_null(b);
        rpc_result_end(b);
        return;
    }

    sol_slot_t first_slot = sol_leader_schedule_first_slot(schedule);
    sol_slot_t last_slot = sol_leader_schedule_last_slot(schedule);
    size_t total_slots = (last_slot >= first_slot) ? (size_t)(last_slot - first_slot + 1) : 0;

    /* Build response - return leader schedule as object mapping pubkey -> slots */
    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);

    if (has_filter) {
        /* Fast path for identity filter */
        if (total_slots > 0) {
            sol_slot_t* slots = sol_calloc(total_slots, sizeof(sol_slot_t));
            if (slots) {
                size_t num_slots = sol_leader_schedule_get_slots(
                    schedule, &filter_pubkey, slots, total_slots);
                if (num_slots > 0) {
                    char pk_str[64];
                    sol_pubkey_to_base58(&filter_pubkey, pk_str, sizeof(pk_str));
                    sol_json_builder_key(b, pk_str);
                    sol_json_builder_array_begin(b);
                    for (size_t j = 0; j < num_slots; j++) {
                        sol_json_builder_uint(b, slots[j] - first_slot);
                    }
                    sol_json_builder_array_end(b);
                }
                sol_free(slots);
            }
        }

        if (schedule_cached) {
            rpc_leader_schedule_release(rpc);
        } else {
            if (rpc) {
                sol_rpc_set_leader_schedule(rpc, schedule);
            }
            sol_leader_schedule_destroy(schedule);
        }
        sol_json_builder_object_end(b);
        rpc_result_end(b);
        return;
    }

    /* Full schedule: build leader->slots in O(num_slots) */
    if (total_slots > 0) {
        size_t num_leaders = sol_leader_schedule_num_leaders(schedule);
        sol_pubkey_t* leaders = sol_calloc(num_leaders, sizeof(sol_pubkey_t));
        sol_pubkey_map_t* index_map = NULL;
        size_t* counts = NULL;
        size_t* offsets = NULL;
        sol_slot_t** slots_by_leader = NULL;

        if (leaders && num_leaders > 0) {
            num_leaders = sol_leader_schedule_get_leaders(schedule, leaders, num_leaders);
        }

        if (leaders && num_leaders > 0) {
            index_map = sol_pubkey_map_new(sizeof(uint32_t), num_leaders * 2 + 1);
            counts = sol_calloc(num_leaders, sizeof(size_t));
            offsets = sol_calloc(num_leaders, sizeof(size_t));
            slots_by_leader = sol_calloc(num_leaders, sizeof(sol_slot_t*));

            if (index_map && counts && offsets && slots_by_leader) {
                for (uint32_t i = 0; i < (uint32_t)num_leaders; i++) {
                    (void)sol_pubkey_map_insert(index_map, &leaders[i], &i);
                }

                /* First pass: count slots per leader */
                for (sol_slot_t s = first_slot; s <= last_slot; s++) {
                    const sol_pubkey_t* leader = sol_leader_schedule_get_leader(schedule, s);
                    if (!leader) continue;
                    uint32_t* idx = (uint32_t*)sol_pubkey_map_get(index_map, leader);
                    if (idx) {
                        counts[*idx]++;
                    }
                }

                /* Allocate slot arrays */
                for (size_t i = 0; i < num_leaders; i++) {
                    if (counts[i] > 0) {
                        slots_by_leader[i] = sol_calloc(counts[i], sizeof(sol_slot_t));
                    }
                }

                /* Second pass: fill slot arrays */
                for (sol_slot_t s = first_slot; s <= last_slot; s++) {
                    const sol_pubkey_t* leader = sol_leader_schedule_get_leader(schedule, s);
                    if (!leader) continue;
                    uint32_t* idx = (uint32_t*)sol_pubkey_map_get(index_map, leader);
                    if (idx && slots_by_leader[*idx]) {
                        size_t pos = offsets[*idx]++;
                        if (pos < counts[*idx]) {
                            slots_by_leader[*idx][pos] = s - first_slot;
                        }
                    }
                }

                /* Emit JSON */
                for (size_t i = 0; i < num_leaders; i++) {
                    if (counts[i] == 0 || !slots_by_leader[i]) continue;
                    char pk_str[64];
                    sol_pubkey_to_base58(&leaders[i], pk_str, sizeof(pk_str));
                    sol_json_builder_key(b, pk_str);
                    sol_json_builder_array_begin(b);
                    for (size_t j = 0; j < counts[i]; j++) {
                        sol_json_builder_uint(b, slots_by_leader[i][j]);
                    }
                    sol_json_builder_array_end(b);
                }
            }
        }

        if (slots_by_leader) {
            for (size_t i = 0; i < num_leaders; i++) {
                sol_free(slots_by_leader[i]);
            }
        }
        sol_free(slots_by_leader);
        sol_free(offsets);
        sol_free(counts);
        sol_pubkey_map_destroy(index_map);
        sol_free(leaders);
    }

    if (schedule_cached) {
        rpc_leader_schedule_release(rpc);
    } else {
        if (rpc) {
            sol_rpc_set_leader_schedule(rpc, schedule);
        }
        sol_leader_schedule_destroy(schedule);
    }

    sol_json_builder_object_end(b);
    rpc_result_end(b);
}

/*
 * Vote account info for getVoteAccounts
 */
typedef struct {
    sol_pubkey_t    vote_pubkey;
    sol_pubkey_t    node_pubkey;
    uint64_t        activated_stake;
    uint8_t         commission;
    sol_slot_t      last_vote;
    sol_slot_t      root_slot;
    bool            has_root;
    bool            is_current;
    struct {
        uint64_t epoch;
        uint64_t credits;
        uint64_t prev_credits;
    } epoch_credits[5];
    uint8_t         epoch_credits_len;
} vote_account_info_t;

/*
 * Context for getVoteAccounts iteration
 */
typedef struct {
    vote_account_info_t* accounts;
    size_t              capacity;
    size_t              count;
    sol_slot_t          current_slot;
    uint64_t            current_epoch;
} vote_accounts_iter_ctx_t;

/*
 * Callback for iterating vote accounts - collect all first
 */
static bool
vote_accounts_collect_cb(const sol_pubkey_t* pubkey, const sol_account_t* account, void* user_data) {
    vote_accounts_iter_ctx_t* ctx = (vote_accounts_iter_ctx_t*)user_data;

    if (ctx->count >= ctx->capacity) {
        return false;  /* Stop iteration */
    }

    /* Check if account is owned by Vote program */
    if (!sol_pubkey_eq(&account->meta.owner, &SOL_VOTE_PROGRAM_ID)) {
        return true;  /* Continue iteration */
    }

    /* Try to deserialize vote state */
    sol_vote_state_t vote_state;
    if (sol_vote_state_deserialize(&vote_state, account->data, account->meta.data_len) != SOL_OK) {
        return true;  /* Skip invalid vote accounts */
    }

    /* Store vote account info */
    vote_account_info_t* info = &ctx->accounts[ctx->count];
    memcpy(&info->vote_pubkey, pubkey, sizeof(sol_pubkey_t));
    memcpy(&info->node_pubkey, &vote_state.node_pubkey, sizeof(sol_pubkey_t));
    info->activated_stake = account->meta.lamports;
    info->commission = vote_state.commission;
    info->last_vote = vote_state.votes_len > 0 ? vote_state.votes[vote_state.votes_len - 1].slot : 0;
    info->root_slot = vote_state.root_slot;
    info->has_root = vote_state.has_root;

    /* Determine if current or delinquent based on recent voting activity */
    info->is_current = false;
    if (vote_state.votes_len > 0 && ctx->current_slot >= info->last_vote) {
        /* Consider current if voted within last 128 slots */
        info->is_current = (ctx->current_slot - info->last_vote) < 128;
    }

    /* Copy epoch credits */
    info->epoch_credits_len = 0;
    for (uint8_t i = 0; i < vote_state.epoch_credits_len && i < 5; i++) {
        info->epoch_credits[i].epoch = vote_state.epoch_credits[i].epoch;
        info->epoch_credits[i].credits = vote_state.epoch_credits[i].credits;
        info->epoch_credits[i].prev_credits = vote_state.epoch_credits[i].prev_credits;
        info->epoch_credits_len++;
    }

    ctx->count++;
    return true;  /* Continue iteration */
}

/*
 * Write a single vote account to JSON
 */
static void
write_vote_account(sol_json_builder_t* b, const vote_account_info_t* info) {
    sol_json_builder_object_begin(b);

    char pk_str[64];
    sol_pubkey_to_base58(&info->vote_pubkey, pk_str, sizeof(pk_str));
    sol_json_builder_key(b, "votePubkey");
    sol_json_builder_string(b, pk_str);

    sol_pubkey_to_base58(&info->node_pubkey, pk_str, sizeof(pk_str));
    sol_json_builder_key(b, "nodePubkey");
    sol_json_builder_string(b, pk_str);

    sol_json_builder_key(b, "activatedStake");
    sol_json_builder_uint(b, info->activated_stake);

    sol_json_builder_key(b, "epochVoteAccount");
    sol_json_builder_bool(b, true);

    sol_json_builder_key(b, "commission");
    sol_json_builder_uint(b, info->commission);

    sol_json_builder_key(b, "lastVote");
    sol_json_builder_uint(b, info->last_vote);

    sol_json_builder_key(b, "rootSlot");
    if (info->has_root) {
        sol_json_builder_uint(b, info->root_slot);
    } else {
        sol_json_builder_null(b);
    }

    /* Epoch credits */
    sol_json_builder_key(b, "epochCredits");
    sol_json_builder_array_begin(b);
    for (uint8_t i = 0; i < info->epoch_credits_len; i++) {
        sol_json_builder_array_begin(b);
        sol_json_builder_uint(b, info->epoch_credits[i].epoch);
        sol_json_builder_uint(b, info->epoch_credits[i].credits);
        sol_json_builder_uint(b, info->epoch_credits[i].prev_credits);
        sol_json_builder_array_end(b);
    }
    sol_json_builder_array_end(b);

    sol_json_builder_object_end(b);
}

static void
handle_get_vote_accounts(sol_rpc_t* rpc, sol_json_builder_t* b, const rpc_id_t* id) {
    sol_slot_t slot = 0;
    uint64_t epoch = 0;

    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        sol_bank_t* bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            slot = sol_bank_slot(bank);
            epoch = sol_bank_epoch(bank);
        }
    }

    /* Allocate storage for vote accounts */
    #define MAX_VOTE_ACCOUNTS 2000
    vote_account_info_t* accounts = sol_calloc(MAX_VOTE_ACCOUNTS, sizeof(vote_account_info_t));
    size_t count = 0;

    if (accounts && forks) {
        sol_bank_t* bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            sol_accounts_db_t* db = sol_bank_get_accounts_db(bank);
            if (db) {
                vote_accounts_iter_ctx_t ctx = {
                    .accounts = accounts,
                    .capacity = MAX_VOTE_ACCOUNTS,
                    .count = 0,
                    .current_slot = slot,
                    .current_epoch = epoch
                };
                sol_accounts_db_iterate_owner(db, &SOL_VOTE_PROGRAM_ID, vote_accounts_collect_cb, &ctx);
                count = ctx.count;
            }
        }
    }

    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);

    /* Current validators */
    sol_json_builder_key(b, "current");
    sol_json_builder_array_begin(b);
    if (accounts) {
        for (size_t i = 0; i < count; i++) {
            if (accounts[i].is_current) {
                write_vote_account(b, &accounts[i]);
            }
        }
    }
    sol_json_builder_array_end(b);

    /* Delinquent validators */
    sol_json_builder_key(b, "delinquent");
    sol_json_builder_array_begin(b);
    if (accounts) {
        for (size_t i = 0; i < count; i++) {
            if (!accounts[i].is_current) {
                write_vote_account(b, &accounts[i]);
            }
        }
    }
    sol_json_builder_array_end(b);

    sol_free(accounts);
    #undef MAX_VOTE_ACCOUNTS

    sol_json_builder_object_end(b);
    rpc_result_end(b);
}

/*
 * Helper to get socket address string from contact info
 */
static bool
get_socket_addr_str(const sol_contact_info_t* info, uint8_t tag, char* buf, size_t buf_len) {
    for (size_t i = 0; i < info->num_sockets; i++) {
        if (info->sockets[i].tag == tag) {
            const sol_sockaddr_t* addr = &info->sockets[i].addr;
            if (addr->addr.sa.sa_family == AF_INET) {
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &addr->addr.sin.sin_addr, ip, sizeof(ip));
                snprintf(buf, buf_len, "%s:%u", ip, ntohs(addr->addr.sin.sin_port));
                return true;
            } else if (addr->addr.sa.sa_family == AF_INET6) {
                char ip[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &addr->addr.sin6.sin6_addr, ip, sizeof(ip));
                snprintf(buf, buf_len, "[%s]:%u", ip, ntohs(addr->addr.sin6.sin6_port));
                return true;
            }
        }
    }
    return false;
}

static void
handle_get_cluster_nodes(sol_rpc_t* rpc, sol_json_builder_t* b, const rpc_id_t* id) {
    rpc_result_begin(b, id);
    sol_json_builder_array_begin(b);

    sol_gossip_t* gossip = rpc_gossip(rpc);
    if (gossip) {
        /* Get cluster nodes from gossip */
        #define MAX_CLUSTER_NODES 1000
        const sol_contact_info_t* nodes[MAX_CLUSTER_NODES];
        size_t num_nodes = sol_gossip_get_cluster_nodes(gossip, nodes, MAX_CLUSTER_NODES);

        for (size_t i = 0; i < num_nodes; i++) {
            const sol_contact_info_t* info = nodes[i];
            if (!info) continue;

            sol_json_builder_object_begin(b);

            /* pubkey */
            sol_json_builder_key(b, "pubkey");
            char pk_str[64];
            sol_pubkey_to_base58(&info->pubkey, pk_str, sizeof(pk_str));
            sol_json_builder_string(b, pk_str);

            /* gossip address */
            sol_json_builder_key(b, "gossip");
            char addr_str[64];
            if (get_socket_addr_str(info, SOL_SOCKET_TAG_GOSSIP, addr_str, sizeof(addr_str))) {
                sol_json_builder_string(b, addr_str);
            } else {
                sol_json_builder_null(b);
            }

            /* tpu address */
            sol_json_builder_key(b, "tpu");
            if (get_socket_addr_str(info, SOL_SOCKET_TAG_TPU, addr_str, sizeof(addr_str))) {
                sol_json_builder_string(b, addr_str);
            } else {
                sol_json_builder_null(b);
            }

            /* tpuQuic address */
            sol_json_builder_key(b, "tpuQuic");
            if (get_socket_addr_str(info, SOL_SOCKET_TAG_TPU_QUIC, addr_str, sizeof(addr_str))) {
                sol_json_builder_string(b, addr_str);
            } else {
                sol_json_builder_null(b);
            }

            /* rpc address */
            sol_json_builder_key(b, "rpc");
            if (get_socket_addr_str(info, SOL_SOCKET_TAG_RPC, addr_str, sizeof(addr_str))) {
                sol_json_builder_string(b, addr_str);
            } else {
                sol_json_builder_null(b);
            }

            /* pubsub address */
            sol_json_builder_key(b, "pubsub");
            if (get_socket_addr_str(info, SOL_SOCKET_TAG_RPC_PUBSUB, addr_str, sizeof(addr_str))) {
                sol_json_builder_string(b, addr_str);
            } else {
                sol_json_builder_null(b);
            }

            /* serveRepair address */
            sol_json_builder_key(b, "serveRepair");
            if (get_socket_addr_str(info, SOL_SOCKET_TAG_SERVE_REPAIR, addr_str, sizeof(addr_str))) {
                sol_json_builder_string(b, addr_str);
            } else {
                sol_json_builder_null(b);
            }

            /* shredVersion */
            sol_json_builder_key(b, "shredVersion");
            sol_json_builder_uint(b, info->shred_version);

            /* Look up version info from CRDS */
            const sol_crds_version_t* version = sol_gossip_get_version(gossip, &info->pubkey);

            /* version */
            sol_json_builder_key(b, "version");
            if (version) {
                char version_str[32];
                snprintf(version_str, sizeof(version_str), "%u.%u.%u",
                         version->major, version->minor, version->patch);
                sol_json_builder_string(b, version_str);
            } else {
                sol_json_builder_null(b);
            }

            /* featureSet */
            sol_json_builder_key(b, "featureSet");
            if (version) {
                sol_json_builder_uint(b, version->feature_set);
            } else {
                sol_json_builder_null(b);
            }

            sol_json_builder_object_end(b);
        }
        #undef MAX_CLUSTER_NODES
    }

    sol_json_builder_array_end(b);
    rpc_result_end(b);
}

static void
handle_get_inflation_rate(sol_rpc_t* rpc, sol_json_builder_t* b, const rpc_id_t* id) {
    /* Use proper inflation calculations from rewards module */
    sol_inflation_t inflation = SOL_INFLATION_DEFAULT;
    sol_rewards_config_t config = SOL_REWARDS_CONFIG_DEFAULT;

    double total = inflation.initial;
    double validator_portion = 1.0 - inflation.foundation;
    double foundation_portion = inflation.foundation;
    uint64_t epoch = 0;
    sol_slot_t slot = 0;

    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        sol_bank_t* bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            slot = sol_bank_slot(bank);
            epoch = sol_bank_epoch(bank);

            /* Calculate inflation rate at current slot using proper formula */
            total = sol_inflation_rate(&inflation, slot, config.slots_per_year);

            /* Calculate validator portion (vs foundation) */
            uint64_t year = slot / config.slots_per_year;
            double validator_rate = sol_inflation_validator_rate(&inflation, year);
            validator_portion = validator_rate;
            foundation_portion = 1.0 - validator_rate;
        }
    }

    /* Calculate actual rates */
    double validator = total * validator_portion;
    double foundation = total * foundation_portion;

    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "total");
    sol_json_builder_double(b, total);
    sol_json_builder_key(b, "validator");
    sol_json_builder_double(b, validator);
    sol_json_builder_key(b, "foundation");
    sol_json_builder_double(b, foundation);
    sol_json_builder_key(b, "epoch");
    sol_json_builder_uint(b, epoch);
    sol_json_builder_object_end(b);
    rpc_result_end(b);
}

static void
handle_get_inflation_governor(sol_rpc_t* rpc, sol_json_builder_t* b, const rpc_id_t* id) {
    (void)rpc;
    sol_inflation_t inflation = SOL_INFLATION_DEFAULT;

    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "initial");
    sol_json_builder_double(b, inflation.initial);
    sol_json_builder_key(b, "terminal");
    sol_json_builder_double(b, inflation.terminal);
    sol_json_builder_key(b, "taper");
    sol_json_builder_double(b, inflation.taper);
    sol_json_builder_key(b, "foundation");
    sol_json_builder_double(b, inflation.foundation);
    sol_json_builder_key(b, "foundationTerm");
    sol_json_builder_double(b, inflation.foundation_term);
    sol_json_builder_object_end(b);
    rpc_result_end(b);
}

static void
handle_get_stake_activation(sol_rpc_t* rpc, sol_json_builder_t* b,
                            const rpc_id_t* id, sol_json_parser_t* params) {
    if (!sol_json_parser_array_begin(params)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected array");
        return;
    }

    /* Parse stake account pubkey */
    char stake_str[64] = {0};
    if (!sol_json_parser_string(params, stake_str, sizeof(stake_str))) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected stake pubkey");
        return;
    }

    sol_pubkey_t stake_pubkey;
    if (sol_pubkey_from_base58(stake_str, &stake_pubkey) != SOL_OK) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, rpc_invalid_param_msg());
        return;
    }

    /* Optional epoch parameter */
    uint64_t target_epoch = UINT64_MAX;
    if (sol_json_parser_object_begin(params)) {
        char key[64];
        while (sol_json_parser_key(params, key, sizeof(key))) {
            if (strcmp(key, "epoch") == 0) {
                sol_json_parser_uint(params, &target_epoch);
            } else {
                sol_json_parser_skip(params);
            }
        }
    }

    uint64_t active = 0;
    uint64_t inactive = 0;
    const char* state = "inactive";

    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        sol_bank_t* bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            uint64_t current_epoch = sol_bank_epoch(bank);

            /* Use target epoch if specified, otherwise current */
            if (target_epoch == UINT64_MAX) {
                target_epoch = current_epoch;
            }

            sol_account_t* account = sol_bank_load_account(bank, &stake_pubkey);
            if (account) {
                /* Parse stake state */
                sol_stake_state_t stake_state;
                if (sol_stake_state_deserialize(&stake_state, account->data,
                                                 account->meta.data_len) == SOL_OK) {
                    if (stake_state.state == SOL_STAKE_STATE_STAKE) {
                        /* Use stake history for proper activation status */
                        sol_stake_history_t history;
                        sol_stake_history_init(&history);
                        const sol_stake_history_t* history_ptr = NULL;
                        sol_account_t* stake_history_acct =
                            sol_bank_load_account(bank, &SOL_SYSVAR_STAKE_HISTORY_ID);
                        if (stake_history_acct && stake_history_acct->meta.data_len >= 8) {
                            if (sol_stake_history_deserialize(&history,
                                                              stake_history_acct->data,
                                                              stake_history_acct->meta.data_len) == SOL_OK) {
                                history_ptr = &history;
                            }
                        }
                        sol_account_destroy(stake_history_acct);

                        sol_stake_activation_t status;
                        if (sol_stake_get_activation_status(&stake_state, target_epoch,
                                                             history_ptr, &status) == SOL_OK) {
                            active = status.effective;
                            inactive = stake_state.delegation.stake - active;

                            /* Determine state string */
                            if (status.activating > 0 && status.deactivating == 0) {
                                state = "activating";
                            } else if (status.deactivating > 0) {
                                state = "deactivating";
                            } else if (active > 0) {
                                state = "active";
                            } else {
                                state = "inactive";
                            }
                        } else {
                            /* Fallback to simple calculation */
                            active = stake_state.delegation.stake;
                            state = "active";
                        }
                    } else if (stake_state.state == SOL_STAKE_STATE_INITIALIZED) {
                        inactive = account->meta.lamports - stake_state.meta.rent_exempt_reserve;
                        state = "inactive";
                    }
                }
                sol_account_destroy(account);
            }
        }
    }

    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "state");
    sol_json_builder_string(b, state);
    sol_json_builder_key(b, "active");
    sol_json_builder_uint(b, active);
    sol_json_builder_key(b, "inactive");
    sol_json_builder_uint(b, inactive);
    sol_json_builder_object_end(b);
    rpc_result_end(b);
}

static void
handle_get_minimum_balance_for_rent_exemption(sol_rpc_t* rpc, sol_json_builder_t* b,
                                               const rpc_id_t* id, sol_json_parser_t* params) {
    (void)rpc;  /* Rent calculation uses fixed parameters */
    if (!sol_json_parser_array_begin(params)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected array");
        return;
    }

    /* Parse data size */
    uint64_t data_size = 0;
    if (!sol_json_parser_uint(params, &data_size)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected data size");
        return;
    }

    /* Calculate rent-exempt minimum */
    uint64_t rent_per_byte_year = 3480;
    uint64_t exemption_threshold = 2;
    uint64_t minimum = sol_account_rent_exempt_minimum(
        (size_t)data_size, rent_per_byte_year, exemption_threshold);

    rpc_result_begin(b, id);
    sol_json_builder_uint(b, minimum);
    rpc_result_end(b);
}

static void
handle_get_fee_for_message(sol_rpc_t* rpc, sol_json_builder_t* b,
                           const rpc_id_t* id, sol_json_parser_t* params) {
    if (!sol_json_parser_array_begin(params)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected array");
        return;
    }

    /* Parse base64 encoded message */
    char msg_data[4096] = {0};
    if (!sol_json_parser_string(params, msg_data, sizeof(msg_data))) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected message");
        return;
    }

    /* Decode base64 message */
    uint8_t msg_bytes[2048];
    ssize_t msg_len = base64_decode(msg_data, strlen(msg_data), msg_bytes, sizeof(msg_bytes));
    if (msg_len < 0) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Invalid base64 encoding");
        return;
    }

    /* Parse message to count signatures */
    sol_message_t msg;
    sol_message_init(&msg);

    sol_decoder_t dec;
    sol_decoder_init(&dec, msg_bytes, (size_t)msg_len);
    sol_err_t err = sol_message_decode(&dec, &msg);
    if (err != SOL_OK) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Failed to parse message");
        return;
    }

    /* Get fee configuration */
    uint64_t lamports_per_signature = 5000;  /* Default */
    sol_slot_t slot = 0;

    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        sol_bank_t* bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            slot = sol_bank_slot(bank);
            /* Could get lamports_per_signature from bank config */
        }
    }

    /* Calculate fee based on number of required signatures */
    uint64_t fee = lamports_per_signature * msg.header.num_required_signatures;

    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "context");
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "slot");
    sol_json_builder_uint(b, slot);
    sol_json_builder_object_end(b);
    sol_json_builder_key(b, "value");
    sol_json_builder_uint(b, fee);
    sol_json_builder_object_end(b);
    rpc_result_end(b);
}

static void
handle_get_transaction_count(sol_rpc_t* rpc, sol_json_builder_t* b, const rpc_id_t* id) {
    uint64_t count = 0;

    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        sol_bank_t* bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            sol_bank_stats_t stats;
            sol_bank_stats(bank, &stats);
            count = stats.transactions_processed;
        }
    }

    rpc_result_begin(b, id);
    sol_json_builder_uint(b, count);
    rpc_result_end(b);
}

static void
handle_get_recent_performance_samples(sol_rpc_t* rpc, sol_json_builder_t* b,
                                      const rpc_id_t* id, sol_json_parser_t* params) {
    uint64_t limit = 1;
    if (params && sol_json_parser_array_begin(params)) {
        uint64_t tmp = 0;
        if (sol_json_parser_uint(params, &tmp)) {
            limit = tmp;
        }
    }

    sol_slot_t slot = 0;
    sol_bank_stats_t stats = {0};
    bool has_bank = false;

    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        sol_bank_t* bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            slot = sol_bank_slot(bank);
            sol_bank_stats(bank, &stats);
            has_bank = true;
        }
    }

    rpc_result_begin(b, id);
    sol_json_builder_array_begin(b);

    if (has_bank && limit > 0) {
        /* We only track one aggregate sample; return up to 1 entry. */
        sol_json_builder_object_begin(b);
        sol_json_builder_key(b, "slot");
        sol_json_builder_uint(b, slot);
        sol_json_builder_key(b, "numTransactions");
        sol_json_builder_uint(b, stats.transactions_processed);
        sol_json_builder_key(b, "numSlots");
        sol_json_builder_uint(b, 1);
        sol_json_builder_key(b, "samplePeriodSecs");
        sol_json_builder_uint(b, 1);
        sol_json_builder_object_end(b);
    }

    sol_json_builder_array_end(b);
    rpc_result_end(b);
}

static void
handle_get_recent_prioritization_fees(sol_rpc_t* rpc, sol_json_builder_t* b,
                                       const rpc_id_t* id, sol_json_parser_t* params) {
    (void)params;  /* Optional account addresses parameter */

    sol_slot_t slot = 0;
    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        sol_bank_t* bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            slot = sol_bank_slot(bank);
        }
    }

    rpc_result_begin(b, id);
    sol_json_builder_array_begin(b);

    /* Return recent prioritization fee samples */
    /* In a full implementation, this would track actual priority fees per slot */
    for (int i = 0; i < 10 && slot > (uint64_t)i; i++) {
        sol_json_builder_object_begin(b);
        sol_json_builder_key(b, "slot");
        sol_json_builder_uint(b, slot - i);
        sol_json_builder_key(b, "prioritizationFee");
        sol_json_builder_uint(b, 0);  /* Base fee, no priority */
        sol_json_builder_object_end(b);
    }

    sol_json_builder_array_end(b);
    rpc_result_end(b);
}

/*
 * Context for getSignaturesForAddress iteration
 */
typedef struct {
    sol_json_builder_t* builder;
    const sol_pubkey_t* address;
    size_t              count;
    size_t              limit;
} signatures_iter_ctx_t;

static void
handle_get_signatures_for_address(sol_rpc_t* rpc, sol_json_builder_t* b,
                                   const rpc_id_t* id, sol_json_parser_t* params) {
    if (!sol_json_parser_array_begin(params)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected array");
        return;
    }

    /* Parse address */
    char addr_str[64] = {0};
    if (!sol_json_parser_string(params, addr_str, sizeof(addr_str))) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected address");
        return;
    }

    sol_pubkey_t address;
    if (sol_pubkey_from_base58(addr_str, &address) != SOL_OK) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, rpc_invalid_param_msg());
        return;
    }

    /* Parse optional config */
    size_t limit = 1000;
    if (sol_json_parser_object_begin(params)) {
        char key[32];
        while (sol_json_parser_key(params, key, sizeof(key))) {
            if (strcmp(key, "limit") == 0) {
                uint64_t l;
                if (sol_json_parser_uint(params, &l)) {
                    limit = (size_t)l;
                    if (limit > 1000) limit = 1000;
                }
            } else {
                sol_json_parser_skip(params);
            }
        }
    }

    rpc_result_begin(b, id);
    sol_json_builder_array_begin(b);

    sol_blockstore_t* bs = rpc_blockstore(rpc);
    if (bs && limit > 0) {
        sol_blockstore_address_signature_t* entries =
            sol_alloc(limit * sizeof(sol_blockstore_address_signature_t));
        if (entries) {
            size_t n = sol_blockstore_get_signatures_for_address(
                bs, &address, limit, entries, limit
            );

            for (size_t i = 0; i < n; i++) {
                char sig_str[128];
                sol_signature_to_base58(&entries[i].signature, sig_str, sizeof(sig_str));

                sol_json_builder_object_begin(b);
                sol_json_builder_key(b, "signature");
                sol_json_builder_string(b, sig_str);
                sol_json_builder_key(b, "slot");
                sol_json_builder_uint(b, entries[i].slot);
                sol_json_builder_key(b, "err");
                if (entries[i].err == SOL_OK) {
                    sol_json_builder_null(b);
                } else {
                    sol_json_builder_object_begin(b);
                    sol_json_builder_key(b, "InstructionError");
                    sol_json_builder_array_begin(b);
                    sol_json_builder_int(b, 0);
                    sol_json_builder_string(b, "Custom");
                    sol_json_builder_array_end(b);
                    sol_json_builder_object_end(b);
                }
                sol_json_builder_key(b, "memo");
                sol_json_builder_null(b);
                sol_json_builder_key(b, "blockTime");
                sol_json_builder_null(b);
                sol_json_builder_key(b, "confirmationStatus");
                sol_json_builder_string(b, "processed");
                sol_json_builder_object_end(b);
            }

            sol_free(entries);
        }
    }

    sol_json_builder_array_end(b);
    rpc_result_end(b);
}

static void
handle_get_first_available_block(sol_rpc_t* rpc, sol_json_builder_t* b, const rpc_id_t* id) {
    sol_slot_t first_slot = 0;

    sol_blockstore_t* bs = rpc_blockstore(rpc);
    if (bs) {
        first_slot = sol_blockstore_lowest_slot(bs);
    }

    rpc_result_begin(b, id);
    sol_json_builder_uint(b, first_slot);
    rpc_result_end(b);
}

static void
handle_is_blockhash_valid(sol_rpc_t* rpc, sol_json_builder_t* b,
                          const rpc_id_t* id, sol_json_parser_t* params) {
    if (!sol_json_parser_array_begin(params)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected array");
        return;
    }

    /* Parse blockhash */
    char hash_str[64] = {0};
    if (!sol_json_parser_string(params, hash_str, sizeof(hash_str))) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected blockhash");
        return;
    }

    sol_hash_t blockhash;
    if (sol_pubkey_from_base58(hash_str, (sol_pubkey_t*)&blockhash) != SOL_OK) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, rpc_invalid_param_msg());
        return;
    }

    bool valid = false;
    sol_slot_t slot = 0;

    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        sol_bank_t* bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            slot = sol_bank_slot(bank);
            valid = sol_bank_is_blockhash_valid(bank, &blockhash);
        }
    }

    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "context");
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "slot");
    sol_json_builder_uint(b, slot);
    sol_json_builder_object_end(b);
    sol_json_builder_key(b, "value");
    sol_json_builder_bool(b, valid);
    sol_json_builder_object_end(b);
    rpc_result_end(b);
}

/*
 * getTokenLargestAccounts - Get largest token accounts for a mint
 */
static void
handle_get_token_largest_accounts(sol_rpc_t* rpc, sol_json_builder_t* b,
                                   const rpc_id_t* id, sol_json_parser_t* params) {
    if (!sol_json_parser_array_begin(params)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected array");
        return;
    }

    /* Parse mint address */
    char mint_str[64] = {0};
    if (!sol_json_parser_string(params, mint_str, sizeof(mint_str))) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected mint address");
        return;
    }

    sol_pubkey_t mint;
    if (sol_pubkey_from_base58(mint_str, &mint) != SOL_OK) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, rpc_invalid_param_msg());
        return;
    }

    sol_slot_t slot = 0;
    sol_bank_t* bank = NULL;
    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            slot = sol_bank_slot(bank);
        }
    }

    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "context");
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "slot");
    sol_json_builder_uint(b, slot);
    sol_json_builder_object_end(b);
    sol_json_builder_key(b, "value");
    sol_json_builder_array_begin(b);

    uint8_t decimals = 0;
    if (bank) {
        sol_account_t* mint_account = sol_bank_load_account(bank, &mint);
        if (mint_account &&
            sol_pubkey_eq(&mint_account->meta.owner, &SOL_TOKEN_PROGRAM_ID) &&
            mint_account->meta.data_len >= SOL_TOKEN_MINT_SIZE) {
            const sol_token_mint_t* mint_data = (const sol_token_mint_t*)mint_account->data;
            if (mint_data->is_initialized) {
                decimals = mint_data->decimals;
            }
        }
        if (mint_account) {
            sol_account_destroy(mint_account);
        }
    }

    if (bank) {
        sol_accounts_db_t* db = sol_bank_get_accounts_db(bank);
        if (db) {
            token_largest_ctx_t ctx = {
                .mint = &mint,
                .count = 0,
            };
            sol_accounts_db_iterate_owner(db, &SOL_TOKEN_PROGRAM_ID, token_largest_iter_cb, &ctx);

            for (size_t i = 0; i < ctx.count; i++) {
                char addr_str[64];
                sol_pubkey_to_base58(&ctx.top[i].pubkey, addr_str, sizeof(addr_str));

                char amount_str[32];
                snprintf(amount_str, sizeof(amount_str), "%lu", (unsigned long)ctx.top[i].amount);

                double ui_amount = (double)ctx.top[i].amount;
                for (uint8_t d = 0; d < decimals; d++) {
                    ui_amount /= 10.0;
                }

                char ui_amount_str[64];
                snprintf(ui_amount_str, sizeof(ui_amount_str), "%.9g", ui_amount);

                sol_json_builder_object_begin(b);
                sol_json_builder_key(b, "address");
                sol_json_builder_string(b, addr_str);
                sol_json_builder_key(b, "amount");
                sol_json_builder_object_begin(b);
                sol_json_builder_key(b, "amount");
                sol_json_builder_string(b, amount_str);
                sol_json_builder_key(b, "decimals");
                sol_json_builder_uint(b, decimals);
                sol_json_builder_key(b, "uiAmount");
                sol_json_builder_double(b, ui_amount);
                sol_json_builder_key(b, "uiAmountString");
                sol_json_builder_string(b, ui_amount_str);
                sol_json_builder_object_end(b);
                sol_json_builder_object_end(b);
            }
        }
    }

    sol_json_builder_array_end(b);
    sol_json_builder_object_end(b);
    rpc_result_end(b);
}

/*
 * requestAirdrop - Request lamports from faucet (testnet/devnet only)
 */
static void
handle_request_airdrop(sol_rpc_t* rpc, sol_json_builder_t* b,
                       const rpc_id_t* id, sol_json_parser_t* params) {
    if (!sol_json_parser_array_begin(params)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected array");
        return;
    }

    /* Parse destination pubkey */
    char pubkey_str[64] = {0};
    if (!sol_json_parser_string(params, pubkey_str, sizeof(pubkey_str))) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected pubkey");
        return;
    }

    sol_pubkey_t pubkey;
    if (sol_pubkey_from_base58(pubkey_str, &pubkey) != SOL_OK) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, rpc_invalid_param_msg());
        return;
    }

    /* Parse lamports */
    uint64_t lamports = 0;
    if (!sol_json_parser_uint(params, &lamports)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected lamports");
        return;
    }

    /* Limit airdrop to 1 SOL */
    if (lamports > 1000000000) {
        lamports = 1000000000;
    }

    sol_signature_t signature = {0};

    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        sol_bank_t* bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            /* Credit the account directly (faucet mode) */
            sol_account_t* account = sol_bank_load_account(bank, &pubkey);
            if (account) {
                account->meta.lamports += lamports;
                sol_bank_store_account(bank, &pubkey, account);
                sol_account_destroy(account);
            } else {
                /* Create new account */
                sol_account_t* new_account = sol_account_new(lamports, 0, &SOL_SYSTEM_PROGRAM_ID);
                if (new_account) {
                    sol_bank_store_account(bank, &pubkey, new_account);
                    sol_account_destroy(new_account);
                }
            }

            /* Generate a pseudo-signature for the airdrop transaction */
            sol_sha256_ctx_t ctx;
            sol_sha256_init(&ctx);
            sol_sha256_update(&ctx, pubkey.bytes, 32);
            sol_sha256_update(&ctx, (uint8_t*)&lamports, 8);
            uint64_t slot = sol_bank_slot(bank);
            sol_sha256_update(&ctx, (uint8_t*)&slot, 8);
            sol_sha256_t hash;
            sol_sha256_final(&ctx, &hash);
            memcpy(signature.bytes, hash.bytes, 32);
            memcpy(signature.bytes + 32, hash.bytes, 32);
        }
    }

    char sig_str[128];
    sol_signature_to_base58(&signature, sig_str, sizeof(sig_str));

    rpc_result_begin(b, id);
    sol_json_builder_string(b, sig_str);
    rpc_result_end(b);
}

/*
 * getBlockProduction - Get block production statistics
 */
static void
handle_get_block_production(sol_rpc_t* rpc, sol_json_builder_t* b, const rpc_id_t* id) {
    sol_slot_t slot = 0;
    sol_slot_t first_slot = 0;
    sol_slot_t last_slot = 0;

    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        sol_bank_t* bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            slot = sol_bank_slot(bank);
            first_slot = slot > 1000 ? slot - 1000 : 0;
            last_slot = slot;
        }
    }

    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "context");
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "slot");
    sol_json_builder_uint(b, slot);
    sol_json_builder_object_end(b);
    sol_json_builder_key(b, "value");
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "byIdentity");
    sol_json_builder_object_begin(b);
    /* Would list validator identities and their produced/skipped slots */
    sol_json_builder_object_end(b);
    sol_json_builder_key(b, "range");
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "firstSlot");
    sol_json_builder_uint(b, first_slot);
    sol_json_builder_key(b, "lastSlot");
    sol_json_builder_uint(b, last_slot);
    sol_json_builder_object_end(b);
    sol_json_builder_object_end(b);
    sol_json_builder_object_end(b);
    rpc_result_end(b);
}

/*
 * getHighestSnapshotSlot - Get highest snapshot slot available
 */
static void
handle_get_highest_snapshot_slot(sol_rpc_t* rpc, sol_json_builder_t* b, const rpc_id_t* id) {
    uint64_t full = 0;
    uint64_t incremental = 0;

    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        sol_bank_t* bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            /* Would get actual snapshot slot from snapshot manager */
            full = sol_bank_slot(bank);
        }
    }

    if (full == 0) {
        rpc_error_response(b, id, SOL_RPC_ERR_NO_SNAPSHOT, "No snapshot available");
        return;
    }

    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "full");
    sol_json_builder_uint(b, full);
    if (incremental > 0) {
        sol_json_builder_key(b, "incremental");
        sol_json_builder_uint(b, incremental);
    }
    sol_json_builder_object_end(b);
    rpc_result_end(b);
}

/*
 * getSupply - Get total supply of SOL
 */
static void
handle_get_supply(sol_rpc_t* rpc, sol_json_builder_t* b, const rpc_id_t* id) {
    sol_slot_t slot = 0;
    uint64_t total = 0;
    uint64_t circulating = 0;
    uint64_t non_circulating = 0;

    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        sol_bank_t* bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            slot = sol_bank_slot(bank);
            total = sol_bank_capitalization(bank);
            /* Simplified: assume all is circulating */
            circulating = total;
            non_circulating = 0;
        }
    }

    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "context");
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "slot");
    sol_json_builder_uint(b, slot);
    sol_json_builder_object_end(b);
    sol_json_builder_key(b, "value");
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "total");
    sol_json_builder_uint(b, total);
    sol_json_builder_key(b, "circulating");
    sol_json_builder_uint(b, circulating);
    sol_json_builder_key(b, "nonCirculating");
    sol_json_builder_uint(b, non_circulating);
    sol_json_builder_key(b, "nonCirculatingAccounts");
    sol_json_builder_array_begin(b);
    sol_json_builder_array_end(b);
    sol_json_builder_object_end(b);
    sol_json_builder_object_end(b);
    rpc_result_end(b);
}

/*
 * getBlockTime - Get estimated production time for a block
 */
static void
handle_get_block_time(sol_rpc_t* rpc, sol_json_builder_t* b,
                      const rpc_id_t* id, sol_json_parser_t* params) {
    if (!sol_json_parser_array_begin(params)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected array");
        return;
    }

    uint64_t target_slot = 0;
    if (!sol_json_parser_uint(params, &target_slot)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected slot");
        return;
    }

    int64_t block_time = 0;

    sol_blockstore_t* bs = rpc_blockstore(rpc);
    if (bs) {
        /* Try to get actual block time from slot metadata */
        sol_slot_meta_t meta;
        if (sol_blockstore_get_slot_meta(bs, target_slot, &meta) == SOL_OK) {
            /* Use completion time if available (ms since epoch) */
            if (meta.completed_time > 0) {
                block_time = (int64_t)(meta.completed_time / 1000);
            } else if (meta.received_time > 0) {
                /* Fallback to received time */
                block_time = (int64_t)(meta.received_time / 1000);
            }
        }

        /* If no metadata available, estimate based on slot timing */
        if (block_time == 0) {
            /* Estimate: slot * 400ms + genesis time */
            block_time = (int64_t)target_slot * 400 / 1000;
            /* Add genesis timestamp (mainnet-beta approximate) */
            block_time += 1609459200;  /* Jan 1, 2021 */
        }
    }

    if (block_time == 0) {
        rpc_result_begin(b, id);
        sol_json_builder_null(b);
        rpc_result_end(b);
        return;
    }

    rpc_result_begin(b, id);
    sol_json_builder_int(b, block_time);
    rpc_result_end(b);
}

/*
 * getBlockCommitment - Get commitment for a block
 */
static void
handle_get_block_commitment(sol_rpc_t* rpc, sol_json_builder_t* b,
                            const rpc_id_t* id, sol_json_parser_t* params) {
    if (!sol_json_parser_array_begin(params)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected array");
        return;
    }

    uint64_t target_slot = 0;
    if (!sol_json_parser_uint(params, &target_slot)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected slot");
        return;
    }

    uint64_t total_stake = 0;
    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        sol_bank_t* bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            total_stake = sol_bank_capitalization(bank) / 10;  /* Approximate stake */
        }
    }

    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "commitment");
    sol_json_builder_array_begin(b);
    /* 32 slots of commitment data (stake per lockout level) */
    for (int i = 0; i < 32; i++) {
        sol_json_builder_uint(b, 0);
    }
    sol_json_builder_array_end(b);
    sol_json_builder_key(b, "totalStake");
    sol_json_builder_uint(b, total_stake);
    sol_json_builder_object_end(b);
    rpc_result_end(b);
    (void)target_slot;
}

/*
 * getGenesisHash - Get genesis hash
 */
static void
handle_get_genesis_hash(sol_rpc_t* rpc, sol_json_builder_t* b, const rpc_id_t* id) {
    sol_hash_t genesis_hash = {0};

    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        sol_bank_t* bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            /* Get actual genesis hash from bank */
            const sol_hash_t* hash = sol_bank_genesis_hash(bank);
            if (hash) {
                genesis_hash = *hash;
            }
        }
    }

    char hash_str[64];
    sol_pubkey_to_base58((const sol_pubkey_t*)&genesis_hash, hash_str, sizeof(hash_str));

    rpc_result_begin(b, id);
    sol_json_builder_string(b, hash_str);
    rpc_result_end(b);
}

/*
 * getIdentity - Get node identity pubkey
 */
static void
handle_get_identity(sol_rpc_t* rpc, sol_json_builder_t* b, const rpc_id_t* id) {
    sol_pubkey_t identity = {0};

    if (rpc->identity_set) {
        memcpy(&identity, &rpc->identity, sizeof(sol_pubkey_t));
    }

    char identity_str[64];
    sol_pubkey_to_base58(&identity, identity_str, sizeof(identity_str));

    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "identity");
    sol_json_builder_string(b, identity_str);
    sol_json_builder_object_end(b);
    rpc_result_end(b);
}

static void
handle_get_latest_blockhash(sol_rpc_t* rpc, sol_json_builder_t* b, const rpc_id_t* id) {
    sol_hash_t blockhash = {0};
    sol_slot_t slot = 0;
    uint64_t last_valid_block_height = 0;

    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        sol_bank_t* bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            slot = sol_bank_slot(bank);
            const sol_hash_t* bh = sol_bank_blockhash(bank);
            if (bh) {
                blockhash = *bh;
            }
            last_valid_block_height = sol_bank_tick_height(bank) + 150;
        }
    }

    char blockhash_str[64];
    sol_pubkey_to_base58((const sol_pubkey_t*)&blockhash, blockhash_str, sizeof(blockhash_str));

    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "context");
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "slot");
    sol_json_builder_uint(b, slot);
    sol_json_builder_object_end(b);
    sol_json_builder_key(b, "value");
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "blockhash");
    sol_json_builder_string(b, blockhash_str);
    sol_json_builder_key(b, "lastValidBlockHeight");
    sol_json_builder_uint(b, last_valid_block_height);
    sol_json_builder_object_end(b);
    sol_json_builder_object_end(b);
    rpc_result_end(b);
}

static void
handle_get_transaction(sol_rpc_t* rpc, sol_json_builder_t* b,
                        const rpc_id_t* id, sol_json_parser_t* params) {
    char sig_str[128] = {0};

    if (!sol_json_parser_array_begin(params)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected array");
        return;
    }

    if (!sol_json_parser_string(params, sig_str, sizeof(sig_str))) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected signature");
        return;
    }

    /* Decode signature from base58 */
    sol_signature_t sig;
    if (sol_signature_from_base58(sig_str, &sig) != SOL_OK) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, rpc_invalid_param_msg());
        return;
    }

    /* Get current bank */
    sol_bank_t* bank = NULL;
    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        bank = sol_bank_forks_working_bank(forks);
    }

    /* Look up transaction status in bank's cache */
    sol_tx_status_entry_t status;
    if (bank && sol_bank_get_tx_status(bank, &sig, &status)) {
        /*
         * We found the transaction status but don't have the full transaction
         * data stored. Return a minimal response with what we have.
         *
         * A full implementation would fetch the transaction from blockstore.
         */
        rpc_result_begin(b, id);
        sol_json_builder_object_begin(b);

        sol_json_builder_key(b, "slot");
        sol_json_builder_uint(b, status.slot);

        sol_json_builder_key(b, "blockTime");
        sol_json_builder_null(b);  /* Not tracked */

        sol_json_builder_key(b, "meta");
        sol_json_builder_object_begin(b);
        sol_json_builder_key(b, "err");
        if (status.status == SOL_OK) {
            sol_json_builder_null(b);
        } else {
            sol_json_builder_object_begin(b);
            sol_json_builder_key(b, "InstructionError");
            sol_json_builder_array_begin(b);
            sol_json_builder_int(b, 0);
            sol_json_builder_string(b, "Custom");
            sol_json_builder_array_end(b);
            sol_json_builder_object_end(b);
        }
        sol_json_builder_key(b, "fee");
        sol_json_builder_uint(b, status.fee);
        sol_json_builder_key(b, "computeUnitsConsumed");
        sol_json_builder_uint(b, status.compute_units);
        sol_json_builder_key(b, "preBalances");
        sol_json_builder_array_begin(b);
        sol_json_builder_array_end(b);
        sol_json_builder_key(b, "postBalances");
        sol_json_builder_array_begin(b);
        sol_json_builder_array_end(b);
        sol_json_builder_key(b, "logMessages");
        sol_json_builder_null(b);
        sol_json_builder_object_end(b);

        sol_json_builder_key(b, "transaction");
        sol_json_builder_null(b);  /* Transaction data not stored */

        sol_json_builder_object_end(b);
        rpc_result_end(b);
    } else {
        /* Transaction not found */
        rpc_result_begin(b, id);
        sol_json_builder_null(b);
        rpc_result_end(b);
    }
}

static void
handle_get_signature_statuses(sol_rpc_t* rpc, sol_json_builder_t* b,
                               const rpc_id_t* id, sol_json_parser_t* params) {
    if (!sol_json_parser_array_begin(params)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected array");
        return;
    }

    /* First element should be array of signatures */
    if (!sol_json_parser_array_begin(params)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected signatures array");
        return;
    }

    /* Parse signatures */
    char sig_strs[256][128];
    size_t sig_count = 0;

    while (sig_count < 256) {
        if (!sol_json_parser_string(params, sig_strs[sig_count], 128)) {
            break;
        }
        sig_count++;
    }

    sol_json_parser_array_end(params);

    /* Get current slot and bank */
    sol_slot_t slot = 0;
    sol_bank_t* bank = NULL;
    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            slot = sol_bank_slot(bank);
        }
    }

    /* Build response with status for each signature */
    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "context");
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "slot");
    sol_json_builder_uint(b, slot);
    sol_json_builder_object_end(b);
    sol_json_builder_key(b, "value");
    sol_json_builder_array_begin(b);

    for (size_t i = 0; i < sig_count; i++) {
        /* Decode signature from base58 */
        sol_signature_t sig;
        if (sol_signature_from_base58(sig_strs[i], &sig) != SOL_OK) {
            sol_json_builder_null(b);
            continue;
        }

        /* Look up status in bank's transaction cache */
        sol_tx_status_entry_t status;
        if (bank && sol_bank_get_tx_status(bank, &sig, &status)) {
            sol_json_builder_object_begin(b);
            sol_json_builder_key(b, "slot");
            sol_json_builder_uint(b, status.slot);
            sol_json_builder_key(b, "confirmations");
            /* Calculate confirmations as current slot - tx slot */
            uint64_t confirmations = (slot > status.slot) ? (slot - status.slot) : 0;
            if (confirmations > 32) {
                /* After 32 confirmations, return null (finalized) */
                sol_json_builder_null(b);
            } else {
                sol_json_builder_uint(b, confirmations);
            }
            sol_json_builder_key(b, "err");
            if (status.status == SOL_OK) {
                sol_json_builder_null(b);
            } else {
                /* Return error object */
                sol_json_builder_object_begin(b);
                sol_json_builder_key(b, "InstructionError");
                sol_json_builder_array_begin(b);
                sol_json_builder_int(b, 0);
                sol_json_builder_string(b, "Custom");
                sol_json_builder_array_end(b);
                sol_json_builder_object_end(b);
            }
            sol_json_builder_key(b, "confirmationStatus");
            if (confirmations >= 32) {
                sol_json_builder_string(b, "finalized");
            } else if (confirmations >= 1) {
                sol_json_builder_string(b, "confirmed");
            } else {
                sol_json_builder_string(b, "processed");
            }
            sol_json_builder_object_end(b);
        } else {
            sol_json_builder_null(b);  /* Status not found */
        }
    }

    sol_json_builder_array_end(b);
    sol_json_builder_object_end(b);
    rpc_result_end(b);
}

static void
handle_simulate_transaction(sol_rpc_t* rpc, sol_json_builder_t* b,
                             const rpc_id_t* id, sol_json_parser_t* params) {
    char tx_data[4096] = {0};
    bool sig_verify = true;
    bool replace_blockhash = false;

    if (!sol_json_parser_array_begin(params)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected array");
        return;
    }

    if (!sol_json_parser_string(params, tx_data, sizeof(tx_data))) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected transaction");
        return;
    }

    /* Parse optional config object */
    if (sol_json_parser_object_begin(params)) {
        char key[64];
        while (sol_json_parser_key(params, key, sizeof(key))) {
            bool val;
            if (strcmp(key, "sigVerify") == 0) {
                if (sol_json_parser_bool(params, &val)) {
                    sig_verify = val;
                }
            } else if (strcmp(key, "replaceRecentBlockhash") == 0) {
                if (sol_json_parser_bool(params, &val)) {
                    replace_blockhash = val;
                }
            } else {
                sol_json_parser_skip(params);
            }
        }
    }

    /* Decode base64 transaction data */
    uint8_t tx_bytes[2048];
    ssize_t tx_len = base64_decode(tx_data, strlen(tx_data), tx_bytes, sizeof(tx_bytes));
    if (tx_len < 0) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Invalid base64 encoding");
        return;
    }

    /* Parse transaction */
    sol_transaction_t tx;
    sol_transaction_init(&tx);

    sol_err_t err = sol_transaction_decode(tx_bytes, (size_t)tx_len, &tx);
    if (err != SOL_OK) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Failed to parse transaction");
        return;
    }

    /* Get current slot and bank */
    sol_slot_t slot = 0;
    sol_bank_t* bank = NULL;
    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            slot = sol_bank_slot(bank);
        }
    }

    /* Run simulation */
    sol_sim_result_t sim_result = {0};
    if (bank) {
        sim_result = sol_bank_simulate_transaction(bank, &tx, sig_verify, replace_blockhash);
    } else {
        sim_result.status = SOL_ERR_UNINITIALIZED;
        sim_result.logs_count = 1;
        snprintf(sim_result.logs[0], SOL_SIM_MAX_LOG_LEN, "No bank available for simulation");
    }

    /* Build response */
    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "context");
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "slot");
    sol_json_builder_uint(b, slot);
    sol_json_builder_object_end(b);
    sol_json_builder_key(b, "value");
    sol_json_builder_object_begin(b);

    sol_json_builder_key(b, "err");
    if (sim_result.status == SOL_OK) {
        sol_json_builder_null(b);
    } else {
        sol_json_builder_object_begin(b);
        sol_json_builder_key(b, "InstructionError");
        sol_json_builder_array_begin(b);
        sol_json_builder_int(b, 0);
        sol_json_builder_string(b, sol_err_str(sim_result.status));
        sol_json_builder_array_end(b);
        sol_json_builder_object_end(b);
    }

    /* Output logs from simulation */
    sol_json_builder_key(b, "logs");
    sol_json_builder_array_begin(b);
    for (size_t i = 0; i < sim_result.logs_count; i++) {
        sol_json_builder_string(b, sim_result.logs[i]);
    }
    sol_json_builder_array_end(b);

    sol_json_builder_key(b, "unitsConsumed");
    sol_json_builder_uint(b, sim_result.units_consumed);

    sol_json_builder_object_end(b);
    sol_json_builder_object_end(b);
    rpc_result_end(b);

    /* Cleanup simulation result */
    sol_sim_result_cleanup(&sim_result);
}

static void
handle_get_block(sol_rpc_t* rpc, sol_json_builder_t* b,
                  const rpc_id_t* id, sol_json_parser_t* params) {
    if (!sol_json_parser_array_begin(params)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected array");
        return;
    }

    /* Parse slot number */
    uint64_t slot;
    if (!sol_json_parser_uint(params, &slot)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected slot");
        return;
    }

    /* Check if we have a blockstore */
    sol_blockstore_t* bs = rpc_blockstore(rpc);
    if (!bs) {
        rpc_error_response(b, id, SOL_RPC_ERR_BLOCK_NOT_AVAILABLE,
                          "Blockstore not available");
        return;
    }

    /* Prefer a complete duplicate-slot variant if needed */
    if (!sol_blockstore_is_slot_complete(bs, slot)) {
        rpc_error_response(b, id, SOL_RPC_ERR_BLOCK_NOT_AVAILABLE,
                          "Block not complete");
        return;
    }

    uint32_t chosen_variant = 0;
    sol_block_t* block = sol_blockstore_get_block_variant(bs, slot, 0);
    if (!block) {
        size_t variants = sol_blockstore_num_variants(bs, slot);
        for (uint32_t v = 1; v < variants; v++) {
            block = sol_blockstore_get_block_variant(bs, slot, v);
            if (block) {
                chosen_variant = v;
                break;
            }
        }
    }

    if (!block) {
        rpc_error_response(b, id, SOL_RPC_ERR_BLOCK_NOT_AVAILABLE,
                          "Block not available");
        return;
    }

    sol_slot_t parent_slot = block->parent_slot;

    /* Best-effort slot metadata (timestamps, etc) */
    sol_slot_meta_t meta = {0};
    (void)sol_blockstore_get_slot_meta(bs, slot, &meta);
    meta.parent_slot = parent_slot;

    /* Parse entries up-front (also used to derive the blockhash) */
    sol_hash_t block_hash = {0};
    sol_entry_batch_t* entries = NULL;
    if (block->data && block->data_len > 0) {
        entries = sol_entry_batch_new(32);
        if (entries && sol_entry_batch_parse(entries, block->data, block->data_len) == SOL_OK) {
            if (entries->num_entries > 0) {
                sol_entry_t* last_entry = &entries->entries[entries->num_entries - 1];
                memcpy(&block_hash, &last_entry->hash, sizeof(sol_hash_t));
            }
        } else {
            if (entries) {
                sol_entry_batch_destroy(entries);
                entries = NULL;
            }
        }
    }

    /* Get parent block hash (best-effort) */
    sol_hash_t parent_hash = {0};
    if (parent_slot > 0) {
        sol_blockstore_get_block_hash(bs, parent_slot, &parent_hash);
    }

    /* Build response */
    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);

    sol_json_builder_key(b, "blockhash");
    char hash_str[64];
    sol_pubkey_to_base58((const sol_pubkey_t*)&block_hash, hash_str, sizeof(hash_str));
    sol_json_builder_string(b, hash_str);

    sol_json_builder_key(b, "previousBlockhash");
    sol_pubkey_to_base58((const sol_pubkey_t*)&parent_hash, hash_str, sizeof(hash_str));
    sol_json_builder_string(b, hash_str);

    sol_json_builder_key(b, "parentSlot");
    sol_json_builder_uint(b, parent_slot);

    sol_json_builder_key(b, "blockHeight");
    sol_json_builder_uint(b, slot);  /* Simplified: use slot as height */

    sol_json_builder_key(b, "blockTime");
    sol_json_builder_uint(b, meta.received_time / 1000);  /* Convert to seconds */

    sol_json_builder_key(b, "transactions");
    sol_json_builder_array_begin(b);

    if (entries) {
        /* Iterate through entries and output transactions */
        for (size_t e = 0; e < entries->num_entries; e++) {
            sol_entry_t* entry = &entries->entries[e];
            for (uint32_t t = 0; t < entry->num_transactions; t++) {
                sol_transaction_t* tx = &entry->transactions[t];

                sol_json_builder_object_begin(b);

                /* transaction object */
                sol_json_builder_key(b, "transaction");
                sol_json_builder_object_begin(b);

                /* signatures */
                sol_json_builder_key(b, "signatures");
                sol_json_builder_array_begin(b);
                for (size_t s = 0; s < tx->signatures_len; s++) {
                    char sig_str[128];
                    sol_signature_to_base58(&tx->signatures[s], sig_str, sizeof(sig_str));
                    sol_json_builder_string(b, sig_str);
                }
                sol_json_builder_array_end(b);

                /* message */
                sol_json_builder_key(b, "message");
                sol_json_builder_object_begin(b);

                sol_json_builder_key(b, "accountKeys");
                sol_json_builder_array_begin(b);
                for (size_t a = 0; a < tx->message.account_keys_len; a++) {
                    char pk_str[64];
                    sol_pubkey_to_base58(&tx->message.account_keys[a], pk_str, sizeof(pk_str));
                    sol_json_builder_string(b, pk_str);
                }
                sol_json_builder_array_end(b);

                sol_json_builder_key(b, "recentBlockhash");
                sol_pubkey_to_base58((const sol_pubkey_t*)&tx->message.recent_blockhash,
                                    hash_str, sizeof(hash_str));
                sol_json_builder_string(b, hash_str);

                sol_json_builder_object_end(b);  /* message */
                sol_json_builder_object_end(b);  /* transaction */

                /* meta */
                sol_json_builder_key(b, "meta");
                sol_json_builder_object_begin(b);
                sol_json_builder_key(b, "err");
                sol_json_builder_null(b);
                sol_json_builder_key(b, "fee");
                sol_json_builder_uint(b, 5000 * tx->signatures_len);
                sol_json_builder_key(b, "preBalances");
                sol_json_builder_array_begin(b);
                sol_json_builder_array_end(b);
                sol_json_builder_key(b, "postBalances");
                sol_json_builder_array_begin(b);
                sol_json_builder_array_end(b);
                sol_json_builder_object_end(b);  /* meta */

                sol_json_builder_object_end(b);  /* transaction entry */
            }
        }
    }

    if (entries) sol_entry_batch_destroy(entries);
    sol_block_destroy(block);

    (void)chosen_variant;

    sol_json_builder_array_end(b);

    sol_json_builder_key(b, "rewards");
    sol_json_builder_array_begin(b);
    sol_json_builder_array_end(b);

    sol_json_builder_object_end(b);
    rpc_result_end(b);
}

static void
handle_get_blocks(sol_rpc_t* rpc, sol_json_builder_t* b,
                   const rpc_id_t* id, sol_json_parser_t* params) {
    if (!sol_json_parser_array_begin(params)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected array");
        return;
    }

    /* Parse start slot */
    uint64_t start_slot;
    if (!sol_json_parser_uint(params, &start_slot)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected start slot");
        return;
    }

    /* Parse optional end slot */
    uint64_t end_slot = start_slot + 500000;  /* Default limit */
    sol_json_parser_uint(params, &end_slot);

    /* Limit range to prevent excessive response */
    if (end_slot - start_slot > 500000) {
        end_slot = start_slot + 500000;
    }

    /* Get current slot as upper bound */
    sol_slot_t current_slot = 0;
    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        sol_bank_t* bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            current_slot = sol_bank_slot(bank);
        }
    }

    if (end_slot > current_slot) {
        end_slot = current_slot;
    }

    /* Build response with available blocks */
    rpc_result_begin(b, id);
    sol_json_builder_array_begin(b);

    sol_blockstore_t* bs = rpc_blockstore(rpc);
    if (bs) {
        for (uint64_t slot = start_slot; slot <= end_slot; slot++) {
            if (sol_blockstore_is_slot_complete(bs, slot)) {
                sol_json_builder_uint(b, slot);
            }
        }
    }

    sol_json_builder_array_end(b);
    rpc_result_end(b);
}

static void
handle_get_blocks_with_limit(sol_rpc_t* rpc, sol_json_builder_t* b,
                             const rpc_id_t* id, sol_json_parser_t* params) {
    if (!sol_json_parser_array_begin(params)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected array");
        return;
    }

    /* Parse start slot */
    uint64_t start_slot;
    if (!sol_json_parser_uint(params, &start_slot)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected start slot");
        return;
    }

    /* Parse limit */
    uint64_t limit;
    if (!sol_json_parser_uint(params, &limit)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected limit");
        return;
    }

    /* Hard cap to prevent excessive scanning / response */
    const uint64_t hard_cap = 500000;
    if (limit > hard_cap) {
        limit = hard_cap;
    }

    /* Get current slot as upper bound */
    sol_slot_t current_slot = 0;
    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        sol_bank_t* bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            current_slot = sol_bank_slot(bank);
        }
    }

    uint64_t scan_end = start_slot + hard_cap;
    if (scan_end > current_slot) {
        scan_end = current_slot;
    }

    rpc_result_begin(b, id);
    sol_json_builder_array_begin(b);

    sol_blockstore_t* bs = rpc_blockstore(rpc);
    if (bs && limit > 0) {
        uint64_t out_count = 0;
        for (uint64_t slot = start_slot; slot <= scan_end; slot++) {
            if (out_count >= limit) break;

            if (sol_blockstore_is_slot_complete(bs, slot)) {
                sol_json_builder_uint(b, slot);
                out_count++;
            }
        }
    }

    sol_json_builder_array_end(b);
    rpc_result_end(b);
}

static void
handle_get_epoch_info(sol_rpc_t* rpc, sol_json_builder_t* b, const rpc_id_t* id) {
    sol_slot_t slot = 0;
    uint64_t epoch = 0;
    uint64_t slot_index = 0;
    uint64_t slots_in_epoch = SOL_DEFAULT_SLOTS_PER_EPOCH;
    uint64_t absolute_slot = 0;
    uint64_t block_height = 0;
    uint64_t transaction_count = 0;

    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        sol_bank_t* bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            slot = sol_bank_slot(bank);
            absolute_slot = slot;
            block_height = sol_bank_tick_height(bank);
            epoch = slot / slots_in_epoch;
            slot_index = slot % slots_in_epoch;
            sol_bank_stats_t stats;
            sol_bank_stats(bank, &stats);
            transaction_count = stats.transactions_processed;
        }
    }

    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "epoch");
    sol_json_builder_uint(b, epoch);
    sol_json_builder_key(b, "slotIndex");
    sol_json_builder_uint(b, slot_index);
    sol_json_builder_key(b, "slotsInEpoch");
    sol_json_builder_uint(b, slots_in_epoch);
    sol_json_builder_key(b, "absoluteSlot");
    sol_json_builder_uint(b, absolute_slot);
    sol_json_builder_key(b, "blockHeight");
    sol_json_builder_uint(b, block_height);
    sol_json_builder_key(b, "transactionCount");
    sol_json_builder_uint(b, transaction_count);
    sol_json_builder_object_end(b);
    rpc_result_end(b);
}

static void
handle_get_epoch_schedule(sol_rpc_t* rpc, sol_json_builder_t* b, const rpc_id_t* id) {
    sol_epoch_schedule_t schedule;
    sol_epoch_schedule_init(&schedule);

    sol_bank_forks_t* forks = rpc_bank_forks(rpc);
    if (forks) {
        sol_bank_t* bank = sol_bank_forks_working_bank(forks);
        if (bank) {
            sol_account_t* account = sol_bank_load_account(bank, &SOL_SYSVAR_EPOCH_SCHEDULE_ID);
            if (account && account->meta.data_len >= SOL_EPOCH_SCHEDULE_SERIALIZED_SIZE) {
                (void)sol_epoch_schedule_deserialize(&schedule, account->data, account->meta.data_len);
            }
            if (account) {
                sol_account_destroy(account);
            }
        }
    }

    rpc_result_begin(b, id);
    sol_json_builder_object_begin(b);
    sol_json_builder_key(b, "slotsPerEpoch");
    sol_json_builder_uint(b, schedule.slots_per_epoch);
    sol_json_builder_key(b, "leaderScheduleSlotOffset");
    sol_json_builder_uint(b, schedule.leader_schedule_slot_offset);
    sol_json_builder_key(b, "warmup");
    sol_json_builder_bool(b, schedule.warmup);
    sol_json_builder_key(b, "firstNormalEpoch");
    sol_json_builder_uint(b, schedule.first_normal_epoch);
    sol_json_builder_key(b, "firstNormalSlot");
    sol_json_builder_uint(b, schedule.first_normal_slot);
    sol_json_builder_object_end(b);
    rpc_result_end(b);
}

/*
 * Base64 encoding table
 */
static const char base64_encode_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 * Encode data to base64
 * Returns output length, or -1 on error
 */
static ssize_t
base64_encode(const uint8_t* input, size_t input_len, char* output, size_t output_max) {
    /* Calculate required output size: ceil(input_len / 3) * 4 + null terminator */
    size_t needed = ((input_len + 2) / 3) * 4 + 1;
    if (output_max < needed) return -1;

    size_t out_idx = 0;
    size_t i = 0;

    while (i < input_len) {
        uint32_t octet_a = i < input_len ? input[i++] : 0;
        uint32_t octet_b = i < input_len ? input[i++] : 0;
        uint32_t octet_c = i < input_len ? input[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        output[out_idx++] = base64_encode_table[(triple >> 18) & 0x3F];
        output[out_idx++] = base64_encode_table[(triple >> 12) & 0x3F];
        output[out_idx++] = base64_encode_table[(triple >> 6) & 0x3F];
        output[out_idx++] = base64_encode_table[triple & 0x3F];
    }

    /* Add padding */
    size_t mod = input_len % 3;
    if (mod == 1) {
        output[out_idx - 1] = '=';
        output[out_idx - 2] = '=';
    } else if (mod == 2) {
        output[out_idx - 1] = '=';
    }

    output[out_idx] = '\0';
    return (ssize_t)out_idx;
}

/*
 * Base64 decoding table
 */
static const int8_t base64_decode_table[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

/*
 * Decode base64 string
 * Returns decoded length, or -1 on error
 */
static ssize_t
base64_decode(const char* input, size_t input_len, uint8_t* output, size_t output_max) {
    size_t out_len = 0;
    uint32_t buf = 0;
    int bits = 0;

    for (size_t i = 0; i < input_len; i++) {
        char c = input[i];

        /* Skip whitespace */
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;

        /* Handle padding */
        if (c == '=') break;

        int8_t val = base64_decode_table[(uint8_t)c];
        if (val < 0) return -1;  /* Invalid character */

        buf = (buf << 6) | val;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            if (out_len >= output_max) return -1;  /* Output buffer full */
            output[out_len++] = (uint8_t)(buf >> bits);
        }
    }

    return (ssize_t)out_len;
}

static void
handle_send_transaction(sol_rpc_t* rpc, sol_json_builder_t* b,
                        const rpc_id_t* id, sol_json_parser_t* params) {
    char tx_data[4096] = {0};

    if (!sol_json_parser_array_begin(params)) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected array");
        return;
    }

    if (!sol_json_parser_string(params, tx_data, sizeof(tx_data))) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Expected transaction");
        return;
    }

    /* Decode base64 transaction data */
    uint8_t tx_bytes[2048];
    ssize_t tx_len = base64_decode(tx_data, strlen(tx_data), tx_bytes, sizeof(tx_bytes));
    if (tx_len < 0) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Invalid base64 encoding");
        return;
    }

    /* Parse transaction (zero-copy) */
    sol_transaction_t tx;
    sol_transaction_init(&tx);

    sol_err_t err = sol_transaction_decode(tx_bytes, (size_t)tx_len, &tx);
    if (err != SOL_OK) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Failed to parse transaction");
        return;
    }

    /* Get the transaction signature */
    if (tx.signatures_len == 0) {
        rpc_error_response(b, id, SOL_RPC_ERR_INVALID_PARAMS, "Transaction has no signatures");
        return;
    }

    /* Encode signature as base58 */
    char sig_str[128];
    err = sol_transaction_id_to_base58(&tx, sig_str, sizeof(sig_str));
    if (err != SOL_OK) {
        rpc_error_response(b, id, SOL_RPC_ERR_INTERNAL_ERROR, "Failed to encode signature");
        return;
    }

    /* Submit transaction via callback if set */
    if (rpc->send_tx_callback) {
        err = rpc->send_tx_callback(&tx, rpc->send_tx_user_data);
        if (err != SOL_OK) {
            rpc_error_response(b, id, SOL_RPC_ERR_INTERNAL_ERROR, "Failed to submit transaction");
            return;
        }
    }

    /* Return the signature */
    rpc_result_begin(b, id);
    sol_json_builder_string(b, sig_str);
    rpc_result_end(b);
}

/*
 * Request handler
 */
void
sol_rpc_handle_request_json(sol_rpc_t* rpc, const char* body, size_t body_len,
                            sol_json_builder_t* response) {
    sol_json_parser_t parser;
    sol_json_parser_init(&parser, body, body_len);

    if (!sol_json_parser_object_begin(&parser)) {
        rpc_error_response(response, NULL, SOL_RPC_ERR_PARSE_ERROR, "Parse error");
        return;
    }

    rpc_id_t id = {0};
    char method[64] = {0};
    sol_json_parser_t params_parser = {0};
    bool has_params = false;

    /* Parse request fields */
    char key[32];
    while (sol_json_parser_key(&parser, key, sizeof(key))) {
        if (strcmp(key, "jsonrpc") == 0) {
            char version[8];
            sol_json_parser_string(&parser, version, sizeof(version));
        } else if (strcmp(key, "id") == 0) {
            char id_str[64] = {0};
            int64_t id_num = 0;
            if (sol_json_parser_string(&parser, id_str, sizeof(id_str))) {
                id.type = RPC_ID_STRING;
                snprintf(id.str, sizeof(id.str), "%s", id_str);
            } else if (sol_json_parser_int(&parser, &id_num)) {
                id.type = RPC_ID_NUMBER;
                id.num = id_num;
            } else if (sol_json_parser_null(&parser)) {
                id.type = RPC_ID_NULL;
            } else {
                /* Invalid ID type - consume and treat as null */
                sol_json_parser_skip(&parser);
                id.type = RPC_ID_NULL;
            }
        } else if (strcmp(key, "method") == 0) {
            sol_json_parser_string(&parser, method, sizeof(method));
        } else if (strcmp(key, "params") == 0) {
            /* Save params position for method handler */
            params_parser = parser;
            has_params = true;
            sol_json_parser_skip(&parser);
        } else {
            sol_json_parser_skip(&parser);
        }
    }

    /* Ensure the request was valid JSON (object terminator present) and had no
     * trailing junk. The minimal JSON parser used here does not track error
     * state beyond individual calls, so without this check invalid JSON like
     * "{not json" would be treated as an empty object and routed to "method
     * not found" instead of returning a JSON-RPC parse error. */
    if (!sol_json_parser_object_end(&parser)) {
        rpc_error_response(response, NULL, SOL_RPC_ERR_PARSE_ERROR, "Parse error");
        return;
    }
    while (parser.pos < parser.len) {
        char c = parser.json[parser.pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            parser.pos++;
            continue;
        }
        rpc_error_response(response, NULL, SOL_RPC_ERR_PARSE_ERROR, "Parse error");
        return;
    }

    if (!rpc_rate_limit_allow(rpc)) {
        rpc_error_response(response, &id, SOL_RPC_ERR_RATE_LIMITED, "Rate limit exceeded");
        __atomic_fetch_add(&rpc->stats.requests_total, 1, __ATOMIC_RELAXED);
        __atomic_fetch_add(&rpc->stats.requests_failed, 1, __ATOMIC_RELAXED);
        return;
    }

    /* Route to method handler */
    if (strcmp(method, "getVersion") == 0) {
        handle_get_version(rpc, response, &id);
    } else if (strcmp(method, "getHealth") == 0) {
        handle_get_health(rpc, response, &id);
    } else if (strcmp(method, "getSlot") == 0) {
        handle_get_slot(rpc, response, &id);
    } else if (strcmp(method, "getBlockHeight") == 0) {
        handle_get_block_height(rpc, response, &id);
    } else if (strcmp(method, "getBalance") == 0) {
        handle_get_balance(rpc, response, &id, has_params ? &params_parser : NULL);
    } else if (strcmp(method, "getAccountInfo") == 0) {
        handle_get_account_info(rpc, response, &id, has_params ? &params_parser : NULL);
    } else if (strcmp(method, "getLatestBlockhash") == 0) {
        handle_get_latest_blockhash(rpc, response, &id);
    } else if (strcmp(method, "getEpochInfo") == 0) {
        handle_get_epoch_info(rpc, response, &id);
    } else if (strcmp(method, "getEpochSchedule") == 0) {
        handle_get_epoch_schedule(rpc, response, &id);
    } else if (strcmp(method, "sendTransaction") == 0) {
        handle_send_transaction(rpc, response, &id, has_params ? &params_parser : NULL);
    } else if (strcmp(method, "getTransaction") == 0) {
        handle_get_transaction(rpc, response, &id, has_params ? &params_parser : NULL);
    } else if (strcmp(method, "getSignatureStatuses") == 0) {
        handle_get_signature_statuses(rpc, response, &id, has_params ? &params_parser : NULL);
    } else if (strcmp(method, "simulateTransaction") == 0) {
        handle_simulate_transaction(rpc, response, &id, has_params ? &params_parser : NULL);
    } else if (strcmp(method, "getBlock") == 0) {
        handle_get_block(rpc, response, &id, has_params ? &params_parser : NULL);
    } else if (strcmp(method, "getBlocks") == 0) {
        handle_get_blocks(rpc, response, &id, has_params ? &params_parser : NULL);
    } else if (strcmp(method, "getBlocksWithLimit") == 0) {
        handle_get_blocks_with_limit(rpc, response, &id, has_params ? &params_parser : NULL);
    } else if (strcmp(method, "getMultipleAccounts") == 0) {
        handle_get_multiple_accounts(rpc, response, &id, has_params ? &params_parser : NULL);
    } else if (strcmp(method, "getProgramAccounts") == 0) {
        handle_get_program_accounts(rpc, response, &id, has_params ? &params_parser : NULL);
    } else if (strcmp(method, "getTokenAccountsByOwner") == 0) {
        handle_get_token_accounts_by_owner(rpc, response, &id, has_params ? &params_parser : NULL);
    } else if (strcmp(method, "getTokenAccountBalance") == 0) {
        handle_get_token_account_balance(rpc, response, &id, has_params ? &params_parser : NULL);
    } else if (strcmp(method, "getTokenSupply") == 0) {
        handle_get_token_supply(rpc, response, &id, has_params ? &params_parser : NULL);
    } else if (strcmp(method, "getSlotLeader") == 0) {
        handle_get_slot_leader(rpc, response, &id);
    } else if (strcmp(method, "getLeaderSchedule") == 0) {
        handle_get_leader_schedule(rpc, response, &id, has_params ? &params_parser : NULL);
    } else if (strcmp(method, "getVoteAccounts") == 0) {
        handle_get_vote_accounts(rpc, response, &id);
    } else if (strcmp(method, "getClusterNodes") == 0) {
        handle_get_cluster_nodes(rpc, response, &id);
    } else if (strcmp(method, "getInflationGovernor") == 0) {
        handle_get_inflation_governor(rpc, response, &id);
    } else if (strcmp(method, "getInflationRate") == 0) {
        handle_get_inflation_rate(rpc, response, &id);
    } else if (strcmp(method, "getStakeActivation") == 0) {
        handle_get_stake_activation(rpc, response, &id, has_params ? &params_parser : NULL);
    } else if (strcmp(method, "getMinimumBalanceForRentExemption") == 0) {
        handle_get_minimum_balance_for_rent_exemption(rpc, response, &id, has_params ? &params_parser : NULL);
    } else if (strcmp(method, "getFeeForMessage") == 0) {
        handle_get_fee_for_message(rpc, response, &id, has_params ? &params_parser : NULL);
    } else if (strcmp(method, "getTransactionCount") == 0) {
        handle_get_transaction_count(rpc, response, &id);
    } else if (strcmp(method, "getRecentPerformanceSamples") == 0) {
        handle_get_recent_performance_samples(rpc, response, &id,
                                              has_params ? &params_parser : NULL);
    } else if (strcmp(method, "getRecentPrioritizationFees") == 0) {
        handle_get_recent_prioritization_fees(rpc, response, &id, has_params ? &params_parser : NULL);
    } else if (strcmp(method, "getSignaturesForAddress") == 0) {
        handle_get_signatures_for_address(rpc, response, &id, has_params ? &params_parser : NULL);
    } else if (strcmp(method, "getFirstAvailableBlock") == 0) {
        handle_get_first_available_block(rpc, response, &id);
    } else if (strcmp(method, "isBlockhashValid") == 0) {
        handle_is_blockhash_valid(rpc, response, &id, has_params ? &params_parser : NULL);
    } else if (strcmp(method, "getTokenLargestAccounts") == 0) {
        handle_get_token_largest_accounts(rpc, response, &id, has_params ? &params_parser : NULL);
    } else if (strcmp(method, "requestAirdrop") == 0) {
        handle_request_airdrop(rpc, response, &id, has_params ? &params_parser : NULL);
    } else if (strcmp(method, "getBlockProduction") == 0) {
        handle_get_block_production(rpc, response, &id);
    } else if (strcmp(method, "getHighestSnapshotSlot") == 0) {
        handle_get_highest_snapshot_slot(rpc, response, &id);
    } else if (strcmp(method, "getSupply") == 0) {
        handle_get_supply(rpc, response, &id);
    } else if (strcmp(method, "getBlockTime") == 0) {
        handle_get_block_time(rpc, response, &id, has_params ? &params_parser : NULL);
    } else if (strcmp(method, "getBlockCommitment") == 0) {
        handle_get_block_commitment(rpc, response, &id, has_params ? &params_parser : NULL);
    } else if (strcmp(method, "getGenesisHash") == 0) {
        handle_get_genesis_hash(rpc, response, &id);
    } else if (strcmp(method, "getIdentity") == 0) {
        handle_get_identity(rpc, response, &id);
    } else {
        rpc_error_response(response, &id, SOL_RPC_ERR_METHOD_NOT_FOUND, "Method not found");
    }

    __atomic_fetch_add(&rpc->stats.requests_total, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&rpc->stats.requests_success, 1, __ATOMIC_RELAXED);
}

/*
 * HTTP handling
 */
static inline ssize_t
rpc_send_once(int fd, const void* buf, size_t len) {
#ifdef MSG_NOSIGNAL
    return send(fd, buf, len, MSG_NOSIGNAL);
#else
    return send(fd, buf, len, 0);
#endif
}

static size_t
rpc_send_all(int fd, const void* buf, size_t len) {
    const char* p = (const char*)buf;
    size_t sent = 0;

    while (sent < len) {
        ssize_t n = rpc_send_once(fd, p + sent, len - sent);
        if (n > 0) {
            sent += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        /* Treat EAGAIN/EWOULDBLOCK as a timeout (SO_SNDTIMEO). */
        break;
    }

    return sent;
}

static size_t
rpc_http_send_response(int client_fd,
                       int status_code,
                       const char* status_text,
                       const char* content_type,
                       const char* body,
                       size_t body_len,
                       bool send_body) {
    char header[512];
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        status_code,
        status_text ? status_text : "OK",
        content_type ? content_type : "text/plain",
        body_len
    );

    size_t bytes_sent = 0;

    if (header_len > 0) {
        size_t hdr_len = (size_t)header_len;
        if (hdr_len > sizeof(header)) hdr_len = sizeof(header);
        bytes_sent += rpc_send_all(client_fd, header, hdr_len);
    }
    if (send_body && body && body_len > 0) {
        bytes_sent += rpc_send_all(client_fd, body, body_len);
    }

    return bytes_sent;
}

static bool
rpc_http_parse_request_line(const char* request,
                            char* method_out,
                            size_t method_out_len,
                            char* path_out,
                            size_t path_out_len) {
    if (!request || !method_out || method_out_len == 0 || !path_out || path_out_len == 0) {
        return false;
    }

    method_out[0] = '\0';
    path_out[0] = '\0';

    if (sscanf(request, "%7s %255s", method_out, path_out) != 2) {
        return false;
    }

    method_out[method_out_len - 1] = '\0';
    path_out[path_out_len - 1] = '\0';

    /* Strip query string */
    char* q = strchr(path_out, '?');
    if (q) *q = '\0';

    return true;
}

static bool
rpc_http_handle_health(sol_rpc_t* rpc, int client_fd, const char* method, const char* path) {
    if (!rpc || !method || !path) return false;
    if (!rpc->config.enable_health_check) return false;

    bool is_get = (strcmp(method, "GET") == 0);
    bool is_head = (strcmp(method, "HEAD") == 0);
    if (!is_get && !is_head) return false;

    bool send_body = !is_head;

    if (strcmp(path, SOL_HEALTH_PATH) == 0 || strcmp(path, "/") == 0) {
        sol_health_result_t result = {0};
        if (rpc->health_callback) {
            result = rpc->health_callback(rpc->health_callback_ctx);
        } else {
            result.status = SOL_HEALTH_OK;
            result.message = "RPC running";
            result.has_identity = rpc->identity_set;
        }

        char body[4096];
        size_t body_len = sol_health_render_json(&result, body, sizeof(body));

        int status_code = (result.status == SOL_HEALTH_UNHEALTHY) ? 503 : 200;
        size_t bytes_sent = rpc_http_send_response(
            client_fd,
            status_code,
            (status_code == 200) ? "OK" : "Service Unavailable",
            "application/json",
            body,
            body_len,
            send_body
        );
        __atomic_fetch_add(&rpc->stats.bytes_sent, bytes_sent, __ATOMIC_RELAXED);
        return true;
    }

    if (strcmp(path, SOL_HEALTH_LIVE_PATH) == 0) {
        if (rpc->running) {
            size_t bytes_sent = rpc_http_send_response(client_fd, 200, "OK", "text/plain", "ok\n", 3, send_body);
            __atomic_fetch_add(&rpc->stats.bytes_sent, bytes_sent, __ATOMIC_RELAXED);
        } else {
            size_t bytes_sent = rpc_http_send_response(client_fd, 503, "Service Unavailable", "text/plain", "not ok\n", 7, send_body);
            __atomic_fetch_add(&rpc->stats.bytes_sent, bytes_sent, __ATOMIC_RELAXED);
        }
        return true;
    }

    if (strcmp(path, SOL_HEALTH_READY_PATH) == 0) {
        sol_health_result_t result = {0};
        if (rpc->health_callback) {
            result = rpc->health_callback(rpc->health_callback_ctx);
        } else {
            result.status = SOL_HEALTH_OK;
            result.has_identity = rpc->identity_set;
        }

        bool ready = (result.status == SOL_HEALTH_OK) &&
                     !result.is_syncing &&
                     result.has_identity;

        if (ready) {
            size_t bytes_sent = rpc_http_send_response(client_fd, 200, "OK", "text/plain", "ready\n", 6, send_body);
            __atomic_fetch_add(&rpc->stats.bytes_sent, bytes_sent, __ATOMIC_RELAXED);
        } else {
            size_t bytes_sent = rpc_http_send_response(client_fd, 503, "Service Unavailable", "text/plain", "not ready\n", 10, send_body);
            __atomic_fetch_add(&rpc->stats.bytes_sent, bytes_sent, __ATOMIC_RELAXED);
        }
        return true;
    }

    return false;
}

static void
handle_client(sol_rpc_t* rpc, int client_fd) {
    /* Enforce a bounded lifetime per request so untrusted clients can't pin
     * per-connection threads indefinitely. */
    uint32_t timeout_ms = rpc ? (uint32_t)rpc->config.request_timeout_ms : 2000u;
    if (timeout_ms == 0) timeout_ms = 30000u;
    struct timeval tv = {
        .tv_sec = (time_t)(timeout_ms / 1000u),
        .tv_usec = (suseconds_t)((timeout_ms % 1000u) * 1000u),
    };
    (void)setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    char buffer[65536];
    ssize_t n = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (n <= 0) {
        return;
    }
    buffer[n] = '\0';

    __atomic_fetch_add(&rpc->stats.bytes_received, n, __ATOMIC_RELAXED);

    char method[8] = {0};
    char path[256] = {0};
    if (rpc_http_parse_request_line(buffer, method, sizeof(method), path, sizeof(path))) {
        if (rpc_http_handle_health(rpc, client_fd, method, path)) {
            return;
        }
        if (strcmp(method, "GET") == 0 || strcmp(method, "HEAD") == 0) {
            size_t bytes_sent = rpc_http_send_response(
                client_fd, 404, "Not Found", "text/plain", "Not Found\n", 10, true);
            __atomic_fetch_add(&rpc->stats.bytes_sent, bytes_sent, __ATOMIC_RELAXED);
            return;
        }
        if (strcmp(method, "POST") != 0) {
            size_t bytes_sent = rpc_http_send_response(
                client_fd, 405, "Method Not Allowed", "text/plain", "Method Not Allowed\n", 19, true);
            __atomic_fetch_add(&rpc->stats.bytes_sent, bytes_sent, __ATOMIC_RELAXED);
            return;
        }
    } else {
        size_t bytes_sent = rpc_http_send_response(
            client_fd, 400, "Bad Request", "text/plain", "Bad Request\n", 12, true);
        __atomic_fetch_add(&rpc->stats.bytes_sent, bytes_sent, __ATOMIC_RELAXED);
        return;
    }

    /* Find body (after headers) */
    const char* body = strstr(buffer, "\r\n\r\n");
    if (!body) {
        size_t bytes_sent = rpc_http_send_response(client_fd, 400, "Bad Request",
                                                   "text/plain", "Bad Request\n", 12, true);
        __atomic_fetch_add(&rpc->stats.bytes_sent, bytes_sent, __ATOMIC_RELAXED);
        return;
    }
    body += 4;
    size_t body_len = n - (body - buffer);

    /* Build response */
    sol_json_builder_t* response = sol_json_builder_new(4096);
    sol_rpc_handle_request_json(rpc, body, body_len, response);

    /* Send HTTP response */
    const char* json = sol_json_builder_str(response);
    size_t json_len = sol_json_builder_len(response);

    size_t bytes_sent = rpc_http_send_response(client_fd, 200, "OK", "application/json", json, json_len, true);
    __atomic_fetch_add(&rpc->stats.bytes_sent, bytes_sent, __ATOMIC_RELAXED);

    sol_json_builder_destroy(response);
}

typedef struct {
    sol_rpc_t* rpc;
    int        client_fd;
} rpc_client_ctx_t;

static bool
rpc_track_http_client_fd(sol_rpc_t* rpc, int client_fd) {
    if (!rpc || client_fd < 0) return false;

    pthread_mutex_lock(&rpc->lock);
    for (int i = 0; i < MAX_HTTP_CLIENTS; i++) {
        if (!rpc->http_clients[i].active) {
            rpc->http_clients[i].active = true;
            rpc->http_clients[i].fd = client_fd;
            pthread_mutex_unlock(&rpc->lock);
            return true;
        }
    }
    pthread_mutex_unlock(&rpc->lock);
    return false;
}

static void
rpc_untrack_http_client_fd(sol_rpc_t* rpc, int client_fd) {
    if (!rpc || client_fd < 0) return;

    pthread_mutex_lock(&rpc->lock);
    for (int i = 0; i < MAX_HTTP_CLIENTS; i++) {
        if (rpc->http_clients[i].active && rpc->http_clients[i].fd == client_fd) {
            rpc->http_clients[i].active = false;
            rpc->http_clients[i].fd = -1;
            break;
        }
    }
    pthread_mutex_unlock(&rpc->lock);
}

static void
rpc_shutdown_http_clients(sol_rpc_t* rpc) {
    if (!rpc) return;

    pthread_mutex_lock(&rpc->lock);
    for (int i = 0; i < MAX_HTTP_CLIENTS; i++) {
        if (!rpc->http_clients[i].active) continue;
        if (rpc->http_clients[i].fd >= 0) {
            (void)shutdown(rpc->http_clients[i].fd, SHUT_RDWR);
        }
    }
    pthread_mutex_unlock(&rpc->lock);
}

static void*
rpc_client_thread_fn(void* arg) {
    rpc_client_ctx_t* ctx = (rpc_client_ctx_t*)arg;
    if (!ctx) return NULL;
    handle_client(ctx->rpc, ctx->client_fd);
    rpc_untrack_http_client_fd(ctx->rpc, ctx->client_fd);
    close(ctx->client_fd);
    __atomic_fetch_sub(&ctx->rpc->stats.active_connections, 1, __ATOMIC_RELAXED);
    sol_free(ctx);
    return NULL;
}

/*
 * Accept thread
 */
static void*
accept_thread_fn(void* arg) {
    sol_rpc_t* rpc = (sol_rpc_t*)arg;
    uint64_t last_emfile_log_ms = 0;

    while (rpc->running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(rpc->listen_fd,
                               (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1000);
                continue;
            }
            if (errno == EMFILE || errno == ENFILE) {
                uint64_t now = rpc_now_ms();
                if (rpc->running &&
                    (last_emfile_log_ms == 0 || (now - last_emfile_log_ms) >= 1000u)) {
                    last_emfile_log_ms = now;
                    sol_log_warn("RPC accept failed: %s (fd pressure; backing off)",
                                 strerror(errno));
                }
                usleep(20000);
                continue;
            }
            if (rpc->running) {
                sol_log_warn("RPC accept failed: %s", strerror(errno));
            }
            usleep(1000);
            continue;
        }

        /* Don't leak client sockets into snapshot helper processes (curl/zstd). */
        {
            int fd_flags = fcntl(client_fd, F_GETFD, 0);
            if (fd_flags >= 0) {
                (void)fcntl(client_fd, F_SETFD, fd_flags | FD_CLOEXEC);
            }
        }

        size_t max_conn = __atomic_load_n(&rpc->max_connections_runtime, __ATOMIC_ACQUIRE);
        if (max_conn > 0) {
            uint64_t active = __atomic_load_n(&rpc->stats.active_connections, __ATOMIC_RELAXED);
            if (active >= (uint64_t)max_conn) {
                close(client_fd);
                continue;
            }
        }

        __atomic_fetch_add(&rpc->stats.active_connections, 1, __ATOMIC_RELAXED);
        rpc_client_ctx_t* ctx = sol_calloc(1, sizeof(*ctx));
        if (!ctx) {
            __atomic_fetch_sub(&rpc->stats.active_connections, 1, __ATOMIC_RELAXED);
            close(client_fd);
            continue;
        }
        ctx->rpc = rpc;
        ctx->client_fd = client_fd;

        if (!rpc_track_http_client_fd(rpc, client_fd)) {
            __atomic_fetch_sub(&rpc->stats.active_connections, 1, __ATOMIC_RELAXED);
            close(client_fd);
            sol_free(ctx);
            continue;
        }

        pthread_t thr;
        if (pthread_create(&thr, NULL, rpc_client_thread_fn, ctx) != 0) {
            rpc_untrack_http_client_fd(rpc, client_fd);
            __atomic_fetch_sub(&rpc->stats.active_connections, 1, __ATOMIC_RELAXED);
            close(client_fd);
            sol_free(ctx);
            continue;
        }
        pthread_detach(thr);
    }

    return NULL;
}

/*
 * WebSocket frame encoding
 */
static size_t
ws_encode_frame(uint8_t* out, size_t out_max, const char* payload, size_t payload_len) {
    if (out_max < 2 + payload_len) return 0;

    size_t idx = 0;
    out[idx++] = 0x81;  /* FIN + text opcode */

    if (payload_len < 126) {
        out[idx++] = (uint8_t)payload_len;
    } else if (payload_len < 65536) {
        if (out_max < 4 + payload_len) return 0;
        out[idx++] = 126;
        out[idx++] = (payload_len >> 8) & 0xFF;
        out[idx++] = payload_len & 0xFF;
    } else {
        if (out_max < 10 + payload_len) return 0;
        out[idx++] = 127;
        for (int i = 7; i >= 0; i--) {
            out[idx++] = (payload_len >> (i * 8)) & 0xFF;
        }
    }

    memcpy(&out[idx], payload, payload_len);
    return idx + payload_len;
}

/*
 * WebSocket handshake
 */
static bool
ws_handshake(int client_fd, const char* request, size_t request_len) {
    (void)request_len;  /* Request is null-terminated, length not needed */
    /* Find Sec-WebSocket-Key header */
    const char* key_header = strstr(request, "Sec-WebSocket-Key:");
    if (!key_header) return false;

    key_header += 18;
    while (*key_header == ' ') key_header++;

    char key[64] = {0};
    int i = 0;
    while (key_header[i] && key_header[i] != '\r' && i < 63) {
        key[i] = key_header[i];
        i++;
    }

    /* Compute accept key: SHA-1(key + GUID) -> base64 */
    const char* guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char concat[128];
    snprintf(concat, sizeof(concat), "%s%s", key, guid);

    /* Simple SHA-1 (use our crypto lib) */
    sol_sha256_t hash;
    sol_sha256_ctx_t sha_ctx;
    sol_sha256_init(&sha_ctx);
    sol_sha256_update(&sha_ctx, (const uint8_t*)concat, strlen(concat));
    sol_sha256_final(&sha_ctx, &hash);

    /* Base64 encode first 20 bytes (SHA-1 is 20 bytes but we have SHA-256) */
    char accept[64];
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int j = 0;
    for (int k = 0; k < 18; k += 3) {
        uint32_t n = (hash.bytes[k] << 16) | (hash.bytes[k+1] << 8) | hash.bytes[k+2];
        accept[j++] = b64[(n >> 18) & 0x3F];
        accept[j++] = b64[(n >> 12) & 0x3F];
        accept[j++] = b64[(n >> 6) & 0x3F];
        accept[j++] = b64[n & 0x3F];
    }
    /* Handle last 2 bytes */
    uint32_t n = (hash.bytes[18] << 16) | (hash.bytes[19] << 8);
    accept[j++] = b64[(n >> 18) & 0x3F];
    accept[j++] = b64[(n >> 12) & 0x3F];
    accept[j++] = b64[(n >> 6) & 0x3F];
    accept[j++] = '=';
    accept[j] = '\0';

    /* Send handshake response */
    char response[512];
    int len = snprintf(response, sizeof(response),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "\r\n", accept);

    (void)rpc_send_all(client_fd, response, (size_t)len);
    return true;
}

/*
 * Handle WebSocket subscription request
 */
static void
ws_handle_subscribe(sol_rpc_t* rpc, int client_fd, const char* method,
                    sol_json_parser_t* params, const char* id) {
    pthread_mutex_lock(&rpc->ws_lock);

    /* Find free subscription slot */
    int slot = -1;
    for (int i = 0; i < MAX_WS_SUBSCRIPTIONS; i++) {
        if (!rpc->ws_subscriptions[i].active) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        pthread_mutex_unlock(&rpc->ws_lock);
        /* Send error - too many subscriptions */
        char error[256];
        snprintf(error, sizeof(error),
            "{\"jsonrpc\":\"2.0\",\"id\":%s,\"error\":{\"code\":-32000,\"message\":\"Too many subscriptions\"}}",
            id);
        uint8_t frame[512];
        size_t frame_len = ws_encode_frame(frame, sizeof(frame), error, strlen(error));
        (void)rpc_send_all(client_fd, frame, frame_len);
        return;
    }

    sol_ws_subscription_t* sub = &rpc->ws_subscriptions[slot];
    sub->id = rpc->ws_next_sub_id++;
    sub->client_fd = client_fd;
    sub->active = true;
    sub->commitment = SOL_COMMITMENT_FINALIZED;

    /* Determine subscription type */
    if (strcmp(method, "accountSubscribe") == 0) {
        sub->type = SOL_WS_SUB_ACCOUNT;
        /* Parse pubkey from params */
        if (sol_json_parser_array_begin(params)) {
            char pubkey_str[64] = {0};
            if (sol_json_parser_string(params, pubkey_str, sizeof(pubkey_str))) {
                sol_pubkey_from_base58(pubkey_str, &sub->pubkey);
            }
        }
    } else if (strcmp(method, "slotSubscribe") == 0) {
        sub->type = SOL_WS_SUB_SLOT;
    } else if (strcmp(method, "signatureSubscribe") == 0) {
        sub->type = SOL_WS_SUB_SIGNATURE;
        /* Parse signature from params */
        if (sol_json_parser_array_begin(params)) {
            char sig_str[128] = {0};
            if (sol_json_parser_string(params, sig_str, sizeof(sig_str))) {
                sol_signature_from_base58(sig_str, &sub->signature);
            }
        }
    } else if (strcmp(method, "logsSubscribe") == 0) {
        sub->type = SOL_WS_SUB_LOGS;
    } else if (strcmp(method, "programSubscribe") == 0) {
        sub->type = SOL_WS_SUB_PROGRAM;
        if (sol_json_parser_array_begin(params)) {
            char pubkey_str[64] = {0};
            if (sol_json_parser_string(params, pubkey_str, sizeof(pubkey_str))) {
                sol_pubkey_from_base58(pubkey_str, &sub->pubkey);
            }
        }
    } else if (strcmp(method, "rootSubscribe") == 0) {
        sub->type = SOL_WS_SUB_ROOT;
    } else {
        sub->active = false;
        pthread_mutex_unlock(&rpc->ws_lock);
        return;
    }

    __atomic_fetch_add(&rpc->stats.ws_subscriptions, 1, __ATOMIC_RELAXED);
    pthread_mutex_unlock(&rpc->ws_lock);

    /* Send subscription ID */
    char response[256];
    snprintf(response, sizeof(response),
        "{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":%lu}",
        id, (unsigned long)sub->id);

    uint8_t frame[512];
    size_t frame_len = ws_encode_frame(frame, sizeof(frame), response, strlen(response));
    (void)rpc_send_all(client_fd, frame, frame_len);
}

/*
 * Handle WebSocket unsubscribe request
 */
static void
ws_handle_unsubscribe(sol_rpc_t* rpc, int client_fd, sol_json_parser_t* params, const char* id) {
    uint64_t sub_id = 0;

    if (sol_json_parser_array_begin(params)) {
        sol_json_parser_uint(params, &sub_id);
    }

    pthread_mutex_lock(&rpc->ws_lock);

    bool found = false;
    for (int i = 0; i < MAX_WS_SUBSCRIPTIONS; i++) {
        if (rpc->ws_subscriptions[i].active && rpc->ws_subscriptions[i].id == sub_id) {
            rpc->ws_subscriptions[i].active = false;
            __atomic_fetch_sub(&rpc->stats.ws_subscriptions, 1, __ATOMIC_RELAXED);
            found = true;
            break;
        }
    }

    pthread_mutex_unlock(&rpc->ws_lock);

    char response[256];
    snprintf(response, sizeof(response),
        "{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":%s}",
        id, found ? "true" : "false");

    uint8_t frame[512];
    size_t frame_len = ws_encode_frame(frame, sizeof(frame), response, strlen(response));
    (void)rpc_send_all(client_fd, frame, frame_len);
}

/*
 * Handle WebSocket message
 */
static void
ws_handle_message(sol_rpc_t* rpc, int client_fd, const char* message, size_t len) {
    sol_json_parser_t parser;
    sol_json_parser_init(&parser, message, len);

    if (!sol_json_parser_object_begin(&parser)) return;

    char method[64] = {0};
    char id[32] = "null";
    sol_json_parser_t params_parser = {0};
    bool has_params = false;

    char key[32];
    while (sol_json_parser_key(&parser, key, sizeof(key))) {
        if (strcmp(key, "method") == 0) {
            sol_json_parser_string(&parser, method, sizeof(method));
        } else if (strcmp(key, "id") == 0) {
            /* Read id as raw value */
            size_t start = parser.pos;
            sol_json_parser_skip(&parser);
            size_t end = parser.pos;
            if (end - start < sizeof(id)) {
                memcpy(id, &message[start], end - start);
                id[end - start] = '\0';
            }
        } else if (strcmp(key, "params") == 0) {
            params_parser = parser;
            has_params = true;
            sol_json_parser_skip(&parser);
        } else {
            sol_json_parser_skip(&parser);
        }
    }

    /* Handle subscription methods */
    if (strstr(method, "Subscribe") != NULL && strstr(method, "Unsubscribe") == NULL) {
        ws_handle_subscribe(rpc, client_fd, method, has_params ? &params_parser : NULL, id);
    } else if (strstr(method, "Unsubscribe") != NULL) {
        ws_handle_unsubscribe(rpc, client_fd, has_params ? &params_parser : NULL, id);
    }
}

/*
 * Handle WebSocket client
 */
static void
ws_handle_client(sol_rpc_t* rpc, int client_fd) {
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    (void)setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    char buffer[65536];
    ssize_t n = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (n <= 0) {
        return;
    }
    buffer[n] = '\0';

    /* Check for WebSocket upgrade request */
    if (strstr(buffer, "Upgrade: websocket") != NULL ||
        strstr(buffer, "upgrade: websocket") != NULL) {
        if (!ws_handshake(client_fd, buffer, n)) {
            return;
        }

        /* Add to client list */
        pthread_mutex_lock(&rpc->ws_lock);
        for (int i = 0; i < MAX_WS_CLIENTS; i++) {
            if (!rpc->ws_clients[i].active) {
                rpc->ws_clients[i].fd = client_fd;
                rpc->ws_clients[i].active = true;
                __atomic_fetch_add(&rpc->stats.ws_connections, 1, __ATOMIC_RELAXED);
                break;
            }
        }
        pthread_mutex_unlock(&rpc->ws_lock);

        /* Read WebSocket frames */
        while (rpc->running) {
            uint8_t frame[65536];
            ssize_t frame_len = recv(client_fd, frame, sizeof(frame), 0);
            if (frame_len <= 0) break;

            /* Parse WebSocket frame */
            if (frame_len < 2) continue;

            uint8_t opcode = frame[0] & 0x0F;
            bool masked = (frame[1] & 0x80) != 0;
            size_t payload_len = frame[1] & 0x7F;
            size_t header_len = 2;

            if (payload_len == 126) {
                if (frame_len < 4) continue;
                payload_len = (frame[2] << 8) | frame[3];
                header_len = 4;
            } else if (payload_len == 127) {
                if (frame_len < 10) continue;
                payload_len = 0;
                for (int i = 0; i < 8; i++) {
                    payload_len = (payload_len << 8) | frame[2 + i];
                }
                header_len = 10;
            }

            if (masked) header_len += 4;

            if (frame_len < header_len + payload_len) continue;

            /* Unmask payload if needed */
            char* payload = (char*)&frame[header_len];
            if (masked) {
                uint8_t* mask = &frame[header_len - 4];
                for (size_t i = 0; i < payload_len; i++) {
                    payload[i] ^= mask[i % 4];
                }
            }

            if (opcode == 0x08) {
                /* Close frame */
                break;
            } else if (opcode == 0x09) {
                /* Ping - send pong */
                uint8_t pong[2] = {0x8A, 0x00};
                (void)rpc_send_all(client_fd, pong, 2);
            } else if (opcode == 0x01) {
                /* Text frame */
                ws_handle_message(rpc, client_fd, payload, payload_len);
            }
        }

        /* Remove from client list and cleanup subscriptions */
        pthread_mutex_lock(&rpc->ws_lock);
        for (int i = 0; i < MAX_WS_CLIENTS; i++) {
            if (rpc->ws_clients[i].fd == client_fd) {
                rpc->ws_clients[i].active = false;
                __atomic_fetch_sub(&rpc->stats.ws_connections, 1, __ATOMIC_RELAXED);
                break;
            }
        }
        /* Remove subscriptions for this client */
        for (int i = 0; i < MAX_WS_SUBSCRIPTIONS; i++) {
            if (rpc->ws_subscriptions[i].active &&
                rpc->ws_subscriptions[i].client_fd == client_fd) {
                rpc->ws_subscriptions[i].active = false;
                __atomic_fetch_sub(&rpc->stats.ws_subscriptions, 1, __ATOMIC_RELAXED);
            }
        }
        pthread_mutex_unlock(&rpc->ws_lock);
    }
}

typedef struct {
    sol_rpc_t* rpc;
    int        client_fd;
} ws_client_ctx_t;

static void*
ws_client_thread_fn(void* arg) {
    ws_client_ctx_t* ctx = (ws_client_ctx_t*)arg;
    if (!ctx) return NULL;
    ws_handle_client(ctx->rpc, ctx->client_fd);
    close(ctx->client_fd);
    sol_free(ctx);
    return NULL;
}

/*
 * WebSocket accept thread
 */
static void*
ws_accept_thread_fn(void* arg) {
    sol_rpc_t* rpc = (sol_rpc_t*)arg;
    uint64_t last_emfile_log_ms = 0;

    while (rpc->running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(rpc->ws_listen_fd,
                               (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1000);
                continue;
            }
            if (errno == EMFILE || errno == ENFILE) {
                uint64_t now = rpc_now_ms();
                if (rpc->running &&
                    (last_emfile_log_ms == 0 || (now - last_emfile_log_ms) >= 1000u)) {
                    last_emfile_log_ms = now;
                    sol_log_warn("WebSocket accept failed: %s (fd pressure; backing off)",
                                 strerror(errno));
                }
                usleep(20000);
                continue;
            }
            if (rpc->running) {
                sol_log_warn("WebSocket accept failed: %s", strerror(errno));
            }
            usleep(1000);
            continue;
        }

        /* Don't leak client sockets into snapshot helper processes (curl/zstd). */
        {
            int fd_flags = fcntl(client_fd, F_GETFD, 0);
            if (fd_flags >= 0) {
                (void)fcntl(client_fd, F_SETFD, fd_flags | FD_CLOEXEC);
            }
        }

        ws_client_ctx_t* ctx = sol_calloc(1, sizeof(*ctx));
        if (!ctx) {
            close(client_fd);
            continue;
        }
        ctx->rpc = rpc;
        ctx->client_fd = client_fd;

        pthread_t thr;
        if (pthread_create(&thr, NULL, ws_client_thread_fn, ctx) != 0) {
            close(client_fd);
            sol_free(ctx);
            continue;
        }
        pthread_detach(thr);
    }

    return NULL;
}

/*
 * Notification functions
 */
void
sol_rpc_notify_account(sol_rpc_t* rpc, const sol_pubkey_t* pubkey,
                       const sol_account_t* account, sol_slot_t slot) {
    if (!rpc) return;

    pthread_mutex_lock(&rpc->ws_lock);

    for (int i = 0; i < MAX_WS_SUBSCRIPTIONS; i++) {
        sol_ws_subscription_t* sub = &rpc->ws_subscriptions[i];
        if (!sub->active || sub->type != SOL_WS_SUB_ACCOUNT) continue;
        if (!sol_pubkey_eq(&sub->pubkey, pubkey)) continue;

        /* Build notification */
        char owner_str[64];
        sol_pubkey_to_base58(&account->meta.owner, owner_str, sizeof(owner_str));

        char notification[4096];
        int len = snprintf(notification, sizeof(notification),
            "{\"jsonrpc\":\"2.0\",\"method\":\"accountNotification\","
            "\"params\":{\"subscription\":%lu,\"result\":{\"context\":{\"slot\":%lu},"
            "\"value\":{\"lamports\":%lu,\"data\":[\"\",\"base64\"],"
            "\"owner\":\"%s\",\"executable\":%s,\"rentEpoch\":%lu}}}}",
            (unsigned long)sub->id, (unsigned long)slot,
            (unsigned long)account->meta.lamports,
            owner_str,
            account->meta.executable ? "true" : "false",
            (unsigned long)account->meta.rent_epoch);

        uint8_t frame[8192];
        size_t frame_len = ws_encode_frame(frame, sizeof(frame), notification, len);
        (void)rpc_send_all(sub->client_fd, frame, frame_len);
    }

    pthread_mutex_unlock(&rpc->ws_lock);
}

void
sol_rpc_notify_slot(sol_rpc_t* rpc, sol_slot_t slot, sol_slot_t parent, const char* status) {
    if (!rpc) return;

    pthread_mutex_lock(&rpc->ws_lock);

    for (int i = 0; i < MAX_WS_SUBSCRIPTIONS; i++) {
        sol_ws_subscription_t* sub = &rpc->ws_subscriptions[i];
        if (!sub->active || sub->type != SOL_WS_SUB_SLOT) continue;

        char notification[512];
        int len = snprintf(notification, sizeof(notification),
            "{\"jsonrpc\":\"2.0\",\"method\":\"slotNotification\","
            "\"params\":{\"subscription\":%lu,\"result\":{\"parent\":%lu,\"root\":%lu,\"slot\":%lu}}}",
            (unsigned long)sub->id, (unsigned long)parent,
            (unsigned long)parent, (unsigned long)slot);

        uint8_t frame[1024];
        size_t frame_len = ws_encode_frame(frame, sizeof(frame), notification, len);
        (void)rpc_send_all(sub->client_fd, frame, frame_len);
    }

    pthread_mutex_unlock(&rpc->ws_lock);
    (void)status;
}

void
sol_rpc_notify_signature(sol_rpc_t* rpc, const sol_signature_t* signature,
                         sol_slot_t slot, sol_err_t err) {
    if (!rpc || !signature) return;

    pthread_mutex_lock(&rpc->ws_lock);

    for (int i = 0; i < MAX_WS_SUBSCRIPTIONS; i++) {
        sol_ws_subscription_t* sub = &rpc->ws_subscriptions[i];
        if (!sub->active || sub->type != SOL_WS_SUB_SIGNATURE) continue;
        if (memcmp(&sub->signature, signature, sizeof(sol_signature_t)) != 0) continue;

        char notification[512];
        int len;
        if (err == SOL_OK) {
            len = snprintf(notification, sizeof(notification),
                "{\"jsonrpc\":\"2.0\",\"method\":\"signatureNotification\","
                "\"params\":{\"subscription\":%lu,\"result\":{\"context\":{\"slot\":%lu},"
                "\"value\":{\"err\":null}}}}",
                (unsigned long)sub->id, (unsigned long)slot);
        } else {
            len = snprintf(notification, sizeof(notification),
                "{\"jsonrpc\":\"2.0\",\"method\":\"signatureNotification\","
                "\"params\":{\"subscription\":%lu,\"result\":{\"context\":{\"slot\":%lu},"
                "\"value\":{\"err\":{\"InstructionError\":[0,%d]}}}}}",
                (unsigned long)sub->id, (unsigned long)slot, (int)err);
        }

        uint8_t frame[1024];
        size_t frame_len = ws_encode_frame(frame, sizeof(frame), notification, len);
        (void)rpc_send_all(sub->client_fd, frame, frame_len);

        /* Auto-unsubscribe after notification */
        sub->active = false;
        __atomic_fetch_sub(&rpc->stats.ws_subscriptions, 1, __ATOMIC_RELAXED);
    }

    pthread_mutex_unlock(&rpc->ws_lock);
}

void
sol_rpc_notify_logs(sol_rpc_t* rpc, const sol_signature_t* signature,
                    const sol_pubkey_t* program_id, const char* const* logs,
                    size_t logs_count, sol_err_t err) {
    if (!rpc) return;

    pthread_mutex_lock(&rpc->ws_lock);

    for (int i = 0; i < MAX_WS_SUBSCRIPTIONS; i++) {
        sol_ws_subscription_t* sub = &rpc->ws_subscriptions[i];
        if (!sub->active || sub->type != SOL_WS_SUB_LOGS) continue;

        char sig_str[128] = {0};
        if (signature) {
            sol_signature_to_base58(signature, sig_str, sizeof(sig_str));
        }

        /* Build logs array */
        char logs_json[4096] = "[";
        size_t pos = 1;
        for (size_t j = 0; j < logs_count && pos < sizeof(logs_json) - 100; j++) {
            if (j > 0) logs_json[pos++] = ',';
            pos += snprintf(&logs_json[pos], sizeof(logs_json) - pos, "\"%s\"", logs[j]);
        }
        logs_json[pos++] = ']';
        logs_json[pos] = '\0';

        char notification[8192];
        int len = snprintf(notification, sizeof(notification),
            "{\"jsonrpc\":\"2.0\",\"method\":\"logsNotification\","
            "\"params\":{\"subscription\":%lu,\"result\":{\"context\":{\"slot\":0},"
            "\"value\":{\"signature\":\"%s\",\"err\":%s,\"logs\":%s}}}}",
            (unsigned long)sub->id, sig_str,
            err == SOL_OK ? "null" : "\"error\"", logs_json);

        uint8_t frame[16384];
        size_t frame_len = ws_encode_frame(frame, sizeof(frame), notification, len);
        (void)rpc_send_all(sub->client_fd, frame, frame_len);
    }

    pthread_mutex_unlock(&rpc->ws_lock);
    (void)program_id;
}

/*
 * RPC Server API
 */

sol_rpc_t*
sol_rpc_new(sol_bank_forks_t* bank_forks, const sol_rpc_config_t* config) {
    sol_rpc_t* rpc = sol_calloc(1, sizeof(sol_rpc_t));
    if (!rpc) return NULL;

    if (config) {
        rpc->config = *config;
    } else {
        rpc->config = (sol_rpc_config_t)SOL_RPC_CONFIG_DEFAULT;
    }

    rpc->max_connections_runtime = rpc->config.max_connections;
    rpc->bank_forks = bank_forks;
    rpc->listen_fd = -1;
    rpc->ws_listen_fd = -1;
    rpc->ws_next_sub_id = 1;
    pthread_mutex_init(&rpc->lock, NULL);
    pthread_mutex_init(&rpc->ws_lock, NULL);
    pthread_mutex_init(&rpc->rate_lock, NULL);

    /* Normalize and initialize rate limiter */
    rpc_rate_limit_reset_locked(rpc, rpc->config.rate_limit_rps, rpc->config.rate_limit_burst);

    return rpc;
}

void
sol_rpc_destroy(sol_rpc_t* rpc) {
    if (!rpc) return;

    if (rpc->running) {
        sol_rpc_stop(rpc);
    }

    if (rpc->leader_schedule) {
        /* Wait for any in-flight readers before destroying. */
        for (;;) {
            pthread_mutex_lock(&rpc->lock);
            uint32_t readers = rpc->leader_schedule_readers;
            pthread_mutex_unlock(&rpc->lock);
            if (readers == 0) break;
            usleep(1000);
        }
        sol_leader_schedule_destroy(rpc->leader_schedule);
        rpc->leader_schedule = NULL;
    }

    pthread_mutex_destroy(&rpc->lock);
    pthread_mutex_destroy(&rpc->ws_lock);
    pthread_mutex_destroy(&rpc->rate_lock);
    sol_free(rpc);
}

sol_err_t
sol_rpc_start(sol_rpc_t* rpc) {
    if (!rpc || rpc->running) return SOL_ERR_INVAL;

    /* Create socket */
    rpc->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (rpc->listen_fd < 0) {
        sol_log_error("RPC socket creation failed: %s", strerror(errno));
        return SOL_ERR_IO;
    }

    /* Ensure listen socket isn't inherited by snapshot helper processes (curl/zstd). */
    {
        int fd_flags = fcntl(rpc->listen_fd, F_GETFD, 0);
        if (fd_flags < 0 || fcntl(rpc->listen_fd, F_SETFD, fd_flags | FD_CLOEXEC) < 0) {
            sol_log_warn("RPC fcntl(FD_CLOEXEC) failed: %s", strerror(errno));
        }
    }

    /* Allow address reuse */
    int opt = 1;
    setsockopt(rpc->listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Set non-blocking */
    int flags = fcntl(rpc->listen_fd, F_GETFL, 0);
    fcntl(rpc->listen_fd, F_SETFL, flags | O_NONBLOCK);

    /* Bind */
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(rpc->config.port);
    inet_pton(AF_INET, rpc->config.bind_address, &addr.sin_addr);

    if (bind(rpc->listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        sol_log_error("RPC bind failed: %s", strerror(errno));
        close(rpc->listen_fd);
        rpc->listen_fd = -1;
        return SOL_ERR_IO;
    }

    /* Listen */
    if (listen(rpc->listen_fd, 128) < 0) {
        sol_log_error("RPC listen failed: %s", strerror(errno));
        close(rpc->listen_fd);
        rpc->listen_fd = -1;
        return SOL_ERR_IO;
    }

    /* Start accept thread */
    rpc->running = true;
    if (pthread_create(&rpc->accept_thread, NULL, accept_thread_fn, rpc) != 0) {
        sol_log_error("RPC thread creation failed");
        rpc->running = false;
        close(rpc->listen_fd);
        rpc->listen_fd = -1;
        return SOL_ERR_AGAIN;
    }

    sol_log_info("RPC server started on %s:%u",
                 rpc->config.bind_address, rpc->config.port);

    /* Start WebSocket server if configured */
    if (rpc->config.ws_port > 0) {
        rpc->ws_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (rpc->ws_listen_fd < 0) {
            sol_log_warn("WebSocket socket creation failed: %s", strerror(errno));
        } else {
            /* Ensure listen socket isn't inherited by snapshot helper processes (curl/zstd). */
            int fd_flags = fcntl(rpc->ws_listen_fd, F_GETFD, 0);
            if (fd_flags < 0 || fcntl(rpc->ws_listen_fd, F_SETFD, fd_flags | FD_CLOEXEC) < 0) {
                sol_log_warn("WebSocket fcntl(FD_CLOEXEC) failed: %s", strerror(errno));
            }

            int opt = 1;
            setsockopt(rpc->ws_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

            int flags = fcntl(rpc->ws_listen_fd, F_GETFL, 0);
            fcntl(rpc->ws_listen_fd, F_SETFL, flags | O_NONBLOCK);

            struct sockaddr_in ws_addr = {0};
            ws_addr.sin_family = AF_INET;
            ws_addr.sin_port = htons(rpc->config.ws_port);
            inet_pton(AF_INET, rpc->config.bind_address, &ws_addr.sin_addr);

            if (bind(rpc->ws_listen_fd, (struct sockaddr*)&ws_addr, sizeof(ws_addr)) < 0) {
                sol_log_warn("WebSocket bind failed: %s", strerror(errno));
                close(rpc->ws_listen_fd);
                rpc->ws_listen_fd = -1;
            } else if (listen(rpc->ws_listen_fd, 128) < 0) {
                sol_log_warn("WebSocket listen failed: %s", strerror(errno));
                close(rpc->ws_listen_fd);
                rpc->ws_listen_fd = -1;
            } else {
                if (pthread_create(&rpc->ws_accept_thread, NULL, ws_accept_thread_fn, rpc) != 0) {
                    sol_log_warn("WebSocket thread creation failed");
                    close(rpc->ws_listen_fd);
                    rpc->ws_listen_fd = -1;
                } else {
                    sol_log_info("WebSocket server started on %s:%u",
                                 rpc->config.bind_address, rpc->config.ws_port);
                }
            }
        }
    }

    return SOL_OK;
}

sol_err_t
sol_rpc_stop(sol_rpc_t* rpc) {
    if (!rpc || !rpc->running) return SOL_ERR_INVAL;

    rpc->running = false;

    if (rpc->listen_fd >= 0) {
        close(rpc->listen_fd);
        rpc->listen_fd = -1;
    }

    if (rpc->ws_listen_fd >= 0) {
        close(rpc->ws_listen_fd);
        rpc->ws_listen_fd = -1;
    }

    pthread_join(rpc->accept_thread, NULL);

    if (rpc->config.ws_port > 0) {
        pthread_join(rpc->ws_accept_thread, NULL);
    }

    /* Force any active client threads to wake up and exit promptly. */
    rpc_shutdown_http_clients(rpc);

    /* Close any active WebSocket client connections */
    pthread_mutex_lock(&rpc->ws_lock);
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        if (rpc->ws_clients[i].active) {
            (void)shutdown(rpc->ws_clients[i].fd, SHUT_RDWR);
        }
    }
    pthread_mutex_unlock(&rpc->ws_lock);

    /* Client handler threads are detached; wait for them to drain so upstream
     * shutdown can safely destroy shared state (accounts DB / blockstore). */
    const uint64_t wait_start = sol_gossip_now_ms();
    for (;;) {
        uint64_t http_active = __atomic_load_n(&rpc->stats.active_connections, __ATOMIC_RELAXED);
        uint64_t ws_active = __atomic_load_n(&rpc->stats.ws_connections, __ATOMIC_RELAXED);
        if (http_active == 0 && ws_active == 0) {
            break;
        }
        if (sol_gossip_now_ms() - wait_start > 30000) {
            sol_log_warn("RPC stop: timed out waiting for client threads to drain (http=%lu ws=%lu)",
                         (unsigned long)http_active,
                         (unsigned long)ws_active);
            break;
        }
        usleep(1000);
    }

    sol_log_info("RPC server stopped");

    return SOL_OK;
}

bool
sol_rpc_is_running(const sol_rpc_t* rpc) {
    return rpc && rpc->running;
}

sol_rpc_stats_t
sol_rpc_stats(const sol_rpc_t* rpc) {
    sol_rpc_stats_t stats = {0};
    if (rpc) {
        stats.requests_total = __atomic_load_n(&rpc->stats.requests_total, __ATOMIC_RELAXED);
        stats.requests_success = __atomic_load_n(&rpc->stats.requests_success, __ATOMIC_RELAXED);
        stats.requests_failed = __atomic_load_n(&rpc->stats.requests_failed, __ATOMIC_RELAXED);
        stats.bytes_received = __atomic_load_n(&rpc->stats.bytes_received, __ATOMIC_RELAXED);
        stats.bytes_sent = __atomic_load_n(&rpc->stats.bytes_sent, __ATOMIC_RELAXED);
        stats.active_connections = __atomic_load_n(&rpc->stats.active_connections, __ATOMIC_RELAXED);
        stats.ws_connections = __atomic_load_n(&rpc->stats.ws_connections, __ATOMIC_RELAXED);
        stats.ws_subscriptions = __atomic_load_n(&rpc->stats.ws_subscriptions, __ATOMIC_RELAXED);
    }
    return stats;
}

void
sol_rpc_set_bank_forks(sol_rpc_t* rpc, sol_bank_forks_t* bank_forks) {
    if (rpc) {
        __atomic_store_n(&rpc->bank_forks, bank_forks, __ATOMIC_RELEASE);
    }
}

void
sol_rpc_set_blockstore(sol_rpc_t* rpc, void* blockstore) {
    if (rpc) {
        __atomic_store_n(&rpc->blockstore, (sol_blockstore_t*)blockstore, __ATOMIC_RELEASE);
    }
}

void
sol_rpc_set_gossip(sol_rpc_t* rpc, void* gossip) {
    if (rpc) {
        __atomic_store_n(&rpc->gossip, (sol_gossip_t*)gossip, __ATOMIC_RELEASE);
    }
}

void
sol_rpc_set_identity(sol_rpc_t* rpc, const sol_pubkey_t* identity) {
    if (rpc && identity) {
        memcpy(&rpc->identity, identity, sizeof(sol_pubkey_t));
        rpc->identity_set = true;
    }
}

void
sol_rpc_set_leader_schedule(sol_rpc_t* rpc, const sol_leader_schedule_t* schedule) {
    if (!rpc) return;

    sol_leader_schedule_t* copy = NULL;
    if (schedule) {
        copy = sol_leader_schedule_clone(schedule);
    }

    pthread_mutex_lock(&rpc->lock);
    sol_leader_schedule_t* old = rpc->leader_schedule;
    rpc->leader_schedule = copy;
    pthread_mutex_unlock(&rpc->lock);

    if (old) {
        /* Wait for any in-flight readers before destroying. */
        for (;;) {
            pthread_mutex_lock(&rpc->lock);
            uint32_t readers = rpc->leader_schedule_readers;
            pthread_mutex_unlock(&rpc->lock);
            if (readers == 0) break;
            usleep(1000);
        }
        sol_leader_schedule_destroy(old);
    }
}

void
sol_rpc_set_send_transaction(sol_rpc_t* rpc,
                              sol_rpc_send_tx_fn callback,
                              void* user_data) {
    if (rpc) {
        rpc->send_tx_callback = callback;
        rpc->send_tx_user_data = user_data;
    }
}

void
sol_rpc_set_health_callback(sol_rpc_t* rpc,
                            sol_health_callback_t callback,
                            void* callback_ctx) {
    if (rpc) {
        rpc->health_callback = callback;
        rpc->health_callback_ctx = callback_ctx;
    }
}

void
sol_rpc_set_rate_limit(sol_rpc_t* rpc, uint32_t rate_limit_rps, uint32_t rate_limit_burst) {
    if (!rpc) return;

    pthread_mutex_lock(&rpc->rate_lock);
    rpc_rate_limit_reset_locked(rpc, rate_limit_rps, rate_limit_burst);
    pthread_mutex_unlock(&rpc->rate_lock);
}

void
sol_rpc_set_max_connections(sol_rpc_t* rpc, size_t max_connections) {
    if (!rpc) return;
    __atomic_store_n(&rpc->max_connections_runtime, max_connections, __ATOMIC_RELEASE);
}
