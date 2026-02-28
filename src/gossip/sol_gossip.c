/*
 * sol_gossip.c - Gossip service implementation
 */

#include "sol_gossip.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include "../crypto/sol_sha256.h"
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <stdint.h>

#ifdef __APPLE__
#include <mach/mach_time.h>
#endif

/*
 * Maximum pending pings
 */
#define MAX_PENDING_PINGS 256

/*
 * Peer table entry
 */
typedef struct sol_peer_entry {
    sol_peer_t              peer;
    struct sol_peer_entry*  next;
} sol_peer_entry_t;

/*
 * Gossip service structure
 */
struct sol_gossip {
    /* Configuration */
    sol_gossip_config_t config;

    /* Network */
    sol_udp_sock_t*     sock;
    bool                running;

    /* Identity */
    sol_pubkey_t        self_pubkey;    /* Cached pubkey from keypair */
    sol_contact_info_t  self_info;

    /* CRDS store */
    sol_crds_t*         crds;

    /* Peer management */
    sol_peer_entry_t**  peer_table;     /* Hash table of peers */
    size_t              peer_table_size;
    size_t              num_peers;
    pthread_rwlock_t    peer_lock;

    /* Pending pings */
    struct {
        sol_pubkey_t    peer;
        sol_hash_t      token;
        uint64_t        sent_at;
    } pending_pings[MAX_PENDING_PINGS];
    size_t              num_pending_pings;

    /* Timing */
    uint64_t            last_pull_time;
    uint64_t            last_push_time;
    uint64_t            last_ping_time;
    uint64_t            last_prune_time;
    uint64_t            last_self_update_time;

    /* Callbacks */
    sol_gossip_value_cb value_callback;
    void*               value_callback_ctx;

    /* Statistics */
    sol_gossip_stats_t  stats;

    /* Receive buffer */
    uint8_t             recv_buf[SOL_NET_MTU];
};

static bool
ipv4_is_global(uint32_t addr_be) {
    uint32_t a = ntohl(addr_be);

    /* 0.0.0.0/8 */
    if ((a & 0xFF000000u) == 0x00000000u) return false;
    /* 10.0.0.0/8 */
    if ((a & 0xFF000000u) == 0x0A000000u) return false;
    /* 100.64.0.0/10 (CGNAT) */
    if ((a & 0xFFC00000u) == 0x64400000u) return false;
    /* 127.0.0.0/8 (loopback) */
    if ((a & 0xFF000000u) == 0x7F000000u) return false;
    /* 169.254.0.0/16 (link-local) */
    if ((a & 0xFFFF0000u) == 0xA9FE0000u) return false;
    /* 172.16.0.0/12 */
    if ((a & 0xFFF00000u) == 0xAC100000u) return false;
    /* 192.168.0.0/16 */
    if ((a & 0xFFFF0000u) == 0xC0A80000u) return false;
    /* 224.0.0.0/4 (multicast) */
    if ((a & 0xF0000000u) == 0xE0000000u) return false;
    /* 240.0.0.0/4 (reserved) */
    if ((a & 0xF0000000u) == 0xF0000000u) return false;

    return true;
}

static bool
ip_str_is_non_global(const char* ip) {
    if (!ip || ip[0] == '\0') return true;
    struct in_addr a4;
    if (inet_pton(AF_INET, ip, &a4) == 1) {
        return !ipv4_is_global(a4.s_addr);
    }
    /* If it's not a valid IPv4 literal, we don't attempt to classify it here. */
    return false;
}

static bool
run_process_capture_stdout(const char* const* argv, char* out, size_t out_len) {
    if (!argv || !argv[0] || !out || out_len == 0) return false;
    out[0] = '\0';

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        return false;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return false;
    }
    if (pid == 0) {
        /* Child */
        (void)dup2(pipefd[1], STDOUT_FILENO);
        (void)dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execvp(argv[0], (char* const*)(uintptr_t)argv);
        _exit(127);
    }

    close(pipefd[1]);

    size_t total = 0;
    while (total + 1 < out_len) {
        ssize_t n = read(pipefd[0], out + total, out_len - 1 - total);
        if (n > 0) {
            total += (size_t)n;
            continue;
        }
        break;
    }
    out[total] = '\0';
    close(pipefd[0]);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) continue;
        break;
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return false;
    }
    return true;
}

static bool
fetch_public_ipv4_best_effort(char* out_ip, size_t out_ip_len) {
    if (!out_ip || out_ip_len == 0) return false;
    out_ip[0] = '\0';

    const char* disable = getenv("SOL_GOSSIP_DISABLE_PUBLIC_IP_ECHO");
    if (disable && disable[0] != '\0' && strcmp(disable, "0") != 0) {
        return false;
    }

    const char* url = getenv("SOL_GOSSIP_PUBLIC_IP_ECHO_URL");
    if (!url || url[0] == '\0') {
        url = "https://api.ipify.org";
    }

    const char* argv[] = {
        "curl",
        "-4",
        "--connect-timeout",
        "2",
        "-m",
        "5",
        "-fsSL",
        url,
        NULL,
    };

    char buf[256] = {0};
    if (!run_process_capture_stdout(argv, buf, sizeof(buf))) {
        return false;
    }

    /* Trim whitespace. */
    char* s = buf;
    while (*s && isspace((unsigned char)*s)) s++;
    char* e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) e--;
    *e = '\0';

    struct in_addr a4;
    if (inet_pton(AF_INET, s, &a4) != 1) {
        return false;
    }
    if (!ipv4_is_global(a4.s_addr)) {
        return false;
    }

    snprintf(out_ip, out_ip_len, "%s", s);
    return true;
}

/*
 * Get current time in milliseconds
 */
uint64_t
sol_gossip_now_ms(void) {
#ifdef __APPLE__
    static mach_timebase_info_data_t timebase = {0};
    if (timebase.denom == 0) {
        mach_timebase_info(&timebase);
    }
    uint64_t ns = mach_absolute_time() * timebase.numer / timebase.denom;
    return ns / 1000000;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
#endif
}

/*
 * Hash pubkey for peer table
 */
static size_t
peer_hash(const sol_pubkey_t* pk, size_t table_size) {
    uint64_t hash = 14695981039346656037ULL;
    for (int i = 0; i < 32; i++) {
        hash ^= pk->bytes[i];
        hash *= 1099511628211ULL;
    }
    return hash % table_size;
}

static uint64_t
sol_gossip_wallclock_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
}

static sol_err_t
add_peer(sol_gossip_t* gossip, const sol_pubkey_t* pk, const sol_sockaddr_t* addr);

static bool
sockaddr_is_any(const sol_sockaddr_t* addr) {
    if (!addr) return true;

    if (addr->addr.sa.sa_family == AF_INET) {
        return addr->addr.sin.sin_addr.s_addr == htonl(INADDR_ANY);
    }

    if (addr->addr.sa.sa_family == AF_INET6) {
        static const struct in6_addr any = IN6ADDR_ANY_INIT;
        return memcmp(&addr->addr.sin6.sin6_addr, &any, sizeof(any)) == 0;
    }

    return true;
}

static void
maybe_add_peer_from_contact_info(sol_gossip_t* gossip, const sol_contact_info_t* ci) {
    if (!gossip || !ci) return;
    if (sol_pubkey_eq(&ci->pubkey, &gossip->self_pubkey)) return;

    if (gossip->config.shred_version != 0 && ci->shred_version != 0 &&
        ci->shred_version != gossip->config.shred_version) {
        return;
    }

    const sol_sockaddr_t* gossip_addr = sol_contact_info_socket(ci, SOL_SOCKET_TAG_GOSSIP);
    if (!gossip_addr) return;
    if (sockaddr_is_any(gossip_addr)) return;
    if (sol_sockaddr_port(gossip_addr) == 0) return;

    add_peer(gossip, &ci->pubkey, gossip_addr);
}

/*
 * Find peer entry
 */
static sol_peer_entry_t*
find_peer(sol_gossip_t* gossip, const sol_pubkey_t* pk) {
    size_t idx = peer_hash(pk, gossip->peer_table_size);
    sol_peer_entry_t* entry = gossip->peer_table[idx];

    while (entry) {
        if (sol_pubkey_eq(&entry->peer.pubkey, pk)) {
            return entry;
        }
        entry = entry->next;
    }
    return NULL;
}

/*
 * Add or update peer
 */
static sol_err_t
add_peer(sol_gossip_t* gossip, const sol_pubkey_t* pk, const sol_sockaddr_t* addr) {
    pthread_rwlock_wrlock(&gossip->peer_lock);

    sol_peer_entry_t* entry = find_peer(gossip, pk);
    if (entry) {
        /* Update existing peer */
        sol_sockaddr_copy(&entry->peer.gossip_addr, addr);
        entry->peer.last_seen = sol_gossip_now_ms();
        pthread_rwlock_unlock(&gossip->peer_lock);
        return SOL_OK;
    }

    /* Check capacity */
    if (gossip->num_peers >= gossip->config.max_peers) {
        pthread_rwlock_unlock(&gossip->peer_lock);
        return SOL_ERR_FULL;
    }

    /* Create new entry */
    entry = sol_calloc(1, sizeof(sol_peer_entry_t));
    if (!entry) {
        pthread_rwlock_unlock(&gossip->peer_lock);
        return SOL_ERR_NOMEM;
    }

    sol_pubkey_copy(&entry->peer.pubkey, pk);
    sol_sockaddr_copy(&entry->peer.gossip_addr, addr);
    entry->peer.state = SOL_PEER_STATE_UNKNOWN;
    entry->peer.last_seen = sol_gossip_now_ms();

    /* Insert into hash table */
    size_t idx = peer_hash(pk, gossip->peer_table_size);
    entry->next = gossip->peer_table[idx];
    gossip->peer_table[idx] = entry;
    gossip->num_peers++;

    pthread_rwlock_unlock(&gossip->peer_lock);
    return SOL_OK;
}

/*
 * Generate random bytes
 */
static void
random_bytes(uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)rand();
    }
}

/*
 * Send a ping to a peer
 */
static sol_err_t
send_ping(sol_gossip_t* gossip, const sol_sockaddr_t* addr) {
    sol_ping_t ping;
    uint8_t token[32];

    random_bytes(token, 32);
    sol_ping_create(&ping, &gossip->self_pubkey, token);

    /* Sign the ping */
    sol_ping_sign(&ping, &gossip->config.identity);

    /* Encode message */
    uint8_t buf[256];
    sol_encoder_t enc;
    sol_encoder_init(&enc, buf, sizeof(buf));

    sol_gossip_msg_t msg = {
        .type = SOL_GOSSIP_MSG_PING,
        .data.ping = ping
    };

    sol_err_t err = sol_gossip_msg_encode(&enc, &msg);
    if (err != SOL_OK) {
        return err;
    }

    /* Send */
    err = sol_udp_send(gossip->sock, buf, sol_encoder_len(&enc), addr);
    if (err == SOL_OK) {
        gossip->stats.pings_sent++;
        gossip->stats.msgs_sent++;
        gossip->stats.bytes_sent += sol_encoder_len(&enc);
    }

    return err;
}

/*
 * Send a pong response
 */
static sol_err_t
send_pong(sol_gossip_t* gossip, const sol_ping_t* ping, const sol_sockaddr_t* addr) {
    sol_pong_t pong;
    sol_pong_create(&pong, &gossip->self_pubkey, ping);

    /* Sign the pong */
    sol_pong_sign(&pong, &gossip->config.identity);

    /* Encode message */
    uint8_t buf[256];
    sol_encoder_t enc;
    sol_encoder_init(&enc, buf, sizeof(buf));

    sol_gossip_msg_t msg = {
        .type = SOL_GOSSIP_MSG_PONG,
        .data.pong = pong
    };

    sol_err_t err = sol_gossip_msg_encode(&enc, &msg);
    if (err != SOL_OK) {
        return err;
    }

    /* Send */
    err = sol_udp_send(gossip->sock, buf, sol_encoder_len(&enc), addr);
    if (err == SOL_OK) {
        gossip->stats.msgs_sent++;
        gossip->stats.bytes_sent += sol_encoder_len(&enc);
    }

    return err;
}

/*
 * Send a pull request to a peer
 */
static sol_err_t
send_pull_request(sol_gossip_t* gossip, const sol_sockaddr_t* addr) {
    /* Build bloom filter of what we already have */
    sol_bloom_t bloom;
    sol_bloom_init(&bloom);

    /* Add all CRDS keys to bloom filter */
    /* For efficiency, we just use a simple bloom of recent entries */
    /* A real implementation would be more sophisticated */

    /* Create pull request */
    sol_pull_request_t req;
    memset(&req, 0, sizeof(req));
    req.filter.filter = bloom;
    req.filter.mask = 0;
    req.filter.mask_bits = 0;
    req.self_value.type = SOL_CRDS_CONTACT_INFO;
    req.self_value.data.contact_info = gossip->self_info;
    (void)sol_gossip_crds_value_sign(&req.self_value, &gossip->config.identity);

    /* Encode message */
    uint8_t buf[1024];
    sol_encoder_t enc;
    sol_encoder_init(&enc, buf, sizeof(buf));

    sol_gossip_msg_t msg = {
        .type = SOL_GOSSIP_MSG_PULL_REQUEST,
        .data.pull_request = req
    };

    sol_err_t err = sol_gossip_msg_encode(&enc, &msg);
    if (err != SOL_OK) {
        return err;
    }

    /* Send */
    err = sol_udp_send(gossip->sock, buf, sol_encoder_len(&enc), addr);
    if (err == SOL_OK) {
        gossip->stats.pulls_sent++;
        gossip->stats.msgs_sent++;
        gossip->stats.bytes_sent += sol_encoder_len(&enc);
    }

    return err;
}

/*
 * Send a pull response with CRDS values
 */
static sol_err_t
send_pull_response(sol_gossip_t* gossip, const sol_bloom_t* filter,
                   const sol_sockaddr_t* addr) {
    /* Get values not in the bloom filter */
    const sol_crds_entry_t* entries[64];
    size_t count = sol_crds_get_entries_since(gossip->crds, 0, entries, 64);

    if (count == 0) {
        return SOL_OK;
    }

    /* Filter out entries that are in the bloom filter */
    sol_crds_value_t values[64];
    size_t values_len = 0;

    for (size_t i = 0; i < count && values_len < 64; i++) {
        sol_crds_key_t key;
        sol_crds_key_from_value(&key, &entries[i]->value);

        /* Check if peer already has this value */
        if (!sol_bloom_contains(filter, (const uint8_t*)&key, sizeof(key))) {
            values[values_len++] = entries[i]->value;
        }
    }

    if (values_len == 0) {
        return SOL_OK;
    }

    /* Create pull response */
    sol_pull_response_t resp;
    sol_pubkey_copy(&resp.pubkey, &gossip->self_pubkey);
    resp.values = values;
    resp.values_len = (uint16_t)values_len;

    /* Encode message */
    uint8_t buf[SOL_NET_MTU];
    sol_encoder_t enc;
    sol_encoder_init(&enc, buf, sizeof(buf));

    sol_gossip_msg_t msg = {
        .type = SOL_GOSSIP_MSG_PULL_RESPONSE,
        .data.pull_response = resp
    };

    sol_err_t err = sol_gossip_msg_encode(&enc, &msg);
    if (err != SOL_OK) {
        return err;
    }

    /* Send */
    err = sol_udp_send(gossip->sock, buf, sol_encoder_len(&enc), addr);
    if (err == SOL_OK) {
        gossip->stats.msgs_sent++;
        gossip->stats.bytes_sent += sol_encoder_len(&enc);
    }

    return err;
}

/*
 * Send push message to a peer
 */
static sol_err_t
send_push_message(sol_gossip_t* gossip, const sol_crds_value_t* values,
                  size_t num_values, const sol_sockaddr_t* addr) {
    if (num_values == 0) {
        return SOL_OK;
    }

    /* Create push message */
    sol_push_msg_t push;
    sol_pubkey_copy(&push.pubkey, &gossip->self_pubkey);
    /* Values are only read during encoding, cast through void* to satisfy const-correctness */
    push.values = (sol_crds_value_t*)(uintptr_t)values;
    push.values_len = (uint16_t)num_values;

    /* Encode message */
    uint8_t buf[SOL_NET_MTU];
    sol_encoder_t enc;
    sol_encoder_init(&enc, buf, sizeof(buf));

    sol_gossip_msg_t msg = {
        .type = SOL_GOSSIP_MSG_PUSH,
        .data.push = push
    };

    sol_err_t err = sol_gossip_msg_encode(&enc, &msg);
    if (err != SOL_OK) {
        return err;
    }

    /* Send */
    err = sol_udp_send(gossip->sock, buf, sol_encoder_len(&enc), addr);
    if (err == SOL_OK) {
        gossip->stats.pushes_sent++;
        gossip->stats.msgs_sent++;
        gossip->stats.bytes_sent += sol_encoder_len(&enc);
    }

    return err;
}

/*
 * Handle incoming ping
 */
static void
handle_ping(sol_gossip_t* gossip, const sol_ping_t* ping, const sol_sockaddr_t* src) {
    sol_log_debug("Received ping from %.*s...",
                  8, ping->from.bytes);

    /* Add/update peer */
    add_peer(gossip, &ping->from, src);

    /* Send pong response */
    send_pong(gossip, ping, src);
}

/*
 * Handle incoming pong
 */
static void
handle_pong(sol_gossip_t* gossip, const sol_pong_t* pong, const sol_sockaddr_t* src) {
    sol_log_debug("Received pong from %.*s...",
                  8, pong->from.bytes);

    gossip->stats.pongs_received++;

    /* Treat a pong as peer discovery and mark the peer active. */
    add_peer(gossip, &pong->from, src);

    /* Find and update peer */
    pthread_rwlock_wrlock(&gossip->peer_lock);
    sol_peer_entry_t* entry = find_peer(gossip, &pong->from);
    if (entry) {
        entry->peer.state = SOL_PEER_STATE_ACTIVE;
        entry->peer.last_seen = sol_gossip_now_ms();
        entry->peer.ping_failures = 0;
    }
    pthread_rwlock_unlock(&gossip->peer_lock);

    /* Update active peer count */
    gossip->stats.active_peers = gossip->num_peers;
}

/*
 * Handle incoming push message
 */
static void
handle_push(sol_gossip_t* gossip, const sol_push_msg_t* push, const sol_sockaddr_t* src) {
    add_peer(gossip, &push->pubkey, src);

    sol_log_debug("Received push with %u values from %.*s...",
                  push->values_len, 8, push->pubkey.bytes);

    gossip->stats.pushes_received++;

    /* Insert values into CRDS */
    uint64_t now = sol_gossip_wallclock_ms();
    for (uint16_t i = 0; i < push->values_len && push->values; i++) {
        sol_crds_insert(gossip->crds, &push->values[i], &push->pubkey, now);

        if (push->values[i].type == SOL_CRDS_CONTACT_INFO) {
            maybe_add_peer_from_contact_info(gossip, &push->values[i].data.contact_info);
        }

        /* Notify callback */
        if (gossip->value_callback) {
            gossip->value_callback(&push->values[i], gossip->value_callback_ctx);
        }
    }
}

/*
 * Handle incoming pull request
 */
static void
handle_pull_request(sol_gossip_t* gossip, const sol_pull_request_t* req,
                   const sol_sockaddr_t* src) {
    sol_log_debug("Received pull request from %.*s...",
                  8, req->self_value.data.contact_info.pubkey.bytes);

    gossip->stats.pulls_received++;

    add_peer(gossip, &req->self_value.data.contact_info.pubkey, src);

    /* Add the requester to our CRDS if they sent contact info */
    if (req->self_value.type == SOL_CRDS_CONTACT_INFO) {
        sol_crds_insert(gossip->crds, &req->self_value,
                        &req->self_value.data.contact_info.pubkey,
                        sol_gossip_wallclock_ms());
        maybe_add_peer_from_contact_info(gossip, &req->self_value.data.contact_info);
    }

    /* Send pull response filtered by bloom */
    send_pull_response(gossip, &req->filter.filter, src);
}

/*
 * Process a received message
 */
static void
process_message(sol_gossip_t* gossip, const uint8_t* data, size_t len,
               const sol_sockaddr_t* src) {
    gossip->stats.msgs_received++;
    gossip->stats.bytes_received += len;

    sol_decoder_t dec;
    sol_decoder_init(&dec, data, len);

    sol_gossip_msg_t msg;
    memset(&msg, 0, sizeof(msg));

    sol_err_t err = sol_gossip_msg_decode(&dec, &msg, NULL);
    if (err != SOL_OK) {
        sol_log_debug("Failed to decode gossip message: %d", err);
        gossip->stats.invalid_msgs++;
        return;
    }

    switch (msg.type) {
    case SOL_GOSSIP_MSG_PING:
        handle_ping(gossip, &msg.data.ping, src);
        break;

    case SOL_GOSSIP_MSG_PONG:
        handle_pong(gossip, &msg.data.pong, src);
        break;

    case SOL_GOSSIP_MSG_PUSH:
        handle_push(gossip, &msg.data.push, src);
        break;

    case SOL_GOSSIP_MSG_PULL_REQUEST:
        handle_pull_request(gossip, &msg.data.pull_request, src);
        break;

    case SOL_GOSSIP_MSG_PULL_RESPONSE: {
        sol_log_debug("Received pull response with %u values",
                      msg.data.pull_response.values_len);

        add_peer(gossip, &msg.data.pull_response.pubkey, src);

        /* Insert values into CRDS */
        uint64_t now = sol_gossip_wallclock_ms();
        for (uint16_t i = 0; i < msg.data.pull_response.values_len; i++) {
            if (msg.data.pull_response.values) {
                sol_crds_insert(gossip->crds,
                               &msg.data.pull_response.values[i],
                               &msg.data.pull_response.pubkey, now);

                if (msg.data.pull_response.values[i].type == SOL_CRDS_CONTACT_INFO) {
                    maybe_add_peer_from_contact_info(
                        gossip,
                        &msg.data.pull_response.values[i].data.contact_info);
                }

                /* Notify callback */
                if (gossip->value_callback) {
                    gossip->value_callback(&msg.data.pull_response.values[i],
                                          gossip->value_callback_ctx);
                }
            }
        }
        break;
    }

    case SOL_GOSSIP_MSG_PRUNE:
        sol_log_debug("Received prune message from %.*s with %u origins",
                      8, msg.data.prune.pubkey.bytes, msg.data.prune.prunes_len);
        gossip->stats.prunes_received++;

        add_peer(gossip, &msg.data.prune.pubkey, src);

        /* Store pruned origins for this peer */
        pthread_rwlock_wrlock(&gossip->peer_lock);
        sol_peer_entry_t* prune_peer = find_peer(gossip, &msg.data.prune.pubkey);
        if (prune_peer) {
            /* Add pruned origins (up to max) */
            for (uint16_t i = 0; i < msg.data.prune.prunes_len &&
                 prune_peer->peer.pruned_origins_len < SOL_MAX_PRUNED_ORIGINS; i++) {
                /* Check if origin is already in prune list */
                bool already_pruned = false;
                for (uint8_t j = 0; j < prune_peer->peer.pruned_origins_len; j++) {
                    if (sol_pubkey_eq(&prune_peer->peer.pruned_origins[j],
                                      &msg.data.prune.prunes[i])) {
                        already_pruned = true;
                        break;
                    }
                }
                if (!already_pruned) {
                    prune_peer->peer.pruned_origins[prune_peer->peer.pruned_origins_len++] =
                        msg.data.prune.prunes[i];
                }
            }
            sol_log_debug("Peer now has %u pruned origins",
                         prune_peer->peer.pruned_origins_len);
        }
        pthread_rwlock_unlock(&gossip->peer_lock);
        break;

    default:
        sol_log_debug("Unknown message type: %d", msg.type);
        gossip->stats.invalid_msgs++;
        break;
    }

    sol_gossip_msg_free(&msg);
}

/*
 * Ping peers periodically
 */
static void
do_pings(sol_gossip_t* gossip) {
    uint64_t now = sol_gossip_now_ms();

    if (now - gossip->last_ping_time < gossip->config.ping_interval_ms) {
        return;
    }
    gossip->last_ping_time = now;

    /* Ping entrypoints if we have no peers */
    if (gossip->num_peers == 0) {
        for (size_t i = 0; i < gossip->config.entrypoints_len; i++) {
            send_ping(gossip, &gossip->config.entrypoints[i]);
        }
        return;
    }

    /* Ping some random peers */
    pthread_rwlock_rdlock(&gossip->peer_lock);

    size_t ping_count = 0;
    for (size_t i = 0; i < gossip->peer_table_size && ping_count < 5; i++) {
        sol_peer_entry_t* entry = gossip->peer_table[i];
        while (entry && ping_count < 5) {
            if (entry->peer.state != SOL_PEER_STATE_ACTIVE ||
                now - entry->peer.last_seen > 30000) {
                send_ping(gossip, &entry->peer.gossip_addr);
                ping_count++;
            }
            entry = entry->next;
        }
    }

    pthread_rwlock_unlock(&gossip->peer_lock);
}

static void
do_self_update(sol_gossip_t* gossip) {
    if (!gossip) return;

    uint64_t now_mono = sol_gossip_now_ms();
    if (now_mono - gossip->last_self_update_time < 5000) {
        return;
    }
    gossip->last_self_update_time = now_mono;

    uint64_t now_wall = sol_gossip_wallclock_ms();
    gossip->self_info.wallclock = now_wall;
    gossip->self_info.outset = now_wall / (1000ULL * 60ULL);

    sol_crds_value_t self_value = {
        .type = SOL_CRDS_CONTACT_INFO,
        .data.contact_info = gossip->self_info
    };

    (void)sol_gossip_crds_value_sign(&self_value, &gossip->config.identity);
    sol_crds_insert(gossip->crds, &self_value, &gossip->self_pubkey, now_wall);
}

/*
 * Send periodic pull requests
 */
static void
do_pulls(sol_gossip_t* gossip) {
    uint64_t now = sol_gossip_now_ms();

    if (now - gossip->last_pull_time < gossip->config.pull_interval_ms) {
        return;
    }
    gossip->last_pull_time = now;

    /* Send pull request to a random active peer */
    pthread_rwlock_rdlock(&gossip->peer_lock);

    sol_peer_entry_t* target = NULL;
    for (size_t i = 0; i < gossip->peer_table_size && !target; i++) {
        sol_peer_entry_t* entry = gossip->peer_table[i];
        while (entry) {
            if (entry->peer.state == SOL_PEER_STATE_ACTIVE) {
                target = entry;
                break;
            }
            entry = entry->next;
        }
    }

    if (target) {
        send_pull_request(gossip, &target->peer.gossip_addr);
    }

    pthread_rwlock_unlock(&gossip->peer_lock);
}

/*
 * Check if an origin is pruned by a peer
 */
static bool
is_origin_pruned(const sol_peer_t* peer, const sol_pubkey_t* origin) {
    for (uint8_t i = 0; i < peer->pruned_origins_len; i++) {
        if (sol_pubkey_eq(&peer->pruned_origins[i], origin)) {
            return true;
        }
    }
    return false;
}

/*
 * Push new values to peers
 */
static void
do_pushes(sol_gossip_t* gossip) {
    uint64_t now = sol_gossip_now_ms();

    if (now - gossip->last_push_time < gossip->config.push_interval_ms) {
        return;
    }
    gossip->last_push_time = now;

    uint64_t now_wall = sol_gossip_wallclock_ms();
    uint64_t since = 0;
    if (now_wall > (uint64_t)gossip->config.push_interval_ms * 2) {
        since = now_wall - (uint64_t)gossip->config.push_interval_ms * 2;
    }

    /* Get recent CRDS values to push */
    const sol_crds_entry_t* entries[32];
    size_t count = sol_crds_get_entries_since(
        gossip->crds,
        since,
        entries, 32
    );

    if (count == 0) {
        return;
    }

    /* Push to a subset of active peers (fanout) */
    pthread_rwlock_rdlock(&gossip->peer_lock);

    size_t push_count = 0;
    for (size_t i = 0; i < gossip->peer_table_size &&
                       push_count < gossip->config.push_fanout; i++) {
        sol_peer_entry_t* entry = gossip->peer_table[i];
        while (entry && push_count < gossip->config.push_fanout) {
            if (entry->peer.state == SOL_PEER_STATE_ACTIVE) {
                /* Filter values by peer's prune list */
                sol_crds_value_t filtered_values[32];
                size_t filtered_count = 0;

                for (size_t j = 0; j < count; j++) {
                    const sol_pubkey_t* origin = sol_crds_value_pubkey(&entries[j]->value);
                    if (origin && !is_origin_pruned(&entry->peer, origin)) {
                        filtered_values[filtered_count++] = entries[j]->value;
                    }
                }

                if (filtered_count > 0) {
                    send_push_message(gossip, filtered_values, filtered_count,
                                     &entry->peer.gossip_addr);
                }
                push_count++;
            }
            entry = entry->next;
        }
    }

    pthread_rwlock_unlock(&gossip->peer_lock);
}

/*
 * Prune old CRDS entries
 */
static void
do_prune(sol_gossip_t* gossip) {
    uint64_t now = sol_gossip_now_ms();

    if (now - gossip->last_prune_time < 60000) {  /* Every 60 seconds */
        return;
    }
    gossip->last_prune_time = now;

    size_t pruned = sol_crds_prune(gossip->crds, now, gossip->config.prune_timeout_ms);
    if (pruned > 0) {
        sol_log_debug("Pruned %zu old CRDS entries", pruned);
    }
}

sol_gossip_t*
sol_gossip_new(const sol_gossip_config_t* config) {
    sol_gossip_t* gossip = sol_calloc(1, sizeof(sol_gossip_t));
    if (!gossip) return NULL;

    /* Copy config */
    if (config) {
        gossip->config = *config;
    } else {
        gossip->config = (sol_gossip_config_t)SOL_GOSSIP_CONFIG_DEFAULT;
    }

    /* Extract pubkey from keypair */
    sol_keypair_pubkey(&gossip->config.identity, &gossip->self_pubkey);

    /* Initialize peer table */
    gossip->peer_table_size = gossip->config.max_peers * 2;
    gossip->peer_table = sol_calloc(gossip->peer_table_size, sizeof(sol_peer_entry_t*));
    if (!gossip->peer_table) {
        sol_free(gossip);
        return NULL;
    }

    if (pthread_rwlock_init(&gossip->peer_lock, NULL) != 0) {
        sol_free(gossip->peer_table);
        sol_free(gossip);
        return NULL;
    }

    /* Create CRDS */
    gossip->crds = sol_crds_new(0);
    if (!gossip->crds) {
        pthread_rwlock_destroy(&gossip->peer_lock);
        sol_free(gossip->peer_table);
        sol_free(gossip);
        return NULL;
    }

    /* Initialize self contact info */
    sol_contact_info_init(&gossip->self_info);
    sol_pubkey_copy(&gossip->self_info.pubkey, &gossip->self_pubkey);
    gossip->self_info.shred_version = gossip->config.shred_version;
    gossip->self_info.wallclock = sol_gossip_wallclock_ms();
    gossip->self_info.outset = gossip->self_info.wallclock / (1000ULL * 60ULL);
    gossip->self_info.version = (sol_version_t){0};

    /* Seed random */
    srand((unsigned int)time(NULL));

    return gossip;
}

void
sol_gossip_destroy(sol_gossip_t* gossip) {
    if (!gossip) return;

    sol_gossip_stop(gossip);

    /* Destroy socket */
    if (gossip->sock) {
        sol_udp_destroy(gossip->sock);
    }

    /* Destroy peer table */
    for (size_t i = 0; i < gossip->peer_table_size; i++) {
        sol_peer_entry_t* entry = gossip->peer_table[i];
        while (entry) {
            sol_peer_entry_t* next = entry->next;
            sol_free(entry);
            entry = next;
        }
    }
    sol_free(gossip->peer_table);

    pthread_rwlock_destroy(&gossip->peer_lock);

    /* Destroy CRDS */
    sol_crds_destroy(gossip->crds);

    /* Free entrypoints */
    if (gossip->config.entrypoints) {
        sol_free(gossip->config.entrypoints);
    }

    sol_free(gossip);
}

sol_err_t
sol_gossip_start(sol_gossip_t* gossip) {
    if (!gossip) return SOL_ERR_INVAL;
    if (gossip->running) return SOL_OK;

    /* Create UDP socket (with race-safe fallback if the chosen port becomes
     * unavailable between CLI/config port selection and binding). */
    sol_udp_config_t udp_cfg = SOL_UDP_CONFIG_DEFAULT;
    udp_cfg.bind_ip = gossip->config.bind_ip;
    udp_cfg.bind_port = gossip->config.gossip_port;
    udp_cfg.nonblocking = true;
    /* Gossip can be extremely bursty on mainnet; keep buffers large to reduce
     * packet drops while the node is busy with catchup/replay. */
    udp_cfg.recv_buf = 128u * 1024u * 1024u;
    udp_cfg.send_buf = 128u * 1024u * 1024u;

    uint16_t requested_port = udp_cfg.bind_port;
    gossip->sock = sol_udp_new(&udp_cfg);
    if (!gossip->sock && errno == EADDRINUSE) {
        const uint16_t reserved_ports[] = {
            gossip->config.tpu_port,
            gossip->config.tpu_quic_port,
            gossip->config.tvu_port,
            gossip->config.serve_repair_port,
        };

        uint16_t base = requested_port ? requested_port : 8001;
        for (uint32_t i = 1; i < 2000; i++) {
            uint16_t candidate = (uint16_t)(base + i);
            if (candidate == 0) continue;

            bool reserved = false;
            for (size_t j = 0; j < sizeof(reserved_ports) / sizeof(reserved_ports[0]); j++) {
                if (reserved_ports[j] != 0 && reserved_ports[j] == candidate) {
                    reserved = true;
                    break;
                }
            }
            if (reserved) continue;

            udp_cfg.bind_port = candidate;
            gossip->sock = sol_udp_new(&udp_cfg);
            if (gossip->sock) {
                sol_log_warn("Gossip port %u is in use; using %u",
                             (unsigned)requested_port,
                             (unsigned)candidate);
                break;
            }
            if (errno != EADDRINUSE) {
                break;
            }
        }

        /* Last resort: bind to any ephemeral port. */
        if (!gossip->sock) {
            udp_cfg.bind_port = 0;
            gossip->sock = sol_udp_new(&udp_cfg);
            if (gossip->sock) {
                sol_log_warn("Gossip port %u is in use; using an ephemeral port",
                             (unsigned)requested_port);
            }
        }
    }

    if (!gossip->sock) {
        sol_log_error("Failed to create gossip UDP socket");
        return SOL_ERR_IO;
    }

    /* Get local address and update self info */
    sol_sockaddr_t local_addr;
    sol_udp_local_addr(gossip->sock, &local_addr);
    uint16_t bound_port = sol_sockaddr_port(&local_addr);
    if (bound_port != 0) {
        gossip->config.gossip_port = bound_port;
    }

    /* Determine advertise IP. */
    char adv_ip[INET6_ADDRSTRLEN] = {0};
    bool advertise_ip_configured =
        (gossip->config.advertise_ip && gossip->config.advertise_ip[0] != '\0');
    if (advertise_ip_configured) {
        snprintf(adv_ip, sizeof(adv_ip), "%s", gossip->config.advertise_ip);
    } else if (gossip->config.entrypoints && gossip->config.entrypoints_len > 0) {
        const sol_sockaddr_t* remote = &gossip->config.entrypoints[0];
        int fd = socket(sol_sockaddr_family(remote), SOCK_DGRAM, 0);
        if (fd >= 0) {
            /* Best-effort: avoid leaking this temp socket across fork/exec helpers. */
            int fd_flags = fcntl(fd, F_GETFD, 0);
            if (fd_flags >= 0) {
                (void)fcntl(fd, F_SETFD, fd_flags | FD_CLOEXEC);
            }

            if (connect(fd, &remote->addr.sa, remote->len) == 0) {
                sol_sockaddr_t guessed = {0};
                socklen_t guessed_len = sizeof(guessed.addr);
                if (getsockname(fd, &guessed.addr.sa, &guessed_len) == 0) {
                    guessed.len = guessed_len;
                    sol_endpoint_t ep = {0};
                    if (sol_endpoint_from_sockaddr(&ep, &guessed) == SOL_OK) {
                        if (strcmp(ep.ip, "0.0.0.0") != 0 && strcmp(ep.ip, "::") != 0) {
                            snprintf(adv_ip, sizeof(adv_ip), "%s", ep.ip);
                        }
                    }
                }
            }
            close(fd);
        }
    }

    if (adv_ip[0] == '\0') {
        sol_endpoint_t ep = {0};
        if (sol_endpoint_from_sockaddr(&ep, &local_addr) == SOL_OK) {
            if (strcmp(ep.ip, "0.0.0.0") != 0 && strcmp(ep.ip, "::") != 0) {
                snprintf(adv_ip, sizeof(adv_ip), "%s", ep.ip);
            }
        }
    }

    /* Fall back to loopback if we still couldn't infer. */
    if (adv_ip[0] == '\0') {
        snprintf(adv_ip, sizeof(adv_ip), "127.0.0.1");
    }

    /* Many hosts infer a private RFC1918 address via getsockname(). That
     * address is not reachable by other validators on the public internet, so
     * turbine shreds and repair requests to our advertised sockets will never
     * arrive. As a best-effort fallback, query a public IP echo service once at
     * startup and advertise that address instead. */
    if (!advertise_ip_configured && ip_str_is_non_global(adv_ip)) {
        char public_ip[INET6_ADDRSTRLEN] = {0};
        if (fetch_public_ipv4_best_effort(public_ip, sizeof(public_ip))) {
            sol_log_info("Gossip advertise IP inferred as %s (non-public); using public IP %s",
                         adv_ip,
                         public_ip);
            snprintf(adv_ip, sizeof(adv_ip), "%s", public_ip);
        } else {
            sol_log_warn("Gossip advertise IP inferred as %s (may be unreachable from the cluster). "
                         "Set --advertise-ip to override.",
                         adv_ip);
        }
    }

    sol_log_info("Gossip advertise IP: %s", adv_ip);

    /* Advertise sockets for contact-info. */
    sol_sockaddr_t adv;
    if (sol_sockaddr_init(&adv, adv_ip, gossip->config.gossip_port) == SOL_OK) {
        sol_contact_info_add_socket(&gossip->self_info, SOL_SOCKET_TAG_GOSSIP, &adv);
    } else {
        sol_contact_info_add_socket(&gossip->self_info, SOL_SOCKET_TAG_GOSSIP, &local_addr);
    }

    if (gossip->config.tvu_port) {
        if (sol_sockaddr_init(&adv, adv_ip, gossip->config.tvu_port) == SOL_OK) {
            (void)sol_contact_info_add_socket(&gossip->self_info, SOL_SOCKET_TAG_TVU, &adv);
        }
    }
    if (gossip->config.tpu_port) {
        if (sol_sockaddr_init(&adv, adv_ip, gossip->config.tpu_port) == SOL_OK) {
            (void)sol_contact_info_add_socket(&gossip->self_info, SOL_SOCKET_TAG_TPU, &adv);
        }
    }
    if (gossip->config.tpu_quic_port) {
        if (sol_sockaddr_init(&adv, adv_ip, gossip->config.tpu_quic_port) == SOL_OK) {
            (void)sol_contact_info_add_socket(&gossip->self_info, SOL_SOCKET_TAG_TPU_QUIC, &adv);
        }
    }
    if (gossip->config.serve_repair_port) {
        if (sol_sockaddr_init(&adv, adv_ip, gossip->config.serve_repair_port) == SOL_OK) {
            (void)sol_contact_info_add_socket(&gossip->self_info, SOL_SOCKET_TAG_SERVE_REPAIR, &adv);
        }
    }
    if (gossip->config.rpc_port) {
        if (sol_sockaddr_init(&adv, adv_ip, gossip->config.rpc_port) == SOL_OK) {
            (void)sol_contact_info_add_socket(&gossip->self_info, SOL_SOCKET_TAG_RPC, &adv);
        }
    }

    /* Add self to CRDS */
    uint64_t now_wall = sol_gossip_wallclock_ms();
    gossip->self_info.wallclock = now_wall;
    gossip->self_info.outset = now_wall / (1000ULL * 60ULL);

    sol_crds_value_t self_value = {
        .type = SOL_CRDS_CONTACT_INFO,
        .data.contact_info = gossip->self_info
    };
    (void)sol_gossip_crds_value_sign(&self_value, &gossip->config.identity);
    sol_crds_insert(gossip->crds, &self_value, &gossip->self_pubkey, now_wall);

    gossip->running = true;

    char addr_str[64];
    sol_sockaddr_to_string(&local_addr, addr_str, sizeof(addr_str));
    sol_log_info("Gossip service started on %s", addr_str);

    return SOL_OK;
}

void
sol_gossip_stop(sol_gossip_t* gossip) {
    if (gossip) {
        gossip->running = false;
    }
}

bool
sol_gossip_is_running(const sol_gossip_t* gossip) {
    return gossip && gossip->running;
}

sol_err_t
sol_gossip_run_once(sol_gossip_t* gossip, uint32_t timeout_ms) {
    if (!gossip || !gossip->running) {
        return SOL_ERR_SHUTDOWN;
    }

    /* Receive messages (drain socket to keep up with mainnet rates). */
    enum { SOL_GOSSIP_RECV_BUDGET = 4096 };
    size_t processed = 0;
    sol_udp_pkt_t pkts[SOL_NET_BATCH_SIZE];
    while (processed < SOL_GOSSIP_RECV_BUDGET) {
        int n = sol_udp_recv_batch(gossip->sock, pkts, SOL_NET_BATCH_SIZE);
        if (n < 0) {
            sol_log_warn("UDP recv error");
            break;
        }
        if (n == 0) {
            break;
        }
        processed += (size_t)n;
        for (int i = 0; i < n; i++) {
            process_message(gossip, pkts[i].data, pkts[i].len, &pkts[i].addr);
        }
    }

    /* Periodic tasks */
    do_pings(gossip);
    do_pulls(gossip);
    do_self_update(gossip);
    do_pushes(gossip);
    do_prune(gossip);

    (void)timeout_ms;  /* Would use for poll/select */

    return SOL_OK;
}

sol_err_t
sol_gossip_run(sol_gossip_t* gossip) {
    while (gossip->running) {
        sol_err_t err = sol_gossip_run_once(gossip, 100);
        if (err == SOL_ERR_SHUTDOWN) {
            break;
        }
    }
    return SOL_OK;
}

const sol_contact_info_t*
sol_gossip_self(const sol_gossip_t* gossip) {
    return gossip ? &gossip->self_info : NULL;
}

const sol_pubkey_t*
sol_gossip_pubkey(const sol_gossip_t* gossip) {
    return gossip ? &gossip->self_pubkey : NULL;
}

sol_crds_t*
sol_gossip_crds(sol_gossip_t* gossip) {
    return gossip ? gossip->crds : NULL;
}

sol_err_t
sol_gossip_push_value(sol_gossip_t* gossip, const sol_crds_value_t* value) {
    if (!gossip || !value) return SOL_ERR_INVAL;

    sol_crds_value_t signed_value = *value;
    const sol_pubkey_t* origin = sol_crds_value_pubkey(value);
    if (origin && sol_pubkey_eq(origin, &gossip->self_pubkey)) {
        (void)sol_gossip_crds_value_sign(&signed_value, &gossip->config.identity);
    }

    /* Insert into local CRDS */
    sol_crds_insert(gossip->crds, &signed_value, &gossip->self_pubkey,
                    sol_gossip_wallclock_ms());

    /* Track the push request (value will be sent during next push cycle
     * or immediately if peers are available) */
    gossip->stats.pushes_sent++;

    /* Push to active peers immediately (fanout) */
    pthread_rwlock_rdlock(&gossip->peer_lock);

    size_t push_count = 0;
    for (size_t i = 0; i < gossip->peer_table_size &&
                       push_count < gossip->config.push_fanout; i++) {
        sol_peer_entry_t* entry = gossip->peer_table[i];
        while (entry && push_count < gossip->config.push_fanout) {
            if (entry->peer.state == SOL_PEER_STATE_ACTIVE) {
                send_push_message(gossip, &signed_value, 1, &entry->peer.gossip_addr);
                push_count++;
            }
            entry = entry->next;
        }
    }

    pthread_rwlock_unlock(&gossip->peer_lock);

    return SOL_OK;
}

size_t
sol_gossip_get_peers(sol_gossip_t* gossip, sol_peer_t* peers, size_t max_peers) {
    if (!gossip || !peers || max_peers == 0) return 0;

    size_t count = 0;

    pthread_rwlock_rdlock(&gossip->peer_lock);

    for (size_t i = 0; i < gossip->peer_table_size && count < max_peers; i++) {
        sol_peer_entry_t* entry = gossip->peer_table[i];
        while (entry && count < max_peers) {
            peers[count++] = entry->peer;
            entry = entry->next;
        }
    }

    pthread_rwlock_unlock(&gossip->peer_lock);

    return count;
}

size_t
sol_gossip_num_peers(const sol_gossip_t* gossip) {
    return gossip ? gossip->num_peers : 0;
}

size_t
sol_gossip_get_cluster_nodes(
    sol_gossip_t*              gossip,
    const sol_contact_info_t** nodes,
    size_t                     max_nodes
) {
    if (!gossip || !nodes || max_nodes == 0) return 0;
    return sol_crds_get_all_contact_info(gossip->crds, nodes, max_nodes);
}

const sol_crds_version_t*
sol_gossip_get_version(sol_gossip_t* gossip, const sol_pubkey_t* pubkey) {
    if (!gossip || !pubkey) return NULL;
    return sol_crds_get_version(gossip->crds, pubkey);
}

void
sol_gossip_set_value_callback(
    sol_gossip_t*        gossip,
    sol_gossip_value_cb  callback,
    void*                ctx
) {
    if (gossip) {
        gossip->value_callback = callback;
        gossip->value_callback_ctx = ctx;
    }
}

void
sol_gossip_stats(const sol_gossip_t* gossip, sol_gossip_stats_t* stats) {
    if (gossip && stats) {
        *stats = gossip->stats;
    }
}

void
sol_gossip_stats_reset(sol_gossip_t* gossip) {
    if (gossip) {
        memset(&gossip->stats, 0, sizeof(gossip->stats));
    }
}

sol_err_t
sol_gossip_add_entrypoint(sol_gossip_t* gossip, const sol_sockaddr_t* addr) {
    if (!gossip || !addr) return SOL_ERR_INVAL;

    size_t new_len = gossip->config.entrypoints_len + 1;
    sol_sockaddr_t* new_arr = sol_realloc(
        gossip->config.entrypoints,
        new_len * sizeof(sol_sockaddr_t)
    );

    if (!new_arr) return SOL_ERR_NOMEM;

    sol_sockaddr_copy(&new_arr[gossip->config.entrypoints_len], addr);
    gossip->config.entrypoints = new_arr;
    gossip->config.entrypoints_len = new_len;

    return SOL_OK;
}

sol_err_t
sol_gossip_pull(sol_gossip_t* gossip) {
    if (!gossip) return SOL_ERR_INVAL;

    /* Force an immediate pull by resetting the timer */
    gossip->last_pull_time = 0;
    do_pulls(gossip);

    return SOL_OK;
}
