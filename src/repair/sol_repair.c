/*
 * sol_repair.c - Shred repair protocol implementation
 */

#include "sol_repair.h"
#include "../util/sol_alloc.h"
#include "../util/sol_bits.h"
#include "../util/sol_log.h"
#include "../gossip/sol_crds_value.h"
#include "../blockstore/sol_blockstore.h"
#include "../crypto/sol_ed25519.h"
#include "../crypto/sol_sha256.h"
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

enum {
    SOL_REPAIR_WARM_PEERS_MAX = 512,
    SOL_REPAIR_WARM_TTL_MS = 60 * 1000,
};

typedef struct {
    sol_pubkey_t pubkey;
    uint64_t     last_seen_ms;
    bool         active;
} sol_repair_warm_peer_t;

/*
 * Repair service structure
 */
struct sol_repair {
    /* Configuration */
    sol_repair_config_t config;
    sol_keypair_t       identity;
    sol_pubkey_t        self_pubkey;
    uint32_t            nonce_counter;

    /* Gossip for peer discovery */
    sol_gossip_t*       gossip;

    /* Blockstore for serving repairs */
    sol_blockstore_t*   blockstore;

    /* Network */
    sol_udp_sock_t*     repair_sock;
    sol_udp_sock_t*     serve_sock;
    bool                running;

    /* Pending requests */
    sol_repair_pending_t* pending;
    size_t              pending_count;
    pthread_mutex_t     pending_lock;

    /* Seed peers for bootstrap (used when gossip CRDS contact-info is empty) */
    sol_repair_seed_peer_t* seed_peers;
    size_t              seed_peers_len;
    pthread_mutex_t     seed_peers_lock;

    /* Peer warm-cache (ping/pong gating) */
    sol_repair_warm_peer_t warm_peers[SOL_REPAIR_WARM_PEERS_MAX];
    pthread_mutex_t     warm_peers_lock;

    /* Callbacks */
    sol_repair_shred_cb shred_callback;
    void*               shred_callback_ctx;
    sol_repair_ancestor_cb ancestor_callback;
    void*               ancestor_callback_ctx;

    /* Statistics */
    sol_repair_stats_t  stats;

    /* Receive buffer */
    uint8_t             recv_buf[2048];
};

/*
 * Get current time in ms
 */
extern uint64_t sol_gossip_now_ms(void);

static uint64_t
sol_unix_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void
mark_peer_warm(sol_repair_t* repair, const sol_pubkey_t* peer_pubkey) {
    if (!repair || !peer_pubkey) return;

    uint64_t now = sol_gossip_now_ms();

    pthread_mutex_lock(&repair->warm_peers_lock);

    sol_repair_warm_peer_t* free_slot = NULL;
    sol_repair_warm_peer_t* oldest = NULL;

    for (size_t i = 0; i < SOL_REPAIR_WARM_PEERS_MAX; i++) {
        sol_repair_warm_peer_t* e = &repair->warm_peers[i];
        if (e->active) {
            if (sol_pubkey_eq(&e->pubkey, peer_pubkey)) {
                e->last_seen_ms = now;
                pthread_mutex_unlock(&repair->warm_peers_lock);
                return;
            }
            if (!oldest || e->last_seen_ms < oldest->last_seen_ms) {
                oldest = e;
            }
        } else if (!free_slot) {
            free_slot = e;
        }
    }

    sol_repair_warm_peer_t* dst = free_slot ? free_slot : oldest;
    if (dst) {
        dst->pubkey = *peer_pubkey;
        dst->last_seen_ms = now;
        dst->active = true;
    }

    pthread_mutex_unlock(&repair->warm_peers_lock);
}

static bool
is_peer_warm(sol_repair_t* repair, const sol_pubkey_t* peer_pubkey, uint64_t now_ms) {
    if (!repair || !peer_pubkey) return false;

    bool warm = false;
    pthread_mutex_lock(&repair->warm_peers_lock);
    for (size_t i = 0; i < SOL_REPAIR_WARM_PEERS_MAX; i++) {
        sol_repair_warm_peer_t* e = &repair->warm_peers[i];
        if (!e->active) continue;
        if (!sol_pubkey_eq(&e->pubkey, peer_pubkey)) continue;
        warm = (now_ms >= e->last_seen_ms) && ((now_ms - e->last_seen_ms) <= SOL_REPAIR_WARM_TTL_MS);
        break;
    }
    pthread_mutex_unlock(&repair->warm_peers_lock);
    return warm;
}

/*
 * Find a free pending slot
 */
static sol_repair_pending_t*
find_free_pending(sol_repair_t* repair) {
    for (size_t i = 0; i < repair->config.max_pending_requests; i++) {
        if (!repair->pending[i].active) {
            return &repair->pending[i];
        }
    }
    return NULL;
}

static int
repair_request_priority(sol_repair_type_t type) {
    switch (type) {
    case SOL_REPAIR_SHRED:           return 3;
    case SOL_REPAIR_HIGHEST_SHRED:   return 2;
    case SOL_REPAIR_ORPHAN:          return 1;
    case SOL_REPAIR_ANCESTOR_HASHES: return 0;
    }
    return 0;
}

static sol_repair_pending_t*
evict_lower_priority_pending(sol_repair_t* repair, sol_repair_type_t new_type) {
    int new_pri = repair_request_priority(new_type);

    sol_repair_pending_t* victim = NULL;
    int victim_pri = new_pri;
    uint64_t oldest_time = UINT64_MAX;

    for (size_t i = 0; i < repair->config.max_pending_requests; i++) {
        sol_repair_pending_t* p = &repair->pending[i];
        if (!p->active) {
            continue;
        }

        int pri = repair_request_priority(p->type);
        if (pri >= new_pri) {
            continue;
        }

        if (!victim || pri < victim_pri || (pri == victim_pri && p->sent_time < oldest_time)) {
            victim = p;
            victim_pri = pri;
            oldest_time = p->sent_time;
        }
    }

    if (!victim) {
        return NULL;
    }

    /* Evict and reuse the slot */
    victim->active = false;
    if (repair->pending_count > 0) {
        repair->pending_count--;
    }
    return victim;
}

static sol_repair_pending_t*
find_pending_slot(sol_repair_t* repair, sol_repair_type_t type) {
    sol_repair_pending_t* pending = find_free_pending(repair);
    if (pending) {
        return pending;
    }
    return evict_lower_priority_pending(repair, type);
}

/*
 * Find pending request by slot/index
 */
static sol_repair_pending_t*
find_pending(sol_repair_t* repair, sol_slot_t slot, uint64_t shred_index) {
    for (size_t i = 0; i < repair->config.max_pending_requests; i++) {
        if (repair->pending[i].active &&
            repair->pending[i].slot == slot &&
            repair->pending[i].shred_index == shred_index) {
            return &repair->pending[i];
        }
    }
    return NULL;
}

static sol_repair_pending_t*
find_pending_slot_only(sol_repair_t* repair, sol_repair_type_t type, sol_slot_t slot) {
    for (size_t i = 0; i < repair->config.max_pending_requests; i++) {
        sol_repair_pending_t* p = &repair->pending[i];
        if (p->active && p->type == type && p->slot == slot) {
            return p;
        }
    }
    return NULL;
}

/*
 * Select a repair peer
 */
static bool
select_repair_peer(sol_repair_t* repair, sol_sockaddr_t* peer, sol_pubkey_t* peer_pubkey) {
    /* Get peers from gossip */
    const sol_contact_info_t* contacts[100];
    size_t num_contacts = 0;
    if (repair->gossip) {
        num_contacts = sol_gossip_get_cluster_nodes(repair->gossip, contacts, 100);
    }

    /* Filter to peers with a serve_repair socket, then pick one pseudo-randomly
     * to spread load and avoid repeatedly selecting a slow/unreachable peer. */
    const sol_contact_info_t* candidates[100];
    size_t candidate_count = 0;
    for (size_t i = 0; i < num_contacts; i++) {
        const sol_sockaddr_t* addr =
            sol_contact_info_socket(contacts[i], SOL_SOCKET_TAG_SERVE_REPAIR);
        if (!addr) {
            continue;
        }
        if (memcmp(contacts[i]->pubkey.bytes, repair->self_pubkey.bytes, SOL_PUBKEY_SIZE) == 0) {
            continue;
        }
        candidates[candidate_count++] = contacts[i];
    }

    if (candidate_count == 0) {
        /* Fallback: use seeded peers, if configured. */
        pthread_mutex_lock(&repair->seed_peers_lock);
        size_t seed_count = repair->seed_peers_len;
        if (seed_count == 0 || !repair->seed_peers) {
            pthread_mutex_unlock(&repair->seed_peers_lock);
            return false;
        }

        uint64_t now_ms = sol_gossip_now_ms();
        size_t warm_idxs[100];
        size_t warm_count = 0;
        for (size_t i = 0; i < seed_count && warm_count < (sizeof(warm_idxs) / sizeof(warm_idxs[0])); i++) {
            if (is_peer_warm(repair, &repair->seed_peers[i].pubkey, now_ms)) {
                warm_idxs[warm_count++] = i;
            }
        }

        uint64_t seed = sol_gossip_now_ms();
        seed ^= (uint64_t)repair->pending_count << 17;
        seed ^= seed >> 33;
        seed *= 0xff51afd7ed558ccdULL;
        seed ^= seed >> 33;

        bool choose_warm = warm_count > 0;
        if (choose_warm && seed_count > warm_count) {
            /* Avoid getting stuck on a single warm peer: occasionally sample
             * the full peer list. */
            choose_warm = (seed % 10) != 0; /* ~90% warm, ~10% any */
        }

        size_t idx = choose_warm ? warm_idxs[(size_t)(seed % warm_count)]
                                 : (size_t)(seed % seed_count);
        sol_sockaddr_copy(peer, &repair->seed_peers[idx].serve_repair_addr);
        if (peer_pubkey) {
            sol_pubkey_copy(peer_pubkey, &repair->seed_peers[idx].pubkey);
        }
        pthread_mutex_unlock(&repair->seed_peers_lock);
        return true;
    }

    /* Prefer peers that have pinged us recently (ping-cache gating). */
    const sol_contact_info_t* warm_candidates[100];
    size_t warm_count = 0;
    uint64_t now_ms = sol_gossip_now_ms();
    for (size_t i = 0; i < candidate_count; i++) {
        if (is_peer_warm(repair, &candidates[i]->pubkey, now_ms)) {
            warm_candidates[warm_count++] = candidates[i];
        }
    }

    uint64_t seed = sol_gossip_now_ms();
    seed ^= (uint64_t)repair->pending_count << 17;
    seed ^= seed >> 33;
    seed *= 0xff51afd7ed558ccdULL;
    seed ^= seed >> 33;

    if (warm_count && candidate_count > warm_count) {
        /* Prefer warm peers most of the time, but keep sampling cold peers to
         * avoid getting stuck on a single slow/unhelpful peer. */
        if ((seed % 10) != 0) { /* ~90% warm */
            memcpy(candidates, warm_candidates, warm_count * sizeof(candidates[0]));
            candidate_count = warm_count;
        }
    } else if (warm_count) {
        memcpy(candidates, warm_candidates, warm_count * sizeof(candidates[0]));
        candidate_count = warm_count;
    }

    size_t idx = (size_t)(seed % candidate_count);
    const sol_contact_info_t* chosen = candidates[idx];
    const sol_sockaddr_t* addr = sol_contact_info_socket(chosen, SOL_SOCKET_TAG_SERVE_REPAIR);
    if (!addr) {
        return false;
    }
    sol_sockaddr_copy(peer, addr);
    if (peer_pubkey) {
        sol_pubkey_copy(peer_pubkey, &chosen->pubkey);
    }
    return true;
}

/*
 * Send a repair request
 */
static sol_err_t
send_repair_request(sol_repair_t* repair, sol_repair_pending_t* pending) {
    if (!repair || !pending) {
        return SOL_ERR_INVAL;
    }

    /* Solana wire format: bincode enum RepairProtocol.
     *
     * We currently only implement the signed variants:
     * - WindowIndex (request specific shred)
     * - HighestWindowIndex (request highest shred >= index)
     * - Orphan (request parent shreds)
     * - AncestorHashes (request ancestor hash chain)
     *
     * Signature is stored immediately after the 4-byte enum discriminator, and
     * is computed over bytes[0..4] + bytes[4+64..] (skipping signature bytes).
     */
    uint32_t protocol_discriminant = 0;
    switch (pending->type) {
    case SOL_REPAIR_SHRED:           protocol_discriminant = 8;  break; /* WindowIndex */
    case SOL_REPAIR_HIGHEST_SHRED:   protocol_discriminant = 9;  break; /* HighestWindowIndex */
    case SOL_REPAIR_ORPHAN:          protocol_discriminant = 10; break; /* Orphan */
    case SOL_REPAIR_ANCESTOR_HASHES: protocol_discriminant = 11; break; /* AncestorHashes */
    default:                         return SOL_ERR_INVAL;
    }

    uint8_t buf[256];
    size_t len = 0;

    /* Enum discriminator (u32 LE) */
    sol_store_u32_le(buf + len, protocol_discriminant);
    len += 4;

    /* RepairRequestHeader.signature placeholder */
    memset(buf + len, 0, SOL_SIGNATURE_SIZE);
    len += SOL_SIGNATURE_SIZE;

    /* RepairRequestHeader.sender */
    memcpy(buf + len, repair->self_pubkey.bytes, SOL_PUBKEY_SIZE);
    len += SOL_PUBKEY_SIZE;

    /* RepairRequestHeader.recipient */
    memcpy(buf + len, pending->peer_pubkey.bytes, SOL_PUBKEY_SIZE);
    len += SOL_PUBKEY_SIZE;

    /* RepairRequestHeader.timestamp (ms since UNIX epoch) */
    uint64_t timestamp_ms = sol_unix_now_ms();
    sol_store_u64_le(buf + len, timestamp_ms);
    len += 8;

    /* RepairRequestHeader.nonce (u32) */
    if (pending->nonce == 0) {
        repair->nonce_counter++;
        if (repair->nonce_counter == 0) {
            repair->nonce_counter = 1;
        }
        pending->nonce = repair->nonce_counter;
    }
    sol_store_u32_le(buf + len, pending->nonce);
    len += 4;

    /* Variant fields */
    switch (pending->type) {
    case SOL_REPAIR_SHRED:
    case SOL_REPAIR_HIGHEST_SHRED:
        sol_store_u64_le(buf + len, (uint64_t)pending->slot);
        len += 8;
        sol_store_u64_le(buf + len, pending->shred_index);
        len += 8;
        break;
    case SOL_REPAIR_ORPHAN:
    case SOL_REPAIR_ANCESTOR_HASHES:
        sol_store_u64_le(buf + len, (uint64_t)pending->slot);
        len += 8;
        break;
    }

    /* Sign request: bytes[0..4] + bytes[4+64..len] */
    uint8_t signable[256];
    size_t signable_len = 0;
    memcpy(signable, buf, 4);
    signable_len += 4;
    memcpy(signable + signable_len, buf + 4 + SOL_SIGNATURE_SIZE, len - (4 + SOL_SIGNATURE_SIZE));
    signable_len += len - (4 + SOL_SIGNATURE_SIZE);

    sol_signature_t signature;
    sol_ed25519_sign(&repair->identity, signable, signable_len, &signature);
    memcpy(buf + 4, signature.bytes, SOL_SIGNATURE_SIZE);

    /* Send */
    sol_err_t err = sol_udp_send(repair->repair_sock, buf, len, &pending->peer);
    if (err == SOL_OK) {
        repair->stats.requests_sent++;
        static uint32_t req_log_budget = 32;
        if (req_log_budget > 0) {
            char addr_str[64] = {0};
            if (sol_sockaddr_to_string(&pending->peer, addr_str, sizeof(addr_str)) == SOL_OK) {
                sol_log_debug("Repair request sent: type=%s slot=%llu index=%llu nonce=%u to=%s",
                              sol_repair_type_name(pending->type),
                              (unsigned long long)pending->slot,
                              (unsigned long long)pending->shred_index,
                              (unsigned)pending->nonce,
                              addr_str);
            } else {
                sol_log_debug("Repair request sent: type=%s slot=%llu index=%llu nonce=%u",
                              sol_repair_type_name(pending->type),
                              (unsigned long long)pending->slot,
                              (unsigned long long)pending->shred_index,
                              (unsigned)pending->nonce);
            }
            req_log_budget--;
        }
        sol_log_trace("Sent repair request: type=%s slot=%llu index=%llu nonce=%u",
                      sol_repair_type_name(pending->type),
                      (unsigned long long)pending->slot,
                      (unsigned long long)pending->shred_index,
                      (unsigned)pending->nonce);
    }

    return err;
}

/*
 * Process timeout for pending requests
 */
static void
process_timeouts(sol_repair_t* repair) {
    uint64_t now = sol_gossip_now_ms();

    pthread_mutex_lock(&repair->pending_lock);

    for (size_t i = 0; i < repair->config.max_pending_requests; i++) {
        sol_repair_pending_t* p = &repair->pending[i];
        if (!p->active) continue;

        if (now - p->sent_time > repair->config.request_timeout_ms) {
            repair->stats.timeouts++;

            if (p->retries < repair->config.max_retries) {
                /* Retry */
                p->retries++;
                p->sent_time = now;

                /* Try a different peer */
                if (select_repair_peer(repair, &p->peer, &p->peer_pubkey)) {
                    send_repair_request(repair, p);
                }
            } else {
                /* Give up */
                p->active = false;
                repair->pending_count--;
            }
        }
    }

    pthread_mutex_unlock(&repair->pending_lock);
}

#define SOL_REPAIR_PING_TOKEN_SIZE 32u
#define SOL_REPAIR_PING_MSG_BYTES (4u + SOL_PUBKEY_SIZE + SOL_REPAIR_PING_TOKEN_SIZE + SOL_SIGNATURE_SIZE)

static bool
parse_ping_envelope(const uint8_t* data, size_t len, uint32_t expected_discriminant,
                    sol_pubkey_t* from, uint8_t token[SOL_REPAIR_PING_TOKEN_SIZE],
                    sol_signature_t* signature) {
    if (!data || len != SOL_REPAIR_PING_MSG_BYTES) {
        return false;
    }

    uint32_t disc = sol_load_u32_le(data);
    if (disc != expected_discriminant) {
        return false;
    }

    size_t off = 4;
    if (from) {
        memcpy(from->bytes, data + off, SOL_PUBKEY_SIZE);
    }
    off += SOL_PUBKEY_SIZE;

    if (token) {
        memcpy(token, data + off, SOL_REPAIR_PING_TOKEN_SIZE);
    }
    off += SOL_REPAIR_PING_TOKEN_SIZE;

    if (signature) {
        memcpy(signature->bytes, data + off, SOL_SIGNATURE_SIZE);
    }

    return true;
}

static void
hex_prefix16(const uint8_t* data, size_t len, char out[17]);

static void
ping_pong_hash(const uint8_t token[SOL_REPAIR_PING_TOKEN_SIZE], sol_sha256_t* out) {
    static const uint8_t prefix[] = "SOLANA_PING_PONG";
    const void* parts[] = {prefix, token};
    const size_t lens[] = {sizeof(prefix) - 1u, SOL_REPAIR_PING_TOKEN_SIZE};
    sol_sha256_multi(parts, lens, 2, out);
}

static sol_err_t
send_repair_pong(sol_repair_t* repair, const uint8_t token[SOL_REPAIR_PING_TOKEN_SIZE],
                 const sol_sockaddr_t* dest) {
    if (!repair || !token || !dest) {
        return SOL_ERR_INVAL;
    }

    /* Pong is a RepairProtocol enum value (discriminant 7), followed by:
     * - from: Pubkey (32)
     * - hash: Hash (sha256("SOLANA_PING_PONG" + token)) (32)
     * - signature: Signature over hash (64)
     */
    uint8_t buf[SOL_REPAIR_PING_MSG_BYTES];
    size_t w = 0;

    sol_store_u32_le(buf + w, 7u);
    w += 4;

    memcpy(buf + w, repair->self_pubkey.bytes, SOL_PUBKEY_SIZE);
    w += SOL_PUBKEY_SIZE;

    sol_sha256_t hash;
    ping_pong_hash(token, &hash);
    memcpy(buf + w, hash.bytes, SOL_SHA256_HASH_SIZE);
    w += SOL_SHA256_HASH_SIZE;

    sol_signature_t signature;
    sol_ed25519_sign(&repair->identity, hash.bytes, SOL_SHA256_HASH_SIZE, &signature);
    memcpy(buf + w, signature.bytes, SOL_SIGNATURE_SIZE);
    w += SOL_SIGNATURE_SIZE;

    if (w != SOL_REPAIR_PING_MSG_BYTES) {
        return SOL_ERR_ENCODE;
    }

    static uint32_t pong_send_budget = 8;
    if (pong_send_budget > 0) {
        char addr_str[64] = {0};
        char hash_hex[17] = {0};
        hex_prefix16(hash.bytes, SOL_SHA256_HASH_SIZE, hash_hex);
        if (sol_sockaddr_to_string(dest, addr_str, sizeof(addr_str)) == SOL_OK) {
            sol_log_debug("Repair pong sent to %s hash=%s...", addr_str, hash_hex);
        } else {
            sol_log_debug("Repair pong sent hash=%s...", hash_hex);
        }
        pong_send_budget--;
    }

    return sol_udp_send(repair->repair_sock, buf, w, dest);
}

static void
hex_prefix16(const uint8_t* data, size_t len, char out[17]) {
    static const char hex[] = "0123456789abcdef";
    size_t n = len < 8 ? len : 8;
    for (size_t i = 0; i < n; i++) {
        out[i * 2] = hex[data[i] >> 4];
        out[i * 2 + 1] = hex[data[i] & 0x0f];
    }
    out[n * 2] = '\0';
}

static void
log_repair_token(const char* label, const sol_pubkey_t* from, const uint8_t token[32]) {
    if (!label || !from || !token) return;
    char pk[64] = {0};
    char tok_hex[17] = {0};
    hex_prefix16(token, 32, tok_hex);
    if (sol_pubkey_to_base58(from, pk, sizeof(pk)) == SOL_OK) {
        sol_log_debug("%s %s token=%s...", label, pk, tok_hex);
    } else {
        sol_log_debug("%s token=%s...", label, tok_hex);
    }
}

static void
resend_pending_for_peer(sol_repair_t* repair, const sol_pubkey_t* peer_pubkey) {
    if (!repair || !peer_pubkey) return;
    if (repair->pending_count == 0) return;

    uint64_t now_ms = sol_gossip_now_ms();
    sol_repair_pending_t* best = NULL;
    int best_prio = -1;
    uint64_t best_sent = 0;

    pthread_mutex_lock(&repair->pending_lock);
    for (size_t i = 0; i < repair->config.max_pending_requests; i++) {
        sol_repair_pending_t* p = &repair->pending[i];
        if (!p->active) continue;
        if (!sol_pubkey_eq(&p->peer_pubkey, peer_pubkey)) continue;

        int prio = repair_request_priority(p->type);
        if (!best ||
            prio > best_prio ||
            (prio == best_prio && p->sent_time < best_sent)) {
            best = p;
            best_prio = prio;
            best_sent = p->sent_time;
        }
    }

    if (best) {
        best->sent_time = now_ms;
        if (best->retries < repair->config.max_retries) {
            best->retries++;
        }
        (void)send_repair_request(repair, best);
    }
    pthread_mutex_unlock(&repair->pending_lock);

    if (best) {
        static uint32_t resend_log_budget = 32;
        if (resend_log_budget > 0) {
            sol_log_debug("Resent 1 pending repair request after ping");
            resend_log_budget--;
        }
    }
}

static sol_repair_pending_t*
find_pending_by_nonce_locked(sol_repair_t* repair, uint32_t nonce) {
    for (size_t i = 0; i < repair->config.max_pending_requests; i++) {
        sol_repair_pending_t* p = &repair->pending[i];
        if (p->active && p->nonce == nonce) {
            return p;
        }
    }
    return NULL;
}

/*
 * Validate ancestor hash chain
 *
 * Checks that:
 * 1. Slots are in strictly decreasing order (child -> parent)
 * 2. First slot matches the requested slot (if present)
 * 3. No duplicate slots
 */
static sol_ancestor_validation_t
validate_ancestor_chain(sol_repair_ancestor_response_t* response) {
    if (response->ancestors_len == 0) {
        return SOL_ANCESTOR_VALID;  /* Empty chain is valid */
    }

    /* First entry should be the requested slot or close to it */
    if (response->ancestors[0].slot > response->requested_slot) {
        return SOL_ANCESTOR_INVALID_ORDER;
    }

    /* Check slot ordering (must be strictly decreasing) */
    for (uint16_t i = 1; i < response->ancestors_len; i++) {
        if (response->ancestors[i].slot >= response->ancestors[i-1].slot) {
            sol_log_warn("Ancestor chain order violation at index %u: "
                        "slot %llu >= previous slot %llu",
                        (unsigned)i,
                        (unsigned long long)response->ancestors[i].slot,
                        (unsigned long long)response->ancestors[i-1].slot);
            return SOL_ANCESTOR_INVALID_ORDER;
        }
    }

    /* Check for zero hashes (likely invalid) */
    for (uint16_t i = 0; i < response->ancestors_len; i++) {
        bool all_zero = true;
        for (size_t j = 0; j < 32; j++) {
            if (response->ancestors[i].hash.bytes[j] != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) {
            sol_log_warn("Ancestor chain has zero hash at slot %llu",
                        (unsigned long long)response->ancestors[i].slot);
            return SOL_ANCESTOR_INVALID_HASH;
        }
    }

    return SOL_ANCESTOR_VALID;
}

/*
 * Process incoming ancestor hash response
 */
static void
process_ancestor_response(sol_repair_t* repair, const uint8_t* data, size_t len) {
    /* Solana wire format: bincode enum AncestorHashesResponse.
     *
     * Hashes response:
     *   discriminator(u32)=0
     *   len(u64)
     *   repeated: (slot(u64), hash([u8;32]))
     *   optionally followed by nonce(u32) (when sent via repair_response_packet_from_bytes).
     */
    if (!repair || !data) {
        return;
    }

    if (len < 4 + 8) {
        repair->stats.invalid_responses++;
        return;
    }

    uint32_t disc = sol_load_u32_le(data);
    if (disc != 0) {
        repair->stats.invalid_responses++;
        return;
    }

    uint64_t vec_len = sol_load_u64_le(data + 4);
    if (vec_len > SOL_REPAIR_MAX_ANCESTOR_HASHES) {
        repair->stats.invalid_responses++;
        return;
    }

    size_t expected = 4 + 8 + (size_t)vec_len * (8 + SOL_SHA256_HASH_SIZE);

    uint32_t resp_nonce = 0;
    if (len == expected + 4) {
        resp_nonce = sol_load_u32_le(data + expected);
        len = expected;
    } else if (len != expected) {
        repair->stats.invalid_responses++;
        return;
    }

    sol_repair_pending_t* pending = NULL;
    pthread_mutex_lock(&repair->pending_lock);
    pending = find_pending_by_nonce_locked(repair, resp_nonce);
    if (pending && pending->type == SOL_REPAIR_ANCESTOR_HASHES) {
        pending->active = false;
        if (repair->pending_count > 0) {
            repair->pending_count--;
        }
    } else {
        pending = NULL;
    }
    pthread_mutex_unlock(&repair->pending_lock);

    if (!pending) {
        repair->stats.duplicates++;
        return;
    }

    sol_repair_ancestor_response_t response;
    memset(&response, 0, sizeof(response));
    response.requested_slot = pending->slot;

    response.ancestors_len = (uint16_t)vec_len;
    const uint8_t* p = data + 12;
    size_t remaining = len - 12;

    for (uint16_t i = 0; i < response.ancestors_len && remaining >= 8 + SOL_SHA256_HASH_SIZE; i++) {
        response.ancestors[i].slot = sol_load_u64_le(p);
        p += 8;
        memcpy(response.ancestors[i].hash.bytes, p, SOL_SHA256_HASH_SIZE);
        p += SOL_SHA256_HASH_SIZE;
        remaining -= 8 + SOL_SHA256_HASH_SIZE;
    }

    response.validation = validate_ancestor_chain(&response);
    response.validated = true;

    if (response.validation != SOL_ANCESTOR_VALID) {
        repair->stats.invalid_responses++;
        sol_log_warn("Invalid ancestor chain for slot %llu: validation=%d",
                     (unsigned long long)response.requested_slot,
                     (int)response.validation);
    }

    if (repair->ancestor_callback) {
        repair->ancestor_callback(&response, repair->ancestor_callback_ctx);
    }

    sol_log_debug("Received %u ancestor hashes for slot %llu (nonce=%u valid=%s)",
                  (unsigned)response.ancestors_len,
                  (unsigned long long)response.requested_slot,
                  (unsigned)resp_nonce,
                  response.validation == SOL_ANCESTOR_VALID ? "yes" : "no");
}

static bool
unwrap_repair_shred_bincode(const uint8_t* data, size_t len,
                            const uint8_t** out_data, size_t* out_len,
                            uint32_t* out_nonce, bool* out_has_nonce) {
    if (!data || !out_data || !out_len) {
        return false;
    }

    if (len < 4 + 8 + 1u) {
        return false;
    }

    uint32_t disc = sol_load_u32_le(data);
    if (disc > 16u) {
        return false;
    }

    uint64_t vec_len = sol_load_u64_le(data + 4);
    if (vec_len == 0 || vec_len > SOL_SHRED_SIZE) {
        return false;
    }

    size_t expected = 4 + 8 + (size_t)vec_len;
    uint32_t nonce = 0;
    bool has_nonce = false;
    if (len == expected + 4) {
        nonce = sol_load_u32_le(data + expected);
        has_nonce = true;
    } else if (len != expected) {
        return false;
    }

    if (vec_len < SOL_SIGNATURE_SIZE + 1u) {
        return false;
    }

    const uint8_t* inner = data + 12;
    uint8_t variant = inner[SOL_SIGNATURE_SIZE];
    if (!sol_shred_variant_is_data(variant) && !sol_shred_variant_is_code(variant)) {
        return false;
    }

    *out_data = inner;
    *out_len = (size_t)vec_len;
    if (out_nonce) {
        *out_nonce = nonce;
    }
    if (out_has_nonce) {
        *out_has_nonce = has_nonce;
    }
    return true;
}

/*
 * Process incoming repair response (shred or ancestor hashes)
 */
static void
process_response(sol_repair_t* repair, const uint8_t* data, size_t len,
                 const sol_sockaddr_t* from) {
    repair->stats.responses_received++;

    if (len != SOL_REPAIR_PING_MSG_BYTES) {
        static uint32_t non_ping_log_budget = 8;
        if (non_ping_log_budget > 0) {
            sol_log_debug("Repair response len=%zu", len);
            non_ping_log_budget--;
        }
    }

    /* Respond to ping/pong gating first. */
    if (len == SOL_REPAIR_PING_MSG_BYTES && from) {
        static uint32_t ping_log_budget = 8;

        sol_pubkey_t ping_from;
        uint8_t token[SOL_REPAIR_PING_TOKEN_SIZE];
        sol_signature_t sig;

        bool is_ping =
            parse_ping_envelope(data, len, 0u, &ping_from, token, &sig) || /* RepairResponse::Ping */
            parse_ping_envelope(data, len, 1u, &ping_from, token, &sig);   /* AncestorHashesResponse::Ping */

        if (is_ping) {
            if (!sol_ed25519_verify(&ping_from, token, SOL_REPAIR_PING_TOKEN_SIZE, &sig)) {
                repair->stats.invalid_responses++;
            } else {
                mark_peer_warm(repair, &ping_from);
                if (send_repair_pong(repair, token, from) == SOL_OK) {
                    resend_pending_for_peer(repair, &ping_from);
                }
                if (ping_log_budget > 0) {
                    log_repair_token("Repair ping", &ping_from, token);
                    ping_log_budget--;
                }
                return;
            }
        }
    }

    /* Ancestor hash responses are bincode and may be mistaken for shreds unless
     * we gate the parse carefully. Only attempt when we have an outstanding
     * ancestor request and the packet length matches the expected layout. */
    bool have_ancestor_pending = false;
    pthread_mutex_lock(&repair->pending_lock);
    for (size_t i = 0; i < repair->config.max_pending_requests; i++) {
        if (repair->pending[i].active && repair->pending[i].type == SOL_REPAIR_ANCESTOR_HASHES) {
            have_ancestor_pending = true;
            break;
        }
    }
    pthread_mutex_unlock(&repair->pending_lock);

    if (have_ancestor_pending && len >= 12) {
        uint32_t disc = sol_load_u32_le(data);
        if (disc == 0u) {
            uint64_t vec_len = sol_load_u64_le(data + 4);
            if (vec_len <= SOL_REPAIR_MAX_ANCESTOR_HASHES) {
                size_t expected = 4 + 8 + (size_t)vec_len * (8 + SOL_SHA256_HASH_SIZE);
                if (len == expected || len == expected + 4) {
                    process_ancestor_response(repair, data, len);
                    return;
                }
            }
        }
    }

    /* Parse as shred */
    const uint8_t* shred_data = data;
    size_t shred_len = len;
    uint32_t resp_nonce = 0;
    bool have_nonce = false;
    bool used_wrapper = false;

    if (unwrap_repair_shred_bincode(data, len, &shred_data, &shred_len,
                                    &resp_nonce, &have_nonce)) {
        used_wrapper = true;
    }

    sol_shred_t shred;
    sol_err_t err = sol_shred_parse(&shred, shred_data, shred_len);
    if (err != SOL_OK && used_wrapper) {
        shred_data = data;
        shred_len = len;
        used_wrapper = false;
        have_nonce = false;
        err = sol_shred_parse(&shred, data, len);
    }
    if (err != SOL_OK) {
        sol_log_debug("Repair response parse failed (len=%zu, err=%d, wrapped=%s)",
                      len, (int)err, used_wrapper ? "yes" : "no");
        repair->stats.invalid_responses++;
        return;
    }

    /* Find and complete pending request */
    pthread_mutex_lock(&repair->pending_lock);

    if (!used_wrapper && len >= 4) {
        resp_nonce = sol_load_u32_le(data + len - 4);
        have_nonce = true;
    }

    sol_repair_pending_t* pending = NULL;
    bool pending_matched_by_nonce = false;
    if (have_nonce) {
        sol_repair_pending_t* by_nonce = find_pending_by_nonce_locked(repair, resp_nonce);
        if (by_nonce) {
            bool match = true;
            if (by_nonce->slot != shred.slot) {
                match = false;
            } else if (by_nonce->type == SOL_REPAIR_SHRED && by_nonce->shred_index != shred.index) {
                match = false;
            }

            if (match) {
                pending = by_nonce;
                pending_matched_by_nonce = true;
            } else {
                static uint32_t nonce_mismatch_budget = 32;
                if (nonce_mismatch_budget > 0) {
                    sol_log_debug("Repair response nonce mismatch: nonce=%u pending(type=%s slot=%llu index=%llu) got(slot=%llu index=%u)",
                                  (unsigned)resp_nonce,
                                  sol_repair_type_name(by_nonce->type),
                                  (unsigned long long)by_nonce->slot,
                                  (unsigned long long)by_nonce->shred_index,
                                  (unsigned long long)shred.slot,
                                  (unsigned)shred.index);
                    nonce_mismatch_budget--;
                }
            }
        }
    }
    if (!pending) {
        pending = find_pending(repair, shred.slot, shred.index);
    }
    if (!pending) {
        /* Highest/orphan requests are satisfied by any shred for the slot. */
        pending = find_pending_slot_only(repair, SOL_REPAIR_HIGHEST_SHRED, shred.slot);
    }
    if (!pending) {
        pending = find_pending_slot_only(repair, SOL_REPAIR_ORPHAN, shred.slot);
    }
    if (pending) {
        /* Treat any valid response as a "warm" signal for ping-cache gating. */
        mark_peer_warm(repair, &pending->peer_pubkey);
        pending->active = false;
        if (repair->pending_count > 0) {
            repair->pending_count--;
        }
        repair->stats.shreds_repaired++;
    } else {
        repair->stats.duplicates++;
    }

    bool pending_hit = (pending != NULL);

    pthread_mutex_unlock(&repair->pending_lock);

    sol_log_debug("Repair response shred slot=%llu index=%u len=%zu wrapped=%s nonce=%u pending=%s%s",
                  (unsigned long long)shred.slot,
                  (unsigned)shred.index,
                  shred_len,
                  used_wrapper ? "yes" : "no",
                  (unsigned)resp_nonce,
                  pending_hit ? "hit" : "miss",
                  pending_matched_by_nonce ? " (nonce)" : "");

    /* Notify callback */
    if (repair->shred_callback) {
        repair->shred_callback(&shred, repair->shred_callback_ctx);
    }
}

/*
 * Process incoming repair request (serve)
 */
static void
process_request(sol_repair_t* repair, const uint8_t* data, size_t len,
                const sol_sockaddr_t* from) {
    if (!repair->config.serve_repairs || !repair->blockstore) {
        return;  /* Not configured to serve repairs */
    }

    if (len < sizeof(uint32_t)) {
        return;  /* Too short */
    }

    /* First 4 bytes are the request type */
    uint32_t type;
    memcpy(&type, data, sizeof(type));
    data += sizeof(type);
    len -= sizeof(type);

    /* Skip the header (signature + sender + recipient + timestamp + nonce) */
    size_t header_size = sizeof(sol_repair_header_t);
    if (len < header_size) {
        return;  /* Too short for header */
    }
    data += header_size;
    len -= header_size;

    switch ((sol_repair_type_t)type) {
    case SOL_REPAIR_SHRED: {
        /* Parse shred request: slot (u64) + shred_index (u64) */
        if (len < sizeof(uint64_t) * 2) return;

        uint64_t slot, shred_index;
        memcpy(&slot, data, sizeof(uint64_t));
        memcpy(&shred_index, data + sizeof(uint64_t), sizeof(uint64_t));

        sol_log_debug("Serving shred request: slot=%llu index=%llu",
                      (unsigned long long)slot, (unsigned long long)shred_index);

        /* Get shred from blockstore */
        uint8_t shred_buf[2048];
        size_t shred_len = sizeof(shred_buf);

        sol_err_t err = sol_blockstore_get_shred(
            repair->blockstore, slot, (uint32_t)shred_index,
            true,  /* is_data */
            shred_buf, &shred_len);

        if (err == SOL_OK && shred_len > 0) {
            /* Send shred back to requester */
            sol_udp_send(repair->serve_sock, shred_buf, shred_len, from);
            repair->stats.responses_received++;  /* Reusing this for responses sent */
        }
        break;
    }

    case SOL_REPAIR_HIGHEST_SHRED: {
        /* Parse highest shred request: slot (u64) */
        if (len < sizeof(uint64_t)) return;

        uint64_t slot;
        memcpy(&slot, data, sizeof(uint64_t));

        sol_log_debug("Serving highest shred request: slot=%llu",
                      (unsigned long long)slot);

        /* Get slot metadata */
        sol_slot_meta_t meta;
        if (sol_blockstore_get_slot_meta(repair->blockstore, slot, &meta) == SOL_OK) {
            /* Send the last shred index as a response */
            /* For now, we send all shreds from index 0 to last_shred_index */
            for (uint32_t i = 0; i <= meta.last_shred_index && i < meta.num_data_shreds; i++) {
                uint8_t shred_buf[2048];
                size_t shred_len = sizeof(shred_buf);

                sol_err_t err = sol_blockstore_get_shred(
                    repair->blockstore, slot, i, true,
                    shred_buf, &shred_len);

                if (err == SOL_OK && shred_len > 0) {
                    sol_udp_send(repair->serve_sock, shred_buf, shred_len, from);
                }
            }
        }
        break;
    }

    case SOL_REPAIR_ORPHAN: {
        /* Parse orphan request: slot (u64) */
        if (len < sizeof(uint64_t)) return;

        uint64_t slot;
        memcpy(&slot, data, sizeof(uint64_t));

        sol_log_debug("Serving orphan request: slot=%llu",
                      (unsigned long long)slot);

        /* Get slot metadata and send parent shreds */
        sol_slot_meta_t meta;
        if (sol_blockstore_get_slot_meta(repair->blockstore, slot, &meta) == SOL_OK) {
            /* Send shreds from parent slot to help requester build chain */
            sol_slot_t parent = meta.parent_slot;

            sol_slot_meta_t parent_meta;
            if (sol_blockstore_get_slot_meta(repair->blockstore, parent, &parent_meta) == SOL_OK) {
                /* Send first few shreds of parent */
                for (uint32_t i = 0; i < parent_meta.num_data_shreds && i < 10; i++) {
                    uint8_t shred_buf[2048];
                    size_t shred_len = sizeof(shred_buf);

                    sol_err_t err = sol_blockstore_get_shred(
                        repair->blockstore, parent, i, true,
                        shred_buf, &shred_len);

                    if (err == SOL_OK && shred_len > 0) {
                        sol_udp_send(repair->serve_sock, shred_buf, shred_len, from);
                    }
                }
            }
        }
        break;
    }

    case SOL_REPAIR_ANCESTOR_HASHES: {
        /* Parse ancestor hashes request: slot (u64) */
        if (len < sizeof(uint64_t)) return;

        uint64_t slot;
        memcpy(&slot, data, sizeof(uint64_t));

        sol_log_debug("Serving ancestor hashes request: slot=%llu",
                      (unsigned long long)slot);

        /* Build ancestor hash response */
        uint8_t response_buf[8192];
        size_t response_len = 0;

        /* Response type marker (distinguish from shred responses) */
        uint32_t resp_type = SOL_REPAIR_ANCESTOR_HASHES;
        memcpy(response_buf + response_len, &resp_type, 4);
        response_len += 4;

        /* Requested slot */
        memcpy(response_buf + response_len, &slot, 8);
        response_len += 8;

        /* Reserve space for count */
        size_t count_offset = response_len;
        uint16_t count = 0;
        response_len += 2;

        /* Walk ancestor chain from blockstore */
        sol_slot_t current_slot = slot;
        while (count < SOL_REPAIR_MAX_ANCESTOR_HASHES) {
            sol_slot_meta_t meta;
            if (sol_blockstore_get_slot_meta(repair->blockstore, current_slot, &meta) != SOL_OK) {
                break;
            }

            /* Get block hash for this slot */
            sol_hash_t block_hash;
            if (sol_blockstore_get_block_hash(repair->blockstore, current_slot, &block_hash) != SOL_OK) {
                break;
            }

            /* Add to response: slot(8) + hash(32) */
            memcpy(response_buf + response_len, &current_slot, 8);
            response_len += 8;
            memcpy(response_buf + response_len, block_hash.bytes, 32);
            response_len += 32;
            count++;

            /* Move to parent */
            if (meta.parent_slot >= current_slot || meta.parent_slot == 0) {
                break;  /* Reached root or invalid parent */
            }
            current_slot = meta.parent_slot;
        }

        /* Write count */
        memcpy(response_buf + count_offset, &count, 2);

        /* Send response */
        if (count > 0) {
            sol_udp_send(repair->serve_sock, response_buf, response_len, from);
            sol_log_debug("Sent %u ancestor hashes for slot %llu",
                          (unsigned)count, (unsigned long long)slot);
        }
        break;
    }

    default:
        sol_log_debug("Unknown repair request type: %u", type);
        break;
    }
}

sol_repair_t*
sol_repair_new(const sol_repair_config_t* config,
               sol_gossip_t* gossip,
               const sol_keypair_t* identity) {
    sol_repair_t* repair = sol_calloc(1, sizeof(sol_repair_t));
    if (!repair) return NULL;

    if (config) {
        repair->config = *config;
    } else {
        repair->config = (sol_repair_config_t)SOL_REPAIR_CONFIG_DEFAULT;
    }

    repair->gossip = gossip;

    if (identity) {
        memcpy(&repair->identity, identity, sizeof(sol_keypair_t));
        sol_keypair_pubkey(identity, &repair->self_pubkey);
    }

    /* Start nonces at a time-derived value to reduce collision risk across
     * restarts. Nonces are per-request and must be unique enough to safely
     * match responses. */
    repair->nonce_counter = (uint32_t)sol_unix_now_ms();
    if (repair->nonce_counter == 0) {
        repair->nonce_counter = 1;
    }

    /* Allocate pending requests */
    repair->pending = sol_calloc(
        repair->config.max_pending_requests,
        sizeof(sol_repair_pending_t));
    if (!repair->pending) {
        sol_free(repair);
        return NULL;
    }

    if (pthread_mutex_init(&repair->pending_lock, NULL) != 0) {
        sol_free(repair->pending);
        sol_free(repair);
        return NULL;
    }

    if (pthread_mutex_init(&repair->seed_peers_lock, NULL) != 0) {
        pthread_mutex_destroy(&repair->pending_lock);
        sol_free(repair->pending);
        sol_free(repair);
        return NULL;
    }

    if (pthread_mutex_init(&repair->warm_peers_lock, NULL) != 0) {
        pthread_mutex_destroy(&repair->seed_peers_lock);
        pthread_mutex_destroy(&repair->pending_lock);
        sol_free(repair->pending);
        sol_free(repair);
        return NULL;
    }

    return repair;
}

void
sol_repair_destroy(sol_repair_t* repair) {
    if (!repair) return;

    sol_repair_stop(repair);

    if (repair->repair_sock) {
        sol_udp_destroy(repair->repair_sock);
    }
    if (repair->serve_sock) {
        sol_udp_destroy(repair->serve_sock);
    }

    pthread_mutex_destroy(&repair->warm_peers_lock);

    pthread_mutex_destroy(&repair->seed_peers_lock);
    sol_free(repair->seed_peers);

    pthread_mutex_destroy(&repair->pending_lock);
    sol_free(repair->pending);
    sol_free(repair);
}

sol_err_t
sol_repair_start(sol_repair_t* repair, uint16_t port) {
    if (!repair) return SOL_ERR_INVAL;
    if (repair->running) return SOL_OK;

    /* Create repair socket (for sending requests) */
    sol_udp_config_t udp_cfg = SOL_UDP_CONFIG_DEFAULT;
    udp_cfg.bind_port = 0;  /* Any port */
    udp_cfg.nonblocking = true;

    repair->repair_sock = sol_udp_new(&udp_cfg);
    if (!repair->repair_sock) {
        sol_log_error("Failed to create repair socket");
        return SOL_ERR_IO;
    }
    sol_sockaddr_t local_addr;
    if (sol_udp_local_addr(repair->repair_sock, &local_addr) == SOL_OK) {
        char addr_buf[64] = {0};
        if (sol_sockaddr_to_string(&local_addr, addr_buf, sizeof(addr_buf)) == SOL_OK) {
            sol_log_info("Repair request socket bound to %s", addr_buf);
        }
    }

    /* Create serve socket (for receiving requests) */
    if (repair->config.serve_repairs) {
        udp_cfg.bind_port = port;
        repair->serve_sock = sol_udp_new(&udp_cfg);
        if (!repair->serve_sock) {
            sol_log_warn("Failed to create serve repair socket");
            /* Not fatal - we can still request repairs */
        }
    }

    repair->running = true;
    sol_log_info("Repair service started on port %u", port);

    return SOL_OK;
}

void
sol_repair_stop(sol_repair_t* repair) {
    if (repair) {
        repair->running = false;
    }
}

bool
sol_repair_is_running(const sol_repair_t* repair) {
    return repair && repair->running;
}

sol_err_t
sol_repair_run_once(sol_repair_t* repair, uint32_t timeout_ms) {
    (void)timeout_ms;

    if (!repair || !repair->running) {
        return SOL_ERR_SHUTDOWN;
    }

    /* Drain repair socket (responses). */
    enum { SOL_REPAIR_RECV_BUDGET = 128 };
    for (size_t i = 0; i < SOL_REPAIR_RECV_BUDGET; i++) {
        sol_sockaddr_t from;
        size_t len = sizeof(repair->recv_buf);

        sol_err_t err = sol_udp_recv(repair->repair_sock, repair->recv_buf,
                                     &len, &from);
        if (err == SOL_OK) {
            process_response(repair, repair->recv_buf, len, &from);
            continue;
        }
        break;
    }

    /* Drain serve socket (requests). */
    if (repair->serve_sock) {
        for (size_t i = 0; i < SOL_REPAIR_RECV_BUDGET; i++) {
            sol_sockaddr_t from;
            size_t len = sizeof(repair->recv_buf);

            sol_err_t err = sol_udp_recv(repair->serve_sock, repair->recv_buf, &len, &from);
            if (err == SOL_OK) {
                process_request(repair, repair->recv_buf, len, &from);
                continue;
            }
            break;
        }
    }

    /* Process timeouts */
    process_timeouts(repair);

    return SOL_OK;
}

sol_err_t
sol_repair_local_addr(const sol_repair_t* repair, sol_sockaddr_t* addr) {
    if (!repair || !addr || !repair->repair_sock) {
        return SOL_ERR_INVAL;
    }

    return sol_udp_local_addr(repair->repair_sock, addr);
}

sol_err_t
sol_repair_request_shred(sol_repair_t* repair, sol_slot_t slot,
                         uint64_t shred_index, bool is_data) {
    if (!repair) return SOL_ERR_INVAL;

    pthread_mutex_lock(&repair->pending_lock);

    /* Check if already pending */
    if (find_pending(repair, slot, shred_index)) {
        pthread_mutex_unlock(&repair->pending_lock);
        return SOL_OK;
    }

    /* Find free slot */
    sol_repair_pending_t* pending = find_pending_slot(repair, SOL_REPAIR_SHRED);
    if (!pending) {
        pthread_mutex_unlock(&repair->pending_lock);
        return SOL_ERR_FULL;
    }

    /* Select peer */
    if (!select_repair_peer(repair, &pending->peer, &pending->peer_pubkey)) {
        pthread_mutex_unlock(&repair->pending_lock);
        return SOL_ERR_PEER_UNAVAILABLE;
    }

    /* Initialize request */
    pending->type = SOL_REPAIR_SHRED;
    pending->slot = slot;
    pending->shred_index = shred_index;
    pending->is_data = is_data;  /* Use shred type flag */
    pending->nonce = 0;
    pending->sent_time = sol_gossip_now_ms();
    pending->retries = 0;
    pending->active = true;
    repair->pending_count++;

    /* Send request */
    sol_err_t err = send_repair_request(repair, pending);
    if (err != SOL_OK) {
        pending->active = false;
        repair->pending_count--;
    }

    pthread_mutex_unlock(&repair->pending_lock);

    return err;
}

sol_err_t
sol_repair_request_highest(sol_repair_t* repair, sol_slot_t slot, uint64_t shred_index) {
    if (!repair) return SOL_ERR_INVAL;

    pthread_mutex_lock(&repair->pending_lock);

    for (size_t i = 0; i < repair->config.max_pending_requests; i++) {
        sol_repair_pending_t* p = &repair->pending[i];
        if (p->active && p->type == SOL_REPAIR_HIGHEST_SHRED && p->slot == slot) {
            pthread_mutex_unlock(&repair->pending_lock);
            return SOL_OK;
        }
    }

    sol_repair_pending_t* pending = find_pending_slot(repair, SOL_REPAIR_HIGHEST_SHRED);
    if (!pending) {
        pthread_mutex_unlock(&repair->pending_lock);
        return SOL_ERR_FULL;
    }

    if (!select_repair_peer(repair, &pending->peer, &pending->peer_pubkey)) {
        pthread_mutex_unlock(&repair->pending_lock);
        return SOL_ERR_PEER_UNAVAILABLE;
    }

    pending->type = SOL_REPAIR_HIGHEST_SHRED;
    pending->slot = slot;
    pending->shred_index = shred_index;
    pending->nonce = 0;
    pending->sent_time = sol_gossip_now_ms();
    pending->retries = 0;
    pending->active = true;
    repair->pending_count++;

    sol_err_t err = send_repair_request(repair, pending);
    if (err != SOL_OK) {
        pending->active = false;
        repair->pending_count--;
    }

    pthread_mutex_unlock(&repair->pending_lock);

    return err;
}

sol_err_t
sol_repair_request_orphan(sol_repair_t* repair, sol_slot_t slot) {
    if (!repair) return SOL_ERR_INVAL;

    pthread_mutex_lock(&repair->pending_lock);

    for (size_t i = 0; i < repair->config.max_pending_requests; i++) {
        sol_repair_pending_t* p = &repair->pending[i];
        if (p->active && p->type == SOL_REPAIR_ORPHAN && p->slot == slot) {
            pthread_mutex_unlock(&repair->pending_lock);
            return SOL_OK;
        }
    }

    sol_repair_pending_t* pending = find_pending_slot(repair, SOL_REPAIR_ORPHAN);
    if (!pending) {
        pthread_mutex_unlock(&repair->pending_lock);
        return SOL_ERR_FULL;
    }

    if (!select_repair_peer(repair, &pending->peer, &pending->peer_pubkey)) {
        pthread_mutex_unlock(&repair->pending_lock);
        return SOL_ERR_PEER_UNAVAILABLE;
    }

    pending->type = SOL_REPAIR_ORPHAN;
    pending->slot = slot;
    pending->shred_index = 0;
    pending->nonce = 0;
    pending->sent_time = sol_gossip_now_ms();
    pending->retries = 0;
    pending->active = true;
    repair->pending_count++;

    sol_err_t err = send_repair_request(repair, pending);
    if (err != SOL_OK) {
        pending->active = false;
        repair->pending_count--;
    }

    pthread_mutex_unlock(&repair->pending_lock);

    return err;
}

void
sol_repair_set_shred_callback(sol_repair_t* repair,
                              sol_repair_shred_cb callback, void* ctx) {
    if (repair) {
        repair->shred_callback = callback;
        repair->shred_callback_ctx = ctx;
    }
}

void
sol_repair_stats(const sol_repair_t* repair, sol_repair_stats_t* stats) {
    if (repair && stats) {
        *stats = repair->stats;
    }
}

void
sol_repair_stats_reset(sol_repair_t* repair) {
    if (repair) {
        memset(&repair->stats, 0, sizeof(repair->stats));
    }
}

size_t
sol_repair_pending_count(sol_repair_t* repair) {
    if (!repair) return 0;
    size_t count = 0;
    pthread_mutex_lock(&repair->pending_lock);
    count = repair->pending_count;
    pthread_mutex_unlock(&repair->pending_lock);
    return count;
}

size_t
sol_repair_max_pending(const sol_repair_t* repair) {
    if (!repair) return 0;
    return (size_t)repair->config.max_pending_requests;
}

void
sol_repair_set_blockstore(sol_repair_t* repair, void* blockstore) {
    if (repair) {
        repair->blockstore = (sol_blockstore_t*)blockstore;
    }
}

sol_err_t
sol_repair_request_ancestor_hashes(sol_repair_t* repair, sol_slot_t slot) {
    if (!repair) return SOL_ERR_INVAL;

    pthread_mutex_lock(&repair->pending_lock);

    /* Check if already pending */
    for (size_t i = 0; i < repair->config.max_pending_requests; i++) {
        sol_repair_pending_t* p = &repair->pending[i];
        if (p->active && p->type == SOL_REPAIR_ANCESTOR_HASHES && p->slot == slot) {
            pthread_mutex_unlock(&repair->pending_lock);
            return SOL_OK;  /* Already requested */
        }
    }

    /* Find free slot */
    sol_repair_pending_t* pending = find_pending_slot(repair, SOL_REPAIR_ANCESTOR_HASHES);
    if (!pending) {
        pthread_mutex_unlock(&repair->pending_lock);
        return SOL_ERR_FULL;
    }

    /* Select peer */
    if (!select_repair_peer(repair, &pending->peer, &pending->peer_pubkey)) {
        pthread_mutex_unlock(&repair->pending_lock);
        return SOL_ERR_PEER_UNAVAILABLE;
    }

    /* Initialize request */
    pending->type = SOL_REPAIR_ANCESTOR_HASHES;
    pending->slot = slot;
    pending->shred_index = 0;  /* Not used for ancestor requests */
    pending->nonce = 0;
    pending->sent_time = sol_gossip_now_ms();
    pending->retries = 0;
    pending->active = true;
    repair->pending_count++;

    /* Send request */
    sol_err_t err = send_repair_request(repair, pending);
    if (err != SOL_OK) {
        pending->active = false;
        repair->pending_count--;
    } else {
        sol_log_debug("Requested ancestor hashes for slot %llu",
                      (unsigned long long)slot);
    }

    pthread_mutex_unlock(&repair->pending_lock);

    return err;
}

sol_err_t
sol_repair_set_seed_peers(sol_repair_t* repair,
                          const sol_repair_seed_peer_t* peers,
                          size_t peers_len) {
    if (!repair) return SOL_ERR_INVAL;

    pthread_mutex_lock(&repair->seed_peers_lock);

    sol_free(repair->seed_peers);
    repair->seed_peers = NULL;
    repair->seed_peers_len = 0;

    if (!peers || peers_len == 0) {
        pthread_mutex_unlock(&repair->seed_peers_lock);
        return SOL_OK;
    }

    sol_repair_seed_peer_t* copy = sol_calloc(peers_len, sizeof(sol_repair_seed_peer_t));
    if (!copy) {
        pthread_mutex_unlock(&repair->seed_peers_lock);
        return SOL_ERR_NOMEM;
    }

    memcpy(copy, peers, peers_len * sizeof(sol_repair_seed_peer_t));
    repair->seed_peers = copy;
    repair->seed_peers_len = peers_len;

    pthread_mutex_unlock(&repair->seed_peers_lock);
    return SOL_OK;
}

void
sol_repair_set_ancestor_callback(sol_repair_t* repair,
                                 sol_repair_ancestor_cb callback, void* ctx) {
    if (repair) {
        repair->ancestor_callback = callback;
        repair->ancestor_callback_ctx = ctx;
    }
}
