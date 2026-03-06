/*
 * sol_repair.c - Shred repair protocol implementation
 */

#include "sol_repair.h"
#include "../util/sol_alloc.h"
#include "../util/sol_bits.h"
#include "../util/sol_log.h"
#include "../gossip/sol_crds_value.h"
#include "../runtime/sol_leader_schedule.h"
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
    SOL_REPAIR_SLOT_PEER_CACHE_SIZE = 2048, /* power of two */
    SOL_REPAIR_SLOT_PEER_TTL_MS = 30 * 1000,
    /* Best-effort hedge fanout for tail-latency sensitive catchup. */
    SOL_REPAIR_MAX_FANOUT = 64,
    /* Throttle timeout scans in sol_repair_run_once. Scanning the full pending
     * table every main-loop iteration is expensive and can cause packet drops
     * under high repair rates. */
    SOL_REPAIR_TIMEOUT_CHECK_MIN_INTERVAL_MS = 2,
};

typedef struct {
    sol_pubkey_t pubkey;
    uint64_t     last_seen_ms;
    bool         active;
} sol_repair_warm_peer_t;

typedef struct {
    sol_slot_t      slot;
    sol_sockaddr_t  addr;
    sol_pubkey_t    pubkey;
    uint64_t        last_seen_ms;
    bool            active;
} sol_repair_slot_peer_t;

static bool
sockaddr_is_public_ip(const sol_sockaddr_t* sa) {
    if (!sa) return false;

    sol_endpoint_t ep = {0};
    if (sol_endpoint_from_sockaddr(&ep, sa) != SOL_OK) {
        return false;
    }

    struct in_addr a4;
    if (inet_pton(AF_INET, ep.ip, &a4) == 1) {
        uint32_t ip = ntohl(a4.s_addr);

        /* Reject unroutable/localhost/private ranges for repair peer selection. */
        if ((ip & 0xFF000000u) == 0x0A000000u) return false;         /* 10.0.0.0/8 */
        if ((ip & 0xFFF00000u) == 0xAC100000u) return false;         /* 172.16.0.0/12 */
        if ((ip & 0xFFFF0000u) == 0xC0A80000u) return false;         /* 192.168.0.0/16 */
        if ((ip & 0xFF000000u) == 0x7F000000u) return false;         /* 127.0.0.0/8 */
        if ((ip & 0xFFFF0000u) == 0xA9FE0000u) return false;         /* 169.254.0.0/16 */
        if ((ip & 0xFFC00000u) == 0x64400000u) return false;         /* 100.64.0.0/10 */
        if ((ip & 0xFF000000u) == 0x00000000u) return false;         /* 0.0.0.0/8 */

        if ((ip & 0xF0000000u) == 0xE0000000u) return false;         /* multicast/reserved */

        return true;
    }

    struct in6_addr a6;
    if (inet_pton(AF_INET6, ep.ip, &a6) == 1) {
        /* Reject loopback, link-local, and unique-local ranges. */
        static const struct in6_addr loopback = IN6ADDR_LOOPBACK_INIT;
        if (memcmp(&a6, &loopback, sizeof(a6)) == 0) return false;

        if ((a6.s6_addr[0] == 0xfe) && ((a6.s6_addr[1] & 0xc0) == 0x80)) return false; /* fe80::/10 */
        if ((a6.s6_addr[0] & 0xfe) == 0xfc) return false;                               /* fc00::/7 */

        if (a6.s6_addr[0] == 0xff) return false; /* multicast */

        return true;
    }

    /* Unknown family; treat as non-public to be safe. */
    return false;
}

/*
 * Repair service structure
 */
struct sol_repair {
    /* Configuration */
    sol_repair_config_t config;
    sol_keypair_t       identity;
    sol_pubkey_t        self_pubkey;
    uint32_t            nonce_counter;
    uint64_t            peer_select_counter;

    /* Gossip for peer discovery */
    sol_gossip_t*       gossip;

    /* Leader schedule for leader-targeted repair peer selection */
    sol_leader_schedule_t* leader_schedule;

    /* Blockstore for serving repairs */
    sol_blockstore_t*   blockstore;

    /* Network */
    sol_udp_sock_t*     repair_sock;
    sol_udp_sock_t*     serve_sock;
    bool                running;

    /* Pending requests */
    sol_repair_pending_t* pending;
    size_t              pending_count;
    size_t              pending_scan_cursor;
    pthread_mutex_t     pending_lock;

    /* Nonce -> pending index map (open addressing). Protected by pending_lock. */
    uint32_t*           nonce_keys;
    int32_t*            nonce_vals;      /* -1 empty, -2 tombstone, >=0 pending index */
    size_t              nonce_map_size;  /* power of two */

    /* (type,slot,shred_index)->pending index map (open addressing). Protected by pending_lock.
     * This eliminates O(n) scans of the pending table on request hot paths. */
    uint64_t*           req_slots;
    uint64_t*           req_indices;
    uint8_t*            req_types;
    int32_t*            req_vals;      /* -1 empty, -2 tombstone, >=0 pending index */
    size_t              req_map_size;  /* power of two */

    /* Track outstanding ancestor-hash requests to avoid scanning pending table
     * on every shred response. Guarded by pending_lock for updates, but read
     * with relaxed atomics in hot paths. */
    uint32_t            ancestor_pending_count;

    uint64_t            last_timeout_check_ms;

    /* Per-slot "sticky" peer cache to improve hit-rate during catchup. */
    sol_repair_slot_peer_t slot_peers[SOL_REPAIR_SLOT_PEER_CACHE_SIZE];

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

/* pending_lock must be held by caller */
static void
pending_deactivate_locked(sol_repair_t* repair, sol_repair_pending_t* pending);

static uint64_t
sol_unix_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static inline bool
pending_ptr_is_tracked(const sol_repair_t* repair, const sol_repair_pending_t* pending) {
    if (!repair || !pending || !repair->pending) return false;
    const sol_repair_pending_t* base = repair->pending;
    const sol_repair_pending_t* end = base + repair->config.max_pending_requests;
    return pending >= base && pending < end;
}

static size_t
pow2_ge(size_t v) {
    size_t p = 1;
    while (p < v && p != 0) p <<= 1;
    return p ? p : (size_t)1;
}

static inline size_t
nonce_hash(uint32_t nonce, size_t mask) {
    /* Knuth multiplicative hash (works best with power-of-two tables). */
    return ((size_t)(nonce * 2654435761u)) & mask;
}

static inline uint64_t
mix_u64(uint64_t x) {
    /* MurmurHash3 finalizer. */
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

static inline uint64_t
req_index_key(sol_repair_type_t type, uint64_t shred_index) {
    /* Only shred requests key by (slot,index). Other request types are treated
     * as "one per slot". */
    return (type == SOL_REPAIR_SHRED) ? shred_index : 0ULL;
}

static inline size_t
req_hash(sol_repair_type_t type, sol_slot_t slot, uint64_t shred_index, size_t mask) {
    uint64_t h = (uint64_t)slot;
    h ^= mix_u64(shred_index + 0x9e3779b97f4a7c15ULL);
    h ^= (uint64_t)((uint32_t)type) * 0x94d049bb133111ebULL;
    return (size_t)mix_u64(h) & mask;
}

/* pending_lock must be held by caller */
static int32_t
nonce_map_get_locked(const sol_repair_t* repair, uint32_t nonce) {
    if (!repair || !repair->nonce_vals || !repair->nonce_keys || repair->nonce_map_size == 0) {
        return -1;
    }
    if (nonce == 0) {
        return -1;
    }
    size_t mask = repair->nonce_map_size - 1u;
    size_t idx = nonce_hash(nonce, mask);
    for (size_t probe = 0; probe < repair->nonce_map_size; probe++) {
        int32_t v = repair->nonce_vals[idx];
        if (v == -1) {
            return -1; /* empty => not found */
        }
        if (v >= 0 && repair->nonce_keys[idx] == nonce) {
            return v;
        }
        idx = (idx + 1u) & mask;
    }
    return -1;
}

/* pending_lock must be held by caller */
static int32_t
req_map_get_locked(const sol_repair_t* repair, sol_repair_type_t type, sol_slot_t slot, uint64_t shred_index) {
    if (!repair || !repair->req_vals || !repair->req_slots || !repair->req_indices || !repair->req_types ||
        repair->req_map_size == 0) {
        return -1;
    }
    if (slot == 0) {
        return -1;
    }
    size_t mask = repair->req_map_size - 1u;
    uint64_t idx_key = req_index_key(type, shred_index);
    size_t idx = req_hash(type, slot, idx_key, mask);
    for (size_t probe = 0; probe < repair->req_map_size; probe++) {
        int32_t v = repair->req_vals[idx];
        if (v == -1) {
            return -1;
        }
        if (v >= 0 &&
            repair->req_slots[idx] == (uint64_t)slot &&
            repair->req_indices[idx] == idx_key &&
            repair->req_types[idx] == (uint8_t)type) {
            return v;
        }
        idx = (idx + 1u) & mask;
    }
    return -1;
}

/* pending_lock must be held by caller */
static void
req_map_put_locked(sol_repair_t* repair, sol_repair_type_t type, sol_slot_t slot, uint64_t shred_index, int32_t pending_idx) {
    if (!repair || !repair->req_vals || !repair->req_slots || !repair->req_indices || !repair->req_types ||
        repair->req_map_size == 0) {
        return;
    }
    if (slot == 0) {
        return;
    }
    size_t mask = repair->req_map_size - 1u;
    uint64_t idx_key = req_index_key(type, shred_index);
    size_t idx = req_hash(type, slot, idx_key, mask);
    size_t first_tomb = (size_t)-1;
    for (size_t probe = 0; probe < repair->req_map_size; probe++) {
        int32_t v = repair->req_vals[idx];
        if (v == -1) {
            size_t use = (first_tomb != (size_t)-1) ? first_tomb : idx;
            repair->req_slots[use] = (uint64_t)slot;
            repair->req_indices[use] = idx_key;
            repair->req_types[use] = (uint8_t)type;
            repair->req_vals[use] = pending_idx;
            return;
        }
        if (v == -2) {
            if (first_tomb == (size_t)-1) first_tomb = idx;
        } else if (repair->req_slots[idx] == (uint64_t)slot &&
                   repair->req_indices[idx] == idx_key &&
                   repair->req_types[idx] == (uint8_t)type) {
            repair->req_vals[idx] = pending_idx;
            return;
        }
        idx = (idx + 1u) & mask;
    }

    /* Table saturated (no empty slots). If we saw a tombstone, reuse it;
     * otherwise, the map is best-effort and callers will fall back. */
    if (first_tomb != (size_t)-1) {
        repair->req_slots[first_tomb] = (uint64_t)slot;
        repair->req_indices[first_tomb] = idx_key;
        repair->req_types[first_tomb] = (uint8_t)type;
        repair->req_vals[first_tomb] = pending_idx;
    }
}

/* pending_lock must be held by caller */
static void
req_map_del_locked(sol_repair_t* repair, sol_repair_type_t type, sol_slot_t slot, uint64_t shred_index) {
    if (!repair || !repair->req_vals || !repair->req_slots || !repair->req_indices || !repair->req_types ||
        repair->req_map_size == 0) {
        return;
    }
    if (slot == 0) {
        return;
    }
    size_t mask = repair->req_map_size - 1u;
    uint64_t idx_key = req_index_key(type, shred_index);
    size_t idx = req_hash(type, slot, idx_key, mask);
    for (size_t probe = 0; probe < repair->req_map_size; probe++) {
        int32_t v = repair->req_vals[idx];
        if (v == -1) {
            return;
        }
        if (v >= 0 &&
            repair->req_slots[idx] == (uint64_t)slot &&
            repair->req_indices[idx] == idx_key &&
            repair->req_types[idx] == (uint8_t)type) {
            repair->req_vals[idx] = -2;
            return;
        }
        idx = (idx + 1u) & mask;
    }
}

/* pending_lock must be held by caller */
static void
nonce_map_put_locked(sol_repair_t* repair, uint32_t nonce, int32_t pending_idx) {
    if (!repair || !repair->nonce_vals || !repair->nonce_keys || repair->nonce_map_size == 0) {
        return;
    }
    if (nonce == 0) {
        return;
    }
    size_t mask = repair->nonce_map_size - 1u;
    size_t idx = nonce_hash(nonce, mask);
    size_t first_tomb = (size_t)-1;
    for (size_t probe = 0; probe < repair->nonce_map_size; probe++) {
        int32_t v = repair->nonce_vals[idx];
        if (v == -1) {
            size_t use = (first_tomb != (size_t)-1) ? first_tomb : idx;
            repair->nonce_keys[use] = nonce;
            repair->nonce_vals[use] = pending_idx;
            return;
        }
        if (v == -2) {
            if (first_tomb == (size_t)-1) first_tomb = idx;
        } else if (repair->nonce_keys[idx] == nonce) {
            repair->nonce_vals[idx] = pending_idx;
            return;
        }
        idx = (idx + 1u) & mask;
    }

    /* Table saturated (no empty slots). If we saw a tombstone, reuse it;
     * otherwise, the map is best-effort and callers will fall back. */
    if (first_tomb != (size_t)-1) {
        repair->nonce_keys[first_tomb] = nonce;
        repair->nonce_vals[first_tomb] = pending_idx;
    }
}

/* pending_lock must be held by caller */
static void
nonce_map_del_locked(sol_repair_t* repair, uint32_t nonce) {
    if (!repair || !repair->nonce_vals || !repair->nonce_keys || repair->nonce_map_size == 0) {
        return;
    }
    if (nonce == 0) {
        return;
    }
    size_t mask = repair->nonce_map_size - 1u;
    size_t idx = nonce_hash(nonce, mask);
    for (size_t probe = 0; probe < repair->nonce_map_size; probe++) {
        int32_t v = repair->nonce_vals[idx];
        if (v == -1) {
            return; /* not found */
        }
        if (v >= 0 && repair->nonce_keys[idx] == nonce) {
            repair->nonce_vals[idx] = -2;
            return;
        }
        idx = (idx + 1u) & mask;
    }
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

static inline size_t
slot_peer_cache_idx(sol_slot_t slot) {
    return ((size_t)slot) & (SOL_REPAIR_SLOT_PEER_CACHE_SIZE - 1u);
}

/* pending_lock must be held by caller */
static bool
slot_peer_cache_get_locked(sol_repair_t* repair,
                           sol_slot_t slot,
                           uint64_t now_ms,
                           sol_sockaddr_t* peer,
                           sol_pubkey_t* peer_pubkey) {
    if (!repair || slot == 0 || !peer) {
        return false;
    }

    sol_repair_slot_peer_t* e = &repair->slot_peers[slot_peer_cache_idx(slot)];
    if (!e->active) {
        return false;
    }
    if (e->slot != slot) {
        return false;
    }
    if (now_ms < e->last_seen_ms ||
        (now_ms - e->last_seen_ms) > SOL_REPAIR_SLOT_PEER_TTL_MS) {
        return false;
    }
    if (!is_peer_warm(repair, &e->pubkey, now_ms)) {
        return false;
    }

    sol_sockaddr_copy(peer, &e->addr);
    if (peer_pubkey) {
        sol_pubkey_copy(peer_pubkey, &e->pubkey);
    }
    return true;
}

/* pending_lock must be held by caller */
static void
slot_peer_cache_update_locked(sol_repair_t* repair,
                              sol_slot_t slot,
                              const sol_sockaddr_t* peer,
                              const sol_pubkey_t* peer_pubkey,
                              uint64_t now_ms) {
    if (!repair || slot == 0 || !peer || !peer_pubkey) {
        return;
    }

    sol_repair_slot_peer_t* e = &repair->slot_peers[slot_peer_cache_idx(slot)];
    e->slot = slot;
    sol_sockaddr_copy(&e->addr, peer);
    sol_pubkey_copy(&e->pubkey, peer_pubkey);
    e->last_seen_ms = now_ms;
    e->active = true;
}

/*
 * Find a free pending slot
 */
static sol_repair_pending_t*
find_free_pending(sol_repair_t* repair) {
    if (!repair || !repair->pending) {
        return NULL;
    }
    size_t cap = repair->config.max_pending_requests;
    if (cap == 0u) {
        return NULL;
    }

    size_t start = repair->pending_scan_cursor;
    if (start >= cap) {
        start = 0u;
    }

    for (size_t n = 0; n < cap; n++) {
        size_t i = start + n;
        if (i >= cap) {
            i -= cap;
        }
        if (!repair->pending[i].active) {
            repair->pending_scan_cursor = (i + 1u < cap) ? (i + 1u) : 0u;
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
    pending_deactivate_locked(repair, victim);
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
find_pending(sol_repair_t* repair, sol_repair_type_t type, sol_slot_t slot, uint64_t shred_index) {
    int32_t idx = req_map_get_locked(repair, type, slot, shred_index);
    if (idx >= 0 && (size_t)idx < repair->config.max_pending_requests) {
        sol_repair_pending_t* p = &repair->pending[idx];
        uint64_t idx_key = req_index_key(type, shred_index);
        if (p->active &&
            p->type == type &&
            p->slot == slot &&
            req_index_key(p->type, p->shred_index) == idx_key) {
            return p;
        }
    }

    /* Fallback: linear scan if map is unavailable. */
    if (!repair->req_map_size || !repair->req_vals) {
        uint64_t idx_key = req_index_key(type, shred_index);
        for (size_t i = 0; i < repair->config.max_pending_requests; i++) {
            sol_repair_pending_t* p = &repair->pending[i];
            if (!p->active) continue;
            if (p->type != type) continue;
            if (p->slot != slot) continue;
            if (req_index_key(p->type, p->shred_index) != idx_key) continue;
            return p;
        }
    }

    return NULL;
}

static sol_repair_pending_t*
find_pending_slot_only(sol_repair_t* repair, sol_repair_type_t type, sol_slot_t slot) {
    int32_t idx = req_map_get_locked(repair, type, slot, 0);
    if (idx >= 0 && (size_t)idx < repair->config.max_pending_requests) {
        sol_repair_pending_t* p = &repair->pending[idx];
        if (p->active && p->type == type && p->slot == slot) {
            return p;
        }
    }

    /* Fallback: linear scan if map is unavailable. */
    if (!repair->req_map_size || !repair->req_vals) {
        for (size_t i = 0; i < repair->config.max_pending_requests; i++) {
            sol_repair_pending_t* p = &repair->pending[i];
            if (p->active && p->type == type && p->slot == slot) {
                return p;
            }
        }
    }

    return NULL;
}

/*
 * Select a repair peer
 */
static bool
pubkey_in_avoid_list(const sol_pubkey_t* pubkey,
                     const sol_pubkey_t* avoid_pubkeys,
                     size_t avoid_pubkeys_len) {
    if (!pubkey || !avoid_pubkeys || avoid_pubkeys_len == 0) {
        return false;
    }
    for (size_t i = 0; i < avoid_pubkeys_len; i++) {
        if (sol_pubkey_eq(pubkey, &avoid_pubkeys[i])) {
            return true;
        }
    }
    return false;
}

static bool
select_repair_peer_ex(sol_repair_t* repair,
                      sol_slot_t slot,
                      const sol_pubkey_t* avoid_pubkeys,
                      size_t avoid_pubkeys_len,
                      sol_sockaddr_t* peer,
                      sol_pubkey_t* peer_pubkey) {
    uint64_t now_ms = sol_gossip_now_ms();
    uint64_t sel_seq = __atomic_fetch_add(&repair->peer_select_counter, 1u, __ATOMIC_RELAXED);

    /* Prefer the slot leader when possible (best-effort). This reduces repair
     * timeouts by targeting a peer that is guaranteed to have produced the
     * shreds for the slot. */
    sol_leader_schedule_t* schedule =
        __atomic_load_n(&repair->leader_schedule, __ATOMIC_RELAXED);
    if (schedule && repair->gossip) {
        const sol_pubkey_t* leader = sol_leader_schedule_get_leader(schedule, slot);
        if (leader &&
            !sol_pubkey_is_zero(leader) &&
            !sol_pubkey_eq(leader, &repair->self_pubkey) &&
            (!avoid_pubkeys_len || !pubkey_in_avoid_list(leader, avoid_pubkeys, avoid_pubkeys_len))) {
            sol_crds_t* crds = sol_gossip_crds(repair->gossip);
            if (crds) {
                const sol_contact_info_t* ci = sol_crds_get_contact_info(crds, leader);
                if (ci) {
                    const sol_sockaddr_t* addr =
                        sol_contact_info_socket(ci, SOL_SOCKET_TAG_SERVE_REPAIR);
                    if (addr && sockaddr_is_public_ip(addr)) {
                        sol_sockaddr_copy(peer, addr);
                        if (peer_pubkey) {
                            sol_pubkey_copy(peer_pubkey, leader);
                        }
                        return true;
                    }
                }
            }
        }
    }

    /* Prefer the most recently successful peer for this slot (catchup hit-rate). */
    if (slot_peer_cache_get_locked(repair, slot, now_ms, peer, peer_pubkey)) {
        if (!peer_pubkey || !pubkey_in_avoid_list(peer_pubkey, avoid_pubkeys, avoid_pubkeys_len)) {
            return true;
        }
    }

    enum { SOL_REPAIR_CONTACTS_MAX = 2048 };

    /* Get peers from gossip */
    const sol_contact_info_t* contacts[SOL_REPAIR_CONTACTS_MAX];
    size_t num_contacts = 0;
    if (repair->gossip) {
        num_contacts = sol_gossip_get_cluster_nodes(repair->gossip, contacts, SOL_REPAIR_CONTACTS_MAX);
    }

    /* Filter to peers with a serve_repair socket.
     *
     * Prefer public addresses (mainnet requirement), but fall back to any
     * addresses if none are available. This keeps local/unit-test clusters
     * functional (e.g. 127.0.0.1) while still avoiding obvious timeouts on
     * mainnet. */
    const sol_contact_info_t* all_candidates[SOL_REPAIR_CONTACTS_MAX];
    size_t all_count = 0;
    const sol_contact_info_t* public_candidates[SOL_REPAIR_CONTACTS_MAX];
    size_t public_count = 0;
    for (size_t i = 0; i < num_contacts; i++) {
        const sol_sockaddr_t* addr =
            sol_contact_info_socket(contacts[i], SOL_SOCKET_TAG_SERVE_REPAIR);
        if (!addr) {
            continue;
        }
        if (memcmp(contacts[i]->pubkey.bytes, repair->self_pubkey.bytes, SOL_PUBKEY_SIZE) == 0) {
            continue;
        }
        if (all_count < SOL_REPAIR_CONTACTS_MAX) {
            all_candidates[all_count++] = contacts[i];
        }
        if (public_count < SOL_REPAIR_CONTACTS_MAX && sockaddr_is_public_ip(addr)) {
            public_candidates[public_count++] = contacts[i];
        }
    }

    const sol_contact_info_t** candidates = public_candidates;
    size_t candidate_count = public_count;
    if (candidate_count == 0) {
        candidates = all_candidates;
        candidate_count = all_count;
    }

    if (candidate_count == 0) {
        /* Fallback: use seeded peers, if configured. */
        pthread_mutex_lock(&repair->seed_peers_lock);
        size_t seed_count = repair->seed_peers_len;
        if (seed_count == 0 || !repair->seed_peers) {
            pthread_mutex_unlock(&repair->seed_peers_lock);
            return false;
        }

        size_t warm_idxs[100];
        size_t warm_count = 0;
        for (size_t i = 0; i < seed_count && warm_count < (sizeof(warm_idxs) / sizeof(warm_idxs[0])); i++) {
            if (is_peer_warm(repair, &repair->seed_peers[i].pubkey, now_ms)) {
                warm_idxs[warm_count++] = i;
            }
        }

        uint64_t seed = now_ms;
        seed ^= mix_u64((uint64_t)slot + 0x9e3779b97f4a7c15ULL);
        seed ^= mix_u64(sel_seq + ((uint64_t)repair->pending_count << 17));
        seed ^= seed >> 33;
        seed *= 0xff51afd7ed558ccdULL;
        seed ^= seed >> 33;

        bool choose_warm = warm_count > 0;
        if (choose_warm && seed_count > warm_count) {
            /* Avoid getting stuck on a single warm peer: occasionally sample
             * the full peer list. */
            choose_warm = (seed % 10) != 0; /* ~90% warm, ~10% any */
        }

        const size_t* idxs = choose_warm ? warm_idxs : NULL;
        size_t idxs_len = choose_warm ? warm_count : seed_count;
        size_t idx = choose_warm ? idxs[(size_t)(seed % warm_count)]
                                 : (size_t)(seed % seed_count);

        /* Scan for a peer not in avoid list. */
        for (size_t attempt = 0; attempt < idxs_len; attempt++) {
            size_t cand = choose_warm ? idxs[(idx + attempt) % idxs_len]
                                      : (idx + attempt) % seed_count;
            if (avoid_pubkeys_len &&
                pubkey_in_avoid_list(&repair->seed_peers[cand].pubkey, avoid_pubkeys, avoid_pubkeys_len)) {
                continue;
            }
            sol_sockaddr_copy(peer, &repair->seed_peers[cand].serve_repair_addr);
            if (peer_pubkey) {
                sol_pubkey_copy(peer_pubkey, &repair->seed_peers[cand].pubkey);
            }
            pthread_mutex_unlock(&repair->seed_peers_lock);
            return true;
        }

        pthread_mutex_unlock(&repair->seed_peers_lock);
        return false;
    }

    /* Prefer peers that have pinged us recently (ping-cache gating). */
    const sol_contact_info_t* warm_candidates[SOL_REPAIR_CONTACTS_MAX];
    size_t warm_count = 0;
    for (size_t i = 0; i < candidate_count; i++) {
        if (is_peer_warm(repair, &candidates[i]->pubkey, now_ms)) {
            warm_candidates[warm_count++] = candidates[i];
        }
    }

    uint64_t seed = now_ms;
    seed ^= mix_u64((uint64_t)slot + 0x9e3779b97f4a7c15ULL);
    seed ^= mix_u64(sel_seq + ((uint64_t)repair->pending_count << 17));
    seed ^= seed >> 33;
    seed *= 0xff51afd7ed558ccdULL;
    seed ^= seed >> 33;

    if (warm_count) {
        /* Prefer warm peers most of the time, including during hedged retries.
         * Avoid-lists naturally exclude already-tried peers, so still allow
         * some cold sampling while keeping bias toward responsive peers. */
        uint64_t warm_mod = avoid_pubkeys_len ? 3u : 10u; /* ~67% warm on retry, ~90% warm initially */
        bool choose_warm = (candidate_count == warm_count);
        if (!choose_warm) {
            choose_warm = (seed % warm_mod) != 0;
        }
        if (choose_warm) {
            candidates = warm_candidates;
            candidate_count = warm_count;
        }
    }

    size_t idx = (size_t)(seed % candidate_count);
    for (size_t attempt = 0; attempt < candidate_count; attempt++) {
        const sol_contact_info_t* chosen = candidates[(idx + attempt) % candidate_count];
        if (avoid_pubkeys_len &&
            pubkey_in_avoid_list(&chosen->pubkey, avoid_pubkeys, avoid_pubkeys_len)) {
            continue;
        }
        const sol_sockaddr_t* addr = sol_contact_info_socket(chosen, SOL_SOCKET_TAG_SERVE_REPAIR);
        if (!addr) {
            continue;
        }
        sol_sockaddr_copy(peer, addr);
        if (peer_pubkey) {
            sol_pubkey_copy(peer_pubkey, &chosen->pubkey);
        }
        return true;
    }

    return false;
}

static bool
select_repair_peer(sol_repair_t* repair,
                   sol_slot_t slot,
                   const sol_pubkey_t* avoid_pubkey,
                   sol_sockaddr_t* peer,
                   sol_pubkey_t* peer_pubkey) {
    if (avoid_pubkey) {
        return select_repair_peer_ex(repair, slot, avoid_pubkey, 1u, peer, peer_pubkey);
    }
    return select_repair_peer_ex(repair, slot, NULL, 0u, peer, peer_pubkey);
}

/*
 * Send a repair request
 */
/* pending_lock must be held by caller */
static uint32_t
ensure_nonce_tracked_locked(sol_repair_t* repair, sol_repair_pending_t* pending) {
    if (!repair || !pending) {
        return 0;
    }

    /* RepairRequestHeader.nonce (u32) */
    if (pending->nonce == 0) {
        repair->nonce_counter++;
        if (repair->nonce_counter == 0) {
            repair->nonce_counter = 1;
        }
        pending->nonce = repair->nonce_counter;
    }

    if (pending_ptr_is_tracked(repair, pending)) {
        int32_t pending_idx = (int32_t)(pending - repair->pending);
        nonce_map_put_locked(repair, pending->nonce, pending_idx);
    }

    return pending->nonce;
}

static sol_err_t
send_repair_request_unlocked(sol_repair_t* repair,
                             sol_repair_type_t type,
                             sol_slot_t slot,
                             uint64_t shred_index,
                             uint32_t nonce,
                             const sol_pubkey_t* peer_pubkey,
                             const sol_sockaddr_t* peer) {
    if (!repair || !peer_pubkey || !peer) {
        return SOL_ERR_INVAL;
    }
    if (nonce == 0) {
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
    switch (type) {
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
    memcpy(buf + len, peer_pubkey->bytes, SOL_PUBKEY_SIZE);
    len += SOL_PUBKEY_SIZE;

    /* RepairRequestHeader.timestamp (ms since UNIX epoch) */
    uint64_t timestamp_ms = sol_unix_now_ms();
    sol_store_u64_le(buf + len, timestamp_ms);
    len += 8;

    /* RepairRequestHeader.nonce (u32) */
    sol_store_u32_le(buf + len, nonce);
    len += 4;

    /* Variant fields */
    switch (type) {
    case SOL_REPAIR_SHRED:
    case SOL_REPAIR_HIGHEST_SHRED:
        sol_store_u64_le(buf + len, (uint64_t)slot);
        len += 8;
        sol_store_u64_le(buf + len, shred_index);
        len += 8;
        break;
    case SOL_REPAIR_ORPHAN:
    case SOL_REPAIR_ANCESTOR_HASHES:
        sol_store_u64_le(buf + len, (uint64_t)slot);
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
    sol_err_t err = sol_udp_send(repair->repair_sock, buf, len, peer);
    if (err == SOL_OK) {
        (void)__atomic_fetch_add(&repair->stats.requests_sent, 1u, __ATOMIC_RELAXED);
        static uint32_t req_log_budget = 32;
        if (req_log_budget > 0) {
            char addr_str[64] = {0};
            if (sol_sockaddr_to_string(peer, addr_str, sizeof(addr_str)) == SOL_OK) {
                sol_log_debug("Repair request sent: type=%s slot=%llu index=%llu nonce=%u to=%s",
                              sol_repair_type_name(type),
                              (unsigned long long)slot,
                              (unsigned long long)shred_index,
                              (unsigned)nonce,
                              addr_str);
            } else {
                sol_log_debug("Repair request sent: type=%s slot=%llu index=%llu nonce=%u",
                              sol_repair_type_name(type),
                              (unsigned long long)slot,
                              (unsigned long long)shred_index,
                              (unsigned)nonce);
            }
            req_log_budget--;
        }
        sol_log_trace("Sent repair request: type=%s slot=%llu index=%llu nonce=%u",
                      sol_repair_type_name(type),
                      (unsigned long long)slot,
                      (unsigned long long)shred_index,
                      (unsigned)nonce);
    }

    return err;
}

static sol_err_t
send_repair_request_unlocked_pending(sol_repair_t* repair, const sol_repair_pending_t* pending) {
    if (!repair || !pending) return SOL_ERR_INVAL;
    return send_repair_request_unlocked(repair,
                                        pending->type,
                                        pending->slot,
                                        pending->shred_index,
                                        pending->nonce,
                                        &pending->peer_pubkey,
                                        &pending->peer);
}

static inline bool
repair_periodic_hedge_enabled(uint32_t fanout) {
    /* Moderate fanout still benefits from periodic bursts under catchup.
     * Restrict one-per-retry behavior to very low fanout to avoid starving
     * replay-critical tail shreds. */
    return fanout >= 8u;
}

static inline uint64_t
repair_periodic_hedge_interval_ms(uint32_t fanout) {
    /* Larger fanout should resend more frequently because each burst can fan
     * out across many peers without increasing tracked pending entries. */
    if (fanout >= 48u) return 2u;
    if (fanout >= 32u) return 3u;
    if (fanout >= 16u) return 4u;
    return 8u;
}

/*
 * Process timeout for pending requests
 */
static void
process_timeouts(sol_repair_t* repair) {
    uint64_t now = sol_gossip_now_ms();

    typedef struct {
        sol_repair_type_t type;
        sol_slot_t        slot;
        uint64_t          shred_index;
        uint32_t          nonce;
        sol_sockaddr_t    peer;
        sol_pubkey_t      peer_pubkey;
    } sol_repair_send_action_t;

    /* Under heavy catchup, many requests can timeout at once. If this buffer is
     * too small, we risk "retrying" a request (updating sent_time/retries) but
     * not actually sending it, which stalls repair. Keep this large enough to
     * make forward progress per timeout scan. */
    enum { SOL_REPAIR_TIMEOUT_SEND_MAX = 32768 };
    sol_repair_send_action_t actions[SOL_REPAIR_TIMEOUT_SEND_MAX];
    size_t action_len = 0;

    pthread_mutex_lock(&repair->pending_lock);

    for (size_t i = 0; i < repair->config.max_pending_requests; i++) {
        sol_repair_pending_t* p = &repair->pending[i];
        if (!p->active) continue;

        if (now - p->sent_time >= repair->config.request_timeout_ms) {
            /* If we cannot enqueue a send action, do not mutate the pending
             * entry. Otherwise we would delay the request by an additional
             * timeout interval without ever sending. */
            if (action_len >= SOL_REPAIR_TIMEOUT_SEND_MAX) {
                break;
            }

            (void)__atomic_fetch_add(&repair->stats.timeouts, 1u, __ATOMIC_RELAXED);

            if (p->retries < repair->config.max_retries) {
                /* Retry */
                /* Try a different peer; if we can't find one, resend to the
                 * existing peer rather than stalling. */
                sol_pubkey_t prev = p->peer_pubkey;
                sol_sockaddr_t new_peer = p->peer;
                sol_pubkey_t new_peer_pubkey = p->peer_pubkey;
                if (select_repair_peer(repair, p->slot, &prev, &new_peer, &new_peer_pubkey)) {
                    p->peer = new_peer;
                    p->peer_pubkey = new_peer_pubkey;
                }

                p->retries++;
                p->sent_time = now;
                (void)ensure_nonce_tracked_locked(repair, p);
                actions[action_len++] = (sol_repair_send_action_t){
                    .type = p->type,
                    .slot = p->slot,
                    .shred_index = p->shred_index,
                    .nonce = p->nonce,
                    .peer = p->peer,
                    .peer_pubkey = p->peer_pubkey,
                };
            } else {
                /* Give up */
                pending_deactivate_locked(repair, p);
            }
        }
    }

    pthread_mutex_unlock(&repair->pending_lock);

    for (size_t i = 0; i < action_len; i++) {
        (void)send_repair_request_unlocked(repair,
                                           actions[i].type,
                                           actions[i].slot,
                                           actions[i].shred_index,
                                           actions[i].nonce,
                                           &actions[i].peer_pubkey,
                                           &actions[i].peer);
    }
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

    sol_repair_pending_t snap;
    bool have_snap = false;
    if (best) {
        best->sent_time = now_ms;
        if (best->retries < repair->config.max_retries) {
            best->retries++;
        }
        (void)ensure_nonce_tracked_locked(repair, best);
        snap = *best;
        have_snap = true;
    }
    pthread_mutex_unlock(&repair->pending_lock);

    if (have_snap) {
        (void)send_repair_request_unlocked_pending(repair, &snap);
    }

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
    int32_t idx = nonce_map_get_locked(repair, nonce);
    if (idx >= 0 && (size_t)idx < repair->config.max_pending_requests) {
        sol_repair_pending_t* p = &repair->pending[idx];
        if (p->active && p->nonce == nonce) {
            return p;
        }
    }

    /* Fast path miss: avoid O(n) scans on the response hot path when the
     * nonce map is available. The map is sized for `max_pending_requests*32`
     * and should have stable hit-rate; linear scans here are catastrophic
     * under mainnet repair response rates. */
    if (repair->nonce_map_size != 0 && repair->nonce_vals && repair->nonce_keys) {
        return NULL;
    }

    /* Fallback: linear scan (map is best-effort and may be disabled). */
    for (size_t i = 0; i < repair->config.max_pending_requests; i++) {
        sol_repair_pending_t* p = &repair->pending[i];
        if (p->active && p->nonce == nonce) {
            return p;
        }
    }
    return NULL;
}

/* pending_lock must be held by caller */
static void
pending_deactivate_locked(sol_repair_t* repair, sol_repair_pending_t* pending) {
    if (!repair || !pending || !pending->active) {
        return;
    }
    if (pending->type == SOL_REPAIR_ANCESTOR_HASHES) {
        uint32_t cur = __atomic_load_n(&repair->ancestor_pending_count, __ATOMIC_RELAXED);
        if (cur > 0u) {
            (void)__atomic_fetch_sub(&repair->ancestor_pending_count, 1u, __ATOMIC_RELAXED);
        }
    }
    req_map_del_locked(repair, pending->type, pending->slot, pending->shred_index);
    nonce_map_del_locked(repair, pending->nonce);
    pending->active = false;
    if (pending_ptr_is_tracked(repair, pending)) {
        size_t idx = (size_t)(pending - repair->pending);
        if (idx < repair->config.max_pending_requests) {
            repair->pending_scan_cursor = idx;
        }
    }
    if (repair->pending_count > 0) {
        repair->pending_count--;
    }
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
        (void)__atomic_fetch_add(&repair->stats.invalid_responses, 1u, __ATOMIC_RELAXED);
        return;
    }

    uint32_t disc = sol_load_u32_le(data);
    if (disc != 0) {
        (void)__atomic_fetch_add(&repair->stats.invalid_responses, 1u, __ATOMIC_RELAXED);
        return;
    }

    uint64_t vec_len = sol_load_u64_le(data + 4);
    if (vec_len > SOL_REPAIR_MAX_ANCESTOR_HASHES) {
        (void)__atomic_fetch_add(&repair->stats.invalid_responses, 1u, __ATOMIC_RELAXED);
        return;
    }

    size_t expected = 4 + 8 + (size_t)vec_len * (8 + SOL_SHA256_HASH_SIZE);

    uint32_t resp_nonce = 0;
    if (len == expected + 4) {
        resp_nonce = sol_load_u32_le(data + expected);
        len = expected;
    } else if (len != expected) {
        (void)__atomic_fetch_add(&repair->stats.invalid_responses, 1u, __ATOMIC_RELAXED);
        return;
    }

    sol_repair_pending_t* pending = NULL;
    sol_slot_t requested_slot = 0;
    pthread_mutex_lock(&repair->pending_lock);
    pending = find_pending_by_nonce_locked(repair, resp_nonce);
    if (pending && pending->type == SOL_REPAIR_ANCESTOR_HASHES) {
        requested_slot = pending->slot;
        pending_deactivate_locked(repair, pending);
    } else {
        pending = NULL;
    }
    pthread_mutex_unlock(&repair->pending_lock);

    if (!pending) {
        (void)__atomic_fetch_add(&repair->stats.duplicates, 1u, __ATOMIC_RELAXED);
        return;
    }

    sol_repair_ancestor_response_t response;
    memset(&response, 0, sizeof(response));
    response.requested_slot = requested_slot;

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
        (void)__atomic_fetch_add(&repair->stats.invalid_responses, 1u, __ATOMIC_RELAXED);
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
    (void)__atomic_fetch_add(&repair->stats.responses_received, 1u, __ATOMIC_RELAXED);

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
                (void)__atomic_fetch_add(&repair->stats.invalid_responses, 1u, __ATOMIC_RELAXED);
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
    bool have_ancestor_pending =
        (__atomic_load_n(&repair->ancestor_pending_count, __ATOMIC_RELAXED) > 0u);

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
        (void)__atomic_fetch_add(&repair->stats.invalid_responses, 1u, __ATOMIC_RELAXED);
        return;
    }

    bool shred_is_data = (shred.type == SOL_SHRED_TYPE_DATA);

    /* Find and complete pending request */
    pthread_mutex_lock(&repair->pending_lock);

    /* Some peers send raw shreds with a trailing nonce(u32) used to match the
     * original request. Only treat the tail as a nonce when it extends the
     * canonical shred wire size; otherwise we'd waste time looking up random
     * payload bytes in the pending map (and potentially do O(n) fallbacks). */
    if (!used_wrapper && len == (size_t)shred.raw_len + 4u) {
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

            /* RepairProtocol::WindowIndex does not encode shred type on the wire.
             * Some peers may respond with a coding shred for the requested index.
             * Track the response for FEC recovery, but do not treat it as
             * satisfying a pending *data* shred request. */
            if (match && by_nonce->type == SOL_REPAIR_SHRED) {
                if (by_nonce->is_data != shred_is_data) {
                    match = false;
                    static uint32_t type_mismatch_budget = 32;
                    if (type_mismatch_budget > 0) {
                        sol_log_debug("Repair response shred-type mismatch: nonce=%u slot=%llu index=%u expected=%s got=%s",
                                      (unsigned)resp_nonce,
                                      (unsigned long long)shred.slot,
                                      (unsigned)shred.index,
                                      by_nonce->is_data ? "data" : "code",
                                      shred_is_data ? "data" : "code");
                        type_mismatch_budget--;
                    }
                }
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
    /* Fallback: match by slot/index (SHRED) or slot-only (HIGHEST/ORPHAN).
     *
     * This used to be O(n) across the pending table. With the request map, it
     * is O(1) and also acts as a correctness backstop if some peers do not
     * include a nonce trailer or if the nonce map becomes temporarily
     * ineffective under sustained churn. */
    if (!pending) {
        pending = find_pending(repair, SOL_REPAIR_SHRED, shred.slot, shred.index);
    }
    if (!pending) {
        /* Highest/orphan requests are satisfied by any shred for the slot. */
        pending = find_pending_slot_only(repair, SOL_REPAIR_HIGHEST_SHRED, shred.slot);
    }
    if (!pending) {
        pending = find_pending_slot_only(repair, SOL_REPAIR_ORPHAN, shred.slot);
    }

    bool pending_satisfied = false;
    if (pending) {
        /* Treat any valid response as a "warm" signal for ping-cache gating. */
        mark_peer_warm(repair, &pending->peer_pubkey);

        bool type_mismatch = false;
        if (pending->type == SOL_REPAIR_SHRED) {
            type_mismatch = (pending->is_data != shred_is_data);
        }

        /* WindowIndex responses are keyed by slot/index, but peers may return
         * either data or coding shreds for that index. Keep type mismatch as a
         * diagnostic signal, but always clear the pending request so catchup can
         * continue issuing fresh fanout requests for the remaining gap. */
        uint64_t now_ms = sol_gossip_now_ms();
        slot_peer_cache_update_locked(repair, shred.slot, &pending->peer, &pending->peer_pubkey, now_ms);
        pending_deactivate_locked(repair, pending);
        pending_satisfied = true;
        if (!type_mismatch) {
            (void)__atomic_fetch_add(&repair->stats.shreds_repaired, 1u, __ATOMIC_RELAXED);
        } else {
            (void)__atomic_fetch_add(&repair->stats.duplicates, 1u, __ATOMIC_RELAXED);
        }
    } else {
        (void)__atomic_fetch_add(&repair->stats.duplicates, 1u, __ATOMIC_RELAXED);
    }

    pthread_mutex_unlock(&repair->pending_lock);

    sol_log_debug("Repair response shred slot=%llu index=%u len=%zu wrapped=%s nonce=%u pending=%s%s",
                  (unsigned long long)shred.slot,
                  (unsigned)shred.index,
                  shred_len,
                  used_wrapper ? "yes" : "no",
                  (unsigned)resp_nonce,
                  pending_satisfied ? "hit" : "miss",
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
            (void)__atomic_fetch_add(&repair->stats.responses_received, 1u, __ATOMIC_RELAXED);  /* Reusing this for responses sent */
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
    repair->pending_scan_cursor = 0;

    /* Allocate pending requests */
    repair->pending = sol_calloc(
        repair->config.max_pending_requests,
        sizeof(sol_repair_pending_t));
    if (!repair->pending) {
        sol_free(repair);
        return NULL;
    }

    /* Allocate nonce -> pending lookup table (best-effort fast-path).
     *
     * Note: open-addressing tables with tombstones degrade under sustained
     * churn (timeout/retry heavy catchup). We intentionally oversize the table
     * so we keep plenty of true empty slots (-1) for fast negative lookups. */
    repair->nonce_map_size = pow2_ge((size_t)repair->config.max_pending_requests * 32u);
    if (repair->nonce_map_size < 64u) {
        repair->nonce_map_size = 64u;
    }
    repair->nonce_keys = sol_calloc(repair->nonce_map_size, sizeof(uint32_t));
    repair->nonce_vals = sol_alloc(repair->nonce_map_size * sizeof(int32_t));
    if (!repair->nonce_keys || !repair->nonce_vals) {
        sol_free(repair->nonce_keys);
        sol_free(repair->nonce_vals);
        sol_free(repair->pending);
        sol_free(repair);
        return NULL;
    }
    for (size_t i = 0; i < repair->nonce_map_size; i++) {
        repair->nonce_vals[i] = -1;
    }

    /* Allocate (type,slot,index)->pending lookup table for request dedupe. */
    repair->req_map_size = pow2_ge((size_t)repair->config.max_pending_requests * 32u);
    if (repair->req_map_size < 64u) {
        repair->req_map_size = 64u;
    }
    repair->req_slots = sol_calloc(repair->req_map_size, sizeof(uint64_t));
    repair->req_indices = sol_calloc(repair->req_map_size, sizeof(uint64_t));
    repair->req_types = sol_calloc(repair->req_map_size, sizeof(uint8_t));
    repair->req_vals = sol_alloc(repair->req_map_size * sizeof(int32_t));
    if (!repair->req_slots || !repair->req_indices || !repair->req_types || !repair->req_vals) {
        sol_free(repair->req_slots);
        sol_free(repair->req_indices);
        sol_free(repair->req_types);
        sol_free(repair->req_vals);
        sol_free(repair->nonce_keys);
        sol_free(repair->nonce_vals);
        sol_free(repair->pending);
        sol_free(repair);
        return NULL;
    }
    for (size_t i = 0; i < repair->req_map_size; i++) {
        repair->req_vals[i] = -1;
    }

    if (pthread_mutex_init(&repair->pending_lock, NULL) != 0) {
        sol_free(repair->req_slots);
        sol_free(repair->req_indices);
        sol_free(repair->req_types);
        sol_free(repair->req_vals);
        sol_free(repair->nonce_keys);
        sol_free(repair->nonce_vals);
        sol_free(repair->pending);
        sol_free(repair);
        return NULL;
    }

    if (pthread_mutex_init(&repair->seed_peers_lock, NULL) != 0) {
        pthread_mutex_destroy(&repair->pending_lock);
        sol_free(repair->req_slots);
        sol_free(repair->req_indices);
        sol_free(repair->req_types);
        sol_free(repair->req_vals);
        sol_free(repair->nonce_keys);
        sol_free(repair->nonce_vals);
        sol_free(repair->pending);
        sol_free(repair);
        return NULL;
    }

    if (pthread_mutex_init(&repair->warm_peers_lock, NULL) != 0) {
        pthread_mutex_destroy(&repair->seed_peers_lock);
        pthread_mutex_destroy(&repair->pending_lock);
        sol_free(repair->req_slots);
        sol_free(repair->req_indices);
        sol_free(repair->req_types);
        sol_free(repair->req_vals);
        sol_free(repair->nonce_keys);
        sol_free(repair->nonce_vals);
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
    sol_free(repair->req_slots);
    sol_free(repair->req_indices);
    sol_free(repair->req_types);
    sol_free(repair->req_vals);
    sol_free(repair->nonce_keys);
    sol_free(repair->nonce_vals);
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
    /* Repair traffic can be bursty during catchup; prefer larger kernel
     * buffers to reduce response drops under load. */
    udp_cfg.recv_buf = 128u * 1024u * 1024u;
    udp_cfg.send_buf = 128u * 1024u * 1024u;

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
    enum { SOL_REPAIR_RECV_BUDGET = 65536 };
    {
        size_t received = 0;
        sol_udp_pkt_t pkts[SOL_NET_BATCH_SIZE];
        while (received < SOL_REPAIR_RECV_BUDGET) {
            int n = sol_udp_recv_batch(repair->repair_sock, pkts, SOL_NET_BATCH_SIZE);
            if (n < 0) {
                break;
            }
            if (n == 0) {
                break;
            }
            received += (size_t)n;
            for (int i = 0; i < n; i++) {
                process_response(repair, pkts[i].data, pkts[i].len, &pkts[i].addr);
            }
        }
    }

    /* Drain serve socket (requests). */
    if (repair->serve_sock) {
        size_t received = 0;
        sol_udp_pkt_t pkts[SOL_NET_BATCH_SIZE];
        while (received < SOL_REPAIR_RECV_BUDGET) {
            int n = sol_udp_recv_batch(repair->serve_sock, pkts, SOL_NET_BATCH_SIZE);
            if (n < 0) {
                break;
            }
            if (n == 0) {
                break;
            }
            received += (size_t)n;
            for (int i = 0; i < n; i++) {
                process_request(repair, pkts[i].data, pkts[i].len, &pkts[i].addr);
            }
        }
    }

    /* Process timeouts (throttled). */
    uint64_t now_ms = sol_gossip_now_ms();
    size_t pending_count = sol_repair_pending_count(repair);
    /* When pending is large, retries must be driven frequently to avoid
     * multi-second stalls on a small number of missing shreds. */
    uint64_t interval_ms = (uint64_t)SOL_REPAIR_TIMEOUT_CHECK_MIN_INTERVAL_MS;
    if (pending_count > 0u && pending_count <= 256u) {
        /* Last-gap catchup is extremely sensitive to timeout scan cadence. */
        interval_ms = 1u;
    }
    if (pending_count > 0 &&
        (repair->last_timeout_check_ms == 0 || (now_ms - repair->last_timeout_check_ms) >= interval_ms)) {
        repair->last_timeout_check_ms = now_ms;
        process_timeouts(repair);
    }

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

    sol_repair_pending_t snap;
    sol_repair_pending_t* tracked = NULL;

    pthread_mutex_lock(&repair->pending_lock);

    /* Check if already pending */
    if (find_pending(repair, SOL_REPAIR_SHRED, slot, shred_index)) {
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
    if (!select_repair_peer(repair, slot, NULL, &pending->peer, &pending->peer_pubkey)) {
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
    pending->hedge_retry_mark = UINT32_MAX;
    pending->last_hedge_sent_time = 0;
    pending->active = true;
    repair->pending_count++;

    (void)ensure_nonce_tracked_locked(repair, pending);
    req_map_put_locked(repair, pending->type, pending->slot, pending->shred_index, (int32_t)(pending - repair->pending));
    snap = *pending;
    tracked = pending;

    pthread_mutex_unlock(&repair->pending_lock);

    /* Send outside pending_lock to avoid blocking response processing. */
    sol_err_t err = send_repair_request_unlocked_pending(repair, &snap);
    if (err != SOL_OK && tracked) {
        pthread_mutex_lock(&repair->pending_lock);
        if (tracked->active && tracked->nonce == snap.nonce) {
            pending_deactivate_locked(repair, tracked);
        }
        pthread_mutex_unlock(&repair->pending_lock);
    }

    return err;
}

sol_err_t
sol_repair_request_shred_fanout(sol_repair_t* repair, sol_slot_t slot,
                                uint64_t shred_index, bool is_data, uint32_t fanout) {
    if (!repair) return SOL_ERR_INVAL;

    if (fanout <= 1u) {
        return sol_repair_request_shred(repair, slot, shred_index, is_data);
    }

    /* Cap to keep stack bounded and avoid accidental misuse. */
    if (fanout > (uint32_t)SOL_REPAIR_MAX_FANOUT) {
        fanout = (uint32_t)SOL_REPAIR_MAX_FANOUT;
    }

    enum {
        /* Keep first hedge fast, but avoid flooding duplicate responses. */
        SOL_REPAIR_HEDGE_DELAY_MS = 3,
    };

    uint64_t now_ms = sol_gossip_now_ms();
    bool created = false;

    sol_repair_pending_t primary_snap;
    bool send_primary = false;
    sol_repair_pending_t* tracked = NULL;
    sol_repair_pending_t hedges[SOL_REPAIR_MAX_FANOUT];
    size_t hedge_len = 0;

    pthread_mutex_lock(&repair->pending_lock);

    sol_repair_pending_t* pending = find_pending(repair, SOL_REPAIR_SHRED, slot, shred_index);
    if (!pending) {
        /* Create the primary tracked request first. */
        pending = find_pending_slot(repair, SOL_REPAIR_SHRED);
        if (!pending) {
            pthread_mutex_unlock(&repair->pending_lock);
            return SOL_ERR_FULL;
        }

        if (!select_repair_peer_ex(repair, slot, NULL, 0u, &pending->peer, &pending->peer_pubkey)) {
            pthread_mutex_unlock(&repair->pending_lock);
            return SOL_ERR_PEER_UNAVAILABLE;
        }

        pending->type = SOL_REPAIR_SHRED;
        pending->slot = slot;
        pending->shred_index = shred_index;
        pending->is_data = is_data;
        pending->nonce = 0;
        pending->sent_time = now_ms;
        pending->retries = 0;
        pending->hedge_retry_mark = UINT32_MAX;
        pending->last_hedge_sent_time = 0;
        pending->active = true;
        repair->pending_count++;

        (void)ensure_nonce_tracked_locked(repair, pending);
        req_map_put_locked(repair, pending->type, pending->slot, pending->shred_index, (int32_t)(pending - repair->pending));
        primary_snap = *pending;
        tracked = pending;
        send_primary = true;

        created = true;
        /* Refresh our local clock for gating, but do not mutate pending->sent_time again. */
        now_ms = sol_gossip_now_ms();
    }

    if (!pending->active || pending->type != SOL_REPAIR_SHRED) {
        pthread_mutex_unlock(&repair->pending_lock);
        return SOL_OK;
    }

    (void)ensure_nonce_tracked_locked(repair, pending);

    if (!created) {
        uint64_t since_send_ms =
            (now_ms >= pending->sent_time) ? (now_ms - pending->sent_time) : 0u;
        uint64_t since_hedge_ms =
            (pending->last_hedge_sent_time != 0u && now_ms >= pending->last_hedge_sent_time)
                ? (now_ms - pending->last_hedge_sent_time)
                : UINT64_MAX;
        bool periodic_hedge = repair_periodic_hedge_enabled(fanout);
        uint64_t burst_interval_ms = repair_periodic_hedge_interval_ms(fanout);

        /* Low fanout mode: hedge once per retry.
         *
         * Periodic mode: allow bounded hedge bursts within a retry window to
         * reduce tail latency on replay-critical missing shreds. */
        if (!periodic_hedge && pending->hedge_retry_mark == pending->retries) {
            pthread_mutex_unlock(&repair->pending_lock);
            return SOL_OK;
        }
        if (since_send_ms < SOL_REPAIR_HEDGE_DELAY_MS) {
            pthread_mutex_unlock(&repair->pending_lock);
            return SOL_OK;
        }
        if (periodic_hedge && since_hedge_ms < burst_interval_ms) {
            pthread_mutex_unlock(&repair->pending_lock);
            return SOL_OK;
        }
    }

    sol_pubkey_t avoid[SOL_REPAIR_MAX_FANOUT];
    size_t avoid_len = 0;
    avoid[avoid_len++] = pending->peer_pubkey;

    /* Best-effort: send additional copies with the same nonce. We don't create
     * additional pending entries; responses will still match by nonce. */
    for (uint32_t i = 1;
         i < fanout && avoid_len < (sizeof(avoid) / sizeof(avoid[0])) && hedge_len < (sizeof(hedges) / sizeof(hedges[0]));
         i++) {
        sol_sockaddr_t peer;
        sol_pubkey_t peer_pk;
        if (!select_repair_peer_ex(repair, slot, avoid, avoid_len, &peer, &peer_pk)) {
            break;
        }
        avoid[avoid_len++] = peer_pk;

        sol_repair_pending_t tmp = *pending;
        tmp.peer = peer;
        tmp.peer_pubkey = peer_pk;
        tmp.is_data = is_data;
        tmp.nonce = pending->nonce;

        hedges[hedge_len++] = tmp;
    }

    pending->hedge_retry_mark = pending->retries;
    pending->last_hedge_sent_time = now_ms;
    pthread_mutex_unlock(&repair->pending_lock);

    if (send_primary) {
        sol_err_t err = send_repair_request_unlocked_pending(repair, &primary_snap);
        if (err != SOL_OK && tracked) {
            pthread_mutex_lock(&repair->pending_lock);
            if (tracked->active && tracked->nonce == primary_snap.nonce) {
                pending_deactivate_locked(repair, tracked);
            }
            pthread_mutex_unlock(&repair->pending_lock);
            return err;
        }
    }

    for (size_t i = 0; i < hedge_len; i++) {
        (void)send_repair_request_unlocked_pending(repair, &hedges[i]);
    }

    return SOL_OK;
}

sol_err_t
sol_repair_request_highest_fanout(sol_repair_t* repair, sol_slot_t slot,
                                  uint64_t shred_index, uint32_t fanout) {
    if (!repair) return SOL_ERR_INVAL;

    if (fanout <= 1u) {
        return sol_repair_request_highest(repair, slot, shred_index);
    }

    /* Cap to keep stack bounded and avoid accidental misuse. */
    if (fanout > (uint32_t)SOL_REPAIR_MAX_FANOUT) {
        fanout = (uint32_t)SOL_REPAIR_MAX_FANOUT;
    }

    enum {
        /* Keep first hedge fast, but avoid flooding duplicate responses. */
        SOL_REPAIR_HEDGE_DELAY_MS = 3,
    };

    uint64_t now_ms = sol_gossip_now_ms();
    bool created = false;
    bool index_advanced = false;

    sol_repair_pending_t primary_snap;
    bool send_primary = false;
    sol_repair_pending_t* tracked = NULL;
    sol_repair_pending_t hedges[SOL_REPAIR_MAX_FANOUT];
    size_t hedge_len = 0;

    pthread_mutex_lock(&repair->pending_lock);

    sol_repair_pending_t* pending = find_pending_slot_only(repair, SOL_REPAIR_HIGHEST_SHRED, slot);

    if (!pending) {
        pending = find_pending_slot(repair, SOL_REPAIR_HIGHEST_SHRED);
        if (!pending) {
            pthread_mutex_unlock(&repair->pending_lock);
            return SOL_ERR_FULL;
        }

        if (!select_repair_peer_ex(repair, slot, NULL, 0u, &pending->peer, &pending->peer_pubkey)) {
            pthread_mutex_unlock(&repair->pending_lock);
            return SOL_ERR_PEER_UNAVAILABLE;
        }

        pending->type = SOL_REPAIR_HIGHEST_SHRED;
        pending->slot = slot;
        pending->shred_index = shred_index;
        pending->nonce = 0;
        pending->sent_time = now_ms;
        pending->retries = 0;
        pending->hedge_retry_mark = UINT32_MAX;
        pending->last_hedge_sent_time = 0;
        pending->active = true;
        repair->pending_count++;

        (void)ensure_nonce_tracked_locked(repair, pending);
        req_map_put_locked(repair, pending->type, pending->slot, pending->shred_index, (int32_t)(pending - repair->pending));
        primary_snap = *pending;
        tracked = pending;
        send_primary = true;

        created = true;
        now_ms = sol_gossip_now_ms();
    } else if (shred_index > pending->shred_index) {
        /* Keep HighestWindowIndex requests moving forward as slot metadata
         * advances. Reusing a stale lower index can repeatedly return already
         * known shreds and stall catchup on tail gaps. */
        pending->shred_index = shred_index;
        pending->sent_time = now_ms;
        pending->hedge_retry_mark = UINT32_MAX;
        pending->last_hedge_sent_time = 0;
        primary_snap = *pending;
        tracked = pending;
        send_primary = true;
        index_advanced = true;
    }

    if (!pending->active || pending->type != SOL_REPAIR_HIGHEST_SHRED) {
        pthread_mutex_unlock(&repair->pending_lock);
        return SOL_OK;
    }

    (void)ensure_nonce_tracked_locked(repair, pending);

    if (!created && !index_advanced) {
        uint64_t since_send_ms =
            (now_ms >= pending->sent_time) ? (now_ms - pending->sent_time) : 0u;
        uint64_t since_hedge_ms =
            (pending->last_hedge_sent_time != 0u && now_ms >= pending->last_hedge_sent_time)
                ? (now_ms - pending->last_hedge_sent_time)
                : UINT64_MAX;
        bool periodic_hedge = repair_periodic_hedge_enabled(fanout);
        uint64_t burst_interval_ms = repair_periodic_hedge_interval_ms(fanout);

        if (!periodic_hedge && pending->hedge_retry_mark == pending->retries) {
            pthread_mutex_unlock(&repair->pending_lock);
            return SOL_OK;
        }
        if (since_send_ms < SOL_REPAIR_HEDGE_DELAY_MS) {
            pthread_mutex_unlock(&repair->pending_lock);
            return SOL_OK;
        }
        if (periodic_hedge && since_hedge_ms < burst_interval_ms) {
            pthread_mutex_unlock(&repair->pending_lock);
            return SOL_OK;
        }
    }

    sol_pubkey_t avoid[SOL_REPAIR_MAX_FANOUT];
    size_t avoid_len = 0;
    avoid[avoid_len++] = pending->peer_pubkey;

    /* Best-effort: send additional copies with the same nonce. We don't create
     * additional pending entries; responses will still match by nonce. */
    for (uint32_t i = 1;
         i < fanout && avoid_len < (sizeof(avoid) / sizeof(avoid[0])) && hedge_len < (sizeof(hedges) / sizeof(hedges[0]));
         i++) {
        sol_sockaddr_t peer;
        sol_pubkey_t peer_pk;
        if (!select_repair_peer_ex(repair, slot, avoid, avoid_len, &peer, &peer_pk)) {
            break;
        }
        avoid[avoid_len++] = peer_pk;

        sol_repair_pending_t tmp = *pending;
        tmp.peer = peer;
        tmp.peer_pubkey = peer_pk;
        tmp.shred_index = shred_index;
        tmp.nonce = pending->nonce;

        hedges[hedge_len++] = tmp;
    }

    pending->hedge_retry_mark = pending->retries;
    pending->last_hedge_sent_time = now_ms;
    pthread_mutex_unlock(&repair->pending_lock);

    if (send_primary) {
        sol_err_t err = send_repair_request_unlocked_pending(repair, &primary_snap);
        if (err != SOL_OK && tracked) {
            pthread_mutex_lock(&repair->pending_lock);
            if (tracked->active && tracked->nonce == primary_snap.nonce) {
                pending_deactivate_locked(repair, tracked);
            }
            pthread_mutex_unlock(&repair->pending_lock);
            return err;
        }
    }

    for (size_t i = 0; i < hedge_len; i++) {
        (void)send_repair_request_unlocked_pending(repair, &hedges[i]);
    }

    return SOL_OK;
}

sol_err_t
sol_repair_request_highest(sol_repair_t* repair, sol_slot_t slot, uint64_t shred_index) {
    if (!repair) return SOL_ERR_INVAL;

    sol_repair_pending_t snap;
    sol_repair_pending_t* tracked = NULL;

    pthread_mutex_lock(&repair->pending_lock);

    sol_repair_pending_t* existing = find_pending_slot_only(repair, SOL_REPAIR_HIGHEST_SHRED, slot);
    if (existing) {
        if (shred_index <= existing->shred_index) {
            pthread_mutex_unlock(&repair->pending_lock);
            return SOL_OK;
        }
        /* Advance the tracked highest index so we don't keep polling an older
         * frontier after new shreds are observed for the slot. */
        existing->shred_index = shred_index;
        existing->sent_time = sol_gossip_now_ms();
        existing->hedge_retry_mark = UINT32_MAX;
        existing->last_hedge_sent_time = 0;
        (void)ensure_nonce_tracked_locked(repair, existing);
        snap = *existing;
        tracked = existing;
        pthread_mutex_unlock(&repair->pending_lock);
        sol_err_t err = send_repair_request_unlocked_pending(repair, &snap);
        if (err != SOL_OK && tracked) {
            pthread_mutex_lock(&repair->pending_lock);
            if (tracked->active && tracked->nonce == snap.nonce) {
                pending_deactivate_locked(repair, tracked);
            }
            pthread_mutex_unlock(&repair->pending_lock);
        }
        return err;
    }

    sol_repair_pending_t* pending = find_pending_slot(repair, SOL_REPAIR_HIGHEST_SHRED);
    if (!pending) {
        pthread_mutex_unlock(&repair->pending_lock);
        return SOL_ERR_FULL;
    }

    if (!select_repair_peer(repair, slot, NULL, &pending->peer, &pending->peer_pubkey)) {
        pthread_mutex_unlock(&repair->pending_lock);
        return SOL_ERR_PEER_UNAVAILABLE;
    }

    pending->type = SOL_REPAIR_HIGHEST_SHRED;
    pending->slot = slot;
    pending->shred_index = shred_index;
    pending->nonce = 0;
    pending->sent_time = sol_gossip_now_ms();
    pending->retries = 0;
    pending->hedge_retry_mark = UINT32_MAX;
    pending->last_hedge_sent_time = 0;
    pending->active = true;
    repair->pending_count++;

    (void)ensure_nonce_tracked_locked(repair, pending);
    req_map_put_locked(repair, pending->type, pending->slot, pending->shred_index, (int32_t)(pending - repair->pending));
    snap = *pending;
    tracked = pending;

    pthread_mutex_unlock(&repair->pending_lock);

    sol_err_t err = send_repair_request_unlocked_pending(repair, &snap);
    if (err != SOL_OK && tracked) {
        pthread_mutex_lock(&repair->pending_lock);
        if (tracked->active && tracked->nonce == snap.nonce) {
            pending_deactivate_locked(repair, tracked);
        }
        pthread_mutex_unlock(&repair->pending_lock);
    }

    return err;
}

sol_err_t
sol_repair_request_orphan(sol_repair_t* repair, sol_slot_t slot) {
    if (!repair) return SOL_ERR_INVAL;

    sol_repair_pending_t snap;
    sol_repair_pending_t* tracked = NULL;

    pthread_mutex_lock(&repair->pending_lock);

    if (find_pending_slot_only(repair, SOL_REPAIR_ORPHAN, slot)) {
        pthread_mutex_unlock(&repair->pending_lock);
        return SOL_OK;
    }

    sol_repair_pending_t* pending = find_pending_slot(repair, SOL_REPAIR_ORPHAN);
    if (!pending) {
        pthread_mutex_unlock(&repair->pending_lock);
        return SOL_ERR_FULL;
    }

    if (!select_repair_peer(repair, slot, NULL, &pending->peer, &pending->peer_pubkey)) {
        pthread_mutex_unlock(&repair->pending_lock);
        return SOL_ERR_PEER_UNAVAILABLE;
    }

    pending->type = SOL_REPAIR_ORPHAN;
    pending->slot = slot;
    pending->shred_index = 0;
    pending->nonce = 0;
    pending->sent_time = sol_gossip_now_ms();
    pending->retries = 0;
    pending->hedge_retry_mark = UINT32_MAX;
    pending->last_hedge_sent_time = 0;
    pending->active = true;
    repair->pending_count++;

    (void)ensure_nonce_tracked_locked(repair, pending);
    req_map_put_locked(repair, pending->type, pending->slot, pending->shred_index, (int32_t)(pending - repair->pending));
    snap = *pending;
    tracked = pending;

    pthread_mutex_unlock(&repair->pending_lock);

    sol_err_t err = send_repair_request_unlocked_pending(repair, &snap);
    if (err != SOL_OK && tracked) {
        pthread_mutex_lock(&repair->pending_lock);
        if (tracked->active && tracked->nonce == snap.nonce) {
            pending_deactivate_locked(repair, tracked);
        }
        pthread_mutex_unlock(&repair->pending_lock);
    }

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
        stats->requests_sent =
            __atomic_load_n(&repair->stats.requests_sent, __ATOMIC_RELAXED);
        stats->responses_received =
            __atomic_load_n(&repair->stats.responses_received, __ATOMIC_RELAXED);
        stats->shreds_repaired =
            __atomic_load_n(&repair->stats.shreds_repaired, __ATOMIC_RELAXED);
        stats->timeouts =
            __atomic_load_n(&repair->stats.timeouts, __ATOMIC_RELAXED);
        stats->duplicates =
            __atomic_load_n(&repair->stats.duplicates, __ATOMIC_RELAXED);
        stats->invalid_responses =
            __atomic_load_n(&repair->stats.invalid_responses, __ATOMIC_RELAXED);
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

bool
sol_repair_pending_slot_stats(sol_repair_t* repair,
                              sol_slot_t slot,
                              sol_repair_pending_slot_stats_t* out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!repair || slot == 0) return false;

    bool have_any = false;
    uint64_t oldest = 0;
    uint64_t newest = 0;

    pthread_mutex_lock(&repair->pending_lock);
    for (size_t i = 0; i < repair->config.max_pending_requests; i++) {
        const sol_repair_pending_t* p = &repair->pending[i];
        if (!p->active) continue;
        if (p->slot != slot) continue;

        out->total++;
        switch (p->type) {
        case SOL_REPAIR_SHRED:           out->shreds++; break;
        case SOL_REPAIR_HIGHEST_SHRED:   out->highest++; break;
        case SOL_REPAIR_ORPHAN:          out->orphan++; break;
        case SOL_REPAIR_ANCESTOR_HASHES: out->ancestor_hashes++; break;
        }

        if (p->retries > out->max_retries) {
            out->max_retries = p->retries;
        }

        if (!have_any || p->sent_time < oldest) {
            oldest = p->sent_time;
        }
        if (!have_any || p->sent_time > newest) {
            newest = p->sent_time;
        }
        have_any = true;
    }
    pthread_mutex_unlock(&repair->pending_lock);

    if (have_any) {
        out->oldest_sent_ms = oldest;
        out->newest_sent_ms = newest;
    }

    return true;
}

size_t
sol_repair_prune_pending_outside_window(sol_repair_t* repair,
                                        sol_slot_t min_slot,
                                        sol_slot_t max_slot) {
    if (!repair || min_slot == 0) return 0;
    if (max_slot != 0 && max_slot < min_slot) return 0;

    size_t pruned = 0;
    pthread_mutex_lock(&repair->pending_lock);
    for (size_t i = 0; i < repair->config.max_pending_requests; i++) {
        sol_repair_pending_t* p = &repair->pending[i];
        if (!p->active) continue;
        if (p->slot == 0) continue;
        if (p->slot < min_slot) {
            pending_deactivate_locked(repair, p);
            pruned++;
            continue;
        }
        if (max_slot != 0 && p->slot > max_slot) {
            pending_deactivate_locked(repair, p);
            pruned++;
            continue;
        }
    }
    pthread_mutex_unlock(&repair->pending_lock);
    return pruned;
}

size_t
sol_repair_prune_pending_slot(sol_repair_t* repair,
                              sol_slot_t slot) {
    if (!repair || slot == 0) return 0;

    size_t pruned = 0;
    pthread_mutex_lock(&repair->pending_lock);
    for (size_t i = 0; i < repair->config.max_pending_requests; i++) {
        sol_repair_pending_t* p = &repair->pending[i];
        if (!p->active) continue;
        if (p->slot != slot) continue;
        pending_deactivate_locked(repair, p);
        pruned++;
    }
    pthread_mutex_unlock(&repair->pending_lock);
    return pruned;
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

void
sol_repair_set_leader_schedule(sol_repair_t* repair, struct sol_leader_schedule* schedule) {
    (void)sol_repair_swap_leader_schedule(repair, schedule);
}

struct sol_leader_schedule*
sol_repair_swap_leader_schedule(sol_repair_t* repair, struct sol_leader_schedule* schedule) {
    if (!repair) return NULL;
    sol_leader_schedule_t* old =
        __atomic_exchange_n(&repair->leader_schedule, (sol_leader_schedule_t*)schedule, __ATOMIC_ACQ_REL);
    return (struct sol_leader_schedule*)old;
}

sol_err_t
sol_repair_request_ancestor_hashes(sol_repair_t* repair, sol_slot_t slot) {
    if (!repair) return SOL_ERR_INVAL;

    sol_repair_pending_t snap;
    sol_repair_pending_t* tracked = NULL;

    pthread_mutex_lock(&repair->pending_lock);

    /* Check if already pending */
    if (find_pending_slot_only(repair, SOL_REPAIR_ANCESTOR_HASHES, slot)) {
        pthread_mutex_unlock(&repair->pending_lock);
        return SOL_OK;  /* Already requested */
    }

    /* Find free slot */
    sol_repair_pending_t* pending = find_pending_slot(repair, SOL_REPAIR_ANCESTOR_HASHES);
    if (!pending) {
        pthread_mutex_unlock(&repair->pending_lock);
        return SOL_ERR_FULL;
    }

    /* Select peer */
    if (!select_repair_peer(repair, slot, NULL, &pending->peer, &pending->peer_pubkey)) {
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
    pending->hedge_retry_mark = UINT32_MAX;
    pending->last_hedge_sent_time = 0;
    pending->active = true;
    repair->pending_count++;
    (void)__atomic_fetch_add(&repair->ancestor_pending_count, 1u, __ATOMIC_RELAXED);

    (void)ensure_nonce_tracked_locked(repair, pending);
    req_map_put_locked(repair, pending->type, pending->slot, pending->shred_index, (int32_t)(pending - repair->pending));
    snap = *pending;
    tracked = pending;

    pthread_mutex_unlock(&repair->pending_lock);

    sol_err_t err = send_repair_request_unlocked_pending(repair, &snap);
    if (err != SOL_OK && tracked) {
        pthread_mutex_lock(&repair->pending_lock);
        if (tracked->active && tracked->nonce == snap.nonce) {
            pending_deactivate_locked(repair, tracked);
        }
        pthread_mutex_unlock(&repair->pending_lock);
    } else if (err == SOL_OK) {
        sol_log_debug("Requested ancestor hashes for slot %llu",
                      (unsigned long long)slot);
    }

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
