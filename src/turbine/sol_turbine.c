/*
 * sol_turbine.c - Turbine block propagation implementation
 */

#include "sol_turbine.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include "../crypto/sol_sha256.h"
#include "../runtime/sol_bank.h"
#include "../runtime/sol_leader_schedule.h"
#include "../programs/sol_vote_program.h"
#include "../programs/sol_stake_program.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#ifdef __linux__
#include <sys/socket.h>
#include <sys/uio.h>
#endif

/*
 * Slot tracking entry
 */
typedef struct sol_slot_entry {
    sol_retransmit_slot_t*   state;
    sol_turbine_tree_t*      tree;
    struct sol_slot_entry*   next;
} sol_slot_entry_t;

/*
 * Turbine service structure
 */
struct sol_turbine {
    /* Configuration */
    sol_turbine_config_t    config;
    sol_pubkey_t            self_pubkey;

    /* Gossip for cluster info */
    sol_gossip_t*           gossip;

    /* Bank for stake lookups */
    sol_bank_t*             bank;
    sol_leader_schedule_t*  leader_schedule;
    uint64_t                stake_epoch;
    sol_pubkey_map_t*       node_stakes;         /* node identity -> stake (epoch cache) */
    uint64_t                node_stakes_total;   /* total active stake */

    /* Network */
    sol_udp_sock_t*         tvu_sock;
    bool                    running;

    /* Slot tracking (hash table) */
    sol_slot_entry_t**      slots;
    size_t                  slots_size;
    size_t                  num_slots;
    pthread_rwlock_t        slots_lock;

    /* Callbacks */
    sol_turbine_slot_cb     slot_callback;
    void*                   slot_callback_ctx;
    sol_turbine_shred_cb    shred_callback;
    void*                   shred_callback_ctx;
    sol_turbine_shred_batch_cb shred_batch_callback;
    void*                      shred_batch_callback_ctx;

    /* Statistics */
    sol_turbine_stats_t     stats;

    /* Receive buffer */
    uint8_t                 recv_buf[2048];
};

/*
 * Hash slot for slot table lookup
 */
static size_t
slot_hash(sol_slot_t slot, size_t table_size) {
    return (size_t)(slot % table_size);
}

/*
 * Find slot entry
 */
static sol_slot_entry_t*
find_slot(sol_turbine_t* turbine, sol_slot_t slot) {
    size_t idx = slot_hash(slot, turbine->slots_size);
    sol_slot_entry_t* entry = turbine->slots[idx];

    while (entry) {
        if (entry->state && entry->state->slot == slot) {
            return entry;
        }
        entry = entry->next;
    }
    return NULL;
}

/*
 * Get or create slot entry
 */
static sol_slot_entry_t*
get_or_create_slot(sol_turbine_t* turbine, sol_slot_t slot) {
    sol_slot_entry_t* entry = find_slot(turbine, slot);
    if (entry) {
        return entry;
    }

    /* Create new entry */
    entry = sol_calloc(1, sizeof(sol_slot_entry_t));
    if (!entry) return NULL;

    entry->state = sol_retransmit_slot_new(slot);
    if (!entry->state) {
        sol_free(entry);
        return NULL;
    }

    /* Insert into hash table */
    size_t idx = slot_hash(slot, turbine->slots_size);
    entry->next = turbine->slots[idx];
    turbine->slots[idx] = entry;
    turbine->num_slots++;

    return entry;
}

typedef struct {
    const sol_pubkey_map_t* vote_stakes;   /* vote account -> stake */
    sol_pubkey_map_t*       node_stakes;   /* node identity -> stake (output) */
} node_stake_build_ctx_t;

static bool
turbine_node_stake_build_cb(const sol_pubkey_t* pubkey,
                            const sol_account_t* account,
                            void* ctx) {
    node_stake_build_ctx_t* build = (node_stake_build_ctx_t*)ctx;
    if (!build || !build->vote_stakes || !build->node_stakes) {
        return false;
    }

    /* Only process vote program accounts */
    if (!sol_pubkey_eq(&account->meta.owner, &SOL_VOTE_PROGRAM_ID)) {
        return true;
    }

    /* Deserialize vote state to get node identity */
    sol_vote_state_t vote_state;
    if (sol_vote_state_deserialize(&vote_state, account->data,
                                   account->meta.data_len) != SOL_OK) {
        return true;
    }

    const uint64_t* stake_ptr =
        (const uint64_t*)sol_pubkey_map_get(build->vote_stakes, pubkey);
    uint64_t delegated_stake = stake_ptr ? *stake_ptr : 0;
    if (delegated_stake == 0) {
        return true;
    }

    uint64_t* cur = (uint64_t*)sol_pubkey_map_get(build->node_stakes, &vote_state.node_pubkey);
    if (cur) {
        *cur += delegated_stake;
        return true;
    }

    (void)sol_pubkey_map_insert(build->node_stakes, &vote_state.node_pubkey, &delegated_stake);
    return true;
}

static void
turbine_refresh_node_stakes_locked(sol_turbine_t* turbine, uint64_t epoch) {
    if (!turbine || !turbine->bank) return;
    if (turbine->node_stakes && turbine->stake_epoch == epoch) return;

    sol_accounts_db_t* accounts_db = sol_bank_get_accounts_db(turbine->bank);
    if (!accounts_db) return;

    uint64_t total_stake = 0;
    sol_pubkey_map_t* vote_stakes =
        sol_stake_build_vote_stake_map(turbine->bank, epoch, &total_stake);
    if (!vote_stakes) {
        sol_log_warn("Turbine: failed to build vote stake map for epoch %lu",
                     (unsigned long)epoch);
        return;
    }

    sol_pubkey_map_t* node_stakes = sol_pubkey_map_new(sizeof(uint64_t), 8192);
    if (!node_stakes) {
        sol_pubkey_map_destroy(vote_stakes);
        return;
    }

    node_stake_build_ctx_t ctx = {
        .vote_stakes = vote_stakes,
        .node_stakes = node_stakes,
    };
    sol_accounts_db_iterate(accounts_db, turbine_node_stake_build_cb, &ctx);

    sol_pubkey_map_destroy(vote_stakes);

    sol_pubkey_map_destroy(turbine->node_stakes);
    turbine->node_stakes = node_stakes;
    turbine->stake_epoch = epoch;
    turbine->node_stakes_total = total_stake;
}

/*
 * Build turbine tree for slot
 */
static sol_turbine_tree_t*
build_tree_for_slot(sol_turbine_t* turbine, sol_slot_t slot,
                    const sol_pubkey_t* leader) {
    const sol_pubkey_t* slot_leader = leader;
    if (!slot_leader || sol_pubkey_is_zero(slot_leader)) {
        if (turbine->leader_schedule) {
            const sol_pubkey_t* scheduled =
                sol_leader_schedule_get_leader(turbine->leader_schedule, slot);
            if (scheduled && !sol_pubkey_is_zero(scheduled)) {
                slot_leader = scheduled;
            }
        }
    }

    /* Get cluster nodes from gossip */
    const sol_contact_info_t* contacts[1024];
    size_t num_contacts = sol_gossip_get_cluster_nodes(
        turbine->gossip, contacts, 1024);

    if (num_contacts == 0) {
        return NULL;
    }

    /* Build node list */
    sol_turbine_node_t* nodes = sol_calloc(num_contacts, sizeof(sol_turbine_node_t));
    if (!nodes) return NULL;

    for (size_t i = 0; i < num_contacts; i++) {
        sol_pubkey_copy(&nodes[i].pubkey, &contacts[i]->pubkey);

        /* Get TVU address from contact info */
        const sol_sockaddr_t* tvu = sol_contact_info_socket(
            contacts[i], SOL_SOCKET_TAG_TVU);
        if (tvu) {
            sol_sockaddr_copy(&nodes[i].tvu_addr, tvu);
        }

        /* Default stake (will be overwritten if bank available) */
        nodes[i].stake = 1;
        nodes[i].index = (uint32_t)i;
    }

    /* If we have a bank, apply cached epoch stake weights */
    if (turbine->bank) {
        sol_epoch_schedule_t epoch_schedule = SOL_EPOCH_SCHEDULE_DEFAULT;
        uint64_t epoch = sol_epoch_schedule_get_epoch(&epoch_schedule, slot);
        turbine_refresh_node_stakes_locked(turbine, epoch);

        bool has_stake = false;
        for (size_t i = 0; i < num_contacts; i++) {
            if (!turbine->node_stakes) break;

            const uint64_t* stake_ptr =
                (const uint64_t*)sol_pubkey_map_get(turbine->node_stakes, &nodes[i].pubkey);
            if (stake_ptr && *stake_ptr > 0) {
                nodes[i].stake = *stake_ptr;
                has_stake = true;
            }
        }

        if (has_stake) {
            sol_log_debug("Turbine tree for slot %lu using stake weighting (epoch %lu, total=%lu)",
                          (unsigned long)slot,
                          (unsigned long)epoch,
                          (unsigned long)turbine->node_stakes_total);
        }
    }

    /* Build tree */
    sol_turbine_tree_t* tree = sol_turbine_tree_new(
        slot, slot_leader, nodes, num_contacts,
        &turbine->self_pubkey, turbine->config.fanout
    );

    sol_free(nodes);
    return tree;
}

/*
 * Retransmit shred to children
 */
static void
retransmit_shred(sol_turbine_t* turbine, sol_slot_entry_t* entry,
                 const uint8_t* data, size_t len) {
    if (!turbine->config.enable_retransmit || !entry->tree) {
        return;
    }

    /* Get children */
    const sol_turbine_node_t* children[SOL_TURBINE_DATA_PLANE_FANOUT];
    size_t num_children = sol_turbine_tree_children(
        entry->tree, children, SOL_TURBINE_DATA_PLANE_FANOUT);

    if (num_children == 0) {
        return;
    }

#ifdef __linux__
    /* Fast path: `sendmmsg` avoids one syscall per child while reusing the
     * same shred buffer for all destinations. */
    int fd = sol_udp_fd(turbine->tvu_sock);
    if (fd >= 0) {
        size_t off = 0;
        while (off < num_children) {
            int batch = (int)(num_children - off);
            if (batch > SOL_NET_BATCH_SIZE) {
                batch = SOL_NET_BATCH_SIZE;
            }

            struct mmsghdr msgs[SOL_NET_BATCH_SIZE];
            struct iovec iovs[SOL_NET_BATCH_SIZE];
            memset(msgs, 0, sizeof(msgs));

            for (int i = 0; i < batch; i++) {
                const sol_turbine_node_t* child = children[off + (size_t)i];

                iovs[i].iov_base = (void*)data;
                iovs[i].iov_len = len;

                msgs[i].msg_hdr.msg_name = (void*)&child->tvu_addr.addr;
                msgs[i].msg_hdr.msg_namelen = child->tvu_addr.len;
                msgs[i].msg_hdr.msg_iov = &iovs[i];
                msgs[i].msg_hdr.msg_iovlen = 1;
            }

            int sent = sendmmsg(fd, msgs, (unsigned)batch, 0);
            if (sent < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }
                break;
            }
            if (sent == 0) {
                break;
            }

            turbine->stats.shreds_retransmitted += (uint64_t)sent;
            turbine->stats.bytes_sent += (uint64_t)sent * (uint64_t)len;

            off += (size_t)sent;
            if (sent < batch) {
                /* Socket backpressure; retry on next tick. */
                break;
            }
        }
        return;
    }
#endif

    /* Portable fallback: per-child send. */
    for (size_t i = 0; i < num_children; i++) {
        sol_err_t err = sol_udp_send(turbine->tvu_sock, data, len,
                                     &children[i]->tvu_addr);
        if (err == SOL_OK) {
            turbine->stats.shreds_retransmitted++;
            turbine->stats.bytes_sent += len;
        }
    }
}

sol_turbine_t*
sol_turbine_new(const sol_turbine_config_t* config,
                sol_gossip_t* gossip,
                const sol_pubkey_t* self_pubkey) {
    sol_turbine_t* turbine = sol_calloc(1, sizeof(sol_turbine_t));
    if (!turbine) return NULL;

    if (config) {
        turbine->config = *config;
    } else {
        turbine->config = (sol_turbine_config_t)SOL_TURBINE_CONFIG_DEFAULT;
    }

    turbine->gossip = gossip;
    if (self_pubkey) {
        sol_pubkey_copy(&turbine->self_pubkey, self_pubkey);
    }

    turbine->stake_epoch = UINT64_MAX;

    /* Initialize slot table */
    turbine->slots_size = turbine->config.max_slots * 2;
    turbine->slots = sol_calloc(turbine->slots_size, sizeof(sol_slot_entry_t*));
    if (!turbine->slots) {
        sol_free(turbine);
        return NULL;
    }

    if (pthread_rwlock_init(&turbine->slots_lock, NULL) != 0) {
        sol_free(turbine->slots);
        sol_free(turbine);
        return NULL;
    }

    return turbine;
}

void
sol_turbine_set_bank(sol_turbine_t* turbine, sol_bank_t* bank) {
    if (!turbine) return;

    pthread_rwlock_wrlock(&turbine->slots_lock);
    turbine->bank = bank;

    if (!bank) {
        sol_pubkey_map_destroy(turbine->node_stakes);
        turbine->node_stakes = NULL;
        turbine->stake_epoch = UINT64_MAX;
        turbine->node_stakes_total = 0;
    } else {
        turbine_refresh_node_stakes_locked(turbine, sol_bank_epoch(bank));
    }

    pthread_rwlock_unlock(&turbine->slots_lock);
}

sol_leader_schedule_t*
sol_turbine_swap_leader_schedule(sol_turbine_t* turbine, sol_leader_schedule_t* schedule) {
    if (!turbine) return NULL;

    pthread_rwlock_wrlock(&turbine->slots_lock);
    sol_leader_schedule_t* old = turbine->leader_schedule;
    turbine->leader_schedule = schedule;
    pthread_rwlock_unlock(&turbine->slots_lock);

    return old;
}

void
sol_turbine_destroy(sol_turbine_t* turbine) {
    if (!turbine) return;

    sol_turbine_stop(turbine);

    if (turbine->tvu_sock) {
        sol_udp_destroy(turbine->tvu_sock);
    }

    /* Free all slot entries */
    for (size_t i = 0; i < turbine->slots_size; i++) {
        sol_slot_entry_t* entry = turbine->slots[i];
        while (entry) {
            sol_slot_entry_t* next = entry->next;
            sol_retransmit_slot_destroy(entry->state);
            sol_turbine_tree_destroy(entry->tree);
            sol_free(entry);
            entry = next;
        }
    }
    sol_free(turbine->slots);

    sol_pubkey_map_destroy(turbine->node_stakes);
    turbine->node_stakes = NULL;

    pthread_rwlock_destroy(&turbine->slots_lock);
    sol_free(turbine);
}

sol_err_t
sol_turbine_start(sol_turbine_t* turbine, uint16_t tvu_port) {
    if (!turbine) return SOL_ERR_INVAL;
    if (turbine->running) return SOL_OK;

    sol_udp_config_t udp_cfg = SOL_UDP_CONFIG_DEFAULT;
    udp_cfg.bind_port = tvu_port;
    udp_cfg.nonblocking = true;
    /* Mainnet shred feeds can exceed tens of thousands of packets/sec. Use a
     * large socket receive buffer to reduce kernel-level drops when user-space
     * is momentarily busy (signature verify, RocksDB, etc.). */
    udp_cfg.recv_buf = 128u * 1024u * 1024u;
    udp_cfg.send_buf = 128u * 1024u * 1024u;

    turbine->tvu_sock = sol_udp_new(&udp_cfg);
    if (!turbine->tvu_sock) {
        sol_log_error("Failed to create TVU socket");
        return SOL_ERR_IO;
    }

    turbine->running = true;
    sol_log_info("Turbine started on port %u", tvu_port);

    return SOL_OK;
}

void
sol_turbine_stop(sol_turbine_t* turbine) {
    if (turbine) {
        turbine->running = false;
    }
}

bool
sol_turbine_is_running(const sol_turbine_t* turbine) {
    return turbine && turbine->running;
}

sol_err_t
sol_turbine_receive_shred(sol_turbine_t* turbine, const uint8_t* data,
                          size_t len, const sol_sockaddr_t* from) {
    if (!turbine || !data || len == 0) {
        return SOL_ERR_INVAL;
    }

    turbine->stats.shreds_received++;
    turbine->stats.bytes_received += len;

    /* Parse shred */
    sol_shred_t shred;
    sol_err_t err = sol_shred_parse(&shred, data, len);
    if (err != SOL_OK) {
        turbine->stats.invalid_shreds++;
        return err;
    }
    size_t shred_len = shred.raw_len;

    /* Get or create slot state */
    pthread_rwlock_wrlock(&turbine->slots_lock);

    sol_slot_entry_t* entry = get_or_create_slot(turbine, shred.slot);
    if (!entry) {
        pthread_rwlock_unlock(&turbine->slots_lock);
        return SOL_ERR_NOMEM;
    }

    /* Build tree if needed */
    if (!entry->tree) {
        entry->tree = build_tree_for_slot(turbine, shred.slot, NULL);
    }

    /* Record shred */
    bool is_new = sol_retransmit_slot_record(entry->state, &shred);

    pthread_rwlock_unlock(&turbine->slots_lock);

    if (!is_new) {
        turbine->stats.duplicate_shreds++;
        return SOL_OK;
    }

    /* Notify consumer */
    if (turbine->shred_callback) {
        turbine->shred_callback(turbine->shred_callback_ctx, data, shred_len, from);
    }

    /* Retransmit to children */
    retransmit_shred(turbine, entry, data, shred_len);

    /* Check for slot completion */
    if (sol_retransmit_slot_is_complete(entry->state)) {
        turbine->stats.slots_completed++;

        if (turbine->slot_callback) {
            turbine->slot_callback(shred.slot, entry->state,
                                  turbine->slot_callback_ctx);
        }
    }

    return SOL_OK;
}

sol_err_t
sol_turbine_run_once(sol_turbine_t* turbine, uint32_t timeout_ms) {
    (void)timeout_ms;

    if (!turbine || !turbine->running) {
        return SOL_ERR_SHUTDOWN;
    }

    /* Drain TVU socket to avoid dropping shreds under load. */
    enum { SOL_TURBINE_RECV_BUDGET = 32768 };
    size_t received = 0;
    sol_udp_pkt_t pkts[SOL_NET_BATCH_SIZE];
    const bool fast_ingress =
        (!turbine->config.enable_retransmit) &&
        (turbine->shred_batch_callback || turbine->shred_callback) &&
        !turbine->slot_callback;

    while (received < SOL_TURBINE_RECV_BUDGET) {
        int n = sol_udp_recv_batch(turbine->tvu_sock, pkts, SOL_NET_BATCH_SIZE);
        if (n < 0) {
            return SOL_ERR_IO;
        }
        if (n == 0) {
            break;
        }
        received += (size_t)n;
        if (fast_ingress && turbine->shred_batch_callback) {
            uint64_t bytes = 0;
            for (int i = 0; i < n; i++) {
                bytes += pkts[i].len;
            }
            turbine->stats.shreds_received += (uint64_t)n;
            turbine->stats.bytes_received += bytes;
            turbine->shred_batch_callback(turbine->shred_batch_callback_ctx, pkts, n);
        } else {
            for (int i = 0; i < n; i++) {
                if (fast_ingress) {
                    turbine->stats.shreds_received++;
                    turbine->stats.bytes_received += pkts[i].len;
                    turbine->shred_callback(turbine->shred_callback_ctx,
                                            pkts[i].data,
                                            pkts[i].len,
                                            &pkts[i].addr);
                } else {
                    (void)sol_turbine_receive_shred(turbine, pkts[i].data, pkts[i].len, &pkts[i].addr);
                }
            }
        }
    }

    return SOL_OK;
}

void
sol_turbine_set_slot_callback(sol_turbine_t* turbine,
                              sol_turbine_slot_cb callback, void* ctx) {
    if (turbine) {
        turbine->slot_callback = callback;
        turbine->slot_callback_ctx = ctx;
    }
}

void
sol_turbine_set_shred_callback(sol_turbine_t* turbine,
                               sol_turbine_shred_cb callback,
                               void* ctx) {
    if (!turbine) return;
    turbine->shred_callback = callback;
    turbine->shred_callback_ctx = ctx;
}

void
sol_turbine_set_shred_batch_callback(sol_turbine_t* turbine,
                                     sol_turbine_shred_batch_cb callback,
                                     void* ctx) {
    if (!turbine) return;
    turbine->shred_batch_callback = callback;
    turbine->shred_batch_callback_ctx = ctx;
}

sol_err_t
sol_turbine_broadcast_shred(sol_turbine_t* turbine,
                            sol_slot_t slot,
                            const sol_pubkey_t* leader,
                            const uint8_t* data,
                            size_t len) {
    if (!turbine || !data || len == 0) {
        return SOL_ERR_INVAL;
    }
    if (!turbine->running || !turbine->tvu_sock) {
        return SOL_ERR_UNINITIALIZED;
    }

    pthread_rwlock_wrlock(&turbine->slots_lock);

    sol_slot_entry_t* entry = get_or_create_slot(turbine, slot);
    if (!entry) {
        pthread_rwlock_unlock(&turbine->slots_lock);
        return SOL_ERR_NOMEM;
    }

    /* Rebuild tree with supplied leader (if any). */
    if (entry->tree) {
        sol_turbine_tree_destroy(entry->tree);
        entry->tree = NULL;
    }
    if (leader) {
        entry->tree = build_tree_for_slot(turbine, slot, leader);
    }

    pthread_rwlock_unlock(&turbine->slots_lock);

    retransmit_shred(turbine, entry, data, len);
    return SOL_OK;
}

void
sol_turbine_stats(const sol_turbine_t* turbine, sol_turbine_stats_t* stats) {
    if (turbine && stats) {
        *stats = turbine->stats;
    }
}

void
sol_turbine_stats_reset(sol_turbine_t* turbine) {
    if (turbine) {
        memset(&turbine->stats, 0, sizeof(turbine->stats));
    }
}

/*
 * Turbine tree implementation
 */

sol_turbine_tree_t*
sol_turbine_tree_new(sol_slot_t slot, const sol_pubkey_t* leader,
                     const sol_turbine_node_t* nodes, size_t num_nodes,
                     const sol_pubkey_t* self_pubkey, uint32_t fanout) {
    if (num_nodes == 0 || !nodes) {
        return NULL;
    }

    sol_turbine_tree_t* tree = sol_calloc(1, sizeof(sol_turbine_tree_t));
    if (!tree) return NULL;

    tree->slot = slot;
    tree->fanout = fanout;

    if (leader) {
        sol_pubkey_copy(&tree->leader, leader);
    }

    /* Copy and shuffle nodes */
    tree->nodes = sol_calloc(num_nodes, sizeof(sol_turbine_node_t));
    if (!tree->nodes) {
        sol_free(tree);
        return NULL;
    }
    memcpy(tree->nodes, nodes, num_nodes * sizeof(sol_turbine_node_t));
    tree->num_nodes = num_nodes;

    /* Weighted shuffle */
    sol_turbine_weighted_shuffle(tree->nodes, num_nodes, slot, leader);

    /* Ensure leader is tree root when present in the node set. */
    if (leader && !sol_pubkey_is_zero(leader)) {
        size_t leader_idx = SIZE_MAX;
        for (size_t i = 0; i < num_nodes; i++) {
            if (sol_pubkey_eq(&tree->nodes[i].pubkey, leader)) {
                leader_idx = i;
                break;
            }
        }
        if (leader_idx != SIZE_MAX && leader_idx != 0) {
            sol_turbine_node_t tmp = tree->nodes[0];
            tree->nodes[0] = tree->nodes[leader_idx];
            tree->nodes[leader_idx] = tmp;
        }
    }

    /* Update indices after shuffle */
    for (size_t i = 0; i < num_nodes; i++) {
        tree->nodes[i].index = (uint32_t)i;
    }

    /* Find our position */
    tree->self_index = UINT32_MAX;
    for (size_t i = 0; i < num_nodes; i++) {
        if (sol_pubkey_eq(&tree->nodes[i].pubkey, self_pubkey)) {
            tree->self_index = (uint32_t)i;
            break;
        }
    }

    if (tree->self_index == UINT32_MAX) {
        /* We're not in the tree */
        sol_turbine_tree_destroy(tree);
        return NULL;
    }

    /* Calculate parent and depth */
    if (tree->self_index == 0) {
        tree->parent_index = UINT32_MAX;  /* Root has no parent */
        tree->depth = 0;
    } else {
        /* Parent is at (index - 1) / fanout */
        tree->parent_index = (tree->self_index - 1) / fanout;
        tree->depth = 1;
        uint32_t idx = tree->self_index;
        while (idx > 0) {
            idx = (idx - 1) / fanout;
            tree->depth++;
        }
        tree->depth--;
    }

    /* Calculate children */
    uint32_t first_child = tree->self_index * fanout + 1;
    if (first_child < num_nodes) {
        size_t max_children = num_nodes - first_child;
        if (max_children > fanout) max_children = fanout;

        tree->children = sol_calloc(max_children, sizeof(uint32_t));
        if (tree->children) {
            for (size_t i = 0; i < max_children; i++) {
                tree->children[i] = first_child + (uint32_t)i;
            }
            tree->num_children = max_children;
        }
    }

    return tree;
}

void
sol_turbine_tree_destroy(sol_turbine_tree_t* tree) {
    if (!tree) return;

    sol_free(tree->nodes);
    sol_free(tree->children);
    sol_free(tree);
}

const sol_turbine_node_t*
sol_turbine_tree_parent(const sol_turbine_tree_t* tree) {
    if (!tree || tree->parent_index == UINT32_MAX) {
        return NULL;
    }
    return &tree->nodes[tree->parent_index];
}

size_t
sol_turbine_tree_children(const sol_turbine_tree_t* tree,
                          const sol_turbine_node_t** children,
                          size_t max_children) {
    if (!tree || !children || max_children == 0) {
        return 0;
    }

    size_t count = tree->num_children;
    if (count > max_children) count = max_children;

    for (size_t i = 0; i < count; i++) {
        children[i] = &tree->nodes[tree->children[i]];
    }

    return count;
}

uint32_t
sol_turbine_tree_depth(const sol_turbine_tree_t* tree) {
    return tree ? tree->depth : 0;
}

bool
sol_turbine_tree_is_root(const sol_turbine_tree_t* tree) {
    return tree && tree->depth == 0;
}

/*
 * Retransmit slot implementation
 */

sol_retransmit_slot_t*
sol_retransmit_slot_new(sol_slot_t slot) {
    sol_retransmit_slot_t* state = sol_calloc(1, sizeof(sol_retransmit_slot_t));
    if (!state) return NULL;

    state->slot = slot;
    state->received_time = 0;  /* Would use sol_gossip_now_ms() */

    /* Allocate initial bitmaps (grow as needed) */
    state->data_bitmap_size = 128;  /* 1024 shreds */
    state->code_bitmap_size = 128;

    state->data_received = sol_calloc(state->data_bitmap_size, 1);
    state->code_received = sol_calloc(state->code_bitmap_size, 1);

    if (!state->data_received || !state->code_received) {
        sol_free(state->data_received);
        sol_free(state->code_received);
        sol_free(state);
        return NULL;
    }

    return state;
}

void
sol_retransmit_slot_destroy(sol_retransmit_slot_t* state) {
    if (!state) return;

    sol_free(state->data_received);
    sol_free(state->code_received);

    /* Free stored shreds */
    if (state->data_shreds) {
        for (size_t i = 0; i <= state->max_data_index; i++) {
            sol_free(state->data_shreds[i]);
        }
        sol_free(state->data_shreds);
    }

    if (state->code_shreds) {
        for (size_t i = 0; i <= state->max_code_index; i++) {
            sol_free(state->code_shreds[i]);
        }
        sol_free(state->code_shreds);
    }

    sol_free(state);
}

bool
sol_retransmit_slot_record(sol_retransmit_slot_t* state,
                           const sol_shred_t* shred) {
    if (!state || !shred) return false;

    uint32_t index = shred->index;
    uint8_t* bitmap;
    size_t* bitmap_size;
    size_t* max_index;
    bool is_data = (shred->type == SOL_SHRED_TYPE_DATA);

    if (is_data) {
        bitmap = state->data_received;
        bitmap_size = &state->data_bitmap_size;
        max_index = &state->max_data_index;
    } else {
        bitmap = state->code_received;
        bitmap_size = &state->code_bitmap_size;
        max_index = &state->max_code_index;
    }

    /* Expand bitmap if needed */
    size_t byte_idx = index / 8;
    if (byte_idx >= *bitmap_size) {
        size_t new_size = byte_idx + 128;
        uint8_t* new_bitmap = sol_realloc(bitmap, new_size);
        if (!new_bitmap) return false;

        memset(new_bitmap + *bitmap_size, 0, new_size - *bitmap_size);

        if (is_data) {
            state->data_received = new_bitmap;
        } else {
            state->code_received = new_bitmap;
        }
        bitmap = new_bitmap;
        *bitmap_size = new_size;
    }

    /* Check if already received */
    uint8_t bit = 1 << (index % 8);
    if (bitmap[byte_idx] & bit) {
        return false;  /* Duplicate */
    }

    /* Mark as received */
    bitmap[byte_idx] |= bit;

    /* Update max index */
    if (index > *max_index) {
        *max_index = index;
    }

    /* Check for last data shred */
    if (is_data && sol_shred_is_last_data(shred)) {
        state->last_data_index = index;
    }

    return true;
}

bool
sol_retransmit_slot_is_complete(const sol_retransmit_slot_t* state) {
    if (!state || state->complete) {
        return state ? state->complete : false;
    }

    /* Need to know the last data shred index */
    if (state->last_data_index == 0) {
        return false;
    }

    /* Check if we have all data shreds up to last */
    for (uint32_t i = 0; i <= state->last_data_index; i++) {
        size_t byte_idx = i / 8;
        uint8_t bit = 1 << (i % 8);
        if (!(state->data_received[byte_idx] & bit)) {
            return false;
        }
    }

    return true;
}

size_t
sol_retransmit_slot_missing(const sol_retransmit_slot_t* state,
                            uint32_t* indices, size_t max_indices,
                            bool data_shreds) {
    if (!state || !indices || max_indices == 0) {
        return 0;
    }

    const uint8_t* bitmap;
    size_t max_index;

    if (data_shreds) {
        bitmap = state->data_received;
        max_index = state->last_data_index > 0 ?
                    state->last_data_index : state->max_data_index;
    } else {
        bitmap = state->code_received;
        max_index = state->max_code_index;
    }

    size_t count = 0;
    for (uint32_t i = 0; i <= max_index && count < max_indices; i++) {
        size_t byte_idx = i / 8;
        uint8_t bit = 1 << (i % 8);
        if (!(bitmap[byte_idx] & bit)) {
            indices[count++] = i;
        }
    }

    return count;
}

/*
 * Weighted shuffle implementation
 *
 * Uses Fisher-Yates shuffle with stake-weighted probability.
 * Seed is derived from slot for deterministic shuffling.
 */
void
sol_turbine_weighted_shuffle(sol_turbine_node_t* nodes, size_t num_nodes,
                             sol_slot_t slot,
                             const sol_pubkey_t* leader) {
    if (!nodes || num_nodes <= 1) return;

    /* Seed RNG with slot (+ leader when available) */
    sol_sha256_ctx_t seed_ctx;
    sol_sha256_init(&seed_ctx);
    sol_sha256_update(&seed_ctx, &slot, sizeof(slot));
    if (leader && !sol_pubkey_is_zero(leader)) {
        sol_sha256_update(&seed_ctx, leader->bytes, SOL_PUBKEY_SIZE);
    }

    sol_sha256_t seed_hash;
    sol_sha256_final(&seed_ctx, &seed_hash);

    uint32_t seed = 0;
    for (int i = 0; i < 4; i++) {
        seed |= (uint32_t)seed_hash.bytes[i] << (i * 8);
    }

    /* Simple weighted shuffle - higher stake nodes go to front */
    /* First, compute total stake */
    uint64_t total_stake = 0;
    for (size_t i = 0; i < num_nodes; i++) {
        total_stake += nodes[i].stake;
    }

    if (total_stake == 0) {
        /* All equal stake, do regular shuffle */
        for (size_t i = num_nodes - 1; i > 0; i--) {
            seed = seed * 1103515245 + 12345;
            size_t j = seed % (i + 1);
            sol_turbine_node_t tmp = nodes[i];
            nodes[i] = nodes[j];
            nodes[j] = tmp;
        }
        return;
    }

    /* Stake-weighted Fisher-Yates */
    for (size_t i = 0; i < num_nodes - 1; i++) {
        /* Calculate cumulative stake for remaining nodes */
        uint64_t remaining_stake = 0;
        for (size_t j = i; j < num_nodes; j++) {
            remaining_stake += nodes[j].stake;
        }

        /* Pick random point in stake space */
        seed = seed * 1103515245 + 12345;
        uint64_t pick = seed % remaining_stake;

        /* Find node at that point */
        uint64_t cumulative = 0;
        size_t selected = i;
        for (size_t j = i; j < num_nodes; j++) {
            cumulative += nodes[j].stake;
            if (cumulative > pick) {
                selected = j;
                break;
            }
        }

        /* Swap */
        if (selected != i) {
            sol_turbine_node_t tmp = nodes[i];
            nodes[i] = nodes[selected];
            nodes[selected] = tmp;
        }
    }
}
