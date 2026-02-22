/*
 * sol_slot_replay_tool.c - Offline slot transaction replay/debug helper
 *
 * This tool is intended to help debug bank-hash parity and bootstrap issues by
 * replaying a single slot's transactions against an on-disk ledger snapshot.
 *
 * It focuses on identifying transactions that fail before being counted in the
 * bank signature_count (i.e. failures that occur before fee deduction and
 * instruction execution).
 */

#include "../blockstore/sol_blockstore.h"
#include "../entry/sol_entry.h"
#include "../programs/sol_system_program.h"
#include "../snapshot/sol_snapshot.h"
#include "../runtime/sol_accounts_db.h"
#include "../runtime/sol_bank.h"
#include "../runtime/sol_sysvar.h"
#include "../txn/sol_signature.h"
#include "../util/sol_alloc.h"
#include "../util/sol_err.h"
#include "../util/sol_log.h"

#include <getopt.h>
#include <inttypes.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    sol_err_t  status;
    uint64_t   tx_count;
    uint64_t   sig_total;
} status_bucket_t;

typedef struct {
    sol_pubkey_t program_id;
    uint64_t     tx_count;
    uint64_t     sig_total;
} program_bucket_t;

typedef struct {
    uint32_t  value;
    uint64_t  tx_count;
    uint64_t  sig_total;
} u32_bucket_t;

static uint64_t
now_ms_monotonic(void) {
    struct timespec ts = {0};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000u);
}

static bool
env_truthy(const char* name) {
    if (!name || name[0] == '\0') return false;
    const char* env = getenv(name);
    return env && env[0] != '\0' && strcmp(env, "0") != 0;
}

static void
usage(const char* argv0) {
    fprintf(stderr,
            "sol-slot-replay 0.1.0 - Offline slot replay helper\\n\\n"
            "Usage:\\n"
            "  %s --ledger PATH --rocksdb-path PATH --slot SLOT [--variant ID] [--print N] [--progress]\\n"
            "  %s --ledger PATH --rocksdb-path PATH --slot SLOT --focus SIG [--stop-after-focus]\\n\\n"
            "Options:\\n"
            "  --ledger PATH        Ledger dir (contains accounts/)\\n"
            "  --rocksdb-path PATH  RocksDB base dir (contains blockstore/ and accounts/)\\n"
            "  --slot SLOT          Slot to replay\\n"
            "  --variant ID         Block variant id (default: 0)\\n"
            "  --print N            Print up to N signature_count-miss txs (default: 20)\\n"
            "  --print-failed N     Print up to N failed vote tx summaries (default: 0)\\n"
            "  --print-failures N   Print up to N failed txs with counted sigs (default: 0)\\n"
            "  --print-failures-status CODE  Only print failures with this status code\\n"
            "  --progress           Periodically print progress to stderr\\n"
            "  --focus SIG          Print detailed diagnostics for a single tx signature\\n"
            "  --stop-after-focus   Stop replay right after the focused tx\\n"
            "  --focus-log-level LV Temporarily set sol_log level for focused tx (default: debug)\\n"
            "  --watch-pubkey PK    Print txs that reference PUBKEY\\n"
            "  --watch-limit N      Limit watched tx prints (default: 0 = unlimited)\\n"
            "  -h, --help           Show help\\n",
            argv0, argv0);
}

static void
bucket_add(status_bucket_t* buckets,
           size_t* bucket_len,
           size_t bucket_cap,
           sol_err_t status,
           uint8_t sig_len) {
    if (!buckets || !bucket_len) return;

    for (size_t i = 0; i < *bucket_len; i++) {
        if (buckets[i].status == status) {
            buckets[i].tx_count++;
            buckets[i].sig_total += (uint64_t)sig_len;
            return;
        }
    }

    if (*bucket_len >= bucket_cap) {
        return;
    }

    buckets[*bucket_len] = (status_bucket_t){
        .status = status,
        .tx_count = 1,
        .sig_total = (uint64_t)sig_len,
    };
    (*bucket_len)++;
}

static int
cmp_bucket_desc(const void* a, const void* b) {
    const status_bucket_t* x = (const status_bucket_t*)a;
    const status_bucket_t* y = (const status_bucket_t*)b;
    if (x->sig_total < y->sig_total) return 1;
    if (x->sig_total > y->sig_total) return -1;
    if (x->tx_count < y->tx_count) return 1;
    if (x->tx_count > y->tx_count) return -1;
    if (x->status < y->status) return -1;
    if (x->status > y->status) return 1;
    return 0;
}

static void
program_bucket_add(program_bucket_t* buckets,
                   size_t* bucket_len,
                   size_t bucket_cap,
                   const sol_pubkey_t* program_id,
                   uint8_t sig_len) {
    if (!buckets || !bucket_len || !program_id) return;

    for (size_t i = 0; i < *bucket_len; i++) {
        if (memcmp(buckets[i].program_id.bytes, program_id->bytes, SOL_PUBKEY_SIZE) == 0) {
            buckets[i].tx_count++;
            buckets[i].sig_total += (uint64_t)sig_len;
            return;
        }
    }

    if (*bucket_len >= bucket_cap) {
        return;
    }

    buckets[*bucket_len] = (program_bucket_t){
        .program_id = *program_id,
        .tx_count = 1,
        .sig_total = (uint64_t)sig_len,
    };
    (*bucket_len)++;
}

static int
cmp_program_bucket_desc(const void* a, const void* b) {
    const program_bucket_t* x = (const program_bucket_t*)a;
    const program_bucket_t* y = (const program_bucket_t*)b;
    if (x->sig_total < y->sig_total) return 1;
    if (x->sig_total > y->sig_total) return -1;
    if (x->tx_count < y->tx_count) return 1;
    if (x->tx_count > y->tx_count) return -1;
    return memcmp(x->program_id.bytes, y->program_id.bytes, SOL_PUBKEY_SIZE);
}

static void
u32_bucket_add(u32_bucket_t* buckets,
               size_t* bucket_len,
               size_t bucket_cap,
               uint32_t value,
               uint8_t sig_len) {
    if (!buckets || !bucket_len) return;

    for (size_t i = 0; i < *bucket_len; i++) {
        if (buckets[i].value == value) {
            buckets[i].tx_count++;
            buckets[i].sig_total += (uint64_t)sig_len;
            return;
        }
    }

    if (*bucket_len >= bucket_cap) {
        return;
    }

    buckets[*bucket_len] = (u32_bucket_t){
        .value = value,
        .tx_count = 1,
        .sig_total = (uint64_t)sig_len,
    };
    (*bucket_len)++;
}

static int
cmp_u32_bucket_desc(const void* a, const void* b) {
    const u32_bucket_t* x = (const u32_bucket_t*)a;
    const u32_bucket_t* y = (const u32_bucket_t*)b;
    if (x->sig_total < y->sig_total) return 1;
    if (x->sig_total > y->sig_total) return -1;
    if (x->tx_count < y->tx_count) return 1;
    if (x->tx_count > y->tx_count) return -1;
    if (x->value < y->value) return -1;
    if (x->value > y->value) return 1;
    return 0;
}

int
main(int argc, char** argv) {
    const char* ledger_dir = NULL;
    const char* rocksdb_base = NULL;
    uint64_t slot = 0;
    uint32_t variant = 0;
    uint32_t print_limit = 20;
    uint32_t print_failed = 0;
    uint32_t print_failures = 0;
    bool have_print_failures_status = false;
    int print_failures_status = 0;
    bool progress = false;
    bool have_focus = false;
    sol_signature_t focus_sig;
    char focus_sig_b58[SOL_SIGNATURE_BASE58_LEN] = {0};
    bool stop_after_focus = false;
    sol_log_level_t focus_log_level = SOL_LOG_DEBUG;
    bool have_watch = false;
    sol_pubkey_t watch_pubkey;
    char watch_pubkey_b58[SOL_PUBKEY_BASE58_LEN] = {0};
    uint32_t watch_limit = 0;
    uint32_t printed_failures = 0;

    static struct option long_opts[] = {
        {"ledger", required_argument, 0, 1000},
        {"rocksdb-path", required_argument, 0, 1001},
        {"slot", required_argument, 0, 1002},
        {"variant", required_argument, 0, 1003},
        {"print", required_argument, 0, 1004},
        {"progress", no_argument, 0, 1005},
        {"print-failed", required_argument, 0, 1006},
        {"print-failures", required_argument, 0, 1012},
        {"print-failures-status", required_argument, 0, 1013},
        {"focus", required_argument, 0, 1007},
        {"stop-after-focus", no_argument, 0, 1008},
        {"focus-log-level", required_argument, 0, 1009},
        {"watch-pubkey", required_argument, 0, 1010},
        {"watch-limit", required_argument, 0, 1011},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 1000:
            ledger_dir = optarg;
            break;
        case 1001:
            rocksdb_base = optarg;
            break;
        case 1002:
            slot = strtoull(optarg, NULL, 10);
            break;
        case 1003:
            variant = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 1004:
            print_limit = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 1005:
            progress = true;
            break;
        case 1006:
            print_failed = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 1012:
            print_failures = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 1013:
            have_print_failures_status = true;
            print_failures_status = (int)strtol(optarg, NULL, 10);
            break;
        case 1007: {
            sol_signature_init(&focus_sig);
            sol_err_t sig_err = sol_signature_from_base58(optarg, &focus_sig);
            if (sig_err != SOL_OK) {
                fprintf(stderr, "error: invalid --focus signature\\n");
                return 1;
            }
            have_focus = true;
            (void)sol_signature_to_base58(&focus_sig, focus_sig_b58, sizeof(focus_sig_b58));
            break;
        }
        case 1008:
            stop_after_focus = true;
            break;
        case 1009:
            focus_log_level = sol_log_level_from_name(optarg);
            break;
        case 1010: {
            sol_err_t err = sol_pubkey_from_base58(optarg, &watch_pubkey);
            if (err != SOL_OK) {
                fprintf(stderr, "error: invalid --watch-pubkey: %s\\n", sol_err_str(err));
                return 1;
            }
            have_watch = true;
            (void)sol_pubkey_to_base58(&watch_pubkey, watch_pubkey_b58, sizeof(watch_pubkey_b58));
            break;
        }
        case 1011:
            watch_limit = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 'h':
        default:
            usage(argv[0]);
            return (opt == 'h') ? 0 : 1;
        }
    }

    if (!ledger_dir || !rocksdb_base || slot == 0) {
        usage(argv[0]);
        return 1;
    }

    sol_log_config_t log_cfg = (sol_log_config_t)SOL_LOG_CONFIG_DEFAULT;
    log_cfg.level = SOL_LOG_OFF;
    const char* log_env = getenv("SOL_SLOT_REPLAY_LOG_LEVEL");
    if (log_env && log_env[0] != '\0') {
        log_cfg.level = sol_log_level_from_name(log_env);
    }
    sol_log_init(&log_cfg);

    char blockstore_path[512];
    char accounts_db_path[512];
    char appendvec_path[512];
    if (snprintf(blockstore_path, sizeof(blockstore_path), "%s/blockstore", rocksdb_base) < 0 ||
        snprintf(accounts_db_path, sizeof(accounts_db_path), "%s/accounts", rocksdb_base) < 0 ||
        snprintf(appendvec_path, sizeof(appendvec_path), "%s/accounts", ledger_dir) < 0) {
        fprintf(stderr, "error: failed to build paths\\n");
        return 1;
    }

    sol_blockstore_config_t bs_cfg = SOL_BLOCKSTORE_CONFIG_DEFAULT;
    bs_cfg.storage_type = SOL_BLOCKSTORE_STORAGE_ROCKSDB;
    bs_cfg.rocksdb_path = blockstore_path;
    sol_blockstore_t* bs = sol_blockstore_new(&bs_cfg);
    if (!bs) {
        fprintf(stderr, "error: failed to open blockstore at %s\\n", blockstore_path);
        return 1;
    }

    uint64_t t0_ms = now_ms_monotonic();

    sol_block_t* block = sol_blockstore_get_block_variant(bs, (sol_slot_t)slot, variant);
    if (!block || !block->data || block->data_len == 0) {
        fprintf(stderr, "error: failed to load block slot=%" PRIu64 " variant=%u\\n", slot, variant);
        sol_block_destroy(block);
        sol_blockstore_destroy(bs);
        return 1;
    }

    sol_entry_batch_t* batch = sol_entry_batch_new(0);
    if (!batch) {
        fprintf(stderr, "error: OOM\\n");
        sol_block_destroy(block);
        sol_blockstore_destroy(bs);
        return 1;
    }

    sol_err_t parse_err = sol_entry_batch_parse(batch, block->data, block->data_len);
    if (parse_err != SOL_OK) {
        fprintf(stderr, "error: failed to parse slot entries: %s\\n", sol_err_str(parse_err));
        sol_entry_batch_destroy(batch);
        sol_block_destroy(block);
        sol_blockstore_destroy(bs);
        return 1;
    }

    uint64_t parsed_tx_total = 0;
    uint64_t parsed_sig_total = 0;
    for (size_t ei = 0; ei < batch->num_entries; ei++) {
        const sol_entry_t* entry = &batch->entries[ei];
        for (uint32_t ti = 0; ti < entry->num_transactions; ti++) {
            const sol_transaction_t* tx = &entry->transactions[ti];
            parsed_tx_total++;
            parsed_sig_total += (uint64_t)tx->signatures_len;
        }
    }

    sol_accounts_db_config_t db_cfg = SOL_ACCOUNTS_DB_CONFIG_DEFAULT;
    db_cfg.storage_type = SOL_ACCOUNTS_STORAGE_APPENDVEC;
    db_cfg.rocksdb_path = accounts_db_path;
    db_cfg.appendvec_path = appendvec_path;
    db_cfg.enable_snapshots = true;
    db_cfg.quiet = true;

    sol_accounts_db_t* accounts_db = sol_accounts_db_new(&db_cfg);
    if (!accounts_db) {
        fprintf(stderr, "error: failed to open AccountsDB (appendvec=%s index=%s)\\n",
                appendvec_path, accounts_db_path);
        sol_entry_batch_destroy(batch);
        sol_block_destroy(block);
        sol_blockstore_destroy(bs);
        return 1;
    }

    sol_accounts_db_bootstrap_state_t bs_state = {0};
    if (!sol_accounts_db_get_bootstrap_state(accounts_db, &bs_state)) {
        fprintf(stderr, "error: AccountsDB bootstrap state not found (need snapshot-ingested ledger)\\n");
        sol_accounts_db_destroy(accounts_db);
        sol_entry_batch_destroy(batch);
        sol_block_destroy(block);
        sol_blockstore_destroy(bs);
        return 1;
    }

    if (progress) {
        uint64_t elapsed_ms = now_ms_monotonic() - t0_ms;
        fprintf(stderr,
                "loaded slot=%" PRIu64 " variant=%u txs=%" PRIu64 " sigs=%" PRIu64 " (init_ms=%" PRIu64 ")\\n",
                slot,
                (unsigned)variant,
                parsed_tx_total,
                parsed_sig_total,
                elapsed_ms);
        fflush(stderr);
    }

    uint64_t t_bank0_ms = now_ms_monotonic();

    sol_bank_config_t bank_cfg = SOL_BANK_CONFIG_DEFAULT;
    if (bs_state.ticks_per_slot) {
        bank_cfg.ticks_per_slot = bs_state.ticks_per_slot;
    }
    if (bs_state.hashes_per_tick) {
        bank_cfg.hashes_per_tick = bs_state.hashes_per_tick;
    }
    if (bs_state.slots_per_epoch) {
        bank_cfg.slots_per_epoch = bs_state.slots_per_epoch;
    }
    if (bs_state.lamports_per_signature) {
        bank_cfg.lamports_per_signature = bs_state.lamports_per_signature;
    } else {
        bank_cfg.lamports_per_signature = 5000;
    }
    if (bs_state.rent_per_byte_year) {
        bank_cfg.rent_per_byte_year = bs_state.rent_per_byte_year;
    }
    if (bs_state.rent_exemption_threshold) {
        bank_cfg.rent_exemption_threshold = bs_state.rent_exemption_threshold;
    }

    sol_bank_t* root_bank = sol_bank_new(bs_state.slot, NULL, accounts_db, &bank_cfg);
    if (!root_bank) {
        fprintf(stderr, "error: failed to create root bank at slot=%" PRIu64 "\\n",
                (uint64_t)bs_state.slot);
        sol_accounts_db_destroy(accounts_db);
        sol_entry_batch_destroy(batch);
        sol_block_destroy(block);
        sol_blockstore_destroy(bs);
        return 1;
    }

    sol_hash_t bh_hashes[SOL_MAX_RECENT_BLOCKHASHES];
    uint64_t bh_fees[SOL_MAX_RECENT_BLOCKHASHES];
    size_t bh_len = 0;
    bool seeded_blockhash_queue = false;
    if (sol_accounts_db_get_bootstrap_blockhash_queue(accounts_db,
                                                      bh_hashes,
                                                      bh_fees,
                                                      SOL_MAX_RECENT_BLOCKHASHES,
                                                      &bh_len) &&
        bh_len > 0) {
        sol_err_t qerr = sol_bank_set_recent_blockhash_queue(root_bank, bh_hashes, bh_fees, bh_len);
        if (qerr != SOL_OK) {
            fprintf(stderr, "warning: failed to seed recent blockhash queue from AccountsDB: %s\\n",
                    sol_err_str(qerr));
        } else {
            seeded_blockhash_queue = true;
        }
    }

    if (!seeded_blockhash_queue) {
        char archive_dir[512];
        if (snprintf(archive_dir, sizeof(archive_dir), "%s/snapshot-archives", ledger_dir) >= 0) {
            DIR* dir = opendir(archive_dir);
            if (dir) {
                char archive_path[1024] = {0};
                struct dirent* entry;
                while ((entry = readdir(dir)) != NULL) {
                    if (entry->d_name[0] == '.') continue;
                    char candidate[1024];
                    if (snprintf(candidate, sizeof(candidate), "%s/%s", archive_dir, entry->d_name) < 0) {
                        continue;
                    }
                    sol_snapshot_info_t sinfo = {0};
                    if (sol_snapshot_get_info(candidate, &sinfo) == SOL_OK &&
                        sinfo.slot != 0 &&
                        sinfo.slot == bs_state.slot) {
                        strncpy(archive_path, candidate, sizeof(archive_path) - 1);
                        archive_path[sizeof(archive_path) - 1] = '\0';
                        break;
                    }
                }
                closedir(dir);

                if (archive_path[0] != '\0') {
                    bh_len = 0;
                    sol_err_t qerr = sol_snapshot_read_blockhash_queue_from_archive(archive_path,
                                                                                    bs_state.slot,
                                                                                    bh_hashes,
                                                                                    bh_fees,
                                                                                    SOL_MAX_RECENT_BLOCKHASHES,
                                                                                    &bh_len);
                    if (qerr == SOL_OK && bh_len > 0) {
                        (void)sol_accounts_db_set_bootstrap_blockhash_queue(accounts_db, bh_hashes, bh_fees, bh_len);
                        qerr = sol_bank_set_recent_blockhash_queue(root_bank, bh_hashes, bh_fees, bh_len);
                        if (qerr != SOL_OK) {
                            fprintf(stderr,
                                    "warning: recovered blockhash queue from snapshot archive but failed to seed bank: %s\\n",
                                    sol_err_str(qerr));
                        } else {
                            seeded_blockhash_queue = true;
                        }
                    } else if (qerr != SOL_OK && qerr != SOL_ERR_NOTFOUND) {
                        fprintf(stderr, "warning: failed to recover blockhash queue from snapshot archive: %s\\n",
                                sol_err_str(qerr));
                    }
                }
            }
        }
    }

    sol_bank_set_parent_slot(root_bank, bs_state.parent_slot);
    if (bs_state.flags & SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_BANK_HASH) {
        sol_bank_set_parent_bank_hash(root_bank, &bs_state.parent_bank_hash);
    }
    sol_bank_set_signature_count(root_bank, bs_state.signature_count);
    if (bs_state.flags & SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_BLOCKHASH) {
        sol_bank_set_blockhash(root_bank, &bs_state.blockhash);
    }
    if (bs_state.flags & SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_BANK_HASH) {
        sol_bank_set_bank_hash(root_bank, &bs_state.bank_hash);
    }
    sol_bank_freeze(root_bank);

    if (progress) {
        uint64_t elapsed_ms = now_ms_monotonic() - t_bank0_ms;
        fprintf(stderr,
                "root_bank slot=%" PRIu64 " created (ms=%" PRIu64 ")\\n",
                (uint64_t)bs_state.slot,
                elapsed_ms);
        fflush(stderr);
    }

    uint64_t t_bank1_ms = now_ms_monotonic();

    sol_bank_t* bank = sol_bank_new_from_parent(root_bank, (sol_slot_t)slot);
    if (!bank) {
        fprintf(stderr, "error: failed to create bank for slot=%" PRIu64 "\\n", slot);
        sol_bank_destroy(root_bank);
        sol_accounts_db_destroy(accounts_db);
        sol_entry_batch_destroy(batch);
        sol_block_destroy(block);
        sol_blockstore_destroy(bs);
        return 1;
    }

    if (progress) {
        uint64_t elapsed_ms = now_ms_monotonic() - t_bank1_ms;
        fprintf(stderr,
                "child_bank slot=%" PRIu64 " created (ms=%" PRIu64 ")\\n",
                slot,
                elapsed_ms);
        fflush(stderr);
    }

    const size_t bucket_cap = 128;
    status_bucket_t buckets[128];
    memset(buckets, 0, sizeof(buckets));
    size_t bucket_len = 0;

    const size_t fail_bucket_cap = 128;
    status_bucket_t fail_buckets[128];
    memset(fail_buckets, 0, sizeof(fail_buckets));
    size_t fail_bucket_len = 0;

    const size_t fail_program_cap = 128;
    program_bucket_t fail_programs[128];
    memset(fail_programs, 0, sizeof(fail_programs));
    size_t fail_program_len = 0;
    uint64_t fail_program_resolve_err = 0;

    const size_t vote_invalid_cap = 64;
    u32_bucket_t vote_invalid_types[64];
    memset(vote_invalid_types, 0, sizeof(vote_invalid_types));
    size_t vote_invalid_len = 0;

    uint64_t miss_tx = 0;
    uint64_t miss_sig = 0;
    uint64_t ok_tx = 0;
    uint64_t fail_tx = 0;
    uint64_t counted_sig = 0;

    const bool skip_exec = env_truthy("SOL_SKIP_INSTRUCTION_EXEC");
    uint64_t last_progress_ms = now_ms_monotonic();
    uint64_t replay_start_ms = last_progress_ms;
    uint64_t processed = 0;

    uint32_t printed = 0;
    uint32_t printed_failed = 0;
    uint32_t watched_printed = 0;
    bool stopped_early = false;

    typedef struct {
        bool exists;
        uint64_t lamports;
        uint64_t data_len;
        sol_pubkey_t owner;
        bool executable;
        uint64_t rent_epoch;
    } focus_acc_state_t;

    focus_acc_state_t focus_pre[SOL_MAX_MESSAGE_ACCOUNTS];
    focus_acc_state_t focus_post[SOL_MAX_MESSAGE_ACCOUNTS];
    sol_pubkey_t focus_keys[SOL_MAX_MESSAGE_ACCOUNTS];
    bool focus_writable[SOL_MAX_MESSAGE_ACCOUNTS];
    bool focus_signer[SOL_MAX_MESSAGE_ACCOUNTS];
    size_t focus_key_len = 0;

    for (size_t ei = 0; ei < batch->num_entries; ei++) {
        const sol_entry_t* entry = &batch->entries[ei];
        for (uint32_t ti = 0; ti < entry->num_transactions; ti++) {
            const sol_transaction_t* tx = &entry->transactions[ti];
            processed++;

            const sol_signature_t* tx_sig = sol_transaction_signature(tx);
            const bool is_focus = have_focus &&
                                  tx_sig &&
                                  (memcmp(tx_sig->bytes, focus_sig.bytes, SOL_SIGNATURE_SIZE) == 0);

            sol_log_level_t saved_level = sol_log_get_level();
            if (is_focus && saved_level == SOL_LOG_OFF) {
                sol_log_set_level(focus_log_level);
            }

            if (is_focus) {
                fprintf(stdout, "\\n=== focus tx ===\\n");
                fprintf(stdout,
                        "sig=%s entry=%zu tx=%u processed=%" PRIu64 "\\n",
                        focus_sig_b58[0] ? focus_sig_b58 : "(unknown)",
                        ei,
                        (unsigned)ti,
                        processed);

                const sol_pubkey_t* fee_payer = sol_transaction_fee_payer(tx);
                if (fee_payer) {
                    char payer_b58[SOL_PUBKEY_BASE58_LEN] = {0};
                    (void)sol_pubkey_to_base58(fee_payer, payer_b58, sizeof(payer_b58));
                    fprintf(stdout, "fee_payer=%s\\n", payer_b58[0] ? payer_b58 : "(unknown)");

                    sol_account_t* payer_acc = sol_bank_load_account(bank, fee_payer);
                    if (payer_acc) {
                        char owner_b58[SOL_PUBKEY_BASE58_LEN] = {0};
                        (void)sol_pubkey_to_base58(&payer_acc->meta.owner, owner_b58, sizeof(owner_b58));
                        fprintf(stdout,
                                "payer: lamports=%" PRIu64 " owner=%s data_len=%" PRIu64 " executable=%s rent_epoch=%" PRIu64 "\\n",
                                payer_acc->meta.lamports,
                                owner_b58[0] ? owner_b58 : "(unknown)",
                                (uint64_t)payer_acc->meta.data_len,
                                payer_acc->meta.executable ? "yes" : "no",
                                payer_acc->meta.rent_epoch);
                        sol_account_destroy(payer_acc);
                    } else {
                        fprintf(stdout, "payer: (missing)\\n");
                    }
                } else {
                    fprintf(stdout, "fee_payer=(missing)\\n");
                }

                const char* ver = (tx->message.version == SOL_MESSAGE_VERSION_V0) ? "v0" : "legacy";
                fprintf(stdout,
                        "message: version=%s sigs=%u static_keys=%u instr=%u lookups=%u\\n",
                        ver,
                        (unsigned)tx->signatures_len,
                        (unsigned)tx->message.account_keys_len,
                        (unsigned)tx->message.instructions_len,
                        (unsigned)tx->message.address_lookups_len);

                focus_key_len = 0;
                sol_err_t resolve_err = sol_bank_resolve_transaction_accounts(
                    bank,
                    tx,
                    focus_keys,
                    focus_writable,
                    focus_signer,
                    SOL_MAX_MESSAGE_ACCOUNTS,
                    &focus_key_len);
                if (resolve_err == SOL_OK && focus_key_len > 0) {
                    fprintf(stdout, "resolved_accounts_len=%zu\\n", focus_key_len);

                    size_t show = focus_key_len;
                    bool truncated = false;
                    if (show > 64) {
                        show = 16;
                        truncated = true;
                    }

                    for (size_t ki = 0; ki < show; ki++) {
                        char pk_b58[SOL_PUBKEY_BASE58_LEN] = {0};
                        (void)sol_pubkey_to_base58(&focus_keys[ki], pk_b58, sizeof(pk_b58));
                        fprintf(stdout,
                                "  key[%zu]=%s signer=%s writable=%s\\n",
                                ki,
                                pk_b58[0] ? pk_b58 : "(unknown)",
                                focus_signer[ki] ? "yes" : "no",
                                focus_writable[ki] ? "yes" : "no");
                    }
                    if (truncated) {
                        fprintf(stdout, "  ...\\n");
                        for (size_t ki = focus_key_len - 16; ki < focus_key_len; ki++) {
                            char pk_b58[SOL_PUBKEY_BASE58_LEN] = {0};
                            (void)sol_pubkey_to_base58(&focus_keys[ki], pk_b58, sizeof(pk_b58));
                            fprintf(stdout,
                                    "  key[%zu]=%s signer=%s writable=%s\\n",
                                    ki,
                                    pk_b58[0] ? pk_b58 : "(unknown)",
                                    focus_signer[ki] ? "yes" : "no",
                                    focus_writable[ki] ? "yes" : "no");
                        }
                    }

                    /* Snapshot pre-state for diffing after execution. */
                    for (size_t ki = 0; ki < focus_key_len && ki < SOL_MAX_MESSAGE_ACCOUNTS; ki++) {
                        focus_pre[ki] = (focus_acc_state_t){0};
                        sol_account_t* acc = sol_bank_load_account(bank, &focus_keys[ki]);
                        if (acc) {
                            focus_pre[ki].exists = true;
                            focus_pre[ki].lamports = acc->meta.lamports;
                            focus_pre[ki].data_len = (uint64_t)acc->meta.data_len;
                            focus_pre[ki].owner = acc->meta.owner;
                            focus_pre[ki].executable = acc->meta.executable;
                            focus_pre[ki].rent_epoch = acc->meta.rent_epoch;
                            sol_account_destroy(acc);
                        }
                    }

                    for (uint8_t ix_i = 0; ix_i < tx->message.instructions_len; ix_i++) {
                        const sol_compiled_instruction_t* ix = &tx->message.instructions[ix_i];
                        const sol_pubkey_t* pid = NULL;
                        if (ix->program_id_index < focus_key_len) {
                            pid = &focus_keys[ix->program_id_index];
                        }
                        char pid_b58[SOL_PUBKEY_BASE58_LEN] = {0};
                        if (pid) {
                            (void)sol_pubkey_to_base58(pid, pid_b58, sizeof(pid_b58));
                        }
                        fprintf(stdout,
                                "ix[%u] program=%s accounts_len=%u data_len=%u\\n",
                                (unsigned)ix_i,
                                pid_b58[0] ? pid_b58 : "(unknown)",
                                (unsigned)ix->account_indices_len,
                                (unsigned)ix->data_len);
                    }
                } else {
                    fprintf(stdout,
                            "resolve_accounts_failed=%s\\n",
                            sol_err_str(resolve_err));
                }
                fflush(stdout);
            }

            uint64_t before = 0;
            if (!skip_exec) {
                before = sol_bank_signature_count(bank);
            }

            bool watch_hit = false;
            bool watch_is_fee_payer = false;
            focus_acc_state_t watch_pre = {0};
            if (have_watch && (watch_limit == 0 || watched_printed < watch_limit)) {
                sol_pubkey_t watch_keys[SOL_MAX_MESSAGE_ACCOUNTS];
                bool watch_writable[SOL_MAX_MESSAGE_ACCOUNTS];
                bool watch_signer[SOL_MAX_MESSAGE_ACCOUNTS];
                size_t watch_len = 0;
                sol_err_t werr = sol_bank_resolve_transaction_accounts(
                    bank,
                    tx,
                    watch_keys,
                    watch_writable,
                    watch_signer,
                    SOL_MAX_MESSAGE_ACCOUNTS,
                    &watch_len);
                if (werr == SOL_OK && watch_len > 0) {
                    for (size_t wi = 0; wi < watch_len; wi++) {
                        if (sol_pubkey_eq(&watch_keys[wi], &watch_pubkey)) {
                            watch_hit = true;
                            break;
                        }
                    }
                }

                if (watch_hit) {
                    const sol_pubkey_t* fee_payer = sol_transaction_fee_payer(tx);
                    watch_is_fee_payer = fee_payer && sol_pubkey_eq(fee_payer, &watch_pubkey);

                    sol_account_t* acc = sol_bank_load_account(bank, &watch_pubkey);
                    if (acc) {
                        watch_pre.exists = true;
                        watch_pre.lamports = acc->meta.lamports;
                        watch_pre.data_len = (uint64_t)acc->meta.data_len;
                        watch_pre.owner = acc->meta.owner;
                        watch_pre.executable = acc->meta.executable;
                        watch_pre.rent_epoch = acc->meta.rent_epoch;
                        sol_account_destroy(acc);
                    }
                }
            }

            sol_tx_result_t r = sol_bank_process_transaction(bank, tx);

            uint64_t after = 0;
            if (!skip_exec) {
                after = sol_bank_signature_count(bank);
            }

            if (watch_hit && (watch_limit == 0 || watched_printed < watch_limit)) {
                const sol_signature_t* sig = sol_transaction_signature(tx);
                char sig_b58[SOL_SIGNATURE_BASE58_LEN] = {0};
                if (sig && sol_signature_to_base58(sig, sig_b58, sizeof(sig_b58)) != SOL_OK) {
                    sig_b58[0] = '\0';
                }

                focus_acc_state_t watch_post = {0};
                sol_account_t* acc = sol_bank_load_account(bank, &watch_pubkey);
                if (acc) {
                    watch_post.exists = true;
                    watch_post.lamports = acc->meta.lamports;
                    watch_post.data_len = (uint64_t)acc->meta.data_len;
                    watch_post.owner = acc->meta.owner;
                    watch_post.executable = acc->meta.executable;
                    watch_post.rent_epoch = acc->meta.rent_epoch;
                    sol_account_destroy(acc);
                }

                char pre_owner[SOL_PUBKEY_BASE58_LEN] = {0};
                char post_owner[SOL_PUBKEY_BASE58_LEN] = {0};
                if (watch_pre.exists) {
                    (void)sol_pubkey_to_base58(&watch_pre.owner, pre_owner, sizeof(pre_owner));
                }
                if (watch_post.exists) {
                    (void)sol_pubkey_to_base58(&watch_post.owner, post_owner, sizeof(post_owner));
                }

                fprintf(stdout,
                        "watch: sig=%s entry=%zu tx=%u key=%s fee_payer=%s status=%d(%s) fee=%" PRIu64 " cu=%" PRIu64
                        " pre_exists=%s pre_lamports=%" PRIu64 " pre_owner=%s post_exists=%s post_lamports=%" PRIu64 " post_owner=%s\n",
                        sig_b58[0] ? sig_b58 : "(unknown)",
                        ei,
                        (unsigned)ti,
                        watch_pubkey_b58[0] ? watch_pubkey_b58 : "(unknown)",
                        watch_is_fee_payer ? "yes" : "no",
                        (int)r.status,
                        sol_err_str(r.status),
                        (uint64_t)r.fee,
                        (uint64_t)r.compute_units_used,
                        watch_pre.exists ? "yes" : "no",
                        watch_pre.lamports,
                        pre_owner[0] ? pre_owner : "(none)",
                        watch_post.exists ? "yes" : "no",
                        watch_post.lamports,
                        post_owner[0] ? post_owner : "(none)");
                fflush(stdout);
                watched_printed++;
            }

            if (is_focus) {
                fprintf(stdout,
                        "focus result: status=%d(%s) fee=%" PRIu64 " cu=%" PRIu64 " sigcount_delta=%" PRIu64 "\\n",
                        (int)r.status,
                        sol_err_str(r.status),
                        (uint64_t)r.fee,
                        (uint64_t)r.compute_units_used,
                        skip_exec ? 0u : (after - before));

                if (focus_key_len > 0) {
                    for (size_t ki = 0; ki < focus_key_len && ki < SOL_MAX_MESSAGE_ACCOUNTS; ki++) {
                        focus_post[ki] = (focus_acc_state_t){0};
                        sol_account_t* acc = sol_bank_load_account(bank, &focus_keys[ki]);
                        if (acc) {
                            focus_post[ki].exists = true;
                            focus_post[ki].lamports = acc->meta.lamports;
                            focus_post[ki].data_len = (uint64_t)acc->meta.data_len;
                            focus_post[ki].owner = acc->meta.owner;
                            focus_post[ki].executable = acc->meta.executable;
                            focus_post[ki].rent_epoch = acc->meta.rent_epoch;
                            sol_account_destroy(acc);
                        }
                    }

                    fprintf(stdout, "focus account diffs (post vs pre):\\n");
                    size_t diffs = 0;
                    size_t shown = 0;
                    for (size_t ki = 0; ki < focus_key_len && ki < SOL_MAX_MESSAGE_ACCOUNTS; ki++) {
                        const focus_acc_state_t* pre = &focus_pre[ki];
                        const focus_acc_state_t* post = &focus_post[ki];
                        bool changed = false;
                        if (pre->exists != post->exists) {
                            changed = true;
                        } else if (pre->exists && post->exists) {
                            if (pre->lamports != post->lamports ||
                                pre->data_len != post->data_len ||
                                pre->executable != post->executable ||
                                pre->rent_epoch != post->rent_epoch ||
                                memcmp(pre->owner.bytes, post->owner.bytes, SOL_PUBKEY_SIZE) != 0) {
                                changed = true;
                            }
                        }

                        if (!changed) {
                            continue;
                        }

                        diffs++;
                        if (shown >= 128) {
                            continue;
                        }
                        shown++;

                        char pk_b58[SOL_PUBKEY_BASE58_LEN] = {0};
                        (void)sol_pubkey_to_base58(&focus_keys[ki], pk_b58, sizeof(pk_b58));
                        char pre_owner_b58[SOL_PUBKEY_BASE58_LEN] = {0};
                        char post_owner_b58[SOL_PUBKEY_BASE58_LEN] = {0};
                        if (pre->exists) {
                            (void)sol_pubkey_to_base58(&pre->owner, pre_owner_b58, sizeof(pre_owner_b58));
                        }
                        if (post->exists) {
                            (void)sol_pubkey_to_base58(&post->owner, post_owner_b58, sizeof(post_owner_b58));
                        }

                        fprintf(stdout,
                                "  %s: pre=%s lamports=%" PRIu64 " owner=%s data_len=%" PRIu64 " exec=%s rent_epoch=%" PRIu64
                                " -> post=%s lamports=%" PRIu64 " owner=%s data_len=%" PRIu64 " exec=%s rent_epoch=%" PRIu64 "\\n",
                                pk_b58[0] ? pk_b58 : "(unknown)",
                                pre->exists ? "present" : "missing",
                                pre->lamports,
                                pre_owner_b58[0] ? pre_owner_b58 : "(n/a)",
                                pre->data_len,
                                pre->executable ? "yes" : "no",
                                pre->rent_epoch,
                                post->exists ? "present" : "missing",
                                post->lamports,
                                post_owner_b58[0] ? post_owner_b58 : "(n/a)",
                                post->data_len,
                                post->executable ? "yes" : "no",
                                post->rent_epoch);
                    }
                    fprintf(stdout, "focus diffs_total=%zu diffs_shown=%zu\\n", diffs, shown);
                    if (diffs > shown) {
                        fprintf(stdout, "  ... (%zu more diffs)\\n", diffs - shown);
                    }
                }

                fflush(stdout);

                sol_log_set_level(saved_level);

                if (stop_after_focus) {
                    stopped_early = true;
                    goto replay_done;
                }
            } else {
                sol_log_set_level(saved_level);
            }

            if (r.status == SOL_OK) {
                ok_tx++;
            } else {
                fail_tx++;
            }

            uint8_t sig_len = tx->signatures_len;
            if (r.status != SOL_OK) {
                bucket_add(fail_buckets, &fail_bucket_len, fail_bucket_cap, r.status, sig_len);

                sol_pubkey_t resolved_keys[SOL_MAX_MESSAGE_ACCOUNTS];
                bool resolved_writable[SOL_MAX_MESSAGE_ACCOUNTS];
                bool resolved_signer[SOL_MAX_MESSAGE_ACCOUNTS];
                size_t resolved_len = 0;
                const sol_pubkey_t* blame = NULL;

                sol_err_t resolve_err = sol_bank_resolve_transaction_accounts(
                    bank,
                    tx,
                    resolved_keys,
                    resolved_writable,
                    resolved_signer,
                    SOL_MAX_MESSAGE_ACCOUNTS,
                    &resolved_len);

                if (resolve_err == SOL_OK && resolved_len > 0) {
                    for (uint8_t ix_i = 0; ix_i < tx->message.instructions_len; ix_i++) {
                        const sol_compiled_instruction_t* ix = &tx->message.instructions[ix_i];
                        if (ix->program_id_index >= resolved_len) {
                            continue;
                        }
                        const sol_pubkey_t* pid = &resolved_keys[ix->program_id_index];
                        if (sol_pubkey_eq(pid, &SOL_COMPUTE_BUDGET_ID)) {
                            continue;
                        }
                        blame = pid;
                        break;
                    }

                    if (!blame && tx->message.instructions_len > 0) {
                        const sol_compiled_instruction_t* ix = &tx->message.instructions[0];
                        if (ix->program_id_index < resolved_len) {
                            blame = &resolved_keys[ix->program_id_index];
                        }
                    }

                    if (blame) {
                        program_bucket_add(fail_programs,
                                           &fail_program_len,
                                           fail_program_cap,
                                           blame,
                                           sig_len);
                    }

                    if (r.status == SOL_ERR_PROGRAM_INVALID_INSTR &&
                        blame &&
                        sol_pubkey_eq(blame, &SOL_VOTE_PROGRAM_ID)) {
                        uint32_t vote_instr_type = UINT32_MAX;
                        size_t vote_ix_len = 0;
                        const uint8_t* vote_ix_data = NULL;
                        const sol_compiled_instruction_t* vote_ix = NULL;

                        for (uint8_t ix_i = 0; ix_i < tx->message.instructions_len; ix_i++) {
                            const sol_compiled_instruction_t* ix = &tx->message.instructions[ix_i];
                            if (ix->program_id_index >= resolved_len) {
                                continue;
                            }
                            const sol_pubkey_t* pid = &resolved_keys[ix->program_id_index];
                            if (!sol_pubkey_eq(pid, &SOL_VOTE_PROGRAM_ID)) {
                                continue;
                            }

                            vote_ix = ix;
                            vote_ix_len = ix->data_len;
                            vote_ix_data = ix->data;
                            if (ix->data && ix->data_len >= 4) {
                                memcpy(&vote_instr_type, ix->data, 4);
                            }
                            break;
                        }

                        if (vote_instr_type != UINT32_MAX) {
                            u32_bucket_add(vote_invalid_types,
                                           &vote_invalid_len,
                                           vote_invalid_cap,
                                           vote_instr_type,
                                           sig_len);
                        }

                        if (print_failed > 0 && printed_failed < print_failed) {
                            const sol_signature_t* sig = sol_transaction_signature(tx);
                            char sig_b58[SOL_SIGNATURE_BASE58_LEN] = {0};
                            if (sig && sol_signature_to_base58(sig, sig_b58, sizeof(sig_b58)) != SOL_OK) {
                                sig_b58[0] = '\0';
                            }

                            fprintf(stdout,
                                    "fail(vote): sig=%s vote_type=%" PRIu32 " ix_data_len=%zu ix_data_prefix[0..64]=",
                                    sig_b58[0] ? sig_b58 : "(unknown)",
                                    vote_instr_type,
                                    vote_ix_len);
                            size_t show = vote_ix_len;
                            if (show > 64) show = 64;
                            for (size_t bi = 0; bi < show; bi++) {
                                fprintf(stdout, "%02x", (unsigned)(vote_ix_data ? vote_ix_data[bi] : 0u));
                            }
                            if (vote_ix_len > show) {
                                fprintf(stdout, "...");
                                size_t suffix = 32;
                                if (vote_ix_len < suffix) suffix = vote_ix_len;
                                if (vote_ix_len > show && suffix > 0 && vote_ix_data) {
                                    fprintf(stdout, " ix_data_suffix[-%zu..]=", suffix);
                                    for (size_t bi = vote_ix_len - suffix; bi < vote_ix_len; bi++) {
                                        fprintf(stdout, "%02x", (unsigned)vote_ix_data[bi]);
                                    }
                                }
                            }
                            fprintf(stdout, "\n");
                            if (vote_ix_data && vote_ix_len > 0 && vote_ix_len <= 256) {
                                fprintf(stdout, "  ix_data_hex=");
                                for (size_t bi = 0; bi < vote_ix_len; bi++) {
                                    fprintf(stdout, "%02x", (unsigned)vote_ix_data[bi]);
                                }
                                fprintf(stdout, "\n");
                            }
                            if (vote_ix && vote_ix->account_indices && vote_ix->account_indices_len > 0) {
                                fprintf(stdout, "  vote_ix_accounts_len=%u\n",
                                        (unsigned)vote_ix->account_indices_len);
                                uint8_t show_acc = vote_ix->account_indices_len;
                                if (show_acc > 8) show_acc = 8;
                                for (uint8_t ai = 0; ai < show_acc; ai++) {
                                    uint8_t key_idx = vote_ix->account_indices[ai];
                                    const sol_pubkey_t* pk = NULL;
                                    if (key_idx < resolved_len) {
                                        pk = &resolved_keys[key_idx];
                                    }
                                    char pk_b58[SOL_PUBKEY_BASE58_LEN] = {0};
                                    if (pk) {
                                        (void)sol_pubkey_to_base58(pk, pk_b58, sizeof(pk_b58));
                                    }
                                    fprintf(stdout,
                                            "    acc[%u]=%s\n",
                                            (unsigned)ai,
                                            pk_b58[0] ? pk_b58 : "(unknown)");
                                }
                            }
                            printed_failed++;
                        }
                    }
                } else {
                    fail_program_resolve_err++;
                }

                if (print_failures > 0 && printed_failures < print_failures) {
                    if (!have_print_failures_status || (int)r.status == print_failures_status) {
                        uint64_t sigcount_delta = skip_exec ? 0u : (after - before);
                        if (skip_exec || sigcount_delta == (uint64_t)sig_len) {
                            const sol_signature_t* sig = sol_transaction_signature(tx);
                            char sig_b58[SOL_SIGNATURE_BASE58_LEN] = {0};
                            if (sig && sol_signature_to_base58(sig, sig_b58, sizeof(sig_b58)) != SOL_OK) {
                                sig_b58[0] = '\0';
                            }

                            const sol_pubkey_t* fee_payer = sol_transaction_fee_payer(tx);
                            char payer_b58[SOL_PUBKEY_BASE58_LEN] = {0};
                            bool payer_exists = false;
                            if (fee_payer &&
                                sol_pubkey_to_base58(fee_payer, payer_b58, sizeof(payer_b58)) == SOL_OK) {
                                sol_account_t* payer_acc = sol_bank_load_account(bank, fee_payer);
                                if (payer_acc) {
                                    payer_exists = true;
                                    sol_account_destroy(payer_acc);
                                }
                            }

                            char blame_b58[SOL_PUBKEY_BASE58_LEN] = {0};
                            if (blame) {
                                (void)sol_pubkey_to_base58(blame, blame_b58, sizeof(blame_b58));
                            }

                            fprintf(stdout,
                                    "fail: sig=%s status=%d(%s) sig_len=%u sigcount_delta=%" PRIu64
                                    " fee=%" PRIu64 " cu=%" PRIu64 "\\n",
                                    sig_b58[0] ? sig_b58 : "(unknown)",
                                    (int)r.status,
                                    sol_err_str(r.status),
                                    (unsigned)sig_len,
                                    sigcount_delta,
                                    (uint64_t)r.fee,
                                    (uint64_t)r.compute_units_used);

                            if (payer_b58[0]) {
                                fprintf(stdout,
                                        "  fee_payer=%s exists_in_index=%s\\n",
                                        payer_b58,
                                        payer_exists ? "yes" : "no");
                            }
                            if (blame_b58[0]) {
                                fprintf(stdout,
                                        "  blame_program=%s\\n",
                                        blame_b58);
                            }

                            fflush(stdout);
                            printed_failures++;
                        }
                    }
                }
            }
            if (skip_exec) {
                if (r.status == SOL_OK) {
                    counted_sig += (uint64_t)sig_len;
                    goto maybe_progress;
                }
            } else {
                if (after - before == (uint64_t)sig_len) {
                    counted_sig += (uint64_t)sig_len;
                    goto maybe_progress;
                }
            }

            miss_tx++;
            miss_sig += (uint64_t)sig_len;
            bucket_add(buckets, &bucket_len, bucket_cap, r.status, sig_len);

            if (printed < print_limit) {
                const sol_signature_t* sig = sol_transaction_signature(tx);
                char sig_b58[SOL_SIGNATURE_BASE58_LEN] = {0};
                if (sig && sol_signature_to_base58(sig, sig_b58, sizeof(sig_b58)) == SOL_OK) {
                    fprintf(stdout,
                            "miss: sig=%s status=%d(%s) sig_len=%u\\n",
                            sig_b58,
                            (int)r.status,
                            sol_err_str(r.status),
                            (unsigned)sig_len);
                } else {
                    fprintf(stdout,
                            "miss: sig=(unknown) status=%d(%s) sig_len=%u\\n",
                            (int)r.status,
                            sol_err_str(r.status),
                            (unsigned)sig_len);
                }

                const sol_pubkey_t* fee_payer = sol_transaction_fee_payer(tx);
                char payer_b58[SOL_PUBKEY_BASE58_LEN] = {0};
                if (fee_payer &&
                    sol_pubkey_to_base58(fee_payer, payer_b58, sizeof(payer_b58)) == SOL_OK) {
                    bool payer_exists = false;
                    sol_account_t* payer_acc = sol_bank_load_account(bank, fee_payer);
                    if (payer_acc) {
                        payer_exists = true;
                        sol_account_destroy(payer_acc);
                    }
                    fprintf(stdout,
                            "  fee_payer=%s exists_in_index=%s\\n",
                            payer_b58,
                            payer_exists ? "yes" : "no");
                }

                char blockhash_b58[SOL_PUBKEY_BASE58_LEN] = {0};
                (void)sol_pubkey_to_base58((const sol_pubkey_t*)&tx->message.recent_blockhash,
                                           blockhash_b58,
                                           sizeof(blockhash_b58));
                fprintf(stdout,
                        "  recent_blockhash=%s\\n",
                        blockhash_b58[0] ? blockhash_b58 : "(unknown)");

                sol_pubkey_t resolved_keys[SOL_MAX_MESSAGE_ACCOUNTS];
                bool resolved_writable[SOL_MAX_MESSAGE_ACCOUNTS];
                bool resolved_signer[SOL_MAX_MESSAGE_ACCOUNTS];
                size_t resolved_len = 0;
                sol_err_t resolve_err = sol_bank_resolve_transaction_accounts(
                    bank,
                    tx,
                    resolved_keys,
                    resolved_writable,
                    resolved_signer,
                    SOL_MAX_MESSAGE_ACCOUNTS,
                    &resolved_len);
                if (resolve_err == SOL_OK && resolved_len > 0) {
                    uint8_t show_ix = tx->message.instructions_len;
                    if (show_ix > 4) {
                        show_ix = 4;
                    }
                    for (uint8_t ix_i = 0; ix_i < show_ix; ix_i++) {
                        const sol_compiled_instruction_t* ix = &tx->message.instructions[ix_i];
                        const sol_pubkey_t* pid = NULL;
                        if (ix->program_id_index < resolved_len) {
                            pid = &resolved_keys[ix->program_id_index];
                        }

                        char pid_b58[SOL_PUBKEY_BASE58_LEN] = {0};
                        if (pid) {
                            (void)sol_pubkey_to_base58(pid, pid_b58, sizeof(pid_b58));
                        }

                        if (pid && sol_pubkey_eq(pid, &SOL_SYSTEM_PROGRAM_ID) &&
                            ix->data && ix->data_len >= 4) {
                            uint32_t instr_type = 0;
                            memcpy(&instr_type, ix->data, 4);
                            fprintf(stdout,
                                    "  ix[%u] program=%s system_type=%u\\n",
                                    (unsigned)ix_i,
                                    pid_b58[0] ? pid_b58 : "(unknown)",
                                    (unsigned)instr_type);
                        } else {
                            fprintf(stdout,
                                    "  ix[%u] program=%s\\n",
                                    (unsigned)ix_i,
                                    pid_b58[0] ? pid_b58 : "(unknown)");
                        }
                    }

                    bool nonce_candidate = false;
                    for (uint8_t ix_i = 0; ix_i < tx->message.instructions_len; ix_i++) {
                        const sol_compiled_instruction_t* ix = &tx->message.instructions[ix_i];
                        if (ix->program_id_index >= resolved_len) {
                            continue;
                        }
                        const sol_pubkey_t* pid = &resolved_keys[ix->program_id_index];
                        if (sol_pubkey_eq(pid, &SOL_COMPUTE_BUDGET_ID)) {
                            continue;
                        }
                        if (sol_pubkey_eq(pid, &SOL_SYSTEM_PROGRAM_ID) &&
                            ix->data && ix->data_len >= 4) {
                            uint32_t instr_type = 0;
                            memcpy(&instr_type, ix->data, 4);
                            if (instr_type == SOL_SYSTEM_INSTR_ADVANCE_NONCE) {
                                nonce_candidate = true;
                            }
                        }
                        break;
                    }
                    fprintf(stdout,
                            "  durable_nonce_candidate=%s\\n",
                            nonce_candidate ? "yes" : "no");
                } else {
                    fprintf(stdout,
                            "  resolve_accounts_failed=%s\\n",
                            sol_err_str(resolve_err));
                }

                printed++;
            }

        maybe_progress:
            if (progress) {
                uint64_t now_ms = now_ms_monotonic();
                if (now_ms - last_progress_ms >= 2000u) {
                    last_progress_ms = now_ms;
                    double pct = (parsed_tx_total > 0)
                        ? (100.0 * (double)processed / (double)parsed_tx_total)
                        : 0.0;
                    uint64_t elapsed_ms = now_ms - replay_start_ms;
                    fprintf(stderr,
                            "progress: tx=%" PRIu64 "/%" PRIu64 " (%.1f%%) ok=%" PRIu64 " fail=%" PRIu64
                            " missing_sig=%" PRIu64 " elapsed_s=%.1f\\n",
                            processed,
                            parsed_tx_total,
                            pct,
                            ok_tx,
                            fail_tx,
                            miss_sig,
                            (double)elapsed_ms / 1000.0);
                    fflush(stderr);
                }
            }
        }
    }

replay_done:
    if (stopped_early) {
        fprintf(stdout,
                "\\nNOTE: stopped early after focused tx; summary reflects partial replay (processed=%" PRIu64 ")\\n",
                processed);
    }

    uint64_t bank_sig_count = sol_bank_signature_count(bank);

    fprintf(stdout, "\\n");
    fprintf(stdout, "slot=%" PRIu64 " variant=%u\\n", slot, (unsigned)variant);
    fprintf(stdout, "parsed_txs=%" PRIu64 " parsed_sig_total=%" PRIu64 "\\n",
            parsed_tx_total, parsed_sig_total);
    fprintf(stdout, "bank_signature_count=%" PRIu64 " counted_sig=%" PRIu64 " missing_sig=%" PRIu64 " missing_txs=%" PRIu64 "\\n",
            bank_sig_count, counted_sig, miss_sig, miss_tx);
    fprintf(stdout, "tx_ok=%" PRIu64 " tx_fail=%" PRIu64 "\\n", ok_tx, fail_tx);

    if (parsed_sig_total >= bank_sig_count) {
        fprintf(stdout, "sig_total_diff=%" PRIu64 "\\n", (parsed_sig_total - bank_sig_count));
    } else {
        fprintf(stdout, "sig_total_diff=%" PRIu64 " (negative?)\\n", (bank_sig_count - parsed_sig_total));
    }

    if (bucket_len > 0) {
        qsort(buckets, bucket_len, sizeof(buckets[0]), cmp_bucket_desc);
        fprintf(stdout, "\\nmissing-by-status (sorted by missing sig_total):\\n");
        for (size_t i = 0; i < bucket_len; i++) {
            fprintf(stdout,
                    "  status=%d(%s) tx_count=%" PRIu64 " sig_total=%" PRIu64 "\\n",
                    (int)buckets[i].status,
                    sol_err_str(buckets[i].status),
                    buckets[i].tx_count,
                    buckets[i].sig_total);
        }
    }

    if (fail_bucket_len > 0) {
        qsort(fail_buckets, fail_bucket_len, sizeof(fail_buckets[0]), cmp_bucket_desc);
        fprintf(stdout, "\\nfailed-by-status (sorted by failed sig_total):\\n");
        size_t show = fail_bucket_len;
        if (show > 32) {
            show = 32;
        }
        for (size_t i = 0; i < show; i++) {
            fprintf(stdout,
                    "  status=%d(%s) tx_count=%" PRIu64 " sig_total=%" PRIu64 "\\n",
                    (int)fail_buckets[i].status,
                    sol_err_str(fail_buckets[i].status),
                    fail_buckets[i].tx_count,
                    fail_buckets[i].sig_total);
        }
        if (fail_bucket_len > show) {
            fprintf(stdout, "  ... (%zu more)\\n", fail_bucket_len - show);
        }
    }

    if (fail_program_len > 0) {
        qsort(fail_programs, fail_program_len, sizeof(fail_programs[0]), cmp_program_bucket_desc);
        fprintf(stdout, "\\nfailed-by-program (first non-ComputeBudget program, sorted by sig_total):\\n");
        size_t show = fail_program_len;
        if (show > 32) {
            show = 32;
        }
        for (size_t i = 0; i < show; i++) {
            char pid_b58[SOL_PUBKEY_BASE58_LEN] = {0};
            (void)sol_pubkey_to_base58(&fail_programs[i].program_id, pid_b58, sizeof(pid_b58));
            fprintf(stdout,
                    "  program=%s tx_count=%" PRIu64 " sig_total=%" PRIu64 "\\n",
                    pid_b58[0] ? pid_b58 : "(unknown)",
                    fail_programs[i].tx_count,
                    fail_programs[i].sig_total);
        }
        if (fail_program_len > show) {
            fprintf(stdout, "  ... (%zu more)\\n", fail_program_len - show);
        }
        if (fail_program_resolve_err > 0) {
            fprintf(stdout, "  resolve_accounts_failed=%" PRIu64 "\\n", fail_program_resolve_err);
        }
    } else if (fail_program_resolve_err > 0) {
        fprintf(stdout,
                "\\nfailed-by-program: unable to resolve accounts for %" PRIu64 " failed txs\\n",
                fail_program_resolve_err);
    }

    if (vote_invalid_len > 0) {
        qsort(vote_invalid_types, vote_invalid_len, sizeof(vote_invalid_types[0]), cmp_u32_bucket_desc);
        fprintf(stdout, "\\nvote-invalid-instr-types (vote ix u32 discriminant, sorted by sig_total):\\n");
        for (size_t i = 0; i < vote_invalid_len; i++) {
            fprintf(stdout,
                    "  type=%" PRIu32 " tx_count=%" PRIu64 " sig_total=%" PRIu64 "\\n",
                    vote_invalid_types[i].value,
                    vote_invalid_types[i].tx_count,
                    vote_invalid_types[i].sig_total);
        }
    }

    sol_bank_destroy(bank);
    sol_bank_destroy(root_bank);
    sol_accounts_db_destroy(accounts_db);
    sol_entry_batch_destroy(batch);
    sol_block_destroy(block);
    sol_blockstore_destroy(bs);

    return 0;
}
