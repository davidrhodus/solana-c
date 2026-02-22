/*
 * sol_snapshot.c - Snapshot Implementation
 */

#include "sol_snapshot.h"
#include "sol_snapshot_archive.h"
#include "../crypto/sol_sha256.h"
#include "../txn/sol_pubkey.h"
#include "../txn/sol_bincode.h"
#include "../util/sol_alloc.h"
#include "../util/sol_bits.h"
#include "../util/sol_log.h"
#include "../util/sol_map.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>

/*
 * Snapshot manager internal state
 */
struct sol_snapshot_mgr {
    sol_snapshot_config_t   config;
    char*                   snapshot_dir;
    char*                   archive_dir;
    bool                    defer_owner_reverse_mark;
};

/* Forward declarations */
static sol_err_t parse_snapshot_manifest(const char* snapshot_dir, sol_snapshot_info_t* info);

typedef struct snapshot_appendvec_index snapshot_appendvec_index_t;
static sol_err_t snapshot_appendvec_index_update(snapshot_appendvec_index_t* idx,
                                                 const sol_pubkey_t* pubkey,
                                                 sol_slot_t slot,
                                                 uint64_t write_version,
                                                 const sol_pubkey_t* owner,
                                                 uint64_t lamports,
                                                 uint64_t data_len,
                                                 uint64_t file_key,
                                                 uint64_t record_offset,
                                                 const sol_hash_t* leaf_hash);

static void
bytes32_to_base58(const uint8_t bytes[32], char* out, size_t out_len) {
    if (!out || out_len == 0) return;
    out[0] = '\0';
    if (!bytes) return;

    sol_pubkey_t pk;
    memcpy(pk.bytes, bytes, sizeof(pk.bytes));
    (void)sol_pubkey_to_base58(&pk, out, out_len);
}

static sol_err_t
snapshot_mkdir_recursive(const char* path) {
    if (!path || path[0] == '\0') return SOL_ERR_INVAL;

    char tmp[512];
    if (strlen(path) >= sizeof(tmp)) return SOL_ERR_INVAL;
    snprintf(tmp, sizeof(tmp), "%s", path);

    for (char* p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                return SOL_ERR_IO;
            }
            *p = '/';
        }
    }

    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        return SOL_ERR_IO;
    }

    return SOL_OK;
}

static sol_err_t
snapshot_mkdir_parent_recursive(const char* path) {
    if (!path || path[0] == '\0') return SOL_ERR_INVAL;

    char tmp[512];
    if (strlen(path) >= sizeof(tmp)) return SOL_ERR_INVAL;
    snprintf(tmp, sizeof(tmp), "%s", path);

    char* slash = strrchr(tmp, '/');
    if (!slash) return SOL_OK;
    if (slash == tmp) return SOL_OK; /* parent is root */
    *slash = '\0';
    return snapshot_mkdir_recursive(tmp);
}

static sol_err_t
snapshot_persist_appendvec_accounts_dir(sol_accounts_db_t* accounts_db,
                                       const char* snapshot_dir,
                                       bool cleanup_extracted) {
    if (!accounts_db || !snapshot_dir) return SOL_ERR_INVAL;

    if (!cleanup_extracted) return SOL_OK;
    if (!sol_accounts_db_is_appendvec(accounts_db)) return SOL_OK;

    const char* dst_dir = sol_accounts_db_appendvec_path(accounts_db);
    if (!dst_dir || dst_dir[0] == '\0') return SOL_ERR_INVAL;

    char src_dir[512];
    snprintf(src_dir, sizeof(src_dir), "%s/accounts", snapshot_dir);

    if (strcmp(src_dir, dst_dir) == 0) return SOL_OK;

    struct stat st = {0};
    if (stat(src_dir, &st) != 0) {
        return SOL_OK;
    }
    if (!S_ISDIR(st.st_mode)) {
        return SOL_OK;
    }

    /* Fast path: rename whole directory if destination doesn't exist. */
    struct stat dst_st = {0};
    bool dst_exists = (stat(dst_dir, &dst_st) == 0 && S_ISDIR(dst_st.st_mode));
    if (!dst_exists) {
        sol_err_t derr = snapshot_mkdir_parent_recursive(dst_dir);
        if (derr != SOL_OK) {
            sol_log_error("Failed to create appendvec parent dir %s", dst_dir);
            return derr;
        }
        if (rename(src_dir, dst_dir) == 0) {
            sol_log_info("Persisted snapshot accounts dir to %s", dst_dir);
            return SOL_OK;
        }
        /* Fall back to per-file move. */
    }

    sol_err_t derr = snapshot_mkdir_recursive(dst_dir);
    if (derr != SOL_OK) {
        sol_log_error("Failed to create appendvec dir %s", dst_dir);
        return derr;
    }

    DIR* dir = opendir(src_dir);
    if (!dir) {
        sol_log_error("Failed to open snapshot accounts dir %s: %s", src_dir, strerror(errno));
        return SOL_ERR_IO;
    }

    struct dirent* entry;
    char src_path[512];
    char dst_path[512];
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        snprintf(src_path, sizeof(src_path), "%s/%s", src_dir, entry->d_name);
        snprintf(dst_path, sizeof(dst_path), "%s/%s", dst_dir, entry->d_name);

        struct stat ent_st = {0};
        if (stat(src_path, &ent_st) != 0) {
            continue;
        }
        if (!S_ISREG(ent_st.st_mode)) {
            continue;
        }

        if (rename(src_path, dst_path) != 0) {
            int e = errno;
            closedir(dir);
            sol_log_error("Failed to move appendvec file %s -> %s: %s",
                          src_path, dst_path, strerror(e));
            return SOL_ERR_IO;
        }
    }

    closedir(dir);
    sol_log_info("Persisted snapshot accounts files to %s", dst_dir);
    return SOL_OK;
}

/*
 * Create snapshot manager
 */
sol_snapshot_mgr_t*
sol_snapshot_mgr_new(const sol_snapshot_config_t* config) {
    sol_snapshot_mgr_t* mgr = sol_calloc(1, sizeof(sol_snapshot_mgr_t));
    if (!mgr) return NULL;

    if (config) {
        mgr->config = *config;
    } else {
        mgr->config = (sol_snapshot_config_t)SOL_SNAPSHOT_CONFIG_DEFAULT;
    }

    /* Copy directory paths if provided */
    if (mgr->config.snapshot_dir) {
        mgr->snapshot_dir = sol_alloc(strlen(mgr->config.snapshot_dir) + 1);
        if (mgr->snapshot_dir) {
            strcpy(mgr->snapshot_dir, mgr->config.snapshot_dir);
        }
    }

    if (mgr->config.archive_dir) {
        mgr->archive_dir = sol_alloc(strlen(mgr->config.archive_dir) + 1);
        if (mgr->archive_dir) {
            strcpy(mgr->archive_dir, mgr->config.archive_dir);
        }
    }

    return mgr;
}

/*
 * Destroy snapshot manager
 */
void
sol_snapshot_mgr_destroy(sol_snapshot_mgr_t* mgr) {
    if (!mgr) return;

    sol_free(mgr->snapshot_dir);
    sol_free(mgr->archive_dir);
    sol_free(mgr);
}

/*
 * Set directories
 */
sol_err_t
sol_snapshot_mgr_set_dirs(sol_snapshot_mgr_t* mgr,
                          const char* snapshot_dir,
                          const char* archive_dir) {
    if (!mgr) return SOL_ERR_INVAL;

    sol_free(mgr->snapshot_dir);
    sol_free(mgr->archive_dir);

    if (snapshot_dir) {
        mgr->snapshot_dir = sol_alloc(strlen(snapshot_dir) + 1);
        if (!mgr->snapshot_dir) return SOL_ERR_NOMEM;
        strcpy(mgr->snapshot_dir, snapshot_dir);
    } else {
        mgr->snapshot_dir = NULL;
    }

    if (archive_dir) {
        mgr->archive_dir = sol_alloc(strlen(archive_dir) + 1);
        if (!mgr->archive_dir) return SOL_ERR_NOMEM;
        strcpy(mgr->archive_dir, archive_dir);
    } else {
        mgr->archive_dir = NULL;
    }

    return SOL_OK;
}

/*
 * Create snapshot working directory structure
 */
static sol_err_t
create_snapshot_dirs(const char* base_dir, sol_slot_t slot) {
    char path[512];

    /* Create base/snapshots/<slot> */
    snprintf(path, sizeof(path), "%s/snapshots", base_dir);
    mkdir(path, 0755);

    snprintf(path, sizeof(path), "%s/snapshots/%lu", base_dir, (unsigned long)slot);
    mkdir(path, 0755);

    /* Create Solana-style nested bank file directory: snapshots/<slot>/snapshots/<slot> */
    snprintf(path, sizeof(path), "%s/snapshots/%lu/snapshots", base_dir, (unsigned long)slot);
    mkdir(path, 0755);

    snprintf(path, sizeof(path), "%s/snapshots/%lu/snapshots/%lu",
             base_dir, (unsigned long)slot, (unsigned long)slot);
    mkdir(path, 0755);

    /* Create base/accounts */
    snprintf(path, sizeof(path), "%s/accounts", base_dir);
    mkdir(path, 0755);

    return SOL_OK;
}

/*
 * Serialize bank fields to snapshot format
 */
size_t
sol_bank_fields_serialize(const sol_bank_t* bank, uint8_t* out_data, size_t max_len) {
    if (!bank || !out_data) return 0;

    sol_bank_fields_t fields = {0};

    fields.slot = sol_bank_slot(bank);
    sol_hash_t bank_hash = {0};
    sol_bank_compute_hash((sol_bank_t*)bank, &bank_hash);
    fields.hash = bank_hash;
    fields.block_height = sol_bank_tick_height(bank) / 64;  /* Approximate */
    fields.epoch = sol_bank_epoch(bank);
    fields.transaction_count = sol_bank_signature_count(bank);
    fields.capitalization = sol_bank_capitalization(bank);

    /* Get parent info if available */
    fields.parent_slot = sol_bank_parent_slot(bank);
    const sol_hash_t* parent_hash_ptr = sol_bank_parent_hash(bank);
    if (parent_hash_ptr) fields.parent_hash = *parent_hash_ptr;

    /* Default configuration values */
    fields.hashes_per_tick = 12500;
    fields.ticks_per_slot = 64;
    fields.lamports_per_signature = sol_bank_lamports_per_signature(bank);
    fields.slots_per_epoch = 432000;

    /* Fee rate governor defaults */
    fields.target_lamports_per_signature = 10000;
    fields.target_signatures_per_slot = 20000;
    fields.min_lamports_per_signature = 5000;
    fields.max_lamports_per_signature = 100000;

    /* Rent defaults */
    fields.rent_lamports_per_byte_year = 3480;
    fields.rent_exemption_threshold = 2.0f;
    fields.rent_burn_percent = 50;

    /* Inflation defaults */
    fields.inflation_initial = 0.08f;
    fields.inflation_terminal = 0.015f;
    fields.inflation_taper = 0.15f;
    fields.inflation_foundation = 0.05f;
    fields.inflation_foundation_term = 7.0f;
    fields.inflation_epoch = 0;

    if (sizeof(fields) > max_len) return 0;

    memcpy(out_data, &fields, sizeof(fields));
    return sizeof(fields);
}

/*
 * Deserialize bank fields from snapshot
 */
sol_err_t
sol_bank_fields_deserialize(const uint8_t* data, size_t len, sol_bank_fields_t* out_fields) {
    if (!data || !out_fields) return SOL_ERR_INVAL;
    if (len == 0) return SOL_ERR_SNAPSHOT_CORRUPT;

    /* Try bincode-style decoding first (no struct padding). This is compatible
     * with Solana's typical snapshot serialization and is also robust for
     * our own raw-struct format (extra bytes are ignored). */
    sol_decoder_t dec;
    sol_decoder_init(&dec, data, len);

    sol_bank_fields_t fields = {0};

    sol_err_t err = SOL_OK;
    err = sol_decode_u64(&dec, (uint64_t*)&fields.slot);
    if (err == SOL_OK) err = sol_decode_u64(&dec, (uint64_t*)&fields.parent_slot);

    const uint8_t* hash_bytes = NULL;
    if (err == SOL_OK) err = sol_decode_bytes(&dec, SOL_HASH_SIZE, &hash_bytes);
    if (err == SOL_OK) memcpy(fields.hash.bytes, hash_bytes, SOL_HASH_SIZE);
    if (err == SOL_OK) err = sol_decode_bytes(&dec, SOL_HASH_SIZE, &hash_bytes);
    if (err == SOL_OK) memcpy(fields.parent_hash.bytes, hash_bytes, SOL_HASH_SIZE);

    if (err == SOL_OK) err = sol_decode_u64(&dec, &fields.block_height);
    if (err == SOL_OK) err = sol_decode_u64(&dec, &fields.epoch);
    if (err == SOL_OK) err = sol_decode_u64(&dec, &fields.transaction_count);
    if (err == SOL_OK) err = sol_decode_u64(&dec, &fields.capitalization);
    if (err == SOL_OK) err = sol_decode_u64(&dec, &fields.max_tick_height);
    if (err == SOL_OK) err = sol_decode_u64(&dec, &fields.hashes_per_tick);
    if (err == SOL_OK) err = sol_decode_u64(&dec, &fields.ticks_per_slot);
    if (err == SOL_OK) err = sol_decode_u64(&dec, &fields.lamports_per_signature);
    if (err == SOL_OK) err = sol_decode_u64(&dec, &fields.slots_per_epoch);

    if (err == SOL_OK) err = sol_decode_u64(&dec, &fields.target_lamports_per_signature);
    if (err == SOL_OK) err = sol_decode_u64(&dec, &fields.target_signatures_per_slot);
    if (err == SOL_OK) err = sol_decode_u64(&dec, &fields.min_lamports_per_signature);
    if (err == SOL_OK) err = sol_decode_u64(&dec, &fields.max_lamports_per_signature);

    if (err == SOL_OK) err = sol_decode_u64(&dec, &fields.rent_lamports_per_byte_year);
    if (err == SOL_OK) {
        uint32_t bits = 0;
        err = sol_decode_u32(&dec, &bits);
        if (err == SOL_OK) {
            union { uint32_t u; float f; } cvt;
            cvt.u = bits;
            fields.rent_exemption_threshold = cvt.f;
        }
    }
    if (err == SOL_OK) err = sol_decode_u8(&dec, &fields.rent_burn_percent);

    if (err == SOL_OK) {
        uint32_t bits = 0;
        union { uint32_t u; float f; } cvt;
        err = sol_decode_u32(&dec, &bits);
        if (err == SOL_OK) { cvt.u = bits; fields.inflation_initial = cvt.f; }
        if (err == SOL_OK) err = sol_decode_u32(&dec, &bits);
        if (err == SOL_OK) { cvt.u = bits; fields.inflation_terminal = cvt.f; }
        if (err == SOL_OK) err = sol_decode_u32(&dec, &bits);
        if (err == SOL_OK) { cvt.u = bits; fields.inflation_taper = cvt.f; }
        if (err == SOL_OK) err = sol_decode_u32(&dec, &bits);
        if (err == SOL_OK) { cvt.u = bits; fields.inflation_foundation = cvt.f; }
        if (err == SOL_OK) err = sol_decode_u32(&dec, &bits);
        if (err == SOL_OK) { cvt.u = bits; fields.inflation_foundation_term = cvt.f; }
    }

    if (err == SOL_OK) err = sol_decode_u64(&dec, &fields.inflation_epoch);

    /* Basic sanity to avoid accepting obviously wrong parses. */
    if (err == SOL_OK && fields.ticks_per_slot > 0 && fields.slots_per_epoch > 0) {
        *out_fields = fields;
        return SOL_OK;
    }

    /* Fallback: raw struct copy (legacy). */
    if (len < sizeof(sol_bank_fields_t)) return SOL_ERR_SNAPSHOT_CORRUPT;
    memcpy(out_fields, data, sizeof(sol_bank_fields_t));
    return SOL_OK;
}

static sol_err_t
sol_bank_fields_deserialize_header(const uint8_t* data, size_t len, sol_bank_fields_t* out_fields) {
    if (!data || !out_fields) return SOL_ERR_INVAL;

    sol_decoder_t dec;
    sol_decoder_init(&dec, data, len);

    sol_bank_fields_t fields = {0};

    sol_err_t err = SOL_OK;
    err = sol_decode_u64(&dec, (uint64_t*)&fields.slot);
    if (err == SOL_OK) err = sol_decode_u64(&dec, (uint64_t*)&fields.parent_slot);

    const uint8_t* hash_bytes = NULL;
    if (err == SOL_OK) err = sol_decode_bytes(&dec, SOL_HASH_SIZE, &hash_bytes);
    if (err == SOL_OK) memcpy(fields.hash.bytes, hash_bytes, SOL_HASH_SIZE);
    if (err == SOL_OK) err = sol_decode_bytes(&dec, SOL_HASH_SIZE, &hash_bytes);
    if (err == SOL_OK) memcpy(fields.parent_hash.bytes, hash_bytes, SOL_HASH_SIZE);

    if (err == SOL_OK) err = sol_decode_u64(&dec, &fields.block_height);
    if (err == SOL_OK) err = sol_decode_u64(&dec, &fields.epoch);
    if (err == SOL_OK) err = sol_decode_u64(&dec, &fields.transaction_count);
    if (err == SOL_OK) err = sol_decode_u64(&dec, &fields.capitalization);
    if (err == SOL_OK) err = sol_decode_u64(&dec, &fields.max_tick_height);
    if (err == SOL_OK) err = sol_decode_u64(&dec, &fields.hashes_per_tick);
    if (err == SOL_OK) err = sol_decode_u64(&dec, &fields.ticks_per_slot);
    if (err == SOL_OK) err = sol_decode_u64(&dec, &fields.lamports_per_signature);
    if (err == SOL_OK) err = sol_decode_u64(&dec, &fields.slots_per_epoch);

    if (err != SOL_OK) {
        return err;
    }

    if (sol_hash_is_zero(&fields.hash) || fields.ticks_per_slot == 0 || fields.slots_per_epoch == 0) {
        return SOL_ERR_DECODE;
    }

    *out_fields = fields;
    return SOL_OK;
}

static sol_err_t
sol_bank_fields_deserialize_solana_snapshot_v1_2_0(const uint8_t* data,
                                                   size_t len,
                                                   sol_slot_t expected_slot,
                                                   const sol_hash_t* latest_blockhash,
                                                   sol_bank_fields_t* out_fields) {
    if (!data || !out_fields) return SOL_ERR_INVAL;
    if (len < 128) return SOL_ERR_DECODE;

    uint8_t slot_bytes[8];
    sol_store_u64_le(slot_bytes, (uint64_t)expected_slot);

    int best_score = -1;
    size_t best_pos = 0;
    sol_bank_fields_t best = {0};

    for (size_t pos = 0; pos + 104 + 8 <= len; pos++) {
        if (memcmp(data + pos, slot_bytes, sizeof(slot_bytes)) != 0) continue;

        if (pos + 24 + SOL_HASH_SIZE > len) continue;

        uint64_t epoch = sol_load_u64_le(data + pos + 8);
        uint64_t signature_count = sol_load_u64_le(data + pos + 16);

        sol_hash_t bank_hash = {0};
        memcpy(bank_hash.bytes, data + pos + 24, SOL_HASH_SIZE);

        if (sol_hash_is_zero(&bank_hash)) continue;

        int score = 0;

        uint64_t expected_epoch = (uint64_t)((uint64_t)expected_slot / SOL_SLOTS_PER_EPOCH);
        if (epoch == expected_epoch) {
            score += 6;
        } else if (epoch + 1 == expected_epoch || (epoch == expected_epoch + 1)) {
            score += 2;
        } else {
            continue;
        }

        if (signature_count > 0) score += 2;
        if (latest_blockhash && !sol_hash_eq(&bank_hash, latest_blockhash)) score += 2;

        /* Heuristic: FeeRateGovernor defaults should appear shortly after the bank hash:
         * target_lamports_per_signature, target_signatures_per_slot,
         * min_lamports_per_signature, max_lamports_per_signature, burn_percent. */
        uint64_t target_lamports = sol_load_u64_le(data + pos + 72);
        uint64_t target_sigs = sol_load_u64_le(data + pos + 80);
        uint64_t min_lamports = sol_load_u64_le(data + pos + 88);
        uint64_t max_lamports = sol_load_u64_le(data + pos + 96);
        uint64_t burn_percent = sol_load_u64_le(data + pos + 104);

        if (min_lamports > 0 &&
            target_lamports >= min_lamports &&
            max_lamports >= target_lamports &&
            target_sigs > 0 &&
            burn_percent <= 100) {
            score += 4;
        }

        if (score > best_score) {
            best_score = score;
            best_pos = pos;

            best = (sol_bank_fields_t){0};
            best.slot = expected_slot;
            best.parent_slot = (expected_slot > 0) ? (expected_slot - 1) : 0;
            best.epoch = epoch;
            best.transaction_count = signature_count;
            best.hash = bank_hash;

            best.block_height = sol_load_u64_le(data);

            /* Populate stable defaults for downstream config wiring. */
            best.hashes_per_tick = SOL_HASHES_PER_TICK;
            best.ticks_per_slot = SOL_TICKS_PER_SLOT;
            best.slots_per_epoch = SOL_SLOTS_PER_EPOCH;
            best.lamports_per_signature = (min_lamports > 0) ? min_lamports : 5000;

            best.target_lamports_per_signature = target_lamports;
            best.target_signatures_per_slot = target_sigs;
            best.min_lamports_per_signature = min_lamports;
            best.max_lamports_per_signature = max_lamports;
            best.rent_burn_percent = (uint8_t)burn_percent;
        }
    }

    if (best_score < 0) {
        return SOL_ERR_NOTFOUND;
    }

    if (best_score < 8) {
        sol_log_warn("Low-confidence Solana bank snapshot parse at slot %lu (pos=%lu, score=%d)",
                     (unsigned long)expected_slot,
                     (unsigned long)best_pos,
                     best_score);
    }

    *out_fields = best;
    return SOL_OK;
}

/* Parse the beginning of an Agave/Solana bank snapshot file (bincode fixint).
 *
 * Layout reference: external/agave/runtime/src/serde_snapshot.rs
 * DeserializableVersionedBank starts with:
 *   blockhash_queue: BlockhashQueue
 *   ancestors: AncestorsForSerialization
 *   hash, parent_hash, parent_slot, hard_forks, ... slot, epoch, block_height, ...
 *
 * We intentionally do NOT deserialize the full Bank; we only extract enough to
 * seed bank hash inputs and bank config. */

#define SOL_SNAPSHOT_MAX_BLOCKHASH_QUEUE_ENTRIES (4096ULL)
#define SOL_SNAPSHOT_MAX_ANCESTORS_ENTRIES       (1ULL << 20) /* 1,048,576 */
#define SOL_SNAPSHOT_MAX_HARDFORKS_ENTRIES       (4096ULL)

static sol_err_t
decode_hash32_bincode(sol_decoder_t* dec, sol_hash_t* out) {
    if (!dec || !out) return SOL_ERR_INVAL;
    const uint8_t* bytes = NULL;
    sol_err_t err = sol_decode_bytes(dec, SOL_HASH_SIZE, &bytes);
    if (err != SOL_OK) return err;
    memcpy(out->bytes, bytes, SOL_HASH_SIZE);
    return SOL_OK;
}

static sol_err_t
sol_bank_fields_deserialize_agave_snapshot_prefix(const uint8_t* data,
                                                  size_t len,
                                                  sol_slot_t expected_slot,
                                                  sol_bank_fields_t* out_fields) {
    if (!data || !out_fields) return SOL_ERR_INVAL;

    sol_decoder_t dec;
    sol_decoder_init(&dec, data, len);

    sol_bank_fields_t fields = {0};

    /* BlockhashQueue */
    uint64_t last_hash_index = 0;
    SOL_DECODE_TRY(sol_decode_u64(&dec, &last_hash_index));

    uint8_t last_hash_tag = 0;
    SOL_DECODE_TRY(sol_decode_u8(&dec, &last_hash_tag));

    sol_hash_t last_hash = {0};
    bool have_last_hash = false;
    if (last_hash_tag == 1) {
        SOL_DECODE_TRY(decode_hash32_bincode(&dec, &last_hash));
        have_last_hash = true;
    } else if (last_hash_tag != 0) {
        return SOL_ERR_DECODE;
    }

    uint64_t hashes_len = 0;
    SOL_DECODE_TRY(sol_decode_u64(&dec, &hashes_len));
    if (hashes_len > SOL_SNAPSHOT_MAX_BLOCKHASH_QUEUE_ENTRIES) {
        return SOL_ERR_SNAPSHOT_CORRUPT;
    }

    uint64_t last_lamports_per_signature = 0;
    bool have_last_lamports_per_signature = false;
    for (uint64_t i = 0; i < hashes_len; i++) {
        sol_hash_t key = {0};
        SOL_DECODE_TRY(decode_hash32_bincode(&dec, &key));

        /* HashInfo: FeeCalculator + hash_index + timestamp */
        uint64_t lamports_per_signature = 0;
        uint64_t hash_index = 0;
        uint64_t timestamp = 0;
        SOL_DECODE_TRY(sol_decode_u64(&dec, &lamports_per_signature));
        SOL_DECODE_TRY(sol_decode_u64(&dec, &hash_index));
        SOL_DECODE_TRY(sol_decode_u64(&dec, &timestamp));

        (void)last_hash_index;
        (void)hash_index;
        (void)timestamp;

        if (have_last_hash && memcmp(key.bytes, last_hash.bytes, SOL_HASH_SIZE) == 0) {
            last_lamports_per_signature = lamports_per_signature;
            have_last_lamports_per_signature = true;
        }
    }

    /* max_age (usize) */
    uint64_t max_age = 0;
    SOL_DECODE_TRY(sol_decode_u64(&dec, &max_age));
    (void)max_age;

    /* AncestorsForSerialization = HashMap<Slot, usize> */
    uint64_t ancestors_len = 0;
    SOL_DECODE_TRY(sol_decode_u64(&dec, &ancestors_len));
    if (ancestors_len > SOL_SNAPSHOT_MAX_ANCESTORS_ENTRIES) {
        return SOL_ERR_SNAPSHOT_CORRUPT;
    }
    for (uint64_t i = 0; i < ancestors_len; i++) {
        uint64_t slot = 0;
        uint64_t val = 0;
        SOL_DECODE_TRY(sol_decode_u64(&dec, &slot));
        SOL_DECODE_TRY(sol_decode_u64(&dec, &val));
    }

    /* BankFields */
    SOL_DECODE_TRY(decode_hash32_bincode(&dec, &fields.hash));
    SOL_DECODE_TRY(decode_hash32_bincode(&dec, &fields.parent_hash));
    SOL_DECODE_TRY(sol_decode_u64(&dec, (uint64_t*)&fields.parent_slot));

    /* HardForks newtype around Vec<(u64, usize)> */
    uint64_t hardforks_len = 0;
    SOL_DECODE_TRY(sol_decode_u64(&dec, &hardforks_len));
    if (hardforks_len > SOL_SNAPSHOT_MAX_HARDFORKS_ENTRIES) {
        return SOL_ERR_SNAPSHOT_CORRUPT;
    }
    for (uint64_t i = 0; i < hardforks_len; i++) {
        uint64_t hf_slot = 0;
        uint64_t hf_count = 0;
        SOL_DECODE_TRY(sol_decode_u64(&dec, &hf_slot));
        SOL_DECODE_TRY(sol_decode_u64(&dec, &hf_count));
    }

    /* Counts + config */
    uint64_t transaction_count = 0;
    uint64_t tick_height = 0;
    uint64_t signature_count = 0;
    SOL_DECODE_TRY(sol_decode_u64(&dec, &transaction_count));
    SOL_DECODE_TRY(sol_decode_u64(&dec, &tick_height));
    SOL_DECODE_TRY(sol_decode_u64(&dec, &signature_count));
    (void)transaction_count;
    (void)tick_height;

    /* `signature_count` is the per-bank signature counter used in the frozen
     * bank hash. We store it in `transaction_count` for legacy reasons. */
    fields.transaction_count = signature_count;

    SOL_DECODE_TRY(sol_decode_u64(&dec, &fields.capitalization));
    SOL_DECODE_TRY(sol_decode_u64(&dec, &fields.max_tick_height));

    /* hashes_per_tick: Option<u64> */
    uint8_t hashes_per_tick_tag = 0;
    SOL_DECODE_TRY(sol_decode_u8(&dec, &hashes_per_tick_tag));
    if (hashes_per_tick_tag == 1) {
        SOL_DECODE_TRY(sol_decode_u64(&dec, &fields.hashes_per_tick));
    } else if (hashes_per_tick_tag != 0) {
        return SOL_ERR_DECODE;
    }

    SOL_DECODE_TRY(sol_decode_u64(&dec, &fields.ticks_per_slot));

    /* ns_per_slot (u128) */
    SOL_DECODE_TRY(sol_decode_skip(&dec, 16));
    /* genesis_creation_time (i64) */
    SOL_DECODE_TRY(sol_decode_skip(&dec, 8));
    /* slots_per_year (f64) */
    SOL_DECODE_TRY(sol_decode_skip(&dec, 8));
    /* accounts_data_len (u64) */
    SOL_DECODE_TRY(sol_decode_skip(&dec, 8));

    SOL_DECODE_TRY(sol_decode_u64(&dec, (uint64_t*)&fields.slot));
    SOL_DECODE_TRY(sol_decode_u64(&dec, &fields.epoch));
    SOL_DECODE_TRY(sol_decode_u64(&dec, &fields.block_height));

    fields.lamports_per_signature =
        have_last_lamports_per_signature ? last_lamports_per_signature : 0;
    fields.slots_per_epoch = SOL_SLOTS_PER_EPOCH;

    if (fields.slot != expected_slot) {
        return SOL_ERR_DECODE;
    }
    if (sol_hash_is_zero(&fields.hash) || fields.ticks_per_slot == 0 || fields.slots_per_epoch == 0) {
        return SOL_ERR_DECODE;
    }
    if (fields.lamports_per_signature == 0) {
        fields.lamports_per_signature = 5000;
    }

    *out_fields = fields;
    return SOL_OK;
}

static sol_err_t
file_read_exact(FILE* f, void* out, size_t len) {
    if (!f || (!out && len != 0)) return SOL_ERR_INVAL;
    if (len == 0) return SOL_OK;
    size_t n = fread(out, 1, len, f);
    if (n != len) {
        return SOL_ERR_DECODE;
    }
    return SOL_OK;
}

static sol_err_t
file_read_u8(FILE* f, uint8_t* out) {
    if (!out) return SOL_ERR_INVAL;
    uint8_t v = 0;
    sol_err_t err = file_read_exact(f, &v, sizeof(v));
    if (err != SOL_OK) return err;
    *out = v;
    return SOL_OK;
}

static sol_err_t
file_read_u64_le(FILE* f, uint64_t* out) {
    if (!out) return SOL_ERR_INVAL;
    uint8_t buf[8];
    sol_err_t err = file_read_exact(f, buf, sizeof(buf));
    if (err != SOL_OK) return err;
    *out = sol_load_u64_le(buf);
    return SOL_OK;
}

static sol_err_t
file_skip(FILE* f, uint64_t bytes) {
    if (!f) return SOL_ERR_INVAL;
    if (bytes == 0) return SOL_OK;

    /* Prefer seeking to avoid touching GBs of snapshot metadata. */
    while (bytes > 0) {
        uint64_t step = bytes;
        if (step > (uint64_t)INT64_MAX) {
            step = (uint64_t)INT64_MAX;
        }
        if (fseeko(f, (off_t)step, SEEK_CUR) != 0) {
            return SOL_ERR_DECODE;
        }
        bytes -= step;
    }
    return SOL_OK;
}

static sol_err_t
file_read_hash32(FILE* f, sol_hash_t* out) {
    if (!out) return SOL_ERR_INVAL;
    sol_err_t err = file_read_exact(f, out->bytes, SOL_HASH_SIZE);
    if (err != SOL_OK) return err;
    return SOL_OK;
}

static sol_err_t
sol_bank_fields_deserialize_agave_snapshot_file(FILE* f,
                                                sol_slot_t expected_slot,
                                                sol_bank_fields_t* out_fields) {
    if (!f || !out_fields) return SOL_ERR_INVAL;

    if (fseeko(f, 0, SEEK_SET) != 0) {
        return SOL_ERR_IO;
    }

    sol_bank_fields_t fields = {0};

    /* BlockhashQueue */
    uint64_t last_hash_index = 0;
    SOL_TRY(file_read_u64_le(f, &last_hash_index));

    uint8_t last_hash_tag = 0;
    SOL_TRY(file_read_u8(f, &last_hash_tag));

    sol_hash_t last_hash = {0};
    bool have_last_hash = false;
    if (last_hash_tag == 1) {
        SOL_TRY(file_read_hash32(f, &last_hash));
        have_last_hash = true;
    } else if (last_hash_tag != 0) {
        return SOL_ERR_DECODE;
    }

    uint64_t hashes_len = 0;
    SOL_TRY(file_read_u64_le(f, &hashes_len));
    if (hashes_len > SOL_SNAPSHOT_MAX_BLOCKHASH_QUEUE_ENTRIES) {
        return SOL_ERR_SNAPSHOT_CORRUPT;
    }

    uint64_t last_lamports_per_signature = 0;
    bool have_last_lamports_per_signature = false;

    for (uint64_t i = 0; i < hashes_len; i++) {
        sol_hash_t key = {0};
        SOL_TRY(file_read_hash32(f, &key));

        /* HashInfo: FeeCalculator + hash_index + timestamp */
        uint64_t lamports_per_signature = 0;
        uint64_t hash_index = 0;
        uint64_t timestamp = 0;
        SOL_TRY(file_read_u64_le(f, &lamports_per_signature));
        SOL_TRY(file_read_u64_le(f, &hash_index));
        SOL_TRY(file_read_u64_le(f, &timestamp));

        (void)hash_index;
        (void)timestamp;

        if (have_last_hash && memcmp(key.bytes, last_hash.bytes, SOL_HASH_SIZE) == 0) {
            last_lamports_per_signature = lamports_per_signature;
            have_last_lamports_per_signature = true;
        }
    }

    /* max_age (usize) */
    uint64_t max_age = 0;
    SOL_TRY(file_read_u64_le(f, &max_age));

    /* AncestorsForSerialization = HashMap<Slot, usize> */
    uint64_t ancestors_len = 0;
    SOL_TRY(file_read_u64_le(f, &ancestors_len));
    if (ancestors_len > (1ULL << 28)) { /* sanity */
        return SOL_ERR_SNAPSHOT_CORRUPT;
    }

    uint64_t ancestors_bytes = 0;
    if (__builtin_mul_overflow(ancestors_len, 16ULL, &ancestors_bytes)) {
        return SOL_ERR_SNAPSHOT_CORRUPT;
    }
    SOL_TRY(file_skip(f, ancestors_bytes));

    /* BankFields */
    SOL_TRY(file_read_hash32(f, &fields.hash));
    SOL_TRY(file_read_hash32(f, &fields.parent_hash));
    SOL_TRY(file_read_u64_le(f, (uint64_t*)&fields.parent_slot));

    /* HardForks newtype around Vec<(u64, usize)> */
    uint64_t hardforks_len = 0;
    SOL_TRY(file_read_u64_le(f, &hardforks_len));
    if (hardforks_len > (1ULL << 20)) { /* sanity */
        return SOL_ERR_SNAPSHOT_CORRUPT;
    }

    uint64_t hardforks_bytes = 0;
    if (__builtin_mul_overflow(hardforks_len, 16ULL, &hardforks_bytes)) {
        return SOL_ERR_SNAPSHOT_CORRUPT;
    }
    SOL_TRY(file_skip(f, hardforks_bytes));

    /* Counts + config */
    uint64_t transaction_count = 0;
    uint64_t tick_height = 0;
    uint64_t signature_count = 0;
    SOL_TRY(file_read_u64_le(f, &transaction_count));
    SOL_TRY(file_read_u64_le(f, &tick_height));
    SOL_TRY(file_read_u64_le(f, &signature_count));
    (void)last_hash_index;
    (void)max_age;
    (void)transaction_count;
    (void)tick_height;

    /* For voting/bank-hash seeding we need the cumulative signature count. */
    fields.transaction_count = signature_count;

    SOL_TRY(file_read_u64_le(f, &fields.capitalization));
    SOL_TRY(file_read_u64_le(f, &fields.max_tick_height));

    /* hashes_per_tick: Option<u64> */
    uint8_t hashes_per_tick_tag = 0;
    SOL_TRY(file_read_u8(f, &hashes_per_tick_tag));
    if (hashes_per_tick_tag == 1) {
        SOL_TRY(file_read_u64_le(f, &fields.hashes_per_tick));
    } else if (hashes_per_tick_tag != 0) {
        return SOL_ERR_DECODE;
    }

    SOL_TRY(file_read_u64_le(f, &fields.ticks_per_slot));

    /* ns_per_slot (u128) */
    SOL_TRY(file_skip(f, 16));
    /* genesis_creation_time (i64) */
    SOL_TRY(file_skip(f, 8));
    /* slots_per_year (f64) */
    SOL_TRY(file_skip(f, 8));
    /* accounts_data_len (u64) */
    SOL_TRY(file_skip(f, 8));

    SOL_TRY(file_read_u64_le(f, (uint64_t*)&fields.slot));
    SOL_TRY(file_read_u64_le(f, &fields.epoch));
    SOL_TRY(file_read_u64_le(f, &fields.block_height));

    fields.lamports_per_signature =
        have_last_lamports_per_signature ? last_lamports_per_signature : 0;
    if (fields.lamports_per_signature == 0) {
        fields.lamports_per_signature = 5000;
    }
    fields.slots_per_epoch = SOL_SLOTS_PER_EPOCH;

    if (fields.slot != expected_slot) {
        return SOL_ERR_DECODE;
    }
    if (sol_hash_is_zero(&fields.hash) || fields.ticks_per_slot == 0 || fields.slots_per_epoch == 0) {
        return SOL_ERR_DECODE;
    }

    *out_fields = fields;
    return SOL_OK;
}

typedef struct {
    sol_slot_t          expected_slot;
    char                expected_slot_str[32];
    uint8_t*            prefix;
    size_t              prefix_cap;
    size_t              prefix_len;
    sol_bank_fields_t   fields;
    bool                have_fields;
} sol_bank_fields_archive_ctx_t;

static bool
rel_path_ends_with_slot(const char* rel_path, const char* slot_str) {
    if (!rel_path || !slot_str) return false;

    const char* last_slash = strrchr(rel_path, '/');
    const char* base = last_slash ? (last_slash + 1) : rel_path;
    return strcmp(base, slot_str) == 0;
}

static sol_err_t
bank_fields_archive_stream_chunk_cb(void* ctx,
                                    const char* rel_path,
                                    const uint8_t* data,
                                    size_t len,
                                    uint64_t file_size,
                                    uint64_t file_offset,
                                    bool is_last) {
    (void)file_size;

    sol_bank_fields_archive_ctx_t* st = (sol_bank_fields_archive_ctx_t*)ctx;
    if (!st) return SOL_ERR_INVAL;
    if (st->have_fields) return SOL_ERR_CANCELLED;
    if (!rel_path) return SOL_OK;

    /* Bank snapshot files live under snapshots/<slot>/... and are named <slot>.
     * Stream all archive files but only capture the bank file. */
    if (!rel_path_ends_with_slot(rel_path, st->expected_slot_str)) {
        return SOL_OK;
    }

    if (file_offset >= st->prefix_cap) {
        return SOL_ERR_TOO_LARGE;
    }

    size_t copy = len;
    if ((uint64_t)copy > st->prefix_cap - (size_t)file_offset) {
        copy = st->prefix_cap - (size_t)file_offset;
    }

    if (copy > 0 && data) {
        memcpy(st->prefix + (size_t)file_offset, data, copy);
    }

    size_t end = (size_t)file_offset + copy;
    if (end > st->prefix_len) st->prefix_len = end;

    /* Attempt to parse bank fields from the growing prefix. */
    sol_bank_fields_t fields = {0};

    sol_hash_t latest_blockhash = {0};
    const sol_hash_t* latest_blockhash_ptr = NULL;
    if (st->prefix_len >= (8u + 1u + SOL_HASH_SIZE)) {
        uint8_t tag = st->prefix[8];
        if (tag == 1) {
            memcpy(latest_blockhash.bytes, st->prefix + 9, SOL_HASH_SIZE);
            if (!sol_hash_is_zero(&latest_blockhash)) {
                latest_blockhash_ptr = &latest_blockhash;
            }
        }
    }

    sol_err_t perr = sol_bank_fields_deserialize_header(st->prefix, st->prefix_len, &fields);
    if (perr != SOL_OK || fields.slot != st->expected_slot) {
        fields = (sol_bank_fields_t){0};
        perr = sol_bank_fields_deserialize_agave_snapshot_prefix(
            st->prefix, st->prefix_len, st->expected_slot, &fields);
        if (perr != SOL_OK) {
            perr = sol_bank_fields_deserialize_solana_snapshot_v1_2_0(
                st->prefix, st->prefix_len, st->expected_slot, latest_blockhash_ptr, &fields);
        }
    }

    if (perr == SOL_OK && fields.slot == st->expected_slot) {
        st->fields = fields;
        st->have_fields = true;
        return SOL_ERR_CANCELLED;
    }

    if (is_last) {
        return SOL_ERR_DECODE;
    }

    return SOL_OK;
}

sol_err_t
sol_snapshot_read_bank_fields_from_archive(const char* archive_path,
                                           sol_slot_t expected_slot,
                                           sol_bank_fields_t* out_fields) {
    if (!archive_path || !out_fields || expected_slot == 0) return SOL_ERR_INVAL;

    sol_bank_fields_archive_ctx_t st = {0};
    st.expected_slot = expected_slot;
    snprintf(st.expected_slot_str, sizeof(st.expected_slot_str), "%lu",
             (unsigned long)expected_slot);
    st.prefix_cap = 16u * 1024u * 1024u;
    st.prefix = sol_alloc(st.prefix_cap);
    if (!st.prefix) return SOL_ERR_NOMEM;
    memset(st.prefix, 0, st.prefix_cap);

    char tmp_dir[256];
    snprintf(tmp_dir, sizeof(tmp_dir), "/tmp/solana_c_snapshot_bank_fields_XXXXXX");
    if (!mkdtemp(tmp_dir)) {
        sol_free(st.prefix);
        return SOL_ERR_IO;
    }

    char bank_prefix[128];
    snprintf(bank_prefix, sizeof(bank_prefix), "snapshots/%lu/",
             (unsigned long)expected_slot);

    sol_archive_extract_opts_t opts = SOL_ARCHIVE_EXTRACT_OPTS_DEFAULT;
    opts.output_dir = tmp_dir;
    opts.stream_prefix = bank_prefix;
    opts.stream_chunk_callback = bank_fields_archive_stream_chunk_cb;
    opts.stream_file_ctx = &st;
    opts.skip_unmatched = true;

    sol_err_t err = sol_snapshot_archive_extract(archive_path, &opts);
    if (err == SOL_ERR_CANCELLED && st.have_fields) {
        err = SOL_OK;
    }

    (void)sol_snapshot_archive_rmdir(tmp_dir);

    if (err == SOL_OK && st.have_fields) {
        *out_fields = st.fields;
    }
    if (err == SOL_OK && !st.have_fields) {
        err = SOL_ERR_NOTFOUND;
    }

    sol_free(st.prefix);
    return err;
}

typedef struct {
    sol_hash_t hash;
    uint64_t   lamports_per_signature;
    uint64_t   hash_index;
} sol_blockhash_queue_entry_t;

static int
sol_blockhash_queue_entry_cmp_desc_hash_index(const void* a, const void* b) {
    const sol_blockhash_queue_entry_t* ea = (const sol_blockhash_queue_entry_t*)a;
    const sol_blockhash_queue_entry_t* eb = (const sol_blockhash_queue_entry_t*)b;
    if (ea->hash_index < eb->hash_index) return 1;
    if (ea->hash_index > eb->hash_index) return -1;
    return 0;
}

static sol_err_t
parse_blockhash_queue_from_snapshot_prefix_bincode(const uint8_t* data,
                                                   size_t len,
                                                   sol_hash_t* out_hashes,
                                                   uint64_t* out_lamports_per_signature,
                                                   size_t out_cap,
                                                   size_t* out_len) {
    if (out_len) {
        *out_len = 0;
    }
    if (!data || !out_hashes || !out_lamports_per_signature || out_cap == 0 || !out_len) {
        return SOL_ERR_INVAL;
    }

    sol_decoder_t dec;
    sol_decoder_init(&dec, data, len);

    uint64_t last_hash_index = 0;
    sol_err_t err = sol_decode_u64(&dec, &last_hash_index);
    if (err != SOL_OK) return err;

    uint8_t last_hash_tag = 0;
    err = sol_decode_u8(&dec, &last_hash_tag);
    if (err != SOL_OK) return err;

    sol_hash_t last_hash = {0};
    bool have_last_hash = false;
    if (last_hash_tag == 1) {
        err = decode_hash32_bincode(&dec, &last_hash);
        if (err != SOL_OK) return err;
        have_last_hash = !sol_hash_is_zero(&last_hash);
    } else if (last_hash_tag != 0) {
        return SOL_ERR_DECODE;
    }

    uint64_t hashes_len_u64 = 0;
    err = sol_decode_u64(&dec, &hashes_len_u64);
    if (err != SOL_OK) return err;
    if (hashes_len_u64 > SOL_SNAPSHOT_MAX_BLOCKHASH_QUEUE_ENTRIES) {
        return SOL_ERR_SNAPSHOT_CORRUPT;
    }

    size_t hashes_len = (size_t)hashes_len_u64;
    sol_blockhash_queue_entry_t* entries = NULL;
    if (hashes_len > 0) {
        if (hashes_len > (SIZE_MAX / sizeof(*entries))) {
            return SOL_ERR_OVERFLOW;
        }
        entries = (sol_blockhash_queue_entry_t*)sol_alloc(hashes_len * sizeof(*entries));
        if (!entries) {
            return SOL_ERR_NOMEM;
        }
    }

    uint64_t last_hash_lamports = 0;
    bool have_last_hash_lamports = false;

    size_t entries_len = 0;
    for (size_t i = 0; i < hashes_len; i++) {
        sol_hash_t key = {0};
        err = decode_hash32_bincode(&dec, &key);
        if (err != SOL_OK) {
            sol_free(entries);
            return err;
        }

        uint64_t lamports_per_signature = 0;
        uint64_t hash_index = 0;
        uint64_t timestamp = 0;

        err = sol_decode_u64(&dec, &lamports_per_signature);
        if (err != SOL_OK) {
            sol_free(entries);
            return err;
        }
        err = sol_decode_u64(&dec, &hash_index);
        if (err != SOL_OK) {
            sol_free(entries);
            return err;
        }
        err = sol_decode_u64(&dec, &timestamp);
        if (err != SOL_OK) {
            sol_free(entries);
            return err;
        }
        (void)timestamp;

        if (entries) {
            entries[entries_len].hash = key;
            entries[entries_len].lamports_per_signature = lamports_per_signature;
            entries[entries_len].hash_index = hash_index;
            entries_len++;
        }

        if (have_last_hash && memcmp(key.bytes, last_hash.bytes, SOL_HASH_SIZE) == 0) {
            last_hash_lamports = lamports_per_signature;
            have_last_hash_lamports = true;
        }
    }

    uint64_t max_age_u64 = 0;
    err = sol_decode_u64(&dec, &max_age_u64);
    if (err != SOL_OK) {
        sol_free(entries);
        return err;
    }

    uint64_t max_age = max_age_u64;
    if (max_age == 0 || max_age > SOL_MAX_RECENT_BLOCKHASHES) {
        max_age = SOL_MAX_RECENT_BLOCKHASHES;
    }

    size_t keep = 0;
    for (size_t i = 0; i < entries_len; i++) {
        sol_blockhash_queue_entry_t e = entries[i];
        if (e.hash_index > last_hash_index) {
            continue;
        }
        uint64_t age = last_hash_index - e.hash_index;
        if (age <= max_age) {
            entries[keep++] = e;
        }
    }
    entries_len = keep;

    if (entries_len > 1) {
        qsort(entries, entries_len, sizeof(*entries), sol_blockhash_queue_entry_cmp_desc_hash_index);
    }

    size_t out_count = 0;
    if (have_last_hash && out_count < out_cap) {
        out_hashes[out_count] = last_hash;
        out_lamports_per_signature[out_count] = have_last_hash_lamports ? last_hash_lamports : 0;
        out_count++;
    }

    for (size_t i = 0; i < entries_len && out_count < out_cap; i++) {
        if (have_last_hash &&
            memcmp(entries[i].hash.bytes, last_hash.bytes, SOL_HASH_SIZE) == 0) {
            continue;
        }
        out_hashes[out_count] = entries[i].hash;
        out_lamports_per_signature[out_count] = entries[i].lamports_per_signature;
        out_count++;
    }

    sol_free(entries);

    if (out_count == 0) {
        return SOL_ERR_NOTFOUND;
    }

    *out_len = out_count;
    return SOL_OK;
}

typedef struct {
    sol_slot_t  expected_slot;
    char        expected_slot_str[32];
    uint8_t*    prefix;
    size_t      prefix_len;
    size_t      prefix_cap;
    sol_hash_t* out_hashes;
    uint64_t*   out_fees;
    size_t      out_cap;
    size_t      out_len;
    bool        have_queue;
} sol_blockhash_queue_archive_ctx_t;

static sol_err_t
blockhash_queue_archive_stream_chunk_cb(void* ctx,
                                        const char* rel_path,
                                        const uint8_t* data,
                                        size_t len,
                                        uint64_t file_size,
                                        uint64_t file_offset,
                                        bool is_last) {
    (void)file_size;

    sol_blockhash_queue_archive_ctx_t* st = (sol_blockhash_queue_archive_ctx_t*)ctx;
    if (!st) return SOL_ERR_INVAL;
    if (st->have_queue) return SOL_ERR_CANCELLED;
    if (!rel_path) return SOL_OK;

    if (!rel_path_ends_with_slot(rel_path, st->expected_slot_str)) {
        return SOL_OK;
    }

    if (file_offset >= st->prefix_cap) {
        return SOL_ERR_TOO_LARGE;
    }

    size_t copy = len;
    if ((uint64_t)copy > st->prefix_cap - (size_t)file_offset) {
        copy = st->prefix_cap - (size_t)file_offset;
    }

    if (copy > 0 && data) {
        memcpy(st->prefix + (size_t)file_offset, data, copy);
    }

    size_t end = (size_t)file_offset + copy;
    if (end > st->prefix_len) st->prefix_len = end;

    size_t parsed_len = 0;
    sol_err_t perr = parse_blockhash_queue_from_snapshot_prefix_bincode(st->prefix,
                                                                        st->prefix_len,
                                                                        st->out_hashes,
                                                                        st->out_fees,
                                                                        st->out_cap,
                                                                        &parsed_len);
    if (perr == SOL_OK && parsed_len > 0) {
        st->out_len = parsed_len;
        st->have_queue = true;
        return SOL_ERR_CANCELLED;
    }

    if (perr == SOL_ERR_NOMEM || perr == SOL_ERR_OVERFLOW) {
        return perr;
    }

    if (is_last) {
        return SOL_ERR_DECODE;
    }

    return SOL_OK;
}

sol_err_t
sol_snapshot_read_blockhash_queue_from_archive(const char* archive_path,
                                               sol_slot_t expected_slot,
                                               sol_hash_t* out_hashes,
                                               uint64_t* out_lamports_per_signature,
                                               size_t out_cap,
                                               size_t* out_len) {
    if (out_len) {
        *out_len = 0;
    }
    if (!archive_path || expected_slot == 0 || !out_hashes || !out_lamports_per_signature || out_cap == 0 || !out_len) {
        return SOL_ERR_INVAL;
    }

    sol_blockhash_queue_archive_ctx_t st = {0};
    st.expected_slot = expected_slot;
    snprintf(st.expected_slot_str, sizeof(st.expected_slot_str), "%lu", (unsigned long)expected_slot);
    st.prefix_cap = 4u * 1024u * 1024u;
    st.prefix = sol_alloc(st.prefix_cap);
    if (!st.prefix) return SOL_ERR_NOMEM;
    memset(st.prefix, 0, st.prefix_cap);
    st.prefix_len = 0;
    st.out_hashes = out_hashes;
    st.out_fees = out_lamports_per_signature;
    st.out_cap = out_cap;
    st.out_len = 0;
    st.have_queue = false;

    char tmp_dir[256];
    snprintf(tmp_dir, sizeof(tmp_dir), "/tmp/solana_c_snapshot_blockhash_queue_XXXXXX");
    if (!mkdtemp(tmp_dir)) {
        sol_free(st.prefix);
        return SOL_ERR_IO;
    }

    char bank_prefix[128];
    snprintf(bank_prefix, sizeof(bank_prefix), "snapshots/%lu/",
             (unsigned long)expected_slot);

    sol_archive_extract_opts_t opts = SOL_ARCHIVE_EXTRACT_OPTS_DEFAULT;
    opts.output_dir = tmp_dir;
    opts.stream_prefix = bank_prefix;
    opts.stream_chunk_callback = blockhash_queue_archive_stream_chunk_cb;
    opts.stream_file_ctx = &st;
    opts.skip_unmatched = true;

    sol_err_t err = sol_snapshot_archive_extract(archive_path, &opts);
    if (err == SOL_ERR_CANCELLED && st.have_queue) {
        err = SOL_OK;
    }

    (void)sol_snapshot_archive_rmdir(tmp_dir);

    if (err == SOL_OK && st.have_queue) {
        *out_len = st.out_len;
    }
    if (err == SOL_OK && !st.have_queue) {
        err = SOL_ERR_NOTFOUND;
    }

    sol_free(st.prefix);
    return err;
}

/*
 * Serialize account to storage format
 */
static size_t
serialize_account(const sol_account_t* account, const sol_pubkey_t* pubkey,
                  uint8_t* out, size_t max_len) {
    sol_stored_account_t stored = {0};

    stored.write_version = 1;
    stored.data_len = account->meta.data_len;
    if (pubkey) stored.pubkey = *pubkey;
    stored.owner = account->meta.owner;
    stored.lamports = account->meta.lamports;
    stored.rent_epoch = account->meta.rent_epoch;
    stored.executable = account->meta.executable;

    size_t total = sizeof(stored) + account->meta.data_len;
    if (total > max_len) return 0;

    memcpy(out, &stored, sizeof(stored));
    if (account->meta.data_len > 0 && account->data) {
        memcpy(out + sizeof(stored), account->data, account->meta.data_len);
    }

    return total;
}

/*
 * Serialize accounts to storage file
 */
size_t
sol_account_storage_serialize(const sol_account_t* accounts, size_t count,
                               sol_slot_t slot, uint64_t storage_id,
                               uint8_t* out_data, size_t max_len) {
    if (!accounts || !out_data || count == 0) return 0;

    sol_account_storage_header_t header = {
        .slot = slot,
        .id = storage_id,
        .count = count,
        .data_len = 0,
    };

    size_t offset = sizeof(header);

    /* Serialize each account */
    for (size_t i = 0; i < count; i++) {
        size_t written = serialize_account(&accounts[i], NULL,
                                           out_data + offset,
                                           max_len - offset);
        if (written == 0) return 0;
        offset += written;
        header.data_len += written;
    }

    /* Write header at beginning */
    memcpy(out_data, &header, sizeof(header));

    return offset;
}

/*
 * Deserialize accounts from storage file
 */
size_t
sol_account_storage_deserialize(const uint8_t* data, size_t len,
                                 sol_account_t* out_accounts, size_t max_count) {
    if (!data || !out_accounts || len < sizeof(sol_account_storage_header_t)) {
        return 0;
    }

    sol_account_storage_header_t header;
    memcpy(&header, data, sizeof(header));

    size_t offset = sizeof(header);
    size_t count = 0;

    while (offset < len && count < max_count && count < header.count) {
        if (offset + sizeof(sol_stored_account_t) > len) break;

        sol_stored_account_t stored;
        memcpy(&stored, data + offset, sizeof(stored));
        offset += sizeof(stored);

        if (offset + stored.data_len > len) break;

        sol_account_t* account = &out_accounts[count];
        /* Note: pubkey is stored separately, not in sol_account_t */
        account->meta.owner = stored.owner;
        account->meta.lamports = stored.lamports;
        account->meta.rent_epoch = stored.rent_epoch;
        account->meta.executable = stored.executable;
        account->meta.data_len = stored.data_len;

        if (stored.data_len > 0) {
            account->data = sol_alloc(stored.data_len);
            if (account->data) {
                memcpy(account->data, data + offset, stored.data_len);
            }
        } else {
            account->data = NULL;
        }

        offset += stored.data_len;
        count++;
    }

    return count;
}

static void
hash32_to_hex(const sol_hash_t* hash, char out[65]) {
    if (!hash || !out) return;
    for (size_t i = 0; i < SOL_HASH_SIZE; i++) {
        snprintf(out + (i * 2), 3, "%02x", hash->bytes[i]);
    }
    out[64] = '\0';
}

static bool
solana_snapshot_hash_compute(sol_slot_t slot,
                             uint64_t epoch,
                             uint64_t slots_per_epoch,
                             const sol_hash_t* accounts_hash,
                             const sol_hash_t* epoch_accounts_hash,
                             sol_hash_t* out_hash) {
    if (!accounts_hash || !out_hash) return false;

    *out_hash = *accounts_hash;

    /* Agave EAH snapshot hash behavior:
     * - If slot is in [start_slot, stop_slot), snapshot hash = SHA256(accounts_hash || epoch_accounts_hash)
     * - Otherwise snapshot hash = accounts_hash
     * See: external/agave/docs/src/implemented-proposals/epoch_accounts_hash.md */
    if (slots_per_epoch < 64 || slots_per_epoch == 0) {
        return true;
    }

    if (epoch > UINT64_MAX / slots_per_epoch) {
        return true;
    }
    uint64_t epoch_first = epoch * slots_per_epoch;

    uint64_t start_off = slots_per_epoch / 4ULL;
    uint64_t stop_off = (slots_per_epoch * 3ULL) / 4ULL;
    if (epoch_first > UINT64_MAX - stop_off) {
        return true;
    }

    sol_slot_t start_slot = (sol_slot_t)(epoch_first + start_off);
    sol_slot_t stop_slot = (sol_slot_t)(epoch_first + stop_off);

    if (slot >= start_slot && slot < stop_slot) {
        if (!epoch_accounts_hash || sol_hash_is_zero(epoch_accounts_hash)) {
            return false;
        }

        sol_sha256_ctx_t ctx;
        sol_sha256_init(&ctx);
        sol_sha256_update(&ctx, accounts_hash->bytes, SOL_HASH_SIZE);
        sol_sha256_update(&ctx, epoch_accounts_hash->bytes, SOL_HASH_SIZE);
        sol_sha256_final_bytes(&ctx, out_hash->bytes);
    }

    return true;
}

/*
 * Create full snapshot
 */
sol_err_t
sol_snapshot_create_full(sol_snapshot_mgr_t* mgr,
                          const sol_bank_t* bank,
                          sol_accounts_db_t* accounts_db,
                          sol_snapshot_info_t* out_info) {
    (void)accounts_db;  /* Will be used when full account serialization is implemented */
    if (!mgr || !bank) return SOL_ERR_INVAL;
    if (!mgr->snapshot_dir || !mgr->archive_dir) return SOL_ERR_UNINITIALIZED;

    sol_slot_t slot = sol_bank_slot(bank);
    sol_hash_t hash = {0};
    sol_bank_compute_hash((sol_bank_t*)bank, &hash);

    /* Create working directory structure */
    char work_dir[512];
    snprintf(work_dir, sizeof(work_dir), "%s/tmp-%lu",
             mgr->snapshot_dir, (unsigned long)slot);
    mkdir(work_dir, 0755);

    sol_err_t err = create_snapshot_dirs(work_dir, slot);
    if (err != SOL_OK) return err;

    /* Serialize bank fields */
    char bank_path[512];
    snprintf(bank_path, sizeof(bank_path),
             "%s/snapshots/%lu/%lu",
             work_dir, (unsigned long)slot, (unsigned long)slot);

    uint8_t bank_data[4096];
    size_t bank_len = sol_bank_fields_serialize(bank, bank_data, sizeof(bank_data));
    if (bank_len == 0) return SOL_ERR_IO;

    FILE* f = fopen(bank_path, "wb");
    if (!f) return SOL_ERR_IO;
    fwrite(bank_data, 1, bank_len, f);
    fclose(f);

    /* Write version file */
    char version_path[512];
    snprintf(version_path, sizeof(version_path), "%s/version", work_dir);
    f = fopen(version_path, "w");
    if (f) {
        fprintf(f, "%s\n", SOL_SNAPSHOT_ARCHIVE_VERSION);
        fclose(f);
    }

    /* Write manifest (best-effort) */
    sol_hash_t accounts_hash = {0};
    if (accounts_db) {
        sol_accounts_db_hash(accounts_db, &accounts_hash);

        char manifest_path[512];
        snprintf(manifest_path, sizeof(manifest_path), "%s/manifest", work_dir);
        f = fopen(manifest_path, "w");
        if (f) {
            char hex[65];
            hash32_to_hex(&accounts_hash, hex);
            fprintf(f, "format=solana-c\n");
            fprintf(f, "slot=%lu\n", (unsigned long)slot);
            fprintf(f, "accounts_hash=%s\n", hex);
            fclose(f);
        }
    }

    /* Populate output info */
    if (out_info) {
        out_info->slot = slot;
        out_info->hash = hash;
        out_info->bank_hash = hash;
        out_info->accounts_hash = accounts_hash;
        out_info->manifest_is_solana_c = true;
        out_info->base_slot = 0;
        memset(&out_info->base_hash, 0, sizeof(sol_hash_t));
        out_info->type = SOL_SNAPSHOT_FULL;
        out_info->lamports_per_signature = 5000;
        out_info->epoch = sol_bank_epoch(bank);
        out_info->block_height = sol_bank_tick_height(bank) / 64;
        out_info->capitalization = sol_bank_capitalization(bank);
        out_info->num_accounts = accounts_db ? sol_accounts_db_count(accounts_db) : 0;
        out_info->compression = mgr->config.compression;
    }

    sol_log_info("Created full snapshot at slot %lu", (unsigned long)slot);

    return SOL_OK;
}

/*
 * Create incremental snapshot
 */
sol_err_t
sol_snapshot_create_incremental(sol_snapshot_mgr_t* mgr,
                                 const sol_bank_t* bank,
                                 sol_accounts_db_t* accounts_db,
                                 sol_slot_t base_slot,
                                 sol_snapshot_info_t* out_info) {
    if (!mgr || !bank) return SOL_ERR_INVAL;
    if (!mgr->snapshot_dir || !mgr->archive_dir) return SOL_ERR_UNINITIALIZED;

    sol_slot_t slot = sol_bank_slot(bank);
    sol_hash_t hash = {0};
    sol_bank_compute_hash((sol_bank_t*)bank, &hash);

    if (slot <= base_slot) return SOL_ERR_INVAL;

    /* Create working directory */
    char work_dir[512];
    snprintf(work_dir, sizeof(work_dir), "%s/inc-tmp-%lu-%lu",
             mgr->snapshot_dir, (unsigned long)base_slot, (unsigned long)slot);
    mkdir(work_dir, 0755);

    sol_err_t err = create_snapshot_dirs(work_dir, slot);
    if (err != SOL_OK) return err;

    /* Serialize bank fields */
    char bank_path[512];
    snprintf(bank_path, sizeof(bank_path),
             "%s/snapshots/%lu/%lu",
             work_dir, (unsigned long)slot, (unsigned long)slot);

    uint8_t bank_data[4096];
    size_t bank_len = sol_bank_fields_serialize(bank, bank_data, sizeof(bank_data));
    if (bank_len == 0) return SOL_ERR_IO;

    FILE* f = fopen(bank_path, "wb");
    if (!f) return SOL_ERR_IO;
    fwrite(bank_data, 1, bank_len, f);
    fclose(f);

    /* Write manifest (best-effort) */
    sol_hash_t accounts_hash = {0};
    if (accounts_db) {
        sol_accounts_db_hash(accounts_db, &accounts_hash);

        char manifest_path[512];
        snprintf(manifest_path, sizeof(manifest_path), "%s/manifest", work_dir);
        f = fopen(manifest_path, "w");
        if (f) {
            char hex[65];
            hash32_to_hex(&accounts_hash, hex);
            fprintf(f, "format=solana-c\n");
            fprintf(f, "slot=%lu\n", (unsigned long)slot);
            fprintf(f, "base_slot=%lu\n", (unsigned long)base_slot);
            fprintf(f, "accounts_hash=%s\n", hex);
            fclose(f);
        }
    }

    /* Populate output info */
    if (out_info) {
        out_info->slot = slot;
        out_info->hash = hash;
        out_info->bank_hash = hash;
        out_info->accounts_hash = accounts_hash;
        out_info->manifest_is_solana_c = true;
        out_info->base_slot = base_slot;
        memset(&out_info->base_hash, 0, sizeof(sol_hash_t));
        out_info->type = SOL_SNAPSHOT_INCREMENTAL;
        out_info->epoch = sol_bank_epoch(bank);
        out_info->block_height = sol_bank_tick_height(bank) / 64;
        out_info->num_accounts = accounts_db ? sol_accounts_db_count(accounts_db) : 0;
        out_info->compression = mgr->config.compression;
    }

    sol_log_info("Created incremental snapshot at slot %lu (base: %lu)",
                 (unsigned long)slot, (unsigned long)base_slot);

    return SOL_OK;
}

/*
 * Load accounts from an extracted snapshot directory
 */
static bool
parse_slot_id_from_filename(const char* name, uint64_t* out_slot, uint64_t* out_id) {
    if (!name || !out_slot || !out_id) return false;
    const char* dot = strchr(name, '.');
    if (!dot) return false;

    char* end = NULL;
    errno = 0;
    unsigned long long slot = strtoull(name, &end, 10);
    if (errno != 0 || end != dot) return false;

    errno = 0;
    unsigned long long id = strtoull(dot + 1, &end, 10);
    if (errno != 0 || end == dot + 1 || *end != '\0') return false;

    *out_slot = (uint64_t)slot;
    *out_id = (uint64_t)id;
    return true;
}

static size_t
align_up_8(size_t x) {
    return (x + 7u) & ~(size_t)7u;
}

static uint64_t
now_ms_monotonic(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static uint32_t
default_snapshot_load_threads(void) {
    const char* env = getenv("SOL_SNAPSHOT_LOAD_THREADS");
    if (env && env[0] != '\0') {
        char* end = NULL;
        errno = 0;
        unsigned long v = strtoul(env, &end, 10);
        if (errno == 0 && end && end != env) {
            while (*end && isspace((unsigned char)*end)) end++;
            if (*end == '\0' && v > 0 && v <= 1024) {
                return (uint32_t)v;
            }
        }
    }

    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n <= 0) return 1;

    uint32_t threads = (uint32_t)n;
    if (threads == 0) threads = 1;
    /* Default thread cap: snapshot ingestion is typically bottlenecked on
     * AccountsDB write throughput. On validator-grade hardware, higher
     * concurrency helps, but cap to avoid pathological contention.
     * Override with SOL_SNAPSHOT_LOAD_THREADS if you want to experiment. */
    uint32_t cap = 32u;
    if (threads >= 96u) {
        cap = 96u;
    } else if (threads >= 64u) {
        cap = 64u;
    } else if (threads >= 48u) {
        cap = 48u;
    } else if (threads >= 32u) {
        cap = 32u;
    } else {
        cap = threads;
    }
    if (threads > cap) threads = cap;
    return threads;
}

static size_t
default_snapshot_load_max_bytes_per_thread(uint32_t threads) {
    const char* env = getenv("SOL_SNAPSHOT_LOAD_MAX_BYTES_PER_THREAD_MB");
    if (env && env[0] != '\0') {
        char* end = NULL;
        errno = 0;
        unsigned long v = strtoul(env, &end, 10);
        if (errno == 0 && end && end != env) {
            while (*end && isspace((unsigned char)*end)) end++;
            if (*end == '\0' && v > 0 && v <= 16384UL) {
                return (size_t)v * 1024u * 1024u;
            }
        }
    }

    if (threads == 0) threads = 1;

    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGESIZE);
    if (pages <= 0 || page_size <= 0) {
        return 256u * 1024u * 1024u;
    }

    uint64_t total = (uint64_t)pages * (uint64_t)page_size;
    if (total == 0) {
        return 256u * 1024u * 1024u;
    }

    /* Use a bounded fraction of physical memory as the write-batch budget.
     * Keeps memory usage sane across different machines while still allowing
     * high-throughput ingestion on validator-grade hardware. */
    uint64_t budget = total / 6u; /* ~16.7% of RAM */
    uint64_t max_budget = 96ull * 1024ull * 1024ull * 1024ull;
    if (budget > max_budget) budget = max_budget;

    uint64_t per = budget / threads;
    uint64_t min_per = 32ull * 1024ull * 1024ull;
    uint64_t max_per = 1024ull * 1024ull * 1024ull;
    if (per < min_per) per = min_per;
    if (per > max_per) per = max_per;

    return (size_t)per;
}

static size_t
snapshot_env_size_t(const char* name, size_t min, size_t max) {
    if (!name || min > max) return 0;
    const char* env = getenv(name);
    if (!env || env[0] == '\0') return 0;
    char* end = NULL;
    errno = 0;
    unsigned long long v = strtoull(env, &end, 10);
    if (errno != 0 || !end || end == env) return 0;
    while (*end && isspace((unsigned char)*end)) end++;
    if (*end != '\0') return 0;
    if (v < (unsigned long long)min || v > (unsigned long long)max) return 0;
    return (size_t)v;
}

typedef enum {
    STORAGE_RECORD_LAYOUT_LEGACY = 0, /* write_version, data_len, pubkey, owner, lamports, rent_epoch, executable */
    STORAGE_RECORD_LAYOUT_SOLANA = 1, /* write_version, pubkey, data_len, lamports, owner, executable, rent_epoch */
    STORAGE_RECORD_LAYOUT_SOLANA2 = 2, /* write_version, data_len, pubkey, lamports, owner, executable, rent_epoch */
    STORAGE_RECORD_LAYOUT_SOLANA3 = 3, /* write_version, data_len, pubkey, lamports, rent_epoch, owner, executable */
} storage_record_layout_t;

typedef struct {
    bool                  valid;
    size_t                start_offset;
    storage_record_layout_t layout;
    size_t                record_size;
    bool                  align_after_data;
} storage_parse_cache_t;

static SOL_THREAD_LOCAL storage_parse_cache_t g_storage_parse_cache = {0};
/* Whether the 32-byte appendvec "meta" suffix contains the Solana account hash.
 * -1: unknown (validate on first use)
 *  0: disabled (meta did not match computed hash)
 *  1: enabled  (meta matched computed hash) */
static int g_appendvec_meta_hash_mode = -1;

static bool
parse_stored_account_record(const uint8_t* data,
                            size_t file_size,
                            size_t offset,
                            storage_record_layout_t layout,
                            sol_stored_account_t* out) {
    if (!data || !out) return false;
    if (offset > file_size || file_size - offset < sizeof(sol_stored_account_t)) return false;

    const uint8_t* p = data + offset;
    sol_stored_account_t* stored = out;

    switch (layout) {
    case STORAGE_RECORD_LAYOUT_LEGACY: {
        memcpy(&stored->write_version, p + 0, sizeof(stored->write_version));
        memcpy(&stored->data_len, p + 8, sizeof(stored->data_len));
        if (stored->data_len > SOL_ACCOUNT_MAX_DATA_SIZE) return false;
        memcpy(&stored->pubkey, p + 16, sizeof(stored->pubkey));
        memcpy(&stored->owner, p + 48, sizeof(stored->owner));
        memcpy(&stored->lamports, p + 80, sizeof(stored->lamports));
        memcpy(&stored->rent_epoch, p + 88, sizeof(stored->rent_epoch));

        uint8_t exec = p[96];
        if (exec > 1) return false;
        stored->executable = (exec != 0);
        break;
    }
    case STORAGE_RECORD_LAYOUT_SOLANA: {
        memcpy(&stored->write_version, p + 0, sizeof(stored->write_version));
        memcpy(&stored->pubkey, p + 8, sizeof(stored->pubkey));
        memcpy(&stored->data_len, p + 40, sizeof(stored->data_len));
        if (stored->data_len > SOL_ACCOUNT_MAX_DATA_SIZE) return false;
        memcpy(&stored->lamports, p + 48, sizeof(stored->lamports));
        memcpy(&stored->owner, p + 56, sizeof(stored->owner));

        uint8_t exec = p[88];
        if (exec > 1) return false;
        stored->executable = (exec != 0);

        memcpy(&stored->rent_epoch, p + 96, sizeof(stored->rent_epoch));
        break;
    }
    case STORAGE_RECORD_LAYOUT_SOLANA2: {
        memcpy(&stored->write_version, p + 0, sizeof(stored->write_version));
        memcpy(&stored->data_len, p + 8, sizeof(stored->data_len));
        if (stored->data_len > SOL_ACCOUNT_MAX_DATA_SIZE) return false;
        memcpy(&stored->pubkey, p + 16, sizeof(stored->pubkey));
        memcpy(&stored->lamports, p + 48, sizeof(stored->lamports));
        memcpy(&stored->owner, p + 56, sizeof(stored->owner));

        uint8_t exec = p[88];
        if (exec > 1) return false;
        stored->executable = (exec != 0);

        memcpy(&stored->rent_epoch, p + 96, sizeof(stored->rent_epoch));
        break;
    }
    case STORAGE_RECORD_LAYOUT_SOLANA3: {
        memcpy(&stored->write_version, p + 0, sizeof(stored->write_version));
        memcpy(&stored->data_len, p + 8, sizeof(stored->data_len));
        if (stored->data_len > SOL_ACCOUNT_MAX_DATA_SIZE) return false;
        memcpy(&stored->pubkey, p + 16, sizeof(stored->pubkey));
        memcpy(&stored->lamports, p + 48, sizeof(stored->lamports));
        memcpy(&stored->rent_epoch, p + 56, sizeof(stored->rent_epoch));
        memcpy(&stored->owner, p + 64, sizeof(stored->owner));

        uint8_t exec = p[96];
        if (exec > 1) return false;
        stored->executable = (exec != 0);
        break;
    }
    default:
        return false;
    }

    /* Treat an all-zero header as end-of-used-region padding. Solana AppendVec
     * files can have preallocated trailing bytes that are zeroed/sparse; parsing
     * those as real records causes enormous amounts of useless work (typically
     * repeated tombstones for the all-zero pubkey). */
    if (stored->write_version == 0 &&
        stored->data_len == 0 &&
        stored->lamports == 0 &&
        stored->rent_epoch == 0 &&
        !stored->executable) {
        bool pubkey_zero = true;
        bool owner_zero = true;
        for (size_t i = 0; i < sizeof(stored->pubkey.bytes); i++) {
            if (stored->pubkey.bytes[i] != 0) {
                pubkey_zero = false;
                break;
            }
        }
        for (size_t i = 0; i < sizeof(stored->owner.bytes); i++) {
            if (stored->owner.bytes[i] != 0) {
                owner_zero = false;
                break;
            }
        }
        if (pubkey_zero && owner_zero) {
            return false;
        }
    }

    return true;
}

static uint64_t
scan_storage_records(const uint8_t* data,
                     size_t file_size,
                     size_t start_offset,
                     uint64_t max_records,
                     storage_record_layout_t layout,
                     size_t record_size,
                     bool align_after_data,
                     uint64_t max_scan) {
    uint64_t scanned = 0;
    uint64_t nonzero_data = 0;
    size_t offset = start_offset;

    while (scanned < max_records &&
           scanned < max_scan &&
           offset <= file_size &&
           file_size - offset >= record_size) {
        sol_stored_account_t stored;
        if (!parse_stored_account_record(data, file_size, offset, layout, &stored)) break;
        offset += record_size;

        if (stored.data_len > (uint64_t)(file_size - offset)) break;

        if (stored.data_len != 0) nonzero_data++;

        offset += (size_t)stored.data_len;
        if (align_after_data) {
            offset = align_up_8(offset);
        }

        scanned++;
    }

    /* Weighted score: prefer layouts that both scan more records AND produce
     * plausible (non-zero) data lengths. */
    return (scanned * 100u) + nonzero_data;
}

static sol_err_t
load_accounts_from_storage_mapped(const uint8_t* data,
                                 size_t file_size,
                                 const char* file_name,
                                 sol_slot_t slot_hint,
                                 sol_accounts_db_t* accounts_db,
                                 sol_accounts_db_bulk_writer_t* bulk_writer,
                                 snapshot_appendvec_index_t* appendvec_index,
                                 uint64_t* out_count) {
    if (!data || file_size == 0 || !accounts_db) return SOL_ERR_INVAL;
    if (out_count) *out_count = 0;

    uint64_t loaded = 0;

    /* Detect our header format: [slot,id,count,data_len]. */
    bool has_header = false;
    sol_account_storage_header_t header = {0};
    if (file_size >= sizeof(header)) {
        memcpy(&header, data, sizeof(header));

        bool plausible = true;
        if (header.count == 0) plausible = false;
        if (header.data_len > file_size) plausible = false;
        if (header.data_len > (file_size - sizeof(sol_account_storage_header_t))) plausible = false;
        if (header.count > (uint64_t)(file_size / (sizeof(sol_stored_account_t) + 1))) plausible = false;

        uint64_t name_slot = 0, name_id = 0;
        if (file_name && parse_slot_id_from_filename(file_name, &name_slot, &name_id)) {
            if (header.slot != name_slot || header.id != name_id) plausible = false;
        }

        /* Validate by actually scanning at least one record after the header. */
        if (plausible) {
            uint64_t score_no_align = scan_storage_records(
                data, file_size, sizeof(sol_account_storage_header_t), header.count,
                STORAGE_RECORD_LAYOUT_LEGACY, sizeof(sol_stored_account_t), false, 1);
            uint64_t score_align = scan_storage_records(
                data, file_size, sizeof(sol_account_storage_header_t), header.count,
                STORAGE_RECORD_LAYOUT_LEGACY, sizeof(sol_stored_account_t), true, 1);
            has_header = (score_no_align > 0 || score_align > 0);
        }
    }

    typedef struct {
        size_t                start_offset;
        uint64_t              max_records;
        storage_record_layout_t layout;
        size_t                record_size;
        bool                  align_after_data;
        uint64_t              score;
    } storage_parse_plan_t;

    storage_parse_plan_t best = {0};

    /* Fast path for Solana mainnet snapshots: modern AppendVec layout.
     *
     * Real Solana snapshots typically store account appendvec files as
     * <slot>.<id> with a per-record 32-byte metadata suffix and 8-byte data
     * alignment. Falling back to heuristic detection for these files is more
     * expensive and can mis-detect in the presence of repeated/zeroed padding. */
    uint64_t name_slot = 0;
    uint64_t name_id = 0;
    if (!has_header && file_name && parse_slot_id_from_filename(file_name, &name_slot, &name_id)) {
        if (g_storage_parse_cache.valid) {
            uint64_t score = scan_storage_records(
                data,
                file_size,
                g_storage_parse_cache.start_offset,
                UINT64_MAX,
                g_storage_parse_cache.layout,
                g_storage_parse_cache.record_size,
                g_storage_parse_cache.align_after_data,
                16);
            uint64_t scanned = score / 100u;
            uint64_t nonzero = score % 100u;
            if (scanned >= 8 && nonzero > 0) {
                best.start_offset = g_storage_parse_cache.start_offset;
                best.max_records = UINT64_MAX;
                best.layout = g_storage_parse_cache.layout;
                best.record_size = g_storage_parse_cache.record_size;
                best.align_after_data = g_storage_parse_cache.align_after_data;
                best.score = score;
            }
        }

        size_t record_size = sizeof(sol_stored_account_t) + 32u;
        uint64_t score = scan_storage_records(
            data,
            file_size,
            0,
            UINT64_MAX,
            STORAGE_RECORD_LAYOUT_SOLANA3,
            record_size,
            true,
            16);
        /* Only take the fast-path if we can parse a meaningful prefix. Small
         * synthetic fixtures (unit tests) may legitimately use other layouts. */
        uint64_t scanned = score / 100u;
        if (scanned >= 8) {
            best.start_offset = 0;
            best.max_records = UINT64_MAX;
            best.layout = STORAGE_RECORD_LAYOUT_SOLANA3;
            best.record_size = record_size;
            best.align_after_data = true;
            best.score = score;
        }
    }

    typedef struct {
        size_t   start_offset;
        uint64_t max_records;
        bool     is_header;
    } storage_candidate_t;

    storage_candidate_t candidates[4];
    size_t cand_count = 0;

    if (best.score == 0 && has_header) {
        /* If we positively detected our header format, only consider parsing
         * records from immediately after the header. */
        candidates[cand_count++] = (storage_candidate_t){
            .start_offset = sizeof(sol_account_storage_header_t),
            .max_records = header.count,
            .is_header = true,
        };
    } else if (best.score == 0) {
        candidates[cand_count++] = (storage_candidate_t){ .start_offset = 0, .max_records = UINT64_MAX, .is_header = false };
        if (file_size > 8) {
            candidates[cand_count++] = (storage_candidate_t){ .start_offset = 8, .max_records = UINT64_MAX, .is_header = false };
        }
        if (file_size > 16) {
            candidates[cand_count++] = (storage_candidate_t){ .start_offset = 16, .max_records = UINT64_MAX, .is_header = false };
        }
    }

    for (size_t i = 0; i < cand_count; i++) {
        const storage_record_layout_t layouts[] = {
            STORAGE_RECORD_LAYOUT_LEGACY,
            STORAGE_RECORD_LAYOUT_SOLANA,
            STORAGE_RECORD_LAYOUT_SOLANA2,
            STORAGE_RECORD_LAYOUT_SOLANA3,
        };
        const size_t record_sizes[] = {
            sizeof(sol_stored_account_t),
            sizeof(sol_stored_account_t) + 32u, /* Newer Solana AppendVec layouts include extra metadata. */
        };
        for (size_t ri = 0; ri < (sizeof(record_sizes) / sizeof(record_sizes[0])); ri++) {
            size_t record_size = record_sizes[ri];

            for (size_t li = 0; li < (sizeof(layouts) / sizeof(layouts[0])); li++) {
                storage_record_layout_t layout = layouts[li];
                uint64_t score_no_align = scan_storage_records(
                    data, file_size, candidates[i].start_offset, candidates[i].max_records,
                    layout, record_size, false, 16);
                uint64_t score_align = scan_storage_records(
                    data, file_size, candidates[i].start_offset, candidates[i].max_records,
                    layout, record_size, true, 16);

                bool align_after_data = false;
                uint64_t score = score_no_align;
                if (score_align > score_no_align) {
                    align_after_data = true;
                    score = score_align;
                } else if (score_no_align > score_align) {
                    align_after_data = false;
                    score = score_no_align;
                } else {
                    /* Tie: prefer alignment for headerless formats, no-align for our headered format. */
                    align_after_data = !candidates[i].is_header;
                    score = score_no_align;
                }

                if (score > best.score) {
                    best.start_offset = candidates[i].start_offset;
                    best.max_records = candidates[i].max_records;
                    best.layout = layout;
                    best.record_size = record_size;
                    best.align_after_data = align_after_data;
                    best.score = score;
                } else if (score == best.score && score > 0) {
                    /* Stable tie-break: prefer header, then offset 0, then Solana layout for headerless. */
                    bool best_is_header = (has_header && best.start_offset == sizeof(sol_account_storage_header_t));
                    if (candidates[i].is_header && !best_is_header) {
                        best.start_offset = candidates[i].start_offset;
                        best.max_records = candidates[i].max_records;
                        best.layout = layout;
                        best.record_size = record_size;
                        best.align_after_data = align_after_data;
                        best.score = score;
                    } else if (!candidates[i].is_header && !best_is_header) {
                        if (candidates[i].start_offset == 0 && best.start_offset == 8) {
                            best.start_offset = candidates[i].start_offset;
                            best.max_records = candidates[i].max_records;
                            best.layout = layout;
                            best.record_size = record_size;
                            best.align_after_data = align_after_data;
                            best.score = score;
                        } else if (candidates[i].start_offset == best.start_offset &&
                                   layout != STORAGE_RECORD_LAYOUT_LEGACY &&
                                   best.layout == STORAGE_RECORD_LAYOUT_LEGACY) {
                            best.start_offset = candidates[i].start_offset;
                            best.max_records = candidates[i].max_records;
                            best.layout = layout;
                            best.record_size = record_size;
                            best.align_after_data = align_after_data;
                            best.score = score;
                        }
                    }
                }
            }
        }
    }

    if (best.score == 0) {
        if (out_count) *out_count = 0;
        return SOL_ERR_NOTFOUND;
    }

    sol_slot_t storage_slot = slot_hint;
    if (has_header) {
        storage_slot = (sol_slot_t)header.slot;
    }

    uint64_t file_key = 0;
    if (file_name) {
        if (strcmp(file_name, "storage.bin") == 0) {
            file_key = 0;
        } else {
            uint64_t fs = 0;
            uint64_t fid = 0;
            if (parse_slot_id_from_filename(file_name, &fs, &fid)) {
                file_key = (fs << 32) | (fid & 0xFFFFFFFFu);
            }
        }
    }

    size_t offset = best.start_offset;
    uint64_t max_records = best.max_records;
    storage_record_layout_t record_layout = best.layout;
    size_t record_size = best.record_size ? best.record_size : sizeof(sol_stored_account_t);
    bool align_after_data = best.align_after_data;

    while (loaded < max_records && offset + record_size <= file_size) {
        size_t record_start = offset;
        sol_stored_account_t stored;
        if (!parse_stored_account_record(data, file_size, offset, record_layout, &stored)) break;
        offset += record_size;

        if (stored.data_len > (uint64_t)(file_size - offset)) break;

        sol_err_t store_err = SOL_OK;
        if (appendvec_index) {
            /* In deferred-index mode, build the final pubkey->appendvec-ref map
             * in memory and only bulk-write it to RocksDB once after all
             * storage files are processed. */
            const uint8_t* account_data = (stored.data_len > 0) ? (data + offset) : NULL;

            sol_hash_t leaf_hash_computed = {0};
            const sol_hash_t* leaf_hash = NULL;
            sol_hash_t leaf_hash_tmp = {0};

            if (stored.lamports != 0 &&
                record_layout == STORAGE_RECORD_LAYOUT_SOLANA3 &&
                record_size == (sizeof(sol_stored_account_t) + 32u) &&
                (record_start + sizeof(sol_stored_account_t) + 32u) <= file_size) {
                memcpy(leaf_hash_tmp.bytes, data + record_start + sizeof(sol_stored_account_t), 32);

                if (!sol_hash_is_zero(&leaf_hash_tmp)) {
                    int mode = __atomic_load_n(&g_appendvec_meta_hash_mode, __ATOMIC_ACQUIRE);
                    if (mode == -1) {
                        sol_account_t account = {0};
                        account.meta.owner = stored.owner;
                        account.meta.lamports = stored.lamports;
                        account.meta.rent_epoch = stored.rent_epoch;
                        account.meta.executable = stored.executable;
                        account.meta.data_len = stored.data_len;
                        account.data = (uint8_t*)account_data;

                        sol_hash_t computed = {0};
                        sol_account_hash(&stored.pubkey, &account, &computed);

                        int decided = (memcmp(computed.bytes, leaf_hash_tmp.bytes, SOL_HASH_SIZE) == 0) ? 1 : 0;
                        int expected = -1;
                        if (__atomic_compare_exchange_n(&g_appendvec_meta_hash_mode,
                                                       &expected,
                                                       decided,
                                                       false,
                                                       __ATOMIC_RELEASE,
                                                       __ATOMIC_RELAXED)) {
                            if (decided == 0) {
                                sol_log_warn("Snapshot appendvec metadata hash did not match computed account hash; "
                                             "re-hashing accounts during ingestion");
                            }
                        }

                        mode = __atomic_load_n(&g_appendvec_meta_hash_mode, __ATOMIC_ACQUIRE);
                    }

                    if (mode == 1) {
                        leaf_hash = &leaf_hash_tmp;
                    }
                }
            }

            if (stored.lamports != 0 && (!leaf_hash || sol_hash_is_zero(leaf_hash))) {
                sol_account_t account = {0};
                account.meta.owner = stored.owner;
                account.meta.lamports = stored.lamports;
                account.meta.rent_epoch = stored.rent_epoch;
                account.meta.executable = stored.executable;
                account.meta.data_len = stored.data_len;
                account.data = (uint8_t*)account_data;
                sol_account_hash(&stored.pubkey, &account, &leaf_hash_computed);
                leaf_hash = &leaf_hash_computed;
            }

            uint64_t idx_file_key = file_key;
            uint64_t idx_record_off = (uint64_t)record_start;
            if (stored.lamports == 0) {
                idx_file_key = 0;
                idx_record_off = 0;
            }

            store_err = snapshot_appendvec_index_update(appendvec_index,
                                                        &stored.pubkey,
                                                        storage_slot,
                                                        stored.write_version,
                                                        &stored.owner,
                                                        stored.lamports,
                                                        stored.data_len,
                                                        idx_file_key,
                                                        idx_record_off,
                                                        leaf_hash);
        } else if (bulk_writer) {
            const uint8_t* account_data = (stored.data_len > 0) ? (data + offset) : NULL;
            const sol_hash_t* leaf_hash = NULL;
            sol_hash_t leaf_hash_tmp = {0};

            /* Modern Solana AppendVec files (layout SOLANA3 + record_size=header+32)
             * store a 32-byte account hash in the metadata suffix. Use it to
             * avoid re-hashing large account data during snapshot ingestion. */
            if (stored.lamports != 0 &&
                record_layout == STORAGE_RECORD_LAYOUT_SOLANA3 &&
                record_size == (sizeof(sol_stored_account_t) + 32u) &&
                (record_start + sizeof(sol_stored_account_t) + 32u) <= file_size) {
                memcpy(leaf_hash_tmp.bytes, data + record_start + sizeof(sol_stored_account_t), 32);

                if (!sol_hash_is_zero(&leaf_hash_tmp)) {
                    int mode = __atomic_load_n(&g_appendvec_meta_hash_mode, __ATOMIC_ACQUIRE);
                    if (mode == -1) {
                        sol_account_t account = {0};
                        account.meta.owner = stored.owner;
                        account.meta.lamports = stored.lamports;
                        account.meta.rent_epoch = stored.rent_epoch;
                        account.meta.executable = stored.executable;
                        account.meta.data_len = stored.data_len;
                        account.data = (uint8_t*)account_data;

                        sol_hash_t computed = {0};
                        sol_account_hash(&stored.pubkey, &account, &computed);

                        int decided = (memcmp(computed.bytes, leaf_hash_tmp.bytes, SOL_HASH_SIZE) == 0) ? 1 : 0;
                        int expected = -1;
                        if (__atomic_compare_exchange_n(&g_appendvec_meta_hash_mode,
                                                       &expected,
                                                       decided,
                                                       false,
                                                       __ATOMIC_RELEASE,
                                                       __ATOMIC_RELAXED)) {
                            if (decided == 0) {
                                sol_log_warn("Snapshot appendvec metadata hash did not match computed account hash; "
                                             "re-hashing accounts during ingestion");
                            }
                        }

                        mode = __atomic_load_n(&g_appendvec_meta_hash_mode, __ATOMIC_ACQUIRE);
                    }

                    if (mode == 1) {
                        leaf_hash = &leaf_hash_tmp;
                    }
                }
            }

            store_err = sol_accounts_db_bulk_writer_put_snapshot_account(bulk_writer,
                                                                         &stored.pubkey,
                                                                         &stored.owner,
                                                                         stored.lamports,
                                                                         account_data,
                                                                         stored.data_len,
                                                                         stored.executable,
                                                                         stored.rent_epoch,
                                                                         storage_slot,
                                                                         stored.write_version,
                                                                         leaf_hash,
                                                                         file_key,
                                                                         (uint64_t)record_start);
        } else {
            sol_account_t account = {0};
            account.meta.owner = stored.owner;
            account.meta.lamports = stored.lamports;
            account.meta.rent_epoch = stored.rent_epoch;
            account.meta.executable = stored.executable;
            account.meta.data_len = stored.data_len;
            account.data = (stored.data_len > 0) ? (uint8_t*)(data + offset) : NULL;

            store_err = sol_accounts_db_store_versioned(accounts_db,
                                                        &stored.pubkey,
                                                        &account,
                                                        storage_slot,
                                                        stored.write_version);
        }
        if (store_err != SOL_OK) {
            if (out_count) *out_count = loaded;
            return store_err;
        }
        loaded++;

        offset += (size_t)stored.data_len;
        if (align_after_data) {
            offset = align_up_8(offset);
        }
    }

    /* If we stopped early, only enforce zero-padding for our own storage format
     * (which is expected to be tightly packed). Solana AppendVec files can be
     * preallocated with non-zero garbage beyond the used region; treating that
     * as corruption prevents bootstrapping from real snapshots. */
    if (has_header && loaded > 0 && offset < file_size) {
        size_t remaining = file_size - offset;
        if (remaining >= record_size) {
            bool all_zero = true;
            for (size_t i = offset; i < file_size; i++) {
                if (data[i] != 0) {
                    all_zero = false;
                    break;
                }
            }
            if (!all_zero) {
                sol_log_error("Account storage parse stopped early (%s): offset=%lu size=%lu",
                              file_name ? file_name : "(unknown)",
                              (unsigned long)offset,
                              (unsigned long)file_size);
                if (out_count) *out_count = loaded;
                return SOL_ERR_SNAPSHOT_CORRUPT;
            }
        }
    } else if (loaded > 0 && offset > file_size && (offset - file_size) >= 8) {
        /* Alignment should never skip more than 7 bytes past EOF. */
        sol_log_error("Account storage parse overran file bounds (%s): offset=%lu size=%lu",
                      file_name ? file_name : "(unknown)",
                      (unsigned long)offset,
                      (unsigned long)file_size);
        if (out_count) *out_count = loaded;
        return SOL_ERR_SNAPSHOT_CORRUPT;
    }

    if (out_count) *out_count = loaded;

    if (!has_header && loaded >= 8 && file_name &&
        parse_slot_id_from_filename(file_name, &name_slot, &name_id)) {
        g_storage_parse_cache.valid = true;
        g_storage_parse_cache.start_offset = best.start_offset;
        g_storage_parse_cache.layout = best.layout;
        g_storage_parse_cache.record_size = record_size;
        g_storage_parse_cache.align_after_data = align_after_data;
    }

    return loaded > 0 ? SOL_OK : SOL_ERR_NOTFOUND;
}

static sol_err_t
load_accounts_from_storage_file(const char* storage_path,
                                const char* file_name,
                                sol_slot_t slot_hint,
                                sol_accounts_db_t* accounts_db,
                                sol_accounts_db_bulk_writer_t* bulk_writer,
                                uint64_t* out_count,
                                uint64_t* out_bytes) {
    if (!storage_path || !accounts_db) return SOL_ERR_INVAL;
    if (out_count) *out_count = 0;
    if (out_bytes) *out_bytes = 0;

    int fd = open(storage_path, O_RDONLY);
    if (fd < 0) return SOL_ERR_NOTFOUND;

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return SOL_ERR_IO;
    }

    if (!S_ISREG(st.st_mode)) {
        close(fd);
        return SOL_ERR_NOTFOUND;
    }

    if (st.st_size <= 0) {
        close(fd);
        return SOL_OK;
    }

    size_t file_size = (size_t)st.st_size;
    if (out_bytes) *out_bytes = (uint64_t)file_size;
    void* map = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return SOL_ERR_IO;

    uint64_t loaded = 0;
    sol_err_t err = load_accounts_from_storage_mapped(
        (const uint8_t*)map,
        file_size,
        file_name,
        slot_hint,
        accounts_db,
        bulk_writer,
        NULL,
        &loaded);

    munmap(map, file_size);

    if (out_count) *out_count = loaded;
    return err;
}

static int
accounts_dir_entry_name_cmp(const void* a, const void* b) {
    const char* sa = *(const char* const*)a;
    const char* sb = *(const char* const*)b;
    uint64_t as = 0, ai = 0, bs = 0, bi = 0;
    bool pa = parse_slot_id_from_filename(sa, &as, &ai);
    bool pb = parse_slot_id_from_filename(sb, &bs, &bi);
    if (pa && pb) {
        if (as < bs) return -1;
        if (as > bs) return 1;
        if (ai < bi) return -1;
        if (ai > bi) return 1;
        return 0;
    }
    if (pa != pb) return pa ? -1 : 1;
    return strcmp(sa, sb);
}

static sol_err_t
load_accounts_from_dir(const char* accounts_dir,
                       sol_slot_t slot_hint,
                       sol_accounts_db_t* accounts_db,
                       sol_accounts_db_bulk_writer_t* bulk_writer,
                       uint64_t* out_count);

typedef struct {
    const char*      accounts_dir;
    char**           names;
    size_t           names_len;
    sol_accounts_db_t* accounts_db;
    size_t           batch_capacity;
    size_t           max_bytes_queued;
    uint32_t         thread_count;

    size_t           next_index;
    uint32_t         done_threads;
    int              first_err;
    int              core_index_ok;
    uint64_t         files_processed;
    uint64_t         accounts_loaded;
    uint64_t         bytes_processed;
} snapshot_accounts_parallel_ctx_t;

static void
snapshot_parallel_set_err(snapshot_accounts_parallel_ctx_t* ctx, sol_err_t err) {
    if (!ctx || err == SOL_OK) return;
    int expected = SOL_OK;
    (void)__atomic_compare_exchange_n(&ctx->first_err,
                                     &expected,
                                     err,
                                     false,
                                     __ATOMIC_RELAXED,
                                     __ATOMIC_RELAXED);
}

static void*
snapshot_accounts_parallel_worker(void* arg) {
    snapshot_accounts_parallel_ctx_t* ctx = (snapshot_accounts_parallel_ctx_t*)arg;
    if (!ctx) return NULL;

    sol_accounts_db_bulk_writer_t* bulk = sol_accounts_db_bulk_writer_new(ctx->accounts_db, ctx->batch_capacity);
    if (!bulk) {
        snapshot_parallel_set_err(ctx, SOL_ERR_NOMEM);
        __atomic_fetch_add(&ctx->done_threads, 1u, __ATOMIC_RELAXED);
        return NULL;
    }

    sol_accounts_db_bulk_writer_set_use_merge(bulk, true);
    if (ctx->max_bytes_queued > 0) {
        sol_accounts_db_bulk_writer_set_max_bytes(bulk, ctx->max_bytes_queued);
    }

    /* AppendVec mode already has owner/lamports metadata in the appendvec
     * headers. Writing a full pubkey->owner reverse mapping during bootstrap
     * can roughly double RocksDB write traffic. Skip it by default; it can be
     * rebuilt later if needed for full owner index / richer RPC queries. */
    if (sol_accounts_db_is_appendvec(ctx->accounts_db)) {
        (void)sol_accounts_db_bulk_writer_set_write_owner_reverse(bulk, false);
    }

    if (__atomic_load_n(&ctx->core_index_ok, __ATOMIC_RELAXED) != 0) {
        sol_err_t idx_err = sol_accounts_db_bulk_writer_set_write_owner_index(bulk, true);
        if (idx_err == SOL_OK) {
            sol_accounts_db_bulk_writer_set_write_owner_index_core_only(bulk, true);
            if (!sol_accounts_db_bulk_writer_is_writing_owner_index(bulk)) {
                (void)__atomic_store_n(&ctx->core_index_ok, 0, __ATOMIC_RELAXED);
            }
        } else {
            (void)__atomic_store_n(&ctx->core_index_ok, 0, __ATOMIC_RELAXED);
        }
    }

    while (1) {
        if (__atomic_load_n(&ctx->first_err, __ATOMIC_RELAXED) != SOL_OK) break;

        size_t idx = __atomic_fetch_add(&ctx->next_index, 1u, __ATOMIC_RELAXED);
        if (idx >= ctx->names_len) break;

        const char* name = ctx->names[idx];
        if (!name || name[0] == '\0') continue;

        uint64_t slot = 0;
        uint64_t id = 0;
        sol_slot_t file_slot = 0;
        if (strcmp(name, "storage.bin") == 0) {
            file_slot = 0;
        } else if (parse_slot_id_from_filename(name, &slot, &id)) {
            file_slot = (sol_slot_t)slot;
        } else {
            continue;
        }

        char path[512];
        snprintf(path, sizeof(path), "%s/%s", ctx->accounts_dir, name);

        uint64_t loaded = 0;
        uint64_t file_bytes = 0;

        struct stat st;
        if (stat(path, &st) != 0) {
            snapshot_parallel_set_err(ctx, SOL_ERR_SNAPSHOT_CORRUPT);
            break;
        }

        sol_err_t err = SOL_OK;
        if (S_ISDIR(st.st_mode)) {
            err = load_accounts_from_dir(path, file_slot, ctx->accounts_db, bulk, &loaded);
            if (err == SOL_ERR_NOTFOUND) {
                err = SOL_ERR_SNAPSHOT_CORRUPT;
            }
        } else if (S_ISREG(st.st_mode)) {
            err = load_accounts_from_storage_file(path,
                                                  name,
                                                  file_slot,
                                                  ctx->accounts_db,
                                                  bulk,
                                                  &loaded,
                                                  &file_bytes);
            if (err == SOL_ERR_NOTFOUND) {
                err = SOL_ERR_SNAPSHOT_CORRUPT;
            }
        } else {
            continue;
        }
        if (err != SOL_OK) {
            snapshot_parallel_set_err(ctx, err);
            break;
        }

        if (loaded > 0) {
            (void)__atomic_fetch_add(&ctx->accounts_loaded, loaded, __ATOMIC_RELAXED);
        }
        if (file_bytes > 0) {
            (void)__atomic_fetch_add(&ctx->bytes_processed, file_bytes, __ATOMIC_RELAXED);
        }
        (void)__atomic_fetch_add(&ctx->files_processed, 1u, __ATOMIC_RELAXED);
    }

    sol_err_t flush_err = sol_accounts_db_bulk_writer_flush(bulk);
    if (flush_err != SOL_OK) {
        snapshot_parallel_set_err(ctx, flush_err);
    }
    sol_accounts_db_bulk_writer_destroy(bulk);

    __atomic_fetch_add(&ctx->done_threads, 1u, __ATOMIC_RELAXED);
    return NULL;
}

static void*
snapshot_accounts_parallel_monitor(void* arg) {
    snapshot_accounts_parallel_ctx_t* ctx = (snapshot_accounts_parallel_ctx_t*)arg;
    if (!ctx) return NULL;

    uint64_t last_log_ms = now_ms_monotonic();

    while (1) {
        if (__atomic_load_n(&ctx->done_threads, __ATOMIC_RELAXED) >= ctx->thread_count) break;
        if (__atomic_load_n(&ctx->first_err, __ATOMIC_RELAXED) != SOL_OK) break;

        uint64_t now = now_ms_monotonic();
        if (now - last_log_ms >= 5000) {
            uint64_t files = __atomic_load_n(&ctx->files_processed, __ATOMIC_RELAXED);
            uint64_t accounts = __atomic_load_n(&ctx->accounts_loaded, __ATOMIC_RELAXED);
            uint64_t bytes = __atomic_load_n(&ctx->bytes_processed, __ATOMIC_RELAXED);
            sol_log_info("Snapshot accounts load progress: %lu files, %lu accounts, %lu MB read",
                         (unsigned long)files,
                         (unsigned long)accounts,
                         (unsigned long)(bytes / (1024 * 1024)));
            last_log_ms = now;
        }

        usleep(200u * 1000u);
    }

    return NULL;
}

static sol_err_t
load_accounts_from_top_level_dir_parallel(const char* accounts_dir,
                                          sol_accounts_db_t* accounts_db,
                                          uint32_t thread_count,
                                          size_t batch_capacity,
                                          size_t max_bytes_queued,
                                          uint64_t* out_count,
                                          int* out_core_index_ok) {
    if (!accounts_dir || !accounts_db) return SOL_ERR_INVAL;
    if (out_count) *out_count = 0;
    if (out_core_index_ok) *out_core_index_ok = 0;
    if (thread_count == 0) thread_count = 1;

    struct stat st;
    if (stat(accounts_dir, &st) != 0) return SOL_ERR_NOTFOUND;
    if (!S_ISDIR(st.st_mode)) return SOL_ERR_INVAL;

    DIR* dir = opendir(accounts_dir);
    if (!dir) return SOL_ERR_NOTFOUND;

    /* Collect entries. */
    size_t names_cap = 0;
    size_t names_len = 0;
    char** names = NULL;
    struct dirent* entry;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        if (names_len == names_cap) {
            size_t new_cap = names_cap ? (names_cap * 2) : 1024;
            if (new_cap < names_cap) {
                closedir(dir);
                return SOL_ERR_OVERFLOW;
            }
            char** new_names = sol_realloc(names, new_cap * sizeof(*names));
            if (!new_names) {
                for (size_t i = 0; i < names_len; i++) sol_free(names[i]);
                sol_free(names);
                closedir(dir);
                return SOL_ERR_NOMEM;
            }
            names = new_names;
            names_cap = new_cap;
        }

        size_t name_len = strlen(entry->d_name);
        char* copy = sol_alloc(name_len + 1);
        if (!copy) {
            for (size_t i = 0; i < names_len; i++) sol_free(names[i]);
            sol_free(names);
            closedir(dir);
            return SOL_ERR_NOMEM;
        }
        memcpy(copy, entry->d_name, name_len + 1);
        names[names_len++] = copy;
    }

    closedir(dir);

    sol_log_info("Snapshot accounts load: found %zu storage entries", names_len);

    snapshot_accounts_parallel_ctx_t ctx = {0};
    ctx.accounts_dir = accounts_dir;
    ctx.names = names;
    ctx.names_len = names_len;
    ctx.accounts_db = accounts_db;
    ctx.batch_capacity = batch_capacity ? batch_capacity : 16384;
    ctx.max_bytes_queued = max_bytes_queued;
    ctx.thread_count = thread_count;
    ctx.next_index = 0;
    ctx.done_threads = 0;
    ctx.first_err = SOL_OK;
    ctx.core_index_ok = 1;
    ctx.files_processed = 0;
    ctx.accounts_loaded = 0;
    ctx.bytes_processed = 0;

    pthread_t* workers = sol_calloc(thread_count, sizeof(*workers));
    if (!workers) {
        for (size_t i = 0; i < names_len; i++) sol_free(names[i]);
        sol_free(names);
        return SOL_ERR_NOMEM;
    }

    pthread_t monitor;
    bool have_monitor = false;
    if (pthread_create(&monitor, NULL, snapshot_accounts_parallel_monitor, &ctx) == 0) {
        have_monitor = true;
    }

    uint32_t workers_created = 0;
    for (uint32_t i = 0; i < thread_count; i++) {
        if (pthread_create(&workers[i], NULL, snapshot_accounts_parallel_worker, &ctx) != 0) {
            snapshot_parallel_set_err(&ctx, SOL_ERR_IO);
            break;
        }
        workers_created++;
    }

    for (uint32_t i = 0; i < workers_created; i++) {
        (void)pthread_join(workers[i], NULL);
    }

    if (have_monitor) {
        (void)pthread_join(monitor, NULL);
    }

    sol_free(workers);

    sol_err_t err = (sol_err_t)__atomic_load_n(&ctx.first_err, __ATOMIC_RELAXED);
    uint64_t total_loaded = __atomic_load_n(&ctx.accounts_loaded, __ATOMIC_RELAXED);
    int core_ok = __atomic_load_n(&ctx.core_index_ok, __ATOMIC_RELAXED);

    for (size_t i = 0; i < names_len; i++) {
        sol_free(names[i]);
    }
    sol_free(names);

    if (out_count) *out_count = total_loaded;
    if (out_core_index_ok) *out_core_index_ok = core_ok;

    if (err != SOL_OK) {
        return err;
    }

    return total_loaded > 0 ? SOL_OK : SOL_ERR_NOTFOUND;
}

/* -------------------------------------------------------------------------- */
/* AppendVec snapshot index (deferred RocksDB write)                           */
/* -------------------------------------------------------------------------- */

typedef struct {
    uint64_t     slot;
    uint64_t     write_version;
    uint64_t     file_key;
    uint64_t     record_offset;
    sol_hash_t   leaf_hash; /* Zero => deleted */
    sol_pubkey_t owner;
    uint64_t     lamports;
    uint64_t     data_len;
} snapshot_appendvec_index_val_t;

typedef struct {
    pthread_mutex_t  lock;
    sol_pubkey_map_t* map;
} snapshot_appendvec_index_shard_t;

struct snapshot_appendvec_index {
    size_t                          shard_count;
    snapshot_appendvec_index_shard_t* shards;
};

static uint32_t
snapshot_appendvec_index_flush_threads_default(const snapshot_appendvec_index_t* idx) {
    if (!idx || idx->shard_count == 0) return 1u;

    size_t env = snapshot_env_size_t("SOL_SNAPSHOT_DEFER_APPENDVEC_INDEX_FLUSH_THREADS",
                                     1u,
                                     1024u);
    if (env > 0) {
        uint32_t threads = (uint32_t)env;
        if ((size_t)threads > idx->shard_count) threads = (uint32_t)idx->shard_count;
        if (threads < 1u) threads = 1u;
        return threads;
    }

    long cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
    uint32_t threads = 1u;
    if (cpu_count > 0) {
        threads = (uint32_t)cpu_count;
    }

    /* Cap to avoid runaway arenas and too many concurrent RocksDB writers. */
    if (threads > 32u) threads = 32u;
    if ((size_t)threads > idx->shard_count) threads = (uint32_t)idx->shard_count;
    if (threads < 1u) threads = 1u;
    return threads;
}

static bool
snapshot_defer_appendvec_index_enabled(void) {
    const char* env = getenv("SOL_SNAPSHOT_DEFER_APPENDVEC_INDEX");
    if (!env || env[0] == '\0') {
        /* Default: enable on very large-memory machines where holding the
         * accounts index in RAM is feasible. This significantly reduces
         * bootstrap time by avoiding billions of RocksDB merge operands during
         * snapshot ingestion.
         *
         * Disable explicitly via: SOL_SNAPSHOT_DEFER_APPENDVEC_INDEX=0 */
        long pages = sysconf(_SC_PHYS_PAGES);
        long page_size = sysconf(_SC_PAGESIZE);
        if (pages <= 0 || page_size <= 0) return false;

        uint64_t total = (uint64_t)pages * (uint64_t)page_size;
        const uint64_t min_enable = 128ull * 1024ull * 1024ull * 1024ull; /* 128 GiB */
        return total >= min_enable;
    }

    while (*env && isspace((unsigned char)*env)) env++;
    if (*env == '\0') return true;

    if (env[0] == '0') return false;
    if (env[0] == 'n' || env[0] == 'N') return false;
    if (env[0] == 'f' || env[0] == 'F') return false;
    return true;
}

static uint32_t
snapshot_appendvec_index_default_shards(uint32_t thread_count) {
    size_t want = (size_t)thread_count * 8u;
    if (want < 64u) want = 64u;
    if (want > 4096u) want = 4096u;
    size_t env = snapshot_env_size_t("SOL_SNAPSHOT_DEFER_APPENDVEC_INDEX_SHARDS", 1u, 16384u);
    if (env > 0) want = env;
    uint32_t shards = (uint32_t)want;
    shards = sol_next_pow2_32(shards);
    if (shards < 1u) shards = 1u;
    return shards;
}

static size_t
snapshot_appendvec_index_default_capacity_per_shard(uint32_t shard_count) {
    if (shard_count == 0) return 0;

    size_t env = snapshot_env_size_t("SOL_SNAPSHOT_DEFER_APPENDVEC_INDEX_CAPACITY_PER_SHARD",
                                     1024u,
                                     (size_t)1u << 24 /* 16,777,216 */);
    if (env > 0) return env;

    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGESIZE);
    if (pages <= 0 || page_size <= 0) return 0;

    uint64_t total = (uint64_t)pages * (uint64_t)page_size;
    uint64_t target_total_capacity = 0;

    if (total >= (1024ull * 1024ull * 1024ull * 1024ull)) {          /* >= 1 TiB */
        target_total_capacity = 1ull << 30;                           /* 1,073,741,824 */
    } else if (total >= (512ull * 1024ull * 1024ull * 1024ull)) {     /* >= 512 GiB */
        target_total_capacity = 1ull << 29;                           /* 536,870,912 */
    } else if (total >= (256ull * 1024ull * 1024ull * 1024ull)) {     /* >= 256 GiB */
        target_total_capacity = 1ull << 28;                           /* 268,435,456 */
    } else if (total >= (128ull * 1024ull * 1024ull * 1024ull)) {     /* >= 128 GiB */
        target_total_capacity = 1ull << 28;                           /* 268,435,456 */
    } else if (total >= (96ull * 1024ull * 1024ull * 1024ull)) {      /* >= 96 GiB */
        target_total_capacity = 1ull << 27;                           /* 134,217,728 */
    } else if (total >= (64ull * 1024ull * 1024ull * 1024ull)) {      /* >= 64 GiB */
        target_total_capacity = 1ull << 26;                           /* 67,108,864 */
    } else {
        return 0;
    }

    uint64_t per = target_total_capacity / (uint64_t)shard_count;
    if (per < 1024u) per = 1024u;
    if (per > (uint64_t)((size_t)1u << 24)) per = (uint64_t)((size_t)1u << 24);
    return (size_t)per;
}

static snapshot_appendvec_index_t*
snapshot_appendvec_index_new(uint32_t shard_count, size_t capacity_per_shard) {
    if (shard_count == 0) shard_count = 1;
    shard_count = sol_next_pow2_32(shard_count);
    if (shard_count == 0) shard_count = 1;

    snapshot_appendvec_index_t* idx = sol_calloc(1, sizeof(*idx));
    if (!idx) return NULL;

    idx->shard_count = (size_t)shard_count;
    idx->shards = sol_calloc(idx->shard_count, sizeof(*idx->shards));
    if (!idx->shards) {
        sol_free(idx);
        return NULL;
    }

    for (size_t i = 0; i < idx->shard_count; i++) {
        if (pthread_mutex_init(&idx->shards[i].lock, NULL) != 0) {
            for (size_t j = 0; j < i; j++) {
                pthread_mutex_destroy(&idx->shards[j].lock);
                sol_pubkey_map_destroy(idx->shards[j].map);
            }
            sol_free(idx->shards);
            sol_free(idx);
            return NULL;
        }

        idx->shards[i].map = sol_pubkey_map_new(sizeof(snapshot_appendvec_index_val_t), capacity_per_shard);
        if (!idx->shards[i].map) {
            pthread_mutex_destroy(&idx->shards[i].lock);
            for (size_t j = 0; j < i; j++) {
                pthread_mutex_destroy(&idx->shards[j].lock);
                sol_pubkey_map_destroy(idx->shards[j].map);
            }
            sol_free(idx->shards);
            sol_free(idx);
            return NULL;
        }
    }

    return idx;
}

static void
snapshot_appendvec_index_destroy(snapshot_appendvec_index_t* idx) {
    if (!idx) return;
    if (idx->shards) {
        for (size_t i = 0; i < idx->shard_count; i++) {
            pthread_mutex_destroy(&idx->shards[i].lock);
            sol_pubkey_map_destroy(idx->shards[i].map);
        }
        sol_free(idx->shards);
    }
    sol_free(idx);
}

SOL_INLINE size_t
snapshot_appendvec_index_shard_for(const snapshot_appendvec_index_t* idx,
                                   const sol_pubkey_t* pubkey) {
    if (!idx || idx->shard_count == 0 || !pubkey) return 0;
    uint64_t h = sol_load_u64_le(pubkey->bytes);
    return (size_t)(h & (idx->shard_count - 1u));
}

static sol_err_t
snapshot_appendvec_index_update(snapshot_appendvec_index_t* idx,
                                const sol_pubkey_t* pubkey,
                                sol_slot_t slot,
                                uint64_t write_version,
                                const sol_pubkey_t* owner,
                                uint64_t lamports,
                                uint64_t data_len,
                                uint64_t file_key,
                                uint64_t record_offset,
                                const sol_hash_t* leaf_hash) {
    if (!idx || !idx->shards || idx->shard_count == 0) return SOL_ERR_INVAL;
    if (!pubkey) return SOL_ERR_INVAL;

    snapshot_appendvec_index_val_t v = {0};
    v.slot = (uint64_t)slot;
    v.write_version = write_version;
    v.file_key = file_key;
    v.record_offset = record_offset;
    v.lamports = lamports;
    v.data_len = data_len;
    if (owner) {
        v.owner = *owner;
    } else {
        memset(v.owner.bytes, 0, sizeof(v.owner.bytes));
    }
    if (lamports != 0 && leaf_hash) {
        v.leaf_hash = *leaf_hash;
    } else {
        memset(v.leaf_hash.bytes, 0, sizeof(v.leaf_hash.bytes));
    }

    size_t shard = snapshot_appendvec_index_shard_for(idx, pubkey);
    snapshot_appendvec_index_shard_t* s = &idx->shards[shard];

    pthread_mutex_lock(&s->lock);

    snapshot_appendvec_index_val_t* cur =
        (snapshot_appendvec_index_val_t*)sol_pubkey_map_get(s->map, pubkey);
    if (cur) {
        if (cur->write_version > write_version ||
            (cur->write_version == write_version && cur->slot >= (uint64_t)slot)) {
            pthread_mutex_unlock(&s->lock);
            return SOL_OK;
        }
        *cur = v;
        pthread_mutex_unlock(&s->lock);
        return SOL_OK;
    }

    void* inserted = sol_pubkey_map_insert(s->map, pubkey, &v);
    pthread_mutex_unlock(&s->lock);
    return inserted ? SOL_OK : SOL_ERR_NOMEM;
}

typedef struct snapshot_stream_task {
    struct snapshot_stream_task* next;
    char                         file_name[128];
    uint8_t*                     data;
    size_t                       len;
} snapshot_stream_task_t;

typedef struct snapshot_stream_chunk_task {
    struct snapshot_stream_chunk_task* next;
    char                               file_name[128];
    uint8_t*                           data;
    size_t                             len;
    uint64_t                           file_size;
    uint64_t                           file_offset;
    bool                               is_last;
} snapshot_stream_chunk_task_t;

typedef struct {
    sol_accounts_db_t* accounts_db;
    size_t             batch_capacity;
    size_t             max_bytes_queued;
    uint32_t           thread_count;

    /* When true, snapshot ingestion will build the AppendVec accounts index
     * in-memory and bulk-write it once after extraction completes. This avoids
     * generating billions of RocksDB merge operands during bootstrap. */
    bool                     defer_appendvec_index;
    snapshot_appendvec_index_t* appendvec_index;

    /* When using AppendVec storage, streamed account files must be persisted to
     * disk so the stored (file_key,record_offset) references remain valid. */
    bool               persist_accounts_files;
    char               accounts_out_dir[512];
    int                persist_fd;
    char               persist_file[128];

    pthread_mutex_t        lock;
    pthread_cond_t         cv;
    pthread_cond_t         cv_space;
    snapshot_stream_task_t* head;
    snapshot_stream_task_t* tail;
    size_t                 queue_len;
    size_t                 queue_max;
    size_t                 queue_bytes_queued;
    size_t                 queue_max_bytes;
    bool                   producer_done;

    pthread_mutex_t            chunk_lock;
    pthread_cond_t             chunk_cv;
    pthread_cond_t             chunk_cv_space;
    snapshot_stream_chunk_task_t* chunk_head;
    snapshot_stream_chunk_task_t* chunk_tail;
    size_t                     chunk_queue_len;
    size_t                     chunk_queue_max;
    size_t                     chunk_bytes_queued;
    size_t                     chunk_max_bytes_queued;
    bool                       chunk_producer_done;

    int                    first_err;
    int                    core_index_ok;
    uint32_t               done_threads;
    uint64_t               files_processed;
    uint64_t               accounts_loaded;
    uint64_t               bytes_processed;
    size_t                 queue_highwater;
    size_t                 queue_bytes_highwater;
    size_t                 chunk_queue_highwater;
    size_t                 chunk_bytes_highwater;
    uint64_t               queue_wait_ms;
    uint64_t               chunk_wait_ms;
    uint64_t               queue_waits;
    uint64_t               chunk_waits;
} snapshot_stream_accounts_ctx_t;

static void
snapshot_stream_set_err(snapshot_stream_accounts_ctx_t* ctx, sol_err_t err) {
    if (!ctx || err == SOL_OK) return;
    int expected = SOL_OK;
    (void)__atomic_compare_exchange_n(&ctx->first_err,
                                     &expected,
                                     err,
                                     false,
                                     __ATOMIC_RELAXED,
                                     __ATOMIC_RELAXED);
}

static sol_err_t
snapshot_stream_write_all(int fd, const uint8_t* data, size_t len, uint64_t offset) {
    if (fd < 0) return SOL_ERR_INVAL;
    if (len > 0 && !data) return SOL_ERR_INVAL;

    size_t written = 0;
    while (written < len) {
        ssize_t n = pwrite(fd,
                           data + written,
                           len - written,
                           (off_t)(offset + written));
        if (n < 0) {
            if (errno == EINTR) continue;
            return SOL_ERR_IO;
        }
        if (n == 0) return SOL_ERR_IO;
        written += (size_t)n;
    }
    return SOL_OK;
}

static sol_err_t
snapshot_stream_persist_file(snapshot_stream_accounts_ctx_t* ctx,
                             const char* base_name,
                             const uint8_t* data,
                             size_t len) {
    if (!ctx || !base_name) return SOL_ERR_INVAL;
    if (!ctx->persist_accounts_files) return SOL_OK;
    if (ctx->accounts_out_dir[0] == '\0') return SOL_ERR_INVAL;

    char path[1024];
    int n = snprintf(path, sizeof(path), "%s/%s", ctx->accounts_out_dir, base_name);
    if (n < 0 || (size_t)n >= sizeof(path)) return SOL_ERR_TOO_LARGE;

    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) return SOL_ERR_IO;

    sol_err_t err = snapshot_stream_write_all(fd, data, len, 0);
    close(fd);
    return err;
}

static sol_err_t
snapshot_stream_persist_chunk(snapshot_stream_accounts_ctx_t* ctx,
                              const char* base_name,
                              const uint8_t* data,
                              size_t len,
                              uint64_t file_offset,
                              bool is_last) {
    if (!ctx || !base_name) return SOL_ERR_INVAL;
    if (!ctx->persist_accounts_files) return SOL_OK;
    if (ctx->accounts_out_dir[0] == '\0') return SOL_ERR_INVAL;

    if (file_offset == 0 || ctx->persist_fd < 0 || strcmp(ctx->persist_file, base_name) != 0) {
        if (ctx->persist_fd >= 0) {
            close(ctx->persist_fd);
            ctx->persist_fd = -1;
        }
        ctx->persist_file[0] = '\0';

        char path[1024];
        int n = snprintf(path, sizeof(path), "%s/%s", ctx->accounts_out_dir, base_name);
        if (n < 0 || (size_t)n >= sizeof(path)) return SOL_ERR_TOO_LARGE;

        int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd < 0) return SOL_ERR_IO;
        ctx->persist_fd = fd;
        snprintf(ctx->persist_file, sizeof(ctx->persist_file), "%s", base_name);
    }

    if (len > 0) {
        sol_err_t werr = snapshot_stream_write_all(ctx->persist_fd, data, len, file_offset);
        if (werr != SOL_OK) return werr;
    }

    if (is_last) {
        if (ctx->persist_fd >= 0) {
            close(ctx->persist_fd);
            ctx->persist_fd = -1;
        }
        ctx->persist_file[0] = '\0';
    }

    return SOL_OK;
}

static sol_err_t
snapshot_stream_accounts_file_cb(void* arg,
                                 const char* rel_path,
                                 uint8_t* data,
                                 size_t len) {
    snapshot_stream_accounts_ctx_t* ctx = (snapshot_stream_accounts_ctx_t*)arg;
    if (!ctx || !rel_path) {
        /* On non-OK return the archive extractor will free `data`. */
        return SOL_ERR_INVAL;
    }

    sol_err_t prior = (sol_err_t)__atomic_load_n(&ctx->first_err, __ATOMIC_RELAXED);
    if (prior != SOL_OK) {
        return prior;
    }

    const char* base = strrchr(rel_path, '/');
    base = base ? (base + 1) : rel_path;
    if (!base || base[0] == '\0') {
        sol_free(data);
        return SOL_OK;
    }

    if (ctx->persist_accounts_files) {
        sol_err_t perr = snapshot_stream_persist_file(ctx, base, data, len);
        if (perr != SOL_OK) {
            sol_free(data);
            snapshot_stream_set_err(ctx, perr);
            return perr;
        }
    }

    snapshot_stream_task_t* t = sol_alloc(sizeof(*t));
    if (!t) {
        snapshot_stream_set_err(ctx, SOL_ERR_NOMEM);
        sol_free(data);
        return SOL_ERR_NOMEM;
    }

    size_t base_len = strlen(base);
    if (base_len >= sizeof(t->file_name)) {
        sol_free(t);
        snapshot_stream_set_err(ctx, SOL_ERR_INVAL);
        return SOL_ERR_INVAL;
    }
    memcpy(t->file_name, base, base_len + 1);

    t->data = data;
    t->len = len;
    t->next = NULL;

    pthread_mutex_lock(&ctx->lock);
    uint64_t wait_start_ms = 0;
    while ((ctx->queue_len >= ctx->queue_max ||
            (ctx->queue_max_bytes > 0 && ctx->queue_bytes_queued + len > ctx->queue_max_bytes)) &&
           __atomic_load_n(&ctx->first_err, __ATOMIC_RELAXED) == SOL_OK) {
        if (wait_start_ms == 0) wait_start_ms = now_ms_monotonic();
        pthread_cond_wait(&ctx->cv_space, &ctx->lock);
    }
    if (wait_start_ms != 0) {
        uint64_t waited = now_ms_monotonic() - wait_start_ms;
        __atomic_fetch_add(&ctx->queue_wait_ms, waited, __ATOMIC_RELAXED);
        __atomic_fetch_add(&ctx->queue_waits, 1u, __ATOMIC_RELAXED);
    }

    sol_err_t err = (sol_err_t)__atomic_load_n(&ctx->first_err, __ATOMIC_RELAXED);
    if (err != SOL_OK) {
        pthread_mutex_unlock(&ctx->lock);
        sol_free(t);
        return err;
    }

    if (!ctx->tail) {
        ctx->head = t;
        ctx->tail = t;
    } else {
        ctx->tail->next = t;
        ctx->tail = t;
    }
    ctx->queue_len++;
    ctx->queue_bytes_queued += len;
    if (ctx->queue_len > ctx->queue_highwater) {
        ctx->queue_highwater = ctx->queue_len;
    }
    if (ctx->queue_bytes_queued > ctx->queue_bytes_highwater) {
        ctx->queue_bytes_highwater = ctx->queue_bytes_queued;
    }
    pthread_cond_signal(&ctx->cv);
    pthread_mutex_unlock(&ctx->lock);

    return SOL_OK;
}

static sol_err_t
snapshot_stream_accounts_chunk_cb(void* arg,
                                  const char* rel_path,
                                  const uint8_t* data,
                                  size_t len,
                                  uint64_t file_size,
                                  uint64_t file_offset,
                                  bool is_last) {
    snapshot_stream_accounts_ctx_t* ctx = (snapshot_stream_accounts_ctx_t*)arg;
    if (!ctx || !rel_path) {
        return SOL_ERR_INVAL;
    }

    sol_err_t prior = (sol_err_t)__atomic_load_n(&ctx->first_err, __ATOMIC_RELAXED);
    if (prior != SOL_OK) {
        return prior;
    }

    const char* base = strrchr(rel_path, '/');
    base = base ? (base + 1) : rel_path;
    if (!base || base[0] == '\0') {
        return SOL_OK;
    }

    if (ctx->persist_accounts_files) {
        sol_err_t perr = snapshot_stream_persist_chunk(ctx, base, data, len, file_offset, is_last);
        if (perr != SOL_OK) {
            snapshot_stream_set_err(ctx, perr);
            return perr;
        }
    }

    snapshot_stream_chunk_task_t* t = sol_alloc(sizeof(*t));
    if (!t) {
        snapshot_stream_set_err(ctx, SOL_ERR_NOMEM);
        return SOL_ERR_NOMEM;
    }

    size_t base_len = strlen(base);
    if (base_len >= sizeof(t->file_name)) {
        sol_free(t);
        snapshot_stream_set_err(ctx, SOL_ERR_INVAL);
        return SOL_ERR_INVAL;
    }
    memcpy(t->file_name, base, base_len + 1);

    t->data = NULL;
    t->len = len;
    t->file_size = file_size;
    t->file_offset = file_offset;
    t->is_last = is_last;
    t->next = NULL;

    if (len > 0) {
        if (!data) {
            sol_free(t);
            snapshot_stream_set_err(ctx, SOL_ERR_INVAL);
            return SOL_ERR_INVAL;
        }

        t->data = sol_alloc(len);
        if (!t->data) {
            sol_free(t);
            snapshot_stream_set_err(ctx, SOL_ERR_NOMEM);
            return SOL_ERR_NOMEM;
        }
        memcpy(t->data, data, len);
    }

    pthread_mutex_lock(&ctx->chunk_lock);
    uint64_t wait_start_ms = 0;
    while ((ctx->chunk_queue_len >= ctx->chunk_queue_max ||
            ctx->chunk_bytes_queued + len > ctx->chunk_max_bytes_queued) &&
           __atomic_load_n(&ctx->first_err, __ATOMIC_RELAXED) == SOL_OK) {
        if (wait_start_ms == 0) wait_start_ms = now_ms_monotonic();
        pthread_cond_wait(&ctx->chunk_cv_space, &ctx->chunk_lock);
    }
    if (wait_start_ms != 0) {
        uint64_t waited = now_ms_monotonic() - wait_start_ms;
        __atomic_fetch_add(&ctx->chunk_wait_ms, waited, __ATOMIC_RELAXED);
        __atomic_fetch_add(&ctx->chunk_waits, 1u, __ATOMIC_RELAXED);
    }

    sol_err_t err = (sol_err_t)__atomic_load_n(&ctx->first_err, __ATOMIC_RELAXED);
    if (err != SOL_OK) {
        pthread_mutex_unlock(&ctx->chunk_lock);
        sol_free(t->data);
        sol_free(t);
        return err;
    }

    if (!ctx->chunk_tail) {
        ctx->chunk_head = t;
        ctx->chunk_tail = t;
    } else {
        ctx->chunk_tail->next = t;
        ctx->chunk_tail = t;
    }
    ctx->chunk_queue_len++;
    ctx->chunk_bytes_queued += len;
    if (ctx->chunk_queue_len > ctx->chunk_queue_highwater) {
        ctx->chunk_queue_highwater = ctx->chunk_queue_len;
    }
    if (ctx->chunk_bytes_queued > ctx->chunk_bytes_highwater) {
        ctx->chunk_bytes_highwater = ctx->chunk_bytes_queued;
    }
    pthread_cond_signal(&ctx->chunk_cv);
    pthread_mutex_unlock(&ctx->chunk_lock);

    return SOL_OK;
}

typedef enum {
    APPENDVEC_STREAM_STATE_RECORD = 0,
    APPENDVEC_STREAM_STATE_DATA,
    APPENDVEC_STREAM_STATE_ALIGN,
} appendvec_stream_state_t;

typedef struct {
    appendvec_stream_state_t state;
    storage_record_layout_t  layout;
    size_t                   record_size;
    bool                     align_after_data;

    bool                     appendvec_mode;
    sol_slot_t               slot_hint;
    uint64_t                 file_key;
    uint64_t                 file_size;
    uint64_t                 offset;
    uint64_t                 record_start;

    sol_stored_account_t     stored;
    sol_hash_t               leaf_hash;
    bool                     leaf_hash_valid;
    uint64_t                 data_len;
    uint64_t                 data_remaining;
    bool                     skip_data;

    uint8_t*                 data_buf;
    size_t                   data_buf_len;
    size_t                   data_buf_written;

    uint8_t                  header_buf[256];
    size_t                   header_filled;

    size_t                   align_remaining;

    uint64_t                 loaded;
    bool                     stopped;
} appendvec_stream_t;

static void
appendvec_stream_reset(appendvec_stream_t* s,
                       sol_slot_t slot_hint,
                       uint64_t file_key,
                       uint64_t file_size) {
    if (!s) return;
    if (s->data_buf) {
        sol_free(s->data_buf);
        s->data_buf = NULL;
    }
    memset(s, 0, sizeof(*s));
    s->state = APPENDVEC_STREAM_STATE_RECORD;
    s->layout = STORAGE_RECORD_LAYOUT_SOLANA3;
    s->record_size = sizeof(sol_stored_account_t) + 32u;
    s->align_after_data = true;
    s->appendvec_mode = false;
    s->slot_hint = slot_hint;
    s->file_key = file_key;
    s->file_size = file_size;
    s->offset = 0;
    s->record_start = 0;
    s->leaf_hash_valid = false;
}

static sol_err_t
appendvec_stream_finalize(const appendvec_stream_t* s) {
    if (!s) return SOL_ERR_INVAL;
    if (s->stopped) return SOL_OK;

    if (s->state == APPENDVEC_STREAM_STATE_DATA && s->data_remaining > 0) {
        return SOL_ERR_TRUNCATED;
    }

    /* Incomplete record headers at EOF are allowed (unused trailing bytes). */
    return (s->loaded > 0) ? SOL_OK : SOL_ERR_NOTFOUND;
}

static sol_err_t
appendvec_stream_feed(appendvec_stream_t* s,
                      sol_accounts_db_bulk_writer_t* bulk,
                      snapshot_appendvec_index_t* appendvec_index,
                      const uint8_t* data,
                      size_t len,
                      uint64_t file_offset,
                      bool is_last,
                      uint64_t* out_loaded_delta) {
    if (!s || (!bulk && !appendvec_index)) return SOL_ERR_INVAL;
    if (len > 0 && !data) return SOL_ERR_INVAL;
    if (out_loaded_delta) *out_loaded_delta = 0;

    if (file_offset != s->offset) {
        return SOL_ERR_SNAPSHOT_CORRUPT;
    }

    uint64_t loaded_delta = 0;
    const uint8_t* p = data;
    size_t remaining = len;

    while (remaining > 0) {
        if (s->stopped) {
            s->offset += (uint64_t)remaining;
            break;
        }

        switch (s->state) {
        case APPENDVEC_STREAM_STATE_RECORD: {
            if (s->record_size == 0 || s->record_size > sizeof(s->header_buf)) {
                return SOL_ERR_SNAPSHOT_CORRUPT;
            }

            if (s->header_filled == 0) {
                s->record_start = s->offset;
                s->leaf_hash_valid = false;
            }

            if (s->header_filled > 0) {
                size_t need = s->record_size - s->header_filled;
                size_t n = remaining < need ? remaining : need;
                memcpy(s->header_buf + s->header_filled, p, n);
                s->header_filled += n;
                s->offset += (uint64_t)n;
                p += n;
                remaining -= n;

                if (s->header_filled < s->record_size) {
                    break;
                }

                sol_stored_account_t stored;
                if (!parse_stored_account_record(s->header_buf,
                                                 s->record_size,
                                                 0,
                                                 s->layout,
                                                 &stored)) {
                    if (s->loaded > 0) {
                        s->header_filled = 0;
                        s->stopped = true;
                        continue;
                    }
                    return SOL_ERR_NOTFOUND;
                }

                if (s->record_size >= (sizeof(sol_stored_account_t) + 32u)) {
                    memcpy(s->leaf_hash.bytes,
                           s->header_buf + sizeof(sol_stored_account_t),
                           32u);
                    s->leaf_hash_valid = true;
                }

                s->stored = stored;
                s->header_filled = 0;
            } else if (remaining >= s->record_size) {
                sol_stored_account_t stored;
                if (!parse_stored_account_record(p,
                                                 s->record_size,
                                                 0,
                                                 s->layout,
                                                 &stored)) {
                    if (s->loaded > 0) {
                        s->stopped = true;
                        continue;
                    }
                    return SOL_ERR_NOTFOUND;
                }

                if (s->record_size >= (sizeof(sol_stored_account_t) + 32u)) {
                    memcpy(s->leaf_hash.bytes,
                           p + sizeof(sol_stored_account_t),
                           32u);
                    s->leaf_hash_valid = true;
                }

                s->stored = stored;
                s->offset += (uint64_t)s->record_size;
                p += s->record_size;
                remaining -= s->record_size;
            } else {
                memcpy(s->header_buf, p, remaining);
                s->header_filled = remaining;
                s->offset += (uint64_t)remaining;
                p += remaining;
                remaining = 0;
                break;
            }

            if (s->stored.data_len > (uint64_t)SOL_ACCOUNT_MAX_DATA_SIZE) {
                return SOL_ERR_SNAPSHOT_CORRUPT;
            }

            if (s->file_size > 0 && s->offset <= s->file_size) {
                uint64_t remain_file = s->file_size - s->offset;
                if (s->stored.data_len > remain_file) {
                    if (s->loaded > 0) {
                        s->stopped = true;
                        break;
                    }
                    return SOL_ERR_NOTFOUND;
                }
            }

            s->data_len = s->stored.data_len;
            s->data_remaining = s->stored.data_len;
            s->skip_data = (s->stored.lamports == 0);

            if (s->skip_data) {
                sol_err_t derr = appendvec_index
                    ? snapshot_appendvec_index_update(appendvec_index,
                                                      &s->stored.pubkey,
                                                      s->slot_hint,
                                                      s->stored.write_version,
                                                      NULL,
                                                      0,
                                                      0,
                                                      0,
                                                      0,
                                                      NULL)
                    : sol_accounts_db_bulk_writer_delete_versioned(
                        bulk,
                        &s->stored.pubkey,
                        s->slot_hint,
                        s->stored.write_version);
                if (derr != SOL_OK) return derr;
                loaded_delta++;
                s->loaded++;
            } else if (s->data_len == 0) {
                const sol_hash_t* leaf_hash = NULL;
                if (s->appendvec_mode && s->leaf_hash_valid && !sol_hash_is_zero(&s->leaf_hash)) {
                    int mode = __atomic_load_n(&g_appendvec_meta_hash_mode, __ATOMIC_ACQUIRE);
                    if (mode == -1) {
                        sol_account_t account = {0};
                        account.meta.owner = s->stored.owner;
                        account.meta.lamports = s->stored.lamports;
                        account.meta.rent_epoch = s->stored.rent_epoch;
                        account.meta.executable = s->stored.executable;
                        account.meta.data_len = s->stored.data_len;
                        account.data = NULL;

                        sol_hash_t computed = {0};
                        sol_account_hash(&s->stored.pubkey, &account, &computed);

                        int decided = (memcmp(computed.bytes, s->leaf_hash.bytes, SOL_HASH_SIZE) == 0) ? 1 : 0;
                        int expected = -1;
                        if (__atomic_compare_exchange_n(&g_appendvec_meta_hash_mode,
                                                       &expected,
                                                       decided,
                                                       false,
                                                       __ATOMIC_RELEASE,
                                                       __ATOMIC_RELAXED)) {
                            if (decided == 0) {
                                sol_log_warn("Snapshot appendvec metadata hash did not match computed account hash; "
                                             "re-hashing accounts during ingestion");
                            }
                        }

                        mode = __atomic_load_n(&g_appendvec_meta_hash_mode, __ATOMIC_ACQUIRE);
                    }

                    if (mode == 1) {
                        leaf_hash = &s->leaf_hash;
                    }
                }

                sol_err_t perr = SOL_OK;
                if (appendvec_index) {
                    sol_hash_t computed = {0};
                    const sol_hash_t* use_leaf = leaf_hash;
                    if (s->stored.lamports != 0 && (!use_leaf || sol_hash_is_zero(use_leaf))) {
                        sol_account_t account = {0};
                        account.meta.owner = s->stored.owner;
                        account.meta.lamports = s->stored.lamports;
                        account.meta.rent_epoch = s->stored.rent_epoch;
                        account.meta.executable = s->stored.executable;
                        account.meta.data_len = s->stored.data_len;
                        account.data = NULL;
                        sol_account_hash(&s->stored.pubkey, &account, &computed);
                        use_leaf = &computed;
                    }
                    perr = snapshot_appendvec_index_update(appendvec_index,
                                                          &s->stored.pubkey,
                                                          s->slot_hint,
                                                          s->stored.write_version,
                                                          &s->stored.owner,
                                                          s->stored.lamports,
                                                          0,
                                                          s->file_key,
                                                          s->record_start,
                                                          use_leaf);
                } else {
                    perr = s->appendvec_mode
                        ? sol_accounts_db_bulk_writer_put_snapshot_account(
                            bulk,
                            &s->stored.pubkey,
                            &s->stored.owner,
                            s->stored.lamports,
                            NULL,
                            0,
                            s->stored.executable,
                            s->stored.rent_epoch,
                            s->slot_hint,
                            s->stored.write_version,
                            leaf_hash,
                            s->file_key,
                            s->record_start)
                        : sol_accounts_db_bulk_writer_put_raw_versioned(
                            bulk,
                            &s->stored.pubkey,
                            &s->stored.owner,
                            s->stored.lamports,
                            NULL,
                            0,
                            s->stored.executable,
                            s->stored.rent_epoch,
                            s->slot_hint,
                            s->stored.write_version);
                }
                if (perr != SOL_OK) return perr;
                loaded_delta++;
                s->loaded++;
            }

            if (s->data_len == 0) {
                if (s->align_after_data) {
                    size_t aligned = align_up_8((size_t)s->offset);
                    s->align_remaining = (aligned >= (size_t)s->offset) ? (aligned - (size_t)s->offset) : 0;
                    s->state = s->align_remaining ? APPENDVEC_STREAM_STATE_ALIGN : APPENDVEC_STREAM_STATE_RECORD;
                } else {
                    s->state = APPENDVEC_STREAM_STATE_RECORD;
                }
            } else {
                s->state = APPENDVEC_STREAM_STATE_DATA;
            }
            break;
        }

        case APPENDVEC_STREAM_STATE_DATA: {
            if (s->data_remaining == 0) {
                if (s->align_after_data) {
                    size_t aligned = align_up_8((size_t)s->offset);
                    s->align_remaining = (aligned >= (size_t)s->offset) ? (aligned - (size_t)s->offset) : 0;
                    s->state = s->align_remaining ? APPENDVEC_STREAM_STATE_ALIGN : APPENDVEC_STREAM_STATE_RECORD;
                } else {
                    s->state = APPENDVEC_STREAM_STATE_RECORD;
                }
                break;
            }

            if (s->skip_data) {
                size_t n = remaining;
                if ((uint64_t)n > s->data_remaining) n = (size_t)s->data_remaining;
                s->data_remaining -= (uint64_t)n;
                s->offset += (uint64_t)n;
                p += n;
                remaining -= n;
                if (s->data_remaining == 0) {
                    if (s->align_after_data) {
                        size_t aligned = align_up_8((size_t)s->offset);
                        s->align_remaining = (aligned >= (size_t)s->offset) ? (aligned - (size_t)s->offset) : 0;
                        s->state = s->align_remaining ? APPENDVEC_STREAM_STATE_ALIGN : APPENDVEC_STREAM_STATE_RECORD;
                    } else {
                        s->state = APPENDVEC_STREAM_STATE_RECORD;
                    }
                }
                break;
            }

            /* Fast path: for AppendVec-backed snapshot ingestion, we don't need
             * to buffer account data as long as the appendvec metadata hash is
             * known-good (mode==1). We can advance through the stream and write
             * just the (pubkey -> file ref + leaf hash) index once the record
             * completes. This avoids per-record malloc/free when account data
             * spans input chunks (common in mainnet snapshots). */
            if (!s->data_buf &&
                s->appendvec_mode &&
                s->leaf_hash_valid &&
                !sol_hash_is_zero(&s->leaf_hash) &&
                __atomic_load_n(&g_appendvec_meta_hash_mode, __ATOMIC_ACQUIRE) == 1) {

                size_t n = remaining;
                if ((uint64_t)n > s->data_remaining) n = (size_t)s->data_remaining;
                s->data_remaining -= (uint64_t)n;
                s->offset += (uint64_t)n;
                p += n;
                remaining -= n;

                if (s->data_remaining == 0) {
                    sol_err_t perr = appendvec_index
                        ? snapshot_appendvec_index_update(appendvec_index,
                                                          &s->stored.pubkey,
                                                          s->slot_hint,
                                                          s->stored.write_version,
                                                          &s->stored.owner,
                                                          s->stored.lamports,
                                                          s->data_len,
                                                          s->file_key,
                                                          s->record_start,
                                                          &s->leaf_hash)
                        : sol_accounts_db_bulk_writer_put_snapshot_account(
                            bulk,
                            &s->stored.pubkey,
                            &s->stored.owner,
                            s->stored.lamports,
                            NULL,
                            s->data_len,
                            s->stored.executable,
                            s->stored.rent_epoch,
                            s->slot_hint,
                            s->stored.write_version,
                            &s->leaf_hash,
                            s->file_key,
                            s->record_start);
                    if (perr != SOL_OK) return perr;
                    loaded_delta++;
                    s->loaded++;

                    if (s->align_after_data) {
                        size_t aligned = align_up_8((size_t)s->offset);
                        s->align_remaining = (aligned >= (size_t)s->offset) ? (aligned - (size_t)s->offset) : 0;
                        s->state = s->align_remaining ? APPENDVEC_STREAM_STATE_ALIGN : APPENDVEC_STREAM_STATE_RECORD;
                    } else {
                        s->state = APPENDVEC_STREAM_STATE_RECORD;
                    }
                }
                break;
            }

            if (!s->data_buf && remaining >= (size_t)s->data_remaining) {
                const sol_hash_t* leaf_hash = NULL;
                if (s->appendvec_mode && s->leaf_hash_valid && !sol_hash_is_zero(&s->leaf_hash)) {
                    int mode = __atomic_load_n(&g_appendvec_meta_hash_mode, __ATOMIC_ACQUIRE);
                    if (mode == -1) {
                        sol_account_t account = {0};
                        account.meta.owner = s->stored.owner;
                        account.meta.lamports = s->stored.lamports;
                        account.meta.rent_epoch = s->stored.rent_epoch;
                        account.meta.executable = s->stored.executable;
                        account.meta.data_len = s->stored.data_len;
                        account.data = (uint8_t*)p;

                        sol_hash_t computed = {0};
                        sol_account_hash(&s->stored.pubkey, &account, &computed);

                        int decided = (memcmp(computed.bytes, s->leaf_hash.bytes, SOL_HASH_SIZE) == 0) ? 1 : 0;
                        int expected = -1;
                        if (__atomic_compare_exchange_n(&g_appendvec_meta_hash_mode,
                                                       &expected,
                                                       decided,
                                                       false,
                                                       __ATOMIC_RELEASE,
                                                       __ATOMIC_RELAXED)) {
                            if (decided == 0) {
                                sol_log_warn("Snapshot appendvec metadata hash did not match computed account hash; "
                                             "re-hashing accounts during ingestion");
                            }
                        }

                        mode = __atomic_load_n(&g_appendvec_meta_hash_mode, __ATOMIC_ACQUIRE);
                    }

                    if (mode == 1) {
                        leaf_hash = &s->leaf_hash;
                    }
                }

                sol_err_t perr = SOL_OK;
                if (appendvec_index) {
                    sol_hash_t computed_leaf = {0};
                    const sol_hash_t* use_leaf = leaf_hash;
                    if (s->stored.lamports != 0 && (!use_leaf || sol_hash_is_zero(use_leaf))) {
                        sol_account_t account = {0};
                        account.meta.owner = s->stored.owner;
                        account.meta.lamports = s->stored.lamports;
                        account.meta.rent_epoch = s->stored.rent_epoch;
                        account.meta.executable = s->stored.executable;
                        account.meta.data_len = s->stored.data_len;
                        account.data = (uint8_t*)p;
                        sol_account_hash(&s->stored.pubkey, &account, &computed_leaf);
                        use_leaf = &computed_leaf;
                    }

                    perr = snapshot_appendvec_index_update(appendvec_index,
                                                          &s->stored.pubkey,
                                                          s->slot_hint,
                                                          s->stored.write_version,
                                                          &s->stored.owner,
                                                          s->stored.lamports,
                                                          s->data_len,
                                                          s->file_key,
                                                          s->record_start,
                                                          use_leaf);
                } else {
                    perr = s->appendvec_mode
                        ? sol_accounts_db_bulk_writer_put_snapshot_account(
                            bulk,
                            &s->stored.pubkey,
                            &s->stored.owner,
                            s->stored.lamports,
                            p,
                            s->data_len,
                            s->stored.executable,
                            s->stored.rent_epoch,
                            s->slot_hint,
                            s->stored.write_version,
                            leaf_hash,
                            s->file_key,
                            s->record_start)
                        : sol_accounts_db_bulk_writer_put_raw_versioned(
                            bulk,
                            &s->stored.pubkey,
                            &s->stored.owner,
                            s->stored.lamports,
                            p,
                            s->data_len,
                            s->stored.executable,
                            s->stored.rent_epoch,
                            s->slot_hint,
                            s->stored.write_version);
                }
                if (perr != SOL_OK) return perr;
                loaded_delta++;
                s->loaded++;

                size_t n = (size_t)s->data_remaining;
                s->data_remaining = 0;
                s->offset += (uint64_t)n;
                p += n;
                remaining -= n;

                if (s->align_after_data) {
                    size_t aligned = align_up_8((size_t)s->offset);
                    s->align_remaining = (aligned >= (size_t)s->offset) ? (aligned - (size_t)s->offset) : 0;
                    s->state = s->align_remaining ? APPENDVEC_STREAM_STATE_ALIGN : APPENDVEC_STREAM_STATE_RECORD;
                } else {
                    s->state = APPENDVEC_STREAM_STATE_RECORD;
                }
                break;
            }

            if (!s->data_buf) {
                if (s->data_len > (uint64_t)SIZE_MAX) {
                    return SOL_ERR_TOO_LARGE;
                }
                s->data_buf_len = (size_t)s->data_len;
                s->data_buf = sol_alloc(s->data_buf_len);
                if (!s->data_buf) return SOL_ERR_NOMEM;
                s->data_buf_written = 0;
            }

            size_t n = remaining;
            if ((uint64_t)n > s->data_remaining) n = (size_t)s->data_remaining;
            memcpy(s->data_buf + s->data_buf_written, p, n);
            s->data_buf_written += n;
            s->data_remaining -= (uint64_t)n;
            s->offset += (uint64_t)n;
            p += n;
            remaining -= n;

            if (s->data_remaining == 0) {
                const sol_hash_t* leaf_hash = NULL;
                if (s->appendvec_mode && s->leaf_hash_valid && !sol_hash_is_zero(&s->leaf_hash)) {
                    int mode = __atomic_load_n(&g_appendvec_meta_hash_mode, __ATOMIC_ACQUIRE);
                    if (mode == -1) {
                        sol_account_t account = {0};
                        account.meta.owner = s->stored.owner;
                        account.meta.lamports = s->stored.lamports;
                        account.meta.rent_epoch = s->stored.rent_epoch;
                        account.meta.executable = s->stored.executable;
                        account.meta.data_len = s->stored.data_len;
                        account.data = s->data_buf;

                        sol_hash_t computed = {0};
                        sol_account_hash(&s->stored.pubkey, &account, &computed);

                        int decided = (memcmp(computed.bytes, s->leaf_hash.bytes, SOL_HASH_SIZE) == 0) ? 1 : 0;
                        int expected = -1;
                        if (__atomic_compare_exchange_n(&g_appendvec_meta_hash_mode,
                                                       &expected,
                                                       decided,
                                                       false,
                                                       __ATOMIC_RELEASE,
                                                       __ATOMIC_RELAXED)) {
                            if (decided == 0) {
                                sol_log_warn("Snapshot appendvec metadata hash did not match computed account hash; "
                                             "re-hashing accounts during ingestion");
                            }
                        }

                        mode = __atomic_load_n(&g_appendvec_meta_hash_mode, __ATOMIC_ACQUIRE);
                    }

                    if (mode == 1) {
                        leaf_hash = &s->leaf_hash;
                    }
                }

                sol_err_t perr = SOL_OK;
                if (appendvec_index) {
                    sol_hash_t computed_leaf = {0};
                    const sol_hash_t* use_leaf = leaf_hash;
                    if (s->stored.lamports != 0 && (!use_leaf || sol_hash_is_zero(use_leaf))) {
                        sol_account_t account = {0};
                        account.meta.owner = s->stored.owner;
                        account.meta.lamports = s->stored.lamports;
                        account.meta.rent_epoch = s->stored.rent_epoch;
                        account.meta.executable = s->stored.executable;
                        account.meta.data_len = s->stored.data_len;
                        account.data = s->data_buf;
                        sol_account_hash(&s->stored.pubkey, &account, &computed_leaf);
                        use_leaf = &computed_leaf;
                    }

                    perr = snapshot_appendvec_index_update(appendvec_index,
                                                          &s->stored.pubkey,
                                                          s->slot_hint,
                                                          s->stored.write_version,
                                                          &s->stored.owner,
                                                          s->stored.lamports,
                                                          s->data_len,
                                                          s->file_key,
                                                          s->record_start,
                                                          use_leaf);
                } else {
                    perr = s->appendvec_mode
                        ? sol_accounts_db_bulk_writer_put_snapshot_account(
                            bulk,
                            &s->stored.pubkey,
                            &s->stored.owner,
                            s->stored.lamports,
                            s->data_buf,
                            s->data_len,
                            s->stored.executable,
                            s->stored.rent_epoch,
                            s->slot_hint,
                            s->stored.write_version,
                            leaf_hash,
                            s->file_key,
                            s->record_start)
                        : sol_accounts_db_bulk_writer_put_raw_versioned(
                            bulk,
                            &s->stored.pubkey,
                            &s->stored.owner,
                            s->stored.lamports,
                            s->data_buf,
                            s->data_len,
                            s->stored.executable,
                            s->stored.rent_epoch,
                            s->slot_hint,
                            s->stored.write_version);
                }
                if (perr != SOL_OK) return perr;
                loaded_delta++;
                s->loaded++;

                sol_free(s->data_buf);
                s->data_buf = NULL;
                s->data_buf_len = 0;
                s->data_buf_written = 0;

                if (s->align_after_data) {
                    size_t aligned = align_up_8((size_t)s->offset);
                    s->align_remaining = (aligned >= (size_t)s->offset) ? (aligned - (size_t)s->offset) : 0;
                    s->state = s->align_remaining ? APPENDVEC_STREAM_STATE_ALIGN : APPENDVEC_STREAM_STATE_RECORD;
                } else {
                    s->state = APPENDVEC_STREAM_STATE_RECORD;
                }
            }
            break;
        }

        case APPENDVEC_STREAM_STATE_ALIGN: {
            if (s->align_remaining == 0) {
                s->state = APPENDVEC_STREAM_STATE_RECORD;
                break;
            }

            size_t n = remaining < s->align_remaining ? remaining : s->align_remaining;
            s->align_remaining -= n;
            s->offset += (uint64_t)n;
            p += n;
            remaining -= n;
            if (s->align_remaining == 0) {
                s->state = APPENDVEC_STREAM_STATE_RECORD;
            }
            break;
        }
        }
    }

    if (is_last) {
        sol_err_t ferr = appendvec_stream_finalize(s);
        if (ferr != SOL_OK) return ferr;
        if (s->data_buf) {
            sol_free(s->data_buf);
            s->data_buf = NULL;
        }
    }

    if (out_loaded_delta) *out_loaded_delta = loaded_delta;
    return SOL_OK;
}

static void*
snapshot_stream_accounts_chunk_worker(void* arg) {
    snapshot_stream_accounts_ctx_t* ctx = (snapshot_stream_accounts_ctx_t*)arg;
    if (!ctx) return NULL;

    sol_accounts_db_bulk_writer_t* bulk = NULL;
    snapshot_appendvec_index_t* appendvec_index = NULL;

    if (ctx->defer_appendvec_index) {
        appendvec_index = ctx->appendvec_index;
        if (!appendvec_index) {
            snapshot_stream_set_err(ctx, SOL_ERR_NOMEM);
            __atomic_fetch_add(&ctx->done_threads, 1u, __ATOMIC_RELAXED);
            return NULL;
        }
        /* Core owner index is built during the final flush. */
        (void)__atomic_store_n(&ctx->core_index_ok, 0, __ATOMIC_RELAXED);
    } else {
        bulk = sol_accounts_db_bulk_writer_new(ctx->accounts_db, ctx->batch_capacity);
        if (!bulk) {
            snapshot_stream_set_err(ctx, SOL_ERR_NOMEM);
            __atomic_fetch_add(&ctx->done_threads, 1u, __ATOMIC_RELAXED);
            return NULL;
        }

        sol_accounts_db_bulk_writer_set_use_merge(bulk, true);
        if (ctx->max_bytes_queued > 0) {
            sol_accounts_db_bulk_writer_set_max_bytes(bulk, ctx->max_bytes_queued);
        }

        if (sol_accounts_db_is_appendvec(ctx->accounts_db)) {
            (void)sol_accounts_db_bulk_writer_set_write_owner_reverse(bulk, false);
        }

        if (__atomic_load_n(&ctx->core_index_ok, __ATOMIC_RELAXED) != 0) {
            sol_err_t idx_err = sol_accounts_db_bulk_writer_set_write_owner_index(bulk, true);
            if (idx_err == SOL_OK) {
                sol_accounts_db_bulk_writer_set_write_owner_index_core_only(bulk, true);
                if (!sol_accounts_db_bulk_writer_is_writing_owner_index(bulk)) {
                    (void)__atomic_store_n(&ctx->core_index_ok, 0, __ATOMIC_RELAXED);
                }
            } else {
                (void)__atomic_store_n(&ctx->core_index_ok, 0, __ATOMIC_RELAXED);
            }
        }
    }

    appendvec_stream_t stream = {0};
    char current_file[128] = {0};
    bool have_file = false;

    while (1) {
        if (__atomic_load_n(&ctx->first_err, __ATOMIC_RELAXED) != SOL_OK) break;

        pthread_mutex_lock(&ctx->chunk_lock);
        while (!ctx->chunk_head && !ctx->chunk_producer_done &&
               __atomic_load_n(&ctx->first_err, __ATOMIC_RELAXED) == SOL_OK) {
            pthread_cond_wait(&ctx->chunk_cv, &ctx->chunk_lock);
        }

        snapshot_stream_chunk_task_t* t = ctx->chunk_head;
        if (t) {
            ctx->chunk_head = t->next;
            if (!ctx->chunk_head) ctx->chunk_tail = NULL;
            ctx->chunk_queue_len--;
            if (ctx->chunk_bytes_queued >= t->len) {
                ctx->chunk_bytes_queued -= t->len;
            } else {
                ctx->chunk_bytes_queued = 0;
            }
            pthread_cond_signal(&ctx->chunk_cv_space);
        }
        bool done = ctx->chunk_producer_done;
        pthread_mutex_unlock(&ctx->chunk_lock);

        if (!t) {
            if (done) break;
            continue;
        }

        if (t->file_offset == 0) {
            if (have_file && !stream.stopped) {
                snapshot_stream_set_err(ctx, SOL_ERR_SNAPSHOT_CORRUPT);
                sol_free(t->data);
                sol_free(t);
                break;
            }

            uint64_t slot = 0;
            uint64_t id = 0;
            if (!parse_slot_id_from_filename(t->file_name, &slot, &id)) {
                snapshot_stream_set_err(ctx, SOL_ERR_SNAPSHOT_CORRUPT);
                sol_free(t->data);
                sol_free(t);
                break;
            }

            snprintf(current_file, sizeof(current_file), "%s", t->file_name);
            have_file = true;
            const bool appendvec_mode = sol_accounts_db_is_appendvec(ctx->accounts_db);
            uint64_t file_key = ((uint64_t)slot << 32) | (id & 0xFFFFFFFFu);
            appendvec_stream_reset(&stream, (sol_slot_t)slot, file_key, t->file_size);
            stream.appendvec_mode = appendvec_mode;
        } else if (!have_file || strcmp(current_file, t->file_name) != 0) {
            snapshot_stream_set_err(ctx, SOL_ERR_SNAPSHOT_CORRUPT);
            sol_free(t->data);
            sol_free(t);
            break;
        }

        uint64_t loaded_delta = 0;
        sol_err_t load_err = appendvec_stream_feed(&stream,
                                                   bulk,
                                                   appendvec_index,
                                                   t->data,
                                                   t->len,
                                                   t->file_offset,
                                                   t->is_last,
                                                   &loaded_delta);
        if (load_err == SOL_ERR_NOTFOUND) {
            load_err = SOL_ERR_SNAPSHOT_CORRUPT;
        }
        if (load_err != SOL_OK) {
            snapshot_stream_set_err(ctx, load_err);
        }

        if (loaded_delta > 0) {
            (void)__atomic_fetch_add(&ctx->accounts_loaded, loaded_delta, __ATOMIC_RELAXED);
        }
        if (t->len > 0) {
            (void)__atomic_fetch_add(&ctx->bytes_processed, (uint64_t)t->len, __ATOMIC_RELAXED);
        }

        if (t->is_last) {
            (void)__atomic_fetch_add(&ctx->files_processed, 1u, __ATOMIC_RELAXED);
            have_file = false;
        }

        sol_free(t->data);
        sol_free(t);

        if (load_err != SOL_OK) {
            break;
        }
    }

    if (stream.data_buf) {
        sol_free(stream.data_buf);
        stream.data_buf = NULL;
    }

    if (bulk) {
        sol_err_t flush_err = sol_accounts_db_bulk_writer_flush(bulk);
        if (flush_err != SOL_OK) {
            snapshot_stream_set_err(ctx, flush_err);
        }
        sol_accounts_db_bulk_writer_destroy(bulk);
    }

    __atomic_fetch_add(&ctx->done_threads, 1u, __ATOMIC_RELAXED);

    pthread_mutex_lock(&ctx->lock);
    pthread_cond_broadcast(&ctx->cv);
    pthread_cond_broadcast(&ctx->cv_space);
    pthread_mutex_unlock(&ctx->lock);

    pthread_mutex_lock(&ctx->chunk_lock);
    pthread_cond_broadcast(&ctx->chunk_cv);
    pthread_cond_broadcast(&ctx->chunk_cv_space);
    pthread_mutex_unlock(&ctx->chunk_lock);

    return NULL;
}

static void*
snapshot_stream_accounts_worker(void* arg) {
    snapshot_stream_accounts_ctx_t* ctx = (snapshot_stream_accounts_ctx_t*)arg;
    if (!ctx) return NULL;

    sol_accounts_db_bulk_writer_t* bulk = NULL;
    snapshot_appendvec_index_t* appendvec_index = NULL;

    if (ctx->defer_appendvec_index) {
        appendvec_index = ctx->appendvec_index;
        if (!appendvec_index) {
            snapshot_stream_set_err(ctx, SOL_ERR_NOMEM);
            __atomic_fetch_add(&ctx->done_threads, 1u, __ATOMIC_RELAXED);
            return NULL;
        }
        /* Core owner index is built during the final flush. */
        (void)__atomic_store_n(&ctx->core_index_ok, 0, __ATOMIC_RELAXED);
    } else {
        bulk = sol_accounts_db_bulk_writer_new(ctx->accounts_db, ctx->batch_capacity);
        if (!bulk) {
            snapshot_stream_set_err(ctx, SOL_ERR_NOMEM);
            __atomic_fetch_add(&ctx->done_threads, 1u, __ATOMIC_RELAXED);
            return NULL;
        }

        sol_accounts_db_bulk_writer_set_use_merge(bulk, true);
        if (ctx->max_bytes_queued > 0) {
            sol_accounts_db_bulk_writer_set_max_bytes(bulk, ctx->max_bytes_queued);
        }

        if (sol_accounts_db_is_appendvec(ctx->accounts_db)) {
            (void)sol_accounts_db_bulk_writer_set_write_owner_reverse(bulk, false);
        }

        if (__atomic_load_n(&ctx->core_index_ok, __ATOMIC_RELAXED) != 0) {
            sol_err_t idx_err = sol_accounts_db_bulk_writer_set_write_owner_index(bulk, true);
            if (idx_err == SOL_OK) {
                sol_accounts_db_bulk_writer_set_write_owner_index_core_only(bulk, true);
                if (!sol_accounts_db_bulk_writer_is_writing_owner_index(bulk)) {
                    (void)__atomic_store_n(&ctx->core_index_ok, 0, __ATOMIC_RELAXED);
                }
            } else {
                (void)__atomic_store_n(&ctx->core_index_ok, 0, __ATOMIC_RELAXED);
            }
        }
    }

    while (1) {
        if (__atomic_load_n(&ctx->first_err, __ATOMIC_RELAXED) != SOL_OK) break;

        pthread_mutex_lock(&ctx->lock);
        while (!ctx->head && !ctx->producer_done &&
               __atomic_load_n(&ctx->first_err, __ATOMIC_RELAXED) == SOL_OK) {
            pthread_cond_wait(&ctx->cv, &ctx->lock);
        }

        snapshot_stream_task_t* t = ctx->head;
        if (t) {
            ctx->head = t->next;
            if (!ctx->head) ctx->tail = NULL;
            ctx->queue_len--;
            if (ctx->queue_bytes_queued >= t->len) {
                ctx->queue_bytes_queued -= t->len;
            } else {
                ctx->queue_bytes_queued = 0;
            }
            pthread_cond_signal(&ctx->cv_space);
        }
        bool done = ctx->producer_done;
        pthread_mutex_unlock(&ctx->lock);

        if (!t) {
            if (done) break;
            continue;
        }

        sol_slot_t file_slot = 0;
        if (strcmp(t->file_name, "storage.bin") == 0) {
            file_slot = 0;
        } else {
            uint64_t slot = 0;
            uint64_t id = 0;
            if (parse_slot_id_from_filename(t->file_name, &slot, &id)) {
                file_slot = (sol_slot_t)slot;
            } else {
                /* Unexpected file; ignore. */
                sol_free(t->data);
                sol_free(t);
                continue;
            }
        }

        uint64_t loaded = 0;
        sol_err_t load_err = load_accounts_from_storage_mapped(t->data,
                                                               t->len,
                                                               t->file_name,
                                                               file_slot,
                                                               ctx->accounts_db,
                                                               bulk,
                                                               appendvec_index,
                                                               &loaded);
        if (load_err == SOL_ERR_NOTFOUND) {
            load_err = SOL_ERR_SNAPSHOT_CORRUPT;
        }
        if (load_err != SOL_OK) {
            snapshot_stream_set_err(ctx, load_err);
        }

        if (loaded > 0) {
            (void)__atomic_fetch_add(&ctx->accounts_loaded, loaded, __ATOMIC_RELAXED);
        }
        if (t->len > 0) {
            (void)__atomic_fetch_add(&ctx->bytes_processed, (uint64_t)t->len, __ATOMIC_RELAXED);
        }
        (void)__atomic_fetch_add(&ctx->files_processed, 1u, __ATOMIC_RELAXED);

        sol_free(t->data);
        sol_free(t);

        if (load_err != SOL_OK) {
            break;
        }
    }

    if (bulk) {
        sol_err_t flush_err = sol_accounts_db_bulk_writer_flush(bulk);
        if (flush_err != SOL_OK) {
            snapshot_stream_set_err(ctx, flush_err);
        }
        sol_accounts_db_bulk_writer_destroy(bulk);
    }

    __atomic_fetch_add(&ctx->done_threads, 1u, __ATOMIC_RELAXED);

    pthread_mutex_lock(&ctx->lock);
    pthread_cond_broadcast(&ctx->cv);
    pthread_cond_broadcast(&ctx->cv_space);
    pthread_mutex_unlock(&ctx->lock);

    pthread_mutex_lock(&ctx->chunk_lock);
    pthread_cond_broadcast(&ctx->chunk_cv);
    pthread_cond_broadcast(&ctx->chunk_cv_space);
    pthread_mutex_unlock(&ctx->chunk_lock);

    return NULL;
}

static void*
snapshot_stream_accounts_monitor(void* arg) {
    snapshot_stream_accounts_ctx_t* ctx = (snapshot_stream_accounts_ctx_t*)arg;
    if (!ctx) return NULL;

    uint64_t last_log_ms = now_ms_monotonic();

    while (1) {
        if (__atomic_load_n(&ctx->done_threads, __ATOMIC_RELAXED) >= ctx->thread_count) break;
        if (__atomic_load_n(&ctx->first_err, __ATOMIC_RELAXED) != SOL_OK) break;

        uint64_t now = now_ms_monotonic();
        if (now - last_log_ms >= 5000) {
            uint64_t files = __atomic_load_n(&ctx->files_processed, __ATOMIC_RELAXED);
            uint64_t accounts = __atomic_load_n(&ctx->accounts_loaded, __ATOMIC_RELAXED);
            uint64_t bytes = __atomic_load_n(&ctx->bytes_processed, __ATOMIC_RELAXED);

            pthread_mutex_lock(&ctx->lock);
            size_t qlen = ctx->queue_len;
            size_t queue_mb = ctx->queue_bytes_queued / (1024u * 1024u);
            size_t queue_max_mb = ctx->queue_max_bytes / (1024u * 1024u);
            size_t queue_hi_mb = ctx->queue_bytes_highwater / (1024u * 1024u);
            pthread_mutex_unlock(&ctx->lock);

            pthread_mutex_lock(&ctx->chunk_lock);
            size_t chunk_qlen = ctx->chunk_queue_len;
            size_t chunk_mb = ctx->chunk_bytes_queued / (1024u * 1024u);
            size_t chunk_max_mb = ctx->chunk_max_bytes_queued / (1024u * 1024u);
            size_t chunk_hi_mb = ctx->chunk_bytes_highwater / (1024u * 1024u);
            size_t queue_hi = ctx->queue_highwater;
            size_t chunk_hi = ctx->chunk_queue_highwater;
            pthread_mutex_unlock(&ctx->chunk_lock);

            uint64_t queue_wait_ms = __atomic_load_n(&ctx->queue_wait_ms, __ATOMIC_RELAXED);
            uint64_t chunk_wait_ms = __atomic_load_n(&ctx->chunk_wait_ms, __ATOMIC_RELAXED);
            uint64_t queue_waits = __atomic_load_n(&ctx->queue_waits, __ATOMIC_RELAXED);
            uint64_t chunk_waits = __atomic_load_n(&ctx->chunk_waits, __ATOMIC_RELAXED);

            sol_log_info("Snapshot accounts load progress: %lu streamed files, %lu accounts, %lu MB read "
                         "(queue=%zu/%zu hi=%zu, queue_mb=%zu/%zu hi=%zu, chunk_queue=%zu/%zu hi=%zu, chunk_mb=%zu/%zu hi=%zu, waits=%lums/%lums (%lu/%lu))",
                         (unsigned long)files,
                         (unsigned long)accounts,
                         (unsigned long)(bytes / (1024 * 1024)),
                         qlen,
                         ctx->queue_max,
                         queue_hi,
                         queue_mb,
                         queue_max_mb,
                         queue_hi_mb,
                         chunk_qlen,
                         ctx->chunk_queue_max,
                         chunk_hi,
                         chunk_mb,
                         chunk_max_mb,
                         chunk_hi_mb,
                         (unsigned long)queue_wait_ms,
                         (unsigned long)chunk_wait_ms,
                         (unsigned long)queue_waits,
                         (unsigned long)chunk_waits);
            last_log_ms = now;
        }

        usleep(200u * 1000u);
    }

    return NULL;
}

static bool
snapshot_stream_accounts_enabled(void) {
    const char* env = getenv("SOL_SNAPSHOT_STREAM_ACCOUNTS");
    if (!env || env[0] == '\0') return true;

    while (*env && isspace((unsigned char)*env)) env++;
    if (*env == '\0') return true;

    if (env[0] == '0') return false;
    if (env[0] == 'n' || env[0] == 'N') return false;
    if (env[0] == 'f' || env[0] == 'F') return false;
    return true;
}

typedef struct {
    const snapshot_appendvec_index_t* idx;
    sol_accounts_db_t*               accounts_db;
    size_t                          batch_capacity;
    size_t                          max_bytes_queued;
    bool                            want_owner_index;
    size_t                          shard_lo;
    size_t                          shard_hi;
    uint64_t                        written;
    uint64_t                        deleted;
    int                             err;
    int*                            first_err;
} snapshot_appendvec_index_flush_worker_t;

static void
snapshot_appendvec_index_flush_set_err(int* first_err, sol_err_t err) {
    if (!first_err || err == SOL_OK) return;
    int expected = SOL_OK;
    (void)__atomic_compare_exchange_n(first_err, &expected, err, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
}

static void*
snapshot_appendvec_index_flush_worker(void* arg) {
    snapshot_appendvec_index_flush_worker_t* w = (snapshot_appendvec_index_flush_worker_t*)arg;
    if (!w) return NULL;

    w->written = 0;
    w->deleted = 0;
    w->err = SOL_OK;

    if (__atomic_load_n(w->first_err, __ATOMIC_RELAXED) != SOL_OK) {
        return NULL;
    }

    sol_accounts_db_bulk_writer_t* bulk =
        sol_accounts_db_bulk_writer_new(w->accounts_db, w->batch_capacity ? w->batch_capacity : 16384);
    if (!bulk) {
        w->err = SOL_ERR_NOMEM;
        snapshot_appendvec_index_flush_set_err(w->first_err, w->err);
        return NULL;
    }

    sol_accounts_db_bulk_writer_set_use_merge(bulk, false);
    if (w->max_bytes_queued > 0) {
        sol_accounts_db_bulk_writer_set_max_bytes(bulk, w->max_bytes_queued);
    }

    /* Keep parity with existing AppendVec bootstrap defaults: core owner index
     * only, owner-reverse mapping deferred. */
    if (sol_accounts_db_is_appendvec(w->accounts_db)) {
        (void)sol_accounts_db_bulk_writer_set_write_owner_reverse(bulk, false);
    }

    if (w->want_owner_index) {
        sol_err_t idx_err = sol_accounts_db_bulk_writer_set_write_owner_index(bulk, true);
        if (idx_err != SOL_OK) {
            w->err = idx_err;
            sol_accounts_db_bulk_writer_destroy(bulk);
            snapshot_appendvec_index_flush_set_err(w->first_err, w->err);
            return NULL;
        }
        sol_accounts_db_bulk_writer_set_write_owner_index_core_only(bulk, true);
    }

    for (size_t si = w->shard_lo; si < w->shard_hi; si++) {
        if (__atomic_load_n(w->first_err, __ATOMIC_RELAXED) != SOL_OK) {
            break;
        }

        sol_pubkey_map_t* map = w->idx->shards[si].map;
        if (!map || !map->inner) continue;

        sol_map_iter_t it = sol_map_iter(map->inner);
        void* key = NULL;
        void* val = NULL;
        while (sol_map_iter_next(&it, &key, &val)) {
            if (__atomic_load_n(w->first_err, __ATOMIC_RELAXED) != SOL_OK) {
                break;
            }
            if (!key || !val) continue;

            snapshot_appendvec_index_val_t* v = (snapshot_appendvec_index_val_t*)val;
            if (v->lamports == 0 || sol_hash_is_zero(&v->leaf_hash)) {
                /* Zero-lamport accounts (tombstones) must be written as deletes
                   to the DB so that stale entries from the full snapshot are
                   properly removed.  Previously these were silently skipped,
                   leaving millions of ghost accounts after incremental snapshot
                   merge. */
                sol_pubkey_t pk;
                memcpy(pk.bytes, key, sizeof(pk.bytes));
                sol_err_t derr = sol_accounts_db_bulk_writer_delete_versioned(
                    bulk,
                    &pk,
                    (sol_slot_t)v->slot,
                    v->write_version);
                if (derr != SOL_OK) {
                    w->err = derr;
                    snapshot_appendvec_index_flush_set_err(w->first_err, w->err);
                    break;
                }
                w->deleted++;
                continue;
            }

            sol_pubkey_t pk;
            memcpy(pk.bytes, key, sizeof(pk.bytes));

            sol_err_t perr = sol_accounts_db_bulk_writer_put_snapshot_account(
                bulk,
                &pk,
                &v->owner,
                v->lamports,
                NULL,
                v->data_len,
                false,
                0,
                (sol_slot_t)v->slot,
                v->write_version,
                &v->leaf_hash,
                v->file_key,
                v->record_offset);
            if (perr != SOL_OK) {
                w->err = perr;
                snapshot_appendvec_index_flush_set_err(w->first_err, w->err);
                break;
            }
            w->written++;
        }

        if (w->err != SOL_OK) break;
    }

    sol_err_t flush_err = sol_accounts_db_bulk_writer_flush(bulk);
    if (w->err == SOL_OK && flush_err != SOL_OK) {
        w->err = flush_err;
        snapshot_appendvec_index_flush_set_err(w->first_err, w->err);
    }
    sol_accounts_db_bulk_writer_destroy(bulk);
    return NULL;
}

static sol_err_t
snapshot_appendvec_index_flush(snapshot_appendvec_index_t* idx,
                               sol_accounts_db_t* accounts_db,
                               size_t batch_capacity,
                               size_t max_bytes_queued,
                               int* out_core_index_ok) {
    if (out_core_index_ok) *out_core_index_ok = 0;
    if (!idx || !accounts_db) return SOL_ERR_INVAL;

    uint64_t started_ms = now_ms_monotonic();

    uint32_t threads = snapshot_appendvec_index_flush_threads_default(idx);

    /* Determine whether the core owner index is available. For correctness, we
     * either build it for all writers or skip it entirely. */
    bool want_owner_index = false;
    int core_ok = 0;
    {
        sol_accounts_db_bulk_writer_t* probe =
            sol_accounts_db_bulk_writer_new(accounts_db, 1024);
        if (probe) {
            sol_accounts_db_bulk_writer_set_use_merge(probe, false);
            if (sol_accounts_db_is_appendvec(accounts_db)) {
                (void)sol_accounts_db_bulk_writer_set_write_owner_reverse(probe, false);
            }
            sol_err_t idx_err = sol_accounts_db_bulk_writer_set_write_owner_index(probe, true);
            if (idx_err == SOL_OK) {
                sol_accounts_db_bulk_writer_set_write_owner_index_core_only(probe, true);
                if (sol_accounts_db_bulk_writer_is_writing_owner_index(probe)) {
                    want_owner_index = true;
                    core_ok = 1;
                }
            }
            sol_accounts_db_bulk_writer_destroy(probe);
        }
    }

    if (threads <= 1u || idx->shard_count <= 1u) {
        int first_err = SOL_OK;
        snapshot_appendvec_index_flush_worker_t w = {
            .idx = idx,
            .accounts_db = accounts_db,
            .batch_capacity = batch_capacity,
            .max_bytes_queued = max_bytes_queued,
            .want_owner_index = want_owner_index,
            .shard_lo = 0,
            .shard_hi = idx->shard_count,
            .written = 0,
            .deleted = 0,
            .err = SOL_OK,
            .first_err = &first_err,
        };
        (void)snapshot_appendvec_index_flush_worker(&w);

        sol_err_t err = (sol_err_t)__atomic_load_n(&first_err, __ATOMIC_RELAXED);
        if (out_core_index_ok) *out_core_index_ok = (err == SOL_OK) ? core_ok : 0;

        uint64_t elapsed_ms = now_ms_monotonic() - started_ms;
        if (err == SOL_OK) {
            sol_log_info("Snapshot accounts index flush: wrote %lu entries (%lu tombstones deleted) in %lums",
                         (unsigned long)w.written,
                         (unsigned long)w.deleted,
                         (unsigned long)elapsed_ms);
        }
        return err;
    }

    int first_err = SOL_OK;
    pthread_t* tids = sol_calloc(threads, sizeof(*tids));
    snapshot_appendvec_index_flush_worker_t* ws = sol_calloc(threads, sizeof(*ws));
    if (!tids || !ws) {
        sol_free(tids);
        sol_free(ws);
        return SOL_ERR_NOMEM;
    }

    uint32_t created = 0;
    for (uint32_t t = 0; t < threads; t++) {
        size_t lo = (idx->shard_count * (size_t)t) / (size_t)threads;
        size_t hi = (idx->shard_count * (size_t)(t + 1u)) / (size_t)threads;
        if (hi <= lo) continue;

        ws[created] = (snapshot_appendvec_index_flush_worker_t){
            .idx = idx,
            .accounts_db = accounts_db,
            .batch_capacity = batch_capacity,
            .max_bytes_queued = max_bytes_queued,
            .want_owner_index = want_owner_index,
            .shard_lo = lo,
            .shard_hi = hi,
            .written = 0,
            .deleted = 0,
            .err = SOL_OK,
            .first_err = &first_err,
        };

        if (pthread_create(&tids[created], NULL, snapshot_appendvec_index_flush_worker, &ws[created]) != 0) {
            snapshot_appendvec_index_flush_set_err(&first_err, SOL_ERR_IO);
            break;
        }
        created++;
    }

    for (uint32_t i = 0; i < created; i++) {
        (void)pthread_join(tids[i], NULL);
    }

    uint64_t written = 0;
    uint64_t deleted = 0;
    for (uint32_t i = 0; i < created; i++) {
        written += ws[i].written;
        deleted += ws[i].deleted;
    }

    sol_free(tids);
    sol_free(ws);

    sol_err_t err = (sol_err_t)__atomic_load_n(&first_err, __ATOMIC_RELAXED);
    if (out_core_index_ok) *out_core_index_ok = (err == SOL_OK) ? core_ok : 0;

    uint64_t elapsed_ms = now_ms_monotonic() - started_ms;
    if (err == SOL_OK) {
        sol_log_info("Snapshot accounts index flush: wrote %lu entries (%lu tombstones deleted) in %lums (threads=%u)",
                     (unsigned long)written,
                     (unsigned long)deleted,
                     (unsigned long)elapsed_ms,
                     (unsigned)created);
    }

    return err;
}

static sol_err_t
load_accounts_from_archive_streaming(const char* archive_path,
                                     const char* output_dir,
                                     sol_accounts_db_t* accounts_db,
                                     uint32_t thread_count,
                                     size_t batch_capacity,
                                     size_t max_bytes_queued,
                                     uint64_t* out_count,
                                     int* out_core_index_ok) {
    if (!archive_path || !output_dir || !accounts_db) return SOL_ERR_INVAL;
    if (out_count) *out_count = 0;
    if (out_core_index_ok) *out_core_index_ok = 0;
    if (thread_count == 0) thread_count = 1;

    snapshot_stream_accounts_ctx_t ctx = {0};
    ctx.accounts_db = accounts_db;
    ctx.batch_capacity = batch_capacity ? batch_capacity : 16384;
    ctx.max_bytes_queued = max_bytes_queued;
    ctx.first_err = SOL_OK;
    ctx.core_index_ok = 1;
    ctx.persist_fd = -1;
    ctx.persist_file[0] = '\0';
    ctx.persist_accounts_files = sol_accounts_db_is_appendvec(accounts_db);
    ctx.accounts_out_dir[0] = '\0';
    if (ctx.persist_accounts_files) {
        int n = snprintf(ctx.accounts_out_dir, sizeof(ctx.accounts_out_dir), "%s/accounts", output_dir);
        if (n < 0 || (size_t)n >= sizeof(ctx.accounts_out_dir)) {
            return SOL_ERR_TOO_LARGE;
        }
        sol_err_t mkerr = snapshot_mkdir_recursive(ctx.accounts_out_dir);
        if (mkerr != SOL_OK) {
            return mkerr;
        }
    }

    uint32_t file_threads = thread_count;
    ctx.thread_count = file_threads + 1u; /* include chunk worker */

    ctx.defer_appendvec_index = false;
    ctx.appendvec_index = NULL;
    if (ctx.persist_accounts_files && snapshot_defer_appendvec_index_enabled()) {
        uint32_t shards = snapshot_appendvec_index_default_shards(file_threads);
        size_t cap = snapshot_appendvec_index_default_capacity_per_shard(shards);
        if (cap == 0) {
            sol_log_warn("Snapshot ingest: deferred AppendVec index requested but no safe default capacity could be derived; "
                         "set SOL_SNAPSHOT_DEFER_APPENDVEC_INDEX_CAPACITY_PER_SHARD to enable. Falling back to RocksDB merge ingestion.");
        } else {
            ctx.appendvec_index = snapshot_appendvec_index_new(shards, cap);
            if (ctx.appendvec_index) {
                ctx.defer_appendvec_index = true;
                sol_log_info("Snapshot ingest: deferring AppendVec index writes (shards=%u, cap/shard=%zu)",
                             (unsigned)shards,
                             cap);
            } else {
                sol_log_warn("Snapshot ingest: failed to allocate deferred AppendVec index; "
                             "falling back to RocksDB merge ingestion");
            }
        }
    }

    size_t qmax = (size_t)file_threads * 16u;
    if (qmax < 128u) qmax = 128u;
    if (qmax > 32768u) qmax = 32768u;
    size_t env_qmax = snapshot_env_size_t("SOL_SNAPSHOT_STREAM_QUEUE_MAX", 16u, 131072u);
    if (env_qmax > 0) qmax = env_qmax;
    ctx.queue_max = qmax;

    size_t queue_max_bytes = max_bytes_queued ? (max_bytes_queued * 2u) : (512u * 1024u * 1024u);
    size_t env_queue_mb = snapshot_env_size_t("SOL_SNAPSHOT_STREAM_QUEUE_MAX_MB", 64u, 131072u);
    if (env_queue_mb > 0) queue_max_bytes = env_queue_mb * 1024u * 1024u;
    size_t queue_min_bytes = 256u * 1024u * 1024u;
    size_t queue_max_cap = (size_t)16u * 1024u * 1024u * 1024u;
    if (queue_max_bytes < queue_min_bytes) queue_max_bytes = queue_min_bytes;
    if (queue_max_bytes > queue_max_cap) queue_max_bytes = queue_max_cap;
    ctx.queue_max_bytes = queue_max_bytes;

    size_t chunk_qmax = (size_t)file_threads * 8u;
    if (chunk_qmax < 32u) chunk_qmax = 32u;
    if (chunk_qmax > 4096u) chunk_qmax = 4096u;
    size_t env_chunk_qmax = snapshot_env_size_t("SOL_SNAPSHOT_STREAM_CHUNK_QUEUE_MAX", 16u, 65536u);
    if (env_chunk_qmax > 0) chunk_qmax = env_chunk_qmax;
    ctx.chunk_queue_max = chunk_qmax;

    size_t chunk_max_bytes = max_bytes_queued ? (max_bytes_queued * 2u) : (512u * 1024u * 1024u);
    size_t env_chunk_max_mb = snapshot_env_size_t("SOL_SNAPSHOT_STREAM_CHUNK_MAX_MB", 64u, 131072u);
    if (env_chunk_max_mb > 0) chunk_max_bytes = env_chunk_max_mb * 1024u * 1024u;
    size_t chunk_min_bytes = 128u * 1024u * 1024u;
    size_t chunk_max_cap = (size_t)8u * 1024u * 1024u * 1024u;
    if (chunk_max_bytes < chunk_min_bytes) chunk_max_bytes = chunk_min_bytes;
    if (chunk_max_bytes > chunk_max_cap) chunk_max_bytes = chunk_max_cap;
    ctx.chunk_max_bytes_queued = chunk_max_bytes;

    sol_log_info("Snapshot stream config: file_threads=%u queue_max=%zu queue_max_mb=%zu chunk_queue_max=%zu chunk_max_mb=%zu",
                 (unsigned)file_threads,
                 ctx.queue_max,
                 ctx.queue_max_bytes / (1024u * 1024u),
                 ctx.chunk_queue_max,
                 ctx.chunk_max_bytes_queued / (1024u * 1024u));

    if (pthread_mutex_init(&ctx.lock, NULL) != 0) return SOL_ERR_IO;
    if (pthread_cond_init(&ctx.cv, NULL) != 0) {
        pthread_mutex_destroy(&ctx.lock);
        return SOL_ERR_IO;
    }
    if (pthread_cond_init(&ctx.cv_space, NULL) != 0) {
        pthread_cond_destroy(&ctx.cv);
        pthread_mutex_destroy(&ctx.lock);
        return SOL_ERR_IO;
    }

    if (pthread_mutex_init(&ctx.chunk_lock, NULL) != 0) {
        pthread_cond_destroy(&ctx.cv_space);
        pthread_cond_destroy(&ctx.cv);
        pthread_mutex_destroy(&ctx.lock);
        return SOL_ERR_IO;
    }
    if (pthread_cond_init(&ctx.chunk_cv, NULL) != 0) {
        pthread_mutex_destroy(&ctx.chunk_lock);
        pthread_cond_destroy(&ctx.cv_space);
        pthread_cond_destroy(&ctx.cv);
        pthread_mutex_destroy(&ctx.lock);
        return SOL_ERR_IO;
    }
    if (pthread_cond_init(&ctx.chunk_cv_space, NULL) != 0) {
        pthread_cond_destroy(&ctx.chunk_cv);
        pthread_mutex_destroy(&ctx.chunk_lock);
        pthread_cond_destroy(&ctx.cv_space);
        pthread_cond_destroy(&ctx.cv);
        pthread_mutex_destroy(&ctx.lock);
        return SOL_ERR_IO;
    }

    pthread_t* workers = sol_calloc(file_threads, sizeof(*workers));
    if (!workers) {
        pthread_cond_destroy(&ctx.chunk_cv_space);
        pthread_cond_destroy(&ctx.chunk_cv);
        pthread_mutex_destroy(&ctx.chunk_lock);
        pthread_cond_destroy(&ctx.cv_space);
        pthread_cond_destroy(&ctx.cv);
        pthread_mutex_destroy(&ctx.lock);
        return SOL_ERR_NOMEM;
    }

    pthread_t chunk_worker;
    bool have_chunk_worker = false;
    if (pthread_create(&chunk_worker, NULL, snapshot_stream_accounts_chunk_worker, &ctx) == 0) {
        have_chunk_worker = true;
    } else {
        snapshot_stream_set_err(&ctx, SOL_ERR_IO);
    }

    pthread_t monitor;
    bool have_monitor = false;
    if (pthread_create(&monitor, NULL, snapshot_stream_accounts_monitor, &ctx) == 0) {
        have_monitor = true;
    }

    uint32_t created = 0;
    for (uint32_t i = 0; i < file_threads; i++) {
        if (pthread_create(&workers[i], NULL, snapshot_stream_accounts_worker, &ctx) != 0) {
            snapshot_stream_set_err(&ctx, SOL_ERR_IO);
            break;
        }
        created++;
    }

    sol_archive_extract_opts_t opts = SOL_ARCHIVE_EXTRACT_OPTS_DEFAULT;
    opts.output_dir = output_dir;
    opts.verify = false;
    opts.stream_prefix = "accounts/";
    opts.stream_file_callback = snapshot_stream_accounts_file_cb;
    opts.stream_chunk_callback = snapshot_stream_accounts_chunk_cb;
    opts.stream_file_ctx = &ctx;
    opts.stream_max_file_size = 64u * 1024u * 1024u; /* 64MB safety cap */

    sol_err_t extract_err = sol_snapshot_archive_extract(archive_path, &opts);
    if (extract_err != SOL_OK) {
        snapshot_stream_set_err(&ctx, extract_err);
    }

    pthread_mutex_lock(&ctx.lock);
    ctx.producer_done = true;
    pthread_cond_broadcast(&ctx.cv);
    pthread_cond_broadcast(&ctx.cv_space);
    pthread_mutex_unlock(&ctx.lock);

    pthread_mutex_lock(&ctx.chunk_lock);
    ctx.chunk_producer_done = true;
    pthread_cond_broadcast(&ctx.chunk_cv);
    pthread_cond_broadcast(&ctx.chunk_cv_space);
    pthread_mutex_unlock(&ctx.chunk_lock);

    for (uint32_t i = 0; i < created; i++) {
        (void)pthread_join(workers[i], NULL);
    }
    if (have_chunk_worker) {
        (void)pthread_join(chunk_worker, NULL);
    }
    if (have_monitor) {
        (void)pthread_join(monitor, NULL);
    }

    sol_free(workers);

    /* Free any queued tasks left over (typically only on error). */
    pthread_mutex_lock(&ctx.lock);
    snapshot_stream_task_t* t = ctx.head;
    ctx.head = NULL;
    ctx.tail = NULL;
    ctx.queue_len = 0;
    pthread_mutex_unlock(&ctx.lock);

    while (t) {
        snapshot_stream_task_t* next = t->next;
        sol_free(t->data);
        sol_free(t);
        t = next;
    }

    pthread_mutex_lock(&ctx.chunk_lock);
    snapshot_stream_chunk_task_t* ct = ctx.chunk_head;
    ctx.chunk_head = NULL;
    ctx.chunk_tail = NULL;
    ctx.chunk_queue_len = 0;
    ctx.chunk_bytes_queued = 0;
    pthread_mutex_unlock(&ctx.chunk_lock);

    while (ct) {
        snapshot_stream_chunk_task_t* next = ct->next;
        sol_free(ct->data);
        sol_free(ct);
        ct = next;
    }

    pthread_cond_destroy(&ctx.chunk_cv_space);
    pthread_cond_destroy(&ctx.chunk_cv);
    pthread_mutex_destroy(&ctx.chunk_lock);

    pthread_cond_destroy(&ctx.cv_space);
    pthread_cond_destroy(&ctx.cv);
    pthread_mutex_destroy(&ctx.lock);

    if (ctx.persist_fd >= 0) {
        close(ctx.persist_fd);
        ctx.persist_fd = -1;
    }

    sol_err_t err = (sol_err_t)__atomic_load_n(&ctx.first_err, __ATOMIC_RELAXED);
    int core_ok = __atomic_load_n(&ctx.core_index_ok, __ATOMIC_RELAXED);

    if (err == SOL_OK && ctx.defer_appendvec_index && ctx.appendvec_index) {
        sol_log_info("Snapshot ingest: flushing deferred accounts index to RocksDB...");
        int flush_core_ok = 0;
        sol_err_t ferr = snapshot_appendvec_index_flush(ctx.appendvec_index,
                                                        accounts_db,
                                                        ctx.batch_capacity,
                                                        ctx.max_bytes_queued,
                                                        &flush_core_ok);
        if (ferr != SOL_OK) {
            err = ferr;
            core_ok = 0;
        } else {
            core_ok = flush_core_ok;
        }
    }

    snapshot_appendvec_index_destroy(ctx.appendvec_index);
    ctx.appendvec_index = NULL;
    ctx.defer_appendvec_index = false;

    if (out_count) {
        *out_count = __atomic_load_n(&ctx.accounts_loaded, __ATOMIC_RELAXED);
    }
    if (out_core_index_ok) {
        *out_core_index_ok = (err == SOL_OK) ? core_ok : 0;
    }
    return err;
}

static sol_err_t
load_accounts_from_dir(const char* accounts_dir,
                       sol_slot_t slot_hint,
                       sol_accounts_db_t* accounts_db,
                       sol_accounts_db_bulk_writer_t* bulk_writer,
                       uint64_t* out_count) {
    if (!accounts_dir || !accounts_db) return SOL_ERR_INVAL;
    if (out_count) *out_count = 0;

    struct stat st;
    if (stat(accounts_dir, &st) != 0) return SOL_ERR_NOTFOUND;

    /* If it's a file, parse it directly. */
    if (S_ISREG(st.st_mode)) {
        const char* name = strrchr(accounts_dir, '/');
        name = name ? (name + 1) : accounts_dir;
        uint64_t slot = 0, id = 0;
        sol_slot_t file_slot = slot_hint;
        if (strcmp(name, "storage.bin") == 0) {
            /* Use directory slot hint when present. */
            file_slot = slot_hint;
        } else if (parse_slot_id_from_filename(name, &slot, &id)) {
            file_slot = (sol_slot_t)slot;
        } else {
            return SOL_ERR_NOTFOUND;
        }
        return load_accounts_from_storage_file(accounts_dir, name, file_slot, accounts_db, bulk_writer, out_count, NULL);
    }

    if (!S_ISDIR(st.st_mode)) return SOL_ERR_INVAL;

    DIR* dir = opendir(accounts_dir);
    if (!dir) return SOL_ERR_NOTFOUND;

    /* Determine if we're currently in a <slot>.<id> directory. */
    bool this_is_slot_dir = false;
    const char* base = strrchr(accounts_dir, '/');
    base = base ? (base + 1) : accounts_dir;
    uint64_t base_slot = 0, base_id = 0;
    if (parse_slot_id_from_filename(base, &base_slot, &base_id)) {
        this_is_slot_dir = true;
        if (slot_hint == 0) {
            slot_hint = (sol_slot_t)base_slot;
        }
    }

    const bool top_level_accounts_dir = (slot_hint == 0 && strcmp(base, "accounts") == 0);

    /* Collect and sort entries for deterministic ordering. */
    size_t names_cap = 0;
    size_t names_len = 0;
    char** names = NULL;

    uint64_t total_loaded = 0;
    uint64_t files_processed = 0;
    uint64_t bytes_processed = 0;
    struct dirent* entry;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        if (names_len == names_cap) {
            size_t new_cap = names_cap ? (names_cap * 2) : 64;
            if (new_cap < names_cap) {
                closedir(dir);
                return SOL_ERR_OVERFLOW;
            }
            char** new_names = sol_realloc(names, new_cap * sizeof(*names));
            if (!new_names) {
                for (size_t i = 0; i < names_len; i++) sol_free(names[i]);
                sol_free(names);
                closedir(dir);
                return SOL_ERR_NOMEM;
            }
            names = new_names;
            names_cap = new_cap;
        }

        size_t name_len = strlen(entry->d_name);
        char* name_copy = sol_alloc(name_len + 1);
        if (!name_copy) {
            for (size_t i = 0; i < names_len; i++) sol_free(names[i]);
            sol_free(names);
            closedir(dir);
            return SOL_ERR_NOMEM;
        }
        memcpy(name_copy, entry->d_name, name_len + 1);
        names[names_len++] = name_copy;
    }

    closedir(dir);

    if (top_level_accounts_dir) {
        sol_log_info("Snapshot accounts load: found %zu storage entries", names_len);
    }

    if (names_len > 1) {
        qsort(names, names_len, sizeof(*names), accounts_dir_entry_name_cmp);
    }

    uint64_t last_log_ms = top_level_accounts_dir ? now_ms_monotonic() : 0;
    sol_err_t first_err = SOL_OK;

    for (size_t i = 0; i < names_len; i++) {
        const char* name = names[i];

        char path[512];
        snprintf(path, sizeof(path), "%s/%s", accounts_dir, name);

        struct stat est;
        if (stat(path, &est) != 0) {
            sol_free(names[i]);
            continue;
        }

        uint64_t loaded = 0;
        sol_err_t err = SOL_OK;
        if (S_ISDIR(est.st_mode)) {
            uint64_t slot = 0, id = 0;
            if (this_is_slot_dir || parse_slot_id_from_filename(name, &slot, &id)) {
                sol_slot_t child_slot = slot_hint;
                if (parse_slot_id_from_filename(name, &slot, &id)) {
                    child_slot = (sol_slot_t)slot;
                }
                err = load_accounts_from_dir(path, child_slot, accounts_db, bulk_writer, &loaded);
                if (err == SOL_ERR_NOTFOUND) {
                    err = SOL_ERR_SNAPSHOT_CORRUPT;
                }
            }
        } else if (S_ISREG(est.st_mode)) {
            uint64_t slot = 0, id = 0;
            sol_slot_t file_slot = slot_hint;
            if (strcmp(name, "storage.bin") == 0) {
                file_slot = slot_hint;
            } else if (parse_slot_id_from_filename(name, &slot, &id)) {
                file_slot = (sol_slot_t)slot;
            } else {
                file_slot = 0;
            }

            if (strcmp(name, "storage.bin") == 0 || file_slot != 0) {
                files_processed++;
                bytes_processed += (uint64_t)est.st_size;
                err = load_accounts_from_storage_file(path, name, file_slot, accounts_db, bulk_writer, &loaded, NULL);
                if (err == SOL_ERR_NOTFOUND) {
                    err = SOL_ERR_SNAPSHOT_CORRUPT;
                }
            }
        }

        if (err != SOL_OK) {
            sol_log_error("Failed to load account storage: %s (%s)",
                          path, sol_err_str(err));
            first_err = err;
        }

        total_loaded += loaded;
        sol_free(names[i]);

        if (first_err != SOL_OK) {
            for (size_t j = i + 1; j < names_len; j++) {
                sol_free(names[j]);
            }
            break;
        }

        if (top_level_accounts_dir) {
            uint64_t now = now_ms_monotonic();
            if (now - last_log_ms >= 5000) {
                sol_log_info("Snapshot accounts load progress: %lu files, %lu accounts, %lu MB read",
                             (unsigned long)files_processed,
                             (unsigned long)total_loaded,
                             (unsigned long)(bytes_processed / (1024 * 1024)));
                last_log_ms = now;
            }
        }
    }

    sol_free(names);

    if (out_count) *out_count = total_loaded;

    if (first_err != SOL_OK) {
        return first_err;
    }

    return total_loaded > 0 ? SOL_OK : SOL_ERR_NOTFOUND;
}

static sol_err_t
find_latest_snapshot_slot(const char* snapshot_dir, sol_slot_t* out_slot) {
    if (!snapshot_dir || !out_slot) return SOL_ERR_INVAL;

    char snapshots_path[512];
    snprintf(snapshots_path, sizeof(snapshots_path), "%s/snapshots", snapshot_dir);

    DIR* dir = opendir(snapshots_path);
    if (!dir) {
        return SOL_ERR_NOTFOUND;
    }

    sol_slot_t best = 0;
    bool found = false;

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char* end = NULL;
        errno = 0;
        unsigned long long val = strtoull(entry->d_name, &end, 10);
        if (errno != 0 || end == entry->d_name || *end != '\0') continue;

        char slot_dir[512];
        snprintf(slot_dir, sizeof(slot_dir), "%s/%s", snapshots_path, entry->d_name);

        struct stat st;
        if (stat(slot_dir, &st) != 0 || !S_ISDIR(st.st_mode)) continue;

        if (!found || (sol_slot_t)val > best) {
            best = (sol_slot_t)val;
            found = true;
        }
    }

    closedir(dir);

    if (!found) {
        return SOL_ERR_NOTFOUND;
    }

    *out_slot = best;
    return SOL_OK;
}

static sol_err_t
load_bank_fields_from_snapshot(const char* snapshot_dir,
                               sol_slot_t slot,
                               sol_snapshot_info_t* info,
                               sol_bank_config_t* out_bank_config,
                               sol_bank_fields_t* out_fields,
                               sol_lt_hash_t* out_accounts_lt_hash,
                               bool* out_accounts_lt_hash_valid) {
    if (!snapshot_dir || !info) return SOL_ERR_INVAL;

    /* Real Solana bank snapshot files can be hundreds of MB/GB. We only need a
     * small, fixed header to seed bank hash inputs (e.g. cumulative signature
     * count) and config parameters. */

    /* Try both layouts:
     * - simplified: snapshots/<slot>/<slot>
     * - Solana-style: snapshots/<slot>/snapshots/<slot>/<slot>
     */
    const char* candidates[2] = {0};
    char bank_path_simple[512];
    char bank_path_nested[512];

    snprintf(bank_path_simple, sizeof(bank_path_simple), "%s/snapshots/%lu/%lu",
             snapshot_dir, (unsigned long)slot, (unsigned long)slot);
    snprintf(bank_path_nested, sizeof(bank_path_nested), "%s/snapshots/%lu/snapshots/%lu/%lu",
             snapshot_dir, (unsigned long)slot, (unsigned long)slot, (unsigned long)slot);

    candidates[0] = bank_path_nested;
    candidates[1] = bank_path_simple;

    for (size_t i = 0; i < 2; i++) {
        struct stat st;
        if (stat(candidates[i], &st) != 0 || !S_ISREG(st.st_mode)) continue;
        if (st.st_size <= 0) continue;

        FILE* f = fopen(candidates[i], "rb");
        if (!f) continue;

        if (out_accounts_lt_hash_valid) {
            *out_accounts_lt_hash_valid = false;
        }

        uint8_t tail[1 + SOL_LT_HASH_SIZE_BYTES];
        bool have_tail = false;
        size_t file_size = (size_t)st.st_size;
        if (out_accounts_lt_hash && out_accounts_lt_hash_valid && file_size >= sizeof(tail)) {
            if (fseek(f, (long)(file_size - sizeof(tail)), SEEK_SET) == 0) {
                size_t n = fread(tail, 1, sizeof(tail), f);
                if (n == sizeof(tail)) {
                    have_tail = true;
                }
            }
            (void)fseek(f, 0, SEEK_SET);
        }
        if (out_accounts_lt_hash && out_accounts_lt_hash_valid && have_tail && tail[0] == 1) {
            bool any_nonzero = false;
            for (size_t j = 1; j < sizeof(tail); j++) {
                if (tail[j] != 0) {
                    any_nonzero = true;
                    break;
                }
            }
            if (any_nonzero) {
                memcpy(out_accounts_lt_hash, tail + 1, SOL_LT_HASH_SIZE_BYTES);
                *out_accounts_lt_hash_valid = true;
            }
        }

        const size_t max_prefix = 16u * 1024u * 1024u; /* 16MB */
        size_t prefix_cap = 256u * 1024u;              /* 256KB */
        if (prefix_cap > file_size) prefix_cap = file_size;
        if (prefix_cap > max_prefix) prefix_cap = max_prefix;

        uint8_t* bank_data = NULL;
        size_t bank_len = 0;
        sol_err_t fields_err = SOL_ERR_DECODE;

        sol_bank_fields_t stream_fields = {0};
        sol_err_t stream_err = sol_bank_fields_deserialize_agave_snapshot_file(f, slot, &stream_fields);
        if (stream_err == SOL_OK && stream_fields.slot == slot) {
            info->slot = stream_fields.slot;
            info->bank_hash = stream_fields.hash;
            info->epoch = stream_fields.epoch;
            info->block_height = stream_fields.block_height;
            info->capitalization = stream_fields.capitalization;

            if (stream_fields.lamports_per_signature) {
                info->lamports_per_signature = stream_fields.lamports_per_signature;
            }

            if (out_fields) {
                *out_fields = stream_fields;
            }

            if (out_bank_config) {
                sol_bank_config_t cfg = SOL_BANK_CONFIG_DEFAULT;
                if (stream_fields.ticks_per_slot) cfg.ticks_per_slot = stream_fields.ticks_per_slot;
                if (stream_fields.hashes_per_tick) cfg.hashes_per_tick = stream_fields.hashes_per_tick;
                if (stream_fields.slots_per_epoch) cfg.slots_per_epoch = stream_fields.slots_per_epoch;
                if (stream_fields.lamports_per_signature) cfg.lamports_per_signature = stream_fields.lamports_per_signature;
                if (stream_fields.rent_lamports_per_byte_year) cfg.rent_per_byte_year = stream_fields.rent_lamports_per_byte_year;
                if (stream_fields.rent_exemption_threshold > 0.0f) {
                    cfg.rent_exemption_threshold = (uint64_t)stream_fields.rent_exemption_threshold;
                }
                *out_bank_config = cfg;
            }

            sol_free(bank_data);
            fclose(f);
            return SOL_OK;
        }

        (void)fseeko(f, 0, SEEK_SET);

        while (prefix_cap > 0) {
            sol_free(bank_data);
            bank_data = sol_alloc(prefix_cap);
            if (!bank_data) {
                fclose(f);
                return SOL_ERR_NOMEM;
            }

            bank_len = fread(bank_data, 1, prefix_cap, f);
            if (bank_len == 0) {
                break;
            }

            sol_hash_t latest_blockhash = {0};
            const sol_hash_t* latest_blockhash_ptr = NULL;
            if (bank_len >= (8u + 1u + SOL_HASH_SIZE)) {
                uint8_t tag = bank_data[8];
                if (tag == 1) {
                    memcpy(latest_blockhash.bytes, bank_data + 9, SOL_HASH_SIZE);
                    if (!sol_hash_is_zero(&latest_blockhash)) {
                        latest_blockhash_ptr = &latest_blockhash;
                    }
                }
            }

            sol_bank_fields_t fields = {0};
            sol_err_t header_err = sol_bank_fields_deserialize_header(bank_data, bank_len, &fields);
            if (header_err == SOL_OK && fields.slot == slot) {
                fields_err = SOL_OK;
            } else {
                fields = (sol_bank_fields_t){0};
                fields_err = sol_bank_fields_deserialize_agave_snapshot_prefix(
                    bank_data, bank_len, slot, &fields);
                if (fields_err != SOL_OK) {
                    fields_err = sol_bank_fields_deserialize_solana_snapshot_v1_2_0(
                        bank_data, bank_len, slot, latest_blockhash_ptr, &fields);
                }
            }

            if (fields_err == SOL_OK && fields.slot == slot) {
                info->slot = fields.slot;
                info->bank_hash = fields.hash;
                info->epoch = fields.epoch;
                info->block_height = fields.block_height;
                info->capitalization = fields.capitalization;
                if (fields.lamports_per_signature) {
                    info->lamports_per_signature = fields.lamports_per_signature;
                }

                if (out_fields) {
                    *out_fields = fields;
                }

                if (out_bank_config) {
                    sol_bank_config_t cfg = SOL_BANK_CONFIG_DEFAULT;
                    if (fields.ticks_per_slot) cfg.ticks_per_slot = fields.ticks_per_slot;
                    if (fields.hashes_per_tick) cfg.hashes_per_tick = fields.hashes_per_tick;
                    if (fields.slots_per_epoch) cfg.slots_per_epoch = fields.slots_per_epoch;
                    if (fields.lamports_per_signature) cfg.lamports_per_signature = fields.lamports_per_signature;
                    if (fields.rent_lamports_per_byte_year) cfg.rent_per_byte_year = fields.rent_lamports_per_byte_year;
                    if (fields.rent_exemption_threshold > 0.0f) {
                        cfg.rent_exemption_threshold = (uint64_t)fields.rent_exemption_threshold;
                    }
                    *out_bank_config = cfg;
                }

                sol_free(bank_data);
                fclose(f);
                return SOL_OK;
            }

            if (prefix_cap >= max_prefix || prefix_cap >= file_size) {
                break;
            }
            prefix_cap *= 2u;
            if (prefix_cap > file_size) prefix_cap = file_size;
            if (prefix_cap > max_prefix) prefix_cap = max_prefix;
            (void)fseek(f, 0, SEEK_SET);
        }

        sol_free(bank_data);
        fclose(f);

        (void)fields_err;
        continue;
    }

    return SOL_ERR_NOTFOUND;
}

static sol_err_t
load_latest_blockhash_from_snapshot(const char* snapshot_dir,
                                    sol_slot_t slot,
                                    sol_hash_t* out_blockhash) {
    if (!snapshot_dir || !out_blockhash) return SOL_ERR_INVAL;
    memset(out_blockhash->bytes, 0, sizeof(out_blockhash->bytes));

    /* Bank snapshots serialize the bank's latest blockhash (used as the PoH
     * start hash for the next slot) early in the file as Option<Hash>. */

    /* Try both layouts:
     * - simplified: snapshots/<slot>/<slot>
     * - Solana-style: snapshots/<slot>/snapshots/<slot>/<slot>
     */
    const char* candidates[2] = {0};
    char bank_path_simple[512];
    char bank_path_nested[512];

    snprintf(bank_path_simple, sizeof(bank_path_simple), "%s/snapshots/%lu/%lu",
             snapshot_dir, (unsigned long)slot, (unsigned long)slot);
    snprintf(bank_path_nested, sizeof(bank_path_nested), "%s/snapshots/%lu/snapshots/%lu/%lu",
             snapshot_dir, (unsigned long)slot, (unsigned long)slot, (unsigned long)slot);

    candidates[0] = bank_path_nested;
    candidates[1] = bank_path_simple;

    for (size_t i = 0; i < 2; i++) {
        struct stat st;
        if (stat(candidates[i], &st) != 0 || !S_ISREG(st.st_mode)) continue;
        if (st.st_size <= 0) continue;

        FILE* f = fopen(candidates[i], "rb");
        if (!f) continue;

        uint8_t hdr[64];
        size_t n = fread(hdr, 1, sizeof(hdr), f);
        fclose(f);
        if (n < (8u + 1u + SOL_HASH_SIZE)) continue;

        uint8_t tag = hdr[8];
        if (tag == 0) continue;     /* None */
        if (tag != 1) continue;     /* Unknown/unsupported */

        sol_hash_t h = {0};
        memcpy(h.bytes, hdr + 9, SOL_HASH_SIZE);
        if (sol_hash_is_zero(&h)) continue;

        *out_blockhash = h;
        return SOL_OK;
    }

    return SOL_ERR_NOTFOUND;
}

typedef struct {
    sol_hash_t hash;
    uint64_t   lamports_per_signature;
    uint64_t   hash_index;
} snapshot_blockhash_queue_entry_t;

static int
snapshot_blockhash_queue_entry_cmp_desc_hash_index(const void* a, const void* b) {
    const snapshot_blockhash_queue_entry_t* ea = (const snapshot_blockhash_queue_entry_t*)a;
    const snapshot_blockhash_queue_entry_t* eb = (const snapshot_blockhash_queue_entry_t*)b;
    if (ea->hash_index < eb->hash_index) return 1;
    if (ea->hash_index > eb->hash_index) return -1;
    return 0;
}

static sol_err_t
load_blockhash_queue_from_snapshot(const char* snapshot_dir,
                                   sol_slot_t slot,
                                   sol_hash_t* out_hashes,
                                   uint64_t* out_lamports_per_signature,
                                   size_t out_cap,
                                   size_t* out_len) {
    if (out_len) {
        *out_len = 0;
    }
    if (!snapshot_dir || !out_hashes || !out_lamports_per_signature || out_cap == 0 || !out_len) {
        return SOL_ERR_INVAL;
    }

    const char* candidates[2] = {0};
    char bank_path_simple[512];
    char bank_path_nested[512];

    snprintf(bank_path_simple, sizeof(bank_path_simple), "%s/snapshots/%lu/%lu",
             snapshot_dir, (unsigned long)slot, (unsigned long)slot);
    snprintf(bank_path_nested, sizeof(bank_path_nested), "%s/snapshots/%lu/snapshots/%lu/%lu",
             snapshot_dir, (unsigned long)slot, (unsigned long)slot, (unsigned long)slot);

    candidates[0] = bank_path_nested;
    candidates[1] = bank_path_simple;

    FILE* f = NULL;
    for (size_t i = 0; i < 2; i++) {
        struct stat st;
        if (stat(candidates[i], &st) != 0 || !S_ISREG(st.st_mode)) continue;
        if (st.st_size <= 0) continue;
        f = fopen(candidates[i], "rb");
        if (f) break;
    }
    if (!f) return SOL_ERR_NOTFOUND;

    uint64_t last_hash_index = 0;
    sol_err_t err = file_read_u64_le(f, &last_hash_index);
    if (err != SOL_OK) {
        fclose(f);
        return err;
    }

    uint8_t last_hash_tag = 0;
    err = file_read_u8(f, &last_hash_tag);
    if (err != SOL_OK) {
        fclose(f);
        return err;
    }

    sol_hash_t last_hash = {0};
    bool have_last_hash = false;
    if (last_hash_tag == 1) {
        err = file_read_hash32(f, &last_hash);
        if (err != SOL_OK) {
            fclose(f);
            return err;
        }
        have_last_hash = !sol_hash_is_zero(&last_hash);
    } else if (last_hash_tag != 0) {
        fclose(f);
        return SOL_ERR_DECODE;
    }

    uint64_t hashes_len_u64 = 0;
    err = file_read_u64_le(f, &hashes_len_u64);
    if (err != SOL_OK) {
        fclose(f);
        return err;
    }
    if (hashes_len_u64 > SOL_SNAPSHOT_MAX_BLOCKHASH_QUEUE_ENTRIES) {
        fclose(f);
        return SOL_ERR_SNAPSHOT_CORRUPT;
    }
    size_t hashes_len = (size_t)hashes_len_u64;

    snapshot_blockhash_queue_entry_t* entries = NULL;
    if (hashes_len > 0) {
        if (hashes_len > (SIZE_MAX / sizeof(*entries))) {
            fclose(f);
            return SOL_ERR_OVERFLOW;
        }
        entries = (snapshot_blockhash_queue_entry_t*)sol_alloc(hashes_len * sizeof(*entries));
        if (!entries) {
            fclose(f);
            return SOL_ERR_NOMEM;
        }
    }

    uint64_t last_hash_lamports = 0;
    bool have_last_hash_lamports = false;
    size_t entries_len = 0;
    for (size_t i = 0; i < hashes_len; i++) {
        sol_hash_t key = {0};
        err = file_read_hash32(f, &key);
        if (err != SOL_OK) {
            break;
        }

        uint64_t lamports_per_signature = 0;
        uint64_t hash_index = 0;
        uint64_t timestamp = 0;
        err = file_read_u64_le(f, &lamports_per_signature);
        if (err != SOL_OK) {
            break;
        }
        err = file_read_u64_le(f, &hash_index);
        if (err != SOL_OK) {
            break;
        }
        err = file_read_u64_le(f, &timestamp);
        if (err != SOL_OK) {
            break;
        }
        (void)timestamp;

        if (entries) {
            entries[entries_len].hash = key;
            entries[entries_len].lamports_per_signature = lamports_per_signature;
            entries[entries_len].hash_index = hash_index;
            entries_len++;
        }

        if (have_last_hash && memcmp(key.bytes, last_hash.bytes, SOL_HASH_SIZE) == 0) {
            last_hash_lamports = lamports_per_signature;
            have_last_hash_lamports = true;
        }
    }

    uint64_t max_age_u64 = 0;
    if (err == SOL_OK) {
        err = file_read_u64_le(f, &max_age_u64);
    }

    fclose(f);
    f = NULL;

    if (err != SOL_OK) {
        sol_free(entries);
        return err;
    }

    uint64_t max_age = max_age_u64;
    if (max_age == 0 || max_age > SOL_MAX_RECENT_BLOCKHASHES) {
        max_age = SOL_MAX_RECENT_BLOCKHASHES;
    }

    size_t keep = 0;
    for (size_t i = 0; i < entries_len; i++) {
        snapshot_blockhash_queue_entry_t e = entries[i];
        if (e.hash_index > last_hash_index) {
            continue;
        }
        uint64_t age = last_hash_index - e.hash_index;
        if (age <= max_age) {
            entries[keep++] = e;
        }
    }
    entries_len = keep;

    if (entries_len > 1) {
        qsort(entries, entries_len, sizeof(*entries), snapshot_blockhash_queue_entry_cmp_desc_hash_index);
    }

    size_t out_count = 0;

    if (have_last_hash && out_count < out_cap) {
        out_hashes[out_count] = last_hash;
        out_lamports_per_signature[out_count] = have_last_hash_lamports ? last_hash_lamports : 0;
        out_count++;
    }

    for (size_t i = 0; i < entries_len && out_count < out_cap; i++) {
        if (have_last_hash &&
            memcmp(entries[i].hash.bytes, last_hash.bytes, SOL_HASH_SIZE) == 0) {
            continue;
        }
        out_hashes[out_count] = entries[i].hash;
        out_lamports_per_signature[out_count] = entries[i].lamports_per_signature;
        out_count++;
    }

    sol_free(entries);
    if (out_count == 0) {
        return SOL_ERR_NOTFOUND;
    }

    *out_len = out_count;
    return SOL_OK;
}

static bool
accounts_dir_has_storage_files(const char* accounts_dir) {
    if (!accounts_dir) return false;

    struct stat st;
    if (stat(accounts_dir, &st) != 0 || !S_ISDIR(st.st_mode)) return false;

    DIR* dir = opendir(accounts_dir);
    if (!dir) return false;

    bool found = false;
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        if (strcmp(entry->d_name, "storage.bin") == 0) {
            found = true;
            break;
        }
        uint64_t slot = 0, id = 0;
        if (parse_slot_id_from_filename(entry->d_name, &slot, &id)) {
            found = true;
            break;
        }
    }
    closedir(dir);
    return found;
}

static sol_err_t
apply_incremental_snapshot_to_accounts_db(sol_snapshot_mgr_t* mgr,
                                         const char* incremental_archive_path,
                                         sol_slot_t expected_base_slot,
                                         sol_accounts_db_t* accounts_db,
                                         sol_bank_t** out_bank) {
    if (!mgr || !incremental_archive_path || !accounts_db || !out_bank) return SOL_ERR_INVAL;

    /* Best-effort validation: ensure base slot matches the provided full snapshot slot. */
    sol_snapshot_info_t name_info = {0};
    if (sol_snapshot_get_info(incremental_archive_path, &name_info) == SOL_OK &&
        name_info.type == SOL_SNAPSHOT_INCREMENTAL &&
        name_info.base_slot != 0 &&
        expected_base_slot != 0 &&
        name_info.base_slot != expected_base_slot) {
        sol_log_error("Incremental snapshot base slot %lu does not match full snapshot slot %lu",
                      (unsigned long)name_info.base_slot,
                      (unsigned long)expected_base_slot);
        return SOL_ERR_INVAL;
    }

    char extracted_dir[512] = {0};
    const char* snapshot_dir = NULL;
    bool cleanup_extracted = false;
    bool accounts_loaded_from_archive = false;
    uint64_t delta_accounts = 0;

    sol_snapshot_info_t info = {0};
    (void)sol_snapshot_get_info(incremental_archive_path, &info);

    struct stat st;
    if (stat(incremental_archive_path, &st) != 0) return SOL_ERR_NOTFOUND;

    if (S_ISDIR(st.st_mode)) {
        snapshot_dir = incremental_archive_path;
        cleanup_extracted = false;
    } else if (S_ISREG(st.st_mode)) {
        sol_err_t err = sol_snapshot_archive_check(incremental_archive_path);
        if (err != SOL_OK) return err;

        const char* base_dir = (mgr && mgr->snapshot_dir) ? mgr->snapshot_dir : "/tmp";
        err = sol_snapshot_archive_mktemp(base_dir, "snapshot_extract", extracted_dir, sizeof(extracted_dir));
        if (err != SOL_OK) return err;

        snapshot_dir = extracted_dir;
        cleanup_extracted = true;

#ifdef SOL_HAS_ZSTD
        bool want_stream =
            snapshot_stream_accounts_enabled() &&
            sol_snapshot_archive_detect_compression(incremental_archive_path) == SOL_SNAPSHOT_COMPRESSION_ZSTD;
#else
        bool want_stream = false;
#endif

        uint64_t streamed = 0;
        const size_t bulk_batch = 262144;
        uint32_t load_threads = default_snapshot_load_threads();
        const size_t max_bytes_per_thread = default_snapshot_load_max_bytes_per_thread(load_threads);

        if (want_stream) {
            sol_log_info("Extracting incremental snapshot + streaming accounts ingestion (threads=%u, batch=%lu)",
                         (unsigned)load_threads, (unsigned long)bulk_batch);

            bool wal_disabled = false;
            bool bulk_load_mode = false;

            if (sol_accounts_db_set_disable_wal(accounts_db, true) == SOL_OK) {
                wal_disabled = true;
            }
            if (sol_accounts_db_set_bulk_load_mode(accounts_db, true) == SOL_OK) {
                bulk_load_mode = true;
            }

            err = load_accounts_from_archive_streaming(incremental_archive_path,
                                                       snapshot_dir,
                                                       accounts_db,
                                                       load_threads,
                                                       bulk_batch,
                                                       max_bytes_per_thread,
                                                       &streamed,
                                                       NULL);

            if (wal_disabled) {
                (void)sol_accounts_db_set_disable_wal(accounts_db, false);
            }
            if (bulk_load_mode) {
                (void)sol_accounts_db_set_bulk_load_mode(accounts_db, false);
            }

            if (err == SOL_OK) {
                accounts_loaded_from_archive = true;
                delta_accounts = streamed;
            } else {
                if (cleanup_extracted) {
                    sol_snapshot_archive_rmdir(extracted_dir);
                }
                return err;
            }
        } else {
            sol_archive_extract_opts_t opts = SOL_ARCHIVE_EXTRACT_OPTS_DEFAULT;
            opts.output_dir = snapshot_dir;
            opts.verify = false;
            err = sol_snapshot_archive_extract(incremental_archive_path, &opts);
            if (err != SOL_OK) {
                if (cleanup_extracted) {
                    sol_snapshot_archive_rmdir(extracted_dir);
                }
                return err;
            }
        }
    } else {
        return SOL_ERR_INVAL;
    }

    sol_slot_t slot = 0;
    sol_err_t slot_err = find_latest_snapshot_slot(snapshot_dir, &slot);
    if (slot_err == SOL_OK) {
        info.slot = slot;
    } else if (info.slot == 0) {
        if (cleanup_extracted) {
            sol_snapshot_archive_rmdir(extracted_dir);
        }
        return slot_err;
    }

    sol_bank_config_t bank_config = SOL_BANK_CONFIG_DEFAULT;
    sol_bank_fields_t bank_fields = {0};
    sol_lt_hash_t accounts_lt_hash = {0};
    bool accounts_lt_hash_valid = false;
    sol_err_t bank_fields_err =
        load_bank_fields_from_snapshot(snapshot_dir,
                                       info.slot,
                                       &info,
                                       &bank_config,
                                       &bank_fields,
                                       &accounts_lt_hash,
                                       &accounts_lt_hash_valid);
    sol_hash_t snapshot_blockhash = {0};
    sol_err_t blockhash_err =
        load_latest_blockhash_from_snapshot(snapshot_dir, info.slot, &snapshot_blockhash);
    sol_hash_t snapshot_blockhash_queue_hashes[SOL_MAX_RECENT_BLOCKHASHES];
    uint64_t snapshot_blockhash_queue_fees[SOL_MAX_RECENT_BLOCKHASHES];
    size_t snapshot_blockhash_queue_len = 0;
    sol_err_t blockhash_queue_err =
        load_blockhash_queue_from_snapshot(snapshot_dir,
                                           info.slot,
                                           snapshot_blockhash_queue_hashes,
                                           snapshot_blockhash_queue_fees,
                                           SOL_MAX_RECENT_BLOCKHASHES,
                                           &snapshot_blockhash_queue_len);
    if (blockhash_queue_err == SOL_OK && snapshot_blockhash_queue_len > 0) {
        snapshot_blockhash = snapshot_blockhash_queue_hashes[0];
        blockhash_err = SOL_OK;
    }

    sol_err_t manifest_err = parse_snapshot_manifest(snapshot_dir, &info);
    if (manifest_err != SOL_OK && manifest_err != SOL_ERR_NOTFOUND) {
        if (cleanup_extracted) {
            sol_snapshot_archive_rmdir(extracted_dir);
        }
        return manifest_err;
    }

    if (!accounts_loaded_from_archive) {
        char accounts_path[512];
        snprintf(accounts_path, sizeof(accounts_path), "%s/accounts", snapshot_dir);

        const size_t bulk_batch = 262144;
        uint32_t load_threads = default_snapshot_load_threads();

        bool wal_disabled = false;
        bool bulk_load_mode = false;
        sol_err_t accounts_err = SOL_OK;

        bool can_parallel = (load_threads > 1);
        if (can_parallel) {
            sol_accounts_db_bulk_writer_t* probe = sol_accounts_db_bulk_writer_new(accounts_db, bulk_batch);
            if (probe) {
                sol_accounts_db_bulk_writer_destroy(probe);
            } else {
                can_parallel = false;
            }
        }

        if (can_parallel) {
            const size_t max_bytes_per_thread = default_snapshot_load_max_bytes_per_thread(load_threads);
            sol_log_info("Applying incremental snapshot with parallel ingestion (threads=%u, batch=%lu)",
                         (unsigned)load_threads, (unsigned long)bulk_batch);

            if (sol_accounts_db_set_disable_wal(accounts_db, true) == SOL_OK) {
                wal_disabled = true;
            }
            if (sol_accounts_db_set_bulk_load_mode(accounts_db, true) == SOL_OK) {
                bulk_load_mode = true;
            }

            accounts_err = load_accounts_from_top_level_dir_parallel(accounts_path,
                                                                     accounts_db,
                                                                     load_threads,
                                                                     bulk_batch,
                                                                     max_bytes_per_thread,
                                                                     &delta_accounts,
                                                                     NULL);
        } else {
            sol_accounts_db_bulk_writer_t* bulk_writer = sol_accounts_db_bulk_writer_new(accounts_db, bulk_batch);
            if (bulk_writer) {
                sol_accounts_db_bulk_writer_set_use_merge(bulk_writer, true);
                if (sol_accounts_db_is_appendvec(accounts_db)) {
                    (void)sol_accounts_db_bulk_writer_set_write_owner_reverse(bulk_writer, false);
                }
                sol_err_t idx_err = sol_accounts_db_bulk_writer_set_write_owner_index(bulk_writer, true);
                if (idx_err == SOL_OK) {
                    sol_accounts_db_bulk_writer_set_write_owner_index_core_only(bulk_writer, true);
                }
                if (sol_accounts_db_set_disable_wal(accounts_db, true) == SOL_OK) {
                    wal_disabled = true;
                }
                if (sol_accounts_db_set_bulk_load_mode(accounts_db, true) == SOL_OK) {
                    bulk_load_mode = true;
                }
            }

            accounts_err = load_accounts_from_dir(accounts_path, 0, accounts_db, bulk_writer, &delta_accounts);

            if (bulk_writer) {
                sol_err_t flush_err = sol_accounts_db_bulk_writer_flush(bulk_writer);
                sol_accounts_db_bulk_writer_destroy(bulk_writer);
                bulk_writer = NULL;
                if (flush_err != SOL_OK) {
                    sol_log_error("Incremental snapshot accounts bulk flush failed: %s", sol_err_str(flush_err));
                    accounts_err = flush_err;
                }
            }
        }

        if (wal_disabled) {
            (void)sol_accounts_db_set_disable_wal(accounts_db, false);
            wal_disabled = false;
        }
        if (bulk_load_mode) {
            (void)sol_accounts_db_set_bulk_load_mode(accounts_db, false);
            bulk_load_mode = false;
        }

        if (accounts_err == SOL_OK) {
            sol_log_info("Applied incremental snapshot (%lu accounts)", (unsigned long)delta_accounts);
        } else if (accounts_err == SOL_ERR_NOTFOUND && accounts_dir_has_storage_files(accounts_path)) {
            sol_log_error("Incremental snapshot contains account storages but none could be loaded");
            if (cleanup_extracted) {
                sol_snapshot_archive_rmdir(extracted_dir);
            }
            return SOL_ERR_SNAPSHOT_CORRUPT;
        } else if (accounts_err != SOL_OK && accounts_err != SOL_ERR_NOTFOUND) {
            if (cleanup_extracted) {
                sol_snapshot_archive_rmdir(extracted_dir);
            }
            return accounts_err;
        }
    } else {
        sol_log_info("Applied incremental snapshot (%lu accounts) (streamed from archive)",
                     (unsigned long)delta_accounts);
    }

    if (!mgr->config.verify_accounts_hash && !sol_hash_is_zero(&info.accounts_hash)) {
        sol_log_info("Skipping incremental snapshot accounts-hash verification (verify_accounts_hash=false)");
    }

    if (mgr->config.verify_accounts_hash && !sol_hash_is_zero(&info.accounts_hash)) {
        sol_hash_t computed = {0};
        sol_accounts_db_hash(accounts_db, &computed);

        if (!sol_hash_eq(&computed, &info.accounts_hash)) {
            sol_log_error("Snapshot accounts hash mismatch at slot %lu", (unsigned long)info.slot);
            if (cleanup_extracted) {
                sol_snapshot_archive_rmdir(extracted_dir);
            }
            return SOL_ERR_SNAPSHOT_MISMATCH;
        }
    }

    sol_err_t persist_err = snapshot_persist_appendvec_accounts_dir(accounts_db, snapshot_dir, cleanup_extracted);
    if (persist_err != SOL_OK) {
        if (cleanup_extracted) {
            sol_snapshot_archive_rmdir(extracted_dir);
        }
        return persist_err;
    }

    sol_bank_t* bank = sol_bank_new(info.slot, NULL, accounts_db, &bank_config);
    if (!bank) {
        if (cleanup_extracted) {
            sol_snapshot_archive_rmdir(extracted_dir);
        }
        return SOL_ERR_NOMEM;
    }

    if (blockhash_queue_err == SOL_OK && snapshot_blockhash_queue_len > 0) {
        sol_err_t qerr = sol_bank_set_recent_blockhash_queue(bank,
                                                             snapshot_blockhash_queue_hashes,
                                                             snapshot_blockhash_queue_fees,
                                                             snapshot_blockhash_queue_len);
        if (qerr != SOL_OK) {
            sol_log_warn("Failed to seed recent blockhash queue from snapshot: %s", sol_err_str(qerr));
        } else {
            sol_err_t perr = sol_accounts_db_set_bootstrap_blockhash_queue(accounts_db,
                                                                           snapshot_blockhash_queue_hashes,
                                                                           snapshot_blockhash_queue_fees,
                                                                           snapshot_blockhash_queue_len);
            if (perr != SOL_OK) {
                sol_log_warn("Failed to persist snapshot blockhash queue: %s", sol_err_str(perr));
            }
        }
    }

    if (blockhash_err == SOL_OK) {
        sol_bank_set_blockhash(bank, &snapshot_blockhash);
    }

    if (accounts_lt_hash_valid) {
        sol_bank_set_accounts_lt_hash(bank, &accounts_lt_hash);
    } else {
        sol_log_warn("No accounts LtHash available for snapshot slot %lu; replay/bank-hash may be slow",
                     (unsigned long)info.slot);
    }

    sol_bank_freeze(bank);
    bool seeded_bank_hash = false;
    if (bank_fields_err == SOL_OK) {
        /* Bank hash includes the cumulative signature count. Seed it from the
         * snapshot so replayed bank hashes match the cluster. */
        sol_bank_set_signature_count(bank, bank_fields.transaction_count);
        sol_bank_set_parent_slot(bank, bank_fields.parent_slot);

        const sol_hash_t* blockhash = sol_bank_blockhash(bank);
        if (blockhash && !sol_hash_eq(blockhash, &bank_fields.hash)) {
            sol_bank_set_parent_bank_hash(bank, &bank_fields.parent_hash);
            sol_bank_set_bank_hash(bank, &bank_fields.hash);
            seeded_bank_hash = true;
        } else {
            sol_log_warn("Snapshot bank fields hash matches latest blockhash; skipping bank-hash seeding");
        }
    }

    if (!seeded_bank_hash) {
        sol_log_warn("No bank hash available for snapshot slot %lu; replay/voting may be incorrect",
                     (unsigned long)info.slot);
    }

    if (!sol_hash_is_zero(&info.epoch_accounts_hash)) {
        (void)sol_accounts_db_set_epoch_accounts_hash(
            accounts_db, sol_bank_epoch(bank), &info.epoch_accounts_hash);
    }

    sol_accounts_db_bootstrap_state_t prev_bootstrap = {0};
    bool have_prev_bootstrap = sol_accounts_db_get_bootstrap_state(accounts_db, &prev_bootstrap);

    sol_accounts_db_bootstrap_state_t bootstrap = {0};
    bootstrap.slot = info.slot;
    bootstrap.parent_slot = (bank_fields_err == SOL_OK) ? bank_fields.parent_slot : 0;
    bootstrap.signature_count = (bank_fields_err == SOL_OK) ? bank_fields.transaction_count : 0;
    bootstrap.flags = 0;
    bootstrap.ticks_per_slot = bank_config.ticks_per_slot;
    bootstrap.hashes_per_tick = bank_config.hashes_per_tick;
    bootstrap.slots_per_epoch = bank_config.slots_per_epoch;
    bootstrap.lamports_per_signature = bank_config.lamports_per_signature;
    bootstrap.rent_per_byte_year = bank_config.rent_per_byte_year;
    bootstrap.rent_exemption_threshold = bank_config.rent_exemption_threshold;

    if (have_prev_bootstrap &&
        (prev_bootstrap.flags & SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_GENESIS_HASH) &&
        !sol_hash_is_zero(&prev_bootstrap.genesis_hash)) {
        bootstrap.flags |= SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_GENESIS_HASH;
        bootstrap.genesis_hash = prev_bootstrap.genesis_hash;
    }
    if (have_prev_bootstrap &&
        (prev_bootstrap.flags & SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_SHRED_VERSION) &&
        prev_bootstrap.shred_version != 0) {
        bootstrap.flags |= SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_SHRED_VERSION;
        bootstrap.shred_version = prev_bootstrap.shred_version;
    }

    if (blockhash_err == SOL_OK) {
        bootstrap.flags |= SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_BLOCKHASH;
        bootstrap.blockhash = snapshot_blockhash;
    }
    if (accounts_lt_hash_valid) {
        bootstrap.flags |= SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_ACCOUNTS_LT_HASH;
        bootstrap.accounts_lt_hash = accounts_lt_hash;
    }
    if (seeded_bank_hash) {
        bootstrap.flags |= SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_BANK_HASH;
        bootstrap.parent_bank_hash = bank_fields.parent_hash;
        bootstrap.bank_hash = bank_fields.hash;
    }

    sol_err_t boot_err = sol_accounts_db_set_bootstrap_state(accounts_db, &bootstrap);
    if (boot_err != SOL_OK) {
        sol_log_warn("Failed to persist bootstrap bank state: %s", sol_err_str(boot_err));
    }

    if (accounts_lt_hash_valid || seeded_bank_hash) {
        /* Emit a "bank frozen" line for parity harnesses. */
        sol_hash_t bank_hash = {0};
        sol_bank_compute_hash(bank, &bank_hash);

        char bank_hash_b58[SOL_PUBKEY_BASE58_LEN] = {0};
        bytes32_to_base58(bank_hash.bytes, bank_hash_b58, sizeof(bank_hash_b58));

        char last_blockhash_b58[SOL_PUBKEY_BASE58_LEN] = {0};
        const sol_hash_t* last_blockhash = sol_bank_blockhash(bank);
        if (last_blockhash) {
            bytes32_to_base58(last_blockhash->bytes, last_blockhash_b58, sizeof(last_blockhash_b58));
        }

        sol_blake3_t lt_checksum = {0};
        sol_bank_accounts_lt_hash_checksum(bank, &lt_checksum);

        char lt_checksum_b58[SOL_PUBKEY_BASE58_LEN] = {0};
        bytes32_to_base58(lt_checksum.bytes, lt_checksum_b58, sizeof(lt_checksum_b58));

        sol_log_info("bank frozen: %lu hash: %s signature_count: %lu last_blockhash: %s accounts_delta_hash: %s accounts_lt_hash checksum: %s",
                     (unsigned long)info.slot,
                     bank_hash_b58[0] ? bank_hash_b58 : "-",
                     (unsigned long)sol_bank_signature_count(bank),
                     last_blockhash_b58[0] ? last_blockhash_b58 : "-",
                     "-",
                     lt_checksum_b58[0] ? lt_checksum_b58 : "-");
    }

    *out_bank = bank;

    if (cleanup_extracted) {
        sol_snapshot_archive_rmdir(extracted_dir);
    }

    return SOL_OK;
}

/*
 * Load bank from snapshot
 *
 * This function loads a snapshot from either:
 * 1. An extracted snapshot directory (uncompressed), or
 * 2. A snapshot archive (tar.zst / tar.gz / tar.lz4 / tar), which will be
 *    extracted to a temporary directory.
 */
sol_err_t
sol_snapshot_load(sol_snapshot_mgr_t* mgr,
                  const char* archive_path,
                  sol_bank_t** out_bank,
                  sol_accounts_db_t** out_accounts_db) {
    return sol_snapshot_load_with_accounts_db_config(mgr, archive_path, NULL, out_bank, out_accounts_db);
}

sol_err_t
sol_snapshot_load_with_accounts_db_config(sol_snapshot_mgr_t* mgr,
                                         const char* archive_path,
                                         const sol_accounts_db_config_t* accounts_db_config,
                                         sol_bank_t** out_bank,
                                         sol_accounts_db_t** out_accounts_db) {
    if (!mgr || !archive_path || !out_bank) return SOL_ERR_INVAL;

    /* Parse snapshot info from filename when available (best-effort). */
    sol_snapshot_info_t info = {0};
    (void)sol_snapshot_get_info(archive_path, &info);

    struct stat st;
    if (stat(archive_path, &st) != 0) return SOL_ERR_NOTFOUND;

    char extracted_dir[512] = {0};
    const char* snapshot_dir = NULL;
    bool cleanup_extracted = false;

    /* Create accounts database early so we can optionally stream ingestion
     * directly from the archive (avoids writing hundreds of GB to disk). */
    sol_accounts_db_t* accounts_db = sol_accounts_db_new(accounts_db_config);
    if (!accounts_db) return SOL_ERR_NOMEM;

    bool accounts_loaded_from_archive = false;
    uint64_t total_accounts = 0;

    if (S_ISDIR(st.st_mode)) {
        snapshot_dir = archive_path;
        cleanup_extracted = false;
    } else if (S_ISREG(st.st_mode)) {
        sol_err_t err = sol_snapshot_archive_check(archive_path);
        if (err != SOL_OK) {
            sol_accounts_db_destroy(accounts_db);
            return err;
        }

        const char* base_dir = (mgr && mgr->snapshot_dir) ? mgr->snapshot_dir : "/tmp";
        err = sol_snapshot_archive_mktemp(base_dir, "snapshot_extract", extracted_dir, sizeof(extracted_dir));
        if (err != SOL_OK) {
            sol_accounts_db_destroy(accounts_db);
            return err;
        }

        snapshot_dir = extracted_dir;
        cleanup_extracted = true;

#ifdef SOL_HAS_ZSTD
        bool want_stream =
            snapshot_stream_accounts_enabled() &&
            sol_snapshot_archive_detect_compression(archive_path) == SOL_SNAPSHOT_COMPRESSION_ZSTD;
#else
        bool want_stream = false;
#endif

        const size_t bulk_batch = 262144;
        uint32_t load_threads = default_snapshot_load_threads();
        const size_t max_bytes_per_thread = default_snapshot_load_max_bytes_per_thread(load_threads);

	        if (want_stream) {
	            sol_log_info("Extracting snapshot + streaming accounts ingestion (threads=%u, batch=%lu)",
	                         (unsigned)load_threads, (unsigned long)bulk_batch);

	            bool wal_disabled = false;
	            bool bulk_load_mode = false;
	            int core_index_ok = 0;

	            if (sol_accounts_db_set_disable_wal(accounts_db, true) == SOL_OK) {
	                wal_disabled = true;
	            }
	            if (sol_accounts_db_set_bulk_load_mode(accounts_db, true) == SOL_OK) {
                bulk_load_mode = true;
            }

	            err = load_accounts_from_archive_streaming(archive_path,
	                                                       snapshot_dir,
	                                                       accounts_db,
	                                                       load_threads,
	                                                       bulk_batch,
	                                                       max_bytes_per_thread,
	                                                       &total_accounts,
	                                                       &core_index_ok);

            if (wal_disabled) {
                (void)sol_accounts_db_set_disable_wal(accounts_db, false);
            }
            if (bulk_load_mode) {
                (void)sol_accounts_db_set_bulk_load_mode(accounts_db, false);
            }

	            accounts_loaded_from_archive = (err == SOL_OK);
	            if (accounts_loaded_from_archive && core_index_ok != 0) {
	                sol_err_t merr = sol_accounts_db_mark_owner_index_core_built(accounts_db);
	                if (merr != SOL_OK) {
	                    sol_log_warn("Failed to mark core owner index built: %s", sol_err_str(merr));
	                }
	            }
	        } else {
            sol_archive_extract_opts_t opts = SOL_ARCHIVE_EXTRACT_OPTS_DEFAULT;
            opts.output_dir = snapshot_dir;
            opts.verify = false;
            err = sol_snapshot_archive_extract(archive_path, &opts);
        }

        if (err != SOL_OK) {
            sol_accounts_db_destroy(accounts_db);
            if (cleanup_extracted) {
                sol_snapshot_archive_rmdir(extracted_dir);
            }
            return err;
        }
    } else {
        sol_accounts_db_destroy(accounts_db);
        return SOL_ERR_INVAL;
    }

    /* Prefer discovering slot from extracted directory. */
    sol_slot_t slot = 0;
    sol_err_t slot_err = find_latest_snapshot_slot(snapshot_dir, &slot);
    if (slot_err == SOL_OK) {
        info.slot = slot;
    } else if (info.slot == 0) {
        if (cleanup_extracted) {
            sol_snapshot_archive_rmdir(extracted_dir);
        }
        return slot_err;
    }

    sol_bank_config_t bank_config = SOL_BANK_CONFIG_DEFAULT;
    sol_bank_fields_t bank_fields = {0};
    sol_lt_hash_t accounts_lt_hash = {0};
    bool accounts_lt_hash_valid = false;
    sol_err_t bank_fields_err =
        load_bank_fields_from_snapshot(snapshot_dir,
                                       info.slot,
                                       &info,
                                       &bank_config,
                                       &bank_fields,
                                       &accounts_lt_hash,
                                       &accounts_lt_hash_valid);
    sol_hash_t snapshot_blockhash = {0};
    sol_err_t blockhash_err =
        load_latest_blockhash_from_snapshot(snapshot_dir, info.slot, &snapshot_blockhash);
    sol_hash_t snapshot_blockhash_queue_hashes[SOL_MAX_RECENT_BLOCKHASHES];
    uint64_t snapshot_blockhash_queue_fees[SOL_MAX_RECENT_BLOCKHASHES];
    size_t snapshot_blockhash_queue_len = 0;
    sol_err_t blockhash_queue_err =
        load_blockhash_queue_from_snapshot(snapshot_dir,
                                           info.slot,
                                           snapshot_blockhash_queue_hashes,
                                           snapshot_blockhash_queue_fees,
                                           SOL_MAX_RECENT_BLOCKHASHES,
                                           &snapshot_blockhash_queue_len);
    if (blockhash_queue_err == SOL_OK && snapshot_blockhash_queue_len > 0) {
        snapshot_blockhash = snapshot_blockhash_queue_hashes[0];
        blockhash_err = SOL_OK;
    }

    sol_err_t manifest_err = parse_snapshot_manifest(snapshot_dir, &info);
    if (manifest_err != SOL_OK && manifest_err != SOL_ERR_NOTFOUND) {
        sol_accounts_db_destroy(accounts_db);
        if (cleanup_extracted) {
            sol_snapshot_archive_rmdir(extracted_dir);
        }
        return manifest_err;
    }

    if (!accounts_loaded_from_archive) {
        /* Load accounts from accounts directory */
        char accounts_path[512];
        snprintf(accounts_path, sizeof(accounts_path), "%s/accounts", snapshot_dir);

        const size_t bulk_batch = 262144;
        uint32_t load_threads = default_snapshot_load_threads();

        bool wal_disabled = false;
        bool bulk_load_mode = false;
        sol_err_t accounts_err = SOL_OK;
        int core_index_ok = 0;

        bool can_parallel = (load_threads > 1);
        if (can_parallel) {
            sol_accounts_db_bulk_writer_t* probe = sol_accounts_db_bulk_writer_new(accounts_db, bulk_batch);
            if (probe) {
                sol_accounts_db_bulk_writer_destroy(probe);
            } else {
                can_parallel = false;
            }
        }

        if (can_parallel) {
            const size_t max_bytes_per_thread = default_snapshot_load_max_bytes_per_thread(load_threads);
            sol_log_info("Using parallel snapshot ingestion (threads=%u, batch=%lu)",
                         (unsigned)load_threads, (unsigned long)bulk_batch);

            if (sol_accounts_db_set_disable_wal(accounts_db, true) == SOL_OK) {
                wal_disabled = true;
            }
            if (sol_accounts_db_set_bulk_load_mode(accounts_db, true) == SOL_OK) {
                bulk_load_mode = true;
            }

            accounts_err = load_accounts_from_top_level_dir_parallel(accounts_path,
                                                                     accounts_db,
                                                                     load_threads,
                                                                     bulk_batch,
                                                                     max_bytes_per_thread,
                                                                     &total_accounts,
                                                                     &core_index_ok);
        } else {
            sol_accounts_db_bulk_writer_t* bulk_writer = sol_accounts_db_bulk_writer_new(accounts_db, bulk_batch);
            if (bulk_writer) {
                sol_log_info("Using bulk-writer snapshot ingestion (batch=%lu)", (unsigned long)bulk_batch);
                sol_accounts_db_bulk_writer_set_use_merge(bulk_writer, true);
                if (sol_accounts_db_is_appendvec(accounts_db)) {
                    (void)sol_accounts_db_bulk_writer_set_write_owner_reverse(bulk_writer, false);
                }
                sol_err_t idx_err = sol_accounts_db_bulk_writer_set_write_owner_index(bulk_writer, true);
                if (idx_err == SOL_OK) {
                    sol_accounts_db_bulk_writer_set_write_owner_index_core_only(bulk_writer, true);
                }
                core_index_ok = sol_accounts_db_bulk_writer_is_writing_owner_index(bulk_writer) ? 1 : 0;
                if (sol_accounts_db_set_disable_wal(accounts_db, true) == SOL_OK) {
                    wal_disabled = true;
                }
                if (sol_accounts_db_set_bulk_load_mode(accounts_db, true) == SOL_OK) {
                    bulk_load_mode = true;
                }
            } else {
                /* Without a bulk-writer, accounts are applied via per-key stores which update
                 * the owner index inline. */
                core_index_ok = 1;
            }

            accounts_err = load_accounts_from_dir(
                accounts_path, 0, accounts_db, bulk_writer, &total_accounts);

            if (bulk_writer) {
                sol_err_t flush_err = sol_accounts_db_bulk_writer_flush(bulk_writer);
                sol_accounts_db_bulk_writer_destroy(bulk_writer);
                bulk_writer = NULL;
                if (flush_err != SOL_OK) {
                    sol_log_error("Snapshot accounts bulk flush failed: %s", sol_err_str(flush_err));
                    accounts_err = flush_err;
                }
            }
        }

        if (wal_disabled) {
            (void)sol_accounts_db_set_disable_wal(accounts_db, false);
            wal_disabled = false;
        }
        if (bulk_load_mode) {
            (void)sol_accounts_db_set_bulk_load_mode(accounts_db, false);
            bulk_load_mode = false;
        }

        if (accounts_err == SOL_OK) {
            info.num_accounts = total_accounts;
            sol_log_info("Loaded %lu accounts from snapshot", (unsigned long)total_accounts);
            if (core_index_ok != 0) {
                sol_err_t merr = sol_accounts_db_mark_owner_index_core_built(accounts_db);
                if (merr != SOL_OK) {
                    sol_log_warn("Failed to mark core owner index built: %s", sol_err_str(merr));
                }
            }
        } else if (accounts_err == SOL_ERR_NOTFOUND && accounts_dir_has_storage_files(accounts_path)) {
            sol_log_error("Snapshot contains account storages but none could be loaded");
            sol_accounts_db_destroy(accounts_db);
            if (cleanup_extracted) {
                sol_snapshot_archive_rmdir(extracted_dir);
            }
            return SOL_ERR_SNAPSHOT_CORRUPT;
        } else if (accounts_err != SOL_OK && accounts_err != SOL_ERR_NOTFOUND) {
            sol_accounts_db_destroy(accounts_db);
            if (cleanup_extracted) {
                sol_snapshot_archive_rmdir(extracted_dir);
            }
            return accounts_err;
        }
    } else {
        info.num_accounts = total_accounts;
        sol_log_info("Loaded %lu accounts from snapshot (streamed from archive)",
                     (unsigned long)total_accounts);
    }

    if (!mgr->config.verify_accounts_hash) {
        sol_log_info("Skipping snapshot accounts-hash verification (verify_accounts_hash=false)");
    }

    bool want_filename_hash_verify =
        mgr->config.verify_accounts_hash &&
        cleanup_extracted &&
        info.type == SOL_SNAPSHOT_FULL &&
        !info.manifest_is_solana_c &&
        !sol_hash_is_zero(&info.hash);

    bool want_accounts_hash =
        mgr->config.verify_accounts_hash &&
        (want_filename_hash_verify || !sol_hash_is_zero(&info.accounts_hash));

    sol_hash_t computed_accounts_hash = {0};
    if (want_accounts_hash) {
        sol_accounts_db_hash(accounts_db, &computed_accounts_hash);

        /* Verify accounts hash if manifest provided it */
        if (!sol_hash_is_zero(&info.accounts_hash) &&
            !sol_hash_eq(&computed_accounts_hash, &info.accounts_hash)) {
            sol_log_error("Snapshot accounts hash mismatch at slot %lu", (unsigned long)info.slot);
            sol_accounts_db_destroy(accounts_db);
            if (cleanup_extracted) {
                sol_snapshot_archive_rmdir(extracted_dir);
            }
            return SOL_ERR_SNAPSHOT_MISMATCH;
        }
    }

    /* Verify the snapshot hash token from the archive name (best-effort). */
    if (want_filename_hash_verify) {
        uint64_t slots_per_epoch = bank_config.slots_per_epoch;
        if (slots_per_epoch == 0) slots_per_epoch = SOL_SLOTS_PER_EPOCH;

        uint64_t epoch = info.epoch;
        if (epoch == 0 && slots_per_epoch > 0) {
            epoch = (uint64_t)(info.slot / (sol_slot_t)slots_per_epoch);
        }

        sol_hash_t expected = {0};
        bool ok = solana_snapshot_hash_compute(
            info.slot,
            epoch,
            slots_per_epoch,
            &computed_accounts_hash,
            &info.epoch_accounts_hash,
            &expected);

        if (!ok) {
            sol_log_warn("Snapshot hash verification skipped: missing epoch accounts hash for slot %lu",
                         (unsigned long)info.slot);
        } else if (!sol_hash_eq(&expected, &info.hash)) {
            sol_log_error("Snapshot archive hash mismatch at slot %lu", (unsigned long)info.slot);
            sol_accounts_db_destroy(accounts_db);
            if (cleanup_extracted) {
                sol_snapshot_archive_rmdir(extracted_dir);
            }
            return SOL_ERR_SNAPSHOT_MISMATCH;
        }
    }

    sol_err_t persist_err = snapshot_persist_appendvec_accounts_dir(accounts_db, snapshot_dir, cleanup_extracted);
    if (persist_err != SOL_OK) {
        sol_accounts_db_destroy(accounts_db);
        if (cleanup_extracted) {
            sol_snapshot_archive_rmdir(extracted_dir);
        }
        return persist_err;
    }

    sol_log_info("Initializing bank from snapshot (slot=%lu)...", (unsigned long)info.slot);

    /* Create bank with snapshot slot and attach accounts_db */
    sol_bank_t* bank = sol_bank_new(info.slot, NULL, accounts_db, &bank_config);
    if (!bank) {
        sol_accounts_db_destroy(accounts_db);
        if (cleanup_extracted) {
            sol_snapshot_archive_rmdir(extracted_dir);
        }
        return SOL_ERR_NOMEM;
    }
    sol_log_info("Bank created from snapshot (slot=%lu)", (unsigned long)info.slot);

    if (blockhash_queue_err == SOL_OK && snapshot_blockhash_queue_len > 0) {
        sol_err_t qerr = sol_bank_set_recent_blockhash_queue(bank,
                                                             snapshot_blockhash_queue_hashes,
                                                             snapshot_blockhash_queue_fees,
                                                             snapshot_blockhash_queue_len);
        if (qerr != SOL_OK) {
            sol_log_warn("Failed to seed recent blockhash queue from snapshot: %s", sol_err_str(qerr));
        } else {
            sol_err_t perr = sol_accounts_db_set_bootstrap_blockhash_queue(accounts_db,
                                                                           snapshot_blockhash_queue_hashes,
                                                                           snapshot_blockhash_queue_fees,
                                                                           snapshot_blockhash_queue_len);
            if (perr != SOL_OK) {
                sol_log_warn("Failed to persist snapshot blockhash queue: %s", sol_err_str(perr));
            }
        }
    }

    if (blockhash_err == SOL_OK) {
        sol_bank_set_blockhash(bank, &snapshot_blockhash);
    }

    if (accounts_lt_hash_valid) {
        sol_bank_set_accounts_lt_hash(bank, &accounts_lt_hash);
        if (sol_log_get_level() <= SOL_LOG_DEBUG) {
            sol_blake3_t checksum = {0};
            sol_hash_t checksum_hash = {0};
            sol_lt_hash_checksum(&accounts_lt_hash, &checksum);
            memcpy(checksum_hash.bytes, checksum.bytes, sizeof(checksum_hash.bytes));
            char hex[65] = {0};
            (void)sol_hash_to_hex(&checksum_hash, hex, sizeof(hex));
            sol_log_debug("Snapshot accounts LtHash checksum: %s", hex);
        }
    } else {
        sol_log_warn("No accounts LtHash available for snapshot slot %lu; replay/bank-hash may be slow",
                     (unsigned long)info.slot);
    }

    sol_bank_freeze(bank);
    bool seeded_bank_hash = false;
    if (bank_fields_err == SOL_OK) {
        /* Bank hash includes the cumulative signature count. Seed it from the
         * snapshot so replayed bank hashes match the cluster. */
        sol_bank_set_signature_count(bank, bank_fields.transaction_count);
        sol_bank_set_parent_slot(bank, bank_fields.parent_slot);

        const sol_hash_t* blockhash = sol_bank_blockhash(bank);
        if (blockhash && !sol_hash_eq(blockhash, &bank_fields.hash)) {
            sol_bank_set_parent_bank_hash(bank, &bank_fields.parent_hash);
            sol_bank_set_bank_hash(bank, &bank_fields.hash);
            seeded_bank_hash = true;
        } else {
            sol_log_warn("Snapshot bank fields hash matches latest blockhash; skipping bank-hash seeding");
        }
    }

    if (!seeded_bank_hash) {
        sol_log_warn("No bank hash available for snapshot slot %lu; replay/voting may be incorrect",
                     (unsigned long)info.slot);
    }

    if (!sol_hash_is_zero(&info.epoch_accounts_hash)) {
        (void)sol_accounts_db_set_epoch_accounts_hash(
            accounts_db, sol_bank_epoch(bank), &info.epoch_accounts_hash);
    }

    sol_accounts_db_bootstrap_state_t prev_bootstrap = {0};
    bool have_prev_bootstrap = sol_accounts_db_get_bootstrap_state(accounts_db, &prev_bootstrap);

    sol_accounts_db_bootstrap_state_t bootstrap = {0};
    bootstrap.slot = info.slot;
    bootstrap.parent_slot = (bank_fields_err == SOL_OK) ? bank_fields.parent_slot : 0;
    bootstrap.signature_count = (bank_fields_err == SOL_OK) ? bank_fields.transaction_count : 0;
    bootstrap.flags = 0;
    bootstrap.ticks_per_slot = bank_config.ticks_per_slot;
    bootstrap.hashes_per_tick = bank_config.hashes_per_tick;
    bootstrap.slots_per_epoch = bank_config.slots_per_epoch;
    bootstrap.lamports_per_signature = bank_config.lamports_per_signature;
    bootstrap.rent_per_byte_year = bank_config.rent_per_byte_year;
    bootstrap.rent_exemption_threshold = bank_config.rent_exemption_threshold;

    if (have_prev_bootstrap &&
        (prev_bootstrap.flags & SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_GENESIS_HASH) &&
        !sol_hash_is_zero(&prev_bootstrap.genesis_hash)) {
        bootstrap.flags |= SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_GENESIS_HASH;
        bootstrap.genesis_hash = prev_bootstrap.genesis_hash;
    }
    if (have_prev_bootstrap &&
        (prev_bootstrap.flags & SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_SHRED_VERSION) &&
        prev_bootstrap.shred_version != 0) {
        bootstrap.flags |= SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_SHRED_VERSION;
        bootstrap.shred_version = prev_bootstrap.shred_version;
    }

    if (blockhash_err == SOL_OK) {
        bootstrap.flags |= SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_BLOCKHASH;
        bootstrap.blockhash = snapshot_blockhash;
    }
    if (accounts_lt_hash_valid) {
        bootstrap.flags |= SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_ACCOUNTS_LT_HASH;
        bootstrap.accounts_lt_hash = accounts_lt_hash;
    }
    if (seeded_bank_hash) {
        bootstrap.flags |= SOL_ACCOUNTS_DB_BOOTSTRAP_HAS_BANK_HASH;
        bootstrap.parent_bank_hash = bank_fields.parent_hash;
        bootstrap.bank_hash = bank_fields.hash;
    }

    sol_err_t boot_err = sol_accounts_db_set_bootstrap_state(accounts_db, &bootstrap);
    if (boot_err != SOL_OK) {
        sol_log_warn("Failed to persist bootstrap bank state: %s", sol_err_str(boot_err));
    }

    if (accounts_lt_hash_valid || seeded_bank_hash) {
        /* Emit a "bank frozen" line for parity harnesses. */
        sol_hash_t bank_hash = {0};
        sol_bank_compute_hash(bank, &bank_hash);

        char bank_hash_b58[SOL_PUBKEY_BASE58_LEN] = {0};
        bytes32_to_base58(bank_hash.bytes, bank_hash_b58, sizeof(bank_hash_b58));

        char last_blockhash_b58[SOL_PUBKEY_BASE58_LEN] = {0};
        const sol_hash_t* last_blockhash = sol_bank_blockhash(bank);
        if (last_blockhash) {
            bytes32_to_base58(last_blockhash->bytes, last_blockhash_b58, sizeof(last_blockhash_b58));
        }

        sol_blake3_t lt_checksum = {0};
        sol_bank_accounts_lt_hash_checksum(bank, &lt_checksum);

        char lt_checksum_b58[SOL_PUBKEY_BASE58_LEN] = {0};
        bytes32_to_base58(lt_checksum.bytes, lt_checksum_b58, sizeof(lt_checksum_b58));

        sol_log_info("bank frozen: %lu hash: %s signature_count: %lu last_blockhash: %s accounts_delta_hash: %s accounts_lt_hash checksum: %s",
                     (unsigned long)info.slot,
                     bank_hash_b58[0] ? bank_hash_b58 : "-",
                     (unsigned long)sol_bank_signature_count(bank),
                     last_blockhash_b58[0] ? last_blockhash_b58 : "-",
                     "-",
                     lt_checksum_b58[0] ? lt_checksum_b58 : "-");
    }

    if (!mgr || !mgr->defer_owner_reverse_mark) {
        /* AppendVec snapshot ingestion currently skips the owner-reverse mapping
         * to keep bootstrap time low. Do not mark it as built, otherwise later
         * index builds may incorrectly assume the reverse mapping is complete. */
        if (!sol_accounts_db_is_appendvec(accounts_db)) {
            sol_err_t merr = sol_accounts_db_mark_owner_reverse_built(accounts_db);
            if (merr != SOL_OK) {
                sol_log_warn("Failed to mark owner reverse mapping built: %s", sol_err_str(merr));
            }
        }
    }

    sol_err_t fixerr = sol_accounts_db_fixup_builtin_program_accounts(accounts_db);
    if (fixerr != SOL_OK) {
        sol_bank_destroy(bank);
        sol_accounts_db_destroy(accounts_db);
        if (cleanup_extracted) {
            sol_snapshot_archive_rmdir(extracted_dir);
        }
        return fixerr;
    }

    *out_bank = bank;
    if (out_accounts_db) {
        *out_accounts_db = accounts_db;
    }

    sol_log_info("Loaded snapshot at slot %lu (epoch %lu, %lu accounts)",
                 (unsigned long)info.slot,
                 (unsigned long)info.epoch,
                 (unsigned long)info.num_accounts);

    if (cleanup_extracted) {
        sol_snapshot_archive_rmdir(extracted_dir);
    }

    return SOL_OK;
}

sol_err_t
sol_snapshot_load_full_and_incremental(sol_snapshot_mgr_t* mgr,
                                       const char* full_archive_path,
                                       const char* incremental_archive_path,
                                       const sol_accounts_db_config_t* accounts_db_config,
                                       sol_bank_t** out_bank,
                                       sol_accounts_db_t** out_accounts_db) {
    if (!mgr || !full_archive_path || !out_bank) return SOL_ERR_INVAL;

    sol_bank_t* bank = NULL;
    sol_accounts_db_t* accounts_db = NULL;

    bool prev_defer = mgr->defer_owner_reverse_mark;
    if (incremental_archive_path && incremental_archive_path[0] != '\0') {
        mgr->defer_owner_reverse_mark = true;
    }

    sol_err_t err = sol_snapshot_load_with_accounts_db_config(
        mgr, full_archive_path, accounts_db_config, &bank, &accounts_db);
    mgr->defer_owner_reverse_mark = prev_defer;
    if (err != SOL_OK) return err;

    if (incremental_archive_path && incremental_archive_path[0] != '\0') {
        sol_bank_t* incr_bank = NULL;
        err = apply_incremental_snapshot_to_accounts_db(
            mgr, incremental_archive_path, sol_bank_slot(bank), accounts_db, &incr_bank);
        if (err != SOL_OK) {
            sol_bank_destroy(bank);
            sol_accounts_db_destroy(accounts_db);
            return err;
        }

        sol_bank_destroy(bank);
        bank = incr_bank;

        if (!sol_accounts_db_is_appendvec(accounts_db)) {
            sol_err_t merr = sol_accounts_db_mark_owner_reverse_built(accounts_db);
            if (merr != SOL_OK) {
                sol_log_warn("Failed to mark owner reverse mapping built after incremental load: %s",
                             sol_err_str(merr));
            }
        }
    }

    /* The full snapshot load already ran the builtin fixup, but the incremental
     * snapshot may have overwritten those accounts with stale values (e.g.
     * System Program with executable=false).  Run the fixup again. */
    sol_err_t fixerr2 = sol_accounts_db_fixup_builtin_program_accounts(accounts_db);
    if (fixerr2 != SOL_OK) {
        sol_log_error("Builtin fixup after incremental load failed: %s", sol_err_str(fixerr2));
    }

    /* DEBUG: verify System Program is accessible after full+incremental load */
    {
        extern const sol_pubkey_t SOL_SYSTEM_PROGRAM_ID;
        sol_account_t* sp = sol_accounts_db_load(accounts_db, &SOL_SYSTEM_PROGRAM_ID);
        if (!sp) {
            sol_log_error("POST-SNAPSHOT: System Program NOT FOUND in accounts_db after full+incremental load!");
        } else {
            sol_log_info("POST-SNAPSHOT: System Program OK: lamports=%lu exec=%d data_len=%lu rent_epoch=%lu",
                         (unsigned long)sp->meta.lamports,
                         (int)sp->meta.executable,
                         (unsigned long)sp->meta.data_len,
                         (unsigned long)sp->meta.rent_epoch);
            sol_account_destroy(sp);
        }
    }

    /* Set zombie filter slot: accounts with lamports==0 stored at or before
     * the snapshot slot are treated as non-existent (simulates Agave's
     * clean_accounts which has been running continuously). */
    sol_bank_set_zombie_filter_slot(bank, sol_bank_slot(bank));

    *out_bank = bank;
    if (out_accounts_db) {
        *out_accounts_db = accounts_db;
    }

    return SOL_OK;
}

sol_err_t
sol_snapshot_apply_incremental_to_accounts_db(sol_snapshot_mgr_t* mgr,
                                             const char* incremental_archive_path,
                                             sol_slot_t expected_base_slot,
                                             sol_accounts_db_t* accounts_db,
                                             sol_bank_t** out_bank) {
    return apply_incremental_snapshot_to_accounts_db(mgr,
                                                     incremental_archive_path,
                                                     expected_base_slot,
                                                     accounts_db,
                                                     out_bank);
}

static int
hex_nibble(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static sol_err_t
parse_hex_hash32(const char* s, sol_hash_t* out) {
    if (!s || !out) return SOL_ERR_INVAL;

    while (*s && isspace((unsigned char)*s)) s++;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    if (strlen(s) < (SOL_HASH_SIZE * 2u)) return SOL_ERR_SNAPSHOT_CORRUPT;

    for (size_t i = 0; i < SOL_HASH_SIZE; i++) {
        int hi = hex_nibble((unsigned char)s[i * 2]);
        int lo = hex_nibble((unsigned char)s[i * 2 + 1]);
        if (hi < 0 || lo < 0) return SOL_ERR_SNAPSHOT_CORRUPT;
        out->bytes[i] = (uint8_t)((hi << 4) | lo);
    }

    return SOL_OK;
}

static sol_err_t
parse_hash32_str(const char* s, sol_hash_t* out) {
    if (!s || !out) return SOL_ERR_INVAL;

    /* Trim whitespace */
    while (*s && isspace((unsigned char)*s)) s++;

    /* Trim optional quotes */
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) len--;
    if (len >= 2 &&
        ((s[0] == '"' && s[len - 1] == '"') ||
         (s[0] == '\'' && s[len - 1] == '\''))) {
        s++;
        len -= 2;
        while (len > 0 && isspace((unsigned char)*s)) {
            s++;
            len--;
        }
        while (len > 0 && isspace((unsigned char)s[len - 1])) {
            len--;
        }
    }

    if (len == 0) return SOL_ERR_SNAPSHOT_CORRUPT;

    char buf[128];
    if (len >= sizeof(buf)) {
        return SOL_ERR_SNAPSHOT_CORRUPT;
    }
    memcpy(buf, s, len);
    buf[len] = '\0';

    sol_hash_t h = {0};
    if (sol_pubkey_from_base58(buf, (sol_pubkey_t*)&h) == SOL_OK) {
        *out = h;
        return SOL_OK;
    }

    return parse_hex_hash32(buf, out);
}

static bool
parse_u64_strict(const char* s, uint64_t* out) {
    if (!s || !out) return false;
    errno = 0;
    char* end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno != 0 || end == s) return false;
    while (*end && isspace((unsigned char)*end)) end++;
    if (*end != '\0') return false;
    *out = (uint64_t)v;
    return true;
}

static sol_err_t
parse_snapshot_manifest(const char* snapshot_dir, sol_snapshot_info_t* info) {
    if (!snapshot_dir || !info) return SOL_ERR_INVAL;

    const char* candidates[] = {"manifest", "snapshot.manifest", "snapshot_manifest", NULL};
    FILE* f = NULL;
    char manifest_path[512];

    for (size_t i = 0; candidates[i] != NULL; i++) {
        snprintf(manifest_path, sizeof(manifest_path), "%s/%s", snapshot_dir, candidates[i]);
        f = fopen(manifest_path, "r");
        if (f) break;
    }

    if (!f) return SOL_ERR_NOTFOUND;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char* s = line;
        while (*s && isspace((unsigned char)*s)) s++;
        if (*s == '\0' || *s == '#') continue;

        char* eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';
        char* key = s;
        char* val = eq + 1;

        /* Trim key */
        size_t key_len = strlen(key);
        while (key_len > 0 && isspace((unsigned char)key[key_len - 1])) {
            key[--key_len] = '\0';
        }

        /* Trim leading/trailing whitespace from value */
        while (*val && isspace((unsigned char)*val)) val++;
        size_t val_len = strlen(val);
        while (val_len > 0 && isspace((unsigned char)val[val_len - 1])) {
            val[--val_len] = '\0';
        }

        if (strcmp(key, "format") == 0) {
            if (strcmp(val, "solana-c") == 0) {
                info->manifest_is_solana_c = true;
            }
        } else if (strcmp(key, "accounts_hash") == 0) {
            sol_hash_t h;
            sol_err_t err = parse_hash32_str(val, &h);
            if (err != SOL_OK) {
                fclose(f);
                return err;
            }
            info->accounts_hash = h;
        } else if (strcmp(key, "epoch_accounts_hash") == 0) {
            sol_hash_t h;
            sol_err_t err = parse_hash32_str(val, &h);
            if (err != SOL_OK) {
                fclose(f);
                return err;
            }
            info->epoch_accounts_hash = h;
        } else if (strcmp(key, "base_slot") == 0) {
            uint64_t v;
            if (parse_u64_strict(val, &v)) info->base_slot = (sol_slot_t)v;
        } else if (strcmp(key, "slot") == 0) {
            uint64_t v;
            if (parse_u64_strict(val, &v)) info->slot = (sol_slot_t)v;
        } else if (strcmp(key, "epoch") == 0) {
            uint64_t v;
            if (parse_u64_strict(val, &v)) info->epoch = v;
        } else if (strcmp(key, "block_height") == 0) {
            uint64_t v;
            if (parse_u64_strict(val, &v)) info->block_height = v;
        } else if (strcmp(key, "capitalization") == 0) {
            uint64_t v;
            if (parse_u64_strict(val, &v)) info->capitalization = v;
        } else if (strcmp(key, "lamports_per_signature") == 0) {
            uint64_t v;
            if (parse_u64_strict(val, &v)) info->lamports_per_signature = v;
        }
    }

    fclose(f);
    return SOL_OK;
}

/*
 * Parse slot and hash from snapshot filename
 */
static sol_err_t
parse_snapshot_filename(const char* filename, sol_snapshot_info_t* info) {
    /* Full: snapshot-<slot>-<hash>.tar.zst */
    /* Incremental: incremental-snapshot-<base>-<slot>-<hash>.tar.zst */

    memset(info, 0, sizeof(*info));

    const char* hash_str = NULL;
    size_t hash_len = 0;
    bool matched = false;

    if (strncmp(filename, "incremental-snapshot-", 21) == 0) {
        info->type = SOL_SNAPSHOT_INCREMENTAL;
        const char* p = filename + 21;

        char* end = NULL;
        errno = 0;
        unsigned long long base = strtoull(p, &end, 10);
        if (errno != 0 || end == p || *end != '-') {
            return SOL_ERR_SNAPSHOT_CORRUPT;
        }
        p = end + 1;

        errno = 0;
        unsigned long long slot = strtoull(p, &end, 10);
        if (errno != 0 || end == p || *end != '-') {
            return SOL_ERR_SNAPSHOT_CORRUPT;
        }
        p = end + 1;

        /* hash is up to the first '.' (extension) */
        const char* dot = strchr(p, '.');
        hash_str = p;
        hash_len = dot ? (size_t)(dot - p) : strlen(p);

        info->base_slot = (sol_slot_t)base;
        info->slot = (sol_slot_t)slot;
        matched = true;
    } else if (strncmp(filename, "snapshot-", 9) == 0) {
        info->type = SOL_SNAPSHOT_FULL;
        const char* p = filename + 9;

        char* end = NULL;
        errno = 0;
        unsigned long long slot = strtoull(p, &end, 10);
        if (errno != 0 || end == p || *end != '-') {
            return SOL_ERR_SNAPSHOT_CORRUPT;
        }
        p = end + 1;

        const char* dot = strchr(p, '.');
        hash_str = p;
        hash_len = dot ? (size_t)(dot - p) : strlen(p);

        info->slot = (sol_slot_t)slot;
        matched = true;
    }

    if (!matched) return SOL_ERR_SNAPSHOT_CORRUPT;

    /* Best-effort hash parsing (base58 or hex). Keep `info->hash` zero if
     * parsing fails so older filenames still work. */
    if (hash_str && hash_len > 0) {
        char buf[128];
        if (hash_len < sizeof(buf)) {
            memcpy(buf, hash_str, hash_len);
            buf[hash_len] = '\0';

            sol_hash_t h = {0};
            if (sol_pubkey_from_base58(buf, (sol_pubkey_t*)&h) == SOL_OK) {
                info->hash = h;
            } else {
                /* Hex fallback (accepts partial hex; fills leading bytes). */
                bool all_hex = (hash_len % 2 == 0 && hash_len <= 64);
                if (all_hex) {
                    for (size_t i = 0; i < hash_len; i++) {
                        char c = buf[i];
                        bool ok = (c >= '0' && c <= '9') ||
                                  (c >= 'a' && c <= 'f') ||
                                  (c >= 'A' && c <= 'F');
                        if (!ok) {
                            all_hex = false;
                            break;
                        }
                    }
                }

                if (all_hex) {
                    memset(&h, 0, sizeof(h));
                    for (size_t i = 0; i < hash_len / 2; i++) {
                        int hi = hex_nibble((unsigned char)buf[i * 2]);
                        int lo = hex_nibble((unsigned char)buf[i * 2 + 1]);
                        if (hi < 0 || lo < 0) {
                            all_hex = false;
                            break;
                        }
                        h.bytes[i] = (uint8_t)((hi << 4) | lo);
                    }
                    if (all_hex) {
                        info->hash = h;
                    }
                }
            }
        }
    }

    return SOL_OK;
}

/*
 * Get snapshot info from archive
 */
sol_err_t
sol_snapshot_get_info(const char* archive_path, sol_snapshot_info_t* out_info) {
    if (!archive_path || !out_info) return SOL_ERR_INVAL;

    /* Extract filename from path */
    const char* filename = strrchr(archive_path, '/');
    if (filename) {
        filename++;
    } else {
        filename = archive_path;
    }

    return parse_snapshot_filename(filename, out_info);
}

/*
 * Get archive filename for snapshot
 */
size_t
sol_snapshot_archive_name(const sol_snapshot_info_t* info,
                           char* out_name, size_t max_len) {
    if (!info || !out_name || max_len == 0) return 0;

    /* Format hash as hex (first 8 bytes) */
    char hash_hex[17];
    for (int i = 0; i < 8; i++) {
        snprintf(&hash_hex[i*2], 3, "%02x", info->hash.bytes[i]);
    }

    const char* ext;
    switch (info->compression) {
        case SOL_SNAPSHOT_COMPRESSION_NONE: ext = "tar"; break;
        case SOL_SNAPSHOT_COMPRESSION_ZSTD: ext = "tar.zst"; break;
        case SOL_SNAPSHOT_COMPRESSION_GZIP: ext = "tar.gz"; break;
        case SOL_SNAPSHOT_COMPRESSION_BZIP2: ext = "tar.bz2"; break;
        case SOL_SNAPSHOT_COMPRESSION_LZ4:  ext = "tar.lz4"; break;
        default: ext = "tar"; break;
    }

    int len;
    if (info->type == SOL_SNAPSHOT_INCREMENTAL) {
        len = snprintf(out_name, max_len,
                       "incremental-snapshot-%lu-%lu-%s.%s",
                       (unsigned long)info->base_slot,
                       (unsigned long)info->slot,
                       hash_hex, ext);
    } else {
        len = snprintf(out_name, max_len,
                       "snapshot-%lu-%s.%s",
                       (unsigned long)info->slot,
                       hash_hex, ext);
    }

    return (len > 0 && (size_t)len < max_len) ? (size_t)len : 0;
}

/*
 * List available snapshots
 */
size_t
sol_snapshot_list(const char* archive_dir,
                   sol_snapshot_info_t* out_infos,
                   size_t max_count) {
    if (!archive_dir || !out_infos || max_count == 0) return 0;

    DIR* dir = opendir(archive_dir);
    if (!dir) return 0;

    size_t count = 0;
    struct dirent* entry;

    while ((entry = readdir(dir)) != NULL && count < max_count) {
        if (entry->d_name[0] == '.') continue;

        sol_snapshot_info_t info;
        if (parse_snapshot_filename(entry->d_name, &info) == SOL_OK) {
            out_infos[count++] = info;
        }
    }

    closedir(dir);
    return count;
}

/*
 * Compare snapshots by slot (for sorting)
 */
static int
compare_snapshots(const void* a, const void* b) {
    const sol_snapshot_info_t* sa = (const sol_snapshot_info_t*)a;
    const sol_snapshot_info_t* sb = (const sol_snapshot_info_t*)b;

    if (sa->slot < sb->slot) return -1;
    if (sa->slot > sb->slot) return 1;
    return 0;
}

/*
 * Find best snapshot for target slot
 */
sol_err_t
sol_snapshot_find_best(const char* archive_dir,
                        sol_slot_t target_slot,
                        sol_snapshot_info_t* out_full,
                        sol_snapshot_info_t* out_incremental) {
    if (!archive_dir || !out_full) return SOL_ERR_INVAL;

    sol_snapshot_info_t infos[100];
    size_t count = sol_snapshot_list(archive_dir, infos, 100);

    if (count == 0) return SOL_ERR_NOTFOUND;

    /* Sort by slot */
    qsort(infos, count, sizeof(sol_snapshot_info_t), compare_snapshots);

    /* Find best full snapshot */
    sol_snapshot_info_t* best_full = NULL;
    for (size_t i = count; i > 0; i--) {
        if (infos[i-1].type == SOL_SNAPSHOT_FULL &&
            infos[i-1].slot <= target_slot) {
            best_full = &infos[i-1];
            break;
        }
    }

    if (!best_full) return SOL_ERR_NOTFOUND;

    *out_full = *best_full;

    /* Find best incremental if requested */
    if (out_incremental) {
        memset(out_incremental, 0, sizeof(*out_incremental));

        for (size_t i = count; i > 0; i--) {
            if (infos[i-1].type == SOL_SNAPSHOT_INCREMENTAL &&
                infos[i-1].base_slot == best_full->slot &&
                infos[i-1].slot <= target_slot) {
                *out_incremental = infos[i-1];
                break;
            }
        }
    }

    return SOL_OK;
}

/*
 * Delete old snapshots
 */
size_t
sol_snapshot_cleanup(sol_snapshot_mgr_t* mgr) {
    if (!mgr || !mgr->archive_dir) return 0;

    sol_snapshot_info_t infos[100];
    size_t count = sol_snapshot_list(mgr->archive_dir, infos, 100);

    if (count <= mgr->config.max_archive_count) return 0;

    /* Sort by slot */
    qsort(infos, count, sizeof(sol_snapshot_info_t), compare_snapshots);

    /* Delete oldest ones */
    size_t deleted = 0;
    size_t to_delete = count - mgr->config.max_archive_count;

    for (size_t i = 0; i < to_delete; i++) {
        char path[512];
        char name[256];

        if (sol_snapshot_archive_name(&infos[i], name, sizeof(name)) > 0) {
            snprintf(path, sizeof(path), "%s/%s", mgr->archive_dir, name);
            if (remove(path) == 0) {
                deleted++;
                sol_log_info("Deleted old snapshot: %s", name);
            }
        }
    }

    return deleted;
}

/*
 * Verify snapshot archive
 */
sol_err_t
sol_snapshot_verify(const char* archive_path) {
    if (!archive_path) return SOL_ERR_INVAL;

    /* Basic check: file exists */
    struct stat st;
    if (stat(archive_path, &st) != 0) return SOL_ERR_NOTFOUND;

    /* Parse filename to validate format */
    sol_snapshot_info_t info;
    return sol_snapshot_get_info(archive_path, &info);
}

/*
 * Status cache implementation
 */

sol_status_cache_t*
sol_status_cache_new(size_t capacity) {
    sol_status_cache_t* cache = sol_calloc(1, sizeof(sol_status_cache_t));
    if (!cache) return NULL;

    cache->entries = sol_calloc(capacity, sizeof(sol_status_cache_entry_t));
    if (!cache->entries) {
        sol_free(cache);
        return NULL;
    }

    cache->capacity = capacity;
    cache->count = 0;
    cache->oldest_slot = UINT64_MAX;

    return cache;
}

void
sol_status_cache_destroy(sol_status_cache_t* cache) {
    if (!cache) return;
    sol_free(cache->entries);
    sol_free(cache);
}

sol_err_t
sol_status_cache_add(sol_status_cache_t* cache,
                      const sol_signature_t* sig,
                      sol_slot_t slot,
                      sol_err_t status) {
    if (!cache || !sig) return SOL_ERR_INVAL;

    if (cache->count >= cache->capacity) {
        /* Evict oldest entries */
        sol_status_cache_purge(cache, cache->oldest_slot);
    }

    if (cache->count >= cache->capacity) {
        return SOL_ERR_FULL;
    }

    sol_status_cache_entry_t* entry = &cache->entries[cache->count++];
    entry->signature = *sig;
    entry->slot = slot;
    entry->status = status;

    if (slot < cache->oldest_slot) {
        cache->oldest_slot = slot;
    }

    return SOL_OK;
}

bool
sol_status_cache_lookup(const sol_status_cache_t* cache,
                         const sol_signature_t* sig,
                         sol_slot_t* out_slot,
                         sol_err_t* out_status) {
    if (!cache || !sig) return false;

    for (size_t i = 0; i < cache->count; i++) {
        if (memcmp(&cache->entries[i].signature, sig, sizeof(sol_signature_t)) == 0) {
            if (out_slot) *out_slot = cache->entries[i].slot;
            if (out_status) *out_status = cache->entries[i].status;
            return true;
        }
    }

    return false;
}

size_t
sol_status_cache_purge(sol_status_cache_t* cache, sol_slot_t min_slot) {
    if (!cache) return 0;

    size_t removed = 0;
    size_t write_idx = 0;

    for (size_t i = 0; i < cache->count; i++) {
        if (cache->entries[i].slot >= min_slot) {
            if (write_idx != i) {
                cache->entries[write_idx] = cache->entries[i];
            }
            write_idx++;
        } else {
            removed++;
        }
    }

    cache->count = write_idx;

    /* Update oldest slot */
    cache->oldest_slot = UINT64_MAX;
    for (size_t i = 0; i < cache->count; i++) {
        if (cache->entries[i].slot < cache->oldest_slot) {
            cache->oldest_slot = cache->entries[i].slot;
        }
    }

    return removed;
}

size_t
sol_status_cache_serialize(const sol_status_cache_t* cache,
                            uint8_t* out_data, size_t max_len) {
    if (!cache || !out_data) return 0;

    size_t needed = sizeof(uint64_t) + cache->count * sizeof(sol_status_cache_entry_t);
    if (needed > max_len) return 0;

    size_t offset = 0;

    /* Write count */
    uint64_t count = cache->count;
    memcpy(out_data + offset, &count, sizeof(count));
    offset += sizeof(count);

    /* Write entries */
    memcpy(out_data + offset, cache->entries,
           cache->count * sizeof(sol_status_cache_entry_t));
    offset += cache->count * sizeof(sol_status_cache_entry_t);

    return offset;
}

sol_err_t
sol_status_cache_deserialize(const uint8_t* data, size_t len,
                              sol_status_cache_t* cache) {
    if (!data || !cache) return SOL_ERR_INVAL;
    if (len < sizeof(uint64_t)) return SOL_ERR_SNAPSHOT_CORRUPT;

    size_t offset = 0;

    /* Read count */
    uint64_t count;
    memcpy(&count, data + offset, sizeof(count));
    offset += sizeof(count);

    size_t entries_size = count * sizeof(sol_status_cache_entry_t);
    if (offset + entries_size > len) return SOL_ERR_SNAPSHOT_CORRUPT;
    if (count > cache->capacity) return SOL_ERR_FULL;

    /* Read entries */
    memcpy(cache->entries, data + offset, entries_size);
    cache->count = count;

    /* Update oldest slot */
    cache->oldest_slot = UINT64_MAX;
    for (size_t i = 0; i < cache->count; i++) {
        if (cache->entries[i].slot < cache->oldest_slot) {
            cache->oldest_slot = cache->entries[i].slot;
        }
    }

    return SOL_OK;
}
