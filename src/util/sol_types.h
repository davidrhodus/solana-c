/*
 * sol_types.h - Fundamental types for Solana validator
 *
 * Core type definitions including Pubkey, Hash, Signature, and basic
 * numeric types used throughout the codebase.
 */

#ifndef SOL_TYPES_H
#define SOL_TYPES_H

#include "sol_base.h"
#include <string.h>

/*
 * Basic type aliases (Firedancer-style naming)
 */
typedef uint8_t   uchar;
typedef uint16_t  ushort;
typedef uint32_t  uint;
typedef uint64_t  ulong;
typedef __uint128_t uint128;

typedef int8_t    schar;
typedef int16_t   sshort;
typedef int32_t   sint;
typedef int64_t   slong;
typedef __int128_t int128;

/*
 * Solana-specific sizes
 */
#define SOL_PUBKEY_SIZE        32
#define SOL_HASH_SIZE          32
#define SOL_SIGNATURE_SIZE     64
#define SOL_KEYPAIR_SIZE       64
#define SOL_PRIVKEY_SIZE       32
#define SOL_SEED_SIZE          32

/*
 * Solana constants
 */
#define SOL_LAMPORTS_PER_SOL   1000000000UL
#define SOL_MAX_TX_SIZE        1232
#define SOL_MAX_ACCOUNTS_PER_TX 256
#define SOL_TICKS_PER_SLOT     64
#define SOL_NS_PER_SLOT        400000000UL  /* 400ms */
#define SOL_MS_PER_SLOT        400
#define SOL_HASHES_PER_TICK    12500
#define SOL_SLOTS_PER_EPOCH    432000UL
#define SOL_MAX_LOCKOUT_HISTORY 31
#define SOL_MAX_RECENT_BLOCKHASHES 300

/*
 * Public key (32 bytes)
 */
typedef struct {
    uchar bytes[SOL_PUBKEY_SIZE];
} sol_pubkey_t;

SOL_STATIC_ASSERT(sizeof(sol_pubkey_t) == 32, "sol_pubkey_t must be 32 bytes");

/* Well-known program addresses */
extern const sol_pubkey_t SOL_SYSTEM_PROGRAM_ID;
extern const sol_pubkey_t SOL_VOTE_PROGRAM_ID;
extern const sol_pubkey_t SOL_STAKE_PROGRAM_ID;
extern const sol_pubkey_t SOL_CONFIG_PROGRAM_ID;
extern const sol_pubkey_t SOL_BPF_LOADER_V2_ID;
extern const sol_pubkey_t SOL_BPF_LOADER_V3_ID;
extern const sol_pubkey_t SOL_BPF_LOADER_UPGRADEABLE_ID;
extern const sol_pubkey_t SOL_COMPUTE_BUDGET_ID;
extern const sol_pubkey_t SOL_ADDRESS_LOOKUP_TABLE_ID;
extern const sol_pubkey_t SOL_ED25519_PROGRAM_ID;
extern const sol_pubkey_t SOL_SECP256K1_PROGRAM_ID;
extern const sol_pubkey_t SOL_SECP256R1_PROGRAM_ID;
extern const sol_pubkey_t SOL_SYSVAR_PROGRAM_ID;
extern const sol_pubkey_t SOL_SYSVAR_CLOCK_ID;
extern const sol_pubkey_t SOL_SYSVAR_RENT_ID;
extern const sol_pubkey_t SOL_SYSVAR_EPOCH_SCHEDULE_ID;
extern const sol_pubkey_t SOL_SYSVAR_RECENT_BLOCKHASHES_ID;
extern const sol_pubkey_t SOL_SYSVAR_INSTRUCTIONS_ID;
extern const sol_pubkey_t SOL_NATIVE_LOADER_ID;
extern const sol_pubkey_t SOL_INCINERATOR_ID;

/* Pubkey operations */
SOL_INLINE bool
sol_pubkey_eq(const sol_pubkey_t* a, const sol_pubkey_t* b) {
    return memcmp(a->bytes, b->bytes, SOL_PUBKEY_SIZE) == 0;
}

SOL_INLINE int
sol_pubkey_cmp(const sol_pubkey_t* a, const sol_pubkey_t* b) {
    return memcmp(a->bytes, b->bytes, SOL_PUBKEY_SIZE);
}

SOL_INLINE bool
sol_pubkey_is_zero(const sol_pubkey_t* pk) {
    /* Use memcmp for safety (compiler will optimize) */
    static const uchar zeros[SOL_PUBKEY_SIZE] = {0};
    return memcmp(pk->bytes, zeros, SOL_PUBKEY_SIZE) == 0;
}

SOL_INLINE void
sol_pubkey_copy(sol_pubkey_t* dst, const sol_pubkey_t* src) {
    memcpy(dst->bytes, src->bytes, SOL_PUBKEY_SIZE);
}

/*
 * Cryptographic hash (32 bytes) - typically SHA-256
 */
typedef struct {
    uchar bytes[SOL_HASH_SIZE];
} sol_hash_t;

SOL_STATIC_ASSERT(sizeof(sol_hash_t) == 32, "sol_hash_t must be 32 bytes");

SOL_INLINE bool
sol_hash_eq(const sol_hash_t* a, const sol_hash_t* b) {
    return memcmp(a->bytes, b->bytes, SOL_HASH_SIZE) == 0;
}

SOL_INLINE int
sol_hash_cmp(const sol_hash_t* a, const sol_hash_t* b) {
    return memcmp(a->bytes, b->bytes, SOL_HASH_SIZE);
}

SOL_INLINE bool
sol_hash_is_zero(const sol_hash_t* h) {
    static const uchar zeros[SOL_HASH_SIZE] = {0};
    return memcmp(h->bytes, zeros, SOL_HASH_SIZE) == 0;
}

SOL_INLINE void
sol_hash_copy(sol_hash_t* dst, const sol_hash_t* src) {
    memcpy(dst->bytes, src->bytes, SOL_HASH_SIZE);
}

/*
 * Ed25519 signature (64 bytes)
 */
typedef struct {
    uchar bytes[SOL_SIGNATURE_SIZE];
} sol_signature_t;

SOL_STATIC_ASSERT(sizeof(sol_signature_t) == 64, "sol_signature_t must be 64 bytes");

SOL_INLINE bool
sol_signature_eq(const sol_signature_t* a, const sol_signature_t* b) {
    return memcmp(a->bytes, b->bytes, SOL_SIGNATURE_SIZE) == 0;
}

SOL_INLINE bool
sol_signature_is_zero(const sol_signature_t* sig) {
    static const uchar zeros[SOL_SIGNATURE_SIZE] = {0};
    return memcmp(sig->bytes, zeros, SOL_SIGNATURE_SIZE) == 0;
}

/*
 * Ed25519 keypair (64 bytes = 32 private + 32 public)
 */
typedef struct {
    uchar bytes[SOL_KEYPAIR_SIZE];
} sol_keypair_t;

SOL_STATIC_ASSERT(sizeof(sol_keypair_t) == 64, "sol_keypair_t must be 64 bytes");

/* Extract public key from keypair (copies to avoid alignment issues) */
SOL_INLINE void
sol_keypair_pubkey(const sol_keypair_t* kp, sol_pubkey_t* out) {
    memcpy(out->bytes, kp->bytes + SOL_PRIVKEY_SIZE, SOL_PUBKEY_SIZE);
}

/*
 * Slot number
 */
typedef ulong sol_slot_t;
#define SOL_SLOT_MAX UINT64_MAX

/*
 * Epoch number
 */
typedef ulong sol_epoch_t;
#define SOL_EPOCH_MAX UINT64_MAX

/*
 * Lamports (smallest unit of SOL)
 */
typedef ulong sol_lamports_t;
#define SOL_LAMPORTS_MAX UINT64_MAX

/*
 * Unix timestamp (seconds since epoch)
 */
typedef slong sol_unix_timestamp_t;

/*
 * Block height
 */
typedef ulong sol_block_height_t;

/*
 * Shred index
 */
typedef uint sol_shred_index_t;

/*
 * Account metadata (stored alongside data)
 */
typedef struct {
    sol_lamports_t  lamports;      /* Balance in lamports */
    ulong           data_len;      /* Length of account data */
    sol_pubkey_t    owner;         /* Program that owns this account */
    sol_epoch_t     rent_epoch;    /* Epoch at which rent is due */
    bool            executable;    /* Can this account's data be executed? */
} sol_account_meta_t;

/*
 * Account with data pointer
 */
typedef struct {
    sol_account_meta_t  meta;
    uchar*              data;       /* Account data (may be NULL if data_len == 0) */
} sol_account_t;

/*
 * Byte slice (non-owning view)
 */
typedef struct {
    const uchar*  ptr;
    ulong         len;
} sol_slice_t;

SOL_INLINE sol_slice_t
sol_slice_new(const void* ptr, ulong len) {
    return (sol_slice_t){ .ptr = (const uchar*)ptr, .len = len };
}

SOL_INLINE bool
sol_slice_eq(sol_slice_t a, sol_slice_t b) {
    if (a.len != b.len) return false;
    return memcmp(a.ptr, b.ptr, a.len) == 0;
}

/*
 * Mutable byte slice
 */
typedef struct {
    uchar*  ptr;
    ulong   len;
} sol_slice_mut_t;

SOL_INLINE sol_slice_mut_t
sol_slice_mut_new(void* ptr, ulong len) {
    return (sol_slice_mut_t){ .ptr = (uchar*)ptr, .len = len };
}

/*
 * Optional types (C doesn't have std::optional)
 */
typedef struct {
    sol_slot_t value;
    bool       has_value;
} sol_opt_slot_t;

typedef struct {
    sol_pubkey_t value;
    bool         has_value;
} sol_opt_pubkey_t;

typedef struct {
    sol_hash_t value;
    bool       has_value;
} sol_opt_hash_t;

#define SOL_OPT_SOME(T, v) ((sol_opt_##T##_t){ .value = (v), .has_value = true })
#define SOL_OPT_NONE(T)    ((sol_opt_##T##_t){ .has_value = false })

/*
 * Range type
 */
typedef struct {
    ulong start;
    ulong end;  /* exclusive */
} sol_range_t;

SOL_INLINE ulong
sol_range_len(sol_range_t r) {
    return r.end > r.start ? r.end - r.start : 0;
}

SOL_INLINE bool
sol_range_contains(sol_range_t r, ulong val) {
    return val >= r.start && val < r.end;
}

/*
 * Epoch schedule
 */
typedef struct {
    ulong  slots_per_epoch;
    ulong  leader_schedule_slot_offset;
    bool   warmup;
    ulong  first_normal_epoch;
    ulong  first_normal_slot;
} sol_epoch_schedule_t;

/*
 * Rent parameters
 */
typedef struct {
    ulong  lamports_per_byte_year;
    double exemption_threshold;
    uchar  burn_percent;
} sol_rent_t;

/*
 * Fee rate governor
 */
typedef struct {
    ulong  target_lamports_per_signature;
    ulong  target_signatures_per_slot;
    ulong  min_lamports_per_signature;
    ulong  max_lamports_per_signature;
    uchar  burn_percent;
} sol_fee_rate_governor_t;

/*
 * Clock sysvar
 */
typedef struct {
    sol_slot_t           slot;
    sol_epoch_t          epoch;
    sol_unix_timestamp_t unix_timestamp;
    ulong                epoch_start_timestamp;
    ulong                leader_schedule_epoch;
} sol_clock_t;

/*
 * Helper to calculate epoch from slot
 */
SOL_INLINE sol_epoch_t
sol_slot_to_epoch(const sol_epoch_schedule_t* schedule, sol_slot_t slot) {
    if (slot < schedule->first_normal_slot) {
        /* Warmup period - epochs are variable length */
        /* Simplified: assume linear for now */
        return slot / (schedule->slots_per_epoch / 32);
    }
    return schedule->first_normal_epoch +
           (slot - schedule->first_normal_slot) / schedule->slots_per_epoch;
}

/*
 * Helper to calculate first slot of epoch
 */
SOL_INLINE sol_slot_t
sol_epoch_first_slot(const sol_epoch_schedule_t* schedule, sol_epoch_t epoch) {
    if (epoch <= schedule->first_normal_epoch) {
        /* Warmup period */
        return 0;  /* Simplified */
    }
    return schedule->first_normal_slot +
           (epoch - schedule->first_normal_epoch) * schedule->slots_per_epoch;
}

#endif /* SOL_TYPES_H */
