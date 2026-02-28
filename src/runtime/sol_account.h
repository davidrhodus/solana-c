/*
 * sol_account.h - Account Operations
 *
 * Helper functions for working with sol_account_t from sol_types.h
 */

#ifndef SOL_ACCOUNT_OPS_H
#define SOL_ACCOUNT_OPS_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../txn/sol_pubkey.h"

/*
 * Account constants
 */
#define SOL_ACCOUNT_MAX_DATA_SIZE       (10 * 1024 * 1024)  /* 10 MB max */

/*
 * System program ID (all zeros)
 */
extern const sol_pubkey_t SOL_SYSTEM_PROGRAM_ID;

/*
 * Native loader program ID
 */
extern const sol_pubkey_t SOL_NATIVE_LOADER_ID;

/*
 * BPF loader program ID
 */
extern const sol_pubkey_t SOL_BPF_LOADER_ID;

/*
 * Initialize account to default values
 */
void sol_account_init(sol_account_t* account);

/*
 * Allocate a zeroed account object.
 *
 * Hot path note: accounts are loaded/destroyed extremely frequently during
 * replay. The implementation may use a thread-local slab allocator to avoid
 * malloc/free overhead.
 */
sol_account_t* sol_account_alloc(void);

/*
 * Create a new account with specified parameters
 */
sol_account_t* sol_account_new(
    uint64_t            lamports,
    size_t              data_len,
    const sol_pubkey_t* owner
);

/*
 * Clone an account (deep copy)
 */
sol_account_t* sol_account_clone(const sol_account_t* account);

/*
 * Destroy account and free memory
 */
void sol_account_destroy(sol_account_t* account);

/*
 * Cleanup account (for stack-allocated accounts)
 */
void sol_account_cleanup(sol_account_t* account);

/*
 * Resize account data
 */
sol_err_t sol_account_resize(sol_account_t* account, size_t new_len);

/*
 * Set account data
 */
sol_err_t sol_account_set_data(
    sol_account_t*  account,
    const uint8_t*  data,
    size_t          len
);

/*
 * Check if account is the system program
 */
static inline bool
sol_account_is_system_program(const sol_pubkey_t* pubkey) {
    return sol_pubkey_eq(pubkey, &SOL_SYSTEM_PROGRAM_ID);
}

/*
 * Check if account is a native program
 */
bool sol_account_is_native_program(const sol_pubkey_t* pubkey);

/*
 * Check if account is rent exempt
 */
bool sol_account_is_rent_exempt(
    const sol_account_t*    account,
    uint64_t                rent_per_byte_year,
    uint64_t                exemption_threshold
);

/*
 * Calculate minimum balance for rent exemption
 */
uint64_t sol_account_rent_exempt_minimum(
    size_t      data_len,
    uint64_t    rent_per_byte_year,
    uint64_t    exemption_threshold
);

/*
 * Serialize account for storage
 */
sol_err_t sol_account_serialize(
    const sol_account_t*    account,
    uint8_t*                buf,
    size_t                  buf_len,
    size_t*                 bytes_written
);

/*
 * Deserialize account from storage
 */
sol_err_t sol_account_deserialize(
    sol_account_t*      account,
    const uint8_t*      data,
    size_t              len,
    size_t*             bytes_consumed
);

/*
 * Compute account hash (for merkle tree)
 */
void sol_account_hash(
    const sol_pubkey_t*     pubkey,
    const sol_account_t*    account,
    sol_hash_t*             out_hash
);

#endif /* SOL_ACCOUNT_OPS_H */
