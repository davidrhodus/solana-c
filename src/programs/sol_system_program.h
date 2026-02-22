/*
 * sol_system_program.h - System Program Implementation
 *
 * The System Program is responsible for:
 * - Creating new accounts
 * - Assigning account ownership
 * - Transferring lamports between accounts
 * - Allocating account data space
 * - Managing nonce accounts
 */

#ifndef SOL_SYSTEM_PROGRAM_H
#define SOL_SYSTEM_PROGRAM_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../util/sol_alloc.h"
#include "../txn/sol_pubkey.h"
#include "../runtime/sol_bank.h"
#include "../runtime/sol_compute_budget.h"

/*
 * System Program ID (all zeros)
 */
extern const sol_pubkey_t SOL_SYSTEM_PROGRAM_ID;

/*
 * System instruction types
 */
typedef enum {
    SOL_SYSTEM_INSTR_CREATE_ACCOUNT = 0,
    SOL_SYSTEM_INSTR_ASSIGN = 1,
    SOL_SYSTEM_INSTR_TRANSFER = 2,
    SOL_SYSTEM_INSTR_CREATE_ACCOUNT_WITH_SEED = 3,
    SOL_SYSTEM_INSTR_ADVANCE_NONCE = 4,
    SOL_SYSTEM_INSTR_WITHDRAW_NONCE = 5,
    SOL_SYSTEM_INSTR_INITIALIZE_NONCE = 6,
    SOL_SYSTEM_INSTR_AUTHORIZE_NONCE = 7,
    SOL_SYSTEM_INSTR_ALLOCATE = 8,
    SOL_SYSTEM_INSTR_ALLOCATE_WITH_SEED = 9,
    SOL_SYSTEM_INSTR_ASSIGN_WITH_SEED = 10,
    SOL_SYSTEM_INSTR_TRANSFER_WITH_SEED = 11,
    SOL_SYSTEM_INSTR_UPGRADE_NONCE = 12,
} sol_system_instr_type_t;

/*
 * CreateAccount instruction data
 */
typedef struct {
    uint64_t        lamports;       /* Lamports to transfer to new account */
    uint64_t        space;          /* Data space to allocate */
    sol_pubkey_t    owner;          /* Program owner of new account */
} sol_system_create_account_t;

/*
 * Assign instruction data
 */
typedef struct {
    sol_pubkey_t    owner;          /* New owner program */
} sol_system_assign_t;

/*
 * Transfer instruction data
 */
typedef struct {
    uint64_t        lamports;       /* Lamports to transfer */
} sol_system_transfer_t;

/*
 * Allocate instruction data
 */
typedef struct {
    uint64_t        space;          /* Data space to allocate */
} sol_system_allocate_t;

/*
 * Nonce account state
 */
typedef enum {
    SOL_NONCE_STATE_UNINITIALIZED = 0,
    SOL_NONCE_STATE_INITIALIZED = 1,
} sol_nonce_state_t;

/*
 * Nonce account data
 */
typedef struct {
    uint32_t        version;        /* Nonce version (currently 1) */
    uint32_t        state;          /* sol_nonce_state_t */
    sol_pubkey_t    authority;      /* Authority that can advance nonce */
    sol_hash_t      blockhash;      /* Current nonce value (blockhash) */
    uint64_t        lamports_per_signature; /* Fee at time of nonce */
} sol_nonce_data_t;

#define SOL_NONCE_DATA_SIZE 80

/*
 * Maximum return data size
 */
#define SOL_MAX_RETURN_DATA 1024

/*
 * Instruction trace - records every instruction executed in a transaction.
 * Used by sol_get_processed_sibling_instruction syscall.
 * Shared across all CPI levels via pointer.
 */
#define SOL_MAX_INSTRUCTION_TRACE 256

typedef struct {
    uint8_t         stack_height;       /* 1-based stack depth */
    sol_pubkey_t    program_id;
    uint8_t*        data;              /* instruction data (heap copy) */
    uint16_t        data_len;
    sol_pubkey_t*   account_keys;      /* array of account pubkeys */
    bool*           account_is_signer;
    bool*           account_is_writable;
    uint16_t        accounts_len;
} sol_instruction_trace_entry_t;

typedef struct {
    sol_instruction_trace_entry_t entries[SOL_MAX_INSTRUCTION_TRACE];
    size_t count;
} sol_instruction_trace_t;

/* Push an instruction entry to the trace. Copies data and account info. */
static inline void
sol_instruction_trace_push(
    sol_instruction_trace_t* trace,
    uint8_t stack_height,
    const sol_pubkey_t* program_id,
    const uint8_t* data,
    uint16_t data_len,
    const sol_pubkey_t* account_keys,
    const bool* is_signer,
    const bool* is_writable,
    uint8_t accounts_len
) {
    if (!trace || trace->count >= SOL_MAX_INSTRUCTION_TRACE) return;
    sol_instruction_trace_entry_t* e = &trace->entries[trace->count];
    e->stack_height = stack_height;
    e->program_id = *program_id;
    e->data = NULL;
    e->data_len = data_len;
    if (data_len > 0 && data) {
        e->data = (uint8_t*)sol_alloc(data_len);
        if (e->data) memcpy(e->data, data, data_len);
    }
    e->account_keys = NULL;
    e->account_is_signer = NULL;
    e->account_is_writable = NULL;
    e->accounts_len = accounts_len;
    if (accounts_len > 0) {
        e->account_keys = (sol_pubkey_t*)sol_alloc(accounts_len * sizeof(sol_pubkey_t));
        e->account_is_signer = (bool*)sol_alloc(accounts_len * sizeof(bool));
        e->account_is_writable = (bool*)sol_alloc(accounts_len * sizeof(bool));
        if (e->account_keys && account_keys)
            memcpy(e->account_keys, account_keys, accounts_len * sizeof(sol_pubkey_t));
        if (e->account_is_signer && is_signer)
            memcpy(e->account_is_signer, is_signer, accounts_len * sizeof(bool));
        if (e->account_is_writable && is_writable)
            memcpy(e->account_is_writable, is_writable, accounts_len * sizeof(bool));
    }
    trace->count++;
}

/* Free all trace entries */
static inline void
sol_instruction_trace_destroy(sol_instruction_trace_t* trace) {
    if (!trace) return;
    for (size_t i = 0; i < trace->count; i++) {
        sol_instruction_trace_entry_t* e = &trace->entries[i];
        if (e->data) sol_free(e->data);
        if (e->account_keys) sol_free(e->account_keys);
        if (e->account_is_signer) sol_free(e->account_is_signer);
        if (e->account_is_writable) sol_free(e->account_is_writable);
    }
    trace->count = 0;
}

/*
 * Instruction execution context
 */
typedef struct {
    sol_bank_t*             bank;
    const sol_pubkey_t*     account_keys;
    uint8_t                 account_keys_len;
    /* Per-account-key flags (length == account_keys_len) */
    const bool*             is_writable;
    const bool*             is_signer;
    const uint8_t*          account_indices;
    uint8_t                 account_indices_len;
    const uint8_t*          instruction_data;
    uint16_t                instruction_data_len;
    sol_pubkey_t            program_id;
    /* Transaction signature (optional; top-level signature[0]) */
    const sol_signature_t*  tx_signature;
    /* Sysvar snapshots */
    sol_clock_t             clock;
    sol_rent_t              rent;
    sol_epoch_schedule_t    epoch_schedule;
    uint64_t                lamports_per_signature; /* Fees sysvar (deprecated) */
    /* Signer information */
    uint8_t                 num_signers;    /* Number of signers from message header */
    /* CPI stack height (1 for top-level, increments per CPI) */
    uint64_t                stack_height;
    /* Transaction compute budget/meter (optional) */
    const sol_compute_budget_t* compute_budget;
    sol_compute_meter_t*        compute_meter;
    uint64_t                    compute_units_accounted;
    /* Return data from program */
    uint8_t                 return_data[SOL_MAX_RETURN_DATA];
    uint16_t                return_data_len;
    sol_pubkey_t            return_data_program;
    /* Transaction context for sol_get_processed_sibling_instruction */
    const sol_transaction_t* transaction;
    uint8_t                 current_instruction_index;
    /* Instruction trace (shared across CPI levels) */
    sol_instruction_trace_t* instruction_trace;
} sol_invoke_context_t;

/*
 * Process a system program instruction
 *
 * @param ctx       Execution context
 * @return          SOL_OK on success, error code otherwise
 */
sol_err_t sol_system_program_execute(sol_invoke_context_t* ctx);

/*
 * Create a CreateAccount instruction
 */
sol_err_t sol_system_create_account_instruction(
    const sol_pubkey_t*     from,
    const sol_pubkey_t*     to,
    uint64_t                lamports,
    uint64_t                space,
    const sol_pubkey_t*     owner,
    uint8_t*                out_data,
    size_t*                 out_len
);

/*
 * Create a Transfer instruction
 */
sol_err_t sol_system_transfer_instruction(
    const sol_pubkey_t*     from,
    const sol_pubkey_t*     to,
    uint64_t                lamports,
    uint8_t*                out_data,
    size_t*                 out_len
);

/*
 * Create an Assign instruction
 */
sol_err_t sol_system_assign_instruction(
    const sol_pubkey_t*     account,
    const sol_pubkey_t*     owner,
    uint8_t*                out_data,
    size_t*                 out_len
);

/*
 * Create an Allocate instruction
 */
sol_err_t sol_system_allocate_instruction(
    const sol_pubkey_t*     account,
    uint64_t                space,
    uint8_t*                out_data,
    size_t*                 out_len
);

/*
 * Derive program address with seed
 */
sol_err_t sol_create_with_seed(
    const sol_pubkey_t*     base,
    const char*             seed,
    size_t                  seed_len,
    const sol_pubkey_t*     program_id,
    sol_pubkey_t*           out_address
);

#endif /* SOL_SYSTEM_PROGRAM_H */
