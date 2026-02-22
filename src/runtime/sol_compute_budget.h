/*
 * sol_compute_budget.h - Compute Budget and Cost Model
 *
 * The compute budget limits how much computation a transaction can perform.
 * Programs consume compute units (CUs) as they execute, and transactions
 * fail if they exceed their budget.
 *
 * The cost model estimates transaction costs before execution for scheduling.
 */

#ifndef SOL_COMPUTE_BUDGET_H
#define SOL_COMPUTE_BUDGET_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../txn/sol_transaction.h"
#include <stdbool.h>

/*
 * Default compute unit limits
 */
#define SOL_DEFAULT_INSTRUCTION_COMPUTE_UNITS  200000
#define SOL_MAX_BUILTIN_COMPUTE_UNITS           3000
#define SOL_DEFAULT_COMPUTE_UNITS             200000
#define SOL_MAX_COMPUTE_UNITS                1400000
#define SOL_DEFAULT_HEAP_BYTES             (32 * 1024)
#define SOL_MAX_HEAP_BYTES                (256 * 1024)
#define SOL_DEFAULT_LOADED_ACCOUNTS_BYTES  (64 * 1024 * 1024)

/*
 * Compute unit costs for various operations
 */
/*
 * Hash syscalls (SHA256, Keccak256, BLAKE3) all use the same constants.
 * Per-slice cost: max(MEM_OP_BASE, HASH_BYTE_COST * slice_len / 2)
 * where HASH_BYTE_COST=1 (integer division).
 */
#define SOL_CU_HASH_BASE                     85
#define SOL_CU_HASH_BYTE_COST                 1
#define SOL_CU_HASH_MAX_SLICES            20000
/* Legacy aliases */
#define SOL_CU_SHA256_BASE          SOL_CU_HASH_BASE
#define SOL_CU_SHA256_BYTE          SOL_CU_HASH_BYTE_COST
#define SOL_CU_KECCAK256_BASE      SOL_CU_HASH_BASE
#define SOL_CU_KECCAK256_BYTE      SOL_CU_HASH_BYTE_COST
#define SOL_CU_SECP256K1_RECOVER          25000
#define SOL_CU_ED25519_VERIFY               600
/*
 * Memory operations: cost = max(MEM_OP_BASE, len / CPI_BYTES_PER_UNIT)
 * NOT base + len * per_byte!
 */
#define SOL_CU_MEM_OP_BASE                   10
#define SOL_CU_CPI_BYTES_PER_UNIT           250
#define SOL_CU_MEM_OP_BYTE                    1  /* deprecated: not used by Agave */
#define SOL_CU_CPI_BASE                    1000
/*
 * Logging: cost = max(SYSCALL_BASE, msg_len)
 * NOT base + len * per_byte!
 */
#define SOL_CU_LOG_BASE                      100
#define SOL_CU_LOG_BYTE                        1  /* deprecated: not used by Agave */
#define SOL_CU_SYSCALL_BASE                  100
#define SOL_CU_CREATE_PROGRAM_ADDRESS       1500
#define SOL_CU_INVOKE_UNITS                 1000
#define SOL_CU_SYSVAR_BASE                   100

/*
 * Per-signature and per-account costs
 */
#define SOL_CU_PER_SIGNATURE                 720
#define SOL_CU_PER_WRITABLE_ACCOUNT          300
#define SOL_CU_PER_ACCOUNT                    50

/*
 * Compute budget instruction types
 * These are parsed from ComputeBudget program instructions
 */
typedef enum {
    SOL_COMPUTE_BUDGET_REQUEST_HEAP_FRAME,
    SOL_COMPUTE_BUDGET_SET_COMPUTE_UNIT_LIMIT,
    SOL_COMPUTE_BUDGET_SET_COMPUTE_UNIT_PRICE,
    SOL_COMPUTE_BUDGET_SET_LOADED_ACCOUNTS_DATA_SIZE_LIMIT,
} sol_compute_budget_instruction_t;

/*
 * Compute budget for a transaction
 */
typedef struct {
    uint32_t    compute_unit_limit;         /* Max CUs for this transaction */
    uint64_t    compute_unit_price;         /* Price per CU in micro-lamports */
    uint32_t    heap_size;                  /* Heap size in bytes */
    uint32_t    loaded_accounts_data_size;  /* Max loaded account data */
    bool        uses_request_heap_frame;    /* Uses deprecated heap frame ix */
} sol_compute_budget_t;

/*
 * Default compute budget
 */
#define SOL_COMPUTE_BUDGET_DEFAULT {                    \
    .compute_unit_limit = SOL_DEFAULT_COMPUTE_UNITS,    \
    .compute_unit_price = 0,                            \
    .heap_size = SOL_DEFAULT_HEAP_BYTES,                \
    .loaded_accounts_data_size = SOL_DEFAULT_LOADED_ACCOUNTS_BYTES, \
    .uses_request_heap_frame = false,                   \
}

/*
 * Compute meter - tracks CU consumption during execution
 */
typedef struct {
    uint64_t    remaining;      /* CUs remaining */
    uint64_t    consumed;       /* CUs consumed so far */
    uint64_t    limit;          /* Original limit */
} sol_compute_meter_t;

/*
 * Initialize compute budget with defaults
 */
void sol_compute_budget_init(sol_compute_budget_t* budget);

/*
 * Parse compute budget instructions from transaction
 * Updates budget based on ComputeBudget program instructions.
 */
sol_err_t sol_compute_budget_parse(
    sol_compute_budget_t* budget,
    const sol_transaction_t* tx
);

/*
 * Calculate prioritization fee for a transaction
 * Fee = compute_unit_limit * compute_unit_price / 1_000_000
 */
uint64_t sol_compute_budget_priority_fee(const sol_compute_budget_t* budget);

/*
 * Initialize compute meter
 */
void sol_compute_meter_init(sol_compute_meter_t* meter, uint64_t limit);

/*
 * Consume compute units
 * Returns SOL_ERR_COMPUTE if budget exceeded.
 */
sol_err_t sol_compute_meter_consume(sol_compute_meter_t* meter, uint64_t units);

/*
 * Check if enough CUs remain (without consuming)
 */
bool sol_compute_meter_check(const sol_compute_meter_t* meter, uint64_t units);

/*
 * Get remaining CUs
 */
uint64_t sol_compute_meter_remaining(const sol_compute_meter_t* meter);

/*
 * Transaction cost model
 */
typedef struct {
    uint64_t    signature_cost;         /* Cost for signature verification */
    uint64_t    write_lock_cost;        /* Cost for write locks */
    uint64_t    data_bytes_cost;        /* Cost for instruction data */
    uint64_t    builtins_cost;          /* Cost for builtin programs */
    uint64_t    compute_unit_limit;     /* Requested CU limit */
    uint64_t    loaded_accounts_cost;   /* Cost for loading accounts */
    uint64_t    total_cost;             /* Total cost */
    bool        is_simple_vote;         /* Is this a simple vote tx? */
} sol_tx_cost_t;

/*
 * Cost model configuration
 */
typedef struct {
    uint64_t    signature_cost;         /* CUs per signature */
    uint64_t    write_lock_cost;        /* CUs per write lock */
    uint64_t    data_byte_cost;         /* CUs per instruction data byte */
    uint64_t    account_data_cost;      /* CUs per loaded account byte */
    uint64_t    max_block_units;        /* Max CUs per block */
    uint64_t    max_vote_units;         /* Max CUs for vote txs per block */
    uint64_t    max_writable_accounts;  /* Max writable accounts per block */
    uint64_t    max_account_data_bytes; /* Max loaded account data per block */
} sol_cost_model_config_t;

#define SOL_COST_MODEL_CONFIG_DEFAULT {         \
    .signature_cost = SOL_CU_PER_SIGNATURE,     \
    .write_lock_cost = SOL_CU_PER_WRITABLE_ACCOUNT, \
    .data_byte_cost = 1,                        \
    .account_data_cost = 1,                     \
    .max_block_units = 48000000,                \
    .max_vote_units = 36000000,                 \
    .max_writable_accounts = 12000000,          \
    .max_account_data_bytes = 64000000000UL,    \
}

/*
 * Cost model state (for tracking block limits)
 */
typedef struct {
    sol_cost_model_config_t config;
    uint64_t    block_cost;             /* Current block CU usage */
    uint64_t    vote_cost;              /* Current vote CU usage */
    uint64_t    writable_accounts;      /* Current writable account usage */
    uint64_t    account_data_bytes;     /* Current account data usage */
} sol_cost_model_t;

/*
 * Initialize cost model
 */
void sol_cost_model_init(sol_cost_model_t* model, const sol_cost_model_config_t* config);

/*
 * Calculate cost of a transaction
 */
sol_err_t sol_cost_model_calculate(
    const sol_cost_model_t* model,
    const sol_transaction_t* tx,
    const sol_compute_budget_t* budget,
    sol_tx_cost_t* out_cost
);

/*
 * Check if transaction fits in block limits
 */
bool sol_cost_model_would_fit(
    const sol_cost_model_t* model,
    const sol_tx_cost_t* cost
);

/*
 * Add transaction cost to block
 */
sol_err_t sol_cost_model_add(
    sol_cost_model_t* model,
    const sol_tx_cost_t* cost
);

/*
 * Remove transaction cost from block (for rollback)
 */
void sol_cost_model_remove(
    sol_cost_model_t* model,
    const sol_tx_cost_t* cost
);

/*
 * Reset cost model for new block
 */
void sol_cost_model_reset(sol_cost_model_t* model);

/*
 * Get block utilization stats
 */
typedef struct {
    double      block_utilization;      /* Block CU utilization (0-1) */
    double      vote_utilization;       /* Vote CU utilization (0-1) */
    double      accounts_utilization;   /* Writable accounts utilization (0-1) */
    double      data_utilization;       /* Account data utilization (0-1) */
} sol_cost_model_stats_t;

void sol_cost_model_stats(
    const sol_cost_model_t* model,
    sol_cost_model_stats_t* out_stats
);

#endif /* SOL_COMPUTE_BUDGET_H */
