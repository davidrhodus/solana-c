/*
 * sol_token_program.h - SPL Token Program Implementation
 *
 * The Token Program manages fungible tokens on Solana:
 * - Creating token mints
 * - Creating token accounts
 * - Transferring tokens
 * - Minting and burning tokens
 * - Approving delegates
 */

#ifndef SOL_TOKEN_PROGRAM_H
#define SOL_TOKEN_PROGRAM_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../txn/sol_pubkey.h"
#include "sol_system_program.h"

/*
 * Token Program ID
 * TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
 */
extern const sol_pubkey_t SOL_TOKEN_PROGRAM_ID;

/*
 * Associated Token Account Program ID
 * ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL
 */
extern const sol_pubkey_t SOL_ASSOCIATED_TOKEN_PROGRAM_ID;

/*
 * Token instruction types
 */
typedef enum {
    SOL_TOKEN_INSTR_INITIALIZE_MINT = 0,
    SOL_TOKEN_INSTR_INITIALIZE_ACCOUNT = 1,
    SOL_TOKEN_INSTR_INITIALIZE_MULTISIG = 2,
    SOL_TOKEN_INSTR_TRANSFER = 3,
    SOL_TOKEN_INSTR_APPROVE = 4,
    SOL_TOKEN_INSTR_REVOKE = 5,
    SOL_TOKEN_INSTR_SET_AUTHORITY = 6,
    SOL_TOKEN_INSTR_MINT_TO = 7,
    SOL_TOKEN_INSTR_BURN = 8,
    SOL_TOKEN_INSTR_CLOSE_ACCOUNT = 9,
    SOL_TOKEN_INSTR_FREEZE_ACCOUNT = 10,
    SOL_TOKEN_INSTR_THAW_ACCOUNT = 11,
    SOL_TOKEN_INSTR_TRANSFER_CHECKED = 12,
    SOL_TOKEN_INSTR_APPROVE_CHECKED = 13,
    SOL_TOKEN_INSTR_MINT_TO_CHECKED = 14,
    SOL_TOKEN_INSTR_BURN_CHECKED = 15,
    SOL_TOKEN_INSTR_INITIALIZE_ACCOUNT2 = 16,
    SOL_TOKEN_INSTR_SYNC_NATIVE = 17,
    SOL_TOKEN_INSTR_INITIALIZE_ACCOUNT3 = 18,
    SOL_TOKEN_INSTR_INITIALIZE_MULTISIG2 = 19,
    SOL_TOKEN_INSTR_INITIALIZE_MINT2 = 20,
    SOL_TOKEN_INSTR_GET_ACCOUNT_DATA_SIZE = 21,
    SOL_TOKEN_INSTR_INITIALIZE_IMMUTABLE_OWNER = 22,
    SOL_TOKEN_INSTR_AMOUNT_TO_UI_AMOUNT = 23,
    SOL_TOKEN_INSTR_UI_AMOUNT_TO_AMOUNT = 24,
} sol_token_instr_type_t;

/*
 * Authority types for SetAuthority
 */
typedef enum {
    SOL_TOKEN_AUTH_MINT_TOKENS = 0,
    SOL_TOKEN_AUTH_FREEZE_ACCOUNT = 1,
    SOL_TOKEN_AUTH_ACCOUNT_OWNER = 2,
    SOL_TOKEN_AUTH_CLOSE_ACCOUNT = 3,
} sol_token_authority_type_t;

/*
 * Account state
 */
typedef enum {
    SOL_TOKEN_ACCOUNT_STATE_UNINITIALIZED = 0,
    SOL_TOKEN_ACCOUNT_STATE_INITIALIZED = 1,
    SOL_TOKEN_ACCOUNT_STATE_FROZEN = 2,
} sol_token_account_state_t;

/*
 * Mint state (82 bytes)
 */
typedef struct __attribute__((packed)) {
    uint32_t    mint_authority_option;  /* 0 = None, 1 = Some */
    sol_pubkey_t mint_authority;        /* Optional mint authority */
    uint64_t    supply;                 /* Current token supply */
    uint8_t     decimals;               /* Decimal places */
    bool        is_initialized;         /* Whether mint is initialized */
    uint32_t    freeze_authority_option; /* 0 = None, 1 = Some */
    sol_pubkey_t freeze_authority;      /* Optional freeze authority */
} sol_token_mint_t;

#define SOL_TOKEN_MINT_SIZE 82

/*
 * Token account state (165 bytes)
 */
typedef struct __attribute__((packed)) {
    sol_pubkey_t mint;                  /* The mint for this account */
    sol_pubkey_t owner;                 /* Owner of this account */
    uint64_t    amount;                 /* Token balance */
    uint32_t    delegate_option;        /* 0 = None, 1 = Some */
    sol_pubkey_t delegate;              /* Optional delegate */
    uint8_t     state;                  /* sol_token_account_state_t */
    uint32_t    is_native_option;       /* 0 = None, 1 = Some (wrapped SOL) */
    uint64_t    is_native;              /* Amount of wrapped SOL */
    uint64_t    delegated_amount;       /* Amount delegated */
    uint32_t    close_authority_option; /* 0 = None, 1 = Some */
    sol_pubkey_t close_authority;       /* Optional close authority */
} sol_token_account_t;

#define SOL_TOKEN_ACCOUNT_SIZE 165

/*
 * Multisig state (355 bytes max)
 */
typedef struct __attribute__((packed)) {
    uint8_t     m;                      /* Required signers */
    uint8_t     n;                      /* Total signers */
    bool        is_initialized;         /* Whether multisig is initialized */
    sol_pubkey_t signers[11];           /* Up to 11 signers */
} sol_token_multisig_t;

#define SOL_TOKEN_MULTISIG_SIZE 355

/*
 * Native SOL mint address (So11111111111111111111111111111111111111112)
 */
extern const sol_pubkey_t SOL_NATIVE_MINT;

/*
 * Process a token program instruction
 *
 * @param ctx       Execution context
 * @return          SOL_OK on success, error code otherwise
 */
sol_err_t sol_token_program_execute(sol_invoke_context_t* ctx);

/*
 * Unpack mint from account data
 */
sol_err_t sol_token_unpack_mint(
    const uint8_t*      data,
    size_t              len,
    sol_token_mint_t*   out_mint
);

/*
 * Pack mint to account data
 */
size_t sol_token_pack_mint(
    const sol_token_mint_t* mint,
    uint8_t*                out_data,
    size_t                  max_len
);

/*
 * Unpack token account from account data
 */
sol_err_t sol_token_unpack_account(
    const uint8_t*          data,
    size_t                  len,
    sol_token_account_t*    out_account
);

/*
 * Pack token account to account data
 */
size_t sol_token_pack_account(
    const sol_token_account_t*  account,
    uint8_t*                    out_data,
    size_t                      max_len
);

/*
 * Get associated token address for a wallet and mint
 */
sol_err_t sol_get_associated_token_address(
    const sol_pubkey_t*     wallet,
    const sol_pubkey_t*     mint,
    const sol_pubkey_t*     token_program_id,
    sol_pubkey_t*           out_address
);

/*
 * Associated Token Account program entry point
 *
 * Handles:
 * - Create (0): Creates ATA, fails if exists
 * - CreateIdempotent (1): Creates ATA, succeeds if exists
 * - RecoverNested (2): Recovers tokens from nested ATA
 */
sol_err_t sol_associated_token_program_execute(sol_invoke_context_t* ctx);

#endif /* SOL_TOKEN_PROGRAM_H */
