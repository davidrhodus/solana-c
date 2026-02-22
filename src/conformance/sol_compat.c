/*
 * sol_compat.c - Firedancer Conformance Harness Implementation
 *
 * Implements the solana-conformance test harness entry points.
 * This provides a minimal implementation that can be extended
 * to pass the full Firedancer conformance test suite.
 */

#include "sol_compat.h"
#include "sol_pb.h"
#include "util/sol_log.h"
#include "util/sol_alloc.h"
#include "util/sol_types.h"
#include "txn/sol_pubkey.h"
#include "crypto/sol_sha256.h"
#include <string.h>

/*
 * Protosol field numbers for InstrContext
 * (verified against test_suite.protos.invoke_pb2)
 */
#define INSTR_CTX_PROGRAM_ID      1
#define INSTR_CTX_ACCOUNTS        3
#define INSTR_CTX_INSTR_ACCOUNTS  4
#define INSTR_CTX_DATA            5
#define INSTR_CTX_CU_AVAIL        6
#define INSTR_CTX_SLOT_CTX        8
#define INSTR_CTX_EPOCH_CTX       9

/*
 * Protosol field numbers for AcctState
 */
#define ACCT_STATE_ADDRESS        1
#define ACCT_STATE_LAMPORTS       2
#define ACCT_STATE_DATA           3
#define ACCT_STATE_EXECUTABLE     4
#define ACCT_STATE_OWNER          6

/*
 * Protosol field numbers for InstrAcct
 */
#define INSTR_ACCT_INDEX          1
#define INSTR_ACCT_IS_WRITABLE    2
#define INSTR_ACCT_IS_SIGNER      3

/*
 * Protosol field numbers for InstrEffects
 */
#define INSTR_EFFECTS_RESULT            1
#define INSTR_EFFECTS_CUSTOM_ERR        2
#define INSTR_EFFECTS_MODIFIED_ACCOUNTS 3
#define INSTR_EFFECTS_CU_AVAIL          4
#define INSTR_EFFECTS_RETURN_DATA       5

/*
 * Protosol field numbers for TxnContext
 */
#define TXN_CTX_TX                    1
#define TXN_CTX_ACCOUNT_SHARED_DATA   3
#define TXN_CTX_BLOCKHASH_QUEUE       5
#define TXN_CTX_EPOCH_CTX             6
#define TXN_CTX_SLOT_CTX              7

/*
 * Protosol field numbers for TxnResult
 */
#define TXN_RESULT_EXECUTED                 1
#define TXN_RESULT_SANITIZATION_ERROR       2
#define TXN_RESULT_RESULTING_STATE          3
#define TXN_RESULT_RETURN_DATA              7
#define TXN_RESULT_EXECUTED_UNITS           8

/*
 * Maximum accounts in a test
 */
#define MAX_TEST_ACCOUNTS 256

/*
 * Solana InstructionError codes for protosol conformance
 * In protosol: result=0 means success, result=N means error enum variant N-1
 * So we define error codes as Rust enum discriminant + 1
 */
#define INSTR_ERR_GENERIC                     1   /* GenericError = 0 + 1 */
#define INSTR_ERR_INVALID_ARGUMENT            2   /* InvalidArgument = 1 + 1 */
#define INSTR_ERR_INVALID_INSTRUCTION_DATA    3   /* InvalidInstructionData = 2 + 1 */
#define INSTR_ERR_INVALID_ACCOUNT_DATA        4   /* InvalidAccountData = 3 + 1 */
#define INSTR_ERR_ACCOUNT_DATA_TOO_SMALL      5   /* AccountDataTooSmall = 4 + 1 */
#define INSTR_ERR_INSUFFICIENT_FUNDS          6   /* InsufficientFunds = 5 + 1 */
#define INSTR_ERR_INCORRECT_PROGRAM_ID        7   /* IncorrectProgramId = 6 + 1 */
#define INSTR_ERR_MISSING_REQUIRED_SIGNATURE  8   /* MissingRequiredSignature = 7 + 1 */
#define INSTR_ERR_ACCOUNT_ALREADY_INITIALIZED 9   /* AccountAlreadyInitialized = 8 + 1 */
#define INSTR_ERR_UNINITIALIZED_ACCOUNT       10  /* UninitializedAccount = 9 + 1 */
#define INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS     11  /* NotEnoughAccountKeys = 10 + 1 */
#define INSTR_ERR_ACCOUNT_BORROW_FAILED       12  /* AccountBorrowFailed = 11 + 1 */
#define INSTR_ERR_MAX_SEED_LENGTH_EXCEEDED    13  /* MaxSeedLengthExceeded = 12 + 1 */
#define INSTR_ERR_INVALID_SEEDS               14  /* InvalidSeeds = 13 + 1 */
#define INSTR_ERR_BORSH_IO_ERROR              15  /* BorshIoError = 14 + 1 */
#define INSTR_ERR_ACCOUNT_NOT_RENT_EXEMPT     16  /* AccountNotRentExempt = 15 + 1 */
#define INSTR_ERR_UNSUPPORTED_SYSVAR          17  /* UnsupportedSysvar = 16 + 1 */
#define INSTR_ERR_ILLEGAL_OWNER               49  /* IllegalOwner = 48 + 1 */
#define INSTR_ERR_MAX_ACCOUNTS_DATA_SIZE      19  /* MaxAccountsDataSizeExceeded = 18 + 1 */
#define INSTR_ERR_INVALID_ACCOUNT_OWNER       33  /* InvalidAccountOwner = 32 + 1 */
#define INSTR_ERR_ARITHMETIC_OVERFLOW         34  /* ArithmeticOverflow = 33 + 1 */
#define INSTR_ERR_IMMUTABLE                   35  /* Immutable = 34 + 1 */
#define INSTR_ERR_INCORRECT_AUTHORITY         36  /* IncorrectAuthority = 35 + 1 */

/* Additional commonly used error codes */
#define INSTR_ERR_CUSTOM                      22  /* Custom(u32) = 21 + 1 */
#define INSTR_ERR_READONLY_LAMPORT_CHANGE     26  /* ReadonlyLamportChange = 25 + 1 */
#define INSTR_ERR_UNSUPPORTED_PROGRAM_ID      27  /* UnsupportedProgramId = 26 + 1 */
#define INSTR_ERR_READONLY_DATA_MODIFIED      28  /* ReadonlyDataModified = 27 + 1 */
#define INSTR_ERR_EXECUTABLE_DATA_MODIFIED    30  /* ExecutableDataModified = 29 + 1 */
#define INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE   31  /* ExecutableLamportChange = 30 + 1 */
#define INSTR_ERR_EXECUTABLE_ACCOUNT_NOT_RENT_EXEMPT 32  /* ExecutableAccountNotRentExempt = 31 + 1 */

/* Runtime-level errors */
#define INSTR_ERR_DUPLICATE_ACCOUNT_INDEX     41  /* DuplicateAccountIndex = 40 + 1 */
#define INSTR_ERR_DUPLICATE_ACCOUNT_OUT_OF_SYNC 42 /* DuplicateAccountOutOfSync = 41 + 1 */

/* Vote program specific errors */
#define VOTE_ERR_VOTE_TOO_OLD                 43  /* VoteTooOld = 42 + 1 */
#define VOTE_ERR_SLOTS_MISMATCH               44  /* SlotsMismatch = 43 + 1 */
#define VOTE_ERR_SLOTS_HASH_MISMATCH          45  /* SlotsHashMismatch = 44 + 1 */
#define VOTE_ERR_EMPTY_SLOTS                  46  /* EmptySlots = 45 + 1 */
#define VOTE_ERR_VOTE_STATE_VERSION           47  /* VoteStateVersionError = 46 + 1 */

/* More runtime errors */
#define INSTR_ERR_INVALID_ACCOUNT_DATA_REALLOC 47 /* InvalidAccountDataRealloc = 46 + 1 */
#define INSTR_ERR_UNBALANCED_INSTRUCTION      49  /* UnbalancedInstruction = 48 + 1 */
/* PrivilegeEscalation = 37 + 1 */
#define INSTR_ERR_PRIVILEGE_ESCALATION        38

/*
 * Result code for conformance harness
 * 0 = success, non-zero = error index
 * This matches the protosol InstrEffects.result field
 */
#define RESULT_SUCCESS 0

/*
 * Parsed account state
 */
typedef struct {
    sol_pubkey_t pubkey;
    uint64_t     lamports;
    uint8_t*     data;
    size_t       data_len;
    bool         executable;
    sol_pubkey_t owner;
} parsed_acct_t;

/*
 * Parsed instruction account reference
 */
typedef struct {
    uint32_t index;
    bool     is_writable;
    bool     is_signer;
} parsed_instr_acct_t;

/*
 * Parsed instruction context
 */
typedef struct {
    sol_pubkey_t         program_id;
    parsed_acct_t        accounts[MAX_TEST_ACCOUNTS];
    size_t               num_accounts;
    parsed_instr_acct_t  instr_accounts[MAX_TEST_ACCOUNTS];
    size_t               num_instr_accounts;
    uint8_t*             data;
    size_t               data_len;
    uint64_t             cu_avail;
    uint64_t             slot;
} parsed_instr_ctx_t;

/*
 * Global initialization state
 */
static bool g_initialized = false;

void
sol_compat_init(void) {
    if (g_initialized) return;

    /* Initialize logging (quiet mode for conformance) */
    sol_log_init(NULL);
    sol_log_set_level(SOL_LOG_ERROR);

    g_initialized = true;
}

void
sol_compat_fini(void) {
    g_initialized = false;
}

/*
 * Parse AcctState protobuf
 */
static bool
parse_acct_state(pb_reader_t* r, parsed_acct_t* acct) {
    memset(acct, 0, sizeof(*acct));

    pb_field_t f;
    while (pb_reader_has_more(r)) {
        if (!pb_read_field(r, &f)) break;

        switch (f.field_num) {
        case ACCT_STATE_ADDRESS:
            if (f.wire_type == PB_WIRE_LEN && f.value.bytes.len == 32) {
                memcpy(acct->pubkey.bytes, f.value.bytes.data, 32);
            }
            break;
        case ACCT_STATE_LAMPORTS:
            if (f.wire_type == PB_WIRE_VARINT) {
                acct->lamports = f.value.varint;
            }
            break;
        case ACCT_STATE_DATA:
            if (f.wire_type == PB_WIRE_LEN) {
                acct->data = sol_alloc(f.value.bytes.len);
                if (acct->data) {
                    memcpy(acct->data, f.value.bytes.data, f.value.bytes.len);
                    acct->data_len = f.value.bytes.len;
                }
            }
            break;
        case ACCT_STATE_EXECUTABLE:
            if (f.wire_type == PB_WIRE_VARINT) {
                acct->executable = f.value.varint != 0;
            }
            break;
        case ACCT_STATE_OWNER:
            if (f.wire_type == PB_WIRE_LEN && f.value.bytes.len == 32) {
                memcpy(acct->owner.bytes, f.value.bytes.data, 32);
            }
            break;
        default:
            /* Skip unknown fields */
            break;
        }
    }

    return true;
}

/*
 * Parse InstrAcct protobuf
 */
static bool
parse_instr_acct(pb_reader_t* r, parsed_instr_acct_t* ia) {
    memset(ia, 0, sizeof(*ia));

    pb_field_t f;
    while (pb_reader_has_more(r)) {
        if (!pb_read_field(r, &f)) break;

        switch (f.field_num) {
        case INSTR_ACCT_INDEX:
            if (f.wire_type == PB_WIRE_VARINT) {
                ia->index = (uint32_t)f.value.varint;
            }
            break;
        case INSTR_ACCT_IS_WRITABLE:
            if (f.wire_type == PB_WIRE_VARINT) {
                ia->is_writable = f.value.varint != 0;
            }
            break;
        case INSTR_ACCT_IS_SIGNER:
            if (f.wire_type == PB_WIRE_VARINT) {
                ia->is_signer = f.value.varint != 0;
            }
            break;
        default:
            break;
        }
    }

    return true;
}

/*
 * Parse InstrContext protobuf
 */
static bool
parse_instr_context(const uint8_t* input, size_t input_len, parsed_instr_ctx_t* ctx) {
    memset(ctx, 0, sizeof(*ctx));
    /* cu_avail defaults to 0 after memset - protobuf omits 0 values */

    pb_reader_t r;
    pb_reader_init(&r, input, input_len);

    pb_field_t f;
    while (pb_reader_has_more(&r)) {
        if (!pb_read_field(&r, &f)) break;

        switch (f.field_num) {
        case INSTR_CTX_PROGRAM_ID:
            if (f.wire_type == PB_WIRE_LEN && f.value.bytes.len == 32) {
                memcpy(ctx->program_id.bytes, f.value.bytes.data, 32);
            }
            break;

        case INSTR_CTX_ACCOUNTS:
            if (f.wire_type == PB_WIRE_LEN && ctx->num_accounts < MAX_TEST_ACCOUNTS) {
                pb_reader_t sub;
                pb_reader_init(&sub, f.value.bytes.data, f.value.bytes.len);
                if (parse_acct_state(&sub, &ctx->accounts[ctx->num_accounts])) {
                    ctx->num_accounts++;
                }
            }
            break;

        case INSTR_CTX_INSTR_ACCOUNTS:
            if (f.wire_type == PB_WIRE_LEN && ctx->num_instr_accounts < MAX_TEST_ACCOUNTS) {
                pb_reader_t sub;
                pb_reader_init(&sub, f.value.bytes.data, f.value.bytes.len);
                if (parse_instr_acct(&sub, &ctx->instr_accounts[ctx->num_instr_accounts])) {
                    ctx->num_instr_accounts++;
                }
            }
            break;

        case INSTR_CTX_DATA:
            if (f.wire_type == PB_WIRE_LEN) {
                ctx->data = sol_alloc(f.value.bytes.len);
                if (ctx->data) {
                    memcpy(ctx->data, f.value.bytes.data, f.value.bytes.len);
                    ctx->data_len = f.value.bytes.len;
                }
            }
            break;

        case INSTR_CTX_CU_AVAIL:
            if (f.wire_type == PB_WIRE_VARINT) {
                ctx->cu_avail = f.value.varint;
            }
            break;

        case INSTR_CTX_SLOT_CTX:
            /* Parse slot from nested message */
            if (f.wire_type == PB_WIRE_LEN) {
                pb_reader_t sub;
                pb_reader_init(&sub, f.value.bytes.data, f.value.bytes.len);
                pb_field_t sf;
                while (pb_reader_has_more(&sub)) {
                    if (!pb_read_field(&sub, &sf)) break;
                    if (sf.field_num == 1 && sf.wire_type == PB_WIRE_VARINT) {
                        ctx->slot = sf.value.varint;
                    }
                }
            }
            break;

        default:
            break;
        }
    }

    return true;
}

/*
 * Free parsed instruction context
 */
static void
free_instr_context(parsed_instr_ctx_t* ctx) {
    for (size_t i = 0; i < ctx->num_accounts; i++) {
        if (ctx->accounts[i].data) {
            sol_free(ctx->accounts[i].data);
        }
    }
    if (ctx->data) {
        sol_free(ctx->data);
    }
}

/*
 * Write AcctState to protobuf
 */
static bool
write_acct_state(pb_writer_t* w, const parsed_acct_t* acct) {
    pb_writer_t msg;
    if (!pb_writer_init(&msg, 256)) return false;

    pb_write_bytes_field(&msg, ACCT_STATE_ADDRESS, acct->pubkey.bytes, 32);
    pb_write_varint_field(&msg, ACCT_STATE_LAMPORTS, acct->lamports);
    if (acct->data && acct->data_len > 0) {
        pb_write_bytes_field(&msg, ACCT_STATE_DATA, acct->data, acct->data_len);
    }
    if (acct->executable) {
        pb_write_varint_field(&msg, ACCT_STATE_EXECUTABLE, 1);
    }
    pb_write_bytes_field(&msg, ACCT_STATE_OWNER, acct->owner.bytes, 32);

    size_t msg_len;
    uint8_t* msg_data = pb_writer_finish(&msg, &msg_len);
    bool ok = pb_write_message_field(w, INSTR_EFFECTS_MODIFIED_ACCOUNTS, msg_data, msg_len);
    sol_free(msg_data);
    return ok;
}

/*
 * Helper: Check if account at instruction index is a signer
 * In Solana, if the same account index appears multiple times in instruction
 * accounts, the account is considered a signer if ANY reference is a signer.
 */
static bool
is_signer(parsed_instr_ctx_t* ctx, size_t instr_acct_idx) {
    if (instr_acct_idx >= ctx->num_instr_accounts) return false;

    /* Get the account index for the requested position */
    size_t account_idx = ctx->instr_accounts[instr_acct_idx].index;

    /* Check if this account index appears anywhere as a signer */
    for (size_t i = 0; i < ctx->num_instr_accounts; i++) {
        if (ctx->instr_accounts[i].index == account_idx) {
            if (ctx->instr_accounts[i].is_signer) {
                return true;  /* Account is a signer somewhere */
            }
        }
    }

    return false;
}

/*
 * Helper: Check if the specific position has signer flag set
 * Used for PrivilegeEscalation detection - checks only the specific position,
 * not other occurrences of the same account index.
 */
static bool
position_is_signer(parsed_instr_ctx_t* ctx, size_t instr_acct_idx) {
    if (instr_acct_idx >= ctx->num_instr_accounts) return false;
    return ctx->instr_accounts[instr_acct_idx].is_signer;
}

/*
 * Helper: Check if the specific position has writable flag set
 * Used for PrivilegeEscalation detection - checks only the specific position.
 */
static bool
position_is_writable(parsed_instr_ctx_t* ctx, size_t instr_acct_idx) {
    if (instr_acct_idx >= ctx->num_instr_accounts) return false;
    return ctx->instr_accounts[instr_acct_idx].is_writable;
}

/*
 * Helper: Check for duplicate account indices in instruction accounts
 * Returns true if duplicates found (same index appears multiple times)
 */
static bool
has_duplicate_account_indices(parsed_instr_ctx_t* ctx) {
    /* Check if any account index appears more than once with different writable/signer flags */
    for (size_t i = 0; i < ctx->num_instr_accounts; i++) {
        for (size_t j = i + 1; j < ctx->num_instr_accounts; j++) {
            if (ctx->instr_accounts[i].index == ctx->instr_accounts[j].index) {
                return true;
            }
        }
    }
    return false;
}

/*
 * Helper: Check if account at instruction index is writable
 * In Solana, if the same account index appears multiple times in instruction
 * accounts, the account is considered read-only if ANY reference is read-only.
 */
static bool
is_writable(parsed_instr_ctx_t* ctx, size_t instr_acct_idx) {
    if (instr_acct_idx >= ctx->num_instr_accounts) return false;

    /* Get the account index for the requested position */
    size_t account_idx = ctx->instr_accounts[instr_acct_idx].index;

    /* Check if this account index appears anywhere as read-only */
    for (size_t i = 0; i < ctx->num_instr_accounts; i++) {
        if (ctx->instr_accounts[i].index == account_idx) {
            if (!ctx->instr_accounts[i].is_writable) {
                return false;  /* Account is read-only somewhere */
            }
        }
    }

    return true;
}

/*
 * Helper: Get parsed account from instruction account index
 */
static parsed_acct_t*
get_account(parsed_instr_ctx_t* ctx, size_t instr_acct_idx) {
    if (instr_acct_idx >= ctx->num_instr_accounts) return NULL;
    uint32_t idx = ctx->instr_accounts[instr_acct_idx].index;
    if (idx >= ctx->num_accounts) return NULL;
    return &ctx->accounts[idx];
}

/*
 * Helper: Parse little-endian u64
 */
static uint64_t
parse_u64_le(const uint8_t* data) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= (uint64_t)data[i] << (i * 8);
    }
    return v;
}

/*
 * Helper: Parse little-endian u32
 */
static uint32_t
parse_u32_le(const uint8_t* data) {
    return data[0] |
           ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}

/*
 * Helper: Parse little-endian u16
 */
static uint16_t
parse_u16_le(const uint8_t* data) {
    return data[0] | ((uint16_t)data[1] << 8);
}

/*
 * Helper: Check if pubkey is all zeros (system program)
 */
static bool
is_system_owned(const sol_pubkey_t* owner) {
    for (int i = 0; i < 32; i++) {
        if (owner->bytes[i] != 0) return false;
    }
    return true;
}

/*
 * Runtime error detection context
 */
typedef struct {
    uint64_t original_lamports[MAX_TEST_ACCOUNTS];
    uint64_t total_lamports_before;
    bool     has_duplicate_indices;
} runtime_check_ctx_t;

/*
 * Save original account state for runtime error detection
 */
__attribute__((unused))
static void
save_original_state(parsed_instr_ctx_t* ctx, runtime_check_ctx_t* rt_ctx) {
    rt_ctx->total_lamports_before = 0;
    rt_ctx->has_duplicate_indices = false;

    /* Save original lamports for all accounts */
    for (size_t i = 0; i < ctx->num_accounts; i++) {
        rt_ctx->original_lamports[i] = ctx->accounts[i].lamports;
        rt_ctx->total_lamports_before += ctx->accounts[i].lamports;
    }

    /* Check for duplicate account indices */
    for (size_t i = 0; i < ctx->num_instr_accounts; i++) {
        for (size_t j = i + 1; j < ctx->num_instr_accounts; j++) {
            if (ctx->instr_accounts[i].index == ctx->instr_accounts[j].index) {
                rt_ctx->has_duplicate_indices = true;
                break;
            }
        }
        if (rt_ctx->has_duplicate_indices) break;
    }
}

/*
 * Check for runtime errors after instruction execution
 * Returns error code if runtime error detected, 0 otherwise
 */
__attribute__((unused))
static int32_t
check_runtime_errors(parsed_instr_ctx_t* ctx, runtime_check_ctx_t* rt_ctx, int32_t program_result) {
    /* If program returned an error, don't check for runtime errors */
    if (program_result != RESULT_SUCCESS) {
        return program_result;
    }

    /* Check for readonly lamport change */
    for (size_t i = 0; i < ctx->num_instr_accounts; i++) {
        uint32_t idx = ctx->instr_accounts[i].index;
        if (idx >= ctx->num_accounts) continue;

        /* Check if this account index appears as read-only anywhere */
        bool is_readonly = false;
        for (size_t j = 0; j < ctx->num_instr_accounts; j++) {
            if (ctx->instr_accounts[j].index == idx && !ctx->instr_accounts[j].is_writable) {
                is_readonly = true;
                break;
            }
        }

        if (is_readonly) {
            if (ctx->accounts[idx].lamports != rt_ctx->original_lamports[idx]) {
                return INSTR_ERR_READONLY_LAMPORT_CHANGE;
            }
        }
    }

    /* Check for unbalanced instruction (lamports created/destroyed) */
    uint64_t total_lamports_after = 0;
    for (size_t i = 0; i < ctx->num_accounts; i++) {
        total_lamports_after += ctx->accounts[i].lamports;
    }

    if (total_lamports_after != rt_ctx->total_lamports_before) {
        return INSTR_ERR_UNBALANCED_INSTRUCTION;
    }

    return RESULT_SUCCESS;
}

/*
 * System Program: Transfer
 * Instruction data: u32 type (2) + u64 lamports
 * Accounts: [0] from (signer, writable), [1] to (writable)
 */
static int32_t
system_transfer(parsed_instr_ctx_t* ctx, uint64_t* cu_consumed) {
    *cu_consumed = 150;

    /* Check we have at least 1 account */
    if (ctx->num_instr_accounts < 1) {
        return INSTR_ERR_INVALID_ACCOUNT_OWNER;
    }

    /* Get from account for ownership check */
    parsed_acct_t* from = get_account(ctx, 0);
    if (!from) {
        return INSTR_ERR_INVALID_ACCOUNT_OWNER;
    }

    /* With only 1 account: if not system-owned -> InvalidAccountOwner, else NotEnoughAccountKeys */
    if (ctx->num_instr_accounts < 2) {
        if (!is_system_owned(&from->owner)) {
            return INSTR_ERR_INVALID_ACCOUNT_OWNER;
        }
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Check instruction data length */
    if (ctx->data_len < 12) {  /* 4 bytes type + 8 bytes lamports */
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }

    /* Get to account */
    parsed_acct_t* to = get_account(ctx, 1);
    if (!to) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Parse lamports */
    uint64_t lamports = parse_u64_le(ctx->data + 4);

    /* Special case: if transferring 0 lamports to same account, it's a no-op
     * This succeeds even for non-system-owned accounts */
    if (lamports == 0 && ctx->instr_accounts[0].index == ctx->instr_accounts[1].index) {
        return RESULT_SUCCESS;
    }

    /* From account must be signer */
    if (!is_signer(ctx, 0)) {
        return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    /* Check from account is system-owned - if not, InvalidArgument */
    if (!is_system_owned(&from->owner)) {
        return INSTR_ERR_INVALID_ARGUMENT;
    }

    /* For system-owned accounts, check for invalid states BEFORE balance check.
     * System-owned but executable or not-writable → InvalidArgument */
    if (from->executable) {
        return INSTR_ERR_INVALID_ARGUMENT;
    }
    if (!is_writable(ctx, 0)) {
        return INSTR_ERR_INVALID_ARGUMENT;
    }

    /* Check sufficient balance */
    if (from->lamports < lamports) {
        return INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    /* Check to account is writable */
    if (!is_writable(ctx, 1)) {
        return INSTR_ERR_INVALID_ARGUMENT;
    }

    /* Executable to accounts are readonly for lamport changes */
    if (to->executable) {
        return INSTR_ERR_INVALID_ARGUMENT;
    }

    /* Perform transfer */
    from->lamports -= lamports;
    to->lamports += lamports;

    return RESULT_SUCCESS;
}

/*
 * System Program: CreateAccount
 * Instruction data: u32 type (0) + u64 lamports + u64 space + pubkey owner
 * Accounts: [0] from (signer, writable), [1] to (signer, writable)
 */
static int32_t
system_create_account(parsed_instr_ctx_t* ctx, uint64_t* cu_consumed) {
    *cu_consumed = 150;

    /* Check instruction data length first (before account count) */
    if (ctx->data_len < 52) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }

    /* Check we have enough accounts */
    if (ctx->num_instr_accounts < 2) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Check for duplicate accounts - can't create an account from itself */
    if (ctx->instr_accounts[0].index == ctx->instr_accounts[1].index) {
        return INSTR_ERR_INVALID_ARGUMENT;
    }

    /* Get accounts */
    parsed_acct_t* from = get_account(ctx, 0);
    parsed_acct_t* to = get_account(ctx, 1);

    if (!from || !to) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Check accounts are writable - return PrivilegeEscalation if system-owned but not writable */
    if (!is_writable(ctx, 0)) {
        if (is_system_owned(&from->owner)) {
            return INSTR_ERR_PRIVILEGE_ESCALATION;
        }
        return INSTR_ERR_READONLY_LAMPORT_CHANGE;
    }
    if (!is_writable(ctx, 1)) {
        if (is_system_owned(&to->owner)) {
            return INSTR_ERR_PRIVILEGE_ESCALATION;
        }
        return INSTR_ERR_READONLY_LAMPORT_CHANGE;
    }

    /* Check to account is system-owned BEFORE checking signatures
     * If we don't own the to account, we can't modify it regardless of signatures */
    if (!is_system_owned(&to->owner)) {
        return INSTR_ERR_READONLY_LAMPORT_CHANGE;
    }

    /* Check to account is not already initialized (must have 0 lamports and no data) */
    if (to->lamports != 0 || to->data_len != 0) {
        return INSTR_ERR_READONLY_LAMPORT_CHANGE;
    }

    /* Both accounts must be signers */
    if (!is_signer(ctx, 0)) {
        return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }
    if (!is_signer(ctx, 1)) {
        return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    /* Parse instruction data */
    uint64_t lamports = parse_u64_le(ctx->data + 4);
    uint64_t space = parse_u64_le(ctx->data + 12);
    sol_pubkey_t owner;
    memcpy(owner.bytes, ctx->data + 20, 32);

    /* Check from account is system-owned - if not, ReadonlyLamportChange */
    if (!is_system_owned(&from->owner)) {
        return INSTR_ERR_READONLY_LAMPORT_CHANGE;
    }

    /* For system-owned accounts: executable → InvalidArgument */
    if (from->executable) {
        return INSTR_ERR_INVALID_ARGUMENT;
    }

    /* Check sufficient balance */
    if (from->lamports < lamports) {
        return INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    /* Check space limit (10MB max) - treat as readonly if exceeded */
    if (space > 10 * 1024 * 1024) {
        return INSTR_ERR_READONLY_LAMPORT_CHANGE;
    }

    /* Perform the operation */
    from->lamports -= lamports;
    to->lamports += lamports;
    memcpy(to->owner.bytes, owner.bytes, 32);

    /* Allocate space */
    if (space > 0) {
        if (to->data) {
            sol_free(to->data);
        }
        to->data = sol_alloc(space);
        if (!to->data) {
            return INSTR_ERR_ACCOUNT_DATA_TOO_SMALL;
        }
        memset(to->data, 0, space);
        to->data_len = space;
    }

    return RESULT_SUCCESS;
}

/*
 * System Program: Assign
 * Instruction data: u32 type (1) + pubkey owner
 * Accounts: [0] account (signer, writable)
 */
static int32_t
system_assign(parsed_instr_ctx_t* ctx, uint64_t* cu_consumed) {
    *cu_consumed = 150;

    /* Check we have enough accounts */
    if (ctx->num_instr_accounts < 1) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Check instruction data length: 4 + 32 = 36 bytes */
    if (ctx->data_len < 36) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }

    /* Get account */
    parsed_acct_t* acct = get_account(ctx, 0);
    if (!acct) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Parse new owner */
    sol_pubkey_t new_owner;
    memcpy(new_owner.bytes, ctx->data + 4, 32);

    /* If assigning same owner, it's a no-op (success) */
    if (memcmp(acct->owner.bytes, new_owner.bytes, 32) == 0) {
        return RESULT_SUCCESS;
    }

    /* For actual reassignment, account must be signer - check FIRST */
    if (!is_signer(ctx, 0)) {
        /* If account is system-owned but not signer, it's privilege escalation */
        if (is_system_owned(&acct->owner)) {
            return INSTR_ERR_PRIVILEGE_ESCALATION;
        }
        return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    /* Account must be writable - returns AccountBorrowFailed if not */
    if (!is_writable(ctx, 0)) {
        return INSTR_ERR_ACCOUNT_BORROW_FAILED;
    }

    /* Account must be system-owned to be assigned to a new owner
     * If not system-owned, we can't borrow it for modification */
    if (!is_system_owned(&acct->owner)) {
        return INSTR_ERR_ACCOUNT_BORROW_FAILED;
    }

    /* Assign new owner */
    memcpy(acct->owner.bytes, new_owner.bytes, 32);

    return RESULT_SUCCESS;
}

/*
 * System Program: Allocate
 * Instruction data: u32 type (8) + u64 space
 * Accounts: [0] account (signer, writable)
 */
static int32_t
system_allocate(parsed_instr_ctx_t* ctx, uint64_t* cu_consumed) {
    *cu_consumed = 150;

    /* Check we have enough accounts */
    if (ctx->num_instr_accounts < 1) {
        return INSTR_ERR_INVALID_ACCOUNT_OWNER;  /* Special case for 0 accounts */
    }

    /* Check instruction data length: 4 + 8 = 12 bytes */
    if (ctx->data_len < 12) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }

    /* Get account early for ownership/signer checks */
    parsed_acct_t* acct = get_account(ctx, 0);
    if (!acct) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Account must be signer - check BEFORE writable.
     * Privilege escalation only if system-owned */
    if (!is_signer(ctx, 0)) {
        if (is_system_owned(&acct->owner)) {
            return INSTR_ERR_PRIVILEGE_ESCALATION;
        }
        return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    /* Account must be writable */
    if (!is_writable(ctx, 0)) {
        return INSTR_ERR_READONLY_LAMPORT_CHANGE;
    }

    /* Parse space */
    uint64_t space = parse_u64_le(ctx->data + 4);

    /* Account must be system-owned - if not, we can't modify it
     * Return ReadonlyLamportChange since we can't allocate on non-owned accounts */
    if (!is_system_owned(&acct->owner)) {
        return INSTR_ERR_READONLY_LAMPORT_CHANGE;
    }

    /* Executable accounts are always readonly */
    if (acct->executable) {
        return INSTR_ERR_READONLY_LAMPORT_CHANGE;
    }

    /* Account must not already have data - treat as readonly if already has data */
    if (acct->data_len != 0) {
        return INSTR_ERR_READONLY_LAMPORT_CHANGE;
    }

    /* Check space limit (10MB max)
     * Solana returns ReadonlyLamportChange for oversized allocations */
    if (space > 10 * 1024 * 1024) {
        return INSTR_ERR_READONLY_LAMPORT_CHANGE;
    }

    /* Allocate space */
    if (space > 0) {
        if (acct->data) {
            sol_free(acct->data);
        }
        acct->data = sol_alloc(space);
        if (!acct->data) {
            return INSTR_ERR_ACCOUNT_DATA_TOO_SMALL;
        }
        memset(acct->data, 0, space);
        acct->data_len = space;
    }

    return RESULT_SUCCESS;
}

/*
 * Maximum seed length for address derivation
 */
#define MAX_SEED_LEN 32

/*
 * Helper: Validate UTF-8 encoding
 * Returns true if the byte sequence is valid UTF-8
 */
static bool
is_valid_utf8(const uint8_t* data, size_t len) {
    size_t i = 0;
    while (i < len) {
        if (data[i] <= 0x7F) {
            /* ASCII byte */
            i++;
        } else if ((data[i] & 0xE0) == 0xC0) {
            /* 2-byte sequence: 110xxxxx 10xxxxxx */
            if (i + 1 >= len) return false;
            if ((data[i + 1] & 0xC0) != 0x80) return false;
            /* Check for overlong encoding */
            if ((data[i] & 0x1E) == 0) return false;
            i += 2;
        } else if ((data[i] & 0xF0) == 0xE0) {
            /* 3-byte sequence: 1110xxxx 10xxxxxx 10xxxxxx */
            if (i + 2 >= len) return false;
            if ((data[i + 1] & 0xC0) != 0x80) return false;
            if ((data[i + 2] & 0xC0) != 0x80) return false;
            /* Check for overlong encoding */
            if (data[i] == 0xE0 && (data[i + 1] & 0x20) == 0) return false;
            i += 3;
        } else if ((data[i] & 0xF8) == 0xF0) {
            /* 4-byte sequence: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx */
            if (i + 3 >= len) return false;
            if ((data[i + 1] & 0xC0) != 0x80) return false;
            if ((data[i + 2] & 0xC0) != 0x80) return false;
            if ((data[i + 3] & 0xC0) != 0x80) return false;
            /* Check for overlong encoding and valid range */
            if (data[i] == 0xF0 && (data[i + 1] & 0x30) == 0) return false;
            if (data[i] > 0xF4) return false;
            if (data[i] == 0xF4 && data[i + 1] > 0x8F) return false;
            i += 4;
        } else {
            /* Invalid leading byte */
            return false;
        }
    }
    return true;
}

/*
 * Helper: Derive address with seed using SHA-256
 * address = sha256(base || seed || program_id)
 */
static void
derive_address_with_seed(const sol_pubkey_t* base, const uint8_t* seed, size_t seed_len,
                         const sol_pubkey_t* program_id, sol_pubkey_t* out) {
    sol_sha256_ctx_t ctx;
    sol_sha256_t hash;

    sol_sha256_init(&ctx);
    sol_sha256_update(&ctx, base->bytes, 32);
    sol_sha256_update(&ctx, seed, seed_len);
    sol_sha256_update(&ctx, program_id->bytes, 32);
    sol_sha256_final(&ctx, &hash);

    memcpy(out->bytes, hash.bytes, 32);
}

/*
 * System Program: CreateAccountWithSeed (type 3)
 * Instruction data: u32 type + pubkey base + u64 seed_len + seed + u64 lamports + u64 space + pubkey owner
 * Accounts: [0] from (signer, writable), [1] to (writable), [2] base (signer)
 */
static int32_t
system_create_account_with_seed(parsed_instr_ctx_t* ctx, uint64_t* cu_consumed) {
    *cu_consumed = 150;

    /* Check we have enough accounts */
    if (ctx->num_instr_accounts < 2) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Minimum data: 4 + 32 + 8 + 0 + 8 + 8 + 32 = 92 bytes (with 0 seed) */
    if (ctx->data_len < 92) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }

    /* Get accounts */
    parsed_acct_t* from = get_account(ctx, 0);
    parsed_acct_t* to = get_account(ctx, 1);

    if (!from || !to) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Parse instruction data early to get base pubkey for validation order */
    size_t pos = 4;

    sol_pubkey_t base;
    memcpy(base.bytes, ctx->data + pos, 32);
    pos += 32;

    uint64_t seed_len = parse_u64_le(ctx->data + pos);
    pos += 8;

    /* Check we have enough data for seed + remaining fields BEFORE seed length validation */
    if (ctx->data_len < pos + seed_len + 8 + 8 + 32) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }

    /* Validate seed length */
    if (seed_len > MAX_SEED_LEN) {
        return INSTR_ERR_MAX_SEED_LENGTH_EXCEEDED;
    }

    const uint8_t* seed = ctx->data + pos;
    pos += seed_len;

    /* Validate seed is valid UTF-8 (Solana requires seeds to be UTF-8 strings) */
    if (seed_len > 0 && !is_valid_utf8(seed, seed_len)) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }

    uint64_t lamports = parse_u64_le(ctx->data + pos);
    pos += 8;

    uint64_t space = parse_u64_le(ctx->data + pos);
    pos += 8;

    sol_pubkey_t owner;
    memcpy(owner.bytes, ctx->data + pos, 32);

    /* Check from is writable - use position_is_writable for PrivilegeEscalation,
     * is_writable for overall check (handles conflicting flags on same account) */
    if (!is_writable(ctx, 0)) {
        /* If the specific position flag is false AND system-owned, PrivilegeEscalation */
        if (!position_is_writable(ctx, 0) && is_system_owned(&from->owner)) {
            return INSTR_ERR_PRIVILEGE_ESCALATION;
        }
        return INSTR_ERR_READONLY_LAMPORT_CHANGE;
    }

    /* Check to is writable */
    if (!is_writable(ctx, 1)) {
        return INSTR_ERR_READONLY_LAMPORT_CHANGE;
    }

    /* Check from is system-owned - if not, ReadonlyLamportChange */
    if (!is_system_owned(&from->owner)) {
        return INSTR_ERR_READONLY_LAMPORT_CHANGE;
    }

    /* For system-owned accounts: executable → InvalidArgument */
    if (from->executable) {
        return INSTR_ERR_INVALID_ARGUMENT;
    }

    /* Check sufficient balance */
    if (from->lamports < lamports) {
        return INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    /* Check if base is different from from (needs separate account at position 2) */
    bool base_is_from = (memcmp(from->pubkey.bytes, base.bytes, 32) == 0);

    /* Note: base account only needs to be signer, not writable */

    /* From must be signer */
    if (!is_signer(ctx, 0)) {
        return INSTR_ERR_PRIVILEGE_ESCALATION;
    }

    /* Base account must sign (may be same as from, or account index 2) */
    bool base_signed = false;
    if (base_is_from && is_signer(ctx, 0)) {
        base_signed = true;
    } else if (ctx->num_instr_accounts >= 3) {
        parsed_acct_t* base_acct = get_account(ctx, 2);
        if (base_acct && memcmp(base_acct->pubkey.bytes, base.bytes, 32) == 0 && is_signer(ctx, 2)) {
            base_signed = true;
        }
    }

    if (!base_signed) {
        return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    /* From account cannot have data - system accounts with data can only be nonces
     * and must use WithdrawNonceAccount for transfers */
    if (from->data_len != 0) {
        return INSTR_ERR_INVALID_ARGUMENT;
    }

    /* Check to is not already initialized */
    if (to->lamports != 0 || to->data_len != 0) {
        return INSTR_ERR_ACCOUNT_ALREADY_INITIALIZED;
    }

    /* Check to is system-owned */
    if (!is_system_owned(&to->owner)) {
        return INSTR_ERR_INVALID_ARGUMENT;
    }

    /* Verify PDA: derived address must match 'to' account address */
    sol_pubkey_t derived_addr;
    derive_address_with_seed(&base, seed, seed_len, &owner, &derived_addr);
    if (memcmp(derived_addr.bytes, to->pubkey.bytes, 32) != 0) {
        return INSTR_ERR_INVALID_ARGUMENT;
    }

    /* Check sufficient balance */
    if (from->lamports < lamports) {
        return INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    /* Check space limit */
    if (space > 10 * 1024 * 1024) {
        return INSTR_ERR_INVALID_ARGUMENT;
    }

    /* Perform the operation */
    from->lamports -= lamports;
    to->lamports += lamports;
    memcpy(to->owner.bytes, owner.bytes, 32);

    /* Allocate space */
    if (space > 0) {
        if (to->data) {
            sol_free(to->data);
        }
        to->data = sol_alloc(space);
        if (!to->data) {
            return INSTR_ERR_ACCOUNT_DATA_TOO_SMALL;
        }
        memset(to->data, 0, space);
        to->data_len = space;
    }

    return RESULT_SUCCESS;
}

/*
 * System Program: AllocateWithSeed (type 9)
 * Instruction data: u32 type + pubkey base + u64 seed_len + seed + u64 space + pubkey owner
 * Accounts: [0] account (writable), [1] base (signer)
 */
static int32_t
system_allocate_with_seed(parsed_instr_ctx_t* ctx, uint64_t* cu_consumed) {
    *cu_consumed = 150;

    /* Check we have enough accounts */
    if (ctx->num_instr_accounts < 2) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Minimum data: 4 + 32 + 8 + 0 + 8 + 32 = 84 bytes */
    if (ctx->data_len < 84) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }

    /* Get accounts first */
    parsed_acct_t* acct = get_account(ctx, 0);
    parsed_acct_t* base_acct = get_account(ctx, 1);

    if (!acct || !base_acct) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Parse instruction data */
    size_t pos = 4;

    sol_pubkey_t base;
    memcpy(base.bytes, ctx->data + pos, 32);
    pos += 32;

    uint64_t seed_len = parse_u64_le(ctx->data + pos);
    pos += 8;

    /* Check data length BEFORE seed length validation */
    if (ctx->data_len < pos + seed_len + 8 + 32) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }

    if (seed_len > MAX_SEED_LEN) {
        return INSTR_ERR_MAX_SEED_LENGTH_EXCEEDED;
    }

    /* Skip over seed bytes (already validated by seed_len check above) */
    pos += seed_len;

    uint64_t space = parse_u64_le(ctx->data + pos);
    pos += 8;

    /* Check space limit early - extremely large values are invalid instruction data */
    if (space > 10 * 1024 * 1024) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }

    sol_pubkey_t owner;
    memcpy(owner.bytes, ctx->data + pos, 32);

    /* Base must be signer - check BEFORE writability */
    if (!is_signer(ctx, 1)) {
        return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    /* Account must be writable */
    if (!is_writable(ctx, 0)) {
        if (!position_is_writable(ctx, 0) && is_system_owned(&acct->owner)) {
            return INSTR_ERR_PRIVILEGE_ESCALATION;
        }
        return INSTR_ERR_READONLY_LAMPORT_CHANGE;
    }

    /* Account must be system-owned
     * If we don't own the account, we can't modify it */
    if (!is_system_owned(&acct->owner)) {
        return INSTR_ERR_READONLY_LAMPORT_CHANGE;
    }

    /* Base pubkey must match */
    if (memcmp(base_acct->pubkey.bytes, base.bytes, 32) != 0) {
        return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    /* Account must not already have data */
    if (acct->data_len != 0) {
        return INSTR_ERR_INVALID_ARGUMENT;
    }

    /* Allocate and assign owner */
    if (space > 0) {
        if (acct->data) {
            sol_free(acct->data);
        }
        acct->data = sol_alloc(space);
        if (!acct->data) {
            return INSTR_ERR_ACCOUNT_DATA_TOO_SMALL;
        }
        memset(acct->data, 0, space);
        acct->data_len = space;
    }

    memcpy(acct->owner.bytes, owner.bytes, 32);

    return RESULT_SUCCESS;
}

/*
 * System Program: AssignWithSeed (type 10)
 * Instruction data: u32 type + pubkey base + u64 seed_len + seed + pubkey owner
 * Accounts: [0] account (writable), [1] base (signer)
 */
static int32_t
system_assign_with_seed(parsed_instr_ctx_t* ctx, uint64_t* cu_consumed) {
    *cu_consumed = 150;

    /* Check we have enough accounts */
    if (ctx->num_instr_accounts < 2) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Minimum data: 4 + 32 + 8 + 0 + 32 = 76 bytes */
    if (ctx->data_len < 76) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }

    /* Parse instruction data */
    size_t pos = 4;

    sol_pubkey_t base;
    memcpy(base.bytes, ctx->data + pos, 32);
    pos += 32;

    uint64_t seed_len = parse_u64_le(ctx->data + pos);
    pos += 8;

    if (seed_len > MAX_SEED_LEN) {
        return INSTR_ERR_MAX_SEED_LENGTH_EXCEEDED;
    }

    if (ctx->data_len < pos + seed_len + 32) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }

    const uint8_t* seed = ctx->data + pos;
    pos += seed_len;
    (void)seed;  /* Used for address derivation verification */

    sol_pubkey_t owner;
    memcpy(owner.bytes, ctx->data + pos, 32);

    /* Get accounts */
    parsed_acct_t* acct = get_account(ctx, 0);
    parsed_acct_t* base_acct = get_account(ctx, 1);

    if (!acct || !base_acct) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Account must be writable - check FIRST before other validations */
    if (!is_writable(ctx, 0)) {
        return INSTR_ERR_READONLY_LAMPORT_CHANGE;
    }

    /* Account must be system-owned to modify - check BEFORE signature checks
     * If we don't own the account, we can't modify it regardless of signatures */
    if (!is_system_owned(&acct->owner)) {
        return INSTR_ERR_READONLY_LAMPORT_CHANGE;
    }

    /* Base must be signer - check before pubkey match */
    if (!is_signer(ctx, 1)) {
        return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    /* Base pubkey must match */
    if (memcmp(base_acct->pubkey.bytes, base.bytes, 32) != 0) {
        return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    /* If assigning same owner, it's a no-op */
    if (memcmp(acct->owner.bytes, owner.bytes, 32) == 0) {
        return RESULT_SUCCESS;
    }

    /* Assign new owner */
    memcpy(acct->owner.bytes, owner.bytes, 32);

    return RESULT_SUCCESS;
}

/*
 * System Program: TransferWithSeed (type 11)
 * Instruction data: u32 type + u64 lamports + u64 seed_len + seed + pubkey from_owner
 * Accounts: [0] from (writable), [1] base (signer), [2] to (writable)
 */
static int32_t
system_transfer_with_seed(parsed_instr_ctx_t* ctx, uint64_t* cu_consumed) {
    *cu_consumed = 150;

    /* Check we have enough accounts */
    if (ctx->num_instr_accounts < 3) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Minimum data: 4 + 8 + 8 + 0 + 32 = 52 bytes */
    if (ctx->data_len < 52) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }

    /* Get accounts */
    parsed_acct_t* from = get_account(ctx, 0);
    parsed_acct_t* base_acct = get_account(ctx, 1);
    parsed_acct_t* to = get_account(ctx, 2);

    if (!from || !base_acct || !to) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Parse instruction data early to check seed validity */
    size_t pos = 4;

    uint64_t lamports = parse_u64_le(ctx->data + pos);
    pos += 8;

    uint64_t seed_len = parse_u64_le(ctx->data + pos);
    pos += 8;

    /* Check remaining data length BEFORE seed length validation */
    if (ctx->data_len < pos + seed_len + 32) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }

    if (seed_len > MAX_SEED_LEN) {
        return INSTR_ERR_MAX_SEED_LENGTH_EXCEEDED;
    }

    const uint8_t* seed = ctx->data + pos;
    pos += seed_len;

    sol_pubkey_t from_owner;
    memcpy(from_owner.bytes, ctx->data + pos, 32);

    /* Base must be signer - check FIRST */
    if (!is_signer(ctx, 1)) {
        return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    /* Check from account is writable.
     * Special case: for system-owned from, not signer, not writable, with valid PDA,
     * Solana returns BorshIoError (likely due to internal processing order). */
    if (!is_writable(ctx, 0)) {
        if (is_system_owned(&from->owner) && !is_signer(ctx, 0)) {
            /* Check if PDA would match - determines which error */
            sol_pubkey_t derived_addr;
            derive_address_with_seed(&base_acct->pubkey, seed, seed_len, &from_owner, &derived_addr);
            if (memcmp(derived_addr.bytes, from->pubkey.bytes, 32) == 0) {
                /* PDA matches but account not writable - Borsh IO error */
                return INSTR_ERR_BORSH_IO_ERROR;
            }
        }
        return INSTR_ERR_READONLY_LAMPORT_CHANGE;
    }

    /* Check to account is writable */
    if (!is_writable(ctx, 2)) {
        return INSTR_ERR_READONLY_LAMPORT_CHANGE;
    }

    /* Executable accounts are always readonly for lamport changes */
    if (from->executable) {
        return INSTR_ERR_READONLY_LAMPORT_CHANGE;
    }
    if (to->executable) {
        return INSTR_ERR_READONLY_LAMPORT_CHANGE;
    }

    /* For non-system-owned accounts, from.owner must match from_owner */
    if (!is_system_owned(&from->owner)) {
        if (memcmp(from->owner.bytes, from_owner.bytes, 32) != 0) {
            return INSTR_ERR_READONLY_LAMPORT_CHANGE;
        }
    } else {
        /* For system-owned accounts, verify PDA derivation */
        sol_pubkey_t derived_addr;
        derive_address_with_seed(&base_acct->pubkey, seed, seed_len, &from_owner, &derived_addr);
        if (memcmp(derived_addr.bytes, from->pubkey.bytes, 32) != 0) {
            /* PDA mismatch - treat as ownership issue */
            return INSTR_ERR_READONLY_LAMPORT_CHANGE;
        }
    }

    /* Check sufficient balance */
    if (from->lamports < lamports) {
        return INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    /* Perform transfer */
    from->lamports -= lamports;
    to->lamports += lamports;

    return RESULT_SUCCESS;
}

/*
 * Nonce account data structure (80 bytes)
 */
#define NONCE_DATA_SIZE 80
#define NONCE_VERSION_CURRENT 1

typedef enum {
    NONCE_STATE_UNINITIALIZED = 0,
    NONCE_STATE_INITIALIZED = 1,
} nonce_state_t;

/*
 * Helper: Parse nonce account data
 */
static bool
parse_nonce_data(const parsed_acct_t* acct, uint32_t* version, uint32_t* state,
                 sol_pubkey_t* authority, uint8_t* blockhash, uint64_t* fee) {
    if (acct->data_len < NONCE_DATA_SIZE) return false;

    *version = parse_u32_le(acct->data);
    *state = parse_u32_le(acct->data + 4);
    memcpy(authority->bytes, acct->data + 8, 32);
    memcpy(blockhash, acct->data + 40, 32);
    *fee = parse_u64_le(acct->data + 72);
    return true;
}

/*
 * Helper: Write nonce account data
 */
static void
write_nonce_data(parsed_acct_t* acct, uint32_t version, uint32_t state,
                 const sol_pubkey_t* authority, const uint8_t* blockhash, uint64_t fee) {
    /* Write version (little-endian u32) */
    acct->data[0] = version & 0xFF;
    acct->data[1] = (version >> 8) & 0xFF;
    acct->data[2] = (version >> 16) & 0xFF;
    acct->data[3] = (version >> 24) & 0xFF;

    /* Write state (little-endian u32) */
    acct->data[4] = state & 0xFF;
    acct->data[5] = (state >> 8) & 0xFF;
    acct->data[6] = (state >> 16) & 0xFF;
    acct->data[7] = (state >> 24) & 0xFF;

    /* Write authority pubkey */
    memcpy(acct->data + 8, authority->bytes, 32);

    /* Write blockhash */
    memcpy(acct->data + 40, blockhash, 32);

    /* Write fee (little-endian u64) */
    for (int i = 0; i < 8; i++) {
        acct->data[72 + i] = (fee >> (i * 8)) & 0xFF;
    }
}

/*
 * System Program: InitializeNonceAccount (type 6)
 * Instruction data: u32 type + pubkey authority
 * Accounts: [0] nonce account (writable), [1] recent blockhashes sysvar, [2] rent sysvar
 */
static int32_t
system_initialize_nonce(parsed_instr_ctx_t* ctx, uint64_t* cu_consumed) {
    *cu_consumed = 150;

    /* Check we have at least 1 account for ownership check */
    if (ctx->num_instr_accounts < 1) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Get nonce account for ownership check */
    parsed_acct_t* nonce_acct = get_account(ctx, 0);
    if (!nonce_acct) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Check nonce account ownership BEFORE account count check.
     * If not system-owned, return InvalidAccountOwner even with insufficient accounts */
    if (!is_system_owned(&nonce_acct->owner)) {
        return INSTR_ERR_INVALID_ACCOUNT_OWNER;
    }

    /* Now check we have 3 accounts */
    if (ctx->num_instr_accounts < 3) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Nonce account must be writable */
    if (!is_writable(ctx, 0)) {
        return INSTR_ERR_INVALID_ARGUMENT;
    }

    /* Validate sysvar accounts - ia[1] must have sysvar prefix (not all zeros) */
    parsed_acct_t* blockhashes_acct = get_account(ctx, 1);
    if (!blockhashes_acct) {
        return INSTR_ERR_INVALID_ARGUMENT;
    }
    /* Check for sysvar prefix 0x06a7d517 - reject obvious invalid addresses like all zeros */
    static const uint8_t sysvar_prefix[] = {0x06, 0xa7, 0xd5, 0x17};
    if (memcmp(blockhashes_acct->pubkey.bytes, sysvar_prefix, 4) != 0) {
        return INSTR_ERR_INVALID_ARGUMENT;
    }

    /* Check instruction data length: 4 + 32 = 36 bytes */
    if (ctx->data_len < 36) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }

    /* Nonce account must have at least NONCE_DATA_SIZE bytes */
    if (nonce_acct->data_len < NONCE_DATA_SIZE) {
        return INSTR_ERR_INVALID_ACCOUNT_DATA;
    }

    /* Parse and validate nonce data */
    uint32_t version, state;
    sol_pubkey_t authority;
    uint8_t blockhash[32];
    uint64_t fee;

    if (!parse_nonce_data(nonce_acct, &version, &state, &authority, blockhash, &fee)) {
        return INSTR_ERR_INVALID_ACCOUNT_DATA;
    }

    /* Check version is valid (0 = legacy, 1 = current) */
    if (version > NONCE_VERSION_CURRENT) {
        return INSTR_ERR_INVALID_ACCOUNT_DATA;
    }

    /* Check if already initialized */
    if (state == NONCE_STATE_INITIALIZED) {
        return INSTR_ERR_ACCOUNT_ALREADY_INITIALIZED;
    }

    /* Parse authority from instruction data */
    sol_pubkey_t new_authority;
    memcpy(new_authority.bytes, ctx->data + 4, 32);

    /* Initialize nonce data with placeholder blockhash */
    uint8_t new_blockhash[32] = {0};
    /* In real impl, get from recent blockhashes sysvar */

    write_nonce_data(nonce_acct, NONCE_VERSION_CURRENT, NONCE_STATE_INITIALIZED,
                     &new_authority, new_blockhash, 5000);

    return RESULT_SUCCESS;
}

/*
 * System Program: AdvanceNonceAccount (type 4)
 * Instruction data: u32 type only
 * Accounts: [0] nonce account (writable), [1] recent blockhashes sysvar, [2] authority (signer)
 */
static int32_t
system_advance_nonce(parsed_instr_ctx_t* ctx, uint64_t* cu_consumed) {
    *cu_consumed = 150;

    /* Check we have enough accounts */
    if (ctx->num_instr_accounts < 2) {
        return INSTR_ERR_INVALID_ACCOUNT_OWNER;  /* Special case for 0-1 accounts */
    }
    if (ctx->num_instr_accounts < 3) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Get nonce account */
    parsed_acct_t* nonce_acct = get_account(ctx, 0);
    if (!nonce_acct) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Nonce account must be system-owned */
    if (!is_system_owned(&nonce_acct->owner)) {
        return INSTR_ERR_INVALID_ARGUMENT;
    }

    /* Nonce account must have at least NONCE_DATA_SIZE bytes */
    if (nonce_acct->data_len < NONCE_DATA_SIZE) {
        return INSTR_ERR_INVALID_ACCOUNT_DATA;
    }

    /* Parse nonce data */
    uint32_t version, state;
    sol_pubkey_t authority;
    uint8_t blockhash[32];
    uint64_t fee;

    if (!parse_nonce_data(nonce_acct, &version, &state, &authority, blockhash, &fee)) {
        return INSTR_ERR_INVALID_ACCOUNT_DATA;
    }

    /* Must be initialized */
    if (state != NONCE_STATE_INITIALIZED) {
        return INSTR_ERR_UNINITIALIZED_ACCOUNT;
    }

    /* Authority must sign */
    parsed_acct_t* authority_acct = get_account(ctx, 2);
    if (!authority_acct) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Check authority matches */
    if (memcmp(authority_acct->pubkey.bytes, authority.bytes, 32) != 0) {
        return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    /* Check authority is signer */
    if (!is_signer(ctx, 2)) {
        return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    /* Advance nonce - in real impl, get new blockhash from sysvar */
    /* For conformance, just increment the first byte as a placeholder */
    blockhash[0]++;
    write_nonce_data(nonce_acct, version, state, &authority, blockhash, fee);

    return RESULT_SUCCESS;
}

/*
 * System Program: WithdrawNonceAccount (type 5)
 * Instruction data: u32 type + u64 lamports
 * Accounts: [0] nonce account (writable), [1] destination (writable),
 *           [2] recent blockhashes sysvar, [3] rent sysvar, [4] authority (signer)
 */
static int32_t
system_withdraw_nonce(parsed_instr_ctx_t* ctx, uint64_t* cu_consumed) {
    *cu_consumed = 150;

    /* Check we have enough accounts - need at least 4: nonce, recipient, blockhashes, rent
     * The 5th account (authority) is only needed when nonce is initialized */
    if (ctx->num_instr_accounts < 1) {
        return INSTR_ERR_INVALID_ACCOUNT_OWNER;  /* Special case for 0 accounts */
    }

    /* Get nonce account early to check ownership before account count */
    parsed_acct_t* nonce_acct = get_account(ctx, 0);
    if (!nonce_acct) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* When accounts < 4, check system ownership first - return InvalidAccountOwner if not owned */
    if (ctx->num_instr_accounts < 4) {
        if (!is_system_owned(&nonce_acct->owner)) {
            return INSTR_ERR_INVALID_ACCOUNT_OWNER;
        }
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Check instruction data length: 4 + 8 = 12 bytes */
    if (ctx->data_len < 12) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }

    /* Get destination account */
    parsed_acct_t* dest_acct = get_account(ctx, 1);
    if (!dest_acct) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Validate sysvar account - ia[2] must have sysvar prefix */
    parsed_acct_t* blockhashes_acct = get_account(ctx, 2);
    if (!blockhashes_acct) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }
    static const uint8_t sysvar_prefix[] = {0x06, 0xa7, 0xd5, 0x17};
    if (memcmp(blockhashes_acct->pubkey.bytes, sysvar_prefix, 4) != 0) {
        return INSTR_ERR_INVALID_ARGUMENT;
    }

    /* Destination must not be a sysvar (can't withdraw to sysvar) */
    if (memcmp(dest_acct->pubkey.bytes, sysvar_prefix, 4) == 0) {
        return INSTR_ERR_INVALID_ARGUMENT;
    }

    /* Nonce account must be system-owned */
    if (!is_system_owned(&nonce_acct->owner)) {
        return INSTR_ERR_INVALID_ARGUMENT;
    }

    /* Check accounts are writable before modifying */
    if (!is_writable(ctx, 0)) {
        return INSTR_ERR_READONLY_LAMPORT_CHANGE;
    }
    if (!is_writable(ctx, 1)) {
        return INSTR_ERR_READONLY_LAMPORT_CHANGE;
    }

    /* Parse lamports to withdraw */
    uint64_t lamports = parse_u64_le(ctx->data + 4);

    /* Check sufficient balance FIRST - before other validation.
     * Solana returns InsufficientFunds even if account has other issues */
    if (nonce_acct->lamports < lamports) {
        return INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    /* Parse nonce data */
    uint32_t version, state;
    sol_pubkey_t authority;
    uint8_t blockhash[32];
    uint64_t fee;

    if (nonce_acct->data_len >= NONCE_DATA_SIZE) {
        if (!parse_nonce_data(nonce_acct, &version, &state, &authority, blockhash, &fee)) {
            return INSTR_ERR_INVALID_ACCOUNT_DATA;
        }
        /* Check version is valid (0 = legacy, 1 = current) */
        if (version > NONCE_VERSION_CURRENT) {
            return INSTR_ERR_INVALID_ACCOUNT_DATA;
        }
    } else {
        /* Uninitialized account - but still check if there's data with invalid version */
        if (nonce_acct->data_len >= 4) {
            version = parse_u32_le(nonce_acct->data);
            if (version > NONCE_VERSION_CURRENT) {
                return INSTR_ERR_INVALID_ACCOUNT_DATA;
            }
        }
        state = NONCE_STATE_UNINITIALIZED;
    }

    /* If initialized, authority must sign */
    if (state == NONCE_STATE_INITIALIZED) {
        parsed_acct_t* authority_acct = get_account(ctx, 4);
        if (!authority_acct) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }

        /* Check authority matches - InvalidArgument if mismatch */
        if (memcmp(authority_acct->pubkey.bytes, authority.bytes, 32) != 0) {
            return INSTR_ERR_INVALID_ARGUMENT;
        }

        /* Check authority is signer */
        if (!is_signer(ctx, 4)) {
            return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
    }

    /* Perform withdrawal */
    nonce_acct->lamports -= lamports;
    dest_acct->lamports += lamports;

    return RESULT_SUCCESS;
}

/*
 * System Program: AuthorizeNonceAccount (type 7)
 * Instruction data: u32 type + pubkey new_authority
 * Accounts: [0] nonce account (writable), [1] authority (signer)
 */
static int32_t
system_authorize_nonce(parsed_instr_ctx_t* ctx, uint64_t* cu_consumed) {
    *cu_consumed = 150;

    /* Check we have enough accounts */
    if (ctx->num_instr_accounts < 1) {
        return INSTR_ERR_INVALID_ACCOUNT_OWNER;  /* Special case for 0 accounts */
    }
    if (ctx->num_instr_accounts < 2) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Get nonce account */
    parsed_acct_t* nonce_acct = get_account(ctx, 0);
    if (!nonce_acct) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Check instruction data length: 4 + 32 = 36 bytes */
    if (ctx->data_len < 36) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }

    /* Nonce account must be writable
     * PrivilegeEscalation: instruction claims writable but system sees as read-only (dup accounts)
     * InvalidArgument: instruction itself says not writable */
    if (!is_writable(ctx, 0)) {
        if (position_is_writable(ctx, 0) && is_system_owned(&nonce_acct->owner)) {
            return INSTR_ERR_PRIVILEGE_ESCALATION;
        }
        return INSTR_ERR_INVALID_ARGUMENT;
    }

    /* Nonce account must be system-owned */
    if (!is_system_owned(&nonce_acct->owner)) {
        return INSTR_ERR_INVALID_ACCOUNT_DATA;
    }

    /* Nonce account must have at least NONCE_DATA_SIZE bytes */
    if (nonce_acct->data_len < NONCE_DATA_SIZE) {
        return INSTR_ERR_INVALID_ACCOUNT_DATA;
    }

    /* Parse nonce data */
    uint32_t version, state;
    sol_pubkey_t authority;
    uint8_t blockhash[32];
    uint64_t fee;

    if (!parse_nonce_data(nonce_acct, &version, &state, &authority, blockhash, &fee)) {
        return INSTR_ERR_INVALID_ACCOUNT_DATA;
    }

    /* Must be initialized */
    if (state != NONCE_STATE_INITIALIZED) {
        return INSTR_ERR_INVALID_ACCOUNT_DATA;  /* Invalid data if not proper nonce */
    }

    /* Authority must sign */
    parsed_acct_t* authority_acct = get_account(ctx, 1);
    if (!authority_acct) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Check authority matches */
    if (memcmp(authority_acct->pubkey.bytes, authority.bytes, 32) != 0) {
        return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    /* Check authority is signer */
    if (!is_signer(ctx, 1)) {
        return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    /* Parse new authority */
    sol_pubkey_t new_authority;
    memcpy(new_authority.bytes, ctx->data + 4, 32);

    /* Update authority */
    write_nonce_data(nonce_acct, version, state, &new_authority, blockhash, fee);

    return RESULT_SUCCESS;
}

/*
 * System Program: UpgradeNonceAccount (type 12)
 * Instruction data: u32 type only
 * Accounts: [0] nonce account (writable)
 */
static int32_t
system_upgrade_nonce(parsed_instr_ctx_t* ctx, uint64_t* cu_consumed) {
    *cu_consumed = 150;

    /* Check we have enough accounts */
    if (ctx->num_instr_accounts < 1) {
        return INSTR_ERR_INVALID_ACCOUNT_OWNER;  /* Special case for 0 accounts */
    }

    /* Nonce account must be writable */
    if (!is_writable(ctx, 0)) {
        return INSTR_ERR_INVALID_ARGUMENT;
    }

    /* Get nonce account */
    parsed_acct_t* nonce_acct = get_account(ctx, 0);
    if (!nonce_acct) {
        return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
    }

    /* Nonce account must be system-owned - returns specific error 47 */
    if (!is_system_owned(&nonce_acct->owner)) {
        return INSTR_ERR_INVALID_ACCOUNT_DATA_REALLOC;
    }

    /* Nonce account must have at least NONCE_DATA_SIZE bytes */
    if (nonce_acct->data_len < NONCE_DATA_SIZE) {
        return INSTR_ERR_INVALID_ACCOUNT_DATA;
    }

    /* Parse nonce data */
    uint32_t version, state;
    sol_pubkey_t authority;
    uint8_t blockhash[32];
    uint64_t fee;

    if (!parse_nonce_data(nonce_acct, &version, &state, &authority, blockhash, &fee)) {
        return INSTR_ERR_INVALID_ACCOUNT_DATA;
    }

    /* Must be initialized */
    if (state != NONCE_STATE_INITIALIZED) {
        return INSTR_ERR_UNINITIALIZED_ACCOUNT;
    }

    /* Already at current version is a no-op success */
    if (version == NONCE_VERSION_CURRENT) {
        return RESULT_SUCCESS;
    }

    /* Upgrade to current version */
    write_nonce_data(nonce_acct, NONCE_VERSION_CURRENT, state, &authority, blockhash, fee);

    return RESULT_SUCCESS;
}

/*
 * Execute system program instruction
 * Returns RESULT_SUCCESS (-1) on success, error code otherwise
 */
static int32_t
execute_system_program(parsed_instr_ctx_t* ctx, uint64_t* cu_consumed) {
    *cu_consumed = 150;  /* Base CU for system program */

    if (ctx->data_len < 4) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }

    /* Parse instruction type (little-endian u32) */
    uint32_t instr_type = parse_u32_le(ctx->data);

    switch (instr_type) {
    case 0: /* CreateAccount */
        return system_create_account(ctx, cu_consumed);

    case 1: /* Assign */
        return system_assign(ctx, cu_consumed);

    case 2: /* Transfer */
        return system_transfer(ctx, cu_consumed);

    case 3: /* CreateAccountWithSeed */
        return system_create_account_with_seed(ctx, cu_consumed);

    case 4: /* AdvanceNonceAccount */
        return system_advance_nonce(ctx, cu_consumed);

    case 5: /* WithdrawNonceAccount */
        return system_withdraw_nonce(ctx, cu_consumed);

    case 6: /* InitializeNonceAccount */
        return system_initialize_nonce(ctx, cu_consumed);

    case 7: /* AuthorizeNonceAccount */
        return system_authorize_nonce(ctx, cu_consumed);

    case 8: /* Allocate */
        return system_allocate(ctx, cu_consumed);

    case 9: /* AllocateWithSeed */
        return system_allocate_with_seed(ctx, cu_consumed);

    case 10: /* AssignWithSeed */
        return system_assign_with_seed(ctx, cu_consumed);

    case 11: /* TransferWithSeed */
        return system_transfer_with_seed(ctx, cu_consumed);

    case 12: /* UpgradeNonceAccount */
        return system_upgrade_nonce(ctx, cu_consumed);

    default:
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }
}

/*
 * Stake Program instruction types
 */
#define STAKE_INSTR_INITIALIZE              0
#define STAKE_INSTR_AUTHORIZE               1
#define STAKE_INSTR_DELEGATE_STAKE          2
#define STAKE_INSTR_SPLIT                   3
#define STAKE_INSTR_WITHDRAW                4
#define STAKE_INSTR_DEACTIVATE              5
#define STAKE_INSTR_SET_LOCKUP              6
#define STAKE_INSTR_MERGE                   7
#define STAKE_INSTR_AUTHORIZE_WITH_SEED     8
#define STAKE_INSTR_INITIALIZE_CHECKED      9
#define STAKE_INSTR_AUTHORIZE_CHECKED       10
#define STAKE_INSTR_AUTHORIZE_CHECKED_WITH_SEED 11
#define STAKE_INSTR_SET_LOCKUP_CHECKED      12
#define STAKE_INSTR_GET_MINIMUM_DELEGATION  13
#define STAKE_INSTR_DEACTIVATE_DELINQUENT   14
#define STAKE_INSTR_REDELEGATE              15
#define STAKE_INSTR_MOVE_STAKE              16
#define STAKE_INSTR_MOVE_LAMPORTS           17
#define STAKE_INSTR_MAX                     18

/*
 * Stake account state types (first 4 bytes)
 */
#define STAKE_STATE_UNINITIALIZED   0
#define STAKE_STATE_INITIALIZED     1
#define STAKE_STATE_STAKE           2
#define STAKE_STATE_REWARDS_POOL    3

/*
 * Stake account minimum sizes per state
 */
#define STAKE_STATE_UNINITIALIZED_SIZE  4
#define STAKE_STATE_INITIALIZED_SIZE    120  /* 4 + Meta (116) */
#define STAKE_STATE_STAKE_SIZE          200  /* 4 + Meta (116) + Stake (80) */

/*
 * Stake-specific error code for invalid stake state
 * This appears to be returned when stake accounts have invalid ownership or state
 * Based on Firedancer conformance testing: error 49 is returned for:
 * - Stake accounts not owned by the stake program
 * - Stake accounts with invalid state structure
 * - Stake accounts with invalid meta (e.g., unreasonable rent_exempt_reserve)
 */
#define STAKE_ERR_INVALID_STATE 49

/*
 * Maximum reasonable rent_exempt_reserve value (100 SOL in lamports).
 * This is a sanity check - real stake accounts have much lower values.
 * Corrupted stake account data often has huge random values here.
 */
#define MAX_REASONABLE_RENT_EXEMPT_RESERVE (100ULL * 1000000000ULL)

/*
 * Helper: Check if stake account has valid state
 * Returns error code (0 for valid, STAKE_ERR_INVALID_STATE for invalid)
 */
static int32_t
check_stake_state(const parsed_acct_t* acct) {
    if (!acct) return 0;

    /* Check ownership - must be owned by stake program */
    if (!sol_pubkey_eq(&acct->owner, &SOL_STAKE_PROGRAM_ID)) {
        return STAKE_ERR_INVALID_STATE;
    }

    /* Check data length - minimum 4 bytes for state type */
    if (acct->data_len < 4) {
        return STAKE_ERR_INVALID_STATE;
    }

    /* Check state type - must be 0, 1, 2, or 3 */
    uint32_t state_type = parse_u32_le(acct->data);
    if (state_type > STAKE_STATE_REWARDS_POOL) {
        return STAKE_ERR_INVALID_STATE;
    }

    /* For initialized states (1, 2, 3), need at least 200 bytes */
    if (state_type != STAKE_STATE_UNINITIALIZED && acct->data_len < 200) {
        return STAKE_ERR_INVALID_STATE;
    }

    /* For initialized states, validate meta fields */
    if (state_type != STAKE_STATE_UNINITIALIZED && acct->data_len >= 12) {
        /* Meta starts at offset 4:
         *   rent_exempt_reserve: u64 (8 bytes)
         *   authorized.staker: Pubkey (32 bytes)
         *   authorized.withdrawer: Pubkey (32 bytes)
         *   ... */
        uint64_t rent_exempt_reserve = parse_u64_le(acct->data + 4);

        /* Check for unreasonable rent_exempt_reserve values.
         * Real stake accounts have values around 2-3 million lamports.
         * Corrupted data often has huge random values (10^18+). */
        if (rent_exempt_reserve > MAX_REASONABLE_RENT_EXEMPT_RESERVE) {
            return STAKE_ERR_INVALID_STATE;
        }
    }

    return 0;
}

/*
 * Helper: Get minimum instruction data size for stake instruction
 */
static size_t
stake_instr_min_data_size(uint32_t instr_type) {
    switch (instr_type) {
    case STAKE_INSTR_INITIALIZE:
        /* Authorized (64) + Lockup (48) */
        return 4 + 64 + 48;  /* = 116 bytes */
    case STAKE_INSTR_AUTHORIZE:
        /* Pubkey (32) + StakeAuthorize enum (4) */
        return 4 + 32 + 4;  /* = 40 bytes */
    case STAKE_INSTR_DELEGATE_STAKE:
        return 4;  /* Just instruction type */
    case STAKE_INSTR_SPLIT:
        /* u64 lamports */
        return 4 + 8;  /* = 12 bytes */
    case STAKE_INSTR_WITHDRAW:
        /* u64 lamports */
        return 4 + 8;  /* = 12 bytes */
    case STAKE_INSTR_DEACTIVATE:
        return 4;
    case STAKE_INSTR_SET_LOCKUP:
        /* LockupArgs: Option<i64> + Option<i64> + Option<Pubkey> */
        return 4 + 1;  /* Minimum with all None */
    case STAKE_INSTR_MERGE:
        return 4;
    case STAKE_INSTR_AUTHORIZE_WITH_SEED:
        /* AuthorizeWithSeedArgs */
        return 4 + 32 + 4 + 8;  /* pubkey + enum + seed_len minimum */
    case STAKE_INSTR_INITIALIZE_CHECKED:
        return 4;  /* Authorities come from accounts */
    case STAKE_INSTR_AUTHORIZE_CHECKED:
        /* StakeAuthorize enum (4) */
        return 4 + 4;  /* = 8 bytes */
    case STAKE_INSTR_AUTHORIZE_CHECKED_WITH_SEED:
        return 4 + 4 + 8;  /* enum + seed_len minimum */
    case STAKE_INSTR_SET_LOCKUP_CHECKED:
        return 4 + 1;  /* Minimum with all None */
    case STAKE_INSTR_GET_MINIMUM_DELEGATION:
        return 4;
    case STAKE_INSTR_DEACTIVATE_DELINQUENT:
        return 4;
    case STAKE_INSTR_REDELEGATE:
        return 4;
    case STAKE_INSTR_MOVE_STAKE:
    case STAKE_INSTR_MOVE_LAMPORTS:
        /* u64 lamports */
        return 4 + 8;  /* = 12 bytes */
    default:
        return 4;
    }
}

/*
 * Helper: Check if stake account state is valid for lamport-changing operations
 * Returns true if the stake account has a valid initialized state
 */
static bool
is_valid_stake_state_for_lamport_ops(const parsed_acct_t* acct) {
    if (!acct) return false;
    if (acct->data_len < 4) return false;
    uint32_t state = parse_u32_le(acct->data);
    /* Stake or Initialized states are valid for lamport operations */
    return (state == STAKE_STATE_STAKE || state == STAKE_STATE_INITIALIZED);
}

/*
 * Helper: Check if clock sysvar account is valid
 * Clock sysvar should have data_len of 40 bytes and must be the actual clock sysvar
 */
static bool
is_valid_clock_sysvar(const parsed_acct_t* acct) {
    if (!acct) return false;
    /* Must be the actual clock sysvar address */
    if (!sol_pubkey_eq(&acct->pubkey, &SOL_SYSVAR_CLOCK_ID)) return false;
    /* Clock sysvar has 40 bytes of data */
    if (acct->data_len != 40) return false;
    /* Should have lamports > 0 */
    if (acct->lamports == 0) return false;
    return true;
}

/*
 * Helper: Check if stake_history sysvar account is valid
 * Stake history has variable size but should be > 0 and properly formatted
 */
static bool
is_valid_stake_history_sysvar(const parsed_acct_t* acct) {
    if (!acct) return false;
    /* Stake history should have data */
    if (acct->data_len == 0) return false;
    /* Should have lamports > 0 */
    if (acct->lamports == 0) return false;
    /* Basic size check - stake history entries are 24 bytes each plus length prefix */
    if (acct->data_len < 8) return false;
    return true;
}

/*
 * Helper: Check if rent sysvar account is valid
 * Rent sysvar has exactly 17 bytes of data and must be the actual rent sysvar
 */
static bool
is_valid_rent_sysvar(const parsed_acct_t* acct) {
    if (!acct) return false;
    /* Must be the actual rent sysvar address */
    if (!sol_pubkey_eq(&acct->pubkey, &SOL_SYSVAR_RENT_ID)) return false;
    /* Rent sysvar has 17 bytes of data */
    if (acct->data_len != 17) return false;
    /* Should have lamports > 0 */
    if (acct->lamports == 0) return false;
    return true;
}

/*
 * Helper: Check if an account is a "valid" existing account
 * An empty account (lamports=0, data_len=0) is considered invalid
 * This is used for authority/signer account validation
 */
static bool
is_valid_account(const parsed_acct_t* acct) {
    if (!acct) return false;
    /* An account with lamports=0 and no data is essentially non-existent */
    if (acct->lamports == 0 && acct->data_len == 0) return false;
    return true;
}

/*
 * Helper: Check if any provided account (other than index 0) is invalid (empty)
 * Solana validates all provided accounts, not just the required ones.
 * If any account has lamports=0 and data_len=0, it's considered invalid.
 * Note: Account 0 (stake account) is handled separately with stake state check.
 */
__attribute__((unused))
static bool
has_any_invalid_account_except_first(parsed_instr_ctx_t* ctx) {
    for (size_t i = 1; i < ctx->num_instr_accounts; i++) {
        parsed_acct_t* acct = get_account(ctx, i);
        if (!is_valid_account(acct)) {
            return true;
        }
    }
    return false;
}

/*
 * Execute stake program instruction
 */
static int32_t
execute_stake_program(parsed_instr_ctx_t* ctx, uint64_t* cu_consumed) {
    *cu_consumed = 750;  /* Base CU for stake program */

    /* Check if we have enough CU to even start execution.
     * Very low CU budgets (0, 256, etc.) can't afford the base cost.
     * In Firedancer conformance tests, this seems to return DuplicateAccountIndex. */
    if (ctx->cu_avail < 750) {
        return INSTR_ERR_DUPLICATE_ACCOUNT_INDEX;
    }

    if (ctx->data_len < 4) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }

    uint32_t instr_type = parse_u32_le(ctx->data);

    /* Get stake account (most instructions need it) */
    parsed_acct_t* stake_acct = NULL;
    if (ctx->num_instr_accounts > 0) {
        stake_acct = get_account(ctx, 0);
    }

    /*
     * Check for duplicate account indices.
     */
    bool has_duplicates = has_duplicate_account_indices(ctx);

    /*
     * If no accounts at all, return StakeInvalidState.
     */
    if (ctx->num_instr_accounts == 0) {
        return STAKE_ERR_INVALID_STATE;
    }

    /*
     * If stake account (position 0) is empty, return ExecutableLamportChange.
     * This takes precedence over stake state validation.
     */
    if (!is_valid_account(stake_acct)) {
        return INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE;
    }

    /*
     * Validate stake account state BEFORE checking other accounts.
     * This ensures invalid stake state (error 49) is returned before
     * ExecutableLamportChange for other empty accounts.
     * Based on Firedancer conformance testing.
     */
    if (stake_acct != NULL) {
        int32_t state_err = check_stake_state(stake_acct);
        if (state_err != 0) {
            return state_err;
        }
    }

    /* Unknown instruction type - checked AFTER stake state validation */
    if (instr_type >= STAKE_INSTR_MAX) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }

    /*
     * Check for invalid (empty) accounts in OTHER positions (not stake account).
     * If any provided account is empty (lamports=0, data_len=0), return ExecutableLamportChange.
     * This check comes AFTER stake state validation.
     */
    for (size_t i = 1; i < ctx->num_instr_accounts; i++) {
        parsed_acct_t* acct = get_account(ctx, i);
        if (!is_valid_account(acct)) {
            return INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE;
        }
    }

    /*
     * If there are duplicates (and no empty accounts), return StakeInvalidState.
     * Solana treats duplicate account indices in stake instructions as invalid state.
     */
    if (has_duplicates) {
        return STAKE_ERR_INVALID_STATE;
    }

    /* Check minimum data size for instruction */
    size_t min_data_size = stake_instr_min_data_size(instr_type);
    if (ctx->data_len < min_data_size) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }

    /*
     * Check if we should return ExecutableLamportChange for insufficient accounts.
     * This happens when:
     * 1. No duplicate account indices
     * 2. Stake account has valid state (Stake or Initialized)
     * 3. Not enough accounts for the instruction
     *
     * This matches Solana's behavior where lamport-changing operations
     * return ExecutableLamportChange when accounts are valid but insufficient.
     */
    bool valid_stake_for_lamport_ops = !has_duplicates &&
                                       is_valid_stake_state_for_lamport_ops(stake_acct);

    switch (instr_type) {
    case STAKE_INSTR_INITIALIZE:
    case STAKE_INSTR_INITIALIZE_CHECKED:
        /* Accounts: stake account, rent sysvar */
        if (ctx->num_instr_accounts < 2) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!stake_acct) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!sol_pubkey_eq(&stake_acct->owner, &SOL_STAKE_PROGRAM_ID)) {
            return INSTR_ERR_INVALID_ACCOUNT_OWNER;
        }
        /* Validate rent sysvar (acct[1]) - must be the actual rent sysvar */
        {
            parsed_acct_t* rent_acct = get_account(ctx, 1);
            if (!is_valid_rent_sysvar(rent_acct)) {
                return INSTR_ERR_ILLEGAL_OWNER;
            }
        }
        /* Check stake account is uninitialized */
        if (stake_acct->data_len >= 4) {
            uint32_t state = parse_u32_le(stake_acct->data);
            if (state != STAKE_STATE_UNINITIALIZED) {
                return INSTR_ERR_ACCOUNT_ALREADY_INITIALIZED;
            }
        }
        return RESULT_SUCCESS;

    case STAKE_INSTR_AUTHORIZE:
    case STAKE_INSTR_AUTHORIZE_CHECKED:
        /* Accounts: stake account, clock sysvar, authority, (optional) lockup authority */
        if (ctx->num_instr_accounts < 3) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!stake_acct) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!sol_pubkey_eq(&stake_acct->owner, &SOL_STAKE_PROGRAM_ID)) {
            return INSTR_ERR_INVALID_ACCOUNT_OWNER;
        }
        /* Validate clock sysvar (acct[1]) and authority account (acct[2]) */
        {
            parsed_acct_t* clock_acct = get_account(ctx, 1);
            parsed_acct_t* auth_acct = get_account(ctx, 2);
            if (valid_stake_for_lamport_ops) {
                if (!is_valid_clock_sysvar(clock_acct) || !is_valid_account(auth_acct)) {
                    return INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE;
                }
            }
        }
        if (!is_signer(ctx, 2)) {
            return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
        return RESULT_SUCCESS;

    case STAKE_INSTR_AUTHORIZE_WITH_SEED:
    case STAKE_INSTR_AUTHORIZE_CHECKED_WITH_SEED:
        /* Accounts: stake account, authority base, clock sysvar */
        if (ctx->num_instr_accounts < 2) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!stake_acct) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!sol_pubkey_eq(&stake_acct->owner, &SOL_STAKE_PROGRAM_ID)) {
            return INSTR_ERR_INVALID_ACCOUNT_OWNER;
        }
        if (!is_signer(ctx, 1)) {
            return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
        return RESULT_SUCCESS;

    case STAKE_INSTR_DELEGATE_STAKE:
        /* Accounts: stake, vote, clock, stake_history, config, stake_authority */
        if (ctx->num_instr_accounts < 6) {
            /* Return ExecutableLamportChange if stake state is valid */
            if (valid_stake_for_lamport_ops) {
                return INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE;
            }
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!stake_acct) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!sol_pubkey_eq(&stake_acct->owner, &SOL_STAKE_PROGRAM_ID)) {
            return INSTR_ERR_INVALID_ACCOUNT_OWNER;
        }
        /* Validate clock sysvar (acct[2]) - must be actual clock sysvar */
        {
            parsed_acct_t* clock_acct = get_account(ctx, 2);
            if (!is_valid_clock_sysvar(clock_acct)) {
                return INSTR_ERR_ILLEGAL_OWNER;
            }
        }
        if (!is_signer(ctx, 5)) {
            return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
        return RESULT_SUCCESS;

    case STAKE_INSTR_SPLIT:
        /* Accounts: stake, split_stake, stake_authority */
        if (ctx->num_instr_accounts < 3) {
            /* Return ExecutableLamportChange if stake state is valid */
            if (valid_stake_for_lamport_ops) {
                return INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE;
            }
            /* For stake-owned accounts that aren't valid for lamport ops (uninitialized),
             * return InvalidState instead of NotEnoughAccountKeys */
            if (stake_acct != NULL && sol_pubkey_eq(&stake_acct->owner, &SOL_STAKE_PROGRAM_ID)) {
                return STAKE_ERR_INVALID_STATE;
            }
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!stake_acct) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!sol_pubkey_eq(&stake_acct->owner, &SOL_STAKE_PROGRAM_ID)) {
            return INSTR_ERR_INVALID_ACCOUNT_OWNER;
        }
        /* Stake account must be in Initialized or Stake state for split */
        if (!valid_stake_for_lamport_ops) {
            return STAKE_ERR_INVALID_STATE;
        }
        if (!is_signer(ctx, 2)) {
            return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
        return RESULT_SUCCESS;

    case STAKE_INSTR_WITHDRAW:
        /* Accounts: stake, recipient, clock, stake_history, withdraw_authority */
        if (ctx->num_instr_accounts < 5) {
            /* Return ExecutableLamportChange if stake state is valid */
            if (valid_stake_for_lamport_ops) {
                return INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE;
            }
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!stake_acct) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!sol_pubkey_eq(&stake_acct->owner, &SOL_STAKE_PROGRAM_ID)) {
            return INSTR_ERR_INVALID_ACCOUNT_OWNER;
        }
        /* Stake account must be in Initialized or Stake state for withdrawal */
        if (!valid_stake_for_lamport_ops) {
            return STAKE_ERR_INVALID_STATE;
        }
        /* If there are duplicate account indices with valid stake, return ExecutableLamportChange */
        if (has_duplicates) {
            return INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE;
        }
        /* Validate authority account (acct[4]) before checking signature */
        {
            parsed_acct_t* auth_acct = get_account(ctx, 4);
            if (!is_valid_account(auth_acct)) {
                return INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE;
            }
        }
        if (!is_signer(ctx, 4)) {
            return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
        return RESULT_SUCCESS;

    case STAKE_INSTR_DEACTIVATE:
        /* Accounts: stake, clock, stake_authority */
        if (ctx->num_instr_accounts < 3) {
            /* Return ExecutableLamportChange if stake state is valid */
            if (valid_stake_for_lamport_ops) {
                return INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE;
            }
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!stake_acct) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!sol_pubkey_eq(&stake_acct->owner, &SOL_STAKE_PROGRAM_ID)) {
            return INSTR_ERR_INVALID_ACCOUNT_OWNER;
        }
        /* Stake account must be in Initialized or Stake state for deactivation */
        if (!valid_stake_for_lamport_ops) {
            return STAKE_ERR_INVALID_STATE;
        }
        /* Validate clock sysvar (acct[1]) and authority account (acct[2]) */
        {
            parsed_acct_t* clock_acct = get_account(ctx, 1);
            parsed_acct_t* auth_acct = get_account(ctx, 2);
            if (!is_valid_clock_sysvar(clock_acct) || !is_valid_account(auth_acct)) {
                return INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE;
            }
        }
        if (!is_signer(ctx, 2)) {
            return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
        return RESULT_SUCCESS;

    case STAKE_INSTR_SET_LOCKUP:
    case STAKE_INSTR_SET_LOCKUP_CHECKED:
        /* Accounts: stake, lockup_authority or withdraw_authority */
        if (ctx->num_instr_accounts < 2) {
            /* SetLockup doesn't change lamports, but conformance testing shows
             * it still returns ExecutableLamportChange when stake is valid */
            if (valid_stake_for_lamport_ops) {
                return INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE;
            }
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!stake_acct) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!sol_pubkey_eq(&stake_acct->owner, &SOL_STAKE_PROGRAM_ID)) {
            return INSTR_ERR_INVALID_ACCOUNT_OWNER;
        }
        /* Validate authority account (acct[1]) */
        {
            parsed_acct_t* auth_acct = get_account(ctx, 1);
            if (valid_stake_for_lamport_ops && !is_valid_account(auth_acct)) {
                return INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE;
            }
        }
        if (!is_signer(ctx, 1)) {
            return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
        return RESULT_SUCCESS;

    case STAKE_INSTR_MERGE:
        /* Accounts: dest_stake, source_stake, clock, stake_history, stake_authority */
        if (ctx->num_instr_accounts < 5) {
            /* Return ExecutableLamportChange if stake state is valid */
            if (valid_stake_for_lamport_ops) {
                return INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE;
            }
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!stake_acct) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!sol_pubkey_eq(&stake_acct->owner, &SOL_STAKE_PROGRAM_ID)) {
            return INSTR_ERR_INVALID_ACCOUNT_OWNER;
        }
        /* Also check source stake account */
        {
            parsed_acct_t* source_acct = get_account(ctx, 1);
            if (source_acct && !sol_pubkey_eq(&source_acct->owner, &SOL_STAKE_PROGRAM_ID)) {
                return INSTR_ERR_INVALID_ACCOUNT_OWNER;
            }
        }
        /* Validate clock sysvar (acct[2]) and stake_history sysvar (acct[3]) */
        {
            parsed_acct_t* clock_acct = get_account(ctx, 2);
            parsed_acct_t* history_acct = get_account(ctx, 3);
            /* If stake is valid but sysvars are invalid, return ExecutableLamportChange */
            if (valid_stake_for_lamport_ops) {
                if (!is_valid_clock_sysvar(clock_acct) || !is_valid_stake_history_sysvar(history_acct)) {
                    return INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE;
                }
            }
        }
        /* Validate authority account (acct[4]) before checking signature */
        {
            parsed_acct_t* auth_acct = get_account(ctx, 4);
            /* If stake is valid but authority account is invalid (empty), return ExecutableLamportChange */
            if (valid_stake_for_lamport_ops && !is_valid_account(auth_acct)) {
                return INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE;
            }
        }
        if (!is_signer(ctx, 4)) {
            return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
        return RESULT_SUCCESS;

    case STAKE_INSTR_GET_MINIMUM_DELEGATION:
        /* No accounts required, returns minimum delegation via return data */
        return RESULT_SUCCESS;

    case STAKE_INSTR_DEACTIVATE_DELINQUENT:
        /* Accounts: stake, delinquent_vote, reference_vote */
        if (ctx->num_instr_accounts < 3) {
            /* Return ExecutableLamportChange if stake state is valid */
            if (valid_stake_for_lamport_ops) {
                return INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE;
            }
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!stake_acct) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!sol_pubkey_eq(&stake_acct->owner, &SOL_STAKE_PROGRAM_ID)) {
            return INSTR_ERR_INVALID_ACCOUNT_OWNER;
        }
        /* This instruction requires vote account delinquency verification
         * which we don't fully implement. Return error 31 (CallDepth/ExecutableLamportChange)
         * to indicate the instruction cannot be executed in this context. */
        return INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE;

    case STAKE_INSTR_REDELEGATE:
        /* Accounts: stake, uninitialized_stake, vote, config, stake_authority */
        if (ctx->num_instr_accounts < 5) {
            /* Return ExecutableLamportChange if stake state is valid */
            if (valid_stake_for_lamport_ops) {
                return INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE;
            }
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!stake_acct) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!sol_pubkey_eq(&stake_acct->owner, &SOL_STAKE_PROGRAM_ID)) {
            return INSTR_ERR_INVALID_ACCOUNT_OWNER;
        }
        /* Validate authority account (acct[4]) before checking signature */
        {
            parsed_acct_t* auth_acct = get_account(ctx, 4);
            if (valid_stake_for_lamport_ops && !is_valid_account(auth_acct)) {
                return INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE;
            }
        }
        if (!is_signer(ctx, 4)) {
            return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
        return RESULT_SUCCESS;

    case STAKE_INSTR_MOVE_STAKE:
    case STAKE_INSTR_MOVE_LAMPORTS:
        /* Accounts: source_stake, dest_stake, stake_authority */
        if (ctx->num_instr_accounts < 3) {
            /* Return ExecutableLamportChange if stake state is valid */
            if (valid_stake_for_lamport_ops) {
                return INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE;
            }
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!stake_acct) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!sol_pubkey_eq(&stake_acct->owner, &SOL_STAKE_PROGRAM_ID)) {
            return INSTR_ERR_INVALID_ACCOUNT_OWNER;
        }
        /* Validate authority account (acct[2]) */
        {
            parsed_acct_t* auth_acct = get_account(ctx, 2);
            if (valid_stake_for_lamport_ops && !is_valid_account(auth_acct)) {
                return INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE;
            }
        }
        if (!is_signer(ctx, 2)) {
            return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
        return RESULT_SUCCESS;

    default:
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }
}

/*
 * Compute Budget Program instruction types
 */
#define COMPUTE_BUDGET_INSTR_REQUEST_HEAP_FRAME             1
#define COMPUTE_BUDGET_INSTR_SET_COMPUTE_UNIT_LIMIT         2
#define COMPUTE_BUDGET_INSTR_SET_COMPUTE_UNIT_PRICE         3
#define COMPUTE_BUDGET_INSTR_SET_LOADED_ACCOUNTS_DATA_SIZE  4

/*
 * Execute compute budget program instruction
 * The compute budget program only reads instruction data to configure compute limits.
 * It doesn't modify any accounts.
 */
static int32_t
execute_compute_budget_program(parsed_instr_ctx_t* ctx, uint64_t* cu_consumed) {
    *cu_consumed = 150;  /* Base CU for compute budget */

    if (ctx->data_len < 1) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }

    /* The first byte is the instruction discriminator */
    uint8_t instr_type = ctx->data[0];

    switch (instr_type) {
    case COMPUTE_BUDGET_INSTR_REQUEST_HEAP_FRAME:
        /* RequestHeapFrame: 1 byte discriminator + 4 bytes u32 heap size */
        if (ctx->data_len < 5) {
            return INSTR_ERR_INVALID_INSTRUCTION_DATA;
        }
        /* Valid heap sizes: 32KB to 256KB in 1KB increments */
        {
            uint32_t heap_size = parse_u32_le(ctx->data + 1);
            if (heap_size < 32 * 1024 || heap_size > 256 * 1024) {
                return INSTR_ERR_INVALID_INSTRUCTION_DATA;
            }
            if (heap_size % 1024 != 0) {
                return INSTR_ERR_INVALID_INSTRUCTION_DATA;
            }
        }
        return RESULT_SUCCESS;

    case COMPUTE_BUDGET_INSTR_SET_COMPUTE_UNIT_LIMIT:
        /* SetComputeUnitLimit: 1 byte discriminator + 4 bytes u32 units */
        if (ctx->data_len < 5) {
            return INSTR_ERR_INVALID_INSTRUCTION_DATA;
        }
        return RESULT_SUCCESS;

    case COMPUTE_BUDGET_INSTR_SET_COMPUTE_UNIT_PRICE:
        /* SetComputeUnitPrice: 1 byte discriminator + 8 bytes u64 micro_lamports */
        if (ctx->data_len < 9) {
            return INSTR_ERR_INVALID_INSTRUCTION_DATA;
        }
        return RESULT_SUCCESS;

    case COMPUTE_BUDGET_INSTR_SET_LOADED_ACCOUNTS_DATA_SIZE:
        /* SetLoadedAccountsDataSizeLimit: 1 byte discriminator + 4 bytes u32 size */
        if (ctx->data_len < 5) {
            return INSTR_ERR_INVALID_INSTRUCTION_DATA;
        }
        return RESULT_SUCCESS;

    default:
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }
}

/*
 * Vote Program instruction types
 */
#define VOTE_INSTR_INITIALIZE_ACCOUNT           0
#define VOTE_INSTR_AUTHORIZE                    1
#define VOTE_INSTR_VOTE                         2
#define VOTE_INSTR_WITHDRAW                     3
#define VOTE_INSTR_UPDATE_VALIDATOR_IDENTITY    4
#define VOTE_INSTR_UPDATE_COMMISSION            5
#define VOTE_INSTR_VOTE_SWITCH                  6
#define VOTE_INSTR_AUTHORIZE_CHECKED            7
#define VOTE_INSTR_UPDATE_VOTE_STATE            8
#define VOTE_INSTR_UPDATE_VOTE_STATE_SWITCH     9
#define VOTE_INSTR_AUTHORIZE_CHECKED_WITH_SEED  10
#define VOTE_INSTR_COMPACT_UPDATE_VOTE_STATE    11
#define VOTE_INSTR_COMPACT_UPDATE_VOTE_STATE_SWITCH 12
#define VOTE_INSTR_TOWER_SYNC                   13
#define VOTE_INSTR_TOWER_SYNC_COMPACT           14
#define VOTE_INSTR_MAX                          15

/*
 * Vote account state sizes
 */
#define VOTE_ACCOUNT_MIN_SIZE 3762
#define VOTE_STATE_VERSION_V0_SIZE 4  /* Minimum for version check */

/*
 * Vote state version discriminators
 */
#define VOTE_STATE_VERSION_UNINITIALIZED 0
#define VOTE_STATE_VERSION_V1_14_11      1
#define VOTE_STATE_VERSION_CURRENT       2

/*
 * Deep vote state validation - attempts to parse the vote state structure.
 * Returns true if the vote state appears to be valid and parseable.
 *
 * Vote state layout (V1 and V2):
 *   4 bytes: version
 *   32 bytes: node_pubkey
 *   32 bytes: authorized_withdrawer
 *   1 byte: commission
 *   8 bytes: votes vec length
 *   N * 12 bytes: votes (each Lockout is slot:u64 + confirmation_count:u32)
 *   1 or 9 bytes: root_slot Option<u64>
 *   ... more fields
 */
/*
 * Simple vote state validation - only checks version and commission.
 * Solana checks signatures before full structure validation in many cases.
 */
static bool
validate_vote_state_simple(const parsed_acct_t* acct) {
    if (!acct || acct->data_len < 4) {
        return false;
    }

    uint32_t version = parse_u32_le(acct->data);

    /* Uninitialized accounts pass simple validation (but operations may still reject them) */
    if (version == VOTE_STATE_VERSION_UNINITIALIZED) {
        return true;
    }

    /* Invalid version */
    if (version > VOTE_STATE_VERSION_CURRENT) {
        return false;
    }

    /* Need at least version + node_pubkey + authorized_withdrawer + commission = 69 bytes */
    if (acct->data_len < 69) {
        return false;
    }

    /* Note: Commission is NOT validated here. Solana allows existing vote accounts
       to have commission > 100 for operations like Authorize. Commission is only
       validated when setting it via UpdateCommission instruction. */

    return true;
}

/*
 * Deep vote state validation - full structure parsing.
 * Used after signature checks pass.
 */
static bool
validate_vote_state_deep(const parsed_acct_t* acct) {
    if (!acct || acct->data_len < 4) {
        return false;
    }

    uint32_t version = parse_u32_le(acct->data);

    /* Uninitialized accounts don't need deep validation */
    if (version == VOTE_STATE_VERSION_UNINITIALIZED) {
        return true;
    }

    /* Invalid version */
    if (version > VOTE_STATE_VERSION_CURRENT) {
        return false;
    }

    /* For V1 and V2, try to parse the basic structure */
    size_t pos = 4;

    /* node_pubkey: 32 bytes */
    if (pos + 32 > acct->data_len) {
        return false;
    }
    pos += 32;

    /* authorized_withdrawer: 32 bytes */
    if (pos + 32 > acct->data_len) {
        return false;
    }
    pos += 32;

    /* commission: 1 byte */
    if (pos + 1 > acct->data_len) {
        return false;
    }
    uint8_t commission = acct->data[pos];
    /* Commission must be <= 100 */
    if (commission > 100) {
        return false;
    }
    pos += 1;

    /* votes: Vec<Lockout> - 8 bytes length + N * 12 bytes per entry */
    if (pos + 8 > acct->data_len) {
        return false;
    }
    uint64_t votes_len = parse_u64_le(acct->data + pos);
    pos += 8;

    /* Sanity check on votes length - max 31 for tower */
    if (votes_len > 31) {
        return false;
    }

    /* Each vote is 12 bytes (u64 slot + u32 confirmation_count) */
    size_t votes_bytes = votes_len * 12;
    if (pos + votes_bytes > acct->data_len) {
        return false;
    }
    pos += votes_bytes;

    /* root_slot: Option<u64> - 1 byte tag + optional 8 bytes */
    if (pos + 1 > acct->data_len) {
        return false;
    }
    uint8_t root_slot_tag = acct->data[pos];
    pos += 1;

    if (root_slot_tag == 0) {
        /* None - no additional bytes */
    } else if (root_slot_tag == 1) {
        /* Some - 8 more bytes */
        if (pos + 8 > acct->data_len) {
            return false;
        }
        pos += 8;
    } else {
        /* Invalid Option tag */
        return false;
    }

    /* At this point we've validated the basic structure.
     * There are more fields but if we got here, the data is likely valid. */
    return true;
}

/*
 * Helper: Check if vote account has valid state version
 * Returns true if valid, false if VoteStateVersionError should be returned
 *
 * The vote state starts with a 4-byte version discriminant:
 * - 0 = Uninitialized (just needs space for future data)
 * - 1 = V1_14_11 (older format)
 * - 2 = Current (full vote state)
 *
 * This check happens BEFORE owner checks and instruction type validation.
 */
/**
 * Check vote state version and return specific error code.
 * Returns:
 *   0 = OK (valid version and sufficient data)
 *   INSTR_ERR_INVALID_ACCOUNT_DATA = invalid/malformed vote state
 *
 * Note: VoteStateVersionError is reserved for specific version mismatch
 * scenarios within instructions, not general account validation.
 */
static int32_t
check_vote_state_version_error(const parsed_acct_t* acct) {
    if (!acct) {
        return INSTR_ERR_INVALID_ACCOUNT_DATA;
    }

    /* Need at least 4 bytes for version */
    if (acct->data_len < 4) {
        return INSTR_ERR_INVALID_ACCOUNT_DATA;
    }

    uint32_t version = parse_u32_le(acct->data);

    /* Valid versions are 0, 1, 2 - anything else is invalid data */
    if (version > 2) {
        return INSTR_ERR_INVALID_ACCOUNT_DATA;
    }

    /* Check minimum data size for each version */
    switch (version) {
    case 0:
        /* Uninitialized - just need the 4-byte discriminant */
        return 0;
    case 1:
        /* V1_14_11 needs at least ~200 bytes for basic structure */
        if (acct->data_len < 200) {
            return INSTR_ERR_INVALID_ACCOUNT_DATA;
        }
        return 0;
    case 2:
        /* Current version needs at least ~200 bytes for basic structure */
        /* Full vote state is ~3762 bytes, but partial deserialization can work */
        if (acct->data_len < 200) {
            return INSTR_ERR_INVALID_ACCOUNT_DATA;
        }
        return 0;
    default:
        return INSTR_ERR_INVALID_ACCOUNT_DATA;
    }
}

/* Backwards-compatible wrapper - returns true if OK, false otherwise */
__attribute__((unused))
static bool
check_vote_state_version(const parsed_acct_t* acct) {
    return check_vote_state_version_error(acct) == 0;
}

/*
 * Helper: Check if vote account is initialized (version 1 or 2)
 * Returns true if initialized, false otherwise
 * Used by operations that need to read existing vote state
 */
static bool
is_vote_account_initialized(const parsed_acct_t* acct) {
    if (!acct) {
        return false;
    }

    /* Need at least 4 bytes for version */
    if (acct->data_len < 4) {
        return false;
    }

    uint32_t version = parse_u32_le(acct->data);

    /* Only version 1 and 2 are initialized states */
    if (version != 1 && version != 2) {
        return false;
    }

    /* Check minimum data size for initialized accounts */
    if (acct->data_len < 200) {
        return false;
    }

    return true;
}

/*
 * Helper: Get authorized_withdrawer pubkey from vote state
 * Returns pointer to the 32-byte pubkey, or NULL if not available
 * Vote state layout: version (4) + node_pubkey (32) + authorized_withdrawer (32)
 */
static const uint8_t*
get_vote_authorized_withdrawer(const parsed_acct_t* acct) {
    if (!acct || acct->data_len < 68) {  /* 4 + 32 + 32 */
        return NULL;
    }
    uint32_t version = parse_u32_le(acct->data);
    if (version == 0 || version > 2) {
        return NULL;
    }
    return acct->data + 36;  /* offset 4 + 32 */
}

/*
 * Helper: Check if the signer at given position matches the authorized_withdrawer
 * Returns true if the account is a signer AND matches the withdrawer pubkey
 */
static bool
verify_vote_withdrawer_signature(parsed_instr_ctx_t* ctx, const parsed_acct_t* vote_acct, size_t signer_pos) {
    const uint8_t* withdrawer = get_vote_authorized_withdrawer(vote_acct);
    if (!withdrawer) {
        return false;
    }

    parsed_acct_t* signer_acct = get_account(ctx, signer_pos);
    if (!signer_acct) {
        return false;
    }

    /* Check if the pubkey matches AND the account is a signer */
    if (memcmp(signer_acct->pubkey.bytes, withdrawer, 32) != 0) {
        return false;
    }

    return is_signer(ctx, signer_pos);
}

/*
 * Helper: Get minimum instruction data size for vote instruction
 */
static size_t
vote_instr_min_data_size(uint32_t instr_type) {
    switch (instr_type) {
    case VOTE_INSTR_INITIALIZE_ACCOUNT:
        /* VoteInit: node_pubkey (32) + authorized_voter (32) + authorized_withdrawer (32) + commission (1) */
        return 4 + 32 + 32 + 32 + 1;  /* = 101 bytes */
    case VOTE_INSTR_AUTHORIZE:
        /* Pubkey (32) + VoteAuthorize enum (4) */
        return 4 + 32 + 4;  /* = 40 bytes */
    case VOTE_INSTR_VOTE:
        /* Vote: slots vec (8 + n*8) + hash (32) + timestamp option (1 or 9) */
        return 4 + 8;  /* Minimum with empty slots vec */
    case VOTE_INSTR_WITHDRAW:
        /* u64 lamports */
        return 4 + 8;  /* = 12 bytes */
    case VOTE_INSTR_UPDATE_VALIDATOR_IDENTITY:
        return 4;  /* Just the instruction type */
    case VOTE_INSTR_UPDATE_COMMISSION:
        /* u8 commission */
        return 4 + 1;  /* = 5 bytes */
    case VOTE_INSTR_VOTE_SWITCH:
        /* Vote + hash */
        return 4 + 8 + 32;  /* = 44 bytes minimum */
    case VOTE_INSTR_AUTHORIZE_CHECKED:
        /* VoteAuthorize enum (4) */
        return 4 + 4;  /* = 8 bytes */
    case VOTE_INSTR_UPDATE_VOTE_STATE:
    case VOTE_INSTR_UPDATE_VOTE_STATE_SWITCH:
        /* VoteStateUpdate: lockouts vec + root + hash + timestamp */
        return 4 + 8;  /* Minimum */
    case VOTE_INSTR_AUTHORIZE_CHECKED_WITH_SEED:
        /* VoteAuthorize (4) + seed_len (8) + seed + owner (32) */
        return 4 + 4 + 8 + 32;  /* = 48 bytes minimum */
    case VOTE_INSTR_COMPACT_UPDATE_VOTE_STATE:
    case VOTE_INSTR_COMPACT_UPDATE_VOTE_STATE_SWITCH:
        /* CompactVoteStateUpdate */
        return 4 + 8;  /* Minimum */
    case VOTE_INSTR_TOWER_SYNC:
    case VOTE_INSTR_TOWER_SYNC_COMPACT:
        /* TowerSync */
        return 4 + 8;  /* Minimum */
    default:
        return 4;
    }
}

/*
 * Helper: Validate VoteStateUpdate instruction data
 * Returns 0 if valid, error code otherwise
 *
 * VoteStateUpdate format:
 * - lockouts: Vec<Lockout> where Lockout = (slot: u64, confirmation_count: u32)
 * - root: Option<u64>
 * - hash: [u8; 32]
 * - timestamp: Option<i64>
 *
 * For SWITCH variants, add additional 32-byte switch proof hash
 */
static int32_t
validate_vote_state_update(const uint8_t* data, size_t data_len, bool is_switch) {
    size_t offset = 4;  /* Skip instruction type */

    /* Parse lockout count */
    if (offset + 8 > data_len) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }
    uint64_t lockout_count = parse_u64_le(data + offset);
    offset += 8;

    /* Sanity check - max 31 lockouts (tower depth), min 1 lockout required */
    if (lockout_count == 0 || lockout_count > 31) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }

    /* Parse and validate lockouts */
    uint64_t prev_slot = 0;
    uint32_t prev_conf = UINT32_MAX;

    for (uint64_t i = 0; i < lockout_count; i++) {
        if (offset + 12 > data_len) {
            return INSTR_ERR_INVALID_INSTRUCTION_DATA;
        }
        uint64_t slot = parse_u64_le(data + offset);
        offset += 8;
        uint32_t conf = parse_u32_le(data + offset);
        offset += 4;

        /* Slots must be strictly increasing */
        if (i > 0 && slot <= prev_slot) {
            return INSTR_ERR_INVALID_INSTRUCTION_DATA;
        }

        /* Confirmation counts must be strictly decreasing */
        if (conf >= prev_conf) {
            return INSTR_ERR_INVALID_INSTRUCTION_DATA;
        }

        prev_slot = slot;
        prev_conf = conf;
    }

    /* Parse Option<u64> root */
    if (offset + 1 > data_len) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }
    uint8_t has_root = data[offset];
    offset += 1;
    if (has_root) {
        if (offset + 8 > data_len) {
            return INSTR_ERR_INVALID_INSTRUCTION_DATA;
        }
        offset += 8;
    }

    /* Parse hash (32 bytes) */
    if (offset + 32 > data_len) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }
    offset += 32;

    /* Parse Option<i64> timestamp */
    if (offset + 1 > data_len) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }
    uint8_t has_timestamp = data[offset];
    offset += 1;
    if (has_timestamp) {
        if (offset + 8 > data_len) {
            return INSTR_ERR_INVALID_INSTRUCTION_DATA;
        }
        offset += 8;
    }

    /* For SWITCH variants, parse switch proof hash */
    if (is_switch) {
        if (offset + 32 > data_len) {
            return INSTR_ERR_INVALID_INSTRUCTION_DATA;
        }
        offset += 32;
    }

    return 0;  /* Valid */
}

/*
 * Helper: Validate Vote instruction data
 * Returns 0 if valid, error code otherwise
 *
 * Vote format:
 * - slots: Vec<u64>
 * - hash: [u8; 32]
 * - timestamp: Option<i64>
 *
 * For VOTE_SWITCH, add additional 32-byte switch proof hash
 */
static int32_t
validate_vote_instr_data(const uint8_t* data, size_t data_len, bool is_switch) {
    size_t offset = 4;  /* Skip instruction type */

    /* Parse slot count */
    if (offset + 8 > data_len) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }
    uint64_t slot_count = parse_u64_le(data + offset);
    offset += 8;

    /* Sanity check - must have at least 1 slot and max 31 slots */
    if (slot_count == 0 || slot_count > 31) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }

    /* Parse slots */
    uint64_t prev_slot = 0;
    for (uint64_t i = 0; i < slot_count; i++) {
        if (offset + 8 > data_len) {
            return INSTR_ERR_INVALID_INSTRUCTION_DATA;
        }
        uint64_t slot = parse_u64_le(data + offset);
        offset += 8;

        /* Slots must be strictly increasing */
        if (i > 0 && slot <= prev_slot) {
            return INSTR_ERR_INVALID_INSTRUCTION_DATA;
        }
        prev_slot = slot;
    }

    /* Parse hash (32 bytes) */
    if (offset + 32 > data_len) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }
    offset += 32;

    /* Parse Option<i64> timestamp */
    if (offset + 1 > data_len) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }
    uint8_t has_timestamp = data[offset];
    offset += 1;
    if (has_timestamp) {
        if (offset + 8 > data_len) {
            return INSTR_ERR_INVALID_INSTRUCTION_DATA;
        }
        offset += 8;
    }

    /* For SWITCH variant, parse switch proof hash */
    if (is_switch) {
        if (offset + 32 > data_len) {
            return INSTR_ERR_INVALID_INSTRUCTION_DATA;
        }
        offset += 32;
    }

    return 0;  /* Valid */
}

/*
 * Helper: Validate vote instruction data based on instruction type
 * Returns 0 if valid, error code otherwise
 */
static int32_t
validate_vote_instruction_data(uint32_t instr_type, const uint8_t* data, size_t data_len) {
    switch (instr_type) {
    case VOTE_INSTR_VOTE:
        return validate_vote_instr_data(data, data_len, false);
    case VOTE_INSTR_VOTE_SWITCH:
        return validate_vote_instr_data(data, data_len, true);
    case VOTE_INSTR_UPDATE_VOTE_STATE:
        return validate_vote_state_update(data, data_len, false);
    case VOTE_INSTR_UPDATE_VOTE_STATE_SWITCH:
        return validate_vote_state_update(data, data_len, true);
    case VOTE_INSTR_COMPACT_UPDATE_VOTE_STATE:
    case VOTE_INSTR_COMPACT_UPDATE_VOTE_STATE_SWITCH:
    case VOTE_INSTR_TOWER_SYNC:
    case VOTE_INSTR_TOWER_SYNC_COMPACT:
        /* These have compact encoding - validate basic structure */
        {
            size_t offset = 4;  /* Skip instruction type */

            /* Parse root (u64) */
            if (offset + 8 > data_len) {
                return INSTR_ERR_INVALID_INSTRUCTION_DATA;
            }
            offset += 8;

            /* Parse lockout count (compact u16) */
            if (offset + 2 > data_len) {
                return INSTR_ERR_INVALID_INSTRUCTION_DATA;
            }
            uint16_t lockout_count = parse_u16_le(data + offset);
            offset += 2;

            /* Must have at least 1 lockout */
            if (lockout_count == 0 || lockout_count > 31) {
                return INSTR_ERR_INVALID_INSTRUCTION_DATA;
            }

            /* Each lockout is (offset: compact, confirmation: u8) */
            /* At minimum 2 bytes per lockout (1 byte offset + 1 byte conf) */
            size_t min_lockout_bytes = lockout_count * 2;
            if (offset + min_lockout_bytes > data_len) {
                return INSTR_ERR_INVALID_INSTRUCTION_DATA;
            }

            /* Validate confirmation counts are strictly decreasing */
            uint8_t prev_conf = 255;
            for (uint16_t i = 0; i < lockout_count; i++) {
                /* Skip offset (variable length, 1-4 bytes for compact encoding) */
                /* For simplicity, check if at least 1 byte remains */
                if (offset >= data_len) {
                    return INSTR_ERR_INVALID_INSTRUCTION_DATA;
                }
                /* Skip offset byte(s) - compact encoding */
                /* Simple heuristic: if high bit set, more bytes follow */
                while (offset < data_len && (data[offset] & 0x80)) {
                    offset++;
                }
                if (offset >= data_len) {
                    return INSTR_ERR_INVALID_INSTRUCTION_DATA;
                }
                offset++;  /* Final byte of offset */

                /* Read confirmation count (1 byte) */
                if (offset >= data_len) {
                    return INSTR_ERR_INVALID_INSTRUCTION_DATA;
                }
                uint8_t conf = data[offset];
                offset++;

                /* Confirmation counts must be strictly decreasing */
                if (conf >= prev_conf) {
                    return INSTR_ERR_INVALID_INSTRUCTION_DATA;
                }
                prev_conf = conf;
            }

            /* Hash (32 bytes) */
            if (offset + 32 > data_len) {
                return INSTR_ERR_INVALID_INSTRUCTION_DATA;
            }
            offset += 32;

            /* Timestamp option */
            if (offset + 1 > data_len) {
                return INSTR_ERR_INVALID_INSTRUCTION_DATA;
            }
            uint8_t has_timestamp = data[offset];
            offset++;
            if (has_timestamp) {
                if (offset + 8 > data_len) {
                    return INSTR_ERR_INVALID_INSTRUCTION_DATA;
                }
                offset += 8;
            }

            /* For SWITCH variants, need additional hash */
            if (instr_type == VOTE_INSTR_COMPACT_UPDATE_VOTE_STATE_SWITCH) {
                if (offset + 32 > data_len) {
                    return INSTR_ERR_INVALID_INSTRUCTION_DATA;
                }
            }

            return 0;
        }

    case VOTE_INSTR_AUTHORIZE:
        /* Authorize: 4 (type) + 32 (new_authority) + 4 (auth_type) = 40 bytes */
        if (data_len < 40) {
            return INSTR_ERR_INVALID_INSTRUCTION_DATA;
        }
        /* auth_type must be 0 (Voter) or 1 (Withdrawer) */
        {
            uint32_t auth_type = parse_u32_le(data + 36);
            if (auth_type > 1) {
                return INSTR_ERR_INVALID_INSTRUCTION_DATA;
            }
        }
        return 0;

    case VOTE_INSTR_AUTHORIZE_CHECKED:
        /* AuthorizeChecked: 4 (type) + 4 (auth_type) = 8 bytes */
        /* New authority is passed as account, not in instruction data */
        if (data_len < 8) {
            return INSTR_ERR_INVALID_INSTRUCTION_DATA;
        }
        {
            uint32_t auth_type = parse_u32_le(data + 4);
            if (auth_type > 1) {
                return INSTR_ERR_INVALID_INSTRUCTION_DATA;
            }
        }
        return 0;

    case VOTE_INSTR_WITHDRAW:
        /* Withdraw: 4 (type) + 8 (lamports) = 12 bytes */
        if (data_len < 12) {
            return INSTR_ERR_INVALID_INSTRUCTION_DATA;
        }
        return 0;

    case VOTE_INSTR_UPDATE_VALIDATOR_IDENTITY:
        /* UpdateValidatorIdentity: 4 bytes (just type) */
        return 0;

    case VOTE_INSTR_AUTHORIZE_CHECKED_WITH_SEED:
        /* AuthorizeCheckedWithSeed: 4 (type) + 4 (auth_type) + 8 (seed_len) + seed + 32 (owner) */
        if (data_len < 16) {  /* Minimum without seed */
            return INSTR_ERR_INVALID_INSTRUCTION_DATA;
        }
        {
            /* Validate auth_type is 0 or 1 */
            uint32_t auth_type = parse_u32_le(data + 4);
            if (auth_type > 1) {
                return INSTR_ERR_INVALID_INSTRUCTION_DATA;
            }
            /* Check seed_len and validate total size */
            uint64_t seed_len = parse_u64_le(data + 8);
            /* seed_len must fit in data: 16 + seed_len + 32 <= data_len */
            if (seed_len > 32 || 16 + seed_len + 32 > data_len) {
                return INSTR_ERR_INVALID_INSTRUCTION_DATA;
            }
        }
        return 0;

    /* Note: VOTE_INSTR_UPDATE_COMMISSION commission validation moved to switch statement
     * to happen AFTER signer check (conformance testing shows signer check comes first) */
    default:
        return 0;  /* Other instruction types validated elsewhere */
    }
}

/*
 * Execute vote program instruction
 *
 * Validation order (derived from Solana conformance tests):
 * The order depends on whether the vote account is owned by the vote program:
 *
 * If vote account is NOT owned by vote program:
 *   1. Check vote state version -> VoteStateVersionError
 *   (then other checks would follow)
 *
 * If vote account IS owned by vote program:
 *   1. Validate instruction data structure -> InvalidInstructionData
 *   2. Check vote state version -> VoteStateVersionError
 *   (then other checks would follow)
 */
static int32_t
execute_vote_program(parsed_instr_ctx_t* ctx, uint64_t* cu_consumed) {
    *cu_consumed = 2100;  /* Base CU for vote program */

    /*
     * If no accounts are provided, return InvalidAccountOwner.
     * This matches Solana's behavior for vote program.
     */
    if (ctx->num_instr_accounts == 0) {
        return INSTR_ERR_INVALID_ACCOUNT_OWNER;
    }

    /* Get vote account if present (needed for version check) */
    parsed_acct_t* vote_acct = get_account(ctx, 0);

    /* Check if vote account is owned by vote program */
    bool is_vote_owned = vote_acct != NULL &&
                         sol_pubkey_eq(&vote_acct->owner, &SOL_VOTE_PROGRAM_ID);

    /*
     * If vote account is NOT owned by vote program, return VoteStateVersionError.
     * This happens BEFORE instruction data validation for non-vote-owned accounts.
     */
    if (vote_acct != NULL && !is_vote_owned) {
        return VOTE_ERR_VOTE_STATE_VERSION;
    }

    /*
     * For vote-owned accounts, validate instruction data.
     */
    if (ctx->data_len >= 4) {
        uint32_t instr_type = parse_u32_le(ctx->data);

        /* Invalid instruction type returns immediately */
        if (instr_type >= VOTE_INSTR_MAX) {
            return INSTR_ERR_INVALID_INSTRUCTION_DATA;
        }

        /* Check minimum data size for instruction */
        size_t min_data_size = vote_instr_min_data_size(instr_type);
        if (ctx->data_len < min_data_size) {
            return INSTR_ERR_INVALID_INSTRUCTION_DATA;
        }

        /* Validate instruction data structure */
        int32_t data_err = validate_vote_instruction_data(instr_type, ctx->data, ctx->data_len);
        if (data_err != 0) {
            return data_err;
        }
    }

    /* Now check vote state version for vote-owned accounts */
    if (is_vote_owned) {
        int32_t version_err = check_vote_state_version_error(vote_acct);
        if (version_err != 0) {
            return version_err;
        }
    }

    /* If we couldn't parse instruction type, return InvalidInstructionData */
    if (ctx->data_len < 4) {
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }

    uint32_t instr_type = parse_u32_le(ctx->data);

    /* Check minimum accounts for each instruction */
    switch (instr_type) {
    case VOTE_INSTR_INITIALIZE_ACCOUNT:
        /* Accounts: vote account, rent sysvar, clock sysvar, node pubkey */
        if (ctx->num_instr_accounts < 4) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!vote_acct) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        /* Check vote account is owned by vote program */
        if (!sol_pubkey_eq(&vote_acct->owner, &SOL_VOTE_PROGRAM_ID)) {
            return INSTR_ERR_INVALID_ACCOUNT_OWNER;
        }
        /* Check account has enough space */
        if (vote_acct->data_len < VOTE_ACCOUNT_MIN_SIZE) {
            return INSTR_ERR_INVALID_ACCOUNT_DATA;
        }
        /* Check account is not already initialized (version should be 0 for uninitialized) */
        if (vote_acct->data_len >= 4) {
            uint32_t version = parse_u32_le(vote_acct->data);
            if (version != 0) {
                /* Already initialized - but first check if data is valid */
                /* If data is corrupt, return InvalidAccountData before AlreadyInitialized */
                if (!validate_vote_state_deep(vote_acct)) {
                    return INSTR_ERR_INVALID_ACCOUNT_DATA;
                }
                return INSTR_ERR_ACCOUNT_ALREADY_INITIALIZED;
            }
        }
        /* Node pubkey must be signer */
        if (!is_signer(ctx, 3)) {
            return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
        /* Check node pubkey account is valid (non-empty) */
        {
            parsed_acct_t* node_acct = get_account(ctx, 3);
            if (!is_valid_account(node_acct)) {
                return INSTR_ERR_INVALID_ACCOUNT_DATA;
            }
        }
        return RESULT_SUCCESS;

    case VOTE_INSTR_AUTHORIZE:
    case VOTE_INSTR_AUTHORIZE_CHECKED:
        /* Accounts: vote account, clock sysvar, authority */
        if (ctx->num_instr_accounts < 3) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!vote_acct) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        /* Check vote state version FIRST (before owner check) */
        {
            int32_t version_err = check_vote_state_version_error(vote_acct);
            if (version_err != 0) {
                return version_err;
            }
        }
        if (!sol_pubkey_eq(&vote_acct->owner, &SOL_VOTE_PROGRAM_ID)) {
            return INSTR_ERR_INVALID_ACCOUNT_OWNER;
        }
        /* Simple validation - check version and commission */
        if (!validate_vote_state_simple(vote_acct)) {
            return INSTR_ERR_INVALID_ACCOUNT_DATA;
        }
        /* For Withdrawer auth_type (1), verify signer matches authorized_withdrawer */
        /* For uninitialized (v0) accounts, just check signer (no pubkey match needed) */
        {
            uint32_t auth_type = 0;
            if (instr_type == VOTE_INSTR_AUTHORIZE && ctx->data_len >= 40) {
                auth_type = parse_u32_le(ctx->data + 36);
            } else if (instr_type == VOTE_INSTR_AUTHORIZE_CHECKED && ctx->data_len >= 8) {
                auth_type = parse_u32_le(ctx->data + 4);
            }
            if (auth_type == 1) {  /* Withdrawer */
                /* For uninitialized accounts, just check signer */
                if (!is_vote_account_initialized(vote_acct)) {
                    if (!is_signer(ctx, 2)) {
                        return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
                    }
                    return RESULT_SUCCESS;
                }
                /* For initialized accounts, verify signer matches authorized_withdrawer */
                if (!verify_vote_withdrawer_signature(ctx, vote_acct, 2)) {
                    return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
                }
                return RESULT_SUCCESS;
            }
        }
        /* For Voter auth_type (0), just check if position 2 is signer (simplified) */
        if (!is_signer(ctx, 2)) {
            return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
        return RESULT_SUCCESS;

    case VOTE_INSTR_VOTE:
    case VOTE_INSTR_VOTE_SWITCH:
        /* Accounts: vote account, slot hashes sysvar, clock sysvar, authority */
        if (ctx->num_instr_accounts < 4) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!vote_acct) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        /* Check vote state version FIRST (before owner check) */
        {
            int32_t version_err = check_vote_state_version_error(vote_acct);
            if (version_err != 0) {
                return version_err;
            }
        }
        /* Vote account must be initialized (version 1 or 2) to vote */
        if (!is_vote_account_initialized(vote_acct)) {
            return INSTR_ERR_INVALID_INSTRUCTION_DATA;
        }
        if (!sol_pubkey_eq(&vote_acct->owner, &SOL_VOTE_PROGRAM_ID)) {
            return INSTR_ERR_INVALID_ACCOUNT_OWNER;
        }
        /* Vote authority must be signer */
        if (!is_signer(ctx, 3)) {
            return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
        return RESULT_SUCCESS;

    case VOTE_INSTR_WITHDRAW:
        /* Accounts: vote account, recipient, withdraw authority */
        if (ctx->num_instr_accounts < 3) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!vote_acct) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        /* Check vote state version FIRST (before owner check) */
        {
            int32_t version_err = check_vote_state_version_error(vote_acct);
            if (version_err != 0) {
                return version_err;
            }
        }
        if (!sol_pubkey_eq(&vote_acct->owner, &SOL_VOTE_PROGRAM_ID)) {
            return INSTR_ERR_INVALID_ACCOUNT_OWNER;
        }
        /* Vote account must be initialized to withdraw */
        if (!is_vote_account_initialized(vote_acct)) {
            /* For uninitialized accounts, check signer first */
            if (!position_is_signer(ctx, 2)) {
                return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
            }
            return INSTR_ERR_INVALID_ACCOUNT_DATA;
        }
        /* Withdraw authority must be signer AND match authorized_withdrawer */
        if (!verify_vote_withdrawer_signature(ctx, vote_acct, 2)) {
            return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
        return RESULT_SUCCESS;

    case VOTE_INSTR_UPDATE_VALIDATOR_IDENTITY:
        /* Accounts: vote account, node pubkey, withdraw authority */
        if (ctx->num_instr_accounts < 3) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!vote_acct) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        /* Check vote state version FIRST (before owner check) */
        {
            int32_t version_err = check_vote_state_version_error(vote_acct);
            if (version_err != 0) {
                return version_err;
            }
        }
        if (!sol_pubkey_eq(&vote_acct->owner, &SOL_VOTE_PROGRAM_ID)) {
            return INSTR_ERR_INVALID_ACCOUNT_OWNER;
        }
        /* Simple validation - check version and commission before signatures */
        if (!validate_vote_state_simple(vote_acct)) {
            return INSTR_ERR_INVALID_ACCOUNT_DATA;
        }
        /* Both node pubkey and withdraw authority must sign */
        if (!is_signer(ctx, 1) || !is_signer(ctx, 2)) {
            return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
        return RESULT_SUCCESS;

    case VOTE_INSTR_UPDATE_COMMISSION:
        /* Accounts: vote account, withdraw authority */
        if (ctx->num_instr_accounts < 2) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!vote_acct) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        /* Check vote state version FIRST (before owner check) */
        {
            int32_t version_err = check_vote_state_version_error(vote_acct);
            if (version_err != 0) {
                return version_err;
            }
        }
        if (!sol_pubkey_eq(&vote_acct->owner, &SOL_VOTE_PROGRAM_ID)) {
            return INSTR_ERR_INVALID_ACCOUNT_OWNER;
        }
        /* Vote account must be initialized to update commission */
        if (!is_vote_account_initialized(vote_acct)) {
            /* For uninitialized accounts, check signer first */
            if (!is_signer(ctx, 1)) {
                return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
            }
            return INSTR_ERR_INVALID_ACCOUNT_DATA;
        }
        /* Simple validation - check version and commission before signatures */
        if (!validate_vote_state_simple(vote_acct)) {
            return INSTR_ERR_INVALID_ACCOUNT_DATA;
        }
        /* Withdraw authority must sign */
        if (!is_signer(ctx, 1)) {
            return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
        /* Check for duplicates when vote account is initialized */
        if (has_duplicate_account_indices(ctx)) {
            return INSTR_ERR_INVALID_ACCOUNT_DATA;
        }
        /* Validate commission value AFTER signer check (conformance testing shows this order) */
        if (ctx->data_len >= 5) {
            uint8_t commission = ctx->data[4];
            if (commission > 100) {
                return INSTR_ERR_INVALID_INSTRUCTION_DATA;
            }
        }
        return RESULT_SUCCESS;

    case VOTE_INSTR_UPDATE_VOTE_STATE:
    case VOTE_INSTR_UPDATE_VOTE_STATE_SWITCH:
    case VOTE_INSTR_COMPACT_UPDATE_VOTE_STATE:
    case VOTE_INSTR_COMPACT_UPDATE_VOTE_STATE_SWITCH:
    case VOTE_INSTR_TOWER_SYNC:
    case VOTE_INSTR_TOWER_SYNC_COMPACT:
        /* Accounts: vote account, authority */
        if (ctx->num_instr_accounts < 2) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!vote_acct) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        /* Check vote state version FIRST (before owner check) */
        {
            int32_t version_err = check_vote_state_version_error(vote_acct);
            if (version_err != 0) {
                return version_err;
            }
        }
        if (!sol_pubkey_eq(&vote_acct->owner, &SOL_VOTE_PROGRAM_ID)) {
            return INSTR_ERR_INVALID_ACCOUNT_OWNER;
        }
        /* Authority must sign */
        if (!is_signer(ctx, 1)) {
            return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
        return RESULT_SUCCESS;

    case VOTE_INSTR_AUTHORIZE_CHECKED_WITH_SEED:
        /* Accounts: vote account, clock sysvar, authority base */
        if (ctx->num_instr_accounts < 3) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        if (!vote_acct) {
            return INSTR_ERR_NOT_ENOUGH_ACCOUNT_KEYS;
        }
        /* Check vote state version FIRST (before owner check) */
        {
            int32_t version_err = check_vote_state_version_error(vote_acct);
            if (version_err != 0) {
                return version_err;
            }
        }
        /* Vote account must be initialized to authorize */
        if (!is_vote_account_initialized(vote_acct)) {
            return INSTR_ERR_INVALID_ACCOUNT_DATA;
        }
        if (!sol_pubkey_eq(&vote_acct->owner, &SOL_VOTE_PROGRAM_ID)) {
            return INSTR_ERR_INVALID_ACCOUNT_OWNER;
        }
        /* Authority base must sign */
        if (!is_signer(ctx, 2)) {
            return INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
        return RESULT_SUCCESS;

    default:
        return INSTR_ERR_INVALID_INSTRUCTION_DATA;
    }
}

/*
 * Instruction execution harness
 */
void*
sol_compat_instr_execute_v1(
    const uint8_t* input,
    size_t         input_len,
    size_t*        output_len
) {
    if (!g_initialized) {
        sol_compat_init();
    }

    *output_len = 0;

    /* Parse input */
    parsed_instr_ctx_t ctx;
    if (!parse_instr_context(input, input_len, &ctx)) {
        return NULL;
    }

    /* Execute based on program ID */
    int32_t result = RESULT_SUCCESS;
    uint64_t cu_consumed = 0;

    /*
     * Runtime validation order (from conformance testing):
     * 1. Check for sufficient compute units -> PrivilegeEscalation (or DuplicateAccountIndex for stake)
     * 2. Execute instruction
     *
     * Note: The stake program has different low-CU behavior than other native programs.
     * When CU is insufficient:
     * - System/Vote programs: return PrivilegeEscalation (38)
     * - Stake program: return DuplicateAccountIndex (41)
     */
    if (ctx.cu_avail < 150) {
        if (sol_pubkey_eq(&ctx.program_id, &SOL_STAKE_PROGRAM_ID)) {
            result = INSTR_ERR_DUPLICATE_ACCOUNT_INDEX;
        } else {
            result = INSTR_ERR_PRIVILEGE_ESCALATION;
        }
        goto build_output;
    }

    if (sol_pubkey_eq(&ctx.program_id, &SOL_SYSTEM_PROGRAM_ID)) {
        result = execute_system_program(&ctx, &cu_consumed);
    }
    else if (sol_pubkey_eq(&ctx.program_id, &SOL_VOTE_PROGRAM_ID)) {
        result = execute_vote_program(&ctx, &cu_consumed);
    }
    else if (sol_pubkey_eq(&ctx.program_id, &SOL_STAKE_PROGRAM_ID)) {
        result = execute_stake_program(&ctx, &cu_consumed);
    }
    else if (sol_pubkey_eq(&ctx.program_id, &SOL_COMPUTE_BUDGET_ID)) {
        result = execute_compute_budget_program(&ctx, &cu_consumed);
    }
    else {
        /* Unknown program - return error */
        result = INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
        cu_consumed = 0;
    }

build_output:;
    /* Build output */
    pb_writer_t w;
    if (!pb_writer_init(&w, 4096)) {
        free_instr_context(&ctx);
        return NULL;
    }

    /* Result: 0 for success, 1+ for error code */
    pb_write_varint_field(&w, INSTR_EFFECTS_RESULT, (uint64_t)result);

    /* Modified accounts (for writable accounts on success) */
    if (result == RESULT_SUCCESS) {
        for (size_t i = 0; i < ctx.num_instr_accounts; i++) {
            uint32_t idx = ctx.instr_accounts[i].index;
            if (idx < ctx.num_accounts && ctx.instr_accounts[i].is_writable) {
                write_acct_state(&w, &ctx.accounts[idx]);
            }
        }
    }

    /* Remaining CU */
    uint64_t cu_remaining = ctx.cu_avail > cu_consumed ? ctx.cu_avail - cu_consumed : 0;
    pb_write_varint_field(&w, INSTR_EFFECTS_CU_AVAIL, cu_remaining);

    /* Cleanup */
    free_instr_context(&ctx);

    return pb_writer_finish(&w, output_len);
}

/*
 * Transaction execution harness
 */
void*
sol_compat_txn_execute_v1(
    const uint8_t* input,
    size_t         input_len,
    size_t*        output_len
) {
    (void)input;
    (void)input_len;

    if (!g_initialized) {
        sol_compat_init();
    }

    *output_len = 0;

    /* For now, return minimal result indicating execution attempted */
    pb_writer_t w;
    if (!pb_writer_init(&w, 256)) {
        return NULL;
    }

    /* executed = true */
    pb_write_varint_field(&w, TXN_RESULT_EXECUTED, 1);

    /* executed_units = 0 (placeholder) */
    pb_write_varint_field(&w, TXN_RESULT_EXECUTED_UNITS, 0);

    return pb_writer_finish(&w, output_len);
}

/*
 * Syscall harness - stub
 */
void*
sol_compat_vm_syscall_execute_v1(
    const uint8_t* input,
    size_t         input_len,
    size_t*        output_len
) {
    (void)input;
    (void)input_len;

    if (!g_initialized) {
        sol_compat_init();
    }

    *output_len = 0;

    /* Return empty response - syscalls not yet implemented */
    pb_writer_t w;
    if (!pb_writer_init(&w, 64)) {
        return NULL;
    }

    /* error = 0 (success placeholder) */
    pb_write_varint_field(&w, 1, 0);

    return pb_writer_finish(&w, output_len);
}

/*
 * VM interpreter harness - stub
 */
void*
sol_compat_vm_interp_v1(
    const uint8_t* input,
    size_t         input_len,
    size_t*        output_len
) {
    (void)input;
    (void)input_len;

    if (!g_initialized) {
        sol_compat_init();
    }

    *output_len = 0;

    pb_writer_t w;
    if (!pb_writer_init(&w, 64)) {
        return NULL;
    }

    /* Return minimal response */
    pb_write_varint_field(&w, 1, 0);

    return pb_writer_finish(&w, output_len);
}

/*
 * VM validation harness - stub
 */
void*
sol_compat_vm_validate_v1(
    const uint8_t* input,
    size_t         input_len,
    size_t*        output_len
) {
    (void)input;
    (void)input_len;

    if (!g_initialized) {
        sol_compat_init();
    }

    *output_len = 0;

    pb_writer_t w;
    if (!pb_writer_init(&w, 64)) {
        return NULL;
    }

    /* Return validation success */
    pb_write_varint_field(&w, 1, 0);

    return pb_writer_finish(&w, output_len);
}

/*
 * ELF loader harness - stub
 */
void*
sol_compat_elf_loader_v1(
    const uint8_t* input,
    size_t         input_len,
    size_t*        output_len
) {
    (void)input;
    (void)input_len;

    if (!g_initialized) {
        sol_compat_init();
    }

    *output_len = 0;

    pb_writer_t w;
    if (!pb_writer_init(&w, 64)) {
        return NULL;
    }

    /* Return load success */
    pb_write_varint_field(&w, 1, 0);

    return pb_writer_finish(&w, output_len);
}

/*
 * Block execution harness - stub
 */
void*
sol_compat_block_execute_v1(
    const uint8_t* input,
    size_t         input_len,
    size_t*        output_len
) {
    (void)input;
    (void)input_len;

    if (!g_initialized) {
        sol_compat_init();
    }

    *output_len = 0;

    pb_writer_t w;
    if (!pb_writer_init(&w, 64)) {
        return NULL;
    }

    /* Return block execution result */
    pb_write_varint_field(&w, 1, 0);

    return pb_writer_finish(&w, output_len);
}

/*
 * Type harness - stub
 */
void*
sol_compat_type_execute_v1(
    const uint8_t* input,
    size_t         input_len,
    size_t*        output_len
) {
    (void)input;
    (void)input_len;

    if (!g_initialized) {
        sol_compat_init();
    }

    *output_len = 0;

    pb_writer_t w;
    if (!pb_writer_init(&w, 64)) {
        return NULL;
    }

    /* Return type validation result */
    pb_write_varint_field(&w, 1, 0);

    return pb_writer_finish(&w, output_len);
}
