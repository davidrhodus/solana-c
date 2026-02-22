/*
 * sol_err.h - Error handling infrastructure
 *
 * All functions return sol_err_t error codes. This header defines
 * the error codes and helper macros for error propagation.
 */

#ifndef SOL_ERR_H
#define SOL_ERR_H

#include "sol_base.h"

/*
 * Error codes
 *
 * Negative values indicate errors, 0 is success.
 * Codes are grouped by category.
 */
typedef int sol_err_t;

/* Success */
#define SOL_OK                          0

/* General errors (-1 to -99) */
#define SOL_ERR_INVAL                  -1   /* Invalid argument */
#define SOL_ERR_NOMEM                  -2   /* Out of memory */
#define SOL_ERR_IO                     -3   /* I/O error */
#define SOL_ERR_TIMEOUT                -4   /* Operation timed out */
#define SOL_ERR_AGAIN                  -5   /* Try again (EAGAIN) */
#define SOL_ERR_BUSY                   -6   /* Resource busy */
#define SOL_ERR_NOTFOUND               -7   /* Item not found */
#define SOL_ERR_EXISTS                 -8   /* Item already exists */
#define SOL_ERR_FULL                   -9   /* Container full */
#define SOL_ERR_EMPTY                  -10  /* Container empty */
#define SOL_ERR_OVERFLOW               -11  /* Numeric overflow */
#define SOL_ERR_UNDERFLOW              -12  /* Numeric underflow */
#define SOL_ERR_RANGE                  -13  /* Out of range */
#define SOL_ERR_PERM                   -14  /* Permission denied */
#define SOL_ERR_UNSUPPORTED            -15  /* Unsupported operation */
#define SOL_ERR_UNINITIALIZED          -16  /* Not initialized */
#define SOL_ERR_SHUTDOWN               -17  /* Shutting down */
#define SOL_ERR_CANCELLED              -18  /* Operation cancelled */

/* Serialization errors (-100 to -199) */
#define SOL_ERR_PARSE                  -100 /* Parse error */
#define SOL_ERR_MALFORMED              -101 /* Malformed data */
#define SOL_ERR_TRUNCATED              -102 /* Data truncated */
#define SOL_ERR_TOO_LARGE              -103 /* Data too large */
#define SOL_ERR_ENCODING               -104 /* Encoding error */
#define SOL_ERR_DECODE                 -105 /* Decoding error */
#define SOL_ERR_ENCODE                 -106 /* Encoding error */

/* Cryptographic errors (-200 to -299) */
#define SOL_ERR_CRYPTO                 -200 /* Generic crypto error */
#define SOL_ERR_INVALID_SIGNATURE      -201 /* Invalid signature */
#define SOL_ERR_INVALID_PUBKEY         -202 /* Invalid public key */
#define SOL_ERR_INVALID_HASH           -203 /* Invalid hash */
#define SOL_ERR_VERIFICATION_FAILED    -204 /* Verification failed */

/* Transaction errors (-300 to -399) */
#define SOL_ERR_TX_MALFORMED           -300 /* Malformed transaction */
#define SOL_ERR_TX_SIGNATURE           -301 /* Signature verification failed */
#define SOL_ERR_TX_BLOCKHASH           -302 /* Blockhash not found/expired */
#define SOL_ERR_TX_INSUFFICIENT_FUNDS  -303 /* Insufficient funds for fee */
#define SOL_ERR_TX_DUPLICATE           -304 /* Duplicate transaction */
#define SOL_ERR_TX_ACCOUNT_NOT_FOUND   -305 /* Account not found */
#define SOL_ERR_TX_ACCOUNT_LOCKED      -306 /* Account locked by another tx */
#define SOL_ERR_TX_PROGRAM_FAILED      -307 /* Program execution failed */
#define SOL_ERR_TX_TOO_LARGE           -308 /* Transaction too large */
#define SOL_ERR_TX_SANITIZE            -309 /* Transaction failed sanitization */
#define SOL_ERR_TX_NONCE               -310 /* Nonce error */
#define SOL_ERR_TX_ALREADY_PROCESSED   -311 /* Transaction already processed */
#define SOL_ERR_TX_DUPLICATE_INSTR     -312 /* Duplicate ComputeBudget instruction */
#define SOL_ERR_TX_INSUFFICIENT_FUNDS_FOR_RENT -313 /* InsufficientFundsForRent */

/* Account errors (-400 to -499) */
#define SOL_ERR_ACCOUNT_NOT_FOUND      -400 /* Account not found */
#define SOL_ERR_ACCOUNT_EXECUTABLE     -401 /* Account not executable */
#define SOL_ERR_ACCOUNT_NOT_EXECUTABLE -402 /* Account is executable */
#define SOL_ERR_ACCOUNT_DATA_TOO_SMALL -403 /* Account data too small */
#define SOL_ERR_ACCOUNT_DATA_TOO_LARGE -404 /* Account data too large */
#define SOL_ERR_ACCOUNT_NOT_OWNED      -405 /* Account not owned by program */
#define SOL_ERR_ACCOUNT_RENT           -406 /* Account would be rent-exempt */
#define SOL_ERR_ACCOUNT_LAMPORTS       -407 /* Lamport balance error */
#define SOL_ERR_ACCOUNT_BORROW         -408 /* Cannot borrow account */

/* Program errors (-500 to -599) */
#define SOL_ERR_PROGRAM_NOT_FOUND      -500 /* Program not found */
#define SOL_ERR_PROGRAM_FAILED         -501 /* Program returned error */
#define SOL_ERR_PROGRAM_COMPUTE        -502 /* Out of compute units */
#define SOL_ERR_PROGRAM_STACK          -503 /* Stack overflow */
#define SOL_ERR_PROGRAM_HEAP           -504 /* Heap error */
#define SOL_ERR_PROGRAM_MEMORY         -505 /* Memory access violation */
#define SOL_ERR_PROGRAM_CPI_DEPTH      -506 /* CPI depth exceeded */
#define SOL_ERR_PROGRAM_REENTRANCY     -507 /* Reentrancy not allowed */
#define SOL_ERR_PROGRAM_INVALID_INSTR  -508 /* Invalid instruction */
#define SOL_ERR_PROGRAM_MISSING_SIGNATURE -509 /* Missing required signature */
#define SOL_ERR_PROGRAM_ACCOUNT_ALREADY_INIT -510 /* Account already initialized */
#define SOL_ERR_PROGRAM_INVALID_OWNER  -511 /* Invalid account owner */
#define SOL_ERR_PROGRAM_INSUFFICIENT_FUNDS -512 /* Insufficient lamports */
#define SOL_ERR_PROGRAM_ALREADY_DELEGATED -513 /* Stake already delegated */
#define SOL_ERR_PROGRAM_LOCKOUT        -514 /* Vote lockout violation */
#define SOL_ERR_PROGRAM_INVALID_STATE  -515 /* Invalid state transition */
#define SOL_ERR_PROGRAM_MAX_ACCOUNTS   -516 /* Max accounts exceeded */
#define SOL_ERR_PROGRAM_MISSING_ACCOUNT -517 /* Missing required account */
#define SOL_ERR_PROGRAM_INVALID_ACCOUNT -518 /* Invalid account state */
#define SOL_ERR_FROZEN                 -519 /* Account is frozen */
#define SOL_ERR_NOT_IMPLEMENTED        -520 /* Feature not implemented */
#define SOL_ERR_ALREADY_INITIALIZED    -521 /* Already initialized */
#define SOL_ERR_MISSING_SIGNATURE      -522 /* Missing required signature */
#define SOL_ERR_INSUFFICIENT_FUNDS     -523 /* Insufficient funds */
#define SOL_ERR_NOT_ENOUGH_KEYS        -524 /* Not enough account keys */

/* Consensus errors (-600 to -699) */
#define SOL_ERR_SLOT_SKIPPED           -600 /* Slot was skipped */
#define SOL_ERR_FORK_DETECTED          -601 /* Fork detected */
#define SOL_ERR_VOTE_INVALID           -602 /* Invalid vote */
#define SOL_ERR_VOTE_LOCKOUT           -603 /* Vote lockout violation */
#define SOL_ERR_LEADER_SCHEDULE        -604 /* Leader schedule error */
#define SOL_ERR_SLOT_HASH_MISMATCH     -605 /* Slot hash mismatch */
#define SOL_ERR_DEAD_SLOT              -606 /* Slot is dead */

/* Storage errors (-700 to -799) */
#define SOL_ERR_BLOCKSTORE             -700 /* Blockstore error */
#define SOL_ERR_ACCOUNTS_DB            -701 /* AccountsDB error */
#define SOL_ERR_SNAPSHOT_CORRUPT       -702 /* Snapshot corrupted */
#define SOL_ERR_SNAPSHOT_MISMATCH      -703 /* Snapshot hash mismatch */
#define SOL_ERR_SHRED_INVALID          -704 /* Invalid shred */
#define SOL_ERR_FEC_RECOVERY           -705 /* FEC recovery failed */

/* Network errors (-800 to -899) */
#define SOL_ERR_NET                    -800 /* Generic network error */
#define SOL_ERR_NET_CONNECT            -801 /* Connection failed */
#define SOL_ERR_NET_DISCONNECT         -802 /* Disconnected */
#define SOL_ERR_NET_TIMEOUT            -803 /* Network timeout */
#define SOL_ERR_GOSSIP_INVALID         -804 /* Invalid gossip message */
#define SOL_ERR_PEER_UNAVAILABLE       -805 /* Peer unavailable */
#define SOL_ERR_REPAIR_FAILED          -806 /* Repair request failed */
#define SOL_ERR_STALE                  -807 /* Stale data (older than existing) */

/* BPF VM errors (-900 to -999) */
#define SOL_ERR_BPF_VERIFY             -900 /* Bytecode verification failed */
#define SOL_ERR_BPF_JIT                -901 /* JIT compilation failed */
#define SOL_ERR_BPF_EXECUTE            -902 /* Execution error */
#define SOL_ERR_BPF_SYSCALL            -903 /* Syscall error */
#define SOL_ERR_BPF_ELF                -904 /* ELF parsing error */

/*
 * Error propagation macros
 */

/* Try expression, return on error */
#define SOL_TRY(expr) do { \
    sol_err_t _err = (expr); \
    if (sol_unlikely(_err != SOL_OK)) return _err; \
} while(0)

/* Try expression, goto label on error */
#define SOL_TRY_GOTO(expr, label) do { \
    sol_err_t _err = (expr); \
    if (sol_unlikely(_err != SOL_OK)) { err = _err; goto label; } \
} while(0)

/* Try expression, run cleanup on error */
#define SOL_TRY_CLEANUP(expr, cleanup) do { \
    sol_err_t _err = (expr); \
    if (sol_unlikely(_err != SOL_OK)) { cleanup; return _err; } \
} while(0)

/* Check condition, return error if false */
#define SOL_CHECK(cond, err_code) do { \
    if (sol_unlikely(!(cond))) return (err_code); \
} while(0)

/* Check non-null, return SOL_ERR_INVAL if null */
#define SOL_CHECK_NONNULL(ptr) SOL_CHECK((ptr) != NULL, SOL_ERR_INVAL)

/* Check allocation, return SOL_ERR_NOMEM if null */
#define SOL_CHECK_ALLOC(ptr) SOL_CHECK((ptr) != NULL, SOL_ERR_NOMEM)

/*
 * Error to string conversion
 */
SOL_PURE const char* sol_err_str(sol_err_t err);

/*
 * Check if error is success
 */
SOL_INLINE bool
sol_err_ok(sol_err_t err) {
    return err == SOL_OK;
}

/*
 * Check if error indicates a fatal condition
 */
SOL_INLINE bool
sol_err_is_fatal(sol_err_t err) {
    /* Memory and I/O errors are generally fatal */
    return err == SOL_ERR_NOMEM || err == SOL_ERR_IO;
}

/*
 * Check if error is transient (can retry)
 */
SOL_INLINE bool
sol_err_is_transient(sol_err_t err) {
    return err == SOL_ERR_AGAIN ||
           err == SOL_ERR_BUSY ||
           err == SOL_ERR_TIMEOUT ||
           err == SOL_ERR_NET_TIMEOUT;
}

/*
 * Extended error context (optional, for detailed error reporting)
 */
typedef struct {
    sol_err_t    code;
    const char*  message;
    const char*  file;
    int          line;
    const char*  func;
} sol_err_ctx_t;

/* Thread-local error context */
#define SOL_ERR_CTX_SET(err_code, msg) do { \
    sol_err_ctx_set((err_code), (msg), __FILE__, __LINE__, __func__); \
} while(0)

void sol_err_ctx_set(sol_err_t code, const char* message,
                     const char* file, int line, const char* func);
const sol_err_ctx_t* sol_err_ctx_get(void);
void sol_err_ctx_clear(void);

#endif /* SOL_ERR_H */
