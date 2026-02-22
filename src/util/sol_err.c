/*
 * sol_err.c - Error handling implementation
 */

#include "sol_err.h"
#include <string.h>

/*
 * Thread-local error context
 */
static SOL_THREAD_LOCAL sol_err_ctx_t g_err_ctx = { 0 };

/*
 * Error code to string
 */
const char*
sol_err_str(sol_err_t err) {
    switch (err) {
    /* Success */
    case SOL_OK:                        return "OK";

    /* General errors */
    case SOL_ERR_INVAL:                 return "Invalid argument";
    case SOL_ERR_NOMEM:                 return "Out of memory";
    case SOL_ERR_IO:                    return "I/O error";
    case SOL_ERR_TIMEOUT:               return "Timeout";
    case SOL_ERR_AGAIN:                 return "Try again";
    case SOL_ERR_BUSY:                  return "Resource busy";
    case SOL_ERR_NOTFOUND:              return "Not found";
    case SOL_ERR_EXISTS:                return "Already exists";
    case SOL_ERR_FULL:                  return "Container full";
    case SOL_ERR_EMPTY:                 return "Container empty";
    case SOL_ERR_OVERFLOW:              return "Overflow";
    case SOL_ERR_UNDERFLOW:             return "Underflow";
    case SOL_ERR_RANGE:                 return "Out of range";
    case SOL_ERR_PERM:                  return "Permission denied";
    case SOL_ERR_UNSUPPORTED:           return "Unsupported";
    case SOL_ERR_UNINITIALIZED:         return "Not initialized";
    case SOL_ERR_SHUTDOWN:              return "Shutting down";
    case SOL_ERR_CANCELLED:             return "Cancelled";

    /* Serialization errors */
    case SOL_ERR_PARSE:                 return "Parse error";
    case SOL_ERR_MALFORMED:             return "Malformed data";
    case SOL_ERR_TRUNCATED:             return "Data truncated";
    case SOL_ERR_TOO_LARGE:             return "Data too large";
    case SOL_ERR_ENCODING:              return "Encoding error";
    case SOL_ERR_DECODE:                return "Decoding error";
    case SOL_ERR_ENCODE:                return "Encoding error";

    /* Crypto errors */
    case SOL_ERR_CRYPTO:                return "Cryptographic error";
    case SOL_ERR_INVALID_SIGNATURE:     return "Invalid signature";
    case SOL_ERR_INVALID_PUBKEY:        return "Invalid public key";
    case SOL_ERR_INVALID_HASH:          return "Invalid hash";
    case SOL_ERR_VERIFICATION_FAILED:   return "Verification failed";

    /* Transaction errors */
    case SOL_ERR_TX_MALFORMED:          return "Malformed transaction";
    case SOL_ERR_TX_SIGNATURE:          return "Transaction signature failed";
    case SOL_ERR_TX_BLOCKHASH:          return "Blockhash not found";
    case SOL_ERR_TX_INSUFFICIENT_FUNDS: return "Insufficient funds";
    case SOL_ERR_TX_DUPLICATE:          return "Duplicate transaction";
    case SOL_ERR_TX_ACCOUNT_NOT_FOUND:  return "Account not found";
    case SOL_ERR_TX_ACCOUNT_LOCKED:     return "Account locked";
    case SOL_ERR_TX_PROGRAM_FAILED:     return "Program failed";
    case SOL_ERR_TX_TOO_LARGE:          return "Transaction too large";
    case SOL_ERR_TX_SANITIZE:           return "Transaction sanitization failed";
    case SOL_ERR_TX_NONCE:              return "Nonce error";
    case SOL_ERR_TX_ALREADY_PROCESSED:  return "Already processed";
    case SOL_ERR_TX_DUPLICATE_INSTR:    return "Duplicate instruction";
    case SOL_ERR_TX_INSUFFICIENT_FUNDS_FOR_RENT: return "Insufficient funds for rent";

    /* Account errors */
    case SOL_ERR_ACCOUNT_NOT_FOUND:     return "Account not found";
    case SOL_ERR_ACCOUNT_EXECUTABLE:    return "Account not executable";
    case SOL_ERR_ACCOUNT_NOT_EXECUTABLE:return "Account is executable";
    case SOL_ERR_ACCOUNT_DATA_TOO_SMALL:return "Account data too small";
    case SOL_ERR_ACCOUNT_DATA_TOO_LARGE:return "Account data too large";
    case SOL_ERR_ACCOUNT_NOT_OWNED:     return "Account not owned";
    case SOL_ERR_ACCOUNT_RENT:          return "Rent error";
    case SOL_ERR_ACCOUNT_LAMPORTS:      return "Lamport error";
    case SOL_ERR_ACCOUNT_BORROW:        return "Cannot borrow account";

    /* Program errors */
    case SOL_ERR_PROGRAM_NOT_FOUND:     return "Program not found";
    case SOL_ERR_PROGRAM_FAILED:        return "Program failed";
    case SOL_ERR_PROGRAM_COMPUTE:       return "Out of compute units";
    case SOL_ERR_PROGRAM_STACK:         return "Stack overflow";
    case SOL_ERR_PROGRAM_HEAP:          return "Heap error";
    case SOL_ERR_PROGRAM_MEMORY:        return "Memory access violation";
    case SOL_ERR_PROGRAM_CPI_DEPTH:     return "CPI depth exceeded";
    case SOL_ERR_PROGRAM_REENTRANCY:    return "Reentrancy not allowed";
    case SOL_ERR_PROGRAM_INVALID_INSTR: return "Invalid instruction";

    /* Consensus errors */
    case SOL_ERR_SLOT_SKIPPED:          return "Slot skipped";
    case SOL_ERR_FORK_DETECTED:         return "Fork detected";
    case SOL_ERR_VOTE_INVALID:          return "Invalid vote";
    case SOL_ERR_VOTE_LOCKOUT:          return "Vote lockout";
    case SOL_ERR_LEADER_SCHEDULE:       return "Leader schedule error";
    case SOL_ERR_SLOT_HASH_MISMATCH:    return "Slot hash mismatch";
    case SOL_ERR_DEAD_SLOT:             return "Dead slot";

    /* Storage errors */
    case SOL_ERR_BLOCKSTORE:            return "Blockstore error";
    case SOL_ERR_ACCOUNTS_DB:           return "AccountsDB error";
    case SOL_ERR_SNAPSHOT_CORRUPT:      return "Snapshot corrupt";
    case SOL_ERR_SNAPSHOT_MISMATCH:     return "Snapshot mismatch";
    case SOL_ERR_SHRED_INVALID:         return "Invalid shred";
    case SOL_ERR_FEC_RECOVERY:          return "FEC recovery failed";

    /* Network errors */
    case SOL_ERR_NET:                   return "Network error";
    case SOL_ERR_NET_CONNECT:           return "Connection failed";
    case SOL_ERR_NET_DISCONNECT:        return "Disconnected";
    case SOL_ERR_NET_TIMEOUT:           return "Network timeout";
    case SOL_ERR_GOSSIP_INVALID:        return "Invalid gossip";
    case SOL_ERR_PEER_UNAVAILABLE:      return "Peer unavailable";
    case SOL_ERR_REPAIR_FAILED:         return "Repair failed";

    /* BPF errors */
    case SOL_ERR_BPF_VERIFY:            return "BPF verification failed";
    case SOL_ERR_BPF_JIT:               return "JIT compilation failed";
    case SOL_ERR_BPF_EXECUTE:           return "BPF execution error";
    case SOL_ERR_BPF_SYSCALL:           return "BPF syscall error";
    case SOL_ERR_BPF_ELF:               return "ELF parse error";

    default:                            return "Unknown error";
    }
}

/*
 * Error context
 */
void
sol_err_ctx_set(sol_err_t code, const char* message,
                const char* file, int line, const char* func) {
    g_err_ctx.code = code;
    g_err_ctx.message = message;
    g_err_ctx.file = file;
    g_err_ctx.line = line;
    g_err_ctx.func = func;
}

const sol_err_ctx_t*
sol_err_ctx_get(void) {
    return &g_err_ctx;
}

void
sol_err_ctx_clear(void) {
    memset(&g_err_ctx, 0, sizeof(g_err_ctx));
}
