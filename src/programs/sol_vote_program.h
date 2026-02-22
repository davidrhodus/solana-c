/*
 * sol_vote_program.h - Vote Program Implementation
 *
 * The Vote Program manages validator voting for Tower BFT consensus:
 * - Vote account creation and management
 * - Recording votes for slots
 * - Tracking vote history (lockouts)
 * - Commission settings for rewards
 */

#ifndef SOL_VOTE_PROGRAM_H
#define SOL_VOTE_PROGRAM_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../txn/sol_pubkey.h"
#include "../runtime/sol_bank.h"
#include "sol_system_program.h"

/*
 * Vote Program ID
 * Vote111111111111111111111111111111111111111
 */
extern const sol_pubkey_t SOL_VOTE_PROGRAM_ID;

/*
 * Maximum number of votes in history (lockout tower depth)
 */
#define SOL_MAX_LOCKOUT_HISTORY 31

/*
 * Maximum epoch credits history
 */
#define SOL_MAX_EPOCH_CREDITS_HISTORY 64

/*
 * Maximum authorized voter history entries stored in vote state.
 *
 * On-chain this is a BTreeMap<Epoch, Pubkey>. In practice it remains small and
 * is bounded by the fixed vote account data size.
 */
#define SOL_MAX_AUTHORIZED_VOTERS 32

/*
 * Initial lockout (2^1 = 2 slots)
 */
#define SOL_INITIAL_LOCKOUT 2

/*
 * Max lockout (2^31 slots)
 */
#define SOL_MAX_LOCKOUT_EXPONENT 31

/*
 * Vote instruction types
 */
typedef enum {
    SOL_VOTE_INSTR_INITIALIZE = 0,
    SOL_VOTE_INSTR_AUTHORIZE = 1,
    SOL_VOTE_INSTR_VOTE = 2,
    SOL_VOTE_INSTR_WITHDRAW = 3,
    SOL_VOTE_INSTR_UPDATE_VALIDATOR = 4,
    SOL_VOTE_INSTR_UPDATE_COMMISSION = 5,
    SOL_VOTE_INSTR_VOTE_SWITCH = 6,
    SOL_VOTE_INSTR_AUTHORIZE_CHECKED = 7,
    SOL_VOTE_INSTR_UPDATE_VALIDATOR_CHECKED = 8,
    SOL_VOTE_INSTR_AUTHORIZE_WITH_SEED = 9,
    SOL_VOTE_INSTR_AUTHORIZE_CHECKED_WITH_SEED = 10,
    SOL_VOTE_INSTR_UPDATE_VOTE_STATE = 11,
    SOL_VOTE_INSTR_UPDATE_VOTE_STATE_SWITCH = 12,
    SOL_VOTE_INSTR_COMPACT_UPDATE_VOTE_STATE = 13,
    SOL_VOTE_INSTR_COMPACT_UPDATE_VOTE_STATE_SWITCH = 14,
} sol_vote_instr_type_t;

/*
 * Vote authorization type
 */
typedef enum {
    SOL_VOTE_AUTHORIZE_VOTER = 0,
    SOL_VOTE_AUTHORIZE_WITHDRAWER = 1,
} sol_vote_authorize_t;

/*
 * Lockout (vote with confirmation count)
 */
typedef struct {
    sol_slot_t      slot;               /* Voted slot */
    uint32_t        confirmation_count; /* Number of confirmations */
} sol_lockout_t;

/*
 * Epoch credits entry
 */
typedef struct {
    uint64_t        epoch;
    uint64_t        credits;            /* Credits earned in epoch */
    uint64_t        prev_credits;       /* Credits at start of epoch */
} sol_epoch_credits_t;

/*
 * Authorized voter entry (epoch -> pubkey)
 */
typedef struct {
    uint64_t        epoch;
    sol_pubkey_t    pubkey;
} sol_authorized_voter_t;

/*
 * Prior voter entry (pubkey + epoch range)
 */
typedef struct {
    sol_pubkey_t    pubkey;
    uint64_t        start_epoch;
    uint64_t        end_epoch;
} sol_prior_voter_t;

/*
 * Vote state (stored in vote account data)
 */
typedef struct {
    /* On-chain vote state version discriminant (bincode VoteStateVersions).
     * 0 = uninitialized, 1 = V1_14_11 (no latency), 2 = current (with latency). */
    uint32_t        onchain_version;

    /* Node identity (validator pubkey) */
    sol_pubkey_t    node_pubkey;

    /* Authorized voter */
    sol_pubkey_t    authorized_voter;

    /* Authorized withdrawer */
    sol_pubkey_t    authorized_withdrawer;

    /* Commission percentage (0-100) */
    uint8_t         commission;

    /* Vote history (lockout tower) */
    sol_lockout_t   votes[SOL_MAX_LOCKOUT_HISTORY];
    uint8_t         votes_len;
    uint8_t         vote_latencies[SOL_MAX_LOCKOUT_HISTORY]; /* v2 only */

    /* Root slot (most recent finalized slot) */
    sol_slot_t      root_slot;
    bool            has_root;

    /* Authorized voters history (BTreeMap<Epoch, Pubkey>) */
    sol_authorized_voter_t authorized_voters[SOL_MAX_AUTHORIZED_VOTERS];
    uint8_t         authorized_voters_len;

    /* Prior voters circular buffer (32 fixed entries) */
    sol_prior_voter_t prior_voters[32];
    uint64_t        prior_voters_idx;
    bool            prior_voters_is_empty;

    /* Epoch credits history */
    sol_epoch_credits_t epoch_credits[SOL_MAX_EPOCH_CREDITS_HISTORY];
    uint8_t         epoch_credits_len;

    /* Last timestamp */
    uint64_t        last_timestamp_slot;
    int64_t         last_timestamp;
} sol_vote_state_t;

/*
 * Vote state versions
 */
typedef enum {
    SOL_VOTE_STATE_V0 = 0,      /* Legacy */
    SOL_VOTE_STATE_V1 = 1,      /* Current */
} sol_vote_state_version_t;

/*
 * Vote (for Vote instruction)
 */
typedef struct {
    sol_slot_t*     slots;              /* Array of voted slots */
    size_t          slots_len;
    sol_hash_t      hash;               /* Bank hash */
    uint64_t        timestamp;          /* Optional timestamp */
    bool            has_timestamp;
} sol_vote_t;

/*
 * Vote initialization data
 */
typedef struct {
    sol_pubkey_t    node_pubkey;        /* Validator identity */
    sol_pubkey_t    authorized_voter;   /* Initial voter authority */
    sol_pubkey_t    authorized_withdrawer; /* Initial withdraw authority */
    uint8_t         commission;         /* Commission percentage */
} sol_vote_init_t;

/*
 * Vote state size (approximate - actual is variable)
 */
#define SOL_VOTE_STATE_SIZE 3762

/*
 * Process a vote program instruction
 */
sol_err_t sol_vote_program_execute(sol_invoke_context_t* ctx);

/*
 * Initialize a vote state
 */
void sol_vote_state_init(
    sol_vote_state_t*       state,
    const sol_vote_init_t*  init
);

/*
 * Serialize vote state to account data
 */
sol_err_t sol_vote_state_serialize(
    const sol_vote_state_t* state,
    uint8_t*                data,
    size_t                  data_len,
    size_t*                 written
);

/*
 * Deserialize vote state from account data
 */
sol_err_t sol_vote_state_deserialize(
    sol_vote_state_t*   state,
    const uint8_t*      data,
    size_t              data_len
);

/*
 * Process a vote
 *
 * Updates the vote state with new votes, managing lockouts
 * according to Tower BFT rules.
 */
sol_err_t sol_vote_state_process_vote(
    sol_vote_state_t*   state,
    const sol_vote_t*   vote,
    sol_slot_t          current_slot,
    uint64_t            current_epoch
);

/*
 * Get the last voted slot
 */
sol_slot_t sol_vote_state_last_voted_slot(const sol_vote_state_t* state);

/*
 * Check if vote state contains a vote for slot
 */
bool sol_vote_state_contains_slot(
    const sol_vote_state_t* state,
    sol_slot_t              slot
);

/*
 * Get lockout for a slot
 */
uint64_t sol_vote_state_lockout(
    const sol_vote_state_t* state,
    sol_slot_t              slot
);

/*
 * Calculate credits earned from votes
 */
uint64_t sol_vote_state_credits(const sol_vote_state_t* state);

/*
 * Pop expired votes (votes that have reached max lockout)
 */
void sol_vote_state_pop_expired_votes(
    sol_vote_state_t*   state,
    sol_slot_t          current_slot
);

/*
 * Create a vote account
 */
sol_err_t sol_vote_create_account(
    sol_bank_t*             bank,
    const sol_pubkey_t*     vote_pubkey,
    const sol_vote_init_t*  init,
    uint64_t                lamports
);

/*
 * Get vote state from account
 */
sol_err_t sol_vote_get_state(
    sol_bank_t*             bank,
    const sol_pubkey_t*     vote_pubkey,
    sol_vote_state_t*       state
);

/*
 * Vote evidence for slashing detection.
 *
 * Slashing occurs when a validator votes for the same slot with
 * different bank hashes (equivocation). This struct captures the
 * evidence needed to prove such a violation.
 */
typedef struct {
    sol_pubkey_t    voter;          /* The authorized voter who signed */
    sol_slot_t      slot;           /* The slot that was voted for */
    sol_hash_t      hash;           /* The bank hash that was voted for */
    sol_signature_t signature;      /* Signature proving the vote */
} sol_vote_evidence_t;

/*
 * Check for vote equivocation (slashable offense).
 *
 * Returns true if the two evidence items prove equivocation:
 * - Same voter
 * - Same slot
 * - Different hashes
 * - Valid signatures
 *
 * This is used for slashing detection in consensus.
 */
bool sol_vote_check_equivocation(
    const sol_vote_evidence_t*  evidence1,
    const sol_vote_evidence_t*  evidence2
);

/*
 * Report vote equivocation (slashing).
 *
 * When equivocation is detected, this function can be called to
 * record the slashing event. In practice, slashing on Solana
 * results in stake being deactivated rather than burned.
 *
 * @param bank          Bank context
 * @param vote_account  Vote account that committed equivocation
 * @param evidence1     First vote evidence
 * @param evidence2     Second vote evidence (conflicting)
 * @return              SOL_OK if slashing was recorded
 */
sol_err_t sol_vote_report_equivocation(
    sol_bank_t*                 bank,
    const sol_pubkey_t*         vote_account,
    const sol_vote_evidence_t*  evidence1,
    const sol_vote_evidence_t*  evidence2
);

#endif /* SOL_VOTE_PROGRAM_H */
