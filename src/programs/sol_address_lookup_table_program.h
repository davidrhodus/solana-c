/*
 * sol_address_lookup_table_program.h - Address Lookup Table Program
 *
 * Manages address lookup tables for v0 transactions.
 * Lookup tables allow transactions to reference accounts by index,
 * reducing transaction size.
 */

#ifndef SOL_ADDRESS_LOOKUP_TABLE_PROGRAM_H
#define SOL_ADDRESS_LOOKUP_TABLE_PROGRAM_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../runtime/sol_account.h"
#include "sol_system_program.h"  /* For sol_invoke_context_t */

/*
 * Address Lookup Table Program ID
 */
extern const sol_pubkey_t SOL_ADDRESS_LOOKUP_TABLE_ID;

/*
 * Lookup table account state
 */
#define SOL_ALT_STATE_UNINITIALIZED  0
#define SOL_ALT_STATE_ACTIVE         1
#define SOL_ALT_STATE_DEACTIVATED    2

/*
 * Maximum addresses per lookup table
 */
#define SOL_ALT_MAX_ADDRESSES  256

/*
 * Lookup table metadata size (before addresses)
 */
#define SOL_ALT_METADATA_SIZE  56

/*
 * Instruction types
 */
typedef enum {
    SOL_ALT_INSTR_CREATE            = 0,
    SOL_ALT_INSTR_FREEZE            = 1,
    SOL_ALT_INSTR_EXTEND            = 2,
    SOL_ALT_INSTR_DEACTIVATE        = 3,
    SOL_ALT_INSTR_CLOSE             = 4,
} sol_alt_instruction_t;

/*
 * Lookup table metadata structure
 *
 * Layout in account data:
 *   [0..4]   - type discriminator (u32)
 *   [4..12]  - deactivation_slot (u64, UINT64_MAX if active)
 *   [12..20] - last_extended_slot (u64)
 *   [20..21] - last_extended_slot_start_index (u8)
 *   [21..22] - padding
 *   [22..54] - authority (Option<Pubkey>: 1 byte tag + 32 bytes)
 *   [54..56] - padding
 *   [56..]   - addresses (array of Pubkey, 32 bytes each)
 */
typedef struct {
    uint32_t    type_discriminator;
    uint64_t    deactivation_slot;
    uint64_t    last_extended_slot;
    uint8_t     last_extended_slot_start_index;
    uint8_t     has_authority;
    sol_pubkey_t authority;
} sol_alt_metadata_t;

/*
 * Lookup table state (full representation)
 */
typedef struct {
    sol_alt_metadata_t  meta;
    sol_pubkey_t*       addresses;
    uint16_t            addresses_len;
} sol_alt_state_t;

/*
 * Initialize lookup table state
 */
void sol_alt_state_init(sol_alt_state_t* state);

/*
 * Free lookup table state
 */
void sol_alt_state_free(sol_alt_state_t* state);

/*
 * Deserialize lookup table from account data
 */
sol_err_t sol_alt_deserialize(
    sol_alt_state_t*    state,
    const uint8_t*      data,
    size_t              len
);

/*
 * Serialize lookup table to account data
 */
sol_err_t sol_alt_serialize(
    const sol_alt_state_t*  state,
    uint8_t*                data,
    size_t                  len,
    size_t*                 written
);

/*
 * Get address from lookup table by index
 */
const sol_pubkey_t* sol_alt_get_address(
    const sol_alt_state_t*  state,
    uint8_t                 index
);

/*
 * Check if lookup table is active
 */
bool sol_alt_is_active(
    const sol_alt_state_t*  state,
    sol_slot_t              current_slot
);

/*
 * Derive lookup table address from authority and recent slot
 */
sol_err_t sol_alt_derive_address(
    const sol_pubkey_t*     authority,
    uint64_t                recent_slot,
    sol_pubkey_t*           out_address,
    uint8_t*                out_bump
);

/*
 * Process Address Lookup Table program instruction
 */
sol_err_t sol_address_lookup_table_process(
    sol_invoke_context_t*   ctx,
    sol_slot_t              current_slot
);

#endif /* SOL_ADDRESS_LOOKUP_TABLE_PROGRAM_H */
