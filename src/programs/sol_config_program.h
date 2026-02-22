/*
 * sol_config_program.h - Config Program
 *
 * The Config program manages on-chain configuration accounts.
 * Config accounts store arbitrary data with optional signature requirements.
 */

#ifndef SOL_CONFIG_PROGRAM_H
#define SOL_CONFIG_PROGRAM_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "../runtime/sol_account.h"
#include "sol_system_program.h"  /* For sol_invoke_context_t */

/*
 * Config Program ID
 */
extern const sol_pubkey_t SOL_CONFIG_PROGRAM_ID;

/*
 * Maximum config keys per account
 */
#define SOL_CONFIG_MAX_KEYS 256

/*
 * Config key structure
 * A key defines a pubkey and whether it must sign updates
 */
typedef struct {
    sol_pubkey_t    pubkey;
    bool            is_signer;
} sol_config_key_t;

/*
 * Config account state
 */
typedef struct {
    sol_config_key_t*   keys;
    uint16_t            keys_len;
    uint8_t*            data;
    size_t              data_len;
} sol_config_state_t;

/*
 * Initialize config state
 */
void sol_config_state_init(sol_config_state_t* state);

/*
 * Free config state resources
 */
void sol_config_state_free(sol_config_state_t* state);

/*
 * Deserialize config state from account data
 */
sol_err_t sol_config_deserialize(
    sol_config_state_t* state,
    const uint8_t*      data,
    size_t              len
);

/*
 * Serialize config state to account data
 */
sol_err_t sol_config_serialize(
    const sol_config_state_t*   state,
    uint8_t*                    data,
    size_t                      len,
    size_t*                     written
);

/*
 * Calculate required account size for config
 */
size_t sol_config_account_size(
    uint16_t    num_keys,
    size_t      data_len
);

/*
 * Process Config program instruction
 */
sol_err_t sol_config_process(sol_invoke_context_t* ctx);

#endif /* SOL_CONFIG_PROGRAM_H */
