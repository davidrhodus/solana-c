/*
 * sol_program.h - Program Dispatch
 *
 * Centralized dispatch for native/BPF programs.
 */

#ifndef SOL_PROGRAM_H
#define SOL_PROGRAM_H

#include "../programs/sol_system_program.h"

/*
 * Execute program based on ctx->program_id.
 */
sol_err_t sol_program_execute(sol_invoke_context_t* ctx);

#endif /* SOL_PROGRAM_H */
