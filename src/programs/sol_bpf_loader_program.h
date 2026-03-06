/*
 * sol_bpf_loader_program.h - BPF Loader native programs
 *
 * Handles deploying and executing BPF programs on-chain.
 */

#ifndef SOL_BPF_LOADER_PROGRAM_H
#define SOL_BPF_LOADER_PROGRAM_H

#include "../util/sol_types.h"
#include "../util/sol_err.h"
#include "sol_system_program.h"  /* For sol_invoke_context_t */
#include "../bpf/sol_bpf.h"

/*
 * Process BPF Upgradeable Loader instruction
 *
 * Handles instructions for the upgradeable loader:
 * - InitializeBuffer
 * - Write
 * - DeployWithMaxDataLen
 * - Upgrade
 * - SetAuthority
 * - Close
 * - ExtendProgram
 */
sol_err_t sol_bpf_upgradeable_loader_process(sol_invoke_context_t* ctx);

/*
 * Process BPF Loader v2 instruction
 *
 * Handles instructions for the non-upgradeable loader:
 * - Write
 * - Finalize
 */
sol_err_t sol_bpf_loader_2_process(sol_invoke_context_t* ctx);

/*
 * Execute a deployed BPF program
 *
 * Loads and executes a BPF program with the given context.
 *
 * @param ctx         Invoke context
 * @param program_id  The program account (must be executable)
 * @return SOL_OK on success
 */
sol_err_t sol_bpf_loader_execute_program(
    sol_invoke_context_t* ctx,
    const sol_pubkey_t* program_id
);

/*
 * Best-effort preload of a deployed BPF program into the shared loader cache.
 *
 * This parses and caches the program ELF without executing it, reducing
 * first-use replay stalls on hot programs.
 */
sol_err_t sol_bpf_loader_prewarm_program(
    sol_bank_t* bank,
    const sol_pubkey_t* program_id
);

/*
 * Budgeted variant of program prewarm.
 *
 * `wait_budget_ns` bounds how long prewarm waits on an in-flight load.
 * Pass `UINT64_MAX` for legacy/unbounded waiting behavior.
 */
sol_err_t sol_bpf_loader_prewarm_program_budget(
    sol_bank_t* bank,
    const sol_pubkey_t* program_id,
    uint64_t wait_budget_ns
);

/*
 * CPI dispatch helper for BPF programs
 */
sol_err_t sol_bpf_loader_cpi_dispatch(
    sol_bpf_vm_t* vm,
    const sol_bpf_cpi_instruction_t* instr
);

/*
 * Main entry point for BPF Loader programs
 *
 * Dispatches to the appropriate handler based on the loader type.
 */
sol_err_t sol_bpf_loader_program_execute(sol_invoke_context_t* ctx);

#endif /* SOL_BPF_LOADER_PROGRAM_H */
