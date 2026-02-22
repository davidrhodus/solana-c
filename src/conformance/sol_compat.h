/*
 * sol_compat.h - Firedancer Conformance Harness Interface
 *
 * This header defines the entry points required by the solana-conformance
 * test suite. Each function takes protobuf-encoded input and produces
 * protobuf-encoded output according to the protosol schema.
 *
 * See: https://github.com/firedancer-io/solana-conformance
 *      https://github.com/firedancer-io/protosol
 */

#ifndef SOL_COMPAT_H
#define SOL_COMPAT_H

#include "util/sol_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Conformance harness initialization
 * Called once before any test execution
 */
void
sol_compat_init(void);

/*
 * Conformance harness cleanup
 * Called once after all tests complete
 */
void
sol_compat_fini(void);

/*
 * ELF Loader Harness
 *
 * Tests ELF binary loading and validation.
 *
 * Input: ElfLoaderContext protobuf
 * Output: ElfLoaderEffects protobuf
 *
 * Returns output length, or 0 on error.
 * Caller must free *output.
 */
typedef void* (*sol_compat_fn_t)(const uint8_t* input, size_t input_len, size_t* output_len);

void*
sol_compat_elf_loader_v1(
    const uint8_t* input,
    size_t         input_len,
    size_t*        output_len
);

/*
 * Instruction Execution Harness
 *
 * Tests single instruction execution against program runtime.
 *
 * Input: InstrContext protobuf containing:
 *   - program_id: 32-byte program address
 *   - accounts: Account states
 *   - instr_accounts: Account access metadata
 *   - data: Instruction data
 *   - cu_avail: Compute units available
 *   - slot_context: Current slot info
 *   - epoch_context: Current epoch info
 *
 * Output: InstrEffects protobuf containing:
 *   - result: 0 for success, error code otherwise
 *   - custom_err: Stable error code
 *   - modified_accounts: Changed account states
 *   - cu_avail: Remaining compute units
 *   - return_data: Program return data
 */
void*
sol_compat_instr_execute_v1(
    const uint8_t* input,
    size_t         input_len,
    size_t*        output_len
);

/*
 * Syscall Execution Harness
 *
 * Tests individual sBPF syscall behavior.
 *
 * Input: SyscallContext protobuf
 * Output: SyscallEffects protobuf
 */
void*
sol_compat_vm_syscall_execute_v1(
    const uint8_t* input,
    size_t         input_len,
    size_t*        output_len
);

/*
 * VM Interpreter Harness
 *
 * Tests sBPF VM instruction interpretation.
 *
 * Input: VmContext protobuf
 * Output: VmEffects protobuf
 */
void*
sol_compat_vm_interp_v1(
    const uint8_t* input,
    size_t         input_len,
    size_t*        output_len
);

/*
 * VM Validation Harness
 *
 * Tests sBPF program validation (verifier).
 *
 * Input: VmValidateContext protobuf
 * Output: VmValidateEffects protobuf
 */
void*
sol_compat_vm_validate_v1(
    const uint8_t* input,
    size_t         input_len,
    size_t*        output_len
);

/*
 * Transaction Execution Harness
 *
 * Tests full transaction execution.
 *
 * Input: TxnContext protobuf containing:
 *   - tx: SanitizedTransaction
 *   - account_shared_data: Account states
 *   - blockhash_queue: Recent blockhashes
 *   - epoch_ctx: Epoch context
 *   - slot_ctx: Slot context
 *
 * Output: TxnResult protobuf containing:
 *   - executed: Whether processing occurred
 *   - sanitization_error: Validation error flag
 *   - resulting_state: Final account states
 *   - return_data: Transaction return data
 *   - executed_units: Compute units used
 *   - fee_details: Fee information
 */
void*
sol_compat_txn_execute_v1(
    const uint8_t* input,
    size_t         input_len,
    size_t*        output_len
);

/*
 * Block Execution Harness
 *
 * Tests full block execution.
 *
 * Input: BlockContext protobuf
 * Output: BlockEffects protobuf
 */
void*
sol_compat_block_execute_v1(
    const uint8_t* input,
    size_t         input_len,
    size_t*        output_len
);

/*
 * Type Validation Harness
 *
 * Tests type serialization/deserialization.
 *
 * Input: TypeContext protobuf
 * Output: TypeEffects protobuf
 */
void*
sol_compat_type_execute_v1(
    const uint8_t* input,
    size_t         input_len,
    size_t*        output_len
);

#ifdef __cplusplus
}
#endif

#endif /* SOL_COMPAT_H */
