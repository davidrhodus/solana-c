/*
 * test_bpf.c - BPF VM unit tests
 */

#include "../test_framework.h"
#include "bpf/sol_bpf.h"
#include "programs/sol_bpf_loader_program.h"
#include "programs/sol_stake_program.h"
#include "programs/sol_system_program.h"
#include "runtime/sol_bank.h"
#include "runtime/sol_compute_budget.h"
#include "runtime/sol_sysvar.h"
#include "crypto/sol_sha256.h"
#include "crypto/sol_ed25519.h"
#include <string.h>

#ifdef SOL_HAS_SECP256K1
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#endif

static sol_err_t
test_cpi_ok_handler(sol_bpf_vm_t* vm, const sol_bpf_cpi_instruction_t* instr) {
    (void)vm;
    (void)instr;
    return SOL_OK;
}

static void
write_u16_le(uint8_t* p, uint16_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void
write_u32_le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void
write_u64_le(uint8_t* p, uint64_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

static uint64_t
read_u64_le(const uint8_t* p) {
    return (uint64_t)p[0] |
           ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}

static const uint8_t test_bpf_loop_elf[] = {
  0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0xf7, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x68, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
  0x05, 0x00, 0x01, 0x00, 0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x7b, 0x1a, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00, 0x79, 0xa2, 0xf8, 0xff,
  0x00, 0x00, 0x00, 0x00, 0x0f, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x7b, 0x2a, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00, 0x79, 0xa2, 0xf8, 0xff,
  0x00, 0x00, 0x00, 0x00, 0x07, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x15, 0x01, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x05, 0x00, 0xfa, 0xff,
  0x00, 0x00, 0x00, 0x00, 0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00,
  0x04, 0x00, 0xf1, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4b, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x02, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x02, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x12, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65, 0x6e, 0x74,
  0x72, 0x79, 0x00, 0x2e, 0x74, 0x65, 0x78, 0x74, 0x00, 0x2e, 0x6c, 0x6c,
  0x76, 0x6d, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x73, 0x69, 0x67, 0x00, 0x73,
  0x6f, 0x6c, 0x61, 0x6e, 0x61, 0x5f, 0x63, 0x5f, 0x74, 0x65, 0x73, 0x74,
  0x5f, 0x62, 0x70, 0x66, 0x5f, 0x70, 0x72, 0x6f, 0x67, 0x2e, 0x63, 0x00,
  0x2e, 0x73, 0x74, 0x72, 0x74, 0x61, 0x62, 0x00, 0x2e, 0x73, 0x79, 0x6d,
  0x74, 0x61, 0x62, 0x00, 0x4c, 0x42, 0x42, 0x30, 0x5f, 0x32, 0x00, 0x4c,
  0x42, 0x42, 0x30, 0x5f, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
  0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0d, 0x00, 0x00, 0x00, 0x03, 0x4c, 0xff, 0x6f, 0x00, 0x00, 0x00, 0x80,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/*
 * Test VM creation and destruction
 */
TEST(vm_create) {
    sol_bpf_vm_t* vm = sol_bpf_vm_new(NULL);
    TEST_ASSERT_NOT_NULL(vm);
    sol_bpf_vm_destroy(vm);
}

/*
 * Test that BPF loader respects compute meter limits
 */
TEST(bpf_loader_compute_meter) {
    sol_bank_t* bank = sol_bank_new(0, NULL, NULL, NULL);
    TEST_ASSERT_NOT_NULL(bank);

    sol_pubkey_t program_id = {0};
    program_id.bytes[0] = 0x42;

    sol_account_t* program_account = sol_account_new(1, sizeof(test_bpf_loop_elf),
                                                     &SOL_BPF_LOADER_V2_ID);
    TEST_ASSERT_NOT_NULL(program_account);
    program_account->meta.executable = true;

    sol_err_t err = sol_account_set_data(program_account, test_bpf_loop_elf,
                                         sizeof(test_bpf_loop_elf));
    TEST_ASSERT_EQ(err, SOL_OK);

    err = sol_bank_store_account(bank, &program_id, program_account);
    TEST_ASSERT_EQ(err, SOL_OK);
    sol_account_destroy(program_account);

    sol_compute_budget_t budget;
    sol_compute_budget_init(&budget);

    sol_compute_meter_t meter;
    sol_compute_meter_init(&meter, 50);

    sol_invoke_context_t ctx = {0};
    ctx.bank = bank;
    ctx.program_id = program_id;
    ctx.compute_budget = &budget;
    ctx.compute_meter = &meter;

    err = sol_bpf_loader_execute_program(&ctx, &program_id);
    TEST_ASSERT_EQ(err, SOL_ERR_PROGRAM_COMPUTE);
    TEST_ASSERT_EQ(meter.remaining, 0);
    TEST_ASSERT_EQ(meter.consumed, 50);

    /* With a larger budget, the same program should succeed */
    sol_compute_meter_init(&meter, 10000);
    ctx.compute_meter = &meter;
    ctx.compute_units_accounted = 0;

    err = sol_bpf_loader_execute_program(&ctx, &program_id);
    TEST_ASSERT_EQ(err, SOL_OK);
    TEST_ASSERT(meter.consumed > 1000);
    TEST_ASSERT(meter.consumed < meter.limit);
    TEST_ASSERT_EQ(meter.remaining, meter.limit - meter.consumed);

    sol_bank_destroy(bank);
}

/*
 * Test simple program: mov r0, 42; exit
 */
TEST(simple_exit) {
    sol_bpf_vm_t* vm = sol_bpf_vm_new(NULL);
    TEST_ASSERT_NOT_NULL(vm);

    /* mov r0, 42
     * exit
     */
    sol_bpf_insn_t program[] = {
        SOL_BPF_MOV64_IMM(0, 42),
        SOL_BPF_EXIT()
    };

    sol_err_t err = sol_bpf_vm_load_raw(vm, program, 2);
    TEST_ASSERT_EQ(err, SOL_OK);

    err = sol_bpf_vm_execute(vm);
    TEST_ASSERT_EQ(err, SOL_OK);

    uint64_t result = sol_bpf_vm_return_value(vm);
    TEST_ASSERT_EQ(result, 42);

    sol_bpf_vm_destroy(vm);
}

/*
 * Test arithmetic: r0 = 10 + 20 + 30
 */
TEST(arithmetic) {
    sol_bpf_vm_t* vm = sol_bpf_vm_new(NULL);
    TEST_ASSERT_NOT_NULL(vm);

    sol_bpf_insn_t program[] = {
        SOL_BPF_MOV64_IMM(0, 10),
        SOL_BPF_ADD64_IMM(0, 20),
        SOL_BPF_ADD64_IMM(0, 30),
        SOL_BPF_EXIT()
    };

    sol_err_t err = sol_bpf_vm_load_raw(vm, program, 4);
    TEST_ASSERT_EQ(err, SOL_OK);

    err = sol_bpf_vm_execute(vm);
    TEST_ASSERT_EQ(err, SOL_OK);

    uint64_t result = sol_bpf_vm_return_value(vm);
    TEST_ASSERT_EQ(result, 60);

    sol_bpf_vm_destroy(vm);
}

/*
 * Test register move
 */
TEST(reg_move) {
    sol_bpf_vm_t* vm = sol_bpf_vm_new(NULL);
    TEST_ASSERT_NOT_NULL(vm);

    sol_bpf_insn_t program[] = {
        SOL_BPF_MOV64_IMM(1, 100),       /* r1 = 100 */
        SOL_BPF_MOV64_IMM(2, 200),       /* r2 = 200 */
        SOL_BPF_MOV64_REG(0, 1),         /* r0 = r1 */
        sol_bpf_insn(SOL_BPF_CLASS_ALU64 | SOL_BPF_SRC_X | SOL_BPF_ALU_ADD, 0, 2, 0, 0),  /* r0 += r2 */
        SOL_BPF_EXIT()
    };

    sol_err_t err = sol_bpf_vm_load_raw(vm, program, 5);
    TEST_ASSERT_EQ(err, SOL_OK);

    err = sol_bpf_vm_execute(vm);
    TEST_ASSERT_EQ(err, SOL_OK);

    uint64_t result = sol_bpf_vm_return_value(vm);
    TEST_ASSERT_EQ(result, 300);

    sol_bpf_vm_destroy(vm);
}

/*
 * Test conditional jump
 */
TEST(jump) {
    sol_bpf_vm_t* vm = sol_bpf_vm_new(NULL);
    TEST_ASSERT_NOT_NULL(vm);

    /*
     * r0 = 0
     * r1 = 10
     * if r1 == 10: goto +1
     * r0 = 1      ; should be skipped
     * r0 += 100   ; should execute
     * exit
     */
    sol_bpf_insn_t program[] = {
        SOL_BPF_MOV64_IMM(0, 0),                                                           /* 0: r0 = 0 */
        SOL_BPF_MOV64_IMM(1, 10),                                                          /* 1: r1 = 10 */
        sol_bpf_insn(SOL_BPF_CLASS_JMP | SOL_BPF_SRC_K | SOL_BPF_JMP_JEQ, 1, 0, 1, 10),    /* 2: if r1 == 10: skip 1 */
        SOL_BPF_MOV64_IMM(0, 1),                                                           /* 3: r0 = 1 (skipped) */
        SOL_BPF_ADD64_IMM(0, 100),                                                         /* 4: r0 += 100 */
        SOL_BPF_EXIT()                                                                     /* 5: exit */
    };

    sol_err_t err = sol_bpf_vm_load_raw(vm, program, 6);
    TEST_ASSERT_EQ(err, SOL_OK);

    err = sol_bpf_vm_execute(vm);
    TEST_ASSERT_EQ(err, SOL_OK);

    uint64_t result = sol_bpf_vm_return_value(vm);
    TEST_ASSERT_EQ(result, 100);  /* 0 + 100, not 1 + 100 */

    sol_bpf_vm_destroy(vm);
}

/*
 * Test memory store and load
 */
TEST(memory) {
    sol_bpf_vm_t* vm = sol_bpf_vm_new(NULL);
    TEST_ASSERT_NOT_NULL(vm);

    /*
     * Store 42 to stack, load it back
     * r10 is frame pointer (points to top of stack)
     */
    sol_bpf_insn_t program[] = {
        SOL_BPF_MOV64_IMM(1, 42),
        /* STX [r10-8] = r1 (double word) */
        sol_bpf_insn(SOL_BPF_CLASS_STX | SOL_BPF_SIZE_DW | SOL_BPF_MODE_MEM, 10, 1, -8, 0),
        /* LDX r0 = [r10-8] (double word) */
        sol_bpf_insn(SOL_BPF_CLASS_LDX | SOL_BPF_SIZE_DW | SOL_BPF_MODE_MEM, 0, 10, -8, 0),
        SOL_BPF_EXIT()
    };

    sol_err_t err = sol_bpf_vm_load_raw(vm, program, 4);
    TEST_ASSERT_EQ(err, SOL_OK);

    err = sol_bpf_vm_execute(vm);
    TEST_ASSERT_EQ(err, SOL_OK);

    uint64_t result = sol_bpf_vm_return_value(vm);
    TEST_ASSERT_EQ(result, 42);

    sol_bpf_vm_destroy(vm);
}

/*
 * Test divide by zero
 */
TEST(divide_by_zero) {
    sol_bpf_vm_t* vm = sol_bpf_vm_new(NULL);
    TEST_ASSERT_NOT_NULL(vm);

    sol_bpf_insn_t program[] = {
        SOL_BPF_MOV64_IMM(0, 100),
        sol_bpf_insn(SOL_BPF_CLASS_ALU64 | SOL_BPF_SRC_K | SOL_BPF_ALU_DIV, 0, 0, 0, 0),  /* r0 /= 0 */
        SOL_BPF_EXIT()
    };

    sol_err_t err = sol_bpf_vm_load_raw(vm, program, 3);
    TEST_ASSERT_EQ(err, SOL_OK);

    err = sol_bpf_vm_execute(vm);
    TEST_ASSERT_EQ(err, SOL_ERR_BPF_EXECUTE);
    TEST_ASSERT_EQ(vm->error, SOL_BPF_ERR_DIVIDE_BY_ZERO);

    sol_bpf_vm_destroy(vm);
}

/*
 * Test SBPFv2 signed remainder (ALU64)
 */
TEST(srem64) {
    sol_bpf_vm_t* vm = sol_bpf_vm_new(NULL);
    TEST_ASSERT_NOT_NULL(vm);

    sol_bpf_insn_t program[] = {
        SOL_BPF_MOV64_IMM(0, -10),
        sol_bpf_insn(SOL_BPF_CLASS_ALU64 | SOL_BPF_SRC_K | SOL_BPF_ALU_SREM, 0, 0, 0, 3),  /* r0 %= 3 (signed) */
        SOL_BPF_EXIT()
    };

    sol_err_t err = sol_bpf_vm_load_raw(vm, program, 3);
    TEST_ASSERT_EQ(err, SOL_OK);

    err = sol_bpf_vm_execute(vm);
    TEST_ASSERT_EQ(err, SOL_OK);

    uint64_t result = sol_bpf_vm_return_value(vm);
    TEST_ASSERT_EQ((int64_t)result, -1);

    sol_bpf_vm_destroy(vm);
}

TEST(srem64_divisor_zero) {
    sol_bpf_vm_t* vm = sol_bpf_vm_new(NULL);
    TEST_ASSERT_NOT_NULL(vm);

    sol_bpf_insn_t program[] = {
        SOL_BPF_MOV64_IMM(0, -10),
        sol_bpf_insn(SOL_BPF_CLASS_ALU64 | SOL_BPF_SRC_K | SOL_BPF_ALU_SREM, 0, 0, 0, 0),  /* r0 %= 0 (signed) */
        SOL_BPF_EXIT()
    };

    sol_err_t err = sol_bpf_vm_load_raw(vm, program, 3);
    TEST_ASSERT_EQ(err, SOL_OK);

    err = sol_bpf_vm_execute(vm);
    TEST_ASSERT_EQ(err, SOL_ERR_BPF_EXECUTE);
    TEST_ASSERT_EQ(vm->error, SOL_BPF_ERR_DIVIDE_BY_ZERO);

    sol_bpf_vm_destroy(vm);
}

TEST(srem64_overflow_case) {
    sol_bpf_vm_t* vm = sol_bpf_vm_new(NULL);
    TEST_ASSERT_NOT_NULL(vm);

    /* SBPF signals DivideOverflow on INT64_MIN % -1. */
    uint64_t value = 0x8000000000000000ULL;
    uint32_t lo = (uint32_t)value;
    uint32_t hi = (uint32_t)(value >> 32);

    sol_bpf_insn_t program[] = {
        sol_bpf_insn(SOL_BPF_OP_LDDW, 0, 0, 0, (int32_t)lo),
        sol_bpf_insn(0, 0, 0, 0, (int32_t)hi),
        sol_bpf_insn(SOL_BPF_CLASS_ALU64 | SOL_BPF_SRC_K | SOL_BPF_ALU_SREM, 0, 0, 0, -1),
        SOL_BPF_EXIT()
    };

    sol_err_t err = sol_bpf_vm_load_raw(vm, program, 4);
    TEST_ASSERT_EQ(err, SOL_OK);

    err = sol_bpf_vm_execute(vm);
    TEST_ASSERT_EQ(err, SOL_ERR_BPF_EXECUTE);
    TEST_ASSERT_EQ(vm->error, SOL_BPF_ERR_DIVIDE_OVERFLOW);

    sol_bpf_vm_destroy(vm);
}

/*
 * Test compute budget
 */
TEST(compute_budget) {
    sol_bpf_config_t config = {
        .stack_size = SOL_BPF_STACK_SIZE,
        .heap_size = SOL_BPF_HEAP_SIZE,
        .compute_units = 5,  /* Very limited */
        .enable_jit = false
    };

    sol_bpf_vm_t* vm = sol_bpf_vm_new(&config);
    TEST_ASSERT_NOT_NULL(vm);

    /* This program needs more than 5 compute units */
    sol_bpf_insn_t program[] = {
        SOL_BPF_MOV64_IMM(0, 0),
        SOL_BPF_ADD64_IMM(0, 1),
        SOL_BPF_ADD64_IMM(0, 1),
        SOL_BPF_ADD64_IMM(0, 1),
        SOL_BPF_ADD64_IMM(0, 1),
        SOL_BPF_ADD64_IMM(0, 1),
        SOL_BPF_ADD64_IMM(0, 1),  /* Should exceed budget here */
        SOL_BPF_EXIT()
    };

    sol_err_t err = sol_bpf_vm_load_raw(vm, program, 8);
    TEST_ASSERT_EQ(err, SOL_OK);

    err = sol_bpf_vm_execute(vm);
    TEST_ASSERT_EQ(err, SOL_ERR_BPF_EXECUTE);

    sol_bpf_vm_destroy(vm);
}

/*
 * Test LDDW (64-bit immediate load)
 */
TEST(lddw) {
    sol_bpf_vm_t* vm = sol_bpf_vm_new(NULL);
    TEST_ASSERT_NOT_NULL(vm);

    /* Load 0x123456789ABCDEF0 into r0 */
    uint64_t value = 0x123456789ABCDEF0ULL;
    uint32_t lo = (uint32_t)value;
    uint32_t hi = (uint32_t)(value >> 32);

    sol_bpf_insn_t program[] = {
        /* LDDW r0, value (2 instructions) */
        sol_bpf_insn(SOL_BPF_OP_LDDW, 0, 0, 0, (int32_t)lo),
        sol_bpf_insn(0, 0, 0, 0, (int32_t)hi),
        SOL_BPF_EXIT()
    };

    sol_err_t err = sol_bpf_vm_load_raw(vm, program, 3);
    TEST_ASSERT_EQ(err, SOL_OK);

    err = sol_bpf_vm_execute(vm);
    TEST_ASSERT_EQ(err, SOL_OK);

    uint64_t result = sol_bpf_vm_return_value(vm);
    TEST_ASSERT_EQ(result, value);

    sol_bpf_vm_destroy(vm);
}

/*
 * Test R_BPF_64_64 relocation for pointers stored in .data.rel.ro
 */
TEST(elf_data_reloc_r_bpf_64_64) {
    enum {
        TEXT_VADDR = 0x100,
        TEXT_OFF = 0x100,
        TEXT_LEN = 0x10,
        DATA_VADDR = 0x200,
        DATA_OFF = 0x200,
        DATA_LEN = 0x8,
        DYNSYM_OFF = 0x208,
        DYNSYM_LEN = 0x30,
        DYNSTR_OFF = 0x238,
        DYNSTR_LEN = 0x6,
        REL_OFF = 0x240,
        REL_LEN = 0x10,
        SHSTRTAB_OFF = 0x250,
        SHSTRTAB_LEN = 55,
        SHOFF = 0x300,
        SHENTSIZE = 64,
        SHNUM = 7,
        ELF_LEN = SHOFF + SHNUM * SHENTSIZE,
    };

    enum {
        SEC_NULL = 0,
        SEC_TEXT = 1,
        SEC_DATA_REL_RO = 2,
        SEC_DYNSYM = 3,
        SEC_DYNSTR = 4,
        SEC_REL_DYN = 5,
        SEC_SHSTRTAB = 6,
    };

    enum {
        SH_NAME_TEXT = 1,
        SH_NAME_DATA_REL_RO = 7,
        SH_NAME_DYNSYM = 20,
        SH_NAME_DYNSTR = 28,
        SH_NAME_REL_DYN = 36,
        SH_NAME_SHSTRTAB = 45,
    };

    uint8_t elf[ELF_LEN];
    memset(elf, 0, sizeof(elf));

    /* ELF header */
    elf[0] = 0x7f;
    elf[1] = 'E';
    elf[2] = 'L';
    elf[3] = 'F';
    elf[4] = 2; /* ELFCLASS64 */
    elf[5] = 1; /* ELFDATA2LSB */
    elf[6] = 1; /* EV_CURRENT */
    write_u16_le(elf + 16, 3);    /* ET_DYN */
    write_u16_le(elf + 18, 247);  /* EM_BPF */
    write_u32_le(elf + 20, 1);    /* EV_CURRENT */
    write_u64_le(elf + 24, TEXT_VADDR);  /* e_entry */
    write_u64_le(elf + 32, 0);    /* e_phoff */
    write_u64_le(elf + 40, SHOFF); /* e_shoff */
    write_u32_le(elf + 48, 0);    /* e_flags */
    write_u16_le(elf + 52, 64);   /* e_ehsize */
    write_u16_le(elf + 54, 0);    /* e_phentsize */
    write_u16_le(elf + 56, 0);    /* e_phnum */
    write_u16_le(elf + 58, SHENTSIZE); /* e_shentsize */
    write_u16_le(elf + 60, SHNUM);     /* e_shnum */
    write_u16_le(elf + 62, SEC_SHSTRTAB); /* e_shstrndx */

    /* .text: two exit instructions */
    elf[TEXT_OFF + 0] = 0x95;
    elf[TEXT_OFF + 8] = 0x95;

    /* .data.rel.ro: addend=0x20 encoded as swapped 32-bit halves */
    write_u64_le(elf + DATA_OFF, 0x0000002000000000ULL);

    /* .dynstr: "\0func\0" */
    elf[DYNSTR_OFF + 0] = 0;
    elf[DYNSTR_OFF + 1] = 'f';
    elf[DYNSTR_OFF + 2] = 'u';
    elf[DYNSTR_OFF + 3] = 'n';
    elf[DYNSTR_OFF + 4] = 'c';
    elf[DYNSTR_OFF + 5] = 0;

    /* .dynsym: null symbol + "func" at TEXT_VADDR */
    size_t sym1 = DYNSYM_OFF + 24;
    write_u32_le(elf + sym1 + 0, 1); /* st_name */
    elf[sym1 + 4] = 0x12;            /* STB_GLOBAL<<4 | STT_FUNC */
    elf[sym1 + 5] = 0;               /* st_other */
    write_u16_le(elf + sym1 + 6, SEC_TEXT); /* st_shndx */
    write_u64_le(elf + sym1 + 8, TEXT_VADDR); /* st_value */
    write_u64_le(elf + sym1 + 16, 0); /* st_size */

    /* .rel.dyn: R_BPF_64_64 @ DATA_VADDR, sym=1 */
    write_u64_le(elf + REL_OFF + 0, DATA_VADDR);
    write_u64_le(elf + REL_OFF + 8, 0x0000000100000001ULL);

    /* .shstrtab */
    static const char shstrtab[SHSTRTAB_LEN] =
        "\0"
        ".text\0"
        ".data.rel.ro\0"
        ".dynsym\0"
        ".dynstr\0"
        ".rel.dyn\0"
        ".shstrtab";
    memcpy(elf + SHSTRTAB_OFF, shstrtab, sizeof(shstrtab));

    /* Section headers */
    const size_t sh_base = SHOFF;

    /* [1] .text */
    size_t sh1 = sh_base + SEC_TEXT * SHENTSIZE;
    write_u32_le(elf + sh1 + 0, SH_NAME_TEXT);
    write_u32_le(elf + sh1 + 4, 1);         /* SHT_PROGBITS */
    write_u64_le(elf + sh1 + 8, 0x6);       /* SHF_ALLOC|SHF_EXECINSTR */
    write_u64_le(elf + sh1 + 16, TEXT_VADDR);
    write_u64_le(elf + sh1 + 24, TEXT_OFF);
    write_u64_le(elf + sh1 + 32, TEXT_LEN);
    write_u32_le(elf + sh1 + 40, 0);
    write_u32_le(elf + sh1 + 44, 0);
    write_u64_le(elf + sh1 + 48, 8);
    write_u64_le(elf + sh1 + 56, 0);

    /* [2] .data.rel.ro */
    size_t sh2 = sh_base + SEC_DATA_REL_RO * SHENTSIZE;
    write_u32_le(elf + sh2 + 0, SH_NAME_DATA_REL_RO);
    write_u32_le(elf + sh2 + 4, 1);         /* SHT_PROGBITS */
    write_u64_le(elf + sh2 + 8, 0x3);       /* SHF_WRITE|SHF_ALLOC */
    write_u64_le(elf + sh2 + 16, DATA_VADDR);
    write_u64_le(elf + sh2 + 24, DATA_OFF);
    write_u64_le(elf + sh2 + 32, DATA_LEN);
    write_u32_le(elf + sh2 + 40, 0);
    write_u32_le(elf + sh2 + 44, 0);
    write_u64_le(elf + sh2 + 48, 8);
    write_u64_le(elf + sh2 + 56, 0);

    /* [3] .dynsym */
    size_t sh3 = sh_base + SEC_DYNSYM * SHENTSIZE;
    write_u32_le(elf + sh3 + 0, SH_NAME_DYNSYM);
    write_u32_le(elf + sh3 + 4, 11);        /* SHT_DYNSYM */
    write_u64_le(elf + sh3 + 8, 0x2);       /* SHF_ALLOC */
    write_u64_le(elf + sh3 + 16, 0);
    write_u64_le(elf + sh3 + 24, DYNSYM_OFF);
    write_u64_le(elf + sh3 + 32, DYNSYM_LEN);
    write_u32_le(elf + sh3 + 40, SEC_DYNSTR);
    write_u32_le(elf + sh3 + 44, 1);
    write_u64_le(elf + sh3 + 48, 8);
    write_u64_le(elf + sh3 + 56, 24);

    /* [4] .dynstr */
    size_t sh4 = sh_base + SEC_DYNSTR * SHENTSIZE;
    write_u32_le(elf + sh4 + 0, SH_NAME_DYNSTR);
    write_u32_le(elf + sh4 + 4, 3);         /* SHT_STRTAB */
    write_u64_le(elf + sh4 + 8, 0x2);       /* SHF_ALLOC */
    write_u64_le(elf + sh4 + 16, 0);
    write_u64_le(elf + sh4 + 24, DYNSTR_OFF);
    write_u64_le(elf + sh4 + 32, DYNSTR_LEN);
    write_u32_le(elf + sh4 + 40, 0);
    write_u32_le(elf + sh4 + 44, 0);
    write_u64_le(elf + sh4 + 48, 1);
    write_u64_le(elf + sh4 + 56, 0);

    /* [5] .rel.dyn */
    size_t sh5 = sh_base + SEC_REL_DYN * SHENTSIZE;
    write_u32_le(elf + sh5 + 0, SH_NAME_REL_DYN);
    write_u32_le(elf + sh5 + 4, 9);         /* SHT_REL */
    write_u64_le(elf + sh5 + 8, 0x2);       /* SHF_ALLOC */
    write_u64_le(elf + sh5 + 16, 0);
    write_u64_le(elf + sh5 + 24, REL_OFF);
    write_u64_le(elf + sh5 + 32, REL_LEN);
    write_u32_le(elf + sh5 + 40, SEC_DYNSYM);
    write_u32_le(elf + sh5 + 44, 0);
    write_u64_le(elf + sh5 + 48, 8);
    write_u64_le(elf + sh5 + 56, 16);

    /* [6] .shstrtab */
    size_t sh6 = sh_base + SEC_SHSTRTAB * SHENTSIZE;
    write_u32_le(elf + sh6 + 0, SH_NAME_SHSTRTAB);
    write_u32_le(elf + sh6 + 4, 3);         /* SHT_STRTAB */
    write_u64_le(elf + sh6 + 8, 0);
    write_u64_le(elf + sh6 + 16, 0);
    write_u64_le(elf + sh6 + 24, SHSTRTAB_OFF);
    write_u64_le(elf + sh6 + 32, SHSTRTAB_LEN);
    write_u32_le(elf + sh6 + 40, 0);
    write_u32_le(elf + sh6 + 44, 0);
    write_u64_le(elf + sh6 + 48, 1);
    write_u64_le(elf + sh6 + 56, 0);

    sol_bpf_vm_t* vm = sol_bpf_vm_new(NULL);
    TEST_ASSERT_NOT_NULL(vm);

    sol_err_t err = sol_bpf_vm_load(vm, elf, sizeof(elf));
    TEST_ASSERT_EQ(err, SOL_OK);

    uint8_t* p = sol_bpf_memory_translate(&vm->memory,
                                          SOL_BPF_MM_PROGRAM_START + DATA_VADDR,
                                          8, false);
    TEST_ASSERT_NOT_NULL(p);

    uint64_t got = read_u64_le(p);
    uint64_t expected = SOL_BPF_MM_PROGRAM_START + TEXT_VADDR + 0x20;
    TEST_ASSERT_EQ(got, expected);

    sol_bpf_vm_destroy(vm);
}

/*
 * Test 32-bit ALU operations
 */
TEST(alu32) {
    sol_bpf_vm_t* vm = sol_bpf_vm_new(NULL);
    TEST_ASSERT_NOT_NULL(vm);

    /* Test 32-bit operations truncate properly */
    sol_bpf_insn_t program[] = {
        /* r0 = 0xFFFFFFFF00000001, then add 1 (32-bit) should wrap to 2 */
        sol_bpf_insn(SOL_BPF_OP_LDDW, 0, 0, 0, 1),             /* LDDW lo */
        sol_bpf_insn(0, 0, 0, 0, (int32_t)0xFFFFFFFF),         /* LDDW hi */
        /* Add 1 using 32-bit ALU - should only affect lower 32 bits and zero-extend */
        sol_bpf_insn(SOL_BPF_CLASS_ALU | SOL_BPF_SRC_K | SOL_BPF_ALU_ADD, 0, 0, 0, 1),
        SOL_BPF_EXIT()
    };

    sol_err_t err = sol_bpf_vm_load_raw(vm, program, 4);
    TEST_ASSERT_EQ(err, SOL_OK);

    err = sol_bpf_vm_execute(vm);
    TEST_ASSERT_EQ(err, SOL_OK);

    uint64_t result = sol_bpf_vm_return_value(vm);
    /* 32-bit add: (0x00000001 + 1) = 2, zero-extended to 64 bits */
    TEST_ASSERT_EQ(result, 2);

    sol_bpf_vm_destroy(vm);
}

static sol_bpf_syscall_t*
find_syscall(sol_bpf_vm_t* vm, const char* name) {
    if (vm == NULL || name == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < vm->syscall_count; i++) {
        if (strcmp(vm->syscalls[i].name, name) == 0) {
            return &vm->syscalls[i];
        }
    }

    return NULL;
}

typedef struct {
    uint64_t    pubkey_ptr;
    uint64_t    lamports_ptr;
    uint64_t    data_len;
    uint64_t    data_ptr;
    uint64_t    owner_ptr;
    uint64_t    rent_epoch;
    uint8_t     is_signer;
    uint8_t     is_writable;
    uint8_t     executable;
    uint8_t     _padding[5];
} sol_bpf_account_info_t;

static bool
derive_pda_with_seed_bump(const sol_pubkey_t* program_id,
                          const uint8_t* seed,
                          size_t seed_len,
                          uint8_t bump,
                          sol_pubkey_t* out) {
    if (!program_id || !seed || !out) {
        return false;
    }

    sol_sha256_ctx_t ctx;
    sol_sha256_t hash;
    sol_sha256_init(&ctx);
    sol_sha256_update(&ctx, seed, seed_len);
    sol_sha256_update(&ctx, &bump, 1);
    sol_sha256_update(&ctx, program_id->bytes, 32);
    static const char PDA_MARKER[] = "ProgramDerivedAddress";
    sol_sha256_update(&ctx, PDA_MARKER, sizeof(PDA_MARKER) - 1);
    sol_sha256_final(&ctx, &hash);
    memcpy(out->bytes, hash.bytes, 32);

    return !sol_ed25519_pubkey_is_on_curve(out);
}

static bool
find_pda_for_seed(const sol_pubkey_t* program_id,
                  const uint8_t* seed,
                  size_t seed_len,
                  sol_pubkey_t* out_pda,
                  uint8_t* out_bump) {
    for (uint16_t bump = 0; bump < 256; bump++) {
        sol_pubkey_t pda;
        if (derive_pda_with_seed_bump(program_id, seed, seed_len, (uint8_t)bump, &pda)) {
            *out_pda = pda;
            *out_bump = (uint8_t)bump;
            return true;
        }
    }

    return false;
}

TEST(return_data_syscalls) {
    sol_bpf_vm_t* vm = sol_bpf_vm_new(NULL);
    TEST_ASSERT_NOT_NULL(vm);

    sol_invoke_context_t ctx = {0};
    for (size_t i = 0; i < sizeof(ctx.program_id.bytes); i++) {
        ctx.program_id.bytes[i] = (uint8_t)i;
    }

    sol_bpf_vm_set_context(vm, &ctx);

    const uint8_t payload[] = {0xde, 0xad, 0xbe, 0xef};
    sol_err_t err = sol_bpf_memory_add_region(
        &vm->memory, SOL_BPF_MM_INPUT_START,
        (uint8_t*)payload, sizeof(payload), false
    );
    TEST_ASSERT_EQ(err, SOL_OK);

    sol_bpf_syscall_t* set_return = find_syscall(vm, "sol_set_return_data");
    TEST_ASSERT_NOT_NULL(set_return);

    uint64_t rc = set_return->handler(
        vm, SOL_BPF_MM_INPUT_START, sizeof(payload), 0, 0, 0
    );
    TEST_ASSERT_EQ(rc, 0);
    TEST_ASSERT_EQ(ctx.return_data_len, sizeof(payload));
    TEST_ASSERT_MEM_EQ(ctx.return_data, payload, sizeof(payload));
    TEST_ASSERT_MEM_EQ(ctx.return_data_program.bytes, ctx.program_id.bytes, 32);

    uint8_t out_buf[8] = {0};
    uint8_t out_prog[32] = {0};
    uint64_t out_addr = SOL_BPF_MM_INPUT_START + 0x1000;
    uint64_t prog_addr = SOL_BPF_MM_INPUT_START + 0x2000;

    err = sol_bpf_memory_add_region(&vm->memory, out_addr, out_buf, sizeof(out_buf), true);
    TEST_ASSERT_EQ(err, SOL_OK);

    err = sol_bpf_memory_add_region(&vm->memory, prog_addr, out_prog, sizeof(out_prog), true);
    TEST_ASSERT_EQ(err, SOL_OK);

    sol_bpf_syscall_t* get_return = find_syscall(vm, "sol_get_return_data");
    TEST_ASSERT_NOT_NULL(get_return);

    rc = get_return->handler(vm, out_addr, sizeof(out_buf), prog_addr, 0, 0);
    TEST_ASSERT_EQ(rc, sizeof(payload));
    TEST_ASSERT_MEM_EQ(out_buf, payload, sizeof(payload));
    TEST_ASSERT_MEM_EQ(out_prog, ctx.program_id.bytes, 32);

    sol_bpf_vm_destroy(vm);
}

TEST(clock_sysvar_syscall) {
    sol_bpf_vm_t* vm = sol_bpf_vm_new(NULL);
    TEST_ASSERT_NOT_NULL(vm);

    sol_invoke_context_t ctx = {0};
    ctx.clock.slot = 4242;
    ctx.clock.epoch_start_timestamp = 1111;
    ctx.clock.epoch = 42;
    ctx.clock.leader_schedule_epoch = 43;
    ctx.clock.unix_timestamp = 2222;

    sol_bpf_vm_set_context(vm, &ctx);

    uint8_t out[SOL_CLOCK_SIZE] = {0};
    uint64_t out_addr = SOL_BPF_MM_INPUT_START + 0x3000;
    sol_err_t err = sol_bpf_memory_add_region(&vm->memory, out_addr, out, sizeof(out), true);
    TEST_ASSERT_EQ(err, SOL_OK);

    sol_bpf_syscall_t* get_clock = find_syscall(vm, "sol_get_clock_sysvar");
    TEST_ASSERT_NOT_NULL(get_clock);

    uint64_t rc = get_clock->handler(vm, out_addr, 0, 0, 0, 0);
    TEST_ASSERT_EQ(rc, 0);

    uint64_t slot = 0;
    int64_t epoch_start = 0;
    uint64_t epoch = 0;
    uint64_t leader_epoch = 0;
    int64_t unix_ts = 0;
    memcpy(&slot, out, 8);
    memcpy(&epoch_start, out + 8, 8);
    memcpy(&epoch, out + 16, 8);
    memcpy(&leader_epoch, out + 24, 8);
    memcpy(&unix_ts, out + 32, 8);

    TEST_ASSERT_EQ(slot, ctx.clock.slot);
    TEST_ASSERT_EQ(epoch_start, (int64_t)ctx.clock.epoch_start_timestamp);
    TEST_ASSERT_EQ(epoch, ctx.clock.epoch);
    TEST_ASSERT_EQ(leader_epoch, ctx.clock.leader_schedule_epoch);
    TEST_ASSERT_EQ(unix_ts, (int64_t)ctx.clock.unix_timestamp);

    sol_bpf_vm_destroy(vm);
}

TEST(rent_sysvar_syscall) {
    sol_bpf_vm_t* vm = sol_bpf_vm_new(NULL);
    TEST_ASSERT_NOT_NULL(vm);

    sol_invoke_context_t ctx = {0};
    ctx.rent.lamports_per_byte_year = 1234;
    ctx.rent.exemption_threshold = 3.5;
    ctx.rent.burn_percent = 7;

    sol_bpf_vm_set_context(vm, &ctx);

    uint8_t out[SOL_RENT_SIZE] = {0};
    uint64_t out_addr = SOL_BPF_MM_INPUT_START + 0x4000;
    sol_err_t err = sol_bpf_memory_add_region(&vm->memory, out_addr, out, sizeof(out), true);
    TEST_ASSERT_EQ(err, SOL_OK);

    sol_bpf_syscall_t* get_rent = find_syscall(vm, "sol_get_rent_sysvar");
    TEST_ASSERT_NOT_NULL(get_rent);

    uint64_t rc = get_rent->handler(vm, out_addr, 0, 0, 0, 0);
    TEST_ASSERT_EQ(rc, 0);

    uint64_t lamports_per_byte_year = 0;
    double exemption_threshold = 0.0;
    uint8_t burn_percent = 0;
    memcpy(&lamports_per_byte_year, out, 8);
    memcpy(&exemption_threshold, out + 8, 8);
    burn_percent = out[16];

    TEST_ASSERT_EQ(lamports_per_byte_year, ctx.rent.lamports_per_byte_year);
    TEST_ASSERT_FLOAT_EQ(exemption_threshold, ctx.rent.exemption_threshold, 1e-9);
    TEST_ASSERT_EQ(burn_percent, ctx.rent.burn_percent);

    sol_bpf_vm_destroy(vm);
}

TEST(epoch_schedule_sysvar_syscall) {
    sol_bpf_vm_t* vm = sol_bpf_vm_new(NULL);
    TEST_ASSERT_NOT_NULL(vm);

    sol_invoke_context_t ctx = {0};
    ctx.epoch_schedule.slots_per_epoch = 123;
    ctx.epoch_schedule.leader_schedule_slot_offset = 4;
    ctx.epoch_schedule.warmup = true;
    ctx.epoch_schedule.first_normal_epoch = 7;
    ctx.epoch_schedule.first_normal_slot = 999;

    sol_bpf_vm_set_context(vm, &ctx);

    uint8_t out[SOL_EPOCH_SCHEDULE_SIZE] = {0};
    uint64_t out_addr = SOL_BPF_MM_INPUT_START + 0x4800;
    sol_err_t err = sol_bpf_memory_add_region(&vm->memory, out_addr, out, sizeof(out), true);
    TEST_ASSERT_EQ(err, SOL_OK);

    sol_bpf_syscall_t* get_epoch = find_syscall(vm, "sol_get_epoch_schedule_sysvar");
    TEST_ASSERT_NOT_NULL(get_epoch);

    uint64_t rc = get_epoch->handler(vm, out_addr, 0, 0, 0, 0);
    TEST_ASSERT_EQ(rc, 0);

    uint64_t slots_per_epoch = 0;
    uint64_t leader_schedule_slot_offset = 0;
    uint8_t warmup = 0;
    uint64_t first_normal_epoch = 0;
    uint64_t first_normal_slot = 0;

    memcpy(&slots_per_epoch, out, 8);
    memcpy(&leader_schedule_slot_offset, out + 8, 8);
    warmup = out[16];
    memcpy(&first_normal_epoch, out + 17, 8);
    memcpy(&first_normal_slot, out + 25, 8);

    TEST_ASSERT_EQ(slots_per_epoch, ctx.epoch_schedule.slots_per_epoch);
    TEST_ASSERT_EQ(leader_schedule_slot_offset, ctx.epoch_schedule.leader_schedule_slot_offset);
    TEST_ASSERT_EQ(warmup, 1);
    TEST_ASSERT_EQ(first_normal_epoch, ctx.epoch_schedule.first_normal_epoch);
    TEST_ASSERT_EQ(first_normal_slot, ctx.epoch_schedule.first_normal_slot);

    sol_bpf_vm_destroy(vm);
}

TEST(fees_sysvar_syscall) {
    sol_bpf_vm_t* vm = sol_bpf_vm_new(NULL);
    TEST_ASSERT_NOT_NULL(vm);

    sol_invoke_context_t ctx = {0};
    ctx.lamports_per_signature = 7777;
    sol_bpf_vm_set_context(vm, &ctx);

    uint8_t out[SOL_FEES_SIZE] = {0};
    uint64_t out_addr = SOL_BPF_MM_INPUT_START + 0x5000;
    sol_err_t err = sol_bpf_memory_add_region(&vm->memory, out_addr, out, sizeof(out), true);
    TEST_ASSERT_EQ(err, SOL_OK);

    sol_bpf_syscall_t* get_fees = find_syscall(vm, "sol_get_fees_sysvar");
    TEST_ASSERT_NOT_NULL(get_fees);

    uint64_t rc = get_fees->handler(vm, out_addr, 0, 0, 0, 0);
    TEST_ASSERT_EQ(rc, 0);

    uint64_t lamports_per_signature = 0;
    memcpy(&lamports_per_signature, out, 8);
    TEST_ASSERT_EQ(lamports_per_signature, ctx.lamports_per_signature);

    sol_bpf_vm_destroy(vm);
}

TEST(secp256k1_recover_syscall) {
#ifndef SOL_HAS_SECP256K1
    TEST_SKIP("libsecp256k1 not available");
#else
    sol_bpf_vm_t* vm = sol_bpf_vm_new(NULL);
    TEST_ASSERT_NOT_NULL(vm);

    uint8_t message_hash[32] = {0};
    for (size_t i = 0; i < sizeof(message_hash); i++) {
        message_hash[i] = (uint8_t)(0x11 + i);
    }

    secp256k1_context* secp_ctx =
        secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    TEST_ASSERT_NOT_NULL(secp_ctx);

    uint8_t seckey[32] = {0};
    seckey[0] = 1;
    TEST_ASSERT(secp256k1_ec_seckey_verify(secp_ctx, seckey));

    secp256k1_ecdsa_recoverable_signature sig;
    TEST_ASSERT(secp256k1_ecdsa_sign_recoverable(secp_ctx, &sig, message_hash, seckey, NULL, NULL));

    uint8_t sig64[64] = {0};
    int recid = 0;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(secp_ctx, sig64, &recid, &sig);

    secp256k1_pubkey pubkey;
    TEST_ASSERT(secp256k1_ec_pubkey_create(secp_ctx, &pubkey, seckey));

    uint8_t pubkey_bytes[65] = {0};
    size_t pubkey_len = sizeof(pubkey_bytes);
    TEST_ASSERT(secp256k1_ec_pubkey_serialize(secp_ctx, pubkey_bytes, &pubkey_len,
                                              &pubkey, SECP256K1_EC_UNCOMPRESSED));
    TEST_ASSERT_EQ(pubkey_len, sizeof(pubkey_bytes));

    uint8_t out[64] = {0};

    uint64_t hash_addr = SOL_BPF_MM_INPUT_START + 0x6000;
    uint64_t sig_addr = SOL_BPF_MM_INPUT_START + 0x6100;
    uint64_t out_addr = SOL_BPF_MM_INPUT_START + 0x6200;

    sol_err_t err = sol_bpf_memory_add_region(&vm->memory, hash_addr, message_hash, sizeof(message_hash), false);
    TEST_ASSERT_EQ(err, SOL_OK);
    err = sol_bpf_memory_add_region(&vm->memory, sig_addr, sig64, sizeof(sig64), false);
    TEST_ASSERT_EQ(err, SOL_OK);
    err = sol_bpf_memory_add_region(&vm->memory, out_addr, out, sizeof(out), true);
    TEST_ASSERT_EQ(err, SOL_OK);

    sol_bpf_syscall_t* recover = find_syscall(vm, "sol_secp256k1_recover");
    TEST_ASSERT_NOT_NULL(recover);

    uint64_t rc = recover->handler(vm, hash_addr, (uint64_t)recid, sig_addr, out_addr, 0);
    TEST_ASSERT_EQ(rc, 0);
    TEST_ASSERT_MEM_EQ(out, pubkey_bytes + 1, 64);

    secp256k1_context_destroy(secp_ctx);
    sol_bpf_vm_destroy(vm);
#endif
}

TEST(stack_height_syscall) {
    sol_bpf_vm_t* vm = sol_bpf_vm_new(NULL);
    TEST_ASSERT_NOT_NULL(vm);

    sol_invoke_context_t ctx = {0};
    ctx.stack_height = 3;
    sol_bpf_vm_set_context(vm, &ctx);

    sol_bpf_syscall_t* get_height = find_syscall(vm, "sol_get_stack_height");
    TEST_ASSERT_NOT_NULL(get_height);

    uint64_t rc = get_height->handler(vm, 0, 0, 0, 0, 0);
    TEST_ASSERT_EQ(rc, ctx.stack_height);

    sol_bpf_vm_destroy(vm);
}

TEST(cpi_signer_escalation) {
    sol_bpf_vm_t* vm = sol_bpf_vm_new(NULL);
    TEST_ASSERT_NOT_NULL(vm);

    sol_invoke_context_t ctx = {0};
    ctx.program_id = SOL_SYSTEM_PROGRAM_ID;
    sol_bpf_vm_set_context(vm, &ctx);
    sol_bpf_vm_set_cpi_handler(vm, test_cpi_ok_handler);

    uint8_t mem[512] = {0};
    uint64_t base = SOL_BPF_MM_INPUT_START + 0x5000;
    sol_err_t err = sol_bpf_memory_add_region(&vm->memory, base, mem, sizeof(mem), true);
    TEST_ASSERT_EQ(err, SOL_OK);

    size_t off_instr = 0x00;
    size_t off_meta = 0x40;
    size_t off_info = 0x80;
    size_t off_pubkey = 0xC0;
    size_t off_owner = 0xE0;
    size_t off_lamports = 0x100;

    sol_pubkey_t meta_pubkey = {0};
    meta_pubkey.bytes[0] = 0xAA;
    memcpy(mem + off_pubkey, meta_pubkey.bytes, 32);
    memcpy(mem + off_owner, SOL_SYSTEM_PROGRAM_ID.bytes, 32);
    uint64_t lamports = 1;
    memcpy(mem + off_lamports, &lamports, 8);

    /* Account meta */
    uint64_t meta_pubkey_addr = base + off_pubkey;
    memcpy(mem + off_meta, &meta_pubkey_addr, 8);
    mem[off_meta + 8] = 0; /* is_writable */
    mem[off_meta + 9] = 1; /* is_signer */

    /* Account info */
    sol_bpf_account_info_t info = {0};
    info.pubkey_ptr = base + off_pubkey;
    info.lamports_ptr = base + off_lamports;
    info.data_len = 0;
    info.data_ptr = 0;
    info.owner_ptr = base + off_owner;
    info.rent_epoch = 0;
    info.is_signer = 0;
    info.is_writable = 0;
    info.executable = 0;
    memcpy(mem + off_info, &info, sizeof(info));

    /* Instruction */
    uint64_t program_id_addr = base + off_owner;
    memcpy(mem + off_instr, &program_id_addr, 8);
    uint64_t accounts_ptr = base + off_meta;
    uint64_t accounts_len = 1;
    uint64_t data_ptr = 0;
    uint64_t data_len = 0;
    memcpy(mem + off_instr + 8, &accounts_ptr, 8);
    memcpy(mem + off_instr + 16, &accounts_len, 8);
    memcpy(mem + off_instr + 24, &data_ptr, 8);
    memcpy(mem + off_instr + 32, &data_len, 8);

    sol_bpf_syscall_t* invoke = find_syscall(vm, "sol_invoke_signed_c");
    TEST_ASSERT_NOT_NULL(invoke);

    uint64_t rc = invoke->handler(vm, base + off_instr, base + off_info, 1, 0, 0);
    TEST_ASSERT_NE(rc, 0);

    sol_bpf_vm_destroy(vm);
}

TEST(cpi_writable_escalation) {
    sol_bpf_vm_t* vm = sol_bpf_vm_new(NULL);
    TEST_ASSERT_NOT_NULL(vm);

    sol_invoke_context_t ctx = {0};
    ctx.program_id = SOL_SYSTEM_PROGRAM_ID;
    sol_bpf_vm_set_context(vm, &ctx);
    sol_bpf_vm_set_cpi_handler(vm, test_cpi_ok_handler);

    uint8_t mem[512] = {0};
    uint64_t base = SOL_BPF_MM_INPUT_START + 0x6000;
    sol_err_t err = sol_bpf_memory_add_region(&vm->memory, base, mem, sizeof(mem), true);
    TEST_ASSERT_EQ(err, SOL_OK);

    size_t off_instr = 0x00;
    size_t off_meta = 0x40;
    size_t off_info = 0x80;
    size_t off_pubkey = 0xC0;
    size_t off_owner = 0xE0;
    size_t off_lamports = 0x100;

    sol_pubkey_t meta_pubkey = {0};
    meta_pubkey.bytes[0] = 0xBB;
    memcpy(mem + off_pubkey, meta_pubkey.bytes, 32);
    memcpy(mem + off_owner, SOL_SYSTEM_PROGRAM_ID.bytes, 32);
    uint64_t lamports = 1;
    memcpy(mem + off_lamports, &lamports, 8);

    uint64_t meta_pubkey_addr = base + off_pubkey;
    memcpy(mem + off_meta, &meta_pubkey_addr, 8);
    mem[off_meta + 8] = 1; /* is_writable */
    mem[off_meta + 9] = 0; /* is_signer */

    sol_bpf_account_info_t info = {0};
    info.pubkey_ptr = base + off_pubkey;
    info.lamports_ptr = base + off_lamports;
    info.data_len = 0;
    info.data_ptr = 0;
    info.owner_ptr = base + off_owner;
    info.rent_epoch = 0;
    info.is_signer = 0;
    info.is_writable = 0;
    info.executable = 0;
    memcpy(mem + off_info, &info, sizeof(info));

    uint64_t program_id_addr = base + off_owner;
    memcpy(mem + off_instr, &program_id_addr, 8);
    uint64_t accounts_ptr = base + off_meta;
    uint64_t accounts_len = 1;
    uint64_t data_ptr = 0;
    uint64_t data_len = 0;
    memcpy(mem + off_instr + 8, &accounts_ptr, 8);
    memcpy(mem + off_instr + 16, &accounts_len, 8);
    memcpy(mem + off_instr + 24, &data_ptr, 8);
    memcpy(mem + off_instr + 32, &data_len, 8);

    sol_bpf_syscall_t* invoke = find_syscall(vm, "sol_invoke_signed_c");
    TEST_ASSERT_NOT_NULL(invoke);

    uint64_t rc = invoke->handler(vm, base + off_instr, base + off_info, 1, 0, 0);
    TEST_ASSERT_NE(rc, 0);

    sol_bpf_vm_destroy(vm);
}

TEST(cpi_pda_signer) {
    sol_bpf_vm_t* vm = sol_bpf_vm_new(NULL);
    TEST_ASSERT_NOT_NULL(vm);

    sol_pubkey_t program_id = {0};
    program_id.bytes[0] = 0x11;
    sol_invoke_context_t ctx = {0};
    ctx.program_id = program_id;
    sol_bpf_vm_set_context(vm, &ctx);
    sol_bpf_vm_set_cpi_handler(vm, test_cpi_ok_handler);

    uint8_t mem[512] = {0};
    uint64_t base = SOL_BPF_MM_INPUT_START + 0x7000;
    sol_err_t err = sol_bpf_memory_add_region(&vm->memory, base, mem, sizeof(mem), true);
    TEST_ASSERT_EQ(err, SOL_OK);

    const uint8_t seed[] = {0x01, 0x02, 0x03};
    sol_pubkey_t pda = {0};
    uint8_t bump = 0;
    bool found = find_pda_for_seed(&program_id, seed, sizeof(seed), &pda, &bump);
    TEST_ASSERT(found);

    size_t off_instr = 0x00;
    size_t off_meta = 0x40;
    size_t off_info = 0x80;
    size_t off_pubkey = 0xC0;
    size_t off_owner = 0xE0;
    size_t off_lamports = 0x100;
    size_t off_seed = 0x110;
    size_t off_bump = 0x118;
    size_t off_seeds = 0x130;
    size_t off_signer_seeds = 0x160;
    size_t off_program_id = 0x180;

    memcpy(mem + off_pubkey, pda.bytes, 32);
    memcpy(mem + off_program_id, program_id.bytes, 32);
    memcpy(mem + off_owner, SOL_SYSTEM_PROGRAM_ID.bytes, 32);
    uint64_t lamports = 1;
    memcpy(mem + off_lamports, &lamports, 8);
    memcpy(mem + off_seed, seed, sizeof(seed));
    mem[off_bump] = bump;

    uint64_t pda_pubkey_addr = base + off_pubkey;
    memcpy(mem + off_meta, &pda_pubkey_addr, 8);
    mem[off_meta + 8] = 0; /* is_writable */
    mem[off_meta + 9] = 1; /* is_signer */

    sol_bpf_account_info_t info = {0};
    info.pubkey_ptr = base + off_pubkey;
    info.lamports_ptr = base + off_lamports;
    info.data_len = 0;
    info.data_ptr = 0;
    info.owner_ptr = base + off_owner;
    info.rent_epoch = 0;
    info.is_signer = 0;
    info.is_writable = 0;
    info.executable = 0;
    memcpy(mem + off_info, &info, sizeof(info));

    /* Seeds array (2 entries) */
    uint64_t seed_ptr = base + off_seed;
    uint64_t seed_len = sizeof(seed);
    uint64_t bump_ptr = base + off_bump;
    uint64_t bump_len = 1;
    memcpy(mem + off_seeds, &seed_ptr, 8);
    memcpy(mem + off_seeds + 8, &seed_len, 8);
    memcpy(mem + off_seeds + 16, &bump_ptr, 8);
    memcpy(mem + off_seeds + 24, &bump_len, 8);

    /* Signer seeds array (1 entry) */
    uint64_t seeds_ptr = base + off_seeds;
    uint64_t seeds_len = 2;
    memcpy(mem + off_signer_seeds, &seeds_ptr, 8);
    memcpy(mem + off_signer_seeds + 8, &seeds_len, 8);

    uint64_t program_id_addr = base + off_program_id;
    memcpy(mem + off_instr, &program_id_addr, 8);
    uint64_t accounts_ptr = base + off_meta;
    uint64_t accounts_len = 1;
    uint64_t data_ptr = 0;
    uint64_t data_len = 0;
    memcpy(mem + off_instr + 8, &accounts_ptr, 8);
    memcpy(mem + off_instr + 16, &accounts_len, 8);
    memcpy(mem + off_instr + 24, &data_ptr, 8);
    memcpy(mem + off_instr + 32, &data_len, 8);

    sol_bpf_syscall_t* invoke = find_syscall(vm, "sol_invoke_signed_c");
    TEST_ASSERT_NOT_NULL(invoke);

    uint64_t rc = invoke->handler(vm, base + off_instr, base + off_info, 1,
                                  base + off_signer_seeds, 1);
    TEST_ASSERT_EQ(rc, 0);

    sol_bpf_vm_destroy(vm);
}

TEST(cpi_return_data_propagation) {
    sol_bpf_vm_t* vm = sol_bpf_vm_new(NULL);
    TEST_ASSERT_NOT_NULL(vm);

    sol_bank_t* bank = sol_bank_new(0, NULL, NULL, NULL);
    TEST_ASSERT_NOT_NULL(bank);

    sol_invoke_context_t ctx = {0};
    ctx.program_id = SOL_SYSTEM_PROGRAM_ID;
    ctx.bank = bank;
    sol_bpf_vm_set_context(vm, &ctx);
    sol_bpf_vm_set_cpi_handler(vm, sol_bpf_loader_cpi_dispatch);

    uint8_t mem[256] = {0};
    uint64_t base = SOL_BPF_MM_INPUT_START + 0x9000;
    sol_err_t err = sol_bpf_memory_add_region(&vm->memory, base, mem, sizeof(mem), true);
    TEST_ASSERT_EQ(err, SOL_OK);

    size_t off_instr = 0x00;
    size_t off_program_id = 0x40;
    size_t off_data = 0x80;

    uint32_t instr_type = SOL_STAKE_INSTR_GET_MINIMUM_DELEGATION;
    memcpy(mem + off_data, &instr_type, 4);

    memcpy(mem + off_program_id, SOL_STAKE_PROGRAM_ID.bytes, 32);
    uint64_t program_id_addr = base + off_program_id;
    memcpy(mem + off_instr, &program_id_addr, 8);
    uint64_t accounts_ptr = 0;
    uint64_t accounts_len = 0;
    uint64_t data_ptr = base + off_data;
    uint64_t data_len = 4;
    memcpy(mem + off_instr + 8, &accounts_ptr, 8);
    memcpy(mem + off_instr + 16, &accounts_len, 8);
    memcpy(mem + off_instr + 24, &data_ptr, 8);
    memcpy(mem + off_instr + 32, &data_len, 8);

    sol_bpf_syscall_t* invoke = find_syscall(vm, "sol_invoke_signed_c");
    TEST_ASSERT_NOT_NULL(invoke);

    uint64_t rc = invoke->handler(vm, base + off_instr, 0, 0, 0, 0);
    TEST_ASSERT_EQ(rc, 0);
    TEST_ASSERT_EQ(ctx.return_data_len, 8);
    TEST_ASSERT_MEM_EQ(ctx.return_data_program.bytes, SOL_STAKE_PROGRAM_ID.bytes, 32);

    uint64_t min_delegation = 0;
    memcpy(&min_delegation, ctx.return_data, 8);
    TEST_ASSERT_EQ(min_delegation, SOL_MIN_STAKE_DELEGATION);

    sol_bank_destroy(bank);
    sol_bpf_vm_destroy(vm);
}

TEST(cpi_account_propagation) {
    sol_bpf_vm_t* vm = sol_bpf_vm_new(NULL);
    TEST_ASSERT_NOT_NULL(vm);

    sol_bank_t* bank = sol_bank_new(0, NULL, NULL, NULL);
    TEST_ASSERT_NOT_NULL(bank);

    sol_pubkey_t from = {0};
    from.bytes[0] = 0x01;
    sol_pubkey_t to = {0};
    to.bytes[0] = 0x02;

    sol_account_t* from_account = sol_account_new(0, 0, &SOL_SYSTEM_PROGRAM_ID);
    sol_account_t* to_account = sol_account_new(0, 0, &SOL_SYSTEM_PROGRAM_ID);
    TEST_ASSERT_NOT_NULL(from_account);
    TEST_ASSERT_NOT_NULL(to_account);

    sol_err_t err = sol_bank_store_account(bank, &from, from_account);
    TEST_ASSERT_EQ(err, SOL_OK);
    err = sol_bank_store_account(bank, &to, to_account);
    TEST_ASSERT_EQ(err, SOL_OK);

    sol_account_destroy(from_account);
    sol_account_destroy(to_account);

    sol_invoke_context_t ctx = {0};
    ctx.program_id = SOL_SYSTEM_PROGRAM_ID;
    ctx.bank = bank;
    sol_bpf_vm_set_context(vm, &ctx);
    sol_bpf_vm_set_cpi_handler(vm, sol_bpf_loader_cpi_dispatch);

    uint8_t mem[512] = {0};
    uint64_t base = SOL_BPF_MM_INPUT_START + 0xA000;
    err = sol_bpf_memory_add_region(&vm->memory, base, mem, sizeof(mem), true);
    TEST_ASSERT_EQ(err, SOL_OK);

    size_t off_instr = 0x00;
    size_t off_meta = 0x40;
    size_t off_info = 0xA0;
    size_t off_from_pk = 0x120;
    size_t off_to_pk = 0x140;
    size_t off_owner = 0x160;
    size_t off_from_lamports = 0x180;
    size_t off_to_lamports = 0x188;
    size_t off_data = 0x190;

    memcpy(mem + off_from_pk, from.bytes, 32);
    memcpy(mem + off_to_pk, to.bytes, 32);
    memcpy(mem + off_owner, SOL_SYSTEM_PROGRAM_ID.bytes, 32);

    uint64_t from_lamports = 50;
    uint64_t to_lamports = 0;
    memcpy(mem + off_from_lamports, &from_lamports, 8);
    memcpy(mem + off_to_lamports, &to_lamports, 8);

    /* Account metas (from, to) */
    uint64_t from_pubkey_addr = base + off_from_pk;
    memcpy(mem + off_meta, &from_pubkey_addr, 8);
    mem[off_meta + 8] = 1; /* is_writable */
    mem[off_meta + 9] = 1; /* is_signer */

    uint64_t to_pubkey_addr = base + off_to_pk;
    memcpy(mem + off_meta + 16, &to_pubkey_addr, 8);
    mem[off_meta + 16 + 8] = 1; /* is_writable */
    mem[off_meta + 16 + 9] = 0; /* is_signer */

    sol_bpf_account_info_t info_from = {0};
    info_from.pubkey_ptr = base + off_from_pk;
    info_from.lamports_ptr = base + off_from_lamports;
    info_from.data_len = 0;
    info_from.data_ptr = 0;
    info_from.owner_ptr = base + off_owner;
    info_from.rent_epoch = 0;
    info_from.is_signer = 1;
    info_from.is_writable = 1;
    info_from.executable = 0;

    sol_bpf_account_info_t info_to = {0};
    info_to.pubkey_ptr = base + off_to_pk;
    info_to.lamports_ptr = base + off_to_lamports;
    info_to.data_len = 0;
    info_to.data_ptr = 0;
    info_to.owner_ptr = base + off_owner;
    info_to.rent_epoch = 0;
    info_to.is_signer = 0;
    info_to.is_writable = 1;
    info_to.executable = 0;

    memcpy(mem + off_info, &info_from, sizeof(info_from));
    memcpy(mem + off_info + sizeof(info_from), &info_to, sizeof(info_to));

    uint32_t instr_type = SOL_SYSTEM_INSTR_TRANSFER;
    uint64_t lamports = 10;
    memcpy(mem + off_data, &instr_type, 4);
    memcpy(mem + off_data + 4, &lamports, 8);

    uint64_t program_id_addr = base + off_owner;
    memcpy(mem + off_instr, &program_id_addr, 8);
    uint64_t accounts_ptr = base + off_meta;
    uint64_t accounts_len = 2;
    uint64_t data_ptr = base + off_data;
    uint64_t data_len = 12;
    memcpy(mem + off_instr + 8, &accounts_ptr, 8);
    memcpy(mem + off_instr + 16, &accounts_len, 8);
    memcpy(mem + off_instr + 24, &data_ptr, 8);
    memcpy(mem + off_instr + 32, &data_len, 8);

    sol_bpf_syscall_t* invoke = find_syscall(vm, "sol_invoke_signed_c");
    TEST_ASSERT_NOT_NULL(invoke);

    uint64_t rc = invoke->handler(vm, base + off_instr, base + off_info, 2, 0, 0);
    TEST_ASSERT_EQ(rc, 0);

    uint64_t out_from = 0;
    uint64_t out_to = 0;
    memcpy(&out_from, mem + off_from_lamports, 8);
    memcpy(&out_to, mem + off_to_lamports, 8);
    TEST_ASSERT_EQ(out_from, 40);
    TEST_ASSERT_EQ(out_to, 10);

    sol_bank_destroy(bank);
    sol_bpf_vm_destroy(vm);
}

/*
 * Test cases array
 */
static test_case_t bpf_tests[] = {
    TEST_CASE(vm_create),
    TEST_CASE(bpf_loader_compute_meter),
    TEST_CASE(simple_exit),
    TEST_CASE(arithmetic),
    TEST_CASE(reg_move),
    TEST_CASE(jump),
    TEST_CASE(memory),
    TEST_CASE(divide_by_zero),
    TEST_CASE(srem64),
    TEST_CASE(srem64_divisor_zero),
    TEST_CASE(srem64_overflow_case),
    TEST_CASE(compute_budget),
    TEST_CASE(lddw),
    TEST_CASE(elf_data_reloc_r_bpf_64_64),
    TEST_CASE(alu32),
    TEST_CASE(return_data_syscalls),
    TEST_CASE(clock_sysvar_syscall),
    TEST_CASE(rent_sysvar_syscall),
    TEST_CASE(epoch_schedule_sysvar_syscall),
    TEST_CASE(fees_sysvar_syscall),
    TEST_CASE(secp256k1_recover_syscall),
    TEST_CASE(stack_height_syscall),
    TEST_CASE(cpi_signer_escalation),
    TEST_CASE(cpi_writable_escalation),
    TEST_CASE(cpi_pda_signer),
    TEST_CASE(cpi_return_data_propagation),
    TEST_CASE(cpi_account_propagation),
};

int main(void) {
    return RUN_TESTS("BPF VM Tests", bpf_tests);
}
