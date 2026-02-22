/*
 * sol_bpf_jit.c - BPF JIT Compiler for x86_64
 *
 * Compiles sBPF bytecode to native x86_64 machine code for
 * high-performance program execution.
 */

#include "sol_bpf.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include <string.h>
#include <sys/mman.h>

#ifdef __x86_64__

/*
 * x86_64 register mapping
 *
 * BPF registers are mapped to x86_64 registers:
 *   r0 -> rax  (return value / accumulator)
 *   r1 -> rdi  (arg1)
 *   r2 -> rsi  (arg2)
 *   r3 -> rdx  (arg3)
 *   r4 -> rcx  (arg4)
 *   r5 -> r8   (arg5)
 *   r6 -> rbx  (callee-saved)
 *   r7 -> r13  (callee-saved)
 *   r8 -> r14  (callee-saved)
 *   r9 -> r15  (callee-saved)
 *   r10 -> rbp (frame pointer, callee-saved)
 */

/* x86_64 register encoding */
#define X64_RAX  0
#define X64_RCX  1
#define X64_RDX  2
#define X64_RBX  3
#define X64_RSP  4
#define X64_RBP  5
#define X64_RSI  6
#define X64_RDI  7
#define X64_R8   8
#define X64_R9   9
#define X64_R10  10
#define X64_R11  11
#define X64_R12  12
#define X64_R13  13
#define X64_R14  14
#define X64_R15  15

/* BPF to x86_64 register mapping */
static const uint8_t bpf_to_x64[SOL_BPF_NUM_REGISTERS] = {
    X64_RAX,   /* r0 */
    X64_RDI,   /* r1 */
    X64_RSI,   /* r2 */
    X64_RDX,   /* r3 */
    X64_RCX,   /* r4 */
    X64_R8,    /* r5 */
    X64_RBX,   /* r6 */
    X64_R13,   /* r7 */
    X64_R14,   /* r8 */
    X64_R15,   /* r9 */
    X64_RBP,   /* r10 (frame pointer) */
};

/*
 * JIT code buffer
 */
typedef struct {
    uint8_t*    code;           /* Code buffer */
    size_t      code_len;       /* Current code length */
    size_t      code_cap;       /* Buffer capacity */
    uint32_t*   insn_offsets;   /* Offset of each BPF instruction */
    size_t      insn_count;     /* Number of BPF instructions */
    /* Fixups for forward jumps */
    uint32_t*   jump_targets;   /* Jump target BPF instruction indices */
    uint32_t*   jump_offsets;   /* Offset of jump displacement in code */
    size_t      jump_count;
    size_t      jump_cap;
} jit_buffer_t;

/*
 * Emit bytes to JIT buffer
 */
static sol_err_t
emit_bytes(jit_buffer_t* jit, const uint8_t* bytes, size_t len) {
    if (jit->code_len + len > jit->code_cap) {
        size_t new_cap = jit->code_cap * 2;
        if (new_cap < jit->code_len + len) {
            new_cap = jit->code_len + len + 4096;
        }
        uint8_t* new_code = sol_realloc(jit->code, new_cap);
        if (new_code == NULL) {
            return SOL_ERR_NOMEM;
        }
        jit->code = new_code;
        jit->code_cap = new_cap;
    }
    memcpy(jit->code + jit->code_len, bytes, len);
    jit->code_len += len;
    return SOL_OK;
}

/* Emit single byte */
static sol_err_t emit_u8(jit_buffer_t* jit, uint8_t val) {
    return emit_bytes(jit, &val, 1);
}

/* Emit 32-bit value */
static sol_err_t emit_u32(jit_buffer_t* jit, uint32_t val) {
    return emit_bytes(jit, (uint8_t*)&val, 4);
}

/* Emit 64-bit value */
static sol_err_t emit_u64(jit_buffer_t* jit, uint64_t val) {
    return emit_bytes(jit, (uint8_t*)&val, 8);
}

/*
 * REX prefix for 64-bit operations
 */
static uint8_t rex_wrxb(bool w, bool r, bool x, bool b) {
    return 0x40 | (w ? 8 : 0) | (r ? 4 : 0) | (x ? 2 : 0) | (b ? 1 : 0);
}

/*
 * ModR/M byte
 */
static uint8_t modrm(uint8_t mod, uint8_t reg, uint8_t rm) {
    return (mod << 6) | ((reg & 7) << 3) | (rm & 7);
}

/*
 * Emit REX prefix if needed for register pair
 */
static sol_err_t
emit_rex_opt(jit_buffer_t* jit, uint8_t dst, uint8_t src, bool w) {
    bool r = src >= 8;
    bool b = dst >= 8;
    if (w || r || b) {
        SOL_TRY(emit_u8(jit, rex_wrxb(w, r, false, b)));
    }
    return SOL_OK;
}

/*
 * Emit ALU64 reg-reg: op dst, src
 */
static sol_err_t
emit_alu64_rr(jit_buffer_t* jit, uint8_t opcode, uint8_t dst, uint8_t src) {
    SOL_TRY(emit_u8(jit, rex_wrxb(true, src >= 8, false, dst >= 8)));
    SOL_TRY(emit_u8(jit, opcode));
    SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
    return SOL_OK;
}

/*
 * Emit ALU64 reg-imm32: op dst, imm
 */
static sol_err_t
emit_alu64_ri(jit_buffer_t* jit, uint8_t opcode_ext, uint8_t dst, int32_t imm) {
    SOL_TRY(emit_u8(jit, rex_wrxb(true, false, false, dst >= 8)));
    SOL_TRY(emit_u8(jit, 0x81));
    SOL_TRY(emit_u8(jit, modrm(3, opcode_ext, dst)));
    SOL_TRY(emit_u32(jit, (uint32_t)imm));
    return SOL_OK;
}

/*
 * Emit MOV reg, imm64
 */
static sol_err_t
emit_mov64_ri(jit_buffer_t* jit, uint8_t dst, uint64_t imm) {
    SOL_TRY(emit_u8(jit, rex_wrxb(true, false, false, dst >= 8)));
    SOL_TRY(emit_u8(jit, 0xB8 + (dst & 7)));
    SOL_TRY(emit_u64(jit, imm));
    return SOL_OK;
}

/*
 * Emit MOV reg, reg
 */
static sol_err_t
emit_mov64_rr(jit_buffer_t* jit, uint8_t dst, uint8_t src) {
    return emit_alu64_rr(jit, 0x89, dst, src);
}

/*
 * Emit load/store operations
 */
static sol_err_t
emit_load(jit_buffer_t* jit, uint8_t dst, uint8_t base, int32_t off, uint8_t size) {
    /* size: 1=byte, 2=word, 4=dword, 8=qword */
    uint8_t opcode;
    bool rex_w = false;

    switch (size) {
        case 1:
            opcode = 0x8A;  /* MOV r8, m8 */
            SOL_TRY(emit_rex_opt(jit, dst, base, false));
            break;
        case 2:
            SOL_TRY(emit_u8(jit, 0x66));  /* Operand size prefix */
            opcode = 0x8B;  /* MOV r16, m16 */
            SOL_TRY(emit_rex_opt(jit, dst, base, false));
            break;
        case 4:
            opcode = 0x8B;  /* MOV r32, m32 */
            SOL_TRY(emit_rex_opt(jit, dst, base, false));
            break;
        case 8:
            opcode = 0x8B;  /* MOV r64, m64 */
            rex_w = true;
            SOL_TRY(emit_u8(jit, rex_wrxb(true, dst >= 8, false, base >= 8)));
            break;
        default:
            return SOL_ERR_INVAL;
    }

    if (!rex_w) {
        SOL_TRY(emit_u8(jit, opcode));
    } else {
        SOL_TRY(emit_u8(jit, opcode));
    }

    /* ModR/M with displacement */
    if (off == 0 && (base & 7) != 5) {
        SOL_TRY(emit_u8(jit, modrm(0, dst, base)));
    } else if (off >= -128 && off <= 127) {
        SOL_TRY(emit_u8(jit, modrm(1, dst, base)));
        SOL_TRY(emit_u8(jit, (uint8_t)off));
    } else {
        SOL_TRY(emit_u8(jit, modrm(2, dst, base)));
        SOL_TRY(emit_u32(jit, (uint32_t)off));
    }

    /* Zero-extend for smaller loads */
    if (size < 8 && size > 1) {
        /* movzx is already implied for 32-bit loads (zero extends to 64) */
        /* For 8 and 16 bit, we need explicit zero extension */
        if (size == 1 || size == 2) {
            /* movzx r64, r8/r16 */
            SOL_TRY(emit_u8(jit, rex_wrxb(true, dst >= 8, false, dst >= 8)));
            SOL_TRY(emit_u8(jit, 0x0F));
            SOL_TRY(emit_u8(jit, size == 1 ? 0xB6 : 0xB7));
            SOL_TRY(emit_u8(jit, modrm(3, dst, dst)));
        }
    }

    return SOL_OK;
}

static sol_err_t
emit_store(jit_buffer_t* jit, uint8_t base, int32_t off, uint8_t src, uint8_t size) {
    uint8_t opcode;

    switch (size) {
        case 1:
            opcode = 0x88;  /* MOV m8, r8 */
            SOL_TRY(emit_rex_opt(jit, base, src, false));
            break;
        case 2:
            SOL_TRY(emit_u8(jit, 0x66));  /* Operand size prefix */
            opcode = 0x89;
            SOL_TRY(emit_rex_opt(jit, base, src, false));
            break;
        case 4:
            opcode = 0x89;
            SOL_TRY(emit_rex_opt(jit, base, src, false));
            break;
        case 8:
            opcode = 0x89;
            SOL_TRY(emit_u8(jit, rex_wrxb(true, src >= 8, false, base >= 8)));
            break;
        default:
            return SOL_ERR_INVAL;
    }

    SOL_TRY(emit_u8(jit, opcode));

    /* ModR/M with displacement */
    if (off == 0 && (base & 7) != 5) {
        SOL_TRY(emit_u8(jit, modrm(0, src, base)));
    } else if (off >= -128 && off <= 127) {
        SOL_TRY(emit_u8(jit, modrm(1, src, base)));
        SOL_TRY(emit_u8(jit, (uint8_t)off));
    } else {
        SOL_TRY(emit_u8(jit, modrm(2, src, base)));
        SOL_TRY(emit_u32(jit, (uint32_t)off));
    }

    return SOL_OK;
}

/*
 * Emit conditional jump
 */
static sol_err_t
emit_jcc(jit_buffer_t* jit, uint8_t cc, int32_t target_pc) {
    /* Record jump for fixup */
    if (jit->jump_count >= jit->jump_cap) {
        size_t new_cap = jit->jump_cap * 2;
        if (new_cap == 0) new_cap = 256;
        uint32_t* new_targets = sol_realloc(jit->jump_targets, new_cap * sizeof(uint32_t));
        uint32_t* new_offsets = sol_realloc(jit->jump_offsets, new_cap * sizeof(uint32_t));
        if (new_targets == NULL || new_offsets == NULL) {
            return SOL_ERR_NOMEM;
        }
        jit->jump_targets = new_targets;
        jit->jump_offsets = new_offsets;
        jit->jump_cap = new_cap;
    }

    jit->jump_targets[jit->jump_count] = (uint32_t)target_pc;
    jit->jump_offsets[jit->jump_count] = (uint32_t)(jit->code_len + 2);  /* After opcode */
    jit->jump_count++;

    /* Emit jcc rel32 (0F 80+cc disp32) */
    SOL_TRY(emit_u8(jit, 0x0F));
    SOL_TRY(emit_u8(jit, 0x80 + cc));
    SOL_TRY(emit_u32(jit, 0));  /* Placeholder, will be fixed up later */

    return SOL_OK;
}

/*
 * Emit unconditional jump
 */
static sol_err_t
emit_jmp(jit_buffer_t* jit, int32_t target_pc) {
    /* Record jump for fixup */
    if (jit->jump_count >= jit->jump_cap) {
        size_t new_cap = jit->jump_cap * 2;
        if (new_cap == 0) new_cap = 256;
        jit->jump_targets = sol_realloc(jit->jump_targets, new_cap * sizeof(uint32_t));
        jit->jump_offsets = sol_realloc(jit->jump_offsets, new_cap * sizeof(uint32_t));
        if (jit->jump_targets == NULL || jit->jump_offsets == NULL) {
            return SOL_ERR_NOMEM;
        }
        jit->jump_cap = new_cap;
    }

    jit->jump_targets[jit->jump_count] = (uint32_t)target_pc;
    jit->jump_offsets[jit->jump_count] = (uint32_t)(jit->code_len + 1);
    jit->jump_count++;

    /* Emit jmp rel32 (E9 disp32) */
    SOL_TRY(emit_u8(jit, 0xE9));
    SOL_TRY(emit_u32(jit, 0));

    return SOL_OK;
}

/*
 * Condition codes for x86_64 Jcc
 */
#define X64_CC_O   0x0   /* Overflow */
#define X64_CC_NO  0x1   /* No overflow */
#define X64_CC_B   0x2   /* Below (unsigned <) */
#define X64_CC_AE  0x3   /* Above or equal (unsigned >=) */
#define X64_CC_E   0x4   /* Equal */
#define X64_CC_NE  0x5   /* Not equal */
#define X64_CC_BE  0x6   /* Below or equal (unsigned <=) */
#define X64_CC_A   0x7   /* Above (unsigned >) */
#define X64_CC_S   0x8   /* Sign */
#define X64_CC_NS  0x9   /* No sign */
#define X64_CC_L   0xC   /* Less (signed <) */
#define X64_CC_GE  0xD   /* Greater or equal (signed >=) */
#define X64_CC_LE  0xE   /* Less or equal (signed <=) */
#define X64_CC_G   0xF   /* Greater (signed >) */

/*
 * Emit function prologue
 */
static sol_err_t
emit_prologue(jit_buffer_t* jit) {
    /* Save callee-saved registers */
    /* push rbx */
    SOL_TRY(emit_u8(jit, 0x53));
    /* push r13 */
    SOL_TRY(emit_u8(jit, 0x41));
    SOL_TRY(emit_u8(jit, 0x55));
    /* push r14 */
    SOL_TRY(emit_u8(jit, 0x41));
    SOL_TRY(emit_u8(jit, 0x56));
    /* push r15 */
    SOL_TRY(emit_u8(jit, 0x41));
    SOL_TRY(emit_u8(jit, 0x57));
    /* push rbp */
    SOL_TRY(emit_u8(jit, 0x55));

    return SOL_OK;
}

/*
 * Emit function epilogue
 */
static sol_err_t
emit_epilogue(jit_buffer_t* jit) {
    /* Restore callee-saved registers */
    /* pop rbp */
    SOL_TRY(emit_u8(jit, 0x5D));
    /* pop r15 */
    SOL_TRY(emit_u8(jit, 0x41));
    SOL_TRY(emit_u8(jit, 0x5F));
    /* pop r14 */
    SOL_TRY(emit_u8(jit, 0x41));
    SOL_TRY(emit_u8(jit, 0x5E));
    /* pop r13 */
    SOL_TRY(emit_u8(jit, 0x41));
    SOL_TRY(emit_u8(jit, 0x5D));
    /* pop rbx */
    SOL_TRY(emit_u8(jit, 0x5B));
    /* ret */
    SOL_TRY(emit_u8(jit, 0xC3));

    return SOL_OK;
}

/*
 * Compile a single BPF instruction
 */
static sol_err_t
compile_insn(jit_buffer_t* jit, const sol_bpf_insn_t* insn, size_t pc) {
    uint8_t opcode = insn->opcode;
    uint8_t dst_bpf = insn->regs & 0xF;
    uint8_t src_bpf = (insn->regs >> 4) & 0xF;
    uint8_t dst = bpf_to_x64[dst_bpf];
    uint8_t src = bpf_to_x64[src_bpf];
    int16_t off = insn->offset;
    int32_t imm = insn->imm;

    uint8_t cls = opcode & 0x07;
    uint8_t alu_op = opcode & 0xF0;
    bool is_imm = (opcode & 0x08) == 0;

    (void)pc;

    switch (cls) {
        case SOL_BPF_CLASS_ALU64:
            switch (alu_op) {
                case SOL_BPF_ALU_ADD:
                    if (is_imm) {
                        SOL_TRY(emit_alu64_ri(jit, 0, dst, imm));  /* add dst, imm */
                    } else {
                        SOL_TRY(emit_alu64_rr(jit, 0x01, dst, src));  /* add dst, src */
                    }
                    break;
                case SOL_BPF_ALU_SUB:
                    if (is_imm) {
                        SOL_TRY(emit_alu64_ri(jit, 5, dst, imm));  /* sub dst, imm */
                    } else {
                        SOL_TRY(emit_alu64_rr(jit, 0x29, dst, src));  /* sub dst, src */
                    }
                    break;
                case SOL_BPF_ALU_MOV:
                    if (is_imm) {
                        SOL_TRY(emit_mov64_ri(jit, dst, (uint64_t)(int64_t)imm));
                    } else {
                        SOL_TRY(emit_mov64_rr(jit, dst, src));
                    }
                    break;
                case SOL_BPF_ALU_OR:
                    if (is_imm) {
                        SOL_TRY(emit_alu64_ri(jit, 1, dst, imm));
                    } else {
                        SOL_TRY(emit_alu64_rr(jit, 0x09, dst, src));
                    }
                    break;
                case SOL_BPF_ALU_AND:
                    if (is_imm) {
                        SOL_TRY(emit_alu64_ri(jit, 4, dst, imm));
                    } else {
                        SOL_TRY(emit_alu64_rr(jit, 0x21, dst, src));
                    }
                    break;
                case SOL_BPF_ALU_XOR:
                    if (is_imm) {
                        SOL_TRY(emit_alu64_ri(jit, 6, dst, imm));
                    } else {
                        SOL_TRY(emit_alu64_rr(jit, 0x31, dst, src));
                    }
                    break;
                case SOL_BPF_ALU_LSH:
                    if (is_imm) {
                        /* shl dst, imm */
                        SOL_TRY(emit_u8(jit, rex_wrxb(true, false, false, dst >= 8)));
                        SOL_TRY(emit_u8(jit, 0xC1));
                        SOL_TRY(emit_u8(jit, modrm(3, 4, dst)));
                        SOL_TRY(emit_u8(jit, imm & 0x3F));
                    } else {
                        /* mov rcx, src; shl dst, cl */
                        if (src != X64_RCX) {
                            SOL_TRY(emit_mov64_rr(jit, X64_RCX, src));
                        }
                        SOL_TRY(emit_u8(jit, rex_wrxb(true, false, false, dst >= 8)));
                        SOL_TRY(emit_u8(jit, 0xD3));
                        SOL_TRY(emit_u8(jit, modrm(3, 4, dst)));
                    }
                    break;
                case SOL_BPF_ALU_RSH:
                    if (is_imm) {
                        /* shr dst, imm */
                        SOL_TRY(emit_u8(jit, rex_wrxb(true, false, false, dst >= 8)));
                        SOL_TRY(emit_u8(jit, 0xC1));
                        SOL_TRY(emit_u8(jit, modrm(3, 5, dst)));
                        SOL_TRY(emit_u8(jit, imm & 0x3F));
                    } else {
                        if (src != X64_RCX) {
                            SOL_TRY(emit_mov64_rr(jit, X64_RCX, src));
                        }
                        SOL_TRY(emit_u8(jit, rex_wrxb(true, false, false, dst >= 8)));
                        SOL_TRY(emit_u8(jit, 0xD3));
                        SOL_TRY(emit_u8(jit, modrm(3, 5, dst)));
                    }
                    break;
                case SOL_BPF_ALU_ARSH:
                    if (is_imm) {
                        /* sar dst, imm */
                        SOL_TRY(emit_u8(jit, rex_wrxb(true, false, false, dst >= 8)));
                        SOL_TRY(emit_u8(jit, 0xC1));
                        SOL_TRY(emit_u8(jit, modrm(3, 7, dst)));
                        SOL_TRY(emit_u8(jit, imm & 0x3F));
                    } else {
                        if (src != X64_RCX) {
                            SOL_TRY(emit_mov64_rr(jit, X64_RCX, src));
                        }
                        SOL_TRY(emit_u8(jit, rex_wrxb(true, false, false, dst >= 8)));
                        SOL_TRY(emit_u8(jit, 0xD3));
                        SOL_TRY(emit_u8(jit, modrm(3, 7, dst)));
                    }
                    break;
                case SOL_BPF_ALU_MUL:
                    if (is_imm) {
                        /* imul dst, dst, imm */
                        SOL_TRY(emit_u8(jit, rex_wrxb(true, dst >= 8, false, dst >= 8)));
                        SOL_TRY(emit_u8(jit, 0x69));
                        SOL_TRY(emit_u8(jit, modrm(3, dst, dst)));
                        SOL_TRY(emit_u32(jit, (uint32_t)imm));
                    } else {
                        /* imul dst, src */
                        SOL_TRY(emit_u8(jit, rex_wrxb(true, dst >= 8, false, src >= 8)));
                        SOL_TRY(emit_u8(jit, 0x0F));
                        SOL_TRY(emit_u8(jit, 0xAF));
                        SOL_TRY(emit_u8(jit, modrm(3, dst, src)));
                    }
                    break;
                case SOL_BPF_ALU_NEG:
                    /* neg dst */
                    SOL_TRY(emit_u8(jit, rex_wrxb(true, false, false, dst >= 8)));
                    SOL_TRY(emit_u8(jit, 0xF7));
                    SOL_TRY(emit_u8(jit, modrm(3, 3, dst)));
                    break;
                case SOL_BPF_ALU_DIV:
                case SOL_BPF_ALU_MOD:
                    /*
                     * Division uses rax:rdx for dividend, result in rax (div) or rdx (mod)
                     * Save registers, perform division, restore
                     */
                    {
                        /* Push r11 for temporary storage */
                        SOL_TRY(emit_u8(jit, 0x41));
                        SOL_TRY(emit_u8(jit, 0x53));  /* push r11 */

                        /* Save rdx to r11 if dst != rdx */
                        if (dst != X64_RDX) {
                            SOL_TRY(emit_mov64_rr(jit, X64_R11, X64_RDX));
                        }

                        /* Move dst to rax if needed */
                        if (dst != X64_RAX) {
                            SOL_TRY(emit_mov64_rr(jit, X64_RAX, dst));
                        }

                        /* Zero rdx for unsigned division */
                        SOL_TRY(emit_u8(jit, rex_wrxb(true, false, false, false)));
                        SOL_TRY(emit_u8(jit, 0x31));  /* xor rdx, rdx */
                        SOL_TRY(emit_u8(jit, modrm(3, X64_RDX, X64_RDX)));

                        if (is_imm) {
                            /* Move immediate to r10 for division */
                            SOL_TRY(emit_mov64_ri(jit, X64_R10, (uint64_t)(int64_t)imm));
                            /* div r10 */
                            SOL_TRY(emit_u8(jit, rex_wrxb(true, false, false, true)));
                            SOL_TRY(emit_u8(jit, 0xF7));
                            SOL_TRY(emit_u8(jit, modrm(3, 6, X64_R10)));
                        } else {
                            /* div src */
                            SOL_TRY(emit_u8(jit, rex_wrxb(true, false, false, src >= 8)));
                            SOL_TRY(emit_u8(jit, 0xF7));
                            SOL_TRY(emit_u8(jit, modrm(3, 6, src)));
                        }

                        /* Move result to dst */
                        if (alu_op == SOL_BPF_ALU_DIV) {
                            /* Result in rax */
                            if (dst != X64_RAX) {
                                SOL_TRY(emit_mov64_rr(jit, dst, X64_RAX));
                            }
                        } else {
                            /* MOD: Result in rdx */
                            if (dst != X64_RDX) {
                                SOL_TRY(emit_mov64_rr(jit, dst, X64_RDX));
                            }
                        }

                        /* Restore rdx from r11 if needed */
                        if (dst != X64_RDX && alu_op == SOL_BPF_ALU_DIV) {
                            SOL_TRY(emit_mov64_rr(jit, X64_RDX, X64_R11));
                        }

                        /* Pop r11 */
                        SOL_TRY(emit_u8(jit, 0x41));
                        SOL_TRY(emit_u8(jit, 0x5B));  /* pop r11 */
                    }
                    break;
                default:
                    return SOL_ERR_NOT_IMPLEMENTED;
            }
            break;

        case SOL_BPF_CLASS_JMP:
            switch (alu_op) {
                case SOL_BPF_JMP_JA:
                    SOL_TRY(emit_jmp(jit, (int32_t)(pc + 1 + off)));
                    break;
                case SOL_BPF_JMP_JEQ:
                    /* cmp dst, src/imm; je target */
                    if (is_imm) {
                        SOL_TRY(emit_alu64_ri(jit, 7, dst, imm));  /* cmp dst, imm */
                    } else {
                        SOL_TRY(emit_u8(jit, rex_wrxb(true, src >= 8, false, dst >= 8)));
                        SOL_TRY(emit_u8(jit, 0x39));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    SOL_TRY(emit_jcc(jit, X64_CC_E, (int32_t)(pc + 1 + off)));
                    break;
                case SOL_BPF_JMP_JNE:
                    if (is_imm) {
                        SOL_TRY(emit_alu64_ri(jit, 7, dst, imm));
                    } else {
                        SOL_TRY(emit_u8(jit, rex_wrxb(true, src >= 8, false, dst >= 8)));
                        SOL_TRY(emit_u8(jit, 0x39));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    SOL_TRY(emit_jcc(jit, X64_CC_NE, (int32_t)(pc + 1 + off)));
                    break;
                case SOL_BPF_JMP_JGT:
                    if (is_imm) {
                        SOL_TRY(emit_alu64_ri(jit, 7, dst, imm));
                    } else {
                        SOL_TRY(emit_u8(jit, rex_wrxb(true, src >= 8, false, dst >= 8)));
                        SOL_TRY(emit_u8(jit, 0x39));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    SOL_TRY(emit_jcc(jit, X64_CC_A, (int32_t)(pc + 1 + off)));
                    break;
                case SOL_BPF_JMP_JGE:
                    if (is_imm) {
                        SOL_TRY(emit_alu64_ri(jit, 7, dst, imm));
                    } else {
                        SOL_TRY(emit_u8(jit, rex_wrxb(true, src >= 8, false, dst >= 8)));
                        SOL_TRY(emit_u8(jit, 0x39));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    SOL_TRY(emit_jcc(jit, X64_CC_AE, (int32_t)(pc + 1 + off)));
                    break;
                case SOL_BPF_JMP_JLT:
                    if (is_imm) {
                        SOL_TRY(emit_alu64_ri(jit, 7, dst, imm));
                    } else {
                        SOL_TRY(emit_u8(jit, rex_wrxb(true, src >= 8, false, dst >= 8)));
                        SOL_TRY(emit_u8(jit, 0x39));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    SOL_TRY(emit_jcc(jit, X64_CC_B, (int32_t)(pc + 1 + off)));
                    break;
                case SOL_BPF_JMP_JLE:
                    if (is_imm) {
                        SOL_TRY(emit_alu64_ri(jit, 7, dst, imm));
                    } else {
                        SOL_TRY(emit_u8(jit, rex_wrxb(true, src >= 8, false, dst >= 8)));
                        SOL_TRY(emit_u8(jit, 0x39));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    SOL_TRY(emit_jcc(jit, X64_CC_BE, (int32_t)(pc + 1 + off)));
                    break;
                case SOL_BPF_JMP_JSET:
                    /* test dst, src/imm; jne target (jump if bits set) */
                    if (is_imm) {
                        /* test r64, imm32 */
                        SOL_TRY(emit_u8(jit, rex_wrxb(true, false, false, dst >= 8)));
                        SOL_TRY(emit_u8(jit, 0xF7));
                        SOL_TRY(emit_u8(jit, modrm(3, 0, dst)));
                        SOL_TRY(emit_u32(jit, (uint32_t)imm));
                    } else {
                        /* test r64, r64 */
                        SOL_TRY(emit_u8(jit, rex_wrxb(true, src >= 8, false, dst >= 8)));
                        SOL_TRY(emit_u8(jit, 0x85));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    SOL_TRY(emit_jcc(jit, X64_CC_NE, (int32_t)(pc + 1 + off)));
                    break;
                case SOL_BPF_JMP_JSGT:
                    if (is_imm) {
                        SOL_TRY(emit_alu64_ri(jit, 7, dst, imm));
                    } else {
                        SOL_TRY(emit_u8(jit, rex_wrxb(true, src >= 8, false, dst >= 8)));
                        SOL_TRY(emit_u8(jit, 0x39));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    SOL_TRY(emit_jcc(jit, X64_CC_G, (int32_t)(pc + 1 + off)));
                    break;
                case SOL_BPF_JMP_JSGE:
                    if (is_imm) {
                        SOL_TRY(emit_alu64_ri(jit, 7, dst, imm));
                    } else {
                        SOL_TRY(emit_u8(jit, rex_wrxb(true, src >= 8, false, dst >= 8)));
                        SOL_TRY(emit_u8(jit, 0x39));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    SOL_TRY(emit_jcc(jit, X64_CC_GE, (int32_t)(pc + 1 + off)));
                    break;
                case SOL_BPF_JMP_JSLT:
                    if (is_imm) {
                        SOL_TRY(emit_alu64_ri(jit, 7, dst, imm));
                    } else {
                        SOL_TRY(emit_u8(jit, rex_wrxb(true, src >= 8, false, dst >= 8)));
                        SOL_TRY(emit_u8(jit, 0x39));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    SOL_TRY(emit_jcc(jit, X64_CC_L, (int32_t)(pc + 1 + off)));
                    break;
                case SOL_BPF_JMP_JSLE:
                    if (is_imm) {
                        SOL_TRY(emit_alu64_ri(jit, 7, dst, imm));
                    } else {
                        SOL_TRY(emit_u8(jit, rex_wrxb(true, src >= 8, false, dst >= 8)));
                        SOL_TRY(emit_u8(jit, 0x39));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    SOL_TRY(emit_jcc(jit, X64_CC_LE, (int32_t)(pc + 1 + off)));
                    break;
                case SOL_BPF_JMP_EXIT:
                    SOL_TRY(emit_epilogue(jit));
                    break;
                case SOL_BPF_JMP_CALL:
                    /*
                     * BPF CALL instruction
                     * - src=0: syscall (imm is syscall hash) - not supported in JIT
                     * - src=1: internal function call (imm is PC offset)
                     */
                    if (src_bpf == 0) {
                        /* Syscall - requires VM context, fall back to interpreter */
                        sol_log_debug("JIT: Syscall encountered, falling back to interpreter");
                        return SOL_ERR_NOT_IMPLEMENTED;
                    } else {
                        /* Internal function call */
                        /* Save return address and callee-saved regs on BPF stack */
                        /* For now, emit a relative call */
                        int32_t target = (int32_t)(pc + 1 + imm);

                        /* Record jump for fixup */
                        if (jit->jump_count >= jit->jump_cap) {
                            size_t new_cap = jit->jump_cap * 2;
                            if (new_cap == 0) new_cap = 256;
                            jit->jump_targets = sol_realloc(jit->jump_targets, new_cap * sizeof(uint32_t));
                            jit->jump_offsets = sol_realloc(jit->jump_offsets, new_cap * sizeof(uint32_t));
                            if (jit->jump_targets == NULL || jit->jump_offsets == NULL) {
                                return SOL_ERR_NOMEM;
                            }
                            jit->jump_cap = new_cap;
                        }

                        jit->jump_targets[jit->jump_count] = (uint32_t)target;
                        jit->jump_offsets[jit->jump_count] = (uint32_t)(jit->code_len + 1);
                        jit->jump_count++;

                        /* Emit call rel32 (E8 disp32) */
                        SOL_TRY(emit_u8(jit, 0xE8));
                        SOL_TRY(emit_u32(jit, 0));
                    }
                    break;
                default:
                    return SOL_ERR_NOT_IMPLEMENTED;
            }
            break;

        case SOL_BPF_CLASS_LDX:
            {
                uint8_t size = (opcode >> 3) & 0x3;
                uint8_t sizes[] = {4, 2, 1, 8};  /* W, H, B, DW */
                SOL_TRY(emit_load(jit, dst, src, off, sizes[size]));
            }
            break;

        case SOL_BPF_CLASS_STX:
            {
                uint8_t size = (opcode >> 3) & 0x3;
                uint8_t sizes[] = {4, 2, 1, 8};
                SOL_TRY(emit_store(jit, dst, off, src, sizes[size]));
            }
            break;

        case SOL_BPF_CLASS_ST:
            /* Store immediate - use r10 as temp since it's reserved */
            {
                uint8_t size = (opcode >> 3) & 0x3;
                uint8_t sizes[] = {4, 2, 1, 8};
                /* Load imm into r10 (temp), then store */
                SOL_TRY(emit_mov64_ri(jit, X64_R10, (uint64_t)(int64_t)imm));
                SOL_TRY(emit_store(jit, dst, off, X64_R10, sizes[size]));
            }
            break;

        case SOL_BPF_CLASS_LD:
            if (opcode == SOL_BPF_OP_LDDW) {
                /* 64-bit immediate load (uses two instructions) */
                /* Second instruction's imm is high 32 bits */
                /* This is handled specially - just emit mov */
                SOL_TRY(emit_mov64_ri(jit, dst, (uint64_t)(uint32_t)imm));
            } else {
                return SOL_ERR_NOT_IMPLEMENTED;
            }
            break;

        case SOL_BPF_CLASS_JMP32:
            /* 32-bit conditional jumps - compare uses 32-bit registers */
            switch (alu_op) {
                case SOL_BPF_JMP_JEQ:
                    if (is_imm) {
                        SOL_TRY(emit_rex_opt(jit, dst, 0, false));
                        SOL_TRY(emit_u8(jit, 0x81));
                        SOL_TRY(emit_u8(jit, modrm(3, 7, dst)));
                        SOL_TRY(emit_u32(jit, (uint32_t)imm));
                    } else {
                        SOL_TRY(emit_rex_opt(jit, dst, src, false));
                        SOL_TRY(emit_u8(jit, 0x39));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    SOL_TRY(emit_jcc(jit, X64_CC_E, (int32_t)(pc + 1 + off)));
                    break;
                case SOL_BPF_JMP_JNE:
                    if (is_imm) {
                        SOL_TRY(emit_rex_opt(jit, dst, 0, false));
                        SOL_TRY(emit_u8(jit, 0x81));
                        SOL_TRY(emit_u8(jit, modrm(3, 7, dst)));
                        SOL_TRY(emit_u32(jit, (uint32_t)imm));
                    } else {
                        SOL_TRY(emit_rex_opt(jit, dst, src, false));
                        SOL_TRY(emit_u8(jit, 0x39));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    SOL_TRY(emit_jcc(jit, X64_CC_NE, (int32_t)(pc + 1 + off)));
                    break;
                case SOL_BPF_JMP_JGT:
                    if (is_imm) {
                        SOL_TRY(emit_rex_opt(jit, dst, 0, false));
                        SOL_TRY(emit_u8(jit, 0x81));
                        SOL_TRY(emit_u8(jit, modrm(3, 7, dst)));
                        SOL_TRY(emit_u32(jit, (uint32_t)imm));
                    } else {
                        SOL_TRY(emit_rex_opt(jit, dst, src, false));
                        SOL_TRY(emit_u8(jit, 0x39));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    SOL_TRY(emit_jcc(jit, X64_CC_A, (int32_t)(pc + 1 + off)));
                    break;
                case SOL_BPF_JMP_JGE:
                    if (is_imm) {
                        SOL_TRY(emit_rex_opt(jit, dst, 0, false));
                        SOL_TRY(emit_u8(jit, 0x81));
                        SOL_TRY(emit_u8(jit, modrm(3, 7, dst)));
                        SOL_TRY(emit_u32(jit, (uint32_t)imm));
                    } else {
                        SOL_TRY(emit_rex_opt(jit, dst, src, false));
                        SOL_TRY(emit_u8(jit, 0x39));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    SOL_TRY(emit_jcc(jit, X64_CC_AE, (int32_t)(pc + 1 + off)));
                    break;
                case SOL_BPF_JMP_JLT:
                    if (is_imm) {
                        SOL_TRY(emit_rex_opt(jit, dst, 0, false));
                        SOL_TRY(emit_u8(jit, 0x81));
                        SOL_TRY(emit_u8(jit, modrm(3, 7, dst)));
                        SOL_TRY(emit_u32(jit, (uint32_t)imm));
                    } else {
                        SOL_TRY(emit_rex_opt(jit, dst, src, false));
                        SOL_TRY(emit_u8(jit, 0x39));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    SOL_TRY(emit_jcc(jit, X64_CC_B, (int32_t)(pc + 1 + off)));
                    break;
                case SOL_BPF_JMP_JLE:
                    if (is_imm) {
                        SOL_TRY(emit_rex_opt(jit, dst, 0, false));
                        SOL_TRY(emit_u8(jit, 0x81));
                        SOL_TRY(emit_u8(jit, modrm(3, 7, dst)));
                        SOL_TRY(emit_u32(jit, (uint32_t)imm));
                    } else {
                        SOL_TRY(emit_rex_opt(jit, dst, src, false));
                        SOL_TRY(emit_u8(jit, 0x39));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    SOL_TRY(emit_jcc(jit, X64_CC_BE, (int32_t)(pc + 1 + off)));
                    break;
                case SOL_BPF_JMP_JSET:
                    if (is_imm) {
                        SOL_TRY(emit_rex_opt(jit, dst, 0, false));
                        SOL_TRY(emit_u8(jit, 0xF7));
                        SOL_TRY(emit_u8(jit, modrm(3, 0, dst)));
                        SOL_TRY(emit_u32(jit, (uint32_t)imm));
                    } else {
                        SOL_TRY(emit_rex_opt(jit, dst, src, false));
                        SOL_TRY(emit_u8(jit, 0x85));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    SOL_TRY(emit_jcc(jit, X64_CC_NE, (int32_t)(pc + 1 + off)));
                    break;
                case SOL_BPF_JMP_JSGT:
                    if (is_imm) {
                        SOL_TRY(emit_rex_opt(jit, dst, 0, false));
                        SOL_TRY(emit_u8(jit, 0x81));
                        SOL_TRY(emit_u8(jit, modrm(3, 7, dst)));
                        SOL_TRY(emit_u32(jit, (uint32_t)imm));
                    } else {
                        SOL_TRY(emit_rex_opt(jit, dst, src, false));
                        SOL_TRY(emit_u8(jit, 0x39));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    SOL_TRY(emit_jcc(jit, X64_CC_G, (int32_t)(pc + 1 + off)));
                    break;
                case SOL_BPF_JMP_JSGE:
                    if (is_imm) {
                        SOL_TRY(emit_rex_opt(jit, dst, 0, false));
                        SOL_TRY(emit_u8(jit, 0x81));
                        SOL_TRY(emit_u8(jit, modrm(3, 7, dst)));
                        SOL_TRY(emit_u32(jit, (uint32_t)imm));
                    } else {
                        SOL_TRY(emit_rex_opt(jit, dst, src, false));
                        SOL_TRY(emit_u8(jit, 0x39));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    SOL_TRY(emit_jcc(jit, X64_CC_GE, (int32_t)(pc + 1 + off)));
                    break;
                case SOL_BPF_JMP_JSLT:
                    if (is_imm) {
                        SOL_TRY(emit_rex_opt(jit, dst, 0, false));
                        SOL_TRY(emit_u8(jit, 0x81));
                        SOL_TRY(emit_u8(jit, modrm(3, 7, dst)));
                        SOL_TRY(emit_u32(jit, (uint32_t)imm));
                    } else {
                        SOL_TRY(emit_rex_opt(jit, dst, src, false));
                        SOL_TRY(emit_u8(jit, 0x39));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    SOL_TRY(emit_jcc(jit, X64_CC_L, (int32_t)(pc + 1 + off)));
                    break;
                case SOL_BPF_JMP_JSLE:
                    if (is_imm) {
                        SOL_TRY(emit_rex_opt(jit, dst, 0, false));
                        SOL_TRY(emit_u8(jit, 0x81));
                        SOL_TRY(emit_u8(jit, modrm(3, 7, dst)));
                        SOL_TRY(emit_u32(jit, (uint32_t)imm));
                    } else {
                        SOL_TRY(emit_rex_opt(jit, dst, src, false));
                        SOL_TRY(emit_u8(jit, 0x39));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    SOL_TRY(emit_jcc(jit, X64_CC_LE, (int32_t)(pc + 1 + off)));
                    break;
                default:
                    return SOL_ERR_NOT_IMPLEMENTED;
            }
            break;

        case SOL_BPF_CLASS_ALU:
            /* 32-bit ALU operations - like ALU64 but without REX.W */
            switch (alu_op) {
                case SOL_BPF_ALU_ADD:
                    if (is_imm) {
                        /* add r32, imm */
                        SOL_TRY(emit_rex_opt(jit, dst, 0, false));
                        SOL_TRY(emit_u8(jit, 0x81));
                        SOL_TRY(emit_u8(jit, modrm(3, 0, dst)));
                        SOL_TRY(emit_u32(jit, (uint32_t)imm));
                    } else {
                        SOL_TRY(emit_rex_opt(jit, dst, src, false));
                        SOL_TRY(emit_u8(jit, 0x01));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    break;
                case SOL_BPF_ALU_SUB:
                    if (is_imm) {
                        SOL_TRY(emit_rex_opt(jit, dst, 0, false));
                        SOL_TRY(emit_u8(jit, 0x81));
                        SOL_TRY(emit_u8(jit, modrm(3, 5, dst)));
                        SOL_TRY(emit_u32(jit, (uint32_t)imm));
                    } else {
                        SOL_TRY(emit_rex_opt(jit, dst, src, false));
                        SOL_TRY(emit_u8(jit, 0x29));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    break;
                case SOL_BPF_ALU_MOV:
                    if (is_imm) {
                        /* mov r32, imm32 - zero extends to 64-bit */
                        SOL_TRY(emit_rex_opt(jit, dst, 0, false));
                        SOL_TRY(emit_u8(jit, 0xB8 + (dst & 7)));
                        SOL_TRY(emit_u32(jit, (uint32_t)imm));
                    } else {
                        SOL_TRY(emit_rex_opt(jit, dst, src, false));
                        SOL_TRY(emit_u8(jit, 0x89));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    break;
                case SOL_BPF_ALU_OR:
                    if (is_imm) {
                        SOL_TRY(emit_rex_opt(jit, dst, 0, false));
                        SOL_TRY(emit_u8(jit, 0x81));
                        SOL_TRY(emit_u8(jit, modrm(3, 1, dst)));
                        SOL_TRY(emit_u32(jit, (uint32_t)imm));
                    } else {
                        SOL_TRY(emit_rex_opt(jit, dst, src, false));
                        SOL_TRY(emit_u8(jit, 0x09));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    break;
                case SOL_BPF_ALU_AND:
                    if (is_imm) {
                        SOL_TRY(emit_rex_opt(jit, dst, 0, false));
                        SOL_TRY(emit_u8(jit, 0x81));
                        SOL_TRY(emit_u8(jit, modrm(3, 4, dst)));
                        SOL_TRY(emit_u32(jit, (uint32_t)imm));
                    } else {
                        SOL_TRY(emit_rex_opt(jit, dst, src, false));
                        SOL_TRY(emit_u8(jit, 0x21));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    break;
                case SOL_BPF_ALU_XOR:
                    if (is_imm) {
                        SOL_TRY(emit_rex_opt(jit, dst, 0, false));
                        SOL_TRY(emit_u8(jit, 0x81));
                        SOL_TRY(emit_u8(jit, modrm(3, 6, dst)));
                        SOL_TRY(emit_u32(jit, (uint32_t)imm));
                    } else {
                        SOL_TRY(emit_rex_opt(jit, dst, src, false));
                        SOL_TRY(emit_u8(jit, 0x31));
                        SOL_TRY(emit_u8(jit, modrm(3, src, dst)));
                    }
                    break;
                case SOL_BPF_ALU_LSH:
                    if (is_imm) {
                        SOL_TRY(emit_rex_opt(jit, dst, 0, false));
                        SOL_TRY(emit_u8(jit, 0xC1));
                        SOL_TRY(emit_u8(jit, modrm(3, 4, dst)));
                        SOL_TRY(emit_u8(jit, imm & 0x1F));
                    } else {
                        if (src != X64_RCX) {
                            SOL_TRY(emit_mov64_rr(jit, X64_RCX, src));
                        }
                        SOL_TRY(emit_rex_opt(jit, dst, 0, false));
                        SOL_TRY(emit_u8(jit, 0xD3));
                        SOL_TRY(emit_u8(jit, modrm(3, 4, dst)));
                    }
                    break;
                case SOL_BPF_ALU_RSH:
                    if (is_imm) {
                        SOL_TRY(emit_rex_opt(jit, dst, 0, false));
                        SOL_TRY(emit_u8(jit, 0xC1));
                        SOL_TRY(emit_u8(jit, modrm(3, 5, dst)));
                        SOL_TRY(emit_u8(jit, imm & 0x1F));
                    } else {
                        if (src != X64_RCX) {
                            SOL_TRY(emit_mov64_rr(jit, X64_RCX, src));
                        }
                        SOL_TRY(emit_rex_opt(jit, dst, 0, false));
                        SOL_TRY(emit_u8(jit, 0xD3));
                        SOL_TRY(emit_u8(jit, modrm(3, 5, dst)));
                    }
                    break;
                case SOL_BPF_ALU_ARSH:
                    if (is_imm) {
                        SOL_TRY(emit_rex_opt(jit, dst, 0, false));
                        SOL_TRY(emit_u8(jit, 0xC1));
                        SOL_TRY(emit_u8(jit, modrm(3, 7, dst)));
                        SOL_TRY(emit_u8(jit, imm & 0x1F));
                    } else {
                        if (src != X64_RCX) {
                            SOL_TRY(emit_mov64_rr(jit, X64_RCX, src));
                        }
                        SOL_TRY(emit_rex_opt(jit, dst, 0, false));
                        SOL_TRY(emit_u8(jit, 0xD3));
                        SOL_TRY(emit_u8(jit, modrm(3, 7, dst)));
                    }
                    break;
                case SOL_BPF_ALU_MUL:
                    if (is_imm) {
                        SOL_TRY(emit_rex_opt(jit, dst, dst, false));
                        SOL_TRY(emit_u8(jit, 0x69));
                        SOL_TRY(emit_u8(jit, modrm(3, dst, dst)));
                        SOL_TRY(emit_u32(jit, (uint32_t)imm));
                    } else {
                        SOL_TRY(emit_rex_opt(jit, src, dst, false));
                        SOL_TRY(emit_u8(jit, 0x0F));
                        SOL_TRY(emit_u8(jit, 0xAF));
                        SOL_TRY(emit_u8(jit, modrm(3, dst, src)));
                    }
                    break;
                case SOL_BPF_ALU_NEG:
                    SOL_TRY(emit_rex_opt(jit, dst, 0, false));
                    SOL_TRY(emit_u8(jit, 0xF7));
                    SOL_TRY(emit_u8(jit, modrm(3, 3, dst)));
                    break;
                case SOL_BPF_ALU_DIV:
                case SOL_BPF_ALU_MOD:
                    /* 32-bit division */
                    {
                        SOL_TRY(emit_u8(jit, 0x41));
                        SOL_TRY(emit_u8(jit, 0x53));  /* push r11 */

                        if (dst != X64_RDX) {
                            SOL_TRY(emit_mov64_rr(jit, X64_R11, X64_RDX));
                        }
                        if (dst != X64_RAX) {
                            /* mov eax, dst (32-bit) */
                            SOL_TRY(emit_rex_opt(jit, X64_RAX, dst, false));
                            SOL_TRY(emit_u8(jit, 0x89));
                            SOL_TRY(emit_u8(jit, modrm(3, dst, X64_RAX)));
                        }

                        /* xor edx, edx */
                        SOL_TRY(emit_u8(jit, 0x31));
                        SOL_TRY(emit_u8(jit, modrm(3, X64_RDX, X64_RDX)));

                        if (is_imm) {
                            /* mov r10d, imm */
                            SOL_TRY(emit_u8(jit, 0x41));
                            SOL_TRY(emit_u8(jit, 0xBA));
                            SOL_TRY(emit_u32(jit, (uint32_t)imm));
                            /* div r10d */
                            SOL_TRY(emit_u8(jit, 0x41));
                            SOL_TRY(emit_u8(jit, 0xF7));
                            SOL_TRY(emit_u8(jit, modrm(3, 6, X64_R10 & 7)));
                        } else {
                            /* div src32 */
                            SOL_TRY(emit_rex_opt(jit, src, 0, false));
                            SOL_TRY(emit_u8(jit, 0xF7));
                            SOL_TRY(emit_u8(jit, modrm(3, 6, src)));
                        }

                        if (alu_op == SOL_BPF_ALU_DIV) {
                            if (dst != X64_RAX) {
                                SOL_TRY(emit_rex_opt(jit, dst, X64_RAX, false));
                                SOL_TRY(emit_u8(jit, 0x89));
                                SOL_TRY(emit_u8(jit, modrm(3, X64_RAX, dst)));
                            }
                        } else {
                            if (dst != X64_RDX) {
                                SOL_TRY(emit_rex_opt(jit, dst, X64_RDX, false));
                                SOL_TRY(emit_u8(jit, 0x89));
                                SOL_TRY(emit_u8(jit, modrm(3, X64_RDX, dst)));
                            }
                        }

                        if (dst != X64_RDX && alu_op == SOL_BPF_ALU_DIV) {
                            SOL_TRY(emit_mov64_rr(jit, X64_RDX, X64_R11));
                        }

                        SOL_TRY(emit_u8(jit, 0x41));
                        SOL_TRY(emit_u8(jit, 0x5B));  /* pop r11 */
                    }
                    break;
                default:
                    return SOL_ERR_NOT_IMPLEMENTED;
            }
            break;

        default:
            return SOL_ERR_NOT_IMPLEMENTED;
    }

    return SOL_OK;
}

/*
 * Fixup jump targets
 */
static sol_err_t
fixup_jumps(jit_buffer_t* jit) {
    for (size_t i = 0; i < jit->jump_count; i++) {
        uint32_t target_pc = jit->jump_targets[i];
        uint32_t code_offset = jit->jump_offsets[i];

        if (target_pc >= jit->insn_count) {
            sol_log_error("JIT: Jump target %u out of bounds", target_pc);
            return SOL_ERR_BPF_VERIFY;
        }

        uint32_t target_offset = jit->insn_offsets[target_pc];
        int32_t rel = (int32_t)target_offset - (int32_t)(code_offset + 4);

        memcpy(jit->code + code_offset, &rel, 4);
    }

    return SOL_OK;
}

/*
 * Compile BPF program to x86_64
 */
sol_err_t sol_bpf_jit_compile(
    sol_bpf_vm_t* vm,
    void** code_out,
    size_t* code_len_out
) {
    if (vm == NULL || vm->program == NULL) {
        return SOL_ERR_INVAL;
    }

    const sol_bpf_program_t* prog = vm->program;
    const sol_bpf_insn_t* insns = prog->instructions;
    size_t insn_count = prog->insn_count;

    /* Initialize JIT buffer */
    jit_buffer_t jit = {0};
    jit.code_cap = 4096;
    jit.code = sol_alloc(jit.code_cap);
    if (jit.code == NULL) {
        return SOL_ERR_NOMEM;
    }

    jit.insn_count = insn_count;
    jit.insn_offsets = sol_calloc(insn_count + 1, sizeof(uint32_t));
    if (jit.insn_offsets == NULL) {
        sol_free(jit.code);
        return SOL_ERR_NOMEM;
    }

    /* Emit prologue */
    sol_err_t err = emit_prologue(&jit);
    if (err != SOL_OK) {
        goto cleanup;
    }

    /* Compile each instruction */
    for (size_t pc = 0; pc < insn_count; pc++) {
        jit.insn_offsets[pc] = (uint32_t)jit.code_len;

        err = compile_insn(&jit, &insns[pc], pc);
        if (err != SOL_OK) {
            sol_log_warn("JIT: Failed to compile instruction at pc=%zu, opcode=0x%02X",
                        pc, insns[pc].opcode);
            goto cleanup;
        }

        /* Handle LDDW which uses two instruction slots */
        if (insns[pc].opcode == SOL_BPF_OP_LDDW && pc + 1 < insn_count) {
            uint64_t full_imm = ((uint64_t)(uint32_t)insns[pc + 1].imm << 32) |
                               (uint64_t)(uint32_t)insns[pc].imm;
            /* Re-emit with full 64-bit value */
            jit.code_len = jit.insn_offsets[pc];
            emit_mov64_ri(&jit, bpf_to_x64[insns[pc].regs & 0xF], full_imm);
            pc++;  /* Skip second part of LDDW */
            jit.insn_offsets[pc] = (uint32_t)jit.code_len;
        }
    }

    /* Mark end position */
    jit.insn_offsets[insn_count] = (uint32_t)jit.code_len;

    /* Fixup jump targets */
    err = fixup_jumps(&jit);
    if (err != SOL_OK) {
        goto cleanup;
    }

    /* Allocate executable memory */
    void* exec_mem = mmap(NULL, jit.code_len,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (exec_mem == MAP_FAILED) {
        err = SOL_ERR_NOMEM;
        goto cleanup;
    }

    /* Copy code */
    memcpy(exec_mem, jit.code, jit.code_len);

    /* Make executable */
    if (mprotect(exec_mem, jit.code_len, PROT_READ | PROT_EXEC) != 0) {
        munmap(exec_mem, jit.code_len);
        err = SOL_ERR_BPF_JIT;
        goto cleanup;
    }

    *code_out = exec_mem;
    *code_len_out = jit.code_len;
    err = SOL_OK;

cleanup:
    sol_free(jit.code);
    sol_free(jit.insn_offsets);
    sol_free(jit.jump_targets);
    sol_free(jit.jump_offsets);
    return err;
}

void
sol_bpf_jit_free(sol_bpf_program_t* prog) {
    if (prog == NULL || prog->jit_code == NULL) {
        return;
    }

    munmap(prog->jit_code, prog->jit_code_len);
    prog->jit_code = NULL;
    prog->jit_code_len = 0;
}

/*
 * Execute JIT-compiled code
 */
sol_err_t sol_bpf_vm_execute_jit(sol_bpf_vm_t* vm) {
    if (vm == NULL) {
        return SOL_ERR_INVAL;
    }

    void* jit_code = NULL;
    size_t jit_len = 0;

    sol_err_t err = sol_bpf_jit_compile(vm, &jit_code, &jit_len);
    if (err != SOL_OK) {
        sol_log_warn("JIT compilation failed, falling back to interpreter");
        return sol_bpf_vm_execute(vm);
    }

    /* Set up registers */
    typedef uint64_t (*jit_fn_t)(void);
    jit_fn_t fn = (jit_fn_t)jit_code;

    /* Execute */
    uint64_t result = fn();

    /* Store return value */
    vm->return_value = result;
    vm->state = SOL_BPF_STATE_STOPPED;

    /* Free JIT code */
    munmap(jit_code, jit_len);

    return SOL_OK;
}

#else /* !__x86_64__ */

/*
 * Fallback for non-x86_64 platforms
 */
sol_err_t sol_bpf_jit_compile(
    sol_bpf_vm_t* vm,
    void** code_out,
    size_t* code_len_out
) {
    (void)vm;
    (void)code_out;
    (void)code_len_out;
    return SOL_ERR_UNSUPPORTED;
}

sol_err_t sol_bpf_vm_execute_jit(sol_bpf_vm_t* vm) {
    /* Fall back to interpreter */
    return sol_bpf_vm_execute(vm);
}

#endif /* __x86_64__ */
