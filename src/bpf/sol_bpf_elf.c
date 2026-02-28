/*
 * sol_bpf_elf.c - BPF ELF Loader
 *
 * Parses and loads Solana BPF programs from ELF format.
 * Supports both SBPFv1 and SBPFv2 programs.
 */

#include "sol_bpf.h"
#include "../util/sol_alloc.h"
#include "../util/sol_log.h"
#include <string.h>
#include <stddef.h>
#include <limits.h>

/*
 * ELF Constants
 */
#define ELF_MAGIC       0x464C457F  /* "\x7FELF" */

/* ELF Class */
#define ELFCLASS64      2

/* ELF Data encoding */
#define ELFDATA2LSB     1   /* Little endian */

/* ELF Type */
#define ET_DYN          3   /* Shared object (used by Solana) */

/* ELF Machine */
#define EM_BPF          247
#define EM_SBPF         263  /* SBPFv2 */

/* Section types */
#define SHT_NULL        0
#define SHT_PROGBITS    1
#define SHT_SYMTAB      2
#define SHT_STRTAB      3
#define SHT_RELA        4
#define SHT_HASH        5
#define SHT_DYNAMIC     6
#define SHT_NOBITS      8
#define SHT_REL         9
#define SHT_DYNSYM      11

/* Section flags */
#define SHF_WRITE       0x1
#define SHF_ALLOC       0x2
#define SHF_EXECINSTR   0x4

/* Dynamic table tags */
#define DT_NULL         0
#define DT_REL          17
#define DT_RELSZ        18

/* Program header types */
#define PT_NULL         0
#define PT_LOAD         1
#define PT_DYNAMIC      2

/* Symbol binding */
#define STB_LOCAL       0
#define STB_GLOBAL      1

/* Symbol types */
#define STT_NOTYPE      0
#define STT_FUNC        2

/* Relocation types for BPF */
#define R_BPF_64_64     1
#define R_BPF_64_RELATIVE 8
#define R_BPF_64_32     10

/*
 * ELF Header (64-bit)
 */
typedef struct {
    uint8_t     e_ident[16];    /* ELF identification */
    uint16_t    e_type;         /* Object file type */
    uint16_t    e_machine;      /* Machine type */
    uint32_t    e_version;      /* Object file version */
    uint64_t    e_entry;        /* Entry point address */
    uint64_t    e_phoff;        /* Program header offset */
    uint64_t    e_shoff;        /* Section header offset */
    uint32_t    e_flags;        /* Processor-specific flags */
    uint16_t    e_ehsize;       /* ELF header size */
    uint16_t    e_phentsize;    /* Program header entry size */
    uint16_t    e_phnum;        /* Number of program headers */
    uint16_t    e_shentsize;    /* Section header entry size */
    uint16_t    e_shnum;        /* Number of section headers */
    uint16_t    e_shstrndx;     /* Section name string table index */
} elf64_ehdr_t;

/*
 * Section Header (64-bit)
 */
typedef struct {
    uint32_t    sh_name;        /* Section name (string table index) */
    uint32_t    sh_type;        /* Section type */
    uint64_t    sh_flags;       /* Section flags */
    uint64_t    sh_addr;        /* Virtual address */
    uint64_t    sh_offset;      /* File offset */
    uint64_t    sh_size;        /* Section size */
    uint32_t    sh_link;        /* Link to another section */
    uint32_t    sh_info;        /* Additional info */
    uint64_t    sh_addralign;   /* Alignment */
    uint64_t    sh_entsize;     /* Entry size if section holds table */
} elf64_shdr_t;

/*
 * Program Header (64-bit)
 */
typedef struct {
    uint32_t    p_type;         /* Segment type */
    uint32_t    p_flags;        /* Segment flags */
    uint64_t    p_offset;       /* File offset */
    uint64_t    p_vaddr;        /* Virtual address */
    uint64_t    p_paddr;        /* Physical address */
    uint64_t    p_filesz;       /* File size */
    uint64_t    p_memsz;        /* Memory size */
    uint64_t    p_align;        /* Alignment */
} elf64_phdr_t;

/*
 * Symbol table entry (64-bit)
 */
typedef struct {
    uint32_t    st_name;        /* Symbol name (string table index) */
    uint8_t     st_info;        /* Symbol type and binding */
    uint8_t     st_other;       /* Symbol visibility */
    uint16_t    st_shndx;       /* Section index */
    uint64_t    st_value;       /* Symbol value */
    uint64_t    st_size;        /* Symbol size */
} elf64_sym_t;

#define ELF64_ST_BIND(info)     ((info) >> 4)
#define ELF64_ST_TYPE(info)     ((info) & 0xf)

/*
 * Relocation entry with addend (64-bit)
 */
typedef struct {
    uint64_t    r_offset;       /* Address */
    uint64_t    r_info;         /* Relocation type and symbol index */
    int64_t     r_addend;       /* Addend */
} elf64_rela_t;

/*
 * Relocation entry without addend (64-bit)
 */
typedef struct {
    uint64_t    r_offset;       /* Address */
    uint64_t    r_info;         /* Relocation type and symbol index */
} elf64_rel_t;

#define ELF64_R_SYM(info)       ((info) >> 32)
#define ELF64_R_TYPE(info)      ((uint32_t)(info))

/*
 * Read values from buffer (little-endian)
 */
static inline uint16_t
read_u16(const uint8_t* p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static inline uint32_t
read_u32(const uint8_t* p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static inline uint64_t
read_u64(const uint8_t* p) {
    return (uint64_t)p[0] |
           ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}

static inline void
write_u64(uint8_t* p, uint64_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

/*
 * Parse ELF header
 */
static sol_err_t
parse_elf_header(const uint8_t* data, size_t len, elf64_ehdr_t* ehdr) {
    if (len < sizeof(elf64_ehdr_t)) {
        return SOL_ERR_BPF_ELF;
    }

    /* Check magic */
    if (read_u32(data) != ELF_MAGIC) {
        sol_log_error("Invalid ELF magic");
        return SOL_ERR_BPF_ELF;
    }

    /* Check class (64-bit) */
    if (data[4] != ELFCLASS64) {
        sol_log_error("Not a 64-bit ELF");
        return SOL_ERR_BPF_ELF;
    }

    /* Check endianness (little) */
    if (data[5] != ELFDATA2LSB) {
        sol_log_error("Not little-endian ELF");
        return SOL_ERR_BPF_ELF;
    }

    /* Parse header fields */
    memcpy(ehdr->e_ident, data, 16);
    ehdr->e_type = read_u16(data + 16);
    ehdr->e_machine = read_u16(data + 18);
    ehdr->e_version = read_u32(data + 20);
    ehdr->e_entry = read_u64(data + 24);
    ehdr->e_phoff = read_u64(data + 32);
    ehdr->e_shoff = read_u64(data + 40);
    ehdr->e_flags = read_u32(data + 48);
    ehdr->e_ehsize = read_u16(data + 52);
    ehdr->e_phentsize = read_u16(data + 54);
    ehdr->e_phnum = read_u16(data + 56);
    ehdr->e_shentsize = read_u16(data + 58);
    ehdr->e_shnum = read_u16(data + 60);
    ehdr->e_shstrndx = read_u16(data + 62);

    /* Validate machine type */
    if (ehdr->e_machine != EM_BPF && ehdr->e_machine != EM_SBPF) {
        sol_log_error("Not a BPF ELF (machine=%u)", ehdr->e_machine);
        return SOL_ERR_BPF_ELF;
    }

    return SOL_OK;
}

/*
 * Parse section header
 */
static void
parse_section_header(const uint8_t* data, elf64_shdr_t* shdr) {
    shdr->sh_name = read_u32(data);
    shdr->sh_type = read_u32(data + 4);
    shdr->sh_flags = read_u64(data + 8);
    shdr->sh_addr = read_u64(data + 16);
    shdr->sh_offset = read_u64(data + 24);
    shdr->sh_size = read_u64(data + 32);
    shdr->sh_link = read_u32(data + 40);
    shdr->sh_info = read_u32(data + 44);
    shdr->sh_addralign = read_u64(data + 48);
    shdr->sh_entsize = read_u64(data + 56);
}

/*
 * Parse symbol table entry
 */
static void
parse_symbol(const uint8_t* data, elf64_sym_t* sym) {
    sym->st_name = read_u32(data);
    sym->st_info = data[4];
    sym->st_other = data[5];
    sym->st_shndx = read_u16(data + 6);
    sym->st_value = read_u64(data + 8);
    sym->st_size = read_u64(data + 16);
}

/*
 * Parse relocation entry
 */
static void
parse_rela(const uint8_t* data, elf64_rela_t* rela) {
    rela->r_offset = read_u64(data);
    rela->r_info = read_u64(data + 8);
    rela->r_addend = (int64_t)read_u64(data + 16);
}

static void
parse_rel(const uint8_t* data, elf64_rel_t* rel) {
    rel->r_offset = read_u64(data);
    rel->r_info = read_u64(data + 8);
}

static bool
program_vaddr_translate(
    sol_bpf_program_t* prog,
    uint64_t vaddr,
    size_t len,
    uint8_t** out
) {
    if (prog == NULL || out == NULL || len == 0) {
        return false;
    }

    /* Unified ro_section covers [0, ro_section_len) */
    if (prog->ro_section != NULL &&
        vaddr + len <= prog->ro_section_len &&
        vaddr + len >= vaddr /* overflow check */) {
        *out = prog->ro_section + vaddr;
        return true;
    }

    return false;
}

/*
 * Get section name from string table
 */
static const char*
get_section_name(const uint8_t* strtab, size_t strtab_size, uint32_t offset) {
    if (offset >= strtab_size) {
        return NULL;
    }
    return (const char*)(strtab + offset);
}

/*
 * Find section by name
 */
static const elf64_shdr_t*
find_section(const uint8_t* data, size_t len,
             const elf64_ehdr_t* ehdr,
             const uint8_t* shstrtab, size_t shstrtab_size,
             const char* name,
             elf64_shdr_t* out_shdr) {
    for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
        size_t shdr_off = ehdr->e_shoff + (size_t)i * ehdr->e_shentsize;
        if (shdr_off + sizeof(elf64_shdr_t) > len) {
            continue;
        }

        elf64_shdr_t shdr;
        parse_section_header(data + shdr_off, &shdr);

        const char* sec_name = get_section_name(shstrtab, shstrtab_size, shdr.sh_name);
        if (sec_name && strcmp(sec_name, name) == 0) {
            *out_shdr = shdr;
            return out_shdr;
        }
    }
    return NULL;
}

/*
 * Load ELF program
 */
sol_err_t
sol_bpf_elf_load(
    sol_bpf_program_t* prog,
    const uint8_t* elf_data,
    size_t elf_len
) {
    if (prog == NULL || elf_data == NULL || elf_len == 0) {
        return SOL_ERR_INVAL;
    }

    sol_err_t err;

    /* Parse ELF header */
    elf64_ehdr_t ehdr;
    err = parse_elf_header(elf_data, elf_len, &ehdr);
    if (err != SOL_OK) {
        return err;
    }

    /* Determine SBPF version from e_flags (matching Agave rbpf elf.rs).
     * The version mapping depends on the runtime's enabled_sbpf_versions,
     * but for mainnet with V2+ support enabled:
     *   e_flags 0 → V0, 1 → V1, 2 → V2, 3 → V3 */
    switch (ehdr.e_flags) {
    case 0:  prog->sbpf_version = SOL_SBPF_V0; break;
    case 1:  prog->sbpf_version = SOL_SBPF_V1; break;
    case 2:  prog->sbpf_version = SOL_SBPF_V2; break;
    case 3:  prog->sbpf_version = SOL_SBPF_V3; break;
    default: prog->sbpf_version = SOL_SBPF_V0; break;  /* fallback */
    }

    sol_log_debug("SBPF version: V%d (e_flags=0x%x, e_machine=%u)",
                 (int)prog->sbpf_version, ehdr.e_flags, ehdr.e_machine);

    /* Validate section header string table */
    if (ehdr.e_shstrndx >= ehdr.e_shnum) {
        return SOL_ERR_BPF_ELF;
    }

    /* Get section header string table */
    size_t shstrtab_off = ehdr.e_shoff + (size_t)ehdr.e_shstrndx * ehdr.e_shentsize;
    if (shstrtab_off + sizeof(elf64_shdr_t) > elf_len) {
        return SOL_ERR_BPF_ELF;
    }

    elf64_shdr_t shstrtab_shdr;
    parse_section_header(elf_data + shstrtab_off, &shstrtab_shdr);

    if (shstrtab_shdr.sh_offset + shstrtab_shdr.sh_size > elf_len) {
        return SOL_ERR_BPF_ELF;
    }

    const uint8_t* shstrtab = elf_data + shstrtab_shdr.sh_offset;
    size_t shstrtab_size = shstrtab_shdr.sh_size;

    /* Find .text section */
    elf64_shdr_t text_shdr;
    if (!find_section(elf_data, elf_len, &ehdr, shstrtab, shstrtab_size,
                      ".text", &text_shdr)) {
        sol_log_error("No .text section found");
        return SOL_ERR_BPF_ELF;
    }

    if (text_shdr.sh_offset + text_shdr.sh_size > elf_len) {
        return SOL_ERR_BPF_ELF;
    }

    /* Validate text section size */
    if (text_shdr.sh_size == 0 || text_shdr.sh_size % 8 != 0) {
        sol_log_error("Invalid .text section size");
        return SOL_ERR_BPF_ELF;
    }

    size_t insn_count = text_shdr.sh_size / 8;
    if (insn_count > SOL_BPF_MAX_INSTRUCTIONS) {
        sol_log_error("Program too large (%zu instructions)", insn_count);
        return SOL_ERR_TOO_LARGE;
    }

    prog->text_vaddr = text_shdr.sh_addr;
    prog->text_len = text_shdr.sh_size;
    prog->insn_count = insn_count;

    /* Find optional ro sections */
    elf64_shdr_t rodata_shdr = {0};
    bool has_rodata = find_section(elf_data, elf_len, &ehdr, shstrtab, shstrtab_size,
                                   ".rodata", &rodata_shdr);
    if (has_rodata && rodata_shdr.sh_offset + rodata_shdr.sh_size > elf_len) {
        return SOL_ERR_BPF_ELF;
    }
    if (has_rodata) {
        prog->rodata_vaddr = rodata_shdr.sh_addr;
    }

    elf64_shdr_t data_rel_ro_shdr = {0};
    bool has_data_rel_ro = find_section(elf_data, elf_len, &ehdr, shstrtab, shstrtab_size,
                                        ".data.rel.ro", &data_rel_ro_shdr);
    if (has_data_rel_ro && data_rel_ro_shdr.sh_offset + data_rel_ro_shdr.sh_size > elf_len) {
        return SOL_ERR_BPF_ELF;
    }
    if (has_data_rel_ro) {
        prog->data_rel_ro_vaddr = data_rel_ro_shdr.sh_addr;
    }

    elf64_shdr_t eh_frame_shdr = {0};
    bool has_eh_frame = find_section(elf_data, elf_len, &ehdr, shstrtab, shstrtab_size,
                                     ".eh_frame", &eh_frame_shdr);
    if (has_eh_frame && eh_frame_shdr.sh_offset + eh_frame_shdr.sh_size > elf_len) {
        has_eh_frame = false;
    }

    /*
     * Build unified ro_section matching Agave rbpf behavior.
     * When optimize_rodata=false (SBFv1), rbpf creates a single zero-filled
     * buffer from vaddr 0 to highest_addr and copies .text, .rodata,
     * .data.rel.ro, and .eh_frame into it at their sh_addr offsets.
     * This is mapped as one contiguous region at MM_PROGRAM_START.
     */
    {
        uint64_t highest_addr = text_shdr.sh_addr + text_shdr.sh_size;
        if (has_rodata && rodata_shdr.sh_size > 0) {
            uint64_t end = rodata_shdr.sh_addr + rodata_shdr.sh_size;
            if (end > highest_addr) highest_addr = end;
        }
        if (has_data_rel_ro && data_rel_ro_shdr.sh_size > 0) {
            uint64_t end = data_rel_ro_shdr.sh_addr + data_rel_ro_shdr.sh_size;
            if (end > highest_addr) highest_addr = end;
        }
        if (has_eh_frame && eh_frame_shdr.sh_size > 0) {
            uint64_t end = eh_frame_shdr.sh_addr + eh_frame_shdr.sh_size;
            if (end > highest_addr) highest_addr = end;
        }

        if (highest_addr > SIZE_MAX || highest_addr == 0) {
            return SOL_ERR_BPF_ELF;
        }

        size_t ro_len = (size_t)highest_addr;
        uint8_t* ro = sol_alloc(ro_len);
        if (ro == NULL) {
            return SOL_ERR_NOMEM;
        }
        memset(ro, 0, ro_len);

        /* Copy sections at their sh_addr offsets */
        memcpy(ro + text_shdr.sh_addr, elf_data + text_shdr.sh_offset, text_shdr.sh_size);
        if (has_rodata && rodata_shdr.sh_size > 0) {
            memcpy(ro + rodata_shdr.sh_addr, elf_data + rodata_shdr.sh_offset, rodata_shdr.sh_size);
        }
        if (has_data_rel_ro && data_rel_ro_shdr.sh_size > 0) {
            memcpy(ro + data_rel_ro_shdr.sh_addr, elf_data + data_rel_ro_shdr.sh_offset, data_rel_ro_shdr.sh_size);
        }
        if (has_eh_frame && eh_frame_shdr.sh_size > 0) {
            memcpy(ro + eh_frame_shdr.sh_addr, elf_data + eh_frame_shdr.sh_offset, eh_frame_shdr.sh_size);
        }

        prog->ro_section = ro;
        prog->ro_section_len = ro_len;
        prog->text_segment = ro + text_shdr.sh_addr;
        prog->instructions = (const sol_bpf_insn_t*)prog->text_segment;
    }

    /* Find symbol table for function registry */
    elf64_shdr_t symtab_shdr = {0};
    elf64_shdr_t strtab_shdr = {0};
    bool has_symtab = false;

    /* Look for .symtab or .dynsym */
    for (uint16_t i = 0; i < ehdr.e_shnum; i++) {
        size_t shdr_off = ehdr.e_shoff + (size_t)i * ehdr.e_shentsize;
        if (shdr_off + sizeof(elf64_shdr_t) > elf_len) continue;

        elf64_shdr_t shdr;
        parse_section_header(elf_data + shdr_off, &shdr);

        if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM) {
            symtab_shdr = shdr;
            has_symtab = true;

            /* Get linked string table */
            if (shdr.sh_link < ehdr.e_shnum) {
                size_t str_off = ehdr.e_shoff + (size_t)shdr.sh_link * ehdr.e_shentsize;
                if (str_off + sizeof(elf64_shdr_t) <= elf_len) {
                    parse_section_header(elf_data + str_off, &strtab_shdr);
                }
            }
            break;
        }
    }

    /* Build function registry from symbols */
    if (has_symtab && symtab_shdr.sh_entsize > 0 &&
        symtab_shdr.sh_offset + symtab_shdr.sh_size <= elf_len &&
        strtab_shdr.sh_offset + strtab_shdr.sh_size <= elf_len) {

        size_t sym_count = symtab_shdr.sh_size / symtab_shdr.sh_entsize;

        /* Count function symbols */
        size_t func_count = 0;
        for (size_t i = 0; i < sym_count; i++) {
            const uint8_t* sym_data = elf_data + symtab_shdr.sh_offset +
                                      i * symtab_shdr.sh_entsize;
            if (sym_data + 24 > elf_data + elf_len) continue;

            elf64_sym_t sym;
            parse_symbol(sym_data, &sym);

            if (ELF64_ST_TYPE(sym.st_info) == STT_FUNC &&
                sym.st_value >= prog->text_vaddr &&
                sym.st_value < prog->text_vaddr + prog->text_len) {
                func_count++;
            }
        }

        /* Allocate function registry */
        if (func_count > 0) {
            prog->function_registry = sol_alloc(func_count * sizeof(uint32_t));
            if (prog->function_registry != NULL) {
                size_t idx = 0;
                for (size_t i = 0; i < sym_count && idx < func_count; i++) {
                    const uint8_t* sym_data = elf_data + symtab_shdr.sh_offset +
                                              i * symtab_shdr.sh_entsize;
                    if (sym_data + 24 > elf_data + elf_len) continue;

                    elf64_sym_t sym;
                    parse_symbol(sym_data, &sym);

                    if (ELF64_ST_TYPE(sym.st_info) == STT_FUNC &&
                        sym.st_value >= prog->text_vaddr &&
                        sym.st_value < prog->text_vaddr + prog->text_len) {
                        /* Store PC (instruction index) */
                        uint32_t pc = (uint32_t)((sym.st_value - prog->text_vaddr) / 8);
                        prog->function_registry[idx++] = pc;
                    }
                }
                prog->function_count = idx;
            }
        }
    }

    /* Set entry point from ELF header e_entry (matching Agave's rbpf behavior) */
    if (ehdr.e_entry >= text_shdr.sh_addr &&
        ehdr.e_entry < text_shdr.sh_addr + text_shdr.sh_size) {
        prog->entry_pc = (uint32_t)((ehdr.e_entry - text_shdr.sh_addr) / 8);
    }

    /* Find relocations via .dynamic section's DT_REL entry, matching Agave/rbpf.
     * For SBPFv2+ programs, rbpf reads relocations from dynamic_table[DT_REL]
     * only, NOT by scanning section headers for SHT_REL/SHT_RELA. If no
     * .dynamic section exists or DT_REL is 0, zero relocations are processed.
     * This is critical for SBPFv2 programs which may have relocation sections
     * that should not be applied.
     *
     * For SBPFv0/v1 programs, older toolchains commonly omit .dynamic.  In that
     * case, apply relocations by scanning SHT_REL sections to preserve legacy
     * compatibility (and unit-test behavior). */
    uint64_t dt_rel_vaddr = 0;
    uint64_t dt_rel_size = 0;
    for (uint16_t i = 0; i < ehdr.e_shnum; i++) {
        size_t shdr_off = ehdr.e_shoff + (size_t)i * ehdr.e_shentsize;
        if (shdr_off + sizeof(elf64_shdr_t) > elf_len) continue;

        elf64_shdr_t dyn_shdr;
        parse_section_header(elf_data + shdr_off, &dyn_shdr);

        if (dyn_shdr.sh_type != SHT_DYNAMIC) continue;
        if (dyn_shdr.sh_offset + dyn_shdr.sh_size > elf_len) continue;

        /* Parse Elf64_Dyn entries (d_tag:i64, d_val:u64 = 16 bytes each) */
        size_t dyn_count = dyn_shdr.sh_size / 16;
        for (size_t j = 0; j < dyn_count; j++) {
            const uint8_t* ent = elf_data + dyn_shdr.sh_offset + j * 16;
            if (ent + 16 > elf_data + elf_len) break;

            int64_t d_tag;
            uint64_t d_val;
            memcpy(&d_tag, ent, 8);
            memcpy(&d_val, ent + 8, 8);

            if (d_tag == DT_REL)       dt_rel_vaddr = d_val;
            else if (d_tag == DT_RELSZ) dt_rel_size = d_val;
            else if (d_tag == DT_NULL)  break;
        }
        break; /* Only one .dynamic section */
    }

    bool scan_all_rel_sections = false;
    if (dt_rel_vaddr == 0 && prog->sbpf_version < SOL_SBPF_V2) {
        scan_all_rel_sections = true;
    }

    /* Process relocations.
     * - SBPFv2+: Only process the REL section that matches DT_REL from .dynamic.
     * - SBPFv0/v1: If DT_REL is missing, scan all SHT_REL sections. */
    for (uint16_t i = 0; i < ehdr.e_shnum; i++) {
        size_t shdr_off = ehdr.e_shoff + (size_t)i * ehdr.e_shentsize;
        if (shdr_off + sizeof(elf64_shdr_t) > elf_len) continue;

        elf64_shdr_t rel_shdr;
        parse_section_header(elf_data + shdr_off, &rel_shdr);

        /* rbpf only supports DT_REL (REL without addend), never RELA. */
        if (rel_shdr.sh_type != SHT_REL) {
            continue;
        }

        if (!scan_all_rel_sections) {
            /* SBPFv2+ strict behavior: no DT_REL => no relocations. */
            if (dt_rel_vaddr == 0) {
                continue;
            }

            /* Only process the REL section that matches DT_REL from .dynamic. */
            if (rel_shdr.sh_addr != dt_rel_vaddr) {
                continue;
            }

            /* Optional sanity check: if DT_RELSZ is present, ensure the section
             * size does not exceed it. */
            if (dt_rel_size != 0 && rel_shdr.sh_size > dt_rel_size) {
                return SOL_ERR_BPF_ELF;
            }
        }

        if (rel_shdr.sh_entsize == 0 ||
            rel_shdr.sh_offset + rel_shdr.sh_size > elf_len) {
            return SOL_ERR_BPF_ELF;
        }

        /* Resolve symbol + string tables for this relocation section, if any. */
        elf64_shdr_t rel_symtab_shdr = {0};
        elf64_shdr_t rel_strtab_shdr = {0};
        const uint8_t* symtab = NULL;
        size_t symtab_size = 0;
        size_t sym_entsize = 0;
        const uint8_t* strtab = NULL;
        size_t strtab_size = 0;

        if (rel_shdr.sh_link < ehdr.e_shnum) {
            size_t symtab_off = ehdr.e_shoff + (size_t)rel_shdr.sh_link * ehdr.e_shentsize;
            if (symtab_off + sizeof(elf64_shdr_t) <= elf_len) {
                parse_section_header(elf_data + symtab_off, &rel_symtab_shdr);
                if ((rel_symtab_shdr.sh_type == SHT_SYMTAB || rel_symtab_shdr.sh_type == SHT_DYNSYM) &&
                    rel_symtab_shdr.sh_entsize > 0 &&
                    rel_symtab_shdr.sh_offset + rel_symtab_shdr.sh_size <= elf_len) {
                    symtab = elf_data + rel_symtab_shdr.sh_offset;
                    symtab_size = rel_symtab_shdr.sh_size;
                    sym_entsize = rel_symtab_shdr.sh_entsize;

                    if (rel_symtab_shdr.sh_link < ehdr.e_shnum) {
                        size_t strtab_off = ehdr.e_shoff + (size_t)rel_symtab_shdr.sh_link * ehdr.e_shentsize;
                        if (strtab_off + sizeof(elf64_shdr_t) <= elf_len) {
                            parse_section_header(elf_data + strtab_off, &rel_strtab_shdr);
                            if (rel_strtab_shdr.sh_type == SHT_STRTAB &&
                                rel_strtab_shdr.sh_offset + rel_strtab_shdr.sh_size <= elf_len) {
                                strtab = elf_data + rel_strtab_shdr.sh_offset;
                                strtab_size = rel_strtab_shdr.sh_size;
                            }
                        }
                    }
                }
            }
        }

        size_t rel_count = rel_shdr.sh_size / rel_shdr.sh_entsize;

        for (size_t j = 0; j < rel_count; j++) {
            const uint8_t* rel_data = elf_data + rel_shdr.sh_offset +
                                      j * rel_shdr.sh_entsize;
            if (rel_data + rel_shdr.sh_entsize > elf_data + elf_len) {
                continue;
            }

            /* DT_REL uses REL (without addend) only, matching rbpf */
            if (rel_shdr.sh_entsize < sizeof(elf64_rel_t)) {
                return SOL_ERR_BPF_ELF;
            }
            elf64_rel_t rel;
            parse_rel(rel_data, &rel);
            uint64_t r_offset = rel.r_offset;
            uint64_t r_info = rel.r_info;

            uint32_t rel_type = ELF64_R_TYPE(r_info);
            uint32_t sym_idx = (uint32_t)ELF64_R_SYM(r_info);

            switch (rel_type) {
            case R_BPF_64_RELATIVE: {
                /* Relative relocation (B + A). In REL, addend is stored in-place. */
                if (r_offset >= prog->text_vaddr &&
                    r_offset + 16 <= prog->text_vaddr + prog->text_len) {
                    uint8_t* target = NULL;
                    if (!program_vaddr_translate(prog, r_offset, 16, &target)) {
                        break;
                    }

                    sol_bpf_insn_t* insn1 = (sol_bpf_insn_t*)target;
                    sol_bpf_insn_t* insn2 = insn1 + 1;

                    /* Agave patches the imm fields without checking the opcode.
                     * Works for both LDDW pairs (V0/V1) and MOV32+HOR64 pairs (V2+)
                     * since the imm field is at the same byte offset. */
                    /* REL: addend is stored in-place in the imm fields */
                    uint64_t imm64 = (uint64_t)(uint32_t)insn1->imm |
                                     ((uint64_t)(uint32_t)insn2->imm << 32);
                    uint64_t new_imm = imm64 + SOL_BPF_MM_PROGRAM_START;

                    insn1->imm = (int32_t)new_imm;
                    insn2->imm = (int32_t)(new_imm >> 32);
                    break;
                }

                uint8_t* target = NULL;
                if (!program_vaddr_translate(prog, r_offset, 8, &target)) {
                    break;
                }

                /* Data relocations: match Agave rbpf legacy compatibility.
                 * Old BPF toolchains (before solana-labs/llvm-project#35) stored
                 * the low 32 bits of the address shifted left by 32 in the 8-byte
                 * field.  Agave reads a u32 from r_offset+4 (the "imm" position),
                 * adds the base, then writes the full u64 to r_offset. */
                uint32_t imm_val = 0;
                memcpy(&imm_val, target + 4, sizeof(uint32_t));
                uint64_t val = SOL_BPF_MM_PROGRAM_START + (uint64_t)imm_val;
                write_u64(target, val);
                break;
            }

            case R_BPF_64_64: {
                /* 64-bit relocation (S + A), typically for LDDW immediates or
                 * pointers stored in data segments. */
                if (symtab == NULL || sym_entsize == 0) {
                    break;
                }
                size_t sym_off = (size_t)sym_idx * sym_entsize;
                if (sym_off + sizeof(elf64_sym_t) > symtab_size) {
                    break;
                }

                elf64_sym_t sym;
                parse_symbol(symtab + sym_off, &sym);

                /* Text relocations patch LDDW pairs. */
                if (r_offset >= prog->text_vaddr &&
                    r_offset + 16 <= prog->text_vaddr + prog->text_len) {
                    uint8_t* target = NULL;
                    if (!program_vaddr_translate(prog, r_offset, 16, &target)) {
                        break;
                    }

                    sol_bpf_insn_t* insn1 = (sol_bpf_insn_t*)target;
                    sol_bpf_insn_t* insn2 = insn1 + 1;

                    /* REL: addend is stored in-place in the imm fields */
                    uint64_t addend = (uint64_t)(uint32_t)insn1->imm |
                                     ((uint64_t)(uint32_t)insn2->imm << 32);

                    uint64_t new_imm = SOL_BPF_MM_PROGRAM_START + sym.st_value + addend;
                    insn1->imm = (int32_t)new_imm;
                    insn2->imm = (int32_t)(new_imm >> 32);
                    break;
                }

                /* Data relocations: S + A + base.  Use same legacy u32-from-
                 * imm-offset read as R_BPF_64_RELATIVE for consistency.
                 * Agave doesn't have a data-specific R_BPF_64_64 path (it always
                 * assumes LDDW), but this handles the rare case correctly. */
                uint8_t* target = NULL;
                if (!program_vaddr_translate(prog, r_offset, 8, &target)) {
                    break;
                }

                /* REL: addend is stored in-place */
                uint32_t imm_val = 0;
                memcpy(&imm_val, target + 4, sizeof(uint32_t));
                uint64_t addend = (uint64_t)imm_val;

                uint64_t val = SOL_BPF_MM_PROGRAM_START + sym.st_value + addend;
                write_u64(target, val);
                break;
            }

            case R_BPF_64_32: {
                /* Call relocation: internal (PC-relative) or syscall (hash). */
                if (symtab == NULL || sym_entsize == 0) {
                    break;
                }
                size_t sym_off = (size_t)sym_idx * sym_entsize;
                if (sym_off + sizeof(elf64_sym_t) > symtab_size) {
                    break;
                }

                elf64_sym_t sym;
                parse_symbol(symtab + sym_off, &sym);

                uint8_t* target = NULL;
                if (!program_vaddr_translate(prog, r_offset, sizeof(sol_bpf_insn_t), &target)) {
                    break;
                }

                sol_bpf_insn_t* insn = (sol_bpf_insn_t*)target;
                uint8_t op_class = SOL_BPF_OP_CLASS(insn->opcode);
                if ((op_class != SOL_BPF_CLASS_JMP && op_class != SOL_BPF_CLASS_JMP32) ||
                    SOL_BPF_OP_CODE(insn->opcode) != SOL_BPF_JMP_CALL) {
                    break;
                }

                /* Agave/rbpf dispatches R_BPF_64_32 relocations based on
                 * the symbol's ELF type, NOT its section index:
                 *   - STT_FUNC with non-zero value => internal call
                 *   - Everything else => syscall hash (or reject if unknown)
                 *
                 * This matches rbpf elf.rs: "if symbol.is_function() &&
                 * symbol.st_value() != 0 { ... internal ... } else {
                 * ... syscall hash ... }" */

                if (ELF64_ST_TYPE(sym.st_info) == STT_FUNC && sym.st_value != 0) {
                    /* STT_FUNC => internal function call (relative PC offset). */
                    if (sym.st_value < prog->text_vaddr || sym.st_value >= prog->text_vaddr + prog->text_len) {
                        break;
                    }

                    if (r_offset < prog->text_vaddr || r_offset >= prog->text_vaddr + prog->text_len) {
                        break;
                    }

                    uint64_t call_off = r_offset - prog->text_vaddr;
                    uint64_t target_off = sym.st_value - prog->text_vaddr;
                    if ((call_off & 7u) != 0 || (target_off & 7u) != 0) {
                        break;
                    }

                    int64_t call_pc = (int64_t)(call_off / 8u);
                    int64_t target_pc = (int64_t)(target_off / 8u);
                    int64_t rel_pc = target_pc - (call_pc + 1);

                    if (rel_pc < INT32_MIN || rel_pc > INT32_MAX) {
                        break;
                    }

                    insn->imm = (int32_t)rel_pc;
                    /* Ensure internal calls are marked as pseudo-calls (src=1). */
                    insn->regs = (uint8_t)((insn->regs & 0x0f) | (1u << 4));
                } else if (sym.st_shndx == 0) {
                    /* Undefined symbol (st_shndx=0) => syscall hash.
                     * Hash the name and set as imm for runtime dispatch. */
                    const char* name = strtab ? get_section_name(strtab, strtab_size, sym.st_name) : NULL;
                    if (name == NULL) {
                        break;
                    }
                    uint32_t hash = sol_bpf_syscall_hash(name);
                    insn->imm = (int32_t)hash;
                    /* Some toolchains emit calls with src=1 and imm=-1 as a
                     * relocation placeholder. Ensure syscalls are marked with
                     * src=0 so the interpreter dispatches by hash. */
                    insn->regs &= 0x0f;
                } else {
                    /* Defined non-function symbol (e.g. STT_NOTYPE label,
                     * STT_FILE).  In Agave/rbpf these go through the syscall
                     * hash path and are rejected by reject_broken_elfs because
                     * the hash of a local label name never matches a registered
                     * syscall.  Reject the ELF to match. */
                    const char* name = strtab ? get_section_name(strtab, strtab_size, sym.st_name) : NULL;
                    sol_log_error("BPF ELF: unresolved non-function symbol "
                                  "\"%s\" (type=%u shndx=%u val=0x%lx) "
                                  "at offset 0x%lx",
                                  name ? name : "?",
                                  (unsigned)ELF64_ST_TYPE(sym.st_info),
                                  (unsigned)sym.st_shndx,
                                  (unsigned long)sym.st_value,
                                  (unsigned long)r_offset);
                    return SOL_ERR_INVAL;
                }
                break;
            }

            default:
                /* Unknown relocation type - ignore */
                break;
            }
        }
    }

    sol_log_debug("Loaded BPF program: %zu instructions, entry=%u",
                  prog->insn_count, prog->entry_pc);

    return SOL_OK;
}

/*
 * Load program from ELF into VM
 */
sol_err_t
sol_bpf_vm_load(
    sol_bpf_vm_t* vm,
    const uint8_t* elf_data,
    size_t elf_len
) {
    if (vm == NULL || elf_data == NULL || elf_len == 0) {
        return SOL_ERR_INVAL;
    }

    /* Create program */
    sol_bpf_program_t* prog = sol_bpf_program_new();
    if (prog == NULL) {
        return SOL_ERR_NOMEM;
    }

    /* Load ELF */
    sol_err_t err = sol_bpf_elf_load(prog, elf_data, elf_len);
    if (err != SOL_OK) {
        sol_bpf_program_destroy(prog);
        return err;
    }

    /* Add unified ro_section as single contiguous region at MM_PROGRAM_START.
     * Matches Agave rbpf: one buffer from vaddr 0 to highest section end,
     * zero-filled with sections copied at their sh_addr offsets. */
    err = sol_bpf_memory_add_region(&vm->memory, SOL_BPF_MM_PROGRAM_START,
                                    prog->ro_section, prog->ro_section_len, false);
    if (err != SOL_OK) {
        sol_bpf_program_destroy(prog);
        return err;
    }

    vm->program = prog;
    vm->pc = prog->entry_pc;

    /* Adjust frame pointer (r10) based on SBPF version.
     *
     * SBPFv0 (static frames): r10 = MM_STACK_START + frame_size.
     *   The VM advances r10 by (frame_size + gap_size) on each call.
     *
     * SBPFv1+ (dynamic frames): r10 = MM_STACK_START + stack_size.
     *   The program manages r10 itself (subtracts to allocate, adds to free).
     *   r10 starts at the TOP of the entire stack, not just the first frame.
     *
     * Matches rbpf: reg[FRAME_PTR_REG] = MM_STACK_START +
     *   if dynamic_stack_frames { config.stack_size() } else { config.stack_frame_size }
     */
    if (sol_sbpf_dynamic_stack_frames(prog->sbpf_version)) {
        vm->reg[10] = SOL_BPF_MM_STACK_START + (uint64_t)vm->stack_size;

        /* SBPFv1+ (dynamic frames): the stack must be contiguous (no gaps).
         * Agave/rbpf passes gap_size=0 when dynamic_stack_frames() is true:
         *   if !sbpf_version.dynamic_stack_frames() && config.enable_stack_frame_gaps
         *       { config.stack_frame_size } else { 0 }
         * Our VM may have created a gapped stack region at init time (before
         * the SBPF version was known).  Convert it to linear now. */
        for (size_t i = 0; i < vm->memory.region_count; i++) {
            sol_bpf_region_t* r = &vm->memory.regions[i];
            if (r->vaddr == SOL_BPF_MM_STACK_START &&
                r->kind == SOL_BPF_REGION_GAPPED) {
                r->kind = SOL_BPF_REGION_LINEAR;
                r->len = r->host_len;  /* physical size = contiguous */
                r->elem_len = 0;
                r->gap_len = 0;
                vm->stack_virt_size = r->host_len;
                vm->stack_gap_size = 0;
                break;
            }
        }
    }
    /* else: keep the default from sol_bpf_vm_create:
     *   vm->reg[10] = MM_STACK_START + stack_frame_size */

    return SOL_OK;
}

/*
 * Verify BPF program
 *
 * Performs static analysis to ensure the program is safe to execute.
 */
sol_err_t
sol_bpf_verify(const sol_bpf_program_t* prog) {
    if (prog == NULL || prog->instructions == NULL || prog->insn_count == 0) {
        return SOL_ERR_INVAL;
    }

    const sol_bpf_insn_t* insns = prog->instructions;
    size_t count = prog->insn_count;

    for (size_t i = 0; i < count; i++) {
        const sol_bpf_insn_t* insn = &insns[i];
        uint8_t op_class = SOL_BPF_OP_CLASS(insn->opcode);
        uint8_t dst = SOL_BPF_INSN_DST(insn);
        uint8_t src = SOL_BPF_INSN_SRC(insn);

        /* Validate register numbers */
        if (dst >= SOL_BPF_NUM_REGISTERS || src >= SOL_BPF_NUM_REGISTERS) {
            sol_log_error("Invalid register at PC %zu", i);
            return SOL_ERR_BPF_VERIFY;
        }

        /* Check for writes to r10 (frame pointer) */
        if (dst == 10 && op_class != SOL_BPF_CLASS_STX) {
            /* Only STX can use r10 as destination (for memory writes) */
            if (op_class == SOL_BPF_CLASS_ALU ||
                op_class == SOL_BPF_CLASS_ALU64 ||
                op_class == SOL_BPF_CLASS_LDX ||
                op_class == SOL_BPF_CLASS_LD) {
                sol_log_error("Write to r10 at PC %zu", i);
                return SOL_ERR_BPF_VERIFY;
            }
        }

        /* Validate jump targets */
        if (op_class == SOL_BPF_CLASS_JMP || op_class == SOL_BPF_CLASS_JMP32) {
            uint8_t op_code = SOL_BPF_OP_CODE(insn->opcode);

            if (op_code != SOL_BPF_JMP_CALL && op_code != SOL_BPF_JMP_EXIT) {
                int64_t target = (int64_t)i + 1 + insn->offset;
                if (target < 0 || (size_t)target >= count) {
                    sol_log_error("Jump out of bounds at PC %zu", i);
                    return SOL_ERR_BPF_VERIFY;
                }
            }
        }

        /* LDDW consumes two instructions */
        if (insn->opcode == SOL_BPF_OP_LDDW) {
            if (i + 1 >= count) {
                sol_log_error("LDDW at end of program");
                return SOL_ERR_BPF_VERIFY;
            }
            i++;  /* Skip next instruction */
        }
    }

    /* Check that program ends with exit */
    const sol_bpf_insn_t* last = &insns[count - 1];
    if (last->opcode != SOL_BPF_OP_EXIT) {
        /* Check if second-to-last is LDDW and last is exit */
        if (count >= 2) {
            const sol_bpf_insn_t* prev = &insns[count - 2];
            if (prev->opcode != SOL_BPF_OP_LDDW ||
                last->opcode != SOL_BPF_OP_EXIT) {
                sol_log_warn("Program does not end with exit");
            }
        }
    }

    return SOL_OK;
}
