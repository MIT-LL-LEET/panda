#ifndef _TCG_MMU_CALLBACKS_REGFIND_I386_H
#define _TCG_MMU_CALLBACKS_REGFIND_I386_H

#if !defined(TARGET_I386) && !defined(TARGET_X86_64)
#error "tcg-mmu-callbacks-regfind-i386 should only be built for TARGET_I386 or TARGET_X86_64"
#endif

enum panda_gp_reg_enum {
    PANDA_GP_REG_IMMEDIATE,

    PANDA_GP_REG_RAX,
    PANDA_GP_REG_EAX,
    PANDA_GP_REG_AX,
    PANDA_GP_REG_AH,
    PANDA_GP_REG_AL,

    PANDA_GP_REG_RBX,
    PANDA_GP_REG_EBX,
    PANDA_GP_REG_BX,
    PANDA_GP_REG_BH,
    PANDA_GP_REG_BL,

    PANDA_GP_REG_RCX,
    PANDA_GP_REG_ECX,
    PANDA_GP_REG_CX,
    PANDA_GP_REG_CH,
    PANDA_GP_REG_CL,

    PANDA_GP_REG_RDX,
    PANDA_GP_REG_EDX,
    PANDA_GP_REG_DX,
    PANDA_GP_REG_DH,
    PANDA_GP_REG_DL,

    PANDA_GP_REG_RSP,
    PANDA_GP_REG_ESP,
    PANDA_GP_REG_SP,

    PANDA_GP_REG_RBP,
    PANDA_GP_REG_EBP,
    PANDA_GP_REG_BP,

    PANDA_GP_REG_RSI,
    PANDA_GP_REG_ESI,
    PANDA_GP_REG_SI,

    PANDA_GP_REG_RDI,
    PANDA_GP_REG_EDI,
    PANDA_GP_REG_DI,

    PANDA_GP_REG_R8,
    PANDA_GP_REG_R9,
    PANDA_GP_REG_R10,
    PANDA_GP_REG_R11,
    PANDA_GP_REG_R12,
    PANDA_GP_REG_R13,
    PANDA_GP_REG_R14,
    PANDA_GP_REG_R15,

    PANDA_GP_REG_RIP,
    PANDA_GP_REG_EIP,
    PANDA_GP_REG_IP,

    PANDA_GP_REG_XMM0,
    PANDA_GP_REG_XMM1,
    PANDA_GP_REG_XMM2,
    PANDA_GP_REG_XMM3,
    PANDA_GP_REG_XMM4,
    PANDA_GP_REG_XMM5,
    PANDA_GP_REG_XMM6,
    PANDA_GP_REG_XMM7,
    PANDA_GP_REG_XMM8,
    PANDA_GP_REG_XMM9,
    PANDA_GP_REG_XMM10,
    PANDA_GP_REG_XMM11,
    PANDA_GP_REG_XMM12,
    PANDA_GP_REG_XMM13,
    PANDA_GP_REG_XMM14,
    PANDA_GP_REG_XMM15,
    PANDA_GP_REG_XMM16,
    PANDA_GP_REG_XMM17,
    PANDA_GP_REG_XMM18,
    PANDA_GP_REG_XMM19,
    PANDA_GP_REG_XMM20,
    PANDA_GP_REG_XMM21,
    PANDA_GP_REG_XMM22,
    PANDA_GP_REG_XMM23,
    PANDA_GP_REG_XMM24,
    PANDA_GP_REG_XMM25,
    PANDA_GP_REG_XMM26,
    PANDA_GP_REG_XMM27,
    PANDA_GP_REG_XMM28,
    PANDA_GP_REG_XMM29,
    PANDA_GP_REG_XMM30,
    PANDA_GP_REG_XMM31,

    PANDA_GP_REG_YMM0,
    PANDA_GP_REG_YMM1,
    PANDA_GP_REG_YMM2,
    PANDA_GP_REG_YMM3,
    PANDA_GP_REG_YMM4,
    PANDA_GP_REG_YMM5,
    PANDA_GP_REG_YMM6,
    PANDA_GP_REG_YMM7,
    PANDA_GP_REG_YMM8,
    PANDA_GP_REG_YMM9,
    PANDA_GP_REG_YMM10,
    PANDA_GP_REG_YMM11,
    PANDA_GP_REG_YMM12,
    PANDA_GP_REG_YMM13,
    PANDA_GP_REG_YMM14,
    PANDA_GP_REG_YMM15,
    PANDA_GP_REG_YMM16,
    PANDA_GP_REG_YMM17,
    PANDA_GP_REG_YMM18,
    PANDA_GP_REG_YMM19,
    PANDA_GP_REG_YMM20,
    PANDA_GP_REG_YMM21,
    PANDA_GP_REG_YMM22,
    PANDA_GP_REG_YMM23,
    PANDA_GP_REG_YMM24,
    PANDA_GP_REG_YMM25,
    PANDA_GP_REG_YMM26,
    PANDA_GP_REG_YMM27,
    PANDA_GP_REG_YMM28,
    PANDA_GP_REG_YMM29,
    PANDA_GP_REG_YMM30,
    PANDA_GP_REG_YMM31,

    PANDA_GP_REG_ZMM0,
    PANDA_GP_REG_ZMM1,
    PANDA_GP_REG_ZMM2,
    PANDA_GP_REG_ZMM3,
    PANDA_GP_REG_ZMM4,
    PANDA_GP_REG_ZMM5,
    PANDA_GP_REG_ZMM6,
    PANDA_GP_REG_ZMM7,
    PANDA_GP_REG_ZMM8,
    PANDA_GP_REG_ZMM9,
    PANDA_GP_REG_ZMM10,
    PANDA_GP_REG_ZMM11,
    PANDA_GP_REG_ZMM12,
    PANDA_GP_REG_ZMM13,
    PANDA_GP_REG_ZMM14,
    PANDA_GP_REG_ZMM15,
    PANDA_GP_REG_ZMM16,
    PANDA_GP_REG_ZMM17,
    PANDA_GP_REG_ZMM18,
    PANDA_GP_REG_ZMM19,
    PANDA_GP_REG_ZMM20,
    PANDA_GP_REG_ZMM21,
    PANDA_GP_REG_ZMM22,
    PANDA_GP_REG_ZMM23,
    PANDA_GP_REG_ZMM24,
    PANDA_GP_REG_ZMM25,
    PANDA_GP_REG_ZMM26,
    PANDA_GP_REG_ZMM27,
    PANDA_GP_REG_ZMM28,
    PANDA_GP_REG_ZMM29,
    PANDA_GP_REG_ZMM30,
    PANDA_GP_REG_ZMM31,

    PANDA_GP_REG_ST0,
    PANDA_GP_REG_ST1,
    PANDA_GP_REG_ST2,
    PANDA_GP_REG_ST3,
    PANDA_GP_REG_ST4,
    PANDA_GP_REG_ST5,
    PANDA_GP_REG_ST6,
    PANDA_GP_REG_ST7,

    PANDA_GP_REG_CR0,
    PANDA_GP_REG_CR2,
    PANDA_GP_REG_CR3,
    PANDA_GP_REG_CR4,

    PANDA_GP_REG_DR0,
    PANDA_GP_REG_DR1,
    PANDA_GP_REG_DR2,
    PANDA_GP_REG_DR3,
    PANDA_GP_REG_DR6,
    PANDA_GP_REG_DR7,

    PANDA_GP_REG_NAMES_COUNT,
    PANDA_GP_REG_INVALID = (int32_t)-1
};

enum panda_gp_reg_enum gp_reg_idx_by_name(const char* reg);
enum panda_gp_reg_enum gp_reg_idx_by_offset(size_t off);
extern const char* const PANDA_GP_REG_NAMES[PANDA_GP_REG_NAMES_COUNT];

#endif
