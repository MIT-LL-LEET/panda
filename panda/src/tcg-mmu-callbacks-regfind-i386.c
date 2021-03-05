#include "qemu/osdep.h"

#include "qemu/cutils.h"
#include "qemu/host-utils.h"
#include "qemu/timer.h"

/* Note: the long term plan is to reduce the dependencies on the QEMU
   CPU definitions. Currently they are used for qemu_ld/st
   instructions */
#define NO_CPU_IO_DEFS
#include "cpu.h"

#include "exec/cpu-common.h"
#include "exec/exec-all.h"

#include "tcg-op.h"

#include "panda/tcg-mmu-callbacks-regfind.h"

#if !defined(TARGET_I386) && !defined(TARGET_X86_64)
#error "tcg-mmu-callbacks-regfind-i386 should only be built for TARGET_I386 or TARGET_X86_64"
#else

const char* const PANDA_GP_REG_NAMES[PANDA_GP_REG_NAMES_COUNT] = {
    [PANDA_GP_REG_IMMEDIATE] = "IMMEDIATE",

    [PANDA_GP_REG_RAX] = "rax",
    [PANDA_GP_REG_EAX] = "eax",
    [PANDA_GP_REG_AX]  = "ax",
    [PANDA_GP_REG_AH]  = "ah",
    [PANDA_GP_REG_AL]  = "al",
    [PANDA_GP_REG_RBX] = "rbx",
    [PANDA_GP_REG_EBX] = "ebx",
    [PANDA_GP_REG_BX]  = "bx",
    [PANDA_GP_REG_BH]  = "bh",
    [PANDA_GP_REG_BL]  = "bl",
    [PANDA_GP_REG_RCX] = "rcx",
    [PANDA_GP_REG_ECX] = "ecx",
    [PANDA_GP_REG_CX]  = "cx",
    [PANDA_GP_REG_CH]  = "ch",
    [PANDA_GP_REG_CL]  = "cl",
    [PANDA_GP_REG_RDX] = "rdx",
    [PANDA_GP_REG_EDX] = "edx",
    [PANDA_GP_REG_DX]  = "dx",
    [PANDA_GP_REG_DH]  = "dh",
    [PANDA_GP_REG_DL]  = "dl",
    [PANDA_GP_REG_RSP] = "rsp",
    [PANDA_GP_REG_ESP] = "esp",
    [PANDA_GP_REG_SP]  = "sp",
    [PANDA_GP_REG_RBP] = "rbp",
    [PANDA_GP_REG_EBP] = "ebp",
    [PANDA_GP_REG_BP]  = "bp",
    [PANDA_GP_REG_RSI] = "rsi",
    [PANDA_GP_REG_ESI] = "esi",
    [PANDA_GP_REG_SI]  = "si",
    [PANDA_GP_REG_RDI] = "rdi",
    [PANDA_GP_REG_EDI] = "edi",
    [PANDA_GP_REG_DI]  = "di",
    [PANDA_GP_REG_R8]  = "r8",
    [PANDA_GP_REG_R9]  = "r9",
    [PANDA_GP_REG_R10] = "r10",
    [PANDA_GP_REG_R11] = "r11",
    [PANDA_GP_REG_R12] = "r12",
    [PANDA_GP_REG_R13] = "r13",
    [PANDA_GP_REG_R14] = "r14",
    [PANDA_GP_REG_R15] = "r15",

    /* not real globals, but used by env offset code */
    [PANDA_GP_REG_RIP] = "rip",
    [PANDA_GP_REG_EIP] = "eip",
    [PANDA_GP_REG_IP]  = "ip",

    [PANDA_GP_REG_XMM0] = "xmm0",
    [PANDA_GP_REG_XMM1] = "xmm1",
    [PANDA_GP_REG_XMM2] = "xmm2",
    [PANDA_GP_REG_XMM3] = "xmm3",
    [PANDA_GP_REG_XMM4] = "xmm4",
    [PANDA_GP_REG_XMM5] = "xmm5",
    [PANDA_GP_REG_XMM6] = "xmm6",
    [PANDA_GP_REG_XMM7] = "xmm7",
    [PANDA_GP_REG_XMM8] = "xmm8",
    [PANDA_GP_REG_XMM9] = "xmm9",
    [PANDA_GP_REG_XMM10] = "xmm10",
    [PANDA_GP_REG_XMM11] = "xmm11",
    [PANDA_GP_REG_XMM12] = "xmm12",
    [PANDA_GP_REG_XMM13] = "xmm13",
    [PANDA_GP_REG_XMM14] = "xmm14",
    [PANDA_GP_REG_XMM15] = "xmm15",
    [PANDA_GP_REG_XMM16] = "xmm16",
    [PANDA_GP_REG_XMM17] = "xmm17",
    [PANDA_GP_REG_XMM18] = "xmm18",
    [PANDA_GP_REG_XMM19] = "xmm19",
    [PANDA_GP_REG_XMM20] = "xmm20",
    [PANDA_GP_REG_XMM21] = "xmm21",
    [PANDA_GP_REG_XMM22] = "xmm22",
    [PANDA_GP_REG_XMM23] = "xmm23",
    [PANDA_GP_REG_XMM24] = "xmm24",
    [PANDA_GP_REG_XMM25] = "xmm25",
    [PANDA_GP_REG_XMM26] = "xmm26",
    [PANDA_GP_REG_XMM27] = "xmm27",
    [PANDA_GP_REG_XMM28] = "xmm28",
    [PANDA_GP_REG_XMM29] = "xmm29",
    [PANDA_GP_REG_XMM30] = "xmm30",
    [PANDA_GP_REG_XMM31] = "xmm31",

    [PANDA_GP_REG_YMM0] = "ymm0",
    [PANDA_GP_REG_YMM1] = "ymm1",
    [PANDA_GP_REG_YMM2] = "ymm2",
    [PANDA_GP_REG_YMM3] = "ymm3",
    [PANDA_GP_REG_YMM4] = "ymm4",
    [PANDA_GP_REG_YMM5] = "ymm5",
    [PANDA_GP_REG_YMM6] = "ymm6",
    [PANDA_GP_REG_YMM7] = "ymm7",
    [PANDA_GP_REG_YMM8] = "ymm8",
    [PANDA_GP_REG_YMM9] = "ymm9",
    [PANDA_GP_REG_YMM10] = "ymm10",
    [PANDA_GP_REG_YMM11] = "ymm11",
    [PANDA_GP_REG_YMM12] = "ymm12",
    [PANDA_GP_REG_YMM13] = "ymm13",
    [PANDA_GP_REG_YMM14] = "ymm14",
    [PANDA_GP_REG_YMM15] = "ymm15",
    [PANDA_GP_REG_YMM16] = "ymm16",
    [PANDA_GP_REG_YMM17] = "ymm17",
    [PANDA_GP_REG_YMM18] = "ymm18",
    [PANDA_GP_REG_YMM19] = "ymm19",
    [PANDA_GP_REG_YMM20] = "ymm20",
    [PANDA_GP_REG_YMM21] = "ymm21",
    [PANDA_GP_REG_YMM22] = "ymm22",
    [PANDA_GP_REG_YMM23] = "ymm23",
    [PANDA_GP_REG_YMM24] = "ymm24",
    [PANDA_GP_REG_YMM25] = "ymm25",
    [PANDA_GP_REG_YMM26] = "ymm26",
    [PANDA_GP_REG_YMM27] = "ymm27",
    [PANDA_GP_REG_YMM28] = "ymm28",
    [PANDA_GP_REG_YMM29] = "ymm29",
    [PANDA_GP_REG_YMM30] = "ymm30",
    [PANDA_GP_REG_YMM31] = "ymm31",

    [PANDA_GP_REG_ZMM0] = "zmm0",
    [PANDA_GP_REG_ZMM1] = "zmm1",
    [PANDA_GP_REG_ZMM2] = "zmm2",
    [PANDA_GP_REG_ZMM3] = "zmm3",
    [PANDA_GP_REG_ZMM4] = "zmm4",
    [PANDA_GP_REG_ZMM5] = "zmm5",
    [PANDA_GP_REG_ZMM6] = "zmm6",
    [PANDA_GP_REG_ZMM7] = "zmm7",
    [PANDA_GP_REG_ZMM8] = "zmm8",
    [PANDA_GP_REG_ZMM9] = "zmm9",
    [PANDA_GP_REG_ZMM10] = "zmm10",
    [PANDA_GP_REG_ZMM11] = "zmm11",
    [PANDA_GP_REG_ZMM12] = "zmm12",
    [PANDA_GP_REG_ZMM13] = "zmm13",
    [PANDA_GP_REG_ZMM14] = "zmm14",
    [PANDA_GP_REG_ZMM15] = "zmm15",
    [PANDA_GP_REG_ZMM16] = "zmm16",
    [PANDA_GP_REG_ZMM17] = "zmm17",
    [PANDA_GP_REG_ZMM18] = "zmm18",
    [PANDA_GP_REG_ZMM19] = "zmm19",
    [PANDA_GP_REG_ZMM20] = "zmm20",
    [PANDA_GP_REG_ZMM21] = "zmm21",
    [PANDA_GP_REG_ZMM22] = "zmm22",
    [PANDA_GP_REG_ZMM23] = "zmm23",
    [PANDA_GP_REG_ZMM24] = "zmm24",
    [PANDA_GP_REG_ZMM25] = "zmm25",
    [PANDA_GP_REG_ZMM26] = "zmm26",
    [PANDA_GP_REG_ZMM27] = "zmm27",
    [PANDA_GP_REG_ZMM28] = "zmm28",
    [PANDA_GP_REG_ZMM29] = "zmm29",
    [PANDA_GP_REG_ZMM30] = "zmm30",
    [PANDA_GP_REG_ZMM31] = "zmm31",

    [PANDA_GP_REG_ST0] = "st0",
    [PANDA_GP_REG_ST1] = "st1",
    [PANDA_GP_REG_ST2] = "st2",
    [PANDA_GP_REG_ST3] = "st3",
    [PANDA_GP_REG_ST4] = "st4",
    [PANDA_GP_REG_ST5] = "st5",
    [PANDA_GP_REG_ST6] = "st6",
    [PANDA_GP_REG_ST7] = "st7",

    [PANDA_GP_REG_CR0] = "cr0",
    [PANDA_GP_REG_CR2] = "cr2",
    [PANDA_GP_REG_CR3] = "cr3",
    [PANDA_GP_REG_CR4] = "cr4",

    [PANDA_GP_REG_DR0] = "dr0",
    [PANDA_GP_REG_DR1] = "dr1",
    [PANDA_GP_REG_DR2] = "dr2",
    [PANDA_GP_REG_DR3] = "dr3",
    [PANDA_GP_REG_DR6] = "dr6",
    [PANDA_GP_REG_DR7] = "dr7"
};

/* gross, but let's do this to start instead of getting smart */
enum panda_gp_reg_enum gp_reg_idx_by_name(const char* reg)
{
    if (!reg || !reg[0])
        return PANDA_GP_REG_INVALID;
    for (int32_t i = 0; i < PANDA_GP_REG_NAMES_COUNT; ++i)
    {
        if (!strcmp(PANDA_GP_REG_NAMES[i], reg))
            return i;
    }
    return PANDA_GP_REG_INVALID;
}

#define _OFF_WITHIN(s, fld, off) ( ((off) >= offsetof(s, fld) && (off) < offsetof(s, fld) + sizeof(((s *)NULL)->fld)) ? true : false )
enum panda_gp_reg_enum gp_reg_idx_by_offset(size_t off)
{
    if (_OFF_WITHIN(CPUArchState, eip, off))
        return PANDA_GP_REG_EIP;
    if (_OFF_WITHIN(CPUArchState, fpregs, off))
    {
        size_t r = (off - offsetof(CPUArchState, fpregs[0])) / sizeof(((CPUArchState*)NULL)->fpregs[0]);
        assert(PANDA_GP_REG_ST0 + r <= PANDA_GP_REG_ST7);
        return PANDA_GP_REG_ST0 + r;
    }
    if (_OFF_WITHIN(CPUArchState, dr, off))
    {
        size_t r = (off - offsetof(CPUArchState, dr[0])) / sizeof(((CPUArchState*)NULL)->dr[0]);
        if (r <= 3)
        {
            assert(PANDA_GP_REG_DR0 + r <= PANDA_GP_REG_DR7);
            return PANDA_GP_REG_DR0 + r;
        }
        else if (r >= 6)
        {
            r -= 2; /* DR4 and DR5 don't exist, but are in the array */
            assert(PANDA_GP_REG_DR0 + r <= PANDA_GP_REG_DR7);
            return PANDA_GP_REG_DR0 + r;
        }
    }
    if (_OFF_WITHIN(CPUArchState, xmm_regs, off))
    {
        size_t r = (off - offsetof(CPUArchState, xmm_regs[0])) / sizeof(((CPUArchState*)NULL)->xmm_regs[0]);
        assert(PANDA_GP_REG_ZMM0 + r <= PANDA_GP_REG_ZMM31);
        return PANDA_GP_REG_ZMM0 + r;
    }
    /*
        taint currently cares about the following additional fields:
            xmm_t0, mmx_t0, cc_dst, cc_src, cc_src2, cc_op, df
        It's not currently clear what hardware registers some of these correspond
        to (df being part of {E,R,}FLAGS).
        Currently it's clear some XMM operations use xmm_t0 as a target (pcmpeqb)
    */
    return PANDA_GP_REG_INVALID;
}

#endif
