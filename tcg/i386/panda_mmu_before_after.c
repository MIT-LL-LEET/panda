#include "panda/callbacks/cb-support.h"

/* signed post store */
static void helper_panda_after_load32_s8(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_load32(addrlo, addrhi, datalo, datahi, 8, true, false, cpu);
}
static void helper_panda_after_load32_s16(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_load32(addrlo, addrhi, datalo, datahi, 16, true, false, cpu);
}
static void helper_panda_after_load32_s32(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_load32(addrlo, addrhi, datalo, datahi, 32, true, false, cpu);
}
static void helper_panda_after_load32_s64(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_load32(addrlo, addrhi, datalo, datahi, 64, true, false, cpu);
}
/* unsigned post store */
static void helper_panda_after_load32_u8(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_load32(addrlo, addrhi, datalo, datahi, 8, false, false, cpu);
}
static void helper_panda_after_load32_u16(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_load32(addrlo, addrhi, datalo, datahi, 16, false, false, cpu);
}
static void helper_panda_after_load32_u32(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_load32(addrlo, addrhi, datalo, datahi, 32, false, false, cpu);
}
static void helper_panda_after_load32_u64(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_load32(addrlo, addrhi, datalo, datahi, 64, false, false, cpu);
}
/* signed pre store */
static void helper_panda_before_load32_s8(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_load32(addrlo, addrhi, datalo, datahi, 8, true, true, cpu);
}
static void helper_panda_before_load32_s16(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_load32(addrlo, addrhi, datalo, datahi, 16, true, true, cpu);
}
static void helper_panda_before_load32_s32(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_load32(addrlo, addrhi, datalo, datahi, 32, true, true, cpu);
}
static void helper_panda_before_load32_s64(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_load32(addrlo, addrhi, datalo, datahi, 64, true, true, cpu);
}
/* unsigned pre store */
static void helper_panda_before_load32_u8(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_load32(addrlo, addrhi, datalo, datahi, 8, false, true, cpu);
}
static void helper_panda_before_load32_u16(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_load32(addrlo, addrhi, datalo, datahi, 16, false, true, cpu);
}
static void helper_panda_before_load32_u32(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_load32(addrlo, addrhi, datalo, datahi, 32, false, true, cpu);
}
static void helper_panda_before_load32_u64(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_load32(addrlo, addrhi, datalo, datahi, 64, false, true, cpu);
}


/* signed post store */
static void helper_panda_after_load64_s8(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_load64(addrlo, datalo, 8, true, false, cpu);
}
static void helper_panda_after_load64_s16(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_load64(addrlo, datalo, 16, true, false, cpu);
}
static void helper_panda_after_load64_s32(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_load64(addrlo, datalo, 32, true, false, cpu);
}
static void helper_panda_after_load64_s64(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_load64(addrlo, datalo, 64, true, false, cpu);
}
/* unsigned post store */
static void helper_panda_after_load64_u8(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_load64(addrlo, datalo, 8, false, false, cpu);
}
static void helper_panda_after_load64_u16(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_load64(addrlo, datalo, 16, false, false, cpu);
}
static void helper_panda_after_load64_u32(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_load64(addrlo, datalo, 32, false, false, cpu);
}
static void helper_panda_after_load64_u64(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_load64(addrlo, datalo, 64, false, false, cpu);
}
/* signed pre store */
static void helper_panda_before_load64_s8(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_load64(addrlo, datalo, 8, true, true, cpu);
}
static void helper_panda_before_load64_s16(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_load64(addrlo, datalo, 16, true, true, cpu);
}
static void helper_panda_before_load64_s32(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_load64(addrlo, datalo, 32, true, true, cpu);
}
static void helper_panda_before_load64_s64(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_load64(addrlo, datalo, 64, true, true, cpu);
}
/* unsigned pre store */
static void helper_panda_before_load64_u8(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_load64(addrlo, datalo, 8, false, true, cpu);
}
static void helper_panda_before_load64_u16(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_load64(addrlo, datalo, 16, false, true, cpu);
}
static void helper_panda_before_load64_u32(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_load64(addrlo, datalo, 32, false, true, cpu);
}
static void helper_panda_before_load64_u64(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_load64(addrlo, datalo, 64, false, true, cpu);
}


/* signed post store */
static void helper_panda_after_store32_s8(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_store32(addrlo, addrhi, datalo, datahi, 8, true, false, cpu);
}
static void helper_panda_after_store32_s16(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_store32(addrlo, addrhi, datalo, datahi, 16, true, false, cpu);
}
static void helper_panda_after_store32_s32(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_store32(addrlo, addrhi, datalo, datahi, 32, true, false, cpu);
}
static void helper_panda_after_store32_s64(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_store32(addrlo, addrhi, datalo, datahi, 64, true, false, cpu);
}
/* unsigned post store */
static void helper_panda_after_store32_u8(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_store32(addrlo, addrhi, datalo, datahi, 8, false, false, cpu);
}
static void helper_panda_after_store32_u16(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_store32(addrlo, addrhi, datalo, datahi, 16, false, false, cpu);
}
static void helper_panda_after_store32_u32(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_store32(addrlo, addrhi, datalo, datahi, 32, false, false, cpu);
}
static void helper_panda_after_store32_u64(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_store32(addrlo, addrhi, datalo, datahi, 64, false, false, cpu);
}
/* signed pre store */
static void helper_panda_before_store32_s8(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_store32(addrlo, addrhi, datalo, datahi, 8, true, true, cpu);
}
static void helper_panda_before_store32_s16(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_store32(addrlo, addrhi, datalo, datahi, 16, true, true, cpu);
}
static void helper_panda_before_store32_s32(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_store32(addrlo, addrhi, datalo, datahi, 32, true, true, cpu);
}
static void helper_panda_before_store32_s64(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_store32(addrlo, addrhi, datalo, datahi, 64, true, true, cpu);
}
/* unsigned pre store */
static void helper_panda_before_store32_u8(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_store32(addrlo, addrhi, datalo, datahi, 8, false, true, cpu);
}
static void helper_panda_before_store32_u16(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_store32(addrlo, addrhi, datalo, datahi, 16, false, true, cpu);
}
static void helper_panda_before_store32_u32(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_store32(addrlo, addrhi, datalo, datahi, 32, false, true, cpu);
}
static void helper_panda_before_store32_u64(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu)
{
    helper_panda_beforeafter_store32(addrlo, addrhi, datalo, datahi, 64, false, true, cpu);
}


/* signed post store */
static void helper_panda_after_store64_s8(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_store64(addrlo, datalo, 8, true, false, cpu);
}
static void helper_panda_after_store64_s16(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_store64(addrlo, datalo, 16, true, false, cpu);
}
static void helper_panda_after_store64_s32(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_store64(addrlo, datalo, 32, true, false, cpu);
}
static void helper_panda_after_store64_s64(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_store64(addrlo, datalo, 64, true, false, cpu);
}
/* unsigned post store */
static void helper_panda_after_store64_u8(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_store64(addrlo, datalo, 8, false, false, cpu);
}
static void helper_panda_after_store64_u16(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_store64(addrlo, datalo, 16, false, false, cpu);
}
static void helper_panda_after_store64_u32(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_store64(addrlo, datalo, 32, false, false, cpu);
}
static void helper_panda_after_store64_u64(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_store64(addrlo, datalo, 64, false, false, cpu);
}
/* signed pre store */
static void helper_panda_before_store64_s8(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_store64(addrlo, datalo, 8, true, true, cpu);
}
static void helper_panda_before_store64_s16(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_store64(addrlo, datalo, 16, true, true, cpu);
}
static void helper_panda_before_store64_s32(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_store64(addrlo, datalo, 32, true, true, cpu);
}
static void helper_panda_before_store64_s64(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_store64(addrlo, datalo, 64, true, true, cpu);
}
/* unsigned pre store */
static void helper_panda_before_store64_u8(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_store64(addrlo, datalo, 8, false, true, cpu);
}
static void helper_panda_before_store64_u16(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_store64(addrlo, datalo, 16, false, true, cpu);
}
static void helper_panda_before_store64_u32(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_store64(addrlo, datalo, 32, false, true, cpu);
}
static void helper_panda_before_store64_u64(uint64_t addrlo, uint64_t datalo, void* cpu)
{
    helper_panda_beforeafter_store64(addrlo, datalo, 64, false, true, cpu);
}
typedef void (*helper_panda_mmu_32_t)(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, void* cpu);
typedef void (*helper_panda_mmu_64_t)(uint64_t addrlo, uint64_t datalo, void* cpu);

helper_panda_mmu_32_t panda_beforeafter_load_32_fns[2][2][4] = {
    /* post load/store */
    {
        /* signed */
        {
            helper_panda_after_load32_s8,
            helper_panda_after_load32_s16,
            helper_panda_after_load32_s32,
            helper_panda_after_load32_s64
        },
        /* unsigned */
        {
            helper_panda_after_load32_u8,
            helper_panda_after_load32_u16,
            helper_panda_after_load32_u32,
            helper_panda_after_load32_u64
        }
    },
    /* pre load/store */
    {
        /* signed */
        {
            helper_panda_before_load32_s8,
            helper_panda_before_load32_s16,
            helper_panda_before_load32_s32,
            helper_panda_before_load32_s64
        },
        /* unsigned */
        {
            helper_panda_before_load32_u8,
            helper_panda_before_load32_u16,
            helper_panda_before_load32_u32,
            helper_panda_before_load32_u64
        }
    }
};

helper_panda_mmu_64_t panda_beforeafter_load_64_fns[2][2][4] = {
    /* post load/store */
    {
        /* signed */
        {
            helper_panda_after_load64_s8,
            helper_panda_after_load64_s16,
            helper_panda_after_load64_s32,
            helper_panda_after_load64_s64
        },
        /* unsigned */
        {
            helper_panda_after_load64_u8,
            helper_panda_after_load64_u16,
            helper_panda_after_load64_u32,
            helper_panda_after_load64_u64
        }
    },
    /* pre load/store */
    {
        /* signed */
        {
            helper_panda_before_load64_s8,
            helper_panda_before_load64_s16,
            helper_panda_before_load64_s32,
            helper_panda_before_load64_s64
        },
        /* unsigned */
        {
            helper_panda_before_load64_u8,
            helper_panda_before_load64_u16,
            helper_panda_before_load64_u32,
            helper_panda_before_load64_u64
        }
    }
};

helper_panda_mmu_32_t panda_beforeafter_store_32_fns[2][2][4] = {
    /* post load/store */
    {
        /* signed */
        {
            helper_panda_after_store32_s8,
            helper_panda_after_store32_s16,
            helper_panda_after_store32_s32,
            helper_panda_after_store32_s64
        },
        /* unsigned */
        {
            helper_panda_after_store32_u8,
            helper_panda_after_store32_u16,
            helper_panda_after_store32_u32,
            helper_panda_after_store32_u64
        }
    },
    /* pre load/store */
    {
        /* signed */
        {
            helper_panda_before_store32_s8,
            helper_panda_before_store32_s16,
            helper_panda_before_store32_s32,
            helper_panda_before_store32_s64
        },
        /* unsigned */
        {
            helper_panda_before_store32_u8,
            helper_panda_before_store32_u16,
            helper_panda_before_store32_u32,
            helper_panda_before_store32_u64
        }
    }
};

helper_panda_mmu_64_t panda_beforeafter_store_64_fns[2][2][4] = {
    /* post load/store */
    {
        /* signed */
        {
            helper_panda_after_store64_s8,
            helper_panda_after_store64_s16,
            helper_panda_after_store64_s32,
            helper_panda_after_store64_s64
        },
        /* unsigned */
        {
            helper_panda_after_store64_u8,
            helper_panda_after_store64_u16,
            helper_panda_after_store64_u32,
            helper_panda_after_store64_u64
        }
    },
    /* pre load/store */
    {
        /* signed */
        {
            helper_panda_before_store64_s8,
            helper_panda_before_store64_s16,
            helper_panda_before_store64_s32,
            helper_panda_before_store64_s64
        },
        /* unsigned */
        {
            helper_panda_before_store64_u8,
            helper_panda_before_store64_u16,
            helper_panda_before_store64_u32,
            helper_panda_before_store64_u64
        }
    }
};

static inline void _tcg_out_panda_callback_shared(TCGContext *s, TCGReg datalo, TCGReg datahi, TCGReg addrlo, TCGReg addrhi, TCGMemOpIdx oi, TCGMemOp opc, bool is64, bool isPre, bool skipData)
{
    if (TCG_TARGET_REG_BITS == 32) {
        /* push arguments onto stack */

        #ifdef PANDA_MMU_CALLBACK_CONST_ARGS
        tcg_out_sti(s, TCG_TYPE_I32, 0xdeadbeef, TCG_REG_ESP, 0);
        #else
        tcg_out_st(s, TCG_TYPE_I32, addrlo, TCG_REG_ESP, 0);
        #endif
        if (TARGET_LONG_BITS == 64) {
            #ifdef PANDA_MMU_CALLBACK_CONST_ARGS
            tcg_out_sti(s, TCG_TYPE_I32, 0xbaadf00d, TCG_REG_ESP, 4);
            #else
            tcg_out_st(s, TCG_TYPE_I32, addrhi, TCG_REG_ESP, 4);
            #endif
        }
        else {
            tcg_out_sti(s, TCG_TYPE_I32, 0, TCG_REG_ESP, 4);
        }

        #ifdef PANDA_MMU_CALLBACK_CONST_ARGS
        tcg_out_sti(s, TCG_TYPE_I32, 0xfeedfeed, TCG_REG_ESP, 8);
        #else
        if (skipData)
            tcg_out_sti(s, TCG_TYPE_I32, 0, TCG_REG_ESP, 8);
        else
            tcg_out_st(s, TCG_TYPE_I32, datalo, TCG_REG_ESP, 8);
        #endif
        if (is64) {
            #ifdef PANDA_MMU_CALLBACK_CONST_ARGS
            tcg_out_sti(s, TCG_TYPE_I32, 0xdead0bed, TCG_REG_ESP, 12);
            #else
            if (skipData)
                tcg_out_sti(s, TCG_TYPE_I32, 0, TCG_REG_ESP, 12);
            else
                tcg_out_st(s, TCG_TYPE_I32, datahi, TCG_REG_ESP, 12);
            #endif
        }
        else {
            tcg_out_sti(s, TCG_TYPE_I32, 0, TCG_REG_ESP, 12);
        }
        tcg_out_st(s, TCG_TYPE_PTR, TCG_AREG0, TCG_REG_ESP, 16);
    } else {
        /* put arguments in x64 call regs */
        #ifdef PANDA_MMU_CALLBACK_CONST_ARGS
        tcg_out_movi(s, TCG_TYPE_I64, tcg_target_call_iarg_regs[0], 0xbaadf00ddeadbeefL);
        tcg_out_movi(s, TCG_TYPE_I64, tcg_target_call_iarg_regs[1], 0xdead0bedfeedfeedL);
        #else
        tcg_out_mov(s, TCG_TYPE_I64, tcg_target_call_iarg_regs[0], addrlo);
        if (skipData)
            tcg_out_movi(s, TCG_TYPE_I64, tcg_target_call_iarg_regs[1], 0);
        else
            tcg_out_mov(s, TCG_TYPE_I64, tcg_target_call_iarg_regs[1], datalo);
        #endif
        tcg_out_mov(s, TCG_TYPE_I64, tcg_target_call_iarg_regs[2], TCG_AREG0);
    }
}

static void tcg_out_panda_callback_qemu_ld(TCGContext *s, const TCGArg *args, bool is64, bool isPre)
{
    TCGReg datalo, datahi, addrlo;
    TCGReg addrhi __attribute__((unused));
    TCGMemOpIdx oi;
    TCGMemOp opc;

    // datalo = datahi = addrlo = addrhi = 0;
    if (isPre)
    {
        datalo = 0;
        datahi = 0;
    }
    else
    {
        datalo = *args++;
        datahi = (TCG_TARGET_REG_BITS == 32 && is64 ? *args++ : 0);
    }
    addrlo = *args++;
    addrhi = (TARGET_LONG_BITS > TCG_TARGET_REG_BITS ? *args++ : 0);
    oi = *args++;
    opc = get_memop(oi);
    _tcg_out_panda_callback_shared(s, datalo, datahi, addrlo, addrhi, oi, opc, is64, isPre, isPre);
    if (TCG_TARGET_REG_BITS == 32)
    {
        tcg_out_call(s, (void*)panda_beforeafter_load_32_fns[isPre][!!(opc & MO_SIGN)][opc & MO_SIZE]);
    }
    else
    {
        tcg_out_call(s, (void*)panda_beforeafter_load_64_fns[isPre][!!(opc & MO_SIGN)][opc & MO_SIZE]);
    }
}

static void tcg_out_panda_callback_qemu_st(TCGContext *s, const TCGArg *args, bool is64, bool isPre)
{
    TCGReg datalo, datahi, addrlo;
    TCGReg addrhi __attribute__((unused));
    TCGMemOpIdx oi;
    TCGMemOp opc;

    // datalo = datahi = addrlo = addrhi = 0;
    datalo = *args++;
    datahi = (TCG_TARGET_REG_BITS == 32 && is64 ? *args++ : 0);
    addrlo = *args++;
    addrhi = (TARGET_LONG_BITS > TCG_TARGET_REG_BITS ? *args++ : 0);
    oi = *args++;
    opc = get_memop(oi);
    _tcg_out_panda_callback_shared(s, datalo, datahi, addrlo, addrhi, oi, opc, is64, isPre, false);
    if (TCG_TARGET_REG_BITS == 32)
    {
        tcg_out_call(s, (void*)panda_beforeafter_store_32_fns[isPre][!!(opc & MO_SIGN)][opc & MO_SIZE]);
    }
    else
    {
        tcg_out_call(s, (void*)panda_beforeafter_store_64_fns[isPre][!!(opc & MO_SIGN)][opc & MO_SIZE]);
    }
}
