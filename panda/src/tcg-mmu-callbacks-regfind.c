#include <stdint.h>
#include "qemu/osdep.h"
#include "cpu.h"
#include "panda/plugin.h"
#include "panda/callbacks/cb-support.h"
#include "panda/tcg-mmu-callbacks.h"
#include "panda/tcg-mmu-callbacks-regfind.h"
#include "panda/common.h"

#include "exec/cpu-common.h"

#ifndef DEBUG_TCG_MMU_CALLBACKS
#define DEBUG_TCG_MMU_CALLBACKS 0
#endif

#if DEBUG_TCG_MMU_CALLBACKS

#define _DEBUG_PRINT_FN(level, msg, ...)(fprintf(stderr, msg, ##__VA_ARGS__))

#define _DEBUG_PRINT(level, msg, ...) do { \
    _DEBUG_PRINT_FN(level, "[%s:%d] " msg, __FUNCTION__, __LINE__, ##__VA_ARGS__) \
} while (0)
#define DEBUG_PRINT(level, msg, ...)(_DEBUG_PRINT(level, msg "\n", ##__VA_ARGS__))
#define DEBUG_PRINT_Start(level, msg, ...)(_DEBUG_PRINT(level, msg, ##__VA_ARGS__))
#define DEBUG_PRINT_Continue(level, msg, ...)(_DEBUG_PRINT_FN(level, msg, ##__VA_ARGS__))
#define DEBUG_PRINT_End(level, msg, ...)(_DEBUG_PRINT_FN(level, msg "\n", ##__VA_ARGS__))

#define PANDA_DEBUG_PRINT_HEX_SYMBOLS ("0123456789abcdef")

#define DEBUG_DUMP_HEX(level, prefix, data, data_len) ({ \
    /* Capture the parameters here to avoid multiple evaluations */ \
    const unsigned char * const __panda_debug_dump_hex_data = (const unsigned char *)(data); \
    const size_t __panda_debug_dump_hex_data_len = (data_len); \
    int __panda_debug_dump_hex_iterator; \
    DEBUG_PRINT_Start(level, "%s", (prefix)); \
    for (__panda_debug_dump_hex_iterator = 0; __panda_debug_dump_hex_iterator < __panda_debug_dump_hex_data_len; ++__panda_debug_dump_hex_iterator) \
        DEBUG_PRINT_Continue(level, "%c%c", \
            PANDA_DEBUG_PRINT_HEX_SYMBOLS[(__panda_debug_dump_hex_data[__panda_debug_dump_hex_iterator] & 0xf0) >> 4], \
            PANDA_DEBUG_PRINT_HEX_SYMBOLS[(__panda_debug_dump_hex_data[__panda_debug_dump_hex_iterator] & 0x0f)] \
        ); \
    DEBUG_PRINT_End(level, ""); \
})

#else
#define DEBUG_PRINT(level, msg, ...) ((void)0)
#define DEBUG_PRINT_Start(level, msg, ...) ((void)0)
#define DEBUG_PRINT_Continue(level, msg, ...) ((void)0)
#define DEBUG_PRINT_End(level, msg, ...) ((void)0)
#define DEBUG_DUMP_HEX(level, prefix, data, data_len) ((void)0)
#endif

static void pstrcpy(char *buf, int buf_size, const char *str)
{
    int c;
    char *q = buf;

    if (buf_size <= 0)
        return;

    for(;;) {
        c = *str++;
        if (c == 0 || q >= buf + buf_size - 1)
            break;
        *q++ = c;
    }
    *q = '\0';
}
static inline int temp_idx(TCGContext *s, TCGTemp *ts)
{
    ptrdiff_t n = ts - s->temps;
    tcg_debug_assert(n >= 0 && n < s->nb_temps);
    return n;
}
static char *tcg_get_arg_str_ptr(TCGContext *s, char *buf, int buf_size,
                                 TCGTemp *ts)
{
    int idx = temp_idx(s, ts);

    if (idx < s->nb_globals) {
        pstrcpy(buf, buf_size, ts->name);
    } else if (ts->temp_local) {
        snprintf(buf, buf_size, "loc%d", idx - s->nb_globals);
    } else {
        snprintf(buf, buf_size, "tmp%d", idx - s->nb_globals);
    }
    return buf;
}

static char *tcg_get_arg_str_idx(TCGContext *s, char *buf,
                                 int buf_size, int idx)
{
    tcg_debug_assert(idx >= 0 && idx < s->nb_temps);
    return tcg_get_arg_str_ptr(s, buf, buf_size, &s->temps[idx]);
}

/* REQUIRES: 1 output argument, 1 input argument, out <- in */
static bool is_move(const TCGOp* op)
{
    switch (op->opc)
    {
        /* Mov Ops */
        /* case INDEX_op_movi_i32: this can only move immediates, we only care about registers */
        case INDEX_op_mov_i32:
        #if TCG_TARGET_REG_BITS == 64
        /* case INDEX_op_movi_i64: this can only move immediates, we only care about registers */
        case INDEX_op_mov_i64:
        #endif

        /*
            Sign Extend Ops:
                these are basically just movs with optional
                sign extension. For now it doesn't seem that
                we have to care about the extension since we're
                just looking for the final register.
        */
        case INDEX_op_ext8s_i32:
        case INDEX_op_ext8u_i32:
        case INDEX_op_ext16s_i32:
        case INDEX_op_ext16u_i32:
        case INDEX_op_extu_i32_i64:
        #if TCG_TARGET_REG_BITS == 64
        case INDEX_op_ext8s_i64:
        case INDEX_op_ext8u_i64:
        case INDEX_op_ext16s_i64:
        case INDEX_op_ext16u_i64:
        case INDEX_op_ext32s_i64:
        case INDEX_op_ext32u_i64:
        #endif
            return true;
        default:
            return false;
    }
}
/* REQUIRES: 1 output argument, 1 constant argument, out <- const */
static bool is_immediate_move(const TCGOp* op)
{
    switch (op->opc)
    {
        case INDEX_op_movi_i32:
        #if TCG_TARGET_REG_BITS == 64
        case INDEX_op_movi_i64:
        #endif
            return true;
        default:
            return false;
    }
}

enum panda_gp_reg_enum panda_find_target_reg(TCGContext* s, TCGArg initial_source, TCGOp* first, TCGOp* last, char* reg_name, size_t reg_name_size, TCGOp** trigger_op)
{
    static struct
    {
        TCGOp* op;
        TCGArg arg;
    } valid_sources[64];
    size_t nvalid = 1;

    valid_sources[0].op = NULL;
    valid_sources[0].arg = initial_source;

    for (TCGOp* opi = first; /* opi != last */; opi = &s->gen_op_buf[opi->next])
    {
        const TCGOpDef* defi = &tcg_op_defs[opi->opc];
        if (is_move(opi))
        {
            /* all our move instructions should have a single output argument and single input argument */
            assert(defi->nb_iargs == 1 && defi->nb_oargs == 1);
            TCGArg dst = (&s->gen_opparam_buf[opi->args])[0]; /* 0 is the first output argument */
            TCGArg src = (&s->gen_opparam_buf[opi->args])[defi->nb_oargs]; /* after output argument, input arguments -- this should be == 1 */
            /*
                if the source is one of the registers we've seen
                the load go through, then the destination is now
                a valid source
            */
            for (size_t i = 0; i < nvalid; ++i)
            {
                if (src == valid_sources[i].arg)
                {
                    /* make sure dst isn't already a source */
                    bool exists = false;
                    for (size_t j = 0; j < nvalid; ++j)
                    {
                        if (valid_sources[j].arg == dst)
                        {
                            exists = true;
                            valid_sources[j].op = opi;
                            /*break;*/
                        }
                    }
                    if (!exists)
                    {
                        if (nvalid >= sizeof(valid_sources)/sizeof(valid_sources[0]))
                        {
                            DEBUG_PRINT(SEVERE, "Unable to track mov, too many valid sources (%d)", (int)nvalid);
                            break;
                        }
                        valid_sources[nvalid].op = opi;
                        valid_sources[nvalid].arg = dst;
                        ++nvalid;
                        /* no need to continue looking, dst is now a valid source */
                        break;
                    }
                }
            }
        }
        else
        {
            switch (opi->opc)
            {
                /*
                    There are a few ops that function like moves into environment offsets...
                    We're going to try to use the env offset to determine a register target
                */
                case INDEX_op_st_i32:
                case INDEX_op_st_i64:
                    {
                        /* i.e. st_i64 tmp0,env,$0x80 */
                        assert(defi->nb_oargs == 0 && defi->nb_iargs == 2 && defi->nb_cargs == 1);
                        TCGArg src = (&s->gen_opparam_buf[opi->args])[defi->nb_oargs]; /* after output arguments, input arguments -- this should be == 0 */
                        TCGArg dst = (&s->gen_opparam_buf[opi->args])[defi->nb_oargs + 1]; /* after output arguments, input arguments -- this should be == 1 */
                        size_t dst_offset = (&s->gen_opparam_buf[opi->args])[defi->nb_oargs + defi->nb_iargs]; /* after intput arguments, const? arguments -- this should be == 2 */
                        reg_name[0] = 0;
                        tcg_get_arg_str_idx(s, reg_name, reg_name_size, dst);
                        if (!strcmp("env", reg_name))
                        {
                            /*
                                if the source is one of the registers we've seen
                                the load go through, then the destination is now
                                a valid source.
                            */
                            for (size_t i = 0; i < nvalid; ++i)
                            {
                                if (src == valid_sources[i].arg)
                                {
                                    enum panda_gp_reg_enum special_dst = gp_reg_idx_by_offset(dst_offset);
                                    if (special_dst < 0)
                                        break;
                                    /* no point in continuing, this is the value we'll return */
                                    DEBUG_PRINT(VERBOSE, "Found target Special reg: %s [%d]", PANDA_GP_REG_NAMES[special_dst], (int)special_dst);
                                    if (trigger_op)
                                        *trigger_op = opi;
                                    return special_dst;
                                }
                            }
                        }
                    }
                    break;
                default:
                    break;
            }
        }
        if (opi == last)
            break;
    }
    for (size_t i = 0; i < nvalid; ++i)
    {
        enum panda_gp_reg_enum target_reg;
        reg_name[0] = 0;
        tcg_get_arg_str_idx(s, reg_name, reg_name_size, valid_sources[i].arg);
        if (reg_name[0] == 0)
        {
            DEBUG_PRINT(WARNING, "Failed to identify register for %d", (int)valid_sources[i].arg);
            continue;
        }
        if ((target_reg = gp_reg_idx_by_name(reg_name)) >= 0)
        {
            DEBUG_PRINT(VERBOSE, "Found target GP reg: %s (%d -> %s [%d])", reg_name, (int)valid_sources[i].arg, PANDA_GP_REG_NAMES[target_reg], (int)target_reg);
            if (trigger_op)
                *trigger_op = valid_sources[i].op;
            return target_reg;
        }
    }
    if (trigger_op)
        *trigger_op = NULL;
    return PANDA_GP_REG_INVALID;
}

enum panda_gp_reg_enum panda_find_source_reg(TCGContext* s, TCGArg initial_source, TCGOp* first, TCGOp* last, char* reg_name, size_t reg_name_size, TCGOp** trigger_op)
{
    static struct
    {
        TCGOp* op;
        TCGArg arg;
    } valid_sources[64];
    size_t nvalid = 1;
    int instrs_scanned = 0;

    valid_sources[0].op = NULL;
    valid_sources[0].arg = initial_source;

    for (TCGOp* opi = last; /* opi != first */; opi = &s->gen_op_buf[opi->prev])
    {
        ++instrs_scanned;
        const TCGOpDef* defi = &tcg_op_defs[opi->opc];
        if (is_move(opi))
        {
            /* all our move instructions should have a single output argument and single input argument */
            assert(defi->nb_iargs == 1 && defi->nb_oargs == 1);
            TCGArg dst = (&s->gen_opparam_buf[opi->args])[0]; /* 0 is the first output argument */
            TCGArg src = (&s->gen_opparam_buf[opi->args])[defi->nb_oargs]; /* after output argument, input arguments -- this should be == 1 */
            /*
                if the source is one of the registers we've seen
                the load go through, then the destination is now
                a valid source
            */
            for (size_t i = 0; i < nvalid; ++i)
            {
                if (dst == valid_sources[i].arg)
                {
                    /* make sure src isn't already a source */
                    bool exists = false;
                    for (size_t j = 0; j < nvalid; ++j)
                    {
                        if (valid_sources[j].arg == src)
                        {
                            exists = true;
                            valid_sources[j].op = opi;
                            /*break;*/
                        }
                    }
                    if (!exists)
                    {
                        if (nvalid >= sizeof(valid_sources)/sizeof(valid_sources[0]))
                        {
                            DEBUG_PRINT(SEVERE, "Unable to track mov, too many valid sources (%d)", (int)nvalid);
                            break;
                        }
                        valid_sources[nvalid].op = opi;
                        valid_sources[nvalid].arg = src;
                        ++nvalid;
                        /* no need to continue looking, src is now a valid source */
                        break;
                    }
                }
            }
        }
        else
        {
            switch (opi->opc)
            {
                /*
                    There are a few ops that function like moves into environment offsets...
                    We're going to try to use the env offset to determine a register target
                */
                case INDEX_op_ld_i32:
                case INDEX_op_ld_i64:
                    {
                        /* i.e. ld_i64 tmp0,env,$0x80 */
                        assert(defi->nb_oargs == 1 && defi->nb_iargs == 1 && defi->nb_cargs == 1);
                        TCGArg dst = (&s->gen_opparam_buf[opi->args])[0]; /* after output arguments, input arguments -- this should be == 0 */
                        TCGArg src = (&s->gen_opparam_buf[opi->args])[defi->nb_oargs]; /* after output arguments, input arguments -- this should be == 1 */
                        size_t src_offset = (&s->gen_opparam_buf[opi->args])[defi->nb_oargs + defi->nb_iargs]; /* after intput arguments, const? arguments -- this should be == 2 */
                        reg_name[0] = 0;
                        tcg_get_arg_str_idx(s, reg_name, reg_name_size, src);
                        if (!strcmp("env", reg_name))
                        {
                            /*
                                if the source is one of the registers we've seen
                                the load go through, then the destination is now
                                a valid source.
                            */
                            for (size_t i = 0; i < nvalid; ++i)
                            {
                                if (dst == valid_sources[i].arg)
                                {
                                    enum panda_gp_reg_enum special_src = gp_reg_idx_by_offset(src_offset);
                                    if (special_src < 0)
                                        break;
                                    /* no point in continuing, this is the value we'll return */
                                    DEBUG_PRINT(VERBOSE, "Found target Special reg: %s [%d]", PANDA_GP_REG_NAMES[special_src], (int)special_src);
                                    if (trigger_op)
                                        *trigger_op = opi;
                                    return special_src;
                                }
                            }
                        }
                    }
                    break;
                default:
                    break;
            }
        }
        if (opi == first)
            break;
    }
    for (size_t i = 0; i < nvalid; ++i)
    {
        enum panda_gp_reg_enum target_reg;
        reg_name[0] = 0;
        tcg_get_arg_str_idx(s, reg_name, reg_name_size, valid_sources[i].arg);
        if (reg_name[0] == 0)
        {
            DEBUG_PRINT(WARNING, "Failed to identify register for %d", (int)valid_sources[i].arg);
            continue;
        }
        if ((target_reg = gp_reg_idx_by_name(reg_name)) >= 0)
        {
            DEBUG_PRINT(VERBOSE, "Found target GP reg: %s (%d -> %s [%d])", reg_name, (int)valid_sources[i].arg, PANDA_GP_REG_NAMES[target_reg], (int)target_reg);
            if (trigger_op)
                *trigger_op = valid_sources[i].op;
            return target_reg;
        }
    }

    /*
        We've failed to find a source...
        Scan through the instructions and see if one of our
        sources recieved an immediate.
    */
    for (TCGOp* opi = last; /* opi != first */; opi = &s->gen_op_buf[opi->prev])
    {
        const TCGOpDef* defi = &tcg_op_defs[opi->opc];
        if (is_immediate_move(opi))
        {
            /* all our immediate move instructions should have a single outputa rgument and a single constant argument */
            assert(defi->nb_cargs == 1 && defi->nb_oargs == 1);
            TCGArg dst = (&s->gen_opparam_buf[opi->args])[0]; /* 0 is the first output argument */

            for (size_t i = 0; i < nvalid; ++i)
            {
                if (dst == valid_sources[i].arg)
                {
                    if (trigger_op)
                        *trigger_op = valid_sources[i].op;
                    return PANDA_GP_REG_IMMEDIATE;
                }
            }
        }
        if (opi == first)
            break;
    }

    DEBUG_PRINT(WARNING, "Failed to identify reg in %d valid after %d instructions", (int)nvalid, instrs_scanned);
    if (trigger_op)
        *trigger_op = NULL;
    return PANDA_GP_REG_INVALID;
}
