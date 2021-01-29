#ifndef _TCG_MMU_CALLBACKS_REGFIND_H
#define _TCG_MMU_CALLBACKS_REGFIND_H

#include <stdint.h>
#include <stdlib.h>
#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/cpu-common.h"
#include "tcg/tcg.h"

#if defined(TARGET_I386) || defined(TARGET_X86_64)
#include "panda/tcg-mmu-callbacks-regfind-i386.h"
#else
/* unsupported arch */
enum panda_gp_reg_enum {
    PANDA_GP_REG_IMMEDIATE,
    PANDA_GP_REG_NAMES_COUNT,
    PANDA_GP_REG_INVALID = (int32_t)-1
};

static inline enum panda_gp_reg_enum gp_reg_idx_by_name(const char* reg)
{
    return PANDA_GP_REG_INVALID;
}
static inline enum panda_gp_reg_enum gp_reg_idx_by_offset(size_t off)
{
    return PANDA_GP_REG_INVALID;
}

static const char* const PANDA_GP_REG_NAMES[PANDA_GP_REG_NAMES_COUNT] = {
    "IMMEDIATE",
};
#endif

enum panda_gp_reg_enum panda_find_target_reg(TCGContext* s, TCGArg initial_source, TCGOp* first, TCGOp* last, char* reg_name, size_t reg_name_size, TCGOp** trigger_op);
enum panda_gp_reg_enum panda_find_source_reg(TCGContext* s, TCGArg initial_source, TCGOp* first, TCGOp* last, char* reg_name, size_t reg_name_size, TCGOp** trigger_op);

#endif
