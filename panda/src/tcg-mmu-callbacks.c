#include <stdint.h>
#include "qemu/osdep.h"
#include "cpu.h"
#include "panda/plugin.h"
#include "panda/callbacks/cb-support.h"
#include "panda/tcg-mmu-callbacks.h"
#include "panda/tcg-mmu-callbacks-regfind.h"
#include "panda/common.h"

#include "exec/cpu-common.h"

#include "tcg/tcg.h"
#include "tcg-op.h"

static void add_panda_mmu_callbacks(TCGContext* s, TCGOp* op, TCGOp* insert_point, TCGOpcode panda_mmu_opc, tcg_op_insert_fn insert_fn, bool skip_outputs, enum panda_gp_reg_enum target_reg)
{
    const TCGOpDef *old_def = &tcg_op_defs[op->opc];
    /* our new op should match the supplied op, except we provide the output argument as an input, and there's an additional constant argument */
    int num_args = ((skip_outputs) ? 0 : old_def->nb_oargs) + old_def->nb_iargs + old_def->nb_cargs + 1;
    TCGOp* new_op = insert_fn(s, insert_point, panda_mmu_opc, num_args);
    const TCGOpDef* new_def = &tcg_op_defs[new_op->opc];

    assert(new_def->nb_oargs == 0);
    assert(new_def->nb_iargs == (skip_outputs) ? old_def->nb_iargs : old_def->nb_iargs + old_def->nb_oargs);
    assert(new_def->nb_cargs == old_def->nb_cargs + 1);

    new_op->calli = (skip_outputs) ? op->calli : op->calli + op->callo;
    new_op->callo = 0;
    new_op->life = op->life;

    TCGArg *new_args = &s->gen_opparam_buf[new_op->args];
    const TCGArg *old_args = &s->gen_opparam_buf[op->args];
    if (skip_outputs)
    {
        for (int i = old_def->nb_oargs; i < old_def->nb_oargs + old_def->nb_iargs + old_def->nb_cargs; ++i)
            new_args[i - old_def->nb_oargs] = old_args[i];
    }
    else
    {
        assert(new_def->nb_iargs + new_def->nb_cargs == old_def->nb_oargs + old_def->nb_iargs + old_def->nb_cargs + 1);
        for (int i = 0; i < num_args; ++i)
            new_args[i] = old_args[i];
    }
    /* We add the target register as a carg */
    new_args[new_def->nb_oargs + new_def->nb_iargs + new_def->nb_cargs - 1] = target_reg;
}

static TCGOp* find_insn_start(TCGContext* s, int oi)
{
    int oi_prev;
    for (; oi != 0; oi = oi_prev)
    {
        TCGOp* op = &s->gen_op_buf[oi];
        oi_prev = op->prev;
        if (op->opc == INDEX_op_insn_start)
            return op;
    }
    /* the start of the TB doesn't have INDEX_op_insn_start */
    return &s->gen_op_buf[s->gen_op_buf[0].next];
}
static TCGOp* find_insn_end(TCGContext* s, int oi)
{
    TCGOp* rv = &s->gen_op_buf[oi];
    /* if we were passed an isn_start op, we need to skip it for simpler loop termination*/
    if (rv->opc == INDEX_op_insn_start)
        oi = rv->next;
    while (oi != 0)
    {
        TCGOp* op = &s->gen_op_buf[oi];
        if (op->opc == INDEX_op_insn_start)
            return rv;
        rv = op;
        oi = op->next;
    }
    /* we didn't find an instruction start, so the end of the TB is the end of the instruction */
    return rv;
}

static __attribute__((unused)) TCGOp* find_last_valid_insn(TCGContext* s, const TCGOp* start, const TCGOp* end, const TCGArg* required_regs, size_t num_required_regs)
{
	int oi = start - &s->gen_op_buf[0];
	assert(oi >= 0 && oi < OPC_BUF_SIZE);
	TCGOp* last = NULL;

	while (oi != 0)
	{
		TCGOp* op = &s->gen_op_buf[oi]; /* we need to return a non-const pointer, but we're not going to change it ourselves... this could alias start/end which are const, unsure of implications of that */
		const TCGOpDef* def = &tcg_op_defs[op->opc];

		if (def->flags & TCG_OPF_BB_END)
			break;

		switch (op->opc)
		{
			case INDEX_op_set_label:
				return last;
			default:
				break;
		}

		last = op;
		oi = op->next;
		if (op == end)
			break;
	}

	return last;
}

void panda_tcg_pass(TCGContext* s, TranslationBlock* tb)
{
    int oi, oi_next;
    char reg_name[32];

    for (oi = s->gen_op_buf[0].next; oi != 0; oi = oi_next)
    {
        TCGOp* op = &s->gen_op_buf[oi];
        #ifdef PANDA_DEBUG_LOG_MMU_CBS
        const TCGOpDef *def = &tcg_op_defs[op->opc];
        #endif
        oi_next = op->next;

        switch (op->opc)
        {
            case INDEX_op_qemu_ld_i32: {
                enum panda_gp_reg_enum target_reg;
                TCGOp* target_reg_op = NULL;
                #ifdef PANDA_DEBUG_LOG_MMU_CBS
                qemu_log_lock();
                qemu_log("Adding panda_(before/after)_mmu_ld_i32 (%d/%d) to qemu_ld_i32 (%d) num_args = %d :: %d\n",
                        INDEX_op_panda_before_mmu_ld_i32,
                        INDEX_op_panda_after_mmu_ld_i32,
                        op->opc,
                        (int)def->nb_iargs + def->nb_oargs + def->nb_cargs,
                        (int)def->nb_iargs + def->nb_cargs);
                qemu_log_unlock();
                #endif
                /*
                	Idea:
                		for load operations, we identify the target register by scanning from the qemu_ld TCG op until the
                		end of the target instruction translation and identifying any mov from the target register of
                		the load (and any new targets found along the way). We search that set for any register which
                		we know to be a target (as in guest hardware) register.
                		The load should logically be completed after whatever TCG op moves into that register, so
                		we can insert out after_load callback there (which should cause all globals to be synced).
                */
                target_reg = panda_find_target_reg(s, (&s->gen_opparam_buf[op->args])[0] /* 0 is output of load */, op, find_insn_end(s, oi), reg_name, sizeof(reg_name), &target_reg_op);
                add_panda_mmu_callbacks(s, op, op, INDEX_op_panda_before_mmu_ld_i32, tcg_op_insert_before, true, target_reg);
                add_panda_mmu_callbacks(s, op, (target_reg_op) ? target_reg_op : op, INDEX_op_panda_after_mmu_ld_i32, tcg_op_insert_after, false, target_reg);
                break;
            }
            case INDEX_op_qemu_st_i32: {
            	enum panda_gp_reg_enum target_reg;
                #ifdef PANDA_DEBUG_LOG_MMU_CBS
                qemu_log_lock();
                qemu_log("Adding panda_(before/after)_mmu_st_i32 (%d/%d) to qemu_st_i32 (%d) num_args = %d :: %d\n",
                        INDEX_op_panda_before_mmu_st_i32,
                        INDEX_op_panda_after_mmu_st_i32,
                        op->opc,
                        (int)def->nb_iargs + def->nb_oargs + def->nb_cargs,
                        (int)def->nb_iargs + def->nb_cargs);
                qemu_log_unlock();
                #endif
                /*
                	Idea:
                		for store operations, we identify the source register by scanning backwards from the qemu_st
                		TCG op until the start of the target instruction translation and identifying any mov to the
                		source register of the store (and any new targets found along the way). We search that set for
                		any register which we know to be a target (as in guest hardware) register.
                		The store should logically be completed after the qemu_st.
                */
                target_reg = panda_find_source_reg(s, (&s->gen_opparam_buf[op->args])[0] /* 0 is source of store */, find_insn_start(s, oi), op, reg_name, sizeof(reg_name), NULL);
                add_panda_mmu_callbacks(s, op, op, INDEX_op_panda_before_mmu_st_i32, tcg_op_insert_before, false, target_reg);
                add_panda_mmu_callbacks(s, op, op, INDEX_op_panda_after_mmu_st_i32, tcg_op_insert_after, false, target_reg);
                break;
            }
            case INDEX_op_qemu_ld_i64: {
                enum panda_gp_reg_enum target_reg;
                TCGOp* target_reg_op = NULL;
                #ifdef PANDA_DEBUG_LOG_MMU_CBS
                qemu_log_lock();
                qemu_log("Adding panda_(before/after)_mmu_ld_i64 (%d/%d) to qemu_ld_i64 (%d) num_args = %d :: %d\n",
                        INDEX_op_panda_before_mmu_ld_i64,
                        INDEX_op_panda_after_mmu_ld_i64,
                        op->opc,
                        (int)def->nb_iargs + def->nb_oargs + def->nb_cargs,
                        (int)def->nb_iargs + def->nb_cargs);
                qemu_log_unlock();
                #endif
                target_reg = panda_find_target_reg(s, (&s->gen_opparam_buf[op->args])[0] /* 0 is output of load */, op, find_insn_end(s, oi), reg_name, sizeof(reg_name), &target_reg_op);
                add_panda_mmu_callbacks(s, op, op, INDEX_op_panda_before_mmu_ld_i64, tcg_op_insert_before, true, target_reg);
                add_panda_mmu_callbacks(s, op, (target_reg_op) ? target_reg_op : op, INDEX_op_panda_after_mmu_ld_i64, tcg_op_insert_after, false, target_reg);
                break;
            }
            case INDEX_op_qemu_st_i64: {
            	enum panda_gp_reg_enum target_reg;
                #ifdef PANDA_DEBUG_LOG_MMU_CBS
                qemu_log_lock();
                qemu_log("Adding panda_(before/after)_mmu_st_i64 (%d/%d) to qemu_st_i64 (%d) num_args = %d :: %d\n",
                        INDEX_op_panda_before_mmu_st_i64,
                        INDEX_op_panda_after_mmu_st_i64,
                        op->opc,
                        (int)def->nb_iargs + def->nb_oargs + def->nb_cargs,
                        (int)def->nb_iargs + def->nb_cargs);
                qemu_log_unlock();
                #endif
                target_reg = panda_find_source_reg(s, (&s->gen_opparam_buf[op->args])[0] /* 0 is source of store */, find_insn_start(s, oi), op, reg_name, sizeof(reg_name), NULL);
                add_panda_mmu_callbacks(s, op, op, INDEX_op_panda_before_mmu_st_i64, tcg_op_insert_before, false, target_reg);
                add_panda_mmu_callbacks(s, op, op, INDEX_op_panda_after_mmu_st_i64, tcg_op_insert_after, false, target_reg);
                break;
            }
            default:
                break;
        }
    }
}
