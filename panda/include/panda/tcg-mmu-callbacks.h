#ifndef _TCG_MMU_CALLBACKS_H
#define _TCG_MMU_CALLBACKS_H

/*#include "tcg/tcg.h"
#include "tcg-op.h"*/

// #define PANDA_DEBUG_LOG_MMU_CBS

typedef TCGOp* (*tcg_op_insert_fn)(TCGContext *s, TCGOp *op, TCGOpcode opc, int narg);

void panda_tcg_pass(TCGContext* s, TranslationBlock* tb);

#endif
