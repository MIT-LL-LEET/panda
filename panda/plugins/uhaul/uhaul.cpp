/* PANDABEGINCOMMENT
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory.    
 * 
 PANDAENDCOMMENT */

// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <unordered_set>
#include <cstdlib>
#include <string>

#include "panda/plugin.h"

#include <cstdio>

extern "C" {
bool init_plugin(void*);
void uninit_plugin(void*);

void panda_uhaul_disas(FILE* out, CPUState* env, target_ulong pc, int nb_insn);

static void before_load(CPUState* env, uint64_t addr, uint64_t data, size_t width, bool isSigned, enum panda_gp_reg_enum target_reg);
static void after_load(CPUState* env, uint64_t addr, uint64_t data, size_t width, bool isSigned, enum panda_gp_reg_enum target_reg);
static void before_store(CPUState* env, uint64_t addr, uint64_t data, size_t width, bool isSigned, enum panda_gp_reg_enum target_reg);
static void after_store(CPUState* env, uint64_t addr, uint64_t data, size_t width, bool isSigned, enum panda_gp_reg_enum target_reg);
static int insn_exec(CPUState *env, target_ptr_t pc);
}

static const char* OutputFileName;
static FILE* OutputFile;
static __attribute__((unused)) bool bDumpCPU = false;

static inline bool in_kernelspace(CPUState* cpu)
{
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
#if defined(TARGET_I386)
    return ((env->hflags & HF_CPL_MASK) == 0);
#elif defined(TARGET_ARM)
    return ((env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_SVC);
#else
    (void)env;
    return false;
#endif
}

const char* target_reg_name(enum panda_gp_reg_enum target_reg)
{
    if (target_reg == PANDA_GP_REG_INVALID)
        return "<Unknown>";
    if (target_reg < 0 || target_reg >= PANDA_GP_REG_NAMES_COUNT)
        return "<Illegal>";
    return PANDA_GP_REG_NAMES[target_reg];
}

static void dump_ldstr_info(const char* time, const char* op, FILE* OutputFile, CPUState* env, uint64_t addr, uint64_t data, size_t width, bool isSigned, enum panda_gp_reg_enum target_reg)
{
    uint64_t cpu_pc = 0;
    #if defined(TARGET_I386)
    cpu_pc = ((CPUArchState*)env->env_ptr)->eip;
    #endif
    fprintf(OutputFile, "%6s %2d bit %8s %5s on CPU %p: IP %#18" PRIx64 " PIP %#18" PRIx64 " Addr %#18" PRIx64 " Data %#18" PRIx64 " Target: %s\n", time, (int)width, (isSigned) ? "signed": "unsigned", op, env, cpu_pc, env->panda_guest_pc, addr, data, target_reg_name(target_reg));
    fprintf(OutputFile, "\t");
    panda_uhaul_disas(OutputFile, env, env->panda_guest_pc, 1);
    fprintf(OutputFile, "\n");
    #if defined(TARGET_I386)
    if (bDumpCPU)
        x86_cpu_dump_state(env, OutputFile, fprintf, 0);
    #endif
}
static void before_load(CPUState* env, uint64_t addr, uint64_t data, size_t width, bool isSigned, enum panda_gp_reg_enum target_reg)
{
    if (in_kernelspace(env))
        return;
    dump_ldstr_info("Before", "Load", OutputFile, env, addr, data, width, isSigned, target_reg);
}
static void after_load(CPUState* env, uint64_t addr, uint64_t data, size_t width, bool isSigned, enum panda_gp_reg_enum target_reg)
{
    if (in_kernelspace(env))
        return;
    dump_ldstr_info("After", "Load", OutputFile, env, addr, data, width, isSigned, target_reg);
}
static void before_store(CPUState* env, uint64_t addr, uint64_t data, size_t width, bool isSigned, enum panda_gp_reg_enum target_reg)
{
    if (in_kernelspace(env))
        return;
    dump_ldstr_info("Before", "Store", OutputFile, env, addr, data, width, isSigned, target_reg);
}
static void after_store(CPUState* env, uint64_t addr, uint64_t data, size_t width, bool isSigned, enum panda_gp_reg_enum target_reg)
{
    if (in_kernelspace(env))
        return;
    dump_ldstr_info("After", "Store", OutputFile, env, addr, data, width, isSigned, target_reg);
}

__attribute__((unused))
static int insn_exec(CPUState *env, target_ptr_t pc)
{
    return 0;
}

bool init_plugin(void* self)
{
    panda_cb pcb;
    panda_arg_list* args;

    if ((args = panda_get_args("uhaul")) == nullptr)
    {
        LOG_ERROR("Unable to get arguments!");
        return false;
    }

    if ((OutputFileName = panda_parse_string_opt(args, "output", nullptr, "File in which output should be stored (the contents will be erased).")) == nullptr)
    {
        OutputFileName = "uhaul.txt";
    }
    
    bDumpCPU = panda_parse_bool_opt(args, "dumpcpu", "If provided, dump the CPU state on each callback.");

    if ((OutputFile = fopen(OutputFileName, "w")) == nullptr)
    {
        LOG_ERROR("Unable to open output file!");
        return false;
    }

    // panda_enable_precise_pc();

    pcb.before_load = before_load;
    panda_register_callback(self, PANDA_CB_BEFORE_LOAD, pcb);
    pcb.after_load = after_load;
    panda_register_callback(self, PANDA_CB_AFTER_LOAD, pcb);
    pcb.before_store = before_store;
    panda_register_callback(self, PANDA_CB_BEFORE_STORE, pcb);
    pcb.after_store = after_store;
    panda_register_callback(self, PANDA_CB_AFTER_STORE, pcb);

/*    pcb.insn_exec = insn_exec;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);*/

    return true;
}

void uninit_plugin(void* self)
{
}

