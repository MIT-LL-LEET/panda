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

static void panda_cb_before_load(CPUState* env, uint64_t addr, uint64_t data, size_t width, bool isSigned);
static void panda_cb_after_load(CPUState* env, uint64_t addr, uint64_t data, size_t width, bool isSigned);
static void panda_cb_before_store(CPUState* env, uint64_t addr, uint64_t data, size_t width, bool isSigned);
static void panda_cb_after_store(CPUState* env, uint64_t addr, uint64_t data, size_t width, bool isSigned);
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

static void panda_cb_before_load(CPUState* env, uint64_t addr, uint64_t data, size_t width, bool isSigned)
{
    uint64_t cpu_pc = 0;
    #if defined(TARGET_I386)
    cpu_pc = ((CPUArchState*)env->env_ptr)->eip;
    #endif
    if (in_kernelspace(env))
        return;
    fprintf(OutputFile, "Before %2d bit %8s  Load on CPU %p: IP %#18" PRIx64 " Addr %#18" PRIx64 "\n", (int)width, (isSigned) ? "signed": "unsigned", env, cpu_pc, addr);
    #if defined(TARGET_I386)
    if (bDumpCPU)
        x86_cpu_dump_state(env, OutputFile, fprintf, 0);
    #endif
}
static void panda_cb_after_load(CPUState* env, uint64_t addr, uint64_t data, size_t width, bool isSigned)
{
    uint64_t cpu_pc = 0;
    #if defined(TARGET_I386)
    cpu_pc = ((CPUArchState*)env->env_ptr)->eip;
    #endif
    if (in_kernelspace(env))
        return;
    fprintf(OutputFile, " After %2d bit %8s  Load on CPU %p: IP %#18" PRIx64 " Addr %#18" PRIx64 " Data %#18" PRIx64 "\n", (int)width, (isSigned) ? "signed": "unsigned", env, cpu_pc, addr, data);
    #if defined(TARGET_I386)
    if (bDumpCPU)
        x86_cpu_dump_state(env, OutputFile, fprintf, 0);
    #endif
}
static void panda_cb_before_store(CPUState* env, uint64_t addr, uint64_t data, size_t width, bool isSigned)
{
    uint64_t cpu_pc = 0;
    #if defined(TARGET_I386)
    cpu_pc = ((CPUArchState*)env->env_ptr)->eip;
    #endif
    if (in_kernelspace(env))
        return;
    fprintf(OutputFile, "Before %2d bit %8s Store on CPU %p: IP %#18" PRIx64 " Addr %#18" PRIx64 " Data %#18" PRIx64 "\n", (int)width, (isSigned) ? "signed": "unsigned", env, cpu_pc, addr, data);
    #if defined(TARGET_I386)
    if (bDumpCPU)
        x86_cpu_dump_state(env, OutputFile, fprintf, 0);
    #endif
}
static void panda_cb_after_store(CPUState* env, uint64_t addr, uint64_t data, size_t width, bool isSigned)
{
    uint64_t cpu_pc = 0;
    #if defined(TARGET_I386)
    cpu_pc = ((CPUArchState*)env->env_ptr)->eip;
    #endif
    if (in_kernelspace(env))
        return;
    fprintf(OutputFile, " After %2d bit %8s Store on CPU %p: IP %#18" PRIx64 " Addr %#18" PRIx64 " Data %#18" PRIx64 "\n", (int)width, (isSigned) ? "signed": "unsigned", env, cpu_pc, addr, data);
    #if defined(TARGET_I386)
    if (bDumpCPU)
        x86_cpu_dump_state(env, OutputFile, fprintf, 0);
    #endif
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

    pcb.panda_cb_before_load = panda_cb_before_load;
    panda_register_callback(self, PANDA_CB_BEFORE_LOAD, pcb);
    pcb.panda_cb_after_load = panda_cb_after_load;
    panda_register_callback(self, PANDA_CB_AFTER_LOAD, pcb);
    pcb.panda_cb_before_store = panda_cb_before_store;
    panda_register_callback(self, PANDA_CB_BEFORE_STORE, pcb);
    pcb.panda_cb_after_store = panda_cb_after_store;
    panda_register_callback(self, PANDA_CB_AFTER_STORE, pcb);

    return true;
}

void uninit_plugin(void* self)
{
}

