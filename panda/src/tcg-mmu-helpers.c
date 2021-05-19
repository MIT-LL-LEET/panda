#include <stdint.h>
#include "qemu/osdep.h"
#include "cpu.h"
#include "panda/plugin.h"
#include "panda/callbacks/cb-support.h"
#include "panda/tcg-mmu-helpers.h"
#include "panda/common.h"

#include "exec/cpu-common.h"

// #define PANDA_MMU_CALLBACK_DUMP_CPU

void helper_panda_beforeafter_load32(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, size_t width, bool isSigned, bool isPre, void* cpu, int32_t target_reg)
{
    #ifdef TARGET_I386
    // fprintf(stderr, "%s load32 %s %d bits CPU %p first_cpu %p IP %#llx addrlo %#llx addrhi %#llx datalo %#llx datahi %#llx \n", (isPre) ? "before" : "after", (isSigned) ? "signed" : "unsigned", (int)width, cpu, first_cpu->env_ptr, (unsigned long long)((CPUArchState*)first_cpu->env_ptr)->eip, (unsigned long long)addrlo, (unsigned long long)addrhi, (unsigned long long)datalo, (unsigned long long)datahi);
    #else
    // fprintf(stderr, "%s load32 %s %d bits CPU %p first_cpu %p addrlo %#llx addrhi %#llx datalo %#llx datahi %#llx \n", (isPre) ? "before" : "after", (isSigned) ? "signed" : "unsigned", (int)width, cpu, first_cpu->env_ptr, (unsigned long long)addrlo, (unsigned long long)addrhi, (unsigned long long)datalo, (unsigned long long)datahi);
    #endif
    #if defined(TARGET_I386) && defined(PANDA_MMU_CALLBACK_DUMP_CPU)
    x86_cpu_dump_state(first_cpu, stderr, fprintf, 0);
    #endif
    uint64_t addr = addrlo | (((uint64_t)addrhi) << 32);
    uint64_t data = datalo | (((uint64_t)datahi) << 32);
    if (isPre)
        panda_callbacks_before_load(ENV_GET_CPU(cpu), addr, data, width, isSigned, target_reg);
    else
        panda_callbacks_after_load(ENV_GET_CPU(cpu), addr, data, width, isSigned, target_reg);
}
void helper_panda_beforeafter_load64(uint64_t addrlo, uint64_t datalo, size_t width, bool isSigned, bool isPre, void* cpu, int32_t target_reg)
{
    #ifdef TARGET_I386
    // fprintf(stderr, "%s load64 %s %d bits CPU %p first_cpu %p IP %#llx addrlo %#llx datalo %#llx \n", (isPre) ? "before" : "after", (isSigned) ? "signed" : "unsigned", (int)width, cpu, first_cpu->env_ptr, (unsigned long long)((CPUArchState*)first_cpu->env_ptr)->eip, (unsigned long long)addrlo, (unsigned long long)datalo);
    #else
    // fprintf(stderr, "%s load64 %s %d bits CPU %p first_cpu %p addrlo %#llx datalo %#llx \n", (isPre) ? "before" : "after", (isSigned) ? "signed" : "unsigned", (int)width, cpu, first_cpu->env_ptr, (unsigned long long)addrlo, (unsigned long long)datalo);
    #endif
    #if defined(TARGET_I386) && defined(PANDA_MMU_CALLBACK_DUMP_CPU)
    x86_cpu_dump_state(first_cpu, stderr, fprintf, 0);
    #endif
    if (isPre)
        panda_callbacks_before_load(ENV_GET_CPU(cpu), addrlo, datalo, width, isSigned, target_reg);
    else
        panda_callbacks_after_load(ENV_GET_CPU(cpu), addrlo, datalo, width, isSigned, target_reg);
}

void helper_panda_beforeafter_store32(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, size_t width, bool isSigned, bool isPre, void* cpu, int32_t target_reg)
{
    // fprintf(stderr, "%s store32 %s %d bits CPU %p first_cpu %p addrlo %#llx addrhi %#llx datalo %#llx datahi %#llx \n", (isPre) ? "before" : "after", (isSigned) ? "signed" : "unsigned", (int)width, cpu, first_cpu->env_ptr, (unsigned long long)addrlo, (unsigned long long)addrhi, (unsigned long long)datalo, (unsigned long long)datahi);
    #if defined(TARGET_I386) && defined(PANDA_MMU_CALLBACK_DUMP_CPU)
    x86_cpu_dump_state(first_cpu, stderr, fprintf, 0);
    #endif
    uint64_t addr = addrlo | (((uint64_t)addrhi) << 32);
    uint64_t data = datalo | (((uint64_t)datahi) << 32);
    if (isPre)
        panda_callbacks_before_store(ENV_GET_CPU(cpu), addr, data, width, isSigned, target_reg);
    else
        panda_callbacks_after_store(ENV_GET_CPU(cpu), addr, data, width, isSigned, target_reg);
}
void helper_panda_beforeafter_store64(uint64_t addrlo, uint64_t datalo, size_t width, bool isSigned, bool isPre, void* cpu, int32_t target_reg)
{
    // fprintf(stderr, "%s load64 %s %d bits CPU %p first_cpu %p addrlo %#llx datalo %#llx \n", (isPre) ? "before" : "after", (isSigned) ? "signed" : "unsigned", (int)width, cpu, first_cpu->env_ptr, (unsigned long long)addrlo, (unsigned long long)datalo);
    #if defined(TARGET_I386) && defined(PANDA_MMU_CALLBACK_DUMP_CPU)
    x86_cpu_dump_state(first_cpu, stderr, fprintf, 0);
    #endif
    if (isPre)
        panda_callbacks_before_store(ENV_GET_CPU(cpu), addrlo, datalo, width, isSigned, target_reg);
    else
        panda_callbacks_after_store(ENV_GET_CPU(cpu), addrlo, datalo, width, isSigned, target_reg);
}
