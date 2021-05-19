#ifndef _TCG_MMU_HELPERS_H
#define _TCG_MMU_HELPERS_H

#include <stdint.h>

void helper_panda_beforeafter_load32(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, size_t width, bool isSigned, bool isPre, void* cpu, int32_t target_reg);
void helper_panda_beforeafter_load64(uint64_t addrlo, uint64_t datalo, size_t width, bool isSigned, bool isPre, void* cpu, int32_t target_reg);
void helper_panda_beforeafter_store32(uint32_t addrlo, uint32_t addrhi, uint32_t datalo, uint32_t datahi, size_t width, bool isSigned, bool isPre, void* cpu, int32_t target_reg);
void helper_panda_beforeafter_store64(uint64_t addrlo, uint64_t datalo, size_t width, bool isSigned, bool isPre, void* cpu, int32_t target_reg);

#endif
