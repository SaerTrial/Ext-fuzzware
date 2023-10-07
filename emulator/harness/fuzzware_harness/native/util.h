#ifndef NATIVE_UTIL_H
#define NATIVE_UTIL_H

#include <unistd.h>
#include <unicorn/unicorn.h>

#define min(a, b) (a < b ? a : b)

#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

void print_state(uc_engine *uc);
int get_instruction_size(uint64_t insn, bool is_thumb);
uint32_t get_current_pc(uc_engine *uc);
uint64_t get_pc_mark(uc_engine *uc);
uint32_t get_current_sp(uc_engine *uc);
void print_bb_info(uc_engine *uc, uint64_t address);
void print_regions(uc_engine *uc);
#endif