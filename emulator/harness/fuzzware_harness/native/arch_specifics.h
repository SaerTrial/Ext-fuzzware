#include <inttypes.h>
#include <unistd.h>
#include <unicorn/unicorn.h>

#ifndef ARCH_SPECIFICS_H
#define ARCH_SPECIFICS_H

int return_pc_const(uc_engine *uc);
int return_sp_const(uc_engine *uc);

void print_bb_info_deep(uc_engine *uc, uint64_t address);
void print_other_stack_state(uc_engine *uc);


uint64_t return_addr_mark(uc_engine *uc);
int return_num_dumped_regs(uc_engine *uc);
int* return_reg_consts(uc_engine *uc);
char** return_reg_names(uc_engine *uc);

//----------------------------arm-------------------------
#define ARM_NUM_DUMPED_REGS 18
static int arm_reg_consts[ARM_NUM_DUMPED_REGS] = {
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
    UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_R12, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_XPSR,
    UC_ARM_REG_SP, UC_ARM_REG_OTHER_SP
};

static char* arm_reg_names[ARM_NUM_DUMPED_REGS] = {
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "lr", "pc", "xpsr", "sp", "other_sp"
};
//--------------------------------------------------------


//----------------------------mips32-------------------------
#define MIPS32_NUM_DUMPED_REGS 33
static int mips32_reg_consts[MIPS32_NUM_DUMPED_REGS] = {
    UC_MIPS_REG_ZERO,
    UC_MIPS_REG_AT,
    UC_MIPS_REG_V0,
    UC_MIPS_REG_V1,
    UC_MIPS_REG_A0,
    UC_MIPS_REG_A1,
    UC_MIPS_REG_A2,
    UC_MIPS_REG_A3,
    UC_MIPS_REG_T0,
    UC_MIPS_REG_T1,
    UC_MIPS_REG_T2,
    UC_MIPS_REG_T3,
    UC_MIPS_REG_T4,
    UC_MIPS_REG_T5,
    UC_MIPS_REG_T6,
    UC_MIPS_REG_T7,
    UC_MIPS_REG_S0,
    UC_MIPS_REG_S1,
    UC_MIPS_REG_S2,
    UC_MIPS_REG_S3,
    UC_MIPS_REG_S4,
    UC_MIPS_REG_S5,
    UC_MIPS_REG_S6,
    UC_MIPS_REG_S7,
    UC_MIPS_REG_T8,
    UC_MIPS_REG_T9,
    UC_MIPS_REG_K0,
    UC_MIPS_REG_K1,
    UC_MIPS_REG_GP,
    UC_MIPS_REG_SP,
    UC_MIPS_REG_RA,
    UC_MIPS_REG_PC
};

static char* mips32_reg_names[MIPS32_NUM_DUMPED_REGS] = {
        "zero", "at", "v0",
        "v1", "a0", "a1",
        "a2", "a3", "t0",
        "t1", "t2", "t3",
        "t4", "t5", "t6",
        "t7", "s0", "s1",
        "s2", "s3", "s4",
        "s5", "s6", "s7",
        "t8", "t9", "k0",
        "k1", "gp", "sp",
        "fp", "ra", "pc"};
//-----------------------------------------------------------

#endif