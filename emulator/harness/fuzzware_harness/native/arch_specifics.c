#include <unicorn/unicorn.h>
#include "arch_specifics.h"

int return_pc_const(uc_engine *uc){
    uint32_t arch = uc_read_arch(uc);

    if (arch == UC_ARCH_ARM)
        return UC_ARM_REG_PC;
    
    if (arch == UC_ARCH_MIPS)
        return UC_MIPS_REG_PC;

    //invalid
    return 0;
}


int return_sp_const(uc_engine *uc){
    uint32_t arch = uc_read_arch(uc);

    if (arch == UC_ARCH_ARM) 
        return UC_ARM_REG_SP;

    if (arch == UC_ARCH_MIPS)
        return UC_MIPS_REG_SP;

    //invalid
    return 0;
}


void print_bb_info_deep(uc_engine *uc, uint64_t address){
    uint32_t arch = uc_read_arch(uc);
    
    if (arch == UC_ARCH_ARM) {
        uint32_t lr;
        uc_reg_read(uc, UC_ARM_REG_LR, &lr);
        printf("Basic Block: addr= 0x%016lx (lr=0x%x)\n", address, lr);
    }
    
    if (arch == UC_ARCH_MIPS){
        printf("Basic Block: addr= 0x%016lx\n", address);
    }
}

void print_other_stack_state(uc_engine *uc){
    uint32_t arch = uc_read_arch(uc);
    uint32_t sp;
    puts("======================\n");
    puts("\n==== UC Other Stack state ====");

    if (arch == UC_ARCH_ARM) {
        uc_reg_read(uc, UC_ARM_REG_OTHER_SP, &sp);
        for (int i = -4; i < 16; ++i)
        {
            uint32_t val;
            if(uc_mem_read(uc, sp+4*i, &val, 4)) {
                continue;
            }
            printf("0x%08x: %08x", sp+4*i, val);
            if(!i) {
                puts(" <---- sp");
            } else {
                puts("");
            }
        }
    }

    if (arch == UC_ARCH_MIPS){
        puts("");
    }

    puts("======================\n");
}


int* return_reg_consts(uc_engine *uc){
    uint32_t arch = uc_read_arch(uc);

    if (arch == UC_ARCH_ARM) 
        return arm_reg_consts;

    if (arch == UC_ARCH_MIPS)
        return mips32_reg_consts;

    //invalid
    return 0;    

}


char** return_reg_names(uc_engine *uc){
    uint32_t arch = uc_read_arch(uc);

    if (arch == UC_ARCH_ARM) 
        return arm_reg_names;

    if (arch == UC_ARCH_MIPS)
        return mips32_reg_names;    

    return 0;
}


int return_num_dumped_regs(uc_engine *uc){
    uint32_t arch = uc_read_arch(uc);

    if (arch == UC_ARCH_ARM) 
        return ARM_NUM_DUMPED_REGS;

    if (arch == UC_ARCH_MIPS)
        return MIPS32_NUM_DUMPED_REGS;    

    return 0;
}


uint64_t return_addr_mark(uc_engine *uc){
    uint32_t arch = uc_read_arch(uc);

    if (arch == UC_ARCH_ARM)
        return 0x1; 

    if (arch == UC_ARCH_MIPS)
        return 0;

    // by default
    return 0;
}