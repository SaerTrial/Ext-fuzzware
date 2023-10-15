#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <unicorn/unicorn.h>
#include "arch_specifics.h"

int get_instruction_size(uint64_t insn, bool is_thumb) {
    if(is_thumb) {
        switch(insn & 0xf800) {
            // Thumb2: 32-bit
            case 0xe800:
            case 0xf000:
            case 0xf800:
                return 4;
            // Thumb: 16-bit
            default:
                return 2;
        }
    } else {
        return 4;
    }
}

void print_state(uc_engine *uc) {
    uint32_t reg;

    int* reg_ids = return_reg_consts(uc);
    char** reg_names = return_reg_names(uc);
    int NUM_DUMPED_REGS = return_num_dumped_regs(uc);

    puts("\n==== UC Reg state ====");
    for (int i = 0; i < NUM_DUMPED_REGS; ++i)
    {
        uc_reg_read(uc, reg_ids[i], &reg);
        printf("%s: 0x%08x\n", reg_names[i], reg);
    }

    print_other_stack_state(uc);

    fflush(stdout);
}


// uint32_t get_current_pc(uc_engine *uc){
//     uint32_t arch = uc_read_arch(uc);

//     if (arch == UC_ARCH_ARM)
//         return UC_ARM_REG_PC;
    
//     if (arch == UC_ARCH_MIPS)
//         return UC_MIPS_REG_PC;

//     //invalid
//     return 0;
// }


// uint64_t get_pc_mark(uc_engine *uc){
//     uint32_t arch = uc_read_arch(uc);

//     if (arch == UC_ARCH_ARM)
//         return 0x1; 
    
//     if (arch == UC_ARCH_MIPS)
//         return 0;

//     // by default
//     return 0;
// }


// uint32_t get_current_sp(uc_engine *uc){
//     uint32_t arch = uc_read_arch(uc);

//     if (arch == UC_ARCH_ARM) 
//         return UC_ARM_REG_SP;

//     if (arch == UC_ARCH_MIPS)
//         return UC_MIPS_REG_SP;

//     //invalid
//     return 0;
// }


void print_bb_info(uc_engine *uc, uint64_t address){ 
    print_bb_info_deep(uc, address);
    fflush(stdout);
}


void print_regions(uc_engine *uc){
    uint32_t num_regions;
    uc_mem_region *regions;
    uc_mem_regions(uc, &regions, &num_regions);
    printf("-----------------mem_regions----------------\n");
    for(int i=0; i < num_regions; ++i){
        printf("region_start:0x%lx, region_end:0x%lx, perms: %x\n", regions[i].begin, regions[i].end, regions[i].perms);
    }
}