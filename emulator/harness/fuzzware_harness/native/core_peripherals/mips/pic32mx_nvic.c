#include "pic32mx_nvic.h"

#define PIC32MX_NVIC_NONE_ACTIVE -1
#define PIC32MX_NVIC_LOWEST_PRIO -1
#define PIC32MX_NVIC_HIGHEST_PRIO 7
#define PIC32MX_NVIC_HIGHEST_SUB_PRIO 3
#define PIC32MX_NVIC_LOWEST_SUB_PRIO 0
// #define DEBUG_NVIC

// We may not want to allow nested interrupts
#define DISABLE_NESTED_INTERRUPTS


uint32_t pic32mx_interrupt_limit = 0;
uint32_t pic32mx_num_config_disabled_interrupts = 0;
uint32_t *pic32mx_config_disabled_interrupts = NULL;
uc_hook pic32mx_nvic_block_hook_handle = -1, pic32mx_nvic_exception_return_hook_handle=-1,
    pic32mx_hook_mmio_write_handle = -1, pic32mx_hook_mmio_read_handle = -1;
uint32_t pic32mx_nesting_detector = 0;

// 3. Dynamic State (required for state restore)
struct Pic32mxNVIC pic32mx_nvic __attribute__ ((aligned (64))) = {
    .vtor = PIC32MX_EBASE, // an idle assignment, we don't need this actually
    .num_enabled = 0
};

// forward declaration
static bool pic32mx_recalc_prios();
static void pic32mx_ExceptionEntry(uc_engine *uc);
bool pic32mx_is_disabled_by_config(int exception_no);
static void pic32mx_core_software_interrupt_controller(uc_engine *uc);
void pic32mx_update_enabled_irq_list(int irq);


__attribute__ ((hot))
static void pic32mx_nvic_block_hook(uc_engine *uc, uint64_t address, uint32_t size, struct Pic32mxNVIC* arg_nvic) {
        

        #ifdef DISABLE_NESTED_INTERRUPTS
            // Hack: prevent nested interrupt from happening
            if (pic32mx_nesting_detector == 1){
                if ((uint32_t)address == arg_nvic->EPC){
                    pic32mx_nesting_detector = 0;
                }else{
                    return;
                }
            }
        #endif
        

            pic32mx_core_software_interrupt_controller(uc);
            #ifdef DISABLE_NESTED_INTERRUPTS
            if( arg_nvic->active_irq == PIC32MX_NVIC_NONE_ACTIVE ) {
            #endif
                pic32mx_ExceptionEntry(uc);
            #ifdef DISABLE_NESTED_INTERRUPTS
            }
            #endif
}


static void pic32mx_core_software_interrupt_controller(uc_engine *uc){
    PIC32MX_CP0_cause CP0_cause;
    uc_reg_read(uc, UC_MIPS_REG_CP0_CAUSE, &CP0_cause);
    // core software interrupt 0
    if (CP0_cause.IP0){
        // Caution: only execute once
        if (pic32mx_nvic.InterruptEnabled[PIC32MX_IRQ_Core_Software_Interrupt_0] == 0){
            pic32mx_nvic.InterruptEnabled[PIC32MX_IRQ_Core_Software_Interrupt_0] = 1;
            pic32mx_nvic.InterruptPriority[PIC32MX_IRQ_Core_Software_Interrupt_0] = PIC32MX_NVIC_HIGHEST_PRIO;
            pic32mx_nvic.InterruptSubPriority[PIC32MX_IRQ_Core_Software_Interrupt_0] = PIC32MX_NVIC_HIGHEST_SUB_PRIO;
            pic32mx_update_enabled_irq_list(PIC32MX_IRQ_Core_Software_Interrupt_0);
        }
        pic32mx_nvic.InterruptPending[PIC32MX_IRQ_Core_Software_Interrupt_0] = 1;
        pic32mx_recalc_prios();
    }else{
            // In general cases, ISR code will clear pending bit via a MMIO write to the interrupt controller
            // then this handling is redundant
            #ifdef DEBUG_NVIC
            if (pic32mx_nvic.InterruptPending[PIC32MX_IRQ_Core_Software_Interrupt_0] == 1){
                printf("[core_software_interrupt_controller] unpending irq 1\n");
                fflush(stdout);
            }
            #endif


        pic32mx_nvic.InterruptPending[PIC32MX_IRQ_Core_Software_Interrupt_0] = 0;
    }

    // core software interrupt 1
    if (CP0_cause.IP1){
        if (pic32mx_nvic.InterruptEnabled[PIC32MX_IRQ_Core_Software_Interrupt_1] == 0){
            pic32mx_nvic.InterruptEnabled[PIC32MX_IRQ_Core_Software_Interrupt_1] = 1;
            pic32mx_nvic.InterruptPriority[PIC32MX_IRQ_Core_Software_Interrupt_1] = PIC32MX_NVIC_HIGHEST_PRIO;
            pic32mx_nvic.InterruptSubPriority[PIC32MX_IRQ_Core_Software_Interrupt_1] = PIC32MX_NVIC_HIGHEST_SUB_PRIO-1;
            pic32mx_update_enabled_irq_list(PIC32MX_IRQ_Core_Software_Interrupt_1);
        }
        pic32mx_nvic.InterruptPending[PIC32MX_IRQ_Core_Software_Interrupt_1] = 1;
    }else{
            #ifdef DEBUG_NVIC
            if (pic32mx_nvic.InterruptPending[PIC32MX_IRQ_Core_Software_Interrupt_1] == 1){
                printf("[core_software_interrupt_controller] unpending irq 2\n");
                fflush(stdout);
            }
            #endif

        pic32mx_nvic.InterruptPending[PIC32MX_IRQ_Core_Software_Interrupt_1] = 0;
    }

    // core timer interrupt 0
    if (CP0_cause.TI){
        if (pic32mx_nvic.InterruptEnabled[PIC32MX_IRQ_Core_Timer] == 0){
            pic32mx_nvic.InterruptEnabled[PIC32MX_IRQ_Core_Timer] = 1;
            pic32mx_nvic.InterruptPriority[PIC32MX_IRQ_Core_Timer] = PIC32MX_NVIC_HIGHEST_PRIO;
            pic32mx_nvic.InterruptSubPriority[PIC32MX_IRQ_Core_Timer] = PIC32MX_NVIC_HIGHEST_SUB_PRIO-1;
            pic32mx_update_enabled_irq_list(PIC32MX_IRQ_Core_Timer);
        }
        pic32mx_nvic.InterruptPending[PIC32MX_IRQ_Core_Timer] = 1;
    }else{
            #ifdef DEBUG_NVIC
            if (pic32mx_nvic.InterruptPending[PIC32MX_IRQ_Core_Timer] == 1){
                printf("[core timer interrupt] unpending irq 0\n");
                fflush(stdout);
            }
            #endif

        pic32mx_nvic.InterruptPending[PIC32MX_IRQ_Core_Timer] = 0;
    }
    

}

// Hack: we update status here by a given IRQ 
// because MMIO accesses don't indicate an IRQ
void pic32mx_pend_interrupt(uc_engine *uc, int exception_no) {
    #ifdef DEBUG_NVIC
    printf("[pend_interrupt] irq=%d, active_irq=%d\n", exception_no, pic32mx_nvic.active_irq);
    fflush(stdout);
    #endif
    if(pic32mx_nvic.InterruptPending[exception_no] == 0) {
        pic32mx_nvic.InterruptPending[exception_no] = 1;

        pic32mx_recalc_prios();
    }else if (pic32mx_nvic.InterruptPending[exception_no] == 1 && \
    pic32mx_nvic.InterruptEnabled[exception_no] == 1){
        pic32mx_recalc_prios();
    }
}


static void pic32mx_ExceptionEntry(uc_engine *uc) {  
    // interrupt trigger sends an IRQ too early and the actual enabling of interrupts hasn't been done.
    if (pic32mx_nvic.pending_irq == PIC32MX_NVIC_NONE_ACTIVE) return;

    #ifdef DEBUG_NVIC
    printf("[NVIC] ExceptionEntry\n"); fflush(stdout);
    #endif
    
    // Store the current PC in EPC
    uint32_t epc;
    uc_reg_read(uc, UC_MIPS_REG_PC, &epc);
    uc_reg_write(uc, UC_MIPS_REG_CP0_EPC, &epc);
    pic32mx_nvic.EPC = epc;

    // Find the ISR entry point and set it
    // EPC to return
    uint32_t ExceptionNumber =  PIC32MX_IRQ2VectorNum[pic32mx_nvic.pending_irq] ;

    //e.g., 0x9FC01000 + 0x200 + VecNum* 0x20
    uint32_t isr_entry = PIC32MX_EBASE + 0x200 + ExceptionNumber * 0x20;
   
    uc_reg_write(uc, UC_MIPS_REG_PC, &isr_entry);

    #ifdef DEBUG_NVIC
    printf("Redirecting irq %d (vector %d) to isr: %08x, EPC: %08x\n", pic32mx_nvic.pending_irq, ExceptionNumber, isr_entry, epc);
    #endif

    // Update pic32mx_nvic state with new active interrupt
    // pic32mx_nvic.InterruptPending[ExceptionNumber] = 0;
    // we clear pending bit in a MMIO write access to IFSxCLR
    
    //pic32mx_nvic.active_irq = ExceptionNumber;
    pic32mx_nvic.active_irq = pic32mx_nvic.pending_irq;

    // We need to re-calculate the pending priority state
    pic32mx_recalc_prios();

    #ifdef DEBUG_NVIC
    puts("************ POST ExceptionEntry");
    print_state(uc);
    #endif

}


uint16_t pic32mx_get_num_enabled() {
    return pic32mx_nvic.num_enabled;
}

uint8_t pic32mx_nth_enabled_irq_num(uint8_t n) {
    return pic32mx_nvic.enabled_irqs[n % pic32mx_nvic.num_enabled];
}

void pic32mx_nvic_set_pending(uc_engine *uc, uint32_t irq, int delay_activation) {
    pic32mx_pend_interrupt(uc, irq);
    // maybe_activate(uc, false);
}



void * pic32mx_nvic_take_snapshot(uc_engine *uc) {
    size_t size = sizeof(pic32mx_nvic);

    // NVIC snapshot: save the sysreg mem page
    char *result = malloc(size + PAGE_SIZE);
    memcpy(result, &pic32mx_nvic, size);
    uc_mem_read(uc, PIC32MX_INTR_CTL_REG_MMIO_BASE, result + size, PAGE_SIZE);

    return result;
}

void pic32mx_nvic_restore_snapshot(uc_engine *uc, void *snapshot) {
    // Restore the pic32mx_nvic
    memcpy(&pic32mx_nvic, snapshot, sizeof(pic32mx_nvic));
    // Restore the sysreg mem page
    uc_mem_write(uc, PIC32MX_INTR_CTL_REG_MMIO_BASE, ((char *) snapshot) + sizeof(pic32mx_nvic), PAGE_SIZE);
}

void pic32mx_nvic_discard_snapshot(uc_engine *uc, void *snapshot) {
    free(snapshot);
}



/*
 * Re-calculate pic32mx_nvic interrupt prios and determine the next interrupt
 * (i.e., a higher-prio interrupt is now pending)
 */
static bool pic32mx_recalc_prios() {
    int highest_pending_prio = PIC32MX_NVIC_LOWEST_PRIO;
    int highest_pending_sub_prio = PIC32MX_NVIC_LOWEST_PRIO;
    int highest_pending_irq = PIC32MX_NVIC_NONE_ACTIVE;
    

    // iterate all enabled and pending interrupts
    // sort the highest irq out
    // the active interrupt should be excluded
    for(int i = 0; i < pic32mx_nvic.num_enabled; ++i) {
        int irq = pic32mx_nvic.enabled_irqs[i];
        int curr_prio = pic32mx_nvic.InterruptPriority[irq];
        int curr_sub_prio = pic32mx_nvic.InterruptSubPriority[irq];
        
        #ifdef DEBUG_NVIC
           printf("[recalc_prios] irq:%d,  irq_prio:%d, irq_sub_prio:%d\n", irq, curr_prio, curr_sub_prio);
        #endif

        if(pic32mx_nvic.InterruptPending[irq] && pic32mx_nvic.active_irq != irq) {
            if (curr_prio > highest_pending_prio) {
                #ifdef DEBUG_NVIC
                printf("[recalc_prios] curr_prio > highest_pending_prio for irq %d: curr: %d > new highest: %d\n", irq, curr_prio, highest_pending_prio);
                #endif

                highest_pending_prio = curr_prio;
                highest_pending_sub_prio = curr_sub_prio;
                highest_pending_irq = irq;
            }
            else if (curr_prio == highest_pending_prio){
                // Further compare sub-priority
                if (curr_sub_prio > highest_pending_sub_prio) {

                    highest_pending_prio = curr_prio;
                    highest_pending_sub_prio = curr_sub_prio;
                    highest_pending_irq = irq;

                    #ifdef DEBUG_NVIC
                    printf("[recalc_prios] curr_sub_prio > highest_pending_sub_prio for irq %d: curr: %d > new highest: %d\n", irq, curr_sub_prio, highest_pending_sub_prio);
                    #endif
                }
            }
        }

        // TODO: consider the case for no active irq, and adjust highest pending one

    }


    pic32mx_nvic.pending_prio = highest_pending_prio;
    pic32mx_nvic.pending_sub_prio = highest_pending_sub_prio;
    pic32mx_nvic.pending_irq = highest_pending_irq;

    // no change
    if (highest_pending_irq == PIC32MX_NVIC_LOWEST_PRIO)
        return false;

    return true;
}



void pic32mx_update_enabled_irq_list(int irq){
    int i = 0;

    for(; i < pic32mx_nvic.num_enabled; ++i) {
        if(pic32mx_nvic.enabled_irqs[i] == irq) {
            return;
        }
    }

    i = 0;
    for(; i < pic32mx_nvic.num_enabled; ++i) {
        if(pic32mx_nvic.enabled_irqs[i] > irq) {
            memmove(&pic32mx_nvic.enabled_irqs[i+1], &pic32mx_nvic.enabled_irqs[i], (pic32mx_nvic.num_enabled-i) * sizeof(pic32mx_nvic.enabled_irqs[0]));
            break;
        }
    }

    pic32mx_nvic.enabled_irqs[i] = irq;
    ++pic32mx_nvic.num_enabled;

    #ifdef DEBUG_NVIC
    printf("[update_enabled_irq_list] \n");
    for(i=0; i < pic32mx_nvic.num_enabled; ++i) {
        printf("irq = %d\n", pic32mx_nvic.enabled_irqs[i]);
    }
    fflush(stdout);
    #endif

}


void pic32mx_update_enabled_interrupts(uc_engine *uc, uint32_t IEC_index, uint32_t value){
    int cur_bit = 0;
    int irq = 0;

    // Hack: we not only record enabled interrupts but also update their priority in pic32mx_nvic
    // in most cases, priority is defined before the interrupt is enabled

    while (cur_bit < 32){
        if (PIC32MX_Get_Bit(value, cur_bit) == 1){

            irq = IEC_index * 32 + cur_bit;

            if(pic32mx_is_disabled_by_config(irq)) break;
            
            pic32mx_nvic.InterruptEnabled[irq] = 1;

            pic32mx_update_disabled_irq_list(irq);


            break;
        }
        cur_bit ++;
    }

}


void pic32mx_update_disabled_irq_list(int irq){
    for(int i = 0; i < pic32mx_nvic.num_enabled; ++i) {
        if(pic32mx_nvic.enabled_irqs[i] == irq) {
            pic32mx_nvic.num_enabled--;
            // we don't care about the last position
            if (i != (PIC32MX_NVIC_NUM_SUPPORTED_INTERRUPTS - 1) )
                memmove(&pic32mx_nvic.enabled_irqs[i], &pic32mx_nvic.enabled_irqs[i+1], (pic32mx_nvic.num_enabled-i) * sizeof(pic32mx_nvic.enabled_irqs[0]));

            #ifdef DEBUG_NVIC
            printf("remove irq %d from the list\n", irq);
            fflush(stdout);
            #endif

            break;
        }
    }
}


void pic32mx_update_disabled_interrupts(uc_engine *uc, uint32_t IEC_index, uint32_t value){
    int cur_bit = 0;
    int irq = 0;

    // Hack: we not only record enabled interrupts but also update their priority in pic32mx_nvic
    // in most cases, priority is defined before the interrupt is enabled

    while (cur_bit < 32){
        if (PIC32MX_Get_Bit(value, cur_bit) == 1){

            irq = IEC_index * 32 + cur_bit;

            if(pic32mx_is_disabled_by_config(irq)) break;
            
            pic32mx_nvic.InterruptEnabled[irq] = 0;

            pic32mx_update_disabled_irq_list(irq);


            break;
        }
        cur_bit ++;
    }

}


void pic32mx_update_pending_interrupts(uint32_t IFS_index, uint32_t value){
    int cur_bit = 0;
    int irq = 0;

    while (cur_bit < 32){
        if (PIC32MX_Get_Bit(value, cur_bit) == 1){
            irq = IFS_index * 32 + cur_bit;
            pic32mx_nvic.InterruptPending[irq] = 1;
            break;
        }

        cur_bit ++;
    }
}


void pic32mx_clear_interrupts(uint32_t IFSxCLR_index, uint32_t value){
    int cur_bit = 0;
    int irq = 0;
    while (cur_bit < 32){
        if (PIC32MX_Get_Bit(value, cur_bit) == 1){
            irq = IFSxCLR_index * 32 + cur_bit;
            pic32mx_nvic.InterruptPending[irq] = 0;

            // Hack: consider as an exception exit
            if (pic32mx_nvic.active_irq == irq) {
                pic32mx_nvic.active_irq = PIC32MX_NVIC_NONE_ACTIVE;
                    #ifdef DEBUG_NVIC
                    printf("[NVIC] setting irq %d as non-active \n", irq);
                    fflush(stdout);
                    #endif
                // check if any pending interrupts
                pic32mx_nesting_detector = pic32mx_recalc_prios();
            }
            break;
        }

        cur_bit ++;
    }
}


void pic32mx_update_enabled_interrupts_priority(uc_engine *uc, uint32_t offset, uint32_t priority){
        uint32_t index = ((offset & ~(0xf)) - PIC32MX_IPC0 )/ 0x10;
        int vector = index * 4; // Note that: it is not an irq but a vector num
        int irq = 0;
        // update priority
        // priority, sub-priority

            // uc_mem_read(uc, PIC32MX_INTR_CTL_REG_MMIO_BASE + PIC32MX_IPC0 + index * 0x10 + PIC32MX_OFFSET_IPCxSET, &priority, 4);

        if (PIC32MX_Prio_0(priority) != 0){
            
            for (int i = 0; i < PIC32MX_MIRROR; i++){
                irq = PIC32MX_VectorNum2IRQ[vector][i];

                if(pic32mx_is_disabled_by_config(irq)) continue;
                
                // pic32mx_nvic.InterruptEnabled[irq] = 1;

                // pic32mx_update_enabled_irq_list(irq);

                pic32mx_nvic.InterruptPriority[irq] = PIC32MX_Prio_0(priority);
                pic32mx_nvic.InterruptSubPriority[irq] = PIC32MX_Sub_Prio_0(priority);
            }
        }
        else if(PIC32MX_Prio_1(priority) != 0){
            vector += 1;

            for (int i = 0; i < PIC32MX_MIRROR; i++){
                irq = PIC32MX_VectorNum2IRQ[vector][i];

                if(pic32mx_is_disabled_by_config(irq)) continue;
                
                // pic32mx_nvic.InterruptEnabled[irq] = 1;

                // pic32mx_update_enabled_irq_list(irq);

                pic32mx_nvic.InterruptPriority[irq] = PIC32MX_Prio_1(priority);
                pic32mx_nvic.InterruptSubPriority[irq] = PIC32MX_Sub_Prio_1(priority);
            }
        }
        else if (PIC32MX_Prio_2(priority) != 0){
            vector += 2;
            for (int i = 0; i < PIC32MX_MIRROR; i++){
                irq = PIC32MX_VectorNum2IRQ[vector][i];

                if(pic32mx_is_disabled_by_config(irq)) continue;
                
                // pic32mx_nvic.InterruptEnabled[irq] = 1;

                // pic32mx_update_enabled_irq_list(irq);
                pic32mx_nvic.InterruptPriority[irq] = PIC32MX_Prio_2(priority);
                pic32mx_nvic.InterruptSubPriority[irq] = PIC32MX_Sub_Prio_2(priority);
            }
        }
        else if (PIC32MX_Prio_3(priority) != 0){
            vector += 3;
            for (int i = 0; i < PIC32MX_MIRROR; i++){
                irq = PIC32MX_VectorNum2IRQ[vector][i];

                if(pic32mx_is_disabled_by_config(irq)) continue;
                
                // pic32mx_nvic.InterruptEnabled[irq] = 1;

                // pic32mx_update_enabled_irq_list(irq);

                pic32mx_nvic.InterruptPriority[irq] = PIC32MX_Prio_3(priority);
                pic32mx_nvic.InterruptSubPriority[irq] = PIC32MX_Sub_Prio_3(priority);
            }
        }
            
        #ifdef DEBUG_NVIC
            printf("[update interrupt priority] irq = %d, priority = %d, sub-priority = %d\n", irq, pic32mx_nvic.InterruptPriority[irq], pic32mx_nvic.InterruptSubPriority[irq]);
            fflush(stdout);
        #endif
    
} 

// due to some application codes that utilze peripheral control registers to enable/disable interrupts along the way
// we need to detect this behavior
void pic32mx_hook_peripheral_ctl_mmio_write(uc_engine *uc, uc_mem_type type,
                        uint64_t addr, int size, int64_t value, void *user_data) {
    #ifdef DEBUG_NVIC
    printf("[NVIC] hook_peripheral_ctl_mmio_write: Write to %08lx, value: %08lx\n", addr, value);
    fflush(stdout);
    #endif     

    // Caution: since we've only noticed that timer is disabled/enabled in running, we thus monitor all timers.
    // TODO: optimize this switch case
    switch(addr) {  
        case PIC32MX_T1CON + PIC32MX_OFFSET_xSET:
            pic32mx_nvic.InterruptPending[PIC32MX_TIMER_1_VECTOR] = 1;
            break;
        case PIC32MX_T1CON + PIC32MX_OFFSET_xCLR:
            pic32mx_nvic.InterruptPending[PIC32MX_TIMER_1_VECTOR] = 0;
            break;             
        case PIC32MX_T2CON + PIC32MX_OFFSET_xSET:
            pic32mx_nvic.InterruptPending[PIC32MX_TIMER_2_VECTOR] = 1;
            break;
        case PIC32MX_T2CON + PIC32MX_OFFSET_xCLR:
            pic32mx_nvic.InterruptPending[PIC32MX_TIMER_2_VECTOR] = 0;
            break;            
        case PIC32MX_T3CON + PIC32MX_OFFSET_xSET:
            pic32mx_nvic.InterruptPending[PIC32MX_TIMER_3_VECTOR] = 1;
            break;            
        case PIC32MX_T3CON + PIC32MX_OFFSET_xCLR:
            pic32mx_nvic.InterruptPending[PIC32MX_TIMER_3_VECTOR] = 0;
            break;  
        case PIC32MX_T4CON + PIC32MX_OFFSET_xSET:
            pic32mx_nvic.InterruptPending[PIC32MX_TIMER_4_VECTOR] = 1;
            break; 
        case PIC32MX_T4CON + PIC32MX_OFFSET_xCLR:
            pic32mx_nvic.InterruptPending[PIC32MX_TIMER_4_VECTOR] = 0;
            break; 
        case PIC32MX_T5CON + PIC32MX_OFFSET_xSET:
            pic32mx_nvic.InterruptPending[PIC32MX_TIMER_5_VECTOR] = 1;
            break;   
        case PIC32MX_T5CON + PIC32MX_OFFSET_xCLR:
            pic32mx_nvic.InterruptPending[PIC32MX_TIMER_5_VECTOR] = 0;
            break;  
        default: break;
    }


}


void pic32mx_hook_sysctl_mmio_write(uc_engine *uc, uc_mem_type type,
                        uint64_t addr, int size, int64_t value, void *user_data) {
    #ifdef DEBUG_NVIC
    printf("[NVIC] hook_sysctl_mmio_write: Write to %08lx, value: %08lx\n", addr, value);
    fflush(stdout);
    #endif                     
    

    // identify which interrupt control register to be written
    // uint32_t offset = addr & 0xFFF;

    switch(addr) {     
        // interrupt flags
        case PIC32MX_IFS0:
            pic32mx_update_pending_interrupts(0, value);
            break;
        case PIC32MX_IFS1:
            pic32mx_update_pending_interrupts(1, value);
            break;
        case PIC32MX_IFS2:
            pic32mx_update_pending_interrupts(2, value);
            break;


        // interrupt mask
        // Hack: once a write to the below registers corresponding to 
        // we then iterate enabled interrupts through this register, each register records 32 IRQ
        case PIC32MX_IEC0:
            pic32mx_update_enabled_interrupts(uc, 0, value);
            break;
        case PIC32MX_IEC1:
            pic32mx_update_enabled_interrupts(uc, 1, value);
            break;
        case PIC32MX_IEC2:
            pic32mx_update_enabled_interrupts(uc, 2, value);
            break;

        // enable an interrupt
        case PIC32MX_IEC0SET:
            pic32mx_update_enabled_interrupts(uc, 0, value);
            break;
        case PIC32MX_IEC1SET:
            pic32mx_update_enabled_interrupts(uc, 1, value);
            break;
        case PIC32MX_IEC2SET:
            pic32mx_update_enabled_interrupts(uc, 2, value);
            break;

        // disable an interrupt
        case PIC32MX_IEC0CLR:
            pic32mx_update_disabled_interrupts(uc, 0, value);
            break;
        case PIC32MX_IEC1CLR:
            pic32mx_update_disabled_interrupts(uc, 1, value);
            break;
        case PIC32MX_IEC2CLR:
            pic32mx_update_disabled_interrupts(uc, 2, value);
            break;

        // interrupt CLR register at the offset of 4 bytes in the associated register, e.g., IFS0CLR
        // crucial to terminate an ISR by setting as non-active
        case PIC32MX_IFS0CLR:
            pic32mx_clear_interrupts(0, value);
            break;
        case PIC32MX_IFS1CLR:
            pic32mx_clear_interrupts(1, value);
            break;
        case PIC32MX_IFS2CLR:
            pic32mx_clear_interrupts(2, value);
            break;
        case PIC32MX_IPC0SET ... PIC32MX_IPC12SET:
            // interrupt priority
            pic32mx_update_enabled_interrupts_priority(uc, addr, value);
            break;

        default: break;
    }

}


bool pic32mx_is_disabled_by_config(int exception_no) {
    for(int i = 0; i < pic32mx_num_config_disabled_interrupts; ++i) {
        if(pic32mx_config_disabled_interrupts[i] == exception_no) {
            return true;
        }
    }

    return false;
}

void pic32mx_init_irq2vector(){
    int index = 0;
    // first ordered tier
    for (; index <= 23; index++){
        PIC32MX_IRQ2VectorNum[index] = index;
        for (int j = 0; j < PIC32MX_MIRROR; j++){
            PIC32MX_VectorNum2IRQ[index][j] = index;
        }
    }


    // unordered
    PIC32MX_IRQ2VectorNum[index] = 23; index++; // irq 24 -> vector 23
    PIC32MX_IRQ2VectorNum[index] = 23; index++; // irq 25 -> vector 23

    PIC32MX_VectorNum2IRQ[23][0] = 23;
    PIC32MX_VectorNum2IRQ[23][1] = 24;
    PIC32MX_VectorNum2IRQ[23][2] = 25;

    PIC32MX_IRQ2VectorNum[index] = 24; index++; // irq 26 -> vector 24
    PIC32MX_IRQ2VectorNum[index] = 24; index++; // irq 27 -> vector 24
    PIC32MX_IRQ2VectorNum[index] = 24; index++; // irq 28 -> vector 24

    PIC32MX_VectorNum2IRQ[24][0] = 26;
    PIC32MX_VectorNum2IRQ[24][1] = 27;
    PIC32MX_VectorNum2IRQ[24][2] = 28;

    PIC32MX_IRQ2VectorNum[index] = 25; index++; // irq 29 -> vector 25
    PIC32MX_IRQ2VectorNum[index] = 25; index++; // irq 30 -> vector 25
    PIC32MX_IRQ2VectorNum[index] = 25; index++; // irq 31 -> vector 25

    PIC32MX_VectorNum2IRQ[25][0] = 29;
    PIC32MX_VectorNum2IRQ[25][1] = 30;
    PIC32MX_VectorNum2IRQ[25][2] = 31;


    PIC32MX_IRQ2VectorNum[index] = 26; index++; // irq 32 -> vector 26
    PIC32MX_IRQ2VectorNum[index] = 27; index++; // irq 33 -> vector 27
    PIC32MX_IRQ2VectorNum[index] = 28; index++; // irq 34 -> vector 28    
    PIC32MX_IRQ2VectorNum[index] = 29; index++; // irq 35 -> vector 29
    PIC32MX_IRQ2VectorNum[index] = 30; index++; // irq 36 -> vector 30

    PIC32MX_VectorNum2IRQ[26][0] = 32; PIC32MX_VectorNum2IRQ[26][1] = 32; PIC32MX_VectorNum2IRQ[26][2] = 32; 
    PIC32MX_VectorNum2IRQ[27][0] = 33; PIC32MX_VectorNum2IRQ[27][1] = 33; PIC32MX_VectorNum2IRQ[27][2] = 33; 
    PIC32MX_VectorNum2IRQ[28][0] = 34; PIC32MX_VectorNum2IRQ[28][1] = 34; PIC32MX_VectorNum2IRQ[28][2] = 34; 
    PIC32MX_VectorNum2IRQ[29][0] = 35; PIC32MX_VectorNum2IRQ[29][1] = 35; PIC32MX_VectorNum2IRQ[29][2] = 35; 
    PIC32MX_VectorNum2IRQ[30][0] = 36; PIC32MX_VectorNum2IRQ[30][1] = 36; PIC32MX_VectorNum2IRQ[30][2] = 36; 

    PIC32MX_IRQ2VectorNum[index] = 31; index++; // irq 37 -> vector 31
    PIC32MX_IRQ2VectorNum[index] = 31; index++; // irq 38 -> vector 31   
    PIC32MX_IRQ2VectorNum[index] = 31; index++; // irq 39 -> vector 31

    PIC32MX_VectorNum2IRQ[31][0] = 37; 
    PIC32MX_VectorNum2IRQ[31][1] = 38; 
    PIC32MX_VectorNum2IRQ[31][2] = 39; 

    PIC32MX_IRQ2VectorNum[index] = 32; index++; // irq 40 -> vector 32
    PIC32MX_IRQ2VectorNum[index] = 32; index++; // irq 41 -> vector 32   
    PIC32MX_IRQ2VectorNum[index] = 32; index++; // irq 42 -> vector 32

    PIC32MX_VectorNum2IRQ[32][0] = 40; 
    PIC32MX_VectorNum2IRQ[32][1] = 41; 
    PIC32MX_VectorNum2IRQ[32][2] = 42; 


    PIC32MX_IRQ2VectorNum[index] = 33; index++; // irq 43 -> vector 33
    PIC32MX_IRQ2VectorNum[index] = 33; index++; // irq 44 -> vector 33   
    PIC32MX_IRQ2VectorNum[index] = 33; index++; // irq 45 -> vector 33

    PIC32MX_VectorNum2IRQ[33][0] = 43; 
    PIC32MX_VectorNum2IRQ[33][1] = 44; 
    PIC32MX_VectorNum2IRQ[33][2] = 45; 

    PIC32MX_IRQ2VectorNum[index] = 34; index++; // irq 46 -> vector 34
    PIC32MX_IRQ2VectorNum[index] = 35; index++; // irq 47 -> vector 35   
    PIC32MX_IRQ2VectorNum[index] = 36; index++; // irq 48 -> vector 36
    PIC32MX_IRQ2VectorNum[index] = 37; index++; // irq 49 -> vector 37
    PIC32MX_IRQ2VectorNum[index] = 38; index++; // irq 50 -> vector 38   
    PIC32MX_IRQ2VectorNum[index] = 39; index++; // irq 51 -> vector 39

    PIC32MX_VectorNum2IRQ[34][0] = 46; PIC32MX_VectorNum2IRQ[34][1] = 46; PIC32MX_VectorNum2IRQ[34][2] = 46; 
    PIC32MX_VectorNum2IRQ[35][0] = 47; PIC32MX_VectorNum2IRQ[35][1] = 47; PIC32MX_VectorNum2IRQ[35][2] = 47; 
    PIC32MX_VectorNum2IRQ[36][0] = 48; PIC32MX_VectorNum2IRQ[36][1] = 48; PIC32MX_VectorNum2IRQ[36][2] = 48; 
    PIC32MX_VectorNum2IRQ[37][0] = 49; PIC32MX_VectorNum2IRQ[37][1] = 49; PIC32MX_VectorNum2IRQ[37][2] = 49; 
    PIC32MX_VectorNum2IRQ[38][0] = 50; PIC32MX_VectorNum2IRQ[38][1] = 50; PIC32MX_VectorNum2IRQ[38][2] = 50; 
    PIC32MX_VectorNum2IRQ[39][0] = 51; PIC32MX_VectorNum2IRQ[39][1] = 51; PIC32MX_VectorNum2IRQ[39][2] = 51; 

}


uc_err pic32mx_init_nvic(uc_engine *uc, uint32_t vtor, uint32_t num_irq, uint32_t p_interrupt_limit, uint32_t num_disabled_interrupts, uint32_t *disabled_interrupts) {
    #ifdef DEBUG_NVIC
    printf("[NVIC] init_nvic called with vtor: %x, num_irq: %d\n", vtor, num_irq); fflush(stdout);
    #endif

    if(num_irq > PIC32MX_NVIC_NUM_SUPPORTED_INTERRUPTS) {
        num_irq = PIC32MX_NVIC_NUM_SUPPORTED_INTERRUPTS;
    }

    pic32mx_init_irq2vector();
    pic32mx_nvic.active_irq = PIC32MX_NVIC_NONE_ACTIVE;
    pic32mx_nvic.pending_irq = PIC32MX_NVIC_NONE_ACTIVE;
    pic32mx_nvic.pending_sub_prio = PIC32MX_NVIC_LOWEST_PRIO;
    pic32mx_nvic.pending_prio = PIC32MX_NVIC_LOWEST_PRIO;

    pic32mx_nvic.interrupt_count = 0;
    pic32mx_interrupt_limit = p_interrupt_limit;
    pic32mx_num_config_disabled_interrupts = num_disabled_interrupts;

    pic32mx_config_disabled_interrupts = calloc(num_disabled_interrupts, sizeof(*disabled_interrupts));

    for(uint32_t i = 0; i < num_disabled_interrupts; ++i)
        // save disabled IRQs
        pic32mx_config_disabled_interrupts[i] = disabled_interrupts[i];
    

    uc_hook_add(uc, &pic32mx_nvic_block_hook_handle, UC_HOOK_BLOCK_UNCONDITIONAL, pic32mx_nvic_block_hook, &pic32mx_nvic, 1, 0);
    
    // pic32mx_nvic MMIO range write handler to update status
    uc_hook_add(uc, &pic32mx_hook_mmio_write_handle, UC_HOOK_MEM_WRITE, pic32mx_hook_sysctl_mmio_write, NULL, PIC32MX_INTR_CTL_REG_MMIO_BASE, PIC32MX_INTR_CTL_REG_MMIO_END);
    // uc_hook_add(uc, &pic32mx_hook_mmio_read_handle, UC_HOOK_MEM_READ, pic32mx_hook_sysctl_mmio_read, NULL, PIC32MX_INTR_CTL_REG_MMIO_BASE, PIC32MX_INTR_CTL_REG_MMIO_END);

    uc_hook_add(uc, &pic32mx_hook_mmio_write_handle, UC_HOOK_MEM_WRITE, pic32mx_hook_peripheral_ctl_mmio_write, NULL, PIC32MX_PERIPHERAL_CTL_MMIO_BASE, PIC32MX_PERIPHERAL_CTL_MMIO_END);



    subscribe_state_snapshotting(uc, pic32mx_nvic_take_snapshot, pic32mx_nvic_restore_snapshot, pic32mx_nvic_discard_snapshot);

    return UC_ERR_OK;
}