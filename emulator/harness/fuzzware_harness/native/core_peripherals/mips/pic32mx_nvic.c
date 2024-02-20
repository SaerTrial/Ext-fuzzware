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
    pic32mx_hook_mmio_write_handle = -1, pic32mx_hook_mmio_read_handle = -1, pic32mx_hook_eret = -1,
    pic32mx_hook_ei = -1, pic32mx_hook_di = -1;
uint32_t pic32mx_nesting_detector = 0;

// 3. Dynamic State (required for state restore)
struct Pic32mxNVIC pic32mx_nvic __attribute__ ((aligned (64))) = {
    .vtor = PIC32MX_EBASE, // an idle assignment, we don't need this actually
    .num_enabled = 0,
    .EPC = 0xffffffff
};

// forward declaration
static bool pic32mx_recalc_prios();
static void pic32mx_ExceptionEntry(uc_engine *uc);
bool pic32mx_is_disabled_by_config(int exception_no);
static void pic32mx_core_software_interrupt_controller(struct Pic32mxNVIC* arg_nvic);
void pic32mx_update_enabled_irq_list(int irq);


__attribute__ ((hot))
static void pic32mx_nvic_block_hook(uc_engine *uc, uint64_t address, uint32_t size, struct Pic32mxNVIC* arg_nvic) {
        

        #ifdef DISABLE_NESTED_INTERRUPTS
            // Hack: prevent nested interrupt from happening
            // if (pic32mx_nesting_detector == 1){
            //     if ((uint32_t)address == arg_nvic->EPC){
            //         pic32mx_nesting_detector = 0;
            //         // arg_nvic->EPC = 0xffffffff;
                    
            //     }else{
            //         return;
            //     }
            // }
        #endif

            



            pic32mx_core_software_interrupt_controller(arg_nvic);

            if (arg_nvic->is_interrupt_disable) return;

            #ifdef DISABLE_NESTED_INTERRUPTS
            if( arg_nvic->active_irq == PIC32MX_NVIC_NONE_ACTIVE ) {
            #endif
                // reset EPC to guarantee a clean state.
                pic32mx_ExceptionEntry(uc);
            #ifdef DISABLE_NESTED_INTERRUPTS
            }
            #endif
}


static void pic32mx_core_software_interrupt_controller(struct Pic32mxNVIC* arg_nvic){
    PIC32MX_CP0_cause CP0_cause;
    uc_reg_read(arg_nvic->uc, UC_MIPS_REG_CP0_CAUSE, &CP0_cause);
    bool pending = false;

    // core software interrupt 0
    if (CP0_cause.IP0){
        // Caution: only execute once
        // if (pic32mx_nvic.InterruptEnabled[PIC32MX_IRQ_Core_Software_Interrupt_0] == 0){

        //     #ifdef DEBUG_NVIC
        //         printf("[core_software_interrupt_controller] pending irq 1\n");
        //         fflush(stdout);
        //     #endif


        //     pic32mx_nvic.InterruptEnabled[PIC32MX_IRQ_Core_Software_Interrupt_0] = 1;
        //     pic32mx_nvic.InterruptPriority[PIC32MX_IRQ_Core_Software_Interrupt_0] = PIC32MX_NVIC_HIGHEST_PRIO;
        //     pic32mx_nvic.InterruptSubPriority[PIC32MX_IRQ_Core_Software_Interrupt_0] = PIC32MX_NVIC_HIGHEST_SUB_PRIO;
        //     pic32mx_update_enabled_irq_list(PIC32MX_IRQ_Core_Software_Interrupt_0);
        // }

        pic32mx_nvic.InterruptPending[PIC32MX_IRQ_Core_Software_Interrupt_0] = 1;
        CP0_cause.IP0 = 0;
        uc_reg_write(arg_nvic->uc, UC_MIPS_REG_CP0_CAUSE, &CP0_cause);
        pending = true;
        
    }
    // else{
    //         // In general cases, ISR code will clear pending bit via a MMIO write to the interrupt controller
    //         // then this handling is redundant
    //         #ifdef DEBUG_NVIC
    //         if (pic32mx_nvic.InterruptPending[PIC32MX_IRQ_Core_Software_Interrupt_0] == 1){
    //             printf("[core_software_interrupt_controller] unpending irq 1\n");
    //             fflush(stdout);
    //         }
    //         #endif


    //     pic32mx_nvic.InterruptPending[PIC32MX_IRQ_Core_Software_Interrupt_0] = 0;
    //     if (pic32mx_nvic.pending_irq == PIC32MX_IRQ_Core_Software_Interrupt_0) pic32mx_nvic.pending_irq = PIC32MX_NVIC_NONE_ACTIVE;
    // }

    // core software interrupt 1
    if (CP0_cause.IP1){
        // if (pic32mx_nvic.InterruptEnabled[PIC32MX_IRQ_Core_Software_Interrupt_1] == 0){

        //     #ifdef DEBUG_NVIC
        //         printf("[core_software_interrupt_controller] pending irq 2\n");
        //         fflush(stdout);
        //     #endif

        //     pic32mx_nvic.InterruptEnabled[PIC32MX_IRQ_Core_Software_Interrupt_1] = 1;
        //     pic32mx_nvic.InterruptPriority[PIC32MX_IRQ_Core_Software_Interrupt_1] = PIC32MX_NVIC_HIGHEST_PRIO;
        //     pic32mx_nvic.InterruptSubPriority[PIC32MX_IRQ_Core_Software_Interrupt_1] = PIC32MX_NVIC_HIGHEST_SUB_PRIO-1;
        //     pic32mx_update_enabled_irq_list(PIC32MX_IRQ_Core_Software_Interrupt_1);
        // }
        pic32mx_nvic.InterruptPending[PIC32MX_IRQ_Core_Software_Interrupt_1] = 1;
        CP0_cause.IP1 = 0;
        uc_reg_write(arg_nvic->uc, UC_MIPS_REG_CP0_CAUSE, &CP0_cause);
        pending = true;
    }
    // else{
    //         #ifdef DEBUG_NVIC
    //         if (pic32mx_nvic.InterruptPending[PIC32MX_IRQ_Core_Software_Interrupt_1] == 1){
    //             printf("[core_software_interrupt_controller] unpending irq 2\n");
    //             fflush(stdout);
    //         }
    //         #endif

    //     pic32mx_nvic.InterruptPending[PIC32MX_IRQ_Core_Software_Interrupt_1] = 0;
    //     if (pic32mx_nvic.pending_irq == PIC32MX_IRQ_Core_Software_Interrupt_1) pic32mx_nvic.pending_irq = PIC32MX_NVIC_NONE_ACTIVE;
    // }

    // core timer interrupt 0
    // if (CP0_cause.TI){
    //     pic32mx_nvic.InterruptPending[PIC32MX_IRQ_Core_Timer] = 1;
    //     CP0_cause.TI = 0;
    //     uc_reg_write(arg_nvic->uc, UC_MIPS_REG_CP0_CAUSE, &CP0_cause);
    //     pending = true;
    // }
    // else{
    //         #ifdef DEBUG_NVIC
    //         if (pic32mx_nvic.InterruptPending[PIC32MX_IRQ_Core_Timer] == 1){
    //             printf("[core timer interrupt] unpending irq 0\n");
    //             fflush(stdout);
    //         }
    //         #endif

    //     pic32mx_nvic.InterruptPending[PIC32MX_IRQ_Core_Timer] = 0;
    //     if (pic32mx_nvic.pending_irq == PIC32MX_IRQ_Core_Timer) pic32mx_nvic.pending_irq = PIC32MX_NVIC_NONE_ACTIVE;
    // }
    
    if (pending) pic32mx_recalc_prios();
}

// Hack: we update status here by a given IRQ 
// because MMIO accesses don't indicate an IRQ
void pic32mx_pend_interrupt(uc_engine *uc, int exception_no) {

// filtering core software interrupts from external signal
    // we dont allow manipulation on these interrupt sources.
    if (exception_no == PIC32MX_IRQ_Core_Software_Interrupt_0 || exception_no == PIC32MX_IRQ_Core_Software_Interrupt_1){
        #ifdef DEBUG_NVIC
        printf("[pend_interrupt] irq(%d) is not allowed by manual trigger\n", exception_no);
        fflush(stdout);
        #endif
        return;
    }


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
    uint32_t updated_reg;
    uc_mem_read(uc, PIC32MX_IFS0 + (0x10 * (exception_no/32)), &updated_reg, sizeof(updated_reg));
    updated_reg |= (uint32_t)PIC32MX_Set_Bit(1, exception_no % 32);
    uc_mem_write(uc, PIC32MX_IFS0 + (0x10 * (exception_no/32)), &updated_reg, sizeof(updated_reg));    
    
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
    
    PIC32MX_CP0_status CP0_status;
    uc_reg_read(pic32mx_nvic.uc, UC_MIPS_REG_CP0_STATUS, &CP0_status);

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

            if (curr_prio <= CP0_status.IPL ) {
                #ifdef DEBUG_NVIC
                printf("[recalc_prios] curr_prio (%d) <= cp0_status.IPL(%d) \n", curr_prio, CP0_status.IPL);
                #endif
                continue;
            }

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


void pic32mx_update_enabled_interrupts(uc_engine *uc, uint32_t IEC_index, uint32_t value){
    int cur_bit = 0;
    int irq = 0;

    // Hack: we not only record enabled interrupts but also update their priority in pic32mx_nvic
    // in most cases, priority is defined before the interrupt is enabled

    while (cur_bit < 32){
        if (PIC32MX_Get_Bit(value, cur_bit) == 1){

            irq = IEC_index * 32 + cur_bit;

            if(!pic32mx_is_disabled_by_config(irq)){
            
                pic32mx_nvic.InterruptEnabled[irq] = 1;

                pic32mx_update_enabled_irq_list(irq);

            }
        }
        cur_bit ++;
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
                    #ifdef DEBUG_NVIC
                    printf("[NVIC] unpending interrupt flag for irq %d\n", irq);
                    fflush(stdout);
                    #endif
            // Hack: consider as an exception exit
            // if (pic32mx_nvic.active_irq == irq) {
            //     pic32mx_nvic.active_irq = PIC32MX_NVIC_NONE_ACTIVE;
            //         #ifdef DEBUG_NVIC
            //         printf("[NVIC] setting irq %d as non-active \n", irq);
            //         fflush(stdout);
            //         #endif
            //     // check if any pending interrupts
            //     pic32mx_nesting_detector = pic32mx_recalc_prios();
            // }
            break;
        }

        cur_bit ++;
    }
}


void pic32mx_update_enabled_interrupts_priority(uc_engine *uc, uint32_t offset, uint32_t priority){
        uint32_t index = ((offset & ~(0xf)) - PIC32MX_IPC0 )/ 0x10;
        int vector = index * 4; // Note that: it is not an irq but a vector num
        int irq = 0;
        int temp_irq;

        if (PIC32MX_Prio_0(priority) != 0){
            
            for (int i = 0; i < PIC32MX_MIRROR; i++){
                temp_irq = PIC32MX_VectorNum2IRQ[vector][i];

                if (temp_irq == PIC32MX_UNREACHABLE_IRQ) break;

                if(pic32mx_is_disabled_by_config(temp_irq)) continue;

                irq = temp_irq;


                pic32mx_nvic.InterruptPriority[irq] = PIC32MX_Prio_0(priority);
                pic32mx_nvic.InterruptSubPriority[irq] = PIC32MX_Sub_Prio_0(priority);
            }
        }
        else if(PIC32MX_Prio_1(priority) != 0){
            vector += 1;

            for (int i = 0; i < PIC32MX_MIRROR; i++){
                temp_irq = PIC32MX_VectorNum2IRQ[vector][i];
                if (temp_irq == PIC32MX_UNREACHABLE_IRQ) break;

                if(pic32mx_is_disabled_by_config(temp_irq)) continue;
                
                irq = temp_irq;


                pic32mx_nvic.InterruptPriority[irq] = PIC32MX_Prio_1(priority);
                pic32mx_nvic.InterruptSubPriority[irq] = PIC32MX_Sub_Prio_1(priority);
            }
        }
        else if (PIC32MX_Prio_2(priority) != 0){
            vector += 2;
            for (int i = 0; i < PIC32MX_MIRROR; i++){
                temp_irq = PIC32MX_VectorNum2IRQ[vector][i];
                if (temp_irq == PIC32MX_UNREACHABLE_IRQ) break;
                if(pic32mx_is_disabled_by_config(temp_irq)) continue;
                
                irq = temp_irq;
                pic32mx_nvic.InterruptPriority[irq] = PIC32MX_Prio_2(priority);
                pic32mx_nvic.InterruptSubPriority[irq] = PIC32MX_Sub_Prio_2(priority);
            }
        }
        else if (PIC32MX_Prio_3(priority) != 0){
            vector += 3;
            for (int i = 0; i < PIC32MX_MIRROR; i++){
                temp_irq = PIC32MX_VectorNum2IRQ[vector][i];
                if (temp_irq == PIC32MX_UNREACHABLE_IRQ) break;
                if(pic32mx_is_disabled_by_config(temp_irq)) continue;
                
                irq = temp_irq;

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
// void pic32mx_hook_peripheral_ctl_mmio_write(uc_engine *uc, uc_mem_type type,
//                         uint64_t addr, int size, int64_t value, void *user_data) {
//     #ifdef DEBUG_NVIC
//     printf("[NVIC] hook_peripheral_ctl_mmio_write: Write to %08lx, value: %08lx\n", addr, value);
//     fflush(stdout);
//     #endif     

//     // Caution: since we've only noticed that timer is disabled/enabled in running, we thus monitor all timers.
//     // TODO: optimize this switch case
//     switch(addr) {  
//         case PIC32MX_T1CON + PIC32MX_OFFSET_xSET:
//             pic32mx_nvic.InterruptPending[PIC32MX_TIMER_1_VECTOR] = 1;
//             break;
//         case PIC32MX_T1CON + PIC32MX_OFFSET_xCLR:
//             pic32mx_nvic.InterruptPending[PIC32MX_TIMER_1_VECTOR] = 0;
//             break;             
//         case PIC32MX_T2CON + PIC32MX_OFFSET_xSET:
//             pic32mx_nvic.InterruptPending[PIC32MX_TIMER_2_VECTOR] = 1;
//             break;
//         case PIC32MX_T2CON + PIC32MX_OFFSET_xCLR:
//             pic32mx_nvic.InterruptPending[PIC32MX_TIMER_2_VECTOR] = 0;
//             break;            
//         case PIC32MX_T3CON + PIC32MX_OFFSET_xSET:
//             pic32mx_nvic.InterruptPending[PIC32MX_TIMER_3_VECTOR] = 1;
//             break;            
//         case PIC32MX_T3CON + PIC32MX_OFFSET_xCLR:
//             pic32mx_nvic.InterruptPending[PIC32MX_TIMER_3_VECTOR] = 0;
//             break;  
//         case PIC32MX_T4CON + PIC32MX_OFFSET_xSET:
//             pic32mx_nvic.InterruptPending[PIC32MX_TIMER_4_VECTOR] = 1;
//             break; 
//         case PIC32MX_T4CON + PIC32MX_OFFSET_xCLR:
//             pic32mx_nvic.InterruptPending[PIC32MX_TIMER_4_VECTOR] = 0;
//             break; 
//         case PIC32MX_T5CON + PIC32MX_OFFSET_xSET:
//             pic32mx_nvic.InterruptPending[PIC32MX_TIMER_5_VECTOR] = 1;
//             break;   
//         case PIC32MX_T5CON + PIC32MX_OFFSET_xCLR:
//             pic32mx_nvic.InterruptPending[PIC32MX_TIMER_5_VECTOR] = 0;
//             break;  
//         default: break;
//     }


// }


void pic32mx_hook_sysctl_mmio_write(uc_engine *uc, uc_mem_type type,
                        uint64_t addr, int size, int64_t value, void *user_data) {
    #ifdef DEBUG_NVIC
    printf("[NVIC] hook_sysctl_mmio_write: Write to %08lx, value: %08lx\n", addr, value);
    fflush(stdout);
    #endif                     
    uint32_t updated_reg;

    // identify which interrupt control register to be written
    // uint32_t offset = addr & 0xFFF;

    switch(addr) {     
        // interrupt flags
        case PIC32MX_IFS0SET:
            pic32mx_update_pending_interrupts(0, value);
            uc_mem_read(uc, PIC32MX_IFS0, &updated_reg, sizeof(updated_reg));
            updated_reg |= (uint32_t)value;
            uc_mem_write(uc, PIC32MX_IFS0, &updated_reg, sizeof(updated_reg));
            break;
        case PIC32MX_IFS1SET:
            pic32mx_update_pending_interrupts(1, value);
            uc_mem_read(uc, PIC32MX_IFS1, &updated_reg, sizeof(updated_reg));
            updated_reg |= (uint32_t)value;
            uc_mem_write(uc, PIC32MX_IFS1, &updated_reg, sizeof(updated_reg));
            break;
        case PIC32MX_IFS2SET:
            pic32mx_update_pending_interrupts(2, value);
            uc_mem_read(uc, PIC32MX_IFS2, &updated_reg, sizeof(updated_reg));
            updated_reg |= (uint32_t)value;
            uc_mem_write(uc, PIC32MX_IFS2, &updated_reg, sizeof(updated_reg));
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
            uc_mem_read(uc, PIC32MX_IEC0, &updated_reg, sizeof(updated_reg));
            updated_reg |= (uint32_t)value;
            uc_mem_write(uc, PIC32MX_IEC0, &updated_reg, sizeof(updated_reg));
            break;
        case PIC32MX_IEC1SET:
            pic32mx_update_enabled_interrupts(uc, 1, value);
            uc_mem_read(uc, PIC32MX_IEC1, &updated_reg, sizeof(updated_reg));
            updated_reg |= (uint32_t)value;
            uc_mem_write(uc, PIC32MX_IEC1, &updated_reg, sizeof(updated_reg));
            break;
        case PIC32MX_IEC2SET:
            pic32mx_update_enabled_interrupts(uc, 2, value);
            uc_mem_read(uc, PIC32MX_IEC2, &updated_reg, sizeof(updated_reg));
            updated_reg |= (uint32_t)value;
            uc_mem_write(uc, PIC32MX_IEC2, &updated_reg, sizeof(updated_reg));
            break;

        // disable an interrupt
        case PIC32MX_IEC0CLR:
            pic32mx_update_disabled_interrupts(uc, 0, value);
            uc_mem_read(uc, PIC32MX_IEC0, &updated_reg, sizeof(updated_reg));
            updated_reg &= (~(uint32_t)value);
            uc_mem_write(uc, PIC32MX_IEC0, &updated_reg, sizeof(updated_reg));
            break;
        case PIC32MX_IEC1CLR:
            pic32mx_update_disabled_interrupts(uc, 1, value);
            pic32mx_update_disabled_interrupts(uc, 0, value);
            uc_mem_read(uc, PIC32MX_IEC1, &updated_reg, sizeof(updated_reg));
            updated_reg &= (~(uint32_t)value);
            uc_mem_write(uc, PIC32MX_IEC1, &updated_reg, sizeof(updated_reg));
            break;
        case PIC32MX_IEC2CLR:
            pic32mx_update_disabled_interrupts(uc, 2, value);
            pic32mx_update_disabled_interrupts(uc, 0, value);
            uc_mem_read(uc, PIC32MX_IEC2, &updated_reg, sizeof(updated_reg));
            updated_reg &= (~(uint32_t)value);
            uc_mem_write(uc, PIC32MX_IEC2, &updated_reg, sizeof(updated_reg));
            break;

        // interrupt CLR register at the offset of 4 bytes in the associated register, e.g., IFS0CLR
        // crucial to terminate an ISR by setting as non-active
        case PIC32MX_IFS0CLR:
            pic32mx_clear_interrupts(0, value);
            uc_mem_read(uc, PIC32MX_IFS0, &updated_reg, sizeof(updated_reg));
            updated_reg &= (~(uint32_t)value);
            uc_mem_write(uc, PIC32MX_IFS0, &updated_reg, sizeof(updated_reg));
            break;
        case PIC32MX_IFS1CLR:
            pic32mx_clear_interrupts(1, value);
            uc_mem_read(uc, PIC32MX_IFS1, &updated_reg, sizeof(updated_reg));
            updated_reg &= (~(uint32_t)value);
            uc_mem_write(uc, PIC32MX_IFS1, &updated_reg, sizeof(updated_reg));
            break;
        case PIC32MX_IFS2CLR:
            pic32mx_clear_interrupts(2, value);
            uc_mem_read(uc, PIC32MX_IFS2, &updated_reg, sizeof(updated_reg));
            updated_reg &= (~(uint32_t)value);
            uc_mem_write(uc, PIC32MX_IFS2, &updated_reg, sizeof(updated_reg));
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

void pic32mx_5XX_6XX_7XX_init_irq2vector(){
    int index = 0;
    // first ordered tier
    for (; index <= 23; index++){
        PIC32MX_IRQ2VectorNum[index] = index;
        
        PIC32MX_VectorNum2IRQ[index][0] = index;
        PIC32MX_VectorNum2IRQ[index][1] = 255;
    }


    // unordered
    PIC32MX_IRQ2VectorNum[index] = 23; index++; // irq 24 -> vector 23
    PIC32MX_IRQ2VectorNum[index] = 23; index++; // irq 25 -> vector 23

    PIC32MX_VectorNum2IRQ[23][0] = 23;
    PIC32MX_VectorNum2IRQ[23][1] = 255;

    PIC32MX_IRQ2VectorNum[index] = 24; index++; // irq 26 -> vector 24
    PIC32MX_IRQ2VectorNum[index] = 24; index++; // irq 27 -> vector 24
    PIC32MX_IRQ2VectorNum[index] = 24; index++; // irq 28 -> vector 24

    PIC32MX_VectorNum2IRQ[24][0] = 26;
    PIC32MX_VectorNum2IRQ[24][1] = 255;

    PIC32MX_IRQ2VectorNum[index] = 25; index++; // irq 29 -> vector 25
    PIC32MX_IRQ2VectorNum[index] = 25; index++; // irq 30 -> vector 25
    PIC32MX_IRQ2VectorNum[index] = 25; index++; // irq 31 -> vector 25

    PIC32MX_VectorNum2IRQ[25][0] = 29;
    PIC32MX_VectorNum2IRQ[25][1] = 255;


    PIC32MX_IRQ2VectorNum[index] = 26; index++; // irq 32 -> vector 26
    PIC32MX_IRQ2VectorNum[index] = 27; index++; // irq 33 -> vector 27
    PIC32MX_IRQ2VectorNum[index] = 28; index++; // irq 34 -> vector 28    
    PIC32MX_IRQ2VectorNum[index] = 29; index++; // irq 35 -> vector 29
    PIC32MX_IRQ2VectorNum[index] = 30; index++; // irq 36 -> vector 30

    PIC32MX_VectorNum2IRQ[26][0] = 32; PIC32MX_VectorNum2IRQ[26][1] = 255; PIC32MX_VectorNum2IRQ[26][2] = 32; 
    PIC32MX_VectorNum2IRQ[27][0] = 33; PIC32MX_VectorNum2IRQ[27][1] = 255; PIC32MX_VectorNum2IRQ[27][2] = 33; 
    PIC32MX_VectorNum2IRQ[28][0] = 34; PIC32MX_VectorNum2IRQ[28][1] = 255; PIC32MX_VectorNum2IRQ[28][2] = 34; 
    PIC32MX_VectorNum2IRQ[29][0] = 35; PIC32MX_VectorNum2IRQ[29][1] = 255; PIC32MX_VectorNum2IRQ[29][2] = 35; 
    PIC32MX_VectorNum2IRQ[30][0] = 36; PIC32MX_VectorNum2IRQ[30][1] = 255; PIC32MX_VectorNum2IRQ[30][2] = 36; 

    PIC32MX_IRQ2VectorNum[index] = 31; index++; // irq 37 -> vector 31
    PIC32MX_IRQ2VectorNum[index] = 31; index++; // irq 38 -> vector 31   
    PIC32MX_IRQ2VectorNum[index] = 31; index++; // irq 39 -> vector 31

    PIC32MX_VectorNum2IRQ[31][0] = 37; 
    PIC32MX_VectorNum2IRQ[31][1] = 38; 
    PIC32MX_VectorNum2IRQ[31][2] = 39; 
    PIC32MX_VectorNum2IRQ[31][3] = 255; 

    PIC32MX_IRQ2VectorNum[index] = 32; index++; // irq 40 -> vector 32
    PIC32MX_IRQ2VectorNum[index] = 32; index++; // irq 41 -> vector 32   
    PIC32MX_IRQ2VectorNum[index] = 32; index++; // irq 42 -> vector 32

    PIC32MX_VectorNum2IRQ[32][0] = 40; 
    PIC32MX_VectorNum2IRQ[32][1] = 41; 
    PIC32MX_VectorNum2IRQ[32][2] = 42;
    PIC32MX_VectorNum2IRQ[32][3] = 255;  


    PIC32MX_IRQ2VectorNum[index] = 33; index++; // irq 43 -> vector 33
    PIC32MX_IRQ2VectorNum[index] = 33; index++; // irq 44 -> vector 33   
    PIC32MX_IRQ2VectorNum[index] = 33; index++; // irq 45 -> vector 33

    PIC32MX_VectorNum2IRQ[33][0] = 43; 
    PIC32MX_VectorNum2IRQ[33][1] = 44; 
    PIC32MX_VectorNum2IRQ[33][2] = 45; 
    PIC32MX_VectorNum2IRQ[33][2] = 255; 

    PIC32MX_IRQ2VectorNum[index] = 34; index++; // irq 46 -> vector 34
    PIC32MX_IRQ2VectorNum[index] = 35; index++; // irq 47 -> vector 35   
    PIC32MX_IRQ2VectorNum[index] = 36; index++; // irq 48 -> vector 36
    PIC32MX_IRQ2VectorNum[index] = 37; index++; // irq 49 -> vector 37
    PIC32MX_IRQ2VectorNum[index] = 38; index++; // irq 50 -> vector 38   
    PIC32MX_IRQ2VectorNum[index] = 39; index++; // irq 51 -> vector 39

    PIC32MX_VectorNum2IRQ[34][0] = 46; PIC32MX_VectorNum2IRQ[34][1] = 255; PIC32MX_VectorNum2IRQ[34][2] = 46; 
    PIC32MX_VectorNum2IRQ[35][0] = 47; PIC32MX_VectorNum2IRQ[35][1] = 255; PIC32MX_VectorNum2IRQ[35][2] = 47; 
    PIC32MX_VectorNum2IRQ[36][0] = 48; PIC32MX_VectorNum2IRQ[36][1] = 255; PIC32MX_VectorNum2IRQ[36][2] = 48; 
    PIC32MX_VectorNum2IRQ[37][0] = 49; PIC32MX_VectorNum2IRQ[37][1] = 255; PIC32MX_VectorNum2IRQ[37][2] = 49; 
    PIC32MX_VectorNum2IRQ[38][0] = 50; PIC32MX_VectorNum2IRQ[38][1] = 255; PIC32MX_VectorNum2IRQ[38][2] = 50; 
    PIC32MX_VectorNum2IRQ[39][0] = 51; PIC32MX_VectorNum2IRQ[39][1] = 255; PIC32MX_VectorNum2IRQ[39][2] = 51; 

}

void pic32mx_3XX_4XX_init_irq2vector(){
    int index = 0;
    // first ordered tier
    for (; index <= 5; index++){
        PIC32MX_IRQ2VectorNum[index] = index;
    }


    // unordered
    PIC32MX_IRQ2VectorNum[index] = 5; index++; // irq 6 -> vector 5 
    PIC32MX_IRQ2VectorNum[index] = 6; index++; // irq 7 -> vector 6
    PIC32MX_IRQ2VectorNum[index] = 7; index++; // irq 8 -> vector 7
    PIC32MX_IRQ2VectorNum[index] = 8; index++; // irq 9 -> vector 8
    PIC32MX_IRQ2VectorNum[index] = 9; index++; // irq 10 -> vector 9
    PIC32MX_IRQ2VectorNum[index] = 9; index++; // irq 11 -> vector 9
    PIC32MX_IRQ2VectorNum[index] = 10; index++; // irq 12 -> vector 10
    PIC32MX_IRQ2VectorNum[index] = 11; index++; // irq 13 -> vector 11
    PIC32MX_IRQ2VectorNum[index] = 12; index++; // irq 14 -> vector 12
    PIC32MX_IRQ2VectorNum[index] = 13; index++; // irq 15 -> vector 13
    PIC32MX_IRQ2VectorNum[index] = 13; index++; // irq 16 -> vector 13
    PIC32MX_IRQ2VectorNum[index] = 14; index++; // irq 17 -> vector 14
    PIC32MX_IRQ2VectorNum[index] = 15; index++; // irq 18 -> vector 15
    PIC32MX_IRQ2VectorNum[index] = 16; index++; // irq 19 -> vector 16
    PIC32MX_IRQ2VectorNum[index] = 17; index++; // irq 20 -> vector 17
    PIC32MX_IRQ2VectorNum[index] = 17; index++; // irq 21 -> vector 17
    PIC32MX_IRQ2VectorNum[index] = 18; index++; // irq 22 -> vector 18
    PIC32MX_IRQ2VectorNum[index] = 19; index++; // irq 23 -> vector 19
    PIC32MX_IRQ2VectorNum[index] = 20; index++; // irq 24 -> vector 20
    PIC32MX_IRQ2VectorNum[index] = 21; index++; // irq 25 -> vector 21
    PIC32MX_IRQ2VectorNum[index] = 21; index++; // irq 26 -> vector 21
    PIC32MX_IRQ2VectorNum[index] = 22; index++; // irq 27 -> vector 22
    PIC32MX_IRQ2VectorNum[index] = 23; index++; // irq 28 -> vector 23
    PIC32MX_IRQ2VectorNum[index] = 24; index++; // irq 29 -> vector 24
    PIC32MX_IRQ2VectorNum[index] = 25; index++; // irq 30 -> vector 25
    PIC32MX_IRQ2VectorNum[index] = 26; index++; // irq 31 -> vector 26
    PIC32MX_IRQ2VectorNum[index] = 27; index++; // irq 32 -> vector 27
    PIC32MX_IRQ2VectorNum[index] = 28; index++; // irq 33 -> vector 28
    PIC32MX_IRQ2VectorNum[index] = 29; index++; // irq 34 -> vector 29
    PIC32MX_IRQ2VectorNum[index] = 30; index++; // irq 35 -> vector 30
    PIC32MX_IRQ2VectorNum[index] = 30; index++; // irq 36 -> vector 30
    PIC32MX_IRQ2VectorNum[index] = 30; index++; // irq 37 -> vector 30
    PIC32MX_IRQ2VectorNum[index] = 31; index++; // irq 38 -> vector 31
    PIC32MX_IRQ2VectorNum[index] = 31; index++; // irq 39 -> vector 31
    PIC32MX_IRQ2VectorNum[index] = 31; index++; // irq 40 -> vector 31
    PIC32MX_IRQ2VectorNum[index] = 32; index++; // irq 41 -> vector 32
    PIC32MX_IRQ2VectorNum[index] = 32; index++; // irq 42 -> vector 32
    PIC32MX_IRQ2VectorNum[index] = 32; index++; // irq 43 -> vector 32
    PIC32MX_IRQ2VectorNum[index] = 33; index++; // irq 44 -> vector 33
    PIC32MX_IRQ2VectorNum[index] = 33; index++; // irq 45 -> vector 33
    PIC32MX_IRQ2VectorNum[index] = 33; index++; // irq 46 -> vector 33
    PIC32MX_IRQ2VectorNum[index] = 33; index++; // irq 47 -> vector 33
    PIC32MX_IRQ2VectorNum[index] = 33; index++; // irq 48 -> vector 33
    PIC32MX_IRQ2VectorNum[index] = 33; index++; // irq 49 -> vector 33
    PIC32MX_IRQ2VectorNum[index] = 33; index++; // irq 50 -> vector 33
    PIC32MX_IRQ2VectorNum[index] = 34; index++; // irq 51 -> vector 34
    PIC32MX_IRQ2VectorNum[index] = 34; index++; // irq 52 -> vector 34
    PIC32MX_IRQ2VectorNum[index] = 35; index++; // irq 53 -> vector 35
    PIC32MX_IRQ2VectorNum[index] = 35; index++; // irq 54 -> vector 35
    PIC32MX_IRQ2VectorNum[index] = 35; index++; // irq 55 -> vector 35
    PIC32MX_IRQ2VectorNum[index] = 36; index++; // irq 56 -> vector 36
    PIC32MX_IRQ2VectorNum[index] = 36; index++; // irq 57 -> vector 36
    PIC32MX_IRQ2VectorNum[index] = 36; index++; // irq 58 -> vector 36
    PIC32MX_IRQ2VectorNum[index] = 37; index++; // irq 59 -> vector 37
    PIC32MX_IRQ2VectorNum[index] = 37; index++; // irq 60 -> vector 37
    PIC32MX_IRQ2VectorNum[index] = 37; index++; // irq 61 -> vector 37
    PIC32MX_IRQ2VectorNum[index] = 38; index++; // irq 62 -> vector 38
    PIC32MX_IRQ2VectorNum[index] = 38; index++; // irq 63 -> vector 38
    PIC32MX_IRQ2VectorNum[index] = 38; index++; // irq 64 -> vector 38
    PIC32MX_IRQ2VectorNum[index] = 39; index++; // irq 65 -> vector 39
    PIC32MX_IRQ2VectorNum[index] = 39; index++; // irq 66 -> vector 39
    PIC32MX_IRQ2VectorNum[index] = 39; index++; // irq 67 -> vector 39
    PIC32MX_IRQ2VectorNum[index] = 40; index++; // irq 68 -> vector 40
    PIC32MX_IRQ2VectorNum[index] = 40; index++; // irq 69 -> vector 40
    PIC32MX_IRQ2VectorNum[index] = 40; index++; // irq 70 -> vector 40
    PIC32MX_IRQ2VectorNum[index] = 41; index++; // irq 71 -> vector 41
    PIC32MX_IRQ2VectorNum[index] = 42; index++; // irq 72 -> vector 42
    PIC32MX_IRQ2VectorNum[index] = 43; index++; // irq 73 -> vector 43
    PIC32MX_IRQ2VectorNum[index] = 44; index++; // irq 74 -> vector 44
    PIC32MX_IRQ2VectorNum[index] = 45; index++; // irq 75 -> vector 45

    
    PIC32MX_VectorNum2IRQ[0][0] = 0; PIC32MX_VectorNum2IRQ[0][1] = 255; 
    PIC32MX_VectorNum2IRQ[1][0] = 1; PIC32MX_VectorNum2IRQ[1][1] = 255; 
    PIC32MX_VectorNum2IRQ[2][0] = 2; PIC32MX_VectorNum2IRQ[2][1] = 255; 
    PIC32MX_VectorNum2IRQ[3][0] = 3; PIC32MX_VectorNum2IRQ[3][1] = 255; 
    PIC32MX_VectorNum2IRQ[4][0] = 4; PIC32MX_VectorNum2IRQ[4][1] = 255; 
    PIC32MX_VectorNum2IRQ[5][0] = 5; PIC32MX_VectorNum2IRQ[5][1] = 6; PIC32MX_VectorNum2IRQ[5][2] = 255;
    PIC32MX_VectorNum2IRQ[6][0] = 7; PIC32MX_VectorNum2IRQ[6][1] = 255;
    PIC32MX_VectorNum2IRQ[7][0] = 8; PIC32MX_VectorNum2IRQ[7][1] = 255;
    PIC32MX_VectorNum2IRQ[8][0] = 9; PIC32MX_VectorNum2IRQ[8][1] = 255;
    PIC32MX_VectorNum2IRQ[9][0] = 10; PIC32MX_VectorNum2IRQ[9][1] = 11; PIC32MX_VectorNum2IRQ[9][2] = 255;
    PIC32MX_VectorNum2IRQ[10][0] = 12; PIC32MX_VectorNum2IRQ[10][1] = 255;
    PIC32MX_VectorNum2IRQ[11][0] = 13; PIC32MX_VectorNum2IRQ[11][1] = 255;
    PIC32MX_VectorNum2IRQ[12][0] = 14; PIC32MX_VectorNum2IRQ[12][1] = 255;
    PIC32MX_VectorNum2IRQ[13][0] = 15; PIC32MX_VectorNum2IRQ[13][1] = 16; PIC32MX_VectorNum2IRQ[13][2] = 255;
    PIC32MX_VectorNum2IRQ[14][0] = 17; PIC32MX_VectorNum2IRQ[14][1] = 255;
    PIC32MX_VectorNum2IRQ[15][0] = 18; PIC32MX_VectorNum2IRQ[15][1] = 255;
    PIC32MX_VectorNum2IRQ[16][0] = 19; PIC32MX_VectorNum2IRQ[16][1] = 255;
    PIC32MX_VectorNum2IRQ[17][0] = 20; PIC32MX_VectorNum2IRQ[17][1] = 21; PIC32MX_VectorNum2IRQ[17][2] = 255;
    PIC32MX_VectorNum2IRQ[18][0] = 22; PIC32MX_VectorNum2IRQ[18][1] = 255;
    PIC32MX_VectorNum2IRQ[19][0] = 23; PIC32MX_VectorNum2IRQ[19][1] = 255;
    PIC32MX_VectorNum2IRQ[20][0] = 24; PIC32MX_VectorNum2IRQ[20][1] = 255;
    PIC32MX_VectorNum2IRQ[21][0] = 25; PIC32MX_VectorNum2IRQ[21][1] = 26; PIC32MX_VectorNum2IRQ[21][2] = 255;
    PIC32MX_VectorNum2IRQ[22][0] = 27; PIC32MX_VectorNum2IRQ[22][1] = 255;
    PIC32MX_VectorNum2IRQ[23][0] = 28; PIC32MX_VectorNum2IRQ[23][1] = 255;
    PIC32MX_VectorNum2IRQ[24][0] = 29; PIC32MX_VectorNum2IRQ[24][1] = 255;
    PIC32MX_VectorNum2IRQ[25][0] = 30; PIC32MX_VectorNum2IRQ[25][1] = 255;
    PIC32MX_VectorNum2IRQ[26][0] = 31; PIC32MX_VectorNum2IRQ[26][1] = 255;
    PIC32MX_VectorNum2IRQ[27][0] = 32; PIC32MX_VectorNum2IRQ[27][1] = 255;
    PIC32MX_VectorNum2IRQ[28][0] = 33; PIC32MX_VectorNum2IRQ[28][1] = 255;
    PIC32MX_VectorNum2IRQ[29][0] = 34; PIC32MX_VectorNum2IRQ[29][1] = 255;
    PIC32MX_VectorNum2IRQ[30][0] = 35; PIC32MX_VectorNum2IRQ[30][1] = 36; PIC32MX_VectorNum2IRQ[30][2] = 37; PIC32MX_VectorNum2IRQ[30][3] = 255;
    PIC32MX_VectorNum2IRQ[31][0] = 38; PIC32MX_VectorNum2IRQ[31][1] = 39; PIC32MX_VectorNum2IRQ[31][2] = 40; PIC32MX_VectorNum2IRQ[31][3] = 255; 
    PIC32MX_VectorNum2IRQ[32][0] = 41; PIC32MX_VectorNum2IRQ[32][1] = 42; PIC32MX_VectorNum2IRQ[32][2] = 43; PIC32MX_VectorNum2IRQ[32][3] = 255; 
    PIC32MX_VectorNum2IRQ[33][0] = 44; PIC32MX_VectorNum2IRQ[33][1] = 45; PIC32MX_VectorNum2IRQ[33][2] = 46; PIC32MX_VectorNum2IRQ[33][3] = 47; PIC32MX_VectorNum2IRQ[33][4] = 48; PIC32MX_VectorNum2IRQ[33][5] = 49; PIC32MX_VectorNum2IRQ[33][6] = 50; PIC32MX_VectorNum2IRQ[33][7] = 255; 
    PIC32MX_VectorNum2IRQ[34][0] = 51; PIC32MX_VectorNum2IRQ[34][1] = 52; PIC32MX_VectorNum2IRQ[34][2] = 255;
    PIC32MX_VectorNum2IRQ[35][0] = 53; PIC32MX_VectorNum2IRQ[35][1] = 54; PIC32MX_VectorNum2IRQ[35][2] = 55; PIC32MX_VectorNum2IRQ[35][3] = 255;
    PIC32MX_VectorNum2IRQ[36][0] = 56; PIC32MX_VectorNum2IRQ[36][1] = 57; PIC32MX_VectorNum2IRQ[36][2] = 58; PIC32MX_VectorNum2IRQ[36][3] = 255;
    PIC32MX_VectorNum2IRQ[37][0] = 59; PIC32MX_VectorNum2IRQ[37][1] = 60; PIC32MX_VectorNum2IRQ[37][2] = 61; PIC32MX_VectorNum2IRQ[37][3] = 255;
    PIC32MX_VectorNum2IRQ[38][0] = 62; PIC32MX_VectorNum2IRQ[38][1] = 63; PIC32MX_VectorNum2IRQ[38][2] = 64; PIC32MX_VectorNum2IRQ[38][3] = 255;
    PIC32MX_VectorNum2IRQ[39][0] = 65; PIC32MX_VectorNum2IRQ[39][1] = 66; PIC32MX_VectorNum2IRQ[39][2] = 67; PIC32MX_VectorNum2IRQ[39][3] = 255;
    PIC32MX_VectorNum2IRQ[40][0] = 68; PIC32MX_VectorNum2IRQ[40][1] = 69; PIC32MX_VectorNum2IRQ[40][2] = 70; PIC32MX_VectorNum2IRQ[40][3] = 255;
    PIC32MX_VectorNum2IRQ[41][0] = 71; PIC32MX_VectorNum2IRQ[41][1] = 255; 
    PIC32MX_VectorNum2IRQ[42][0] = 72; PIC32MX_VectorNum2IRQ[42][1] = 255; 
    PIC32MX_VectorNum2IRQ[43][0] = 73; PIC32MX_VectorNum2IRQ[43][1] = 255;
    PIC32MX_VectorNum2IRQ[44][0] = 74; PIC32MX_VectorNum2IRQ[44][1] = 255; 
    PIC32MX_VectorNum2IRQ[45][0] = 75; PIC32MX_VectorNum2IRQ[45][1] = 255;  
}

// callback for eret instruction.
static void hook_eret(uc_engine *uc, uint32_t EPC, struct Pic32mxNVIC* arg_nvic)
{
    #ifdef DEBUG_NVIC
        uint32_t pc;
        uc_reg_read(uc, UC_MIPS_REG_PC, &pc);
        printf("[hook_eret] eret at 0x%x is pointing to 0x%x\n", pc, EPC); fflush(stdout);
    #endif
    if (arg_nvic->active_irq != PIC32MX_NVIC_NONE_ACTIVE){
        
        #ifdef DEBUG_NVIC
            printf("[hook_eret] proactively unpending irq(%d) while facing ERET instruction \n", arg_nvic->active_irq); fflush(stdout);
        #endif
        
        arg_nvic->InterruptPending[arg_nvic->active_irq] = 0;
        arg_nvic->active_irq = PIC32MX_NVIC_NONE_ACTIVE;
        pic32mx_recalc_prios();
    }
    arg_nvic->is_interrupt_disable = false;
}


static void hook_ei(uc_engine *uc, uint32_t data, struct Pic32mxNVIC* arg_nvic){
    arg_nvic->is_interrupt_disable = false;
}

static void hook_di(uc_engine *uc, uint32_t data, struct Pic32mxNVIC* arg_nvic){
    arg_nvic->is_interrupt_disable = true;
}



uc_err pic32mx_init_nvic(uc_engine *uc, uint32_t vtor, uint32_t num_irq, uint32_t p_interrupt_limit, uint32_t num_disabled_interrupts, uint32_t *disabled_interrupts, uint32_t family) {
    #ifdef DEBUG_NVIC
    printf("[NVIC] init_nvic called with vtor: %x, num_irq: %d\n", vtor, num_irq); fflush(stdout);
    #endif

    if(num_irq > PIC32MX_NVIC_NUM_SUPPORTED_INTERRUPTS) {
        num_irq = PIC32MX_NVIC_NUM_SUPPORTED_INTERRUPTS;
    }

    if (family == FAMILY_PIC32MX5XX_6XX_7XX)
        pic32mx_5XX_6XX_7XX_init_irq2vector();
    if (family == FAMILY_PIC32MX3XX_4XX) 
        pic32mx_3XX_4XX_init_irq2vector();

    pic32mx_nvic.active_irq = PIC32MX_NVIC_NONE_ACTIVE;
    pic32mx_nvic.pending_irq = PIC32MX_NVIC_NONE_ACTIVE;
    pic32mx_nvic.pending_sub_prio = PIC32MX_NVIC_LOWEST_PRIO;
    pic32mx_nvic.pending_prio = PIC32MX_NVIC_LOWEST_PRIO;
    pic32mx_nvic.uc = uc;
    pic32mx_nvic.interrupt_count = 0;
    pic32mx_nvic.is_interrupt_disable = false;
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

    // uc_hook_add(uc, &pic32mx_hook_mmio_write_handle, UC_HOOK_MEM_WRITE, pic32mx_hook_peripheral_ctl_mmio_write, NULL, PIC32MX_PERIPHERAL_CTL_MMIO_BASE, PIC32MX_PERIPHERAL_CTL_MMIO_END);

    uc_hook_add(uc, &pic32mx_hook_eret, UC_HOOK_INSN, hook_eret, &pic32mx_nvic, 1, 0, UC_MIPS_INS_ERET);
    uc_hook_add(uc, &pic32mx_hook_ei, UC_HOOK_INSN, hook_ei, &pic32mx_nvic, 1, 0, UC_MIPS_INS_EI);
    uc_hook_add(uc, &pic32mx_hook_di, UC_HOOK_INSN, hook_di, &pic32mx_nvic, 1, 0, UC_MIPS_INS_DI);


    subscribe_state_snapshotting(uc, pic32mx_nvic_take_snapshot, pic32mx_nvic_restore_snapshot, pic32mx_nvic_discard_snapshot);

    return UC_ERR_OK;
}