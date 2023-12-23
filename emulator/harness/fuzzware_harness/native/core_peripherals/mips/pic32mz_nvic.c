
#include "pic32mz_nvic.h"

#define PIC32MZ_NVIC_NONE_ACTIVE -1
#define PIC32MZ_NVIC_LOWEST_PRIO -1
#define PIC32MZ_NVIC_HIGHEST_PRIO 7
#define PIC32MZ_NVIC_HIGHEST_SUB_PRIO 3
#define PIC32MZ_NVIC_LOWEST_SUB_PRIO 0
#define DEBUG_NVIC

// We may not want to allow nested interrupts
#define DISABLE_NESTED_INTERRUPTS

uint32_t pic32mz_interrupt_limit = 0;
uint32_t pic32mz_num_config_disabled_interrupts = 0;
uint32_t *pic32mz_config_disabled_interrupts = NULL;
uc_hook pic32mz_nvic_block_hook_handle = -1, pic32mz_nvic_exception_return_hook_handle=-1,
    pic32mz_hook_mmio_write_handle = -1, pic32mz_hook_mmio_read_handle = -1;
uint32_t nesting_detector = 0;

// 3. Dynamic State (required for state restore)
struct Pic32mzNVIC pic32mz_nvic __attribute__ ((aligned (64))) = {
    .vtor = PIC32MZ_EBASE, // an idle assignment, we don't need this actually
    .NonPersistantIRQs = {0,1,2,3,4,7,8,9,12,13,14,17,18,19,22,23,24,27,28,31,32,35,36,39,40,43,104,130,131,134,135,136,137,138,139,140,141,166,167},
    .num_enabled = 0
};

// forward declaration
static bool pic32mz_recalc_prios();
static void pic32mz_ExceptionEntry(uc_engine *uc);
bool pic32mz_is_disabled_by_config(int exception_no);
static void pic32mz_core_software_interrupt_controller(uc_engine *uc);
void update_enabled_irq_list(int irq);



__attribute__ ((hot))
static void pic32mz_nvic_block_hook(uc_engine *uc, uint64_t address, uint32_t size, struct Pic32mzNVIC* arg_nvic) {
        

        #ifdef DISABLE_NESTED_INTERRUPTS
            // Hack: prevent nested interrupt from happening
            if (nesting_detector == 1){
                if ((uint32_t)address == arg_nvic->EPC){
                    nesting_detector = 0;
                }else{
                    return;
                }
            }
        #endif
        

            pic32mz_core_software_interrupt_controller(uc);
            if( arg_nvic->active_irq == PIC32MZ_NVIC_NONE_ACTIVE ) {
                pic32mz_ExceptionEntry(uc);
            }
        
        
}


//  Hack: we need to manually detect if any core software interrupt request
//  since generally they are not configured in interrupt control MMIO range but in CP0 cause register
//  Cause: application code doesn't set up prioritization for these, we, by default, prioritize them in a manner, like lowest irq with highest prio
//  In the meanwhile, we assume these two are in higher priority than other interrupt sources
static void pic32mz_core_software_interrupt_controller(uc_engine *uc){
    PIC32MZ_CP0_cause CP0_cause;
    uc_reg_read(uc, UC_MIPS_REG_CP0_CAUSE, &CP0_cause);
    // core software interrupt 0
    if (CP0_cause.IP0){
        // Caution: only execute once
        if (pic32mz_nvic.InterruptEnabled[PIC32MZ_IRQ_Core_Software_Interrupt_0] == 0){
            pic32mz_nvic.InterruptEnabled[PIC32MZ_IRQ_Core_Software_Interrupt_0] = 1;
            pic32mz_nvic.InterruptPriority[PIC32MZ_IRQ_Core_Software_Interrupt_0] = PIC32MZ_NVIC_HIGHEST_PRIO;
            pic32mz_nvic.InterruptSubPriority[PIC32MZ_IRQ_Core_Software_Interrupt_0] = PIC32MZ_NVIC_HIGHEST_SUB_PRIO;
            update_enabled_irq_list(PIC32MZ_IRQ_Core_Software_Interrupt_0);
        }
        pic32mz_nvic.InterruptPending[PIC32MZ_IRQ_Core_Software_Interrupt_0] = 1;
        pic32mz_recalc_prios();

    }else{
            // In general cases, ISR code will clear pending bit via a MMIO write to the interrupt controller
            // then this handling is redundant
            #ifdef DEBUG_NVIC
            if (pic32mz_nvic.InterruptPending[PIC32MZ_IRQ_Core_Software_Interrupt_0] == 1){
                printf("[core_software_interrupt_controller] unpending irq 1\n");
                fflush(stdout);
            }
            #endif


        pic32mz_nvic.InterruptPending[PIC32MZ_IRQ_Core_Software_Interrupt_0] = 0;
    }

    // core software interrupt 1
    if (CP0_cause.IP1){
        if (pic32mz_nvic.InterruptEnabled[PIC32MZ_IRQ_Core_Software_Interrupt_1] == 0){
            pic32mz_nvic.InterruptEnabled[PIC32MZ_IRQ_Core_Software_Interrupt_1] = 1;
            pic32mz_nvic.InterruptPriority[PIC32MZ_IRQ_Core_Software_Interrupt_1] = PIC32MZ_NVIC_HIGHEST_PRIO;
            pic32mz_nvic.InterruptSubPriority[PIC32MZ_IRQ_Core_Software_Interrupt_1] = PIC32MZ_NVIC_HIGHEST_SUB_PRIO-1;
            update_enabled_irq_list(PIC32MZ_IRQ_Core_Software_Interrupt_1);
        }
        pic32mz_nvic.InterruptPending[PIC32MZ_IRQ_Core_Software_Interrupt_1] = 1;
    }else{
            #ifdef DEBUG_NVIC
            if (pic32mz_nvic.InterruptPending[PIC32MZ_IRQ_Core_Software_Interrupt_1] == 1){
                printf("[core_software_interrupt_controller] unpending irq 2\n");
                fflush(stdout);
            }
            #endif

        pic32mz_nvic.InterruptPending[PIC32MZ_IRQ_Core_Software_Interrupt_1] = 0;
    }

    
    

}

// Hack: we update status here by a given IRQ 
// because MMIO accesses don't indicate an IRQ
void pic32mz_pend_interrupt(uc_engine *uc, int exception_no) {
    #ifdef DEBUG_NVIC
    printf("[pend_interrupt] irq=%d, active_irq=%d\n", exception_no, pic32mz_nvic.active_irq);
    fflush(stdout);
    #endif
    if(pic32mz_nvic.InterruptPending[exception_no] == 0) {
        pic32mz_nvic.InterruptPending[exception_no] = 1;

        // set IFSx bit
        // int index = exception_no / 32;
        // uint32_t value;
        // uc_reg_read(uc, PIC32MZ_EBASE + PIC32MZ_IFS0 + index * 0x10, &value);
        // value = PIC32MZ_Set_Bit(value, exception_no % 32);
        // uc_reg_write(uc, PIC32MZ_EBASE + PIC32MZ_IFS0 + index * 0x10, &value);

        // read enabled bit in IEC registers
        // uc_reg_read(uc, PIC32MZ_EBASE + PIC32MZ_IEC0 + index * 0x10, &value);
        // pic32mz_nvic.InterruptEnabled[exception_no] = PIC32MZ_Get_Bit(value, exception_no % 32);



        pic32mz_recalc_prios();
    }else if (pic32mz_nvic.InterruptPending[exception_no] == 1 && \
    pic32mz_nvic.InterruptEnabled[exception_no] == 1){
        pic32mz_recalc_prios();
    }
}


static void pic32mz_ExceptionEntry(uc_engine *uc) {  
    // interrupt trigger sends an IRQ too early and the actual enabling of interrupts hasn't been done.
    if (pic32mz_nvic.pending_irq == PIC32MZ_NVIC_NONE_ACTIVE) return;

    #ifdef DEBUG_NVIC
    printf("[NVIC] ExceptionEntry\n"); fflush(stdout);
    #endif

    if (pic32mz_nvic.active_irq != PIC32MZ_NVIC_NONE_ACTIVE){
        // CAUTION: preempting an existing interrupt
        // we come into a nested interrupt process

        bool is_persistant = true;
        // Or we just care about persistant interrupts
        for (int i = 0; i < sizeof(pic32mz_nvic.NonPersistantIRQs)/sizeof(pic32mz_nvic.NonPersistantIRQs[0]); i++){
            if ((uint8_t)pic32mz_nvic.pending_irq == pic32mz_nvic.NonPersistantIRQs[i]){
                is_persistant = false;
                break;
            }
        }
        
        // we can't take precedence
        if(is_persistant) 
        {
            #ifdef DEBUG_NVIC
                printf("[NVIC] The current IRQ is not preemptable!\n"); fflush(stdout);
            #endif
            return;
        }

        // due to X32 compiler prologue automatically preserves context for the further interrupts,
        // we don't need to handle anything, but inform the emulator
        #ifdef DEBUG_NVIC
            printf("[NVIC] Preempting an existing interrupt!\n"); fflush(stdout);
        #endif
    }
    
    // Store the current PC in EPC
    uint32_t epc;
    uc_reg_read(uc, UC_MIPS_REG_PC, &epc);
    uc_reg_write(uc, UC_MIPS_REG_CP0_EPC, &epc);
    pic32mz_nvic.EPC = epc;

    // Find the ISR entry point and set it
    // EPC to return
    uint32_t ExceptionNumber = pic32mz_nvic.pending_irq;
    uint32_t isr_entry = PIC32MZ_EBASE;
    uint32_t OFFx = PIC32MZ_OFF000 + 4 * ExceptionNumber ;
    uint32_t ISR_offset;
    
    uc_mem_read(uc, PIC32MZ_INTR_CTL_REG_MMIO_BASE + OFFx, &ISR_offset, sizeof(ISR_offset));
    isr_entry += ISR_offset; //e.g., 0x9d000000 + 0x200
    uc_reg_write(uc, UC_MIPS_REG_PC, &isr_entry);

    #ifdef DEBUG_NVIC
    printf("Redirecting irq %d to isr: %08x, EPC: %08x\n", ExceptionNumber, isr_entry, epc);
    #endif

    // Update pic32mz_nvic state with new active interrupt
    // pic32mz_nvic.InterruptPending[ExceptionNumber] = 0;
    // we clear pending bit in a MMIO write access to IFSxCLR
    pic32mz_nvic.active_irq = ExceptionNumber;

    // We need to re-calculate the pending priority state
    pic32mz_recalc_prios();

    #ifdef DEBUG_NVIC
    puts("************ POST ExceptionEntry");
    print_state(uc);
    #endif

}

uint16_t pic32mz_get_num_enabled() {
    return pic32mz_nvic.num_enabled;
}

uint8_t pic32mz_nth_enabled_irq_num(uint8_t n) {
    return pic32mz_nvic.enabled_irqs[n % pic32mz_nvic.num_enabled];
}

void pic32mz_nvic_set_pending(uc_engine *uc, uint32_t irq, int delay_activation) {
    pic32mz_pend_interrupt(uc, irq);
    // maybe_activate(uc, false);
}


void * pic32mz_nvic_take_snapshot(uc_engine *uc) {
    size_t size = sizeof(pic32mz_nvic);

    // NVIC snapshot: save the sysreg mem page
    char *result = malloc(size + PAGE_SIZE);
    memcpy(result, &pic32mz_nvic, size);
    uc_mem_read(uc, PIC32MZ_INTR_CTL_REG_MMIO_BASE, result + size, PAGE_SIZE);

    return result;
}

void pic32mz_nvic_restore_snapshot(uc_engine *uc, void *snapshot) {
    // Restore the pic32mz_nvic
    memcpy(&pic32mz_nvic, snapshot, sizeof(pic32mz_nvic));
    // Restore the sysreg mem page
    uc_mem_write(uc, PIC32MZ_INTR_CTL_REG_MMIO_BASE, ((char *) snapshot) + sizeof(pic32mz_nvic), PAGE_SIZE);
}

void pic32mz_nvic_discard_snapshot(uc_engine *uc, void *snapshot) {
    free(snapshot);
}


/*
 * Re-calculate pic32mz_nvic interrupt prios and determine the next interrupt
 * (i.e., a higher-prio interrupt is now pending)
 */
static bool pic32mz_recalc_prios() {
    int highest_pending_prio = PIC32MZ_NVIC_LOWEST_PRIO;
    int highest_pending_sub_prio = PIC32MZ_NVIC_LOWEST_PRIO;
    int highest_pending_irq = PIC32MZ_NVIC_NONE_ACTIVE;
    

    // iterate all enabled and pending interrupts
    // sort the highest irq out
    // the active interrupt should be excluded
    for(int i = 0; i < pic32mz_nvic.num_enabled; ++i) {
        int irq = pic32mz_nvic.enabled_irqs[i];
        int curr_prio = pic32mz_nvic.InterruptPriority[irq];
        int curr_sub_prio = pic32mz_nvic.InterruptSubPriority[irq];
        
        #ifdef DEBUG_NVIC
           printf("[recalc_prios] irq:%d,  irq_prio:%d, irq_sub_prio:%d\n", irq, curr_prio, curr_sub_prio);
        #endif

        if(pic32mz_nvic.InterruptPending[irq] && pic32mz_nvic.active_irq != irq) {
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


    pic32mz_nvic.pending_prio = highest_pending_prio;
    pic32mz_nvic.pending_sub_prio = highest_pending_sub_prio;
    pic32mz_nvic.pending_irq = highest_pending_irq;

    // no change
    if (highest_pending_irq == PIC32MZ_NVIC_LOWEST_PRIO)
        return false;

    return true;
}


void update_enabled_irq_list(int irq){
    int i = 0;
    for(; i < pic32mz_nvic.num_enabled; ++i) {
        if(pic32mz_nvic.enabled_irqs[i] > irq) {
            memmove(&pic32mz_nvic.enabled_irqs[i+1], &pic32mz_nvic.enabled_irqs[i], (pic32mz_nvic.num_enabled-i) * sizeof(pic32mz_nvic.enabled_irqs[0]));
            break;
        }
    }

    pic32mz_nvic.enabled_irqs[i] = irq;
    ++pic32mz_nvic.num_enabled;

    #ifdef DEBUG_NVIC
    printf("[update_enabled_irq_list] \n");
    for(i=0; i < pic32mz_nvic.num_enabled; ++i) {
        printf("irq = %d\n", pic32mz_nvic.enabled_irqs[i]);
    }
    fflush(stdout);
    #endif

}


void pic32mz_update_enabled_interrupts(uc_engine *uc, uint32_t IEC_index, uint32_t value){
    int cur_bit = 0;
    int irq = 0;

    // Hack: we not only record enabled interrupts but also update their priority in pic32mz_nvic
    // in most cases, priority is defined before the interrupt is enabled

    while (cur_bit < 32){
        if (PIC32MZ_Get_Bit(value, cur_bit) == 1){

            irq = IEC_index * 32 + cur_bit;

            if(pic32mz_is_disabled_by_config(irq)) break;
            
            pic32mz_nvic.InterruptEnabled[irq] = 1;
            // pic32mz_nvic.InterruptPending[irq] = 0;

            // update priority
            // priority, sub-priority
            int index = irq / 4;
            uint32_t priority;
            uc_reg_read(uc, PIC32MZ_EBASE + PIC32MZ_IPC0 + index * 0x10, &priority);
            switch (irq % 4)
            {
            case 0:
                pic32mz_nvic.InterruptPriority[irq] = PIC32MZ_Prio_0(priority);
                pic32mz_nvic.InterruptSubPriority[irq] = PIC32MZ_Sub_Prio_0(priority);
                break;
            case 1:
                pic32mz_nvic.InterruptPriority[irq] = PIC32MZ_Prio_1(priority);
                pic32mz_nvic.InterruptSubPriority[irq] = PIC32MZ_Sub_Prio_1(priority);
                break;
            case 2:
                pic32mz_nvic.InterruptPriority[irq] = PIC32MZ_Prio_2(priority);
                pic32mz_nvic.InterruptSubPriority[irq] = PIC32MZ_Sub_Prio_2(priority);
                break;
            case 3:
                pic32mz_nvic.InterruptPriority[irq] = PIC32MZ_Prio_3(priority);
                pic32mz_nvic.InterruptSubPriority[irq] = PIC32MZ_Sub_Prio_3(priority);
                break;
            }

            update_enabled_irq_list(irq);
            break;
        }
        cur_bit ++;
    }

}


void pic32mz_update_pending_interrupts(uint32_t IFS_index, uint32_t value){
    int cur_bit = 0;
    int irq = 0;

    while (cur_bit < 32){
        if (PIC32MZ_Get_Bit(value, cur_bit) == 1){
            irq = IFS_index * 32 + cur_bit;
            pic32mz_nvic.InterruptPending[irq] = 1;
            break;
        }

        cur_bit ++;
    }
}


void pic32mz_clear_interrupts(uint32_t IFSxCLR_index, uint32_t value){
    int cur_bit = 0;
    int irq = 0;
    while (cur_bit < 32){
        if (PIC32MZ_Get_Bit(value, cur_bit) == 1){
            irq = IFSxCLR_index * 32 + cur_bit;
            pic32mz_nvic.InterruptPending[irq] = 0;
            // Hack: consider as an exception exit
            if (pic32mz_nvic.active_irq == irq) {
                pic32mz_nvic.active_irq = PIC32MZ_NVIC_NONE_ACTIVE;
                    #ifdef DEBUG_NVIC
                    printf("[NVIC] setting irq %d as non-active \n", irq);
                    fflush(stdout);
                    #endif
                // check if any pending interrupts
                nesting_detector = pic32mz_recalc_prios();
            }
            break;
        }

        cur_bit ++;
    }
}



void pic32mz_hook_sysctl_mmio_write(uc_engine *uc, uc_mem_type type,
                        uint64_t addr, int size, int64_t value, void *user_data) {
    #ifdef DEBUG_NVIC
    printf("[NVIC] hook_sysctl_mmio_write: Write to %08lx, value: %08lx\n", addr, value);
    fflush(stdout);
    #endif                     
    

    // identify which interrupt control register to be written
    uint32_t offset = addr & 0xFFF;

    switch(offset) {     
        // interrupt flags
        case PIC32MZ_IFS0:
            pic32mz_update_pending_interrupts(0, value);
            break;
        case PIC32MZ_IFS1:
            pic32mz_update_pending_interrupts(1, value);
            break;
        case PIC32MZ_IFS2:
            pic32mz_update_pending_interrupts(2, value);
            break;
        case PIC32MZ_IFS3:
            pic32mz_update_pending_interrupts(3, value);
            break;
        case PIC32MZ_IFS4:
            pic32mz_update_pending_interrupts(4, value);
            break;
        case PIC32MZ_IFS5:
            pic32mz_update_pending_interrupts(5, value);
            break;

        // interrupt mask
        // Hack: once a write to the below registers corresponding to 
        // we then iterate enabled interrupts through this register, each register records 32 IRQ
        case PIC32MZ_IEC0:
            pic32mz_update_enabled_interrupts(uc, 0, value);
            break;
        case PIC32MZ_IEC1:
            pic32mz_update_enabled_interrupts(uc, 1, value);
            break;
        case PIC32MZ_IEC2:
            pic32mz_update_enabled_interrupts(uc, 2, value);
            break;
        case PIC32MZ_IEC3:
            pic32mz_update_enabled_interrupts(uc, 3, value);
            break;
        case PIC32MZ_IEC4:
            pic32mz_update_enabled_interrupts(uc, 4, value);
            break;
        case PIC32MZ_IEC5:
            pic32mz_update_enabled_interrupts(uc, 5, value);
            break;

        // enable an interrupt
        // same as above, but some system code utilizes this register
        case PIC32MZ_IEC0 + PIC32MZ_OFFSET_IECxSET:
            pic32mz_update_enabled_interrupts(uc, 0, value);
            break;
        case PIC32MZ_IEC1 + PIC32MZ_OFFSET_IECxSET:
            pic32mz_update_enabled_interrupts(uc, 1, value);
            break;
        case PIC32MZ_IEC2 + PIC32MZ_OFFSET_IECxSET:
            pic32mz_update_enabled_interrupts(uc, 2, value);
            break;
        case PIC32MZ_IEC3 + PIC32MZ_OFFSET_IECxSET:
            pic32mz_update_enabled_interrupts(uc, 3, value);
            break;
        case PIC32MZ_IEC4 + PIC32MZ_OFFSET_IECxSET:
            pic32mz_update_enabled_interrupts(uc, 4, value);
            break;
        case PIC32MZ_IEC5 + PIC32MZ_OFFSET_IECxSET:
            pic32mz_update_enabled_interrupts(uc, 5, value);
            break;        

        // interrupt CLR register at the offset of 4 bytes in the associated register, e.g., IFS0CLR
        // crucial to terminate an ISR by setting as non-active
        case PIC32MZ_IFS0CLR:
            pic32mz_clear_interrupts(0, value);
            break;
        case PIC32MZ_IFS1CLR:
            pic32mz_clear_interrupts(1, value);
            break;
        case PIC32MZ_IFS2CLR:
            pic32mz_clear_interrupts(2, value);
            break;
        case PIC32MZ_IFS3CLR:
            pic32mz_clear_interrupts(3, value);
            break;
        case PIC32MZ_IFS4CLR:
            pic32mz_clear_interrupts(4, value);
            break;
        case PIC32MZ_IFS5CLR:
            pic32mz_clear_interrupts(5, value);
            break;       


        case PIC32MZ_IPC0 ... PIC32MZ_IPC12:
            // interrupt priority
            // we may need to update prio on pic32mz_nvic structure?
            // no, we can't acquire an IRQ number from the given address
            break;
        case PIC32MZ_OFF000 ... (PIC32MZ_OFF000 + 4*PIC32MZ_NUM_OFFX): break;
            // OFFx registers
        case PIC32MZ_INTCON:    break;
        case PIC32MZ_INTSTAT:   break;
        default: break;
    }


}

bool pic32mz_is_disabled_by_config(int exception_no) {
    for(int i = 0; i < pic32mz_num_config_disabled_interrupts; ++i) {
        if(pic32mz_config_disabled_interrupts[i] == exception_no) {
            return true;
        }
    }

    return false;
}


uc_err pic32mz_init_nvic(uc_engine *uc, uint32_t vtor, uint32_t num_irq, uint32_t p_interrupt_limit, uint32_t num_disabled_interrupts, uint32_t *disabled_interrupts) {
    #ifdef DEBUG_NVIC
    printf("[NVIC] init_nvic called with vtor: %x, num_irq: %d\n", vtor, num_irq); fflush(stdout);
    #endif

    if(num_irq > PIC32MZ_NVIC_NUM_SUPPORTED_INTERRUPTS) {
        num_irq = PIC32MZ_NVIC_NUM_SUPPORTED_INTERRUPTS;
    }


    pic32mz_nvic.active_irq = PIC32MZ_NVIC_NONE_ACTIVE;
    pic32mz_nvic.pending_irq = PIC32MZ_NVIC_NONE_ACTIVE;
    pic32mz_nvic.pending_sub_prio = PIC32MZ_NVIC_LOWEST_PRIO;
    pic32mz_nvic.pending_prio = PIC32MZ_NVIC_LOWEST_PRIO;

    pic32mz_nvic.interrupt_count = 0;
    pic32mz_interrupt_limit = p_interrupt_limit;
    pic32mz_num_config_disabled_interrupts = num_disabled_interrupts;

    pic32mz_config_disabled_interrupts = calloc(num_disabled_interrupts, sizeof(*disabled_interrupts));

    for(uint32_t i = 0; i < num_disabled_interrupts; ++i)
        // save disabled IRQs
        pic32mz_config_disabled_interrupts[i] = disabled_interrupts[i];
    

    uc_hook_add(uc, &pic32mz_nvic_block_hook_handle, UC_HOOK_BLOCK_UNCONDITIONAL, pic32mz_nvic_block_hook, &pic32mz_nvic, 1, 0);
    
    // pic32mz_nvic MMIO range write handler to update status
    uc_hook_add(uc, &pic32mz_hook_mmio_write_handle, UC_HOOK_MEM_WRITE, pic32mz_hook_sysctl_mmio_write, NULL, PIC32MZ_INTR_CTL_REG_MMIO_BASE, PIC32MZ_INTR_CTL_REG_MMIO_END);
    // uc_hook_add(uc, &pic32mz_hook_mmio_read_handle, UC_HOOK_MEM_READ, pic32mz_hook_sysctl_mmio_read, NULL, PIC32MZ_INTR_CTL_REG_MMIO_BASE, PIC32MZ_INTR_CTL_REG_MMIO_END);

    subscribe_state_snapshotting(uc, pic32mz_nvic_take_snapshot, pic32mz_nvic_restore_snapshot, pic32mz_nvic_discard_snapshot);

    return UC_ERR_OK;
}