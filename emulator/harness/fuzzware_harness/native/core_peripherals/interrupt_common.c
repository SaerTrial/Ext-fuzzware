#include "interrupt_common.h"



uc_err init_nvic(uc_engine *uc, uint32_t processor, uint32_t vtor, uint32_t num_irq, uint32_t p_interrupt_limit, uint32_t num_disabled_interrupts, uint32_t *disabled_interrupts){
    uint32_t arch = uc_read_arch(uc);

    if (arch == UC_ARCH_ARM) {
        nvic_set_pending = cortexm_nvic_set_pending;
        get_num_enabled = cortexm_get_num_enabled;
        nth_enabled_irq_num = cortexm_nth_enabled_irq_num;
        cortexm_init_nvic(uc, vtor, num_irq, p_interrupt_limit, num_disabled_interrupts, disabled_interrupts);
    }

    if (arch == UC_ARCH_MIPS){
        if (processor == PROCESSOR_PIC32MZ){
            nvic_set_pending = pic32mz_nvic_set_pending;
            get_num_enabled = pic32mz_get_num_enabled;
            nth_enabled_irq_num = pic32mz_nth_enabled_irq_num;
            pic32mz_init_nvic(uc, vtor, num_irq, p_interrupt_limit, num_disabled_interrupts, disabled_interrupts);
        }
        if (processor == PROCESSOR_PIC32MX){
            nvic_set_pending = pic32mx_nvic_set_pending;
            get_num_enabled = pic32mx_get_num_enabled;
            nth_enabled_irq_num = pic32mx_nth_enabled_irq_num;
            pic32mx_init_nvic(uc, vtor, num_irq, p_interrupt_limit, num_disabled_interrupts, disabled_interrupts);
        }
    }
    return UC_ERR_OK;
}