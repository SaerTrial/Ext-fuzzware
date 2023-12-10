
#include "cortexm/cortexm_nvic.h"
#include "mips/pic32mx_nvic.h"
#include "mips/pic32mz_nvic.h"

#ifndef INTR_COMMON_H
#define INTR_COMMON_H

#define PROCESSOR_PIC32MZ 0x1
#define PROCESSOR_PIC32MX 0x2

uc_err init_nvic(uc_engine *uc, uint32_t processor,uint32_t vtor, uint32_t num_irq, uint32_t p_interrupt_limit, uint32_t num_disabled_interrupts, uint32_t *disabled_interrupts);


// setting a pending bit in an arch-specific structure
void (*nvic_set_pending)(uc_engine, uint32_t, int);

// getting the number of enabled irqs
uint16_t (*get_num_enabled) ();

// getting the nth of enabled irq number
uint8_t (*nth_enabled_irq_num) (uint8_t);


#endif