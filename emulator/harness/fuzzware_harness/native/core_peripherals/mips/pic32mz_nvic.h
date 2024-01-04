#ifndef PIC32MZ_NVIC_H
#define PIC32MZ_NVIC_H

#include <string.h>
#include <assert.h>

#include "unicorn/unicorn.h"
#include "../../util.h"
#include "../../timer.h"
#include "../../native_hooks.h"
#include "../../uc_snapshot.h"



// define interrupt control registers (ICRs)
// https://ww1.microchip.com/downloads/en/DeviceDoc/60001191G.pdf 
// TABLE 7-3: INTERRUPT REGISTER MAP
// offset againt PIC32MZ_INTR_CTL_REG_MMIO_BASE
#define PIC32MZ_INTCON 0x0
#define PIC32MZ_INTSTAT 0x20

// interrupt flag
#define PIC32MZ_IFS0 0x40
#define PIC32MZ_IFS1 0x50
#define PIC32MZ_IFS2 0x60
#define PIC32MZ_IFS3 0x70
#define PIC32MZ_IFS4 0x80
#define PIC32MZ_IFS5 0x90

// interrupt clear
#define PIC32MZ_IFS0CLR 0x44
#define PIC32MZ_IFS1CLR 0x54
#define PIC32MZ_IFS2CLR 0x64
#define PIC32MZ_IFS3CLR 0x74
#define PIC32MZ_IFS4CLR 0x84
#define PIC32MZ_IFS5CLR 0x94


// interrupt mask
#define PIC32MZ_IEC0 0xc0
#define PIC32MZ_IEC1 0xd0
#define PIC32MZ_IEC2 0xe0
#define PIC32MZ_IEC3 0xf0
#define PIC32MZ_IEC4 0x100
#define PIC32MZ_IEC5 0x110


// interrupt set
// note that enabling an interrupt could be done either in IECx or IECxSET registers
#define PIC32MZ_OFFSET_IECxSET 0x8

#define PIC32MZ_OFFSET_IECxCLR 0x4


// interrupt priority
#define PIC32MZ_IPC0 0x140
#define PIC32MZ_IPC1 0x150
#define PIC32MZ_IPC2 0x160
#define PIC32MZ_IPC3 0x170
#define PIC32MZ_IPC4 0x180
#define PIC32MZ_IPC5 0x190
#define PIC32MZ_IPC6 0x1a0
#define PIC32MZ_IPC7 0x1b0
#define PIC32MZ_IPC8 0x1c0
#define PIC32MZ_IPC9 0x1d0
#define PIC32MZ_IPC10 0x1e0
#define PIC32MZ_IPC11 0x1f0
#define PIC32MZ_IPC12 0x200
#define PIC32MZ_IPC53 0x490

#define PIC32MZ_OFFSET_IPCxSET 0x8

// OFFx registers
// OFFx = 0x540 + 0x4 * x
#define PIC32MZ_OFF000 0x540
#define PIC32MZ_NUM_OFFX 190 + 1


// CP0 registers
// https://ww1.microchip.com/downloads/en/DeviceDoc/61113E.pdf page 27
// CP0 status bit 12-10 IPL<2:0>: Interrupt Priority Level bits
typedef struct CP0_status
{
  uint32_t IE:1;
  uint32_t EXL:1;
  uint32_t ERL:1;
  uint32_t :1;
  uint32_t UM:1;
  uint32_t :5;
  uint32_t IPL:3;
} PIC32MZ_CP0_status;


typedef struct _PIC32MZ_CP0_cause
{
  uint32_t :2;
  uint32_t EXCCODE:5;
  uint32_t :1;
  uint32_t IP0:1;
  uint32_t IP1:1;
  uint32_t RILP:3;
  uint32_t :10;
  uint32_t IV:1;
  uint32_t :3;
  uint32_t DC:1;
  uint32_t CE:2;
  uint32_t TI:1;
} PIC32MZ_CP0_cause;

// extra marcro for irqs of core software interrupts
#define PIC32MZ_IRQ_Core_Software_Interrupt_0 1
#define PIC32MZ_IRQ_Core_Software_Interrupt_1 2
#define PIC32MZ_IRQ_Core_Timer 0



typedef struct IFS
{
  uint32_t IE:1;
} PIC32MZ_IFS;

// marcro for extracting bits
#define PIC32MZ_Sub_Prio_0(x) (x & 0x3)
#define PIC32MZ_Prio_0(x) ((x & 0x1C) >> 2)
#define PIC32MZ_Sub_Prio_1(x) ((x & 0x300) >> 8)
#define PIC32MZ_Prio_1(x) ((x & 0x1C00) >> 10)
#define PIC32MZ_Sub_Prio_2(x) ((x & 0x30000) >> 16) 
#define PIC32MZ_Prio_2(x) ((x & 0x1C0000) >> 18)
#define PIC32MZ_Sub_Prio_3(x) ((x & 0x3000000) >> 24) 
#define PIC32MZ_Prio_3(x) ((x & 0x1C000000) >> 26)

// marco for getting nth bit at a certain point
#define PIC32MZ_Get_Bit(data, n) ((data & ( 1 << n )) >> n)

// marco for setting a bit at a certain point
#define PIC32MZ_Set_Bit(data, n) (data | ( 1 << n ))

// marco for getting vector offset
#define PIC32MZ_Get_Vector_Offset(OFFX) ((OFFX & 0x3FFFE) >> 1)

// define ebase and MMIO addresses for ICRs
// https://microchipdeveloper.com/xwiki/bin/view/products/mcu-mpu/32bit-mcu/PIC32/mz-arch-cpu-overview/exception-mechanism/entry-points/#HInterruptExceptionVectors
#define PIC32MZ_EBASE 0x9D000000
#define PIC32MZ_INTR_CTL_REG_MMIO_BASE 0xBF810000 
#define PIC32MZ_INTR_CTL_REG_MMIO_END 0xBF811000 


// We support 256 interrupts
#define PIC32MZ_NVIC_NUM_SUPPORTED_INTERRUPTS 191

// TODO: helper marco to retrieve relevant bits from registers
// IRQ: x  IPC: x/4  IEC: x/32  OFF:x  IFS: x/32
// Priority: 
    // x % 4 == 0: <4:2>
    // x % 4 == 1: <12:10>
    // x % 4 == 2: <20:18>
    // x % 4 == 3: <28:26>
// Sub Priority: 
    // x % 4 == 0: <1:0>
    // x % 4 == 1: <9:8>
    // x % 4 == 2: <17:16>
    // x % 4 == 3: <25:24> 
// Flag
    // IFS = x/32  x%32 bit     PIC32MZ_Get_Bit(IFS, x%32)
// Mask
    // IEC = x/32  x%32 bit     PIC32MZ_Get_Bit(IEC, x%32)
// offset vector address
    // OFF = x <17:1>           


// IRQ table - https://ww1.microchip.com/downloads/en/DeviceDoc/60001191G.pdf TABLE 7-2





struct Pic32mzNVIC {
    // We put some members to the front as they are required in the basic block hot path

    // dynamic state which we re-calculate upon changes
    int active_irq;
    int pending_prio;
    int pending_sub_prio;
    int pending_irq;
    uint32_t EPC;
    // Vector table base address
    uint32_t vtor;

    uint32_t interrupt_count;
    uint8_t NonPersistantIRQs[PIC32MZ_NVIC_NUM_SUPPORTED_INTERRUPTS];
    uint8_t InterruptEnabled[PIC32MZ_NVIC_NUM_SUPPORTED_INTERRUPTS];
    uint8_t InterruptActive[PIC32MZ_NVIC_NUM_SUPPORTED_INTERRUPTS];
    uint8_t InterruptPending[PIC32MZ_NVIC_NUM_SUPPORTED_INTERRUPTS];
    int InterruptPriority[PIC32MZ_NVIC_NUM_SUPPORTED_INTERRUPTS];
    int InterruptSubPriority[PIC32MZ_NVIC_NUM_SUPPORTED_INTERRUPTS];
    // We keep track of enabled interrupts for fuzzing
    int num_enabled;
    uint8_t enabled_irqs[PIC32MZ_NVIC_NUM_SUPPORTED_INTERRUPTS];
};




// interrupt process
// https://ww1.microchip.com/downloads/en/DeviceDoc/61108F.pdf

//  A pending IRQ is indicated by the flag bit being equal to ‘1’ in an IFSx register
//  The pending IRQ will not cause further processing if the 
//  corresponding IECx bit in the Interrupt Enable register is clear
//  compare IPCx register and  CPU Interrupt Priority bits, IPL<2:0> == Status<12:10>
//  if greater than CPU's priority, then jump to EPC


uint16_t pic32mz_get_num_enabled();

uint8_t pic32mz_nth_enabled_irq_num(uint8_t n);

void pic32mz_nvic_set_pending(uc_engine *uc, uint32_t irq, int delay_activation);

uc_err pic32mz_init_nvic(uc_engine *uc, uint32_t vtor, uint32_t num_irq, uint32_t p_interrupt_limit, uint32_t num_disabled_interrupts, uint32_t *disabled_interrupts);

#endif