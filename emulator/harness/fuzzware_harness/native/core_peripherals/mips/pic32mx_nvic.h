
#ifndef PIC32MX_NVIC_H
#define PIC32MX_NVIC_H

#include <string.h>
#include <assert.h>

#include "unicorn/unicorn.h"
#include "../../util.h"
#include "../../timer.h"
#include "../../native_hooks.h"
#include "../../uc_snapshot.h"


typedef struct _PIC32MX_CP0_cause
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
} PIC32MX_CP0_cause;


// TABLE 6-6: PERIPHERAL ADDRESS TABLE
// https://ww1.microchip.com/downloads/en/DeviceDoc/PIC32MX_Datasheet_v2_61143B.pdf
// page 113


#define PIC32MX_IFS0              0xBF881030 
#define PIC32MX_IFS0CLR           0xBF881034 
#define PIC32MX_IFS0SET           0xBF881038 
#define PIC32MX_IFS0INV           0xBF88103C 
#define PIC32MX_IFS1              0xBF881040 
#define PIC32MX_IFS1CLR           0xBF881044 
#define PIC32MX_IFS1SET           0xBF881048 
#define PIC32MX_IFS1INV           0xBF88104C 
#define PIC32MX_IFS2              0xBF881050 
#define PIC32MX_IFS2CLR           0xBF881054 
#define PIC32MX_IFS2SET           0xBF881058 
#define PIC32MX_IFS2INV           0xBF88105C 
#define PIC32MX_IEC0              0xBF881060 
#define PIC32MX_IEC0CLR           0xBF881064 
#define PIC32MX_IEC0SET           0xBF881068 
#define PIC32MX_IEC0INV           0xBF88106C 
#define PIC32MX_IEC1              0xBF881070 
#define PIC32MX_IEC1CLR           0xBF881074 
#define PIC32MX_IEC1SET           0xBF881078 
#define PIC32MX_IEC1INV           0xBF88107C 
#define PIC32MX_IEC2              0xBF881080 
#define PIC32MX_IEC2CLR           0xBF881084 
#define PIC32MX_IEC2SET           0xBF881088 
#define PIC32MX_IEC2INV           0xBF88108C 
#define PIC32MX_IPC0              0xBF881090 
#define PIC32MX_IPC0CLR           0xBF881094 
#define PIC32MX_IPC0SET           0xBF881098 
#define PIC32MX_IPC0INV           0xBF88109C 
#define PIC32MX_IPC1              0xBF8810A0 
#define PIC32MX_IPC1CLR           0xBF8810A4 
#define PIC32MX_IPC1SET           0xBF8810A8 
#define PIC32MX_IPC1INV           0xBF8810AC 
#define PIC32MX_IPC2              0xBF8810B0 
#define PIC32MX_IPC2CLR           0xBF8810B4 
#define PIC32MX_IPC2SET           0xBF8810B8 
#define PIC32MX_IPC2INV           0xBF8810BC 
#define PIC32MX_IPC3              0xBF8810C0 
#define PIC32MX_IPC3CLR           0xBF8810C4 
#define PIC32MX_IPC3SET           0xBF8810C8 
#define PIC32MX_IPC3INV           0xBF8810CC 
#define PIC32MX_IPC4              0xBF8810D0 
#define PIC32MX_IPC4CLR           0xBF8810D4 
#define PIC32MX_IPC4SET           0xBF8810D8 
#define PIC32MX_IPC4INV           0xBF8810DC 
#define PIC32MX_IPC5              0xBF8810E0 
#define PIC32MX_IPC5CLR           0xBF8810E4 
#define PIC32MX_IPC5SET           0xBF8810E8 
#define PIC32MX_IPC5INV           0xBF8810EC 
#define PIC32MX_IPC6              0xBF8810F0 
#define PIC32MX_IPC6CLR           0xBF8810F4 
#define PIC32MX_IPC6SET           0xBF8810F8 
#define PIC32MX_IPC6INV           0xBF8810FC 
#define PIC32MX_IPC7              0xBF881100 
#define PIC32MX_IPC7CLR           0xBF881104 
#define PIC32MX_IPC7SET           0xBF881108 
#define PIC32MX_IPC7INV           0xBF88110C 
#define PIC32MX_IPC8              0xBF881110 
#define PIC32MX_IPC8CLR           0xBF881114 
#define PIC32MX_IPC8SET           0xBF881118 
#define PIC32MX_IPC8INV           0xBF88111C 
#define PIC32MX_IPC9              0xBF881120 
#define PIC32MX_IPC9CLR           0xBF881124 
#define PIC32MX_IPC9SET           0xBF881128 
#define PIC32MX_IPC9INV           0xBF88112C 
#define PIC32MX_IPC10             0xBF881130 
#define PIC32MX_IPC10CLR          0xBF881134 
#define PIC32MX_IPC10SET          0xBF881138 
#define PIC32MX_IPC10INV          0xBF88113C 
#define PIC32MX_IPC11             0xBF881140 
#define PIC32MX_IPC11CLR          0xBF881144 
#define PIC32MX_IPC11SET          0xBF881148 
#define PIC32MX_IPC11INV          0xBF88114C 
#define PIC32MX_IPC12             0xBF881150 
#define PIC32MX_IPC12CLR          0xBF881154 
#define PIC32MX_IPC12SET          0xBF881158 
#define PIC32MX_IPC12INV          0xBF88115C 

#define PIC32MX_OFFSET_xSET 0x8
#define PIC32MX_OFFSET_xCLR 0x4
// SFRs
#define PIC32MX_T1CON             0xBF800600 
#define PIC32MX_T2CON             0xBF800800 
#define PIC32MX_T3CON             0xBF800A00 
#define PIC32MX_T4CON             0xBF800C00 
#define PIC32MX_T5CON             0xBF800E00 
#define PIC32MX_IC1CON            0xBF802000 
#define PIC32MX_IC2CON            0xBF802200 
#define PIC32MX_IC3CON            0xBF802400 
#define PIC32MX_IC4CON            0xBF802600 
#define PIC32MX_IC5CON            0xBF802800 
#define PIC32MX_OC1CON            0xBF803000 
#define PIC32MX_OC2CON            0xBF803200 
#define PIC32MX_OC3CON            0xBF803400 
#define PIC32MX_OC4CON            0xBF803600 
#define PIC32MX_OC5CON            0xBF803800 
#define PIC32MX_I2C1CON           0xBF805300 
#define PIC32MX_I2C2CON           0xBF805400 
#define PIC32MX_SPI3CON           0xBF805800 
#define PIC32MX_SPI2CON           0xBF805A00 
#define PIC32MX_SPI4CON           0xBF805C00 
#define PIC32MX_SPI1CON           0xBF805E00 
#define PIC32MX_UART1CON          0xBF806000 
#define PIC32MX_UART2CON          0xBF806200  


#define PIC32MX_EBASE 0x9FC01000
#define PIC32MX_INTR_CTL_REG_MMIO_BASE 0xBF881030 
#define PIC32MX_INTR_CTL_REG_MMIO_END 0xBF88115C

#define PIC32MX_PERIPHERAL_CTL_MMIO_BASE 0xBF800000 
#define PIC32MX_PERIPHERAL_CTL_MMIO_END 0xBF809000 //ADC




// The number of supported interrupts
// https://ww1.microchip.com/downloads/en/DeviceDoc/PIC32MX_Datasheet_v2_61143B.pdf
// TABLE 8-1
#define PIC32MX_NVIC_NUM_SUPPORTED_INTERRUPTS 54
#define PIC32MX_NVIC_NUM_SUPPORTED_VECTOR 45
#define PIC32MX_MIRROR 0x3
uint32_t PIC32MX_IRQ2VectorNum[PIC32MX_NVIC_NUM_SUPPORTED_INTERRUPTS];
uint32_t PIC32MX_VectorNum2IRQ[PIC32MX_NVIC_NUM_SUPPORTED_VECTOR][PIC32MX_MIRROR];

// IRQ: x  IPC: x/4  IEC: x/32  IFS: x/32
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
    // IFS = x/32  x%32 bit     PIC32MX_Get_Bit(IFS, x%32)
// Mask
    // IEC = x/32  x%32 bit     PIC32MX_Get_Bit(IEC, x%32)

// IPC0-IPC12
// IEC0-IEC1
// IFS0-IFS1

// extra marcro for irqs of core software interrupts
#define PIC32MX_IRQ_Core_Software_Interrupt_0 1
#define PIC32MX_IRQ_Core_Software_Interrupt_1 2
#define PIC32MX_IRQ_Core_Timer 0


// marcro for extracting bits
#define PIC32MX_Sub_Prio_0(x) (x & 0x3)
#define PIC32MX_Prio_0(x) ((x & 0x1C) >> 2)
#define PIC32MX_Sub_Prio_1(x) ((x & 0x300) >> 8)
#define PIC32MX_Prio_1(x) ((x & 0x1C00) >> 10)
#define PIC32MX_Sub_Prio_2(x) ((x & 0x30000) >> 16) 
#define PIC32MX_Prio_2(x) ((x & 0x1C0000) >> 18)
#define PIC32MX_Sub_Prio_3(x) ((x & 0x3000000) >> 24) 
#define PIC32MX_Prio_3(x) ((x & 0x1C000000) >> 26)

// marco for getting nth bit at a certain point
#define PIC32MX_Get_Bit(data, n) ((data & ( 1 << n )) >> n)

// marco for setting a bit at a certain point
#define PIC32MX_Set_Bit(data, n) (data | ( 1 << n ))

/* Vector Numbers */
#define PIC32MX_CORE_TIMER_VECTOR                       0
#define PIC32MX_CORE_SOFTWARE_0_VECTOR                  1
#define PIC32MX_CORE_SOFTWARE_1_VECTOR                  2
#define PIC32MX_EXTERNAL_0_VECTOR                       3
#define PIC32MX_TIMER_1_VECTOR                          4
#define PIC32MX_INPUT_CAPTURE_1_VECTOR                  5
#define PIC32MX_OUTPUT_COMPARE_1_VECTOR                 6
#define PIC32MX_EXTERNAL_1_VECTOR                       7
#define PIC32MX_TIMER_2_VECTOR                          8
#define PIC32MX_INPUT_CAPTURE_2_VECTOR                  9
#define PIC32MX_OUTPUT_COMPARE_2_VECTOR                 10
#define PIC32MX_EXTERNAL_2_VECTOR                       11
#define PIC32MX_TIMER_3_VECTOR                          12
#define PIC32MX_INPUT_CAPTURE_3_VECTOR                  13
#define PIC32MX_OUTPUT_COMPARE_3_VECTOR                 14
#define PIC32MX_EXTERNAL_3_VECTOR                       15
#define PIC32MX_TIMER_4_VECTOR                          16
#define PIC32MX_INPUT_CAPTURE_4_VECTOR                  17
#define PIC32MX_OUTPUT_COMPARE_4_VECTOR                 18
#define PIC32MX_EXTERNAL_4_VECTOR                       19
#define PIC32MX_TIMER_5_VECTOR                          20
#define PIC32MX_INPUT_CAPTURE_5_VECTOR                  21
#define PIC32MX_OUTPUT_COMPARE_5_VECTOR                 22
#define PIC32MX_SPI_1_VECTOR                            23
#define PIC32MX_I2C_3_VECTOR                            24
#define PIC32MX_I2C_1A_VECTOR                           24
#define PIC32MX_SPI_3_VECTOR                            24
#define PIC32MX_SPI_1A_VECTOR                           24
#define PIC32MX_UART_1_VECTOR                           24
#define PIC32MX_UART_1A_VECTOR                          24
#define PIC32MX_I2C_1_VECTOR                            25
#define PIC32MX_CHANGE_NOTICE_VECTOR                    26
#define PIC32MX_ADC_VECTOR                              27
#define PIC32MX_PMP_VECTOR                              28
#define PIC32MX_COMPARATOR_1_VECTOR                     29
#define PIC32MX_COMPARATOR_2_VECTOR                     30
#define PIC32MX_I2C_4_VECTOR                            31
#define PIC32MX_I2C_2A_VECTOR                           31
#define PIC32MX_SPI_2_VECTOR                            31
#define PIC32MX_SPI_2A_VECTOR                           31
#define PIC32MX_UART_3_VECTOR                           31
#define PIC32MX_UART_2A_VECTOR                          31
#define PIC32MX_I2C_5_VECTOR                            32
#define PIC32MX_I2C_3A_VECTOR                           32
#define PIC32MX_SPI_4_VECTOR                            32
#define PIC32MX_SPI_3A_VECTOR                           32
#define PIC32MX_UART_2_VECTOR                           32
#define PIC32MX_UART_3A_VECTOR                          32
#define PIC32MX_I2C_2_VECTOR                            33
#define PIC32MX_FAIL_SAFE_MONITOR_VECTOR                34
#define PIC32MX_RTCC_VECTOR                             35
#define PIC32MX_DMA_0_VECTOR                            36
#define PIC32MX_DMA_1_VECTOR                            37
#define PIC32MX_DMA_2_VECTOR                            38
#define PIC32MX_DMA_3_VECTOR                            39
#define PIC32MX_DMA_4_VECTOR                            40
#define PIC32MX_DMA_5_VECTOR                            41
#define PIC32MX_DMA_6_VECTOR                            42
#define PIC32MX_DMA_7_VECTOR                            43
#define PIC32MX_USB_1_VECTOR                            45
#define PIC32MX_CAN_1_VECTOR                            46
#define PIC32MX_CAN_2_VECTOR                            47
#define PIC32MX_ETH_VECTOR                              48
#define PIC32MX_UART_4_VECTOR                           49
#define PIC32MX_UART_1B_VECTOR                          49
#define PIC32MX_UART_6_VECTOR                           50
#define PIC32MX_UART_2B_VECTOR                          50
#define PIC32MX_UART_5_VECTOR                           51
#define PIC32MX_UART_3B_VECTOR                          51
#define PIC32MX_FCE_VECTOR                              44

struct Pic32mxNVIC {
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
    // uint8_t NonPersistantIRQs[PIC32MX_NVIC_NUM_SUPPORTED_INTERRUPTS];
    uint8_t InterruptEnabled[PIC32MX_NVIC_NUM_SUPPORTED_INTERRUPTS];
    uint8_t InterruptActive[PIC32MX_NVIC_NUM_SUPPORTED_INTERRUPTS];
    uint8_t InterruptPending[PIC32MX_NVIC_NUM_SUPPORTED_INTERRUPTS];
    int InterruptPriority[PIC32MX_NVIC_NUM_SUPPORTED_INTERRUPTS];
    int InterruptSubPriority[PIC32MX_NVIC_NUM_SUPPORTED_INTERRUPTS];
    // We keep track of enabled interrupts for fuzzing
    int num_enabled;
    uint8_t enabled_irqs[PIC32MX_NVIC_NUM_SUPPORTED_INTERRUPTS];
};

uint16_t pic32mx_get_num_enabled();

uint8_t pic32mx_nth_enabled_irq_num(uint8_t n);

void pic32mx_nvic_set_pending(uc_engine *uc, uint32_t irq, int delay_activation);

uc_err pic32mx_init_nvic(uc_engine *uc, uint32_t vtor, uint32_t num_irq, uint32_t p_interrupt_limit, uint32_t num_disabled_interrupts, uint32_t *disabled_interrupts);



#endif



