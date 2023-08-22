#!/usr/bin/env python
# Sample code for MIPS of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
# Python sample ported by Loi Anh Tuan <loianhtuan@gmail.com>

from __future__ import print_function
from unicorn import *
from unicorn.mips_const import *


# code to be emulated
MIPS_CODE_EB = b"\x34\x21\x34\x56" # ori $at, $at, 0x3456;
MIPS_CODE_EL = b"\x56\x34\x21\x34" # ori $at, $at, 0x3456;

# memory address where emulation starts
ADDRESS      = 0x10000


from capstone import *
from capstone.mips import *


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
    instr = uc.mem_read(address, size)
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32+CS_MODE_LITTLE_ENDIAN)
    for i in md.disasm(instr, address):
        print("%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

# Test MIPS EB
def test_mips_eb():
    print("Emulate MIPS code (big-endian)")
    try:
        # Initialize emulator in MIPS32 + EB mode
        mu = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, MIPS_CODE_EB)

        # initialize machine registers
        mu.reg_write(UC_MIPS_REG_1, 0x6789)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)


        def hook_mmio_access(uc, type, addr, size, value, user_data):
            pc = mu.reg_read(UC_MIPS_REG_PC)
            print(">>> MMIO access at 0x%x, pc = 0x%x" %(address, pc))


        # tracing memory access
        mu.hook_add(UC_HOOK_MEM_READ, hook_mmio_access, None, 0xbfc00000, 0xbfc40000)


        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(MIPS_CODE_EB))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        r1 = mu.reg_read(UC_MIPS_REG_1)
        print(">>> R1 = 0x%x" %r1)

    except UcError as e:
        print("ERROR: %s" % e)


# Test MIPS EL
def test_mips_el():
    print("Emulate MIPS code (little-endian)")
    try:
        # Initialize emulator in MIPS32 + EL mode
        mu = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)
        code_lbux = b"\x8A\x19\x62\x7C"
        code_lbu = b"\x01\x00\x8A\x90"
        # code = b"\x86\xBF\x02\x3C\x20\x06\x42\x8C"
        code_two = b"\x86\xBF\x02\x3C\x20\x06\x42\x8C\x81\xBF\x02\x3C"
        entry_point = 0x9D003460
        # text region
        text_addr = 0x9d000000
        text_size = 0x5000
        mu.mem_map(text_addr, text_size)
       
        # mmio region
        mmio_addr = 0xbf800000
        mmio_size = 0x100000
        mu.mem_map(mmio_addr, mmio_size)


        # write machine code to be emulated to memory
        mu.mem_write(entry_point, code_lbu)

        # initialize machine registers
        # mu.reg_write(UC_MIPS_REG_1, 0x6789)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        def hook_mmio_access(uc, type, addr, size, value, user_data):
            pc = mu.reg_read(UC_MIPS_REG_PC)
            print(">>> MMIO access at 0x%x, pc = 0x%x" %(addr, pc))


        # tracing memory access
        mu.hook_add(UC_HOOK_MEM_READ, hook_mmio_access, None, 0xbf800000, 0xbf900000)
        
        # emulate machine code in infinite time
        mu.emu_start(entry_point, entry_point + len(code_lbu))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        # r1 = mu.reg_read(UC_MIPS_REG_1)
        # print(">>> R1 = 0x%x" %r1)

    except UcError as e:
        print("ERROR: %s" % e)


if __name__ == '__main__':
    # test_mips_eb()
    # print("=" * 27)
    test_mips_el()
