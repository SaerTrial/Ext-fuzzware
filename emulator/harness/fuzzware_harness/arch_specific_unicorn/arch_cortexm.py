from .arch import Const, ArchSpecifics, Patch, logger, Context, UserHooks
from unicorn.arm_const import *
from unicorn import *
import archinfo
from ..util import bytes2int
import struct
from ..user_hooks.generic.malloc import _free, _malloc, _realloc, _calloc
import sys
from string import digits
from ..user_hooks.fuzz import get_fuzz

endianness = {"LE":UC_MODE_LITTLE_ENDIAN,
    "BE": UC_MODE_BIG_ENDIAN
}


arm_registers = {'r0': UC_ARM_REG_R0, 'r1': UC_ARM_REG_R1, 'r2': UC_ARM_REG_R2,
                         'r3': UC_ARM_REG_R3, 'r4': UC_ARM_REG_R4, 'r5': UC_ARM_REG_R5,
                         'r6': UC_ARM_REG_R6, 'r7': UC_ARM_REG_R7, 'r8': UC_ARM_REG_R8,
                         'r9': UC_ARM_REG_R9, 'r10': UC_ARM_REG_R10, 'r11': UC_ARM_REG_R11,
                         'r12': UC_ARM_REG_R12, 'sp': UC_ARM_REG_SP, 'lr': UC_ARM_REG_LR,
                         'pc': UC_ARM_REG_PC, 'cpsr': UC_ARM_REG_CPSR}


arm_target_xml = b'''<?xml version="1.0"?>
<!-- Copyright (C) 2008 Free Software Foundation, Inc.

     Copying and distribution of this file, with or without modification,
     are permitted in any medium without royalty provided the copyright
     notice and this notice are preserved.  -->



<target>
    <architecture>arm</architecture>
    <feature name="org.gnu.gdb.arm.core">
      <reg name="r0" bitsize="32"/>
      <reg name="r1" bitsize="32"/>
      <reg name="r2" bitsize="32"/>
      <reg name="r3" bitsize="32"/>
      <reg name="r4" bitsize="32"/>
      <reg name="r5" bitsize="32"/>
      <reg name="r6" bitsize="32"/>
      <reg name="r7" bitsize="32"/>
      <reg name="r8" bitsize="32"/>
      <reg name="r9" bitsize="32"/>
      <reg name="r10" bitsize="32"/>
      <reg name="r11" bitsize="32"/>
      <reg name="r12" bitsize="32"/>
      <reg name="sp" bitsize="32" type="data_ptr"/>
      <reg name="lr" bitsize="32"/>
      <reg name="pc" bitsize="32" type="code_ptr"/>

      <!-- The CPSR is register 25, rather than register 16, because
           the FPA registers historically were placed between the PC
           and the CPSR in the "g" packet.  -->
      <reg name="cpsr" bitsize="32" regnum="25"/>
    </feature>
</target>
'''

arm_dump_template = """r0=0x{:x}
r1=0x{:x}
r2=0x{:x}
r3=0x{:x}
r4=0x{:x}
r5=0x{:x}
r6=0x{:x}
r7=0x{:x}
r8=0x{:x}
r9=0x{:x}
r10=0x{:x}
r11=0x{:x}
r12=0x{:x}
lr=0x{:x}
pc=0x{:x}
sp=0x{:x}
xpsr=0x{:x}
"""

snapshot_reg_cons = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4,
            UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9,
            UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_R12, UC_ARM_REG_LR, UC_ARM_REG_PC,
            UC_ARM_REG_SP, UC_ARM_REG_XPSR]


class ConstARMCortexM(Const):
    def __init__(self) -> None:
        super(ConstARMCortexM, self).__init__()

    def __getattribute__(self, const_name):
        for x in dir(arm_const):
            if x.endswith('REG_' + const_name.upper()):
                return getattr(arm_const, x)
        return object.__getattribute__(self, const_name)

""" ASM
ldr r0, =0x90909090
bx lr
NOP
"""
LDR_R0_LITERAL_POOL_RET = b"\x00\x48\x70\x47"
THUMB_NOP = b"\xC0\x46"

# bx lr
THUMB_RET = b'\x70\x47'


class PatchARMCortexM(Patch):
    def __init__(self, endness) -> None:
        super(PatchARMCortexM, self).__init__(endness)
        self._endness = endness
    
    def load_and_ret(self, addr, val):
        if self._endness == "LE":
            packed = struct.pack("<I", val)
        else:
            packed = struct.pack(">I", val)

        patch = LDR_R0_LITERAL_POOL_RET + packed

        # For unaligned addresses, align the instruction first for a correct pc-relative load
        if addr & 2 == 2:
            patch = THUMB_NOP + patch

        return patch
    
    def ret(self):
        return THUMB_RET
        
    def nop(self):
        return THUMB_NOP

class ContextARMCortexM(Context):
    def __init__(self, uc) -> None:
        self._uc = uc

    def print_context(self):
        print("==== State ====")
        r0 = self._uc.regs.r0
        r1 = self._uc.regs.r1
        r2 = self._uc.regs.r2
        r3 = self._uc.regs.r3
        r4 = self._uc.regs.r4
        r5 = self._uc.self._uc.regs.r5
        r7 = self._uc.self._uc.regs.r7
        sp = self._uc.regs.sp
        pc = self._uc.regs.pc
        print("r0: 0x{:x}\nr1: 0x{:x}\nr2: 0x{:x}\nr3: 0x{:x}\nr4: 0x{:x}\nr5: 0x{:x}\nr7: 0x{:x}\npc: 0x{:x}\nsp: 0x{:x}".format(r0, r1, r2, r3, r4, r5, r7, pc, sp), flush=True)

    def print_args(self, arg_num = 4):
        pc = self._uc.regs.pc
        fn_name = self._uc.syms_by_addr.get(pc, None)
        if fn_name is None:
            fn_name = self._uc.syms_by_addr.get(pc | 1, None)
            if fn_name is None:
                fn_name = f"UNKNOWN_FUNC_{pc:08x}"

        regvals = (self._uc.regs.r0, self._uc.regs.r1, self._uc.regs.r2, self._uc.regs.r3)       
        args_text = ','.join([f"{addr:#010x}" for addr in regvals[0:arg_num]])
        print(f"{fn_name}({args_text})", flush=True)

    def function_args(self, arg_num = 4):
        return (self._uc.regs.r0, self._uc.regs.r1, self._uc.regs.r2, self._uc.regs.r3)[0:arg_num]

    def return_zero(self):
        self._uc.regs.r0 = 0


class UserHooksARMCortexM(UserHooks):
    def __init__(self, uc):
        super(UserHooksARMCortexM, self).__init__(uc)
        self._uc = uc
    
    def calloc(self):
        nitem = self._uc.regs.r0
        size = self._uc.regs.r1
        res = _calloc(self._uc, size * nitem)
        self._uc.regs.r0 = res
        print("malloc. size=0x{:x} -> 0x{:x}".format(size * nitem, res))

    def realloc(self):
        addr = self._uc.regs.r0
        size = self._uc.regs.r1
        print("realloc. addr: 0x{:x}, size=0x{:x}".format(addr, size))
        res = _realloc(self._uc, addr, size)
        self._uc.regs.r0 = res

    def malloc(self):
        size = self._uc.regs.r0
        res = _malloc(self._uc, size)
        self._uc.regs.r0 = res
        print("malloc. size=0x{:x} -> 0x{:x}".format(size, res))

    def memp_free(self):
        addr = self._uc.regs.r1
        _free(self._uc, addr)

    def free(self):
        addr = self._uc.regs.r0
        print("freeing 0x{:x}".format(addr))
        if addr != 0:
            _free(self._uc, addr)       

    def puts(self):
        ptr = self._uc.regs.r0
        if ptr == 0:
            print("puts(NULL)", flush=True)
            return

        msg = self._uc.mem_read(ptr, 256)
        #ptr += 1
        #while msg[-1] != b"\0":
        #    msg += uc.mem_read(ptr, 1)
        #    ptr += 1
        if b'\0' in msg:
            msg = msg[:msg.find(b'\0')]
        print(msg.decode())

    def putchar(self):
        c = self._uc.regs.r0
        assert c < 256
        sys.stdout.write(chr(c))
        sys.stdout.flush()

    def printf(self):
        # for now just print out the fmt string
        ptr = self._uc.regs.r0
        assert ptr != 0
        msg = self._uc.mem_read(ptr, 256)

        if b'\0' in msg:
            msg = msg[:msg.find(b'\0')]
        output = b''

        # just allow a limited number of arguments
        args = [self._uc.regs.r1, self._uc.regs.r2, self._uc.regs.r3]
        args.reverse()

        prev_ind, cursor = 0, 0
        while args:
            cursor = msg.find(b"%", prev_ind)

            if cursor == -1:
                break

            output += msg[prev_ind:cursor]
            cursor += 1

            num_str = b""
            while msg[cursor] in digits.encode():
                num_str += msg[cursor]
                cursor += 1
            while msg[cursor] == ord('l'):
                cursor += 1

            if msg[cursor] == ord('s'):
                string_addr = args.pop()
                s = self._uc.mem_read(string_addr, 1)
                while s[-1] != ord("\0"):
                    string_addr += 1
                    s += self._uc.mem_read(string_addr, 1)
                output += s[:-1]
            elif msg[cursor] == ord('d'):
                val = args.pop()
                output += f"{val:d}".encode()
            elif msg[cursor] in (ord('x'), ord('p')):
                val = args.pop()
                output += f"{val:x}".encode()

            cursor += 1
            prev_ind = cursor

        output += msg[prev_ind:]
        sys.stdout.write(output.decode('latin1'))
        sys.stdout.flush()

    def readline(self):
        ptr = self._uc.regs.r0
        l = self._uc.regs.r1
        assert ptr != 0
        data = b''
        while len(data) < l:
            data += get_fuzz(self._uc, 1)
            if data.endswith(b'\n'):
                break
        self._uc.mem_write(ptr, data)
        self._uc.regs.r0 = 0
        # echo
        sys.stdout.write(data.decode('latin1'))
        sys.stdout.flush()



class ArchSpecificsARMCortexM(ArchSpecifics):
    def __init__(self, endness):
        super(ArchSpecificsARMCortexM, self).__init__(endness)
        self._endness = endness
        self._uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS | endianness[endness])
        self._const = ConstARMCortexM()
        self._archinfo_registers = archinfo.ArchARMCortexM().register_list
        self._patch = PatchARMCortexM(endness)
        self._context = ContextARMCortexM(self._uc)
        self._userhooks = UserHooksARMCortexM(self._uc)

    @property
    def const(self):
        return self._const

    @property
    def gdb_registers(self):
        return arm_registers

    @property
    def archinfo_registers(self):
        return self._archinfo_registers

    def read_initial_sp(self, config, image_base):
        if "initial_sp" in config:
            return config["initial_sp"]

        if image_base is None:
            raise ValueError("image_base is None")
        
        initial_sp =  bytes2int(self._uc.mem_read(image_base, 4))

        return initial_sp

    def read_entry_point(self, config, image_base):
        if "entry_point" in config:
            return config["entry_point"]

        if image_base is None:
            raise ValueError("image_base is None")

        entry_point = bytes2int(self._uc.mem_read(image_base + 4, 4))

        logger.debug(f"Recovered entry points: {entry_point:08x}")

        return entry_point        

    def return_addr(self, addr, thumb_mode = True):
        if thumb_mode:
            return addr | 1

        return addr & 0xFFFFFFFE

    @property
    def target_xml(self):
        return arm_target_xml
    
    @property
    def dump_template(self):
        return ("arch=ARMCortexM\n" + "endness=LE\n" if self._endness == "LE" else "endness=BE\n") \
            + arm_dump_template
    
    @property
    def all_const(self):
        return arm_const
    
    @property
    def snapshot_reg_cons(self):
        return snapshot_reg_cons
    
    @property
    def patch(self):
        return self._patch
    
    @property
    def context(self):
        return self._context
    
    @property
    def userhooks(self):
        return self._userhooks