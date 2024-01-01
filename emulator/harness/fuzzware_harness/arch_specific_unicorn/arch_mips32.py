from .arch import Const, ArchSpecifics, logger, Patch, Context, UserHooks
from unicorn.mips_const import *
from unicorn import *
import archinfo
import struct
from ..user_hooks.generic.malloc import _free, _malloc, _realloc, _calloc
import sys
from string import digits
from ..user_hooks.fuzz import get_fuzz

endianness = {"LE":UC_MODE_LITTLE_ENDIAN,
    "BE": UC_MODE_BIG_ENDIAN
}

mips_registers = {
        'zero': UC_MIPS_REG_0, 'at': UC_MIPS_REG_1, 'v0': UC_MIPS_REG_2,
        'v1': UC_MIPS_REG_3, 'a0': UC_MIPS_REG_4, 'a1': UC_MIPS_REG_5,
        'a2': UC_MIPS_REG_6, 'a3': UC_MIPS_REG_7, 't0': UC_MIPS_REG_8,
        't1': UC_MIPS_REG_9, 't2': UC_MIPS_REG_10, 't3': UC_MIPS_REG_11,
        't4': UC_MIPS_REG_12, 't5': UC_MIPS_REG_13, 't6': UC_MIPS_REG_14,
        't7': UC_MIPS_REG_15, 's0': UC_MIPS_REG_16, 's1': UC_MIPS_REG_17,
        's2': UC_MIPS_REG_18, 's3': UC_MIPS_REG_19, 's4': UC_MIPS_REG_20,
        's5': UC_MIPS_REG_21, 's6': UC_MIPS_REG_22, 's7': UC_MIPS_REG_23,
        't8': UC_MIPS_REG_24, 't9': UC_MIPS_REG_25, 'k0': UC_MIPS_REG_26,
        'k1': UC_MIPS_REG_27, 'gp': UC_MIPS_REG_28, 'sp': UC_MIPS_REG_29,
        'fp': UC_MIPS_REG_30, 'ra': UC_MIPS_REG_31, 'pc': UC_MIPS_REG_PC
        }


mips32_target_xml = b'''<?xml version="1.0"?>
<!-- Copyright (C) 2008 Free Software Foundation, Inc.

     Copying and distribution of this file, with or without modification,
     are permitted in any medium without royalty provided the copyright
     notice and this notice are preserved.  -->



<target>
    <architecture>mips32</architecture>
    <feature name="org.gnu.gdb.arm.core">
      <reg name="zero" bitsize="32"/>
      <reg name="at" bitsize="32"/>
      <reg name="v0" bitsize="32"/>
      <reg name="v1" bitsize="32"/>
      <reg name="a0" bitsize="32"/>
      <reg name="a1" bitsize="32"/>
      <reg name="a2" bitsize="32"/>
      <reg name="a3" bitsize="32"/>
      <reg name="t0" bitsize="32"/>
      <reg name="t1" bitsize="32"/>
      <reg name="t2" bitsize="32"/>
      <reg name="t3" bitsize="32"/>
      <reg name="t4" bitsize="32"/>
      <reg name="t5" bitsize="32"/>
      <reg name="t6" bitsize="32"/>
      <reg name="t7" bitsize="32"/>
      <reg name="s0" bitsize="32"/>
      <reg name="s1" bitsize="32"/>
      <reg name="s2" bitsize="32"/>
      <reg name="s3" bitsize="32"/>
      <reg name="s4" bitsize="32"/>
      <reg name="s5" bitsize="32"/>
      <reg name="s6" bitsize="32"/>
      <reg name="s7" bitsize="32"/>
      <reg name="t8" bitsize="32"/>
      <reg name="t9" bitsize="32"/>
      <reg name="k0" bitsize="32"/>
      <reg name="k1" bitsize="32"/>
      <reg name="gp" bitsize="32"/>
      <reg name="sp" bitsize="32" type="data_ptr"/>
      <reg name="fp" bitsize="32"/>
      <reg name="ra" bitsize="32"/>
      <reg name="pc" bitsize="32" type="code_ptr"/>
    </feature>
</target>
'''

mips_dump_template = """zero=0x{:x}
at=0x{:x}
v0=0x{:x}
v1=0x{:x}
a0=0x{:x}
a1=0x{:x}
a2=0x{:x}
a3=0x{:x}
t0=0x{:x}
t1=0x{:x}
t2=0x{:x}
t3=0x{:x}
t4=0x{:x}
t5=0x{:x}
t6=0x{:x}
t7=0x{:x}
s0=0x{:x}
s1=0x{:x}
s2=0x{:x}
s3=0x{:x}
s4=0x{:x}
s5=0x{:x}
s6=0x{:x}
s7=0x{:x}
t8=0x{:x}
t9=0x{:x}
k0=0x{:x}
k1=0x{:x}
gp=0x{:x}
sp=0x{:x}
ra=0x{:x}
pc=0x{:x}
"""


snapshot_reg_cons = [UC_MIPS_REG_ZERO,
    UC_MIPS_REG_AT,
    UC_MIPS_REG_V0,
    UC_MIPS_REG_V1,
    UC_MIPS_REG_A0,
    UC_MIPS_REG_A1,
    UC_MIPS_REG_A2,
    UC_MIPS_REG_A3,
    UC_MIPS_REG_T0,
    UC_MIPS_REG_T1,
    UC_MIPS_REG_T2,
    UC_MIPS_REG_T3,
    UC_MIPS_REG_T4,
    UC_MIPS_REG_T5,
    UC_MIPS_REG_T6,
    UC_MIPS_REG_T7,
    UC_MIPS_REG_S0,
    UC_MIPS_REG_S1,
    UC_MIPS_REG_S2,
    UC_MIPS_REG_S3,
    UC_MIPS_REG_S4,
    UC_MIPS_REG_S5,
    UC_MIPS_REG_S6,
    UC_MIPS_REG_S7,
    UC_MIPS_REG_T8,
    UC_MIPS_REG_T9,
    UC_MIPS_REG_K0,
    UC_MIPS_REG_K1,
    UC_MIPS_REG_GP,
    UC_MIPS_REG_SP,
    UC_MIPS_REG_RA,
    UC_MIPS_REG_PC]


class ConstMIPS32(Const):
    def __init__(self) -> None:
        super(ConstMIPS32, self).__init__()

    def __getattribute__(self, const_name):
        for x in dir(mips_const):
            if x.endswith('REG_' + const_name.upper()):
                return getattr(mips_const, x)
        return object.__getattribute__(self, const_name)

""" MIPS
li, v0, 0xBF811078 == b"\x81\xBF\x02\x3C\x78\x10\x42\x24"
li, v1, 0xAA996655 == b"\x99\xAA\x03\x3C\x55\x66\x63\x24
jr $ra == b"\x08\x00\xE0\x03"
nop == b"\x00\x00\x00\x00"
"""

LOAD_V0 = None

# TODO: replace thoses with archinfo, but I've found that CortexM in archinfo doesn't match bytecode of ret instruction
MIPS32_RET = b"\x08\x00\xE0\x03\x25\x08\x20\x00"
MIPS32_NOP = b"\x00\x00\x00\x00"


class PatchMIPS32Patch(Patch):
    def __init__(self, endness) -> None:
        super(PatchMIPS32Patch, self).__init__(endness)
        self._endness = endness
    
    def load_and_ret(self, addr, val = None, reg = "v0"):
        if self._endness == "LE":
            packed = struct.pack("<I", val)
        else:
            packed = struct.pack(">I", val)
        
        patch = MIPS32_RET

        opcode = None
        if reg == "v0":
            opcode = b"\x02\x3c\x63\x24"
        elif reg == "v1":
            opcode = b"\x03\x3c\x42\x24"
        else:
            raise ValueError("a wrong return reg is set")

        if val != None:
            LOAD_V0 = b"".join([packed[0].to_bytes(1, "little"), 
                    packed[1].to_bytes(1, "little"), 
                    opcode[0].to_bytes(1, "little"), 
                    opcode[1].to_bytes(1, "little"),
                    packed[2].to_bytes(1, "little"),
                    packed[3].to_bytes(1, "little"),
                    opcode[2].to_bytes(1, "little"),
                    opcode[3].to_bytes(1, "little")]) + MIPS32_RET
            patch = LOAD_V0 + MIPS32_RET

        return patch

    def ret(self):
        return MIPS32_RET

    def nop(self):
        return MIPS32_NOP

class ContextMIPS32(Context):
    def __init__(self, uc) -> None:
        self._uc = uc

    def print_context(self):
        print("==== State ====")
        v0 = self._uc.regs.v0
        v1 = self._uc.regs.v1
        a0 = self._uc.regs.a0
        a1 = self._uc.regs.a1
        a2 = self._uc.regs.a2
        a3 = self._uc.regs.a3
        sp = self._uc.regs.sp
        ra = self._uc.regs.ra
        pc = self._uc.regs.pc
        print("v0: 0x{:x}\nv1: 0x{:x}\na0: 0x{:x}\na1: 0x{:x}\na2: 0x{:x}\na3: 0x{:x}\nsp: 0x{:x}\nra: 0x{:x}\npc: 0x{:x}".format(v0, v1, a0, a1, a2, a3, sp, ra, pc), flush=True)
   
    def print_args(self, arg_num = 4):
        pc = self._uc.regs.pc
        fn_name = self._uc.syms_by_addr.get(pc, None)
        if fn_name is None:
            fn_name = f"UNKNOWN_FUNC_{pc:08x}"

        regvals = (self._uc.regs.a0, self._uc.regs.a1, self._uc.regs.a2, self._uc.regs.a3)       
        args_text = ','.join([f"{addr:#010x}" for addr in regvals[0:arg_num]])
        print(f"{fn_name}({args_text})", flush=True)
    
    def function_args(self, arg_num = 4):
        return (self._uc.regs.a0, self._uc.regs.a1, self._uc.regs.a2, self._uc.regs.a3)[0:arg_num]    

    def change_return_vals(self, val):
        self._uc.regs.v0 = self._uc.regs.v1 = val

    def return_zero(self):
        self._uc.regs.v0 = 0
        self._uc.regs.v1 = 0


class UserHooksMIPS32(UserHooks):
    def __init__(self, uc):
        self._uc = uc
    
    def calloc(self):
        nitem = self._uc.regs.a0
        size = self._uc.regs.a1
        res = _calloc(self._uc, size * nitem)
        self._uc.regs.v0 = res
        print("malloc. size=0x{:x} -> 0x{:x}".format(size * nitem, res))

    def realloc(self):
        addr = self._uc.regs.a0
        size = self._uc.regs.a1
        print("realloc. addr: 0x{:x}, size=0x{:x}".format(addr, size))
        res = _realloc(self._uc, addr, size)
        self._uc.regs.v0 = res

    def malloc(self):
        size = self._uc.regs.a0
        res = _malloc(self._uc, size)
        self._uc.regs.v0 = res
        print("malloc. size=0x{:x} -> 0x{:x}".format(size, res))

    def memp_free(self):
        addr = self._uc.regs.a1
        _free(self._uc, addr)

    def free(self):
        addr = self._uc.regs.a0
        print("freeing 0x{:x}".format(addr))
        if addr != 0:
            _free(self._uc, addr)   

    def putchar(self):
        c = self._uc.regs.a0
        assert c < 256
        sys.stdout.write(chr(c))
        sys.stdout.flush()

    def printf(self):
        # for now just print out the fmt string
        ptr = self._uc.regs.a0
        assert ptr != 0
        msg = self._uc.mem_read(ptr, 256)

        if b'\0' in msg:
            msg = msg[:msg.find(b'\0')]
        output = b''

        # just allow a limited number of arguments
        args = [self._uc.regs.a1, self._uc.regs.a2, self._uc.regs.a3]
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
        ptr = self._uc.regs.a0
        l = self._uc.regs.a1
        assert ptr != 0
        data = b''
        while len(data) < l:
            data += get_fuzz(self._uc, 1)
            if data.endswith(b'\n'):
                break
        self._uc.mem_write(ptr, data)
        self._uc.regs.v0 = 0
        # echo
        sys.stdout.write(data.decode('latin1'))
        sys.stdout.flush()


class ArchSpecificsMIPS32(ArchSpecifics):
    def __init__(self, endness):
        super(ArchSpecificsMIPS32, self).__init__(endness)
        self._endness = endness
        self._uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 | endianness[endness])
        self._const = ConstMIPS32()
        self._archinfo_registers = archinfo.ArchMIPS32().register_list[0:30] + archinfo.ArchMIPS32().register_list[31:33]
        self._patch = PatchMIPS32Patch(endness)
        self._context = ContextMIPS32(self._uc)
        self._userhooks = UserHooksMIPS32(self._uc)
        ArchSpecificsMIPS32.mips_enable_DSP(self._uc)

    @staticmethod
    def mips_enable_DSP(uc):
        # enable DSP
        dsp = uc.reg_read(UC_MIPS_REG_CP0_STATUS)
        dsp |= (1 << 24)
        uc.reg_write(UC_MIPS_REG_CP0_STATUS, dsp)

    @property
    def const(self):
        return self._const
    
    @property
    def gdb_registers(self):
        return mips_registers

    @property
    def archinfo_registers(self):
        # unicorn doesn't support s8
        return self._archinfo_registers

    def read_initial_sp(self, config, image_base):
        if "initial_sp" in config:
            return config["initial_sp"]
        
        raise KeyError("initial_sp is not found")

    def read_entry_point(self, config, image_base):
        if "entry_point" in config:
            return config["entry_point"]

        raise KeyError("entry_point is not found")       

    def return_addr(self, addr, thumb_mode = True):
        return addr


    @property
    def target_xml(self):
        return mips32_target_xml

    @property
    def dump_template(self):
        return ("arch=MIPS32\n" + "endness=LE\n" if self._endness == "LE" else "endness=BE\n") \
            + mips_dump_template

    @property
    def all_const(self):
        return mips_const
    
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
