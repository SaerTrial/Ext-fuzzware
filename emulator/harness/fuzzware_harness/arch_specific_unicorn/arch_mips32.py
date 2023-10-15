from .arch import Const, ArchSpecifics
from unicorn.mips_const import *
from unicorn import *
import archinfo

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


class ArchSpecificsMIPS32(ArchSpecifics):
    def __init__(self, endness):
        super(ArchSpecificsMIPS32, self).__init__(endness)
        self._endness = endness
        self._uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 | endianness[endness])
        ArchSpecificsMIPS32.mips_enable_DSP(self._uc)

    @staticmethod
    def mips_enable_DSP(uc):
        # enable DSP
        dsp = uc.reg_read(UC_MIPS_REG_CP0_STATUS)
        dsp |= (1 << 24)
        uc.reg_write(UC_MIPS_REG_CP0_STATUS, dsp)

    @property
    def const(self):
        return ConstMIPS32()

    @property
    def gdb_registers(self):
        return mips_registers

    @property
    def archinfo_registers(self):
        # unicorn doesn't support s8
        return archinfo.ArchMIPS32().register_list[0:30] + archinfo.ArchMIPS32().register_list[31:33]

    def read_initial_sp(self, config, image_base):
        if "initial_sp" in config:
            return config["initial_sp"]
        
        raise KeyError("initial_sp is not found")

    def read_entry_point(self, config, image_base):
        if "entry_point" in config:
            return config["entry_point"]

        raise KeyError("entry_point is not found")       

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