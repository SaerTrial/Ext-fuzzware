from .arch import Const, ArchSpecifics, logger
from unicorn.arm_const import *
from unicorn import *
import archinfo
from ..util import bytes2int

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

class ArchSpecificsARMCortexM(ArchSpecifics):
    def __init__(self, endness):
        super(ArchSpecificsARMCortexM, self).__init__(endness)
        self._endness = endness
        self._uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS | endianness[endness])

    @property
    def const(self):
        return ConstARMCortexM()

    @property
    def gdb_registers(self):
        return arm_registers

    @property
    def archinfo_registers(self):
        return archinfo.ArchARMCortexM().register_list

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