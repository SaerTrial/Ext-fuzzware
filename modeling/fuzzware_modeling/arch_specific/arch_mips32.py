from .arch import *
from typing import Tuple


REG_NAME_PC = 'pc'
REG_NAME_SP = 'sp'


CORTEXM_MMIO_START = 0xbf800000
CORTEXM_MMIO_END   = 0xbf900000

""" MMIO Ranges """
DEFAULT_MMIO_RANGES = (
    # MIPS32 System register ranges
    (0xFFFF0000, 0xFFFFFFFF),
)

ISR_START_IN_ROM = 0xbfc00000

class MIPS32Quirks():
    def __init__(self):
        pass
    
    @classmethod
    def add_special_initstate_reg_vals(self, initial_state, regs):
        pass

    @classmethod
    def model_arch_specific(self, project, initial_state, base_snapshot, simulation) -> Tuple[str, dict]:
        return None, None

class ArchSpecificsMIPS32(ArchSpecifics):
    def __init__(self, endness):
        super(ArchSpecificsMIPS32, self).__init__(endness)
        self.state_snapshot_reg_list = ['zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2',
                            'a3', 't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
                            's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 't8',
                            't9', 'k0', 'k1', 'gp', 'sp', 'ra', 'pc']
        
        self.scope_reg_names = ('at', 'v0', 'v1', 'a0', 'a1', 'a2',
                            'a3', 't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
                            's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 't8',
                            't9', 'k0', 'k1', 'gp', 'sp', 'ra', 'pc')
        
        self.regular_register_names = ('zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2',
                            'a3', 't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
                            's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 't8',
                            't9', 'k0', 'k1', 'gp', 'sp', 'ra')
        
        self.newly_added_constraints_reg_names = self.scope_reg_names

        if endness == "LE":
            self.arch = archinfo.ArchMIPS32(endness='Iend_LE')
        else:
            self.arch = archinfo.ArchMIPS32(endness='Iend_BE')

    def return_reg(self):
        if self.state is None:
            raise ValueError("State is None")
        return self.state.regs.v0, self.state.regs.v1
    
    def translate_reg_name_to_vex_internal_name(self, name):
        name = name.lower()
        return name
    
    def leave_reg_untainted(self, name):
        # TODO: more regs to be added
        return False
    
    def read_pc(self, regs, thumb_mode=False):
        return regs[REG_NAME_PC]
    
    @property
    def quirks(self):
        return MIPS32Quirks
    
    def mmio_and_isr_range(self):
        # default mmio range
        # MMIO range to be added
        # ISR range
        return [DEFAULT_MMIO_RANGES, (CORTEXM_MMIO_START, CORTEXM_MMIO_END), (ISR_START_IN_ROM, ISR_START_IN_ROM | 0xfff)]
