from .arch import *
from typing import Tuple
from ..angr_utils import all_states

REG_NAME_PC = 'pc'
REG_NAME_SP = 'sp'

OPCODE_WFI = 0x42000020
OPCODE_BYTE_BREAK = 0x0d


MIPS32_MMIO_START = 0xbf800000
MIPS32_MMIO_END   = 0xbf900000

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

    @classmethod
    def try_handling_decode_error(self, simulation, stash_name, addr):
        sample_state = simulation.stashes[stash_name][0]
        if sample_state.mem_concrete(addr, 4) == OPCODE_BYTE_BREAK:
            # Clear block translation cache
            sample_state.project.factory.default_engine._block_cache.clear()
            for state in all_states(simulation):
                assert(state.mem_concrete(addr, 4) == OPCODE_BYTE_BREAK)
                state.memory.store(addr, OPCODE_WFI, 4, disable_actions=True, inspect=False, endness=state.project.arch.memory_endness)
            return True
        else:
            return False   


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

        self.scratch_reg_names = ('a0', 'a1', 'a2', 'a3', 't4', 't5', 't6', 't7', 't8', 't9')

        if endness == "LE":
            self._arch = archinfo.ArchMIPS32(endness='Iend_LE')
            self._endness = archinfo.Endness.LE
        else:
            self._arch = archinfo.ArchMIPS32(endness='Iend_BE')
            self._endness = archinfo.Endness.BE

    def return_reg(self, state):
        if state is None:
            raise ValueError("State is None")
        return state.regs.v0, state.regs.v1
    
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
        return [DEFAULT_MMIO_RANGES, (MIPS32_MMIO_START, MIPS32_MMIO_END), (ISR_START_IN_ROM, ISR_START_IN_ROM | 0xfff)]

    @property
    def endianness(self):
        return self._endness
    
    @property
    def REG_SP(self):
        return REG_NAME_SP
    
    @property
    def REG_PC(self):
        return REG_NAME_PC
