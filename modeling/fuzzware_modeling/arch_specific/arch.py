import archinfo
import logging


l = logging.getLogger("arch_specific")


class ArchSpecifics:
    def __init__(self, endness):
        self.state_snapshot_reg_list = []
        self.scope_reg_names = ()
        self.regular_register_names = ()
        self.newly_added_constraints_reg_names = ()
        self.scratch_reg_names = ()
        self._arch = None
        self._endness = None

    def return_reg(self, state): 
        pass

    def translate_reg_name_to_vex_internal_name(self, name):
        pass

    def leave_reg_untainted(self, name):
        pass

    def read_pc(self, thumb_mode=False):
        pass

    @property
    def arch(self):
        return self._arch

    @property
    def quirks(self):
        pass

    @property
    def endianness(self):
        pass




    

        
