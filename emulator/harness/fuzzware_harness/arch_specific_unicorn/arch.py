import logging
logger = logging.getLogger("emulator")



class Const:
    def __init__(self) -> None:
        pass

    def __getattribute__(self, const_name):
        pass


class ArchSpecifics:
    def __init__(self, endness):
        self._uc = None
        self._endness = None

    @property
    def const(self):
        pass

    @property
    def gdb_registers(self):
        pass

    @property
    def archinfo_registers(self):
        pass
    
    def read_initial_sp(self, config, image_base):
        pass

    def read_entry_point(self, config, image_base):
        pass

    def return_addr(self, addr, thumb_mode = True):
        pass

    @property
    def target_xml(self):
        pass

    @property
    def snapshot_reg_cons(self):
        pass
    
    @property
    def dump_template(self):
        pass

    @property
    def uc(self):
        return self._uc    
    
