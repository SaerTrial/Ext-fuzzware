import logging
logger = logging.getLogger("emulator")



class Const:
    def __init__(self) -> None:
        pass

    def __getattribute__(self, const_name):
        pass


class Patch:
    def __init__(self, endness) -> None:
        pass

    def load_and_ret(self, addr, val):
        pass

    def ret(self):
        pass

    def nop(self):
        pass

class Context:
    def __init__(self, uc) -> None:
        self._uc = uc

    def print_context(self):
        pass

    def print_args(self, arg_num):
        pass

    def function_args(self, arg_num):
        pass

    def return_zero(self):
        pass

class UserHooks:
    def __init__(self, uc):
        self._uc = uc
    
    def calloc(self):
        pass

    def realloc(self):
        pass

    def malloc(self):
        pass

    def memp_free(self):
        pass

    def free(self):
        pass

    def puts(self):
        pass

    def putchar(self):
        pass

    def printf(self):
        pass

    def readline(self):
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
    
