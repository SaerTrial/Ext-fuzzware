from .arch_cortexm import ArchSpecificsARMCortexM
from .arch_mips32 import ArchSpecificsMIPS32

def identify_arch_from_statefile(arch, endness_line):
    arch = arch.split("=")[1]
    endness_line = endness_line.split("=")[1]

    selector = {"ARMCortexM": ArchSpecificsARMCortexM, "MIPS32": ArchSpecificsMIPS32}

    return selector[arch](endness_line)
    
