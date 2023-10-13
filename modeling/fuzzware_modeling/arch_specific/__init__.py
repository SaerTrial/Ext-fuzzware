from .arch_cortexm import ArchSpecificsARMCortexM
from .arch_mips32 import ArchSpecificsMIPS32
import re

line_match = re.compile(r"^[a-zA-Z]{2,9}=([0-9a-zA-Z]+)$")

def identify_arch_from_statefile(arch, endness_line):
    arch = line_match.match(arch).group(1)
    endness  = line_match.match(endness_line).group(1)
    print(f"arch:{arch}, endness:{endness}")
    selector = {"ARMCortexM": ArchSpecificsARMCortexM, "MIPS32": ArchSpecificsMIPS32}

    return selector[arch](endness)
    
