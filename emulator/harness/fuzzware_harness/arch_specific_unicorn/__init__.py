from .arch_cortexm import ArchSpecificsARMCortexM
from .arch_mips32 import ArchSpecificsMIPS32
import logging

logger = logging.getLogger("arch_specific_unicorn")


def create_unicorn_from_config(arch, endness):
    logger.debug(f"arch:{arch}, endness:{endness}")
    selector = {"ARMCortexM": ArchSpecificsARMCortexM, "MIPS32": ArchSpecificsMIPS32}

    arch_specifics = selector[arch](endness)
    uc = arch_specifics.uc
    uc.specifics = arch_specifics