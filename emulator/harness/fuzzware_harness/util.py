import os
import signal
import string
import struct
import sys
from glob import glob as directory_glob
import archinfo
from unicorn import *
from unicorn.mips_const import *
from unicorn.arm_const import *
import yaml

from . import globs

import logging
logger = logging.getLogger("emulator")


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

arm_registers = {'r0': UC_ARM_REG_R0, 'r1': UC_ARM_REG_R1, 'r2': UC_ARM_REG_R2,
                         'r3': UC_ARM_REG_R3, 'r4': UC_ARM_REG_R4, 'r5': UC_ARM_REG_R5,
                         'r6': UC_ARM_REG_R6, 'r7': UC_ARM_REG_R7, 'r8': UC_ARM_REG_R8,
                         'r9': UC_ARM_REG_R9, 'r10': UC_ARM_REG_R10, 'r11': UC_ARM_REG_R11,
                         'r12': UC_ARM_REG_R12, 'sp': UC_ARM_REG_SP, 'lr': UC_ARM_REG_LR,
                         'pc': UC_ARM_REG_PC, 'cpsr': UC_ARM_REG_CPSR}

def parse_address_value(symbols, value, enforce=True):
    if isinstance(value, int):
        return value
    if "+" in value:
        name, offset = value.split("+")
        name = name.rstrip(" ")
        offset = int(offset, 0)
    else:
        name = value
        offset = 0
    if name in symbols:
        return symbols[name] + offset
    try:
        return int(value, 16)
    except ValueError:
        if enforce:
            logger.error(f"Could not resolve symbol '{value}' and cannot proceed. Exiting...")
            if not symbols:
                logger.info("Hint: No symbols found - did you forget to (generate and) include a symbols file?")
            if sum([value.count(d) for d in string.digits]) > 2:
                logger.info("Hint: Found multiple digits in the value - did you mis-type a number?")
            sys.exit(1)
        return None


def parse_symbols(config):
    name_to_addr = {}
    addr_to_name = {}
    # TODO: due to the dependency of this function, 
    # we still use a single thumb bit cleaner here
    thumb_bit_cleaner = 0xFFFFFFFF
    if config["arch"] == "ARMCortexM":
        thumb_bit_cleaner = 0xFFFFFFFE

    # Create the symbol table
    if 'symbols' in config:
        try: 
            addr_to_name = {thumb_bit_cleaner & k: v for k, v in config['symbols'].items()}
            name_to_addr = {v: thumb_bit_cleaner & k for k, v in config['symbols'].items()}
        except TypeError as e:
            logger.error("Type error while parsing symbols. The symbols configuration was likely mis-formatted. The format is 0xdeadbeef: my_symbol_name. Raising original error.")
            raise e
    return name_to_addr, addr_to_name


def closest_symbol(addr_to_name, addr, max_offset=0x1000):
    """
    Find the symbol which is closest to addr, alongside with its offset.

    Returns:
        - (symbol_name, offset_to_symbol) if a symbol exists with an offset of a maximum of max_offset
        - Otherwise, (None, None) is returned in case no symbol with appropriate offset exists
    """
    if not addr_to_name:
        return (None, None)

    sorted_addrs = sorted(addr_to_name)
    for i, sym_addr in enumerate(sorted_addrs):
        # last entry?
        if i == len(sorted_addrs) - 1 or sorted_addrs[i+1] > addr:
            off = addr - sym_addr
            if 0 <= off <= max_offset:
                return addr_to_name[sym_addr], off
            return (None, None)
    return (None, None)

def bytes2int(bs):
    if len(bs) == 4:
        return struct.unpack("<I", bs)[0]
    if len(bs) == 2:
        return struct.unpack("<H", bs)[0]
    if len(bs) == 1:
        return struct.unpack("<B", bs)[0]
    if len(bs) == 8:
        return struct.unpack("<Q", bs)[0]
    from binascii import hexlify
    logger.info("Can not unpack {} bytes: {}".format(len(bs), hexlify(bs)))
    assert False


def int2bytes(i):
    return struct.pack("<I", i)


def crash(sig=signal.SIGSEGV):
    logger.error("-------------------------------- CRASH DETECTED-------------------------")
    os.kill(os.getpid(), sig)


def ensure_rw_mapped(uc, start, end):
    start = start & (~0xfff)
    end = (end + 0xfff) & (~0xfff)
    if start == end:
        end += 0x1000

    if all([start < rstart or end > rstart + size for rstart, size, _ in globs.regions.values()]):
        logger.info("Adding mapping {:08x}-{:08x} because of a configured mmio model".format(start, end))
        globs.regions['mmio_model_region_{:x}_{:x}'.format(start, end)] = (start, end-start, 3)
        uc.mem_map(start, end-start, 3)

###########
# Stuff about configuration files

def _merge_dict(dct, merge_dct):
    for k, _ in merge_dct.items():
        if (k in dct and isinstance(dct[k], dict)
                and isinstance(merge_dct[k], dict)):
            _merge_dict(dct[k], merge_dct[k])
        else:
            dct[k] = merge_dct[k]

def adjust_config_relative_paths(config, base_path):
    # "./"-prefixed paths to properly resolve relative to config snippet
    if 'memory_map' not in config:
        return

    for _, region in config['memory_map'].items():
        if 'file' in region and region['file'].startswith("./"):
            region['file'] = os.path.join(os.path.dirname(base_path), region['file'])
            logger.debug("Fixed up file path to '{}'".format(region['file']))

def resolve_config_includes(config, base_path):
    """
    Recursively resolves a config file, adjusting paths along
    the way
    """
    if 'include' in config:
        # Merge config files listed in 'include' in listed order
        # Root file gets priority
        newconfig = {}
        for f in config['include']:
            if not f.startswith("/"):
                # Make configs relative to the including config file
                cur_dir = os.path.dirname(base_path)
                f = os.path.abspath(os.path.join(cur_dir, f))

            logger.info(f"\tIncluding configuration from {f}")
            with open(f, 'rb') as infile:
                other_config_snippet = yaml.load(infile, Loader=yaml.FullLoader)
            adjust_config_relative_paths(other_config_snippet, f)
            other_config_snippet = resolve_config_includes(other_config_snippet, f)
            _merge_dict(newconfig, other_config_snippet)
        _merge_dict(newconfig, config)
        config = newconfig
    return config

def resolve_config_file_pattern(config_dir_path, f):
    """
    Resolve the path pattern in a config to the actual file path
    """
    if not f.startswith("/"):
        f = os.path.join(config_dir_path, f)

    if '*' in f:
        candidates = directory_glob(f)
        if len(candidates) != 1:
            raise ValueError("Could not unambiguously find pattern '{}' matching paths: {}".format(f, candidates))

        f = candidates[0]

    return os.path.abspath(f)

def resolve_region_file_paths(config_file_path, config):
    """
    Updates the config map's 'memory_map' entry, resolving patterns
    and relative paths.
    """

    for _, region in config['memory_map'].items():
        path = region.get('file')
        if path:
            region['file'] = resolve_config_file_pattern(os.path.dirname(config_file_path), path)
            logger.info("Found path '{}' for pattern '{}'".format(region['file'], path))

def load_config_deep(path):
    if not os.path.isfile(path):
        return {}
    with open(path, 'rb') as infile:
        config = yaml.load(infile, Loader=yaml.FullLoader)
    if config is None:
        return {}
    return resolve_config_includes(config, path)


# def create_unicorn_instance(arch, endianness = "little-endian"):
#     assert len(arch) != 0 and type(arch) == str
#     assert endianness == "little-endian" or endianness == "big-endian"  

#     if endianness == "little-endian":
#         uc_mode = UC_MODE_LITTLE_ENDIAN
#     else:
#         uc_mode = UC_MODE_BIG_ENDIAN

#     if arch.lower() == "mips32":
#         uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 | uc_mode)
#         uc.arch_name = "mips32"
#         uc.arch = archinfo.ArchMIPS32()
#         mips_enable_DSP(uc)
#     elif arch.lower() == "cortex-m":
#         uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS | uc_mode)
#         uc.arch_name = "cortex-m"
#         uc.arch = archinfo.ArchARMCortexM()
    
#     return uc


# def mips_enable_DSP(uc):
#     assert uc.arch_name == "mips32"

#     # enable DSP
#     dsp = uc.reg_read(UC_MIPS_REG_CP0_STATUS)
#     dsp |= (1 << 24)
#     uc.reg_write(UC_MIPS_REG_CP0_STATUS, dsp)


# def arm_clear_thumb_bit(arch_name, addr_val):
#     if arch_name != "cortex-m":
#         return addr_val

#     addr_val &= 0xFFFFFFFE

#     return addr_val


# def read_entry_point(config, entry_image_base, uc):
#     if "entry_point" in config:
#         return config["entry_point"]

#     if uc.arch_name != "cortex-m":
#         logger.error("For binaries of other archs, entry_point needs to be set up")
#         sys.exit(1)

#     if entry_image_base is None:
#         logger.error("Binary entry point missing! Make sure 'entry_point is in your configuration")
#         sys.exit(1)


#     entry_point = bytes2int(uc.mem_read(entry_image_base + 4, 4))

#     logger.debug(f"Recovered entry points: {entry_point:08x}")

#     return entry_point


# def read_initial_sp(config, entry_image_base, uc):
#     if "initial_sp" in config:
#         return config["initial_sp"]

#     if uc.arch_name != "cortex-m":
#         logger.error("For binaries of other archs, initial stack pointer needs to be set up")
#         sys.exit(1)

#     if entry_image_base is None:
#         logger.error("Binary entry point missing! Make sure 'entry_point is in your configuration")
#         sys.exit(1)
    

#     initial_sp =  bytes2int(uc.mem_read(entry_image_base, 4))

#     logger.debug(f"Recovered initial_sp: {initial_sp:08x}")

#     return initial_sp


# def get_current_pc(uc):
#     if uc.arch_name == "mips32":
#       return UC_MIPS_REG_PC
#     elif uc.arch_name == "cortex-m":
#       return UC_ARM_REG_PC

#     raise ValueError


# def get_current_sp(uc):
#     if uc.arch_name == "mips32":
#       return UC_MIPS_REG_SP
#     elif uc.arch_name == "cortex-m":
#       return UC_ARM_REG_SP

#     raise ValueError


# def get_arch_const(uc):
#     if uc.arch_name == "mips32":
#       return mips_const
#     elif uc.arch_name == "cortex-m":
#       return arm_const

#     raise ValueError

# def get_arch_registers(uc):
#     if uc.arch_name == "mips32":
#       return mips_registers
#     elif uc.arch_name == "cortex-m":
#       return arm_registers

#     raise ValueError