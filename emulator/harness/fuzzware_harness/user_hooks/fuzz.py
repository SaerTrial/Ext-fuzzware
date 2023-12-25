from unicorn.arm_const import UC_ARM_REG_R0
from .. import native

def get_fuzz(uc, size):
    """
    Gets at most 'size' bytes from the fuzz pool.

    If we run out of fuzz, something will happen (e.g., exit)
    :param size:
    :return:
    """
    return native.get_fuzz(uc, size)

def fuzz_remaining():
    return native.fuzz_remaining()

def load_fuzz(file_path):
    native.load_fuzz(file_path)

def return_fuzz_byte(uc):
    global fuzz
    c = get_fuzz(uc, 1)
    print("[return_fuzz_byte] writting data:{} into 0x{:02x}".format(c, uc.specifics.context.function_args()[0]), flush=True)
    uc.mem[uc.specifics.context.function_args()[0]] = c
 