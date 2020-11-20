from unicorn.x86_const import *

# Example code
# PRE instruction exection
def instruction_hook(emulator, index, instruction):
    if instruction == "INC RAX":
        emulator.reg_write(UC_X86_REG_RAX, 0x5)
