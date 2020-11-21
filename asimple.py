#!/usr/bin/python3

import argparse
import sys
import array
from os import path
from keystone import *
from unicorn import *
from unicorn.x86_const import *
import importlib.util

def importer(module):
    spec = importlib.util.spec_from_file_location("hooks", module)
    instance = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(instance)
    return instance

def get_ks_options(arch, mode):
    ks_arch = KS_ARCH_X86 if arch == UC_ARCH_X86 else None
    ks_mode = KS_MODE_64 if mode == UC_MODE_64 else None

    return ks_arch, ks_mode


def assemble(instructions, arch, mode):
    ks_arch, ks_mode = get_ks_options(arch, mode)

    assembler = Ks(ks_arch, ks_mode)
    return assembler.asm(instructions)


# Not modular, edit later
def dump_registers(emulator):
    registers = {
        "RAX": emulator.reg_read(UC_X86_REG_RAX),
        "RBX": emulator.reg_read(UC_X86_REG_RBX),
        "RCX": emulator.reg_read(UC_X86_REG_RCX),
        "RDX": emulator.reg_read(UC_X86_REG_RDX),
        "RBP": emulator.reg_read(UC_X86_REG_RBP),
        "RSP": emulator.reg_read(UC_X86_REG_RSP),
        "RIP": emulator.reg_read(UC_X86_REG_RIP),
    }

    print("\t>  Registers: ")
    for reg in registers:
        print("\t\t{} = 0x{:08x}".format(reg, registers[reg]) )
    print()

def dump_assembly(code, count):
    print(f"[A] Instructions count: {hex(count)}")
    print(f"[A] Assembled size: {hex(len(code))}")
    print("[A] Assembled bytes:")

    dump = '\t['
    line_counter = 0
    for b in code:
        if line_counter == 15:
            line_counter = 0
            dump += "\n"
        dump += str(hex(b)) + ", "
    dump = dump[:-2]
    dump += "]"

    print(dump)

current_instruction = 0
loop_index = 0
index_specification  = None
def instruction_hook(emulator, addr, size, data):
    global current_instruction, index_specification, loop_index

    # Call hook if it exists 
    if data[1] is not None:
        data[1].instruction_hook(emulator, current_instruction, data[0].split(';')[current_instruction].strip())

    print(f"\n[{current_instruction}] Tracing instruction at {hex(addr)}, instruction size {hex(size)}:")
    if current_instruction == 0:
        print(f"[{current_instruction}] Exectued instruction: None yet. Initial state.")
    if current_instruction > 0:
        print(f"[{current_instruction}] Exectued instruction: {data[0].split(';')[current_instruction-1]}")

    if index_specification is None:
        dump_registers(emulator)
    else:
        if ( (index_specification[0] == loop_index) or (loop_index == -1)) and (index_specification[1] == current_instruction):
            dump_registers(emulator)

    current_instruction += 1


def runner(inst_file, arch, mode, text_base, text_size, stack_base, stack_size, hook, loop, index):
    global current_instruction, index_specification, loop_index

    if not path.exists(inst_file):
        print(f"File {inst_file} does not exist.")
        return

    instructions = open(inst_file, "r").read().strip()
    instructions = instructions.replace("\n", "; ")

    # Assembling
    code, count = assemble(instructions= instructions,
                          arch=  arch,
                          mode= mode)
    dump_assembly(code, count)


    # Initial mappings.
    emulator  = Uc(arch, mode)

    print( f"\n[E] Allocating Text: {hex(text_size)} bytes at base {hex(text_base)}" )
    emulator.mem_map(text_base, text_size)
    print( f"\n[E] Writing assembly to Text" )
    emulator.mem_write(text_base, array.array('B', code).tostring())
    print( f"[E] Allocating Stack: {hex(stack_size)} bytes at base {hex(stack_base)}" )
    emulator.mem_map(stack_base, stack_size)
    print( f"[E] Zeroing out the stack." )
    emulator.mem_write(stack_base, b'\x00' * stack_size)

    # this is not modular enoguh for now, edit later
    print( f"[E] Setting RSP to {hex(stack_base)}" )
    emulator.reg_write(UC_X86_REG_RSP, stack_base)

    hook_instance = None
    if hook is not None:
        hook_instance = importer(hook)

    if index is not None:
        loop_index = -1
        inst_index = index
        if "-" in index:
            indexer = index.split('-')
            loop_index = int(indexer[0].strip())
            inst_index = int(indexer[1].strip())
        else:
            inst_index = int(inst_index.strip())
        index_specification = [loop_index, inst_index]

    # Hooking execution at every instruction
    emulator.hook_add(UC_HOOK_CODE, instruction_hook, user_data= [instructions, hook_instance])



    # Start emulation
    size = len(code)
    print( f"[E] Executing instructions starting at {hex(text_base)} to {hex(text_base + size)}." )

    if loop == None:
        loop = 1

    for i in range(loop):
        if loop_index != -1:
            loop_index = i
        if i > 0:
            print(f"[E] Starting {str(i)} Loop")
        current_instruction = 0
        emulator.emu_start(text_base, text_base + size)

        # End state
        print(f"[{current_instruction}] Exectued instruction: {instructions.split(';')[current_instruction-1]}")
        if index_specification is None:
            dump_registers(emulator)
        else:
            if ((index_specification[0] == i) or (loop_index == -1)) and (index_specification[1] == current_instruction):
                dump_registers(emulator)

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Simple assembler and emulator for x86-64 asm.')
    parser.add_argument('--file', "-f", help='Assembly instructions text file')

    parser.add_argument('--base', "-b", type=lambda x: hex(int(x,0)), default="0x1000", help='Text base address')
    parser.add_argument('--size', "-s", type=lambda x: hex(int(x,0)), default="0x1000", help='Text size')

    parser.add_argument('--stackbase', "-sb", type=lambda x: hex(int(x,0)), default="0xf000", help='Stack base address')
    parser.add_argument('--stacksize', "-sz", type=lambda x: hex(int(x,0)), default="0x1000", help='Stack size')

    parser.add_argument('--hook', "-hf", help='Python hook file')
    parser.add_argument('--loop', "-l", type=int, help='Count to loop execution of instrctions')

    parser.add_argument('--index', "-i", help='When specified, context will be printed after execution of instruction index i only, or loop-index')

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    if args.file is not None:
        # Might add more archs options later .. 
        runner(inst_file= args.file,
               arch= UC_ARCH_X86,
               mode= UC_MODE_64,
               text_base= int(args.base, 16),
               text_size= int(args.size, 16),
               stack_base= int(args.stackbase, 16),
               stack_size= int(args.stacksize, 16),
               hook= args.hook,
               loop= args.loop,
               index= args.index)

