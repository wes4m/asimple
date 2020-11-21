# asimple
A quick and dirty script to assemble and emulate small chuncks of assembly instructions `x86-64 for now` for whatever reason you don't want to compile and open up a debugger. 

## Dependencies 
- Unicron-engine
- Keystone-engine

## Usage

For the simplest use case just have your instructions in a file
```bash
> python3 asimple.py -f example.txt
```

### Options
There are a few options available such as text base addr, size, stack base addr, size, hooks, and loops.

#### Hook file
Example hook file
```python
# exmaple_hook.py
from unicorn.x86_const import *

def instruction_hook(emulator, index, instruction):
    if instruction == "inc rax":
        emulator.reg_write(UC_X86_REG_RAX, 0x10)
```
```bash
> python3 asimple.py -f example.txt -hf example_hook.py
```

#### Other options
Other options such as custom text & stack base addr, custom sections size, specific instruction context prints and loops are available
```bash
# Sets different base addresses and sizes
> python3 asimple.py -f example.txt --base 0x2000 --size 0x1000 --stackbase 0xf000 --stacksize 0x1000
```

```bash
# Loops example.txt instructions 10 times
> python3 asimple.py -f example.txt --loop 10
```

```bash
# Only prints registers after execution of 3rd instruction
> python3 asimple.py -f example.txt -i 3
# Only prints registers after execution of 3rd instruction in 2nd loop
> python3 asimple.py -f example.txt -l 5 -i 2:3
```
