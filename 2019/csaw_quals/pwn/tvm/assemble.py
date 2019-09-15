#!/usr/bin/env python3
import struct
import sys
from binascii import hexlify

OP = {
        "DST": 0xDD,
        "HLT": 0xFE,
        "MOV": 0x88,
        "MOVI": 0x89,
        "PUSH": 0xED,
        "POP": 0xB1,
        "ADD": 0xD3,
        "ADDI": 0xC6,
        "SUB": 0xD8,
        "SUBI": 0xEF,
        "MUL": 0x34,
        "DIV": 0xB9,
        "XOR": 0xB7,
        "CMP": 0xCC,
        "JMP": 0x96,
        "JE": 0x81,
        "JNE": 0x9E,
        "JG": 0x2F,
        "JGE": 0xF4,
        "JL": 0x69,
        "JLE": 0x5F,
        "LDF": 0xD9,
        "AGE": 0x9B,
        "AGD": 0x7F,
}

REG = {
        "KAX": 0x0A,
        "KBX": 0x0b,
        "KCX": 0x0c,
        "KDX": 0x0d,
        "KPC": 0x0e,
        "KRX": 0x0f,
        "KSP": 0x10,
        "KFLAG": 0x11,
}


def p16(n):
    return struct.pack("<H", n)


def p64(n):
    return struct.pack("<Q", n)


def assemble(code):
    lines = code.split("\n")[:-1]
    bytecode = bytearray()

    for line in lines:
        print(line)
        if line == "":
            continue
        if line.startswith("#"):
            continue
        line = line.upper().replace(",", "")
        tmp = line.split(" ")

        opcode = tmp[0]
        # ldf, div, hlt, dst, agd
        if len(tmp) == 1:
            if tmp[0] == "SECRET":
                bytecode.append(0x42)
                bytecode.append(0x3f)
            else:
                bytecode.append(OP[opcode])
        elif len(tmp) == 2:
            # dst: POP
            # src: push, age
            # 
            # val: JLE, JL, JGE, JG, JNE, JMP
            # 16-bit immediate
            if opcode in [ "JLE", "JL", "JGE", "JG", "JNE", "JMP" ]:
                print("{}: val: {}".format(opcode, int(tmp[1])))
                bytecode.append(OP[opcode])
                bytecode.append(p16(int(tmp[1], 16)))
            elif opcode in [ "PUSH", "AGE" ]:
                src = REG[tmp[1]]
                print("{}: src: {} ({})".format(opcode, tmp[1], src))
                bytecode.append(OP[opcode])
                bytecode.append(src)
            elif opcode in [ "POP" ]:
                dst = REG[tmp[1]]
                print("{}: src: {} ({})".format(opcode, tmp[1], dst))
                bytecode.append(OP[opcode])
                bytecode.append(dst)
        elif len(tmp) == 3:
            # dst src: mov add sub mul xor
            # dst val: movi addi subi
            # reg1 reg2: cmp
            if opcode in [ "MOV", "ADD", "SUB", "MUL", "XOR", "CMP"]:
                dst = REG[tmp[1]]
                src = REG[tmp[2]]
                print("{} {} {}".format(opcode, dst, src))
                bytecode.append(OP[opcode])
                bytecode.append(dst)
                bytecode.append(src)
            elif opcode in [ "MOVI", "ADDI", "SUBI" ]:
                dst = REG[tmp[1]]
                val = p64(int(tmp[2], 16))
                print("{}: {} {}".format(opcode, dst, hexlify(val)))
                bytecode.append(OP[opcode])
                bytecode.append(dst)
                bytecode += val
        else:
            print("invalid opcode length!")
            sys.exit(1)

    with open("out.bin", "wb+") as f:
        f.write(bytecode)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: {} <code.s>".format(sys.argv[0]))
        sys.exit()

    contents = open(sys.argv[1], "r").read()
    assemble(contents)
