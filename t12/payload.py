from pwn import *
context(arch='i386',os='linux')

def printable(ctt):
    return 1
    for i in ctt:
        if(i<=31 or i==127):
            return 0

t=b''

def shc(ctt):
    global t
    tmp=asm(ctt)
    if(not printable(tmp)):
        return "err"
    else:
        t+=tmp
        return tmp

print(shc('xor eax,eax'))
print(shc('add bl,0x4b'))
print(shc('sub bl,0x40'))
print(shc('mov eax,ebx'))
print(shc('int 0x80'))

print(disasm(b'\x6b\x40'))