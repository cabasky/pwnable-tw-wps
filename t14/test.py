from pwn import *

host='chall.pwnable.tw'
port=10204
p=remote(host,port)

context.log_level='debug'
'''
print(p.recvuntil(b'name: '))
p.send(b'aaaa')
print(p.recvuntil(b'age: '))
p.sendline(b'24')
print(p.recvuntil(b'movie? '))
p.send(b'@'*8)
print(p.recvuntil(b'comment: '))
p.send(b'aaaa')
print(p.recv())'''

libc=ELF('./libc_32.so.6')
for i in libc.symbols:
    if(libc.symbols[i]%0x1000==0xd60):
        print(i)
