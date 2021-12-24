from pwn import *
libc=ELF('libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so')
for i in dir(libc):
    print(i)

for i in libc.sections:
    print(i)