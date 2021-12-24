from pwn import *
e=ELF('./libc_64.so.6')
print(hex(e.symbols['_IO_2_1_stdout_']))
print(hex(e.symbols['_IO_file_setbuf']))
print(hex(e.symbols['setvbuf']))