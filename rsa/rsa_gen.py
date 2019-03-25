from primefac import *

target = 0x602560
error = 1

for p in primegen():
    if p < 0xfff:
        continue
    elif p > 0x10000:
        break

    for q in primegen():

        if q < 0xfff:
            continue
        elif q > 0x10000:
            break

        N = p*q
        r = (p-1)*(q-1)

        for i in range(1,256):
            K = i*r + 1

            if not isprime(K):
                K_facs = list(primefac(K))
                #print K_facs
                e = K_facs[-1]
                d = listprod(K_facs[:-1])

                #print "p: %d q: %d N: %d (0x%08x) e: %d d: %d" % (p, q, N, N, e, d)

                for j in range(256):
                    cipher = pow(j, e, N)

                    if cipher >= target and cipher < target + error:
                        print "p: %d q: %d N: %d (0x%08x) e: %d d: %d" % (p, q, N, N, e, d)
                        print "MAGIC BYTE: %02x (%s) ADDRESS: %08x (%d offset)" % (j, chr(j), cipher, cipher-target)
                        quit()
