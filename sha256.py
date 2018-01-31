#!/usr/bin/env python2

import struct
import math
import sys
from struct import pack

def bitwise_not(x):
    return (1 << 32) - 1 - x

def toBits(x):
    x = x.encode("hex")
    x = int(x, 16)

    return x

def init_round():
    
    k = [ 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 ]

    return k

def rightrotate(x, n):    	

    x = x.encode("hex")
    x = int(x, 16)

    for i in range(0, n):
	temp = x & 0x1
	x = x >> 1
	temp = temp << 31
	x = x | temp
	
    #print bin(x)
    #x = "%08x" % int(bin(x), 2)
    #print x
    #x = x.decode("hex")

    return x

def leftrotate(x, n):    	
        
    for i in range(0, n):
	temp = x & 0b10000000
	x = x << 1
	temp = temp >> 31
	x = x | temp

    return x

def pad_message(msg):
    """ Pad msg appropriately for SHA-256. """
    L = len(msg)*8 		# length of msg in bits

    K = 0
    while True:
        if ((L + 1 + K + 64)%512) == 0:
	    break
	K=K+1

    msg_b = msg.encode("hex")   # convert msg from ASCII to hex
    msg_b = (int(msg_b, 16)<<1) | 1	# concat msg a '1' bit
    msg_b = msg_b << K			# concat K '0' bits
    msg_b = msg_b << 64 | L		# concat 64-bit big-endian L
    
    msg = "%x" % int(bin(msg_b), 2)	# convert msg_b to hex representation
    msg = msg.decode("hex")		# decode from hex to string

    return msg				# return the msg as string

def process_chunk(md, chunk):
    """ Process the next 512-bit chunk, updating the md array. """
    k = init_round()
    w = [['\x00' for x in range(0, 4)] for i in range(0, 64)]                      
    
    for i in range(0,16):
	for j in range(0,4):
	    w[i][j] = chunk[4*i+j]

    for i in range(0, 48):
	s0 = rightrotate(''.join(w[i+ 1]),  7) ^ rightrotate(''.join(w[i+ 1]), 18) ^ (toBits(''.join(w[i+ 1])) >> 3)
	s1 = rightrotate(''.join(w[i+14]), 17) ^ rightrotate(''.join(w[i+14]), 19) ^ (toBits(''.join(w[i+14])) >> 10)
	    
	temp = (toBits(''.join(w[i])) + s0 + toBits(''.join(w[i+9])) + s1)
	temp = int(bin(temp), 2)%math.pow(2, 32)
	temp = "%08x" % int(temp)
	temp = temp.decode("hex")
	for j in range(0, 4):
	    w[i+16][j] = temp[j]
	     

    a = "%08x" % int(md[0])
    b = "%08x" % int(md[1])
    c = "%08x" % int(md[2])
    d = "%08x" % int(md[3])
    e = "%08x" % int(md[4])
    f = "%08x" % int(md[5])
    g = "%08x" % int(md[6])
    h = "%08x" % int(md[7])

    for i in range(0, 64):

	S1 = rightrotate(e.decode("hex"), 6) ^ rightrotate(e.decode("hex"), 11) ^ rightrotate(e.decode("hex"), 25)

	ch = (toBits(e.decode("hex")) & toBits(f.decode("hex"))) ^ (bitwise_not((toBits(e.decode("hex")))) & toBits(g.decode("hex")))

	k_str = "%08x" % int(k[i])
	
	temp1 = toBits(h.decode("hex")) + S1 + ch + toBits(k_str.decode("hex")) + toBits(''.join(w[i]))

	temp1 = int(int(bin(temp1), 2)%math.pow(2, 32))

	S0 = rightrotate(a.decode("hex"), 2) ^ rightrotate(a.decode("hex"), 13) ^ rightrotate(a.decode("hex"), 22)

        maj = (toBits(a.decode("hex")) & toBits(b.decode("hex"))) ^ (toBits(a.decode("hex")) & toBits(c.decode("hex"))) ^ (toBits(b.decode("hex")) & toBits(c.decode("hex")))

        temp2 = S0 + maj

        temp2 = int(int(bin(temp2), 2)%math.pow(2, 32))
	
	h = g
	g = f
	f = e
	tmp = int((int(d, 16) + temp1)%math.pow(2, 32))
	tmp = "%08x" % int(tmp)
	e = tmp
	d = c
	c = b
	b = a
	tmp = int((temp1 + temp2)%math.pow(2, 32))
	tmp = "%08x" % int(tmp)
	a = tmp
	
    md[0] = int((md[0] + int(a, 16))%math.pow(2, 32))
    md[1] = int((md[1] + int(b, 16))%math.pow(2, 32))
    md[2] = int((md[2] + int(c, 16))%math.pow(2, 32))
    md[3] = int((md[3] + int(d, 16))%math.pow(2, 32))
    md[4] = int((md[4] + int(e, 16))%math.pow(2, 32))
    md[5] = int((md[5] + int(f, 16))%math.pow(2, 32))
    md[6] = int((md[6] + int(g, 16))%math.pow(2, 32))
    md[7] = int((md[7] + int(h, 16))%math.pow(2, 32))

def hexdigest(md):
    """ Return the hex digest of the hashed value. """
    digest = ''
    for var in md:
        digest += "{:08x}".format(var)
    return digest

def sha256(msg):
    """ Return the SHA-256 hash of msg as a hex string. """
    # Pad the message
    msg = pad_message(msg)

    # Initialization vector
    md = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

    # Break msg into 512-bit chunks
    view = memoryview(msg)
    for chunk_start in range(0, len(msg), 64):
        process_chunk(md, view[chunk_start:chunk_start+64])

    # Produce the final value
    return hexdigest(md)

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        sys.exit("Usage: {} string".format(sys.argv[0]))
 
    print sha256(sys.argv[1]) 
