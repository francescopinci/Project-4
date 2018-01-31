from sha256 import process_chunk
from sha256 import hexdigest

def create_forgery(oracle):
    '''msgs = []
    macs = []'''
    md = []


    '''for i in range(10):
        msgs.append("msg %d" % i)
        macs.append(oracle(msgs[i]))'''
    
    evil = "evil"
    angel = "ciao"
    s1 = oracle(angel)
    
    # obtain output state
    view = memoryview(s1)
    for i in range(0,8):
	md.append(int(view[i*8:(i+1)*8].tobytes(),16))
	
    msg = angel
    # convert to hex
    msg_b = msg.encode("hex")
    msg_b = (int(msg_b, 16) << 1) | 1
    msg_b = msg_b << (512 - (16+len(angel))*8 - 64 - 1)
    msg_b = msg_b << 64 | (16+len(angel))*8
    
    msg = "%x" % int(bin(msg_b), 2)
    msg = msg.decode("hex")
    msg += evil
    
    # compute collision input
    x = evil
    
    evil_h = x.encode("hex")
    evil_h = (int(evil_h, 16) << 1) | 1
    evil_h = evil_h << (512 - 1 - 64 - (len(evil)*8))
    evil_h = evil_h << 64 | (len(msg)+16)*8
    
    x = "%x" % int(bin(evil_h), 2)
    x = x.decode("hex")
    
    process_chunk(md, memoryview(x))
    s2 = hexdigest(md)

    return (msg, s2)
