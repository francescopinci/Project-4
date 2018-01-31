#!/usr/bin/env python2

import hashlib
import random
import sys

from forger import create_forgery

def badmac(key, msg):
    """
    Computes SHA256(key || msg) and returns a hex string.
    """
    md = hashlib.sha256()
    md.update(key)
    md.update(msg)
    return md.hexdigest()

def main():
    prng = random.SystemRandom()
    key = bytearray(prng.getrandbits(8) for _ in range(16))
    queries = set()

    def oracle(msg):
        queries.add(msg)
        return badmac(key, msg)

    forgery, mac = create_forgery(oracle)
    real_mac = badmac(key, forgery)

    print "Made {} distinct oracle call(s)".format(len(queries))
    print "Key:        {}".format(str(key).encode("hex"))
    print "Forgery:    {}".format(repr(forgery))
    print "Forged MAC: {}".format(mac)
    print "MAC:        {}".format(real_mac)

    if real_mac != mac:
        sys.exit("Failure: Forged MAC is incorrect")

    if forgery in queries:
        sys.exit("Failure: Forged message {} used in call to oracle".format(repr(forgery)))

    print "Success"
    return 0

if __name__ == '__main__':
    sys.exit(main())
