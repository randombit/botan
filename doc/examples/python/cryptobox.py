#!/usr/bin/python

import sys
import botan

def main(args = None):
    if args is None:
        args = sys.argv

    if len(args) != 3:
        raise Exception("Usage: <password> <input>");

    password = args[1]
    input = ''.join(open(args[2]).readlines())

    rng = botan.RandomNumberGenerator()

    ciphertext = botan.cryptobox_encrypt(input, password, rng)

    print ciphertext

    plaintext = ''

    try:
        plaintext = botan.cryptobox_decrypt(ciphertext, password + 'FAIL')
    except Exception, e:
        print "Good news: bad password caused exception: "
        print e

    plaintext = botan.cryptobox_decrypt(ciphertext, password)

    print "Original input was: "
    print plaintext

if __name__ == '__main__':
    sys.exit(main())
