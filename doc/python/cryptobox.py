#!/usr/bin/python

import sys
import botan

def main(args = None):
    if args is None:
        args = sys.argv

    if len(args) != 3:
        raise Exception("Bad usage")

    password = args[1]
    input = ''.join(open(args[2]).readlines())

    rng = botan.RandomNumberGenerator()

    ciphertext = botan.cryptobox_encrypt(input, password, rng)

    print ciphertext

    plaintext = ''

    try:
        plaintext = botan.cryptobox_decrypt(ciphertext, password + 'FAIL')
    except Exception, e:
        print "Oops -- ", e

    plaintext = botan.cryptobox_decrypt(ciphertext, password)

    print plaintext

if __name__ == '__main__':
    sys.exit(main())
