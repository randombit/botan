#!/usr/bin/python

import botan
import sys

def encrypt(input, passphrase):
    rng = botan.RandomNumberGenerator()

    # Use as both EAX IV and PBKDF2 salt
    salt = rng.gen_random(10)

    iterations = 10000
    output_size = 16

    key = botan.pbkdf2(passphrase, salt, iterations, output_size, "SHA-1")

    encryptor = botan.Cipher("AES-128/EAX", "encrypt", key)

    ciphertext = encryptor.cipher(input, salt)
    return (ciphertext, salt)

def decrypt(input, salt, passphrase):
    iterations = 10000
    output_size = 16

    key = botan.pbkdf2(passphrase, salt, iterations, output_size, "SHA-1")

    decryptor = botan.Cipher("AES-128/EAX", "decrypt", key)

    return decryptor.cipher(input, salt)

def main(args = None):
    if args is None:
        args = sys.argv

    passphrase = args[1]
    input = ''.join(open(args[2]).readlines())

    (ciphertext, salt) = encrypt(input, passphrase)

    print decrypt(ciphertext, salt, passphrase)

if __name__ == '__main__':
    sys.exit(main())
