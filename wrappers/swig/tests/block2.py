#!/usr/bin/python

import botan, base64

class MyCipher(botan.BlockCipherImpl):
    def __init__(self):
        botan.BlockCipherImpl.__init__(self, 8, 8, 16, 1)

    def name(self):
        return "MyCipher"

    def encrypt(self, input):
        return input.swapcase()

    def decrypt(self, input):
        return input.swapcase()

    def set_key(self, key):
        print "Got key",key

def test(cipher):
    print
    print cipher
    print "Testing", cipher.name()
    print cipher.block_size
    print cipher.keylength_min, cipher.keylength_max, cipher.keylength_mod
    for i in range(1, 64):
        if cipher.valid_keylength(i):
            print "1",
        else:
            print "0",
    print
    cipher.set_key(botan.SymmetricKey(16))
    ciphertext = cipher.encrypt("aBcDeFgH" * (cipher.block_size / 8))
    print repr(ciphertext)
    print cipher.decrypt(ciphertext)

def main():
    test(botan.BlockCipher("Blowfish"))
    test(MyCipher())
    test(botan.BlockCipher("AES"))

if __name__ == "__main__":
    main()
