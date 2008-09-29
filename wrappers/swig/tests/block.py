#!/usr/bin/python

import botan, base64

class MyCipher(botan.BlockCipher):
    def __init__(self):
        botan.BlockCipher.__init__(self, 16, 16, 32, 8)
    def encrypt(self, val):
        print "encrypt", val
        return val.swapcase()
    def decrypt(self, val):
        print "decrypt", val
        return val.swapcase()
    def set_key(self, key):
        print "set_key", key
    def clone(self):
        print "cloning"
        return MyCipher()
    def name(self):
        print "naming"
        return "MyCipher"

cipher = botan.BlockCipher("AES-128")

print cipher.block_size
print cipher.keylength_min
print cipher.keylength_max
print cipher.keylength_mod
print cipher.name()

for kl in range(1, 128):
    if cipher.valid_keylength(kl):
        print "1",
    else:
        print "0",
print
key = botan.SymmetricKey(16)

cipher.set_key(key)
ciphertext = cipher.encrypt("ABCDEFGH12345678")
print base64.b16encode(ciphertext)

cipher2 = cipher.clone()
cipher2.set_key(key)

plaintext = cipher2.decrypt(ciphertext)
print plaintext

botan.get_info(cipher)

mycipher = MyCipher()
botan.get_info(mycipher)
