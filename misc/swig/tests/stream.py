#!/usr/bin/python

import botan, base64

cipher = botan.StreamCipher("ARC4")

print cipher.name

key = botan.SymmetricKey(16)

cipher.set_key(key)
ciphertext = cipher.crypt("hi chappy")

cipher.set_key(key)
plaintext = cipher.crypt(ciphertext)

print plaintext
