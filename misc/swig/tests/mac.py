#!/usr/bin/python

import botan, base64

mac = botan.MAC("HMAC(SHA-512)")

print mac.name
print mac.output_length

mac.set_key(botan.SymmetricKey("abcd"))
mac.update("hi chappy")
print base64.b16encode(mac.final())
