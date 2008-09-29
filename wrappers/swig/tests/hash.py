#!/usr/bin/python

import botan, base64, md5

class PyMD5(botan.HashFunctionImpl):
    def name(self):
        return "PyMD5"
    def update(self, input):
        self.md5.update(input)
    def final(self):
        output = self.md5.digest()
        self.md5 = md5.new()
        return output
    def __init__(self):
        botan.HashFunctionImpl.__init__(self, 16, 64)
        self.md5 = md5.new()

hash = botan.HashFunction("SHA-256")

print hash.name()
print hash.digest_size

hash.update("hi")
hash.update(" ")
hash.update("chappy")
print base64.b16encode(hash.final())

hash2 = PyMD5()
hash2.update("hi chappy")
print base64.b16encode(hash2.final())
