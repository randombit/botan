#!/usr/bin/python

import sys, botan

def encrypt(input):
    cipher_key = botan.SymmetricKey("AABB")
    print cipher_key.length
    cipher_key = botan.SymmetricKey("AABBCCDD")
    print cipher_key.length

    cipher = botan.Filter("ARC4", key = cipher_key)
    
    pipe = botan.Pipe(cipher, botan.Filter("Hex_Encoder"))

    pipe.start_msg()
    pipe.write(input)
    pipe.end_msg()

    str = pipe.read_all()
    print str
    return str

def decrypt(input):
    pipe = botan.Pipe(botan.Filter("Hex_Decoder"),
                      botan.Filter("ARC4",
                                   key = botan.SymmetricKey("AABBCCDD")))

    pipe.process_msg(input)
    return pipe.read_all()

def main():
    ciphertext = encrypt("hi chappy")
    print ciphertext
    print decrypt(ciphertext)

if __name__ == "__main__":
    sys.exit(main())
