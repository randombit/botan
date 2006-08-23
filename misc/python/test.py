#!/usr/bin/python

import sys, botan

def encrypt(input):
    pipe = botan.Pipe(botan.Filter("ARC4",
                                   key = botan.SymmetricKey("AABB")),
                      botan.Filter("Hex_Encoder"))

    pipe.start_msg()
    pipe.write(input)
    pipe.end_msg()

    return pipe.read_all_as_string()

def decrypt(input):
    pipe = botan.Pipe(botan.Filter("Hex_Decoder"),

                      botan.Filter("ARC4",
                                   key = botan.SymmetricKey("AABB")))

    pipe.start_msg()
    pipe.write(input)
    pipe.end_msg()

    return pipe.read_all_as_string()

def main():
    ciphertext = encrypt("hi chappy")
    print ciphertext
    print decrypt(ciphertext)

if __name__ == "__main__":
    sys.exit(main())
