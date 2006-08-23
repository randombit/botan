#!/usr/bin/python

import sys, botan

def do_hash(input):
    cipher_key = botan.SymmetricKey("AABB")
    
    pipe = botan.Pipe(botan.Filter("Blowfish/CBC/PKCS7",
                                   key = botan.SymmetricKey("AABB"),
                                   iv = botan.InitializationVector("AABBCCDDEEFF0011"),
                                   dir = botan.cipher_dir.encryption),
                      botan.Filter("Hex_Encoder"))

    pipe.start_msg()
    pipe.write(input)
    pipe.end_msg()

    return pipe.read_all_as_string()

def main():
    print do_hash("hi chappy")

if __name__ == "__main__":
    sys.exit(main())
