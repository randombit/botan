#!/usr/bin/python

import sys, botan

class PyFilter(botan.FilterObj):
    def start_msg(self):
        print "PyFilter start_msg"
        self.send_str('initial')

    def end_msg(self):
        print "PyFilter end_msg"

    def write(self, data):
        print "PyFilter write called with", data
        self.send_str(data.replace('h', 'r'))

def encrypt(input):
    filter = PyFilter()
    
    pipe = botan.Pipe(filter)

    pipe.start_msg()
    pipe.write(input)
    pipe.end_msg()

    str = pipe.read_all()
    print str
    return str

def decrypt(input):
    pipe = botan.Pipe(botan.Filter("Hex_Decoder"),
                      botan.Filter("ARC4",
                                   key = botan.SymmetricKey("AABB")))

    pipe.process_msg(input)
    return pipe.read_all()

def main():
    ciphertext = encrypt("hi chappy")
    print ciphertext
    #print decrypt(ciphertext)

if __name__ == "__main__":
    sys.exit(main())
