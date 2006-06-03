#!/usr/bin/python

import sys, botan

def do_hash(input):
    pipe = botan.Pipe(botan.Filter("MD5"), botan.Filter("Hex_Encoder"))

    print pipe
    pipe.start_msg()
    pipe.write(input)
    pipe.end_msg()

    return pipe.read_all()

def main():
    print do_hash("foo")

if __name__ == "__main__":
    sys.exit(main())
