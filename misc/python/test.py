#!/usr/bin/python

import sys, botan

def do_hash(input):
    pipe = botan.Pipe(botan.Filter("Hex_Encoder"),
                      botan.Filter("Hex_Decoder"))

    pipe.start_msg()
    pipe.write(input)
    pipe.end_msg()

    return pipe.read_all_as_string()

def main():
    print do_hash("hi chappy")

if __name__ == "__main__":
    sys.exit(main())
