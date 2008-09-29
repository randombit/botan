#!/usr/bin/python

import sys, botan

class MyFilter(botan.FilterObj):
    def write(self, input):
        print "MyFilter::write",input
        self.send(input)
    def start_msg(self):
        print "MyFilter::start_msg"
    def end_msg(self):
        print "MyFilter::end_msg"
    def __del__(self):
        print "~MyFilter"

def main():
    filter = MyFilter()
    
    pipe = botan.Pipe(botan.Filter("Hex_Encoder"), filter,
                      botan.Filter("Hex_Decoder"))
    pipe.start_msg()
    pipe.write("hi chappy")
    pipe.end_msg()
    print pipe.read_all()

if __name__ == "__main__":
    sys.exit(main())
