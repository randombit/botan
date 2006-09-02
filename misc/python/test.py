#!/usr/bin/python

import sys, botan

class PyAlgo(botan.Algorithm):
    def name(self):
        return "PyAlgo"
    def clear(self):
        print "clearing"

def main():
    alg = PyAlgo()
    botan.print_algo(alg)

if __name__ == "__main__":
    sys.exit(main())
