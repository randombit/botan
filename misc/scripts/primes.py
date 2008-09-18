#!/usr/bin/env python

import sys

def gcd(x,y):
    if x <= 0 or y <= 0:
       raise ValueError, "Arguments must be positive integers"
    g = y
    while x > 0:
        g = x
        x = y % x
        y = g
    return g


def gen_primes():
    primes = [2,3,5,7,11]

    # Primes < 11351 fit into less than 256x64 bits
    for i in xrange(1+primes[-1], 11351+1):
        for prime in primes:
            if gcd(i, prime) != 1:
                break
        else:
            primes.append(i)

    return primes

def extract_product(primes):
    product = 1

    used = set()

    for prime in sorted(primes, reverse=True):
        if product * prime < 2**64:
            product *= prime
            used.add(prime)

    primes -= used

    return product

def main():
    primes = gen_primes()

    primes.sort()
    primes.reverse()

    primes = set(primes)

    while len(primes):
        print "0x%016X, " % extract_product(primes)

    #product = 1
    #for prime in primes:
    #    product *= prime

    #    if product >= 2**64:
    #        print "%016X" % (product/prime)
    #        product = prime

if __name__ == '__main__':
    sys.exit(main())
