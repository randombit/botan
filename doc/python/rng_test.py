#!/usr/bin/python

import botan

rng = botan.RandomNumberGenerator()

print "name", rng.name()

rng.add_entropy("blah")

print "random 16", rng.gen_random(16).encode("hex")
print "random 32", rng.gen_random(32).encode("base64"),

rng.reseed()

for i in range(0, 10):
    print rng.gen_random_byte(),
print

rng.add_entropy("blah")

print "random 16", rng.gen_random(16).encode("hex")
