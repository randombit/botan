#!/usr/bin/python

import botan

key = botan.X509_PublicKey("rsapub.pem")
print key
print key.key_id()
print key.max_input_bits
print key.algo
print key.oid
