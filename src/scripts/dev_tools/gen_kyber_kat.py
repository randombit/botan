#!/usr/bin/env python3

#
# Strips the KAT harness in the Kyber reference implementation down
# to a less space consuming version. This script was used to generate
# `src/tests/data/pubkey/kyber_kat.vec` test data from the *.rsp files in
# the reference implementation repository.
#
# See here: https://github.com/pq-crystals/kyber
#
# NOTE! The reference implementation does not distinguish between vanilla
#       Kyber and the 90s mode when generating the *.rsp files. Run this
#       script to retrofit the distinction:
#
#       rm -f *.rsp
#       mkdir KATs
#       for gen in PQCgenKAT_kem1024 PQCgenKAT_kem1024-90s PQCgenKAT_kem512 PQCgenKAT_kem512-90s PQCgenKAT_kem768 PQCgenKAT_kem768-90s; do
#         ./$gen
#         mv *.rsp KATs/${gen}.rsp
#       done
#
# (C) 2023 Jack Lloyd
# (C) 2023 René Meusel - Rohde & Schwarz Cybersecurity
#
# Botan is released under the Simplified BSD License (see license.txt)
#

import sys
import hashlib
import binascii
import os

class KatReader:
    def __init__(self, file):
        self.file = file
        self.last_mlen = None

    def next_value(self):
        while True:
            line = self.file.readline()

            if line == "":
                return (None, None)

            if line.startswith('#') or line == "\n":
                continue

            key, val = line.strip().split(' = ')

            return (key, val)

    def read_kats(self):
        kat = {}

        while True:
            key, val = self.next_value()

            if key == None:
                return # eof

            if key not in ['count', 'seed', 'pk', 'sk', 'ct', 'ss']:
                raise Exception("Unknown key %s" % (key))

            if key == 'count':
                kat[key] = int(val)
            else:
                kat[key] = val

            if key == 'ss':
                yield kat
                kat = {}

def shake_256_16(v):
    # v is assumed to be hex
    h = hashlib.shake_256()
    h.update(binascii.unhexlify(v))
    return h.hexdigest(16)

def sha256_16(v):
    # v is assumed to be hex
    h = hashlib.sha256()
    h.update(binascii.unhexlify(v))
    return h.hexdigest()[:32]

def compress_kat(kat, mode_90s):
    first = kat['count'] == 0
    del kat['count']

    hash_fn = sha256_16 if mode_90s else shake_256_16

    # rename keys and hash large values to reduce size of KAT vectors
    kat['Seed'] = kat.pop('seed')
    kat['SS']   = kat.pop('ss')
    kat['PK']   = hash_fn(kat.pop('pk'))
    kat['SK']   = hash_fn(kat.pop('sk'))
    kat['CT']   = hash_fn(kat.pop('ct'))

    return kat

def map_mode(mode):
    out = None

    # Note! See the helper shellscipt in the comment on the top of this file
    #       to generate KAT *.rsp files that match this naming scheme.
    if mode == "PQCgenKAT_kem1024-90s":
        return "Kyber-1024-90s-r3"
    if mode == "PQCgenKAT_kem512-90s":
        return "Kyber-512-90s-r3"
    if mode == "PQCgenKAT_kem768-90s":
        return "Kyber-768-90s-r3"
    if mode == "PQCgenKAT_kem1024":
        return "Kyber-1024-r3"
    if mode == "PQCgenKAT_kem512":
        return "Kyber-512-r3"
    if mode == "PQCgenKAT_kem768":
        return "Kyber-768-r3"

    raise Exception('Unknown Kyber mode', mode)

def main(args = None):
    if args is None:
        args = sys.argv

    with open('src/tests/data/pubkey/kyber_kat.vec', 'w') as output:
        print("# This file was auto-generated from the reference implemention's KATs", file=output)
        print("# See src/scripts/dev_tools/gen_kyber_kat.py\n", file=output)

        for file in args[1:]:
            mode = map_mode(os.path.basename(os.path.splitext(file)[0]))

            reader = KatReader(open(file))

            print(f"[{mode}]", file=output)

            for kat in list(reader.read_kats())[:25]:
                kat = compress_kat(kat, '90s' in mode)

                for key in kat.keys():
                    print(key, '=', kat[key], file=output)
                print("", file=output)

if __name__ == '__main__':
    sys.exit(main())
