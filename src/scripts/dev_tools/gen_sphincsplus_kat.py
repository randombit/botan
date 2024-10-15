#!/usr/bin/env python3

#
# Strips the KAT harness produced by the SPHINCS+ reference implementation down
# to a less space consuming version. This script was used to generate
# `src/tests/data/pubkey/sphincsplus.vec` test data from the *.rsp files of the
# reference implemenation.
#
# (C) 2023 Jack Lloyd
# (C) 2023 René Meusel, Rohde & Schwarz Cybersecurity
#
# Botan is released under the Simplified BSD License (see license.txt)
#

import sys
import hashlib
import binascii

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

            if key is None:
                return # eof

            if key not in ['count', 'seed', 'mlen', 'msg', 'pk', 'sk', 'smlen', 'sm']:
                raise Exception("Unknown key %s" % (key))

            if key in ['count', 'mlen', 'smlen']:
                kat[key] = int(val)
            else:
                kat[key] = val

            if key == 'sm':
                yield kat
                kat = {}


def sha3_256(v):
    h = hashlib.sha3_256()
    h.update(v)
    return h.digest()


def sha256(v):
    h = hashlib.sha256()
    h.update(v)
    return h.digest()


def main(args = None):
    if args is None:
        args = sys.argv

    if len(args) < 3:
        print("Usage: %s <algo-spec as found in oids.txt> <*.rsp file> [optional: limit of KATs]")
        return 1

    param = args[1]
    katfile = args[2]
    limit = int(args[3]) if len(args) > 3 else 1

    reader = KatReader(open(katfile, encoding="utf-8"))

    hash_fn = sha256 if "sha2" in param.lower() else sha3_256

    l = 0
    for kat in reader.read_kats():
        if l >= limit:
            break
        l += 1

        # Remove the input message from the end of the 'sm' field
        signature = binascii.unhexlify(kat["sm"][:-kat["mlen"]*2])

        print("SphincsParameterSet = %s" % param)
        print("seed = %s" % kat["seed"])
        print("msg = %s" % kat["msg"])
        print("pk = %s" % kat["pk"])
        print("sk = %s" % kat["sk"])
        print("HashSig = %s" % binascii.hexlify(hash_fn(signature)).decode("utf-8").upper())
        print()

    return 0

if __name__ == '__main__':
    sys.exit(main())
