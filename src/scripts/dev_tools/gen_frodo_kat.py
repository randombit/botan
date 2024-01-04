#!/usr/bin/env python3

#
# Strips the KAT harness in the FrodoKEM reference implementation down
# to a less space consuming version. This script was used to generate
# `src/tests/data/pubkey/frodokem_kat.vec` test data from the *.rsp files in
# the reference implemenation repository.
#
# See here: https://github.com/microsoft/PQCrypto-LWEKE/tree/master/KAT
#
# (C) 2023 Jack Lloyd
# (C) 2023 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
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

def compress_kat(kat):
    first = kat['count'] == 0
    del kat['count']

    # rename keys
    kat['Seed'] = kat.pop('seed')
    kat['SS']   = kat.pop('ss')
    kat['PK']   = shake_256_16(kat.pop('pk'))
    kat['SK']   = shake_256_16(kat.pop('sk'))
    kat['CT']   = shake_256_16(kat.pop('ct'))

    return kat

def map_mode(mode, is_ephemeral = False):
    out = None
    if mode == "PQCkemKAT_19888":
        out = "eFrodoKEM-640-AES"
    if mode == "PQCkemKAT_19888_shake":
        out = "eFrodoKEM-640-SHAKE"
    if mode == "PQCkemKAT_31296":
        out = "eFrodoKEM-976-AES"
    if mode == "PQCkemKAT_31296_shake":
        out = "eFrodoKEM-976-SHAKE"
    if mode == "PQCkemKAT_43088":
        out = "eFrodoKEM-1344-AES"
    if mode == "PQCkemKAT_43088_shake":
        out = "eFrodoKEM-1344-SHAKE"

    if out is None:
        raise Exception('Unknown FrodoKEM mode', mode)

    if is_ephemeral:
        return out
    else:
        return out[1:]  # remove 'e' to obtain 'FrodoKEM'

def main(args = None):
    """Set True for eFrodo, otherwise the non-ephemeral variant is assumed.
    Necessary because the files have the same name for either variant."""
    is_ephemeral = False

    if args is None:
        args = sys.argv

    with open('src/tests/data/pubkey/frodokem_kat.vec', 'w') as output:
        print("# This file was auto-generated from the reference implemention's KATs", file=output)
        print("# See src/scripts/dev_tools/gen_frodo_kat.py\n", file=output)

        for file in args[1:]:
            mode = map_mode(os.path.basename(os.path.splitext(file)[0]), is_ephemeral)

            reader = KatReader(open(file))

            print(f"[{mode}]", file=output)

            for kat in list(reader.read_kats())[:25]:
                kat = compress_kat(kat)

                for key in kat.keys():
                    print(key, '=', kat[key], file=output)
                print("", file=output)

if __name__ == '__main__':
    sys.exit(main())
