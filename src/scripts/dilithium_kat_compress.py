#!/usr/bin/env python3

#
# Strips the KAT harness produced by the Dilithium reference implementation down
# to a less space consuming version. This script was used to generate
# `src/tests/data/pubkey/dilithium_[...].vec` test data from the *.rsp files of
# the reference implemenation.
#
# (C) 2022,2023 Jack Lloyd
# (C) 2022 René Meusel, Rohde & Schwarz Cybersecurity
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

            if key == None:
                return # eof

            if key not in ['count', 'seed', 'mlen', 'msg', 'pk', 'sk', 'smlen', 'sm']:
                raise Exception("Unknown key %s" % (key))

            if key in ['count', 'mlen', 'smlen']:
                kat[key] = int(val)
            elif key == 'sm':
                # remove message appended to signature
                kat[key] = val[:-kat['mlen']*2]
            else:
                kat[key] = val

            if key == 'sm':
                yield kat
                kat = {}

def sha3_256(v):
    # v is assumed to be hex
    h = hashlib.sha3_256()
    h.update(binascii.unhexlify(v))
    return h.hexdigest()

def compress_kat(kat):
    first = kat['count'] == 0
    del kat['count']
    del kat['smlen']
    del kat['mlen']

    # rename keys
    kat['Seed'] = kat.pop('seed')
    kat['Msg'] = kat.pop('msg')

    kat['HashPk'] = sha3_256(kat.pop('pk'))
    kat['HashSk'] = sha3_256(kat.pop('sk'))

    sig = kat.pop('sm')
    if first:
        kat['Sig'] = sig
    kat['HashSig'] = sha3_256(sig)

    return kat

def map_mode(mode):
    if mode == 'Dilithium2':
        return '4x4'
    if mode == 'Dilithium2-AES':
        return '4x4_AES'
    if mode == 'Dilithium3':
        return '6x5'
    if mode == 'Dilithium3-AES':
        return '6x5_AES'
    if mode == 'Dilithium5':
        return '8x7'
    if mode == 'Dilithium5-AES':
        return '8x7_AES'

    raise Exception('Unknown Dilithium mode', mode)

def main(args = None):
    if args is None:
        args = sys.argv

    randomized = True

    type = 'Randomized' if randomized else 'Deterministic'

    for file in args[1:]:
        mode = map_mode(open(file).readline().strip()[2:])

        reader = KatReader(open(file))

        output = open('src/tests/data/pubkey/dilithium_%s_%s.vec' % (mode, type), 'w')

        print("# See src/scripts/dilithium_kat_compress.py\n", file=output)
        print("[Dilithium_%s]" % (mode), file=output)

        for kat in reader.read_kats():
            kat = compress_kat(kat)

            for key in ['Seed', 'Msg', 'HashPk', 'HashSk', 'Sig', 'HashSig']:
                if key in kat:
                    print(key, '=', kat[key], file=output)
            print("\n", file=output)

        output.close()

if __name__ == '__main__':
    sys.exit(main())
