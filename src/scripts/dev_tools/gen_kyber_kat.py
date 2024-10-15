#!/usr/bin/env python3

#
# Strips the KAT harness in the Kyber reference implementation down to a less
# space consuming version. This script was used to generate:
#   * `src/tests/data/pubkey/kyber_kat.vec` and
#   * `src/tests/data/pubkey/ml_kem_ipd.vec`
# test data from the *.rsp files in the reference implementation repository.
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
# (C) 2024 Amos Treiber, René Meusel - Rohde & Schwarz Cybersecurity
#
# Botan is released under the Simplified BSD License (see license.txt)
#

import sys
import hashlib
import binascii
import os
import argparse

class KatReader:
    def __init__(self, file):
        self.file = file

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

            if key in ['msg']:
                continue

            if key not in ['count', 'z', 'd', 'seed', 'pk', 'sk', 'ct', 'ss', 'ct_n', 'ss_n']:
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

def compress_kat(kat, mode):
    first = kat['count'] == 0
    del kat['count']

    hash_fn = sha256_16 if '90s' in mode else shake_256_16

    # For ML-KEM we use the private seed as the private key's storage format
    if mode == "ML-KEM":
        kat['sk'] = kat['d'] + kat['z']
        del kat['d']
        del kat['z']

    # rename keys and hash large values to reduce size of KAT vectors
    kat['Seed'] = kat.pop('seed')
    kat['SS']   = kat.pop('ss')
    kat['PK']   = hash_fn(kat.pop('pk'))
    kat['SK']   = hash_fn(kat.pop('sk'))
    kat['CT']   = hash_fn(kat.pop('ct'))

    if mode == "ML-KEM":
        kat['CT_N'] = kat.pop('ct_n')
        kat['SS_N'] = kat.pop('ss_n')

    return kat


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="+", help="Input files")
    parser.add_argument("--kyber-r3", action="store_true", help="Enable Kyber R3 mode", default=False)
    parser.add_argument("--ml-kem-ipd", action="store_true", help="Enable ML-KEM initial public draft mode", default=False)
    parser.add_argument("--ml-kem", action="store_true", help="Enable ML-KEM final mode", default=False)
    parser.add_argument("--kats-per-mode", type=int, help="Number of KATs to generate per mode", default=25)

    return parser.parse_args()


def map_mode(file_name, mode):
    if mode == "Kyber-r3":
        # Note! See the helper shellscipt in the comment on the top of this file
        #       to generate KAT *.rsp files that match this naming scheme.
        if file_name == "PQCgenKAT_kem1024-90s":
            return "Kyber-1024-90s-r3"
        if file_name == "PQCgenKAT_kem512-90s":
            return "Kyber-512-90s-r3"
        if file_name == "PQCgenKAT_kem768-90s":
            return "Kyber-768-90s-r3"
        if file_name == "PQCgenKAT_kem1024":
            return "Kyber-1024-r3"
        if file_name == "PQCgenKAT_kem512":
            return "Kyber-512-r3"
        if file_name == "PQCgenKAT_kem768":
            return "Kyber-768-r3"
    elif mode == "ML-KEM-ipd":
        if file_name == "PQCkemKAT_3168":
            return "ML-KEM-1024-ipd"
        if file_name == "PQCkemKAT_1632":
            return "ML-KEM-512-ipd"
        if file_name == "PQCkemKAT_2400":
            return "ML-KEM-768-ipd"
    elif mode == "ML-KEM":
        if file_name == "kat_MLKEM_1024":
            return "ML-KEM-1024"
        if file_name == "kat_MLKEM_512":
            return "ML-KEM-512"
        if file_name == "kat_MLKEM_768":
            return "ML-KEM-768"
    else:
        raise Exception('Unknown mode', mode)

    raise Exception('Unknown Kyber KAT file name', file_name)


def selected_mode(args):
    modes = []

    if args.kyber_r3:
        modes.append("Kyber-r3")
    if args.ml_kem_ipd:
        modes.append("ML-KEM-ipd")
    if args.ml_kem:
        modes.append("ML-KEM")

    if len(modes) > 1:
        raise Exception("Error: More than one mode selected")

    if len(modes) == 0:
        raise Exception("Error: No mode selected")

    return modes[0]


def output_file(mode):
    if mode == "Kyber-r3":
        return "src/tests/data/pubkey/kyber_kat.vec"
    if mode == "ML-KEM-ipd":
        return "src/tests/data/pubkey/ml_kem_ipd.vec"
    if mode == "ML-KEM":
        return "src/tests/data/pubkey/ml_kem.vec"

    raise Exception("Unknown mode", mode)


def main(args = None):
    if args is None:
        return 1

    mode = selected_mode(args)

    with open(output_file(mode), 'w') as output:
        if mode == "ML-KEM":
            print("# This file was auto-generated from github.com/post-quantum-cryptography/KAT", file=output)
        else:
            print("# This file was auto-generated from the reference implemention's KATs", file=output)
        print("# See src/scripts/dev_tools/gen_kyber_kat.py\n", file=output)

        for file in args.files:
            algo_mode = map_mode(os.path.basename(os.path.splitext(file)[0]), mode)

            reader = KatReader(open(file))

            print(f"[{algo_mode}]", file=output)

            for kat in list(reader.read_kats())[:args.kats_per_mode]:
                kat = compress_kat(kat, mode)

                for key in kat.keys():
                    print(key, '=', kat[key], file=output)
                print("", file=output)

if __name__ == '__main__':
    args = parse_arguments()
    sys.exit(main(args))
