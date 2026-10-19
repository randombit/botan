#!/usr/bin/env python3

#
# Converts the NIST-style KAT files (PQCkemKAT_32.rsp) of the HQC reference
# implementation, as vendored in the Rust crate rust-hqc, into the test vector
# file `src/tests/data/pubkey/hqc_kat.vec` in the format of Botan's generic
# PQC KEM KAT test (PK_PQC_KEM_KAT_Test): for every vector the 48 byte DRBG
# seed, the shared secret and the 32 byte private key (the master seed) in
# full, and the public key and the ciphertext as SHAKE-256(128) digests.
#
# Usage:
#   ./src/scripts/dev_tools/gen_hqc_kat.py src/lib/pubkey/hqc/rust/kats/ref
#
# (C) 2026 Falko Strenzke
#
# Botan is released under the Simplified BSD License (see license.txt)
#

import argparse
import binascii
import hashlib
import os
import sys

PARAMETER_SETS = [
    ("HQCr4-1", "hqc-1", "PQCkemKAT_32.rsp"),
    ("HQCr4-3", "hqc-3", "PQCkemKAT_32.rsp"),
    ("HQCr4-5", "hqc-5", "PQCkemKAT_32.rsp"),
]

HEADER = """# This file was auto-generated from the HQC reference implementation's KATs
# as vendored in the Rust crate rust-hqc (kats/ref/hqc-{1,3,5}/PQCkemKAT_32.rsp).
# See src/scripts/dev_tools/gen_hqc_kat.py
#
# PK and CT are SHAKE-256(128) digests; SK (the 32 byte master seed) and SS are
# stored in full.
"""


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

            if key is None:
                return  # eof

            if key not in ['count', 'seed', 'pk', 'sk', 'ct', 'ss']:
                raise ValueError("Unknown key %s" % (key))

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


def kat_vector(kat):
    # The test framework runs a vector as soon as it reads the last required
    # key (Seed,SS,PK,SK,CT), so CT must be last.
    return [('Seed', kat['seed']), ('SS', kat['ss']), ('PK', shake_256_16(kat['pk'])),
            ('SK', kat['sk']), ('CT', shake_256_16(kat['ct']))]


def read_all_kats(kats_dir):
    for (mode, subdir, filename) in PARAMETER_SETS:
        path = os.path.join(kats_dir, subdir, filename)
        with open(path, encoding='utf8') as kat_file:
            yield (mode, list(KatReader(kat_file).read_kats()))


def write_vec_file(path, sections):
    with open(path, 'w', encoding='utf8') as output:
        output.write(HEADER)
        output.write("\n")

        for (mode, vectors) in sections:
            print(f"[{mode}]", file=output)

            for vector in vectors:
                for (key, val) in vector:
                    print(key, '=', val, file=output)
                print(file=output)


def main(args=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kats_dir', help='directory containing hqc-1/, hqc-3/, hqc-5/ with the .rsp files')
    parser.add_argument('--output-dir', default='src/tests/data/pubkey')
    opts = parser.parse_args(args)

    kats = list(read_all_kats(opts.kats_dir))

    write_vec_file(
        os.path.join(opts.output_dir, 'hqc_kat.vec'),
        [(mode, [kat_vector(kat) for kat in vectors]) for (mode, vectors) in kats])

    return 0


if __name__ == '__main__':
    sys.exit(main())
