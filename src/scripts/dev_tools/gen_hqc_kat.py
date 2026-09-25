#!/usr/bin/env python3

#
# Converts the NIST-style KAT files (PQCkemKAT_*.rsp) of the HQC reference
# implementation, as vendored in the Rust crate rust-hqc, into the test vector
# files `src/tests/data/pubkey/hqc_kat_keygen.vec` and
# `src/tests/data/pubkey/hqc_kat_decap.vec`.
#
# The key generation file carries, for every vector, the 48 byte seed and the
# SHAKE-256(128) digests of the encapsulation and decapsulation key.
#
# Since the reference KAT driver continues a single PRNG stream from key
# generation into encapsulation, the encapsulation results cannot be reproduced
# through the stateless C API of the crate. The decapsulation, however, is
# deterministic; therefore the decapsulation file carries the seed, the full
# ciphertext and the shared secret for the first vectors of every parameter set.
#
# Usage:
#   ./src/scripts/dev_tools/gen_hqc_kat.py src/lib/pubkey/hqc/rust-hqc/rust-hqc/kats/ref
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
    ("HQC-1", "hqc-1", "PQCkemKAT_2321.rsp"),
    ("HQC-3", "hqc-3", "PQCkemKAT_4602.rsp"),
    ("HQC-5", "hqc-5", "PQCkemKAT_7333.rsp"),
]

HEADER = """# This file was auto-generated from the HQC reference implementation's KATs
# as vendored in the Rust crate rust-hqc (kats/ref/hqc-{1,3,5}/PQCkemKAT_*.rsp).
# See src/scripts/dev_tools/gen_hqc_kat.py
#
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


def keygen_vector(kat):
    # The test framework runs a vector as soon as it reads the last required
    # key, so the order of the keys matters: DK must be last.
    return [('Seed', kat['seed']), ('EK', shake_256_16(kat['pk'])), ('DK', shake_256_16(kat['sk']))]


def decap_vector(kat):
    # SS must be last, see above
    return [('Seed', kat['seed']), ('CT', kat['ct']), ('SS', kat['ss'])]


def read_all_kats(kats_dir):
    for (mode, subdir, filename) in PARAMETER_SETS:
        path = os.path.join(kats_dir, subdir, filename)
        with open(path, encoding='utf8') as kat_file:
            yield (mode, list(KatReader(kat_file).read_kats()))


def write_vec_file(path, description, sections):
    with open(path, 'w', encoding='utf8') as output:
        output.write(HEADER)
        output.write(description)
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
    parser.add_argument('--full-ct-count', type=int, default=3,
                        help='number of vectors per parameter set written to the decapsulation file')
    opts = parser.parse_args(args)

    kats = list(read_all_kats(opts.kats_dir))

    write_vec_file(
        os.path.join(opts.output_dir, 'hqc_kat_keygen.vec'),
        "# EK and DK are SHAKE-256(128) digests of the keys generated from Seed.\n",
        [(mode, [keygen_vector(kat) for kat in vectors]) for (mode, vectors) in kats])

    write_vec_file(
        os.path.join(opts.output_dir, 'hqc_kat_decap.vec'),
        "# CT is decapsulated with the private key generated from Seed and must yield SS.\n"
        "# Only the first %d vectors of each parameter set are included.\n" % opts.full_ct_count,
        [(mode, [decap_vector(kat) for kat in vectors[:opts.full_ct_count]]) for (mode, vectors) in kats])

    return 0


if __name__ == '__main__':
    sys.exit(main())
