#!/usr/bin/env python3

# Converts the json files of ACVP KATs to a format that can be used by Botan tests.
# This script relies on unlicensed code from Markku-Juhani O. Saarinen
# taken from https://github.com/mjosaarinen/py-acvp-pqc/blob/main/test_mlkem.py
#
# (C) 2024 Jack Lloyd
# (C) 2024 Amos Treiber - Rohde & Schwarz Cybersecurity
#
# Botan is released under the Simplified BSD License (see license.txt)
#

import binascii
import hashlib
import json
import argparse
import sys

def shake_256_16(v):
    # v is assumed to be hex
    h = hashlib.shake_256()
    h.update(binascii.unhexlify(v))
    return h.hexdigest(16)

def mlkem_load_keygen(req_fn, res_fn):
    with open(req_fn) as f:
        keygen_req = json.load(f)
    with open(res_fn) as f:
        keygen_res = json.load(f)

    keygen_kat = []
    for qtg in keygen_req['testGroups']:
        alg = qtg['parameterSet']
        tgid = qtg['tgId']

        rtg = None
        for tg in keygen_res['testGroups']:
            if tg['tgId'] == tgid:
                rtg = tg['tests']
                break

        for qt in qtg['tests']:
            tcid = qt['tcId']
            for t in rtg:
                if t['tcId'] == tcid:
                    qt.update(t)
            qt['parameterSet'] = alg
            keygen_kat += [qt]

    return keygen_kat

def mlkem_load_encdec(req_fn, res_fn):
    with open(req_fn) as f:
        encdec_req = json.load(f)
    with open(res_fn) as f:
        encdec_res = json.load(f)

    encaps_kat = []
    decaps_kat = []
    for qtg in encdec_req['testGroups']:
        alg = qtg['parameterSet']
        func = qtg['function']
        tgid = qtg['tgId']

        rtg = None
        for tg in encdec_res['testGroups']:
            if tg['tgId'] == tgid:
                rtg = tg['tests']
                break

        for qt in qtg['tests']:
            tcid = qt['tcId']
            for t in rtg:
                if t['tcId'] == tcid:
                    qt.update(t)
            qt['parameterSet'] = alg
            if func == 'encapsulation':
                encaps_kat += [qt]
            elif func == 'decapsulation':
                qt['dk'] = qtg['dk']
                decaps_kat += [qt]
            else:
                print('ERROR: Unkonwn function:', func)

    return (encaps_kat, decaps_kat)

def group_by_parameter_set(keygen_kat):
    grouped_kat = {}
    for kat in keygen_kat:
        parameter_set = kat['parameterSet']
        if parameter_set not in grouped_kat:
            grouped_kat[parameter_set] = []
        grouped_kat[parameter_set].append(kat)
    return grouped_kat

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--keygen-directory", type=str, help="Directory 'ML-KEM-keyGen-FIPS203' containing the JSON files")
    parser.add_argument("--encapdecap-directory", type=str, help="Directory 'ML-KEM-encapDecap-FIPS203' containing the JSON files")

    return parser.parse_args()

def compress_kat_keygen(kat):
    kat['Z']  = kat.pop('z')
    kat['D']  = kat.pop('d')
    kat['EK'] = shake_256_16(kat.pop('ek'))
    kat['DK'] = shake_256_16(kat['D'] + kat['Z'])
    del kat['dk'] # remove the original decaps key (Botan uses the private seed as storage format)

    return kat

def compress_kat_encaps(kat):
    kat['EK'] = kat.pop('ek')
    kat['M']  = kat.pop('m')
    kat['K']  = kat.pop('k')
    kat['C']  = shake_256_16(kat.pop('c'))

    return kat

def main(args = None):
    if args is None:
        return 1

    if args.keygen_directory is not None:

        keygen_kat = mlkem_load_keygen(
                    args.keygen_directory + '/prompt.json',
                    args.keygen_directory + '/expectedResults.json')
        with open("src/tests/data/pubkey/ml_kem_acvp_keygen.vec", 'w') as output:
            print("# This file was auto-generated from the ACVP KATs", file=output)
            print("# See src/scripts/dev_tools/gen_mlkem_acvp_kat.py\n", file=output)

            for paramset, kat_by_paramset in group_by_parameter_set(keygen_kat).items():
                print(f"[{paramset}]", file=output)

                for kat in kat_by_paramset:
                    kat = compress_kat_keygen(kat)
                    for key in kat.keys():
                        if key in ["Z", "D", "EK", "DK"]:
                            print(key, '=', kat[key], file=output)
                    print("", file=output)
    if args.encapdecap_directory is not None:
        encaps_kat, decaps_kat = mlkem_load_encdec(
                    args.encapdecap_directory + '/prompt.json',
                    args.encapdecap_directory + '/expectedResults.json')

        with open("src/tests/data/pubkey/ml_kem_acvp_encap.vec", 'w') as output:
            print("# This file was auto-generated from the ACVP KATs", file=output)
            print("# See src/scripts/dev_tools/gen_mlkem_acvp_kat.py\n", file=output)

            for paramset, kat_by_paramset in group_by_parameter_set(encaps_kat).items():
                print(f"[{paramset}]", file=output)

                for kat in kat_by_paramset:
                    kat = compress_kat_encaps(kat)
                    for key in kat.keys():
                        if key in ["M", "EK", "K", "C"]:
                            print(key, '=', kat[key], file=output)
                    print("", file=output)

        with open("src/tests/data/pubkey/ml_kem_acvp_decap.vec", 'w') as output:
            print("# This file was auto-generated from the ACVP KATs", file=output)
            print("# See src/scripts/dev_tools/gen_mlkem_acvp_kat.py\n", file=output)

            # We cannot use this KAT at the moment as it does not provide the
            # private seeds for the decapsulation operation.

            # for paramset, kat_by_paramset in group_by_parameter_set(decaps_kat).items():
            #     print(f"[{paramset}]", file=output)

            #     for kat in kat_by_paramset:
            #         # No compressions possible in decaps
            #         for key in ["C", "DK", "K"]:
            #             if key.lower() in kat.keys():
            #                 print(key, '=', kat[key.lower()], file=output)
            #         print("", file=output)



if __name__ == '__main__':
    args = parse_arguments()
    sys.exit(main(args))
