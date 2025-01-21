#!/usr/bin/env python3

# Converts the json files of ACVP KATs to a format that can be used by Botan tests.
# This script relies on unlicensed code from Markku-Juhani O. Saarinen
# taken from https://github.com/mjosaarinen/py-acvp-pqc/blob/main/test_mldsa.py
# and https://github.com/mjosaarinen/py-acvp-pqc/blob/main/test_slhdsa.py
#
# (C) 2025 Jack Lloyd
# (C) 2025 Amos Treiber - Rohde & Schwarz Cybersecurity
#
# Botan is released under the Simplified BSD License (see license.txt)
#

import binascii
import json
import re
import argparse
import sys
import hashlib

# specifies which DSA algorithm to generate KATs for
dsa_str = ""

# "ML-DSA-44" -> "ML-DSA-4x4"
def transform_algo_string(s):
    if dsa_str == "ml_dsa":
        transformed = re.sub(r'(\d)(\d)$', r'\1x\2', s)
        return transformed
    else:
        return s

def shake_256_16(v):
    # v is assumed to be hex
    h = hashlib.shake_256()
    h.update(binascii.unhexlify(v))
    return h.hexdigest(16)

# taken from py-acvp-pqc
def dsa_load_keygen(req_fn, res_fn):
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

# taken from py-acvp-pqc
def dsa_load_siggen(req_fn, res_fn):
    with open(req_fn) as f:
        siggen_req = json.load(f)
    with open(res_fn) as f:
        siggen_res = json.load(f)

    siggen_kat = []
    for qtg in siggen_req['testGroups']:
        alg = qtg['parameterSet']
        det = qtg['deterministic']
        pre = False
        if 'preHash' in qtg and qtg['preHash'] == 'preHash':
                pre = True
        ifc = None
        if 'signatureInterface' in qtg:
            ifc = qtg['signatureInterface']
        if 'externalMu' in qtg:
            emu = qtg['externalMu']
        else:
            emu = False
        tgid = qtg['tgId']

        rtg = None
        for tg in siggen_res['testGroups']:
            if tg['tgId'] == tgid:
                rtg = tg['tests']
                break

        for qt in qtg['tests']:
            tcid = qt['tcId']
            for t in rtg:
                if t['tcId'] == tcid:
                    qt.update(t)
            qt['parameterSet'] = alg
            qt['deterministic'] = det
            if not det and qt['additionalRandomness']: # case for SLH-DSA
                qt['rnd'] = qt['additionalRandomness']
            if 'preHash' not in qt:
                qt['preHash'] = pre
            if 'context' not in qt:
                qt['context'] = ''
            qt['signatureInterface'] = ifc
            qt['externalMu'] = emu
            siggen_kat += [qt]
    return siggen_kat

# taken from py-acvp-pqc
def dsa_load_sigver(req_fn, res_fn, int_fn):

    with open(req_fn) as f:
        sigver_req = json.load(f)
    with open(res_fn) as f:
        sigver_res = json.load(f)
    with open(int_fn) as f:
        sigver_int = json.load(f)

    sigver_kat = []
    if dsa_str == "ml_dsa":
        for qtg in sigver_req['testGroups']:
            alg = qtg['parameterSet']
            pre = False
            if 'preHash' in qtg and qtg['preHash'] == 'preHash':
                    pre = True
            tgid = qtg['tgId']
            ifc = None
            if 'signatureInterface' in qtg:
                ifc = qtg['signatureInterface']
            if 'externalMu' in qtg:
                emu = qtg['externalMu']
            else:
                emu = False

            rtg = None
            for tg in sigver_res['testGroups']:
                if tg['tgId'] == tgid:
                    rtg = tg['tests']
                    break

            itg = None
            for tg in sigver_int['testGroups']:
                if tg['tgId'] == tgid:
                    itg = tg['tests']
                    break

            for qt in qtg['tests']:
                tcid = qt['tcId']
                for t in rtg:
                    if t['tcId'] == tcid:
                        qt.update(t)
                #   message, signature in this file overrides prompts
                for t in itg:
                    if t['tcId'] == tcid:
                        qt.update(t)
                qt['parameterSet'] = alg
                if 'preHash' not in qt:
                    qt['preHash'] = pre
                if 'context' not in qt:
                    qt['context'] = ''
                qt['signatureInterface'] = ifc
                qt['externalMu'] = emu
                sigver_kat += [qt]

    elif dsa_str == "slh_dsa":
        for qtg in sigver_req['testGroups']:
            alg = qtg['parameterSet']
            tgid = qtg['tgId']
            pre = False
            if 'preHash' in qtg and qtg['preHash'] == 'preHash':
                    pre = True
            ifc = None
            if 'signatureInterface' in qtg:
                ifc = qtg['signatureInterface']

            rtg = None
            for tg in sigver_res['testGroups']:
                if tg['tgId'] == tgid:
                    rtg = tg['tests']
                    break

            itg = None
            for tg in sigver_int['testGroups']:
                if tg['tgId'] == tgid:
                    itg = tg['tests']
                    break

            for qt in qtg['tests']:
                pk   = qt['pk']
                tcid = qt['tcId']
                for t in rtg:
                    if t['tcId'] == tcid:
                        qt.update(t)
                #   message, signature in this file overrides prompts
                for t in itg:
                    if t['tcId'] == tcid:
                        qt.update(t)
                qt['parameterSet'] = alg
                qt['pk'] = pk
                if 'preHash' not in qt:
                    qt['preHash'] = pre
                if 'context' not in qt:
                    qt['context'] = ''
                qt['signatureInterface'] = ifc
                sigver_kat += [qt]
    return sigver_kat

def group_by_parameter_set_and_filter(keygen_kat):
    grouped_kat = {}
    for kat in keygen_kat:
        # Botan does not support preHash and can only test external interface
        if kat['signatureInterface'] == "external" and not (kat['preHash'] or kat.get('externalMu', False)):
            parameter_set = kat['parameterSet']
            if parameter_set not in grouped_kat:
                grouped_kat[parameter_set] = []

            # SLH-DSA sigVer is huge, so we only add one kat per "reason" for verification failure
            if dsa_str == "slh_dsa" and 'reason' in kat:
                if not kat['testPassed'] and any(k['reason'] == kat['reason'] for k in grouped_kat[parameter_set]):
                    continue

            # SLH-DSA sigGen is slow, so we only add one kat per RND and CONTEXT variation
            if dsa_str == "slh_dsa" and 'sk' in kat and 'context' in kat: # Establish we are in SigGen
                context_rnd_repeat =  (
                    kat['context'] == '' and 'rnd' not in kat and any(k['context'] == '' and 'rnd' not in k for k in grouped_kat[parameter_set]) or
                    kat['context'] == '' and 'rnd' in kat and any(k['context'] == '' and 'rnd'  in k for k in grouped_kat[parameter_set]) or
                    kat['context'] != '' and 'rnd' not in kat and any(k['context'] != '' and 'rnd' not in k for k in grouped_kat[parameter_set]) or
                    kat['context'] != '' and 'rnd' in kat and any(k['context'] != '' and 'rnd' in k for k in grouped_kat[parameter_set])
                )
                if context_rnd_repeat:
                    continue

            grouped_kat[parameter_set].append(kat)
    return grouped_kat

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fips", type=str, help="204 for FIPS204 (ML-DSA), 205 for FIPS205 (SLH-DSA)")
    parser.add_argument("--keygen-directory", type=str, help="Directory '[ML/SLH]-DSA-keyGen-FIPS20[4/5]' containing the JSON files")
    parser.add_argument("--siggen-directory", type=str, help="Directory '[ML/SLH]-DSA-sigGen-FIPS20[4/5]' containing the JSON files")
    parser.add_argument("--sigver-directory", type=str, help="Directory '[ML/SLH]-DSA-sigVer-FIPS20[4/5]' containing the JSON files")

    return parser.parse_args()

def compress_kat_keygen(kat):
    if dsa_str == "ml_dsa":
        kat['SEED']  = kat.pop('seed')
        kat['SK'] = shake_256_16(kat['SEED']) # Botan only stores the seed
    elif dsa_str == "slh_dsa":
        kat['SKSEED'] = kat.pop('skSeed')
        kat['SKPRF'] = kat.pop('skPrf')
        kat['PKSEED'] = kat.pop('pkSeed')
        kat['SK'] = shake_256_16(kat.pop('sk'))
    kat['PK'] = shake_256_16(kat.pop('pk'))

     # The 'SK' key needs to be the last written one to match Botan's tests
    kat['SK'] = kat.pop('SK')

    return kat

def compress_kat_siggen(kat):
    kat['CONTEXT'] = kat.pop('context')
    kat['SK'] = kat.pop('sk')
    kat['MESSAGE'] = kat.pop('message')
    if 'rnd' in kat:
        kat['RND'] = kat.pop('rnd')
    kat['SIGNATURE'] = shake_256_16(kat.pop('signature'))

    return kat

def compress_kat_sigver(kat):
    # We actually can't compress anything for this type of test
    kat['CONTEXT'] = kat.pop('context')
    kat['PK'] = kat.pop('pk')
    kat['MESSAGE'] = kat.pop('message')
    kat['SIGNATURE'] = kat.pop('signature')
    kat['RESULT'] = kat.pop('testPassed')

    return kat

def main(args = None):
    if args is None:
        return 1

    global dsa_str
    if args.fips is not None:
        if args.fips == "204":
            dsa_str = "ml_dsa"
        elif args.fips == "205":
            dsa_str = "slh_dsa"
        else:
            return 1
    else:
        return 1

    if args.keygen_directory is not None:
        keygen_kat = dsa_load_keygen(
                    args.keygen_directory + '/prompt.json',
                    args.keygen_directory + '/expectedResults.json')

        with open(f"src/tests/data/pubkey/{dsa_str}_acvp_keygen.vec", 'w') as output:
            print("# This file was auto-generated from the ACVP KATs", file=output)
            print("# See src/scripts/dev_tools/gen_pqc_dsa_acvp_kat.py\n", file=output)

            for paramset, kat_by_paramset in group_by_parameter_set_and_filter(keygen_kat).items():
                print(f"[{transform_algo_string(paramset)}]", file=output)

                for kat in kat_by_paramset:
                    kat = compress_kat_keygen(kat)
                    for key in kat.keys():
                        if key in ['SEED', 'SKSEED', 'SKPRF', 'PKSEED', 'PK', 'SK']:
                            print(key, '=', kat[key], file=output)
                    print("", file=output)

    # We cannot do sigGen for ML-DSA because Botan requires the SK seed which ACVP does
    # not provide.
    if args.siggen_directory is not None and dsa_str != "ml_dsa":
        siggen_kat = dsa_load_siggen(
                    args.siggen_directory + '/prompt.json',
                    args.siggen_directory + '/expectedResults.json')

        with open(f"src/tests/data/pubkey/{dsa_str}_acvp_siggen.vec", 'w') as output:
            print("# This file was auto-generated from the ACVP KATs", file=output)
            print("# See src/scripts/dev_tools/gen_pqc_dsa_acvp_kat.py\n", file=output)

            for paramset, kat_by_paramset in group_by_parameter_set_and_filter(siggen_kat).items():
                print(f"[{transform_algo_string(paramset)}]", file=output)

                for kat in kat_by_paramset:
                    for key, value in compress_kat_siggen(kat).items():
                        if key in ['MESSAGE', 'SK', 'RND', 'CONTEXT', 'SIGNATURE']:
                            print(key, '=', value, file=output)
                    print("", file=output)

    if args.sigver_directory is not None:
        sigver_kat = dsa_load_sigver(
                    args.sigver_directory + '/prompt.json',
                    args.sigver_directory + '/expectedResults.json',
                    args.sigver_directory + '/internalProjection.json')

        with open(f"src/tests/data/pubkey/{dsa_str}_acvp_sigver.vec", 'w') as output:
            print("# This file was auto-generated from the ACVP KATs", file=output)
            print("# See src/scripts/dev_tools/gen_pqc_dsa_acvp_kat.py\n", file=output)

            for paramset, kat_by_paramset in group_by_parameter_set_and_filter(sigver_kat).items():
                print(f"[{transform_algo_string(paramset)}]", file=output)
                for kat in kat_by_paramset:
                    for key, value in compress_kat_sigver(kat).items():
                        if key in ['MESSAGE', 'PK', 'RESULT', 'CONTEXT', 'SIGNATURE']:
                            print(key, '=', value, file=output)
                    print("", file=output)

if __name__ == '__main__':
    args = parse_arguments()
    sys.exit(main(args))
