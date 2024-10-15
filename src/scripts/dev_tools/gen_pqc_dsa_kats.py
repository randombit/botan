# This test data is generated from the *_DSA implementations of https://github.com/mjosaarinen/py-acvp-pqc/tree/main
# and using the drbg.aes256_ctr_drbg module from https://github.com/giacomopope/dilithium-py
#
# (C) 2024 Jack Lloyd
# (C) 2024 Amos Treiber, René Meusel - Rohde & Schwarz Cybersecurity
#
# Botan is released under the Simplified BSD License (see license.txt)
#

import binascii
import hashlib
import os
import re
import sys
from dilithium_py.drbg.aes256_ctr_drbg import AES256_CTR_DRBG
from fips204 import ML_DSA, ML_DSA_PARAM
from fips205 import SLH_DSA_PARAMS

random_bytes = os.urandom

# "ML-DSA-44" -> "ml-dsa-4x4"
def transform_mldsa_string(s):
    s = s.lower()
    transformed = re.sub(r'(\d)(\d)$', r'\1x\2', s)
    return transformed

def create_mldsa_ini_label(s, det):
    algo = re.sub(r'(\d)(\d)$', r'\1x\2', s)
    return f"[{algo}_{det}]"

def sha3_256(v):
    h = hashlib.sha3_256()
    h.update(v)
    return h.digest()


def sha256(v):
    h = hashlib.sha256()
    h.update(v)
    return h.digest()

def sign(sign_internal_func, sk_bytes, m, random_bytes, n, ctx=b"", deterministic=False):
     if len(ctx) > 255:
         raise ValueError(
             f"ctx bytes must have length at most 255, ctx has length {len(ctx) = }"
         )
     if deterministic:
         rnd = None
     else:
         rnd = random_bytes(n)   #drbg.random_bytes(n)
     # Format the message using the context
     m_prime = bytes([0]) + bytes([len(ctx)]) + ctx + m
     # Compute the signature of m_prime
     sig_bytes = sign_internal_func(m_prime, sk_bytes, rnd)
     return sig_bytes

def main(args = None):
    msg = binascii.unhexlify("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8")
    if args is None:
        args = sys.argv

    if len(args) != 2 or (args[1] != "ml_dsa" and args[1] != "slh_dsa"):
        print("Usage: gen_pqc_dsa_kats.py <ml_dsa|slh_dsa>")
        return 1

    algo = args[1]

    # Initialize DRBG with the magic value
    entropy = binascii.unhexlify("60496cd0a12512800a79161189b055ac3996ad24e578d3c5fc57c1e60fa2eb4e550d08e51e9db7b67f1a616681d9182d")
    drbg = AES256_CTR_DRBG(seed=entropy)

    if algo == "slh_dsa":
        output = open('src/tests/data/pubkey/slh_dsa.vec', 'w')

        print("# See src/scripts/dev_tools/gen_pqc_dsa_kats.py\n", file=output)

        for param, alg in SLH_DSA_PARAMS.items():
            hash_fn = sha256 if "sha2" in param.lower() else sha3_256

            seed = drbg.random_bytes(len(entropy))

            drbg_instance = AES256_CTR_DRBG(seed=seed)
            keygen_rand = drbg_instance.random_bytes(3*alg.n)
            sk_seed = keygen_rand[:alg.n]
            sk_prf = keygen_rand[alg.n:2*alg.n]
            pk_seed = keygen_rand[2*alg.n:]
            pk, sk = alg.slh_keygen_internal(sk_seed, sk_prf, pk_seed)
            signature_rand = sign(alg.slh_sign_internal, sk, msg, drbg_instance.random_bytes, alg.n, deterministic=False)
            signature_det = sign(alg.slh_sign_internal, sk, msg, drbg_instance.random_bytes, alg.n, deterministic=True)

            print("SphincsParameterSet = %s" % param, file=output)
            print("seed = %s" % seed.hex().upper(), file=output)
            print("msg = %s" % msg.hex().upper(), file=output)
            print("pk = %s" % pk.hex().upper(), file=output)
            print("sk = %s" % sk.hex().upper(), file=output)
            if param == "SLH-DSA-SHAKE-128s":
                print("SigDet = %s" % binascii.hexlify(signature_det).decode("utf-8").upper(), file=output)
            print("HashSigDet = %s" % binascii.hexlify(hash_fn(signature_det)).decode("utf-8").upper(), file=output)
            print("HashSigRand = %s" % binascii.hexlify(hash_fn(signature_rand)).decode("utf-8").upper(), file=output)
            print("", file=output)

    elif algo == "ml_dsa":
        for param in ML_DSA_PARAM.keys():
            for det_str, deterministic in [("Deterministic", True), ("Randomized", False)]:
                alg = ML_DSA(param)
                output = open('src/tests/data/pubkey/%s_%s.vec' % (transform_mldsa_string(param), det_str), 'w')
                print("# See src/scripts/dev_tools/gen_pqc_dsa_kats.py", file=output)
                print("", file=output)
                print(create_mldsa_ini_label(param, det_str), file=output)
                print("", file=output)

                hash_fn = sha3_256
                def mldsa_sign_internal(m, sk, rnd):
                    # For some reason the interfaces vary between FIPS 204 and FIPS 205...
                    if rnd == None:
                        rnd = bytes([0]*32)
                    return alg.sign_internal(sk, m, rnd)

                samples = 25
                for _ in range(100):
                    seed = drbg.random_bytes(len(entropy))

                    if samples == 0:
                        continue

                    samples -= 1
                    drbg_instance = AES256_CTR_DRBG(seed=seed)
                    keygen_rand = drbg_instance.random_bytes(32)
                    pk, sk = alg.keygen_internal(keygen_rand)
                    signature = sign(mldsa_sign_internal, sk, msg, drbg_instance.random_bytes, 32, deterministic=deterministic)

                    print("Seed = %s" % seed.hex().upper(), file=output)
                    print("Msg = %s" % msg.hex().upper(), file=output)
                    print("HashPk = %s" % binascii.hexlify(hash_fn(pk)).decode("utf-8").upper(), file=output)
                    print("HashSk = %s" % binascii.hexlify(hash_fn(keygen_rand)).decode("utf-8").upper(), file=output)
                    print("HashSig = %s" % binascii.hexlify(hash_fn(signature)).decode("utf-8").upper(), file=output)
                    print("", file=output)
    else:
        print("Usage: gen_pqc_dsa_kats.py <ml_dsa|slh_dsa>")
        return 1

if __name__ == '__main__':
    sys.exit(main())

