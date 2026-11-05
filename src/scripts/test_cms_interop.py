#!/usr/bin/env python3

"""
Offline CMS interoperability test between the botan CLI and openssl.

For every supported combination this drives both directions
(openssl->botan and botan->openssl) of encryption and signing, and
prints a result matrix. The ML-KEM and ML-DSA private keys are also
re-encoded in each format openssl can emit (seed, expanded key, or
both) to check that botan accepts all of them. It is not part of
botan-test; run it manually:

   ./src/scripts/test_cms_interop.py --botan ./botan

Requires openssl >= 3.5 on PATH (ML-KEM and ML-DSA support).

(C) 2026 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import argparse
import os
import subprocess
import sys
import tempfile

TEST_MESSAGE = b"CMS interop test message\n"

# openssl cipher flag -> botan cipher name
CIPHERS = {
    "-aes-128-cbc": "AES-128/CBC",
    "-aes-256-cbc": "AES-256/CBC",
    "-aes-128-gcm": "AES-128/GCM",
    "-aes-256-gcm": "AES-256/GCM",
}

# signer -> extra openssl cms -sign arguments
SIGNERS = {
    "rsa": [],
    "ecdsa": [],
    "ed25519": ["-md", "sha512"],
    "mldsa": ["-md", "sha512"],
}

# openssl private key output formats, covering each alternative of the
# RFC 9881 (ML-DSA) and RFC 9935 (ML-KEM) private key CHOICE
PQ_KEY_FORMATS = ["seed-only", "priv-only", "seed-priv"]

class Runner:
    def __init__(self, botan, openssl, workdir, verbose):
        self.botan = botan
        self.openssl = openssl
        self.workdir = workdir
        self.verbose = verbose
        self.results = []

    def run(self, cmd, **kwargs):
        if self.verbose:
            print("+ %s" % " ".join(cmd), file=sys.stderr)
        return subprocess.run(
            cmd, cwd=self.workdir, capture_output=True, check=False, **kwargs)

    def check(self, cmd, **kwargs):
        proc = self.run(cmd, **kwargs)
        if proc.returncode != 0:
            raise RuntimeError(
                "command %s failed:\n%s" % (" ".join(cmd), proc.stderr.decode()))
        return proc

    def path(self, name):
        return os.path.join(self.workdir, name)

    def record(self, direction, op, algo, outcome):
        self.results.append((direction, op, algo, outcome))
        if self.verbose:
            print("%s %s %s: %s" % (direction, op, algo, outcome), file=sys.stderr)

    def attempt(self, direction, op, algo, fn):
        try:
            fn()
            self.record(direction, op, algo, "PASS")
        except Exception as e:
            self.record(direction, op, algo, "FAIL")
            print("FAIL %s %s %s:\n%s" % (direction, op, algo, e), file=sys.stderr)


def generate_credentials(r):
    def openssl(*args):
        r.check([r.openssl] + list(args))

    openssl("genpkey", "-algorithm", "EC", "-pkeyopt",
            "ec_paramgen_curve:P-256", "-out", "ca_key.pem")
    openssl("req", "-x509", "-new", "-key", "ca_key.pem",
            "-subj", "/O=Botan/CN=CMS Interop CA", "-days", "30",
            "-out", "ca_cert.pem",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign")

    exts = r.path("exts.cnf")
    with open(exts, "w", encoding="utf-8") as f:
        f.write("keyUsage=critical,digitalSignature,keyEncipherment\n"
                "subjectKeyIdentifier=hash\n")

    mlkem_exts = r.path("mlkem_exts.cnf")
    with open(mlkem_exts, "w", encoding="utf-8") as f:
        f.write("keyUsage=critical,keyEncipherment\n"
                "subjectKeyIdentifier=hash\n")

    keygen = {
        "rsa": ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
        "ecdsa": ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
        "ed25519": ["-algorithm", "ED25519"],
        "mldsa": ["-algorithm", "ML-DSA-65"],
    }

    serial = 1000
    for name, args in keygen.items():
        openssl("genpkey", *args, "-out", "%s_key.pem" % name)
        openssl("req", "-new", "-key", "%s_key.pem" % name,
                "-subj", "/O=Botan/CN=CMS Interop %s" % name,
                "-out", "%s.csr" % name)
        openssl("x509", "-req", "-in", "%s.csr" % name,
                "-CA", "ca_cert.pem", "-CAkey", "ca_key.pem",
                "-set_serial", str(serial), "-days", "30",
                "-extfile", exts, "-out", "%s_cert.pem" % name)
        serial += 1

    openssl("genpkey", "-algorithm", "ML-KEM-768", "-out", "mlkem_key.pem")
    openssl("pkey", "-in", "mlkem_key.pem", "-pubout", "-out", "mlkem_pub.pem")
    openssl("x509", "-new", "-subj", "/O=Botan/CN=CMS Interop mlkem",
            "-force_pubkey", "mlkem_pub.pem",
            "-CA", "ca_cert.pem", "-CAkey", "ca_key.pem",
            "-set_serial", str(serial), "-days", "30",
            "-extfile", mlkem_exts, "-out", "mlkem_cert.pem")

    with open(r.path("msg.bin"), "wb") as f:
        f.write(TEST_MESSAGE)


def encrypt_tests(r):
    for recipient in ["rsa", "mlkem"]:
        cert = "%s_cert.pem" % recipient
        key = "%s_key.pem" % recipient

        for ossl_cipher, botan_cipher in CIPHERS.items():
            algo = "%s %s" % (recipient, botan_cipher)

            def openssl_to_botan(cert=cert, key=key,
                                 ossl_cipher=ossl_cipher):
                blob = r.path("o2b_env.der")
                out = r.path("o2b_env.txt")
                # openssl defaults to streaming (indefinite-length BER)
                r.check([r.openssl, "cms", "-encrypt", ossl_cipher,
                         "-in", "msg.bin", "-binary", "-outform", "DER",
                         "-stream", "-out", blob, cert])
                r.check([r.botan, "cms_decrypt", "--key=" + r.path(key),
                         "--cert=" + r.path(cert), "--output=" + out, blob])
                with open(out, "rb") as f:
                    assert f.read() == TEST_MESSAGE

            def botan_to_openssl(cert=cert, key=key,
                                 botan_cipher=botan_cipher):
                blob = r.path("b2o_env.der")
                proc = r.check([r.botan, "cms_encrypt",
                                "--cipher=" + botan_cipher,
                                "--output=" + blob, r.path(cert), "msg.bin"])
                proc = r.check([r.openssl, "cms", "-decrypt", "-inform", "DER",
                                "-in", blob, "-inkey", key, "-recip", cert])
                assert proc.stdout == TEST_MESSAGE

            r.attempt("openssl->botan", "encrypt", algo, openssl_to_botan)
            r.attempt("botan->openssl", "encrypt", algo, botan_to_openssl)


def sign_tests(r):
    for signer, md_args in SIGNERS.items():
        cert = "%s_cert.pem" % signer
        key = "%s_key.pem" % signer

        for detached in [False, True]:
            algo = "%s %s" % (signer, "detached" if detached else "attached")

            def openssl_to_botan(cert=cert, key=key, md_args=md_args,
                                 detached=detached):
                blob = r.path("o2b_signed.der")
                cmd = [r.openssl, "cms", "-sign", "-signer", cert,
                       "-inkey", key, "-in", "msg.bin", "-binary",
                       "-nosmimecap", "-outform", "DER",
                       "-out", blob] + md_args
                if detached:
                    # openssl -stream ignores detachment, so use
                    # definite-length output for detached signatures
                    cmd.append("-noindef")
                else:
                    cmd += ["-nodetach", "-stream"]
                r.check(cmd)
                cmd = [r.botan, "cms_verify",
                       "--trusted=" + r.path("ca_cert.pem")]
                if detached:
                    cmd.append("--content=msg.bin")
                cmd.append(blob)
                r.check(cmd)

            def botan_to_openssl(cert=cert, key=key, detached=detached):
                blob = r.path("b2o_signed.der")
                cmd = [r.botan, "cms_sign", "--key=" + r.path(key),
                       "--cert=" + r.path(cert), "--output=" + blob]
                if detached:
                    cmd.append("--detached")
                cmd.append("msg.bin")
                r.check(cmd)
                cmd = [r.openssl, "cms", "-verify", "-inform", "DER",
                       "-in", blob, "-CAfile", "ca_cert.pem", "-binary",
                       "-out", os.devnull]
                if detached:
                    cmd += ["-content", "msg.bin"]
                r.check(cmd)

            r.attempt("openssl->botan", "sign", algo, openssl_to_botan)
            r.attempt("botan->openssl", "sign", algo, botan_to_openssl)


def pq_key_format_tests(r):
    for fmt in PQ_KEY_FORMATS:
        mlkem_key = "mlkem_key_%s.pem" % fmt
        r.check([r.openssl, "pkey", "-in", "mlkem_key.pem",
                 "-provparam", "ml-kem.output_formats=" + fmt,
                 "-out", mlkem_key])

        def decrypt_with_key(key=mlkem_key, fmt=fmt):
            blob = r.path("o2b_env_%s.der" % fmt)
            out = r.path("o2b_env_%s.txt" % fmt)
            r.check([r.openssl, "cms", "-encrypt", "-aes-256-gcm",
                     "-in", "msg.bin", "-binary", "-outform", "DER",
                     "-stream", "-out", blob, "mlkem_cert.pem"])
            r.check([r.botan, "cms_decrypt", "--key=" + r.path(key),
                     "--cert=" + r.path("mlkem_cert.pem"),
                     "--output=" + out, blob])
            with open(out, "rb") as f:
                assert f.read() == TEST_MESSAGE

        r.attempt("openssl->botan", "encrypt", "mlkem %s key" % fmt,
                  decrypt_with_key)

        mldsa_key = "mldsa_key_%s.pem" % fmt
        r.check([r.openssl, "pkey", "-in", "mldsa_key.pem",
                 "-provparam", "ml-dsa.output_formats=" + fmt,
                 "-out", mldsa_key])

        def sign_with_key(key=mldsa_key, fmt=fmt):
            blob = r.path("b2o_signed_%s.der" % fmt)
            r.check([r.botan, "cms_sign", "--key=" + r.path(key),
                     "--cert=" + r.path("mldsa_cert.pem"),
                     "--output=" + blob, "msg.bin"])
            r.check([r.openssl, "cms", "-verify", "-inform", "DER",
                     "-in", blob, "-CAfile", "ca_cert.pem", "-binary",
                     "-out", os.devnull])

        r.attempt("botan->openssl", "sign", "mldsa %s key" % fmt,
                  sign_with_key)


def main(args=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--botan", default="./botan",
                        help="path to the botan cli (default ./botan)")
    parser.add_argument("--openssl", default="openssl",
                        help="path to openssl (default openssl)")
    parser.add_argument("--verbose", action="store_true")
    options = parser.parse_args(args)

    botan = os.path.abspath(options.botan)
    if not os.path.exists(botan):
        print("botan cli not found at %s" % botan, file=sys.stderr)
        return 2

    # Prefer the in-tree library when running an in-tree cli
    botan_dir = os.path.dirname(botan)
    if os.path.exists(os.path.join(botan_dir, "libbotan-3.so")):
        os.environ["LD_LIBRARY_PATH"] = botan_dir + os.pathsep + \
            os.environ.get("LD_LIBRARY_PATH", "")

    with tempfile.TemporaryDirectory(prefix="cms_interop_") as workdir:
        r = Runner(botan, options.openssl, workdir, options.verbose)
        generate_credentials(r)
        encrypt_tests(r)
        sign_tests(r)
        pq_key_format_tests(r)

    width = max(len(algo) for _, _, algo, _ in r.results)
    fails = 0
    for direction, op, algo, outcome in r.results:
        print("%-15s %-8s %-*s %s" % (direction, op, width, algo, outcome))
        if outcome == "FAIL":
            fails += 1

    if fails > 0:
        print("%d combinations FAILED" % fails)
        return 1
    print("All supported combinations passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
