#!/usr/bin/python

import subprocess
import sys
import os
import logging
import optparse # pylint: disable=deprecated-module
import time
import shutil
import tempfile
import re

# pylint: disable=global-statement

CLI_PATH = None
TESTS_RUN = 0
TESTS_FAILED = 0

class TestLogHandler(logging.StreamHandler, object):
    def emit(self, record):
        # Do the default stuff first
        super(TestLogHandler, self).emit(record)
        if record.levelno >= logging.ERROR:
            global TESTS_FAILED
            TESTS_FAILED += 1

def setup_logging(options):
    if options.verbose:
        log_level = logging.DEBUG
    elif options.quiet:
        log_level = logging.WARNING
    else:
        log_level = logging.INFO

    lh = TestLogHandler(sys.stdout)
    lh.setFormatter(logging.Formatter('%(levelname) 7s: %(message)s'))
    logging.getLogger().addHandler(lh)
    logging.getLogger().setLevel(log_level)


def test_cli(cmd, cmd_options, expected_output=None, cmd_input=None):
    global TESTS_RUN
    global TESTS_FAILED

    TESTS_RUN += 1

    logging.debug("Running %s %s", cmd, cmd_options)

    fixed_drbg_seed = "802" * 32

    opt_list = []

    if isinstance(cmd_options, str):
        opt_list = cmd_options.split(' ')
    elif isinstance(cmd_options, list):
        opt_list = cmd_options

    drbg_options = ['--rng-type=drbg', '--drbg-seed=' + fixed_drbg_seed]
    cmdline = [CLI_PATH, cmd] + drbg_options + opt_list

    stdout = None
    stderr = None

    if cmd_input is None:
        proc = subprocess.Popen(cmdline, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (stdout, stderr) = proc.communicate()
    else:
        proc = subprocess.Popen(cmdline, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (stdout, stderr) = proc.communicate(cmd_input.encode())

    if stderr:
        logging.error("Got output on stderr %s", stderr)

    output = stdout.decode('ascii').strip()

    if expected_output != None:
        if output != expected_output:
            logging.error("Got unexpected output running cmd %s %s", cmd, cmd_options)
            logging.info("Output lengths %d vs expected %d", len(output), len(expected_output))
            logging.info("Got %s", output)
            logging.info("Exp %s", expected_output)

    return output

def cli_help_tests():
    output = test_cli("help", None, None)

    # Maybe test format somehow??
    if len(output) < 500:
        logging.error("Help output seems very short")

def cli_is_prime_tests():
    test_cli("is_prime", "5", "5 is probably prime")
    test_cli("is_prime", "9", "9 is composite")
    test_cli("is_prime", "548950623407687320763", "548950623407687320763 is probably prime")

def cli_gen_prime_tests():
    test_cli("gen_prime", "64", "15568813029901363223")
    test_cli("gen_prime", "128", "287193909494025008847286845478788769439")

def cli_factor_tests():
    test_cli("factor", "97", "97: 97")
    test_cli("factor", "9753893489562389", "9753893489562389: 21433 455087644733")
    test_cli("factor", "12019502040659149507", "12019502040659149507: 3298628633 3643787579")

def cli_mod_inverse_tests():
    test_cli("mod_inverse", "97 802", "339")
    test_cli("mod_inverse", "98 802", "0")

def cli_base64_tests():
    test_cli("base64_enc", "-", "YmVlcyE=", "bees!")
    test_cli("base64_dec", "-", "bees!", "YmVlcyE=")

def cli_hex_tests():
    test_cli("hex_enc", "-", "6265657321", "bees!")
    test_cli("hex_dec", "-", "bees!", "6265657321")

def cli_hash_tests():
    test_cli("hash", "--algo=SHA-256",
             "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 -", "")

    test_cli("hash", "--algo=SHA-256",
             "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD -", "abc")

def cli_bcrypt_tests():
    test_cli("gen_bcrypt", "--work-factor=4 s3kr1t",
             "$2a$04$0.8G7o08XYwvBBWA3l0WUujtwoGZgGDzVSN8fNkNqXikcK4A3lHPS")

    test_cli("check_bcrypt", "s3kr1t $2a$04$gHX4Qg7pDSJuXiPXnmt8leyb.FFzX1Bv4rXwIj2cPSakJ8zNnhIka",
             "Password is valid")

    test_cli("check_bcrypt", "santa $2a$04$gHX4Qg7pDSJuXiPXnmt8leyb.FFzX1Bv4rXwIj2cPSakJ8zNnhIka",
             "Password is NOT valid")

def cli_gen_dl_group_tests():

    pem = """-----BEGIN X9.42 DH PARAMETERS-----
MIIBJAKBgwS7QodscwdpuPdbHL7YeFP7yRjdqWovbwD+/zSd2OMswe82XnawKsSq
FSCVAfsG75CBRZ2krSY8X/7zuIh8yoAPs87ZIQJmKJem/MdII7zndfnec+klKtHo
FX2mOFzmndWJBXv4fwWLHEGIoeCamveL2+q1M8sakNicI7U2vUkX30CxAoGDArnH
im+KLvXXL4uR97V/yDVx/Vf0Eu8Bqxkx6jFMiabzc4mhCJ+MHh2nH3U67PLAnTgR
zCQcHevoOKd/ODychEHWwqP26aKCaRUS1DLq8U/qPL7L2pTMLYu27THt7HvKfA0D
mMo6OGy9uFpJkaLVypD+LKEY/Bc540iRFQcW63ngpo0CFjgPiPatvmWssQw2AuZ9
mFvAZ/8wal0=
-----END X9.42 DH PARAMETERS-----"""

    test_cli("gen_dl_group", "--pbits=1043", pem)

def cli_key_tests():

    pem = """-----BEGIN PRIVATE KEY-----
MD4CAQAwEAYHKoZIzj0CAQYFK4EEAAoEJzAlAgEBBCDYD4j2rb5lrLEMNgLmfZhb
wGf/MGbgPebBLmozAANENw==
-----END PRIVATE KEY-----"""

    tmp_dir = tempfile.mkdtemp(prefix='botan_cli')

    priv_key = os.path.join(tmp_dir, 'priv.pem')
    pub_key = os.path.join(tmp_dir, 'pub.pem')
    ca_cert = os.path.join(tmp_dir, 'ca.crt')
    crt_req = os.path.join(tmp_dir, 'crt.req')
    user_cert = os.path.join(tmp_dir, 'user.crt')

    test_cli("keygen", ["--algo=ECDSA", "--params=secp256k1"], pem)

    test_cli("keygen", ["--algo=ECDSA", "--params=secp256r1", "--output=" + priv_key], "")

    test_cli("pkcs8", "--pub-out --output=%s %s" % (pub_key, priv_key), "")

    valid_sig = "xd3J9jtTBWFWA9ceVGYpmEB0A1DmOoxHRF7FpYW2ng/GYEH/HYljIfYzu/L5iTK6XfVePxeMr6ubCYCD9vFGIw=="

    test_cli("sign", "--provider=base %s %s" % (priv_key, priv_key), valid_sig)

    test_cli("verify", [pub_key, priv_key, '-'],
             "Signature is valid", valid_sig)

    test_cli("verify", [pub_key, priv_key, '-'],
             "Signature is invalid",
             valid_sig.replace("W", "Z"))

    test_cli("gen_self_signed",
             [priv_key, "CA", "--ca", "--country=VT",
              "--dns=ca.example", "--hash=SHA-384", "--output="+ca_cert],
             "")

    test_cli("cert_verify", ca_cert, "Certificate did not validate - Cannot establish trust")

    test_cli("gen_pkcs10", "%s User --output=%s" % (priv_key, crt_req))

    test_cli("sign_cert", "%s %s %s --output=%s" % (ca_cert, priv_key, crt_req, user_cert))

    test_cli("cert_verify", [user_cert, ca_cert],
             "Certificate passes validation checks")

    test_cli("cert_verify", user_cert,
             "Certificate did not validate - Certificate issuer not found")

    shutil.rmtree(tmp_dir)

def cli_psk_db_tests():
    tmp_dir = tempfile.mkdtemp(prefix='botan_cli')

    psk_db = os.path.join(tmp_dir, 'psk.db')
    db_key = "909"*32

    test_cli("psk_set", [psk_db, db_key, "name", "val"], "")

    shutil.rmtree(tmp_dir)

def cli_rng_tests():
    test_cli("rng", "10", "D80F88F6ADBE65ACB10C")
    test_cli("rng", "16", "D80F88F6ADBE65ACB10C3602E67D985B")
    test_cli("rng", "10 6", "D80F88F6ADBE65ACB10C\n1B119CC068AF")

def cli_ec_group_info_tests():

    # pylint: disable=line-too-long
    secp256r1_info = """P = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
B = 5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
G = 6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"""

    secp256r1_pem = """-----BEGIN EC PARAMETERS-----
MIHgAgEBMCwGByqGSM49AQECIQD/////AAAAAQAAAAAAAAAAAAAAAP//////////
/////zBEBCD/////AAAAAQAAAAAAAAAAAAAAAP///////////////AQgWsY12Ko6
k+ez671VdpiGvGUdBrDMU7D2O848PifSYEsEQQRrF9Hy4SxCR/i85uVjpEDydwN9
gS3rM6D0oTlF2JjClk/jQuL+Gn+bjufrSnwPnhYrzjNXazFezsu2QGg3v1H1AiEA
/////wAAAAD//////////7zm+q2nF56E87nKwvxjJVECAQE=
-----END EC PARAMETERS-----"""

    test_cli("ec_group_info", "secp256r1", secp256r1_info)
    test_cli("ec_group_info", "--pem secp256r1", secp256r1_pem)

def cli_cc_enc_tests():
    test_cli("cc_encrypt", ["8028028028028029", "pass"], "4308989841607208")
    test_cli("cc_decrypt", ["4308989841607208", "pass"], "8028028028028027")

def cli_timing_test_tests():

    timing_tests = ["bleichenbacher", "manger",
                    "ecdsa", "ecc_mul", "inverse_mod",
                    "lucky13sec3", "lucky13sec4sha1",
                    "lucky13sec4sha256", "lucky13sec4sha384"]

    output_re = re.compile('[0-9]+;[0-9];[0-9]+')

    for suite in timing_tests:
        output = test_cli("timing_test", [suite, "--measurement-runs=16", "--warmup-runs=3"], None).split('\n')

        for line in output:
            if output_re.match(line) is None:
                logging.error("Unexpected output in timing_test %s: %s", suite, line)

def cli_tls_ciphersuite_tests():
    policies = ['default', 'suiteb', 'strict', 'all']

    versions = ['tls1.0', 'tls1.1', 'tls1.2']

    ciphersuite_re = re.compile('^[A-Z0-9_]+$')

    for policy in policies:
        for version in versions:

            if policy in ['suiteb', 'strict'] and version != 'tls1.2':
                continue

            output = test_cli("tls_ciphers", ["--version=" + version, "--policy=" + policy], None).split('\n')

            for line in output:
                if ciphersuite_re.match(line) is None:
                    logging.error("Unexpected ciphersuite line %s", line)

def cli_asn1_tests():
    input_pem = """-----BEGIN BLOB-----
MCACAQUTBnN0cmluZzEGAQH/AgFjBAUAAAAAAAMEAP///w==
-----END BLOB------
"""

    expected = """d= 0, l=  32: SEQUENCE
  d= 1, l=   1:  INTEGER                                    05
  d= 1, l=   6:  PRINTABLE STRING                           string
  d= 1, l=   6:  SET
  d= 2, l=   1:   BOOLEAN                                   true
  d= 2, l=   1:   INTEGER                                   63
  d= 1, l=   5:  OCTET STRING                               0000000000
  d= 1, l=   4:  BIT STRING                                 FFFFFF"""

    test_cli("asn1print", "--pem -", expected, input_pem)

def cli_speed_tests():
    output = test_cli("speed", ["--msec=1", "--buf-size=64,512", "AES-128"], None).split('\n')

    if len(output) % 4 != 0:
        logging.error("Unexpected number of lines for AES-128 speed test")

    # pylint: disable=line-too-long
    format_re = re.compile(r'^AES-128 .* buffer size [0-9]+ bytes: [0-9]+\.[0-9]+ MiB\/sec .*\([0-9]+\.[0-9]+ MiB in [0-9]+\.[0-9]+ ms\)')
    for line in output:
        if format_re.match(line) is None:
            logging.error("Unexpected line %s", line)

    output = test_cli("speed", ["--msec=1", "ChaCha20", "SHA-256", "HMAC(SHA-256)"], None).split('\n')

    # pylint: disable=line-too-long
    format_re = re.compile(r'^.* buffer size [0-9]+ bytes: [0-9]+\.[0-9]+ MiB\/sec .*\([0-9]+\.[0-9]+ MiB in [0-9]+\.[0-9]+ ms\)')
    for line in output:
        if format_re.match(line) is None:
            logging.error("Unexpected line %s", line)


    pk_algos = ["ECDSA", "ECDH", "SM2", "ECKCDSA", "ECGDSA",
                "DH", "DSA", "ElGamal", "Ed25519", "Curve25519",
                "NEWHOPE", "McEliece"]

    output = test_cli("speed", ["--msec=5"] + pk_algos, None).split('\n')

    # ECDSA-secp256r1 106 keygen/sec; 9.35 ms/op 37489733 cycles/op (1 op in 9 ms)
    format_re = re.compile(r'^.* [0-9]+ ([A-Za-z ]+)/sec; [0-9]+\.[0-9]+ ms/op .*\([0-9]+ (op|ops) in [0-9]+ ms\)')
    for line in output:
        if format_re.match(line) is None:
            logging.error("Unexpected line %s", line)

def main(args=None):
    if args is None:
        args = sys.argv

    parser = optparse.OptionParser(
        formatter=optparse.IndentedHelpFormatter(max_help_position=50))

    parser.add_option('--verbose', action='store_true', default=False)
    parser.add_option('--quiet', action='store_true', default=False)

    (options, args) = parser.parse_args(args)

    setup_logging(options)

    if len(args) != 2:
        logging.error("Usage: ./cli_tests.py path_to_botan_cli")
        return 1

    if os.access(args[1], os.X_OK) != True:
        logging.error("Could not access/execute %s", args[1])
        return 2

    global CLI_PATH
    CLI_PATH = args[1]

    start_time = time.time()
    cli_help_tests()
    cli_is_prime_tests()
    cli_factor_tests()
    cli_mod_inverse_tests()
    cli_base64_tests()
    cli_hex_tests()
    cli_gen_prime_tests()
    cli_hash_tests()
    cli_rng_tests()
    cli_bcrypt_tests()
    cli_gen_dl_group_tests()
    cli_ec_group_info_tests()
    cli_key_tests()
    cli_cc_enc_tests()
    cli_timing_test_tests()
    cli_asn1_tests()
    cli_speed_tests()
    cli_tls_ciphersuite_tests()
    #cli_psk_db_tests()
    end_time = time.time()

    print("Ran %d tests with %d failures in %.02f seconds" % (
        TESTS_RUN, TESTS_FAILED, end_time - start_time))

    if TESTS_FAILED > 0:
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
