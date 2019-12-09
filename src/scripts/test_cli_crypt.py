#!/usr/bin/env python

import binascii
from collections import OrderedDict
import unittest
import argparse
import re
import subprocess
import sys
import os.path

import vecparser

cli_binary = ""

SUPPORTED_ALGORITHMS = {
    "AES-128/CFB": "aes-128-cfb",
    "AES-192/CFB": "aes-192-cfb",
    "AES-256/CFB": "aes-256-cfb",
    "AES-128/GCM": "aes-128-gcm",
    "AES-192/GCM": "aes-192-gcm",
    "AES-256/GCM": "aes-256-gcm",
    "AES-128/OCB": "aes-128-ocb",
    "AES-128/XTS": "aes-128-xts",
    "AES-256/XTS": "aes-256-xts",
    "ChaCha20Poly1305": "chacha20poly1305",
}

class TestSequence(unittest.TestCase):
    pass

def create_test(data):
    def do_test_expected(self):
        iv = data['Nonce']
        key = data['Key']
        ad = data['AD'] if 'AD' in data else ""
        plaintext = data['In'].lower()
        ciphertext = data['Out'].lower()
        algorithm = data['Algorithm']
        direction = data['Direction']

        mode = SUPPORTED_ALGORITHMS.get(algorithm)
        if mode is None:
            raise Exception("Unknown algorithm: '" + algorithm + "'")

        cmd = [
            cli_binary,
            "encryption",
            "--mode=%s" % mode,
            "--iv=%s" % iv,
            "--ad=%s" % ad,
            "--key=%s" % key]
        if direction == "decrypt":
            cmd += ['--decrypt']

        if direction == "decrypt":
            invalue = ciphertext
        else:
            invalue = plaintext

        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        out_raw = p.communicate(input=binascii.unhexlify(invalue))[0]
        out = binascii.hexlify(out_raw).decode("UTF-8").lower()

        # Renamings
        if direction == "decrypt":
            expected = plaintext
        else:
            expected = ciphertext
        actual = out
        self.assertEqual(expected, actual)
    return do_test_expected

def get_testdata(document, max_tests):
    out = OrderedDict()
    for algorithm in document:
        if algorithm in SUPPORTED_ALGORITHMS:
            testcase_number = 0
            for testcase in document[algorithm]:
                testcase_number += 1
                for direction in ['encrypt', 'decrypt']:
                    testname = "{} no {:0>3} ({})".format(
                        algorithm.lower(), testcase_number, direction)
                    testname = re.sub("[^a-z0-9-]", "_", testname)
                    testname = re.sub("_+", "_", testname)
                    testname = testname.strip("_")
                    out[testname] = {}
                    for key in testcase:
                        value = testcase[key]
                        out[testname][key] = value
                    out[testname]['Algorithm'] = algorithm
                    out[testname]['Direction'] = direction

                if max_tests > 0 and testcase_number > max_tests:
                    break
    return out

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="")
    parser.add_argument('cli_binary',
                        help='path to the botan cli binary')
    parser.add_argument('--max-tests', type=int, default=20)
    parser.add_argument('--threads', type=int, default=0)
    parser.add_argument('unittest_args', nargs="*")
    args = parser.parse_args()

    cli_binary = args.cli_binary
    max_tests = args.max_tests

    test_data_dir = os.path.join('src', 'tests', 'data')

    mode_test_data = [os.path.join(test_data_dir, 'modes', 'cfb.vec'),
                      os.path.join(test_data_dir, 'aead', 'gcm.vec'),
                      os.path.join(test_data_dir, 'aead', 'ocb.vec'),
                      os.path.join(test_data_dir, 'modes', 'xts.vec'),
                      os.path.join(test_data_dir, 'aead', 'chacha20poly1305.vec')]

    testdata = OrderedDict()

    for f in mode_test_data:
        vecfile = vecparser.VecDocument(f)
        vecdata = get_testdata(vecfile.get_data(), max_tests)
        for key in vecdata:
            testdata[key] = vecdata[key]

    for testname in testdata:
        test_method = create_test(testdata[testname])
        test_method.__name__ = 'test_%s' % testname
        setattr(TestSequence, test_method.__name__, test_method)

    # Hand over sys.argv[0] and unittest_args to the testing framework
    sys.argv[1:] = args.unittest_args
    unittest.main()
