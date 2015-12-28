#!/usr/bin/env python3

import binascii
import collections
import unittest
import argparse
import re
import subprocess
import vecparser
import sys

cli_binary = ""
testdata = {}

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

        if algorithm == "AES-128/GCM":
            mode = "aes-128-gcm"
        elif algorithm == "AES-192/GCM":
            mode = "aes-192-gcm"
        elif algorithm == "AES-256/GCM":
            mode = "aes-256-gcm"
        else: raise Exception("Unknown algorithm: '" + algorithm + "'")

        cmd = [
            cli_binary,
            "encryption",
            "--mode=%s" % mode,
            "--iv=%s" % iv,
            "--ad=%s" % ad,
            "--key=%s" % key]
        if direction == "decrypt":
            cmd += ['--decrypt']
        # out_raw = subprocess.check_output(cmd)

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

def get_testdata(document):
    out = collections.OrderedDict()
    for algorithm in document:
        if algorithm in ['AES-128/GCM', 'AES-192/GCM', 'AES-256/GCM']:
            testcase_number = 0
            for testcase in document[algorithm]:
                testcase_number += 1
                for direction in ['encrypt', 'decrypt']:
                    testname = "%s no %d (%s)" % (algorithm.lower(), testcase_number, direction)
                    testname = re.sub("[^a-z0-9\-]", "_", testname)
                    testname = re.sub("_+", "_", testname)
                    testname = testname.strip("_")
                    out[testname] = {}
                    for key in testcase:
                        value = testcase[key]
                        out[testname][key] = value
                    out[testname]['Algorithm'] = algorithm
                    out[testname]['Direction'] = direction
    return out

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="")
    parser.add_argument('cli_binary',
                        help='path to the botan cli binary')
    parser.add_argument('unittest_args', nargs="*")
    args = parser.parse_args()

    cli_binary = args.cli_binary

    vecfile = vecparser.VecDocument("src/tests/data/aead/gcm.vec")
    #data = vecfile.get_data()
    #for algo in data:
    #    print(algo)
    #    i = 0
    #    for testcase in data[algo]:
    #        i += 1
    #        print(str(i) + ":", testcase)

    testdata = get_testdata(vecfile.get_data())
    #for testname in testdata:
    #    print(testname)
    #    for key in testdata[testname]:
    #        print("    " + key + ": " + testdata[testname][key])
    for testname in testdata:
        test_method = create_test (testdata[testname])
        test_method.__name__ = 'test_%s' % testname
        setattr(TestSequence, test_method.__name__, test_method)

    # Hand over sys.argv[0] and unittest_args to the testing framework
    sys.argv[1:] = args.unittest_args
    unittest.main()
