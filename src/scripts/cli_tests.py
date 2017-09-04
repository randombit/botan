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

SUPPORTED_ALGORITHMS = [
    'AES-128/CFB',
    'AES-192/CFB',
    'AES-256/CFB',
    'AES-128/GCM',
    'AES-192/GCM',
    'AES-256/GCM',
    'AES-128/OCB',
    'AES-128/XTS',
    'AES-256/XTS'
]

def append_ordered(base, additional_elements):
    for key in additional_elements:
        value = additional_elements[key]
        base[key] = value

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

        # CFB
        if algorithm == "AES-128/CFB":
            mode = "aes-128-cfb"
        elif algorithm == "AES-192/CFB":
            mode = "aes-192-cfb"
        elif algorithm == "AES-256/CFB":
            mode = "aes-256-cfb"
        # GCM
        elif algorithm == "AES-128/GCM":
            mode = "aes-128-gcm"
        elif algorithm == "AES-192/GCM":
            mode = "aes-192-gcm"
        elif algorithm == "AES-256/GCM":
            mode = "aes-256-gcm"
        # OCB
        elif algorithm == "AES-128/OCB":
            mode = "aes-128-ocb"
        # XTS
        elif algorithm == "AES-128/XTS":
            mode = "aes-128-xts"
        elif algorithm == "AES-256/XTS":
            mode = "aes-256-xts"
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

        #print(cmd)

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
    out = OrderedDict()
    for algorithm in document:
        if algorithm in SUPPORTED_ALGORITHMS:
            testcase_number = 0
            for testcase in document[algorithm]:
                testcase_number += 1
                for direction in ['encrypt', 'decrypt']:
                    testname = "{} no {:0>3} ({})".format(
                        algorithm.lower(), testcase_number, direction)
                    testname = re.sub("[^-a-z0-9-]", "_", testname)
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

    vecfile_cfb = vecparser.VecDocument(os.path.join('src', 'tests', 'data', 'modes', 'cfb.vec'))
    vecfile_gcm = vecparser.VecDocument(os.path.join('src', 'tests', 'data', 'aead', 'gcm.vec'))
    vecfile_ocb = vecparser.VecDocument(os.path.join('src', 'tests', 'data', 'aead', 'ocb.vec'))
    vecfile_xts = vecparser.VecDocument(os.path.join('src', 'tests', 'data', 'modes', 'xts.vec'))
    #data = vecfile.get_data()
    #for algo in data:
    #    print(algo)
    #    i = 0
    #    for testcase in data[algo]:
    #        i += 1
    #        print(str(i) + ":", testcase)

    testdata = OrderedDict()
    append_ordered(testdata, get_testdata(vecfile_cfb.get_data()))
    append_ordered(testdata, get_testdata(vecfile_gcm.get_data()))
    append_ordered(testdata, get_testdata(vecfile_ocb.get_data()))
    append_ordered(testdata, get_testdata(vecfile_xts.get_data()))

    #for testname in testdata:
    #    print(testname)
    #    for key in testdata[testname]:
    #        print("    " + key + ": " + testdata[testname][key])
    for testname in testdata:
        test_method = create_test(testdata[testname])
        test_method.__name__ = 'test_%s' % testname
        setattr(TestSequence, test_method.__name__, test_method)

    # Hand over sys.argv[0] and unittest_args to the testing framework
    sys.argv[1:] = args.unittest_args
    unittest.main()
