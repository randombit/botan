#!/usr/bin/env python

import binascii
import argparse
import re
import subprocess
import sys
import os.path
import logging
import time
from collections import OrderedDict
import multiprocessing
from multiprocessing.pool import ThreadPool

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

class VecDocument:
    def __init__(self, filepath):
        self.data = OrderedDict()
        last_testcase_number = 1
        current_testcase_number = 1
        current_group_name = ""
        last_group_name = ""
        current_testcase = {}

        PATTERN_GROUPHEADER = "^\[(.+)\]$"
        PATTERN_KEYVALUE = "^\s*([a-zA-Z]+)\s*=(.*)$"

        with open(filepath, 'r') as f:
            # Append one empty line to simplify parsing
            lines = f.read().splitlines() + ["\n"]

            for line in lines:
                line = line.strip()
                if line.startswith("#"):
                    pass # Skip
                elif line == "":
                    current_testcase_number += 1
                elif re.match(PATTERN_GROUPHEADER, line):
                    match = re.match(PATTERN_GROUPHEADER, line)
                    current_group_name = match.group(1)
                elif re.match(PATTERN_KEYVALUE, line):
                    match = re.match(PATTERN_KEYVALUE, line)
                    key = match.group(1)
                    value = match.group(2).strip()
                    current_testcase[key] = value

                if current_testcase_number != last_testcase_number:
                    if not current_group_name in self.data:
                        self.data[current_group_name] = []
                    if len(current_testcase) != 0:
                        self.data[current_group_name].append(current_testcase)
                    current_testcase = {}
                    last_testcase_number = current_testcase_number

                if current_group_name != last_group_name:
                    last_group_name = current_group_name
                    # Reset testcase number
                    last_testcase_number = 1
                    current_testcase_number = 1

    def get_data(self):
        return self.data

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

def test_cipher_kat(cli_binary, data):
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
    output = binascii.hexlify(out_raw).decode("UTF-8").lower()

    expected = plaintext if direction == "decrypt" else ciphertext
    if expected != output:
        logging.error("For test %s got %s expected %s" % (data['testname'], output, expected))

def get_testdata(document, max_tests):
    out = []
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
                    test = {'testname': testname}
                    for key in testcase:
                        value = testcase[key]
                        test[key] = value
                    test['Algorithm'] = algorithm
                    test['Direction'] = direction

                    out.append(test)

                if max_tests > 0 and testcase_number > max_tests:
                    break
    return out

def main(args=None):
    if args is None:
        args = sys.argv

    parser = argparse.ArgumentParser(description="")
    parser.add_argument('cli_binary', help='path to the botan cli binary')
    parser.add_argument('--max-tests', type=int, default=50, metavar="M")
    parser.add_argument('--threads', type=int, default=0, metavar="T")
    parser.add_argument('--verbose', action='store_true', default=False)
    parser.add_argument('--quiet', action='store_true', default=False)
    args = parser.parse_args()

    setup_logging(args)

    cli_binary = args.cli_binary
    max_tests = args.max_tests
    threads = args.threads

    if threads == 0:
        threads = multiprocessing.cpu_count()

    test_data_dir = os.path.join('src', 'tests', 'data')

    mode_test_data = [os.path.join(test_data_dir, 'modes', 'cfb.vec'),
                      os.path.join(test_data_dir, 'aead', 'gcm.vec'),
                      os.path.join(test_data_dir, 'aead', 'ocb.vec'),
                      os.path.join(test_data_dir, 'modes', 'xts.vec'),
                      os.path.join(test_data_dir, 'aead', 'chacha20poly1305.vec')]

    kats = []
    for f in mode_test_data:
        vecfile = VecDocument(f)
        kats += get_testdata(vecfile.get_data(), max_tests)

    start_time = time.time()

    if threads > 1:
        pool = ThreadPool(processes=threads)
        results = []
        for test in kats:
            results.append(pool.apply_async(test_cipher_kat, (cli_binary, test)))

        for result in results:
            result.get()
    else:
        for test in kats:
            test_cipher_kat(test)

    end_time = time.time()

    print("Ran %d tests with %d failures in %.02f seconds" % (
        len(kats), TESTS_FAILED, end_time - start_time))

    if TESTS_FAILED > 0:
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
