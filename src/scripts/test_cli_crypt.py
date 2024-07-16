#!/usr/bin/env python3

"""
(C) 2015,2016,2017,2018 Simon Warta
(C) 2019,2020,2021 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

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

class VecDocument:
    def __init__(self, filepath):
        self.data = OrderedDict()
        last_testcase_number = 1
        current_testcase_number = 1
        current_group_name = ""
        last_group_name = ""
        current_testcase = {}

        PATTERN_GROUPHEADER = r"^\[(.+)\]$"
        PATTERN_KEYVALUE = r"^\s*([a-zA-Z]+)\s*=(.*)$"

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
    iv = data['Nonce'] if 'Nonce' in data else ''
    key = data['Key']
    plaintext = data['In'].lower()
    ciphertext = data['Out'].lower()
    algorithm = data['Algorithm']
    direction = data['Direction']

    cmd = [
        cli_binary,
        "cipher",
        "--cipher=%s" % algorithm,
        "--nonce=%s" % iv,
        "--key=%s" % key,
        "-"]

    if 'AD' in data:
        cmd += ['--ad=%s' % (data['AD'])]

    if direction == "decrypt":
        cmd += ['--decrypt']

    if direction == "decrypt":
        invalue = ciphertext
    else:
        invalue = plaintext

    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    (stdout_raw, stderr_raw) = p.communicate(input=binascii.unhexlify(invalue))
    output = binascii.hexlify(stdout_raw).decode("UTF-8").lower()
    stderr = stderr_raw.decode("UTF-8")

    if stderr != '':
        logging.error("Unexpected stderr output %s" % (stderr))

    expected = plaintext if direction == "decrypt" else ciphertext
    if expected != output:
        logging.error("For test %s got %s expected %s" % (data['testname'], output, expected))

def get_testdata(document, max_tests):
    out = []
    for algorithm in document:
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
    parser.add_argument('--threads', type=int, default=0, metavar="T")
    parser.add_argument('--verbose', action='store_true', default=False)
    parser.add_argument('--quiet', action='store_true', default=False)
    parser.add_argument('--run-slow-tests', action='store_true', default=False)
    parser.add_argument('--test-data-dir', default='.')
    args = parser.parse_args()

    setup_logging(args)

    cli_binary = args.cli_binary
    max_tests = 0 if args.run_slow_tests else 30
    threads = args.threads

    if threads == 0:
        threads = multiprocessing.cpu_count()

    test_data_dir = os.path.join(args.test_data_dir, 'src', 'tests', 'data')

    mode_test_data = [
        os.path.join(test_data_dir, 'aead', 'ccm.vec'),
        os.path.join(test_data_dir, 'aead', 'chacha20poly1305.vec'),
        os.path.join(test_data_dir, 'aead', 'eax.vec'),
        os.path.join(test_data_dir, 'aead', 'gcm.vec'),
        os.path.join(test_data_dir, 'aead', 'ocb.vec'),
        os.path.join(test_data_dir, 'modes', 'cbc.vec'),
        os.path.join(test_data_dir, 'modes', 'cfb.vec'),
        os.path.join(test_data_dir, 'modes', 'ctr.vec'),
        os.path.join(test_data_dir, 'modes', 'xts.vec'),
    ]

    kats = []
    for f in mode_test_data:
        vecfile = VecDocument(f)
        kats += get_testdata(vecfile.get_data(), max_tests)

    start_time = time.time()

    if threads > 1:
        with ThreadPool(processes=threads) as pool:
            results = []
            for test in kats:
                results.append(pool.apply_async(test_cipher_kat, (cli_binary, test)))

            for result in results:
                result.get()
    else:
        for test in kats:
            test_cipher_kat(cli_binary, test)

    end_time = time.time()

    print("Ran %d tests with %d failures in %.02f seconds" % (
        len(kats), TESTS_FAILED, end_time - start_time))

    if TESTS_FAILED > 0:
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
