#!/usr/bin/env python3

import os
import re
import argparse
import glob

import common

TESTS_DIR = "src/tests"


def discover_tests_in_file(test_file):
    if not os.path.dirname(test_file) == TESTS_DIR:
        return []

    with open(test_file, 'r', encoding='utf-8') as f:
        find_test_registration = \
            re.compile(
                r'BOTAN_REGISTER_[A-Z_]*TEST(_FN)?\s*\(\s*\"(.+)\",\s*\"(.+)\",[^)]+\)')

        matches = find_test_registration.findall(f.read())
        return [match[-1] for match in matches]

def discover_tests(args):
    tests = []
    if args.test_src_file:
        tests = discover_tests_in_file(args.test_src_file)

    if args.list and not tests:
        # Apparently 'test_src_file' didn't contain any tests, lets
        # go ahead and discover all unit tests in the src/tests dir.
        test_files = glob.glob(os.path.join(TESTS_DIR, '*.cpp'), recursive=False)
        for test_file in test_files:
            tests += discover_tests_in_file(test_file)

    return sorted(set(tests))

def main():
    test_binary = os.path.join('.', common.get_test_binary_name())
    args = argparse.ArgumentParser(description='Run Botan tests')
    args.add_argument('--list', action='store_true', default=False, help='List all available tests')
    args.add_argument('test_src_file', nargs='?', help='Path to the test source file')
    parsed_args = args.parse_args()

    discovered_tests = discover_tests(parsed_args)

    if parsed_args.list:
        print("\n".join(discovered_tests))
        return

    if not parsed_args.test_src_file:
        discovered_tests.clear()

    common.run_cmd(" ".join([test_binary, *discovered_tests]))


if __name__ == '__main__':
    main()
