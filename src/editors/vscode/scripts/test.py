#!/usr/bin/env python3

import os
import re
import sys

import common


TESTS_DIR = "src/tests"


def get_test_names_from(test_file):
    if not os.path.dirname(test_file) == TESTS_DIR:
        raise common.BuildError(
            'Given file path is not a Botan unit test: ' + test_file)

    with open(test_file, 'r', encoding='utf-8') as f:
        find_test_registration = \
            re.compile(
                r'BOTAN_REGISTER_TEST(_FN)?\s*\(\s*\"(.+)\",\s*\"(.+)\",[^)]+\)')

        matches = find_test_registration.findall(f.read())
        tests = [match[-1] for match in matches]

    if not tests:
        raise common.BuildError(
            'Failed to find a BOTAN_REGISTER_TEST in the given test file: ' + test_file)

    return tests


def main():
    test_binary = os.path.join('.', common.get_test_binary_name())

    if len(sys.argv) == 2:
        test_src_file = sys.argv[1]
        test_names = get_test_names_from(test_src_file)
        common.run_cmd("%s %s" % (test_binary, ' '.join(test_names)))
    else:
        common.run_cmd(test_binary)


if __name__ == '__main__':
    main()
