#!/usr/bin/env python3

"""
Build helper script for Botan's Sublime Text integration

(C) 2022 Jack Lloyd
(C) 2022 René Meusel (neXenio GmbH)

Botan is released under the Simplified BSD License (see license.txt)
"""

import argparse
import multiprocessing
import subprocess
import sys
import os
import re


class BuildError(Exception):
    pass


def run_cmd(cmd):
    if isinstance(cmd, str):
        print('> running: ' + cmd)
        shell = True
    else:
        print('> running: ' + ' '.join(cmd))
        shell = False
    sys.stdout.flush()

    try:
        subprocess.run(cmd, shell=shell, check=True)
    except subprocess.CalledProcessError as ex:
        raise BuildError('Command failed, aborting...') from ex


def _find_regex_in_makefile(regex):
    if not os.path.exists('Makefile'):
        raise BuildError(
            'No Makefile found. Initial ./configure.py invocation must be performed manually.')

    with open('Makefile', 'r', encoding='utf8') as f:
        return re.search(regex, f.read())


def _retrieve_test_binary_name():
    match = _find_regex_in_makefile(r'TEST\s*=\s*([^\n]+)\n')
    if not match:
        raise BuildError('Test binary name not found in Makefile')
    test_file = os.path.split(match.group(1))[1]
    if not test_file:
        raise BuildError(
            'Cannot make sense of test binary name: ' + match.group(0))

    return test_file


def _retrieve_configure_command():
    match = _find_regex_in_makefile(r'\'(configure\.py.+)\'\n')
    if not match:
        raise BuildError('configure.py command not found in Makefile')
    return match.group(1)


def reconfigure():
    run_cmd("./" + _retrieve_configure_command())


def build(target=''):
    reconfigure()
    cmd = ['make', '-j', str(multiprocessing.cpu_count())]
    if target:
        cmd.append(target)
    run_cmd(cmd)


def _parse_test_file(test_file):
    if not re.search(r'.+/tests/.+\.cpp', test_file):
        raise BuildError(
            'Given file path is not a Botan unit test: ' + test_file)

    with open(test_file, 'r', encoding='utf8') as f:
        find_test_registration = \
            re.compile(
                r'BOTAN_REGISTER_TEST(_FN)?\s*\(\s*\"(.+)\",\s*\"(.+)\",[^)]+\)')

        matches = find_test_registration.findall(f.read())
        tests = [match[-1] for match in matches]

    if not tests:
        raise BuildError(
            'Failed to find a BOTAN_REGISTER_TEST in the given test file: ' + test_file)

    return tests


def unittests(test_file):
    tests = _parse_test_file(test_file) if test_file else []

    build('tests')
    run_cmd(['./' + _retrieve_test_binary_name()] + tests)


def apply_astyle_format(format_file):
    ext = os.path.splitext(format_file)[1]
    if ext not in ['.cpp', '.h']:
        raise BuildError(
            "Refuse to format source files that appear to be non-C++")

    try:
        run_cmd(['astyle',
                 '--suffix=none',  # do not create a backup copy of the unformatted file
                 '--project=src/configs/astyle.rc',
                 format_file])
    except FileNotFoundError as ex:
        raise BuildError(
            "astyle utility not installed, cannot apply formatting") from ex


def main():
    parser = argparse.ArgumentParser(description='Sublime build helper')
    parser.add_argument('job', type=str)
    parser.add_argument('--project-root', type=str, required=True)
    parser.add_argument('--test-file', type=str, default='')
    parser.add_argument('--format-file', type=str, default='')

    opts = parser.parse_args()

    os.chdir(opts.project_root)

    if opts.job == 'all':
        build()
    elif opts.job == 'test':
        unittests(opts.test_file)
    elif opts.job == 'format':
        apply_astyle_format(opts.format_file)
    else:
        raise RuntimeError('Unknown build job: ' + opts.job)


if __name__ == '__main__':
    try:
        main()
    except BuildError as msg:
        print(msg, file=sys.stderr)
        sys.exit(1)
