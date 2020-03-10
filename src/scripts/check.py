#!/usr/bin/env python

"""
Implements the "make check" target

(C) 2020 Jack Lloyd, Rene Meusel

Botan is released under the Simplified BSD License (see license.txt)
"""

import os
import sys
import optparse
import subprocess
import logging
import platform

def is_macos():
    return platform.system() == "Darwin"

def run_and_check(cmd_line, env=None, cwd=None):

    logging.info("Starting %s", ' '.join(cmd_line))

    try:
        proc = subprocess.Popen(cmd_line, cwd=cwd, env=env)
        proc.communicate()
    except OSError as e:
        logging.error("Executing %s failed (%s)", ' '.join(cmd_line), e)

    if proc.returncode != 0:
        logging.error("Error running %s", ' '.join(cmd_line))
        sys.exit(1)


def parse_options(args):
    parser = optparse.OptionParser()
    parser.add_option('--test-exe', default='botan-test', metavar='BINARY',
                      help='specify the botan-test binary name (default %default)')
    parser.add_option('--shared-lib', default=None, metavar='SHARED_LIB',
                      help='use shared library of botan (default %default)')

    (options, args) = parser.parse_args(args)

    if len(args) > 1:
        raise Exception("Unknown arguments")

    return options


def main(args=None):
    if args is None:
        args = sys.argv

    options = parse_options(args)
    test_exe = options.test_exe
    shared_lib = options.shared_lib

    if not os.path.isfile(test_exe) or not os.access(test_exe, os.X_OK):
        raise Exception("Test binary not built")

    if shared_lib and not os.path.isfile(shared_lib):
        raise Exception("Shared library %s not found" % shared_lib)

    env = os.environ.copy()
    if shared_lib and is_macos():
        env["DYLD_LIBRARY_PATH"] = "."

    run_and_check([ test_exe ], env)

    return 0

if __name__ == '__main__':
    sys.exit(main())
