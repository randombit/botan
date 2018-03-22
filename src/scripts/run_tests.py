#!/usr/bin/python

"""
(C) 2018 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import sys
import os
import subprocess
import optparse # pylint: disable=deprecated-module

def main(args=None):
    if args is None:
        args = sys.argv

    parser = optparse.OptionParser()
    parser.add_option('--build-dir', metavar='DIR', default='build')
    parser.add_option('--test-data-dir', metavar='DIR', default='src/tests/data')

    (options, args) = parser.parse_args(args)

    if len(args) != 2:
        print("Error: usage %s --build-dir=D /path/to/botan-test" % (args[0]))
        return 1

    botan_test = args[1]

    # We assume shared obj, if created, exists in same dir as the test
    dlib_dir = os.path.normpath(os.path.dirname(botan_test))
    data_dir = os.path.normpath(options.test_data_dir)

    env = {}
    env['DYLD_LIBRARY_PATH'] = dlib_dir
    env['LD_LIBRARY_PATH'] = dlib_dir

    # stdout, stderr not captured
    proc = subprocess.Popen([botan_test, '--data-dir=%s' % (data_dir)],
                            env=env)

    proc.communicate()

    if proc.returncode != 0:
        print("Error: running %s returned code %d" % (botan_test, proc.returncode))
    return proc.returncode

if __name__ == '__main__':
    sys.exit(main())
