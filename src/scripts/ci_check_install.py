#!/usr/bin/env python
# coding=utf8

"""
Botan CI check installation script
This script is used to validate the results of `make install`

(C) 2020 Jack Lloyd, René Meusel, Hannes Rantzsch

Botan is released under the Simplified BSD License (see license.txt)
"""

import os
import sys

def has_extension(filename, extensions):
    for ext in [ext for ext in extensions]:
        if filename.endswith(".%s" % ext):
            return True
    return False

def is_lib_file(filename):
    return has_extension(filename, ["so", "a", "dll", "dylib", "lib"])

def is_header_file(filename):
    return has_extension(filename, ["h", "hpp", "h++", "hxx", "hh"])

def main():
    if len(sys.argv) < 2:
        print("Usage: %s <install_prefix>" % sys.argv[0])
        return 1
    install_prefix = sys.argv[1]

    if not os.path.isdir(install_prefix):
        print('Error: install_prefix "%s" is not a directory' % install_prefix)
        return 1

    found_libs = False
    found_headers = False

    for (_, _, filenames) in os.walk(install_prefix):
        for filename in filenames:
            if is_header_file(filename):
                found_headers = True
            elif is_lib_file(filename):
                found_libs = True
        if found_libs and found_headers:
            return 0

    print("Error: installation incomplete. Found headers: %s. Found libs: %s. install_prefix was %s"
            % (found_headers, found_libs, install_prefix))
    return 1


if __name__ == '__main__':
    sys.exit(main())
