#!/usr/bin/env python3
# coding=utf8

"""
This script reports the sizes of various binary artifacts in CI

(C) 2025 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import os
import sys
import json
import re

def format_size(bytes):
    kB = 1024

    if bytes > kB:
        return "%.02f kB" % (bytes / kB)
    else:
        return "%d bytes" % (bytes)

def report_size(fsname):
    if os.access(fsname, os.R_OK) == False:
        print("ERROR: Could not find %s" % (fsname))
        return
    bytes = os.stat(fsname).st_size
    print("File '%s' is %s" % (fsname, format_size(bytes)))

def main(args = None):
    if args is None:
        args = sys.argv

    if len(args) != 2:
        print("Usage: %s <build_config.json>" % (args[0]))
        return 1

    build_config = json.loads(open(args[1]).read())

    for lib in build_config['library_targets'].split(' '):
        report_size(lib)

    if 'text_exe' in build_config:
        report_size(build_config['test_exe'])

    if 'cli_exe' in build_config:
        report_size(build_config['cli_exe'])

if __name__ == '__main__':
    sys.exit(main())
