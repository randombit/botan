#!/usr/bin/env python3
# coding=utf8

"""
Botan CI check headers script

(C) 2023 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import sys
import os
import json
import re

def main(args=None):
    if args is None:
        args = sys.argv

    if len(args) < 2:
        print("Usage: %s <build_config.json>" % args[0])
        return 1

    with open(os.path.join(args[1]), encoding='utf8') as f:
        build_config = json.load(f)

        public_include_dir = build_config['public_include_path']
        internal_include_dir = build_config['internal_include_path']

        internal_inc = re.compile(r'#include <botan/(internal/.*)>')

        for header in build_config['public_headers']:
            contents = open(os.path.join(public_include_dir, header), encoding='utf8').read()

            match = internal_inc.search(contents)
            if match:
                print("ERROR: Public header '%s' includes an internal header '%s'" % (header, match.group(1)))
                return 1


        all_headers = build_config['public_headers'] + build_config['internal_headers']
        header_guard = re.compile(r'\n#define BOTAN_([A-Z0-9_]{3,})_H_\n')
        header_guards = {}

        for header in all_headers:

            if header in build_config['public_headers']:
                path = os.path.join(public_include_dir, header)
            else:
                path = os.path.join(internal_include_dir, header)

            contents = open(path, encoding='utf8').read()

            match = header_guard.search(contents)
            if not match:
                print("ERROR: Header '%s' is missing an appropriate header guard" % (header))
                return 1

            guard = match.group(1)
            if guard in header_guards:
                print("ERROR: Duplicate header guard (%s) in '%s' and '%s'" % (guard, header, header_guards[guard]))
                return 1
            else:
                header_guards[guard] = header

    return 0

if __name__ == '__main__':
    sys.exit(main())
