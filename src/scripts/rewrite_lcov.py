#!/usr/bin/env python3

"""
(C) 2023 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import sys
import re
import os

def main(args = None):
    if args is None:
        args = sys.argv

    if len(args) != 2:
        print("Usage: %s <lcov_filename>" % (args[0]))
        return 1

    header_re = re.compile(R'^SF:(.*/build/include/(public|internal|external)/botan(/internal)?/.*)')

    new_content = ""

    for line in open(args[1]):
        match = header_re.match(line)
        if match is not None:
            inc_path = match.group(1)

            if not os.path.islink(inc_path):
                print("ERROR %s in lcov but not a symlink" % (inc_path))
                return 1

            new_path = os.path.realpath(inc_path)
            print("Rewrote %s to %s in lcov file" % (inc_path, new_path))
            new_content += "SF:%s\n" % (new_path)
        else:
            new_content += line

    fd = open(args[1], 'w')
    fd.write(new_content)
    fd.close()

    return 0

if __name__ == '__main__':
    sys.exit(main())
