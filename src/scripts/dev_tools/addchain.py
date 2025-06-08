#!/usr/bin/env python3

# (C) 2024 Jack Lloyd
#
# Botan is released under the Simplified BSD License (see license.txt)

"""
Runs https://github.com/mmcloughlin/addchain and formats
the code suitable for pcurves
"""

import sys
import subprocess

def addchain_gen(n):
    search = subprocess.Popen(['addchain', 'search', str(n)],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)

    (stdout, stderr) = search.communicate()

    gen = subprocess.Popen(['addchain', 'gen'],
                           stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)

    gen.stdin.write(stdout)

    (stdout, stderr) = gen.communicate()

    return stdout.decode('utf8').split('\n')

def addchain_code(n, indent=3):
    vars = set([])

    output = []

    for line in addchain_gen(n):
        if line == '':
            continue
        c = line.strip().split()

        if c[0] == 'tmp':
            continue

        decl = '' if c[1] in vars else 'auto '

        if c[0] == 'double':
            assert(len(c) == 3)
            output.append("%s%s = %s.square()" % (decl, c[1], c[2]))
            vars.add(c[1])
        elif c[0] == 'add':
            assert(len(c) == 4)
            if c[1] == c[2]:
                output.append("%s *= %s" % (c[1], c[3]))
            elif c[1] == c[3]:
                output.append("%s *= %s" % (c[1], c[2]))
            else:
                if c[2] < c[3]:
                    output.append("%s%s = %s * %s" % (decl, c[1], c[2], c[3]))
                else:
                    output.append("%s%s = %s * %s" % (decl, c[1], c[3], c[2]))
            vars.add(c[1])
        elif c[0] == 'shift':

            assert(len(c) == 4)
            if c[1] != c[2]:
                output.append("%s%s = %s" % (decl, c[1], c[2]))
            output.append("%s.square_n(%s)" % (c[1], c[3]))
            vars.add(c[1])
        else:
            raise Exception("Don't know what to do with %s" % (c[0]))

    output.append('return z')

    ws = " " * indent
    return '\n'.join(['%s%s;' % (ws, l) for l in output])

def main(args = None):
    if args is None:
        args = sys.argv
    if len(args) != 2:
        print("Usage: %s <n>" % (args[0]))
        return 1

    n = int(args[1], 0)
    print(addchain_code(n))
    return 0

if __name__ == '__main__':
    sys.exit(main())
