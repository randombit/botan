#!/usr/bin/env python3

"""
(C) 2016,2025 Jack Lloyd
(C) 2017 Fabian Weissberg, Rohde & Schwarz Cybersecurity

Botan is released under the Simplified BSD License (see license.txt)
"""

import sys
import datetime
import re
from collections import defaultdict

def format_oid(oid):
    return "{" + oid.replace('.', ', ') + '}'

def format_str2oid(m):
    s = ''
    for k in sorted(m.keys()):
        v = m[k]

        if len(s) > 0:
            s += '      '

        s += '{"%s", %s},\n' % (k,format_oid(v))

    s = s[:-2] # chomp last two chars

    return s

def format_dup_oids(m):
    s = ''
    for kv in m:
        if len(s) > 0:
            s += '      '

        s += '{"%s", %s},\n' % (kv[0],format_oid(kv[1]))

    s = s[:-2] # chomp last two chars

    return s

def main(args = None):
    """
    Regenerate src/lib/asn1/oid_maps.cpp
    """
    if args is None:
        args = sys.argv

    oid_lines = open('./src/build-data/oids.txt').readlines()

    oid_re = re.compile(r"^([0-9][0-9.]+) += +([A-Za-z0-9_\./\(\), -]+)$")
    hdr_re = re.compile(r"^\[([a-z0-9_]+)\]$")

    oid2str = {}
    str2oid = {}
    dup_oids = []
    aliases = []

    cur_hdr = None

    for line in oid_lines:
        line = line.strip()
        if len(line) == 0:
            continue

        if line[0] == '#':
            continue

        match = hdr_re.match(line)
        if match is not None:
            cur_hdr = match.group(1)
            continue

        match = oid_re.match(line)
        if match is None:
            raise Exception(line)

        oid = match.group(1)
        nam = match.group(2)

        if nam not in str2oid and oid not in oid2str:
            str2oid[nam] = oid
            oid2str[oid] = nam
        elif nam in str2oid:
            dup_oids.append((nam, oid))
        elif oid in oid2str:
            aliases.append((nam, oid))

    template = open('src/build-data/oid_maps.cpp.in').read()
    new_oid = template % (
        sys.argv[0],
        datetime.date.today().strftime("%Y-%m-%d"),
        format_str2oid(str2oid),
        format_dup_oids(dup_oids),
        format_dup_oids(aliases))

    file = open('src/lib/asn1/oid_maps.cpp', 'w')
    file.write(new_oid)
    file.close()

    return 0

if __name__ == '__main__':
    sys.exit(main())
