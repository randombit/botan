#!/usr/bin/env python3

"""
(C) 2016,2025 Jack Lloyd
(C) 2017 Fabian Weissberg, Rohde & Schwarz Cybersecurity

Botan is released under the Simplified BSD License (see license.txt)

NOTE: This script requires the Jinja templating library to be installed.
"""

import sys
import datetime
import re
from jinja2 import Environment, FileSystemLoader

# This must match OID::hash_code
def hash_oid(oid):
    word_size = 2 ** 64
    h = 0x621F302327D9A49A

    for part in map(int, oid.split('.')):
        h = (h * 193) % word_size
        h += part

    # This reduction step occurs in static_oids.cpp.in
    return h % 858701

# This must match hash_oid_name in static_oids.cpp.in
def hash_oid_name(name):
    word_size = 2 ** 64

    h = 0x8188B31879A4879A

    for part in map(ord, name):
        h = (h * 251) % word_size
        h += part

    return h % 805289

def format_oid(oid):
    return '{' + oid.replace('.', ', ') + '}'

def render_static_oid(m):
    res = []

    name_hashes = {}
    oid_hashes = {}

    for (k, v) in m.items():

        # Verify no collsions between any of the values
        oid_hc = hash_oid(v)
        if oid_hc in oid_hashes:
            raise Exception("Hash collision between %s and %s" % (v, oid_hashes[oid_hc]))
        oid_hashes[oid_hc] = v

        name_hc = hash_oid_name(k)
        if name_hc in name_hashes:
            raise Exception("Hash collision between %s and %s" % (k, name_hashes[name_hc]))
        name_hashes[name_hc] = k

        res.append({ 'oid_hash': oid_hc,
                     'name_hash': name_hc,
                     'name': k,
                     'oid': format_oid(v) })

    return res

def format_oid_with_name(m):
    return [ {'name': kv[0], 'oid': format_oid(kv[1])} for kv in m ]

def main(args = None):
    """
    Regenerate src/lib/asn1/static_oids.cpp
    """
    if args is None:
        args = sys.argv

    oid_lines = open('./src/build-data/oids.txt', encoding='utf8').readlines()

    oid_re = re.compile(r"^([0-9][0-9.]+) += +([A-Za-z0-9_\./\(\), -]+)$")
    hdr_re = re.compile(r"^\[([a-z0-9_]+)\]$")

    oid2str = {}
    str2oid = {}
    dup_oids = []
    aliases = []

    for line in oid_lines:
        line = line.strip()
        if len(line) == 0:
            continue

        if line[0] == '#':
            continue

        match = hdr_re.match(line)
        if match is not None:
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

    this_script = sys.argv[0]
    date = datetime.date.today().strftime("%Y-%m-%d")

    env = Environment(loader=FileSystemLoader("src/build-data/templates"))

    with open('./src/lib/asn1/static_oids.cpp', encoding='utf8', mode='w') as static_oids:
        template = env.get_template("static_oids.cpp.in")
        static_oids.write(template.render(script=this_script,
                                          date=date,
                                          static_oid_data=render_static_oid(str2oid),
                                          dup_oids=format_oid_with_name(dup_oids),
                                          aliases=format_oid_with_name(aliases)))
        static_oids.write("\n")

    return 0

if __name__ == '__main__':
    sys.exit(main())
