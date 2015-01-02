#!/usr/bin/python

"""
(C) 2014 Jack Lloyd

Distributed under the terms of the Botan license
"""

import re
import sys
import os

def combine_relnotes(relnote_dir, with_rst_labels):

    relnotes = [p for p in os.listdir(relnote_dir) if p.startswith(('0', '1', '2'))]

    re_version = re.compile('Version (\d+\.\d+\.\d+), ([0-9]{4}-[0-9]{2}-[0-9]{2})$')
    re_nyr = re.compile('Version (\d+\.\d+\.\d+), Not Yet Released$')

    version_contents = {}
    version_date = {}
    versions = []
    versions_nyr = []

    for f in relnotes:
        contents = open(os.path.join(relnote_dir, f)).readlines()

        match = re_version.match(contents[0])

        if match:
            version = match.group(1)
            date = match.group(2)
            versions.append(version)
            version_date[version] = date
        else:
            match = re_nyr.match(contents[0])
            version = match.group(1)

            versions_nyr.append(version)
            if not match:
                raise Exception('No version match for %s' % (f))

        version_contents[version] = (''.join(contents)).strip()

    def make_label(v):
        if with_rst_labels:
            return ".. _v%s:\n\n" % (v.replace('.', '_'))
        else:
            return ''

    s = ''

    s += "Release Notes\n"
    s += "========================================\n"
    s += "\n"

    date_to_version = {}
    for (v,d) in version_date.items():
        date_to_version.setdefault(d, []).append(v)

    if len(versions_nyr) > 0:
        for v in versions_nyr:
            s += make_label(v)
            s += version_contents[v]
            s += "\n\n"

    for d in sorted(date_to_version.keys(), reverse=True):
        for v in sorted(date_to_version[d]):
            s += make_label(v)
            s += version_contents[v]
            s += "\n\n"

    return s

def main(args = None):
    if args is None:
        args = sys.argv

    print combine_relnotes(args[1], True)

if __name__ == '__main__':
    sys.exit(main())
