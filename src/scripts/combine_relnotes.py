#!/usr/bin/python

import re
import sys

def main(args = None):
    if args is None:
        args = sys.argv

    re_version = re.compile('Version (\d+\.\d+\.\d+), ([0-9]{4}-[0-9]{2}-[0-9]{2})$')
    re_nyr = re.compile('Version (\d+\.\d+\.\d+), Not Yet Released$')

    version_contents = {}
    version_date = {}
    versions = []
    versions_nyr = []

    for f in args[1:]:
        contents = open(f).readlines()

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
        return ".. _v%s:\n" % (v.replace('.', '_'))

    print "Release Notes"
    print "========================================"
    print

    date_to_version = {}
    for (v,d) in version_date.items():
        date_to_version.setdefault(d, []).append(v)

    if len(versions_nyr) > 0:
        for v in versions_nyr:
            print make_label(v)
            print version_contents[v], "\n"

    for d in sorted(date_to_version.keys(), reverse=True):
        for v in sorted(date_to_version[d]):
            print make_label(v)
            print version_contents[v], "\n"

if __name__ == '__main__':
    sys.exit(main())
