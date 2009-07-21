#!/usr/bin/python

"""
Analyze the botan source tree and print the module interdependencies

(C) 2009 Jack Lloyd
Distributed under the terms of the Botan license
"""

import os
import os.path
import sys
import re

def find_deps_in(filename):
    # By convention #include's with spaces before them are
    # always wrapped in #ifdef blocks
    regexp = re.compile('^#include <botan/(.*)>')

    for line in open(filename).readlines():
        match = regexp.match(line)
        if match != None:
            yield match.group(1)

def get_dependencies(dirname):
    all_dirdeps = {}
    file_homes = {}

    is_sourcefile = re.compile('\.(cpp|h|S)$')

    for (dirpath, dirnames, filenames) in os.walk('src'):
        dirdeps = set()
        for filename in filenames:
            if is_sourcefile.search(filename) != None:
                file_homes[filename] = os.path.basename(dirpath)

                for dep in find_deps_in(os.path.join(dirpath, filename)):
                    if dep not in filenames and dep != 'build.h':
                        dirdeps.add(dep)

        dirdeps = sorted(dirdeps)
        if dirdeps != []:
            all_dirdeps[dirpath] = dirdeps

    return (all_dirdeps, file_homes)

def main():
    (all_dirdeps, file_homes) = get_dependencies('src')

    def interesting_dep_for(dirname):
        def interesting_dep(dep):
            if dep == 'utils':
                return False # everything depends on it

            # block/serpent depends on block, etc
            if dirname.find('/%s/' % (dep)) > 0:
                return False
            return True
        return interesting_dep

    for dirname in sorted(all_dirdeps.keys()):
        depdirs = sorted(set(map(lambda x: file_homes[x], all_dirdeps[dirname])))

        depdirs = filter(interesting_dep_for(dirname), depdirs)

        if depdirs != []:
            print "%s: %s" % (dirname, ' '.join(depdirs))

if __name__ == '__main__':
    sys.exit(main())
