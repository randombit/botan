#!/usr/bin/python

# (C) 2018 Jack Lloyd
# Botan is released under the Simplified BSD License (see license.txt)

# Scans all source and test files and makes sure we are not using a
# BOTAN_HAS_xxx macro which is not actually defined anywhere.

from configure import ModuleInfo, load_info_files
import os
import re
import logging

src_dir = 'src'
lib_dir = os.path.join(src_dir, 'lib')

info_modules = load_info_files(lib_dir, 'Modules', "info.txt", ModuleInfo)

all_defines = set()

for module in info_modules.values():
    for define in module._defines:
        all_defines.add(define)

extras = ['MP_DWORD', 'VALGRIND', 'SANITIZER_UNDEFINED',
          'ONLINE_REVOCATION_CHECKS', 'NIST_PRIME_REDUCERS_W32']

for extra in extras:
    all_defines.add(extra)

macro = re.compile('BOTAN_HAS_([A-Z0-9_]+)')

for dirname, subdirs, files in os.walk(src_dir):
    for fname in files:
        if fname.endswith('.h') or fname.endswith('.cpp'):
            contents = open(os.path.join(dirname, fname)).read()

            for m in re.finditer(macro, contents):

                if m.group(1) not in all_defines:
                    logging.error('In %s found unknown feature macro %s' % (fname, m.group(1)))

