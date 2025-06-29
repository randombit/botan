#!/usr/bin/env python3

"""
(C) 2021,2025 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

"""
NOTE: This script requires the Jinja templating library to be installed.

This script generates the following files

src/lib/pubkey/ec_group/ec_named.cpp
src/lib/math/pcurves/pcurves_instance.h
src/lib/math/pcurves/pcurves.cpp

Additionally if a group is given in ec_groups.txt with an `Impl` that contains
"pcurves", and no pcurves implementation exists on disk, a default version will be
created. This step requires that addchain (https://github.com/mmcloughlin/addchain)
be installed.
"""

import sys
import re
import datetime
import os
import errno
from textwrap import dedent, indent
from jinja2 import Environment, FileSystemLoader
from addchain import addchain_code

def curve_info(src):
    re_kv = re.compile('([A-Za-z]+) = ([0-9A-Za-z-_\\. ]+)')

    current = {}

    for line in src:
        line = line.strip()
        if line == '':
            continue

        kv = re_kv.match(line)
        if kv is None:
            raise Exception('Unknown line', line)

        key = kv.group(1)
        val = kv.group(2)

        if key in ['Name']:
            current[key] = val
        elif key in ['OID', 'Impl']:
            current[key] = val.split(' ')
        elif key in ['A']:
            if val == '-3':
                current[key] = current['P'] - 3
            else:
                current[key] = int(val, 16)
        elif key in ['P', 'B', 'X', 'Y', 'N']:
            current[key] = int(val, 16)

        if key == 'N':
            current["N32"] = current["N"] & 0xFFFFFFFF
            current["OIDExpr"] = ['OID{%s}' % (oid.replace('.', ', ')) for oid in current['OID']]
            yield current
            current = {}

def format_names(names):
    # This would be quite complicated to render in the Jinja template language so
    # we pre-render it as a string and insert it directly
    legacy = []
    generic = []
    pcurves = []
    pcurves_no_generic = []

    for (nm, impl) in names:
        if 'pcurve' in impl:
            pcurves.append(nm)
            if 'generic' not in impl:
                pcurves_no_generic.append(nm)
        elif 'generic' in impl:
            generic.append(nm)
        else:
            assert 'legacy' in impl
            legacy.append(nm)

    legacy_macro = "defined(BOTAN_HAS_LEGACY_EC_POINT)"
    generic_macro = "defined(BOTAN_HAS_PCURVES_GENERIC)"
    for nm in sorted(pcurves):
        nm_macro = "BOTAN_HAS_PCURVES_%s" % (nm.upper())

        if nm in pcurves_no_generic:
            yield "#if defined(%s) || %s" % (nm_macro, legacy_macro)
            yield "      // Not supported by pcurves_generic"
        else:
            yield "#if defined(%s) || %s || %s" % (nm_macro, legacy_macro, generic_macro)
        yield '      \"%s\",' % (nm)
        yield "#endif\n"

    yield "#if %s || %s" % (legacy_macro, generic_macro)
    for nm in sorted(generic):
        yield '      \"%s\",' % (nm)
    yield "#endif\n"

    yield "#if %s" % (legacy_macro)
    for nm in sorted(legacy):
        yield '      \"%s\",' % (nm)
    yield "#endif\n"

def datestamp():
    current_date = datetime.datetime.now()
    return int(current_date.strftime("%Y%m%d"))

class OmitFirstLine:
    def __init__(self):
        self.first_line = True

    def __call__(self, l):
        r = not self.first_line
        self.first_line = False
        return r

def main():
    curves = [c for c in curve_info(open('./src/build-data/ec_groups.txt'))]

    pcurves = []
    for c in curves:
        if 'pcurve' in c['Impl']:
            pcurves.append(c)

    this_script = sys.argv[0]
    date = datetime.date.today().strftime("%Y-%m-%d")

    env = Environment(loader=FileSystemLoader("src/build-data/templates"))

    # write ec_named.cpp
    with open('./src/lib/pubkey/ec_group/ec_named.cpp', encoding='utf8', mode='w') as ec_named:
        template = env.get_template("ec_named.cpp.in")

        named_groups = "\n".join(format_names([(c['Name'], c['Impl']) for c in curves]))

        ec_named.write(template.render(script=this_script, date=date, curves=curves, named_groups=named_groups.strip()))
        ec_named.write("\n")

    # write pcurves_instance.h
    with open('./src/lib/math/pcurves/pcurves_instance.h', encoding='utf8', mode='w') as pcurves_h:
        template = env.get_template("pcurves_instance.h.in")
        pcurves_h.write(template.render(script=this_script, date=date, pcurves=pcurves))
        pcurves_h.write("\n")

    # write pcurves.cpp
    with open('./src/lib/math/pcurves/pcurves.cpp', encoding='utf8', mode='w') as pcurves_cpp:
        template = env.get_template("pcurves.cpp.in")
        pcurves_cpp.write(template.render(script=this_script, date=date, pcurves=pcurves))
        pcurves_cpp.write("\n")

    # Check if any pcurves modules need a new stub impl
    for pcurve in pcurves:
        curve = pcurve["Name"]
        mod_dir = './src/lib/math/pcurves/pcurves_%s' % (curve)
        info_path = os.path.join(mod_dir, 'info.txt')
        impl_path = os.path.join(mod_dir, f'pcurves_{curve}.cpp')

        if os.access(impl_path, os.R_OK):
            continue

        addchain_fe2 = addchain_code(pcurve['P'] - 3, 0)
        addchain_fe_sqrt = addchain_code((pcurve['P'] + 1) // 4, 0) if pcurve['P'] % 4 == 3 else None
        addchain_scalar = addchain_code(pcurve['N'] - 2, 0)

        try:
            os.makedirs(mod_dir)
        except OSError as ex:
            if ex.errno != errno.EEXIST:
                raise

        module_define = f"PCURVES_{curve.upper()}"
        if not re.match('^[0-9A-Za-z_]{3,30}$', module_define):
            raise ValueError(f"Invalid preprocessor define name ({module_define}) for new pcurve module")

        with open(info_path, 'w', encoding='utf8') as info_file:
            info_file.write(dedent(f"""\
                <defines>
                {module_define} -> {datestamp()}
                </defines>

                <module_info>
                name -> "PCurve {curve}"
                </module_info>

                <requires>
                pcurves_impl
                </requires>
            """))

        with open(impl_path, 'w', encoding='utf8') as src_file:
            crandall = (1 << pcurve["P"].bit_length()) - pcurve["P"]
            if crandall > 2**32:
                crandall = 0

            template = env.get_template("pcurves_stub.cpp.in")
            src_file.write(template.render(curve = pcurve,
                                           crandall=crandall,
                                           addchain_fe2=indent(addchain_fe2, 9 * ' ', OmitFirstLine()),
                                           addchain_fe_sqrt=indent(addchain_fe_sqrt, 9 * ' ', OmitFirstLine()) if addchain_fe_sqrt else None,
                                           addchain_scalar=indent(addchain_scalar, 9 * ' ', OmitFirstLine())))
            src_file.write("\n")


    return 0

if __name__ == '__main__':
    sys.exit(main())
