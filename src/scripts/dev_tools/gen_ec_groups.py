#!/usr/bin/env python3

"""
(C) 2021,2025 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import sys
import re
import datetime

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
            yield current
            current = {}

def format_int(x):
    return hex(x).upper().replace('0X', '0x')

def print_curve(curve):
    template_str = """   // %s
   if(%s) {
      return load_EC_group_info(
         "%s",
         "%s",
         "%s",
         "%s",
         "%s",
         "%s",
         %s);
   }
"""

    name = curve['Name']
    oids = ['OID{%s}' % (oid.replace('.', ', ')) for oid in curve['OID']]
    p = format_int(curve['P'])
    a = format_int(curve['A'])
    b = format_int(curve['B'])
    x = format_int(curve['X'])
    y = format_int(curve['Y'])
    n = format_int(curve['N'])

    oid_match = ' || '.join(['oid == %s' % oid for oid in oids])

    pref_oid = 'oid' if len(oids) == 1 else oids[0]

    return template_str % (name, oid_match, p, a, b, x, y, n, pref_oid)

def format_names(names):
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

def format_orders(orders):
    template_str = """   if(low_bits == 0x%08X && order == BigInt("%s")) {\n      return OID{%s};\n   }\n""";

    orders_seen = set([])

    for (order,oid) in orders:
        low_bits = order & 0xFFFFFFFF
        order = format_int(order)
        if order in orders_seen:
            raise Exception("Duplicate EC group order %s" % (order))
        orders_seen.add(order)
        oid = oid[0].replace('.', ', ')
        yield template_str % (low_bits, order, oid)

def main():
    curves = [c for c in curve_info(open('./src/build-data/ec_groups.txt'))]

    template_str = open('./src/build-data/ec_named.cpp.in').read()

    names = "\n".join(format_names([(c['Name'], c['Impl']) for c in curves]))
    orders = "\n".join(format_orders([(c['N'], c['OID']) for c in curves]))
    curves = '\n'.join([print_curve(curve) for curve in curves])
    this_script = sys.argv[0]
    today = datetime.date.today().strftime("%Y-%m-%d")

    print(template_str % (this_script, today, curves, orders, names.strip()), end='')
    return 0

if __name__ == '__main__':
    sys.exit(main())
