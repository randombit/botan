#!/usr/bin/env python3

"""
(C) 2021 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import sys
import re
import datetime

def curve_info(src):
    re_kv = re.compile('([A-Za-z]+) = ([0-9A-Za-z-_\. ]+)')

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
        elif key in ['OID']:
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
    if x.bit_length() <= 5:
        return str(x)
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
    for nm in sorted(names):
        yield '      \"%s\",' % (nm)

def format_orders(orders):
    template_str = """   if(low_bits == %s && order == BigInt("%s")) {\n      return OID{%s};\n   }\n""";

    orders_seen = set([])

    for (order,oid) in orders:
        low_bits = hex(order & 0xFFFFFFFF).upper().replace('0X', '0x')
        order = format_int(order)
        if order in orders_seen:
            raise Exception("Duplicate EC group order %s" % (order))
        orders_seen.add(order)
        oid = oid[0].replace('.', ', ')
        yield template_str % (low_bits, order, oid)

def main():
    curves = [c for c in curve_info(open('./src/build-data/ec_groups.txt'))]

    template_str = open('./src/build-data/ec_named.cpp.in').read()

    names = "\n".join(format_names([c['Name'] for c in curves]))
    orders = "\n".join(format_orders([(c['N'], c['OID']) for c in curves]))
    curves = '\n'.join([print_curve(curve) for curve in curves])
    this_script = sys.argv[0]
    today = datetime.date.today().strftime("%Y-%m-%d")

    print(template_str % (this_script, today, curves, orders, names), end='')
    return 0

if __name__ == '__main__':
    sys.exit(main())
