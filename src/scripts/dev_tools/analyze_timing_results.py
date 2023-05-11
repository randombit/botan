#!/usr/bin/env python3

"""
(C) 2023 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import re
import sys
import numpy

def compute_stats_for(nm, results):
    return {
        'name': nm,
        'count': len(results),
        'mean': numpy.mean(results),
        'median': numpy.median(results),
        'min': min(results),
        'max': max(results),
        'stddev': numpy.std(results),
        '99pct': numpy.percentile(results, 99),
        '90pct': numpy.percentile(results, 90)
        }

def main(args = None):
    if args is None:
        args = sys.argv

    if len(args) != 2:
        print("Usage: %s <filename>" % (args[0]))
        return 1

    timing_line = re.compile('([0-9]+);([0-9]+);([0-9]+)')

    key_ids = set([])
    results = {}

    for line in open(args[1]):
        match = timing_line.match(line)
        if match is None:
            print("Failed to match on '%s'" % (line))

        cnt = int(match.group(1))
        id = int(match.group(2))
        time = int(match.group(3))

        key_ids.add(id)
        results.setdefault(id, []).append(time)

    stats = {}

    for id in key_ids:
        s = compute_stats_for("secret %d" % (id), results[id])
        print("%d: min=%.02f max=%.02f mean=%.02f median=%.02f std=%.02f 90pct=%.02f 99pct=%.02f" % (
            id, s['min'], s['max'], s['mean'], s['median'], s['stddev'], s['90pct'], s['99pct']))
        stats[id] = s

    for field in ['mean', 'median', 'min', 'max', 'stddev', '90pct', '99pct']:

        res = []
        for id in key_ids:
            res.append(stats[id][field])

        range = max(res) - min(res)

        print("range of %s: %.02f (%.02f - %.02f)" % (field, range, min(res), max(res)))

if __name__ == '__main__':
    sys.exit(main())
