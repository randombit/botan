#!/usr/bin/env python3

"""
(C) 2025 Jack Lloyd
Botan is released under the Simplified BSD License (see license.txt)

Compare two JSON files output by `botan speed --format=json` and report
on noticable improvements or regressions in performance.
"""

import json
import optparse # pylint: disable=deprecated-module
import sys
import re

def ops_per_second(events, nanos):
    return (events * 1000000000) / nanos

def format_pct(r):
    assert r > 1
    return "%.01f%%" % ((r - 1) * 100)

def parse_perf_report(report):
    if len(report) == 0:
        print("No report data")
        return None

    version = {'version': 'unknown', 'git': 'unknown'}
    if 'version' in report[0]:
        version = report[0]

        if 'git' in version and version['git'] != 'unknown':
            version['git'] = version['git'][:12]

        report = report[1:]

    results = []
    for t in report:
        if 'algo' in t and 'op' in t and 'events' in t and 'nanos' in t:
            results.append(((t['algo'], t['op']), ops_per_second(t['events'], t['nanos'])))
        else:
            print("Unexpected record", t)

    results = sorted(results, key=lambda r: r[0])
    return (version, results)

def main(args = None):
    if args is None:
        args = sys.argv

    usage = "usage: %prog [options] base.json compare.json"
    parser = optparse.OptionParser(usage=usage)

    parser.add_option('--limit', default=3, help="set reporting limit (as percent)")
    parser.add_option('--filter', default='.*', help="filter results by regex")

    (options, args) = parser.parse_args(args)

    if len(args) != 3:
        print("Usage: compare_perf.py orig.json new.json")
        return 1

    (ver0, rep0) = parse_perf_report(json.loads(open(args[1], encoding='utf8').read()))
    (ver1, rep1) = parse_perf_report(json.loads(open(args[2], encoding='utf8').read()))

    reportable = float(options.limit) / 100
    filter_re = re.compile(options.filter)

    def diff(k, a, b):
        return k in a and k in b and a[k] != b[k] and (a[k] != "unknown" or b[k] != "unknown")

    if ver0 and ver1:
        s = "Diff between "

        diff_version = diff('version', ver0, ver1)
        diff_git = diff('git', ver0, ver1)

        # TODO check/diff the compiler flags

        s += args[1]

        if diff_version or diff_git:
            s += " ("
            if diff_version and diff_git:
                s += ver0['version'] + " " + ver0['git']
            elif diff_version:
                s += ver0['version']
            elif diff_git:
                s += ver0['git']
            s += ")"

        s += " and " + args[2]

        if diff_version or diff_git:
            s += " ("
            if diff_version and diff_git:
                s += ver1['version'] + " " + ver1['git']
            elif diff_version:
                s += ver1['version']
            elif diff_git:
                s += ver1['git']
            s += ")"

        s += "\n"

        print(s)

    data_points = 0
    speedups = 0
    slowdowns = 0
    missing = 0

    while rep0 != [] and rep1 != []:
        while rep0 != [] and rep1 != [] and rep0[0][0] != rep1[0][0]:
            missing += 1
            if rep0[0][0] < rep1[0][0]:
                rep0 = rep0[1:]
            else:
                rep1 = rep1[1:]

        if rep0 != [] and rep1 != []:
            assert rep0[0][0] == rep1[0][0]
            algo = ' '.join(rep0[0][0])

            if filter_re.search(algo) is not None:
                orig = rep0[0][1]
                new = rep1[0][1]

                ratio = new / orig

                data_points += 1

                if ratio >= 1 + reportable:
                    print("+ %s speedup for %s" % (format_pct(ratio), algo))
                    speedups += 1
                elif (orig / new) >= 1 + reportable:
                    print("- %s slowdown for %s" % (format_pct(orig / new), algo))
                    slowdowns += 1

            # go to next
            rep0 = rep0[1:]
            rep1 = rep1[1:]

    if data_points > 0:
        print("\nSummary: over %d tests saw %d speedups and %d slowdowns" % (data_points, speedups, slowdowns))
    else:
        print("\nNo data points")

    if missing > 0:
        print("NOTE: there were %d data points in one set but not the other" % (missing))

if __name__ == '__main__':
    sys.exit(main())
