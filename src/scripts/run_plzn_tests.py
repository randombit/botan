#!/usr/bin/env python3

"""
Runs the plzn TLS/DTLS conformance suite against Botan's plzn shim and
summarizes the outcome.

plzn (https://github.com/randombit/plzn) drives the shim built from
src/plzn_shim with its own adversarial TLS stack. This script runs it in
--json mode, tallies every case, prints the unexpected results (failures,
shim crashes, and unexpected passes of tests expected to fail) in full,
and exits nonzero if there were any. Expected failures and skips are
counted but do not affect the exit status; local expectations live in
src/plzn_shim/expectations.json

(C) 2026 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import json
import optparse  # pylint: disable=deprecated-module
import os
import subprocess
import sys
from collections import defaultdict

UNEXPECTED_STATUSES = ['fail', 'crash', 'xpass']
EXPECTED_STATUSES = ['pass', 'skip', 'xfail']

def is_running_in_github_actions():
    return os.environ.get("GITHUB_ACTIONS", "false") == "true"

def gha_escape(msg):
    return msg.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')

def gha_annotation(level, title, msg):
    if is_running_in_github_actions():
        print("::%s title=%s::%s" % (level, gha_escape(title), gha_escape(msg)))

class LogGroup:
    """
    Collapsible section in the GitHub Actions log; a plain heading elsewhere
    """

    def __init__(self, title):
        self.title = title

    def __enter__(self):
        if is_running_in_github_actions():
            print("::group::%s" % (self.title))
        else:
            print("--- %s ---" % (self.title))

    def __exit__(self, exc_type, exc_value, exc_tb):
        if is_running_in_github_actions():
            print("::endgroup::")

def one_line(status, rec):
    desc = "[%s] %s" % (status.upper(), rec.get('test_id', '?'))
    if 'reason' in rec:
        desc += ": %s" % (rec['reason'])
    return desc

def describe_case(rec):
    """
    Everything plzn knows about a case that did not go as expected
    """
    status = rec.get('status', '?')
    lines = [one_line(status, rec)]

    what = [rec.get(k) for k in ['protocol', 'version', 'uut'] if rec.get(k)]
    if what:
        lines.append("   %s" % (' '.join(what)))

    for key in ['classification', 'expected', 'observed', 'error']:
        if rec.get(key) and rec[key] != 'test':
            lines.append("   %s: %s" % (key, rec[key]))

    for step in rec.get('steps', []):
        if step.get('status') == 'failed':
            lines.append("   step %s (%s) failed: %s" % (step.get('index'), step.get('description'), step.get('error')))

    shim = rec.get('shim')
    if shim:
        if shim.get('exit'):
            lines.append("   shim: %s" % (shim['exit']))
        stderr = (shim.get('stderr') or '').strip()
        if stderr:
            lines.append("   shim stderr:")
            lines.extend("      %s" % (line) for line in stderr.splitlines())

    return '\n'.join(lines)

def plzn_command(options, paths):
    cmd = [options.plzn, 'run', '--json', '--shim', options.shim]
    if options.jobs is not None:
        cmd += ['--jobs', str(options.jobs)]
    if options.cert is not None:
        cmd += ['--cert', options.cert]
    return cmd + paths

def run_plzn(cmd, verbose):
    """
    Runs plzn and returns (exit code, case records keyed by status, summary record)
    """
    print("Running '%s'" % (' '.join(cmd)))
    sys.stdout.flush()

    # plzn keeps its NDJSON stream on stdout; shim and runner diagnostics stay on stderr
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)

    cases = defaultdict(list)
    summary = None

    for raw_line in proc.stdout:
        line = raw_line.decode('utf8', errors='replace').rstrip('\n')
        if not line:
            continue

        try:
            rec = json.loads(line)
        except ValueError:
            print(line)
            continue

        rec_type = rec.get('type')
        if rec_type == 'summary':
            summary = rec
        elif rec_type == 'case':
            status = rec.get('status', 'unknown')
            cases[status].append(rec)
            if status in UNEXPECTED_STATUSES:
                print(describe_case(rec))
                gha_annotation('error', 'plzn %s' % (status), describe_case(rec))
                sys.stdout.flush()
            elif verbose:
                print(one_line(status, rec))
        else:
            print(line)

    return proc.wait(), cases, summary

def print_grouped(title, recs):
    """
    List cases grouped by their reason so the same skip is not spelled out N times
    """
    by_reason = defaultdict(list)
    for rec in recs:
        by_reason[rec.get('reason') or rec.get('error') or '(no reason given)'].append(rec.get('test_id', '?'))

    with LogGroup("%s (%d)" % (title, len(recs))):
        for reason, ids in sorted(by_reason.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            print("%d %s" % (len(ids), reason))
            for test_id in sorted(ids):
                print("   %s" % (test_id))

def main(args=None):
    if args is None:
        args = sys.argv

    parser = optparse.OptionParser(usage='%prog [options] <suite dir or .plzn file>...')

    parser.add_option('--plzn', metavar='PATH', default='plzn',
                      help='plzn binary to run (default: %default from PATH)')
    parser.add_option('--shim', metavar='PATH', default=os.path.join('.', 'botan_plzn_shim'),
                      help='shim binary built from src/plzn_shim (default %default)')
    parser.add_option('--jobs', metavar='N', type='int', default=None,
                      help='run N cases concurrently (default: plzn decides)')
    parser.add_option('--cert', metavar='TYPE', default=None,
                      help='certificate chain used by tests with `chain: [default]` (default: ecdsa)')
    parser.add_option('--verbose', action='store_true', default=False,
                      help='print every case, and list skips and expected failures')

    (options, args) = parser.parse_args(args)

    paths = args[1:]
    if not paths:
        parser.print_usage()
        return 2

    if not os.access(options.shim, os.X_OK):
        print("Shim %s is not executable; build with --build-targets=plzn_shim" % (options.shim))
        return 2

    exit_code, cases, summary = run_plzn(plzn_command(options, paths), options.verbose)

    counts = {status: len(cases.get(status, [])) for status in EXPECTED_STATUSES + UNEXPECTED_STATUSES}
    unknown = sorted(set(cases.keys()) - set(counts.keys()))
    total = sum(len(recs) for recs in cases.values())

    problems = []

    if summary is None:
        problems.append("plzn did not produce a summary record")
    elif summary.get('aborted'):
        problems.append("plzn aborted the run (consecutive shim crashes)")
    if exit_code != 0:
        problems.append("plzn exited with code %d" % (exit_code))
    if unknown:
        problems.append("unknown case status(es): %s" % (', '.join(unknown)))

    unexpected = [rec for status in UNEXPECTED_STATUSES for rec in cases.get(status, [])]

    duration = ''
    if summary and 'duration_ns' in summary:
        duration = ' in %.1fs' % (summary['duration_ns'] / 1e9)
    backend = summary.get('backend', 'botan') if summary else 'botan'

    print()
    print("plzn ran %d tests against %s%s" % (total, backend, duration))
    print("   passed %d, skipped %d, xfailed %d, xpassed %d, failed %d, crashed %d" % (
        counts['pass'], counts['skip'], counts['xfail'], counts['xpass'], counts['fail'], counts['crash']))

    # The skip and xfail lists are what to audit when wondering what the run
    # really covered; collapsed in CI, on request locally
    if is_running_in_github_actions() or options.verbose:
        if counts['skip'] > 0:
            print_grouped('skipped', cases['skip'])
        if counts['xfail'] > 0:
            print_grouped('expected failures', cases['xfail'])

    if unexpected:
        print()
        print("%d unexpected result(s):" % (len(unexpected)))
        for rec in unexpected:
            print("   %s" % (one_line(rec.get('status', '?'), rec)))

    for problem in problems:
        print(problem)
        gha_annotation('error', 'plzn', problem)

    if unexpected or problems:
        return 1

    return 0

if __name__ == '__main__':
    sys.exit(main())
