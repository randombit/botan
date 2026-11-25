#!/usr/bin/env python3

"""
Runs the plzn TLS/DTLS conformance suite against Botan's plzn shim and
summarizes the outcome.

plzn (https://github.com/randombit/plzn) drives the shim built from
src/plzn_shim with its own adversarial TLS stack. This script runs it in
--json mode, tallies every case, reports the unexpected results (failures,
shim crashes, and unexpected passes of tests expected to fail) in full,
grouped by how they went wrong, and exits nonzero if there were any.
Expected failures and skips are counted but do not affect the exit status;
local expectations live in src/plzn_shim/expectations.json

(C) 2026 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import json
import optparse  # pylint: disable=deprecated-module
import os
import re
import subprocess
import sys
from collections import defaultdict

UNEXPECTED_STATUSES = ['fail', 'crash', 'xpass']
EXPECTED_STATUSES = ['pass', 'skip', 'xfail']

# GitHub Actions displays at most this many error annotations per step
MAX_GHA_ANNOTATIONS = 10

# Test ids listed per annotation; the log has all of them
MAX_IDS_PER_ANNOTATION = 10

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

def find_test_sources(paths):
    """
    Map the name of each test declared in the given .plzn files or directories to (file, line)
    """
    decl = re.compile(r'^\s*plzn\s+(?:tls|dtls)\s+"([^"]+)"')

    files = []
    for path in paths:
        if os.path.isdir(path):
            for root, _, names in os.walk(path):
                files += [os.path.join(root, name) for name in sorted(names) if name.endswith('.plzn')]
        else:
            files.append(path)

    sources = {}
    for path in files:
        try:
            with open(path, encoding='utf8') as f:
                for lineno, line in enumerate(f, 1):
                    match = decl.match(line)
                    if match:
                        sources[match.group(1)] = (path, lineno)
        except (OSError, UnicodeDecodeError):
            pass
    return sources

def test_source(sources, rec):
    # Matrix cases append "[binding,...]" to the declared name, multi-session tests ":session"
    return sources.get(re.split(r'[\[:]', rec.get('test_id', ''), maxsplit=1)[0])

def signature(rec):
    """
    How a case went wrong, as (status, what), leaving out anything specific
    to the case so that results with a common cause are reported together
    """
    status = rec.get('status', '?').upper()
    shim_exit = (rec.get('shim') or {}).get('exit')

    if status == 'CRASH' and shim_exit:
        return (status, "shim %s" % (shim_exit))
    if status == 'XPASS' and rec.get('reason'):
        return (status, "passed, but expected to fail: %s" % (rec['reason']))
    if rec.get('expected') or rec.get('observed'):
        return (status, "expected `%s`, observed `%s`" % (rec.get('expected', '?'), rec.get('observed', '?')))
    for key in ['error', 'reason']:
        if rec.get(key):
            return (status, rec[key])
    if shim_exit:
        return (status, "shim %s" % (shim_exit))
    return (status, "no details reported")

def indented(prefix, text):
    return ["%s%s" % (prefix, line) for line in text.splitlines()]

def describe_case(rec, sources):
    """
    Everything plzn reports about a case beyond its signature()
    """
    (_, what) = signature(rec)
    lines = [one_line(rec.get('status', '?'), rec)]

    source = test_source(sources, rec)
    if source:
        lines.append("   at %s:%d" % source)

    context = [' '.join(rec[k] for k in ['version', 'uut'] if rec.get(k))]
    context = [c for c in context if c]
    if rec.get('classification') and rec['classification'] != 'test':
        context.append(rec['classification'])
    if 'duration_ns' in rec:
        context.append("%.1f ms" % (rec['duration_ns'] / 1e6))
    if context:
        lines.append("   %s" % (', '.join(context)))

    for key in ['expected', 'observed']:
        if rec.get(key) and "`%s`" % (rec[key]) not in what:
            lines.append("   %s: %s" % (key, rec[key]))

    # plzn's error for an expectation mismatch just restates expected and observed
    error = rec.get('error') or ''
    restates = rec.get('expected') and rec.get('observed') and rec['expected'] in error and rec['observed'] in error
    if error and error not in what and not restates:
        lines += indented("   error: ", error)

    suite = rec.get('negotiated_cipher_suite')
    if suite:
        lines.append("   negotiated: %s" % (suite.get('name') or suite.get('hex')))

    if rec.get('steps'):
        lines.append("   steps:")
        for step in rec['steps']:
            lines.append("      %d. %-7s %s" % (step.get('index', -1), step.get('status', '?'), step.get('description', '')))
            if step.get('error'):
                lines += indented("            ", step['error'])

    shim = rec.get('shim')
    if shim:
        if shim.get('exit') and shim['exit'] not in what:
            lines.append("   shim: %s" % (shim['exit']))
        for stream in ['stdout', 'stderr']:
            # The PLZN-RESULT line is what plzn turned into the exit description above
            output = [l for l in (shim.get(stream) or '').splitlines() if l.strip() and not l.startswith('PLZN-RESULT ')]
            if output:
                lines.append("   shim %s:" % (stream))
                lines += ["      %s" % (l) for l in output]

    return '\n'.join(lines)

def plzn_command(options, paths):
    cmd = [options.plzn, 'run', '--json', '--shim', options.shim]
    if options.jobs is not None:
        cmd += ['--jobs', str(options.jobs)]
    if options.cert is not None:
        cmd += ['--cert', options.cert]
    return cmd + paths

def rerun_command(options, paths):
    cmd = [options.plzn, 'run', '--shim', options.shim]
    if options.cert is not None:
        cmd += ['--cert', options.cert]
    return ' '.join(cmd + paths)

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
            if verbose:
                print(one_line(status, rec))
                sys.stdout.flush()
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

def report_unexpected(unexpected, sources, options, paths, annotation_budget):
    by_signature = defaultdict(list)
    for rec in unexpected:
        by_signature[signature(rec)].append(rec)
    groups = sorted(by_signature.items(), key=lambda kv: (-len(kv[1]), kv[0]))

    for (status, what), recs in groups:
        print()
        print("=== %d x %s: %s" % (len(recs), status, what))
        for rec in recs:
            print()
            print(describe_case(rec, sources))

    # Repeated in short at the end, which is where a CI log is read first
    print()
    print("%d unexpected result(s):" % (len(unexpected)))
    for (status, what), recs in groups:
        print("%d x %s: %s" % (len(recs), status, what))
        for rec in recs:
            print("   %s" % (rec.get('test_id', '?')))

    files = []
    for rec in unexpected:
        source = test_source(sources, rec)
        if source is None:
            files = paths
            break
        if source[0] not in files:
            files.append(source[0])
    print()
    print("To rerun just the affected file(s) with plzn's own report:")
    print("   %s" % (rerun_command(options, files)))

    for i, ((status, what), recs) in enumerate(groups):
        if i == annotation_budget - 1 and len(groups) > annotation_budget:
            gha_annotation('error', 'plzn', "%d more kinds of unexpected result; see the log" % (len(groups) - i))
            break
        ids = [rec.get('test_id', '?') for rec in recs]
        if len(ids) > MAX_IDS_PER_ANNOTATION:
            ids = ids[:MAX_IDS_PER_ANNOTATION] + ["... and %d more" % (len(ids) - MAX_IDS_PER_ANNOTATION)]
        gha_annotation('error', "plzn %s (%d)" % (status, len(recs)), '\n'.join([what] + ids))

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

    sources = find_test_sources(paths)
    exit_code, cases, summary = run_plzn(plzn_command(options, paths), options.verbose)

    counts = {status: len(cases.get(status, [])) for status in EXPECTED_STATUSES + UNEXPECTED_STATUSES}
    unknown = sorted(set(cases.keys()) - set(counts.keys()))
    total = sum(len(recs) for recs in cases.values())

    unexpected = [rec for status in UNEXPECTED_STATUSES for rec in cases.get(status, [])]

    problems = []

    if summary is None:
        problems.append("plzn did not produce a summary record")
    elif summary.get('aborted'):
        problems.append("plzn aborted the run (consecutive shim crashes)")
    # plzn exits 1 when any case failed or unexpectedly passed
    if exit_code != 0 and not (exit_code == 1 and unexpected):
        problems.append("plzn exited with code %d" % (exit_code))
    if unknown:
        problems.append("unknown case status(es): %s" % (', '.join(unknown)))

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
        report_unexpected(unexpected, sources, options, paths, MAX_GHA_ANNOTATIONS - len(problems))

    for problem in problems:
        print(problem)
        gha_annotation('error', 'plzn', problem)

    if unexpected or problems:
        return 1

    return 0

if __name__ == '__main__':
    sys.exit(main())
