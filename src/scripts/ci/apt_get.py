#!/usr/bin/env python3

"""
(C) 2026 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)

Runs apt-get with fetch timeouts, plus a retry loop with an overall
per-attempt timeout.
"""

import argparse
import os
import signal
import subprocess
import sys
import time

import gha_linux_packages


def run_with_timeout(cmd, timeout):
    """
    Run cmd, killing its entire process group if it runs for longer
    than timeout seconds. Returns the exit code, or None on timeout.
    """
    proc = subprocess.Popen(cmd, start_new_session=True)

    try:
        return proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        pass

    for sig in [signal.SIGTERM, signal.SIGKILL]:
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            break
        try:
            proc.wait(timeout=10)
            break
        except subprocess.TimeoutExpired:
            continue

    return None

def main():
    parser = argparse.ArgumentParser(description='Run apt-get with timeouts and retries for CI')
    parser.add_argument('command', choices=['update', 'install'])
    parser.add_argument('target', nargs='?',
                        help='CI target name (install only)')
    parser.add_argument('compiler', nargs='?',
                        help='CI compiler name (install only)')
    parser.add_argument('--attempts', default=3, type=int,
                        help='Total attempts before giving up')
    parser.add_argument('--attempt-timeout', default=120, type=int, metavar='SECS',
                        help='Kill an attempt that runs longer than this')
    parser.add_argument('--retry-delay', default=7, type=int, metavar='SECS',
                        help='Delay between attempts')
    parser.add_argument('--fetch-timeout', default=15, type=int, metavar='SECS',
                        help='Acquire::http::Timeout and Acquire::https::Timeout')
    parser.add_argument('--fetch-retries', default=3, type=int,
                        help='Acquire::Retries')
    args = parser.parse_args()

    if args.command == 'update' and args.target is not None:
        parser.error('update does not take target/compiler')
    if args.command == 'install' and args.compiler is None:
        parser.error('install requires target and compiler')

    sudo = [] if os.geteuid() == 0 else ['sudo']

    apt_options = [
        '-o', 'Acquire::Retries=%d' % (args.fetch_retries),
        '-o', 'Acquire::http::Timeout=%d' % (args.fetch_timeout),
        '-o', 'Acquire::https::Timeout=%d' % (args.fetch_timeout),
    ]

    if args.command == 'update':
        # Otherwise a failure to fetch an index is just a warning, and the
        # job fails later with confusing missing-package errors
        apt_options += ['-o', 'APT::Update::Error-Mode=any']

    if args.command == 'install':
        packages = gha_linux_packages.gha_linux_packages(args.target, args.compiler)
    else:
        packages = []

    cmd = sudo + ['apt-get', '-qq'] + apt_options + [args.command] + packages

    what = 'apt-get %s' % (args.command)
    start_time = time.time()
    rc = None

    for attempt in range(1, args.attempts + 1):
        if attempt > 1:
            time.sleep(args.retry_delay)
            if args.command == 'install':
                # A killed install can leave dpkg half-configured
                run_with_timeout(sudo + ['dpkg', '--configure', '-a'], args.attempt_timeout)

        sys.stdout.flush()
        rc = run_with_timeout(cmd, args.attempt_timeout)

        if rc == 0:
            break
        if rc is None:
            print("%s timed out after %d seconds (attempt %d of %d)" % (
                what, args.attempt_timeout, attempt, args.attempts))
        else:
            print("%s failed with exit code %d (attempt %d of %d)" % (
                what, rc, attempt, args.attempts))

    time_taken = int(time.time() - start_time)
    print("> Running '%s' took %d seconds" % (what, time_taken))

    return 0 if rc == 0 else 1

if __name__ == '__main__':
    sys.exit(main())
