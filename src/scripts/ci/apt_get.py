#!/usr/bin/env python3

"""
(C) 2026 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)

Runs apt-get with fetch timeouts, plus a retry loop. Each attempt to fetch
indexes or packages gets a fixed time, as a slow mirror is better retried
than waited on, while installing is only killed once apt-get has been
silent for too long. All attempts together are bounded by an overall
timeout.
"""

import argparse
import math
import os
import select
import signal
import subprocess
import sys
import time

import gha_linux_packages

# The GHA images list this mirror first, and it is sometimes very slow
# https://github.com/actions/runner-images/issues/14823
SLOW_MIRROR = 'azure.archive.ubuntu.com'
MIRROR_LIST = '/etc/apt/apt-mirrors.txt'

# apt tries mirrors in increasing order of priority
LAST_PRIORITY = 'priority:1000'


def kill_process_group(proc):
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

def run_with_timeouts(cmd, silence_timeout, deadline):
    """
    Run cmd, copying its output to stdout. Its entire process group is
    killed if it prints nothing for silence_timeout seconds, or is still
    running at deadline (a time.monotonic() value).

    Returns (exit code, None), or (None, reason) if it was killed.
    """
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    output = proc.stdout.fileno()
    start = time.monotonic()
    last_output = start

    while True:
        now = time.monotonic()
        if now - last_output >= silence_timeout:
            reason = "printed nothing for %d seconds" % (silence_timeout)
            break
        if now >= deadline:
            reason = "was still running after %d seconds" % (round(now - start))
            break

        # Wake up regularly, as the process can exit while a child keeps the pipe open
        wait = min(1.0, last_output + silence_timeout - now, deadline - now)
        if select.select([output], [], [], wait)[0]:
            data = os.read(output, 65536)
            if data:
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
                last_output = time.monotonic()
                continue
            output_closed = True
        else:
            output_closed = False

        rc = proc.poll()
        if rc is not None:
            proc.stdout.close()
            return (rc, None)
        if output_closed:
            # Only the process exit is left to wait for
            try:
                rc = proc.wait(timeout=max(0, min(last_output + silence_timeout, deadline) - time.monotonic()))
                proc.stdout.close()
                return (rc, None)
            except subprocess.TimeoutExpired:
                continue

    kill_process_group(proc)
    proc.stdout.close()
    return (None, reason)

def demote_slow_mirror(sudo):
    """
    Make apt try SLOW_MIRROR last, so that a retry fetches from another mirror
    """
    try:
        with open(MIRROR_LIST, encoding='utf8') as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        return

    updated = []
    for line in lines:
        if SLOW_MIRROR in line and LAST_PRIORITY not in line:
            fields = [field for field in line.split() if not field.startswith('priority:')]
            line = '\t'.join(fields + [LAST_PRIORITY])
        updated.append(line)

    if updated != lines:
        print("Moving %s to the end of %s" % (SLOW_MIRROR, MIRROR_LIST), flush=True)
        subprocess.run(sudo + ['tee', MIRROR_LIST], input='\n'.join(updated) + '\n', text=True,
                       stdout=subprocess.DEVNULL, check=True)

def run_attempts(what, cmd, args, deadline, attempt_timeout, before_retry):
    """
    Run cmd until it succeeds, at most args.attempts times, calling
    before_retry() in between. Each attempt may run for attempt_timeout
    seconds, and all of them end at deadline. Returns True on success.
    """
    for attempt in range(1, args.attempts + 1):
        if attempt > 1:
            if time.monotonic() + args.retry_delay >= deadline:
                break
            time.sleep(args.retry_delay)
            before_retry()
            if time.monotonic() >= deadline:
                break

        sys.stdout.flush()
        rc, reason = run_with_timeouts(cmd, args.silence_timeout, min(deadline, time.monotonic() + attempt_timeout))

        if rc == 0:
            return True
        if rc is None:
            print("%s %s (attempt %d of %d)" % (what, reason, attempt, args.attempts), flush=True)
        else:
            print("%s failed with exit code %d (attempt %d of %d)" % (
                what, rc, attempt, args.attempts), flush=True)

    return False

def main():
    parser = argparse.ArgumentParser(description='Run apt-get with timeouts and retries for CI')
    parser.add_argument('command', choices=['update', 'install'])
    parser.add_argument('target', nargs='?',
                        help='CI target name (install only)')
    parser.add_argument('compiler', nargs='?',
                        help='CI compiler name (install only)')
    parser.add_argument('--attempts', default=3, type=int,
                        help='Attempts at each step before giving up')
    parser.add_argument('--download-timeout', default=120, type=int, metavar='SECS',
                        help='Kill an attempt to fetch indexes or packages that runs this long')
    parser.add_argument('--silence-timeout', default=120, type=int, metavar='SECS',
                        help='Kill an attempt that prints nothing for this long')
    parser.add_argument('--total-timeout', default=600, type=int, metavar='SECS',
                        help='Give up once all attempts together have run for this long')
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

    # A single -q still prints a line per downloaded package, which the
    # silence timeout relies on to tell a slow download from a hung one.
    # Unlike -qq, it does not imply -y.
    apt_get = sudo + ['apt-get', '-q', '-y'] + apt_options

    what = 'apt-get %s' % (args.command)
    start_time = time.monotonic()
    deadline = start_time + args.total_timeout

    def demote_mirror():
        demote_slow_mirror(sudo)

    def configure_dpkg():
        # A killed install can leave dpkg half-configured
        run_with_timeouts(sudo + ['dpkg', '--configure', '-a'], args.silence_timeout, deadline)

    if args.command == 'update':
        ok = run_attempts(what, apt_get + ['update'], args, deadline, args.download_timeout, demote_mirror)
    else:
        packages = gha_linux_packages.gha_linux_packages(args.target, args.compiler)

        # Downloading first means only the install proper can take long, as long
        # as it keeps printing; packages fetched by failed attempts are kept
        ok = run_attempts('apt-get install --download-only', apt_get + ['install', '--download-only'] + packages,
                          args, deadline, args.download_timeout, demote_mirror) and \
             run_attempts(what, apt_get + ['install'] + packages, args, deadline, math.inf, configure_dpkg)

    time_taken = int(time.monotonic() - start_time)
    print("> Running '%s' took %d seconds" % (what, time_taken))

    return 0 if ok else 1

if __name__ == '__main__':
    sys.exit(main())
