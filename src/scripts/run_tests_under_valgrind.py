#!/usr/bin/env python3

"""
Run all tests under valgrind in a thread pool

(C) 2025 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import multiprocessing
import optparse # pylint: disable=deprecated-module
import subprocess
import sys
import time

from multiprocessing.pool import ThreadPool

def get_concurrency():
    def_concurrency = 2
    max_concurrency = 16

    try:
        return min(max_concurrency, multiprocessing.cpu_count())
    except ImportError:
        return def_concurrency

def available_tests(botan_test):
    cmd = [botan_test, '--list-tests']
    tests = subprocess.Popen(cmd, close_fds=True, stdout=subprocess.PIPE).communicate()

    return [str(s, encoding='utf8') for s in tests[0].split()]

def run_valgrind(options, test):
    if test.startswith('pkcs11'):
        return True

    valgrind_cmd = ['valgrind', '-v', '--error-exitcode=9']

    if options.with_leak_check:
        valgrind_cmd += ['--leak-check=full', '--show-reachable=yes']

    if options.track_origins:
        valgrind_cmd += ['--track-origins=yes']

    cmd = valgrind_cmd + [options.test_binary, test]

    start = time.time()
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    duration = time.time() - start

    if options.verbose:
        print("Testing '%s' took %.02fs" % (test, duration))
        sys.stdout.flush()

    if proc.returncode == 0:
        return True # success

    print("FAILED: valgrind testing %s failed with error code %d" % (test, proc.returncode))
    print(proc.stdout.decode('utf8'))
    print(proc.stderr.decode('utf8'))
    return False

def main(args = None):
    if args is None:
        args = sys.argv

    parser = optparse.OptionParser()

    parser.add_option('--verbose', action='store_true', default=False, help='be noisy')

    parser.add_option('--test-binary', metavar='PATH', default='./botan-test',
                      help='path to botan-test binary')

    parser.add_option('--jobs', metavar='J', default=get_concurrency(),
                      help='number of jobs to run in parallel (default %default)')

    parser.add_option('--with-leak-check', action='store_true', default=False,
                      help='enable full valgrind leak checks')

    parser.add_option('--track-origins', action='store_true', default=False,
                      help='enable origin tracking')

    (options, args) = parser.parse_args(args)

    args = args[1:]

    tests = available_tests(options.test_binary)

    pool = ThreadPool(options.jobs)

    results = []
    for test in tests:
        if args == [] or test in args:
            results.append(pool.apply_async(run_valgrind, (options, test)))

    fail_cnt = 0
    for result in results:
        if not result.get():
            fail_cnt += 1

    if fail_cnt > 0:
        print("%d tests failed" % (fail_cnt))
        return 1
    else:
        return 0

if __name__ == '__main__':
    sys.exit(main())
