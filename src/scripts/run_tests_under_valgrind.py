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
    valgrind_cmd = ['valgrind', '-v', '--error-exitcode=9']

    if options.with_leak_check:
        valgrind_cmd += ['--leak-check=full', '--show-reachable=yes']

    if options.track_origins:
        valgrind_cmd += ['--track-origins=yes']

    botan_test_options = ['--test-threads=1', '--run-memory-intensive-tests']
    cmd = valgrind_cmd + [options.test_binary] + botan_test_options + test

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

def filter_tests(available, cmdline, options):
    skip_tests = sum([x.split(',') for x in options.skip_tests], [])

    to_run = []

    for test in available:
        if test in skip_tests:
            continue

        if test.startswith('pkcs11'):
            continue

        if cmdline == [] or test in cmdline:
            to_run.append(test)

    return to_run

def split_list(list, n):
    return [list[x:x+n] for x in range(0, len(list), n)]

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

    parser.add_option('--skip-tests', metavar='TESTS', default=[], action='append',
                      help='skip the named tests')

    parser.add_option('--bunch', action='store_true', default=False,
                      help='run several test suites under each valgrind exec')

    (options, args) = parser.parse_args(args)

    tests = filter_tests(available_tests(options.test_binary), args[1:], options)

    jobs = int(options.jobs)
    pool = ThreadPool(jobs)

    results = []

    if options.bunch:
        bunching = len(tests) // (jobs * 8)

        for test in split_list(tests, bunching):
            results.append(pool.apply_async(run_valgrind, (options, test)))
    else:
        for test in tests:
            results.append(pool.apply_async(run_valgrind, (options, [test])))

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
