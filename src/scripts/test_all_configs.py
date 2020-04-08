#!/usr/bin/python

"""
This configures and builds with many different sub-configurations
in an attempt to flush out missing feature macro checks, etc.

There is probably no reason for you to run this. Unless you want to.

(C) 2017 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import optparse # pylint: disable=deprecated-module
import sys
import subprocess

def get_module_list(configure_py):
    configure = subprocess.Popen([configure_py, '--list-modules'], stdout=subprocess.PIPE)

    (stdout, _) = configure.communicate()

    if configure.returncode != 0:
        raise Exception("Running configure.py --list-modules failed")

    modules = [s.decode('ascii') for s in stdout.split()]
    modules.remove('tpm') # can't test
    modules.remove('base') # can't remove
    return modules

def get_concurrency():
    def_concurrency = 2

    try:
        import multiprocessing
        return max(def_concurrency, multiprocessing.cpu_count())
    except ImportError:
        return def_concurrency

def try_to_run(cmdline):
    print("Running %s ... " % (' '.join(cmdline)))
    sys.stdout.flush()

    cmd = subprocess.Popen(cmdline, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (stdout, stderr) = cmd.communicate()

    failed = (cmd.returncode != 0)

    if failed:
        print("FAILURE")
        print(stdout)
        print(stderr)
        sys.stdout.flush()

    return not failed

def run_test_build(configure_py, modules, include, jobs, run_tests):
    config = [configure_py, '--without-documentation']

    if include:
        config.append('--minimized')
        if modules:
            config.append('--enable-modules=' + ','.join(modules))
    else:
        config.append('--disable-modules=' + ','.join(modules))

    if try_to_run(config) is False:
        return False

    if try_to_run(['make', '-j', str(jobs)]) is False:
        return False

    if run_tests is False:
        return True

    # Flaky test causing errors when running tests
    tests_to_skip = []

    cmdline = ['./botan-test', '--test-threads=%d' % (jobs)]

    if len(tests_to_skip) > 0:
        cmdline.append('--skip-tests=%s' % (','.join(tests_to_skip)))

    return try_to_run(cmdline)

def main(args):

    # TODO take configure.py and botan-test paths via options

    parser = optparse.OptionParser()

    parser.add_option('--run-tests', default=False, action='store_true')
    parser.add_option('--jobs', default=get_concurrency(),
                      help="jobs to run (default %default)")

    (options, args) = parser.parse_args(args)

    run_tests = options.run_tests
    jobs = int(options.jobs)

    configure_py = './configure.py'
    modules = get_module_list(configure_py)

    cant_disable = ['block', 'hash', 'hex', 'mac', 'modes', 'rng', 'stream', 'utils', 'cpuid', 'entropy']
    always_include = ['thread_utils', 'sha2_64']#, 'sha2_64', 'aes']

    fails = 0
    failed = []

    for module in sorted(modules):
        if (module in always_include) or (module in cant_disable):
            continue # already testing it

        extra = []
        if module == 'auto_rng':
            extra.append('dev_random')
        if run_test_build(configure_py, [module] + always_include + extra, True, jobs, run_tests) is False:
            failed.append(module)
            fails += 1

    for module in sorted(modules):
        if module in cant_disable or module in always_include:
            continue
        if run_test_build(configure_py, [module], False, jobs, run_tests) is False:
            failed.append(module)
            fails += 1

    if len(failed) > 0:
        print("Failed building with %s" % (' '.join(failed)))
    else:
        print("All configurations ok")

    return fails

if __name__ == '__main__':
    sys.exit(main(sys.argv))
