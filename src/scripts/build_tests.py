#!/usr/bin/python3

"""
This configures and builds with many different sub-configurations
in an attempt to flush out missing feature macro checks, etc.

There is probably no reason for you to run this. Unless you want to.

(C) 2017 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import sys
import subprocess

def get_module_list(configure_py):
    configure = subprocess.Popen([configure_py, '--list-modules'], stdout=subprocess.PIPE)

    (stdout, _) = configure.communicate()

    if configure.returncode != 0:
        raise Exception("Running configure.py --list-modules failed")

    modules = [s.decode('ascii') for s in stdout.split()]
    modules.remove('bearssl') # can't test
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
    cmd = subprocess.Popen(cmdline, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (stdout, stderr) = cmd.communicate()

    if cmd.returncode != 0:
        print("FAILURE")
        print(stdout.decode('ascii'))
        print(stderr.decode('ascii'))

    sys.stdout.flush()

    return (cmd.returncode == 0)

def run_test_build(configure_py, modules, include, run_tests = False):
    config = [configure_py]

    if include:
        config.append('--minimized')
        if modules:
            config.append('--enable-modules=' + ','.join(modules))
    else:
        config.append('--disable-modules=' + ','.join(modules))

    if try_to_run(config) is False:
        return False

    if try_to_run(['make', '-j', str(get_concurrency())]) is False:
        return False

    if run_tests is False:
        return True

    return try_to_run(['./botan-test'])

def main(args):

    # TODO take configure.py and botan-test paths via options

    configure_py = './configure.py'
    modules = get_module_list(configure_py)

    cant_disable = ['block', 'hash', 'hex', 'mac', 'modes', 'rng', 'stream', 'utils']
    always_include = ['sha2_32', 'sha2_64', 'aes']

    for module in sorted(modules):
        continue
        if module in always_include or module in cant_disable:
            continue # already testing it

        extra = []
        if module == 'auto_rng':
            extra.append('dev_random')
        run_test_build(configure_py, [module] + always_include + extra, True)

    for module in sorted(modules):
        if module in cant_disable or module in always_include:
            continue
        run_test_build(configure_py, [module], False)


if __name__ == '__main__':
    sys.exit(main(sys.argv))
