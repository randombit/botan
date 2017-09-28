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
    modules.remove('bearssl')
    return modules

def get_concurrency():
    def_concurrency = 2

    try:
        import multiprocessing
        return max(def_concurrency, multiprocessing.cpu_count())
    except ImportError:
        return def_concurrency

def run_test_build(configure_py, modules, include):
    cmdline = [configure_py]

    if include:
        cmdline.append('--minimized')
        if modules:
            cmdline.append('--enable-modules=' + ','.join(modules))
    else:
        cmdline.append('--disable-modules=' + ','.join(modules))

    print("Testing", cmdline)
    configure = subprocess.Popen(cmdline, stdout=subprocess.PIPE)
    configure.communicate()

    if configure.returncode != 0:
        raise Exception("Running %s failed" % (' '.join(cmdline)))

    make = subprocess.Popen(['make', '-j', str(get_concurrency())],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (stdout, stderr) = make.communicate()

    if make.returncode != 0:
        print("Build failed:")
        print(stdout.decode('ascii'))
        print(stderr.decode('ascii'))

    tests = subprocess.Popen(['./botan-test'],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    (stdout, stderr) = tests.communicate()
    if tests.returncode != 0:
        print("Tests failed:")
        print(stdout.decode('ascii'))
        print(stderr.decode('ascii'))

    sys.stdout.flush()

def main(args):

    # TODO take configure.py and botan-test paths via options

    configure_py = './configure.py'
    modules = get_module_list(configure_py)

    for module in sorted(modules):
        extra = ['sha2_32', 'sha2_64', 'aes']
        if module == 'auto_rng':
            extra.append('dev_random')
        run_test_build(configure_py, [module] + extra, True)

    for module in sorted(modules):
        run_test_build(configure_py, [module], False)

if __name__ == '__main__':
    sys.exit(main(sys.argv))
