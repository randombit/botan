#!/usr/bin/python

# CI build script
# (C) 2017 Jack Lloyd
# Botan is released under the Simplified BSD License (see license.txt)

import time
import subprocess
import optparse
import platform
import sys
import os

def getenv_or_die(var):
    val = os.getenv(var)
    if val is None:
        raise Exception('Required variable %s not set in environment' % (var))
    return val

def determine_flags(target, target_os, cc, cc_bin, use_ccache, root_dir):
    is_cross_target = target.startswith('cross-')

    if target_os not in ['linux', 'osx']:
        print('Error unknown OS %s' % (target_os))
        return 1

    if cc not in ['gcc', 'clang']:
        print('Error unknown compiler %s' % (cc))
        return 1

    if is_cross_target:
        if target_os == 'osx':
            target_os = 'ios'
        elif target == 'cross-mingw':
            target_os = 'mingw'

    make_prefix = []
    test_prefix = []
    test_cmd = [os.path.join(root_dir, 'botan-test')]

    flags = ['--prefix=/tmp/botan-install', '--cc=%s' % (cc), '--os=%s' % (target_os)]

    if target in ['static', 'mini-static', 'fuzzers'] or target_os in ['ios', 'mingw']:
        flags += ['--disable-shared']

    if target in ['mini-static', 'mini-shared']:
        flags += ['--minimized-build', '--enable-modules=dev_random,system_rng,sha2_32,sha2_64,aes']

    if target == 'shared':
        # Arbitrarily test amalgamation on shared obj builds
        flags += ['--amalgamation']

    if target in ['bsi', 'nist']:
        flags += ['--module-policy=%s' % (target)]

    if target == 'docs':
        flags += ['--with-doxygen', '--with-sphinx']

    if target == 'parallel':
        if 'cc' == 'gcc':
            flags += ['--with-cilkplus']
        else:
            flags += ['--with-openmp']

    if target == 'coverage':
        flags += ['--with-coverage']
    if target == 'valgrind':
        flags += ['--with-valgrind']
        test_prefix = ['valgrind', '--error-exitcode=9', '-v']

    if target in ['fuzzers', 'coverage', 'valgrind']:
        flags += ['--with-debug-info']
    if target in ['fuzzers', 'coverage']:
        flags += ['--build-fuzzers=test']
    if target in ['fuzzers', 'sanitizer']:
        flags += ['--with-sanitizers']
    if target in ['valgrind', 'sanitizer', 'fuzzers']:
        flags += ['--disable-modules=locking_allocator']

    if target == 'sonarqube':
        make_prefix = [os.path.join(root_dir, 'build-wrapper-linux-x86/build-wrapper-linux-x86-64'), '--out-dir', 'bw-outputs']
        test_cmd = ['sonar-scanner', '-Dsonar.login=%s' % (getenv_or_die('SONAR_TOKEN'))]

    if target_os == 'linux' and (target == 'valgrind' or is_cross_target):
        # Minimize the build when doing something that is slow
        # Note this skips os == 'mingw' since the tests are fast under Wine
        flags += ['--module-policy=modern', '--enable-modules=tls']

    if is_cross_target:
        if target_os == 'ios':
            make_prefix = ['xcrun', '--sdk', 'iphoneos']
            test_cmd = None
            if target == 'cross-arm32':
                flags += ['--cpu=armv7', '--cc-abi-flags=-arch armv7 -arch armv7s -stdlib=libc++']
            elif target == 'cross-arm64':
                flags += ['--cpu=armv8-a', '--cc-abi-flags=-arch arm64 -stdlib=libc++']
            else:
                raise Exception("Unknown cross target '%s' for iOS" % (target))
        else:

            if target == 'cross-arm32':
                flags += ['--cpu=armv7']
                cc_bin = 'arm-linux-gnueabihf-g++-4.8'
                test_prefix = ['qemu-arm', '-L', '/usr/arm-linux-gnueabihf/']
            elif target == 'cross-arm64':
                flags += ['--cpu=armv8-a']
                cc_bin = 'aarch64-linux-gnu-g++-4.8'
                test_prefix = ['qemu-aarch64', '-L', '/usr/aarch64-linux-gnu/']
            elif target == 'cross-ppc32':
                flags += ['--cpu=ppc32']
                cc_bin = 'powerpc-linux-gnu-g++-4.8'
                test_prefix = ['qemu-ppc', '-L', '/usr/powerpc-linux-gnu/']
            elif target == 'cross-ppc64':
                flags += ['--cpu=ppc64', '--with-endian=little']
                cc_bin = 'powerpc64le-linux-gnu-g++-4.8'
                test_prefix = ['qemu-ppc64le', '-L', '/usr/powerpc64le-linux-gnu/']
            elif target == 'cross-win32':
                flags += ['--cpu=x86_32', '--cc-abi-flags=-static']
                cc_bin = 'i686-w64-mingw32-g++'
                test_cmd = os.path.join(root_dir, 'botan-test.exe')
                # No runtime prefix required for Wine
            else:
                raise Exception("Unknown cross target '%s' for Linux" % (target))
    else:
        # Flags specific to native targets
        flags += ['--with-bzip2', '--with-lzma', '--with-sqlite', '--with-zlib']

        if target == 'coverage':
            flags += ['--with-tpm']
            test_cmd += ['--run-long-tests', '--run-online-tests', '--pkcs11-lib=/tmp/softhsm/lib/softhsm/libsofthsm2.so']

        if target_os == 'osx':
            # Test Boost on OS X
            flags += ['--with-boost']
        elif target_os == 'linux' and target not in ['sanitizer', 'valgrind']:
            # Avoid OpenSSL when using dynamic checkers, or on OS X where it sporadically
            # is not installed on the CI image
            flags += ['--with-openssl']

    flags += ['--cc-bin=%s%s' % ('ccache ' if use_ccache else '', cc_bin)]

    if test_cmd is None:
        run_test_command = None
    else:
        run_test_command = test_prefix + test_cmd

    return flags, run_test_command, make_prefix

def run_cmd(cmd):

    print("Running '%s':\n" % (' '.join(cmd)))
    sys.stdout.flush()

    start = time.time()

    # TODO pass LD_LIBRARY_PATH=.
    proc = subprocess.Popen(cmd, close_fds=True)
    proc.communicate()

    time_taken = time.time() - start

    if time_taken > 2:
        print("Ran for %f seconds" % (time_taken))

    if proc.returncode != 0:
        raise Exception("Command failed with error code %d" % (proc.returncode))

def main(args=None):
    if args is None:
        args = sys.argv

    parser = optparse.OptionParser()

    parser.add_option('--os', default=platform.system().lower(),
                      help='Set the target os (default %default)')
    parser.add_option('--cc', default='gcc',
                      help='Set the target compiler type (default %default)')
    parser.add_option('--cc-bin', default='g++',
                      help='Set path to compiler (default %default)')
    parser.add_option('--root-dir', metavar='D', default='.',
                      help='Set directory to execute from (default %default)')

    parser.add_option('--branch', metavar='B', default=None,
                      help='Specify branch being built')

    parser.add_option('--dry-run', action='store_true', default=False,
                      help='Just show commands to be executed')
    parser.add_option('--build-jobs', metavar='J', default='2',
                      help='Set number of jobs to run in parallel (default %default)')
    parser.add_option('--without-ccache', dest='use_ccache', action='store_false', default=True,
                      help='Disable using ccache')

    (options, args) = parser.parse_args(args)

    if len(args) != 2:
        print('Usage: %s [options] target' % (args[0]))
        return 1

    if options.use_ccache == None:
        options.use_ccache = True

    target = args[1]

    root_dir = options.root_dir

    if os.access(root_dir, os.R_OK) != True:
        raise Exception('Bad root dir setting, dir %s not readable', root_dir)

    config_flags, run_test_command, make_prefix = determine_flags(
        target, options.os, options.cc, options.cc_bin, options.use_ccache, root_dir)

    cmds = []

    cmds.append([os.path.join(root_dir, 'configure.py')] + config_flags)

    if target == 'docs':
        cmds.append(['make', '-C', root_dir, 'docs'])
    else:
        if options.use_ccache:
            cmds.append(['ccache', '--show-stats'])

        cmds.append(make_prefix + ['make', '-C', root_dir, '-j', str(options.build_jobs)])

        if target in ['coverage', 'fuzzers']:
            cmds.append(make_prefix + ['make', '-C', root_dir, 'fuzzers', 'fuzzer_corpus_zip'])

        if options.use_ccache:
            cmds.append(['ccache', '--show-stats'])

    if run_test_command != None:
        cmds.append(run_test_command)

    if target in ['coverage', 'fuzzers']:
        cmds.append([os.path.join(root_dir, 'src/scripts/test_fuzzers.py'),
                     os.path.join(root_dir, 'fuzzer_corpus'),
                     os.path.join(root_dir, 'build/fuzzer')])

    if target in ['static', 'shared']:
        cmds.append([os.path.join(root_dir, 'src/scripts/cli_tests.py'), os.path.join(root_dir, 'botan')])

    if target in ['shared', 'coverage']:
        cmds.append(['python2', os.path.join(root_dir, 'src/python/botan2.py')])
        cmds.append(['python3', os.path.join(root_dir, 'src/python/botan2.py')])

    if target != 'docs':
        cmds.append(['make', 'install'])

    for cmd in cmds:
        if options.dry_run:
            print('$ ' + ' '.join(cmd))
        else:
            run_cmd(cmd)

    return 0

if __name__ == '__main__':
    sys.exit(main())
