#!/usr/bin/env python

"""
CI build script
(C) 2017 Jack Lloyd
Botan is released under the Simplified BSD License (see license.txt)
"""

import os
import platform
import subprocess
import sys
import time
import optparse # pylint: disable=deprecated-module

def get_concurrency():
    """
    Get default concurrency level of build
    """
    def_concurrency = 2

    try:
        import multiprocessing
        return max(def_concurrency, multiprocessing.cpu_count())
    except ImportError:
        return def_concurrency

def getenv_or_die(var):
    """
    Like it says...
    """
    val = os.getenv(var)
    if val is None:
        raise Exception('Required variable %s not set in environment' % (var))
    return val

def determine_flags(target, target_os, target_cc, cc_bin, use_ccache, root_dir):
    # pylint: disable=too-many-branches,too-many-statements,too-many-arguments

    """
    Return the configure.py flags as well as make/test running prefixes
    """
    is_cross_target = target.startswith('cross-')

    if target_os not in ['linux', 'osx']:
        print('Error unknown OS %s' % (target_os))
        return 1

    if is_cross_target:
        if target_os == 'osx':
            target_os = 'ios'
        elif target == 'cross-win32':
            target_os = 'mingw'

    make_prefix = []
    test_prefix = []
    test_cmd = [os.path.join(root_dir, 'botan-test')]

    fast_tests = ['block', 'aead', 'hash', 'stream', 'mac', 'modes',
                  'hmac_drbg', 'hmac_drbg_unit',
                  'tls', 'ffi',
                  'rsa_sign', 'rsa_verify', 'dh_kat', 'ecdsa_sign', 'curve25519_scalar',
                  'simd_32', 'os_utils', 'util', 'util_dates']

    flags = ['--prefix=/tmp/botan-install', '--cc=%s' % (target_cc), '--os=%s' % (target_os)]

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
        test_cmd = None

    if target in ['coverage', 'sonar']:
        flags += ['--with-coverage-info']
    if target == 'valgrind':
        flags += ['--with-valgrind']
        test_prefix = ['valgrind', '--error-exitcode=9', '-v']
        test_cmd += fast_tests

    if target in ['fuzzers', 'coverage', 'valgrind']:
        flags += ['--with-debug-info']
    if target in ['fuzzers', 'coverage']:
        flags += ['--build-fuzzers=test']
    if target in ['fuzzers', 'sanitizer']:
        flags += ['--with-sanitizers']
    if target in ['valgrind', 'sanitizer', 'fuzzers']:
        flags += ['--disable-modules=locking_allocator']

    if target == 'parallel':
        if 'cc' == 'gcc':
            flags += ['--with-cilkplus']
        else:
            flags += ['--with-openmp']

    if target == 'sonar':
        make_prefix = [os.path.join(root_dir, 'build-wrapper-linux-x86/build-wrapper-linux-x86-64'),
                       '--out-dir', 'bw-outputs']
        test_cmd = ['sonar-scanner',
                    '-Dproject.settings=%s' % (os.path.join(root_dir, 'src', 'build-data', 'sonar-project.properties')),
                    '-Dsonar.login=%s' % (getenv_or_die('SONAR_TOKEN'))]

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
        elif target == 'cross-win32':
            flags += ['--cpu=x86_32', '--cc-abi-flags=-static']
            cc_bin = 'i686-w64-mingw32-g++'
            test_cmd = [os.path.join(root_dir, 'botan-test.exe')]
            # No runtime prefix required for Wine
        else:
            # Build everything but restrict what is run
            test_cmd += fast_tests

            if target == 'cross-arm32':
                flags += ['--cpu=armv7']
                cc_bin = 'arm-linux-gnueabihf-g++'
                test_prefix = ['qemu-arm', '-L', '/usr/arm-linux-gnueabihf/']
            elif target == 'cross-arm64':
                flags += ['--cpu=armv8-a']
                cc_bin = 'aarch64-linux-gnu-g++'
                test_prefix = ['qemu-aarch64', '-L', '/usr/aarch64-linux-gnu/']
            elif target == 'cross-ppc32':
                flags += ['--cpu=ppc32']
                cc_bin = 'powerpc-linux-gnu-g++'
                test_prefix = ['qemu-ppc', '-L', '/usr/powerpc-linux-gnu/']
            elif target == 'cross-ppc64':
                flags += ['--cpu=ppc64', '--with-endian=little']
                cc_bin = 'powerpc64le-linux-gnu-g++'
                test_prefix = ['qemu-ppc64le', '-L', '/usr/powerpc64le-linux-gnu/']
            else:
                raise Exception("Unknown cross target '%s' for Linux" % (target))
    else:
        # Flags specific to native targets
        flags += ['--with-bzip2', '--with-lzma', '--with-sqlite', '--with-zlib']

        if target_os == 'osx':
            # Test Boost on OS X
            flags += ['--with-boost']
        elif target not in ['sanitizer', 'valgrind', 'mini-shared', 'mini-static']:
            # Avoid OpenSSL when using dynamic checkers, or on OS X where it sporadically
            # is not installed on the CI image
            flags += ['--with-openssl']

        if target == 'coverage':
            flags += ['--with-tpm']
            test_cmd += ['--run-long-tests', '--run-online-tests']

            softhsm_lib = '/tmp/softhsm/lib/softhsm/libsofthsm2.so'
            if os.access(softhsm_lib, os.R_OK):
                test_cmd += ['--pkcs11-lib=%s' % (softhsm_lib)]

    flags += ['--cc-bin=%s%s' % ('ccache ' if use_ccache else '', cc_bin)]

    if test_cmd is None:
        run_test_command = None
    else:
        run_test_command = test_prefix + test_cmd

    return flags, run_test_command, make_prefix

def run_cmd(cmd, root_dir):
    """
    Execute a command, die if it failed
    """
    print("Running '%s':\n" % (' '.join(cmd)))
    sys.stdout.flush()

    start = time.time()

    sub_env = os.environ.copy()
    sub_env['LD_LIBRARY_PATH'] = root_dir
    proc = subprocess.Popen(cmd, close_fds=True, env=sub_env)
    proc.communicate()

    time_taken = int(time.time() - start)

    if time_taken > 2:
        print("Ran for %d seconds" % (time_taken))

    if proc.returncode != 0:
        print("Command failed with error code %d" % (proc.returncode))
        sys.exit(proc.returncode)

def parse_args(args):
    """
    Parse arguments
    """
    parser = optparse.OptionParser()

    parser.add_option('--os', default=platform.system().lower(),
                      help='Set the target os (default %default)')
    parser.add_option('--cc', default='gcc',
                      help='Set the target compiler type (default %default)')
    parser.add_option('--cc-bin', default=None,
                      help='Set path to compiler')
    parser.add_option('--root-dir', metavar='D', default='.',
                      help='Set directory to execute from (default %default)')

    parser.add_option('--branch', metavar='B', default=None,
                      help='Specify branch being built')

    parser.add_option('--add-travis-folds', action='store_true', default=False,
                      help='Add fold markers for Travis UI')

    parser.add_option('--dry-run', action='store_true', default=False,
                      help='Just show commands to be executed')
    parser.add_option('--build-jobs', metavar='J', default=get_concurrency(),
                      help='Set number of jobs to run in parallel (default %default)')

    parser.add_option('--with-ccache', dest='use_ccache', action='store_true', default=None,
                      help='Enable using ccache')
    parser.add_option('--without-ccache', dest='use_ccache', action='store_false',
                      help='Disable using ccache')

    parser.add_option('--with-python3', dest='use_python3', action='store_true', default=None,
                      help='Enable using python3')
    parser.add_option('--without-python3', dest='use_python3', action='store_false',
                      help='Disable using python3')

    return parser.parse_args(args)

def have_prog(prog):
    """
    Check if some named program exists in the path
    """
    for path in os.environ['PATH'].split(os.pathsep):
        exe_file = os.path.join(path, prog)
        if os.path.exists(exe_file) and os.access(exe_file, os.X_OK):
            return True

def main(args=None):
    # pylint: disable=too-many-branches,too-many-statements
    """
    Parse options, do the things
    """
    (options, args) = parse_args(args or sys.argv)

    if len(args) != 2:
        print('Usage: %s [options] target' % (args[0]))
        return 1

    if options.use_ccache is None:
        options.use_ccache = have_prog('ccache')

    use_python2 = have_prog('python2')

    if options.use_python3 is None:
        use_python3 = have_prog('python3')
    else:
        use_python3 = options.use_python3

    if options.cc_bin is None:
        if options.cc == 'gcc':
            options.cc_bin = 'g++'
        elif options.cc == 'clang':
            options.cc_bin = 'clang++'
        else:
            print('Error unknown compiler %s' % (options.cc))
            return 1

    target = args[1]

    root_dir = options.root_dir

    if os.access(root_dir, os.R_OK) != True:
        raise Exception('Bad root dir setting, dir %s not readable', root_dir)

    cmds = []

    if target == 'lint':

        if not use_python2 and not use_python3:
            raise Exception('No python interpreters found cannot lint')

        py_scripts = [
            'configure.py',
            'src/python/botan2.py',
            'src/scripts/ci_build.py',
            'src/scripts/install.py',
            'src/scripts/python_unittests.py',
            'src/scripts/python_unittests_unix.py']

        for target in py_scripts:
            target_path = os.path.join(root_dir, target)

            if use_python2:
                # Some disabled rules specific to Python2
                # superfluous-parens: needed for Python3 compatible print statements
                # too-many-locals: variable counting differs from pylint3
                py2_flags = '--disable=superfluous-parens,too-many-locals'
                cmds.append(['python2', '-m', 'pylint', py2_flags, target_path])

            if use_python3:
                cmds.append(['python3', '-m', 'pylint', target_path])

    else:
        config_flags, run_test_command, make_prefix = determine_flags(
            target, options.os, options.cc, options.cc_bin, options.use_ccache, root_dir)

        cmds.append([os.path.join(root_dir, 'configure.py')] + config_flags)

        if target == 'docs':
            cmds.append(['make', '-C', root_dir, 'docs'])
        else:
            if options.use_ccache:
                cmds.append(['ccache', '--show-stats'])

            make_targets = ['libs', 'cli', 'tests']
            if target in ['coverage', 'fuzzers']:
                make_targets += ['fuzzers', 'fuzzer_corpus_zip']

            cmds.append(make_prefix +
                        ['make', '-j', str(options.build_jobs), '-C', root_dir] +
                        make_targets)

            if options.use_ccache:
                cmds.append(['ccache', '--show-stats'])

        if run_test_command != None:
            cmds.append(run_test_command)

        if target in ['coverage', 'fuzzers']:
            cmds.append([os.path.join(root_dir, 'src/scripts/test_fuzzers.py'),
                         os.path.join(root_dir, 'fuzzer_corpus'),
                         os.path.join(root_dir, 'build/fuzzer')])

        if target in ['static', 'shared']:
            cmds.append([os.path.join(root_dir, 'src/scripts/cli_tests.py'),
                         os.path.join(root_dir, 'botan')])

        if target in ['shared', 'coverage']:

            if use_python2:
                cmds.append(['python2', os.path.join(root_dir, 'src/python/botan2.py')])
            if use_python3:
                cmds.append(['python3', os.path.join(root_dir, 'src/python/botan2.py')])

        if target != 'docs':
            cmds.append(['make', '-C', root_dir, 'install'])

        if target in ['coverage']:

            if not have_prog('lcov'):
                print('Error: lcov not found in PATH (%s)' % (os.getenv('PATH')))
                return 1

            if not have_prog('gcov'):
                print('Error: gcov not found in PATH (%s)' % (os.getenv('PATH')))
                return 1

            cmds.append(['lcov', '--capture', '--directory', options.root_dir, '--output-file', 'coverage.info.raw'])
            cmds.append(['lcov', '--remove', 'coverage.info.raw', '/usr/*', '--output-file', 'coverage.info'])
            cmds.append(['lcov', '--list', 'coverage.info'])

            if have_prog('coverage'):
                cmds.append(['coverage', 'run', '--branch', os.path.join(root_dir, 'src/python/botan2.py')])

            if have_prog('codecov'):
                # If codecov exists assume we are on Travis and report to codecov.io
                cmds.append(['codecov'])
            else:
                # Otherwise generate a local HTML report
                cmds.append(['genhtml', 'coverage.info', '--output-directory', 'lcov-out'])

    for cmd in cmds:
        if options.dry_run:
            print('$ ' + ' '.join(cmd))
        else:
            run_cmd(cmd, root_dir)

    return 0

if __name__ == '__main__':
    sys.exit(main())
