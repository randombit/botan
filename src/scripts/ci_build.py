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
import tempfile
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

def determine_flags(target, target_os, target_cpu, target_cc, cc_bin, ccache, root_dir, pkcs11_lib):
    # pylint: disable=too-many-branches,too-many-statements,too-many-arguments,too-many-locals

    """
    Return the configure.py flags as well as make/test running prefixes
    """
    is_cross_target = target.startswith('cross-')

    if target_os not in ['linux', 'osx', 'windows']:
        print('Error unknown OS %s' % (target_os))
        return (None, None, None)

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

    install_prefix = os.path.join(tempfile.gettempdir(), 'botan-install')
    flags = ['--prefix=%s' % (install_prefix),
             '--cc=%s' % (target_cc),
             '--os=%s' % (target_os)]

    if target_cpu != None:
        flags += ['--cpu=%s' % (target_cpu)]

    if target in ['static', 'mini-static', 'fuzzers'] or target_os in ['ios', 'mingw']:
        flags += ['--disable-shared']

    if target in ['mini-static', 'mini-shared']:
        flags += ['--minimized-build', '--enable-modules=system_rng,sha2_32,sha2_64,aes']

    if target == 'static':
        # Arbitrarily test amalgamation on static lib builds
        flags += ['--amalgamation']

    if target in ['bsi', 'nist']:
        flags += ['--module-policy=%s' % (target)]

    if target == 'docs':
        flags += ['--with-doxygen', '--with-sphinx']
        test_cmd = None

    if target == 'coverage':
        flags += ['--with-coverage-info']
    if target == 'valgrind':
        flags += ['--with-valgrind']
        test_prefix = ['valgrind', '--error-exitcode=9', '-v', '--leak-check=full', '--show-reachable=yes']
        test_cmd += fast_tests
    if target == 'fuzzers':
        flags += ['--unsafe-fuzzer-mode']

    if target in ['fuzzers', 'coverage', 'valgrind']:
        flags += ['--with-debug-info']
    if target in ['fuzzers', 'coverage']:
        flags += ['--build-fuzzers=test']
    if target in ['fuzzers', 'sanitizer']:

        # On VC iterator debugging comes from generic debug mode
        if target_cc == 'msvc':
            flags += ['--with-debug-info']
        else:
            flags += ['--with-sanitizers']
    if target in ['valgrind', 'sanitizer', 'fuzzers']:
        flags += ['--disable-modules=locking_allocator']

    if target == 'parallel':
        if target_cc == 'gcc':
            flags += ['--with-cilkplus']
        else:
            flags += ['--with-openmp']

    if target == 'sonar':
        if target_os != 'linux' or target_cc != 'clang':
            raise Exception('Only Linux/clang supported in Sonar target currently')

        flags += ['--cc-abi-flags=-fprofile-instr-generate -fcoverage-mapping',
                  '--disable-shared']

        make_prefix = [os.path.join(root_dir, 'build-wrapper-linux-x86/build-wrapper-linux-x86-64'),
                       '--out-dir', 'bw-outputs']

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

        if target_os in ['osx', 'linux']:
            flags += ['--with-bzip2', '--with-sqlite', '--with-zlib']

        if target_os == 'osx':
            # Test Boost on OS X
            flags += ['--with-boost']
        elif target_os == 'linux':
            flags += ['--with-lzma']

        if target_os == 'linux':
            if target not in ['sanitizer', 'valgrind', 'mini-shared', 'mini-static']:
                # Avoid OpenSSL when using dynamic checkers, or on OS X where it sporadically
                # is not installed on the CI image
                flags += ['--with-openssl']

        if target in ['sonar', 'coverage']:
            flags += ['--with-tpm']
            test_cmd += ['--run-long-tests', '--run-online-tests']
            if pkcs11_lib and os.access(pkcs11_lib, os.R_OK):
                test_cmd += ['--pkcs11-lib=%s' % (pkcs11_lib)]

    if ccache is None:
        flags += ['--cc-bin=%s' % (cc_bin)]
    elif ccache == 'clcache':
        flags += ['--cc-bin=%s' % (ccache)]
    else:
        flags += ['--cc-bin=%s %s' % (ccache, cc_bin)]

    if test_cmd is None:
        run_test_command = None
    else:
        run_test_command = test_prefix + test_cmd

    return flags, run_test_command, make_prefix

def run_cmd(cmd, root_dir):
    """
    Execute a command, die if it failed
    """
    print("Running '%s' ..." % (' '.join(cmd)))
    sys.stdout.flush()

    start = time.time()

    sub_env = os.environ.copy()
    sub_env['LD_LIBRARY_PATH'] = root_dir

    redirect_stdout = None
    if len(cmd) > 3 and cmd[-2] == '>':
        redirect_stdout = open(cmd[-1], 'w')
        cmd = cmd[:-2]
    proc = subprocess.Popen(cmd, close_fds=True, env=sub_env, stdout=redirect_stdout)
    proc.communicate()

    time_taken = int(time.time() - start)

    if time_taken > 10:
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

    parser.add_option('--make-tool', metavar='TOOL', default='make',
                      help='Specify tool to run to build source (default %default)')

    parser.add_option('--cpu', default=None,
                      help='Specify a target CPU platform')

    parser.add_option('--with-debug', action='store_true', default=False,
                      help='Include debug information')
    parser.add_option('--amalgamation', action='store_true', default=False,
                      help='Build via amalgamation')
    parser.add_option('--disable-shared', action='store_true', default=False,
                      help='Disable building shared libraries')

    parser.add_option('--branch', metavar='B', default=None,
                      help='Specify branch being built')

    parser.add_option('--add-travis-folds', action='store_true', default=False,
                      help='Add fold markers for Travis UI')

    parser.add_option('--dry-run', action='store_true', default=False,
                      help='Just show commands to be executed')
    parser.add_option('--build-jobs', metavar='J', default=get_concurrency(),
                      help='Set number of jobs to run in parallel (default %default)')

    parser.add_option('--compiler-cache', default=None,
                      help='Set a compiler cache to use (ccache, clcache)')

    parser.add_option('--pkcs11-lib', default=None,
                      help='Set PKCS11 lib to use for testing')

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
    # pylint: disable=too-many-branches,too-many-statements,too-many-locals,too-many-return-statements
    """
    Parse options, do the things
    """

    if os.getenv('COVERITY_SCAN_BRANCH') == '1':
        print('Skipping build COVERITY_SCAN_BRANCH set in environment')
        return 0

    (options, args) = parse_args(args or sys.argv)

    if len(args) != 2:
        print('Usage: %s [options] target' % (args[0]))
        return 1

    target = args[1]

    py_interp = 'python'

    use_python2 = have_prog('python2')

    if options.use_python3 is None:
        use_python3 = have_prog('python3')
    else:
        use_python3 = options.use_python3
        if use_python3:
            py_interp = 'python3'

    if options.cc_bin is None:
        if options.cc == 'gcc':
            options.cc_bin = 'g++'
        elif options.cc == 'clang':
            options.cc_bin = 'clang++'
        elif options.cc == 'msvc':
            options.cc_bin = 'cl'
        else:
            print('Error unknown compiler %s' % (options.cc))
            return 1

    if options.compiler_cache is None and options.cc != 'msvc':
        # Autodetect ccache, unless using clang profiling - ccache seems to misbehave there
        if have_prog('ccache') and target not in ['sonar']:
            options.compiler_cache = 'ccache'

    if options.compiler_cache == 'clcache' and target in ['sanitizer']:
        # clcache doesn't support /Zi so using it just adds overhead with
        # no benefit
        options.compiler_cache = None

    if target == 'sonar' and os.getenv('SONAR_TOKEN') is None:
        print('Skipping Sonar scan due to missing SONAR_TOKEN env variable')
        return 0

    root_dir = options.root_dir

    if os.access(root_dir, os.R_OK) != True:
        raise Exception('Bad root dir setting, dir %s not readable', root_dir)

    cmds = []

    if target == 'lint':

        if not use_python2 and not use_python3:
            raise Exception('No python interpreters found cannot lint')

        pylint_rc = '--rcfile=%s' % (os.path.join(root_dir, 'src/configs/pylint.rc'))
        pylint_flags = [pylint_rc, '--reports=no', '--score=no']

        # Some disabled rules specific to Python2
        # superfluous-parens: needed for Python3 compatible print statements
        # too-many-locals: variable counting differs from pylint3
        py2_flags = '--disable=superfluous-parens,too-many-locals'

        py_scripts = [
            'configure.py',
            'src/python/botan2.py',
            'src/scripts/ci_build.py',
            'src/scripts/install.py',
            'src/scripts/website.py',
            'src/scripts/python_unittests.py',
            'src/scripts/python_unittests_unix.py']

        for target in py_scripts:
            target_path = os.path.join(root_dir, target)

            if use_python2:
                cmds.append(['python2', '-m', 'pylint'] + pylint_flags + [py2_flags, target_path])

            if use_python3:
                cmds.append(['python3', '-m', 'pylint'] + pylint_flags + [target_path])

    else:
        config_flags, run_test_command, make_prefix = determine_flags(
            target, options.os, options.cpu, options.cc,
            options.cc_bin, options.compiler_cache, root_dir,
            options.pkcs11_lib)

        cmds.append([py_interp, os.path.join(root_dir, 'configure.py')] + config_flags)

        make_cmd = [options.make_tool]
        if root_dir != '.':
            make_cmd += ['-C', root_dir]
        if options.build_jobs > 1:
            make_cmd += ['-j%d' % (options.build_jobs)]
        make_cmd += ['-k']

        if target == 'docs':
            cmds.append(make_cmd + ['docs'])
        else:
            if options.compiler_cache == 'ccache':
                cmds.append(['ccache', '--show-stats'])
            elif options.compiler_cache == 'clcache':
                cmds.append(['clcache', '-s'])

            make_targets = ['libs', 'cli', 'tests']
            if target in ['coverage', 'fuzzers']:
                make_targets += ['fuzzers', 'fuzzer_corpus_zip']

            cmds.append(make_prefix + make_cmd + make_targets)

            if options.compiler_cache == 'ccache':
                cmds.append(['ccache', '--show-stats'])
            elif options.compiler_cache == 'clcache':
                cmds.append(['clcache', '-s'])

        if run_test_command != None:
            cmds.append(run_test_command)

        if target in ['coverage', 'fuzzers']:
            cmds.append([py_interp, os.path.join(root_dir, 'src/scripts/test_fuzzers.py'),
                         os.path.join(root_dir, 'fuzzer_corpus'),
                         os.path.join(root_dir, 'build/fuzzer')])

        if target in ['static', 'shared'] and options.os != 'windows':
            botan_exe = os.path.join(root_dir, 'botan-cli.exe' if options.os == 'windows' else 'botan')
            cmds.append([py_interp,
                         os.path.join(root_dir, 'src/scripts/cli_tests.py'),
                         botan_exe])

        botan_py = os.path.join(root_dir, 'src/python/botan2.py')

        if target in ['shared', 'coverage']:

            if use_python2:
                cmds.append(['python2', botan_py])
            if use_python3:
                cmds.append(['python3', botan_py])

        if target == 'shared':
            cmds.append(make_cmd + ['install'])

        if target in ['sonar']:

            cmds.append(['llvm-profdata', 'merge', '-sparse', 'default.profraw', '-o', 'botan.profdata'])
            cmds.append(['llvm-cov', 'show', './botan-test',
                         '-instr-profile=botan.profdata',
                         '>', 'build/cov_report.txt'])
            sonar_config = os.path.join(root_dir, os.path.join(root_dir, 'src/build-data/sonar-project.properties'))
            cmds.append(['sonar-scanner',
                         '-Dproject.settings=%s' % (sonar_config),
                         '-Dsonar.login=%s' % (os.getenv('SONAR_TOKEN'))])

        if target in ['coverage']:

            if not have_prog('lcov'):
                print('Error: lcov not found in PATH (%s)' % (os.getenv('PATH')))
                return 1

            if not have_prog('gcov'):
                print('Error: gcov not found in PATH (%s)' % (os.getenv('PATH')))
                return 1

            cov_file = 'coverage.info'
            raw_cov_file = 'coverage.info.raw'

            cmds.append(['lcov', '--capture', '--directory', options.root_dir,
                         '--output-file', raw_cov_file])
            cmds.append(['lcov', '--remove', raw_cov_file, '/usr/*', '--output-file', cov_file])
            cmds.append(['lcov', '--list', cov_file])

            if have_prog('coverage'):
                cmds.append(['coverage', 'run', '--branch',
                             '--rcfile', os.path.join(root_dir, 'src/configs/coverage.rc'),
                             botan_py])

            if have_prog('codecov'):
                # If codecov exists assume we are on Travis and report to codecov.io
                cmds.append(['codecov'])
            else:
                # Otherwise generate a local HTML report
                cmds.append(['genhtml', cov_file, '--output-directory', 'lcov-out'])

    for cmd in cmds:
        if options.dry_run:
            print('$ ' + ' '.join(cmd))
        else:
            run_cmd(cmd, root_dir)

    return 0

if __name__ == '__main__':
    sys.exit(main())
