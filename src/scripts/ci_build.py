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
    def_concurrency = 2

    try:
        import multiprocessing
        return multiprocessing.cpu_count()
    except ImportError:
        return def_concurrency

def build_targets(target, target_os):
    if target in ['shared', 'mini-shared', 'bsi', 'nist']:
        yield 'shared'
    elif target in ['static', 'mini-static', 'fuzzers', 'baremetal']:
        yield 'static'
    elif target_os in ['windows']:
        yield 'shared'
    elif target_os in ['ios', 'mingw']:
        yield 'static'
    else:
        yield 'shared'
        yield 'static'

    yield 'cli'
    yield 'tests'

    if target in ['coverage']:
        yield 'bogo_shim'

def determine_flags(target, target_os, target_cpu, target_cc, cc_bin,
                    ccache, root_dir, pkcs11_lib, use_gdb, disable_werror, extra_cxxflags):
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
        elif target == 'cross-win64':
            target_os = 'mingw'
        elif target in ['cross-android-arm32', 'cross-android-arm64']:
            target_os = 'android'

    if target_os == 'windows' and target_cc == 'gcc':
        target_os = 'mingw'

    if target == 'baremetal':
        target_os = 'none'

    make_prefix = []
    test_prefix = []
    test_cmd = [os.path.join(root_dir, 'botan-test')]

    essential_tests = ['block', 'aead', 'hash', 'stream', 'mac', 'modes', 'kdf',
                       'hmac_drbg', 'hmac_drbg_unit', 'tls',
                       'rsa_sign', 'rsa_verify', 'dh_kat',
                       'ecc_randomized', 'ecdh_kat', 'ecdsa_sign', 'curve25519_scalar',
                       'cpuid', 'simd_32', 'os_utils', 'util', 'util_dates']

    install_prefix = os.path.join(tempfile.gettempdir(), 'botan-install')

    flags = ['--prefix=%s' % (install_prefix),
             '--cc=%s' % (target_cc),
             '--os=%s' % (target_os),
             '--build-targets=%s' % ','.join(build_targets(target, target_os))]

    if not disable_werror:
        flags += ['--werror-mode']

    if target_cpu is not None:
        flags += ['--cpu=%s' % (target_cpu)]

    for flag in extra_cxxflags:
        flags += ['--extra-cxxflags=%s' % (flag)]

    if target in ['mini-static', 'mini-shared']:
        flags += ['--minimized-build', '--enable-modules=system_rng,sha2_32,sha2_64,aes']

    if target == 'static':
        # Arbitrarily test amalgamation with the static lib builds
        flags += ['--amalgamation']

    if target in ['bsi', 'nist']:
        # Arbitrarily test disable static on module policy builds
        # tls is optional for bsi/nist but add it so verify tests work with these minimized configs
        flags += ['--module-policy=%s' % (target),
                  '--enable-modules=tls']

    if target == 'docs':
        flags += ['--with-doxygen', '--with-sphinx', '--with-rst2man']
        test_cmd = None

    if target == 'cross-win64':
        # this test compiles under MinGW but fails when run under Wine
        test_cmd += ['--skip-tests=certstor_system']

    if target == 'coverage':
        flags += ['--with-coverage-info', '--with-debug-info', '--test-mode']
        test_cmd += ['--skip-tests=tls_stream_integration']

    if target == 'valgrind':
        # valgrind in 16.04 has a bug with rdrand handling
        flags += ['--with-valgrind', '--disable-rdrand']
        test_prefix = ['valgrind', '--error-exitcode=9', '-v', '--leak-check=full', '--show-reachable=yes']
        # valgrind is single threaded anyway
        test_cmd += ['--test-threads=1']
        # valgrind is slow
        test_cmd += essential_tests

    if target == 'fuzzers':
        flags += ['--unsafe-fuzzer-mode']

    if target in ['fuzzers', 'coverage', 'valgrind']:
        flags += ['--with-debug-info']

    if target in ['fuzzers', 'coverage']:
        flags += ['--build-fuzzers=test']

    if target in ['fuzzers', 'sanitizer']:
        flags += ['--with-debug-asserts']

        if target_cc in ['clang', 'gcc']:
            flags += ['--enable-sanitizers=address,undefined']
        else:
            flags += ['--with-sanitizers']

    if target in ['valgrind', 'sanitizer', 'fuzzers']:
        flags += ['--disable-modules=locking_allocator']

    if target == 'parallel':
        flags += ['--with-openmp']

    if target == 'baremetal':
        cc_bin = 'arm-none-eabi-c++'
        flags += ['--cpu=arm32', '--disable-neon', '--without-stack-protector', '--ldflags=-specs=nosys.specs']
        test_cmd = None

    if is_cross_target:
        if target_os == 'ios':
            make_prefix = ['xcrun', '--sdk', 'iphoneos']
            test_cmd = None
            if target == 'cross-arm32':
                flags += ['--cpu=armv7', '--cc-abi-flags=-arch armv7 -arch armv7s -stdlib=libc++']
            elif target == 'cross-arm64':
                flags += ['--cpu=arm64', '--cc-abi-flags=-arch arm64 -stdlib=libc++']
            else:
                raise Exception("Unknown cross target '%s' for iOS" % (target))
        elif target_os == 'android':

            ndk = os.getenv('ANDROID_NDK')
            if ndk is None:
                raise Exception('Android CI build requires ANDROID_NDK env variable be set')

            api_lvl = int(os.getenv('ANDROID_API_LEVEL', '0'))
            if api_lvl == 0:
                # If not set arbitrarily choose API 16 (Android 4.1) for ARMv7 and 28 (Android 9) for AArch64
                api_lvl = 16 if target == 'cross-android-arm32' else 28

            toolchain_dir = os.path.join(ndk, 'toolchains/llvm/prebuilt/linux-x86_64/bin')
            test_cmd = None

            if target == 'cross-android-arm32':
                cc_bin = os.path.join(toolchain_dir, 'armv7a-linux-androideabi%d-clang++' % (api_lvl))
                flags += ['--cpu=armv7',
                          '--ar-command=%s' % (os.path.join(toolchain_dir, 'arm-linux-androideabi-ar'))]
            elif target == 'cross-android-arm64':
                cc_bin = os.path.join(toolchain_dir, 'aarch64-linux-android%d-clang++' % (api_lvl))
                flags += ['--cpu=arm64',
                          '--ar-command=%s' % (os.path.join(toolchain_dir, 'aarch64-linux-android-ar'))]

            if api_lvl < 18:
                flags += ['--without-os-features=getauxval']
            if api_lvl >= 28:
                flags += ['--with-os-features=getentropy']

        elif target == 'cross-i386':
            flags += ['--cpu=x86_32']
        elif target == 'cross-arm32':
            flags += ['--cpu=armv7']
            cc_bin = 'arm-linux-gnueabihf-g++'

        elif target == 'cross-win64':
            # MinGW in 16.04 is lacking std::mutex for unknown reason
            cc_bin = 'x86_64-w64-mingw32-g++'
            flags += ['--cpu=x86_64', '--cc-abi-flags=-static',
                      '--ar-command=x86_64-w64-mingw32-ar', '--without-os-feature=threads']
            test_cmd = [os.path.join(root_dir, 'botan-test.exe')] + test_cmd[1:]
            test_prefix = ['wine']
        else:
            # Build everything but restrict what is run
            test_cmd += essential_tests

            if target == 'cross-arm64':
                flags += ['--cpu=aarch64']
                cc_bin = 'aarch64-linux-gnu-g++'
                test_prefix = ['qemu-aarch64', '-L', '/usr/aarch64-linux-gnu/']
            elif target == 'cross-ppc32':
                flags += ['--cpu=ppc32']
                cc_bin = 'powerpc-linux-gnu-g++'
                test_prefix = ['qemu-ppc', '-L', '/usr/powerpc-linux-gnu/']
            elif target == 'cross-ppc64':
                flags += ['--cpu=ppc64', '--with-endian=little']
                cc_bin = 'powerpc64le-linux-gnu-g++'
                test_prefix = ['qemu-ppc64le', '-cpu', 'POWER8', '-L', '/usr/powerpc64le-linux-gnu/']
            elif target == 'cross-mips64':
                flags += ['--cpu=mips64', '--with-endian=big']
                cc_bin = 'mips64-linux-gnuabi64-g++'
                test_prefix = ['qemu-mips64', '-L', '/usr/mips64-linux-gnuabi64/']
                test_cmd.remove('simd_32') # no SIMD on MIPS
            else:
                raise Exception("Unknown cross target '%s' for Linux" % (target))
    else:
        # Flags specific to native targets

        if target == 'gcc4.8':
            cc_bin = 'g++-4.8'

        if target_os in ['osx', 'linux']:
            flags += ['--with-bzip2', '--with-sqlite', '--with-zlib']

        if target_os in ['osx', 'ios']:
            flags += ['--with-commoncrypto']

        if target_os == 'osx' or target == 'coverage':
            flags += ['--with-boost']

        if target_os == 'windows' and target in ['shared', 'static']:
            # ./configure.py needs extra hand-holding for boost on windows
            boost_root = os.environ.get('BOOST_ROOT')
            boost_libs = os.environ.get('BOOST_LIBRARYDIR')
            boost_system = os.environ.get('BOOST_SYSTEM_LIBRARY')

            if boost_root and boost_libs and boost_system:
                flags += ['--with-boost',
                          '--with-external-includedir', boost_root,
                          '--with-external-libdir', boost_libs,
                          '--boost-library-name', boost_system]

        if target_os == 'linux':
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
        # Avoid putting the revision in build.h, which helps ccache hit rates
        flags += ['--no-store-vc-rev']

    if test_cmd is None:
        run_test_command = None
    else:
        if use_gdb:
            (cmd, args) = test_cmd[0], test_cmd[1:]
            args += ['--skip-tests=os_utils']
            run_test_command = test_prefix + ['gdb', cmd,
                                              '-ex', 'run %s' % (' '.join(args)),
                                              '-ex', 'bt',
                                              '-ex', 'quit']
        else:
            run_test_command = test_prefix + test_cmd

    return flags, run_test_command, make_prefix, install_prefix

def run_cmd(cmd, root_dir):
    """
    Execute a command, die if it failed
    """
    print("Running '%s' ..." % (' '.join(cmd)))
    sys.stdout.flush()

    start = time.time()

    cmd = [os.path.expandvars(elem) for elem in cmd]
    sub_env = os.environ.copy()
    sub_env['LD_LIBRARY_PATH'] = os.path.abspath(root_dir)
    sub_env['DYLD_LIBRARY_PATH'] = os.path.abspath(root_dir)
    sub_env['PYTHONPATH'] = os.path.abspath(os.path.join(root_dir, 'src/python'))
    cwd = None

    redirect_stdout = None
    if len(cmd) >= 3 and cmd[-2] == '>':
        redirect_stdout = open(cmd[-1], 'w')
        cmd = cmd[:-2]
    if len(cmd) > 1 and cmd[0].startswith('indir:'):
        cwd = cmd[0][6:]
        cmd = cmd[1:]
    while len(cmd) > 1 and cmd[0].startswith('env:') and cmd[0].find('=') > 0:
        env_key, env_val = cmd[0][4:].split('=')
        sub_env[env_key] = env_val
        cmd = cmd[1:]

    proc = subprocess.Popen(cmd, cwd=cwd, close_fds=True, env=sub_env, stdout=redirect_stdout)
    proc.communicate()

    time_taken = int(time.time() - start)

    if time_taken > 10:
        print("Ran for %d seconds" % (time_taken))

    if proc.returncode != 0:
        print("Command '%s' failed with error code %d" % (' '.join(cmd), proc.returncode))

        if cmd[0] not in ['lcov']:
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

    parser.add_option('--extra-cxxflags', metavar='FLAGS', default=[], action='append',
                      help='Specify extra build flags')

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

    parser.add_option('--compiler-cache', default=None, metavar='CC',
                      help='Set a compiler cache to use (ccache, sccache, clcache)')

    parser.add_option('--pkcs11-lib', default=None, metavar='LIB',
                      help='Set PKCS11 lib to use for testing')

    parser.add_option('--with-python3', dest='use_python3', action='store_true', default=None,
                      help='Enable using python3')
    parser.add_option('--without-python3', dest='use_python3', action='store_false',
                      help='Disable using python3')

    parser.add_option('--with-pylint3', dest='use_pylint3', action='store_true', default=True,
                      help='Enable using python3 pylint')
    parser.add_option('--without-pylint3', dest='use_pylint3', action='store_false',
                      help='Disable using python3 pylint')

    parser.add_option('--disable-werror', action='store_true', default=False,
                      help='Allow warnings to compile')

    parser.add_option('--run-under-gdb', dest='use_gdb', action='store_true', default=False,
                      help='Run test suite under gdb and capture backtrace')

    return parser.parse_args(args)

def have_prog(prog):
    """
    Check if some named program exists in the path
    """
    for path in os.environ['PATH'].split(os.pathsep):
        exe_file = os.path.join(path, prog)
        if os.path.exists(exe_file) and os.access(exe_file, os.X_OK):
            return True
    return False

def main(args=None):
    # pylint: disable=too-many-branches,too-many-statements,too-many-locals,too-many-return-statements,too-many-locals
    """
    Parse options, do the things
    """

    if os.getenv('COVERITY_SCAN_BRANCH') == '1':
        print('Skipping build COVERITY_SCAN_BRANCH set in environment')
        return 0

    if args is None:
        args = sys.argv
    print("Invoked as '%s'" % (' '.join(args)))
    (options, args) = parse_args(args)

    if len(args) != 2:
        print('Usage: %s [options] target' % (args[0]))
        return 1

    target = args[1]

    use_python2 = have_prog('python2')

    if options.use_python3 is None:
        use_python3 = have_prog('python3')
    else:
        use_python3 = options.use_python3

    py_interp = 'python'
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

    if not os.access(root_dir, os.R_OK):
        raise Exception('Bad root dir setting, dir %s not readable' % (root_dir))

    cmds = []

    if target == 'lint':

        if not use_python2 and not use_python3:
            raise Exception('No python interpreters found cannot lint')

        pylint_rc = '--rcfile=%s' % (os.path.join(root_dir, 'src/configs/pylint.rc'))
        pylint_flags = [pylint_rc, '--reports=no']

        # Some disabled rules specific to Python2
        # superfluous-parens: needed for Python3 compatible print statements
        # too-many-locals: variable counting differs from pylint3
        py2_flags = '--disable=superfluous-parens,too-many-locals'

        # Some disabled rules specific to Python3
        # useless-object-inheritance: complains about code still useful in Python2
        py3_flags = '--disable=useless-object-inheritance'

        py_scripts = [
            'configure.py',
            'src/python/botan2.py',
            'src/scripts/ci_build.py',
            'src/scripts/install.py',
            'src/scripts/ci_check_install.py',
            'src/scripts/dist.py',
            'src/scripts/cleanup.py',
            'src/scripts/check.py',
            'src/scripts/build_docs.py',
            'src/scripts/website.py',
            'src/scripts/bench.py',
            'src/scripts/test_python.py',
            'src/scripts/test_fuzzers.py',
            'src/scripts/test_cli.py',
            'src/scripts/python_unittests.py',
            'src/scripts/python_unittests_unix.py']

        full_paths = [os.path.join(root_dir, s) for s in py_scripts]

        if use_python2:
            cmds.append(['python2', '-m', 'pylint'] + pylint_flags + [py2_flags] + full_paths)

        if use_python3 and options.use_pylint3:
            cmds.append(['python3', '-m', 'pylint'] + pylint_flags + [py3_flags] + full_paths)

    else:
        config_flags, run_test_command, make_prefix, install_prefix = determine_flags(
            target, options.os, options.cpu, options.cc,
            options.cc_bin, options.compiler_cache, root_dir,
            options.pkcs11_lib, options.use_gdb, options.disable_werror,
            options.extra_cxxflags)

        cmds.append([py_interp, os.path.join(root_dir, 'configure.py')] + config_flags)

        make_cmd = [options.make_tool]
        if root_dir != '.':
            make_cmd += ['-C', root_dir]
        if options.build_jobs > 1 and options.make_tool != 'nmake':
            make_cmd += ['-j%d' % (options.build_jobs)]
        make_cmd += ['-k']

        if target == 'docs':
            cmds.append(make_cmd + ['docs'])
        else:

            ccache_show_stats = {
                'ccache': '--show-stats',
                'sccache': '--show-stats',
                'clcache': '-s'
            }

            if options.compiler_cache in ccache_show_stats:
                cmds.append([options.compiler_cache, ccache_show_stats[options.compiler_cache]])

            make_targets = ['libs', 'tests', 'cli']

            if target in ['coverage', 'fuzzers']:
                make_targets += ['tests', 'cli', 'fuzzers', 'fuzzer_corpus_zip']

            if target in ['coverage']:
                make_targets += ['bogo_shim']

            cmds.append(make_prefix + make_cmd + make_targets)

            if options.compiler_cache in ccache_show_stats:
                cmds.append([options.compiler_cache, ccache_show_stats[options.compiler_cache]])

        if run_test_command is not None:
            cmds.append(run_test_command)

        if target == 'coverage':
            runner_dir = os.path.abspath(os.path.join(root_dir, 'boringssl', 'ssl', 'test', 'runner'))

            cmds.append(['indir:%s' % (runner_dir),
                         'go', 'test', '-pipe',
                         '-num-workers', str(4*get_concurrency()),
                         '-shim-path', os.path.abspath(os.path.join(root_dir, 'botan_bogo_shim')),
                         '-shim-config', os.path.abspath(os.path.join(root_dir, 'src', 'bogo_shim', 'config.json'))])

        if target in ['coverage', 'fuzzers']:
            cmds.append([py_interp, os.path.join(root_dir, 'src/scripts/test_fuzzers.py'),
                         os.path.join(root_dir, 'fuzzer_corpus'),
                         os.path.join(root_dir, 'build/fuzzer')])

        if target in ['shared', 'coverage'] and options.os != 'windows':
            botan_exe = os.path.join(root_dir, 'botan-cli.exe' if options.os == 'windows' else 'botan')

            test_scripts = ['test_cli.py', 'test_cli_crypt.py']
            for script in test_scripts:
                cmds.append([py_interp,
                             os.path.join(root_dir, 'src/scripts', script),
                             '--threads=%d' % (options.build_jobs),
                             botan_exe])

        python_tests = os.path.join(root_dir, 'src/scripts/test_python.py')

        if target in ['shared', 'coverage']:

            if options.os == 'windows':
                if options.cpu == 'x86':
                    # Python on AppVeyor is a 32-bit binary so only test for 32-bit
                    cmds.append([py_interp, '-b', python_tests])
            else:
                if use_python2:
                    cmds.append(['python2', '-b', python_tests])
                if use_python3:
                    cmds.append(['python3', '-b', python_tests])

        if target in ['shared', 'static', 'bsi', 'nist']:
            cmds.append(make_cmd + ['install'])
            cmds.append([py_interp, os.path.join(root_dir, 'src/scripts/ci_check_install.py'), install_prefix])

        if target in ['sonar']:

            cmds.append(['llvm-profdata', 'merge', '-sparse', 'default.profraw', '-o', 'botan.profdata'])
            cmds.append(['llvm-cov', 'show', './botan-test',
                         '-instr-profile=botan.profdata',
                         '>', 'build/cov_report.txt'])
            sonar_config = os.path.join(root_dir, 'src/configs/sonar-project.properties')
            cmds.append(['sonar-scanner',
                         '-Dproject.settings=%s' % (sonar_config),
                         '-Dsonar.login=$SONAR_TOKEN'])

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
                             python_tests])

            if have_prog('codecov'):
                # If codecov exists assume we are on Travis and report to codecov.io
                cmds.append(['codecov', '>', 'codecov_stdout.log'])
            else:
                # Otherwise generate a local HTML report
                cmds.append(['genhtml', cov_file, '--output-directory', 'lcov-out'])

        cmds.append(make_cmd + ['clean'])
        cmds.append(make_cmd + ['distclean'])

    for cmd in cmds:
        if options.dry_run:
            print('$ ' + ' '.join(cmd))
        else:
            run_cmd(cmd, root_dir)

    return 0

if __name__ == '__main__':
    sys.exit(main())
