#!/usr/bin/env python3

"""
CI build script
(C) 2017-2022 Jack Lloyd
    2022 René Meusel - Rohde & Schwarz Cybersecurity


Botan is released under the Simplified BSD License (see license.txt)
"""

import os
import platform
import subprocess
import sys
import time
import tempfile
import optparse # pylint: disable=deprecated-module
import multiprocessing
import pathlib

def get_concurrency():
    def_concurrency = 2
    max_concurrency = 16

    try:
        return min(max_concurrency, multiprocessing.cpu_count())
    except ImportError:
        return def_concurrency

def known_targets():
    return [
        'amalgamation',
        'bsi',
        'coverage',
        'cross-android-arm32',
        'cross-android-arm64',
        'cross-arm32',
        'cross-arm32-baremetal',
        'cross-arm64',
        'cross-i386',
        'cross-ios-arm64',
        'cross-mips64',
        'cross-ppc32',
        'cross-ppc64',
        'cross-riscv64',
        'cross-win64',
        'docs',
        'emscripten',
        'examples',
        'fuzzers',
        'lint',
        'minimized',
        'nist',
        'sanitizer',
        'shared',
        'static',
        'valgrind',
    ]

def build_targets(target, target_os):
    if target in ['shared', 'minimized', 'bsi', 'nist']:
        yield 'shared'
    elif target in ['static', 'examples', 'fuzzers', 'cross-arm32-baremetal', 'emscripten']:
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
    if target in ['sanitizer'] and target_os not in ['windows']:
        yield 'bogo_shim'

def determine_flags(target, target_os, target_cpu, target_cc, cc_bin, ccache,
                    root_dir, build_dir, test_results_dir, pkcs11_lib, use_gdb,
                    disable_werror, extra_cxxflags, disabled_tests):
    # pylint: disable=too-many-branches,too-many-statements,too-many-arguments,too-many-locals

    """
    Return the configure.py flags as well as make/test running prefixes
    """
    is_cross_target = target.startswith('cross-')

    if target_os not in ['linux', 'osx', 'windows', 'freebsd']:
        print('Error unknown OS %s' % (target_os))
        return (None, None, None, None)

    if is_cross_target:
        if target_os == 'osx':
            target_os = 'ios'
        elif target == 'cross-win64':
            target_os = 'mingw'
        elif target in ['cross-android-arm32', 'cross-android-arm64']:
            target_os = 'android'

    if target_os == 'windows' and target_cc == 'gcc':
        target_os = 'mingw'

    if target == 'cross-arm32-baremetal':
        target_os = 'none'

    if target == 'emscripten':
        target_os = 'emscripten'

    make_prefix = []
    test_prefix = []
    test_cmd = [os.path.join(build_dir, 'botan-test'),
                '--data-dir=%s' % os.path.join(root_dir, 'src', 'tests', 'data'),
                '--run-memory-intensive-tests']

    # generate JUnit test report
    if test_results_dir:
        if not os.path.isdir(test_results_dir):
            raise Exception("Test results directory does not exist")

        def sanitize_kv(some_string):
            return some_string.replace(':', '').replace(',', '')

        report_props = {"ci_target": target, "os": target_os}

        test_cmd += ['--test-results-dir=%s' % test_results_dir]
        test_cmd += ['--report-properties=%s' %
                     ','.join(['%s:%s' % (sanitize_kv(k), sanitize_kv(v)) for k, v in report_props.items()])]

    install_prefix = tempfile.mkdtemp(prefix='botan-install-')

    flags = ['--prefix=%s' % (install_prefix),
             '--cc=%s' % (target_cc),
             '--os=%s' % (target_os),
             '--build-targets=%s' % ','.join(build_targets(target, target_os)),
             '--with-build-dir=%s' % build_dir]

    if ccache is not None:
        flags += ['--no-store-vc-rev', '--compiler-cache=%s' % (ccache)]

    if not disable_werror:
        flags += ['--werror-mode']

    if target_cpu is not None:
        flags += ['--cpu=%s' % (target_cpu)]

    for flag in extra_cxxflags:
        flags += ['--extra-cxxflags=%s' % (flag)]

    if target in ['minimized']:
        flags += ['--minimized-build', '--enable-modules=system_rng,sha2_32,sha2_64,aes']

    if target in ['amalgamation']:
        flags += ['--amalgamation']

    if target in ['bsi', 'nist']:
        # tls is optional for bsi/nist but add it so verify tests work with these minimized configs
        flags += ['--module-policy=%s' % (target), '--enable-modules=tls12']

    if target == 'docs':
        flags += ['--with-doxygen', '--with-sphinx', '--with-rst2man']
        test_cmd = None

    if target == 'cross-win64':
        # this test compiles under MinGW but fails when run under Wine
        disabled_tests.append('certstor_system')

    if target_os == 'mingw':
        # make sure to link against static versions of libstdc++, libgcc* and winpthread
        flags += ['--ldflags=-static']

    if target == 'coverage':
        flags += ['--with-coverage-info']

    if target in ['coverage']:
        flags += ['--with-debug-info']

    if target in ['coverage', 'sanitizer', 'fuzzers']:
        flags += ['--terminate-on-asserts']

    if target == 'valgrind':
        flags += ['--with-valgrind']
        test_prefix = ['valgrind', '--error-exitcode=9', '-v', '--leak-check=full', '--show-reachable=yes']
        # valgrind is single threaded anyway
        test_cmd += ['--test-threads=1']
        # valgrind is slow
        slow_tests = [
            'cryptobox', 'dh_invalid', 'dh_kat', 'dh_keygen',
            'dl_group_gen', 'dlies', 'dsa_param', 'ecc_basemul',
            'ecdsa_verify_wycheproof', 'mce_keygen', 'passhash9',
            'rsa_encrypt', 'rsa_pss', 'rsa_pss_raw', 'scrypt',
            'srp6_kat', 'x509_path_bsi', 'xmss_keygen', 'xmss_sign',
            'pbkdf', 'argon2', 'bcrypt', 'bcrypt_pbkdf', 'compression',
            'ed25519_sign', 'elgamal_keygen', 'x509_path_rsa_pss']

        disabled_tests += slow_tests

    if target == 'examples':
        flags += ['--with-boost']
        test_cmd = None

    if target == 'fuzzers':
        flags += ['--unsafe-fuzzer-mode']

    if target in ['fuzzers', 'coverage']:
        flags += ['--build-fuzzers=test']

    if target in ['fuzzers', 'sanitizer']:
        flags += ['--with-debug-asserts']

        if target_cc in ['clang', 'gcc']:
            flags += ['--enable-sanitizers=address,undefined']
        else:
            flags += ['--enable-sanitizers=address']

    if target in ['valgrind', 'sanitizer', 'fuzzers']:
        flags += ['--disable-modules=locking_allocator']

    if target == 'emscripten':
        flags += ['--cpu=wasm']
        # need to find a way to run the wasm-compiled tests w/o a browser
        test_cmd = None

    if is_cross_target:
        if target_os == 'ios':
            make_prefix = ['xcrun', '--sdk', 'iphoneos']
            test_cmd = None
            if target == 'cross-ios-arm64':
                flags += ['--cpu=arm64', '--cc-abi-flags=-arch arm64 -stdlib=libc++']
            else:
                raise Exception("Unknown cross target '%s' for iOS" % (target))
        elif target_os == 'android':

            ndk_version = os.getenv('ANDROID_NDK_VERSION')
            if ndk_version is None:
                raise Exception('Android CI build requires ANDROID_NDK_VERSION env variable be set')

            ndk_root = os.getenv('ANDROID_SDK_ROOT')
            if ndk_root is None:
                raise Exception('Android CI build requires ANDROID_SDK_ROOT env variable be set')

            ndks = list(pathlib.Path(ndk_root).glob('ndk/%s.*' % ndk_version))
            if len(ndks) == 0:
                raise Exception('Android CI build did not find NDK with version %s' % ndk_version)
            if len(ndks) > 1:
                raise Exception('Android CI build did find multiple NDKs with version: %s' % ndk_version)

            ndk = ndks[0]

            api_lvl = int(os.getenv('ANDROID_API_LEVEL', '0'))
            if api_lvl == 0:
                # If not set arbitrarily choose API 19 (Android 4.4) for ARMv7 and 28 (Android 9) for AArch64
                api_lvl = 19 if target == 'cross-android-arm32' else 28

            toolchain_dir = os.path.join(ndk, 'toolchains/llvm/prebuilt/linux-x86_64/bin')
            test_cmd = None

            if target == 'cross-android-arm32':
                cc_bin = os.path.join(toolchain_dir, 'armv7a-linux-androideabi%d-clang++' % (api_lvl))
                flags += ['--cpu=armv7',
                          '--ar-command=%s' % (os.path.join(toolchain_dir, 'llvm-ar'))]
            elif target == 'cross-android-arm64':
                cc_bin = os.path.join(toolchain_dir, 'aarch64-linux-android%d-clang++' % (api_lvl))
                flags += ['--cpu=arm64',
                          '--ar-command=%s' % (os.path.join(toolchain_dir, 'llvm-ar'))]

            if api_lvl < 18:
                flags += ['--without-os-features=getauxval']
            if api_lvl >= 28:
                flags += ['--with-os-features=getentropy']

        elif target == 'cross-i386':
            flags += ['--cpu=x86_32']

        elif target == 'cross-win64':
            # MinGW in 16.04 is lacking std::mutex for unknown reason
            cc_bin = 'x86_64-w64-mingw32-g++'
            flags += ['--cpu=x86_64', '--cc-abi-flags=-static',
                      '--ar-command=x86_64-w64-mingw32-ar', '--without-os-feature=threads']
            test_cmd = [os.path.join(root_dir, 'botan-test.exe')] + test_cmd[1:]
            test_prefix = ['wine']
        else:
            if target == 'cross-arm32':
                flags += ['--cpu=armv7', '--extra-cxxflags=-D_FILE_OFFSET_BITS=64']
                cc_bin = 'arm-linux-gnueabihf-g++'
                test_prefix = ['qemu-arm', '-L', '/usr/arm-linux-gnueabihf/']
            elif target == 'cross-arm64':
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
                test_prefix = ['qemu-ppc64le', '-cpu', 'power10', '-L', '/usr/powerpc64le-linux-gnu/']
            elif target == 'cross-riscv64':
                flags += ['--cpu=riscv64']
                cc_bin = 'riscv64-linux-gnu-g++'
                test_prefix = ['qemu-riscv64', '-L', '/usr/riscv64-linux-gnu/']
            elif target == 'cross-mips64':
                flags += ['--cpu=mips64', '--with-endian=big']
                cc_bin = 'mips64-linux-gnuabi64-g++'
                test_prefix = ['qemu-mips64', '-L', '/usr/mips64-linux-gnuabi64/']
                test_cmd.remove('simd_32') # no SIMD on MIPS
            elif target in ['cross-arm32-baremetal']:
                flags += ['--cpu=arm32', '--disable-neon', '--without-stack-protector', '--ldflags=-specs=nosys.specs']
                cc_bin = 'arm-none-eabi-c++'
                test_cmd = None
            else:
                raise Exception("Unknown cross target '%s' for Linux" % (target))
    else:
        # Flags specific to native targets

        if target_os in ['osx', 'linux']:
            flags += ['--with-bzip2', '--with-sqlite', '--with-zlib']

        if target_os in ['osx', 'ios']:
            flags += ['--with-commoncrypto']

        def add_boost_support(target, target_os):
            if target in ['coverage', 'shared']:
                return True

            if target == 'sanitizer' and target_os == 'linux':
                return True

            return False

        if add_boost_support(target, target_os):
            flags += ['--with-boost']
            if target_cc == 'clang':
                # make sure clang ignores warnings in boost headers
                flags += ["--extra-cxxflags=--system-header-prefix=boost/"]

            if target_os in ['windows', 'mingw']:
                # ./configure.py needs boost's location on Windows
                if 'BOOST_INCLUDEDIR' in os.environ:
                    flags += ['--with-external-includedir', os.environ.get('BOOST_INCLUDEDIR')]

            if target_os == 'mingw':
                # apparently mingw needs this legacy socket library version for reasons
                # as per: https://stackoverflow.com/questions/38770895/how-to-fix-undefined-reference-to-getacceptexsockaddrs-boost-asio-in-clion#comment105791579_38771260
                flags += ['--ldflags=-static -lwsock32']

        if target_os == 'linux':
            flags += ['--with-lzma']

        if target in ['coverage']:
            flags += ['--with-tpm']
            test_cmd += ['--run-online-tests']
            if pkcs11_lib and os.access(pkcs11_lib, os.R_OK):
                test_cmd += ['--pkcs11-lib=%s' % (pkcs11_lib)]

    if target in ['coverage', 'sanitizer']:
        test_cmd += ['--run-long-tests']

        if target_os == 'windows' and target == 'sanitizer':
            # GitHub Actions worker intermittently ran out of memory when
            # asked to allocate multi-gigabyte buffers under MSVC's ASan.
            test_cmd.remove('--run-memory-intensive-tests')

            # MSVC sanitizer produces very slow code causing some of the
            # slower tests to take as long as 5 minutes
            test_cmd.remove('--run-long-tests')

    flags += ['--cc-bin=%s' % (cc_bin)]

    if test_cmd is None:
        run_test_command = None
    else:
        if use_gdb:
            disabled_tests.append("os_utils")

        # render 'disabled_tests' array into test_cmd
        if disabled_tests:
            test_cmd += ['--skip-tests=%s' % (','.join(disabled_tests))]

        if use_gdb:
            (cmd, args) = test_cmd[0], test_cmd[1:]
            run_test_command = test_prefix + ['gdb', cmd,
                                              '-ex', 'run %s' % (' '.join(args)),
                                              '-ex', 'bt',
                                              '-ex', 'quit']
        else:
            run_test_command = test_prefix + test_cmd

    return flags, run_test_command, make_prefix, install_prefix

def run_cmd(cmd, root_dir, build_dir):
    """
    Execute a command, die if it failed
    """
    print("Running '%s' ..." % (' '.join(cmd)))
    sys.stdout.flush()

    start = time.time()

    cmd = [os.path.expandvars(elem) for elem in cmd]
    sub_env = os.environ.copy()
    sub_env['LD_LIBRARY_PATH'] = os.path.abspath(build_dir)
    sub_env['DYLD_LIBRARY_PATH'] = os.path.abspath(build_dir)
    sub_env['PYTHONPATH'] = os.path.abspath(os.path.join(root_dir, 'src/python'))
    cwd = None

    redirect_stdout = None
    if len(cmd) >= 3 and cmd[-2] == '>':
        redirect_stdout = open(cmd[-1], 'w', encoding='utf8')
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

def default_os():
    platform_os = platform.system().lower()
    if platform_os == 'darwin':
        return 'osx'
    return platform_os

def parse_args(args):
    """
    Parse arguments
    """
    parser = optparse.OptionParser()

    parser.add_option('--os', default=default_os(),
                      help='Set the target os (default %default)')
    parser.add_option('--cpu', default=None,
                      help='Specify a target CPU platform')
    parser.add_option('--cc', default='gcc',
                      help='Set the target compiler type (default %default)')
    parser.add_option('--cc-bin', default=None,
                      help='Set path to compiler')
    parser.add_option('--root-dir', metavar='D', default='.',
                      help='Set directory to execute from (default %default)')
    parser.add_option('--build-dir', metavar='D', default='.',
                      help='Set directory to place build artifacts into (default %default)')
    parser.add_option('--boringssl-dir', metavar='D', default='boringssl',
                      help='Set directory of BoringSSL checkout to use for BoGo tests')

    parser.add_option('--make-tool', metavar='TOOL', default='make',
                      help='Specify tool to run to build source (default %default)')

    parser.add_option('--extra-cxxflags', metavar='FLAGS', default=[], action='append',
                      help='Specify extra build flags')

    parser.add_option('--disabled-tests', metavar='DISABLED_TESTS', default=[], action='append',
                      help='Comma separated list of tests that should not be run')

    parser.add_option('--dry-run', action='store_true', default=False,
                      help='Just show commands to be executed')
    parser.add_option('--build-jobs', metavar='J', default=get_concurrency(),
                      help='Set number of jobs to run in parallel (default %default)')

    parser.add_option('--compiler-cache', default=None, metavar='CC',
                      help='Set a compiler cache to use (ccache, sccache)')

    parser.add_option('--pkcs11-lib', default=os.getenv('PKCS11_LIB'), metavar='LIB',
                      help='Set PKCS11 lib to use for testing')

    parser.add_option('--disable-werror', action='store_true', default=False,
                      help='Allow warnings to compile')

    parser.add_option('--run-under-gdb', dest='use_gdb', action='store_true', default=False,
                      help='Run test suite under gdb and capture backtrace')

    parser.add_option('--test-results-dir', default=None,
                      help='Directory to store JUnit XML test reports')

    return parser.parse_args(args)

def have_prog(prog):
    """
    Check if some named program exists in the path
    """
    for path in os.environ['PATH'].split(os.pathsep):
        exe_file = os.path.join(path, prog)
        for ef in [exe_file, exe_file + ".exe"]:
            if os.path.exists(ef) and os.access(ef, os.X_OK):
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

    if target not in known_targets():
        print("Unknown target '%s'" % (target))
        return 2

    py_interp = 'python3'
    if options.cc_bin is None:
        if options.cc == 'gcc':
            options.cc_bin = 'g++'
        elif options.cc == 'clang':
            options.cc_bin = 'clang++'
        elif options.cc == 'msvc':
            options.cc_bin = 'cl'
        elif options.cc == "emcc":
            options.cc_bin = "em++"
        else:
            print('Error unknown compiler %s' % (options.cc))
            return 1

    if options.compiler_cache is None:
        # Autodetect compiler cache
        if have_prog('sccache'):
            options.compiler_cache = 'sccache'
        elif have_prog('ccache'):
            options.compiler_cache = 'ccache'
        if options.compiler_cache:
            print("Found '%s' installed, will use it..." % (options.compiler_cache))

    if options.compiler_cache not in [None, 'ccache', 'sccache']:
        raise Exception("Don't know about %s as a compiler cache" % (options.compiler_cache))

    root_dir = options.root_dir
    build_dir = options.build_dir

    if not os.access(root_dir, os.R_OK):
        raise Exception('Bad root dir setting, dir %s not readable' % (root_dir))
    if not os.path.exists(build_dir):
        os.makedirs(build_dir)
    elif not os.path.isdir(build_dir) or not os.access(build_dir, os.R_OK | os.W_OK):
        raise Exception("Bad build dir setting %s is not a directory or not accessible" % (build_dir))

    cmds = []

    if target == 'lint':

        pylint_rc = '--rcfile=%s' % (os.path.join(root_dir, 'src/configs/pylint.rc'))
        pylint_flags = [pylint_rc, '--reports=no']

        py_scripts = [
            'configure.py',
            'src/python/botan3.py',
            'src/scripts/ci_build.py',
            'src/scripts/install.py',
            'src/scripts/ci_check_headers.py',
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
            'src/scripts/python_unittests_unix.py',
            'src/editors/sublime/build.py',
            'src/editors/vscode/scripts/bogo.py',
            'src/editors/vscode/scripts/common.py',
            'src/editors/vscode/scripts/test.py']

        full_paths = [os.path.join(root_dir, s) for s in py_scripts]
        cmds.append([py_interp, '-m', 'pylint'] + pylint_flags + full_paths)

    else:
        if options.test_results_dir:
            os.makedirs(options.test_results_dir)

        config_flags, run_test_command, make_prefix, install_prefix = determine_flags(
            target, options.os, options.cpu, options.cc, options.cc_bin,
            options.compiler_cache, root_dir, build_dir, options.test_results_dir,
            options.pkcs11_lib, options.use_gdb, options.disable_werror,
            options.extra_cxxflags, options.disabled_tests)

        cmds.append([py_interp, os.path.join(root_dir, 'configure.py')] + config_flags)

        if options.make_tool == '':
            options.make_tool = 'make'

        make_cmd = [options.make_tool]
        if build_dir != '.':
            make_cmd = ['indir:%s' % build_dir] + make_cmd
        if options.build_jobs > 1 and options.make_tool != 'nmake':
            make_cmd += ['-j%d' % (options.build_jobs)]

        make_cmd += ['-k']

        if target == 'docs':
            cmds.append(make_cmd + ['docs'])
        else:
            if options.compiler_cache is not None:
                cmds.append([options.compiler_cache, '--show-stats'])

            make_targets = ['libs', 'tests', 'cli']

            if target in ['coverage', 'fuzzers']:
                make_targets += ['fuzzer_corpus_zip', 'fuzzers']

            if target in ['coverage', 'sanitizer'] and options.os not in ['windows']:
                make_targets += ['bogo_shim']

            cmds.append(make_prefix + make_cmd + make_targets)

            if options.compiler_cache is not None:
                cmds.append([options.compiler_cache, '--show-stats'])

        if run_test_command is not None:
            cmds.append(run_test_command)

        if target in ['coverage', 'sanitizer'] and options.os != 'windows':
            if not options.boringssl_dir:
                raise Exception('coverage build needs --boringssl-dir')

            runner_dir = os.path.abspath(os.path.join(options.boringssl_dir, 'ssl', 'test', 'runner'))

            cmds.append(['indir:%s' % (runner_dir),
                         'go', 'test', '-pipe',
                         '-num-workers', str(4*get_concurrency()),
                         '-shim-path', os.path.abspath(os.path.join(build_dir, 'botan_bogo_shim')),
                         '-shim-config', os.path.abspath(os.path.join(root_dir, 'src', 'bogo_shim', 'config.json'))])

        if target in ['coverage', 'fuzzers']:
            cmds.append([py_interp, os.path.join(root_dir, 'src/scripts/test_fuzzers.py'),
                         os.path.join(build_dir, 'fuzzer_corpus'),
                         os.path.join(build_dir, 'build/fuzzer')])

        if target in ['shared', 'coverage', 'sanitizer'] and options.os != 'windows':
            botan_exe = os.path.join(build_dir, 'botan-cli.exe' if options.os == 'windows' else 'botan')

            args = ['--threads=%d' % (options.build_jobs)]
            if target in ['coverage']:
                args.append('--run-slow-tests')
            if root_dir != '.':
                args.append('--test-data-dir=%s' % root_dir)
            test_scripts = ['test_cli.py', 'test_cli_crypt.py']
            for script in test_scripts:
                test_data_arg = []
                cmds.append([py_interp, os.path.join(root_dir, 'src/scripts', script)] +
                            args + test_data_arg + [botan_exe])

        python_tests = [os.path.join(root_dir, 'src/scripts/test_python.py')]
        if root_dir != '.':
            python_tests.append('--test-data-dir=%s' % root_dir)

        if target in ['shared', 'coverage'] and not (options.os == 'windows' and options.cpu == 'x86'):
            cmds.append([py_interp, '-b'] + python_tests)

        if target in ['shared', 'static', 'bsi', 'nist']:
            cmds.append(make_cmd + ['install'])
            build_config = os.path.join(build_dir, 'build', 'build_config.json')
            cmds.append([py_interp, os.path.join(root_dir, 'src/scripts/ci_check_install.py'), build_config])
            cmds.append([py_interp, os.path.join(root_dir, 'src/scripts/ci_check_headers.py'), build_config])

        if target in ['examples']:
            cmds.append(make_cmd + ['install'])
            cmds.append([options.make_tool, '-C', os.path.join(root_dir, 'src/examples'),
                         'INCLUDES=-I %s/include/botan-3' % (install_prefix),
                         'BUILD_DIR_LINK_PATH=-L%s/lib' % (install_prefix)])

        if target in ['coverage']:
            if not have_prog('lcov'):
                print('Error: lcov not found in PATH (%s)' % (os.getenv('PATH')))
                return 1

            if not have_prog('gcov'):
                print('Error: gcov not found in PATH (%s)' % (os.getenv('PATH')))
                return 1

            cov_file = os.path.join(build_dir, 'coverage.info')
            raw_cov_file = os.path.join(build_dir, 'coverage.info.raw')

            cmds.append(['lcov', '--capture', '--directory', build_dir,
                         '--output-file', raw_cov_file])
            cmds.append(['lcov', '--remove', raw_cov_file, '/usr/*', '--output-file', cov_file])
            cmds.append(['lcov', '--list', cov_file])

            if have_prog('coverage'):
                cmds.append(['coverage', 'run', '--branch',
                             '--rcfile', os.path.join(root_dir, 'src/configs/coverage.rc')] +
                            python_tests)

            if have_prog('codecov'):
                # If codecov exists assume we are in CI and report to codecov.io
                cmds.append(['indir:%s' % root_dir, 'codecov', '--required', '--gcov-root', build_dir, '>', os.path.join(build_dir, 'codecov_stdout.log')])
            else:
                # Otherwise generate a local HTML report
                cmds.append(['genhtml', cov_file, '--output-directory', os.path.join(build_dir, 'lcov-out')])

        cmds.append(make_cmd + ['clean'])
        cmds.append(make_cmd + ['distclean'])

    for cmd in cmds:
        if options.dry_run:
            print('$ ' + ' '.join(cmd))
        else:
            run_cmd(cmd, root_dir, build_dir)

    return 0

if __name__ == '__main__':
    sys.exit(main())
