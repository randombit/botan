#!/usr/bin/env python3

"""
CI build script
(C) 2017-2022 Jack Lloyd
    2022-2023 René Meusel - Rohde & Schwarz Cybersecurity


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
        'codeql',
        'coverage',
        'cross-alpha',
        'cross-android-arm32',
        'cross-android-arm64',
        'cross-android-arm64-amalgamation',
        'cross-arm32',
        'cross-arm32-baremetal',
        'cross-arm64',
        'cross-arm64-amalgamation',
        'cross-hppa64',
        'cross-i386',
        'cross-ios-arm64',
        'cross-loongarch64',
        'cross-m68k',
        'cross-mips',
        'cross-mips64',
        'cross-ppc32',
        'cross-ppc64',
        'cross-riscv64',
        'cross-s390x',
        'cross-sh4',
        'cross-sparc64',
        'cross-win64',
        'docs',
        'emscripten',
        'examples',
        'format',
        'fuzzers',
        'hybrid-tls13-interop-test',
        'lint',
        'limbo',
        'minimized',
        'nist',
        'no_pcurves',
        'policy-bsi',
        'policy-fips140',
        'policy-modern',
        'sanitizer',
        'sde',
        'shared',
        'static',
        'strubbing',
        'typos',
        'valgrind',
        'valgrind-full',
        'valgrind-ct',
        'valgrind-ct-full',
    ]

def is_running_in_github_actions():
    return os.environ.get("GITHUB_ACTIONS", "false") == "true"

class LoggingGroup:
    """
    Context Manager that opportunistically uses GitHub Actions workflow commands
    to group all log output inside the managed context into an expandable group.
    """

    def __init__(self, group_title):
        self.group_title = group_title
        self.start_time = time.time()

    def __enter__(self):
        if is_running_in_github_actions():
            print("::group::%s" % self.group_title)
        else:
            print("Running '%s' ..." % self.group_title)

        sys.stdout.flush()

    def __exit__(self, exc_type, exc_value, exc_tb):
        time_taken = int(time.time() - self.start_time)

        if is_running_in_github_actions():
            print("::endgroup::")

        if time_taken > 10:
            print("> Running '%s' took %d seconds" % (self.group_title, time_taken))

def build_targets(target, target_os):
    if target in ['shared', 'minimized', 'examples', 'limbo'] or target.startswith('policy-'):
        yield 'shared'
    elif target in ['static', 'fuzzers', 'cross-arm32-baremetal', 'emscripten', 'strubbing']:
        yield 'static'
    elif target_os in ['windows']:
        yield 'shared'
    elif target_os in ['ios', 'mingw']:
        yield 'static'
    else:
        yield 'shared'
        yield 'static'

    if target not in ['examples', 'limbo']:
        yield 'cli'

    if target not in ['examples', 'limbo', 'hybrid-tls13-interop-test', 'strubbing']:
        yield 'tests'

    if target in ['coverage']:
        yield 'bogo_shim'
    if target in ['sanitizer'] and target_os not in ['windows']:
        yield 'bogo_shim'
    if target in ['examples', 'amalgamation']:
        yield 'examples'
    if target in ['valgrind', 'valgrind-full', 'valgrind-ct', 'valgrind-ct-full']:
        yield 'ct_selftest'

def make_targets(target, target_os):
    # The result of build_targets() is for ./configure.py --build-targets='...'.
    # make_targets() go into `make/ninja ...` and they are mostly equal. Except
    # for 'libs' which is an umbrella target for 'static' and 'shared'.
    tgts = [tgt if tgt not in ['static', 'shared'] else 'libs' for tgt in build_targets(target, target_os)]
    if target in ['coverage', 'fuzzers']:
        # These are special targets not found in ./configure.py --build-targets=
        tgts += ['fuzzers', 'fuzzer_corpus_zip']
    return list(set(tgts))

def determine_flags(target, target_os, target_cpu, target_cc, cc_bin, ccache,
                    root_dir, build_dir, test_results_dir, pkcs11_lib, use_gdb,
                    disable_werror, extra_cxxflags, custom_optimization_flags, disabled_tests):

    """
    Return the configure.py flags as well as make/test running prefixes
    """
    is_cross_target = target.startswith('cross-')

    if target_os not in ['linux', 'osx', 'windows', 'freebsd']:
        print('Error unknown OS %s' % (target_os))
        return (None, None, None)

    if is_cross_target:
        if target_os == 'osx':
            target_os = 'ios'
        elif target == 'cross-win64':
            target_os = 'mingw'
        elif target in ['cross-android-arm32', 'cross-android-arm64', 'cross-android-arm64-amalgamation']:
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


    flags = ['--cc=%s' % (target_cc),
             '--os=%s' % (target_os),
             '--build-targets=%s' % ','.join(build_targets(target, target_os)),
             '--with-build-dir=%s' % build_dir,
             '--link-method=symlink',
             '--enable-experimental-features']

    if target in ['shared', 'static']:
        install_prefix = tempfile.mkdtemp(prefix='botan-install-')
        flags += ['--prefix=%s' % (install_prefix)]

    if ccache is not None:
        flags += ['--compiler-cache=%s' % (ccache)]

    if not disable_werror:
        flags += ['--werror-mode']

    if target_cpu is not None:
        flags += ['--cpu=%s' % (target_cpu)]

    if custom_optimization_flags and any(flag for flag in custom_optimization_flags):
        flags += ['--no-optimizations']
        for flag in custom_optimization_flags:
            flags += ['--extra-cxxflags=%s' % (flag)]

    for flag in extra_cxxflags:
        flags += ['--extra-cxxflags=%s' % (flag)]

    if target_os == 'windows':
        # Workaround for https://github.com/actions/runner-images/issues/10004
        flags += ['--extra-cxxflags=/D_DISABLE_CONSTEXPR_MUTEX_CONSTRUCTOR']

    if target in ['minimized']:
        flags += ['--minimized-build', '--enable-modules=system_rng,sha2*,aes']

    if target in ['no_pcurves']:
        flags += ['--disable-modules=pcurves_impl']

    if target in ['amalgamation', 'cross-arm64-amalgamation', 'cross-android-arm64-amalgamation']:
        flags += ['--amalgamation']

    if target.startswith('policy-'):
        # tls is optional for bsi/fips140 but add it so verify tests work with these minimized configs
        flags += ['--module-policy=%s' % (target.replace('policy-', '')), '--enable-modules=tls12,tls13', '--disable-deprecated-features']

    if target in ['docs']:
        flags += ['--with-doxygen', '--with-sphinx', '--with-rst2man']
    else:
        flags += ['--without-doc']

    if target in ['docs', 'codeql', 'hybrid-tls13-interop-test', 'limbo']:
        test_cmd = None

    if target in ['codeql']:
        flags += ['--no-optimizations']

    if target == 'cross-win64':
        # this test compiles under MinGW but fails when run under Wine
        disabled_tests.append('certstor_system')

    if target_os == 'mingw':
        # make sure to link against static versions of libstdc++, libgcc* and winpthread
        flags += ['--ldflags=-static']

    if target == 'coverage':
        flags += ['--with-coverage-info']

    if target in ['coverage', 'valgrind', 'valgrind-full', 'valgrind-ct', 'valgrind-ct-full']:
        flags += ['--with-debug-info']

    if target in ['strubbing']:
        # Stack scrubbing tests are based on scripted gdb runs and won't work on
        # an optimized build unfortunately.
        flags += ['--debug-mode']
        test_cmd = None

    if target in ['coverage', 'sanitizer', 'fuzzers']:
        flags += ['--unsafe-terminate-on-asserts', '--enable-modules=tls_null']

    if target in ['sde']:
        test_prefix = ['sde', '-future', '--']

    if target in ['valgrind', 'valgrind-full', 'valgrind-ct', 'valgrind-ct-full']:
        flags += ['--with-valgrind']
        # valgrind is run via a script setup later
        test_cmd = None

    if target == 'examples':
        flags += ['--with-boost']
        test_cmd = None

    if target == 'fuzzers':
        flags += ['--unsafe-fuzzer-mode']

    if target in ['fuzzers', 'coverage']:
        flags += ['--build-fuzzers=test']

    if target in ['fuzzers', 'sanitizer']:
        flags += ['--with-debug-asserts']

        if target_cc in ['clang', 'gcc', 'xcode']:
            flags += ['--enable-sanitizers=address,undefined,iterator']
        else:
            flags += ['--enable-sanitizers=address,iterator']

    if target in ['valgrind', 'valgrind-full', 'valgrind-ct', 'valgrind-ct-full', 'sanitizer', 'fuzzers']:
        flags += ['--disable-modules=locking_allocator']

    if target == 'emscripten':
        flags += ['--cpu=wasm']
        # need to find a way to run the wasm-compiled tests w/o a browser
        test_cmd = None

    if target in ['sanitizer', 'strubbing'] and target_cc in ['gcc']:
        # Stack scrubbing is supported on GCC 14 and newer, only. This is newer
        # than the current default compiler on GHA's Linux image (ubuntu 24.04).
        # The CI setup has to ensure that we are configured to use a recent
        # compiler for these targets, otherwise `./configure.py` will fail.
        flags += ['--enable-stack-scrubbing']

    if is_cross_target:
        if target_os == 'ios':
            make_prefix = ['xcrun', '--sdk', 'iphoneos']
            test_cmd = None
            if target == 'cross-ios-arm64':
                flags += ['--cpu=arm64', '--cc-abi-flags=-arch arm64 -stdlib=libc++']
            else:
                raise Exception("Unknown cross target '%s' for iOS" % (target))
        elif target_os == 'android':

            ndk = os.getenv('ANDROID_NDK')
            if ndk is None:
                raise Exception('Android CI build requires ANDROID_NDK env variable be set')

            api_lvl = int(os.getenv('ANDROID_API_LEVEL', '0'))
            if api_lvl == 0:
                # If not set arbitrarily choose API 21 (Android 5.0) for ARMv7 and 31 (Android 12) for AArch64
                api_lvl = 21 if target == 'cross-android-arm32' else 31

            toolchain_dir = os.path.join(ndk, 'toolchains/llvm/prebuilt/linux-x86_64/bin')
            test_cmd = None

            if target == 'cross-android-arm32':
                cc_bin = os.path.join(toolchain_dir, 'armv7a-linux-androideabi%d-clang++' % (api_lvl))
                flags += ['--cpu=armv7',
                          '--ar-command=%s' % (os.path.join(toolchain_dir, 'llvm-ar'))]
            elif target in ['cross-android-arm64', 'cross-android-arm64-amalgamation']:
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
            elif target in ['cross-arm64', 'cross-arm64-amalgamation']:
                flags += ['--cpu=aarch64']
                cc_bin = 'aarch64-linux-gnu-g++'
                test_prefix = ['qemu-aarch64', '-L', '/usr/aarch64-linux-gnu/']
            elif target == 'cross-alpha':
                flags += ['--cpu=alpha']
                cc_bin = 'alpha-linux-gnu-g++'
                test_prefix = ['qemu-alpha', '-L', '/usr/alpha-linux-gnu/']
                flags += ['--without-stack-protector'] # not supported
            elif target == 'cross-sh4':
                flags += ['--cpu=sh4']
                cc_bin = 'sh4-linux-gnu-g++'
                test_prefix = ['qemu-sh4', '-L', '/usr/sh4-linux-gnu/']
            elif target == 'cross-m68k':
                flags += ['--cpu=m68k']
                cc_bin = 'm68k-linux-gnu-g++'
                test_prefix = ['qemu-m68k', '-L', '/usr/m68k-linux-gnu/']
            elif target == 'cross-hppa64':
                flags += ['--cpu=hppa']
                cc_bin = 'hppa-linux-gnu-g++'
                test_prefix = ['qemu-hppa', '-L', '/usr/hppa-linux-gnu/']
            elif target == 'cross-sparc64':
                flags += ['--cpu=sparc64']
                cc_bin = 'sparc64-linux-gnu-g++'
                test_prefix = ['qemu-sparc64', '-L', '/usr/sparc64-linux-gnu/']
            elif target == 'cross-ppc32':
                flags += ['--cpu=ppc32']
                cc_bin = 'powerpc-linux-gnu-g++'
                test_prefix = ['qemu-ppc', '-L', '/usr/powerpc-linux-gnu/']
                test_cmd = None # qemu crashes ...
            elif target == 'cross-ppc64':
                flags += ['--cpu=ppc64']
                cc_bin = 'powerpc64le-linux-gnu-g++'
                test_prefix = ['qemu-ppc64le', '-cpu', 'power10', '-L', '/usr/powerpc64le-linux-gnu/']
            elif target == 'cross-riscv64':
                flags += ['--cpu=riscv64']
                cc_bin = 'riscv64-linux-gnu-g++'
                test_prefix = ['qemu-riscv64', '-L', '/usr/riscv64-linux-gnu/']
            elif target == 'cross-s390x':
                flags += ['--cpu=s390x']
                cc_bin = 's390x-linux-gnu-g++'
                test_prefix = ['qemu-s390x', '-L', '/usr/s390x-linux-gnu/']
            elif target == 'cross-loongarch64':
                flags += ['--cpu=loongarch64']
                cc_bin = 'loongarch64-linux-gnu-g++-14'
                test_prefix = ['qemu-loongarch64', '-L', '/usr/loongarch64-linux-gnu/']
            elif target == 'cross-mips':
                flags += ['--cpu=mips32']
                cc_bin = 'mips-linux-gnu-g++'
                test_prefix = ['qemu-mips', '-L', '/usr/mips-linux-gnu/']
            elif target == 'cross-mips64':
                flags += ['--cpu=mips64']
                cc_bin = 'mips64-linux-gnuabi64-g++'
                test_prefix = ['qemu-mips64', '-L', '/usr/mips64-linux-gnuabi64/']
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
            if target in ['coverage', 'amalgamation']:
                return True

            if target == 'sanitizer' and target_os == 'linux':
                return True

            if target == 'shared' and target_os != 'windows':
                return True

            return False

        if add_boost_support(target, target_os):
            flags += ['--with-boost']
            if target_cc in ['clang', 'xcode']:
                # make sure clang ignores warnings in boost headers
                flags += ["--extra-cxxflags=--system-header-prefix=boost/"]

            if 'BOOST_INCLUDEDIR' in os.environ:
                # ./configure.py needs boost's location on some platforms
                # BOOST_INCLUDEDIR is set by the setup_gh_actions.* script
                flags += ['--with-external-includedir', os.environ.get('BOOST_INCLUDEDIR')]

            if target_os == 'mingw':
                # apparently mingw needs this legacy socket library version for reasons
                # as per: https://stackoverflow.com/questions/38770895/how-to-fix-undefined-reference-to-getacceptexsockaddrs-boost-asio-in-clion#comment105791579_38771260
                flags += ['--ldflags=-static -lwsock32']

        if target_os == 'linux':
            flags += ['--with-lzma']

        if is_running_in_github_actions() and 'BOTAN_TPM2_ENABLED' in os.environ:
            flags += ['--with-tpm2']

            if os.environ.get('BOTAN_TPM2_ENABLED') == 'test':
                # run the TPM2 tests
                test_cmd += ["--tpm2-tcti-name=%s" % os.getenv('BOTAN_TPM2_TCTI_NAME'),
                             "--tpm2-tcti-conf=%s" % os.getenv('BOTAN_TPM2_TCTI_CONF'),
                             "--tpm2-persistent-rsa-handle=%s" % os.getenv('BOTAN_TPM2_PERSISTENT_RSA_KEY_HANDLE'),
                             "--tpm2-persistent-ecc-handle=%s" % os.getenv('BOTAN_TPM2_PERSISTENT_ECC_KEY_HANDLE'),
                             "--tpm2-persistent-auth-value=%s" % os.getenv('BOTAN_TPM2_PERSISTENT_KEY_AUTH_VALUE')]
            elif os.environ.get('BOTAN_TPM2_ENABLED') == 'build':
                # build the TPM2 module but don't run the tests
                # TCTI name 'disabled' is a special value that disables the TPM2 tests
                #
                # TODO: This is a hack. It would be great if `./botan-test --skip-tests=`
                #       would also work for test categories like `tpm2`. Currently it
                #       only works for individual test names.
                test_cmd += ["--tpm2-tcti-name=disabled"]

        if is_running_in_github_actions():
            if 'BOTAN_BUILD_WITH_JITTERENTROPY' in os.environ:
                flags += ['--enable-modules=jitter_rng']
            if 'BOTAN_BUILD_WITH_ESDM' in os.environ:
                flags += ['--with-esdm_rng']

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

    if os.getenv('CXX') is None:
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

    return flags, run_test_command, make_prefix

def run_cmd(cmd, root_dir, build_dir):
    """
    Execute a command, die if it failed
    """

    with LoggingGroup(' '.join(cmd)):
        cmd = [os.path.expandvars(elem) for elem in cmd]
        sub_env = os.environ.copy()
        sub_env['LD_LIBRARY_PATH'] = os.path.abspath(build_dir)
        sub_env['DYLD_LIBRARY_PATH'] = os.path.abspath(build_dir)
        sub_env['PYTHONPATH'] = os.path.abspath(os.path.join(root_dir, 'src/python'))
        cwd = None

        redirect_stdout_fd = None
        redirect_stdout_fsname = None

        if len(cmd) >= 3 and cmd[-2] == '>':
            redirect_stdout_fsname = cmd[-1]
            redirect_stdout_fd = open(redirect_stdout_fsname, 'w', encoding='utf8')
            cmd = cmd[:-2]
        if len(cmd) > 1 and cmd[0].startswith('indir:'):
            cwd = cmd[0][6:]
            cmd = cmd[1:]
        while len(cmd) > 1 and cmd[0].startswith('env:') and cmd[0].find('=') > 0:
            env_key, env_val = cmd[0][4:].split('=')
            sub_env[env_key] = env_val
            cmd = cmd[1:]

        proc = subprocess.Popen(cmd, cwd=cwd, close_fds=True, env=sub_env, stdout=redirect_stdout_fd)
        proc.communicate()

        if proc.returncode != 0:
            print("Command '%s' failed with error code %d" % (' '.join(cmd), proc.returncode))

            if redirect_stdout_fd is not None:
                redirect_stdout_fd.close()
                last_lines = open(redirect_stdout_fsname, encoding='utf8').readlines()[-100:]
                print("%s", ''.join(last_lines))

            if cmd[0] not in ['lcov', 'codecov']:
                sys.exit(proc.returncode)

def default_os():
    platform_os = platform.system().lower()
    if platform_os == 'darwin':
        return 'osx'
    return platform_os

def default_cc():
    platform_os = platform.system().lower()
    return 'msvc' if platform_os == 'windows' else 'gcc'

def default_make_tool():
    platform_os = platform.system().lower()
    return 'nmake' if platform_os == 'windows' else 'make'

def parse_args(args):
    """
    Parse arguments
    """
    parser = optparse.OptionParser()

    parser.add_option('--os', default=default_os(),
                      help='Set the target os (default %default)')
    parser.add_option('--cpu', default=None,
                      help='Specify a target CPU platform')
    parser.add_option('--cc', default=default_cc(),
                      help='Set the target compiler type (default %default)')
    parser.add_option('--cc-bin', default=None,
                      help='Set path to compiler')
    parser.add_option('--root-dir', metavar='D', default='.',
                      help='Set directory to execute from (default %default)')
    parser.add_option('--build-dir', metavar='D', default='.',
                      help='Set directory to place build artifacts into (default %default)')
    parser.add_option('--boringssl-dir', metavar='D', default='boringssl',
                      help='Set directory of BoringSSL checkout to use for BoGo tests')

    parser.add_option('--make-tool', metavar='TOOL', default=default_make_tool(),
                      help='Specify tool to run to build source (default %default)')

    parser.add_option('--extra-cxxflags', metavar='FLAGS', default=[], action='append',
                      help='Specify extra build flags')
    parser.add_option('--custom-optimization-flags', metavar='FLAGS', default=[], action='append',
                      help='Specify custom optimization flags (disables all default optimizations)')

    parser.add_option('--disabled-tests', metavar='DISABLED_TESTS', default=[], action='append',
                      help='Comma separated list of tests that should not be run')

    parser.add_option('--dry-run', action='store_true', default=False,
                      help='Just show commands to be executed')
    parser.add_option('--build-jobs', metavar='J', default=get_concurrency(),
                      help='Set number of jobs to run in parallel (default %default)')

    parser.add_option('--compiler-cache', default=None, metavar='CC',
                      help='Set a compiler cache to use (ccache, sccache, none)')

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

def validate_make_tool(make_tool, build_jobs):
    if make_tool == '':
        return validate_make_tool('make', build_jobs)

    if make_tool not in ['ninja', 'nmake', 'make']:
        raise Exception("Don't know about %s as a make tool" % (make_tool))

    if make_tool in ['make']:
        return make_tool, ['-j%d' % (build_jobs), '-k']
    elif make_tool in ['ninja']:
        return make_tool, ['-k', '0']
    else:
        return make_tool, []

def main(args=None):
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
        elif options.cc == 'gcc-14':
            options.cc = 'gcc' # Hack: 'gcc-14' is not a valid compiler identifier for ``./configure.py --cc``
            options.cc_bin = 'g++-14'
        elif options.cc == 'clang':
            options.cc_bin = 'clang++'
        elif options.cc == 'xcode':
            options.cc_bin = 'clang++'
        elif options.cc == 'msvc':
            options.cc_bin = 'cl'
        elif options.cc == 'clangcl':
            options.cc_bin = 'clang-cl'
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

    if options.compiler_cache == 'none':
        options.compiler_cache = None

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
        pylint_flags += ['--ignored-modules=gdb'] # 'import gdb' is not available outside gdb...

        if is_running_in_github_actions():
            pylint_flags += ["--msg-template='::warning file={path},line={line},endLine={end_line}::Pylint ({category}): {msg_id} {msg} ({symbol})'"]

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
            'src/scripts/compare_perf.py',
            'src/scripts/build_docs.py',
            'src/scripts/website.py',
            'src/scripts/bench.py',
            'src/scripts/test_python.py',
            'src/scripts/test_python_packaging.py',
            'src/scripts/test_strubbed_symbols.py',
            'src/scripts/test_fuzzers.py',
            'src/scripts/test_cli.py',
            'src/scripts/repo_config.py',
            'src/scripts/python_unittests.py',
            'src/scripts/python_unittests_unix.py',
            'src/scripts/dev_tools/run_clang_format.py',
            'src/scripts/dev_tools/run_clang_tidy.py',
            'src/scripts/gdb/strubtest.py',
            'src/editors/vscode/scripts/bogo.py',
            'src/editors/vscode/scripts/common.py',
            'src/editors/vscode/scripts/test.py',
            'src/ct_selftest/ct_selftest.py']

        # These commands have to run in the repository root to generate the correct
        # relative paths in the output. Otherwise GitHub Actions will not
        # be able to annotate the correct files.
        cmds.append(["indir:%s" % root_dir, py_interp, '-m', 'pylint'] + pylint_flags + py_scripts)

        ruff_flags = []
        if is_running_in_github_actions():
            ruff_flags += ["--output-format=github"]

        cmds.append(["indir:%s" % (root_dir), "ruff", "check"] + ruff_flags + ["."])

    elif target == 'typos':
        cmds.append(['indir:%s' % (root_dir), 'typos', '-c', 'src/configs/typos.toml', '.'])
    elif target == 'format':
        cmds.append([py_interp,
                     os.path.join(root_dir, 'src/scripts/dev_tools/run_clang_format.py'),
                     '--clang-format=clang-format-17',
                     '--src-dir=%s' % (os.path.join(root_dir, 'src')),
                     '--check'])
    else:
        if options.test_results_dir:
            os.makedirs(options.test_results_dir)

        config_flags, run_test_command, make_prefix = determine_flags(
            target, options.os, options.cpu, options.cc, options.cc_bin,
            options.compiler_cache, root_dir, build_dir, options.test_results_dir,
            options.pkcs11_lib, options.use_gdb, options.disable_werror,
            options.extra_cxxflags, options.custom_optimization_flags, options.disabled_tests)

        make_tool, make_opts = validate_make_tool(options.make_tool, options.build_jobs)

        cmds.append([py_interp,
            os.path.join(root_dir, 'configure.py')] +
            ['--build-tool=' + make_tool] +
            config_flags)

        make_cmd = [make_tool] + make_opts

        if build_dir != '.':
            make_cmd = ['indir:%s' % build_dir] + [make_tool] + make_opts

        if target == 'docs':
            cmds.append(make_cmd + ['docs'])
        else:
            if options.compiler_cache is not None:
                cmds.append([options.compiler_cache, '--show-stats'])

            cmds.append(make_prefix + make_cmd + make_targets(target, options.os))

            if target in ['examples'] and options.cc in ['clang', 'gcc']:
                cmds.append([options.cc, '-Wall', '-Wextra', '-std=c89',
                             '-I%s' % (os.path.join(build_dir, 'build/include/public')),
                             os.path.join(root_dir, 'src/examples/ffi.c'),
                             '-L%s' % (build_dir), '-lbotan-3', '-o',
                             os.path.join(build_dir, 'build/examples/ffi')])

            if options.compiler_cache is not None:
                cmds.append([options.compiler_cache, '--show-stats'])

        if run_test_command is not None:
            cmds.append(run_test_command)

        if target in ['valgrind', 'valgrind-full', 'valgrind-ct', 'valgrind-ct-full']:

            build_config = os.path.join(build_dir, 'build', 'build_config.json')
            cmds.append([os.path.join(root_dir, 'src', 'ct_selftest', 'ct_selftest.py'),
                         "--build-config-path=%s" % build_config,
                         os.path.join(build_dir, 'botan_ct_selftest')])

            valgrind_script_options = ['--test-binary=%s' % (os.path.join(build_dir, 'botan-test')),
                                       '--verbose',
                                       '--bunch',
                                       '--track-origins']

            # For finding memory bugs, we're enabling more features that add runtime
            # overhead which we don't need for the secret-dependent execution checks
            # that 'valgrind-ct' and 'valgrind-ct-full' are aiming for.
            if target not in ['valgrind-ct', 'valgrind-ct-full']:
                valgrind_script_options.append('--with-leak-check')

            if target not in ['valgrind-full', 'valgrind-ct-full']:
                # valgrind is slow, so some tests only run in the nightly check
                slow_tests = [
                    'argon2', 'bcrypt', 'bcrypt_pbkdf', 'compression_tests', 'cryptobox',
                    'dh_invalid', 'dh_kat', 'dh_keygen', 'dl_group_gen', 'dlies',
                    'dsa_kat_verify', 'dsa_param', 'ecc_basemul', 'ecdsa_verify_wycheproof',
                    'ed25519_sign', 'elgamal_decrypt', 'elgamal_encrypt', 'elgamal_keygen',
                    'ffi_dh', 'ffi_dsa', 'ffi_elgamal', 'frodo_kat_tests', 'hash_nist_mc',
                    'hss_lms_keygen', 'hss_lms_sign', 'mce_keygen', 'passhash9', 'pbkdf',
                    'pcurves_arith', 'pwdhash', 'rsa_encrypt', 'rsa_pss', 'rsa_pss_raw', 'scrypt',
                    'sphincsplus', 'sphincsplus_fors', 'slh_dsa_keygen', 'slh_dsa', 'srp6_kat',
                    'srp6_rt', 'unit_tls', 'x509_path_bsi', 'x509_path_rsa_pss',
                    'xmss_keygen', 'xmss_keygen_reference', 'xmss_sign', 'xmss_unit_tests',
                    'xmss_verify', 'xmss_verify_invalid',
                ]
                slow_tests += [f"dilithium_kat_{mode}_{rand}" for mode in ('6x5', '8x7', '6x5_AES', '8x7_AES') for rand in ('Deterministic', 'Randomized')]
                slow_tests += [f"ml_dsa_kat_{mode}_{rand}" for mode in ('6x5', '8x7') for rand in ('Deterministic', 'Randomized')]

                valgrind_script_options.append('--skip-tests=%s' % (','.join(slow_tests)))
            elif target == 'valgrind-ct-full' and options.cc == 'clang' and '-Os' in options.custom_optimization_flags:
                # Clang 18 (only) with -Os seems to have a problem with std::optional which flags certain
                # uses as touching an uninitialized stack variable. This affects the x509_rpki tests
                # TODO(26.04) We can remove this once we have a new version of Clang to use
                valgrind_script_options.append('--skip-tests=x509_rpki')

            cmds.append(['indir:%s' % (root_dir),
                         'src/scripts/run_tests_under_valgrind.py'] +
                        valgrind_script_options)

        if target in ['coverage', 'sanitizer'] and options.os != 'windows':
            if not options.boringssl_dir:
                raise Exception('coverage build needs --boringssl-dir')

            runner_dir = os.path.abspath(os.path.join(options.boringssl_dir, 'ssl', 'test', 'runner'))

            cmds.append(['indir:%s' % (runner_dir),
                         'go', 'test', '-pipe',
                         '-num-workers', str(4*get_concurrency()),
                         '-shim-path', os.path.abspath(os.path.join(build_dir, 'botan_bogo_shim')),
                         '-shim-config', os.path.abspath(os.path.join(root_dir, 'src', 'bogo_shim', 'config.json'))])

        if target in ['limbo']:
            cmds.append([py_interp, os.path.join(root_dir, 'src/scripts/run_limbo_tests.py'),
                         os.path.join(root_dir, 'limbo.json')])

        if target in ['coverage', 'fuzzers']:
            cmds.append([py_interp, os.path.join(root_dir, 'src/scripts/test_fuzzers.py'),
                         os.path.join(build_dir, 'fuzzer_corpus'),
                         os.path.join(build_dir, 'build/fuzzer')])

        if target in ['shared', 'coverage', 'sanitizer']:
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

        if target in ['strubbing']:
            cmds.append([py_interp, os.path.join(root_dir, 'src/scripts/test_strubbed_symbols.py'),
                         '--botan-cli', os.path.join(build_dir, 'botan')])

        if target in ['hybrid-tls13-interop-test']:
            cmds.append([py_interp, os.path.join(root_dir, 'src/scripts/test_cli.py'),
                         '--run-online-tests', os.path.join(build_dir, 'botan'), 'pqc_hybrid_tests'])

        python_tests = [os.path.join(root_dir, 'src/scripts/test_python.py')]
        if root_dir != '.':
            python_tests.append('--test-data-dir=%s' % root_dir)

        if is_running_in_github_actions() and os.environ.get('BOTAN_TPM2_ENABLED', 'no') == 'test':
            python_tests.extend(["--tpm2-tcti-name=%s" % os.getenv('BOTAN_TPM2_TCTI_NAME'),
                                 "--tpm2-tcti-conf=%s" % os.getenv('BOTAN_TPM2_TCTI_CONF')])

        if target in ['shared', 'coverage'] and not (options.os == 'windows' and options.cpu == 'x86'):
            cmds.append([py_interp, '-b'] + python_tests)

        if target in ['shared'] and options.os == 'linux':
            with tempfile.TemporaryDirectory() as venv_dir:
                cmds.append([py_interp, '-m', 'venv', venv_dir])
                cmds.append([os.path.join(venv_dir, 'bin/python'), '-m', 'pip', 'install', os.path.join(root_dir, 'src/python')])
                cmds.append([os.path.join(venv_dir, 'bin/python'), os.path.join(root_dir, 'src/scripts/test_python_packaging.py')])

        if target in ['shared', 'static']:
            cmds.append(make_cmd + ['install'])
            build_config = os.path.join(build_dir, 'build', 'build_config.json')
            cmds.append([py_interp, os.path.join(root_dir, 'src/scripts/ci_check_install.py'), build_config])
            cmds.append([py_interp, os.path.join(root_dir, 'src/scripts/ci_check_headers.py'), build_config])
            cmds.append([py_interp, os.path.join(root_dir, 'src/scripts/ci_report_sizes.py'), build_config])

        if target in ['coverage']:
            if have_prog('coverage'):
                cmds.append(['coverage', 'run', '--branch',
                             '--rcfile', os.path.join(root_dir, 'src/configs/coverage.rc')] +
                            python_tests)

            cov_file = os.path.join(build_dir, 'coverage.lcov')
            raw_cov_file = os.path.join(build_dir, 'coverage.raw.lcov')

            cmds.append(['lcov', '--capture', '--directory', build_dir,
                         '--output-file', raw_cov_file])
            cmds.append(['lcov', '--remove', raw_cov_file, '/usr/*', '--output-file', cov_file])
            cmds.append(['lcov', '--list', cov_file])
            cmds.append([os.path.join(root_dir, 'src/scripts/rewrite_lcov.py'), cov_file])

            if have_prog('coveralls'):
                # If coveralls command exists, assume we are in CI and report to coveralls.io
                cmds.append(['coveralls', '--no-fail', '--format=lcov', '--file=%s' % (cov_file)])
            else:
                # Otherwise generate a local HTML report
                cmds.append(['genhtml', cov_file, '--output-directory', os.path.join(build_dir, 'lcov-out')])

        cmds.append(make_cmd + ['clean'])
        cmds.append(make_cmd + ['distclean'])

    esdm_process = None
    # start ESDM in background, if on Linux
    if is_running_in_github_actions() and 'BOTAN_BUILD_WITH_ESDM' in os.environ:
        print('Starting esdm-server for this target')
        esdm_process = subprocess.Popen('sudo /usr/bin/esdm-server -f', shell=True)
        assert esdm_process.poll() is None, f"esdm-server did not start for target {target}"

    for cmd in cmds:
        if options.dry_run:
            print('$ ' + ' '.join(cmd))
        else:
            run_cmd(cmd, root_dir, build_dir)

    if esdm_process:
        print('Stopping esdm-server')
        esdm_process.kill()

    return 0

if __name__ == '__main__':
    sys.exit(main())
