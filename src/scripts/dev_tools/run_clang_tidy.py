#!/usr/bin/env python3

"""
(C) 2022,2023 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import subprocess
import sys
import json
import optparse # pylint: disable=deprecated-module
import os
import multiprocessing
import time
from multiprocessing.pool import ThreadPool

quick_checks = [
    '-clang-analyzer*', # has to be explicitly disabled
    'modernize-use-nullptr',
    'readability-braces-around-statements'
]

enabled_checks = [
    'bugprone-*',
    'cert-*',
    'clang-analyzer-*',
    'cppcoreguidelines-*',
    'hicpp-*',
    'misc-*',
    'modernize-*',
    'performance-*',
    'portability-*',
    'readability-*',
]

# these checks are ignored for cli/tests
disabled_checks_non_lib = [
    'cert-err58-cpp',
    'cppcoreguidelines-macro-usage',
    'misc-non-private-member-variables-in-classes',
    'performance-inefficient-string-concatenation',
    'performance-no-automatic-move',
]

# these are ones that ideally we would be clean for, but
# currently are not
disabled_needs_work = [
    'misc-non-private-member-variables-in-classes',
    '*-named-parameter',
    '*-member-init', # seems bad
    'bugprone-lambda-function-name', # should be an easy fix
    'bugprone-unchecked-optional-access', # clang-tidy seems buggy (many false positives)
    'cert-err58-cpp', # many false positives eg __m128i
    'cppcoreguidelines-init-variables',
    'cppcoreguidelines-owning-memory',
    'cppcoreguidelines-prefer-member-initializer',
    'cppcoreguidelines-slicing', # private->public key slicing
    'hicpp-explicit-conversions',
    'misc-const-correctness', # pretty noisy
    'misc-redundant-expression', # BigInt seems to confuse clang-tidy
    'misc-misplaced-const',
    'misc-confusable-identifiers',
    'modernize-avoid-bind', # used a lot in pkcs11
    'modernize-pass-by-value',
    'readability-convert-member-functions-to-static',
    'readability-implicit-bool-conversion', # maybe fix this
    'readability-inconsistent-declaration-parameter-name', # should fix this, blocked by https://github.com/llvm/llvm-project/issues/60845
    'readability-qualified-auto',
    'readability-simplify-boolean-expr', # sometimes ok
    'readability-static-accessed-through-instance',
]

# these we are probably not interested in ever being clang-tidy clean for
disabled_not_interested = [
    '*-array-to-pointer-decay',
    '*-avoid-c-arrays',
    '*-else-after-return',
    '*-function-size',
    '*-magic-numbers', # can't stop the magic
    '*-narrowing-conversions',
    '*-no-array-decay',
    '*-use-auto', # not universally a good idea
    '*-use-emplace', # often less clear
    '*-deprecated-headers', # wrong for system headers like stdlib.h
    'bugprone-argument-comment',
    'bugprone-branch-clone', # doesn't interact well with feature macros
    'bugprone-easily-swappable-parameters',
    'bugprone-implicit-widening-of-multiplication-result',
    'cppcoreguidelines-avoid-non-const-global-variables',
    'cppcoreguidelines-non-private-member-variables-in-classes', # pk split keys
    'cppcoreguidelines-pro-bounds-pointer-arithmetic',
    'cppcoreguidelines-pro-bounds-constant-array-index',
    'cppcoreguidelines-pro-type-const-cast', # see above
    'cppcoreguidelines-pro-type-reinterpret-cast', # not possible thanks though
    'cppcoreguidelines-pro-type-vararg', # idiocy
    'hicpp-no-assembler',
    'hicpp-vararg', # idiocy
    'hicpp-signed-bitwise', # impossible to avoid in C/C++, int promotion rules :/
    'misc-no-recursion',
    'modernize-loop-convert', # sometimes very ugly
    'modernize-raw-string-literal', # usually less readable
    'modernize-use-trailing-return-type', # fine, but we're not using it everywhere
    'modernize-return-braced-init-list', # thanks I hate it
    'modernize-use-default-member-init',
    'modernize-use-nodiscard',
    'modernize-use-using', # fine not great
    'portability-simd-intrinsics',
    'readability-container-data-pointer',
    'readability-function-cognitive-complexity',
    'readability-identifier-length', # lol, lmao
    'readability-isolate-declaration',
    'readability-non-const-parameter',
    'readability-redundant-access-specifiers', # reneme likes doing this
    'readability-suspicious-call-argument',
    'readability-use-anyofallof', # not more readable
]

disabled_checks = disabled_needs_work + disabled_not_interested
disabled_checks_non_lib = disabled_checks + disabled_checks_non_lib

def create_check_option(enabled, disabled):
    return ','.join(enabled) + ',' + ','.join(['-' + d for d in disabled])

def load_compile_commands(build_dir):
    compile_commands_file = os.path.join(build_dir, 'compile_commands.json')
    compile_commands = open(compile_commands_file, encoding='utf8').read()
    return (compile_commands_file, json.loads(compile_commands))

def run_command(cmdline):
    proc = subprocess.Popen(cmdline,
                            stdout=subprocess.PIPE)

    (stdout, _) = proc.communicate()

    stdout = stdout.decode('utf8')

    return stdout

def run_clang_tidy(compile_commands_file,
                   check_config,
                   source_file,
                   options):

    cmdline = ['clang-tidy',
               '--quiet',
               '-checks=%s' % (check_config),
               '-p', compile_commands_file]

    if options.fixit:
        cmdline.append('-fix')

    cmdline.append(source_file)

    stdout = run_command(cmdline)

    if options.verbose:
        print("Checked", source_file)
        sys.stdout.flush()
    if stdout != "":
        print(stdout)
        sys.stdout.flush()
        return False

    return True

def file_matches(file, args):
    if args is None or len(args) == 0:
        return True

    for arg in args:
        if file.find(arg) > 0:
            return True
    return False

def main(args = None):
    if args is None:
        args = sys.argv

    parser = optparse.OptionParser()

    parser.add_option('-j', '--jobs', action='store', type='int', default=0)
    parser.add_option('--verbose', action='store_true', default=False)
    parser.add_option('--fixit', action='store_true', default=False)
    parser.add_option('--build-dir', default='build')
    parser.add_option('--list-checks', action='store_true', default=False)
    parser.add_option('--fast-checks-only', action='store_true', default=False)

    (options, args) = parser.parse_args(args)

    jobs = options.jobs
    if jobs == 0:
        jobs = multiprocessing.cpu_count() + 1

    (compile_commands_file, compile_commands) = load_compile_commands(options.build_dir)

    # For some reason clang-tidy takes an enourmous amount of time
    # on this file; skip it for now
    def remove_bad(cc):
        if cc['file'].find('tls_client_impl_12.cpp') > 0:
            return True
        return False

    compile_commands = [x for x in compile_commands if not remove_bad(x)]

    if options.fast_checks_only:
        check_config_lib = ','.join(quick_checks)
        check_config_rest = check_config_lib
    else:
        check_config_lib = create_check_option(enabled_checks, disabled_checks)
        check_config_rest = create_check_option(enabled_checks, disabled_checks_non_lib)

    if options.list_checks:
        print(run_command(['clang-tidy', '-list-checks', '-checks', check_config_lib]), end='')
        return 0

    pool = ThreadPool(jobs)

    start_time = time.time()
    files_checked = 0

    results = []
    for info in compile_commands:
        file = info['file']

        if not file_matches(file, args[1:]):
            continue

        config = check_config_lib if file.startswith('src/lib') else check_config_rest

        files_checked += 1
        results.append(pool.apply_async(
            run_clang_tidy,
            (compile_commands_file,
             config,
             file,
             options)))

    fail_cnt = 0
    for result in results:
        if not result.get():
            fail_cnt += 1

    time_consumed = time.time() - start_time

    print("Checked %d files in %d seconds" % (files_checked, time_consumed))

    if fail_cnt == 0:
        return 0
    else:
        print("Found clang-tidy errors in %d files" % (fail_cnt))
        return 1

if __name__ == '__main__':
    sys.exit(main())
