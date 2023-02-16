#!/usr/bin/env python3

"""
(C) 2022,2023 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import subprocess
import sys
import json
import optparse
import os
import multiprocessing
import re
import time
from multiprocessing.pool import ThreadPool

enabled_checks = [
    'bugprone-*',
    'cert-*',
    'clang-analyzer-*',
    'cppcoreguidelines-*',
    'hicpp-*',
    'modernize-*',
    'performance-*',
    'portability-*',
    'readability-*',
]

# these might be worth being clean for
disabled_needs_work = [
    '*-braces-around-statements', # should fix (need clang-format)
    '*-named-parameter',
    '*-member-init', # seems bad
    'bugprone-easily-swappable-parameters',
    'bugprone-implicit-widening-of-multiplication-result',
    'bugprone-lambda-function-name', # should be an easy fix
    'bugprone-macro-parentheses', # should be fixed (using inline/constexpr)
    'bugprone-narrowing-conversions', # should be fixed
    'bugprone-unchecked-optional-access', # clang-tidy seems buggy (many false positives)
    'cppcoreguidelines-init-variables',
    'cppcoreguidelines-macro-usage',
    'cppcoreguidelines-narrowing-conversions', # lot of these
    'cppcoreguidelines-owning-memory',
    'cppcoreguidelines-prefer-member-initializer',
    'cppcoreguidelines-pro-bounds-pointer-arithmetic',
    'cppcoreguidelines-slicing', # private->public key slicing
    'hicpp-explicit-conversions',
    'hicpp-signed-bitwise', # djb shit
    'hicpp-move-const-arg',
    'modernize-avoid-bind', # used a lot in pkcs11
    'modernize-pass-by-value',
    'modernize-use-nodiscard',
    'modernize-use-trailing-return-type',
    'performance-inefficient-string-concatenation',
    'performance-inefficient-vector-operation',
    'performance-move-const-arg',
    'performance-no-automatic-move',
    'performance-unnecessary-copy-initialization',
    'readability-container-contains',
    'readability-convert-member-functions-to-static',
    'readability-implicit-bool-conversion', # maybe fix this
    'readability-inconsistent-declaration-parameter-name', # should fix this
    'readability-isolate-declaration',
    'readability-qualified-auto',
    'readability-redundant-access-specifiers',
    'readability-redundant-member-init',
    'readability-redundant-string-cstr',
    'readability-simplify-boolean-expr', # sometimes ok
    'readability-static-accessed-through-instance',
]

# these we are not interested in ever being clang-tidy clean for
disabled_not_interested = [
    '*-array-to-pointer-decay',
    '*-avoid-c-arrays',
    '*-else-after-return',
    '*-function-size',
    '*-magic-numbers', # can't stop the magic
    '*-no-array-decay',
    '*-use-auto', # not universally a good idea
    '*-use-emplace', # often less clear
    '*-deprecated-headers', # wrong for system headers like stdlib.h
    'bugprone-argument-comment',
    'bugprone-branch-clone', # doesn't interact well with feature macros
    'cert-err58-cpp',
    'cppcoreguidelines-avoid-non-const-global-variables',
    'cppcoreguidelines-no-malloc',
    'cppcoreguidelines-non-private-member-variables-in-classes', # pk split keys
    'cppcoreguidelines-pro-bounds-constant-array-index',
    'cppcoreguidelines-pro-type-const-cast', # see above
    'cppcoreguidelines-pro-type-cstyle-cast', # system headers
    'cppcoreguidelines-pro-type-reinterpret-cast', # not possible thanks though
    'cppcoreguidelines-pro-type-vararg', # idiocy
    'hicpp-no-assembler',
    'hicpp-no-malloc',
    'hicpp-vararg', # idiocy
    'modernize-loop-convert', # sometimes very ugly
    'modernize-raw-string-literal',
    'modernize-return-braced-init-list', # thanks I hate it
    'modernize-use-default-member-init',
    'modernize-use-using', # fine not great
    'portability-simd-intrinsics',
    'readability-container-data-pointer',
    'readability-function-cognitive-complexity',
    'readability-identifier-length', # lol, lmao
    'readability-non-const-parameter',
    'readability-suspicious-call-argument',
    'readability-use-anyofallof', # not more readable
]

disabled_checks = disabled_needs_work + disabled_not_interested

def create_check_option(enabled, disabled):
    return ','.join(enabled) + ',' + ','.join(['-' + d for d in disabled])

def load_compile_commands(build_dir):
    compile_commands_file = os.path.join(build_dir, 'compile_commands.json')
    compile_commands = open(compile_commands_file).read()
    return (compile_commands_file, json.loads(compile_commands))

def run_command(cmdline):
    proc = subprocess.Popen(cmdline,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)

    (stdout, stderr) = proc.communicate()

    stdout = stdout.decode('utf8')
    # stderr discarded

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
        print(source_file)
    if stdout != "":
        print(stdout)
        sys.stdout.flush()

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

    (options, args) = parser.parse_args(args)

    jobs = options.jobs
    if jobs == 0:
        jobs = multiprocessing.cpu_count()

    (compile_commands_file, compile_commands) = load_compile_commands(options.build_dir)

    # For some reason clang-tidy takes an enourmous amount of time
    # on this file; skip it for now
    def remove_bad(cc):
        if cc['file'].find('tls_client_impl_12.cpp') > 0:
            return True
        return False

    compile_commands = [x for x in compile_commands if not remove_bad(x)]

    check_config = create_check_option(enabled_checks, disabled_checks)

    if options.list_checks:
        print(run_command(['clang-tidy', '-list-checks', '-checks', check_config]))
        return 0

    pool = ThreadPool(jobs)

    start_time = time.time()
    files_checked = 0

    results = []
    for info in compile_commands:
        file = info['file']

        if not file_matches(file, args[1:]):
            continue

        files_checked += 1
        results.append(pool.apply_async(
            run_clang_tidy,
            (compile_commands_file,
             check_config,
             file,
             options)))

    for result in results:
        result.get()

    time_consumed = time.time() - start_time

    print("Checked %d files in %d seconds" % (files_checked, time_consumed))

    return 0

if __name__ == '__main__':
    sys.exit(main())

