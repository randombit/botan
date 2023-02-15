#!/usr/bin/env python3

import subprocess
import sys
import json
import optparse
import os
import multiprocessing
import re
from multiprocessing.pool import ThreadPool

enabled_checks = [
    'bugprone-*',
    'cert-*',
    'clang-analyzer-*',
    'performance-*',
    'portability-*',

    'modernize-concat-nested-namespaces',
    'modernize-make-unique',
    'modernize-make-shared',

    'readability-container-size-empty',
    'readability-static-definition-in-anonymous-namespace',
    'readability-convert-member-functions-to-static',
    'readability-redundant-smartptr-get',

    'hicpp-special-member-functions',

#    'cppcoreguidelines-*',
#    'hicpp-*',
#    'modernize-*',
#    'readability-*',
]

# these might be worth being clean for
disabled_needs_work = [
    '*-braces-around-statements', # should fix (need clang-format)
    'bugprone-easily-swappable-parameters',
    'bugprone-implicit-widening-of-multiplication-result',
    'bugprone-macro-parentheses', # should be fixed (using inline/constexpr)
    'bugprone-narrowing-conversions', # should be fixed
    'bugprone-unchecked-optional-access', # clang-tidy seems buggy (many false positives)
    'bugprone-lambda-function-name', # should be an easy fix
    'cppcoreguidelines-init-variables',
    'cppcoreguidelines-narrowing-conversions', # lot of these
    'cppcoreguidelines-macro-usage',
    'cppcoreguidelines-owning-memory',
    'cppcoreguidelines-prefer-member-initializer',
    'cppcoreguidelines-pro-bounds-pointer-arithmetic',
    'cppcoreguidelines-pro-type-union-access', # only in sha1_sse2
    'cppcoreguidelines-slicing', # private->public key slicing
    'hicpp-signed-bitwise', # djb shit
    'hicpp-explicit-conversions',
    'modernize-pass-by-value',
    'modernize-use-nodiscard',
    'modernize-avoid-bind', # used a lot in pkcs11
    'modernize-use-trailing-return-type',
    'performance-inefficient-string-concatenation',
    'performance-inefficient-vector-operation',
    'performance-no-int-to-ptr',
    'performance-unnecessary-copy-initialization',
    'performance-move-const-arg',
    'performance-no-automatic-move',
    'readability-convert-member-functions-to-static',
    'readability-implicit-bool-conversion', # maybe fix this
    'readability-inconsistent-declaration-parameter-name', # should fix this
    'readability-isolate-declaration',
    'readability-simplify-boolean-expr', # sometimes ok
    'readability-qualified-auto',
    'readability-redundant-member-init',
    'readability-redundant-string-cstr',
    'readability-redundant-access-specifiers',
    'readability-container-contains',
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
    'cppcoreguidelines-no-malloc',
    'cppcoreguidelines-pro-bounds-constant-array-index',
    'cppcoreguidelines-avoid-non-const-global-variables',
    'cppcoreguidelines-non-private-member-variables-in-classes', # pk split keys
    'cppcoreguidelines-pro-type-cstyle-cast', # system headers
    'cppcoreguidelines-pro-type-reinterpret-cast', # not possible thanks though
    'cppcoreguidelines-pro-type-const-cast', # see above
    'cppcoreguidelines-pro-type-vararg', # idiocy
    'hicpp-no-assembler',
    'hicpp-no-malloc',
    'hicpp-vararg', # idiocy
    'modernize-loop-convert', # sometimes very ugly
    'modernize-raw-string-literal',
    'modernize-return-braced-init-list', # thanks I hate it
    'modernize-use-using', # fine not great
    'modernize-use-default-member-init',
    'portability-simd-intrinsics',
    'readability-function-cognitive-complexity',
    'readability-use-anyofallof', # not more readable
    'readability-identifier-length', # lol, lmao
    'readability-container-data-pointer',
    'readability-suspicious-call-argument',
    'readability-non-const-parameter',
]

disabled_checks = disabled_needs_work + disabled_not_interested

def create_check_option(enabled, disabled):
    return ','.join(enabled) + ',' + ','.join(['-' + d for d in disabled])

def load_compile_commands(build_dir):
    compile_commands_file = os.path.join(build_dir, 'compile_commands.json')
    compile_commands = open(compile_commands_file).read()
    return (compile_commands_file, json.loads(compile_commands))

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

    clang_tidy = subprocess.Popen(cmdline,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)

    (stdout, stderr) = clang_tidy.communicate()

    stdout = stdout.decode('utf8')
    # stderr discarded

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

    pool = ThreadPool(jobs)

    results = []
    for info in compile_commands:
        file = info['file']

        if not file_matches(file, args[1:]):
            continue

        results.append(pool.apply_async(
            run_clang_tidy,
            (compile_commands_file,
             check_config,
             file,
             options)))

    for result in results:
        result.get()

    return 0

if __name__ == '__main__':
    sys.exit(main())

