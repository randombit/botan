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
    'modernize-concat-nested-namespaces',
    'performance-*',
    'portability-*',
    'readability-container-size-empty',
    'readability-static-definition-in-anonymous-namespace',
    'readability-convert-member-functions-to-static',
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
    'cppcoreguidelines-init-variables',
    'cppcoreguidelines-narrowing-conversions', # lot of these
    'cppcoreguidelines-owning-memory',
    'cppcoreguidelines-pro-bounds-pointer-arithmetic',
    'cppcoreguidelines-pro-type-union-access', # only in sha1_sse2
    'hicpp-signed-bitwise', # djb shit
    'modernize-pass-by-value',
    'modernize-use-nodiscard',
    'modernize-use-trailing-return-type',
    'performance-inefficient-string-concatenation',
    'performance-no-int-to-ptr',
    'readability-implicit-bool-conversion', # maybe fix this
    'readability-inconsistent-declaration-parameter-name', # should fix this
    'readability-isolate-declaration',
    'readability-simplify-boolean-expr', # sometimes ok
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
    '-*deprecated-headers', # wrong for system headers like stdlib.h
    'bugprone-argument-comment',
    'bugprone-branch-clone', # doesn't interact well with feature macros
    'cert-err58-cpp',
    'cppcoreguidelines-no-malloc',
    'cppcoreguidelines-pro-bounds-constant-array-index',
    'cppcoreguidelines-pro-type-cstyle-cast', # system headers
    'cppcoreguidelines-pro-type-reinterpret-cast', # not possible thanks though
    'cppcoreguidelines-pro-type-vararg', # idiocy
    'hicpp-no-assembler',
    'hicpp-no-malloc',
    'hicpp-vararg', # idiocy
    'modernize-loop-convert', # sometimes very ugly
    'modernize-raw-string-literal',
    'modernize-return-braced-init-list', # thanks I hate it
    'modernize-use-using', # fine not great
    'portability-simd-intrinsics',
    'readability-function-cognitive-complexity',
    'readability-use-anyofallof', # not more readable
]

disabled_checks = disabled_needs_work + disabled_not_interested

def create_check_option(enabled, disabled):
    return ','.join(enabled) + ',' + ','.join(['-' + d for d in disabled])

def load_compile_commands(build_dir):
    compile_commands_file = os.path.join(build_dir, 'compile_commands.json')

    compile_commands = open(compile_commands_file).read()
    # hack for configure.py generating invalid JSON
    compile_commands = re.sub(r',\n+]', '\n]', compile_commands)
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

