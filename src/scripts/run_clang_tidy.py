#!/usr/bin/python

import subprocess
import sys
import json
import optparse
import os
import multiprocessing
import re
from multiprocessing.pool import ThreadPool

enabled_checks = [
    #'clang-analyzer-*',
    #'performance-*',
    #'bugprone-*',
    #'cert-*',
    #'cppcoreguidelines-*',
    #'hicpp-*',
    #'modernize-*',
    #'portability-*',
    #'readability-*',
    #'readability-container-size-empty',
    #'readability-static-definition-in-anonymous-namespace',
    #'modernize-make-unique',
    'modernize-concat-nested-namespaces',
    #'readability-inconsistent-declaration-parameter-name',
]

disabled_checks = [
    '*-array-to-pointer-decay',
    '*-avoid-c-arrays',
    '*-braces-around-statements', # should fix
    '*-else-after-return',
    '*-function-size', # don't care
    '*-magic-numbers', # not a problem
    '*-no-array-decay',
    '*-use-auto', # not universally a good idea
    'bugprone-easily-swappable-parameters',
    'bugprone-implicit-widening-of-multiplication-result',
    'bugprone-macro-parentheses', # should be fixed (using inline/constexpr)
    'cert-err58-cpp', # shut up whiner
    'cppcoreguidelines-init-variables',
    'cppcoreguidelines-no-malloc',
    'cppcoreguidelines-owning-memory',
    'cppcoreguidelines-pro-bounds-constant-array-index',
    'cppcoreguidelines-pro-bounds-pointer-arithmetic',
    'cppcoreguidelines-pro-type-reinterpret-cast', # not possible thanks though
    'hicpp-signed-bitwise', # djb shit
    'modernize-loop-convert', # sometimes very ugly
    'modernize-pass-by-value',
    'modernize-return-braced-init-list', # thanks I hate it
    'modernize-use-nodiscard', # maybe
    'modernize-use-trailing-return-type',
    'performance-inefficient-string-concatenation',
    'performance-no-int-to-ptr',
    'portability-simd-intrinsics', # not a problem
    'readability-function-cognitive-complexity', # bogus
    'readability-implicit-bool-conversion', # maybe fix this
    'readability-inconsistent-declaration-parameter-name', # should fix this
    'readability-isolate-declaration',
    'readability-simplify-boolean-expr', # sometimes ok
]

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

