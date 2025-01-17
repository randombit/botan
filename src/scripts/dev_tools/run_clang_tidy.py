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
import re
import multiprocessing
import time
import uuid
from multiprocessing.pool import ThreadPool

quick_checks = [
    '-clang-analyzer*', # has to be explicitly disabled
    'modernize-use-nullptr',
    'readability-braces-around-statements',
    'performance-unnecessary-value-param',
    '*-non-private-member-variables-in-classes',
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

# these are ones that we might want to be clean for in the future,
# but currently are not
disabled_needs_work = [
    '*-named-parameter',
    '*-member-init', # should definitely fix this one
    'bugprone-lambda-function-name', # should be an easy fix
    'bugprone-unchecked-optional-access', # clang-tidy seems buggy (many false positives)
    'bugprone-empty-catch',
    'cert-err58-cpp', # many false positives eg __m128i
    'cppcoreguidelines-avoid-const-or-ref-data-members',
    'cppcoreguidelines-init-variables',
    'cppcoreguidelines-owning-memory',
    'cppcoreguidelines-prefer-member-initializer',
    'cppcoreguidelines-slicing', # private->public key slicing
    'hicpp-explicit-conversions',
    'misc-const-correctness', # pretty noisy
    'misc-include-cleaner',
    'misc-redundant-expression', # BigInt seems to confuse clang-tidy
    'misc-misplaced-const',
    'misc-confusable-identifiers',
    'modernize-avoid-bind',
    'modernize-pass-by-value',
    'modernize-use-ranges', # limited by compiler support currently
    'performance-avoid-endl',
    'readability-convert-member-functions-to-static',
    'readability-implicit-bool-conversion',
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
    'bugprone-suspicious-stringview-data-usage', # triggers on every use of string_view::data ??
    'cppcoreguidelines-avoid-do-while',
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
    'modernize-use-designated-initializers',
    'modernize-use-nodiscard',
    'modernize-use-using', # fine not great
    'portability-simd-intrinsics',
    'readability-avoid-return-with-void-value',
    'readability-container-data-pointer',
    'readability-function-cognitive-complexity',
    'readability-identifier-length', # lol, lmao
    'readability-isolate-declaration',
    'readability-math-missing-parentheses',
    'readability-non-const-parameter',
    'readability-redundant-access-specifiers', # reneme likes doing this
    'readability-suspicious-call-argument',
    'readability-use-std-min-max',
    'readability-use-anyofallof', # not more readable
]

disabled_checks = disabled_needs_work + disabled_not_interested

def create_check_option(enabled, disabled):
    return ','.join(enabled) + ',' + ','.join(['-' + d for d in disabled])

def render_clang_tidy_file(target_dir, enabled, disabled):
    filepath = os.path.join(target_dir, '.clang-tidy')
    print(f'regenerating {filepath}')
    with open(filepath, "w", encoding="utf-8") as clang_tidy_file:
        clang_tidy_file.writelines([
            '---\n',
            f'# This file was automatically generated by {sys.argv[0]} --regenerate-inline-config-file\n',
            '#\n',
            '# All manual edits to this file will be lost. Edit the script\n',
            '# then regenerate this configuration file.\n',
            '\n',
            'Checks: >\n'] +
            [ f'    {check},\n' for check in enabled ] +
            [ f'    -{check},\n' for check in disabled] +
            ['---\n'])

def load_compile_commands(build_dir):
    compile_commands_file = os.path.join(build_dir, 'compile_commands.json')
    compile_commands = open(compile_commands_file, encoding='utf8').read()
    return (compile_commands_file, json.loads(compile_commands))

def run_command(cmdline):
    proc = subprocess.Popen(cmdline,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)

    (stdout, _stderr) = proc.communicate()

    stdout = stdout.decode('utf8')
    # stderr is discarded

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

    if options.export_fixes_dir:
        os.makedirs(options.export_fixes_dir, exist_ok=True)
        yml_file = os.path.join(options.export_fixes_dir, "%s.yml" % uuid.uuid4())
        cmdline.append("--export-fixes=%s" % yml_file)

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

def main(args = None): # pylint: disable=too-many-return-statements
    if args is None:
        args = sys.argv

    parser = optparse.OptionParser()

    parser.add_option('-j', '--jobs', action='store', type='int', default=0)
    parser.add_option('--verbose', action='store_true', default=False)
    parser.add_option('--fixit', action='store_true', default=False)
    parser.add_option('--build-dir', default='build')
    parser.add_option('--list-checks', action='store_true', default=False)
    parser.add_option('--regenerate-inline-config-file', action='store_true', default=False)
    parser.add_option('--fast-checks-only', action='store_true', default=False)
    parser.add_option('--only-changed-files', action='store_true', default=False)
    parser.add_option('--only-matching', metavar='REGEX', default='.*')
    parser.add_option('--take-file-list-from-stdin', action='store_true', default=False)
    parser.add_option('--export-fixes-dir', default=None)

    (options, args) = parser.parse_args(args)

    if len(args) > 1:
        print("ERROR: Unknown extra arguments to run_clang_tidy.py")
        return 1

    if options.only_changed_files and options.take_file_list_from_stdin:
        print("Cannot use both --only-changed-files and --take-file-list-from-stdin", file=sys.stderr)
        return 1

    files_to_check = []
    if options.only_changed_files:
        changes = run_command(['git', 'diff', '--name-only', '-r', 'master'])

        files_to_check = []
        for file in changes.split():
            if file.endswith('.cpp') or file.endswith('.h'):
                files_to_check.append(os.path.basename(file))

        if len(files_to_check) == 0:
            print("No C++ files were modified vs master, skipping clang-tidy checks")
            return 0
    elif options.take_file_list_from_stdin:
        for line in sys.stdin:
            file = os.path.basename(line.strip())
            if file.endswith('.cpp') or file.endswith('.h'):
                files_to_check.append(file)

        if len(files_to_check) == 0:
            print("No C++ files were provided on stdin, skipping clang-tidy checks")
            return 0

    jobs = options.jobs
    if jobs == 0:
        jobs = multiprocessing.cpu_count() + 1

    (compile_commands_file, compile_commands) = load_compile_commands(options.build_dir)

    if options.fast_checks_only:
        check_config = ','.join(quick_checks)
    else:
        check_config = create_check_option(enabled_checks, disabled_checks)

    if options.list_checks:
        print(run_command(['clang-tidy', '-list-checks', '-checks', check_config]), end='')
        return 0

    if options.regenerate_inline_config_file:
        render_clang_tidy_file('src', enabled_checks, disabled_checks)
        return 0

    pool = ThreadPool(jobs)

    start_time = time.time()
    files_checked = 0

    file_matcher = re.compile(options.only_matching)

    results = []
    for info in compile_commands:
        file = info['file']

        if len(files_to_check) > 0 and os.path.basename(file) not in files_to_check:
            continue

        if file_matcher.search(file) is None:
            continue

        files_checked += 1
        results.append(pool.apply_async(
            run_clang_tidy,
            (compile_commands_file,
             check_config,
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
