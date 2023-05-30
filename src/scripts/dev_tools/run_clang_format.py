#!/usr/bin/env python3

"""
(C) 2023 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import subprocess
import sys
import optparse # pylint: disable=deprecated-module
import multiprocessing
import difflib
import time
import os
import re
from multiprocessing.pool import ThreadPool

def run_command(cmdline):
    proc = subprocess.Popen(cmdline,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)

    (stdout, stderr) = proc.communicate()

    stdout = stdout.decode('utf8')
    stderr = stderr.decode('utf8')

    return (stdout, stderr)

def apply_clang_format(clang_format, source_file):
    cmdline = [clang_format, '-i', source_file]
    (stdout, stderr) = run_command(cmdline)

    if stdout != '' or stderr != '':
        print("Running '%s' stdout: '%s' stderr: '%s''" % (' '.join(cmdline), stdout, stderr))
        return False
    return True

def run_diff(source_file, formatted_contents):
    original_contents = open(source_file, encoding='utf8').read()
    if original_contents == formatted_contents:
        return ''

    return '\n'.join(difflib.unified_diff(
        original_contents.splitlines(),
        formatted_contents.splitlines(),
        fromfile="%s (original)" % (source_file),
        tofile="%s" % (source_file),
        lineterm="",
    ))

def check_clang_format(clang_format, source_file):
    cmdline = [clang_format, source_file]
    (stdout, stderr) = run_command(cmdline)

    if stderr != '':
        print("Running '%s' stderr: '%s''" % (' '.join(cmdline), stderr))
        return False

    diff = run_diff(source_file, stdout)
    if diff != '':
        print(diff)
        return False

    return True

def list_source_files_in(directory):
    excluded = ['pkcs11t.h', 'pkcs11f.h', 'pkcs11.h']

    for (dirpath, _, filenames) in os.walk(directory):
        for filename in filenames:
            if filename.endswith('.cpp') or filename.endswith('.h'):

                if filename not in excluded:
                    yield os.path.join(dirpath, filename)

def filter_files(files, filters):
    if len(filters) == 0:
        return files

    files_to_fmt = []

    for file in files:
        for filt in filters:
            if file.find(filt) >= 0:
                files_to_fmt.append(file)
                break

    return files_to_fmt

def main(args = None):
    if args is None:
        args = sys.argv

    parser = optparse.OptionParser()

    parser.add_option('-j', '--jobs', action='store', type='int', default=0)
    parser.add_option('--src-dir', metavar='DIR', default='src')
    parser.add_option('--check', action='store_true', default=False)
    parser.add_option('--clang-format-binary', metavar='PATH', default='clang-format')

    (options, args) = parser.parse_args(args)

    clang_format_version_re = re.compile(r'^(.* )?clang-format version ([0-9]+)\.([0-9]+)\.([0-9]+)')

    clang_format = options.clang_format_binary

    (stdout, stderr) = run_command([clang_format, '-version'])

    if stderr != '':
        print("Error trying to get clang-format version number: '%s'" % (stderr))
        return 1

    version = clang_format_version_re.match(stdout)

    if version is None:
        print("Cannot interpret clang-format output (%s) as version" % (stdout.strip()))
        return 1

    # This check is probably stricter than we really need, and should
    # be revised as we gain more experience with clang-format

    if int(version.group(2)) != 15:
        print("This version of the script requires clang-format 15: got '%s'" % (stdout.strip()))
        return 1

    jobs = options.jobs
    if jobs == 0:
        jobs = multiprocessing.cpu_count()

    pool = ThreadPool(jobs)

    start_time = time.time()

    all_files = sorted(list_source_files_in(options.src_dir))

    if len(all_files) == 0:
        print("Error: unable to find any source files in %s'" % (options.src_dir))
        return 1

    files_to_fmt = filter_files(all_files, args[1:])

    if len(files_to_fmt) == 0:
        print("Error: filter does not match any files")
        return 1

    results = []
    for file in files_to_fmt:
        if options.check:
            results.append(pool.apply_async(check_clang_format, (clang_format, file,)))
        else:
            results.append(pool.apply_async(apply_clang_format, (clang_format, file,)))

    fail_execution = False

    for result in results:
        ok = result.get()
        if not ok:
            fail_execution = True

    time_consumed = time.time() - start_time

    print("Formatted %d files in %d seconds" % (len(files_to_fmt), time_consumed))

    return -1 if fail_execution else 0

if __name__ == '__main__':
    sys.exit(main())
