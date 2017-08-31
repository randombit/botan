#!/usr/bin/python

# (C) 2017 Jack Lloyd

import sys
import os
import subprocess
import optparse
import stat
import multiprocessing

def run_fuzzer_gdb(args):
    (fuzzer_bin, corpus_file) = args

    gdb_proc = subprocess.Popen(['gdb', '--quiet', '--return-child-result', fuzzer_bin],
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                close_fds=True)

    gdb_commands = ('run < %s\nbt\nquit\n' % (corpus_file)).encode('ascii')

    (stdout, stderr) = gdb_proc.communicate(gdb_commands)

    if gdb_proc.returncode == 0:
        return (0, '', '')

    return (corpus_file, gdb_proc.returncode, stdout.decode('ascii'), stderr.decode('ascii'))

def run_fuzzer(args):
    (fuzzer_bin, corpus_file) = args
    corpus_fd = open(corpus_file, 'r')
    fuzzer_proc = subprocess.Popen([fuzzer_bin], stdin=corpus_fd,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    (stdout, stderr) = fuzzer_proc.communicate()
    corpus_fd.close()
    return (corpus_file, fuzzer_proc.returncode, stdout.decode('ascii'), stderr.decode('ascii'))

def main(args=None):
    if args is None:
        args = sys.argv

    parser = optparse.OptionParser(
        usage='Usage: %prog [options] corpus_dir fuzzers_dir',
    )

    parser.add_option('--gdb', action='store_true',
                      help='Run under GDB and capture backtraces')

    (options, args) = parser.parse_args(args)

    if len(args) != 3:
        parser.print_usage()
        return 1

    corpus_dir = args[1]
    fuzzer_dir = args[2]

    if not os.access(corpus_dir, os.R_OK):
        print("Error could not access corpus directory '%s'" % (corpus_dir))
        return 1

    if not os.access(fuzzer_dir, os.R_OK):
        print("Error could not access fuzzers directory '%s'" % (fuzzer_dir))
        return 1

    fuzzers = set([])
    for fuzzer in os.listdir(fuzzer_dir):
        if fuzzer.endswith('.zip'):
            continue
        fuzzers.add(fuzzer)

    corpii = set([])
    for corpus in os.listdir(corpus_dir):
        # Ignore regular files in toplevel dir
        if not stat.S_ISDIR(os.stat(os.path.join(corpus_dir, corpus)).st_mode):
            continue

        if corpus == '.git':
            continue

        corpii.add(corpus)

    fuzzers_without_corpus = fuzzers - corpii
    corpus_without_fuzzers = corpii - fuzzers

    for f in sorted(list(fuzzers_without_corpus)):
        print("Warning: Fuzzer %s has no corpus" % (f))
    for c in sorted(list(corpus_without_fuzzers)):
        print("Warning: Corpus %s has no fuzzer" % (c))

    fuzzers_with_corpus = fuzzers & corpii

    crash_count = 0
    stderr_count = 0
    stdout_count = 0

    gdb_commands = None

    pool = multiprocessing.Pool(None)
    chunk_size = 32 # arbitrary

    run_fuzzer_func = run_fuzzer_gdb if options.gdb else run_fuzzer

    for fuzzer in sorted(list(fuzzers_with_corpus)):
        fuzzer_bin = os.path.join(fuzzer_dir, fuzzer)
        corpus_subdir = os.path.join(corpus_dir, fuzzer)
        corpus_files = [os.path.join(corpus_subdir, l) for l in sorted(list(os.listdir(corpus_subdir)))]

        # We have to do this hack because multiprocessing's Pool.map doesn't support
        # passing any initial arguments, just the single iteratable
        map_args = [(fuzzer_bin, f) for f in corpus_files]

        for result in pool.map(run_fuzzer_func, map_args, chunk_size):
            (corpus_file, retcode, stdout, stderr) = result

            if retcode != 0:
                print("Fuzzer %s crashed with input %s returncode %d" % (fuzzer, corpus_file, retcode))
                crash_count += 1

            if len(stdout) != 0:
                print("Fuzzer %s produced stdout on input %s:\n%s" % (fuzzer, corpus_file, stdout))
                stdout_count += 1

            if len(stderr) != 0:
                print("Fuzzer %s produced stderr on input %s:\n%s" % (fuzzer, corpus_file, stderr))
                stderr_count += 1

        print("Tested fuzzer %s with %d test cases, %d crashes" % (fuzzer, len(corpus_files), crash_count))
        sys.stdout.flush()

    if crash_count > 0 or stderr_count > 0 or stdout_count > 0:
        print("Ran fuzzer tests, %d crashes %d stdout %d stderr" % (crash_count, stdout_count, stderr_count))
        return 2
    return 0

if __name__ == '__main__':
    sys.exit(main())
