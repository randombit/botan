#!/usr/bin/python

import sys
import os
import subprocess

def main(args=None):
    if args is None:
        args = sys.argv

    if len(args) != 3:
        print("Usage: %s <corpus_dir> <fuzzers_dir>" % (args[0]))
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
        if corpus in ['.git', 'readme.txt']:
            continue
        corpii.add(corpus)

    fuzzers_without_corpus = fuzzers - corpii
    corpus_without_fuzzers = corpii - fuzzers

    for f in sorted(list(fuzzers_without_corpus)):
        print("Warning: Fuzzer %s has no corpus" % (f))
    for c in sorted(list(corpus_without_fuzzers)):
        print("Warning: Corpus %s has no fuzzer" % (c))

    fuzzers_with_corpus = fuzzers & corpii

    any_crashes = False

    for f in sorted(list(fuzzers_with_corpus)):
        fuzzer_bin = os.path.join(fuzzer_dir, f)
        corpus_files = os.path.join(corpus_dir, f)
        for corpus_file in sorted(list(os.listdir(corpus_files))):
            corpus_fd = open(os.path.join(corpus_files, corpus_file), 'r')
            fuzzer_proc = subprocess.Popen([fuzzer_bin], stdin=corpus_fd,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
            (stdout, stderr) = fuzzer_proc.communicate()
            corpus_fd.close()

            if fuzzer_proc.returncode != 0:
                print("Fuzzer %s crashed with input %s returncode %d" % (f, corpus_file, fuzzer_proc.returncode))
                any_crashes = True

            if len(stdout) != 0:
                stdout = stdout.decode('ascii')
                print("Fuzzer %s produced stdout on input %s:\n%s" % (f, corpus_file, stdout))

            if len(stderr) != 0:
                stderr = stderr.decode('ascii')
                print("Fuzzer %s produced stderr on input %s:\n%s" % (f, corpus_file, stderr))

    if any_crashes:
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
