#!/usr/bin/python

import json
import subprocess
import re
import sys
from multiprocessing.pool import ThreadPool

def lines_in(f):
    lines = 0
    for line in f.decode('utf8').splitlines():
        if line == '':
            continue

        if line.startswith('#'):
            continue
        lines += 1
    return lines

def run_cc(cmd):
    preproc = subprocess.run(cmd.split(' '), stdout=subprocess.PIPE)

    return lines_in(preproc.stdout)

def main():
    search_for = None

    if len(sys.argv) == 2:
        search_for = re.compile(sys.argv[1])

    cc = json.loads(open('build/compile_commands.json').read())

    src_file = re.compile('-E src/.*/([a-z0-9/_]+.cpp) ')

    pool = ThreadPool(8)

    total_lines = 0
    futures = []
    for c in cc:
        cmd = c['command'].replace(' -c ', ' -E ').split(' -o')[0] + " -o -"
        file_name = src_file.search(cmd)
        if file_name is None:
            continue

        file_name = file_name.group(1)
        if search_for is not None and search_for.search(file_name) is None:
            continue

        futures.append((file_name, pool.apply_async(run_cc, (cmd, ))))

    for (file_name, future) in futures:
        lines = future.get()
        total_lines += lines
        print(lines, file_name)
        sys.stdout.flush()

    print(total_lines, "total")

if __name__ == '__main__':
    sys.exit(main())
