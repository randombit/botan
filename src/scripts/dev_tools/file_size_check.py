#!/usr/bin/python

import json
import subprocess
import re
import sys

def lines_in(f):
    lines = 0
    for l in f.decode('utf8').splitlines():
        if l == '':
            continue

        if l.startswith('#'):
            continue
        lines += 1
    return lines

def run_cc(cmd):
    preproc = subprocess.run(cmd.split(' '), stdout=subprocess.PIPE)

    return lines_in(preproc.stdout)

cc = json.loads(open('build/compile_commands.json').read())

src_file = re.compile('-E src/.*/([a-z0-9/_]+.cpp) ')

search_for = None

if len(sys.argv) == 2:
    search_for = re.compile(sys.argv[1])

total_lines = 0
for c in cc:
    cmd = c['command'].replace(' -c ', ' -E ').split(' -o')[0] + " -o -"
    file_name = src_file.search(cmd)
    if file_name is None:
        continue

    file_name = file_name.group(1)
    if search_for is not None and search_for.search(file_name) is None:
        continue

    lines = run_cc(cmd)
    total_lines += lines
    print(lines, file_name)
    sys.stdout.flush()

print(total_lines, "total")
