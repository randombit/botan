#!/usr/bin/python

import sys
import re
import os.path

def update_requires(dir, deps):
    lines = map(lambda x: x.strip(),
                open(os.path.join(dir, 'info.txt')).readlines())

    if '<requires>' in lines:
        start = lines.index('<requires>')

        while lines.pop(start) != '</requires>':
            pass

    while lines[-1] == '':
        lines = lines[:-1]

    if len(deps) > 0:
        lines.append('')
        lines.append('<requires>')
        for dep in deps:
            lines.append(dep)
        lines.append('</requires>')
        lines.append('')

    lines = "\n".join(lines).replace("\n\n\n", "\n\n")

    output = open(os.path.join(dir, 'info.txt'), 'w')
    output.write(lines)
    output.close()

def main():
    for line in sys.stdin.readlines():
        (dirname, deps) = line.split(':')
        deps = deps.strip().split(' ')
        update_requires(dirname, deps)

if __name__ == '__main__':
    sys.exit(main())
