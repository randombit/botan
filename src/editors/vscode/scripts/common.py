import os
import sys
import subprocess
import re
import multiprocessing

class BuildError(Exception):
    pass


_MAKEFILE = "Makefile"


def get_concurrency():
    def_concurrency = 2
    max_concurrency = 16

    try:
        return min(max_concurrency, multiprocessing.cpu_count())
    except ImportError:
        return def_concurrency


def run_cmd(cmd, workingdir=None):
    if isinstance(cmd, str):
        print('> running: ' + cmd)
        shell = True
    else:
        print('> running: ' + ' '.join(cmd))
        shell = False
    sys.stdout.flush()

    try:
        subprocess.run(cmd, shell=shell, check=True, cwd=workingdir)
    except subprocess.CalledProcessError as ex:
        raise BuildError('External command failed, aborting...') from ex


def _find_regex_in_makefile(regex):
    if not os.path.exists(_MAKEFILE):
        raise BuildError('No Makefile found. Maybe run ./configure.py?')

    with open(_MAKEFILE, 'r', encoding="utf-8") as f:
        return re.search(regex, f.read())


def get_test_binary_name():
    match = _find_regex_in_makefile(r'TEST\s*=\s*([^\n]+)\n')
    if not match:
        raise BuildError('Test binary name not found in Makefile')
    test_file = os.path.split(match.group(1))[1]
    if not test_file:
        raise BuildError(
            'Cannot make sense of test binary name: ' + match.group(0))

    return test_file
