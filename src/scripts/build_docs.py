#!/usr/bin/env python

"""
Botan doc generation script

(C) 2014,2015,2017 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import sys
import optparse # pylint: disable=deprecated-module
import subprocess
import shutil
import logging
import json
import tempfile
import os
import stat

def get_concurrency():
    """
    Get default concurrency level of build
    """
    def_concurrency = 2

    try:
        import multiprocessing
        return max(def_concurrency, multiprocessing.cpu_count())
    except ImportError:
        return def_concurrency

def have_prog(prog):
    """
    Check if some named program exists in the path
    """
    for path in os.environ['PATH'].split(os.pathsep):
        exe_file = os.path.join(path, prog)
        if os.path.exists(exe_file) and os.access(exe_file, os.X_OK):
            return True
    return False

def touch(fname):
    try:
        os.utime(fname, None)
    except OSError:
        open(fname, 'a').close()

def copy_files(src_path, dest_dir):

    file_mode = os.stat(src_path).st_mode

    if stat.S_ISREG(file_mode):
        logging.debug("Copying file %s to %s", src_path, dest_dir)
        shutil.copy(src_path, dest_dir)
    else:
        for f in os.listdir(src_path):
            src_file = os.path.join(src_path, f)
            dest_file = os.path.join(dest_dir, f)
            logging.debug("Copying dir %s to %s", src_file, dest_file)
            shutil.copyfile(src_file, dest_file)

def run_and_check(cmd_line, cwd=None):

    logging.debug("Executing %s", ' '.join(cmd_line))

    stdout = None
    stderr = None

    try:
        proc = subprocess.Popen(cmd_line,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                cwd=cwd)

        (stdout, stderr) = proc.communicate()
    except OSError as e:
        logging.error("Executing %s failed (%s)", ' '.join(cmd_line), e)

    if stdout:
        logging.debug(stdout.decode())

    if stderr:
        logging.debug(stderr.decode())

    if proc.returncode != 0:
        logging.info(stdout.decode())
        logging.info(stderr.decode())
        logging.error("Error running %s", ' '.join(cmd_line))
        sys.exit(1)


def parse_options(args):
    parser = optparse.OptionParser()

    parser.add_option('--verbose', action='store_true', default=False,
                      help='Show debug messages')
    parser.add_option('--quiet', action='store_true', default=False,
                      help='Show only warnings and errors')

    parser.add_option('--build-dir', metavar='DIR', default='build',
                      help='Location of build output (default \'%default\')')
    parser.add_option('--dry-run', default=False, action='store_true',
                      help='Just display what would be done')

    (options, args) = parser.parse_args(args)

    if len(args) > 1:
        logging.error("Unknown arguments")
        return None

    def log_level():
        if options.verbose:
            return logging.DEBUG
        if options.quiet:
            return logging.WARNING
        return logging.INFO

    logging.getLogger().setLevel(log_level())

    return options


def main(args=None):
    # pylint: disable=too-many-branches,too-many-locals

    if args is None:
        args = sys.argv

    logging.basicConfig(stream=sys.stdout,
                        format='%(levelname) 7s: %(message)s')

    options = parse_options(args)

    if options is None:
        return 1

    with open(os.path.join(options.build_dir, 'build_config.json')) as f:
        cfg = json.load(f)

    with_docs = bool(cfg['with_documentation'])
    with_sphinx = bool(cfg['with_sphinx'])
    with_pdf = bool(cfg['with_pdf'])
    with_rst2man = bool(cfg['with_rst2man'])
    with_doxygen = bool(cfg['with_doxygen'])

    doc_stamp_file = cfg['doc_stamp_file']

    manual_src = os.path.join(cfg['doc_dir'], 'manual')
    manual_output = os.path.join(cfg['doc_output_dir'], 'manual')

    if with_docs is False:
        logging.debug('Documentation build disabled')
        return 0

    cmds = []

    if with_doxygen:
        cmds.append(['doxygen', os.path.join(cfg['build_dir'], 'botan.doxy')])

    if with_sphinx:
        sphinx_build = ['sphinx-build',
                        '-c', cfg['sphinx_config_dir'],
                        '-j', str(get_concurrency())]

        cmds.append(sphinx_build + ['-b', 'html', manual_src, manual_output])

        if with_pdf:
            latex_output = tempfile.mkdtemp(prefix='botan_latex_')
            cmds.append(sphinx_build + ['-b', 'latex', manual_src, latex_output])
            cmds.append(['make', '-C', latex_output])
            cmds.append(['cp', os.path.join(latex_output, 'botan.pdf'), manual_output])
    else:
        # otherwise just copy it
        cmds.append(['cp', manual_src, manual_output])

    def find_rst2man():
        possible_names = ['rst2man', 'rst2man.py']

        for name in possible_names:
            if have_prog(name):
                return name

        raise Exception("Was configured with rst2man but could not be located in PATH")

    if with_rst2man:
        cmds.append([find_rst2man(),
                     os.path.join(cfg['build_dir'], 'botan.rst'),
                     os.path.join(cfg['build_dir'], 'botan.1')])

    cmds.append(['touch', doc_stamp_file])

    for cmd in cmds:
        if options.dry_run:
            print(' '.join(cmd))
        else:
            if cmd[0] == 'cp':
                assert len(cmd) == 3
                copy_files(cmd[1], cmd[2])
            elif cmd[0] == 'touch':
                assert len(cmd) == 2
                touch(cmd[1])
            else:
                run_and_check(cmd)
    return 0

if __name__ == '__main__':
    sys.exit(main())
