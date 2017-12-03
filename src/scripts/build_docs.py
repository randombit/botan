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
import os

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

def touch(fname):
    try:
        os.utime(fname, None)
    except OSError:
        open(fname, 'a').close()

def copy_files(src_dir, dest_dir):
    for f in os.listdir(src_dir):
        src_file = os.path.join(src_dir, f)
        dest_file = os.path.join(dest_dir, f)
        logging.debug("Copying from %s to %s", src_file, dest_file)
        shutil.copyfile(src_file, dest_file)

def run_and_check(cmd_line):

    logging.debug("Executing %s", ' '.join(cmd_line))

    proc = subprocess.Popen(cmd_line,
                            close_fds=True)

    (stdout, stderr) = proc.communicate()

    if proc.returncode != 0:
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
        cmds.append(['sphinx-build', '-q', '-b', 'html', '-c', cfg['sphinx_config_dir'],
                     '-j', str(get_concurrency()), manual_src, manual_output])
    else:
        # otherwise just copy it
        cmds.append(['cp', manual_src, manual_output])

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

if __name__ == '__main__':
    sys.exit(main())
