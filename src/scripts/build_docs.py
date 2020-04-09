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

def find_rst2man():
    possible_names = ['rst2man', 'rst2man.py']

    for name in possible_names:
        if have_prog(name):
            return name
    raise Exception("Was configured with rst2man but could not be located in PATH")

def touch(fname):
    try:
        os.utime(fname, None)
    except OSError:
        open(fname, 'a').close()

def copy_files(src_path, dest_dir):

    logging.debug("Copying %s to %s", src_path, dest_dir)

    file_mode = os.stat(src_path).st_mode

    try:
        os.mkdir(dest_dir)
    except OSError:
        pass

    if stat.S_ISREG(file_mode):
        logging.debug("Copying file %s to %s", src_path, dest_dir)
        shutil.copy(src_path, dest_dir)
    else:
        for f in os.listdir(src_path):
            src_file = os.path.join(src_path, f)
            file_mode = os.stat(src_file).st_mode
            if stat.S_ISREG(file_mode):
                dest_file = os.path.join(dest_dir, f)
                shutil.copyfile(src_file, dest_file)
            elif stat.S_ISDIR(file_mode):
                copy_files(os.path.join(src_path, f), os.path.join(dest_dir, f))

def run_and_check(cmd_line, cwd=None):

    logging.info("Starting %s", ' '.join(cmd_line))

    try:
        proc = subprocess.Popen(cmd_line, cwd=cwd)

        proc.communicate()
    except OSError as e:
        logging.error("Executing %s failed (%s)", ' '.join(cmd_line), e)

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

def sphinx_supports_concurrency():
    import re
    from distutils.version import StrictVersion

    proc = subprocess.Popen(['sphinx-build', '--version'],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    output, _ = proc.communicate()
    if isinstance(output, bytes):
        output = output.decode('ascii')
    output = output.strip()

    # Sphinx v1.1.3
    # sphinx-build 1.7.4
    match = re.match(r'^(?:[a-zA-Z_-]+) v?(([0-9]+)\.([0-9]+))', output)

    if match is None:
        # If regex doesn't match, disable by default
        logging.warning("Did not recognize sphinx version from '%s'", output)
        return False

    version = StrictVersion(match.group(1))

    if version < StrictVersion('1.4'):
        # not supported
        return False
    if version == StrictVersion('3.0'):
        # Bug in Sphinx 3.0 https://github.com/sphinx-doc/sphinx/issues/7438
        return False
    return True

def read_config(config):
    try:
        f = open(config)
        cfg = json.load(f)
        f.close()
    except OSError:
        raise Exception('Failed to load build config %s - is build dir correct?' % (config))

    return cfg

def main(args=None):
    # pylint: disable=too-many-branches

    if args is None:
        args = sys.argv

    logging.basicConfig(stream=sys.stdout,
                        format='%(levelname) 7s: %(message)s')

    options = parse_options(args)

    if options is None:
        return 1

    cfg = read_config(os.path.join(options.build_dir, 'build_config.json'))

    with_docs = bool(cfg['with_documentation'])
    with_sphinx = bool(cfg['with_sphinx'])
    with_pdf = bool(cfg['with_pdf'])
    with_rst2man = bool(cfg['with_rst2man'])
    with_doxygen = bool(cfg['with_doxygen'])

    doc_stamp_file = cfg['doc_stamp_file']

    handbook_src = cfg['doc_dir']
    handbook_output = cfg['handbook_output_dir']

    if with_docs is False:
        logging.debug('Documentation build disabled')
        return 0

    cmds = []

    if with_doxygen:
        cmds.append(['doxygen', os.path.join(cfg['build_dir'], 'botan.doxy')])

    if with_sphinx:
        sphinx_build = ['sphinx-build', '-q', '-c', cfg['sphinx_config_dir']]
        if sphinx_supports_concurrency():
            sphinx_build += ['-j', str(get_concurrency())]

        cmds.append(sphinx_build + ['-b', 'html', handbook_src, handbook_output])

        if with_pdf:
            latex_output = tempfile.mkdtemp(prefix='botan_latex_')
            cmds.append(sphinx_build + ['-b', 'latex', handbook_src, latex_output])
            cmds.append(['make', '-C', latex_output])
            cmds.append(['cp', os.path.join(latex_output, 'botan.pdf'), handbook_output])
    else:
        # otherwise just copy it
        cmds.append(['cp', handbook_src, handbook_output])

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
