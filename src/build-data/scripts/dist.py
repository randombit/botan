#!/usr/bin/python

"""
Release script for botan (http://botan.randombit.net/)

(C) 2011, 2012 Jack Lloyd

Distributed under the terms of the Botan license
"""

import optparse
import subprocess
import logging
import os
import sys
import shutil
import tarfile
import errno

def check_subprocess_results(subproc, name):
    (stdout, stderr) = subproc.communicate()

    stdout = stdout.strip()
    stderr = stderr.strip()

    if subproc.returncode != 0:
        if stdout != '':
            logging.error(stdout)
        if stderr != '':
            logging.error(stderr)
        raise Exception('Running %s failed' % (name))
    else:
        if stderr != '':
            logging.debug(stderr)

    return stdout

def run_monotone(db, args):
    mtn = subprocess.Popen(['mtn', '--db', db] + args,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)

    return check_subprocess_results(mtn, 'mtn')

def gpg_sign(file, keyid):
    logging.info('Signing %s using PGP id %s' % (file, keyid))

    gpg = subprocess.Popen(['gpg', '--armor', '--detach-sign',
                            '--local-user', keyid, file],
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)

    check_subprocess_results(gpg, 'gpg')

def parse_args(args):
    parser = optparse.OptionParser()
    parser.add_option('--verbose', action='store_true',
                      default=False, help='Extra debug output')

    parser.add_option('--output-dir', metavar='DIR',
                      default='.',
                      help='Where to place output (default %default)')

    parser.add_option('--mtn-db', metavar='DB',
                      default=os.getenv('BOTAN_MTN_DB', ''),
                      help='Set monotone db (default \'%default\')')

    parser.add_option('--pgp-key-id', metavar='KEYID',
                      default='EFBADFBC',
                      help='PGP signing key (default %default)')

    return parser.parse_args(args)

def remove_file_if_exists(fspath):
    try:
        os.unlink(fspath)
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise

def main(args = None):
    if args is None:
        args = sys.argv[1:]

    (options, args) = parse_args(args)

    def log_level():
        if options.verbose:
            return logging.DEBUG
        return logging.INFO

    logging.basicConfig(stream = sys.stdout,
                        format = '%(levelname) 7s: %(message)s',
                        level = log_level())

    if options.mtn_db == '':
        logging.error('No monotone db set (use --mtn-db)')
        return 1

    if not os.access(options.mtn_db, os.R_OK):
        logging.error('Monotone db %s not found' % (options.mtn_db))
        return 1

    if len(args) != 1:
        logging.error('Usage: %s version' % (sys.argv[0]))
        return 1

    version = args[0]

    rev_id = run_monotone(options.mtn_db,
                          ['automate', 'select', 't:' + version])

    if rev_id == '':
        logging.error('No revision for %s found' % (version))
        return 2

    output_basename = os.path.join(options.output_dir, 'Botan-' + version)

    output_tgz = output_basename + '.tgz'
    output_tbz = output_basename + '.tbz'

    logging.info('Found revision id %s' % (rev_id))

    if os.access(output_basename, os.X_OK):
        shutil.rmtree(output_basename)

    run_monotone(options.mtn_db,
                 ['checkout', '-r', rev_id, output_basename])

    shutil.rmtree(os.path.join(output_basename, '_MTN'))
    remove_file_if_exists(os.path.join(output_basename, '.mtn-ignore'))

    version_file = os.path.join(output_basename, 'botan_version.py')

    if os.access(version_file, os.R_OK):
        # rewrite botan_version.py

        contents = open(version_file).readlines()

        def content_rewriter():
            for line in contents:
                if line == 'release_vc_rev = None\n':
                    yield 'release_vc_rev = \'mtn:%s\'\n' % (rev_id)
                else:
                    yield line

        open(version_file, 'w').write(''.join(list(content_rewriter())))
    else:
        logging.error('Cannot find %s' % (version_file))
        return 2

    try:
        os.makedirs(options.output_dir)
    except OSError as e:
        if e.errno != errno.EEXIST:
            logging.error('Creating dir %s failed %s' % (options.output_dir, e))
            return 2

    remove_file_if_exists(output_tgz)
    remove_file_if_exists(output_tgz + '.asc')
    archive = tarfile.open(output_tgz, 'w:gz')
    archive.add(output_basename)
    archive.close()
    if options.pgp_key_id != '':
        gpg_sign(output_tgz, options.pgp_key_id)

    remove_file_if_exists(output_tbz)
    remove_file_if_exists(output_tbz + '.asc')
    archive = tarfile.open(output_tbz, 'w:bz2')
    archive.add(output_basename)
    archive.close()
    if options.pgp_key_id != '':
        gpg_sign(output_tbz, options.pgp_key_id)

    shutil.rmtree(output_basename)

    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as e:
        logging.error(e)
        import traceback
        logging.info(traceback.format_exc())
        sys.exit(1)
