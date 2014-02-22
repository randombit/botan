#!/usr/bin/env python

"""
Release script for botan (http://botan.randombit.net/)

(C) 2011, 2012, 2013 Jack Lloyd

Distributed under the terms of the Botan license
"""

import errno
import logging
import optparse
import os
import shlex
import StringIO
import shutil
import subprocess
import sys
import tarfile
import datetime
import hashlib

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
    cmd = ['mtn', '--db', db] + args

    logging.debug('Running %s' % (' '.join(cmd)))

    mtn = subprocess.Popen(cmd,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)

    return check_subprocess_results(mtn, 'mtn')

def get_certs(db, rev_id):
    tokens = shlex.split(run_monotone(db, ['automate', 'certs', rev_id]))

    def usable_cert(cert):
        if 'signature' not in cert or cert['signature'] != 'ok':
            return False
        if 'trust' not in cert or cert['trust'] != 'trusted':
            return False
        if 'name' not in cert or 'value' not in cert:
            return False
        return True

    def cert_builder(tokens):
        pairs = zip(tokens[::2], tokens[1::2])
        current_cert = {}
        for pair in pairs:
            if pair[0] == 'trust':
                if usable_cert(current_cert):
                    name = current_cert['name']
                    value = current_cert['value']
                    current_cert = {}

                    logging.debug('Cert %s "%s" for rev %s' % (name, value, rev_id))
                    yield (name, value)

            current_cert[pair[0]] = pair[1]

    certs = dict(cert_builder(tokens))
    return certs

def datestamp(db, rev_id):
    certs = get_certs(db, rev_id)

    if 'date' in certs:
        datestamp = int(certs['date'].replace('-','')[0:8])
        logging.info('Using datestamp %s for rev %s' % (datestamp, rev_id))
        return datestamp

    logging.info('Could not retreive date for %s' % (rev_id))
    return 0

def gpg_sign(keyid, passphrase_file, files, detached = True):

    options = ['--armor', '--detach-sign'] if detached else ['--clearsign']

    gpg_cmd = ['gpg', '--batch'] + options + ['--local-user', keyid]
    if passphrase_file != None:
        gpg_cmd[1:1] = ['--passphrase-file', passphrase_file]

    for filename in files:
        logging.info('Signing %s using PGP id %s' % (filename, keyid))

        cmd = gpg_cmd + [filename]

        logging.debug('Running %s' % (' '.join(cmd)))

        gpg = subprocess.Popen(cmd,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)

        check_subprocess_results(gpg, 'gpg')

    return [filename + '.asc' for filename in files]

def parse_args(args):
    parser = optparse.OptionParser(
        "usage: %prog [options] <version #>\n" +
        "       %prog [options] snapshot <branch>"
        )

    parser.add_option('--verbose', action='store_true',
                      default=False, help='Extra debug output')

    parser.add_option('--quiet', action='store_true',
                      default=False, help='Only show errors')

    parser.add_option('--output-dir', metavar='DIR',
                      default='.',
                      help='Where to place output (default %default)')

    parser.add_option('--mtn-db', metavar='DB',
                      default=os.getenv('BOTAN_MTN_DB', ''),
                      help='Set monotone db (default \'%default\')')

    parser.add_option('--print-output-names', action='store_true',
                      help='Print output archive filenames to stdout')

    parser.add_option('--archive-types', metavar='LIST', default='tbz,tgz',
                      help='Set archive types to generate (default %default)')

    parser.add_option('--pgp-key-id', metavar='KEYID',
                      default='EFBADFBC',
                      help='PGP signing key (default %default, "none" to disable)')

    parser.add_option('--pgp-passphrase-file', metavar='FILE',
                      default=None,
                      help='PGP signing key passphrase file')

    parser.add_option('--write-hash-file', metavar='FILE', default=None,
                      help='Write a file with checksums')

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
        if options.quiet:
            return logging.ERROR
        return logging.INFO

    logging.basicConfig(stream = sys.stderr,
                        format = '%(levelname) 7s: %(message)s',
                        level = log_level())

    if options.mtn_db == '':
        logging.error('No monotone db set (use --mtn-db)')
        return 1

    if not os.access(options.mtn_db, os.R_OK):
        logging.error('Monotone db %s not found' % (options.mtn_db))
        return 1

    if len(args) == 0 or len(args) >= 3:
        logging.error('Usage error, try --help')
        return 1

    # Sanity check arguments

    if args[0] == 'snapshot':

        if len(args) == 1:
            logging.error('Missing branch name for snapshot command')
            return 1

        logging.info('Creating snapshot release from branch %s', args[1])

    elif len(args) == 1:
        try:
            logging.info('Creating release for version %s' % (args[0]))

            (major,minor,patch) = map(int, args[0].split('.'))

            assert args[0] == '%d.%d.%d' % (major,minor,patch)
        except:
            logging.error('Invalid version number %s' % (args[0]))
            return 1

    else:
        logging.error('Usage error, try --help')
        return 1

    def selector(args):
        if args[0] == 'snapshot':
            return 'h:' + args[1]
        else:
            return 't:' + args[0]

    def output_name(args):
        if args[0] == 'snapshot':
            datestamp = datetime.date.today().isoformat().replace('-', '')

            def snapshot_name(branch):
                if branch == 'net.randombit.botan':
                    return 'trunk'
                elif branch == 'net.randombit.botan.1_10':
                    return '1.10'
                else:
                    return branch

            return 'botan-%s-snapshot-%s' % (snapshot_name(args[1]), datestamp)
        else:
            return 'Botan-' + args[0]

    rev_id = run_monotone(options.mtn_db, ['automate', 'select', selector(args)])

    if rev_id == '':
        logging.error('No revision matching %s found' % (selector(args)))
        return 2

    logging.info('Found revision id %s' % (rev_id))

    output_basename = output_name(args)

    logging.debug('Output basename %s' % (output_basename))

    if os.access(output_basename, os.X_OK):
        logging.info('Removing existing output dir %s' % (output_basename))
        shutil.rmtree(output_basename)

    run_monotone(options.mtn_db,
                 ['checkout', '--quiet', '-r', rev_id, output_basename])

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
                elif line == 'release_datestamp = 0\n':
                    yield 'release_datestamp = %d\n' % (datestamp(options.mtn_db, rev_id))
                elif line == "release_type = \'unreleased\'\n":
                    if args[0] == 'snapshot':
                        yield "release_type = 'snapshot'\n"
                    else:
                        yield "release_type = 'released'\n"
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

    output_files = []

    archives = options.archive_types.split(',') if options.archive_types != '' else []

    hash_file = None
    if options.write_hash_file != None:
        hash_file = open(options.write_hash_file, 'w')

    for archive in archives:
        logging.debug('Writing archive type "%s"' % (archive))

        output_archive = output_basename + '.' + archive

        remove_file_if_exists(output_archive)
        remove_file_if_exists(output_archive + '.asc')

        if archive in ['tgz', 'tbz']:

            def write_mode():
                if archive == 'tgz':
                    return 'w:gz'
                elif archive == 'tbz':
                    return 'w:bz2'

            archive = tarfile.open(output_archive, write_mode())

            all_files = []
            for (curdir,_,files) in os.walk(output_basename):
                all_files += [os.path.join(curdir, f) for f in files]
            all_files.sort()

            for f in all_files:
                archive.add(f)
            archive.close()

            if hash_file != None:
                sha256 = hashlib.new('sha256')
                sha256.update(open(output_archive).read())
                hash_file.write("%s  %s\n" % (sha256.hexdigest(), output_archive))
        else:
            raise Exception('Unknown archive type "%s"' % (archive))

        output_files.append(output_archive)

    if hash_file != None:
        hash_file.close()

    shutil.rmtree(output_basename)

    if options.print_output_names:
        for output_file in output_files:
            print(output_file)

    if options.pgp_key_id != 'none':
        if options.write_hash_file != None:
            output_files += gpg_sign(options.pgp_key_id, options.pgp_passphrase_file,
                                     [options.write_hash_file], False)
        else:
            output_files += gpg_sign(options.pgp_key_id, options.pgp_passphrase_file,
                                     output_files, True)

    if options.output_dir != '.':
        for output_file in output_files:
            logging.debug('Moving %s to %s' % (output_file, options.output_dir))
            shutil.move(output_file, os.path.join(options.output_dir, output_file))

    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as e:
        logging.error(e)
        import traceback
        logging.info(traceback.format_exc())
        sys.exit(1)
