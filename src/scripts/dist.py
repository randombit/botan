#!/usr/bin/env python2

"""
Release script for botan (http://botan.randombit.net/)

(C) 2011, 2012, 2013, 2015, 2016 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import errno
import logging
import optparse
import os
import shutil
import subprocess
import sys
import tarfile
import datetime
import hashlib
import re
import StringIO

def check_subprocess_results(subproc, name):
    (stdout, stderr) = subproc.communicate()

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

def run_git(args):
    cmd = ['git'] + args
    logging.debug('Running %s' % (' '.join(cmd)))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return check_subprocess_results(proc, 'git')

def maybe_gpg(val):
    # TODO: verify signatures
    if 'BEGIN PGP SIGNATURE' in val:
        return val.split('\n')[-2]
    else:
        return val.strip()

def datestamp(tag):
    ts = maybe_gpg(run_git(['show', '--no-patch', '--format=%ai', tag]))

    ts_matcher = re.compile('^(\d{4})-(\d{2})-(\d{2}) \d{2}:\d{2}:\d{2} .*')
    match = ts_matcher.match(ts)

    if match is None:
        logging.error('Failed parsing timestamp "%s" of tag %s' % (ts, tag))
        return 0

    return int(match.group(1) + match.group(2) + match.group(3))

def revision_of(tag):
    return maybe_gpg(run_git(['show', '--no-patch', '--format=%H', tag]))

def extract_revision(revision, to):
    tar_val = run_git(['archive', '--format=tar', '--prefix=%s/' % (to), revision])
    tar_f = tarfile.open(fileobj=StringIO.StringIO(tar_val))
    tar_f.extractall()

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

    parser.add_option('--output-dir', metavar='DIR', default='.',
                      help='Where to place output (default %default)')

    parser.add_option('--print-output-names', action='store_true',
                      help='Print output archive filenames to stdout')

    parser.add_option('--archive-types', metavar='LIST', default='tgz',
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

    if len(args) == 0 or len(args) > 2:
        logging.error('Usage error, try --help')
        return 1

    is_snapshot = args[0] == 'snapshot'
    target_version = None

    if is_snapshot:
        if len(args) == 1:
            logging.error('Missing branch name for snapshot command')
            return 1

        logging.info('Creating snapshot release from branch %s', args[1])
        target_version = 'HEAD'
    elif len(args) == 1:
        try:
            logging.info('Creating release for version %s' % (args[0]))

            (major,minor,patch) = map(int, args[0].split('.'))

            assert args[0] == '%d.%d.%d' % (major,minor,patch)
            target_version = args[0]
        except:
            logging.error('Invalid version number %s' % (args[0]))
            return 1
    else:
        logging.error('Usage error, try --help')
        return 1

    def output_name(args):
        if is_snapshot:
            datestamp = datetime.date.today().isoformat().replace('-', '')

            def snapshot_name(branch):
                if branch == 'master':
                    return 'trunk'
                else:
                    return branch

            return 'botan-%s-snapshot-%s' % (snapshot_name(args[1]), datestamp)
        else:
            return 'Botan-' + args[0]

    rev_id = revision_of(target_version)

    if rev_id == '':
        logging.error('No tag matching %s found' % (target_version))
        return 2

    rel_date = datestamp(target_version)
    if rel_date == 0:
        logging.error('No date found for version')
        return 2

    logging.info('Found %s at revision id %s released %d' % (target_version, rev_id, rel_date))

    output_basename = output_name(args)

    logging.debug('Output basename %s' % (output_basename))

    if os.access(output_basename, os.X_OK):
        logging.info('Removing existing output dir %s' % (output_basename))
        shutil.rmtree(output_basename)

    extract_revision(rev_id, output_basename)

    version_file = os.path.join(output_basename, 'botan_version.py')

    if os.access(version_file, os.R_OK) == False:
        logging.error('Cannot read %s' % (version_file))
        return 2

    # rewrite botan_version.py

    contents = open(version_file).readlines()

    version_re = re.compile('release_(major|minor|patch) = ([0-9]+)')
    version_parts = target_version.split('.')
    assert len(version_parts) == 3

    def content_rewriter():
        for line in contents:

            if target_version != 'HEAD':
                match = version_re.match(line)
                if match:
                    name_to_idx = {
                        'major': 0,
                        'minor': 1,
                        'patch': 2
                    }
                    in_tag = int(version_parts[name_to_idx[match.group(1)]])
                    in_file = int(match.group(2))

                    if in_tag != in_file:
                        logging.error('Version number part "%s" in botan_version.py does not match tag %s' %
                                      (match.group(1), target_version))
                        raise Exception('Bad botan_version.py')

            if line == 'release_vc_rev = None\n':
                yield 'release_vc_rev = \'git:%s\'\n' % (rev_id)
            elif line == 'release_datestamp = 0\n':
                yield 'release_datestamp = %d\n' % (rel_date)
            elif line == "release_type = \'unreleased\'\n":
                if args[0] == 'snapshot':
                    yield "release_type = 'snapshot'\n"
                else:
                    yield "release_type = 'released'\n"
            else:
                yield line

    open(version_file, 'w').write(''.join(list(content_rewriter())))

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

    if options.print_output_names:
        for output_file in output_files:
            print(output_file)

    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as e:
        logging.error(e)
        import traceback
        logging.debug(traceback.format_exc())
        sys.exit(1)
