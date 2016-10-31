#!/usr/bin/env python

"""
Botan install script

(C) 2014,2015 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import errno
import logging
import optparse
import os
import shutil
import string
import sys
import subprocess

def parse_command_line(args):

    parser = optparse.OptionParser()

    parser.add_option('--verbose', action='store_true', default=False,
                      help='Show debug messages')
    parser.add_option('--quiet', action='store_true', default=False,
                      help='Show only warnings and errors')

    build_group = optparse.OptionGroup(parser, 'Source options')
    build_group.add_option('--build-dir', metavar='DIR', default='build',
                           help='Location of build output (default \'%default\')')
    parser.add_option_group(build_group)

    install_group = optparse.OptionGroup(parser, 'Installation options')
    install_group.add_option('--destdir', default='/usr/local',
                             help='Set output directory (default %default)')
    install_group.add_option('--bindir', default='bin', metavar='DIR',
                             help='Set binary subdir (default %default)')
    install_group.add_option('--libdir', default='lib', metavar='DIR',
                             help='Set library subdir (default %default)')
    install_group.add_option('--includedir', default='include', metavar='DIR',
                             help='Set include subdir (default %default)')
    install_group.add_option('--docdir', default='share/doc', metavar='DIR',
                             help='Set documentation subdir (default %default)')
    install_group.add_option('--pkgconfigdir', default='pkgconfig', metavar='DIR',
                             help='Set pkgconfig subdir (default %default)')

    install_group.add_option('--umask', metavar='MASK', default='022',
                             help='Umask to set (default %default)')
    parser.add_option_group(install_group)

    (options, args) = parser.parse_args(args)

    def log_level():
        if options.verbose:
            return logging.DEBUG
        if options.quiet:
            return logging.WARNING
        return logging.INFO

    logging.getLogger().setLevel(log_level())

    return (options, args)

def makedirs(dirname, exist_ok = True):
    try:
        logging.debug('Creating directory %s' % (dirname))
        os.makedirs(dirname)
    except OSError as e:
        if e.errno != errno.EEXIST or not exist_ok:
            raise e

# Clear link and create new one
def force_symlink(target, linkname):
    try:
        os.unlink(linkname)
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise e
    os.symlink(target, linkname)

def main(args = None):
    if args is None:
        args = sys.argv

    logging.basicConfig(stream = sys.stdout,
                        format = '%(levelname) 7s: %(message)s')

    (options, args) = parse_command_line(args)

    exe_mode = 0o777

    if 'umask' in os.__dict__:
        umask = int(options.umask, 8)
        logging.debug('Setting umask to %s' % oct(umask))
        os.umask(int(options.umask, 8))
        exe_mode &= (umask ^ 0o777)

    def copy_file(src, dst):
        shutil.copyfile(src, dst)
        #logging.debug('Copied %s to %s' % (src, dst))

    def copy_executable(src, dst):
        copy_file(src, dst)
        logging.debug('Copied %s to %s' % (src, dst))
        os.chmod(dst, exe_mode)

    cfg = eval(open(os.path.join(options.build_dir, 'build_config.py')).read())

    def process_template(template_str):
        class PercentSignTemplate(string.Template):
            delimiter = '%'

        try:
            template = PercentSignTemplate(template_str)
            return template.substitute(cfg)
        except KeyError as e:
            raise Exception('Unbound var %s in template' % (e))
        except Exception as e:
            raise Exception('Exception %s in template' % (e))

    ver_major = int(cfg['version_major'])
    ver_minor = int(cfg['version_minor'])
    ver_patch = int(cfg['version_patch'])

    bin_dir = os.path.join(options.destdir, options.bindir)
    lib_dir = os.path.join(options.destdir, options.libdir)
    target_doc_dir = os.path.join(options.destdir,
                                  options.docdir,
                                  'botan-%d.%d.%d' % (ver_major, ver_minor, ver_patch))
    target_include_dir = os.path.join(options.destdir,
                                      options.includedir,
                                      'botan-%d.%d' % (ver_major, ver_minor),
                                      'botan')

    out_dir = process_template('%{out_dir}')
    app_exe = process_template('botan%{program_suffix}') if str(cfg['os']) != "windows" else 'botan-cli.exe'

    for d in [options.destdir, lib_dir, bin_dir, target_doc_dir, target_include_dir]:
        makedirs(d)

    build_include_dir = os.path.join(options.build_dir, 'include', 'botan')

    for include in sorted(os.listdir(build_include_dir)):
        if include == 'internal':
            continue
        copy_file(os.path.join(build_include_dir, include),
                  os.path.join(target_include_dir, include))

    build_external_include_dir = os.path.join(options.build_dir, 'include', 'external')

    for include in sorted(os.listdir(build_external_include_dir)):
        copy_file(os.path.join(build_external_include_dir, include),
                  os.path.join(target_include_dir, include))

    static_lib = process_template('%{lib_prefix}%{libname}.%{static_suffix}')
    copy_file(os.path.join(out_dir, static_lib),
              os.path.join(lib_dir, os.path.basename(static_lib)))

    if bool(cfg['build_shared_lib']):
        if str(cfg['os']) == "windows":
            libname = process_template('%{libname}')
            soname_base = libname + '.dll'
            copy_executable(os.path.join(out_dir, soname_base),
                            os.path.join(lib_dir, soname_base))
        else:
            soname_patch = process_template('%{soname_patch}')
            soname_abi   = process_template('%{soname_abi}')
            soname_base  = process_template('%{soname_base}')

            copy_executable(os.path.join(out_dir, soname_patch),
                            os.path.join(lib_dir, soname_patch))

            prev_cwd = os.getcwd()

            try:
                os.chdir(lib_dir)
                force_symlink(soname_patch, soname_abi)
                force_symlink(soname_patch, soname_base)
            finally:
                os.chdir(prev_cwd)

    copy_executable(os.path.join(out_dir, app_exe), os.path.join(bin_dir, app_exe))

    # On Darwin, if we are using shared libraries and we install, we should fix
    # up the library name, otherwise the botan command won't work; ironically
    # we only need to do this because we previously changed it from a setting
    # that would be correct for installation to one that lets us run it from
    # the build directory
    if str(cfg['os']) == 'darwin' and bool(cfg['build_shared_lib']):
        soname_abi = process_template('%{soname_abi}')

        subprocess.check_call(['install_name_tool',
                               '-change',
                               os.path.join('@executable_path', soname_abi),
                               os.path.join(lib_dir, soname_abi),
                               os.path.join(bin_dir, app_exe)])

    if 'botan_pkgconfig' in cfg:
        pkgconfig_dir = os.path.join(options.destdir, options.libdir, options.pkgconfigdir)
        makedirs(pkgconfig_dir)
        copy_file(cfg['botan_pkgconfig'],
                  os.path.join(pkgconfig_dir, os.path.basename(cfg['botan_pkgconfig'])))

    if 'ffi' in cfg['mod_list'].split('\n'):
        for ver in cfg['python_version'].split(','):
            py_lib_path = os.path.join(lib_dir, 'python%s' % (ver), 'site-packages')
            logging.debug('Installing python module to %s' % (py_lib_path))
            makedirs(py_lib_path)
            for py in ['botan.py']:
                copy_file(os.path.join(cfg['python_dir'], py), os.path.join(py_lib_path, py))

    shutil.rmtree(target_doc_dir, True)
    shutil.copytree(cfg['doc_output_dir'], target_doc_dir)

    for f in [f for f in os.listdir(cfg['doc_dir']) if f.endswith('.txt')]:
        copy_file(os.path.join(cfg['doc_dir'], f), os.path.join(target_doc_dir, f))

    copy_file(os.path.join(cfg['base_dir'], 'license.txt'), os.path.join(target_doc_dir, 'license.txt'))
    copy_file(os.path.join(cfg['base_dir'], 'news.rst'), os.path.join(target_doc_dir, 'news.txt'))

    logging.info('Botan %s installation complete', cfg['version'])

if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as e:
        logging.error('Failure: %s' % (e))
        import traceback
        logging.info(traceback.format_exc())
        sys.exit(1)
