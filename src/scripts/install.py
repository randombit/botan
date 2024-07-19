#!/usr/bin/env python3

"""
Botan install script

(C) 2014,2015,2017 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import errno
import json
import logging
import optparse # pylint: disable=deprecated-module
import os
import shutil
import sys
import traceback

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

    install_group = optparse.OptionGroup(parser, 'Install options')
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


class PrependDestdirError(Exception):
    pass


def is_subdir(path, subpath):
    return os.path.relpath(path, start=subpath).startswith("..")


def prepend_destdir(path):
    """
    Needed because os.path.join() discards the first path if the
    second one is absolute, which is usually the case here. Still, we
    want relative paths to work and leverage the os awareness of
    os.path.join().
    """
    destdir = os.environ.get('DESTDIR', "")

    if destdir:
        # DESTDIR is non-empty, but we only join absolute paths on UNIX-like file systems
        if os.path.sep != "/":
            raise PrependDestdirError("Only UNIX-like file systems using forward slash " \
                                      "separator supported when DESTDIR is set.")
        if not os.path.isabs(path):
            raise PrependDestdirError("--prefix must be an absolute path when DESTDIR is set.")

        path = os.path.normpath(path)
        # Remove / or \ prefixes if existent to accomodate for os.path.join()
        path = path.lstrip(os.path.sep)
        path = os.path.join(destdir, path)

        if not is_subdir(destdir, path):
            raise PrependDestdirError("path escapes DESTDIR (path='%s', destdir='%s')" % (path, destdir))

    return path


def makedirs(dirname, exist_ok=True):
    try:
        logging.debug('Creating directory %s', dirname)
        os.makedirs(dirname)
    except OSError as ex:
        if ex.errno != errno.EEXIST or not exist_ok:
            raise ex

# Clear link and create new one
def force_symlink(target, linkname):
    try:
        os.unlink(linkname)
    except OSError as ex:
        if ex.errno != errno.ENOENT:
            raise ex
    os.symlink(target, linkname)

def calculate_exec_mode(options):
    out = 0o777
    if 'umask' in os.__dict__:
        umask = int(options.umask, 8)
        logging.debug('Setting umask to %s', oct(umask))
        os.umask(int(options.umask, 8))
        out &= (umask ^ 0o777)
    return out

def main(args):
    logging.basicConfig(stream=sys.stdout,
                        format='%(levelname) 7s: %(message)s')

    (options, args) = parse_command_line(args)

    exe_mode = calculate_exec_mode(options)
    build_dir = options.build_dir

    def copy_file(src, dst):
        logging.debug('Copying %s to %s', src, dst)
        shutil.copyfile(src, dst)

    def copy_executable(src, dst):
        copy_file(src, dst)
        logging.debug('Make %s executable', dst)
        os.chmod(dst, exe_mode)

    with open(os.path.join(build_dir, 'build_config.json'), encoding='utf8') as f:
        cfg = json.load(f)

    ver_major = int(cfg['version_major'])
    ver_minor = int(cfg['version_minor'])
    ver_patch = int(cfg['version_patch'])
    target_os = cfg['os']
    build_shared_lib = bool(cfg['build_shared_lib'])
    build_static_lib = bool(cfg['build_static_lib'])
    build_cli = bool(cfg['build_cli_exe'])
    out_dir = cfg['out_dir']

    bin_dir = cfg['bindir']
    lib_dir = cfg['libdir']
    target_include_dir = cfg['installed_include_dir']
    pkgconfig_dir = os.path.join(lib_dir, 'pkgconfig')
    cmake_dir = os.path.join(lib_dir, 'cmake', 'Botan-%s' % cfg["version"])

    prefix = cfg['prefix']

    for d in [prefix, lib_dir, bin_dir, target_include_dir]:
        makedirs(prepend_destdir(d))

    for header in cfg['public_headers']:
        full_header_path = os.path.join(cfg['public_include_path'], header)
        copy_file(full_header_path,
                  prepend_destdir(os.path.join(target_include_dir, header)))

    for header in cfg['external_headers']:
        full_header_path = os.path.join(cfg['external_include_path'], header)
        copy_file(full_header_path,
                  prepend_destdir(os.path.join(target_include_dir, header)))

    if build_static_lib:
        static_lib = cfg['static_lib_name']
        copy_file(os.path.join(out_dir, static_lib),
                  prepend_destdir(os.path.join(lib_dir, os.path.basename(static_lib))))

    if build_shared_lib:
        if target_os == "windows":
            libname = cfg['libname']
            soname_base = libname + '.dll'
            implib = cfg['implib_name']
            copy_executable(os.path.join(out_dir, soname_base),
                            prepend_destdir(os.path.join(bin_dir, soname_base)))
            copy_file(os.path.join(out_dir, implib),
                      prepend_destdir(os.path.join(lib_dir, os.path.basename(implib))))
        elif target_os == "mingw":
            shared_lib_name = cfg['shared_lib_name']
            copy_executable(os.path.join(out_dir, shared_lib_name),
                            prepend_destdir(os.path.join(bin_dir, shared_lib_name)))
            implib_name = shared_lib_name + '.a'
            copy_executable(os.path.join(out_dir, implib_name),
                            prepend_destdir(os.path.join(lib_dir, implib_name)))
        else:
            soname_patch = cfg['soname_patch']
            soname_abi = cfg['soname_abi']
            soname_base = cfg['soname_base']

            copy_executable(os.path.join(out_dir, soname_patch),
                            prepend_destdir(os.path.join(lib_dir, soname_patch)))

            if cfg['symlink_shared_lib']:
                prev_cwd = os.getcwd()
                try:
                    os.chdir(prepend_destdir(lib_dir))
                    force_symlink(soname_patch, soname_abi)
                    force_symlink(soname_patch, soname_base)
                finally:
                    os.chdir(prev_cwd)

    if build_cli:
        copy_executable(cfg['cli_exe'], prepend_destdir(os.path.join(bin_dir, cfg['cli_exe_name'])))

    if 'botan_pkgconfig' in cfg:
        makedirs(prepend_destdir(pkgconfig_dir))
        copy_file(cfg['botan_pkgconfig'],
                  prepend_destdir(os.path.join(pkgconfig_dir, os.path.basename(cfg['botan_pkgconfig']))))

    if 'botan_cmake_config' in cfg and 'botan_cmake_version_config' in cfg:
        makedirs(prepend_destdir(cmake_dir))
        copy_file(cfg['botan_cmake_config'],
                  prepend_destdir(os.path.join(cmake_dir, os.path.basename(cfg['botan_cmake_config']))))
        copy_file(cfg['botan_cmake_version_config'],
                  prepend_destdir(os.path.join(cmake_dir, os.path.basename(cfg['botan_cmake_version_config']))))

    if 'ffi' in cfg['mod_list'] and cfg['build_shared_lib'] is True and cfg['install_python_module'] is True:
        for ver in cfg['python_version'].split(','):
            py_lib_path = os.path.join(lib_dir, 'python%s' % (ver), 'site-packages')
            logging.debug('Installing python module to %s', py_lib_path)
            makedirs(prepend_destdir(py_lib_path))

            py_dir = cfg['python_dir']

            copy_file(os.path.join(py_dir, 'botan3.py'),
                      prepend_destdir(os.path.join(py_lib_path, 'botan3.py')))

    if cfg['with_documentation']:
        target_doc_dir = os.path.join(prefix, cfg['docdir'],
                                      'botan-%d.%d.%d' % (ver_major, ver_minor, ver_patch))

        shutil.rmtree(prepend_destdir(target_doc_dir), True)
        shutil.copytree(cfg['doc_output_dir'], prepend_destdir(target_doc_dir))

        copy_file(os.path.join(cfg['base_dir'], 'license.txt'),
                  prepend_destdir(os.path.join(target_doc_dir, 'license.txt')))
        copy_file(os.path.join(cfg['base_dir'], 'news.rst'),
                  prepend_destdir(os.path.join(target_doc_dir, 'news.txt')))
        for f in [f for f in os.listdir(cfg['doc_dir']) if f.endswith('.txt')]:
            copy_file(os.path.join(cfg['doc_dir'], f), prepend_destdir(os.path.join(target_doc_dir, f)))

        if cfg['with_rst2man']:
            man1_dir = prepend_destdir(os.path.join(prefix, os.path.join(cfg['mandir'], 'man1')))
            makedirs(man1_dir)

            copy_file(os.path.join(cfg['build_dir'], 'botan.1'),
                      os.path.join(man1_dir, 'botan.1'))

    logging.info('Botan %s installation to %s complete', cfg['version'], cfg['prefix'])
    return 0

if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv))
    except Exception as e:
        logging.error('Failure: %s', str(e))
        logging.info(traceback.format_exc())
        sys.exit(1)
