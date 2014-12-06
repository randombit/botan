#!/usr/bin/python

import errno
import logging
import optparse
import os
import shutil
import string
import sys

import combine_relnotes

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
    install_group.add_option('--destdir', default='/tmp/local',
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

    install_group.add_option('--include-dir-suffix', metavar='SUFFIX', default='',
                             help='Set optional suffix on include dir')
    install_group.add_option('--doc-dir-suffix', metavar='SUFFIX', default='',
                             help='Set optional suffix on doc dir')

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

def license_text(rst_license):
    end_of_rst = 'terms::'
    contents = open(rst_license).read()
    x = contents.find(end_of_rst) + len(end_of_rst)

    lines = contents[x:].split('\n')

    while lines[0] == '':
        lines.pop(0)

    leading_ws = min([len(l) - len(l.lstrip(' ')) for l in lines if l != ''])

    return '\n'.join([l[leading_ws:] for l in lines])

def main(args = None):
    if args is None:
        args = sys.argv

    logging.basicConfig(stream = sys.stdout,
                        format = '%(levelname) 7s: %(message)s')

    (options, args) = parse_command_line(args)

    exe_mode = 0777

    if 'umask' in os.__dict__:
        umask = int(options.umask, 8)
        logging.debug('Setting umask to %s' % oct(umask))
        os.umask(int(options.umask, 8))
        exe_mode &= (umask ^ 0777)

    def copy_executable(src, dest):
        shutil.copyfile(src, dest)
        logging.debug('Copied %s to %s' % (src, dest))
        os.chmod(dest, exe_mode)

    build_vars = eval(open(os.path.join(options.build_dir, 'build_config.py')).read())

    def process_template(template_str):
        class PercentSignTemplate(string.Template):
            delimiter = '%'

        try:
            template = PercentSignTemplate(template_str)
            return template.substitute(build_vars)
        except KeyError as e:
            raise Exception('Unbound var %s in template' % (e))
        except Exception as e:
            raise Exception('Exception %s in template' % (e))

    bin_dir = os.path.join(options.destdir, options.bindir)
    lib_dir = os.path.join(options.destdir, options.libdir)
    doc_dir = os.path.join(options.destdir, options.docdir)
    include_dir = os.path.join(options.destdir, options.includedir)
    botan_doc_dir = os.path.join(doc_dir, 'botan' + options.doc_dir_suffix)
    botan_include_dir = os.path.join(include_dir, 'botan' + options.include_dir_suffix)

    out_dir = process_template('%{out_dir}')
    app_exe = process_template('botan%{program_suffix}')

    makedirs(options.destdir)
    makedirs(lib_dir)
    makedirs(bin_dir)
    makedirs(doc_dir)
    makedirs(include_dir)
    makedirs(botan_include_dir) # False

    build_include_dir = os.path.join(options.build_dir, 'include', 'botan')

    for include in os.listdir(build_include_dir):
        if include == 'internal':
            continue
        shutil.copyfile(os.path.join(build_include_dir, include),
                        os.path.join(botan_include_dir, include))

    static_lib = process_template('%{lib_prefix}%{libname}.%{static_suffix}')
    shutil.copyfile(static_lib, os.path.join(lib_dir, os.path.basename(static_lib)))

    if bool(build_vars['with_shared_lib']):
        shared_lib = process_template('%{lib_prefix}%{libname}.%{so_suffix}.%{so_abi_rev}.%{version_patch}')
        soname = process_template('%{lib_prefix}%{libname}.%{so_suffix}.%{so_abi_rev}')
        baselib = process_template('%{lib_prefix}%{libname}.%{so_suffix}')

        copy_executable(shared_lib, os.path.join(lib_dir, os.path.basename(shared_lib)))

        prev_cwd = os.getcwd()

        try:
            os.chdir(lib_dir)

            try:
                os.unlink(soname)
            except OSError as e:
                if e.errno != errno.ENOENT:
                    raise e

            try:
                os.unlink(baselib)
            except OSError as e:
                if e.errno != errno.ENOENT:
                    raise e

            os.symlink(shared_lib, soname)
            os.symlink(soname, baselib)
        finally:
            os.chdir(prev_cwd)

    copy_executable(os.path.join(out_dir, app_exe), os.path.join(bin_dir, app_exe))

    if 'botan_config' in build_vars:
        copy_executable(build_vars['botan_config'],
                        os.path.join(bin_dir, os.path.basename(build_vars['botan_config'])))

    if 'botan_pkgconfig' in build_vars:
        pkgconfig_dir = os.path.join(options.destdir, options.pkgconfigdir)
        makedirs(pkgconfig_dir)
        shutil.copyfile(build_vars['botan_pkgconfig'],
                        os.path.join(pkgconfig_dir, os.path.basename(build_vars['botan_pkgconfig'])))

    shutil.rmtree(botan_doc_dir, True)
    shutil.copytree(build_vars['doc_output_dir'], botan_doc_dir)

    with open(os.path.join(botan_doc_dir, 'license.txt'), 'w+') as lic:
        lic.write(license_text('doc/license.rst'))

    with open(os.path.join(botan_doc_dir, 'news.txt'), 'w+') as news:
        news.write(combine_relnotes.combine_relnotes('doc/relnotes'))

    logging.info('Botan %s installation complete', build_vars['version'])

if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as e:
        logging.error('Failure: %s' % (e))
        import traceback
        logging.debug(traceback.format_exc())
        sys.exit(1)
