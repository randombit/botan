#!/usr/bin/env python

"""
Configuration program for botan

(C) 2009,2010,2011,2012,2013,2014,2015,2016,2017 Jack Lloyd
(C) 2015,2016,2017 Simon Warta (Kullo GmbH)

Botan is released under the Simplified BSD License (see license.txt)

This script is regularly tested with CPython 2.7 and 3.5, and
occasionally tested with CPython 2.6 and PyPy 4.

Support for CPython 2.6 will be dropped eventually, but is kept up for as
long as reasonably convenient.

CPython 2.5 and earlier are not supported.

On Jython target detection does not work (use --os and --cpu).
"""

import collections
import copy
import json
import sys
import os
import os.path
import platform
import re
import shlex
import shutil
import string
import subprocess
import traceback
import logging
import time
import errno
import optparse # pylint: disable=deprecated-module

# Avoid useless botan_version.pyc (Python 2.6 or higher)
if 'dont_write_bytecode' in sys.__dict__:
    sys.dont_write_bytecode = True

import botan_version # pylint: disable=wrong-import-position


# An error caused by and to be fixed by the user, e.g. invalid command line argument
class UserError(Exception):
    pass


# An error caused by bugs in this script or when reading/parsing build data files
# Those are not expected to be fixed by the user of this script
class InternalError(Exception):
    pass


def flatten(l):
    return sum(l, [])


class Version(object):
    """
    Version information are all static members
    """
    major = botan_version.release_major
    minor = botan_version.release_minor
    patch = botan_version.release_patch
    so_rev = botan_version.release_so_abi_rev
    release_type = botan_version.release_type
    datestamp = botan_version.release_datestamp
    packed = major * 1000 + minor # Used on Darwin for dylib versioning
    _vc_rev = None

    @staticmethod
    def as_string():
        return '%d.%d.%d' % (Version.major, Version.minor, Version.patch)

    @staticmethod
    def vc_rev():
        # Lazy load to ensure _local_repo_vc_revision() does not run before logger is set up
        if Version._vc_rev is None:
            Version._vc_rev = botan_version.release_vc_rev
        if Version._vc_rev is None:
            Version._vc_rev = Version._local_repo_vc_revision()
        if Version._vc_rev is None:
            Version._vc_rev = 'unknown'
        return Version._vc_rev

    @staticmethod
    def _local_repo_vc_revision():
        vc_command = ['git', 'rev-parse', 'HEAD']
        cmdname = vc_command[0]

        try:
            vc = subprocess.Popen(
                vc_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True)
            (stdout, stderr) = vc.communicate()

            if vc.returncode != 0:
                logging.debug('Error getting rev from %s - %d (%s)'
                              % (cmdname, vc.returncode, stderr))
                return None

            rev = str(stdout).strip()
            logging.debug('%s reported revision %s' % (cmdname, rev))

            return '%s:%s' % (cmdname, rev)
        except OSError as e:
            logging.debug('Error getting rev from %s - %s' % (cmdname, e.strerror))
            return None


class SourcePaths(object):
    """
    A collection of paths defined by the project structure and
    independent of user configurations.
    All paths are relative to the base_dir, which may be relative as well (e.g. ".")
    """

    def __init__(self, base_dir):
        self.base_dir = base_dir
        self.doc_dir = os.path.join(self.base_dir, 'doc')
        self.src_dir = os.path.join(self.base_dir, 'src')

        # dirs in src/
        self.build_data_dir = os.path.join(self.src_dir, 'build-data')
        self.lib_dir = os.path.join(self.src_dir, 'lib')
        self.python_dir = os.path.join(self.src_dir, 'python')
        self.scripts_dir = os.path.join(self.src_dir, 'scripts')

        # dirs in src/build-data/
        self.sphinx_config_dir = os.path.join(self.build_data_dir, 'sphinx')
        self.makefile_dir = os.path.join(self.build_data_dir, 'makefile')


class BuildPaths(object): # pylint: disable=too-many-instance-attributes
    """
    Constructor
    """
    def __init__(self, source_paths, options, modules):
        self.build_dir = os.path.join(options.with_build_dir, 'build')

        self.libobj_dir = os.path.join(self.build_dir, 'obj', 'lib')
        self.cliobj_dir = os.path.join(self.build_dir, 'obj', 'cli')
        self.testobj_dir = os.path.join(self.build_dir, 'obj', 'test')

        self.doc_output_dir = os.path.join(self.build_dir, 'docs')
        self.doc_output_dir_manual = os.path.join(self.doc_output_dir, 'manual')
        self.doc_output_dir_doxygen = os.path.join(self.doc_output_dir, 'doxygen') if options.with_doxygen else None

        self.include_dir = os.path.join(self.build_dir, 'include')
        self.botan_include_dir = os.path.join(self.include_dir, 'botan')
        self.internal_include_dir = os.path.join(self.botan_include_dir, 'internal')
        self.external_include_dir = os.path.join(self.include_dir, 'external')

        self.internal_headers = sorted(flatten([m.internal_headers() for m in modules]))
        self.external_headers = sorted(flatten([m.external_headers() for m in modules]))

        if options.amalgamation:
            self.lib_sources = ['botan_all.cpp']
        else:
            self.lib_sources = sorted(flatten([mod.sources() for mod in modules]))

        self.public_headers = sorted(flatten([m.public_headers() for m in modules]))

        def find_sources_in(basedir, srcdir):
            for (dirpath, _, filenames) in os.walk(os.path.join(basedir, srcdir)):
                for filename in filenames:
                    if filename.endswith('.cpp') and not filename.startswith('.'):
                        yield os.path.join(dirpath, filename)

        def find_headers_in(basedir, srcdir):
            for (dirpath, _, filenames) in os.walk(os.path.join(basedir, srcdir)):
                for filename in filenames:
                    if filename.endswith('.h') and not filename.startswith('.'):
                        yield os.path.join(dirpath, filename)

        self.cli_sources = list(find_sources_in(source_paths.src_dir, 'cli'))
        self.cli_headers = list(find_headers_in(source_paths.src_dir, 'cli'))
        self.test_sources = list(find_sources_in(source_paths.src_dir, 'tests'))

    def build_dirs(self):
        out = [
            self.libobj_dir,
            self.cliobj_dir,
            self.testobj_dir,
            self.botan_include_dir,
            self.internal_include_dir,
            self.external_include_dir,
            self.doc_output_dir_manual,
        ]
        if self.doc_output_dir_doxygen:
            out += [self.doc_output_dir_doxygen]
        return out

    def src_info(self, typ):
        if typ == 'lib':
            return (self.lib_sources, self.libobj_dir)
        elif typ == 'cli':
            return (self.cli_sources, self.cliobj_dir)
        elif typ == 'test':
            return (self.test_sources, self.testobj_dir)


PKG_CONFIG_FILENAME = 'botan-%d.pc' % (Version.major)


def make_build_doc_commands(source_paths, build_paths, options):
    def build_manual_command(src_dir, dst_dir):
        if options.with_sphinx:
            sphinx = 'sphinx-build -c $(SPHINX_CONFIG) $(SPHINX_OPTS) '
            if options.quiet:
                sphinx += '-q '
            sphinx += '%s %s' % (src_dir, dst_dir)
            return sphinx
        else:
            return '$(COPY) %s%s*.rst %s' %  (src_dir, os.sep, dst_dir)

    cmds = [
        build_manual_command(os.path.join(source_paths.doc_dir, 'manual'), build_paths.doc_output_dir_manual)
    ]
    if options.with_doxygen:
        cmds += ['doxygen %s%sbotan.doxy' % (build_paths.build_dir, os.sep)]
    return '\n'.join(['\t' + cmd for cmd in cmds])


def process_command_line(args): # pylint: disable=too-many-locals
    """
    Handle command line options
    Do not use logging in this method as command line options need to be
    available before logging is setup.
    """

    parser = optparse.OptionParser(
        formatter=optparse.IndentedHelpFormatter(max_help_position=50),
        version=Version.as_string())

    parser.add_option('--verbose', action='store_true', default=False,
                      help='Show debug messages')
    parser.add_option('--quiet', action='store_true', default=False,
                      help='Show only warnings and errors')

    target_group = optparse.OptionGroup(parser, 'Target options')

    target_group.add_option('--cpu',
                            help='set the target CPU type/model')

    target_group.add_option('--os',
                            help='set the target operating system')

    target_group.add_option('--cc', dest='compiler',
                            help='set the desired build compiler')

    target_group.add_option('--cc-bin', dest='compiler_binary',
                            metavar='BINARY',
                            help='set path to compiler binary')

    target_group.add_option('--cc-abi-flags', metavar='FLAG',
                            help='set compiler ABI flags',
                            default='')

    target_group.add_option('--with-endian', metavar='ORDER', default=None,
                            help='override byte order guess')

    target_group.add_option('--with-unaligned-mem',
                            dest='unaligned_mem', action='store_true',
                            default=None,
                            help='use unaligned memory accesses')

    target_group.add_option('--without-unaligned-mem',
                            dest='unaligned_mem', action='store_false',
                            help=optparse.SUPPRESS_HELP)

    target_group.add_option('--with-os-features', action='append', metavar='FEAT',
                            help='specify OS features to use')
    target_group.add_option('--without-os-features', action='append', metavar='FEAT',
                            help='specify OS features to disable')

    for isa_extn_name in ['SSE2', 'SSSE3', 'AVX2', 'AES-NI', 'AltiVec', 'NEON']:
        isa_extn = isa_extn_name.lower()

        target_group.add_option('--disable-%s' % (isa_extn),
                                help='disable %s intrinsics' % (isa_extn_name),
                                action='append_const',
                                const=isa_extn.replace('-', ''),
                                dest='disable_intrinsics')

    build_group = optparse.OptionGroup(parser, 'Build options')

    build_group.add_option('--with-debug-info', action='store_true', default=False, dest='with_debug_info',
                           help='include debug symbols')

    build_group.add_option('--with-sanitizers', action='store_true', default=False, dest='with_sanitizers',
                           help='enable ASan/UBSan checks')

    build_group.add_option('--without-stack-protector', action='store_false', default=True, dest='with_stack_protector',
                           help='disable stack smashing protections')

    build_group.add_option('--with-coverage', action='store_true', default=False, dest='with_coverage',
                           help='add coverage info and disable opts')

    build_group.add_option('--with-coverage-info', action='store_true', default=False, dest='with_coverage_info',
                           help='add coverage info')

    build_group.add_option('--enable-shared-library', dest='build_shared_lib',
                           action='store_true', default=True,
                           help=optparse.SUPPRESS_HELP)
    build_group.add_option('--disable-shared', dest='build_shared_lib',
                           action='store_false',
                           help='disable building shared library')

    build_group.add_option('--optimize-for-size', dest='optimize_for_size',
                           action='store_true', default=False,
                           help='optimize for code size')

    build_group.add_option('--no-optimizations', dest='no_optimizations',
                           action='store_true', default=False,
                           help='disable all optimizations (for debugging)')

    build_group.add_option('--debug-mode', action='store_true', default=False, dest='debug_mode',
                           help='enable debug info and disable optimizations')

    build_group.add_option('--gen-amalgamation', dest='gen_amalgamation',
                           default=False, action='store_true',
                           help='generate amalgamation files and build without amalgamation (removed)')

    build_group.add_option('--via-amalgamation', dest='via_amalgamation',
                           default=False, action='store_true',
                           help='build via amalgamation (deprecated, use --amalgamation)')

    build_group.add_option('--amalgamation', dest='amalgamation',
                           default=False, action='store_true',
                           help='generate amalgamation files and build via amalgamation')

    build_group.add_option('--single-amalgamation-file',
                           default=False, action='store_true',
                           help='build single file instead of splitting on ABI')

    build_group.add_option('--with-build-dir', metavar='DIR', default='',
                           help='setup the build in DIR')

    build_group.add_option('--with-external-includedir', metavar='DIR', default='',
                           help='use DIR for external includes')

    build_group.add_option('--with-external-libdir', metavar='DIR', default='',
                           help='use DIR for external libs')

    build_group.add_option('--with-openmp', default=False, action='store_true',
                           help='enable use of OpenMP')
    build_group.add_option('--with-cilkplus', default=False, action='store_true',
                           help='enable use of Cilk Plus')

    link_methods = ['symlink', 'hardlink', 'copy']
    build_group.add_option('--link-method', default=None, metavar='METHOD',
                           choices=link_methods,
                           help='choose how links to include headers are created (%s)' % ', '.join(link_methods))

    makefile_styles = ['gmake', 'nmake']
    build_group.add_option('--makefile-style', metavar='STYLE', default=None,
                           choices=makefile_styles,
                           help='makefile type (%s)' % ' or '.join(makefile_styles))

    build_group.add_option('--with-local-config',
                           dest='local_config', metavar='FILE',
                           help='include the contents of FILE into build.h')

    build_group.add_option('--distribution-info', metavar='STRING',
                           help='distribution specific version',
                           default='unspecified')

    build_group.add_option('--with-sphinx', action='store_true',
                           default=None, help='Use Sphinx')

    build_group.add_option('--without-sphinx', action='store_false',
                           dest='with_sphinx', help=optparse.SUPPRESS_HELP)

    build_group.add_option('--with-doxygen', action='store_true',
                           default=False, help='Use Doxygen')

    build_group.add_option('--without-doxygen', action='store_false',
                           dest='with_doxygen', help=optparse.SUPPRESS_HELP)

    build_group.add_option('--maintainer-mode', dest='maintainer_mode',
                           action='store_true', default=False,
                           help="Enable extra warnings")

    build_group.add_option('--dirty-tree', dest='clean_build_tree',
                           action='store_false', default=True,
                           help=optparse.SUPPRESS_HELP)

    build_group.add_option('--with-python-versions', dest='python_version',
                           metavar='N.M',
                           default='%d.%d' % (sys.version_info[0], sys.version_info[1]),
                           help='where to install botan2.py (def %default)')

    build_group.add_option('--with-valgrind', help='use valgrind API',
                           dest='with_valgrind', action='store_true', default=False)

    build_group.add_option('--with-bakefile', action='store_true',
                           default=False,
                           help='Generate bakefile which can be used to create Visual Studio or Xcode project files')

    build_group.add_option('--with-cmake', action='store_true',
                           default=False,
                           help='Generate CMakeLists.txt which can be used to create many IDEs project files')

    build_group.add_option('--unsafe-fuzzer-mode', action='store_true', default=False,
                           help='disable essential checks for testing')

    mods_group = optparse.OptionGroup(parser, 'Module selection')

    mods_group.add_option('--module-policy', dest='module_policy',
                          help="module policy file (see src/build-data/policy)",
                          metavar='POL', default=None)

    mods_group.add_option('--enable-modules', dest='enabled_modules',
                          metavar='MODS', action='append',
                          help='enable specific modules')
    mods_group.add_option('--disable-modules', dest='disabled_modules',
                          metavar='MODS', action='append',
                          help='disable specific modules')
    mods_group.add_option('--list-modules', dest='list_modules',
                          action='store_true',
                          help='list available modules and exit')
    mods_group.add_option('--no-autoload', action='store_true', default=False,
                          help=optparse.SUPPRESS_HELP)
    mods_group.add_option('--minimized-build', action='store_true', dest='no_autoload',
                          help='minimize build')

    # Should be derived from info.txt but this runs too early
    third_party = ['boost', 'bzip2', 'lzma', 'openssl', 'sqlite3', 'zlib', 'tpm']

    for mod in third_party:
        mods_group.add_option('--with-%s' % (mod),
                              help=('use %s' % (mod)) if mod in third_party else optparse.SUPPRESS_HELP,
                              action='append_const',
                              const=mod,
                              dest='enabled_modules')

        mods_group.add_option('--without-%s' % (mod),
                              help=optparse.SUPPRESS_HELP,
                              action='append_const',
                              const=mod,
                              dest='disabled_modules')

    mods_group.add_option('--with-everything', help=optparse.SUPPRESS_HELP,
                          action='store_true', default=False)

    install_group = optparse.OptionGroup(parser, 'Installation options')

    install_group.add_option('--program-suffix', metavar='SUFFIX',
                             help='append string to program names')

    install_group.add_option('--prefix', metavar='DIR',
                             help='set the install prefix')
    install_group.add_option('--destdir', metavar='DIR',
                             help='set the install directory')
    install_group.add_option('--docdir', metavar='DIR',
                             help='set the doc install dir')
    install_group.add_option('--bindir', metavar='DIR',
                             help='set the binary install dir')
    install_group.add_option('--libdir', metavar='DIR',
                             help='set the library install dir')
    install_group.add_option('--includedir', metavar='DIR',
                             help='set the include file install dir')

    misc_group = optparse.OptionGroup(parser, 'Miscellaneous options')

    misc_group.add_option('--house-curve', metavar='STRING', dest='house_curve',
                          help='a custom in-house curve of the format: curve.pem,NAME,OID,CURVEID')

    parser.add_option_group(target_group)
    parser.add_option_group(build_group)
    parser.add_option_group(mods_group)
    parser.add_option_group(install_group)
    parser.add_option_group(misc_group)

    # These exist only for autoconf compatibility (requested by zw for mtn)
    compat_with_autoconf_options = [
        'datadir',
        'datarootdir',
        'dvidir',
        'exec-prefix',
        'htmldir',
        'infodir',
        'libexecdir',
        'localedir',
        'localstatedir',
        'mandir',
        'oldincludedir',
        'pdfdir',
        'psdir',
        'sbindir',
        'sharedstatedir',
        'sysconfdir'
        ]

    for opt in compat_with_autoconf_options:
        parser.add_option('--' + opt, help=optparse.SUPPRESS_HELP)

    (options, args) = parser.parse_args(args)

    if args != []:
        raise UserError('Unhandled option(s): ' + ' '.join(args))
    if options.with_endian != None and \
       options.with_endian not in ['little', 'big']:
        raise UserError('Bad value to --with-endian "%s"' % (
            options.with_endian))

    if options.debug_mode:
        options.no_optimizations = True
        options.with_debug_info = True

    if options.with_coverage:
        options.with_coverage_info = True
        options.no_optimizations = True

    def parse_multiple_enable(modules):
        if modules is None:
            return []
        return sorted(set(flatten([s.split(',') for s in modules])))

    options.enabled_modules = parse_multiple_enable(options.enabled_modules)
    options.disabled_modules = parse_multiple_enable(options.disabled_modules)

    options.with_os_features = parse_multiple_enable(options.with_os_features)
    options.without_os_features = parse_multiple_enable(options.without_os_features)

    options.disable_intrinsics = parse_multiple_enable(options.disable_intrinsics)

    return options


class LexResult(object):
    pass


class LexerError(InternalError):
    def __init__(self, msg, lexfile, line):
        super(LexerError, self).__init__(msg)
        self.msg = msg
        self.lexfile = lexfile
        self.line = line

    def __str__(self):
        return '%s at %s:%d' % (self.msg, self.lexfile, self.line)


def parse_lex_dict(as_list):
    if len(as_list) % 3 != 0:
        raise InternalError(
            "Lex dictionary has invalid format (input not divisible by 3): %s" % as_list)

    result = {}
    for key, sep, value in [as_list[3*i:3*i+3] for i in range(0, len(as_list)//3)]:
        if sep != '->':
            raise InternalError("Lex dictionary has invalid format")
        result[key] = value
    return result


def lex_me_harder(infofile, allowed_groups, name_val_pairs):
    """
    Generic lexer function for info.txt and src/build-data files
    """
    out = LexResult()

    # Format as a nameable Python variable
    def py_var(group):
        return group.replace(':', '_')

    lexer = shlex.shlex(open(infofile), infofile, posix=True)
    lexer.wordchars += '|:.<>/,-!+' # handle various funky chars in info.txt

    for group in allowed_groups:
        out.__dict__[py_var(group)] = []
    for (key, val) in name_val_pairs.items():
        out.__dict__[key] = val

    def lexed_tokens(): # Convert to an interator
        while True:
            token = lexer.get_token()
            if token != lexer.eof:
                yield token
            else:
                return

    for token in lexed_tokens():
        match = re.match('<(.*)>', token)

        # Check for a grouping
        if match is not None:
            group = match.group(1)

            if group not in allowed_groups:
                raise LexerError('Unknown group "%s"' % (group),
                                 infofile, lexer.lineno)

            end_marker = '</' + group + '>'

            token = lexer.get_token()
            while token != end_marker:
                out.__dict__[py_var(group)].append(token)
                token = lexer.get_token()
                if token is None:
                    raise LexerError('Group "%s" not terminated' % (group),
                                     infofile, lexer.lineno)

        elif token in name_val_pairs.keys():
            if isinstance(out.__dict__[token], list):
                out.__dict__[token].append(lexer.get_token())
            else:
                out.__dict__[token] = lexer.get_token()

        else: # No match -> error
            raise LexerError('Bad token "%s"' % (token), infofile, lexer.lineno)

    return out


def force_to_dict(l):
    """
    Convert a lex'ed map (from build-data files) from a list to a dict
    TODO: Add error checking of input...
    """

    return dict(zip(l[::3], l[2::3]))


class InfoObject(object):
    def __init__(self, infofile):
        """
        Constructor sets members `infofile`, `lives_in`, `parent_module` and `basename`
        """

        self.infofile = infofile
        (dirname, basename) = os.path.split(infofile)
        self.lives_in = dirname
        if basename == 'info.txt':
            (obj_dir, self.basename) = os.path.split(dirname)
            if os.access(os.path.join(obj_dir, 'info.txt'), os.R_OK):
                self.parent_module = os.path.basename(obj_dir)
            else:
                self.parent_module = None
        else:
            self.basename = basename.replace('.txt', '')


class ModuleInfo(InfoObject):
    """
    Represents the information about a particular module
    """

    def __init__(self, infofile):
        super(ModuleInfo, self).__init__(infofile)
        lex = lex_me_harder(
            infofile,
            [
                'defines', 'header:internal', 'header:public', 'header:external', 'requires',
                'os', 'arch', 'cc', 'libs', 'frameworks', 'comment', 'warning'
            ],
            {
                'load_on': 'auto',
                'need_isa': ''
            })

        def check_header_duplicates(header_list_public, header_list_internal):
            pub_header = set(header_list_public)
            int_header = set(header_list_internal)
            if not pub_header.isdisjoint(int_header):
                logging.error("Module %s header contains same header in public and internal sections" % self.infofile)

        check_header_duplicates(lex.header_public, lex.header_internal)

        all_source_files = []
        all_header_files = []

        for fspath in os.listdir(self.lives_in):
            if fspath.endswith('.cpp'):
                all_source_files.append(fspath)
            elif fspath.endswith('.h'):
                all_header_files.append(fspath)

        self.source = all_source_files

        # If not entry for the headers, all are assumed public
        if lex.header_internal == [] and lex.header_public == []:
            self.header_public = list(all_header_files)
            self.header_internal = []
        else:
            self.header_public = lex.header_public
            self.header_internal = lex.header_internal
        self.header_external = lex.header_external

        # Coerce to more useful types
        def convert_lib_list(l):
            if len(l) % 3 != 0:
                raise InternalError("Bad <libs> in module %s" % (self.basename))
            result = {}

            for sep in l[1::3]:
                if sep != '->':
                    raise InternalError("Bad <libs> in module %s" % (self.basename))

            for (targetlist, vallist) in zip(l[::3], l[2::3]):
                vals = vallist.split(',')
                for target in targetlist.split(','):
                    result[target] = result.setdefault(target, []) + vals
            return result

        # Convert remaining lex result to members
        self.arch = lex.arch
        self.cc = lex.cc
        self.comment = ' '.join(lex.comment) if lex.comment else None
        self._defines = parse_lex_dict(lex.defines)
        self._validate_defines_content(self._defines)
        self.frameworks = convert_lib_list(lex.frameworks)
        self.libs = convert_lib_list(lex.libs)
        self.load_on = lex.load_on
        self.need_isa = lex.need_isa.split(',') if lex.need_isa else []
        self.os = lex.os
        self.requires = lex.requires
        self.warning = ' '.join(lex.warning) if lex.warning else None

        def add_dir_name(filename):
            if filename.count(':') == 0:
                return os.path.join(self.lives_in, filename)

            # modules can request to add files of the form
            # MODULE_NAME:FILE_NAME to add a file from another module
            # For these, assume other module is always in a
            # neighboring directory; this is true for all current uses
            return os.path.join(os.path.split(self.lives_in)[0],
                                *filename.split(':'))

        # Modify members
        self.source = [add_dir_name(s) for s in self.source]
        self.header_internal = [add_dir_name(s) for s in self.header_internal]
        self.header_public = [add_dir_name(s) for s in self.header_public]
        self.header_external = [add_dir_name(s) for s in self.header_external]

        # Filesystem read access check
        for src in self.source + self.header_internal + self.header_public + self.header_external:
            if not os.access(src, os.R_OK):
                logging.error("Missing file %s in %s" % (src, infofile))

        # Check for duplicates
        def intersect_check(type_a, list_a, type_b, list_b):
            intersection = set.intersection(set(list_a), set(list_b))
            if intersection:
                logging.error('Headers %s marked both %s and %s' % (' '.join(intersection), type_a, type_b))

        intersect_check('public', self.header_public, 'internal', self.header_internal)
        intersect_check('public', self.header_public, 'external', self.header_external)
        intersect_check('external', self.header_external, 'internal', self.header_internal)

    @staticmethod
    def _validate_defines_content(defines):
        for key, value in defines.items():
            if not re.match('^[0-9A-Za-z_]{3,30}$', key):
                raise InternalError('Module defines key has invalid format: "%s"' % key)
            if not re.match('^[0-9]{8}$', value):
                raise InternalError('Module defines value has invalid format: "%s"' % value)

    def cross_check(self, arch_info, os_info, cc_info):
        for supp_os in self.os:
            if supp_os not in os_info:
                raise InternalError('Module %s mentions unknown OS %s' % (self.infofile, supp_os))
        for supp_cc in self.cc:
            if supp_cc not in cc_info:
                colon_idx = supp_cc.find(':')
                # a versioned compiler dependency
                if colon_idx > 0 and supp_cc[0:colon_idx] in cc_info:
                    pass
                else:
                    raise InternalError('Module %s mentions unknown compiler %s' % (self.infofile, supp_cc))
        for supp_arch in self.arch:
            if supp_arch not in arch_info:
                raise InternalError('Module %s mentions unknown arch %s' % (self.infofile, supp_arch))

    def sources(self):
        return self.source

    def public_headers(self):
        return self.header_public

    def internal_headers(self):
        return self.header_internal

    def external_headers(self):
        return self.header_external

    def defines(self):
        return ['HAS_%s %s' % (key, value) for key, value in self._defines.items()]

    def compatible_cpu(self, archinfo, options):
        arch_name = archinfo.basename
        cpu_name = options.cpu

        for isa in self.need_isa:
            if isa in options.disable_intrinsics:
                return False # explicitly disabled

            if isa not in archinfo.isa_extensions:
                return False

        if self.arch != []:
            if arch_name not in self.arch and cpu_name not in self.arch:
                return False

        return True

    def compatible_os(self, os_name):
        return self.os == [] or os_name in self.os

    def compatible_compiler(self, ccinfo, cc_version, arch):
        # Check if this compiler supports the flags we need
        def supported_isa_flags(ccinfo, arch):
            for isa in self.need_isa:
                if ccinfo.isa_flags_for(isa, arch) is None:
                    return False
            return True

        # Check if module gives explicit compiler dependencies
        def supported_compiler(ccinfo, cc_version):

            if self.cc == [] or ccinfo.basename in self.cc:
                return True

            # Maybe a versioned compiler dep
            if cc_version != None:
                for cc in self.cc:
                    with_version = cc.find(':')
                    if with_version > 0:
                        if cc[0:with_version] == ccinfo.basename:
                            min_cc_version = [int(v) for v in cc[with_version+1:].split('.')]
                            cur_cc_version = [int(v) for v in cc_version.split('.')]
                            # With lists of ints, this does what we want
                            return cur_cc_version >= min_cc_version

        return supported_isa_flags(ccinfo, arch) and supported_compiler(ccinfo, cc_version)

    def dependencies(self):
        # base is an implicit dep for all submodules
        deps = self.requires + ['base']
        if self.parent_module != None:
            deps.append(self.parent_module)
        return deps

    def dependencies_exist(self, modules):
        """
        Ensure that all dependencies of this module actually exist, warning
        about any that do not
        """

        all_deps = [s.split('|') for s in self.dependencies()]

        for missing in [s for s in flatten(all_deps) if s not in modules]:
            logging.error("Module '%s', dep of '%s', does not exist" % (
                missing, self.basename))


class ModulePolicyInfo(InfoObject):
    def __init__(self, infofile):
        super(ModulePolicyInfo, self).__init__(infofile)
        lex = lex_me_harder(
            infofile,
            ['required', 'if_available', 'prohibited'],
            {})

        self.if_available = lex.if_available
        self.required = lex.required
        self.prohibited = lex.prohibited

    def cross_check(self, modules):
        def check(tp, lst):
            for mod in lst:
                if mod not in modules:
                    logging.error("Module policy %s includes non-existent module %s in <%s>" % (
                        self.infofile, mod, tp))

        check('required', self.required)
        check('if_available', self.if_available)
        check('prohibited', self.prohibited)


class ArchInfo(InfoObject):
    def __init__(self, infofile):
        super(ArchInfo, self).__init__(infofile)
        lex = lex_me_harder(
            infofile,
            ['aliases', 'submodels', 'submodel_aliases', 'isa_extensions'],
            {
                'endian': None,
                'family': None,
                'unaligned': 'no',
                'wordsize': 32
            })

        self.aliases = lex.aliases
        self.endian = lex.endian
        self.family = lex.family
        self.isa_extensions = lex.isa_extensions
        self.unaligned_ok = (1 if lex.unaligned == 'ok' else 0)
        self.submodels = lex.submodels
        self.submodel_aliases = force_to_dict(lex.submodel_aliases)
        self.wordsize = int(lex.wordsize)

    def all_submodels(self):
        """
        Return a list of all submodels for this arch, ordered longest
        to shortest
        """

        return sorted([(k, k) for k in self.submodels] +
                      [k for k in self.submodel_aliases.items()],
                      key=lambda k: len(k[0]), reverse=True)

    def defines(self, cc, options):
        """
        Return CPU-specific defines for build.h
        """

        def form_macro(cpu_name):
            return cpu_name.upper().replace('.', '').replace('-', '_')

        macros = []

        macros.append('TARGET_ARCH_IS_%s' % (form_macro(self.basename.upper())))

        if self.basename != options.cpu:
            macros.append('TARGET_CPU_IS_%s' % (form_macro(options.cpu)))

        enabled_isas = set(self.isa_extensions)
        disabled_isas = set(options.disable_intrinsics)

        isa_extensions = sorted(enabled_isas - disabled_isas)

        for isa in isa_extensions:
            if cc.isa_flags_for(isa, self.basename) is not None:
                macros.append('TARGET_SUPPORTS_%s' % (form_macro(isa)))
            else:
                logging.warning("Disabling support for %s intrinsics due to missing flag for compiler" % (isa))

        endian = options.with_endian or self.endian

        if endian != None:
            macros.append('TARGET_CPU_IS_%s_ENDIAN' % (endian.upper()))
            logging.info('Assuming CPU is %s endian' % (endian))

        unaligned_ok = options.unaligned_mem
        if unaligned_ok is None:
            unaligned_ok = self.unaligned_ok
            if unaligned_ok:
                logging.info('Assuming unaligned memory access works')

        if self.family is not None:
            macros.append('TARGET_CPU_IS_%s_FAMILY' % (self.family.upper()))

        macros.append('TARGET_CPU_NATIVE_WORD_SIZE %d' % (self.wordsize))

        if self.wordsize == 64:
            macros.append('TARGET_CPU_HAS_NATIVE_64BIT')

        macros.append('TARGET_UNALIGNED_MEMORY_ACCESS_OK %d' % (unaligned_ok))

        if options.with_valgrind:
            macros.append('HAS_VALGRIND')

        if options.with_openmp:
            macros.append('TARGET_HAS_OPENMP')
        if options.with_cilkplus:
            macros.append('TARGET_HAS_CILKPLUS')

        return macros


MachOptFlags = collections.namedtuple('MachOptFlags', ['flags', 'submodel_prefix'])


class CompilerInfo(InfoObject): # pylint: disable=too-many-instance-attributes
    def __init__(self, infofile):
        super(CompilerInfo, self).__init__(infofile)
        lex = lex_me_harder(
            infofile,
            ['so_link_commands', 'binary_link_commands', 'mach_opt', 'mach_abi_linking', 'isa_flags'],
            {
                'binary_name': None,
                'linker_name': None,
                'macro_name': None,
                'output_to_option': '-o ',
                'add_include_dir_option': '-I',
                'add_lib_dir_option': '-L',
                'add_lib_option': '-l',
                'add_framework_option': '-framework ',
                'compile_flags': '',
                'debug_info_flags': '',
                'optimization_flags': '',
                'size_optimization_flags': '',
                'coverage_flags': '',
                'sanitizer_flags': '',
                'stack_protector_flags': '',
                'shared_flags': '',
                'lang_flags': '',
                'warning_flags': '',
                'maintainer_warning_flags': '',
                'visibility_build_flags': '',
                'visibility_attribute': '',
                'ar_command': None,
                'makefile_style': ''
            })

        self.add_framework_option = lex.add_framework_option
        self.add_include_dir_option = lex.add_include_dir_option
        self.add_lib_option = lex.add_lib_option
        self.add_lib_dir_option = lex.add_lib_dir_option
        self.ar_command = lex.ar_command
        self.binary_link_commands = force_to_dict(lex.binary_link_commands)
        self.binary_name = lex.binary_name
        self.compile_flags = lex.compile_flags
        self.coverage_flags = lex.coverage_flags
        self.debug_info_flags = lex.debug_info_flags
        self.isa_flags = force_to_dict(lex.isa_flags)
        self.lang_flags = lex.lang_flags
        self.linker_name = lex.linker_name
        self.mach_abi_linking = force_to_dict(lex.mach_abi_linking)
        self.macro_name = lex.macro_name
        self.maintainer_warning_flags = lex.maintainer_warning_flags
        self.makefile_style = lex.makefile_style
        self.optimization_flags = lex.optimization_flags
        self.output_to_option = lex.output_to_option
        self.sanitizer_flags = lex.sanitizer_flags
        self.shared_flags = lex.shared_flags
        self.size_optimization_flags = lex.size_optimization_flags
        self.so_link_commands = force_to_dict(lex.so_link_commands)
        self.stack_protector_flags = lex.stack_protector_flags
        self.visibility_build_flags = lex.visibility_build_flags
        self.visibility_attribute = lex.visibility_attribute
        self.warning_flags = lex.warning_flags

        self.mach_opt_flags = {}
        for key, value in parse_lex_dict(lex.mach_opt).items():
            parts = value.split("|")
            self.mach_opt_flags[key] = MachOptFlags(parts[0], parts[1] if len(parts) == 2 else '')

    def isa_flags_for(self, isa, arch):
        if isa in self.isa_flags:
            return self.isa_flags[isa]
        arch_isa = '%s:%s' % (arch, isa)
        if arch_isa in self.isa_flags:
            return self.isa_flags[arch_isa]
        return None

    def gen_shared_flags(self, options):
        """
        Return the shared library build flags, if any
        """

        def flag_builder():
            if options.build_shared_lib:
                yield self.shared_flags
                yield self.visibility_build_flags

        return ' '.join(list(flag_builder()))

    def gen_visibility_attribute(self, options):
        if options.build_shared_lib:
            return self.visibility_attribute
        return ''

    def mach_abi_link_flags(self, options):
        """
        Return the machine specific ABI flags
        """

        def all_group():
            if options.with_debug_info and 'all-debug' in self.mach_abi_linking:
                return 'all-debug'
            return 'all'

        abi_link = list()
        for what in [all_group(), options.os, options.arch, options.cpu]:
            flag = self.mach_abi_linking.get(what)
            if flag != None and flag != '' and flag not in abi_link:
                abi_link.append(flag)

        if options.with_stack_protector and self.stack_protector_flags != '':
            abi_link.append(self.stack_protector_flags)

        if options.with_coverage_info:
            if self.coverage_flags == '':
                raise InternalError('No coverage handling for %s' % (self.basename))
            abi_link.append(self.coverage_flags)

        if options.with_sanitizers:
            if self.sanitizer_flags == '':
                raise InternalError('No sanitizer handling for %s' % (self.basename))
            abi_link.append(self.sanitizer_flags)

        if options.with_openmp:
            if 'openmp' not in self.mach_abi_linking:
                raise InternalError('No support for OpenMP for %s' % (self.basename))
            abi_link.append(self.mach_abi_linking['openmp'])

        if options.with_cilkplus:
            if 'cilkplus' not in self.mach_abi_linking:
                raise InternalError('No support for Cilk Plus for %s' % (self.basename))
            abi_link.append(self.mach_abi_linking['cilkplus'])

        abi_flags = ' '.join(sorted(abi_link))

        if options.cc_abi_flags != '':
            abi_flags += ' ' + options.cc_abi_flags

        return abi_flags

    def cc_warning_flags(self, options):
        def gen_flags():
            yield self.warning_flags
            if options.maintainer_mode:
                yield self.maintainer_warning_flags

        return (' '.join(gen_flags())).strip()

    def cc_compile_flags(self, options):
        def gen_flags():
            yield self.lang_flags

            if options.with_debug_info:
                yield self.debug_info_flags

            if not options.no_optimizations:
                if options.optimize_for_size:
                    if self.size_optimization_flags != '':
                        yield self.size_optimization_flags
                    else:
                        logging.warning("No size optimization flags set for current compiler")
                        yield self.optimization_flags
                else:
                    yield self.optimization_flags

            def submodel_fixup(full_cpu, mach_opt_flags_tupel):
                submodel_replacement = full_cpu.replace(mach_opt_flags_tupel.submodel_prefix, '')
                return mach_opt_flags_tupel.flags.replace('SUBMODEL', submodel_replacement)

            if options.cpu != options.arch:
                if options.cpu in self.mach_opt_flags:
                    yield submodel_fixup(options.cpu, self.mach_opt_flags[options.cpu])
                elif options.arch in self.mach_opt_flags:
                    yield submodel_fixup(options.cpu, self.mach_opt_flags[options.arch])

            all_arch = 'all_%s' % (options.arch)

            if all_arch in self.mach_opt_flags:
                yield self.mach_opt_flags[all_arch][0]

        return (' '.join(gen_flags())).strip()

    @staticmethod
    def _so_link_search(osname, debug_info):
        if debug_info:
            return [osname + '-debug', 'default-debug']
        else:
            return [osname, 'default']

    def so_link_command_for(self, osname, options):
        """
        Return the command needed to link a shared object
        """

        for s in self._so_link_search(osname, options.with_debug_info):
            if s in self.so_link_commands:
                return self.so_link_commands[s]

        raise InternalError(
            "No shared library link command found for target '%s' in compiler settings '%s'" %
            (osname, self.infofile))

    def binary_link_command_for(self, osname, options):
        """
        Return the command needed to link an app/test object
        """

        for s in self._so_link_search(osname, options.with_debug_info):
            if s in self.binary_link_commands:
                return self.binary_link_commands[s]

        return '$(LINKER)'

    def defines(self):
        """
        Return defines for build.h
        """

        return ['BUILD_COMPILER_IS_' + self.macro_name]


class OsInfo(InfoObject): # pylint: disable=too-many-instance-attributes
    def __init__(self, infofile):
        super(OsInfo, self).__init__(infofile)
        lex = lex_me_harder(
            infofile,
            ['aliases', 'target_features'],
            {
                'os_type': None,
                'program_suffix': '',
                'obj_suffix': 'o',
                'soname_suffix': '',
                'soname_pattern_patch': '',
                'soname_pattern_abi': '',
                'soname_pattern_base': '',
                'static_suffix': 'a',
                'ar_command': 'ar crs',
                'ar_needs_ranlib': False,
                'install_root': '/usr/local',
                'header_dir': 'include',
                'bin_dir': 'bin',
                'lib_dir': 'lib',
                'doc_dir': 'share/doc',
                'building_shared_supported': 'yes',
                'install_cmd_data': 'install -m 644',
                'install_cmd_exec': 'install -m 755'
            })

        if lex.soname_pattern_base:
            self.soname_pattern_base = lex.soname_pattern_base
            if lex.soname_pattern_patch == '' and lex.soname_pattern_abi == '':
                self.soname_pattern_patch = lex.soname_pattern_base
                self.soname_pattern_abi = lex.soname_pattern_base
            elif lex.soname_pattern_abi != '' and lex.soname_pattern_abi != '':
                self.soname_pattern_patch = lex.soname_pattern_patch
                self.soname_pattern_abi = lex.soname_pattern_abi
            else:
                # base set, only one of patch/abi set
                raise InternalError("Invalid soname_patterns in %s" % (self.infofile))
        else:
            if lex.soname_suffix:
                self.soname_pattern_base = "libbotan-{version_major}.%s" % (lex.soname_suffix)
                self.soname_pattern_abi = self.soname_pattern_base + ".{abi_rev}"
                self.soname_pattern_patch = self.soname_pattern_abi + ".{version_minor}.{version_patch}"
            else:
                # Could not calculate soname_pattern_*
                # This happens for OSs without shared library support (e.g. nacl, mingw, includeos, cygwin)
                self.soname_pattern_base = None
                self.soname_pattern_abi = None
                self.soname_pattern_patch = None

        self.aliases = lex.aliases
        self.ar_command = lex.ar_command
        self.ar_needs_ranlib = bool(lex.ar_needs_ranlib)
        self.bin_dir = lex.bin_dir
        self.building_shared_supported = (True if lex.building_shared_supported == 'yes' else False)
        self.doc_dir = lex.doc_dir
        self.header_dir = lex.header_dir
        self.install_cmd_data = lex.install_cmd_data
        self.install_cmd_exec = lex.install_cmd_exec
        self.install_root = lex.install_root
        self.lib_dir = lex.lib_dir
        self.os_type = lex.os_type
        self.obj_suffix = lex.obj_suffix
        self.program_suffix = lex.program_suffix
        self.static_suffix = lex.static_suffix
        self.target_features = lex.target_features

    def ranlib_command(self):
        return 'ranlib' if self.ar_needs_ranlib else 'true'

    def defines(self, options):
        r = []
        r += ['TARGET_OS_IS_%s' % (self.basename.upper())]

        if self.os_type != None:
            r += ['TARGET_OS_TYPE_IS_%s' % (self.os_type.upper())]

        def feat_macros():
            for feat in self.target_features:
                if feat not in options.without_os_features:
                    yield 'TARGET_OS_HAS_' + feat.upper()
            for feat in options.with_os_features:
                if feat not in self.target_features:
                    yield 'TARGET_OS_HAS_' + feat.upper()

        r += sorted(feat_macros())
        return r


def fixup_proc_name(proc):
    proc = proc.lower().replace(' ', '')
    for junk in ['(tm)', '(r)']:
        proc = proc.replace(junk, '')
    return proc

def canon_processor(archinfo, proc):
    proc = fixup_proc_name(proc)

    # First, try to search for an exact match
    for ainfo in archinfo.values():
        if ainfo.basename == proc or proc in ainfo.aliases:
            return (ainfo.basename, ainfo.basename)

        for (match, submodel) in ainfo.all_submodels():
            if proc == submodel or proc == match:
                return (ainfo.basename, submodel)

    logging.debug('Could not find an exact match for CPU "%s"' % (proc))

    # Now, try searching via regex match
    for ainfo in archinfo.values():
        for (match, submodel) in ainfo.all_submodels():
            if re.search(match, proc) != None:
                logging.debug('Possible match "%s" with "%s" (%s)' % (
                    proc, match, submodel))
                return (ainfo.basename, submodel)

    return None

def system_cpu_info():

    cpu_info = []

    if platform.machine() != '':
        cpu_info.append(platform.machine())

    if platform.processor() != '':
        cpu_info.append(platform.processor())

    try:
        with open('/proc/cpuinfo') as f:
            for line in f.readlines():
                colon = line.find(':')
                if colon > 1:
                    key = line[0:colon].strip()
                    val = ' '.join([s.strip() for s in line[colon+1:].split(' ') if s != ''])

                    # Different Linux arch use different names for this field in cpuinfo
                    if key in ["model name", "cpu model", "Processor"]:
                        logging.info('Detected CPU model "%s" in /proc/cpuinfo' % (val))
                        cpu_info.append(val)
                        break
    except IOError:
        pass

    return cpu_info

def guess_processor(archinfo):
    for info_part in system_cpu_info():
        if info_part:
            match = canon_processor(archinfo, info_part)
            if match != None:
                logging.debug("Matched '%s' to processor '%s'" % (info_part, match))
                return match
            else:
                logging.debug("Failed to deduce CPU from '%s'" % info_part)

    raise UserError('Could not determine target CPU; set with --cpu')


def read_textfile(filepath):
    """
    Read a whole file into memory as a string
    """
    if filepath is None:
        return ''

    with open(filepath) as f:
        return ''.join(f.readlines())


def process_template(template_file, variables):
    """
    Perform template substitution
    """

    class PercentSignTemplate(string.Template):
        delimiter = '%'

    try:
        template = PercentSignTemplate(read_textfile(template_file))
        return template.substitute(variables)
    except KeyError as e:
        raise InternalError('Unbound var %s in template %s' % (e, template_file))
    except Exception as e:
        raise InternalError('Exception %s in template %s' % (e, template_file))

def makefile_list(items):
    separator = " \\\n" + 16*" "
    return separator.join(items)

def gen_bakefile(build_config, options, external_libs):

    def bakefile_sources(fd, sources):
        for src in sources:
            (directory, filename) = os.path.split(os.path.normpath(src))
            directory = directory.replace('\\', '/')
            _, directory = directory.split('src/', 1)
            fd.write('\tsources { src/%s/%s } \n' % (directory, filename))

    def bakefile_cli_headers(fd, headers):
        for header in headers:
            (directory, filename) = os.path.split(os.path.normpath(header))
            directory = directory.replace('\\', '/')
            _, directory = directory.split('src/', 1)
            fd.write('\theaders { src/%s/%s } \n' % (directory, filename))

    def bakefile_test_sources(fd, sources):
        for src in sources:
            (_, filename) = os.path.split(os.path.normpath(src))
            fd.write('\tsources { src/tests/%s } \n' %filename)

    f = open('botan.bkl', 'w')
    f.write('toolsets = vs2013;\n')

    # shared library project
    f.write('shared-library botan {\n')
    f.write('\tdefines = "BOTAN_DLL=__declspec(dllexport)";\n')
    bakefile_sources(f, build_config.lib_sources)
    f.write('}\n')

    # cli project
    f.write('program cli {\n')
    f.write('\tdeps = botan;\n')
    bakefile_sources(f, build_config.cli_sources)
    bakefile_cli_headers(f, build_config.cli_headers)
    f.write('}\n')

    # tests project
    f.write('program tests {\n')
    f.write('\tdeps = botan;\n')
    bakefile_test_sources(f, build_config.test_sources)
    f.write('}\n')

    # global options
    f.write('includedirs += build/include/;\n')

    for lib in external_libs.split(" "):
        f.write('libs += "%s";\n' %lib.replace('.lib', ''))

    if options.with_external_includedir:
        external_inc_dir = options.with_external_includedir.replace('\\', '/')
        # Attention: bakefile supports only relative paths
        f.write('includedirs += "%s";\n' %external_inc_dir)

    if options.with_external_libdir:
        external_lib_dir = options.with_external_libdir.replace('\\', '/')
        # Attention: bakefile supports only relative paths
        f.write('libdirs += "%s";\n' %external_lib_dir)

    if build_config.external_headers:
        f.write('includedirs += build/include/external;\n')

    if options.cpu in "x86_64":
        f.write('archs = x86_64;\n')
    else:
        f.write('archs = x86;\n')

    # vs2013 options
    f.write('vs2013.option.ClCompile.DisableSpecificWarnings = "4250;4251;4275";\n')
    f.write('vs2013.option.ClCompile.WarningLevel = Level4;\n')
    f.write('vs2013.option.ClCompile.ExceptionHandling = SyncCThrow;\n')
    f.write('vs2013.option.ClCompile.RuntimeTypeInfo = true;\n')
    f.write('if ( $(config) == Release ) {\n')
    f.write('vs2013.option.Configuration.WholeProgramOptimization = true;\n')
    f.write('}\n')

    f.close()


class CmakeGenerator(object):
    def __init__(self, build_paths, using_mods, cc, options, template_vars):
        self._build_paths = build_paths
        self._using_mods = using_mods
        self._cc = cc

        self._options_release = copy.deepcopy(options)
        self._options_release.no_optimizations = False
        self._options_release.with_debug_info = False

        self._options_debug = copy.deepcopy(options)
        self._options_debug.no_optimizations = True
        self._options_debug.with_debug_info = True

        self._template_vars = template_vars

    @staticmethod
    def _escape(input_str):
        return input_str.replace('(', '\\(').replace(')', '\\)').replace('#', '\\#').replace('$', '\\$')

    @staticmethod
    def _cmake_normalize(source):
        return os.path.normpath(source).replace('\\', '/')

    @staticmethod
    def _create_target_rules(sources):
        target = {'sources': {}, 'frameworks': set(), 'libs': set()}
        for source in sources:
            target['sources'][source] = {'isa_flags': set()}
        return target

    def _add_target_details(self, target, using_mod):
        libs_or_frameworks_needed = False
        for source_path in target['sources']:
            for mod_source in using_mod.source:
                if source_path == mod_source:
                    libs_or_frameworks_needed = True
                    for isa in using_mod.need_isa:
                        isa_flag = self._cc.isa_flags_for(isa, self._template_vars['arch'])
                        target['sources'][source_path]['isa_flags'].add(isa_flag)
        if libs_or_frameworks_needed:
            if self._options_release.os in using_mod.libs:
                for lib in using_mod.libs[self._options_release.os]:
                    target['libs'].add(lib)
            if self._options_release.os in using_mod.frameworks:
                for framework in using_mod.frameworks[self._options_release.os]:
                    target['frameworks'].add('"-framework %s"' % framework)

    @staticmethod
    def _generate_target_sources_list(fd, target_name, target):
        fd.write('set(%s\n' % target_name)
        sorted_sources = sorted(target['sources'].keys())
        for source in sorted_sources:
            fd.write('    "${CMAKE_CURRENT_LIST_DIR}/%s"\n' % CmakeGenerator._cmake_normalize(source))
        fd.write(')\n\n')

    @staticmethod
    def _generate_target_source_files_isa_properties(fd, target):
        sorted_sources = sorted(target['sources'].keys())
        for source in sorted_sources:
            joined_isa_flags = ' '.join(target['sources'][source]['isa_flags'])
            if joined_isa_flags:
                fd.write('set_source_files_properties("${CMAKE_CURRENT_LIST_DIR}/%s" PROPERTIES COMPILE_FLAGS "%s")\n'
                         % (CmakeGenerator._cmake_normalize(source), joined_isa_flags))

    @staticmethod
    def _write_header(fd):
        fd.write('cmake_minimum_required(VERSION 2.8.0)\n')
        fd.write('project(botan)\n\n')
        fd.write('if(POLICY CMP0042)\n')
        fd.write('cmake_policy(SET CMP0042 NEW)\n')
        fd.write('endif()\n\n')

    def _write_footer(self, fd, library_link, cli_link, tests_link):
        fd.write('\n')

        fd.write('option(ENABLED_OPTIONAL_WARINIGS "If enabled more strict warinig policy will be used" OFF)\n')
        fd.write('option(ENABLED_LTO "If enabled link time optimization will be used" OFF)\n\n')

        fd.write('set(COMPILER_FEATURES_RELEASE %s %s)\n'
                 % (self._cc.cc_compile_flags(self._options_release),
                    self._cc.mach_abi_link_flags(self._options_release)))

        fd.write('set(COMPILER_FEATURES_DEBUG %s %s)\n'
                 % (self._cc.cc_compile_flags(self._options_debug),
                    self._cc.mach_abi_link_flags(self._options_debug)))

        fd.write('set(COMPILER_FEATURES $<$<NOT:$<CONFIG:DEBUG>>:${COMPILER_FEATURES_RELEASE}>'
                 +'  $<$<CONFIG:DEBUG>:${COMPILER_FEATURES_DEBUG}>)\n')

        fd.write('set(SHARED_FEATURES %s)\n' % self._escape(self._template_vars['shared_flags']))
        fd.write('set(STATIC_FEATURES -DBOTAN_DLL=)\n')

        fd.write('set(COMPILER_WARNINGS %s)\n' % self._cc.cc_warning_flags(self._options_release))
        fd.write('set(COMPILER_INCLUDE_DIRS build/include build/include/external)\n')
        fd.write('if(ENABLED_LTO)\n')
        fd.write('    set(COMPILER_FEATURES ${COMPILER_FEATURES} -lto)\n')
        fd.write('endif()\n')
        fd.write('if(ENABLED_OPTIONAL_WARINIGS)\n')
        fd.write('    set(COMPILER_OPTIONAL_WARNINGS -Wsign-promo -Wctor-dtor-privacy -Wdeprecated -Winit-self' +
                 ' -Wnon-virtual-dtor -Wunused-macros -Wold-style-cast -Wuninitialized)\n')
        fd.write('endif()\n\n')

        fd.write('add_library(${PROJECT_NAME} STATIC ${BOTAN_SOURCES})\n')
        fd.write('target_link_libraries(${PROJECT_NAME} PUBLIC %s)\n'
                 % library_link)
        fd.write('target_compile_options(${PROJECT_NAME} PUBLIC ${COMPILER_WARNINGS} ${COMPILER_FEATURES}' +
                 ' ${COMPILER_OPTIONAL_WARNINGS} PRIVATE ${STATIC_FEATURES})\n')

        fd.write('target_include_directories(${PROJECT_NAME} PUBLIC ${COMPILER_INCLUDE_DIRS})\n\n')
        fd.write('set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME ${PROJECT_NAME}-static)\n\n')

        fd.write('add_library(${PROJECT_NAME}_shared SHARED ${BOTAN_SOURCES})\n')
        fd.write('target_link_libraries(${PROJECT_NAME}_shared PUBLIC %s)\n'
                 % library_link)
        fd.write('target_compile_options(${PROJECT_NAME}_shared PUBLIC ${COMPILER_WARNINGS}' +
                 ' ${COMPILER_FEATURES} ${COMPILER_OPTIONAL_WARNINGS} PRIVATE ${SHARED_FEATURES})\n')
        fd.write('target_include_directories(${PROJECT_NAME}_shared PUBLIC ${COMPILER_INCLUDE_DIRS})\n')
        fd.write('set_target_properties(${PROJECT_NAME}_shared PROPERTIES OUTPUT_NAME ${PROJECT_NAME})\n\n')

        fd.write('add_executable(${PROJECT_NAME}_cli ${BOTAN_CLI})\n')
        fd.write('target_link_libraries(${PROJECT_NAME}_cli PRIVATE ${PROJECT_NAME}_shared %s)\n'
                 % cli_link)
        fd.write('set_target_properties(${PROJECT_NAME}_cli PROPERTIES OUTPUT_NAME ${PROJECT_NAME}-cli)\n\n')

        fd.write('add_executable(${PROJECT_NAME}_tests ${BOTAN_TESTS})\n')
        fd.write('target_link_libraries(${PROJECT_NAME}_tests PRIVATE ${PROJECT_NAME}_shared %s)\n'
                 % tests_link)
        fd.write('set_target_properties(${PROJECT_NAME}_tests PROPERTIES OUTPUT_NAME botan-test)\n\n')

        fd.write('set(CONFIGURATION_FILES configure.py .gitignore .astylerc authors.txt news.rst readme.rst)\n')
        fd.write('file(GLOB_RECURSE DOCUMENTATION_FILES doc/* )\n')
        fd.write('file(GLOB_RECURSE HEADER_FILES src/*.h )\n')
        fd.write('file(GLOB_RECURSE INFO_FILES src/lib/*info.txt )\n')
        fd.write('add_custom_target(CONFIGURATION_DUMMY SOURCES ' +
                 '${CONFIGURATION_FILES} ${DOCUMENTATION_FILES} ${INFO_FILES} ${HEADER_FILES})\n')

    def generate(self):
        library_target_configuration = self._create_target_rules(self._build_paths.lib_sources)
        tests_target_configuration = self._create_target_rules(self._build_paths.test_sources)
        cli_target_configuration = self._create_target_rules(self._build_paths.cli_sources)

        for module in self._using_mods:
            self._add_target_details(library_target_configuration, module)
            self._add_target_details(tests_target_configuration, module)
            self._add_target_details(cli_target_configuration, module)

        library_target_libs_and_frameworks = '%s %s' % (
            ' '.join(library_target_configuration['frameworks']),
            ' '.join(library_target_configuration['libs']),
        )
        tests_target_libs_and_frameworks = '%s %s' % (
            ' '.join(tests_target_configuration['frameworks']),
            ' '.join(tests_target_configuration['libs'])
        )
        cli_target_libs_and_frameworks = '%s %s' % (
            ' '.join(cli_target_configuration['frameworks']),
            ' '.join(cli_target_configuration['libs'])
        )

        with open('CMakeLists.txt', 'w') as f:
            self._write_header(f)
            self._generate_target_sources_list(f, 'BOTAN_SOURCES', library_target_configuration)
            self._generate_target_sources_list(f, 'BOTAN_CLI', cli_target_configuration)
            self._generate_target_sources_list(f, 'BOTAN_TESTS', tests_target_configuration)

            self._generate_target_source_files_isa_properties(f, library_target_configuration)
            self._generate_target_source_files_isa_properties(f, cli_target_configuration)
            self._generate_target_source_files_isa_properties(f, tests_target_configuration)

            self._write_footer(f,
                               library_target_libs_and_frameworks,
                               tests_target_libs_and_frameworks,
                               cli_target_libs_and_frameworks)


class MakefileListsGenerator(object):
    def __init__(self, build_paths, options, modules, cc, arch, osinfo):
        self._build_paths = build_paths
        self._options = options
        self._modules = modules
        self._cc = cc
        self._arch = arch
        self._osinfo = osinfo

    def _simd_implementation(self):
        for simd32_impl in ['sse2', 'altivec', 'neon']:
            if simd32_impl in self._arch.isa_extensions \
                and self._cc.isa_flags_for(simd32_impl, self._arch.basename) is not None:
                return simd32_impl
        return None

    def _get_isa_specific_flags(self, isas):
        flags = set()
        for isa in isas:
            # a flagset is a string that may contain multiple command
            # line arguments, e.g. "-maes -mpclmul -mssse3"
            flagset = self._cc.isa_flags_for(isa, self._arch.basename)
            if flagset is None:
                raise UserError('Compiler %s does not support %s' % (self._cc.basename, isa))
            flags.add(flagset)
        return flags

    def _isa_specific_flags(self, src):
        simd_impl = self._simd_implementation()

        if os.path.basename(src) == 'test_simd.cpp':
            isas = [simd_impl] if simd_impl else []
            return self._get_isa_specific_flags(isas)

        for mod in self._modules:
            if src in mod.sources():
                isas = mod.need_isa
                if 'simd' in mod.dependencies():
                    if simd_impl:
                        isas.append(simd_impl)

                return self._get_isa_specific_flags(isas)

        if src.startswith('botan_all_'):
            isas = src.replace('botan_all_', '').replace('.cpp', '').split('_')
            return self._get_isa_specific_flags(isas)

        return set()

    def _objectfile_list(self, sources, obj_dir):
        for src in sources:
            (directory, filename) = os.path.split(os.path.normpath(src))

            parts = directory.split(os.sep)
            if 'src' in parts:
                parts = parts[parts.index('src')+2:]
            elif 'tests' in parts:
                parts = parts[parts.index('tests')+2:]
            elif 'cli' in parts:
                parts = parts[parts.index('cli'):]
            elif filename.find('botan_all') != -1:
                parts = []
            else:
                raise InternalError("Unexpected file '%s/%s'" % (directory, filename))

            if parts != []:
                # Handle src/X/X.cpp -> X.o
                if filename == parts[-1] + '.cpp':
                    name = '_'.join(parts) + '.cpp'
                else:
                    name = '_'.join(parts) + '_' + filename

                def fixup_obj_name(name):
                    def remove_dups(parts):
                        last = None
                        for part in parts:
                            if last is None or part != last:
                                last = part
                                yield part

                    return '_'.join(remove_dups(name.split('_')))

                name = fixup_obj_name(name)
            else:
                name = filename

            for src_suffix in ['.cpp', '.S']:
                name = name.replace(src_suffix, '.' + self._osinfo.obj_suffix)

            yield os.path.join(obj_dir, name)

    def _build_commands(self, sources, obj_dir, flags):
        """
        Form snippets of makefile for building each source file
        """

        includes = self._cc.add_include_dir_option + self._build_paths.include_dir
        if self._build_paths.external_headers:
            includes += ' ' + self._cc.add_include_dir_option + self._build_paths.external_include_dir
        if self._options.with_external_includedir:
            includes += ' ' + self._cc.add_include_dir_option + self._options.with_external_includedir

        for (obj_file, src) in zip(self._objectfile_list(sources, obj_dir), sources):
            isa_specific_flags_str = "".join([" %s" % flagset for flagset in sorted(self._isa_specific_flags(src))])
            yield '%s: %s\n\t$(CXX)%s $(%s_FLAGS) %s %s %s %s$@\n' % (
                obj_file,
                src,
                isa_specific_flags_str,
                flags,
                includes,
                self._cc.compile_flags,
                src,
                self._cc.output_to_option)

    def generate(self):
        out = {}
        for t in ['lib', 'cli', 'test']:
            obj_key = '%s_objs' % (t)
            src_list, src_dir = self._build_paths.src_info(t)
            src_list.sort()
            out[obj_key] = makefile_list(self._objectfile_list(src_list, src_dir))
            build_key = '%s_build_cmds' % (t)
            out[build_key] = '\n'.join(self._build_commands(src_list, src_dir, t.upper()))
        return out


class HouseEccCurve(object):
    def __init__(self, house_curve):
        p = house_curve.split(",")
        if len(p) != 4:
            raise UserError('--house-curve must have 4 comma separated parameters. See --help')
        # make sure TLS curve id is in reserved for private use range (0xFE00..0xFEFF)
        curve_id = int(p[3], 16)
        if curve_id < 0xfe00 or curve_id > 0xfeff:
            raise UserError('TLS curve ID not in reserved range (see RFC 4492)')

        self._defines = [
            'HOUSE_ECC_CURVE_NAME \"' + p[1] + '\"',
            'HOUSE_ECC_CURVE_OID \"' + p[2] + '\"',
            'HOUSE_ECC_CURVE_PEM ' + self._read_pem(filepath=p[0]),
            'HOUSE_ECC_CURVE_TLS_ID ' + hex(curve_id),
        ]

    def defines(self):
        return self._defines

    @staticmethod
    def _read_pem(filepath):
        try:
            with open(filepath) as f:
                lines = [line.rstrip() for line in f]
        except IOError:
            raise UserError("Error reading file '%s'" % filepath)

        for ndx, _ in enumerate(lines):
            lines[ndx] = '   \"%s\"' % lines[ndx]
        return "\\\n" + ' \\\n'.join(lines)


def create_template_vars(source_paths, build_config, options, modules, cc, arch, osinfo):
    """
    Create the template variables needed to process the makefile, build.h, etc
    """

    def make_cpp_macros(macros):
        return '\n'.join(['#define BOTAN_' + macro for macro in macros])

    def external_link_cmd():
        return ' ' + cc.add_lib_dir_option + options.with_external_libdir if options.with_external_libdir else ''

    def link_to(module_member_name):
        """
        Figure out what external libraries/frameworks are needed based on selected modules
        """
        if not (module_member_name == 'libs' or module_member_name == 'frameworks'):
            raise InternalError("Invalid argument")

        libs = set()
        for module in modules:
            for (osname, module_link_to) in getattr(module, module_member_name).items():
                if osname == 'all' or osname == osinfo.basename:
                    libs |= set(module_link_to)
                else:
                    match = re.match('^all!(.*)', osname)
                    if match is not None:
                        exceptions = match.group(1).split(',')
                        if osinfo.basename not in exceptions:
                            libs |= set(module_link_to)
        return sorted(libs)

    def choose_mp_bits():
        mp_bits = arch.wordsize # allow command line override?
        logging.debug('Using MP bits %d' % (mp_bits))
        return mp_bits

    def innosetup_arch(os_name, arch):
        if os_name == 'windows':
            inno_arch = {'x86_32': '', 'x86_64': 'x64', 'ia64': 'ia64'}
            if arch in inno_arch:
                return inno_arch[arch]
            else:
                logging.warning('Unknown arch in innosetup_arch %s' % (arch))
        return None

    def configure_command_line():
        # Cut absolute path from main executable (e.g. configure.py or python interpreter)
        # to get the same result when configuring the same thing on different machines
        main_executable = os.path.basename(sys.argv[0])
        return ' '.join([main_executable] + sys.argv[1:])

    variables = {
        'version_major':  Version.major,
        'version_minor':  Version.minor,
        'version_patch':  Version.patch,
        'version_vc_rev': Version.vc_rev(),
        'so_abi_rev':     Version.so_rev,
        'version':        Version.as_string(),
        'version_packed': Version.packed,
        'release_type':   Version.release_type,
        'version_datestamp': Version.datestamp,

        'distribution_info': options.distribution_info,

        'base_dir': source_paths.base_dir,
        'src_dir': source_paths.src_dir,
        'doc_dir': source_paths.doc_dir,

        'command_line': configure_command_line(),
        'local_config': read_textfile(options.local_config),
        'makefile_style': options.makefile_style or cc.makefile_style,

        'makefile_path': os.path.join(build_config.build_dir, '..', 'Makefile'),

        'program_suffix': options.program_suffix or osinfo.program_suffix,

        'prefix': options.prefix or osinfo.install_root,
        'destdir': options.destdir or options.prefix or osinfo.install_root,
        'bindir': options.bindir or osinfo.bin_dir,
        'libdir': options.libdir or osinfo.lib_dir,
        'includedir': options.includedir or osinfo.header_dir,
        'docdir': options.docdir or osinfo.doc_dir,

        'out_dir': options.with_build_dir or os.path.curdir,
        'build_dir': build_config.build_dir,

        'scripts_dir': source_paths.scripts_dir,

        'build_shared_lib': options.build_shared_lib,

        'libobj_dir': build_config.libobj_dir,
        'cliobj_dir': build_config.cliobj_dir,
        'testobj_dir': build_config.testobj_dir,

        'doc_output_dir': build_config.doc_output_dir,

        'build_doc_commands': make_build_doc_commands(source_paths, build_config, options),

        'python_dir': source_paths.python_dir,
        'sphinx_config_dir': source_paths.sphinx_config_dir,

        'os': options.os,
        'arch': options.arch,
        'submodel': options.cpu,

        'innosetup_arch': innosetup_arch(options.os, options.arch),

        'mp_bits': choose_mp_bits(),

        'cxx': (options.compiler_binary or cc.binary_name),
        'cxx_abi_flags': cc.mach_abi_link_flags(options),
        'linker': cc.linker_name or '$(CXX)',

        'cc_compile_flags': cc.cc_compile_flags(options),
        'cc_warning_flags': cc.cc_warning_flags(options),

        'shared_flags': cc.gen_shared_flags(options),
        'visibility_attribute': cc.gen_visibility_attribute(options),

        'lib_link_cmd': cc.so_link_command_for(osinfo.basename, options) + external_link_cmd(),
        'cli_link_cmd': cc.binary_link_command_for(osinfo.basename, options) + external_link_cmd(),
        'test_link_cmd': cc.binary_link_command_for(osinfo.basename, options) + external_link_cmd(),

        'link_to': ' '.join(
            [cc.add_lib_option + lib for lib in link_to('libs')] +
            [cc.add_framework_option + fw for fw in link_to('frameworks')]
        ),

        'module_defines': make_cpp_macros(sorted(flatten([m.defines() for m in modules]))),

        'target_os_defines': make_cpp_macros(osinfo.defines(options)),

        'target_compiler_defines': make_cpp_macros(cc.defines()),

        'target_cpu_defines': make_cpp_macros(arch.defines(cc, options)),

        'botan_include_dir': build_config.botan_include_dir,

        'include_files': makefile_list(build_config.public_headers),

        'unsafe_fuzzer_mode_define': '' if not options.unsafe_fuzzer_mode else '#define BOTAN_UNSAFE_FUZZER_MODE',

        'ar_command': cc.ar_command or osinfo.ar_command,
        'ranlib_command': osinfo.ranlib_command(),
        'install_cmd_exec': osinfo.install_cmd_exec,
        'install_cmd_data': osinfo.install_cmd_data,

        'lib_prefix': 'lib' if options.os != 'windows' else '',

        'static_suffix': osinfo.static_suffix,

        'mod_list': '\n'.join(sorted([m.basename for m in modules])),

        'python_version': options.python_version,
        'with_sphinx': options.with_sphinx,
        'house_ecc_curve_defines': make_cpp_macros(HouseEccCurve(options.house_curve).defines()) \
                                   if options.house_curve else ''
        }

    if options.build_shared_lib:

        if osinfo.soname_pattern_base != None:
            variables['soname_base'] = osinfo.soname_pattern_base.format(
                version_major=Version.major,
                version_minor=Version.minor,
                version_patch=Version.patch,
                abi_rev=Version.so_rev)

        if osinfo.soname_pattern_abi != None:
            variables['soname_abi'] = osinfo.soname_pattern_abi.format(
                version_major=Version.major,
                version_minor=Version.minor,
                version_patch=Version.patch,
                abi_rev=Version.so_rev)

        if osinfo.soname_pattern_patch != None:
            variables['soname_patch'] = osinfo.soname_pattern_patch.format(
                version_major=Version.major,
                version_minor=Version.minor,
                version_patch=Version.patch,
                abi_rev=Version.so_rev)

    if options.os == 'darwin' and options.build_shared_lib:
        # In order that these executables work from the build directory,
        # we need to change the install names
        variables['cli_post_link_cmd'] = \
            'install_name_tool -change "$(INSTALLED_LIB_DIR)/$(SONAME_ABI)" "@executable_path/$(SONAME_ABI)" $(CLI)'
        variables['test_post_link_cmd'] = \
            'install_name_tool -change "$(INSTALLED_LIB_DIR)/$(SONAME_ABI)" "@executable_path/$(SONAME_ABI)" $(TEST)'
    else:
        variables['cli_post_link_cmd'] = ''
        variables['test_post_link_cmd'] = ''

    variables.update(MakefileListsGenerator(build_config, options, modules, cc, arch, osinfo).generate())

    if options.os == 'windows':
        if options.with_debug_info:
            variables['libname'] = 'botand'
        else:
            variables['libname'] = 'botan'
    else:
        variables['botan_pkgconfig'] = os.path.join(build_config.build_dir, PKG_CONFIG_FILENAME)

        # 'botan' or 'botan-2'. Used in Makefile and install script
        # This can be made consistent over all platforms in the future
        variables['libname'] = 'botan-%d' % (Version.major)

    variables["header_in"] = process_template(os.path.join(source_paths.makefile_dir, 'header.in'), variables)

    if variables["makefile_style"] == "gmake":
        variables["gmake_commands_in"] = process_template(
            os.path.join(source_paths.makefile_dir, 'gmake_commands.in'),
            variables)
        variables["gmake_dso_in"] = process_template(
            os.path.join(source_paths.makefile_dir, 'gmake_dso.in'),
            variables
            ) if options.build_shared_lib else ''
        variables["gmake_coverage_in"] = process_template(
            os.path.join(source_paths.makefile_dir, 'gmake_coverage.in'),
            variables
            ) if options.with_coverage_info else ''

    return variables

class ModulesChooser(object):
    """
    Determine which modules to load based on options, target, etc
    """

    def __init__(self, modules, module_policy, archinfo, ccinfo, cc_version, options):
        self._modules = modules
        self._module_policy = module_policy
        self._archinfo = archinfo
        self._ccinfo = ccinfo
        self._cc_version = cc_version
        self._options = options

        self._maybe_dep = set()
        self._to_load = set()
        # string to set mapping with reasons as key and modules as value
        self._not_using_because = collections.defaultdict(set)

        ModulesChooser._validate_dependencies_exist(self._modules)
        ModulesChooser._validate_user_selection(
            self._modules, self._options.enabled_modules, self._options.disabled_modules)

    def _check_usable(self, module, modname):
        if not module.compatible_os(self._options.os):
            self._not_using_because['incompatible OS'].add(modname)
            return False
        elif not module.compatible_compiler(self._ccinfo, self._cc_version, self._archinfo.basename):
            self._not_using_because['incompatible compiler'].add(modname)
            return False
        elif not module.compatible_cpu(self._archinfo, self._options):
            self._not_using_because['incompatible CPU'].add(modname)
            return False
        return True

    @staticmethod
    def _display_module_information_unused(skipped_modules):
        for reason in sorted(skipped_modules.keys()):
            disabled_mods = sorted(skipped_modules[reason])
            if disabled_mods:
                logging.info('Skipping (%s): %s' % (reason, ' '.join(disabled_mods)))

    @staticmethod
    def _display_module_information_to_load(all_modules, modules_to_load):
        sorted_modules_to_load = sorted(modules_to_load)

        for modname in sorted_modules_to_load:
            if modname.startswith('simd_') and modname != 'simd_engine':
                logging.info('Using SIMD module ' + modname)

        for modname in sorted_modules_to_load:
            if all_modules[modname].comment:
                logging.info('%s: %s' % (modname, all_modules[modname].comment))
            if all_modules[modname].warning:
                logging.warning('%s: %s' % (modname, all_modules[modname].warning))
            if all_modules[modname].load_on == 'vendor':
                logging.info('Enabling use of external dependency %s' % modname)

        if sorted_modules_to_load:
            logging.info('Loading modules: %s', ' '.join(sorted_modules_to_load))
        else:
            logging.error('This configuration disables every submodule and is invalid')

    @staticmethod
    def _validate_state(used_modules, unused_modules):
        for reason, unused_for_reason in unused_modules.items():
            intersection = unused_for_reason & used_modules
            if intersection:
                raise InternalError(
                    "Disabled modules (%s) and modules to load have common elements: %s"
                    % (reason, intersection))

    @staticmethod
    def _validate_dependencies_exist(modules):
        for module in modules.values():
            module.dependencies_exist(modules)

    @staticmethod
    def _validate_user_selection(modules, enabled_modules, disabled_modules):
        for modname in enabled_modules:
            if modname not in modules:
                logging.error("Module not found: %s" % modname)

        for modname in disabled_modules:
            if modname not in modules:
                logging.warning("Disabled module not found: %s" % modname)

    def _handle_by_module_policy(self, modname, usable):
        if self._module_policy is not None:
            if modname in self._module_policy.required:
                if not usable:
                    logging.error('Module policy requires module %s not usable on this platform' % (modname))
                elif modname in self._options.disabled_modules:
                    logging.error('Module %s was disabled but is required by policy' % (modname))
                self._to_load.add(modname)
                return True
            elif modname in self._module_policy.if_available:
                if modname in self._options.disabled_modules:
                    self._not_using_because['disabled by user'].add(modname)
                elif usable:
                    logging.debug('Enabling optional module %s' % (modname))
                    self._to_load.add(modname)
                return True
            elif modname in self._module_policy.prohibited:
                if modname in self._options.enabled_modules:
                    logging.error('Module %s was requested but is prohibited by policy' % (modname))
                self._not_using_because['prohibited by module policy'].add(modname)
                return True

        return False

    @staticmethod
    def resolve_dependencies(available_modules, dependency_table, module, loaded_modules=None):
        """
        Parameters
        - available_modules: modules to choose from. Constant.
        - dependency_table: module to dependencies map. Constant.
        - module: name of the module to resolve dependencies. Constant.
        - loaded_modules: modules already loaded. Defensive copy in order to not change value for caller.
        """
        if loaded_modules is None:
            loaded_modules = set([])
        else:
            loaded_modules = copy.deepcopy(loaded_modules)

        if module not in available_modules:
            return False, None

        loaded_modules.add(module)
        for dependency in dependency_table[module]:
            dependency_choices = set(dependency.split('|'))

            dependency_met = False

            if not set(dependency_choices).isdisjoint(loaded_modules):
                dependency_met = True
            else:
                possible_mods = dependency_choices.intersection(available_modules)

                for mod in possible_mods:
                    ok, dependency_modules = ModulesChooser.resolve_dependencies(
                        available_modules, dependency_table, mod, loaded_modules)
                    if ok:
                        dependency_met = True
                        loaded_modules.add(mod)
                        loaded_modules.update(dependency_modules)
                        break

            if not dependency_met:
                return False, None

        return True, loaded_modules

    def _modules_dependency_table(self):
        out = {}
        for modname in self._modules:
            out[modname] = self._modules[modname].dependencies()
        return out

    def _resolve_dependencies_for_all_modules(self):
        available_modules = set(self._to_load) | set(self._maybe_dep)
        dependency_table = self._modules_dependency_table()

        successfully_loaded = set()

        for modname in self._to_load:
            # This will try to recusively load all dependencies of modname
            ok, modules = self.resolve_dependencies(available_modules, dependency_table, modname)
            if ok:
                successfully_loaded.add(modname)
                successfully_loaded.update(modules)
            else:
                # Skip this module
                pass

        self._not_using_because['dependency failure'].update(self._to_load - successfully_loaded)
        self._to_load = successfully_loaded
        self._maybe_dep -= successfully_loaded

    def _handle_by_load_on(self, module): # pylint: disable=too-many-branches
        modname = module.basename
        if module.load_on == 'never':
            self._not_using_because['disabled as buggy'].add(modname)
        elif module.load_on == 'request':
            if self._options.with_everything:
                self._to_load.add(modname)
            else:
                self._not_using_because['by request only'].add(modname)
        elif module.load_on == 'vendor':
            if self._options.with_everything:
                self._to_load.add(modname)
            else:
                self._not_using_because['requires external dependency'].add(modname)
        elif module.load_on == 'dep':
            self._maybe_dep.add(modname)

        elif module.load_on == 'always':
            self._to_load.add(modname)

        elif module.load_on == 'auto':
            if self._options.no_autoload or self._module_policy is not None:
                self._maybe_dep.add(modname)
            else:
                self._to_load.add(modname)
        else:
            logging.error('Unknown load_on %s in %s' % (
                module.load_on, modname))

    def choose(self):
        for (modname, module) in self._modules.items():
            usable = self._check_usable(module, modname)

            module_handled = self._handle_by_module_policy(modname, usable)
            if module_handled:
                continue

            if modname in self._options.disabled_modules:
                self._not_using_because['disabled by user'].add(modname)
            elif usable:
                if modname in self._options.enabled_modules:
                    self._to_load.add(modname) # trust the user
                else:
                    self._handle_by_load_on(module)

        if 'compression' in self._to_load:
            # Confirm that we have at least one compression library enabled
            # Otherwise we leave a lot of useless support code compiled in, plus a
            # make_compressor call that always fails
            if 'zlib' not in self._to_load and 'bzip2' not in self._to_load and 'lzma' not in self._to_load:
                self._to_load.remove('compression')
                self._not_using_because['no enabled compression schemes'].add('compression')

        self._resolve_dependencies_for_all_modules()

        for not_a_dep in self._maybe_dep:
            self._not_using_because['not requested'].add(not_a_dep)

        ModulesChooser._validate_state(self._to_load, self._not_using_because)
        ModulesChooser._display_module_information_unused(self._not_using_because)
        ModulesChooser._display_module_information_to_load(self._modules, self._to_load)

        return self._to_load

def choose_link_method(options):
    """
    Choose the link method based on system availablity and user request
    """

    req = options.link_method

    def useable_methods():
        # Symbolic link support on Windows was introduced in Windows 6.0 (Vista) and Python 3.2
        # Furthermore the SeCreateSymbolicLinkPrivilege is required in order to successfully create symlinks
        # So only try to use symlinks on Windows if explicitly requested
        if req == 'symlink' and options.os == 'windows':
            yield 'symlink'
        # otherwise keep old conservative behavior
        if 'symlink' in os.__dict__ and options.os != 'windows':
            yield 'symlink'
        if 'link' in os.__dict__:
            yield 'hardlink'
        yield 'copy'

    for method in useable_methods():
        if req is None or req == method:
            logging.info('Using %s to link files into build dir ' \
                         '(use --link-method to change)' % (method))
            return method

    logging.warning('Could not use link method "%s", will copy instead' % (req))
    return 'copy'

def portable_symlink(file_path, target_dir, method):
    """
    Copy or link the file, depending on what the platform offers
    """

    if not os.access(file_path, os.R_OK):
        logging.warning('Missing file %s' % (file_path))
        return

    if method == 'symlink':
        rel_file_path = os.path.relpath(file_path, start=target_dir)
        os.symlink(rel_file_path, os.path.join(target_dir, os.path.basename(file_path)))
    elif method == 'hardlink':
        os.link(file_path, os.path.join(target_dir, os.path.basename(file_path)))
    elif method == 'copy':
        shutil.copy(file_path, target_dir)
    else:
        raise UserError('Unknown link method %s' % (method))


class AmalgamationHelper(object):
    _any_include_matcher = re.compile(r'#include <(.*)>$')
    _botan_include_matcher = re.compile(r'#include <botan/(.*)>$')
    _std_include_matcher = re.compile(r'^#include <([^/\.]+|stddef.h)>$')

    @staticmethod
    def is_any_include(cpp_source_line):
        match = AmalgamationHelper._any_include_matcher.search(cpp_source_line)
        if match:
            return match.group(1)
        else:
            return None

    @staticmethod
    def is_botan_include(cpp_source_line):
        match = AmalgamationHelper._botan_include_matcher.search(cpp_source_line)
        if match:
            return match.group(1)
        else:
            return None

    @staticmethod
    def is_std_include(cpp_source_line):
        match = AmalgamationHelper._std_include_matcher.search(cpp_source_line)
        if match:
            return match.group(1)
        else:
            return None


class AmalgamationHeader(object):
    def __init__(self, input_filepaths):

        self.included_already = set()
        self.all_std_includes = set()

        self.file_contents = {}
        for filepath in sorted(input_filepaths):
            try:
                with open(filepath) as f:
                    raw_content = f.readlines()
                contents = AmalgamationGenerator.strip_header_goop(filepath, raw_content)
                self.file_contents[os.path.basename(filepath)] = contents
            except IOError as e:
                logging.error('Error processing file %s for amalgamation: %s' % (filepath, e))

        self.contents = ''
        for name in sorted(self.file_contents):
            self.contents += ''.join(list(self.header_contents(name)))

        self.header_includes = ''
        for std_header in sorted(self.all_std_includes):
            self.header_includes += '#include <%s>\n' % (std_header)
        self.header_includes += '\n'

    def header_contents(self, name):
        name = name.replace('internal/', '')

        if name in self.included_already:
            return

        self.included_already.add(name)

        if name not in self.file_contents:
            return

        for line in self.file_contents[name]:
            header = AmalgamationHelper.is_botan_include(line)
            if header:
                for c in self.header_contents(header):
                    yield c
            else:
                std_header = AmalgamationHelper.is_std_include(line)

                if std_header:
                    self.all_std_includes.add(std_header)
                else:
                    yield line

    @staticmethod
    def write_banner(fd):
        fd.write("""/*
* Botan %s Amalgamation
* (C) 1999-2013,2014,2015,2016 Jack Lloyd and others
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
""" % (Version.as_string()))

    @staticmethod
    def _write_start_include_guard(fd, title):
        fd.write("""
#ifndef %s
#define %s

""" % (title, title))

    @staticmethod
    def _write_end_include_guard(fd, title):
        fd.write("\n#endif // %s\n" % (title))

    def write_to_file(self, filepath, include_guard):
        with open(filepath, 'w') as f:
            self.write_banner(f)
            self._write_start_include_guard(f, include_guard)
            f.write(self.header_includes)
            f.write(self.contents)
            self._write_end_include_guard(f, include_guard)


class AmalgamationGenerator(object):
    filename_prefix = 'botan_all'

    _header_guard_pattern = re.compile('^#define BOTAN_.*_H__$')

    @staticmethod
    def strip_header_goop(header_name, header_lines):
        lines = copy.deepcopy(header_lines) # defensive copy: don't mutate argument

        start_header_guard_index = None
        for index, line in enumerate(lines):
            if AmalgamationGenerator._header_guard_pattern.match(line):
                start_header_guard_index = index
                break
        if start_header_guard_index is None:
            raise InternalError("No header guard start found in " + header_name)

        end_header_guard_index = None
        for index, line in enumerate(lines):
            if line == '#endif\n':
                end_header_guard_index = index # override with last found
        if end_header_guard_index is None:
            raise InternalError("No header guard end found in " + header_name)

        lines = lines[start_header_guard_index+1 : end_header_guard_index]

        # Strip leading and trailing empty lines
        while lines[0].strip() == "":
            lines = lines[1:]
        while lines[-1].strip() == "":
            lines = lines[0:-1]

        return lines

    def __init__(self, build_paths, modules, options):
        self._build_paths = build_paths
        self._modules = modules
        self._options = options

    def _target_for_module(self, mod):
        target = ''
        if not self._options.single_amalgamation_file:
            if mod.need_isa != []:
                target = '_'.join(sorted(mod.need_isa))
                if target == 'sse2' and self._options.arch == 'x86_64':
                    target = '' # SSE2 is always available on x86-64

            if self._options.arch == 'x86_32' and 'simd' in mod.requires:
                target = 'sse2'
        return target

    def _isas_for_target(self, target):
        for mod in sorted(self._modules, key=lambda module: module.basename):
            # Only first module for target is considered. Does this make sense?
            if self._target_for_module(mod) == target:
                out = set()
                for isa in mod.need_isa:
                    if isa == 'aesni':
                        isa = "aes,ssse3,pclmul"
                    elif isa == 'rdrand':
                        isa = 'rdrnd'
                    out.add(isa)
                return out
        # Return set such that we can also iterate over result in the NA case
        return set()

    def _generate_headers(self):
        pub_header_amalag = AmalgamationHeader(self._build_paths.public_headers)
        header_name = '%s.h' % (AmalgamationGenerator.filename_prefix)
        logging.info('Writing amalgamation header to %s' % (header_name))
        pub_header_amalag.write_to_file(header_name, "BOTAN_AMALGAMATION_H__")

        internal_headers = AmalgamationHeader(self._build_paths.internal_headers)
        header_int_name = '%s_internal.h' % (AmalgamationGenerator.filename_prefix)
        logging.info('Writing amalgamation header to %s' % (header_int_name))
        internal_headers.write_to_file(header_int_name, "BOTAN_AMALGAMATION_INTERNAL_H__")

        header_files = [header_name, header_int_name]
        included_in_headers = pub_header_amalag.all_std_includes | internal_headers.all_std_includes
        return header_files, included_in_headers

    def _generate_sources(self, amalgamation_headers, included_in_headers): #pylint: disable=too-many-locals,too-many-branches
        # target to filepath map
        amalgamation_sources = {}
        for mod in self._modules:
            target = self._target_for_module(mod)
            amalgamation_sources[target] = '%s%s.cpp' % (
                AmalgamationGenerator.filename_prefix,
                '_' + target if target else '')

        # file descriptors for all `amalgamation_sources`
        amalgamation_files = {}
        for target, filepath in amalgamation_sources.items():
            logging.info('Writing amalgamation source to %s' % (filepath))
            amalgamation_files[target] = open(filepath, 'w')

        for target, f in amalgamation_files.items():
            AmalgamationHeader.write_banner(f)
            f.write('\n')
            for header in amalgamation_headers:
                f.write('#include "%s"\n' % (header))
            f.write('\n')

            for isa in self._isas_for_target(target):
                f.write('#if defined(__GNUG__)\n')
                f.write('#pragma GCC target ("%s")\n' % (isa))
                f.write('#endif\n')

        # target to include header map
        headers_written = {}
        for target, _ in amalgamation_sources.items():
            headers_written[target] = included_in_headers.copy()

        for mod in sorted(self._modules, key=lambda module: module.basename):
            tgt = self._target_for_module(mod)
            for src in sorted(mod.source):
                with open(src, 'r') as f:
                    for line in f:
                        if AmalgamationHelper.is_botan_include(line):
                            continue

                        header = AmalgamationHelper.is_any_include(line)
                        if header:
                            if header in headers_written[tgt]:
                                continue

                            amalgamation_files[tgt].write(line)
                            headers_written[tgt].add(header)
                        else:
                            amalgamation_files[tgt].write(line)

        for f in amalgamation_files.values():
            f.close()

        return set(amalgamation_sources.values())

    def generate(self):
        amalgamation_headers, included_in_headers = self._generate_headers()
        amalgamation_sources = self._generate_sources(amalgamation_headers, included_in_headers)
        return amalgamation_sources


def detect_compiler_version(ccinfo, cc_bin, os_name):
    # pylint: disable=too-many-locals

    cc_version_flag = {
        'msvc': ([], r'Compiler Version ([0-9]+).([0-9]+).[0-9\.]+ for'),
        'gcc': (['-v'], r'gcc version ([0-9]+.[0-9])+.[0-9]+'),
        'clang': (['-v'], r'clang version ([0-9]+.[0-9])[ \.]')
    }

    cc_name = ccinfo.basename
    if cc_name not in cc_version_flag.keys():
        logging.info("No compiler version detection available for %s" % (cc_name))
        return None

    (flags, version_re_str) = cc_version_flag[cc_name]
    cc_cmd = cc_bin.split(' ') + flags

    try:
        cc_version = None

        version = re.compile(version_re_str)
        cc_output = subprocess.Popen(cc_cmd,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     universal_newlines=True).communicate()

        cc_output = str(cc_output)
        match = version.search(cc_output)

        if match:
            if cc_name == 'msvc':
                cl_version_to_msvc_version = {
                    '18.00': '2013',
                    '19.00': '2015',
                    '19.10': '2017'
                }
                cl_version = match.group(1) + '.' + match.group(2)
                if cl_version in cl_version_to_msvc_version:
                    cc_version = cl_version_to_msvc_version[cl_version]
                else:
                    logging.warning('Unable to determine MSVC version from output "%s"' % (cc_output))
                    return None
            else:
                cc_version = match.group(1)
        elif match is None and cc_name == 'clang' and os_name in ['darwin', 'ios']:
            xcode_version_to_clang = {
                '703': '3.8',
                '800': '3.9',
                '802': '4.0'
            }

            version = re.compile(r'Apple LLVM version [0-9.]+ \(clang-([0-9]{3})\.')
            match = version.search(cc_output)

            if match:
                apple_clang_version = match.group(1)
                if apple_clang_version in xcode_version_to_clang:
                    cc_version = xcode_version_to_clang[apple_clang_version]
                    logging.info('Mapping Apple Clang version %s to LLVM version %s' % (
                        apple_clang_version, cc_version))
                else:
                    logging.warning('Unable to determine LLVM Clang version cooresponding to Apple Clang %s' %
                                    (apple_clang_version))
                    return '3.8' # safe default

        if cc_version is None:
            logging.warning("Ran '%s' to get %s version, but output '%s' does not match expected version format" % (
                ' '.join(cc_cmd), cc_name, cc_output))
            return None

        logging.info('Detected %s compiler version %s' % (cc_name, cc_version))
        return cc_version
    except OSError as e:
        logging.warning('Could not execute %s for version check: %s' % (cc_cmd, e))
        return None

def have_program(program):
    """
    Test for the existence of a program
    """

    def exe_test(path, program):
        exe_file = os.path.join(path, program)

        if os.path.exists(exe_file) and os.access(exe_file, os.X_OK):
            logging.debug('Found program %s in %s' % (program, path))
            return True
        else:
            return False

    exe_suffixes = ['', '.exe']

    for path in os.environ['PATH'].split(os.pathsep):
        for suffix in exe_suffixes:
            if exe_test(path, program + suffix):
                return True

    logging.debug('Program %s not found' % (program))
    return False


class BotanConfigureLogHandler(logging.StreamHandler, object):
    def emit(self, record):
        # Do the default stuff first
        super(BotanConfigureLogHandler, self).emit(record)
        # Exit script if and ERROR or worse occurred
        if record.levelno >= logging.ERROR:
            sys.exit(1)


def setup_logging(options):
    if options.verbose:
        log_level = logging.DEBUG
    elif options.quiet:
        log_level = logging.WARNING
    else:
        log_level = logging.INFO

    lh = BotanConfigureLogHandler(sys.stdout)
    lh.setFormatter(logging.Formatter('%(levelname) 7s: %(message)s'))
    logging.getLogger().addHandler(lh)
    logging.getLogger().setLevel(log_level)


def load_info_files(search_dir, descr, filename_matcher, class_t):
    info = {}

    def filename_matches(filename):
        if isinstance(filename_matcher, str):
            return filename == filename_matcher
        else:
            return filename_matcher.match(filename) is not None

    for (dirpath, _, filenames) in os.walk(search_dir):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            if filename_matches(filename):
                info_obj = class_t(filepath)
                info[info_obj.basename] = info_obj

    if info:
        infotxt_basenames = ' '.join(sorted([key for key in info]))
        logging.debug('Loaded %d %s files: %s' % (len(info), descr, infotxt_basenames))
    else:
        logging.warning('Failed to load any %s files' % (descr))

    return info


def load_build_data_info_files(source_paths, descr, subdir, class_t):
    matcher = re.compile(r'[_a-z0-9]+\.txt$')
    return load_info_files(os.path.join(source_paths.build_data_dir, subdir), descr, matcher, class_t)


# Workaround for Windows systems where antivirus is enabled GH #353
def robust_rmtree(path, max_retries=5):
    for _ in range(max_retries):
        try:
            shutil.rmtree(path)
            return
        except OSError:
            time.sleep(0.1)

    # Final attempt, pass any exceptions up to caller.
    shutil.rmtree(path)


# Workaround for Windows systems where antivirus is enabled GH #353
def robust_makedirs(directory, max_retries=5):
    for _ in range(max_retries):
        try:
            os.makedirs(directory)
            return
        except OSError as e:
            if e.errno == errno.EEXIST:
                raise
            else:
                time.sleep(0.1)

    # Final attempt, pass any exceptions up to caller.
    os.makedirs(directory)


# This is for otions that have --with-XYZ and --without-XYZ. If user does not
# set any of those, we choose a default here.
# Mutates `options`
def set_defaults_for_unset_options(options, info_arch, info_cc): # pylint: disable=too-many-branches
    if options.os is None:
        system_from_python = platform.system().lower()
        if re.match('^cygwin_.*', system_from_python):
            logging.debug("Converting '%s' to 'cygwin'", system_from_python)
            options.os = 'cygwin'
        else:
            options.os = system_from_python
        logging.info('Guessing target OS is %s (use --os to set)' % (options.os))

    if options.compiler is None:
        if options.os == 'windows':
            if have_program('g++') and not have_program('cl'):
                options.compiler = 'gcc'
            else:
                options.compiler = 'msvc'
        elif options.os in ['darwin', 'freebsd', 'ios']:
            if have_program('clang++'):
                options.compiler = 'clang'
        elif options.os == 'openbsd':
            if have_program('eg++'):
                info_cc['gcc'].binary_name = 'eg++'
            else:
                logging.warning('Default GCC is too old; install a newer one using \'pkg_add gcc\'')
            # The assembler shipping with OpenBSD 5.9 does not support avx2
            del info_cc['gcc'].isa_flags['avx2']
            options.compiler = 'gcc'
        else:
            options.compiler = 'gcc'
        logging.info('Guessing to use compiler %s (use --cc to set)' % (
            options.compiler))

    if options.cpu is None:
        (options.arch, options.cpu) = guess_processor(info_arch)
        logging.info('Guessing target processor is a %s/%s (use --cpu to set)' % (
            options.arch, options.cpu))

    if options.with_sphinx is None:
        if have_program('sphinx-build'):
            logging.info('Found sphinx-build (use --without-sphinx to disable)')
            options.with_sphinx = True


# Mutates `options`
def canonicalize_options(options, info_os, info_arch):
    if options.os not in info_os:
        def find_canonical_os_name(os_name_variant):
            for (canonical_os_name, info) in info_os.items():
                if os_name_variant in info.aliases:
                    return canonical_os_name
            return os_name_variant # not found
        options.os = find_canonical_os_name(options.os)

    # canonical ARCH/CPU
    cpu_from_user = options.cpu
    results = canon_processor(info_arch, options.cpu)
    if results != None:
        (options.arch, options.cpu) = results
        logging.info('Canonicalized CPU target %s to %s/%s' % (
            cpu_from_user, options.arch, options.cpu))
    else:
        raise UserError('Unknown or unidentifiable processor "%s"' % (options.cpu))


# Checks user options for consistency
# This method DOES NOT change options on behalf of the user but explains
# why the given configuration does not work.
def validate_options(options, info_os, info_cc, available_module_policies):
    if options.gen_amalgamation:
        raise UserError("--gen-amalgamation was removed. Migrate to --amalgamation.")

    if options.via_amalgamation:
        raise UserError("--via-amalgamation was removed. Use --amalgamation instead.")

    if options.single_amalgamation_file and not options.amalgamation:
        raise UserError("--single-amalgamation-file requires --amalgamation.")

    if options.os == "java":
        raise UserError("Jython detected: need --os and --cpu to set target")

    if options.os not in info_os:
        raise UserError('Unknown OS "%s"; available options: %s' % (
            options.os, ' '.join(sorted(info_os.keys()))))

    if options.compiler not in info_cc:
        raise UserError('Unknown compiler "%s"; available options: %s' % (
            options.compiler, ' '.join(sorted(info_cc.keys()))))

    if options.module_policy and options.module_policy not in available_module_policies:
        raise UserError("Unknown module set %s" % options.module_policy)

    # Warnings

    if options.os == 'windows' and options.compiler == 'gcc':
        logging.warning('Detected GCC on Windows; use --os=cygwin or --os=mingw?')

def main_action_list_available_modules(info_modules):
    for modname in sorted(info_modules.keys()):
        print(modname)


def prepare_configure_build(info_modules, source_paths, options,
                            cc, cc_version, arch, osinfo, module_policy):
    loaded_module_names = ModulesChooser(info_modules, module_policy, arch, cc, cc_version, options).choose()
    using_mods = [info_modules[modname] for modname in loaded_module_names]

    build_config = BuildPaths(source_paths, options, using_mods)
    build_config.public_headers.append(os.path.join(build_config.build_dir, 'build.h'))

    template_vars = create_template_vars(source_paths, build_config, options, using_mods, cc, arch, osinfo)

    makefile_template = os.path.join(source_paths.makefile_dir, '%s.in' % (template_vars['makefile_style']))
    logging.debug('Using makefile template %s' % (makefile_template))

    return using_mods, build_config, template_vars, makefile_template


def main_action_configure_build(info_modules, source_paths, options,
                                cc, cc_version, arch, osinfo, module_policy):
    # pylint: disable=too-many-locals

    using_mods, build_config, template_vars, makefile_template = prepare_configure_build(
        info_modules, source_paths, options, cc, cc_version, arch, osinfo, module_policy)

    # Now we start writing to disk

    try:
        if options.clean_build_tree:
            robust_rmtree(build_config.build_dir)
    except OSError as e:
        if e.errno != errno.ENOENT:
            logging.error('Problem while removing build dir: %s' % (e))

    for build_dir in build_config.build_dirs():
        try:
            robust_makedirs(build_dir)
        except OSError as e:
            if e.errno != errno.EEXIST:
                logging.error('Error while creating "%s": %s' % (build_dir, e))

    def write_template(sink, template):
        with open(sink, 'w') as f:
            f.write(process_template(template, template_vars))

    def in_build_dir(p):
        return os.path.join(build_config.build_dir, p)
    def in_build_data(p):
        return os.path.join(source_paths.build_data_dir, p)

    write_template(in_build_dir('build.h'), in_build_data('buildh.in'))
    write_template(in_build_dir('botan.doxy'), in_build_data('botan.doxy.in'))

    if options.os != 'windows':
        write_template(in_build_dir(PKG_CONFIG_FILENAME), in_build_data('botan.pc.in'))

    if options.os == 'windows':
        write_template(in_build_dir('botan.iss'), in_build_data('innosetup.in'))

    link_method = choose_link_method(options)

    def link_headers(headers, visibility, directory):
        logging.debug('Linking %d %s header files in %s' % (len(headers), visibility, directory))

        for header_file in headers:
            try:
                portable_symlink(header_file, directory, link_method)
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise UserError('Error linking %s into %s: %s' % (header_file, directory, e))

    link_headers(build_config.public_headers, 'public',
                 build_config.botan_include_dir)

    link_headers(build_config.internal_headers, 'internal',
                 build_config.internal_include_dir)

    link_headers(build_config.external_headers, 'external',
                 build_config.external_include_dir)

    with open(os.path.join(build_config.build_dir, 'build_config.json'), 'w') as f:
        json.dump(template_vars, f, sort_keys=True, indent=2)

    if options.amalgamation:
        amalgamation_cpp_files = AmalgamationGenerator(build_config, using_mods, options).generate()
        build_config.lib_sources = sorted(amalgamation_cpp_files)
        template_vars.update(MakefileListsGenerator(build_config, options, using_mods, cc, arch, osinfo).generate())

    if options.with_bakefile:
        gen_bakefile(build_config, options, template_vars['link_to'])

    if options.with_cmake:
        CmakeGenerator(build_config, using_mods, cc, options, template_vars).generate()

    write_template(template_vars['makefile_path'], makefile_template)

    def release_date(datestamp):
        if datestamp == 0:
            return 'undated'
        return 'dated %d' % (datestamp)

    logging.info('Botan %s (VC %s) (%s %s) build setup is complete' % (
        Version.as_string(),
        Version.vc_rev(),
        Version.release_type,
        release_date(Version.datestamp)))

    if options.unsafe_fuzzer_mode:
        logging.warning("The fuzzer mode flag is labeled unsafe for a reason, this version is for testing only")


def main(argv):
    """
    Main driver
    """

    options = process_command_line(argv[1:])

    setup_logging(options)

    logging.info('%s invoked with options "%s"' % (argv[0], ' '.join(argv[1:])))
    logging.info('Platform: OS="%s" machine="%s" proc="%s"' % (
        platform.system(), platform.machine(), platform.processor()))

    source_paths = SourcePaths(os.path.dirname(argv[0]))

    info_modules = load_info_files(source_paths.lib_dir, 'Modules', "info.txt", ModuleInfo)
    info_arch = load_build_data_info_files(source_paths, 'CPU info', 'arch', ArchInfo)
    info_os = load_build_data_info_files(source_paths, 'OS info', 'os', OsInfo)
    info_cc = load_build_data_info_files(source_paths, 'compiler info', 'cc', CompilerInfo)
    info_module_policies = load_build_data_info_files(source_paths, 'module policy', 'policy', ModulePolicyInfo)

    for mod in info_modules.values():
        mod.cross_check(info_arch, info_os, info_cc)

    for policy in info_module_policies.values():
        policy.cross_check(info_modules)

    logging.debug('Known CPU names: ' + ' '.join(
        sorted(flatten([[ainfo.basename] + \
                        ainfo.aliases + \
                        [x for (x, _) in ainfo.all_submodels()]
                        for ainfo in info_arch.values()]))))

    set_defaults_for_unset_options(options, info_arch, info_cc)
    canonicalize_options(options, info_os, info_arch)
    validate_options(options, info_os, info_cc, info_module_policies)

    logging.info('Target is %s-%s-%s-%s' % (
        options.compiler, options.os, options.arch, options.cpu))

    cc = info_cc[options.compiler]
    arch = info_arch[options.arch]
    osinfo = info_os[options.os]
    module_policy = info_module_policies[options.module_policy] if options.module_policy else None

    cc_version = detect_compiler_version(cc, options.compiler_binary or cc.binary_name, osinfo.basename)

    if options.build_shared_lib and not osinfo.building_shared_supported:
        logging.warning('Shared libs not supported on %s, disabling shared lib support' % (osinfo.basename))
        options.build_shared_lib = False

    if options.list_modules:
        main_action_list_available_modules(info_modules)
        return 0
    else:
        main_action_configure_build(info_modules, source_paths, options, cc, cc_version, arch, osinfo, module_policy)
        return 0


if __name__ == '__main__':
    try:
        sys.exit(main(argv=sys.argv))
    except UserError as e:
        logging.debug(traceback.format_exc())
        logging.error(e)
    except Exception as e: # pylint: disable=broad-except
        # error() will stop script, so wrap all information into one call
        logging.error("""%s
An internal error occurred.

Don't panic, this is probably not your fault!

Please report the entire output at https://github.com/randombit/botan or email
to the mailing list https://lists.randombit.net/mailman/listinfo/botan-devel

You'll meet friendly people happy to help!""" % traceback.format_exc())

    sys.exit(0)
