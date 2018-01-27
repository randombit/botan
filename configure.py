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
import subprocess
import traceback
import logging
import time
import errno
import optparse # pylint: disable=deprecated-module

# An error caused by and to be fixed by the user, e.g. invalid command line argument
class UserError(Exception):
    pass


# An error caused by bugs in this script or when reading/parsing build data files
# Those are not expected to be fixed by the user of this script
class InternalError(Exception):
    pass


def flatten(l):
    return sum(l, [])

def normalize_source_path(source):
    """
    cmake needs this, and nothing else minds
    """
    return os.path.normpath(source).replace('\\', '/')

def parse_version_file(version_path):
    version_file = open(version_path)
    key_and_val = re.compile(r"([a-z_]+) = ([a-zA-Z0-9:\-\']+)")

    results = {}
    for line in version_file.readlines():
        if not line or line[0] == '#':
            continue
        match = key_and_val.match(line)
        if match:
            key = match.group(1)
            val = match.group(2)

            if val == 'None':
                val = None
            elif val.startswith("'") and val.endswith("'"):
                val = val[1:len(val)-1]
            else:
                val = int(val)

            results[key] = val
    return results

class Version(object):
    """
    Version information are all static members
    """
    data = {}

    @staticmethod
    def get_data():
        if not Version.data:
            root_dir = os.path.dirname(os.path.realpath(__file__))
            Version.data = parse_version_file(os.path.join(root_dir, 'version.txt'))
        return Version.data

    @staticmethod
    def major():
        return Version.get_data()["release_major"]

    @staticmethod
    def minor():
        return Version.get_data()["release_minor"]

    @staticmethod
    def patch():
        return Version.get_data()["release_patch"]

    @staticmethod
    def packed():
         # Used on Darwin for dylib versioning
        return Version.major() * 1000 + Version.minor()

    @staticmethod
    def so_rev():
        return Version.get_data()["release_so_abi_rev"]

    @staticmethod
    def release_type():
        return Version.get_data()["release_type"]

    @staticmethod
    def datestamp():
        return Version.get_data()["release_datestamp"]

    @staticmethod
    def as_string():
        return '%d.%d.%d' % (Version.major(), Version.minor(), Version.patch())

    @staticmethod
    def vc_rev():
        # Lazy load to ensure _local_repo_vc_revision() does not run before logger is set up
        if Version.get_data()["release_vc_rev"] is None:
            Version.data["release_vc_rev"] = Version._local_repo_vc_revision()
        return Version.get_data()["release_vc_rev"]

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
                return 'unknown'

            rev = str(stdout).strip()
            logging.debug('%s reported revision %s' % (cmdname, rev))

            return '%s:%s' % (cmdname, rev)
        except OSError as e:
            logging.debug('Error getting rev from %s - %s' % (cmdname, e.strerror))
            return 'unknown'



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
        self.configs_dir = os.path.join(self.src_dir, 'configs')
        self.lib_dir = os.path.join(self.src_dir, 'lib')
        self.python_dir = os.path.join(self.src_dir, 'python')
        self.scripts_dir = os.path.join(self.src_dir, 'scripts')

        # subdirs of src/
        self.sphinx_config_dir = os.path.join(self.configs_dir, 'sphinx')


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
            self.lib_sources = [normalize_source_path(s) for s in sorted(flatten([mod.sources() for mod in modules]))]

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

        self.cli_sources = [normalize_source_path(s) for s in find_sources_in(source_paths.src_dir, 'cli')]
        self.cli_headers = [normalize_source_path(s) for s in find_headers_in(source_paths.src_dir, 'cli')]
        self.test_sources = [normalize_source_path(s) for s in find_sources_in(source_paths.src_dir, 'tests')]

        if options.build_fuzzers:
            self.fuzzer_sources = list(find_sources_in(source_paths.src_dir, 'fuzzer'))
            self.fuzzer_output_dir = os.path.join(self.build_dir, 'fuzzer')
            self.fuzzobj_dir = os.path.join(self.build_dir, 'obj', 'fuzzer')
        else:
            self.fuzzer_sources = None
            self.fuzzer_output_dir = None
            self.fuzzobj_dir = None

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
        if self.fuzzer_output_dir:
            out += [self.fuzzobj_dir]
            out += [self.fuzzer_output_dir]
        return out

    def format_include_paths(self, cc, external_include):
        dash_i = cc.add_include_dir_option
        output = dash_i + self.include_dir
        if self.external_headers:
            output += ' ' + dash_i + self.external_include_dir
        if external_include:
            output += ' ' + dash_i + external_include
        return output

    def src_info(self, typ):
        if typ == 'lib':
            return (self.lib_sources, self.libobj_dir)
        elif typ == 'cli':
            return (self.cli_sources, self.cliobj_dir)
        elif typ == 'test':
            return (self.test_sources, self.testobj_dir)
        elif typ == 'fuzzer':
            return (self.fuzzer_sources, self.fuzzobj_dir)
        else:
            raise InternalError("Unknown src info type '%s'" % (typ))

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

    target_group.add_option('--cpu', help='set the target CPU architecture')

    target_group.add_option('--os', help='set the target operating system')

    target_group.add_option('--cc', dest='compiler', help='set the desired build compiler')

    target_group.add_option('--cc-min-version', dest='cc_min_version', default=None,
                            metavar='MAJOR.MINOR',
                            help='Set the minimal version of the target compiler. ' \
                                 'Use --cc-min-version=0.0 to support all compiler versions. ' \
                                 'Default is auto detection.')

    target_group.add_option('--cc-bin', dest='compiler_binary', metavar='BINARY',
                            help='set path to compiler binary')

    target_group.add_option('--cc-abi-flags', metavar='FLAG', default='',
                            help='set compiler ABI flags')

    target_group.add_option('--cxxflags', metavar='FLAG', default=None,
                            help='set compiler flags')

    target_group.add_option('--ldflags', metavar='FLAG',
                            help='set linker flags', default=None)

    target_group.add_option('--ar-command', dest='ar_command', metavar='AR', default=None,
                            help='set path to static archive creator')

    target_group.add_option('--with-endian', metavar='ORDER', default=None,
                            help='override byte order guess')

    target_group.add_option('--with-os-features', action='append', metavar='FEAT',
                            help='specify OS features to use')
    target_group.add_option('--without-os-features', action='append', metavar='FEAT',
                            help='specify OS features to disable')

    for isa_extn_name in ['SSE2', 'SSSE3', 'SSE4.1', 'SSE4.2', 'AVX2', 'AES-NI', 'SHA', 'AltiVec', 'NEON']:
        isa_extn = isa_extn_name.lower()

        target_group.add_option('--disable-%s' % (isa_extn),
                                help='disable %s intrinsics' % (isa_extn_name),
                                action='append_const',
                                const=isa_extn.replace('-', '').replace('.', ''),
                                dest='disable_intrinsics')

    build_group = optparse.OptionGroup(parser, 'Build options')

    build_group.add_option('--with-debug-info', action='store_true', default=False, dest='with_debug_info',
                           help='include debug symbols')

    build_group.add_option('--with-sanitizers', action='store_true', default=False, dest='with_sanitizers',
                           help='enable ASan/UBSan checks')

    build_group.add_option('--with-stack-protector', dest='with_stack_protector',
                           action='store_false', default=None, help=optparse.SUPPRESS_HELP)

    build_group.add_option('--without-stack-protector', dest='with_stack_protector',
                           action='store_false', help='disable stack smashing protections')

    build_group.add_option('--with-coverage', action='store_true', default=False, dest='with_coverage',
                           help='add coverage info and disable opts')

    build_group.add_option('--with-coverage-info', action='store_true', default=False, dest='with_coverage_info',
                           help='add coverage info')

    build_group.add_option('--enable-shared-library', dest='build_shared_lib',
                           action='store_true', default=None,
                           help=optparse.SUPPRESS_HELP)
    build_group.add_option('--disable-shared-library', dest='build_shared_lib',
                           action='store_false',
                           help='disable building shared library')

    build_group.add_option('--enable-static-library', dest='build_static_lib',
                           action='store_true', default=None,
                           help=optparse.SUPPRESS_HELP)
    build_group.add_option('--disable-static-library', dest='build_static_lib',
                           action='store_false',
                           help='disable building static library')

    build_group.add_option('--optimize-for-size', dest='optimize_for_size',
                           action='store_true', default=False,
                           help='optimize for code size')

    build_group.add_option('--no-optimizations', dest='no_optimizations',
                           action='store_true', default=False,
                           help='disable all optimizations (for debugging)')

    build_group.add_option('--debug-mode', action='store_true', default=False, dest='debug_mode',
                           help='enable debug info, disable optimizations')

    build_group.add_option('--amalgamation', dest='amalgamation',
                           default=False, action='store_true',
                           help='use amalgamation to build')

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

    link_methods = ['symlink', 'hardlink', 'copy']
    build_group.add_option('--link-method', default=None, metavar='METHOD',
                           choices=link_methods,
                           help='choose how links to include headers are created (%s)' % ', '.join(link_methods))

    build_group.add_option('--with-local-config',
                           dest='local_config', metavar='FILE',
                           help='include the contents of FILE into build.h')

    build_group.add_option('--distribution-info', metavar='STRING',
                           help='distribution specific version',
                           default='unspecified')

    build_group.add_option('--maintainer-mode', dest='maintainer_mode',
                           action='store_true', default=False,
                           help="Enable extra warnings")

    build_group.add_option('--with-python-versions', dest='python_version',
                           metavar='N.M',
                           default='%d.%d' % (sys.version_info[0], sys.version_info[1]),
                           help='where to install botan2.py (def %default)')

    build_group.add_option('--with-valgrind', help='use valgrind API',
                           dest='with_valgrind', action='store_true', default=False)

    # Cmake and bakefile options are hidden as they should not be used by end users
    build_group.add_option('--with-cmake', action='store_true',
                           default=False, help=optparse.SUPPRESS_HELP)

    build_group.add_option('--with-bakefile', action='store_true',
                           default=False, help=optparse.SUPPRESS_HELP)

    build_group.add_option('--unsafe-fuzzer-mode', action='store_true', default=False,
                           help='Disable essential checks for testing')

    build_group.add_option('--build-fuzzers', dest='build_fuzzers',
                           metavar='TYPE', default=None,
                           help='Build fuzzers (afl, libfuzzer, klee, test)')

    build_group.add_option('--with-fuzzer-lib', metavar='LIB', default=None, dest='fuzzer_lib',
                           help='additionally link in LIB')

    docs_group = optparse.OptionGroup(parser, 'Documentation Options')

    docs_group.add_option('--with-documentation', action='store_true',
                          help=optparse.SUPPRESS_HELP)

    docs_group.add_option('--without-documentation', action='store_false',
                          default=True, dest='with_documentation',
                          help='Skip building/installing documentation')

    docs_group.add_option('--with-sphinx', action='store_true',
                          default=None, help='Use Sphinx')

    docs_group.add_option('--without-sphinx', action='store_false',
                          dest='with_sphinx', help=optparse.SUPPRESS_HELP)

    docs_group.add_option('--with-pdf', action='store_true',
                          default=False, help='Use Sphinx to generate PDF doc')

    docs_group.add_option('--without-pdf', action='store_false',
                          dest='with_pdf', help=optparse.SUPPRESS_HELP)

    docs_group.add_option('--with-rst2man', action='store_true',
                          default=None, help='Use rst2man to generate man page')

    docs_group.add_option('--without-rst2man', action='store_false',
                          dest='with_rst2man', help=optparse.SUPPRESS_HELP)

    docs_group.add_option('--with-doxygen', action='store_true',
                          default=False, help='Use Doxygen')

    docs_group.add_option('--without-doxygen', action='store_false',
                          dest='with_doxygen', help=optparse.SUPPRESS_HELP)

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
    mods_group.add_option('--no-autoload', action='store_true', default=False,
                          help=optparse.SUPPRESS_HELP)
    mods_group.add_option('--minimized-build', action='store_true', dest='no_autoload',
                          help='minimize build')

    # Should be derived from info.txt but this runs too early
    third_party = ['bearssl', 'boost', 'bzip2', 'lzma', 'openssl', 'sqlite3', 'zlib', 'tpm']

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
    install_group.add_option('--library-suffix', metavar='SUFFIX', default='',
                             help='append string to library names')

    install_group.add_option('--prefix', metavar='DIR',
                             help='set the install prefix')
    install_group.add_option('--docdir', metavar='DIR',
                             help='set the doc install dir')
    install_group.add_option('--bindir', metavar='DIR',
                             help='set the binary install dir')
    install_group.add_option('--libdir', metavar='DIR',
                             help='set the library install dir')
    install_group.add_option('--mandir', metavar='DIR',
                             help='set the install dir for man pages')
    install_group.add_option('--includedir', metavar='DIR',
                             help='set the include file install dir')

    info_group = optparse.OptionGroup(parser, 'Informational')

    info_group.add_option('--list-modules', dest='list_modules',
                          action='store_true',
                          help='list available modules and exit')

    info_group.add_option('--list-os-features', dest='list_os_features',
                          action='store_true',
                          help='list available OS features and exit')

    parser.add_option_group(target_group)
    parser.add_option_group(build_group)
    parser.add_option_group(docs_group)
    parser.add_option_group(mods_group)
    parser.add_option_group(install_group)
    parser.add_option_group(info_group)

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

    if options.with_endian not in [None, 'little', 'big']:
        raise UserError('Bad value to --with-endian "%s"' % (options.with_endian))

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

    # Take some values from environment, if not set on command line

    if options.ar_command is None:
        options.ar_command = os.getenv('AR')
    if options.compiler_binary is None:
        options.compiler_binary = os.getenv('CXX')
    if options.cxxflags is None:
        options.cxxflags = os.getenv('CXXFLAGS')
    if options.ldflags is None:
        options.ldflags = os.getenv('LDFLAGS')

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
        raise InternalError("Lex dictionary has invalid format (input not divisible by 3): %s" % as_list)

    result = {}
    for key, sep, value in [as_list[3*i:3*i+3] for i in range(0, len(as_list)//3)]:
        if sep != '->':
            raise InternalError("Lex dictionary has invalid format")
        result[key] = value
    return result


def lex_me_harder(infofile, allowed_groups, allowed_maps, name_val_pairs):
    """
    Generic lexer function for info.txt and src/build-data files
    """
    out = LexResult()

    # Format as a nameable Python variable
    def py_var(group):
        return group.replace(':', '_')

    lexer = shlex.shlex(open(infofile), infofile, posix=True)
    lexer.wordchars += '|:.<>/,-!+*' # handle various funky chars in info.txt

    groups = allowed_groups + allowed_maps
    for group in groups:
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

            if group not in groups:
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

    for group in allowed_maps:
        out.__dict__[group] = parse_lex_dict(out.__dict__[group])

    return out

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
            ['header:internal', 'header:public', 'header:external', 'requires',
             'os_features', 'arch', 'cc', 'libs', 'frameworks', 'comment', 'warning'
            ],
            ['defines'],
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
        self._defines = lex.defines
        self._validate_defines_content(self._defines)
        self.frameworks = convert_lib_list(lex.frameworks)
        self.libs = convert_lib_list(lex.libs)
        self.load_on = lex.load_on
        self.need_isa = lex.need_isa.split(',') if lex.need_isa else []
        self.os_features = lex.os_features
        self.requires = lex.requires
        self.warning = ' '.join(lex.warning) if lex.warning else None

        # Modify members
        self.source = [normalize_source_path(os.path.join(self.lives_in, s)) for s in self.source]
        self.header_internal = [os.path.join(self.lives_in, s) for s in self.header_internal]
        self.header_public = [os.path.join(self.lives_in, s) for s in self.header_public]
        self.header_external = [os.path.join(self.lives_in, s) for s in self.header_external]

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

    def cross_check(self, arch_info, cc_info, all_os_features):

        for feat in set(flatten([o.split(',') for o in self.os_features])):
            if feat not in all_os_features:
                logging.error("Module %s uses an OS feature (%s) which no OS supports", self.infofile, feat)

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
        return [(key + ' ' + value) for key, value in self._defines.items()]

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

    def compatible_os(self, os_data, options):
        if not self.os_features:
            return True

        def has_all(needed, provided):
            for n in needed:
                if n not in provided:
                    return False
            return True

        provided_features = os_data.enabled_features(options)

        for feature_set in self.os_features:
            if has_all(feature_set.split(','), provided_features):
                return True

        return False

    def compatible_compiler(self, ccinfo, cc_min_version, arch):
        # Check if this compiler supports the flags we need
        def supported_isa_flags(ccinfo, arch):
            for isa in self.need_isa:
                if ccinfo.isa_flags_for(isa, arch) is None:
                    return False
            return True

        # Check if module gives explicit compiler dependencies
        def supported_compiler(ccinfo, cc_min_version):
            if self.cc == []:
                # no compiler restriction
                return True

            if ccinfo.basename in self.cc:
                # compiler is supported, independent of version
                return True

            # Maybe a versioned compiler dep
            for cc in self.cc:
                try:
                    name, version = cc.split(":")
                    if name == ccinfo.basename:
                        min_cc_version = [int(v) for v in version.split('.')]
                        cur_cc_version = [int(v) for v in cc_min_version.split('.')]
                        # With lists of ints, this does what we want
                        return cur_cc_version >= min_cc_version
                except ValueError:
                    # No version part specified
                    pass

            return False # compiler not listed

        return supported_isa_flags(ccinfo, arch) and supported_compiler(ccinfo, cc_min_version)

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
            [],
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
            ['aliases', 'isa_extensions'],
            [],
            {
                'endian': None,
                'family': None,
                'wordsize': 32
            })

        self.aliases = lex.aliases
        self.endian = lex.endian
        self.family = lex.family
        self.isa_extensions = lex.isa_extensions
        self.wordsize = int(lex.wordsize)

        alphanumeric = re.compile('^[a-z0-9]+$')
        for isa in self.isa_extensions:
            if alphanumeric.match(isa) is None:
                logging.error('Invalid name for ISA extension "%s"', isa)

    def supported_isa_extensions(self, cc, options):
        isas = []

        for isa in self.isa_extensions:
            if isa not in options.disable_intrinsics:
                if cc.isa_flags_for(isa, self.basename) is not None:
                    isas.append(isa)

        return sorted(isas)


class CompilerInfo(InfoObject): # pylint: disable=too-many-instance-attributes
    def __init__(self, infofile):
        super(CompilerInfo, self).__init__(infofile)
        lex = lex_me_harder(
            infofile,
            [],
            ['cpu_flags', 'so_link_commands', 'binary_link_commands', 'mach_abi_linking', 'isa_flags'],
            {
                'binary_name': None,
                'linker_name': None,
                'macro_name': None,
                'output_to_object': '-o ',
                'output_to_exe': '-o ',
                'add_include_dir_option': '-I',
                'add_lib_dir_option': '-L',
                'add_lib_option': '-l',
                'add_framework_option': '-framework ',
                'preproc_flags': '-E',
                'compile_flags': '-c',
                'debug_info_flags': '-g',
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
                'ar_command': '',
                'ar_options': '',
                'ar_output_to': '',
            })

        self.add_framework_option = lex.add_framework_option
        self.add_include_dir_option = lex.add_include_dir_option
        self.add_lib_dir_option = lex.add_lib_dir_option
        self.add_lib_option = lex.add_lib_option
        self.ar_command = lex.ar_command
        self.ar_options = lex.ar_options
        self.ar_output_to = lex.ar_output_to
        self.binary_link_commands = lex.binary_link_commands
        self.binary_name = lex.binary_name
        self.cpu_flags = lex.cpu_flags
        self.compile_flags = lex.compile_flags
        self.coverage_flags = lex.coverage_flags
        self.debug_info_flags = lex.debug_info_flags
        self.isa_flags = lex.isa_flags
        self.lang_flags = lex.lang_flags
        self.linker_name = lex.linker_name
        self.mach_abi_linking = lex.mach_abi_linking
        self.macro_name = lex.macro_name
        self.maintainer_warning_flags = lex.maintainer_warning_flags
        self.optimization_flags = lex.optimization_flags
        self.output_to_exe = lex.output_to_exe
        self.output_to_object = lex.output_to_object
        self.preproc_flags = lex.preproc_flags
        self.sanitizer_flags = lex.sanitizer_flags
        self.shared_flags = lex.shared_flags
        self.size_optimization_flags = lex.size_optimization_flags
        self.so_link_commands = lex.so_link_commands
        self.stack_protector_flags = lex.stack_protector_flags
        self.visibility_attribute = lex.visibility_attribute
        self.visibility_build_flags = lex.visibility_build_flags
        self.warning_flags = lex.warning_flags

    def isa_flags_for(self, isa, arch):
        if isa in self.isa_flags:
            return self.isa_flags[isa]
        arch_isa = '%s:%s' % (arch, isa)
        if arch_isa in self.isa_flags:
            return self.isa_flags[arch_isa]
        return None

    def get_isa_specific_flags(self, isas, arch):
        flags = set()

        def simd32_impl():
            for simd_isa in ['sse2', 'altivec', 'neon']:
                if simd_isa in arch.isa_extensions and self.isa_flags_for(simd_isa, arch.basename):
                    return simd_isa
            return None

        for isa in isas:

            if isa == 'simd':
                isa = simd32_impl()

                if isa is None:
                    continue

            flagset = self.isa_flags_for(isa, arch.basename)
            if flagset is None:
                raise UserError('Compiler %s does not support %s' % (self.basename, isa))
            flags.add(flagset)

        return " ".join(sorted(flags))

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

    def mach_abi_link_flags(self, options, with_debug_info=None):
        """
        Return the machine specific ABI flags
        """

        if with_debug_info is None:
            with_debug_info = options.with_debug_info

        def mach_abi_groups():
            if with_debug_info and 'all-debug' in self.mach_abi_linking:
                yield 'all-debug'
            elif 'all' in self.mach_abi_linking:
                yield 'all'

            for all_except in [s for s in self.mach_abi_linking.keys() if s.startswith('all!')]:
                exceptions = all_except[4:].split(',')
                if options.os not in exceptions and options.arch not in exceptions:
                    yield all_except

            yield options.os
            yield options.cpu

        abi_link = list()
        for what in mach_abi_groups():
            flag = self.mach_abi_linking.get(what)
            if flag != None and flag != '' and flag not in abi_link:
                abi_link.append(flag)

        if options.with_stack_protector and self.stack_protector_flags != '':
            abi_link.append(self.stack_protector_flags)

        if options.with_coverage_info:
            if self.coverage_flags == '':
                raise UserError('No coverage handling for %s' % (self.basename))
            abi_link.append(self.coverage_flags)

        if options.with_sanitizers:
            if self.sanitizer_flags == '':
                raise UserError('No sanitizer handling for %s' % (self.basename))
            abi_link.append(self.sanitizer_flags)

        if options.with_openmp:
            if 'openmp' not in self.mach_abi_linking:
                raise UserError('No support for OpenMP for %s' % (self.basename))
            abi_link.append(self.mach_abi_linking['openmp'])

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

    def cc_lang_flags(self):
        return self.lang_flags

    def cc_compile_flags(self, options, with_debug_info=None, enable_optimizations=None):
        def gen_flags(with_debug_info, enable_optimizations):
            if with_debug_info is None:
                with_debug_info = options.with_debug_info
            if enable_optimizations is None:
                enable_optimizations = not options.no_optimizations

            if with_debug_info:
                yield self.debug_info_flags

            if enable_optimizations:
                if options.optimize_for_size:
                    if self.size_optimization_flags != '':
                        yield self.size_optimization_flags
                    else:
                        logging.warning("No size optimization flags set for current compiler")
                        yield self.optimization_flags
                else:
                    yield self.optimization_flags

            if options.arch in self.cpu_flags:
                yield self.cpu_flags[options.arch]

        return (' '.join(gen_flags(with_debug_info, enable_optimizations))).strip()

    @staticmethod
    def _so_link_search(osname, debug_info):
        so_link_typ = [osname, 'default']
        if debug_info:
            so_link_typ = [l + '-debug' for l in so_link_typ] + so_link_typ
        return so_link_typ

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

class OsInfo(InfoObject): # pylint: disable=too-many-instance-attributes
    def __init__(self, infofile):
        super(OsInfo, self).__init__(infofile)
        lex = lex_me_harder(
            infofile,
            ['aliases', 'target_features'],
            [],
            {
                'program_suffix': '',
                'obj_suffix': 'o',
                'soname_suffix': '',
                'soname_pattern_patch': '',
                'soname_pattern_abi': '',
                'soname_pattern_base': '',
                'static_suffix': 'a',
                'ar_command': 'ar',
                'ar_options': '',
                'ar_output_to': '',
                'install_root': '/usr/local',
                'header_dir': 'include',
                'bin_dir': 'bin',
                'lib_dir': 'lib',
                'doc_dir': 'share/doc',
                'man_dir': 'share/man',
                'use_stack_protector': 'true',
                'so_post_link_command': '',
                'cli_exe_name': 'botan',
                'lib_prefix': 'lib',
                'library_name': 'botan{suffix}-{major}',
            })

        if lex.ar_command == 'ar' and lex.ar_options == '':
            lex.ar_options = 'crs'

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
                self.soname_pattern_base = "libbotan{lib_suffix}-{version_major}.%s" % (lex.soname_suffix)
                self.soname_pattern_abi = self.soname_pattern_base + ".{abi_rev}"
                self.soname_pattern_patch = self.soname_pattern_abi + ".{version_minor}.{version_patch}"
            else:
                # Could not calculate soname_pattern_*
                # This happens for OSs without shared library support (e.g. nacl, mingw, includeos, cygwin)
                self.soname_pattern_base = None
                self.soname_pattern_abi = None
                self.soname_pattern_patch = None

        self._aliases = lex.aliases
        self.ar_command = lex.ar_command
        self.ar_options = lex.ar_options
        self.bin_dir = lex.bin_dir
        self.cli_exe_name = lex.cli_exe_name
        self.doc_dir = lex.doc_dir
        self.header_dir = lex.header_dir
        self.install_root = lex.install_root
        self.lib_dir = lex.lib_dir
        self.lib_prefix = lex.lib_prefix
        self.library_name = lex.library_name
        self.man_dir = lex.man_dir
        self.obj_suffix = lex.obj_suffix
        self.program_suffix = lex.program_suffix
        self.so_post_link_command = lex.so_post_link_command
        self.static_suffix = lex.static_suffix
        self.target_features = lex.target_features
        self.use_stack_protector = (lex.use_stack_protector == "true")

    def matches_name(self, nm):
        if nm in self._aliases:
            return True

        for alias in self._aliases:
            if re.match(alias, nm):
                return True
        return False

    def building_shared_supported(self):
        return self.soname_pattern_base != None

    def enabled_features(self, options):
        feats = []
        for feat in self.target_features:
            if feat not in options.without_os_features:
                feats.append(feat)
        for feat in options.with_os_features:
            if feat not in self.target_features:
                feats.append(feat)

        return sorted(feats)

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
            return ainfo.basename

    return None

def system_cpu_info():

    cpu_info = []

    if platform.machine() != '':
        cpu_info.append(platform.machine())

    if platform.processor() != '':
        cpu_info.append(platform.processor())

    if 'uname' in os.__dict__:
        cpu_info.append(os.uname()[4])

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
    # pylint: disable=too-many-branches,too-many-statements

    """
    Perform template substitution

    The template language supports (un-nested) conditionals.
    """
    class SimpleTemplate(object):

        def __init__(self, vals):
            self.vals = vals
            self.value_pattern = re.compile(r'%{([a-z][a-z_0-9\|]+)}')
            self.cond_pattern = re.compile('%{(if|unless) ([a-z][a-z_0-9]+)}')
            self.for_pattern = re.compile('(.*)%{for ([a-z][a-z_0-9]+)}')
            self.join_pattern = re.compile('(.*)%{join ([a-z][a-z_0-9]+)}')

        def substitute(self, template):
            # pylint: disable=too-many-locals
            def insert_value(match):
                v = match.group(1)
                if v in self.vals:
                    return str(self.vals.get(v))
                if v.endswith('|upper'):
                    v = v.replace('|upper', '')
                    if v in self.vals:
                        return str(self.vals.get(v)).upper()

                raise KeyError(v)

            lines = template.splitlines()

            output = ""
            idx = 0

            while idx < len(lines):
                cond_match = self.cond_pattern.match(lines[idx])
                join_match = self.join_pattern.match(lines[idx])
                for_match = self.for_pattern.match(lines[idx])

                if cond_match:
                    cond_type = cond_match.group(1)
                    cond_var = cond_match.group(2)

                    include_cond = False

                    if cond_type == 'if' and cond_var in self.vals and self.vals.get(cond_var):
                        include_cond = True
                    elif cond_type == 'unless' and (cond_var not in self.vals or (not self.vals.get(cond_var))):
                        include_cond = True

                    idx += 1
                    while idx < len(lines):
                        if lines[idx] == '%{endif}':
                            break
                        if include_cond:
                            output += lines[idx] + "\n"
                        idx += 1
                elif join_match:
                    join_var = join_match.group(2)
                    join_str = ' '
                    join_line = '%%{join %s}' % (join_var)
                    output += lines[idx].replace(join_line, join_str.join(self.vals[join_var])) + "\n"
                elif for_match:
                    for_prefix = for_match.group(1)
                    output += for_prefix
                    for_var = for_match.group(2)

                    if for_var not in self.vals:
                        raise InternalError("Unknown for loop iteration variable '%s'" % (for_var))

                    var = self.vals[for_var]
                    if not isinstance(var, list):
                        raise InternalError("For loop iteration variable '%s' is not a list" % (for_var))
                    idx += 1

                    for_body = ""
                    while idx < len(lines):
                        if lines[idx] == '%{endfor}':
                            break
                        for_body += lines[idx] + "\n"
                        idx += 1

                    for v in var:
                        if isinstance(v, dict):
                            for_val = for_body
                            for ik, iv in v.items():
                                for_val = for_val.replace('%{' + ik + '}', iv)
                            output += for_val + "\n"
                        else:
                            output += for_body.replace('%{i}', v).replace('%{i|upper}', v.upper())
                    output += "\n"
                else:
                    output += lines[idx] + "\n"
                idx += 1

            return self.value_pattern.sub(insert_value, output) + '\n'

    try:
        return SimpleTemplate(variables).substitute(read_textfile(template_file))
    except KeyError as e:
        logging.error('Unbound var %s in template %s' % (e, template_file))
    except Exception as e: # pylint: disable=broad-except
        logging.error('Exception %s during template processing file %s' % (e, template_file))

def yield_objectfile_list(sources, obj_dir, obj_suffix):
    obj_suffix = '.' + obj_suffix

    for src in sources:
        (directory, filename) = os.path.split(os.path.normpath(src))
        parts = directory.split(os.sep)

        if 'src' in parts:
            parts = parts[parts.index('src')+2:]
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

        name = name.replace('.cpp', obj_suffix)
        yield os.path.join(obj_dir, name)

def generate_build_info(build_paths, modules, cc, arch, osinfo):
    # pylint: disable=too-many-locals

    # first create a map of src_file->owning module

    module_that_owns = {}

    for mod in modules:
        for src in mod.sources():
            module_that_owns[src] = mod

    def _isa_specific_flags(src):
        if os.path.basename(src) == 'test_simd.cpp':
            return cc.get_isa_specific_flags(['simd'], arch)

        if src in module_that_owns:
            module = module_that_owns[src]
            isas = module.need_isa
            if 'simd' in module.dependencies():
                isas.append('simd')

            return cc.get_isa_specific_flags(isas, arch)

        if src.startswith('botan_all_'):
            isas = src.replace('botan_all_', '').replace('.cpp', '').split('_')
            return cc.get_isa_specific_flags(isas, arch)

        return ''

    def _build_info(sources, objects, target_type):
        output = []
        for (obj_file, src) in zip(objects, sources):
            info = {
                'src': src,
                'obj': obj_file,
                'isa_flags': _isa_specific_flags(src)
                }

            if target_type == 'fuzzer':
                fuzz_basename = os.path.basename(obj_file).replace('.' + osinfo.obj_suffix, '')
                info['exe'] = os.path.join(build_paths.fuzzer_output_dir, fuzz_basename)

            output.append(info)

        return output

    out = {}

    targets = ['lib', 'cli', 'test', 'fuzzer']

    out['isa_build_info'] = []

    fuzzer_bin = []
    for t in targets:
        src_list, src_dir = build_paths.src_info(t)

        src_key = '%s_srcs' % (t)
        obj_key = '%s_objs' % (t)
        build_key = '%s_build_info' % (t)

        objects = []
        build_info = []

        if src_list is not None:
            src_list.sort()
            objects = list(yield_objectfile_list(src_list, src_dir, osinfo.obj_suffix))
            build_info = _build_info(src_list, objects, t)

            for b in build_info:
                if b['isa_flags'] != '':
                    out['isa_build_info'].append(b)

            if t == 'fuzzer':
                fuzzer_bin = [b['exe'] for b in build_info]

        out[src_key] = src_list if src_list else []
        out[obj_key] = objects
        out[build_key] = build_info

    out['fuzzer_bin'] = ' '.join(fuzzer_bin)
    out['cli_headers'] = build_paths.cli_headers

    return out

def create_template_vars(source_paths, build_paths, options, modules, cc, arch, osinfo):
    #pylint: disable=too-many-locals,too-many-branches,too-many-statements

    """
    Create the template variables needed to process the makefile, build.h, etc
    """

    def external_link_cmd():
        return (' ' + cc.add_lib_dir_option + options.with_external_libdir) if options.with_external_libdir else ''

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

    def cmake_escape(s):
        return s.replace('(', '\\(').replace(')', '\\)')

    def ar_command():
        if options.ar_command:
            return options.ar_command

        if cc.ar_command:
            if cc.ar_command == cc.binary_name:
                return options.compiler_binary or cc.binary_name
            else:
                return cc.ar_command

        return osinfo.ar_command

    def choose_endian(arch_info, options):
        if options.with_endian != None:
            return options.with_endian

        if options.cpu.endswith('eb') or options.cpu.endswith('be'):
            return 'big'
        elif options.cpu.endswith('el') or options.cpu.endswith('le'):
            return 'little'

        return arch_info.endian

    build_dir = options.with_build_dir or os.path.curdir
    program_suffix = options.program_suffix or osinfo.program_suffix

    variables = {
        'version_major':  Version.major(),
        'version_minor':  Version.minor(),
        'version_patch':  Version.patch(),
        'version_vc_rev': Version.vc_rev(),
        'abi_rev':        Version.so_rev(),

        'version':        Version.as_string(),
        'release_type':   Version.release_type(),
        'version_datestamp': Version.datestamp(),

        'distribution_info': options.distribution_info,

        'darwin_so_compat_ver': '%s.%s.0' % (Version.packed(), Version.so_rev()),
        'darwin_so_current_ver': '%s.%s.%s' % (Version.packed(), Version.so_rev(), Version.patch()),

        'base_dir': source_paths.base_dir,
        'src_dir': source_paths.src_dir,
        'doc_dir': source_paths.doc_dir,
        'scripts_dir': source_paths.scripts_dir,
        'python_dir': source_paths.python_dir,

        'cli_exe_name': osinfo.cli_exe_name + program_suffix,
        'cli_exe': os.path.join(build_dir, osinfo.cli_exe_name + program_suffix),
        'test_exe': os.path.join(build_dir, 'botan-test' + program_suffix),

        'lib_prefix': osinfo.lib_prefix,
        'static_suffix': osinfo.static_suffix,
        'lib_suffix': options.library_suffix,
        'libname': osinfo.library_name.format(major=Version.major(),
                                              minor=Version.minor(),
                                              suffix=options.library_suffix),

        'command_line': configure_command_line(),
        'local_config': read_textfile(options.local_config),

        'program_suffix': program_suffix,

        'prefix': options.prefix or osinfo.install_root,
        'bindir': options.bindir or osinfo.bin_dir,
        'libdir': options.libdir or osinfo.lib_dir,
        'mandir': options.mandir or osinfo.man_dir,
        'includedir': options.includedir or osinfo.header_dir,
        'docdir': options.docdir or osinfo.doc_dir,

        'with_documentation': options.with_documentation,
        'with_sphinx': options.with_sphinx,
        'with_pdf': options.with_pdf,
        'with_rst2man': options.with_rst2man,
        'sphinx_config_dir': source_paths.sphinx_config_dir,
        'with_doxygen': options.with_doxygen,

        'out_dir': options.with_build_dir or os.path.curdir,
        'build_dir': build_paths.build_dir,

        'doc_stamp_file': os.path.join(build_paths.build_dir, 'doc.stamp'),
        'makefile_path': os.path.join(build_paths.build_dir, '..', 'Makefile'),

        'build_static_lib': options.build_static_lib,
        'build_fuzzers': options.build_fuzzers,

        'build_shared_lib': options.build_shared_lib,
        'build_unix_shared_lib': options.build_shared_lib and options.compiler != 'msvc',
        'build_msvc_shared_lib': options.build_shared_lib and options.compiler == 'msvc',

        'libobj_dir': build_paths.libobj_dir,
        'cliobj_dir': build_paths.cliobj_dir,
        'testobj_dir': build_paths.testobj_dir,
        'fuzzobj_dir': build_paths.fuzzobj_dir,

        'fuzzer_output_dir': build_paths.fuzzer_output_dir if build_paths.fuzzer_output_dir else '',
        'doc_output_dir': build_paths.doc_output_dir,
        'doc_output_dir_manual': build_paths.doc_output_dir_manual,
        'doc_output_dir_doxygen': build_paths.doc_output_dir_doxygen,

        'os': options.os,
        'arch': options.arch,
        'cpu_family': arch.family,
        'endian': choose_endian(arch, options),
        'cpu_is_64bit': arch.wordsize == 64,

        'bakefile_arch': 'x86' if options.arch == 'x86_32' else 'x86_64',

        'innosetup_arch': innosetup_arch(options.os, options.arch),

        'mp_bits': choose_mp_bits(),

        'python_exe': sys.executable,
        'python_version': options.python_version,

        'cxx': (options.compiler_binary or cc.binary_name),
        'cxx_abi_flags': cc.mach_abi_link_flags(options),
        'linker': cc.linker_name or '$(CXX)',
        'make_supports_phony': cc.basename != 'msvc',

        'cc_compile_opt_flags': cc.cc_compile_flags(options, False, True),
        'cc_compile_debug_flags': cc.cc_compile_flags(options, True, False),
        'cxx_abi_opt_flags': cc.mach_abi_link_flags(options, False),
        'cxx_abi_debug_flags': cc.mach_abi_link_flags(options, True),

        'dash_o': cc.output_to_object,
        'dash_c': cc.compile_flags,

        'cc_lang_flags': cc.cc_lang_flags(),
        'cc_compile_flags': options.cxxflags or cc.cc_compile_flags(options),
        'ldflags': options.ldflags or '',
        'cc_warning_flags': cc.cc_warning_flags(options),
        'output_to_exe': cc.output_to_exe,
        'cc_macro': cc.macro_name,

        'shared_flags': cc.gen_shared_flags(options),
        'cmake_shared_flags': cmake_escape(cc.gen_shared_flags(options)),
        'visibility_attribute': cc.gen_visibility_attribute(options),

        'lib_link_cmd': cc.so_link_command_for(osinfo.basename, options) + external_link_cmd(),
        'exe_link_cmd': cc.binary_link_command_for(osinfo.basename, options) + external_link_cmd(),
        'post_link_cmd': '',

        'ar_command': ar_command(),
        'ar_options': cc.ar_options or osinfo.ar_options,
        'ar_output_to': cc.ar_output_to,

        'link_to': ' '.join(
            [cc.add_lib_option + lib for lib in link_to('libs')] +
            [cc.add_framework_option + fw for fw in link_to('frameworks')]
        ),

        'cmake_link_to': ' '.join(
            [lib for lib in link_to('libs')] +
            [('"' + cc.add_framework_option + fw + '"') for fw in link_to('frameworks')]
        ),

        'fuzzer_lib': (cc.add_lib_option + options.fuzzer_lib) if options.fuzzer_lib else '',
        'libs_used': [lib.replace('.lib', '') for lib in link_to('libs')],

        'include_paths': build_paths.format_include_paths(cc, options.with_external_includedir),
        'module_defines': sorted(flatten([m.defines() for m in modules])),

        'os_features': osinfo.enabled_features(options),
        'os_name': osinfo.basename,
        'cpu_features': arch.supported_isa_extensions(cc, options),

        'fuzzer_mode': options.unsafe_fuzzer_mode,
        'fuzzer_type': options.build_fuzzers.upper() if options.build_fuzzers else '',

        'with_valgrind': options.with_valgrind,
        'with_openmp': options.with_openmp,

        'mod_list': sorted([m.basename for m in modules])
        }

    if options.os != 'windows':
        variables['botan_pkgconfig'] = os.path.join(build_paths.build_dir, 'botan-%d.pc' % (Version.major()))

    # The name is always set because Windows build needs it
    variables['static_lib_name'] = '%s%s.%s' % (variables['lib_prefix'], variables['libname'],
                                                variables['static_suffix'])

    if options.build_shared_lib:
        if osinfo.soname_pattern_base != None:
            variables['soname_base'] = osinfo.soname_pattern_base.format(**variables)
            variables['shared_lib_name'] = variables['soname_base']

        if osinfo.soname_pattern_abi != None:
            variables['soname_abi'] = osinfo.soname_pattern_abi.format(**variables)
            variables['shared_lib_name'] = variables['soname_abi']

        if osinfo.soname_pattern_patch != None:
            variables['soname_patch'] = osinfo.soname_pattern_patch.format(**variables)

        variables['lib_link_cmd'] = variables['lib_link_cmd'].format(**variables)
        variables['post_link_cmd'] = osinfo.so_post_link_command.format(**variables) if options.build_shared_lib else ''

    lib_targets = []
    if options.build_static_lib:
        lib_targets.append('static_lib_name')
    if options.build_shared_lib:
        lib_targets.append('shared_lib_name')

    variables['library_targets'] = ' '.join([os.path.join(build_dir, variables[t]) for t in lib_targets])

    if options.os == 'llvm' or options.compiler == 'msvc':
        # llvm-link and msvc require just naming the file directly
        variables['link_to_botan'] = os.path.join(build_dir, variables['static_lib_name'])
    else:
        variables['link_to_botan'] = '%s%s %s%s' % (cc.add_lib_dir_option, build_dir,
                                                    cc.add_lib_option, variables['libname'])

    return variables

class ModulesChooser(object):
    """
    Determine which modules to load based on options, target, etc
    """

    def __init__(self, modules, module_policy, archinfo, osinfo, ccinfo, cc_min_version, options):
        self._modules = modules
        self._module_policy = module_policy
        self._archinfo = archinfo
        self._osinfo = osinfo
        self._ccinfo = ccinfo
        self._cc_min_version = cc_min_version
        self._options = options

        self._maybe_dep = set()
        self._to_load = set()
        # string to set mapping with reasons as key and modules as value
        self._not_using_because = collections.defaultdict(set)

        ModulesChooser._validate_dependencies_exist(self._modules)
        ModulesChooser._validate_user_selection(
            self._modules, self._options.enabled_modules, self._options.disabled_modules)

    def _check_usable(self, module, modname):
        if not module.compatible_os(self._osinfo, self._options):
            self._not_using_because['incompatible OS'].add(modname)
            return False
        elif not module.compatible_compiler(self._ccinfo, self._cc_min_version, self._archinfo.basename):
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
            loaded_modules = copy.copy(loaded_modules)

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
    Choose the link method based on system availability and user request
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
    # All include types may have trailing comment like e.g. '#include <vector> // IWYU pragma: export'
    _any_include = re.compile(r'#include <(.*)>')
    _botan_include = re.compile(r'#include <botan/(.*)>')

    # Only matches at the beginning of the line. By convention, this means that the include
    # is not wrapped by condition macros
    _unconditional_any_include = re.compile(r'^#include <(.*)>')
    _unconditional_std_include = re.compile(r'^#include <([^/\.]+|stddef.h)>')

    @staticmethod
    def is_any_include(cpp_source_line):
        match = AmalgamationHelper._any_include.search(cpp_source_line)
        if match:
            return match.group(1)
        else:
            return None

    @staticmethod
    def is_botan_include(cpp_source_line):
        match = AmalgamationHelper._botan_include.search(cpp_source_line)
        if match:
            return match.group(1)
        else:
            return None

    @staticmethod
    def is_unconditional_any_include(cpp_source_line):
        match = AmalgamationHelper._unconditional_any_include.search(cpp_source_line)
        if match:
            return match.group(1)
        else:
            return None

    @staticmethod
    def is_unconditional_std_include(cpp_source_line):
        match = AmalgamationHelper._unconditional_std_include.search(cpp_source_line)
        if match:
            return match.group(1)
        else:
            return None


class AmalgamationHeader(object):
    def __init__(self, input_filepaths):

        self.included_already = set()
        self.all_std_includes = set()

        encoding_kwords = {}
        if sys.version_info[0] == 3:
            encoding_kwords['encoding'] = 'utf8'

        self.file_contents = {}
        for filepath in sorted(input_filepaths):
            try:
                with open(filepath, **encoding_kwords) as f:
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

        if name == 'botan.h':
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
                std_header = AmalgamationHelper.is_unconditional_std_include(line)

                if std_header:
                    self.all_std_includes.add(std_header)
                else:
                    yield line

    @staticmethod
    def write_banner(fd):
        fd.write("""/*
* Botan %s Amalgamation
* (C) 1999-2018 The Botan Authors
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

    _header_guard_pattern = re.compile('^#define BOTAN_.*_H_$')

    @staticmethod
    def strip_header_goop(header_name, header_lines):
        lines = copy.copy(header_lines) # defensive copy

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
        pub_header_amalag.write_to_file(header_name, "BOTAN_AMALGAMATION_H_")

        internal_headers = AmalgamationHeader(self._build_paths.internal_headers)
        header_int_name = '%s_internal.h' % (AmalgamationGenerator.filename_prefix)
        logging.info('Writing amalgamation header to %s' % (header_int_name))
        internal_headers.write_to_file(header_int_name, "BOTAN_AMALGAMATION_INTERNAL_H_")

        header_files = [header_name, header_int_name]
        included_in_headers = pub_header_amalag.all_std_includes | internal_headers.all_std_includes
        return header_files, included_in_headers

    def _generate_sources(self, amalgamation_headers, included_in_headers): #pylint: disable=too-many-locals,too-many-branches
        encoding_kwords = {}
        if sys.version_info[0] == 3:
            encoding_kwords['encoding'] = 'utf8'

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
            amalgamation_files[target] = open(filepath, 'w', **encoding_kwords)

        for target, f in amalgamation_files.items():
            AmalgamationHeader.write_banner(f)
            f.write('\n')
            for header in amalgamation_headers:
                f.write('#include "%s"\n' % (header))
            f.write('\n')

            for isa in self._isas_for_target(target):
                f.write('#if defined(__GNUG__) && !defined(__clang__)\n')
                f.write('#pragma GCC target ("%s")\n' % (isa))
                f.write('#endif\n')

        # target to include header map
        unconditional_headers_written = {}
        for target, _ in amalgamation_sources.items():
            unconditional_headers_written[target] = included_in_headers.copy()

        for mod in sorted(self._modules, key=lambda module: module.basename):
            tgt = self._target_for_module(mod)
            for src in sorted(mod.source):
                with open(src, 'r', **encoding_kwords) as f:
                    for line in f:
                        if AmalgamationHelper.is_botan_include(line):
                            # Botan headers are inlined in amalgamation headers
                            continue

                        if AmalgamationHelper.is_any_include(line) in unconditional_headers_written[tgt]:
                            # This include (conditional or unconditional) was unconditionally added before
                            continue

                        amalgamation_files[tgt].write(line)
                        unconditional_header = AmalgamationHelper.is_unconditional_any_include(line)
                        if unconditional_header:
                            unconditional_headers_written[tgt].add(unconditional_header)

        for f in amalgamation_files.values():
            f.close()

        return set(amalgamation_sources.values())

    def generate(self):
        amalgamation_headers, included_in_headers = self._generate_headers()
        amalgamation_sources = self._generate_sources(amalgamation_headers, included_in_headers)
        return (sorted(amalgamation_sources), sorted(amalgamation_headers))


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

    def deduce_compiler_type_from_cc_bin(cc_bin):
        if cc_bin.find('clang') != -1 or cc_bin in ['emcc', 'em++']:
            return 'clang'
        if cc_bin.find('-g++') != -1:
            return 'gcc'
        return None

    if options.compiler is None and options.compiler_binary != None:
        options.compiler = deduce_compiler_type_from_cc_bin(options.compiler_binary)

    if options.compiler is None:
        if options.os == 'windows':
            if have_program('g++') and not have_program('cl'):
                options.compiler = 'gcc'
            else:
                options.compiler = 'msvc'
        elif options.os in ['darwin', 'freebsd', 'openbsd', 'ios']:
            # Prefer Clang on these systems
            if have_program('clang++'):
                options.compiler = 'clang'
            else:
                options.compiler = 'gcc'
                if options.os == 'openbsd':
                    # The assembler shipping with OpenBSD 5.9 does not support avx2
                    del info_cc['gcc'].isa_flags['avx2']
        else:
            options.compiler = 'gcc'

        if options.compiler is None:
            logging.error('Could not guess which compiler to use, use --cc or CXX to set')
        else:
            logging.info('Guessing to use compiler %s (use --cc or CXX to set)' % (options.compiler))

    if options.cpu is None:
        options.cpu = options.arch = guess_processor(info_arch)
        logging.info('Guessing target processor is a %s (use --cpu to set)' % (options.arch))

    if options.with_documentation is True:
        if options.with_sphinx is None and have_program('sphinx-build'):
            logging.info('Found sphinx-build (use --without-sphinx to disable)')
            options.with_sphinx = True
        if options.with_rst2man is None and have_program('rst2man'):
            logging.info('Found rst2man (use --without-rst2man to disable)')
            options.with_rst2man = True


# Mutates `options`
def canonicalize_options(options, info_os, info_arch):
    # pylint: disable=too-many-branches
    if options.os not in info_os:
        def find_canonical_os_name(os_name_variant):
            for (canonical_os_name, os_info) in info_os.items():
                if os_info.matches_name(os_name_variant):
                    return canonical_os_name
            return os_name_variant # not found
        options.os = find_canonical_os_name(options.os)

    # canonical ARCH/CPU
    options.arch = canon_processor(info_arch, options.cpu)
    if options.arch is None:
        raise UserError('Unknown or unidentifiable processor "%s"' % (options.cpu))

    if options.cpu != options.arch:
        logging.info('Canonicalized CPU target %s to %s', options.cpu, options.arch)

    shared_libs_supported = options.os in info_os and info_os[options.os].building_shared_supported()

    if not shared_libs_supported:
        if options.build_shared_lib is not None:
            logging.warning('Shared libs not supported on %s, disabling shared lib support' % (options.os))
            options.build_shared_lib = False
        else:
            logging.info('Shared libs not supported on %s, disabling shared lib support' % (options.os))

    if options.os == 'windows' and options.build_shared_lib is None and options.build_static_lib is None:
        options.build_shared_lib = True

    if options.with_stack_protector is None:
        if options.os in info_os:
            options.with_stack_protector = info_os[options.os].use_stack_protector

    if options.build_shared_lib is None:
        if options.os == 'windows' and options.build_static_lib:
            pass
        else:
            options.build_shared_lib = shared_libs_supported

    if options.build_static_lib is None:
        if options.os == 'windows' and options.build_shared_lib:
            pass
        else:
            options.build_static_lib = True

    # Set default fuzzing lib
    if options.build_fuzzers == 'libfuzzer' and options.fuzzer_lib is None:
        options.fuzzer_lib = 'Fuzzer'

# Checks user options for consistency
# This method DOES NOT change options on behalf of the user but explains
# why the given configuration does not work.
def validate_options(options, info_os, info_cc, available_module_policies):
    # pylint: disable=too-many-branches

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

    if options.cc_min_version is not None and not re.match(r'^[0-9]+\.[0-9]+$', options.cc_min_version):
        raise UserError("--cc-min-version must have the format MAJOR.MINOR")

    if options.module_policy and options.module_policy not in available_module_policies:
        raise UserError("Unknown module set %s" % options.module_policy)

    if options.os == 'llvm' or options.cpu == 'llvm':
        if options.compiler != 'clang':
            raise UserError('LLVM target requires using Clang')
        if options.os != options.cpu:
            raise UserError('LLVM target requires both CPU and OS be set to llvm')

    if options.build_fuzzers != None:
        if options.build_fuzzers not in ['libfuzzer', 'afl', 'klee', 'test']:
            raise UserError('Bad value to --build-fuzzers')

        if options.build_fuzzers == 'klee' and options.os != 'llvm':
            raise UserError('Building for KLEE requires targeting LLVM')

    if options.build_static_lib is False and options.build_shared_lib is False:
        raise UserError('With both --disable-static-library and --disable-shared-library, nothing to do')

    if options.os == 'windows' and options.build_static_lib is True and options.build_shared_lib is True:
        raise UserError('On Windows only one of static lib and DLL can be selected')

    if options.with_documentation is False:
        if options.with_doxygen:
            raise UserError('Using --with-doxygen plus --without-documentation makes no sense')
        if options.with_sphinx:
            raise UserError('Using --with-sphinx plus --without-documentation makes no sense')
        if options.with_pdf:
            raise UserError('Using --with-pdf plus --without-documentation makes no sense')

    if options.with_pdf and not options.with_sphinx:
        raise UserError('Option --with-pdf requires --with-sphinx')

    if options.with_bakefile:
        if options.os != 'windows' or options.compiler != 'msvc' or options.build_shared_lib is False:
            raise UserError("Building via bakefile is only supported for MSVC DLL build")

        if options.arch not in ['x86_64', 'x86_32']:
            raise UserError("Bakefile only supports x86 targets")

        # Warnings
    if options.os == 'windows' and options.compiler != 'msvc':
        logging.warning('The windows target is oriented towards MSVC; maybe you want cygwin or mingw')

def calculate_cc_min_version(options, ccinfo, source_paths):
    version_patterns = {
        'msvc': r'^ *MSVC ([0-9]{2})([0-9]{2})$',
        'gcc': r'^ *GCC ([0-9]+) ([0-9]+)$',
        'clang': r'^ *CLANG ([0-9]+) ([0-9]+)$',
        'xlc': r'^ *XLC (0x[0-9a-fA-F]{2})([0-9a-fA-F]{2})$'
    }

    if ccinfo.basename not in version_patterns:
        logging.info("No compiler version detection available for %s" % (ccinfo.basename))
        return "0.0"

    detect_version_source = os.path.join(source_paths.build_data_dir, "detect_version.cpp")

    cc_bin = options.compiler_binary or ccinfo.binary_name

    cmd = cc_bin.split(' ') + ccinfo.preproc_flags.split(' ') + [detect_version_source]

    try:
        logging.debug("Running '%s'", ' '.join(cmd))
        stdout, stderr = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True).communicate()
        cc_output = stdout + "\n" + stderr
    except OSError as e:
        logging.warning('Could not execute %s for version check: %s' % (cmd, e))
        return "0.0"

    def cleanup_output(output):
        return ('\n'.join([l for l in output.splitlines() if l.startswith('#') is False])).strip()

    match = re.search(version_patterns[ccinfo.basename], cc_output, flags=re.MULTILINE)
    if match is None:
        logging.warning("Tried to get %s version, but output '%s' does not match expected version format" % (
            ccinfo.basename, cleanup_output(cc_output)))
        return "0.0"

    cc_version = "%d.%d" % (int(match.group(1), 0), int(match.group(2), 0))
    logging.info('Auto-detected compiler version %s' % (cc_version))
    return cc_version

def do_io_for_build(cc, arch, osinfo, using_mods, build_paths, source_paths, template_vars, options):
    # pylint: disable=too-many-locals,too-many-branches

    try:
        robust_rmtree(build_paths.build_dir)
    except OSError as e:
        if e.errno != errno.ENOENT:
            logging.error('Problem while removing build dir: %s' % (e))

    for build_dir in build_paths.build_dirs():
        try:
            robust_makedirs(build_dir)
        except OSError as e:
            if e.errno != errno.EEXIST:
                logging.error('Error while creating "%s": %s' % (build_dir, e))

    def write_template(sink, template):
        with open(sink, 'w') as f:
            f.write(process_template(template, template_vars))

    def in_build_dir(p):
        return os.path.join(build_paths.build_dir, p)
    def in_build_data(p):
        return os.path.join(source_paths.build_data_dir, p)

    write_template(in_build_dir('build.h'), in_build_data('buildh.in'))
    write_template(in_build_dir('botan.doxy'), in_build_data('botan.doxy.in'))

    if 'botan_pkgconfig' in template_vars:
        write_template(template_vars['botan_pkgconfig'], in_build_data('botan.pc.in'))

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

    link_headers(build_paths.public_headers, 'public',
                 build_paths.botan_include_dir)

    link_headers(build_paths.internal_headers, 'internal',
                 build_paths.internal_include_dir)

    link_headers(build_paths.external_headers, 'external',
                 build_paths.external_include_dir)

    if options.amalgamation:
        (amalg_cpp_files, amalg_headers) = AmalgamationGenerator(build_paths, using_mods, options).generate()
        build_paths.lib_sources = amalg_cpp_files
        template_vars['generated_files'] = ' '.join(amalg_cpp_files + amalg_headers)

    template_vars.update(generate_build_info(build_paths, using_mods, cc, arch, osinfo))

    with open(os.path.join(build_paths.build_dir, 'build_config.json'), 'w') as f:
        json.dump(template_vars, f, sort_keys=True, indent=2)

    if options.with_cmake:
        logging.warning("CMake build is only for development: use make for production builds")
        cmake_template = os.path.join(source_paths.build_data_dir, 'cmake.in')
        write_template('CMakeLists.txt', cmake_template)
    elif options.with_bakefile:
        logging.warning("Bakefile build is only for development: use make for production builds")
        bakefile_template = os.path.join(source_paths.build_data_dir, 'bakefile.in')
        write_template('botan.bkl', bakefile_template)
    else:
        makefile_template = os.path.join(source_paths.build_data_dir, 'makefile.in')
        write_template(template_vars['makefile_path'], makefile_template)

    if options.with_rst2man:
        rst2man_file = os.path.join(build_paths.build_dir, 'botan.rst')
        cli_doc = os.path.join(source_paths.doc_dir, 'manual/cli.rst')

        cli_doc_contents = open(cli_doc).readlines()

        while cli_doc_contents[0] != "\n":
            cli_doc_contents.pop(0)

        rst2man_header = """
botan
=============================

:Subtitle: Botan command line util
:Manual section: 1

        """.strip()

        with open(rst2man_file, 'w') as f:
            f.write(rst2man_header)
            f.write("\n")
            for line in cli_doc_contents:
                f.write(line)

    logging.info('Botan %s (revision %s) (%s %s) build setup is complete' % (
        Version.as_string(),
        Version.vc_rev(),
        Version.release_type(),
        ('dated %d' % (Version.datestamp())) if Version.datestamp() != 0 else 'undated'))

    if options.unsafe_fuzzer_mode:
        logging.warning("The fuzzer mode flag is labeled unsafe for a reason, this version is for testing only")

def list_os_features(all_os_features, info_os):
    for feat in all_os_features:
        os_with_feat = [o for o in info_os.keys() if feat in info_os[o].target_features]
        os_without_feat = [o for o in info_os.keys() if feat not in info_os[o].target_features]

        if len(os_with_feat) < len(os_without_feat):
            print("%s: %s" % (feat, ' '.join(sorted(os_with_feat))))
        else:
            print("%s: %s" % (feat, '!' + ' !'.join(sorted(os_without_feat))))
    return 0


def main(argv):
    """
    Main driver
    """

    # pylint: disable=too-many-locals

    options = process_command_line(argv[1:])

    setup_logging(options)

    source_paths = SourcePaths(os.path.dirname(argv[0]))

    info_modules = load_info_files(source_paths.lib_dir, 'Modules', "info.txt", ModuleInfo)

    if options.list_modules:
        for mod in sorted(info_modules.keys()):
            print(mod)
        return 0

    info_arch = load_build_data_info_files(source_paths, 'CPU info', 'arch', ArchInfo)
    info_os = load_build_data_info_files(source_paths, 'OS info', 'os', OsInfo)
    info_cc = load_build_data_info_files(source_paths, 'compiler info', 'cc', CompilerInfo)
    info_module_policies = load_build_data_info_files(source_paths, 'module policy', 'policy', ModulePolicyInfo)

    all_os_features = sorted(set(flatten([o.target_features for o in info_os.values()])))

    if options.list_os_features:
        return list_os_features(all_os_features, info_os)

    for mod in info_modules.values():
        mod.cross_check(info_arch, info_cc, all_os_features)

    for policy in info_module_policies.values():
        policy.cross_check(info_modules)

    logging.info('%s invoked with options "%s"' % (argv[0], ' '.join(argv[1:])))
    logging.debug('Platform running configuration (autodetected): OS="%s" machine="%s" proc="%s"' % (
        platform.system(), platform.machine(), platform.processor()))

    logging.debug('Known CPU names: ' + ' '.join(
        sorted(flatten([[ainfo.basename] + ainfo.aliases for ainfo in info_arch.values()]))))

    set_defaults_for_unset_options(options, info_arch, info_cc)
    canonicalize_options(options, info_os, info_arch)
    validate_options(options, info_os, info_cc, info_module_policies)

    cc = info_cc[options.compiler]
    arch = info_arch[options.arch]
    osinfo = info_os[options.os]
    module_policy = info_module_policies[options.module_policy] if options.module_policy else None
    cc_min_version = options.cc_min_version or calculate_cc_min_version(options, cc, source_paths)

    logging.info('Target is %s:%s-%s-%s' % (
        options.compiler, cc_min_version, options.os, options.arch))

    chooser = ModulesChooser(info_modules, module_policy, arch, osinfo, cc, cc_min_version, options)
    loaded_module_names = chooser.choose()
    using_mods = [info_modules[modname] for modname in loaded_module_names]

    build_paths = BuildPaths(source_paths, options, using_mods)
    build_paths.public_headers.append(os.path.join(build_paths.build_dir, 'build.h'))

    template_vars = create_template_vars(source_paths, build_paths, options, using_mods, cc, arch, osinfo)

    # Now we start writing to disk
    do_io_for_build(cc, arch, osinfo, using_mods, build_paths, source_paths, template_vars, options)

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
