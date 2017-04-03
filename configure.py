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

class ConfigureError(Exception):
    pass

def flatten(l):
    return sum(l, [])

def chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i:i+n]


def get_vc_revision():

    def get_vc_revision_impl(cmdlist):
        try:
            cmdname = cmdlist[0]

            vc = subprocess.Popen(cmdlist,
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

    vc_command = ['git', 'rev-parse', 'HEAD']
    rev = get_vc_revision_impl(vc_command)
    if rev is not None:
        return rev
    else:
        return 'unknown'


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
        # Lazy load to ensure get_vc_revision() does not run before logger is set up
        if Version._vc_rev is None:
            Version._vc_rev = botan_version.release_vc_rev if botan_version.release_vc_rev else get_vc_revision()
        return Version._vc_rev


class BuildPaths(object): # pylint: disable=too-many-instance-attributes
    """
    Constructor
    """
    def __init__(self, options, modules):
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

        self.doc_dir = os.path.join(options.base_dir, 'doc')
        self.src_dir = os.path.join(options.base_dir, 'src')

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

        self.cli_sources = list(find_sources_in(self.src_dir, 'cli'))
        self.cli_headers = list(find_headers_in(self.src_dir, 'cli'))
        self.test_sources = list(find_sources_in(self.src_dir, 'tests'))

        self.python_dir = os.path.join(options.src_dir, 'python')

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


def make_build_doc_commands(build_paths, options):
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
        build_manual_command(os.path.join(build_paths.doc_dir, 'manual'), build_paths.doc_output_dir_manual)
    ]
    if options.with_doxygen:
        cmds += ['doxygen %s%sbotan.doxy' % (build_paths.build_dir, os.sep)]
    return '\n'.join(['\t' + cmd for cmd in cmds])


def process_command_line(args): # pylint: disable=too-many-locals
    """
    Handle command line options
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

    target_group.add_option('--chost', help=optparse.SUPPRESS_HELP)

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

    build_group.add_option('--with-visibility', action='store_true',
                           default=None, help=optparse.SUPPRESS_HELP)

    build_group.add_option('--without-visibility', action='store_false',
                           dest='with_visibility', help=optparse.SUPPRESS_HELP)

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
                          help='list available modules')
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
        raise ConfigureError('Unhandled option(s): ' + ' '.join(args))
    if options.with_endian != None and \
       options.with_endian not in ['little', 'big']:
        raise ConfigureError('Bad value to --with-endian "%s"' % (
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


class LexerError(ConfigureError):
    def __init__(self, msg, lexfile, line):
        super(LexerError, self).__init__(msg)
        self.msg = msg
        self.lexfile = lexfile
        self.line = line

    def __str__(self):
        return '%s at %s:%d' % (self.msg, self.lexfile, self.line)


def parse_lex_dict(as_list):
    if len(as_list) % 3 != 0:
        raise ConfigureError("Lex dictionary has invalid format")

    result = {}
    for key, sep, value in [as_list[3*i:3*i+3] for i in range(0, len(as_list)//3)]:
        if sep != '->':
            raise ConfigureError("Lex dictionary has invalid format")
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
                raise ConfigureError("Bad <libs> in module %s" % (self.basename))
            result = {}

            for sep in l[1::3]:
                if sep != '->':
                    raise ConfigureError("Bad <libs> in module %s" % (self.basename))

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
            if len(intersection) > 0:
                logging.error('Headers %s marked both %s and %s' % (' '.join(intersection), type_a, type_b))

        intersect_check('public', self.header_public, 'internal', self.header_internal)
        intersect_check('public', self.header_public, 'external', self.header_external)
        intersect_check('external', self.header_external, 'internal', self.header_internal)

    @staticmethod
    def _validate_defines_content(defines):
        for key, value in defines.items():
            if not re.match('^[0-9A-Za-z_]{3,30}$', key):
                raise ConfigureError('Module defines key has invalid format: "%s"' % key)
            if not re.match('^[0-9]{8}$', value):
                raise ConfigureError('Module defines value has invalid format: "%s"' % value)

    def cross_check(self, arch_info, os_info, cc_info):
        for supp_os in self.os:
            if supp_os not in os_info:
                raise ConfigureError('Module %s mentions unknown OS %s' % (self.infofile, supp_os))
        for supp_cc in self.cc:
            if supp_cc not in cc_info:
                raise ConfigureError('Module %s mentions unknown compiler %s' % (self.infofile, supp_cc))
        for supp_arch in self.arch:
            if supp_arch not in arch_info:
                raise ConfigureError('Module %s mentions unknown arch %s' % (self.infofile, supp_arch))

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

    def compatible_compiler(self, cc, arch):
        if self.cc != [] and cc.basename not in self.cc:
            return False

        for isa in self.need_isa:
            if cc.isa_flags_for(isa, arch) is None:
                return False

        return True

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

    def __cmp__(self, other):
        if self.basename < other.basename:
            return -1
        if self.basename == other.basename:
            return 0
        return 1


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

class CompilerInfo(InfoObject):
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
        while lex.mach_opt:
            proc = lex.mach_opt.pop(0)
            if lex.mach_opt.pop(0) != '->':
                raise ConfigureError('Parsing err in %s mach_opt' % self.basename)

            flags = lex.mach_opt.pop(0)
            regex = ''
            if lex.mach_opt and (len(lex.mach_opt) == 1 or lex.mach_opt[1] != '->'):
                regex = lex.mach_opt.pop(0)
            self.mach_opt_flags[proc] = (flags, regex)

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
                if options.with_visibility:
                    yield self.visibility_build_flags

        return ' '.join(list(flag_builder()))

    def gen_visibility_attribute(self, options):
        if options.build_shared_lib and options.with_visibility:
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
                raise ConfigureError('No coverage handling for %s' % (self.basename))
            abi_link.append(self.coverage_flags)

        if options.with_sanitizers:
            if self.sanitizer_flags == '':
                raise ConfigureError('No sanitizer handling for %s' % (self.basename))
            abi_link.append(self.sanitizer_flags)

        if options.with_openmp:
            if 'openmp' not in self.mach_abi_linking:
                raise ConfigureError('No support for OpenMP for %s' % (self.basename))
            abi_link.append(self.mach_abi_linking['openmp'])

        if options.with_cilkplus:
            if 'cilkplus' not in self.mach_abi_linking:
                raise ConfigureError('No support for Cilk Plus for %s' % (self.basename))
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

            def submodel_fixup(flags, tup):
                return tup[0].replace('SUBMODEL', flags.replace(tup[1], ''))

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

        raise ConfigureError(
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


class OsInfo(InfoObject):
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
                raise ConfigureError("Invalid soname_patterns in %s" % (self.infofile))
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

    raise ConfigureError('Could not determine target CPU; set with --cpu')

def slurp_file(filename):
    """
    Read a whole file into memory as a string
    """

    # type: (object) -> object
    if filename is None:
        return ''
    return ''.join(open(filename).readlines())

def process_template(template_file, variables):
    """
    Perform template substitution
    """

    class PercentSignTemplate(string.Template):
        delimiter = '%'

    try:
        template = PercentSignTemplate(slurp_file(template_file))
        return template.substitute(variables)
    except KeyError as e:
        raise ConfigureError('Unbound var %s in template %s' % (e, template_file))
    except Exception as e:
        raise ConfigureError('Exception %s in template %s' % (e, template_file))

def makefile_list(items):
    items = list(items) # force evaluation so we can slice it
    return (' '*16).join([item + ' \\\n' for item in items[:-1]] + [items[-1]])

def gen_bakefile(build_config, options, external_libs):

    def bakefile_sources(file, sources):
        for src in sources:
            (directory, filename) = os.path.split(os.path.normpath(src))
            directory = directory.replace('\\', '/')
            _, directory = directory.split('src/', 1)
            file.write('\tsources { src/%s/%s } \n' % (directory, filename))

    def bakefile_cli_headers(file, headers):
        for header in headers:
            (directory, filename) = os.path.split(os.path.normpath(header))
            directory = directory.replace('\\', '/')
            _, directory = directory.split('src/', 1)
            file.write('\theaders { src/%s/%s } \n' % (directory, filename))

    def bakefile_test_sources(file, sources):
        for src in sources:
            (_, filename) = os.path.split(os.path.normpath(src))
            file.write('\tsources { src/tests/%s } \n' %filename)

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

def gen_makefile_lists(var, build_config, options, modules, cc, arch, osinfo):
    def get_isa_specific_flags(cc, isas):
        flags = []
        for isa in isas:
            flag = cc.isa_flags_for(isa, arch.basename)
            if flag is None:
                raise ConfigureError('Compiler %s does not support %s' % (cc.basename, isa))
            flags.append(flag)
        return '' if len(flags) == 0 else (' ' + ' '.join(sorted(list(flags))))

    def isa_specific_flags(cc, src):

        def simd_dependencies():

            for simd32_impl in ['sse2', 'altivec', 'neon']:
                if simd32_impl in arch.isa_extensions and cc.isa_flags_for(simd32_impl, arch.basename) is not None:
                    return [simd32_impl]

            # default scalar
            return []

        if os.path.basename(src) == 'test_simd.cpp':
            isas = list(simd_dependencies())
            return get_isa_specific_flags(cc, isas)

        for mod in modules:
            if src in mod.sources():
                isas = mod.need_isa
                if 'simd' in mod.dependencies():
                    isas += list(simd_dependencies())

                return get_isa_specific_flags(cc, isas)

        if src.startswith('botan_all_'):
            isa = src.replace('botan_all_', '').replace('.cpp', '').split('_')
            return get_isa_specific_flags(cc, isa)

        return ''

    def objectfile_list(sources, obj_dir):
        for src in sources:
            (directory, file) = os.path.split(os.path.normpath(src))

            parts = directory.split(os.sep)
            if 'src' in parts:
                parts = parts[parts.index('src')+2:]
            elif 'tests' in parts:
                parts = parts[parts.index('tests')+2:]
            elif 'cli' in parts:
                parts = parts[parts.index('cli'):]
            elif file.find('botan_all') != -1:
                parts = []
            else:
                raise ConfigureError("Unexpected file '%s/%s'" % (directory, file))

            if parts != []:

                # Handle src/X/X.cpp -> X.o
                if file == parts[-1] + '.cpp':
                    name = '_'.join(parts) + '.cpp'
                else:
                    name = '_'.join(parts) + '_' + file

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
                name = file

            for src_suffix in ['.cpp', '.S']:
                name = name.replace(src_suffix, '.' + osinfo.obj_suffix)

            yield os.path.join(obj_dir, name)

    def build_commands(sources, obj_dir, flags):
        """
        Form snippets of makefile for building each source file
        """

        includes = cc.add_include_dir_option + build_config.include_dir
        if build_config.external_headers:
            includes += ' ' + cc.add_include_dir_option + build_config.external_include_dir
        if options.with_external_includedir:
            includes += ' ' + cc.add_include_dir_option + options.with_external_includedir

        for (obj_file, src) in zip(objectfile_list(sources, obj_dir), sources):
            yield '%s: %s\n\t$(CXX)%s $(%s_FLAGS) %s %s %s %s$@\n' % (
                obj_file, src,
                isa_specific_flags(cc, src),
                flags,
                includes,
                cc.compile_flags,
                src,
                cc.output_to_option)

    for t in ['lib', 'cli', 'test']:
        obj_key = '%s_objs' % (t)
        src_list, src_dir = build_config.src_info(t)
        src_list.sort()
        var[obj_key] = makefile_list(objectfile_list(src_list, src_dir))
        build_key = '%s_build_cmds' % (t)
        var[build_key] = '\n'.join(build_commands(src_list, src_dir, t.upper()))

def create_template_vars(build_config, options, modules, cc, arch, osinfo):
    """
    Create the template variables needed to process the makefile, build.h, etc
    """

    def make_cpp_macros(macros):
        return '\n'.join(['#define BOTAN_' + macro for macro in macros])

    def external_link_cmd():
        return ' ' + cc.add_lib_dir_option + options.with_external_libdir if options.with_external_libdir else ''

    def link_to():
        """
        Figure out what external libraries are needed based on selected modules
        """

        return do_link_to('libs')

    def link_to_frameworks():
        """
        Figure out what external frameworks are needed based on selected modules
        """

        return do_link_to('frameworks')

    def do_link_to(module_member_name):
        libs = set()
        for module in modules:
            for (osname, link_to) in getattr(module, module_member_name).items():
                if osname == 'all' or osname == osinfo.basename:
                    libs |= set(link_to)
                else:
                    match = re.match('^all!(.*)', osname)
                    if match is not None:
                        exceptions = match.group(1).split(',')
                        if osinfo.basename not in exceptions:
                            libs |= set(link_to)
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

    def read_pem(filename):
        lines = [line.rstrip() for line in open(filename)]
        for ndx, _ in enumerate(lines):
            lines[ndx] = ''.join(('\"', lines[ndx], '\" \\', '\n'))
        return ''.join(lines)

    def misc_config():
        opts = list()
        if options.house_curve:
            p = options.house_curve.split(",")
            if len(p) < 4:
                logging.error('Too few parameters to --in-house-curve')
            # make sure TLS curve id is in reserved for private use range (0xFE00..0xFEFF)
            curve_id = int(p[3], 16)
            if curve_id < 0xfe00 or curve_id > 0xfeff:
                logging.error('TLS curve ID not in reserved range (see RFC 4492)')
            opts.append('HOUSE_ECC_CURVE_NAME \"' + p[1] + '\"')
            opts.append('HOUSE_ECC_CURVE_OID \"' + p[2] + '\"')
            opts.append('HOUSE_ECC_CURVE_PEM ' + read_pem(filename=p[0]))
            opts.append('HOUSE_ECC_CURVE_TLS_ID ' + hex(curve_id))

        return opts

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

        'base_dir': options.base_dir,
        'src_dir': options.src_dir,
        'doc_dir': build_config.doc_dir,

        'command_line': ' '.join(sys.argv),
        'local_config': slurp_file(options.local_config),
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

        'scripts_dir': os.path.join(build_config.src_dir, 'scripts'),

        'build_shared_lib': options.build_shared_lib,

        'libobj_dir': build_config.libobj_dir,
        'cliobj_dir': build_config.cliobj_dir,
        'testobj_dir': build_config.testobj_dir,

        'doc_output_dir': build_config.doc_output_dir,

        'build_doc_commands': make_build_doc_commands(build_config, options),

        'python_dir': build_config.python_dir,
        'sphinx_config_dir': os.path.join(options.build_data, 'sphinx'),

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
            [cc.add_lib_option + lib for lib in link_to()] +
            [cc.add_framework_option + fw for fw in link_to_frameworks()]
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

        'soname_base': osinfo.soname_pattern_base.format(
            version_major=Version.major,
            version_minor=Version.minor,
            version_patch=Version.patch,
            abi_rev=Version.so_rev),
        'soname_abi': osinfo.soname_pattern_abi.format(
            version_major=Version.major,
            version_minor=Version.minor,
            version_patch=Version.patch,
            abi_rev=Version.so_rev),
        'soname_patch': osinfo.soname_pattern_patch.format(
            version_major=Version.major,
            version_minor=Version.minor,
            version_patch=Version.patch,
            abi_rev=Version.so_rev),

        'mod_list': '\n'.join(sorted([m.basename for m in modules])),

        'python_version': options.python_version,
        'with_sphinx': options.with_sphinx,

        'misc_config': make_cpp_macros(misc_config())
        }

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

    gen_makefile_lists(variables, build_config, options, modules, cc, arch, osinfo)

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

    variables["header_in"] = process_template(os.path.join(options.makefile_dir, 'header.in'), variables)

    if variables["makefile_style"] == "gmake":
        variables["gmake_commands_in"] = process_template(os.path.join(options.makefile_dir, 'gmake_commands.in'),
                                                          variables)
        variables["gmake_dso_in"] = process_template(os.path.join(options.makefile_dir, 'gmake_dso.in'), variables) \
                                    if options.build_shared_lib else ''
        variables["gmake_coverage_in"] = process_template(os.path.join(options.makefile_dir, 'gmake_coverage.in'),
                                                          variables) \
                                         if options.with_coverage_info else ''

    return variables

def choose_modules_to_use(modules, module_policy, archinfo, ccinfo, options):
    """
    Determine which modules to load based on options, target, etc
    """

    for mod in modules.values():
        mod.dependencies_exist(modules)

    to_load = []
    maybe_dep = []
    not_using_because = {}

    def cannot_use_because(mod, reason):
        not_using_because.setdefault(reason, []).append(mod)

    def check_usable(module, modname, options):
        if not module.compatible_os(options.os):
            cannot_use_because(modname, 'incompatible OS')
            return False
        elif not module.compatible_compiler(ccinfo, archinfo.basename):
            cannot_use_because(modname, 'incompatible compiler')
            return False
        elif not module.compatible_cpu(archinfo, options):
            cannot_use_because(modname, 'incompatible CPU')
            return False
        return True

    for modname in options.enabled_modules:
        if modname not in modules:
            logging.error("Module not found: %s" % (modname))

    for modname in options.disabled_modules:
        if modname not in modules:
            logging.warning("Disabled module not found: %s" % (modname))

    for (modname, module) in modules.items():
        usable = check_usable(module, modname, options)

        if module_policy is not None:

            if modname in module_policy.required:
                if not usable:
                    logging.error('Module policy requires module %s not usable on this platform' % (modname))
                elif modname in options.disabled_modules:
                    logging.error('Module %s was disabled but is required by policy' % (modname))
                to_load.append(modname)
                continue
            elif modname in module_policy.if_available:
                if modname in options.disabled_modules:
                    cannot_use_because(modname, 'disabled by user')
                elif usable:
                    logging.debug('Enabling optional module %s' % (modname))
                    to_load.append(modname)
                continue
            elif modname in module_policy.prohibited:
                if modname in options.enabled_modules:
                    logging.error('Module %s was requested but is prohibited by policy' % (modname))
                cannot_use_because(modname, 'prohibited by module policy')
                continue

        if modname in options.disabled_modules:
            cannot_use_because(modname, 'disabled by user')
        elif usable:
            if modname in options.enabled_modules:
                to_load.append(modname) # trust the user

            if module.load_on == 'never':
                cannot_use_because(modname, 'disabled as buggy')
            elif module.load_on == 'request':
                if options.with_everything:
                    to_load.append(modname)
                else:
                    cannot_use_because(modname, 'by request only')
            elif module.load_on == 'vendor':
                if options.with_everything:
                    to_load.append(modname)
                else:
                    cannot_use_because(modname, 'requires external dependency')
            elif module.load_on == 'dep':
                maybe_dep.append(modname)

            elif module.load_on == 'always':
                to_load.append(modname)

            elif module.load_on == 'auto':
                if options.no_autoload or module_policy is not None:
                    maybe_dep.append(modname)
                else:
                    to_load.append(modname)
            else:
                logging.error('Unknown load_on %s in %s' % (
                    module.load_on, modname))

    if 'compression' in to_load:
        # Confirm that we have at least one compression library enabled
        # Otherwise we leave a lot of useless support code compiled in, plus a
        # make_compressor call that always fails
        if 'zlib' not in to_load and 'bzip2' not in to_load and 'lzma' not in to_load:
            to_load.remove('compression')
            cannot_use_because('compression', 'no enabled compression schemes')

    dependency_failure = True

    while dependency_failure:
        dependency_failure = False
        for modname in to_load:
            for deplist in [s.split('|') for s in modules[modname].dependencies()]:

                dep_met = False
                for mod in deplist:
                    if dep_met is True:
                        break

                    if mod in to_load:
                        dep_met = True
                    elif mod in maybe_dep:
                        maybe_dep.remove(mod)
                        to_load.append(mod)
                        dep_met = True

                if not dep_met:
                    dependency_failure = True
                    if modname in to_load:
                        to_load.remove(modname)
                    if modname in maybe_dep:
                        maybe_dep.remove(modname)
                    cannot_use_because(modname, 'dependency failure')

    for not_a_dep in maybe_dep:
        cannot_use_because(not_a_dep, 'not requested')

    for reason in sorted(not_using_because.keys()):
        disabled_mods = sorted(set([mod for mod in not_using_because[reason]]))

        if disabled_mods != []:
            logging.info('Skipping, %s - %s' % (
                reason, ' '.join(disabled_mods)))

    for mod in sorted(to_load):
        if mod.startswith('simd_') and mod != 'simd_engine':
            logging.info('Using SIMD module ' + mod)

    for mod in sorted(to_load):
        if modules[mod].comment:
            logging.info('%s: %s' % (mod, modules[mod].comment))
        if modules[mod].warning:
            logging.warning('%s: %s' % (mod, modules[mod].warning))

    # force through set to dedup if required
    to_load = sorted(list(set(to_load)))
    logging.info('Loading modules %s', ' '.join(to_load))

    return to_load

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
        raise ConfigureError('Unknown link method %s' % (method))

def generate_amalgamation(build_config, modules, options):
    """
    Generate the amalgamation
    """

    def strip_header_goop(header_name, contents):
        header_guard = re.compile('^#define BOTAN_.*_H__$')

        while len(contents) > 0:
            if header_guard.match(contents[0]):
                contents = contents[1:]
                break

            contents = contents[1:]

        if len(contents) == 0:
            raise ConfigureError("No header guard found in " + header_name)

        while contents[0] == '\n':
            contents = contents[1:]

        while contents[-1] == '\n':
            contents = contents[0:-1]
        if contents[-1] == '#endif\n':
            contents = contents[0:-1]

        return contents

    botan_include_matcher = re.compile(r'#include <botan/(.*)>$')
    std_include_matcher = re.compile(r'^#include <([^/\.]+|stddef.h)>$')
    any_include_matcher = re.compile(r'#include <(.*)>$')

    class AmalgamationGenerator:
        def __init__(self, input_list):

            self.included_already = set()
            self.all_std_includes = set()

            self.file_contents = {}
            for f in sorted(input_list):
                try:
                    contents = strip_header_goop(f, open(f).readlines())
                    self.file_contents[os.path.basename(f)] = contents
                except IOError as e:
                    logging.error('Error processing file %s for amalgamation: %s' % (f, e))

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
                match = botan_include_matcher.search(line)
                if match:
                    for c in self.header_contents(match.group(1)):
                        yield c
                else:
                    match = std_include_matcher.search(line)

                    if match:
                        self.all_std_includes.add(match.group(1))
                    else:
                        yield line

    amalg_basename = 'botan_all'

    header_name = '%s.h' % (amalg_basename)
    header_int_name = '%s_internal.h' % (amalg_basename)

    logging.info('Writing amalgamation header to %s' % (header_name))

    botan_h = open(header_name, 'w')
    botan_int_h = open(header_int_name, 'w')

    pub_header_amalag = AmalgamationGenerator(build_config.public_headers)

    amalg_header = """/*
* Botan %s Amalgamation
* (C) 1999-2013,2014,2015,2016 Jack Lloyd and others
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
""" % (Version.as_string())

    botan_h.write(amalg_header)

    botan_h.write("""
#ifndef BOTAN_AMALGAMATION_H__
#define BOTAN_AMALGAMATION_H__

""")

    botan_h.write(pub_header_amalag.header_includes)
    botan_h.write(pub_header_amalag.contents)
    botan_h.write("\n#endif\n")

    internal_headers = AmalgamationGenerator([s for s in build_config.internal_headers])

    botan_int_h.write("""
#ifndef BOTAN_AMALGAMATION_INTERNAL_H__
#define BOTAN_AMALGAMATION_INTERNAL_H__

""")
    botan_int_h.write(internal_headers.header_includes)
    botan_int_h.write(internal_headers.contents)
    botan_int_h.write("\n#endif\n")

    headers_written_in_h_files = pub_header_amalag.all_std_includes | internal_headers.all_std_includes

    botan_amalgs_fs = []

    def open_amalg_file(tgt):
        fsname = '%s%s.cpp' % (amalg_basename, '_' + tgt if tgt else '')
        botan_amalgs_fs.append(fsname)
        logging.info('Writing amalgamation source to %s' % (fsname))
        f = open(fsname, 'w')
        f.write(amalg_header)

        f.write('\n#include "%s"\n' % (header_name))
        f.write('#include "%s"\n\n' % (header_int_name))

        return f

    botan_amalg_files = {}
    headers_written = {}

    for mod in modules:
        tgt = ''

        if not options.single_amalgamation_file:
            if mod.need_isa != []:
                tgt = '_'.join(sorted(mod.need_isa))
                if tgt == 'sse2' and options.arch == 'x86_64':
                    tgt = '' # SSE2 is always available on x86-64

            if options.arch == 'x86_32' and 'simd' in mod.requires:
                tgt = 'sse2'

        if tgt not in botan_amalg_files:
            botan_amalg_files[tgt] = open_amalg_file(tgt)

            if tgt != '':
                for isa in mod.need_isa:
                    if isa == 'aesni':
                        isa = "aes,ssse3,pclmul"
                    elif isa == 'rdrand':
                        isa = 'rdrnd'

                    botan_amalg_files[tgt].write('#if defined(__GNUG__)\n#pragma GCC target ("%s")\n#endif\n' % (isa))

        if tgt not in headers_written:
            headers_written[tgt] = headers_written_in_h_files.copy()

        for src in sorted(mod.source):
            contents = open(src, 'r').readlines()
            for line in contents:
                if botan_include_matcher.search(line):
                    continue

                match = any_include_matcher.search(line)
                if match:
                    header = match.group(1)
                    if header in headers_written[tgt]:
                        continue

                    botan_amalg_files[tgt].write(line)
                    headers_written[tgt].add(header)
                else:
                    botan_amalg_files[tgt].write(line)

    return botan_amalgs_fs

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

def main(argv=None):
    """
    Main driver
    """

    if argv is None:
        argv = sys.argv

    class BotanConfigureLogHandler(logging.StreamHandler, object):
        def emit(self, record):
            # Do the default stuff first
            super(BotanConfigureLogHandler, self).emit(record)
            # Exit script if and ERROR or worse occurred
            if record.levelno >= logging.ERROR:
                sys.exit(1)

    lh = BotanConfigureLogHandler(sys.stdout)
    lh.setFormatter(logging.Formatter('%(levelname) 7s: %(message)s'))
    logging.getLogger().addHandler(lh)

    options = process_command_line(argv[1:])

    def log_level():
        if options.verbose:
            return logging.DEBUG
        if options.quiet:
            return logging.WARNING
        return logging.INFO

    logging.getLogger().setLevel(log_level())

    logging.info('%s invoked with options "%s"' % (
        argv[0], ' '.join(argv[1:])))

    logging.info('Platform: OS="%s" machine="%s" proc="%s"' % (
        platform.system(), platform.machine(), platform.processor()))

    if options.os == "java":
        raise ConfigureError("Jython detected: need --os and --cpu to set target")

    options.base_dir = os.path.dirname(argv[0])
    options.src_dir = os.path.join(options.base_dir, 'src')
    options.lib_dir = os.path.join(options.src_dir, 'lib')

    options.build_data = os.path.join(options.src_dir, 'build-data')
    options.makefile_dir = os.path.join(options.build_data, 'makefile')

    def find_files_named(desired_name, in_path):
        for (dirpath, _, filenames) in os.walk(in_path):
            if desired_name in filenames:
                yield os.path.join(dirpath, desired_name)

    modules = dict([(mod.basename, mod) for mod in
                    [ModuleInfo(info) for info in
                     find_files_named('info.txt', options.lib_dir)]])

    def load_build_data(descr, subdir, class_t):
        info = {}

        subdir = os.path.join(options.build_data, subdir)

        for fsname in os.listdir(subdir):
            if fsname.endswith('.txt'):
                info[fsname.replace('.txt', '')] = class_t(os.path.join(subdir, fsname))
        if len(info) == 0:
            logging.warning('Failed to load any %s files' % (descr))
        else:
            infotxt_basenames = ' '.join(sorted([key for key in info]))
            logging.debug('Loaded %d %s files (%s)' % (len(info), descr, infotxt_basenames))

        return info

    info_arch = load_build_data('CPU info', 'arch', ArchInfo)
    info_os = load_build_data('OS info', 'os', OsInfo)
    info_cc = load_build_data('compiler info', 'cc', CompilerInfo)

    for mod in modules.values():
        mod.cross_check(info_arch, info_os, info_cc)

    module_policies = load_build_data('module policy', 'policy', ModulePolicyInfo)

    for policy in module_policies.values():
        policy.cross_check(modules)

    logging.debug('Known CPU names: ' + ' '.join(
        sorted(flatten([[ainfo.basename] + \
                        ainfo.aliases + \
                        [x for (x, _) in ainfo.all_submodels()]
                        for ainfo in info_arch.values()]))))

    if options.list_modules:
        for k in sorted(modules.keys()):
            print(k)
        sys.exit(0)

    if options.chost:
        chost = options.chost.split('-')

        if options.cpu is None and len(chost) > 0:
            options.cpu = chost[0]

        if options.os is None and len(chost) > 2:
            options.os = '-'.join(chost[2:])

    if options.os is None:
        options.os = platform.system().lower()

        if re.match('^cygwin_.*', options.os):
            logging.debug("Converting '%s' to 'cygwin'", options.os)
            options.os = 'cygwin'

        if options.os == 'windows' and options.compiler == 'gcc':
            logging.warning('Detected GCC on Windows; use --os=cygwin or --os=mingw?')

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

    if options.compiler not in info_cc:
        raise ConfigureError('Unknown compiler "%s"; available options: %s' % (
            options.compiler, ' '.join(sorted(info_cc.keys()))))

    if options.os not in info_os:

        def find_canonical_os_name(os_name_variant):
            for (canonical_os_name, info) in info_os.items():
                if os_name_variant in info.aliases:
                    return canonical_os_name
            return os_name_variant # not found

        options.os = find_canonical_os_name(options.os)

        if options.os not in info_os:
            raise ConfigureError('Unknown OS "%s"; available options: %s' % (
                options.os, ' '.join(sorted(info_os.keys()))))

    if options.cpu is None:
        (options.arch, options.cpu) = guess_processor(info_arch)
        logging.info('Guessing target processor is a %s/%s (use --cpu to set)' % (
            options.arch, options.cpu))
    else:
        cpu_from_user = options.cpu

        results = canon_processor(info_arch, options.cpu)

        if results != None:
            (options.arch, options.cpu) = results
            logging.info('Canonicalizized CPU target %s to %s/%s' % (
                cpu_from_user, options.arch, options.cpu))
        else:
            logging.error('Unknown or unidentifiable processor "%s"' % (options.cpu))

    logging.info('Target is %s-%s-%s-%s' % (
        options.compiler, options.os, options.arch, options.cpu))

    cc = info_cc[options.compiler]
    arch = info_arch[options.arch]
    osinfo = info_os[options.os]
    module_policy = None

    if options.module_policy != None:
        if options.module_policy not in module_policies:
            logging.error("Unknown module set %s", options.module_policy)
        module_policy = module_policies[options.module_policy]

    if options.with_visibility is None:
        options.with_visibility = True

    if options.with_sphinx is None:
        if have_program('sphinx-build'):
            logging.info('Found sphinx-build (use --without-sphinx to disable)')
            options.with_sphinx = True

    if options.gen_amalgamation:
        raise ConfigureError("--gen-amalgamation was removed. Migrate to --amalgamation.")

    if options.via_amalgamation:
        raise ConfigureError("--via-amalgamation was removed. Use --amalgamation instead.")

    if options.build_shared_lib and not osinfo.building_shared_supported:
        logging.warning('Shared libs not supported on %s, disabling shared lib support' % (osinfo.basename))
        options.build_shared_lib = False

    loaded_mods = choose_modules_to_use(modules, module_policy, arch, cc, options)

    for m in loaded_mods:
        if modules[m].load_on == 'vendor':
            logging.info('Enabling use of external dependency %s' % (m))

    using_mods = [modules[m] for m in loaded_mods]

    build_config = BuildPaths(options, using_mods)

    build_config.public_headers.append(os.path.join(build_config.build_dir, 'build.h'))

    template_vars = create_template_vars(build_config, options, using_mods, cc, arch, osinfo)

    makefile_template = os.path.join(options.makefile_dir, '%s.in' % (template_vars['makefile_style']))
    logging.debug('Using makefile template %s' % (makefile_template))

    # Now begin the actual IO to setup the build

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
        try:
            f = open(sink, 'w')
            f.write(process_template(template, template_vars))
        finally:
            f.close()

    def in_build_dir(p):
        return os.path.join(build_config.build_dir, p)
    def in_build_data(p):
        return os.path.join(options.build_data, p)

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
                    raise ConfigureError('Error linking %s into %s: %s' % (header_file, directory, e))

    link_headers(build_config.public_headers, 'public',
                 build_config.botan_include_dir)

    link_headers(build_config.internal_headers, 'internal',
                 build_config.internal_include_dir)

    link_headers(build_config.external_headers, 'external',
                 build_config.external_include_dir)

    with open(os.path.join(build_config.build_dir, 'build_config.json'), 'w') as f:
        json.dump(template_vars, f, sort_keys=True, indent=2)

    if options.amalgamation:
        amalgamation_cpp_files = generate_amalgamation(build_config, using_mods, options)
        build_config.lib_sources = amalgamation_cpp_files
        gen_makefile_lists(template_vars, build_config, options, using_mods, cc, arch, osinfo)

    if options.with_bakefile:
        gen_bakefile(build_config, options, template_vars['link_to'])

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

if __name__ == '__main__':
    try:
        main()
    except ConfigureError as e:
        logging.debug(traceback.format_exc())
        logging.error(e)
    except Exception as e: # pylint: disable=broad-except
        logging.debug(traceback.format_exc())
        logging.error(e)
    sys.exit(0)
