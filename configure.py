#!/usr/bin/env python

"""
Configuration program for botan

(C) 2009,2010,2011,2012,2013,2014,2015 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)

Tested with CPython 2.6, 2.7, and 3.3

CPython 2.5 and earlier are not supported

Jython - Target detection does not work (use --os and --cpu)
"""

import sys
import os
import os.path
import platform
import re
import shlex
import shutil
import string
import subprocess
import logging
import getpass
import time
import errno
import optparse

# Avoid useless botan_version.pyc (Python 2.6 or higher)
if 'dont_write_bytecode' in sys.__dict__:
    sys.dont_write_bytecode = True

import botan_version

def flatten(l):
    return sum(l, [])

def chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i:i+n]

def is_official_release():
    # Assume a release date implies official release
    return (botan_version.release_datestamp > 20130000)

def default_build_mode():
    if os.getenv('CONTINUOUS_INTEGRATION') == 'true' or \
       os.getenv('GO_ENVIRONMENT_NAME') == 'Botan':
        return 'maintainer'

    if is_official_release():
        return 'release'
    return 'debug'

def get_vc_revision():

    def get_vc_revision(cmdlist):
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
        except Exception as e:
            logging.debug('Error getting rev from %s - %s' % (cmdname, e))
            return None

    vc_commands = [['mtn', 'automate', 'heads'],
                   ['git', 'rev-parse', 'HEAD']]

    for vc_cmd in vc_commands:
        rev = get_vc_revision(vc_cmd)
        if rev is not None:
            return rev

    return 'unknown'

class BuildConfigurationInformation(object):

    """
    Version information
    """
    version_major = botan_version.release_major
    version_minor = botan_version.release_minor
    version_patch = botan_version.release_patch
    version_so_rev = botan_version.release_so_abi_rev

    version_release_type = botan_version.release_type

    version_datestamp = botan_version.release_datestamp

    version_vc_rev = botan_version.release_vc_rev
    version_string = '%d.%d.%d' % (version_major, version_minor, version_patch)

    """
    Constructor
    """
    def __init__(self, options, modules):

        if self.version_vc_rev is None:
            self.version_vc_rev = get_vc_revision()

        self.build_dir = os.path.join(options.with_build_dir, 'build')

        self.obj_dir = os.path.join(self.build_dir, 'obj')
        self.appobj_dir = os.path.join(self.obj_dir, 'app')
        self.libobj_dir = os.path.join(self.obj_dir, 'lib')
        self.testobj_dir = os.path.join(self.obj_dir, 'test')

        self.doc_output_dir = os.path.join(self.build_dir, 'docs')

        self.include_dir = os.path.join(self.build_dir, 'include')
        self.botan_include_dir = os.path.join(self.include_dir, 'botan')
        self.internal_include_dir = os.path.join(self.botan_include_dir, 'internal')

        self.modules = modules
        self.sources = sorted(flatten([mod.sources() for mod in modules]))
        self.internal_headers = sorted(flatten([m.internal_headers() for m in modules]))

        if options.via_amalgamation:
            self.build_sources = ['botan_all.cpp']
            self.build_internal_headers = []
        else:
            self.build_sources = self.sources
            self.build_internal_headers = self.internal_headers

        self.public_headers = sorted(flatten([m.public_headers() for m in modules]))

        self.doc_dir = os.path.join(options.base_dir, 'doc')
        self.src_dir = os.path.join(options.base_dir, 'src')

        def find_sources_in(basedir, srcdir):
            for (dirpath, dirnames, filenames) in os.walk(os.path.join(basedir, srcdir)):
                for filename in filenames:
                    if filename.endswith('.cpp') and not filename.startswith('.'):
                        yield os.path.join(dirpath, filename)

        self.app_sources = list(find_sources_in(self.src_dir, 'cmd'))
        self.test_sources = list(find_sources_in(self.src_dir, 'tests'))

        self.python_dir = os.path.join(options.src_dir, 'python')

        def build_doc_commands():

            def get_doc_cmd():
                if options.with_sphinx:
                    sphinx = 'sphinx-build -c $(SPHINX_CONFIG) $(SPHINX_OPTS) '
                    if options.quiet:
                        sphinx += '-q '
                    sphinx += '%s %s'
                    return sphinx
                else:
                    return '$(COPY) %s' + os.sep + '*.rst %s'

            doc_cmd = get_doc_cmd()

            def cmd_for(src):
                return doc_cmd % (os.path.join(self.doc_dir, src),
                                  os.path.join(self.doc_output_dir, src))

            yield cmd_for('manual')

            if options.with_doxygen:
                yield 'doxygen %s%sbotan.doxy' % (self.build_dir, os.sep)

        self.build_doc_commands = '\n'.join(['\t' + s for s in build_doc_commands()])

        def build_dirs():
            yield self.libobj_dir
            yield self.appobj_dir
            yield self.testobj_dir
            yield self.botan_include_dir
            yield self.internal_include_dir
            yield os.path.join(self.doc_output_dir, 'manual')

            if options.with_doxygen:
                yield os.path.join(self.doc_output_dir, 'doxygen')

        self.build_dirs = list(build_dirs())

    def src_info(self, typ):
        if typ == 'lib':
            return (self.build_sources, self.libobj_dir)
        elif typ == 'app':
            return (self.app_sources, self.appobj_dir)
        elif typ == 'test':
            return (self.test_sources, self.testobj_dir)

    def pkg_config_file(self):
        return 'botan-%d.%d.pc' % (self.version_major, self.version_minor)

    def username(self):
        return getpass.getuser()

    def hostname(self):
        return platform.node()

    def timestamp(self):
        return time.ctime()

"""
Handle command line options
"""
def process_command_line(args):

    parser = optparse.OptionParser(
        formatter = optparse.IndentedHelpFormatter(max_help_position = 50),
        version = BuildConfigurationInformation.version_string)

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

    for isa_extn_name in ['SSE2', 'SSSE3', 'AVX2', 'AES-NI', 'AltiVec']:
        isa_extn = isa_extn_name.lower()

        target_group.add_option('--disable-%s' % (isa_extn),
                                help='disable %s intrinsics' % (isa_extn_name),
                                action='append_const',
                                const=isa_extn,
                                dest='disable_intrinsics')

    build_group = optparse.OptionGroup(parser, 'Build options')

    modes = ['release', 'debug', 'coverage']
    build_group.add_option('--build-mode', default='release', metavar='MODE',
                           help="Build mode (one of %s; default %%default)" % (', '.join(modes)))

    build_group.add_option('--debug-mode', action='store_const',
                           const='debug', dest='build_mode',
                           help='enable debugging build')

    build_group.add_option('--enable-shared', dest='build_shared_lib',
                           action='store_true', default=True,
                            help=optparse.SUPPRESS_HELP)
    build_group.add_option('--disable-shared', dest='build_shared_lib',
                           action='store_false',
                           help='disable building shared library')

    build_group.add_option('--enable-asm', dest='asm_ok',
                           action='store_true', default=True,
                           help=optparse.SUPPRESS_HELP)
    build_group.add_option('--disable-asm', dest='asm_ok',
                           action='store_false',
                           help='disallow use of assembler')

    build_group.add_option('--no-optimizations', dest='no_optimizations',
                           action='store_true', default=False,
                           help=optparse.SUPPRESS_HELP)

    build_group.add_option('--gen-amalgamation', dest='gen_amalgamation',
                           default=False, action='store_true',
                           help='generate amalgamation files')

    build_group.add_option('--via-amalgamation', dest='via_amalgamation',
                           default=False, action='store_true',
                           help='build via amalgamation')

    build_group.add_option('--single-amalgamation-file',
                           default=False, action='store_true',
                           help='build single file instead of splitting on ABI')

    build_group.add_option('--with-build-dir', metavar='DIR', default='',
                           help='setup the build in DIR')

    build_group.add_option('--link-method', default=None, metavar='METHOD',
                           help='choose how links are created')

    build_group.add_option('--makefile-style', metavar='STYLE', default=None,
                           help='makefile type (gmake or nmake)')

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

    wrapper_group = optparse.OptionGroup(parser, 'Python FFI options')

    wrapper_group.add_option('--with-python-version', dest='python_version',
                             metavar='N.M',
                             default='.'.join(map(str, sys.version_info[0:2])),
                             help='set Python version (def %default)')

    mods_group = optparse.OptionGroup(parser, 'Module selection')

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
                          help='disable automatic loading')

    # Should be derived from info.txt but this runs too early
    third_party  = ['boost', 'bzip2', 'lzma', 'openssl', 'sqlite3', 'zlib']

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

    parser.add_option_group(target_group)
    parser.add_option_group(build_group)
    parser.add_option_group(mods_group)
    parser.add_option_group(wrapper_group)
    parser.add_option_group(install_group)

    # These exist only for autoconf compatability (requested by zw for mtn)
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
        raise Exception('Unhandled option(s): ' + ' '.join(args))
    if options.with_endian != None and \
       options.with_endian not in ['little', 'big']:
        raise Exception('Bad value to --with-endian "%s"' % (
            options.with_endian))

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

"""
Generic lexer function for info.txt and src/build-data files
"""
def lex_me_harder(infofile, to_obj, allowed_groups, name_val_pairs):

    # Format as a nameable Python variable
    def py_var(group):
        return group.replace(':', '_')

    class LexerError(Exception):
        def __init__(self, msg, line):
            self.msg = msg
            self.line = line

        def __str__(self):
            return '%s at %s:%d' % (self.msg, infofile, self.line)

    (dirname, basename) = os.path.split(infofile)

    to_obj.lives_in = dirname
    if basename == 'info.txt':
        (obj_dir,to_obj.basename) = os.path.split(dirname)
        if os.access(os.path.join(obj_dir, 'info.txt'), os.R_OK):
            to_obj.parent_module = os.path.basename(obj_dir)
        else:
            to_obj.parent_module = None
    else:
        to_obj.basename = basename.replace('.txt', '')

    lexer = shlex.shlex(open(infofile), infofile, posix=True)
    lexer.wordchars += '|:.<>/,-!+' # handle various funky chars in info.txt

    for group in allowed_groups:
        to_obj.__dict__[py_var(group)] = []
    for (key,val) in name_val_pairs.items():
        to_obj.__dict__[key] = val

    def lexed_tokens(): # Convert to an interator
        token = lexer.get_token()
        while token != None:
            yield token
            token = lexer.get_token()

    for token in lexed_tokens():
        match = re.match('<(.*)>', token)

        # Check for a grouping
        if match is not None:
            group = match.group(1)

            if group not in allowed_groups:
                raise LexerError('Unknown group "%s"' % (group),
                                 lexer.lineno)

            end_marker = '</' + group + '>'

            token = lexer.get_token()
            while token != end_marker:
                to_obj.__dict__[py_var(group)].append(token)
                token = lexer.get_token()
                if token is None:
                    raise LexerError('Group "%s" not terminated' % (group),
                                     lexer.lineno)

        elif token in name_val_pairs.keys():
            if type(to_obj.__dict__[token]) is list:
                to_obj.__dict__[token].append(lexer.get_token())

                # Dirty hack
                if token == 'define':
                    nxt = lexer.get_token()
                    if not nxt:
                        raise LexerError('No version set for API', lexer.lineno)
                    if not re.match('^[0-9]{8}$', nxt):
                        raise LexerError('Bad API rev "%s"' % (nxt), lexer.lineno)
                    to_obj.__dict__[token].append(nxt)
            else:
                to_obj.__dict__[token] = lexer.get_token()

        else: # No match -> error
            raise LexerError('Bad token "%s"' % (token), lexer.lineno)

"""
Convert a lex'ed map (from build-data files) from a list to a dict
"""
def force_to_dict(l):
    return dict(zip(l[::3],l[2::3]))

"""
Represents the information about a particular module
"""
class ModuleInfo(object):

    def __init__(self, infofile):

        lex_me_harder(infofile, self,
                      ['source', 'header:internal', 'header:public',
                       'requires', 'os', 'arch', 'cc', 'libs',
                       'comment', 'warning'],
                      {
                        'load_on': 'auto',
                        'define': [],
                        'need_isa': '',
                        'mp_bits': 0 })

        def extract_files_matching(basedir, suffixes):
            for (dirpath, dirnames, filenames) in os.walk(basedir):
                if dirpath == basedir:
                    for filename in filenames:
                        if filename.startswith('.'):
                            continue

                        for suffix in suffixes:
                            if filename.endswith(suffix):
                                yield filename

        if self.need_isa == '':
            self.need_isa = []
        else:
            self.need_isa = self.need_isa.split(',')

        if self.source == []:
            self.source = list(extract_files_matching(self.lives_in, ['.cpp', '.S']))

        if self.header_internal == [] and self.header_public == []:
            self.header_public = list(extract_files_matching(self.lives_in, ['.h']))

        # Coerce to more useful types
        def convert_lib_list(l):
            result = {}
            for (targetlist, vallist) in zip(l[::3], l[2::3]):
                vals = vallist.split(',')
                for target in targetlist.split(','):
                    result[target] = result.setdefault(target, []) + vals
            return result

        self.libs = convert_lib_list(self.libs)

        def add_dir_name(filename):
            if filename.count(':') == 0:
                return os.path.join(self.lives_in, filename)

            # modules can request to add files of the form
            # MODULE_NAME:FILE_NAME to add a file from another module
            # For these, assume other module is always in a
            # neighboring directory; this is true for all current uses
            return os.path.join(os.path.split(self.lives_in)[0],
                                *filename.split(':'))

        self.source = [add_dir_name(s) for s in self.source]
        self.header_internal = [add_dir_name(s) for s in self.header_internal]
        self.header_public = [add_dir_name(s) for s in self.header_public]

        for src in self.source + self.header_internal + self.header_public:
            if os.access(src, os.R_OK) == False:
                logging.warning("Missing file %s in %s" % (src, infofile))

        self.mp_bits = int(self.mp_bits)

        if self.comment != []:
            self.comment = ' '.join(self.comment)
        else:
            self.comment = None

        if self.warning != []:
            self.warning = ' '.join(self.warning)
        else:
            self.warning = None

        intersection = set(self.header_public) & set(self.header_internal)

        if len(intersection) > 0:
            logging.warning('Headers %s marked both public and internal' % (' '.join(intersection)))

    def sources(self):
        return self.source

    def public_headers(self):
        return self.header_public

    def internal_headers(self):
        return self.header_internal

    def defines(self):
        return ['HAS_' + d[0] + ' ' + d[1] for d in chunks(self.define, 2)]

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

    def compatible_os(self, os):
        return self.os == [] or os in self.os

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

    """
    Ensure that all dependencies of this module actually exist, warning
    about any that do not
    """
    def dependencies_exist(self, modules):
        all_deps = [s.split('|') for s in self.dependencies()]

        for missing in [s for s in flatten(all_deps) if s not in modules]:
            logging.warn("Module '%s', dep of '%s', does not exist" % (
                missing, self.basename))

    def __cmp__(self, other):
        if self.basename < other.basename:
            return -1
        if self.basename == other.basename:
            return 0
        return 1

class ArchInfo(object):
    def __init__(self, infofile):
        lex_me_harder(infofile, self,
                      ['aliases', 'submodels', 'submodel_aliases', 'isa_extensions'],
                      { 'endian': None,
                        'family': None,
                        'unaligned': 'no',
                        'wordsize': 32
                        })

        self.submodel_aliases = force_to_dict(self.submodel_aliases)

        self.unaligned_ok = (1 if self.unaligned == 'ok' else 0)

        self.wordsize = int(self.wordsize)

    """
    Return a list of all submodels for this arch, ordered longest
    to shortest
    """
    def all_submodels(self):
        return sorted([(k,k) for k in self.submodels] +
                      [k for k in self.submodel_aliases.items()],
                      key = lambda k: len(k[0]), reverse = True)

    """
    Return CPU-specific defines for build.h
    """
    def defines(self, options):
        def form_macro(cpu_name):
            return cpu_name.upper().replace('.', '').replace('-', '_')

        macros = ['TARGET_ARCH_IS_%s' %
                  (form_macro(self.basename.upper()))]

        if self.basename != options.cpu:
            macros.append('TARGET_CPU_IS_%s' % (form_macro(options.cpu)))

        enabled_isas = set(self.isa_extensions)
        disabled_isas = set(options.disable_intrinsics)

        isa_extensions = sorted(enabled_isas - disabled_isas)

        for isa in isa_extensions:
            macros.append('TARGET_SUPPORTS_%s' % (form_macro(isa)))

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

        return macros

class CompilerInfo(object):
    def __init__(self, infofile):
        lex_me_harder(infofile, self,
                      ['so_link_flags', 'mach_opt', 'mach_abi_linking', 'isa_flags'],
                      { 'binary_name': None,
                        'macro_name': None,
                        'compile_option': '-c ',
                        'output_to_option': '-o ',
                        'add_include_dir_option': '-I',
                        'add_lib_dir_option': '-L',
                        'add_lib_option': '-l',
                        'lib_opt_flags': '',
                        'app_opt_flags': '',
                        'debug_flags': '',
                        'no_debug_flags': '',
                        'coverage_flags': '',
                        'shared_flags': '',
                        'lang_flags': '',
                        'warning_flags': '',
                        'maintainer_warning_flags': '',
                        'visibility_build_flags': '',
                        'visibility_attribute': '',
                        'ar_command': None,
                        'makefile_style': ''
                        })

        self.so_link_flags = force_to_dict(self.so_link_flags)
        self.mach_abi_linking = force_to_dict(self.mach_abi_linking)
        self.isa_flags = force_to_dict(self.isa_flags)

        self.mach_opt_flags = {}

        while self.mach_opt != []:
            proc = self.mach_opt.pop(0)
            if self.mach_opt.pop(0) != '->':
                raise Exception('Parsing err in %s mach_opt' % (self.basename))

            flags = self.mach_opt.pop(0)
            regex = ''

            if len(self.mach_opt) > 0 and \
               (len(self.mach_opt) == 1 or self.mach_opt[1] != '->'):
                regex = self.mach_opt.pop(0)

            self.mach_opt_flags[proc] = (flags,regex)

        del self.mach_opt

    def isa_flags_for(self, isa, arch):
        if isa in self.isa_flags:
            return self.isa_flags[isa]
        arch_isa = '%s:%s' % (arch, isa)
        if arch_isa in self.isa_flags:
            return self.isa_flags[arch_isa]
        return None

    """
    Return the shared library build flags, if any
    """
    def gen_shared_flags(self, options):
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

    """
    Return the machine specific ABI flags
    """
    def mach_abi_link_flags(self, options):
        def all():
            if 'all-debug' in self.mach_abi_linking and options.build_mode == 'debug':
                return 'all-debug'
            return 'all'

        abi_link = set()
        for what in [all(), options.os, options.arch, options.cpu]:
            flag = self.mach_abi_linking.get(what)
            if flag != None and flag != '':
                abi_link.add(flag)

        for flag in options.cc_abi_flags.split(' '):
            if flag != '':
                abi_link.add(flag)

        if len(abi_link) == 0:
            return ''
        abi_flags = ' '.join(sorted(list(abi_link)))

        if options.build_mode == 'coverage':
            if self.coverage_flags == '':
                raise Exception('No coverage handling for %s' % (self.basename))
            return ' ' + self.coverage_flags + ' ' + abi_flags

        return ' ' + abi_flags

    """
    Return the optimization flags to use
    """
    def opt_flags(self, who, options):
        def gen_flags():
            if options.build_mode in ['debug', 'coverage']:
                yield self.debug_flags
            else:
                yield self.no_debug_flags

            if options.no_optimizations or options.build_mode == 'coverage':
                return

            if who != 'lib':
                yield self.app_opt_flags
                return

            yield self.lib_opt_flags

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

    """
    Return the command needed to link a shared object
    """
    def so_link_command_for(self, osname):
        if osname in self.so_link_flags:
            return self.so_link_flags[osname]
        if 'default' in self.so_link_flags:
            return self.so_link_flags['default']
        return ''

    """
    Return defines for build.h
    """
    def defines(self):
        return ['BUILD_COMPILER_IS_' + self.macro_name]

class OsInfo(object):
    def __init__(self, infofile):
        lex_me_harder(infofile, self,
                      ['aliases', 'target_features'],
                      { 'os_type': None,
                        'obj_suffix': 'o',
                        'so_suffix': 'so',
                        'static_suffix': 'a',
                        'ar_command': 'ar crs',
                        'ar_needs_ranlib': False,
                        'install_root': '/usr/local',
                        'header_dir': 'include',
                        'bin_dir': 'bin',
                        'lib_dir': 'lib',
                        'doc_dir': 'share/doc',
                        'build_shared': 'yes',
                        'install_cmd_data': 'install -m 644',
                        'install_cmd_exec': 'install -m 755'
                        })

        self.ar_needs_ranlib = bool(self.ar_needs_ranlib)

        self.build_shared = (True if self.build_shared == 'yes' else False)

    def ranlib_command(self):
        return ('ranlib' if self.ar_needs_ranlib else 'true')

    def defines(self, options):
        r = []
        for feat in self.target_features:
            if feat not in options.without_os_features:
                r += ['TARGET_OS_HAS_' + feat.upper()]
        for feat in options.with_os_features:
            if feat not in self.target_features:
                r += ['TARGET_OS_HAS_' + feat.upper()]
        return ['TARGET_OS_IS_%s' % (self.basename.upper())] + sorted(r)

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

        for (match,submodel) in ainfo.all_submodels():
            if proc == submodel or proc == match:
                return (ainfo.basename, submodel)

    logging.debug('Could not find an exact match for CPU "%s"' % (proc))

    # Now, try searching via regex match
    for ainfo in archinfo.values():
        for (match,submodel) in ainfo.all_submodels():
            if re.search(match, proc) != None:
                logging.debug('Possible match "%s" with "%s" (%s)' % (
                    proc, match, submodel))
                return (ainfo.basename, submodel)

    logging.debug('Known CPU names: ' + ' '.join(
        sorted(flatten([[ainfo.basename] + \
                        ainfo.aliases + \
                        [x for (x,_) in ainfo.all_submodels()]
                        for ainfo in archinfo.values()]))))

    raise Exception('Unknown or unidentifiable processor "%s"' % (proc))

def guess_processor(archinfo):
    base_proc = platform.machine()

    if base_proc == '':
        raise Exception('Could not determine target CPU; set with --cpu')

    full_proc = fixup_proc_name(platform.processor()) or base_proc

    for ainfo in archinfo.values():
        if ainfo.basename == base_proc or base_proc in ainfo.aliases:
            for (match,submodel) in ainfo.all_submodels():
                if re.search(match, full_proc) != None:
                    return (ainfo.basename, submodel)

            return canon_processor(archinfo, ainfo.basename)

    # No matches, so just use the base proc type
    return canon_processor(archinfo, base_proc)

"""
Read a whole file into memory as a string
"""
def slurp_file(filename):
    if filename is None:
        return ''
    return ''.join(open(filename).readlines())

"""
Perform template substitution
"""
def process_template(template_file, variables):
    class PercentSignTemplate(string.Template):
        delimiter = '%'

    try:
        template = PercentSignTemplate(slurp_file(template_file))
        return template.substitute(variables)
    except KeyError as e:
        raise Exception('Unbound var %s in template %s' % (e, template_file))
    except Exception as e:
        raise Exception('Exception %s in template %s' % (e, template_file))

def makefile_list(items):
    items = list(items) # force evaluation so we can slice it
    return (' '*16).join([item + ' \\\n' for item in items[:-1]] + [items[-1]])

def gen_makefile_lists(var, build_config, options, modules, cc, arch, osinfo):
    def get_isa_specific_flags(cc, isas):
        flags = []
        for isa in isas:
            flag = cc.isa_flags_for(isa, arch.basename)
            if flag is None:
                raise Exception('Compiler %s does not support %s' % (cc.basename, isa))
            flags.append(flag)
        return '' if len(flags) == 0 else (' ' + ' '.join(sorted(list(flags))))

    def isa_specific_flags(cc, src):

        def simd_dependencies():
            simd_re = re.compile('simd_(.*)')
            for mod in modules:
                if simd_re.match(mod.basename):
                    for isa in mod.need_isa:
                        yield isa

        for mod in modules:
            if src in mod.sources():
                isas = mod.need_isa
                if 'simd' in mod.dependencies():
                    isas += list(simd_dependencies())

                return get_isa_specific_flags(cc, isas)

        if src.startswith('botan_all_'):
            isa =  src.replace('botan_all_','').replace('.cpp', '').split('_')
            return get_isa_specific_flags(cc, isa)

        return ''

    def objectfile_list(sources, obj_dir):
        for src in sources:
            (dir,file) = os.path.split(os.path.normpath(src))

            parts = dir.split(os.sep)[2:]
            if parts != []:

                # Handle src/X/X.cpp -> X.o
                if file == parts[-1] + '.cpp':
                    name = '_'.join(dir.split(os.sep)[2:]) + '.cpp'
                else:
                    name = '_'.join(dir.split(os.sep)[2:]) + '_' + file

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

    """
    Form snippets of makefile for building each source file
    """
    def build_commands(sources, obj_dir, flags):
        for (obj_file,src) in zip(objectfile_list(sources, obj_dir), sources):
            yield '%s: %s\n\t$(CXX)%s $(%s_FLAGS) %s%s %s%s %s$@\n' % (
                obj_file, src,
                isa_specific_flags(cc, src),
                flags,
                cc.add_include_dir_option,
                build_config.include_dir,
                cc.compile_option,
                src,
                cc.output_to_option)


    for t in ['lib', 'app', 'test']:
        obj_key = '%s_objs' % (t)
        src_list, src_dir = build_config.src_info(t)
        var[obj_key] = makefile_list(objectfile_list(src_list, src_dir))
        build_key = '%s_build_cmds' % (t)
        var[build_key] = '\n'.join(build_commands(src_list, src_dir, t.upper()))

"""
Create the template variables needed to process the makefile, build.h, etc
"""
def create_template_vars(build_config, options, modules, cc, arch, osinfo):
    def make_cpp_macros(macros):
        return '\n'.join(['#define BOTAN_' + macro for macro in macros])

    """
    Figure out what external libraries are needed based on selected modules
    """
    def link_to():
        libs = set()
        for module in modules:
            for (osname,link_to) in module.libs.items():
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
        mp_bits = [mod.mp_bits for mod in modules if mod.mp_bits != 0]

        if mp_bits == []:
            logging.debug('Using arch default MP bits %d' % (arch.wordsize))
            return arch.wordsize

        # Check that settings are consistent across modules
        for mp_bit in mp_bits[1:]:
            if mp_bit != mp_bits[0]:
                raise Exception('Incompatible mp_bits settings found')

        logging.debug('Using MP bits %d' % (mp_bits[0]))
        return mp_bits[0]

    def prefix_with_build_dir(path):
        if options.with_build_dir != None:
            return os.path.join(options.with_build_dir, path)
        return path

    def warning_flags(normal_flags,
                      maintainer_flags,
                      maintainer_mode):
        if maintainer_mode and maintainer_flags != '':
            return normal_flags + ' ' + maintainer_flags
        else:
            return normal_flags

    def innosetup_arch(os, arch):
        if os == 'windows':
            inno_arch = { 'x86_32': '', 'x86_64': 'x64', 'ia64': 'ia64' }
            if arch in inno_arch:
                return inno_arch[arch]
            else:
                logging.warn('Unknown arch in innosetup_arch %s' % (arch))
        return None

    vars = {
        'version_major':  build_config.version_major,
        'version_minor':  build_config.version_minor,
        'version_patch':  build_config.version_patch,
        'version_vc_rev': build_config.version_vc_rev,
        'so_abi_rev':     build_config.version_so_rev,
        'version':        build_config.version_string,

        'release_type':   build_config.version_release_type,

        'distribution_info': options.distribution_info,

        'version_datestamp': build_config.version_datestamp,

        'src_dir': build_config.src_dir,
        'doc_dir': build_config.doc_dir,

        'timestamp': build_config.timestamp(),
        'user':      build_config.username(),
        'hostname':  build_config.hostname(),
        'command_line': ' '.join(sys.argv),
        'local_config': slurp_file(options.local_config),
        'makefile_style': options.makefile_style or cc.makefile_style,

        'makefile_path': prefix_with_build_dir('Makefile'),

        'program_suffix': options.program_suffix or ('.exe' if options.os in ('windows', 'mingw', 'cygwin') else ''),

        'prefix': options.prefix or osinfo.install_root,
        'destdir': options.destdir or options.prefix or osinfo.install_root,
        'bindir': options.bindir or osinfo.bin_dir,
        'libdir': options.libdir or osinfo.lib_dir,
        'includedir': options.includedir or osinfo.header_dir,
        'docdir': options.docdir or osinfo.doc_dir,

        'out_dir': options.with_build_dir or os.path.curdir,
        'build_dir': build_config.build_dir,

        'scripts_dir': os.path.join(build_config.src_dir, 'scripts'),

        'with_shared_lib': options.build_shared_lib,

        'appobj_dir': build_config.appobj_dir,
        'libobj_dir': build_config.libobj_dir,
        'testobj_dir': build_config.testobj_dir,

        'doc_output_dir': build_config.doc_output_dir,

        'build_doc_commands': build_config.build_doc_commands,

        'python_dir': build_config.python_dir,
        'sphinx_config_dir': os.path.join(options.build_data, 'sphinx'),

        'os': options.os,
        'arch': options.arch,
        'submodel': options.cpu,

        'innosetup_arch': innosetup_arch(options.os, options.arch),

        'mp_bits': choose_mp_bits(),

        'cc': (options.compiler_binary or cc.binary_name) + cc.mach_abi_link_flags(options),

        'lib_opt': cc.opt_flags('lib', options),
        'app_opt': cc.opt_flags('app', options),
        'lang_flags': cc.lang_flags,
        'warn_flags': warning_flags(cc.warning_flags,
                                    cc.maintainer_warning_flags,
                                    options.maintainer_mode),

        'shared_flags': cc.gen_shared_flags(options),
        'visibility_attribute': cc.gen_visibility_attribute(options),

        'libname': 'botan-%d.%d' % (build_config.version_major, build_config.version_minor),

        'so_link': cc.so_link_command_for(osinfo.basename),

        'link_to': ' '.join([cc.add_lib_option + lib for lib in link_to()]),

        'module_defines': make_cpp_macros(sorted(flatten([m.defines() for m in modules]))),

        'target_os_defines': make_cpp_macros(osinfo.defines(options)),

        'target_compiler_defines': make_cpp_macros(cc.defines()),

        'target_cpu_defines': make_cpp_macros(arch.defines(options)),

        'botan_include_dir': build_config.botan_include_dir,

        'include_files': makefile_list(build_config.public_headers),

        'ar_command': cc.ar_command or osinfo.ar_command,
        'ranlib_command': osinfo.ranlib_command(),
        'install_cmd_exec': osinfo.install_cmd_exec,
        'install_cmd_data': osinfo.install_cmd_data,

        'lib_prefix': 'lib' if options.os != 'windows' else '',

        'static_suffix': osinfo.static_suffix,
        'so_suffix': osinfo.so_suffix,

        'mod_list': '\n'.join(sorted([m.basename for m in modules])),

        'python_version': options.python_version,
        'with_sphinx': options.with_sphinx
        }

    gen_makefile_lists(vars, build_config, options, modules, cc, arch, osinfo)

    if options.os != 'windows':
        vars['botan_pkgconfig'] = prefix_with_build_dir(os.path.join(build_config.build_dir,
                                                                     build_config.pkg_config_file()))

    vars["header_in"] = process_template('src/build-data/makefile/header.in', vars)
    vars["commands_in"] = process_template('src/build-data/makefile/commands.in', vars)

    vars["coverage_in"] = process_template('src/build-data/makefile/coverage.in', vars) \
                          if options.build_mode == 'coverage' else ''

    if options.build_shared_lib:
        vars["dso_in"] = process_template('src/build-data/makefile/dso.in', vars)
    else:
        vars["dso_in"] = ""

    return vars

"""
Determine which modules to load based on options, target, etc
"""
def choose_modules_to_use(modules, archinfo, ccinfo, options):

    for mod in modules.values():
        mod.dependencies_exist(modules)

    to_load = []
    maybe_dep = []
    not_using_because = {}

    def cannot_use_because(mod, reason):
        not_using_because.setdefault(reason, []).append(mod)

    for modname in options.enabled_modules:
        if modname not in modules:
            logging.warning("Unknown enabled module %s" % (modname))

    for modname in options.disabled_modules:
        if modname not in modules:
            logging.warning("Unknown disabled module %s" % (modname))

    for (modname, module) in modules.items():
        if modname in options.disabled_modules:
            cannot_use_because(modname, 'disabled by user')
        elif modname in options.enabled_modules:
            to_load.append(modname) # trust the user

        elif not module.compatible_os(options.os):
            cannot_use_because(modname, 'incompatible OS')
        elif not module.compatible_compiler(ccinfo, archinfo.basename):
            cannot_use_because(modname, 'incompatible compiler')
        elif not module.compatible_cpu(archinfo, options):
            cannot_use_because(modname, 'incompatible CPU')

        else:
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

            elif module.load_on == 'asm_ok':
                if options.asm_ok:
                    if options.no_autoload:
                        maybe_dep.append(modname)
                    else:
                        to_load.append(modname)
                else:
                    cannot_use_because(modname,
                                       'uses assembly and --disable-asm set')
            elif module.load_on == 'auto':
                if options.no_autoload:
                    maybe_dep.append(modname)
                else:
                    to_load.append(modname)
            else:
                logging.warning('Unknown load_on %s in %s' % (
                    module.load_on, modname))

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

                if dep_met == False:
                    dependency_failure = True
                    if modname in to_load:
                        to_load.remove(modname)
                    if modname in maybe_dep:
                        maybe_dep.remove(modname)
                    cannot_use_because(modname, 'dependency failure')

    for not_a_dep in maybe_dep:
        cannot_use_because(not_a_dep, 'loaded only if needed by dependency')

    for reason in sorted(not_using_because.keys()):
        disabled_mods = sorted(set([mod for mod in not_using_because[reason]]))

        if disabled_mods != []:
            logging.info('Skipping, %s - %s' % (
                reason, ' '.join(disabled_mods)))

    for mod in sorted(to_load):
        if mod.startswith('mp_'):
            logging.info('Using MP module ' + mod)
        if mod.startswith('simd_') and mod != 'simd_engine':
            logging.info('Using SIMD module ' + mod)

    for mod in sorted(to_load):
        if modules[mod].comment:
            logging.info('%s: %s' % (mod, modules[mod].comment))
        if modules[mod].warning:
            logging.warning('%s: %s' % (mod, modules[mod].warning))

    to_load.sort()
    logging.info('Loading modules %s', ' '.join(to_load))

    return to_load

"""
Load the info files about modules, targets, etc
"""
def load_info_files(options):

    def find_files_named(desired_name, in_path):
        for (dirpath, dirnames, filenames) in os.walk(in_path):
            if desired_name in filenames:
                yield os.path.join(dirpath, desired_name)

    modules = dict([(mod.basename, mod) for mod in
                    [ModuleInfo(info) for info in
                     find_files_named('info.txt', options.lib_dir)]])

    def list_files_in_build_data(subdir):
        for (dirpath, dirnames, filenames) in \
                os.walk(os.path.join(options.build_data, subdir)):
            for filename in filenames:
                if filename.endswith('.txt'):
                    yield os.path.join(dirpath, filename)

    def form_name(filepath):
        return os.path.basename(filepath).replace('.txt', '')

    archinfo = dict([(form_name(info), ArchInfo(info))
                     for info in list_files_in_build_data('arch')])

    osinfo   = dict([(form_name(info), OsInfo(info))
                      for info in list_files_in_build_data('os')])

    ccinfo = dict([(form_name(info), CompilerInfo(info))
                    for info in list_files_in_build_data('cc')])

    def info_file_load_report(type, num):
        if num > 0:
            logging.debug('Loaded %d %s info files' % (num, type))
        else:
            logging.warning('Failed to load any %s info files' % (type))

    info_file_load_report('CPU', len(archinfo));
    info_file_load_report('OS', len(osinfo))
    info_file_load_report('compiler', len(ccinfo))

    return (modules, archinfo, ccinfo, osinfo)


"""
Choose the link method based on system availablity and user request
"""
def choose_link_method(options):

    def useable_methods():
        if 'symlink' in os.__dict__ and options.os != 'windows':
            yield 'symlink'
        if 'link' in os.__dict__:
            yield 'hardlink'
        yield 'copy'

    req = options.link_method

    for method in useable_methods():
        if req is None or req == method:
            logging.info('Using %s to link files into build dir ' \
                         '(use --link-method to change)' % (method))
            return method

    logging.warning('Could not use link method "%s", will copy instead' % (req))
    return 'copy'

"""
Copy or link the file, depending on what the platform offers
"""
def portable_symlink(filename, target_dir, method):

    if not os.access(filename, os.R_OK):
        logging.warning('Missing file %s' % (filename))
        return

    if method == 'symlink':
        def count_dirs(dir, accum = 0):
            if dir in ['', '/', os.path.curdir]:
                return accum
            (dir,basename) = os.path.split(dir)
            return accum + 1 + count_dirs(dir)

        dirs_up = count_dirs(target_dir)
        source = os.path.join(os.path.join(*[os.path.pardir] * dirs_up), filename)
        target = os.path.join(target_dir, os.path.basename(filename))
        os.symlink(source, target)

    elif method == 'hardlink':
        os.link(filename, os.path.join(target_dir, os.path.basename(filename)))

    elif method == 'copy':
        shutil.copy(filename, target_dir)
    else:
        raise Exception('Unknown link method %s' % (method))

"""
Generate the amalgamation
"""
def generate_amalgamation(build_config, options):
    def strip_header_goop(header_name, contents):
        header_guard = re.compile('^#define BOTAN_.*_H__$')

        while len(contents) > 0:
            if header_guard.match(contents[0]):
                contents = contents[1:]
                break

            contents = contents[1:]

        if len(contents) == 0:
            raise Exception("No header guard found in " + header_name)

        while contents[0] == '\n':
            contents = contents[1:]

        while contents[-1] == '\n':
            contents = contents[0:-1]
        if contents[-1] == '#endif\n':
            contents = contents[0:-1]

        return contents

    botan_include = re.compile('#include <botan/(.*)>$')
    std_include = re.compile('#include <([^/\.]+|stddef.h)>$')
    any_include = re.compile('#include <(.*)>$')

    class Amalgamation_Generator:
        def __init__(self, input_list):

            self.included_already = set()
            self.all_std_includes = set()

            self.file_contents = {}
            for f in sorted(input_list):
                contents = strip_header_goop(f, open(f).readlines())
                self.file_contents[os.path.basename(f)] = contents

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
                match = botan_include.search(line)
                if match:
                    for c in self.header_contents(match.group(1)):
                        yield c
                else:
                    match = std_include.search(line)

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

    pub_header_amalag = Amalgamation_Generator(build_config.public_headers)

    amalg_header = """/*
* Botan %s Amalgamation
* (C) 1999-2013,2014,2015 Jack Lloyd and others
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
""" % (build_config.version_string)

    botan_h.write(amalg_header)

    botan_h.write("""
#ifndef BOTAN_AMALGAMATION_H__
#define BOTAN_AMALGAMATION_H__

""")

    botan_h.write(pub_header_amalag.header_includes)
    botan_h.write(pub_header_amalag.contents)
    botan_h.write("\n#endif\n")

    internal_headers = Amalgamation_Generator(
        [s for s in build_config.internal_headers
         if s.find('asm_macr_') == -1])

    botan_int_h.write("""
#ifndef BOTAN_AMALGAMATION_INTERNAL_H__
#define BOTAN_AMALGAMATION_INTERNAL_H__

""")
    botan_int_h.write(internal_headers.header_includes)
    botan_int_h.write(internal_headers.contents)
    botan_int_h.write("\n#endif\n")

    headers_written = pub_header_amalag.all_std_includes.union(internal_headers.all_std_includes)

    botan_amalgs_fs = []

    def open_amalg_file(tgt):
        fsname = '%s%s.cpp' % (amalg_basename, '_' + tgt if tgt else '' )
        botan_amalgs_fs.append(fsname)
        logging.info('Writing amalgamation source to %s' % (fsname))
        f = open(fsname, 'w')
        f.write(amalg_header)

        f.write('\n#include "%s"\n' % (header_name))
        f.write('#include "%s"\n\n' % (header_int_name))

        return f

    botan_amalgs = {}
    botan_amalgs[''] = open_amalg_file('')

    for mod in build_config.modules:
        tgt = ''

        if not options.single_amalgamation_file and mod.need_isa != []:
            tgt = '_'.join(sorted(mod.need_isa))
            if tgt == 'sse2' and options.arch == 'x86_64':
                tgt = '' # SSE2 is always available on x86-64

        if tgt not in botan_amalgs:
            botan_amalgs[tgt] = open_amalg_file(tgt)
        for src in sorted(mod.source):
            contents = open(src, 'r').readlines()
            for line in contents:
                if botan_include.search(line):
                    continue

                match = any_include.search(line)
                if match:
                    header = match.group(1)
                    if header in headers_written:
                        continue

                    botan_amalgs[tgt].write(line)
                    headers_written.add(header)
                else:
                    botan_amalgs[tgt].write(line)

    return botan_amalgs_fs

"""
Test for the existence of a program
"""
def have_program(program):

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

"""
Main driver
"""
def main(argv = None):
    if argv is None:
        argv = sys.argv

    logging.basicConfig(stream = sys.stdout,
                        format = '%(levelname) 7s: %(message)s')

    options = process_command_line(argv[1:])

    def log_level():
        if options.verbose:
            return logging.DEBUG
        if options.quiet:
            return logging.WARNING
        return logging.INFO

    logging.getLogger().setLevel(log_level())

    logging.debug('%s invoked with options "%s"' % (
        argv[0], ' '.join(argv[1:])))

    logging.info('Platform: OS="%s" machine="%s" proc="%s"' % (
        platform.system(), platform.machine(), platform.processor()))

    if options.os == "java":
        raise Exception("Jython detected: need --os and --cpu to set target")

    options.base_dir = os.path.dirname(argv[0])
    options.src_dir = os.path.join(options.base_dir, 'src')
    options.lib_dir = os.path.join(options.src_dir, 'lib')

    options.build_data = os.path.join(options.src_dir, 'build-data')
    options.makefile_dir = os.path.join(options.build_data, 'makefile')

    (modules, info_arch, info_cc, info_os) = load_info_files(options)

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
        elif options.os == 'darwin':
            if have_program('clang++'):
                options.compiler = 'clang'
        else:
            options.compiler = 'gcc'
        logging.info('Guessing to use compiler %s (use --cc to set)' % (
            options.compiler))

    if options.compiler not in info_cc:
        raise Exception('Unknown compiler "%s"; available options: %s' % (
            options.compiler, ' '.join(sorted(info_cc.keys()))))

    if options.os not in info_os:

        def find_canonical_os_name(os):
            for (name, info) in info_os.items():
                if os in info.aliases:
                    return name
            return os # not found

        options.os = find_canonical_os_name(options.os)

        if options.os not in info_os:
            raise Exception('Unknown OS "%s"; available options: %s' % (
                options.os, ' '.join(sorted(info_os.keys()))))

    if options.cpu is None:
        (options.arch, options.cpu) = guess_processor(info_arch)
        logging.info('Guessing target processor is a %s/%s (use --cpu to set)' % (
            options.arch, options.cpu))
    else:
        cpu_from_user = options.cpu
        (options.arch, options.cpu) = canon_processor(info_arch, options.cpu)
        logging.info('Canonicalizized CPU target %s to %s/%s' % (
            cpu_from_user, options.arch, options.cpu))

    logging.info('Target is %s-%s-%s-%s' % (
        options.compiler, options.os, options.arch, options.cpu))

    cc = info_cc[options.compiler]
    arch = info_arch[options.arch]
    osinfo = info_os[options.os]

    if options.with_visibility is None:
        options.with_visibility = True

    if options.with_sphinx is None:
        if have_program('sphinx-build'):
            logging.info('Found sphinx-build (use --without-sphinx to disable)')
            options.with_sphinx = True

    if options.via_amalgamation:
        options.gen_amalgamation = True

    if options.gen_amalgamation:
        if options.asm_ok:
            logging.info('Disabling assembly code, cannot use in amalgamation')
            options.asm_ok = False

    loaded_mods = choose_modules_to_use(modules, arch, cc, options)

    for m in loaded_mods:
        if modules[m].load_on == 'vendor':
            logging.info('Enabling use of external dependency %s' % (m))

        if not osinfo.build_shared:
            if options.build_shared_lib:
                logging.info('Disabling shared lib on %s' % (options.os))
                options.build_shared_lib = False

    using_mods = [modules[m] for m in loaded_mods]

    build_config = BuildConfigurationInformation(options, using_mods)
    build_config.public_headers.append(os.path.join(build_config.build_dir, 'build.h'))

    template_vars = create_template_vars(build_config, options, using_mods, cc, arch, osinfo)

    makefile_template = os.path.join(options.makefile_dir, '%s.in' % (template_vars['makefile_style']))
    logging.debug('Using makefile template %s' % (makefile_template))

    # Now begin the actual IO to setup the build

    try:
        if options.clean_build_tree:
            shutil.rmtree(build_config.build_dir)
    except OSError as e:
        if e.errno != errno.ENOENT:
            logging.error('Problem while removing build dir: %s' % (e))

    for dir in build_config.build_dirs:
        try:
            os.makedirs(dir)
        except OSError as e:
            if e.errno != errno.EEXIST:
                logging.error('Error while creating "%s": %s' % (dir, e))

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
        write_template(in_build_dir(build_config.pkg_config_file()), in_build_data('botan.pc.in'))

    if options.os == 'windows':
        write_template(in_build_dir('botan.iss'), in_build_data('innosetup.in'))

    link_method = choose_link_method(options)

    def link_headers(headers, type, dir):
        logging.debug('Linking %d %s header files in %s' % (len(headers), type, dir))

        for header_file in headers:
            try:
                portable_symlink(header_file, dir, link_method)
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise Exception('Error linking %s into %s: %s' % (header_file, dir, e))

    link_headers(build_config.public_headers, 'public', build_config.botan_include_dir)

    link_headers(build_config.build_internal_headers, 'internal',
                 build_config.internal_include_dir)

    with open(os.path.join(build_config.build_dir, 'build_config.py'), 'w') as f:
        f.write(str(template_vars))

    if options.gen_amalgamation:
        fs = generate_amalgamation(build_config, options)
        if options.via_amalgamation:
            build_config.build_sources = fs
            gen_makefile_lists(template_vars, build_config, options, using_mods, cc, arch, osinfo)

    write_template(template_vars['makefile_path'], makefile_template)

    def release_date(datestamp):
        if datestamp == 0:
            return 'undated'
        return 'dated %d' % (datestamp)

    logging.info('Botan %s (%s %s) build setup is complete' % (
        build_config.version_string,
        build_config.version_release_type,
        release_date(build_config.version_datestamp)))

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        logging.error(e)
        import traceback
        logging.debug(traceback.format_exc())
        sys.exit(1)
    sys.exit(0)
