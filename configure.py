#!/usr/bin/env python

"""
Configuration program for botan

(C) 2009,2010,2011,2012,2013,2014,2015 Jack Lloyd
(C) 2015,2016 Simon Warta (Kullo GmbH)

Botan is released under the Simplified BSD License (see license.txt)

This script is regularly tested with CPython 2.7 and 3.5, and
occasionally tested with CPython 2.6 and PyPy 4.

Support for CPython 2.6 will be dropped eventually, but is kept up for as
long as reasonably convenient.

CPython 2.5 and earlier are not supported.

On Jython target detection does not work (use --os and --cpu).
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

    vc_command = ['git', 'rev-parse', 'HEAD']
    rev = get_vc_revision(vc_command)
    if rev is not None:
        return rev
    else:
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

    # This is used on Darwin for dylib versioning
    version_packed = version_major * 1000 + version_minor
    
    """
    Constructor
    """
    def __init__(self, options, modules):

        if self.version_vc_rev is None:
            self.version_vc_rev = get_vc_revision()

        self.build_dir = os.path.join(options.with_build_dir, 'build')

        self.obj_dir = os.path.join(self.build_dir, 'obj')
        self.libobj_dir = os.path.join(self.obj_dir, 'lib')
        self.cliobj_dir = os.path.join(self.obj_dir, 'cli')
        self.testobj_dir = os.path.join(self.obj_dir, 'test')

        self.doc_output_dir = os.path.join(self.build_dir, 'docs')

        self.include_dir = os.path.join(self.build_dir, 'include')
        self.botan_include_dir = os.path.join(self.include_dir, 'botan')
        self.internal_include_dir = os.path.join(self.botan_include_dir, 'internal')
        self.external_include_dir = os.path.join(self.include_dir, 'external')

        self.modules = modules
        self.sources = sorted(flatten([mod.sources() for mod in modules]))
        self.internal_headers = sorted(flatten([m.internal_headers() for m in modules]))
        self.external_headers = sorted(flatten([m.external_headers() for m in modules]))

        if options.via_amalgamation:
            self.build_sources = ['botan_all.cpp']
        else:
            self.build_sources = self.sources

        self.public_headers = sorted(flatten([m.public_headers() for m in modules]))

        self.doc_dir = os.path.join(options.base_dir, 'doc')
        self.src_dir = os.path.join(options.base_dir, 'src')

        def find_sources_in(basedir, srcdir):
            for (dirpath, dirnames, filenames) in os.walk(os.path.join(basedir, srcdir)):
                for filename in filenames:
                    if filename.endswith('.cpp') and not filename.startswith('.'):
                        yield os.path.join(dirpath, filename)

        self.cli_sources = list(find_sources_in(self.src_dir, 'cli'))
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
            yield self.cliobj_dir
            yield self.testobj_dir
            yield self.botan_include_dir
            yield self.internal_include_dir
            yield self.external_include_dir
            yield os.path.join(self.doc_output_dir, 'manual')

            if options.with_doxygen:
                yield os.path.join(self.doc_output_dir, 'doxygen')

        self.build_dirs = list(build_dirs())

    def src_info(self, typ):
        if typ == 'lib':
            return (self.build_sources, self.libobj_dir)
        elif typ == 'cli':
            return (self.cli_sources, self.cliobj_dir)
        elif typ == 'test':
            return (self.test_sources, self.testobj_dir)

    def pkg_config_file(self):
        return 'botan-%d.%d.pc' % (self.version_major, self.version_minor)


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
                                const=isa_extn.replace('-', ''),
                                dest='disable_intrinsics')

    build_group = optparse.OptionGroup(parser, 'Build options')

    build_group.add_option('--with-debug-info', action='store_true', default=False, dest='with_debug_info',
                           help='enable debug info')

    build_group.add_option('--with-sanitizers', action='store_true', default=False, dest='with_sanitizers',
                           help='enable runtime checks')

    build_group.add_option('--with-coverage', action='store_true', default=False, dest='with_coverage',
                           help='enable coverage checking')

    build_group.add_option('--enable-shared-library', dest='build_shared_lib',
                           action='store_true', default=True,
                           help=optparse.SUPPRESS_HELP)
    build_group.add_option('--disable-shared', dest='build_shared_lib',
                           action='store_false',
                           help='disable building shared library')

    build_group.add_option('--no-optimizations', dest='no_optimizations',
                           action='store_true', default=False,
                           help='disable all optimizations (for debugging)')

    build_group.add_option('--debug-mode', action='store_true', default=False, dest='debug_mode',
                           help='enable debug info and disable optimizations')

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

    build_group.add_option('--with-external-includedir', metavar='DIR', default='',
                           help='use DIR for external includes')

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
                           default='.'.join(map(str, sys.version_info[0:2])),
                           help='where to install botan.py (def %default)')

    build_group.add_option('--with-valgrind', help='use valgrind API',
                           dest='with_valgrind', action='store_true', default=False)

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
    third_party  = ['boost', 'bzip2', 'lzma', 'openssl', 'sqlite3', 'zlib', 'tpm', 'pkcs11']

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
    parser.add_option_group(install_group)

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
        raise Exception('Unhandled option(s): ' + ' '.join(args))
    if options.with_endian != None and \
       options.with_endian not in ['little', 'big']:
        raise Exception('Bad value to --with-endian "%s"' % (
            options.with_endian))

    if options.debug_mode:
        options.no_optimizations = True
        options.with_debug_info = True

    if options.with_coverage:
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
                        'header:external', 'requires', 'os', 'arch', 
                        'cc', 'libs', 'frameworks', 'comment', 
                        'warning'],
                      {
                        'load_on': 'auto',
                        'define': [],
                        'need_isa': ''})

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
            self.source = list(extract_files_matching(self.lives_in, ['.cpp']))

        if self.header_internal == [] and self.header_public == []:
            self.header_public = list(extract_files_matching(self.lives_in, ['.h']))

        # Coerce to more useful types
        def convert_lib_list(l):
            if len(l) % 3 != 0:
                raise Exception("Bad <libs> in module %s" % (self.basename))
            result = {}

            for sep in l[1::3]:
                if(sep != '->'):
                    raise Exception("Bad <libs> in module %s" % (self.basename))

            for (targetlist, vallist) in zip(l[::3], l[2::3]):
                vals = vallist.split(',')
                for target in targetlist.split(','):
                    result[target] = result.setdefault(target, []) + vals
            return result

        self.libs = convert_lib_list(self.libs)
        self.frameworks = convert_lib_list(self.frameworks)

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
        self.header_external = [add_dir_name(s) for s in self.header_external]

        for src in self.source + self.header_internal + self.header_public + self.header_external:
            if os.access(src, os.R_OK) == False:
                logging.error("Missing file %s in %s" % (src, infofile))

        if self.comment != []:
            self.comment = ' '.join(self.comment)
        else:
            self.comment = None

        if self.warning != []:
            self.warning = ' '.join(self.warning)
        else:
            self.warning = None

        def intersect_check(typeA, listA, typeB, listB):
           intersection = set.intersection(set(listA), set(listB))
           if len(intersection) > 0:
              logging.error('Headers %s marked both %s and %s' % (' '.join(intersection), typeA, typeB))

        intersect_check('public', self.header_public, 'internal', self.header_internal)
        intersect_check('public', self.header_public, 'external', self.header_external)
        intersect_check('external', self.header_external, 'internal', self.header_internal)

    def sources(self):
        return self.source

    def public_headers(self):
        return self.header_public

    def internal_headers(self):
        return self.header_internal

    def external_headers(self):
        return self.header_external

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

class ModulePolicyInfo(object):
    def __init__(self, infofile):
        lex_me_harder(infofile, self,
                      ['required', 'if_available', 'prohibited'], {})

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

        if options.with_valgrind:
            macros.append('HAS_VALGRIND')

        return macros

class CompilerInfo(object):
    def __init__(self, infofile):
        lex_me_harder(infofile, self,
                      ['so_link_commands', 'binary_link_commands', 'mach_opt', 'mach_abi_linking', 'isa_flags'],
                      { 'binary_name': None,
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
                        'coverage_flags': '',
                        'sanitizer_flags': '',
                        'shared_flags': '',
                        'lang_flags': '',
                        'warning_flags': '',
                        'maintainer_warning_flags': '',
                        'visibility_build_flags': '',
                        'visibility_attribute': '',
                        'ar_command': None,
                        'makefile_style': ''
                        })

        self.so_link_commands     = force_to_dict(self.so_link_commands)
        self.binary_link_commands = force_to_dict(self.binary_link_commands)
        self.mach_abi_linking     = force_to_dict(self.mach_abi_linking)
        self.isa_flags            = force_to_dict(self.isa_flags)

        self.infofile = infofile
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
            if options.with_debug_info and 'all-debug' in self.mach_abi_linking:
                return 'all-debug'
            return 'all'

        abi_link = list()
        for what in [all(), options.os, options.arch, options.cpu]:
            flag = self.mach_abi_linking.get(what)
            if flag != None and flag != '' and flag not in abi_link:
                abi_link.append(flag)

        if options.with_coverage:
            if self.coverage_flags == '':
                raise Exception('No coverage handling for %s' % (self.basename))
            abi_link.append(self.coverage_flags)

        if options.with_sanitizers:
            if self.sanitizer_flags == '':
                raise Exception('No sanitizer handling for %s' % (self.basename))
            abi_link.append(self.sanitizer_flags)

        abi_flags = ' '.join(sorted(abi_link))

        if options.cc_abi_flags != '':
            abi_flags += ' ' + options.cc_abi_flags

        if abi_flags != '':
            return ' ' + abi_flags
        return ''

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

    def _so_link_search(self, osname, debug_info):
        if debug_info:
            return [osname + '-debug', 'default-debug']
        else:
            return [osname, 'default']

    """
    Return the command needed to link a shared object
    """
    def so_link_command_for(self, osname, options):
        for s in self._so_link_search(osname, options.with_debug_info):
            if s in self.so_link_commands:
                return self.so_link_commands[s]

        raise Exception("No shared library link command found for target '%s' in compiler settings '%s'" %
                    (osname, self.infofile))

    """
    Return the command needed to link an app/test object
    """
    def binary_link_command_for(self, osname, options):
        for s in self._so_link_search(osname, options.with_debug_info):
            if s in self.binary_link_commands:
                return self.binary_link_commands[s]

        return '$(LINKER)'

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
                        'program_suffix': '',
                        'obj_suffix': 'o',
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

        self.ar_needs_ranlib = bool(self.ar_needs_ranlib)

        self.building_shared_supported = (True if self.building_shared_supported == 'yes' else False)

    def ranlib_command(self):
        return ('ranlib' if self.ar_needs_ranlib else 'true')

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
            if 'sse2' in arch.isa_extensions:
                return ['sse2']
            elif 'altivec' in arch.isa_extensions:
                return ['altivec']
            return []

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
        includes = cc.add_include_dir_option + build_config.include_dir
        includes+= ' ' + cc.add_include_dir_option + build_config.external_include_dir if build_config.external_headers else ''
        includes+= ' ' + cc.add_include_dir_option + options.with_external_includedir if options.with_external_includedir else ''
        for (obj_file,src) in zip(objectfile_list(sources, obj_dir), sources):
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
        return do_link_to('libs')

    """
    Figure out what external frameworks are needed based on selected modules
    """
    def link_to_frameworks():
        return do_link_to('frameworks')

    def do_link_to(module_member_name):
        libs = set()
        for module in modules:
            for (osname,link_to) in getattr(module, module_member_name).items():
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

    def prefix_with_build_dir(path):
        if options.with_build_dir != None:
            return os.path.join(options.with_build_dir, path)
        return path

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

        'version_packed': build_config.version_packed,

        'release_type':   build_config.version_release_type,

        'distribution_info': options.distribution_info,

        'version_datestamp': build_config.version_datestamp,

        'src_dir': build_config.src_dir,
        'doc_dir': build_config.doc_dir,

        'command_line': ' '.join(sys.argv),
        'local_config': slurp_file(options.local_config),
        'makefile_style': options.makefile_style or cc.makefile_style,

        'makefile_path': prefix_with_build_dir('Makefile'),

        'program_suffix': options.program_suffix or osinfo.program_suffix,

        'prefix': options.prefix or osinfo.install_root,
        'destdir': options.destdir or options.prefix or osinfo.install_root,
        'bindir': options.bindir or osinfo.bin_dir,
        'libdir': options.libdir or osinfo.lib_dir,
        'includedir': options.includedir or osinfo.header_dir,
        'docdir': options.docdir or osinfo.doc_dir,

        'out_dir': options.with_build_dir or os.path.curdir,
        'build_dir': build_config.build_dir,
        'src_dir': options.src_dir,

        'scripts_dir': os.path.join(build_config.src_dir, 'scripts'),

        'build_shared_lib': options.build_shared_lib,

        'libobj_dir': build_config.libobj_dir,
        'cliobj_dir': build_config.cliobj_dir,
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

        'cxx': (options.compiler_binary or cc.binary_name),
        'cxx_abi_flags': cc.mach_abi_link_flags(options),
        'linker': cc.linker_name or '$(CXX)',

        'cc_compile_flags': cc.cc_compile_flags(options),
        'cc_warning_flags': cc.cc_warning_flags(options),

        'shared_flags': cc.gen_shared_flags(options),
        'visibility_attribute': cc.gen_visibility_attribute(options),

        'lib_link_cmd':  cc.so_link_command_for(osinfo.basename, options),
        'cli_link_cmd':  cc.binary_link_command_for(osinfo.basename, options),
        'test_link_cmd': cc.binary_link_command_for(osinfo.basename, options),

        'link_to': ' '.join([cc.add_lib_option + lib for lib in link_to()] + [cc.add_framework_option + fw for fw in link_to_frameworks()]),

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

        'soname_base': osinfo.soname_pattern_base.format(
                            version_major = build_config.version_major,
                            version_minor = build_config.version_minor,
                            version_patch = build_config.version_patch,
                            abi_rev       = build_config.version_so_rev),
        'soname_abi': osinfo.soname_pattern_abi.format(
                            version_major = build_config.version_major,
                            version_minor = build_config.version_minor,
                            version_patch = build_config.version_patch,
                            abi_rev       = build_config.version_so_rev),
        'soname_patch': osinfo.soname_pattern_patch.format(
                            version_major = build_config.version_major,
                            version_minor = build_config.version_minor,
                            version_patch = build_config.version_patch,
                            abi_rev       = build_config.version_so_rev),

        'mod_list': '\n'.join(sorted([m.basename for m in modules])),

        'python_version': options.python_version,
        'with_sphinx': options.with_sphinx
        }

    if options.os == 'darwin' and options.build_shared_lib:
        # In order that these executables work from the build directory,
        # we need to change the install names
        vars['cli_post_link_cmd']  = 'install_name_tool -change "$(INSTALLED_LIB_DIR)/$(SONAME_ABI)" "@executable_path/$(SONAME_ABI)" $(CLI)'
        vars['test_post_link_cmd'] = 'install_name_tool -change "$(INSTALLED_LIB_DIR)/$(SONAME_ABI)" "@executable_path/$(SONAME_ABI)" $(TEST)'
    else:
        vars['cli_post_link_cmd'] = ''
        vars['test_post_link_cmd'] = ''

    gen_makefile_lists(vars, build_config, options, modules, cc, arch, osinfo)

    if options.os != 'windows':
        vars['botan_pkgconfig'] = prefix_with_build_dir(os.path.join(build_config.build_dir,
                                                                     build_config.pkg_config_file()))

        # 'botan' or 'botan-1.11'. Used in Makefile and install script
        # This can be made consistent over all platforms in the future    
        vars['libname'] = 'botan-%d.%d' % (build_config.version_major, build_config.version_minor)
    else:
        if options.with_debug_info:
            vars['libname'] = 'botand'
        else:
            vars['libname'] = 'botan'

    vars["header_in"] = process_template('src/build-data/makefile/header.in', vars)

    if vars["makefile_style"] == "gmake":
        vars["gmake_commands_in"] = process_template('src/build-data/makefile/gmake_commands.in', vars)
        vars["gmake_dso_in"]      = process_template('src/build-data/makefile/gmake_dso.in', vars) \
                                    if options.build_shared_lib else ''
        vars["gmake_coverage_in"] = process_template('src/build-data/makefile/gmake_coverage.in', vars) \
                                    if options.with_coverage else ''

    return vars

"""
Determine which modules to load based on options, target, etc
"""
def choose_modules_to_use(modules, module_policy, archinfo, ccinfo, options):

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
        elif modname in options.enabled_modules:
            to_load.append(modname) # trust the user
        elif usable:
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
        cannot_use_because(not_a_dep, 'only used if needed or requested')

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

    to_load.sort()
    logging.info('Loading modules %s', ' '.join(to_load))

    return to_load

"""
Choose the link method based on system availablity and user request
"""
def choose_link_method(options):

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

    botan_include_matcher = re.compile('#include <botan/(.*)>$')
    std_include_matcher = re.compile('#include <([^/\.]+|stddef.h)>$')
    any_include_matcher = re.compile('#include <(.*)>$')

    class Amalgamation_Generator:
        def __init__(self, input_list):

            self.included_already = set()
            self.all_std_includes = set()

            self.file_contents = {}
            for f in sorted(input_list):
                try:
                    contents = strip_header_goop(f, open(f).readlines())
                    self.file_contents[os.path.basename(f)] = contents
                except Exception as e:
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

    internal_headers = Amalgamation_Generator([s for s in build_config.internal_headers])

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
        fsname = '%s%s.cpp' % (amalg_basename, '_' + tgt if tgt else '' )
        botan_amalgs_fs.append(fsname)
        logging.info('Writing amalgamation source to %s' % (fsname))
        f = open(fsname, 'w')
        f.write(amalg_header)

        f.write('\n#include "%s"\n' % (header_name))
        f.write('#include "%s"\n\n' % (header_int_name))

        return f

    botan_amalg_files = {}
    headers_written = {}

    for mod in build_config.modules:
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
        raise Exception("Jython detected: need --os and --cpu to set target")

    options.base_dir = os.path.dirname(argv[0])
    options.src_dir = os.path.join(options.base_dir, 'src')
    options.lib_dir = os.path.join(options.src_dir, 'lib')

    options.build_data = os.path.join(options.src_dir, 'build-data')
    options.makefile_dir = os.path.join(options.build_data, 'makefile')

    def find_files_named(desired_name, in_path):
        for (dirpath, dirnames, filenames) in os.walk(in_path):
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
            logging.debug('Loaded %d %s files' % (len(info), descr))

        return info

    info_arch = load_build_data('CPU info', 'arch', ArchInfo)
    info_os   = load_build_data('OS info', 'os', OsInfo)
    info_cc   = load_build_data('compiler info', 'cc', CompilerInfo)

    module_policies = load_build_data('module policy', 'policy', ModulePolicyInfo)

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
        elif options.os == 'darwin' or options.os == 'freebsd':
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

    if options.via_amalgamation:
        options.gen_amalgamation = True

    if options.build_shared_lib and not osinfo.building_shared_supported:
        raise Exception('Botan does not support building as shared library on the target os. '
                'Build static using --disable-shared.')

    loaded_mods = choose_modules_to_use(modules, module_policy, arch, cc, options)

    for m in loaded_mods:
        if modules[m].load_on == 'vendor':
            logging.info('Enabling use of external dependency %s' % (m))

    using_mods = [modules[m] for m in loaded_mods]

    build_config = BuildConfigurationInformation(options, using_mods)
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

        # Final attempt, pass any Exceptions up to caller.
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

        # Final attempt, pass any Exceptions up to caller.
        os.makedirs(dir)

    try:
        if options.clean_build_tree:
            robust_rmtree(build_config.build_dir)
    except OSError as e:
        if e.errno != errno.ENOENT:
            logging.error('Problem while removing build dir: %s' % (e))

    for dir in build_config.build_dirs:
        try:
            robust_makedirs(dir)
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

    link_headers(build_config.public_headers, 'public',
                 build_config.botan_include_dir)

    link_headers(build_config.internal_headers, 'internal',
                 build_config.internal_include_dir)

    link_headers(build_config.external_headers, 'external',
                 build_config.external_include_dir)

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
        import traceback
        logging.debug(traceback.format_exc())
        logging.error(e)
    sys.exit(0)
