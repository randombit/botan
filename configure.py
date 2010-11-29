#!/usr/bin/env python

"""
Configuration program for botan (http://botan.randombit.net/)
  (C) 2009-2010 Jack Lloyd
  Distributed under the terms of the Botan license

Tested with
   CPython 2.5, 2.6 - OK
   Jython 2.5 - Target detection does not work (use --os and --cpu)

   CPython 2.4 and earlier are not supported

   Use the 2to3 script to use with Python 3

   Has not been tested with IronPython or PyPy
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

from optparse import (OptionParser, OptionGroup,
                      IndentedHelpFormatter, SUPPRESS_HELP)

def flatten(l):
    return sum(l, [])

class BuildConfigurationInformation(object):

    """
    Version information
    """
    version_major = 1
    version_minor = 9
    version_patch = 11
    version_so_patch = 11
    version_suffix = ''

    version_datestamp = 20101129

    version_string = '%d.%d.%d%s' % (
        version_major, version_minor, version_patch, version_suffix)
    soversion_string = '%d.%d.%d%s' % (
        version_major, version_minor, version_so_patch, version_suffix)

    """
    Constructor
    """
    def __init__(self, options, modules):

        # If not preset, use today
        if self.version_datestamp is None:
            self.version_datestamp = time.strftime("%Y%m%d", time.gmtime())

        self.build_dir = os.path.join(options.with_build_dir, 'build')

        self.checkobj_dir = os.path.join(self.build_dir, 'checks')
        self.libobj_dir = os.path.join(self.build_dir, 'lib')

        self.python_dir = os.path.join(options.src_dir, 'wrap', 'python')

        self.use_boost_python = options.boost_python

        self.pyobject_dir = os.path.join(self.build_dir, 'python')

        self.include_dir = os.path.join(self.build_dir, 'include')
        self.botan_include_dir = os.path.join(self.include_dir, 'botan')
        self.internal_include_dir = os.path.join(self.botan_include_dir, 'internal')

        self.sources = sorted(flatten([mod.sources() for mod in modules]))
        self.public_headers = sorted(flatten([m.public_headers() for m in modules]))
        self.internal_headers = sorted(flatten([m.internal_headers() for m in modules]))

        checks_dir = os.path.join(options.base_dir, 'checks')

        self.check_sources = sorted(
            [os.path.join(checks_dir, file) for file in os.listdir(checks_dir)
             if file.endswith('.cpp')])

        self.python_sources = sorted(
            [os.path.join(self.python_dir, file)
             for file in os.listdir(self.python_dir)
             if file.endswith('.cpp')])

    def doc_files(self):
        docs = ['readme.txt']

        for docfile in ['api.pdf', 'tutorial.pdf', 'fips140.pdf',
                        'api.tex', 'tutorial.tex', 'fips140.tex',
                        'credits.txt', 'license.txt', 'log.txt',
                        'thanks.txt', 'todo.txt', 'pgpkeys.asc']:
            filename = os.path.join('doc', docfile)
            if os.access(filename, os.R_OK):
                docs.append(filename)
        return docs

    def pkg_config_file(self):
        return 'botan-%d.%d.pc' % (self.version_major,
                                   self.version_minor)

    def build_dirs(self):
        dirs = [self.checkobj_dir,
                self.libobj_dir,
                self.botan_include_dir,
                self.internal_include_dir]
        if self.use_boost_python:
            dirs.append(self.pyobject_dir)
        return dirs

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

    parser = OptionParser(
        formatter = IndentedHelpFormatter(max_help_position = 50),
        version = BuildConfigurationInformation.version_string)

    parser.add_option('--verbose', action='store_true', default=False,
                      help='Show debug messages')
    parser.add_option('--quiet', action='store_true', default=False,
                      help='Show only warnings and errors')

    target_group = OptionGroup(parser, 'Target options')

    target_group.add_option('--cc', dest='compiler',
                            help='set the desired build compiler')
    target_group.add_option('--os',
                            help='set the target operating system')
    target_group.add_option('--cpu',
                            help='set the target processor type/model')
    target_group.add_option('--with-endian', metavar='ORDER', default=None,
                            help='override guess of CPU byte order')

    target_group.add_option('--with-unaligned-mem',
                            dest='unaligned_mem', action='store_true',
                            default=None,
                            help='enable unaligned memory accesses')

    target_group.add_option('--without-unaligned-mem',
                            dest='unaligned_mem', action='store_false',
                            help=SUPPRESS_HELP)

    for isa_extn_name in ['SSE2', 'SSSE3', 'AltiVec', 'AES-NI', 'movbe']:
        isa_extn = isa_extn_name.lower()

        target_group.add_option('--enable-%s' % (isa_extn),
                                help='enable use of %s' % (isa_extn_name),
                                action='append_const',
                                const=isa_extn,
                                dest='enable_isa_extns')

        target_group.add_option('--disable-%s' % (isa_extn),
                                help=SUPPRESS_HELP,
                                action='append_const',
                                const=isa_extn,
                                dest='disable_isa_extns')

    build_group = OptionGroup(parser, 'Build options')

    build_group.add_option('--enable-shared', dest='build_shared_lib',
                           action='store_true', default=True,
                            help=SUPPRESS_HELP)
    build_group.add_option('--disable-shared', dest='build_shared_lib',
                           action='store_false',
                           help='disable building a shared library')

    build_group.add_option('--enable-asm', dest='asm_ok',
                           action='store_true', default=True,
                           help=SUPPRESS_HELP)
    build_group.add_option('--disable-asm', dest='asm_ok',
                           action='store_false',
                           help='disallow use of assembler')

    build_group.add_option('--enable-debug', dest='debug_build',
                           action='store_true', default=False,
                           help='enable debug build')
    build_group.add_option('--disable-debug', dest='debug_build',
                           action='store_false', help=SUPPRESS_HELP)

    build_group.add_option('--gen-amalgamation', dest='gen_amalgamation',
                           default=False, action='store_true',
                           help='generate amalgamation files')

    build_group.add_option('--with-tr1-implementation', metavar='WHICH',
                           dest='with_tr1', default=None,
                           help='enable TR1 (choices: none, system, boost)')

    build_group.add_option('--with-build-dir',
                           metavar='DIR', default='',
                           help='setup the build in DIR')

    build_group.add_option('--makefile-style', metavar='STYLE', default=None,
                           help='choose a makefile style (unix or nmake)')

    build_group.add_option('--with-local-config',
                           dest='local_config', metavar='FILE',
                           help='include the contents of FILE into build.h')

    build_group.add_option('--dumb-gcc', dest='dumb_gcc',
                           action='store_true', default=False,
                           help=SUPPRESS_HELP)

    build_group.add_option('--maintainer-mode', dest='maintainer_mode',
                           action='store_true', default=False,
                           help=SUPPRESS_HELP)

    build_group.add_option('--dirty-tree', dest='clean_build_tree',
                           action='store_false', default=True,
                           help=SUPPRESS_HELP)

    wrapper_group = OptionGroup(parser, 'Wrapper options')

    wrapper_group.add_option('--with-boost-python', dest='boost_python',
                             default=False, action='store_true',
                             help='enable Boost.Python wrapper')

    wrapper_group.add_option('--without-boost-python',
                             dest='boost_python',
                             action='store_false',
                             help=SUPPRESS_HELP)

    wrapper_group.add_option('--use-python-version', dest='python_version',
                             metavar='N.M',
                             default='.'.join(map(str, sys.version_info[0:2])),
                             help='specify version of Python to build against (eg %default)')

    mods_group = OptionGroup(parser, 'Module selection')

    mods_group.add_option('--enable-modules', dest='enabled_modules',
                          metavar='MODS', action='append',
                          help='enable specific modules')
    mods_group.add_option('--disable-modules', dest='disabled_modules',
                          metavar='MODS', action='append',
                          help='disable specific modules')
    mods_group.add_option('--no-autoload', action='store_true', default=False,
                          help='disable automatic loading')

    for lib in ['OpenSSL', 'GNU MP', 'Bzip2', 'Zlib']:

        mod = lib.lower().replace(' ', '')

        mods_group.add_option('--with-%s' % (mod),
                              help='add support for using %s' % (lib),
                              action='append_const',
                              const=mod,
                              dest='enabled_modules')

        mods_group.add_option('--without-%s' % (mod),
                              help=SUPPRESS_HELP,
                              action='append_const',
                              const=mod,
                              dest='disabled_modules')

    install_group = OptionGroup(parser, 'Installation options')

    install_group.add_option('--prefix', metavar='DIR',
                             help='set the base install directory')
    install_group.add_option('--docdir', metavar='DIR',
                             help='set the documentation install directory')
    install_group.add_option('--libdir', metavar='DIR',
                             help='set the library install directory')
    install_group.add_option('--includedir', metavar='DIR',
                             help='set the include file install directory')

    parser.add_option_group(target_group)
    parser.add_option_group(build_group)
    parser.add_option_group(mods_group)
    parser.add_option_group(wrapper_group)
    parser.add_option_group(install_group)

    # These exist only for autoconf compatability (requested by zw for mtn)
    compat_with_autoconf_options = [
        'bindir',
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
        parser.add_option('--' + opt, help=SUPPRESS_HELP)

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

    options.enable_isa_extns = parse_multiple_enable(options.enable_isa_extns)
    options.disable_isa_extns = parse_multiple_enable(options.disable_isa_extns)

    def enabled_or_disabled_isa(isa):
        if isa in options.enable_isa_extns:
            return True
        if isa in options.disable_isa_extns:
            return True
        return False

    isa_deps = {
        'ssse3': 'sse2',
        'aes-ni': 'sse2'
        }

    if 'sse2' in options.disable_isa_extns:
        for isa in [k for (k,v) in isa_deps.items() if v == 'sse2']:
            # If explicitly enabled, allow it even if a dependency
            # violation; trust the user to know what they want
            if not enabled_or_disabled_isa(isa):
                options.disable_isa_extns.append(isa)

    for isa in options.enable_isa_extns:
        if isa in isa_deps:
            for dep in isa_deps.get(isa, '').split(','):
                if not enabled_or_disabled_isa(dep):
                    options.enable_isa_extns.append(dep)

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
                       'requires', 'os', 'arch', 'cc', 'libs'],
                      { 'load_on': 'auto',
                        'define': None,
                        'uses_tr1': 'false',
                        'need_isa': None,
                        'mp_bits': 0 })

        if self.source == [] and \
            self.header_internal == [] and \
            self.header_public == []:

            for (dirpath, dirnames, filenames) in os.walk(self.lives_in):
                if dirpath == self.lives_in:
                    for filename in filenames:
                        if filename.startswith('.'):
                            continue

                        if filename.endswith('.cpp') or \
                           filename.endswith('.S'):
                            self.source.append(filename)
                        elif filename.endswith('.h'):
                            self.header_public.append(filename)

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

        self.mp_bits = int(self.mp_bits)

        self.uses_tr1 = (True if self.uses_tr1 == 'yes' else False)

    def sources(self):
        return self.source

    def public_headers(self):
        return self.header_public

    def internal_headers(self):
        return self.header_internal

    def compatible_cpu(self, archinfo, options):

        arch_name = archinfo.basename
        cpu_name = options.cpu

        if self.arch != []:
            if arch_name not in self.arch and cpu_name not in self.arch:
                return False

        if self.need_isa != None:
            if self.need_isa in options.disable_isa_extns:
                return False # explicitly disabled

            if self.need_isa in options.enable_isa_extns:
                return True # explicitly enabled

            # Default to whatever the CPU is supposed to support
            return self.need_isa in archinfo.isa_extensions_in(cpu_name)

        return True

    def compatible_os(self, os):
        return self.os == [] or os in self.os

    def compatible_compiler(self, cc):
        return self.cc == [] or cc in self.cc

    def tr1_ok(self, with_tr1):
        if self.uses_tr1:
            return with_tr1 in ['boost', 'system']
        else:
            return True

    def dependencies(self):
        # utils is an implicit dep (contains types, etc)
        deps = self.requires + ['utils']
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
                      ['aliases', 'submodels', 'submodel_aliases', 'isa_extn'],
                      { 'endian': None,
                        'family': None,
                        'unaligned': 'no'
                        })

        def convert_isa_list(input):
            isa_info = {}
            for line in self.isa_extn:
                (isa,cpus) = line.split(':')
                for cpu in cpus.split(','):
                    isa_info.setdefault(cpu, []).append(isa)
            return isa_info

        self.isa_extn = convert_isa_list(self.isa_extn)

        self.submodel_aliases = force_to_dict(self.submodel_aliases)

        self.unaligned_ok = (1 if self.unaligned == 'ok' else 0)

    """
    Return ISA extensions specific to this CPU
    """
    def isa_extensions_in(self, cpu_type):
        return sorted(self.isa_extn.get(cpu_type, []) +
                      self.isa_extn.get('all', []))

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

        enabled_isas = set(self.isa_extensions_in(options.cpu) +
                           options.enable_isa_extns)
        disabled_isas = set(options.disable_isa_extns)

        isa_extensions = sorted(enabled_isas - disabled_isas)

        for isa in isa_extensions:
            macros.append('TARGET_CPU_HAS_%s' % (form_macro(isa)))

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

        macros.append('TARGET_UNALIGNED_MEMORY_ACCESS_OK %d' % (unaligned_ok))

        return macros

class CompilerInfo(object):
    def __init__(self, infofile):
        lex_me_harder(infofile, self,
                      ['so_link_flags', 'mach_opt', 'mach_abi_linking'],
                      { 'binary_name': None,
                        'macro_name': None,
                        'compile_option': '-c ',
                        'output_to_option': '-o ',
                        'add_include_dir_option': '-I',
                        'add_lib_dir_option': '-L',
                        'add_lib_option': '-l',
                        'lib_opt_flags': '',
                        'check_opt_flags': '',
                        'debug_flags': '',
                        'no_debug_flags': '',
                        'shared_flags': '',
                        'lang_flags': '',
                        'warning_flags': '',
                        'maintainer_warning_flags': '',
                        'dll_import_flags': '',
                        'ar_command': None,
                        'makefile_style': '',
                        'has_tr1': False,
                        })

        self.so_link_flags = force_to_dict(self.so_link_flags)
        self.mach_abi_linking = force_to_dict(self.mach_abi_linking)

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

    """
    Return the machine specific ABI flags
    """
    def mach_abi_link_flags(self, osname, arch, submodel, debug_p):

        def all():
            if debug_p:
                return 'all-debug'
            return 'all'

        abi_link = set()
        for what in [all(), osname, arch, submodel]:
            if self.mach_abi_linking.get(what) != None:
                abi_link.add(self.mach_abi_linking.get(what))

        if len(abi_link) == 0:
            return ''
        return ' ' + ' '.join(abi_link)

    """
    Return the flags for MACH_OPT
    """
    def mach_opts(self, arch, submodel):

        def submodel_fixup(tup):
            return tup[0].replace('SUBMODEL', submodel.replace(tup[1], ''))

        if submodel == arch:
            return ''

        if submodel in self.mach_opt_flags:
            return submodel_fixup(self.mach_opt_flags[submodel])
        if arch in self.mach_opt_flags:
            return submodel_fixup(self.mach_opt_flags[arch])

        return ''

    """
    Return the flags for LIB_OPT
    """
    def library_opt_flags(self, debug_build):
        flags = self.lib_opt_flags
        if debug_build and self.debug_flags != '':
            flags += ' ' + self.debug_flags
        if not debug_build and self.no_debug_flags != '':
            flags += ' ' + self.no_debug_flags
        return flags

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
    def defines(self, with_tr1):

        def tr1_macro():
            if with_tr1:
                if with_tr1 == 'boost':
                    return ['USE_BOOST_TR1']
                elif with_tr1 == 'system':
                    return ['USE_STD_TR1']
            elif self.has_tr1:
                return ['USE_STD_TR1']
            return []

        return ['BUILD_COMPILER_IS_' + self.macro_name] + tr1_macro()

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

    def defines(self):
        return ['TARGET_OS_IS_%s' % (self.basename.upper())] + \
               ['TARGET_OS_HAS_' + feat.upper()
                for feat in sorted(self.target_features)]

def fixup_proc_name(proc):
    proc = proc.lower().replace(' ', '')
    for junk in ['(tm)', '(r)']:
        proc = proc.replace(junk, '')
    return proc

def canon_processor(archinfo, proc):
    proc = fixup_proc_name(proc)

    for ainfo in archinfo.values():
        if ainfo.basename == proc or proc in ainfo.aliases:
            return (ainfo.basename, ainfo.basename)
        else:
            for (match,submodel) in ainfo.all_submodels():
                if re.search(match, proc) != None:
                    return (ainfo.basename, submodel)

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
    except KeyError, e:
        raise Exception('Unbound var %s in template %s' % (e, template_file))

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

    def objectfile_list(sources, obj_dir):
        for src in sources:
            basename = os.path.basename(src)

            for src_suffix in ['.cpp', '.S']:
                basename = basename.replace(src_suffix,
                                            '.' + osinfo.obj_suffix)

            yield os.path.join(obj_dir, basename)


    def choose_mp_bits():
        mp_bits = [mod.mp_bits for mod in modules if mod.mp_bits != 0]

        if mp_bits == []:
            return 32 # default

        # Check that settings are consistent across modules
        for mp_bit in mp_bits[1:]:
            if mp_bit != mp_bits[0]:
                raise Exception('Incompatible mp_bits settings found')

        return mp_bits[0]

    """
    Form snippets of makefile for building each source file
    """
    def build_commands(sources, obj_dir, flags):
        for (obj_file,src) in zip(objectfile_list(sources, obj_dir), sources):
            yield '%s: %s\n\t$(CXX) %s%s $(%s_FLAGS) %s$? %s$@\n' % (
                obj_file, src,
                cc.add_include_dir_option,
                build_config.include_dir,
                flags,
                cc.compile_option,
                cc.output_to_option)

    def makefile_list(items):
        items = list(items) # force evaluation so we can slice it
        return (' '*16).join([item + ' \\\n' for item in items[:-1]] +
                             [items[-1]])

    def prefix_with_build_dir(path):
        if options.with_build_dir != None:
            return os.path.join(options.with_build_dir, path)
        return path

    def only_if_shared(option):
        if options.build_shared_lib:
            return option
        return ''

    def warning_flags(normal_flags,
                      maintainer_flags,
                      maintainer_mode):
        if maintainer_mode and maintainer_flags != '':
            return maintainer_flags
        return normal_flags

    return {
        'version_major': build_config.version_major,
        'version_minor': build_config.version_minor,
        'version_patch': build_config.version_patch,
        'version':       build_config.version_string,

        'version_datestamp': build_config.version_datestamp,

        'so_version': build_config.soversion_string,

        'timestamp': build_config.timestamp(),
        'user':      build_config.username(),
        'hostname':  build_config.hostname(),
        'command_line': ' '.join(sys.argv),
        'local_config': slurp_file(options.local_config),
        'makefile_style': options.makefile_style or cc.makefile_style,

        'makefile_path': prefix_with_build_dir('Makefile'),

        'prefix': options.prefix or osinfo.install_root,
        'libdir': options.libdir or osinfo.lib_dir,
        'includedir': options.includedir or osinfo.header_dir,
        'docdir': options.docdir or osinfo.doc_dir,

        'doc_src_dir': 'doc',
        'build_dir': build_config.build_dir,

        'os': options.os,
        'arch': options.arch,
        'submodel': options.cpu,

        'mp_bits': choose_mp_bits(),

        'cc': cc.binary_name + cc.mach_abi_link_flags(
            options.os, options.arch, options.cpu, options.debug_build),

        'lib_opt': cc.library_opt_flags(options.debug_build),
        'mach_opt': cc.mach_opts(options.arch, options.cpu),
        'check_opt': cc.check_opt_flags,
        'lang_flags': cc.lang_flags + options.extra_flags,
        'warn_flags': warning_flags(cc.warning_flags,
                                    cc.maintainer_warning_flags,
                                    options.maintainer_mode),

        'shared_flags': only_if_shared(cc.shared_flags),
        'dll_import_flags': only_if_shared(cc.dll_import_flags),

        'so_link': cc.so_link_command_for(osinfo.basename),

        'link_to': ' '.join([cc.add_lib_option + lib for lib in link_to()]),

        'module_defines': make_cpp_macros(
            sorted(['HAS_' + m.define for m in modules if m.define])),

        'target_os_defines': make_cpp_macros(osinfo.defines()),

        'target_compiler_defines': make_cpp_macros(
            cc.defines(options.with_tr1)),

        'target_cpu_defines': make_cpp_macros(arch.defines(options)),

        'include_files': makefile_list(build_config.public_headers),

        'lib_objs': makefile_list(
            objectfile_list(build_config.sources,
                            build_config.libobj_dir)),

        'check_objs': makefile_list(
            objectfile_list(build_config.check_sources,
                            build_config.checkobj_dir)),

        'lib_build_cmds': '\n'.join(
            build_commands(build_config.sources,
                           build_config.libobj_dir, 'LIB')),

        'check_build_cmds': '\n'.join(
            build_commands(build_config.check_sources,
                           build_config.checkobj_dir, 'CHECK')),

        'python_obj_dir': build_config.pyobject_dir,

        'python_objs': makefile_list(
            objectfile_list(build_config.python_sources,
                            build_config.pyobject_dir)),

        'python_build_cmds': '\n'.join(
            build_commands(build_config.python_sources,
                           build_config.pyobject_dir, 'PYTHON')),

        'ar_command': cc.ar_command or osinfo.ar_command,
        'ranlib_command': osinfo.ranlib_command(),
        'install_cmd_exec': osinfo.install_cmd_exec,
        'install_cmd_data': osinfo.install_cmd_data,

        'check_prefix': prefix_with_build_dir(''),
        'lib_prefix': prefix_with_build_dir(''),

        'static_suffix': osinfo.static_suffix,
        'so_suffix': osinfo.so_suffix,

        'botan_config': prefix_with_build_dir(
            os.path.join(build_config.build_dir, 'botan-config')),
        'botan_pkgconfig': prefix_with_build_dir(
            os.path.join(build_config.build_dir,
                         build_config.pkg_config_file())),

        'doc_files': makefile_list(build_config.doc_files()),

        'mod_list': '\n'.join(sorted([m.basename for m in modules])),

        'python_version': options.python_version
        }

"""
Determine which modules to load based on options, target, etc
"""
def choose_modules_to_use(modules, archinfo, options):

    for mod in modules.values():
        mod.dependencies_exist(modules)

    to_load = []
    maybe_dep = []
    not_using_because = {}

    def cannot_use_because(mod, reason):
        not_using_because.setdefault(reason, []).append(mod)

    for (modname, module) in modules.items():
        if modname in options.disabled_modules:
            cannot_use_because(modname, 'disabled by user')
        elif modname in options.enabled_modules:
            to_load.append(modname) # trust the user

        elif not module.compatible_os(options.os):
            cannot_use_because(modname, 'incompatible OS')
        elif not module.compatible_compiler(options.compiler):
            cannot_use_because(modname, 'incompatible compiler')
        elif not module.compatible_cpu(archinfo, options):
            cannot_use_because(modname, 'incompatible CPU')
        elif not module.tr1_ok(options.with_tr1):
            cannot_use_because(modname, 'missing TR1')

        else:
            if module.load_on == 'never':
                cannot_use_because(modname, 'disabled as buggy')
            elif module.load_on == 'request':
                cannot_use_because(modname, 'by request only')
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

    logging.debug('Loading modules %s', ' '.join(sorted(to_load)))

    return [modules[mod] for mod in to_load]

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
                     find_files_named('info.txt', options.src_dir)]])

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
Perform the filesystem operations needed to setup the build
"""
def setup_build(build_config, options, template_vars):

    """
    Copy or link the file, depending on what the platform offers
    """
    def portable_symlink(filename, target_dir):

        if not os.access(filename, os.R_OK):
            logging.warning('Missing file %s' % (filename))
            return

        if 'symlink' in os.__dict__:
            def count_dirs(dir, accum = 0):
                if dir == '' or dir == os.path.curdir:
                    return accum
                (dir,basename) = os.path.split(dir)
                return accum + 1 + count_dirs(dir)

            dirs_up = count_dirs(target_dir)

            source = os.path.join(os.path.join(*[os.path.pardir]*dirs_up),
                                  filename)

            target = os.path.join(target_dir, os.path.basename(filename))

            os.symlink(source, target)

        elif 'link' in os.__dict__:
            os.link(filename,
                    os.path.join(target_dir, os.path.basename(filename)))

        else:
            shutil.copy(filename, target_dir)

    def choose_makefile_template(style):
        if style == 'nmake':
            return 'nmake.in'
        elif style == 'unix':
            return ('unix_shr.in' if options.build_shared_lib else 'unix.in')
        else:
            raise Exception('Unknown makefile style "%s"' % (style))

    # First delete the build tree, if existing
    try:
        if options.clean_build_tree:
            shutil.rmtree(build_config.build_dir)
    except OSError, e:
        if e.errno != errno.ENOENT:
            logging.error('Problem while removing build dir: %s' % (e))

    for dir in build_config.build_dirs():
        try:
            os.makedirs(dir)
        except OSError, e:
            if e.errno != errno.EEXIST:
                logging.error('Error while creating "%s": %s' % (dir, e))

    makefile_template = os.path.join(
        options.makefile_dir,
        choose_makefile_template(template_vars['makefile_style']))

    logging.debug('Using makefile template %s' % (makefile_template))

    templates_to_proc = {
        makefile_template: template_vars['makefile_path']
        }

    def templates_to_use():
        yield (options.build_data, 'buildh.in', 'build.h')
        yield (options.build_data, 'botan.doxy.in', 'botan.doxy')

        if options.os != 'windows':
            yield (options.build_data, 'botan.pc.in', build_config.pkg_config_file())
            yield (options.build_data, 'botan-config.in', 'botan-config')

        if options.os == 'windows':
            yield (options.build_data, 'innosetup.in', 'botan.iss')

        if options.boost_python:
            yield (options.makefile_dir, 'python.in', 'Makefile.python')

    for (template_dir, template, sink) in templates_to_use():
        source = os.path.join(template_dir, template)
        if template_dir == options.build_data:
            sink = os.path.join(build_config.build_dir, sink)
        templates_to_proc[source] = sink

    for (template, sink) in templates_to_proc.items():
        try:
            f = open(sink, 'w')
            f.write(process_template(template, template_vars))
        finally:
            f.close()

    def link_headers(header_list, type, dir):
        logging.debug('Linking %d %s header files in %s' % (
            len(header_list), type, dir))

        for header_file in header_list:
            try:
                portable_symlink(header_file, dir)
            except OSError, e:
                if e.errno != errno.EEXIST:
                    logging.error('Error linking %s into %s: %s' % (
                        header_file, dir, e))

    link_headers(build_config.public_headers, 'public',
                 build_config.botan_include_dir)

    link_headers(build_config.internal_headers, 'internal',
                 build_config.internal_include_dir)

"""
Generate Amalgamation
"""
def generate_amalgamation(build_config):
    def ending_with_suffix(suffix):
        def predicate(val):
            return val.endswith(suffix)
        return predicate

    def strip_header_goop(contents):
        header_guard = re.compile('^#define BOTAN_.*_H__$')

        while len(contents) > 0:
            if header_guard.match(contents[0]):
                contents = contents[1:]
                break

            contents = contents[1:]

        while contents[0] == '\n':
            contents = contents[1:]

        while contents[-1] == '\n':
            contents = contents[0:-1]
        if contents[-1] == '#endif\n':
            contents = contents[0:-1]

        return contents

    botan_include = re.compile('#include <botan/(.*)>$')
    std_include = re.compile('#include <([^/\.]+)>$')

    class Amalgamation_Generator:
        def __init__(self, input_list):

            self.included_already = set()
            self.all_std_includes = set()

            self.file_contents = {}
            for f in sorted(input_list):
                contents = strip_header_goop(open(f).readlines())
                self.file_contents[os.path.basename(f)] = contents

            self.contents = ''
            for name in self.file_contents:
                self.contents += ''.join(list(self.header_contents(name)))

            self.header_includes = ''
            for std_header in self.all_std_includes:
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

    botan_all_h = open('botan_all.h', 'w')

    pub_header_amalag = Amalgamation_Generator(build_config.public_headers)

    amalg_header = """/*
* Botan %s Amalgamation
* (C) 1999-2009 Jack Lloyd and others
*
* Distributed under the terms of the Botan license
*/
""" % (build_config.version_string)

    botan_all_h.write(amalg_header)

    botan_all_h.write("""
#ifndef BOTAN_AMALGAMATION_H__
#define BOTAN_AMALGAMATION_H__

""")

    botan_all_h.write(pub_header_amalag.header_includes)
    botan_all_h.write(pub_header_amalag.contents)
    botan_all_h.write("\n#endif\n")

    internal_header_amalag = Amalgamation_Generator(
        [s for s in build_config.internal_headers
         if s.find('asm_macr_') == -1])

    botan_all_cpp = open('botan_all.cpp', 'w')

    botan_all_cpp.write(amalg_header)

    botan_all_cpp.write('#include "botan_all.h"\n')

    botan_all_cpp.write(internal_header_amalag.header_includes)
    botan_all_cpp.write(internal_header_amalag.contents)


    for src in build_config.sources:
        if src.endswith('.S'):
            continue

        contents = open(src).readlines()
        for line in contents:
            if botan_include.search(line):
                continue
            else:
                botan_all_cpp.write(line)

"""
Finding a program by name
code from http://stackoverflow.com/questions/377017/#377028
"""
def which(program):
    def have_exe(fpath):
        return os.path.exists(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if have_exe(program):
            return program
    else:
        for path in os.environ['PATH'].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if have_exe(exe_file):
                return exe_file

    return None

"""
Main driver
"""
def main(argv = None):
    if argv is None:
        argv = sys.argv

    options = process_command_line(argv[1:])

    def log_level():
        if options.verbose:
            return logging.DEBUG
        if options.quiet:
            return logging.WARNING
        return logging.INFO

    logging.basicConfig(stream = sys.stdout,
                        format = '%(levelname) 7s: %(message)s',
                        level = log_level())

    logging.debug('%s invoked with options "%s"' % (
        argv[0], ' '.join(argv[1:])))

    logging.debug('Platform: OS="%s" machine="%s" proc="%s"' % (
        platform.system(), platform.machine(), platform.processor()))

    if options.os == "java":
        raise Exception("Jython detected: need --os and --cpu to set target")

    options.base_dir = os.path.dirname(argv[0])
    options.src_dir = os.path.join(options.base_dir, 'src')

    options.build_data = os.path.join(options.src_dir, 'build-data')
    options.makefile_dir = os.path.join(options.build_data, 'makefile')

    (modules, archinfo, ccinfo, osinfo) = load_info_files(options)

    if options.os is None:
        options.os = platform.system().lower()
        logging.info('Guessing taget OS is %s (--os to set)' % (options.os))

    if options.compiler is None:
        if options.os == 'windows':
            if which('cl.exe') is not None:
                options.compiler = 'msvc'
            elif which('g++.exe') is not None:
                options.compiler = 'gcc'
            else:
                options.compiler = 'msvc'
        else:
            options.compiler = 'gcc'
        logging.info('Guessing to use compiler %s (--cc to set)' % (
            options.compiler))

    if options.compiler not in ccinfo:
        raise Exception('Unknown compiler "%s"; available options: %s' % (
            options.compiler, ' '.join(sorted(ccinfo.keys()))))

    if options.os not in osinfo:

        def find_canonical_os_name(os):
            for (name, info) in osinfo.items():
                if os in info.aliases:
                    return name
            return os # not found

        options.os = find_canonical_os_name(options.os)

        if options.os not in osinfo:
            raise Exception('Unknown OS "%s"; available options: %s' % (
                options.os, ' '.join(sorted(osinfo.keys()))))

    if options.cpu is None:
        (options.arch, options.cpu) = guess_processor(archinfo)
        logging.info('Guessing target processor is a %s/%s (--cpu to set)' % (
            options.arch, options.cpu))
    else:
        cpu_from_user = options.cpu
        (options.arch, options.cpu) = canon_processor(archinfo, options.cpu)
        logging.info('Canonicalizized --cpu=%s to %s/%s' % (
            cpu_from_user, options.arch, options.cpu))

    logging.info('Target is %s-%s-%s-%s' % (
        options.compiler, options.os, options.arch, options.cpu))

    # Kind of a hack...
    options.extra_flags = ''
    if options.compiler == 'gcc':

        def is_64bit_arch(arch):
            if arch.endswith('64') or arch in ['alpha', 's390x']:
                return True
            return False

        if not is_64bit_arch(options.arch) and not options.dumb_gcc:
            try:
                matching_version = '(4\.[01234]\.)|(3\.[34]\.)|(2\.95\.[0-4])'

                gcc_version = ''.join(subprocess.Popen(
                    ['g++', '-dumpversion'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE).communicate()).strip()

                logging.info('Detected GCC version %s' % (gcc_version))

                if re.search(matching_version, gcc_version):
                    options.dumb_gcc = True
            except OSError:
                logging.warning('Could not execute GCC for version check')

        if options.dumb_gcc is True:
            logging.info('Setting -fpermissive to work around gcc bug')
            options.extra_flags = ' -fpermissive'

    if options.with_tr1 == None:
        options.with_tr1 = ('system' if ccinfo[options.compiler].has_tr1 else 'none')

    if options.gen_amalgamation:
        if options.asm_ok:
            logging.info('Disabling assembly code, cannot use in amalgamation')
            options.asm_ok = False

        for mod in ['sha1_sse2', 'serpent_simd']:
            if mod not in options.disabled_modules:
                logging.info('Disabling %s, cannot use in amalgamation' % (mod))
                options.disabled_modules.append(mod)

    modules_to_use = choose_modules_to_use(modules,
                                           archinfo[options.arch],
                                           options)

    if not osinfo[options.os].build_shared:
        if options.build_shared_lib:
            logging.info('Disabling shared lib on %s' % (options.os))
            options.build_shared_lib = False

    build_config = BuildConfigurationInformation(options, modules_to_use)
    build_config.public_headers.append(
        os.path.join(build_config.build_dir, 'build.h'))

    template_vars = create_template_vars(build_config, options,
                                         modules_to_use,
                                         ccinfo[options.compiler],
                                         archinfo[options.arch],
                                         osinfo[options.os])

    # Performs the I/O
    setup_build(build_config, options, template_vars)

    if options.gen_amalgamation:
        generate_amalgamation(build_config)

    logging.info('Botan %s build setup is complete' % (
        build_config.version_string))

if __name__ == '__main__':
    try:
        main()
    except Exception, e:
        logging.error(str(e))
        #import traceback
        #traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    sys.exit(0)
