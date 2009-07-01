#!/usr/bin/python

"""
Configuration program for botan
Requires at least python 2.4 (for string.Template)

(C) 2009 Jack Lloyd
Distributed under the terms of the Botan license
"""

import os
import os.path
import platform
import pwd
import re
import shutil
import shlex
import sys
import time

from socket import gethostname
from string import Template
from optparse import OptionParser, SUPPRESS_HELP

def process_command_line(args):
    parser = OptionParser()

    parser.add_option("--cc", dest="compiler",
                      help="set the desired build compiler")
    parser.add_option("--os", dest="os", default=platform.system().lower(),
                      help="set the target operating system [%default]")
    parser.add_option("--cpu", dest="cpu",
                      help="set the target processor type/model")

    parser.add_option("--with-build-dir", dest="build_dir",
                      metavar="DIR", default="build",
                      help="setup the build in DIR [default %default]")

    parser.add_option("--prefix", dest="prefix",
                      help="set the base installation directory")
    parser.add_option("--docdir", dest="docdir", default="docdir",
                      help="set the documentation installation directory")

    compat_with_autoconf_options = [
        "bindir",
        "datadir",
        "datarootdir",
        "dvidir",
        "exec-prefix",
        "htmldir",
        "includedir",
        "infodir",
        "libdir",
        "libexecdir",
        "localedir",
        "localstatedir",
        "mandir",
        "oldincludedir",
        "pdfdir",
        "psdir",
        "sbindir",
        "sharedstatedir",
        "sysconfdir"
        ]

    for opt in compat_with_autoconf_options:
        parser.add_option("--" + opt, dest=opt, help=SUPPRESS_HELP)

    (options, args) = parser.parse_args(args)

    return (options, args)

"""
Generic lexer function for info.txt and src/build-data files
"""
def lex_me_harder(infofile, to_obj, allowed_groups, name_val_pairs):

    class LexerError(Exception):
        def __init__(self, msg, line):
            self.msg = msg
            self.line = line

        def __str__(self):
            return "%s at %s:%d" % (self.msg, infofile, self.line)

    (dirname, basename) = os.path.split(infofile)

    to_obj.lives_in = dirname
    if basename == 'info.txt':
        (dummy,to_obj.basename) = os.path.split(dirname)
    else:
        to_obj.basename = basename

    lex = shlex.shlex(open(infofile), infofile, posix=True)

    lex.wordchars += ':.<>/,-'

    for group in allowed_groups:
        to_obj.__dict__[group] = []
    for (key,val) in name_val_pairs.iteritems():
        to_obj.__dict__[key] = val

    token = lex.get_token()
    while token != None:
        match = re.match('<(.*)>', token)

        # Check for a grouping
        if match is not None:
            group = match.group(1)

            if group not in allowed_groups:
                raise LexerError("Unknown group '%s'" % (group), lex.lineno)

            end_marker = '</' + group + '>'

            token = lex.get_token()
            while token != None and token != end_marker:
                to_obj.__dict__[group].append(token)
                token = lex.get_token()
        elif token in name_val_pairs.keys():
            to_obj.__dict__[token] = lex.get_token()
        else: # No match -> error
            raise LexerError("Bad token '%s'" % (token), lex.lineno)

        token = lex.get_token()

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
                      ['add', 'requires', 'os', 'arch', 'cc', 'libs'],
                      { 'realname': '<UNKNOWN>',
                        'load_on': 'request',
                        'define': None,
                        'modset': None,
                        'uses_tr1': 'false',
                        'note': '',
                        'mp_bits': 0 })

        # Coerce to more useful types
        self.mp_bits = int(self.mp_bits)
        self.uses_tr1 == bool(self.uses_tr1)

        self.add = map(lambda f: os.path.join(self.lives_in, f), self.add)

    def __cmp__(self, other):
        if self.basename < other.basename:
            return -1
        if self.basename == other.basename:
            return 0
        return 1

class ArchInfo(object):
    def __init__(self, infofile):
        lex_me_harder(infofile, self,
                      ['aliases', 'submodels', 'submodel_aliases'],
                      { 'realname': '<UNKNOWN>',
                        'default_submodel': None,
                        'endian': None,
                        'unaligned': 'no'
                        })

        self.submodel_aliases = force_to_dict(self.submodel_aliases)

    def defines(self, target_submodel):
        define = []
        define.append("TARGET_ARCH_IS_%s" % (self.basename.upper()))

        if self.basename != target_submodel:
            define.append("TARGET_CPU_IS_%s" % (target_submodel.upper()))

        if self.endian != None:
            define.append("TARGET_CPU_IS_%s_ENDIAN" % (self.endian.upper()))

        define.append("TARGET_UNALIGNED_LOADSTORE_OK %d" % (self.unaligned == "ok"))

        return "\n".join(["#define BOTAN_" + macro for macro in define])

class CompilerInfo(object):
    def __init__(self, infofile):
        lex_me_harder(infofile, self,
                      ['so_link_flags', 'mach_opt', 'mach_abi_linking'],
                      { 'realname': '<UNKNOWN>',
                        'binary_name': None,
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
                        'dll_import_flags': '',
                        'dll_export_flags': '',
                        'ar_command': '',
                        'makefile_style': '',
                        'compiler_has_tr1': False,
                        })

        self.so_link_flags = force_to_dict(self.so_link_flags)
        self.mach_abi_linking = force_to_dict(self.mach_abi_linking)

        # FIXME: this has weirdness to handle s// ing out bits
        self.mach_opt = force_to_dict(self.mach_opt)

    def defines(self):
        if self.compiler_has_tr1:
            return "#define BOTAN_USE_STD_TR1"
        return ""

class OperatingSystemInfo(object):
    def __init__(self, infofile):
        lex_me_harder(infofile, self,
                      ['aliases', 'target_features', 'supports_shared'],
                      { 'realname': '<UNKNOWN>',
                        'os_type': None,
                        'obj_suffix': 'o',
                        'so_suffix': 'so',
                        'static_suffix': 'a',
                        'ar_command': 'ar crs',
                        'ar_needs_ranlib': False,
                        'install_root': '/usr/local',
                        'header_dir': 'include',
                        'lib_dir': 'lib',
                        'doc_dir': 'share/doc',
                        'install_cmd_data': 'install -m 644',
                        'install_cmd_exec': 'install -m 755'
                        })

    def defines(self):
        define = ["TARGET_OS_IS_%s" % (self.basename.upper())]
        define += ["TARGET_OS_HAS_" + feat.upper() for feat in self.target_features]

        return "\n".join(["#define BOTAN_" + macro for macro in define])

def guess_processor(archinfo):
    base_proc = platform.machine()
    full_proc = platform.processor()

    full_proc = full_proc.replace(' ', '').lower()

    for junk in ['(tm)', '(r)']:
        full_proc = full_proc.replace(junk, '')

    for ainfo in archinfo:
        if ainfo.basename == base_proc or base_proc in ainfo.aliases:
            base_proc = ainfo.basename

            for sm_alias in ainfo.submodel_aliases:
                if re.match(sm_alias, full_proc) != None:
                    return (base_proc,ainfo.submodel_aliases[sm_alias])
            for submodel in ainfo.submodels:
                if re.match(submodel, full_proc) != None:
                    return (base_proc,submodel)

    # No matches, so just use the base proc type
    return (base_proc,base_proc)

def process_template(template, variables):
    class PercentSignTemplate(Template):
        delimiter = '%'

    try:
        template = PercentSignTemplate(''.join(open(template).readlines()))
        return template.substitute(variables)
    except KeyError, e:
        raise Exception("Unbound variable %s in template %s" % (e, template))

def create_template_vars(options, modules, cc, arch, osinfo):
    vars = {}

    vars['version_major'] = 1
    vars['version_minor'] = 8
    vars['version_patch'] = 3
    vars['version'] = '1.8.3'

    vars['timestamp'] = time.ctime()
    vars['user'] = pwd.getpwuid(os.getuid())[0]
    vars['hostname'] = gethostname()
    vars['command_line'] = ' '.join(sys.argv)

    vars['module_defines'] = "\n".join(sorted(["#define BOTAN_HAS_" + m.define
                                               for m in modules if m.define != None]))
    vars['target_os_defines'] = osinfo.defines()
    vars['target_cpu_defines'] = arch.defines(options.cpu)
    vars['target_compiler_defines'] = cc.defines()

    vars['local_config'] = "NO LOCAL CONFIG FOR YOU"

    vars['cc'] = cc.binary_name
    vars['lib_opt'] = cc.lib_opt_flags
    vars['check_opt'] = cc.check_opt_flags
    vars['mach_opt'] = ''
    vars['lang_flags'] = cc.lang_flags
    vars['warn_flags'] = cc.warning_flags
    vars['shared_flags'] = cc.shared_flags
    vars['so_link'] = 'so link command'
    vars['so_version'] = 'SO VERSION'
    vars['so_suffix'] = 'SO'
    vars['dll_export_flags'] = cc.dll_export_flags
    vars['mp_bits'] = 666

    vars['submodel'] = options.cpu
    vars['arch'] = options.arch
    vars['os'] = options.os

    vars['mod_list'] = "\n".join(["%s (%s)" % (m.basename, m.realname)
                                  for m in sorted(modules)])

    vars['link_to'] = ''

    vars['ar_command'] = cc.ar_command

    vars['install_cmd_exec'] = 'install exec'
    vars['install_cmd_data'] = 'install data'
    vars['ranlib_command'] = 'randlib command'
    vars['check_prefix'] = 'check prefix'
    vars['doc_files'] = 'list of doc files'
    vars['doc_src_dir'] = 'doc'
    vars['include_files'] = 'list of include files'
    vars['lib_objs'] = 'list of obj files'
    vars['check_objs'] = 'list of check objs'
    vars['lib_prefix'] = 'lib prefix'
    vars['lib_build_cmds'] = 'lib build commands'
    vars['check_build_cmds'] = 'check build commands'

    vars['static_suffix'] = 'a'

    vars['botan_config'] = 'botan-config'
    vars['botan_pkgconfig'] = 'botan.pc'

    return vars

def choose_modules_to_use(options, modules):
    chosen = []

    for module in modules:
        if module.cc != [] and options.compiler not in module.cc:
            continue

        if module.os != [] and options.os not in module.os:
            continue

        if module.arch != [] and options.arch not in module.arch \
               and options.cpu not in module.arch:
            continue

        chosen.append(module)
    return chosen

def setup_build_tree(options, headers, sources):
    shutil.rmtree(options.build_dir)

    include_dir = os.path.join(options.build_dir, 'include', 'botan')
    checks_dir = os.path.join(options.build_dir, 'checks')
    libobj_dir = os.path.join(options.build_dir, 'lib')

    os.makedirs(include_dir)
    os.makedirs(checks_dir)
    os.makedirs(libobj_dir)

    for header_file in headers:
        shutil.copy(header_file, include_dir)

def main(argv = None):
    if argv is None:
        argv = sys.argv

    (options, args) = process_command_line(argv[1:])

    if args != []:
        raise Exception("Unhandled option(s) " + ' '.join(args))

    """
    Walk through a directory and find all files named desired_name
    """
    def find_files_named(desired_name, in_path):
        for (dirpath, dirnames, filenames) in os.walk(in_path):
            if desired_name in filenames:
                yield os.path.join(dirpath, desired_name)

    def list_files_in(in_path):
        for (dirpath, dirnames, filenames) in os.walk(in_path):
            for filename in filenames:
                yield os.path.join(dirpath, filename)

    modules = [ModuleInfo(info)
               for info in find_files_named('info.txt', 'src')]

    archinfo = [ArchInfo(info)
                for info in list_files_in('src/build-data/arch')]
    ccinfo   = [CompilerInfo(info)
                for info in list_files_in('src/build-data/cc')]
    osinfo   = [OperatingSystemInfo(info)
                for info in list_files_in('src/build-data/os')]

    # FIXME: need full canonicalization to (arch,submodel) when --cpu is used
    if options.cpu is None:
        (options.arch,options.cpu) = guess_processor(archinfo)
    else:
        options.arch = options.cpu

    # FIXME: epic fail
    if options.compiler is None:
        options.compiler = 'gcc'

    modules_to_use = choose_modules_to_use(options, modules)

    def find_it(what, infoset):
        for info in infoset:
            if info.basename == what:
                return info
        return None

    template_vars = create_template_vars(options, modules_to_use,
                                         find_it(options.compiler, ccinfo),
                                         find_it(options.arch, archinfo),
                                         find_it(options.os, osinfo))

    #headers = [file for file in all_files if file.endswith('.h')]
    #sources = list(set(all_files) - set(headers))
    #setup_build_tree(options, headers, sources)

    print process_template('src/build-data/buildh.in', template_vars)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception, e:
        print >>sys.stderr, "Exception:", e
