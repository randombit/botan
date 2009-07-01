#!/usr/bin/python

import sys
import re
import shlex
import platform
import os.path

from os import walk as os_walk
from optparse import OptionParser, SUPPRESS_HELP

def process_command_line(args):
    parser = OptionParser()

    parser.add_option("--cc", dest="compiler",
                      help="set the desired build compiler")
    parser.add_option("--os", dest="os", default=platform.system().lower(),
                      help="set the target operating system [%default]")
    parser.add_option("--cpu", dest="cpu",
                      help="set the target processor type/model")

    parser.add_option("--prefix", dest="prefix",
                      help="set the base installation directory")

    compat_with_autoconf_options = [
        "bindir",
        "datadir",
        "datarootdir",
        "docdir",
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

    basename = os.path.basename(infofile)
    if basename != 'info.txt':
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

    def __str__(self):
        return "ModuleInfo('%s', '-D%s', add=%s, requires=%s)" % (
            self.realname, self.define, ','.join(self.add),
            ','.join(self.requires))

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

    def __str__(self):
        return "%s - %s" % (self.realname, ','.join(self.aliases))

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
        self.mach_opt = force_to_dict(self.mach_opt)
        self.mach_abi_linking = force_to_dict(self.mach_abi_linking)

    def __str__(self):
        return "%s %s" % (self.realname, self.binary_name)

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

    def __str__(self):
        return self.realname

def guess_processor(archinfo):
    base_proc = platform.machine()
    full_proc = platform.processor()

    full_proc = full_proc.replace(' ', '').lower()

    for junk in ['(tm)', '(r)']:
        full_proc = full_proc.replace(junk, '')

    for ainfo in archinfo:
        if ainfo.basename == base_proc or base_proc in ainfo.aliases:
            for sm_alias in ainfo.submodel_aliases:
                if re.match(sm_alias, full_proc) != None:
                    return ainfo.submodel_aliases[sm_alias]
            for submodel in ainfo.submodels:
                if re.match(submodel, full_proc) != None:
                    return submodel

    # No matches, so just use the base proc type
    return base_proc

def main(argv = None):
    if argv is None:
        argv = sys.argv

    """
    Walk through a directory and find all files named desired_name
    """
    def find_files_named(desired_name, in_path):
        for (dirpath, dirnames, filenames) in os_walk(in_path):
            if desired_name in filenames:
                yield os.path.join(dirpath, desired_name)

    def list_files_in(in_path):
        for (dirpath, dirnames, filenames) in os_walk(in_path):
            for filename in filenames:
                yield os.path.join(dirpath, filename)

    try:
        (options, args) = process_command_line(argv[1:])

        if args != []:
            raise Exception("Unhandled option(s) " + ' '.join(args))

        modules = [ModuleInfo(info) for info in find_files_named('info.txt', 'src')]

        archinfo = [ArchInfo(info) for info in list_files_in('src/build-data/arch')]
        ccinfo = [CompilerInfo(info) for info in list_files_in('src/build-data/cc')]
        osinfo = [OperatingSystemInfo(info) for info in list_files_in('src/build-data/os')]

        if options.cpu is None:
            options.cpu = guess_processor(archinfo)
        if options.compiler is None:
            options.compiler = 'gcc' # FIXME

        for module in modules:
            print module

    except Exception,e:
        print "Exception:", e

if __name__ == '__main__':
    sys.exit(main())
