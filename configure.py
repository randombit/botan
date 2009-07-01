#!/usr/bin/python

import sys
import re
import shlex
from os import walk as os_walk
from os.path import join as os_path_join
from optparse import OptionParser, SUPPRESS_HELP

def process_command_line(args):
    parser = OptionParser()

    parser.add_option("--cc", dest="compiler",
                      help="set the desired build compiler")
    parser.add_option("--os", dest="os",
                      help="set the target operating system")
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


class LexerError(Exception):
    def __init__(self, msg, filename, line):
        self.msg = msg
        self.filename = filename
        self.line = line

    def __str__(self):
        return "%s at %s:%d" % (self.msg, self.filename, self.line)


def lex_me_harder():
    pass


"""
Represents the information about a particular module
"""
class ModuleInfo(object):
    def __init__(self, infofile):
        lex = shlex.shlex(open(infofile), infofile, posix=True)

        self.realname = "<UNKNOWN>"
        self.load_on = "request"
        self.define = None
        self.modset = None
        self.uses_tr1 = False
        self.notes = ''
        self.mp_bits = 0

        self.requires = []
        self.add = []
        self.os = []
        self.arch = []
        self.cc = []
        self.libs = []

        lex.wordchars += '.<>/,'

        token = lex.get_token()
        while token != None:
            match = re.match('<(.*)>', token)

            # Check for a grouping
            if match is not None:
                group = match.group(1)

                if group not in ['add','requires','os','arch','cc','libs']:
                    raise LexerError("Unknown group '%s'" % (group), infofile, lex.lineno)

                end_marker = '</' + group + '>'

                token = lex.get_token()
                while token != None and token != end_marker:
                    self.__dict__[group].append(token)
                    token = lex.get_token()
            # Or single name->value pairs
            elif token in ['realname', 'define', 'load_on', 'modset', 'note', 'mp_bits', 'uses_tr1']:
                self.__dict__[token] = lex.get_token()
            else: # No match -> error
                raise LexerError("Bad token '%s'" % (token), infofile, lex.lineno)

            token = lex.get_token()

        # Coerce to more useful types
        self.mp_bits = int(self.mp_bits)
        self.uses_tr1 == bool(self.uses_tr1)

    def __str__(self):
        return "ModuleInfo('%s', '-D%s', add=%s, requires=%s)" % (
            self.realname, self.define, ','.join(self.add),
            ','.join(self.requires))

class ArchInfo(object):
    def __init__(self, infofile):
        self.realname = "<UNKNOWN>"
        self.default_submodel = None
        self.endian = None
        self.unaligned = 'no'

        self.submodels = []
        #self.aliases = []
        self.submodel_aliases = []

        lex = shlex.shlex(open(infofile), infofile, posix=True)

        lex.wordchars += '.<>/,-'

        token = lex.get_token()
        while token != None:
            match = re.match('<(.*)>', token)

            # Check for a grouping
            if match is not None:
                group = match.group(1)

                if group not in ['aliases','submodels','submodel_aliases']:
                    raise LexerError("Unknown group '%s'" % (group), infofile, lex.lineno)

                end_marker = '</' + group + '>'

                token = lex.get_token()
                while token != None and token != end_marker:
                    if group not in self.__dict__:
                        self.__dict__[group] = []
                    #self.__dict__[group].append(token)
                    token = lex.get_token()
            # Or single name->value pairs
            elif token in ['realname', 'default_submodel', 'endian','unaligned']:
                self.__dict__[token] = lex.get_token()
            else: # No match -> error
                raise LexerError("Bad token '%s'" % (token), infofile, lex.lineno)

            token = lex.get_token()

    def __str__(self):
        return ','.join(self.aliases)

def main(argv = None):
    if argv is None:
        argv = sys.argv

    """
    Walk through a directory and find all files named desired_name
    """
    def find_files_named(desired_name, in_path):
        for (dirpath, dirnames, filenames) in os_walk(in_path):
            if desired_name in filenames:
                yield os_path_join(dirpath, desired_name)

    def list_files_in(in_path):
        for (dirpath, dirnames, filenames) in os_walk(in_path):
            for filename in filenames:
                yield os_path_join(dirpath, filename)

    try:
        (options, args) = process_command_line(argv[1:])

        modules = [ModuleInfo(info) for info in find_files_named('info.txt', 'src')]

        arches = [ArchInfo(info) for info in list_files_in('src/build-data/arch')]

        #print '\n'.join(map(str, modules))
        print '\n'.join(map(str, arches))
    except Exception,e:
        print "Exception:", e

if __name__ == '__main__':
    sys.exit(main())
