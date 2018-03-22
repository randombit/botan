#!/usr/bin/env python

"""
Show Botan module dependencies as a list or graph.

Requires graphviz from pip when graphical output is selected:
https://pypi.python.org/pypi/graphviz

(C) 2015,2018 Simon Warta (Kullo GmbH)

Botan is released under the Simplified BSD License (see license.txt)
"""

# global
import argparse
import copy
import sys
import subprocess
from collections import OrderedDict
import glob
import os

# Assume this script is in botan/src/scripts
botan_root = os.path.join(os.path.dirname(sys.argv[0]), "..", "..")

# locale
sys.path.append(botan_root)
from configure import ModuleInfo

parser = argparse.ArgumentParser(description=
    'Show Botan module dependencies. '
    'The output is reduced by indirect dependencies, '
    'i.e. you must look at the result recursively to get all dependencies.')

parser.add_argument('mode',
                    choices=["list", "draw"],
                    help='The output mode')
parser.add_argument('--format',
                    nargs='?',
                    choices=["pdf", "png"],
                    default="pdf",
                    help='The file format (drawing mode only)')
parser.add_argument('--engine',
                    nargs='?',
                    choices=["fdp", "dot"],
                    default="dot",
                    help='The graph engine (drawing mode only)')
parser.add_argument('--all', dest='all', action='store_const',
                    const=True, default=False,
                    help='Show all dependencies. Default: direct dependencies only. (list mode only)')
parser.add_argument('--verbose', dest='verbose', action='store_const',
                    const=True, default=False,
                    help='Verbose output (default: false)')
args = parser.parse_args()

files = []
files += glob.glob(botan_root + '/src/lib/*/*/*/*/*/*/info.txt')
files += glob.glob(botan_root + '/src/lib/*/*/*/*/*/info.txt')
files += glob.glob(botan_root + '/src/lib/*/*/*/*/info.txt')
files += glob.glob(botan_root + '/src/lib/*/*/*/info.txt')
files += glob.glob(botan_root + '/src/lib/*/*/info.txt')
files += glob.glob(botan_root + '/src/lib/*/info.txt')
files += glob.glob(botan_root + '/src/lib/info.txt')
files.sort()

if len(files) == 0:
    print("No info.txt files found.")
    sys.exit(1)

modules = []

def dicts(t): return {k: dicts(t[k]) for k in t}

def paths(t, path = [], level=0):
    ret =  []
    for key in t:
        ret.append(path + [key])
        ret += paths(t[key], path + [key], level+1)
    return ret

if args.verbose:
    print("Getting dependencies from into.txt files ...")

for filename in files:
    (rest, info_txt) = os.path.split(filename)
    (rest, modname) = os.path.split(rest)
    module = ModuleInfo(filename)
    modules.append(module)
    if args.verbose:
        print(module.basename)
        print("\t" + str(set(module.dependencies(None))))

if args.verbose:
    print(str(len(modules)) + " modules:")
    names=[m.basename for m in modules]
    names.sort()
    print(names)
    print("")

if args.verbose:
    print("resolving dependencies ...")

def cartinality(depdict):
    return sum([len(depdict[k]) for k in depdict])

registered_dependencies = dict()
all_dependencies = dict()
direct_dependencies = dict()

for module in modules:
    lst = module.dependencies(None)
    registered_dependencies[module.basename] = set(lst) - set([module.basename])

# Get all_dependencies from registered_dependencies
def add_dependency():
    for key in all_dependencies:
        potentially_new_modules_for_key = None
        new_modules_for_key = None
        for currently_in in all_dependencies[key]:
            if currently_in in all_dependencies:
                potentially_new_modules_for_key = all_dependencies[currently_in] - set([key])
                if not potentially_new_modules_for_key <= all_dependencies[key]:
                    new_modules_for_key = potentially_new_modules_for_key.copy()
                    break
        if new_modules_for_key:
            all_dependencies[key] |= new_modules_for_key
            return


all_dependencies = copy.deepcopy(registered_dependencies)
direct_dependencies = copy.deepcopy(registered_dependencies)

# Sort
all_dependencies = OrderedDict(sorted(all_dependencies.items()))
direct_dependencies = OrderedDict(sorted(direct_dependencies.items()))

#print(direct_dependencies)

last_card = -1
while True:
    card = cartinality(all_dependencies)
    # print(card)
    if card == last_card:
        break
    last_card = card
    add_dependency()

# Return true iff a depends on b,
# i.e. b is in the dependencies of a
def depends_on(a, b):
    if not a in direct_dependencies:
        return False
    else:
        return b in direct_dependencies[a]

def remove_indirect_dependencies():
    for mod in direct_dependencies:
        for one in direct_dependencies[mod]:
            others = direct_dependencies[mod] - set([one])
            for other in others:
                if depends_on(other, one):
                    direct_dependencies[mod].remove(one)
                    return
                    # Go to next mod

last_card = -1
while True:
    card = cartinality(direct_dependencies)
    # print(card)
    if card == last_card:
        break
    last_card = card
    remove_indirect_dependencies()

def openfile(f):
    # pylint: disable=no-member
    # os.startfile is available on Windows only
    if sys.platform.startswith('linux'):
        subprocess.call(["xdg-open", f])
    else:
        os.startfile(f)

if args.verbose:
    print("Done resolving dependencies.")

if args.mode == "list":
    if args.all:
        for key in all_dependencies:
            print(key.ljust(17) + " : " + ", ".join(sorted(all_dependencies[key])))
    else:
        for key in direct_dependencies:
            print(key.ljust(17) + " : " + ", ".join(sorted(direct_dependencies[key])))

if args.mode == "draw":
    import graphviz as gv
    import tempfile

    tmpdir = tempfile.mkdtemp(prefix="botan-")

    g2 = gv.Digraph(format=args.format, engine=args.engine)
    g2.attr('graph', rankdir='RL') # draw horizontally
    for key in direct_dependencies:
        g2.node(key)
        for dep in direct_dependencies[key]:
            g2.edge(key, dep)

    if args.verbose:
        print("Rendering graph ...")
    filename = g2.render(filename='graph', directory=tmpdir)

    if args.verbose:
        print("Opening " + filename + " ...")
    openfile(filename)
