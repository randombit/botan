#!/usr/bin/env python

"""
Show Botan module dependencies as a list or graph.

Requires graphviz from pip when graphical output is selected:
https://pypi.python.org/pypi/graphviz

(C) 2015 Simon Warta (Kullo GmbH)

Botan is released under the Simplified BSD License (see license.txt)
"""

# global
import argparse
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
                    default="fdp",
                    help='The graph engine (drawing mode only)')
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
        print("\t" + str(set(module.dependencies())))

if args.verbose:
    print(str(len(modules)) + " modules:")
    names=[m.basename for m in modules]
    names.sort()
    print(names)
    print("")

if args.verbose:
    print("resolving dependencies ...")

all_dependencies = dict()
direct_dependencies = dict()

for module in modules:
    lst = module.dependencies()
    direct_dependencies[module.basename] = set(lst)

all_dependencies = direct_dependencies.copy()

#print(direct_dependencies)

def cartinality(depdict):
    return sum([len(depdict[k]) for k in depdict])

# Sort
direct_dependencies = OrderedDict(sorted(direct_dependencies.items()))

def depends_on(a, b):
    if not a in all_dependencies:
        return False
    else:
        return b in all_dependencies[a]

def remove_indirect_dependencies():
    for mod in direct_dependencies:
        for one in direct_dependencies[mod]:
            others = direct_dependencies[mod] - set([one])
            for other in others:
                if depends_on(one, other):
                    direct_dependencies[mod].remove(one)
                    return
                    # Go to next mod

last_card = -1
while True:
    card = cartinality(direct_dependencies)
    # print(card)
    if card == last_card:
        break;
    last_card = card
    remove_indirect_dependencies()

def openfile(f):
    if sys.platform.startswith('linux'):
        subprocess.call(["xdg-open", f])
    else:
        os.startfile(f)

if args.verbose:
    print("Done resolving dependencies.")

if args.mode == "list":
    for key in direct_dependencies:
        print(key.ljust(17) + " : " + ", ".join(sorted(direct_dependencies[key])))

if args.mode == "draw":
    import graphviz as gv
    import tempfile

    tmpdir = tempfile.mkdtemp(prefix="botan-")

    g2 = gv.Digraph(format=args.format, engine=args.engine)
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

