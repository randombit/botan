#!/bin/sh
set -e
which shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

# extra ../ is needed due to ocamlbuild chdiring into _build
ocamlbuild -pkg ctypes.foreign -lflags -cclib,-L../../.. -lflags -cclib,-lbotan-1.11 botan.native
