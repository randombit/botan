#!/bin/bash
set -ev
which shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

BUILD_NICKNAME=$(basename "$0" .sh)
BUILD_DIR="./build-$BUILD_NICKNAME"

./configure.py --with-build-dir="$BUILD_DIR" --with-debug-info --cc=clang
make -j 2 -f "$BUILD_DIR"/Makefile
"$BUILD_DIR"/botan-test
