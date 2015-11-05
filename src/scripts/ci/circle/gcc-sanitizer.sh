#!/bin/bash
set -ev
which shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

BUILD_NICKNAME=$(basename "$0" .sh)
BUILD_DIR="./build-$BUILD_NICKNAME"

# Adding Ubsan here, only added in GCC 4.9
./configure.py --with-build-dir="$BUILD_DIR" --with-debug-info --with-sanitizer --cc-abi-flags='-fsanitize=undefined'
make -j 2 -f "$BUILD_DIR"/Makefile
"$BUILD_DIR"/botan-test
