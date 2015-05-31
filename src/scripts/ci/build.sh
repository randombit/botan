#!/bin/sh

set -ev

if [ "$BUILD_MODE" = "static" ]; then
    CFG_FLAGS="--disable-shared --via-amalgamation"
elif [ "$BUILD_MODE" = "shared" ]; then
   CFG_FLAGS="--build-mode=shared"
elif [ "$BUILD_MODE" = "coverage" ]; then
   # lcov gets confused by symlinks
   CFG_FLAGS="--build-mode=coverage --link-method=copy"
fi

$CXX --version
python configure.py $CFG_FLAGS --cc=$CC --cc-bin=$CXX --with-openssl --with-sqlite --with-zlib
make -j 4
LD_LIBRARY_PATH=. ./botan-test
