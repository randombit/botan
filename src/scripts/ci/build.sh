#!/bin/sh

set -ev

if [ "$BUILD_MODE" = "static" ]; then
   CFG_FLAGS="--disable-shared --via-amalgamation"
elif [ "$BUILD_MODE" = "shared" ]; then
   CFG_FLAGS=""
elif [ "$BUILD_MODE" = "coverage" ]; then
   # lcov gets confused by symlinks
   CFG_FLAGS="--build-mode=coverage --link-method=copy"
fi

$CXX --version
python configure.py $CFG_FLAGS --cc=$CC --cc-bin=$CXX --with-openssl --with-sqlite --with-zlib
make -j 2
./botan-test
