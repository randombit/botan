#!/bin/bash
set -ev
which shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

if [ "$BUILD_MODE" = "static" ]; then
   CFG_FLAGS=(--disable-shared --via-amalgamation)
elif [ "$BUILD_MODE" = "shared" ]; then
   CFG_FLAGS=()
elif [ "$BUILD_MODE" = "coverage" ]; then
   # lcov gets confused by symlinks
   CFG_FLAGS=(--build-mode=coverage --link-method=copy)
elif [ "$BUILD_MODE" = "sanitizer" ]; then
   CFG_FLAGS=(--build-mode=sanitizer)
fi

if [ "$MODULES" = "min" ]; then
   CFG_FLAGS+=(--no-autoload --enable-modules=base)
fi

# Workaround for missing update-alternatives
# https://github.com/travis-ci/travis-ci/issues/3668
if [ "$CXX" = "g++" ]; then
    export CXX="/usr/bin/g++-4.8"
fi

#enable ccache
if [ "$TRAVIS_OS_NAME" = "linux" ]; then
    ccache --max-size=30M
    ccache --show-stats

    export CXX="ccache $CXX"    
fi

$CXX --version
./configure.py "${CFG_FLAGS[@]}" --cc="$CC" --cc-bin="$CXX" \
    --with-openssl --with-sqlite --with-zlib \
    --prefix=/tmp/botan-installation
make -j 2

if [ "$MODULES" != "min" ]; then
    ./botan-test
fi

make install
