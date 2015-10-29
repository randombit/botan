#!/bin/bash

set -ev
which shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

if [ "$BUILD_MODE" = "static" ]; then
    CFG_FLAGS=(--disable-shared --via-amalgamation)
elif [ "$BUILD_MODE" = "shared" ]; then
    CFG_FLAGS=()
elif [ "$BUILD_MODE" = "coverage" ]; then
    CFG_FLAGS=(--with-coverage)
elif [ "$BUILD_MODE" = "sanitizer" ]; then
    CFG_FLAGS=(--with-sanitizer)
fi

if [ "$MODULES" = "min" ]; then
    CFG_FLAGS+=(--minimized-build)
fi

# Workaround for missing update-alternatives
# https://github.com/travis-ci/travis-ci/issues/3668
if [ "$CXX" = "g++" ]; then
    export CXX="/usr/bin/g++-4.8"
fi

# enable ccache
if [ "$TRAVIS_OS_NAME" = "linux" ]; then
    ccache --max-size=30M
    ccache --show-stats

    export CXX="ccache $CXX"
fi

# choose configure flags

MAKE_COMMAND="make -j 2"
INSTALL_DIR="/tmp/botan-installation"
CFG="./configure.py ${CFG_FLAGS[@]} --prefix=$INSTALL_DIR"

if [ $TARGET = "native" ]; then
    $CXX --version
    CFG="$CFG --cc=\"$CC\" --cc-bin=\"$CXX\" --with-bzip2 --with-lzma --with-openssl --with-sqlite --with-zlib"
else

    if [ "$TRAVIS_OS_NAME" = "osx" ]; then

        # On OS X we target iOS/ARM
        MAKE_COMMAND="xcrun --sdk=iphoneos $MAKE_COMMAND"

        if [ "$TARGET" = "arm32" ]; then
            CFG="$CFG --cpu=armv7 --cc=clang --cc-abi-flags=\"-arch armv7 -arch armv7s -stdlib=libc++\""
        elif [ "$TARGET" = "arm64" ]; then
            CFG="$CFG --cpu=armv8-a --cc=clang --cc-abi-flags=\"-arch arm64 -stdlib=libc++\""
        else
            echo "Unknown target $TARGET"
        fi

    else

        # On Linux we target ARM EABI
        if [ "$TARGET" = "arm32" ]; then
            CFG="$CFG --cpu=armv7 --cc-bin=arm-linux-gnueabi-gcc"
        else
            echo "Unknown target $TARGET"
        fi
    fi
fi

# run configure script
eval $CFG

# build
eval $MAKE_COMMAND

# run tests when possible
if [ "$TARGET" = "native" ]; then

   # TODO run arm-eabi tests under qemu
   ./botan-test

   if [ "$MODULES" != "min" ] && [ "$BUILD_MODE" = "shared" ]; then
       python2 --version
       python3 --version
       LD_LIBRARY_PATH=. python2 src/python/botan.py
       LD_LIBRARY_PATH=. python3 src/python/botan.py
   fi

fi

# test installation process
make install

ls -lR $INSTALL_DIR
