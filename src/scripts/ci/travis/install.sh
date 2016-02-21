#!/bin/sh
set -ev
which shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

if [ "$BUILD_MODE" = "coverage" ]; then
    wget http://ftp.de.debian.org/debian/pool/main/l/lcov/lcov_1.11.orig.tar.gz
    tar -xvf lcov_1.11.orig.tar.gz
    export PREFIX="/tmp"
    make -C lcov-1.11/ install

    pip install --user coverage

    pip install --user codecov
fi

if [ "$TRAVIS_OS_NAME" = "osx" ] && [ "$TARGETOS" != "ios" ]; then
    # Workaround for https://github.com/Homebrew/homebrew/issues/42553
    brew update || brew update

    brew install xz
    brew install python # python2
    brew install python3

    # Boost 1.58 is installed on Travis OS X images
    # brew install boost
fi
