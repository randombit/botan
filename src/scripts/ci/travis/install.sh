#!/bin/bash
set -ev
which shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

if [ "$BUILD_MODE" = "coverage" ]; then
    wget http://ftp.de.debian.org/debian/pool/main/l/lcov/lcov_1.12.orig.tar.gz
    tar -xvf lcov_1.12.orig.tar.gz
    export PREFIX="/tmp"
    make -C lcov-1.12/ install

    pip install --user coverage

    pip install --user codecov
fi

if [ "$BUILD_MODE" = "sonarqube" ]; then
    curl -LsS https://sonarqube.com/static/cpp/build-wrapper-linux-x86.zip > build-wrapper-linux-x86.zip
    unzip build-wrapper-linux-x86.zip
fi

if [ "$TRAVIS_OS_NAME" = "linux" ]; then
    if [ "$BUILD_MODE" = "valgrind" ] || [ "${BUILD_MODE:0:5}" = "cross" ]; then
        sudo apt-get -qq update

        if [ "$BUILD_MODE" = "valgrind" ]; then
            sudo apt-get install valgrind
        elif [ "$BUILD_MODE" = "cross-arm32" ]; then
            sudo apt-get install g++-4.8-arm-linux-gnueabihf libc6-dev-armhf-cross qemu-user
        elif [ "$BUILD_MODE" = "cross-arm64" ]; then
            sudo apt-get install g++-4.8-aarch64-linux-gnu libc6-dev-arm64-cross qemu-user
        elif [ "$BUILD_MODE" = "cross-ppc32" ]; then
            sudo apt-get install g++-4.8-powerpc-linux-gnu libc6-dev-powerpc-cross qemu-user
        elif [ "$BUILD_MODE" = "cross-ppc64" ]; then
            sudo apt-get install g++-4.8-powerpc64le-linux-gnu libc6-dev-ppc64el-cross qemu-user
        elif [ "$BUILD_MODE" = "cross-win32" ]; then
            sudo apt-get install g++-mingw-w64-i686 mingw-w64-i686-dev

            # See https://github.com/travis-ci/travis-ci/issues/6460
            sudo dpkg --add-architecture i386
            sudo apt-get -qq update # have to update again due to adding i386 above
            sudo apt-get install wine
        fi
    fi
fi

if [ "$TRAVIS_OS_NAME" = "osx" ]; then
    # Workaround for https://github.com/Homebrew/homebrew/issues/42553
    brew update || brew update

    brew install ccache

    if [ "$BUILD_MODE" != "cross-arm32" ] && [ "$BUILD_MODE" != "cross-arm64" ]; then
        brew install xz
        brew install python # python2
        brew install python3

        # Boost 1.58 is installed on Travis OS X images
        # brew install boost
    fi

fi
