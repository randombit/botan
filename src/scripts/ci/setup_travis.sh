#!/bin/bash

# Travis CI setup script for Botan build
#
# (C) 2015,2017 Simon Warta
# (C) 2016,2017,2018 Jack Lloyd

command -v shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

set -ev

if [ "$TRAVIS_OS_NAME" = "linux" ]; then

    if [ "$BUILD_MODE" = "valgrind" ]; then
        sudo apt-get -qq update
        sudo apt-get install valgrind

    elif [ "$BUILD_MODE" = "gcc4.8" ]; then
        sudo apt-get -qq update
        sudo apt-get install g++-4.8

    elif [ "$BUILD_MODE" = "cross-i386" ]; then
        sudo apt-get -qq update
        sudo apt-get install g++-multilib linux-libc-dev libc6-dev-i386

    elif [ "$BUILD_MODE" = "cross-win64" ]; then
        sudo apt-get -qq update
        sudo apt-get install wine g++-mingw-w64-x86-64

    elif [ "$BUILD_MODE" = "cross-arm32" ]; then
        sudo apt-get -qq update
        sudo apt-get install qemu-user g++-arm-linux-gnueabihf

    elif [ "$BUILD_MODE" = "cross-arm64" ]; then
        sudo apt-get -qq update
        sudo apt-get install qemu-user g++-aarch64-linux-gnu

    elif [ "$BUILD_MODE" = "cross-ppc32" ]; then
        sudo apt-get -qq update
        sudo apt-get install qemu-user g++-powerpc-linux-gnu

    elif [ "$BUILD_MODE" = "cross-ppc64" ]; then
        sudo apt-get -qq update
        sudo apt-get install qemu-user g++-powerpc64le-linux-gnu

    elif [ "$BUILD_MODE" = "cross-mips64" ]; then
        sudo apt-get -qq update
        sudo apt-get install qemu-user g++-mips64-linux-gnuabi64

    elif [ "$BUILD_MODE" = "lint" ]; then
        sudo apt-get -qq update
        sudo apt-get install pylint

    elif [ "$BUILD_MODE" = "coverage" ]; then
        sudo apt-get -qq update
        sudo apt-get install trousers libtspi-dev lcov python-coverage

        git clone --depth 1 https://github.com/randombit/botan-ci-tools

        # FIXME use distro softhsm2 package instead
        # need to figure out ownership problem
        # Installs prebuilt SoftHSMv2 binaries into /tmp
        tar -C / -xvjf botan-ci-tools/softhsm2-trusty-bin.tar.bz2
        /tmp/softhsm/bin/softhsm2-util --init-token --free --label test --pin 123456 --so-pin 12345678

        pip install --user codecov==2.0.10

    elif [ "$BUILD_MODE" = "docs" ]; then
        sudo apt-get -qq update
        sudo apt-get install doxygen python-docutils

        # Version of Sphinx in 16.04 is too old and dies on enum definitions
        sudo pip install sphinx==1.7.9
    fi

elif [ "$TRAVIS_OS_NAME" = "osx" ]; then
    HOMEBREW_NO_AUTO_UPDATE=1 brew install ccache
fi
