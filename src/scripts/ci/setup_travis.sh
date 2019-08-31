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

    elif [ "$BUILD_MODE" = "cross-android-arm32" ] || [ "$BUILD_MODE" = "cross-android-arm64" ]; then
        wget -nv https://dl.google.com/android/repository/"$ANDROID_NDK"-linux-x86_64.zip
        unzip -qq "$ANDROID_NDK"-linux-x86_64.zip

    elif [ "$BUILD_MODE" = "lint" ]; then
        sudo apt-get -qq update
        sudo apt-get install pylint

    elif [ "$BUILD_MODE" = "coverage" ]; then
        # need updated softhsm to avoid https://github.com/opendnssec/SoftHSMv2/issues/239
        sudo add-apt-repository -y ppa:pkg-opendnssec/ppa
        sudo apt-get -qq update
        sudo apt-get install softhsm2 trousers libtspi-dev lcov python-coverage libboost-all-dev golang-1.10 gdb
        pip install --user codecov==2.0.10
        git clone --depth 1 --branch runner-changes https://github.com/randombit/boringssl.git

        sudo chgrp -R "$(id -g)" /var/lib/softhsm/ /etc/softhsm
        sudo mkdir /var/lib/softhsm/tokens
        sudo chmod g+w /var/lib/softhsm/tokens

        softhsm2-util --init-token --free --label test --pin 123456 --so-pin 12345678

    elif [ "$BUILD_MODE" = "docs" ]; then
        sudo apt-get -qq update
        sudo apt-get install doxygen python-docutils

        # Version of Sphinx in 16.04 is too old and dies on enum definitions
        sudo pip install sphinx==1.7.9
    fi

elif [ "$TRAVIS_OS_NAME" = "osx" ]; then
    HOMEBREW_NO_AUTO_UPDATE=1 brew install ccache
fi
