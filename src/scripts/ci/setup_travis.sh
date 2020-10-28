#!/bin/bash

# Travis CI setup script for Botan build
#
# (C) 2015,2017 Simon Warta
# (C) 2016,2017,2018 Jack Lloyd

command -v shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

set -ev

if [ "$TRAVIS_OS_NAME" = "linux" ]; then

    if [ "$TARGET" = "valgrind" ]; then
        sudo apt-get -qq update
        sudo apt-get install valgrind

    elif [ "$TARGET" = "gcc4.8" ]; then
        sudo apt-get -qq update
        sudo apt-get install g++-4.8

    elif [ "$TARGET" = "clang8" ]; then
        sudo apt-get -qq update
        sudo apt-get install clang-8

    elif [ "$TARGET" = "cross-i386" ]; then
        sudo apt-get -qq update
        sudo apt-get install g++-multilib linux-libc-dev libc6-dev-i386

    elif [ "$TARGET" = "cross-win64" ]; then
        sudo apt-get -qq update
        sudo apt-get install wine-development g++-mingw-w64-x86-64

    elif [ "$TARGET" = "cross-arm32" ]; then
        sudo dpkg --add-architecture armhf
        sudo apt-get -qq update
        sudo apt-get install g++-arm-linux-gnueabihf
        sudo apt-get install -o APT::Immediate-Configure=0 libc6:armhf libstdc++6:armhf

    elif [ "$TARGET" = "cross-arm64" ]; then
        sudo apt-get -qq update
        sudo apt-get install qemu-user g++-aarch64-linux-gnu

    elif [ "$TARGET" = "cross-ppc32" ]; then
        sudo apt-get -qq update
        sudo apt-get install qemu-user g++-powerpc-linux-gnu

    elif [ "$TARGET" = "cross-ppc64" ]; then
        sudo apt-get -qq update
        sudo apt-get install qemu-user g++-powerpc64le-linux-gnu

    elif [ "$TARGET" = "cross-mips64" ]; then
        sudo apt-get -qq update
        sudo apt-get install qemu-user g++-mips64-linux-gnuabi64

    elif [ "$TARGET" = "cross-android-arm32" ] || [ "$TARGET" = "cross-android-arm64" ]; then
        wget -nv https://dl.google.com/android/repository/"$ANDROID_NDK"-linux-x86_64.zip
        unzip -qq "$ANDROID_NDK"-linux-x86_64.zip

    elif [ "$TARGET" = "baremetal" ]; then
        sudo apt-get -qq update
        sudo apt-get install gcc-arm-none-eabi libstdc++-arm-none-eabi-newlib

        echo 'extern "C" void __sync_synchronize() {}' >> src/tests/main.cpp
        echo 'extern "C" void __sync_synchronize() {}' >> src/cli/main.cpp

    elif [ "$TARGET" = "lint" ]; then
        sudo apt-get -qq update
        sudo apt-get install pylint

    elif [ "$TARGET" = "coverage" ]; then
        sudo apt-get -qq update
        sudo apt-get install g++-8 softhsm2 libtspi-dev lcov python-coverage libboost-all-dev gdb
        pip install --user codecov
        git clone --depth 1 --branch runner-changes-golang1.10 https://github.com/randombit/boringssl.git

        sudo chgrp -R "$(id -g)" /var/lib/softhsm/ /etc/softhsm
        sudo chmod g+w /var/lib/softhsm/tokens

        softhsm2-util --init-token --free --label test --pin 123456 --so-pin 12345678

    elif [ "$TARGET" = "docs" ]; then
        sudo apt-get -qq update
        sudo apt-get install doxygen python-docutils python3-sphinx
    fi

elif [ "$TRAVIS_OS_NAME" = "osx" ]; then
    HOMEBREW_NO_AUTO_UPDATE=1 brew install ccache
fi
