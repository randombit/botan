#!/bin/bash

# GitHub Actions setup script for Botan build
#
# (C) 2015,2017 Simon Warta
# (C) 2016,2017,2018,2020 Jack Lloyd
#
# Botan is released under the Simplified BSD License (see license.txt)

command -v shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

set -ex

TARGET=$1

if type -p "apt-get"; then
    sudo apt-get -qq update
    sudo apt-get -qq install ccache

    if [ "$TARGET" = "valgrind" ]; then
        sudo apt-get -qq install valgrind

    elif [ "$TARGET" = "clang" ]; then
        sudo apt-get -qq install clang

    elif [ "$TARGET" = "cross-i386" ]; then
        sudo apt-get -qq install g++-multilib linux-libc-dev libc6-dev-i386

    elif [ "$TARGET" = "cross-win64" ]; then
        sudo apt-get -qq install wine-development g++-mingw-w64-x86-64

    elif [ "$TARGET" = "cross-arm64" ]; then
        sudo apt-get -qq install qemu-user g++-aarch64-linux-gnu

    elif [ "$TARGET" = "cross-ppc64" ]; then
        sudo apt-get -qq install qemu-user g++-powerpc64le-linux-gnu

    elif [ "$TARGET" = "cross-android-arm32" ] || [ "$TARGET" = "cross-android-arm64" ]; then
        wget -nv https://dl.google.com/android/repository/"$ANDROID_NDK"-linux-x86_64.zip
        unzip -qq "$ANDROID_NDK"-linux-x86_64.zip

    elif [ "$TARGET" = "baremetal" ]; then
        sudo apt-get -qq install gcc-arm-none-eabi libstdc++-arm-none-eabi-newlib

        echo 'extern "C" void __sync_synchronize() {}' >> src/tests/main.cpp
        echo 'extern "C" void __sync_synchronize() {}' >> src/cli/main.cpp

    elif [ "$TARGET" = "lint" ]; then
        sudo apt-get -qq install pylint

    elif [ "$TARGET" = "coverage" ]; then
        sudo apt-get -qq install g++-8 softhsm2 libtspi-dev lcov python-coverage libboost-all-dev gdb
        pip install --user codecov
        echo "$HOME/.local/bin" >> "$GITHUB_PATH"

        git clone --depth 1 --branch runner-changes https://github.com/randombit/boringssl.git

        sudo chgrp -R "$(id -g)" /var/lib/softhsm/ /etc/softhsm
        sudo chmod g+w /var/lib/softhsm/tokens

        softhsm2-util --init-token --free --label test --pin 123456 --so-pin 12345678
        echo "PKCS11_LIB=/usr/lib/softhsm/libsofthsm2.so" >> "$GITHUB_ENV"

    elif [ "$TARGET" = "docs" ]; then
        sudo apt-get -qq install doxygen python-docutils python3-sphinx
    fi
else
    HOMEBREW_NO_AUTO_UPDATE=1 brew install ccache
fi
