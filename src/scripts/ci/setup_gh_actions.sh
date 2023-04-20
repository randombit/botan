#!/bin/bash

# GitHub Actions setup script for Botan build
#
# (C) 2015,2017 Simon Warta
# (C) 2016,2017,2018,2020 Jack Lloyd
#
# Botan is released under the Simplified BSD License (see license.txt)

command -v shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

set -ex

TARGET="$1"
ARCH="$2"

SCRIPT_LOCATION=$(cd "$(dirname "$0")"; pwd)

if type -p "apt-get"; then
    sudo apt-get -qq update
    sudo apt-get -qq install ccache

    if [ "$TARGET" = "valgrind" ]; then
        sudo apt-get -qq install valgrind

    elif [ "$TARGET" = "shared" ] || [ "$TARGET" = "examples" ] ; then
        sudo apt-get -qq install libboost-dev

    elif [ "$TARGET" = "clang" ]; then
        sudo apt-get -qq install clang

    elif [ "$TARGET" = "cross-i386" ]; then
        sudo apt-get -qq install g++-multilib linux-libc-dev libc6-dev-i386

    elif [ "$TARGET" = "cross-win64" ]; then
        sudo apt-get -qq install wine-development g++-mingw-w64-x86-64

    elif [ "$TARGET" = "cross-arm32" ]; then
        sudo apt-get -qq install qemu-user g++-arm-linux-gnueabihf

    elif [ "$TARGET" = "cross-arm64" ]; then
        sudo apt-get -qq install qemu-user g++-aarch64-linux-gnu

    elif [ "$TARGET" = "cross-ppc64" ]; then
        sudo apt-get -qq install qemu-user g++-powerpc64le-linux-gnu

    elif [ "$TARGET" = "cross-riscv64" ]; then
        sudo apt-get -qq install qemu-user g++-riscv64-linux-gnu

    elif [ "$TARGET" = "cross-arm32-baremetal" ]; then
        sudo apt-get -qq install gcc-arm-none-eabi libstdc++-arm-none-eabi-newlib

        echo 'extern "C" void __sync_synchronize() {}' >> "${SCRIPT_LOCATION}/../../tests/main.cpp"
        echo 'extern "C" void __sync_synchronize() {}' >> "${SCRIPT_LOCATION}/../../cli/main.cpp"

    elif [ "$TARGET" = "emscripten" ]; then
        sudo apt-get -qq install emscripten

    elif [ "$TARGET" = "lint" ]; then
        sudo apt-get -qq install pylint

    elif [ "$TARGET" = "coverage" ] || [ "$TARGET" = "sanitizer" ]; then
        if [ "$TARGET" = "coverage" ]; then
            sudo apt-get -qq install lcov python3-coverage
            curl -L https://coveralls.io/coveralls-linux.tar.gz | tar -xz -C /usr/local/bin
        fi

        sudo apt-get -qq install softhsm2 libtspi-dev libboost-dev

        echo "$HOME/.local/bin" >> "$GITHUB_PATH"

        sudo chgrp -R "$(id -g)" /var/lib/softhsm/ /etc/softhsm
        sudo chmod g+w /var/lib/softhsm/tokens

        softhsm2-util --init-token --free --label test --pin 123456 --so-pin 12345678
        echo "PKCS11_LIB=/usr/lib/softhsm/libsofthsm2.so" >> "$GITHUB_ENV"

    elif [ "$TARGET" = "docs" ]; then
        sudo apt-get -qq install doxygen python-docutils python3-sphinx
    fi
else
    export HOMEBREW_NO_AUTO_UPDATE=1
    brew install ccache

    if [ "$TARGET" = "shared" ]; then
        brew install boost
    fi
fi

# find the ccache cache location and store it in the build job's environment
if type -p "ccache"; then
    cache_location="$( ccache --get-config cache_dir )"
    echo "COMPILER_CACHE_LOCATION=${cache_location}" >> "${GITHUB_ENV}"
fi

echo "CCACHE_MAXSIZE=200M" >> "${GITHUB_ENV}"
