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

    if [ "$(lsb_release -sr)" = "22.04" ]; then
        # Hack to deal with https://github.com/actions/runner-images/issues/8659
        sudo rm -f /etc/apt/sources.list.d/ubuntu-toolchain-r-ubuntu-test-jammy.list
        sudo apt-get update
        sudo apt-get install -y --allow-downgrades libc6=2.35-* libc6-dev=2.35-* libstdc++6=12.3.0-* libgcc-s1=12.3.0-*
    fi

    # Normal workflow follows
    #sudo apt-get -qq update
    sudo apt-get -qq install ccache libbz2-dev liblzma-dev libsqlite3-dev

    if [ "$TARGET" = "valgrind" ] || [ "$TARGET" = "valgrind-full" ]; then
        # (l)ist mode (avoiding https://github.com/actions/runner-images/issues/9996)
        sudo NEEDRESTART_MODE=l apt-get -qq install valgrind

    elif [ "$TARGET" = "shared" ] || [ "$TARGET" = "examples" ] || [ "$TARGET" = "tlsanvil" ] || [ "$TARGET" = "clang-tidy" ] ; then
        sudo apt-get -qq install libboost-dev

    elif [ "$TARGET" = "clang" ]; then
        sudo apt-get -qq install clang

    elif [ "$TARGET" = "cross-i386" ]; then
        sudo NEEDRESTART_MODE=l apt-get -qq install g++-multilib linux-libc-dev libc6-dev-i386

    elif [ "$TARGET" = "cross-win64" ]; then
        sudo apt-get -qq install wine-development g++-mingw-w64-x86-64

    elif [ "$TARGET" = "cross-arm32" ]; then
        sudo apt-get -qq install qemu-user g++-arm-linux-gnueabihf

    elif [ "$TARGET" = "cross-arm64" ] || [ "$TARGET" = "cross-arm64-amalgamation" ]; then
        sudo apt-get -qq install qemu-user g++-aarch64-linux-gnu

    elif [ "$TARGET" = "cross-ppc64" ]; then
        sudo apt-get -qq install qemu-user g++-powerpc64le-linux-gnu

    elif [ "$TARGET" = "cross-riscv64" ]; then
        sudo apt-get -qq install qemu-user g++-riscv64-linux-gnu

    elif [ "$TARGET" = "cross-mips64" ]; then
        sudo apt-get -qq install qemu-user g++-mips64-linux-gnuabi64

    elif [ "$TARGET" = "cross-s390x" ]; then
        sudo apt-get -qq install qemu-user g++-s390x-linux-gnu

    elif [ "$TARGET" = "cross-android-arm32" ] || [ "$TARGET" = "cross-android-arm64" ] || [ "$TARGET" = "cross-android-arm64-amalgamation" ]; then
        wget -nv https://dl.google.com/android/repository/"$ANDROID_NDK"-linux.zip
        unzip -qq "$ANDROID_NDK"-linux.zip

    elif [ "$TARGET" = "cross-arm32-baremetal" ]; then
        sudo apt-get -qq install gcc-arm-none-eabi libstdc++-arm-none-eabi-newlib

        echo 'extern "C" void __sync_synchronize() {}' >> "${SCRIPT_LOCATION}/../../tests/main.cpp"
        echo 'extern "C" void __sync_synchronize() {}' >> "${SCRIPT_LOCATION}/../../cli/main.cpp"

    elif [ "$TARGET" = "emscripten" ]; then
        sudo apt-get -qq install emscripten

    elif [ "$TARGET" = "lint" ]; then
        sudo apt-get -qq install pylint python3-matplotlib

    elif [ "$TARGET" = "limbo" ]; then
        sudo apt-get -qq install python3-dateutil
        wget -nv https://raw.githubusercontent.com/C2SP/x509-limbo/bd88042508ccfde351b2fee293aebda8971fbebb/limbo.json -O "${SCRIPT_LOCATION}/../../../limbo.json"

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
        sudo apt-get -qq install doxygen python3-docutils python3-sphinx

    fi
else
    export HOMEBREW_NO_AUTO_UPDATE=1
    export HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK=1
    brew install ccache

    if [ "$TARGET" = "shared" ]; then
        brew install boost

        # On Apple Silicon we need to specify the include directory
        # so that the build can find the boost headers.
        boostincdir=$(brew --prefix boost)/include
        echo "BOOST_INCLUDEDIR=$boostincdir" >> "$GITHUB_ENV"
    elif [ "$TARGET" = "emscripten" ]; then
        brew install emscripten
    fi

    if [ -d '/Applications/Xcode_15.3.app/Contents/Developer' ]; then
        sudo xcrun xcode-select --switch '/Applications/Xcode_15.4.app/Contents/Developer'
    else
        sudo xcrun xcode-select --switch '/Applications/Xcode_15.2.app/Contents/Developer'
    fi
fi

# find the ccache cache location and store it in the build job's environment
if type -p "ccache"; then
    cache_location="$( ccache --get-config cache_dir )"
    echo "COMPILER_CACHE_LOCATION=${cache_location}" >> "${GITHUB_ENV}"
fi

echo "CCACHE_MAXSIZE=200M" >> "${GITHUB_ENV}"
