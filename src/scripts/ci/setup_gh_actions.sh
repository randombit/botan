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

function build_and_install_jitterentropy() {
    mkdir jitterentropy-library
    curl -L https://github.com/smuellerDD/jitterentropy-library/archive/refs/tags/v3.6.0.tar.gz | tar -xz -C .
    jel_dir="$(realpath jitterentropy-library-*)"
    cmake -B "${jel_dir}/build" -S "${jel_dir}" -DCMAKE_BUILD_TYPE=Release
    cmake --build "${jel_dir}/build"
    sudo cmake --install "${jel_dir}/build"
    echo "BOTAN_BUILD_WITH_JITTERENTROPY=1" >> "$GITHUB_ENV"
    rm -rf "${jel_dir}"
}

if type -p "apt-get"; then
    # TPM2-TSS library (to build the library against)
    tpm2_specific_packages=("libtss2-dev")

    # Our simulated TPM 2.0 setup depends on convenience features that are
    # available only in Ubuntu 24.04. Technically, most of the TPM 2.0 support
    # in Botan should work on 22.04 as well.
    #
    # TODO: Look into whether we can use the TPM 2.0 simulator on 22.04 to be
    #       able to run the tests on that version as well.
    if [ "$(lsb_release -sr)" = "24.04" ]; then
        # Additional TPM 2.0 related packages to set up a simulated
        # TPM 2.0 environment for testing.
        tpm2_specific_packages+=("tpm2-tools"            # CLI tools to interact with the TPM
                                 "swtpm"                 # TPM 2.0 simulator
                                 "swtpm-tools"           # CLI tools to set up the TPM simulator
                                 "tpm2-abrmd"            # user-space resource manager for TPM 2.0
                                 "libtss2-tcti-tabrmd0") # TCTI (TPM Command Transmission Interface) for the user-space resource manager)
        ci_support_of_tpm2="test"
    else
        # If we are not on Ubuntu 24.04, we can't set up a TPM 2.0 simulator
        # and potentially just build the library with TPM 2.0 support but don't
        # run the tests.
        ci_support_of_tpm2="build"
    fi

    if [ "$(lsb_release -sr)" = "22.04" ]; then
        # Hack to deal with https://github.com/actions/runner-images/issues/8659
        sudo rm -f /etc/apt/sources.list.d/ubuntu-toolchain-r-ubuntu-test-jammy.list
        sudo apt-get update
        sudo apt-get install -y --allow-downgrades libc6=2.35-* libc6-dev=2.35-* libstdc++6=12.3.0-* libgcc-s1=12.3.0-*
    fi

    # Normal workflow follows
    sudo apt-get -qq update
    sudo apt-get -qq install ccache libbz2-dev liblzma-dev libsqlite3-dev

    if [ "$TARGET" = "valgrind" ] || [ "$TARGET" = "valgrind-full" ]; then
        # (l)ist mode (avoiding https://github.com/actions/runner-images/issues/9996)
        sudo NEEDRESTART_MODE=l apt-get -qq install valgrind
        build_and_install_jitterentropy

    elif [ "$TARGET" = "static" ]; then
        sudo apt-get -qq install "${tpm2_specific_packages[@]}"
        echo "BOTAN_TPM2_ENABLED=${ci_support_of_tpm2}" >> "$GITHUB_ENV"

    elif [ "$TARGET" = "shared" ]; then
        sudo apt-get -qq install libboost-dev "${tpm2_specific_packages[@]}"
        echo "BOTAN_TPM2_ENABLED=${ci_support_of_tpm2}" >> "$GITHUB_ENV"

    elif [ "$TARGET" = "examples" ] || [ "$TARGET" = "amalgamation" ] || [ "$TARGET" = "tlsanvil" ] || [ "$TARGET" = "clang-tidy" ] ; then
        sudo apt-get -qq install libboost-dev libtss2-dev
        build_and_install_jitterentropy

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

    elif [ "$TARGET" = "cross-ppc32" ]; then
        sudo apt-get -qq install qemu-user g++-powerpc-linux-gnu

    elif [ "$TARGET" = "cross-ppc64" ]; then
        sudo apt-get -qq install qemu-user g++-powerpc64le-linux-gnu

    elif [ "$TARGET" = "cross-sh4" ]; then
        sudo apt-get -qq install qemu-user g++-sh4-linux-gnu

    elif [ "$TARGET" = "cross-sparc64" ]; then
        sudo apt-get -qq install qemu-user g++-sparc64-linux-gnu

    elif [ "$TARGET" = "cross-m68k" ]; then
        sudo apt-get -qq install qemu-user g++-m68k-linux-gnu

    elif [ "$TARGET" = "cross-riscv64" ]; then
        sudo apt-get -qq install qemu-user g++-riscv64-linux-gnu

    elif [ "$TARGET" = "cross-alpha" ]; then
        sudo apt-get -qq install qemu-user g++-alpha-linux-gnu

    elif [ "$TARGET" = "cross-arc" ]; then
        sudo apt-get -qq install qemu-user g++-arc-linux-gnu

    elif [ "$TARGET" = "cross-hppa64" ]; then
        sudo apt-get -qq install qemu-user g++-hppa-linux-gnu

    elif [ "$TARGET" = "cross-mips" ]; then
        sudo apt-get -qq install qemu-user g++-mips-linux-gnu

    elif [ "$TARGET" = "cross-mips64" ]; then
        sudo apt-get -qq install qemu-user g++-mips64-linux-gnuabi64

    elif [ "$TARGET" = "cross-s390x" ]; then
        sudo apt-get -qq install qemu-user g++-s390x-linux-gnu

    elif [ "$TARGET" = "sde" ]; then
        SDE_VER=sde-external-9.38.0-2024-04-18-lin
        wget https://downloadmirror.intel.com/823664/${SDE_VER}.tar.xz
        tar -xvf ${SDE_VER}.tar.xz
        echo ${SDE_VER} >> "$GITHUB_PATH"

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
        wget -nv https://raw.githubusercontent.com/C2SP/x509-limbo/f98aa03f45d108ae4e1bc5a61ec4bd0b8d137559/limbo.json -O "${SCRIPT_LOCATION}/../../../limbo.json"

    elif [ "$TARGET" = "coverage" ] || [ "$TARGET" = "sanitizer" ]; then
        if [ "$TARGET" = "coverage" ]; then
            sudo apt-get -qq install lcov python3-coverage
            curl -L https://coveralls.io/coveralls-linux.tar.gz | tar -xz -C /usr/local/bin
        fi

        sudo apt-get -qq install softhsm2 libtspi-dev libboost-dev "${tpm2_specific_packages[@]}"
        echo "BOTAN_TPM2_ENABLED=${ci_support_of_tpm2}" >> "$GITHUB_ENV"

        echo "$HOME/.local/bin" >> "$GITHUB_PATH"

        sudo chgrp -R "$(id -g)" /var/lib/softhsm/ /etc/softhsm
        sudo chmod g+w /var/lib/softhsm/tokens

        softhsm2-util --init-token --free --label test --pin 123456 --so-pin 12345678
        echo "PKCS11_LIB=/usr/lib/softhsm/libsofthsm2.so" >> "$GITHUB_ENV"

        build_and_install_jitterentropy

    elif [ "$TARGET" = "docs" ]; then
        sudo apt-get -qq install doxygen python3-docutils python3-sphinx

    fi
else
    export HOMEBREW_NO_AUTO_UPDATE=1
    export HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK=1
    brew install ccache

    if [ "$TARGET" = "shared" ]  || [ "$TARGET" = "amalgamation" ] ; then
        brew install boost

        # On Apple Silicon we need to specify the include directory
        # so that the build can find the boost headers.
        boostincdir=$(brew --prefix boost)/include
        echo "BOOST_INCLUDEDIR=$boostincdir" >> "$GITHUB_ENV"
    elif [ "$TARGET" = "emscripten" ]; then
        # Workaround: emscripten 3.1.63 is broken, install an older one...
        brew tap-new botan/local-emscripten
        brew tap --force homebrew/core
        brew extract --version=3.1.61 emscripten botan/local-emscripten
        brew install emscripten@3.1.61
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
