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
COMPILER="$2"

# shellcheck disable=SC2034
ARCH="$3"

SCRIPT_LOCATION=$(cd "$(dirname "$0")"; pwd)

if [ "$GITHUB_ACTIONS" != "true" ]; then
    echo "This script should only run in a Github Actions environment" >&2
    exit 1
fi

if [ -z "$REPO_CONFIG_LOADED" ]; then
    echo "Repository configuration not loaded" >&2
    exit 1
fi

if type -p "apt-get"; then

    sudo rm /var/lib/man-db/auto-update

    sudo apt-get -qq update
    # shellcheck disable=SC2046
    sudo apt-get -qq install $("${SCRIPT_LOCATION}"/gha_linux_packages.py "$TARGET" "$COMPILER")

    if [ "$TARGET" = "sde" ]; then
        wget -nv "https://downloadmirror.intel.com/823664/${INTEL_SDE_VERSION}.tar.xz"
        tar -xf "${INTEL_SDE_VERSION}.tar.xz"
        echo "${INTEL_SDE_VERSION}" >> "$GITHUB_PATH"

        echo "CXX=g++-14" >> "$GITHUB_ENV"

    elif [ "$TARGET" = "cross-android-arm32" ] || [ "$TARGET" = "cross-android-arm64" ] || [ "$TARGET" = "cross-android-arm64-amalgamation" ]; then
        wget -nv "https://dl.google.com/android/repository/${ANDROID_NDK}-linux.zip"
        unzip -qq "$ANDROID_NDK"-linux.zip

    elif [ "$TARGET" = "cross-arm32-baremetal" ]; then
        echo 'extern "C" void __sync_synchronize() {}' >> "${SCRIPT_LOCATION}/../../tests/main.cpp"
        echo 'extern "C" void __sync_synchronize() {}' >> "${SCRIPT_LOCATION}/../../cli/main.cpp"

    elif [ "$TARGET" = "limbo" ]; then
        wget -nv "https://raw.githubusercontent.com/C2SP/x509-limbo/${LIMBO_TEST_SUITE_REVISION}/limbo.json" -O "${SCRIPT_LOCATION}/../../../limbo.json"

    elif [ "$TARGET" = "coverage" ] || [ "$TARGET" = "sanitizer" ]; then
        if [ "$TARGET" = "coverage" ]; then
            curl -L https://coveralls.io/coveralls-linux.tar.gz | tar -xz -C /usr/local/bin
        fi

        echo "BOTAN_TPM2_ENABLED=test" >> "$GITHUB_ENV"

        echo "$HOME/.local/bin" >> "$GITHUB_PATH"

        sudo chgrp -R "$(id -g)" /var/lib/softhsm/ /etc/softhsm
        sudo chmod g+w /var/lib/softhsm/tokens

        softhsm2-util --init-token --free --label test --pin 123456 --so-pin 12345678
        echo "PKCS11_LIB=/usr/lib/softhsm/libsofthsm2.so" >> "$GITHUB_ENV"
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
        brew install emscripten
    fi

    if [ -d '/Applications/Xcode_16.1.app/Contents/Developer' ]; then
        sudo xcrun xcode-select --switch '/Applications/Xcode_16.1.app/Contents/Developer'
    else
        sudo xcrun xcode-select --switch '/Applications/Xcode_15.2.app/Contents/Developer'
    fi
fi

# find the ccache cache location and store it in the build job's environment
if type -p "ccache"; then
    cache_location="$( ccache --get-config cache_dir )"
    echo "COMPILER_CACHE_LOCATION=${cache_location}" >> "${GITHUB_ENV}"
fi

echo "BOTAN_CLANG_TIDY_CACHE=$HOME/botan_clang_tidy.db" >> "${GITHUB_ENV}"
