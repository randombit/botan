#!/bin/bash

# GitHub Actions setup script for Botan build
# (runs after build environment is set up)
#
# (C) 2025 Jack Lloyd
# (C) 2025 René Meusel
#
# Botan is released under the Simplified BSD License (see license.txt)

command -v shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

set -ex

TARGET="$1"

SCRIPT_LOCATION=$(cd "$(dirname "$0")"; pwd)

function build_and_install_jitterentropy() {
    mkdir jitterentropy-library
    curl -L "https://github.com/smuellerDD/jitterentropy-library/archive/refs/tags/v${JITTERENTROPY_VERSION}.tar.gz" | tar -xz -C .
    jel_dir="$(realpath jitterentropy-library-*)"
    cmake -B "${jel_dir}/build" -S "${jel_dir}" -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER_LAUNCHER=ccache
    cmake --build "${jel_dir}/build"
    sudo cmake --install "${jel_dir}/build"
    echo "BOTAN_BUILD_WITH_JITTERENTROPY=1" >> "$GITHUB_ENV"
    rm -rf "${jel_dir}"
}

function build_and_install_esdm() {
    # build dependencies
    sudo apt-get -qq install libprotobuf-c-dev meson

    # download, build and install ESDM
    curl -L "https://github.com/smuellerDD/esdm/archive/refs/tags/v${ESDM_VERSION}.tar.gz" | tar -xz -C .
    pushd "$(realpath esdm-*)"
    meson setup build -Dselinux=disabled -Dais2031=false -Dlinux-devfiles=disabled -Des_jent=disabled --prefix=/usr --libdir=lib
    meson compile -C build
    sudo meson install -C build
    popd
}

if type -p "apt-get"; then
    if [ "$TARGET" = "valgrind" ] || [ "$TARGET" = "valgrind-full" ] || [ "$TARGET" = "valgrind-ct-full" ] || [ "$TARGET" = "valgrind-ct" ] || \
       [ "$TARGET" = "examples" ] || [ "$TARGET" = "amalgamation" ] || [ "$TARGET" = "tlsanvil" ] || [ "$TARGET" = "clang-tidy" ] ; then
        build_and_install_jitterentropy

    elif [ "$TARGET" = "shared" ]; then
        build_and_install_esdm

    elif [ "$TARGET" = "coverage" ] || [ "$TARGET" = "sanitizer" ]; then
        build_and_install_jitterentropy
        build_and_install_esdm

    fi
fi
