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

    # The -DCMAKE_POLICY_VERSION_MINIMUM=3.5 directive is a workaround because
    # recent versions of CMake refused to configure this project as it still
    # claims compatibility with 2.x releases of CMake which have now fallen out
    # of support.
    #
    #   See also: https://github.com/smuellerDD/jitterentropy-library/issues/147
    cmake -B "${jel_dir}/build" -S "${jel_dir}" -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_POLICY_VERSION_MINIMUM=3.5
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
    echo "BOTAN_BUILD_WITH_ESDM=1" >> "$GITHUB_ENV"
}

if type -p "apt-get"; then
    if [ "$TARGET" = "coverage" ] || [ "$TARGET" = "clang-tidy" ]; then
        build_and_install_jitterentropy
        build_and_install_esdm
    fi
fi
