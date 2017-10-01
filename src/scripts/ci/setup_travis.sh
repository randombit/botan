#!/bin/bash
set -ev
which shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

git clone --depth 1 https://github.com/randombit/botan-ci-tools

if [ "$TRAVIS_OS_NAME" = "linux" ]; then

    # ccache in Trusty is too old, use version from Xenial
    sudo dpkg -i botan-ci-tools/ubuntu/ccache_3.2.4-1_amd64.deb

    if [ "$BUILD_MODE" = "valgrind" ]; then
        sudo apt-get -qq update
        sudo apt-get install valgrind

    elif [ "$BUILD_MODE" = "cross-win32" ]; then
        # See https://github.com/travis-ci/travis-ci/issues/6460
        sudo dpkg --add-architecture i386
        sudo apt-get -qq update # have to run this after --add-architecture
        sudo apt-get install wine g++-mingw-w64-i686 mingw-w64-i686-dev

    elif [ "${BUILD_MODE:0:5}" = "cross" ]; then
         # Need updated qemu
         sudo add-apt-repository -y ppa:ubuntu-cloud-archive/kilo-staging
         sudo apt-get -qq update
         sudo apt-get install qemu-user

         if [ "$BUILD_MODE" = "cross-arm32" ]; then
             sudo apt-get install g++-arm-linux-gnueabihf libc6-dev-armhf-cross
         elif [ "$BUILD_MODE" = "cross-arm64" ]; then
             sudo apt-get install g++-aarch64-linux-gnu libc6-dev-arm64-cross
         elif [ "$BUILD_MODE" = "cross-ppc32" ]; then
             sudo apt-get install g++-powerpc-linux-gnu libc6-dev-powerpc-cross
         elif [ "$BUILD_MODE" = "cross-ppc64" ]; then
             sudo apt-get install g++-powerpc64le-linux-gnu libc6-dev-ppc64el-cross
         fi

    elif [ "$BUILD_MODE" = "lint" ]; then
        pip install --user pylint

        sudo apt-get install python3-pip
        pip3 install --user pylint

    elif [ "$BUILD_MODE" = "coverage" ]; then
        sudo apt-get -qq update
        sudo apt-get install trousers libtspi-dev

        # SoftHSMv1 in 14.04 does not work
        # Installs prebuilt SoftHSMv2 binaries into /tmp
        tar -C / -xvjf botan-ci-tools/softhsm2-trusty-bin.tar.bz2
        /tmp/softhsm/bin/softhsm2-util --init-token --free --label test --pin 123456 --so-pin 12345678

        # need updated lcov for gcc 4.8 coverage format
        sudo dpkg -i botan-ci-tools/ubuntu/lcov_1.12-2_all.deb

        (cd /home/travis/bin && ln -s gcov-4.8 gcov)

        pip install --user coverage
        pip install --user codecov

    elif [ "$BUILD_MODE" = "sonar" ]; then
        sudo apt-get -qq update
        sudo apt-get install trousers libtspi-dev
        # installed llvm-3.4 conflicts with clang-3.9 in /usr/local
        # we need a more recent llvm-cov for coverage reports
        sudo apt-get remove llvm

        tar -C / -xvjf botan-ci-tools/softhsm2-trusty-bin.tar.bz2
        /tmp/softhsm/bin/softhsm2-util --init-token --free --label test --pin 123456 --so-pin 12345678

        wget https://sonarqube.com/static/cpp/build-wrapper-linux-x86.zip
        unzip build-wrapper-linux-x86.zip

    elif [ "$BUILD_MODE" = "docs" ]; then
        sudo apt-get -qq update
        sudo apt-get install doxygen

        # The version of Sphinx in 14.04 is too old (1.2.2) and does not support
        # all C++ features used in the manual. Install python-requests to avoid
        # problem in Ubuntu packaged version, see
        # http://stackoverflow.com/questions/32779919/no-module-named-for-requests
        sudo apt-get remove python-requests python-openssl
        sudo pip install requests sphinx pyopenssl
    fi

elif [ "$TRAVIS_OS_NAME" = "osx" ]; then
    HOMEBREW_NO_AUTO_UPDATE=1 brew install ccache
fi
