#!/bin/bash
set -ev
which shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

if [ "$BUILD_MODE" = "coverage" ]; then
    wget http://ftp.de.debian.org/debian/pool/main/l/lcov/lcov_1.12.orig.tar.gz
    tar -xvf lcov_1.12.orig.tar.gz
    export PREFIX="/tmp"
    make -C lcov-1.12/ install

    pip install --user coverage

    pip install --user codecov
fi

if [ "$BUILD_MODE" = "sonarqube" ]; then
    curl -LsS https://sonarqube.com/static/cpp/build-wrapper-linux-x86.zip > build-wrapper-linux-x86.zip
    unzip build-wrapper-linux-x86.zip
fi

if [ "$TRAVIS_OS_NAME" = "linux" ]; then
    sudo apt-get -qq update

    if [ "$BUILD_MODE" = "docs" ]; then
        sudo apt-get install doxygen

        # The version of Sphinx in 14.04 is too old (1.2.2) and does not support
        # all C++ features used in the manual. Install python-requests to avoid
        # problem in Ubuntu packaged version, see
        # http://stackoverflow.com/questions/32779919/no-module-named-for-requests
        sudo apt-get remove python-requests python-openssl
        sudo pip install requests sphinx pyopenssl
    fi

    if [ "$BUILD_MODE" = "coverage" ]; then
        sudo apt-get install trousers libtspi-dev

        # SoftHSMv1 in 14.04 does not work
        # Installs prebuilt SoftHSMv2 binaries into /tmp
        wget https://www.randombit.net/softhsm2-trusty-bin.tar.bz2
        tar -C / -xvjf softhsm2-trusty-bin.tar.bz2
        /tmp/softhsm/bin/softhsm2-util --init-token --free --label test --pin 123456 --so-pin 12345678
    fi

    if [ "$BUILD_MODE" = "valgrind" ] || [ "${BUILD_MODE:0:5}" = "cross" ]; then
        if [ "$BUILD_MODE" = "valgrind" ]; then
            sudo apt-get install valgrind
        elif [ "$BUILD_MODE" = "cross-win32" ]; then
            sudo apt-get install g++-mingw-w64-i686 mingw-w64-i686-dev

            # See https://github.com/travis-ci/travis-ci/issues/6460
            sudo dpkg --add-architecture i386
            sudo apt-get -qq update # have to update again due to adding i386 above
            sudo apt-get install wine
        else

            # Need updated qemu
            sudo add-apt-repository -y ppa:ubuntu-cloud-archive/kilo-staging
            sudo apt-get -qq update
            sudo apt-get install qemu

            if [ "$BUILD_MODE" = "cross-arm32" ]; then
                sudo apt-get install g++-4.8-arm-linux-gnueabihf libc6-dev-armhf-cross
            elif [ "$BUILD_MODE" = "cross-arm64" ]; then
                sudo apt-get install g++-4.8-aarch64-linux-gnu libc6-dev-arm64-cross
            elif [ "$BUILD_MODE" = "cross-ppc32" ]; then
                sudo apt-get install g++-4.8-powerpc-linux-gnu libc6-dev-powerpc-cross
            elif [ "$BUILD_MODE" = "cross-ppc64" ]; then
                sudo apt-get install g++-4.8-powerpc64le-linux-gnu libc6-dev-ppc64el-cross
            fi
        fi
    fi
fi

if [ "$TRAVIS_OS_NAME" = "osx" ]; then
    # Workaround for https://github.com/Homebrew/homebrew/issues/42553
    brew update || brew update

    brew install ccache

    if [ "$BUILD_MODE" != "cross-arm32" ] && [ "$BUILD_MODE" != "cross-arm64" ]; then
        brew install xz
        # Python2 is already installed
        brew install python3

        # Boost 1.58 is installed on Travis OS X images
        # brew install boost
    fi

fi
