#!/bin/sh

set -ev

if [ "$TRAVIS_OS_NAME" = "linux" ]; then
   sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
   sudo apt-get update -qq

   sudo apt-get install -y g++-4.8
   sudo apt-get install -y libssl-dev
   sudo apt-get install -y libz-dev
   sudo apt-get install -y libsqlite3-dev
   sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-4.8 90
   sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-4.8 90
   sudo update-alternatives --install /usr/bin/gcov gcov /usr/bin/gcov-4.8 90
fi

if [ "$BUILD_MODE" = "coverage" ]; then
   wget http://ftp.de.debian.org/debian/pool/main/l/lcov/lcov_1.11.orig.tar.gz
   tar -xvf lcov_1.11.orig.tar.gz
   sudo make -C lcov-1.11/ install
   gem install coveralls-lcov
fi
