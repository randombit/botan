#!/bin/sh

set -ev

sudo apt-get install -y g++-4.8
sudo apt-get install -y libssl-dev
sudo apt-get install -y libz-dev
sudo apt-get install -y libsqlite3-dev
sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-4.8 90
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-4.8 90
sudo update-alternatives --install /usr/bin/gcov gcov /usr/bin/gcov-4.8 90

if [ "$BUILD_MODE" = "coverage" ]; then
   wget http://ftp.de.debian.org/debian/pool/main/l/lcov/lcov_1.11.orig.tar.gz
   tar -xvf lcov_1.11.orig.tar.gz
   sudo make -C lcov-1.11/ install
   gem install coveralls-lcov
fi
