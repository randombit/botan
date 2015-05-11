#!/bin/sh

set -ev

apt-get install -y g++-4.8
apt-get install -y libssl-dev
apt-get install -y libz-dev
apt-get install -y libsqlite3-dev
update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-4.8 90
update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-4.8 90
update-alternatives --install /usr/bin/gcov gcov /usr/bin/gcov-4.8 90

if [ "$BUILD_MODE" = "coverage" ]
then
   wget http://ftp.de.debian.org/debian/pool/main/l/lcov/lcov_1.11.orig.tar.gz
   tar -xvf lcov_1.11.orig.tar.gz
   make -C lcov-1.11/ install
   gem install coveralls-lcov
fi
