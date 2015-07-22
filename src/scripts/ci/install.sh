#!/bin/sh
set -ev
which shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

if [ "$BUILD_MODE" = "coverage" ]; then
   wget http://ftp.de.debian.org/debian/pool/main/l/lcov/lcov_1.11.orig.tar.gz
   tar -xvf lcov_1.11.orig.tar.gz
   export PREFIX="/tmp"
   make -C lcov-1.11/ install
   gem install coveralls-lcov
fi
