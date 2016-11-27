#!/bin/sh

./configure.py --with-debug-info --with-coverage-info --with-bzip2 --with-lzma --with-sqlite --with-zlib --with-pkcs11 --with-openssl --with-sqlite3

make -l4 -j$(nproc) -k
./botan-test --pkcs11-lib=/usr/lib/libsofthsm2.so --run-online-tests

#LCOV_OPTIONS="--rc lcov_branch_coverage=1"
LCOV_OPTIONS=""

rm -f coverage.info coverage.info.raw
lcov $LCOV_OPTIONS --capture --directory . --output-file coverage.info.raw
lcov $LCOV_OPTIONS  --remove coverage.info.raw '/usr/*' --output-file coverage.info
genhtml $LCOV_OPTIONS coverage.info --output-directory lcov-out
