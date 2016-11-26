#!/bin/sh

./configure.py --with-debug-info --with-coverage-info --no-optimizations --with-bzip2 --with-lzma --with-sqlite --with-zlib --with-pkcs11 --with-openssl --with-sqlite3

make -l4 -j8 -k
./botan-test --pkcs11-lib=/usr/lib/libsofthsm2.so

lcov --rc lcov_branch_coverage=1 --capture --directory . --output-file coverage.info.raw
lcov --remove coverage.info.raw '/usr/*' --output-file coverage.info
genhtml --rc lcov_branch_coverage=1 coverage.info --output-directory lcov-out
