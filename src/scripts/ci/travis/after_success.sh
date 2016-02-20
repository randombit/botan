#!/bin/sh
set -ev
which shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

if [ "$BUILD_MODE" = "coverage" ]; then
    GCOV="/usr/bin/gcov-4.8"
    /tmp/usr/bin/lcov --gcov-tool "$GCOV" --directory . --capture --output-file coverage.info
    /tmp/usr/bin/lcov --gcov-tool "$GCOV" --remove coverage.info 'tests/*' '/usr/*' --output-file coverage.info
    /tmp/usr/bin/lcov --gcov-tool "$GCOV" --list coverage.info

    LD_LIBRARY_PATH=. coverage run --branch src/python/botan.py

    codecov
fi
