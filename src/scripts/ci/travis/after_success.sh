#!/bin/sh
set -ev
which shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

if [ "$BUILD_MODE" = "coverage" ]; then
    GCOV="/usr/bin/gcov-4.8"
    /tmp/bin/lcov --gcov-tool "$GCOV" --directory . --capture --output-file $(pwd)/coverage.info.in
    /tmp/bin/lcov --gcov-tool "$GCOV" --remove $(pwd)/coverage.info.in 'tests/*' '/usr/*' --output-file $(pwd)/coverage.info
    /tmp/bin/lcov --gcov-tool "$GCOV" --list $(pwd)/coverage.info

    LD_LIBRARY_PATH=. coverage run --branch src/python/botan.py

    codecov
fi
