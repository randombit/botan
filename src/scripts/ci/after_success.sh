#!/bin/sh

set -ev

if [ "$BUILD_MODE" = "coverage" ]; then
   GCOV="/usr/bin/gcov-4.8"
   /tmp/usr/bin/lcov --gcov-tool "$GCOV" --directory . --capture --output-file coverage.info
   /tmp/usr/bin/lcov --gcov-tool "$GCOV" --remove coverage.info 'tests/*' '/usr/*' --output-file coverage.info
   /tmp/usr/bin/lcov --gcov-tool "$GCOV" --list coverage.info

   # Assume that $COVERALLS_REPO_TOKEN might not be set (e.g. pull requests)
   coveralls-lcov --repo-token="$COVERALLS_REPO_TOKEN" coverage.info
fi
