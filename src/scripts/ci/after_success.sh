#!/bin/sh

set -ev

if [ "$BUILD_MODE" = "coverage" ]; then
  lcov --directory . --capture --output-file coverage.info
  lcov --remove coverage.info 'tests/*' '/usr/*' --output-file coverage.info
  lcov --list coverage.info
  # Assume that $COVERALLS_REPO_TOKEN might not be set (e.g. pull requests)
  coveralls-lcov --repo-token="$COVERALLS_REPO_TOKEN" coverage.info
fi
