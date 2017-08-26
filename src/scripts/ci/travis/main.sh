#!/bin/bash
set -ev
which shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

PARENT_DIR=$(dirname "$0")

if [ "$BUILD_MODE" = "lint" ]; then
    "$PARENT_DIR"/lint.sh
else

    ./src/scripts/ci_build.py --build-jobs=2 --with-ccache --os=$TRAVIS_OS_NAME --cc=$CC --cc-bin=$CXX $BUILD_MODE
fi
