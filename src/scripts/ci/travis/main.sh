#!/bin/bash
set -ev
which shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

PARENT_DIR=$(dirname "$0")

if [ "$BUILD_MODE" = "lint" ]; then
    "$PARENT_DIR"/lint.sh
else
    "$PARENT_DIR"/build.sh
fi
