#!/bin/bash
set -ev
which shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

echo "travis_fold:start:pylint"
python3 -m pylint configure.py
python2 -m pylint configure.py
echo "travis_fold:end:pylint"
