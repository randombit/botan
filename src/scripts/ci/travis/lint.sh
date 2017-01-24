#!/bin/bash
set -ev
which shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

echo "travis_fold:start:pylint_configure"
python3 -m pylint configure.py
python2 -m pylint configure.py
echo "travis_fold:end:pylint_configure"

echo "travis_fold:start:pylint_botanpy"
python3 -m pylint src/python/botan2.py
python2 -m pylint src/python/botan2.py
echo "travis_fold:end:pylint_botanpy"
