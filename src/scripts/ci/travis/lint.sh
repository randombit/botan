#!/bin/bash
set -ev
which shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

# Disabled rules in Python 2 only
# superfluous-parens: needed for print statements
# too-many-locals: variable counting differs from pylint3

echo "travis_fold:start:pylint_configure"
python3 -m pylint configure.py
python2 -m pylint --disable=superfluous-parens,too-many-locals configure.py
echo "travis_fold:end:pylint_configure"

echo "travis_fold:start:pylint_python_unittests"
python3 -m pylint src/scripts/python_uniitests.py
echo "travis_fold:end:pylint_python_unittests"

echo "travis_fold:start:pylint_botanpy"
python3 -m pylint src/python/botan2.py
python2 -m pylint --disable=superfluous-parens,too-many-locals src/python/botan2.py
echo "travis_fold:end:pylint_botanpy"
