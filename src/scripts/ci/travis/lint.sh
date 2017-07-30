#!/bin/bash
set -ev
which shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

shopt -s expand_aliases

# Disabled rules in Python 2 only
# superfluous-parens: needed for print statements
# too-many-locals: variable counting differs from pylint3
alias python2_pylint='python2 -m pylint --disable=superfluous-parens,too-many-locals'
alias python3_pylint='python3 -m pylint'

echo "travis_fold:start:pylint_configure"
python2_pylint configure.py
python3_pylint configure.py
echo "travis_fold:end:pylint_configure"

echo "travis_fold:start:pylint_install"
python2_pylint src/scripts/install.py
python3_pylint src/scripts/install.py
echo "travis_fold:end:pylint_configure"

echo "travis_fold:start:pylint_python_unittests"
python3_pylint src/scripts/python_uniitests.py
echo "travis_fold:end:pylint_python_unittests"

echo "travis_fold:start:pylint_botanpy"
python2_pylint src/python/botan2.py
python3_pylint src/python/botan2.py
echo "travis_fold:end:pylint_botanpy"
