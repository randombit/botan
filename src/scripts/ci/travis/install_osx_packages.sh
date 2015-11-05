#!/bin/sh
set -ev
which shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

# Workaround for https://github.com/Homebrew/homebrew/issues/42553
brew update || brew update

brew install xz
brew install python # python2
brew install python3
