#!/bin/bash

# Development Container Startup Script
#
# This runs whenever the container starts. Use it to set up common things in the
# repository. The current working directory is always at the repository's root.
#
# (C) 2025 Jack Lloyd
# (C)      René Meusel, Rohde & Schwarz Cybersecurity
#
# Botan is released under the Simplified BSD License (see license.txt)

create_symlink() {
    if [ ! -L "$1" ]; then
        echo "Creating symlink from '$1' to '$2'"
        ln -s "$2" "$1"
    else
        echo "Symlink '$1' already exists"
    fi
}

create_symlink .vscode src/editors/vscode
create_symlink .editorconfig src/editors/editorconfig
create_symlink .clang-format src/configs/clang-format

echo "Setting up git blame to ignore certain commits"
git config --local blame.ignoreRevsFile src/configs/git-blame-ignore-revs
git config --local blame.markIgnoredLines true
