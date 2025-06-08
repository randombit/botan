#!/usr/bin/env python3

"""
(C) 2024 Jack Lloyd
(C) 2024 René Meusel - Rohde & Schwarz Cybersecurity

Botan is released under the Simplified BSD License (see license.txt)
"""

# Use this as a script to read the repository's configuration file and access
# its contents. For instance:
#
#   $ python3 repo_config.py all
#   $ python3 repo_config.py get BORINGSSL_REPO
#
# This might also be used as a module to access the configuration file from
# other python scripts.

import argparse
import os
import re
import sys

_DEFAULT_REPO_CONFIG_LOCATION = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'configs', 'repo_config.env'))

class RepoConfig(dict):
    """ Reads the repository's configuration file and provides access to its variables. """

    def __init__(self, env_file: str = _DEFAULT_REPO_CONFIG_LOCATION):
        self._file_path = env_file
        parser = re.compile(r'^(?P<var>\w+)\s*=\s*((?P<val>[^\"]\S+)|\"(?P<quoted_val>\S+)\")\s*$')
        with open(self._file_path, 'r', encoding='utf-8') as f:
            for line in f.readlines():
                if m := parser.match(line):
                    var = m.group('var')
                    val = m.group('val') or m.group('quoted_val')
                    try:
                        self[var] = int(val)
                    except ValueError:
                        self[var] = val

    @property
    def config_file_path(self):
        return self._file_path

def main():
    def print_all(cfg: RepoConfig, *_):
        print('\n'.join(f'{key}={value}' for key, value in cfg.items()))

    def list_vars(cfg: RepoConfig, *_):
        print('\n'.join(key for key in cfg))

    def get_var(cfg: RepoConfig, args):
        if args.var not in cfg:
            print(f'Variable "{args.var}" not found in the configuration file.', file=sys.stderr)
            raise KeyError()
        print(cfg[args.var])

    def print_config_file_path(cfg, *_):
        print(cfg.config_file_path)

    parser = argparse.ArgumentParser(description='Read and process a .env file.')
    subparsers = parser.add_subparsers(dest='command', required=True)

    parser_all = subparsers.add_parser('all', help='Print all variables and their values.')
    parser_all.set_defaults(dispatch=print_all)

    parser_all = subparsers.add_parser('list', help='Print all variable names.')
    parser_all.set_defaults(dispatch=list_vars)

    parser_get = subparsers.add_parser('get', help='Get the value of a specific variable.')
    parser_get.add_argument('var', type=str, help='The variable name to retrieve.')
    parser_get.set_defaults(dispatch=get_var)

    parser_file = subparsers.add_parser('file', help='Print the path to the configuration file.')
    parser_file.set_defaults(dispatch=print_config_file_path)

    args = parser.parse_args()
    try:
        args.dispatch(RepoConfig(), args)
    except Exception:
        return 1

    return 0

if __name__ == '__main__':
    sys.exit(main())
