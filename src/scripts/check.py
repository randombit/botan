#!/usr/bin/env python3

"""
Implements the "make check" target

(C) 2020 Jack Lloyd, Rene Meusel

Botan is released under the Simplified BSD License (see license.txt)
"""

import json
import logging
import optparse # pylint: disable=deprecated-module
import os
import subprocess
import sys

def run_and_check(cmd_line, env=None, cwd=None):

    logging.info("Starting %s", ' '.join(cmd_line))

    try:
        proc = subprocess.Popen(cmd_line, cwd=cwd, env=env)
        proc.communicate()
    except OSError as e:
        logging.error("Executing %s failed (%s)", ' '.join(cmd_line), e)

    if proc.returncode != 0:
        logging.error("Error running %s", ' '.join(cmd_line))
        sys.exit(1)


def make_environment(build_shared_lib):
    if not build_shared_lib:
        return None

    env = os.environ.copy()

    def extend_colon_list(k, n):
        env[k] = n if k not in env else ":".join([env[k], n])

    extend_colon_list("DYLD_LIBRARY_PATH", os.path.abspath("."))
    extend_colon_list("LD_LIBRARY_PATH", os.path.abspath("."))

    return env


def parse_options(args):
    parser = optparse.OptionParser()
    parser.add_option('--build-dir', default='build', metavar='DIR',
                      help='specify the botan build directory (default %default)')

    (options, args) = parser.parse_args(args)

    if len(args) > 1:
        raise Exception("Unknown arguments")

    return options


def read_config(config):
    try:
        with open(config, encoding='utf8') as f:
            return json.load(f)
    except OSError as ex:
        raise Exception('Failed to load build config %s - is build dir correct?' % (config)) from ex


def main(args=None):
    if args is None:
        args = sys.argv

    options = parse_options(args)

    cfg = read_config(os.path.join(options.build_dir, 'build_config.json'))

    test_exe = cfg.get('test_exe')
    build_shared_lib = cfg.get('build_shared_lib')

    if not os.path.isfile(test_exe) or not os.access(test_exe, os.X_OK):
        raise Exception("Test binary not built")

    run_and_check([test_exe, "--data-dir=%s" % cfg.get('test_data_dir')],
                  make_environment(build_shared_lib))

    return 0

if __name__ == '__main__':
    sys.exit(main())
