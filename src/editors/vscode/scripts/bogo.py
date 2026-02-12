#!/usr/bin/env python3

import argparse
import os
from common import run_cmd, get_concurrency


BORING_REPO = "https://github.com/randombit/boringssl.git"
BORING_BRANCH = "rene/runner-20241016"

BORING_PATH = "build_deps/boringssl"
BOGO_PATH = os.path.join(BORING_PATH, "ssl", "test", "runner")

SHIM_PATH = "./botan_bogo_shim"
SHIM_CONFIG_NO_TLS13 = "src/bogo_shim/config_no_tls13.json"
SHIM_CONFIG = "src/bogo_shim/config.json"


def main():
    parser = argparse.ArgumentParser(description='Run BoringSSL Bogo tests with Botan shim')
    parser.add_argument('--without-tls-13', action='store_true',
                        help='Use shim config that disables TLS 1.3')
    parser.add_argument('--wait-for-debugger', action='store_true',
                        help='BoGo waits for some seconds so that we can attach a debugger to the shim')
    parser.add_argument('bogo_args', nargs=argparse.REMAINDER, help='Extra args for the bogo runner')
    args = parser.parse_args()

    # Select config depending on the option
    if args.without_tls_13:
        config_path = SHIM_CONFIG_NO_TLS13
    else:
        config_path = SHIM_CONFIG

    if not os.path.isdir(BORING_PATH):
        # check out our fork of boring ssl
        run_cmd("git clone --depth 1 --branch %s %s %s" %
                (BORING_BRANCH, BORING_REPO, BORING_PATH))

    # make doubly sure we're on the correct branch
    run_cmd("git -C %s checkout %s" % (BORING_PATH, BORING_BRANCH))

    bogo_args = ';'.join(args.bogo_args) if args.bogo_args else ''
    extra_args = "-wait-for-debugger " if args.wait_for_debugger else ""
    extra_args += "-skip-tls13 " if args.without_tls_13 else ""
    extra_args += "-debug -test '%s'" % bogo_args if bogo_args else ''

    run_cmd("go test -pipe -num-workers %d -shim-path %s -shim-config %s %s" %
            (get_concurrency(), os.path.abspath(SHIM_PATH), os.path.abspath(config_path), extra_args),
            BOGO_PATH)

if __name__ == '__main__':
    main()
