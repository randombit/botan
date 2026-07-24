#!/usr/bin/env python3

import argparse
import os
import sys

from common import get_concurrency, run_cmd


def find_repo_root():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    while not os.path.isfile(os.path.join(current_dir, "news.rst")):
        parent_dir = os.path.dirname(current_dir)
        if parent_dir == current_dir:
            raise RuntimeError("Could not find the repository root")
        current_dir = parent_dir
    return current_dir

REPO_ROOT = find_repo_root()

sys.path.insert(0, os.path.join(REPO_ROOT, 'src', 'scripts'))
from repo_config import RepoConfig  # pylint: disable=wrong-import-position

BORING_PATH = os.path.join(REPO_ROOT, "build_deps", "boringssl")
BOGO_PATH = os.path.join(BORING_PATH, "ssl", "test", "runner")

SHIM_PATH = os.path.join(REPO_ROOT, "botan_bogo_shim")
SHIM_CONFIG_NO_TLS13 = os.path.join(REPO_ROOT, "src", "bogo_shim", "config_no_tls13.json")
SHIM_CONFIG_NO_TLS12 = os.path.join(REPO_ROOT, "src", "bogo_shim", "config_no_tls12.json")
SHIM_CONFIG = os.path.join(REPO_ROOT, "src", "bogo_shim", "config.json")


def main():
    parser = argparse.ArgumentParser(description='Run BoringSSL Bogo tests with Botan shim')
    parser.add_argument('--without-tls-12', action='store_true',
                        help='Use shim config that disables TLS 1.2')
    parser.add_argument('--without-tls-13', action='store_true',
                        help='Use shim config that disables TLS 1.3')
    parser.add_argument('--wait-for-debugger', action='store_true',
                        help='BoGo waits for some seconds so that we can attach a debugger to the shim')
    parser.add_argument('bogo_args', nargs=argparse.REMAINDER, help='Extra args for the bogo runner')
    args = parser.parse_args()

    repo_config = RepoConfig()

    # Select config depending on the option
    if args.without_tls_13:
        config_path = SHIM_CONFIG_NO_TLS13
    elif args.without_tls_12:
        config_path = SHIM_CONFIG_NO_TLS12
    else:
        config_path = SHIM_CONFIG

    if not os.path.isdir(BORING_PATH):
        # check out our fork of boring ssl
        run_cmd("git clone --depth 1 --branch %s https://github.com/%s.git %s" %
                (repo_config["BORINGSSL_BRANCH"], repo_config["BORINGSSL_REPO"], BORING_PATH))

    # make doubly sure we're on the correct branch
    run_cmd("git -C %s checkout %s" % (BORING_PATH, repo_config["BORINGSSL_BRANCH"]))

    bogo_args = ';'.join(args.bogo_args) if args.bogo_args else ''
    extra_args = "-wait-for-debugger " if args.wait_for_debugger else ""
    extra_args += "-skip-tls12 -skip-dtls " if args.without_tls_12 else ""
    extra_args += "-skip-tls13 " if args.without_tls_13 else ""
    extra_args += "-debug -test '%s'" % bogo_args if bogo_args else ''

    run_cmd("go test -pipe -allow-unimplemented -num-workers %d -shim-path %s -shim-config %s %s" %
            (get_concurrency(), SHIM_PATH, config_path, extra_args),
            BOGO_PATH)

if __name__ == '__main__':
    main()
