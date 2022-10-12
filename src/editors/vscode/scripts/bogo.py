#!/usr/bin/env python3

import os
from common import run_cmd, get_concurrency


boring_repo = "https://github.com/reneme/boringssl.git"
boring_branch = "rene/runner-20220322"

boring_path = "build_deps/boringssl"
bogo_path = os.path.join(boring_path, "ssl", "test", "runner")

shim_path = "./botan_bogo_shim"
shim_config = "src/bogo_shim/config.json"


def main():
    if not os.path.isdir(boring_path):
        # check out our fork of boring ssl
        run_cmd("git clone --depth 1 --branch %s %s %s" %
                (boring_branch, boring_path, boring_path))

    # make doubly sure we're on the correct branch
    run_cmd("git -C %s checkout %s" % (boring_path, boring_branch))

    run_cmd("go test -pipe -num-workers %d -shim-path %s -shim-config %s" %
            (get_concurrency(), os.path.abspath(shim_path), os.path.abspath(shim_config)), BOGO_PATH)


if __name__ == '__main__':
    main()
