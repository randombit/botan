#!/usr/bin/env python3

"""
Runs all tests inmplemented in `ct_selftest`

(C) 2024 Jack Lloyd
    2024 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity

Botan is released under the Simplified BSD License (see license.txt)
"""

import subprocess
import argparse
import os
import sys
from typing import Self
from enum import StrEnum, auto
import json

def run_command(cmd: list[str], is_text = True):
    """ Run the command . """
    return subprocess.run(cmd, capture_output=True, text=is_text, check=False)

def run_with_valgrind(cmd: list[str]):
    """ Run a command with valgrind. """
    valgrind_args = ['valgrind',
                     '-v',
                     '--error-exitcode=2']
    res = run_command(valgrind_args + cmd, is_text=False)
    # valgrind may output non-utf-8 characters
    res.stdout = res.stdout.decode("utf-8", errors="replace")
    res.stderr = res.stderr.decode("utf-8", errors="replace")
    return res

class ValgrindTest:
    """ A single test from ct_selftest """

    class Status(StrEnum):
        """ Defines the test result status """
        OK = auto()
        WARNING = auto()
        ERROR = auto()
        SKIP = auto()
        UNKNOWN = auto()

    def __init__(self, name, expect_failure, needs_special_config):
        self.name = name
        self.expect_failure = expect_failure
        self.needs_special_config = needs_special_config
        self.status = self.Status.UNKNOWN
        self.stdout = None
        self.stderr = None

    @staticmethod
    def from_line(line: str):
        info = line.split("\t")
        assert len(info) == 3
        return ValgrindTest(name=info[2],
                            expect_failure=info[0] == "true",
                            needs_special_config=info[1] == "true")

    def runnable(self, build_cfg):
        """ Decide whether or not to run this test given build config info """
        if not self.needs_special_config:
            return True

        if not build_cfg:
            return False  # test has special build requirements, but we have no info

        if self.name == "clang_vs_bare_metal_ct_mask":
            return build_cfg["cc_macro"] == "CLANG" and "-Os" in build_cfg["cc_compile_flags"]

        raise LookupError(f"Unknown special config test '{self.name}'")

    def run(self, exe_path: str, build_config):
        """ Run the test and return whether it succeeded """

        if not self.runnable(build_config):
            self.status = self.Status.SKIP
        else:
            result = run_with_valgrind([exe_path, self.name])
            self.stdout = result.stdout
            self.stderr = result.stderr

            if result.returncode == 1:
                # The ct_selftest program reported an error
                self.status = self.Status.WARNING
            else:
                failed = result.returncode != 0
                if failed != self.expect_failure:
                    # Valgrind reported an error (or not), but we expected the opposite
                    self.status = self.Status.ERROR
                else:
                    # Everything behaved as expected
                    self.status = self.Status.OK

        return self.status

    @staticmethod
    def read_test_list(ct_selftest_test_list: str) -> list[Self]:
        """ Read the list of tests from the output of `ct_selftest --list`. """

        return [ValgrindTest.from_line(line) for line in ct_selftest_test_list.split("\n")[2:] if line]


def main(): # pylint: disable=missing-function-docstring
    parser = argparse.ArgumentParser("ct_selftests")
    parser.add_argument("ct_selftest_path", help="Path to the ct_selftest executable")
    parser.add_argument("--build-config-path", help="Path to Botan's build-config.json file", default="")

    args = parser.parse_args()

    # Check if the path is valid
    if not os.path.isfile(args.ct_selftest_path):
        raise FileNotFoundError(f"Invalid path: {args.ct_selftest_path}")

    def find_test_list():
        test_list_result = run_command([args.ct_selftest_path, "--list"])
        if test_list_result.returncode != 0:
            raise RuntimeError("Failed to collect the test list from ct_selftest")
        return ValgrindTest.read_test_list(test_list_result.stdout)

    def open_build_config(build_config_path):
        if not build_config_path:
            return None

        if not os.path.isfile(build_config_path):
            raise FileNotFoundError(f"Invalid path: {build_config_path}")

        with open(build_config_path, encoding="utf-8") as build_info_file:
            return json.load(build_info_file)

    test_list = find_test_list()
    build_config = open_build_config(args.build_config_path)

    for test in test_list:
        print(f"running {test.name}... ", end="", flush=True)
        print(test.run(args.ct_selftest_path, build_config))
        if test.status not in [ValgrindTest.Status.OK, ValgrindTest.Status.SKIP]:
            if test.stdout:
                print("stdout:")
                print(test.stdout)
            if test.stderr:
                print("stderr:")
                print(test.stderr)


if __name__ == '__main__':
    sys.exit(main())
