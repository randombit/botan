#!/usr/bin/env python3

# (C) 2025 Jack Lloyd
#     2025 René Meusel, Rohde & Schwarz Cybersecurity
#
# Botan is released under the Simplified BSD License (see license.txt)
#

import subprocess
import os
import sys
import argparse
import tempfile

from textwrap import indent

SCRIPT_LOCATION = os.path.dirname(os.path.abspath(__file__))
GDB_EXTENSION = os.path.join(SCRIPT_LOCATION, "gdb", "strubtest.py")

class StrubTest:
    def __init__(self, symbol, inferior_cmdline, masked_cpuid_bits = None, expect_fail = False):
        self.symbol = symbol
        self.inferior_cmdline = inferior_cmdline
        self.masked_cpuid_bits = masked_cpuid_bits
        self.expect_fail = expect_fail

    @property
    def gdb_command(self):
        return ["gdb", "-x", GDB_EXTENSION,
                       "-ex", f"strubtest {self.symbol}",
                       "-ex", "run",
                       "--batch",
                       "--args", *self.inferior_cmdline]

    @property
    def rendered_gdb_command(self):
        return " ".join([token if " " not in token else f"'{token}'" for token in self.gdb_command])

    @property
    def environment(self):
        return {"BOTAN_CLEAR_CPUID": ",".join(self.masked_cpuid_bits)} if self.masked_cpuid_bits else {}

    @property
    def rendered_environment(self):
        full_env = os.environ.copy()
        full_env.update(self.environment)
        return full_env

    def run(self):
        print(f"Checking {self.symbol}... ", end="")
        try:
            proc = subprocess.run(self.gdb_command, capture_output=True, check=False, env=self.rendered_environment)
        except subprocess.SubprocessError as ex:
            return self._fail("subprocess failure", exception=ex)

        if proc.returncode != 0:
            return self._fail("nonzero error code", proc_result=proc)

        if "Error: " in proc.stderr.decode("utf-8"):
            return self._fail("fail", proc_result=proc, may_be_expected=True)

        if "Success: " in proc.stdout.decode("utf-8"):
            return self._succeed(proc_result=proc)
        else:
            return self._fail("never invoked", proc_result=proc)

    def _print_debug_report(self, proc_result = None, exception = None):
        print(f"    ran: {self.rendered_gdb_command}")

        if self.environment:
            print("    Environment:")
            print(indent("\n".join([f"{k}={v}" for (k,v) in self.environment.items()]), " " * 6))
        if exception:
            print("    Exception:")
            print(indent(str(exception), " " * 6))
        if proc_result:
            if proc_result.stdout:
                print("    stdout:")
                print(indent(proc_result.stdout.decode("utf-8"), " " * 6))
            if proc_result.stderr:
                print("    stderr:")
                print(indent(proc_result.stderr.decode("utf-8"), " " * 6))

    def _fail(self, errmsg, proc_result = None, exception = None, may_be_expected = False):
        if may_be_expected and self.expect_fail:
            print(f"{errmsg} (expected)")
            return True
        else:
            print(errmsg)
            self._print_debug_report(proc_result=proc_result, exception=exception)
            return False

    def _succeed(self, proc_result = None):
        if not self.expect_fail:
            print("ok")
        else:
            print("ok (unexpected)")
            self._print_debug_report(proc_result=proc_result)
        return not self.expect_fail

def dummy_file(size = 1024):
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(os.urandom(size))
        return temp_file.name

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--botan-cli', required=True)
    args = parser.parse_args()

    cli = args.botan_cli
    myfile = dummy_file()

    tests = [
        # This is a self-test, it is expected to fail because the version
        # information is naturally not annotated for stack scrubbing.
        StrubTest("Botan::version_string", [cli, "version", "--full"], expect_fail=True),

        # Below is a list of all strub-annotated symbols. Note that we currently run
        # this on x86_64 only. So platform specific symbols on other architectures are
        # commented out for completeness and easier future extension.

        StrubTest("Botan::SHA_256::compress_digest",          [cli, "hash", "--algo=SHA-256", myfile]),
        StrubTest("Botan::SHA_256::compress_digest_x86",      [cli, "hash", "--algo=SHA-256", myfile]),
        #StrubTest("Botan::SHA_256::compress_digest_armv8",   [cli, "hash", "--algo=SHA-256", myfile]),
        StrubTest("Botan::SHA_256::compress_digest_x86_avx2", [cli, "hash", "--algo=SHA-256", myfile], masked_cpuid_bits=["intel_sha"]),
        StrubTest("Botan::SHA_256::compress_digest_x86_simd", [cli, "hash", "--algo=SHA-256", myfile], masked_cpuid_bits=["intel_sha", "avx2"]),
    ]

    results = [test.run() for test in tests]
    os.remove(myfile)

    return 1 if any(not ok for ok in results) else 0

if __name__ == '__main__':
    sys.exit(main())
