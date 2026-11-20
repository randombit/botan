#!/usr/bin/env python3
"""Combine Botan's C++ objects and the HQC Rust static library.

(C) 2026 The Botan Authors
Botan is released under the Simplified BSD License (see license.txt)
"""

import argparse
import os
import shlex
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ar', required=True)
    parser.add_argument('--ar-options', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--rust-archive', required=True)
    parser.add_argument('objects', nargs='+')
    args = parser.parse_args()
    ar = shlex.split(args.ar)
    output = os.path.abspath(args.output)
    with tempfile.TemporaryDirectory(prefix='hqc-archive-', dir=os.path.dirname(output)) as work:
        cpp_archive = os.path.join(work, 'cpp.a')
        subprocess.run(ar + shlex.split(args.ar_options) + [cpp_archive] + args.objects, check=True)
        os.symlink(os.path.abspath(args.rust_archive), os.path.join(work, 'rust.a'))
        # ADDLIB copies archive members rather than nesting the Rust archive.
        # Fixed relative names also avoid MRI's restrictions on path quoting.
        subprocess.run(ar + ['-M'], cwd=work, check=True, text=True,
                       input='CREATE combined.a\nADDLIB cpp.a\nADDLIB rust.a\nSAVE\nEND\n')
        os.replace(os.path.join(work, 'combined.a'), output)


if __name__ == '__main__':
    main()
