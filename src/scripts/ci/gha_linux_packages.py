#!/usr/bin/env python3

"""
(C) 2025 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import sys

def gha_linux_packages(target):
    packages = [
        'ccache',
        'libbz2-dev',
        'liblzma-dev',
        'libsqlite3-dev',
    ]

    if target.startswith('valgrind'):
        packages.append('valgrind')

    if target in ['shared', 'coverage', 'amalgamation', 'sanitizer', 'tlsanvil', 'examples', 'clang-tidy']:
        packages.append('libboost-dev')

    if target in ['clang']:
        packages.append('clang')

    if target in ['cross-i386']:
        packages.append('g++-multilib')
        packages.append('linux-libc-dev')
        packages.append('libc6-dev-i386')

    if target in ['cross-win64']:
        packages.append('wine-development')
        packages.append('g++-mingw-w64-x86-64')

    if target in ['cross-arm32']:
        packages.append('qemu-user')
        packages.append('g++-arm-linux-gnueabihf')

    if target in ['cross-arm64', 'cross-arm64-amalgamation']:
        packages.append('qemu-user')
        packages.append('g++-aarch64-linux-gnu')

    if target in ['cross-ppc32']:
        packages.append('qemu-user')
        packages.append('g++-powerpc-linux-gnu')

    if target in ['cross-ppc64']:
        packages.append('qemu-user')
        packages.append('g++-powerpc64le-linux-gnu')

    if target in ['cross-sh4']:
        packages.append('qemu-user')
        packages.append('g++-sh4-linux-gnu')

    if target in ['cross-sparc64']:
        packages.append('qemu-user')
        packages.append('g++-sparc64-linux-gnu')

    if target in ['cross-m68k']:
        packages.append('qemu-user')
        packages.append('g++-m68k-linux-gnu')

    if target in ['cross-riscv64']:
        packages.append('qemu-user')
        packages.append('g++-riscv64-linux-gnu')

    if target in ['cross-alpha']:
        packages.append('qemu-user')
        packages.append('g++-alpha-linux-gnu')

    if target in ['cross-arc']:
        packages.append('qemu-user')
        packages.append('g++-arc-linux-gnu')

    if target in ['cross-hppa64']:
        packages.append('qemu-user')
        packages.append('g++-hppa-linux-gnu')

    if target in ['cross-mips']:
        packages.append('qemu-user')
        packages.append('g++-mips-linux-gnu')

    if target in ['cross-mips64']:
        packages.append('qemu-user')
        packages.append('g++-mips64-linux-gnuabi64')

    if target in ['cross-s390x']:
        packages.append('qemu-user')
        packages.append('g++-s390x-linux-gnu')

    if target in ['cross-arm32-baremetal']:
        packages.append('gcc-arm-none-eabi')
        packages.append('libstdc++-arm-none-eabi-newlib')

    if target in ['emscripten']:
        packages.append('emscripten')

    if target in ['lint']:
        packages.append('pylint')
        packages.append('python3-matplotlib')

    if target in ['limbo']:
        packages.append('python3-dateutil')

    if target in ['coverage']:
        packages.append('lcov')
        packages.append('python3-coverage')

    if target in ['coverage', 'sanitizer']:
        packages.append('softhsm2')
        packages.append('libtspi-dev')     # TPM 1 development library [TODO(Botan4) remove this]
        packages.append('libtss2-dev')     # TPM 2 development library

        # Following are only available on Ubuntu 24.04
        # If we wanted to test building of TPM2 on 22.04 we'd need to restrict these

        packages.append('tpm2-tools')      # CLI tools to interact with the TPM
        packages.append('swtpm')           # TPM 2.0 simulator
        packages.append('swtpm-tools')     # CLI tools to set up the TPM simulator
        packages.append('tpm2-abrmd')      # user-space resource manager for TPM 2.0
        packages.append('libtss2-tcti-tabrmd0') # TCTI (TPM Command Transmission Interface) for the user-space resource manager

    if target in ['docs']:
        packages.append('doxygen')
        packages.append('python3-docutils')
        packages.append('python3-sphinx')

    return packages


def main(args = None):
    if args is None:
        args = sys.argv

    if len(args) != 2:
        print("Unexpected usage: %s <target>" % (args[0]))
        return 1

    target = args[1]

    print(" ".join(gha_linux_packages(target)))

    return 0

if __name__ == '__main__':
    sys.exit(main())
