#!/usr/bin/env python3
# coding=utf8

"""
Botan CI check installation script
This script is used to validate the results of `make install`

(C) 2020 Jack Lloyd, René Meusel, Hannes Rantzsch
(C) 2023 René Meusel

Botan is released under the Simplified BSD License (see license.txt)
"""

import os
import sys
import json
import re
import subprocess

def verify_library(build_config):
    lib_dir = build_config['libdir']
    if not os.path.isdir(lib_dir):
        print('Error: libdir "%s" is not a directory' % lib_dir)
        return False

    found_libs = set([])

    major_version = int(build_config["version_major"])

    if build_config['compiler'] == 'msvc':
        expected_lib_format = r'^botan-%d\.(dll|lib)$' % (major_version)
    elif build_config['os'] == 'macos':
        expected_lib_format = r'^libbotan-%d\.(a|dylib)$' % (major_version)
    else:
        expected_lib_format = r'^libbotan-%d\.(a|so)$' % (major_version)

    lib_re = re.compile(expected_lib_format)

    # Unlike the include dir this may have other random libs in it
    for (_, _, filenames) in os.walk(lib_dir):
        for filename in filenames:
            if lib_re.match(filename) is not None:
                found_libs.add(filename)

    if len(found_libs) == 0:
        print("Could not find any libraries from us")
        return False

    # This should match up the count and names of libraries installed
    # vs the build configuration (eg static lib installed or not)

    return True

def verify_includes(build_config):
    include_dir = build_config['installed_include_dir']
    if not os.path.isdir(include_dir):
        print('Error: installed_include_dir "%s" is not a directory' % include_dir)
        return False

    expected_headers = set(build_config['public_headers'] + build_config['external_headers'])
    found_headers = set([])

    for (_, _, filenames) in os.walk(include_dir):
        for filename in filenames:
            found_headers.add(filename)

    if found_headers != expected_headers:
        missing = expected_headers - found_headers
        extra = found_headers - expected_headers

        if len(missing) > 0:
            print("Missing expected headers: %s" % (" ".join(sorted(missing))))

        if len(extra) > 0:
            print("Have unexpected headers: %s" % (" ".join(sorted(extra))))
        return False

    return True

def verify_cmake_package(build_config):
    if build_config['os'] not in ['windows', 'linux', 'macos']:
        return True # skip (e.g. for mingw)

    cmake_build_dir = os.path.join(build_config['abs_root_dir'], build_config['build_dir'], 'cmake_test')
    cmake_test_dir = os.path.join(build_config['abs_root_dir'], "src", "scripts", "ci", "cmake_tests")

    def cmake_preset():
        if build_config['os'] == 'windows':
            return 'windows_x86_64' if build_config['arch'] == 'x86_64' else 'windows_x86'
        return 'unix'

    def test_target():
        return 'test' if build_config['os'] != 'windows' else 'RUN_TESTS'

    disabled_module = build_config['disabled_mod_list'][0] if build_config['disabled_mod_list'] else None
    if not disabled_module:
        print("Not a single disabled module in this build to use for testing.") # just for good measure
        return False

    try:
        subprocess.run(["cmake", "--preset", cmake_preset(),
                                 "-B", cmake_build_dir,
                                 "-S", cmake_test_dir,
                                 "-DCMAKE_PREFIX_PATH=%s" % build_config['prefix'],
                                 "-DBOTAN_DISABLED_MODULE=%s" % disabled_module], check=True)
        subprocess.run(["cmake", "--build", cmake_build_dir, "--config", "Release"], check=True)
        subprocess.run(["cmake", "--build", cmake_build_dir, "--config", "Release", "--target", test_target()], check=True)
    except RuntimeError as e:
        print("Using the CMake package failed: %s" % str(e))
        return False

    return True

def main(args=None):
    if args is None:
        args = sys.argv

    if len(args) < 2:
        print("Usage: %s <build_config.json>" % args[0])
        return 1

    with open(os.path.join(args[1]), encoding='utf8') as f:
        build_config = json.load(f)

    install_prefix = build_config['prefix']

    if not os.path.isdir(install_prefix):
        print('Error: install_prefix "%s" is not a directory' % install_prefix)
        return 1

    if not verify_includes(build_config):
        return 1

    if not verify_library(build_config):
        return 1

    has_cmake = 'botan_cmake_config' in build_config and 'botan_cmake_version_config' in build_config
    if has_cmake and not verify_cmake_package(build_config):
        return 1

    return 0

if __name__ == '__main__':
    sys.exit(main())
