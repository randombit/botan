#!/usr/bin/env python3

"""
Unittests for Botan Python scripts.

Requires Python 3.

(C) 2017 Simon Warta (Kullo GmbH)

Botan is released under the Simplified BSD License (see license.txt)
"""

import sys
import unittest

sys.path.append("../..") # Botan repo root
from configure import CompilerDetector # pylint: disable=wrong-import-position
from configure import ModulesChooser # pylint: disable=wrong-import-position


class CompilerDetection(unittest.TestCase):

    def test_gcc_invalid(self):
        detector = CompilerDetector("gcc", "g++", "linux")

        compiler_out = ""
        self.assertEqual(detector.version_from_compiler_output(compiler_out), None)
        compiler_out = "gcc version 20170406 (Ubuntu 6.3.0-12ubuntu2)"
        self.assertEqual(detector.version_from_compiler_output(compiler_out), None)

    def test_clang_invalid(self):
        detector = CompilerDetector("clang", "clang++", "linux")

        compiler_out = ""
        self.assertEqual(detector.version_from_compiler_output(compiler_out), None)
        compiler_out = "clang version 20170406."
        self.assertEqual(detector.version_from_compiler_output(compiler_out), None)

    def test_msvc_invalid(self):
        detector = CompilerDetector("msvc", "cl.exe", "windows")

        compiler_out = ""
        self.assertEqual(detector.version_from_compiler_output(compiler_out), None)
        compiler_out = "Microsoft (R) C/C++ Optimizing Compiler Version 19.00.24213.1 for x86"
        self.assertEqual(detector.version_from_compiler_output(compiler_out), None)

    def test_gcc_version(self):
        detector = CompilerDetector("gcc", "g++", "linux")
        compiler_out = """Using built-in specs.
COLLECT_GCC=/usr/bin/gcc
COLLECT_LTO_WRAPPER=/usr/lib/gcc/x86_64-linux-gnu/6/lto-wrapper
Target: x86_64-linux-gnu
Configured with: ../src/configure -v --with-pkgversion='Ubuntu 6.3.0-12ubuntu2' --with-bugurl=file:///usr/share/doc/gcc-6/README.Bugs --enable-languages=c,ada,c++,java,go,d,fortran,objc,obj-c++ --prefix=/usr --program-suffix=-6 --program-prefix=x86_64-linux-gnu- --enable-shared --enable-linker-build-id --libexecdir=/usr/lib --without-included-gettext --enable-threads=posix --libdir=/usr/lib --enable-nls --with-sysroot=/ --enable-clocale=gnu --enable-libstdcxx-debug --enable-libstdcxx-time=yes --with-default-libstdcxx-abi=new --enable-gnu-unique-object --disable-vtable-verify --enable-libmpx --enable-plugin --enable-default-pie --with-system-zlib --disable-browser-plugin --enable-java-awt=gtk --enable-gtk-cairo --with-java-home=/usr/lib/jvm/java-1.5.0-gcj-6-amd64/jre --enable-java-home --with-jvm-root-dir=/usr/lib/jvm/java-1.5.0-gcj-6-amd64 --with-jvm-jar-dir=/usr/lib/jvm-exports/java-1.5.0-gcj-6-amd64 --with-arch-directory=amd64 --with-ecj-jar=/usr/share/java/eclipse-ecj.jar --with-target-system-zlib --enable-objc-gc=auto --enable-multiarch --disable-werror --with-arch-32=i686 --with-abi=m64 --with-multilib-list=m32,m64,mx32 --enable-multilib --with-tune=generic --enable-checking=release --build=x86_64-linux-gnu --host=x86_64-linux-gnu --target=x86_64-linux-gnu
Thread model: posix
gcc version 6.3.0 20170406 (Ubuntu 6.3.0-12ubuntu2)"""
        self.assertEqual(detector.version_from_compiler_output(compiler_out), "6.3")

    def test_clang_version(self):
        detector = CompilerDetector("clang", "clang++", "linux")
        compiler_out = """clang version 4.0.0-1ubuntu1 (tags/RELEASE_400/rc1)
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/bin
Found candidate GCC installation: /usr/bin/../lib/gcc/i686-linux-gnu/6
Found candidate GCC installation: /usr/bin/../lib/gcc/i686-linux-gnu/6.3.0
Found candidate GCC installation: /usr/bin/../lib/gcc/x86_64-linux-gnu/4.9
Found candidate GCC installation: /usr/bin/../lib/gcc/x86_64-linux-gnu/4.9.4
Found candidate GCC installation: /usr/bin/../lib/gcc/x86_64-linux-gnu/5
Found candidate GCC installation: /usr/bin/../lib/gcc/x86_64-linux-gnu/5.4.1
Found candidate GCC installation: /usr/bin/../lib/gcc/x86_64-linux-gnu/6
Found candidate GCC installation: /usr/bin/../lib/gcc/x86_64-linux-gnu/6.3.0
Found candidate GCC installation: /usr/lib/gcc/i686-linux-gnu/6
Found candidate GCC installation: /usr/lib/gcc/i686-linux-gnu/6.3.0
Found candidate GCC installation: /usr/lib/gcc/x86_64-linux-gnu/4.9
Found candidate GCC installation: /usr/lib/gcc/x86_64-linux-gnu/4.9.4
Found candidate GCC installation: /usr/lib/gcc/x86_64-linux-gnu/5
Found candidate GCC installation: /usr/lib/gcc/x86_64-linux-gnu/5.4.1
Found candidate GCC installation: /usr/lib/gcc/x86_64-linux-gnu/6
Found candidate GCC installation: /usr/lib/gcc/x86_64-linux-gnu/6.3.0
Selected GCC installation: /usr/bin/../lib/gcc/x86_64-linux-gnu/6.3.0
Candidate multilib: .;@m64
Selected multilib: .;@m64"""
        self.assertEqual(detector.version_from_compiler_output(compiler_out), "4.0")

    def test_clang_version_two_digit(self):
        # Output from Crystax NDK. Note: there is a trailing whitespace behind the version
        # number for whatever reason. But let's keep the original output unchanged.
        # pylint: disable=trailing-whitespace
        detector = CompilerDetector("clang", "clang++", "android")
        compiler_out = """clang version 3.7 
Target: i686-none-linux-android
Thread model: posix
Found candidate GCC installation: /foo/crystax-toolchains/x86/bin/../lib/gcc/i686-linux-android/4.9
Selected GCC installation: /foo/crystax-toolchains/x86/bin/../lib/gcc/i686-linux-android/4.9
Candidate multilib: .;@m32
Selected multilib: .;@m32"""
        self.assertEqual(detector.version_from_compiler_output(compiler_out), "3.7")

    def test_clang_version_appleclang(self):
        detector = CompilerDetector("clang", "clang++", "darwin")
        compiler_out = """Apple LLVM version 8.1.0 (clang-802.0.42)
Target: x86_64-apple-darwin16.7.0
Thread model: posix
InstalledDir: /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin"""
        self.assertEqual(detector.version_from_compiler_output(compiler_out), "3.9")

        compiler_out = """Apple LLVM version 9.0.0 (clang-900.0.35)
Target: x86_64-apple-darwin16.7.0
Thread model: posix
InstalledDir: /Applications/Xcode-beta.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin"""
        self.assertEqual(detector.version_from_compiler_output(compiler_out), "4.0")

    def test_clang_version_appleclang_intermediate(self):
        # fake versions in between the knwon ones
        # clang-700.0.0 is lower than all known versions
        # clang-802.1.0 is a minor update of known clang-802
        # clang-1111.9.99 is a random future value
        detector = CompilerDetector("clang", "clang++", "darwin")

        compiler_out = """Apple LLVM version 7.0.0 (clang-700.0.0)
Target: x86_64-apple-darwin16.7.0
Thread model: posix
InstalledDir: /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin"""
        self.assertEqual(detector.version_from_compiler_output(compiler_out), "3.7")

        compiler_out = """Apple LLVM version 8.1.1 (clang-802.1.0)
Target: x86_64-apple-darwin16.7.0
Thread model: posix
InstalledDir: /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin"""
        self.assertEqual(detector.version_from_compiler_output(compiler_out), "3.9")

        compiler_out = """Apple LLVM version 11.11.0 (clang-1111.9.99)
Target: x86_64-apple-darwin16.7.0
Thread model: posix
InstalledDir: /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin"""
        self.assertEqual(detector.version_from_compiler_output(compiler_out), "4.0")

    def test_msvc_version(self):
        detector = CompilerDetector("msvc", "cl.exe", "windows")
        compiler_out = """msvc_version.c

1900
"""
        self.assertEqual(detector.version_from_compiler_output(compiler_out), "19.0")

        compiler_out = """msvc_version.c

1910
"""
        self.assertEqual(detector.version_from_compiler_output(compiler_out), "19.10")


class ModulesChooserResolveDependencies(unittest.TestCase):
    def test_base(self):
        available_modules = set(["A", "B"])
        table = {
            "A": [],
        }
        ok, modules = ModulesChooser.resolve_dependencies(available_modules, table, "A")
        self.assertTrue(ok)
        self.assertEqual(modules, set(["A"]))

    def test_no_dependencies_defined(self):
        available_modules = set(["A", "B"])
        table = {
            "A": [],
        }
        with self.assertRaises(KeyError):
            ModulesChooser.resolve_dependencies(available_modules, table, "B")

        available_modules = set(["A", "B"])
        table = {
            "A": ["B"],
        }
        with self.assertRaises(KeyError):
            ModulesChooser.resolve_dependencies(available_modules, table, "A")

    def test_add_dependency(self):
        available_modules = set(["A", "B"])
        table = {
            "A": ["B"],
            "B": []
        }
        ok, modules = ModulesChooser.resolve_dependencies(available_modules, table, "A")
        self.assertTrue(ok)
        self.assertEqual(modules, set(["A", "B"]))

    def test_add_dependencies_two_levels(self):
        available_modules = set(["A", "B", "C"])
        table = {
            "A": ["B"],
            "B": ["C"],
            "C": []
        }
        ok, modules = ModulesChooser.resolve_dependencies(available_modules, table, "A")
        self.assertTrue(ok)
        self.assertEqual(modules, set(["A", "B", "C"]))

    def test_circular(self):
        available_modules = set(["A", "B", "C"])
        table = {
            "A": ["B"],
            "B": ["C"],
            "C": ["A"]
        }
        ok, modules = ModulesChooser.resolve_dependencies(available_modules, table, "A")
        self.assertTrue(ok)
        self.assertEqual(modules, set(["A", "B", "C"]))

    def test_not_available(self):
        available_modules = set(["A", "C"])
        table = {
            "A": ["B"],
            "B": ["C"],
            "C": ["A"]
        }
        ok, _ = ModulesChooser.resolve_dependencies(available_modules, table, "B")
        self.assertFalse(ok)

    def test_dependency_not_available(self):
        available_modules = set(["A", "C"])
        table = {
            "A": ["B"],
            "B": ["C"],
            "C": ["A"]
        }
        ok, _ = ModulesChooser.resolve_dependencies(available_modules, table, "A")
        self.assertFalse(ok)

    def test_dependency2_not_available(self):
        available_modules = set(["A", "B"])
        table = {
            "A": ["B"],
            "B": ["C"],
            "C": ["A"]
        }
        ok, _ = ModulesChooser.resolve_dependencies(available_modules, table, "A")
        self.assertFalse(ok)

    def test_dependency_choices(self):
        available_modules = set(["A", "B", "C"])
        table = {
            "A": ["B|C"],
            "B": [],
            "C": []
        }
        ok, modules = ModulesChooser.resolve_dependencies(available_modules, table, "A")
        self.assertTrue(ok)
        self.assertTrue(modules == set(["A", "B"]) or modules == set(["A", "C"]))

    def test_dependency_prefer_existing(self):
        available_modules = set(["A", "B", "C"])
        table = {
            "A": ["C", "B|C"],
            "B": [],
            "C": []
        }
        ok, modules = ModulesChooser.resolve_dependencies(available_modules, table, "A")
        self.assertTrue(ok)
        self.assertEqual(modules, set(["A", "C"]))

    def test_dependency_prefer_existing2(self):
        available_modules = set(["A", "B", "C"])
        table = {
            "A": ["B", "B|C"],
            "B": [],
            "C": []
        }
        ok, modules = ModulesChooser.resolve_dependencies(available_modules, table, "A")
        self.assertTrue(ok)
        self.assertEqual(modules, set(["A", "B"]))

    def test_dependency_choices_impossible(self):
        available_modules = set(["A", "C"])
        table = {
            "A": ["B|C"],
            "B": [],
            "C": []
        }
        ok, modules = ModulesChooser.resolve_dependencies(available_modules, table, "A")
        self.assertTrue(ok)
        self.assertEqual(modules, set(["A", "C"]))

    def test_dependency_choices_impossible2(self):
        available_modules = set(["A", "B"])
        table = {
            "A": ["B|C"],
            "B": [],
            "C": []
        }
        ok, modules = ModulesChooser.resolve_dependencies(available_modules, table, "A")
        self.assertTrue(ok)
        self.assertEqual(modules, set(["A", "B"]))

    def test_deep(self):
        available_modules = set(["A", "B", "C", "E", "G"])
        table = {
            "A": ["B|C"],
            "B": ["D"],
            "C": ["E"],
            "D": [],
            "E": ["F|G"],
            "F": ["A", "B"],
            "G": ["A", "G"]
        }
        ok, modules = ModulesChooser.resolve_dependencies(available_modules, table, "G")
        self.assertTrue(ok)
        self.assertEqual(modules, set(["G", "A", "C", "E"]))


if __name__ == '__main__':
    unittest.TestCase.longMessage = True
    unittest.main()
