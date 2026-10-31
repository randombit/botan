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
from configure import (  # pylint: disable=wrong-import-position
    AmalgamationHelper,
    ModulesChooser,
    process_command_line,
)


class AmalgamationHelperTests(unittest.TestCase):
    def test_matcher_std_includes(self):
        self.assertEqual(AmalgamationHelper.is_unconditional_std_include("#include <string>"), "string")
        self.assertEqual(AmalgamationHelper.is_unconditional_std_include("#include <string> // comment"), "string")

        self.assertEqual(AmalgamationHelper.is_unconditional_std_include("#include <myfile.h>"), None)
        self.assertEqual(AmalgamationHelper.is_unconditional_std_include("#include <unistd.h>"), None)
        self.assertEqual(AmalgamationHelper.is_unconditional_std_include("  #include <string>"), None)

    def test_matcher_botan_include(self):
        self.assertEqual(AmalgamationHelper.is_botan_include("#include <botan/oids.h>"),
                         "oids.h")
        self.assertEqual(AmalgamationHelper.is_botan_include("#include <botan/internal/socket.h>"),
                         "internal/socket.h")
        self.assertEqual(AmalgamationHelper.is_botan_include("#include <botan/oids.h> // comment"),
                         "oids.h")
        self.assertEqual(AmalgamationHelper.is_botan_include("#include <botan/internal/socket.h> // comment"),
                         "internal/socket.h")
        self.assertEqual(AmalgamationHelper.is_botan_include("  #include <botan/oids.h>"),
                         "oids.h")
        self.assertEqual(AmalgamationHelper.is_botan_include("  #include <botan/internal/socket.h>"),
                         "internal/socket.h")

        self.assertEqual(AmalgamationHelper.is_botan_include("#include <string>"), None)
        self.assertEqual(AmalgamationHelper.is_botan_include("#include <myfile.h>"), None)
        self.assertEqual(AmalgamationHelper.is_botan_include("#include <unistd.h>"), None)

    def test_matcher_any_includes(self):
        self.assertEqual(AmalgamationHelper.is_any_include("#include <string>"), "string")
        self.assertEqual(AmalgamationHelper.is_any_include("#include <myfile.h>"), "myfile.h")
        self.assertEqual(AmalgamationHelper.is_any_include("#include <unistd.h>"), "unistd.h")
        self.assertEqual(AmalgamationHelper.is_any_include("#include <botan/oids.h>"),
                         "botan/oids.h")
        self.assertEqual(AmalgamationHelper.is_any_include("  #include <string>"), "string")
        self.assertEqual(AmalgamationHelper.is_any_include("  #include <myfile.h>"), "myfile.h")
        self.assertEqual(AmalgamationHelper.is_any_include("  #include <unistd.h>"), "unistd.h")
        self.assertEqual(AmalgamationHelper.is_any_include("  #include <botan/oids.h>"),
                         "botan/oids.h")
        self.assertEqual(AmalgamationHelper.is_any_include("#include <string> // comment"), "string")
        self.assertEqual(AmalgamationHelper.is_any_include("#include <myfile.h> // comment"), "myfile.h")
        self.assertEqual(AmalgamationHelper.is_any_include("#include <unistd.h> // comment"), "unistd.h")
        self.assertEqual(AmalgamationHelper.is_any_include("#include <botan/oids.h> // comment"),
                         "botan/oids.h")

class ModulesChooserResolveDependencies(unittest.TestCase):
    def test_base(self):
        available_modules = {"A", "B"}
        table = {
            "A": [],
        }
        ok, modules = ModulesChooser.resolve_dependencies(available_modules, table, "A")
        self.assertTrue(ok)
        self.assertEqual(modules, {"A"})

    def test_no_dependencies_defined(self):
        available_modules = {"A", "B"}
        table = {
            "A": [],
        }
        with self.assertRaises(KeyError):
            ModulesChooser.resolve_dependencies(available_modules, table, "B")

        available_modules = {"A", "B"}
        table = {
            "A": ["B"],
        }
        with self.assertRaises(KeyError):
            ModulesChooser.resolve_dependencies(available_modules, table, "A")

    def test_add_dependency(self):
        available_modules = {"A", "B"}
        table = {
            "A": ["B"],
            "B": []
        }
        ok, modules = ModulesChooser.resolve_dependencies(available_modules, table, "A")
        self.assertTrue(ok)
        self.assertEqual(modules, {"A", "B"})

    def test_add_dependencies_two_levels(self):
        available_modules = {"A", "B", "C"}
        table = {
            "A": ["B"],
            "B": ["C"],
            "C": []
        }
        ok, modules = ModulesChooser.resolve_dependencies(available_modules, table, "A")
        self.assertTrue(ok)
        self.assertEqual(modules, {"A", "B", "C"})

    def test_circular(self):
        available_modules = {"A", "B", "C"}
        table = {
            "A": ["B"],
            "B": ["C"],
            "C": ["A"]
        }
        ok, modules = ModulesChooser.resolve_dependencies(available_modules, table, "A")
        self.assertTrue(ok)
        self.assertEqual(modules, {"A", "B", "C"})

    def test_not_available(self):
        available_modules = {"A", "C"}
        table = {
            "A": ["B"],
            "B": ["C"],
            "C": ["A"]
        }
        ok, _ = ModulesChooser.resolve_dependencies(available_modules, table, "B")
        self.assertFalse(ok)

    def test_dependency_not_available(self):
        available_modules = {"A", "C"}
        table = {
            "A": ["B"],
            "B": ["C"],
            "C": ["A"]
        }
        ok, _ = ModulesChooser.resolve_dependencies(available_modules, table, "A")
        self.assertFalse(ok)

    def test_dependency2_not_available(self):
        available_modules = {"A", "B"}
        table = {
            "A": ["B"],
            "B": ["C"],
            "C": ["A"]
        }
        ok, _ = ModulesChooser.resolve_dependencies(available_modules, table, "A")
        self.assertFalse(ok)

    def test_dependency_choices(self):
        available_modules = {"A", "B", "C"}
        table = {
            "A": ["B|C"],
            "B": [],
            "C": []
        }
        ok, modules = ModulesChooser.resolve_dependencies(available_modules, table, "A")
        self.assertTrue(ok)
        self.assertTrue(modules in ({"A", "B"}, {"A", "C"}))

    def test_dependency_prefer_existing(self):
        available_modules = {"A", "B", "C"}
        table = {
            "A": ["C", "B|C"],
            "B": [],
            "C": []
        }
        ok, modules = ModulesChooser.resolve_dependencies(available_modules, table, "A")
        self.assertTrue(ok)
        self.assertEqual(modules, {"A", "C"})

    def test_dependency_prefer_existing2(self):
        available_modules = {"A", "B", "C"}
        table = {
            "A": ["B", "B|C"],
            "B": [],
            "C": []
        }
        ok, modules = ModulesChooser.resolve_dependencies(available_modules, table, "A")
        self.assertTrue(ok)
        self.assertEqual(modules, {"A", "B"})

    def test_dependency_choices_impossible(self):
        available_modules = {"A", "C"}
        table = {
            "A": ["B|C"],
            "B": [],
            "C": []
        }
        ok, modules = ModulesChooser.resolve_dependencies(available_modules, table, "A")
        self.assertTrue(ok)
        self.assertEqual(modules, {"A", "C"})

    def test_dependency_choices_impossible2(self):
        available_modules = {"A", "B"}
        table = {
            "A": ["B|C"],
            "B": [],
            "C": []
        }
        ok, modules = ModulesChooser.resolve_dependencies(available_modules, table, "A")
        self.assertTrue(ok)
        self.assertEqual(modules, {"A", "B"})

    def test_deep(self):
        available_modules = {"A", "B", "C", "E", "G"}
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
        self.assertEqual(modules, {"G", "A", "C", "E"})


class FakeModule:
    def is_public(self):
        return True


class ModulesChooserUserSelection(unittest.TestCase):
    """
    The module selection switches are applied in command line order
    """

    MODULES = {name: FakeModule() for name in [
        "pcurves", "pcurves_generic", "pcurves_secp256r1",
        "pcurves_brainpool256r1", "pcurves_brainpool384r1",
        "sha2_32", "sha2_32_avx2", "aes_avx2", "chacha_avx2"]}

    def select(self, *args):
        options = process_command_line(list(args))
        return ModulesChooser._apply_user_selection(self.MODULES, options.module_selection)

    def test_enable_then_specific_disable(self):
        enabled, disabled = self.select("--minimized-build",
                                        "--enable-modules=pcurves*",
                                        "--disable-modules=pcurves_brainpool*")
        self.assertEqual(enabled, ["pcurves_generic", "pcurves_secp256r1"])
        self.assertEqual(disabled, ["pcurves_brainpool256r1", "pcurves_brainpool384r1"])

    def test_disable_then_specific_enable(self):
        enabled, disabled = self.select("--disable-modules=pcurves*",
                                        "--enable-modules=pcurves_generic")
        self.assertEqual(enabled, ["pcurves_generic"])
        self.assertEqual(disabled, ["pcurves_brainpool256r1", "pcurves_brainpool384r1",
                                    "pcurves_secp256r1"])

    def test_disable_avx2_except_one(self):
        enabled, disabled = self.select("--disable-modules=*avx2",
                                        "--enable-modules=sha2_32_avx2")
        self.assertEqual(enabled, ["sha2_32_avx2"])
        self.assertEqual(disabled, ["aes_avx2", "chacha_avx2"])

    def test_last_switch_wins(self):
        self.assertEqual(self.select("--enable-modules=sha2_32", "--disable-modules=sha2_32"),
                         ([], ["sha2_32"]))
        self.assertEqual(self.select("--disable-modules=sha2_32", "--enable-modules=sha2_32"),
                         (["sha2_32"], []))

    def test_comma_separated_and_repeated(self):
        enabled, disabled = self.select("--enable-modules=sha2_32,aes_avx2",
                                        "--disable-modules=aes_avx2,chacha_avx2",
                                        "--enable-modules=chacha_avx2")
        self.assertEqual(enabled, ["chacha_avx2", "sha2_32"])
        self.assertEqual(disabled, ["aes_avx2"])

    def test_with_and_without_are_ordered_too(self):
        self.assertEqual(self.select("--without-zlib", "--with-zlib"), (["zlib"], []))
        self.assertEqual(self.select("--with-zlib", "--without-zlib"), ([], ["zlib"]))
        self.assertEqual(self.select("--disable-modules=zlib", "--with-zlib"), (["zlib"], []))

    def test_wildcard_matching_nothing_is_not_an_error(self):
        self.assertEqual(self.select("--disable-modules=zz*"), ([], []))

    def test_no_switches(self):
        self.assertEqual(self.select(), ([], []))


if __name__ == '__main__':
    unittest.TestCase.longMessage = True
    unittest.main()
