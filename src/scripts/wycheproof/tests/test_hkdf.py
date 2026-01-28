"""
(C) 2026 Jack Lloyd
(C) 2026 René Meusel, Rohde & Schwarz Cybersecurity

Botan is released under the Simplified BSD License (see license.txt)
"""

import binascii
import unittest
import botan3 as botan

from .wycheproof import WycheproofTests


_HKDF_ALIASES = {
    "HKDF-SHA-1": "HKDF(SHA-1)",
    "HKDF-SHA-256": "HKDF(SHA-256)",
    "HKDF-SHA-384": "HKDF(SHA-384)",
    "HKDF-SHA-512": "HKDF(SHA-512)",
}


class TestHKDF(WycheproofTests, unittest.TestCase):
    def input_files(self) -> list[str]:
        return [
            "hkdf_sha1_test.json",
            "hkdf_sha256_test.json",
            "hkdf_sha384_test.json",
            "hkdf_sha512_test.json",
        ]

    def run_test(self, data: dict, _group: dict, test: dict) -> None:
        algo = _HKDF_ALIASES.get(data["algorithm"])
        if algo is None:
            raise ValueError(f"Unsupported HKDF algorithm: {data['algorithm']}")

        ikm = binascii.unhexlify(test["ikm"])
        salt = binascii.unhexlify(test["salt"])
        info = binascii.unhexlify(test["info"])
        size = test["size"]
        expected = binascii.unhexlify(test["okm"])

        try:
            actual = botan.kdf(algo, ikm, size, salt, info)
        except botan.BotanException:
            if test["result"] in ("invalid", "acceptable"):
                return
            raise

        if test["result"] == "valid":
            self.assertEqual(actual, expected)
        elif test["result"] == "invalid":
            self.assertNotEqual(actual, expected)
        elif test["result"] == "acceptable":
            pass
        else:
            self.fail(f"Unknown test result: {test['result']}")
