"""
(C) 2026 Jack Lloyd
(C) 2026 René Meusel, Rohde & Schwarz Cybersecurity

Botan is released under the Simplified BSD License (see license.txt)
"""

import binascii
import unittest

import botan3 as botan

from .wycheproof import WycheproofTests


def _from_hex(value: str) -> bytes:
    return binascii.unhexlify(value)


def _map_curve_name(wycheproof_curve: str) -> str:
    """Map Wycheproof curve name to Botan curve name."""
    mapping = {
        "brainpoolP224r1": "brainpool224r1",
        "brainpoolP256r1": "brainpool256r1",
        "brainpoolP384r1": "brainpool384r1",
        "brainpoolP512r1": "brainpool512r1",
    }
    return mapping.get(wycheproof_curve, wycheproof_curve)


class TestECDH(WycheproofTests, unittest.TestCase):
    def input_files(self) -> list[str]:
        return [
            "ecdh_secp224r1_test.json",
            "ecdh_secp256r1_test.json",
            "ecdh_secp256k1_test.json",
            "ecdh_secp384r1_test.json",
            "ecdh_secp521r1_test.json",
            "ecdh_brainpoolP224r1_test.json",
            "ecdh_brainpoolP256r1_test.json",
            "ecdh_brainpoolP384r1_test.json",
            "ecdh_brainpoolP512r1_test.json",
        ]

    def run_test(self, data: dict, group: dict, test: dict) -> None:
        curve = _map_curve_name(group["curve"])
        if not botan.ECGroup.supports_named_group(curve):
            self.skipTest(f"Curve {curve} not supported in this build")

        try:
            priv_value = botan.MPI(test["private"], radix=16)
            priv_key = botan.PrivateKey.load_ecdh(curve, priv_value)
        except botan.BotanException:
            if test["result"] != "valid":
                return
            raise

        try:
            pub_key = botan.PublicKey.load(_from_hex(test["public"]))
        except botan.BotanException:
            if test["result"] != "valid":
                return
            raise

        explicit_encoding = pub_key.used_explicit_encoding()
        if explicit_encoding:
            # Wycheproof encodes ECDH public keys as DER encoded EC points that
            # inherently allow an explicit encoding of the EC group. The Python
            # API can load such keys generically (PublicKey.load()), but the
            # PKKeyAgreement class expects the public value as SEC1 encoding
            # which does not allow the explicit encoding of the EC group.
            #
            # Therefore, PKKeyAgreement.agree() cannot detect the discrepancy in
            # the underlying EC groups and we need to handle this case manually.
            self.assertIn(test["result"], ("invalid", "acceptable"))
            return

        try:
            ka = botan.PKKeyAgreement(priv_key, "Raw")
            shared_secret = ka.agree(pub_key.to_raw(), 0, b"")
        except botan.BotanException:
            if test["result"] != "valid":
                return
            raise

        self.assertIn(
            test["result"],
            ("valid", "acceptable"),
            "Invalid test case produced a shared secret",
        )
        self.assertEqual(
            shared_secret,
            _from_hex(test["shared"]),
            "Shared secret does not match expected value",
        )
