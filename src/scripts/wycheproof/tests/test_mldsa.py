"""
(C) 2026 Jack Lloyd
(C) 2026 René Meusel, Rohde & Schwarz Cybersecurity

Botan is released under the Simplified BSD License (see license.txt)
"""

import binascii
import unittest

import botan3 as botan

from .wycheproof import WycheproofTests, NullRNG


def _from_hex(value: str) -> bytes:
    return binascii.unhexlify(value)


def _map_algorithm_to_mode(algorithm: str) -> str:
    """Map Wycheproof algorithm name to Botan ML-DSA mode name."""
    mapping = {
        "ML-DSA-44": "ML-DSA-4x4",
        "ML-DSA-65": "ML-DSA-6x5",
        "ML-DSA-87": "ML-DSA-8x7",
    }
    return mapping.get(algorithm, algorithm)


class TestMLDSA(WycheproofTests, unittest.TestCase):
    def input_files(self) -> list[str]:
        # TODO: enable *_noseed_*.json once support for expanded private keys is implemented
        return [
            "mldsa_44_sign_seed_test.json",
            # "mldsa_44_sign_noseed_test.json",
            "mldsa_44_verify_test.json",
            "mldsa_65_sign_seed_test.json",
            # "mldsa_65_sign_noseed_test.json",
            "mldsa_65_verify_test.json",
            "mldsa_87_sign_seed_test.json",
            # "mldsa_87_sign_noseed_test.json",
            "mldsa_87_verify_test.json",
        ]

    def run_test(self, data: dict, group: dict, test: dict) -> None:
        ctx = test.get("ctx")
        if ctx is not None and ctx != "":
            # Currently Botan doesn't support context (ctx), skip...
            self.skipTest("ML-DSA ctx not supported")

        mldsa_mode = _map_algorithm_to_mode(data.get("algorithm", ""))
        group_type = group.get("type")

        if group_type == "MlDsaSign":
            self._run_sign_test(mldsa_mode, group, test)
        elif group_type == "MlDsaVerify":
            self._run_verify_test(mldsa_mode, group, test)
        else:
            self.fail(f"Unknown test group type: {group_type}")

    def _run_sign_test(self, mldsa_mode: str, group: dict, test: dict) -> None:
        """Run a signing test (either seed or noseed variant)."""

        # Load the private key
        priv = None
        try:
            if "privateSeed" in group:
                priv = botan.PrivateKey.load_ml_dsa(
                    mldsa_mode, _from_hex(group["privateSeed"])
                )
            # TODO: implement loading from expanded private key and enable the relevant
            #       input files with *_noseed_*.json
        except botan.BotanException:
            if test["result"] == "invalid":
                return
            raise
        if priv is None:
            self.fail("No private key available for signing test")

        # Derive the public key and validate it against the expected public key
        pub = priv.get_public_key()
        if "publicKey" in group:
            self.assertEqual(
                pub.to_raw(),
                _from_hex(group["publicKey"]),
                "Deserialized public key does not match expected public key from test group",
            )

        # Perform signing
        try:
            signer = botan.PKSign(priv, "Deterministic")
            signer.update(_from_hex(test["msg"]))
            actual_sig = signer.finish(NullRNG())
        except botan.BotanException:
            if test["result"] == "invalid":
                return
            raise

        # Validate the generated signature
        self.assertEqual(
            actual_sig,
            _from_hex(test["sig"]),
            "Generated signature does not match expected signature in test vector",
        )

    def _run_verify_test(self, mldsa_mode: str, group: dict, test: dict) -> None:
        """Run a verification test."""
        # Load public key
        try:
            pub = botan.PublicKey.load_ml_dsa(mldsa_mode, _from_hex(group["publicKey"]))
        except botan.BotanException:
            if test["result"] == "invalid":
                return
            raise

        # Perform verification
        verifier = botan.PKVerify(pub, "")
        verifier.update(_from_hex(test["msg"]))
        valid = verifier.check_signature(_from_hex(test["sig"]))

        # Validate the verification result
        self.assertEqual(
            valid,
            test["result"] == "valid",
            "Signature should be valid"
            if test["result"] == "valid"
            else "Signature should be invalid",
        )
