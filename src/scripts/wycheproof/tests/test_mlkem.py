"""
(C) 2026 Jack Lloyd
(C) 2026 René Meusel, Rohde & Schwarz Cybersecurity

Botan is released under the Simplified BSD License (see license.txt)
"""

import binascii
import unittest

import botan3 as botan

from .wycheproof import WycheproofTests, FixedOutputRNG


def _from_hex(value: str) -> bytes:
    return binascii.unhexlify(value)


class TestMLKEM(WycheproofTests, unittest.TestCase):
    def input_files(self) -> list[str]:
        return [
            "mlkem_512_test.json",
            "mlkem_768_test.json",
            "mlkem_1024_test.json",
            "mlkem_512_keygen_seed_test.json",
            "mlkem_768_keygen_seed_test.json",
            "mlkem_1024_keygen_seed_test.json",
            "mlkem_512_encaps_test.json",
            "mlkem_768_encaps_test.json",
            "mlkem_1024_encaps_test.json",
        ]

    def run_test(self, _data: dict, group: dict, test: dict) -> None:
        mlkem_mode = group["parameterSet"]

        priv = None
        pub = None

        # load the private key, if a seed is provided
        if "seed" in test:
            seed = _from_hex(test["seed"])
            try:
                priv = botan.PrivateKey.load_ml_kem(mlkem_mode, seed)
            except botan.BotanException:
                if test["result"] == "invalid":
                    return
                raise
            pub = priv.get_public_key()

        # load and/or validate the public key
        if "ek" in test:
            expected_ek = _from_hex(test["ek"])

            # load the public key, if no private key was loaded
            if pub is None:
                try:
                    pub = botan.PublicKey.load_ml_kem(mlkem_mode, expected_ek)
                except botan.BotanException:
                    if test["result"] == "invalid":
                        return
                    raise

            self.assertEqual(pub.to_raw(), expected_ek)

        if not pub:
            raise ValueError("No public key available in this test vector")

        # reload and validate the private key
        if "dk" in test:
            try:
                expected_dk = _from_hex(test["dk"])
                priv2 = botan.PrivateKey.load_ml_kem(mlkem_mode, expected_dk)
                # TODO: currently we cannot export the expanded private key
                #       via the python API, we would need to be able to access
                #       ML_KEM_PrivateKey::private_key_bits_with_format()
                #
                # Hence, we only validate that the public key is the same.
                # and not that priv.to_expanded_raw() == expected_dk
                self.assertEqual(priv2.to_raw(), expected_dk)
                self.assertEqual(priv2.get_public_key().to_raw(), pub.to_raw())
            except botan.BotanException:
                if test["result"] in ("invalid", "acceptable"):
                    return
                raise

        if "c" in test and "K" in test:
            expected_k = _from_hex(test["K"])
            expected_c = _from_hex(test["c"])

            # encapsulation
            if "m" in test:
                rng = FixedOutputRNG(_from_hex(test["m"]))
                kem_e = botan.KemEncrypt(pub, "Raw")
                actual_k, actual_c = kem_e.create_shared_key(rng, b"", len(expected_k))
                self.assertEqual(actual_k, expected_k)
                self.assertEqual(actual_c, expected_c)

            # decapsulation
            if priv is not None:
                kem_d = botan.KemDecrypt(priv, "Raw")

                try:
                    actual_k = kem_d.decrypt_shared_key(
                        b"", len(expected_k), expected_c
                    )
                except botan.BotanException:
                    if test["result"] in ("invalid", "acceptable"):
                        return
                    raise

                if test["result"] == "valid":
                    self.assertEqual(actual_k, expected_k)
                elif test["result"] == "invalid":
                    self.assertNotEqual(actual_k, expected_k)
                elif test["result"] == "acceptable":
                    pass
                else:
                    self.fail(f"Unknown test result: {test['result']}")
