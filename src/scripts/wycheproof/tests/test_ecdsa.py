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
        "brainpoolP320r1": "brainpool320r1",
        "brainpoolP384r1": "brainpool384r1",
        "brainpoolP512r1": "brainpool512r1",
    }
    return mapping.get(wycheproof_curve, wycheproof_curve)


def _map_hash_name(wycheproof_hash: str) -> str | None:
    """Map Wycheproof hash name to Botan hash name.
    Returns None for unsupported hashes.
    """
    mapping = {
        "SHA-224": "SHA-224",
        "SHA-256": "SHA-256",
        "SHA-384": "SHA-384",
        "SHA-512": "SHA-512",
        "SHA3-224": "SHA-3(224)",
        "SHA3-256": "SHA-3(256)",
        "SHA3-384": "SHA-3(384)",
        "SHA3-512": "SHA-3(512)",
        "SHAKE128": "SHAKE-128(256)",
        "SHAKE256": "SHAKE-256(512)",
    }
    return mapping.get(wycheproof_hash)


class TestECDSA(WycheproofTests, unittest.TestCase):
    def input_files(self) -> list[str]:
        return [
            "ecdsa_brainpoolP224r1_sha224_p1363_test.json",
            "ecdsa_brainpoolP224r1_sha224_test.json",
            "ecdsa_brainpoolP224r1_sha3_224_test.json",
            "ecdsa_brainpoolP256r1_sha256_p1363_test.json",
            "ecdsa_brainpoolP256r1_sha256_test.json",
            "ecdsa_brainpoolP256r1_sha3_256_test.json",
            "ecdsa_brainpoolP320r1_sha384_p1363_test.json",
            "ecdsa_brainpoolP320r1_sha384_test.json",
            "ecdsa_brainpoolP320r1_sha3_384_test.json",
            "ecdsa_brainpoolP384r1_sha384_p1363_test.json",
            "ecdsa_brainpoolP384r1_sha384_test.json",
            "ecdsa_brainpoolP384r1_sha3_384_test.json",
            "ecdsa_brainpoolP512r1_sha3_512_test.json",
            "ecdsa_brainpoolP512r1_sha512_p1363_test.json",
            "ecdsa_brainpoolP512r1_sha512_test.json",
            "ecdsa_secp160k1_sha256_p1363_test.json",
            "ecdsa_secp160k1_sha256_test.json",
            "ecdsa_secp160r1_sha256_p1363_test.json",
            "ecdsa_secp160r1_sha256_test.json",
            "ecdsa_secp160r2_sha256_p1363_test.json",
            "ecdsa_secp160r2_sha256_test.json",
            "ecdsa_secp192k1_sha256_p1363_test.json",
            "ecdsa_secp192k1_sha256_test.json",
            "ecdsa_secp192r1_sha256_p1363_test.json",
            "ecdsa_secp192r1_sha256_test.json",
            "ecdsa_secp224k1_sha224_p1363_test.json",
            "ecdsa_secp224k1_sha224_test.json",
            "ecdsa_secp224k1_sha256_p1363_test.json",
            "ecdsa_secp224k1_sha256_test.json",
            "ecdsa_secp224r1_sha224_p1363_test.json",
            "ecdsa_secp224r1_sha224_test.json",
            "ecdsa_secp224r1_sha256_p1363_test.json",
            "ecdsa_secp224r1_sha256_test.json",
            "ecdsa_secp224r1_sha3_224_test.json",
            "ecdsa_secp224r1_sha3_256_test.json",
            "ecdsa_secp224r1_sha3_512_test.json",
            "ecdsa_secp224r1_sha512_p1363_test.json",
            "ecdsa_secp224r1_sha512_test.json",
            "ecdsa_secp224r1_shake128_p1363_test.json",
            "ecdsa_secp224r1_shake128_test.json",
            "ecdsa_secp256k1_sha256_bitcoin_test.json",
            "ecdsa_secp256k1_sha256_p1363_test.json",
            "ecdsa_secp256k1_sha256_test.json",
            "ecdsa_secp256k1_sha3_256_test.json",
            "ecdsa_secp256k1_sha3_512_test.json",
            "ecdsa_secp256k1_sha512_p1363_test.json",
            "ecdsa_secp256k1_sha512_test.json",
            "ecdsa_secp256k1_shake128_p1363_test.json",
            "ecdsa_secp256k1_shake128_test.json",
            "ecdsa_secp256k1_shake256_p1363_test.json",
            "ecdsa_secp256k1_shake256_test.json",
            "ecdsa_secp256r1_sha256_p1363_test.json",
            "ecdsa_secp256r1_sha256_test.json",
            "ecdsa_secp256r1_sha3_256_test.json",
            "ecdsa_secp256r1_sha3_512_test.json",
            "ecdsa_secp256r1_sha512_p1363_test.json",
            "ecdsa_secp256r1_sha512_test.json",
            "ecdsa_secp256r1_shake128_p1363_test.json",
            "ecdsa_secp256r1_shake128_test.json",
            "ecdsa_secp384r1_sha256_test.json",
            "ecdsa_secp384r1_sha384_p1363_test.json",
            "ecdsa_secp384r1_sha384_test.json",
            "ecdsa_secp384r1_sha3_384_test.json",
            "ecdsa_secp384r1_sha3_512_test.json",
            "ecdsa_secp384r1_sha512_p1363_test.json",
            "ecdsa_secp384r1_sha512_test.json",
            "ecdsa_secp384r1_shake256_p1363_test.json",
            "ecdsa_secp384r1_shake256_test.json",
            "ecdsa_secp521r1_sha3_512_test.json",
            "ecdsa_secp521r1_sha512_p1363_test.json",
            "ecdsa_secp521r1_sha512_test.json",
            "ecdsa_secp521r1_shake256_p1363_test.json",
            "ecdsa_secp521r1_shake256_test.json",
        ]

    def run_test(self, data: dict, group: dict, test: dict) -> None:
        botan_hash = _map_hash_name(group["sha"])
        curve = _map_curve_name(group["publicKey"]["curve"])
        if not botan.ECGroup.supports_named_group(curve):
            self.skipTest(f"Curve {curve} not supported in this build")

        # Load public key from DER
        try:
            pub_key = botan.PublicKey.load(_from_hex(group["publicKeyDer"]))
        except botan.BotanException:
            if test["result"] != "valid":
                return
            raise

        # Determine signature format from group type
        group_type = group["type"]
        if group_type == "EcdsaBitcoinVerify":
            # Botan currently does not prevent signature malleability via
            # low-s normalization.
            self.skipTest("Bitcoin variant of ECDSA is not supported")

        if group_type in ("EcdsaVerify", "EcdsaBitcoinVerify"):
            use_der = True
        elif group_type == "EcdsaP1363Verify":
            use_der = False
        else:
            self.fail(f"Unknown test group type: {group_type}")

        # Perform verification
        try:
            verifier = botan.PKVerify(pub_key, botan_hash, der=use_der)
            verifier.update(_from_hex(test["msg"]))
            valid = verifier.check_signature(_from_hex(test["sig"]))
        except botan.BotanException:
            if test["result"] != "valid":
                return
            raise

        # Validate the verification result
        self.assertEqual(
            valid,
            test["result"] == "valid",
            "Signature should be valid"
            if test["result"] == "valid"
            else "Signature should be invalid",
        )
