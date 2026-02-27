"""
(C) 2026 Jack Lloyd
(C) 2026 René Meusel, Rohde & Schwarz Cybersecurity

Botan is released under the Simplified BSD License (see license.txt)
"""

import binascii
import unittest

import botan3 as botan

from .wycheproof import WycheproofTests

_MAC_ALGORITHMS = {
    "HMACSHA1": "HMAC(SHA-1)",
    "HMACSHA224": "HMAC(SHA-224)",
    "HMACSHA256": "HMAC(SHA-256)",
    "HMACSHA384": "HMAC(SHA-384)",
    "HMACSHA512": "HMAC(SHA-512)",
    "HMACSHA3-224": "HMAC(SHA-3(224))",
    "HMACSHA3-256": "HMAC(SHA-3(256))",
    "HMACSHA3-384": "HMAC(SHA-3(384))",
    "HMACSHA3-512": "HMAC(SHA-3(512))",
    "HMACSM3": "HMAC(SM3)",
    "SipHash-1-3": "SipHash(1,3)",
    "SipHash-2-4": "SipHash(2,4)",
    "SipHash-4-8": "SipHash(4,8)",
    "KMAC128": "KMAC-128",
    "KMAC256": "KMAC-256",
}


def _mac_algorithm(
    algorithm: str, key_size_bits: int | None, tag_size_bits: int | None
) -> str:
    if algorithm == "AES-GMAC":
        if key_size_bits is None:
            raise ValueError("AES-GMAC requires a key size")
        return f"GMAC(AES-{key_size_bits})"
    if algorithm.startswith("KMAC"):
        if tag_size_bits is None:
            raise ValueError("KMAC requires a tag size")
        return f"{_MAC_ALGORITHMS[algorithm]}({tag_size_bits})"
    return _MAC_ALGORITHMS[algorithm]


class TestMAC(WycheproofTests, unittest.TestCase):
    def input_files(self) -> list[str]:
        return [
            "hmac_sha1_test.json",
            "hmac_sha224_test.json",
            "hmac_sha256_test.json",
            "hmac_sha384_test.json",
            "hmac_sha3_224_test.json",
            "hmac_sha3_256_test.json",
            "hmac_sha3_384_test.json",
            "hmac_sha3_512_test.json",
            "hmac_sha512_test.json",
            "hmac_sm3_test.json",
            "siphash_1_3_test.json",
            "siphash_2_4_test.json",
            "siphash_4_8_test.json",
            "aes_gmac_test.json",
            "kmac128_no_customization_test.json",
            "kmac256_no_customization_test.json",
        ]

    def run_test(self, data: dict, group: dict, test: dict) -> None:
        key_size_bits = group.get("keySize")
        iv_size_bits = group.get("ivSize")
        tag_size_bits = group.get("tagSize")

        algo = _mac_algorithm(data["algorithm"], key_size_bits, tag_size_bits)

        mac = botan.MsgAuthCode(algo)
        mac.set_key(binascii.unhexlify(test["key"]))
        if iv_size_bits is not None:
            mac.set_nonce(binascii.unhexlify(test["iv"]))
        mac.update(binascii.unhexlify(test["msg"]))

        final_mac = mac.final()
        actual_mac = (
            final_mac[: tag_size_bits // 8] if tag_size_bits is not None else final_mac
        )

        expected = binascii.unhexlify(test["tag"])

        if test["result"] == "valid":
            self.assertEqual(actual_mac, expected)
        elif test["result"] == "invalid":
            self.assertNotEqual(actual_mac, expected)
        elif test["result"] == "acceptable":
            pass
        else:
            self.fail(f"Unknown test result: {test['result']}")
