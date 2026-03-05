"""
(C) 2026 Jack Lloyd
(C) 2026 René Meusel, Rohde & Schwarz Cybersecurity

Botan is released under the Simplified BSD License (see license.txt)
"""

import binascii
import unittest

import botan3 as botan

from .wycheproof import WycheproofTests

_AEAD_CIPHER_ALIASES = {
    "AES-GCM": "AES",
    "AES-CCM": "AES",
    "AEAD-AES-SIV-CMAC": "AES-SIV-CMAC",
    "ARIA-GCM": "ARIA",
    "ARIA-CCM": "ARIA",
    "CAMELLIA-CCM": "Camellia",
    "SEED-GCM": "SEED",
    "SEED-CCM": "SEED",
    "SM4-GCM": "SM4",
    "SM4-CCM": "SM4",
}


def _aead_algorithm(
    algorithm: str, key_size_bits: int, tag_size_bits: int | None, nonce_len: int
) -> str:
    cipher = _AEAD_CIPHER_ALIASES.get(algorithm)
    if cipher is None:
        raise ValueError(f"Unsupported AEAD algorithm: {algorithm}")

    tag_len_bytes = tag_size_bits // 8 if tag_size_bits is not None else None

    if algorithm == "AEAD-AES-SIV-CMAC":
        aes_size = key_size_bits // 2
        return f"AES-{aes_size}/SIV"

    if cipher in ("AES", "ARIA", "Camellia"):
        cipher = f"{cipher}-{key_size_bits}"

    if algorithm.endswith("GCM"):
        suffix = f"/GCM({tag_len_bytes})" if tag_len_bytes is not None else "/GCM"
        return f"{cipher}{suffix}"

    if algorithm.endswith("CCM"):
        l_val = 15 - nonce_len
        if tag_len_bytes is None:
            return f"{cipher}/CCM({l_val})"
        return f"{cipher}/CCM({tag_len_bytes},{l_val})"

    raise ValueError(f"Unhandled AEAD algorithm: {algorithm}")


def _encrypt(aead: botan.SymmetricCipher, iv: bytes, aad: bytes, msg: bytes) -> bytes:
    aead.set_assoc_data(aad)
    aead.start(iv)
    return aead.finish(msg)


def _decrypt(
    aead: botan.SymmetricCipher, iv: bytes, aad: bytes, ct_tag: bytes
) -> bytes:
    aead.set_assoc_data(aad)
    aead.start(iv)
    return aead.finish(ct_tag)


class TestAEAD(WycheproofTests, unittest.TestCase):
    def input_files(self) -> list[str]:
        return [
            "aes_ccm_test.json",
            "aes_gcm_test.json",
            "aria_ccm_test.json",
            "aria_gcm_test.json",
            "camellia_ccm_test.json",
            "seed_ccm_test.json",
            "seed_gcm_test.json",
            "sm4_ccm_test.json",
            "sm4_gcm_test.json",
            "aead_aes_siv_cmac_test.json",
        ]

    def run_test(self, data: dict, group: dict, test: dict) -> None:
        algorithm = data["algorithm"]
        is_siv = algorithm == "AEAD-AES-SIV-CMAC"

        tag_size_bits = group.get("tagSize")
        key_size_bits = group.get("keySize")

        key = binascii.unhexlify(test["key"])
        iv = binascii.unhexlify(test["iv"])
        aad = binascii.unhexlify(test["aad"])
        msg = binascii.unhexlify(test["msg"])
        ct = binascii.unhexlify(test["ct"])
        tag = binascii.unhexlify(test["tag"])
        expected_ct_tag = (tag + ct) if is_siv else (ct + tag)

        algo = _aead_algorithm(algorithm, key_size_bits, tag_size_bits, len(iv))

        if test["result"] == "valid":
            enc = botan.SymmetricCipher(algo, True)
            enc.set_key(key)
            enc_out = _encrypt(enc, iv, aad, msg)
            self.assertEqual(enc_out, expected_ct_tag)

            dec = botan.SymmetricCipher(algo, False)
            dec.set_key(key)
            dec_out = _decrypt(dec, iv, aad, expected_ct_tag)
            self.assertEqual(dec_out, msg)
        elif test["result"] in ("invalid", "acceptable"):
            try:
                dec = botan.SymmetricCipher(algo, False)
                dec.set_key(key)
                dec_out = _decrypt(dec, iv, aad, expected_ct_tag)
                if test["result"] == "invalid":
                    self.assertNotEqual(dec_out, msg)
                if test["result"] == "acceptable":
                    self.assertEqual(dec_out, msg)
            except botan.BotanException:
                # may fail, because test is "invalid" or "acceptable"
                pass
        else:
            self.fail(f"Unknown test result: {test['result']}")
