#!/usr/bin/env python3

"""
(C) 2025 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import unittest
import botan3 as botan # pylint: disable=wrong-import-position

class BotanPythonTests(unittest.TestCase):
    def test_version(self):
        version_str = botan.version_string()
        self.assertTrue(version_str.startswith('Botan '))
        self.assertGreaterEqual(botan.version_major(), 3)
        self.assertGreaterEqual(botan.version_minor(), 0)
        self.assertGreaterEqual(botan.ffi_api_version(), 20180713)

    def test_hash(self):
        # small smoke test for hash operation
        hash_input = "hash test"
        hf = botan.HashFunction('SHA-256')
        hf.update(hash_input.encode())
        hash_out = hf.final().hex()
        print(f'SHA-256("{hash_input}")={hash_out}')

        # created for comparison with: echo -n "hash test" | sha256sum
        hash_precomputed = 'cd5e9b1a6c3c37593b8b622b2921ee5320944192acb48b55155cbe8d32dc5ea1'

        self.assertEqual(hash_out, hash_precomputed)

def main():
    unittest.main()

if __name__ == '__main__':
    main()
