"""
(C) 2026 Jack Lloyd
(C) 2026 René Meusel, Rohde & Schwarz Cybersecurity

Botan is released under the Simplified BSD License (see license.txt)
"""

import json
import os
import unittest
from abc import ABC, abstractmethod
from urllib.request import urlopen
from typing import BinaryIO
from pathlib import Path

import botan3 as botan


class FixedOutputRNG(botan.RandomNumberGenerator):
    def __init__(self, entropy_pool: bytes = b""):
        """
        A random number generator that outputs a pre-determined sequence of bytes.
        This is exclusively useful for testing.
        """
        super().__init__(
            "custom", get_callback=self._get, add_entropy_callback=self._add_entropy
        )
        self._entropy_pool = entropy_pool

    def _get(self, length: int) -> bytes:
        if length > len(self._entropy_pool):
            raise ValueError("Not enough entropy in pool")
        entropy = self._entropy_pool[:length]
        self._entropy_pool = self._entropy_pool[length:]
        return entropy

    def _add_entropy(self, data: bytes) -> None:
        self._entropy_pool += data


# An RNG implementation called NullRNG that raises an exception if it is used
class NullRNG(botan.RandomNumberGenerator):
    def __init__(self):
        super().__init__(
            "custom", get_callback=self._get, add_entropy_callback=self._add_entropy
        )

    def _get(self, length: int) -> bytes:
        raise botan.BotanException("Unexpected request to get entropy from RNG", rc=-23)

    def _add_entropy(self, data: bytes) -> None:
        raise botan.BotanException("Unexpected request to add entropy to RNG", rc=-23)


class WycheproofTests(ABC):
    """
    Base mixin class for Wycheproof tests.

    This class is intended to be used as a mixin with unittest.TestCase.
    It explicitly relies on methods provided by unittest.TestCase

        class MyTest(WycheproofTests, unittest.TestCase):
            ...
    """

    @abstractmethod
    def input_files(self) -> list[str]:
        """
        Return the list of input files to test. Those files are expected to
        be in the `testvectors_v1` directory of the Wycheproof repository.
        """

    @abstractmethod
    def run_test(self, data: dict, group: dict, test: dict) -> None:
        """
        Run a single test.
        Args:
            data: The data for the test. This is the entire JSON file.
            group: The group for the test. This is the group of test vectors.
            test: The test itself. This is the individual test vector.
        """

    @staticmethod
    def _get_cached_or_downloaded_file(filename: str) -> BinaryIO:
        """
        Returns an open file handle to the JSON file with given filename.
        If WYCHEPROOF_TESTDATA_CACHE_DIR is set, the file is cached in that directory.
        """

        base_url = os.environ.get("WYCHEPROOF_TESTDATA_URL")
        if base_url is None:
            raise RuntimeError("Environment variable WYCHEPROOF_TESTDATA_URL not set")
        url = f"{base_url}/{filename}"

        # Check if the cache can be used
        cache_dir = os.environ.get("WYCHEPROOF_TESTDATA_CACHE_DIR")
        if cache_dir is not None:
            cache_path = Path(cache_dir)
            cache_path.mkdir(parents=True, exist_ok=True)
            cache_entry = cache_path / filename
            if not cache_entry.exists():
                with urlopen(url, timeout=30) as response:
                    with open(cache_entry, "wb") as f:
                        f.write(response.read())
            return open(cache_entry, mode="rb")
        return urlopen(url, timeout=30)

    @staticmethod
    def _read_datafile(filename: str) -> dict | None:
        """
        Reads the datafile named 'filename' from cache (if available) or downloads and caches it.
        Returns the loaded JSON content.
        """
        with WycheproofTests._get_cached_or_downloaded_file(filename) as f:
            return json.load(f) if f is not None else None

    def _validate_unittest_mixin(self) -> None:
        if not isinstance(self, unittest.TestCase):
            raise TypeError(
                f"{self.__class__.__name__} must be used as a mixin with unittest.TestCase"
            )

    def _wycheproof_subtest(self, test: dict, filename: str):
        self._validate_unittest_mixin()
        params = {}
        tc_id = test.get("tcId")
        if tc_id is not None:
            params["tcId"] = tc_id
        comment = test.get("comment")
        if comment:
            params["comment"] = comment
        flags = test.get("flags")
        if flags:
            params["flags"] = ",".join(flags)
        params["filename"] = filename
        return unittest.TestCase.subTest(self, **params)

    def test_wycheproof(self) -> None:
        self._validate_unittest_mixin()
        for filename in self.input_files():
            data = self._read_datafile(filename)
            for group in data["testGroups"]:
                for test in group["tests"]:
                    with self._wycheproof_subtest(test, filename):
                        self.run_test(data, group, test)
