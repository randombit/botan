"""
(C) 2026 Jack Lloyd
(C) 2026 René Meusel, Rohde & Schwarz Cybersecurity

Botan is released under the Simplified BSD License (see license.txt)
"""

import json
import os
from abc import ABC, abstractmethod
from urllib.request import urlopen

import unittest

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
    def _read_datafile(filename: str) -> dict | None:
        if 'WYCHEPROOF_TESTDATA_URL' not in os.environ:
            raise RuntimeError("Environment variable WYCHEPROOF_TESTDATA_URL not set")
        with urlopen(os.environ['WYCHEPROOF_TESTDATA_URL'] + '/' + filename) as response:
            return json.load(response)

    def _validate_unittest_mixin(self) -> None:
        if not isinstance(self, unittest.TestCase):
            raise TypeError(
                f"{self.__class__.__name__} must be used as a mixin with unittest.TestCase"
            )

    def _wycheproof_subtest(self, test: dict):
        self._validate_unittest_mixin()
        params = {}
        tc_id = test.get('tcId')
        if tc_id is not None:
            params['tcId'] = tc_id
        comment = test.get('comment')
        if comment:
            params['comment'] = comment
        flags = test.get('flags')
        if flags:
            params['flags'] = ",".join(flags)
        return unittest.TestCase.subTest(self, **params)

    def test_wycheproof(self) -> None:
        self._validate_unittest_mixin()
        for filename in self.input_files():
            data = self._read_datafile(filename)
            for group in data['testGroups']:
                for test in group['tests']:
                    with self._wycheproof_subtest(test):
                        self.run_test(data, group, test)
