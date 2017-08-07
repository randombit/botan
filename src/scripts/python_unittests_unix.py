#!/usr/bin/env python3

"""
Unittests for Botan Python scripts. Those tests only need to pass un UNIX-like
operating systems.

Requires Python 3.

(C) 2017 Simon Warta (Kullo GmbH)

Botan is released under the Simplified BSD License (see license.txt)
"""

import os
import sys
import unittest

sys.path.append("../..") # Botan repo root
from install import prepend_destdir # pylint: disable=wrong-import-position
from install import PrependDestdirError # pylint: disable=wrong-import-position


class PrependDestdir(unittest.TestCase):
    def test_absolute_destdir(self):
        os.environ["DESTDIR"] = "/"
        self.assertEqual(prepend_destdir("/home/me"), "/home/me")
        self.assertEqual(prepend_destdir("/home/me/"), "/home/me")
        self.assertEqual(prepend_destdir("/home/me/../me2"), "/home/me2")

        os.environ["DESTDIR"] = "/opt"
        self.assertEqual(prepend_destdir("/home/me"), "/opt/home/me")
        self.assertEqual(prepend_destdir("/home/me/"), "/opt/home/me")
        self.assertEqual(prepend_destdir("/home/me/../me2"), "/opt/home/me2")

    def test_relative_destdir(self):
        os.environ["DESTDIR"] = "."
        self.assertEqual(prepend_destdir("/home/me"), "./home/me")
        self.assertEqual(prepend_destdir("/home/me/"), "./home/me")
        self.assertEqual(prepend_destdir("/home/me/../me2"), "./home/me2")

        os.environ["DESTDIR"] = "bar"
        self.assertEqual(prepend_destdir("/home/me"), "bar/home/me")
        self.assertEqual(prepend_destdir("/home/me/"), "bar/home/me")
        self.assertEqual(prepend_destdir("/home/me/../me2"), "bar/home/me2")

    def test_relative(self):
        # No destdir set
        os.environ["DESTDIR"] = ""
        self.assertEqual(prepend_destdir("foo"), "foo")
        self.assertEqual(prepend_destdir("../foo"), "../foo")

        # Destdir set
        os.environ["DESTDIR"] = "/opt"
        with self.assertRaises(PrependDestdirError):
            prepend_destdir("foo")
        with self.assertRaises(PrependDestdirError):
            prepend_destdir("../foo")

    def test_escaping(self):
        os.environ["DESTDIR"] = "/opt"
        with self.assertRaises(PrependDestdirError):
            prepend_destdir("/foo/../..")


if __name__ == '__main__':
    unittest.TestCase.longMessage = True
    unittest.main()
