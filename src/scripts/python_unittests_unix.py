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


class PrependDestdir(unittest.TestCase):
    def test_base(self):
        os.environ["DESTDIR"] = "/"
        self.assertEqual(prepend_destdir("/home/me"), "/home/me")
        self.assertEqual(prepend_destdir("relative_path"), "/relative_path")
        self.assertEqual(prepend_destdir("./relative_path"), "/relative_path")
        self.assertEqual(prepend_destdir("relative/sub"), "/relative/sub")

        self.assertEqual(prepend_destdir("/home/me/"), "/home/me")
        self.assertEqual(prepend_destdir("relative_path/"), "/relative_path")

        self.assertEqual(prepend_destdir("/home/me/../me2"), "/home/me2")
        self.assertEqual(prepend_destdir("relative/sub/../sub2"), "/relative/sub2")

        os.environ["DESTDIR"] = "/opt"
        self.assertEqual(prepend_destdir("/home/me"), "/opt/home/me")
        self.assertEqual(prepend_destdir("relative_path"), "/opt/relative_path")
        self.assertEqual(prepend_destdir("./relative_path"), "/opt/relative_path")
        self.assertEqual(prepend_destdir("relative/sub"), "/opt/relative/sub")

        self.assertEqual(prepend_destdir("/home/me/"), "/opt/home/me")
        self.assertEqual(prepend_destdir("relative_path/"), "/opt/relative_path")

        self.assertEqual(prepend_destdir("/home/me/../me2"), "/opt/home/me2")
        self.assertEqual(prepend_destdir("relative/sub/../sub2"), "/opt/relative/sub2")


if __name__ == '__main__':
    unittest.TestCase.longMessage = True
    unittest.main()
