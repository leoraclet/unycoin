# Copyright (c) 2022 Neutronys

# The software is distributed under the MIT software license
# See the accompanying file LICENSE in the main directory of
# the project for more details.

"""

Some basic unit testing of MURMUR3-32.

"""


import unittest

from crypto.mmh3 import murmur3


class TestMurmur3(unittest.TestCase):

    """
    MURMUR3-32 unit tests
    """

    def test_murmur3(self):

        # Murmur3 should output the
        # correct hash bytes

        msg = b'Hello, World!'

        mmh3 = murmur3(msg)
        expected = 592631239

        self.assertEqual(mmh3, expected)


if __name__ == '__main__':
    unittest.main()
