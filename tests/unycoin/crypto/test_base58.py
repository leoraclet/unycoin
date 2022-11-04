# Copyright (c) 2022 Neutronys

# The software is distributed under the MIT software license
# See the accompanying file LICENSE in the main directory of
# the project for more details.

"""

Some basic unit testing of BASE-58.

"""


import unittest

from crypto.base58 import (
    b58decode,
    b58encode,
    b58decode_check,
    b58encode_check
)


class TestBase58(unittest.TestCase):

    """
    BASE-58 unit tests
    """

    def test_base58_encode(self):

        # b58encode should output correct
        # encoded bytes

        msg = b'Hello, World!'

        base58 = b58encode(msg)
        expected = b'72k1xXWG59fYdzSNoA'

        self.assertEqual(base58, expected)

    def test_base58_decode(self):

        # b58decode should output correct
        # decoded bytes

        msg = b'72k1xXWG59fYdzSNoA'
        expected = b'Hello, World!'

        self.assertEqual(b58decode(msg), expected)

    def test_base58_encode_check(self):

        # b58encode_check should output correct
        # encoded bytes and checksum

        msg = b'Hello, World!'

        base58 = b58encode_check(msg)
        expected = b'gTazoqFvnegwaKM8v1B33sR'

        self.assertEqual(base58, expected)

    def test_base58_decode_check(self):

        # b58decode_check should output correct
        # decoded bytes and verify checksum

        msg = b'gTazoqFvnegwaKM8v1B33sR'
        expected = b'Hello, World!'

        self.assertEqual(b58decode_check(msg), expected)


if __name__ == '__main__':
    unittest.main()
