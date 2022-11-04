# Copyright (c) 2022 Neutronys

# The software is distributed under the MIT software license
# See the accompanying file LICENSE in the main directory of
# the project for more details.

"""

Some basic unit testing of SHA-256.

"""


import hashlib
import unittest

from crypto.sha256 import Sha256


class TestSha256(unittest.TestCase):

    """
    SHA-256 unit tests
    """

    def test_sha256_vs_hashlib(self):

        # Output of Sha256 should be similar to the
        # output of the standard python sha256

        msg = b'Hello, World!'

        hash1 = hashlib.sha256(msg).digest()
        hash2 = Sha256(msg).digest()

        self.assertEqual(hash1, hash2)

    def test_sha256_type_error(self):

        # If input is not bytes
        # Sha256 should raise a TypeError

        msg = 'Hello, World!'

        with self.assertRaises(TypeError):
            Sha256(msg).digest()


if __name__ == '__main__':
    unittest.main()
