# Copyright (c) 2022 Neutronys

# The software is distributed under the MIT software license
# See the accompanying file LICENSE in the main directory of
# the project for more details.

"""

Some basic unit testing of RIPEMD-160.

"""

import hashlib
import unittest

from crypto.ripemd160 import Ripemd160


class TestSha256(unittest.TestCase):

    """
    RIPEMD-160 unit tests
    """

    def test_sha256_vs_hashlib(self):

        # Output of Ripemd160 should be similar to the
        # output of the standard python ripemd160

        msg = b'Hello, World!'

        hash1 = hashlib.new('ripemd160', msg).digest()
        hash2 = Ripemd160(msg).digest()

        self.assertEqual(hash1, hash2)

    def test_sha256_type_error(self):

        # If input is not bytes
        # Ripemd160 should raise a TypeError

        msg = 'Hello, World!'

        with self.assertRaises(TypeError):
            Ripemd160(msg).digest()


if __name__ == '__main__':
    unittest.main()
