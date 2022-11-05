# Copyright (c) 2022 Neutronys

# The software is distributed under the MIT software license
# See the accompanying file LICENSE in the main directory of
# the project for more details.


"""

This file implements some basic utility functions.

"""


from .ripemd160 import Ripemd160
from .sha256 import Sha256


def sha256(b):

    """
    Compute SHA-256 hash of given bytes
    """

    return Sha256(b).digest()


def ripemd160(b):

    """
    Compute RIPEMD-160 hash of given bytes
    """

    return Ripemd160(b).digest()


def hash256(b):

    """
    Compute double SHA-256 of given bytes
    """

    return sha256(sha256(b))


def hash160(b):

    """
    Compute RIPEMD-160 of SHA-256 of given bytes
    """

    return ripemd160(sha256(b))


if __name__ == '__main__':
    pass
