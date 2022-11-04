# Copyright (c) 2022 Neutronys

# The software is distributed under the MIT software license
# See the accompanying file LICENSE in the main directory of
# the project for more details.


"""

A pure python implementation of MURMUR3-32.

"""


def load_data(data, i):

    """
    Load bytes in little endian order
    """

    return (
        (data[i] & 0xff)
        | ((data[i + 1] & 0xff) << 8)
        | ((data[i + 2] & 0xff) << 16)
        | (data[i + 3] << 24)
    )


def murmur3(data, seed=0):

    """
    Compute MURMUR3 hash of given bytes
    """

    c1 = 0xcc9e2d51
    c2 = 0x1b873593

    length = len(data)
    h1 = seed

    # Round down to 4 byte block
    roundedEnd = (length & 0xfffffffc)

    for i in range(0, roundedEnd, 4):

        # Load bytes
        k1 = load_data(data, i)

        k1 *= c1
        k1 = (k1 << 15) | ((k1 & 0xffffffff) >> 17)  # ROTL32(k1, 15)
        k1 *= c2
        h1 ^= k1
        h1 = (h1 << 13) | ((h1 & 0xffffffff) >> 19)  # ROTL32(h1, 13)
        h1 = h1 * 5 + 0xe6546b64

    # Tail
    val = length & 0x03
    k1 = 0

    if val == 3:
        k1 = (data[roundedEnd + 2] & 0xff) << 16

    # Fallthrough
    if val in [2, 3]:
        k1 |= (data[roundedEnd + 1] & 0xff) << 8

    # Fallthrough
    if val in [1, 2, 3]:

        k1 |= data[roundedEnd] & 0xff
        k1 *= c1
        k1 = (k1 << 15) | ((k1 & 0xffffffff) >> 17)  # ROTL32(k1, 15)
        k1 *= c2
        h1 ^= k1

    # Finalization
    h1 ^= length
    h1 ^= ((h1 & 0xffffffff) >> 16)
    h1 *= 0x85ebca6b
    h1 ^= ((h1 & 0xffffffff) >> 13)
    h1 *= 0xc2b2ae35
    h1 ^= ((h1 & 0xffffffff) >> 16)

    return h1 & 0xffffffff


if __name__ == '__main__':
    pass
