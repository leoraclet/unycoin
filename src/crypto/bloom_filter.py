# Copyright (c) 2022 Neutronys

# The software is distributed under the MIT software license
# See the accompanying file LICENSE in the main directory of
# the project for more details.


"""

A pure python implementation of a Bloom Filter.

"""


# Murmur3 is used as the default hash function
# for bloom filters as it is faster to compute
# than SHA256 or RIPEMD-160.


from math import log

from .mmh3 import murmur3
from utils import (
    bits2bytes,
    bytes2bits,
    bytes2int,
    int2bytes,
    int2varint,
    varint2int,
)


C = 0xfba4c795  # Magic constant
F = 0xffffffff


class BloomFilter:

    """
    Bloom filter class
    """

    # m: Size of filter in bytes
    # k: Number of hash functions

    def __init__(self, n=10, p=1e-9, tweak=0):

        self.m = int(-(n * log(p)) / (log(2) ** 2))
        self.k = int((self.m / n) * log(2))
        self.m += 8 - (self.m % 8)

        self.tweak = tweak
        self.bit_array = [0] * self.m

    def hashes(self, data):

        """
        Compute hashes from given bytes
        """

        hashes = []

        for i in range(self.k):

            seed = (i * C + self.tweak) % F
            hashes.append(murmur3(data, seed) % self.m)

        return hashes

    def add(self, data):

        """
        Add an element to the filter
        """

        for h in self.hashes(data):
            self.bit_array[h] = 1

    def has(self, data):

        """
        Check if the element is in the filter
        """

        for h in self.hashes(data):
            if self.bit_array[h] == 0:
                return False

        return True

    def to_bytes(self):

        """
        Encode bitarray to bytes
        """

        return bits2bytes(self.bit_array)

    def encode(self):

        """
        Encode bloom filter to bytes
        """

        s = bytes()

        # Size of the bloom filter in bytes
        s += int2varint(self.m // 8)

        # Bitarray to bytes
        s += self.to_bytes()

        # Number of hash functions to bytes
        s += int2bytes(self.k, 4)

        # Tweak value
        s += int2bytes(self.tweak, 4)

        return s

    @classmethod
    def decode(cls, s):

        """
        Decode bytes to bloom filter
        """

        bf = BloomFilter()

        # Size of the bloom filter in bytes
        bf.m = varint2int(s) * 8

        # Bytes to bitarray
        bf.bitarray = bytes2bits(s.read(bf.m // 8))

        # Number of hash functions from bytes
        bf.k = bytes2int(s.read(4))

        # Read tweak from bytes
        bf.tweak = bytes2int(s.read(4))

        return bf

    def to_json(self):

        """
        Encode bloom filter to JSON
        """

        return {
            'size': self.m,
            'num_hash': self.k,
            'bit_array': self.to_bytes(),
            'tweak': self.tweak
        }


if __name__ == '__main__':
    pass
