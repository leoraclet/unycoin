# Copyright (c) 2022 Neutronys

# The software is distributed under the MIT software license
# See the accompanying file LICENSE in the main directory of
# the project for more details.

"""

A pure python implementation of SHA-256.

"""


import copy
import struct


F = 0xFFFFFFFF
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]
H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]


def ror(x, y):
    return ((x >> y) | (x << (32 - y))) & F


def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def ch(x, y, z):
    return (x & y) ^ ((~x) & z)


def pad(msg_len):

    """
    Build message padding from length
    """

    length = struct.pack('!Q', msg_len << 3)
    mdi = msg_len & 0x3F

    if mdi < 56:
        pad_len = 55 - mdi
    else:
        pad_len = 119 - mdi

    return b'\x80' + (b'\x00' * pad_len) + length


def compress(cache, _h):

    """
    SHA-256 compression function
    """

    # Unpack given bytes
    w = [0] * 64
    w[0:16] = struct.unpack('!16L', cache)

    for i in range(16, 64):

        s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & F

    # Copy current state
    a, b, c, d, e, f, g, h = _h

    for i in range(64):

        s0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)
        t2 = s0 + maj(a, b, c)
        s1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)
        t1 = h + s1 + ch(e, f, g) + K[i] + w[i]

        h = g
        g = f
        f = e
        e = (d + t1) & F
        d = c
        c = b
        b = a
        a = (t1 + t2) & F

    # Update current state
    for i, (x, y) in enumerate(zip(_h, [a, b, c, d, e, f, g, h])):
        _h[i] = (x + y) & F


class Sha256:

    """
    SHA-256 class
    """

    def __init__(self, b):

        # Initialize hash values
        self.h = copy.deepcopy(H)

        self.cache = b''
        self.counter = 0

        # Update state
        self.update(b)

    def update(self, b):

        """
        Update current state
        """

        self.counter += len(b)
        self.cache += b

        while len(self.cache) >= 64:

            compress(self.cache[:64], self.h)
            self.cache = self.cache[64:]

    def digest(self):

        """
        Current state to bytes
        """

        self.update(pad(self.counter))
        data = [struct.pack('!L', i) for i in self.h[:8]]

        return b''.join(data)


if __name__ == '__main__':
    pass
