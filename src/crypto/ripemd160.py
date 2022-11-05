# Copyright (c) 2022 Neutronys

# The software is distributed under the MIT software license
# See the accompanying file LICENSE in the main directory of
# the project for more details.


"""

A pure python implementation of RIPEMD-160.

"""


import copy
import struct


I32 = 0x100000000           # 2^32
F32 = 0x0FFFFFFFF           # 2^31 + 2^30 + ... + 2^0

P = [0x0000080] + [0] * 63  # Padding
K = [
    0x00000000,
    0x5A827999,
    0x6ED9EBA1,
    0x8F1BBCDC,
    0xA953FD4E,
    0x50A28BE6,
    0x5C4DD124,
    0x6D703EF3,
    0x7A6D76E9,
    0x00000000,
]
S = [
    0x67452301,
    0xEFCDAB89,
    0x98BADCFE,
    0x10325476,
    0xC3D2E1F0,
]
F = [
    lambda x, y, z: x ^ y ^ z,                     # F0 (FF)
    lambda x, y, z: (x & y) | ((~x % I32) & z),    # F1 (GG)
    lambda x, y, z: (x | (~y % I32)) ^ z,          # F2 (HH)
    lambda x, y, z: (x & z) | ((~z % I32) & y),    # F3 (II)
    lambda x, y, z: x ^ (y | (~z % I32)),          # F4 (JJ)
]


def rr(a, b, c, d, e, fj, kj, sj, rj, x):

    """
    Basic operations on current state
    """

    a = (a + F[fj](b, c, d) + x[rj] + K[kj]) % I32

    a = ((a << sj) & F32) | (a >> (32 - sj))  # ROL(a, sj) -> Rotate left
    c = ((c << 10) & F32) | (c >> (32 - 10))  # ROL(c, 10) -> Rotate left

    return (a + e) % I32, c


def transform(state, block):

    """
    RIPEMD-160 transform function
    """

    # Unpack given block of bytes
    x = struct.unpack('<16L', bytes(block[:64]))

    a = state[0]
    b = state[1]
    c = state[2]
    d = state[3]
    e = state[4]

    # Round 1
    a, c = rr(a, b, c, d, e, 0, 0, 11,  0, x)
    e, b = rr(e, a, b, c, d, 0, 0, 14,  1, x)
    d, a = rr(d, e, a, b, c, 0, 0, 15,  2, x)
    c, e = rr(c, d, e, a, b, 0, 0, 12,  3, x)
    b, d = rr(b, c, d, e, a, 0, 0,  5,  4, x)
    a, c = rr(a, b, c, d, e, 0, 0,  8,  5, x)
    e, b = rr(e, a, b, c, d, 0, 0,  7,  6, x)
    d, a = rr(d, e, a, b, c, 0, 0,  9,  7, x)
    c, e = rr(c, d, e, a, b, 0, 0, 11,  8, x)
    b, d = rr(b, c, d, e, a, 0, 0, 13,  9, x)
    a, c = rr(a, b, c, d, e, 0, 0, 14, 10, x)
    e, b = rr(e, a, b, c, d, 0, 0, 15, 11, x)
    d, a = rr(d, e, a, b, c, 0, 0,  6, 12, x)
    c, e = rr(c, d, e, a, b, 0, 0,  7, 13, x)
    b, d = rr(b, c, d, e, a, 0, 0,  9, 14, x)
    a, c = rr(a, b, c, d, e, 0, 0,  8, 15, x)

    # Round 2
    e, b = rr(e, a, b, c, d, 1, 1,  7,  7, x)
    d, a = rr(d, e, a, b, c, 1, 1,  6,  4, x)
    c, e = rr(c, d, e, a, b, 1, 1,  8, 13, x)
    b, d = rr(b, c, d, e, a, 1, 1, 13,  1, x)
    a, c = rr(a, b, c, d, e, 1, 1, 11, 10, x)
    e, b = rr(e, a, b, c, d, 1, 1,  9,  6, x)
    d, a = rr(d, e, a, b, c, 1, 1,  7, 15, x)
    c, e = rr(c, d, e, a, b, 1, 1, 15,  3, x)
    b, d = rr(b, c, d, e, a, 1, 1,  7, 12, x)
    a, c = rr(a, b, c, d, e, 1, 1, 12,  0, x)
    e, b = rr(e, a, b, c, d, 1, 1, 15,  9, x)
    d, a = rr(d, e, a, b, c, 1, 1,  9,  5, x)
    c, e = rr(c, d, e, a, b, 1, 1, 11,  2, x)
    b, d = rr(b, c, d, e, a, 1, 1,  7, 14, x)
    a, c = rr(a, b, c, d, e, 1, 1, 13, 11, x)
    e, b = rr(e, a, b, c, d, 1, 1, 12,  8, x)

    # Round 3
    d, a = rr(d, e, a, b, c, 2, 2, 11,  3, x)
    c, e = rr(c, d, e, a, b, 2, 2, 13, 10, x)
    b, d = rr(b, c, d, e, a, 2, 2,  6, 14, x)
    a, c = rr(a, b, c, d, e, 2, 2,  7,  4, x)
    e, b = rr(e, a, b, c, d, 2, 2, 14,  9, x)
    d, a = rr(d, e, a, b, c, 2, 2,  9, 15, x)
    c, e = rr(c, d, e, a, b, 2, 2, 13,  8, x)
    b, d = rr(b, c, d, e, a, 2, 2, 15,  1, x)
    a, c = rr(a, b, c, d, e, 2, 2, 14,  2, x)
    e, b = rr(e, a, b, c, d, 2, 2,  8,  7, x)
    d, a = rr(d, e, a, b, c, 2, 2, 13,  0, x)
    c, e = rr(c, d, e, a, b, 2, 2,  6,  6, x)
    b, d = rr(b, c, d, e, a, 2, 2,  5, 13, x)
    a, c = rr(a, b, c, d, e, 2, 2, 12, 11, x)
    e, b = rr(e, a, b, c, d, 2, 2,  7,  5, x)
    d, a = rr(d, e, a, b, c, 2, 2,  5, 12, x)

    # Round 4
    c, e = rr(c, d, e, a, b, 3, 3, 11,  1, x)
    b, d = rr(b, c, d, e, a, 3, 3, 12,  9, x)
    a, c = rr(a, b, c, d, e, 3, 3, 14, 11, x)
    e, b = rr(e, a, b, c, d, 3, 3, 15, 10, x)
    d, a = rr(d, e, a, b, c, 3, 3, 14,  0, x)
    c, e = rr(c, d, e, a, b, 3, 3, 15,  8, x)
    b, d = rr(b, c, d, e, a, 3, 3,  9, 12, x)
    a, c = rr(a, b, c, d, e, 3, 3,  8,  4, x)
    e, b = rr(e, a, b, c, d, 3, 3,  9, 13, x)
    d, a = rr(d, e, a, b, c, 3, 3, 14,  3, x)
    c, e = rr(c, d, e, a, b, 3, 3,  5,  7, x)
    b, d = rr(b, c, d, e, a, 3, 3,  6, 15, x)
    a, c = rr(a, b, c, d, e, 3, 3,  8, 14, x)
    e, b = rr(e, a, b, c, d, 3, 3,  6,  5, x)
    d, a = rr(d, e, a, b, c, 3, 3,  5,  6, x)
    c, e = rr(c, d, e, a, b, 3, 3, 12,  2, x)

    # Round 5
    b, d = rr(b, c, d, e, a, 4, 4,  9,  4, x)
    a, c = rr(a, b, c, d, e, 4, 4, 15,  0, x)
    e, b = rr(e, a, b, c, d, 4, 4,  5,  5, x)
    d, a = rr(d, e, a, b, c, 4, 4, 11,  9, x)
    c, e = rr(c, d, e, a, b, 4, 4,  6,  7, x)
    b, d = rr(b, c, d, e, a, 4, 4,  8, 12, x)
    a, c = rr(a, b, c, d, e, 4, 4, 13,  2, x)
    e, b = rr(e, a, b, c, d, 4, 4, 12, 10, x)
    d, a = rr(d, e, a, b, c, 4, 4,  5, 14, x)
    c, e = rr(c, d, e, a, b, 4, 4, 12,  1, x)
    b, d = rr(b, c, d, e, a, 4, 4, 13,  3, x)
    a, c = rr(a, b, c, d, e, 4, 4, 14,  8, x)
    e, b = rr(e, a, b, c, d, 4, 4, 11, 11, x)
    d, a = rr(d, e, a, b, c, 4, 4,  8,  6, x)
    c, e = rr(c, d, e, a, b, 4, 4,  5, 15, x)
    b, d = rr(b, c, d, e, a, 4, 4,  6, 13, x)

    a, aa = state[0], a
    b, bb = state[1], b
    c, cc = state[2], c
    d, dd = state[3], d
    e, ee = state[4], e

    # Parallel round 1
    a, c = rr(a, b, c, d, e, 4, 5,  8,  5, x)
    e, b = rr(e, a, b, c, d, 4, 5,  9, 14, x)
    d, a = rr(d, e, a, b, c, 4, 5,  9,  7, x)
    c, e = rr(c, d, e, a, b, 4, 5, 11,  0, x)
    b, d = rr(b, c, d, e, a, 4, 5, 13,  9, x)
    a, c = rr(a, b, c, d, e, 4, 5, 15,  2, x)
    e, b = rr(e, a, b, c, d, 4, 5, 15, 11, x)
    d, a = rr(d, e, a, b, c, 4, 5,  5,  4, x)
    c, e = rr(c, d, e, a, b, 4, 5,  7, 13, x)
    b, d = rr(b, c, d, e, a, 4, 5,  7,  6, x)
    a, c = rr(a, b, c, d, e, 4, 5,  8, 15, x)
    e, b = rr(e, a, b, c, d, 4, 5, 11,  8, x)
    d, a = rr(d, e, a, b, c, 4, 5, 14,  1, x)
    c, e = rr(c, d, e, a, b, 4, 5, 14, 10, x)
    b, d = rr(b, c, d, e, a, 4, 5, 12,  3, x)
    a, c = rr(a, b, c, d, e, 4, 5,  6, 12, x)

    # Parallel round 2
    e, b = rr(e, a, b, c, d, 3, 6,  9,  6, x)
    d, a = rr(d, e, a, b, c, 3, 6, 13, 11, x)
    c, e = rr(c, d, e, a, b, 3, 6, 15,  3, x)
    b, d = rr(b, c, d, e, a, 3, 6,  7,  7, x)
    a, c = rr(a, b, c, d, e, 3, 6, 12,  0, x)
    e, b = rr(e, a, b, c, d, 3, 6,  8, 13, x)
    d, a = rr(d, e, a, b, c, 3, 6,  9,  5, x)
    c, e = rr(c, d, e, a, b, 3, 6, 11, 10, x)
    b, d = rr(b, c, d, e, a, 3, 6,  7, 14, x)
    a, c = rr(a, b, c, d, e, 3, 6,  7, 15, x)
    e, b = rr(e, a, b, c, d, 3, 6, 12,  8, x)
    d, a = rr(d, e, a, b, c, 3, 6,  7, 12, x)
    c, e = rr(c, d, e, a, b, 3, 6,  6,  4, x)
    b, d = rr(b, c, d, e, a, 3, 6, 15,  9, x)
    a, c = rr(a, b, c, d, e, 3, 6, 13,  1, x)
    e, b = rr(e, a, b, c, d, 3, 6, 11,  2, x)

    # Parallel round 3
    d, a = rr(d, e, a, b, c, 2, 7,  9, 15, x)
    c, e = rr(c, d, e, a, b, 2, 7,  7,  5, x)
    b, d = rr(b, c, d, e, a, 2, 7, 15,  1, x)
    a, c = rr(a, b, c, d, e, 2, 7, 11,  3, x)
    e, b = rr(e, a, b, c, d, 2, 7,  8,  7, x)
    d, a = rr(d, e, a, b, c, 2, 7,  6, 14, x)
    c, e = rr(c, d, e, a, b, 2, 7,  6,  6, x)
    b, d = rr(b, c, d, e, a, 2, 7, 14,  9, x)
    a, c = rr(a, b, c, d, e, 2, 7, 12, 11, x)
    e, b = rr(e, a, b, c, d, 2, 7, 13,  8, x)
    d, a = rr(d, e, a, b, c, 2, 7,  5, 12, x)
    c, e = rr(c, d, e, a, b, 2, 7, 14,  2, x)
    b, d = rr(b, c, d, e, a, 2, 7, 13, 10, x)
    a, c = rr(a, b, c, d, e, 2, 7, 13,  0, x)
    e, b = rr(e, a, b, c, d, 2, 7,  7,  4, x)
    d, a = rr(d, e, a, b, c, 2, 7,  5, 13, x)

    # Parallel round 4
    c, e = rr(c, d, e, a, b, 1, 8, 15,  8, x)
    b, d = rr(b, c, d, e, a, 1, 8,  5,  6, x)
    a, c = rr(a, b, c, d, e, 1, 8,  8,  4, x)
    e, b = rr(e, a, b, c, d, 1, 8, 11,  1, x)
    d, a = rr(d, e, a, b, c, 1, 8, 14,  3, x)
    c, e = rr(c, d, e, a, b, 1, 8, 14, 11, x)
    b, d = rr(b, c, d, e, a, 1, 8,  6, 15, x)
    a, c = rr(a, b, c, d, e, 1, 8, 14,  0, x)
    e, b = rr(e, a, b, c, d, 1, 8,  6,  5, x)
    d, a = rr(d, e, a, b, c, 1, 8,  9, 12, x)
    c, e = rr(c, d, e, a, b, 1, 8, 12,  2, x)
    b, d = rr(b, c, d, e, a, 1, 8,  9, 13, x)
    a, c = rr(a, b, c, d, e, 1, 8, 12,  9, x)
    e, b = rr(e, a, b, c, d, 1, 8,  5,  7, x)
    d, a = rr(d, e, a, b, c, 1, 8, 15, 10, x)
    c, e = rr(c, d, e, a, b, 1, 8,  8, 14, x)

    # Parallel round 5
    b, d = rr(b, c, d, e, a, 0, 9,  8, 12, x)
    a, c = rr(a, b, c, d, e, 0, 9,  5, 15, x)
    e, b = rr(e, a, b, c, d, 0, 9, 12, 10, x)
    d, a = rr(d, e, a, b, c, 0, 9,  9,  4, x)
    c, e = rr(c, d, e, a, b, 0, 9, 12,  1, x)
    b, d = rr(b, c, d, e, a, 0, 9,  5,  5, x)
    a, c = rr(a, b, c, d, e, 0, 9, 14,  8, x)
    e, b = rr(e, a, b, c, d, 0, 9,  6,  7, x)
    d, a = rr(d, e, a, b, c, 0, 9,  8,  6, x)
    c, e = rr(c, d, e, a, b, 0, 9, 13,  2, x)
    b, d = rr(b, c, d, e, a, 0, 9,  6, 13, x)
    a, c = rr(a, b, c, d, e, 0, 9,  5, 14, x)
    e, b = rr(e, a, b, c, d, 0, 9, 15,  0, x)
    d, a = rr(d, e, a, b, c, 0, 9, 13,  3, x)
    c, e = rr(c, d, e, a, b, 0, 9, 11,  9, x)
    b, d = rr(b, c, d, e, a, 0, 9, 11, 11, x)

    # Combine results
    t = (state[1] + cc + d) % I32
    state[1] = (state[2] + dd + e) % I32
    state[2] = (state[3] + ee + a) % I32
    state[3] = (state[4] + aa + b) % I32
    state[4] = (state[0] + bb + c) % I32
    state[0] = t % I32


class Ripemd160:

    """
    RIPEMD-160 class
    """

    def __init__(self, b):

        self.state = copy.deepcopy(S)
        self.buffer = [0] * 64
        self.count = 0

        # Update current state
        self.update(b, len(b))

    def update(self, b, input_len):

        """
        Update current state
        """

        have = (self.count // 8) % 64
        need = 64 - have
        off = 0

        self.count += 8 * input_len

        if input_len >= need:
            if have:
                for i in range(need):
                    self.buffer[have + i] = b[i]

                transform(self.state, self.buffer)
                off, have = need, 0

            while off + 64 <= input_len:
                transform(self.state, self[off:])
                off += 64

        if off < input_len:
            for i in range(input_len - off):
                self.buffer[have + i] = b[off + i]

    def digest(self):

        """
        Current state to bytes
        """

        pad_len = 64 - ((self.count // 8) % 64)
        size = struct.pack("<Q", self.count)

        if pad_len < 9:
            pad_len += 64

        self.update(P, pad_len - 8)
        self.update(size, 8)

        return struct.pack("<5L", *self.state)


if __name__ == '__main__':
    pass
