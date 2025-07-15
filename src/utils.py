# Copyright (c) 2022 Neutronys

# The software is distributed under the MIT software license
# See the accompanying file LICENSE in the main directory of
# the project for more details.


"""

This file implements some basic utility functions.

"""


from constants import (
    MAX_TARGET, 
    THREE_DAYS,
)


def int2bytes(nb, size):

    """
    Encode integer to bytes in little endian order
    """

    return nb.to_bytes(size, 'little')


def bytes2int(b):

    """
    Decode bytes in little endian order to integer
    """

    return int.from_bytes(b, 'little')


def int2varint(i):

    """
    Encode integer as compact integer to bytes
    """

    if i <= 0xfc:
        return int2bytes(i, 1)

    if i <= 0xffff:
        return '\xfd' + int2bytes(i, 2)

    if i <= 0xffffffff:
        return '\xfe' + int2bytes(i, 4)

    if i <= 0xffffffffffffffff:
        return '\xff' + int2bytes(i, 8)


def varint2int(s):

    """
    Decode bytes as compact integer to integer
    """

    b = s.read(1)[0]

    if b == '\xfd':
        return bytes2int(s.read(2))

    if b == '\xfe':
        return bytes2int(s.read(4))

    if b == '\xff':
        return bytes2int(s.read(8))

    return b


def bits2target(bits):

    """
    Convert given bits to target
    """

    c = bytes2int(bits[:-1])
    e = bits[-1]

    return c * 256 ** (e - 3)


def target2bits(target):

    """
    Convert given target to bits
    """

    b = target.to_bytes(32, 'big')
    b = b.lstrip(b'\0')

    # e: exponent
    # c: coefficient

    if b[0] > 0x7f:
        e, c = len(b) + 1, b'\0' + b[:2]
    else:
        e, c = len(b), b[:3]

    return c[::-1] + bytes([e])


def bits2bytes(bits):

    """
    Encode bits filed to bytes
    """

    result = bytearray(len(bits) // 8)

    # Loop over each bit in the bits field
    for i, bit in enumerate(bits):

        if bit:
            byte_index, bit_index = divmod(i, 8)
            result[byte_index] |= 1 << bit_index

    return bytes(result)


def bytes2bits(b):

    """
    Decode bytes to bits field
    """

    flag_bits = []

    for byte in b:

        # Iterate over each bit, right-to-left
        for _ in range(8):

            flag_bits.append(byte & 1)
            byte >>= 1

    return flag_bits


def new_bits(bits, dt):

    """
    Calculate new target from last bits and
    time differential
    """

    # Check time differential boundaries
    dt = min(THREE_DAYS * 4, dt)
    dt = max(THREE_DAYS / 4, dt)

    # Calculate new target
    new_target = bits2target(bits) * dt // THREE_DAYS
    new_target = max(MAX_TARGET, new_target)

    return target2bits(new_target)


if __name__ == '__main__':
    pass
