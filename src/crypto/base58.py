# Copyright (c) 2022 Neutronys

# The software is distributed under the MIT software license
# See the accompanying file LICENSE in the main directory of
# the project for more details.


"""

A pure python implementation of BASE-58.

"""


from .hasher import hash256


ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def b58encode(b):

    """
    Encode bytes to Base 58
    """

    # Count leading zeros
    c = len(b) - len(b.lstrip(b'\0'))

    # Bytes to integer
    n = int.from_bytes(b, 'big')
    s = bytes()

    # Integer to Base 58
    while n:

        n, i = divmod(n, 58)
        s = ALPHABET[i:i + 1] + s

    return b'1' * c + s


def b58decode(b):

    """
    Decode Base 58 to bytes
    """

    # Count leading zeros
    c = len(b) - len(b.lstrip(b'\0'))

    n = 0

    # Base 58 to integer
    for char in b:

        i = ALPHABET.index(char)
        n = n * 58 + i

    s = []

    # Integer to bytes
    while n:

        n, mod = divmod(n, 256)
        s.append(mod)

    return b'\0' * c + bytes(s[::-1])


def b58encode_check(b):

    """
    Encode bytes to Base 58 with checksum
    """

    return b58encode(b + hash256(b)[:4])


def b58decode_check(b):

    """
    Decode Base 58 with checksum to bytes
    """

    decoded = b58decode(b)

    # Separate database and checksum
    checksum = decoded[-4:]
    result = decoded[:-4]

    # Verify checksum
    if checksum != hash256(result)[:4]:
        raise Exception('Invalid checksum')

    return result


if __name__ == '__main__':
    pass
