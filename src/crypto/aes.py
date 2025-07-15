# Copyright (c) 2022 Neutronys

# The software is distributed under the MIT software license
# See the accompanying file LICENSE in the main directory of
# the project for more details.


"""

A pure python implementation of AES-256.

"""


# This implementation use CBC as the default
# block cipher mode of operation.


import hashlib
import hmac
import os


# Key size in bytes and number of rounds
# for an output of 256 bits ( 32 bytes )

KEY_SIZE = 32
ROUNDS = 14

# 8-bit substitution box
S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

# 8-bit inverse substitution box
INV_S_BOX = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
    0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
    0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
    0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
    0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
    0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
    0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
    0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
    0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
    0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
    0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
    0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
]

R_CON = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
]


def shift_rows(s):

    """
    Bytes in each row of the state are shifted cyclically to the left.
    The number of places each byte is shifted differs incrementally for
    each row.
    """

    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


def inv_shift_rows(s):

    """
    Bytes in each row of the state are shifted cyclically to the right.
    The number of places each byte is shifted differs incrementally for
    each row
    """

    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]


def xtime(a):

    """
    Multiply the given polynomial by x
    """

    # If x^8 is set, XOR with irreducible polynomial 0x1B to
    # return within range. AND with 0xFF to remove
    # extraneous bits to the left

    if a & 0x80:
        return ((a << 1) ^ 0x1B) & 0xFF
    else:
        return a << 1


def mix_columns(s):

    """
    Each column of the state is multiplied
    with a fixed polynomial
    """

    for i in range(4):

        t = s[i][0] ^ s[i][1] ^ s[i][2] ^ s[i][3]
        u = s[i][0]

        s[i][0] ^= t ^ xtime(s[i][0] ^ s[i][1])
        s[i][1] ^= t ^ xtime(s[i][1] ^ s[i][2])
        s[i][2] ^= t ^ xtime(s[i][2] ^ s[i][3])
        s[i][3] ^= t ^ xtime(s[i][3] ^ u)


def inv_mix_columns(s):

    """
    Each column of the state is divided
    with a fixed polynomial
    """

    for i in range(4):

        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))

        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)


def add_round_key(s, k):

    """
    Each byte of the state is combined with a byte
    of the round subkey using the XOR operation
    """

    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]


def sub_bytes(s):

    """
    Each byte in the state is replaced with its
    entry in a fixed 8-bit lookup table
    """

    for i in range(4):
        for j in range(4):
            s[i][j] = S_BOX[s[i][j]]


def inv_sub_bytes(s):

    """
    Each byte in the state is replaced with its
    entry in a fixed 8-bit lookup table
    """

    for i in range(4):
        for j in range(4):
            s[i][j] = INV_S_BOX[s[i][j]]


def sub_word(word):

    """
    Each of the four bytes of the word is replaced
    with its entry in a fixed 8-bit lookup table
    """

    return [S_BOX[b] for b in word]


def rot_word(word):

    """
    One-byte left circular shift
    """

    return word[1:] + word[:1]


def bytes2matrix(b):

    """
    Encode bytes to a 4x4 matrix
    """

    return [list(b[i:i + 4]) for i in range(0, len(b), 4)]


def matrix2bytes(m):

    """
    Decode a 4x4 matrix to bytes
    """

    return bytes(sum(m, []))


def xor_bytes(a, b):

    """
    XOR between each byte of bytes
    """

    return bytes(i ^ j for i, j in zip(a, b))


def pad(plaintext):

    """
    Extend plaintext size to a multiple of 16
    """

    padding_len = 16 - (len(plaintext) % 16)
    padding = bytes([padding_len] * padding_len)

    return plaintext + padding


def unpad(plaintext):

    """
    Recover plaintext original size by removing
    padding from padded plaintext
    """

    padding_len = plaintext[-1]

    # Padding should be positive
    if padding_len <= 0:
        raise Exception('Invalid padding')

    message = plaintext[:-padding_len]
    padding = plaintext[-padding_len:]

    # check all padding lengths
    if not all(p == padding_len for p in padding):
        raise Exception('Invalid padding')

    return message


def split_blocks(message):

    """
    Split message into blocks of 16 bytes
    """

    if len(message) % 16 != 0:
        raise Exception('Invalid message length')

    # Split message into blocks of 16 bytes
    return [message[i:i + 16] for i in range(0, len(message), 16)]


def key_expansion(key):

    """
    Expand a short key into a number of
    separate round keys
    """

    k = bytes2matrix(key)
    keys = []

    # Expand master key
    for i in range(8, 4 * (ROUNDS + 1)):

        word = list(k[-1])

        if i % 8 == 0:
            word = sub_word(rot_word(word))
            word[0] ^= R_CON[i // 8]

        elif i % 8 == 4:
            word = sub_word(word)

        k.append(list(xor_bytes(word, k[-8])))

    # Reshape keys in a 4x4 matrix
    for i in range(len(k) // 4):
        keys.append(k[4 * i: 4 * (i + 1)])

    return keys


def encrypt_block(block, key):

    """
    Encrypt block of 16 bytes using AES-256
    """

    block = bytes2matrix(block)

    add_round_key(block, key[0])

    for i in range(1, ROUNDS):

        sub_bytes(block)
        shift_rows(block)
        mix_columns(block)
        add_round_key(block, key[i])

    sub_bytes(block)
    shift_rows(block)
    add_round_key(block, key[-1])

    return matrix2bytes(block)


def decrypt_block(block, key):

    """
    Decrypt block of 16 bytes using AES-256
    """

    block = bytes2matrix(block)

    add_round_key(block, key[-1])
    inv_shift_rows(block)
    inv_sub_bytes(block)

    for i in reversed(range(1, ROUNDS)):

        add_round_key(block, key[i])
        inv_mix_columns(block)
        inv_shift_rows(block)
        inv_sub_bytes(block)

    add_round_key(block, key[0])

    return matrix2bytes(block)


def encrypt_cbc(message, key, iv):

    """
    Encrypt message using AES-256 with CBC mode
    """

    message = pad(message)
    key = key_expansion(key)

    blocks = [iv]

    for block in split_blocks(message):

        block = xor_bytes(block, blocks[-1])
        block = encrypt_block(block, key)

        blocks.append(block)

    return b''.join(blocks[1:])


def decrypt_cbc(message, key, iv):

    """
    Decrypt message using AES-256 with CBC mode
    """

    key = key_expansion(key)
    blocks = [iv]

    for block in split_blocks(message):

        block = decrypt_block(block, key)
        block = xor_bytes(blocks[-1], block)

        blocks.append(block)

    return unpad(b''.join(blocks[1:]))


def get_key_iv(password, salt):

    """
    Stretches the password and extracts an AES key,
    an HMAC key and an initialization vector
    """

    stretched = hashlib.pbkdf2_hmac('sha256', password, salt, 100000, 96)
    return stretched[:32], stretched[32:64], stretched[64:]


def encrypt(plain, key):

    """
    Encrypts plaintext using AES-256, an HMAC to verify
    integrity, and PBKDF2 to stretch the given key
    """

    salt = os.urandom(32)
    key, hmac_key, iv = get_key_iv(key, salt)

    ciphertext = encrypt_cbc(plain, key, iv)
    hmac_bytes = hmac.new(hmac_key, salt + ciphertext, 'sha256')

    return hmac_bytes.digest() + salt + ciphertext


def decrypt(cipher, key):

    """
    Decrypts ciphertext using AES-256, an HMAC to verify
    integrity, and PBKDF2 to stretch the given key
    """

    hmac_bytes, cipher = cipher[:32], cipher[32:]
    salt_bytes, cipher = cipher[:32], cipher[32:]

    key, hmac_key, iv = get_key_iv(key, salt_bytes)
    expected_hmac = hmac.new(hmac_key, salt_bytes + cipher, 'sha256')
    
    # Verify digest integrity
    if not hmac.compare_digest(hmac_bytes, expected_hmac.digest()):
        raise Exception('Invalid ciphertext')

    return decrypt_cbc(cipher, key, iv)


if __name__ == '__main__':
    pass
