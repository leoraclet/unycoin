# Copyright (c) 2022 Neutronys

# The software is distributed under the MIT software license
# See the accompanying file LICENSE in the main directory of
# the project for more details.


"""

A pure python implementation of ECDSA.

"""


# This is a lightweight and pure python implementation of
# Elliptic Curve Cryptography using elegant maths such as
# Jacobian coordinates to speed up ECDSA. Secret integers
# for signing are generated per RFC6979. Secp256k1 is the
# default curve as used by bitcoin. Timing side challenge
# is mitigated via Montgomery point multiplication if you
# use the Montgomery ladder. Else, use the Double-and-add
# algorithm for faster computations.


from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO

import hmac
import os

from .base58 import b58decode_check, b58encode_check
from .hasher import hash160, hash256


# Safe point multiplication ?
SAFE_CRYPTO = True


@dataclass
class Point:

    """
    Point in jacobian coordinates
    """

    x: int = 0
    y: int = 0
    z: int = 0

    def __add__(self, other):

        """
        Add two points in elliptic curves.
        """

        return jacobian_to_point(
            jacobian_add(
                point_to_jacobian(self),
                point_to_jacobian(other)
            )
        )

    def __sub__(self, other):

        """
        Subtract two points in elliptic curves.
        """

        return jacobian_to_point(
            jacobian_add(
                point_to_jacobian(self),
                point_to_jacobian(
                    Point(other.x, -other.y % P)
                )
            )
        )

    def __mul__(self, other):

        """
        Multiply point by scalar in elliptic curves.
        """

        # Montgomery ladder
        if SAFE_CRYPTO:

            return jacobian_to_point(
                jacobian_multiply2(
                    point_to_jacobian(self),
                    other
                )
            )

        # Double-and-add method
        else:

            return jacobian_to_point(
                jacobian_multiply1(
                    point_to_jacobian(self),
                    other
                )
            )


@dataclass
class Signature:

    """
    ECDSA signature
    """

    r: int
    s: int

    def encode(self):

        """
        Encode signature to bytes
        """

        r_bin = self.r.to_bytes(32, 'big')
        s_bin = self.s.to_bytes(32, 'big')

        # Remove leading zeros
        r_bin = r_bin.lstrip(b'\0')
        s_bin = s_bin.lstrip(b'\0')

        if r_bin[0] & 0x80:
            r_bin = b'\0' + r_bin

        if s_bin[0] & 0x80:
            s_bin = b'\0' + s_bin

        r_bin = bytes([0x02, len(r_bin)]) + r_bin
        s_bin = bytes([0x02, len(s_bin)]) + s_bin

        # Encode total length
        length = bytes([0x30, len(r_bin + s_bin)])

        return length + r_bin + s_bin

    @classmethod
    def decode(cls, b):

        """
        Decode bytes to signature
        """

        s = BytesIO(b)

        if s.read(1)[0] != 0x30:
            raise ValueError('Invalid prefix')

        if s.read(1)[0] != len(b) - 2:
            raise ValueError('Invalid length')

        if s.read(1)[0] != 0x02:
            raise ValueError('Invalid prefix')

        # Read first encode integer
        r_l = s.read(1)[0]
        r = int.from_bytes(s.read(r_l), 'big')

        if s.read(1)[0] != 0x02:
            raise ValueError('Invalid prefix')

        # Read second encode integer
        s_l = s.read(1)[0]
        s = int.from_bytes(s.read(s_l), 'big')

        # Verify signature total length
        if len(b) != 6 + r_l + s_l:
            raise ValueError('Invalid length')

        return cls(r, s)


@dataclass
class PublicKey(Point):

    """
    Point in elliptic curves
    """

    def pubkey_hash(self):

        """
        Compute public key hash
        """

        return hash160(self.encode())

    def to_base58(self):

        """
        Encode public key hash to base 58
        """

        pk_hash = self.pubkey_hash()
        version = b'\x00'

        return b58encode_check(version + pk_hash)

    def encode(self, is_compressed=True):

        """
        Encode public key to bytes
        """

        x = self.x.to_bytes(32, 'big')
        y = self.y.to_bytes(32, 'big')

        if is_compressed:
            if self.y & 1 == 0:
                return b'\x02' + x
            else:
                return b'\x03' + x
        else:
            return b'\x04' + x + y

    @classmethod
    def decode(cls, b):

        """
        Decode bytes to public key
        """

        s = BytesIO(b)
        prefix = s.read(1)[0]

        # If it's compressed encoding
        if prefix == 4:

            x = int.from_bytes(s.read(32), 'big')
            y = int.from_bytes(s.read(32), 'big')

            return cls(x, y)

        else:

            x = int.from_bytes(s.read(32), 'big')

            # Compute y squared from curves equation
            y = (pow(x, 3, P) + B) % P

            # Modular square root
            y = pow(y, (P + 1) // 4, P)

            # Negate y according to parity bytes
            if y & 1 != prefix - 2:
                y = -y % P

            return cls(x, y)


@dataclass
class SecretKey:

    """
    Represents an ECDSA private key
    """

    secret: int

    def to_pubkey(self):

        """
        Compute public from secret integer.
        """

        pk = G * self.secret

        return PublicKey(pk.x, pk.y, pk.z)

    def encode(self):

        """
        Encode secret key to bytes
        """

        s = self.secret.to_bytes(32, 'big')

        return b58encode_check(b'\x80' + s + b'\x01')

    @classmethod
    def decode(cls, b):

        """
        Decode bytes to secret key
        """

        s = b58decode_check(b)
        s = int.from_bytes(s[1:-1], 'big')

        return cls(s)


# Curve's parameters
# https://en.bitcoin.it/wiki/Secp256k1

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

A = 0
B = 7

G = Point(
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0X483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def point_to_jacobian(p):

    """
    Convert point to Jacobian coordinates
    """

    return Point(p.x, p.y, 1)


def jacobian_to_point(p):

    """
    Convert Jacobian coordinates to point
    """

    z = pow(p.z, -1, P)  # Modular multiplicative inverse

    x = (p.x * z ** 2) % P
    y = (p.y * z ** 3) % P

    return Point(x, y, 0)


def jacobian_double(p):

    """
    Double a point in elliptic curves
    """

    if p.y == 0:
        return Point(0, 0, 0)

    ysq = (p.y ** 2) % P
    S = (4 * p.x * ysq) % P
    M = (3 * p.x ** 2 + A * p.z ** 4) % P
    nx = (M ** 2 - 2 * S) % P
    ny = (M * (S - nx) - 8 * ysq ** 2) % P
    nz = (2 * p.y * p.z) % P

    return Point(nx, ny, nz)


def jacobian_add(p, q):

    """
    Add two points in elliptic curves
    """

    if p.y == 0:
        return q

    if q.y == 0:
        return p

    U1 = (p.x * q.z ** 2) % P
    U2 = (q.x * p.z ** 2) % P
    S1 = (p.y * q.z ** 3) % P
    S2 = (q.y * p.z ** 3) % P

    if U1 == U2:
        if S1 != S2:
            return Point(0, 0, 1)
        else:
            return jacobian_double(p)

    H = U2 - U1
    R = S2 - S1
    H2 = (H * H) % P
    H3 = (H * H2) % P
    U1H2 = (U1 * H2) % P
    nx = (R ** 2 - H3 - 2 * U1H2) % P
    ny = (R * (U1H2 - nx) - S1 * H3) % P
    nz = (H * p.z * q.z) % P

    return Point(nx, ny, nz)


def jacobian_multiply1(p, s):

    """
    Multiply point and scalar in elliptic curves
    using the double-and-add method
    """

    if p.y == 0 or s == 0:
        return Point(0, 0, 1)

    if s == 1:
        return p

    if s < 0 or s >= N:
        return jacobian_multiply1(p, s % N)

    if (s % 2) == 0:
        return jacobian_double(
            jacobian_multiply1(p, s // 2)
        )

    return jacobian_add(
        jacobian_double(
            jacobian_multiply1(p, s // 2)
        ),
        p
    )


def jacobian_multiply2(p, s):

    """
    Multiply point and scalar in elliptic curves
    using the Montgomery ladder
    """

    R0 = Point()
    R1 = p

    for i in reversed(range(0, N.bit_length())):

        if (s >> i) & 1 == 0:
            R1 = jacobian_add(R0, R1)
            R0 = jacobian_double(R0)

        else:
            R0 = jacobian_add(R0, R1)
            R1 = jacobian_double(R1)

    return R0


def hash_message(message):

    """
    Hash bytes string and convert it to an integer.
    """

    e = int.from_bytes(hash256(message), 'big')

    # FIPS 180 says that when a hash needs to be truncated,
    # the rightmost bits should be discarded.

    if e.bit_length() >= N.bit_length():
        return e >> (e.bit_length() - N.bit_length())

    return e


def deterministic_k(z, s):

    """
    Compute a deterministic integer
    According to RFC6979
    """

    k = b'\x00' * 32
    v = b'\x01' * 32

    if z > N:
        z -= N

    z = z.to_bytes(32, 'big')
    s = s.to_bytes(32, 'big')

    k = hmac.new(k, v + b'\x00' + s + z, sha256).digest()
    v = hmac.new(k, v, sha256).digest()
    k = hmac.new(k, v + b'\x01' + s + z, sha256).digest()
    v = hmac.new(k, v, sha256).digest()

    while True:

        t = b''

        while len(t) * 8 < N.bit_length():

            v = hmac.new(k, v, sha256).digest()
            t = t + v

        # Candidate integer
        c = int.from_bytes(t, 'big')

        if 1 <= c < N:
            break

        k = hmac.new(k, v + b'\x00', sha256).digest()
        v = hmac.new(k, v, sha256).digest()

    return c


def gen_secret_key():

    """
    Generate a cryptographically secure random integer
    It must lie in the [1, N - 1] range
    """

    while True:

        key = int.from_bytes(os.urandom(32), 'big')

        if 1 <= key < N:
            break

    return key


def gen_key_pair():

    """
    Generate a new key pair.
    """

    sk = SecretKey(gen_secret_key())
    vk = sk.to_pubkey()

    return sk, vk


def child_public_keys():

    """
    Compute child public keys.
    """

    # TODO: implement child public keys

    pass


def recover(message, signature):

    """
    Recover public keys from message and signature.
    """

    try:
        sig = Signature.decode(signature)
    except ValueError:
        raise Exception('Bad signature')

    z = hash_message(message)
    r_inv = pow(sig.r, -1, N)

    # Compute y squared from curves equation
    y = (pow(sig.r, 3, P) + B) % P
    y = pow(y, (P + 1) // 4, P)

    # Point and the opposite one
    R1 = Point(sig.r, y)
    R2 = Point(sig.r, -y % P)

    # There is two valid public keys
    Q1 = (R1 * sig.s - G * z) * r_inv
    Q2 = (R2 * sig.s - G * z) * r_inv

    Q1 = PublicKey(Q1.x, Q1.y)
    Q2 = PublicKey(Q2.x, Q2.y)

    return [Q1, Q2]


def sign(message, secret_key):

    """
    Sign message using ECDSA.
    """

    s = int(secret_key.secret)
    z = hash_message(message)

    k = deterministic_k(z, s)
    k_inv = pow(k, -1, N)

    # Compute signature integers
    r = (G * k).x % N
    s = ((z + r * s) * k_inv) % N

    return Signature(r, s)


def verify(message, signature, public_key):

    """
    Verify signature using ECDSA.
    """

    # Catch decoding errors
    try:
        sig = Signature.decode(signature)
        pk = PublicKey.decode(public_key)

    except ValueError:
        return False

    # Verify signature integers
    if not (1 <= sig.r < N):
        return False

    if not (1 <= sig.s < N):
        return False

    z = hash_message(message)
    s_inv = pow(sig.s, -1, N)

    u = G * ((z * s_inv) % N)
    v = pk * ((sig.r * s_inv) % N)

    return (u + v).x % N == sig.r


if __name__ == '__main__':
    pass
