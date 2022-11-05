# Copyright (c) 2022 Neutronys

# The software is distributed under the MIT software license
# See the accompanying file LICENSE in the main directory of
# the project for more details.


"""

A pure python implementation ob bitcoin's Blocks.

"""


from dataclasses import dataclass

from crypto.hasher import hash256
from crypto.merkle_tree import MerkleTree
from transaction import Tx
from utils import (
    bits2target,
    bytes2bits,
    bytes2int,
    int2bytes,
    int2varint,
    varint2int,
)


@dataclass
class Header:

    """
    Block header
    """

    version: int
    parent_hash: bytes
    sparse_root: bytes
    merkle_root: bytes
    bits: bytes
    timestamp: int
    nonce: int

    def encode(self):

        """
        Encode block header to bytes
        """

        s = bytes()

        # Version, 4 bytes, little endian
        s += int2bytes(self.version, 4)

        # Parent hash, 32 bytes
        s += self.parent_hash[::-1]

        # Sparse root, 32 bytes
        s += self.sparse_root[::-1]

        # Merkle root, 32 bytes
        s += self.merkle_root[::-1]

        # Bits, 4 bytes
        s += self.bits[::-1]

        # Timestamp, 4 bytes, little endian
        s += int2bytes(self.timestamp, 4)

        # Nonce, 4 bytes, little endian
        s += int2bytes(self.nonce, 4)

        return s

    @classmethod
    def decode(cls, s):

        """
        Decode bytes to block header
        """
        # Version, 4 bytes, little endian
        version = bytes2int(s.read(4))

        # Parent hash, 32 bytes
        parent_hash = s.read(32)[::-1]

        # Sparse root, 32 bytes
        sparse_root = s.read(32)[::-1]

        # Merkle root, 32 bytes
        merkle_root = s.read(32)[::-1]

        # Bits, 4 bytes
        bits = s.read(4)[::-1]

        # Timestamp, 4 bytes, little endian
        timestamp = bytes2int(s.read(4))

        # Nonce, 4 bytes, little endian
        nonce = bytes2int(s.read(4))

        return cls(
            version,
            parent_hash,
            sparse_root,
            merkle_root,
            bits,
            timestamp,
            nonce
        )

    def to_json(self):

        """
        Encode block header to json
        """

        return {
            'version': self.version,
            'parent_hash': self.parent_hash.hex(),
            'merkle_root': self.merkle_root.hex(),
            'bits': self.bits.hex(),
            'timestamp': self.timestamp,
            'nonce': self.nonce
        }


@dataclass
class Block:

    """
    Complete block
    """

    header: Header
    txns: [Tx]

    def get_size(self):

        """
        Size of serialized block in bytes
        """

        return len(self.encode())

    def get_hash(self):

        """
        Hash of serialized header
        """

        return hash256(self.header.encode())

    def target(self):

        """
        Convert bits field to a target
        """

        return bits2target(self.header.bits)

    def difficulty(self):

        """
        Calculate mining difficulty
        """

        lowest = 0xffff * 256 ** (0x1d - 3)
        target = self.target()

        return int(lowest / target)

    def check_pow(self):

        """
        Whether this block satisfies proof
        of work or not
        """

        block_hash = self.get_hash()
        proof = bytes2int(block_hash)

        return proof < self.target()

    def mine(self):

        """
        Mine block according to target
        """

        while self.header.nonce < 2 ** 32:

            if self.check_pow():
                break

            self.header.nonce += 1

    def encode(self):

        """
        Encode block to bytes
        """

        # Block header
        s = self.header.encode()

        # Number of transactions
        s += int2varint(len(self.txns))

        # Transactions
        for tx in self.txns:
            s += tx.encode()

        return s

    @classmethod
    def decode(cls, s):

        """
        Decode bytes to block
        """

        # Block header
        header = Header.decode(s)

        # Number of transactions
        txns = []
        txns_count = varint2int(s)

        # Transactions
        for _ in range(txns_count):
            txns.append(Tx.decode(s))

        return cls(
            header,
            txns
        )

    def to_json(self):

        """
        Encode block to json
        """

        return {
            'header': self.header.to_json(),
            'txns': [tx.to_json() for tx in self.txns]
        }


@dataclass
class MerkleBlock:

    """
    Block header and hashes
    """

    header: Header
    total: int
    hashes: [bytes]
    flags: bytes

    def is_valid(self):

        """
        Is it a valid merkle block ?
        """

        # Flag as bytes to bits flag
        flag_bits = bytes2bits(self.flags)

        # Populate merkle tree
        tree = MerkleTree(self.total)
        tree.build_tree(self.hashes, flag_bits)

        return tree.get_root() == self.header.merkle_root

    def encode(self):

        """
        Encode merkle Block to bytes
        """

        s = bytes()

        # Block header
        s += self.header.encode()

        # NUmber of transactions
        s += int2bytes(self.total, 4)

        # Number of hashes
        s += int2varint(len(self.hashes))

        # All hashes
        for merkle_hash in self.hashes:
            s += merkle_hash[::-1]

        # Flags length
        s += int2varint(len(self.flags))

        # Flags
        s += self.flags

        return s

    @classmethod
    def decode(cls, s):

        """
        Decode bytes to merkle block
        """

        # Block header
        header = Header.decode(s)

        # Number of transactions
        total = bytes2int(s.read(4))

        # Number of hashes
        num_hashes = varint2int(s)

        # All hashes
        hashes = []

        for _ in range(num_hashes):
            hashes.append(s.read(32)[::-1])

        # Flags length
        flags_length = varint2int(s)
        flags = s.read(flags_length)  # Flag bits

        return cls(
            header,
            total,
            hashes,
            flags
        )

    def to_json(self):

        """
        Encode merkle block to json
        """

        return {
            'header': self.header.to_json(),
            'total': self.total,
            'hashes': [tx_id.hex() for tx_id in self.hashes],
            'flags': self.flags.hex()
        }


if __name__ == '__main__':
    pass
