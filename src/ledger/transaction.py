# Copyright (c) 2022 Neutronys

# The software is distributed under the MIT software license
# See the accompanying file LICENSE in the main directory of
# the project for more details.


"""

This file implements a basic Transaction.

"""


from dataclasses import dataclass

from crypto.ecc import sign
from crypto.hasher import hash256
from vm.script import Script
from constants import (
    MINING_REWARD,
    SIGHASH_ALL,
)
from utils import (
    bytes2int,
    int2bytes,
    int2varint,
    varint2int,
)


@dataclass
class Outpoint:

    """
    Previous transaction output
    """

    tx: bytes = bytes(32)
    index: int = 0xffffffff

    def encode(self):

        """
        Encode previous transaction output to bytes
        """

        s = bytes()

        # Tx, 32 bytes
        s += self.tx[::-1]

        # Index, 4 bytes, little endian
        s += int2bytes(self.index, 4)

        return s

    @classmethod
    def decode(cls, s):

        """
        Decode bytes to previous transaction output
        """

        # Tx, 32 bytes
        tx = s.read(32)[::-1]

        # Index, 4 bytes, little endian
        index = bytes2int(s.read(4))

        return cls(
            tx,
            index
        )

    def to_json(self):

        """
        Encode previous output to json
        """

        return {
            'tx': self.tx.hex(),
            'index': self.index,
        }


@dataclass
class TxIn:

    """
    Transaction input
    """

    prev_out: Outpoint
    sig_script: Script
    sequence: int = 0xffffffff
    witness: [bytes] = None

    def encode(self):

        """
        Encode transaction input to bytes
        """

        s = bytes()

        # Previous output
        s += self.prev_out.encode()

        # Sig vm
        s += self.sig_script.encode()

        # Sequence, 4 bytes, little endian
        s += int2bytes(self.sequence, 4)

        return s

    @classmethod
    def decode(cls, s):

        """
        Decode bytes to transaction input
        """

        # Previous output
        prev_out = Outpoint.decode(s)

        # Sig vm
        sig_script = Script.decode(s)

        # Sequence, 4 byes, little endian
        sequence = bytes2int(s.read(4))

        return cls(
            prev_out,
            sig_script,
            sequence
        )

    def to_json(self):

        """
        Encode transaction input ot json
        """

        return {
            'prev_out': self.prev_out.to_json(),
            'sig_script': self.sig_script.to_json(),
            'sequence': self.sequence
        }


@dataclass
class TxOut:

    """
    Transaction output
    """

    value: int
    pubkey_script: Script

    def encode(self):

        """
        Encode transaction output to bytes
        """

        s = bytes()

        # Value, 8 bytes, little endian
        s += int2bytes(self.value, 8)

        # Pubkey vm
        s += self.pubkey_script.encode()

        return s

    @classmethod
    def decode(cls, s):

        """
        Decode bytes to transaction output
        """

        # Value, 8 bytes, little endian
        value = bytes2int(s.read(8))

        # Pubkey vm
        pubkey_script = Script.decode(s)

        return cls(
            value,
            pubkey_script
        )

    def to_json(self):

        """
        Encode transaction output to json
        """

        return {
            'value': self.value,
            'pubkey_script': self.pubkey_script.to_json()
        }


@dataclass
class Coinbase(TxIn):

    """
    Coinbase input
    """

    height: Script = None
    prev_out: Outpoint = Outpoint()

    def encode(self):

        """
        Encode coinbase input to bytes
        """

        s = bytes()

        # Previous output
        s += self.prev_out.encode()

        # Height vm
        s += self.height.encode()

        # Sig vm
        s += self.sig_script.encode()

        # Sequence, 4 bytes, little endian
        s += int2bytes(self.sequence, 4)

        return s

    @classmethod
    def decode(cls, s):

        """
        Decode bytes to coinbase input
        """

        # Previous output
        prev_out = Outpoint.decode(s)

        # Height vm
        height = Script.decode(s)

        # Sig vm
        sig_script = Script.decode(s)

        # Sequence, 4 bytes, little endian
        sequence = bytes2int(s.read(4))

        return cls(
            prev_out,
            height,
            sig_script,
            sequence
        )

    def to_json(self):

        """
        Encode coinbase input to json
        """

        return {
            'prev_out': self.prev_out.to_json(),
            'height': self.height.to_json(),
            'sig_script': self.sig_script.to_json(),
            'sequence': self.sequence
        }


@dataclass
class Tx:

    """
    Complete transaction
    """

    version: int
    tx_in: [TxIn]
    tx_out: [TxOut]
    locktime: int = 0

    def get_size(self):

        """
        Size of serialized transaction in bytes
        """

        return len(self.encode())

    def get_hash(self):

        """
        Hash of serialized transaction
        """

        return hash256(self.encode())[::-1]

    def compute_hashes(self):

        """
        Precompute hashes to calculate sig hash
        """

        pre_hashed = [bytes()] * 3

        # Pre-hashed transaction outputs
        for tx_out in self.tx_out:
            pre_hashed[2] += tx_out.encode()

        for tx_in in self.tx_in:

            # Pre-hashed transaction inputs sequence
            pre_hashed[1] += int2bytes(tx_in.sequence, 4)

            # Pre-hashed transaction inputs outpoint
            pre_hashed[0] += tx_in.prev_out.tx[::-1]
            pre_hashed[0] += int2bytes(tx_in.prev_out.index, 4)

        return [hash256(e) for e in pre_hashed]

    def sig_hash(self, index, pre_hashed, prevouts):

        """
        Compute sig hash used for signing
        """

        tx_in = self.tx_in[index]
        prevout = prevouts[index]

        s = bytes()

        # Version, 4 bytes, little endian
        s += int2bytes(self.version, 4)

        # Pre-hashed inputs outpoint
        s += pre_hashed[0]

        # Pre-hashed inputs sequence
        s += pre_hashed[1]

        # Previous transaction, 32 bytes
        s += tx_in.prev_out.tx[::-1]

        # Previous output index, 4 bytes, little endian
        s += int2bytes(tx_in.prev_out.index, 4)

        # Previous output pubkey vm
        s += prevout.pubkey_script.encode()

        # Previous output value, 8 bytes, little endian
        s += int2bytes(prevout.value, 8)

        # Input sequence, 4 bytes, little endian
        s += int2bytes(tx_in.sequence, 4)

        # Pre-hashed outputs
        s += pre_hashed[2]

        # Input locktime, 4 bytes, little endian
        s += int2bytes(self.locktime, 4)

        # SIGHASH_ALL, 4 bytes, little endian
        s += int2bytes(SIGHASH_ALL, 4)

        return s

    def sign(self, secret_key, prevouts):

        """
        Sign transaction inputs
        """

        # Don't sign a coinbase transaction
        if self.is_coinbase():
            return True

        # Pre-compute hashes
        pre_hashed = self.compute_hashes()

        for i, tx_in in enumerate(self.tx_in):

            # Compute hash that need to be signed
            z = self.sig_hash(i, pre_hashed, prevouts)
            sec = secret_key.to_pubkey().encode()

            # Sign input hash
            der = sign(z, secret_key).encode()
            sig = der + SIGHASH_ALL.to_bytes(1, 'big')

            # Create signature vm
            sig_script = Script([sig, sec])
            self.tx_in[i].sig_script = sig_script

        return self.verify(prevouts)

    def verify(self, prevouts):

        """
        Verify transaction inputs
        """

        # Coinbase transactions are valid
        if self.is_coinbase():
            return True

        # Pre-compute hashes
        pre_hashed = self.compute_hashes()

        for i, tx_in in enumerate(self.tx_in):

            # Compute hash that was signed
            z = self.sig_hash(i, pre_hashed, prevouts)

            # Combine signature vm and public key vm
            script = tx_in.sig_script + prevouts[i].pubkey_script

            # Execute vm
            if not script.evaluate(z, tx_in.witness):
                return False

        return True

    def is_coinbase(self):

        """
        Is it a coinbase transaction ?
        """

        # Check number of inputs
        if len(self.tx_in) != 1:
            return False

        # Sum of all outputs values
        value = sum([e.value for e in self.tx_out])

        # Check coinbase reward
        if value != MINING_REWARD:
            return False

        # Grab first input
        first_input = self.tx_in[0]

        # Check first input hash
        if first_input.prev_out.tx != bytes(32):
            return False

        # Check first input prev index
        if first_input.prev_out.index != 0xffffffff:
            return False

        return True

    def coinbase_height(self):

        """
        Block height in the blockchain
        """

        # If it's a coinbase transaction
        if not self.is_coinbase():
            return None

        # Grab vm first command of first input
        height_script = self.tx_in[0].height

        return bytes2int(height_script.cmds[0])

    def encode(self, is_segwit=False):

        """
        Encode transaction to bytes
        """

        # Version
        s = int2bytes(self.version, 4)

        if is_segwit:
            s += b'\x00\x01'

        # Number of transaction inputs
        s += int2varint(len(self.tx_in))

        # Transaction inputs
        for tx_input in self.tx_in:
            s += tx_input.encode()

        # Number of transaction outputs
        s += int2varint(len(self.tx_out))

        # Transaction outputs
        for tx_output in self.tx_out:
            s += tx_output.encode()

        # Witness items
        if is_segwit:

            for tx_in in self.tx_in:

                # Encode segwit length
                s += int2varint(len(tx_in.witness))

                for item in tx_in.witness:

                    if isinstance(item, int):
                        s += int2bytes(item, 1)
                    else:
                        s += int2varint(len(item)) + item

        # Lock time
        s += int2bytes(self.locktime, 4)

        return s

    @classmethod
    def decode(cls, s, is_coinbase=False):

        """
        Decode bytes to transaction
        """

        is_segwit = False

        # Version
        version = bytes2int(s.read(4))

        # Check for segwit transaction marker
        if s.read(2) == b'\x00\x01':
            is_segwit = True
        else:
            s.seek(-2, 1)

        # Number of transaction inputs
        tx_ins = []
        tx_in_count = varint2int(s)

        # Transaction inputs
        for _ in range(tx_in_count):

            # If it's the first transaction of a block
            # Decode first input as a coinbase input

            if is_coinbase:
                tx_ins.append(Coinbase.decode(s))
            else:
                tx_ins.append(TxIn.decode(s))

        # Number of transaction outputs
        tx_outs = []
        tx_out_count = varint2int(s)

        # Transaction outputs
        for _ in range(tx_out_count):
            tx_outs.append(TxOut.decode(s))

        # Witness items
        if is_segwit:

            for tx_in in tx_ins:

                # Number of items
                nb_items = varint2int(s)
                items = []

                for _ in range(nb_items):

                    # Segwit length
                    item_len = varint2int(s)

                    if item_len == 0:
                        items.append(0)
                    else:
                        items.append(s.read(item_len))

                tx_in.witness = items

        # Lock time
        locktime = bytes2int(s.read(4))

        return cls(
            version,
            tx_ins,
            tx_outs,
            locktime
        )

    def to_json(self):

        """
        Encode transaction to json
        """

        return {
            'version': self.version,
            'tx_in': [tx_in.to_json() for tx_in in self.tx_in],
            'tx_out': [tx_out.to_json() for tx_out in self.tx_out],
            'locktime': self.locktime
        }


if __name__ == '__main__':
    pass
