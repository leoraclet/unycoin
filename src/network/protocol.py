# Copyright (c) 2022 Neutronys

# The software is distributed under the MIT software license
# See the accompanying file LICENSE in the main directory of
# the project for more details.


"""

This file implements basics network protocols.

"""


from dataclasses import dataclass
from time import time

from crypto.bloom_filter import BloomFilter
from crypto.hasher import hash256
from ledger.block import Header, Block, MerkleBlock
from ledger.transaction import Tx
from utils import (
    bytes2int,
    int2bytes,
    int2varint,
    varint2int,
)


# IV database types
MSG_TX = 1
MSG_BLOCK = 2
MSG_CMPCT_BLOCK = 4
MSG_FILTERED_BLOCK = 3

# Network magic bytes
MAGICS = {
    'main': b'\xf9\xbe\xb4\xd9',
    'test': b'\x0b\x11\x09\x07',
}


@dataclass
class MessageHeader:

    """
    Message Header
    """

    command: bytes = b''
    payload: bytes = b''
    net: str = 'main'

    def encode(self):

        """
        Encode message header to bytes
        """

        s = bytes()

        # Add the network magic
        s += MAGICS[self.net]

        # Command is 12 bytes long. Fill rest with zeros
        s += self.command + b'\0' * (12 - len(self.command))

        # Add payload length, 4 bytes
        s += int2bytes(len(self.payload), 4)

        # Add checksum, first 4 bytes of HASH-256 of payload
        s += hash256(self.payload)[:4]

        # Add payload
        s += self.payload

        return s

    @classmethod
    def decode(cls, s, net='main'):

        """
        Decode bytes to message header
        """

        # Read network magic bytes
        magic = s.read(4)

        # Verify magic
        if magic != MAGICS[net]:
            raise Exception('Invalid header')

        # Read command, get rid of filled zeros
        command = s.read(12).strip(b'\0')

        # Read payload length
        payload_l = bytes2int(s.read(4))

        # Read checksum
        checksum = s.read(4)

        # Read payload
        payload = s.read(payload_l)

        # Verify checksum
        if checksum != hash256(payload)[:4]:
            raise Exception('Checksum match error')

        return cls(command, payload, net)


@dataclass
class NetworkAddress:

    """
    Network address structure
    """

    services: int = 0
    ip: bytes = b'\x00\x00\x00\x00'
    port: int = 8333

    def encode(self):

        """
        Encode network address to bytes
        """

        s = bytes()

        # Add address services, 8 bytes
        s += int2bytes(self.services, 8)

        # Add IPV-4 address, pre-filled with 10 0x00 and 2 0xff
        s += b'\0' * 10 + b'\xff' * 2 + self.ip

        # Add address port number
        s += self.port.to_bytes(2, 'big')

        return s

    @classmethod
    def decode(cls, s):

        """
        Decode bytes to network address
        """

        # Read address services, 8 bytes
        services = bytes2int(s.read(8))

        # Read IPV-4 address, last 4 bytes
        ip = s.read(16)[-4:]

        # Read address port number
        port = int.from_bytes(s.read(2), 'big')

        return cls(services, ip, port)


@dataclass
class InventoryVector:

    """
    Inventory vector
    """

    type: int = 0
    hash: bytes = bytes(32)

    def encode(self):

        """
        Encode inventory vector to bytes
        """

        s = bytes()

        # Add inventory vector type
        s += int2bytes(self.type, 4)

        # Add hash identifier
        s += self.hash[::-1]

        return s

    @classmethod
    def decode(cls, s):

        """
        Decode bytes to inventory vector
        """

        # Read type of inventory vector
        inv_type = bytes2int(s.read(4))

        # Read hash
        inv_hash = s.read(32)[::-1]

        return cls(inv_type, inv_hash)


@dataclass
class VersionMessage:

    """
    Version message
    """

    version: int = 0
    services: int = 0
    timestamp: int = 0
    addr_recv: NetworkAddress = NetworkAddress()
    addr_from: NetworkAddress = NetworkAddress()
    nonce: bytes = b'\0' * 8
    user_agent: bytes = b''
    latest_block: int = 0
    relay: bool = False
    command: bytes = b'version'

    def encode(self):

        """
        Encode version message to bytes
        """

        s = bytes()

        # Add version, 4 bytes
        s += int2bytes(self.version, 4)

        # Add services, 8 bytes
        s += int2bytes(self.services, 8)

        # Add timestamp, 8 bytes
        s += int2bytes(self.timestamp, 8)

        # Add receiver address
        s += self.addr_recv.encode()

        # Add sender address
        s += self.addr_from.encode()

        # Add nonce, 8 bytes
        if len(self.nonce) != 8:
            raise Exception('Nonce must be 8 bytes')

        # Nonce
        s += self.nonce

        # Add user-agent, variable string
        s += int2varint(len(self.user_agent))
        s += self.user_agent

        # Add number of the latest block, 4 bytes
        s += int2bytes(self.latest_block, 4)

        # Add relay, 1 bytes, 1 if true, 0 otherwise
        s += b'\x01' if self.relay else b'\x00'

        return s

    @classmethod
    def decode(cls, s):

        """
        Decode bytes to version message
        """

        # Read version
        version = bytes2int(s.read(4))

        # Read services
        services = bytes2int(s.read(8))

        # Read timestamp
        timestamp = bytes2int(s.read(8))

        # Read receiver address
        addr_recv = NetworkAddress.decode(s)

        # Read sender address
        addr_from = NetworkAddress.decode(s)

        # Read nonce
        nonce = s.read(8)

        # Read user-agent, variable string
        user_agent = s.read(varint2int(s))

        # Read number of the latest block
        latest_block = bytes2int(s.read(4))

        # Read relay
        relay = bytes2int(s.read(1))
        relay = True if relay == 1 else False

        return cls(
            version,
            services,
            timestamp,
            addr_recv,
            addr_from,
            nonce,
            user_agent,
            latest_block,
            relay
        )


@dataclass
class AddrMessage:

    """
    Address message
    """

    addr_list: [NetworkAddress]
    command: bytes = b'addr'

    def __post_init__(self):

        if len(self.addr_list) > 1000:
            raise Exception('Maximum addresses is 1000')

    def encode(self):

        """
        Encode address message to bytes
        """

        s = bytes()

        # Add number of addresses, variable integer
        s += int2varint(len(self.addr_list))

        # Add all addresses, preceded by a timestamp
        for addr in self.addr_list:

            s += int2bytes(int(time()), 4)
            s += addr.encode()

        return s

    @classmethod
    def decode(cls, s):

        """
        Decode bytes to address message
        """

        # Read number of address
        n_addr = varint2int(s)

        addr_list = []

        # Read all addresses
        for _ in range(n_addr):

            _ = bytes2int(s.read(4))
            addr_list.append(NetworkAddress.decode(s))

        return cls(addr_list)


@dataclass
class VerAckMessage:

    """
    Verack message
    """

    payload: bytes = b''
    command: bytes = b'verack'

    def __post_init__(self):

        if len(self.payload) != 0:
            raise Exception('Payload must be empty')

    def encode(self):

        """
        Encode verack message to bytes
        """

        return self.payload

    @classmethod
    def decode(cls, s):

        """
        Decode bytes to verack message
        """

        return cls(s.read())


@dataclass
class PingMessage:

    """
    Ping message
    """

    nonce: bytes = b'\0' * 8
    command: bytes = b'ping'

    def __post_init__(self):

        if len(self.nonce) != 8:
            raise Exception('Nonce must be 8 bytes')

    def encode(self):

        """
        Encode ping message to bytes
        """

        return self.nonce

    @classmethod
    def decode(cls, s):

        """
        Decode bytes to ping message
        """

        return cls(s.read(8))


@dataclass
class PongMessage:

    """
    Pong message
    """

    nonce: bytes = b'\0' * 8
    command: bytes = b'pong'

    def __post_init__(self):

        if len(self.nonce) != 8:
            raise Exception('Nonce must be 8 bytes')

    def encode(self):

        """
        Encode pong message to bytes
        """

        return self.nonce

    @classmethod
    def decode(cls, s):

        """
        Decode bytes to pong message
        """

        return cls(s.read(8))


@dataclass
class GetHeadersMessage:

    """
    Get headers message
    """

    version: int = 70015
    hash_count: int = 1
    hash_start: bytes = bytes(32)
    hash_end: bytes = bytes(32)
    command: bytes = b'getheaders'

    def encode(self):

        """
        Encode get headers message to bytes
        """

        s = bytes()

        # Add version, 4 bytes
        s += int2bytes(self.version, 4)

        # Add number of hashes
        s += int2varint(self.hash_count)

        # Add hash of start block
        s += self.hash_start[::-1]

        # Add hash of end block
        s += self.hash_end[::-1]

        return s

    @classmethod
    def decode(cls, s):

        """
        Decode bytes to get headers message
        """

        # Read version, 4 bytes
        version = bytes2int(s.read(4))

        # Read number of hashes
        hash_count = varint2int(s)

        # Read hash of start block
        hash_start = s.read(32)[::-1]

        # Read hash of start block
        hash_end = s.read(32)[::-1]

        return cls(
            version,
            hash_count,
            hash_start,
            hash_end,
        )


@dataclass
class GetBlocksMessage(GetHeadersMessage):

    """
    Get blocks message
    """

    command: bytes = b'getblocks'


@dataclass
class HeadersMessage:

    """
    Headers message
    """

    headers: [Header]
    command: bytes = b'headers'

    def encode(self):

        """
        Encode headers message to bytes
        """

        s = bytes()

        # Add numer of headers, variable integer
        s += int2varint(len(self.headers))

        # Add all headers
        for header in self.headers:
            s += header.encode()

        return s

    @classmethod
    def decode(cls, s):

        """
        Decode bytes to headers message
        """

        # Read number of block headers
        nb_h = varint2int(s)

        headers = []

        # Read all block headers
        for _ in range(nb_h):
            headers.append(Header.decode(s))

        return cls(headers)


@dataclass
class BlockMessage:

    """
    Block message
    """

    block: Block
    command: bytes = b'block'

    def __post_init__(self):

        if len(self.block.header.encode()) != 80:
            raise Exception('Block must be 80 bytes')

    def encode(self):

        """
        Encode block message to bytes
        """

        return self.block.encode()

    @classmethod
    def decode(cls, s):

        """
        Decode bytes to block message
        """

        return cls(Block.decode(s))


@dataclass
class TxMessage:

    """
    Transaction message
    """

    tx: Tx
    command: bytes = b'tx'

    def encode(self):

        """
        Encode transaction message to bytes
        """

        return self.tx.encode()

    @classmethod
    def decode(cls, s):

        """
        Decode bytes to transaction message
        """

        return cls(Tx.decode(s))


@dataclass
class InvMessage:

    """
    Inventory vector message
    """

    inventory: [InventoryVector]
    command: bytes = b'inv'

    def __post_init__(self):

        if len(self.inventory) > 50000:
            raise Exception('Maximum of 50.000 entries')

    def encode(self):

        """
        Encode inventory vector message to bytes
        """

        s = bytes()

        # Add the number of entries in the inventory
        s += int2varint(len(self.inventory))

        # Add all inventory vectors
        for inv in self.inventory:
            s += inv.encode()

        return s

    @classmethod
    def decode(cls, s):

        """
        Decode bytes to inventory vector message
        """

        # Read number of entries
        nb_inv = varint2int(s)

        inventory = []

        # Read all entries
        for _ in range(nb_inv):
            inventory.append(InventoryVector.decode(s))

        return cls(inventory)


@dataclass
class GetDataMessage(InvMessage):

    """
    Get database message
    """

    command: bytes = b'getdata'


@dataclass
class NotFoundMessage(InvMessage):

    """
    Not found message
    """

    command: bytes = b'notfound'


@dataclass
class GetAddrMessage:

    """
    Get address message
    """

    command: bytes = b'getaddr'


@dataclass
class MemPoolMessage:

    """
    Memory pool message
    """

    command: bytes = b'mempool'


@dataclass
class FilterLoadMessage:

    """
    Filter load message
    """

    filter: BloomFilter
    command: bytes = b'filterload'


@dataclass
class FilterAddMessage:

    """
    Filter add message
    """

    element: bytes = bytes(32)
    command: bytes = b'filteradd'


@dataclass
class FilterClearMessage:

    """
    Filter clear message
    """

    command: bytes = b'filterclear'


@dataclass
class MerkleBlockMessage:

    """
    Merkle block message
    """

    merkle_block: MerkleBlock
    command: bytes = b'merkleblock'


@dataclass
class AlertMessage:

    """
    Alert message
    """

    command: bytes = b'alert'


@dataclass
class RejectMessage:

    """
    Reject message
    """

    command: bytes = b'reject'


@dataclass
class CompactBlockMessage:

    """
    Compact block message
    """

    command: bytes = b'cmpctblock'


@dataclass
class GetBlockTxnMessage:

    """
    Get block transactions message
    """

    command: bytes = b'getblocktxn'


@dataclass
class BlockTxnMessage:

    """
    Block transactions message
    """

    command: bytes = b'blocktxn'


@dataclass
class FeeFilterMessage:

    """
    Fee filter message
    """

    command: bytes = b'feefilter'


@dataclass
class GenericMessage:

    """
    Generic message
    """

    command: bytes
    payload: bytes

    def encode(self):

        """
        Encode generic message to bytes
        """

        return self.payload


# Message by their classes
MESSAGE_CLASSES = {
    b'version': VersionMessage,
    b'addr': AddrMessage,
    b'verack': VerAckMessage,
    b'ping': PingMessage,
    b'pong': PongMessage,
    b'getheaders': GetHeadersMessage,
    b'getblocks': GetBlocksMessage,
    b'headers': HeadersMessage,
    b'block': BlockMessage,
    b'tx': TxMessage,
    b'getdata': GetDataMessage,
    b'notfound': NotFoundMessage,
    b'inv': InvMessage,
    b'getblocktxn': GetBlockTxnMessage,
    b'blocktxn': BlockTxnMessage,
    b'reject': RejectMessage,
    b'alert': AlertMessage,
    b'cmpctblock': CompactBlockMessage,
    b'merkleblock': MerkleBlockMessage,
    b'filterclear': FilterClearMessage,
    b'filteradd': FilterAddMessage,
    b'filterload': FilterLoadMessage,
    b'feefilter': FeeFilterMessage,
    b'getaddr': GetAddrMessage,
    b'mempool': MemPoolMessage,
}


if __name__ == '__main__':
    pass


# TODO: Implement missing messages
