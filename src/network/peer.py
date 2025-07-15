# Copyright (c) 2022 Neutronys

# The software is distributed under the MIT software license
# See the accompanying file LICENSE in the main directory of
# the project for more details.


"""

A pure python implementation of network Peers.

"""


import socket
import threading

from .protocol import MessageHeader


class Peer(threading.Thread):

    """
    Peer in a P2P network
    """

    def __init__(self, host='0.0.0.0', port=9999):

        super().__init__()

        # To stop peer
        self.stop_flag = False

        # Peer host and port
        self.host = host
        self.port = port

        # Inbound and outbound connections
        self.node_recv = {}
        self.node_from = {}

        # Create server socket and server stream
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.stream = self.server.makefile('rb', None)

        # Set server socket default options
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, self.port))
        self.server.listen(10)
        self.server.settimeout(10.0)

    def connect(self, host, port):

        """
        Connect peer to another one
        """

        pass

    def read(self):

        """
        Read server socket stream
        """

        return MessageHeader.decode(self.stream)

    def send(self, message):

        """
        Send bytes database to peers
        """

        pass

    def run(self):

        """
        Run peer thread
        """

        pass

    def close(self):

        """
        Close peer connections
        """

        self.server.close()
        self.stop_flag = True


if __name__ == '__main__':
    pass


# TODO: Implement peers discovery
# TODO: Implement missing methods
