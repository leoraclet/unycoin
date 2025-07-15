# Copyright (c) 2022 Neutronys

# The software is distributed under the MIT software license
# See the accompanying file LICENSE in the main directory of
# the project for more details.


"""

A pure python implementation of a Merkle Tree.

"""


from math import ceil, log

from .hasher import hash256


class MerkleTree:

    """
    Binary hash tree structure
    """

    def __init__(self, nb_hashes):

        # Maximum depth of the tree
        self.depth = ceil(log(nb_hashes, 2))
        self.nodes = []

        # Tree levels size
        for d in range(self.depth + 1):
            nb_items = ceil(nb_hashes / 2 ** (self.depth - d))
            self.nodes.append([None] * nb_items)

    def get_root(self):

        """
        Return merkle root
        """

        return self.nodes[0][0]

    def build_tree(self, hashes, flag_bits=None):

        """
        Build merkle tree with given hashes
        according to flag bits
        """

        # By default, populate the entire tree
        if flag_bits is None:
            flag_length = sum([len(e) for e in self.nodes])
            flag_bits = [1] * flag_length

        # Start at root node
        depth = 0
        index = 0

        while self.get_root() is None:

            # If we are at the leaves level
            if depth == self.depth:

                flag_bits.pop(0)
                self.nodes[depth][index] = hashes.pop(0)
                # Go up a level
                depth, index = depth - 1, index // 2

            else:

                # Get left node hash
                left = self.nodes[depth + 1][index * 2]

                if left is None:

                    if flag_bits.pop(0) == 0:

                        self.nodes[depth][index] = hashes.pop(0)
                        # Go up a level
                        depth, index = depth - 1, index // 2

                    else:
                        # Go to the left node
                        depth, index = depth + 1, index * 2

                elif len(self.nodes[depth + 1]) > index * 2 + 1:

                    # Get right node hash
                    right = self.nodes[depth + 1][index * 2 + 1]

                    # Go to the right node
                    if right is None:
                        depth, index = depth + 1, index * 2 + 1

                    else:
                        # Combine the left and right hashes
                        self.nodes[depth][index] = hash256(left + right)
                        depth, index = depth - 1, index // 2

                else:
                    # Combine the left hash twice
                    self.nodes[depth][index] = hash256(left + left)
                    depth, index = depth - 1, index // 2

        # Fail if not all hashes were used
        if len(hashes) != 0:
            raise Exception('Hashes not all used')

        # Fail if not all flag bits were used
        for flag_bit in flag_bits:
            if flag_bit != 0:
                raise Exception('Flag bits not all used')

    def get_ancestors(self, tx_ids):

        """
        Get matched ancestor nodes of tx ids
        """

        ancestors = []

        for tx_id in tx_ids:

            if tx_id not in self.nodes[-1]:
                raise Exception('No matching tx id')

            # Start at leaf level
            depth = self.depth
            index = self.nodes[-1].index(tx_id)

            while depth != 0:

                # Get node at current position
                node = self.nodes[depth][index]

                # If not already added
                if node not in ancestors:
                    ancestors.append(node)

                # Go up by one level
                depth, index = depth - 1, index // 2

        return [self.get_root()] + ancestors

    def get_hash(self, depth, index):

        """
        Get node hash value in depth first order
        """

        # If node is a tx id
        if depth == self.depth:
            return self.nodes[depth][index]

        else:
            # Get hash for node's left child
            left = self.get_hash(depth + 1, index * 2)

            # Get hash for right node's child if exist
            if index * 2 + 1 < len(self.nodes[depth + 1]):

                right = self.get_hash(depth + 1, index * 2 + 1)
                return hash256(left + right)

        return hash256(left + left)

    def traverse(self, depth, index, hashes, bits, ancestors):

        """
        Traverse merkle tree in depth first order
        """

        # Append 1 if current node in matched
        # ancestors, 0 otherwise

        if self.nodes[depth][index] in ancestors:
            bits.append(1)
        else:
            bits.append(0)

        # If tx id or match ancestor node
        if depth == self.depth or not bits[-1]:
            hashes.append(self.get_hash(depth, index))

        else:
            # Process left child of current node
            self.traverse(depth + 1, index * 2, hashes, bits, ancestors)

            # Process right child if exist
            if index * 2 + 1 < len(self.nodes[depth + 1]):
                self.traverse(depth + 1, index * 2 + 1, hashes, bits, ancestors)

    def get_proof(self, tx_ids):

        """
        Create hashes and bits for merkle block
        """

        hashes, flag_bits = [], []
        ancestors = self.get_ancestors(tx_ids)
        self.traverse(0, 0, hashes, flag_bits, ancestors)

        return hashes, flag_bits


if __name__ == '__main__':
    pass
