# Copyright (c) 2022 Neutronys

# The software is distributed under the MIT software license
# See the accompanying file LICENSE in the main directory of
# the project for more details.


"""

A pure python implementation of a Sparse Merkle Tree.

"""


from .hasher import hash256


LEAF = b'\x00'
NODE = b'\x01'

PLACEHOLDER = bytes(32)
DEFAULT = bytes()
SIZE = 256


def decode_node(node):

    """
    Decode left and right children of node
    """

    return node[1:33], node[33:]


def encode_node(left, right):

    """
    Encode node's left and right children
    """

    node = NODE + left + right
    return hash256(node), node


def encode_leaf(left, right):

    """
    Encode leaf's key and value
    """

    leaf = LEAF + left + right
    return hash256(leaf), leaf


def get_bit(index, data):

    """
    Get value of a bit in bytes string
    """

    if data[index >> 3] & 1 << (7 - index % 8) > 0:
        return 1
    else:
        return 0


def common_prefix_bits(a, b):

    """
    Number of common prefix bits
    """

    for i in range(len(a) * 8):
        if get_bit(i, a) != get_bit(i, b):
            return i

    return len(a) * 8


class Store:

    """
    Database to store nodes
    """

    def __init__(self):

        self.nodes = {}
        self.leafs = {}

    def get(self, key, is_leaf=False):

        """
        Get value from the database
        """

        if is_leaf:
            return self.leafs.get(key, None)
        else:
            return self.nodes.get(key, None)

    def put(self, key, value, is_leaf=False):

        """
        Append value to the database
        """

        if is_leaf:
            self.leafs[key] = value
        else:
            self.nodes[key] = value

    def rmv(self, key, is_leaf=False):

        """
        Delete value from database
        """

        if is_leaf:
            if key not in self.leafs:
                return False

            del self.leafs[key]

        else:
            if key not in self.nodes:
                return False

            del self.nodes[key]

        return True


class Proof:

    """
    Sparse merkle proof
    """

    def __init__(self, side_nodes, non_member_data):

        self.side_nodes = side_nodes
        self.non_member_data = non_member_data

    def verify(self, key, value, root):

        """
        Verify sparse merkle proof
        """

        path, node = hash256(key), [PLACEHOLDER]

        # Non-membership merkle proof
        if value == DEFAULT:
            if self.non_member_data:

                node = decode_node(self.non_member_data)

                if node[0] == path:
                    return False

                node = encode_leaf(node[0], node[1])

        # Membership merkle proof
        else:
            value_hash = hash256(value)
            node = encode_leaf(path, value_hash)

        for i, sn in enumerate(self.side_nodes):

            # Check side bit: 1 = RIGHT, 0 = LEFT
            if get_bit(len(self.side_nodes) - 1 - i, path):
                node = encode_node(sn, node[0])
            else:
                node = encode_node(node[0], sn)

        return node[0] == root


class CompactProof:

    """
    Compact sparse merkle proof
    """

    def __init__(self):

        self.hashes = []
        self.flag_bits = []


class SparseMerkleTree:

    """
    Fully filed merkle tree
    """

    def __init__(self):

        self.root = PLACEHOLDER
        self.tree = Store()

    def get_root(self):

        """
        Get sparse merkle root
        """

        return self.root

    def get(self, key):

        """
        Get value for given key
        """

        return self.tree.get(hash256(key))

    def has(self, key):

        """
        Is key in the tree ?
        """

        return self.get(key) is not None

    def update(self, key, value):

        """
        Update value in the tree
        """

        path = hash256(key)

        sn = self._get_side_nodes(path)
        self.root = self._update(path, value, sn)

    def delete(self, key):

        """
        Delete value in the tree
        """

        path = hash256(key)

        sn = self._get_side_nodes(path)
        root = self._delete(path, sn)

        if root is None:
            raise Exception('Failed to delete')

        self.root = root

    def prove(self, key):

        """
        Merkle proof og given key
        """

        path = hash256(key)
        sns = self._get_side_nodes(path)

        # Non empty side nodes
        non_empty_sn = []

        for side_node in sns[0]:
            if side_node is not None:
                non_empty_sn.append(side_node)

        # Non-membership database
        non_member_data = None

        if sns[-1] != PLACEHOLDER and sns[-1] is not None:

            actual_path, _ = decode_node(sns[2])
            if actual_path != path:
                non_member_data = sns[2]

        return Proof(
            non_empty_sn,
            non_member_data
        )

    def _store(self, node, is_leaf=False):

        """
        Store node in tree's database
        """

        self.tree.put(node[0], node[1], is_leaf)
        return node[::-1]

    def _get_side_nodes(self, path):

        """
        Walk the tree down from the root gathering
        neighbor nodes on the way
        """

        side_nodes = []
        path_nodes = [self.root]

        if self.root == PLACEHOLDER:
            return [side_nodes, path_nodes, None]

        node_data = self.tree.get(self.root)

        if node_data is None:
            return [None, None, None]

        if node_data[0] == 0:
            return [side_nodes, path_nodes, node_data]

        for i in range(SIZE):

            # Node's left and right children
            l, r = decode_node(node_data)

            # Inverse if bit i of path is 0
            if get_bit(i, path) == 0:
                l, r = r, l

            side_nodes.append(l)
            path_nodes.append(r)

            if r == PLACEHOLDER:
                node_data = None
                break

            node_data = self.tree.get(r)

            if node_data is None:
                return [None, None, None]

            if node_data[0] == 0:
                break

        return [
            side_nodes[::-1],
            path_nodes[::-1],
            node_data
        ]

    def _update(self, path, value, sns):

        """
        Update value with given side nodes
        """

        value_hash = hash256(value)
        self.tree.put(path, value, False)

        # Create leaf and store as node
        node = encode_leaf(path, value_hash)
        node = self._store(node, False)

        old_hash = None
        cmn_bits = SIZE  # Number of common prefix bits

        if sns[1][0] != PLACEHOLDER:
            actual_path, old_hash = decode_node(sns[-1])
            cmn_bits = common_prefix_bits(path, actual_path)

        if cmn_bits != 256:

            if get_bit(cmn_bits, path):
                node = encode_node(sns[1][0], node[0])
            else:
                node = encode_node(node[0], sns[1][0])

            node = self._store(node, False)

        elif old_hash is not None:
            if old_hash == value_hash:
                return self.root

            self.tree.rmv(sns[1][0], False)
            self.tree.rmv(path, True)

        for sn in sns[1][1:]:
            self.tree.rmv(sn)

        offset = SIZE - len(sns[0])

        for i in range(SIZE):

            if i - offset < 0:
                if cmn_bits == 256 or cmn_bits <= SIZE - 1 - i:
                    continue

                side_node = PLACEHOLDER
            else:
                side_node = sns[0][i - offset]

            if get_bit(SIZE - 1 - i, path):
                node = encode_node(side_node, node[0])
            else:
                node = encode_node(node[0], side_node)

            node = self._store(node, False)

        return node[1]

    def _delete(self, path, sns):

        """
        Delete value with given side nodes
        """

        if sns[1][0] == PLACEHOLDER:
            return None

        if decode_node(sns[-1])[0] != path:
            return None

        for node in sns[1]:
            if not self.tree.rmv(node):
                return None

        node_hash = None
        node_data = None
        reached_placeholder = False

        for i, sn in enumerate(sns[0]):

            if sn is None:
                continue

            if node_data is None:

                sn_value = self.tree.get(sn)

                if sn_value is None:
                    return None

                if sn_value[0] == 0:

                    node_hash = sn
                    node_data = sn
                    continue

                else:
                    node_data = PLACEHOLDER
                    reached_placeholder = True

            if not reached_placeholder:
                if sn == PLACEHOLDER:
                    continue

                reached_placeholder = True

            if get_bit(len(sns[0]) - 1 - i, path):
                node = encode_node(sn, node_data)
            else:
                node = encode_node(node_data, sn)

            node = self._store(node, False)
            node_data, node_hash = list(node)

        if node_hash is None:
            node_hash = PLACEHOLDER

        return node_hash


if __name__ == '__main__':
    pass


# TODO: Need more comments
