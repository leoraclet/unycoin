# Copyright (c) 2022 Neutronys

# The software is distributed under the MIT software license
# See the accompanying file LICENSE in the main directory of
# the project for more details.


"""

This file implements a basic wallet to hold keys.

"""


from crypto.ecc import gen_key_pair


class Wallet:

    """
    Wallet to store key pairs
    """

    def __init__(self):

        self.vk2sk = {}
        self.sk2vk = {}

    def get_pubkey(self, sk=None):

        """
        Return public key
        """

        # Last generated public key
        if sk is None:
            return list(self.sk2vk.values())[-1]

        return self.sk2vk[sk]

    def new_address(self):

        """
        Generate a new wallet address
        """

        sk, vk = gen_key_pair()

        self.vk2sk[vk] = sk
        self.sk2vk[sk] = vk

    def to_json(self):

        """
        Encode wallet to json
        """

        return {
            'keys': self.vk2sk
        }


if __name__ == '__main__':
    pass


# TODO: Implement deterministic
