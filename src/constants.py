# Copyright (c) 2022 Neutronys

# The software is distributed under the MIT software license
# See the accompanying file LICENSE in the main directory of
# the project for more details.


"""

This file implements some global program constants.

"""

# Some mining constants
THREE_DAYS = 60 * 60 * 24 * 3
MAX_TARGET = 0xffff * 256 ** (0x1d - 3)


# Transaction constants
MINING_REWARD = 5000000000
SIGHASH_ALL = 1
TRANSACTION_FEE = 1000000


if __name__ == '__main__':
    pass
