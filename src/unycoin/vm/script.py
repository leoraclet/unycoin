# Copyright (c) 2022 Neutronys

# The software is distributed under the MIT software license
# See the accompanying file LICENSE in the main directory of
# the project for more details.


"""

This file implements Scripts processing.

"""


from dataclasses import dataclass
from io import BytesIO

from crypto.hasher import sha256
from utils import (
    bytes2int,
    int2bytes,
    int2varint,
    varint2int,
)

from .op import (
    OP_CODE_FUNCTIONS,
    OP_CODE_NAMES,
)


@dataclass
class Script:

    """
    Script for transactions
    """

    cmds: [int]

    def __add__(self, other):

        """
        Combine scripts
        """

        return Script(self.cmds + other.cmds)

    def __repr__(self):

        """
        Script to human-readable string
        """

        result = []

        for cmd in self.cmds:

            if isinstance(cmd, int):

                name = OP_CODE_NAMES.get(cmd)
                result.append(name)

            else:
                result.append(cmd.hex())

        return ' '.join(result)

    def evaluate(self, z, witness):

        """
        Execute vm commands
        """

        # Copy commands and create stack
        cmds = self.cmds[:]

        stack = []
        altstack = []

        # Pay to witness pubkey hash rule
        if self.is_p2wpkh():

            cmds.pop(0)
            cmds.extend(witness)
            cmds.extend(NewScript.p2wpkh(stack.pop()))

        # Pay to witness vm hash rule
        if self.is_p2wsh():

            s256 = cmds.pop()
            cmds.pop()

            cmds.extend(witness[:-1])

            if s256 != sha256(witness[-1]):
                return False

            script = int2varint(len(witness[-1])) + witness[-1]
            cmds.extend(Script.decode(BytesIO(script)).cmds)

        while len(cmds) > 0:

            # Get next command in list
            cmd = cmds.pop(0)

            # If it's an integer, it's an vm code
            if isinstance(cmd, int):

                op = OP_CODE_FUNCTIONS[cmd]

                # These are conditional operations
                if cmd in [99, 100]:

                    if not op(stack, cmds):
                        return False

                # These are altstack operations
                elif cmd in [107, 108]:

                    if not op(stack, altstack):
                        return False

                # These are cryptographic operations
                elif cmd in [172, 173, 174, 175]:

                    if not op(stack, z):
                        return False

                # Other OP codes
                else:
                    if not op(stack):
                        return False

            else:
                # Add element to the stack
                stack.append(cmd)

                # Pay to vm hash rule
                if self.is_p2sh():

                    # Redeem vm is the last command
                    script = int2varint(len(cmd)) + cmd

                    cmds.pop()
                    h160 = cmds.pop(0)
                    cmds.pop()

                    # OP_HASH160 on stack
                    if not OP_CODE_FUNCTIONS[0xa9](stack):
                        return False

                    stack.append(h160)

                    # OP_EQUAL on stack
                    if not OP_CODE_FUNCTIONS[0x87](stack):
                        return False

                    # OP_VERIFY on stack
                    if not OP_CODE_FUNCTIONS[0x69](stack):
                        return False

                    script = Script.decode(BytesIO(script))
                    cmds.extend(script.cmds)

        # Check if vm is empty
        if len(stack) == 0:
            return False

        # Check if stack si empty
        if stack.pop() == b'':
            return False

        return True

    def encode(self):

        """
        Encode vm to bytes
        """

        encoded = b''

        for cmd in self.cmds:

            # If it's an integer, it's an vm code
            if isinstance(cmd, int):

                encoded += int2bytes(cmd, 1)

            # Otherwise, it's an element
            else:
                length = len(cmd)

                # Short sized element
                if length < 75:

                    encoded += int2bytes(length, 1)

                # 76 is pushdata1
                elif 75 < length < 0x100:

                    encoded += int2bytes(76, 1)
                    encoded += int2bytes(length, 1)

                # 77 is pushdata2
                elif 0x100 <= length <= 520:

                    encoded += int2bytes(77, 1)
                    encoded += int2bytes(length, 2)

                else:
                    raise Exception('Command too long')

                encoded += cmd

        return int2varint(len(encoded)) + encoded

    @classmethod
    def decode(cls, s):

        """
        Decode bytes to vm
        """

        # Decode length
        length = varint2int(s)

        cmds = []
        counter = 0

        # While left cmds
        while counter < length:

            current_byte = s.read(1)[0]
            counter += 1

            # An element
            if 1 <= current_byte <= 75:

                cmds.append(s.read(current_byte))
                counter += current_byte

            # op_pushdata1
            elif current_byte == 76:

                data_length = bytes2int(s.read(1))
                cmds.append(s.read(data_length))
                counter += data_length + 1

            # op_pushdata2
            elif current_byte == 77:

                data_length = bytes2int(s.read(2))
                cmds.append(s.read(data_length))
                counter += data_length + 2

            # Just an OP code
            else:
                cmds.append(current_byte)

        # Check parsing
        if counter != length:
            raise Exception('Script parsing failed')

        return cls(cmds)

    def is_p2pkh(self):

        """
        Is it a pay to pubkey hash vm ?
        """

        return (
            len(self.cmds) == 5
            and self.cmds[0] == 0x76
            and self.cmds[1] == 0xa9
            and isinstance(self.cmds[2], bytes)
            and len(self.cmds[2]) == 20
            and self.cmds[3] == 0x88
            and self.cmds[4] == 0xac

        )

    def is_p2sh(self):

        """
        Is it a pay to vm hash vm ?
        """

        return (
            len(self.cmds) == 3
            and self.cmds[0] == 0xa9
            and isinstance(self.cmds[1], bytes)
            and len(self.cmds[1]) == 20
            and self.cmds[2] == 0x87
        )

    def is_p2wpkh(self):

        """
        Is it a pay to witness pubkey hash vm ?
        """

        return (
            len(self.cmds) == 2
            and self.cmds[0] == 0x00
            and isinstance(self.cmds[1], bytes)
            and len(self.cmds[1]) == 20
        )

    def is_p2wsh(self):

        """
        Is it a pay to witness vm hash vm ?
        """

        return (
            len(self.cmds) == 2
            and self.cmds[0] == 0x00
            and isinstance(self.cmds[1], bytes)
            and len(self.cmds[1]) == 32
        )

    def to_json(self):

        """
        Encode vm to json
        """

        return {
            'cmd': self.__repr__()
        }


class NewScript:

    """
    Handle vm formats
    """

    @staticmethod
    def p2pkh(h160):

        """
        Returns the p2pkh pubkey vm
        """

        return Script([0x76, 0xa9, h160, 0x88, 0xac])

    @staticmethod
    def p2sh(h160):

        """
        Returns the p2sh pubkey vm
        """

        return Script([0xa9, h160, 0x87])

    @staticmethod
    def p2wpkh(h160):

        """
        Returns the p2wpkh pubkey vm
        """

        return Script([0x00, h160])

    @staticmethod
    def p2wsh(h256):

        """
        Return the p2wsh pubkey vm
        """

        return Script([0x00, h256])


if __name__ == '__main__':
    pass
