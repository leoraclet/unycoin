# Copyright (c) 2022 Neutronys

# The software is distributed under the MIT software license
# See the accompanying file LICENSE in the main directory of
# the project for more details.


"""

This file implements all supported OP CODES.

"""


from crypto.ecc import verify
from crypto.hasher import (
    hash160,
    hash256,
    ripemd160,
    sha256
)


def encode_num(number):

    """
    Encode number to bytes
    """

    if number == 0:
        return b''

    result = bytearray()
    abs_number = abs(number)

    while abs_number:

        result.append(abs_number & 0xff)
        abs_number >>= 8

    # If it's a positive number
    if result[-1] == 0x80:
        if number < 0:
            result.append(0x80)
        else:
            result.append(0x00)

    elif number < 0:
        result[-1] |= 0x80

    return bytes(result)


def decode_num(element):

    """
    Decode bytes to number
    """

    if element == b'':
        return 0

    # Reverse for big endian order
    big_endian = element[::-1]

    # Top bit being 1 means it's negative
    if big_endian[0] & 0x80:

        result = big_endian[0] & 0x7f
        negative = True

    # Else it's positive
    else:
        result = big_endian[0]
        negative = False

    for c in big_endian[1:]:
        result <<= 8
        result += c

    # Return decoded number
    if negative:
        return -result

    return result


def op_0(stack):

    """
    An empty array of bytes is pushed
    onto the stack.
    """

    stack.append(encode_num(0))
    return True


def op_1negate(stack):

    """
    The number -1 is pushed onto the stack.
    """

    stack.append(encode_num(-1))
    return True


def op_1(stack):

    """
    The number 1 is pushed onto the stack.
    """

    stack.append(encode_num(1))
    return True


def op_2(stack):

    """
    The number 2 is pushed onto the stack.
    """

    stack.append(encode_num(2))
    return True


def op_3(stack):

    """
    The number 3 is pushed onto the stack.
    """

    stack.append(encode_num(3))
    return True


def op_4(stack):

    """
    The number 4 is pushed onto the stack.
    """

    stack.append(encode_num(4))
    return True


def op_5(stack):

    """
    The number 5 is pushed onto the stack.
    """

    stack.append(encode_num(5))
    return True


def op_6(stack):

    """
    The number 6 is pushed onto the stack.
    """

    stack.append(encode_num(6))
    return True


def op_7(stack):

    """
    The number 7 is pushed onto the stack.
    """

    stack.append(encode_num(7))
    return True


def op_8(stack):

    """
    The number 8 is pushed onto the stack.
    """

    stack.append(encode_num(8))
    return True


def op_9(stack):

    """
    The number 9 is pushed onto the stack.
    """

    stack.append(encode_num(9))
    return True


def op_10(stack):

    """
    The number 10 is pushed onto the stack.
    """

    stack.append(encode_num(10))
    return True


def op_11(stack):

    """
    The number 11 is pushed onto the stack.
    """

    stack.append(encode_num(11))
    return True


def op_12(stack):

    """
    The number 12 is pushed onto the stack.
    """

    stack.append(encode_num(12))
    return True


def op_13(stack):

    """
    The number 13 is pushed onto the stack.
    """

    stack.append(encode_num(13))
    return True


def op_14(stack):

    """
    The number 14 is pushed onto the stack.
    """

    stack.append(encode_num(14))
    return True


def op_15(stack):

    """
    The number 15 is pushed onto the stack.
    """

    stack.append(encode_num(15))
    return True


def op_16(stack):

    """
    The number 16 is pushed onto the stack.
    """

    stack.append(encode_num(16))
    return True


def op_nop():

    """
    Does nothing.
    The word is ignored.
    Does not mark transaction as invalid.
    """

    return True


def op_if(stack, items):

    """
    If the top stack value is not FALSE,
    the statements between IF and ELSE are executed.

    If the top stack value is FALSE,
    the statements between ELSE and ENDIF are executed.

    The top stack value is removed.
    """

    if len(stack) < 1:
        return False

    true_items = []
    false_items = []

    found = False
    endifs_needed = 0
    current_items = true_items

    while len(items) > 0:

        item = items.pop(0)

        if item in [99, 100]:

            endifs_needed += 1
            current_items.append(item)

        elif endifs_needed == 1 and item == 103:

            current_items = false_items

        elif item == 104:

            if endifs_needed == 1:

                found = True
                break

            else:
                endifs_needed -= 1
                current_items.append(item)

        else:
            current_items.append(item)

    if not found:
        return False

    element = stack.pop()

    if decode_num(element) == 0:
        items[:0] = false_items
    else:
        items[:0] = true_items

    return True


def op_notif(stack, items):

    """
    If the top stack value is FALSE,
    the statements between IF and ELSE are executed.

    If the top stack value is not FALSE,
    the statements between ELSE and ENDIF are executed.

    The top stack value is removed.
    """

    if len(stack) < 1:
        return False

    true_items = []
    false_items = []

    found = False
    endifs_needed = 0
    current_items = true_items

    while len(items) > 0:

        item = items.pop(0)

        if item in [99, 100]:

            endifs_needed += 1
            current_items.append(item)

        elif endifs_needed == 1 and item == 103:

            current_items = false_items

        elif item == 104:

            if endifs_needed == 1:

                found = True
                break

            else:
                endifs_needed -= 1
                current_items.append(item)

        else:
            current_items.append(item)

    if not found:
        return False

    element = stack.pop()

    if decode_num(element) == 0:
        items[:0] = true_items
    else:
        items[:0] = false_items

    return True


def op_else(stack):

    """
    If the preceding OP_IF or OP_NOTIF or OP_ELSE was
    not executed then these statements are and if the
    preceding OP_IF or OP_NOTIF or OP_ELSE was executed
    then these statements are not.
    """

    if len(stack) < 1:
        return False

    return True


def op_endif(stack):

    """
    Ends an if/else block. All blocks must end, or the
    transaction is invalid. An OP_ENDIF without a prior
    matching OP_IF or OP_NOTIF is also invalid.
    """

    if len(stack) < 1:
        return False

    return True


def op_return():

    """
    OP_RETURN can also be used to create "False Return"
    outputs with a scriptPubKey consisting of OP_FALSE
    OP_RETURN followed by database.
    """

    return False


def op_verify(stack):

    """
    Marks transaction as invalid if top stack value
    is not true. The top stack value is removed.
    """

    if len(stack) < 1:
        return False

    e = stack.pop()

    if decode_num(e) == 0:
        return False

    return True


def op_toaltstack(stack, altstack):

    """
    Puts the input onto the top of the alt stack.
    Removes it from the main stack.
    """

    if len(stack) < 1:
        return False

    altstack.append(stack.pop())

    return True


def op_fromaltstack(stack, altstack):

    """
    Puts the input onto the top of the main stack.
    Removes it from the alt stack.
    """

    if len(altstack) < 1:
        return False

    stack.append(altstack.pop())

    return True


def op_2drop(stack):

    """
    Removes the top two stack items.
    """

    if len(stack) < 2:
        return False

    stack.pop()
    stack.pop()

    return True


def op_2dup(stack):

    """
    Duplicates the top two stack items.
    """

    if len(stack) < 2:
        return False

    stack.extend(stack[-2:])

    return True


def op_3dup(stack):

    """
    Duplicates the top three stack items.
    """

    if len(stack) < 3:
        return False

    stack.extend(stack[-3:])

    return True


def op_2over(stack):

    """
    Copies the pair of items two spaces back in
    the stack to the front.
    """

    if len(stack) < 4:
        return False

    stack.extend(stack[-4:-2])

    return True


def op_2rot(stack):

    """
    The fifth and sixth items back are moved
    to the top of the stack.
    """

    if len(stack) < 6:
        return False

    stack.extend(stack[-6:-4])

    return True


def op_2swap(stack):

    """
    Swaps the top two pairs of items.
    """

    if len(stack) < 4:
        return False

    stack[-4:] = stack[-2:] + stack[-4:-2]

    return True


def op_ifdup(stack):

    """
    If the top stack value is not 0,
    duplicate it.
    """

    if len(stack) < 1:
        return False

    if decode_num(stack[-1]) != 0:
        stack.append(stack[-1])

    return True


def op_depth(stack):

    """
    Counts the number of stack items onto the stack
    and places the value on the top
    """

    stack.append(encode_num(len(stack)))

    return True


def op_drop(stack):

    """
    Removes the top stack item.
    """

    if len(stack) < 1:
        return False

    stack.pop()

    return True


def op_dup(stack):

    """
    Duplicates the top stack item.
    """

    if len(stack) < 2:
        return False

    stack.append(stack[-1])
    return True


def op_nip(stack):

    """
    Removes the second-to-top
    stack item.
    """

    if len(stack) < 2:
        return False

    stack[-2:] = stack[-1:]

    return True


def op_over(stack):

    """
    Copies the second-to-top stack
    item to the top.
    """

    if len(stack) < 2:
        return False

    stack.append(stack[-2])

    return True


def op_pick(stack):

    """
    The item n back in the stack is
    copied to the top.
    """

    if len(stack) < 1:
        return False

    n = decode_num(stack.pop())

    if len(stack) < n + 1:
        return False

    stack.append(stack[-n - 1])

    return True


def op_roll(stack):

    """
    The item n back in the stack is
    moved to the top.
    """

    if len(stack) < 1:
        return False

    n = decode_num(stack.pop())

    if len(stack) < n + 1:
        return False

    if n == 0:
        return True

    stack.append(stack.pop(-n - 1))

    return True


def op_rot(stack):

    """
    The top three items on the stack
    are rotated to the left.
    """

    if len(stack) < 3:
        return False

    stack.append(stack.pop(-3))

    return True


def op_swap(stack):

    """
    The top two items on the stack are swapped.
    """

    if len(stack) < 2:
        return False

    stack.append(stack.pop(-2))

    return True


def op_tuck(stack):

    """
    The item at the top of the stack is copied and
    inserted before the second-to-top item.
    """

    if len(stack) < 2:
        return False

    stack.insert(-2, stack[-1])

    return True


def op_cat(stack):

    """
    Concatenates two strings.
    """

    if len(stack) < 2:
        return False

    s1 = stack.pop()
    s2 = stack.pop()

    stack.append(s1 + s2)

    return True


def op_split(stack):

    """
    Splits byte sequence X at position n.
    """

    if len(stack) < 1:
        return False

    b = stack.pop(0)
    n = decode_num(stack.pop(0))

    stack.append(b[:n])
    stack.appedn(b[n:])

    return True


def op_num2bin(stack):

    """
    Converts numeric value A into byte
    sequence of length B.
    """

    if len(stack) < 2:
        return False

    a = decode_num(stack.pop(0))
    b = decode_num(stack.pop(0))

    stack.append(a.to_bytes(b, 'little'))

    return True


def op_bin2num(stack):

    """
    Converts byte sequence X into
    a numeric value.
    """

    if len(stack) < 2:
        return False

    x = decode_num(stack.pop(0))
    stack.append(int.from_bytes(x, 'little'))

    return True


def op_size(stack):

    """
    Pushes the string length of the top element of
    the stack ( without popping it ).
    """

    if len(stack) < 1:
        return False

    stack.append(encode_num(len(stack[-1])))

    return True


def op_invert(stack):

    """
    Flips all the bits in the input.
    """

    if len(stack) < 1:
        return False

    number = decode_num(stack.pop())
    stack.append(encode_num(~number & 255))

    return True


def op_and(stack):

    """
    Boolean and between each bit
    in the inputs.
    """

    if len(stack) < 2:
        return False

    number1 = decode_num(stack.pop())
    number2 = decode_num(stack.pop())

    stack.append(encode_num(number1 & number2))

    return True


def op_or(stack):

    """
    Boolean or between each bit
    in the inputs.
    """

    if len(stack) < 2:
        return False

    number1 = decode_num(stack.pop())
    number2 = decode_num(stack.pop())

    stack.append(encode_num(number1 | number2))

    return True


def op_xor(stack):

    """
    Boolean exclusive or between each
    bit in the inputs.
    """

    if len(stack) < 2:
        return False

    number1 = decode_num(stack.pop())
    number2 = decode_num(stack.pop())

    stack.append(encode_num(number1 ^ number2))

    return True


def op_equal(stack):

    """
    Returns 1 if the inputs are exactly equal,
    0 otherwise.
    """

    if len(stack) < 2:
        return False

    e1 = stack.pop()
    e2 = stack.pop()

    if e1 == e2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))

    return True


def op_equalverify(stack):

    """
    Same as OP_EQUAL, but runs
    OP_VERIFY afterward.
    """

    return op_equal(stack) and op_verify(stack)


def op_1add(stack):

    """
    1 is added to the input.
    """

    if len(stack) < 1:
        return False

    element = decode_num(stack.pop())
    stack.append(encode_num(element + 1))

    return True


def op_1sub(stack):

    """
    1 is subtracted from the input.
    """

    if len(stack) < 1:
        return False

    element = decode_num(stack.pop())
    stack.append(encode_num(element - 1))

    return True


def op_2mul(stack):

    """
    The input is multiplied by 2.
    """

    if len(stack) < 1:
        return False

    element = decode_num(stack.pop())
    stack.append(encode_num(element * 2))

    return True


def op_2div(stack):

    """
    The input is divided by 2.
    """

    if len(stack) < 1:
        return False

    element = decode_num(stack.pop())
    stack.append(encode_num(element // 2))

    return True


def op_negate(stack):

    """
    The sign of the input is flipped.
    """

    if len(stack) < 1:
        return False

    number = decode_num(stack.pop())
    stack.append(encode_num(-number))

    return True


def op_abs(stack):

    """
    The input is made positive.
    """

    if len(stack) < 1:
        return False

    element = decode_num(stack.pop())

    if element < 0:
        stack.append(encode_num(-element))
    else:
        stack.append(encode_num(element))

    return True


def op_not(stack):

    """
    If the input is 0 or 1, it is flipped.
    Otherwise, the output will be 0.
    """

    if len(stack) < 1:
        return False

    element = stack.pop()

    if decode_num(element) == 0:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))

    return True


def op_0notequal(stack):

    """
    Returns 0 if the input is 0.
    1 otherwise.
    """

    if len(stack) < 1:
        return False

    number = decode_num(stack.pop())

    if number == 0:
        stack.append(encode_num(0))
    else:
        stack.append(encode_num(1))

    return True


def op_add(stack):

    """
    A is added to B.
    """

    if len(stack) < 2:
        return False

    number1 = decode_num(stack.pop())
    number2 = decode_num(stack.pop())

    stack.append(encode_num(number1 + number2))

    return True


def op_sub(stack):

    """
    B is subtracted from A.
    """

    if len(stack) < 2:
        return False

    number1 = decode_num(stack.pop())
    number2 = decode_num(stack.pop())

    stack.append(encode_num(number2 - number1))

    return True


def op_mul(stack):

    """
    A is multiplied by B.
    """

    if len(stack) < 2:
        return False

    number1 = decode_num(stack.pop())
    number2 = decode_num(stack.pop())

    stack.append(encode_num(number2 * number1))

    return True


def op_div(stack):

    """
    A is divided by B.
    """

    if len(stack) < 2:
        return False

    number1 = decode_num(stack.pop())
    number2 = decode_num(stack.pop())

    if number1 == 0:
        return False

    stack.append(encode_num(number2 // number1))

    return True


def op_mod(stack):

    """
    Returns the remainder after dividing A by B.
    """

    if len(stack) < 2:
        return False

    number1 = decode_num(stack.pop())
    number2 = decode_num(stack.pop())

    if number1 == 0:
        return False

    stack.append(encode_num(number2 % number1))

    return True


def op_lshift(stack):

    """
    Logical left shift b bits
    """

    if len(stack) < 2:
        return False

    number1 = decode_num(stack.pop())
    number2 = decode_num(stack.pop())

    stack.append(encode_num(number1 << number2))

    return True


def op_rshift(stack):

    """
    Logical right shift b bits.
    """

    if len(stack) < 2:
        return False

    number1 = decode_num(stack.pop())
    number2 = decode_num(stack.pop())

    stack.append(encode_num(number1 >> number2))

    return True


def op_booland(stack):

    """
    If both a and b are not 0, the output is 1.
    Otherwise, 0.
    """

    if len(stack) < 2:
        return False

    number1 = decode_num(stack.pop())
    number2 = decode_num(stack.pop())

    if number1 and number2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))

    return True


def op_boolor(stack):

    """
    If a or b is not 0, the output is 1.
    Otherwise, 0.
    """

    if len(stack) < 2:
        return False

    number1 = decode_num(stack.pop())
    number2 = decode_num(stack.pop())

    if number1 or number2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))

    return True


def op_numequal(stack):

    """
    Returns 1 if the numbers are equal,
    0 otherwise.
    """

    if len(stack) < 2:
        return False

    number1 = decode_num(stack.pop())
    number2 = decode_num(stack.pop())

    if number1 == number2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))

    return True


def op_numequalverify(stack):

    """
    Same as OP_NUMEQUAL, but runs
    OP_VERIFY afterward.
    """

    return op_numequal(stack) and op_verify(stack)


def op_numnotequal(stack):

    """
    Returns 1 if the numbers are not equal,
    0 otherwise.
    """

    if len(stack) < 2:
        return False

    number1 = decode_num(stack.pop())
    number2 = decode_num(stack.pop())

    if number1 != number2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))

    return True


def op_lessthan(stack):

    """
    Returns 1 if A is less than B,
    0 otherwise.
    """

    if len(stack) < 2:
        return False

    number1 = decode_num(stack.pop())
    number2 = decode_num(stack.pop())

    if number2 < number1:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))

    return True


def op_greaterthan(stack):

    """
    Returns 1 if A is greater than B,
    0 otherwise.
    """

    if len(stack) < 2:
        return False

    number1 = decode_num(stack.pop())
    number2 = decode_num(stack.pop())

    if number2 > number1:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))

    return True


def op_lessthanorequal(stack):

    """
    Returns 1 if A is less than or equal to B,
    0 otherwise.
    """

    if len(stack) < 2:
        return False

    number1 = decode_num(stack.pop())
    number2 = decode_num(stack.pop())

    if number2 <= number1:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))

    return True


def op_greaterthanorequal(stack):

    """
    Returns 1 if A is greater than or equal to B,
    0 otherwise.
    """

    if len(stack) < 2:
        return False

    number1 = decode_num(stack.pop())
    number2 = decode_num(stack.pop())

    if number2 >= number1:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))

    return True


def op_min(stack):

    """
    Returns the smallest of A and B.
    """

    if len(stack) < 2:
        return False

    number1 = decode_num(stack.pop())
    number2 = decode_num(stack.pop())

    if number1 < number2:
        stack.append(encode_num(number1))
    else:
        stack.append(encode_num(number2))

    return True


def op_max(stack):

    """
    Returns the largest of a and b.
    """

    if len(stack) < 2:
        return False

    number1 = decode_num(stack.pop())
    number2 = decode_num(stack.pop())

    if number1 > number2:
        stack.append(encode_num(number1))
    else:
        stack.append(encode_num(number2))

    return True


def op_within(stack):

    """
    Returns 1 if x is within the specified range
    (left-inclusive), 0 otherwise.
    """

    if len(stack) < 3:
        return False

    max_nb = decode_num(stack.pop())
    min_nb = decode_num(stack.pop())
    number = decode_num(stack.pop())

    if min_nb <= number < max_nb:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))

    return True


def op_ripemd160(stack):

    """
    The input is hashed using RIPEMD-160.
    """

    if len(stack) < 1:
        return False

    e = stack.pop()
    stack.append(ripemd160(e))

    return True


def op_sha1():

    """
    The input is hashed using SHA-1.
    """

    return True


def op_sha256(stack):

    """
    The input is hashed using SHA-256.
    """

    if len(stack) < 1:
        return False

    e = stack.pop()
    stack.append(sha256(e))

    return True


def op_hash160(stack):

    """
    The input is hashed twice: first with
    SHA-256 and then with RIPEMD-160.
    """

    if len(stack) < 1:
        return False

    e = stack.pop()
    stack.append(hash160(e))

    return True


def op_hash256(stack):

    """
    The input is hashed two times
    with SHA-256.
    """

    if len(stack) < 1:
        return False

    e = stack.pop()
    stack.append(hash256(e))

    return True


def op_checksig(stack, b):

    """
    If it is a valid signature, 1 is returned,
    0 otherwise.
    """

    if len(stack) < 2:
        return False

    sec = stack.pop()
    der = stack.pop()[:-1]

    if verify(b, der, sec):
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))

    return True


def op_checksigverify(stack, b):

    """
    Same as OP_CHECKSIG, but OP_VERIFY
    is executed afterward.
    """

    return op_checksig(stack, b) and op_verify(stack)


def op_checkmultisig(stack, z):

    """
    If all signatures are valid, 1 is returned,
    0 otherwise.

    Due to a bug, an extra unused value (x) is removed
    from the stack.
    Script spenders must account for this by adding a
    junk value to the stack.
    """

    if len(stack) < 1:
        return False

    # Number of public keys
    n = decode_num(stack.pop())

    if len(stack) < n + 1:
        return False

    sec_pubkeys = []

    for _ in range(n):
        sec_pubkeys.append(stack.pop())

    # Number of signatures
    m = decode_num(stack.pop())

    if len(stack) < m + 1:
        return False

    der_sigs = []

    for _ in range(m):
        der_sigs.append(stack.pop())

    # OP_CHECKMULTISIG bug
    stack.pop()

    for sec, der in zip(sec_pubkeys, der_sigs):

        if not verify(z, der, sec):
            return False

    return True


def op_checkmultisigverify(stack, b):

    """
    Same as OP_CHECKMULTISIG, but OP_VERIFY
    is executed afterward.
    """

    return op_checkmultisig(stack, b) and op_verify(stack)


def op_checklocktimeverify(stack, locktime, sequence):

    """
    Mark transaction as invalid if

    1. The top stack item is greater
       than the transaction's nLockTime field
    2. The stack is empty
    3. The top stack item is negative
    4. The top stack item is greater than or equal to
       500000000 while the transaction's nLockTime field is
       less than 500000000, or vice versa
    5. The input's nSequence field is equal to 0xffffffff.

    Otherwise, vm evaluation continues as though
    an OP_NOP was executed.
    """

    if sequence == 0xffffffff:
        return False

    if len(stack) < 1:
        return False

    element = decode_num(stack[-1])

    if element < 0:
        return False

    if locktime < element:
        return False

    if element < 500000000 < locktime:
        return False

    return True


def op_checksequenceverify(stack, version, sequence):

    """
    Mark transaction as invalid if the relative lock
    time of the input is not equal to or longer than
    the value of the top stack item.
    """

    if sequence & (1 << 31) == (1 << 31):
        return False

    if len(stack) < 1:
        return False

    element = decode_num(stack[-1])

    if element < 0:
        return False

    if element & (1 << 31) != (1 << 31):

        if version < 2:
            return False

        if sequence & (1 << 31) == (1 << 31):
            return False

        if element & (1 << 22) != sequence & (1 << 22):
            return False

        if element & 0xffff > sequence & 0xffff:
            return False

    return True


OP_CODE_FUNCTIONS = {
    0: op_0,                      # OP_0
    76: op_nop,                   # OP_PUSHDATA1
    77: op_nop,                   # OP_PUSHDATA2
    78: op_nop,                   # OP_PUSHDATA4
    79: op_1negate,               # OP_1NEGATE
    81: op_1,                     # OP_1
    82: op_2,                     # OP_2
    83: op_3,                     # OP_3
    84: op_4,                     # OP_4
    85: op_5,                     # OP_5
    86: op_6,                     # OP_6
    87: op_7,                     # OP_7
    88: op_8,                     # OP_8
    89: op_9,                     # OP_9
    90: op_10,                    # OP_10
    91: op_11,                    # OP_11
    92: op_12,                    # OP_12
    93: op_13,                    # OP_13
    94: op_14,                    # OP_14
    95: op_15,                    # OP_15
    96: op_16,                    # OP_16
    97: op_nop,                   # OP_NOP
    99: op_if,                    # OP_IF
    100: op_notif,                # OP_NOTIF
    103: op_else,                 # OP_ELSE
    104: op_endif,                # OP_ENDIF
    105: op_verify,               # OP_VERIFY
    106: op_return,               # OP_RETURN
    107: op_toaltstack,           # OP_TOALTSTACK
    108: op_fromaltstack,         # OP_FROMALTSTACK
    109: op_2drop,                # OP_2DROP
    110: op_2dup,                 # OP_2DUP
    111: op_3dup,                 # OP_3DUP
    112: op_2over,                # OP_2OVER
    113: op_2rot,                 # OP_2ROT
    114: op_2swap,                # OP_2SWAP
    115: op_ifdup,                # OP_IFDUP
    116: op_depth,                # OP_DEPTH
    117: op_drop,                 # OP_DROP
    118: op_dup,                  # OP_DUP
    119: op_nip,                  # OP_NIP
    120: op_over,                 # OP_OVER
    121: op_pick,                 # OP_PICK
    122: op_roll,                 # OP_ROLL
    123: op_rot,                  # OP_ROT
    124: op_swap,                 # OP_SWAP
    125: op_tuck,                 # OP_TUCK
    126: op_cat,                  # OP_CAT
    127: op_split,                # OP_SPLIT
    128: op_num2bin,              # OP_NUM2BIN
    129: op_bin2num,              # OP_BIN2NUM
    130: op_size,                 # OP_SIZE
    131: op_invert,               # OP_INVERT
    132: op_and,                  # OP_AND
    133: op_or,                   # OP_OR
    134: op_xor,                  # OP_XOR
    135: op_equal,                # OP_EQUAL
    136: op_equalverify,          # OP_EQUALVERIFY
    139: op_1add,                 # OP_1ADD
    140: op_1sub,                 # OP_1SUB
    141: op_2mul,                 # OP_2MUL
    142: op_2div,                 # OP_2DIV
    143: op_negate,               # OP_NEGATE
    144: op_abs,                  # OP_ABS
    145: op_not,                  # OP_NOT
    146: op_0notequal,            # OP_0NOTEQUAL
    147: op_add,                  # OP_ADD
    148: op_sub,                  # OP_SUB
    149: op_mul,                  # OP_MUL
    150: op_div,                  # OP_DIV
    151: op_mod,                  # OP_MOD
    152: op_lshift,               # OP_LSHIFT
    153: op_rshift,               # OP_RSHIFT
    154: op_booland,              # OP_BOOLAND
    155: op_boolor,               # OP_BOOLOR
    156: op_numequal,             # OP_NUMEQUAL
    157: op_numequalverify,       # OP_NUMEQUALVERIFY
    158: op_numnotequal,          # OP_NUMNOTEQUAL
    159: op_lessthan,             # OP_LESSTHAN
    160: op_greaterthan,          # OP_GREATERTHAN
    161: op_lessthanorequal,      # OP_LESSTHANOREQUAL
    162: op_greaterthanorequal,   # OP_GREATERTHANOREQUAL
    163: op_min,                  # OP_MIN
    164: op_max,                  # OP_MAX
    165: op_within,               # OP_WITHIN
    166: op_ripemd160,            # OP_RIPEMD160
    167: op_nop,                  # OP_SHA1 ( NOT IMPLEMENTED )
    168: op_sha256,               # OP_SHA256
    169: op_hash160,              # OP_HASH160
    170: op_hash256,              # OP_HASH256
    171: op_nop,                  # OP_CODESEPARATOR
    172: op_checksig,             # OP_CHECKSIG
    173: op_checksigverify,       # OP_CHECKSIGVERIFY
    174: op_checkmultisig,        # OP_CHECKMULTISIG
    175: op_checkmultisigverify,  # OP_CHECKMULTISIGVERIFY
    176: op_nop,                  # OP_NOP1
    177: op_checklocktimeverify,  # OP_CHECKLOCKTIMEVERIFY
    178: op_checksequenceverify,  # OP_CHECKSEQUENCEVERIFY
    179: op_nop,                  # OP_NOP4
    180: op_nop,                  # OP_NOP5
    181: op_nop,                  # OP_NOP6
    182: op_nop,                  # OP_NOP7
    183: op_nop,                  # OP_NOP8
    184: op_nop,                  # OP_NOP9
    185: op_nop,                  # OP_NOP10
}

OP_CODE_NAMES = {
    0: 'OP_0',
    76: 'OP_PUSHDATA1',
    77: 'OP_PUSHDATA2',
    78: 'OP_PUSHDATA4',
    79: 'OP_1NEGATE',
    81: 'OP_1',
    82: 'OP_2',
    83: 'OP_3',
    84: 'OP_4',
    85: 'OP_5',
    86: 'OP_6',
    87: 'OP_7',
    88: 'OP_8',
    89: 'OP_9',
    90: 'OP_10',
    91: 'OP_11',
    92: 'OP_12',
    93: 'OP_13',
    94: 'OP_14',
    95: 'OP_15',
    96: 'OP_16',
    97: 'OP_NOP',
    99: 'OP_IF',
    100: 'OP_NOTIF',
    103: 'OP_ELSE',
    104: 'OP_ENDIF',
    105: 'OP_VERIFY',
    106: 'OP_RETURN',
    107: 'OP_TOALTSTACK',
    108: 'OP_FROMALTSTACK',
    109: 'OP_2DROP',
    110: 'OP_2DUP',
    111: 'OP_3DUP',
    112: 'OP_2OVER',
    113: 'OP_2ROT',
    114: 'OP_2SWAP',
    115: 'OP_IFDUP',
    116: 'OP_DEPTH',
    117: 'OP_DROP',
    118: 'OP_DUP',
    119: 'OP_NIP',
    120: 'OP_OVER',
    121: 'OP_PICK',
    122: 'OP_ROLL',
    123: 'OP_ROT',
    124: 'OP_SWAP',
    125: 'OP_TUCK',
    126: 'OP_CAT',
    127: 'OP_SPLIT',
    128: 'OP_NUM2BIN',
    129: 'OP_BIN2NUM',
    130: 'OP_SIZE',
    131: 'OP_INVERT',
    132: 'OP_AND',
    133: 'OP_OR',
    134: 'OP_XOR',
    135: 'OP_EQUAL',
    136: 'OP_EQUALVERIFY',
    139: 'OP_1ADD',
    140: 'OP_1SUB',
    141: 'OP_2MUL',
    142: 'OP_2DIV',
    143: 'OP_NEGATE',
    144: 'OP_ABS',
    145: 'OP_NOT',
    146: 'OP_0NOTEQUAL',
    147: 'OP_ADD',
    148: 'OP_SUB',
    149: 'OP_MUL',
    150: 'OP_DIV',
    151: 'OP_MOD',
    152: 'OP_LSHIFT',
    153: 'OP_RSHIFT',
    154: 'OP_BOOLAND',
    155: 'OP_BOOLOR',
    156: 'OP_NUMEQUAL',
    157: 'OP_NUMEQUALVERIFY',
    158: 'OP_NUMNOTEQUAL',
    159: 'OP_LESSTHAN',
    160: 'OP_GREATERTHAN',
    161: 'OP_LESSTHANOREQUAL',
    162: 'OP_GREATERTHANOREQUAL',
    163: 'OP_MIN',
    164: 'OP_MAX',
    165: 'OP_WITHIN',
    166: 'OP_RIPEMD160',
    167: 'OP_SHA1',
    168: 'OP_SHA256',
    169: 'OP_HASH160',
    170: 'OP_HASH256',
    171: 'OP_CODESEPARATOR',
    172: 'OP_CHECKSIG',
    173: 'OP_CHECKSIGVERIFY',
    174: 'OP_CHECKMULTISIG',
    175: 'OP_CHECKMULTISIGVERIFY',
    176: 'OP_NOP1',
    177: 'OP_CHECKLOCKTIMEVERIFY',
    178: 'OP_CHECKSEQUENCEVERIFY',
    179: 'OP_NOP4',
    180: 'OP_NOP5',
    181: 'OP_NOP6',
    182: 'OP_NOP7',
    183: 'OP_NOP8',
    184: 'OP_NOP9',
    185: 'OP_NOP10',
}


if __name__ == '__main__':
    pass


# TODO: Implement missing OP CODES
