"""
Module to implement the GIFT-128 bit sliced block cipher for use
in GIFT-COFB class
"""
from utils import *


# define round constants
round_constants = [0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B,
                   0x37, 0x2F, 0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E,
                   0x1D, 0x3A, 0x35, 0x2B, 0x16, 0x2C, 0x18, 0x30,
                   0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E, 0x1C, 0x38,
                   0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A,
                   0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04]


class Gift128BitSliced:
    def __init__(self):
        # initialise empty state and key states
        self.state = []
        self.key = []

    def encrypt_block(self, plaintext, input_key):
        """
        Method to run the GIFT-128 (bit-sliced) BC.
        Parameters: The plaintext block (128 bits) and input key
        Returns: Ciphertext
        """

        # initialise the cipher and key state
        self.initialise(plaintext, input_key)

        # run the round function for 40 rounds
        for i in range(0, 40):
            self.sub_cells()
            self.perm_bits()
            self.add_round_key_and_constant(i)

            # update the key state
            self.key_update()

        # convert ciphertext to hex to return
        ciphertext = self.state_to_hex()

        return ciphertext

    def initialise(self, plaintext, key_input):
        """
        Method to initialise the cipher state and key state arrays
        Parameters: plaintext block and input key
        Returns: none (stored as class attributes)
        """

        self.state = [0] * 4
        self.key = [0] * 8

        # load state into the desired format
        for i in range(0, 16, 4):
            # for every four hexadecimal characters in the plaintext we combine
            # them together and store in the cipher state
            self.state[i // 4] = plaintext[i] << 24 | plaintext[i + 1] << 16 \
                                 | plaintext[i + 2] << 8 | plaintext[i + 3]

        # load key state into the desired format
        for i in range(0, 15, 2):
            # for every two hexadecimal characters in the plaintext we combine
            # them together and store in the key state
            self.key[i // 2] = key_input[i] << 8 | key_input[i + 1]

    def sub_cells(self):
        """
        Method to apply the sub cells step of the round function.
        Parameters: the cipher state
        Returns: the cipher state after sub cells
        """

        # apply the sub-cells step - as taken from the GIFT-128 bit
        # sliced paper
        self.state[1] = self.state[1] ^ (self.state[0] & self.state[2])
        self.state[0] = self.state[0] ^ (self.state[1] & self.state[3])
        self.state[2] = self.state[2] ^ (self.state[0] | self.state[1])

        self.state[3] = self.state[3] ^ self.state[2]
        self.state[1] = self.state[1] ^ self.state[3]

        self.state[3] = ~ self.state[3]
        self.state[2] = self.state[2] ^ (self.state[0] & self.state[1])
        self.state[0], self.state[3] = self.state[3], self.state[0]

    def perm_bits(self):
        """
        Method to apply bit permutation to cipher state
        We iterate over all four cells in the cipher state, for each cell we
        iterate over every nibble, and then every bit in each nibble
        and apply the bit permutation according to the bit positions 2D array
        Parameters: none
        Returns: none (cipher state attribute updated with
        the bit permutation applied)
        """

        # new bit positions in each nibble for each cell in the cipher state
        bit_positions = [[0, 3, 2, 1], [1, 0, 3, 2],
                         [2, 1, 0, 3], [3, 2, 1, 0]]

        # iterate over each cell in the cipher state
        for cell in range(0, 4):
            new_value = 0
            # determine new value of the cipher state cell by applying bit
            # permutation

            # iterate over every nibble in the cell (0-7)
            for i in range(0, 8):
                # iterate over each bit in each nibble (0-4) and apply
                # bit permutation to it
                for j in range(0, 4):
                    new_value = new_value | (self.state[cell] >>
                                             (4 * i + j) & 0x1) << (
                                            i + 8 * bit_positions[cell][j])

            self.state[cell] = new_value

    def add_round_key_and_constant(self, round_num):
        """
        Method to apply the round key and round constant to the
        cipher state
        Parameters: The cipher state S, key state W and round number
        Returns: the cipher state after round key and constant applied
        """

        # add round key
        self.state[2] ^= (self.key[2] << 16) | self.key[3]  # apply U
        self.state[1] ^= (self.key[6] << 16) | self.key[7]  # apply V

        # add round constant
        # get the round constant and determine 0x800000XY
        # where XY = = 00c5c4c3c2c1c0
        round_constant = 0x80000000 | round_constants[round_num]
        self.state[3] = self.state[3] ^ round_constant

    def state_to_hex(self):
        """
        Method to convert the cipher state to the hex output
        Parameters: none
        Returns: the ciphertext hex
        """

        ciphertext = []
        # iterate over each cell in the cipher state
        for i in range(0, 4):
            # convert cell to hex, remove the 0x, pad to length 8
            # and convert to integer representation of hex (0-15)
            hex_element = hex(self.state[i])[2:]
            hex_element = hex_element.zfill(8)

            # add hex characters to the ciphertext list
            for j in hex_element:
                ciphertext.append(int(j, 16))

        return ciphertext

    def key_update(self):
        """
        Method to update the key after each iteration of the round function.
        Parameters: none
        Returns: none (updates key attribute variable)
        """

        # convert w6 and w7 to bit representation
        w6_bits = bin(self.key[6])
        # remove 0b at front and pad to 16 bits
        w6_bits = w6_bits[2:].zfill(16)
        w7_bits = bin(self.key[7])
        # remove 0b at front and pad to 16 bits
        w7_bits = w7_bits[2:].zfill(16)

        # apply w6 >>> 2 and w7 >>> 12
        T6 = apply_rotation(w6_bits, 2)
        T7 = apply_rotation(w7_bits, 12)

        # apply key schedule
        # key cells shifted left by 2
        for i in range(7, 1, -1):
            self.key[i] = self.key[i - 2 % 7]

        # lastly T7 and T6 are set to key state positions 1 and 0
        self.key[1] = T7
        self.key[0] = T6


def apply_rotation(bits, num_to_shift):
    """
    Function to apply a
    """
    return int((bits[-num_to_shift:] + bits[:-num_to_shift]), 2)