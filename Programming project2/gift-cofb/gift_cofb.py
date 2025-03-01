"""
Module to implement the GIFT-COFB algorithm - note the need to import the
GIFT-128 bit sliced version of the GIFT block cipher for use in GIFT-COFB
"""


from gift128bitsliced import *


class GiftCofb:
    def __init__(self):
        # instantiate GIFT-128 object - the block cipher used in GIFT-COFB
        self.cipher = Gift128BitSliced()

        # declare n which is the block size (bits)
        self.n = 128

    def encrypt(self, plaintext_blocks, key, associated_data_blocks, nonce):
        """
        Method to run GIFT-COFB to produce ciphertext and tag
        Parameters: the plaintext blocks, key, associated data blocks, nonce.
        Returns: the ciphertext and tag
        """

        # 1. Initialisation
        ciphertext_blocks = []

        # the nonce is encrypted with GIFT-128 and set as the state
        state = nonce[:]
        state = self.cipher.encrypt_block(hex_to_decimal(state),
                                          hex_to_decimal(key))

        # truncate state (y[0]) and set to delta
        delta = state[0:16]

        # 2. Process associated data blocks

        # iterate over all associated data blocks excluding the last
        for i in range(0, len(associated_data_blocks) - 1):
            # L ← 2 · L
            delta = self.double(delta)
            # apply ρ1(Y, M) = G· Y ⊕ M
            state = self.pho1(state, associated_data_blocks[i])

            # xor state with delta (pad delta with 0's)
            state = xor_bits(state, delta + [0] * 32)

            # encrypt state under GIFT-128
            state = self.cipher.encrypt_block(hex_to_decimal(state),
                                              hex_to_decimal(key))

        # L ← 3 · L
        delta = self.triple(delta)

        # check whether last associated data block is not a full block
        if len((associated_data_blocks[-1]) * 4) != self.n:
            # L ← 3 · L if last associated data block is not full
            delta = self.triple(delta)

        # check whether plaintext is empty
        if plaintext_blocks == [[]]:
            # L ← 3^2 · L if plaintext is empty
            delta = self.triple(delta)
            delta = self.triple(delta)

        # pad last associated data block (where necessary)
        associated_data_blocks[-1] = apply_padding(associated_data_blocks[-1],
                                                   128)
        # apply ρ1(Y, M) = G· Y ⊕ M
        state = self.pho1(state, associated_data_blocks[-1])

        # xor state with delta (pad delta with 0's) and encrypt state
        state = xor_bits(state, delta + [0] * 32)

        state = self.cipher.encrypt_block(hex_to_decimal(state),
                                          hex_to_decimal(key))

        # 3. Process plaintext blocks

        # iterate over all plaintext blocks excluding the last one
        for i in range(0, len(plaintext_blocks) - 1):
            # L ← 2 · L
            delta = self.double(delta)

            # apply ρ(Y, M) = (ρ1(Y, M), Y ⊕ M)
            state, ciphertext = self.pho(state, plaintext_blocks[i])
            ciphertext_blocks.append(ciphertext)

            # xor state with padded delta and encrypt state
            state = xor_bits(state, delta + [0] * 32)
            state = self.cipher.encrypt_block(hex_to_decimal(state),
                                              hex_to_decimal(key))

        # check whether plaintext is not empty, i.e. there is a final block
        # to analyse
        if plaintext_blocks != [[]]:
            # L ← 3 · L
            delta = self.triple(delta)

            # check whether last block of plaintext is not full
            if len(plaintext_blocks[-1]) != 32:
                # L ← 3 · L if last plaintext block not full
                delta = self.triple(delta)

            # apply padding where necessary to last plaintext block
            length = len(plaintext_blocks[-1])
            plaintext_blocks[-1] = apply_padding(plaintext_blocks[-1], 128)

            # apply ρ(Y, M) = (ρ1(Y, M), Y ⊕ M)
            state, ciphertext = self.pho(state, plaintext_blocks[-1])
            ciphertext_blocks.append(ciphertext[0:length])

            # xor state with padded delta and encrypt state
            state = xor_bits(state, delta + [0] * 32)

            state = self.cipher.encrypt_block(hex_to_decimal(state),
                                              hex_to_decimal(key))
            
        # tag becomes the current value of state
        tag = state

        return ciphertext_blocks, tag

    def verify(self, ciphertext, key, associated_data, nonce, tag_to_verify):
        """
        Method to verify whether GIFT-COFB tag. If tag is verified, decrypted
        message is returned.
        Parameters: ciphertext blocks, key, associated data blocks, nonce
        and the tag to verify.
        Returns: if tag is verified, the plaintext, otherwise returns empty
        plaintext.
        """

        # 1. Initialisation
        plaintext_blocks = []

        # the nonce is encrypted with GIFT-128 and set as the state
        state = nonce[:]
        state = self.cipher.encrypt_block(hex_to_decimal(state),
                                          hex_to_decimal(key))

        # truncate state (y[0]) and set to delta
        delta = state[0:16]

        # 2. Process associated data blocks

        # iterate over all associated data blocks excluding the last
        for i in range(0, len(associated_data) - 1):
            # L ← 2 · L
            delta = self.double(delta)

            # apply ρ1(Y, M) = G· Y ⊕ M
            state = self.pho1(state, associated_data[i])

            # xor state with delta (pad delta with 0's)
            state = xor_bits(state, delta + [0] * 32)

            # encrypt state under GIFT-128
            state = self.cipher.encrypt_block(hex_to_decimal(state),
                                              hex_to_decimal(key))

        # L ← 3 · L
        delta = self.triple(delta)

        # check whether last associated data block is not a full block
        if len((associated_data[-1]) * 4) != self.n:
            # L ← 3 · L if last associated data block is not full
            delta = self.triple(delta)

        # check whether plaintext is empty
        if ciphertext == [[]]:
            # L ← 3^2 · L if plaintext is empty
            delta = self.triple(delta)
            delta = self.triple(delta)

        # pad last associated data block (where necessary)
        associated_data[-1] = apply_padding(associated_data[-1], 128)

        # apply ρ1(Y, M) = G· Y ⊕ M
        state = self.pho1(state, associated_data[-1])

        # xor state with delta (pad delta with 0's) and encrypt state
        state = xor_bits(state, delta + [0] * 32)
        state = self.cipher.encrypt_block(hex_to_decimal(state),
                                          hex_to_decimal(key))

        # 3. Process plaintext blocks

        # iterate over all plaintext blocks excluding the last one
        for i in range(0, len(ciphertext) - 1):
            # L ← 2 · L
            delta = self.double(delta)

            # apply ρ(Y, M) = (ρ1(Y, M), Y ⊕ M)
            state, ciphertext_block = self.phoprime(state, ciphertext[i])
            plaintext_blocks.append(ciphertext_block)

            # xor state with padded delta and encrypt state
            state = xor_bits(state, delta + [0] * 32)
            state = self.cipher.encrypt_block(hex_to_decimal(state),
                                              hex_to_decimal(key))

        # check whether plaintext is not empty, i.e. there is a final block
        # to analyse
        if ciphertext != [[]]:
            # L ← 3 · L
            delta = self.triple(delta)

            # check whether last block of plaintext is not full
            if len(ciphertext[-1]) != 32:
                # L ← 3 · L if last plaintext block not full
                delta = self.triple(delta)

                # xor the last block with the current state
                last_plaintext_block = xor_bits(ciphertext[-1], state)
                plaintext_blocks.append(last_plaintext_block)

                # apply padding to the final block
                last_plaintext_block = apply_padding(last_plaintext_block[:],
                                                     128)
            else:
                last_plaintext_block = xor_bits(ciphertext[-1], state)
                plaintext_blocks.append(last_plaintext_block)

            # apply ρ(Y, M) = (ρ1(Y, M), Y ⊕ M)
            state = self.pho1(state, last_plaintext_block)

            # xor state with padded delta and encrypt state
            state = xor_bits(state, delta + [0] * 32)
            state = self.cipher.encrypt_block(hex_to_decimal(state),
                                              hex_to_decimal(key))

        # tag becomes the current value of state
        tag = state

        # verify whether the generated tag matches the tag to verify
        if tag == tag_to_verify:
            # if tag matches, return the plaintext
            return plaintext_blocks
        else:
            return [-1]

    def pho1(self, Y, M):
        """
        Method to apply ρ1 function.
        ρ1(Y, M) = G· Y ⊕ M
        Parameters: Y and M
        Returns: ρ1(Y, M)
        """
        
        return xor_bits(self.G(Y), M)

    def pho(self, Y, M):
        """
        Method to apply the ρ function.
        ρ(Y, M) = (ρ1(Y, M), Y ⊕ M)
        Parameters: Y and M
        Returns: ρ(Y, M)
        """

        return self.pho1(Y, M), xor_bits(Y, M)

    def phoprime(self, Y, C):
        """
        Method to apply the ρ function.
        ρ(Y, M) = (ρ1(Y, M), Y ⊕ M)
        Parameters: Y and M
        Returns: ρ(Y, M)
        """
        temp = xor_bits(Y, C)

        return self.pho1(Y, temp), temp

    def double(self, delta):
        """
        Method to apply L ← 2 · L
        Parameters: L
        Returns: L ← 2 · L
        """

        # convert delta to bits and define new delta list
        delta_bits = convert_to_bits(delta)
        delta_bits_double = [0] * 64

        # apply left shift by 1 bit
        for i in range(1, 64):
            delta_bits_double[i - 1] = delta_bits[i]
        delta_bits_double[63] = 0

        # if a63 = 1 apply constant x^64 + x^4 + x^3 + x + 1
        if delta_bits[0] != 0:
            constant = [0] * 59 + [1, 1, 0, 1, 1]
            delta_bits_double = xor_bits(delta_bits_double, constant)

        # return new delta in hex representation
        return convert_from_bits(delta_bits_double, 64)

    def triple(self, delta):
        """
        Method to apply L ← 3 · L
        Parameters: L
        Returns: L ← 3 · L
        """

        triple = self.double(delta[:])

        return xor_bits(triple, delta)

    def G(self, Y):
        """
        Method to apply G, where G(Y) = (Y [2], Y [1] ≪ 1)
        Parameters: Y, the string (in list format) we are to apply G to
        Returns: the result of G(Y).
        """

        # first define Y1 and Y2 as each half of Y respectively
        length = len(Y)
        Y1 = Y[0:length // 2]
        Y2 = Y[length // 2:]

        # apply left rotation by 1 to Y1
    
        Y1_bits = convert_to_bits(Y1)
        
        Y1_bits_shifted = [0] * 64

        # shift the bits by 1 to the left
        for i in range(1, 64):
            Y1_bits_shifted[i - 1] = Y1_bits[i]

        Y1_bits_shifted[63] = Y1_bits[0]

        # convert Y1 back to hex
        Y1 = convert_from_bits(Y1_bits_shifted, 64)

        # return the concatenation of Y2 + Y1
        return Y2 + Y1

if __name__ == "__main__":
    gift_cofb = GiftCofb()

    # Parameters (Ensure 128-bit by padding zeros to the right)
    key_hex = "0123456789ABCDEF0123456789ABCDEF"  # 128-bit key as hex
    nonce_hex = "AABB0011AABB0011AABB0011AABB0011"  # Original nonce (64 bits)
    ad_hex = "61626364616263646162636461626364"  # Original associated data (32 bits)
    pt_hex = "61626364616263646162636461626364"  # Original plaintext (40 bits)

     # Debug prints
    print(f"Input lengths (bits):")
    print(f"Key: {len(key_hex)*4}")
    print(f"Nonce: {len(nonce_hex)*4}")
    print(f"AD: {len(ad_hex)*4}")
    print(f"PT: {len(pt_hex)*4}")
    # Debug prints
    print("GIFT light-weight cipher")
    print(f"Plaintext: {bytes.fromhex(pt_hex).decode('utf-8').rstrip(chr(0))}")
    print(f"Key: {key_hex}")
    print(f"Nonce: {nonce_hex}")
    print(f"Additional Information: {bytes.fromhex(ad_hex).decode('utf-8').rstrip(chr(0))}")

    # Convert the hex strings to list of integers (nibbles)
    key_list = string_to_list(key_hex)
    nonce_list = string_to_list(nonce_hex)
    ad_list = string_to_list(ad_hex)
    pt_list = string_to_list(pt_hex)

    # Encrypt
    ciphertext, tag = gift_cofb.encrypt([pt_list], key_list, [ad_list], nonce_list)
    cipher_str = list_to_string(ciphertext)
    print(f"\nCiphertext: {cipher_str}, Len: {len(cipher_str)}")

    # Decrypt and verify
    decrypted = gift_cofb.verify(ciphertext, key_list, [ad_list], nonce_list, tag)
    if decrypted != [-1]:
        decrypted_str = bytes.fromhex(list_to_string(decrypted)).decode('utf-8').rstrip(chr(0))
        print(f"Plaintext: {decrypted_str}, Len: {len(decrypted_str)}")
        print("Success!")
    else:
        print("Decryption failed or authentication error.")
    
