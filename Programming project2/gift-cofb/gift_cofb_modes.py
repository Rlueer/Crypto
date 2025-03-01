#!/usr/bin/env python3

from gift_cofb import GiftCofb
from utils import hex_to_decimal, decimal_to_hex, string_to_list

class GiftCofbModes:
    def __init__(self):
        self.cipher = GiftCofb()

    @staticmethod
    def pad_data(data, block_size):
        """Apply PKCS7 padding to the data"""
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    @staticmethod
    def unpad_data(padded_data):
        """Remove PKCS7 padding from the data"""
        padding_length = padded_data[-1]
        if padding_length == 0 or padding_length > 16:
            raise ValueError("Invalid padding")
        if padded_data[-padding_length:] != bytes([padding_length] * padding_length):
            raise ValueError("Invalid padding")
        return padded_data[:-padding_length]

    def _process_block(self, key, block):
        """Process a single block using GIFT-COFB"""
        # Convert block to proper format for GIFT-COFB
        block_list = string_to_list(block.hex())
        key_list = string_to_list(key.hex())
        # Use a zero nonce and associated data for block encryption
        nonce = string_to_list("0" * 32)  # 128-bit zero nonce
        empty_ad = []
        
        ciphertext, _ = self.cipher.encrypt([block_list], key_list, [empty_ad], nonce)
        # Convert back to bytes
        return bytes.fromhex(''.join([f"{x:x}" for x in ciphertext[0]]))

    def cbc_encrypt(self, key, iv, plaintext):
        """Encrypt using GIFT-COFB in CBC mode"""
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes")
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes")

        block_size = 16
        padded_plaintext = self.pad_data(plaintext, block_size)
        ciphertext = b''
        previous_block = iv

        for i in range(0, len(padded_plaintext), block_size):
            block = padded_plaintext[i:i + block_size]
            # XOR with previous ciphertext block or IV
            xored = bytes(a ^ b for a, b in zip(block, previous_block))
            # Encrypt block using GIFT-COFB
            encrypted = self._process_block(key, xored)
            ciphertext += encrypted
            previous_block = encrypted

        return ciphertext

    def cbc_decrypt(self, key, iv, ciphertext):
        """Decrypt using GIFT-COFB in CBC mode"""
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes")
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes")
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be multiple of 16")

        block_size = 16
        plaintext = b''
        previous_block = iv

        for i in range(0, len(ciphertext), block_size):
            current_block = ciphertext[i:i + block_size]
            # Decrypt block using GIFT-COFB
            decrypted = self._process_block(key, current_block)
            # XOR with previous block or IV
            plaintext_block = bytes(a ^ b for a, b in zip(decrypted, previous_block))
            plaintext += plaintext_block
            previous_block = current_block

        return self.unpad_data(plaintext)

    def ofb_encrypt(self, key, iv, plaintext):
        """Encrypt using GIFT-COFB in OFB mode"""
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes")
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes")

        block_size = 16
        padded_plaintext = self.pad_data(plaintext, block_size)
        ciphertext = b''
        previous_block = iv

        for i in range(0, len(padded_plaintext), block_size):
            # Generate keystream using GIFT-COFB
            keystream = self._process_block(key, previous_block)
            # XOR with plaintext block
            block = padded_plaintext[i:i + block_size]
            encrypted_block = bytes(a ^ b for a, b in zip(block, keystream))
            ciphertext += encrypted_block
            previous_block = keystream

        return ciphertext

    def ofb_decrypt(self, key, iv, ciphertext):
        """Decrypt using GIFT-COFB in OFB mode"""
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes")
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes")
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be multiple of 16")

        block_size = 16
        plaintext = b''
        previous_block = iv

        for i in range(0, len(ciphertext), block_size):
            # Generate keystream using GIFT-COFB
            keystream = self._process_block(key, previous_block)
            # XOR with ciphertext block
            block = ciphertext[i:i + block_size]
            decrypted_block = bytes(a ^ b for a, b in zip(block, keystream))
            plaintext += decrypted_block
            previous_block = keystream

        return self.unpad_data(plaintext)