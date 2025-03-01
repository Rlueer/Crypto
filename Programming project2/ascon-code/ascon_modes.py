#!/usr/bin/env python3

import importlib.util
import sys

# Dynamically import the original Ascon implementation
spec = importlib.util.spec_from_file_location("ascon", "ascon.py")
ascon_module = importlib.util.module_from_spec(spec)
sys.modules["ascon"] = ascon_module
spec.loader.exec_module(ascon_module)

from ascon import get_random_bytes, zero_bytes, bytes_to_hex

class AsconModes:
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

    @staticmethod
    def cbc_encrypt(key, iv, plaintext):
        """Encrypt using Ascon in CBC mode"""
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes")
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes")

        block_size = 16
        padded_plaintext = AsconModes.pad_data(plaintext, block_size)
        ciphertext = b''
        previous_block = iv

        for i in range(0, len(padded_plaintext), block_size):
            block = padded_plaintext[i:i + block_size]
            # XOR with previous ciphertext block or IV
            xored = bytes(a ^ b for a, b in zip(block, previous_block))
            # Encrypt block using Ascon
            encrypted = ascon_module.ascon_encrypt(key, previous_block, b'', xored)[:block_size]
            ciphertext += encrypted
            previous_block = encrypted

        return ciphertext

    @staticmethod
    def cbc_decrypt(key, iv, ciphertext):
        """Decrypt using Ascon in CBC mode"""
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
            # Use Ascon to generate keystream
            keystream = ascon_module.ascon_encrypt(key, previous_block, b'', zero_bytes(block_size))[:block_size]
            # XOR keystream with current block
            decrypted = bytes(a ^ b for a, b in zip(current_block, keystream))
            # XOR with previous block or IV
            plaintext_block = bytes(a ^ b for a, b in zip(decrypted, previous_block))
            plaintext += plaintext_block
            previous_block = current_block

        # Remove padding
        return AsconModes.unpad_data(plaintext)

    @staticmethod
    def ofb_encrypt(key, iv, plaintext):
        """Encrypt using Ascon in OFB mode"""
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes")
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes")

        block_size = 16
        padded_plaintext = AsconModes.pad_data(plaintext, block_size)
        ciphertext = b''
        previous_block = iv

        for i in range(0, len(padded_plaintext), block_size):
            # Generate keystream using Ascon
            keystream = ascon_module.ascon_encrypt(key, previous_block, b'', zero_bytes(block_size))[:block_size]
            # XOR with plaintext block
            block = padded_plaintext[i:i + block_size]
            encrypted_block = bytes(a ^ b for a, b in zip(block, keystream))
            ciphertext += encrypted_block
            previous_block = keystream

        return ciphertext

    @staticmethod
    def ofb_decrypt(key, iv, ciphertext):
        """Decrypt using Ascon in OFB mode"""
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
            # Generate keystream using Ascon
            keystream = ascon_module.ascon_encrypt(key, previous_block, b'', zero_bytes(block_size))[:block_size]
            # XOR with ciphertext block
            block = ciphertext[i:i + block_size]
            decrypted_block = bytes(a ^ b for a, b in zip(block, keystream))
            plaintext += decrypted_block
            previous_block = keystream

        # Remove padding
        return AsconModes.unpad_data(plaintext)