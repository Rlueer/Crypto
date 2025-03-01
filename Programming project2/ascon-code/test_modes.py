#!/usr/bin/env python3

from ascon_modes import AsconModes
from ascon import get_random_bytes, bytes_to_hex
import sys

def print_hex_blocks(data, block_size=16):
    """Print data in hexadecimal blocks for debugging"""
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        print(f"Block {i//block_size}: {bytes_to_hex(block)}")

def test_encryption_mode(mode_name, encrypt_func, decrypt_func):
    """Test an encryption mode with detailed debugging output"""
    print(f"\n=== Testing {mode_name} Mode ===")
    
    try:
        # Generate test data
        key = get_random_bytes(16)
        iv = get_random_bytes(16)
        plaintext = b"This is a test message for Ascon encryption modes!"
        
        print(f"Test Parameters:")
        print(f"Key (hex): {bytes_to_hex(key)}")
        print(f"IV (hex): {bytes_to_hex(iv)}")
        print(f"Original plaintext: {plaintext.decode('utf-8')}")
        print(f"Plaintext length: {len(plaintext)} bytes")
        
        # Encryption
        print("\nEncryption Phase:")
        ciphertext = encrypt_func(key, iv, plaintext)
        print("Ciphertext blocks:")
        print_hex_blocks(ciphertext)
        print(f"Total ciphertext length: {len(ciphertext)} bytes")
        
        # Decryption
        print("\nDecryption Phase:")
        decrypted = decrypt_func(key, iv, ciphertext)
        print(f"Decrypted text: {decrypted.decode('utf-8')}")
        print(f"Decrypted length: {len(decrypted)} bytes")
        
        # Verification
        if decrypted == plaintext:
            print(f"\n{mode_name} test PASSED ✓")
            return True
        else:
            print(f"\n{mode_name} test FAILED ✗")
            print("\nDebug Information:")
            print("Original:", plaintext)
            print("Decrypted:", decrypted)
            return False
            
    except Exception as e:
        print(f"\n{mode_name} test FAILED ✗")
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def main():
    test_modes = [
        ("CBC", AsconModes.cbc_encrypt, AsconModes.cbc_decrypt),
        ("OFB", AsconModes.ofb_encrypt, AsconModes.ofb_decrypt)
    ]
    
    results = []
    for mode_name, encrypt_func, decrypt_func in test_modes:
        results.append((mode_name, test_encryption_mode(mode_name, encrypt_func, decrypt_func)))
    
    print("\n=== Final Test Summary ===")
    all_passed = True
    for mode_name, passed in results:
        status = "PASSED ✓" if passed else "FAILED ✗"
        print(f"{mode_name}: {status}")
        all_passed = all_passed and passed
    
    sys.exit(0 if all_passed else 1)

if __name__ == "__main__":
    main()