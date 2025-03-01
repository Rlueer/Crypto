
from gift_cofb_modes import GiftCofbModes
import os
import sys

def print_hex_blocks(data, block_size=16):
    """Print data in hexadecimal blocks for debugging"""
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        print(f"Block {i//block_size}: {block.hex()}")

def test_encryption_mode(mode_name, encrypt_func, decrypt_func):
    """Test an encryption mode with detailed debugging output"""
    print(f"\n=== Testing {mode_name} Mode ===")
    
    try:
        # Generate test data
        key = os.urandom(16)  # 128-bit key
        iv = os.urandom(16)   # 128-bit IV
        plaintext = b"This is a test message for GIFT-COFB encryption modes!"
        
        print(f"Test Parameters:")
        print(f"Key (hex): {key.hex()}")
        print(f"IV (hex): {iv.hex()}")
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
    gift_modes = GiftCofbModes()
    test_modes = [
        ("CBC", gift_modes.cbc_encrypt, gift_modes.cbc_decrypt),
        ("OFB", gift_modes.ofb_encrypt, gift_modes.ofb_decrypt)
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