import os
from datetime import datetime
import struct
from gift_cofb import GiftCofb, string_to_list, list_to_string

class GiftSignatureError(Exception):
    """Custom exception for GIFT-COFB signature-related errors"""
    pass

def create_gift_document_signature(filepath, author_key_hex, author_id):
    """
    Creates and appends a digital signature to a document using GIFT-COFB
    
    Args:
        filepath: Path to the document to sign
        author_key_hex: 32-character hex string (16 bytes) known only to the author
        author_id: String identifying the author
    
    Returns:
        Tuple of (signature_bytes, signature_length)
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Document not found: {filepath}")
    
    if len(author_key_hex) != 32:
        raise ValueError("Author key must be exactly 32 hex characters (16 bytes)")
        
    try:
        # Initialize GIFT-COFB
        gift_cofb = GiftCofb()
        
        # Read the document content
        with open(filepath, 'rb') as f:
            document_content = f.read()
        
        # Create metadata
        timestamp = datetime.now().isoformat().encode('utf-8')
        author_id_bytes = author_id.encode('utf-8')
        
        # Create metadata block with length prefixes
        metadata = struct.pack('<H', len(timestamp)) + timestamp + \
                  struct.pack('<H', len(author_id_bytes)) + author_id_bytes
        
        # Convert document content to hex string for GIFT-COFB input
        doc_hex = document_content.hex()
        doc_blocks = [string_to_list(doc_hex[i:i+32]) for i in range(0, len(doc_hex), 32)]
        if not doc_blocks:
            doc_blocks = [[]]
            
        # Convert metadata to hex
        metadata_hex = metadata.hex()
        metadata_blocks = [string_to_list(metadata_hex[i:i+32]) for i in range(0, len(metadata_hex), 32)]
        if not metadata_blocks:
            metadata_blocks = [[]]
            
        # Convert key from hex string to list format
        key_list = string_to_list(author_key_hex)
        
        # Generate nonce (use first 32 chars of document content hash as nonce)
        nonce_hex = doc_hex[:32].ljust(32, '0')
        nonce_list = string_to_list(nonce_hex)
        
        # Encrypt metadata using GIFT-COFB
        encrypted_blocks, tag = gift_cofb.encrypt(
            metadata_blocks,
            key_list,
            doc_blocks,  # Use document content as associated data
            nonce_list
        )
        
        # Convert encrypted blocks and tag to bytes
        encrypted_data = bytes.fromhex(list_to_string(encrypted_blocks))
        tag_bytes = bytes.fromhex(list_to_string([tag]))
        
        # Create final signature block with magic number
        MAGIC = b"GIFT_SIG"
        final_signature = MAGIC + \
                         struct.pack('<Q', len(encrypted_data)) + \
                         bytes.fromhex(nonce_hex) + \
                         encrypted_data + \
                         tag_bytes
        
        # Append to document
        with open(filepath, 'ab') as f:
            f.write(final_signature)
        
        return final_signature, len(final_signature)
        
    except Exception as e:
        raise GiftSignatureError(f"Failed to create signature: {str(e)}")

def verify_gift_document_signature(filepath, author_key_hex):
    """
    Verifies the integrity and authorship of a signed document using GIFT-COFB
    
    Args:
        filepath: Path to the signed document
        author_key_hex: 32-character hex string (16 bytes) of the purported author
    
    Returns:
        Tuple of (is_valid, author_id, timestamp) if verification succeeds
        Raises GiftSignatureError if verification fails
    """
    MAGIC = b"GIFT_SIG"
    MIN_SIG_SIZE = len(MAGIC) + 8 + 16  # Magic + size + nonce
    
    try:
        # Initialize GIFT-COFB
        gift_cofb = GiftCofb()
        
        with open(filepath, 'rb') as f:
            # Read the entire file
            content = f.read()
            
            if len(content) < MIN_SIG_SIZE:
                raise GiftSignatureError("File too small to contain a valid signature")
            
            # Look for magic number from the end
            sig_start = content.rfind(MAGIC)
            if sig_start == -1:
                raise GiftSignatureError("No valid signature found")
            
            # Extract signature components
            pos = sig_start + len(MAGIC)
            sig_len = struct.unpack('<Q', content[pos:pos+8])[0]
            pos += 8
            
            nonce = content[pos:pos+16]
            pos += 16
            
            encrypted_data = content[pos:pos+sig_len]
            tag = content[pos+sig_len:pos+sig_len+16]
            
            # Extract original document content
            document_content = content[:sig_start]
            
            # Convert to GIFT-COFB format
            key_list = string_to_list(author_key_hex)
            nonce_list = string_to_list(nonce.hex())
            doc_hex = document_content.hex()
            doc_blocks = [string_to_list(doc_hex[i:i+32]) for i in range(0, len(doc_hex), 32)]
            if not doc_blocks:
                doc_blocks = [[]]
            
            encrypted_hex = encrypted_data.hex()
            encrypted_blocks = [string_to_list(encrypted_hex[i:i+32]) for i in range(0, len(encrypted_hex), 32)]
            if not encrypted_blocks:
                encrypted_blocks = [[]]
            
            # Decrypt and verify using GIFT-COFB
            decrypted_blocks = gift_cofb.verify(
                encrypted_blocks,
                key_list,
                doc_blocks,  # Document content as associated data
                nonce_list,
                string_to_list(tag.hex())
            )
            
            if decrypted_blocks == [-1]:
                raise GiftSignatureError("Signature verification failed")
                
            # Convert decrypted blocks back to bytes
            decrypted_data = bytes.fromhex(list_to_string(decrypted_blocks))
            
            # Parse metadata
            pos = 0
            timestamp_len = struct.unpack('<H', decrypted_data[pos:pos+2])[0]
            pos += 2
            timestamp = decrypted_data[pos:pos+timestamp_len].decode('utf-8')
            pos += timestamp_len
            
            author_id_len = struct.unpack('<H', decrypted_data[pos:pos+2])[0]
            pos += 2
            author_id = decrypted_data[pos:pos+author_id_len].decode('utf-8')
            
            return True, author_id, timestamp
            
    except GiftSignatureError:
        raise
    except Exception as e:
        raise GiftSignatureError(f"Verification failed: {str(e)}")

def demo_gift_document_integrity():
    """
    Demonstrates the document integrity and authorship verification system using GIFT-COFB
    """
    try:
        # Create test document
        test_file = 'test_document.txt'
        with open(test_file, 'wb') as f:
            f.write(b"This is a test document content.")
        print("Test document created.")
        
        # Generate author key (32 hex characters = 16 bytes)
        author_key = "0123456789ABCDEF0123456789ABCDEF"
        author_id = "john.doe@example.com"
        
        print("Signing the document...")
        signature, sig_len = create_gift_document_signature(test_file, author_key, author_id)
        print("Document signed successfully.")
        
        print("Verifying the document...")
        result = verify_gift_document_signature(test_file, author_key)
        is_valid, verified_author, timestamp = result
        print(f"Verification successful:")
        print(f"Author: {verified_author}")
        print(f"Timestamp: {timestamp}")
        
        # Test tampering detection
        print("\nModifying document to test tampering detection...")
        with open(test_file, 'r+b') as f:
            f.seek(5)
            f.write(b"was")
        
        try:
            verify_gift_document_signature(test_file, author_key)
            print("ERROR: Tampering not detected!")
        except GiftSignatureError as e:
            print(f"Successfully detected tampering: {str(e)}")
            
    except Exception as e:
        print(f"Error during demo: {str(e)}")
    finally:
        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)

if __name__ == "__main__":
    demo_gift_document_integrity()