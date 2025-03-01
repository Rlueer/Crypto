import os
from datetime import datetime
import struct
from ascon import ascon_hash, ascon_encrypt, ascon_decrypt, get_random_bytes

class SignatureError(Exception):
    """Custom exception for signature-related errors"""
    pass

def create_document_signature(filepath, author_key, author_id):
    """
    Creates and appends a digital signature to a document
    
    Args:
        filepath: Path to the document to sign
        author_key: 16-byte key known only to the author (must be exactly 16 bytes)
        author_id: String identifying the author
    
    Returns:
        Tuple of (signature_bytes, signature_length)
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Document not found: {filepath}")
    
    if len(author_key) != 16:
        raise ValueError("Author key must be exactly 16 bytes")
        
    try:
        # Read the document content
        with open(filepath, 'rb') as f:
            document_content = f.read()
        
        # Create metadata
        timestamp = datetime.now().isoformat().encode('utf-8')
        author_id_bytes = author_id.encode('utf-8')
        
        # Create metadata block with length prefixes
        metadata = struct.pack('<H', len(timestamp)) + timestamp + \
                  struct.pack('<H', len(author_id_bytes)) + author_id_bytes
        
        # Generate document hash
        doc_hash = ascon_hash(document_content)
        
        # Combine metadata and hash
        signature_data = metadata + doc_hash
        
        # Generate nonce for encryption
        nonce = get_random_bytes(16)
        
        # Encrypt the signature block
        encrypted_signature = ascon_encrypt(
            key=author_key,
            nonce=nonce,
            associateddata=b"",
            plaintext=signature_data
        )
        
        # Create final signature block with magic number
        MAGIC = b"ASCON_SIG"
        final_signature = MAGIC + \
                         struct.pack('<Q', len(encrypted_signature)) + \
                         nonce + \
                         encrypted_signature
        
        # Append to document
        with open(filepath, 'ab') as f:
            f.write(final_signature)
        
        return final_signature, len(final_signature)
        
    except Exception as e:
        raise SignatureError(f"Failed to create signature: {str(e)}")

def verify_document_signature(filepath, author_key):
    """
    Verifies the integrity and authorship of a signed document
    
    Args:
        filepath: Path to the signed document
        author_key: 16-byte key of the purported author
    
    Returns:
        Tuple of (is_valid, author_id, timestamp) if verification succeeds
        Raises SignatureError if verification fails
    """
    MAGIC = b"ASCON_SIG"
    MIN_SIG_SIZE = len(MAGIC) + 8 + 16  # Magic + size + nonce
    
    try:
        with open(filepath, 'rb') as f:
            # Read the entire file
            content = f.read()
            
            if len(content) < MIN_SIG_SIZE:
                raise SignatureError("File too small to contain a valid signature")
            
            # Look for magic number from the end
            sig_start = content.rfind(MAGIC)
            if sig_start == -1:
                raise SignatureError("No valid signature found")
            
            # Extract signature components
            pos = sig_start + len(MAGIC)
            sig_len = struct.unpack('<Q', content[pos:pos+8])[0]
            pos += 8
            
            nonce = content[pos:pos+16]
            pos += 16
            
            encrypted_signature = content[pos:pos+sig_len]
            
            # Extract original document content
            document_content = content[:sig_start]
            
            # Decrypt signature
            signature_block = ascon_decrypt(
                key=author_key,
                nonce=nonce,
                associateddata=b"",
                ciphertext=encrypted_signature
            )
            
            if signature_block is None:
                raise SignatureError("Signature decryption failed")
            
            # Parse metadata
            pos = 0
            timestamp_len = struct.unpack('<H', signature_block[pos:pos+2])[0]
            pos += 2
            timestamp = signature_block[pos:pos+timestamp_len].decode('utf-8')
            pos += timestamp_len
            
            author_id_len = struct.unpack('<H', signature_block[pos:pos+2])[0]
            pos += 2
            author_id = signature_block[pos:pos+author_id_len].decode('utf-8')
            pos += author_id_len
            
            stored_hash = signature_block[pos:pos+32]
            
            # Verify document hash
            current_hash = ascon_hash(document_content)
            
            if current_hash != stored_hash:
                raise SignatureError("Document content has been modified")
            
            return True, author_id, timestamp
            
    except SignatureError:
        raise
    except Exception as e:
        raise SignatureError(f"Verification failed: {str(e)}")

def demo_document_integrity():
    """
    Demonstrates the document integrity and authorship verification system
    """
    try:
        # Create test document
        test_file = 'test_document.txt'
        with open(test_file, 'wb') as f:
            f.write(b"This is a test document content.")
        print("Test document created.")
        
        # Generate author key
        author_key = get_random_bytes(16)
        author_id = "john.doe@example.com"
        
        print("Signing the document...")
        signature, sig_len = create_document_signature(test_file, author_key, author_id)
        print("Document signed successfully.")
        
        print("Verifying the document...")
        result = verify_document_signature(test_file, author_key)
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
            verify_document_signature(test_file, author_key)
            print("ERROR: Tampering not detected!")
        except SignatureError as e:
            print(f"Successfully detected tampering: {str(e)}")
            
    except Exception as e:
        print(f"Error during demo: {str(e)}")
    finally:
        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)

if __name__ == "__main__":
    demo_document_integrity()