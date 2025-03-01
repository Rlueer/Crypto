import os
import tempfile
import unittest
from datetime import datetime
from changes import create_gift_document_signature, verify_gift_document_signature, GiftSignatureError

class TestGiftDocumentIntegrity(unittest.TestCase):
    def setUp(self):
        """Set up test environment before each test"""
        self.test_dir = tempfile.mkdtemp()
        self.author_key = "0123456789ABCDEF0123456789ABCDEF"
        self.author_id = "test.author@organization.com"

    def tearDown(self):
        """Clean up test environment after each test"""
        for file in os.listdir(self.test_dir):
            os.remove(os.path.join(self.test_dir, file))
        os.rmdir(self.test_dir)

    def create_test_file(self, content, filename):
        """Helper method to create a test file with given content"""
        filepath = os.path.join(self.test_dir, filename)
        with open(filepath, 'wb') as f:
            f.write(content)
        return filepath

    def test_basic_integrity_check(self):
        """Test basic document signing and verification"""
        # Create and sign a document
        original_content = b"This is a test document for basic integrity verification."
        filepath = self.create_test_file(original_content, "basic_test.doc")
        
        signature, sig_len = create_gift_document_signature(
            filepath, 
            self.author_key, 
            self.author_id
        )
        
        # Verify the signature
        is_valid, author, timestamp = verify_gift_document_signature(
            filepath,
            self.author_key
        )
        
        self.assertTrue(is_valid)
        self.assertEqual(author, self.author_id)
        self.assertIsInstance(datetime.fromisoformat(timestamp), datetime)

    def test_tampered_content(self):
        """Test detection of document tampering"""
        # Create and sign original document
        original_content = b"Original content that should not be modified."
        filepath = self.create_test_file(original_content, "tamper_test.doc")
        
        create_gift_document_signature(filepath, self.author_key, self.author_id)
        
        # Modify the document
        with open(filepath, 'r+b') as f:
            f.seek(5)
            f.write(b"modified")
        
        # Verify should fail
        with self.assertRaises(GiftSignatureError):
            verify_gift_document_signature(filepath, self.author_key)

    def test_large_file_integrity(self):
        """Test integrity verification with larger files"""
        # Create a moderate-sized document (100KB instead of 1MB)
        chunk_size = 1024 * 100  # 100KB
        large_content = os.urandom(chunk_size)
        filepath = self.create_test_file(large_content, "large_test.doc")
        
        try:
            print(f"\nTesting large file ({chunk_size/1024:.0f}KB)...")
            
            print("Signing document...")
            signature, sig_len = create_gift_document_signature(
                filepath,
                self.author_key,
                self.author_id
            )
            
            print("Verifying signature...")
            is_valid, author, timestamp = verify_gift_document_signature(
                filepath,
                self.author_key
            )
            
            self.assertTrue(is_valid)
            self.assertEqual(author, self.author_id)
            print("Large file verification successful")
            
        except Exception as e:
            self.fail(f"Large file test failed with error: {str(e)}")

    def test_empty_file(self):
        """Test handling of empty files"""
        filepath = self.create_test_file(b"", "empty_test.doc")
        
        signature, sig_len = create_gift_document_signature(
            filepath,
            self.author_key,
            self.author_id
        )
        
        # Verify the signature
        is_valid, author, timestamp = verify_gift_document_signature(
            filepath,
            self.author_key
        )
        
        self.assertTrue(is_valid)
        self.assertEqual(author, self.author_id)

    def test_invalid_key(self):
        """Test verification with incorrect key"""
        # Create and sign with original key
        content = b"Test content for key verification."
        filepath = self.create_test_file(content, "key_test.doc")
        
        create_gift_document_signature(filepath, self.author_key, self.author_id)
        
        # Try to verify with different key
        wrong_key = "FEDCBA9876543210FEDCBA9876543210"
        
        with self.assertRaises(GiftSignatureError):
            verify_gift_document_signature(filepath, wrong_key)

    def test_multiple_signatures(self):
        """Test handling of multiple signatures on the same document"""
        content = b"Test content for multiple signatures."
        filepath = self.create_test_file(content, "multiple_sig_test.doc")
        
        # Sign first time
        create_gift_document_signature(
            filepath,
            self.author_key,
            self.author_id
        )
        
        # Sign second time with different author
        second_author = "second.author@organization.com"
        create_gift_document_signature(
            filepath,
            self.author_key,
            second_author
        )
        
        # Verification should return most recent signature
        is_valid, author, timestamp = verify_gift_document_signature(
            filepath,
            self.author_key
        )
        
        self.assertTrue(is_valid)
        self.assertEqual(author, second_author)

    def test_binary_file_integrity(self):
        """Test integrity verification with binary file content"""
        # Create binary content
        binary_content = bytes([i % 256 for i in range(1000)])
        filepath = self.create_test_file(binary_content, "binary_test.bin")
        
        signature, sig_len = create_gift_document_signature(
            filepath,
            self.author_key,
            self.author_id
        )
        
        # Verify the signature
        is_valid, author, timestamp = verify_gift_document_signature(
            filepath,
            self.author_key
        )
        
        self.assertTrue(is_valid)
        self.assertEqual(author, self.author_id)

def run_integrity_tests():
    """Run the test suite and print results"""
    print("Starting GIFT-COFB Document Integrity Test Suite")
    print("-" * 50)
    
    # Create test suite
    suite = unittest.TestLoader().loadTestsFromTestCase(TestGiftDocumentIntegrity)
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\nTest Summary:")
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    return result.wasSuccessful()

if __name__ == '__main__':
    success = run_integrity_tests()
    exit(0 if success else 1)