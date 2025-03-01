import os
import tempfile
import unittest
from datetime import datetime
from changes import create_document_signature, verify_document_signature, SignatureError

class TestAsconDocumentIntegrity(unittest.TestCase):
    def setUp(self):
        """Set up test environment before each test"""
        self.test_dir = tempfile.mkdtemp()
        self.author_key = os.urandom(16)  # Generate 16-byte key for Ascon
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
        print("\nTesting basic document integrity...")
        original_content = b"This is a test document for basic integrity verification."
        filepath = self.create_test_file(original_content, "basic_test.doc")
        
        print("Signing document...")
        signature, sig_len = create_document_signature(
            filepath, 
            self.author_key, 
            self.author_id
        )
        
        print("Verifying signature...")
        is_valid, author, timestamp = verify_document_signature(
            filepath,
            self.author_key
        )
        
        self.assertTrue(is_valid)
        self.assertEqual(author, self.author_id)
        self.assertIsInstance(datetime.fromisoformat(timestamp), datetime)
        print("Basic integrity check passed")

    def test_tampered_content(self):
        """Test detection of document tampering"""
        print("\nTesting tamper detection...")
        original_content = b"Original content that should not be modified."
        filepath = self.create_test_file(original_content, "tamper_test.doc")
        
        create_document_signature(filepath, self.author_key, self.author_id)
        
        print("Modifying document...")
        with open(filepath, 'r+b') as f:
            f.seek(5)
            f.write(b"modified")
        
        print("Verifying modified document...")
        with self.assertRaises(SignatureError):
            verify_document_signature(filepath, self.author_key)
        print("Tamper detection successful")

    def test_large_file_integrity(self):
        """Test integrity verification with larger files"""
        print("\nTesting large file integrity...")
        # Create a moderate-sized document (100KB)
        chunk_size = 1024 * 100  # 100KB
        large_content = os.urandom(chunk_size)
        filepath = self.create_test_file(large_content, "large_test.doc")
        
        try:
            print(f"Testing file size: {chunk_size/1024:.0f}KB")
            
            print("Signing large document...")
            signature, sig_len = create_document_signature(
                filepath,
                self.author_key,
                self.author_id
            )
            
            print("Verifying large document...")
            is_valid, author, timestamp = verify_document_signature(
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
        print("\nTesting empty file handling...")
        filepath = self.create_test_file(b"", "empty_test.doc")
        
        signature, sig_len = create_document_signature(
            filepath,
            self.author_key,
            self.author_id
        )
        
        is_valid, author, timestamp = verify_document_signature(
            filepath,
            self.author_key
        )
        
        self.assertTrue(is_valid)
        self.assertEqual(author, self.author_id)
        print("Empty file test successful")

    def test_invalid_key(self):
        """Test verification with incorrect key"""
        print("\nTesting invalid key detection...")
        content = b"Test content for key verification."
        filepath = self.create_test_file(content, "key_test.doc")
        
        create_document_signature(filepath, self.author_key, self.author_id)
        
        wrong_key = os.urandom(16)  # Generate different key
        
        with self.assertRaises(SignatureError):
            verify_document_signature(filepath, wrong_key)
        print("Invalid key detection successful")

    def test_multiple_signatures(self):
        """Test handling of multiple signatures on the same document"""
        print("\nTesting multiple signatures...")
        content = b"Test content for multiple signatures."
        filepath = self.create_test_file(content, "multiple_sig_test.doc")
        
        # Sign first time
        create_document_signature(
            filepath,
            self.author_key,
            self.author_id
        )
        
        # Sign second time with different author
        second_author = "second.author@organization.com"
        create_document_signature(
            filepath,
            self.author_key,
            second_author
        )
        
        # Verification should return most recent signature
        is_valid, author, timestamp = verify_document_signature(
            filepath,
            self.author_key
        )
        
        self.assertTrue(is_valid)
        self.assertEqual(author, second_author)
        print("Multiple signatures test successful")

    def test_binary_file_integrity(self):
        """Test integrity verification with binary file content"""
        print("\nTesting binary file integrity...")
        binary_content = bytes([i % 256 for i in range(1000)])
        filepath = self.create_test_file(binary_content, "binary_test.bin")
        
        signature, sig_len = create_document_signature(
            filepath,
            self.author_key,
            self.author_id
        )
        
        is_valid, author, timestamp = verify_document_signature(
            filepath,
            self.author_key
        )
        
        self.assertTrue(is_valid)
        self.assertEqual(author, self.author_id)
        print("Binary file test successful")

def run_ascon_integrity_tests():
    """Run the Ascon integrity test suite and print results"""
    print("Starting Ascon Document Integrity Test Suite")
    print("-" * 50)
    
    # Create test suite
    suite = unittest.TestLoader().loadTestsFromTestCase(TestAsconDocumentIntegrity)
    
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
    success = run_ascon_integrity_tests()
    exit(0 if success else 1)