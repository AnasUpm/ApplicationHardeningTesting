import unittest
import hashlib
import random
import string
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

class ApplicationHardeningTests(unittest.TestCase):

    def setUp(self):
        # Setup mock data and configurations
        self.sample_code = "def example_function(): return 'Hello, World!'"
        self.original_hash = hashlib.sha256(self.sample_code.encode()).hexdigest()
        
        # RSA keys for testing code integrity
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

        # Generate signature for original code
        self.original_signature = self.sign_code(self.sample_code)
    
    def obfuscate_code(self, code):
        # Mock obfuscation by reversing the string and adding a simple transformation
        obfuscated_code = ''.join(chr(ord(char) + 2) for char in code[::-1])
        return obfuscated_code

    def deobfuscate_code(self, code):
        # Reverse the obfuscation
        deobfuscated_code = ''.join(chr(ord(char) - 2) for char in code)[::-1]
        return deobfuscated_code

    def sign_code(self, code):
        # Sign the hash of the given code
        code_hash = hashlib.sha256(code.encode()).digest()
        signature = self.private_key.sign(
            code_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(f"\n[Signing Code]")
        print(f"Code Hash for Signing: {code_hash.hex()}")
        print(f"Signature: {signature.hex()}")
        return signature
    
    def verify_code_signature(self, code, signature):
        # Verify the signature of the given code
        code_hash = hashlib.sha256(code.encode()).digest()
        print(f"\n[Verifying Code]")
        print(f"Code Hash for Verification: {code_hash.hex()}")
        try:
            self.public_key.verify(
                signature,
                code_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Verification: Succeeded")
            return True
        except Exception as e:
            print(f"Verification: Failed ({e})")
            return False

    def generate_random_string(self, length):
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
    
    def test_obfuscation(self):
        print("\n[Test: Obfuscation]")
        obfuscated_code = self.obfuscate_code(self.sample_code)
        deobfuscated_code = self.deobfuscate_code(obfuscated_code)
        self.assertNotEqual(obfuscated_code, self.sample_code, "Code should be obfuscated")
        self.assertEqual(deobfuscated_code, self.sample_code, "Deobfuscated code should match the original code")
    
    def test_anti_tamper(self):
        print("\n[Test: Anti-Tamper]")
        tampered_code = self.sample_code + " tampered"
        tampered_hash = hashlib.sha256(tampered_code.encode()).hexdigest()
        self.assertNotEqual(tampered_hash, self.original_hash, "Tampered code hash should not match original hash")
        self.assertFalse(self.verify_code_signature(tampered_code, self.original_signature), "Code integrity check should fail for tampered code")

    def test_code_integrity(self):
        print("\n[Test: Code Integrity]")
        self.assertTrue(self.verify_code_signature(self.sample_code, self.original_signature), "Code integrity check should pass for original code")
        
        tampered_code = self.sample_code + " tampered"
        self.assertFalse(self.verify_code_signature(tampered_code, self.original_signature), "Code integrity check should fail for tampered code")

    def test_runtime_application_self_protection(self):
        print("\n[Test: Runtime Application Self-Protection (RASP)]")
        def risky_operation(input_string):
            assert len(input_string) < 100, "Input string is too long!"
            return True
        
        self.assertTrue(risky_operation(self.generate_random_string(50)), "RASP should allow safe operations")
        
        with self.assertRaises(AssertionError):
            risky_operation(self.generate_random_string(150))
    
    def test_certificate_pinning(self):
        print("\n[Test: Certificate Pinning]")
        expected_certificate = "expected_certificate_hash"
        def mock_certificate_verification(cert):
            return cert == expected_certificate
        
        actual_certificate = "expected_certificate_hash"
        self.assertTrue(mock_certificate_verification(actual_certificate), "Certificate should match pinned certificate")
        
        invalid_certificate = "invalid_certificate_hash"
        self.assertFalse(mock_certificate_verification(invalid_certificate), "Certificate should not match pinned certificate")

if __name__ == '__main__':
    unittest.main(verbosity=2)
