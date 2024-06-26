# Application Hardening Tests

This test suite, written using Python's `unittest` framework, is designed to evaluate various application hardening techniques including code obfuscation, anti-tamper mechanisms, code integrity verification, runtime application self-protection (RASP), and certificate pinning. Below is a detailed description of each test.

## Test Descriptions

### 1. **Code Obfuscation**

The `test_obfuscation` method checks the obfuscation and deobfuscation processes of a given code snippet. The code is obfuscated by reversing the string and transforming each character. It is then deobfuscated and compared with the original code to ensure the processes are functioning correctly.

### 2. **Anti-Tamper Mechanism**

The `test_anti_tamper` method tests the application's ability to detect tampered code. A tampered version of the original code is created, hashed, and its signature is verified. The test ensures that the tampered code does not match the original hash and fails the integrity check.

### 3. **Code Integrity Verification**

The `test_code_integrity` method verifies the integrity of the code by signing the original code and validating the signature. The test confirms that the original code passes the integrity check, while a tampered code fails.

### 4. **Runtime Application Self-Protection (RASP)**

The `test_runtime_application_self_protection` method tests a mock RASP mechanism by asserting the length of an input string. Safe operations are allowed, while operations with excessively long input strings trigger an assertion error, simulating a protection mechanism.

### 5. **Certificate Pinning**

The `test_certificate_pinning` method simulates certificate pinning by comparing an actual certificate with an expected certificate hash. The test ensures that only the pinned certificate is accepted, while any mismatched certificate is rejected.

## How to Run the Tests

To run the test suite, execute the following command in your terminal:

```bash
python -m unittest <filename>.py
```

Replace `<filename>` with the name of the file containing the test suite. Ensure you have the necessary dependencies installed, including `unittest`, `hashlib`, `random`, `string`, and `cryptography`.

# Description of Functions in Application Hardening Tests

This test suite is designed to evaluate various application hardening techniques such as code obfuscation, anti-tamper mechanisms, code integrity verification, runtime application self-protection (RASP), and certificate pinning. Below is a detailed description of each function in the code.

## Functions

### 1. **setUp**

```python
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
```

- **Purpose**: Initializes test setup by generating a sample code snippet, computing its hash, and creating RSA keys for signing the code.
- **Operations**:
  - Sets up `sample_code` and its SHA-256 hash.
  - Generates RSA private and public keys.
  - Signs the original code to create `original_signature`.

### 2. **obfuscate_code**

```python
def obfuscate_code(self, code):
    obfuscated_code = ''.join(chr(ord(char) + 2) for char in code[::-1])
    return obfuscated_code
```

- **Purpose**: Mock obfuscation of the code by reversing the string and applying a simple character transformation.
- **Parameters**: `code` (str): The code to be obfuscated.
- **Returns**: `obfuscated_code` (str): The obfuscated version of the code.

### 3. **deobfuscate_code**

```python
def deobfuscate_code(self, code):
    deobfuscated_code = ''.join(chr(ord(char) - 2) for char in code)[::-1]
    return deobfuscated_code
```

- **Purpose**: Reverses the obfuscation applied by `obfuscate_code`.
- **Parameters**: `code` (str): The obfuscated code.
- **Returns**: `deobfuscated_code` (str): The deobfuscated (original) version of the code.

### 4. **sign_code**

```python
def sign_code(self, code):
    code_hash = hashlib.sha256(code.encode()).digest()
    signature = self.private_key.sign(
        code_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature
```

- **Purpose**: Signs the hash of the given code using the RSA private key.
- **Parameters**: `code` (str): The code to be signed.
- **Returns**: `signature` (bytes): The signature of the code.

### 5. **verify_code_signature**

```python
def verify_code_signature(self, code, signature):
    code_hash = hashlib.sha256(code.encode()).digest()
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
        return True
    except Exception as e:
        return False
```

- **Purpose**: Verifies the signature of the given code using the RSA public key.
- **Parameters**:
  - `code` (str): The code whose signature is to be verified.
  - `signature` (bytes): The signature to be verified.
- **Returns**: `True` if the signature is valid, `False` otherwise.

### 6. **generate_random_string**

```python
def generate_random_string(self, length):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
```

- **Purpose**: Generates a random string of a given length composed of letters and digits.
- **Parameters**: `length` (int): The length of the random string to be generated.
- **Returns**: `random_string` (str): The generated random string.

### 7. **test_obfuscation**

```python
def test_obfuscation(self):
    obfuscated_code = self.obfuscate_code(self.sample_code)
    deobfuscated_code = self.deobfuscate_code(obfuscated_code)
    self.assertNotEqual(obfuscated_code, self.sample_code, "Code should be obfuscated")
    self.assertEqual(deobfuscated_code, self.sample_code, "Deobfuscated code should match the original code")
```

- **Purpose**: Tests the obfuscation and deobfuscation processes.
- **Assertions**:
  - Asserts that the obfuscated code is not equal to the original code.
  - Asserts that the deobfuscated code matches the original code.

### 8. **test_anti_tamper**

```python
def test_anti_tamper(self):
    tampered_code = self.sample_code + " tampered"
    tampered_hash = hashlib.sha256(tampered_code.encode()).hexdigest()
    self.assertNotEqual(tampered_hash, self.original_hash, "Tampered code hash should not match original hash")
    self.assertFalse(self.verify_code_signature(tampered_code, self.original_signature), "Code integrity check should fail for tampered code")
```

- **Purpose**: Tests the application's ability to detect tampered code.
- **Assertions**:
  - Asserts that the hash of the tampered code does not match the original hash.
  - Asserts that the tampered code fails the integrity check.

### 9. **test_code_integrity**

```python
def test_code_integrity(self):
    self.assertTrue(self.verify_code_signature(self.sample_code, self.original_signature), "Code integrity check should pass for original code")
    
    tampered_code = self.sample_code + " tampered"
    self.assertFalse(self.verify_code_signature(tampered_code, self.original_signature), "Code integrity check should fail for tampered code")
```

- **Purpose**: Verifies the integrity of the original code and ensures that tampered code fails the integrity check.
- **Assertions**:
  - Asserts that the original code passes the integrity check.
  - Asserts that the tampered code fails the integrity check.

### 10. **test_runtime_application_self_protection**

```python
def test_runtime_application_self_protection(self):
    def risky_operation(input_string):
        assert len(input_string) < 100, "Input string is too long!"
        return True
    
    self.assertTrue(risky_operation(self.generate_random_string(50)), "RASP should allow safe operations")
    
    with self.assertRaises(AssertionError):
        risky_operation(self.generate_random_string(150))
```

- **Purpose**: Tests a mock RASP mechanism by asserting the length of an input string.
- **Assertions**:
  - Asserts that safe operations with short input strings pass.
  - Asserts that operations with excessively long input strings raise an `AssertionError`.

### 11. **test_certificate_pinning**

```python
def test_certificate_pinning(self):
    expected_certificate = "expected_certificate_hash"
    def mock_certificate_verification(cert):
        return cert == expected_certificate
    
    actual_certificate = "expected_certificate_hash"
    self.assertTrue(mock_certificate_verification(actual_certificate), "Certificate should match pinned certificate")
    
    invalid_certificate = "invalid_certificate_hash"
    self.assertFalse(mock_certificate_verification(invalid_certificate), "Certificate should not match pinned certificate")
```

- **Purpose**: Simulates certificate pinning by comparing an actual certificate with an expected certificate hash.
- **Assertions**:
  - Asserts that the actual certificate matches the pinned certificate.
  - Asserts that an invalid certificate does not match the pinned certificate.
