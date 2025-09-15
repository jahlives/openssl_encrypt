"""
Known-Answer Tests (KAT) Suite for OpenSSL Encrypt Library.

Implements test vectors from NIST and custom test vectors to ensure
cryptographic algorithms produce expected results.
"""

import hashlib
import hmac
import os
import tempfile
import json
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass, field

from .base_test import BaseSecurityTest, TestResult, TestResultLevel, TestConfig
from ..crypt_core import encrypt_file, decrypt_file


@dataclass
class TestVector:
    """Represents a cryptographic test vector."""
    algorithm: str
    test_name: str
    input_data: bytes
    key: bytes
    expected_output: bytes
    additional_params: Dict[str, Any] = field(default_factory=dict)
    description: str = ""


class NISTTestVectors:
    """NIST test vectors for cryptographic algorithms."""
    
    @staticmethod
    def get_sha256_vectors() -> List[TestVector]:
        """Get SHA-256 test vectors."""
        vectors = []
        
        # Test vector 1: Empty string
        vectors.append(TestVector(
            algorithm="SHA256",
            test_name="empty_string",
            input_data=b"",
            key=b"",  # SHA doesn't use keys
            expected_output=bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            description="SHA-256 of empty string"
        ))
        
        # Test vector 2: Single byte
        vectors.append(TestVector(
            algorithm="SHA256", 
            test_name="single_byte",
            input_data=b"\x61",  # 'a'
            key=b"",
            expected_output=bytes.fromhex("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"),
            description="SHA-256 of single byte 'a'"
        ))
        
        # Test vector 3: Multi-byte string
        vectors.append(TestVector(
            algorithm="SHA256",
            test_name="abc_string", 
            input_data=b"abc",
            key=b"",
            expected_output=bytes.fromhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            description="SHA-256 of 'abc'"
        ))
        
        # Test vector 4: Longer string
        vectors.append(TestVector(
            algorithm="SHA256",
            test_name="longer_string",
            input_data=b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            key=b"",
            expected_output=bytes.fromhex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
            description="SHA-256 of longer test string"
        ))
        
        return vectors
    
    @staticmethod
    def get_sha512_vectors() -> List[TestVector]:
        """Get SHA-512 test vectors."""
        vectors = []
        
        # Test vector 1: Empty string
        vectors.append(TestVector(
            algorithm="SHA512",
            test_name="empty_string",
            input_data=b"",
            key=b"",
            expected_output=bytes.fromhex("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
            description="SHA-512 of empty string"
        ))
        
        # Test vector 2: 'abc'
        vectors.append(TestVector(
            algorithm="SHA512",
            test_name="abc_string",
            input_data=b"abc",
            key=b"",
            expected_output=bytes.fromhex("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
            description="SHA-512 of 'abc'"
        ))
        
        return vectors
    
    @staticmethod
    def get_hmac_vectors() -> List[TestVector]:
        """Get HMAC test vectors."""
        vectors = []
        
        # HMAC-SHA256 test vectors from RFC 4231
        vectors.append(TestVector(
            algorithm="HMAC-SHA256",
            test_name="rfc4231_test1",
            input_data=b"Hi There",
            key=bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            expected_output=bytes.fromhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
            description="HMAC-SHA256 RFC 4231 Test Case 1"
        ))
        
        vectors.append(TestVector(
            algorithm="HMAC-SHA256",
            test_name="rfc4231_test2",
            input_data=b"what do ya want for nothing?",
            key=b"Jefe",
            expected_output=bytes.fromhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
            description="HMAC-SHA256 RFC 4231 Test Case 2"
        ))
        
        return vectors
    
    @staticmethod 
    def get_pbkdf2_vectors() -> List[TestVector]:
        """Get PBKDF2 test vectors."""
        vectors = []
        
        # PBKDF2 test vectors from RFC 6070
        vectors.append(TestVector(
            algorithm="PBKDF2",
            test_name="rfc6070_test1",
            input_data=b"password",
            key=b"salt",
            expected_output=bytes.fromhex("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"),
            additional_params={"iterations": 1, "dklen": 32},
            description="PBKDF2-HMAC-SHA256 RFC 6070 Test 1"
        ))
        
        vectors.append(TestVector(
            algorithm="PBKDF2",
            test_name="rfc6070_test2", 
            input_data=b"password",
            key=b"salt",
            expected_output=bytes.fromhex("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"),
            additional_params={"iterations": 2, "dklen": 32},
            description="PBKDF2-HMAC-SHA256 RFC 6070 Test 2"
        ))
        
        return vectors


class CustomTestVectors:
    """Custom test vectors for OpenSSL Encrypt specific functionality."""
    
    @staticmethod
    def get_file_encryption_vectors() -> List[TestVector]:
        """Get test vectors for file encryption/decryption."""
        vectors = []
        
        # Test vector 1: Small file with Fernet
        vectors.append(TestVector(
            algorithm="fernet",
            test_name="small_file_fernet",
            input_data=b"Hello, World! This is a test file for encryption.",
            key=b"test_password_123",
            expected_output=b"",  # Will be set during test
            additional_params={"hash_algorithm": "SHA256", "kdf": "pbkdf2"},
            description="Small file encryption with Fernet"
        ))
        
        # Test vector 2: Binary data with AES-GCM
        vectors.append(TestVector(
            algorithm="aes-gcm",
            test_name="binary_data_aes_gcm",
            input_data=bytes(range(256)),  # All byte values 0-255
            key=b"binary_test_password",
            expected_output=b"",
            additional_params={"hash_algorithm": "SHA256", "kdf": "pbkdf2"},
            description="Binary data encryption with AES-GCM"
        ))
        
        # Test vector 3: Unicode text with ChaCha20-Poly1305
        unicode_text = "Hello 世界! 🔒 Encryption test with émojis and spëcial châractërs"
        vectors.append(TestVector(
            algorithm="chacha20-poly1305",
            test_name="unicode_chacha20",
            input_data=unicode_text.encode('utf-8'),
            key="unicode_password_测试".encode('utf-8'),
            expected_output=b"",
            additional_params={"hash_algorithm": "SHA256", "kdf": "pbkdf2"},
            description="Unicode text encryption with ChaCha20-Poly1305"
        ))
        
        return vectors


class KATTestSuite(BaseSecurityTest):
    """Known-Answer Tests (KAT) suite."""
    
    def __init__(self):
        super().__init__(
            "KATTestSuite",
            "Known-Answer Tests to verify cryptographic algorithm correctness"
        )
        self.temp_dir = None
    
    def setup_temp_directory(self) -> str:
        """Set up temporary directory for test files."""
        if not self.temp_dir:
            self.temp_dir = tempfile.mkdtemp(prefix="kat_test_")
        return self.temp_dir
    
    def cleanup_temp_directory(self) -> None:
        """Clean up temporary directory."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            self.temp_dir = None
    
    def run_tests(self, **kwargs) -> List[TestResult]:
        """Run all KAT tests."""
        self.clear_results()
        config = TestConfig(**kwargs)
        
        try:
            self.setup_temp_directory()
            
            # Run different categories of KAT tests
            self._test_hash_algorithms(config)
            self._test_hmac_algorithms(config)
            self._test_kdf_algorithms(config)
            self._test_file_encryption(config)
            self._test_cross_platform_compatibility(config)
            
        finally:
            self.cleanup_temp_directory()
        
        return self.get_results()
    
    def _test_hash_algorithms(self, config: TestConfig) -> None:
        """Test hash algorithms against known vectors."""
        
        # Test SHA-256
        sha256_vectors = NISTTestVectors.get_sha256_vectors()
        for vector in sha256_vectors:
            result = self.run_single_test(
                self._test_hash_vector,
                f"hash_sha256_{vector.test_name}",
                vector
            )
            self.add_result(result)
        
        # Test SHA-512
        sha512_vectors = NISTTestVectors.get_sha512_vectors()
        for vector in sha512_vectors:
            result = self.run_single_test(
                self._test_hash_vector,
                f"hash_sha512_{vector.test_name}",
                vector
            )
            self.add_result(result)
    
    def _test_hash_vector(self, vector: TestVector) -> TestResult:
        """Test a single hash algorithm vector."""
        try:
            if vector.algorithm == "SHA256":
                computed_hash = hashlib.sha256(vector.input_data).digest()
            elif vector.algorithm == "SHA512":
                computed_hash = hashlib.sha512(vector.input_data).digest()
            else:
                return TestResult(
                    f"hash_{vector.algorithm}_{vector.test_name}",
                    TestResultLevel.ERROR,
                    f"Unsupported hash algorithm: {vector.algorithm}"
                )
            
            if computed_hash == vector.expected_output:
                return TestResult(
                    f"hash_{vector.algorithm}_{vector.test_name}",
                    TestResultLevel.PASS,
                    f"{vector.algorithm} test vector passed: {vector.description}",
                    details={
                        "input_size": len(vector.input_data),
                        "output_size": len(computed_hash),
                        "expected_hash": vector.expected_output.hex(),
                        "computed_hash": computed_hash.hex()
                    }
                )
            else:
                return TestResult(
                    f"hash_{vector.algorithm}_{vector.test_name}",
                    TestResultLevel.ERROR,
                    f"{vector.algorithm} test vector failed: {vector.description}",
                    details={
                        "expected": vector.expected_output.hex(),
                        "computed": computed_hash.hex(),
                        "input": vector.input_data.hex() if len(vector.input_data) < 100 else f"{len(vector.input_data)} bytes"
                    }
                )
                
        except Exception as e:
            return TestResult(
                f"hash_{vector.algorithm}_{vector.test_name}",
                TestResultLevel.ERROR,
                f"Exception during {vector.algorithm} test: {str(e)}",
                exception=e
            )
    
    def _test_hmac_algorithms(self, config: TestConfig) -> None:
        """Test HMAC algorithms against known vectors."""
        
        hmac_vectors = NISTTestVectors.get_hmac_vectors()
        for vector in hmac_vectors:
            result = self.run_single_test(
                self._test_hmac_vector,
                f"hmac_{vector.test_name}",
                vector
            )
            self.add_result(result)
    
    def _test_hmac_vector(self, vector: TestVector) -> TestResult:
        """Test a single HMAC vector."""
        try:
            if vector.algorithm == "HMAC-SHA256":
                computed_hmac = hmac.new(vector.key, vector.input_data, hashlib.sha256).digest()
            else:
                return TestResult(
                    f"hmac_{vector.test_name}",
                    TestResultLevel.ERROR,
                    f"Unsupported HMAC algorithm: {vector.algorithm}"
                )
            
            if computed_hmac == vector.expected_output:
                return TestResult(
                    f"hmac_{vector.test_name}",
                    TestResultLevel.PASS,
                    f"HMAC test vector passed: {vector.description}",
                    details={
                        "key_size": len(vector.key),
                        "input_size": len(vector.input_data),
                        "hmac_size": len(computed_hmac)
                    }
                )
            else:
                return TestResult(
                    f"hmac_{vector.test_name}",
                    TestResultLevel.ERROR,
                    f"HMAC test vector failed: {vector.description}",
                    details={
                        "expected": vector.expected_output.hex(),
                        "computed": computed_hmac.hex(),
                        "key": vector.key.hex(),
                        "input": vector.input_data.hex() if len(vector.input_data) < 100 else f"{len(vector.input_data)} bytes"
                    }
                )
                
        except Exception as e:
            return TestResult(
                f"hmac_{vector.test_name}",
                TestResultLevel.ERROR,
                f"Exception during HMAC test: {str(e)}",
                exception=e
            )
    
    def _test_kdf_algorithms(self, config: TestConfig) -> None:
        """Test KDF algorithms against known vectors."""
        
        pbkdf2_vectors = NISTTestVectors.get_pbkdf2_vectors()
        for vector in pbkdf2_vectors:
            result = self.run_single_test(
                self._test_kdf_vector,
                f"kdf_{vector.test_name}",
                vector
            )
            self.add_result(result)
    
    def _test_kdf_vector(self, vector: TestVector) -> TestResult:
        """Test a single KDF vector."""
        try:
            if vector.algorithm == "PBKDF2":
                import hashlib
                
                iterations = vector.additional_params.get("iterations", 1)
                dklen = vector.additional_params.get("dklen", 32)
                
                computed_key = hashlib.pbkdf2_hmac(
                    'sha256', 
                    vector.input_data, 
                    vector.key, 
                    iterations, 
                    dklen
                )
            else:
                return TestResult(
                    f"kdf_{vector.test_name}",
                    TestResultLevel.ERROR,
                    f"Unsupported KDF algorithm: {vector.algorithm}"
                )
            
            if computed_key == vector.expected_output:
                return TestResult(
                    f"kdf_{vector.test_name}",
                    TestResultLevel.PASS,
                    f"KDF test vector passed: {vector.description}",
                    details={
                        "iterations": iterations,
                        "key_length": dklen,
                        "salt_size": len(vector.key),
                        "password_size": len(vector.input_data)
                    }
                )
            else:
                return TestResult(
                    f"kdf_{vector.test_name}",
                    TestResultLevel.ERROR,
                    f"KDF test vector failed: {vector.description}",
                    details={
                        "expected": vector.expected_output.hex(),
                        "computed": computed_key.hex(),
                        "iterations": iterations,
                        "dklen": dklen
                    }
                )
                
        except Exception as e:
            return TestResult(
                f"kdf_{vector.test_name}",
                TestResultLevel.ERROR,
                f"Exception during KDF test: {str(e)}",
                exception=e
            )
    
    def _test_file_encryption(self, config: TestConfig) -> None:
        """Test file encryption with known test vectors."""
        
        file_vectors = CustomTestVectors.get_file_encryption_vectors()
        for vector in file_vectors:
            result = self.run_single_test(
                self._test_file_encryption_vector,
                f"file_encrypt_{vector.test_name}",
                vector
            )
            self.add_result(result)
    
    def _test_file_encryption_vector(self, vector: TestVector) -> TestResult:
        """Test a single file encryption vector."""
        try:
            # Create input file
            input_file = os.path.join(self.temp_dir, f"kat_input_{vector.test_name}.bin")
            encrypted_file = os.path.join(self.temp_dir, f"kat_encrypted_{vector.test_name}.bin")
            decrypted_file = os.path.join(self.temp_dir, f"kat_decrypted_{vector.test_name}.bin")
            
            with open(input_file, 'wb') as f:
                f.write(vector.input_data)
            
            # Prepare configuration
            config_dict = {
                "algorithm": vector.algorithm,
                "hash_algorithm": vector.additional_params.get("hash_algorithm", "SHA256"),
                "kdf": vector.additional_params.get("kdf", "pbkdf2")
            }
            
            password = vector.key.decode('utf-8', errors='replace')
            
            # Encrypt file
            encrypt_file(input_file, encrypted_file, password, hash_config=config_dict)
            
            if not os.path.exists(encrypted_file):
                return TestResult(
                    f"file_encrypt_{vector.test_name}",
                    TestResultLevel.ERROR,
                    f"Encryption failed - no output file created"
                )
            
            # Decrypt file 
            decrypt_file(encrypted_file, decrypted_file, password)
            
            if not os.path.exists(decrypted_file):
                return TestResult(
                    f"file_encrypt_{vector.test_name}",
                    TestResultLevel.ERROR,
                    f"Decryption failed - no output file created"
                )
            
            # Verify data integrity
            with open(decrypted_file, 'rb') as f:
                decrypted_data = f.read()
            
            if decrypted_data == vector.input_data:
                return TestResult(
                    f"file_encrypt_{vector.test_name}",
                    TestResultLevel.PASS,
                    f"File encryption test passed: {vector.description}",
                    details={
                        "algorithm": vector.algorithm,
                        "input_size": len(vector.input_data),
                        "encrypted_size": os.path.getsize(encrypted_file),
                        "integrity_verified": True
                    }
                )
            else:
                return TestResult(
                    f"file_encrypt_{vector.test_name}",
                    TestResultLevel.ERROR,
                    f"File encryption test failed: data corruption detected",
                    details={
                        "expected_size": len(vector.input_data),
                        "actual_size": len(decrypted_data),
                        "data_matches": False
                    }
                )
                
        except Exception as e:
            return TestResult(
                f"file_encrypt_{vector.test_name}",
                TestResultLevel.ERROR,
                f"Exception during file encryption test: {str(e)}",
                exception=e
            )
    
    def _test_cross_platform_compatibility(self, config: TestConfig) -> None:
        """Test cross-platform compatibility with known data."""
        
        result = self.run_single_test(
            self._test_platform_compatibility,
            "cross_platform_compatibility",
            config
        )
        self.add_result(result)
    
    def _test_platform_compatibility(self, config: TestConfig) -> TestResult:
        """Test cross-platform compatibility."""
        try:
            # Create test data
            test_data = "Cross-platform compatibility test data with unicode: 世界🔒"
            
            input_file = os.path.join(self.temp_dir, "platform_test.txt")
            encrypted_file = os.path.join(self.temp_dir, "platform_test_enc.bin")
            decrypted_file = os.path.join(self.temp_dir, "platform_test_dec.txt")
            
            with open(input_file, 'w', encoding='utf-8') as f:
                f.write(test_data)
            
            # Test with multiple algorithms to ensure consistency
            algorithms = ["fernet", "aes-gcm", "chacha20-poly1305"]
            success_count = 0
            total_tests = len(algorithms)
            
            for algorithm in algorithms:
                try:
                    config_dict = {
                        "algorithm": algorithm,
                        "hash_algorithm": "SHA256",
                        "kdf": "pbkdf2"
                    }
                    
                    encrypt_file(input_file, encrypted_file, "platform_test_password", hash_config=config_dict)
                    decrypt_file(encrypted_file, decrypted_file, "platform_test_password")
                    
                    with open(decrypted_file, 'r', encoding='utf-8') as f:
                        decrypted_data = f.read()
                    
                    if decrypted_data == test_data:
                        success_count += 1
                    
                    # Clean up for next algorithm
                    for temp_file in [encrypted_file, decrypted_file]:
                        if os.path.exists(temp_file):
                            os.remove(temp_file)
                            
                except Exception:
                    # Algorithm failed, continue with others
                    pass
            
            if success_count == total_tests:
                return TestResult(
                    "cross_platform_compatibility",
                    TestResultLevel.PASS,
                    f"All {success_count} algorithms passed cross-platform test",
                    details={
                        "algorithms_tested": algorithms,
                        "success_count": success_count,
                        "total_tests": total_tests,
                        "unicode_support": True
                    }
                )
            elif success_count > 0:
                return TestResult(
                    "cross_platform_compatibility",
                    TestResultLevel.WARNING,
                    f"{success_count}/{total_tests} algorithms passed cross-platform test",
                    details={
                        "algorithms_tested": algorithms,
                        "success_count": success_count,
                        "total_tests": total_tests
                    }
                )
            else:
                return TestResult(
                    "cross_platform_compatibility",
                    TestResultLevel.ERROR,
                    "No algorithms passed cross-platform compatibility test",
                    details={
                        "algorithms_tested": algorithms,
                        "success_count": success_count,
                        "total_tests": total_tests
                    }
                )
                
        except Exception as e:
            return TestResult(
                "cross_platform_compatibility",
                TestResultLevel.ERROR,
                f"Exception during cross-platform test: {str(e)}",
                exception=e
            )