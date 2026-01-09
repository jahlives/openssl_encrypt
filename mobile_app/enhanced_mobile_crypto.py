#!/usr/bin/env python3
"""
Enhanced Mobile Crypto Core - Integrates with main OpenSSL Encrypt
Provides mobile-optimized access to full cryptographic capabilities
"""

import json
import os
import sys
from typing import Dict, Any, Optional, List
import importlib.util

# Add the main OpenSSL Encrypt path
main_project_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, main_project_path)

try:
    # Import main project functions
    from openssl_encrypt.modules.crypt_core import (
        encrypt_file, decrypt_file, 
        EncryptionAlgorithm,
        PQC_AVAILABLE, PQC_ALGORITHMS,
        ARGON2_AVAILABLE, BALLOON_AVAILABLE, 
        HKDF_AVAILABLE, BLAKE3_AVAILABLE
    )
    MAIN_CRYPTO_AVAILABLE = True
    print("✅ Main crypto functions imported successfully")
except ImportError as e:
    print(f"Warning: Could not import main crypto functions: {e}")
    MAIN_CRYPTO_AVAILABLE = False

# Fallback to simple crypto if main project unavailable
from mobile_crypto_core import MobileCryptoCore


class EnhancedMobileCrypto:
    """Enhanced mobile crypto with full algorithm support"""
    
    def __init__(self):
        self.fallback_crypto = MobileCryptoCore()
        
        if MAIN_CRYPTO_AVAILABLE:
            self._load_main_algorithms()
        else:
            self.supported_algorithms = ["fernet", "aes-gcm"]
            self.hash_algorithms = ["sha256", "sha512"]
            self.kdf_algorithms = ["pbkdf2"]
    
    def _load_main_algorithms(self):
        """Load algorithms from main OpenSSL Encrypt"""
        try:
            # Get encryption algorithms
            self.supported_algorithms = []
            for algo in EncryptionAlgorithm:
                self.supported_algorithms.append(algo.value)
            
            # Add PQC algorithms if available
            if PQC_AVAILABLE and PQC_ALGORITHMS:
                self.supported_algorithms.extend([f"{algo}-hybrid" for algo in PQC_ALGORITHMS[:3]])  # Limit for mobile
            
            # Hash algorithms
            self.hash_algorithms = ["sha256", "sha512", "sha3-256", "sha3-512"]
            if BLAKE3_AVAILABLE:
                self.hash_algorithms.append("blake3")
            
            # KDF algorithms  
            self.kdf_algorithms = ["pbkdf2"]
            if ARGON2_AVAILABLE:
                self.kdf_algorithms.append("argon2")
            if BALLOON_AVAILABLE:
                self.kdf_algorithms.append("balloon")
            if HKDF_AVAILABLE:
                self.kdf_algorithms.append("hkdf")
                
        except Exception as e:
            print(f"Error loading main algorithms: {e}")
            # Fallback to simple algorithms
            self.supported_algorithms = ["fernet", "aes-gcm"]
            self.hash_algorithms = ["sha256", "sha512"]
            self.kdf_algorithms = ["pbkdf2"]
    
    def get_algorithm_info(self) -> Dict[str, Any]:
        """Get comprehensive algorithm information"""
        return {
            "encryption_algorithms": self.supported_algorithms,
            "hash_algorithms": self.hash_algorithms,
            "kdf_algorithms": self.kdf_algorithms,
            "features": {
                "main_crypto_available": MAIN_CRYPTO_AVAILABLE,
                "pqc_available": MAIN_CRYPTO_AVAILABLE and PQC_AVAILABLE,
                "argon2_available": MAIN_CRYPTO_AVAILABLE and ARGON2_AVAILABLE,
                "balloon_available": MAIN_CRYPTO_AVAILABLE and BALLOON_AVAILABLE,
                "hkdf_available": MAIN_CRYPTO_AVAILABLE and HKDF_AVAILABLE,
                "blake3_available": MAIN_CRYPTO_AVAILABLE and BLAKE3_AVAILABLE,
            }
        }
    
    def encrypt_file_enhanced(self, input_path: str, password: str, output_path: str = None, 
                            algorithm: str = "fernet", progress_callback=None) -> Dict[str, Any]:
        """
        Enhanced file encryption using main project capabilities
        """
        try:
            if not MAIN_CRYPTO_AVAILABLE:
                # Fallback to simple mobile crypto
                return self.fallback_crypto.encrypt_file(input_path, password, output_path, progress_callback)
            
            if progress_callback:
                progress_callback(10)
            
            # Use main project encryption
            result = encrypt_file(
                input_file=input_path,
                password=password,
                output_file=output_path,
                algorithm=algorithm,
                iterations=100000,  # Mobile-optimized
                hash_algorithm="sha256",  # Efficient for mobile
                kdf_algorithm="pbkdf2"    # Compatible everywhere
            )
            
            if progress_callback:
                progress_callback(100)
            
            return {
                "success": True,
                "output_path": result.get("output_file", output_path),
                "algorithm": algorithm,
                "metadata": result.get("metadata", {}),
                "file_format": "openssl_encrypt_v5"
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "fallback_used": not MAIN_CRYPTO_AVAILABLE
            }
    
    def decrypt_file_enhanced(self, input_path: str, password: str, output_path: str = None,
                            progress_callback=None) -> Dict[str, Any]:
        """
        Enhanced file decryption using main project capabilities
        """
        try:
            if not MAIN_CRYPTO_AVAILABLE:
                # Fallback to simple mobile crypto
                return self.fallback_crypto.decrypt_file(input_path, password, output_path, progress_callback)
            
            if progress_callback:
                progress_callback(10)
            
            # Use main project decryption
            result = decrypt_file(
                input_file=input_path,
                password=password,
                output_file=output_path
            )
            
            if progress_callback:
                progress_callback(100)
            
            return {
                "success": True,
                "output_path": result.get("output_file", output_path),
                "metadata": result.get("metadata", {}),
                "file_format": result.get("format", "openssl_encrypt")
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "fallback_used": not MAIN_CRYPTO_AVAILABLE
            }
    
    def encrypt_text(self, text: str, password: str, algorithm: str = "fernet") -> str:
        """Enhanced text encryption"""
        if MAIN_CRYPTO_AVAILABLE and algorithm in self.supported_algorithms:
            try:
                # Create temporary file for main crypto
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp:
                    tmp.write(text)
                    tmp_path = tmp.name
                
                try:
                    result = self.encrypt_file_enhanced(tmp_path, password, algorithm=algorithm)
                    if result["success"]:
                        with open(result["output_path"], 'r') as f:
                            encrypted_content = f.read()
                        
                        # Cleanup
                        os.unlink(tmp_path)
                        os.unlink(result["output_path"])
                        
                        return encrypted_content
                    else:
                        raise Exception(result["error"])
                finally:
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
                        
            except Exception as e:
                # Fallback to simple crypto
                pass
        
        # Use fallback
        return self.fallback_crypto.encrypt_text(text, password)
    
    def decrypt_text(self, encrypted_text: str, password: str) -> str:
        """Enhanced text decryption"""
        if MAIN_CRYPTO_AVAILABLE:
            try:
                # Try to detect format and decrypt accordingly
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.enc') as tmp:
                    tmp.write(encrypted_text)
                    tmp_path = tmp.name
                
                try:
                    result = self.decrypt_file_enhanced(tmp_path, password)
                    if result["success"]:
                        with open(result["output_path"], 'r') as f:
                            decrypted_content = f.read()
                        
                        # Cleanup
                        os.unlink(tmp_path)
                        os.unlink(result["output_path"])
                        
                        return decrypted_content
                    else:
                        raise Exception(result["error"])
                finally:
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
                        
            except Exception as e:
                # Fallback to simple crypto
                pass
        
        # Use fallback
        return self.fallback_crypto.decrypt_text(encrypted_text, password)
    
    def get_supported_algorithms(self) -> str:
        """Get algorithms as JSON string"""
        return json.dumps({
            "encryption": self.supported_algorithms[:8],  # Limit for mobile UI
            "status": "enhanced" if MAIN_CRYPTO_AVAILABLE else "fallback",
            "features": self.get_algorithm_info()["features"]
        })


# Global instance for FFI
enhanced_crypto = EnhancedMobileCrypto()

# FFI-compatible functions
def mobile_encrypt_text_enhanced(text: str, password: str, algorithm: str = "fernet") -> str:
    """Enhanced FFI-compatible text encryption"""
    return enhanced_crypto.encrypt_text(text, password, algorithm)

def mobile_decrypt_text_enhanced(encrypted_text: str, password: str) -> str:
    """Enhanced FFI-compatible text decryption"""
    return enhanced_crypto.decrypt_text(encrypted_text, password)

def mobile_get_algorithms_enhanced() -> str:
    """Enhanced FFI-compatible algorithm list"""
    return enhanced_crypto.get_supported_algorithms()

def mobile_encrypt_file_enhanced(input_path: str, password: str, output_path: str = "", 
                                algorithm: str = "fernet") -> str:
    """Enhanced FFI-compatible file encryption"""
    output_path = output_path if output_path else None
    result = enhanced_crypto.encrypt_file_enhanced(input_path, password, output_path, algorithm)
    return json.dumps(result)

def mobile_decrypt_file_enhanced(input_path: str, password: str, output_path: str = "") -> str:
    """Enhanced FFI-compatible file decryption"""
    output_path = output_path if output_path else None
    result = enhanced_crypto.decrypt_file_enhanced(input_path, password, output_path)
    return json.dumps(result)


if __name__ == "__main__":
    # Test the enhanced crypto
    crypto = EnhancedMobileCrypto()
    
    print("🔐 Enhanced Mobile Crypto Test")
    print("=" * 40)
    
    # Show algorithm info
    algo_info = crypto.get_algorithm_info()
    print(f"Main crypto available: {algo_info['features']['main_crypto_available']}")
    print(f"Encryption algorithms: {len(algo_info['encryption_algorithms'])}")
    print(f"Algorithms: {', '.join(algo_info['encryption_algorithms'][:5])}...")
    
    # Test text encryption
    test_text = "Hello from Enhanced Mobile Crypto!"
    test_password = "test123"
    
    print(f"\n📝 Testing text encryption...")
    encrypted = crypto.encrypt_text(test_text, test_password)
    print(f"✅ Text encrypted ({len(encrypted)} chars)")
    
    decrypted = crypto.decrypt_text(encrypted, test_password)
    print(f"✅ Text decrypted: {decrypted}")
    
    success = decrypted == test_text
    print(f"🎯 Test {'PASSED' if success else 'FAILED'}")
    
    print(f"\n🔧 Supported algorithms JSON:")
    print(crypto.get_supported_algorithms())