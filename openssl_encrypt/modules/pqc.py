#!/usr/bin/env python3
"""
Post-Quantum Cryptography Module

This module provides support for post-quantum cryptographic algorithms 
using the liboqs-python wrapper for liboqs.
"""

import base64
import secrets
import hashlib
import os
from enum import Enum
from typing import Tuple, Optional, Union

from .secure_memory import SecureBytes, secure_memzero

# Try to import PQC libraries, provide fallbacks if not available
try:
    import oqs
    LIBOQS_AVAILABLE = True
except ImportError:
    LIBOQS_AVAILABLE = False
    oqs = None

# Define supported PQC algorithms
class PQCAlgorithm(Enum):
    # NIST Round 3 Finalists and Selected Algorithms
    KYBER512 = "Kyber-512"
    KYBER768 = "Kyber-768"
    KYBER1024 = "Kyber-1024"
    DILITHIUM2 = "Dilithium-2"
    DILITHIUM3 = "Dilithium-3"
    DILITHIUM5 = "Dilithium-5"
    FALCON512 = "Falcon-512"
    FALCON1024 = "Falcon-1024"
    SPHINCSSHA2128F = "SPHINCS+-SHA2-128f"
    SPHINCSSHA2256F = "SPHINCS+-SHA2-256f"

def check_pqc_support() -> Tuple[bool, Optional[str], list]:
    """
    Check if post-quantum cryptography is available and which algorithms are supported.

    Returns:
        tuple: (is_available, version, supported_algorithms)
    """
    if not LIBOQS_AVAILABLE:
        return False, None, []

    try:
        # Get liboqs version
        version = oqs.get_version()
        
        # Get supported algorithms
        supported_algorithms = []
        
        # Check KEM algorithms
        for alg in oqs.get_enabled_KEM_mechanisms():
            supported_algorithms.append(alg)
            
        # Check signature algorithms
        for alg in oqs.get_enabled_sig_mechanisms():
            supported_algorithms.append(alg)
            
        return True, version, supported_algorithms
    except Exception:
        return False, None, []

class PQCipher:
    """
    Post-Quantum Cipher implementation using liboqs
    
    This implementation combines post-quantum key encapsulation with 
    symmetric encryption using AES-256-GCM.
    """
    def __init__(self, algorithm: Union[PQCAlgorithm, str]):
        """
        Initialize a post-quantum cipher instance
        
        Args:
            algorithm (Union[PQCAlgorithm, str]): The post-quantum algorithm to use
        
        Raises:
            ValueError: If liboqs is not available or algorithm not supported
            ImportError: If required dependencies are missing
        """
        if not LIBOQS_AVAILABLE:
            raise ImportError("liboqs-python is required for post-quantum cryptography. "
                             "Install with: pip install liboqs-python")
        
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            self.AESGCM = AESGCM
        except ImportError:
            raise ImportError("The 'cryptography' library is required")
            
        # Convert string to enum if necessary
        if isinstance(algorithm, str):
            algorithm = PQCAlgorithm(algorithm)
            
        self.algorithm = algorithm
        self.algorithm_name = algorithm.value
        
        # Check if algorithm is supported
        supported = check_pqc_support()[2]
        if self.algorithm_name not in supported:
            raise ValueError(f"Algorithm {self.algorithm_name} is not supported by liboqs")
        
        # Determine whether this is a KEM or signature algorithm
        if "Kyber" in self.algorithm_name:
            self.is_kem = True
        else:
            self.is_kem = False
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a post-quantum keypair
        
        Returns:
            Tuple[bytes, bytes]: (public_key, private_key)
        """
        if not self.is_kem:
            raise ValueError("This method is only supported for KEM algorithms")
            
        with oqs.KeyEncapsulation(self.algorithm_name) as kem:
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()
            
        return public_key, private_key
    
    def encrypt(self, data: bytes, public_key: bytes) -> bytes:
        """
        Encrypt data using a hybrid post-quantum + symmetric approach
        
        Args:
            data (bytes): The data to encrypt
            public_key (bytes): The recipient's public key
            
        Returns:
            bytes: The encrypted data format: encapsulated_key + nonce + ciphertext
        """
        if not self.is_kem:
            raise ValueError("This method is only supported for KEM algorithms")
            
        # Use PQ-KEM to establish a shared secret
        with oqs.KeyEncapsulation(self.algorithm_name) as kem:
            ciphertext, shared_secret = kem.encapsulate(public_key)
            
        # Create a secure symmetric key from the shared secret
        symmetric_key = hashlib.sha256(shared_secret).digest()
        
        try:
            # Use the symmetric key with AES-GCM for data encryption
            nonce = secrets.token_bytes(12)  # 12 bytes for AES-GCM
            cipher = self.AESGCM(symmetric_key)
            encrypted_data = cipher.encrypt(nonce, data, None)
            
            # Return the encapsulated_key + nonce + encrypted_data
            return ciphertext + nonce + encrypted_data
        finally:
            # Clean up sensitive data
            secure_memzero(shared_secret)
            secure_memzero(symmetric_key)
    
    def decrypt(self, encrypted_data: bytes, private_key: bytes) -> bytes:
        """
        Decrypt data that was encrypted with the corresponding public key
        
        Args:
            encrypted_data (bytes): The encrypted data
            private_key (bytes): The recipient's private key
            
        Returns:
            bytes: The decrypted data
            
        Raises:
            ValueError: If decryption fails
        """
        if not self.is_kem:
            raise ValueError("This method is only supported for KEM algorithms")
            
        try:
            # Import the KeyEncapsulation object
            with oqs.KeyEncapsulation(self.algorithm_name) as kem:
                # Determine size of encapsulated key
                kem_ciphertext_size = kem.details['length_ciphertext']
                
                # Split the encrypted data
                encapsulated_key = encrypted_data[:kem_ciphertext_size]
                remaining_data = encrypted_data[kem_ciphertext_size:]
                
                # Use 12 bytes for AES-GCM nonce
                nonce = remaining_data[:12]
                ciphertext = remaining_data[12:]
                
                # Decapsulate to get the shared secret
                shared_secret = kem.decapsulate(encapsulated_key)
                
                # Derive the symmetric key
                symmetric_key = hashlib.sha256(shared_secret).digest()
                
                # Decrypt the data using AES-GCM
                cipher = self.AESGCM(symmetric_key)
                try:
                    return cipher.decrypt(nonce, ciphertext, None)
                except Exception as e:
                    # Use generic error message to prevent oracle attacks
                    raise ValueError("Decryption failed: authentication error")
        finally:
            # Clean up sensitive data
            if 'shared_secret' in locals():
                secure_memzero(shared_secret)
            if 'symmetric_key' in locals():
                secure_memzero(symmetric_key)